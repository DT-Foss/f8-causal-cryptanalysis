#!/usr/bin/env python3
"""Partition the retained 20-coordinate R1 Boolean transform instance."""
from __future__ import annotations

import argparse
import concurrent.futures
import hashlib
import importlib.util
import json
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any

from arx_carry_leak.crypto_causal import CryptoCausalBuilder, CryptoCausalReader


def _import_sibling(filename: str, module_name: str) -> Any:
    path = Path(__file__).with_name(filename)
    spec = importlib.util.spec_from_file_location(module_name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


_R1 = _import_sibling(
    "shake_symbolic_r1_scaling_reader.py",
    "shake_symbolic_r1_scaling_reader_partition_scaling_base",
)
_R2 = _import_sibling(
    "shake_symbolic_r2_partition_reader.py",
    "shake_symbolic_r2_partition_reader_r1_scaling_base",
)

_BASE = _R1._BASE
_NATIVE = _R1._NATIVE
_WINDOW = _R1._WINDOW
_SMT = _R1._SMT

A138_SHA256 = "428e17c9d959e425f417b0c3ce15bd1e9065b8284229ce78f7dd8cb4dce0b078"
WINDOW_BITS = 20
PARTITION_BITS = 4
SEED = 89755037
TIMEOUT_SECONDS = 60
MAX_WORKERS = 5


def _a138_unknown_trial(payload: dict[str, Any]) -> dict[str, Any]:
    if payload.get("schema") != "shake-symbolic-r1-scaling-reader-v1":
        raise RuntimeError("A138 schema does not identify the retained R1 scaling run")
    trials = payload.get("trials")
    if not isinstance(trials, list):
        raise RuntimeError("A138 does not contain a trial list")
    matches = [row for row in trials if row.get("window_bits") == WINDOW_BITS]
    if len(matches) != 1:
        raise RuntimeError("A138 must contain exactly one 20-coordinate trial")
    trial = matches[0]
    if trial.get("seed") != SEED:
        raise RuntimeError("A138 20-coordinate trial seed differs from 89755037")
    if trial.get("first_solver", {}).get("status") != "unknown":
        raise RuntimeError("A138 20-coordinate trial is not recorded as unknown")
    return trial


def _load_a138(path: Path) -> dict[str, Any]:
    raw = path.read_bytes()
    observed = hashlib.sha256(raw).hexdigest()
    if observed != A138_SHA256:
        raise RuntimeError(f"A138 retained artifact hash differs for {path}: {observed}")
    payload = json.loads(raw)
    _a138_unknown_trial(payload)
    return payload


def _subspace_plan(window_bits: int, partition_bits: int) -> list[dict[str, Any]]:
    if partition_bits < 1 or partition_bits >= window_bits:
        raise ValueError("partition width must be in 1..window_bits-1")
    fixed_coordinates = list(range(partition_bits))
    free_coordinates = list(range(partition_bits, window_bits))
    assignments_per_subspace = 1 << (window_bits - partition_bits)
    return [
        {
            "subspace_index": value,
            "fixed_low_value": value,
            "fixed_coordinates": [
                {"coordinate": coordinate, "value": (value >> coordinate) & 1}
                for coordinate in fixed_coordinates
            ],
            "free_coordinates": free_coordinates,
            "logical_assignments": assignments_per_subspace,
        }
        for value in range(1 << partition_bits)
    ]


def _partition_trial(
    variant: Any,
    window_bits: int,
    seed: int,
    partition_bits: int,
    timeout_seconds: int,
    max_workers: int,
    z3: Path,
    work_dir: Path,
    keep_smt: bool,
    expected_unpartitioned_smt_sha256: str | None = None,
) -> dict[str, Any]:
    if timeout_seconds < 1 or max_workers < 1:
        raise ValueError("timeout and worker count must be positive")

    plan = _subspace_plan(window_bits, partition_bits)
    problem = _NATIVE._problem(variant, window_bits, seed)
    writer, inputs, encoding = _R1._SPLIT._encode_problem(
        problem, variant, seed, prefix_rounds=1
    )
    unpartitioned_raw = writer.render(inputs, include_model=True)
    unpartitioned_sha256 = hashlib.sha256(unpartitioned_raw).hexdigest()
    if (
        expected_unpartitioned_smt_sha256 is not None
        and unpartitioned_sha256 != expected_unpartitioned_smt_sha256
    ):
        raise RuntimeError(
            "regenerated R1 formulation differs from the hash-gated A138 trial"
        )

    work_dir.mkdir(parents=True, exist_ok=True)
    subspace_files = []
    for row in plan:
        raw = _R2._branch_raw(
            writer, inputs, partition_bits, row["fixed_low_value"]
        )
        path = work_dir / (
            f"{variant.name.lower()}_r1_w{window_bits}_"
            f"subspace{row['subspace_index']:04d}.smt2"
        )
        path.write_bytes(raw)
        subspace_files.append(
            {
                **row,
                "path": path,
                "smt_bytes": len(raw),
                "smt_sha256": hashlib.sha256(raw).hexdigest(),
            }
        )

    def solve(row: dict[str, Any]) -> dict[str, Any]:
        result = _SMT._run_z3(z3, row["path"], timeout_seconds, inputs)
        return {
            "subspace_index": row["subspace_index"],
            "fixed_low_value": row["fixed_low_value"],
            "fixed_coordinates": row["fixed_coordinates"],
            "free_coordinates": row["free_coordinates"],
            "logical_assignments": row["logical_assignments"],
            "remaining_variables": window_bits - partition_bits,
            "smt_bytes": row["smt_bytes"],
            "smt_sha256": row["smt_sha256"],
            "solver": _SMT._solver_summary(result),
            "assignment": result["assignment"],
        }

    try:
        with concurrent.futures.ThreadPoolExecutor(
            max_workers=max_workers
        ) as executor:
            subspaces = sorted(
                executor.map(solve, subspace_files),
                key=lambda row: row["subspace_index"],
            )
    finally:
        if not keep_smt:
            for row in subspace_files:
                row["path"].unlink(missing_ok=True)

    actual = _WINDOW._extract_window(
        problem["base_state"], variant, problem["positions"]
    )
    found_assignments = []
    verified_assignments = []
    for row in subspaces:
        assignment = row["assignment"]
        if assignment is None:
            row["independent_verification"] = None
            row["matches_instrumented_assignment"] = None
            continue
        verification = _R2._verify_assignment(problem, variant, assignment)
        row["independent_verification"] = verification
        row["matches_instrumented_assignment"] = assignment == actual
        found_assignments.append(assignment)
        if verification["complete_rate_match"]:
            verified_assignments.append(assignment)

    statuses = ("sat", "unsat", "unknown", "error")
    status_counts = {
        status: sum(row["solver"]["status"] == status for row in subspaces)
        for status in statuses
    }
    distinct_found = sorted(set(found_assignments))
    distinct_verified = sorted(set(verified_assignments))
    return {
        "variant": variant.name,
        "window_bits": window_bits,
        "seed": seed,
        "window_start_capacity_bit": int(problem["positions"][0]),
        "window_stop_capacity_bit_exclusive": int(problem["positions"][-1] + 1),
        "partition_bits": partition_bits,
        "partitioned_coordinates": list(range(partition_bits)),
        "subspace_schedule": "ascending_unsigned_low_bits",
        "subspace_count": len(plan),
        "subspaces_are_pairwise_disjoint": True,
        "subspaces_cover_complete_assignment_space": True,
        "stored_assignment_used_for_plan_or_generation": False,
        "max_workers": max_workers,
        "solver_threads_per_worker": 1,
        "timeout_seconds_per_subspace": timeout_seconds,
        "actual_assignment_posthoc": actual,
        "actual_low_value_posthoc": actual & ((1 << partition_bits) - 1),
        "status_counts": status_counts,
        "found_assignments": found_assignments,
        "distinct_found_assignments": distinct_found,
        "verified_assignments": verified_assignments,
        "all_found_assignments_independently_verified": (
            len(found_assignments) == len(verified_assignments)
        ),
        "reconstructed_assignment": (
            distinct_verified[0] if len(distinct_verified) == 1 else None
        ),
        "reconstruction_matches_instrumented_assignment": (
            distinct_verified == [actual]
        ),
        "all_subspaces_resolved": (
            status_counts["unknown"] == 0 and status_counts["error"] == 0
        ),
        "encoding": {
            **encoding,
            "unpartitioned_smt_bytes": len(unpartitioned_raw),
            "unpartitioned_smt_sha256": unpartitioned_sha256,
            "matches_retained_a138_formulation": (
                unpartitioned_sha256 == expected_unpartitioned_smt_sha256
                if expected_unpartitioned_smt_sha256 is not None
                else None
            ),
        },
        "subspaces_detail": subspaces,
    }


def _build_graph(
    path: Path,
    window_bits: int,
    partition_bits: int,
    timeout_seconds: int,
    max_workers: int,
) -> dict[str, Any]:
    builder = CryptoCausalBuilder(
        experiment="shake_symbolic_r1_partition_scaling_reader",
        parameters={
            "system": "fixed_boolean_transform_constraint_system",
            "window_bits": window_bits,
            "partition_bits": partition_bits,
            "subspace_count": 1 << partition_bits,
            "timeout_seconds_per_subspace": timeout_seconds,
            "worker_processes": max_workers,
            "solver_threads_per_worker": 1,
        },
    )
    plan_id = "boolean-transform-complete-low-coordinate-subspace-plan"
    solve_id = "boolean-transform-bounded-subspace-observations"
    builder.add_triplet(
        edge_id=plan_id,
        trigger="boolean_transform:fixed_coordinate_constraint_system",
        mechanism="enumerate_all_low_coordinate_values_in_unsigned_order",
        outcome="boolean_transform:complete_disjoint_subspace_plan",
        confidence=1.0,
        evidence_kind="deterministic_partition_construction",
        source="reader_local_enumeration",
        attrs={
            "reader_recipe": {
                "formulation_module": "shake_symbolic_r1_scaling_reader.py",
                "partition_module": "shake_symbolic_r2_partition_reader.py",
                "fixed_coordinates": list(range(partition_bits)),
                "subspace_values": list(range(1 << partition_bits)),
                "stored_assignment_input": None,
            }
        },
    )
    builder.add_triplet(
        edge_id=solve_id,
        trigger="boolean_transform:complete_disjoint_subspace_plan",
        mechanism="execute_each_R1_boolean_subspace_with_equal_local_limit",
        outcome="boolean_transform:subspace_statuses_and_candidate_assignments",
        confidence=1.0,
        evidence_kind="bounded_solver_observations",
        source="Z3_Boolean_SMT",
        provenance=[plan_id],
        attrs={
            "reader_recipe": {
                "symbolic_prefix_rounds": 1,
                "subspace_order": "ascending_unsigned_low_bits",
                "timeout_seconds_per_subspace": timeout_seconds,
                "worker_processes": max_workers,
                "solver_threads_per_worker": 1,
            }
        },
    )
    builder.add_triplet(
        edge_id="boolean-transform-independent-candidate-checks",
        trigger="boolean_transform:subspace_statuses_and_candidate_assignments",
        mechanism="evaluate_each_candidate_with_independent_complete_output_core",
        outcome="boolean_transform:candidate_output_equality_records",
        confidence=1.0,
        evidence_kind="complete_1344_bit_output_comparison",
        source="independent_bit_sliced_transform_core",
        provenance=[solve_id],
    )
    stats = builder.save(path)
    reader = CryptoCausalReader(path)
    rows = reader.triplets(include_inferred=False)
    if not reader.verify_provenance() or len(rows) != 3:
        raise RuntimeError("R1 partition scaling causal graph gate failed")
    return stats


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--z3", type=Path, default=Path(shutil.which("z3") or "/opt/homebrew/bin/z3")
    )
    parser.add_argument(
        "--a138",
        type=Path,
        default=Path("research/results/v1/shake_symbolic_r1_scaling_reader_v1.json"),
    )
    parser.add_argument(
        "--work-dir", type=Path, default=Path("build/shake-symbolic-r1-partition")
    )
    parser.add_argument("--keep-smt", action="store_true")
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--causal-output", type=Path, required=True)
    args = parser.parse_args()

    a138 = _load_a138(args.a138)
    retained_trial = _a138_unknown_trial(a138)
    retained_smt_sha256 = retained_trial["encoding"]["first_smt_sha256"]

    z3 = Path(shutil.which(str(args.z3)) or args.z3)
    if not z3.is_file():
        raise FileNotFoundError(f"Z3 executable not found: {args.z3}")
    version = subprocess.run(
        [str(z3), "-version"], check=True, capture_output=True, text=True
    ).stdout.strip()

    causal = _build_graph(
        args.causal_output,
        WINDOW_BITS,
        PARTITION_BITS,
        TIMEOUT_SECONDS,
        MAX_WORKERS,
    )
    reader = CryptoCausalReader(args.causal_output)
    variant = _BASE.VARIANTS["shake128"]
    trial = _partition_trial(
        variant,
        WINDOW_BITS,
        SEED,
        PARTITION_BITS,
        TIMEOUT_SECONDS,
        MAX_WORKERS,
        z3,
        args.work_dir,
        args.keep_smt,
        expected_unpartitioned_smt_sha256=retained_smt_sha256,
    )
    payload = {
        "schema": "shake-symbolic-r1-partition-scaling-reader-v1",
        "evidence_stage": "BOUNDED_R1_PARTITION_OBSERVATIONS_RECORDED",
        "result": (
            "The fixed 20-coordinate Boolean system was divided into all 16 "
            "low-four-coordinate subspaces; solver statuses and independent "
            "candidate checks are recorded without outcome selection."
        ),
        "scope": (
            "One hash-gated R1 Boolean transform constraint system, regenerated "
            "for the retained seed and executed under equal local limits."
        ),
        "parameters": {
            "solver": version,
            "worker_processes": MAX_WORKERS,
            "solver_threads_per_worker": 1,
            "timeout_seconds_per_subspace": TIMEOUT_SECONDS,
            "window_bits": WINDOW_BITS,
            "partition_bits": PARTITION_BITS,
            "subspace_count": 1 << PARTITION_BITS,
            "seed": SEED,
            "symbolic_prefix_rounds": 1,
            "a138_sha256": A138_SHA256,
            "a138_20_coordinate_status": "unknown",
            "a138_assignment_used_for_plan_or_generation": False,
        },
        "kat": _BASE._kat(),
        "causal": causal,
        "reader_triplets": reader.triplets(include_inferred=False),
        "trial": trial,
    }
    raw = (json.dumps(payload, indent=2, sort_keys=True) + "\n").encode()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_bytes(raw)
    print(
        json.dumps(
            {
                "output": str(args.output),
                "sha256": hashlib.sha256(raw).hexdigest(),
                "status_counts": trial["status_counts"],
                "found_assignments": trial["found_assignments"],
                "verified_assignments": trial["verified_assignments"],
                "reconstructed_assignment": trial["reconstructed_assignment"],
                "matches_instrumented_assignment": trial[
                    "reconstruction_matches_instrumented_assignment"
                ],
            },
            indent=2,
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    main()

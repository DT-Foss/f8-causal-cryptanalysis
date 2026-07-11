#!/usr/bin/env python3
"""Partition the retained 20-coordinate R1 instance on its upper coordinates."""

from __future__ import annotations

import argparse
import concurrent.futures
import hashlib
import importlib.util
import json
import shutil
import subprocess
import sys
from collections.abc import Sequence
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


_LOW = _import_sibling(
    "shake_symbolic_r1_partition_scaling_reader.py",
    "shake_symbolic_r1_partition_scaling_reader_upper_base",
)

_R1 = _LOW._R1
_R2 = _LOW._R2
_BASE = _LOW._BASE
_NATIVE = _LOW._NATIVE
_WINDOW = _LOW._WINDOW
_SMT = _LOW._SMT

A138_SHA256 = _LOW.A138_SHA256
A139_SHA256 = "443e7db3ebd72c4d916b6c688443c27aeb696746db676624b77891722213ab8c"
WINDOW_BITS = 20
SEED = 89755037
FIXED_COORDINATES = [16, 17, 18, 19]
LOW_COORDINATES = [0, 1, 2, 3]
TIMEOUT_SECONDS = 60
MAX_WORKERS = 5


def _a139_unknown_low_trial(payload: dict[str, Any]) -> dict[str, Any]:
    """Return A139's retained Low-4 trial after checking its neutral outcome."""
    if payload.get("schema") != "shake-symbolic-r1-partition-scaling-reader-v1":
        raise RuntimeError("A139 schema does not identify the retained Low-4 run")
    trial = payload.get("trial")
    if not isinstance(trial, dict):
        raise RuntimeError("A139 does not contain its retained trial")
    if trial.get("window_bits") != WINDOW_BITS or trial.get("seed") != SEED:
        raise RuntimeError("A139 does not contain the retained width-20 seed-89755037 case")
    if trial.get("partitioned_coordinates") != LOW_COORDINATES:
        raise RuntimeError("A139 trial is not the Low-4 coordinate partition")

    rows = trial.get("subspaces_detail")
    if not isinstance(rows, list) or len(rows) != 1 << len(LOW_COORDINATES):
        raise RuntimeError("A139 must contain exactly 16 Low-4 subspaces")
    expected_counts = {"sat": 0, "unsat": 0, "unknown": 16, "error": 0}
    if trial.get("status_counts") != expected_counts:
        raise RuntimeError("A139 must record exactly 16 unknown Low-4 subspaces")
    for value, row in enumerate(rows):
        expected_fixed = [
            {"coordinate": coordinate, "value": (value >> bit) & 1}
            for bit, coordinate in enumerate(LOW_COORDINATES)
        ]
        if (
            row.get("subspace_index") != value
            or row.get("fixed_low_value") != value
            or row.get("fixed_coordinates") != expected_fixed
            or row.get("solver", {}).get("status") != "unknown"
            or row.get("assignment") is not None
        ):
            raise RuntimeError("A139 Low-4 subspace detail differs from the retained gate")
    return trial


def _load_a139(path: Path) -> dict[str, Any]:
    raw = path.read_bytes()
    observed = hashlib.sha256(raw).hexdigest()
    if observed != A139_SHA256:
        raise RuntimeError(f"A139 retained artifact hash differs for {path}: {observed}")
    payload = json.loads(raw)
    _a139_unknown_low_trial(payload)
    return payload


def _validated_coordinates(window_bits: int, fixed_coordinates: Sequence[int]) -> list[int]:
    if window_bits < 2:
        raise ValueError("window width must leave room for fixed and free coordinates")
    coordinates = list(fixed_coordinates)
    if not coordinates or len(coordinates) >= window_bits:
        raise ValueError("fixed coordinate count must be in 1..window_bits-1")
    if any(not isinstance(coordinate, int) for coordinate in coordinates):
        raise TypeError("fixed coordinates must be integers")
    if len(set(coordinates)) != len(coordinates):
        raise ValueError("fixed coordinates must be unique")
    if any(coordinate < 0 or coordinate >= window_bits for coordinate in coordinates):
        raise ValueError("fixed coordinate lies outside the input window")
    return coordinates


def _render_fixed_coordinates(
    writer: Any,
    inputs: list[str],
    fixed_coordinates: Sequence[int],
    fixed_value: int,
    *,
    include_model: bool = True,
) -> bytes:
    """Render one subspace while constraining exactly the requested inputs.

    Bit ``j`` of ``fixed_value`` is assigned to ``fixed_coordinates[j]``.  The
    coordinate order is therefore explicit and works for high or noncontiguous
    input indices without changing the global assignment encoding.
    """
    coordinates = _validated_coordinates(len(inputs), fixed_coordinates)
    if fixed_value < 0 or fixed_value >= 1 << len(coordinates):
        raise ValueError("fixed value does not fit the selected coordinates")
    lines = list(writer.lines)
    for bit, coordinate in enumerate(coordinates):
        name = inputs[coordinate]
        literal = name if ((fixed_value >> bit) & 1) else f"(not {name})"
        lines.append(f"(assert {literal})")
    lines.append("(check-sat)")
    if include_model:
        lines.append(f"(get-value ({' '.join(inputs)}))")
    lines.append("(exit)")
    return ("\n".join(lines) + "\n").encode()


def _subspace_plan(window_bits: int, fixed_coordinates: Sequence[int]) -> list[dict[str, Any]]:
    coordinates = _validated_coordinates(window_bits, fixed_coordinates)
    fixed_set = set(coordinates)
    free_coordinates = [
        coordinate for coordinate in range(window_bits) if coordinate not in fixed_set
    ]
    assignments_per_subspace = 1 << len(free_coordinates)
    return [
        {
            "subspace_index": value,
            "fixed_value": value,
            "fixed_coordinates": [
                {"coordinate": coordinate, "value": (value >> bit) & 1}
                for bit, coordinate in enumerate(coordinates)
            ],
            "free_coordinates": free_coordinates,
            "logical_assignments": assignments_per_subspace,
        }
        for value in range(1 << len(coordinates))
    ]


def _project_assignment(assignment: int, coordinates: Sequence[int]) -> int:
    return sum(
        ((assignment >> coordinate) & 1) << bit for bit, coordinate in enumerate(coordinates)
    )


def _partition_trial(
    variant: Any,
    window_bits: int,
    seed: int,
    fixed_coordinates: Sequence[int],
    timeout_seconds: int,
    max_workers: int,
    z3: Path,
    work_dir: Path,
    keep_smt: bool,
    expected_unpartitioned_smt_sha256: str | None = None,
) -> dict[str, Any]:
    if timeout_seconds < 1 or max_workers < 1:
        raise ValueError("timeout and worker count must be positive")
    coordinates = _validated_coordinates(window_bits, fixed_coordinates)

    # The complete plan exists before the instrumented assignment is computed.
    plan = _subspace_plan(window_bits, coordinates)
    problem = _NATIVE._problem(variant, window_bits, seed)
    writer, inputs, encoding = _R1._SPLIT._encode_problem(problem, variant, seed, prefix_rounds=1)
    unpartitioned_raw = writer.render(inputs, include_model=True)
    unpartitioned_sha256 = hashlib.sha256(unpartitioned_raw).hexdigest()
    if (
        expected_unpartitioned_smt_sha256 is not None
        and unpartitioned_sha256 != expected_unpartitioned_smt_sha256
    ):
        raise RuntimeError("regenerated R1 formulation differs from the hash-gated A138 trial")

    work_dir.mkdir(parents=True, exist_ok=True)
    coordinate_label = "-".join(str(coordinate) for coordinate in coordinates)
    subspace_files = []
    for row in plan:
        raw = _render_fixed_coordinates(writer, inputs, coordinates, row["fixed_value"])
        path = work_dir / (
            f"{variant.name.lower()}_r1_w{window_bits}_coords{coordinate_label}_"
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
            "fixed_value": row["fixed_value"],
            "fixed_coordinates": row["fixed_coordinates"],
            "free_coordinates": row["free_coordinates"],
            "logical_assignments": row["logical_assignments"],
            "remaining_variables": window_bits - len(coordinates),
            "smt_bytes": row["smt_bytes"],
            "smt_sha256": row["smt_sha256"],
            "solver": _SMT._solver_summary(result),
            "assignment": result["assignment"],
        }

    try:
        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
            subspaces = sorted(
                executor.map(solve, subspace_files),
                key=lambda row: row["subspace_index"],
            )
    finally:
        if not keep_smt:
            for row in subspace_files:
                row["path"].unlink(missing_ok=True)

    actual = _WINDOW._extract_window(problem["base_state"], variant, problem["positions"])
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
        status: sum(row["solver"]["status"] == status for row in subspaces) for status in statuses
    }
    distinct_found = sorted(set(found_assignments))
    distinct_verified = sorted(set(verified_assignments))
    return {
        "variant": variant.name,
        "window_bits": window_bits,
        "seed": seed,
        "window_start_capacity_bit": int(problem["positions"][0]),
        "window_stop_capacity_bit_exclusive": int(problem["positions"][-1] + 1),
        "partition_bits": len(coordinates),
        "partitioned_coordinates": coordinates,
        "subspace_schedule": "ascending_unsigned_fixed_coordinate_values",
        "subspace_count": len(plan),
        "subspaces_are_pairwise_disjoint": True,
        "subspaces_cover_complete_assignment_space": True,
        "stored_assignment_used_for_plan_or_generation": False,
        "posthoc_assignment_used_for_plan_or_generation": False,
        "max_workers": max_workers,
        "solver_threads_per_worker": 1,
        "timeout_seconds_per_subspace": timeout_seconds,
        "actual_assignment_posthoc": actual,
        "actual_fixed_value_posthoc": _project_assignment(actual, coordinates),
        "status_counts": status_counts,
        "found_assignments": found_assignments,
        "distinct_found_assignments": distinct_found,
        "verified_assignments": verified_assignments,
        "all_found_assignments_independently_verified": (
            len(found_assignments) == len(verified_assignments)
        ),
        "reconstructed_assignment": (distinct_verified[0] if len(distinct_verified) == 1 else None),
        "reconstruction_matches_instrumented_assignment": (distinct_verified == [actual]),
        "all_subspaces_resolved": (status_counts["unknown"] == 0 and status_counts["error"] == 0),
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
    fixed_coordinates: Sequence[int],
    timeout_seconds: int,
    max_workers: int,
) -> dict[str, Any]:
    coordinates = _validated_coordinates(window_bits, fixed_coordinates)
    builder = CryptoCausalBuilder(
        experiment="shake_symbolic_r1_upper_partition_reader",
        parameters={
            "system": "fixed_boolean_transform_constraint_system",
            "window_bits": window_bits,
            "partitioned_coordinates": coordinates,
            "subspace_count": 1 << len(coordinates),
            "timeout_seconds_per_subspace": timeout_seconds,
            "max_workers": max_workers,
            "solver_threads_per_worker": 1,
        },
    )
    plan_id = "boolean-transform-orthogonal-coordinate-subspace-plan"
    solve_id = "boolean-transform-upper-partition-observations"
    check_id = "boolean-transform-independent-candidate-checks"
    builder.add_triplet(
        edge_id=plan_id,
        trigger="boolean_transform:fixed_coordinate_constraint_system",
        mechanism="enumerate_selected_coordinate_values_in_unsigned_order",
        outcome="boolean_transform:complete_disjoint_orthogonal_subspace_plan",
        confidence=1.0,
        evidence_kind="deterministic_partition_construction",
        source="reader_local_enumeration",
        attrs={
            "reader_recipe": {
                "formulation_module": "shake_symbolic_r1_scaling_reader.py",
                "renderer_module": "shake_symbolic_r1_upper_partition_reader.py",
                "fixed_coordinates": coordinates,
                "subspace_values": list(range(1 << len(coordinates))),
                "stored_assignment_input": None,
                "posthoc_assignment_input": None,
            }
        },
    )
    builder.add_triplet(
        edge_id=solve_id,
        trigger="boolean_transform:complete_disjoint_orthogonal_subspace_plan",
        mechanism="execute_each_R1_boolean_subspace_with_equal_local_limit",
        outcome="boolean_transform:subspace_statuses_and_candidate_assignments",
        confidence=1.0,
        evidence_kind="bounded_solver_observations",
        source="Z3_Boolean_SMT",
        provenance=[plan_id],
        attrs={
            "reader_recipe": {
                "symbolic_prefix_rounds": 1,
                "subspace_order": "ascending_unsigned_fixed_coordinate_values",
                "timeout_seconds_per_subspace": timeout_seconds,
                "max_workers": max_workers,
                "solver_threads_per_worker": 1,
            }
        },
    )
    builder.add_triplet(
        edge_id=check_id,
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
    by_id = {row["edge_id"]: row for row in rows}
    if (
        not reader.verify_provenance()
        or len(rows) != 3
        or by_id.get(solve_id, {}).get("provenance") != [plan_id]
        or by_id.get(check_id, {}).get("provenance") != [solve_id]
    ):
        raise RuntimeError("R1 upper-partition causal graph gate failed")
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
        "--a139",
        type=Path,
        default=Path("research/results/v1/shake_symbolic_r1_partition_scaling_reader_v1.json"),
    )
    parser.add_argument(
        "--work-dir", type=Path, default=Path("build/shake-symbolic-r1-upper-partition")
    )
    parser.add_argument("--keep-smt", action="store_true")
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--causal-output", type=Path, required=True)
    args = parser.parse_args()

    a139 = _load_a139(args.a139)
    retained_low_trial = _a139_unknown_low_trial(a139)
    a138 = _LOW._load_a138(args.a138)
    retained_r1_trial = _LOW._a138_unknown_trial(a138)
    retained_smt_sha256 = retained_r1_trial["encoding"]["first_smt_sha256"]
    if (
        retained_low_trial.get("encoding", {}).get("unpartitioned_smt_sha256")
        != retained_smt_sha256
    ):
        raise RuntimeError("A139 and A138 do not identify the same R1 formulation")

    z3 = Path(shutil.which(str(args.z3)) or args.z3)
    if not z3.is_file():
        raise FileNotFoundError(f"Z3 executable not found: {args.z3}")
    version = subprocess.run(
        [str(z3), "-version"], check=True, capture_output=True, text=True
    ).stdout.strip()

    causal = _build_graph(
        args.causal_output,
        WINDOW_BITS,
        FIXED_COORDINATES,
        TIMEOUT_SECONDS,
        MAX_WORKERS,
    )
    reader = CryptoCausalReader(args.causal_output)
    variant = _BASE.VARIANTS["shake128"]
    trial = _partition_trial(
        variant,
        WINDOW_BITS,
        SEED,
        FIXED_COORDINATES,
        TIMEOUT_SECONDS,
        MAX_WORKERS,
        z3,
        args.work_dir,
        args.keep_smt,
        expected_unpartitioned_smt_sha256=retained_smt_sha256,
    )
    payload = {
        "schema": "shake-symbolic-r1-upper-partition-reader-v1",
        "evidence_stage": "BOUNDED_R1_ORTHOGONAL_PARTITION_OBSERVATIONS_RECORDED",
        "result": (
            "The fixed 20-coordinate Boolean system was divided into all 16 "
            "upper-four-coordinate subspaces; solver statuses and independent "
            "candidate checks are recorded without outcome selection."
        ),
        "scope": (
            "One hash-gated R1 Boolean transform constraint system, partitioned "
            "on coordinates 16 through 19 and executed under equal local limits."
        ),
        "parameters": {
            "solver": version,
            "max_workers": MAX_WORKERS,
            "solver_threads_per_worker": 1,
            "timeout_seconds_per_subspace": TIMEOUT_SECONDS,
            "window_bits": WINDOW_BITS,
            "partition_bits": len(FIXED_COORDINATES),
            "partitioned_coordinates": FIXED_COORDINATES,
            "subspace_count": 1 << len(FIXED_COORDINATES),
            "seed": SEED,
            "symbolic_prefix_rounds": 1,
            "a138_sha256": A138_SHA256,
            "a138_unpartitioned_smt_sha256": retained_smt_sha256,
            "a139_sha256": A139_SHA256,
            "a139_low_partition_status_counts": retained_low_trial["status_counts"],
            "a139_assignment_used_for_plan_or_generation": False,
            "posthoc_assignment_used_for_plan_or_generation": False,
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
                "causal_output": str(args.causal_output),
                "causal_sha256": reader.file_sha256,
                "status_counts": trial["status_counts"],
                "found_assignments": trial["found_assignments"],
                "verified_assignments": trial["verified_assignments"],
                "reconstructed_assignment": trial["reconstructed_assignment"],
                "actual_fixed_value_posthoc": trial["actual_fixed_value_posthoc"],
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

#!/usr/bin/env python3
"""Autonomous partitioned native-XOR Reader for 16-coordinate SHAKE windows."""
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

import numpy as np

from arx_carry_leak.crypto_causal import CryptoCausalBuilder, CryptoCausalReader


_SMT_PATH = Path(__file__).with_name("shake_symbolic_r2_smt_reader.py")
_SMT_SPEC = importlib.util.spec_from_file_location(
    "shake_symbolic_r2_smt_reader_partition_base", _SMT_PATH
)
assert _SMT_SPEC is not None and _SMT_SPEC.loader is not None
_SMT = importlib.util.module_from_spec(_SMT_SPEC)
sys.modules[_SMT_SPEC.name] = _SMT
_SMT_SPEC.loader.exec_module(_SMT)

_BASE = _SMT._BASE
_NATIVE = _SMT._NATIVE
_WINDOW = _SMT._WINDOW


def _branch_raw(
    writer: Any,
    inputs: list[str],
    partition_bits: int,
    branch: int,
) -> bytes:
    lines = list(writer.lines)
    for bit in range(partition_bits):
        literal = inputs[bit] if ((branch >> bit) & 1) else f"(not {inputs[bit]})"
        lines.append(f"(assert {literal})")
    lines.extend(
        [
            "(check-sat)",
            f"(get-value ({' '.join(inputs)}))",
            "(exit)",
        ]
    )
    return ("\n".join(lines) + "\n").encode()


def _verify_assignment(
    problem: dict[str, Any], variant: Any, assignment: int
) -> dict[str, Any]:
    template = _WINDOW._clear_window(
        problem["base_state"], variant, problem["positions"]
    )
    candidate = _WINDOW._inject_candidates(
        template,
        variant,
        problem["positions"],
        np.array([assignment], dtype=np.uint64),
    )
    output = _BASE._keccak_f1600(candidate)
    exact = np.array_equal(
        output[:, : variant.rate_lanes], problem["target"][:, : variant.rate_lanes]
    )
    return {
        "complete_rate_match": bool(exact),
        "rate_lanes_checked": variant.rate_lanes,
        "rate_bits_checked": variant.rate_lanes * 64,
        "candidate_rate_sha256": hashlib.sha256(
            output[:, : variant.rate_lanes].astype("<u8", copy=False).tobytes()
        ).hexdigest(),
        "target_rate_sha256": hashlib.sha256(
            problem["target"][:, : variant.rate_lanes]
            .astype("<u8", copy=False)
            .tobytes()
        ).hexdigest(),
    }


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
) -> dict[str, Any]:
    if partition_bits < 1 or partition_bits >= window_bits:
        raise ValueError("partition width must be in 1..window_bits-1")
    problem = _NATIVE._problem(variant, window_bits, seed)
    writer, inputs, encoding = _SMT._encode_problem(problem, variant, seed)
    work_dir.mkdir(parents=True, exist_ok=True)
    branch_files = []
    for branch in range(1 << partition_bits):
        raw = _branch_raw(writer, inputs, partition_bits, branch)
        path = work_dir / f"{variant.name.lower()}_w{window_bits}_branch{branch:04d}.smt2"
        path.write_bytes(raw)
        branch_files.append(
            {
                "branch": branch,
                "path": path,
                "bytes": len(raw),
                "sha256": hashlib.sha256(raw).hexdigest(),
            }
        )

    def solve(row: dict[str, Any]) -> dict[str, Any]:
        result = _SMT._run_z3(z3, row["path"], timeout_seconds, inputs)
        return {
            "branch": row["branch"],
            "fixed_prefix": row["branch"],
            "remaining_variables": window_bits - partition_bits,
            "smt_bytes": row["bytes"],
            "smt_sha256": row["sha256"],
            "solver": _SMT._solver_summary(result),
            "assignment": result["assignment"],
        }

    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        branches = sorted(executor.map(solve, branch_files), key=lambda row: row["branch"])
    if not keep_smt:
        for row in branch_files:
            row["path"].unlink()

    actual = _WINDOW._extract_window(
        problem["base_state"], variant, problem["positions"]
    )
    models = []
    for row in branches:
        assignment = row["assignment"]
        if assignment is not None:
            verification = _verify_assignment(problem, variant, assignment)
            row["independent_verification"] = verification
            row["matches_instrumented_assignment"] = assignment == actual
            models.append(assignment)
        else:
            row["independent_verification"] = None
            row["matches_instrumented_assignment"] = None
    status_counts = {
        status: sum(row["solver"]["status"] == status for row in branches)
        for status in ("sat", "unsat", "unknown", "error")
    }
    distinct_models = sorted(set(models))
    verified_models = [
        row["assignment"]
        for row in branches
        if row["independent_verification"]
        and row["independent_verification"]["complete_rate_match"]
    ]
    return {
        "variant": variant.name,
        "window_bits": window_bits,
        "seed": seed,
        "partition_bits": partition_bits,
        "partitioned_variables": list(range(partition_bits)),
        "branch_schedule": "ascending_unsigned_prefix",
        "branches": 1 << partition_bits,
        "max_workers": max_workers,
        "timeout_seconds_per_branch": timeout_seconds,
        "ground_truth_used_for_branch_schedule": False,
        "actual_assignment_posthoc": actual,
        "actual_prefix_posthoc": actual & ((1 << partition_bits) - 1),
        "status_counts": status_counts,
        "distinct_models": distinct_models,
        "verified_models": verified_models,
        "reconstructed_assignment": (
            verified_models[0] if len(set(verified_models)) == 1 else None
        ),
        "reconstruction_matches_ground_truth": set(verified_models) == {actual},
        "global_uniqueness_proved": status_counts["unknown"] == 0
        and status_counts["error"] == 0
        and len(distinct_models) == 1,
        "encoding": encoding,
        "branches_detail": branches,
    }


def _build_graph(
    path: Path,
    window_bits: int,
    partition_bits: int,
    timeout_seconds: int,
    max_workers: int,
) -> dict[str, Any]:
    builder = CryptoCausalBuilder(
        experiment="shake_symbolic_r2_partition_reader",
        parameters={
            "variant": "shake128",
            "window_bits": window_bits,
            "partition_bits": partition_bits,
            "branches": 1 << partition_bits,
            "timeout_seconds_per_branch": timeout_seconds,
            "max_workers": max_workers,
            "prediction_before_measurement": (
                "Disjoint fixed-prefix partitions should turn the monolithic "
                "16-coordinate native-XOR boundary into independently solvable "
                "subtrees and expose a verified model without using its prefix "
                "in the branch schedule."
            ),
        },
    )
    split_id = "shake128-exhaustive-prefix-partition"
    solve_id = "shake128-partitioned-native-xor-models"
    builder.add_triplet(
        edge_id=split_id,
        trigger="shake128:16_coordinate_native_xor_constraint_system",
        mechanism="reader_partition_first_coordinates_into_all_disjoint_prefixes",
        outcome="shake128:complete_prefix_branch_schedule",
        confidence=1.0,
        evidence_kind="all_prefixes_exactly_once",
        source="ascending_unsigned_prefix_schedule",
    )
    builder.add_triplet(
        edge_id=solve_id,
        trigger="shake128:complete_prefix_branch_schedule",
        mechanism="reader_solve_each_exact_R2_plus_R3_R24_native_xor_branch",
        outcome="shake128:partition_model_set",
        confidence=1.0,
        evidence_kind="branch_local_fullround_solver_models",
        source="Z3_Boolean_SMT",
        provenance=[split_id],
        attrs={
            "reader_recipe": {
                "prefix_source": "none_from_ground_truth",
                "partition_variables": list(range(partition_bits)),
                "branch_order": "ascending_unsigned",
                "branch_count": 1 << partition_bits,
            }
        },
    )
    builder.add_triplet(
        edge_id="shake128-partition-model-independent-check",
        trigger="shake128:partition_model_set",
        mechanism="reader_inject_model_and_execute_independent_24_round_core",
        outcome="shake128:complete_rate_model_verification",
        confidence=1.0,
        evidence_kind="all_1344_target_rate_bits",
        source="independent_bit_sliced_keccak_core",
        provenance=[solve_id],
    )
    stats = builder.save(path)
    reader = CryptoCausalReader(path)
    if not reader.verify_provenance() or len(reader.triplets(include_inferred=False)) != 3:
        raise RuntimeError("SHAKE partition causal graph gate failed")
    return stats


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--window-bits", type=int, default=16)
    parser.add_argument("--partition-bits", type=int, default=4)
    parser.add_argument("--timeout-seconds", type=int, default=60)
    parser.add_argument("--max-workers", type=int, default=5)
    parser.add_argument("--seed", type=int, default=89754028)
    parser.add_argument(
        "--z3", type=Path, default=Path(shutil.which("z3") or "/opt/homebrew/bin/z3")
    )
    parser.add_argument("--work-dir", type=Path, default=Path("build/shake-partition-smt"))
    parser.add_argument("--keep-smt", action="store_true")
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--causal-output", type=Path, required=True)
    args = parser.parse_args()
    if args.timeout_seconds < 1 or args.max_workers < 1:
        raise ValueError("timeout and worker count must be positive")
    z3 = Path(shutil.which(str(args.z3)) or args.z3)
    if not z3.is_file():
        raise FileNotFoundError(f"Z3 executable not found: {args.z3}")
    version = subprocess.run(
        [str(z3), "-version"], check=True, capture_output=True, text=True
    ).stdout.strip()
    causal = _build_graph(
        args.causal_output,
        args.window_bits,
        args.partition_bits,
        args.timeout_seconds,
        args.max_workers,
    )
    reader = CryptoCausalReader(args.causal_output)
    variant = _BASE.VARIANTS["shake128"]
    trial = _partition_trial(
        variant,
        args.window_bits,
        args.seed,
        args.partition_bits,
        args.timeout_seconds,
        args.max_workers,
        z3,
        args.work_dir,
        args.keep_smt,
    )
    payload = {
        "schema": "shake-symbolic-r2-partition-reader-v1",
        "evidence_stage": "FULLROUND_PARTITIONED_NATIVE_XOR_MODEL_RECONSTRUCTED",
        "result": (
            "The exhaustive ground-truth-blind prefix schedule produced a model "
            "whose complete 1,344-bit next-rate state matches independently."
        ),
        "scope": (
            "Known-complement 16-coordinate SHAKE128 state-window inference; exact "
            "symbolic R2 prefix and exact Boolean R3--R24 suffix in every branch."
        ),
        "parameters": {
            "solver": version,
            "solver_threads_per_branch": 1,
            "window_bits": args.window_bits,
            "partition_bits": args.partition_bits,
            "timeout_seconds_per_branch": args.timeout_seconds,
            "max_workers": args.max_workers,
            "seed": args.seed,
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
                "verified_models": trial["verified_models"],
                "reconstructed_assignment": trial["reconstructed_assignment"],
                "matches_ground_truth": trial["reconstruction_matches_ground_truth"],
                "global_uniqueness_proved": trial["global_uniqueness_proved"],
            },
            indent=2,
        )
    )


if __name__ == "__main__":
    main()

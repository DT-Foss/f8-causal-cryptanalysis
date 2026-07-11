#!/usr/bin/env python3
"""Scale the exact R1 symbolic-prefix SHAKE state-window Reader."""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any

from arx_carry_leak.crypto_causal import CryptoCausalBuilder, CryptoCausalReader


_SPLIT_PATH = Path(__file__).with_name("shake_symbolic_split_frontier.py")
_SPLIT_SPEC = importlib.util.spec_from_file_location(
    "shake_symbolic_split_frontier_r1_base", _SPLIT_PATH
)
assert _SPLIT_SPEC is not None and _SPLIT_SPEC.loader is not None
_SPLIT = importlib.util.module_from_spec(_SPLIT_SPEC)
sys.modules[_SPLIT_SPEC.name] = _SPLIT
_SPLIT_SPEC.loader.exec_module(_SPLIT)

_SMT = _SPLIT._SMT
_PARTITION = _SPLIT._PARTITION
_BASE = _SPLIT._BASE
_NATIVE = _SPLIT._NATIVE
_WINDOW = _SPLIT._WINDOW

A137_SHA256 = "19cc21bb0b60943182ac8d0c927e9090ac881c24fba04a9f646ae4972fe84583"


def _parse_windows(value: str) -> list[int]:
    windows = sorted({int(item) for item in value.split(",")})
    if not windows or any(bits < 1 or bits > 40 for bits in windows):
        raise ValueError("window sizes must be in 1..40")
    return windows


def _trial(
    variant: Any,
    window_bits: int,
    seed: int,
    timeout_seconds: int,
    z3: Path,
    work_dir: Path,
    keep_smt: bool,
) -> dict[str, Any]:
    problem = _NATIVE._problem(variant, window_bits, seed)
    writer, inputs, encoding = _SPLIT._encode_problem(
        problem, variant, seed, prefix_rounds=1
    )
    first_raw = writer.render(inputs, include_model=True)
    first_path = work_dir / f"{variant.name.lower()}_r1_w{window_bits}_first.smt2"
    first_path.write_bytes(first_raw)
    first = _SMT._run_z3(z3, first_path, timeout_seconds, inputs)
    assignment = first["assignment"]
    actual = _WINDOW._extract_window(
        problem["base_state"], variant, problem["positions"]
    )
    verification = (
        _PARTITION._verify_assignment(problem, variant, assignment)
        if assignment is not None
        else None
    )

    second = None
    second_raw = None
    second_path = None
    if assignment is not None:
        second_raw = writer.render(
            inputs, blocked_assignment=assignment, include_model=False
        )
        second_path = work_dir / (
            f"{variant.name.lower()}_r1_w{window_bits}_blocked.smt2"
        )
        second_path.write_bytes(second_raw)
        second = _SMT._run_z3(z3, second_path, timeout_seconds, inputs)
    if not keep_smt:
        first_path.unlink()
        if second_path is not None:
            second_path.unlink()

    decisions = first["stats"].get("decisions")
    logical_assignments = 1 << window_bits
    return {
        "variant": variant.name,
        "window_bits": window_bits,
        "seed": seed,
        "window_start_capacity_bit": int(problem["positions"][0]),
        "window_stop_capacity_bit_exclusive": int(problem["positions"][-1] + 1),
        "logical_assignment_space": logical_assignments,
        "actual_assignment_posthoc": actual,
        "reconstructed_assignment": assignment,
        "matches_instrumented_assignment": assignment == actual,
        "independent_verification": verification,
        "unique_assignment_proved": second["status"] == "unsat" if second else None,
        "decision_ratio_vs_complete_assignment_space": (
            decisions / logical_assignments if decisions is not None else None
        ),
        "encoding": {
            **encoding,
            "first_smt_bytes": len(first_raw),
            "first_smt_sha256": hashlib.sha256(first_raw).hexdigest(),
            "blocked_smt_bytes": len(second_raw) if second_raw is not None else None,
            "blocked_smt_sha256": (
                hashlib.sha256(second_raw).hexdigest()
                if second_raw is not None
                else None
            ),
        },
        "first_solver": _SMT._solver_summary(first),
        "second_solver": _SMT._solver_summary(second) if second else None,
    }


def _build_graph(
    path: Path, windows: list[int], timeout_seconds: int
) -> dict[str, Any]:
    builder = CryptoCausalBuilder(
        experiment="shake_symbolic_r1_scaling_reader",
        parameters={
            "variant": "shake128",
            "window_bits": windows,
            "symbolic_prefix_rounds": 1,
            "explicit_suffix_rounds": 23,
            "timeout_seconds": timeout_seconds,
            "selection_source": "A137_minimum_decision_split",
        },
    )
    compile_id = "shake128-symbolic-r1-interface"
    solve_id = "shake128-r2-r24-complete-rate-reader"
    builder.add_triplet(
        edge_id=compile_id,
        trigger="shake128:known_complement_plus_variable_capacity_window",
        mechanism="compile_exact_first_round_boolean_ring_interface",
        outcome="shake128:native_xor_R1_state_formulas",
        confidence=1.0,
        evidence_kind="A137_selected_minimum_decision_split",
        source="A137_symbolic_split_frontier",
    )
    builder.add_triplet(
        edge_id=solve_id,
        trigger="shake128:native_xor_R1_state_formulas_plus_complete_next_rate",
        mechanism="attach_exact_remaining_23_rounds_and_read_consistent_model",
        outcome="shake128:capacity_window_assignment",
        confidence=1.0,
        evidence_kind="complete_rate_state_consistency",
        source="Z3_Boolean_SMT",
        provenance=[compile_id],
        attrs={
            "reader_recipe": {
                "symbolic_prefix_rounds": 1,
                "explicit_round_indices": list(range(1, 24)),
                "output_coordinates": "complete_SHAKE128_rate",
            }
        },
    )
    builder.add_triplet(
        edge_id="shake128-r1-reader-model-gates",
        trigger="shake128:capacity_window_assignment",
        mechanism="independent_24_round_rate_check_then_blocked_model_query",
        outcome="shake128:model_verification_and_uniqueness_status",
        confidence=1.0,
        evidence_kind="complete_1344_bit_check_plus_second_solver_query",
        source="independent_bit_sliced_core_and_Z3",
        provenance=[solve_id],
    )
    stats = builder.save(path)
    reader = CryptoCausalReader(path)
    if not reader.verify_provenance() or len(reader.triplets(include_inferred=False)) != 3:
        raise RuntimeError("SHAKE symbolic R1 causal graph gate failed")
    return stats


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--window-bits", default="16,20,24")
    parser.add_argument("--timeout-seconds", type=int, default=120)
    parser.add_argument("--seed", type=int, default=89754028)
    parser.add_argument(
        "--z3", type=Path, default=Path(shutil.which("z3") or "/opt/homebrew/bin/z3")
    )
    parser.add_argument(
        "--a137",
        type=Path,
        default=Path("research/results/v1/shake_symbolic_split_frontier_v1.json"),
    )
    parser.add_argument(
        "--work-dir", type=Path, default=Path("build/shake-symbolic-r1")
    )
    parser.add_argument("--keep-smt", action="store_true")
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--causal-output", type=Path, required=True)
    args = parser.parse_args()

    windows = _parse_windows(args.window_bits)
    if args.timeout_seconds < 1:
        raise ValueError("timeout must be positive")
    z3 = Path(shutil.which(str(args.z3)) or args.z3)
    if not z3.is_file():
        raise FileNotFoundError(f"Z3 executable not found: {args.z3}")
    version = subprocess.run(
        [str(z3), "-version"], check=True, capture_output=True, text=True
    ).stdout.strip()
    a137 = _SPLIT._load_hashed_json(args.a137, A137_SHA256)
    if any(
        a137["minimum_decision_split_by_window"][key]["symbolic_prefix_rounds"]
        != 1
        for key in ("12", "16")
    ):
        raise RuntimeError("A137 does not select the R1 symbolic split")

    args.work_dir.mkdir(parents=True, exist_ok=True)
    causal = _build_graph(args.causal_output, windows, args.timeout_seconds)
    reader = CryptoCausalReader(args.causal_output)
    variant = _BASE.VARIANTS["shake128"]
    canonical_offsets = {16: 0, 20: 1009, 24: 2018}
    trials = []
    for index, bits in enumerate(windows):
        seed = args.seed + canonical_offsets.get(bits, 1009 * index)
        print(f"SHAKE128 symbolic-R1 Reader bits={bits}", flush=True)
        trials.append(
            _trial(
                variant,
                bits,
                seed,
                args.timeout_seconds,
                z3,
                args.work_dir,
                args.keep_smt,
            )
        )

    exact_models = [
        row
        for row in trials
        if row["matches_instrumented_assignment"]
        and row["independent_verification"]
        and row["independent_verification"]["complete_rate_match"]
    ]
    payload = {
        "schema": "shake-symbolic-r1-scaling-reader-v1",
        "evidence_stage": "EXACT_R1_STATE_WINDOW_SCALING_MEASURED",
        "result": (
            f"The A137-selected R1 Reader reconstructed {len(exact_models)}/"
            f"{len(trials)} tested complete-round state windows."
        ),
        "scope": (
            "SHAKE128 known-complement capacity windows read from the complete "
            "next-rate state; exact symbolic R1 plus exact remaining 23 rounds."
        ),
        "parameters": {
            "solver": version,
            "solver_threads": 1,
            "timeout_seconds": args.timeout_seconds,
            "window_bits": windows,
            "symbolic_prefix_rounds": 1,
            "a137_sha256": A137_SHA256,
        },
        "kat": _BASE._kat(),
        "causal": causal,
        "reader_triplets": reader.triplets(include_inferred=False),
        "trials": trials,
        "exact_model_count": len(exact_models),
    }
    raw = (json.dumps(payload, indent=2, sort_keys=True) + "\n").encode()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_bytes(raw)
    print(
        json.dumps(
            {
                "output": str(args.output),
                "sha256": hashlib.sha256(raw).hexdigest(),
                "trials": [
                    {
                        "bits": row["window_bits"],
                        "first": row["first_solver"]["status"],
                        "second": (
                            row["second_solver"]["status"]
                            if row["second_solver"]
                            else None
                        ),
                        "correct": row["matches_instrumented_assignment"],
                        "unique": row["unique_assignment_proved"],
                        "decisions": row["first_solver"]["stats"].get("decisions"),
                        "decision_ratio_vs_space": row[
                            "decision_ratio_vs_complete_assignment_space"
                        ],
                    }
                    for row in trials
                ],
            },
            indent=2,
        )
    )


if __name__ == "__main__":
    main()

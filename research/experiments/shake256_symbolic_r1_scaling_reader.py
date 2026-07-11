#!/usr/bin/env python3
"""Run the hash-gated R1 symbolic-window comparison on SHAKE256."""

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
    "shake_symbolic_r1_scaling_reader_shake256_transfer_base",
)

_BASE = _R1._BASE
_parse_windows = _R1._parse_windows
_trial = _R1._trial

A137_SHA256 = _R1.A137_SHA256
CANONICAL_WINDOWS = (16, 20, 24)
TIMEOUT_SECONDS = 120
BASE_SEED = 89757055
SEED_STEP = 1009
OUTPUT_PATH = Path("research/results/v1/shake256_symbolic_r1_scaling_reader_v1.json")
CAUSAL_OUTPUT_PATH = Path("research/results/v1/shake256_symbolic_r1_scaling_reader_v1.causal")


def _seed_plan(windows: list[int], base_seed: int = BASE_SEED) -> list[dict[str, int]]:
    """Assign stable canonical seeds, independent of window ordering or subsets."""
    canonical_offsets = {bits: index * SEED_STEP for index, bits in enumerate(CANONICAL_WINDOWS)}
    return [
        {
            "window_bits": bits,
            "seed": base_seed + canonical_offsets.get(bits, index * SEED_STEP),
        }
        for index, bits in enumerate(windows)
    ]


def _load_a137(path: Path) -> dict[str, Any]:
    payload = _R1._SPLIT._load_hashed_json(path, A137_SHA256)
    if payload.get("schema") != "shake-symbolic-prefix-split-frontier-v1":
        raise RuntimeError("A137 schema does not identify the symbolic split frontier")
    selections = payload.get("minimum_decision_split_by_window")
    if not isinstance(selections, dict) or any(
        selections.get(key, {}).get("symbolic_prefix_rounds") != 1 for key in ("12", "16")
    ):
        raise RuntimeError("A137 does not select R1 for both retained windows")
    return payload


def _shake256_trial(
    window_bits: int,
    seed: int,
    timeout_seconds: int,
    z3: Path,
    work_dir: Path,
    keep_smt: bool,
) -> dict[str, Any]:
    """Delegate unchanged trial mechanics to the retained R1 implementation."""
    row = _trial(
        _BASE.VARIANTS["shake256"],
        window_bits,
        seed,
        timeout_seconds,
        z3,
        work_dir,
        keep_smt,
    )
    verification = row["independent_verification"]
    if verification is not None and (
        verification["rate_lanes_checked"] != 17 or verification["rate_bits_checked"] != 1088
    ):
        raise RuntimeError("SHAKE256 independent verification is not complete-rate")
    return row


def _build_graph(path: Path, windows: list[int], timeout_seconds: int) -> dict[str, Any]:
    builder = CryptoCausalBuilder(
        experiment="shake256_symbolic_r1_scaling_reader",
        parameters={
            "variant": "shake256",
            "window_bits": windows,
            "symbolic_prefix_rounds": 1,
            "explicit_suffix_rounds": 23,
            "complete_rate_lanes": 17,
            "complete_rate_bits": 1088,
            "timeout_seconds": timeout_seconds,
            "transfer_hypothesis_source": "A137_SHAKE128_R1_selection",
            "a137_sha256": A137_SHA256,
        },
    )
    transfer_id = "shake256-r1-transfer-hypothesis-instance"
    query_id = "shake256-r1-model-query-observations"
    builder.add_triplet(
        edge_id=transfer_id,
        trigger="shake256:known_complement_plus_variable_capacity_window",
        mechanism="instantiate_A137_R1_choice_as_transfer_hypothesis",
        outcome="shake256:R1_boolean_constraint_instance",
        confidence=1.0,
        evidence_kind="hash_gated_transfer_hypothesis_configuration",
        source="A137_SHAKE128_symbolic_split_frontier",
        attrs={
            "reader_recipe": {
                "formulation_module": "shake_symbolic_r1_scaling_reader.py",
                "source_variant": "shake128",
                "target_variant": "shake256",
                "transferred_symbolic_prefix_rounds": 1,
                "transfer_role": "hypothesis_not_prior_SHAKE256_evidence",
            }
        },
    )
    builder.add_triplet(
        edge_id=query_id,
        trigger="shake256:R1_boolean_constraint_instance_plus_complete_next_rate",
        mechanism="run_first_query_then_assignment_blocked_query_when_available",
        outcome="shake256:model_and_solver_status_records",
        confidence=1.0,
        evidence_kind="bounded_deterministic_solver_observations",
        source="Z3_Boolean_SMT",
        provenance=[transfer_id],
        attrs={
            "reader_recipe": {
                "trial_function": "shake_symbolic_r1_scaling_reader._trial",
                "symbolic_prefix_rounds": 1,
                "explicit_round_indices": list(range(1, 24)),
                "output_coordinates": "complete_SHAKE256_rate",
                "output_lanes": 17,
                "output_bits": 1088,
                "second_query": "block_first_assignment_if_model_is_available",
            }
        },
    )
    check_id = "shake256-r1-independent-complete-rate-check"
    builder.add_triplet(
        edge_id=check_id,
        trigger="shake256:model_and_solver_status_records",
        mechanism="evaluate_candidate_with_independent_24_round_complete_rate_core",
        outcome="shake256:complete_rate_equality_and_uniqueness_records",
        confidence=1.0,
        evidence_kind="complete_17_lane_1088_bit_comparison",
        source="independent_numpy_keccak_f1600_core",
        provenance=[query_id],
    )
    stats = builder.save(path)
    reader = CryptoCausalReader(path)
    rows = reader.triplets(include_inferred=False)
    by_id = {row["edge_id"]: row for row in rows}
    if (
        not reader.verify_provenance()
        or len(rows) != 3
        or len(reader.triplets()) != 3
        or by_id.get(query_id, {}).get("provenance") != [transfer_id]
        or by_id.get(check_id, {}).get("provenance") != [query_id]
    ):
        raise RuntimeError("SHAKE256 symbolic R1 causal graph gate failed")
    return stats


def _deterministic_json_bytes(payload: dict[str, Any]) -> bytes:
    return (json.dumps(payload, indent=2, sort_keys=True, allow_nan=False) + "\n").encode("utf-8")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--window-bits", default="16,20,24")
    parser.add_argument("--timeout-seconds", type=int, default=TIMEOUT_SECONDS)
    parser.add_argument("--seed", type=int, default=BASE_SEED)
    parser.add_argument(
        "--z3", type=Path, default=Path(shutil.which("z3") or "/opt/homebrew/bin/z3")
    )
    parser.add_argument(
        "--a137",
        type=Path,
        default=Path("research/results/v1/shake_symbolic_split_frontier_v1.json"),
    )
    parser.add_argument("--work-dir", type=Path, default=Path("build/shake256-symbolic-r1"))
    parser.add_argument("--keep-smt", action="store_true")
    parser.add_argument("--output", type=Path, default=OUTPUT_PATH)
    parser.add_argument("--causal-output", type=Path, default=CAUSAL_OUTPUT_PATH)
    args = parser.parse_args()

    windows = _parse_windows(args.window_bits)
    if args.timeout_seconds < 1:
        raise ValueError("timeout must be positive")
    seed_plan = _seed_plan(windows, args.seed)
    a137 = _load_a137(args.a137)

    z3 = Path(shutil.which(str(args.z3)) or args.z3)
    if not z3.is_file():
        raise FileNotFoundError(f"Z3 executable not found: {args.z3}")
    version = subprocess.run(
        [str(z3), "-version"], check=True, capture_output=True, text=True
    ).stdout.strip()

    args.work_dir.mkdir(parents=True, exist_ok=True)
    causal = _build_graph(args.causal_output, windows, args.timeout_seconds)
    reader = CryptoCausalReader(args.causal_output)
    trials = []
    for item in seed_plan:
        bits = item["window_bits"]
        seed = item["seed"]
        print(f"SHAKE256 symbolic-R1 comparison bits={bits}", flush=True)
        trials.append(
            _shake256_trial(
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
    unique_models = [row for row in exact_models if row["unique_assignment_proved"]]
    payload = {
        "schema": "shake256-symbolic-r1-scaling-reader-v1",
        "evidence_stage": "NEUTRAL_SHAKE256_R1_TRANSFER_COMPARISON_RECORDED",
        "result": (
            f"Recorded {len(trials)} SHAKE256 trials under the hash-gated A137 "
            "R1 transfer hypothesis; per-trial solver and verification statuses "
            "are retained without importing a SHAKE128 outcome."
        ),
        "scope": (
            "SHAKE256 known-complement capacity windows constrained by the complete "
            "next-rate state; exact symbolic R1 plus exact remaining 23 rounds."
        ),
        "transfer_hypothesis": {
            "source_artifact": "A137",
            "source_artifact_schema": a137["schema"],
            "source_artifact_sha256": A137_SHA256,
            "source_variant": "SHAKE128",
            "target_variant": "SHAKE256",
            "transferred_choice": "symbolic_prefix_rounds=1",
            "role": "R1_carried_forward_as_transfer_hypothesis_only",
            "source_selection_windows": [12, 16],
            "target_windows": windows,
            "SHAKE128_outcome_imported": False,
        },
        "parameters": {
            "variant": "shake256",
            "solver": version,
            "solver_threads": 1,
            "timeout_seconds_per_query": args.timeout_seconds,
            "window_bits": windows,
            "seed_plan": seed_plan,
            "symbolic_prefix_rounds": 1,
            "explicit_suffix_rounds": 23,
            "complete_rate_lanes": 17,
            "complete_rate_bits": 1088,
            "first_query": "model_query",
            "second_query": "blocked_assignment_query_when_model_available",
            "a137_sha256": A137_SHA256,
        },
        "kat": _BASE._kat(),
        "causal": causal,
        "reader_triplets": reader.triplets(include_inferred=False),
        "trials": trials,
        "exact_model_count": len(exact_models),
        "unique_exact_model_count": len(unique_models),
    }
    raw = _deterministic_json_bytes(payload)
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
                            row["second_solver"]["status"] if row["second_solver"] else None
                        ),
                        "complete_rate_match": (
                            row["independent_verification"]["complete_rate_match"]
                            if row["independent_verification"]
                            else None
                        ),
                        "unique": row["unique_assignment_proved"],
                    }
                    for row in trials
                ],
            },
            indent=2,
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    main()

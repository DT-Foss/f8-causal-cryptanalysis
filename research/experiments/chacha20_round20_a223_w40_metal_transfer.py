#!/usr/bin/env python3
"""Prospective transfer of the fixed A224 trajectory readout to A223-W40."""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import sys
from collections.abc import Sequence
from pathlib import Path
from typing import Any

import numpy as np

ROOT = Path(__file__).parents[2]
RESEARCH = ROOT / "research"


def _import_sibling(filename: str, module_name: str) -> Any:
    path = Path(__file__).with_name(filename)
    spec = importlib.util.spec_from_file_location(module_name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


A224 = _import_sibling(
    "chacha20_round20_a223_w32_metal_label.py",
    "a225_fixed_a224_reader",
)
A184 = A224.A184
A223 = A224.A223
A119 = A224.A119

ATTEMPT_ID = "R20-A225-A223-W40-METAL-TRANSFER-V1"
SCHEMA = "chacha20-round20-a223-w40-metal-transfer-v1"
RESULT_FILENAME = "chacha20_round20_a223_w40_metal_transfer_v1.json"
REPORT_FILENAME = "CAUSAL_CHACHA20_ROUND20_A223_W40_METAL_TRANSFER_V1.md"
CHECKPOINT_FILENAME = "chacha20_round20_a223_w40_metal_transfer_v1.checkpoint.json"

CONFIG_PATH = A224.CONFIG_PATH
A223_RESULT_PATH = A224.A223_RESULT_PATH
A224_SOURCE_PATH = Path(A224.__file__)
A224_RESULT_PATH = A224.DEFAULT_RESULT_PATH
DEFAULT_RESULT_PATH = RESEARCH / "results" / "v1" / RESULT_FILENAME
DEFAULT_REPORT_PATH = RESEARCH / "reports" / REPORT_FILENAME
DEFAULT_CHECKPOINT_PATH = RESEARCH / "results" / "v1" / CHECKPOINT_FILENAME
DEFAULT_BUILD_DIR = RESEARCH / "artifacts" / "a225_w40_metal_transfer_v1"

WIDTH = 40
WORD0_BITS = 32
LOW_WORD1_BITS = 8
OUTER_SLICES = 1 << LOW_WORD1_BITS
INNER_CANDIDATES = 1 << WORD0_BITS
DOMAIN_SIZE = 1 << WIDTH
STREAM_CANDIDATES = A184.STREAM_CANDIDATES
BLOCK_COUNT = 8
ARM_NAMES = ("gray8_w40", "numeric_w40")


def _sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _file_sha256(path: Path) -> str:
    return _sha256(path.read_bytes())


def _load_inputs() -> tuple[dict[str, Any], dict[str, Any], dict[str, list[dict[str, Any]]]]:
    config = A223._load_config()
    challenges = [row for row in config["challenges"] if int(row["width"]) == WIDTH]
    if len(challenges) != 1:
        raise RuntimeError("A225 requires exactly one A223 W40 challenge")
    challenge = challenges[0]["public_challenge"]
    A223._validate_challenge(challenge, width=WIDTH)
    if (
        challenge["known_key_value_words"][0] != 0
        or challenge["known_key_value_words"][1] & 0xFF
        or challenge["known_key_mask_words"][:2] != [0, 0xFFFFFF00]
    ):
        raise RuntimeError("A225 W40 challenge does not match the Metal slice layout")

    result = json.loads(A223_RESULT_PATH.read_bytes())
    if (
        result.get("schema") != A223.RESULT_SCHEMA
        or result.get("attempt_id") != A223.ATTEMPT_ID
        or result.get("all_predeclared_arms_complete_and_valid") is not True
    ):
        raise RuntimeError("A225 A223 result gate failed")
    by_arm: dict[str, list[dict[str, Any]]] = {}
    for name in ARM_NAMES:
        matches = [row for row in result["arm_results"] if row.get("arm") == name]
        if len(matches) != 1 or matches[0].get("complete_valid_arm") is not True:
            raise RuntimeError(f"A225 missing complete A223 arm {name}")
        observations = matches[0].get("observations", [])
        prefixes = [row.get("prefix8") for row in observations]
        if (
            len(observations) != 256
            or len(set(prefixes)) != 256
            or set(prefixes) != {f"{value:08b}" for value in range(256)}
            or any(row.get("status") != "unknown" for row in observations)
        ):
            raise RuntimeError(f"A225 malformed A223 arm {name}")
        by_arm[name] = observations
    return challenge, result, by_arm


def _initial(challenge: dict[str, Any], low_word1: int) -> np.ndarray:
    if low_word1 < 0 or low_word1 >= OUTER_SLICES:
        raise ValueError("low_word1 is outside the eight-bit slice domain")
    initial = np.zeros(16, dtype=np.uint32)
    initial[:4] = A119.CONSTANTS
    initial[4:12] = np.array(challenge["known_key_value_words"], dtype=np.uint32)
    initial[5] = np.uint32(int(initial[5]) | low_word1)
    initial[12] = np.uint32(challenge["counter_start"])
    initial[13:16] = np.array(challenge["nonce_words"], dtype=np.uint32)
    return initial


def _mapping_gate(
    host: A184.SliceMetalHost,
    challenge: dict[str, Any],
    target: np.ndarray,
    control: np.ndarray,
) -> dict[str, Any]:
    first = 0x2468AC00
    count = 8
    rows = []
    for low in (0, 0x5A, 0xFF):
        initial = _initial(challenge, low)
        host.configure(initial, target, control)
        observed = host.blocks(first, count)
        scalar = np.repeat(initial.reshape(1, 16), count, axis=0)
        scalar[:, 4] = np.arange(first, first + count, dtype=np.uint32)
        expected = (A119._core(scalar.copy(), 20) + scalar).astype(np.uint32)
        if not np.array_equal(observed, expected):
            raise RuntimeError("A225 Metal two-word slice mapping differs from NumPy")
        rows.append(
            {
                "key_word1_low_value": low,
                "first_key_word0": first,
                "candidate_count": count,
                "complete_output_bits_checked": int(observed.size * 32),
                "output_sha256": _sha256(observed.astype("<u4", copy=False).tobytes()),
            }
        )
    return {
        "rows": rows,
        "logical_candidates_checked": len(rows) * count,
        "complete_output_bits_checked": sum(row["complete_output_bits_checked"] for row in rows),
        "exact_numpy_identity": True,
    }


def _checkpoint_fingerprint(challenge: dict[str, Any]) -> dict[str, Any]:
    return {
        "schema": "chacha20-round20-a223-w40-metal-transfer-checkpoint-v1",
        "attempt_id": ATTEMPT_ID,
        "A223_config_sha256": _file_sha256(CONFIG_PATH),
        "A223_result_sha256": _file_sha256(A223_RESULT_PATH),
        "A224_source_sha256": _file_sha256(A224_SOURCE_PATH),
        "A224_result_sha256": _file_sha256(A224_RESULT_PATH),
        "Metal_native_source_sha256": A184.NATIVE_SOURCE_SHA256,
        "challenge_id": challenge["challenge_id"],
        "target_block_sha256": challenge["target_block_sha256"][0],
        "control_target_block_sha256": challenge["control_target_block_sha256"],
        "stream_candidates": STREAM_CANDIDATES,
    }


def _enumerate_partial_key(
    *,
    host: A184.SliceMetalHost,
    challenge: dict[str, Any],
    target: np.ndarray,
    control: np.ndarray,
    checkpoint_path: Path,
    resume: bool,
) -> dict[str, Any]:
    fingerprint = _checkpoint_fingerprint(challenge)
    next_assignment = 0
    factual: list[int] = []
    control_matches: list[int] = []
    if resume and checkpoint_path.exists():
        checkpoint = json.loads(checkpoint_path.read_bytes())
        if any(checkpoint.get(key) != value for key, value in fingerprint.items()):
            raise RuntimeError("A225 checkpoint fingerprint differs")
        next_assignment = int(checkpoint["next_assignment"])
        factual = [int(value) for value in checkpoint["factual_filter_matches"]]
        control_matches = [int(value) for value in checkpoint["control_filter_matches"]]
        if (
            next_assignment < 0
            or next_assignment > DOMAIN_SIZE
            or next_assignment % STREAM_CANDIDATES
            or any(value < 0 or value >= next_assignment for value in factual + control_matches)
        ):
            raise RuntimeError("A225 checkpoint progress is invalid")
    resumed_assignment_count = next_assignment
    configured_low: int | None = None
    while next_assignment < DOMAIN_SIZE:
        low = next_assignment >> WORD0_BITS
        first_word0 = next_assignment & 0xFFFFFFFF
        count = min(
            STREAM_CANDIDATES,
            INNER_CANDIDATES - first_word0,
            DOMAIN_SIZE - next_assignment,
        )
        if configured_low != low:
            host.configure(_initial(challenge, low), target, control)
            configured_low = low
        response = host.filter(first_word0, count)
        factual.extend((low << WORD0_BITS) | int(value) for value in response["factual"])
        control_matches.extend(
            (low << WORD0_BITS) | int(value) for value in response["control"]
        )
        next_assignment += count
        A224._atomic_json(
            checkpoint_path,
            {
                **fingerprint,
                "next_assignment": next_assignment,
                "factual_filter_matches": factual,
                "control_filter_matches": control_matches,
            },
        )
        if next_assignment % INNER_CANDIDATES == 0:
            print(
                f"A225 Metal slices={next_assignment // INNER_CANDIDATES}/{OUTER_SLICES} "
                f"assignments={next_assignment}/{DOMAIN_SIZE}",
                flush=True,
            )
    if len(factual) != 1 or control_matches:
        raise RuntimeError(
            f"A225 expected one factual filter match and no control matches; "
            f"observed factual={factual}, control={control_matches}"
        )
    return {
        "logical_candidate_count": DOMAIN_SIZE,
        "outer_slice_count": OUTER_SLICES,
        "inner_candidate_count_per_slice": INNER_CANDIDATES,
        "stream_candidate_count": STREAM_CANDIDATES,
        "stream_batch_count": DOMAIN_SIZE // STREAM_CANDIDATES,
        "resumed_assignment_count": resumed_assignment_count,
        "newly_executed_assignment_count": DOMAIN_SIZE - resumed_assignment_count,
        "complete_domain_executed": True,
        "early_stop_used": False,
        "filter_output_words": 2,
        "filter_output_bits": 64,
        "factual_filter_matches": factual,
        "control_filter_matches": control_matches,
    }


def _confirm(challenge: dict[str, Any], assignment: int) -> dict[str, Any]:
    word0 = assignment & 0xFFFFFFFF
    low_word1 = assignment >> WORD0_BITS
    key_words = list(challenge["known_key_value_words"])
    key_words[0] = word0
    key_words[1] |= low_word1
    candidate_blocks = [
        A223.P1._chacha_block(
            key_words=key_words,
            counter=(challenge["counter_start"] + block) & 0xFFFFFFFF,
            nonce_words=challenge["nonce_words"],
            rounds=20,
        )
        for block in range(BLOCK_COUNT)
    ]
    matches = [
        candidate == target
        for candidate, target in zip(candidate_blocks, challenge["target_words"], strict=True)
    ]
    digests = [_sha256(A223.P1._word_bytes(block)) for block in candidate_blocks]
    control_rejected = digests[0] != challenge["control_target_block_sha256"]
    if not all(matches) or not control_rejected:
        raise RuntimeError("A225 recovered assignment failed eight-block confirmation")
    return {
        "recovered_combined_assignment": assignment,
        "recovered_key_word0": word0,
        "recovered_key_word0_hex": f"0x{word0:08x}",
        "recovered_key_word1_low_value": low_word1,
        "recovered_key_word1_low_hex": f"0x{low_word1:02x}",
        "true_prefix8": f"{low_word1:08b}",
        "block_matches": matches,
        "candidate_block_sha256": digests,
        "target_block_sha256": challenge["target_block_sha256"],
        "block_count_checked": BLOCK_COUNT,
        "output_bits_checked": BLOCK_COUNT * 512,
        "all_blocks_match": True,
        "flipped_control_rejected": True,
        "implementation": "independent_Python_ChaCha20_block_function",
    }


def _write_report(path: Path, payload: dict[str, Any]) -> None:
    confirmation = payload["confirmation"]
    lines = [
        "# A225 — Prospective A224 readout transfer to A223-W40",
        "",
        "## Outcome",
        "",
        f"- Recovered assignment: `{confirmation['recovered_combined_assignment']}`",
        f"- Recovered key word 0: `{confirmation['recovered_key_word0_hex']}`",
        f"- Recovered key word 1 low byte / true prefix: `{confirmation['recovered_key_word1_low_hex']}` / `{confirmation['true_prefix8']}`",
        f"- Complete Metal domain: `{payload['metal_execution']['logical_candidate_count']}` candidates",
        f"- Independent confirmation: `{confirmation['output_bits_checked']}` bits across eight blocks",
        "",
        "## Unchanged A224 readout on both A223-W40 trajectories",
        "",
        "| Arm | Execution rank | Conflicts rank | Decisions rank | Coherence rank | Local residual rank |",
        "|---|---:|---:|---:|---:|---:|",
    ]
    for arm, readout in payload["trajectory_readouts"].items():
        ranks = readout["true_cell_ranks"]
        lines.append(
            f"| `{arm}` | {readout['true_prefix_execution_rank']} / 256 | "
            f"{ranks['conflicts']['rank']} | {ranks['decisions']['rank']} | "
            f"{ranks['constraint_coherence']['rank']} | "
            f"{ranks['coherence_local_residual']['rank']} |"
        )
    lines.extend(
        [
            "",
            "The score definition and rank directions are inherited byte-for-byte from A224; "
            "the W40 assignment was unavailable until the complete A225 Metal pass finished.",
            "",
        ]
    )
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.tmp")
    temporary.write_text("\n".join(lines))
    temporary.replace(path)


def run(
    *,
    output: Path,
    report: Path,
    checkpoint_path: Path,
    build_dir: Path,
    swiftc: str,
    resume: bool,
) -> dict[str, Any]:
    challenge, a223_result, observations = _load_inputs()
    target = np.array(challenge["target_words"][0], dtype=np.uint32)
    control = np.array(challenge["control_target_words"], dtype=np.uint32)
    executable, native_build = A184._A181._compile_native(build_dir, swiftc)
    host = A184.SliceMetalHost(executable, _initial(challenge, 0), target, control)
    try:
        mapping_gate = _mapping_gate(host, challenge, target, control)
        execution = _enumerate_partial_key(
            host=host,
            challenge=challenge,
            target=target,
            control=control,
            checkpoint_path=checkpoint_path,
            resume=resume,
        )
        host_identity = host.identity
    finally:
        host.close()

    confirmation = _confirm(challenge, execution["factual_filter_matches"][0])
    true_prefix = confirmation["true_prefix8"]
    readouts = {
        arm: A224._trajectory_readout(rows, true_prefix8=true_prefix)
        for arm, rows in observations.items()
    }
    payload = {
        "schema": SCHEMA,
        "attempt_id": ATTEMPT_ID,
        "evidence_stage": "A224_FIXED_READOUT_TRANSFERRED_TO_INDEPENDENT_A223_W40_CHALLENGE",
        "result": (
            "The discarded A223 W40 assignment is recovered over the complete 2^40 "
            "domain, confirmed across all eight blocks, and read with the unchanged "
            "A224 trajectory operator on both pre-existing A223 W40 arms."
        ),
        "scope": {
            "primitive": "standard_ChaCha20_20_rounds_with_feedforward",
            "unknown_key_bits": WIDTH,
            "known_key_bits": 256 - WIDTH,
            "target_blocks": BLOCK_COUNT,
            "target_output_bits": BLOCK_COUNT * 512,
        },
        "anchors": {
            "A223_config_sha256": _file_sha256(CONFIG_PATH),
            "A223_result_sha256": _file_sha256(A223_RESULT_PATH),
            "A223_cell_observation_count": a223_result["cell_observation_count"],
            "A224_source_sha256": _file_sha256(A224_SOURCE_PATH),
            "A224_result_sha256": _file_sha256(A224_RESULT_PATH),
            "Metal_native_source_sha256": A184.NATIVE_SOURCE_SHA256,
        },
        "information_boundary": {
            "A223_W40_secret_was_discarded_after_target_construction": True,
            "A224_score_and_directions_fixed_before_A225_label_recovery": True,
            "ground_truth_obtained_only_from_complete_W40_domain_execution": True,
            "A223_trajectory_observations_modified": False,
            "A223_trajectory_outcomes_used_to_change_A225_score": False,
        },
        "native_build": native_build,
        "host_identity": host_identity,
        "mapping_gate": mapping_gate,
        "metal_execution": execution,
        "confirmation": confirmation,
        "trajectory_readouts": readouts,
    }
    A224._atomic_json(output, payload)
    _write_report(report, payload)
    checkpoint_path.unlink(missing_ok=True)
    return payload


def main(argv: Sequence[str] | None = None) -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, default=DEFAULT_RESULT_PATH)
    parser.add_argument("--report", type=Path, default=DEFAULT_REPORT_PATH)
    parser.add_argument("--checkpoint", type=Path, default=DEFAULT_CHECKPOINT_PATH)
    parser.add_argument("--build-dir", type=Path, default=DEFAULT_BUILD_DIR)
    parser.add_argument("--swiftc", default="swiftc")
    parser.add_argument("--no-resume", action="store_true")
    args = parser.parse_args(argv)
    payload = run(
        output=args.output,
        report=args.report,
        checkpoint_path=args.checkpoint,
        build_dir=args.build_dir,
        swiftc=args.swiftc,
        resume=not args.no_resume,
    )
    print(
        json.dumps(
            {
                "attempt_id": payload["attempt_id"],
                "recovered_key_word0_hex": payload["confirmation"]["recovered_key_word0_hex"],
                "true_prefix8": payload["confirmation"]["true_prefix8"],
                "best_rank_by_arm": {
                    arm: readout["best_observed_true_cell_rank"]
                    for arm, readout in payload["trajectory_readouts"].items()
                },
                "output": str(args.output),
                "report": str(args.report),
            },
            indent=2,
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    main()

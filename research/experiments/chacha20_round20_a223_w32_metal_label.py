#!/usr/bin/env python3
"""Recover A223-W32 ground truth and read its retained-state trajectory.

The A223 challenge deliberately discarded its secret after target construction.
This experiment exhausts the missing 32-bit key word with the retained A181/A184
Metal kernel, confirms the recovered word against all eight ChaCha20 blocks, and
then measures where the true high-byte cell sits in A223's already-recorded
Gray-order solver trajectory.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import math
import sys
from collections.abc import Sequence
from pathlib import Path
from statistics import median
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


A184 = _import_sibling(
    "chacha20_metal_width40_partial_key_recovery.py",
    "a224_retained_a184_metal",
)
A223 = _import_sibling(
    "chacha20_round20_capacity_moonshot_a223.py",
    "a224_retained_a223_trajectory",
)
A119 = A184._A119

ATTEMPT_ID = "R20-A224-A223-W32-METAL-LABEL-V1"
SCHEMA = "chacha20-round20-a223-w32-metal-label-v1"
RESULT_FILENAME = "chacha20_round20_a223_w32_metal_label_v1.json"
REPORT_FILENAME = "CAUSAL_CHACHA20_ROUND20_A223_W32_METAL_LABEL_V1.md"
CONFIG_PATH = RESEARCH / "configs" / A223.CONFIG_FILENAME
A223_RESULT_PATH = RESEARCH / "results" / "v1" / A223.RESULT_FILENAME
DEFAULT_RESULT_PATH = RESEARCH / "results" / "v1" / RESULT_FILENAME
DEFAULT_REPORT_PATH = RESEARCH / "reports" / REPORT_FILENAME
DEFAULT_BUILD_DIR = RESEARCH / "artifacts" / "a224_w32_metal_label_v1"

WIDTH = 32
DOMAIN_SIZE = 1 << WIDTH
STREAM_CANDIDATES = A184.STREAM_CANDIDATES
BLOCK_COUNT = 8
FILTER_WORDS = 2
METRICS = ("conflicts", "decisions", "search_propagations")


def _sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _file_sha256(path: Path) -> str:
    return _sha256(path.read_bytes())


def _atomic_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    raw = json.dumps(value, indent=2, sort_keys=True, allow_nan=False).encode() + b"\n"
    temporary = path.with_name(f".{path.name}.tmp")
    temporary.write_bytes(raw)
    temporary.replace(path)


def _load_inputs() -> tuple[dict[str, Any], dict[str, Any], list[dict[str, Any]]]:
    config = A223._load_config()
    challenge_rows = [row for row in config["challenges"] if int(row["width"]) == WIDTH]
    if len(challenge_rows) != 1:
        raise RuntimeError("A224 requires exactly one A223 W32 challenge")
    challenge = challenge_rows[0]["public_challenge"]
    A223._validate_challenge(challenge, width=WIDTH)

    result = json.loads(A223_RESULT_PATH.read_bytes())
    arms = [row for row in result.get("arm_results", []) if row.get("arm") == "gray8_w32"]
    if (
        result.get("schema") != A223.RESULT_SCHEMA
        or result.get("attempt_id") != A223.ATTEMPT_ID
        or result.get("all_predeclared_arms_complete_and_valid") is not True
        or len(arms) != 1
        or arms[0].get("complete_valid_arm") is not True
    ):
        raise RuntimeError("A224 A223 result gate failed")
    observations = arms[0].get("observations", [])
    prefixes = [row.get("prefix8") for row in observations]
    if (
        len(observations) != 256
        or len(set(prefixes)) != 256
        or set(prefixes) != {f"{value:08b}" for value in range(256)}
        or any(row.get("status") != "unknown" for row in observations)
        or any(tuple(row.get("metric_names", ())) != METRICS for row in observations)
    ):
        raise RuntimeError("A224 A223 W32 trajectory is incomplete or malformed")
    return challenge, result, observations


def _initial(challenge: dict[str, Any], *, counter_offset: int = 0) -> np.ndarray:
    initial = np.zeros(16, dtype=np.uint32)
    initial[:4] = A119.CONSTANTS
    initial[4:12] = np.array(challenge["known_key_value_words"], dtype=np.uint32)
    initial[12] = np.uint32((challenge["counter_start"] + counter_offset) & 0xFFFFFFFF)
    initial[13:16] = np.array(challenge["nonce_words"], dtype=np.uint32)
    return initial


def _mapping_gate(host: A184.SliceMetalHost, challenge: dict[str, Any]) -> dict[str, Any]:
    first = 0x13579B00
    count = 8
    observed = host.blocks(first, count)
    scalar = np.repeat(_initial(challenge).reshape(1, 16), count, axis=0)
    scalar[:, 4] = np.arange(first, first + count, dtype=np.uint32)
    expected = (A119._core(scalar.copy(), 20) + scalar).astype(np.uint32)
    if not np.array_equal(observed, expected):
        raise RuntimeError("A224 Metal candidate-to-key-word mapping differs from NumPy")
    return {
        "first_candidate": first,
        "candidate_count": count,
        "complete_output_bits_checked": int(observed.size * 32),
        "output_sha256": _sha256(observed.astype("<u4", copy=False).tobytes()),
        "exact_numpy_identity": True,
    }


def _enumerate_word0(
    host: A184.SliceMetalHost,
) -> dict[str, Any]:
    factual: list[int] = []
    control: list[int] = []
    batches = 0
    for first in range(0, DOMAIN_SIZE, STREAM_CANDIDATES):
        count = min(STREAM_CANDIDATES, DOMAIN_SIZE - first)
        response = host.filter(first, count)
        factual.extend(int(value) for value in response["factual"])
        control.extend(int(value) for value in response["control"])
        batches += 1
        print(
            f"A224 Metal batches={batches}/{DOMAIN_SIZE // STREAM_CANDIDATES} "
            f"candidates={first + count}/{DOMAIN_SIZE}",
            flush=True,
        )
    if len(factual) != 1 or control:
        raise RuntimeError(
            f"A224 expected one factual filter match and no control matches; "
            f"observed factual={factual}, control={control}"
        )
    return {
        "logical_candidate_count": DOMAIN_SIZE,
        "stream_candidate_count": STREAM_CANDIDATES,
        "stream_batch_count": batches,
        "complete_domain_executed": True,
        "early_stop_used": False,
        "filter_output_words": FILTER_WORDS,
        "filter_output_bits": FILTER_WORDS * 32,
        "factual_filter_matches": factual,
        "control_filter_matches": control,
    }


def _confirm(challenge: dict[str, Any], word0: int) -> dict[str, Any]:
    key_words = list(challenge["known_key_value_words"])
    key_words[0] = word0
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
        for candidate, target in zip(
            candidate_blocks, challenge["target_words"], strict=True
        )
    ]
    digests = [_sha256(A223.P1._word_bytes(block)) for block in candidate_blocks]
    control_rejected = digests[0] != challenge["control_target_block_sha256"]
    if not all(matches) or not control_rejected:
        raise RuntimeError("A224 recovered word failed independent eight-block confirmation")
    return {
        "recovered_key_word0": word0,
        "recovered_key_word0_hex": f"0x{word0:08x}",
        "block_matches": matches,
        "candidate_block_sha256": digests,
        "target_block_sha256": challenge["target_block_sha256"],
        "block_count_checked": BLOCK_COUNT,
        "output_bits_checked": BLOCK_COUNT * 512,
        "all_blocks_match": True,
        "flipped_control_rejected": True,
        "implementation": "independent_Python_ChaCha20_block_function",
    }


def _rank(values: list[float], target_index: int, *, descending: bool) -> dict[str, Any]:
    target = values[target_index]
    better = sum(value > target if descending else value < target for value in values)
    tied = sum(value == target for value in values)
    return {
        "direction": "descending" if descending else "ascending",
        "rank": better + 1,
        "tied_count": tied,
        "target_value": target,
        "empirical_top_fraction": (better + 1) / len(values),
    }


def _trajectory_readout(
    observations: list[dict[str, Any]],
    recovered_word0: int | None = None,
    *,
    true_prefix8: str | None = None,
) -> dict[str, Any]:
    if true_prefix8 is None:
        if recovered_word0 is None:
            raise ValueError("a recovered word or an explicit true prefix is required")
        true_prefix = f"{(recovered_word0 >> 24) & 0xFF:08b}"
    else:
        if len(true_prefix8) != 8 or set(true_prefix8) - {"0", "1"}:
            raise ValueError("true_prefix8 must contain exactly eight bits")
        true_prefix = true_prefix8
    target_index = next(
        index for index, row in enumerate(observations) if row["prefix8"] == true_prefix
    )
    rows: list[dict[str, Any]] = []
    for row in observations:
        delta = row["metrics_delta"]
        conflicts = float(delta["conflicts"])
        decisions = float(delta["decisions"])
        propagations = float(delta["search_propagations"])
        coherence = (
            math.log1p(propagations)
            - math.log1p(decisions)
            - math.log1p(conflicts)
        )
        rows.append(
            {
                "prefix8": row["prefix8"],
                "cell_index": int(row["cell_index"]),
                "conflicts": conflicts,
                "decisions": decisions,
                "search_propagations": propagations,
                "propagations_per_decision": propagations / max(decisions, 1.0),
                "propagations_per_conflict": propagations / max(conflicts, 1.0),
                "conflicts_per_decision": conflicts / max(decisions, 1.0),
                "constraint_coherence": coherence,
            }
        )

    window = 8
    for index, row in enumerate(rows):
        previous = [
            rows[(index - offset) % len(rows)]["constraint_coherence"]
            for offset in range(1, window + 1)
        ]
        row["coherence_local_residual"] = row["constraint_coherence"] - median(previous)

    directions = {
        "conflicts": False,
        "decisions": False,
        "search_propagations": True,
        "propagations_per_decision": True,
        "propagations_per_conflict": True,
        "conflicts_per_decision": False,
        "constraint_coherence": True,
        "coherence_local_residual": True,
    }
    ranks = {
        name: _rank(
            [float(row[name]) for row in rows],
            target_index,
            descending=descending,
        )
        for name, descending in directions.items()
    }
    top_coherence = sorted(
        rows, key=lambda row: row["constraint_coherence"], reverse=True
    )[:16]
    top_residual = sorted(
        rows, key=lambda row: row["coherence_local_residual"], reverse=True
    )[:16]
    best_rank = min(value["rank"] for value in ranks.values())
    return {
        "true_prefix8": true_prefix,
        "true_prefix_numeric_value": int(true_prefix, 2),
        "true_prefix_gray_order_cell_index": int(observations[target_index]["cell_index"]),
        "true_prefix_gray_order_execution_rank": target_index + 1,
        "true_prefix_execution_rank": target_index + 1,
        "observation_count": len(rows),
        "hypothesis_fixed_before_label_readout": (
            "The satisfiable prefix should exhibit more constraint propagation per "
            "decision/conflict than incompatible prefixes; constraint_coherence is "
            "therefore ranked descending, with an eight-cell local residual as a "
            "retained-state transition view."
        ),
        "score_definition": (
            "ln(1+search_propagations)-ln(1+decisions)-ln(1+conflicts)"
        ),
        "rank_directions": {
            name: "descending" if descending else "ascending"
            for name, descending in directions.items()
        },
        "true_cell_ranks": ranks,
        "best_observed_true_cell_rank": best_rank,
        "true_cell_in_top16_on_any_fixed_view": best_rank <= 16,
        "top16_constraint_coherence": top_coherence,
        "top16_coherence_local_residual": top_residual,
        "true_cell_features": rows[target_index],
    }


def _write_report(path: Path, payload: dict[str, Any]) -> None:
    readout = payload["trajectory_readout"]
    ranks = readout["true_cell_ranks"]
    lines = [
        "# A224 — A223-W32 Metal label and trajectory readout",
        "",
        "## Outcome",
        "",
        f"- Recovered key word 0: `{payload['confirmation']['recovered_key_word0_hex']}`",
        f"- True A223 prefix: `{readout['true_prefix8']}`",
        f"- Full Metal domain executed: `{payload['metal_execution']['logical_candidate_count']}` candidates",
        f"- Independent confirmation: `{payload['confirmation']['output_bits_checked']}` output bits across eight blocks",
        f"- Best true-cell rank among the fixed trajectory views: **{readout['best_observed_true_cell_rank']} / 256**",
        "",
        "## Fixed trajectory readout",
        "",
        "| View | Direction | True-cell rank | Target value |",
        "|---|---:|---:|---:|",
    ]
    for name, row in ranks.items():
        lines.append(
            f"| `{name}` | {row['direction']} | {row['rank']} / 256 | {row['target_value']:.9g} |"
        )
    lines.extend(
        [
            "",
            "The label was unavailable in A223 and was reconstructed only by the complete Metal W32 pass. "
            "The trajectory observations themselves are unchanged from A223.",
            "",
        ]
    )
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.tmp")
    temporary.write_text("\n".join(lines))
    temporary.replace(path)


def run(*, output: Path, report: Path, build_dir: Path, swiftc: str) -> dict[str, Any]:
    challenge, a223_result, observations = _load_inputs()
    target = np.array(challenge["target_words"][0], dtype=np.uint32)
    control = np.array(challenge["control_target_words"], dtype=np.uint32)
    executable, native_build = A184._A181._compile_native(build_dir, swiftc)
    host = A184.SliceMetalHost(executable, _initial(challenge), target, control)
    try:
        mapping_gate = _mapping_gate(host, challenge)
        metal_execution = _enumerate_word0(host)
        host_identity = host.identity
    finally:
        host.close()

    word0 = metal_execution["factual_filter_matches"][0]
    confirmation = _confirm(challenge, word0)
    readout = _trajectory_readout(observations, word0)
    payload = {
        "schema": SCHEMA,
        "attempt_id": ATTEMPT_ID,
        "evidence_stage": "A223_W32_GROUND_TRUTH_RECOVERED_AND_TRAJECTORY_READ",
        "result": (
            "The discarded A223 W32 assignment is recovered over the complete 2^32 "
            "domain, confirmed across all eight R20 blocks, and used to label the "
            "unchanged A223 retained-state trajectory."
        ),
        "scope": {
            "primitive": "standard_ChaCha20_20_rounds_with_feedforward",
            "unknown_key_bits": WIDTH,
            "known_key_bits": 256 - WIDTH,
            "target_blocks": BLOCK_COUNT,
            "target_output_bits": BLOCK_COUNT * 512,
        },
        "anchors": {
            "A223_config_path": str(CONFIG_PATH.relative_to(ROOT)),
            "A223_config_sha256": _file_sha256(CONFIG_PATH),
            "A223_result_path": str(A223_RESULT_PATH.relative_to(ROOT)),
            "A223_result_sha256": _file_sha256(A223_RESULT_PATH),
            "A223_cell_observation_count": a223_result["cell_observation_count"],
            "Metal_native_source_sha256": A184.NATIVE_SOURCE_SHA256,
        },
        "information_boundary": {
            "A223_secret_was_discarded_after_target_construction": True,
            "ground_truth_obtained_only_from_complete_W32_domain_execution": True,
            "A223_trajectory_observations_modified": False,
            "trajectory_score_definition_fixed_before_recovered_label_readout": True,
        },
        "native_build": native_build,
        "host_identity": host_identity,
        "mapping_gate": mapping_gate,
        "metal_execution": metal_execution,
        "confirmation": confirmation,
        "trajectory_readout": readout,
    }
    _atomic_json(output, payload)
    _write_report(report, payload)
    return payload


def main(argv: Sequence[str] | None = None) -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, default=DEFAULT_RESULT_PATH)
    parser.add_argument("--report", type=Path, default=DEFAULT_REPORT_PATH)
    parser.add_argument("--build-dir", type=Path, default=DEFAULT_BUILD_DIR)
    parser.add_argument("--swiftc", default="swiftc")
    args = parser.parse_args(argv)
    payload = run(
        output=args.output,
        report=args.report,
        build_dir=args.build_dir,
        swiftc=args.swiftc,
    )
    print(
        json.dumps(
            {
                "attempt_id": payload["attempt_id"],
                "recovered_key_word0_hex": payload["confirmation"]["recovered_key_word0_hex"],
                "true_prefix8": payload["trajectory_readout"]["true_prefix8"],
                "best_true_cell_rank": payload["trajectory_readout"]["best_observed_true_cell_rank"],
                "output": str(args.output),
                "report": str(args.report),
            },
            indent=2,
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    main()

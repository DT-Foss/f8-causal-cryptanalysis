#!/usr/bin/env python3
"""Recover and diagnose all seven A233 W32 labels after its frozen barrier."""

from __future__ import annotations

import hashlib
import importlib.util
import json
import statistics
import sys
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


A233 = _import_sibling(
    "chacha20_round20_w32_h16_top64_prospective.py",
    "a234_completed_a233_anchor",
)
A229 = A233.A229
A227 = A233.A227
A224 = A227.A224
A184 = A233.A184

ATTEMPT_ID = "R20-A234-A233-POSTBARRIER-LABELS-V1"
SCHEMA = "chacha20-round20-a233-postbarrier-labels-v1"
OUTPUT = (
    RESEARCH
    / "results"
    / "v1"
    / "chacha20_round20_a233_postbarrier_labels_v1.json"
)
REPORT = (
    RESEARCH
    / "reports"
    / "CAUSAL_CHACHA20_ROUND20_A233_POSTBARRIER_LABELS_V1.md"
)
THRESHOLDS = (4, 16, 32, 64, 128)


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


def _stage_features(stage: dict[str, Any]) -> dict[str, float]:
    """Mirror A231's complete scalar readout for direct cross-batch comparison."""

    stage_metrics = stage["metrics_stage_delta"]
    cumulative_metrics = stage["metrics_cell_cumulative_delta"]
    return {
        "stage_conflicts": float(stage_metrics[0]),
        "stage_decisions": float(stage_metrics[1]),
        "stage_search_propagations": float(stage_metrics[2]),
        "cumulative_conflicts": float(cumulative_metrics[0]),
        "cumulative_decisions": float(cumulative_metrics[1]),
        "cumulative_search_propagations": float(cumulative_metrics[2]),
        "active_variables_stage_delta": float(stage["active_variables_stage_delta"]),
        "irredundant_clauses_stage_delta": float(
            stage["irredundant_clauses_stage_delta"]
        ),
        "redundant_clauses_stage_delta": float(stage["redundant_clauses_stage_delta"]),
        "active_variables_cumulative_delta": float(
            stage["active_variables_cell_cumulative_delta"]
        ),
        "irredundant_clauses_cumulative_delta": float(
            stage["irredundant_clauses_cell_cumulative_delta"]
        ),
        "redundant_clauses_cumulative_delta": float(
            stage["redundant_clauses_cell_cumulative_delta"]
        ),
        "elapsed_seconds": float(stage["elapsed_seconds"]),
    }


def _tieaware_rank(
    stages: list[dict[str, Any]],
    *,
    feature_name: str,
    target_prefix: str,
    descending: bool,
) -> dict[str, Any]:
    rows = [
        (stage["prefix8"], _stage_features(stage)[feature_name])
        for stage in stages
    ]
    target_value = next(value for prefix, value in rows if prefix == target_prefix)
    strictly_better = sum(
        value > target_value if descending else value < target_value
        for _, value in rows
    )
    tied_prefixes = sorted(prefix for prefix, value in rows if value == target_value)
    tie_offset = tied_prefixes.index(target_prefix)
    return {
        "rank": 1 + strictly_better + tie_offset,
        "strictly_better_count": strictly_better,
        "tie_count": len(tied_prefixes),
        "deterministic_prefix_tie_offset": tie_offset,
        "target_value": target_value,
    }


def _candidate_ranks(
    stages: list[dict[str, Any]], true_prefix: str
) -> dict[str, dict[str, Any]]:
    if len(stages) != 256 or len({row["prefix8"] for row in stages}) != 256:
        raise RuntimeError("A234 requires one complete 256-cell H16 matrix")
    result = {}
    for feature_name in _stage_features(stages[0]):
        for descending in (False, True):
            direction = "desc" if descending else "asc"
            name = f"one_shot_h16_wd30.h16.{feature_name}.{direction}"
            result[name] = _tieaware_rank(
                stages,
                feature_name=feature_name,
                target_prefix=true_prefix,
                descending=descending,
            )
    return result


def _reader_summary(name: str, labels: list[dict[str, Any]]) -> dict[str, Any]:
    ranks = [row["candidate_reader_ranks"][name]["rank"] for row in labels]
    return {
        "reader": name,
        "ranks": ranks,
        "top64_hits": sum(rank <= 64 for rank in ranks),
        "median_rank": statistics.median(ranks),
        "mean_rank": statistics.fmean(ranks),
        "worst_rank": max(ranks),
        "best_rank": min(ranks),
        "hits": {
            f"top_{threshold}": sum(rank <= threshold for rank in ranks)
            for threshold in THRESHOLDS
        },
    }


def _selection_key(row: dict[str, Any]) -> tuple[Any, ...]:
    return (
        -row["top64_hits"],
        row["worst_rank"],
        row["median_rank"],
        row["mean_rank"],
        row["reader"],
    )


def _write_report(payload: dict[str, Any]) -> None:
    lines = [
        "# A234 — A233 post-barrier labels",
        "",
        "A233 completed all seven prospective top-64 searches before this artifact recovered any missing W32 label.",
        "",
        "| Challenge | Word 0 | True prefix | Frozen H16 rank | Selected |",
        "|---:|---:|---:|---:|---:|",
    ]
    for row in payload["labels"]:
        lines.append(
            f"| {row['index']} | `{row['confirmation']['key_word0_hex']}` | "
            f"`{row['true_prefix8']}` | {row['frozen_A233_reader_rank']} | "
            f"{row['A233_selected_top64_contained_true_prefix']} |"
        )
    lines.extend(
        [
            "",
            "## Descriptive scalar readback",
            "",
            "These rows are post-barrier diagnostics, not prospectively frozen readers.",
            "",
            "| Reader | Ranks | Median | Top-64 hits |",
            "|---|---|---:|---:|",
        ]
    )
    for row in payload["aggregate"]["best_postbarrier_readers"][:12]:
        lines.append(
            f"| `{row['reader']}` | "
            f"{', '.join(str(rank) for rank in row['ranks'])} | "
            f"{row['median_rank']} | {row['top64_hits']}/7 |"
        )
    lines.extend(
        [
            "",
            "The frozen A233 reader recovered 1/7 and therefore did not establish a transferable fourfold candidate-domain reduction. The labels above convert every miss into a complete H16 training and diagnosis row.",
            "",
        ]
    )
    REPORT.parent.mkdir(parents=True, exist_ok=True)
    temporary = REPORT.with_name(f".{REPORT.name}.tmp")
    temporary.write_text("\n".join(lines))
    temporary.replace(REPORT)


def main() -> None:
    if OUTPUT.exists():
        raise RuntimeError(f"A234 output already exists: {OUTPUT}")
    protocol = json.loads(A233.PROTOCOL_PATH.read_bytes())
    a233 = json.loads(A233.RESULT_PATH.read_bytes())
    aggregate = a233.get("aggregate", {})
    if (
        protocol.get("schema") != A233.PROTOCOL_SCHEMA
        or a233.get("schema") != A233.RESULT_SCHEMA
        or aggregate.get("challenge_count") != A233.CHALLENGE_COUNT
        or aggregate.get("success_count") != 1
        or aggregate.get("failure_count") != 6
        or aggregate.get("all_selected_regions_completed_without_early_stop") is not True
        or len(protocol.get("challenges", [])) != A233.CHALLENGE_COUNT
        or len(a233.get("challenge_results", [])) != A233.CHALLENGE_COUNT
    ):
        raise RuntimeError("A234 requires the complete final 1/7 A233 barrier")

    executable, native_build = A184._A181._compile_native(
        A233.ARTIFACT_DIR / "a234_metal_build", "swiftc"
    )
    labels = []
    host_identities = []
    for index, (protocol_row, result_row) in enumerate(
        zip(protocol["challenges"], a233["challenge_results"], strict=True)
    ):
        if protocol_row.get("index") != index or result_row.get("index") != index:
            raise RuntimeError("A234 challenge order differs")
        if (
            result_row.get("public_challenge_sha256")
            != protocol_row["public_challenge_sha256"]
        ):
            raise RuntimeError("A234 challenge digest differs")

        challenge = protocol_row["public_challenge"]
        target = np.array(challenge["target_words"][0], dtype=np.uint32)
        control = np.array(challenge["control_target_words"], dtype=np.uint32)
        host = A184.SliceMetalHost(
            executable, A229._initial(challenge), target, control
        )
        try:
            execution = A224._enumerate_word0(host)
            host_identities.append(host.identity)
        finally:
            host.close()
        if (
            execution.get("complete_domain_executed") is not True
            or len(execution.get("factual_filter_matches", [])) != 1
            or execution.get("control_filter_matches") != []
        ):
            raise RuntimeError(f"A234 challenge {index} full-domain label failed")
        word0 = int(execution["factual_filter_matches"][0])
        confirmation = A227._confirm_candidate(challenge, word0)
        if (
            confirmation.get("all_blocks_match") is not True
            or confirmation.get("flipped_control_rejected") is not True
            or confirmation.get("output_bits_checked") != 4096
        ):
            raise RuntimeError(f"A234 challenge {index} confirmation failed")

        true_prefix = confirmation["prefix8"]
        stages = [
            stage
            for stage in result_row["trajectory"]["stages"]
            if stage["horizon"] == A233.HORIZON
        ]
        ranked = result_row["reader"]["ranked_cells"]
        selected = {
            row["prefix8"] for row in result_row["reader"]["selected_top64"]
        }
        frozen_rank = next(
            rank
            for rank, row in enumerate(ranked, start=1)
            if row["prefix8"] == true_prefix
        )
        selected_true = true_prefix in selected
        prospective_success = result_row["limited_Metal_search"][
            "prospective_recovery_success"
        ]
        if selected_true != prospective_success or selected_true != (frozen_rank <= 64):
            raise RuntimeError(f"A234 challenge {index} selection/result contradiction")
        if prospective_success:
            matches = result_row["limited_Metal_search"]["exact_confirmed_matches"]
            if len(matches) != 1 or int(matches[0]["key_word0"]) != word0:
                raise RuntimeError(f"A234 challenge {index} recovered word differs")
        elif result_row["limited_Metal_search"]["exact_confirmed_matches"]:
            raise RuntimeError(f"A234 challenge {index} miss contains a confirmed match")

        true_stage = next(stage for stage in stages if stage["prefix8"] == true_prefix)
        labels.append(
            {
                "index": index,
                "public_challenge_sha256": protocol_row["public_challenge_sha256"],
                "full_domain_execution": execution,
                "confirmation": confirmation,
                "true_prefix8": true_prefix,
                "true_gray_execution_rank": int(true_stage["cell_index"]) + 1,
                "frozen_A233_reader_rank": frozen_rank,
                "A233_selected_top64_contained_true_prefix": selected_true,
                "A233_prospective_recovery_success": prospective_success,
                "true_cell_features": _stage_features(true_stage),
                "candidate_reader_ranks": _candidate_ranks(stages, true_prefix),
            }
        )

    reader_names = list(labels[0]["candidate_reader_ranks"])
    summaries = sorted(
        (_reader_summary(name, labels) for name in reader_names),
        key=_selection_key,
    )
    payload = {
        "schema": SCHEMA,
        "attempt_id": ATTEMPT_ID,
        "evidence_stage": "POST_A233_BARRIER_SEVEN_FULL_W32_LABELS_AND_H16_RANK_DIAGNOSIS",
        "anchors": {
            "A233_protocol_sha256": _file_sha256(A233.PROTOCOL_PATH),
            "A233_preflight_sha256": _file_sha256(A233.PREFLIGHT_PATH),
            "A233_result_sha256": _file_sha256(A233.RESULT_PATH),
            "A233_report_sha256": _file_sha256(A233.REPORT_PATH),
            "A233_all_seven_top64_searches_completed_before_A234": True,
        },
        "information_boundary": {
            "A234_started_only_after_A233_result_was_final": True,
            "A234_labels_could_not_change_A233_horizon_score_direction_threshold_or_selected_regions": True,
            "A234_bidirectional_scalar_sweep_is_descriptive_not_a_frozen_reader": True,
        },
        "tie_policy": {
            "primary": "metric direction",
            "secondary": "ascending binary prefix8",
            "large_ties_never_receive_shared_competition_rank": True,
        },
        "native_build": native_build,
        "host_identities": host_identities,
        "labels": labels,
        "aggregate": {
            "label_count": len(labels),
            "all_full_domains_completed": all(
                row["full_domain_execution"]["complete_domain_executed"]
                for row in labels
            ),
            "all_labels_independently_confirmed_over_4096_bits": all(
                row["confirmation"]["output_bits_checked"] == 4096
                and row["confirmation"]["all_blocks_match"]
                for row in labels
            ),
            "frozen_A233_reader_ranks": [
                row["frozen_A233_reader_rank"] for row in labels
            ],
            "frozen_A233_top64_hits": sum(
                row["A233_selected_top64_contained_true_prefix"] for row in labels
            ),
            "candidate_reader_count": len(summaries),
            "best_postbarrier_readers": summaries,
        },
    }
    _atomic_json(OUTPUT, payload)
    _write_report(payload)
    print(
        json.dumps(
            {
                "labels": [
                    {
                        "index": row["index"],
                        "word0": row["confirmation"]["key_word0_hex"],
                        "true_prefix8": row["true_prefix8"],
                        "frozen_A233_reader_rank": row["frozen_A233_reader_rank"],
                    }
                    for row in labels
                ],
                "best_postbarrier_reader": summaries[0],
                "output": str(OUTPUT),
            },
            indent=2,
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""Recover all seven A229 W32 labels after its prospective barrier."""

from __future__ import annotations

import hashlib
import importlib.util
import json
import math
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


A229 = _import_sibling(
    "chacha20_round20_w32_top64_batch_recovery.py",
    "a230_completed_a229_anchor",
)
A227 = A229.A227
A224 = A227.A224
A184 = A229.A184

ATTEMPT_ID = "R20-A230-A229-POSTBARRIER-LABELS-V1"
SCHEMA = "chacha20-round20-a229-postbarrier-labels-v1"
OUTPUT = (
    RESEARCH
    / "results"
    / "v1"
    / "chacha20_round20_a229_postbarrier_labels_v1.json"
)
REPORT = (
    RESEARCH
    / "reports"
    / "CAUSAL_CHACHA20_ROUND20_A229_POSTBARRIER_LABELS_V1.md"
)

METRIC_DIRECTIONS = {
    "conflicts": False,
    "decisions": False,
    "search_propagations": True,
    "propagations_per_decision": True,
    "propagations_per_conflict": True,
    "conflicts_per_decision": False,
    "constraint_coherence": True,
    "coherence_local_residual": True,
}
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


def _rank(values: list[float], target_index: int, *, descending: bool) -> int:
    target = values[target_index]
    return 1 + sum(value > target if descending else value < target for value in values)


def _bidirectional_ranks(
    rows: list[dict[str, Any]], true_prefix: str
) -> dict[str, dict[str, int]]:
    target_index = next(index for index, row in enumerate(rows) if row["prefix8"] == true_prefix)
    result = {}
    for metric, preferred_descending in METRIC_DIRECTIONS.items():
        values = [float(row[metric]) for row in rows]
        result[metric] = {
            "predeclared_rank": _rank(
                values, target_index, descending=preferred_descending
            ),
            "inverse_rank": _rank(
                values, target_index, descending=not preferred_descending
            ),
        }
    return result


def _feature_rows(observations: list[dict[str, Any]]) -> list[dict[str, Any]]:
    rows = []
    for observation in observations:
        delta = observation["metrics_delta"]
        conflicts = float(delta["conflicts"])
        decisions = float(delta["decisions"])
        propagations = float(delta["search_propagations"])
        rows.append(
            {
                "prefix8": observation["prefix8"],
                "cell_index": int(observation["cell_index"]),
                "conflicts": conflicts,
                "decisions": decisions,
                "search_propagations": propagations,
                "propagations_per_decision": propagations / max(decisions, 1.0),
                "propagations_per_conflict": propagations / max(conflicts, 1.0),
                "conflicts_per_decision": conflicts / max(decisions, 1.0),
                "constraint_coherence": (
                    math.log1p(propagations)
                    - math.log1p(decisions)
                    - math.log1p(conflicts)
                ),
            }
        )
    for index, row in enumerate(rows):
        previous = [
            rows[(index - offset) % len(rows)]["constraint_coherence"]
            for offset in range(1, 9)
        ]
        row["coherence_local_residual"] = (
            row["constraint_coherence"] - statistics.median(previous)
        )
    return rows


def _aggregate_metric_ranks(
    labels: list[dict[str, Any]], rank_field: str
) -> dict[str, Any]:
    aggregate = {}
    for metric in METRIC_DIRECTIONS:
        ranks = [row["bidirectional_ranks"][metric][rank_field] for row in labels]
        aggregate[metric] = {
            "ranks": ranks,
            "mean_rank": statistics.fmean(ranks),
            "median_rank": statistics.median(ranks),
            "best_rank": min(ranks),
            "worst_rank": max(ranks),
            "hits": {
                f"top_{threshold}": sum(rank <= threshold for rank in ranks)
                for threshold in THRESHOLDS
            },
        }
    return aggregate


def _write_report(payload: dict[str, Any]) -> None:
    lines = [
        "# A230 — A229 post-barrier labels",
        "",
        "A229 completed all seven prospective top-64 searches before any label in this artifact was recovered.",
        "",
        "| Challenge | Word 0 | True prefix | Coherence rank | Best predeclared view |",
        "|---:|---:|---:|---:|---:|",
    ]
    for row in payload["labels"]:
        best = min(
            ranks["predeclared_rank"]
            for ranks in row["bidirectional_ranks"].values()
        )
        lines.append(
            f"| {row['index']} | `{row['confirmation']['key_word0_hex']}` | "
            f"`{row['true_prefix8']}` | {row['fixed_coherence_rank']} | {best} |"
        )
    lines.extend(
        [
            "",
            "## Predeclared metric transfer",
            "",
            "| Metric | Ranks | Median | Top-64 hits |",
            "|---|---|---:|---:|",
        ]
    )
    for metric, row in payload["aggregate"]["predeclared_metric_ranks"].items():
        ranks = ", ".join(str(rank) for rank in row["ranks"])
        lines.append(
            f"| `{metric}` | {ranks} | {row['median_rank']} | {row['hits']['top_64']}/7 |"
        )
    lines.append("")
    REPORT.parent.mkdir(parents=True, exist_ok=True)
    temporary = REPORT.with_name(f".{REPORT.name}.tmp")
    temporary.write_text("\n".join(lines))
    temporary.replace(REPORT)


def main() -> None:
    if OUTPUT.exists():
        raise RuntimeError(f"A230 output already exists: {OUTPUT}")
    protocol = json.loads(A229.PROTOCOL_PATH.read_bytes())
    a229 = json.loads(A229.RESULT_PATH.read_bytes())
    aggregate = a229.get("aggregate", {})
    if (
        a229.get("schema") != A229.RESULT_SCHEMA
        or aggregate.get("challenge_count") != A229.CHALLENGE_COUNT
        or aggregate.get("success_count") != 0
        or aggregate.get("failure_count") != A229.CHALLENGE_COUNT
        or aggregate.get("all_selected_regions_completed_without_early_stop") is not True
        or len(a229.get("challenge_results", [])) != A229.CHALLENGE_COUNT
    ):
        raise RuntimeError("A230 requires the completed unsuccessful A229 barrier")

    executable, native_build = A184._A181._compile_native(
        A229.ARTIFACT_DIR / "a230_metal_build", "swiftc"
    )
    labels = []
    host_identities = []
    for index, (protocol_row, result_row) in enumerate(
        zip(protocol["challenges"], a229["challenge_results"], strict=True)
    ):
        if result_row.get("index") != index:
            raise RuntimeError("A230 challenge order differs")
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
            raise RuntimeError(f"A230 challenge {index} full-domain label failed")
        word0 = int(execution["factual_filter_matches"][0])
        confirmation = A227._confirm_candidate(challenge, word0)
        if (
            confirmation.get("all_blocks_match") is not True
            or confirmation.get("flipped_control_rejected") is not True
        ):
            raise RuntimeError(f"A230 challenge {index} confirmation failed")
        true_prefix = confirmation["prefix8"]
        feature_rows = _feature_rows(result_row["trajectory"]["observations"])
        fixed_rank = next(
            rank
            for rank, row in enumerate(result_row["reader"]["ranked_cells"], start=1)
            if row["prefix8"] == true_prefix
        )
        selected = {
            row["prefix8"] for row in result_row["reader"]["selected_top64"]
        }
        if true_prefix in selected:
            raise RuntimeError("A230 label contradicts the completed A229 miss")
        labels.append(
            {
                "index": index,
                "public_challenge_sha256": protocol_row["public_challenge_sha256"],
                "full_domain_execution": execution,
                "confirmation": confirmation,
                "true_prefix8": true_prefix,
                "true_gray_execution_rank": next(
                    int(row["cell_index"]) + 1
                    for row in feature_rows
                    if row["prefix8"] == true_prefix
                ),
                "fixed_coherence_rank": fixed_rank,
                "A229_selected_top64_contained_true_prefix": False,
                "true_cell_features": next(
                    row for row in feature_rows if row["prefix8"] == true_prefix
                ),
                "bidirectional_ranks": _bidirectional_ranks(
                    feature_rows, true_prefix
                ),
            }
        )

    payload = {
        "schema": SCHEMA,
        "attempt_id": ATTEMPT_ID,
        "evidence_stage": "POST_A229_BARRIER_SEVEN_FULL_W32_LABELS_AND_RANK_DIAGNOSIS",
        "anchors": {
            "A229_protocol_sha256": _file_sha256(A229.PROTOCOL_PATH),
            "A229_result_sha256": _file_sha256(A229.RESULT_PATH),
            "A229_report_sha256": _file_sha256(A229.REPORT_PATH),
            "A229_all_seven_top64_searches_completed_before_A230": True,
        },
        "information_boundary": {
            "A230_started_only_after_A229_result_was_final": True,
            "A230_labels_could_not_change_A229_scores_thresholds_or_selected_regions": True,
            "A230_rank_direction_sweep_is_descriptive_not_a_frozen_reader": True,
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
            "fixed_coherence_ranks": [row["fixed_coherence_rank"] for row in labels],
            "predeclared_metric_ranks": _aggregate_metric_ranks(
                labels, "predeclared_rank"
            ),
            "inverse_metric_ranks": _aggregate_metric_ranks(labels, "inverse_rank"),
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
                        "coherence_rank": row["fixed_coherence_rank"],
                    }
                    for row in labels
                ],
                "output": str(OUTPUT),
            },
            indent=2,
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""Apply the A225 dual-order minimax breadcrumb to the complete A218 corpus."""

from __future__ import annotations

import argparse
import hashlib
import json
import math
from collections.abc import Sequence
from pathlib import Path
from statistics import mean, median
from typing import Any

ROOT = Path(__file__).parents[2]
RESEARCH = ROOT / "research"
CORPUS_PATH = RESEARCH / "results" / "v1" / "chacha20_round20_knownkey_trajectory_corpus_v1.json"
A225_RESULT_PATH = RESEARCH / "results" / "v1" / "chacha20_round20_a223_w40_metal_transfer_v1.json"
DEFAULT_RESULT_PATH = RESEARCH / "results" / "v1" / "chacha20_round20_dual_order_minimax_transfer_v1.json"
DEFAULT_REPORT_PATH = RESEARCH / "reports" / "CAUSAL_CHACHA20_ROUND20_DUAL_ORDER_MINIMAX_TRANSFER_V1.md"

ATTEMPT_ID = "R20-A226-DUAL-ORDER-MINIMAX-TRANSFER-V1"
SCHEMA = "chacha20-round20-dual-order-minimax-transfer-v1"
OPERATORS = ("numeric", "reflected_gray8")
FEATURES = {
    "conflicts": "ascending",
    "decisions": "ascending",
    "constraint_coherence": "descending",
}


def _sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _file_sha256(path: Path) -> str:
    return _sha256(path.read_bytes())


def _midranks(values: dict[str, float], *, descending: bool) -> dict[str, float]:
    result = {}
    population = list(values.values())
    for prefix, value in values.items():
        better = sum(other > value if descending else other < value for other in population)
        tied = sum(other == value for other in population)
        result[prefix] = 1.0 + better + (tied - 1) / 2.0
    return result


def _competition_rank(values: dict[str, float], target: str) -> int:
    value = values[target]
    return 1 + sum(other < value for other in values.values())


def _features(rows: list[dict[str, Any]]) -> dict[str, dict[str, float]]:
    result = {name: {} for name in FEATURES}
    for row in rows:
        conflicts, decisions, propagations = map(float, row["metrics_delta"])
        result["conflicts"][row["prefix8"]] = conflicts
        result["decisions"][row["prefix8"]] = decisions
        result["constraint_coherence"][row["prefix8"]] = (
            math.log1p(propagations)
            - math.log1p(decisions)
            - math.log1p(conflicts)
        )
    return result


def analyze() -> dict[str, Any]:
    corpus = json.loads(CORPUS_PATH.read_bytes())
    a225 = json.loads(A225_RESULT_PATH.read_bytes())
    if (
        corpus.get("schema") != "chacha20-round20-knownkey-trajectory-corpus-v1"
        or corpus.get("attempt_id") != "A218"
        or corpus.get("complete") is not True
        or corpus.get("operator_names") != list(OPERATORS)
        or len(corpus.get("challenges", [])) != 24
        or a225.get("schema") != "chacha20-round20-a223-w40-metal-transfer-v1"
        or a225.get("metal_execution", {}).get("complete_domain_executed") is not True
    ):
        raise RuntimeError("A226 input gate failed")

    challenge_rows = []
    for challenge in corpus["challenges"]:
        target = challenge["target_prefix8"]
        by_operator = {}
        for operator in OPERATORS:
            trajectory = challenge["trajectories"][operator]
            if (
                trajectory.get("retained_state_continuity_verified") is not True
                or trajectory.get("all_watchdogs_clear") is not True
                or len(trajectory.get("rows", [])) != 256
            ):
                raise RuntimeError(f"A226 malformed trajectory {challenge['label']} {operator}")
            by_operator[operator] = _features(trajectory["rows"])

        feature_rows = {}
        for feature, direction in FEATURES.items():
            ranks = {
                operator: _midranks(
                    by_operator[operator][feature],
                    descending=direction == "descending",
                )
                for operator in OPERATORS
            }
            prefixes = set(ranks[OPERATORS[0]])
            if prefixes != set(ranks[OPERATORS[1]]) or len(prefixes) != 256:
                raise RuntimeError("A226 operator prefix domains differ")
            minimax = {
                prefix: max(ranks[operator][prefix] for operator in OPERATORS)
                for prefix in prefixes
            }
            feature_rows[feature] = {
                "direction_per_operator": direction,
                "fusion": "minimum_worst_operator_rank",
                "target_operator_midranks": {
                    operator: ranks[operator][target] for operator in OPERATORS
                },
                "target_minimax_value": minimax[target],
                "target_joint_rank": _competition_rank(minimax, target),
                "all_candidate_joint_ranks": {
                    prefix: _competition_rank(minimax, prefix) for prefix in sorted(prefixes)
                },
            }
        challenge_rows.append(
            {
                "label": challenge["label"],
                "split": challenge["split"],
                "target_prefix8": target,
                "features": feature_rows,
            }
        )

    summaries = {}
    for feature in FEATURES:
        summaries[feature] = {}
        for split in ("all", "train", "validation"):
            rows = challenge_rows if split == "all" else [row for row in challenge_rows if row["split"] == split]
            ranks = [row["features"][feature]["target_joint_rank"] for row in rows]
            summaries[feature][split] = {
                "challenge_count": len(ranks),
                "ranks": ranks,
                "mean_rank": mean(ranks),
                "median_rank": median(ranks),
                "hit_at_8": sum(rank <= 8 for rank in ranks),
                "hit_at_16": sum(rank <= 16 for rank in ranks),
                "hit_at_32": sum(rank <= 32 for rank in ranks),
                "hit_at_64": sum(rank <= 64 for rank in ranks),
            }

    return {
        "schema": SCHEMA,
        "attempt_id": ATTEMPT_ID,
        "evidence_stage": "RETROSPECTIVE_DUAL_ORDER_MINIMAX_TRANSFER_READ",
        "result": (
            "The A225-derived target-blind minimax fusion is applied unchanged to "
            "both pre-existing A218 operator trajectories for all 24 known-key challenges."
        ),
        "anchors": {
            "A218_corpus_sha256": _file_sha256(CORPUS_PATH),
            "A225_result_sha256": _file_sha256(A225_RESULT_PATH),
        },
        "reader": {
            "operators": list(OPERATORS),
            "features": FEATURES,
            "operator_rank_method": "midrank",
            "fusion": "max_of_two_operator_midranks_lower_is_better",
            "joint_rank_method": "competition_rank",
            "target_label_used_only_after_candidate_scores_exist": True,
        },
        "challenge_results": challenge_rows,
        "summaries": summaries,
    }


def _atomic_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    raw = json.dumps(value, indent=2, sort_keys=True, allow_nan=False).encode() + b"\n"
    temporary = path.with_name(f".{path.name}.tmp")
    temporary.write_bytes(raw)
    temporary.replace(path)


def _write_report(path: Path, payload: dict[str, Any]) -> None:
    lines = [
        "# A226 — Dual-order minimax transfer",
        "",
        "The fixed reader ranks every prefix independently in Numeric and Gray order, "
        "then scores it by its worse of the two ranks. Lower is better.",
        "",
        "| Feature | Split | N | Median rank | Hit@16 | Hit@32 | Hit@64 |",
        "|---|---|---:|---:|---:|---:|---:|",
    ]
    for feature, by_split in payload["summaries"].items():
        for split, summary in by_split.items():
            lines.append(
                f"| `{feature}` | {split} | {summary['challenge_count']} | "
                f"{summary['median_rank']:.1f} | {summary['hit_at_16']} | "
                f"{summary['hit_at_32']} | {summary['hit_at_64']} |"
            )
    lines.append("")
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.tmp")
    temporary.write_text("\n".join(lines))
    temporary.replace(path)


def main(argv: Sequence[str] | None = None) -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, default=DEFAULT_RESULT_PATH)
    parser.add_argument("--report", type=Path, default=DEFAULT_REPORT_PATH)
    args = parser.parse_args(argv)
    payload = analyze()
    _atomic_json(args.output, payload)
    _write_report(args.report, payload)
    print(json.dumps(payload["summaries"], indent=2, sort_keys=True))


if __name__ == "__main__":
    main()

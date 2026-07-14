#!/usr/bin/env python3
"""Tie-aware deterministic readback of the valid A231 raw measurements."""

from __future__ import annotations

import hashlib
import importlib.util
import json
import statistics
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).parents[2]
RESEARCH = ROOT / "research"


def _import(path: Path, module_name: str) -> Any:
    spec = importlib.util.spec_from_file_location(module_name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


A231 = _import(
    Path(__file__).with_name("chacha20_round20_a229_multihorizon_replay.py"),
    "a232_a231_anchor",
)

ATTEMPT_ID = "R20-A232-A231-TIEAWARE-READ-V1"
SCHEMA = "chacha20-round20-a231-tieaware-read-v1"
OUTPUT = (
    RESEARCH
    / "results"
    / "v1"
    / "chacha20_round20_a231_tieaware_read_v1.json"
)
REPORT = (
    RESEARCH
    / "reports"
    / "CAUSAL_CHACHA20_ROUND20_A231_TIEAWARE_READ_V1.md"
)


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


def _rank(
    stages: list[dict[str, Any]],
    *,
    feature_name: str,
    target_prefix: str,
    descending: bool,
) -> dict[str, Any]:
    rows = [
        (stage["prefix8"], A231._stage_features(stage)[feature_name])
        for stage in stages
    ]
    target_value = next(value for prefix, value in rows if prefix == target_prefix)
    better = sum(
        value > target_value if descending else value < target_value
        for _, value in rows
    )
    tied_prefixes = sorted(prefix for prefix, value in rows if value == target_value)
    deterministic_tie_offset = tied_prefixes.index(target_prefix)
    return {
        "rank": 1 + better + deterministic_tie_offset,
        "strictly_better_count": better,
        "tie_count": len(tied_prefixes),
        "deterministic_prefix_tie_offset": deterministic_tie_offset,
        "target_value": target_value,
    }


def _candidate_matrix(raw: dict[str, Any]) -> dict[str, dict[str, Any]]:
    labels = raw["labels"]
    candidates = {}
    for schedule_name, runs in raw["schedules"].items():
        for horizon in A231.SCHEDULES[schedule_name]:
            per_challenge = []
            for run, label in zip(runs, labels, strict=True):
                stages = [stage for stage in run["stages"] if stage["horizon"] == horizon]
                if len(stages) != 256:
                    raise RuntimeError("A232 requires a complete A231 scalar matrix")
                per_challenge.append((stages, label["true_prefix8"]))
            for feature_name in A231._stage_features(per_challenge[0][0][0]):
                for descending in (False, True):
                    name = (
                        f"{schedule_name}.h{horizon}.{feature_name}."
                        f"{'desc' if descending else 'asc'}"
                    )
                    details = [
                        _rank(
                            stages,
                            feature_name=feature_name,
                            target_prefix=target_prefix,
                            descending=descending,
                        )
                        for stages, target_prefix in per_challenge
                    ]
                    candidates[name] = {
                        "ranks": [row["rank"] for row in details],
                        "details": details,
                    }
    return candidates


def _summary(
    name: str, candidate: dict[str, Any], indices: list[int]
) -> dict[str, Any]:
    ranks = [candidate["ranks"][index] for index in indices]
    return {
        "reader": name,
        "ranks": ranks,
        "top64_hits": sum(rank <= 64 for rank in ranks),
        "median_rank": statistics.median(ranks),
        "mean_rank": statistics.fmean(ranks),
        "worst_rank": max(ranks),
        "best_rank": min(ranks),
    }


def _selection_key(row: dict[str, Any]) -> tuple[Any, ...]:
    return (
        -row["top64_hits"],
        row["worst_rank"],
        row["median_rank"],
        row["mean_rank"],
        row["reader"],
    )


def main() -> None:
    if OUTPUT.exists():
        raise RuntimeError(f"A232 output already exists: {OUTPUT}")
    raw = json.loads(A231.OUTPUT.read_bytes())
    if (
        raw.get("schema") != A231.SCHEMA
        or len(raw.get("labels", [])) != A231.A229.CHALLENGE_COUNT
        or raw.get("information_boundary", {}).get(
            "all_fourteen_measurement_processes_completed_before_A230_labels_loaded"
        )
        is not True
    ):
        raise RuntimeError("A232 requires the complete A231 raw measurement artifact")
    candidates = _candidate_matrix(raw)
    indices = list(range(A231.A229.CHALLENGE_COUNT))
    global_rows = sorted(
        (_summary(name, candidate, indices) for name, candidate in candidates.items()),
        key=_selection_key,
    )
    leave_one_out = []
    for held in indices:
        training = [index for index in indices if index != held]
        selected = min(
            (
                _summary(name, candidate, training)
                for name, candidate in candidates.items()
            ),
            key=_selection_key,
        )
        held_rank = candidates[selected["reader"]]["ranks"][held]
        leave_one_out.append(
            {
                "held_challenge": held,
                "selected_reader_from_other_six": selected["reader"],
                "training_summary": selected,
                "held_rank": held_rank,
                "held_top64": held_rank <= 64,
            }
        )
    best = global_rows[0]
    payload = {
        "schema": SCHEMA,
        "attempt_id": ATTEMPT_ID,
        "evidence_stage": "TIEAWARE_DETERMINISTIC_READBACK_OF_A231_RAW_MEASUREMENTS",
        "anchors": {
            "A231_raw_result_sha256": _file_sha256(A231.OUTPUT),
            "A231_raw_measurements_retained": True,
        },
        "correction": {
            "A231_competition_rank_interpretation_superseded": True,
            "cause": "constant-valued channels produced large ties that competition rank assigned rank one",
            "replacement": "metric direction followed by ascending binary prefix as deterministic tie break",
        },
        "candidate_readers": candidates,
        "evaluation": {
            "candidate_reader_count": len(candidates),
            "globally_best_readers": global_rows[:32],
            "best_global_reader": best,
            "leave_one_key_out": leave_one_out,
            "leave_one_key_out_ranks": [row["held_rank"] for row in leave_one_out],
            "leave_one_key_out_top64_hits": sum(
                row["held_top64"] for row in leave_one_out
            ),
        },
        "prospective_consequence": {
            "reader_to_freeze": best["reader"],
            "reader_ranks_on_seven_known_keys": best["ranks"],
            "selected_cells": 64,
            "fresh_prospective_recovery_required": True,
        },
    }
    _atomic_json(OUTPUT, payload)
    lines = [
        "# A232 — Tie-aware A231 readback",
        "",
        "A231's raw H8/H16 measurements are valid. Its original scalar ranking is superseded because competition rank treated large ties as rank one.",
        "",
        f"- Best tie-aware reader: `{best['reader']}`",
        f"- Ranks: `{best['ranks']}`",
        f"- Top-64 hits: **{best['top64_hits']} / 7**",
        f"- Median rank: **{best['median_rank']}**",
        f"- Leave-one-key-out ranks: `{payload['evaluation']['leave_one_key_out_ranks']}`",
        "",
        "This reader is posthoc calibration and must be frozen on fresh challenges before a recovery claim.",
        "",
    ]
    REPORT.parent.mkdir(parents=True, exist_ok=True)
    temporary = REPORT.with_name(f".{REPORT.name}.tmp")
    temporary.write_text("\n".join(lines))
    temporary.replace(REPORT)
    print(
        json.dumps(
            {
                "best_global_reader": best,
                "leave_one_key_out_ranks": payload["evaluation"][
                    "leave_one_key_out_ranks"
                ],
                "leave_one_key_out_top64_hits": payload["evaluation"][
                    "leave_one_key_out_top64_hits"
                ],
                "output": str(OUTPUT),
            },
            indent=2,
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    main()

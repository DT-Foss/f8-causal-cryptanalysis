#!/usr/bin/env python3
"""Replay the seven labelled A229 W32 CNFs at early conflict horizons."""

from __future__ import annotations

import hashlib
import importlib.util
import json
import statistics
import sys
from concurrent.futures import ThreadPoolExecutor
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


A229 = _import(
    Path(__file__).with_name("chacha20_round20_w32_top64_batch_recovery.py"),
    "a231_a229_anchor",
)
MULTIHORIZON = _import(
    Path(__file__).with_name("chacha20_retained_multihorizon.py"),
    "a231_multihorizon_anchor",
)

ATTEMPT_ID = "R20-A231-A229-MULTIHORIZON-REPLAY-V1"
SCHEMA = "chacha20-round20-a229-multihorizon-replay-v1"
LABEL_PATH = (
    RESEARCH
    / "results"
    / "v1"
    / "chacha20_round20_a229_postbarrier_labels_v1.json"
)
OUTPUT = (
    RESEARCH
    / "results"
    / "v1"
    / "chacha20_round20_a229_multihorizon_replay_v1.json"
)
REPORT = (
    RESEARCH
    / "reports"
    / "CAUSAL_CHACHA20_ROUND20_A229_MULTIHORIZON_REPLAY_V1.md"
)
ARTIFACT_DIR = RESEARCH / "artifacts" / "a231_multihorizon_replay_v1"

SCHEDULES = {
    "one_shot_h8": [8],
    "one_shot_h16_wd30": [16],
}
WATCHDOG_SECONDS_BY_SCHEDULE = {
    "one_shot_h8": 5.0,
    "one_shot_h16_wd30": 30.0,
}
TOP_K = 64
MAX_WORKERS = 4


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


def _mapping20(structural: dict[str, Any]) -> list[int]:
    model = structural["transformed_model_one_literals_bit0_upward"]
    prefix = structural["transformed_prefix_one_literals_high_to_low"]
    if len(model) != 32 or len(prefix) != 8:
        raise RuntimeError("A231 requires the A229 W32 mapping")
    mapping = list(model[:12]) + [0] * 8
    for index, literal in enumerate(prefix):
        mapping[19 - index] = literal
    if len(mapping) != 20 or len({abs(value) for value in mapping}) != 20:
        raise RuntimeError("A231 compatible 20-literal projection is not bijective")
    return mapping


def _run_schedule(
    *,
    helper: Path,
    preflight: dict[str, Any],
    schedule_name: str,
    horizons: list[int],
) -> list[dict[str, Any]]:
    order = A229.A223._gray8_order()
    watchdog_seconds = WATCHDOG_SECONDS_BY_SCHEDULE[schedule_name]

    def run(row: dict[str, Any]) -> dict[str, Any]:
        index = int(row["index"])
        structural = row["structural_CNF"]
        artifact = ARTIFACT_DIR / f"{schedule_name}_challenge_{index:02d}.json"
        mode = f"A231_{schedule_name}_challenge_{index:02d}"
        if artifact.exists():
            retained = json.loads(artifact.read_bytes())
            if (
                retained.get("index") != index
                or retained.get("mode") != mode
                or retained.get("conflict_horizons") != horizons
                or retained.get("watchdog_seconds_per_stage") != watchdog_seconds
                or retained.get("all_watchdogs_clear") is not True
                or retained.get("summary", {}).get("cells") != 256
            ):
                raise RuntimeError(f"A231 retained arm identity differs: {artifact}")
            return retained
        result = MULTIHORIZON.run_multihorizon(
            helper=helper,
            cnf=ROOT / structural["artifact"],
            mode=mode,
            order=order,
            key_one_literals_bit0_through_bit19=_mapping20(structural),
            conflict_horizons=horizons,
            watchdog_seconds=watchdog_seconds,
            external_timeout_seconds=300.0,
        )
        retained = {"index": index, **result}
        _atomic_json(artifact, retained)
        return retained

    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        rows = list(executor.map(run, preflight["challenge_preflights"]))
    rows.sort(key=lambda row: row["index"])
    if [row["index"] for row in rows] != list(range(A229.CHALLENGE_COUNT)):
        raise RuntimeError("A231 schedule challenge coverage differs")
    return rows


def _stage_features(stage: dict[str, Any]) -> dict[str, float]:
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
        "redundant_clauses_stage_delta": float(
            stage["redundant_clauses_stage_delta"]
        ),
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


def _rank(values: list[float], target_index: int, *, descending: bool) -> int:
    target = values[target_index]
    return 1 + sum(value > target if descending else value < target for value in values)


def _candidate_matrix(
    schedules: dict[str, list[dict[str, Any]]], labels: list[dict[str, Any]]
) -> dict[str, list[int]]:
    candidates: dict[str, list[int]] = {}
    for schedule_name, runs in schedules.items():
        horizons = SCHEDULES[schedule_name]
        for horizon in horizons:
            per_challenge = []
            for run, label in zip(runs, labels, strict=True):
                stages = [stage for stage in run["stages"] if stage["horizon"] == horizon]
                if len(stages) != 256:
                    raise RuntimeError(
                        f"A231 terminal stage prevents complete {schedule_name} h{horizon} matrix"
                    )
                target_index = next(
                    index
                    for index, stage in enumerate(stages)
                    if stage["prefix8"] == label["true_prefix8"]
                )
                per_challenge.append((stages, target_index))
            feature_names = _stage_features(per_challenge[0][0][0]).keys()
            for feature_name in feature_names:
                for descending in (False, True):
                    name = (
                        f"{schedule_name}.h{horizon}.{feature_name}."
                        f"{'desc' if descending else 'asc'}"
                    )
                    candidates[name] = [
                        _rank(
                            [_stage_features(stage)[feature_name] for stage in stages],
                            target_index,
                            descending=descending,
                        )
                        for stages, target_index in per_challenge
                    ]
    return candidates


def _summary(name: str, ranks: list[int], indices: list[int]) -> dict[str, Any]:
    selected = [ranks[index] for index in indices]
    return {
        "reader": name,
        "ranks": selected,
        "top64_hits": sum(rank <= TOP_K for rank in selected),
        "median_rank": statistics.median(selected),
        "mean_rank": statistics.fmean(selected),
        "worst_rank": max(selected),
        "best_rank": min(selected),
    }


def _selection_key(row: dict[str, Any]) -> tuple[Any, ...]:
    return (
        -row["top64_hits"],
        row["worst_rank"],
        row["median_rank"],
        row["mean_rank"],
        row["reader"],
    )


def _evaluate(candidates: dict[str, list[int]]) -> dict[str, Any]:
    all_indices = list(range(A229.CHALLENGE_COUNT))
    global_rows = sorted(
        (_summary(name, ranks, all_indices) for name, ranks in candidates.items()),
        key=_selection_key,
    )
    leave_one_out = []
    for held in all_indices:
        training = [index for index in all_indices if index != held]
        selected = min(
            (_summary(name, ranks, training) for name, ranks in candidates.items()),
            key=_selection_key,
        )
        held_rank = candidates[selected["reader"]][held]
        leave_one_out.append(
            {
                "held_challenge": held,
                "selected_reader_from_other_six": selected["reader"],
                "training_summary": selected,
                "held_rank": held_rank,
                "held_top64": held_rank <= TOP_K,
            }
        )
    return {
        "candidate_reader_count": len(candidates),
        "globally_best_readers": global_rows[:32],
        "leave_one_key_out": leave_one_out,
        "leave_one_key_out_ranks": [row["held_rank"] for row in leave_one_out],
        "leave_one_key_out_top64_hits": sum(
            row["held_top64"] for row in leave_one_out
        ),
    }


def _write_report(payload: dict[str, Any]) -> None:
    evaluation = payload["evaluation"]
    lines = [
        "# A231 — A229 multi-horizon replay",
        "",
        f"- Leave-one-key-out top-64 hits: **{evaluation['leave_one_key_out_top64_hits']} / 7**",
        f"- Leave-one-key-out ranks: `{evaluation['leave_one_key_out_ranks']}`",
        "",
        "## Globally strongest scalar readers (descriptive)",
        "",
        "| Reader | Ranks | Top-64 | Median | Worst |",
        "|---|---|---:|---:|---:|",
    ]
    for row in evaluation["globally_best_readers"][:16]:
        lines.append(
            f"| `{row['reader']}` | {row['ranks']} | {row['top64_hits']}/7 | "
            f"{row['median_rank']} | {row['worst_rank']} |"
        )
    lines.append("")
    REPORT.parent.mkdir(parents=True, exist_ok=True)
    temporary = REPORT.with_name(f".{REPORT.name}.tmp")
    temporary.write_text("\n".join(lines))
    temporary.replace(REPORT)


def main() -> None:
    if OUTPUT.exists():
        raise RuntimeError(f"A231 output already exists: {OUTPUT}")
    preflight = json.loads(A229.PREFLIGHT_PATH.read_bytes())
    a229 = json.loads(A229.RESULT_PATH.read_bytes())
    if (
        a229.get("schema") != A229.RESULT_SCHEMA
        or a229.get("aggregate", {}).get("success_count") != 0
        or a229.get("aggregate", {}).get(
            "all_selected_regions_completed_without_early_stop"
        )
        is not True
        or len(preflight.get("challenge_preflights", [])) != A229.CHALLENGE_COUNT
    ):
        raise RuntimeError("A231 requires completed A229 and its seven retained CNFs")

    build = MULTIHORIZON.compile_helper()
    helper = Path(build["binary_path"])
    schedules = {
        schedule_name: _run_schedule(
            helper=helper,
            preflight=preflight,
            schedule_name=schedule_name,
            horizons=horizons,
        )
        for schedule_name, horizons in SCHEDULES.items()
    }

    # Label barrier: no A230 label is loaded until every helper process has completed.
    labels_artifact = json.loads(LABEL_PATH.read_bytes())
    labels = labels_artifact.get("labels", [])
    if (
        labels_artifact.get("schema")
        != "chacha20-round20-a229-postbarrier-labels-v1"
        or len(labels) != A229.CHALLENGE_COUNT
        or [row.get("index") for row in labels]
        != list(range(A229.CHALLENGE_COUNT))
    ):
        raise RuntimeError("A231 A230 label identity gate failed")
    candidates = _candidate_matrix(schedules, labels)
    evaluation = _evaluate(candidates)
    payload = {
        "schema": SCHEMA,
        "attempt_id": ATTEMPT_ID,
        "evidence_stage": "KNOWNKEY_W32_EIGHT_BLOCK_MULTIHORIZON_REPLAY_AND_GROUP_TRANSFER",
        "anchors": {
            "A229_preflight_sha256": _file_sha256(A229.PREFLIGHT_PATH),
            "A229_result_sha256": _file_sha256(A229.RESULT_PATH),
            "A230_labels_sha256": _file_sha256(LABEL_PATH),
            "multihorizon_wrapper_sha256": _file_sha256(MULTIHORIZON.WRAPPER),
            "multihorizon_source_sha256": _file_sha256(MULTIHORIZON.SOURCE),
            "multihorizon_helper_sha256": _file_sha256(helper),
        },
        "information_boundary": {
            "all_fourteen_measurement_processes_completed_before_A230_labels_loaded": True,
            "helper_processes_received_no_true_prefix_or_key_word0": True,
            "leave_one_key_out_reader_selected_only_from_other_six_labels": True,
            "known_key_calibration_not_a_prospective_recovery_claim": True,
        },
        "native_build": build,
        "schedules": schedules,
        "labels": [
            {
                "index": row["index"],
                "true_prefix8": row["true_prefix8"],
                "confirmation_sha256": _sha256(
                    json.dumps(
                        row["confirmation"],
                        sort_keys=True,
                        separators=(",", ":"),
                    ).encode()
                ),
            }
            for row in labels
        ],
        "candidate_ranks": candidates,
        "evaluation": evaluation,
    }
    _atomic_json(OUTPUT, payload)
    _write_report(payload)
    print(
        json.dumps(
            {
                "leave_one_key_out_ranks": evaluation[
                    "leave_one_key_out_ranks"
                ],
                "leave_one_key_out_top64_hits": evaluation[
                    "leave_one_key_out_top64_hits"
                ],
                "globally_best_reader": evaluation["globally_best_readers"][0],
                "output": str(OUTPUT),
            },
            indent=2,
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    main()

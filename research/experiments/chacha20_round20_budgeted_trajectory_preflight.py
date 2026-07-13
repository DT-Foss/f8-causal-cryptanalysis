#!/usr/bin/env python3
"""Calibrate deterministic conflict budgets on the already revealed R20 anchor."""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import sys
import tempfile
from pathlib import Path
from typing import Any

import numpy as np
from scipy.stats import spearmanr

ROOT = Path(__file__).parents[2]
RESEARCH = ROOT / "research"
R20_RUNNER = RESEARCH / "experiments/chacha20_round20_global_incremental_transfer.py"
R20_RUNNER_SHA256 = "1825035b90317e9d6c8a2ee0894f2569eada44177ee01ced49d043ca37ec881d"
TEMPLATE_HELPER = RESEARCH / "experiments/chacha20_round20_symbolic_template.py"
TEMPLATE_HELPER_SHA256 = "34f4c5542f7fa12e7b0ff06ab7e042605c2414f23001f11894fa6dbdfc0b4721"
TRAJECTORY_HELPER = RESEARCH / "experiments/chacha20_round20_budgeted_trajectory.py"
TEMPLATE_PROTOCOL = RESEARCH / "configs/chacha20_round20_knownkey_propagation_atlas_v3.json"
TEMPLATE_PROTOCOL_SHA256 = "aa5b7af87c74cbffe7f6d3e50332cc65c07f084435edb4314b32e4904b625698"
R20_RESULT = RESEARCH / "results/v1/chacha20_round20_global_incremental_transfer_v1.json"
R20_RESULT_SHA256 = "a5be062ebce29cbc864ef926c55a1f9dbaadd69c9edcc54aed43552304f8e3f0"
DEFAULT_OUTPUT = RESEARCH / "results/v1/chacha20_round20_budgeted_trajectory_preflight_v1.json"


def _sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _file_sha256(path: Path) -> str:
    return _sha256(path.read_bytes())


def _import_path(path: Path, name: str) -> Any:
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot import {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _atomic_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.tmp")
    temporary.write_bytes(
        json.dumps(value, indent=2, sort_keys=True, allow_nan=False).encode() + b"\n"
    )
    temporary.replace(path)


def _exact_rank(values: np.ndarray, target: int, *, descending: bool) -> int:
    scores = np.asarray(values, dtype=np.float64)
    target_score = scores[target]
    candidates = np.arange(len(scores))
    if descending:
        return (
            1
            + int(np.count_nonzero(scores > target_score))
            + int(np.count_nonzero((scores == target_score) & (candidates < target)))
        )
    return (
        1
        + int(np.count_nonzero(scores < target_score))
        + int(np.count_nonzero((scores == target_score) & (candidates < target)))
    )


def _aligned(trajectory: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {row["prefix8"]: row for row in trajectory["rows"]}


def _feature(row: dict[str, Any], name: str) -> float:
    if name.startswith("metric_"):
        index = {"conflicts": 0, "decisions": 1, "propagations": 2}[name.removeprefix("metric_")]
        return float(row["metrics_delta"][index])
    return float(row[name])


FEATURES = (
    "metric_conflicts",
    "metric_decisions",
    "metric_propagations",
    "active_variables_delta",
    "irredundant_clauses_delta",
    "redundant_clauses_delta",
)


def _summarize_run(trajectory: dict[str, Any], target_prefix: int) -> dict[str, Any]:
    aligned = _aligned(trajectory)
    rows = [aligned[f"{prefix:08b}"] for prefix in range(256)]
    feature_summary: dict[str, Any] = {}
    for name in FEATURES:
        values = np.asarray([_feature(row, name) for row in rows], dtype=np.float64)
        feature_summary[name] = {
            "minimum": float(values.min()),
            "maximum": float(values.max()),
            "mean": float(values.mean()),
            "standard_deviation": float(values.std()),
            "distinct_values": int(len(np.unique(values))),
            "revealed_anchor_target_value": float(values[target_prefix]),
            "revealed_anchor_target_descending_rank": _exact_rank(
                values, target_prefix, descending=True
            ),
            "revealed_anchor_target_ascending_rank": _exact_rank(
                values, target_prefix, descending=False
            ),
        }
    return {
        "status_counts": {
            status: sum(row["status"] == status for row in rows)
            for status in ("sat", "unsat", "unknown")
        },
        "budget_exhausted_cells": sum(row["budget_exhausted"] for row in rows),
        "watchdog_fires": sum(row["watchdog_fired"] for row in rows),
        "process_elapsed_seconds": trajectory["process_elapsed_seconds"],
        "feature_summary": feature_summary,
    }


def _paired_summary(left: dict[str, Any], right: dict[str, Any]) -> dict[str, Any]:
    left_rows, right_rows = _aligned(left), _aligned(right)
    result: dict[str, Any] = {}
    for name in FEATURES:
        left_values = np.asarray(
            [_feature(left_rows[f"{prefix:08b}"], name) for prefix in range(256)]
        )
        right_values = np.asarray(
            [_feature(right_rows[f"{prefix:08b}"], name) for prefix in range(256)]
        )
        if np.all(left_values == left_values[0]) or np.all(right_values == right_values[0]):
            correlation = float("nan")
        else:
            correlation = spearmanr(left_values, right_values).statistic
        result[name] = {
            "same_prefix_spearman": (float(correlation) if np.isfinite(correlation) else None),
            "identical_prefix_values": int(np.count_nonzero(left_values == right_values)),
            "mean_absolute_delta": float(np.mean(np.abs(left_values - right_values))),
        }
    return result


def run(output: Path) -> dict[str, Any]:
    anchors = {
        R20_RUNNER: R20_RUNNER_SHA256,
        TEMPLATE_HELPER: TEMPLATE_HELPER_SHA256,
        TEMPLATE_PROTOCOL: TEMPLATE_PROTOCOL_SHA256,
        R20_RESULT: R20_RESULT_SHA256,
    }
    differences = {
        str(path.relative_to(ROOT)): _file_sha256(path)
        for path, expected in anchors.items()
        if _file_sha256(path) != expected
    }
    if differences:
        raise RuntimeError(f"A218P anchor drift: {differences}")
    r20 = _import_path(R20_RUNNER, "a218p_r20")
    template = _import_path(TEMPLATE_HELPER, "a218p_template")
    trajectory = _import_path(TRAJECTORY_HELPER, "a218p_trajectory")
    protocol = json.loads(TEMPLATE_PROTOCOL.read_bytes())
    retained = json.loads(R20_RESULT.read_bytes())
    recovered = {row["recovered_unknown_low20"] for row in retained["confirmations"]}
    if len(recovered) != 1:
        raise RuntimeError("A218P revealed R20 anchor is not unique")
    target_low20 = recovered.pop()
    target_prefix = target_low20 >> 12
    analysis = r20.analyze()
    public = analysis["public_challenge"]
    helper_build = trajectory.compile_helper()
    with tempfile.TemporaryDirectory(prefix="a218p-budgeted-r20-") as raw_directory:
        directory = Path(raw_directory)
        base_raw, key_mapping, output_mapping, template_manifest = template.compile_template(
            r20=r20,
            public_challenge=public,
            protocol=protocol,
            directory=directory,
        )
        target_raw, _, target_instantiation = template.instantiate_output(
            base_raw, output_mapping, public["target_words"][0]
        )
        if (
            target_instantiation["sha256"]
            != protocol["symbolic_R20_template"]["instantiated_target_sha256"]
        ):
            raise RuntimeError("A218P symbolic target instantiation differs")
        cnf = directory / "a218p_revealed_anchor.cnf"
        cnf.write_bytes(target_raw)
        orders = {
            "numeric": trajectory.numeric_order(),
            "reflected_gray8": trajectory.reflected_gray8_order(),
        }
        runs: dict[str, dict[str, Any]] = {}
        for budget in (16, 32):
            for mode, order in orders.items():
                name = f"conflicts{budget}_{mode}"
                print(f"A218P start {name}", flush=True)
                runs[name] = trajectory.run_trajectory(
                    helper=trajectory.BINARY,
                    cnf=cnf,
                    mode=name,
                    order=order,
                    key_one_literals_bit0_through_bit19=key_mapping,
                    conflict_budget=budget,
                    watchdog_seconds=5.0,
                    external_timeout_seconds=600.0,
                )
                print(f"A218P complete {name}", flush=True)
    summaries = {name: _summarize_run(value, target_prefix) for name, value in runs.items()}
    paired = {
        f"conflicts{budget}": _paired_summary(
            runs[f"conflicts{budget}_numeric"],
            runs[f"conflicts{budget}_reflected_gray8"],
        )
        for budget in (16, 32)
    }
    payload = {
        "schema": "chacha20-round20-budgeted-trajectory-preflight-v1",
        "attempt_id": "A218P",
        "evidence_stage": "FULLROUND_R20_BUDGETED_TRAJECTORY_CALIBRATION",
        "scientific_scope": (
            "posthoc calibration on the already revealed R20 anchor; it selects a "
            "deterministic conflict budget and does not count as prospective target evidence"
        ),
        "anchor_hashes": {
            str(path.relative_to(ROOT)): expected for path, expected in anchors.items()
        },
        "trajectory_helper_sha256": _file_sha256(TRAJECTORY_HELPER),
        "native_helper_source_sha256": _file_sha256(trajectory.SOURCE),
        "native_helper_binary_sha256": _file_sha256(trajectory.BINARY),
        "native_helper_build": helper_build,
        "symbolic_template_manifest": template_manifest,
        "target_instantiation": target_instantiation,
        "revealed_anchor_target_low20": target_low20,
        "revealed_anchor_target_prefix8": f"{target_prefix:08b}",
        "runs": runs,
        "run_summaries": summaries,
        "paired_operator_summaries": paired,
        "all_runs_complete": len(runs) == 4,
        "all_retained_state_continuity_verified": all(
            row["retained_state_continuity_verified"] for row in runs.values()
        ),
        "all_watchdogs_clear": all(row["all_watchdogs_clear"] for row in runs.values()),
    }
    measurement_summaries = {
        name: {key: value for key, value in summary.items() if key != "process_elapsed_seconds"}
        for name, summary in summaries.items()
    }
    payload["measurement_hash_scope"] = {
        "included": ["run_summaries_without_wall_time", "paired_operator_summaries"],
        "excluded": ["process_elapsed_seconds"],
    }
    payload["measurement_sha256"] = _sha256(
        json.dumps(
            {"summaries": measurement_summaries, "paired": paired},
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode()
    )
    _atomic_json(output, payload)
    return payload


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    arguments = parser.parse_args()
    payload = run(arguments.output)
    print(
        json.dumps(
            {
                "output": str(arguments.output),
                "output_sha256": _file_sha256(arguments.output),
                "measurement_sha256": payload["measurement_sha256"],
                "run_summaries": payload["run_summaries"],
            },
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    main()

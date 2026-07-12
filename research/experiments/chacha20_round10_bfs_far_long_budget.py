#!/usr/bin/env python3
"""Long-budget transfer of the A207 systematic BFS-far search-density outlier."""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import subprocess
import sys
import tempfile
import time
from collections.abc import Sequence
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any

import numpy as np

from arx_carry_leak.crypto_causal import CryptoCausalBuilder, CryptoCausalReader


def _import_sibling(filename: str, module_name: str) -> Any:
    path = Path(__file__).with_name(filename)
    spec = importlib.util.spec_from_file_location(module_name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


_A207 = _import_sibling(
    "chacha20_round10_structural_portfolio.py",
    "chacha20_a208_a207_anchor",
)
_ARCHIVE = _A207._ARCHIVE
_A206 = _A207._A206
_A205 = _A207._A205
_A204 = _A207._A204
_A198 = _A207._A198

ATTEMPT_ID = "A208"
SCHEMA = "chacha20-round10-bfs-far-long-budget-transfer-v1"
PROTOCOL_SCHEMA = "chacha20-round10-bfs-far-long-budget-transfer-protocol-v1"
PROTOCOL_FILENAME = "chacha20_round10_bfs_far_long_budget_v1.json"
PROTOCOL_SHA256 = "c5c08f078b3b3d9487d593850bcf469f4bd95f788bb4d0bca85b8ae7a58ee104"
RESULT_FILENAME = "chacha20_round10_bfs_far_long_budget_v1.json"
CAUSAL_FILENAME = "chacha20_round10_bfs_far_long_budget_v1.causal"

A207_FILENAME = _A207.RESULT_FILENAME
A207_SHA256 = "80ce896083b239e3bb95e31433fc8cdf6157491005bbb3b024182f730b545652"
A207_CAUSAL_FILENAME = _A207.CAUSAL_FILENAME
A207_CAUSAL_SHA256 = "0d23f4fcb91c6602b3222315afb84f203eff8f5d51b0e4df5f6f6430616d6dfa"
A207_CAUSAL_GRAPH_SHA256 = "ceb1013b7c5387dedbcf5dfe7c5072fe73c200ba72f5d42b5ff7b0866ddb9b14"
ORDER_ARCHIVE_FILENAME = _A207.ORDER_ARCHIVE_FILENAME
ORDER_ARCHIVE_SHA256 = _A207.ORDER_ARCHIVE_SHA256
ORDER_METADATA_FILENAME = _A207.ORDER_METADATA_FILENAME
ORDER_METADATA_SHA256 = _A207.ORDER_METADATA_SHA256
ORDER_CAUSAL_FILENAME = _A207.ORDER_CAUSAL_FILENAME
ORDER_CAUSAL_SHA256 = _A207.ORDER_CAUSAL_SHA256
ORDER_CAUSAL_GRAPH_SHA256 = _A207.ORDER_CAUSAL_GRAPH_SHA256

SELECTED_CANDIDATE = "output_unit_bfs_far"
ARCHIVE_ROW_INDEX = 5
SOLVER_MODE = "reverse"
PREFIXES = _A204.PREFIXES
VARIANTS = _A204.VARIANTS
MAX_PARALLEL_WORKERS = 4
SOLVER_LIMIT_SECONDS = 60
EXTERNAL_TIMEOUT_SECONDS = 65
BASELINE_LIMIT_SECONDS = 10


def _sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _canonical_sha256(value: Any) -> str:
    return _A204._canonical_sha256(value)


def _file_sha256(path: Path) -> str:
    return _A204._file_sha256(path)


def _load_protocol_gate() -> dict[str, Any]:
    path = Path(__file__).parents[1] / "configs" / PROTOCOL_FILENAME
    if _file_sha256(path) != PROTOCOL_SHA256:
        raise RuntimeError("A208 frozen protocol hash differs")
    protocol = json.loads(path.read_bytes())
    selection = protocol.get("selection", {})
    order = protocol.get("candidate_order", {})
    source = protocol.get("round10_source", {})
    plan = protocol.get("execution_plan", {})
    boundary = protocol.get("information_boundary", {})
    if (
        protocol.get("schema") != PROTOCOL_SCHEMA
        or protocol.get("attempt_id") != ATTEMPT_ID
        or protocol.get("protocol_state")
        != "frozen_after_complete_A207_progress_map_selection_before_any_A208_solver_execution"
        or selection.get("selected_candidate") != SELECTED_CANDIDATE
        or selection.get("archive_row_index") != ARCHIVE_ROW_INDEX
        or selection.get("solver_mode") != SOLVER_MODE
        or selection.get("selection_time_data_used") is not False
        or selection.get("A207_total_ratios", {}).get("conflicts_per_propagation")
        != 4.644075913140431
        or selection.get("A207_total_ratios", {}).get("decisions_per_propagation")
        != 9.571921365274823
        or selection.get("A207_all_prefix_direction_gates", {}).get("conflicts_ratio_min")
        != 1.703481842006739
        or selection.get("A207_all_prefix_direction_gates", {}).get("decisions_ratio_min")
        != 3.3145624103299856
        or selection.get("A207_all_prefix_direction_gates", {}).get("propagations_ratio_max")
        != 0.7555339998822715
        or order.get("order_sha256")
        != "7d324874eef605c9b648ad50511d74a2bb351878a42c7f79bb96ded9a6633370"
        or order.get("old_to_new_sha256")
        != "7ed58987174cd64065d9bf0e7451843e2e92e328eeb0ceeecff9ed0bc9c5d519"
        or source.get("prefix_order") != list(PREFIXES)
        or source.get("common_normalized_sha256")
        != "a9cd80dc9e7934f3c29681a78e4d734d598205e81b9796e9413b78be85e4fa2b"
        or plan.get("solver_time_limit_seconds_per_cell") != SOLVER_LIMIT_SECONDS
        or plan.get("external_timeout_seconds_per_cell") != EXTERNAL_TIMEOUT_SECONDS
        or plan.get("max_parallel_workers") != MAX_PARALLEL_WORKERS
        or plan.get("cell_count") != len(PREFIXES)
        or plan.get("inverse_restore_prefix_endpoints") != ["00000", "11111"]
        or plan.get("early_stop_permitted") is not False
        or boundary.get("any_A208_solver_outcome_known_before_freeze") is not False
        or boundary.get("round10_unknown_assignment_in_protocol_source_or_order_archive")
        is not False
        or boundary.get("round10_unknown_assignment_available_to_runner_before_execution")
        is not False
        or boundary.get("selection_used_only_complete_A207_progress_metrics_not_volatile_seconds")
        is not True
        or boundary.get(
            "candidate_order_mode_prefix_order_budget_or_predictions_changed_after_any_A208_outcome"
        )
        is not False
        or boundary.get("early_stop_permitted") is not False
    ):
        raise RuntimeError("A208 frozen protocol identity gate failed")
    return protocol


def _load_anchor_gates(
    results_dir: Path, protocol: dict[str, Any]
) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    research_root = Path(__file__).parents[1]
    a207_protocol = research_root / "configs" / _A207.PROTOCOL_FILENAME
    a207_runner = Path(__file__).with_name("chacha20_round10_structural_portfolio.py")
    a207_result_path = results_dir / A207_FILENAME
    a207_causal_path = results_dir / A207_CAUSAL_FILENAME
    archive_path = results_dir / ORDER_ARCHIVE_FILENAME
    metadata_path = results_dir / ORDER_METADATA_FILENAME
    order_causal_path = results_dir / ORDER_CAUSAL_FILENAME
    if (
        _file_sha256(a207_protocol) != protocol["anchors"]["A207"]["protocol_sha256"]
        or _file_sha256(a207_runner) != protocol["anchors"]["A207"]["runner_sha256"]
        or _file_sha256(a207_result_path) != A207_SHA256
        or _file_sha256(a207_causal_path) != A207_CAUSAL_SHA256
        or _file_sha256(archive_path) != ORDER_ARCHIVE_SHA256
        or _file_sha256(metadata_path) != ORDER_METADATA_SHA256
        or _file_sha256(order_causal_path) != ORDER_CAUSAL_SHA256
    ):
        raise RuntimeError("A208 A207/order-archive anchor hash gate failed")
    a207 = json.loads(a207_result_path.read_bytes())
    metadata = json.loads(metadata_path.read_bytes())
    a207_reader = CryptoCausalReader(a207_causal_path)
    order_reader = CryptoCausalReader(order_causal_path)
    summary = next(
        row
        for row in a207["progress_map"]["candidate_summaries"]
        if row["candidate"] == SELECTED_CANDIDATE
    )
    metrics = summary["metrics"]
    if (
        a207.get("progress_map_sha256") != protocol["anchors"]["A207"]["progress_map_sha256"]
        or a207.get("comparisons", {}).get("new_status_counts")
        != {"sat": 0, "unsat": 0, "unknown": 352, "invalid": 0}
        or metrics["conflicts"]["total_ratio"] != 2.7585773439810706
        or metrics["decisions"]["total_ratio"] != 5.685713565082508
        or metrics["propagations"]["total_ratio"] != 0.5939991928589421
        or metrics["restarts"]["total_ratio"] != 0.478
        or metrics["conflicts"]["cell_ratio_min"] != 1.703481842006739
        or metrics["decisions"]["cell_ratio_min"] != 3.3145624103299856
        or metrics["propagations"]["cell_ratio_max"] != 0.7555339998822715
        or a207_reader.graph_sha256 != A207_CAUSAL_GRAPH_SHA256
        or not a207_reader.verify_provenance()
        or metadata.get("archive_sha256") != ORDER_ARCHIVE_SHA256
        or order_reader.graph_sha256 != ORDER_CAUSAL_GRAPH_SHA256
        or not order_reader.verify_provenance()
    ):
        raise RuntimeError("A208 A207 progress/order semantic anchor gate failed")
    gates = {
        "A207_result_sha256": A207_SHA256,
        "A207_causal_sha256": A207_CAUSAL_SHA256,
        "A207_causal_graph_sha256": A207_CAUSAL_GRAPH_SHA256,
        "A207_causal_provenance_verified": True,
        "A207_complete_352_unknown_boundary_retained": True,
        "A207_selected_progress_outlier_retained": True,
        "order_archive_sha256": ORDER_ARCHIVE_SHA256,
        "order_metadata_sha256": ORDER_METADATA_SHA256,
        "order_causal_sha256": ORDER_CAUSAL_SHA256,
        "order_causal_graph_sha256": ORDER_CAUSAL_GRAPH_SHA256,
        "order_causal_provenance_verified": True,
    }
    return a207, metadata, gates


def analyze(results_dir: Path) -> dict[str, Any]:
    protocol = _load_protocol_gate()
    a207, metadata, gates = _load_anchor_gates(results_dir, protocol)
    a207_analysis = _A207.analyze(results_dir)
    matrix = np.load(results_dir / ORDER_ARCHIVE_FILENAME, mmap_mode="r", allow_pickle=False)
    metadata_row = metadata["candidate_manifest"][ARCHIVE_ROW_INDEX]
    order = np.asarray(matrix[ARCHIVE_ROW_INDEX], dtype=np.int64)
    if (
        metadata_row["candidate"] != SELECTED_CANDIDATE
        or metadata_row["order_sha256"] != protocol["candidate_order"]["order_sha256"]
        or _sha256(order.astype("<u4", copy=False).tobytes())
        != protocol["candidate_order"]["order_sha256"]
        or a207_analysis["public_challenge"]["unknown_assignment_included"] is not False
    ):
        raise RuntimeError("A208 archived order/public challenge boundary gate failed")
    baseline_observations = [
        row for row in a207["execution"]["observations"] if row["candidate"] == SELECTED_CANDIDATE
    ]
    if len(baseline_observations) != 32:
        raise RuntimeError("A208 exact A207 selected baseline count differs")
    return {
        "protocol": protocol,
        "anchor_gates": gates,
        "a207_result": a207,
        "order_metadata": metadata,
        "metadata_row": metadata_row,
        "order": order,
        "a207_analysis": a207_analysis,
        "public_challenge": a207_analysis["public_challenge"],
        "formulas": a207_analysis["formulas"],
        "formula_plan": a207_analysis["formula_plan"],
        "baseline_observations": baseline_observations,
        "solver_execution_started": False,
    }


def _run_cell(
    *,
    variant: str,
    cnf_path: Path,
    transformed_mapping: Sequence[int],
    challenge: dict[str, Any],
    cadical_path: str,
) -> tuple[dict[str, Any], dict[str, Any] | None]:
    prefix = variant[-5:]
    label = f"{SELECTED_CANDIDATE}__{variant}__reverse__long60"
    command = [
        cadical_path,
        "--reverse=true",
        "-t",
        str(SOLVER_LIMIT_SECONDS),
        str(cnf_path),
    ]
    started = time.perf_counter()
    try:
        result = subprocess.run(
            command,
            text=True,
            capture_output=True,
            timeout=EXTERNAL_TIMEOUT_SECONDS,
            check=False,
        )
        externally_timed_out = False
        stdout, stderr, returncode = result.stdout, result.stderr, result.returncode
    except subprocess.TimeoutExpired as error:
        externally_timed_out = True
        stdout = _A204._as_text(error.stdout)
        stderr = _A204._as_text(error.stderr)
        returncode = None
    status = _A204._cadical_status(stdout, returncode)
    status_lines = [line.strip() for line in stdout.splitlines() if line.startswith("s ")]
    recognized_unknown = status == "unknown" and (
        status_lines == ["s UNKNOWN"]
        or any(line.startswith("c Timeout reached!") for line in stdout.splitlines())
    )
    invalid_reason = None
    if externally_timed_out:
        status = "invalid"
        invalid_reason = "external_timeout"
    elif status == "unknown" and (returncode != 0 or not recognized_unknown):
        status = "invalid"
        invalid_reason = "unrecognized_unknown_boundary"
    elif status == "invalid":
        invalid_reason = "invalid_solver_status_or_returncode"
    witness = _A204._parse_cadical_witness(stdout) if status == "sat" else {}
    model = None
    confirmation = None
    if status == "sat":
        model = _A204._decode_round10_model(
            challenge=challenge,
            prefix=prefix,
            witness=witness,
            mapping=transformed_mapping,
        )
        confirmation = {
            "variant": label,
            "candidate": SELECTED_CANDIDATE,
            "solver_mode": SOLVER_MODE,
            "source_variant": variant,
            "prefix": prefix,
            **_A198._confirm_model(challenge, model),
        }
        if (
            confirmation["known_key_constraints_match"] is not True
            or confirmation["all_blocks_match"] is not True
            or confirmation["control_first_block_match"] is not False
            or confirmation["output_bits_checked"] != 4096
        ):
            raise RuntimeError(f"A208 {label} decoded model failed independent confirmation")
    observation = {
        "variant": label,
        "candidate": SELECTED_CANDIDATE,
        "solver_mode": SOLVER_MODE,
        "source_variant": variant,
        "prefix": prefix,
        "command": command,
        "status": status,
        "status_line": status_lines[0] if len(status_lines) == 1 else None,
        "internal_timeout_marker": any(
            line.startswith("c Timeout reached!") for line in stdout.splitlines()
        ),
        "returncode": returncode,
        "externally_timed_out": externally_timed_out,
        "invalid_reason": invalid_reason,
        "volatile_seconds": time.perf_counter() - started,
        "witness_assignment_count": len(witness),
        "metrics": _A205._solver_metrics(stdout),
        "model": model,
        "transformed_cnf_sha256": _file_sha256(cnf_path),
        "stdout_sha256": _sha256(stdout.encode()),
        "stderr_sha256": _sha256(stderr.encode()),
    }
    return observation, confirmation


def _execute(
    *,
    transformed_paths: dict[str, Path],
    transformed_mapping: Sequence[int],
    challenge: dict[str, Any],
    cadical_path: str,
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    observations = []
    confirmations = []
    waves = []
    for wave_index, start in enumerate(range(0, len(VARIANTS), MAX_PARALLEL_WORKERS)):
        wave = VARIANTS[start : start + MAX_PARALLEL_WORKERS]

        def execute(variant: str) -> tuple[dict[str, Any], dict[str, Any] | None]:
            return _run_cell(
                variant=variant,
                cnf_path=transformed_paths[variant],
                transformed_mapping=transformed_mapping,
                challenge=challenge,
                cadical_path=cadical_path,
            )

        with ThreadPoolExecutor(max_workers=MAX_PARALLEL_WORKERS) as executor:
            rows = list(executor.map(execute, wave))
        for observation, confirmation in rows:
            observations.append(observation)
            if confirmation is not None:
                confirmations.append(confirmation)
        waves.append(
            {
                "wave_index": wave_index,
                "variants": [row[0]["variant"] for row in rows],
                "statuses": [row[0]["status"] for row in rows],
                "maximum_volatile_seconds": max(row[0]["volatile_seconds"] for row in rows),
            }
        )
    expected = [f"{SELECTED_CANDIDATE}__{variant}__reverse__long60" for variant in VARIANTS]
    if [row["variant"] for row in observations] != expected:
        raise RuntimeError("A208 complete execution order differs from freeze")
    return {
        "variant_order": expected,
        "complete_cell_plan_executed": len(observations) == 32,
        "early_stop_used": False,
        "observations": observations,
        "wave_observations": waves,
        "returned_model_count": len(confirmations),
        "round10_unknown_assignment_available_to_runner_before_execution": False,
    }, confirmations


def _rate_comparison(
    observations: list[dict[str, Any]], baseline_observations: list[dict[str, Any]]
) -> dict[str, Any]:
    baseline = {row["prefix"]: row for row in baseline_observations}
    metrics = ("conflicts", "decisions", "propagations", "restarts")
    rows = []
    for observation in observations:
        base = baseline[observation["prefix"]]
        metric_rows = {}
        for metric in metrics:
            current = observation["metrics"].get(metric)
            prior = base["metrics"].get(metric)
            metric_rows[metric] = {
                "A208_total": current,
                "A207_total": prior,
                "raw_total_ratio": current / prior if current is not None and prior else None,
                "nominal_per_second_ratio": (
                    (current / SOLVER_LIMIT_SECONDS) / (prior / BASELINE_LIMIT_SECONDS)
                    if current is not None and prior
                    else None
                ),
                "volatile_per_second_ratio": (
                    (current / observation["volatile_seconds"]) / (prior / base["volatile_seconds"])
                    if current is not None
                    and prior
                    and observation["volatile_seconds"] > 0
                    and base["volatile_seconds"] > 0
                    else None
                ),
            }
        rows.append(
            {
                "prefix": observation["prefix"],
                "A208_variant": observation["variant"],
                "A207_variant": base["variant"],
                "metrics": metric_rows,
            }
        )
    totals = {}
    for metric in metrics:
        current_values = [
            row["metrics"].get(metric)
            for row in observations
            if row["metrics"].get(metric) is not None
        ]
        prior_values = [
            row["metrics"].get(metric)
            for row in baseline_observations
            if row["metrics"].get(metric) is not None
        ]
        matched_pairs = [
            (
                row["metrics"][metric]["A208_total"],
                row["metrics"][metric]["A207_total"],
            )
            for row in rows
            if row["metrics"][metric]["A208_total"] is not None
            and row["metrics"][metric]["A207_total"] is not None
        ]
        current_total = sum(current for current, _ in matched_pairs) if matched_pairs else None
        prior_total = sum(prior for _, prior in matched_pairs) if matched_pairs else None
        nominal_ratios = [
            row["metrics"][metric]["nominal_per_second_ratio"]
            for row in rows
            if row["metrics"][metric]["nominal_per_second_ratio"] is not None
        ]
        totals[metric] = {
            "A208_total": current_total,
            "A207_total": prior_total,
            "totals_use_only_same_prefix_matched_metric_pairs": True,
            "matched_prefix_count": len(matched_pairs),
            "A208_all_observed_total": sum(current_values) if current_values else None,
            "A207_full_baseline_total": sum(prior_values) if prior_values else None,
            "A208_metric_observation_count": len(current_values),
            "A208_metric_missing_count": len(observations) - len(current_values),
            "A207_metric_observation_count": len(prior_values),
            "A207_metric_missing_count": len(baseline_observations) - len(prior_values),
            "raw_total_ratio": (
                current_total / prior_total
                if current_total is not None and prior_total not in {None, 0}
                else None
            ),
            "nominal_per_second_ratio": (
                (current_total / SOLVER_LIMIT_SECONDS) / (prior_total / BASELINE_LIMIT_SECONDS)
                if current_total is not None and prior_total not in {None, 0}
                else None
            ),
            "cell_nominal_rate_ratio_count": len(nominal_ratios),
            "cell_nominal_rate_ratio_min": min(nominal_ratios) if nominal_ratios else None,
            "cell_nominal_rate_ratio_median": (
                float(np.median(nominal_ratios)) if nominal_ratios else None
            ),
            "cell_nominal_rate_ratio_max": max(nominal_ratios) if nominal_ratios else None,
        }
    return {
        "baseline": "A207_output_unit_bfs_far_reverse_same_prefix_at_10_seconds",
        "A208_nominal_budget_seconds": SOLVER_LIMIT_SECONDS,
        "A207_nominal_budget_seconds": BASELINE_LIMIT_SECONDS,
        "cell_rows": rows,
        "total_metrics": totals,
    }


def _compare(execution: dict[str, Any], confirmations: list[dict[str, Any]]) -> dict[str, Any]:
    observations = execution["observations"]
    status_counts = {
        status: sum(row["status"] == status for row in observations)
        for status in ("sat", "unsat", "unknown", "invalid")
    }
    recovered = sorted({row["recovered_unknown_low20"] for row in confirmations})
    complete = (
        status_counts == {"sat": 1, "unsat": 31, "unknown": 0, "invalid": 0} and len(recovered) == 1
    )
    return {
        "complete_cell_count": len(observations),
        "complete_predeclared_execution": len(observations) == 32,
        "early_stop_used": False,
        "status_counts": status_counts,
        "confirmed_variants": [row["variant"] for row in confirmations],
        "confirmed_prefixes": sorted({row["prefix"] for row in confirmations}),
        "confirmed_combined_assignments": sorted(
            {row["combined_assignment"] for row in confirmations}
        ),
        "recovered_unknown_low20_assignments": recovered,
        "confirmed_recovery_retained": len(confirmations) >= 1,
        "complete_domain_resolution_retained": complete,
        "complete_partition_and_disjoint_by_construction": True,
        "complete_domain_candidate_count": 1 << 20,
        "statuses": {row["variant"]: row["status"] for row in observations},
    }


def _build_causal(path: Path, payload: dict[str, Any]) -> dict[str, Any]:
    builder = CryptoCausalBuilder(
        experiment="chacha20_round10_bfs_far_long_budget",
        parameters={
            "attempt_id": ATTEMPT_ID,
            "rounds": 10,
            "unknown_key_bits": 20,
            "cells": 32,
            "solver_seconds_per_cell": SOLVER_LIMIT_SECONDS,
        },
    )
    ids = [
        "chacha20-a208-a207-portfolio-anchor",
        "chacha20-a208-systematic-density-selection",
        "chacha20-a208-exact-order-source",
        "chacha20-a208-complete-long-execution",
        "chacha20-a208-independent-confirmation",
        "chacha20-a208-rate-comparison",
        "chacha20-a208-long-budget-result",
    ]
    rows = [
        (
            "A207:complete_416_cell_calibrated_portfolio_boundary",
            "retain_all_statuses_metrics_and_native_provenance",
            "A208:complete_progress_map_anchor",
            "retained_A207_portfolio",
            A207_CAUSAL_SHA256,
            [],
            {"anchor_gates": payload["anchor_gates"]},
        ),
        (
            "A208:complete_progress_map_anchor",
            "select_the_every_prefix_BFS_far_conflict_and_decision_density_outlier",
            "A208:frozen_long_budget_candidate",
            "prospective_progress_selection",
            payload["selection_sha256"],
            [ids[0]],
            {"selection": payload["selection"]},
        ),
        (
            "A208:frozen_long_budget_candidate",
            "load_the_exact_archived_order_and_replay_all_32_transformed_CNF_cells",
            "A208:semantics_preserved_long_budget_cover",
            "exact_order_and_transform",
            payload["transform_manifest_sha256"],
            [ids[1]],
            {
                "order_archive": payload["order_archive"],
                "transform_manifest": payload["transform_manifest"],
            },
        ),
        (
            "A208:semantics_preserved_long_budget_cover",
            "execute_all_32_prefix_cells_at_the_frozen_60_second_budget",
            "A208:complete_long_budget_execution",
            "complete_predeclared_solver_execution",
            payload["execution_sha256"],
            [ids[2]],
            {"execution": payload["execution"]},
        ),
        (
            "A208:complete_long_budget_execution",
            "decode_every_SAT_witness_and_recompute_all_4096_target_bits",
            "A208:independently_confirmed_models_or_boundary",
            "independent_model_confirmation",
            payload["confirmation_sha256"],
            [ids[3]],
            {"confirmations": payload["confirmations"]},
        ),
        (
            "A208:independently_confirmed_models_or_boundary",
            "compare_same_prefix_metric_rates_to_the_exact_A207_10_second_trajectory",
            "A208:long_budget_search_density_trajectory",
            "same_candidate_rate_comparison",
            payload["rate_comparison_sha256"],
            [ids[4]],
            {"rate_comparison": payload["rate_comparison"]},
        ),
        (
            "A208:long_budget_search_density_trajectory",
            "evaluate_confirmed_recovery_and_complete_domain_resolution_predictions",
            "A208:prospective_long_budget_result",
            "prospective_long_budget_comparison",
            payload["comparison_sha256"],
            [ids[5]],
            {"comparisons": payload["comparisons"]},
        ),
    ]
    for index, row in enumerate(rows):
        trigger, mechanism, outcome, kind, source, provenance, attrs = row
        builder.add_triplet(
            edge_id=ids[index],
            trigger=trigger,
            mechanism=mechanism,
            outcome=outcome,
            confidence=1.0,
            evidence_kind=kind,
            source=source,
            provenance=provenance,
            attrs=attrs,
        )
    stats = dict(builder.save(path))
    stats.pop("path", None)
    reader = CryptoCausalReader(path)
    if len(reader.triplets(include_inferred=False)) != len(ids) or not reader.verify_provenance():
        raise RuntimeError("A208 Causal Reader provenance gate failed")
    return {
        "stats": stats,
        "explicit_triplets": len(ids),
        "provenance_verified": True,
        "file_sha256": reader.file_sha256,
        "graph_sha256": reader.graph_sha256,
    }


def run(*, results_dir: Path, output: Path, causal_output: Path) -> dict[str, Any]:
    analysis = analyze(results_dir)
    protocol = analysis["protocol"]
    identities = _A204._solver_gates(_A204._load_protocol_gate())
    transform_protocol = {
        "round10_source": protocol["round10_source"],
        "execution_plan": {
            "inverse_restore_prefix_endpoints_per_candidate": protocol["execution_plan"][
                "inverse_restore_prefix_endpoints"
            ]
        },
    }
    with tempfile.TemporaryDirectory(prefix="a208-bfs-far-long-") as raw_directory:
        directory = Path(raw_directory)
        source_exports, source_paths = _A204._export_round10_cnfs(
            analysis["a207_analysis"]["a206_analysis"]["a204_analysis"], identities, directory
        )
        transform_manifest, transformed_paths, transformed_mapping = (
            _A207._candidate_transform_family(
                candidate=SELECTED_CANDIDATE,
                order=analysis["order"],
                metadata_row=analysis["metadata_row"],
                source_paths=source_paths,
                protocol=transform_protocol,
                directory=directory,
            )
        )
        execution, confirmations = _execute(
            transformed_paths=transformed_paths,
            transformed_mapping=transformed_mapping,
            challenge=analysis["public_challenge"],
            cadical_path=identities["cadical"]["path"],
        )

    rate_comparison = _rate_comparison(execution["observations"], analysis["baseline_observations"])
    comparisons = _compare(execution, confirmations)
    if comparisons["complete_domain_resolution_retained"]:
        evidence_stage = "ROUND10_BFS_FAR_LONG_COMPLETE_DOMAIN_RESOLUTION_RETAINED"
    elif comparisons["confirmed_recovery_retained"]:
        evidence_stage = "ROUND10_BFS_FAR_LONG_CONFIRMED_RECOVERY_RETAINED"
    else:
        evidence_stage = "ROUND10_BFS_FAR_LONG_COMPLETE_BOUNDARY_RETAINED"
    clean_source_exports = [
        {key: value for key, value in row.items() if key != "path"} for row in source_exports
    ]
    order_archive = {
        "archive_sha256": ORDER_ARCHIVE_SHA256,
        "metadata_sha256": ORDER_METADATA_SHA256,
        "archive_row_index": ARCHIVE_ROW_INDEX,
        "candidate": SELECTED_CANDIDATE,
        "order_sha256": protocol["candidate_order"]["order_sha256"],
        "old_to_new_sha256": protocol["candidate_order"]["old_to_new_sha256"],
    }
    payload: dict[str, Any] = {
        "schema": SCHEMA,
        "attempt_id": ATTEMPT_ID,
        "evidence_stage": evidence_stage,
        "result": (
            "The systematic A207 output-unit-BFS-far search-density outlier is executed "
            "prospectively over every Round-10 prefix cell at a 60-second budget."
        ),
        "scope": "Reduced ChaCha10 20-bit partial-key recovery over eight shared-key blocks.",
        "protocol_gate": {
            "artifact_sha256": PROTOCOL_SHA256,
            "protocol_state": protocol["protocol_state"],
            "information_boundary": protocol["information_boundary"],
            "prospective_predictions": protocol["prospective_predictions"],
        },
        "anchor_gates": analysis["anchor_gates"],
        "selection": protocol["selection"],
        "selection_sha256": _canonical_sha256(protocol["selection"]),
        "solver_identities": {
            "bitwuzla": identities["bitwuzla"],
            "cadical": identities["cadical"],
        },
        "public_challenge": analysis["public_challenge"],
        "public_challenge_sha256": _A198.PUBLIC_CHALLENGE_SHA256,
        "formula_plan": analysis["formula_plan"],
        "formula_plan_sha256": _canonical_sha256(analysis["formula_plan"]),
        "order_archive": order_archive,
        "order_archive_sha256": _canonical_sha256(order_archive),
        "source_exports": clean_source_exports,
        "source_exports_sha256": _canonical_sha256(clean_source_exports),
        "transform_manifest": transform_manifest,
        "transform_manifest_sha256": _canonical_sha256(transform_manifest),
        "execution_plan": protocol["execution_plan"],
        "execution_plan_sha256": _canonical_sha256(protocol["execution_plan"]),
        "execution": execution,
        "execution_sha256": _canonical_sha256(execution),
        "confirmations": confirmations,
        "confirmation_sha256": _canonical_sha256(confirmations),
        "rate_comparison": rate_comparison,
        "rate_comparison_sha256": _canonical_sha256(rate_comparison),
        "comparisons": comparisons,
        "comparison_sha256": _canonical_sha256(comparisons),
    }
    causal = _build_causal(causal_output, payload)
    payload["causal"] = causal
    raw = json.dumps(payload, indent=2, sort_keys=True, allow_nan=False).encode() + b"\n"
    _A204._A198._A185._atomic_write(output, raw)
    reader = CryptoCausalReader(causal_output)
    if (
        _file_sha256(output) != _sha256(raw)
        or reader.file_sha256 != causal["file_sha256"]
        or not reader.verify_provenance()
    ):
        raise RuntimeError("A208 final artifact reopen gate failed")
    return {
        "json_sha256": _sha256(raw),
        "causal_sha256": reader.file_sha256,
        "causal_graph_sha256": reader.graph_sha256,
        "evidence_stage": evidence_stage,
        "status_counts": comparisons["status_counts"],
        "confirmed_variants": comparisons["confirmed_variants"],
        "recovered_unknown_low20_assignments": comparisons["recovered_unknown_low20_assignments"],
        "complete_domain_resolution_retained": comparisons["complete_domain_resolution_retained"],
        "output": str(output),
        "causal_output": str(causal_output),
    }


def main(argv: Sequence[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    research_root = Path(__file__).parents[1]
    parser.add_argument("--results-dir", type=Path, default=research_root / "results" / "v1")
    parser.add_argument("--analyze-only", action="store_true")
    parser.add_argument(
        "--output", type=Path, default=research_root / "results" / "v1" / RESULT_FILENAME
    )
    parser.add_argument(
        "--causal-output",
        type=Path,
        default=research_root / "results" / "v1" / CAUSAL_FILENAME,
    )
    args = parser.parse_args(argv)
    if args.analyze_only:
        analysis = analyze(args.results_dir.resolve())
        summary = {
            "protocol_sha256": PROTOCOL_SHA256,
            "selected_candidate": analysis["protocol"]["selection"]["selected_candidate"],
            "solver_mode": analysis["protocol"]["selection"]["solver_mode"],
            "cells": analysis["protocol"]["execution_plan"]["cell_count"],
            "seconds_per_cell": analysis["protocol"]["execution_plan"][
                "solver_time_limit_seconds_per_cell"
            ],
            "solver_execution_started": analysis["solver_execution_started"],
        }
    else:
        summary = run(
            results_dir=args.results_dir.resolve(),
            output=args.output.resolve(),
            causal_output=args.causal_output.resolve(),
        )
    print(json.dumps(summary, sort_keys=True))


if __name__ == "__main__":
    main()

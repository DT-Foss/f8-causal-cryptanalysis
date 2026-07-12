#!/usr/bin/env python3
"""Execute the remaining calibrated structural-order portfolio over ChaCha10."""

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


_ARCHIVE = _import_sibling(
    "chacha20_round10_structural_order_archive.py",
    "chacha20_a207_structural_archive_anchor",
)
_A206 = _ARCHIVE._A206
_A205 = _A206._A205
_A204 = _A206._A204
_A198 = _A204._A198

ATTEMPT_ID = "A207"
SCHEMA = "chacha20-round10-structural-portfolio-transfer-v1"
PROTOCOL_SCHEMA = "chacha20-round10-structural-portfolio-transfer-protocol-v1"
PROTOCOL_FILENAME = "chacha20_round10_structural_portfolio_v1.json"
PROTOCOL_SHA256 = "05bbf03fac0f6d817e4af040df070673a6da1e6f618cca8193c860819fb20127"
RESULT_FILENAME = "chacha20_round10_structural_portfolio_v1.json"
CAUSAL_FILENAME = "chacha20_round10_structural_portfolio_v1.causal"

A206_FILENAME = _A206.RESULT_FILENAME
A206_SHA256 = _ARCHIVE.A206_SHA256
A206_CAUSAL_FILENAME = _A206.CAUSAL_FILENAME
A206_CAUSAL_SHA256 = _ARCHIVE.A206_CAUSAL_SHA256
A206_CAUSAL_GRAPH_SHA256 = _ARCHIVE.A206_CAUSAL_GRAPH_SHA256
ARCHIVE_RUNNER_SHA256 = "db8a611629773eb1af545879de04403ff90f821bd98cf12c407bafd0fa5f1bf6"
ORDER_ARCHIVE_FILENAME = _ARCHIVE.ARCHIVE_FILENAME
ORDER_ARCHIVE_SHA256 = "ea45134552a6ad3bb6c277ec6bd271d22764f902298b78bda568aef57a12f72f"
ORDER_METADATA_FILENAME = _ARCHIVE.METADATA_FILENAME
ORDER_METADATA_SHA256 = "b6dfb42095d176823c15d36a490297eb24bc85feedb916513b329d52808a73ce"
ORDER_CAUSAL_FILENAME = _ARCHIVE.CAUSAL_FILENAME
ORDER_CAUSAL_SHA256 = "71295ac95e3a2e5248e5d58cf3a40053bfe2a84f3ce30145f07b5abdbed9a58c"
ORDER_CAUSAL_GRAPH_SHA256 = "dad19e2848cb3d480713113b45cfc4a65344b3582ada2bccceec1ce9321c061b"

PREFIXES = _A204.PREFIXES
VARIANTS = _A204.VARIANTS
REMAINING_CANDIDATES = tuple(
    name for name in _ARCHIVE.CANDIDATE_ORDER if name != "bidirectional_min_distance"
)
MAX_PARALLEL_WORKERS = 4
SOLVER_LIMIT_SECONDS = 10
EXTERNAL_TIMEOUT_SECONDS = 13


def _sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _canonical_sha256(value: Any) -> str:
    return _A204._canonical_sha256(value)


def _file_sha256(path: Path) -> str:
    return _A204._file_sha256(path)


def _load_protocol_gate() -> dict[str, Any]:
    path = Path(__file__).parents[1] / "configs" / PROTOCOL_FILENAME
    if _file_sha256(path) != PROTOCOL_SHA256:
        raise RuntimeError("A207 frozen protocol hash differs")
    protocol = json.loads(path.read_bytes())
    portfolio = protocol.get("complete_calibrated_portfolio", {})
    source = protocol.get("round10_source", {})
    plan = protocol.get("execution_plan", {})
    boundary = protocol.get("information_boundary", {})
    if (
        protocol.get("schema") != PROTOCOL_SCHEMA
        or protocol.get("attempt_id") != ATTEMPT_ID
        or protocol.get("protocol_state")
        != "frozen_after_A207_order_archive_and_A206_complete_boundary_before_any_A207_remaining_portfolio_solver_execution"
        or portfolio.get("candidate_order") != list(_ARCHIVE.CANDIDATE_ORDER)
        or portfolio.get("remaining_candidate_order") != list(REMAINING_CANDIDATES)
        or portfolio.get("A206_completed_candidate") != "bidirectional_min_distance"
        or portfolio.get("A206_reexecution_permitted") is not False
        or portfolio.get("solver_mode_by_remaining_candidate")
        != {candidate: _ARCHIVE.CALIBRATED_MODES[candidate] for candidate in REMAINING_CANDIDATES}
        or portfolio.get("volatile_calibration_time_used_for_selection") is not False
        or source.get("prefix_order") != list(PREFIXES)
        or source.get("cell_count") != len(PREFIXES)
        or source.get("common_normalized_sha256")
        != "a9cd80dc9e7934f3c29681a78e4d734d598205e81b9796e9413b78be85e4fa2b"
        or plan.get("solver_time_limit_seconds_per_cell") != SOLVER_LIMIT_SECONDS
        or plan.get("external_timeout_seconds_per_cell") != EXTERNAL_TIMEOUT_SECONDS
        or plan.get("max_parallel_workers") != MAX_PARALLEL_WORKERS
        or plan.get("remaining_candidate_count") != len(REMAINING_CANDIDATES)
        or plan.get("new_cell_mode_count") != len(REMAINING_CANDIDATES) * len(PREFIXES)
        or plan.get("combined_with_A206_cell_mode_count") != 416
        or plan.get("inverse_restore_prefix_endpoints_per_candidate") != ["00000", "11111"]
        or plan.get("early_stop_permitted") is not False
        or boundary.get("any_A207_remaining_portfolio_solver_outcome_known_before_freeze")
        is not False
        or boundary.get("round10_unknown_assignment_in_protocol_source_or_order_archive")
        is not False
        or boundary.get("round10_unknown_assignment_available_to_runner_before_execution")
        is not False
        or boundary.get(
            "unrelated_A188_known_positive_model_used_in_A207_order_transform_or_solver_input"
        )
        is not False
        or boundary.get(
            "candidate_order_modes_prefix_order_budget_or_comparison_rules_changed_after_any_A207_outcome"
        )
        is not False
        or boundary.get("A206_candidate_reexecution_permitted") is not False
        or boundary.get("early_stop_permitted") is not False
    ):
        raise RuntimeError("A207 frozen protocol identity gate failed")
    return protocol


def _load_anchor_gates(
    results_dir: Path, protocol: dict[str, Any]
) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    research_root = Path(__file__).parents[1]
    archive_runner = Path(__file__).with_name("chacha20_round10_structural_order_archive.py")
    a206_protocol = research_root / "configs" / _A206.PROTOCOL_FILENAME
    a206_result_path = results_dir / A206_FILENAME
    a206_causal_path = results_dir / A206_CAUSAL_FILENAME
    archive_path = results_dir / ORDER_ARCHIVE_FILENAME
    metadata_path = results_dir / ORDER_METADATA_FILENAME
    order_causal_path = results_dir / ORDER_CAUSAL_FILENAME
    if (
        _file_sha256(a206_protocol) != protocol["anchors"]["A206"]["protocol_sha256"]
        or _file_sha256(a206_result_path) != A206_SHA256
        or _file_sha256(a206_causal_path) != A206_CAUSAL_SHA256
        or _file_sha256(archive_runner) != ARCHIVE_RUNNER_SHA256
        or _file_sha256(archive_path) != ORDER_ARCHIVE_SHA256
        or _file_sha256(metadata_path) != ORDER_METADATA_SHA256
        or _file_sha256(order_causal_path) != ORDER_CAUSAL_SHA256
    ):
        raise RuntimeError("A207 A206/order-archive anchor hash gate failed")
    a206 = json.loads(a206_result_path.read_bytes())
    metadata = json.loads(metadata_path.read_bytes())
    a206_reader = CryptoCausalReader(a206_causal_path)
    order_reader = CryptoCausalReader(order_causal_path)
    if (
        a206.get("comparisons", {}).get("status_counts")
        != {"sat": 0, "unsat": 0, "unknown": 64, "invalid": 0}
        or a206.get("execution", {}).get("complete_cell_mode_plan_executed") is not True
        or a206_reader.graph_sha256 != A206_CAUSAL_GRAPH_SHA256
        or not a206_reader.verify_provenance()
        or metadata.get("candidate_manifest_sha256")
        != protocol["anchors"]["A207_order_archive"]["candidate_manifest_sha256"]
        or metadata.get("archive_sha256") != ORDER_ARCHIVE_SHA256
        or metadata.get("information_boundary", {}).get(
            "any_A207_remaining_portfolio_solver_outcome_known_before_archive_derivation"
        )
        is not False
        or order_reader.graph_sha256 != ORDER_CAUSAL_GRAPH_SHA256
        or not order_reader.verify_provenance()
    ):
        raise RuntimeError("A207 A206/order-archive semantic anchor gate failed")
    gates = {
        "A206_result_sha256": A206_SHA256,
        "A206_causal_sha256": A206_CAUSAL_SHA256,
        "A206_causal_graph_sha256": A206_CAUSAL_GRAPH_SHA256,
        "A206_causal_provenance_verified": True,
        "A206_complete_64_unknown_boundary_retained": True,
        "order_archive_runner_sha256": ARCHIVE_RUNNER_SHA256,
        "order_archive_sha256": ORDER_ARCHIVE_SHA256,
        "order_metadata_sha256": ORDER_METADATA_SHA256,
        "order_causal_sha256": ORDER_CAUSAL_SHA256,
        "order_causal_graph_sha256": ORDER_CAUSAL_GRAPH_SHA256,
        "order_causal_provenance_verified": True,
        "order_archive_12_exact_permutations_retained": True,
    }
    return a206, metadata, gates


def analyze(results_dir: Path) -> dict[str, Any]:
    protocol = _load_protocol_gate()
    a206, metadata, gates = _load_anchor_gates(results_dir, protocol)
    a206_analysis = _A206.analyze(results_dir)
    matrix = np.load(results_dir / ORDER_ARCHIVE_FILENAME, mmap_mode="r", allow_pickle=False)
    manifest = metadata["candidate_manifest"]
    if (
        matrix.shape != (12, 232191)
        or matrix.dtype != np.dtype("<i4")
        or [row["candidate"] for row in manifest] != list(_ARCHIVE.CANDIDATE_ORDER)
        or a206_analysis["public_challenge"]["unknown_assignment_included"] is not False
        or a206_analysis["public_challenge"]["unknown_key_word0_low_value_included"] is not False
    ):
        raise RuntimeError("A207 archive/public challenge boundary gate failed")
    for index, row in enumerate(manifest):
        digest = _sha256(np.asarray(matrix[index], dtype="<u4").tobytes())
        if digest != row["order_sha256"]:
            raise RuntimeError(f"A207 archived row {index} hash gate failed")
    return {
        "protocol": protocol,
        "anchor_gates": gates,
        "a206_result": a206,
        "order_metadata": metadata,
        "a206_analysis": a206_analysis,
        "public_challenge": a206_analysis["public_challenge"],
        "formulas": a206_analysis["formulas"],
        "formula_plan": a206_analysis["formula_plan"],
        "solver_execution_started": False,
    }


def _candidate_transform_family(
    *,
    candidate: str,
    order: np.ndarray,
    metadata_row: dict[str, Any],
    source_paths: dict[str, Path],
    protocol: dict[str, Any],
    directory: Path,
) -> tuple[list[dict[str, Any]], dict[str, Path], list[int]]:
    variable_count = len(order)
    expected_ids = np.arange(1, variable_count + 1, dtype=np.int64)
    if not np.array_equal(np.sort(order), expected_ids):
        raise RuntimeError(f"A207 {candidate} archived order is not a permutation")
    mapping = _A205._old_to_new(order)
    inverse = np.zeros_like(mapping)
    inverse[mapping[1:]] = expected_ids
    order_sha256 = _sha256(order.astype("<u4", copy=False).tobytes())
    mapping_sha256 = _sha256(mapping.astype("<u4", copy=False).tobytes())
    source_mapping = protocol["round10_source"]["free_k0_bit_one_literal_mapping"]
    transformed_free_mapping = [
        int(mapping[abs(literal)]) if literal > 0 else -int(mapping[abs(literal)])
        for literal in source_mapping
    ]
    if (
        order_sha256 != metadata_row["order_sha256"]
        or mapping_sha256 != metadata_row["old_to_new_sha256"]
        or transformed_free_mapping != metadata_row["transformed_free_k0_bit_one_literal_mapping"]
        or _canonical_sha256(transformed_free_mapping)
        != metadata_row["transformed_free_mapping_sha256"]
    ):
        raise RuntimeError(f"A207 {candidate} archived mapping gate failed")
    expected_normalized = metadata_row["representative_transformed_cnf_sha256"]
    inverse_prefixes = set(
        protocol["execution_plan"]["inverse_restore_prefix_endpoints_per_candidate"]
    )
    manifest = []
    transformed_paths = {}
    for variant in VARIANTS:
        prefix = variant[-5:]
        raw = source_paths[variant].read_bytes()
        transformed = _A205._reindex_cnf(raw, mapping)
        header, tail_units, normalized_sha256 = _A204._normalized_cnf(transformed)
        if normalized_sha256 != expected_normalized:
            raise RuntimeError(f"A207 {candidate}/{prefix} normalized transform differs")
        inverse_checked = prefix in inverse_prefixes
        inverse_restored_sha256 = None
        if inverse_checked:
            restored = _A205._reindex_cnf(transformed, inverse)
            if restored != raw:
                raise RuntimeError(f"A207 {candidate}/{prefix} inverse endpoint gate failed")
            inverse_restored_sha256 = _sha256(restored)
        output = directory / f"{variant}__{candidate}.cnf"
        output.write_bytes(transformed)
        row = {
            "candidate": candidate,
            "source_variant": variant,
            "prefix": prefix,
            "source_cnf_sha256": _sha256(raw),
            "transformed_cnf_sha256": _sha256(transformed),
            "transformed_cnf_bytes": len(transformed),
            "transformed_header": header,
            "transformed_tail_units": tail_units,
            "transformed_normalized_sha256": normalized_sha256,
            "inverse_endpoint_checked": inverse_checked,
            "inverse_restored_sha256": inverse_restored_sha256,
        }
        manifest.append(row)
        transformed_paths[variant] = output
    representative = manifest[-1]
    if (
        representative["prefix"] != "11111"
        or representative["transformed_cnf_sha256"]
        != metadata_row["representative_transformed_cnf_sha256"]
        or representative["transformed_cnf_bytes"]
        != metadata_row["representative_transformed_cnf_bytes"]
        or representative["inverse_restored_sha256"] != metadata_row["inverse_restored_sha256"]
        or sum(row["inverse_endpoint_checked"] for row in manifest) != 2
    ):
        raise RuntimeError(f"A207 {candidate} representative transform gate failed")
    return manifest, transformed_paths, transformed_free_mapping


def _run_cell(
    *,
    candidate: str,
    mode_name: str,
    variant: str,
    cnf_path: Path,
    transformed_mapping: Sequence[int],
    challenge: dict[str, Any],
    cadical_path: str,
) -> tuple[dict[str, Any], dict[str, Any] | None]:
    prefix = variant[-5:]
    mode_arguments = [] if mode_name == "default" else ["--reverse=true"]
    label = f"{candidate}__{variant}__{mode_name}"
    command = [
        cadical_path,
        *mode_arguments,
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
            "candidate": candidate,
            "solver_mode": mode_name,
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
            raise RuntimeError(f"A207 {label} decoded model failed independent confirmation")
    observation = {
        "variant": label,
        "candidate": candidate,
        "solver_mode": mode_name,
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
        "volatile_seconds": time.perf_counter() - started,
        "witness_assignment_count": len(witness),
        "metrics": _A205._solver_metrics(stdout),
        "model": model,
        "transformed_cnf_sha256": _file_sha256(cnf_path),
        "stdout_sha256": _sha256(stdout.encode()),
        "stderr_sha256": _sha256(stderr.encode()),
    }
    if status == "unknown":
        recognized_unknown = (
            observation["status_line"] == "s UNKNOWN"
            or observation["internal_timeout_marker"] is True
        )
        if returncode != 0 or not recognized_unknown or externally_timed_out is not False:
            raise RuntimeError(f"A207 {label} invalid UNKNOWN boundary")
    return observation, confirmation


def _execute_candidate(
    *,
    candidate: str,
    mode_name: str,
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
                candidate=candidate,
                mode_name=mode_name,
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
    expected = [f"{candidate}__{variant}__{mode_name}" for variant in VARIANTS]
    if [row["variant"] for row in observations] != expected:
        raise RuntimeError(f"A207 {candidate} execution order differs")
    return {
        "candidate": candidate,
        "solver_mode": mode_name,
        "variant_order": expected,
        "complete_prefix_plan_executed": len(observations) == 32,
        "early_stop_used": False,
        "observations": observations,
        "wave_observations": waves,
        "returned_model_count": len(confirmations),
    }, confirmations


def _progress_map(observations: list[dict[str, Any]], a206: dict[str, Any]) -> dict[str, Any]:
    baselines = {
        (row["prefix"], row["solver_mode"]): row for row in a206["execution"]["observations"]
    }
    metrics = ("conflicts", "decisions", "propagations", "restarts")
    rows = []
    for observation in observations:
        baseline = baselines[(observation["prefix"], observation["solver_mode"])]
        ratios = {}
        for metric in metrics:
            candidate_value = observation["metrics"].get(metric)
            baseline_value = baseline["metrics"].get(metric)
            ratios[metric] = (
                candidate_value / baseline_value
                if candidate_value is not None and baseline_value not in {None, 0}
                else None
            )
        rows.append(
            {
                "variant": observation["variant"],
                "candidate": observation["candidate"],
                "solver_mode": observation["solver_mode"],
                "prefix": observation["prefix"],
                "baseline_variant": baseline["variant"],
                "candidate_metrics": observation["metrics"],
                "A206_same_mode_metrics": baseline["metrics"],
                "candidate_over_A206_ratio": ratios,
            }
        )
    summaries = []
    for candidate in REMAINING_CANDIDATES:
        candidate_rows = [row for row in rows if row["candidate"] == candidate]
        metric_summary = {}
        for metric in metrics:
            candidate_values = [
                row["candidate_metrics"].get(metric)
                for row in candidate_rows
                if row["candidate_metrics"].get(metric) is not None
            ]
            baseline_values = [
                row["A206_same_mode_metrics"].get(metric)
                for row in candidate_rows
                if row["A206_same_mode_metrics"].get(metric) is not None
            ]
            candidate_total = sum(candidate_values) if candidate_values else None
            baseline_total = sum(baseline_values) if baseline_values else None
            ratios = [
                row["candidate_over_A206_ratio"][metric]
                for row in candidate_rows
                if row["candidate_over_A206_ratio"][metric] is not None
            ]
            metric_summary[metric] = {
                "candidate_total": candidate_total,
                "A206_same_mode_total": baseline_total,
                "total_ratio": (
                    candidate_total / baseline_total
                    if candidate_total is not None and baseline_total not in {None, 0}
                    else None
                ),
                "candidate_metric_observation_count": len(candidate_values),
                "candidate_metric_missing_count": len(candidate_rows) - len(candidate_values),
                "cell_ratio_min": min(ratios) if ratios else None,
                "cell_ratio_median": float(np.median(ratios)) if ratios else None,
                "cell_ratio_max": max(ratios) if ratios else None,
            }
        summaries.append(
            {
                "candidate": candidate,
                "solver_mode": candidate_rows[0]["solver_mode"],
                "metrics": metric_summary,
            }
        )
    return {
        "baseline": "A206_bidirectional_min_distance_same_solver_mode_same_prefix_at_10_seconds",
        "ratios_are_descriptive_not_used_for_execution_selection": True,
        "cell_rows": rows,
        "candidate_summaries": summaries,
    }


def _compare(
    *,
    protocol: dict[str, Any],
    observations: list[dict[str, Any]],
    confirmations: list[dict[str, Any]],
    a206: dict[str, Any],
) -> dict[str, Any]:
    status_counts = {
        status: sum(row["status"] == status for row in observations)
        for status in ("sat", "unsat", "unknown", "invalid")
    }
    per_candidate = {
        candidate: {
            status: sum(
                row["candidate"] == candidate and row["status"] == status for row in observations
            )
            for status in ("sat", "unsat", "unknown", "invalid")
        }
        for candidate in REMAINING_CANDIDATES
    }
    complete_candidates = [
        candidate
        for candidate, counts in per_candidate.items()
        if counts == {"sat": 1, "unsat": 31, "unknown": 0, "invalid": 0}
    ]
    a206_observations = a206["execution"]["observations"]
    combined_observations = [*a206_observations, *observations]
    confirmed_prefixes = sorted({row["prefix"] for row in confirmations})
    confirmed_assignments = sorted({row["combined_assignment"] for row in confirmations})
    unsat_prefixes = sorted(
        {row["prefix"] for row in combined_observations if row["status"] == "unsat"}
    )
    contradictory_prefixes = sorted(set(confirmed_prefixes) & set(unsat_prefixes))
    portfolio_complete = (
        len(confirmed_prefixes) == 1
        and len(confirmed_assignments) == 1
        and not contradictory_prefixes
        and all(prefix == confirmed_prefixes[0] or prefix in unsat_prefixes for prefix in PREFIXES)
    )
    return {
        "new_cell_mode_count": len(observations),
        "complete_new_predeclared_execution": len(observations) == 352,
        "A206_cell_mode_count_reused_without_reexecution": len(a206_observations),
        "combined_calibrated_portfolio_cell_mode_count": len(combined_observations),
        "early_stop_used": False,
        "new_status_counts": status_counts,
        "new_per_candidate_status_counts": per_candidate,
        "confirmed_variants": [row["variant"] for row in confirmations],
        "confirmed_prefixes": confirmed_prefixes,
        "confirmed_combined_assignments": confirmed_assignments,
        "recovered_unknown_low20_assignments": sorted(
            {row["recovered_unknown_low20"] for row in confirmations}
        ),
        "confirmed_recovery_retained": len(confirmations) >= 1,
        "single_candidate_complete_domain_resolution": complete_candidates,
        "single_candidate_complete_domain_resolution_retained": len(complete_candidates) >= 1,
        "portfolio_unsat_prefixes": unsat_prefixes,
        "portfolio_contradictory_sat_unsat_prefixes": contradictory_prefixes,
        "portfolio_complete_domain_resolution_retained": portfolio_complete,
        "complete_partition_and_disjoint_by_construction": True,
        "complete_domain_candidate_count": 1 << 20,
        "statuses": {row["variant"]: row["status"] for row in observations},
        "frozen_predictions": protocol["prospective_predictions"],
    }


def _build_causal(path: Path, payload: dict[str, Any]) -> dict[str, Any]:
    builder = CryptoCausalBuilder(
        experiment="chacha20_round10_structural_portfolio",
        parameters={
            "attempt_id": ATTEMPT_ID,
            "rounds": 10,
            "unknown_key_bits": 20,
            "new_candidates": len(REMAINING_CANDIDATES),
            "new_cell_modes": 352,
            "combined_cell_modes": 416,
        },
    )
    ids = [
        "chacha20-a207-calibrated-portfolio-anchor",
        "chacha20-a207-a206-boundary-anchor",
        "chacha20-a207-exact-order-archive",
        "chacha20-a207-complete-source-replay",
        "chacha20-a207-endpoint-verified-transforms",
        "chacha20-a207-complete-remaining-execution",
        "chacha20-a207-independent-confirmation",
        "chacha20-a207-portfolio-result",
    ]
    rows = [
        (
            "A205:12_confirmed_noncontrol_candidate_mappings",
            "retain_each_mapping_with_its_confirmed_mode_without_time_ranking",
            "A207:frozen_13_mode_calibrated_portfolio",
            "retained_calibration_portfolio",
            _A206.A205_CAUSAL_SHA256,
            [],
            {"portfolio": payload["portfolio"]},
        ),
        (
            "A207:frozen_13_mode_calibrated_portfolio",
            "reuse_the_complete_A206_both_mode_boundary_without_reexecution",
            "A207:11_remaining_candidate_modes",
            "retained_A206_boundary",
            A206_CAUSAL_SHA256,
            [ids[0]],
            {"anchor_gates": payload["anchor_gates"]},
        ),
        (
            "A207:11_remaining_candidate_modes",
            "load_and_hash_verify_every_exact_archived_round10_order",
            "A207:exact_candidate_specific_literal_maps",
            "exact_order_archive",
            ORDER_CAUSAL_SHA256,
            [ids[1]],
            {"order_archive": payload["order_archive"]},
        ),
        (
            "A207:exact_candidate_specific_literal_maps",
            "replay_all_32_exact_A204_source_CNF_cells_once",
            "A207:complete_exact_source_cover",
            "complete_source_replay",
            payload["source_exports_sha256"],
            [ids[2]],
            {"source_exports": payload["source_exports"]},
        ),
        (
            "A207:complete_exact_source_cover",
            "transform_all_352_candidate_cells_with_endpoint_inverse_and_common_skeleton_gates",
            "A207:semantics_preserved_remaining_portfolio",
            "candidate_specific_bijective_transforms",
            payload["transform_manifest_sha256"],
            [ids[3]],
            {"transform_manifest": payload["transform_manifest"]},
        ),
        (
            "A207:semantics_preserved_remaining_portfolio",
            "execute_all_352_frozen_candidate_prefix_cells_at_10_seconds",
            "A207:complete_remaining_portfolio_execution",
            "complete_predeclared_solver_execution",
            payload["execution_sha256"],
            [ids[4]],
            {"execution": payload["execution"]},
        ),
        (
            "A207:complete_remaining_portfolio_execution",
            "decode_every_SAT_witness_and_recompute_all_4096_target_bits",
            "A207:independently_confirmed_models_or_exact_boundary",
            "independent_model_confirmation",
            payload["confirmation_sha256"],
            [ids[5]],
            {"confirmations": payload["confirmations"]},
        ),
        (
            "A207:independently_confirmed_models_or_exact_boundary",
            "combine_A206_and_A207_statuses_and_retain_same_mode_progress_ratios",
            "A207:complete_calibrated_structural_portfolio_result",
            "portfolio_comparison",
            payload["portfolio_evaluation_sha256"],
            [ids[6]],
            {"comparisons": payload["comparisons"], "progress_map": payload["progress_map"]},
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
        raise RuntimeError("A207 Causal Reader provenance gate failed")
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
    archive = np.load(results_dir / ORDER_ARCHIVE_FILENAME, mmap_mode="r", allow_pickle=False)
    metadata_rows = {
        row["candidate"]: row for row in analysis["order_metadata"]["candidate_manifest"]
    }
    all_transform_rows = []
    candidate_executions = []
    observations = []
    confirmations = []
    with tempfile.TemporaryDirectory(prefix="a207-structural-portfolio-") as raw_directory:
        directory = Path(raw_directory)
        source_exports, source_paths = _A204._export_round10_cnfs(
            analysis["a206_analysis"]["a204_analysis"], identities, directory
        )
        for candidate in REMAINING_CANDIDATES:
            row_index = protocol["complete_calibrated_portfolio"]["archive_row_indices"][candidate]
            order = np.asarray(archive[row_index], dtype=np.int64)
            transform_rows, transformed_paths, transformed_mapping = _candidate_transform_family(
                candidate=candidate,
                order=order,
                metadata_row=metadata_rows[candidate],
                source_paths=source_paths,
                protocol=protocol,
                directory=directory,
            )
            all_transform_rows.extend(transform_rows)
            mode_name = protocol["complete_calibrated_portfolio"][
                "solver_mode_by_remaining_candidate"
            ][candidate]
            execution, candidate_confirmations = _execute_candidate(
                candidate=candidate,
                mode_name=mode_name,
                transformed_paths=transformed_paths,
                transformed_mapping=transformed_mapping,
                challenge=analysis["public_challenge"],
                cadical_path=identities["cadical"]["path"],
            )
            candidate_executions.append(execution)
            observations.extend(execution["observations"])
            confirmations.extend(candidate_confirmations)
            for path in transformed_paths.values():
                path.unlink()

    expected = [
        f"{candidate}__{variant}__{protocol['complete_calibrated_portfolio']['solver_mode_by_remaining_candidate'][candidate]}"
        for candidate in REMAINING_CANDIDATES
        for variant in VARIANTS
    ]
    if [row["variant"] for row in observations] != expected:
        raise RuntimeError("A207 complete remaining execution order differs from freeze")
    execution = {
        "candidate_order": list(REMAINING_CANDIDATES),
        "variant_order": expected,
        "complete_new_cell_mode_plan_executed": len(observations) == 352,
        "early_stop_used": False,
        "candidate_executions": candidate_executions,
        "observations": observations,
        "returned_model_count": len(confirmations),
        "round10_unknown_assignment_available_to_runner_before_execution": False,
        "A206_candidate_reexecuted": False,
    }
    progress_map = _progress_map(observations, analysis["a206_result"])
    comparisons = _compare(
        protocol=protocol,
        observations=observations,
        confirmations=confirmations,
        a206=analysis["a206_result"],
    )
    if comparisons["portfolio_complete_domain_resolution_retained"]:
        evidence_stage = "ROUND10_STRUCTURAL_PORTFOLIO_COMPLETE_DOMAIN_RESOLUTION_RETAINED"
    elif comparisons["single_candidate_complete_domain_resolution_retained"]:
        evidence_stage = "ROUND10_STRUCTURAL_PORTFOLIO_SINGLE_ORDER_RESOLUTION_RETAINED"
    elif comparisons["confirmed_recovery_retained"]:
        evidence_stage = "ROUND10_STRUCTURAL_PORTFOLIO_CONFIRMED_RECOVERY_RETAINED"
    else:
        evidence_stage = "ROUND10_STRUCTURAL_PORTFOLIO_COMPLETE_BOUNDARY_RETAINED"
    clean_source_exports = [
        {key: value for key, value in row.items() if key != "path"} for row in source_exports
    ]
    order_archive = {
        "archive_sha256": ORDER_ARCHIVE_SHA256,
        "metadata_sha256": ORDER_METADATA_SHA256,
        "candidate_manifest_sha256": analysis["order_metadata"]["candidate_manifest_sha256"],
        "row_candidate_order": analysis["order_metadata"]["archive"]["row_candidate_order"],
        "shape": analysis["order_metadata"]["archive"]["shape"],
        "all_12_rows_hash_verified_before_execution": True,
    }
    payload: dict[str, Any] = {
        "schema": SCHEMA,
        "attempt_id": ATTEMPT_ID,
        "evidence_stage": evidence_stage,
        "result": (
            "The eleven remaining A205-calibrated structural candidate modes are executed "
            "prospectively across every cell of the complete reduced ChaCha10 cover."
        ),
        "scope": "Reduced ChaCha10 20-bit partial-key recovery over eight shared-key blocks.",
        "protocol_gate": {
            "artifact_sha256": PROTOCOL_SHA256,
            "protocol_state": protocol["protocol_state"],
            "information_boundary": protocol["information_boundary"],
            "prospective_predictions": protocol["prospective_predictions"],
        },
        "anchor_gates": analysis["anchor_gates"],
        "portfolio": protocol["complete_calibrated_portfolio"],
        "portfolio_sha256": _canonical_sha256(protocol["complete_calibrated_portfolio"]),
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
        "transform_manifest": all_transform_rows,
        "transform_manifest_sha256": _canonical_sha256(all_transform_rows),
        "execution_plan": protocol["execution_plan"],
        "execution_plan_sha256": _canonical_sha256(protocol["execution_plan"]),
        "execution": execution,
        "execution_sha256": _canonical_sha256(execution),
        "confirmations": confirmations,
        "confirmation_sha256": _canonical_sha256(confirmations),
        "progress_map": progress_map,
        "progress_map_sha256": _canonical_sha256(progress_map),
        "comparisons": comparisons,
        "comparison_sha256": _canonical_sha256(comparisons),
    }
    payload["portfolio_evaluation_sha256"] = _canonical_sha256(
        {
            "progress_map_sha256": payload["progress_map_sha256"],
            "comparison_sha256": payload["comparison_sha256"],
        }
    )
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
        raise RuntimeError("A207 final artifact reopen gate failed")
    return {
        "json_sha256": _sha256(raw),
        "causal_sha256": reader.file_sha256,
        "causal_graph_sha256": reader.graph_sha256,
        "evidence_stage": evidence_stage,
        "new_status_counts": comparisons["new_status_counts"],
        "confirmed_variants": comparisons["confirmed_variants"],
        "recovered_unknown_low20_assignments": comparisons["recovered_unknown_low20_assignments"],
        "single_candidate_complete_domain_resolution_retained": comparisons[
            "single_candidate_complete_domain_resolution_retained"
        ],
        "portfolio_complete_domain_resolution_retained": comparisons[
            "portfolio_complete_domain_resolution_retained"
        ],
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
            "remaining_candidate_order": analysis["protocol"]["complete_calibrated_portfolio"][
                "remaining_candidate_order"
            ],
            "new_cell_modes": analysis["protocol"]["execution_plan"]["new_cell_mode_count"],
            "combined_cell_modes": analysis["protocol"]["execution_plan"][
                "combined_with_A206_cell_mode_count"
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

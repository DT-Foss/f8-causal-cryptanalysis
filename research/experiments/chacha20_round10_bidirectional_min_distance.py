#!/usr/bin/env python3
"""Prospective robust structural-order transfer over the complete ChaCha10 cover."""

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


_A204 = _import_sibling(
    "chacha20_round10_external_cnf_reverse.py",
    "chacha20_a206_a204_anchor",
)
_A205 = _import_sibling(
    "chacha20_a188_cnf_structural_ordering.py",
    "chacha20_a206_a205_anchor",
)
_A198 = _A204._A198

ATTEMPT_ID = "A206"
SCHEMA = "chacha20-round10-bidirectional-min-distance-transfer-v1"
PROTOCOL_SCHEMA = "chacha20-round10-bidirectional-min-distance-transfer-protocol-v1"
PROTOCOL_FILENAME = "chacha20_round10_bidirectional_min_distance_v1.json"
PROTOCOL_SHA256 = "10ff5f93a346824cdb7e0d3a15b48f72fa7f27ad9ef31e42c5d05cd61856c858"
RESULT_FILENAME = "chacha20_round10_bidirectional_min_distance_v1.json"
CAUSAL_FILENAME = "chacha20_round10_bidirectional_min_distance_v1.causal"

A204_FILENAME = _A204.RESULT_FILENAME
A204_SHA256 = "603eaf8a2a6bb85c3c4bb2fdf4b7466205ffd1d8005593d987c8a6461b7c8c22"
A204_CAUSAL_FILENAME = _A204.CAUSAL_FILENAME
A204_CAUSAL_SHA256 = "f1ca39f964640d8aa2a5c6f6dab9bcfb48dfaddf6dda2e399275f77235ca71c3"
A204_CAUSAL_GRAPH_SHA256 = "0cbdde4c25a7c804706a9e8b9823c71ec9bc74046191526cae4a7a55b5dbdc73"
A205_FILENAME = _A205.RESULT_FILENAME
A205_SHA256 = "b3c76fca5a9ffabf3bd2c2bf812c8ef66b9be56bc7f9936a9525fd5e8d3c7f7f"
A205_CAUSAL_FILENAME = _A205.CAUSAL_FILENAME
A205_CAUSAL_SHA256 = "d17ed98433e70ecfafd75ce895372aa7f150cb2b178c853697ee8406f0582f80"
A205_CAUSAL_GRAPH_SHA256 = "8dddd0764910b940627c65e2b21b2e4e0e367db388d481954e70c3213c56fec0"

ROUNDS = 10
BLOCK_COUNT = 8
UNKNOWN_KEY_BITS = 20
FREE_BITS = 15
PREFIXES = _A204.PREFIXES
VARIANTS = _A204.VARIANTS
SELECTED_CANDIDATE = "bidirectional_min_distance"
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
        raise RuntimeError("A206 frozen protocol hash differs")
    protocol = json.loads(path.read_bytes())
    selection = protocol.get("selection", {})
    source = protocol.get("round10_source", {})
    structural = protocol.get("structural_order", {})
    plan = protocol.get("execution_plan", {})
    boundary = protocol.get("information_boundary", {})
    modes = protocol.get("solver_modes", [])
    if (
        protocol.get("schema") != PROTOCOL_SCHEMA
        or protocol.get("attempt_id") != ATTEMPT_ID
        or protocol.get("protocol_state")
        != "frozen_after_A205_r2_robust_structural_calibration_and_A206_source_preflight_before_any_A206_round10_solver_execution"
        or selection.get("selected_candidate") != SELECTED_CANDIDATE
        or selection.get("robust_both_mode_candidates") != [SELECTED_CANDIDATE]
        or selection.get("selection_time_data_used") is not False
        or selection.get("complete_A205_transfer_portfolio_deferred_not_cancelled") is not True
        or source.get("prefix_order") != list(PREFIXES)
        or source.get("cell_count") != len(PREFIXES)
        or source.get("partition_free_bits") != FREE_BITS
        or source.get("common_normalized_sha256")
        != "a9cd80dc9e7934f3c29681a78e4d734d598205e81b9796e9413b78be85e4fa2b"
        or structural.get("order_sha256")
        != "c019beaea6888a5db16c3805922752c273aacd5a70498df1119edb21535db8d3"
        or structural.get("old_to_new_sha256")
        != "8568c89883908e5eadead20533c700c4a6a37d7ac9968de5ea939f66f2012702"
        or modes
        != [
            {"name": "default", "arguments": []},
            {"name": "reverse", "arguments": ["--reverse=true"]},
        ]
        or plan.get("solver_time_limit_seconds_per_cell_mode") != SOLVER_LIMIT_SECONDS
        or plan.get("external_timeout_seconds_per_cell_mode") != EXTERNAL_TIMEOUT_SECONDS
        or plan.get("max_parallel_workers") != MAX_PARALLEL_WORKERS
        or plan.get("cell_mode_count") != len(PREFIXES) * len(modes)
        or plan.get("early_stop_permitted") is not False
        or boundary.get("any_A206_round10_solver_outcome_known_before_freeze") is not False
        or boundary.get("round10_unknown_assignment_in_protocol_or_source") is not False
        or boundary.get("round10_unknown_assignment_available_to_runner_before_execution")
        is not False
        or boundary.get("unrelated_A188_known_positive_model_used_in_A206_order_or_solver_input")
        is not False
        or boundary.get(
            "source_manifest_candidate_order_solver_modes_or_budget_changed_after_any_A206_outcome"
        )
        is not False
        or boundary.get("early_stop_permitted") is not False
    ):
        raise RuntimeError("A206 frozen protocol identity gate failed")
    return protocol


def _load_anchor(
    results_dir: Path,
    *,
    label: str,
    result_name: str,
    result_sha256: str,
    causal_name: str,
    causal_sha256: str,
    causal_graph_sha256: str,
) -> tuple[dict[str, Any], dict[str, Any]]:
    result_path = results_dir / result_name
    causal_path = results_dir / causal_name
    if _file_sha256(result_path) != result_sha256 or _file_sha256(causal_path) != causal_sha256:
        raise RuntimeError(f"A206 {label} anchor hash gate failed")
    payload = json.loads(result_path.read_bytes())
    reader = CryptoCausalReader(causal_path)
    if (
        reader.file_sha256 != causal_sha256
        or reader.graph_sha256 != causal_graph_sha256
        or payload.get("causal", {}).get("graph_sha256") != causal_graph_sha256
        or not reader.verify_provenance()
    ):
        raise RuntimeError(f"A206 {label} Causal anchor gate failed")
    return payload, {
        f"{label}_result_sha256": result_sha256,
        f"{label}_causal_sha256": causal_sha256,
        f"{label}_causal_graph_sha256": causal_graph_sha256,
        f"{label}_causal_provenance_verified": True,
    }


def _load_anchor_gates(results_dir: Path, protocol: dict[str, Any]) -> dict[str, Any]:
    a205_protocol_path = Path(__file__).parents[1] / "configs" / _A205.PROTOCOL_FILENAME
    if (
        _file_sha256(a205_protocol_path) != protocol["anchors"]["A205_r2"]["protocol_sha256"]
        or _file_sha256(a205_protocol_path) != _A205.PROTOCOL_SHA256
    ):
        raise RuntimeError("A206 A205-r2 protocol anchor hash gate failed")
    a204, gates204 = _load_anchor(
        results_dir,
        label="A204",
        result_name=A204_FILENAME,
        result_sha256=A204_SHA256,
        causal_name=A204_CAUSAL_FILENAME,
        causal_sha256=A204_CAUSAL_SHA256,
        causal_graph_sha256=A204_CAUSAL_GRAPH_SHA256,
    )
    a205, gates205 = _load_anchor(
        results_dir,
        label="A205_r2",
        result_name=A205_FILENAME,
        result_sha256=A205_SHA256,
        causal_name=A205_CAUSAL_FILENAME,
        causal_sha256=A205_CAUSAL_SHA256,
        causal_graph_sha256=A205_CAUSAL_GRAPH_SHA256,
    )
    comparisons205 = a205.get("comparisons", {})
    correction = a205.get("metadata_correction", {})
    if (
        a204.get("evidence_stage") != "ROUND10_EXTERNAL_CNF_COMPLETE_PARTITION_BOUNDARY_RETAINED"
        or a204.get("comparisons", {}).get("status_counts")
        != {"sat": 0, "unsat": 0, "unknown": 32, "invalid": 0}
        or a205.get("evidence_stage") != "A188_CNF_ROBUST_STRUCTURAL_ORDERING_OUTLIER_RETAINED"
        or comparisons205.get("robust_both_mode_structural_candidates") != [SELECTED_CANDIDATE]
        or comparisons205.get("A206_transfer_selection")
        != protocol["selection"][
            "calibration_candidates_with_at_least_one_confirmed_noncontrol_SAT_mode"
        ]
        or correction.get("solver_observations_changed") is not False
        or correction.get("known_positive_model_not_used_in_order_construction_or_solver_input")
        is not True
        or a205.get("causal", {}).get("explicit_triplets") != 8
    ):
        raise RuntimeError("A206 retained A204/A205 semantic anchor gate failed")
    return {
        **gates204,
        **gates205,
        "A204_complete_round10_cover_all_unknown_retained": True,
        "A205_r2_unique_robust_both_mode_candidate_retained": True,
        "A205_r2_boundary_metadata_correction_retained": True,
    }


def analyze(results_dir: Path) -> dict[str, Any]:
    protocol = _load_protocol_gate()
    anchors = _load_anchor_gates(results_dir, protocol)
    a204 = _A204.analyze(results_dir)
    if (
        tuple(a204["formulas"]) != VARIANTS
        or a204["public_challenge"]["unknown_assignment_included"] is not False
        or a204["public_challenge"]["unknown_key_word0_low_value_included"] is not False
        or protocol["round10_source"]["free_k0_bit_one_literal_mapping"]
        != a204["protocol"]["A202_round10_cnf_freeze"]["free_k0_bit_one_literal_mapping"]
    ):
        raise RuntimeError("A206 public challenge and exact mapping boundary gate failed")
    return {
        "protocol": protocol,
        "anchor_gates": anchors,
        "public_challenge": a204["public_challenge"],
        "formulas": a204["formulas"],
        "formula_plan": a204["formula_plan"],
        "a204_analysis": a204,
        "solver_execution_started": False,
    }


def _derive_structural_order(
    parsed: dict[str, Any], protocol: dict[str, Any]
) -> tuple[np.ndarray, np.ndarray, np.ndarray, dict[str, Any], dict[str, Any]]:
    variable_count = parsed["variable_count"]
    ids = np.arange(1, variable_count + 1, dtype=np.int64)
    key_sources = np.asarray(
        sorted(set(protocol["round10_source"]["free_k0_bit_one_literal_mapping"])),
        dtype=np.int64,
    )
    unit_distance = _A205._multi_source_bfs(parsed["graph"], parsed["units"])
    key_distance = _A205._multi_source_bfs(parsed["graph"], key_sources)
    signed_distance = key_distance - unit_distance
    order = ids[np.lexsort((ids, signed_distance, np.minimum(unit_distance, key_distance)))]
    expected_ids = np.arange(1, variable_count + 1, dtype=np.int64)
    if len(order) != variable_count or not np.array_equal(np.sort(order), expected_ids):
        raise RuntimeError("A206 structural order is not a bijection")
    mapping = _A205._old_to_new(order)
    inverse = np.zeros_like(mapping)
    inverse[mapping[1:]] = expected_ids
    graph = parsed["graph"]
    graph_payload = {
        "variable_count": variable_count,
        "clause_count": parsed["clause_count"],
        "unit_clause_variable_count": len(parsed["units"]),
        "undirected_edges": int(graph.nnz // 2),
        "connected_components": parsed["component_count"],
        "largest_component": int(parsed["component_sizes"].max()),
        "isolated_vertices": int(np.sum(parsed["component_sizes"] == 1)),
        "minimum_degree": int(parsed["degrees"].min()),
        "maximum_degree": int(parsed["degrees"].max()),
        "key_distance_min": int(key_distance.min()),
        "key_distance_max": int(key_distance.max()),
        "unit_distance_min": int(unit_distance.min()),
        "unit_distance_max": int(unit_distance.max()),
        "csr_indptr_sha256": _sha256(graph.indptr.astype("<i8", copy=False).tobytes()),
        "csr_indices_sha256": _sha256(graph.indices.astype("<i4", copy=False).tobytes()),
    }
    order_sha256 = _sha256(order.astype("<u4", copy=False).tobytes())
    mapping_sha256 = _sha256(mapping.astype("<u4", copy=False).tobytes())
    transformed_free_mapping = [
        int(mapping[abs(literal)]) if literal > 0 else -int(mapping[abs(literal)])
        for literal in protocol["round10_source"]["free_k0_bit_one_literal_mapping"]
    ]
    diagnostics = {
        "candidate": SELECTED_CANDIDATE,
        "key_source_count": len(key_sources),
        "unit_source_count": len(parsed["units"]),
        "order_sha256": order_sha256,
        "old_to_new_sha256": mapping_sha256,
        "transformed_free_k0_bit_one_literal_mapping": transformed_free_mapping,
        "transformed_free_mapping_sha256": _canonical_sha256(transformed_free_mapping),
    }
    expected_graph = protocol["representative_graph_preflight"]
    expected_structural = protocol["structural_order"]
    if (
        graph_payload != expected_graph
        or order_sha256 != expected_structural["order_sha256"]
        or mapping_sha256 != expected_structural["old_to_new_sha256"]
        or transformed_free_mapping
        != expected_structural["transformed_free_k0_bit_one_literal_mapping"]
        or diagnostics["transformed_free_mapping_sha256"]
        != expected_structural["transformed_free_mapping_sha256"]
    ):
        raise RuntimeError("A206 representative structural preflight differs from freeze")
    return order, mapping, inverse, graph_payload, diagnostics


def _transform_cnfs(
    *,
    cnf_paths: dict[str, Path],
    mapping: np.ndarray,
    inverse: np.ndarray,
    protocol: dict[str, Any],
    directory: Path,
) -> tuple[list[dict[str, Any]], dict[str, Path]]:
    manifest = []
    transformed_paths = {}
    expected_normalized = protocol["structural_order"]["representative_transformed_cnf_sha256"]
    for variant in VARIANTS:
        source_path = cnf_paths[variant]
        raw = source_path.read_bytes()
        transformed = _A205._reindex_cnf(raw, mapping)
        restored = _A205._reindex_cnf(transformed, inverse)
        if restored != raw or _sha256(restored) != _sha256(raw):
            raise RuntimeError(f"A206 {variant} inverse byte gate failed")
        header, tail_units, normalized_sha256 = _A204._normalized_cnf(transformed)
        if normalized_sha256 != expected_normalized:
            raise RuntimeError(f"A206 {variant} transformed normalized skeleton differs")
        output = directory / f"{variant}__{SELECTED_CANDIDATE}.cnf"
        output.write_bytes(transformed)
        row = {
            "variant": variant,
            "prefix": variant[-5:],
            "source_cnf_sha256": _sha256(raw),
            "transformed_cnf_sha256": _sha256(transformed),
            "transformed_cnf_bytes": len(transformed),
            "transformed_header": header,
            "transformed_tail_units": tail_units,
            "transformed_normalized_sha256": normalized_sha256,
            "inverse_restored_sha256": _sha256(restored),
            "inverse_byte_identical": True,
        }
        manifest.append(row)
        transformed_paths[variant] = output
    representative = next(row for row in manifest if row["prefix"] == "11111")
    structural = protocol["structural_order"]
    if (
        representative["transformed_cnf_sha256"]
        != structural["representative_transformed_cnf_sha256"]
        or representative["transformed_cnf_bytes"]
        != structural["representative_transformed_cnf_bytes"]
        or representative["inverse_restored_sha256"]
        != structural["representative_inverse_restored_sha256"]
        or not all(row["inverse_byte_identical"] for row in manifest)
    ):
        raise RuntimeError("A206 representative transformed CNF gate failed")
    return manifest, transformed_paths


def _run_cell_mode(
    *,
    variant: str,
    mode: dict[str, Any],
    cnf_path: Path,
    transformed_mapping: Sequence[int],
    challenge: dict[str, Any],
    cadical_path: str,
) -> tuple[dict[str, Any], dict[str, Any] | None]:
    prefix = variant[-5:]
    label = f"{variant}__{SELECTED_CANDIDATE}__{mode['name']}"
    command = [
        cadical_path,
        *mode["arguments"],
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
            "source_variant": variant,
            "prefix": prefix,
            "candidate": SELECTED_CANDIDATE,
            "solver_mode": mode["name"],
            **_A198._confirm_model(challenge, model),
        }
        if (
            confirmation["known_key_constraints_match"] is not True
            or confirmation["all_blocks_match"] is not True
            or confirmation["control_first_block_match"] is not False
            or confirmation["output_bits_checked"] != 4096
        ):
            raise RuntimeError(f"A206 {label} decoded model failed independent confirmation")
    observation = {
        "variant": label,
        "source_variant": variant,
        "prefix": prefix,
        "candidate": SELECTED_CANDIDATE,
        "solver_mode": mode["name"],
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
            raise RuntimeError(f"A206 {label} invalid UNKNOWN boundary")
    return observation, confirmation


def _execute_complete_plan(
    *,
    protocol: dict[str, Any],
    transformed_paths: dict[str, Path],
    transformed_mapping: Sequence[int],
    challenge: dict[str, Any],
    cadical_path: str,
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    jobs = [(variant, mode) for variant in VARIANTS for mode in protocol["solver_modes"]]
    expected_labels = [f"{variant}__{SELECTED_CANDIDATE}__{mode['name']}" for variant, mode in jobs]
    observations = []
    confirmations = []
    waves = []
    for wave_index, start in enumerate(range(0, len(jobs), MAX_PARALLEL_WORKERS)):
        wave = jobs[start : start + MAX_PARALLEL_WORKERS]

        def execute(
            job: tuple[str, dict[str, Any]],
        ) -> tuple[dict[str, Any], dict[str, Any] | None]:
            variant, mode = job
            return _run_cell_mode(
                variant=variant,
                mode=mode,
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
    if [row["variant"] for row in observations] != expected_labels:
        raise RuntimeError("A206 complete execution order differs from freeze")
    execution = {
        "variant_order": expected_labels,
        "complete_cell_mode_plan_executed": len(observations) == len(expected_labels),
        "early_stop_used": False,
        "observations": observations,
        "wave_observations": waves,
        "returned_model_count": len(confirmations),
        "round10_unknown_assignment_available_to_runner_before_execution": False,
        "unrelated_A188_known_positive_model_used_in_order_or_solver_input": False,
    }
    return execution, confirmations


def _compare(
    protocol: dict[str, Any], execution: dict[str, Any], confirmations: list[dict[str, Any]]
) -> dict[str, Any]:
    observations = execution["observations"]
    status_counts = {
        status: sum(row["status"] == status for row in observations)
        for status in ("sat", "unsat", "unknown", "invalid")
    }
    per_mode = {
        mode["name"]: {
            status: sum(
                row["solver_mode"] == mode["name"] and row["status"] == status
                for row in observations
            )
            for status in ("sat", "unsat", "unknown", "invalid")
        }
        for mode in protocol["solver_modes"]
    }
    assignments = sorted({row["combined_assignment"] for row in confirmations})
    recovered_low20 = sorted({row["recovered_unknown_low20"] for row in confirmations})
    confirmed_prefixes = sorted({row["prefix"] for row in confirmations})
    both_mode_confirmations = []
    for prefix in PREFIXES:
        rows = [row for row in confirmations if row["prefix"] == prefix]
        by_assignment: dict[int, set[str]] = {}
        for row in rows:
            by_assignment.setdefault(row["combined_assignment"], set()).add(row["solver_mode"])
        for assignment, modes in sorted(by_assignment.items()):
            if modes == {"default", "reverse"}:
                both_mode_confirmations.append(
                    {
                        "prefix": prefix,
                        "combined_assignment": assignment,
                        "solver_modes": sorted(modes),
                    }
                )
    complete_modes = [
        mode
        for mode, counts in per_mode.items()
        if counts == {"sat": 1, "unsat": 31, "unknown": 0, "invalid": 0}
    ]
    return {
        "complete_cell_mode_count": len(observations),
        "complete_predeclared_execution": len(observations) == 64,
        "early_stop_used": False,
        "status_counts": status_counts,
        "per_mode_status_counts": per_mode,
        "confirmed_variants": [row["variant"] for row in confirmations],
        "confirmed_prefixes": confirmed_prefixes,
        "confirmed_combined_assignments": assignments,
        "recovered_unknown_low20_assignments": recovered_low20,
        "confirmed_partial_recovery_retained": len(confirmations) >= 1,
        "both_mode_confirmations": both_mode_confirmations,
        "both_mode_transfer_retained": len(both_mode_confirmations) >= 1,
        "complete_domain_resolution_modes": complete_modes,
        "complete_domain_resolution_retained": len(complete_modes) >= 1,
        "complete_partition_and_disjoint_by_construction": True,
        "complete_domain_candidate_count": 1 << UNKNOWN_KEY_BITS,
        "statuses": {row["variant"]: row["status"] for row in observations},
    }


def _build_causal(path: Path, payload: dict[str, Any]) -> dict[str, Any]:
    builder = CryptoCausalBuilder(
        experiment="chacha20_round10_bidirectional_min_distance",
        parameters={
            "attempt_id": ATTEMPT_ID,
            "rounds": ROUNDS,
            "unknown_key_bits": UNKNOWN_KEY_BITS,
            "shared_key_blocks": BLOCK_COUNT,
            "prefix_cells": len(PREFIXES),
            "cell_modes": 64,
        },
    )
    ids = [
        "chacha20-a206-round10-cover-anchor",
        "chacha20-a206-robust-order-selection",
        "chacha20-a206-primal-graph-order",
        "chacha20-a206-bijective-transform",
        "chacha20-a206-complete-cell-mode-execution",
        "chacha20-a206-independent-confirmation",
        "chacha20-a206-transfer-result",
    ]
    rows = [
        (
            "A204:complete_32_cell_round10_CNF_cover",
            "retain_the_exact_public_challenge_literal_map_and_all_unknown_external_baseline",
            "A206:frozen_round10_source_cover",
            "retained_round10_anchor",
            A204_CAUSAL_SHA256,
            [],
            {"anchor_gates": payload["anchor_gates"]},
        ),
        (
            "A206:frozen_round10_source_cover",
            "select_the_unique_A205_noncontrol_order_confirmed_in_both_solver_modes",
            "A206:frozen_bidirectional_min_distance_candidate",
            "prospective_calibration_transfer",
            A205_CAUSAL_SHA256,
            [ids[0]],
            {"selection": payload["selection"]},
        ),
        (
            "A206:frozen_bidirectional_min_distance_candidate",
            "construct_the_clause_primal_graph_and_two_source_BFS_sum_difference_order",
            "A206:exact_round10_structural_order",
            "formula_derived_structural_order",
            payload["structural_diagnostics_sha256"],
            [ids[1]],
            {
                "graph": payload["graph"],
                "structural_diagnostics": payload["structural_diagnostics"],
            },
        ),
        (
            "A206:exact_round10_structural_order",
            "reindex_all_32_CNF_cells_and_inverse_restore_each_source_byte_exactly",
            "A206:semantics_preserved_transformed_cover",
            "complete_bijective_CNF_transform",
            payload["transform_manifest_sha256"],
            [ids[2]],
            {"transform_manifest": payload["transform_manifest"]},
        ),
        (
            "A206:semantics_preserved_transformed_cover",
            "execute_all_64_prefix_mode_cells_at_the_frozen_10_second_budget",
            "A206:complete_bidirectional_transfer_execution",
            "complete_predeclared_solver_execution",
            payload["execution_sha256"],
            [ids[3]],
            {"execution": payload["execution"]},
        ),
        (
            "A206:complete_bidirectional_transfer_execution",
            "decode_each_returned_witness_and_recompute_all_4096_target_bits",
            "A206:independently_confirmed_models_or_exact_boundary",
            "independent_model_confirmation",
            payload["confirmation_sha256"],
            [ids[4]],
            {"confirmations": payload["confirmations"]},
        ),
        (
            "A206:independently_confirmed_models_or_exact_boundary",
            "evaluate_confirmed_recovery_both_mode_and_complete_resolution_predictions",
            "A206:prospective_round10_structural_transfer_result",
            "prospective_transfer_comparison",
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
        raise RuntimeError("A206 Causal Reader provenance gate failed")
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
    with tempfile.TemporaryDirectory(prefix="a206-round10-structural-") as raw_directory:
        directory = Path(raw_directory)
        source_exports, source_paths = _A204._export_round10_cnfs(
            analysis["a204_analysis"], identities, directory
        )
        representative_raw = source_paths["cse_prefix_11111"].read_bytes()
        parsed = _A205._parse_cnf(representative_raw)
        order, mapping, inverse, graph, structural_diagnostics = _derive_structural_order(
            parsed, protocol
        )
        transform_manifest, transformed_paths = _transform_cnfs(
            cnf_paths=source_paths,
            mapping=mapping,
            inverse=inverse,
            protocol=protocol,
            directory=directory,
        )
        execution, confirmations = _execute_complete_plan(
            protocol=protocol,
            transformed_paths=transformed_paths,
            transformed_mapping=structural_diagnostics[
                "transformed_free_k0_bit_one_literal_mapping"
            ],
            challenge=analysis["public_challenge"],
            cadical_path=identities["cadical"]["path"],
        )

    comparisons = _compare(protocol, execution, confirmations)
    if comparisons["complete_domain_resolution_retained"]:
        evidence_stage = "ROUND10_STRUCTURAL_ORDER_COMPLETE_DOMAIN_RESOLUTION_RETAINED"
    elif comparisons["both_mode_transfer_retained"]:
        evidence_stage = "ROUND10_STRUCTURAL_ORDER_BOTH_MODE_RECOVERY_RETAINED"
    elif comparisons["confirmed_partial_recovery_retained"]:
        evidence_stage = "ROUND10_STRUCTURAL_ORDER_CONFIRMED_RECOVERY_RETAINED"
    else:
        evidence_stage = "ROUND10_STRUCTURAL_ORDER_COMPLETE_TRANSFER_BOUNDARY_RETAINED"
    clean_source_exports = [
        {key: value for key, value in row.items() if key != "path"} for row in source_exports
    ]
    payload: dict[str, Any] = {
        "schema": SCHEMA,
        "attempt_id": ATTEMPT_ID,
        "evidence_stage": evidence_stage,
        "result": (
            "The unique robust both-mode A205 structural order is transferred prospectively "
            "to every cell of the complete reduced ChaCha10 partial-key cover."
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
        "source_exports": clean_source_exports,
        "source_exports_sha256": _canonical_sha256(clean_source_exports),
        "graph": graph,
        "graph_sha256": _canonical_sha256(graph),
        "structural_order": order.tolist(),
        "structural_order_sha256": _sha256(order.astype("<u4", copy=False).tobytes()),
        "structural_diagnostics": structural_diagnostics,
        "structural_diagnostics_sha256": _canonical_sha256(structural_diagnostics),
        "transform_manifest": transform_manifest,
        "transform_manifest_sha256": _canonical_sha256(transform_manifest),
        "execution_plan": protocol["execution_plan"],
        "execution_plan_sha256": _canonical_sha256(protocol["execution_plan"]),
        "execution": execution,
        "execution_sha256": _canonical_sha256(execution),
        "confirmations": confirmations,
        "confirmation_sha256": _canonical_sha256(confirmations),
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
        raise RuntimeError("A206 final artifact reopen gate failed")
    return {
        "json_sha256": _sha256(raw),
        "causal_sha256": reader.file_sha256,
        "causal_graph_sha256": reader.graph_sha256,
        "evidence_stage": evidence_stage,
        "status_counts": comparisons["status_counts"],
        "per_mode_status_counts": comparisons["per_mode_status_counts"],
        "confirmed_variants": comparisons["confirmed_variants"],
        "recovered_unknown_low20_assignments": comparisons["recovered_unknown_low20_assignments"],
        "both_mode_transfer_retained": comparisons["both_mode_transfer_retained"],
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
            "candidate": analysis["protocol"]["selection"]["selected_candidate"],
            "prefix_cells": len(analysis["protocol"]["round10_source"]["prefix_order"]),
            "cell_modes": analysis["protocol"]["execution_plan"]["cell_mode_count"],
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

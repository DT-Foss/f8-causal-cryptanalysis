#!/usr/bin/env python3
"""Test incremental sibling-clause learning over two complete ChaCha10 covers."""

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


_A209 = _import_sibling(
    "chacha20_round10_bfs_far_width12_refinement.py",
    "chacha20_a210_a209_anchor",
)
_A208 = _A209._A208
_A205 = _A209._A205
_A204 = _A209._A204
_A198 = _A209._A198

ATTEMPT_ID = "A210"
SCHEMA = "chacha20-round10-incremental-sibling-learning-v1"
PROTOCOL_SCHEMA = "chacha20-round10-incremental-sibling-learning-protocol-v1"
PROTOCOL_FILENAME = "chacha20_round10_incremental_sibling_learning_v1.json"
PROTOCOL_SHA256 = "9eb5183162d6aff09a956b482baa943a60a7c3770bde5e6d10cf67e125388258"
RESULT_FILENAME = "chacha20_round10_incremental_sibling_learning_v1.json"
CAUSAL_FILENAME = "chacha20_round10_incremental_sibling_learning_v1.causal"

A209_RESULT_FILENAME = _A209.RESULT_FILENAME
A209_RESULT_SHA256 = "242a87fd56da3fcf60e6ae4c1a5dd75effc9a2293a41496ea71f4c4342cc5c1e"
A209_CAUSAL_FILENAME = _A209.CAUSAL_FILENAME
A209_CAUSAL_SHA256 = "577f8fdbf41d95d6a61316103c48cc6f366311821b830ac2e4d11b7f4f79eb7f"
A209_CAUSAL_GRAPH_SHA256 = "21090e1289ff3cd46ec5403c1a0ab81a5272f056eb5a72ce6da08491aa48eeb1"

PARENTS = _A208.PREFIXES
METRIC_NAMES = ("conflicts", "decisions", "search_propagations")
A209_COMPARABLE_METRICS = ("conflicts", "decisions")
SOLVER_LIMIT_SECONDS = 10
PARENT_EXTERNAL_TIMEOUT_SECONDS = 95
MAX_PARALLEL_PARENT_RUNS = 4


def _sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _canonical_sha256(value: Any) -> str:
    return _A204._canonical_sha256(value)


def _file_sha256(path: Path) -> str:
    return _A204._file_sha256(path)


def _mode_plan(protocol: dict[str, Any]) -> list[dict[str, Any]]:
    return [
        {"mode": mode["name"], "parent_prefix5": parent}
        for mode in protocol["incremental_modes"]
        for parent in PARENTS
    ]


def _cell_plan(protocol: dict[str, Any]) -> list[dict[str, Any]]:
    return [
        {"mode": mode["name"], "prefix8": parent + child}
        for mode in protocol["incremental_modes"]
        for parent in PARENTS
        for child in mode["child_order"]
    ]


def _load_protocol_gate() -> dict[str, Any]:
    path = Path(__file__).parents[1] / "configs" / PROTOCOL_FILENAME
    if _file_sha256(path) != PROTOCOL_SHA256:
        raise RuntimeError("A210 frozen protocol hash differs")
    protocol = json.loads(path.read_bytes())
    selection = protocol.get("selection_basis", {})
    helper = protocol.get("native_helper", {})
    parent = protocol.get("parent_CNF_preflight", {})
    mapping = protocol.get("assumption_and_model_mapping", {})
    modes = protocol.get("incremental_modes", [])
    execution = protocol.get("execution_plan", {})
    boundary = protocol.get("information_boundary", {})
    expected_modes = [
        {
            "name": "numeric_incremental",
            "child_order": ["000", "001", "010", "011", "100", "101", "110", "111"],
        },
        {
            "name": "gray_incremental",
            "child_order": ["000", "001", "011", "010", "110", "111", "101", "100"],
        },
    ]
    if (
        protocol.get("schema") != PROTOCOL_SCHEMA
        or protocol.get("attempt_id") != ATTEMPT_ID
        or protocol.get("protocol_state")
        != "frozen_after_complete_A209_phase_reset_boundary_and_native_incremental_toy_validation_before_any_A210_round10_helper_execution"
        or selection.get("public_challenge_sha256") != _A198.PUBLIC_CHALLENGE_SHA256
        or selection.get("A209_status_counts")
        != {"sat": 0, "unsat": 0, "unknown": 256, "invalid": 0}
        or selection.get("A209_all_256_child_directions")
        != {
            "decisions_above_parent": True,
            "propagations_above_parent": True,
            "restarts_above_parent": True,
        }
        or selection.get("any_A210_round10_incremental_outcome_known_at_selection") is not False
        or helper.get("source_sha256")
        != "d5742b03db88677dee7fc52d3fa93e994153d909de0edc574e1ea611a6ef69c6"
        or helper.get("compiled_binary_sha256")
        != "b214c67932ff7092f802976fa132977a9b5447d0d05f76c64da0dd83d307301e"
        or helper.get("API_metric_names") != list(METRIC_NAMES)
        or helper.get("A209_metric_comparison_scope") != list(A209_COMPARABLE_METRICS)
        or helper.get("toy_validation_completed_before_freeze") is not True
        or helper.get("toy_contains_round10_data") is not False
        or helper.get("round10_helper_execution_completed_before_freeze") is not False
        or parent.get("parent_count") != 32
        or parent.get("order_sha256")
        != "814798f19a33a3a397a6af9f6fa126207e1e10e092d8ee80dcaba4ef3bae95c8"
        or parent.get("old_to_new_sha256")
        != "50d03bfd6520685c3b17ec822ad08f4b5cce80f91c771a2b1b6377fffab2f30b"
        or parent.get("transformed_parent_manifest_sha256")
        != "3fc86268d53150d75c90a5d69138801788a49f0001b39fbc5cb902bcb2e8baa0"
        or mapping.get("child_bits_descending") != [14, 13, 12]
        or mapping.get("transformed_child_one_literals_descending") != [225285, 225284, 225283]
        or mapping.get("transformed_child_mapping_sha256")
        != _canonical_sha256([225285, 225284, 225283])
        or mapping.get("transformed_model_mapping_sha256")
        != _canonical_sha256(mapping.get("transformed_model_one_literals_bit0_through_bit14"))
        or modes != expected_modes
        or protocol.get("incremental_mode_manifest_sha256") != _canonical_sha256(modes)
        or protocol.get("numeric_child_order_sha256") != _canonical_sha256(modes[0]["child_order"])
        or protocol.get("gray_child_order_sha256") != _canonical_sha256(modes[1]["child_order"])
        or execution.get("parent_run_order_sha256") != _canonical_sha256(_mode_plan(protocol))
        or execution.get("child_observation_order_sha256")
        != _canonical_sha256(_cell_plan(protocol))
        or execution.get("parent_run_count") != 64
        or execution.get("child_observation_count") != 512
        or execution.get("solver_time_limit_seconds_per_child") != SOLVER_LIMIT_SECONDS
        or execution.get("external_timeout_seconds_per_parent_run")
        != PARENT_EXTERNAL_TIMEOUT_SECONDS
        or execution.get("max_parallel_parent_runs") != MAX_PARALLEL_PARENT_RUNS
        or execution.get("wave_count") != 16
        or execution.get("parent_output_validation")
        != "atomic_all_or_nothing_for_child_rows_and_summary"
        or execution.get("early_stop_permitted") is not False
        or boundary.get("any_A210_round10_helper_or_solver_outcome_known_before_freeze")
        is not False
        or boundary.get("unknown_assignment_in_protocol_source_helper_or_mapping") is not False
        or boundary.get("unknown_assignment_available_to_runner_or_helper_before_execution")
        is not False
        or boundary.get("correct_parent_or_child_prefix_known_before_execution") is not False
        or boundary.get(
            "mode_parent_child_order_budget_or_predictions_changed_after_any_A210_round10_outcome"
        )
        is not False
        or boundary.get("numeric_outcomes_used_to_change_gray_execution") is not False
        or boundary.get("early_stop_permitted") is not False
    ):
        raise RuntimeError("A210 frozen protocol identity gate failed")
    return protocol


def _toolchain_gates(protocol: dict[str, Any]) -> dict[str, Any]:
    repo_root = Path(__file__).parents[2]
    helper = protocol["native_helper"]
    source = repo_root / helper["source"]
    fixture = repo_root / helper["toy_fixture"]
    base_unsat_fixture = repo_root / helper["base_unsat_toy_fixture"]
    compiler = Path(helper["compiler"])
    header = Path(helper["cadical_header"])
    library = Path(helper["cadical_static_library"])
    version = subprocess.run(
        [str(compiler), "--version"],
        text=True,
        capture_output=True,
        check=False,
    )
    first_line = version.stdout.splitlines()[0] if version.stdout.splitlines() else ""
    if (
        _file_sha256(source) != helper["source_sha256"]
        or _file_sha256(fixture) != helper["toy_fixture_sha256"]
        or _file_sha256(base_unsat_fixture) != helper["base_unsat_toy_fixture_sha256"]
        or _file_sha256(compiler) != helper["compiler_sha256"]
        or _file_sha256(header) != helper["cadical_header_sha256"]
        or _file_sha256(library) != helper["cadical_static_library_sha256"]
        or version.returncode != 0
        or first_line != helper["compiler_version_first_line"]
    ):
        raise RuntimeError("A210 native helper toolchain gate failed")
    return {
        "source_sha256": helper["source_sha256"],
        "toy_fixture_sha256": helper["toy_fixture_sha256"],
        "base_unsat_toy_fixture_sha256": helper["base_unsat_toy_fixture_sha256"],
        "compiler_sha256": helper["compiler_sha256"],
        "compiler_version_first_line": first_line,
        "cadical_header_sha256": helper["cadical_header_sha256"],
        "cadical_static_library_sha256": helper["cadical_static_library_sha256"],
        "compiled_binary_expected_sha256": helper["compiled_binary_sha256"],
        "round10_helper_execution_started": False,
    }


def _load_a209_gate(
    results_dir: Path, protocol: dict[str, Any]
) -> tuple[dict[str, Any], dict[str, Any]]:
    research_root = Path(__file__).parents[1]
    a209_protocol = research_root / "configs" / _A209.PROTOCOL_FILENAME
    a209_runner = Path(__file__).with_name("chacha20_round10_bfs_far_width12_refinement.py")
    result_path = results_dir / A209_RESULT_FILENAME
    causal_path = results_dir / A209_CAUSAL_FILENAME
    if (
        _file_sha256(a209_protocol) != _A209.PROTOCOL_SHA256
        or _file_sha256(a209_runner) != protocol["anchors"]["A209"]["runner_sha256"]
        or _file_sha256(result_path) != A209_RESULT_SHA256
        or _file_sha256(causal_path) != A209_CAUSAL_SHA256
    ):
        raise RuntimeError("A210 A209 anchor hash gate failed")
    a209 = json.loads(result_path.read_bytes())
    reader = CryptoCausalReader(causal_path)
    phase = a209["phase_reset_comparison"]
    total = phase["total_metrics"]
    selection = protocol["selection_basis"]
    observed = {
        metric: total[metric]["compute_normalized_mean_child_over_parent"]
        for metric in ("conflicts", "decisions", "propagations", "restarts")
    }
    observed["decisions_per_propagation"] = observed["decisions"] / observed["propagations"]
    all_cells = phase["cell_rows"]
    parent_density = [
        row["metrics"]["decisions"]["compute_normalized_mean_child_over_parent"]
        / row["metrics"]["propagations"]["compute_normalized_mean_child_over_parent"]
        for row in phase["parent_summaries"]
    ]
    if (
        a209.get("comparisons", {}).get("status_counts") != selection["A209_status_counts"]
        or a209.get("confirmations") != []
        or a209.get("public_challenge_sha256") != _A198.PUBLIC_CHALLENGE_SHA256
        or observed != selection["A209_compute_normalized_child_over_parent"]
        or not all(
            row["child_over_A207_parent_ratio"][metric] > 1
            for row in all_cells
            for metric in ("decisions", "propagations", "restarts")
        )
        or [min(parent_density), max(parent_density)]
        != selection["A209_parent_decisions_per_propagation_ratio_range"]
        or reader.graph_sha256 != A209_CAUSAL_GRAPH_SHA256
        or not reader.verify_provenance()
    ):
        raise RuntimeError("A210 A209 semantic selection gate failed")
    gates = {
        "A209_result_sha256": A209_RESULT_SHA256,
        "A209_causal_sha256": A209_CAUSAL_SHA256,
        "A209_causal_graph_sha256": A209_CAUSAL_GRAPH_SHA256,
        "A209_causal_provenance_verified": True,
        "A209_complete_256_unknown_boundary_retained": True,
        "A209_systematic_decision_rich_phase_reset_retained": True,
    }
    return a209, gates


def analyze(results_dir: Path) -> dict[str, Any]:
    protocol = _load_protocol_gate()
    toolchain = _toolchain_gates(protocol)
    a209, anchor = _load_a209_gate(results_dir, protocol)
    a209_analysis = _A209.analyze(results_dir)
    challenge = a209_analysis["public_challenge"]
    baseline = a209["execution"]["observations"]
    if (
        challenge["unknown_assignment_included"] is not False
        or challenge["unknown_key_word0_low_value_included"] is not False
        or len(baseline) != 256
        or [row["prefix8"] for row in baseline] != list(_A209.PREFIXES)
        or any(row["status"] != "unknown" for row in baseline)
        or a209_analysis["solver_execution_started"] is not False
    ):
        raise RuntimeError("A210 challenge or A209 baseline boundary gate failed")
    return {
        "protocol": protocol,
        "toolchain_gates": toolchain,
        "anchor_gates": anchor,
        "a209_result": a209,
        "a209_analysis": a209_analysis,
        "public_challenge": challenge,
        "formula_plan": a209_analysis["formula_plan"],
        "baseline_observations": baseline,
        "solver_execution_started": False,
    }


def _compile_helper(
    protocol: dict[str, Any], *, repo_root: Path, directory: Path
) -> tuple[Path, dict[str, Any]]:
    helper = protocol["native_helper"]
    output = directory / "cadical_incremental_assumptions"
    command = [
        helper["compiler"],
        *helper["compile_arguments"],
        "-o",
        str(output),
    ]
    started = time.perf_counter()
    result = subprocess.run(
        command,
        cwd=repo_root,
        text=True,
        capture_output=True,
        check=False,
    )
    observation = {
        "command": command,
        "returncode": result.returncode,
        "volatile_seconds": time.perf_counter() - started,
        "stdout_sha256": _sha256(result.stdout.encode()),
        "stderr_sha256": _sha256(result.stderr.encode()),
        "binary_sha256": _file_sha256(output) if output.exists() else None,
    }
    if (
        result.returncode != 0
        or result.stdout
        or result.stderr
        or observation["binary_sha256"] != helper["compiled_binary_sha256"]
    ):
        raise RuntimeError("A210 native helper compilation gate failed")
    return output, observation


def _build_parent_transforms(
    *,
    analysis: dict[str, Any],
    identities: dict[str, dict[str, Any]],
    directory: Path,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], dict[str, Path]]:
    protocol = analysis["protocol"]
    a209_analysis = analysis["a209_analysis"]
    source_exports, source_paths = _A204._export_round10_cnfs(
        a209_analysis["a208_analysis"]["a207_analysis"]["a206_analysis"]["a204_analysis"],
        identities,
        directory,
    )
    free_mapping = a209_analysis["a208_analysis"]["protocol"]["round10_source"][
        "free_k0_bit_one_literal_mapping"
    ]
    representative_refined = _A209._refine_cnf(
        source_paths["cse_prefix_11111"].read_bytes(),
        prefix8="11111111",
        free_mapping=free_mapping,
    )
    _, mapping, inverse, transformed_model_mapping, diagnostics = _A209._derive_refined_order(
        representative_refined,
        free_mapping,
        a209_analysis["protocol"],
    )
    expected_mapping = protocol["assumption_and_model_mapping"][
        "transformed_model_one_literals_bit0_through_bit14"
    ]
    if transformed_model_mapping != expected_mapping:
        raise RuntimeError("A210 transformed model mapping differs")
    manifest = []
    paths = {}
    preflight = protocol["parent_CNF_preflight"]
    for parent_prefix5 in PARENTS:
        source_variant = f"cse_prefix_{parent_prefix5}"
        raw = source_paths[source_variant].read_bytes()
        transformed = _A205._reindex_cnf(raw, mapping)
        header, tail, normalized_sha256 = _A204._normalized_cnf(transformed)
        restored = _A205._reindex_cnf(transformed, inverse)
        if restored != raw:
            raise RuntimeError(f"A210 {parent_prefix5} inverse transform differs")
        output = directory / f"a210_parent_{parent_prefix5}.cnf"
        output.write_bytes(transformed)
        manifest.append(
            {
                "parent_prefix5": parent_prefix5,
                "source_variant": source_variant,
                "source_cnf_sha256": _sha256(raw),
                "transformed_parent_cnf_sha256": _sha256(transformed),
                "transformed_parent_cnf_bytes": len(transformed),
                "transformed_header": header,
                "transformed_tail_units": tail,
                "transformed_normalized_sha256": normalized_sha256,
                "inverse_byte_identical": True,
                "inverse_restored_sha256": _sha256(restored),
            }
        )
        paths[parent_prefix5] = output
    if (
        diagnostics["order_sha256"] != preflight["order_sha256"]
        or diagnostics["old_to_new_sha256"] != preflight["old_to_new_sha256"]
        or _canonical_sha256(manifest) != preflight["transformed_parent_manifest_sha256"]
        or len({row["transformed_parent_cnf_sha256"] for row in manifest}) != 32
        or {row["transformed_normalized_sha256"] for row in manifest}
        != {preflight["transformed_parent_common_normalized_sha256"]}
        or manifest[-1]["transformed_parent_cnf_sha256"]
        != preflight["representative_transformed_parent_sha256"]
        or manifest[-1]["transformed_parent_cnf_bytes"]
        != preflight["representative_transformed_parent_bytes"]
        or not all(row["inverse_byte_identical"] for row in manifest)
    ):
        raise RuntimeError("A210 complete transformed parent manifest gate failed")
    clean_sources = [
        {key: value for key, value in row.items() if key != "path"} for row in source_exports
    ]
    return clean_sources, manifest, paths


def _decode_model(
    *,
    challenge: dict[str, Any],
    parent_prefix5: str,
    model_bits: Sequence[int],
) -> dict[str, int]:
    if len(model_bits) != 15 or any(value not in {0, 1} for value in model_bits):
        raise RuntimeError("A210 helper SAT model bits are not fifteen Boolean values")
    free_value = sum(value << bit for bit, value in enumerate(model_bits))
    key_word0 = challenge["known_key_word0_upper12"] | (int(parent_prefix5, 2) << 15) | free_value
    key_word1_low_value = challenge["known_key_word1"] & 0xFF
    return {
        "key_word0": key_word0,
        "key_word1_low_value": key_word1_low_value,
        "combined_assignment": (key_word1_low_value << 32) | key_word0,
        "recovered_unknown_low20": key_word0 & ((1 << 20) - 1),
    }


def _invalid_child(
    *, mode: str, parent_prefix5: str, child: str, child_index: int, reason: str
) -> dict[str, Any]:
    return {
        "variant": f"{mode}__prefix_{parent_prefix5 + child}",
        "mode": mode,
        "parent_prefix5": parent_prefix5,
        "child": child,
        "child_index": child_index,
        "prefix8": parent_prefix5 + child,
        "status": "invalid",
        "returncode": None,
        "elapsed_seconds": None,
        "terminator_fired": False,
        "assumptions": [],
        "failed_assumptions": [],
        "metrics_before": {},
        "metrics_after": {},
        "metrics_delta": {},
        "active_variables": None,
        "irredundant_clauses": None,
        "redundant_clauses": None,
        "model": None,
        "invalid_reason": reason,
    }


def _parse_parent_output(
    *,
    mode: dict[str, Any],
    parent_prefix5: str,
    stdout: str,
    helper_returncode: int | None,
    externally_timed_out: bool,
    challenge: dict[str, Any],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], dict[str, Any] | None]:
    parsed_results: dict[str, dict[str, Any]] = {}
    summary = None
    malformed = False
    for line in stdout.splitlines():
        try:
            if line.startswith("A210_RESULT "):
                row = json.loads(line.removeprefix("A210_RESULT "))
                if row["child"] in parsed_results:
                    malformed = True
                parsed_results[row["child"]] = row
            elif line.startswith("A210_SUMMARY "):
                if summary is not None:
                    malformed = True
                summary = json.loads(line.removeprefix("A210_SUMMARY "))
            elif line.strip():
                malformed = True
        except (KeyError, TypeError, ValueError, json.JSONDecodeError):
            malformed = True
    observations = []
    confirmations = []
    previous_after = None
    assumptions_map = [225285, 225284, 225283]
    if externally_timed_out:
        parent_invalid_reason = "external_parent_timeout"
    elif helper_returncode != 0:
        parent_invalid_reason = "invalid_helper_returncode"
    elif malformed or set(parsed_results) != set(mode["child_order"]):
        parent_invalid_reason = "malformed_or_incomplete_helper_output"
    else:
        parent_invalid_reason = None
    valid_parent_output = parent_invalid_reason is None
    for child_index, child in enumerate(mode["child_order"]):
        raw = parsed_results.get(child)
        if raw is None or not valid_parent_output:
            reason = parent_invalid_reason or "missing_helper_child"
            observations.append(
                _invalid_child(
                    mode=mode["name"],
                    parent_prefix5=parent_prefix5,
                    child=child,
                    child_index=child_index,
                    reason=reason,
                )
            )
            continue
        expected_assumptions = [
            variable if bit == "1" else -variable
            for bit, variable in zip(child, assumptions_map, strict=True)
        ]
        status = raw.get("status")
        failed_assumptions = raw.get("failed_assumptions")
        before_values = raw.get("metrics_before")
        after_values = raw.get("metrics_after")
        delta_values = raw.get("metrics_delta")
        if (
            raw.get("prefix5") != parent_prefix5
            or raw.get("child_index") != child_index
            or raw.get("metric_names") != list(METRIC_NAMES)
            or raw.get("assumptions") != expected_assumptions
            or status not in {"sat", "unsat", "unknown"}
            or raw.get("returncode") != {"sat": 10, "unsat": 20, "unknown": 0}[status]
            or not isinstance(before_values, list)
            or not isinstance(after_values, list)
            or not isinstance(delta_values, list)
            or len(before_values) != 3
            or len(after_values) != 3
            or len(delta_values) != 3
            or any(
                after - before != delta
                for before, after, delta in zip(
                    before_values, after_values, delta_values, strict=True
                )
            )
            or any(value < 0 for value in [*before_values, *after_values, *delta_values])
            or (previous_after is not None and before_values != previous_after)
            or (status == "unknown") != (raw.get("terminator_fired") is True)
            or not isinstance(failed_assumptions, list)
            or len(set(failed_assumptions)) != len(failed_assumptions)
            or any(literal not in expected_assumptions for literal in failed_assumptions)
            or (status != "unsat" and failed_assumptions != [])
            or (status == "sat" and len(raw.get("model_bits_bit0_through_bit14", [])) != 15)
            or (status != "sat" and raw.get("model_bits_bit0_through_bit14") != [])
        ):
            observations.append(
                _invalid_child(
                    mode=mode["name"],
                    parent_prefix5=parent_prefix5,
                    child=child,
                    child_index=child_index,
                    reason="helper_semantic_gate_failed",
                )
            )
            valid_parent_output = False
            parent_invalid_reason = "helper_semantic_gate_failed"
            continue
        previous_after = after_values
        model = None
        if status == "sat":
            model = _decode_model(
                challenge=challenge,
                parent_prefix5=parent_prefix5,
                model_bits=raw["model_bits_bit0_through_bit14"],
            )
            confirmation = {
                "variant": f"{mode['name']}__prefix_{parent_prefix5 + child}",
                "mode": mode["name"],
                "parent_prefix5": parent_prefix5,
                "child": child,
                "prefix8": parent_prefix5 + child,
                "prefix8_match": ((model["key_word0"] >> 12) & 0xFF)
                == int(parent_prefix5 + child, 2),
                **_A198._confirm_model(challenge, model),
            }
            if (
                confirmation["prefix8_match"] is not True
                or confirmation["known_key_constraints_match"] is not True
                or confirmation["all_blocks_match"] is not True
                or confirmation["control_first_block_match"] is not False
                or confirmation["output_bits_checked"] != 4096
            ):
                raise RuntimeError("A210 helper SAT model failed independent confirmation")
            confirmations.append(confirmation)
        observations.append(
            {
                "variant": f"{mode['name']}__prefix_{parent_prefix5 + child}",
                "mode": mode["name"],
                "parent_prefix5": parent_prefix5,
                "child": child,
                "child_index": child_index,
                "prefix8": parent_prefix5 + child,
                "status": status,
                "returncode": raw["returncode"],
                "elapsed_seconds": raw["elapsed_seconds"],
                "terminator_fired": raw["terminator_fired"],
                "assumptions": raw["assumptions"],
                "failed_assumptions": raw["failed_assumptions"],
                "metrics_before": dict(zip(METRIC_NAMES, before_values, strict=True)),
                "metrics_after": dict(zip(METRIC_NAMES, after_values, strict=True)),
                "metrics_delta": dict(zip(METRIC_NAMES, delta_values, strict=True)),
                "active_variables": raw["active_variables"],
                "irredundant_clauses": raw["irredundant_clauses"],
                "redundant_clauses": raw["redundant_clauses"],
                "model": model,
                "invalid_reason": None,
            }
        )
    if valid_parent_output:
        counts = {
            status: sum(row["status"] == status for row in observations)
            for status in ("sat", "unsat", "unknown")
        }
        if (
            summary is None
            or summary.get("signature") != "cadical-3.0.0"
            or summary.get("version") != "3.0.0"
            or summary.get("prefix5") != parent_prefix5
            or summary.get("variables") != 232191
            or summary.get("children") != 8
            or summary.get("metric_names") != list(METRIC_NAMES)
            or {status: summary.get(status) for status in counts} != counts
        ):
            valid_parent_output = False
            parent_invalid_reason = "helper_summary_gate_failed"
    if not valid_parent_output:
        observations = [
            _invalid_child(
                mode=mode["name"],
                parent_prefix5=parent_prefix5,
                child=child,
                child_index=child_index,
                reason=parent_invalid_reason or "invalid_parent_output",
            )
            for child_index, child in enumerate(mode["child_order"])
        ]
        confirmations = []
    return observations, confirmations, summary


def _run_parent(
    *,
    mode: dict[str, Any],
    parent_prefix5: str,
    cnf_path: Path,
    helper_path: Path,
    protocol: dict[str, Any],
    challenge: dict[str, Any],
) -> tuple[dict[str, Any], list[dict[str, Any]], list[dict[str, Any]]]:
    mapping = protocol["assumption_and_model_mapping"]
    command = [
        str(helper_path),
        "--cnf",
        str(cnf_path),
        "--prefix5",
        parent_prefix5,
        "--assumption-vars",
        ",".join(str(value) for value in mapping["transformed_child_one_literals_descending"]),
        "--model-vars",
        ",".join(
            str(value) for value in mapping["transformed_model_one_literals_bit0_through_bit14"]
        ),
        "--child-order",
        ",".join(mode["child_order"]),
        "--seconds",
        str(SOLVER_LIMIT_SECONDS),
    ]
    started = time.perf_counter()
    try:
        result = subprocess.run(
            command,
            text=True,
            capture_output=True,
            timeout=PARENT_EXTERNAL_TIMEOUT_SECONDS,
            check=False,
        )
        externally_timed_out = False
        stdout, stderr, returncode = result.stdout, result.stderr, result.returncode
    except subprocess.TimeoutExpired as error:
        externally_timed_out = True
        stdout = _A204._as_text(error.stdout)
        stderr = _A204._as_text(error.stderr)
        returncode = None
    observations, confirmations, summary = _parse_parent_output(
        mode=mode,
        parent_prefix5=parent_prefix5,
        stdout=stdout,
        helper_returncode=returncode,
        externally_timed_out=externally_timed_out,
        challenge=challenge,
    )
    parent = {
        "mode": mode["name"],
        "parent_prefix5": parent_prefix5,
        "command": command,
        "returncode": returncode,
        "externally_timed_out": externally_timed_out,
        "volatile_seconds": time.perf_counter() - started,
        "stdout_sha256": _sha256(stdout.encode()),
        "stderr_sha256": _sha256(stderr.encode()),
        "summary": summary,
        "child_statuses": [row["status"] for row in observations],
        "valid_child_count": sum(row["status"] != "invalid" for row in observations),
    }
    return parent, observations, confirmations


def _execute(
    *,
    parent_paths: dict[str, Path],
    helper_path: Path,
    protocol: dict[str, Any],
    challenge: dict[str, Any],
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    parent_runs = []
    observations = []
    confirmations = []
    waves = []
    wave_index = 0
    for mode in protocol["incremental_modes"]:
        for start in range(0, len(PARENTS), MAX_PARALLEL_PARENT_RUNS):
            wave = PARENTS[start : start + MAX_PARALLEL_PARENT_RUNS]

            def execute(
                parent: str,
                frozen_mode: dict[str, Any] = mode,
            ) -> tuple[dict[str, Any], list[dict[str, Any]], list[dict[str, Any]]]:
                return _run_parent(
                    mode=frozen_mode,
                    parent_prefix5=parent,
                    cnf_path=parent_paths[parent],
                    helper_path=helper_path,
                    protocol=protocol,
                    challenge=challenge,
                )

            with ThreadPoolExecutor(max_workers=MAX_PARALLEL_PARENT_RUNS) as executor:
                rows = list(executor.map(execute, wave))
            for parent_run, child_rows, confirmed in rows:
                parent_runs.append(parent_run)
                observations.extend(child_rows)
                confirmations.extend(confirmed)
            waves.append(
                {
                    "wave_index": wave_index,
                    "mode": mode["name"],
                    "parents": list(wave),
                    "valid_child_counts": [row[0]["valid_child_count"] for row in rows],
                    "maximum_volatile_seconds": max(row[0]["volatile_seconds"] for row in rows),
                }
            )
            wave_index += 1
    expected_parents = _mode_plan(protocol)
    expected_cells = _cell_plan(protocol)
    if [
        {"mode": row["mode"], "parent_prefix5": row["parent_prefix5"]} for row in parent_runs
    ] != expected_parents or [
        {"mode": row["mode"], "prefix8": row["prefix8"]} for row in observations
    ] != expected_cells:
        raise RuntimeError("A210 complete execution order differs from freeze")
    return {
        "parent_run_order": expected_parents,
        "child_observation_order": expected_cells,
        "complete_parent_plan_executed": len(parent_runs) == 64,
        "complete_child_plan_executed": len(observations) == 512,
        "early_stop_used": False,
        "parent_runs": parent_runs,
        "observations": observations,
        "wave_observations": waves,
        "returned_model_count": len(confirmations),
        "round10_unknown_assignment_available_to_runner_or_helper_before_execution": False,
    }, confirmations


def _metric_ratio_summary(
    rows: list[dict[str, Any]], numerator_key: str, denominator_key: str, metric: str
) -> dict[str, Any]:
    pairs = [
        (row[numerator_key].get(metric), row[denominator_key].get(metric))
        for row in rows
        if row[numerator_key].get(metric) is not None
        and row[denominator_key].get(metric) is not None
    ]
    ratios = [numerator / denominator for numerator, denominator in pairs if denominator != 0]
    numerator_total = sum(numerator for numerator, _ in pairs) if pairs else None
    denominator_total = sum(denominator for _, denominator in pairs) if pairs else None
    return {
        "matched_count": len(pairs),
        "numerator_total": numerator_total,
        "denominator_total": denominator_total,
        "total_ratio": (
            numerator_total / denominator_total
            if numerator_total is not None and denominator_total not in {None, 0}
            else None
        ),
        "cell_ratio_count": len(ratios),
        "cell_ratio_min": min(ratios) if ratios else None,
        "cell_ratio_median": float(np.median(ratios)) if ratios else None,
        "cell_ratio_max": max(ratios) if ratios else None,
    }


def _comparative_metrics(
    observations: list[dict[str, Any]], baseline_observations: list[dict[str, Any]]
) -> dict[str, Any]:
    baseline = {row["prefix8"]: row for row in baseline_observations}
    mode_rows = {}
    for mode in ("numeric_incremental", "gray_incremental"):
        rows = []
        for observation in observations:
            if observation["mode"] != mode:
                continue
            parent = baseline[observation["prefix8"]]
            rows.append(
                {
                    "mode": mode,
                    "prefix8": observation["prefix8"],
                    "child_index": observation["child_index"],
                    "status": observation["status"],
                    "incremental_metrics_delta": observation["metrics_delta"],
                    "A209_fresh_metrics": parent["metrics"],
                }
            )
        mode_rows[mode] = rows
    summaries = {}
    for mode, rows in mode_rows.items():
        summaries[mode] = {
            metric: _metric_ratio_summary(
                rows,
                "incremental_metrics_delta",
                "A209_fresh_metrics",
                metric,
            )
            for metric in A209_COMPARABLE_METRICS
        }
    numeric = {row["prefix8"]: row for row in mode_rows["numeric_incremental"]}
    gray = {row["prefix8"]: row for row in mode_rows["gray_incremental"]}
    ordered_rows = []
    for prefix8 in _A209.PREFIXES:
        left, right = numeric[prefix8], gray[prefix8]
        ordered_rows.append(
            {
                "prefix8": prefix8,
                "numeric_status": left["status"],
                "gray_status": right["status"],
                "status_differs": left["status"] != right["status"],
                "numeric_metrics_delta": left["incremental_metrics_delta"],
                "gray_metrics_delta": right["incremental_metrics_delta"],
            }
        )
    ordered_summary = {
        "status_difference_prefixes": [
            row["prefix8"] for row in ordered_rows if row["status_differs"]
        ],
        "gray_over_numeric": {
            metric: _metric_ratio_summary(
                ordered_rows,
                "gray_metrics_delta",
                "numeric_metrics_delta",
                metric,
            )
            for metric in METRIC_NAMES
        },
    }
    position_summaries = {}
    for mode, rows in mode_rows.items():
        position_summaries[mode] = []
        for child_index in range(8):
            selected = [row for row in rows if row["child_index"] == child_index]
            position_summaries[mode].append(
                {
                    "child_index": child_index,
                    "cell_count": len(selected),
                    "status_counts": {
                        status: sum(row["status"] == status for row in selected)
                        for status in ("sat", "unsat", "unknown", "invalid")
                    },
                    "metric_totals": {
                        metric: sum(
                            row["incremental_metrics_delta"].get(metric, 0) for row in selected
                        )
                        for metric in METRIC_NAMES
                    },
                }
            )
    return {
        "A209_comparison_scope": list(A209_COMPARABLE_METRICS),
        "search_propagations_not_compared_to_A209_CLI_total_propagations": True,
        "mode_cell_rows": mode_rows,
        "mode_vs_A209_summaries": summaries,
        "ordered_mode_rows": ordered_rows,
        "ordered_mode_summary": ordered_summary,
        "child_position_summaries": position_summaries,
    }


def _compare(
    *,
    execution: dict[str, Any],
    confirmations: list[dict[str, Any]],
) -> dict[str, Any]:
    observations = execution["observations"]
    per_mode = {
        mode: {
            status: sum(row["mode"] == mode and row["status"] == status for row in observations)
            for status in ("sat", "unsat", "unknown", "invalid")
        }
        for mode in ("numeric_incremental", "gray_incremental")
    }
    complete_modes = [
        mode
        for mode, counts in per_mode.items()
        if counts == {"sat": 1, "unsat": 255, "unknown": 0, "invalid": 0}
    ]
    confirmed_by_mode = {
        mode: [row for row in confirmations if row["mode"] == mode] for mode in per_mode
    }
    confirmed_prefixes = {
        mode: sorted({row["prefix8"] for row in rows}) for mode, rows in confirmed_by_mode.items()
    }
    unsat_prefixes = {
        mode: sorted(
            {
                row["prefix8"]
                for row in observations
                if row["mode"] == mode and row["status"] == "unsat"
            }
        )
        for mode in per_mode
    }
    contradictory = sorted(
        (set(confirmed_prefixes["numeric_incremental"]) & set(unsat_prefixes["gray_incremental"]))
        | (set(confirmed_prefixes["gray_incremental"]) & set(unsat_prefixes["numeric_incremental"]))
    )
    resolved_modes = [
        mode for mode in complete_modes if len(confirmed_by_mode[mode]) == 1 and not contradictory
    ]
    return {
        "parent_run_count": len(execution["parent_runs"]),
        "child_observation_count": len(observations),
        "complete_predeclared_execution": len(execution["parent_runs"]) == 64
        and len(observations) == 512,
        "early_stop_used": False,
        "per_mode_status_counts": per_mode,
        "terminal_cell_counts": {
            mode: counts["sat"] + counts["unsat"] for mode, counts in per_mode.items()
        },
        "confirmed_variants": [row["variant"] for row in confirmations],
        "confirmed_prefixes_by_mode": confirmed_prefixes,
        "confirmed_combined_assignments": sorted(
            {row["combined_assignment"] for row in confirmations}
        ),
        "recovered_unknown_low20_assignments": sorted(
            {row["recovered_unknown_low20"] for row in confirmations}
        ),
        "confirmed_recovery_retained": len(confirmations) >= 1,
        "complete_domain_resolution_candidate_modes": complete_modes,
        "cross_mode_contradictory_confirmed_unsat_prefixes": contradictory,
        "complete_domain_resolution_modes": resolved_modes,
        "complete_domain_resolution_retained": bool(resolved_modes),
        "incremental_resolution_transfer_retained": any(
            counts["sat"] + counts["unsat"] > 0 for counts in per_mode.values()
        ),
        "complete_domain_covered_once_per_mode": True,
        "complete_domain_candidate_count": 1 << 20,
        "statuses": {row["variant"]: row["status"] for row in observations},
    }


def _build_causal(path: Path, payload: dict[str, Any]) -> dict[str, Any]:
    builder = CryptoCausalBuilder(
        experiment="chacha20_round10_incremental_sibling_learning",
        parameters={
            "attempt_id": ATTEMPT_ID,
            "rounds": 10,
            "modes": 2,
            "parents_per_mode": 32,
            "children_per_parent": 8,
            "child_observations": 512,
        },
    )
    ids = [
        "chacha20-a210-a209-phase-reset-anchor",
        "chacha20-a210-native-helper-identity",
        "chacha20-a210-exact-parent-transforms",
        "chacha20-a210-ordered-incremental-factorial",
        "chacha20-a210-complete-incremental-execution",
        "chacha20-a210-independent-confirmation",
        "chacha20-a210-comparative-metrics",
        "chacha20-a210-incremental-result",
    ]
    rows = [
        (
            "A209:complete_width12_phase_reset_boundary",
            "retain_the_256_cell_unknown_boundary_and_systematic_decision_rich_reset",
            "A210:incremental_learning_selection_anchor",
            "retained_A209_phase_reset",
            A209_CAUSAL_SHA256,
            [],
            {
                "anchor_gates": payload["anchor_gates"],
                "selection_basis": payload["selection_basis"],
            },
        ),
        (
            "A210:incremental_learning_selection_anchor",
            "compile_and_hash_gate_the_CaDiCaL_3_native_assumption_helper",
            "A210:exact_incremental_solver_primitive",
            "native_helper_identity",
            payload["native_helper_sha256"],
            [ids[0]],
            {"native_helper": payload["native_helper"]},
        ),
        (
            "A210:exact_incremental_solver_primitive",
            "apply_the_A209_BFS_far_bijection_to_all_32_parent_CNF_cells",
            "A210:complete_transformed_parent_cover",
            "exact_parent_CNF_transform",
            payload["parent_transform_manifest_sha256"],
            [ids[1]],
            {"parent_transform_manifest": payload["parent_transform_manifest"]},
        ),
        (
            "A210:complete_transformed_parent_cover",
            "execute_numeric_and_Gray_T01_ordered_child_update_sequences_in_independent_states",
            "A210:frozen_two_mode_incremental_factorial",
            "T01_ordered_noncommutative_update_transfer",
            payload["incremental_modes_sha256"],
            [ids[2]],
            {"incremental_modes": payload["incremental_modes"]},
        ),
        (
            "A210:frozen_two_mode_incremental_factorial",
            "retain_learned_clauses_within_each_parent_and_execute_all_512_children",
            "A210:complete_incremental_execution",
            "complete_predeclared_incremental_execution",
            payload["execution_sha256"],
            [ids[3]],
            {"execution": payload["execution"]},
        ),
        (
            "A210:complete_incremental_execution",
            "decode_every_SAT_model_and_recompute_all_4096_target_bits",
            "A210:independently_confirmed_models_or_boundary",
            "independent_model_confirmation",
            payload["confirmation_sha256"],
            [ids[4]],
            {"confirmations": payload["confirmations"]},
        ),
        (
            "A210:independently_confirmed_models_or_boundary",
            "compare_numeric_Gray_and_exact_A209_fresh_cell_metrics_on_valid_scopes",
            "A210:ordered_incremental_learning_profile",
            "matched_incremental_comparison",
            payload["comparative_metrics_sha256"],
            [ids[5]],
            {"comparative_metrics": payload["comparative_metrics"]},
        ),
        (
            "A210:ordered_incremental_learning_profile",
            "evaluate_recovery_resolution_and_ordered_update_predictions",
            "A210:prospective_incremental_result",
            "prospective_incremental_comparison",
            payload["comparison_sha256"],
            [ids[6]],
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
        raise RuntimeError("A210 Causal Reader provenance gate failed")
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
    repo_root = Path(__file__).parents[2]
    identities = _A204._solver_gates(_A204._load_protocol_gate())
    with tempfile.TemporaryDirectory(prefix="a210-incremental-sibling-") as raw_directory:
        directory = Path(raw_directory)
        helper_path, compilation = _compile_helper(
            protocol,
            repo_root=repo_root,
            directory=directory,
        )
        source_exports, parent_manifest, parent_paths = _build_parent_transforms(
            analysis=analysis,
            identities=identities,
            directory=directory,
        )
        execution, confirmations = _execute(
            parent_paths=parent_paths,
            helper_path=helper_path,
            protocol=protocol,
            challenge=analysis["public_challenge"],
        )
    comparative = _comparative_metrics(execution["observations"], analysis["baseline_observations"])
    comparisons = _compare(execution=execution, confirmations=confirmations)
    if comparisons["complete_domain_resolution_retained"]:
        evidence_stage = "ROUND10_INCREMENTAL_COMPLETE_DOMAIN_RESOLUTION_RETAINED"
    elif comparisons["confirmed_recovery_retained"]:
        evidence_stage = "ROUND10_INCREMENTAL_CONFIRMED_RECOVERY_RETAINED"
    elif comparisons["incremental_resolution_transfer_retained"]:
        evidence_stage = "ROUND10_INCREMENTAL_TERMINAL_TRANSFER_RETAINED"
    else:
        evidence_stage = "ROUND10_INCREMENTAL_COMPLETE_BOUNDARY_RETAINED"
    native_helper = {
        "protocol_identity": protocol["native_helper"],
        "toolchain_gates": analysis["toolchain_gates"],
        "compilation": compilation,
    }
    payload: dict[str, Any] = {
        "schema": SCHEMA,
        "attempt_id": ATTEMPT_ID,
        "evidence_stage": evidence_stage,
        "result": (
            "Two complete assumption-incremental covers test learned-clause transfer "
            "across numeric and Gray ordered Width-12 sibling cells."
        ),
        "scope": "Reduced ChaCha10 20-bit partial-key recovery over eight shared-key blocks.",
        "protocol_gate": {
            "artifact_sha256": PROTOCOL_SHA256,
            "protocol_state": protocol["protocol_state"],
            "information_boundary": protocol["information_boundary"],
            "prospective_predictions": protocol["prospective_predictions"],
        },
        "anchor_gates": analysis["anchor_gates"],
        "selection_basis": protocol["selection_basis"],
        "selection_basis_sha256": _canonical_sha256(protocol["selection_basis"]),
        "solver_identities": {
            "bitwuzla": identities["bitwuzla"],
            "cadical_cli_anchor": identities["cadical"],
        },
        "public_challenge": analysis["public_challenge"],
        "public_challenge_sha256": _A198.PUBLIC_CHALLENGE_SHA256,
        "formula_plan": analysis["formula_plan"],
        "formula_plan_sha256": _canonical_sha256(analysis["formula_plan"]),
        "native_helper": native_helper,
        "native_helper_sha256": _canonical_sha256(native_helper),
        "source_exports": source_exports,
        "source_exports_sha256": _canonical_sha256(source_exports),
        "parent_transform_manifest": parent_manifest,
        "parent_transform_manifest_sha256": _canonical_sha256(parent_manifest),
        "assumption_and_model_mapping": protocol["assumption_and_model_mapping"],
        "mapping_sha256": _canonical_sha256(protocol["assumption_and_model_mapping"]),
        "incremental_modes": protocol["incremental_modes"],
        "incremental_modes_sha256": _canonical_sha256(protocol["incremental_modes"]),
        "execution_plan": protocol["execution_plan"],
        "execution_plan_sha256": _canonical_sha256(protocol["execution_plan"]),
        "execution": execution,
        "execution_sha256": _canonical_sha256(execution),
        "confirmations": confirmations,
        "confirmation_sha256": _canonical_sha256(confirmations),
        "comparative_metrics": comparative,
        "comparative_metrics_sha256": _canonical_sha256(comparative),
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
        raise RuntimeError("A210 final artifact reopen gate failed")
    return {
        "json_sha256": _sha256(raw),
        "causal_sha256": reader.file_sha256,
        "causal_graph_sha256": reader.graph_sha256,
        "evidence_stage": evidence_stage,
        "per_mode_status_counts": comparisons["per_mode_status_counts"],
        "confirmed_variants": comparisons["confirmed_variants"],
        "recovered_unknown_low20_assignments": comparisons["recovered_unknown_low20_assignments"],
        "complete_domain_resolution_modes": comparisons["complete_domain_resolution_modes"],
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
            "modes": [mode["name"] for mode in analysis["protocol"]["incremental_modes"]],
            "parent_runs": analysis["protocol"]["execution_plan"]["parent_run_count"],
            "child_observations": analysis["protocol"]["execution_plan"]["child_observation_count"],
            "seconds_per_child": analysis["protocol"]["execution_plan"][
                "solver_time_limit_seconds_per_child"
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

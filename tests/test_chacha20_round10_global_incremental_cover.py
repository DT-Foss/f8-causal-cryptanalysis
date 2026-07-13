from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest

ROOT = Path(__file__).parents[1]
MODULE_PATH = ROOT / "research" / "experiments" / "chacha20_round10_global_incremental_cover.py"
SPEC = importlib.util.spec_from_file_location(
    "chacha20_round10_global_incremental_cover_tested", MODULE_PATH
)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)

RESULTS = ROOT / "research" / "results" / "v1"
PROTOCOL_PATH = ROOT / "research" / "configs" / MODULE.PROTOCOL_FILENAME


@pytest.fixture(scope="module")
def analysis() -> dict[str, Any]:
    return MODULE.analyze(RESULTS)


def test_a211_protocol_anchor_selection_and_toolchain_are_exact(
    analysis: dict[str, Any],
) -> None:
    assert MODULE._file_sha256(PROTOCOL_PATH) == MODULE.PROTOCOL_SHA256
    assert analysis["solver_execution_started"] is False
    assert analysis["anchor_gates"] == {
        "A210_result_sha256": MODULE.A210_RESULT_SHA256,
        "A210_causal_sha256": MODULE.A210_CAUSAL_SHA256,
        "A210_causal_graph_sha256": MODULE.A210_CAUSAL_GRAPH_SHA256,
        "A210_causal_provenance_verified": True,
        "A210_complete_512_unknown_boundary_retained": True,
        "A210_systematic_sibling_state_transfer_retained": True,
    }
    selection = analysis["protocol"]["selection_basis"]
    assert selection["A210_numeric_first_child_decision_share"] == 0.8856242142055105
    assert selection["A210_gray_first_child_decision_share"] == 0.8683062507305199
    assert selection["formula_transfer_family"] == (
        "T01_global_ordered_noncommutative_update_composition"
    )
    assert selection["any_A211_round10_global_incremental_outcome_known_at_selection"] is False
    toolchain = analysis["toolchain_gates"]
    assert toolchain["source_sha256"] == (
        "3b4a5aa0a8d537d6599ec20d9e17d173db0c7b5fbddf8864859346b5fd4a497c"
    )
    assert toolchain["compiled_binary_expected_sha256"] == (
        "fb822acdd0453a36bf6e5f6df763a72a7b999710e47ac9329160f28603d1ce84"
    )
    assert toolchain["round10_helper_execution_started"] is False


def test_a211_complete_numeric_and_true_gray8_orders_are_frozen(
    analysis: dict[str, Any],
) -> None:
    orders = analysis["mode_orders"]
    numeric = orders["numeric_global_incremental"]
    gray = orders["reflected_gray8_global_incremental"]
    assert len(numeric) == len(gray) == 256
    assert set(numeric) == set(gray) == {f"{value:08b}" for value in range(256)}
    assert numeric == [f"{value:08b}" for value in range(256)]
    assert gray == [f"{value ^ (value >> 1):08b}" for value in range(256)]
    assert MODULE._canonical_sha256(numeric) == (
        "31d5ffc95c2e51b8800e5aaf590fe08386b11a05ea646bf756f3026bece5aaa0"
    )
    assert MODULE._canonical_sha256(gray) == (
        "1501c2c1050a88600b03f1735f7ac9285703229fa9ce4b6739d5260360a3b936"
    )
    assert MODULE._hamming_profile(gray)["distance_counts"] == {"1": 255}
    assert MODULE._hamming_profile(numeric)["maximum"] == 8


def test_a211_mapping_execution_and_information_boundary_are_exact(
    analysis: dict[str, Any],
) -> None:
    protocol = analysis["protocol"]
    mapping = protocol["assumption_and_model_mapping"]
    assert mapping["prefix_bits_descending"] == list(range(19, 11, -1))
    assert mapping["transformed_prefix_one_literals_descending"] == [
        225290,
        225289,
        225288,
        225287,
        225286,
        225285,
        225284,
        225283,
    ]
    assert len(mapping["transformed_model_one_literals_bit0_through_bit19"]) == 20
    plan = protocol["execution_plan"]
    assert plan["mode_run_count"] == 2
    assert plan["child_observation_count"] == 512
    assert plan["solver_time_limit_seconds_per_cell"] == 10
    assert plan["external_timeout_seconds_per_mode"] == 3050
    assert plan["fresh_solver_instance_per_mode"] is True
    assert plan["learned_state_retained_across_all_256_cells_within_mode"] is True
    assert plan["early_stop_permitted"] is False
    boundary = protocol["information_boundary"]
    assert boundary["any_A211_round10_helper_or_solver_outcome_known_before_freeze"] is False
    assert boundary["unknown_assignment_available_to_runner_or_helper_before_execution"] is False
    assert boundary["correct_prefix_known_before_execution"] is False
    assert boundary["numeric_outcomes_used_to_change_Gray8_execution"] is False


def test_a211_native_helper_compiles_and_passes_both_256_cell_toys(
    analysis: dict[str, Any], tmp_path: Path
) -> None:
    helper, compilation = MODULE._compile_helper(
        analysis["protocol"], repo_root=ROOT, directory=tmp_path
    )
    assert compilation["returncode"] == 0
    assert compilation["binary_sha256"] == (
        "fb822acdd0453a36bf6e5f6df763a72a7b999710e47ac9329160f28603d1ce84"
    )
    order = analysis["mode_orders"]["numeric_global_incremental"]
    command = [
        str(helper),
        "--cnf",
        str(ROOT / "tests" / "fixtures" / "cadical_global_incremental_assumptions_toy.cnf"),
        "--mode",
        "toy_numeric",
        "--assumption-vars",
        "20,19,18,17,16,15,14,13",
        "--model-vars",
        ",".join(str(value) for value in range(1, 21)),
        "--cell-order",
        ",".join(order),
        "--seconds",
        "0.01",
    ]
    result = subprocess.run(command, text=True, capture_output=True, check=False)
    assert result.returncode == 0
    assert result.stderr == ""
    rows = [
        json.loads(line.removeprefix("A211_RESULT "))
        for line in result.stdout.splitlines()
        if line.startswith("A211_RESULT ")
    ]
    assert len(rows) == 256
    assert [row["prefix8"] for row in rows] == order
    assert sum(row["status"] == "sat" for row in rows) == 1
    assert sum(row["status"] == "unsat" for row in rows) == 255
    assert rows[-1]["status"] == "sat"
    assert rows[-1]["model_bits_bit0_through_bit19"][12:] == [1] * 8

    base_unsat_command = command.copy()
    base_unsat_command[2] = str(
        ROOT
        / "tests"
        / "fixtures"
        / "cadical_global_incremental_assumptions_base_unsat.cnf"
    )
    base_unsat = subprocess.run(
        base_unsat_command, text=True, capture_output=True, check=False
    )
    assert base_unsat.returncode == 0
    assert base_unsat.stderr == ""
    base_rows = [
        json.loads(line.removeprefix("A211_RESULT "))
        for line in base_unsat.stdout.splitlines()
        if line.startswith("A211_RESULT ")
    ]
    assert len(base_rows) == 256
    assert all(row["status"] == "unsat" for row in base_rows)
    assert all(row["failed_assumptions"] == [] for row in base_rows)


def test_a211_complete_global_base_preflight_is_exact(
    analysis: dict[str, Any], tmp_path: Path
) -> None:
    identities = MODULE._A204._solver_gates(MODULE._A204._load_protocol_gate())
    sources, manifest, path = MODULE._build_global_base(
        analysis=analysis, identities=identities, directory=tmp_path
    )
    assert len(sources) == 32
    assert manifest["all_32_original_bases_byte_identical"] is True
    assert manifest["all_32_transformed_bases_byte_identical"] is True
    assert manifest["all_32_cells_reconstructed_byte_identically"] is True
    assert manifest["global_original_sha256"] == (
        "581e891ec1433a6075b8de8b15869ae11da590d9e7dfe3f181c5f555c3bb1720"
    )
    assert manifest["global_transformed_sha256"] == (
        "138ceb0a8f47dae3fd2c25e8b93165c08862a3951f7c0b4f4022e47750125e8e"
    )
    assert manifest["clause_length_counts"] == {
        "unit": 6915,
        "binary": 402744,
        "ternary": 324516,
    }
    assert manifest["assumption_variables_absent_from_base_units"] is True
    assert manifest["inverse_reindex_byte_identical"] is True
    assert MODULE._file_sha256(path) == manifest["global_transformed_sha256"]


def _synthetic_mode_stdout(
    *, mode: str, order: list[str], status: str = "unknown"
) -> str:
    lines = []
    cumulative = [0, 0, 0]
    assumption_vars = [225290, 225289, 225288, 225287, 225286, 225285, 225284, 225283]
    for index, prefix8 in enumerate(order):
        before = cumulative.copy()
        delta = [index + 1, 2 * (index + 1), 3 * (index + 1)]
        cumulative = [left + right for left, right in zip(cumulative, delta, strict=True)]
        assumptions = [
            variable if bit == "1" else -variable
            for bit, variable in zip(prefix8, assumption_vars, strict=True)
        ]
        row = {
            "mode": mode,
            "prefix8": prefix8,
            "cell_index": index,
            "status": status,
            "returncode": {"unknown": 0, "unsat": 20}[status],
            "elapsed_seconds": 10.0 if status == "unknown" else 0.001,
            "terminator_fired": status == "unknown",
            "assumptions": assumptions,
            "failed_assumptions": [],
            "model_bits_bit0_through_bit19": [],
            "metric_names": list(MODULE.METRIC_NAMES),
            "metrics_before": before,
            "metrics_after": cumulative,
            "metrics_delta": delta,
            "active_variables": 100,
            "irredundant_clauses": 200,
            "redundant_clauses": index,
        }
        lines.append("A211_RESULT " + json.dumps(row, separators=(",", ":")))
    summary = {
        "signature": "cadical-3.0.0",
        "version": "3.0.0",
        "mode": mode,
        "variables": 232191,
        "cells": 256,
        "sat": 0,
        "unsat": 256 if status == "unsat" else 0,
        "unknown": 256 if status == "unknown" else 0,
        "metric_names": list(MODULE.METRIC_NAMES),
    }
    lines.append("A211_SUMMARY " + json.dumps(summary, separators=(",", ":")))
    return "\n".join(lines) + "\n"


def test_a211_mode_parser_retains_one_complete_cumulative_state(
    analysis: dict[str, Any],
) -> None:
    mode = "reflected_gray8_global_incremental"
    order = analysis["mode_orders"][mode]
    observations, confirmations, summary = MODULE._parse_mode_output(
        mode=mode,
        order=order,
        stdout=_synthetic_mode_stdout(mode=mode, order=order),
        helper_returncode=0,
        externally_timed_out=False,
        challenge=analysis["public_challenge"],
        protocol=analysis["protocol"],
    )
    assert len(observations) == 256
    assert confirmations == []
    assert summary is not None
    assert all(row["status"] == "unknown" for row in observations)
    assert observations[1]["metrics_before"] == observations[0]["metrics_after"]
    assert observations[-1]["metrics_delta"] == {
        "conflicts": 256,
        "decisions": 512,
        "search_propagations": 768,
    }


@pytest.mark.parametrize("corruption", ["timeout", "duplicate"])
def test_a211_any_mode_corruption_invalidates_all_256_cells_atomically(
    analysis: dict[str, Any], corruption: str
) -> None:
    mode = "numeric_global_incremental"
    order = analysis["mode_orders"][mode]
    stdout = ""
    returncode = None
    externally_timed_out = True
    expected_reason = "external_mode_timeout"
    if corruption == "duplicate":
        stdout = _synthetic_mode_stdout(mode=mode, order=order)
        duplicate = next(
            line for line in stdout.splitlines() if line.startswith("A211_RESULT ")
        )
        stdout += duplicate + "\n"
        returncode = 0
        externally_timed_out = False
        expected_reason = "malformed_or_incomplete_helper_output"
    observations, confirmations, _ = MODULE._parse_mode_output(
        mode=mode,
        order=order,
        stdout=stdout,
        helper_returncode=returncode,
        externally_timed_out=externally_timed_out,
        challenge=analysis["public_challenge"],
        protocol=analysis["protocol"],
    )
    assert confirmations == []
    assert len(observations) == 256
    assert all(row["status"] == "invalid" for row in observations)
    assert all(row["invalid_reason"] == expected_reason for row in observations)


def test_a211_mode_parser_accepts_base_unsat_empty_cores(
    analysis: dict[str, Any],
) -> None:
    mode = "numeric_global_incremental"
    order = analysis["mode_orders"][mode]
    observations, confirmations, _ = MODULE._parse_mode_output(
        mode=mode,
        order=order,
        stdout=_synthetic_mode_stdout(mode=mode, order=order, status="unsat"),
        helper_returncode=0,
        externally_timed_out=False,
        challenge=analysis["public_challenge"],
        protocol=analysis["protocol"],
    )
    assert confirmations == []
    assert all(row["status"] == "unsat" for row in observations)
    assert all(row["failed_assumptions"] == [] for row in observations)


def _synthetic_comparative(*, differ: bool = False) -> dict[str, Any]:
    state_rows = []
    order_rows = []
    for index in range(256):
        prefix8 = f"{index:08b}"
        base = {metric: index + 1 for metric in MODULE.METRIC_NAMES}
        changed = {
            metric: value + (1 if differ else 0) for metric, value in base.items()
        }
        state_rows.append(
            {
                "prefix8": prefix8,
                "global_status": "unknown",
                "A210_status": "unknown",
                "global_metrics_delta": changed,
                "A210_local_metrics_delta": base,
            }
        )
        order_rows.append(
            {
                "prefix8": prefix8,
                "numeric_status": "unknown",
                "gray8_status": "unknown",
                "numeric_metrics_delta": base,
                "gray8_metrics_delta": changed,
            }
        )
    return {
        "numeric_global_vs_A210_local_rows": state_rows,
        "global_order_paired_rows": order_rows,
    }


def test_a211_comparison_keeps_unknown_distinct_from_unsat(
    analysis: dict[str, Any],
) -> None:
    observations = [
        {
            "variant": f"{mode}__prefix_{prefix8}",
            "mode": mode,
            "prefix8": prefix8,
            "status": "unknown",
        }
        for mode, order in analysis["mode_orders"].items()
        for prefix8 in order
    ]
    comparison = MODULE._compare(
        execution={
            "mode_runs": [{}, {}],
            "observations": observations,
            "complete_valid_mode_plan_executed": True,
            "complete_valid_cell_plan_executed": True,
        },
        confirmations=[],
        comparative=_synthetic_comparative(),
        modes=list(analysis["mode_orders"]),
    )
    assert comparison["complete_predeclared_execution"] is True
    assert all(
        counts == {"sat": 0, "unsat": 0, "unknown": 256, "invalid": 0}
        for counts in comparison["per_mode_status_counts"].values()
    )
    assert comparison["global_resolution_transfer_retained"] is False
    assert comparison["global_state_transfer_prediction"]["evaluated"] is True
    assert comparison["global_state_transfer_retained"] is False
    assert comparison["true_gray8_order_effect_prediction"]["evaluated"] is True
    assert comparison["true_gray8_order_effect_retained"] is False
    assert comparison["complete_domain_resolution_retained"] is False
    assert MODULE._evidence_stage(comparison) == (
        "ROUND10_GLOBAL_INCREMENTAL_COMPLETE_BOUNDARY_RETAINED"
    )


def test_a211_predictions_are_retained_and_staged_when_valid(
    analysis: dict[str, Any],
) -> None:
    observations = [
        {
            "variant": f"{mode}__prefix_{prefix8}",
            "mode": mode,
            "prefix8": prefix8,
            "status": "unknown",
        }
        for mode, order in analysis["mode_orders"].items()
        for prefix8 in order
    ]
    comparison = MODULE._compare(
        execution={
            "mode_runs": [{}, {}],
            "observations": observations,
            "complete_valid_mode_plan_executed": True,
            "complete_valid_cell_plan_executed": True,
        },
        confirmations=[],
        comparative=_synthetic_comparative(differ=True),
        modes=list(analysis["mode_orders"]),
    )
    assert comparison["global_state_transfer_retained"] is True
    assert comparison["true_gray8_order_effect_retained"] is True
    assert comparison["global_state_transfer_prediction"]["metric_difference_prefix_counts"] == {
        "conflicts": 256,
        "decisions": 256,
    }
    assert MODULE._evidence_stage(comparison) == (
        "ROUND10_GLOBAL_INCREMENTAL_STATE_AND_ORDER_EFFECT_RETAINED"
    )


def test_a211_invalid_mode_cannot_be_labeled_complete(
    analysis: dict[str, Any],
) -> None:
    modes = list(analysis["mode_orders"])
    observations = []
    for mode, order in analysis["mode_orders"].items():
        status = "invalid" if mode == modes[0] else "unknown"
        observations.extend(
            {
                "variant": f"{mode}__prefix_{prefix8}",
                "mode": mode,
                "prefix8": prefix8,
                "status": status,
            }
            for prefix8 in order
        )
    invalid_comparative = _synthetic_comparative(differ=True)
    for row in invalid_comparative["numeric_global_vs_A210_local_rows"]:
        row["global_status"] = "invalid"
        row["global_metrics_delta"] = {}
    for row in invalid_comparative["global_order_paired_rows"]:
        row["numeric_status"] = "invalid"
        row["numeric_metrics_delta"] = {}
    comparison = MODULE._compare(
        execution={
            "mode_runs": [{}, {}],
            "observations": observations,
            "complete_valid_mode_plan_executed": False,
            "complete_valid_cell_plan_executed": False,
        },
        confirmations=[],
        comparative=invalid_comparative,
        modes=modes,
    )
    assert comparison["mode_plan_materialized"] is True
    assert comparison["cell_plan_materialized"] is True
    assert comparison["complete_predeclared_execution"] is False
    assert comparison["complete_domain_covered_once_per_mode"] is False
    assert comparison["global_state_transfer_prediction"]["evaluated"] is False
    assert comparison["true_gray8_order_effect_prediction"]["evaluated"] is False
    assert MODULE._evidence_stage(comparison) == (
        "ROUND10_GLOBAL_INCREMENTAL_INVALID_EXECUTION_RETAINED"
    )


def test_a211_protocol_is_canonical_json() -> None:
    raw = PROTOCOL_PATH.read_bytes()
    assert json.loads(raw)["attempt_id"] == "A211"
    assert raw.endswith(b"\n")

from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest

ROOT = Path(__file__).parents[1]
MODULE_PATH = (
    ROOT
    / "research"
    / "experiments"
    / "chacha20_round20_global_incremental_transfer.py"
)
SPEC = importlib.util.spec_from_file_location(
    "chacha20_round20_global_incremental_transfer_tested", MODULE_PATH
)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)

PROTOCOL_PATH = ROOT / "research" / "configs" / MODULE.PROTOCOL_FILENAME
RESULT_PATH = ROOT / "research" / "results" / "v1" / MODULE.RESULT_FILENAME
CAUSAL_PATH = ROOT / "research" / "results" / "v1" / MODULE.CAUSAL_FILENAME


@pytest.fixture(scope="module")
def analysis() -> dict[str, Any]:
    return MODULE.analyze()


@pytest.fixture(scope="module")
def exact_preflight(
    analysis: dict[str, Any], tmp_path_factory: pytest.TempPathFactory
) -> dict[str, Any]:
    directory = tmp_path_factory.mktemp("r20-global-transfer-preflight")
    mapping, base_path = MODULE._derive_signed_mapping(
        formula=analysis["source_formula"],
        protocol=analysis["protocol"],
        directory=directory,
    )
    bfs, transformed_path = MODULE._build_R20_specific_global_base(
        base_path=base_path,
        mapping_manifest=mapping,
        protocol=analysis["protocol"],
        directory=directory,
    )
    return {
        "mapping": mapping,
        "base_path": base_path,
        "bfs": bfs,
        "transformed_path": transformed_path,
    }


def test_r20_transfer_protocol_anchors_and_information_boundary_are_exact(
    analysis: dict[str, Any],
) -> None:
    assert MODULE._file_sha256(PROTOCOL_PATH) == MODULE.PROTOCOL_SHA256
    assert analysis["solver_execution_started"] is False
    assert analysis["public_challenge_sha256"] == (
        "98d375fb9432e17b9a701137617a6384ebc60a0ac9054ec203f2364a5338d762"
    )
    anchors = analysis["anchor_gates"]
    assert anchors["phase2_complete_32_unknown_boundary_retained"] is True
    assert anchors["A184_prior_stronger_fullround_width40_recovery_retained"] is True
    assert anchors["phase2_causal_provenance_verified"] is True
    assert anchors["A184_causal_provenance_verified"] is True
    boundary = analysis["protocol"]["information_boundary"]
    assert boundary["unknown_assignment_available_to_runner_or_helper_before_execution"] is False
    assert boundary["correct_prefix_known_before_execution"] is False
    assert boundary["any_R20_global_incremental_helper_solve_outcome_known_before_freeze"] is False
    assert boundary["early_stop_permitted"] is False


def test_r20_transfer_source_mapping_and_R20_specific_order_are_frozen(
    analysis: dict[str, Any],
) -> None:
    protocol = analysis["protocol"]
    source = protocol["source_formula_and_CNF_preflight"]
    assert len(analysis["source_formula"].encode()) == source["source_formula_bytes"]
    assert MODULE._sha256(analysis["source_formula"].encode()) == source["source_formula_sha256"]
    signed = protocol["signed_literal_derivation"]
    assert signed["probe_count"] == 40
    assert signed["all_40_exact_one_unit_delta_gates_passed_before_freeze"] is True
    assert signed["all_20_opposite_polarity_gates_passed_before_freeze"] is True
    assert signed["source_one_literals_bit0_through_bit19"][-2:] == [55, 60]
    order = protocol["R20_specific_BFS_far_preflight"]
    assert order["explicitly_not_reused_from_R10"] is True
    assert order["bijection_proved"] is True
    assert order["inverse_reindex_byte_identical"] is True
    assert order["transformed_prefix_one_literals_bits19_through12"] == [
        67917,
        67916,
        67915,
        67914,
        67913,
        67912,
        67911,
        67910,
    ]


def test_r20_transfer_all_40_signed_probes_rebuild_exactly(
    exact_preflight: dict[str, Any],
) -> None:
    mapping = exact_preflight["mapping"]
    assert mapping["probe_count"] == 40
    assert len(mapping["probe_rows"]) == 40
    assert all(row["exactly_one_unit_clause_added"] for row in mapping["probe_rows"])
    assert all(row["returncode"] == 0 for row in mapping["probe_rows"])
    assert all(row["externally_timed_out"] is False for row in mapping["probe_rows"])
    assert all(row["export_status"] == "unknown" for row in mapping["probe_rows"])
    assert mapping["all_exact_one_unit_delta_gates_passed"] is True
    assert mapping["all_opposite_polarity_gates_passed"] is True
    assert mapping["source_one_literals_bit0_through_bit19"] == [
        16,
        15,
        18,
        20,
        22,
        24,
        26,
        28,
        30,
        32,
        34,
        36,
        38,
        40,
        42,
        44,
        46,
        48,
        55,
        60,
    ]


def test_r20_transfer_R20_specific_BFS_far_inverse_is_byte_exact(
    exact_preflight: dict[str, Any],
) -> None:
    bfs = exact_preflight["bfs"]
    assert bfs["order_sha256"] == (
        "e397b58fdaee44d6306f714ef9b280dc547019662f0ef4ac9cfbd2b60114dfee"
    )
    assert bfs["old_to_new_sha256"] == (
        "13a9f01c6295baae836025be550f283265c313e418d45afcd6c9560839787455"
    )
    assert bfs["transformed_sha256"] == (
        "2c33afd9f78ed3e1a2180313571918af51d5eaf2e1cd3b09fb588b86745f19b1"
    )
    assert bfs["bijection_proved"] is True
    assert bfs["inverse_reindex_byte_identical"] is True
    assert bfs["transformed_assumption_variables_absent_from_base_units"] is True
    assert MODULE._file_sha256(exact_preflight["transformed_path"]) == bfs[
        "transformed_sha256"
    ]


def test_r20_transfer_complete_numeric_and_true_gray8_orders_are_frozen(
    analysis: dict[str, Any],
) -> None:
    orders = analysis["mode_orders"]
    numeric = orders["numeric_global_incremental"]
    gray = orders["reflected_gray8_global_incremental"]
    assert len(numeric) == len(gray) == 256
    assert numeric == [f"{value:08b}" for value in range(256)]
    assert gray == [f"{value ^ (value >> 1):08b}" for value in range(256)]
    assert set(numeric) == set(gray)
    assert all(
        sum(left != right for left, right in zip(previous, current, strict=True)) == 1
        for previous, current in zip(gray, gray[1:], strict=False)
    )


def test_r20_transfer_analyze_only_launches_no_solver() -> None:
    result = subprocess.run(
        [sys.executable, str(MODULE_PATH), "--analyze-only"],
        cwd=ROOT,
        text=True,
        capture_output=True,
        check=False,
    )
    assert result.returncode == 0
    assert result.stderr == ""
    summary = json.loads(result.stdout)
    assert summary["solver_execution_started"] is False
    assert summary["cell_observations"] == 512
    assert summary["seconds_per_cell"] == 10


def test_r20_transfer_signed_native_helper_handles_negative_one_literals(
    analysis: dict[str, Any], tmp_path: Path
) -> None:
    helper, compilation = MODULE._compile_helper(
        analysis["protocol"], directory=tmp_path
    )
    assert compilation["binary_sha256"] == analysis["protocol"]["native_helper"][
        "compiled_binary_sha256"
    ]
    order = analysis["mode_orders"]["numeric_global_incremental"]
    command = [
        str(helper),
        "--cnf",
        str(ROOT / "tests" / "fixtures" / "cadical_global_incremental_assumptions_toy.cnf"),
        "--mode",
        "toy_signed_negative",
        "--assumption-one-literals",
        "-20,-19,-18,-17,-16,-15,-14,-13",
        "--model-one-literals",
        ",".join(str(-value) for value in range(1, 21)),
        "--cell-order",
        ",".join(order),
        "--seconds",
        "0.01",
    ]
    result = subprocess.run(command, text=True, capture_output=True, check=False)
    assert result.returncode == 0
    assert result.stderr == ""
    rows = [
        json.loads(line.removeprefix("R20_XFER_RESULT "))
        for line in result.stdout.splitlines()
        if line.startswith("R20_XFER_RESULT ")
    ]
    assert len(rows) == 256
    assert sum(row["status"] == "sat" for row in rows) == 1
    assert sum(row["status"] == "unsat" for row in rows) == 255
    assert rows[0]["prefix8"] == "00000000"
    assert rows[0]["status"] == "sat"
    assert rows[0]["model_bits_bit0_through_bit19"][12:] == [0] * 8


def test_r20_transfer_load_only_RSS_policy_calls_no_solver(
    analysis: dict[str, Any], exact_preflight: dict[str, Any], tmp_path: Path
) -> None:
    helper, _ = MODULE._compile_helper(analysis["protocol"], directory=tmp_path)
    gate = MODULE._load_only_RSS_gate(
        base_path=exact_preflight["transformed_path"],
        helper_path=helper,
        protocol=analysis["protocol"],
    )
    assert gate["returncode"] == 0
    assert gate["load_record"]["variables"] == 68783
    assert gate["load_only_solve_calls"] == 0
    assert gate["selected_max_parallel_mode_runs"] in {1, 2}
    assert gate["selected_execution"] in {"sequential", "concurrent"}
    assert gate["two_copy_margin_safe"] == (
        gate["selected_max_parallel_mode_runs"] == 2
    )


def _synthetic_mode_stdout(
    *, analysis: dict[str, Any], mode: str, order: list[str]
) -> str:
    cumulative = [0, 0, 0]
    assumption_one = analysis["protocol"]["R20_specific_BFS_far_preflight"][
        "transformed_prefix_one_literals_bits19_through12"
    ]
    lines = []
    for index, prefix8 in enumerate(order):
        before = cumulative.copy()
        delta = [index + 1, 2 * index + 1, 3 * index + 1]
        cumulative = [left + right for left, right in zip(before, delta, strict=True)]
        assumptions = [
            literal if bit == "1" else -literal
            for bit, literal in zip(prefix8, assumption_one, strict=True)
        ]
        row = {
            "mode": mode,
            "prefix8": prefix8,
            "cell_index": index,
            "status": "unknown",
            "returncode": 0,
            "elapsed_seconds": 10.0,
            "terminator_fired": True,
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
        lines.append("R20_XFER_RESULT " + json.dumps(row, separators=(",", ":")))
    summary = {
        "signature": "cadical-3.0.0",
        "version": "3.0.0",
        "mode": mode,
        "variables": 68783,
        "cells": 256,
        "sat": 0,
        "unsat": 0,
        "unknown": 256,
        "metric_names": list(MODULE.METRIC_NAMES),
    }
    lines.append("R20_XFER_SUMMARY " + json.dumps(summary, separators=(",", ":")))
    return "\n".join(lines) + "\n"


def test_r20_transfer_parser_retains_dynamic_variable_count_and_cumulative_state(
    analysis: dict[str, Any],
) -> None:
    mode = "reflected_gray8_global_incremental"
    order = analysis["mode_orders"][mode]
    observations, confirmations, summary = MODULE._parse_mode_output(
        mode=mode,
        order=order,
        stdout=_synthetic_mode_stdout(analysis=analysis, mode=mode, order=order),
        helper_returncode=0,
        externally_timed_out=False,
        challenge=analysis["public_challenge"],
        protocol=analysis["protocol"],
    )
    assert confirmations == []
    assert summary is not None and summary["variables"] == 68783
    assert len(observations) == 256
    assert all(row["status"] == "unknown" for row in observations)
    assert observations[1]["metrics_before"] == observations[0]["metrics_after"]


def test_r20_transfer_unknown_remains_distinct_from_unsat(
    analysis: dict[str, Any],
) -> None:
    observations = [
        {
            "variant": f"{mode}__prefix_{prefix8}",
            "mode": mode,
            "prefix8": prefix8,
            "cell_index": index,
            "status": "unknown",
            "metrics_delta": {
                metric: int(prefix8, 2) + 1 for metric in MODULE.METRIC_NAMES
            },
        }
        for mode, order in analysis["mode_orders"].items()
        for index, prefix8 in enumerate(order)
    ]
    comparative = MODULE._comparative_metrics(observations, analysis["mode_orders"])
    comparison = MODULE._compare(
        execution={
            "mode_runs": [{}, {}],
            "observations": observations,
            "complete_valid_mode_plan_executed": True,
            "complete_valid_cell_plan_executed": True,
        },
        confirmations=[],
        comparative=comparative,
        modes=list(analysis["mode_orders"]),
    )
    assert comparison["complete_predeclared_execution"] is True
    assert comparison["global_terminal_transfer_retained"] is False
    assert comparison["complete_domain_resolution_retained"] is False
    assert comparison["unknown_is_not_unsat"] is True
    assert MODULE._evidence_stage(comparison) == (
        "FULLROUND_R20_GLOBAL_INCREMENTAL_COMPLETE_BOUNDARY_RETAINED"
    )


def test_r20_transfer_invalid_mode_is_retained_without_metric_crash(
    analysis: dict[str, Any],
) -> None:
    observations = []
    for mode, order in analysis["mode_orders"].items():
        for index, prefix8 in enumerate(order):
            if mode == "numeric_global_incremental":
                row = MODULE._invalid_cell(
                    mode=mode,
                    prefix8=prefix8,
                    index=index,
                    reason="synthetic_mode_timeout",
                )
            else:
                row = {
                    "variant": f"{mode}__prefix_{prefix8}",
                    "mode": mode,
                    "prefix8": prefix8,
                    "cell_index": index,
                    "status": "unknown",
                    "metrics_delta": {
                        metric: int(prefix8, 2) + 1 for metric in MODULE.METRIC_NAMES
                    },
                }
            observations.append(row)
    comparative = MODULE._comparative_metrics(observations, analysis["mode_orders"])
    comparison = MODULE._compare(
        execution={
            "mode_runs": [{}, {}],
            "observations": observations,
            "complete_valid_mode_plan_executed": False,
            "complete_valid_cell_plan_executed": False,
        },
        confirmations=[],
        comparative=comparative,
        modes=list(analysis["mode_orders"]),
    )
    assert comparison["complete_predeclared_execution"] is False
    assert comparison["per_mode_status_counts"]["numeric_global_incremental"] == {
        "sat": 0,
        "unsat": 0,
        "unknown": 0,
        "invalid": 256,
    }
    assert comparison["true_gray8_order_effect_prediction"]["evaluated"] is False
    assert MODULE._evidence_stage(comparison) == (
        "FULLROUND_R20_GLOBAL_INCREMENTAL_INVALID_EXECUTION_RETAINED"
    )


def test_r20_transfer_retained_result_reopens_if_present() -> None:
    if not RESULT_PATH.exists() or not CAUSAL_PATH.exists():
        pytest.skip("R20 transfer execution is still running")
    payload = json.loads(RESULT_PATH.read_bytes())
    reader = MODULE.CryptoCausalReader(CAUSAL_PATH)
    assert payload["public_challenge_sha256"] == (
        "98d375fb9432e17b9a701137617a6384ebc60a0ac9054ec203f2364a5338d762"
    )
    assert payload["comparisons"]["unknown_is_not_unsat"] is True
    assert payload["comparisons"]["first_fullround_recovery_claimed"] is False
    assert payload["comparisons"]["prior_stronger_A184_fullround_width40_recovery_retained"] is True
    assert payload["execution"]["early_stop_used"] is False
    assert len(payload["execution"]["observations"]) == 512
    assert reader.file_sha256 == payload["causal"]["file_sha256"]
    assert reader.graph_sha256 == payload["causal"]["graph_sha256"]
    assert reader.verify_provenance()

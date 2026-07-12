from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest

ROOT = Path(__file__).parents[1]
MODULE_PATH = ROOT / "research" / "experiments" / "chacha20_round10_incremental_sibling_learning.py"
SPEC = importlib.util.spec_from_file_location(
    "chacha20_round10_incremental_sibling_learning_tested", MODULE_PATH
)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)

RESULTS = ROOT / "research" / "results" / "v1"
PROTOCOL_PATH = ROOT / "research" / "configs" / MODULE.PROTOCOL_FILENAME
RUNNER_SHA256 = "48038ff750c5ca6a961fb7bc60f0d1c18b2f6910ed396bdbfc03c63327676378"
RETAINED_RESULT_SHA256 = "1765ddabcec9c35d778bbb6e4c4e4aadc66277e7d9255d1f2a8ffdcd7b8152ce"
RETAINED_CAUSAL_SHA256 = "ff7f2019001d4c0e8478dd35476d975dde5b6faa1110c0383fbffba9091a6586"
RETAINED_CAUSAL_GRAPH_SHA256 = (
    "cc450abd4035fc9f823234a8001a37f59cd1a7ec8a6e2839a366d8b34a229363"
)
FROZEN_NATIVE_TOOLCHAIN_AVAILABLE = (
    sys.platform == "darwin"
    and Path("/usr/bin/clang++").is_file()
    and Path("/opt/homebrew/include/cadical.hpp").is_file()
    and Path("/opt/homebrew/lib/libcadical.a").is_file()
)
FROZEN_EXPORT_TOOLCHAIN_AVAILABLE = (
    sys.platform == "darwin" and Path("/opt/homebrew/bin/bitwuzla").is_file()
)


@pytest.fixture(scope="module")
def analysis() -> dict[str, Any]:
    return MODULE.analyze(RESULTS)


def test_a210_protocol_runner_anchor_and_toolchain_are_exact(
    analysis: dict[str, Any],
) -> None:
    assert MODULE._file_sha256(PROTOCOL_PATH) == MODULE.PROTOCOL_SHA256
    assert MODULE._file_sha256(MODULE_PATH) == RUNNER_SHA256
    assert analysis["solver_execution_started"] is False
    assert analysis["anchor_gates"] == {
        "A209_result_sha256": MODULE.A209_RESULT_SHA256,
        "A209_causal_sha256": MODULE.A209_CAUSAL_SHA256,
        "A209_causal_graph_sha256": MODULE.A209_CAUSAL_GRAPH_SHA256,
        "A209_causal_provenance_verified": True,
        "A209_complete_256_unknown_boundary_retained": True,
        "A209_systematic_decision_rich_phase_reset_retained": True,
    }
    toolchain = analysis["toolchain_gates"]
    assert toolchain["source_sha256"] == (
        "d5742b03db88677dee7fc52d3fa93e994153d909de0edc574e1ea611a6ef69c6"
    )
    assert toolchain["compiled_binary_expected_sha256"] == (
        "b214c67932ff7092f802976fa132977a9b5447d0d05f76c64da0dd83d307301e"
    )
    assert toolchain["round10_helper_execution_started"] is False


def test_a210_selection_and_information_boundary_are_frozen(
    analysis: dict[str, Any],
) -> None:
    protocol = analysis["protocol"]
    selection = protocol["selection_basis"]
    assert selection["A209_status_counts"] == {
        "sat": 0,
        "unsat": 0,
        "unknown": 256,
        "invalid": 0,
    }
    assert selection["A209_compute_normalized_child_over_parent"]["decisions"] == (
        2.7925087307017944
    )
    assert (
        selection["A209_compute_normalized_child_over_parent"]["decisions_per_propagation"]
        == 1.7292295808776634
    )
    assert selection["formula_transfer_family"] == "T01_ordered_noncommutative_update_composition"
    assert selection["any_A210_round10_incremental_outcome_known_at_selection"] is False
    boundary = protocol["information_boundary"]
    assert boundary["any_A210_round10_helper_or_solver_outcome_known_before_freeze"] is False
    assert boundary["unknown_assignment_in_protocol_source_helper_or_mapping"] is False
    assert boundary["unknown_assignment_available_to_runner_or_helper_before_execution"] is False
    assert boundary["correct_parent_or_child_prefix_known_before_execution"] is False
    assert boundary["numeric_outcomes_used_to_change_gray_execution"] is False
    assert boundary["early_stop_permitted"] is False


def test_a210_complete_two_mode_factorial_is_frozen(analysis: dict[str, Any]) -> None:
    protocol = analysis["protocol"]
    modes = protocol["incremental_modes"]
    assert modes == [
        {
            "name": "numeric_incremental",
            "child_order": ["000", "001", "010", "011", "100", "101", "110", "111"],
        },
        {
            "name": "gray_incremental",
            "child_order": ["000", "001", "011", "010", "110", "111", "101", "100"],
        },
    ]
    assert MODULE._canonical_sha256(modes) == protocol["incremental_mode_manifest_sha256"]
    parent_plan = MODULE._mode_plan(protocol)
    cell_plan = MODULE._cell_plan(protocol)
    assert len(parent_plan) == 64
    assert len(cell_plan) == 512
    assert len({(row["mode"], row["parent_prefix5"]) for row in parent_plan}) == 64
    assert len({(row["mode"], row["prefix8"]) for row in cell_plan}) == 512
    assert (
        MODULE._canonical_sha256(parent_plan)
        == protocol["execution_plan"]["parent_run_order_sha256"]
    )
    assert (
        MODULE._canonical_sha256(cell_plan)
        == protocol["execution_plan"]["child_observation_order_sha256"]
    )
    plan = protocol["execution_plan"]
    assert plan["complete_domain_covered_once_per_mode"] is True
    assert plan["solver_time_limit_seconds_per_child"] == 10
    assert plan["external_timeout_seconds_per_parent_run"] == 95
    assert plan["max_parallel_parent_runs"] == 4
    assert plan["wave_count"] == 16
    assert plan["all_eight_children_required_after_any_intermediate_status"] is True
    assert plan["early_stop_permitted"] is False


def test_a210_mapping_and_metric_scope_are_exact(analysis: dict[str, Any]) -> None:
    protocol = analysis["protocol"]
    mapping = protocol["assumption_and_model_mapping"]
    assert mapping["child_bits_descending"] == [14, 13, 12]
    assert mapping["transformed_child_one_literals_descending"] == [225285, 225284, 225283]
    assert mapping["transformed_model_one_literals_bit0_through_bit14"][-3:] == [
        225283,
        225284,
        225285,
    ]
    helper = protocol["native_helper"]
    assert helper["API_metric_names"] == [
        "conflicts",
        "decisions",
        "search_propagations",
    ]
    assert helper["A209_metric_comparison_scope"] == ["conflicts", "decisions"]
    assert helper["search_propagations_comparison_scope"] == (
        "within_A210_numeric_vs_Gray_only_not_against_A209_CLI_total_propagations"
    )


def test_a210_retained_complete_boundary_and_causal_are_exact() -> None:
    result_path = RESULTS / MODULE.RESULT_FILENAME
    causal_path = RESULTS / MODULE.CAUSAL_FILENAME
    assert MODULE._file_sha256(result_path) == RETAINED_RESULT_SHA256
    assert MODULE._file_sha256(causal_path) == RETAINED_CAUSAL_SHA256
    result = json.loads(result_path.read_bytes())
    assert result["evidence_stage"] == "ROUND10_INCREMENTAL_COMPLETE_BOUNDARY_RETAINED"
    assert result["comparisons"]["per_mode_status_counts"] == {
        "numeric_incremental": {"sat": 0, "unsat": 0, "unknown": 256, "invalid": 0},
        "gray_incremental": {"sat": 0, "unsat": 0, "unknown": 256, "invalid": 0},
    }
    assert result["comparisons"]["parent_run_count"] == 64
    assert result["comparisons"]["child_observation_count"] == 512
    assert result["comparisons"]["early_stop_used"] is False
    assert result["confirmations"] == []

    hash_pairs = [
        ("selection_basis", "selection_basis_sha256"),
        ("formula_plan", "formula_plan_sha256"),
        ("native_helper", "native_helper_sha256"),
        ("source_exports", "source_exports_sha256"),
        ("parent_transform_manifest", "parent_transform_manifest_sha256"),
        ("assumption_and_model_mapping", "mapping_sha256"),
        ("incremental_modes", "incremental_modes_sha256"),
        ("execution_plan", "execution_plan_sha256"),
        ("execution", "execution_sha256"),
        ("confirmations", "confirmation_sha256"),
        ("comparative_metrics", "comparative_metrics_sha256"),
        ("comparisons", "comparison_sha256"),
    ]
    for payload_key, digest_key in hash_pairs:
        assert MODULE._canonical_sha256(result[payload_key]) == result[digest_key]

    groups: dict[tuple[str, str], list[dict[str, Any]]] = {}
    for row in result["execution"]["observations"]:
        groups.setdefault((row["mode"], row["parent_prefix5"]), []).append(row)
    assert len(groups) == 64
    for rows in groups.values():
        ordered = sorted(rows, key=lambda row: row["child_index"])
        assert len(ordered) == 8
        assert ordered[0]["metrics_delta"]["decisions"] > max(
            row["metrics_delta"]["decisions"] for row in ordered[1:]
        )
        assert ordered[0]["metrics_delta"]["conflicts"] > max(
            row["metrics_delta"]["conflicts"] for row in ordered[1:]
        )

    reader = MODULE.CryptoCausalReader(causal_path)
    assert reader.file_sha256 == RETAINED_CAUSAL_SHA256
    assert reader.graph_sha256 == RETAINED_CAUSAL_GRAPH_SHA256
    assert len(reader.triplets(include_inferred=False)) == 8
    assert reader.verify_provenance() is True


@pytest.mark.skipif(
    not FROZEN_NATIVE_TOOLCHAIN_AVAILABLE,
    reason="exact A210 Apple-Clang/CaDiCaL static toolchain is not installed",
)
def test_a210_native_helper_compiles_and_passes_toy_factorial(
    analysis: dict[str, Any], tmp_path: Path
) -> None:
    helper, compilation = MODULE._compile_helper(
        analysis["protocol"],
        repo_root=ROOT,
        directory=tmp_path,
    )
    assert compilation["returncode"] == 0
    assert compilation["binary_sha256"] == (
        "b214c67932ff7092f802976fa132977a9b5447d0d05f76c64da0dd83d307301e"
    )
    command = [
        str(helper),
        "--cnf",
        str(ROOT / "tests" / "fixtures" / "cadical_incremental_assumptions_toy.cnf"),
        "--prefix5",
        "00000",
        "--assumption-vars",
        "1,2,3",
        "--model-vars",
        "1,2,3,4,5,6,7,8,9,10,11,12,13,14,15",
        "--child-order",
        "000,001,011,010,110,111,101,100",
        "--seconds",
        "0.1",
    ]
    result = subprocess.run(command, text=True, capture_output=True, check=False)
    assert result.returncode == 0
    assert result.stderr == ""
    rows = [
        json.loads(line.removeprefix("A210_RESULT "))
        for line in result.stdout.splitlines()
        if line.startswith("A210_RESULT ")
    ]
    summary = json.loads(
        next(
            line.removeprefix("A210_SUMMARY ")
            for line in result.stdout.splitlines()
            if line.startswith("A210_SUMMARY ")
        )
    )
    assert len(rows) == 8
    assert [row["child"] for row in rows] == [
        "000",
        "001",
        "011",
        "010",
        "110",
        "111",
        "101",
        "100",
    ]
    assert rows[0]["status"] == "unsat"
    assert all(row["status"] == "sat" for row in rows[1:])
    assert all(row["metric_names"] == list(MODULE.METRIC_NAMES) for row in rows)
    assert summary["sat"] == 7
    assert summary["unsat"] == 1
    assert summary["unknown"] == 0

    base_unsat_command = command.copy()
    base_unsat_command[2] = str(
        ROOT / "tests" / "fixtures" / "cadical_incremental_assumptions_base_unsat.cnf"
    )
    base_unsat = subprocess.run(
        base_unsat_command,
        text=True,
        capture_output=True,
        check=False,
    )
    assert base_unsat.returncode == 0
    assert base_unsat.stderr == ""
    base_rows = [
        json.loads(line.removeprefix("A210_RESULT "))
        for line in base_unsat.stdout.splitlines()
        if line.startswith("A210_RESULT ")
    ]
    assert len(base_rows) == 8
    assert all(row["status"] == "unsat" for row in base_rows)
    assert all(row["failed_assumptions"] == [] for row in base_rows)


@pytest.mark.skipif(
    not FROZEN_EXPORT_TOOLCHAIN_AVAILABLE,
    reason="exact A210 Bitwuzla CNF-export toolchain is not installed",
)
def test_a210_parent_transform_manifest_preflight_is_exact(
    analysis: dict[str, Any], tmp_path: Path
) -> None:
    identities = MODULE._A204._solver_gates(MODULE._A204._load_protocol_gate())
    sources, manifest, paths = MODULE._build_parent_transforms(
        analysis=analysis,
        identities=identities,
        directory=tmp_path,
    )
    assert len(sources) == 32
    assert len(manifest) == 32
    assert len(paths) == 32
    assert MODULE._canonical_sha256(manifest) == (
        "3fc86268d53150d75c90a5d69138801788a49f0001b39fbc5cb902bcb2e8baa0"
    )
    assert len({row["transformed_parent_cnf_sha256"] for row in manifest}) == 32
    assert {row["transformed_normalized_sha256"] for row in manifest} == {
        "22c9683b7ae6423ccb812735564581a04c7a819719362857acb03d283544157e"
    }
    assert all(row["inverse_byte_identical"] is True for row in manifest)


def _synthetic_parent_stdout(mode: dict[str, Any], parent: str) -> str:
    lines = []
    cumulative = [0, 0, 0]
    assumption_vars = [225285, 225284, 225283]
    for index, child in enumerate(mode["child_order"]):
        before = cumulative.copy()
        delta = [index + 1, 2 * (index + 1), 3 * (index + 1)]
        cumulative = [left + right for left, right in zip(cumulative, delta, strict=True)]
        assumptions = [
            variable if bit == "1" else -variable
            for bit, variable in zip(child, assumption_vars, strict=True)
        ]
        row = {
            "prefix5": parent,
            "child": child,
            "child_index": index,
            "status": "unknown",
            "returncode": 0,
            "elapsed_seconds": 10.0,
            "terminator_fired": True,
            "assumptions": assumptions,
            "failed_assumptions": [],
            "model_bits_bit0_through_bit14": [],
            "metric_names": list(MODULE.METRIC_NAMES),
            "metrics_before": before,
            "metrics_after": cumulative,
            "metrics_delta": delta,
            "active_variables": 100,
            "irredundant_clauses": 200,
            "redundant_clauses": index,
        }
        lines.append("A210_RESULT " + json.dumps(row, separators=(",", ":")))
    summary = {
        "signature": "cadical-3.0.0",
        "version": "3.0.0",
        "prefix5": parent,
        "variables": 232191,
        "children": 8,
        "sat": 0,
        "unsat": 0,
        "unknown": 8,
        "metric_names": list(MODULE.METRIC_NAMES),
    }
    lines.append("A210_SUMMARY " + json.dumps(summary, separators=(",", ":")))
    return "\n".join(lines) + "\n"


def test_a210_parent_parser_retains_incremental_cumulative_state(
    analysis: dict[str, Any],
) -> None:
    mode = analysis["protocol"]["incremental_modes"][1]
    observations, confirmations, summary = MODULE._parse_parent_output(
        mode=mode,
        parent_prefix5="10101",
        stdout=_synthetic_parent_stdout(mode, "10101"),
        helper_returncode=0,
        externally_timed_out=False,
        challenge=analysis["public_challenge"],
    )
    assert len(observations) == 8
    assert confirmations == []
    assert summary is not None
    assert all(row["status"] == "unknown" for row in observations)
    assert all(row["terminator_fired"] is True for row in observations)
    assert observations[1]["metrics_before"] == observations[0]["metrics_after"]
    assert observations[-1]["metrics_delta"] == {
        "conflicts": 8,
        "decisions": 16,
        "search_propagations": 24,
    }


def test_a210_invalid_parent_output_yields_complete_invalid_children(
    analysis: dict[str, Any],
) -> None:
    mode = analysis["protocol"]["incremental_modes"][0]
    observations, confirmations, summary = MODULE._parse_parent_output(
        mode=mode,
        parent_prefix5="00000",
        stdout="",
        helper_returncode=None,
        externally_timed_out=True,
        challenge=analysis["public_challenge"],
    )
    assert len(observations) == 8
    assert confirmations == []
    assert summary is None
    assert all(row["status"] == "invalid" for row in observations)
    assert all(row["invalid_reason"] == "external_parent_timeout" for row in observations)


def test_a210_duplicate_child_invalidates_parent_atomically(
    analysis: dict[str, Any],
) -> None:
    mode = analysis["protocol"]["incremental_modes"][1]
    valid_stdout = _synthetic_parent_stdout(mode, "10101")
    duplicate = next(line for line in valid_stdout.splitlines() if line.startswith("A210_RESULT "))
    corrupted = valid_stdout + duplicate + "\n"
    observations, confirmations, summary = MODULE._parse_parent_output(
        mode=mode,
        parent_prefix5="10101",
        stdout=corrupted,
        helper_returncode=0,
        externally_timed_out=False,
        challenge=analysis["public_challenge"],
    )
    assert summary is not None
    assert confirmations == []
    assert len(observations) == 8
    assert all(row["status"] == "invalid" for row in observations)
    assert all(
        row["invalid_reason"] == "malformed_or_incomplete_helper_output" for row in observations
    )


def test_a210_parent_parser_accepts_base_unsat_empty_cores(
    analysis: dict[str, Any],
) -> None:
    mode = analysis["protocol"]["incremental_modes"][0]
    lines = []
    for index, child in enumerate(mode["child_order"]):
        assumptions = [
            variable if bit == "1" else -variable
            for bit, variable in zip(child, [225285, 225284, 225283], strict=True)
        ]
        row = {
            "prefix5": "11111",
            "child": child,
            "child_index": index,
            "status": "unsat",
            "returncode": 20,
            "elapsed_seconds": 0.001,
            "terminator_fired": False,
            "assumptions": assumptions,
            "failed_assumptions": [],
            "model_bits_bit0_through_bit14": [],
            "metric_names": list(MODULE.METRIC_NAMES),
            "metrics_before": [0, 0, 0],
            "metrics_after": [0, 0, 0],
            "metrics_delta": [0, 0, 0],
            "active_variables": 0,
            "irredundant_clauses": 0,
            "redundant_clauses": 0,
        }
        lines.append("A210_RESULT " + json.dumps(row, separators=(",", ":")))
    summary = {
        "signature": "cadical-3.0.0",
        "version": "3.0.0",
        "prefix5": "11111",
        "variables": 232191,
        "children": 8,
        "sat": 0,
        "unsat": 8,
        "unknown": 0,
        "metric_names": list(MODULE.METRIC_NAMES),
    }
    lines.append("A210_SUMMARY " + json.dumps(summary, separators=(",", ":")))
    observations, confirmations, parsed_summary = MODULE._parse_parent_output(
        mode=mode,
        parent_prefix5="11111",
        stdout="\n".join(lines) + "\n",
        helper_returncode=0,
        externally_timed_out=False,
        challenge=analysis["public_challenge"],
    )
    assert confirmations == []
    assert parsed_summary == summary
    assert len(observations) == 8
    assert all(row["status"] == "unsat" for row in observations)
    assert all(row["failed_assumptions"] == [] for row in observations)


def test_a210_comparison_keeps_unknown_distinct_from_unsat() -> None:
    protocol = json.loads(PROTOCOL_PATH.read_bytes())
    observations = [
        {
            "variant": f"{row['mode']}__prefix_{row['prefix8']}",
            "mode": row["mode"],
            "prefix8": row["prefix8"],
            "status": "unknown",
        }
        for row in MODULE._cell_plan(protocol)
    ]
    execution = {
        "parent_runs": [{} for _ in range(64)],
        "observations": observations,
    }
    comparison = MODULE._compare(execution=execution, confirmations=[])
    assert comparison["per_mode_status_counts"] == {
        "numeric_incremental": {"sat": 0, "unsat": 0, "unknown": 256, "invalid": 0},
        "gray_incremental": {"sat": 0, "unsat": 0, "unknown": 256, "invalid": 0},
    }
    assert comparison["complete_predeclared_execution"] is True
    assert comparison["incremental_resolution_transfer_retained"] is False
    assert comparison["complete_domain_resolution_retained"] is False


def test_a210_protocol_is_canonical_json() -> None:
    raw = PROTOCOL_PATH.read_bytes()
    assert json.loads(raw)["attempt_id"] == "A210"
    assert raw.endswith(b"\n")

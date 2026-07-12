from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
from fractions import Fraction
from pathlib import Path
from typing import Any

import pytest

ROOT = Path(__file__).parents[1]
MODULE_PATH = ROOT / "research" / "experiments" / "chacha20_round10_bfs_far_width12_refinement.py"
SPEC = importlib.util.spec_from_file_location(
    "chacha20_round10_bfs_far_width12_refinement_tested", MODULE_PATH
)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)

RESULTS = ROOT / "research" / "results" / "v1"
PROTOCOL_PATH = ROOT / "research" / "configs" / MODULE.PROTOCOL_FILENAME
RUNNER_SHA256 = "02d0209b3e07893400169e3d620b9a08d1eef7e0bcda09c5907bfe13e641f884"
RESULT_PATH = RESULTS / MODULE.RESULT_FILENAME
CAUSAL_PATH = RESULTS / MODULE.CAUSAL_FILENAME
RESULT_SHA256 = "242a87fd56da3fcf60e6ae4c1a5dd75effc9a2293a41496ea71f4c4342cc5c1e"
CAUSAL_SHA256 = "577f8fdbf41d95d6a61316103c48cc6f366311821b830ac2e4d11b7f4f79eb7f"
CAUSAL_GRAPH_SHA256 = "21090e1289ff3cd46ec5403c1a0ab81a5272f056eb5a72ce6da08491aa48eeb1"
COMPOSITION_SHA256 = "9fd1aa30e9b71f8b30606e4ec9770886a746a5bf24e89e124c0bb0935eb66eb4"
PHASE_ANCHOR_SHA256 = "690bcb2bd0ff76ded4acb35cb30d24ad516167e97c015ba75a69ee574e933edc"
FORMULA_PLAN_SHA256 = "81d2468b21fa1296ce046303cc325fc7ef1e2cd4e4062a3ca7ec1d68b0275427"
REFINEMENT_SHA256 = "a62f175b7ea7faec8426811ed8b6f5a5fe16e0dc0dae96f2a5a2148d8b1e3a8b"
SOURCE_EXPORTS_SHA256 = "e7e56d9b2d0a70875fec0f64c873a691c55784e5b5c69c2151e751b1265b8e92"
ORDER_DIAGNOSTICS_SHA256 = "a27378c350a21830b983526db545b8eb386380a705127e11bd4a90151f0e9e7b"
TRANSFORM_MANIFEST_SHA256 = "eb179d02331166bed5c59c1839b20107903d4761256e9d83911ff652df4085ec"
EXECUTION_PLAN_SHA256 = "399152f6514ee4064e5f1f3b6337386f5036aacfd69d15a083b27c006ec40f1c"
EXECUTION_SHA256 = "afc248b833d4f560b462b008ab13f7198b9286641f8626362fdd261632e223d7"
CONFIRMATION_SHA256 = "4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945"
PHASE_RESET_SHA256 = "07d4484ae6e54bd204a6ae35bd79fae857bef7081b134371f21e963c8f0f5259"
COMPARISON_SHA256 = "2084a11660112892c047a289967674c2b7b136a22d64dea00719ac7d020d01cf"


@pytest.fixture(scope="module")
def analysis() -> dict[str, Any]:
    return MODULE.analyze(RESULTS)


def test_a209_protocol_runner_and_anchor_chain_are_exact(analysis: dict[str, Any]) -> None:
    assert MODULE._file_sha256(PROTOCOL_PATH) == MODULE.PROTOCOL_SHA256
    assert MODULE._file_sha256(MODULE_PATH) == RUNNER_SHA256
    assert analysis["solver_execution_started"] is False
    assert analysis["anchor_gates"] == {
        "A197_result_sha256": MODULE.A197_RESULT_SHA256,
        "A197_causal_sha256": MODULE.A197_CAUSAL_SHA256,
        "A197_causal_graph_sha256": MODULE.A197_CAUSAL_GRAPH_SHA256,
        "A197_causal_provenance_verified": True,
        "A197_complete_256_width12_unknown_boundary_retained": True,
        "A208_result_sha256": MODULE.A208_RESULT_SHA256,
        "A208_causal_sha256": MODULE.A208_CAUSAL_SHA256,
        "A208_causal_graph_sha256": MODULE.A208_CAUSAL_GRAPH_SHA256,
        "A208_causal_provenance_verified": True,
        "A208_complete_32_long_budget_unknown_boundary_retained": True,
        "A208_exact_phase_transition_retained": True,
        "same_public_challenge_retained": True,
    }


def test_a209_new_composition_and_information_boundary_are_frozen(
    analysis: dict[str, Any],
) -> None:
    protocol = analysis["protocol"]
    composition = protocol["composition_basis"]
    assert composition["same_public_challenge_in_A197_and_A208"] is True
    assert composition["this_exact_composition_executed_before_freeze"] is False
    assert composition["formula_transfer_family"] == (
        "T04_multisource_graph_distance_recomputed_after_three_new_key_unit_sources"
    )
    boundary = protocol["information_boundary"]
    assert boundary["A197_and_A208_outcomes_known_before_freeze"] is True
    assert boundary["any_A209_solver_outcome_known_before_freeze"] is False
    assert boundary["round10_unknown_assignment_in_protocol_source_order_or_archive"] is False
    assert boundary["round10_unknown_assignment_available_to_runner_before_execution"] is False
    assert boundary["correct_8bit_prefix_known_before_execution"] is False
    assert boundary["early_stop_permitted"] is False
    assert analysis["public_challenge"]["unknown_assignment_included"] is False
    assert analysis["public_challenge"]["unknown_key_word0_low_value_included"] is False


def test_a209_exact_phase_fractions_are_reconstructed(analysis: dict[str, Any]) -> None:
    phase = analysis["protocol"]["A208_phase_anchor"]
    early = phase["early_0_to_10_second_totals"]
    late = phase["late_10_to_60_second_increments"]
    rate = phase["late50_rate_over_early10_rate_exact_fractions"]
    for metric in early:
        assert MODULE._fraction(rate[metric]) == Fraction(late[metric], 5 * early[metric])
    density = phase["late50_density_over_early10_density_exact_fractions"]
    assert MODULE._fraction(density["conflicts_per_propagation"]) == Fraction(
        late["conflicts"] * early["propagations"],
        late["propagations"] * early["conflicts"],
    )
    decisions_fraction = MODULE._fraction(density["decisions_per_propagation"])
    assert decisions_fraction == Fraction(245315730720758, 8306250555382593)
    assert float(decisions_fraction) == 0.02953387079827362


def test_a209_complete_width12_partition_and_execution_plan_are_frozen(
    analysis: dict[str, Any],
) -> None:
    protocol = analysis["protocol"]
    refinement = protocol["refinement"]
    assert len(MODULE.PREFIXES) == 256
    assert MODULE.PREFIXES[0] == "00000000"
    assert MODULE.PREFIXES[-1] == "11111111"
    assert len(set(MODULE.PREFIXES)) == 256
    assert MODULE._canonical_sha256(list(MODULE.PREFIXES)) == refinement["full_prefix_order_sha256"]
    assert refinement["source_fixed_prefix_bits"] == 5
    assert refinement["target_fixed_prefix_bits"] == 8
    assert refinement["target_free_bits"] == 12
    assert refinement["target_complete_domain_candidates"] == 1 << 20
    assert refinement["pairwise_disjoint"] is True
    assert refinement["union_equals_original_20bit_domain"] is True
    plan = protocol["execution_plan"]
    assert plan["cell_count"] == 256
    assert plan["wave_count"] == 64
    assert plan["solver_time_limit_seconds_per_cell"] == 10
    assert plan["external_timeout_seconds_per_cell"] == 13
    assert plan["max_parallel_workers"] == 4
    assert plan["variant_order_sha256"] == MODULE._canonical_sha256(list(MODULE.VARIANTS))
    assert plan["complete_cell_plan_required"] is True
    assert plan["early_stop_permitted"] is False


def test_a209_refinement_units_and_normalization_are_exact() -> None:
    mapping = list(range(100, 115))
    source = b"p cnf 232191 734180\n1 -2 0\n-200 0\n-201 0\n-202 0\n-203 0\n-204 0\n"
    refined = MODULE._refine_cnf(source, prefix8="00000101", free_mapping=mapping)
    header, tail, normalized_sha256 = MODULE._normalized_refined_cnf(refined)
    assert header == "p cnf 232191 734183"
    assert tail == [-200, -201, -202, -203, -204, 114, -113, 112]
    normalized = refined.replace(b"-200", b"200").replace(b"-201", b"201")
    normalized = normalized.replace(b"-202", b"202").replace(b"-203", b"203")
    normalized = normalized.replace(b"-204", b"204").replace(b"-113", b"113")
    assert MODULE._sha256(normalized) == normalized_sha256


def test_a209_rederived_order_and_representative_transform_are_exact(
    analysis: dict[str, Any], tmp_path: Path
) -> None:
    identities = MODULE._A204._solver_gates(MODULE._A204._load_protocol_gate())
    source = tmp_path / "cse_prefix_11111.cnf"
    exported = MODULE._A204._export_cnf(
        variant="cse_prefix_11111",
        formula=analysis["a208_analysis"]["a207_analysis"]["a206_analysis"]["a204_analysis"][
            "formulas"
        ]["cse_prefix_11111"],
        output=source,
        bitwuzla_path=identities["bitwuzla"]["path"],
        limit_ms=MODULE._A204.CNF_EXPORT_LIMIT_MS,
    )
    assert exported["sha256"] == (
        "a9cd80dc9e7934f3c29681a78e4d734d598205e81b9796e9413b78be85e4fa2b"
    )
    full_mapping = analysis["a208_analysis"]["protocol"]["round10_source"][
        "free_k0_bit_one_literal_mapping"
    ]
    refined = MODULE._refine_cnf(source.read_bytes(), prefix8="11111111", free_mapping=full_mapping)
    order, mapping, inverse, transformed_mapping, diagnostics = MODULE._derive_refined_order(
        refined, full_mapping, analysis["protocol"]
    )
    assert diagnostics["order_sha256"] == (
        "814798f19a33a3a397a6af9f6fa126207e1e10e092d8ee80dcaba4ef3bae95c8"
    )
    assert diagnostics["unit_source_count"] == 6922
    assert len(order) == 232191
    assert len(set(order.tolist())) == 232191
    transformed = MODULE._A205._reindex_cnf(refined, mapping)
    assert MODULE._sha256(transformed) == (
        "3ebdaee2fdc586c0b73e9a44b8002de3f435303286ef07dd73e9815320168735"
    )
    assert MODULE._A205._reindex_cnf(transformed, inverse) == refined
    assert (
        transformed_mapping
        == analysis["protocol"]["refined_CNF_and_order_preflight"][
            "transformed_free_k0_bit_one_literal_mapping"
        ]
    )


def test_a209_comparison_keeps_unknown_distinct_from_unsat() -> None:
    observations = [
        {"variant": variant, "prefix8": prefix, "status": "unknown"}
        for prefix, variant in zip(MODULE.PREFIXES, MODULE.VARIANTS, strict=True)
    ]
    comparison = MODULE._compare({"observations": observations}, [])
    assert comparison["status_counts"] == {
        "sat": 0,
        "unsat": 0,
        "unknown": 256,
        "invalid": 0,
    }
    assert comparison["complete_predeclared_execution"] is True
    assert comparison["confirmed_recovery_retained"] is False
    assert comparison["complete_domain_resolution_retained"] is False


def test_a209_phase_reset_comparison_is_same_parent_and_missing_safe() -> None:
    baselines = [
        {
            "prefix": f"{parent:05b}",
            "variant": f"parent_{parent:05b}",
            "metrics": {"conflicts": 10, "decisions": 20, "propagations": 30, "restarts": 2},
        }
        for parent in range(32)
    ]
    observations = []
    for prefix, variant in zip(MODULE.PREFIXES, MODULE.VARIANTS, strict=True):
        metrics = {"conflicts": 5, "decisions": 10, "propagations": 15, "restarts": 1}
        if prefix == "00000000":
            metrics = {}
        observations.append(
            {
                "variant": variant,
                "prefix8": prefix,
                "parent_prefix5": prefix[:5],
                "child_suffix3": prefix[5:],
                "metrics": metrics,
            }
        )
    comparison = MODULE._phase_reset_comparison(observations, baselines)
    assert len(comparison["cell_rows"]) == 256
    assert len(comparison["parent_summaries"]) == 32
    first = comparison["parent_summaries"][0]["metrics"]["conflicts"]
    assert first["child_metric_observation_count"] == 7
    assert first["child_metric_missing_count"] == 1
    assert first["observed_child_total"] == 35
    assert first["complete_eight_child_total"] is None
    assert first["A207_parent_total"] == 10
    assert first["repeated_matched_parent_total"] == 70
    assert first["complete_eight_child_total_over_parent"] is None
    assert first["compute_normalized_mean_child_over_parent"] == 0.5
    total = comparison["total_metrics"]["conflicts"]
    assert total["A209_metric_observation_count"] == 255
    assert total["A209_metric_missing_count"] == 1
    assert total["matched_child_parent_count"] == 255
    assert total["A209_matched_child_total"] == 1275
    assert total["A207_repeated_matched_parent_total"] == 2550
    assert total["compute_normalized_mean_child_over_parent"] == 0.5


def test_a209_external_timeout_is_retained_as_invalid(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    cnf = tmp_path / "cell.cnf"
    cnf.write_text("p cnf 1 1\n1 0\n")

    def timeout(*args: Any, **kwargs: Any) -> subprocess.CompletedProcess[str]:
        raise subprocess.TimeoutExpired(args[0], MODULE.EXTERNAL_TIMEOUT_SECONDS, output="")

    monkeypatch.setattr(MODULE.subprocess, "run", timeout)
    observation, confirmation = MODULE._run_cell(
        variant="bfs_far_width12_prefix_00000000",
        cnf_path=cnf,
        transformed_mapping=[0],
        challenge={},
        cadical_path="cadical",
    )
    assert confirmation is None
    assert observation["status"] == "invalid"
    assert observation["invalid_reason"] == "external_timeout"
    assert observation["externally_timed_out"] is True


def test_a209_protocol_is_canonical_json() -> None:
    raw = PROTOCOL_PATH.read_bytes()
    assert json.loads(raw)["attempt_id"] == "A209"
    assert raw.endswith(b"\n")


def test_a209_retained_artifact_and_subhashes_are_exact() -> None:
    payload = json.loads(RESULT_PATH.read_bytes())
    assert MODULE._file_sha256(RESULT_PATH) == RESULT_SHA256
    assert MODULE._file_sha256(CAUSAL_PATH) == CAUSAL_SHA256
    assert payload["attempt_id"] == "A209"
    assert payload["schema"] == MODULE.SCHEMA
    assert payload["evidence_stage"] == "ROUND10_BFS_FAR_WIDTH12_COMPLETE_BOUNDARY_RETAINED"
    assert payload["composition_sha256"] == COMPOSITION_SHA256
    assert payload["A208_phase_anchor_sha256"] == PHASE_ANCHOR_SHA256
    assert payload["formula_plan_sha256"] == FORMULA_PLAN_SHA256
    assert payload["refinement_sha256"] == REFINEMENT_SHA256
    assert payload["source_exports_sha256"] == SOURCE_EXPORTS_SHA256
    assert payload["order_diagnostics_sha256"] == ORDER_DIAGNOSTICS_SHA256
    assert payload["transform_manifest_sha256"] == TRANSFORM_MANIFEST_SHA256
    assert payload["execution_plan_sha256"] == EXECUTION_PLAN_SHA256
    assert payload["execution_sha256"] == EXECUTION_SHA256
    assert payload["confirmation_sha256"] == CONFIRMATION_SHA256
    assert payload["phase_reset_comparison_sha256"] == PHASE_RESET_SHA256
    assert payload["comparison_sha256"] == COMPARISON_SHA256


def test_a209_retained_sources_order_and_all_256_transforms_are_exact() -> None:
    payload = json.loads(RESULT_PATH.read_bytes())
    sources = payload["source_exports"]
    assert len(sources) == 32
    assert len({row["sha256"] for row in sources}) == 32
    assert {row["normalized_sha256"] for row in sources} == {
        "a9cd80dc9e7934f3c29681a78e4d734d598205e81b9796e9413b78be85e4fa2b"
    }
    diagnostics = payload["order_diagnostics"]
    assert diagnostics["candidate"] == "output_unit_bfs_far"
    assert diagnostics["solver_mode"] == "reverse"
    assert diagnostics["unit_source_count"] == 6922
    assert diagnostics["order_sha256"] == (
        "814798f19a33a3a397a6af9f6fa126207e1e10e092d8ee80dcaba4ef3bae95c8"
    )
    assert MODULE._canonical_sha256(diagnostics) == ORDER_DIAGNOSTICS_SHA256
    transforms = payload["transform_manifest"]
    assert len(transforms) == 256
    assert [row["prefix8"] for row in transforms] == list(MODULE.PREFIXES)
    assert len({row["refined_cnf_sha256"] for row in transforms}) == 256
    assert len({row["transformed_cnf_sha256"] for row in transforms}) == 256
    assert {row["refined_normalized_sha256"] for row in transforms} == {
        "4cc857b7275c23dfc53638ac9d78d8cba427d18e901ce4b5b347a6a99c4344a8"
    }
    assert {row["transformed_normalized_sha256"] for row in transforms} == {
        "3ebdaee2fdc586c0b73e9a44b8002de3f435303286ef07dd73e9815320168735"
    }
    assert [row["prefix8"] for row in transforms if row["inverse_endpoint_checked"]] == [
        "00000000",
        "11111111",
    ]
    assert all(
        row["inverse_restored_sha256"] is not None
        for row in transforms
        if row["inverse_endpoint_checked"]
    )
    assert MODULE._canonical_sha256(transforms) == TRANSFORM_MANIFEST_SHA256


def test_a209_retained_complete_256_cell_boundary_is_exact() -> None:
    payload = json.loads(RESULT_PATH.read_bytes())
    execution = payload["execution"]
    observations = execution["observations"]
    assert len(observations) == 256
    assert len(execution["wave_observations"]) == 64
    assert [row["variant"] for row in observations] == execution["variant_order"]
    assert all(row["status"] == "unknown" for row in observations)
    assert all(row["status_line"] is None for row in observations)
    assert all(row["internal_timeout_marker"] is True for row in observations)
    assert all(row["returncode"] == 0 for row in observations)
    assert all(row["externally_timed_out"] is False for row in observations)
    assert all(row["invalid_reason"] is None for row in observations)
    assert all(row["witness_assignment_count"] == 0 for row in observations)
    assert all(row["model"] is None for row in observations)
    assert all(
        set(row["metrics"]) == {"conflicts", "decisions", "propagations", "restarts"}
        for row in observations
    )
    assert sum(row["volatile_seconds"] for row in observations) == 2573.8158471663482
    assert execution["complete_cell_plan_executed"] is True
    assert execution["early_stop_used"] is False
    assert execution["returned_model_count"] == 0
    assert MODULE._canonical_sha256(execution) == EXECUTION_SHA256
    assert payload["confirmations"] == []
    assert payload["comparisons"]["status_counts"] == {
        "sat": 0,
        "unsat": 0,
        "unknown": 256,
        "invalid": 0,
    }
    assert payload["comparisons"]["confirmed_recovery_retained"] is False
    assert payload["comparisons"]["complete_domain_resolution_retained"] is False


def test_a209_retained_phase_reset_transfer_is_systematic() -> None:
    payload = json.loads(RESULT_PATH.read_bytes())
    phase = payload["phase_reset_comparison"]
    totals = phase["total_metrics"]
    expected = {
        "conflicts": 1.0398057000026804,
        "decisions": 2.7925087307017944,
        "propagations": 1.614886051905536,
        "restarts": 6.634065550906555,
    }
    for metric, ratio in expected.items():
        summary = totals[metric]
        assert summary["compute_normalized_mean_child_over_parent"] == ratio
        assert summary["matched_child_parent_count"] == 256
        assert summary["A209_metric_missing_count"] == 0
        assert summary["A207_metric_missing_count"] == 0
    cells = phase["cell_rows"]
    assert len(cells) == 256
    for metric in ("decisions", "propagations", "restarts"):
        assert all(row["child_over_A207_parent_ratio"][metric] > 1.0 for row in cells)
    parent_decision_density = [
        row["metrics"]["decisions"]["compute_normalized_mean_child_over_parent"]
        / row["metrics"]["propagations"]["compute_normalized_mean_child_over_parent"]
        for row in phase["parent_summaries"]
    ]
    assert len(parent_decision_density) == 32
    assert min(parent_decision_density) == 1.18197724560133
    assert max(parent_decision_density) == 2.1704799900516685
    assert all(value > 1.0 for value in parent_decision_density)
    assert (
        totals["decisions"]["compute_normalized_mean_child_over_parent"]
        / totals["propagations"]["compute_normalized_mean_child_over_parent"]
        == 1.7292295808776634
    )
    assert MODULE._canonical_sha256(phase) == PHASE_RESET_SHA256


def test_a209_native_reader_DAG_is_exact() -> None:
    reader = MODULE.CryptoCausalReader(CAUSAL_PATH)
    assert reader.file_sha256 == CAUSAL_SHA256
    assert reader.graph_sha256 == CAUSAL_GRAPH_SHA256
    assert reader.verify_provenance() is True
    rows = reader.triplets(include_inferred=False)
    by_id = {row["edge_id"]: row for row in rows}
    ids = [
        "chacha20-a209-a197-width12-anchor",
        "chacha20-a209-a208-phase-anchor",
        "chacha20-a209-composition-selection",
        "chacha20-a209-refined-bfs-far-order",
        "chacha20-a209-complete-refined-transforms",
        "chacha20-a209-complete-width12-execution",
        "chacha20-a209-independent-confirmation",
        "chacha20-a209-phase-reset-comparison",
        "chacha20-a209-width12-result",
    ]
    assert len(rows) == 9
    assert set(by_id) == set(ids)
    assert [by_id[edge_id]["provenance"] for edge_id in ids] == [
        [],
        [],
        [ids[0], ids[1]],
        [ids[2]],
        [ids[3]],
        [ids[4]],
        [ids[5]],
        [ids[6]],
        [ids[7]],
    ]
    assert [by_id[edge_id]["source"] for edge_id in ids] == [
        MODULE.A197_CAUSAL_SHA256,
        MODULE.A208_CAUSAL_SHA256,
        COMPOSITION_SHA256,
        ORDER_DIAGNOSTICS_SHA256,
        TRANSFORM_MANIFEST_SHA256,
        EXECUTION_SHA256,
        CONFIRMATION_SHA256,
        PHASE_RESET_SHA256,
        COMPARISON_SHA256,
    ]

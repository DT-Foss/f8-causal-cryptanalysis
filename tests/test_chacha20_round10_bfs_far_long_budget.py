from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest

ROOT = Path(__file__).parents[1]
MODULE_PATH = ROOT / "research" / "experiments" / "chacha20_round10_bfs_far_long_budget.py"
SPEC = importlib.util.spec_from_file_location(
    "chacha20_round10_bfs_far_long_budget_tested", MODULE_PATH
)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)

RESULTS = ROOT / "research" / "results" / "v1"
PROTOCOL_PATH = ROOT / "research" / "configs" / MODULE.PROTOCOL_FILENAME
RUNNER_SHA256 = "68233f022ded5285ad0926be508f20532d85b5adbaefabbcff6e8096d7ebeb73"
RESULT_PATH = RESULTS / MODULE.RESULT_FILENAME
CAUSAL_PATH = RESULTS / MODULE.CAUSAL_FILENAME
RESULT_SHA256 = "58af841aa508978857f629c43c3fdb679e620eb9ec365b5211b4f708d287203c"
CAUSAL_SHA256 = "9e5e35ec7a3a005f8bd10d1608dd078b7b79aaaf9bd1e4e77ac5e7201c4a0993"
CAUSAL_GRAPH_SHA256 = "cc938bef2e6cfed1f629c5b034987676817be80b0f46c140b32617bd5901e21e"
SELECTION_SHA256 = "861b798682dcfde21e69fc90b3d427c32d0977c7f8e2c6876079b29435449d6c"
FORMULA_PLAN_SHA256 = "81d2468b21fa1296ce046303cc325fc7ef1e2cd4e4062a3ca7ec1d68b0275427"
ORDER_ARCHIVE_PAYLOAD_SHA256 = "44995760475aa4981779e77244d5bc9a215ce9da5818db3ecb9a40b50199030b"
SOURCE_EXPORTS_SHA256 = "c8fa202c2b50904fe40b5cde0b01e779b9ad99c708fc8c8f275b421c688e0370"
TRANSFORM_MANIFEST_SHA256 = "f9ae77ed7bcae1e22f5084c0c23a906a7d40ae947a9ba4f744fe8ba6185dcca8"
EXECUTION_PLAN_SHA256 = "4e785a3f977634d26f182ab8316f0a46522b98d0c1eecfa03ebbe46a166a5946"
EXECUTION_SHA256 = "299e0545f91c4fc2218221aec25d6d66e8b9d055f143559c8ad642ea427ee5f4"
CONFIRMATION_SHA256 = "4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945"
RATE_COMPARISON_SHA256 = "7cee747dc5deb9722e47c6d9a5d1a67b9df5cdcf31774ba6d45c531474c63e89"
COMPARISON_SHA256 = "19050abc8736416bb7f27f43a48eeb2ae147deb2b2e095eb07d3636b4febb6a7"


@pytest.fixture(scope="module")
def analysis() -> dict[str, Any]:
    return MODULE.analyze(RESULTS)


def test_a208_protocol_runner_and_a207_anchor_chain_are_exact(
    analysis: dict[str, Any],
) -> None:
    assert MODULE._file_sha256(PROTOCOL_PATH) == MODULE.PROTOCOL_SHA256
    assert MODULE._file_sha256(MODULE_PATH) == RUNNER_SHA256
    assert analysis["solver_execution_started"] is False
    assert analysis["anchor_gates"] == {
        "A207_result_sha256": MODULE.A207_SHA256,
        "A207_causal_sha256": MODULE.A207_CAUSAL_SHA256,
        "A207_causal_graph_sha256": MODULE.A207_CAUSAL_GRAPH_SHA256,
        "A207_causal_provenance_verified": True,
        "A207_complete_352_unknown_boundary_retained": True,
        "A207_selected_progress_outlier_retained": True,
        "order_archive_sha256": MODULE.ORDER_ARCHIVE_SHA256,
        "order_metadata_sha256": MODULE.ORDER_METADATA_SHA256,
        "order_causal_sha256": MODULE.ORDER_CAUSAL_SHA256,
        "order_causal_graph_sha256": MODULE.ORDER_CAUSAL_GRAPH_SHA256,
        "order_causal_provenance_verified": True,
    }


def test_a208_systematic_outlier_selection_is_frozen(analysis: dict[str, Any]) -> None:
    selection = analysis["protocol"]["selection"]
    assert selection["selected_candidate"] == "output_unit_bfs_far"
    assert selection["archive_row_index"] == 5
    assert selection["solver_mode"] == "reverse"
    assert selection["selection_time_data_used"] is False
    assert selection["A207_total_ratios"] == {
        "conflicts": 2.7585773439810706,
        "decisions": 5.685713565082508,
        "propagations": 0.5939991928589421,
        "restarts": 0.478,
        "conflicts_per_propagation": 4.644075913140431,
        "decisions_per_propagation": 9.571921365274823,
    }
    assert selection["A207_all_prefix_direction_gates"] == {
        "conflicts_ratio_min": 1.703481842006739,
        "decisions_ratio_min": 3.3145624103299856,
        "propagations_ratio_max": 0.7555339998822715,
    }


def test_a208_exact_archived_order_and_public_boundary_are_retained(
    analysis: dict[str, Any],
) -> None:
    protocol = analysis["protocol"]
    assert analysis["metadata_row"]["candidate"] == MODULE.SELECTED_CANDIDATE
    assert (
        MODULE._sha256(analysis["order"].astype("<u4", copy=False).tobytes())
        == (protocol["candidate_order"]["order_sha256"])
    )
    assert analysis["public_challenge"]["unknown_assignment_included"] is False
    assert analysis["public_challenge"]["unknown_key_word0_low_value_included"] is False
    assert len(analysis["baseline_observations"]) == 32
    assert all(
        row["candidate"] == MODULE.SELECTED_CANDIDATE for row in analysis["baseline_observations"]
    )
    assert all(
        row["solver_mode"] == MODULE.SOLVER_MODE for row in analysis["baseline_observations"]
    )


def test_a208_complete_long_budget_plan_is_frozen(analysis: dict[str, Any]) -> None:
    plan = analysis["protocol"]["execution_plan"]
    assert plan["solver_time_limit_seconds_per_cell"] == 60
    assert plan["external_timeout_seconds_per_cell"] == 65
    assert plan["max_parallel_workers"] == 4
    assert plan["cell_count"] == 32
    assert plan["execution_order"] == "prefix_ascending"
    assert plan["inverse_restore_prefix_endpoints"] == ["00000", "11111"]
    assert plan["complete_cell_plan_required"] is True
    assert plan["early_stop_permitted"] is False


def test_a208_information_boundary_is_explicit(analysis: dict[str, Any]) -> None:
    boundary = analysis["protocol"]["information_boundary"]
    assert boundary["A207_outcomes_and_progress_map_known_before_freeze"] is True
    assert boundary["any_A208_solver_outcome_known_before_freeze"] is False
    assert boundary["round10_unknown_assignment_in_protocol_source_or_order_archive"] is False
    assert boundary["round10_unknown_assignment_available_to_runner_before_execution"] is False
    assert (
        boundary["selection_used_only_complete_A207_progress_metrics_not_volatile_seconds"] is True
    )
    assert (
        boundary[
            "candidate_order_mode_prefix_order_budget_or_predictions_changed_after_any_A208_outcome"
        ]
        is False
    )
    assert boundary["early_stop_permitted"] is False


def test_a208_comparison_keeps_unknown_distinct_from_unsat() -> None:
    observations = [
        {
            "variant": f"long_{prefix}",
            "prefix": prefix,
            "status": "unknown",
        }
        for prefix in MODULE.PREFIXES
    ]
    comparison = MODULE._compare(
        {"observations": observations},
        [],
    )
    assert comparison["status_counts"] == {
        "sat": 0,
        "unsat": 0,
        "unknown": 32,
        "invalid": 0,
    }
    assert comparison["confirmed_recovery_retained"] is False
    assert comparison["complete_domain_resolution_retained"] is False


def test_a208_rate_comparison_uses_nominal_budget_and_same_prefix() -> None:
    observations = [
        {
            "variant": "long_00000",
            "prefix": "00000",
            "volatile_seconds": 60.5,
            "metrics": {"conflicts": 120, "decisions": 240, "propagations": 360, "restarts": 12},
        }
    ]
    baseline = [
        {
            "variant": "short_00000",
            "prefix": "00000",
            "volatile_seconds": 10.5,
            "metrics": {"conflicts": 10, "decisions": 20, "propagations": 30, "restarts": 1},
        }
    ]
    comparison = MODULE._rate_comparison(observations, baseline)
    assert comparison["cell_rows"][0]["A207_variant"] == "short_00000"
    for metric in ("conflicts", "decisions", "propagations", "restarts"):
        summary = comparison["total_metrics"][metric]
        assert summary["raw_total_ratio"] == 12.0
        assert summary["nominal_per_second_ratio"] == 2.0
        assert summary["cell_nominal_rate_ratio_count"] == 1


def test_a208_rate_comparison_retains_missing_metrics() -> None:
    observations = [
        {
            "variant": "long_00000",
            "prefix": "00000",
            "volatile_seconds": 65.0,
            "metrics": {},
        }
    ]
    baseline = [
        {
            "variant": "short_00000",
            "prefix": "00000",
            "volatile_seconds": 10.0,
            "metrics": {"conflicts": 10, "decisions": 20, "propagations": 30, "restarts": 1},
        }
    ]
    comparison = MODULE._rate_comparison(observations, baseline)
    for summary in comparison["total_metrics"].values():
        assert summary["A208_total"] is None
        assert summary["A207_total"] is None
        assert summary["matched_prefix_count"] == 0
        assert summary["totals_use_only_same_prefix_matched_metric_pairs"] is True
        assert summary["A208_metric_observation_count"] == 0
        assert summary["A208_metric_missing_count"] == 1
        assert summary["nominal_per_second_ratio"] is None
        assert summary["cell_nominal_rate_ratio_count"] == 0
        assert summary["cell_nominal_rate_ratio_min"] is None


def test_a208_partial_metrics_compare_only_the_same_prefix_subset() -> None:
    observations = [
        {
            "variant": "long_00000",
            "prefix": "00000",
            "volatile_seconds": 60.0,
            "metrics": {"conflicts": 120},
        },
        {
            "variant": "long_00001",
            "prefix": "00001",
            "volatile_seconds": 65.0,
            "metrics": {},
        },
    ]
    baseline = [
        {
            "variant": "short_00000",
            "prefix": "00000",
            "volatile_seconds": 10.0,
            "metrics": {"conflicts": 10},
        },
        {
            "variant": "short_00001",
            "prefix": "00001",
            "volatile_seconds": 10.0,
            "metrics": {"conflicts": 1000},
        },
    ]
    summary = MODULE._rate_comparison(observations, baseline)["total_metrics"]["conflicts"]
    assert summary["A208_total"] == 120
    assert summary["A207_total"] == 10
    assert summary["A207_full_baseline_total"] == 1010
    assert summary["matched_prefix_count"] == 1
    assert summary["raw_total_ratio"] == 12.0
    assert summary["nominal_per_second_ratio"] == 2.0


def test_a208_external_timeout_is_retained_as_invalid(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    cnf = tmp_path / "cell.cnf"
    cnf.write_text("p cnf 1 1\n1 0\n")

    def timeout(*args: Any, **kwargs: Any) -> subprocess.CompletedProcess[str]:
        raise subprocess.TimeoutExpired(args[0], MODULE.EXTERNAL_TIMEOUT_SECONDS, output="")

    monkeypatch.setattr(MODULE.subprocess, "run", timeout)
    observation, confirmation = MODULE._run_cell(
        variant="cse_prefix_00000",
        cnf_path=cnf,
        transformed_mapping=[0],
        challenge={},
        cadical_path="cadical",
    )
    assert confirmation is None
    assert observation["status"] == "invalid"
    assert observation["invalid_reason"] == "external_timeout"
    assert observation["externally_timed_out"] is True


def test_a208_protocol_is_canonical_json() -> None:
    raw = PROTOCOL_PATH.read_bytes()
    assert json.loads(raw)["attempt_id"] == "A208"
    assert raw.endswith(b"\n")


def test_a208_retained_artifact_and_subhashes_are_exact() -> None:
    payload = json.loads(RESULT_PATH.read_bytes())
    assert MODULE._file_sha256(RESULT_PATH) == RESULT_SHA256
    assert MODULE._file_sha256(CAUSAL_PATH) == CAUSAL_SHA256
    assert payload["attempt_id"] == "A208"
    assert payload["schema"] == MODULE.SCHEMA
    assert payload["evidence_stage"] == "ROUND10_BFS_FAR_LONG_COMPLETE_BOUNDARY_RETAINED"
    assert payload["selection_sha256"] == SELECTION_SHA256
    assert payload["formula_plan_sha256"] == FORMULA_PLAN_SHA256
    assert payload["order_archive_sha256"] == ORDER_ARCHIVE_PAYLOAD_SHA256
    assert payload["source_exports_sha256"] == SOURCE_EXPORTS_SHA256
    assert payload["transform_manifest_sha256"] == TRANSFORM_MANIFEST_SHA256
    assert payload["execution_plan_sha256"] == EXECUTION_PLAN_SHA256
    assert payload["execution_sha256"] == EXECUTION_SHA256
    assert payload["confirmation_sha256"] == CONFIRMATION_SHA256
    assert payload["rate_comparison_sha256"] == RATE_COMPARISON_SHA256
    assert payload["comparison_sha256"] == COMPARISON_SHA256


def test_a208_retained_sources_and_all_32_transforms_are_exact() -> None:
    payload = json.loads(RESULT_PATH.read_bytes())
    sources = payload["source_exports"]
    assert len(sources) == 32
    assert len({row["sha256"] for row in sources}) == 32
    assert {row["normalized_sha256"] for row in sources} == {
        "a9cd80dc9e7934f3c29681a78e4d734d598205e81b9796e9413b78be85e4fa2b"
    }
    transforms = payload["transform_manifest"]
    assert len(transforms) == 32
    assert len({row["transformed_cnf_sha256"] for row in transforms}) == 32
    assert [row["prefix"] for row in transforms if row["inverse_endpoint_checked"]] == [
        "00000",
        "11111",
    ]
    assert all(
        row["inverse_restored_sha256"] is not None
        for row in transforms
        if row["inverse_endpoint_checked"]
    )
    assert MODULE._canonical_sha256(transforms) == TRANSFORM_MANIFEST_SHA256


def test_a208_retained_complete_32_cell_boundary_is_exact() -> None:
    payload = json.loads(RESULT_PATH.read_bytes())
    execution = payload["execution"]
    observations = execution["observations"]
    assert len(observations) == 32
    assert len(execution["wave_observations"]) == 8
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
    assert sum(row["volatile_seconds"] for row in observations) == 1922.5255002505146
    assert execution["complete_cell_plan_executed"] is True
    assert execution["early_stop_used"] is False
    assert execution["returned_model_count"] == 0
    assert MODULE._canonical_sha256(execution) == EXECUTION_SHA256
    assert payload["confirmations"] == []
    assert payload["comparisons"]["status_counts"] == {
        "sat": 0,
        "unsat": 0,
        "unknown": 32,
        "invalid": 0,
    }
    assert payload["comparisons"]["confirmed_recovery_retained"] is False
    assert payload["comparisons"]["complete_domain_resolution_retained"] is False


def test_a208_retained_long_budget_phase_shift_is_systematic() -> None:
    payload = json.loads(RESULT_PATH.read_bytes())
    rate = payload["rate_comparison"]
    totals = rate["total_metrics"]
    expected = {
        "conflicts": (2.275404079663334, 0.37923401327722234),
        "decisions": (1.2748510318807855, 0.21247517198013094),
        "propagations": (10.306298986614777, 1.7177164977691295),
        "restarts": (13.868898186889819, 2.311483031148303),
    }
    for metric, (raw_ratio, nominal_ratio) in expected.items():
        summary = totals[metric]
        assert summary["raw_total_ratio"] == raw_ratio
        assert summary["nominal_per_second_ratio"] == nominal_ratio
        assert summary["matched_prefix_count"] == 32
        assert summary["A208_metric_missing_count"] == 0
        assert summary["A207_metric_missing_count"] == 0
        assert summary["totals_use_only_same_prefix_matched_metric_pairs"] is True

    rows = rate["cell_rows"]
    for metric in ("conflicts", "decisions"):
        late_over_early = [
            ((row["metrics"][metric]["A208_total"] - row["metrics"][metric]["A207_total"]) / 50)
            / (row["metrics"][metric]["A207_total"] / 10)
            for row in rows
        ]
        assert all(value < 1.0 for value in late_over_early)
    late_propagation_over_early = [
        (
            (
                row["metrics"]["propagations"]["A208_total"]
                - row["metrics"]["propagations"]["A207_total"]
            )
            / 50
        )
        / (row["metrics"]["propagations"]["A207_total"] / 10)
        for row in rows
    ]
    assert all(value > 1.0 for value in late_propagation_over_early)
    assert MODULE._canonical_sha256(rate) == RATE_COMPARISON_SHA256


def test_a208_native_reader_chain_is_exact() -> None:
    reader = MODULE.CryptoCausalReader(CAUSAL_PATH)
    assert reader.file_sha256 == CAUSAL_SHA256
    assert reader.graph_sha256 == CAUSAL_GRAPH_SHA256
    assert reader.verify_provenance() is True
    rows = reader.triplets(include_inferred=False)
    by_id = {row["edge_id"]: row for row in rows}
    ids = [
        "chacha20-a208-a207-portfolio-anchor",
        "chacha20-a208-systematic-density-selection",
        "chacha20-a208-exact-order-source",
        "chacha20-a208-complete-long-execution",
        "chacha20-a208-independent-confirmation",
        "chacha20-a208-rate-comparison",
        "chacha20-a208-long-budget-result",
    ]
    assert len(rows) == 7
    assert set(by_id) == set(ids)
    assert [by_id[edge_id]["provenance"] for edge_id in ids] == [
        [],
        [ids[0]],
        [ids[1]],
        [ids[2]],
        [ids[3]],
        [ids[4]],
        [ids[5]],
    ]
    assert [by_id[edge_id]["source"] for edge_id in ids] == [
        MODULE.A207_CAUSAL_SHA256,
        SELECTION_SHA256,
        TRANSFORM_MANIFEST_SHA256,
        EXECUTION_SHA256,
        CONFIRMATION_SHA256,
        RATE_COMPARISON_SHA256,
        COMPARISON_SHA256,
    ]

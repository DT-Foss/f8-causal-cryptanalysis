from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path
from typing import Any

import pytest

ROOT = Path(__file__).parents[1]
MODULE_PATH = (
    ROOT / "research" / "experiments" / "chacha20_solver_trajectory_formula_atlas.py"
)
SPEC = importlib.util.spec_from_file_location(
    "chacha20_solver_trajectory_formula_atlas_tested", MODULE_PATH
)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)

RESULTS = ROOT / "research" / "results" / "v1"
PROTOCOL_PATH = ROOT / "research" / "configs" / MODULE.PROTOCOL_FILENAME
RESULT_PATH = RESULTS / MODULE.RESULT_FILENAME
CAUSAL_PATH = RESULTS / MODULE.CAUSAL_FILENAME

RUNNER_SHA256 = "589a18aae5bdc9ed6c2b0bf052d223d086feb2c06b291d801e53b86d98760dbe"
RESULT_SHA256 = "d7fc64a9aac6f36483b238595332fd3a4f351c39e501de56b0d1f832903bc8cf"
CAUSAL_SHA256 = "ce5b4f5859a4e4d4c33be185deb2625fa1dc113c1127f0635444ff6ff1789c49"
CAUSAL_GRAPH_SHA256 = (
    "54526aaab678b6e4a7c1f18357e149b29ab9c3096ca3df9e2297cc1043a304f4"
)
T01_SHA256 = "4d2a8ce8aab142469e723328f62c8f773034c49f2aa5b71c6ca18322864805ec"
T02_SHA256 = "e993cc6811c3fb43033a7cb3073bcf845e947d44da22728a8505e144a4cee8c6"
T03_SHA256 = "8e47e1893a4c96b0a59ca73c110e1a3b6eaf7ad87f4458f2383729fced71bd90"
T05_SHA256 = "2e4c6b7465261c6dfe68f3fd8163cf0e9f0a653fda418df5e17286883afa29cd"
T06_SHA256 = "3c61a97631ff25639cbefd6aa11c19c4cff1db0ac976403c435cde6c694b47cc"
SCHEDULE_SHA256 = (
    "65db0b3a024b8d494b0c56a9f013820e31c07e59b61b919fbb09bf3b3c8f1142"
)


@pytest.fixture(scope="module")
def payload() -> dict[str, Any]:
    return json.loads(RESULT_PATH.read_bytes())


@pytest.fixture(scope="module")
def recomputed(tmp_path_factory: pytest.TempPathFactory) -> dict[str, Any]:
    directory = tmp_path_factory.mktemp("a212-recompute")
    output = directory / MODULE.RESULT_FILENAME
    causal = directory / MODULE.CAUSAL_FILENAME
    summary = MODULE.run(results_dir=RESULTS, output=output, causal_output=causal)
    return {"summary": summary, "output": output, "causal": causal}


def test_a212_frozen_protocol_and_analyze_only_are_exact_and_write_free() -> None:
    assert MODULE._file_sha256(PROTOCOL_PATH) == MODULE.PROTOCOL_SHA256
    assert MODULE._file_sha256(MODULE_PATH) == RUNNER_SHA256
    before = (RESULT_PATH.stat().st_mtime_ns, CAUSAL_PATH.stat().st_mtime_ns)
    analysis = MODULE.analyze(RESULTS)
    after = (RESULT_PATH.stat().st_mtime_ns, CAUSAL_PATH.stat().st_mtime_ns)
    assert analysis == {
        "protocol_sha256": MODULE.PROTOCOL_SHA256,
        "context_rows": {
            "A210_numeric_reset_local": 256,
            "A210_gray_reset_local": 256,
            "A211_numeric_retained_global": 256,
            "A211_gray_retained_global": 256,
        },
        "solver_execution_started": False,
        "output_written": False,
    }
    assert before == after


def test_a212_retained_artifacts_recompute_byte_exactly(
    payload: dict[str, Any], recomputed: dict[str, Any]
) -> None:
    assert MODULE._file_sha256(RESULT_PATH) == RESULT_SHA256
    assert MODULE._file_sha256(CAUSAL_PATH) == CAUSAL_SHA256
    assert MODULE._file_sha256(recomputed["output"]) == RESULT_SHA256
    assert MODULE._file_sha256(recomputed["causal"]) == CAUSAL_SHA256
    assert recomputed["summary"]["causal_graph_sha256"] == CAUSAL_GRAPH_SHA256
    assert payload["schema"] == MODULE.SCHEMA
    assert payload["attempt_id"] == "A212"
    assert payload["evidence_stage"] == (
        "SOLVER_TRAJECTORY_FORMULA_ATLAS_MIXED_BOUNDARY_RETAINED"
    )
    assert payload["solver_execution"] == {
        "future_R11_or_R20_outcomes_used": False,
        "model_or_assignment_fields_accessed": False,
        "solver_processes_started": 0,
        "status_labels_used_as_features": False,
    }


def test_a212_t01_exactly_localizes_the_order_coherence_boundary(
    payload: dict[str, Any]
) -> None:
    t01 = payload["T01"]
    assert payload["T01_sha256"] == T01_SHA256 == MODULE._canonical_sha256(t01)
    assert t01["all_operator_gates_passed"] is True
    assert t01["retained_global_contexts"] == []
    assert t01["prediction_retained"] is False
    assert t01["posthoc_lower_tail_order_coherence_discovery_contexts"] == [
        "A210_gray_reset_local"
    ]
    gray = t01["contexts"]["A210_gray_reset_local"]
    assert gray["chronological_reverse_relative_frobenius"] == 0.654296667872
    assert gray["order_null"]["lower_2_5_percentile"] == 0.75291529077
    assert gray["order_null"]["empirical_lower_p_value"] == 0.007566512082
    assert gray["maximum_adjoint_identity_error"] == 0.0
    assert gray["posthoc_lower_tail_order_coherence_discovery"] is True


def test_a212_t02_retains_two_distinct_triplet_regimes_after_holm(
    payload: dict[str, Any]
) -> None:
    t02 = payload["T02"]
    assert payload["T02_sha256"] == T02_SHA256 == MODULE._canonical_sha256(t02)
    assert t02["all_null_marginals_preserved_exactly"] is True
    assert t02["retained_context_statistics"] == [
        {"context": "A210_numeric_reset_local", "statistic": "l2_norm"},
        {"context": "A211_gray_retained_global", "statistic": "l2_norm"},
    ]
    local = t02["contexts"]["A210_numeric_reset_local"]
    global_gray = t02["contexts"]["A211_gray_retained_global"]
    assert local["observed"]["l2_norm"] == 4.627675230777
    assert global_gray["observed"]["l2_norm"] == 7.951825766927
    assert (
        local["nulls"]["permutation"]["statistics"]["l2_norm"][
            "holm_adjusted_p_value"
        ]
        == 0.042884990253
    )
    assert (
        global_gray["nulls"]["circular_shift"]["statistics"]["l2_norm"][
            "holm_adjusted_p_value"
        ]
        == 0.031189083821
    )


def test_a212_t03_reconstructs_all_characteristic_derivative_views(
    payload: dict[str, Any]
) -> None:
    t03 = payload["T03"]
    assert payload["T03_sha256"] == T03_SHA256 == MODULE._canonical_sha256(t03)
    assert t03["diagnostic_count"] == 30
    assert t03["all_operator_gates_passed"] is True
    assert t03["maximum_coefficient_reconstruction_relative_error"] == 1e-15
    assert t03["maximum_root_residual_relative"] == 0.0
    assert all(row["gate_passed"] for row in t03["diagnostics"])


def test_a212_t05_t06_copy_symmetry_and_latent_couplings_are_exact(
    payload: dict[str, Any]
) -> None:
    t05, t06 = payload["T05"], payload["T06"]
    assert payload["T05_sha256"] == T05_SHA256 == MODULE._canonical_sha256(t05)
    assert payload["T06_sha256"] == T06_SHA256 == MODULE._canonical_sha256(t06)
    assert t05["prediction_retained"] is True
    assert t05["pairs"]["A210_reset_local"]["eligible_unknown_pair_count"] == 256
    assert t05["pairs"]["A211_retained_global"]["excluded_non_unknown_pair_count"] == 1
    for row in t05["pairs"].values():
        assert row["physical_sum_copy_swap_error"] == 0.0
        assert row["signed_difference_copy_swap_error"] == 0.0
    assert t06["all_matrix_log_gates_passed"] is True
    assert t06["prediction_retained"] is True
    for row in t06["pairs"].values():
        assert row["effective_rank_1e_10"] == 6
        assert row["matrix_log_reconstruction_relative_error"] == 1e-15
        assert row["gate_passed"] is True


def test_a212_formula_schedule_is_a_complete_target_independent_gray_path(
    payload: dict[str, Any]
) -> None:
    schedule = payload["prospective_schedule"]
    assert (
        payload["prospective_schedule_sha256"]
        == SCHEDULE_SHA256
        == MODULE._canonical_sha256(schedule)
    )
    assert schedule["start_prefix8"] == "10110000"
    assert schedule["selected_bit_permutation_source_to_target"] == [5, 4, 3, 7, 6, 0, 1, 2]
    assert schedule["selected_direction"] == "forward"
    assert schedule["formula_gray8_order_sha256"] == (
        "ba9cf4d93c1937665772c77b9091d45cb575054c70037d9cc540ee70a9609127"
    )
    assert schedule["complete_256_prefix_permutation"] is True
    assert schedule["gray8_Hamiltonian_path"] is True
    assert schedule["adjacent_hamming_histogram"] == {"1": 255}
    assert schedule["discounted_objectives"]["formula_over_standard_ratio"] == (
        1.137417853723
    )
    assert schedule["status_or_model_field_used"] is False
    assert schedule["future_solver_outcome_used"] is False
    assert schedule["prediction_retained"] is True


def test_a212_native_causal_reader_opens_exact_nine_edge_provenance_dag() -> None:
    reader = MODULE.CryptoCausalReader(CAUSAL_PATH)
    assert reader.file_sha256 == CAUSAL_SHA256
    assert reader.graph_sha256 == CAUSAL_GRAPH_SHA256
    assert reader.verify_provenance() is True
    rows = reader.triplets(include_inferred=False)
    assert len(rows) == 9
    by_id = {row["edge_id"]: row for row in rows}
    assert by_id["a212-t01"]["provenance"] == [
        "a212-formula-anchor",
        "a212-global-anchor",
        "a212-local-anchor",
    ]
    assert by_id["a212-t03"]["provenance"] == ["a212-t01"]
    assert by_id["a212-t06"]["provenance"] == ["a212-t05"]
    assert by_id["a212-schedule"]["provenance"] == ["a212-t05", "a212-t06"]

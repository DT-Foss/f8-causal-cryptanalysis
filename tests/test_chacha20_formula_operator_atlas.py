from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path
from typing import Any

import numpy as np
import pytest

ROOT = Path(__file__).parents[1]
MODULE_PATH = ROOT / "research" / "experiments" / "chacha20_formula_operator_atlas.py"
SPEC = importlib.util.spec_from_file_location("chacha20_formula_operator_atlas_tested", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)

RESULTS = ROOT / "research" / "results" / "v1"
PROTOCOL_PATH = ROOT / "research" / "configs" / MODULE.PROTOCOL_FILENAME
RESULT_PATH = RESULTS / MODULE.RESULT_FILENAME
CAUSAL_PATH = RESULTS / MODULE.CAUSAL_FILENAME

RUNNER_SHA256 = "f3004f369db934c1f29c791bf06cfbbc67d54095ea1e517b17b906f2bc330e80"
RESULT_SHA256 = "16c1025308bae64e2c45339804ec0a39d5fcb927c1cd0a1dcbf2ca8dfd3d5c48"
CAUSAL_SHA256 = "bb509b61239bf3bc4396bac2b882820204deba6683186f9f5a89f65c1968fc89"
CAUSAL_GRAPH_SHA256 = "d8f154f8993f9e9fcb438f55cd290c5323a5e4e46934b72775d9584f569783d2"
OPERATOR_SHA256 = "67a22de6143cb81761b0f0b249a2664ba31185d2e714a3aa0573aa5510e63fe3"
T01_SHA256 = "a9a7b99948befc125d3ac9363da7eee03fb550631695878fa983979100b6cb75"
T02_SHA256 = "3ebadac5c333a05566f300ef73eaa4fe5763a1d2f6cc28adaf2629ad1979a234"
T03_SHA256 = "d6496150463ebd978d3ea57d87d7b6a41d177aa93631f0c84a0e0cd045e93481"
T04_SHA256 = "bb39f9d359503b67dc037acb87fa5a280b43e1e1a5c30660e1ca851fc090da99"
T05_SHA256 = "303ac7a4f1d66703757a74252fafcabd908df9c979919cb588949149ab75ebca"


@pytest.fixture(scope="module")
def recomputed() -> dict[str, Any]:
    states = MODULE._public_states(MODULE.TRIPLET_SAMPLES)
    operator_states = states[: MODULE.OPERATOR_SAMPLES]
    cuts = MODULE._base_cuts(operator_states)
    forward_operators, inverse_operators, operator_gates = MODULE._local_operators(cuts)
    trajectories, _ = MODULE._key_trajectories(states)
    _, forward_profiles = MODULE._key_trajectories(operator_states)
    backward_profiles = MODULE._backward_key_profiles(operator_states, cuts)
    t01, products = MODULE._t01(forward_operators)
    t02 = MODULE._t02(trajectories)
    t03 = MODULE._t03(forward_operators, products)
    t05, features = MODULE._t05(forward_profiles, backward_profiles)
    t04 = MODULE._t04(features)
    return {
        "states": states,
        "operator_states": operator_states,
        "cuts": cuts,
        "forward_operators": forward_operators,
        "inverse_operators": inverse_operators,
        "operator_gates": operator_gates,
        "T01": t01,
        "T02": t02,
        "T03": t03,
        "T04": t04,
        "T05": t05,
    }


def test_a199_protocol_source_and_public_implementation_gates_are_exact(
    recomputed: dict[str, Any],
) -> None:
    protocol = MODULE._load_protocol(RESULTS)
    assert MODULE._file_sha256(PROTOCOL_PATH) == MODULE.PROTOCOL_SHA256
    assert MODULE._file_sha256(MODULE_PATH) == RUNNER_SHA256
    assert protocol["protocol_state"] == (
        "frozen_after_A198_and_full_formula_reaudit_before_any_A199_measurement"
    )
    assert protocol["information_boundary"]["hidden_cipher_assignment_used"] is False
    assert protocol["information_boundary"]["solver_execution_in_A199"] is False
    assert MODULE._kat_gate()["passed"] is True
    assert (
        MODULE._inverse_gates(recomputed["operator_states"], recomputed["cuts"])["all_exact"]
        is True
    )


def test_a199_retained_artifacts_and_public_operators_are_byte_exact(
    recomputed: dict[str, Any],
) -> None:
    payload = json.loads(RESULT_PATH.read_bytes())
    assert MODULE._file_sha256(RESULT_PATH) == RESULT_SHA256
    assert MODULE._file_sha256(CAUSAL_PATH) == CAUSAL_SHA256
    assert payload["schema"] == MODULE.SCHEMA
    assert payload["attempt_id"] == "A199"
    assert payload["evidence_stage"] == "PUBLIC_FORMULA_OPERATOR_ATLAS_MIXED_BOUNDARY_RETAINED"
    assert payload["public_input"]["hidden_assignment_present"] is False
    assert payload["operator_sha256"] == OPERATOR_SHA256
    assert payload["operator_gates"] == recomputed["operator_gates"]
    operator_payload = {
        "forward_word_operators": MODULE._q_list(recomputed["forward_operators"]),
        "aligned_inverse_word_operators": MODULE._q_list(recomputed["inverse_operators"]),
    }
    assert MODULE._canonical_sha256(operator_payload) == OPERATOR_SHA256
    for matrix in (recomputed["forward_operators"], recomputed["inverse_operators"]):
        assert matrix.shape == (20, 16, 16)
        assert np.isfinite(matrix).all()
        assert np.max(np.abs(matrix.sum(axis=1) - 1.0)) <= 1e-12


def test_a199_t01_order_nonclosure_and_phase_control_recompute_exactly(
    recomputed: dict[str, Any],
) -> None:
    payload = json.loads(RESULT_PATH.read_bytes())
    result = recomputed["T01"]
    assert MODULE._canonical_sha256(result) == T01_SHA256 == payload["T01_sha256"]
    assert result == payload["T01"]
    assert result["prediction_retained"] is True
    assert result["adjacent_summary"] == {
        "minimum": 0.514697778819,
        "mean": 0.52158921895,
        "maximum": 0.528689138102,
    }
    assert result["lag2_summary"] == {
        "minimum": 0.006616527349,
        "mean": 0.013002274002,
        "maximum": 0.023701318633,
    }
    assert result["adjacent_summary"]["mean"] / result["lag2_summary"]["mean"] > 40.0
    assert result["depth_products"][-1]["forward_reverse_relative_frobenius"] == (0.017336635791)
    assert result["depth_products"][-1]["chronological_dobrushin"] == 1e-12
    assert result["maximum_adjoint_identity_error"] == 0.0


def test_a199_t02_retains_the_predeclared_triplet_boundary_exactly(
    recomputed: dict[str, Any],
) -> None:
    payload = json.loads(RESULT_PATH.read_bytes())
    result = recomputed["T02"]
    assert MODULE._canonical_sha256(result) == T02_SHA256 == payload["T02_sha256"]
    assert result == payload["T02"]
    assert result["triplet_count"] == 1140
    assert result["sample_key_bit_rows"] == 1280
    assert len(result["null_l2_norms"]) == 32
    assert result["same_marginals_exact"] is True
    assert result["observed_l2_norm"] == 1.0990101174e-05
    assert result["null_97_5_percentile_higher"] == 1.127894423e-05
    assert result["observed_to_null_mean_ratio"] == 1.019311642184
    assert result["empirical_upper_p_value"] == 0.272727272727
    assert result["prediction_retained"] is False


def test_a199_t03_stable_derivative_root_view_recomputes_all_40_gates(
    recomputed: dict[str, Any],
) -> None:
    payload = json.loads(RESULT_PATH.read_bytes())
    result = recomputed["T03"]
    assert MODULE._canonical_sha256(result) == T03_SHA256 == payload["T03_sha256"]
    assert result == payload["T03"]
    assert result["diagnostic_count"] == 40
    assert result["maximum_gate_error"] == 6.798995e-09
    assert result["prediction_retained"] is True
    rows = [*result["local_operators"], *result["cumulative_products"]]
    assert len(rows) == 40
    assert all(row["gate_passed"] for row in rows)
    assert all(row["maximum_gate_error"] <= MODULE.ROOT_TOLERANCE for row in rows)


def test_a199_t04_t05_public_geometry_is_exact_complete_and_disjoint(
    recomputed: dict[str, Any],
) -> None:
    payload = json.loads(RESULT_PATH.read_bytes())
    t04 = recomputed["T04"]
    t05 = recomputed["T05"]
    assert MODULE._canonical_sha256(t04) == T04_SHA256 == payload["T04_sha256"]
    assert MODULE._canonical_sha256(t05) == T05_SHA256 == payload["T05_sha256"]
    assert t04 == payload["T04"]
    assert t05 == payload["T05"]
    assert t04["chosen_mask_hex_order"] == [
        "0x0087f",
        "0x00c7f",
        "0x10c7f",
        "0x12c7f",
        "0x1ac7f",
    ]
    assert {row["mode_index"] for row in t04["chosen_masks"]} == {1}
    assert t04["spectral_partition"]["binary_rank"] == 5
    assert t04["spectral_partition"]["cell_histogram"] == [1 << 15] * 32
    assert t04["spectral_partition"]["complete_candidate_count"] == 1 << 20
    assert t04["spectral_partition"]["syndrome_map_sha256"] == (
        "7d5f36876224beb1fa9981a161c6217b227aaa31e7a8549dcd7ba64edff93507"
    )
    assert t05["signed_channel_relative_frobenius"] == 0.244046475056
    assert t05["physical_sum_copy_swap_error"] == 0.0
    assert t05["signed_difference_copy_swap_error"] == 0.0
    assert t05["cross_copy_effective_rank_1e_10"] == 20
    assert t04["prediction_retained"] is t05["prediction_retained"] is True


def test_a199_native_causal_reader_opens_the_exact_eight_edge_dag() -> None:
    payload = json.loads(RESULT_PATH.read_bytes())
    reader = MODULE.CryptoCausalReader(CAUSAL_PATH)
    assert reader.file_sha256 == CAUSAL_SHA256
    assert reader.graph_sha256 == CAUSAL_GRAPH_SHA256
    assert reader.verify_provenance() is True
    assert payload["causal"]["explicit_triplets"] == 8
    rows = reader.triplets(include_inferred=False)
    by_id = {row["edge_id"]: row for row in rows}
    assert len(rows) == 8
    assert by_id["a199-formula-audit-anchor"]["provenance"] == []
    assert by_id["a199-a198-boundary-anchor"]["provenance"] == []
    assert by_id["a199-public-cha-cha-operators"]["provenance"] == ["a199-formula-audit-anchor"]
    assert by_id["a199-t01-ordered-products"]["provenance"] == ["a199-public-cha-cha-operators"]
    assert by_id["a199-t02-triplet-cumulants"]["provenance"] == ["a199-formula-audit-anchor"]
    assert by_id["a199-t03-derivative-roots"]["provenance"] == ["a199-public-cha-cha-operators"]
    assert by_id["a199-t05-sum-difference"]["provenance"] == ["a199-public-cha-cha-operators"]
    assert by_id["a199-t04-public-partition"]["provenance"] == [
        "a199-a198-boundary-anchor",
        "a199-t05-sum-difference",
    ]

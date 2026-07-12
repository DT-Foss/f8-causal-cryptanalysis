from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

ROOT = Path(__file__).parents[1]
MODULE_PATH = ROOT / "research" / "experiments" / "chacha20_phase_conjugacy_holdout.py"
SPEC = importlib.util.spec_from_file_location(
    "chacha20_phase_conjugacy_holdout_tested", MODULE_PATH
)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)

RESULTS = ROOT / "research" / "results" / "v1"
PROTOCOL_PATH = ROOT / "research" / "configs" / MODULE.PROTOCOL_FILENAME
RESULT_PATH = RESULTS / MODULE.RESULT_FILENAME
CAUSAL_PATH = RESULTS / MODULE.CAUSAL_FILENAME

RUNNER_SHA256 = "2e73950e1f4e703de015326b705a82bd1e8944f2c8d1534757b6a5dd465a4f2c"
RESULT_SHA256 = "c186da54770b520153f94b0b9f72e809d6b78d950a52bee39d74ea9c15194767"
CAUSAL_SHA256 = "adfb1e7e3390b67725587373dac8423b20a4873bd46a278bdd4d97ac672816d8"
CAUSAL_GRAPH_SHA256 = "705d302c02ae943c8e4543ecc9c1265b84b07e53b99d00e5ca4d05a9bc41fe4a"
BATCH_SHA256 = "0d35134eb1e8afe9766abf89bb00d29e2748c2df404ba39453e10131eaad43de"
SUMMARY_SHA256 = "37b42187a07e231aee8b66d6177911b9914a7bcb881688d747cc736be47bfb3a"
PREDICTION_SHA256 = "7ac0f1a1dd05765e329c9490e388c4f9047ceff5a803300424c3466ad7fb3891"


def test_a201_frozen_protocol_runner_and_public_boundary_are_exact() -> None:
    protocol = MODULE._load_protocol(RESULTS)
    assert MODULE._file_sha256(PROTOCOL_PATH) == MODULE.PROTOCOL_SHA256
    assert MODULE._file_sha256(MODULE_PATH) == RUNNER_SHA256
    assert protocol["protocol_state"] == (
        "frozen_after_A199_discovery_conjugacy_audit_before_any_A201_holdout_measurement"
    )
    assert protocol["holdout_plan"]["batch_count"] == 8
    assert protocol["holdout_plan"]["sample_count_per_batch"] == 16
    assert (
        protocol["holdout_plan"]["word_permutation_new_position_gets_old_position"]
        == MODULE.PERMUTATION.tolist()
    )
    assert protocol["information_boundary"] == {
        "A201_holdout_measurements_used_before_protocol_freeze": False,
        "hidden_cipher_assignment_used": False,
        "permutation_fitted_to_holdout_data": False,
        "seed_batch_or_threshold_changed_after_any_holdout_measurement": False,
    }


def test_a201_all_eight_public_batches_recompute_byte_exactly() -> None:
    payload = json.loads(RESULT_PATH.read_bytes())
    recomputed = [MODULE._batch_metrics(index) for index in range(MODULE.BATCH_COUNT)]
    assert recomputed == payload["batches"]
    assert MODULE._canonical_sha256(recomputed) == BATCH_SHA256
    assert payload["batch_sha256"] == BATCH_SHA256
    assert [batch["batch_index"] for batch in recomputed] == list(range(8))
    assert len({batch["public_states_sha256"] for batch in recomputed}) == 8
    assert len({batch["operator_forward_sha256"] for batch in recomputed}) == 8
    assert all(batch["inverse_roundtrip_exact"] for batch in recomputed)
    assert all(all(batch["predictions"].values()) for batch in recomputed)


def test_a201_retained_summary_and_five_predictions_are_exact() -> None:
    payload = json.loads(RESULT_PATH.read_bytes())
    assert MODULE._file_sha256(RESULT_PATH) == RESULT_SHA256
    assert MODULE._file_sha256(CAUSAL_PATH) == CAUSAL_SHA256
    assert payload["schema"] == MODULE.SCHEMA
    assert payload["attempt_id"] == "A201"
    assert payload["evidence_stage"] == "PUBLIC_CHACHA_PHASE_CONJUGACY_HOLDOUT_RETAINED"
    assert payload["parameters"]["hidden_assignment_present"] is False
    assert payload["summary"] == {
        "aligned_mean_operator_distance_range": [0.003605606397, 0.00693567577],
        "aligned_to_lag2_ratio_range": [0.896365770018, 1.152298962767],
        "correctly_aligned_adjacent_mean_range": [0.011691218573, 0.015537430753],
        "raw_adjacent_mean_range": [0.519377937285, 0.522234010744],
        "raw_to_aligned_ratio_range": [33.442854286179, 44.473808424522],
        "wrongly_aligned_adjacent_mean_range": [0.166456108432, 0.168060976184],
    }
    assert MODULE._canonical_sha256(payload["summary"]) == SUMMARY_SHA256
    assert payload["summary_sha256"] == SUMMARY_SHA256
    assert MODULE._canonical_sha256(payload["predictions"]) == PREDICTION_SHA256
    assert payload["prediction_sha256"] == PREDICTION_SHA256
    assert set(payload["predictions"]) == {
        "H1_layout_dominance",
        "H2_same_phase_scale",
        "H3_operator_alignment",
        "H4_wrong_direction_control",
        "H5_residual_channel",
    }
    assert all(
        row
        == {
            "batch_count": 8,
            "retained_batch_count": 8,
            "retained_in_every_batch": True,
        }
        for row in payload["predictions"].values()
    )
    assert payload["all_predictions_retained_in_every_batch"] is True


def test_a201_correct_conjugacy_dominates_with_nonzero_residual_in_every_batch() -> None:
    batches = json.loads(RESULT_PATH.read_bytes())["batches"]
    for batch in batches:
        assert batch["raw_to_correctly_aligned_ratio"] > 20.0
        assert 0.5 <= batch["aligned_to_lag2_ratio"] <= 2.0
        assert batch["aligned_column_diagonal_mean_operator_distance"] < 0.02
        assert batch["wrongly_aligned_adjacent_commutator_mean"] > 0.10
        assert batch["correctly_aligned_adjacent_commutator_mean"] > 0.003
        assert batch["wrongly_aligned_adjacent_commutator_mean"] > (
            10 * batch["correctly_aligned_adjacent_commutator_mean"]
        )


def test_a201_native_reader_opens_the_exact_five_edge_chain() -> None:
    reader = MODULE.CryptoCausalReader(CAUSAL_PATH)
    assert reader.file_sha256 == CAUSAL_SHA256
    assert reader.graph_sha256 == CAUSAL_GRAPH_SHA256
    assert reader.verify_provenance() is True
    rows = reader.triplets(include_inferred=False)
    by_id = {row["edge_id"]: row for row in rows}
    ids = [
        "chacha20-a201-a199-order-anchor",
        "chacha20-a201-public-layout-conjugacy",
        "chacha20-a201-eight-holdout-batches",
        "chacha20-a201-correct-wrong-conjugation-controls",
        "chacha20-a201-phase-mechanism-attribution",
    ]
    assert len(rows) == 5
    assert set(by_id) == set(ids)
    assert [by_id[edge_id]["provenance"] for edge_id in ids] == [
        [],
        [ids[0]],
        [ids[1]],
        [ids[2]],
        [ids[3]],
    ]
    assert all(
        by_id[left]["outcome"] == by_id[right]["trigger"]
        for left, right in zip(ids[:-1], ids[1:], strict=True)
    )

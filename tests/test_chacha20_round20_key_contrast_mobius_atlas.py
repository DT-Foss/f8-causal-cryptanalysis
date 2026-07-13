from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

import numpy as np
import pytest

from arx_carry_leak.crypto_causal import CryptoCausalReader


ROOT = Path(__file__).parents[1]
RUNNER_PATH = (
    ROOT
    / "research"
    / "experiments"
    / "chacha20_round20_key_contrast_mobius_atlas.py"
)
SPEC = importlib.util.spec_from_file_location("a215_key_contrast_test", RUNNER_PATH)
assert SPEC is not None and SPEC.loader is not None
RUNNER = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = RUNNER
SPEC.loader.exec_module(RUNNER)
MEASUREMENT_PATH = (
    ROOT
    / "research/results/v1/chacha20_round20_key_contrast_mobius_atlas_v1_measurements.npz"
)
REQUIRES_ARCHIVED_A215_MEASUREMENTS = pytest.mark.skipif(
    not MEASUREMENT_PATH.is_file(),
    reason="145 MB A215 raw measurement archive is hash-pinned but excluded from the public Git tree",
)


def test_protocol_training_and_holdout_freeze() -> None:
    protocol = RUNNER._load_protocol()
    public = RUNNER._load_public_challenge(protocol)
    training, ledger = RUNNER._training_ledger()
    holdouts = RUNNER._shake_holdouts(set(int(value) for value in training))

    assert protocol["attempt_id"] == RUNNER.ATTEMPT_ID
    assert public["rounds"] == 20
    assert len(training) == len(ledger) == 5404
    assert len(np.unique(training)) == 5404
    assert len(holdouts) == len(np.unique(holdouts)) == 1024
    assert not np.intersect1d(training, holdouts).size
    assert RUNNER._sha256(holdouts.astype("<u4").tobytes()) == RUNNER._sha256(
        RUNNER._shake_holdouts(set(int(value) for value in training))
        .astype("<u4")
        .tobytes()
    )


def test_accuracy_majority_distance_and_rank_utilities() -> None:
    actual = np.zeros((2, 1, 1, 2), dtype=np.uint32)
    predicted = actual.copy()
    predicted[1, 0, 0, 0] = 1
    metrics = RUNNER._accuracy_rows(predicted, actual)[0]
    assert metrics["error_bits"] == 1
    assert metrics["bit_accuracy"] == 127 / 128
    assert metrics["exact_words"] == 3
    assert metrics["exact_blocks"] == 1
    assert metrics["exact_keys_all_8_blocks"] == 1

    centers = np.asarray(
        [
            [[0b0000]],
            [[0b0011]],
            [[0b0101]],
            [[0b0110]],
        ],
        dtype=np.uint32,
    )
    majority = RUNNER._majority_four_with_nearest_tie(centers, np.asarray([0]))
    assert int(majority[0, 0]) == 0

    table = np.asarray([[[0]], [[1]], [[3]], [[7]]], dtype=np.uint32)
    targets = np.asarray([[[0]], [[7]]], dtype=np.uint32)
    distances = RUNNER._distance_rows(table, targets, chunk_size=2)
    assert distances.tolist() == [[0, 1, 2, 3], [3, 2, 1, 0]]
    assert RUNNER._rank_from_distances(distances[0], 0) == 1
    assert RUNNER._rank_from_distances(np.asarray([1, 1, 1]), 1) == 2


def test_postseal_target_reveal_uses_retained_confirmations() -> None:
    target, manifest = RUNNER._postseal_target_low20()

    assert target == 0xE4934
    assert manifest["target_reveal_after_prereveal"] is True
    assert manifest["independent_confirmed_modes"] == 2


@REQUIRES_ARCHIVED_A215_MEASUREMENTS
def test_retained_a215_artifacts_and_information_boundary() -> None:
    result_path = (
        ROOT / "research/results/v1/chacha20_round20_key_contrast_mobius_atlas_v1.json"
    )
    prereveal_path = (
        ROOT
        / "research/results/v1/chacha20_round20_key_contrast_mobius_atlas_v1_prereveal.json"
    )
    measurement_path = (
        ROOT
        / "research/results/v1/chacha20_round20_key_contrast_mobius_atlas_v1_measurements.npz"
    )
    causal_path = (
        ROOT / "research/results/v1/chacha20_round20_key_contrast_mobius_atlas_v1.causal"
    )
    result = json.loads(result_path.read_bytes())
    prereveal = json.loads(prereveal_path.read_bytes())

    assert RUNNER._file_sha256(result_path) == (
        "85448ceec849c8d65f088efd1abdf156c0b9f9f57145429e292606bec6fe9700"
    )
    assert RUNNER._file_sha256(prereveal_path) == (
        "aad591b55094f50497ebf19c0399bfae2c6e33c8d1e3c3cfdae764ef50813839"
    )
    assert RUNNER._file_sha256(measurement_path) == (
        "882ae2504851f1bac1f2350f8c160dba6cddd5b03afc4eb09f2252fc9b8cb5ff"
    )
    assert RUNNER._file_sha256(causal_path) == (
        "223edf9cdaaef9fa61c73238070d3211ec5382f9a4593dbfcf764270c8eedc31"
    )
    assert prereveal["target_key_available"] is False
    assert prereveal["target_ciphertext_used_for_model_selection"] is False
    assert "target_reveal" not in prereveal
    assert result["prereveal_sha256"] == RUNNER._file_sha256(prereveal_path)
    assert result["target_reveal"]["target_low20"] == 0xE4934
    assert result["target_reveal"]["target_reveal_after_prereveal"] is True
    assert result["evidence_stage"] == (
        "R3_RAW_OUTPUT_DEGREE_SATURATION_AND_R20_LOW_ORDER_REPRESENTATION_BOUNDARY"
    )
    assert result["target_ranks"]["selected_model_rank"] == 985694
    assert result["selected_validation_model"]["summary"][
        "beats_all_key_label_nulls"
    ] is False
    assert prereveal["degree_atlas"]["carry_free_degree_2_or_3_active_bits"] == 0
    order3 = next(
        row for row in prereveal["validation"]["nearest_center"] if row["order"] == 3
    )
    round20 = next(row for row in order3["rounds"] if row["round"] == 20)
    assert abs(round20["bit_accuracy"] - 0.5) < 0.001
    reader = CryptoCausalReader(causal_path)
    assert reader.verify_provenance()
    assert reader.graph_sha256 == result["causal_artifact"]["graph_sha256"]


@REQUIRES_ARCHIVED_A215_MEASUREMENTS
def test_retained_measurement_shapes() -> None:
    path = (
        ROOT
        / "research/results/v1/chacha20_round20_key_contrast_mobius_atlas_v1_measurements.npz"
    )
    with np.load(path, allow_pickle=False) as measurement:
        assert set(measurement.files) == {
            "training_low20",
            "holdout_low20",
            "masks",
            "centers",
            "factual_core",
            "factual_output",
            "carry_free_core",
            "carry_free_output",
            "carry_out",
            "carry_in",
        }
        assert measurement["training_low20"].shape == (5404,)
        assert measurement["holdout_low20"].shape == (1024,)
        assert measurement["factual_output"].shape == (4, 1351, 21, 8, 16)
        assert measurement["carry_out"].shape == (4, 1351, 20, 4, 4)

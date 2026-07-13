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
    / "chacha20_round20_multifrequency_selection_matched_null.py"
)
SPEC = importlib.util.spec_from_file_location("a216n_selection_null_test", RUNNER_PATH)
assert SPEC is not None and SPEC.loader is not None
RUNNER = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = RUNNER
SPEC.loader.exec_module(RUNNER)
A215_MEASUREMENT_PATH = (
    ROOT
    / "research/results/v1/chacha20_round20_key_contrast_mobius_atlas_v1_measurements.npz"
)
REQUIRES_ARCHIVED_A215_MEASUREMENTS = pytest.mark.skipif(
    not A215_MEASUREMENT_PATH.is_file(),
    reason="145 MB A215 raw measurement archive is hash-pinned but excluded from the public Git tree",
)


@REQUIRES_ARCHIVED_A215_MEASUREMENTS
def test_protocol_and_frozen_A216_anchors() -> None:
    protocol = RUNNER._load_protocol()
    result, prereveal, training_keys, validation_keys, training, validation = (
        RUNNER._load_frozen_inputs()
    )

    assert protocol["attempt_id"] == RUNNER.ATTEMPT_ID
    assert result["prereveal"] == prereveal
    assert result["target_rank"] == 1_041_965
    assert len(training_keys) == 5404
    assert len(validation_keys) == 1024
    assert not np.intersect1d(training_keys, validation_keys).size
    assert set(training) == set(RUNNER.REPRESENTATIONS)
    assert set(validation) == set(RUNNER.REPRESENTATIONS)


def test_optimized_five_shrinkage_scores_equal_direct_negative_mse() -> None:
    rng = np.random.default_rng(0xA2160)
    training = rng.normal(size=(79, 37)).astype(np.float32)
    validation = np.asfortranarray(rng.normal(size=(31, 37)).astype(np.float32))
    labels = np.tile(np.arange(16, dtype=np.uint8), 5)[: len(training)]
    rng.shuffle(labels)

    with np.errstate(all="raise"):
        observed, counts = RUNNER._all_shrinkage_scores(
            training, validation, labels
        )
    means, expected_counts = RUNNER._class_means(training, labels)
    global_mean = training.mean(axis=0)

    assert np.array_equal(counts, expected_counts)
    for shrinkage, scores in zip(RUNNER.SHRINKAGES, observed, strict=True):
        prototypes = (
            (1.0 - shrinkage) * means.astype(np.float64)
            + shrinkage * global_mean.astype(np.float64)[None, :]
        )
        expected = -np.mean(
            (
                validation.astype(np.float64)[:, None, :]
                - prototypes[None, :, :]
            )
            ** 2,
            axis=2,
        )
        assert scores.dtype == np.float64
        assert np.all(np.isfinite(scores))
        assert np.allclose(scores, expected, atol=2e-14, rtol=2e-14)


@REQUIRES_ARCHIVED_A215_MEASUREMENTS
def test_observed_optimizer_exactly_replays_A216() -> None:
    result, _prereveal, training_keys, validation_keys, training, validation = (
        RUNNER._load_frozen_inputs()
    )
    observed = RUNNER._observed_replay(
        result, training_keys, validation_keys, training, validation
    )

    assert [row["representation_index"] for row in observed] == [2, 2, 1, 2, 3]
    assert [row["shrinkage_index"] for row in observed] == [4, 0, 2, 3, 3]
    assert [row["validation"]["top1_accuracy"] for row in observed] == [
        0.0751953125,
        0.08203125,
        0.076171875,
        0.080078125,
        0.072265625,
    ]


def test_add_one_upper_tail_and_stage_rules() -> None:
    test = RUNNER._upper_tail_add_one(0.3, [0.1, 0.2, 0.3, 0.4])
    assert test["null_greater_or_equal_observed"] == 2
    assert test["add_one_upper_tail_p_value"] == 3 / 5
    assert test["strictly_beats_all_nulls"] is False

    macro = {"strictly_beats_all_nulls": True}
    groups = [{"strictly_beats_all_nulls": False} for _ in range(5)]
    assert (
        RUNNER._evidence_stage({"macro": macro, "groups": groups})
        == "SELECTION_MATCHED_MULTIFREQUENCY_TRANSFER_CONFIRMED"
    )
    macro["strictly_beats_all_nulls"] = False
    groups[2]["strictly_beats_all_nulls"] = True
    assert (
        RUNNER._evidence_stage({"macro": macro, "groups": groups})
        == "GROUP_SPECIFIC_SELECTION_MATCHED_MULTIFREQUENCY_TRANSFER_CONFIRMED"
    )
    groups[2]["strictly_beats_all_nulls"] = False
    assert (
        RUNNER._evidence_stage({"macro": macro, "groups": groups})
        == "MULTIFREQUENCY_MODEL_SELECTION_EXPLAINED"
    )


def test_retained_A216N_artifacts_if_present() -> None:
    result_path = (
        ROOT
        / "research/results/v1/chacha20_round20_multifrequency_selection_matched_null_v1.json"
    )
    causal_path = result_path.with_suffix(".causal")
    if not result_path.exists() or not causal_path.exists():
        return
    result = json.loads(result_path.read_bytes())
    reader = CryptoCausalReader(causal_path)
    assert result["protocol_sha256"] == RUNNER.PROTOCOL_SHA256
    assert result["observed_replay_exact"] is True
    assert result["target_evaluation_performed"] is False
    assert reader.verify_provenance()
    assert reader.graph_sha256 == result["causal_artifact"]["graph_sha256"]

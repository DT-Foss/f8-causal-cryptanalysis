from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import numpy as np
import pytest

ROOT = Path(__file__).parents[1]
RUNNER_PATH = (
    ROOT
    / "research"
    / "experiments"
    / "chacha20_round20_multifrequency_group_readout.py"
)
SPEC = importlib.util.spec_from_file_location("a216_multifrequency_test", RUNNER_PATH)
assert SPEC is not None and SPEC.loader is not None
RUNNER = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = RUNNER
SPEC.loader.exec_module(RUNNER)
A215_MEASUREMENT_PATH = (
    ROOT
    / "research/results/v1/chacha20_round20_key_contrast_mobius_atlas_v1_measurements.npz"
)


@pytest.mark.skipif(
    not A215_MEASUREMENT_PATH.is_file(),
    reason="145 MB A215 raw measurement archive is hash-pinned but excluded from the public Git tree",
)
def test_protocol_and_a215_ledgers() -> None:
    protocol = RUNNER._load_protocol()
    training, validation, prereveal = RUNNER._load_ledgers()

    assert protocol["attempt_id"] == RUNNER.ATTEMPT_ID
    assert len(training) == 5404
    assert len(validation) == 1024
    assert not np.intersect1d(training, validation).size
    assert prereveal["target_key_available"] is False


def test_feature_shapes_and_fourier_identity() -> None:
    outputs = np.arange(3 * 8 * 16, dtype=np.uint32).reshape(3, 8, 16)
    features = RUNNER._feature_representations(outputs)

    assert features["raw_output_bits_pm1"].shape == (3, 4096)
    assert features["adjacent_block_xor_bits_pm1"].shape == (3, 3584)
    assert features["per_block_byte_histograms"].shape == (3, 256)
    assert features["per_block_bit_rfft_magnitudes"].shape == (3, 2056)
    assert set(np.unique(features["raw_output_bits_pm1"])) <= {-1.0, 1.0}

    rng = np.random.default_rng(216)
    means = rng.normal(size=(16, 23)).astype(np.float32)
    bank, error = RUNNER._character_bank(means)
    reconstructed = np.fft.ifft(bank * 16, axis=0).real
    assert error <= 1e-10
    assert np.allclose(reconstructed, means, atol=1e-10, rtol=0)


def test_scores_rank_and_candidate_factorization() -> None:
    features = np.asarray([[0.0, 0.0], [1.0, 1.0]], dtype=np.float32)
    prototypes = np.zeros((16, 2), dtype=np.float32)
    prototypes[3] = 1.0
    scores = RUNNER._scores(features, prototypes)
    metrics = RUNNER._rank_metrics(scores, np.asarray([0, 3], dtype=np.uint8))

    assert metrics["top1_accuracy"] == 1.0
    group_scores = [np.arange(16, dtype=np.float64) for _ in range(5)]
    candidates = RUNNER._candidate_scores(group_scores)
    assert len(candidates) == 1 << 20
    assert RUNNER._exact_rank(candidates, (1 << 20) - 1) == 1
    assert RUNNER._exact_rank(np.zeros(8), 3) == 4


def test_scores_are_stable_for_float32_fortran_layout() -> None:
    rng = np.random.default_rng(0xA216)
    features = np.asfortranarray(rng.normal(size=(31, 257)).astype(np.float32))
    prototypes = rng.normal(size=(16, 257)).astype(np.float32)

    with np.errstate(all="raise"):
        observed = RUNNER._scores(features, prototypes)
    expected = -np.mean(
        (
            features.astype(np.float64)[:, None, :]
            - prototypes.astype(np.float64)[None, :, :]
        )
        ** 2,
        axis=2,
    )

    assert observed.dtype == np.float64
    assert np.all(np.isfinite(observed))
    assert np.allclose(observed, expected, atol=1e-12, rtol=1e-12)

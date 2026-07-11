import numpy as np
import pytest

from arx_carry_leak.differential import differential_metrics, repairing_analysis


def test_differential_metrics_detects_fixed_difference() -> None:
    difference = np.zeros((1000, 16), dtype=np.uint8)
    metrics = differential_metrics(difference)
    assert metrics["entropy_deficit_sum"] == 128.0
    assert metrics["maximum_absolute_bit_probability_bias"] == 0.5


def test_repairing_analysis_separates_chosen_from_random_pairing() -> None:
    rng = np.random.default_rng(7)
    first = rng.integers(0, 256, size=(4000, 16), dtype=np.uint8)
    second = first ^ np.uint8(1)
    result = repairing_analysis(first, second, routes=4, seed=8)
    assert result["effects"]["entropy_deficit_sum"]["difference"] > 100


def test_repairing_analysis_validates_input() -> None:
    values = np.zeros((10, 2), dtype=np.uint8)
    with pytest.raises(ValueError):
        repairing_analysis(values, values[:, :1], routes=4, seed=1)
    with pytest.raises(ValueError):
        differential_metrics(values.astype(np.uint16))

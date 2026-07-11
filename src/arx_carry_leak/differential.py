"""Generic statistics for paired cipher-output differential experiments."""

from __future__ import annotations

from typing import Any

import numpy as np


def entropy(values: np.ndarray, bins: int = 256) -> float:
    counts = np.bincount(np.asarray(values, dtype=np.int64), minlength=bins)
    probabilities = counts[counts > 0] / counts.sum()
    return -float(np.sum(probabilities * np.log2(probabilities)))


def differential_metrics(difference: np.ndarray) -> dict[str, float]:
    """Summarize byte entropy and bit bias for an (n, width) XOR difference."""
    if difference.ndim != 2 or difference.dtype != np.uint8 or len(difference) < 2:
        raise ValueError("difference must be a uint8 matrix with at least two rows")
    n, width = difference.shape
    deficits = np.asarray(
        [8.0 - entropy(difference[:, position]) for position in range(width)]
    )
    bits = np.unpackbits(difference, axis=1)
    ones = bits.sum(axis=0).astype(float)
    chi2 = 4.0 * (ones - n / 2.0) ** 2 / n
    probabilities = ones / n
    return {
        "entropy_deficit_sum": float(deficits.sum()),
        "maximum_byte_entropy_deficit": float(deficits.max()),
        "mean_bit_bias_chi2": float(chi2.mean()),
        "maximum_bit_bias_chi2": float(chi2.max()),
        "maximum_absolute_bit_probability_bias": float(np.max(np.abs(probabilities - 0.5))),
    }


def repairing_analysis(
    first: np.ndarray,
    second: np.ndarray,
    *,
    routes: int,
    seed: int,
) -> dict[str, Any]:
    """Compare the chosen pairing with independent row re-pairings."""
    if first.shape != second.shape or first.dtype != np.uint8 or first.ndim != 2:
        raise ValueError("first and second must be equally shaped uint8 matrices")
    if routes < 2:
        raise ValueError("at least two control routes are required")
    actual = differential_metrics(first ^ second)
    rng = np.random.default_rng(seed)
    controls = [
        differential_metrics(first ^ second[rng.permutation(len(second))])
        for _ in range(routes)
    ]
    effects: dict[str, Any] = {}
    for metric, actual_value in actual.items():
        values = np.asarray([row[metric] for row in controls], dtype=float)
        sd = float(values.std(ddof=1))
        difference = float(actual_value - values.mean())
        effects[metric] = {
            "difference": difference,
            "control_mean": float(values.mean()),
            "control_sd_ddof1": sd,
            "route_z": 0.0 if sd <= 1e-12 else difference / sd,
            "control_degenerate": sd <= 1e-12,
        }
    return {"actual": actual, "controls": controls, "effects": effects}

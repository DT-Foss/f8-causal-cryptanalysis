from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import numpy as np

ROOT = Path(__file__).parents[1]
RUNNER_PATH = (
    ROOT
    / "research"
    / "experiments"
    / "chacha20_round20_operator_diversity_audit.py"
)
SPEC = importlib.util.spec_from_file_location("a217_operator_diversity_test", RUNNER_PATH)
assert SPEC is not None and SPEC.loader is not None
RUNNER = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = RUNNER
SPEC.loader.exec_module(RUNNER)


def test_rank_correlations_and_ties() -> None:
    increasing = np.arange(8, dtype=np.float64)
    decreasing = increasing[::-1]
    assert RUNNER._spearman(increasing, increasing) == 1.0
    assert RUNNER._spearman(increasing, decreasing) == -1.0
    assert RUNNER._kendall_tau_b(increasing, increasing) == 1.0
    assert RUNNER._kendall_tau_b(increasing, decreasing) == -1.0
    assert np.array_equal(
        RUNNER._rank_average(np.asarray([1.0, 1.0, 3.0])),
        np.asarray([1.5, 1.5, 3.0]),
    )


def test_linear_cka_controls() -> None:
    rng = np.random.default_rng(217)
    matrix = RUNNER._standardize(rng.normal(size=(256, 3)))
    assert np.isclose(RUNNER._linear_cka(matrix, matrix), 1.0, atol=1e-14)
    shuffled = matrix[rng.permutation(len(matrix))]
    assert RUNNER._linear_cka(matrix, shuffled) < 0.1


def test_retained_pair_gates() -> None:
    _protocol, retained = RUNNER._load()
    extracted = RUNNER._extract(retained)
    assert extracted["numeric"].shape == (256, 3)
    assert extracted["gray"].shape == (256, 3)
    assert all(extracted["statuses_equal"])
    assert extracted["same_model"] is True
    assert extracted["recovered_unknown_low20"] == 0xE4934

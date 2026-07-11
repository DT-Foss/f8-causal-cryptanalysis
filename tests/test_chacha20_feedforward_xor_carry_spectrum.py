from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import numpy as np

from arx_carry_leak.crypto_causal import CryptoCausalReader


_SCRIPT = (
    Path(__file__).parents[1]
    / "research"
    / "experiments"
    / "chacha20_feedforward_xor_carry_spectrum.py"
)
_SPEC = importlib.util.spec_from_file_location(
    "chacha20_feedforward_xor_carry_spectrum", _SCRIPT
)
assert _SPEC is not None and _SPEC.loader is not None
_SPECTRUM = importlib.util.module_from_spec(_SPEC)
sys.modules[_SPEC.name] = _SPECTRUM
_SPEC.loader.exec_module(_SPECTRUM)


def test_chacha20_conditional_carry_prediction_extremes() -> None:
    zero = np.zeros((1, 16), dtype=np.uint32)
    predicted_zero, expected_zero_words = _SPECTRUM._conditional_prediction(
        zero, _SPECTRUM.CARRY_RECIPE
    )
    assert np.all(predicted_zero == 1.0)
    assert expected_zero_words == 16.0

    ones = np.full((1, 16), np.uint32(0xFFFFFFFF), dtype=np.uint32)
    predicted_ones, expected_ones_words = _SPECTRUM._conditional_prediction(
        ones, _SPECTRUM.CARRY_RECIPE
    )
    assert np.all(predicted_ones[:, 0] == 1.0)
    assert np.all(predicted_ones[:, 1] == 0.5)
    assert expected_ones_words == 16 * 2.0**-31


def test_chacha20_exact_carry_identities_on_fullround_states() -> None:
    rng = np.random.default_rng(89328001)
    row = _SPECTRUM._empirical_seed(
        _SPECTRUM._BASE._fixed_key_inputs(rng, 257),
        _SPECTRUM.CARRY_RECIPE,
    )
    assert row["carry_identity_accuracy"] == 1.0
    assert row["carry_identity_matches"] == row["carry_identity_total"]
    observed = np.asarray(row["observed_accuracy"])
    assert np.all(observed[:, 0] == 1.0)


def test_chacha20_carry_recipe_is_loaded_from_causal(tmp_path: Path) -> None:
    path = tmp_path / "chacha20-carry.causal"
    _SPECTRUM._build_graph(path, pairs=128, seeds=1)
    recipe, rows = _SPECTRUM._recipe_from_reader(path)
    reader = CryptoCausalReader(path)
    assert reader.verify_provenance()
    assert len(rows) == 3
    assert recipe["exact_match_criterion"].endswith("carry[k] == 0")


def test_chacha20_conditional_prediction_beats_wrong_lane_mapping() -> None:
    rows = []
    for seed_index in range(2):
        rng = np.random.default_rng(89328111 + 1009 * seed_index)
        rows.append(
            _SPECTRUM._empirical_seed(
                _SPECTRUM._BASE._fixed_key_inputs(rng, 1024),
                _SPECTRUM.CARRY_RECIPE,
            )
        )
    pooled = _SPECTRUM._pooled(rows)
    assert pooled["carry_identity_matches"] == pooled["carry_identity_total"]
    assert pooled["analytic_observed_correlation_512_cells"] > 0.999
    assert pooled["wrong_lane_prediction_correlation"] < 0.8
    assert pooled["rmse"] < pooled["wrong_lane_prediction_rmse"]

from __future__ import annotations

import importlib.util
import sys
from fractions import Fraction
from pathlib import Path

import numpy as np

from arx_carry_leak.crypto_causal import CryptoCausalReader


_SCRIPT = (
    Path(__file__).parents[1]
    / "research"
    / "experiments"
    / "blake3_output_borrow_spectrum.py"
)
_SPEC = importlib.util.spec_from_file_location("blake3_output_borrow_spectrum", _SCRIPT)
assert _SPEC is not None and _SPEC.loader is not None
_SPECTRUM = importlib.util.module_from_spec(_SPEC)
sys.modules[_SPEC.name] = _SPECTRUM
_SPEC.loader.exec_module(_SPECTRUM)


def test_blake3_exact_coupled_borrow_transition_matrix() -> None:
    expected = [
        [Fraction(5, 8), Fraction(1, 8), Fraction(1, 8), Fraction(1, 8)],
        [Fraction(1, 4), Fraction(1, 2), Fraction(0), Fraction(1, 4)],
        [Fraction(1, 4), Fraction(0), Fraction(1, 2), Fraction(1, 4)],
        [Fraction(1, 8), Fraction(1, 8), Fraction(1, 8), Fraction(5, 8)],
    ]
    assert _SPECTRUM._derive_transition_matrix() == expected


def test_blake3_analytic_borrow_spectrum_and_word_probability() -> None:
    analytic = _SPECTRUM._analytic_spectrum(_SPECTRUM.BORROW_RECIPE)
    assert analytic["high_match_probability"][0] == 1.0
    assert analytic["low_match_probability"][0] == 1.0
    assert analytic["combined_match_probability"][1] == 0.75
    assert abs(analytic["average_bit_accuracy"] - 0.6059027777741398) < 1e-15
    assert (
        Fraction(analytic["exact_word_match_probability_fraction"])
        == Fraction(3, 4) ** 31
    )


def test_blake3_borrow_identities_hold_on_full_compression_states() -> None:
    rng = np.random.default_rng(89128001)
    row = _SPECTRUM._empirical_seed(_SPECTRUM._BASE._random_inputs(rng, 257))
    assert row["borrow_identity_accuracy"] == 1.0
    assert row["borrow_identity_matches"] == row["borrow_identity_total"]
    assert row["high_bit_accuracy"][0] == 1.0
    assert row["low_bit_accuracy"][0] == 1.0


def test_blake3_borrow_recipe_is_loaded_from_causal(tmp_path: Path) -> None:
    path = tmp_path / "blake3-borrow.causal"
    _SPECTRUM._build_graph(path, pairs=128, seeds=1)
    recipe, rows = _SPECTRUM._recipe_from_reader(path)
    reader = CryptoCausalReader(path)
    assert reader.verify_provenance()
    assert len(rows) == 4
    assert recipe["word_match_probability"] == "(3/4)^31"
    assert _SPECTRUM._analytic_spectrum(recipe)["transition_matrix"] == recipe[
        "transition_matrix"
    ]

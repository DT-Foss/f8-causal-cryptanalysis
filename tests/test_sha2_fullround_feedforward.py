from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import numpy as np
import pytest


_SCRIPT = Path(__file__).parents[1] / "research" / "experiments" / "sha2_fullround_feedforward_causal.py"
_SPEC = importlib.util.spec_from_file_location("sha2_fullround_feedforward_causal", _SCRIPT)
assert _SPEC is not None and _SPEC.loader is not None
_SHA2 = importlib.util.module_from_spec(_SPEC)
sys.modules[_SPEC.name] = _SHA2
_SPEC.loader.exec_module(_SHA2)

_SPECTRUM_SCRIPT = (
    Path(__file__).parents[1]
    / "research"
    / "experiments"
    / "sha2_feedforward_carry_spectrum.py"
)
_SPECTRUM_SPEC = importlib.util.spec_from_file_location(
    "sha2_feedforward_carry_spectrum", _SPECTRUM_SCRIPT
)
assert _SPECTRUM_SPEC is not None and _SPECTRUM_SPEC.loader is not None
_SPECTRUM = importlib.util.module_from_spec(_SPECTRUM_SPEC)
sys.modules[_SPECTRUM_SPEC.name] = _SPECTRUM
_SPECTRUM_SPEC.loader.exec_module(_SPECTRUM)


@pytest.mark.parametrize("name,steps", [("sha256", 64), ("sha512", 80)])
def test_instrumented_sha2_kats_and_constants(name: str, steps: int) -> None:
    variant = _SHA2._VARIANTS[name]
    assert len(_SHA2._constants(variant)) == steps
    kat = _SHA2._kat(variant)
    assert len(kat["vectors"]) == 2
    assert all(row["matches_fixed_standard_vector"] for row in kat["vectors"])
    assert all(row["matches_hashlib"] for row in kat["vectors"])


@pytest.mark.parametrize("name", ["sha256", "sha512"])
def test_full_compression_feedforward_bit0_identity(name: str) -> None:
    variant = _SHA2._VARIANTS[name]
    rng = np.random.default_rng(88428001)
    blocks = rng.integers(0, 256, size=(32, variant.block_bytes), dtype=np.uint8)
    working, output = _SHA2._compress(blocks, variant)
    initial = np.asarray(variant.iv, dtype=variant.dtype)[None, :]
    assert np.array_equal(working & variant.dtype(1), (initial ^ output) & variant.dtype(1))

    random_initial = rng.integers(
        0, 1 << variant.word_bits, size=(32, 8), dtype=variant.dtype
    )
    working, output = _SHA2._compress(blocks, variant, random_initial)
    assert np.array_equal(
        working & variant.dtype(1),
        (random_initial ^ output) & variant.dtype(1),
    )


@pytest.mark.parametrize(
    "name,exact_cells,biased_cells",
    [("sha256", 12, 236), ("sha512", 11, 493)],
)
def test_fixed_iv_carry_spectrum_partition(
    name: str,
    exact_cells: int,
    biased_cells: int,
) -> None:
    variant = _SHA2._VARIANTS[name]
    exact = sum(
        _SPECTRUM._trailing_zeros(word, variant.word_bits) + 1
        for word in variant.iv
    )
    assert exact == exact_cells
    assert 8 * variant.word_bits - exact - 8 == biased_cells

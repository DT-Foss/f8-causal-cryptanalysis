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
    / "shake_anf_compression_cascade.py"
)
_SPEC = importlib.util.spec_from_file_location(
    "shake_anf_compression_cascade", _SCRIPT
)
assert _SPEC is not None and _SPEC.loader is not None
_CASCADE = importlib.util.module_from_spec(_SPEC)
sys.modules[_SPEC.name] = _CASCADE
_SPEC.loader.exec_module(_CASCADE)


def test_binary_pack_writer_reader_roundtrip(tmp_path: Path) -> None:
    matrix = np.array(
        [
            [1, 0, 1, 0, 1, 0, 1, 0],
            [0, 1, 0, 1, 0, 1, 0, 1],
            [1, 1, 0, 0, 1, 1, 0, 0],
        ],
        dtype=np.uint8,
    )
    record = {
        "variant": "SHAKE128",
        "round": 2,
        "window_bits": 3,
        "state_coordinates": 8,
        "assignments": 8,
        "seed": 123,
        "window_start_capacity_bit": 4,
        "window_stop_capacity_bit_exclusive": 7,
        "basis": np.array([0, 1, 6], dtype="<u4"),
        "packed_matrix": np.packbits(matrix, axis=1, bitorder="little").tobytes(),
    }
    path = tmp_path / "test.anfpack"
    stats = _CASCADE._write_pack(path, [record])
    reader = _CASCADE.ANFDictionaryPackReader(path)
    assert stats["records"] == 1
    assert len(reader.records) == 1
    reopened = reader.records[0]
    assert reopened["basis"].tolist() == [0, 1, 6]
    assert np.array_equal(_CASCADE._unpack_matrix(reopened), matrix)


def test_ordered_codec_cascades_are_measured_both_directions() -> None:
    raw = (b"abcdefgh" * 512) + bytes(range(256))
    transformed = b"ANF" + (b"\x00" * 1024) + (b"\xff" * 1024)
    result = _CASCADE._compression_suite(raw, transformed, True)
    for representation in result["representations"].values():
        assert len(representation["first_stage"]) == 3
        assert len(representation["ordered_two_codec_cascades"]) == 6
        assert representation["best_bytes"] > 0
    assert result["best_anf_over_best_raw_size_gain"] > 0


def test_small_complete_state_pack_reconstructs_every_truth_value() -> None:
    variant = _CASCADE._BASE.VARIANTS["shake128"]
    window_bits = 8
    seed = 89806001
    rng = np.random.default_rng(seed)
    message = rng.integers(
        0, 256, size=(1, variant.message_bytes), dtype=np.uint8
    )
    base_state, _ = _CASCADE._BASE._first_squeeze_state(message, variant)
    positions = _CASCADE._WINDOW._window_positions(
        variant.capacity_bits, window_bits, seed ^ 0xC05CADE
    )
    template = _CASCADE._WINDOW._clear_window(base_state, variant, positions)
    state = _CASCADE._BITSLICED._candidate_planes(
        _CASCADE._BITSLICED._template_planes(template),
        variant,
        positions,
        np.arange(1 << (window_bits - 6), dtype=np.uint64),
    )
    for round_number in range(2):
        state = _CASCADE._PREFIX._keccak_round_bitsliced(state, round_number)
    _, metrics = _CASCADE._encode_state(
        state,
        variant,
        2,
        window_bits,
        seed,
        positions,
        False,
    )
    assert metrics["reader_roundtrip"]["exact_match"]
    assert metrics["reader_roundtrip"]["truth_values_checked"] == 256 * 1600
    assert metrics["basis_monomials"] <= 256


def test_anf_compression_recipe_roundtrip(tmp_path: Path) -> None:
    path = tmp_path / "shake-anf-compression.causal"
    _CASCADE._build_graph(path, 8, [0, 2, 3, 24], [2, 3])
    reader = CryptoCausalReader(path)
    rows = reader.triplets(include_inferred=False)
    assert reader.verify_provenance()
    assert len(rows) == 6
    recipes = [
        row["attrs"]["reader_recipe"]
        for row in rows
        if row["mechanism"] == "reader_lossless_binary_dictionary_pack"
    ]
    assert len(recipes) == 2
    assert all(recipe["format"] == "F8ANFPK1" for recipe in recipes)

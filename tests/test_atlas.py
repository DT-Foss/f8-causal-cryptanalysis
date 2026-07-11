import numpy as np

from arx_carry_leak.atlas import (
    aes_inverse_linear_layer,
    aes_inverse_shift_rows,
    aes_prefix_batch,
    chacha_counter_blocks,
    exact_sign_flip_test,
    mutual_information_matrix,
    permutation_control,
    rows32,
)
from arx_carry_leak.live_casi_v091.ciphers import _aes_ecb_batch, _chacha_block


def test_chacha20_rfc_8439_block_vector() -> None:
    key = bytes(range(32))
    nonce = bytes.fromhex("000000090000004a00000000")
    expected = bytes.fromhex(
        "10f1e7e4d13b5915500fdd1fa32071c4c7d1f4c733c068030422aa9ac3d46c4e"
        "d2826446079faa0914c2d705d98b02a2b5129cd1de164eb9cbd083e8a2503c4e"
    )
    assert _chacha_block(key, 1, nonce, 20) == expected


def test_explicit_chacha_counter_traversal_matches_stream_generator() -> None:
    from arx_carry_leak.live_casi_v091.ciphers import generate_chacha_stream

    counters = np.arange(4, dtype=np.uint32)
    assert chacha_counter_blocks(counters, 3, 42).tobytes() == generate_chacha_stream(
        8, rounds=3, seed=42
    )


def test_chacha_core_view_is_distinct_but_deterministic() -> None:
    counters = np.asarray([0, 1, 7, 0xFFFFFFFF], dtype=np.uint32)
    full = chacha_counter_blocks(counters, 3, 42)
    core = chacha_counter_blocks(counters, 3, 42, feedforward=False)
    assert full.shape == core.shape == (4, 64)
    assert not np.array_equal(full, core)
    assert np.array_equal(core, chacha_counter_blocks(counters, 3, 42, feedforward=False))


def test_aes128_fips_197_vector() -> None:
    key = np.frombuffer(bytes.fromhex("000102030405060708090a0b0c0d0e0f"), dtype=np.uint8)
    plaintext = np.frombuffer(
        bytes.fromhex("00112233445566778899aabbccddeeff"), dtype=np.uint8
    ).reshape(1, 16)
    actual = _aes_ecb_batch(key, plaintext, 10).tobytes()
    assert actual.hex() == "69c4e0d86a7b0430d8cdb78070b4c55a"


def test_atlas_aes_prefix_full_round_matches_fips_197() -> None:
    key = np.frombuffer(bytes.fromhex("000102030405060708090a0b0c0d0e0f"), dtype=np.uint8)
    plaintext = np.frombuffer(
        bytes.fromhex("00112233445566778899aabbccddeeff"), dtype=np.uint8
    ).reshape(1, 16)
    assert aes_prefix_batch(key, plaintext, 10).tobytes().hex() == (
        "69c4e0d86a7b0430d8cdb78070b4c55a"
    )


def test_aes_inverse_linear_layer_localizes_round_one_difference() -> None:
    rng = np.random.default_rng(212)
    key = rng.integers(0, 256, size=16, dtype=np.uint8)
    first = rng.integers(0, 256, size=(200, 16), dtype=np.uint8)
    second = first.copy()
    second[:, 7] ^= np.uint8(4)
    difference = aes_prefix_batch(key, first, 1) ^ aes_prefix_batch(key, second, 1)
    peeled = aes_inverse_linear_layer(difference)
    assert np.all(peeled[:, 7] != 0)
    assert np.count_nonzero(np.delete(peeled, 7, axis=1)) == 0


def test_aes_inverse_shift_rows_is_inverse_of_public_permutation() -> None:
    blocks = np.arange(32, dtype=np.uint8).reshape(2, 16)
    state = blocks.reshape(-1, 4, 4).transpose(0, 2, 1).copy()
    for row in range(1, 4):
        state[:, row, :] = np.roll(state[:, row, :], -row, axis=1)
    shifted = state.transpose(0, 2, 1).reshape(-1, 16)
    assert np.array_equal(aes_inverse_shift_rows(shifted), blocks)


def test_information_heatmap_separates_identity_from_independence() -> None:
    rng = np.random.default_rng(9)
    source = rng.integers(0, 256, size=(20_000, 2), dtype=np.uint8)
    identity = mutual_information_matrix(source, source, shift=5)
    independent = mutual_information_matrix(
        source, rng.integers(0, 256, size=source.shape, dtype=np.uint8), shift=5
    )
    assert identity[0, 0] > 2.9
    assert identity[1, 1] > 2.9
    assert independent.max() < 0.01


def test_permutation_control_and_exact_test_are_deterministic() -> None:
    rng = np.random.default_rng(12)
    row = rng.integers(0, 256, size=32, dtype=np.uint8)
    matrix = np.vstack([row ^ np.uint8(index & 1) for index in range(1000)])
    first = permutation_control(matrix, shift=5, permutations=3, seed=17)
    second = permutation_control(matrix, shift=5, permutations=3, seed=17)
    assert np.array_equal(first["control_matrices"], second["control_matrices"])
    assert exact_sign_flip_test([1.0, 1.0])["upper_tail_p"] == 0.25
    assert rows32(matrix.tobytes(), limit=7).shape == (7, 32)

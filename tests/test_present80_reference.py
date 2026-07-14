from __future__ import annotations

import random

import pytest

from arx_carry_leak.present80_reference import (
    INV_PBOX,
    INV_SBOX,
    MASK80,
    PBOX,
    PRESENT80_CHES2007_KATS,
    PRESENT80_ISO29192_B_1_1_KAT,
    SBOX,
    decrypt_block,
    encrypt_block,
    inverse_permutation_layer,
    inverse_sbox_layer,
    key_bytes_to_parts,
    key_schedule,
    permutation_layer,
    sbox_layer,
    verify_ches2007_kats,
    verify_iso29192_b_1_1,
    verify_orientation_sentinels,
)


def _independent_encrypt(plaintext: bytes, key: bytes) -> bytes:
    state = int.from_bytes(plaintext, "big")
    register = int.from_bytes(key, "big")
    for round_index in range(1, 32):
        state ^= register >> 16
        substituted = 0
        for nibble in range(16):
            substituted |= SBOX[(state >> (4 * nibble)) & 0xF] << (4 * nibble)
        permuted = 0
        for source in range(64):
            destination = 63 if source == 63 else (16 * source) % 63
            permuted |= ((substituted >> source) & 1) << destination
        state = permuted
        register = ((register << 61) | (register >> 19)) & MASK80
        register ^= (register >> 76 ^ SBOX[register >> 76]) << 76
        register ^= round_index << 15
    return (state ^ (register >> 16)).to_bytes(8, "big")


def test_published_ches_and_iso_vectors_with_round_keys() -> None:
    ches = verify_ches2007_kats()
    assert len(ches) == len(PRESENT80_CHES2007_KATS) == 4
    assert all(row["pass"] is True for row in ches)
    iso = verify_iso29192_b_1_1()
    assert iso["pass"] is True
    assert iso["ciphertext_hex"] == "f8dd50531d973bde"
    assert iso["actual_round_key_hex"] == {
        "1": "0123456789abcdef",
        "2": "1024602468acf135",
        "31": "b57108e6e7d71e08",
        "32": "5d37d6ae211cdcf5",
    }


def test_nonpalindromic_key_and_state_orientation() -> None:
    key = bytes.fromhex(PRESENT80_ISO29192_B_1_1_KAT["key_hex"])
    assert key_bytes_to_parts(key) == (0x0123, 0x456789AB, 0xCDEF0123)
    assert encrypt_block(bytes.fromhex("0123456789abcdef"), key).hex() == (
        "f8dd50531d973bde"
    )
    sentinels = verify_orientation_sentinels()
    assert len(sentinels) == 2
    assert all(row["pass"] is True for row in sentinels)


def test_random_independent_differential_and_decrypt_roundtrip() -> None:
    rng = random.Random(0xA253)
    for _ in range(256):
        key = rng.randbytes(10)
        plaintext = rng.randbytes(8)
        ciphertext = encrypt_block(plaintext, key)
        assert ciphertext == _independent_encrypt(plaintext, key)
        assert decrypt_block(ciphertext, key) == plaintext


def test_sbox_and_permutation_inverses() -> None:
    assert tuple(INV_SBOX[SBOX[value]] for value in range(16)) == tuple(range(16))
    assert tuple(INV_PBOX[PBOX[value]] for value in range(64)) == tuple(range(64))
    rng = random.Random(0x50524553454E54)
    for _ in range(64):
        value = rng.getrandbits(64)
        assert inverse_sbox_layer(sbox_layer(value)) == value
        assert inverse_permutation_layer(permutation_layer(value)) == value


def test_input_validation() -> None:
    with pytest.raises(ValueError, match="10 key bytes"):
        key_bytes_to_parts(b"short")
    with pytest.raises(ValueError, match="10 key bytes"):
        encrypt_block(bytes(8), b"short")
    with pytest.raises(ValueError, match="8 bytes"):
        encrypt_block(b"short", bytes(10))
    with pytest.raises(ValueError, match="32 round keys"):
        from arx_carry_leak.present80_reference import encrypt_int

        encrypt_int(0, key_schedule(0)[:-1])

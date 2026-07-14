from __future__ import annotations

import random

import pytest

from arx_carry_leak.present128_reference import (
    INV_PBOX,
    INV_SBOX,
    MASK128,
    PBOX,
    PRESENT128_OFFICIAL_ZERO_KAT,
    PRESENT128_REFERENCE_KATS,
    PRESENT128_ROUND_KEY_SENTINEL,
    SBOX,
    decrypt_block,
    encrypt_block,
    inverse_permutation_layer,
    inverse_sbox_layer,
    key_bytes_to_parts,
    key_schedule,
    permutation_layer,
    sbox_layer,
    verify_official_zero_kat,
    verify_orientation_sentinels,
    verify_reference_kats,
    verify_round_key_sentinel,
)


def _independent_encrypt(plaintext: bytes, key: bytes) -> bytes:
    state = int.from_bytes(plaintext, "big")
    register = int.from_bytes(key, "big")
    for round_index in range(1, 32):
        state ^= register >> 64
        substituted = 0
        for nibble in range(16):
            substituted |= SBOX[(state >> (4 * nibble)) & 0xF] << (4 * nibble)
        permuted = 0
        for source in range(64):
            destination = 63 if source == 63 else (16 * source) % 63
            permuted |= ((substituted >> source) & 1) << destination
        state = permuted
        register = ((register << 61) | (register >> 67)) & MASK128
        top = SBOX[(register >> 124) & 0xF]
        second = SBOX[(register >> 120) & 0xF]
        register &= (1 << 120) - 1
        register |= top << 124
        register |= second << 120
        register ^= round_index << 62
    return (state ^ (register >> 64)).to_bytes(8, "big")


def _split_lane_round_keys(key: int) -> list[int]:
    """Mirror the Metal `ulong2` schedule without using a 128-bit rotate."""

    high = key >> 64
    low = key & ((1 << 64) - 1)
    round_keys: list[int] = []
    for round_index in range(1, 33):
        round_keys.append(high)
        if round_index == 32:
            break
        next_high = ((high << 61) & ((1 << 64) - 1)) | (low >> 3)
        next_low = ((low << 61) & ((1 << 64) - 1)) | (high >> 3)
        top = SBOX[next_high >> 60]
        second = SBOX[(next_high >> 56) & 0xF]
        next_high &= 0x00FFFFFFFFFFFFFF
        next_high |= top << 60
        next_high |= second << 56
        next_low ^= (round_index & 0x3) << 62
        next_high ^= round_index >> 2
        high, low = next_high, next_low
    return round_keys


def test_official_zero_vector_reference_suite_and_local_round_key_trace() -> None:
    official = verify_official_zero_kat()
    assert official["pass"] is True
    assert official["ciphertext_hex"] == "96db702a2e6900af"
    assert PRESENT128_OFFICIAL_ZERO_KAT == PRESENT128_REFERENCE_KATS[0]
    kats = verify_reference_kats()
    assert len(kats) == len(PRESENT128_REFERENCE_KATS) == 4
    assert all(row["pass"] is True for row in kats)
    sentinel = verify_round_key_sentinel()
    assert sentinel["pass"] is True
    assert sentinel["ciphertext_hex"] == "0e3dcaff311f1809"
    assert sentinel["actual_round_key_hex"] == {
        "1": "0001020304050607",
        "2": "150121416181a1c1",
        "3": "b90004080c101418",
        "31": "a6a7d33563271366",
        "32": "47760455aebda684",
    }


def test_nonpalindromic_key_and_state_orientation() -> None:
    key = bytes.fromhex(PRESENT128_ROUND_KEY_SENTINEL["key_hex"])
    assert key_bytes_to_parts(key) == (
        0x0001020304050607,
        0x08090A0B,
        0x0C0D0E0F,
    )
    assert encrypt_block(bytes.fromhex("0123456789abcdef"), key).hex() == (
        "0e3dcaff311f1809"
    )
    sentinels = verify_orientation_sentinels()
    assert len(sentinels) == 2
    assert all(row["pass"] is True for row in sentinels)


def test_random_independent_differential_and_decrypt_roundtrip() -> None:
    rng = random.Random(0xA278)
    for _ in range(256):
        key = rng.randbytes(16)
        plaintext = rng.randbytes(8)
        ciphertext = encrypt_block(plaintext, key)
        assert ciphertext == _independent_encrypt(plaintext, key)
        assert decrypt_block(ciphertext, key) == plaintext


def test_metal_split_lane_schedule_matches_scalar_for_random_keys() -> None:
    rng = random.Random(0x12861)
    anchors = [0, (1 << 128) - 1, int(PRESENT128_ROUND_KEY_SENTINEL["key_hex"], 16)]
    anchors.extend(rng.getrandbits(128) for _ in range(256))
    for key in anchors:
        assert _split_lane_round_keys(key) == key_schedule(key)


def test_legacy_local_implementation_matches_for_full_round_random_corpus() -> None:
    from arx_carry_leak.nano_ciphers import (
        _present_encrypt,
        _present_key_schedule_128,
    )

    rng = random.Random(0x12831)
    for _ in range(256):
        key = rng.getrandbits(128)
        plaintext = rng.getrandbits(64)
        assert encrypt_block(plaintext.to_bytes(8, "big"), key.to_bytes(16, "big")) == (
            _present_encrypt(
                plaintext,
                _present_key_schedule_128(key, 31),
                31,
            ).to_bytes(8, "big")
        )


def test_sbox_and_permutation_inverses() -> None:
    assert tuple(INV_SBOX[SBOX[value]] for value in range(16)) == tuple(range(16))
    assert tuple(INV_PBOX[PBOX[value]] for value in range(64)) == tuple(range(64))
    rng = random.Random(0x50524553454E54)
    for _ in range(64):
        value = rng.getrandbits(64)
        assert inverse_sbox_layer(sbox_layer(value)) == value
        assert inverse_permutation_layer(permutation_layer(value)) == value


def test_input_validation() -> None:
    with pytest.raises(ValueError, match="16 key bytes"):
        key_bytes_to_parts(b"short")
    with pytest.raises(ValueError, match="16 key bytes"):
        encrypt_block(bytes(8), b"short")
    with pytest.raises(ValueError, match="8 bytes"):
        encrypt_block(b"short", bytes(16))
    with pytest.raises(ValueError, match="32 round keys"):
        from arx_carry_leak.present128_reference import encrypt_int

        encrypt_int(0, key_schedule(0)[:-1])

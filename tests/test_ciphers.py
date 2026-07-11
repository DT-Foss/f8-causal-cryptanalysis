import importlib.util
from pathlib import Path

from arx_carry_leak.ciphers import (
    SPECK_VARIANTS,
    speck_stream,
    threefish256_stream,
    verify_reference_vectors,
)
from arx_carry_leak.nano_ciphers import (
    SIMON_PARAMS,
    SPECK_PARAMS,
    _SIMON_Z_SEQ,
    _present_encrypt,
    _present_inverse_permutation,
    _present_inverse_sbox_layer,
    _present_key_schedule_128,
    _present_key_schedule_80,
    _simon_encrypt,
    _simon_key_schedule,
    _speck_encrypt,
    _speck_key_schedule,
)

_AUDIT_PATH = Path(__file__).parents[1] / "research/experiments/reference_vector_audit.py"
_AUDIT_SPEC = importlib.util.spec_from_file_location("reference_vector_audit", _AUDIT_PATH)
assert _AUDIT_SPEC is not None and _AUDIT_SPEC.loader is not None
_AUDIT = importlib.util.module_from_spec(_AUDIT_SPEC)
_AUDIT_SPEC.loader.exec_module(_AUDIT)


def test_reference_vectors() -> None:
    assert all(verify_reference_vectors().values())


def test_nano_registry_speck32_64_reference_vector() -> None:
    key = [0x0100, 0x0908, 0x1110, 0x1918]
    round_keys = _speck_key_schedule(key, 16, 4, 22, 7, 2)
    assert _speck_encrypt(0x6574, 0x694C, round_keys, 16, 7, 2) == (0xA868, 0x42F2)


def test_nano_registry_simon32_64_reference_vector() -> None:
    key = [0x0100, 0x0908, 0x1110, 0x1918]
    round_keys = _simon_key_schedule(key, 16, 4, 32, _SIMON_Z_SEQ[0])
    assert _simon_encrypt(0x6565, 0x6877, round_keys, 16) == (0xC69B, 0xE9BB)


def test_present80_official_zero_reference_vector() -> None:
    """PRESENT-80: zero key / zero plaintext after all 31 rounds."""
    round_keys = _present_key_schedule_80(0x00000000000000000000, 31)
    assert _present_encrypt(0x0000000000000000, round_keys, 31) == 0x5579C1387B228445


def test_present128_official_zero_reference_vector() -> None:
    round_keys = _present_key_schedule_128(0x00000000000000000000000000000000, 31)
    assert _present_encrypt(0x0000000000000000, round_keys, 31) == 0x96DB702A2E6900AF


def test_present_inverse_layers_are_exact() -> None:
    from arx_carry_leak.nano_ciphers import _PRESENT_SBOX, _PRESENT_PERM_MASK

    state = 0x0123456789ABCDEF
    sboxed = sum(_PRESENT_SBOX[(state >> (4 * i)) & 0xF] << (4 * i) for i in range(16))
    assert _present_inverse_sbox_layer(sboxed) == state
    permuted = sum((1 << dst) for src, dst in _PRESENT_PERM_MASK if state & (1 << src))
    assert _present_inverse_permutation(permuted) == state


def test_all_nano_speck_variants_against_official_vectors() -> None:
    assert len(SPECK_PARAMS) == len(_AUDIT.SPECK_VECTORS) == 10
    assert all(
        _AUDIT._nano_speck_result(name, key, plaintext, expected)["pass"]
        for name, (key, plaintext, expected) in _AUDIT.SPECK_VECTORS.items()
    )


def test_all_nano_simon_variants_against_official_vectors() -> None:
    assert len(SIMON_PARAMS) == len(_AUDIT.SIMON_VECTORS) == 10
    assert all(
        _AUDIT._nano_simon_result(name, key, plaintext, expected)["pass"]
        for name, (key, plaintext, expected) in _AUDIT.SIMON_VECTORS.items()
    )


def test_all_speck_variants_have_consistent_stream_shape() -> None:
    for name, variant in SPECK_VARIANTS.items():
        raw, block_bytes, word_bytes = speck_stream(3, variant.full_rounds, 42, name)
        assert len(raw) == 3 * block_bytes
        assert block_bytes == variant.block_bits // 8
        assert word_bytes == variant.word_size // 8


def test_generators_are_deterministic_and_seeded() -> None:
    first = speck_stream(4, 22, 42)
    second = speck_stream(4, 22, 42)
    different = speck_stream(4, 22, 1042)
    assert first == second
    assert first[0] != different[0]

    tf_first = threefish256_stream(2, 72, 42)
    tf_second = threefish256_stream(2, 72, 42)
    assert tf_first == tf_second

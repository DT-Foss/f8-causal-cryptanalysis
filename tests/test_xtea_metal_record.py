from __future__ import annotations

import importlib.util
import os
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).parents[1]
SCRIPT = ROOT / "research/experiments/xtea_metal_record.py"
SPEC = importlib.util.spec_from_file_location("xtea_metal_record", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
XTEA = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = XTEA
SPEC.loader.exec_module(XTEA)


def test_published_xtea_vector_and_independent_reference() -> None:
    gate = XTEA.reference_gate()
    assert gate["zero_vector_exact"] is True
    assert gate["zero_key_zero_plaintext_ciphertext"] == [0xDEE9D4D8, 0xF7131ED9]
    assert gate["all_exact"] is True


@pytest.mark.parametrize("width", [36, 39, 42])
def test_xtea_residual_mapping(width: int) -> None:
    context = XTEA._context(width)
    known = (0, 0xFEDCBA98 & ~context["outer_mask"], 0x12345678, 0x90ABCDEF)
    for assignment in (0, 1, (1 << 32) - 1, 1 << 32, (1 << width) - 1):
        key = XTEA.apply_assignment(known, assignment, width)
        assert key[0] == assignment & XTEA.MASK32
        assert key[1] & context["outer_mask"] == assignment >> 32


def test_scalar_numpy_and_decrypt_roundtrip() -> None:
    for index in range(12):
        plaintext = (
            (0xDEADBEEF + index * 0x10203) & XTEA.MASK32,
            (0xCAFEBABE ^ index * 0x1001001) & XTEA.MASK32,
        )
        key = tuple((0x31415927 * (index + word + 1)) & XTEA.MASK32 for word in range(4))
        scalar = XTEA.scalar_encrypt(plaintext, key)
        assert scalar == XTEA.numpy_encrypt(plaintext, key)
        assert XTEA.scalar_decrypt(scalar, key) == plaintext


def test_small_xtea_metal_mapping_if_available(tmp_path: Path) -> None:
    if sys.platform != "darwin" or os.environ.get("F8_RUN_NATIVE_METAL_TESTS") != "1":
        pytest.skip("set F8_RUN_NATIVE_METAL_TESTS=1 for the optional Metal integration")
    executable, _ = XTEA.FAMILY._compile_native(tmp_path)
    width = 39
    key = (0x01234567, 0x89ABCDEF, 0x0BADF00D, 0xC001D00D)
    plaintext = (0, 0, 0x10203040, 0x50607080)
    context = XTEA._context(width)
    known = (0, key[1] & ~context["outer_mask"], key[2], key[3])
    assignment = key[0] | ((key[1] & context["outer_mask"]) << 32)
    target = XTEA.encrypt_relation(plaintext, key)
    with XTEA.MetalTEAHost(executable) as host:
        host.configure(
            target=target,
            control=(target[0] ^ 1, *target[1:]),
            known_zeroed_key=known,
            plaintext_words=plaintext,
            width=width,
            algorithm="xtea",
        )
        observed = host.blocks(assignment >> 32, assignment & XTEA.MASK32, 1)[0]
    assert observed == target


def test_authentic_xtea_causal_roundtrip(tmp_path: Path) -> None:
    payload = {
        "qualification_sha256": "1" * 64,
        "mapping_gate": {"scalar_numpy_metal_exact": True},
        "execution_sha256": "2" * 64,
        "confirmation_sha256": "3" * 64,
        "execution": {
            "unknown_key_bits": 39,
            "logical_candidate_count": 1 << 39,
            "factual_filter_matches": [123],
            "control_filter_matches": [],
            "factual_confirmations": [{"assignment": 123, "complete_128_bit_match": True}],
            "control_confirmations": [],
        },
    }
    result = XTEA.build_causal(
        path=tmp_path / "xtea.causal",
        payload=payload,
        dotcausal_src=XTEA.DEFAULT_DOTCAUSAL_SRC,
    )
    assert result["api_id"] == "xteakr1"
    assert result["triplets"] == 7
    assert result["rules"] == 2

from __future__ import annotations

import importlib.util
import os
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).parents[1]
SCRIPT = ROOT / "research/experiments/siphash24_metal_record.py"
SPEC = importlib.util.spec_from_file_location("siphash24_metal_record", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
SIP = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = SIP
SPEC.loader.exec_module(SIP)


def test_official_siphash24_vectors_and_independent_reference() -> None:
    gate = SIP.reference_gate()
    assert gate["official_vectors_exact"] is True
    assert gate["official_empty_observed_uint64"] == 0x726FDB47DD0E0E31
    assert gate["official_length8_observed_uint64"] == 0x93F5F5799A932462
    assert gate["all_exact"] is True


@pytest.mark.parametrize("width", [36, 40, 43])
def test_siphash_residual_mapping(width: int) -> None:
    context = SIP._context(width)
    known = (0, 0xFEDCBA98 & ~context["outer_mask"], 0x12345678, 0x90ABCDEF)
    for assignment in (0, 1, (1 << 32) - 1, 1 << 32, (1 << width) - 1):
        key = SIP.apply_assignment(known, assignment, width)
        assert key[0] == assignment & SIP.MASK32
        assert key[1] & context["outer_mask"] == assignment >> 32


def test_scalar_numpy_siphash_match() -> None:
    for index in range(12):
        messages = (
            (0xDEADBEEF + index * 0x10203) & SIP.MASK32,
            (0xCAFEBABE ^ index * 0x1001001) & SIP.MASK32,
        )
        key = tuple((0x31415927 * (index + word + 1)) & SIP.MASK32 for word in range(4))
        assert SIP.scalar_hash8(messages, key) == SIP.numpy_hash8(messages, key)


def test_small_siphash_metal_mapping_if_available(tmp_path: Path) -> None:
    if sys.platform != "darwin" or os.environ.get("F8_RUN_NATIVE_METAL_TESTS") != "1":
        pytest.skip("set F8_RUN_NATIVE_METAL_TESTS=1 for the optional Metal integration")
    executable, _ = SIP.FAMILY._compile_native(tmp_path)
    width = 40
    key = (0x01234567, 0x89ABCDEF, 0x0BADF00D, 0xC001D00D)
    messages = (0x03020100, 0x07060504, 0xA3A2A1A0, 0xA7A6A5A4)
    context = SIP._context(width)
    known = (0, key[1] & ~context["outer_mask"], key[2], key[3])
    assignment = key[0] | ((key[1] & context["outer_mask"]) << 32)
    target = SIP.hash_relation(messages, key)
    with SIP.MetalTEAHost(executable) as host:
        host.configure(
            target=target,
            control=(target[0] ^ 1, *target[1:]),
            known_zeroed_key=known,
            plaintext_words=messages,
            width=width,
            algorithm="siphash24",
        )
        observed = host.blocks(assignment >> 32, assignment & SIP.MASK32, 1)[0]
    assert observed == target


def test_authentic_siphash_causal_roundtrip(tmp_path: Path) -> None:
    payload = {
        "qualification_sha256": "1" * 64,
        "mapping_gate": {"scalar_numpy_metal_exact": True},
        "execution_sha256": "2" * 64,
        "confirmation_sha256": "3" * 64,
        "execution": {
            "unknown_key_bits": 40,
            "logical_candidate_count": 1 << 40,
            "factual_filter_matches": [123],
            "control_filter_matches": [],
            "factual_confirmations": [{"assignment": 123, "complete_128_bit_match": True}],
            "control_confirmations": [],
        },
    }
    result = SIP.build_causal(
        path=tmp_path / "siphash.causal",
        payload=payload,
        dotcausal_src=SIP.DEFAULT_DOTCAUSAL_SRC,
    )
    assert result["api_id"] == "sipkr1"
    assert result["triplets"] == 7
    assert result["rules"] == 2

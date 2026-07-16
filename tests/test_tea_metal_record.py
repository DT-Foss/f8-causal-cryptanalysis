from __future__ import annotations

import importlib.util
import json
import os
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).parents[1]
SCRIPT = ROOT / "research/experiments/tea_metal_record.py"
SPEC = importlib.util.spec_from_file_location("tea_metal_record", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
TEA = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = TEA
SPEC.loader.exec_module(TEA)


def test_published_reference_and_independent_formulation() -> None:
    gate = TEA.reference_gate()
    assert gate["zero_vector_exact"] is True
    assert gate["zero_key_zero_plaintext_ciphertext"] == [
        0x41EA3A0A,
        0x94BAA940,
    ]
    assert len(gate["cross_reference_rows"]) == 8
    assert gate["all_exact"] is True


@pytest.mark.parametrize("width", [36, 39, 42])
def test_residual_assignment_mapping_is_exact(width: int) -> None:
    context = TEA._context(width)
    known = (0, 0xFEDCBA98 & ~context["outer_mask"], 0x12345678, 0x90ABCDEF)
    for assignment in (0, 1, (1 << 32) - 1, 1 << 32, (1 << width) - 1):
        key = TEA.apply_assignment(known, assignment, width)
        assert key[0] == assignment & TEA.MASK32
        assert key[1] & context["outer_mask"] == assignment >> 32
        assert key[1] & ~context["outer_mask"] == known[1]
        assert key[2:] == known[2:]


def test_scalar_numpy_and_decryption_match_on_non_reference_material() -> None:
    for index in range(12):
        plaintext = (
            (0xDEADBEEF + index * 0x10203) & TEA.MASK32,
            (0xCAFEBABE ^ index * 0x1001001) & TEA.MASK32,
        )
        key = tuple(
            (0x31415927 * (index + word + 1)) & TEA.MASK32
            for word in range(4)
        )
        scalar = TEA.scalar_encrypt(plaintext, key)
        assert scalar == TEA.numpy_encrypt(plaintext, key)
        assert TEA.scalar_decrypt(scalar, key) == plaintext


def test_native_source_contains_complete_tea_contract() -> None:
    source = TEA.NATIVE_SOURCE.read_text()
    assert "cycle < 32u" in source
    assert "tea_filter" in source
    assert "tea_blocks" in source
    assert "xtea_encrypt" in source
    assert "siphash24_8byte" in source
    assert "complete_128_bit_relation_comparison" in source
    assert "key_word1_unknown_mask" in source


def test_authentic_causal_roundtrip(tmp_path: Path) -> None:
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
            "factual_confirmations": [
                {"assignment": 123, "complete_128_bit_match": True}
            ],
            "control_confirmations": [],
        },
    }
    path = tmp_path / "tea.causal"
    result = TEA.build_causal(
        path=path, payload=payload, dotcausal_src=TEA.DEFAULT_DOTCAUSAL_SRC
    )
    assert result["api_id"] == "teakr1"
    assert result["triplets"] == 7
    assert result["rules"] == 2
    assert result["clusters"] == 2
    assert result["gaps"][0]["expected_object_type"] == (
        "prospectively_selected_strict_subset_of_W39_domain"
    )


def test_small_metal_mapping_if_available(tmp_path: Path) -> None:
    if sys.platform != "darwin" or os.environ.get("F8_RUN_NATIVE_METAL_TESTS") != "1":
        pytest.skip("set F8_RUN_NATIVE_METAL_TESTS=1 for the optional Metal integration")
    executable, build = TEA._compile_native(tmp_path)
    assert len(build["executable_sha256"]) == 64
    width = 39
    key = (0x01234567, 0x89ABCDEF, 0x0BADF00D, 0xC001D00D)
    plaintext = (0, 0, 0x10203040, 0x50607080)
    context = TEA._context(width)
    known = (0, key[1] & ~context["outer_mask"], key[2], key[3])
    assignment = key[0] | ((key[1] & context["outer_mask"]) << 32)
    target = TEA.encrypt_relation(plaintext, key)
    control = (target[0] ^ 1, *target[1:])
    with TEA.MetalTEAHost(executable) as host:
        host.configure(
            target=target,
            control=control,
            known_zeroed_key=known,
            plaintext_words=plaintext,
            width=width,
        )
        observed = host.blocks(assignment >> 32, assignment & TEA.MASK32, 1)[0]
    assert observed == target


def test_checkpoint_fingerprint_is_canonical() -> None:
    protocol = {
        "challenge": {"unknown_key_bits": 40},
        "public_challenge_sha256": "a" * 64,
    }
    fingerprint = TEA._checkpoint_fingerprint("b" * 64, protocol)
    encoded = json.dumps(fingerprint, sort_keys=True)
    assert str(1 << 40) in encoded
    assert fingerprint["stream_candidate_count"] == 1 << 28

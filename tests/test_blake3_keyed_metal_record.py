from __future__ import annotations

import importlib.util
import json
import os
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).parents[1]
SCRIPT = ROOT / "research/experiments/blake3_keyed_metal_record.py"
SPEC = importlib.util.spec_from_file_location("blake3_keyed_metal_record", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
B3 = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = B3
SPEC.loader.exec_module(B3)


def test_official_keyed_blake3_vectors_and_independent_reference() -> None:
    gate = B3.official_kat_gate()
    assert gate["all_exact"] is True
    assert [row["input_len"] for row in gate["rows"]] == [0, 1, 63, 64]
    assert all(row["exact"] for row in gate["rows"])


@pytest.mark.parametrize("width", [38, 41, 43])
def test_residual_assignment_mapping_is_exact(width: int) -> None:
    mask = (1 << width) - 1
    known = (int.from_bytes(bytes(range(32)), "little") & ~mask).to_bytes(
        32, "little"
    )
    for assignment in (0, 1, (1 << 32) - 1, 1 << 32, mask):
        key = B3.apply_assignment(known, assignment, width)
        assert int.from_bytes(key, "little") & mask == assignment
        assert int.from_bytes(key, "little") & ~mask == int.from_bytes(
            known, "little"
        )


def test_scalar_and_numpy_keyed_root_match_on_non_kat_material() -> None:
    for index, length in enumerate((0, 7, 32, 64)):
        key = bytes((position * 17 + index) & 0xFF for position in range(32))
        message = bytes((position * 29 + index) & 0xFF for position in range(length))
        assert B3.scalar_keyed_root(key, message) == B3.numpy_keyed_root(key, message)


def test_native_source_contains_complete_keyed_root_contract() -> None:
    source = B3.NATIVE_SOURCE.read_text()
    assert "round_index < 7u" in source
    assert "blake3_keyed_filter" in source
    assert "blake3_keyed_blocks" in source
    assert "complete_256_bit_output_comparison" in source
    assert "key_word1_unknown_mask" in source


def test_authentic_causal_roundtrip(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    payload = {
        "qualification_sha256": "1" * 64,
        "mapping_gate": {"scalar_numpy_metal_exact": True},
        "execution_sha256": "2" * 64,
        "confirmation_sha256": "3" * 64,
        "execution": {
            "unknown_key_bits": 38,
            "logical_candidate_count": 1 << 38,
            "factual_filter_matches": [123],
            "control_filter_matches": [],
            "factual_confirmations": [
                {"assignment": 123, "complete_256_bit_match": True}
            ],
            "control_confirmations": [],
        },
    }
    path = tmp_path / "blake3.causal"
    monkeypatch.setattr(B3, "ROOT", tmp_path)
    result = B3.build_causal(
        path=path, payload=payload, dotcausal_src=B3.DEFAULT_DOTCAUSAL_SRC
    )
    assert result["api_id"] == "b3kr1"
    assert result["triplets"] == 7
    assert result["rules"] == 2
    assert result["clusters"] == 2
    assert result["gaps"][0]["expected_object_type"] == (
        "prospectively_selected_strict_subset_of_W38_domain"
    )
    assert len(path.read_bytes()) > 0


def test_small_metal_mapping_if_available(tmp_path: Path) -> None:
    if sys.platform != "darwin" or os.environ.get("F8_RUN_NATIVE_METAL_TESTS") != "1":
        pytest.skip("set F8_RUN_NATIVE_METAL_TESTS=1 for the optional Metal integration")
    executable, build = B3._compile_native(tmp_path)
    assert len(build["executable_sha256"]) == 64
    width = 38
    message = bytes(index % 251 for index in range(64))
    key = B3.OFFICIAL_KEY
    mask = (1 << width) - 1
    known = (int.from_bytes(key, "little") & ~mask).to_bytes(32, "little")
    assignment = int.from_bytes(key, "little") & mask
    target = B3.scalar_keyed_root(key, message)
    control = bytes([target[0] ^ 1]) + target[1:]
    with B3.MetalBlake3Host(executable) as host:
        host.configure(
            target=target,
            control=control,
            known_zeroed_key=known,
            message=message,
            width=width,
        )
        observed = host.blocks(assignment >> 32, assignment & B3.MASK32, 1)[0]
    assert observed == target


def test_checkpoint_fingerprint_is_canonical() -> None:
    protocol = {
        "challenge": {"unknown_key_bits": 41},
        "public_challenge_sha256": "a" * 64,
    }
    fingerprint = B3._checkpoint_fingerprint("b" * 64, protocol)
    encoded = json.dumps(fingerprint, sort_keys=True)
    assert "2199023255552" in encoded
    assert fingerprint["stream_candidate_count"] == 1 << 29

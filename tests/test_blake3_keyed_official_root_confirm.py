from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).parents[1]
SCRIPT = ROOT / "research/experiments/blake3_keyed_official_root_confirm.py"
SPEC = importlib.util.spec_from_file_location("blake3_keyed_official_root_confirm", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
B3OFF = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = B3OFF
SPEC.loader.exec_module(B3OFF)


def test_official_b3sum_kat_when_fixture_is_available() -> None:
    source = Path("/tmp/blake3-official-a287")
    binary = source / "b3sum/target/release/b3sum"
    if not source.is_dir() or not binary.is_file():
        pytest.skip("official BLAKE3 build fixture is unavailable")
    gate = B3OFF.official_tool_gate(source, binary)
    assert gate["official_KAT_exact"] is True
    assert gate["official_keyed_64_byte_message_KAT_observed_hex"] == (
        B3OFF.OFFICIAL_KEYED64_HEX
    )
    assert len(gate["commit"]) == 40
    assert len(gate["binary_sha256"]) == 64

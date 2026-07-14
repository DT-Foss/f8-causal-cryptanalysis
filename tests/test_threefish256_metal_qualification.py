from __future__ import annotations

import importlib.util
import sys
from collections.abc import Iterator
from pathlib import Path

import pytest

MODULE_PATH = (
    Path(__file__).parents[1]
    / "research"
    / "experiments"
    / "threefish256_metal_qualification.py"
)
SPEC = importlib.util.spec_from_file_location(
    "threefish256_metal_qualification_tested", MODULE_PATH
)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)


@pytest.fixture(scope="module")
def metal_host(
    tmp_path_factory: pytest.TempPathFactory,
) -> Iterator[MODULE.MetalThreefish256Host]:
    executable, _build = MODULE._compile_native(
        tmp_path_factory.mktemp("threefish256-metal"), "swiftc"
    )
    host = MODULE.MetalThreefish256Host(executable)
    try:
        yield host
    finally:
        host.close()


def test_uint32_half_transport_roundtrips_uint64_words() -> None:
    words = [0, 1, 0xFFFFFFFF, 0x100000000, 0xFEDCBA9876543210]
    assert MODULE._words(MODULE._halves(words)) == words


def test_real_metal_host_passes_both_official_fullround_kats(
    metal_host: MODULE.MetalThreefish256Host,
) -> None:
    gate = MODULE._kat_gate(metal_host)
    assert gate["all_passed"] is True
    assert [row["name"] for row in gate["cases"]] == [
        "official_zero",
        "official_nonzero",
    ]
    assert all(row["exact_scalar_and_Metal_identity"] for row in gate["cases"])
    assert gate["cases"][0]["actual_words_hex"] == [
        "94eeea8b1f2ada84",
        "adf103313eae6670",
        "952419a1f4b16d53",
        "d83f13e63c9f6b11",
    ]


def test_real_metal_host_matches_scalar_and_uint32_boundaries(
    metal_host: MODULE.MetalThreefish256Host,
) -> None:
    cross = MODULE._cross_gate(metal_host)
    assert cross["candidate_count"] == 256
    assert cross["target_candidate"] == 123_456_862
    assert cross["complete_output_bits_checked"] == 65_536
    assert cross["exact_scalar_identity"] is True
    assert cross["exact_filter_identity"] is True

    boundary = MODULE._boundary_gate(metal_host)
    assert boundary["exact"] is True
    assert [row["first_candidate"] for row in boundary["intervals"]] == [
        0,
        0x90210FED - 128,
        2**32 - 256,
    ]
    assert [row["factual_matches"] for row in boundary["intervals"]] == [
        [],
        [0x90210FED],
        [],
    ]
    assert all(row["control_matches"] == [] for row in boundary["intervals"])


def test_candidate_mapping_changes_only_low32_of_key0() -> None:
    key = MODULE._halves(
        [0xA5A5A5A500000000, 0x1122334455667788, 0x99AABBCCDDEEFF00, 7]
    )
    candidate = 0xDEADBEEF
    mapped = MODULE._candidate_key(candidate, key)
    assert mapped[0] == 0xA5A5A5A5DEADBEEF
    assert mapped[1:] == [0x1122334455667788, 0x99AABBCCDDEEFF00, 7]

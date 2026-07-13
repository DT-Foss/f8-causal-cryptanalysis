"""Frozen A222 key-disjoint 8x4 known-key design for block ensembling.

This module is deliberately pure: it has no file, clock, RNG, solver, result,
target, or network access.  It exposes the exact 32-key prefix-by-suffix ledger
that a later A222 collector may use after its execution protocol is frozen.
"""

from __future__ import annotations

import hashlib
import json
from collections import Counter
from collections.abc import Iterable, Mapping, Sequence
from typing import Any

SCHEMA = "chacha20-round20-factorial-eight-block-key-design-v1"
ATTEMPT_ID = "A222"

# Eight new prefix clusters and four new suffix replicates.  The prefix columns
# contain four ones each; the suffix columns contain two ones each.  Their
# Cartesian product is therefore exactly balanced at 16 ones in every low20
# bit over the complete 32-key ledger.
PREFIX8_LEVELS = (0x64, 0x9B, 0x16, 0xE9, 0x2A, 0xD5, 0x4E, 0xB1)
SUFFIX12_LEVELS = (0x4E9, 0x715, 0x81A, 0xBE6)
PREFIX_CLUSTER_IDS = tuple(f"a222_p{index:02d}" for index in range(8))
SUFFIX_REPLICATE_IDS = tuple(f"a222_s{index:02d}" for index in range(4))

# Complete A220 level sets, copied as an immutable compatibility boundary from
# chacha20_round20_factorial_key_design.py (ledger SHA-256 below).  Explicit
# level disjointness is stronger than merely checking the 144 composed keys.
A220_PREFIX8_LEVELS = (
    0xD6,
    0x7E,
    0x4C,
    0x3B,
    0x8D,
    0xA3,
    0xB0,
    0x41,
    0x55,
    0x6A,
    0xC8,
    0x9F,
    0x24,
    0x38,
    0xCB,
    0x74,
    0x13,
    0xEE,
)
A220_SUFFIX12_LEVELS = (0x885, 0x3E3, 0xC7C, 0x71A, 0x1D1, 0xCAF, 0x61E, 0xB60)
A220_LOW20_LEDGER = frozenset(
    (prefix << 12) | suffix for prefix in A220_PREFIX8_LEVELS for suffix in A220_SUFFIX12_LEVELS
)

# The 24 deterministic A214 keys plus the revealed A218/A219 key, copied from
# the frozen A220 protocol.  This is public exclusion metadata, not target
# material for A222.
PRIOR_A214_A218_A219_LOW20 = (
    3305,
    226210,
    228629,
    314119,
    363912,
    403466,
    448301,
    451254,
    563959,
    605207,
    679900,
    690170,
    697127,
    711703,
    806712,
    856377,
    916992,
    920891,
    952164,
    955072,
    973392,
    997714,
    1014518,
    1026757,
    1035738,
)

A220_FACTORIAL_LEDGER_SHA256 = "820e792d740ce2f5aec5586dd1ab5e3ec79bbce8661706d21274d11c8246c0fe"
EXPECTED_PRIOR_EXCLUSION_SHA256 = "47eabd2bae0f7194a3be2a1fad2e55a38760140ff5a2fd9b2c474aa38936d9fb"
EXPECTED_A220_LOW20_SET_SHA256 = "b850f9afd33c106b8e3bc4ac4e5286aa7fa2ec0eb99d5fa245a9331e782f4255"
EXPECTED_LEDGER_SHA256 = "d482325d6f8592982cc6469aea7c7ccd14ce7bf4b70de27cb2a9bee21fd72300"
EXPECTED_LEDGER_ORDER_SHA256 = "fff553cba37e681f492ee7505b83320a903341ecad77d45a5e495c6b5fd75fc0"
EXPECTED_PREFIX_CLUSTER_IDS_SHA256 = (
    "29ce2b8f62323b4aef156c8522232654ff63b236365535a42f6aa96d0aaff7d5"
)
EXPECTED_SUFFIX_REPLICATE_IDS_SHA256 = (
    "8a8aa49799b40b977c587ddf4b10eca5b23ae69784f2db2506ee15960746f69f"
)

ROW_FIELDS = frozenset(
    {
        "label",
        "prefix_cluster_id",
        "prefix_index",
        "prefix8",
        "prefix8_bits",
        "prefix8_hex",
        "suffix_replicate_id",
        "suffix_index",
        "suffix12",
        "suffix12_bits",
        "suffix12_hex",
        "low20",
        "low20_bits",
        "low20_hex",
    }
)


def _canonical_bytes(value: Any) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode()


def _canonical_sha256(value: Any) -> str:
    return hashlib.sha256(_canonical_bytes(value)).hexdigest()


def _bit_counts(values: Sequence[int], width: int) -> tuple[int, ...]:
    return tuple(sum((value >> bit) & 1 for value in values) for bit in range(width))


def _pairwise_hamming(values: Sequence[int]) -> tuple[int, ...]:
    return tuple(
        (left ^ right).bit_count()
        for index, left in enumerate(values)
        for right in values[index + 1 :]
    )


def _build_ledger() -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for prefix_index, prefix8 in enumerate(PREFIX8_LEVELS):
        for suffix_index, suffix12 in enumerate(SUFFIX12_LEVELS):
            low20 = (prefix8 << 12) | suffix12
            rows.append(
                {
                    "label": f"a222_p{prefix_index:02d}_s{suffix_index:02d}",
                    "prefix_cluster_id": PREFIX_CLUSTER_IDS[prefix_index],
                    "prefix_index": prefix_index,
                    "prefix8": prefix8,
                    "prefix8_bits": f"{prefix8:08b}",
                    "prefix8_hex": f"{prefix8:02x}",
                    "suffix_replicate_id": SUFFIX_REPLICATE_IDS[suffix_index],
                    "suffix_index": suffix_index,
                    "suffix12": suffix12,
                    "suffix12_bits": f"{suffix12:012b}",
                    "suffix12_hex": f"{suffix12:03x}",
                    "low20": low20,
                    "low20_bits": f"{low20:020b}",
                    "low20_hex": f"{low20:05x}",
                }
            )
    return rows


def _ledger_order_material(rows: Sequence[Mapping[str, Any]]) -> list[dict[str, Any]]:
    return [
        {"index": index, "label": row["label"], "low20": row["low20"]}
        for index, row in enumerate(rows)
    ]


def validate_eight_block_key_ledger(
    rows: Sequence[Mapping[str, Any]], *, additional_forbidden_low20: Iterable[int] = ()
) -> None:
    """Validate exact identity, disjointness, balance, and diversity gates."""

    if not isinstance(rows, Sequence) or isinstance(rows, (str, bytes, bytearray)):
        raise RuntimeError("A222 key ledger is not a row sequence")
    if len(rows) != 32 or any(not isinstance(row, Mapping) for row in rows):
        raise RuntimeError("A222 key ledger must contain exactly 32 rows")
    if any(set(row) != ROW_FIELDS for row in rows):
        raise RuntimeError("A222 key ledger row schema differs")
    for row in rows:
        for field in ("prefix_index", "prefix8", "suffix_index", "suffix12", "low20"):
            if type(row[field]) is not int:
                raise RuntimeError("A222 key ledger integer field differs")

    expected = _build_ledger()
    if [dict(row) for row in rows] != expected:
        raise RuntimeError("A222 key ledger row identity or order differs")

    low20_values = tuple(int(row["low20"]) for row in rows)
    labels = tuple(str(row["label"]) for row in rows)
    if len(set(low20_values)) != 32 or len(set(labels)) != 32:
        raise RuntimeError("A222 key ledger key or label uniqueness differs")
    if Counter(row["prefix_cluster_id"] for row in rows) != {
        cluster_id: 4 for cluster_id in PREFIX_CLUSTER_IDS
    } or Counter(row["suffix_replicate_id"] for row in rows) != {
        replicate_id: 8 for replicate_id in SUFFIX_REPLICATE_IDS
    }:
        raise RuntimeError("A222 key ledger 8x4 replication differs")

    if set(PREFIX8_LEVELS) & set(A220_PREFIX8_LEVELS) or set(SUFFIX12_LEVELS) & set(
        A220_SUFFIX12_LEVELS
    ):
        raise RuntimeError("A222 key design reuses an A220 prefix or suffix level")
    forbidden = set(PRIOR_A214_A218_A219_LOW20) | set(A220_LOW20_LEDGER)
    for value in additional_forbidden_low20:
        if type(value) is not int or not 0 <= value < (1 << 20):
            raise RuntimeError("A222 additional forbidden key differs")
        forbidden.add(value)
    if set(low20_values) & forbidden:
        raise RuntimeError("A222 key ledger intersects a prior key ledger")

    if len(A220_LOW20_LEDGER) != 144:
        raise RuntimeError("A222 embedded A220 ledger is incomplete")
    if _canonical_sha256(sorted(A220_LOW20_LEDGER)) != EXPECTED_A220_LOW20_SET_SHA256:
        raise RuntimeError("A222 embedded A220 low20-set digest differs")
    if _canonical_sha256(list(PRIOR_A214_A218_A219_LOW20)) != EXPECTED_PRIOR_EXCLUSION_SHA256:
        raise RuntimeError("A222 embedded prior-exclusion digest differs")

    if _bit_counts(PREFIX8_LEVELS, 8) != (4,) * 8:
        raise RuntimeError("A222 prefixes are not exactly bit-balanced")
    if _bit_counts(SUFFIX12_LEVELS, 12) != (2,) * 12:
        raise RuntimeError("A222 suffixes are not exactly bit-balanced")
    if _bit_counts(low20_values, 20) != (16,) * 20:
        raise RuntimeError("A222 low20 ledger is not exactly bit-balanced")

    prefix_distances = _pairwise_hamming(PREFIX8_LEVELS)
    suffix_distances = _pairwise_hamming(SUFFIX12_LEVELS)
    key_distances = _pairwise_hamming(low20_values)
    if (
        min(prefix_distances) < 3
        or min(suffix_distances) < 8
        or min(key_distances) < 3
        or sum(key_distances) * 2 < 19 * len(key_distances)
    ):
        raise RuntimeError("A222 key design fails the Hamming-diversity gate")
    if any(not 3 <= value.bit_count() <= 5 for value in PREFIX8_LEVELS):
        raise RuntimeError("A222 prefix design contains an extreme-weight level")
    if any(not 4 <= value.bit_count() <= 8 for value in SUFFIX12_LEVELS):
        raise RuntimeError("A222 suffix design contains an extreme-weight level")
    if any(not 7 <= value.bit_count() <= 13 for value in low20_values):
        raise RuntimeError("A222 low20 design contains an extreme-weight key")


def factorial_eight_block_key_ledger() -> list[dict[str, Any]]:
    rows = _build_ledger()
    validate_eight_block_key_ledger(rows)
    if _canonical_sha256(rows) != EXPECTED_LEDGER_SHA256:
        raise RuntimeError("A222 key ledger digest differs")
    if _canonical_sha256(_ledger_order_material(rows)) != EXPECTED_LEDGER_ORDER_SHA256:
        raise RuntimeError("A222 key ledger order digest differs")
    return rows


def ledger_bytes(rows: Sequence[Mapping[str, Any]] | None = None) -> bytes:
    material = factorial_eight_block_key_ledger() if rows is None else list(rows)
    validate_eight_block_key_ledger(material)
    return _canonical_bytes(material)


def ledger_sha256(rows: Sequence[Mapping[str, Any]] | None = None) -> str:
    digest = hashlib.sha256(ledger_bytes(rows)).hexdigest()
    if rows is None and digest != EXPECTED_LEDGER_SHA256:
        raise RuntimeError("A222 key ledger digest differs")
    return digest


def ledger_order_sha256(rows: Sequence[Mapping[str, Any]] | None = None) -> str:
    material = factorial_eight_block_key_ledger() if rows is None else list(rows)
    validate_eight_block_key_ledger(material)
    digest = _canonical_sha256(_ledger_order_material(material))
    if rows is None and digest != EXPECTED_LEDGER_ORDER_SHA256:
        raise RuntimeError("A222 key ledger order digest differs")
    return digest


def design_manifest() -> dict[str, Any]:
    rows = factorial_eight_block_key_ledger()
    low20_values = tuple(int(row["low20"]) for row in rows)
    key_distances = _pairwise_hamming(low20_values)
    manifest = {
        "schema": SCHEMA,
        "attempt_id": ATTEMPT_ID,
        "ledger_rows": 32,
        "prefix_clusters": 8,
        "suffix_replicates_per_cluster": 4,
        "prefix_cluster_ids": list(PREFIX_CLUSTER_IDS),
        "suffix_replicate_ids": list(SUFFIX_REPLICATE_IDS),
        "prefix8_levels_hex": [f"{value:02x}" for value in PREFIX8_LEVELS],
        "suffix12_levels_hex": [f"{value:03x}" for value in SUFFIX12_LEVELS],
        "ledger_sha256": ledger_sha256(rows),
        "ledger_order_sha256": ledger_order_sha256(rows),
        "prefix_cluster_ids_sha256": _canonical_sha256(list(PREFIX_CLUSTER_IDS)),
        "suffix_replicate_ids_sha256": _canonical_sha256(list(SUFFIX_REPLICATE_IDS)),
        "A220_factorial_ledger_sha256": A220_FACTORIAL_LEDGER_SHA256,
        "A220_low20_set_sha256": EXPECTED_A220_LOW20_SET_SHA256,
        "prior_exclusion_sha256": EXPECTED_PRIOR_EXCLUSION_SHA256,
        "balance": {
            "prefix_bit_one_counts": list(_bit_counts(PREFIX8_LEVELS, 8)),
            "suffix_bit_one_counts": list(_bit_counts(SUFFIX12_LEVELS, 12)),
            "low20_bit_one_counts": list(_bit_counts(low20_values, 20)),
        },
        "diversity": {
            "minimum_prefix_hamming": min(_pairwise_hamming(PREFIX8_LEVELS)),
            "minimum_suffix_hamming": min(_pairwise_hamming(SUFFIX12_LEVELS)),
            "minimum_low20_hamming": min(key_distances),
            "maximum_low20_hamming": max(key_distances),
            "mean_low20_hamming_numerator": sum(key_distances),
            "mean_low20_hamming_denominator": len(key_distances),
        },
        "information_boundary": {
            "rng_clock_network_solver_or_result_input_used": False,
            "A220_prefix_or_suffix_level_reused": False,
            "prior_or_A220_low20_key_reused": False,
        },
    }
    if (
        manifest["prefix_cluster_ids_sha256"] != EXPECTED_PREFIX_CLUSTER_IDS_SHA256
        or manifest["suffix_replicate_ids_sha256"] != EXPECTED_SUFFIX_REPLICATE_IDS_SHA256
    ):
        raise RuntimeError("A222 cluster identity digest differs")
    return manifest

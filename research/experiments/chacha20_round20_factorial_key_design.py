"""Deterministic A220 prefix-by-suffix keys and paired cell orders."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Iterable, Sequence
from typing import Any

PREFIX_SPLITS: dict[str, tuple[int, ...]] = {
    "fit": (0xD6, 0x7E, 0x4C, 0x3B, 0x8D, 0xA3, 0xB0, 0x41),
    "select": (0x55, 0x6A, 0xC8, 0x9F, 0x24),
    "confirm": (0x38, 0xCB, 0x74, 0x13, 0xEE),
}
SUFFIX_SPLITS: dict[str, tuple[int, ...]] = {
    "fit": (0x885, 0x3E3, 0xC7C, 0x71A),
    "confirm": (0x1D1, 0xCAF, 0x61E, 0xB60),
}
PREFIX_SPLIT_ORDER = ("fit", "select", "confirm")
SUFFIX_SPLIT_ORDER = ("fit", "confirm")
FORMULA_GRAY_SOURCE_TO_TARGET = (5, 4, 3, 7, 6, 0, 1, 2)
FORMULA_GRAY_XOR_ANCHOR = 176
EXPECTED_LEDGER_SHA256 = "820e792d740ce2f5aec5586dd1ab5e3ec79bbce8661706d21274d11c8246c0fe"
EXPECTED_ORDER_SHA256 = {
    "numeric_forward": "40aff2e9d2d8922e47afd4648e6967497158785fbd1da870e7110266bf944880",
    "numeric_reverse_same_anchor": (
        "17cbb2feea07cbe912f6f8c094c2469d98f9703052c950ab20796d5cea23217a"
    ),
    "reflected_gray8_forward": ("6ccee3ab08882a58e0debe15a25ada10de0891da82a9ac5fcf4ee591617b0c39"),
    "reflected_gray8_reverse_same_anchor": (
        "adf6f4b68664cd53e55bbecbe52a2756640a73e55cab5f70c2d1dcddad2a3931"
    ),
    "formula_gray8_forward": ("ba9cf4d93c1937665772c77b9091d45cb575054c70037d9cc540ee70a9609127"),
    "formula_gray8_reverse_same_anchor": (
        "7116050e6dd5aef0a295cdd5291205b1ddac952883535f35370e521b190c5ae7"
    ),
}


def _canonical_bytes(value: Any) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode()


def _sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _bit_counts(values: Sequence[int], width: int) -> list[int]:
    return [sum((value >> bit) & 1 for value in values) for bit in range(width)]


def _minimum_hamming(values: Sequence[int]) -> int:
    return min(
        (left ^ right).bit_count()
        for index, left in enumerate(values)
        for right in values[index + 1 :]
    )


def factorial_ledger() -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for prefix_split in PREFIX_SPLIT_ORDER:
        for suffix_split in SUFFIX_SPLIT_ORDER:
            for prefix_index, prefix8 in enumerate(PREFIX_SPLITS[prefix_split]):
                for suffix_index, suffix12 in enumerate(SUFFIX_SPLITS[suffix_split]):
                    low20 = (prefix8 << 12) | suffix12
                    rows.append(
                        {
                            "label": (
                                f"a220_{prefix_split}_p{prefix_index:02d}_"
                                f"{suffix_split}_s{suffix_index:02d}"
                            ),
                            "prefix_split": prefix_split,
                            "prefix_index": prefix_index,
                            "prefix8": prefix8,
                            "prefix8_binary": f"{prefix8:08b}",
                            "suffix_split": suffix_split,
                            "suffix_index": suffix_index,
                            "suffix12": suffix12,
                            "low20": low20,
                            "low20_hex": f"{low20:05x}",
                        }
                    )
    validate_factorial_ledger(rows)
    return rows


def validate_factorial_ledger(
    rows: Sequence[dict[str, Any]], *, forbidden_low20: Iterable[int] = ()
) -> None:
    if len(rows) != 144 or len({int(row["low20"]) for row in rows}) != 144:
        raise RuntimeError("A220 factorial ledger must contain 144 unique low20 keys")
    expected_cells = {
        ("fit", "fit"): 32,
        ("fit", "confirm"): 32,
        ("select", "fit"): 20,
        ("select", "confirm"): 20,
        ("confirm", "fit"): 20,
        ("confirm", "confirm"): 20,
    }
    observed_cells = {
        cell: sum(row["prefix_split"] == cell[0] and row["suffix_split"] == cell[1] for row in rows)
        for cell in expected_cells
    }
    if observed_cells != expected_cells:
        raise RuntimeError("A220 factorial split sizes differ")
    for row in rows:
        prefix = int(row["prefix8"])
        suffix = int(row["suffix12"])
        low20 = int(row["low20"])
        prefix_split = str(row["prefix_split"])
        suffix_split = str(row["suffix_split"])
        prefix_index = int(row["prefix_index"])
        suffix_index = int(row["suffix_index"])
        expected_label = (
            f"a220_{prefix_split}_p{prefix_index:02d}_{suffix_split}_s{suffix_index:02d}"
        )
        if prefix_split not in PREFIX_SPLITS or suffix_split not in SUFFIX_SPLITS:
            raise RuntimeError("A220 factorial ledger row identity differs")
        if (
            prefix_index < 0
            or prefix_index >= len(PREFIX_SPLITS[prefix_split])
            or suffix_index < 0
            or suffix_index >= len(SUFFIX_SPLITS[suffix_split])
            or prefix != PREFIX_SPLITS[prefix_split][prefix_index]
            or suffix != SUFFIX_SPLITS[suffix_split][suffix_index]
            or low20 != (prefix << 12) | suffix
            or row["label"] != expected_label
            or row["prefix8_binary"] != f"{prefix:08b}"
            or row["low20_hex"] != f"{low20:05x}"
        ):
            raise RuntimeError("A220 factorial ledger row identity differs")
    if {int(row["low20"]) for row in rows} & {int(value) for value in forbidden_low20}:
        raise RuntimeError("A220 factorial ledger intersects a forbidden prior key")
    if _bit_counts(PREFIX_SPLITS["fit"], 8) != [4] * 8:
        raise RuntimeError("A220 fit prefixes are not exactly bit-balanced")
    for split in ("select", "confirm"):
        if any(count not in {2, 3} for count in _bit_counts(PREFIX_SPLITS[split], 8)):
            raise RuntimeError(f"A220 {split} prefixes are not near bit-balanced")
    if any(_bit_counts(values, 12) != [2] * 12 for values in SUFFIX_SPLITS.values()):
        raise RuntimeError("A220 suffix panels are not exactly bit-balanced")
    if (
        _minimum_hamming(PREFIX_SPLITS["fit"]) < 3
        or _minimum_hamming(PREFIX_SPLITS["select"]) < 3
        or _minimum_hamming(PREFIX_SPLITS["confirm"]) < 3
        or _minimum_hamming(SUFFIX_SPLITS["fit"]) < 7
        or _minimum_hamming(SUFFIX_SPLITS["confirm"]) < 6
    ):
        raise RuntimeError("A220 factorial levels fail the frozen Hamming-diversity gate")
    if any(
        value.bit_count() < 2 or value.bit_count() > 6
        for values in PREFIX_SPLITS.values()
        for value in values
    ) or any(
        value.bit_count() < 4 or value.bit_count() > 8
        for values in SUFFIX_SPLITS.values()
        for value in values
    ):
        raise RuntimeError("A220 factorial levels contain an extreme-weight contrast value")


def ledger_sha256(rows: Sequence[dict[str, Any]] | None = None) -> str:
    material = factorial_ledger() if rows is None else list(rows)
    digest = _sha256(_canonical_bytes(material))
    if rows is None and digest != EXPECTED_LEDGER_SHA256:
        raise RuntimeError("A220 factorial ledger digest differs")
    return digest


def _permute_bits(value: int) -> int:
    result = 0
    for source, target in enumerate(FORMULA_GRAY_SOURCE_TO_TARGET):
        result |= ((value >> source) & 1) << target
    return result


def _same_anchor_reverse(order: Sequence[int]) -> list[int]:
    values = list(order)
    if len(values) != 256:
        raise ValueError("A220 order must contain 256 values")
    return [values[0], *reversed(values[1:])]


def operator_orders() -> dict[str, list[int]]:
    numeric = list(range(256))
    reflected_gray = [index ^ (index >> 1) for index in range(256)]
    formula_gray = [
        _permute_bits(index ^ (index >> 1)) ^ FORMULA_GRAY_XOR_ANCHOR for index in range(256)
    ]
    orders = {
        "numeric_forward": numeric,
        "numeric_reverse_same_anchor": _same_anchor_reverse(numeric),
        "reflected_gray8_forward": reflected_gray,
        "reflected_gray8_reverse_same_anchor": _same_anchor_reverse(reflected_gray),
        "formula_gray8_forward": formula_gray,
        "formula_gray8_reverse_same_anchor": _same_anchor_reverse(formula_gray),
    }
    for name, order in orders.items():
        if len(order) != 256 or set(order) != set(range(256)):
            raise RuntimeError(f"A220 {name} is not a complete prefix permutation")
        if _sha256(bytes(order)) != EXPECTED_ORDER_SHA256[name]:
            raise RuntimeError(f"A220 {name} digest differs")
    for stem in ("numeric", "reflected_gray8", "formula_gray8"):
        forward = orders[f"{stem}_forward"]
        reverse = orders[f"{stem}_reverse_same_anchor"]
        if reverse != [forward[0], *reversed(forward[1:])]:
            raise RuntimeError(f"A220 {stem} reverse does not preserve the anchor")
    return orders


def order_manifest() -> dict[str, dict[str, Any]]:
    result = {}
    for name, order in operator_orders().items():
        distances = [
            (left ^ right).bit_count() for left, right in zip(order, order[1:], strict=False)
        ]
        result[name] = {
            "sha256_uint8": EXPECTED_ORDER_SHA256[name],
            "start": order[0],
            "second": order[1],
            "end": order[-1],
            "unique_values": len(set(order)),
            "path_hamming_histogram": {
                str(distance): distances.count(distance) for distance in sorted(set(distances))
            },
            "reverse_pair_geometry": (
                "same_anchor_cycle_exact"
                if name.startswith(("reflected_gray8_", "formula_gray8_"))
                else "same_anchor_with_numeric_wrap_edge_substitution"
            ),
        }
    return result

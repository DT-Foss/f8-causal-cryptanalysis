#!/usr/bin/env python3
"""Render the deterministic A200 public-geometry boundary figure."""

from __future__ import annotations

import argparse
import hashlib
import html
import json
from collections.abc import Sequence
from pathlib import Path
from typing import Any

RESULT_FILENAME = "chacha20_round10_public_geometry_partition_v1.json"
RESULT_SHA256 = "a945e95c63499d84cf0c41932dbe056b1eb39adbaf6d7a2096887e1b108d99ad"
FIGURE_FILENAME = "chacha20_a200_round10_public_geometry_boundary_v1.svg"
GEOMETRIES = (
    "gray_prefix_control",
    "fiedler_filtration",
    "laplacian_distinct_modes",
    "signed_svd_distinct_modes",
)
LABELS = {
    "gray_prefix_control": "Gray control",
    "fiedler_filtration": "Fiedler filtration",
    "laplacian_distinct_modes": "Laplacian modes 1–5",
    "signed_svd_distinct_modes": "Signed-SVD modes 1–5",
}


def _file_sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _rref(masks: list[int], width: int = 20) -> tuple[int, ...]:
    rows = masks.copy()
    rank = 0
    for bit in reversed(range(width)):
        pivot = next((i for i in range(rank, len(rows)) if rows[i] >> bit & 1), None)
        if pivot is None:
            continue
        rows[rank], rows[pivot] = rows[pivot], rows[rank]
        for index in range(len(rows)):
            if index != rank and rows[index] >> bit & 1:
                rows[index] ^= rows[rank]
        rank += 1
    return tuple(sorted(rows[:rank], reverse=True))


def _load(path: Path) -> dict[str, Any]:
    if _file_sha256(path) != RESULT_SHA256:
        raise RuntimeError("A200 retained result hash differs")
    payload = json.loads(path.read_bytes())
    comparisons = payload.get("comparisons", {})
    observations = payload.get("execution", {}).get("observations", [])
    if (
        payload.get("attempt_id") != "A200"
        or payload.get("evidence_stage")
        != "ROUND10_PUBLIC_GEOMETRY_COMPLETE_PARTITION_BOUNDARY_RETAINED"
        or len(observations) != 128
        or [row.get("status") for row in observations] != ["unknown"] * 128
        or any(row.get("returncode") != 0 for row in observations)
        or any(row.get("externally_timed_out") is not False for row in observations)
        or payload.get("execution", {}).get("returned_model_count") != 0
        or comparisons.get("primary_prediction_retained") is not False
        or comparisons.get("comparative_prediction_retained") is not False
        or comparisons.get("numeric_prefix_A198_not_reexecuted") is not True
    ):
        raise RuntimeError("A200 retained figure input boundary failed")
    return payload


def render(payload: dict[str, Any]) -> bytes:
    comparisons = payload["comparisons"]
    masks = {
        name: [int(value, 16) for value in payload["geometry_masks"][name]] for name in GEOMETRIES
    }
    spaces = {name: _rref(rows) for name, rows in masks.items()}
    numeric = _rref([1 << bit for bit in range(19, 14, -1)])
    if spaces["gray_prefix_control"] != numeric:
        raise RuntimeError("A200 Gray/numeric row-space fairness gate failed")
    weights = {name: sorted(row.bit_count() for row in space) for name, space in spaces.items()}
    if len({spaces[name] for name in GEOMETRIES[1:]}) != 3:
        raise RuntimeError("A200 formula-derived row spaces are not pairwise distinct")

    lines = [
        '<?xml version="1.0" encoding="UTF-8"?>',
        '<svg xmlns="http://www.w3.org/2000/svg" width="1240" height="800" viewBox="0 0 1240 800" role="img" aria-labelledby="title desc">',
        '  <title id="title">A200 ChaCha10 public-geometry complete-partition boundary</title>',
        '  <desc id="desc">Four complete affine covers each contain 32 unknown cells and no returned model. Gray spans the same row space as the prior numeric prefix, while the three formula-derived row spaces are pairwise distinct.</desc>',
        "  <style>",
        "    .title{font:700 24px system-ui,sans-serif;fill:#17202a}.sub{font:600 15px system-ui,sans-serif;fill:#334155}.label{font:13px system-ui,sans-serif;fill:#334155}.small{font:12px system-ui,sans-serif;fill:#475569}",
        "  </style>",
        '  <rect width="1240" height="800" fill="#fff"/>',
        '  <text x="36" y="42" class="title">A200 — four complete public-geometry covers</text>',
        '  <text x="36" y="69" class="sub">Same still-secret ChaCha10 width-20 challenge · b8 / 4,096 target bits · 10,000 ms per cell</text>',
    ]
    colors = ("#64748b", "#2563a8", "#7c3aed", "#0f766e")
    for panel, geometry in enumerate(GEOMETRIES):
        column, row = panel % 2, panel // 2
        x0, y0 = 36 + column * 594, 94 + row * 246
        result = comparisons["geometry_results"][geometry]
        if result["status_counts"] != {"sat": 0, "unsat": 0, "unknown": 32, "invalid": 0}:
            raise RuntimeError("A200 geometry status gate failed")
        lines.extend(
            [
                f'  <rect x="{x0}" y="{y0}" width="574" height="224" rx="9" fill="#fafbfc" stroke="#9aa6b2" stroke-width="1.5"/>',
                f'  <text x="{x0 + 20}" y="{y0 + 30}" class="sub">{html.escape(LABELS[geometry])}</text>',
                f'  <text x="{x0 + 554}" y="{y0 + 30}" text-anchor="end" class="small">32 × 2¹⁵ = 2²⁰ · 32 UNKNOWN · 0 models</text>',
            ]
        )
        for index in range(32):
            tile_x = x0 + 18 + (index % 8) * 68
            tile_y = y0 + 52 + (index // 8) * 39
            lines.extend(
                [
                    f'  <rect data-geometry="{geometry}" data-cell="{index:05b}" x="{tile_x}" y="{tile_y}" width="61" height="31" rx="4" fill="#f1f3f5" stroke="{colors[panel]}"/>',
                    f'  <text x="{tile_x + 30.5}" y="{tile_y + 20}" text-anchor="middle" class="small">{index:05b}</text>',
                ]
            )

    lines.extend(
        [
            '  <rect x="36" y="590" width="1168" height="174" rx="9" fill="#f8fafc" stroke="#9aa6b2" stroke-width="1.5"/>',
            '  <text x="58" y="622" class="sub">Row-space fairness audit</text>',
            '  <text x="58" y="648" class="label">Gray = A198 numeric-prefix row span exactly: encoding/compiler control, not new cell membership.</text>',
        ]
    )
    y = 675
    for geometry in GEOMETRIES:
        weight_text = ",".join(str(value) for value in weights[geometry])
        relation = (
            "same span as numeric"
            if geometry == "gray_prefix_control"
            else "distinct formula-derived span"
        )
        lines.append(
            f'  <text data-row-space="{geometry}" x="58" y="{y}" class="small">{html.escape(LABELS[geometry])}: canonical RREF weights [{weight_text}] · {relation}</text>'
        )
        y += 22
    lines.extend(
        [
            '  <text x="1200" y="746" text-anchor="end" class="small">All 128 cells executed · UNKNOWN is not UNSAT · no absence, recovery, or uniqueness claim</text>',
            "</svg>",
        ]
    )
    return ("\n".join(lines) + "\n").encode()


def main(argv: Sequence[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    root = Path(__file__).parents[1]
    parser.add_argument("--result", type=Path, default=root / "results/v1" / RESULT_FILENAME)
    parser.add_argument("--output", type=Path, default=root / "results/v1" / FIGURE_FILENAME)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args(argv)
    raw = render(_load(args.result))
    if args.check:
        if not args.output.exists() or args.output.read_bytes() != raw:
            raise RuntimeError(f"deterministic figure differs: {args.output}")
    else:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_bytes(raw)
    print(f"{hashlib.sha256(raw).hexdigest()}  {args.output}")


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""Render deterministic SVG summaries for the retained A187/A188 artifacts."""

from __future__ import annotations

import argparse
import hashlib
import html
import json
import math
from collections.abc import Sequence
from pathlib import Path
from typing import Any

A187_FILENAME = "chacha20_smt_shared_key_multiblock_transfer_v1.json"
A188_FILENAME = "chacha20_bitwuzla_round5_transfer_v1.json"
A189_FILENAME = "chacha20_bitwuzla_round6_width20_transfer_v1.json"
A187_SHA256 = "ec00786b9e778b3914cc2594919da11b763cfffa72f71fa110c2c90dc8e9e3e3"
A188_SHA256 = "d1a75d6456f75257cbd0be41864fad0810540508aa5c30239b16bd3998eef73a"
A189_SHA256 = "e57294c1aabf29f2e8fff87b9b06f0ed1ab0d8392cc9ea79f4f97745904e6b70"
A187_FIGURE = "chacha20_a187_fixed_rlimit_search_shape_v1.svg"
A188_FIGURE = "chacha20_a188_solver_portfolio_v1.svg"
A189_FIGURE = "chacha20_a189_round6_width20_portfolio_v1.svg"


def _load(path: Path, expected_sha256: str) -> dict[str, Any]:
    raw = path.read_bytes()
    observed = hashlib.sha256(raw).hexdigest()
    if observed != expected_sha256:
        raise RuntimeError(f"retained artifact hash differs: {path} ({observed})")
    return json.loads(raw)


def _svg_header(width: int, height: int, title: str, description: str) -> list[str]:
    return [
        '<?xml version="1.0" encoding="UTF-8"?>',
        (
            f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" '
            f'viewBox="0 0 {width} {height}" role="img" aria-labelledby="title desc">'
        ),
        f"  <title id=\"title\">{html.escape(title)}</title>",
        f"  <desc id=\"desc\">{html.escape(description)}</desc>",
        "  <rect width=\"100%\" height=\"100%\" fill=\"#ffffff\"/>",
        "  <style>",
        "    text { font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; fill: #17202a; }",
        "    .title { font-family: ui-sans-serif, system-ui, sans-serif; font-size: 26px; font-weight: 700; }",
        "    .subtitle { font-family: ui-sans-serif, system-ui, sans-serif; font-size: 15px; fill: #43515d; }",
        "    .label { font-size: 13px; }",
        "    .small { font-size: 11px; fill: #43515d; }",
        "    .value { font-size: 11px; font-weight: 700; }",
        "  </style>",
    ]


def render_a187(payload: dict[str, Any]) -> bytes:
    observations = payload["execution"]["observations"]
    if (
        payload["attempt_id"] != "A187"
        or len(observations) != 10
        or any(row["status"] != "unknown" for row in observations)
    ):
        raise RuntimeError("A187 retained figure input boundary failed")

    width, height = 1_240, 760
    lines = _svg_header(
        width,
        height,
        "A187 fixed-rlimit ChaCha5 shared-key search shape",
        "Exact Z3 decisions and conflicts for ten predeclared formulations at rlimit ten million.",
    )
    lines.extend(
        [
            '  <text x="36" y="43" class="title">A187 — fixed-rlimit shared-key search shape</text>',
            '  <text x="36" y="70" class="subtitle">Reduced ChaCha5 · 40 unknown key bits · 216 known key bits · all statuses unknown</text>',
            '  <rect x="930" y="30" width="16" height="12" fill="#2468b4"/><text x="954" y="41" class="label">decisions</text>',
            '  <rect x="1046" y="30" width="16" height="12" fill="#d35454"/><text x="1070" y="41" class="label">conflicts</text>',
        ]
    )

    plot_x, plot_width = 338, 820
    for exponent, label in ((2, "10²"), (3, "10³"), (4, "10⁴"), (5, "10⁵")):
        x = plot_x + (exponent - 2) * plot_width / 3
        lines.append(
            f'  <line x1="{x:.2f}" y1="94" x2="{x:.2f}" y2="670" stroke="#d7dde3" stroke-width="1"/>'
        )
        lines.append(f'  <text x="{x:.2f}" y="690" text-anchor="middle" class="small">{label}</text>')
    lines.append(
        '  <text x="748" y="716" text-anchor="middle" class="subtitle">log₁₀ solver count (exact values printed)</text>'
    )

    highlight = {"split4_full_b1": "#fff4df", "split4_full_b8": "#eaf8ee"}
    for index, row in enumerate(observations):
        y = 112 + index * 54
        variant = row["variant"]
        if variant in highlight:
            lines.append(
                f'  <rect x="24" y="{y - 19}" width="1190" height="47" rx="5" fill="{highlight[variant]}"/>'
            )
        lines.append(f'  <text x="36" y="{y + 7}" class="label">{html.escape(variant)}</text>')
        for offset, key, color in (
            (-7, "sat-decisions", "#2468b4"),
            (9, "sat-conflicts", "#d35454"),
        ):
            value = row["statistics"][key]
            length = (math.log10(value) - 2.0) * plot_width / 3.0
            lines.append(
                f'  <rect x="{plot_x}" y="{y + offset}" width="{length:.2f}" height="12" rx="2" fill="{color}"/>'
            )
            lines.append(
                f'  <text x="{plot_x + length + 7:.2f}" y="{y + offset + 10}" class="value">{value:,}</text>'
            )
    lines.extend(
        [
            '  <text x="36" y="742" class="small">Full b1 → b8: decisions 35,285 → 1,686 (20.93×); conflicts 29,385 → 389 (75.54×).</text>',
            "</svg>",
        ]
    )
    return ("\n".join(lines) + "\n").encode()


def render_a188(payload: dict[str, Any]) -> bytes:
    observations = payload["execution"]["observations"]
    statuses = [row["status"] for row in observations]
    if (
        payload["attempt_id"] != "A188"
        or len(observations) != 8
        or statuses != ["unknown", "unknown", "unknown", "sat", "unknown", "unknown", "invalid", "unknown"]
    ):
        raise RuntimeError("A188 retained figure input boundary failed")

    width, height = 1_240, 510
    lines = _svg_header(
        width,
        height,
        "A188 predeclared ChaCha5 solver portfolio",
        "Complete eight-variant solver portfolio showing the Bitwuzla b8 recovery and b4 prediction boundary.",
    )
    lines.extend(
        [
            '  <text x="36" y="43" class="title">A188 — complete predeclared solver portfolio</text>',
            '  <text x="36" y="70" class="subtitle">Fresh reduced ChaCha5 challenge · 40 unknown key bits · eight counter-related blocks · 5 s per variant</text>',
        ]
    )

    tile_width = 139
    for index, row in enumerate(observations):
        x = 36 + index * 148
        status = row["status"]
        fill = {"sat": "#dff3e4", "unknown": "#f1f3f5", "invalid": "#fff0d5"}[status]
        stroke = {"sat": "#238a4b", "unknown": "#8d99a5", "invalid": "#c57c00"}[status]
        lines.append(
            f'  <rect x="{x}" y="106" width="{tile_width}" height="258" rx="8" fill="{fill}" stroke="{stroke}" stroke-width="2"/>'
        )
        engine = row["engine"]
        mode = row["mode"]
        lines.extend(
            [
                f'  <text x="{x + 10}" y="135" class="label">{html.escape(engine)}</text>',
                f'  <text x="{x + 10}" y="158" class="small">{html.escape(mode)}</text>',
                f'  <text x="{x + 10}" y="181" class="small">blocks = {row["block_count"]}</text>',
                f'  <text x="{x + tile_width / 2:.1f}" y="225" text-anchor="middle" class="title" fill="{stroke}">{status.upper()}</text>',
            ]
        )
        if row["variant"] == "bitwuzla_bitblast_b8":
            lines.extend(
                [
                    f'  <text x="{x + tile_width / 2:.1f}" y="258" text-anchor="middle" class="value">0x5345585503</text>',
                    f'  <text x="{x + tile_width / 2:.1f}" y="280" text-anchor="middle" class="small">4096/4096 bits</text>',
                    f'  <text x="{x + tile_width / 2:.1f}" y="300" text-anchor="middle" class="small">control rejected</text>',
                    f'  <text x="{x + tile_width / 2:.1f}" y="330" text-anchor="middle" class="value">4.856995 s</text>',
                ]
            )
        elif row["variant"] in {"bitwuzla_bitblast_b4", "bitwuzla_preprop_b4"}:
            lines.extend(
                [
                    f'  <text x="{x + tile_width / 2:.1f}" y="276" text-anchor="middle" class="small">predeclared</text>',
                    f'  <text x="{x + tile_width / 2:.1f}" y="296" text-anchor="middle" class="small">prediction view</text>',
                ]
            )
        elif row["variant"] == "z3_bitblast_b4":
            lines.extend(
                [
                    f'  <text x="{x + tile_width / 2:.1f}" y="270" text-anchor="middle" class="small">no status token</text>',
                    f'  <text x="{x + tile_width / 2:.1f}" y="290" text-anchor="middle" class="small">parser boundary</text>',
                ]
            )
        lines.append(
            f'  <text x="{x + tile_width / 2:.1f}" y="350" text-anchor="middle" class="small">{html.escape(row["variant"].replace("_", " "))}</text>'
        )

    lines.extend(
        [
            '  <path d="M 332 390 L 332 414 L 776 414 L 776 390" fill="none" stroke="#c57c00" stroke-width="2"/>',
            '  <text x="554" y="438" text-anchor="middle" class="subtitle">Frozen b4 prediction not retained; the predeclared b8 view is the recovered-instance boundary.</text>',
            '  <text x="36" y="478" class="small">All eight variants executed in fixed order without early stop. This is reduced-round partial-key recovery, not fullround ChaCha20.</text>',
            "</svg>",
        ]
    )
    return ("\n".join(lines) + "\n").encode()


def render_a189(payload: dict[str, Any]) -> bytes:
    observations = payload["execution"]["observations"]
    statuses = [row["status"] for row in observations]
    if (
        payload["attempt_id"] != "A189"
        or len(observations) != 8
        or statuses != ["sat", "unknown", "unknown", "sat", "sat", "unknown", "invalid", "unknown"]
    ):
        raise RuntimeError("A189 retained figure input boundary failed")

    width, height = 1_240, 510
    lines = _svg_header(
        width,
        height,
        "A189 prospective ChaCha6 width-20 solver portfolio",
        "Complete eight-variant portfolio showing the retained b8 prediction, the independent preprop b8 recovery, and the b1 recovery.",
    )
    lines.extend(
        [
            '  <text x="36" y="43" class="title">A189 — prospective round-6 width-20 transfer</text>',
            '  <text x="36" y="70" class="subtitle">Fresh reduced ChaCha6 · 20 unknown key bits · 236 known key bits · eight counter-related blocks</text>',
        ]
    )

    tile_width = 139
    for index, row in enumerate(observations):
        x = 36 + index * 148
        status = row["status"]
        fill = {"sat": "#dff3e4", "unknown": "#f1f3f5", "invalid": "#fff0d5"}[status]
        stroke = {"sat": "#238a4b", "unknown": "#8d99a5", "invalid": "#c57c00"}[status]
        lines.append(
            f'  <rect x="{x}" y="106" width="{tile_width}" height="258" rx="8" fill="{fill}" stroke="{stroke}" stroke-width="2"/>'
        )
        lines.extend(
            [
                f'  <text x="{x + 10}" y="135" class="label">{html.escape(row["engine"])}</text>',
                f'  <text x="{x + 10}" y="158" class="small">{html.escape(row["mode"])}</text>',
                f'  <text x="{x + 10}" y="181" class="small">blocks = {row["block_count"]}</text>',
                f'  <text x="{x + tile_width / 2:.1f}" y="225" text-anchor="middle" class="title" fill="{stroke}">{status.upper()}</text>',
            ]
        )
        if status == "sat":
            checked = 4_096 if row["block_count"] == 8 else 512
            label = (
                "predicted b8"
                if row["variant"] == "bitwuzla_bitblast_b8"
                else "independent b8"
                if row["variant"] == "bitwuzla_preprop_b8"
                else "b1 boundary"
            )
            lines.extend(
                [
                    f'  <text x="{x + tile_width / 2:.1f}" y="258" text-anchor="middle" class="value">low20 = 0x6fa70</text>',
                    f'  <text x="{x + tile_width / 2:.1f}" y="280" text-anchor="middle" class="small">{checked}/{checked} bits</text>',
                    f'  <text x="{x + tile_width / 2:.1f}" y="300" text-anchor="middle" class="small">control rejected</text>',
                    f'  <text x="{x + tile_width / 2:.1f}" y="322" text-anchor="middle" class="value">{row["volatile_seconds"]:.6f} s</text>',
                    f'  <text x="{x + tile_width / 2:.1f}" y="342" text-anchor="middle" class="small">{label}</text>',
                ]
            )
        elif row["variant"] == "z3_bitblast_b8":
            lines.extend(
                [
                    f'  <text x="{x + tile_width / 2:.1f}" y="270" text-anchor="middle" class="small">no status token</text>',
                    f'  <text x="{x + tile_width / 2:.1f}" y="290" text-anchor="middle" class="small">parser boundary</text>',
                ]
            )
        if status != "sat":
            lines.append(
                f'  <text x="{x + tile_width / 2:.1f}" y="350" text-anchor="middle" class="small">{html.escape(row["variant"].replace("_", " "))}</text>'
            )

    lines.extend(
        [
            '  <path d="M 480 390 L 480 414 L 776 414 L 776 390" fill="none" stroke="#238a4b" stroke-width="2"/>',
            '  <text x="628" y="438" text-anchor="middle" class="subtitle">Prospective bitblast b8 prediction retained; preprop b8 independently returns the same assignment.</text>',
            '  <text x="36" y="478" class="small">All eight variants executed without early stop. The predeclared b1 view also returns low20 = 0x6fa70 with an independent 512-bit check.</text>',
            "</svg>",
        ]
    )
    return ("\n".join(lines) + "\n").encode()


def _write_or_check(path: Path, raw: bytes, *, check: bool) -> None:
    if check:
        if not path.exists() or path.read_bytes() != raw:
            raise RuntimeError(f"deterministic figure differs: {path}")
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(raw)


def main(argv: Sequence[str] | None = None) -> None:
    parser = argparse.ArgumentParser()
    research_root = Path(__file__).parents[1]
    parser.add_argument("--results-dir", type=Path, default=research_root / "results" / "v1")
    parser.add_argument("--output-dir", type=Path, default=research_root / "results" / "v1")
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args(argv)

    a187 = _load(args.results_dir / A187_FILENAME, A187_SHA256)
    a188 = _load(args.results_dir / A188_FILENAME, A188_SHA256)
    a189 = _load(args.results_dir / A189_FILENAME, A189_SHA256)
    outputs = {
        args.output_dir / A187_FIGURE: render_a187(a187),
        args.output_dir / A188_FIGURE: render_a188(a188),
        args.output_dir / A189_FIGURE: render_a189(a189),
    }
    for path, raw in outputs.items():
        _write_or_check(path, raw, check=args.check)
        print(f"{hashlib.sha256(raw).hexdigest()}  {path}")


if __name__ == "__main__":
    main()

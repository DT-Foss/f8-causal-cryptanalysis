#!/usr/bin/env python3
"""Render deterministic SVG summaries for retained A187--A198 artifacts."""

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
A190_FILENAME = "chacha20_bitwuzla_round7_width18_transfer_v1.json"
A191_FILENAME = "chacha20_bitwuzla_round7_partition_transfer_v1.json"
A192_FILENAME = "chacha20_bitwuzla_round7_width20_partition_transfer_v1.json"
A193_FILENAME = "chacha20_bitwuzla_round8_width20_partition_transfer_v1.json"
A194_FILENAME = "chacha20_bitwuzla_round9_width20_partition_transfer_v1.json"
A195_FILENAME = "chacha20_bitwuzla_round10_width20_partition_transfer_v1.json"
A196_FILENAME = "chacha20_bitwuzla_round10_split9_transfer_v1.json"
A197_FILENAME = "chacha20_bitwuzla_round10_width12_refinement_v1.json"
A198_FILENAME = "chacha20_bitwuzla_round10_b8_partition_transfer_v1.json"
A187_SHA256 = "ec00786b9e778b3914cc2594919da11b763cfffa72f71fa110c2c90dc8e9e3e3"
A188_SHA256 = "d1a75d6456f75257cbd0be41864fad0810540508aa5c30239b16bd3998eef73a"
A189_SHA256 = "e57294c1aabf29f2e8fff87b9b06f0ed1ab0d8392cc9ea79f4f97745904e6b70"
A190_SHA256 = "f1cdad782a7ed82e893517eb2bffc1973640652bd59bcdc6a76a8ce060659220"
A191_SHA256 = "11911962fa7cdfaa3c1b996e2f45ccbbc3584948612ef98d88b3719099c31172"
A192_SHA256 = "0d29693fe454ca6827c2c7eb11179a62f79fc39459b99941a0f5b500dcf422c2"
A193_SHA256 = "b4d146be64030e08ca6e7ce2e626acfa52ba8a4e6003ec5e605760b295053fae"
A194_SHA256 = "d1a8b58f313467851d5162998d1ed8a71e250f64ee5d98d5ea6024c0e814227b"
A195_SHA256 = "8d8fc41df65d98af3eb7a0e117b2255c07e465cc16638f67ebe7df39dcc7e107"
A196_SHA256 = "722a2e0d6c697d47189f157b9878d723dc05e264f328c2386ef9189458b33eaa"
A197_SHA256 = "177a76c130d3705e8e3ebcd35f517486b204c6f7d501adaae1cdba8dca90060c"
A198_SHA256 = "693367464ab488c49d386c1d011e8c45e7fb094cceeb37352934dde121773373"
A187_FIGURE = "chacha20_a187_fixed_rlimit_search_shape_v1.svg"
A188_FIGURE = "chacha20_a188_solver_portfolio_v1.svg"
A189_FIGURE = "chacha20_a189_round6_width20_portfolio_v1.svg"
A190_FIGURE = "chacha20_a190_round7_width18_boundary_v1.svg"
A191_FIGURE = "chacha20_a191_round7_complete_partition_v1.svg"
A192_FIGURE = "chacha20_a192_round7_width20_complete_partition_v1.svg"
A193_FIGURE = "chacha20_a193_round8_width20_partition_transfer_v1.svg"
A194_FIGURE = "chacha20_a194_round9_width20_partition_transfer_v1.svg"
A195_FIGURE = "chacha20_a195_round10_width20_partition_boundary_v1.svg"
A196_FIGURE = "chacha20_a196_round10_split8_split9_cut_boundary_v1.svg"
A197_FIGURE = "chacha20_a197_round10_width12_refinement_boundary_v1.svg"
A198_FIGURE = "chacha20_a198_round10_b8_two_budget_boundary_v1.svg"


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
        f'  <title id="title">{html.escape(title)}</title>',
        f'  <desc id="desc">{html.escape(description)}</desc>',
        '  <rect width="100%" height="100%" fill="#ffffff"/>',
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
        lines.append(
            f'  <text x="{x:.2f}" y="690" text-anchor="middle" class="small">{label}</text>'
        )
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
        or statuses
        != ["unknown", "unknown", "unknown", "sat", "unknown", "unknown", "invalid", "unknown"]
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


def render_a190(payload: dict[str, Any]) -> bytes:
    observations = payload["execution"]["observations"]
    statuses = [row["status"] for row in observations]
    if (
        payload["attempt_id"] != "A190"
        or len(observations) != 9
        or statuses != ["unknown"] * 7 + ["invalid", "unknown"]
        or payload["execution"]["returned_model_count"] != 0
    ):
        raise RuntimeError("A190 retained figure input boundary failed")

    width, height = 1_400, 520
    lines = _svg_header(
        width,
        height,
        "A190 prospective ChaCha7 width-18 instance boundary",
        "Complete nine-view portable solver portfolio with eight unknown statuses, one exact Z3 parser boundary, and no returned model.",
    )
    lines.extend(
        [
            '  <text x="30" y="43" class="title">A190 — prospective round-7 width-18 instance boundary</text>',
            '  <text x="30" y="70" class="subtitle">Fresh reduced ChaCha7 · 18 unknown key bits · 238 known key bits · complete nine-view portfolio</text>',
        ]
    )

    tile_width = 138
    for index, row in enumerate(observations):
        x = 30 + index * 150
        status = row["status"]
        fill = {"unknown": "#f1f3f5", "invalid": "#fff0d5"}[status]
        stroke = {"unknown": "#667788", "invalid": "#c57c00"}[status]
        lines.append(
            f'  <rect x="{x}" y="106" width="{tile_width}" height="268" rx="8" fill="{fill}" stroke="{stroke}" stroke-width="2"/>'
        )
        lines.extend(
            [
                f'  <text x="{x + 10}" y="135" class="label">{html.escape(row["engine"])}</text>',
                f'  <text x="{x + 10}" y="158" class="small">{html.escape(row["mode"])} · {html.escape(row["cut"])}</text>',
                f'  <text x="{x + 10}" y="181" class="small">blocks = {row["block_count"]}</text>',
                f'  <text x="{x + tile_width / 2:.1f}" y="230" text-anchor="middle" class="title" fill="{stroke}">{status.upper()}</text>',
                f'  <text x="{x + tile_width / 2:.1f}" y="268" text-anchor="middle" class="small">budget {row["solver_time_limit_milliseconds"] // 1000} s</text>',
            ]
        )
        if row["variant"] == "z3_bitblast_split6_b1":
            lines.extend(
                [
                    f'  <text x="{x + tile_width / 2:.1f}" y="294" text-anchor="middle" class="small">no status token</text>',
                    f'  <text x="{x + tile_width / 2:.1f}" y="314" text-anchor="middle" class="small">parser boundary</text>',
                ]
            )
        else:
            lines.append(
                f'  <text x="{x + tile_width / 2:.1f}" y="304" text-anchor="middle" class="small">no model</text>'
            )
        lines.append(
            f'  <text x="{x + tile_width / 2:.1f}" y="350" text-anchor="middle" class="small">{html.escape(row["variant"].replace("_", " "))}</text>'
        )

    lines.extend(
        [
            '  <path d="M 30 400 L 30 424 L 1368 424 L 1368 400" fill="none" stroke="#667788" stroke-width="2"/>',
            '  <text x="699" y="450" text-anchor="middle" class="subtitle">All nine predeclared views executed without early stop; zero models were returned.</text>',
            '  <text x="30" y="486" class="small">Retained result: a prospective round-7 width-18 monolithic/portfolio instance boundary, not an absence claim for the complete 2¹⁸ domain.</text>',
            "</svg>",
        ]
    )
    return ("\n".join(lines) + "\n").encode()


def render_a191(payload: dict[str, Any]) -> bytes:
    observations = payload["execution"]["observations"]
    statuses = [row["status"] for row in observations]
    if (
        payload["attempt_id"] != "A191"
        or len(observations) != 8
        or statuses != ["unsat"] * 7 + ["sat"]
        or payload["comparisons"]["complete_domain_candidate_count"] != 1 << 18
    ):
        raise RuntimeError("A191 retained figure input boundary failed")

    width, height = 1_240, 550
    lines = _svg_header(
        width,
        height,
        "A191 assignment-free complete ChaCha7 width-18 partition",
        "All eight disjoint 15-bit prefix cells covering the original 18-bit domain, with seven UNSAT cells and one independently confirmed SAT cell.",
    )
    lines.extend(
        [
            '  <text x="36" y="43" class="title">A191 — assignment-free complete round-7 partition</text>',
            '  <text x="36" y="70" class="subtitle">Fresh reduced ChaCha7 · unchanged 2¹⁸ candidate domain · eight disjoint 2¹⁵ cells · fixed numeric order</text>',
        ]
    )

    tile_width = 139
    for index, row in enumerate(observations):
        x = 36 + index * 148
        status = row["status"]
        fill = {"unsat": "#eaf1f8", "sat": "#dff3e4"}[status]
        stroke = {"unsat": "#356c9b", "sat": "#238a4b"}[status]
        lines.append(
            f'  <rect x="{x}" y="106" width="{tile_width}" height="270" rx="8" fill="{fill}" stroke="{stroke}" stroke-width="2"/>'
        )
        lines.extend(
            [
                f'  <text x="{x + tile_width / 2:.1f}" y="139" text-anchor="middle" class="label">prefix {html.escape(row["prefix"])}</text>',
                f'  <text x="{x + tile_width / 2:.1f}" y="166" text-anchor="middle" class="small">bits 17…15 fixed</text>',
                f'  <text x="{x + tile_width / 2:.1f}" y="188" text-anchor="middle" class="small">2¹⁵ candidates</text>',
                f'  <text x="{x + tile_width / 2:.1f}" y="238" text-anchor="middle" class="title" fill="{stroke}">{status.upper()}</text>',
            ]
        )
        if status == "sat":
            lines.extend(
                [
                    f'  <text x="{x + tile_width / 2:.1f}" y="274" text-anchor="middle" class="value">low18 = 0x3d051</text>',
                    f'  <text x="{x + tile_width / 2:.1f}" y="298" text-anchor="middle" class="small">512/512 bits</text>',
                    f'  <text x="{x + tile_width / 2:.1f}" y="320" text-anchor="middle" class="small">control rejected</text>',
                ]
            )
        else:
            lines.extend(
                [
                    f'  <text x="{x + tile_width / 2:.1f}" y="286" text-anchor="middle" class="small">cell closed</text>',
                    f'  <text x="{x + tile_width / 2:.1f}" y="308" text-anchor="middle" class="small">no model</text>',
                ]
            )
        lines.append(
            f'  <text x="{x + tile_width / 2:.1f}" y="350" text-anchor="middle" class="small">{html.escape(row["variant"].replace("_", " "))}</text>'
        )

    lines.extend(
        [
            '  <path d="M 36 402 L 36 430 L 1211 430 L 1211 402" fill="none" stroke="#17202a" stroke-width="2"/>',
            '  <text x="623.5" y="458" text-anchor="middle" class="subtitle">8 × 2¹⁵ = 2¹⁸: pairwise-disjoint union equals the complete original domain.</text>',
            '  <text x="36" y="496" class="small">All cells executed in frozen order with no early stop. Prefixes 000–110 are UNSAT; prefix 111 returns the independently confirmed assignment.</text>',
            '  <text x="36" y="522" class="small">The partition changes representation only; it does not shrink the candidate domain.</text>',
            "</svg>",
        ]
    )
    return ("\n".join(lines) + "\n").encode()


def render_a192(payload: dict[str, Any]) -> bytes:
    observations = payload["execution"]["observations"]
    statuses = [row["status"] for row in observations]
    if (
        payload["attempt_id"] != "A192"
        or len(observations) != 32
        or statuses != ["sat"] + ["unsat"] * 31
        or payload["comparisons"]["complete_domain_candidate_count"] != 1 << 20
    ):
        raise RuntimeError("A192 retained figure input boundary failed")

    width, height = 1_240, 800
    lines = _svg_header(
        width,
        height,
        "A192 assignment-free complete ChaCha7 width-20 partition",
        "Thirty-two disjoint 15-bit prefix cells covering the complete original 20-bit domain, with one independently confirmed SAT cell and thirty-one UNSAT cells.",
    )
    lines.extend(
        [
            '  <text x="36" y="43" class="title">A192 — prospective complete width-20 partition scaling</text>',
            '  <text x="36" y="70" class="subtitle">Fresh reduced ChaCha7 · unchanged 2²⁰ domain · 32 disjoint 2¹⁵ cells · assignment-free numeric order</text>',
        ]
    )

    tile_width, tile_height = 139, 116
    for index, row in enumerate(observations):
        column, grid_row = index % 8, index // 8
        x = 36 + column * 148
        y = 104 + grid_row * 132
        status = row["status"]
        fill = {"unsat": "#eaf1f8", "sat": "#dff3e4"}[status]
        stroke = {"unsat": "#356c9b", "sat": "#238a4b"}[status]
        lines.append(
            f'  <rect x="{x}" y="{y}" width="{tile_width}" height="{tile_height}" rx="7" fill="{fill}" stroke="{stroke}" stroke-width="2"/>'
        )
        lines.extend(
            [
                f'  <text x="{x + tile_width / 2:.1f}" y="{y + 27}" text-anchor="middle" class="label">prefix {html.escape(row["prefix"])}</text>',
                f'  <text x="{x + tile_width / 2:.1f}" y="{y + 59}" text-anchor="middle" class="value" fill="{stroke}">{status.upper()}</text>',
                f'  <text x="{x + tile_width / 2:.1f}" y="{y + 86}" text-anchor="middle" class="small">2¹⁵ candidates</text>',
            ]
        )
        if status == "sat":
            lines.append(
                f'  <text x="{x + tile_width / 2:.1f}" y="{y + 106}" text-anchor="middle" class="small">low20 0x05eb0 · 512/512</text>'
            )

    lines.extend(
        [
            '  <path d="M 36 650 L 36 678 L 1211 678 L 1211 650" fill="none" stroke="#17202a" stroke-width="2"/>',
            '  <text x="623.5" y="706" text-anchor="middle" class="subtitle">32 × 2¹⁵ = 2²⁰: the pairwise-disjoint union equals all 1,048,576 original candidates.</text>',
            '  <text x="36" y="744" class="small">Prefix 00000 returns the independently confirmed model; every other prefix is UNSAT. All 32 cells execute without early stop.</text>',
            '  <text x="36" y="770" class="small">A191 → A192 holds cell width at 15 while scaling the complete unknown domain from 18 to 20 bits.</text>',
            "</svg>",
        ]
    )
    return ("\n".join(lines) + "\n").encode()


def render_a193(payload: dict[str, Any]) -> bytes:
    observations = payload["execution"]["observations"]
    statuses = [row["status"] for row in observations]
    if (
        payload["attempt_id"] != "A193"
        or len(observations) != 32
        or statuses != ["unknown"] * 11 + ["sat"] + ["unknown"] * 20
        or payload["comparisons"]["complete_domain_candidate_count"] != 1 << 20
    ):
        raise RuntimeError("A193 retained figure input boundary failed")

    width, height = 1_240, 820
    lines = _svg_header(
        width,
        height,
        "A193 prospective ChaCha8 width-20 complete-partition transfer",
        "Thirty-two structurally complete split7 prefix cells covering the full 20-bit domain, with one independently confirmed SAT recovery and thirty-one bounded UNKNOWN cells.",
    )
    lines.extend(
        [
            '  <text x="36" y="43" class="title">A193 — prospective round-8 width-20 depth transfer</text>',
            '  <text x="36" y="70" class="subtitle">Fresh reduced ChaCha8 · split7 · unchanged 2²⁰ domain · 32 disjoint 2¹⁵ cells</text>',
        ]
    )

    tile_width, tile_height = 139, 116
    for index, row in enumerate(observations):
        column, grid_row = index % 8, index // 8
        x = 36 + column * 148
        y = 104 + grid_row * 132
        status = row["status"]
        fill = {"unknown": "#f1f3f5", "sat": "#dff3e4"}[status]
        stroke = {"unknown": "#667788", "sat": "#238a4b"}[status]
        lines.append(
            f'  <rect x="{x}" y="{y}" width="{tile_width}" height="{tile_height}" rx="7" fill="{fill}" stroke="{stroke}" stroke-width="2"/>'
        )
        lines.extend(
            [
                f'  <text x="{x + tile_width / 2:.1f}" y="{y + 27}" text-anchor="middle" class="label">prefix {html.escape(row["prefix"])}</text>',
                f'  <text x="{x + tile_width / 2:.1f}" y="{y + 59}" text-anchor="middle" class="value" fill="{stroke}">{status.upper()}</text>',
                f'  <text x="{x + tile_width / 2:.1f}" y="{y + 86}" text-anchor="middle" class="small">2¹⁵ candidates</text>',
            ]
        )
        if status == "sat":
            lines.append(
                f'  <text x="{x + tile_width / 2:.1f}" y="{y + 106}" text-anchor="middle" class="small">low20 0x5a40a · 512/512</text>'
            )

    lines.extend(
        [
            '  <path d="M 36 650 L 36 678 L 1211 678 L 1211 650" fill="none" stroke="#17202a" stroke-width="2"/>',
            '  <text x="623.5" y="706" text-anchor="middle" class="subtitle">32 × 2¹⁵ = 2²⁰: structural partition coverage equals all 1,048,576 original candidates.</text>',
            '  <text x="36" y="744" class="small">Prefix 01011 returns low20 0x5a40a with independent 512-bit confirmation and control rejection.</text>',
            '  <text x="36" y="770" class="small">The other 31 cells are UNKNOWN, not UNSAT: recovery transfer is retained; uniqueness is not adjudicated.</text>',
            '  <text x="36" y="796" class="small">All 32 predeclared cells execute in fixed numeric order without early stop.</text>',
            "</svg>",
        ]
    )
    return ("\n".join(lines) + "\n").encode()


def render_a194(payload: dict[str, Any]) -> bytes:
    observations = payload["execution"]["observations"]
    statuses = [row["status"] for row in observations]
    if (
        payload["attempt_id"] != "A194"
        or len(observations) != 32
        or statuses != ["unknown"] * 16 + ["sat"] + ["unknown"] * 15
        or payload["comparisons"]["complete_domain_candidate_count"] != 1 << 20
    ):
        raise RuntimeError("A194 retained figure input boundary failed")

    width, height = 1_240, 820
    lines = _svg_header(
        width,
        height,
        "A194 prospective ChaCha9 width-20 complete-partition transfer",
        "Thirty-two structurally complete split8 prefix cells covering the full 20-bit domain, with one independently confirmed SAT recovery and thirty-one bounded UNKNOWN cells.",
    )
    lines.extend(
        [
            '  <text x="36" y="43" class="title">A194 — prospective round-9 width-20 depth transfer</text>',
            '  <text x="36" y="70" class="subtitle">Fresh reduced ChaCha9 · split8 · unchanged 2²⁰ domain · 32 disjoint 2¹⁵ cells</text>',
        ]
    )

    tile_width, tile_height = 139, 116
    for index, row in enumerate(observations):
        column, grid_row = index % 8, index // 8
        x = 36 + column * 148
        y = 104 + grid_row * 132
        status = row["status"]
        fill = {"unknown": "#f1f3f5", "sat": "#dff3e4"}[status]
        stroke = {"unknown": "#667788", "sat": "#238a4b"}[status]
        lines.append(
            f'  <rect x="{x}" y="{y}" width="{tile_width}" height="{tile_height}" rx="7" fill="{fill}" stroke="{stroke}" stroke-width="2"/>'
        )
        lines.extend(
            [
                f'  <text x="{x + tile_width / 2:.1f}" y="{y + 27}" text-anchor="middle" class="label">prefix {html.escape(row["prefix"])}</text>',
                f'  <text x="{x + tile_width / 2:.1f}" y="{y + 59}" text-anchor="middle" class="value" fill="{stroke}">{status.upper()}</text>',
                f'  <text x="{x + tile_width / 2:.1f}" y="{y + 86}" text-anchor="middle" class="small">2¹⁵ candidates</text>',
            ]
        )
        if status == "sat":
            lines.append(
                f'  <text x="{x + tile_width / 2:.1f}" y="{y + 106}" text-anchor="middle" class="small">low20 0x8675b · 512/512</text>'
            )

    lines.extend(
        [
            '  <path d="M 36 650 L 36 678 L 1211 678 L 1211 650" fill="none" stroke="#17202a" stroke-width="2"/>',
            '  <text x="623.5" y="706" text-anchor="middle" class="subtitle">32 × 2¹⁵ = 2²⁰: structural partition coverage equals all 1,048,576 original candidates.</text>',
            '  <text x="36" y="744" class="small">Prefix 10000 returns low20 0x8675b with independent 512-bit confirmation and control rejection.</text>',
            '  <text x="36" y="770" class="small">The other 31 cells are UNKNOWN, not UNSAT: recovery transfer is retained; uniqueness is not adjudicated.</text>',
            '  <text x="36" y="796" class="small">All 32 predeclared split8 cells execute in fixed numeric order without early stop.</text>',
            "</svg>",
        ]
    )
    return ("\n".join(lines) + "\n").encode()


def render_a195(payload: dict[str, Any]) -> bytes:
    observations = payload["execution"]["observations"]
    statuses = [row["status"] for row in observations]
    if (
        payload["attempt_id"] != "A195"
        or len(observations) != 32
        or statuses != ["unknown"] * 32
        or payload["execution"]["returned_model_count"] != 0
        or payload["comparisons"]["complete_domain_candidate_count"] != 1 << 20
    ):
        raise RuntimeError("A195 retained figure input boundary failed")

    width, height = 1_240, 820
    lines = _svg_header(
        width,
        height,
        "A195 prospective ChaCha10 width-20 complete-partition boundary",
        "Thirty-two structurally complete split8 prefix cells covering the full 20-bit domain; all bounded outcomes are UNKNOWN and no model is returned.",
    )
    lines.extend(
        [
            '  <text x="36" y="43" class="title">A195 — prospective round-10 width-20 depth boundary</text>',
            '  <text x="36" y="70" class="subtitle">Fresh reduced ChaCha10 · split8 · unchanged 2²⁰ domain · 32 disjoint 2¹⁵ cells</text>',
        ]
    )

    tile_width, tile_height = 139, 116
    for index, row in enumerate(observations):
        column, grid_row = index % 8, index // 8
        x = 36 + column * 148
        y = 104 + grid_row * 132
        lines.extend(
            [
                f'  <rect x="{x}" y="{y}" width="{tile_width}" height="{tile_height}" rx="7" fill="#f1f3f5" stroke="#667788" stroke-width="2"/>',
                f'  <text x="{x + tile_width / 2:.1f}" y="{y + 27}" text-anchor="middle" class="label">prefix {html.escape(row["prefix"])}</text>',
                f'  <text x="{x + tile_width / 2:.1f}" y="{y + 59}" text-anchor="middle" class="value" fill="#667788">UNKNOWN</text>',
                f'  <text x="{x + tile_width / 2:.1f}" y="{y + 86}" text-anchor="middle" class="small">2¹⁵ candidates</text>',
            ]
        )

    lines.extend(
        [
            '  <path d="M 36 650 L 36 678 L 1211 678 L 1211 650" fill="none" stroke="#17202a" stroke-width="2"/>',
            '  <text x="623.5" y="706" text-anchor="middle" class="subtitle">32 × 2¹⁵ = 2²⁰: structural partition coverage equals all 1,048,576 original candidates.</text>',
            '  <text x="36" y="744" class="small">All 32 predeclared split8 cells execute in fixed numeric order without early stop; zero models are returned.</text>',
            '  <text x="36" y="770" class="small">Every outcome is UNKNOWN, not UNSAT: this is a fresh-instance/cut transfer boundary, not an absence claim.</text>',
            '  <text x="36" y="796" class="small">The boundary motivates the separately frozen split9 A196 follow-up; A195 itself makes no recovery claim.</text>',
            "</svg>",
        ]
    )
    return ("\n".join(lines) + "\n").encode()


def render_a196(payload: dict[str, Any], a195_payload: dict[str, Any]) -> bytes:
    a195_observations = a195_payload["execution"]["observations"]
    a196_observations = payload["execution"]["observations"]
    if (
        a195_payload["attempt_id"] != "A195"
        or payload["attempt_id"] != "A196"
        or len(a195_observations) != 32
        or len(a196_observations) != 32
        or [row["status"] for row in a195_observations] != ["unknown"] * 32
        or [row["status"] for row in a196_observations] != ["unknown"] * 32
        or payload["public_challenge"] != a195_payload["public_challenge"]
        or payload["comparisons"] != a195_payload["comparisons"]
    ):
        raise RuntimeError("A196 retained figure input boundary failed")

    width, height = 1_240, 820
    lines = _svg_header(
        width,
        height,
        "A196 controlled ChaCha10 split8 versus split9 cut boundary",
        "The same still-secret round-10 width-20 challenge has status-equivalent complete 32-cell split8 and split9 boundaries: all cells are UNKNOWN and no model is returned.",
    )
    lines.extend(
        [
            '  <text x="36" y="43" class="title">A196 — controlled split8 versus split9 cut transfer</text>',
            '  <text x="36" y="70" class="subtitle">Byte-identical fresh ChaCha10 challenge · unchanged 2²⁰ domain · equal 10 s per-cell budgets</text>',
        ]
    )

    tile_width, tile_height = 63, 82
    for panel, (label, observations) in enumerate(
        (("A195 · split8", a195_observations), ("A196 · split9", a196_observations))
    ):
        panel_x = 36 + panel * 600
        lines.extend(
            [
                f'  <rect x="{panel_x}" y="96" width="568" height="424" rx="9" fill="#fafbfc" stroke="#9aa6b2" stroke-width="2"/>',
                f'  <text x="{panel_x + 284}" y="128" text-anchor="middle" class="subtitle">{label} · 32/32 UNKNOWN · 0 models</text>',
            ]
        )
        for index, row in enumerate(observations):
            column, grid_row = index % 8, index // 8
            x = panel_x + 16 + column * 68
            y = 146 + grid_row * 91
            lines.extend(
                [
                    f'  <rect x="{x}" y="{y}" width="{tile_width}" height="{tile_height}" rx="5" fill="#f1f3f5" stroke="#667788"/>',
                    f'  <text x="{x + tile_width / 2:.1f}" y="{y + 25}" text-anchor="middle" class="small">{html.escape(row["prefix"])}</text>',
                    f'  <text x="{x + tile_width / 2:.1f}" y="{y + 50}" text-anchor="middle" class="small">UNKNOWN</text>',
                    f'  <text x="{x + tile_width / 2:.1f}" y="{y + 69}" text-anchor="middle" class="small">2¹⁵</text>',
                ]
            )

    lines.extend(
        [
            '  <path d="M 36 556 L 36 584 L 1204 584 L 1204 556" fill="none" stroke="#17202a" stroke-width="2"/>',
            '  <text x="620" y="612" text-anchor="middle" class="subtitle">Each cut: 32 × 2¹⁵ = 2²⁰, a complete disjoint structural cover of the same 1,048,576 candidates.</text>',
            '  <text x="36" y="658" class="small">Same public-challenge SHA-256: 5d17ed241b6b91224a4974f36b4b0b4ec5c677b9d975dd6bc8cec83b6ddbf86b.</text>',
            '  <text x="36" y="690" class="small">Split8 and split9 are status-equivalent complete boundaries under this fixed budget; neither returns a model.</text>',
            '  <text x="36" y="722" class="small">UNKNOWN is not UNSAT: the controlled comparison makes no absence, recovery, or uniqueness claim.</text>',
            '  <text x="36" y="754" class="small">All 64 predeclared cell executions complete in numeric order without early stop.</text>',
            "</svg>",
        ]
    )
    return ("\n".join(lines) + "\n").encode()


def render_a197(
    payload: dict[str, Any],
    a195_payload: dict[str, Any],
    a196_payload: dict[str, Any],
) -> bytes:
    observations = payload["execution"]["observations"]
    waves = payload["execution"]["wave_observations"]
    if (
        payload["attempt_id"] != "A197"
        or len(observations) != 256
        or [row["status"] for row in observations] != ["unknown"] * 256
        or len(waves) != 64
        or any(wave["statuses"] != ["unknown"] * 4 for wave in waves)
        or payload["public_challenge"] != a195_payload["public_challenge"]
        or payload["public_challenge"] != a196_payload["public_challenge"]
        or payload["comparisons"]["complete_domain_candidate_count"] != 1 << 20
        or payload["execution"]["returned_model_count"] != 0
    ):
        raise RuntimeError("A197 retained figure input boundary failed")

    width, height = 1_240, 820
    lines = _svg_header(
        width,
        height,
        "A197 ChaCha10 width-12 complete-partition refinement boundary",
        "A 16-by-16 map of all 256 width-12 cells in the complete round-10 refinement; every bounded result is UNKNOWN and no model is returned.",
    )
    lines.extend(
        [
            '  <text x="36" y="43" class="title">A197 — complete width-12 partition refinement</text>',
            '  <text x="36" y="70" class="subtitle">Same still-secret ChaCha10 challenge · 256 disjoint 2¹² cells · 64 numeric waves × 4 workers</text>',
        ]
    )

    grid_x, grid_y, cell, gap = 76, 122, 28, 3
    for value, row in enumerate(observations):
        column, grid_row = value % 16, value // 16
        x = grid_x + column * (cell + gap)
        y = grid_y + grid_row * (cell + gap)
        lines.append(
            f'  <rect data-prefix="{html.escape(row["prefix"])}" x="{x}" y="{y}" width="{cell}" height="{cell}" rx="2" fill="#d8dde3" stroke="#667788"/>'
        )
    for value in range(16):
        coordinate = grid_x + value * (cell + gap) + cell / 2
        lines.append(
            f'  <text x="{coordinate:.1f}" y="108" text-anchor="middle" class="small">{value:X}</text>'
        )
        coordinate = grid_y + value * (cell + gap) + cell / 2 + 4
        lines.append(
            f'  <text x="56" y="{coordinate:.1f}" text-anchor="middle" class="small">{value:X}</text>'
        )
    lines.extend(
        [
            '  <text x="324" y="646" text-anchor="middle" class="subtitle">high-prefix byte: row nibble × column nibble</text>',
            '  <rect x="618" y="112" width="574" height="432" rx="10" fill="#fafbfc" stroke="#9aa6b2" stroke-width="2"/>',
            '  <text x="905" y="151" text-anchor="middle" class="subtitle">Same challenge · complete structural covers</text>',
            '  <text x="652" y="203" class="label">A195 split8</text><text x="1160" y="203" text-anchor="end" class="value">32 × 2¹⁵ · 32 UNKNOWN · 0 models</text>',
            '  <text x="652" y="251" class="label">A196 split9</text><text x="1160" y="251" text-anchor="end" class="value">32 × 2¹⁵ · 32 UNKNOWN · 0 models</text>',
            '  <line x1="650" y1="281" x2="1160" y2="281" stroke="#9aa6b2" stroke-width="1"/>',
            '  <text x="652" y="325" class="label">A197 split8 refined</text><text x="1160" y="325" text-anchor="end" class="value">256 × 2¹² · 256 UNKNOWN · 0 models</text>',
            '  <text x="652" y="377" class="label">execution</text><text x="1160" y="377" text-anchor="end" class="value">64 deterministic waves × 4 cells</text>',
            '  <text x="652" y="429" class="label">cell budget</text><text x="1160" y="429" text-anchor="end" class="value">5,000 ms</text>',
            '  <text x="652" y="481" class="label">structural union</text><text x="1160" y="481" text-anchor="end" class="value">2²⁰ = 1,048,576 candidates</text>',
            '  <path d="M 36 686 L 36 714 L 1204 714 L 1204 686" fill="none" stroke="#17202a" stroke-width="2"/>',
            '  <text x="620" y="743" text-anchor="middle" class="subtitle">Finer complete partition, same bounded status boundary: UNKNOWN is not UNSAT.</text>',
            '  <text x="620" y="780" text-anchor="middle" class="small">The refinement makes no absence, recovery, or uniqueness claim; all 256 cells execute without early stop.</text>',
            "</svg>",
        ]
    )
    return ("\n".join(lines) + "\n").encode()


def render_a198(payload: dict[str, Any]) -> bytes:
    observations = payload["execution"]["observations"]
    first_budget = observations[:32]
    second_budget = observations[32:]
    if (
        payload["attempt_id"] != "A198"
        or len(observations) != 64
        or [row["status"] for row in observations] != ["unknown"] * 64
        or [row["budget_milliseconds"] for row in first_budget] != [10_000] * 32
        or [row["budget_milliseconds"] for row in second_budget] != [30_000] * 32
        or [row["formula_sha256"] for row in first_budget]
        != [row["formula_sha256"] for row in second_budget]
        or payload["execution"]["returned_model_count"] != 0
        or payload["comparisons"]["complete_domain_covered_once_per_budget"] is not True
        or payload["comparisons"]["same_formula_bytes_across_budgets"] is not True
    ):
        raise RuntimeError("A198 retained figure input boundary failed")

    width, height = 1_240, 820
    lines = _svg_header(
        width,
        height,
        "A198 ChaCha10 shared-key eight-block two-budget boundary",
        "Two complete 32-cell width-15 covers use identical eight-block SMT formulas at 10-second and 30-second budgets; all 64 bounded outcomes are UNKNOWN and no model is returned.",
    )
    lines.extend(
        [
            '  <text x="36" y="43" class="title">A198 — eight-block complete-partition resource boundary</text>',
            '  <text x="36" y="70" class="subtitle">Same still-secret ChaCha10 challenge · 8 shared-key blocks · 4,096 target bits per cell</text>',
        ]
    )

    tile_width, tile_height = 63, 82
    for panel, (budget_label, rows) in enumerate(
        (("10,000 ms", first_budget), ("30,000 ms", second_budget))
    ):
        panel_x = 36 + panel * 600
        lines.extend(
            [
                f'  <rect x="{panel_x}" y="96" width="568" height="424" rx="9" fill="#fafbfc" stroke="#9aa6b2" stroke-width="2"/>',
                f'  <text x="{panel_x + 284}" y="128" text-anchor="middle" class="subtitle">{budget_label} · complete 2²⁰ cover · 32 UNKNOWN · 0 models</text>',
            ]
        )
        for index, row in enumerate(rows):
            column, grid_row = index % 8, index // 8
            x = panel_x + 16 + column * 68
            y = 146 + grid_row * 91
            lines.extend(
                [
                    f'  <rect data-budget="{row["budget_milliseconds"]}" data-prefix="{html.escape(row["prefix"])}" x="{x}" y="{y}" width="{tile_width}" height="{tile_height}" rx="5" fill="#f1f3f5" stroke="#667788"/>',
                    f'  <text x="{x + tile_width / 2:.1f}" y="{y + 25}" text-anchor="middle" class="small">{html.escape(row["prefix"])}</text>',
                    f'  <text x="{x + tile_width / 2:.1f}" y="{y + 50}" text-anchor="middle" class="small">UNKNOWN</text>',
                    f'  <text x="{x + tile_width / 2:.1f}" y="{y + 69}" text-anchor="middle" class="small">2¹⁵</text>',
                ]
            )

    lines.extend(
        [
            '  <path d="M 36 556 L 36 584 L 1204 584 L 1204 556" fill="none" stroke="#17202a" stroke-width="2"/>',
            '  <text x="620" y="612" text-anchor="middle" class="subtitle">Each budget executes 32 × 2¹⁵ = 2²⁰ candidates; formula bytes and hashes are identical across budgets.</text>',
            '  <text x="36" y="658" class="small">Every formula observes eight counter-related blocks (4,096 target bits) under one shared unknown low-20 key value.</text>',
            '  <text x="36" y="690" class="small">All 64 processes return normally, no external guard fires, and both complete covers execute without early stop.</text>',
            '  <text x="36" y="722" class="small">The 10-second secondary and 30-second primary predictions are both not retained on this challenge.</text>',
            '  <text x="36" y="754" class="small">UNKNOWN is not UNSAT: this is a resource/representation boundary, with no absence, recovery, or uniqueness claim.</text>',
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
    a190 = _load(args.results_dir / A190_FILENAME, A190_SHA256)
    a191 = _load(args.results_dir / A191_FILENAME, A191_SHA256)
    a192 = _load(args.results_dir / A192_FILENAME, A192_SHA256)
    a193 = _load(args.results_dir / A193_FILENAME, A193_SHA256)
    a194 = _load(args.results_dir / A194_FILENAME, A194_SHA256)
    a195 = _load(args.results_dir / A195_FILENAME, A195_SHA256)
    a196 = _load(args.results_dir / A196_FILENAME, A196_SHA256)
    a197 = _load(args.results_dir / A197_FILENAME, A197_SHA256)
    a198 = _load(args.results_dir / A198_FILENAME, A198_SHA256)
    outputs = {
        args.output_dir / A187_FIGURE: render_a187(a187),
        args.output_dir / A188_FIGURE: render_a188(a188),
        args.output_dir / A189_FIGURE: render_a189(a189),
        args.output_dir / A190_FIGURE: render_a190(a190),
        args.output_dir / A191_FIGURE: render_a191(a191),
        args.output_dir / A192_FIGURE: render_a192(a192),
        args.output_dir / A193_FIGURE: render_a193(a193),
        args.output_dir / A194_FIGURE: render_a194(a194),
        args.output_dir / A195_FIGURE: render_a195(a195),
        args.output_dir / A196_FIGURE: render_a196(a196, a195),
        args.output_dir / A197_FIGURE: render_a197(a197, a195, a196),
        args.output_dir / A198_FIGURE: render_a198(a198),
    }
    for path, raw in outputs.items():
        _write_or_check(path, raw, check=args.check)
        print(f"{hashlib.sha256(raw).hexdigest()}  {path}")


if __name__ == "__main__":
    main()

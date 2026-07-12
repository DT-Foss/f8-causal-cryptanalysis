#!/usr/bin/env python3
"""Render deterministic A204--A207 structural-CNF summary figures."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

RESULTS = {
    "A204": (
        "chacha20_round10_external_cnf_reverse_v1.json",
        "603eaf8a2a6bb85c3c4bb2fdf4b7466205ffd1d8005593d987c8a6461b7c8c22",
        "chacha20_a204_external_cnf_reverse_boundary_v1.svg",
    ),
    "A205": (
        "chacha20_a188_cnf_structural_ordering_v1.json",
        "b3c76fca5a9ffabf3bd2c2bf812c8ef66b9be56bc7f9936a9525fd5e8d3c7f7f",
        "chacha20_a205_structural_ordering_calibration_v1.svg",
    ),
    "A206": (
        "chacha20_round10_bidirectional_min_distance_v1.json",
        "c2d4b703c463d5cdd2c95f22d9a5627c0cf0157e8929df5090ef2e9fe8e02c25",
        "chacha20_a206_bidirectional_round10_boundary_v1.svg",
    ),
    "A207": (
        "chacha20_round10_structural_portfolio_v1.json",
        "80ce896083b239e3bb95e31433fc8cdf6157491005bbb3b024182f730b545652",
        "chacha20_a207_structural_portfolio_boundary_v1.svg",
    ),
}


def _header(title: str, subtitle: str, height: int) -> list[str]:
    return [
        '<?xml version="1.0"?>',
        f'<svg xmlns="http://www.w3.org/2000/svg" width="1240" height="{height}">',
        "<style>.t{font:700 24px system-ui}.s{font:600 15px system-ui}.x{font:12px system-ui;fill:#475569}.sat{fill:#dcfce7;stroke:#15803d}.unk{fill:#f1f3f5;stroke:#7c3aed}.box{fill:#fafbfc;stroke:#9aa6b2}</style>",
        f'<rect width="1240" height="{height}" fill="white"/>',
        f'<text x="36" y="42" class="t">{title}</text>',
        f'<text x="36" y="70" class="s">{subtitle}</text>',
    ]


def _footer(lines: list[str], y: int, text: str) -> bytes:
    lines.extend(
        [
            f'<text x="58" y="{y}" class="s">{text}</text>',
            f'<text x="58" y="{y + 24}" class="x">UNKNOWN is not UNSAT · exact retained observations only</text>',
            "</svg>",
        ]
    )
    return ("\n".join(lines) + "\n").encode()


def render_a204(payload: dict) -> bytes:
    if payload["attempt_id"] != "A204":
        raise RuntimeError("A204 attempt gate failed")
    counts = payload["comparisons"]["status_counts"]
    calibration = payload["calibration"]
    if counts != {"invalid": 0, "sat": 0, "unknown": 32, "unsat": 0}:
        raise RuntimeError("A204 status gate failed")
    if calibration["tested_configuration_count"] != 26:
        raise RuntimeError("A204 calibration gate failed")
    lines = _header(
        "A204 — external-CNF calibration and round-10 transfer",
        "26 frozen A188 configurations select CaDiCaL reverse · complete A202 cover remains open",
        590,
    )
    lines.extend(
        [
            '<rect x="36" y="96" width="1168" height="104" rx="9" class="box"/>',
            '<text x="58" y="130" class="s">A188 calibration: 1 SAT · 25 UNKNOWN</text>',
            '<rect x="58" y="148" width="1080" height="28" rx="4" class="unk"/>',
            '<rect data-calibration="cadical_reverse" x="1096" y="148" width="42" height="28" rx="4" class="sat"/>',
            '<text x="598" y="168" text-anchor="middle" class="x">unique selected cell: cadical_reverse · independently confirmed 4,096 bits</text>',
            '<rect x="36" y="224" width="1168" height="246" rx="9" class="box"/>',
            '<text x="58" y="258" class="s">A204 prospective ChaCha10 cover: 32 × 2¹⁵ = 2²⁰</text>',
        ]
    )
    for index in range(32):
        x = 58 + (index % 8) * 140
        y = 278 + (index // 8) * 42
        lines.extend(
            [
                f'<rect data-cell="{index:05b}" x="{x}" y="{y}" width="126" height="32" rx="4" class="unk"/>',
                f'<text x="{x + 63}" y="{y + 21}" text-anchor="middle" class="x">{index:05b} · UNKNOWN</text>',
            ]
        )
    return _footer(
        lines, 526, "Exact CNF mapping retained; selected A188 rule does not resolve an A204 cell."
    )


def render_a205(payload: dict) -> bytes:
    if payload["attempt_id"] != "A205":
        raise RuntimeError("A205 attempt gate failed")
    comparison = payload["comparisons"]
    if comparison["status_counts"] != {
        "invalid": 0,
        "sat": 16,
        "unknown": 30,
        "unsat": 0,
    }:
        raise RuntimeError("A205 status gate failed")
    candidates = comparison["structural_outlier_candidates"]
    if len(candidates) != 12:
        raise RuntimeError("A205 candidate gate failed")
    lines = _header(
        "A205-r2 — structural CNF ordering calibration",
        "23 exact orders × default/reverse · 46 complete observations · every SAT witness confirmed",
        720,
    )
    lines.extend(
        [
            '<rect x="36" y="96" width="1168" height="86" rx="9" class="box"/>',
            '<text x="58" y="132" class="s">16 SAT · 30 UNKNOWN · 12 non-control structural candidates</text>',
            '<text x="58" y="160" class="x">r2 corrects boundary metadata only; observations, confirmations, and comparisons are unchanged.</text>',
            '<rect x="36" y="204" width="1168" height="410" rx="9" class="box"/>',
            '<text x="58" y="238" class="s">Confirmed structural candidates and successful mode</text>',
        ]
    )
    statuses = comparison["statuses"]
    for index, candidate in enumerate(candidates):
        y = 258 + index * 27
        default = statuses[f"{candidate}__default"]
        reverse = statuses[f"{candidate}__reverse"]
        lines.extend(
            [
                f'<text x="58" y="{y + 18}" class="x">{candidate}</text>',
                f'<rect data-candidate="{candidate}" data-mode="default" x="720" y="{y}" width="190" height="22" rx="4" class="{"sat" if default == "sat" else "unk"}"/>',
                f'<text x="815" y="{y + 16}" text-anchor="middle" class="x">default · {default.upper()}</text>',
                f'<rect data-candidate="{candidate}" data-mode="reverse" x="930" y="{y}" width="190" height="22" rx="4" class="{"sat" if reverse == "sat" else "unk"}"/>',
                f'<text x="1025" y="{y + 16}" text-anchor="middle" class="x">reverse · {reverse.upper()}</text>',
            ]
        )
    return _footer(
        lines,
        660,
        "bidirectional_min_distance is the unique structural candidate confirmed in both modes.",
    )


def render_a206(payload: dict) -> bytes:
    if payload["attempt_id"] != "A206":
        raise RuntimeError("A206 attempt gate failed")
    comparison = payload["comparisons"]
    if comparison["status_counts"] != {
        "invalid": 0,
        "sat": 0,
        "unknown": 64,
        "unsat": 0,
    }:
        raise RuntimeError("A206 status gate failed")
    lines = _header(
        "A206 — bidirectional-min-distance round-10 transfer",
        "Unique robust A205 order · 32 complete prefix cells × two solver modes",
        660,
    )
    lines.extend(
        [
            '<rect x="36" y="96" width="1168" height="456" rx="9" class="box"/>',
            '<text x="58" y="130" class="s">64/64 valid UNKNOWN · 0 SAT · 0 UNSAT · 0 invalid · 0 models</text>',
            '<text x="758" y="160" class="x">default</text>',
            '<text x="1018" y="160" class="x">reverse</text>',
        ]
    )
    for index in range(32):
        col = index // 16
        row = index % 16
        x0 = 58 + col * 574
        y = 174 + row * 22
        lines.extend(
            [
                f'<text x="{x0}" y="{y + 15}" class="x">{index:05b}</text>',
                f'<rect data-cell="{index:05b}" data-mode="default" x="{x0 + 84}" y="{y}" width="190" height="18" rx="3" class="unk"/>',
                f'<rect data-cell="{index:05b}" data-mode="reverse" x="{x0 + 294}" y="{y}" width="190" height="18" rx="3" class="unk"/>',
            ]
        )
    return _footer(
        lines,
        598,
        "The robust known-positive order does not cross the complete A206 fixed-budget frontier.",
    )


def render_a207(payload: dict) -> bytes:
    if payload["attempt_id"] != "A207":
        raise RuntimeError("A207 attempt gate failed")
    comparison = payload["comparisons"]
    if comparison["new_status_counts"] != {
        "invalid": 0,
        "sat": 0,
        "unknown": 352,
        "unsat": 0,
    }:
        raise RuntimeError("A207 status gate failed")
    summaries = payload["progress_map"]["candidate_summaries"]
    if len(summaries) != 11:
        raise RuntimeError("A207 progress-map gate failed")
    lines = _header(
        "A207 — complete structural-order portfolio boundary",
        "352 new cells · 416 combined calibrated cells · all valid UNKNOWN",
        700,
    )
    lines.extend(
        [
            '<rect x="36" y="96" width="1168" height="490" rx="9" class="box"/>',
            '<text x="58" y="130" class="s">Same-mode total ratio versus A206 bidirectional-min-distance baseline</text>',
            '<text x="790" y="158" class="x">conflicts</text>',
            '<text x="970" y="158" class="x">decisions</text>',
        ]
    )
    for index, summary in enumerate(summaries):
        candidate = summary["candidate"]
        conflicts = summary["metrics"]["conflicts"]["total_ratio"]
        decisions = summary["metrics"]["decisions"]["total_ratio"]
        y = 176 + index * 35
        conflict_width = min(250.0, conflicts * 42.0)
        decision_width = min(250.0, decisions * 42.0)
        css = "sat" if candidate == "output_unit_bfs_far" else "unk"
        lines.extend(
            [
                f'<text x="58" y="{y + 18}" class="x">{candidate}</text>',
                f'<rect data-candidate="{candidate}" data-metric="conflicts" x="720" y="{y}" width="{conflict_width:.3f}" height="22" rx="4" class="{css}"/>',
                f'<text x="{730 + conflict_width}" y="{y + 16}" class="x">{conflicts:.3f}×</text>',
                f'<rect data-candidate="{candidate}" data-metric="decisions" x="900" y="{y}" width="{decision_width:.3f}" height="22" rx="4" class="{css}"/>',
                f'<text x="{910 + decision_width}" y="{y + 16}" class="x">{decisions:.3f}×</text>',
            ]
        )
    lines.extend(
        [
            '<text x="58" y="610" class="s">output_unit_bfs_far: 2.759× conflicts · 5.686× decisions · 0.594× propagations</text>',
            '<text x="58" y="634" class="x">Every prefix: conflict ratio ≥1.703 · decision ratio ≥3.315</text>',
        ]
    )
    return _footer(
        lines,
        660,
        "No candidate resolves a cell; the progress map exposes a systematic search-density outlier.",
    )


RENDERERS = {
    "A204": render_a204,
    "A205": render_a205,
    "A206": render_a206,
    "A207": render_a207,
}


def render_all(results_dir: Path) -> dict[str, bytes]:
    rendered = {}
    for attempt, (filename, expected_sha, output) in RESULTS.items():
        source = results_dir / filename
        if hashlib.sha256(source.read_bytes()).hexdigest() != expected_sha:
            raise RuntimeError(f"{attempt} result hash differs")
        rendered[output] = RENDERERS[attempt](json.loads(source.read_bytes()))
    return rendered


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    results_dir = Path(__file__).parents[1] / "results" / "v1"
    for filename, raw in render_all(results_dir).items():
        output = results_dir / filename
        if args.check:
            if output.read_bytes() != raw:
                raise RuntimeError(f"figure differs: {filename}")
        else:
            output.write_bytes(raw)
        print(f"{hashlib.sha256(raw).hexdigest()}  {filename}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

#!/usr/bin/env python3
"""Generate deterministic SVG figures from retained SHAKE result JSON."""

from __future__ import annotations

import argparse
import hashlib
import html
import json
from dataclasses import dataclass
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
RESULTS = ROOT / "research/results/v1"
OUTPUT = ROOT / "docs/figures/shake_frontier.svg"


@dataclass(frozen=True)
class Stage:
    name: str
    filename: str
    representation: str
    color: str


STAGES = (
    Stage("Scalar", "shake_capacity_window_inference_v1.json", "NumPy batch", "#4c78a8"),
    Stage("Bit-sliced", "shake_bitsliced_window_solver_v1.json", "64-way uint64", "#59a14f"),
    Stage("Native", "shake_native_window_solver_v1.json", "C11 / 10 threads", "#f28e2b"),
    Stage("Native 32", "shake_native_window32_solver_v1.json", "resumable C11", "#e15759"),
)


def load(stage: Stage) -> dict:
    path = RESULTS / stage.filename
    return json.loads(path.read_text(encoding="utf-8"))


def rows() -> list[dict]:
    output = []
    for stage in STAGES:
        path = RESULTS / stage.filename
        payload = load(stage)
        runs = [run for variant in payload["confirmation"].values() for run in variant]
        if not runs or not all(
            run.get("unique_exact_recovery", run.get("unique_exact_consistency", False))
            and run.get("wrong_target_rejected", False)
            for run in runs
        ):
            raise ValueError(f"non-retained or incomplete stage: {stage.filename}")
        output.append(
            {
                "name": stage.name,
                "representation": stage.representation,
                "color": stage.color,
                "max_bits": max(run["window_bits"] for run in runs),
                "candidates": sum(run["candidate_count"] for run in runs),
                "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
            }
        )
    return output


def render() -> str:
    data = rows()
    width, height = 1120, 620
    left, top, chart_w, chart_h = 115, 105, 900, 350
    bar_w, gap = 150, 75
    max_bits = 32
    parts = [
        '<?xml version="1.0" encoding="UTF-8"?>',
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" viewBox="0 0 {width} {height}" role="img" aria-labelledby="title desc">',
        '<title id="title">SHAKE exact state-window reconstruction frontier</title>',
        '<desc id="desc">Maximum uniquely reconstructed coordinate window for scalar, bit-sliced, native, and resumable native 24-round Keccak readers. Values are generated from committed result JSON.</desc>',
        '<rect width="1120" height="620" fill="#fbfbfa"/>',
        '<text x="560" y="42" text-anchor="middle" font-family="system-ui,sans-serif" font-size="25" font-weight="700" fill="#17202a">SHAKE exact state-window frontier</text>',
        '<text x="560" y="72" text-anchor="middle" font-family="system-ui,sans-serif" font-size="14" fill="#4d5966">All stages execute 24 Keccak-f[1600] rounds; every listed SHAKE128/256 window is unique</text>',
    ]
    for tick in range(0, max_bits + 1, 4):
        y = top + chart_h - chart_h * tick / max_bits
        parts.append(
            f'<line x1="{left}" y1="{y:.2f}" x2="{left + chart_w}" y2="{y:.2f}" stroke="#d8dde3" stroke-width="1"/>'
        )
        parts.append(
            f'<text x="{left - 14}" y="{y + 5:.2f}" text-anchor="end" font-family="ui-monospace,monospace" font-size="13" fill="#56616d">{tick}</text>'
        )
    parts.append(
        f'<text x="28" y="{top + chart_h / 2}" transform="rotate(-90 28 {top + chart_h / 2})" text-anchor="middle" font-family="system-ui,sans-serif" font-size="15" font-weight="600" fill="#26323d">maximum variable coordinates</text>'
    )
    for index, item in enumerate(data):
        x = left + 70 + index * (bar_w + gap)
        bar_h = chart_h * item["max_bits"] / max_bits
        y = top + chart_h - bar_h
        parts.extend(
            [
                f'<rect x="{x}" y="{y:.2f}" width="{bar_w}" height="{bar_h:.2f}" rx="7" fill="{item["color"]}"/>',
                f'<text x="{x + bar_w / 2}" y="{y - 12:.2f}" text-anchor="middle" font-family="ui-monospace,monospace" font-size="22" font-weight="700" fill="#17202a">{item["max_bits"]}</text>',
                f'<text x="{x + bar_w / 2}" y="{top + chart_h + 31}" text-anchor="middle" font-family="system-ui,sans-serif" font-size="15" font-weight="700" fill="#17202a">{html.escape(item["name"])}</text>',
                f'<text x="{x + bar_w / 2}" y="{top + chart_h + 53}" text-anchor="middle" font-family="system-ui,sans-serif" font-size="12" fill="#56616d">{html.escape(item["representation"])}</text>',
                f'<text x="{x + bar_w / 2}" y="{top + chart_h + 75}" text-anchor="middle" font-family="ui-monospace,monospace" font-size="11" fill="#56616d">Σ {item["candidates"]:,} candidates</text>',
            ]
        )
    hash_lines = " · ".join(f"{item['name']} {item['sha256'][:12]}" for item in data)
    parts.extend(
        [
            '<line x1="80" y1="565" x2="1040" y2="565" stroke="#d8dde3"/>',
            f'<text x="560" y="590" text-anchor="middle" font-family="ui-monospace,monospace" font-size="10" fill="#68737d">source SHA-256 prefixes: {html.escape(hash_lines)}</text>',
            '</svg>',
        ]
    )
    return "\n".join(parts) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true", help="fail unless the committed SVG is current")
    args = parser.parse_args()
    expected = render()
    if args.check:
        if not OUTPUT.is_file() or OUTPUT.read_text(encoding="utf-8") != expected:
            print(f"stale deterministic figure: {OUTPUT.relative_to(ROOT)}")
            return 1
        print(f"deterministic figure: OK ({OUTPUT.relative_to(ROOT)})")
        return 0
    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT.write_text(expected, encoding="utf-8")
    print(f"wrote {OUTPUT.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

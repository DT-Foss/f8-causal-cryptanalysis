#!/usr/bin/env python3
"""Render the deterministic A201 phase-conjugacy holdout figure."""

from __future__ import annotations

import argparse
import hashlib
import json
from collections.abc import Sequence
from pathlib import Path
from typing import Any

RESULT_FILENAME = "chacha20_phase_conjugacy_holdout_v1.json"
RESULT_SHA256 = "c186da54770b520153f94b0b9f72e809d6b78d950a52bee39d74ea9c15194767"
FIGURE_FILENAME = "chacha20_a201_phase_conjugacy_holdout_v1.svg"


def _load(path: Path) -> dict[str, Any]:
    if hashlib.sha256(path.read_bytes()).hexdigest() != RESULT_SHA256:
        raise RuntimeError("A201 result hash differs")
    payload = json.loads(path.read_bytes())
    if (
        payload.get("attempt_id") != "A201"
        or payload.get("evidence_stage") != "PUBLIC_CHACHA_PHASE_CONJUGACY_HOLDOUT_RETAINED"
        or len(payload.get("batches", [])) != 8
        or payload.get("all_predictions_retained_in_every_batch") is not True
        or payload.get("parameters", {}).get("hidden_assignment_present") is not False
    ):
        raise RuntimeError("A201 figure input gate failed")
    return payload


def render(payload: dict[str, Any]) -> bytes:
    batches = payload["batches"]
    series = (
        ("raw", "raw_adjacent_commutator_mean", "#c2413b"),
        ("wrong conjugation", "wrongly_aligned_adjacent_commutator_mean", "#d97706"),
        ("correct conjugation", "correctly_aligned_adjacent_commutator_mean", "#2563a8"),
        ("same-phase lag 2", "same_phase_lag2_commutator_mean", "#0f766e"),
    )
    lines = [
        '<?xml version="1.0" encoding="UTF-8"?>',
        '<svg xmlns="http://www.w3.org/2000/svg" width="1240" height="680" viewBox="0 0 1240 680" role="img" aria-labelledby="title desc">',
        '  <title id="title">A201 ChaCha phase-conjugacy holdout</title>',
        '  <desc id="desc">Eight unseen public batches show that correct row-rotation conjugation removes the dominant raw column-diagonal layout mismatch, leaving a smaller residual at same-phase scale.</desc>',
        "<style>.title{font:700 24px system-ui,sans-serif;fill:#17202a}.sub{font:600 15px system-ui,sans-serif;fill:#334155}.small{font:12px system-ui,sans-serif;fill:#475569}.grid{stroke:#d8dee7}.axis{stroke:#64748b;stroke-width:1.2}</style>",
        '<rect width="1240" height="680" fill="#fff"/>',
        '<text x="36" y="42" class="title">A201 — prospective ChaCha phase-conjugacy holdout</text>',
        '<text x="36" y="69" class="sub">8 unseen public SHAKE256 batches × 16 states · 20 rounds · no hidden assignment · no solver</text>',
        '<rect x="36" y="94" width="1168" height="432" rx="9" fill="#fafbfc" stroke="#9aa6b2"/>',
    ]
    x0, x1, y0, y1 = 94.0, 1172.0, 130.0, 474.0
    for tick in range(6):
        value = tick / 10
        y = y1 - value / 0.55 * (y1 - y0)
        lines += [
            f'<line x1="{x0}" y1="{y:.2f}" x2="{x1}" y2="{y:.2f}" class="grid"/>',
            f'<text x="82" y="{y + 4:.2f}" text-anchor="end" class="small">{value:.1f}</text>',
        ]
    for index in range(8):
        x = x0 + index / 7 * (x1 - x0)
        lines.append(
            f'<text x="{x:.2f}" y="500" text-anchor="middle" class="small">batch {index}</text>'
        )
    for name, key, color in series:
        points = []
        for index, batch in enumerate(batches):
            x = x0 + index / 7 * (x1 - x0)
            y = y1 - float(batch[key]) / 0.55 * (y1 - y0)
            points.append(f"{x:.2f},{y:.2f}")
            lines.append(
                f'<circle data-series="{name}" cx="{x:.2f}" cy="{y:.2f}" r="4" fill="{color}"/>'
            )
        lines.append(
            f'<polyline data-line="{name}" points="{" ".join(points)}" fill="none" stroke="{color}" stroke-width="2.6"/>'
        )
    for index, (name, _, color) in enumerate(series):
        x = 300 + index * 220
        lines += [
            f'<line x1="{x}" y1="112" x2="{x + 24}" y2="112" stroke="{color}" stroke-width="3"/>',
            f'<text x="{x + 30}" y="117" class="small">{name}</text>',
        ]
    summary = payload["summary"]
    lines += [
        '<rect x="36" y="548" width="1168" height="96" rx="9" fill="#f8fafc" stroke="#9aa6b2"/>',
        f'<text x="58" y="578" class="sub">Correct alignment: {summary["correctly_aligned_adjacent_mean_range"][0]:.6f}–{summary["correctly_aligned_adjacent_mean_range"][1]:.6f}; raw/aligned ratio {summary["raw_to_aligned_ratio_range"][0]:.2f}–{summary["raw_to_aligned_ratio_range"][1]:.2f}×.</text>',
        '<text x="58" y="607" class="small">Mechanism: known Column/Diagonal row-rotation conjugacy explains the dominant raw factor-40 signal.</text>',
        '<text x="58" y="629" class="small">A smaller nonzero state-dependent residual remains at same-phase scale; this is not a new carry leak or cryptanalytic break.</text>',
        "</svg>",
    ]
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
            raise RuntimeError("A201 deterministic figure differs")
    else:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_bytes(raw)
    print(f"{hashlib.sha256(raw).hexdigest()}  {args.output}")


if __name__ == "__main__":
    main()

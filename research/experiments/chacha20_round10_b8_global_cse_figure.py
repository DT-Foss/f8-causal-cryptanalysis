#!/usr/bin/env python3
"""Render deterministic A202 global-CSE boundary figure."""

from __future__ import annotations

import argparse
import hashlib
import json
from collections.abc import Sequence
from pathlib import Path
from typing import Any

RESULT_FILENAME = "chacha20_round10_b8_global_cse_v1.json"
RESULT_SHA256 = "4fbfc950984d3cb8eee85ba5532217cab2edae43e7ed8444ff2363259d3e990b"
FIGURE_FILENAME = "chacha20_a202_round10_b8_global_cse_boundary_v1.svg"


def _load(path: Path) -> dict[str, Any]:
    if hashlib.sha256(path.read_bytes()).hexdigest() != RESULT_SHA256:
        raise RuntimeError("A202 result hash differs")
    p = json.loads(path.read_bytes())
    if (
        p.get("attempt_id") != "A202"
        or len(p.get("execution", {}).get("observations", [])) != 32
        or p["comparisons"]["status_counts"] != {"sat": 0, "unsat": 0, "unknown": 32, "invalid": 0}
    ):
        raise RuntimeError("A202 figure gate failed")
    return p


def render(p: dict[str, Any]) -> bytes:
    s = p["cse_stats"]
    lines = [
        '<?xml version="1.0" encoding="UTF-8"?>',
        '<svg xmlns="http://www.w3.org/2000/svg" width="1240" height="650" viewBox="0 0 1240 650" role="img">',
        "<style>.t{font:700 24px system-ui;fill:#17202a}.s{font:600 15px system-ui;fill:#334155}.x{font:12px system-ui;fill:#475569}</style>",
        '<rect width="1240" height="650" fill="#fff"/>',
        '<text x="36" y="42" class="t">A202 — global hash-consing meets the same internal DAG</text>',
        '<text x="36" y="69" class="s">Exact expression reuse only · no algebraic rewrite · same A198 ChaCha10 b8 challenge</text>',
        '<rect x="36" y="94" width="1168" height="174" rx="9" fill="#fafbfc" stroke="#9aa6b2"/>',
        f'<text x="58" y="128" class="s">Source SMT-LIB2: {s["original_definition_count"]:,} → {s["cse_definition_count"]:,} definitions; {s["reused_definition_occurrences"]} exact reused occurrences</text>',
        f'<rect x="58" y="154" width="900" height="32" fill="#cbd5e1"/><rect x="58" y="154" width="{900 * (1 - s["byte_reduction_fraction"]):.2f}" height="32" fill="#2563a8"/>',
        f'<text x="978" y="176" class="s">{s["original_base_bytes"]:,} → {s["cse_base_bytes"]:,} bytes (−{100 * s["byte_reduction_fraction"]:.6f}%)</text>',
        '<text x="58" y="222" class="s">Bitwuzla --pp-only --print-formula: byte-identical for original and CSE</text>',
        '<text x="58" y="246" class="x">231,733 bytes · 2,927 lines · 130 assertions · 0 define-fun · SHA 532479d8427f…1bd9</text>',
        '<rect x="36" y="292" width="1168" height="260" rx="9" fill="#fafbfc" stroke="#9aa6b2"/>',
        '<text x="58" y="326" class="s">Complete CSE numeric-prefix cover · 32 × 2¹⁵ = 2²⁰ · 10,000 ms/cell · 32 UNKNOWN · 0 models</text>',
    ]
    for i in range(32):
        x = 58 + (i % 8) * 140
        y = 350 + (i // 8) * 45
        lines += [
            f'<rect data-cell="{i:05b}" x="{x}" y="{y}" width="126" height="34" rx="4" fill="#f1f3f5" stroke="#2563a8"/>',
            f'<text x="{x + 63}" y="{y + 22}" text-anchor="middle" class="x">{i:05b} · UNKNOWN</text>',
        ]
    lines += [
        '<text x="58" y="586" class="s">Mechanism audit: external CSE changed source bytes, but Bitwuzla had already canonicalized the same internal preprocessed formula.</text>',
        '<text x="58" y="614" class="x">UNKNOWN is not UNSAT · no absence, recovery, or uniqueness claim</text>',
        "</svg>",
    ]
    return ("\n".join(lines) + "\n").encode()


def main(argv: Sequence[str] | None = None) -> None:
    q = argparse.ArgumentParser()
    root = Path(__file__).parents[1]
    q.add_argument("--result", type=Path, default=root / "results/v1" / RESULT_FILENAME)
    q.add_argument("--output", type=Path, default=root / "results/v1" / FIGURE_FILENAME)
    q.add_argument("--check", action="store_true")
    a = q.parse_args(argv)
    raw = render(_load(a.result))
    if a.check:
        if not a.output.exists() or a.output.read_bytes() != raw:
            raise RuntimeError("A202 figure differs")
    else:
        a.output.parent.mkdir(parents=True, exist_ok=True)
        a.output.write_bytes(raw)
    print(f"{hashlib.sha256(raw).hexdigest()}  {a.output}")


if __name__ == "__main__":
    main()

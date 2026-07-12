#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

RESULT = "chacha20_round10_b8_lane_major_v1.json"
SHA = "65fb21c0aec9cfe1b599b3c2c73ed9a2e34f0640899db3b31099b3c6d1d37d35"
FIG = "chacha20_a203_round10_b8_lane_major_boundary_v1.svg"


def render(p):
    if p["attempt_id"] != "A203" or p["comparisons"]["status_counts"] != {
        "sat": 0,
        "unsat": 0,
        "unknown": 32,
        "invalid": 0,
    }:
        raise RuntimeError("gate")
    lines = [
        '<?xml version="1.0"?>',
        '<svg xmlns="http://www.w3.org/2000/svg" width="1240" height="560"><style>.t{font:700 24px system-ui}.s{font:600 15px system-ui}.x{font:12px system-ui;fill:#475569}</style><rect width="1240" height="560" fill="white"/>',
        '<text x="36" y="42" class="t">A203 — lane-major assertion-order boundary</text>',
        '<text x="36" y="70" class="s">Same 128 equalities · different Bitwuzla preprocessed formula · same complete UNKNOWN frontier</text>',
        '<rect x="36" y="96" width="1168" height="112" rx="9" fill="#fafbfc" stroke="#9aa6b2"/>',
        '<text x="58" y="130" class="s">A202 block-major SHA 532479d8427f…1bd9</text>',
        '<text x="58" y="158" class="s">A203 lane-major SHA 7722f9deb960…69da8</text>',
        '<text x="58" y="188" class="x">Equal assertion multiset; ordering changes the internal preprocessed bytes.</text>',
        '<rect x="36" y="230" width="1168" height="248" rx="9" fill="#fafbfc" stroke="#9aa6b2"/>',
        '<text x="58" y="264" class="s">32 × 2¹⁵ = 2²⁰ · 10,000 ms/cell · 32 UNKNOWN · 0 models</text>',
    ]
    for i in range(32):
        x = 58 + (i % 8) * 140
        y = 286 + (i // 8) * 42
        lines += [
            f'<rect data-cell="{i:05b}" x="{x}" y="{y}" width="126" height="32" rx="4" fill="#f1f3f5" stroke="#7c3aed"/>',
            f'<text x="{x + 63}" y="{y + 21}" text-anchor="middle" class="x">{i:05b} · UNKNOWN</text>',
        ]
    lines += [
        '<text x="58" y="518" class="s">Ordering changes preprocessing, but does not cross the tested 10-second boundary.</text>',
        '<text x="58" y="542" class="x">UNKNOWN is not UNSAT · no absence, recovery, or uniqueness claim</text></svg>',
    ]
    return ("\n".join(lines) + "\n").encode()


def main():
    q = argparse.ArgumentParser()
    r = Path(__file__).parents[1]
    q.add_argument("--check", action="store_true")
    a = q.parse_args()
    p = r / "results/v1" / RESULT
    o = r / "results/v1" / FIG
    if hashlib.sha256(p.read_bytes()).hexdigest() != SHA:
        raise RuntimeError("hash")
    raw = render(json.loads(p.read_bytes()))
    if a.check:
        if o.read_bytes() != raw:
            raise RuntimeError("figure")
    else:
        o.write_bytes(raw)
    print(hashlib.sha256(raw).hexdigest())


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""Render the deterministic A199 public ChaCha20 operator-atlas figure."""

from __future__ import annotations

import argparse
import hashlib
import html
import json
import math
from collections.abc import Sequence
from pathlib import Path
from typing import Any

RESULT_FILENAME = "chacha20_formula_operator_atlas_v1.json"
RESULT_SHA256 = "16c1025308bae64e2c45339804ec0a39d5fcb927c1cd0a1dcbf2ca8dfd3d5c48"
FIGURE_FILENAME = "chacha20_a199_formula_operator_atlas_v1.svg"


def _file_sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _load(path: Path) -> dict[str, Any]:
    if _file_sha256(path) != RESULT_SHA256:
        raise RuntimeError("A199 retained result hash differs")
    payload = json.loads(path.read_bytes())
    predictions = payload.get("prospective_predictions_retained", {})
    t01 = payload.get("T01", {})
    t02 = payload.get("T02", {})
    t03 = payload.get("T03", {})
    t04 = payload.get("T04", {})
    t05 = payload.get("T05", {})
    if (
        payload.get("attempt_id") != "A199"
        or payload.get("evidence_stage") != "PUBLIC_FORMULA_OPERATOR_ATLAS_MIXED_BOUNDARY_RETAINED"
        or payload.get("public_input", {}).get("hidden_assignment_present") is not False
        or predictions
        != {
            "H1_noncommutative_order": True,
            "H2_triplet_dependence": False,
            "H3_derivative_root_gate": True,
            "H4_complete_public_partition": True,
            "H5_sum_difference": True,
        }
        or t01.get("adjacent_summary", {}).get("mean") != 0.52158921895
        or t01.get("lag2_summary", {}).get("mean") != 0.013002274002
        or t01.get("depth_products", [{}])[-1].get("forward_reverse_relative_frobenius")
        != 0.017336635791
        or t01.get("depth_products", [{}])[-1].get("chronological_dobrushin") != 1e-12
        or t02.get("observed_l2_norm") != 1.0990101174e-05
        or t02.get("null_97_5_percentile_higher") != 1.127894423e-05
        or t02.get("empirical_upper_p_value") != 0.272727272727
        or t03.get("maximum_gate_error") != 6.798995e-09
        or {row.get("mode_index") for row in t04.get("chosen_masks", [])} != {1}
        or t04.get("spectral_partition", {}).get("cell_histogram") != [1 << 15] * 32
        or t05.get("signed_channel_relative_frobenius") != 0.244046475056
    ):
        raise RuntimeError("A199 retained figure input boundary failed")
    return payload


def _polyline(
    values: list[float],
    *,
    x0: float,
    x1: float,
    y_of: Any,
    color: str,
    data_series: str,
) -> list[str]:
    step = (x1 - x0) / (len(values) - 1)
    points = [(x0 + index * step, y_of(value)) for index, value in enumerate(values)]
    point_text = " ".join(f"{x:.2f},{y:.2f}" for x, y in points)
    lines = [
        f'  <polyline data-series="{html.escape(data_series)}" points="{point_text}" '
        f'fill="none" stroke="{color}" stroke-width="2.4"/>',
    ]
    for index, (x, y) in enumerate(points, start=1):
        lines.append(
            f'  <circle data-series="{html.escape(data_series)}" data-index="{index}" '
            f'cx="{x:.2f}" cy="{y:.2f}" r="3.1" fill="{color}"/>'
        )
    return lines


def render(payload: dict[str, Any]) -> bytes:
    t01 = payload["T01"]
    t02 = payload["T02"]
    t04 = payload["T04"]
    t05 = payload["T05"]
    adjacent = [float(value) for value in t01["adjacent_relative_commutators"]]
    lag2 = [float(value) for value in t01["lag2_same_phase_relative_commutators"]]
    depth_rows = t01["depth_products"]
    gaps = [max(float(row["forward_reverse_relative_frobenius"]), 1e-12) for row in depth_rows]
    dobrushin = [max(float(row["chronological_dobrushin"]), 1e-12) for row in depth_rows]
    null_values = [float(value) for value in t02["null_l2_norms"]]
    null_mean = sum(null_values) / len(null_values)
    observed_ratio = float(t02["observed_l2_norm"]) / null_mean
    threshold_ratio = float(t02["null_97_5_percentile_higher"]) / null_mean

    width, height = 1_240, 800
    lines = [
        '<?xml version="1.0" encoding="UTF-8"?>',
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" viewBox="0 0 {width} {height}" role="img" aria-labelledby="title desc">',
        '  <title id="title">A199 public ChaCha20 formula-operator atlas</title>',
        '  <desc id="desc">Adjacent column-diagonal commutators dominate same-phase lag-two controls, the chronological product contracts while its order gap persists, and the third-cumulant statistic remains below its frozen marginal-preserving null threshold.</desc>',
        "  <style>",
        "    .title { font: 700 24px system-ui, sans-serif; fill: #17202a; }",
        "    .subtitle { font: 600 15px system-ui, sans-serif; fill: #334155; }",
        "    .label { font: 13px system-ui, sans-serif; fill: #334155; }",
        "    .small { font: 12px system-ui, sans-serif; fill: #475569; }",
        "    .axis { stroke: #64748b; stroke-width: 1.2; }",
        "    .grid { stroke: #d8dee7; stroke-width: 1; }",
        "  </style>",
        '  <rect width="1240" height="800" fill="#ffffff"/>',
        '  <text x="36" y="42" class="title">A199 — public ChaCha20 formula-operator atlas</text>',
        '  <text x="36" y="69" class="subtitle">Deterministic public states · 20 rounds · no hidden assignment · no solver · no key-recovery claim</text>',
        '  <rect x="36" y="92" width="574" height="452" rx="9" fill="#fafbfc" stroke="#9aa6b2" stroke-width="1.5"/>',
        '  <text x="58" y="123" class="subtitle">T01 · phase-sensitive noncommutativity</text>',
        '  <text x="58" y="145" class="small">Relative Frobenius commutator by starting round</text>',
    ]

    left_x0, left_x1 = 92.0, 584.0
    left_y0, left_y1 = 172.0, 476.0
    for tick in range(6):
        value = tick / 10
        y = left_y1 - value / 0.55 * (left_y1 - left_y0)
        lines.extend(
            [
                f'  <line x1="{left_x0}" y1="{y:.2f}" x2="{left_x1}" y2="{y:.2f}" class="grid"/>',
                f'  <text x="82" y="{y + 4:.2f}" text-anchor="end" class="small">{value:.1f}</text>',
            ]
        )
    lines.extend(
        [
            f'  <line x1="{left_x0}" y1="{left_y0}" x2="{left_x0}" y2="{left_y1}" class="axis"/>',
            f'  <line x1="{left_x0}" y1="{left_y1}" x2="{left_x1}" y2="{left_y1}" class="axis"/>',
        ]
    )
    for tick in (1, 5, 10, 15, 19):
        x = left_x0 + (tick - 1) / 18 * (left_x1 - left_x0)
        lines.append(
            f'  <text x="{x:.2f}" y="498" text-anchor="middle" class="small">{tick}</text>'
        )

    def left_y(value: float) -> float:
        return left_y1 - value / 0.55 * (left_y1 - left_y0)

    lines.extend(
        _polyline(
            adjacent,
            x0=left_x0,
            x1=left_x1,
            y_of=left_y,
            color="#c2413b",
            data_series="adjacent-column-diagonal",
        )
    )
    lines.extend(
        _polyline(
            lag2,
            x0=left_x0,
            x1=left_x0 + 17 / 18 * (left_x1 - left_x0),
            y_of=left_y,
            color="#2563a8",
            data_series="same-phase-lag2",
        )
    )
    lines.extend(
        [
            '  <line x1="378" y1="118" x2="404" y2="118" stroke="#c2413b" stroke-width="3"/>',
            '  <text x="410" y="123" class="small">adjacent C↔D · mean 0.521589</text>',
            '  <line x1="378" y1="141" x2="404" y2="141" stroke="#2563a8" stroke-width="3"/>',
            '  <text x="410" y="146" class="small">same-phase lag 2 · mean 0.013002</text>',
            '  <text x="323" y="527" text-anchor="middle" class="label">mean contrast = 40.12×</text>',
            '  <rect x="630" y="92" width="574" height="300" rx="9" fill="#fafbfc" stroke="#9aa6b2" stroke-width="1.5"/>',
            '  <text x="652" y="123" class="subtitle">T01 · order information survives contraction</text>',
            '  <text x="652" y="145" class="small">Log-scale diagnostic by cumulative round depth</text>',
        ]
    )

    right_x0, right_x1 = 686.0, 1178.0
    right_y0, right_y1 = 184.0, 330.0

    def log_y(value: float) -> float:
        exponent = max(-12.0, min(0.0, math.log10(max(value, 1e-12))))
        return right_y0 + (-exponent / 12.0) * (right_y1 - right_y0)

    for exponent in (0, -3, -6, -9, -12):
        y = log_y(10.0**exponent)
        lines.extend(
            [
                f'  <line x1="{right_x0}" y1="{y:.2f}" x2="{right_x1}" y2="{y:.2f}" class="grid"/>',
                f'  <text x="676" y="{y + 4:.2f}" text-anchor="end" class="small">10^{exponent}</text>',
            ]
        )
    lines.extend(
        _polyline(
            gaps,
            x0=right_x0,
            x1=right_x1,
            y_of=log_y,
            color="#7c3aed",
            data_series="forward-reverse-gap",
        )
    )
    lines.extend(
        _polyline(
            dobrushin,
            x0=right_x0,
            x1=right_x1,
            y_of=log_y,
            color="#0f766e",
            data_series="chronological-dobrushin",
        )
    )
    lines.extend(
        [
            f'  <line x1="{right_x0}" y1="{right_y0}" x2="{right_x0}" y2="{right_y1}" class="axis"/>',
            f'  <line x1="{right_x0}" y1="{right_y1}" x2="{right_x1}" y2="{right_y1}" class="axis"/>',
            '  <line x1="856" y1="164" x2="880" y2="164" stroke="#7c3aed" stroke-width="3"/>',
            '  <text x="886" y="169" class="small">forward/reverse gap</text>',
            '  <line x1="1014" y1="164" x2="1038" y2="164" stroke="#0f766e" stroke-width="3"/>',
            '  <text x="1044" y="169" class="small">Dobrushin</text>',
            '  <text x="932" y="360" text-anchor="middle" class="small">depth 20: order gap 0.017337 · Dobrushin 10⁻¹²</text>',
            '  <rect x="630" y="412" width="574" height="216" rx="9" fill="#fafbfc" stroke="#9aa6b2" stroke-width="1.5"/>',
            '  <text x="652" y="443" class="subtitle">T02 · frozen third-cumulant boundary</text>',
            '  <text x="652" y="465" class="small">L2 statistic normalized by the exact 32-null mean</text>',
        ]
    )

    null_x0, null_x1 = 682.0, 1172.0

    def null_x(ratio: float) -> float:
        return null_x0 + (ratio - 0.94) / 0.12 * (null_x1 - null_x0)

    baseline_y = 520.0
    lines.append(
        f'  <line x1="{null_x0}" y1="{baseline_y}" x2="{null_x1}" y2="{baseline_y}" class="axis"/>'
    )
    for tick in (0.94, 0.98, 1.00, 1.02, 1.06):
        x = null_x(tick)
        lines.extend(
            [
                f'  <line x1="{x:.2f}" y1="514" x2="{x:.2f}" y2="526" class="axis"/>',
                f'  <text x="{x:.2f}" y="548" text-anchor="middle" class="small">{tick:.2f}</text>',
            ]
        )
    for index, value in enumerate(null_values):
        ratio = value / null_mean
        x = null_x(ratio)
        y0 = 504 - (index % 3) * 5
        lines.append(
            f'  <line data-null-replicate="{index}" x1="{x:.2f}" y1="{y0}" x2="{x:.2f}" y2="526" stroke="#94a3b8" stroke-width="1"/>'
        )
    mean_x = null_x(1.0)
    observed_x = null_x(observed_ratio)
    threshold_x = null_x(threshold_ratio)
    lines.extend(
        [
            f'  <line data-marker="null-mean" x1="{mean_x:.2f}" y1="488" x2="{mean_x:.2f}" y2="532" stroke="#334155" stroke-width="2"/>',
            f'  <line data-marker="observed" x1="{observed_x:.2f}" y1="482" x2="{observed_x:.2f}" y2="532" stroke="#d97706" stroke-width="3"/>',
            f'  <line data-marker="frozen-threshold" x1="{threshold_x:.2f}" y1="482" x2="{threshold_x:.2f}" y2="532" stroke="#b91c1c" stroke-width="3" stroke-dasharray="5 4"/>',
            f'  <text x="{observed_x:.2f}" y="578" text-anchor="middle" class="small">observed 1.0193×</text>',
            f'  <text x="{threshold_x:.2f}" y="598" text-anchor="middle" class="small">97.5% higher = {threshold_ratio:.4f}×</text>',
            '  <text x="652" y="612" class="small">H2 not retained · empirical upper p = 0.272727 · same marginals exact</text>',
            '  <rect x="36" y="652" width="1168" height="112" rx="9" fill="#f8fafc" stroke="#9aa6b2" stroke-width="1.5"/>',
            '  <text x="58" y="684" class="subtitle">Exact retained construction and scope</text>',
            f'  <text x="58" y="710" class="label">T04 Fiedler filtration: {html.escape(", ".join(t04["chosen_mask_hex_order"]))} · GF(2) rank 5 · 32 × 32,768 = 2²⁰</text>',
            f'  <text x="58" y="736" class="label">All five masks are nested thresholds of mode 1; this is a partition baseline, not a demonstrated multimode mixture. T05 signed channel = {t05["signed_channel_relative_frobenius"]:.12f}, rank = {t05["cross_copy_effective_rank_1e_10"]}.</text>',
            "</svg>",
        ]
    )
    return ("\n".join(lines) + "\n").encode()


def main(argv: Sequence[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    research_root = Path(__file__).parents[1]
    parser.add_argument(
        "--result",
        type=Path,
        default=research_root / "results" / "v1" / RESULT_FILENAME,
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=research_root / "results" / "v1" / FIGURE_FILENAME,
    )
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

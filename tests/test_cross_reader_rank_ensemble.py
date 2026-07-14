from __future__ import annotations

import numpy as np

from arx_carry_leak.cross_reader_rank_ensemble import (
    build_rank_overlay_corpus,
    selection_corrected_rank_overlay,
    ternary_coefficient_modes,
)


def _synthetic_rows() -> dict[str, list[dict]]:
    readers = {"direct": [], "inverse": [], "noise": []}
    prefixes = [19, 67, 109, 173, 227]
    for group, prefix in enumerate(prefixes):
        for seed in range(4):
            label = f"synthetic_p{group:02d}_fit_s{seed:02d}"
            direct = np.zeros(256, dtype=float)
            direct[prefix] = 10.0
            inverse = np.zeros(256, dtype=float)
            inverse[prefix] = -10.0
            noise = ((np.arange(256) * (seed + 3) + group) % 17).astype(float)
            for reader_id, scores in (
                ("direct", direct),
                ("inverse", inverse),
                ("noise", noise),
            ):
                readers[reader_id].append(
                    {
                        "label": label,
                        "true_prefix": prefix,
                        "scores": scores.tolist(),
                    }
                )
    return readers


def test_complete_ternary_mode_count() -> None:
    assert len(ternary_coefficient_modes(2)) == 8
    assert len(ternary_coefficient_modes(3)) == 26


def test_selection_corrected_overlay_finds_direct_plus_flipped_inverse() -> None:
    corpus = build_rank_overlay_corpus(_synthetic_rows())
    result = selection_corrected_rank_overlay(corpus)
    coefficients = dict(
        zip(result["reader_ids"], result["selected_coefficients"], strict=True)
    )
    assert coefficients["direct"] - coefficients["inverse"] > 0
    assert result["mean_log2_rank"] == 0.0
    assert result["mean_log2_rank_bit_gain"] > 6.0
    assert result["outer_prefix_folds_with_positive_bit_gain"] == 5
    assert result["selection_corrected_exact_shared_xor_p"] == 1.0 / 256.0

from __future__ import annotations

import numpy as np

from arx_carry_leak.fresh_candidate_reader import (
    BASE_FEATURE_NAMES,
    FEATURE_NAMES,
    HORIZONS,
    METRICS,
    build_feature_table,
    concatenate_training,
    descending_midrank,
)


def _measurement(*, label: str, true_prefix: int, xor_offset: int = 0) -> dict:
    stages = []
    for candidate in range(256):
        source = candidate ^ xor_offset
        for stage_index, horizon in enumerate(HORIZONS):
            base = (source ^ true_prefix).bit_count() + horizon
            stages.append(
                {
                    "prefix8": f"{candidate:08b}",
                    "horizon": horizon,
                    "metric_names": list(METRICS),
                    "metrics_cell_cumulative_delta": [horizon, base * 3, base * 17],
                    "metrics_stage_delta": [1, base + stage_index, base * 2],
                    "active_variables_delta": -base,
                    "irredundant_clauses_delta": base - 6,
                    "redundant_clauses_delta": base * 5 - 11,
                }
            )
    return {
        "label": label,
        "known_key_design": {"prefix8": true_prefix ^ xor_offset},
        "run": {"stages": stages},
    }


def test_feature_table_is_finite_and_has_declared_shape() -> None:
    table = build_feature_table(_measurement(label="k0", true_prefix=37))
    assert len(BASE_FEATURE_NAMES) == 36
    assert len(FEATURE_NAMES) == 144
    assert table.matrix.shape == (256, 144)
    assert np.isfinite(table.matrix).all()
    assert table.labels().sum() == 1
    assert table.labels()[37] == 1


def test_xor_translation_reindexes_features_exactly() -> None:
    offset = 0xA5
    base = build_feature_table(_measurement(label="base", true_prefix=0x31))
    translated = build_feature_table(
        _measurement(label="translated", true_prefix=0x31, xor_offset=offset)
    )
    for candidate in range(256):
        np.testing.assert_allclose(
            translated.matrix[candidate ^ offset],
            base.matrix[candidate],
            atol=1e-12,
            rtol=1e-12,
        )
    assert translated.true_prefix == (base.true_prefix ^ offset)


def test_training_concatenation_and_midrank() -> None:
    tables = [
        build_feature_table(_measurement(label="k0", true_prefix=3)),
        build_feature_table(_measurement(label="k1", true_prefix=91)),
    ]
    matrix, labels = concatenate_training(tables)
    assert matrix.shape == (512, 144)
    assert labels.shape == (512,)
    assert labels.sum() == 2
    scores = np.arange(256, dtype=np.float64)
    assert descending_midrank(scores, 255) == 1.0
    assert descending_midrank(np.zeros(256), 12) == 128.5

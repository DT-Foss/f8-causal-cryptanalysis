from __future__ import annotations

import numpy as np

from arx_carry_leak.chacha20_continuous_flow import (
    ContinuousFlowTable,
    fit_continuous_flow_model,
    nested_continuous_flow_evaluate,
    score_continuous_flow_table,
)


def _synthetic_tables() -> list[ContinuousFlowTable]:
    tables = []
    prefixes = [17, 61, 113, 177, 229]
    for group, prefix in enumerate(prefixes):
        for seed in range(4):
            signal = np.zeros(256, dtype=np.int32)
            signal[prefix] = 12 + seed
            inverse = np.full(256, 8, dtype=np.int32)
            inverse[prefix] = 0
            nuisance = (np.arange(256, dtype=np.int32) * (seed + 1) + group) % 7
            tables.append(
                ContinuousFlowTable(
                    label=f"synthetic_p{group:02d}_fit_s{seed:02d}",
                    true_prefix=prefix,
                    feature_counts={
                        "all_pair|direct_signal": signal,
                        "all_clause|inverse_signal": inverse,
                        "all_unsigned_variable|nuisance": nuisance,
                    },
                )
            )
    return tables


def test_continuous_flow_model_ranks_unseen_prefix_signal_first() -> None:
    tables = _synthetic_tables()
    model = fit_continuous_flow_model(
        tables[:16],
        view="log1p_l1",
        maximum_features=16,
        ridge=1.0,
    )
    assert model.feature_weights
    for table in tables[16:]:
        assert score_continuous_flow_table(model, table)["midrank"] == 1.0


def test_nested_continuous_flow_evaluation_keeps_all_prefixes_unseen() -> None:
    evaluation = nested_continuous_flow_evaluate(
        _synthetic_tables(),
        views=("linear_l1", "log1p_l1"),
        maximum_features_grid=(2, 3),
        ridge_grid=(0.25, 1.0),
    )
    assert evaluation["mean_log2_rank"] == 0.0
    assert evaluation["mean_log2_rank_bit_gain"] > 6.0
    assert evaluation["outer_prefix_folds_with_positive_bit_gain"] == 5
    assert evaluation["exact_shared_xor_p"] == 1.0 / 256.0
    for fold in evaluation["outer_folds"]:
        assert fold["outer_prefix_index"] not in fold["model"][
            "training_prefix_groups"
        ]

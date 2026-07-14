from __future__ import annotations

import numpy as np

from arx_carry_leak.solver_trajectory_shape import (
    BASE_FEATURE_NAMES,
    CHANNELS,
    FEATURE_NAMES,
    HORIZONS,
    TrajectoryShapeTable,
    _shape_vector,
    build_trajectory_shape_table,
    nested_trajectory_shape_evaluate,
)


def _measurement(true_prefix: int = 73) -> dict[str, object]:
    stages = []
    for candidate in range(256):
        for horizon_index, horizon in enumerate(HORIZONS):
            base = candidate % 9 + 1
            lengths = [3 + horizon_index, 5 + candidate % 3]
            stages.append(
                {
                    "prefix8": f"{candidate:08b}",
                    "horizon": horizon,
                    "metric_names": [
                        "conflicts",
                        "decisions",
                        "search_propagations",
                    ],
                    "metrics_stage_delta": [
                        base * (horizon_index + 1),
                        base * (horizon_index + 2),
                        base * (horizon_index + 4),
                    ],
                    "active_variables_delta": base - horizon_index,
                    "irredundant_clauses_delta": base + horizon_index,
                    "redundant_clauses_delta": 2 * base + horizon_index,
                    "learned_clause_accepted_stage": base + horizon_index,
                    "learned_clause_offered_stage": 2 * base + horizon_index,
                    "learned_clause_rejected_large_stage": candidate % 2,
                    "learned_literal_count_stage": 7 * base + horizon_index,
                    "learned_clause_lengths_stage": lengths,
                }
            )
    return {
        "label": "synthetic_p00_fit_s00",
        "known_key_design": {"prefix8": true_prefix},
        "run": {
            "learned_clause_identity_complete": True,
            "bounded_variable_addition_enabled": False,
            "stages": stages,
        },
    }


def test_shape_vector_is_invariant_to_per_channel_positive_scale() -> None:
    original = {
        channel: np.asarray([1.0, 2.0, 4.0, 8.0]) * (index + 1)
        for index, channel in enumerate(CHANNELS)
    }
    scaled = {
        channel: values * (index + 2)
        for index, (channel, values) in enumerate(original.items())
    }
    first = _shape_vector(original)
    second = _shape_vector(scaled)
    profile_derivative_end = len(CHANNELS) * 9
    assert np.allclose(
        first[:profile_derivative_end], second[:profile_derivative_end]
    )


def test_trajectory_shape_builder_is_target_blind_and_has_frozen_geometry() -> None:
    first = build_trajectory_shape_table(_measurement(73))
    second = build_trajectory_shape_table(_measurement(211))
    assert len(BASE_FEATURE_NAMES) == 133
    assert len(FEATURE_NAMES) == 532
    assert first.matrix.shape == (256, 532)
    assert np.array_equal(first.matrix, second.matrix)
    assert first.true_prefix == 73
    assert second.true_prefix == 211


def _synthetic_tables() -> list[TrajectoryShapeTable]:
    tables = []
    prefixes = [17, 61, 113, 177, 229]
    signal_index = FEATURE_NAMES.index(
        "conflicts__profile_h1__raw_z"
    )
    for group, prefix in enumerate(prefixes):
        for seed in range(4):
            matrix = np.zeros((256, len(FEATURE_NAMES)), dtype=np.float64)
            matrix[prefix, signal_index] = 10.0 + seed
            tables.append(
                TrajectoryShapeTable(
                    label=f"synthetic_p{group:02d}_fit_s{seed:02d}",
                    true_prefix=prefix,
                    feature_names=FEATURE_NAMES,
                    matrix=matrix,
                )
            )
    return tables


def test_nested_trajectory_shape_reader_transfers_synthetic_signal() -> None:
    evaluation = nested_trajectory_shape_evaluate(
        _synthetic_tables(), ridge_lambdas=(0.1, 1.0)
    )
    assert evaluation["mean_log2_rank"] == 0.0
    assert evaluation["outer_prefix_folds_with_positive_bit_gain"] == 5
    assert evaluation["exact_shared_xor_p"] == 1.0 / 256.0

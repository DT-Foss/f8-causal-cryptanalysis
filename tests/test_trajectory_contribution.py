from __future__ import annotations

import numpy as np

from arx_carry_leak.trajectory_contribution import (
    familywise_best_gain,
    feature_source_and_transform,
    grouped_scores,
    score_view_statistics,
    signed_semantic_groups,
    standardized_contributions,
)


def test_feature_source_and_transform_separates_semantics_from_orbit() -> None:
    assert feature_source_and_transform(
        "conflicts__first_difference_1_2__xor_laplacian"
    ) == ("conflicts", "xor_laplacian")
    assert feature_source_and_transform(
        "ratio_decisions_versus_conflicts__h4__raw_z"
    ) == ("ratio_decisions_versus_conflicts", "raw_z")


def test_signed_groups_partition_only_nonzero_coefficients() -> None:
    names = (
        "conflicts__profile_h1__raw_z",
        "conflicts__profile_h2__raw_z",
        "decisions__profile_h1__xor_laplacian",
        "decisions__profile_h2__xor_laplacian",
    )
    groups = signed_semantic_groups(names, [2.0, -3.0, 0.0, 4.0])
    assert groups == {
        "conflicts::coefficient_negative": (1,),
        "conflicts::coefficient_positive": (0,),
        "decisions::coefficient_positive": (3,),
    }


def test_grouped_standardized_contributions_reconstruct_frozen_logit() -> None:
    matrix = np.asarray([[3.0, 8.0], [5.0, 2.0]])
    contributions = standardized_contributions(
        matrix,
        means=[1.0, 4.0],
        scales=[2.0, 2.0],
        coefficients=[3.0, -0.5],
    )
    groups = grouped_scores(contributions, {"all": (0, 1)})
    expected = ((matrix - np.asarray([1.0, 4.0])) / 2.0) @ np.asarray([3.0, -0.5])
    np.testing.assert_allclose(groups["all"], expected)


def _synthetic_fields(true_prefixes: list[int], offset: int) -> list[np.ndarray]:
    fields = []
    for truth in true_prefixes:
        scores = np.zeros(256)
        scores[truth ^ offset] = 1.0
        fields.append(scores)
    return fields


def test_exact_view_and_familywise_controls_retain_shared_xor_geometry() -> None:
    truths = [11, 11, 11, 11, 27, 27, 27, 27, 49, 49, 49, 49, 88, 88, 88, 88, 201, 201, 201, 201]
    groups = [value for value in range(5) for _ in range(4)]
    correct = score_view_statistics(
        _synthetic_fields(truths, 0), true_prefixes=truths, prefix_indices=groups
    )
    shifted = score_view_statistics(
        _synthetic_fields(truths, 7), true_prefixes=truths, prefix_indices=groups
    )
    assert correct["best_shared_xor_offset"] == 0
    assert correct["exact_shared_xor_p"] == 1 / 256
    family = familywise_best_gain({"correct": correct, "shifted": shifted})
    assert family["best_observed_view"] == "correct"
    assert family["exact_familywise_shared_xor_p"] == 2 / 256

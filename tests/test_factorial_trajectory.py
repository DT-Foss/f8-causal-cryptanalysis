from __future__ import annotations

import hashlib
import json
from pathlib import Path

import numpy as np
import pytest

from arx_carry_leak.factorial_trajectory import (
    BUNDLE_ORDER,
    EXPECTED_MATCHED_NULL_PERMUTATION_SHA256,
    FEATURE_COUNTS,
    FEATURE_FAMILY_ORDER,
    MATCHED_NULL_SEED_LABEL,
    READOUT_ORDER,
    RIDGE_LAMBDA_GRID,
    CandidateIdentity,
    add_one_lower_tail_p,
    candidate_selection_key,
    centered_score_ranks,
    deterministic_matched_permutation_pairs,
    dual_schedule_score_matrix,
    dual_schedule_scores,
    evaluate_score_matrix,
    exact_lower_tail_p,
    exact_rank,
    extract_pair_feature_views,
    fit_factorial_readout,
    permute_cluster_targets,
    rank_metrics,
    readout_from_dict,
    select_candidate,
    training_matrix,
)

ROOT = Path(__file__).parents[1]
A220P = ROOT / "research/results/v1/chacha20_round20_multihorizon_preflight_v1.json"


def _trajectory(order: list[int], offset: int) -> dict:
    cells = []
    for cell_index, prefix in enumerate(order):
        cells.append(
            {
                "prefix8": f"{prefix:08b}",
                "cell_index": cell_index,
                "metrics_delta": [
                    64 + (prefix % 3),
                    70 + ((prefix * 5 + offset) % 101),
                    1000 + ((prefix * 37 + offset * 13) % 4001),
                ],
                "active_variables_delta": 0,
                "irredundant_clauses_delta": 0,
                "redundant_clauses_delta": ((prefix * 11 + offset) % 47) - 23,
            }
        )
    return {"order": [f"{value:08b}" for value in order], "cells": cells}


def test_pair_feature_families_have_frozen_shapes_names_and_finite_values() -> None:
    forward = _trajectory(list(range(256)), 3)
    reverse = _trajectory([0, *range(255, 0, -1)], 17)
    views = extract_pair_feature_views(forward, reverse)
    assert tuple(views) == FEATURE_FAMILY_ORDER
    for family, view in views.items():
        assert view.matrix.shape == (256, FEATURE_COUNTS[family])
        assert len(view.names) == len(set(view.names)) == FEATURE_COUNTS[family]
        assert np.isfinite(view.matrix).all()
    assert not np.array_equal(
        views["P3_dense_cube"].matrix[:, -12:],
        views["P1_dense_local"].matrix,
    )


def test_pair_features_align_by_prefix_and_cross_difference_vanishes_for_identical_runs() -> None:
    order = [0, *range(255, 0, -1)]
    trajectory = _trajectory(order, 11)
    shuffled_cells = {**trajectory, "cells": list(reversed(trajectory["cells"]))}
    baseline = extract_pair_feature_views(trajectory, trajectory)
    shuffled = extract_pair_feature_views(shuffled_cells, trajectory)
    for family in FEATURE_FAMILY_ORDER:
        assert np.array_equal(baseline[family].matrix, shuffled[family].matrix)
        assert baseline[family].names == shuffled[family].names
    cross = baseline["P2_dense_cross"]
    difference_columns = [index for index, name in enumerate(cross.names) if ".difference." in name]
    assert len(difference_columns) == 6
    assert np.array_equal(cross.matrix[:, difference_columns], np.zeros((256, 6)))


def test_training_and_both_readouts_roundtrip() -> None:
    challenges = []
    targets = []
    for index in range(4):
        views = extract_pair_feature_views(
            _trajectory(list(range(256)), index + 1),
            _trajectory([0, *range(255, 0, -1)], index + 19),
        )
        challenges.append(views["P2_dense_cross"])
        targets.append((index * 61 + 7) % 256)
    matrix, labels, names = training_matrix(challenges, targets)
    assert matrix.shape == (1024, 24)
    assert labels.sum() == 4
    for kind in ("ridge_logistic", "gram_wiener_fisher"):
        fitted = fit_factorial_readout(
            matrix,
            labels,
            kind=kind,
            feature_family="P2_dense_cross",
            feature_names=names,
            ridge_lambda=1.0,
        )
        restored = readout_from_dict(fitted.as_dict())
        expected = fitted.scores(challenges[0].matrix)
        assert np.array_equal(expected, restored.scores(challenges[0].matrix))
        assert np.isfinite(expected).all()


def test_dual_schedule_scores_are_scale_invariant_rank_averages() -> None:
    left = np.arange(256, dtype=np.float64)
    right = np.arange(255, -1, -1, dtype=np.float64)
    assert np.allclose(dual_schedule_scores(left, right), 0.0)
    assert np.array_equal(centered_score_ranks(left), centered_score_ranks(7.0 * left + 3.0))
    assert np.allclose(
        dual_schedule_score_matrix(np.row_stack((left, right)), np.row_stack((right, left))),
        0.0,
    )
    with pytest.raises(ValueError):
        dual_schedule_scores(left[:-1], right)


def test_frozen_lower_tail_p_value_rules() -> None:
    assert add_one_lower_tail_p(1.0, [2.0] * 64) == 1 / 65
    assert add_one_lower_tail_p(2.0, [2.0] * 64) == 1.0
    exact = [1.0, *([2.0] * 119)]
    assert exact_lower_tail_p(1.0, exact) == 1 / 120
    with pytest.raises(ValueError, match="identity observation"):
        exact_lower_tail_p(0.0, exact)


def test_exact_rank_metrics_and_frozen_candidate_grid_order() -> None:
    tied = np.zeros(256, dtype=np.float64)
    assert exact_rank(tied, 0) == 1
    assert exact_rank(tied, 255) == 256
    descending = np.arange(256, dtype=np.float64)
    assert exact_rank(descending, 255) == 1
    assert exact_rank(descending, 0) == 256
    evaluated = evaluate_score_matrix(np.row_stack((tied, descending)), [0, 255])
    assert evaluated["ranks"] == [1, 1]
    assert rank_metrics(range(1, 257))["mean_log2_rank"] == pytest.approx(
        6.578110496969589, abs=1e-15
    )

    identities = [
        CandidateIdentity(bundle, family, readout, ridge)
        for bundle in BUNDLE_ORDER
        for family in FEATURE_FAMILY_ORDER
        for readout in READOUT_ORDER
        for ridge in RIDGE_LAMBDA_GRID
    ]
    assert len(identities) == len(set(identities)) == 450
    tied_metrics = {
        "mean_log2_rank": 4.0,
        "median_rank": 16.0,
        "hit_at_16": 0.5,
        "mean_reciprocal_rank": 0.1,
    }
    selected, _ = select_candidate([(identity, tied_metrics) for identity in identities])
    assert selected == identities[0]
    assert candidate_selection_key(identities[0], tied_metrics) < candidate_selection_key(
        identities[-1], tied_metrics
    )


def test_matched_null_permutations_are_cluster_level_unique_and_deterministic() -> None:
    seed = MATCHED_NULL_SEED_LABEL
    first = deterministic_matched_permutation_pairs(seed)
    second = deterministic_matched_permutation_pairs(seed)
    assert first == second
    assert EXPECTED_MATCHED_NULL_PERMUTATION_SHA256 == (
        "8e7af50c509be00878d335acc0b49c4838f74ed9ae2c96ba9ca9f6938819a588"
    )
    assert len(first) == len(set(first)) == 64
    assert all(pair.fit_cluster_permutation != tuple(range(8)) for pair in first)
    assert all(pair.selection_cluster_permutation != tuple(range(5)) for pair in first)

    clusters = [f"cluster-{cluster}" for cluster in range(8) for _ in range(4)]
    targets = [target for target in (11, 23, 37, 61, 89, 127, 173, 229) for _ in range(4)]
    permuted = permute_cluster_targets(
        clusters,
        targets,
        first[0].fit_cluster_permutation,
    )
    assert len(permuted) == 32
    assert sorted(permuted) == sorted(targets)
    assert all(len(set(permuted[start : start + 4])) == 1 for start in range(0, 32, 4))


def test_feature_reader_accepts_the_completed_a220p_real_trajectory_schema() -> None:
    result = json.loads(A220P.read_bytes())
    records = result["run_records"]
    expected = {
        ("numeric", "staged_retained_resolve"): (
            "c72ad600f55525ba050277980ed3aaaa1aaa0514532f4be29c1bd0ed715a77d1"
        ),
        ("numeric", "one_shot"): (
            "ec4c3d495beda3543b4f78b86d9d8a4ef8db069d4db2629903a488e944aeb68f"
        ),
        ("reflected_gray8", "staged_retained_resolve"): (
            "c830af9dd5a60dedde48d0a21557af9e50f9f86c04a54f391ff34115d8891f9f"
        ),
        ("reflected_gray8", "one_shot"): (
            "b0584ace68c9c9facc89517d5b3067c666c2dd32e081d1d6aa75b22ef0402943"
        ),
        ("formula_gray8", "staged_retained_resolve"): (
            "9c2ff9f31159c35def061c472218057f8af62b96d50452e1f96f7b0e18a07a4d"
        ),
        ("formula_gray8", "one_shot"): (
            "4095991a5b5f1ca03681d4eadf4b1e71b4275e567a74ee3b597f547efc04cadd"
        ),
    }
    for (geometry, schedule), digest in expected.items():
        forward = records[f"{geometry}_forward__{schedule}"]["scientific_measurement"]
        reverse = records[f"{geometry}_reverse_same_anchor__{schedule}"]["scientific_measurement"]
        views = extract_pair_feature_views(forward, reverse)
        raw = b"".join(
            views[family].matrix.astype("<f8").tobytes() for family in FEATURE_FAMILY_ORDER
        )
        assert hashlib.sha256(raw).hexdigest() == digest


def test_malformed_or_forbidden_channel_inputs_fail_closed() -> None:
    forward = _trajectory(list(range(256)), 1)
    reverse = _trajectory([0, *range(255, 0, -1)], 2)
    forward["cells"][0]["metrics_delta"][1] = -1
    with pytest.raises(ValueError, match="eligible trajectory channel"):
        extract_pair_feature_views(forward, reverse)


def test_malformed_reader_artifact_labels_and_operator_paths_fail_closed() -> None:
    forward = _trajectory(list(range(256)), 1)
    reverse = _trajectory([0, *range(255, 0, -1)], 2)
    views = extract_pair_feature_views(forward, reverse)
    matrix, labels, names = training_matrix(
        [views["P1_dense_local"], views["P1_dense_local"]], [3, 7]
    )

    malformed_labels = labels.astype(np.float64)
    malformed_labels[0] = 0.5
    with pytest.raises(ValueError, match="invalid A220 readout"):
        fit_factorial_readout(
            matrix,
            malformed_labels,
            kind="ridge_logistic",
            feature_family="P1_dense_local",
            feature_names=names,
            ridge_lambda=1.0,
        )

    invalid_order = {**forward, "order": [*forward["order"]]}
    invalid_order["order"][0] = "not-bits"
    with pytest.raises(ValueError, match="operator order"):
        extract_pair_feature_views(invalid_order, reverse)

    valid = fit_factorial_readout(
        matrix,
        labels,
        kind="gram_wiener_fisher",
        feature_family="P1_dense_local",
        feature_names=names,
        ridge_lambda=1.0,
    ).as_dict()
    valid["scales"][0] = 0.0
    with pytest.raises(ValueError, match="serialized readout"):
        readout_from_dict(valid)

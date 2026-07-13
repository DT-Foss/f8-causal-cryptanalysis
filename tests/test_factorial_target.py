from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path
from typing import Any

import numpy as np
import pytest

from arx_carry_leak import factorial_target as target
from arx_carry_leak.factorial_trajectory import CandidateIdentity, PairFeatureView

ROOT = Path(__file__).parents[1]
ENSEMBLE_PROTOCOL = (
    ROOT / "research/configs/chacha20_round20_factorial_eight_block_ensemble_v1.json"
)


def _reader(bundle: str) -> dict[str, Any]:
    identity = CandidateIdentity(bundle, "P1_dense_local", "ridge_logistic", 0.01)
    constituent_ids = (
        (bundle,)
        if bundle != "numeric__dual_schedule"
        else ("numeric__staged_retained_resolve", "numeric__one_shot")
    )
    return {
        "selected_identity": identity.as_dict(),
        "selected_metrics": {"ranks": [1]},
        "selected_score_sha256": "11" * 32,
        "candidate_grid_sha256": "22" * 32,
        "selected_constituent_readouts": {
            constituent: {
                "kind": "ridge_logistic",
                "feature_family": "P1_dense_local",
                "feature_names": [f"f{index}" for index in range(12)],
                "means": [0.0] * 12,
                "scales": [1.0] * 12,
                "intercept": 0.0,
                "coefficients": [1.0, *([0.0] * 11)],
                "ridge_lambda": 0.01,
                "diagnostics": {"fixture": True},
            }
            for constituent in constituent_ids
        },
    }


def _runs(bundle: str) -> dict[str, dict[str, Any]]:
    return {
        run_id: {
            "mode": f"fixture_{run_id}",
            "order": [f"{value:08b}" for value in range(256)],
            "cells": [
                {
                    "prefix8": f"{value:08b}",
                    "metrics_delta": [0, 0, 0],
                    "redundant_clauses_delta": 0,
                }
                for value in range(256)
            ],
        }
        for run_id in target.selected_bundle_run_ids(bundle)
    }


def _set_fixture_scores(runs: dict[str, dict[str, Any]], run_id: str, scores: list[int]) -> None:
    assert len(scores) == 256
    for cell, score in zip(runs[run_id]["cells"], scores, strict=True):
        cell["metrics_delta"][0] = int(score)


def _block_observation(block: int, runs: dict[str, dict[str, Any]]) -> dict[str, Any]:
    return {
        "counter_block_index": block,
        "counter_value": (0xFFFFFFFC + block) & 0xFFFFFFFF,
        "public_challenge_sha256": "aa" * 32,
        "target_block_words_sha256": hashlib.sha256(bytes([block])).hexdigest(),
        "launch_manifest_sha256": "bb" * 32,
        "measurement_sha256": hashlib.sha256(b"measurement" + bytes([block])).hexdigest(),
        "scientific_runs_sha256": target._canonical_sha256(runs),
        "scientific_runs": runs,
    }


def _fake_pair_view(
    runs: dict[str, dict[str, Any]], *, bundle_id: str, feature_family: str
) -> PairFeatureView:
    del feature_family
    geometry, schedule = bundle_id.split("__", 1)
    forward_id = f"{geometry}_forward__{schedule}"
    score = [cell["metrics_delta"][0] for cell in runs[forward_id]["cells"]]
    matrix = np.zeros((256, 12), dtype=np.float64)
    matrix[:, 0] = score
    return PairFeatureView(tuple(f"f{index}" for index in range(12)), matrix)


def test_atomic_label_free_reader_emits_complete_tie_stable_order(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    bundle = "numeric__one_shot"
    runs = _runs(bundle)
    scores = np.zeros(256)
    scores[91] = 4.0
    scores[17] = 3.0
    _set_fixture_scores(runs, "numeric_forward__one_shot", scores.astype(int).tolist())
    monkeypatch.setattr(target, "_pair_view", _fake_pair_view)
    result = target.score_label_free_target(_reader(bundle), runs)
    assert result["target_label_or_secret_used"] is False
    assert result["complete_prefix_order"][:4] == [91, 17, 0, 1]
    assert len(result["complete_prefix_order"]) == 256
    assert result["top_1_prefix"] == 91
    assert result["score_vector_prefix_order"] == list(range(256))
    assert result["score_vector_float64"] == scores.tolist()
    assert (
        result["score_vector_float64_le_sha256"]
        == hashlib.sha256(np.asarray(scores, dtype="<f8").tobytes()).hexdigest()
    )


def test_dual_schedule_combines_both_constituents(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    bundle = "numeric__dual_schedule"
    runs = _runs(bundle)
    staged = np.zeros(256)
    one_shot = np.zeros(256)
    staged[7] = 10.0
    one_shot[7] = 10.0
    staged[9] = 9.0
    one_shot[11] = 9.0
    _set_fixture_scores(
        runs, "numeric_forward__staged_retained_resolve", staged.astype(int).tolist()
    )
    _set_fixture_scores(runs, "numeric_forward__one_shot", one_shot.astype(int).tolist())
    monkeypatch.setattr(target, "_pair_view", _fake_pair_view)
    result = target.score_label_free_target(_reader(bundle), runs)
    assert result["top_1_prefix"] == 7
    assert len(result["selected_run_ids"]) == 4
    assert len(result["constituent_bundle_ids"]) == 2


def test_all_equal_scores_use_ascending_prefix_tie_break(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    bundle = "numeric__staged_retained_resolve"
    runs = _runs(bundle)
    monkeypatch.setattr(target, "_pair_view", _fake_pair_view)
    result = target.score_label_free_target(_reader(bundle), runs)
    assert result["complete_prefix_order"] == list(range(256))


def test_missing_or_extra_selected_run_is_rejected() -> None:
    bundle = "numeric__one_shot"
    runs = _runs(bundle)
    runs.pop("numeric_reverse_same_anchor__one_shot")
    with pytest.raises(ValueError, match="run cover"):
        target.score_label_free_target(_reader(bundle), runs)


def test_reader_schema_or_readout_identity_is_rejected() -> None:
    bundle = "numeric__one_shot"
    reader = _reader(bundle)
    reader["selected_constituent_readouts"][bundle]["feature_family"] = "P2_dense_cross"
    with pytest.raises(ValueError):
        target.score_label_free_target(reader, _runs(bundle))


def test_reader_binding_covers_full_selected_reader_and_executable_readout(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    bundle = "numeric__one_shot"
    reader = _reader(bundle)
    monkeypatch.setattr(target, "_pair_view", _fake_pair_view)
    baseline = target.score_label_free_target(reader, _runs(bundle))

    changed_metrics = copy.deepcopy(reader)
    changed_metrics["selected_metrics"]["ranks"] = [2]
    metrics_result = target.score_label_free_target(changed_metrics, _runs(bundle))
    assert (
        metrics_result["selected_reader_canonical_sha256"]
        != baseline["selected_reader_canonical_sha256"]
    )
    assert metrics_result["selected_readout_sha256"] == baseline["selected_readout_sha256"]

    changed_readout = copy.deepcopy(reader)
    changed_readout["selected_constituent_readouts"][bundle]["coefficients"][0] = 2.0
    readout_result = target.score_label_free_target(changed_readout, _runs(bundle))
    assert (
        readout_result["selected_reader_canonical_sha256"]
        != baseline["selected_reader_canonical_sha256"]
    )
    assert readout_result["selected_readout_sha256"] != baseline["selected_readout_sha256"]


def test_single_return_binds_exact_scientific_run_input_even_when_scores_match(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    bundle = "numeric__one_shot"
    baseline_runs = _runs(bundle)
    changed_runs = copy.deepcopy(baseline_runs)
    changed_runs["numeric_forward__one_shot"]["cells"][0]["redundant_clauses_delta"] = 1
    monkeypatch.setattr(target, "_pair_view", _fake_pair_view)
    baseline = target.score_label_free_target(_reader(bundle), baseline_runs)
    changed = target.score_label_free_target(_reader(bundle), changed_runs)
    assert baseline["score_vector_float64_le_sha256"] == changed["score_vector_float64_le_sha256"]
    assert (
        baseline["scientific_runs_canonical_sha256"] != changed["scientific_runs_canonical_sha256"]
    )


def test_single_reader_rejects_nonprojected_public_run_fields(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    bundle = "numeric__one_shot"
    runs = _runs(bundle)
    runs["numeric_forward__one_shot"]["summary"] = {"public_only": True}
    monkeypatch.setattr(target, "_pair_view", _fake_pair_view)
    with pytest.raises(ValueError, match="non-projected"):
        target.score_label_free_target(_reader(bundle), runs)


@pytest.mark.parametrize(
    ("location", "field"),
    [
        ("reader", "target_prefix8"),
        ("reader", "low20"),
        ("runs", "true_prefix8"),
        ("runs", "secret_low20"),
        ("runs", "model_bits_bit0_through_bit19"),
        ("runs", "unknown_assignment"),
    ],
)
def test_recursive_reveal_or_label_fields_are_rejected(
    monkeypatch: pytest.MonkeyPatch, location: str, field: str
) -> None:
    bundle = "numeric__one_shot"
    reader = _reader(bundle)
    runs = _runs(bundle)
    if location == "reader":
        reader["selected_constituent_readouts"][bundle]["diagnostics"][field] = 7
    else:
        runs["numeric_forward__one_shot"]["nested"] = [{field: 7}]
    monkeypatch.setattr(target, "_pair_view", _fake_pair_view)
    with pytest.raises(ValueError, match="forbidden reveal/label fields"):
        target.score_label_free_target(reader, runs)


def test_candidate_prefix_fields_remain_permitted(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    bundle = "numeric__one_shot"
    runs = _runs(bundle)
    monkeypatch.setattr(target, "_pair_view", _fake_pair_view)
    result = target.score_label_free_target(copy.deepcopy(_reader(bundle)), runs)
    assert result["recursive_reveal_label_field_gate_passed"] is True
    assert result["complete_prefix_order"] == list(range(256))


def _raw_run(order: list[str] | None = None) -> dict[str, Any]:
    prefixes = order or [f"{value:08b}" for value in range(256)]
    return {
        "mode": "A221_fixture",
        "order": prefixes,
        "stages": [
            {
                "prefix8": prefix,
                "model_bits_bit0_through_bit19": [],
                "status": "unknown",
            }
            for prefix in prefixes
        ],
        "cells": [
            {
                "prefix8": prefix,
                "metrics_delta": [index, index + 1, index + 2],
                "redundant_clauses_delta": index - 128,
                "final_status": "unknown",
            }
            for index, prefix in enumerate(prefixes)
        ],
        "summary": {"fixture": True},
    }


def test_reader_projection_keeps_only_exact_three_channels() -> None:
    raw = {"numeric_forward__one_shot": _raw_run()}
    projected = target.project_label_free_reader_runs(raw)
    run = projected["numeric_forward__one_shot"]
    assert set(run) == {"mode", "order", "cells"}
    assert set(run["cells"][0]) == {
        "prefix8",
        "metrics_delta",
        "redundant_clauses_delta",
    }
    assert run["cells"][0]["metrics_delta"] == [0, 1, 2]
    assert target._forbidden_target_field_paths(projected, path="projected") == ()


def test_reader_projection_refuses_nonempty_solver_model() -> None:
    raw = {"numeric_forward__one_shot": _raw_run()}
    raw["numeric_forward__one_shot"]["stages"][17]["model_bits_bit0_through_bit19"] = [0] * 20
    with pytest.raises(target.ProspectiveTargetModelObserved):
        target.project_label_free_reader_runs(raw)


def test_reader_projection_refuses_raw_secret_or_target_label() -> None:
    raw = {"numeric_forward__one_shot": _raw_run()}
    raw["numeric_forward__one_shot"]["summary"]["low20"] = 9
    with pytest.raises(ValueError, match="raw trajectory contains forbidden"):
        target.project_label_free_reader_runs(raw)


@pytest.mark.parametrize(
    "mutation",
    [
        "duplicate_order",
        "cell_order_mismatch",
        "negative_decisions",
        "boolean_metric",
        "missing_redundant",
    ],
)
def test_reader_projection_rejects_malformed_channels(mutation: str) -> None:
    raw = {"numeric_forward__one_shot": _raw_run()}
    run = raw["numeric_forward__one_shot"]
    if mutation == "duplicate_order":
        run["order"][1] = run["order"][0]
    elif mutation == "cell_order_mismatch":
        run["cells"][1]["prefix8"] = run["cells"][0]["prefix8"]
    elif mutation == "negative_decisions":
        run["cells"][0]["metrics_delta"][1] = -1
    elif mutation == "boolean_metric":
        run["cells"][0]["metrics_delta"][0] = True
    else:
        run["cells"][0].pop("redundant_clauses_delta")
    with pytest.raises(ValueError):
        target.project_label_free_reader_runs(raw)


def test_eight_block_ensemble_retains_only_cross_block_coherent_peak(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    bundle = "numeric__one_shot"
    runs_by_block = {}
    for block in range(8):
        runs = _runs(bundle)
        scores = np.zeros(256)
        scores[73] = 4.0
        scores[100 + block] = 20.0
        _set_fixture_scores(runs, "numeric_forward__one_shot", scores.astype(int).tolist())
        runs_by_block[block] = _block_observation(block, runs)
    monkeypatch.setattr(target, "_pair_view", _fake_pair_view)
    result = target.score_label_free_target_ensemble(_reader(bundle), runs_by_block)
    assert result["top_1_prefix"] == 73
    assert result["block_indices"] == list(range(8))
    assert len(result["per_block_score_vector_float64_le_sha256"]) == 8
    assert result["block_selection_weighting_or_dropping_performed"] is False
    assert result["target_label_or_secret_used"] is False
    assert len(result["selected_reader_canonical_sha256"]) == 64
    assert len(result["selected_readout_sha256"]) == 64
    assert result["counter_values"] == [(0xFFFFFFFC + block) & 0xFFFFFFFF for block in range(8)]
    assert len(result["ordered_block_input_manifest"]) == 8


def test_eight_block_dual_schedule_uses_all_four_runs_per_block(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    bundle = "numeric__dual_schedule"
    observations = {}
    for block in range(8):
        runs = _runs(bundle)
        staged = np.zeros(256)
        one_shot = np.zeros(256)
        staged[31] = 5.0
        one_shot[31] = 7.0
        _set_fixture_scores(
            runs, "numeric_forward__staged_retained_resolve", staged.astype(int).tolist()
        )
        _set_fixture_scores(runs, "numeric_forward__one_shot", one_shot.astype(int).tolist())
        observations[block] = _block_observation(block, runs)
    monkeypatch.setattr(target, "_pair_view", _fake_pair_view)
    result = target.score_label_free_target_ensemble(_reader(bundle), observations)
    assert result["top_1_prefix"] == 31
    assert len(result["selected_run_ids_per_block"]) == 4


def test_eight_block_rank_overlay_is_positive_affine_and_mapping_order_invariant(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    bundle = "numeric__one_shot"
    baseline = {}
    transformed = {}
    for block in range(8):
        values = np.arange(256, dtype=np.int64)
        values = np.roll(values, block * 7)
        runs = _runs(bundle)
        _set_fixture_scores(runs, "numeric_forward__one_shot", values.tolist())
        baseline[block] = _block_observation(block, runs)
        scaled_runs = _runs(bundle)
        _set_fixture_scores(
            scaled_runs,
            "numeric_forward__one_shot",
            ((3 + block) * values + 17 - block).tolist(),
        )
        transformed[block] = _block_observation(block, scaled_runs)
    monkeypatch.setattr(target, "_pair_view", _fake_pair_view)
    first = target.score_label_free_target_ensemble(_reader(bundle), baseline)
    reversed_mapping = dict(reversed(list(transformed.items())))
    second = target.score_label_free_target_ensemble(_reader(bundle), reversed_mapping)
    assert first["complete_prefix_order"] == second["complete_prefix_order"]
    assert first["score_vector_float64"] == second["score_vector_float64"]
    assert (
        first["ordered_block_input_manifest_sha256"]
        != second["ordered_block_input_manifest_sha256"]
    )


def test_eight_block_complete_tie_uses_ascending_prefix_order(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    bundle = "numeric__one_shot"
    observations = {block: _block_observation(block, _runs(bundle)) for block in range(8)}
    monkeypatch.setattr(target, "_pair_view", _fake_pair_view)
    result = target.score_label_free_target_ensemble(_reader(bundle), observations)
    assert result["complete_prefix_order"] == list(range(256))


def test_eight_block_ensemble_requires_all_blocks_and_rejects_secret_field(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    bundle = "numeric__one_shot"
    runs_by_block = {block: _block_observation(block, _runs(bundle)) for block in range(8)}
    monkeypatch.setattr(target, "_pair_view", _fake_pair_view)
    incomplete = dict(runs_by_block)
    incomplete.pop(7)
    with pytest.raises(ValueError, match="blocks zero through seven"):
        target.score_label_free_target_ensemble(_reader(bundle), incomplete)
    runs_by_block[6]["scientific_runs"]["numeric_forward__one_shot"]["nested"] = {"low20": 1}
    with pytest.raises(ValueError, match="forbidden reveal/label fields"):
        target.score_label_free_target_ensemble(_reader(bundle), runs_by_block)


@pytest.mark.parametrize(
    "mutation",
    [
        "embedded_index",
        "counter_sequence",
        "challenge",
        "run_hash",
        "extra_field",
        "boolean_key",
    ],
)
def test_eight_block_ensemble_rejects_unbound_block_provenance(
    monkeypatch: pytest.MonkeyPatch, mutation: str
) -> None:
    bundle = "numeric__one_shot"
    observations = {block: _block_observation(block, _runs(bundle)) for block in range(8)}
    monkeypatch.setattr(target, "_pair_view", _fake_pair_view)
    if mutation == "embedded_index":
        observations[7]["counter_block_index"] = 0
    elif mutation == "counter_sequence":
        observations[7]["counter_value"] ^= 1
    elif mutation == "challenge":
        observations[7]["public_challenge_sha256"] = "cc" * 32
    elif mutation == "run_hash":
        observations[7]["scientific_runs_sha256"] = "dd" * 32
    elif mutation == "boolean_key":
        replacement = observations.pop(1)
        observations[True] = replacement
    else:
        observations[7]["unregistered"] = True
    with pytest.raises(ValueError):
        target.score_label_free_target_ensemble(_reader(bundle), observations)


def test_eight_block_mechanism_was_frozen_before_outcome() -> None:
    protocol = json.loads(ENSEMBLE_PROTOCOL.read_bytes())
    anchors = protocol["anchors"]
    assert protocol["schema"] == "chacha20-round20-factorial-eight-block-ensemble-protocol-v1"
    assert protocol["protocol_state"].endswith("any_A222_solver_process")
    for path_key, hash_key in (
        ("A220_protocol_path", "A220_protocol_sha256"),
        ("ensemble_core_path", "ensemble_core_sha256"),
        ("ensemble_core_test_path", "ensemble_core_test_sha256"),
        ("key_design_path", "key_design_sha256"),
        ("key_design_test_path", "key_design_test_sha256"),
    ):
        assert (
            hashlib.sha256((ROOT / anchors[path_key]).read_bytes()).hexdigest() == anchors[hash_key]
        )
    assert protocol["execution"]["counter_block_indices"] == list(range(8))
    assert protocol["execution"]["block_selection_weighting_or_dropping_permitted"] is False
    assert protocol["validation"]["reader_refit_or_reselection_permitted"] is False
    statistic = protocol["validation"]["paired_primary_statistic"]
    assert statistic["exact_null_transformations"] == 256
    assert statistic["retention_threshold"] == 0.05
    assert statistic["retained_exactly_if"].endswith("strictly_below_0")
    assert (
        protocol["validation"][
            "key_block_operator_retry_drop_weight_budget_or_threshold_adaptation_permitted"
        ]
        is False
    )
    assert (
        protocol["information_boundary"]["A220_holdout_outcome_opened_before_mechanism_freeze"]
        is False
    )
    assert (
        protocol["information_boundary"][
            "block_observation_requires_embedded_index_counter_challenge_target_launch_measurement_and_projected_input_hashes"
        ]
        is True
    )

from __future__ import annotations

from typing import Any

import numpy as np
import pytest

from arx_carry_leak import factorial_target as target
from arx_carry_leak.factorial_trajectory import CandidateIdentity, PairFeatureView


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
        run_id: {"fixture_scores": np.zeros(256)}
        for run_id in target.selected_bundle_run_ids(bundle)
    }


def _fake_pair_view(
    runs: dict[str, dict[str, Any]], *, bundle_id: str, feature_family: str
) -> PairFeatureView:
    del feature_family
    geometry, schedule = bundle_id.split("__", 1)
    forward_id = f"{geometry}_forward__{schedule}"
    score = runs[forward_id]["fixture_scores"]
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
    runs["numeric_forward__one_shot"]["fixture_scores"] = scores
    monkeypatch.setattr(target, "_pair_view", _fake_pair_view)
    result = target.score_label_free_target(_reader(bundle), runs)
    assert result["target_label_or_secret_used"] is False
    assert result["complete_prefix_order"][:4] == [91, 17, 0, 1]
    assert len(result["complete_prefix_order"]) == 256
    assert result["top_1_prefix"] == 91


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
    runs["numeric_forward__staged_retained_resolve"]["fixture_scores"] = staged
    runs["numeric_forward__one_shot"]["fixture_scores"] = one_shot
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

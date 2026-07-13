from __future__ import annotations

import hashlib
import itertools
import json
from typing import Any

import numpy as np
import pytest

from arx_carry_leak import factorial_holdout as holdout
from arx_carry_leak.factorial_trajectory import (
    CandidateIdentity,
    PairFeatureView,
    exact_rank,
)


def _rows() -> list[dict[str, Any]]:
    result = []
    panels = (
        ("fit", "confirm", 8),
        ("select", "confirm", 5),
        ("confirm", "fit", 5),
        ("confirm", "confirm", 5),
    )
    prefix_seed = 11
    for prefix_split, suffix_split, clusters in panels:
        for prefix_index in range(clusters):
            prefix8 = prefix_seed
            prefix_seed += 7
            for suffix_index in range(4):
                suffix12 = 0x101 + 13 * suffix_index
                result.append(
                    {
                        "label": (
                            f"a220_{prefix_split}_p{prefix_index:02d}_"
                            f"{suffix_split}_s{suffix_index:02d}"
                        ),
                        "prefix_split": prefix_split,
                        "prefix_index": prefix_index,
                        "prefix8": prefix8,
                        "prefix8_binary": f"{prefix8:08b}",
                        "suffix_split": suffix_split,
                        "suffix_index": suffix_index,
                        "suffix12": suffix12,
                        "low20": (prefix8 << 12) | suffix12,
                        "low20_hex": f"{((prefix8 << 12) | suffix12):05x}",
                    }
                )
    assert len(result) == 92
    return result


def _readout(bundle: str) -> dict[str, Any]:
    identity = CandidateIdentity(bundle, "P1_dense_local", "ridge_logistic", 0.01)
    constituent_ids = (
        (bundle,)
        if bundle != "numeric__dual_schedule"
        else ("numeric__staged_retained_resolve", "numeric__one_shot")
    )
    serialized = {
        constituent: {
            "kind": identity.readout_kind,
            "feature_family": identity.feature_family,
            "feature_names": [f"f{index}" for index in range(12)],
            "means": [0.0] * 12,
            "scales": [1.0] * 12,
            "intercept": 0.0,
            "coefficients": [1.0, *([0.0] * 11)],
            "ridge_lambda": identity.ridge_lambda,
            "diagnostics": {"fixture": True},
        }
        for constituent in constituent_ids
    }
    return {
        "selected_identity": identity.as_dict(),
        "selected_metrics": {"ranks": [1]},
        "selected_score_sha256": "11" * 32,
        "selected_constituent_readouts": serialized,
        "candidate_grid_sha256": "22" * 32,
    }


def _run_ids(bundle: str) -> tuple[str, ...]:
    return holdout.selected_bundle_run_ids(bundle)


def _payloads(rows: list[dict[str, Any]], bundle: str) -> list[dict[str, Any]]:
    return [
        {
            "key_factorial_identity": dict(row),
            "scientific_runs": {run_id: {"run_id": run_id} for run_id in _run_ids(bundle)},
        }
        for row in rows
    ]


def _fake_view(run: dict[str, Any], reverse: dict[str, Any]) -> dict[str, PairFeatureView]:
    del reverse
    # Each fixture run carries its desired 256-score vector in the first column.
    score = np.asarray(run["fixture_scores"], dtype=np.float64)
    matrix = np.zeros((256, 12), dtype=np.float64)
    matrix[:, 0] = score
    return {"P1_dense_local": PairFeatureView(tuple(f"f{i}" for i in range(12)), matrix)}


@pytest.mark.parametrize(
    ("bundle", "expected"),
    [
        (
            "numeric__staged_retained_resolve",
            (
                "numeric_forward__staged_retained_resolve",
                "numeric_reverse_same_anchor__staged_retained_resolve",
            ),
        ),
        (
            "numeric__dual_schedule",
            (
                "numeric_forward__staged_retained_resolve",
                "numeric_reverse_same_anchor__staged_retained_resolve",
                "numeric_forward__one_shot",
                "numeric_reverse_same_anchor__one_shot",
            ),
        ),
    ],
)
def test_selected_bundle_run_ids_are_exact(bundle: str, expected: tuple[str, ...]) -> None:
    assert holdout.selected_bundle_run_ids(bundle) == expected


def test_score_verified_holdout_applies_atomic_reader_without_refit(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    rows = _rows()
    bundle = "numeric__staged_retained_resolve"
    payloads = _payloads(rows, bundle)
    for row, payload in zip(rows, payloads, strict=True):
        score = np.zeros(256)
        score[int(row["prefix8"])] = 10.0
        payload["scientific_runs"][_run_ids(bundle)[0]]["fixture_scores"] = score
    monkeypatch.setattr(holdout, "extract_pair_feature_views", _fake_view)
    scored = holdout.score_verified_holdout(_readout(bundle), rows, payloads)
    assert scored["overall_metrics"]["ranks"] == [1] * 92
    assert scored["selected_run_ids"] == list(_run_ids(bundle))
    assert len(scored["per_key"]) == 92


def test_dual_schedule_uses_both_constituent_readouts(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    rows = _rows()
    bundle = "numeric__dual_schedule"
    payloads = _payloads(rows, bundle)
    for row, payload in zip(rows, payloads, strict=True):
        target = int(row["prefix8"])
        for run_id in (
            "numeric_forward__staged_retained_resolve",
            "numeric_forward__one_shot",
        ):
            score = np.arange(256, dtype=np.float64) * 1e-6
            score[target] = 10.0
            payload["scientific_runs"][run_id]["fixture_scores"] = score
    monkeypatch.setattr(holdout, "extract_pair_feature_views", _fake_view)
    scored = holdout.score_verified_holdout(_readout(bundle), rows, payloads)
    assert scored["overall_metrics"]["ranks"] == [1] * 92
    assert len(scored["selected_run_ids"]) == 4
    assert len(scored["constituent_bundle_ids"]) == 2


def test_complete_cluster_null_retains_a_transferring_reader(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    rows = _rows()
    bundle = "numeric__one_shot"
    payloads = _payloads(rows, bundle)
    for row, payload in zip(rows, payloads, strict=True):
        score = np.arange(256, dtype=np.float64) * 1e-9
        score[int(row["prefix8"])] = 100.0
        payload["scientific_runs"][_run_ids(bundle)[0]]["fixture_scores"] = score
    monkeypatch.setattr(holdout, "extract_pair_feature_views", _fake_view)
    result = holdout.evaluate_verified_holdout(_readout(bundle), rows, payloads)
    primary = result["primary_exact_cluster_null"]
    assert len(primary["permutation_records"]) == 120
    assert primary["exact_lower_tail_p"] == pytest.approx(1 / 120)
    assert primary["retained"] is True
    assert result["evidence_stage"] == "FULLROUND_R20_FACTORIAL_TRAJECTORY_HOLDOUT_TRANSFER"
    assert all(metrics["ranks"] == [1] * len(metrics["ranks"]) for metrics in result["panel_metrics"].values())


def test_complete_cluster_null_marks_only_the_scoped_probe_boundary(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    rows = _rows()
    bundle = "numeric__one_shot"
    payloads = _payloads(rows, bundle)
    score = np.linspace(0.0, 1.0, 256)
    for payload in payloads:
        payload["scientific_runs"][_run_ids(bundle)[0]]["fixture_scores"] = score
    monkeypatch.setattr(holdout, "extract_pair_feature_views", _fake_view)
    result = holdout.evaluate_verified_holdout(_readout(bundle), rows, payloads)
    assert result["primary_exact_cluster_null"]["retained"] is False
    assert result["evidence_stage"].endswith("PROBE_SPECIFIC_BOUNDARY")


def test_primary_null_is_exactly_all_five_factorial_cluster_permutations() -> None:
    rows = _rows()
    primary_rows = [row for row in rows if holdout.holdout_panel_name(row) == "confirm_by_confirm"]
    scores = np.tile(np.linspace(0.0, 1.0, 256), (20, 1))
    null = holdout._primary_exact_null(primary_rows, scores)
    observed_permutations = {
        tuple(record["cluster_permutation"]) for record in null["permutation_records"]
    }
    assert observed_permutations == set(itertools.permutations(range(5)))


def test_tie_break_remains_ascending_prefix() -> None:
    scores = np.zeros(256)
    assert exact_rank(scores, 0) == 1
    assert exact_rank(scores, 255) == 256


def test_payload_order_and_run_cover_are_fail_closed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    rows = _rows()
    bundle = "numeric__one_shot"
    payloads = _payloads(rows, bundle)
    monkeypatch.setattr(holdout, "extract_pair_feature_views", _fake_view)
    payloads[0]["key_factorial_identity"] = dict(rows[1])
    with pytest.raises(ValueError, match="payload order"):
        holdout.score_verified_holdout(_readout(bundle), rows, payloads)


def test_evaluation_digest_is_canonical_and_score_digest_is_binary_stable(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    rows = _rows()
    bundle = "numeric__one_shot"
    payloads = _payloads(rows, bundle)
    for row, payload in zip(rows, payloads, strict=True):
        score = np.arange(256, dtype=np.float64)
        score[int(row["prefix8"])] += 300.0
        payload["scientific_runs"][_run_ids(bundle)[0]]["fixture_scores"] = score
    monkeypatch.setattr(holdout, "extract_pair_feature_views", _fake_view)
    first = holdout.evaluate_verified_holdout(_readout(bundle), rows, payloads)
    second = holdout.evaluate_verified_holdout(_readout(bundle), rows, payloads)
    assert first == second
    unhashed = {key: value for key, value in first.items() if key != "evaluation_sha256"}
    raw = json.dumps(
        unhashed, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False
    ).encode()
    assert first["evaluation_sha256"] == hashlib.sha256(raw).hexdigest()

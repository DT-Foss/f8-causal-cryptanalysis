from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import numpy as np
import pytest

ROOT = Path(__file__).parents[1]
SOURCE = ROOT / "research/experiments/chacha20_round20_factorial_trajectory_read.py"


def _load(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


MODULE = _load(SOURCE, "a220_factorial_reader_test")


class _FakeReadout:
    def __init__(self, identity: str, family: str, kind: str, ridge_lambda: float):
        self.identity = identity
        self.family = family
        self.kind = kind
        self.ridge_lambda = ridge_lambda

    def as_dict(self) -> dict:
        width = MODULE.FEATURE_COUNTS[self.family]
        return {
            "kind": self.kind,
            "feature_family": self.family,
            "feature_names": [f"feature-{index}" for index in range(width)],
            "means": [0.0] * width,
            "scales": [1.0] * width,
            "intercept": 0.0,
            "coefficients": [0.0] * width,
            "ridge_lambda": self.ridge_lambda,
            "diagnostics": {"fake_identity": self.identity},
        }


def test_frozen_protocol_reader_source_and_orders_are_exact() -> None:
    protocol, digest = MODULE._load_protocol()
    assert digest == MODULE._file_sha256(MODULE.PROTOCOL)
    assert protocol["learning_protocol"]["frozen_bundle_order"] == list(MODULE.BUNDLE_ORDER)
    assert protocol["learning_protocol"]["frozen_feature_family_order"] == list(
        MODULE.FEATURE_FAMILY_ORDER
    )
    assert protocol["learning_protocol"]["frozen_readout_order"] == list(MODULE.READOUT_ORDER)
    assert MODULE.NULL_REPLICATES == 64
    assert MODULE.NULL_WORKERS == 2


def test_training_labels_are_exactly_one_positive_per_fit_key() -> None:
    targets = [(index * 17 + 3) % 256 for index in range(MODULE.FIT_KEYS)]
    labels = MODULE._training_labels(targets).reshape(MODULE.FIT_KEYS, 256)
    assert np.array_equal(labels.sum(axis=1), np.ones(MODULE.FIT_KEYS))
    assert [int(np.flatnonzero(row)[0]) for row in labels] == targets
    with pytest.raises(ValueError, match="32-key panel"):
        MODULE._training_labels(targets[:-1])


def test_complete_300_fit_450_bundle_grid_and_tie_order_with_solver_free_mocks(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    training = {}
    selection = {}
    for bundle in MODULE.ATOMIC_BUNDLE_ORDER:
        for family in MODULE.FEATURE_FAMILY_ORDER:
            width = MODULE.FEATURE_COUNTS[family]
            names = (f"{bundle}:{family}", *[f"f{index}" for index in range(1, width)])
            training[(bundle, family)] = (np.zeros((1, width)), names)
            selection[(bundle, family)] = [object()] * MODULE.SELECTION_KEYS

    fits = []

    def fake_fit(matrix, labels, *, kind, feature_family, feature_names, ridge_lambda):
        assert len(labels) == MODULE.FIT_KEYS * 256
        identity = f"{feature_names[0]}:{kind}:{ridge_lambda}"
        fits.append(identity)
        return _FakeReadout(identity, feature_family, kind, ridge_lambda)

    def fake_scores(readout, views):
        assert len(views) == MODULE.SELECTION_KEYS
        return np.tile(np.arange(256, dtype=np.float64), (MODULE.SELECTION_KEYS, 1))

    monkeypatch.setattr(MODULE, "fit_factorial_readout", fake_fit)
    monkeypatch.setattr(MODULE, "score_readout_views", fake_scores)
    result = MODULE._evaluate_grid(
        training=training,
        selection=selection,
        fit_targets=[0] * MODULE.FIT_KEYS,
        selection_targets=[255] * MODULE.SELECTION_KEYS,
        retain_grid=True,
    )
    assert len(fits) == 300
    assert len(result["candidate_grid"]) == 450
    assert result["selected_identity"] == {
        "bundle_id": "numeric__staged_retained_resolve",
        "feature_family": "P1_dense_local",
        "readout_kind": "ridge_logistic",
        "ridge_lambda": 0.01,
        "run_count": 2,
    }
    assert result["selected_metrics"]["ranks"] == [1] * MODULE.SELECTION_KEYS
    assert set(result["selected_constituent_readouts"]) == {"numeric__staged_retained_resolve"}
    MODULE._validate_observed_grid(result)


def test_reader_checkpoint_resumes_only_verified_completed_null_replicates(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    pairs = MODULE.deterministic_matched_permutation_pairs(MODULE.MATCHED_NULL_SEED_LABEL)
    identity = {
        "schema": "chacha20-round20-factorial-trajectory-reader-checkpoint-v1",
        "protocol_sha256": "11" * 32,
        "reader_runner_sha256": "22" * 32,
        "fit_select_index_sha256": "33" * 32,
        "feature_matrix_sha256": {"frozen": "44" * 32},
        "fit_targets_sha256": "55" * 32,
        "selection_targets_sha256": "66" * 32,
    }
    path = tmp_path / "reader.checkpoint.json"
    empty = MODULE._load_reader_checkpoint(path, identity=identity, pairs=pairs)
    assert empty["observed"] is None
    assert empty["null_records"] == []

    candidate_grid = [{"candidate": index} for index in range(450)]
    null_record = {
        **pairs[0].as_dict(),
        "permuted_fit_targets_sha256": "88" * 32,
        "permuted_selection_targets_sha256": "99" * 32,
        "selected_identity": MODULE.CandidateIdentity(
            "numeric__one_shot", "P1_dense_local", "ridge_logistic", 0.01
        ).as_dict(),
        "candidate_grid_sha256": "77" * 32,
        "selected_selection_metrics": MODULE.rank_metrics([1] * MODULE.SELECTION_KEYS),
        "selected_score_sha256": "aa" * 32,
    }
    checkpoint = {
        **identity,
        "observed": {
            "candidate_grid": candidate_grid,
            "candidate_grid_sha256": MODULE._canonical_sha256(candidate_grid),
            "selected_constituent_readouts": {"numeric__one_shot": {}},
        },
        "null_records": [null_record],
    }
    monkeypatch.setattr(MODULE, "_validate_observed_grid", lambda observed: None)
    MODULE._atomic_json(path, checkpoint, private=True)
    assert MODULE._load_reader_checkpoint(path, identity=identity, pairs=pairs) == checkpoint
    assert path.stat().st_mode & 0o777 == 0o600

    checkpoint["null_records"][0]["fit_cluster_permutation"] = list(range(8))
    MODULE._atomic_json(path, checkpoint, private=True)
    with pytest.raises(RuntimeError, match="null checkpoint"):
        MODULE._load_reader_checkpoint(path, identity=identity, pairs=pairs)

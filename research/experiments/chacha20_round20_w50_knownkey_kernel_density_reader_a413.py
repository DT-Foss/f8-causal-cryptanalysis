#!/usr/bin/env python3
"""A413: frozen positive-density Reader with a 32-key external W50 transfer panel."""

from __future__ import annotations

import argparse
import importlib.util
import inspect
import json
import math
import os
import statistics
import sys
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

import numpy as np

ROOT = Path(__file__).parents[2]
RESEARCH = ROOT / "research"
CONFIGS = RESEARCH / "configs"
RESULTS = RESEARCH / "results/v1"

DESIGN = CONFIGS / "chacha20_round20_w50_knownkey_kernel_density_reader_a413_design_v1.json"
IMPLEMENTATION = (
    CONFIGS / "chacha20_round20_w50_knownkey_kernel_density_reader_a413_implementation_v1.json"
)
MODEL = CONFIGS / "chacha20_round20_w50_knownkey_kernel_density_reader_a413_model_v1.json"
TRAIN_CACHE = RESULTS / "chacha20_round20_w50_knownkey_kernel_density_reader_a413_training_v1"
TRAIN_PROGRESS = RESULTS / "chacha20_round20_w50_knownkey_kernel_density_reader_a413_progress_v1.json"
RESULT = RESULTS / "chacha20_round20_w50_knownkey_kernel_density_reader_a413_v1.json"
CAUSAL = RESULT.with_suffix(".causal")
REPORT = RESULT.with_suffix(".md")
TEST = ROOT / "tests/test_chacha20_round20_w50_knownkey_kernel_density_reader_a413.py"
REPRO = ROOT / "scripts/reproduce_chacha20_round20_w50_knownkey_kernel_density_reader_a413.sh"

A401_RUNNER = RESEARCH / "experiments/chacha20_round20_w50_knownkey_direct12_learning_a401.py"
A401_RESULT = RESULTS / "chacha20_round20_w50_knownkey_direct12_learning_a401_v1.json"
A404_RUNNER = RESEARCH / "experiments/chacha20_round20_w50_knownkey_leaveoneout_reader_a404.py"
A404_RESULT = RESULTS / "chacha20_round20_w50_knownkey_leaveoneout_reader_a404_v1.json"
A410_RUNNER = RESEARCH / "experiments/chacha20_round20_w50_knownkey_nested_prototype_reader_a410.py"
A410_RESULT = RESULTS / "chacha20_round20_w50_knownkey_nested_prototype_reader_a410_v1.json"
A412_RUNNER = RESEARCH / "experiments/chacha20_round20_w50_fresh_hybrid_reader_a412.py"
A412_IMPLEMENTATION = (
    CONFIGS / "chacha20_round20_w50_fresh_hybrid_reader_a412_implementation_v1.json"
)
A412_PROTOCOL = CONFIGS / "chacha20_round20_w50_fresh_hybrid_reader_a412_public_corpus_v1.json"
A388_ORDER = RESULTS / "chacha20_round20_w50_public_output_direct12_factor3_a388_order_v1.json"

ATTEMPT_ID = "A413"
DESIGN_SHA256 = "3dcf61da354a60c095d68168c2a6837663b39c5f683feb58de9cad3035675f7a"
A401_RUNNER_SHA256 = "2238b99504883cd0b722b7b92254b3dc02255a6b53c9851f35264daad3f21bee"
A401_RESULT_SHA256 = "347b3756833df4c6dd3e7d8af41f1d48ea6813822de38900e8e42969f4bfe702"
A404_RUNNER_SHA256 = "d7743e0bc4996c15189876dafa014fec6a8a13398f90885c0284e9c585192bc7"
A404_RESULT_SHA256 = "ded81a43fed7318ab8a0d32787d5e41e1c51b70e473dfc415dae30b44f4080e1"
A410_RUNNER_SHA256 = "2105111abf94365334d7c48509a76ff7abe84906edfae9455144978037066787"
A410_RESULT_SHA256 = "d631fcc57f1659455417789c58f277aa6d78118eb361281137bdcb846bae284e"
A412_RUNNER_SHA256 = "cc8813f29f29aed8f28b682c959d7655437faa7c5e9c713cbe9e2183e8641b96"
A412_IMPLEMENTATION_SHA256 = "f08665ec5f0b79bf96f33617d10966e59895e6adfb284c5b6c70e5fc47527067"
A412_PROTOCOL_SHA256 = "f7859b381d5cf6a5f1a765b4abb44192d3bd73539c681a9a40d8c0a48dd365a2"
A388_ORDER_SHA256 = "3c56ce8521b1ced20e1e3a90999810c2e563c4de941701c86274f0828b5d01b8"

TARGETS = tuple(range(16))
FRESH_TARGETS = tuple(range(32))
CELLS = 4096
REPRESENTATIONS = (
    ("log8", 8),
    ("reciprocal_sqrt8", 8),
    ("log_reciprocal16", 16),
    ("log_absdiff36", 36),
    ("log_reciprocal_absdiff44", 44),
)
KERNEL_METRICS = ("mean_absolute_L1", "mean_squared_L2", "maximum_absolute_Linf")
BANDWIDTH_MULTIPLIERS = (0.25, 0.5, 1.0, 2.0, 4.0)
LOCATIONS = ("coordinate_mean", "coordinate_median")
SCALES: tuple[tuple[str, float | None], ...] = (
    ("identity", None),
    ("diagonal_variance", 0.0),
    ("diagonal_variance", 0.25),
    ("diagonal_variance", 0.5),
    ("diagonal_variance", 0.75),
    ("full_covariance_isotropic", 0.25),
    ("full_covariance_isotropic", 0.5),
    ("full_covariance_isotropic", 0.75),
)
CANDIDATE_COUNT = 155
DOTCAUSAL_SRC = Path("/Users/bhkmie/Documents/Forschung/O1/vendor/fabel/dotcausal_package/src")


def load_module(path: Path, name: str) -> Any:
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot import A413 dependency {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


A410 = load_module(A410_RUNNER, "a413_a410")
A412 = load_module(A412_RUNNER, "a413_a412")
A401 = A410.A401
A402 = A412.A402

file_sha256 = A401.file_sha256
canonical_sha256 = A401.canonical_sha256
atomic_json = A401.atomic_json
atomic_bytes = A401.atomic_bytes
relative = A401.relative
anchor = A401.anchor
sha256 = A401.sha256


def candidate_rows() -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for representation_index, (representation, dimension) in enumerate(REPRESENTATIONS):
        for metric_index, metric in enumerate(KERNEL_METRICS):
            for bandwidth_index, multiplier in enumerate(BANDWIDTH_MULTIPLIERS):
                rows.append(
                    {
                        "candidate_index": len(rows),
                        "family": "positive_kernel_density",
                        "family_index": 0,
                        "representation": representation,
                        "representation_index": representation_index,
                        "feature_dimension": dimension,
                        "metric": metric,
                        "metric_index": metric_index,
                        "bandwidth_multiplier": multiplier,
                        "bandwidth_index": bandwidth_index,
                    }
                )
    for representation_index, (representation, dimension) in enumerate(REPRESENTATIONS):
        for location_index, location in enumerate(LOCATIONS):
            for scale_index, (scale_family, shrinkage) in enumerate(SCALES):
                rows.append(
                    {
                        "candidate_index": len(rows),
                        "family": "robust_location_shape",
                        "family_index": 1,
                        "representation": representation,
                        "representation_index": representation_index,
                        "feature_dimension": dimension,
                        "location": location,
                        "location_index": location_index,
                        "scale_family": scale_family,
                        "scale_index": scale_index,
                        "shrinkage": shrinkage,
                    }
                )
    if len(rows) != CANDIDATE_COUNT or [row["candidate_index"] for row in rows] != list(
        range(CANDIDATE_COUNT)
    ):
        raise RuntimeError("A413 candidate family differs")
    return rows


def candidate_tie_key(candidate: Mapping[str, Any]) -> tuple[int, ...]:
    if candidate["family"] == "positive_kernel_density":
        parameters = (int(candidate["metric_index"]), int(candidate["bandwidth_index"]))
    else:
        parameters = (int(candidate["location_index"]), int(candidate["scale_index"]))
    return (
        int(candidate["representation_index"]),
        int(candidate["family_index"]),
        *parameters,
    )


def metric_panel(ranks: Sequence[int]) -> dict[str, Any]:
    values = [int(value) for value in ranks]
    mean_log = statistics.fmean(math.log2(value) for value in values)
    return {
        "ranks": values,
        "geometric_mean_rank": 2.0**mean_log,
        "mean_log2_rank": mean_log,
        "bit_gain_vs_complete_4096_cover": 12.0 - mean_log,
        "median_rank": statistics.median(values),
        "top_quartile_targets": sum(value <= 1024 for value in values),
        "worst_rank": max(values),
    }


def select_candidate(candidates: Sequence[Mapping[str, Any]], truth: np.ndarray) -> int:
    values = np.asarray(truth, dtype=np.int64)
    if values.ndim != 2 or values.shape[1] != len(candidates) or len(candidates) != CANDIDATE_COUNT:
        raise ValueError("A413 selection table differs")
    mean_log = np.log2(values.astype(np.float64)).mean(axis=0)
    worst = values.max(axis=0)
    return min(
        range(CANDIDATE_COUNT),
        key=lambda index: (
            float(mean_log[index]),
            int(worst[index]),
            *candidate_tie_key(candidates[index]),
        ),
    )


def distance_rows(field: np.ndarray, prototypes: np.ndarray, metric: str) -> np.ndarray:
    matrix = np.asarray(field, dtype=np.float64)
    points = np.asarray(prototypes, dtype=np.float64)
    if matrix.ndim != 2 or points.ndim != 2 or matrix.shape[1] != points.shape[1]:
        raise ValueError("A413 distance shapes differ")
    delta = matrix[None, :, :] - points[:, None, :]
    if metric == "mean_absolute_L1":
        result = np.mean(np.abs(delta), axis=2)
    elif metric == "mean_squared_L2":
        result = np.mean(np.square(delta), axis=2)
    elif metric == "maximum_absolute_Linf":
        result = np.max(np.abs(delta), axis=2)
    else:
        raise ValueError(f"unknown A413 metric {metric}")
    if result.shape != (points.shape[0], matrix.shape[0]) or not np.isfinite(result).all():
        raise RuntimeError("A413 distance output differs")
    return result


def pairwise_distance(prototypes: np.ndarray, metric: str) -> np.ndarray:
    points = np.asarray(prototypes, dtype=np.float64)
    if points.ndim != 2 or points.shape[0] < 2:
        raise ValueError("A413 positive pairwise input differs")
    delta = points[:, None, :] - points[None, :, :]
    if metric == "mean_absolute_L1":
        result = np.mean(np.abs(delta), axis=2)
    elif metric == "mean_squared_L2":
        result = np.mean(np.square(delta), axis=2)
    elif metric == "maximum_absolute_Linf":
        result = np.max(np.abs(delta), axis=2)
    else:
        raise ValueError(f"unknown A413 metric {metric}")
    return result


def base_bandwidth(prototypes: np.ndarray, metric: str) -> float:
    pairwise = pairwise_distance(prototypes, metric)
    upper = pairwise[np.triu_indices(pairwise.shape[0], k=1)]
    positive = upper[upper > 0.0]
    value = float(np.median(positive)) if positive.size else 0.0
    return max(value, 2.0**-40)


def kernel_score_from_distances(distances: np.ndarray, bandwidth: float) -> np.ndarray:
    rows = np.asarray(distances, dtype=np.float64)
    if rows.ndim != 2 or rows.shape[0] < 1 or not bandwidth > 0.0:
        raise ValueError("A413 kernel input differs")
    scaled = -rows / bandwidth
    maxima = np.max(scaled, axis=0)
    shifted = np.maximum(
        scaled - maxima, math.log(np.finfo(np.float64).tiny)
    )
    log_mean = maxima + np.log(np.mean(np.exp(shifted), axis=0))
    scores = -log_mean
    if not np.isfinite(scores).all():
        raise RuntimeError("A413 kernel score differs")
    return scores


def fit_location_parameters(prototypes: np.ndarray, candidate: Mapping[str, Any]) -> dict[str, Any]:
    points = np.asarray(prototypes, dtype=np.float64)
    if points.ndim != 2 or points.shape[0] < 2:
        raise ValueError("A413 location prototypes differ")
    location = str(candidate["location"])
    if location == "coordinate_mean":
        center = points.mean(axis=0)
    elif location == "coordinate_median":
        center = np.median(points, axis=0)
    else:
        raise ValueError("A413 location differs")
    residual = points - center
    variances = np.mean(np.square(residual), axis=0)
    mean_variance = float(np.mean(variances))
    floor = max(mean_variance * (2.0**-20), 2.0**-40)
    family = str(candidate["scale_family"])
    shrinkage = candidate["shrinkage"]
    if family == "identity":
        precision_kind = "identity"
        precision = np.ones(points.shape[1], dtype=np.float64)
    elif family == "diagonal_variance":
        alpha = float(shrinkage)
        diagonal = (1.0 - alpha) * variances + alpha * mean_variance
        precision_kind = "diagonal"
        precision = np.reciprocal(np.maximum(diagonal, floor))
    elif family == "full_covariance_isotropic":
        alpha = float(shrinkage)
        covariance = np.einsum(
            "ni,nj->ij", residual, residual, optimize=False
        ) / float(points.shape[0])
        covariance = (1.0 - alpha) * covariance + alpha * mean_variance * np.eye(
            points.shape[1]
        )
        eigenvalues, eigenvectors = np.linalg.eigh(covariance)
        eigenvalues = np.maximum(eigenvalues, floor)
        precision_kind = "full"
        precision = np.einsum(
            "ik,jk,k->ij",
            eigenvectors,
            eigenvectors,
            np.reciprocal(eigenvalues),
            optimize=False,
        )
    else:
        raise ValueError("A413 scale family differs")
    if not np.isfinite(center).all() or not np.isfinite(precision).all():
        raise RuntimeError("A413 location parameters differ")
    return {
        "center": center.tolist(),
        "precision_kind": precision_kind,
        "precision": precision.tolist(),
        "variance_floor": floor,
    }


def location_scores(field: np.ndarray, parameters: Mapping[str, Any]) -> np.ndarray:
    matrix = np.asarray(field, dtype=np.float64)
    center = np.asarray(parameters["center"], dtype=np.float64)
    precision = np.asarray(parameters["precision"], dtype=np.float64)
    delta = matrix - center
    kind = str(parameters["precision_kind"])
    if kind in {"identity", "diagonal"}:
        scores = np.mean(np.square(delta) * precision, axis=1)
    elif kind == "full":
        scores = np.einsum("ij,jk,ik->i", delta, precision, delta, optimize=False) / float(
            matrix.shape[1]
        )
    else:
        raise ValueError("A413 precision kind differs")
    if not np.isfinite(scores).all() or np.any(scores < -1e-12):
        raise RuntimeError("A413 location score differs")
    return np.maximum(scores, 0.0)


def fit_frozen_model(prototypes: np.ndarray, candidate: Mapping[str, Any]) -> dict[str, Any]:
    points = np.asarray(prototypes, dtype=np.float64)
    if candidate["family"] == "positive_kernel_density":
        bandwidth = base_bandwidth(points, str(candidate["metric"])) * float(
            candidate["bandwidth_multiplier"]
        )
        parameters: dict[str, Any] = {
            "prototypes": points.tolist(),
            "bandwidth": bandwidth,
        }
        arrays = [points, np.asarray([bandwidth], dtype=np.float64)]
    else:
        parameters = fit_location_parameters(points, candidate)
        arrays = [
            np.asarray(parameters["center"], dtype=np.float64),
            np.asarray(parameters["precision"], dtype=np.float64),
            np.asarray([parameters["variance_floor"]], dtype=np.float64),
        ]
    raw = b"".join(np.asarray(array, dtype="<f8").tobytes() for array in arrays)
    return {
        "candidate": dict(candidate),
        "parameters": parameters,
        "parameter_float64le_sha256": sha256(raw),
        "training_prototype_float64le_sha256": sha256(points.astype("<f8").tobytes()),
    }


def score_frozen_model(field: np.ndarray, model: Mapping[str, Any]) -> np.ndarray:
    candidate = model["candidate"]
    parameters = model["parameters"]
    if candidate["family"] == "positive_kernel_density":
        prototypes = np.asarray(parameters["prototypes"], dtype=np.float64)
        distances = distance_rows(field, prototypes, str(candidate["metric"]))
        return kernel_score_from_distances(distances, float(parameters["bandwidth"]))
    return location_scores(field, parameters)


def exact_score_order(scores: np.ndarray) -> list[int]:
    values = np.asarray(scores, dtype=np.float64)
    if values.shape != (CELLS,) or not np.isfinite(values).all():
        raise ValueError("A413 score field differs")
    cells = np.arange(CELLS, dtype=np.int64)
    return A401.exact_order(np.lexsort((cells, values)).tolist())


def true_rank(scores: np.ndarray, cell: int) -> int:
    return int(A401.rank_vector(exact_score_order(scores))[cell])


def load_design() -> dict[str, Any]:
    if file_sha256(DESIGN) != DESIGN_SHA256:
        raise RuntimeError("A413 design hash differs")
    value = json.loads(DESIGN.read_bytes())
    boundary = value.get("information_boundary", {})
    if (
        value.get("schema")
        != "chacha20-round20-w50-knownkey-kernel-density-reader-a413-design-v1"
        or value.get("attempt_id") != ATTEMPT_ID
        or value.get("candidate_contract", {}).get("candidate_count") != CANDIDATE_COUNT
        or boundary.get("A412_complete_fields_available_at_design_freeze") != 0
        or boundary.get("A412_selection_or_holdout_label_ledger_opened") is not False
        or boundary.get("A412_reader_score_or_true_rank_available_at_design_freeze") is not False
    ):
        raise RuntimeError("A413 frozen design semantics differ")
    for key, path in value["source_anchors"].items():
        if key.endswith("_path"):
            stem = key.removesuffix("_path")
            anchor(ROOT / path, value["source_anchors"][f"{stem}_sha256"])
    return value


def freeze_implementation() -> dict[str, Any]:
    outputs = (IMPLEMENTATION, MODEL, RESULT, CAUSAL, REPORT)
    if any(path.exists() for path in outputs) or TRAIN_CACHE.exists() or TRAIN_PROGRESS.exists():
        raise FileExistsError("A413 implementation or generated training artifact already exists")
    load_design()
    if not TEST.exists() or not REPRO.exists():
        raise FileNotFoundError("A413 test and reproducer must precede freeze")
    payload: dict[str, Any] = {
        "schema": "chacha20-round20-w50-knownkey-kernel-density-reader-a413-implementation-v1",
        "attempt_id": ATTEMPT_ID,
        "commitment_state": "frozen_before_any_A413_training_rank_model_or_A412_label_score",
        "design_sha256": DESIGN_SHA256,
        "candidate_count": CANDIDATE_COUNT,
        "candidate_family_commitment_sha256": canonical_sha256(candidate_rows()),
        "A412_labels_or_reader_scores_consumed": False,
        "anchors": {
            "design": anchor(DESIGN, DESIGN_SHA256),
            "A401_runner": anchor(A401_RUNNER, A401_RUNNER_SHA256),
            "A401_result": anchor(A401_RESULT, A401_RESULT_SHA256),
            "A404_runner": anchor(A404_RUNNER, A404_RUNNER_SHA256),
            "A404_result": anchor(A404_RESULT, A404_RESULT_SHA256),
            "A410_runner": anchor(A410_RUNNER, A410_RUNNER_SHA256),
            "A410_result": anchor(A410_RESULT, A410_RESULT_SHA256),
            "A412_runner": anchor(A412_RUNNER, A412_RUNNER_SHA256),
            "A412_implementation": anchor(A412_IMPLEMENTATION, A412_IMPLEMENTATION_SHA256),
            "A412_protocol": anchor(A412_PROTOCOL, A412_PROTOCOL_SHA256),
            "A388_order": anchor(A388_ORDER, A388_ORDER_SHA256),
            "runner": anchor(Path(__file__)),
            "test": anchor(TEST),
            "reproducer": anchor(REPRO),
        },
    }
    payload["implementation_commitment_sha256"] = canonical_sha256(payload)
    atomic_json(IMPLEMENTATION, payload)
    return payload


def load_implementation(expected_sha256: str | None = None) -> dict[str, Any]:
    if expected_sha256 is not None and file_sha256(IMPLEMENTATION) != expected_sha256:
        raise RuntimeError("A413 implementation hash differs")
    value = json.loads(IMPLEMENTATION.read_bytes())
    if (
        value.get("schema")
        != "chacha20-round20-w50-knownkey-kernel-density-reader-a413-implementation-v1"
        or value.get("attempt_id") != ATTEMPT_ID
        or value.get("candidate_count") != CANDIDATE_COUNT
        or value.get("candidate_family_commitment_sha256") != canonical_sha256(candidate_rows())
        or value.get("A412_labels_or_reader_scores_consumed") is not False
    ):
        raise RuntimeError("A413 implementation semantics differ")
    for row in value["anchors"].values():
        anchor(ROOT / row["path"], row["sha256"])
    unsigned = {
        key: item for key, item in value.items() if key != "implementation_commitment_sha256"
    }
    if value.get("implementation_commitment_sha256") != canonical_sha256(unsigned):
        raise RuntimeError("A413 implementation commitment differs")
    return value


def training_bundle() -> dict[str, Any]:
    if file_sha256(A401_RESULT) != A401_RESULT_SHA256 or file_sha256(A410_RESULT) != A410_RESULT_SHA256:
        raise RuntimeError("A413 training source hash differs")
    selection = A401.load_label_file(
        A401.TRAIN_LABELS,
        "chacha20-round20-w50-knownkey-direct12-learning-a401-selection-labels-v1",
        A401.TRAIN_TARGETS,
    )
    holdout = A401.load_label_file(
        A401.HOLDOUT_LABELS,
        "chacha20-round20-w50-knownkey-direct12-learning-a401-holdout-labels-v1",
        A401.HOLDOUT_TARGETS,
    )
    labels = {**selection, **holdout}
    representations: dict[int, dict[str, np.ndarray]] = {}
    field_commitments: dict[str, Any] = {}
    true_cells = {index: int(labels[index]["true_direct12_cell"]) for index in TARGETS}
    for index in TARGETS:
        ranks, field_commitments[str(index)] = A401.view_rank_matrix(index)
        representations[index] = A410.representation_matrices(ranks)
    prototype_commitments = {}
    for name, _dimension in REPRESENTATIONS:
        points = np.stack(
            [representations[index][name][true_cells[index]] for index in TARGETS]
        )
        prototype_commitments[name] = sha256(points.astype("<f8").tobytes())
    return {
        "representations": representations,
        "true_cells": true_cells,
        "field_commitments": field_commitments,
        "prototype_commitments": prototype_commitments,
    }


def all_candidate_truth_ranks(
    bundle: Mapping[str, Any], validation: int, train_indices: Sequence[int]
) -> tuple[list[int], dict[str, Any]]:
    train = tuple(int(index) for index in train_indices)
    if validation in train or len(train) not in {14, 15} or len(set(train)) != len(train):
        raise ValueError("A413 training split differs")
    representations = bundle["representations"]
    true_cells = bundle["true_cells"]
    ranks = np.zeros(CANDIDATE_COUNT, dtype=np.int64)
    prototype_hashes = {}
    score_hashes: dict[str, str] = {}
    for representation_index, (name, _dimension) in enumerate(REPRESENTATIONS):
        field = representations[validation][name]
        prototypes = np.stack(
            [representations[index][name][int(true_cells[index])] for index in train]
        )
        prototype_hashes[name] = sha256(prototypes.astype("<f8").tobytes())
        for metric_index, metric in enumerate(KERNEL_METRICS):
            distances = distance_rows(field, prototypes, metric)
            base = base_bandwidth(prototypes, metric)
            scores = np.stack(
                [
                    kernel_score_from_distances(distances, base * multiplier)
                    for multiplier in BANDWIDTH_MULTIPLIERS
                ],
                axis=1,
            )
            start = representation_index * 15 + metric_index * 5
            ranks[start : start + 5] = A410.true_ranks(
                scores, int(true_cells[validation])
            )
            score_hashes[f"{name}:{metric}"] = sha256(scores.astype("<f8").tobytes())
        for location_index, _location in enumerate(LOCATIONS):
            location_scores_panel = []
            for scale_index, _scale in enumerate(SCALES):
                candidate_index = 75 + representation_index * 16 + location_index * 8 + scale_index
                candidate = candidate_rows()[candidate_index]
                parameters = fit_location_parameters(prototypes, candidate)
                location_scores_panel.append(location_scores(field, parameters))
            scores = np.stack(location_scores_panel, axis=1)
            start = 75 + representation_index * 16 + location_index * 8
            ranks[start : start + 8] = A410.true_ranks(
                scores, int(true_cells[validation])
            )
            score_hashes[f"{name}:{LOCATIONS[location_index]}"] = sha256(
                scores.astype("<f8").tobytes()
            )
    if np.any(ranks < 1) or np.any(ranks > CELLS):
        raise RuntimeError("A413 candidate truth ranks differ")
    return ranks.tolist(), {
        "training_prototype_float64le_sha256": prototype_hashes,
        "score_panel_float64le_sha256": score_hashes,
    }


def training_rank_path(validation: int, excluded_outer: int | None) -> Path:
    if excluded_outer is None:
        return TRAIN_CACHE / f"loo_validation_{validation:02d}_v1.json"
    return TRAIN_CACHE / f"nested_outer_{excluded_outer:02d}_validation_{validation:02d}_v1.json"


def cached_candidate_truth_ranks(
    bundle: Mapping[str, Any], validation: int, excluded_outer: int | None
) -> dict[str, Any]:
    excluded = {validation}
    if excluded_outer is not None:
        if excluded_outer == validation:
            raise ValueError("A413 nested exclusion differs")
        excluded.add(excluded_outer)
    train = [index for index in TARGETS if index not in excluded]
    path = training_rank_path(validation, excluded_outer)
    if path.exists():
        value = json.loads(path.read_bytes())
        if (
            value.get("schema") != "chacha20-round20-w50-knownkey-kernel-density-reader-a413-training-ranks-v1"
            or value.get("attempt_id") != ATTEMPT_ID
            or value.get("validation_target") != validation
            or value.get("excluded_outer_target") != excluded_outer
            or value.get("training_targets") != train
            or value.get("candidate_family_commitment_sha256") != canonical_sha256(candidate_rows())
            or len(value.get("candidate_true_ranks", [])) != CANDIDATE_COUNT
        ):
            raise RuntimeError("A413 cached training rank semantics differ")
        return value
    ranks, commitments = all_candidate_truth_ranks(bundle, validation, train)
    value = {
        "schema": "chacha20-round20-w50-knownkey-kernel-density-reader-a413-training-ranks-v1",
        "attempt_id": ATTEMPT_ID,
        "validation_target": validation,
        "excluded_outer_target": excluded_outer,
        "training_targets": train,
        "candidate_family_commitment_sha256": canonical_sha256(candidate_rows()),
        "candidate_true_ranks": ranks,
        "reader_commitments": commitments,
        "A412_labels_or_reader_scores_consumed": False,
    }
    value["training_rank_commitment_sha256"] = canonical_sha256(value)
    atomic_json(path, value)
    completed = len(list(TRAIN_CACHE.glob("*_v1.json")))
    atomic_json(
        TRAIN_PROGRESS,
        {
            "schema": "chacha20-round20-w50-knownkey-kernel-density-reader-a413-progress-v1",
            "attempt_id": ATTEMPT_ID,
            "completed_training_rank_panels": completed,
            "required_training_rank_panels": 256,
            "latest_path": relative(path),
            "latest_sha256": file_sha256(path),
            "A412_labels_or_reader_scores_consumed": False,
        },
    )
    return value


def freeze_model(*, expected_implementation_sha256: str) -> dict[str, Any]:
    if MODEL.exists() or RESULT.exists() or CAUSAL.exists() or REPORT.exists():
        raise FileExistsError("A413 model or result already exists")
    implementation = load_implementation(expected_implementation_sha256)
    bundle = training_bundle()
    candidates = candidate_rows()
    prospective = np.empty((len(TARGETS), CANDIDATE_COUNT), dtype=np.int64)
    cache_anchors: dict[str, Any] = {}
    for heldout in TARGETS:
        row = cached_candidate_truth_ranks(bundle, heldout, None)
        prospective[heldout] = row["candidate_true_ranks"]
        cache_anchors[f"loo_{heldout:02d}"] = anchor(training_rank_path(heldout, None))
    folds = []
    nested_ranks = []
    winner_frequency: dict[str, int] = {}
    for outer in TARGETS:
        validations = [target for target in TARGETS if target != outer]
        inner = np.empty((len(validations), CANDIDATE_COUNT), dtype=np.int64)
        for row_index, validation in enumerate(validations):
            row = cached_candidate_truth_ranks(bundle, validation, outer)
            inner[row_index] = row["candidate_true_ranks"]
            cache_anchors[f"nested_{outer:02d}_{validation:02d}"] = anchor(
                training_rank_path(validation, outer)
            )
        winner = select_candidate(candidates, inner)
        rank = int(prospective[outer, winner])
        nested_ranks.append(rank)
        winner_frequency[str(winner)] = winner_frequency.get(str(winner), 0) + 1
        folds.append(
            {
                "outer_heldout_target": outer,
                "inner_validation_targets": validations,
                "selected_candidate_index": winner,
                "selected_candidate": candidates[winner],
                "outer_heldout_rank": rank,
            }
        )
    fullfit_index = select_candidate(candidates, prospective)
    fullfit_candidate = candidates[fullfit_index]
    representations = bundle["representations"]
    true_cells = bundle["true_cells"]
    prototypes = np.stack(
        [
            representations[index][fullfit_candidate["representation"]][int(true_cells[index])]
            for index in TARGETS
        ]
    )
    frozen_model = fit_frozen_model(prototypes, fullfit_candidate)
    a410 = json.loads(A410_RESULT.read_bytes())
    a410_ranks = [int(value) for value in a410["nested_evaluation"]["nested_panel"]["ranks"]]
    nested_panel = metric_panel(nested_ranks)
    baseline_panel = metric_panel(a410_ranks)
    comparison = {
        "A413_nested_panel": nested_panel,
        "A410_nested_panel": baseline_panel,
        "geometric_rank_improvement_factor": baseline_panel["geometric_mean_rank"]
        / nested_panel["geometric_mean_rank"],
        "additional_bit_gain": nested_panel["bit_gain_vs_complete_4096_cover"]
        - baseline_panel["bit_gain_vs_complete_4096_cover"],
        "A413_better_folds": sum(
            left < right for left, right in zip(nested_ranks, a410_ranks, strict=True)
        ),
        "A413_equal_folds": sum(
            left == right for left, right in zip(nested_ranks, a410_ranks, strict=True)
        ),
        "A413_worse_folds": sum(
            left > right for left, right in zip(nested_ranks, a410_ranks, strict=True)
        ),
    }
    payload: dict[str, Any] = {
        "schema": "chacha20-round20-w50-knownkey-kernel-density-reader-a413-model-v1",
        "attempt_id": ATTEMPT_ID,
        "model_state": "fixed_from_A401_before_any_A412_label_or_reader_score",
        "design_sha256": DESIGN_SHA256,
        "implementation_sha256": expected_implementation_sha256,
        "implementation_commitment_sha256": implementation[
            "implementation_commitment_sha256"
        ],
        "candidate_family_commitment_sha256": implementation[
            "candidate_family_commitment_sha256"
        ],
        "nested_diagnostic": {
            "folds": folds,
            "nested_winner_frequency": winner_frequency,
            "comparison_to_A410": comparison,
        },
        "fullfit_candidate_index": fullfit_index,
        "fullfit_candidate": fullfit_candidate,
        "fullfit_leaveoneout_panel": metric_panel(prospective[:, fullfit_index].tolist()),
        "prospective_candidate_rank_table_int32le_sha256": sha256(
            prospective.astype("<i4").tobytes()
        ),
        "frozen_model": frozen_model,
        "knownkey_field_commitments": bundle["field_commitments"],
        "knownkey_prototype_commitments": bundle["prototype_commitments"],
        "training_rank_cache_anchors": cache_anchors,
        "A412_target_labels_used": 0,
        "A412_reader_scores_used": 0,
        "live_recovery_progress_filter_outcomes_or_results_consumed": False,
        "anchors": {
            "design": anchor(DESIGN, DESIGN_SHA256),
            "implementation": anchor(IMPLEMENTATION, expected_implementation_sha256),
            "A401_result": anchor(A401_RESULT, A401_RESULT_SHA256),
            "A404_result": anchor(A404_RESULT, A404_RESULT_SHA256),
            "A410_result": anchor(A410_RESULT, A410_RESULT_SHA256),
            "A412_protocol": anchor(A412_PROTOCOL, A412_PROTOCOL_SHA256),
            "runner": anchor(Path(__file__)),
        },
    }
    payload["model_commitment_sha256"] = canonical_sha256(payload)
    atomic_json(MODEL, payload)
    return payload


def load_model(expected_sha256: str | None = None) -> dict[str, Any]:
    if expected_sha256 is not None and file_sha256(MODEL) != expected_sha256:
        raise RuntimeError("A413 model hash differs")
    value = json.loads(MODEL.read_bytes())
    if (
        value.get("schema") != "chacha20-round20-w50-knownkey-kernel-density-reader-a413-model-v1"
        or value.get("attempt_id") != ATTEMPT_ID
        or value.get("model_state") != "fixed_from_A401_before_any_A412_label_or_reader_score"
        or value.get("fullfit_candidate") not in candidate_rows()
        or value.get("A412_target_labels_used") != 0
        or value.get("A412_reader_scores_used") != 0
    ):
        raise RuntimeError("A413 model semantics differ")
    load_implementation(value["implementation_sha256"])
    unsigned = {key: item for key, item in value.items() if key != "model_commitment_sha256"}
    if value.get("model_commitment_sha256") != canonical_sha256(unsigned):
        raise RuntimeError("A413 model commitment differs")
    return value


def build_causal(payload: Mapping[str, Any]) -> dict[str, Any]:
    sys.path.insert(0, str(DOTCAUSAL_SRC))
    from dotcausal.io import CausalReader, CausalWriter

    qualified = bool(payload["external_transfer"]["qualified"])
    terminal = (
        "A413_external_transfer_qualified_production_order"
        if qualified
        else "A413_external_transfer_boundary_retained"
    )
    writer = CausalWriter(api_id="a413w50")
    writer._rules = []
    writer.add_rule(
        name="knownkey_geometry_to_fixed_density_reader",
        description="Sixteen A401 positives select and freeze one of 155 density or location-shape Readers without any A412 label.",
        pattern=["A401_knownkey_positive_geometry", "A413_frozen_155_reader_family"],
        conclusion="A413_fixed_density_reader",
        confidence_modifier=1.0,
    )
    writer.add_rule(
        name="fixed_reader_to_external_transfer_panel",
        description="The fixed Reader scores thirty-two complete A412 fields before their labels are used for any model choice or refit.",
        pattern=["A413_fixed_density_reader", "A412_thirtytwo_fresh_complete_fields"],
        conclusion="A413_external_transfer_panel",
        confidence_modifier=1.0,
    )
    writer.add_rule(
        name="external_panel_to_production_boundary",
        description="Only strict improvement over the better frozen A404/A410 baseline permits zero-refit A388 deployment.",
        pattern=["A413_external_transfer_panel", "strict_better_singleton_gate"],
        conclusion=terminal,
        confidence_modifier=1.0,
    )
    writer.add_triplet(
        trigger="A401:sixteen_knownkey_positive_geometries",
        mechanism="nested_selection_of_frozen_density_or_location_shape_reader",
        outcome="A413:fixed_A401_only_model",
        confidence=1.0,
        source=payload["model_sha256"],
        quantification=json.dumps(payload["model_summary"], sort_keys=True),
        evidence="A413 model artifact records zero A412 target labels and zero A412 Reader scores",
        domain="full-round ChaCha20 W50 known-key Reader learning",
        quality_score=1.0,
    )
    writer.add_triplet(
        trigger="A413:fixed_A401_only_model",
        mechanism="unchanged_scoring_of_thirtytwo_fresh_complete_A412_fields",
        outcome=f"A413:{terminal}",
        confidence=1.0,
        source=payload["external_measurement_sha256"],
        quantification=json.dumps(payload["external_transfer"], sort_keys=True),
        evidence="thirty-two fresh labels are evaluation-only after model freeze",
        domain="independent same-width external transfer",
        quality_score=1.0,
    )
    writer.add_triplet(
        trigger="A401:sixteen_knownkey_positive_geometries",
        mechanism="materialized_fixed_model_external_panel_closure",
        outcome=f"A413:{terminal}",
        confidence=1.0,
        source="materialized:A413_density_transfer_chain",
        quantification="exact retained closure",
        evidence="design, implementation, model and external-panel commitments",
        domain="AI-native retained inference",
        quality_score=1.0,
        is_inferred=True,
    )
    writer.add_cluster(
        name="A413 external W50 density Reader transfer",
        entities=[
            "A401:sixteen_knownkey_positive_geometries",
            "A413:fixed_A401_only_model",
            f"A413:{terminal}",
        ],
    )
    writer.add_gap(
        subject=f"A413:{terminal}",
        predicate="next_required_object",
        expected_object_type=(
            "complete_group_recovery_in_A413_production_order"
            if qualified
            else "polyphase_or_conditional_geometry_reader"
        ),
        confidence=1.0,
        suggested_queries=[
            "Execute the exact A413 production order with matched control."
            if qualified
            else "Freeze a polyphase conditional Reader before reusing the same external fields."
        ],
    )
    temporary = CAUSAL.with_name(f".{CAUSAL.name}.tmp")
    temporary.unlink(missing_ok=True)
    stats = writer.save(str(temporary))
    os.replace(temporary, CAUSAL)
    reader = CausalReader(str(CAUSAL), verify_integrity=True)
    explicit = reader.get_all_triplets(include_inferred=False)
    all_rows = reader.get_all_triplets(include_inferred=True)
    inferred = [row for row in reader._triplets if row.get("is_inferred", False)]
    if (
        reader.api_id != "a413w50"
        or len(explicit) != 2
        or len(all_rows) != 3
        or len(inferred) != 1
        or len(reader._rules) != 3
        or len(reader._clusters) != 1
        or len(reader._gaps) != 1
    ):
        raise RuntimeError("A413 authentic Causal reopen gate failed")
    return {
        "format": "authentic_dotcausal_v1_AI_native",
        "path": relative(CAUSAL),
        "sha256": file_sha256(CAUSAL),
        "api_id": reader.api_id,
        "explicit_triplets": len(explicit),
        "materialized_inferred_triplets": len(inferred),
        "embedded_rules": len(reader._rules),
        "clusters": len(reader._clusters),
        "gaps": len(reader._gaps),
        "reader_source": anchor(Path(inspect.getsourcefile(CausalReader) or "")),
        "writer_stats": stats,
        "personal_semantic_readback": {
            "model": explicit[0],
            "external_transfer": explicit[1],
            "terminal_chain": all_rows[-1],
            "next_gap": reader._gaps[0],
        },
    }


def evaluate_external(
    *, expected_implementation_sha256: str, expected_model_sha256: str
) -> dict[str, Any]:
    if RESULT.exists() or CAUSAL.exists() or REPORT.exists():
        raise FileExistsError("A413 external result already exists")
    implementation = load_implementation(expected_implementation_sha256)
    model = load_model(expected_model_sha256)
    protocol = A412.load_protocol(A412_PROTOCOL_SHA256)
    for target in FRESH_TARGETS:
        A412.load_fresh_complete(target, protocol)
    selection_labels = A412.load_label(
        A412.SELECTION_LABELS,
        "chacha20-round20-w50-fresh-hybrid-reader-a412-selection-labels-v1",
        A412.SELECTION_TARGETS,
    )
    holdout_labels = A412.load_label(
        A412.HOLDOUT_LABELS,
        "chacha20-round20-w50-fresh-hybrid-reader-a412-holdout-labels-v1",
        A412.HOLDOUT_TARGETS,
    )
    labels = {**selection_labels, **holdout_labels}
    source = A412.source_bundle()
    frozen = model["frozen_model"]
    representation = str(model["fullfit_candidate"]["representation"])
    a413_ranks = []
    a404_ranks = []
    a410_ranks = []
    field_commitments: dict[str, Any] = {}
    reader_commitments: dict[str, Any] = {}
    for target in FRESH_TARGETS:
        rank_matrix, field_commitments[str(target)] = A412.fresh_rank_matrix(target)
        left_order, right_order, metadata = A412.reader_orders(rank_matrix, source)
        field = A410.representation_matrices(rank_matrix)[representation]
        scores = score_frozen_model(field, frozen)
        order = exact_score_order(scores)
        cell = int(labels[target]["true_direct12_cell"])
        a413_ranks.append(int(A401.rank_vector(order)[cell]))
        a404_ranks.append(int(A401.rank_vector(left_order)[cell]))
        a410_ranks.append(int(A401.rank_vector(right_order)[cell]))
        metadata.update(
            {
                "A413_score_float64le_sha256": sha256(scores.astype("<f8").tobytes()),
                "A413_order_uint16be_sha256": A401.A400_uint16_sha(order),
            }
        )
        reader_commitments[str(target)] = metadata
    a413_panel = metric_panel(a413_ranks)
    a404_panel = metric_panel(a404_ranks)
    a410_panel = metric_panel(a410_ranks)
    baseline_name, baseline_panel = min(
        (("A404", a404_panel), ("A410", a410_panel)),
        key=lambda item: (item[1]["mean_log2_rank"], item[0]),
    )
    factor = baseline_panel["geometric_mean_rank"] / a413_panel["geometric_mean_rank"]
    gain = (
        a413_panel["bit_gain_vs_complete_4096_cover"]
        - baseline_panel["bit_gain_vs_complete_4096_cover"]
    )
    qualified = factor > 1.0 and gain > 0.0
    external = {
        "qualified": qualified,
        "best_frozen_singleton": baseline_name,
        "A413_panel": a413_panel,
        "A404_panel": a404_panel,
        "A410_panel": a410_panel,
        "selection_half_A413_panel": metric_panel(a413_ranks[:16]),
        "holdout_half_A413_panel": metric_panel(a413_ranks[16:]),
        "geometric_rank_improvement_factor": factor,
        "additional_bit_gain": gain,
        "A413_better_targets": sum(
            left < right for left, right in zip(a413_ranks, baseline_panel["ranks"], strict=True)
        ),
        "A413_equal_targets": sum(
            left == right for left, right in zip(a413_ranks, baseline_panel["ranks"], strict=True)
        ),
        "A413_worse_targets": sum(
            left > right for left, right in zip(a413_ranks, baseline_panel["ranks"], strict=True)
        ),
    }
    production_order = None
    production_metadata = None
    production_diversity = None
    if qualified:
        with A412.a401_paths(A412.ORIGINAL_A401_ARTIFACTS, A412.ORIGINAL_A401_MEASUREMENTS):
            production_ranks, view_orders, production_metadata = A402.production_rank_matrix()
        left_order, right_order, source_metadata = A412.reader_orders(production_ranks, source)
        production_field = A410.representation_matrices(production_ranks)[representation]
        production_scores = score_frozen_model(production_field, frozen)
        production_order = exact_score_order(production_scores)
        production_metadata = {
            **production_metadata,
            **source_metadata,
            "A413_score_float64le_sha256": sha256(production_scores.astype("<f8").tobytes()),
        }
        production_diversity = {
            "A404": A401.A388.A351.diversity_panel(production_order, left_order),
            "A410": A401.A388.A351.diversity_panel(production_order, right_order),
            **{
                name: A401.A388.A351.diversity_panel(production_order, view_orders[name])
                for name in A401.VIEW_NAMES
            },
        }
    payload: dict[str, Any] = {
        "schema": "chacha20-round20-w50-knownkey-kernel-density-reader-a413-result-v1",
        "attempt_id": ATTEMPT_ID,
        "evidence_stage": (
            "THIRTYTWO_FRESH_KEY_EXTERNAL_TRANSFER_QUALIFIED_A413_APPLIED_ZERO_REFIT_TO_A388"
            if qualified
            else "THIRTYTWO_FRESH_KEY_EXTERNAL_TRANSFER_BOUNDARY_RETAINED"
        ),
        "design_sha256": DESIGN_SHA256,
        "implementation_sha256": expected_implementation_sha256,
        "implementation_commitment_sha256": implementation[
            "implementation_commitment_sha256"
        ],
        "model_sha256": expected_model_sha256,
        "model_commitment_sha256": model["model_commitment_sha256"],
        "model_summary": {
            "fullfit_candidate_index": model["fullfit_candidate_index"],
            "fullfit_candidate": model["fullfit_candidate"],
            "parameter_float64le_sha256": frozen["parameter_float64le_sha256"],
        },
        "external_transfer": external,
        "production_order": production_order,
        "production_order_uint16be_sha256": (
            A401.A400_uint16_sha(production_order) if production_order is not None else None
        ),
        "production_view_metadata": production_metadata,
        "production_operator_diversity": production_diversity,
        "fresh_field_commitments": field_commitments,
        "fresh_reader_commitments": reader_commitments,
        "complete_external_targets": len(FRESH_TARGETS),
        "external_target_labels_used_for_model_selection": 0,
        "external_reader_refits": 0,
        "new_solver_stages": 0,
        "production_target_labels_used": 0,
        "production_reader_refits": 0,
        "production_candidate_assignments_executed": 0,
        "live_recovery_progress_filter_outcomes_or_results_consumed": False,
        "anchors": {
            "design": anchor(DESIGN, DESIGN_SHA256),
            "implementation": anchor(IMPLEMENTATION, expected_implementation_sha256),
            "model": anchor(MODEL, expected_model_sha256),
            "A404_result": anchor(A404_RESULT, A404_RESULT_SHA256),
            "A410_result": anchor(A410_RESULT, A410_RESULT_SHA256),
            "A412_protocol": anchor(A412_PROTOCOL, A412_PROTOCOL_SHA256),
            "A388_order": anchor(A388_ORDER, A388_ORDER_SHA256),
            "runner": anchor(Path(__file__)),
        },
    }
    payload["external_measurement_sha256"] = canonical_sha256(
        {
            "external_transfer": external,
            "fresh_field_commitments": field_commitments,
            "fresh_reader_commitments": reader_commitments,
        }
    )
    payload["deployment_commitment_sha256"] = canonical_sha256(
        {
            "model_summary": payload["model_summary"],
            "external_transfer": external,
            "production_order": production_order,
            "production_view_metadata": production_metadata,
        }
    )
    payload["causal"] = build_causal(payload)
    atomic_json(RESULT, payload)
    atomic_bytes(
        REPORT,
        (
            "# A413 — Fixed density Reader on 32 fresh W50 fields\n\n"
            f"Evidence stage: **{payload['evidence_stage']}**\n\n"
            f"- Frozen model: **{model['fullfit_candidate']}**\n"
            f"- A413 ranks: **{a413_panel['ranks']}**\n"
            f"- A404 ranks: **{a404_panel['ranks']}**\n"
            f"- A410 ranks: **{a410_panel['ranks']}**\n"
            f"- Improvement factor: **{factor:.9f}**\n"
            f"- Additional bit gain: **{gain:.9f}**\n"
            "- External model choices / refits / new solver stages: **0 / 0 / 0**\n"
            "- Authentic AI-native Causal readback: **2 explicit + 1 inferred chain**\n"
        ).encode(),
    )
    return payload


def analyze() -> dict[str, Any]:
    payload: dict[str, Any] = {
        "attempt_id": ATTEMPT_ID,
        "design_sha256": DESIGN_SHA256,
        "implementation_frozen": IMPLEMENTATION.exists(),
        "model_frozen": MODEL.exists(),
        "training_progress_exists": TRAIN_PROGRESS.exists(),
        "result_complete": RESULT.exists(),
    }
    if IMPLEMENTATION.exists():
        payload["implementation_sha256"] = file_sha256(IMPLEMENTATION)
    if TRAIN_PROGRESS.exists():
        progress = json.loads(TRAIN_PROGRESS.read_bytes())
        payload["completed_training_rank_panels"] = progress[
            "completed_training_rank_panels"
        ]
        payload["required_training_rank_panels"] = progress[
            "required_training_rank_panels"
        ]
    if MODEL.exists():
        model = load_model()
        payload["model_sha256"] = file_sha256(MODEL)
        payload["fullfit_candidate"] = model["fullfit_candidate"]
        payload["nested_comparison"] = model["nested_diagnostic"]["comparison_to_A410"]
    if RESULT.exists():
        result = json.loads(RESULT.read_bytes())
        payload["result_sha256"] = file_sha256(RESULT)
        payload["evidence_stage"] = result["evidence_stage"]
        payload["external_transfer"] = result["external_transfer"]
    return payload


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    action = parser.add_mutually_exclusive_group(required=True)
    action.add_argument("--analyze", action="store_true")
    action.add_argument("--freeze-implementation", action="store_true")
    action.add_argument("--freeze-model", action="store_true")
    action.add_argument("--evaluate-external", action="store_true")
    parser.add_argument("--expected-implementation-sha256")
    parser.add_argument("--expected-model-sha256")
    args = parser.parse_args()
    if args.freeze_implementation:
        payload = freeze_implementation()
    elif args.freeze_model:
        if not args.expected_implementation_sha256:
            parser.error("--freeze-model requires --expected-implementation-sha256")
        payload = freeze_model(
            expected_implementation_sha256=args.expected_implementation_sha256
        )
    elif args.evaluate_external:
        if not args.expected_implementation_sha256 or not args.expected_model_sha256:
            parser.error("--evaluate-external requires implementation and model SHA-256")
        payload = evaluate_external(
            expected_implementation_sha256=args.expected_implementation_sha256,
            expected_model_sha256=args.expected_model_sha256,
        )
    else:
        payload = analyze()
    print(json.dumps(payload, indent=2, sort_keys=True), flush=True)


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""A415: polarity-complete XOR-landscape Reader portfolio for ChaCha20 W50."""

from __future__ import annotations

import argparse
import importlib.util
import inspect
import json
import math
import os
import sys
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

import numpy as np

ROOT = Path(__file__).parents[2]
RESEARCH = ROOT / "research"
CONFIGS = RESEARCH / "configs"
RESULTS = RESEARCH / "results/v1"

DESIGN = CONFIGS / "chacha20_round20_w50_xor_landscape_portfolio_a415_design_v1.json"
TRAINING = RESULTS / "chacha20_round20_w50_xor_landscape_portfolio_a415_training_v1.json"
IMPLEMENTATION = (
    CONFIGS / "chacha20_round20_w50_xor_landscape_portfolio_a415_implementation_v1.json"
)
MODEL = CONFIGS / "chacha20_round20_w50_xor_landscape_portfolio_a415_model_v1.json"
RESULT = RESULTS / "chacha20_round20_w50_xor_landscape_portfolio_a415_v1.json"
CAUSAL = RESULT.with_suffix(".causal")
REPORT = RESULT.with_suffix(".md")
TEST = ROOT / "tests/test_chacha20_round20_w50_xor_landscape_portfolio_a415.py"
REPRO = ROOT / "scripts/reproduce_chacha20_round20_w50_xor_landscape_portfolio_a415.sh"

A414_RUNNER = RESEARCH / "experiments/chacha20_round20_w50_knownkey_parallel_portfolio_a414.py"
A414_IMPLEMENTATION = (
    CONFIGS / "chacha20_round20_w50_knownkey_parallel_portfolio_a414_implementation_v1.json"
)
A414_MODEL = CONFIGS / "chacha20_round20_w50_knownkey_parallel_portfolio_a414_model_v1.json"
A413_RUNNER = RESEARCH / "experiments/chacha20_round20_w50_knownkey_kernel_density_reader_a413.py"
A413_IMPLEMENTATION = (
    CONFIGS / "chacha20_round20_w50_knownkey_kernel_density_reader_a413_implementation_v1.json"
)
A413_MODEL = CONFIGS / "chacha20_round20_w50_knownkey_kernel_density_reader_a413_model_v1.json"
A412_RUNNER = RESEARCH / "experiments/chacha20_round20_w50_fresh_hybrid_reader_a412.py"
A412_IMPLEMENTATION = (
    CONFIGS / "chacha20_round20_w50_fresh_hybrid_reader_a412_implementation_v1.json"
)
A412_PROTOCOL = CONFIGS / "chacha20_round20_w50_fresh_hybrid_reader_a412_public_corpus_v1.json"
A388_ORDER = RESULTS / "chacha20_round20_w50_public_output_direct12_factor3_a388_order_v1.json"

ATTEMPT_ID = "A415"
DESIGN_SHA256 = "5b04e9eeac29efad0bff2596cc870f7382003be64b7cdddc281ce1b88247a09b"
A414_RUNNER_SHA256 = "3c0eac31a79141b3c9c39c4c249d7c0a681576bfe652940d9a5151b45b7e9f23"
A414_IMPLEMENTATION_SHA256 = "a6f30f5f025de34e05b52f61966d2363dc386ec0402a6dd6cf9d6fe58506ddd1"
A414_MODEL_SHA256 = "1e65ef99e4a49861ffcfe5e6f30ec3018516e7d91bbdb2a2539980efcaba6f0b"
A413_RUNNER_SHA256 = "e8f939d84cf53364bbbb4c729c1e9fa7fd5dce2742cd24fcc6e3e6a559c804d4"
A413_IMPLEMENTATION_SHA256 = "715aa6660bff6f3c6b3b3336cc3b755581c528898ca75defb6cbe8fea539e693"
A413_MODEL_SHA256 = "71141bdac6a3f4bea95980e21777eb00a774ecde88a29028c441453dc62b7cf8"
A412_RUNNER_SHA256 = "cc8813f29f29aed8f28b682c959d7655437faa7c5e9c713cbe9e2183e8641b96"
A412_IMPLEMENTATION_SHA256 = "f08665ec5f0b79bf96f33617d10966e59895e6adfb284c5b6c70e5fc47527067"
A412_PROTOCOL_SHA256 = "f7859b381d5cf6a5f1a765b4abb44192d3bd73539c681a9a40d8c0a48dd365a2"
A388_ORDER_SHA256 = "3c56ce8521b1ced20e1e3a90999810c2e563c4de941701c86274f0828b5d01b8"

CELLS = 4096
WORKERS = 8
OPTIMAL_EPOCHS = 512
REPRESENTATION = "reciprocal_sqrt8"
POSITIVE_INDEX = 155
NEGATIVE_INDEX = 156
SELECTED_INDICES = (156, 123, 20, 155, 153, 100, 49, 5)
SOURCE_ROLES = (
    "xor_negative",
    "A413_candidate_123",
    "A413_candidate_020",
    "xor_positive",
    "A413_candidate_153",
    "A413_candidate_100",
    "A413_candidate_049",
    "A413_candidate_005",
)
EXPECTED_POSITIVE_RANKS = (
    3631, 3051, 4086, 210, 2318, 163, 2316, 1692,
    3667, 4095, 2814, 3692, 1584, 2161, 804, 607,
)
EXPECTED_NEGATIVE_RANKS = (
    466, 1046, 11, 3887, 1779, 3934, 1781, 2405,
    430, 2, 1283, 405, 2513, 1936, 3293, 3490,
)
EXPECTED_PORTFOLIO_RANKS = (
    466, 66, 11, 210, 122, 163, 935, 1692,
    10, 2, 1283, 405, 3, 402, 101, 607,
)
EXPECTED_PORTFOLIO_GM = 119.44814036295723
DOTCAUSAL_SRC = Path("/Users/bhkmie/Documents/Forschung/O1/vendor/fabel/dotcausal_package/src")


def load_module(path: Path, name: str) -> Any:
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot import A415 dependency {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


A414 = load_module(A414_RUNNER, "a415_a414")
A413 = A414.A413
A412 = A414.A412
A410 = A414.A410
A401 = A414.A401
A402 = A414.A402

file_sha256 = A414.file_sha256
canonical_sha256 = A414.canonical_sha256
atomic_json = A414.atomic_json
atomic_bytes = A414.atomic_bytes
relative = A414.relative
anchor = A414.anchor
sha256 = A414.sha256
metric_panel = A414.metric_panel
exact_order = A414.exact_order
uint16be_sha256 = A414.uint16be_sha256


def load_design() -> dict[str, Any]:
    if file_sha256(DESIGN) != DESIGN_SHA256:
        raise RuntimeError("A415 design hash differs")
    value = json.loads(DESIGN.read_bytes())
    training = value.get("training_discovery_panel", {})
    boundary = value.get("information_boundary", {})
    if (
        value.get("schema") != "chacha20-round20-w50-xor-landscape-portfolio-a415-design-v1"
        or value.get("attempt_id") != ATTEMPT_ID
        or tuple(training.get("selected_canonical_indices", [])) != SELECTED_INDICES
        or tuple(training.get("selected_roles", [])) != SOURCE_ROLES
        or tuple(training.get("selected_pointwise_minimum_ranks", []))
        != EXPECTED_PORTFOLIO_RANKS
        or boundary.get("A412_measurement_fields_or_reader_scores_consumed") is not False
        or boundary.get("A412_holdout_label_ledger_opened") is not False
    ):
        raise RuntimeError("A415 frozen design semantics differ")
    for key, path in value["source_anchors"].items():
        if key.endswith("_path"):
            stem = key.removesuffix("_path")
            anchor(ROOT / path, value["source_anchors"][f"{stem}_sha256"])
    return value


def standardize_landscape(rank_matrix: np.ndarray) -> np.ndarray:
    representations = A410.representation_matrices(np.asarray(rank_matrix, dtype=np.int64))
    field = np.asarray(representations[REPRESENTATION], dtype=np.float64)
    if field.shape != (CELLS, 8) or not np.isfinite(field).all():
        raise ValueError("A415 reciprocal-sqrt landscape shape differs")
    mean = field.mean(axis=0, keepdims=True)
    scale = field.std(axis=0, keepdims=True)
    if np.any(scale <= 0.0) or not np.isfinite(scale).all():
        raise RuntimeError("A415 landscape channel scale differs")
    standardized = (field - mean) / scale
    if not np.isfinite(standardized).all():
        raise RuntimeError("A415 standardized landscape differs")
    return standardized


def fwht(matrix: np.ndarray) -> np.ndarray:
    values = np.asarray(matrix, dtype=np.float64)
    if values.ndim == 1:
        values = values[:, None]
    if values.ndim != 2 or values.shape[0] < 1 or values.shape[0] & (values.shape[0] - 1):
        raise ValueError("A415 FWHT requires a power-of-two leading dimension")
    transformed = values.copy()
    size = transformed.shape[0]
    width = 1
    while width < size:
        blocks = transformed.reshape(-1, 2 * width, transformed.shape[1])
        left = blocks[:, :width, :].copy()
        right = blocks[:, width:, :].copy()
        blocks[:, :width, :] = left + right
        blocks[:, width:, :] = left - right
        width *= 2
    return transformed


def xor_correlation_scores(field: np.ndarray, template: np.ndarray) -> np.ndarray:
    observed = np.asarray(field, dtype=np.float64)
    reference = np.asarray(template, dtype=np.float64)
    if observed.shape != (CELLS, 8) or reference.shape != observed.shape:
        raise ValueError("A415 XOR correlation shapes differ")
    channel_norms = np.sqrt(np.sum(np.square(reference), axis=0))
    if np.any(channel_norms <= 0.0) or not np.isfinite(channel_norms).all():
        raise RuntimeError("A415 template channel norm differs")
    correlations = fwht(fwht(reference) * fwht(observed)) / float(CELLS)
    scores = np.sum(correlations / channel_norms, axis=1)
    if scores.shape != (CELLS,) or not np.isfinite(scores).all():
        raise RuntimeError("A415 XOR score field differs")
    return scores


def polarity_orders(scores: np.ndarray) -> tuple[list[int], list[int]]:
    values = np.asarray(scores, dtype=np.float64)
    if values.shape != (CELLS,) or not np.isfinite(values).all():
        raise ValueError("A415 polarity score field differs")
    cells = np.arange(CELLS, dtype=np.int64)
    positive = exact_order(np.lexsort((cells, -values)).tolist())
    negative = exact_order(np.lexsort((cells, values)).tolist())
    return positive, negative


def load_base_rank_matrix() -> np.ndarray:
    return A414.load_leaveoneout_rank_matrix()


def greedy_portfolio(combined: np.ndarray) -> dict[str, Any]:
    matrix = np.asarray(combined, dtype=np.int64)
    if matrix.shape != (16, 157) or np.any(matrix < 1) or np.any(matrix > CELLS):
        raise ValueError("A415 combined rank matrix differs")
    selected: list[int] = []
    current: np.ndarray | None = None
    steps = []
    for step in range(WORKERS):
        choices = []
        for candidate in range(matrix.shape[1]):
            if candidate in selected:
                continue
            panel = matrix[:, candidate] if current is None else np.minimum(
                current, matrix[:, candidate]
            )
            mean_log = float(np.log2(panel.astype(np.float64)).mean())
            choices.append((mean_log, int(panel.max()), candidate, panel))
        mean_log, worst, winner, panel = min(choices, key=lambda row: row[:3])
        selected.append(winner)
        current = panel.copy()
        steps.append(
            {
                "step": step,
                "selected_canonical_index": winner,
                "geometric_mean_parallel_rank": 2.0**mean_log,
                "worst_parallel_rank": worst,
                "pointwise_minimum_ranks": panel.tolist(),
            }
        )
    if (
        tuple(selected) != SELECTED_INDICES
        or tuple(int(value) for value in current) != EXPECTED_PORTFOLIO_RANKS
        or not math.isclose(
            2.0 ** float(np.log2(current.astype(np.float64)).mean()),
            EXPECTED_PORTFOLIO_GM,
        )
    ):
        raise RuntimeError("A415 frozen greedy portfolio differs")
    return {
        "selected_canonical_indices": selected,
        "selected_roles": list(SOURCE_ROLES),
        "steps": steps,
        "pointwise_minimum_panel": metric_panel(current.tolist()),
        "combined_rank_matrix_int32le_sha256": sha256(matrix.astype("<i4").tobytes()),
    }


def materialize_training() -> dict[str, Any]:
    if any(path.exists() for path in (TRAINING, IMPLEMENTATION, MODEL, RESULT, CAUSAL, REPORT)):
        raise FileExistsError("A415 training or downstream artifact already exists")
    load_design()
    bundle = A413.training_bundle()
    targets = tuple(A413.TARGETS)
    true_cells = np.asarray([int(bundle["true_cells"][target]) for target in targets])
    cells = np.arange(CELLS, dtype=np.int64)
    fields = {
        target: standardize_landscape(
            A410.rank_matrix_from_representations(bundle["representations"][target])
            if hasattr(A410, "rank_matrix_from_representations")
            else _rank_matrix_from_log8(bundle["representations"][target]["log8"])
        )
        for target in targets
    }
    aligned = {
        target: fields[target][cells ^ int(true_cells[target])] for target in targets
    }
    total = np.sum([aligned[target] for target in targets], axis=0)
    positive_ranks = []
    negative_ranks = []
    score_commitments: dict[str, Any] = {}
    for heldout in targets:
        template = (total - aligned[heldout]) / float(len(targets) - 1)
        scores = xor_correlation_scores(fields[heldout], template)
        positive, negative = polarity_orders(scores)
        positive_rank_vector = A401.rank_vector(positive)
        negative_rank_vector = A401.rank_vector(negative)
        positive_ranks.append(int(positive_rank_vector[true_cells[heldout]]))
        negative_ranks.append(int(negative_rank_vector[true_cells[heldout]]))
        score_commitments[str(heldout)] = {
            "template_float64le_sha256": sha256(template.astype("<f8").tobytes()),
            "score_float64le_sha256": sha256(scores.astype("<f8").tobytes()),
            "positive_order_uint16be_sha256": uint16be_sha256(positive),
            "negative_order_uint16be_sha256": uint16be_sha256(negative),
        }
    if tuple(positive_ranks) != EXPECTED_POSITIVE_RANKS:
        raise RuntimeError("A415 positive LOO ranks differ")
    if tuple(negative_ranks) != EXPECTED_NEGATIVE_RANKS:
        raise RuntimeError("A415 negative LOO ranks differ")
    base = load_base_rank_matrix()
    combined = np.column_stack(
        [base, np.asarray(positive_ranks), np.asarray(negative_ranks)]
    )
    selection = greedy_portfolio(combined)
    fullfit_template = total / float(len(targets))
    candidates = A413.candidate_rows()
    a413_models = {}
    for candidate_index in SELECTED_INDICES:
        if candidate_index >= A413.CANDIDATE_COUNT:
            continue
        candidate = candidates[candidate_index]
        prototypes = np.stack(
            [
                bundle["representations"][target][candidate["representation"]][
                    int(true_cells[target])
                ]
                for target in targets
            ]
        )
        a413_models[str(candidate_index)] = A413.fit_frozen_model(prototypes, candidate)
    payload: dict[str, Any] = {
        "schema": "chacha20-round20-w50-xor-landscape-portfolio-a415-training-v1",
        "attempt_id": ATTEMPT_ID,
        "training_state": "A401_only_before_any_A412_measurement_field_or_reader_score",
        "design_sha256": DESIGN_SHA256,
        "positive_LOO_panel": metric_panel(positive_ranks),
        "negative_LOO_panel": metric_panel(negative_ranks),
        "two_polarity_parallel_panel": metric_panel(
            [min(left, right) for left, right in zip(positive_ranks, negative_ranks, strict=True)]
        ),
        "portfolio_selection": selection,
        "score_commitments": score_commitments,
        "fullfit_xor_template": fullfit_template.tolist(),
        "fullfit_xor_template_float64le_sha256": sha256(
            fullfit_template.astype("<f8").tobytes()
        ),
        "fullfit_xor_template_channel_norms": np.sqrt(
            np.sum(np.square(fullfit_template), axis=0)
        ).tolist(),
        "A413_frozen_models": a413_models,
        "knownkey_field_commitments": bundle["field_commitments"],
        "knownkey_prototype_commitments": bundle["prototype_commitments"],
        "A413_training_rank_cache_anchors": {
            str(target): anchor(A413.training_rank_path(target, None)) for target in targets
        },
        "A412_measurement_fields_used": 0,
        "A412_reader_scores_used": 0,
        "A412_holdout_labels_used": 0,
        "anchors": {
            "design": anchor(DESIGN, DESIGN_SHA256),
            "A413_runner": anchor(A413_RUNNER, A413_RUNNER_SHA256),
            "A413_model": anchor(A413_MODEL, A413_MODEL_SHA256),
            "A414_model": anchor(A414_MODEL, A414_MODEL_SHA256),
            "A412_protocol": anchor(A412_PROTOCOL, A412_PROTOCOL_SHA256),
            "runner": anchor(Path(__file__)),
        },
    }
    payload["training_commitment_sha256"] = canonical_sha256(payload)
    atomic_json(TRAINING, payload)
    return payload


def _rank_matrix_from_log8(log8: np.ndarray) -> np.ndarray:
    values = np.asarray(log8, dtype=np.float64)
    if values.shape != (CELLS, 8):
        raise ValueError("A415 log8 recovery shape differs")
    ranks = np.rint(np.exp2(values.T * 12.0)).astype(np.int64)
    if ranks.shape != (8, CELLS) or any(
        set(row.tolist()) != set(range(1, CELLS + 1)) for row in ranks
    ):
        raise RuntimeError("A415 log8 rank recovery differs")
    return ranks


def load_training(expected_sha256: str | None = None) -> dict[str, Any]:
    if expected_sha256 is not None and file_sha256(TRAINING) != expected_sha256:
        raise RuntimeError("A415 training hash differs")
    value = json.loads(TRAINING.read_bytes())
    if (
        value.get("schema") != "chacha20-round20-w50-xor-landscape-portfolio-a415-training-v1"
        or value.get("attempt_id") != ATTEMPT_ID
        or tuple(value.get("positive_LOO_panel", {}).get("ranks", []))
        != EXPECTED_POSITIVE_RANKS
        or tuple(value.get("negative_LOO_panel", {}).get("ranks", []))
        != EXPECTED_NEGATIVE_RANKS
        or tuple(
            value.get("portfolio_selection", {}).get("selected_canonical_indices", [])
        )
        != SELECTED_INDICES
        or value.get("A412_measurement_fields_used") != 0
        or value.get("A412_reader_scores_used") != 0
        or value.get("A412_holdout_labels_used") != 0
    ):
        raise RuntimeError("A415 training semantics differ")
    unsigned = {key: item for key, item in value.items() if key != "training_commitment_sha256"}
    if value.get("training_commitment_sha256") != canonical_sha256(unsigned):
        raise RuntimeError("A415 training commitment differs")
    return value


def freeze_implementation(*, expected_training_sha256: str) -> dict[str, Any]:
    if any(path.exists() for path in (IMPLEMENTATION, MODEL, RESULT, CAUSAL, REPORT)):
        raise FileExistsError("A415 implementation or downstream artifact already exists")
    load_design()
    training = load_training(expected_training_sha256)
    if not TEST.exists() or not REPRO.exists():
        raise FileNotFoundError("A415 test and reproducer must precede freeze")
    payload: dict[str, Any] = {
        "schema": "chacha20-round20-w50-xor-landscape-portfolio-a415-implementation-v1",
        "attempt_id": ATTEMPT_ID,
        "commitment_state": "frozen_after_A401_training_before_any_A412_field_or_reader_score",
        "design_sha256": DESIGN_SHA256,
        "training_sha256": expected_training_sha256,
        "training_commitment_sha256": training["training_commitment_sha256"],
        "selected_canonical_indices": list(SELECTED_INDICES),
        "A412_measurement_fields_used": 0,
        "A412_reader_scores_used": 0,
        "anchors": {
            "design": anchor(DESIGN, DESIGN_SHA256),
            "training": anchor(TRAINING, expected_training_sha256),
            "A413_runner": anchor(A413_RUNNER, A413_RUNNER_SHA256),
            "A413_implementation": anchor(A413_IMPLEMENTATION, A413_IMPLEMENTATION_SHA256),
            "A413_model": anchor(A413_MODEL, A413_MODEL_SHA256),
            "A414_runner": anchor(A414_RUNNER, A414_RUNNER_SHA256),
            "A414_implementation": anchor(A414_IMPLEMENTATION, A414_IMPLEMENTATION_SHA256),
            "A414_model": anchor(A414_MODEL, A414_MODEL_SHA256),
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
        raise RuntimeError("A415 implementation hash differs")
    value = json.loads(IMPLEMENTATION.read_bytes())
    if (
        value.get("schema")
        != "chacha20-round20-w50-xor-landscape-portfolio-a415-implementation-v1"
        or value.get("attempt_id") != ATTEMPT_ID
        or tuple(value.get("selected_canonical_indices", [])) != SELECTED_INDICES
        or value.get("A412_measurement_fields_used") != 0
        or value.get("A412_reader_scores_used") != 0
    ):
        raise RuntimeError("A415 implementation semantics differ")
    for row in value["anchors"].values():
        anchor(ROOT / row["path"], row["sha256"])
    unsigned = {
        key: item for key, item in value.items() if key != "implementation_commitment_sha256"
    }
    if value.get("implementation_commitment_sha256") != canonical_sha256(unsigned):
        raise RuntimeError("A415 implementation commitment differs")
    return value


def freeze_model(*, expected_implementation_sha256: str) -> dict[str, Any]:
    if any(path.exists() for path in (MODEL, RESULT, CAUSAL, REPORT)):
        raise FileExistsError("A415 model or downstream artifact already exists")
    implementation = load_implementation(expected_implementation_sha256)
    training = load_training(implementation["training_sha256"])
    payload: dict[str, Any] = {
        "schema": "chacha20-round20-w50-xor-landscape-portfolio-a415-model-v1",
        "attempt_id": ATTEMPT_ID,
        "model_state": "fixed_from_A401_before_any_A412_measurement_field_or_reader_score",
        "design_sha256": DESIGN_SHA256,
        "implementation_sha256": expected_implementation_sha256,
        "implementation_commitment_sha256": implementation[
            "implementation_commitment_sha256"
        ],
        "training_sha256": implementation["training_sha256"],
        "training_commitment_sha256": training["training_commitment_sha256"],
        "selected_canonical_indices": list(SELECTED_INDICES),
        "source_roles": list(SOURCE_ROLES),
        "portfolio_selection": training["portfolio_selection"],
        "xor_template": training["fullfit_xor_template"],
        "xor_template_float64le_sha256": training[
            "fullfit_xor_template_float64le_sha256"
        ],
        "xor_template_channel_norms": training["fullfit_xor_template_channel_norms"],
        "A413_frozen_models": training["A413_frozen_models"],
        "A412_measurement_fields_used": 0,
        "A412_reader_scores_used": 0,
        "A412_holdout_labels_used": 0,
        "target_specific_polarity_choices": 0,
        "anchors": {
            "design": anchor(DESIGN, DESIGN_SHA256),
            "implementation": anchor(IMPLEMENTATION, expected_implementation_sha256),
            "training": anchor(TRAINING, implementation["training_sha256"]),
            "A413_model": anchor(A413_MODEL, A413_MODEL_SHA256),
            "A414_model": anchor(A414_MODEL, A414_MODEL_SHA256),
            "A412_protocol": anchor(A412_PROTOCOL, A412_PROTOCOL_SHA256),
            "runner": anchor(Path(__file__)),
        },
    }
    payload["model_commitment_sha256"] = canonical_sha256(payload)
    atomic_json(MODEL, payload)
    return payload


def load_model(expected_sha256: str | None = None) -> dict[str, Any]:
    if expected_sha256 is not None and file_sha256(MODEL) != expected_sha256:
        raise RuntimeError("A415 model hash differs")
    value = json.loads(MODEL.read_bytes())
    if (
        value.get("schema") != "chacha20-round20-w50-xor-landscape-portfolio-a415-model-v1"
        or value.get("attempt_id") != ATTEMPT_ID
        or tuple(value.get("selected_canonical_indices", [])) != SELECTED_INDICES
        or tuple(value.get("source_roles", [])) != SOURCE_ROLES
        or value.get("A412_measurement_fields_used") != 0
        or value.get("A412_reader_scores_used") != 0
        or value.get("target_specific_polarity_choices") != 0
    ):
        raise RuntimeError("A415 model semantics differ")
    load_implementation(value["implementation_sha256"])
    template = np.asarray(value["xor_template"], dtype=np.float64)
    if (
        template.shape != (CELLS, 8)
        or sha256(template.astype("<f8").tobytes())
        != value["xor_template_float64le_sha256"]
    ):
        raise RuntimeError("A415 XOR template differs")
    unsigned = {key: item for key, item in value.items() if key != "model_commitment_sha256"}
    if value.get("model_commitment_sha256") != canonical_sha256(unsigned):
        raise RuntimeError("A415 model commitment differs")
    return value


def portfolio_orders(rank_matrix: np.ndarray, model: Mapping[str, Any]) -> dict[str, list[int]]:
    ranks = np.asarray(rank_matrix, dtype=np.int64)
    representations = A410.representation_matrices(ranks)
    field = standardize_landscape(ranks)
    template = np.asarray(model["xor_template"], dtype=np.float64)
    scores = xor_correlation_scores(field, template)
    positive, negative = polarity_orders(scores)
    orders: dict[str, list[int]] = {}
    for canonical_index, role in zip(SELECTED_INDICES, SOURCE_ROLES, strict=True):
        if canonical_index == POSITIVE_INDEX:
            orders[role] = positive
        elif canonical_index == NEGATIVE_INDEX:
            orders[role] = negative
        else:
            frozen = model["A413_frozen_models"][str(canonical_index)]
            representation = str(frozen["candidate"]["representation"])
            candidate_scores = A413.score_frozen_model(
                representations[representation], frozen
            )
            orders[role] = A413.exact_score_order(candidate_scores)
    if tuple(orders) != SOURCE_ROLES:
        raise RuntimeError("A415 portfolio order roles differ")
    return orders


def prove_schedule(
    owners: Mapping[str, Any], work: Mapping[str, Any], roles: Sequence[str]
) -> dict[str, Any]:
    role_order = tuple(roles)
    ranks = owners["source_ranks_one_based"]
    owner_depths = [int(value) for value in owners["owner_lane_depth_one_based"]]
    epochs = [int(value) for value in work["cell_epoch_one_based"]]
    maximum_depth_ratio = 0.0
    maximum_work_ratio = 0.0
    for cell in range(CELLS):
        best = min(int(ranks[role][cell]) for role in role_order)
        owner = owners["owner_role"][cell]
        owner_rank = int(ranks[owner][cell])
        owner_depth = owner_depths[cell]
        epoch = epochs[cell]
        total_work = min(WORKERS * epoch, CELLS)
        if owner_rank != best or epoch > owner_depth or owner_depth > best:
            raise RuntimeError("A415 minimum-rank depth theorem failed")
        if total_work > WORKERS * best:
            raise RuntimeError("A415 total-work theorem failed")
        maximum_depth_ratio = max(maximum_depth_ratio, epoch / best)
        maximum_work_ratio = max(maximum_work_ratio, total_work / (WORKERS * best))
    proof = {
        "cells_checked": CELLS,
        "complete_cover_cells": work["complete_cover_cells"],
        "duplicate_cells": work["duplicate_cells"],
        "uncovered_cells": work["uncovered_cells"],
        "owner_queue_order_preservation_violations": 0,
        "depth_bound": "D_A415(c) <= D_owner(c) <= min_i R_i(c)",
        "depth_bound_violations": 0,
        "maximum_depth_to_best_source_ratio": maximum_depth_ratio,
        "total_work_bound": "W_A415(c) <= 8*min_i R_i(c)",
        "total_work_bound_violations": 0,
        "maximum_total_work_to_bound_ratio": maximum_work_ratio,
        "makespan_epochs": work["epochs"],
        "theoretical_minimum_epochs": work["theoretical_minimum_epochs"],
        "makespan_optimal": work["epochs"] == work["theoretical_minimum_epochs"],
    }
    if (
        proof["complete_cover_cells"] != CELLS
        or proof["duplicate_cells"] != 0
        or proof["uncovered_cells"] != 0
        or proof["makespan_epochs"] != OPTIMAL_EPOCHS
        or proof["makespan_optimal"] is not True
    ):
        raise RuntimeError("A415 complete schedule proof failed")
    return proof


def build_causal(payload: Mapping[str, Any]) -> dict[str, Any]:
    sys.path.insert(0, str(DOTCAUSAL_SRC))
    from dotcausal.io import CausalReader, CausalWriter

    qualified = bool(payload["external_transfer"]["qualified"])
    terminal = (
        "A415_holdout_qualified_polarity_complete_scheduler"
        if qualified
        else "A415_external_boundary_retained_polarity_mechanism"
    )
    writer = CausalWriter(api_id="a415w50")
    writer._rules = []
    writer.add_rule(
        name="known_key_landscapes_to_polarity_complete_reader",
        description="XOR-align complete 4,096-cell A401 fields, correlate by FWHT, and retain both fixed global polarities.",
        pattern=["A401_known_key_landscapes", "FWHT_XOR_translation_reader"],
        conclusion="A415_fixed_positive_negative_landscape_readers",
        confidence_modifier=1.0,
    )
    writer.add_rule(
        name="landscape_and_point_readers_to_equal_worker_portfolio",
        description="Greedy A401-only selection combines both landscape polarities with six complementary A413 geometries.",
        pattern=["A415_fixed_positive_negative_landscape_readers", "A413_fixed_reader_family"],
        conclusion="A415_fixed_eight_reader_portfolio",
        confidence_modifier=1.0,
    )
    writer.add_rule(
        name="fixed_portfolio_to_external_scheduler",
        description="The fixed portfolio scores untouched A412 holdout fields and maps A388 into eight exact order-preserving worker lists.",
        pattern=["A415_fixed_eight_reader_portfolio", "A412_untouched_holdout_and_A388"],
        conclusion=terminal,
        confidence_modifier=1.0,
    )
    writer.add_triplet(
        trigger="A401:complete_known_key_reader_landscapes",
        mechanism="XOR_alignment_plus_FWHT_dual_polarity_readout",
        outcome="A415:fixed_polarity_complete_eight_reader_portfolio",
        confidence=1.0,
        source=payload["model_sha256"],
        quantification=json.dumps(payload["training_selection"], sort_keys=True),
        evidence="all model members and both polarity orders fixed before any A412 score",
        domain="full-round ChaCha20 W50 known-key landscape inference",
        quality_score=1.0,
    )
    writer.add_triplet(
        trigger="A415:fixed_polarity_complete_eight_reader_portfolio",
        mechanism="untouched_holdout_equal_worker_transfer_plus_exact_scheduler",
        outcome=f"A415:{terminal}",
        confidence=1.0,
        source=payload["external_measurement_sha256"],
        quantification=json.dumps(payload["external_transfer"], sort_keys=True),
        evidence="zero external model choices, refits, or target-specific polarity choices",
        domain="full-round ChaCha20 W50 parallel recovery scheduling",
        quality_score=1.0,
    )
    writer.add_triplet(
        trigger="A401:complete_known_key_reader_landscapes",
        mechanism="materialized_dual_polarity_external_scheduler_closure",
        outcome=f"A415:{terminal}",
        confidence=1.0,
        source="materialized:A415_landscape_scheduler_chain",
        quantification="exact retained closure",
        evidence="design, training, model, external panel, and scheduler commitments",
        domain="AI-native retained inference",
        quality_score=1.0,
        is_inferred=True,
    )
    writer.add_cluster(
        name="A415 polarity-complete full-landscape W50 scheduler",
        entities=[
            "A401:complete_known_key_reader_landscapes",
            "A415:fixed_polarity_complete_eight_reader_portfolio",
            f"A415:{terminal}",
        ],
    )
    writer.add_gap(
        subject=f"A415:{terminal}",
        predicate="next_required_object",
        expected_object_type=(
            "shared_stop_execution_of_eight_frozen_A415_worker_lists"
            if qualified
            else "polarity_predictor_or_sign_invariant_single_reader"
        ),
        confidence=1.0,
        suggested_queries=[
            "Execute the exact A415 worker lists with one shared confirmed stop."
            if qualified
            else "Learn a target-blind polarity invariant from A401 and A412 selection geometry."
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
        reader.api_id != "a415w50"
        or len(explicit) != 2
        or len(all_rows) != 3
        or len(inferred) != 1
        or len(reader._rules) != 3
        or len(reader._clusters) != 1
        or len(reader._gaps) != 1
    ):
        raise RuntimeError("A415 authentic Causal reopen gate failed")
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
            "mechanism": explicit[0],
            "external_scheduler": explicit[1],
            "terminal_chain": all_rows[-1],
            "next_gap": reader._gaps[0],
        },
    }


def evaluate_external(
    *, expected_implementation_sha256: str, expected_model_sha256: str
) -> dict[str, Any]:
    if RESULT.exists() or CAUSAL.exists() or REPORT.exists():
        raise FileExistsError("A415 result already exists")
    implementation = load_implementation(expected_implementation_sha256)
    model = load_model(expected_model_sha256)
    baseline_model = A414.load_portfolio(A414_MODEL_SHA256)
    protocol = A412.load_protocol(A412_PROTOCOL_SHA256)
    for target in range(32):
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
    learned_depths = []
    baseline_depths = []
    field_commitments: dict[str, Any] = {}
    reader_commitments: dict[str, Any] = {}
    for target in range(32):
        rank_matrix, field_commitments[str(target)] = A412.fresh_rank_matrix(target)
        cell = int(labels[target]["true_direct12_cell"])
        learned_orders = portfolio_orders(rank_matrix, model)
        baseline_orders = A414.portfolio_orders(rank_matrix, baseline_model)
        learned_ranks = {
            role: int(A401.rank_vector(order)[cell])
            for role, order in learned_orders.items()
        }
        baseline_ranks = {
            role: int(A401.rank_vector(order)[cell])
            for role, order in baseline_orders.items()
        }
        learned_depths.append(min(learned_ranks.values()))
        baseline_depths.append(min(baseline_ranks.values()))
        reader_commitments[str(target)] = {
            "A415_order_uint16be_sha256": {
                role: uint16be_sha256(order) for role, order in learned_orders.items()
            },
            "A415_true_ranks": learned_ranks,
            "A414_true_ranks": baseline_ranks,
        }
    learned_holdout = metric_panel(learned_depths[16:])
    baseline_holdout = metric_panel(baseline_depths[16:])
    factor = baseline_holdout["geometric_mean_rank"] / learned_holdout[
        "geometric_mean_rank"
    ]
    gain = (
        learned_holdout["bit_gain_vs_complete_4096_cover"]
        - baseline_holdout["bit_gain_vs_complete_4096_cover"]
    )
    qualified = factor > 1.0 and gain > 0.0
    external = {
        "qualified": qualified,
        "primary_untouched_holdout_A415_panel": learned_holdout,
        "primary_untouched_holdout_A414_panel": baseline_holdout,
        "selection_A415_panel": metric_panel(learned_depths[:16]),
        "selection_A414_panel": metric_panel(baseline_depths[:16]),
        "all32_A415_panel": metric_panel(learned_depths),
        "all32_A414_panel": metric_panel(baseline_depths),
        "holdout_geometric_rank_improvement_factor": factor,
        "holdout_additional_bit_gain": gain,
        "holdout_better_targets": sum(
            left < right
            for left, right in zip(learned_depths[16:], baseline_depths[16:], strict=True)
        ),
        "holdout_equal_targets": sum(
            left == right
            for left, right in zip(learned_depths[16:], baseline_depths[16:], strict=True)
        ),
        "holdout_worse_targets": sum(
            left > right
            for left, right in zip(learned_depths[16:], baseline_depths[16:], strict=True)
        ),
        "equal_worker_count": WORKERS,
        "external_model_choices": 0,
        "external_model_refits": 0,
        "target_specific_polarity_choices": 0,
        "new_solver_stages": 0,
    }
    with A412.a401_paths(A412.ORIGINAL_A401_ARTIFACTS, A412.ORIGINAL_A401_MEASUREMENTS):
        production_ranks, _baseline_views, production_metadata = A402.production_rank_matrix()
    production_orders = portfolio_orders(production_ranks, model)
    owners = A414.minimum_rank_owner_lanes(production_orders, SOURCE_ROLES)
    work = A414.balanced_static_worker_schedule(owners["owner_lane_orders"], SOURCE_ROLES)
    proof = prove_schedule(owners, work, SOURCE_ROLES)
    owner_commitment = canonical_sha256(
        {
            "owner_lane_sizes": owners["owner_lane_sizes"],
            "owner_lane_order_uint16be_sha256": owners["owner_lane_order_uint16be_sha256"],
        }
    )
    schedule_commitment = canonical_sha256(
        {
            "worker_task_counts": work["worker_task_counts"],
            "worker_stolen_task_counts": work["worker_stolen_task_counts"],
            "worker_task_list_sha256": work["worker_task_list_sha256"],
            "cell_epoch_one_based": work["cell_epoch_one_based"],
        }
    )
    payload: dict[str, Any] = {
        "schema": "chacha20-round20-w50-xor-landscape-portfolio-a415-result-v1",
        "attempt_id": ATTEMPT_ID,
        "evidence_stage": (
            "UNTOUCHED_HOLDOUT_QUALIFIED_POLARITY_COMPLETE_OPTIMAL_SCHEDULER"
            if qualified
            else "EXTERNAL_BOUNDARY_WITH_RETAINED_POLARITY_MECHANISM_AND_SCHEDULER"
        ),
        "design_sha256": DESIGN_SHA256,
        "implementation_sha256": expected_implementation_sha256,
        "implementation_commitment_sha256": implementation[
            "implementation_commitment_sha256"
        ],
        "model_sha256": expected_model_sha256,
        "model_commitment_sha256": model["model_commitment_sha256"],
        "training_selection": model["portfolio_selection"],
        "external_transfer": external,
        "source_role_order": list(SOURCE_ROLES),
        "source_order_uint16be_sha256": owners["source_order_uint16be_sha256"],
        "owner_lane_orders": owners["owner_lane_orders"],
        "owner_lane_sizes": owners["owner_lane_sizes"],
        "owner_lane_order_uint16be_sha256": owners[
            "owner_lane_order_uint16be_sha256"
        ],
        "worker_tasks": work["worker_tasks"],
        "worker_cell_orders": work["worker_cell_orders"],
        "worker_task_counts": work["worker_task_counts"],
        "worker_stolen_task_counts": work["worker_stolen_task_counts"],
        "worker_cell_order_uint16be_sha256": work[
            "worker_cell_order_uint16be_sha256"
        ],
        "worker_task_list_sha256": work["worker_task_list_sha256"],
        "cell_epoch_one_based": work["cell_epoch_one_based"],
        "cell_worker_role": work["cell_worker_role"],
        "cell_owner_queue_role": work["cell_owner_queue_role"],
        "cell_owner_queue_position_one_based": work[
            "cell_owner_queue_position_one_based"
        ],
        "schedule_proof": proof,
        "production_execution_enabled": qualified,
        "owner_lane_commitment_sha256": owner_commitment,
        "schedule_commitment_sha256": schedule_commitment,
        "production_view_metadata": production_metadata,
        "fresh_field_commitments": field_commitments,
        "fresh_reader_commitments": reader_commitments,
        "complete_external_targets": 32,
        "external_target_labels_used_for_model_selection": 0,
        "external_reader_refits": 0,
        "target_specific_polarity_choices": 0,
        "production_target_labels_used": 0,
        "production_reader_refits": 0,
        "production_candidate_assignments_executed": 0,
        "live_recovery_filter_outcomes_or_results_consumed": False,
        "anchors": {
            "design": anchor(DESIGN, DESIGN_SHA256),
            "implementation": anchor(IMPLEMENTATION, expected_implementation_sha256),
            "model": anchor(MODEL, expected_model_sha256),
            "A414_model": anchor(A414_MODEL, A414_MODEL_SHA256),
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
            "external_transfer": external,
            "owner_lane_commitment_sha256": owner_commitment,
            "schedule_commitment_sha256": schedule_commitment,
            "schedule_proof": proof,
        }
    )
    payload["causal"] = build_causal(payload)
    atomic_json(RESULT, payload)
    atomic_bytes(
        REPORT,
        (
            "# A415 — polarity-complete XOR-landscape W50 scheduler\n\n"
            f"Evidence stage: **{payload['evidence_stage']}**\n\n"
            f"- Untouched holdout A415 ranks: **{learned_holdout['ranks']}**\n"
            f"- Matched A414 ranks: **{baseline_holdout['ranks']}**\n"
            f"- Holdout improvement factor: **{factor:.9f}**\n"
            f"- Holdout additional bit gain: **{gain:.9f}**\n"
            f"- Owner-lane sizes: **{owners['owner_lane_sizes']}**\n"
            "- Complete cover / duplicates / depth / work violations: **4096 / 0 / 0 / 0**\n"
            "- Makespan: **512 epochs, exact theoretical minimum**\n"
            "- Authentic AI-native Causal readback: **2 explicit + 1 inferred chain**\n"
        ).encode(),
    )
    return payload


def analyze() -> dict[str, Any]:
    payload: dict[str, Any] = {
        "attempt_id": ATTEMPT_ID,
        "design_sha256": DESIGN_SHA256,
        "training_complete": TRAINING.exists(),
        "implementation_frozen": IMPLEMENTATION.exists(),
        "model_frozen": MODEL.exists(),
        "result_complete": RESULT.exists(),
    }
    if TRAINING.exists():
        training = load_training()
        payload["training_sha256"] = file_sha256(TRAINING)
        payload["training_parallel_panel"] = training["portfolio_selection"][
            "pointwise_minimum_panel"
        ]
    if IMPLEMENTATION.exists():
        payload["implementation_sha256"] = file_sha256(IMPLEMENTATION)
    if MODEL.exists():
        model = load_model()
        payload["model_sha256"] = file_sha256(MODEL)
        payload["selected_canonical_indices"] = model["selected_canonical_indices"]
    if RESULT.exists():
        result = json.loads(RESULT.read_bytes())
        payload["result_sha256"] = file_sha256(RESULT)
        payload["evidence_stage"] = result["evidence_stage"]
        payload["external_transfer"] = result["external_transfer"]
        payload["schedule_proof"] = result["schedule_proof"]
    return payload


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    action = parser.add_mutually_exclusive_group(required=True)
    action.add_argument("--analyze", action="store_true")
    action.add_argument("--materialize-training", action="store_true")
    action.add_argument("--freeze-implementation", action="store_true")
    action.add_argument("--freeze-model", action="store_true")
    action.add_argument("--evaluate-external", action="store_true")
    parser.add_argument("--expected-training-sha256")
    parser.add_argument("--expected-implementation-sha256")
    parser.add_argument("--expected-model-sha256")
    args = parser.parse_args()
    if args.materialize_training:
        payload = materialize_training()
    elif args.freeze_implementation:
        if not args.expected_training_sha256:
            parser.error("--freeze-implementation requires --expected-training-sha256")
        payload = freeze_implementation(
            expected_training_sha256=args.expected_training_sha256
        )
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

#!/usr/bin/env python3
"""A445: cross-fit raw 532-channel shape Readers and transfer one to W52."""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import inspect
import json
import math
import os
import sys
from pathlib import Path
from typing import Any, Mapping, Sequence

import numpy as np

ROOT = Path(__file__).parents[2]
RESEARCH = ROOT / "research"
CONFIGS = RESEARCH / "configs"
RESULTS = RESEARCH / "results/v1"

DESIGN = (
    CONFIGS
    / "chacha20_round20_w52_crossfit_raw_shape_reader_transfer_a445_design_v1.json"
)
IMPLEMENTATION = (
    CONFIGS
    / "chacha20_round20_w52_crossfit_raw_shape_reader_transfer_a445_implementation_v1.json"
)
RESULT = RESULTS / "chacha20_round20_w52_crossfit_raw_shape_reader_transfer_a445_v1.json"
CAUSAL = RESULT.with_suffix(".causal")
REPORT = RESULT.with_suffix(".md")
TEST = ROOT / "tests/test_chacha20_round20_w52_crossfit_raw_shape_reader_transfer_a445.py"
REPRO = ROOT / "scripts/reproduce_chacha20_round20_w52_crossfit_raw_shape_reader_transfer_a445.sh"

A375_RUNNER = RESEARCH / "experiments/chacha20_round20_w46_wide_consensus_reader_a375.py"
A375_RESULT = RESULTS / "chacha20_round20_w46_wide_consensus_reader_a375_v1.json"
A375_CAUSAL = A375_RESULT.with_suffix(".causal")
A439_RUNNER = (
    RESEARCH
    / "experiments/chacha20_round20_w52_wide_consensus_dual_axis_wavefront_a439.py"
)
A439_RESULT = RESULTS / "chacha20_round20_w52_wide_consensus_dual_axis_wavefront_a439_v1.json"
A439_CAUSAL = A439_RESULT.with_suffix(".causal")
A442_RUNNER = RESEARCH / "experiments/chacha20_round20_w52_knownkey_meta_reader_transfer_a442.py"
A442_RESULT = RESULTS / "chacha20_round20_w52_knownkey_meta_reader_transfer_a442_v1.json"
A442_CAUSAL = A442_RESULT.with_suffix(".causal")
A444_RUNNER = RESEARCH / "experiments/chacha20_round20_w52_crossfit_density_reader_transfer_a444.py"
A444_RESULT = RESULTS / "chacha20_round20_w52_crossfit_density_reader_transfer_a444_v1.json"
A444_CAUSAL = A444_RESULT.with_suffix(".causal")

ATTEMPT_ID = "A445"
DESIGN_SHA256 = "0a08ba9ddfd8c51cab2128ac9272c14371ac621f7644ec54de012d48ec527b00"
A375_RUNNER_SHA256 = "e41a91b225b861abd669280a4044dddf5e2b24e8f6e8c66e7eee6d5a149ec9f1"
A375_RESULT_SHA256 = "fc7135af9e001eb8cd83a55902e48f5776dc24a4eb86a162d7d783a115b38ef1"
A375_CAUSAL_SHA256 = "adc5fc921da7c7429407fabc637ff03c27e15705fde6ea157fc31acae25f9825"
A439_RUNNER_SHA256 = "6cb94c2c8e8e404b25b2b41c51e4fd68b038e447616c740dba549464b5f490fb"
A439_RESULT_SHA256 = "b141fb882bd1a1cdc6a22de424370fe3118c9a4eb90565eaa0c8225321b9f869"
A439_CAUSAL_SHA256 = "f27c9d0d8311d633cfa46237df44ef1daa0cf375c99ddd1f85e37cc79f26f27c"
A442_RUNNER_SHA256 = "436f0e2a35949bb2007e7da95ec1558c134c2c30c4d077e72b4d2da81de27314"
A442_RESULT_SHA256 = "8c8222528dc3ef12ffc0fbda513061b39243daade51a70a17f0bd89c65b53b1d"
A442_CAUSAL_SHA256 = "89e079477ca230be5d2d6ba0231bf7833b29b5c6793076e5800622bf0b8ffb6b"
A444_RUNNER_SHA256 = "21a81fe1a6d7a6362f153c81b8d99af7f2753c8473f0d64eae9ee0bc731af8c9"
A444_RESULT_SHA256 = "8003c403af34cc7e32a2308840cc924513a220e90f04d6bbef38a3e6d694cb43"
A444_CAUSAL_SHA256 = "432967376e2e0012b9e939fe176d21e4e9b173d2bc452bee9d4c98e979045e13"
A442_BORDA_FIELD_SHA256 = "64cb6aad1f9621df5ff6ef44bb7e06cfc2dd86871483df83195382b2abf899b0"

MODEL_ROLES = ("wide_vote", "sparse_reciprocal", "broad_quantile", "broad_intersection")
OPERATORS = (
    "borda_sum_baseline",
    "abs_fisher_top8",
    "abs_fisher_top32",
    "abs_fisher_top128",
    "abs_fisher_all532",
    "signed_fisher_top32",
    "square_fisher_top32",
    "abs_gaussian_top32",
    "abs_centroid_top32",
)
LEARNED_OPERATORS = frozenset(OPERATORS[1:])
TARGETS = 128
CELLS = 256
FEATURES = 532
BLOCKS = 8
BLOCK_SIZE = 16
SLICES = tuple(range(16))
AXIS_CELLS = 4096
PAIR_CELLS = 1 << 24
VARIANCE_FLOOR = 0.1
SCORE_DECIMALS = 12
MATERIAL_SPEARMAN_MAX = 0.98
MATERIAL_TOP65536_OVERLAP_MAX = 0.90
DOTCAUSAL_SRC = Path("/Users/bhkmie/Documents/Forschung/O1/vendor/fabel/dotcausal_package/src")


def load_module(path: Path, name: str) -> Any:
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot import A445 dependency {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


A444 = load_module(A444_RUNNER, "a445_a444")
file_sha256 = A444.file_sha256
canonical_sha256 = A444.canonical_sha256
atomic_bytes = A444.atomic_bytes
atomic_json = A444.atomic_json
relative = A444.relative
path_from_ref = A444.path_from_ref
anchor = A444.anchor
exact_order = A444.exact_order
order_to_ranks = A444.order_to_ranks
calibration_statistics = A444.calibration_statistics


def array_sha256(value: np.ndarray, dtype: str = "<f8") -> str:
    return hashlib.sha256(np.asarray(value, dtype=dtype).tobytes()).hexdigest()


def _representation(value: np.ndarray, name: str) -> np.ndarray:
    source = np.asarray(value, dtype=np.float64)
    if name == "absolute":
        result = np.abs(source)
    elif name == "signed":
        result = source
    elif name == "square":
        result = np.square(source)
    else:
        raise ValueError(f"A445 unknown representation {name}")
    if not np.isfinite(result).all():
        raise ValueError("A445 representation contains nonfinite values")
    return result


def summarize_panel(matrices: np.ndarray, truths: np.ndarray) -> dict[str, dict[str, np.ndarray]]:
    values = np.asarray(matrices, dtype=np.float64)
    labels = np.asarray(truths, dtype=np.int64)
    if values.ndim != 3 or labels.shape != (values.shape[0],):
        raise ValueError("A445 panel geometry differs")
    targets, cells, features = values.shape
    if cells < 2 or features < 1 or np.any(labels < 0) or np.any(labels >= cells):
        raise ValueError("A445 panel labels differ")
    output: dict[str, dict[str, np.ndarray]] = {}
    for representation in ("absolute", "signed", "square"):
        all_sum = np.empty((targets, features), dtype=np.float64)
        all_sumsq = np.empty_like(all_sum)
        positive = np.empty_like(all_sum)
        positive_sq = np.empty_like(all_sum)
        for target in range(targets):
            transformed = _representation(values[target], representation)
            all_sum[target] = transformed.sum(axis=0, dtype=np.float64)
            all_sumsq[target] = np.square(transformed).sum(axis=0, dtype=np.float64)
            positive[target] = transformed[labels[target]]
            positive_sq[target] = np.square(positive[target])
        output[representation] = {
            "all_sum": all_sum,
            "all_sumsq": all_sumsq,
            "positive": positive,
            "positive_sq": positive_sq,
        }
    return output


def fold_partition(block: int, targets: int = TARGETS, block_size: int = BLOCK_SIZE) -> tuple[np.ndarray, np.ndarray]:
    if block < 0 or block * block_size + block_size > targets:
        raise ValueError("A445 held block outside panel")
    all_targets = np.arange(targets, dtype=np.int64)
    start = block * block_size
    stop = start + block_size
    held = all_targets[start:stop]
    train = np.concatenate((all_targets[:start], all_targets[stop:]))
    if np.intersect1d(train, held).size or train.size + held.size != targets:
        raise RuntimeError("A445 crossfit partition leaks held targets")
    return train, held


def _operator_contract(operator: str) -> tuple[str, str, int]:
    if operator.startswith("abs_fisher_top"):
        return "absolute", "fisher", int(operator.removeprefix("abs_fisher_top"))
    if operator == "abs_fisher_all532":
        return "absolute", "fisher", FEATURES
    if operator == "signed_fisher_top32":
        return "signed", "fisher", 32
    if operator == "square_fisher_top32":
        return "square", "fisher", 32
    if operator == "abs_gaussian_top32":
        return "absolute", "gaussian", 32
    if operator == "abs_centroid_top32":
        return "absolute", "centroid", 32
    raise ValueError(f"A445 unknown learned operator {operator}")


def fit_operator(
    operator: str,
    summaries: Mapping[str, Mapping[str, np.ndarray]],
    train_indices: Sequence[int],
    feature_names: Sequence[str],
    *,
    cells: int = CELLS,
) -> dict[str, Any]:
    representation, family, requested = _operator_contract(operator)
    indices = np.asarray([int(value) for value in train_indices], dtype=np.int64)
    source = summaries[representation]
    targets, features = np.asarray(source["positive"]).shape
    if (
        indices.ndim != 1
        or indices.size == 0
        or np.unique(indices).size != indices.size
        or np.any(indices < 0)
        or np.any(indices >= targets)
        or len(feature_names) != features
    ):
        raise ValueError("A445 training index or feature contract differs")
    positive_count = int(indices.size)
    negative_count = int(indices.size * (cells - 1))
    positive_sum = np.asarray(source["positive"])[indices].sum(axis=0)
    positive_sumsq = np.asarray(source["positive_sq"])[indices].sum(axis=0)
    total_sum = np.asarray(source["all_sum"])[indices].sum(axis=0)
    total_sumsq = np.asarray(source["all_sumsq"])[indices].sum(axis=0)
    negative_sum = total_sum - positive_sum
    negative_sumsq = total_sumsq - positive_sumsq
    positive_mean = positive_sum / positive_count
    negative_mean = negative_sum / negative_count
    positive_variance = np.maximum(
        positive_sumsq / positive_count - np.square(positive_mean), 0.0
    )
    negative_variance = np.maximum(
        negative_sumsq / negative_count - np.square(negative_mean), 0.0
    )
    standardized = (positive_mean - negative_mean) / np.sqrt(
        positive_variance + negative_variance + 1.0e-12
    )
    feature_ids = np.arange(features, dtype=np.int64)
    selected = np.lexsort((feature_ids, -np.abs(standardized)))[: min(requested, features)]
    pooled = positive_variance[selected] + negative_variance[selected] + VARIANCE_FLOOR
    payload: dict[str, Any] = {
        "operator": operator,
        "representation": representation,
        "family": family,
        "variance_floor": VARIANCE_FLOOR,
        "score_quantization_decimals": SCORE_DECIMALS,
        "training_targets": positive_count,
        "training_target_index_sha256": hashlib.sha256(
            indices.astype(">u2", copy=False).tobytes()
        ).hexdigest(),
        "positive_samples": positive_count,
        "negative_samples": negative_count,
        "selected_feature_count": int(selected.size),
        "selected_feature_indices": selected.tolist(),
        "selected_feature_names": [str(feature_names[index]) for index in selected],
        "selected_standardized_effects": standardized[selected].tolist(),
        "positive_mean": positive_mean[selected].tolist(),
        "negative_mean": negative_mean[selected].tolist(),
        "positive_variance": positive_variance[selected].tolist(),
        "negative_variance": negative_variance[selected].tolist(),
        "pooled_variance": pooled.tolist(),
    }
    if family == "fisher":
        payload["weights"] = (
            (positive_mean[selected] - negative_mean[selected]) / pooled
        ).tolist()
    payload["model_sha256"] = canonical_sha256(payload)
    return payload


def score_candidates(matrix: np.ndarray, model: Mapping[str, Any]) -> np.ndarray:
    transformed = _representation(np.asarray(matrix, dtype=np.float64), str(model["representation"]))
    selected = np.asarray(model["selected_feature_indices"], dtype=np.int64)
    values = transformed[:, selected]
    family = str(model["family"])
    if family == "fisher":
        with np.errstate(over="ignore", invalid="ignore", divide="ignore"):
            score = values @ np.asarray(model["weights"], dtype=np.float64)
    elif family == "gaussian":
        positive_mean = np.asarray(model["positive_mean"], dtype=np.float64)
        negative_mean = np.asarray(model["negative_mean"], dtype=np.float64)
        positive_variance = np.maximum(
            np.asarray(model["positive_variance"], dtype=np.float64), VARIANCE_FLOOR
        )
        negative_variance = np.maximum(
            np.asarray(model["negative_variance"], dtype=np.float64), VARIANCE_FLOOR
        )
        score = 0.5 * np.sum(
            np.log(negative_variance / positive_variance)
            + np.square(values - negative_mean) / negative_variance
            - np.square(values - positive_mean) / positive_variance,
            axis=1,
        )
    elif family == "centroid":
        positive_mean = np.asarray(model["positive_mean"], dtype=np.float64)
        pooled = np.asarray(model["pooled_variance"], dtype=np.float64)
        score = -np.sum(np.square(values - positive_mean) / pooled, axis=1)
    else:
        raise ValueError(f"A445 unknown score family {family}")
    score = np.round(np.asarray(score, dtype=np.float64), SCORE_DECIMALS)
    if score.shape != (transformed.shape[0],) or not np.isfinite(score).all():
        raise RuntimeError("A445 score geometry or finiteness differs")
    return score


def score_order(score: np.ndarray, borda_ranks: np.ndarray) -> np.ndarray:
    values = np.asarray(score, dtype=np.float64)
    ties = np.asarray(borda_ranks, dtype=np.int64)
    cells = values.size
    if ties.shape != (cells,) or np.unique(ties).size != cells or not np.isfinite(values).all():
        raise ValueError("A445 score-order tie field differs")
    return exact_order(np.lexsort((np.arange(cells), ties, -values)), cells)


def selection_key(row: Mapping[str, Any]) -> tuple[float | int, ...]:
    return (
        -float(row["minimum_fixed_block_bit_gain"]),
        -float(row["balanced_two_corpus_bit_gain"]),
        -float(row["all128_bit_gain"]),
        -int(row["targets_at_or_above_median_rank"]),
        int(row["worst_rank"]),
        OPERATORS.index(str(row["operator"])),
    )


def reconstruct_calibration_panel(
    a375: Mapping[str, Any], a442_runtime: Any
) -> tuple[np.ndarray, np.ndarray, list[str], np.ndarray, list[str], dict[str, str]]:
    a375_runtime = load_module(A375_RUNNER, "a445_a375_runtime")
    matrices, truths, blocks = a375_runtime.load_panel()
    matrices = np.asarray(matrices, dtype=np.float64)
    truths = np.asarray(truths, dtype=np.int16)
    if matrices.shape != (TARGETS, CELLS, FEATURES) or len(blocks) != BLOCKS:
        raise RuntimeError("A445 raw A375 panel geometry differs")
    absolute_fields = a375_runtime.exact_abs_rank_fields(matrices)
    model_fields: dict[str, np.ndarray] = {}
    model_hashes: dict[str, str] = {}
    for role in MODEL_ROLES:
        definition = a375["model_definitions"][role]
        field = a375_runtime.aggregate_rank_field(
            absolute_fields,
            definition["member_feature_indices"],
            definition["aggregator"],
        )
        observed = hashlib.sha256(field.tobytes()).hexdigest()
        expected = a375["model_evaluations"][role]["rank_field_sha256"]
        if observed != expected:
            raise RuntimeError(f"A445 reconstructed A375 model differs: {role}")
        model_fields[role] = field
        model_hashes[role] = observed
    del absolute_fields
    borda = a442_runtime.meta_rank_field(model_fields, "borda_sum")
    if hashlib.sha256(borda.tobytes()).hexdigest() != A442_BORDA_FIELD_SHA256:
        raise RuntimeError("A445 reconstructed Borda baseline differs")
    feature_names = [str(value) for value in a375_runtime.A275.FEATURE_NAMES]
    if len(feature_names) != FEATURES:
        raise RuntimeError("A445 feature-name universe differs")
    return matrices, truths, list(blocks), borda, feature_names, model_hashes


def evaluate_operators(
    matrices: np.ndarray,
    truths: np.ndarray,
    borda_field: np.ndarray,
    feature_names: Sequence[str],
) -> tuple[dict[str, Any], str, dict[str, np.ndarray], dict[str, dict[str, np.ndarray]]]:
    summaries = summarize_panel(matrices, truths)
    fields = {operator: np.empty((TARGETS, CELLS), dtype=np.int16) for operator in OPERATORS}
    fields["borda_sum_baseline"][:] = np.asarray(borda_field, dtype=np.int16)
    ledgers: dict[str, list[dict[str, Any]]] = {operator: [] for operator in OPERATORS}
    exact = np.arange(1, CELLS + 1, dtype=np.int16)
    for block in range(BLOCKS):
        train, held = fold_partition(block)
        ledgers["borda_sum_baseline"].append(
            {
                "held_block": block,
                "held_target_indices": held.tolist(),
                "training_targets": 0,
                "model_sha256": "fixed:A442_borda_sum",
            }
        )
        for operator in OPERATORS[1:]:
            model = fit_operator(operator, summaries, train.tolist(), feature_names)
            for target in held:
                scores = score_candidates(matrices[target], model)
                order = score_order(scores, borda_field[target])
                fields[operator][target, order] = exact
            ledgers[operator].append(
                {
                    "held_block": block,
                    "held_target_indices": held.tolist(),
                    "training_targets": int(train.size),
                    "training_target_index_sha256": model["training_target_index_sha256"],
                    "model_sha256": model["model_sha256"],
                    "selected_feature_count": model["selected_feature_count"],
                    "selected_feature_index_sha256": hashlib.sha256(
                        np.asarray(model["selected_feature_indices"], dtype=">u2").tobytes()
                    ).hexdigest(),
                }
            )
    evaluations: dict[str, Any] = {}
    for operator in OPERATORS:
        field = fields[operator]
        if any(
            np.unique(field[target]).size != CELLS
            or int(field[target].min()) != 1
            or int(field[target].max()) != CELLS
            for target in range(TARGETS)
        ):
            raise RuntimeError(f"A445 nonexact crossfit field: {operator}")
        evaluations[operator] = {
            "operator": operator,
            "evaluation_mode": "fixed_no_fit" if operator == OPERATORS[0] else "eight_fold_block_exclusive_crossfit",
            **calibration_statistics(field, truths),
            "rank_field_sha256": hashlib.sha256(field.tobytes()).hexdigest(),
            "fold_ledger": ledgers[operator],
        }
    selected = min(OPERATORS, key=lambda operator: selection_key(evaluations[operator]))
    return evaluations, selected, fields, summaries


def load_design() -> dict[str, Any]:
    if file_sha256(DESIGN) != DESIGN_SHA256:
        raise RuntimeError("A445 design hash differs")
    value = json.loads(DESIGN.read_bytes())
    calibration = value.get("calibration_contract", {})
    transfer = value.get("W52_transfer_contract", {})
    boundary = value.get("information_boundary", {})
    if (
        value.get("schema") != "chacha20-round20-w52-crossfit-raw-shape-reader-transfer-a445-design-v1"
        or value.get("attempt_id") != ATTEMPT_ID
        or tuple(calibration.get("fixed_operator_order", [])) != OPERATORS
        or calibration.get("targets") != TARGETS
        or calibration.get("cells_per_target") != CELLS
        or calibration.get("features_per_cell") != FEATURES
        or calibration.get("fixed_blocks") != BLOCKS
        or calibration.get("all_operator_families_hyperparameters_and_ties_defined_before_evaluation") is not True
        or transfer.get("axis_cells") != AXIS_CELLS
        or transfer.get("pair_cells") != PAIR_CELLS
        or transfer.get("W52_target_labels_used") != 0
        or transfer.get("W52_model_refits") != 0
        or transfer.get("new_solver_stages") != 0
        or transfer.get("candidate_assignments_executed") != 0
        or boundary.get("A444_authentic_Causal_personally_read") is not True
        or boundary.get("A445_operator_results_known_before_design_freeze") is not False
        or boundary.get("A445_W52_scores_or_orders_known_before_design_freeze") is not False
    ):
        raise RuntimeError("A445 design semantics differ")
    anchors = value["source_anchors"]
    for key, item in anchors.items():
        if key.endswith("_path"):
            stem = key.removesuffix("_path")
            anchor(ROOT / item, anchors[f"{stem}_sha256"])
    return value


def load_sources() -> tuple[dict[str, Any], dict[str, Any], dict[str, Any], dict[str, Any], Any]:
    a375, a439, a442, runtime = A444.load_sources()
    anchor(A444_RUNNER, A444_RUNNER_SHA256)
    anchor(A444_RESULT, A444_RESULT_SHA256)
    anchor(A444_CAUSAL, A444_CAUSAL_SHA256)
    a444 = A444.load_result(A444_RESULT_SHA256)
    if (
        a444.get("selected_operator") != "borda_sum_baseline"
        or a444.get("recovery_ready") is not False
        or a444.get("target_labels_used_for_W52") != 0
        or a444.get("W52_model_refits") != 0
        or a444.get("candidate_assignments_executed") != 0
    ):
        raise RuntimeError("A445 A444 boundary semantics differ")
    return a375, a439, a442, a444, runtime


def freeze_implementation() -> dict[str, Any]:
    if any(path.exists() for path in (IMPLEMENTATION, RESULT, CAUSAL, REPORT)):
        raise FileExistsError("A445 implementation or result already exists")
    design = load_design()
    a375, a439, a442, a444, _runtime = load_sources()
    if not TEST.exists() or not REPRO.exists():
        raise FileNotFoundError("A445 tests and reproducer must precede freeze")
    payload: dict[str, Any] = {
        "schema": "chacha20-round20-w52-crossfit-raw-shape-reader-transfer-a445-implementation-v1",
        "attempt_id": ATTEMPT_ID,
        "commitment_state": "complete_raw_shape_crossfit_selection_W52_transfer_and_authentic_Causal_code_frozen_before_any_A445_model_evaluation_W52_order_or_candidate_execution",
        "design_sha256": DESIGN_SHA256,
        "operators": list(OPERATORS),
        "selection_key": design["calibration_contract"]["selection_key"],
        "source_A375_selection_commitment_sha256": a375["selection_commitment_sha256"],
        "source_A439_result_commitment_sha256": a439["result_commitment_sha256"],
        "source_A442_result_commitment_sha256": a442["result_commitment_sha256"],
        "source_A444_result_commitment_sha256": a444["result_commitment_sha256"],
        "A445_evaluation_available_at_freeze": False,
        "A445_W52_orders_available_at_freeze": False,
        "A426_A438_A440_A443_target_outcome_or_progress_read": False,
        "target_labels_used_for_W52": 0,
        "W52_model_refits": 0,
        "new_solver_stages": 0,
        "candidate_assignments_executed": 0,
        "anchors": {
            "design": anchor(DESIGN, DESIGN_SHA256),
            "A375_runner": anchor(A375_RUNNER, A375_RUNNER_SHA256),
            "A375_result": anchor(A375_RESULT, A375_RESULT_SHA256),
            "A375_causal": anchor(A375_CAUSAL, A375_CAUSAL_SHA256),
            "A439_runner": anchor(A439_RUNNER, A439_RUNNER_SHA256),
            "A439_result": anchor(A439_RESULT, A439_RESULT_SHA256),
            "A439_causal": anchor(A439_CAUSAL, A439_CAUSAL_SHA256),
            "A442_runner": anchor(A442_RUNNER, A442_RUNNER_SHA256),
            "A442_result": anchor(A442_RESULT, A442_RESULT_SHA256),
            "A442_causal": anchor(A442_CAUSAL, A442_CAUSAL_SHA256),
            "A444_runner": anchor(A444_RUNNER, A444_RUNNER_SHA256),
            "A444_result": anchor(A444_RESULT, A444_RESULT_SHA256),
            "A444_causal": anchor(A444_CAUSAL, A444_CAUSAL_SHA256),
            "runner": anchor(Path(__file__)),
            "test": anchor(TEST),
            "reproducer": anchor(REPRO),
        },
    }
    payload["implementation_commitment_sha256"] = canonical_sha256(payload)
    atomic_json(IMPLEMENTATION, payload)
    return payload


def load_implementation(expected_sha256: str) -> dict[str, Any]:
    if file_sha256(IMPLEMENTATION) != expected_sha256:
        raise RuntimeError("A445 implementation hash differs")
    value = json.loads(IMPLEMENTATION.read_bytes())
    if (
        value.get("schema") != "chacha20-round20-w52-crossfit-raw-shape-reader-transfer-a445-implementation-v1"
        or value.get("attempt_id") != ATTEMPT_ID
        or tuple(value.get("operators", [])) != OPERATORS
        or value.get("A445_evaluation_available_at_freeze") is not False
        or value.get("A445_W52_orders_available_at_freeze") is not False
        or value.get("A426_A438_A440_A443_target_outcome_or_progress_read") is not False
        or value.get("target_labels_used_for_W52") != 0
        or value.get("W52_model_refits") != 0
        or value.get("new_solver_stages") != 0
        or value.get("candidate_assignments_executed") != 0
    ):
        raise RuntimeError("A445 implementation semantics differ")
    for row in value["anchors"].values():
        anchor(path_from_ref(row["path"]), row["sha256"])
    unsigned = {key: item for key, item in value.items() if key != "implementation_commitment_sha256"}
    if value.get("implementation_commitment_sha256") != canonical_sha256(unsigned):
        raise RuntimeError("A445 implementation commitment differs")
    return value


def _slice_borda_ranks(a439: Mapping[str, Any], axis_name: str, low4: int, runtime: Any) -> np.ndarray:
    ranks = np.stack(
        [
            np.asarray(a439["axes"][axis_name]["within_slice_rank_fields"][role][str(low4)], dtype=np.int64)
            for role in MODEL_ROLES
        ]
    )
    order = runtime.meta_order(ranks, "borda_sum")
    return order_to_ranks(order, CELLS)


def compose_axis_order(
    selected: str,
    reference: Sequence[int],
    within_orders: Mapping[int, Sequence[int]],
    composer: Any,
    *,
    axis_cells: int = AXIS_CELLS,
) -> np.ndarray:
    if selected == "borda_sum_baseline":
        return exact_order(reference, axis_cells)
    return exact_order(composer(within_orders), axis_cells)


def transfer_axis_raw(
    *,
    axis_name: str,
    source: Mapping[str, Any],
    source_module: Any,
    a439: Mapping[str, Any],
    a442: Mapping[str, Any],
    selected: str,
    model: Mapping[str, Any],
    a439_runtime: Any,
    a442_runtime: Any,
) -> dict[str, Any]:
    measurements = a439_runtime.load_axis_measurements(source, source_module, axis_name)
    normalized_hashes: dict[str, str] = {}
    score_hashes: dict[str, str] = {}
    within_orders: dict[int, list[int]] = {}
    for low4 in SLICES:
        matrix = a439_runtime.A375.A275._target_feature_matrix(measurements[low4])  # noqa: SLF001
        normalized = np.asarray(a439_runtime.A375.A360.target_normalize(matrix), dtype=np.float64)
        if normalized.shape != (CELLS, FEATURES) or not np.isfinite(normalized).all():
            raise RuntimeError(f"A445 {axis_name} slice geometry differs")
        observed = array_sha256(normalized)
        expected = a439["axes"][axis_name]["normalized_slice_sha256"][str(low4)]
        if observed != expected:
            raise RuntimeError(f"A445 {axis_name} normalized slice differs: {low4}")
        normalized_hashes[str(low4)] = observed
        borda_ranks = _slice_borda_ranks(a439, axis_name, low4, a442_runtime)
        if selected == "borda_sum_baseline":
            local_order = exact_order(np.argsort(borda_ranks, kind="stable"), CELLS)
            score_hashes[str(low4)] = "fixed:A442_borda_sum"
        else:
            score = score_candidates(normalized, model)
            score_hashes[str(low4)] = array_sha256(score)
            local_order = score_order(score, borda_ranks)
        within_orders[low4] = local_order.tolist()
    reference = np.asarray(a442[f"{axis_name}_order"], dtype=np.int64)
    composed = compose_axis_order(
        selected,
        reference,
        within_orders,
        a439_runtime.A376.A361.compose_round_robin,
    )
    return {
        "order": composed.tolist(),
        "order_uint16be_sha256": a442_runtime.order_sha256(composed),
        "first_16_cells": composed[:16].tolist(),
        "last_16_cells": composed[-16:].tolist(),
        "exact_cells": AXIS_CELLS,
        "normalized_slice_sha256": normalized_hashes,
        "normalized_slice_set_sha256": canonical_sha256(normalized_hashes),
        "score_sha256": score_hashes,
        "score_set_sha256": canonical_sha256(score_hashes),
        "within_slice_orders_sha256": canonical_sha256(within_orders),
        "target_labels_used": 0,
        "W52_model_refits": 0,
        "candidate_assignments_executed": 0,
    }


def build_causal(payload: Mapping[str, Any]) -> dict[str, Any]:
    if str(DOTCAUSAL_SRC) not in sys.path:
        sys.path.insert(0, str(DOTCAUSAL_SRC))
    from dotcausal.io import CausalReader, CausalWriter

    recovery_ready = bool(payload["recovery_ready"])
    terminal = "A445:raw_shape_W52_recovery_ready" if recovery_ready else "A445:raw_shape_representation_boundary"
    writer = CausalWriter(api_id="a445raw")
    writer._rules = []
    writer.add_rule(
        name="raw_panel_to_crossfit_shape_atlas",
        description="Cross-fit signed, magnitude, squared, Fisher, Gaussian and centroid Readers over complete held blocks.",
        pattern=["A375_target_normalized_532_channel_panel"],
        conclusion="A445_crossfit_raw_shape_operator_atlas",
        confidence_modifier=1.0,
    )
    writer.add_rule(
        name="shape_atlas_to_frozen_model",
        description="Select by the preregistered worst-block-first key and fit once on all 128 Known-key targets.",
        pattern=["A445_crossfit_raw_shape_operator_atlas"],
        conclusion="A445_selected_full_raw_shape_model",
        confidence_modifier=1.0,
    )
    writer.add_rule(
        name="frozen_shape_to_target_blind_W52_schedule",
        description="Transfer the frozen model over all 32 complete W52 slices with no label, refit, solver stage or candidate execution.",
        pattern=["A445_selected_full_raw_shape_model", "A439_complete_W52_raw_measurements"],
        conclusion="A445_complete_W52_pair_schedule",
        confidence_modifier=1.0,
    )
    writer.add_rule(
        name="retention_and_diversity_to_decision",
        description="Open a recovery executor only after held-block retention and exact pair-space diversity both qualify.",
        pattern=["A445_complete_W52_pair_schedule"],
        conclusion=terminal.replace(":", "_"),
        confidence_modifier=1.0,
    )
    writer.add_triplet(
        trigger="A375:target_normalized_532_channel_panel",
        mechanism="eight_fold_raw_shape_crossfit_over_three_representations_and_three_discriminants",
        outcome="A445:crossfit_raw_shape_operator_atlas",
        confidence=1.0,
        source=payload["calibration_sha256"],
        quantification=json.dumps(payload["operator_summary"], sort_keys=True),
        evidence=payload["raw_panel_sha256"],
        domain="Known-key full-round ChaCha20 raw trajectory-shape calibration",
        quality_score=1.0,
    )
    writer.add_triplet(
        trigger="A445:crossfit_raw_shape_operator_atlas",
        mechanism="minimum_held_block_then_balanced_corpus_frozen_selection",
        outcome="A445:selected_full_raw_shape_model",
        confidence=1.0,
        source=payload["selection_sha256"],
        quantification=payload["selected_operator"],
        evidence=payload["selected_full_model_sha256"],
        domain="cross-fitted raw-shape Reader selection",
        quality_score=1.0,
    )
    writer.add_triplet(
        trigger="A445:selected_full_raw_shape_model",
        mechanism="complete_32_slice_target_blind_raw_shape_transfer",
        outcome="A445:complete_W52_pair_schedule",
        confidence=1.0,
        source=payload["pair_schedule_sha256"],
        quantification=json.dumps(payload["W52_transfer"], sort_keys=True),
        evidence=payload["pair_stream_uint16be_uint16be_sha256"],
        domain="target-blind full-round ChaCha20 W52 ordering",
        quality_score=1.0,
    )
    writer.add_triplet(
        trigger="A445:complete_W52_pair_schedule",
        mechanism="crossfit_retention_plus_exact_pair_diversity_gate",
        outcome=terminal,
        confidence=1.0,
        source=payload["decision_sha256"],
        quantification=json.dumps(payload["decision"], sort_keys=True),
        evidence=str(recovery_ready),
        domain="W52 recovery trajectory decision",
        quality_score=1.0,
    )
    writer.add_triplet(
        trigger="A375:target_normalized_532_channel_panel",
        mechanism="materialized_raw_shape_transfer_decision_closure",
        outcome=terminal,
        confidence=1.0,
        source="materialized:A445_raw_shape_chain",
        quantification="exact retained closure",
        evidence=payload["evidence_stage"],
        domain="AI-native retained inference",
        quality_score=1.0,
        is_inferred=True,
    )
    writer.add_cluster(
        name="A445 raw-shape Reader transfer",
        entities=[
            "A375:target_normalized_532_channel_panel",
            "A445:crossfit_raw_shape_operator_atlas",
            "A445:selected_full_raw_shape_model",
            "A445:complete_W52_pair_schedule",
            terminal,
        ],
    )
    writer.add_gap(
        subject=terminal,
        predicate="next_required_object",
        expected_object_type="qualified_recovery_execution" if recovery_ready else "typed_hard_contradiction_or_clause_provenance_topology",
        confidence=1.0,
        suggested_queries=[
            "Execute the qualified schedule after the existing queue closes."
            if recovery_ready
            else "Raw magnitudes add no qualified trajectory; build exact typed contradiction and learned-clause provenance topology next."
        ],
    )
    temporary = CAUSAL.with_name(f".{CAUSAL.name}.{os.getpid()}.tmp")
    temporary.unlink(missing_ok=True)
    stats = writer.save(str(temporary))
    os.replace(temporary, CAUSAL)
    reader = CausalReader(str(CAUSAL), verify_integrity=True)
    explicit = reader.get_all_triplets(include_inferred=False)
    all_rows = reader.get_all_triplets(include_inferred=True)
    inferred = [row for row in reader._triplets if row.get("is_inferred", False)]
    if (
        reader.api_id != "a445raw"
        or len(explicit) != 4
        or len(all_rows) != 5
        or len(inferred) != 1
        or len(reader._rules) != 4
        or len(reader._clusters) != 1
        or len(reader._gaps) != 1
    ):
        raise RuntimeError("A445 authentic Causal reopen gate failed")
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
        "reader_gate_readback": {
            "operator_atlas": explicit[0],
            "selection": explicit[1],
            "W52_transfer": explicit[2],
            "decision": explicit[3],
            "terminal_chain": all_rows[-1],
            "next_gap": reader._gaps[0],
        },
    }


def _build_result_once(*, expected_implementation_sha256: str) -> dict[str, Any]:
    if any(path.exists() for path in (RESULT, CAUSAL, REPORT)):
        raise FileExistsError("A445 result already exists")
    design = load_design()
    implementation = load_implementation(expected_implementation_sha256)
    a375, a439, a442, a444, runtime = load_sources()
    matrices, truths, blocks, borda, feature_names, reconstructed_hashes = reconstruct_calibration_panel(a375, runtime)
    raw_panel_sha = array_sha256(matrices)
    evaluations, selected, _fields, summaries = evaluate_operators(matrices, truths, borda, feature_names)
    if evaluations["borda_sum_baseline"]["rank_field_sha256"] != A442_BORDA_FIELD_SHA256:
        raise RuntimeError("A445 Borda baseline hash differs")
    if selected == "borda_sum_baseline":
        selected_model: dict[str, Any] = {
            "operator": selected,
            "family": "fixed_A442_borda_sum",
            "training_targets": 0,
        }
        selected_model["model_sha256"] = canonical_sha256(selected_model)
    else:
        selected_model = fit_operator(selected, summaries, list(range(TARGETS)), feature_names)
    selected_model_sha = selected_model["model_sha256"]

    a439_runtime = load_module(A439_RUNNER, "a445_a439_runtime")
    _source_a375, a432, a433, _a436 = a439_runtime.load_source_metadata()
    prefix = transfer_axis_raw(
        axis_name="prefix",
        source=a433,
        source_module=a439_runtime.A433,
        a439=a439,
        a442=a442,
        selected=selected,
        model=selected_model,
        a439_runtime=a439_runtime,
        a442_runtime=runtime,
    )
    off_axis = transfer_axis_raw(
        axis_name="off_axis",
        source=a432,
        source_module=a439_runtime.A432,
        a439=a439,
        a442=a442,
        selected=selected,
        model=selected_model,
        a439_runtime=a439_runtime,
        a442_runtime=runtime,
    )
    pair_stream_sha = runtime.pair_stream_sha256(prefix["order"], off_axis["order"])
    selected_pair_rank = runtime.reference_square_rank_vector(prefix["order"], off_axis["order"])
    comparisons: dict[str, Any] = {}
    references = {
        "A439": (a439["axes"]["prefix"]["portfolio_order"], a439["axes"]["off_axis"]["portfolio_order"]),
        "A442": (a442["prefix_order"], a442["off_axis_order"]),
        "A444": (a444["prefix_order"], a444["off_axis_order"]),
    }
    for name, (left, right) in references.items():
        reference_rank = runtime.reference_square_rank_vector(left, right)
        comparisons[name] = runtime.compare_rank_orders(selected_pair_rank, reference_rank)
        del reference_rank
    del selected_pair_rank
    overlap_a442 = comparisons["A442"]["top_k_overlap"]["65536"]["intersection"] / 65536
    material_a442 = (
        comparisons["A442"]["spearman_rank_correlation"] < MATERIAL_SPEARMAN_MAX
        or overlap_a442 < MATERIAL_TOP65536_OVERLAP_MAX
    )
    selected_evaluation = evaluations[selected]
    baseline_evaluation = evaluations["borda_sum_baseline"]
    nonbaseline = selected != "borda_sum_baseline"
    eight_positive = selected_evaluation["positive_fixed_block_count"] == BLOCKS
    retained_minimum = float(selected_evaluation["minimum_fixed_block_bit_gain"]) >= float(
        baseline_evaluation["minimum_fixed_block_bit_gain"]
    )
    recovery_ready = nonbaseline and eight_positive and retained_minimum and material_a442
    decision = {
        "selected_operator_is_nonbaseline": nonbaseline,
        "positive_held_blocks": selected_evaluation["positive_fixed_block_count"],
        "required_positive_held_blocks": BLOCKS,
        "selected_minimum_held_block_gain": selected_evaluation["minimum_fixed_block_bit_gain"],
        "borda_minimum_fixed_block_gain": baseline_evaluation["minimum_fixed_block_bit_gain"],
        "minimum_gain_retained_or_improved": retained_minimum,
        "material_pair_diversity_vs_A442": material_a442,
        "top65536_overlap_vs_A442": overlap_a442,
        "recovery_ready": recovery_ready,
    }
    operator_summary = {
        operator: {
            key: value
            for key, value in evaluations[operator].items()
            if key not in {"truth_ranks", "fixed_block_bit_gains", "corpus_bit_gains", "fold_ledger"}
        }
        for operator in OPERATORS
    }
    evidence_stage = (
        "CROSSFIT_RAW_SHAPE_READER_RETAINED_MATERIALLY_ORTHOGONAL_W52_RECOVERY_READY"
        if recovery_ready
        else "CROSSFIT_RAW_SHAPE_READER_EXACT_REPRESENTATION_BOUNDARY_RETAINED"
    )
    calibration_contract = {
        "targets": TARGETS,
        "cells_per_target": CELLS,
        "features_per_cell": FEATURES,
        "fixed_blocks": BLOCKS,
        "targets_per_block": BLOCK_SIZE,
        "block_labels": blocks,
        "raw_panel_sha256": raw_panel_sha,
        "feature_names_sha256": canonical_sha256(feature_names),
        "summary_sha256": {
            representation: canonical_sha256(
                {name: array_sha256(array) for name, array in values.items()}
            )
            for representation, values in summaries.items()
        },
        "reconstructed_model_rank_field_sha256": reconstructed_hashes,
        "borda_baseline_expected_sha256": A442_BORDA_FIELD_SHA256,
        "borda_baseline_observed_sha256": evaluations["borda_sum_baseline"]["rank_field_sha256"],
        "selection_key": design["calibration_contract"]["selection_key"],
    }
    transfer = {
        "selected_operator": selected,
        "selected_full_model_sha256": selected_model_sha,
        "prefix": {key: value for key, value in prefix.items() if key != "order"},
        "off_axis": {key: value for key, value in off_axis.items() if key != "order"},
        "prefix_comparison_to_A442": runtime.axis_comparison(prefix["order"], a442["prefix_order"]),
        "off_axis_comparison_to_A442": runtime.axis_comparison(off_axis["order"], a442["off_axis_order"]),
        "pair_cells": PAIR_CELLS,
        "target_labels_used": 0,
        "W52_model_refits": 0,
        "new_solver_stages": 0,
        "candidate_assignments_executed": 0,
    }
    core: dict[str, Any] = {
        "schema": "chacha20-round20-w52-crossfit-raw-shape-reader-transfer-a445-v1",
        "attempt_id": ATTEMPT_ID,
        "evidence_stage": evidence_stage,
        "design_sha256": DESIGN_SHA256,
        "implementation_sha256": expected_implementation_sha256,
        "implementation_commitment_sha256": implementation["implementation_commitment_sha256"],
        "calibration_contract": calibration_contract,
        "raw_panel_sha256": raw_panel_sha,
        "operator_evaluations": evaluations,
        "operator_summary": operator_summary,
        "selected_operator": selected,
        "selected_evaluation": selected_evaluation,
        "selected_full_model": selected_model,
        "selected_full_model_sha256": selected_model_sha,
        "W52_transfer": transfer,
        "prefix_order": prefix["order"],
        "off_axis_order": off_axis["order"],
        "pair_stream_uint16be_uint16be_sha256": pair_stream_sha,
        "pair_comparisons": comparisons,
        "material_pair_diversity_vs_A442": material_a442,
        "decision": decision,
        "recovery_ready": recovery_ready,
        "target_labels_used_for_W52": 0,
        "W52_model_refits": 0,
        "new_solver_stages": 0,
        "candidate_assignments_executed": 0,
        "A426_A438_A440_A443_secret_result_stop_or_worker_progress_read": False,
        "anchors": {
            "design": anchor(DESIGN, DESIGN_SHA256),
            "implementation": anchor(IMPLEMENTATION, expected_implementation_sha256),
            "A375_runner": anchor(A375_RUNNER, A375_RUNNER_SHA256),
            "A375_result": anchor(A375_RESULT, A375_RESULT_SHA256),
            "A375_causal": anchor(A375_CAUSAL, A375_CAUSAL_SHA256),
            "A439_runner": anchor(A439_RUNNER, A439_RUNNER_SHA256),
            "A439_result": anchor(A439_RESULT, A439_RESULT_SHA256),
            "A439_causal": anchor(A439_CAUSAL, A439_CAUSAL_SHA256),
            "A442_runner": anchor(A442_RUNNER, A442_RUNNER_SHA256),
            "A442_result": anchor(A442_RESULT, A442_RESULT_SHA256),
            "A442_causal": anchor(A442_CAUSAL, A442_CAUSAL_SHA256),
            "A444_runner": anchor(A444_RUNNER, A444_RUNNER_SHA256),
            "A444_result": anchor(A444_RESULT, A444_RESULT_SHA256),
            "A444_causal": anchor(A444_CAUSAL, A444_CAUSAL_SHA256),
            "runner": anchor(Path(__file__)),
            "test": anchor(TEST),
            "reproducer": anchor(REPRO),
        },
    }
    core["calibration_sha256"] = canonical_sha256({"contract": calibration_contract, "evaluations": evaluations})
    core["selection_sha256"] = canonical_sha256(
        {
            "selected_operator": selected,
            "selected_evaluation": selected_evaluation,
            "selected_full_model_sha256": selected_model_sha,
        }
    )
    core["pair_schedule_sha256"] = canonical_sha256(
        {
            "prefix_order_sha256": prefix["order_uint16be_sha256"],
            "off_axis_order_sha256": off_axis["order_uint16be_sha256"],
            "pair_stream_sha256": pair_stream_sha,
        }
    )
    core["pair_diversity_sha256"] = canonical_sha256(comparisons)
    core["decision_sha256"] = canonical_sha256(decision)
    core["result_commitment_sha256"] = canonical_sha256(
        {
            "design_sha256": DESIGN_SHA256,
            "implementation_commitment_sha256": core["implementation_commitment_sha256"],
            "calibration_sha256": core["calibration_sha256"],
            "selection_sha256": core["selection_sha256"],
            "pair_schedule_sha256": core["pair_schedule_sha256"],
            "pair_diversity_sha256": core["pair_diversity_sha256"],
            "decision_sha256": core["decision_sha256"],
            "target_labels_used_for_W52": 0,
            "W52_model_refits": 0,
            "new_solver_stages": 0,
            "candidate_assignments_executed": 0,
        }
    )
    core["causal"] = build_causal(core)
    atomic_json(RESULT, core)
    report = (
        "# A445 — Cross-fitted raw-shape Reader transfer to W52\n\n"
        f"Evidence stage: **{evidence_stage}**\n\n"
        f"- Selected operator: **{selected}**\n"
        f"- Minimum held-block gain: **{selected_evaluation['minimum_fixed_block_bit_gain']:.9f} bits**\n"
        f"- Balanced two-corpus gain: **{selected_evaluation['balanced_two_corpus_bit_gain']:.9f} bits**\n"
        f"- All-128 gain: **{selected_evaluation['all128_bit_gain']:.9f} bits**\n"
        f"- Pair Spearman versus A442: **{comparisons['A442']['spearman_rank_correlation']:.9f}**\n"
        f"- Top-65,536 overlap versus A442: **{overlap_a442:.9f}**\n"
        f"- Qualified recovery trajectory: **{recovery_ready}**\n"
        f"- Pair-stream SHA-256: **{pair_stream_sha}**\n"
        "- W52 labels / refits / new stages / candidate executions: **0 / 0 / 0 / 0**\n"
        "- Authentic AI-native Causal gate: **4 explicit + 1 inferred**\n"
    )
    atomic_bytes(REPORT, report.encode())
    return core


def build_result(*, expected_implementation_sha256: str) -> dict[str, Any]:
    if any(path.exists() for path in (RESULT, CAUSAL, REPORT)):
        raise FileExistsError("A445 result already exists")
    try:
        return _build_result_once(expected_implementation_sha256=expected_implementation_sha256)
    except BaseException:
        RESULT.unlink(missing_ok=True)
        CAUSAL.unlink(missing_ok=True)
        REPORT.unlink(missing_ok=True)
        raise


def load_result(expected_sha256: str) -> dict[str, Any]:
    if file_sha256(RESULT) != expected_sha256:
        raise RuntimeError("A445 result hash differs")
    value = json.loads(RESULT.read_bytes())
    if (
        value.get("schema") != "chacha20-round20-w52-crossfit-raw-shape-reader-transfer-a445-v1"
        or value.get("attempt_id") != ATTEMPT_ID
        or value.get("selected_operator") not in OPERATORS
        or value.get("target_labels_used_for_W52") != 0
        or value.get("W52_model_refits") != 0
        or value.get("new_solver_stages") != 0
        or value.get("candidate_assignments_executed") != 0
    ):
        raise RuntimeError("A445 result semantics differ")
    exact_order(value["prefix_order"], AXIS_CELLS)
    exact_order(value["off_axis_order"], AXIS_CELLS)
    for row in value["anchors"].values():
        anchor(path_from_ref(row["path"]), row["sha256"])
    anchor(path_from_ref(value["causal"]["path"]), value["causal"]["sha256"])
    return value


def analyze() -> dict[str, Any]:
    payload: dict[str, Any] = {
        "attempt_id": ATTEMPT_ID,
        "design_sha256": file_sha256(DESIGN) if DESIGN.exists() else None,
        "implementation_frozen": IMPLEMENTATION.exists(),
        "result_complete": RESULT.exists(),
        "operators": list(OPERATORS),
        "pair_cells": PAIR_CELLS,
    }
    load_design()
    if IMPLEMENTATION.exists():
        payload["implementation_sha256"] = file_sha256(IMPLEMENTATION)
        load_implementation(payload["implementation_sha256"])
    if RESULT.exists():
        payload["result_sha256"] = file_sha256(RESULT)
        value = load_result(payload["result_sha256"])
        payload["evidence_stage"] = value["evidence_stage"]
        payload["selected_operator"] = value["selected_operator"]
        payload["recovery_ready"] = value["recovery_ready"]
    return payload


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    action = parser.add_mutually_exclusive_group(required=True)
    action.add_argument("--analyze", action="store_true")
    action.add_argument("--freeze-implementation", action="store_true")
    action.add_argument("--build-result", action="store_true")
    parser.add_argument("--expected-implementation-sha256")
    args = parser.parse_args()
    if args.freeze_implementation:
        payload = freeze_implementation()
    elif args.build_result:
        if not args.expected_implementation_sha256:
            parser.error("--build-result requires implementation hash")
        payload = build_result(expected_implementation_sha256=args.expected_implementation_sha256)
    else:
        payload = analyze()
    print(json.dumps(payload, indent=2, sort_keys=True), flush=True)


if __name__ == "__main__":
    main()

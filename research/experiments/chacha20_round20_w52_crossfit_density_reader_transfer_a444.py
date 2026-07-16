#!/usr/bin/env python3
"""A444: cross-fit a four-Reader density model and transfer it to W52."""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import inspect
import json
import math
import os
import sys
from itertools import combinations
from pathlib import Path
from typing import Any, Mapping, Sequence

import numpy as np

ROOT = Path(__file__).parents[2]
RESEARCH = ROOT / "research"
CONFIGS = RESEARCH / "configs"
RESULTS = RESEARCH / "results/v1"

DESIGN = (
    CONFIGS
    / "chacha20_round20_w52_crossfit_density_reader_transfer_a444_design_v1.json"
)
IMPLEMENTATION = (
    CONFIGS
    / "chacha20_round20_w52_crossfit_density_reader_transfer_a444_implementation_v1.json"
)
RESULT = RESULTS / "chacha20_round20_w52_crossfit_density_reader_transfer_a444_v1.json"
CAUSAL = RESULT.with_suffix(".causal")
REPORT = RESULT.with_suffix(".md")
TEST = ROOT / "tests/test_chacha20_round20_w52_crossfit_density_reader_transfer_a444.py"
REPRO = ROOT / "scripts/reproduce_chacha20_round20_w52_crossfit_density_reader_transfer_a444.sh"

A375_RUNNER = RESEARCH / "experiments/chacha20_round20_w46_wide_consensus_reader_a375.py"
A375_RESULT = RESULTS / "chacha20_round20_w46_wide_consensus_reader_a375_v1.json"
A375_CAUSAL = A375_RESULT.with_suffix(".causal")
A439_RUNNER = (
    RESEARCH
    / "experiments/chacha20_round20_w52_wide_consensus_dual_axis_wavefront_a439.py"
)
A439_RESULT = RESULTS / "chacha20_round20_w52_wide_consensus_dual_axis_wavefront_a439_v1.json"
A439_CAUSAL = A439_RESULT.with_suffix(".causal")
A442_RUNNER = (
    RESEARCH
    / "experiments/chacha20_round20_w52_knownkey_meta_reader_transfer_a442.py"
)
A442_RESULT = RESULTS / "chacha20_round20_w52_knownkey_meta_reader_transfer_a442_v1.json"
A442_CAUSAL = A442_RESULT.with_suffix(".causal")

ATTEMPT_ID = "A444"
DESIGN_SHA256 = "b6f842b04ba69ae50c8d93092816797a1e371d314e862107b2efd7555dd997f2"
A375_RUNNER_SHA256 = "e41a91b225b861abd669280a4044dddf5e2b24e8f6e8c66e7eee6d5a149ec9f1"
A375_RESULT_SHA256 = "fc7135af9e001eb8cd83a55902e48f5776dc24a4eb86a162d7d783a115b38ef1"
A375_CAUSAL_SHA256 = "adc5fc921da7c7429407fabc637ff03c27e15705fde6ea157fc31acae25f9825"
A439_RUNNER_SHA256 = "6cb94c2c8e8e404b25b2b41c51e4fd68b038e447616c740dba549464b5f490fb"
A439_RESULT_SHA256 = "b141fb882bd1a1cdc6a22de424370fe3118c9a4eb90565eaa0c8225321b9f869"
A439_CAUSAL_SHA256 = "f27c9d0d8311d633cfa46237df44ef1daa0cf375c99ddd1f85e37cc79f26f27c"
A442_RUNNER_SHA256 = "436f0e2a35949bb2007e7da95ec1558c134c2c30c4d077e72b4d2da81de27314"
A442_RESULT_SHA256 = "8c8222528dc3ef12ffc0fbda513061b39243daade51a70a17f0bd89c65b53b1d"
A442_CAUSAL_SHA256 = "89e079477ca230be5d2d6ba0231bf7833b29b5c6793076e5800622bf0b8ffb6b"
A442_BORDA_FIELD_SHA256 = "64cb6aad1f9621df5ff6ef44bb7e06cfc2dd86871483df83195382b2abf899b0"
A442_PAIR_STREAM_SHA256 = "b2b6e7a0b716083ae357e1dcde436a68e8ca64334ac5ec9009d74742989c6d48"

MODEL_ROLES = (
    "wide_vote",
    "sparse_reciprocal",
    "broad_quantile",
    "broad_intersection",
)
OPERATORS = (
    "borda_sum_baseline",
    "multiscale_vote",
    "dominance_count",
    "marginal_hist8_lr",
    "pairwise_hist4_lr",
    "joint_hist4_lr",
    "hierarchical_hist8_4_lr",
    "gaussian_logrank_shrink25_lr",
)
LEARNED_OPERATORS = frozenset(
    {
        "marginal_hist8_lr",
        "pairwise_hist4_lr",
        "joint_hist4_lr",
        "hierarchical_hist8_4_lr",
        "gaussian_logrank_shrink25_lr",
    }
)
PAIR_INDICES = tuple(combinations(range(len(MODEL_ROLES)), 2))
TARGETS = 128
CELLS = 256
BLOCKS = 8
BLOCK_SIZE = 16
AXIS_CELLS = 4096
PAIR_CELLS = 1 << 24
SCORE_DECIMALS = 12
MATERIAL_SPEARMAN_MAX = 0.98
MATERIAL_TOP65536_OVERLAP_MAX = 0.90
DOTCAUSAL_SRC = Path(
    "/Users/bhkmie/Documents/Forschung/O1/vendor/fabel/dotcausal_package/src"
)


def load_module(path: Path, name: str) -> Any:
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot import A444 dependency {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def canonical_sha256(value: Any) -> str:
    raw = json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("ascii")
    return hashlib.sha256(raw).hexdigest()


def atomic_bytes(path: Path, raw: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    temporary.write_bytes(raw)
    os.replace(temporary, path)


def atomic_json(path: Path, value: Any) -> None:
    atomic_bytes(
        path,
        json.dumps(
            value,
            indent=2,
            sort_keys=True,
            ensure_ascii=True,
            allow_nan=False,
        ).encode("ascii")
        + b"\n",
    )


def relative(path: Path) -> str:
    resolved = path.resolve()
    try:
        return str(resolved.relative_to(ROOT.resolve()))
    except ValueError:
        return str(resolved)


def path_from_ref(value: str | Path) -> Path:
    candidate = Path(value)
    return candidate if candidate.is_absolute() else ROOT / candidate


def anchor(path: Path, expected: str | None = None) -> dict[str, str]:
    observed = file_sha256(path)
    if expected is not None and observed != expected:
        raise RuntimeError(f"A444 anchor differs: {path}")
    return {"path": relative(path), "sha256": observed}


def exact_order(values: Sequence[int] | np.ndarray, cells: int) -> np.ndarray:
    order = np.asarray([int(value) for value in values], dtype=np.int64)
    if (
        order.shape != (cells,)
        or int(order.min(initial=0)) != 0
        or int(order.max(initial=-1)) != cells - 1
        or np.unique(order).size != cells
    ):
        raise ValueError("A444 order is not exact")
    return order


def order_to_ranks(values: Sequence[int] | np.ndarray, cells: int) -> np.ndarray:
    order = exact_order(values, cells)
    result = np.empty(cells, dtype=np.int64)
    result[order] = np.arange(1, cells + 1, dtype=np.int64)
    return result


def _lexicographic_order(
    primary: np.ndarray, secondary: Sequence[np.ndarray], cells: int
) -> np.ndarray:
    cell_ids = np.arange(cells, dtype=np.int64)
    keys: list[np.ndarray] = [cell_ids]
    keys.extend(np.asarray(key) for key in reversed(tuple(secondary)))
    keys.append(np.asarray(primary))
    return exact_order(np.lexsort(tuple(keys)), cells)


def _rank_matrix(value: np.ndarray) -> np.ndarray:
    ranks = np.asarray(value, dtype=np.int64)
    if ranks.ndim != 2 or ranks.shape[0] != len(MODEL_ROLES):
        raise ValueError("A444 rank matrix differs")
    cells = ranks.shape[1]
    if (
        cells < 2
        or np.any(ranks < 1)
        or any(np.unique(row).size != cells or int(row.max()) != cells for row in ranks)
    ):
        raise ValueError("A444 source rank row is not exact")
    return ranks


def _rank_bins(samples: np.ndarray, cells: int, bins: int) -> np.ndarray:
    values = np.asarray(samples, dtype=np.int64)
    if values.ndim != 2 or values.shape[1] != len(MODEL_ROLES):
        raise ValueError("A444 binned sample geometry differs")
    if np.any(values < 1) or np.any(values > cells):
        raise ValueError("A444 rank sample outside domain")
    return np.minimum(bins - 1, ((values - 1) * bins) // cells).astype(np.int16)


def _logrank_features(samples: np.ndarray, cells: int) -> np.ndarray:
    values = np.asarray(samples, dtype=np.float64)
    if values.ndim != 2 or values.shape[1] != len(MODEL_ROLES):
        raise ValueError("A444 Gaussian sample geometry differs")
    return np.log2((values - 0.5) / float(cells))


def _hist_lr(pos: np.ndarray, neg: np.ndarray, states: int) -> np.ndarray:
    alpha = 1.0
    pos_counts = np.bincount(pos.astype(np.int64), minlength=states).astype(np.float64)
    neg_counts = np.bincount(neg.astype(np.int64), minlength=states).astype(np.float64)
    pos_probability = (pos_counts + alpha) / (pos.size + alpha * states)
    neg_probability = (neg_counts + alpha) / (neg.size + alpha * states)
    return np.log(pos_probability) - np.log(neg_probability)


def _training_samples(
    target_ranks: np.ndarray, truths: np.ndarray, train_indices: Sequence[int]
) -> tuple[np.ndarray, np.ndarray]:
    ranks = np.asarray(target_ranks, dtype=np.int64)
    labels = np.asarray(truths, dtype=np.int64)
    indices = np.asarray([int(value) for value in train_indices], dtype=np.int64)
    if ranks.shape != (TARGETS, len(MODEL_ROLES), CELLS) or labels.shape != (TARGETS,):
        raise ValueError("A444 training panel geometry differs")
    if (
        indices.ndim != 1
        or indices.size == 0
        or np.unique(indices).size != indices.size
        or np.any(indices < 0)
        or np.any(indices >= TARGETS)
    ):
        raise ValueError("A444 training index cover differs")
    positive = np.stack([ranks[target, :, labels[target]] for target in indices])
    negative_rows: list[np.ndarray] = []
    cells = np.arange(CELLS, dtype=np.int64)
    for target in indices:
        negative_rows.append(ranks[target][:, cells != labels[target]].T)
    negative = np.concatenate(negative_rows, axis=0)
    if positive.shape != (indices.size, len(MODEL_ROLES)) or negative.shape != (
        indices.size * (CELLS - 1),
        len(MODEL_ROLES),
    ):
        raise RuntimeError("A444 positive/negative sample cover differs")
    return positive, negative


def _gaussian_parameters(samples: np.ndarray) -> dict[str, Any]:
    values = np.asarray(samples, dtype=np.float64)
    mean = values.mean(axis=0)
    covariance = np.cov(values, rowvar=False, ddof=1)
    diagonal = np.diag(np.diag(covariance))
    covariance = 0.75 * covariance + 0.25 * diagonal
    covariance += np.eye(values.shape[1], dtype=np.float64) * 1e-6
    sign, logdet = np.linalg.slogdet(covariance)
    if sign <= 0.0 or not np.isfinite(logdet):
        raise RuntimeError("A444 Gaussian covariance is not positive definite")
    inverse = np.linalg.inv(covariance)
    return {
        "mean": mean.tolist(),
        "covariance": covariance.tolist(),
        "inverse": inverse.tolist(),
        "logdet": float(logdet),
    }


def fit_operator(
    operator: str,
    target_ranks: np.ndarray,
    truths: np.ndarray,
    train_indices: Sequence[int],
) -> dict[str, Any]:
    if operator not in OPERATORS:
        raise ValueError(f"A444 unknown operator {operator}")
    indices = [int(value) for value in train_indices]
    base: dict[str, Any] = {
        "operator": operator,
        "training_target_indices": indices,
        "training_targets": len(indices),
        "score_quantization_decimals": SCORE_DECIMALS,
    }
    if operator not in LEARNED_OPERATORS:
        base["family"] = "fixed_rank_geometry"
        base["model_sha256"] = canonical_sha256(base)
        return base
    positive, negative = _training_samples(target_ranks, truths, indices)
    base.update(
        {
            "family": "crossfit_density_ratio",
            "positive_samples": int(positive.shape[0]),
            "negative_samples": int(negative.shape[0]),
        }
    )
    if operator in {"marginal_hist8_lr", "hierarchical_hist8_4_lr"}:
        bins = 8
        pos_bins = _rank_bins(positive, CELLS, bins)
        neg_bins = _rank_bins(negative, CELLS, bins)
        base["marginal_bins"] = bins
        base["marginal_log_lr"] = [
            _hist_lr(pos_bins[:, role], neg_bins[:, role], bins).tolist()
            for role in range(len(MODEL_ROLES))
        ]
    if operator in {"pairwise_hist4_lr", "hierarchical_hist8_4_lr"}:
        bins = 4
        pos_bins = _rank_bins(positive, CELLS, bins)
        neg_bins = _rank_bins(negative, CELLS, bins)
        base["pairwise_bins"] = bins
        tables: list[dict[str, Any]] = []
        for left, right in PAIR_INDICES:
            pos_code = pos_bins[:, left] * bins + pos_bins[:, right]
            neg_code = neg_bins[:, left] * bins + neg_bins[:, right]
            tables.append(
                {
                    "roles": [left, right],
                    "log_lr": _hist_lr(pos_code, neg_code, bins * bins).tolist(),
                }
            )
        base["pairwise_log_lr"] = tables
        if operator == "hierarchical_hist8_4_lr":
            base["pairwise_weight"] = 0.5
    if operator == "joint_hist4_lr":
        bins = 4
        pos_bins = _rank_bins(positive, CELLS, bins)
        neg_bins = _rank_bins(negative, CELLS, bins)
        multipliers = np.asarray([bins**3, bins**2, bins, 1], dtype=np.int64)
        pos_code = pos_bins.astype(np.int64) @ multipliers
        neg_code = neg_bins.astype(np.int64) @ multipliers
        base["joint_bins"] = bins
        base["joint_log_lr"] = _hist_lr(pos_code, neg_code, bins**4).tolist()
    if operator == "gaussian_logrank_shrink25_lr":
        base["positive_gaussian"] = _gaussian_parameters(
            _logrank_features(positive, CELLS)
        )
        base["negative_gaussian"] = _gaussian_parameters(
            _logrank_features(negative, CELLS)
        )
        base["covariance_shrink_to_diagonal"] = 0.25
        base["diagonal_floor"] = 1e-6
    base["model_sha256"] = canonical_sha256(base)
    return base


def _gaussian_log_density(features: np.ndarray, parameters: Mapping[str, Any]) -> np.ndarray:
    values = np.asarray(features, dtype=np.float64)
    mean = np.asarray(parameters["mean"], dtype=np.float64)
    inverse = np.asarray(parameters["inverse"], dtype=np.float64)
    centered = values - mean
    quadratic = np.einsum("ni,ij,nj->n", centered, inverse, centered)
    return -0.5 * (quadratic + float(parameters["logdet"]))


def score_candidates(
    rank_matrix: np.ndarray, operator: str, model: Mapping[str, Any]
) -> np.ndarray:
    ranks = _rank_matrix(rank_matrix)
    cells = ranks.shape[1]
    samples = ranks.T
    score = np.zeros(cells, dtype=np.float64)
    if operator in {"marginal_hist8_lr", "hierarchical_hist8_4_lr"}:
        bins = int(model["marginal_bins"])
        binned = _rank_bins(samples, cells, bins)
        tables = np.asarray(model["marginal_log_lr"], dtype=np.float64)
        for role in range(len(MODEL_ROLES)):
            score += tables[role, binned[:, role]]
    if operator in {"pairwise_hist4_lr", "hierarchical_hist8_4_lr"}:
        bins = int(model["pairwise_bins"])
        binned = _rank_bins(samples, cells, bins)
        pair_score = np.zeros(cells, dtype=np.float64)
        for row in model["pairwise_log_lr"]:
            left, right = (int(value) for value in row["roles"])
            code = binned[:, left] * bins + binned[:, right]
            pair_score += np.asarray(row["log_lr"], dtype=np.float64)[code]
        score += pair_score * float(model.get("pairwise_weight", 1.0))
    if operator == "joint_hist4_lr":
        bins = int(model["joint_bins"])
        binned = _rank_bins(samples, cells, bins).astype(np.int64)
        multipliers = np.asarray([bins**3, bins**2, bins, 1], dtype=np.int64)
        code = binned @ multipliers
        score = np.asarray(model["joint_log_lr"], dtype=np.float64)[code]
    if operator == "gaussian_logrank_shrink25_lr":
        features = _logrank_features(samples, cells)
        score = _gaussian_log_density(
            features, model["positive_gaussian"]
        ) - _gaussian_log_density(features, model["negative_gaussian"])
    if operator not in LEARNED_OPERATORS:
        raise ValueError(f"A444 {operator} does not expose a learned score")
    if not np.isfinite(score).all():
        raise RuntimeError("A444 candidate score is nonfinite")
    return np.round(score, SCORE_DECIMALS)


def dominance_counts(rank_matrix: np.ndarray, chunk: int = 256) -> np.ndarray:
    ranks = _rank_matrix(rank_matrix).T
    cells = ranks.shape[0]
    result = np.empty(cells, dtype=np.int64)
    for start in range(0, cells, chunk):
        stop = min(cells, start + chunk)
        candidates = ranks[start:stop]
        no_worse = np.all(ranks[:, None, :] <= candidates[None, :, :], axis=2)
        strictly_better = np.any(ranks[:, None, :] < candidates[None, :, :], axis=2)
        result[start:stop] = np.count_nonzero(no_worse & strictly_better, axis=0)
    return result


def operator_order(
    rank_matrix: np.ndarray, operator: str, model: Mapping[str, Any]
) -> np.ndarray:
    ranks = _rank_matrix(rank_matrix)
    cells = ranks.shape[1]
    minimum = ranks.min(axis=0)
    maximum = ranks.max(axis=0)
    rank_sum = ranks.sum(axis=0)
    source_rows = [ranks[index] for index in range(ranks.shape[0])]
    if operator == "borda_sum_baseline":
        return _lexicographic_order(
            rank_sum, [maximum, minimum, *source_rows], cells
        )
    if operator == "multiscale_vote":
        thresholds = tuple(max(1, cells // divisor) for divisor in (16, 8, 4, 2))
        votes = [(ranks <= threshold).sum(axis=0) for threshold in thresholds]
        return _lexicographic_order(
            -votes[0],
            [-votes[1], -votes[2], -votes[3], rank_sum, maximum, minimum, *source_rows],
            cells,
        )
    if operator == "dominance_count":
        count = dominance_counts(ranks)
        return _lexicographic_order(
            count, [rank_sum, maximum, minimum, *source_rows], cells
        )
    if operator in LEARNED_OPERATORS:
        score = score_candidates(ranks, operator, model)
        return _lexicographic_order(
            -score, [rank_sum, maximum, minimum, *source_rows], cells
        )
    raise ValueError(f"A444 unknown operator {operator}")


def target_rank_tensor(model_fields: Mapping[str, np.ndarray]) -> np.ndarray:
    if set(model_fields) != set(MODEL_ROLES):
        raise ValueError("A444 model-field role cover differs")
    tensor = np.stack(
        [np.asarray(model_fields[role], dtype=np.int64) for role in MODEL_ROLES],
        axis=1,
    )
    if tensor.shape != (TARGETS, len(MODEL_ROLES), CELLS):
        raise ValueError("A444 calibration tensor geometry differs")
    return tensor


def crossfit_rank_field(
    target_ranks: np.ndarray, truths: np.ndarray, operator: str
) -> tuple[np.ndarray, list[dict[str, Any]]]:
    ranks = np.asarray(target_ranks, dtype=np.int64)
    labels = np.asarray(truths, dtype=np.int64)
    field = np.empty((TARGETS, CELLS), dtype=np.int16)
    exact = np.arange(1, CELLS + 1, dtype=np.int16)
    fold_ledger: list[dict[str, Any]] = []
    all_targets = np.arange(TARGETS, dtype=np.int64)
    for block in range(BLOCKS):
        start = block * BLOCK_SIZE
        stop = start + BLOCK_SIZE
        held = all_targets[start:stop]
        train = np.concatenate((all_targets[:start], all_targets[stop:]))
        if np.intersect1d(train, held).size or train.size != TARGETS - BLOCK_SIZE:
            raise RuntimeError("A444 crossfit partition leaks held targets")
        model = fit_operator(operator, ranks, labels, train.tolist())
        for target in held:
            order = operator_order(ranks[target], operator, model)
            field[target, order] = exact
        fold_ledger.append(
            {
                "held_block": block,
                "held_target_indices": held.tolist(),
                "training_targets": int(train.size),
                "training_target_index_sha256": hashlib.sha256(
                    train.astype(">u2", copy=False).tobytes()
                ).hexdigest(),
                "model_sha256": model["model_sha256"],
            }
        )
    if any(
        np.unique(field[target]).size != CELLS
        or int(field[target].min()) != 1
        or int(field[target].max()) != CELLS
        for target in range(TARGETS)
    ):
        raise RuntimeError("A444 crossfit rank field is not exact")
    return field, fold_ledger


def calibration_statistics(rank_field: np.ndarray, truths: np.ndarray) -> dict[str, Any]:
    field = np.asarray(rank_field, dtype=np.int16)
    labels = np.asarray(truths, dtype=np.int16)
    if field.shape != (TARGETS, CELLS) or labels.shape != (TARGETS,):
        raise ValueError("A444 calibration rank-field geometry differs")
    true_ranks = field[np.arange(TARGETS), labels].astype(np.int64)
    logs = np.log2(true_ranks.astype(np.float64))
    uniform = sum(math.log2(rank) for rank in range(1, CELLS + 1)) / CELLS
    blocks = [
        float(uniform - logs[start : start + BLOCK_SIZE].mean())
        for start in range(0, TARGETS, BLOCK_SIZE)
    ]
    corpus_size = TARGETS // 2
    corpus = [
        float(uniform - logs[:corpus_size].mean()),
        float(uniform - logs[corpus_size:].mean()),
    ]
    return {
        "truth_ranks": true_ranks.tolist(),
        "fixed_block_bit_gains": blocks,
        "minimum_fixed_block_bit_gain": min(blocks),
        "positive_fixed_block_count": sum(value > 0.0 for value in blocks),
        "corpus_bit_gains": corpus,
        "balanced_two_corpus_bit_gain": min(corpus),
        "all128_bit_gain": float(uniform - logs.mean()),
        "targets_at_or_above_median_rank": int(np.count_nonzero(true_ranks <= CELLS // 2)),
        "worst_rank": int(true_ranks.max()),
    }


def selection_key(row: Mapping[str, Any]) -> tuple[float | int, ...]:
    return (
        -float(row["minimum_fixed_block_bit_gain"]),
        -float(row["balanced_two_corpus_bit_gain"]),
        -float(row["all128_bit_gain"]),
        -int(row["targets_at_or_above_median_rank"]),
        int(row["worst_rank"]),
        OPERATORS.index(str(row["operator"])),
    )


def evaluate_operators(
    target_ranks: np.ndarray, truths: np.ndarray
) -> tuple[dict[str, Any], str, dict[str, np.ndarray]]:
    evaluations: dict[str, Any] = {}
    fields: dict[str, np.ndarray] = {}
    for operator in OPERATORS:
        field, folds = crossfit_rank_field(target_ranks, truths, operator)
        stats = calibration_statistics(field, truths)
        evaluations[operator] = {
            "operator": operator,
            "evaluation_mode": (
                "eight_fold_crossfit" if operator in LEARNED_OPERATORS else "fixed_no_fit"
            ),
            **stats,
            "rank_field_sha256": hashlib.sha256(field.tobytes()).hexdigest(),
            "fold_ledger": folds,
        }
        fields[operator] = field
    selected = min(OPERATORS, key=lambda name: selection_key(evaluations[name]))
    return evaluations, selected, fields


def load_design() -> dict[str, Any]:
    if file_sha256(DESIGN) != DESIGN_SHA256:
        raise RuntimeError("A444 design hash differs")
    value = json.loads(DESIGN.read_bytes())
    calibration = value.get("calibration_contract", {})
    transfer = value.get("W52_transfer_contract", {})
    boundary = value.get("information_boundary", {})
    if (
        value.get("schema")
        != "chacha20-round20-w52-crossfit-density-reader-transfer-a444-design-v1"
        or value.get("attempt_id") != ATTEMPT_ID
        or tuple(calibration.get("fixed_operator_order", [])) != OPERATORS
        or calibration.get("targets") != TARGETS
        or calibration.get("cells_per_target") != CELLS
        or calibration.get("fixed_blocks") != BLOCKS
        or calibration.get("score_quantization_decimals") != SCORE_DECIMALS
        or calibration.get("all_operator_families_and_hyperparameters_defined_before_evaluation")
        is not True
        or transfer.get("axis_cells") != AXIS_CELLS
        or transfer.get("pair_cells") != PAIR_CELLS
        or transfer.get("W52_target_labels_used") != 0
        or transfer.get("W52_model_refits") != 0
        or transfer.get("candidate_assignments_executed") != 0
        or boundary.get("A442_authentic_Causal_personally_read") is not True
        or boundary.get("A444_operator_results_known_before_design_freeze") is not False
        or boundary.get("A444_W52_orders_known_before_design_freeze") is not False
        or boundary.get("A444_target_labels_used") != 0
        or boundary.get("A444_W52_model_refits") != 0
        or boundary.get("A444_candidate_assignments_executed") != 0
    ):
        raise RuntimeError("A444 design semantics differ")
    anchors = value["source_anchors"]
    for key, item in anchors.items():
        if key.endswith("_path"):
            stem = key.removesuffix("_path")
            anchor(ROOT / item, anchors[f"{stem}_sha256"])
    return value


def load_sources() -> tuple[dict[str, Any], dict[str, Any], dict[str, Any], Any]:
    anchor(A375_RUNNER, A375_RUNNER_SHA256)
    anchor(A375_RESULT, A375_RESULT_SHA256)
    anchor(A375_CAUSAL, A375_CAUSAL_SHA256)
    anchor(A439_RUNNER, A439_RUNNER_SHA256)
    anchor(A439_RESULT, A439_RESULT_SHA256)
    anchor(A439_CAUSAL, A439_CAUSAL_SHA256)
    anchor(A442_RUNNER, A442_RUNNER_SHA256)
    anchor(A442_RESULT, A442_RESULT_SHA256)
    anchor(A442_CAUSAL, A442_CAUSAL_SHA256)
    a375 = json.loads(A375_RESULT.read_bytes())
    a439 = json.loads(A439_RESULT.read_bytes())
    a442 = json.loads(A442_RESULT.read_bytes())
    if (
        a375.get("schema") != "chacha20-round20-w46-wide-consensus-reader-a375-v1"
        or a375.get("candidate_assignments_executed") != 0
        or a439.get("schema")
        != "chacha20-round20-w52-wide-consensus-dual-axis-wavefront-a439-v1"
        or a439.get("target_labels_used") != 0
        or a439.get("reader_refits") != 0
        or a439.get("candidate_assignments_executed") != 0
        or a442.get("schema")
        != "chacha20-round20-w52-knownkey-meta-reader-transfer-a442-v1"
        or a442.get("selected_operator") != "borda_sum"
        or a442.get("operator_evaluations", {})
        .get("borda_sum", {})
        .get("rank_field_sha256")
        != A442_BORDA_FIELD_SHA256
        or a442.get("pair_stream_uint16be_uint16be_sha256")
        != A442_PAIR_STREAM_SHA256
        or a442.get("target_labels_used_for_W52") != 0
        or a442.get("reader_refits_on_W52") != 0
        or a442.get("candidate_assignments_executed") != 0
    ):
        raise RuntimeError("A444 source semantics differ")
    for axis_name in ("prefix", "off_axis"):
        axis = a439["axes"][axis_name]
        if set(axis["source_orders"]) != set(MODEL_ROLES):
            raise RuntimeError(f"A444 A439 {axis_name} source role cover differs")
        for role in MODEL_ROLES:
            exact_order(axis["source_orders"][role], AXIS_CELLS)
    exact_order(a442["prefix_order"], AXIS_CELLS)
    exact_order(a442["off_axis_order"], AXIS_CELLS)
    runtime = load_module(A442_RUNNER, "a444_a442_runtime")
    return a375, a439, a442, runtime


def reconstruct_panel(
    a375: Mapping[str, Any], runtime: Any
) -> tuple[np.ndarray, np.ndarray, list[str], dict[str, str]]:
    model_fields, truths, blocks, hashes = runtime.reconstruct_model_fields(a375)
    tensor = target_rank_tensor(model_fields)
    if np.asarray(truths).shape != (TARGETS,) or len(blocks) != BLOCKS:
        raise RuntimeError("A444 reconstructed panel differs")
    return tensor, np.asarray(truths, dtype=np.int16), list(blocks), dict(hashes)


def transfer_axis(
    source_orders: Mapping[str, Sequence[int]],
    operator: str,
    model: Mapping[str, Any],
    runtime: Any,
) -> dict[str, Any]:
    if set(source_orders) != set(MODEL_ROLES):
        raise ValueError("A444 W52 source-order role cover differs")
    rank_matrix = np.stack(
        [order_to_ranks(source_orders[role], AXIS_CELLS) for role in MODEL_ROLES]
    )
    order = operator_order(rank_matrix, operator, model)
    return {
        "order": order.tolist(),
        "order_uint16be_sha256": runtime.order_sha256(order),
        "first_16_cells": order[:16].tolist(),
        "last_16_cells": order[-16:].tolist(),
        "exact_cells": AXIS_CELLS,
    }


def freeze_implementation() -> dict[str, Any]:
    if IMPLEMENTATION.exists():
        raise FileExistsError("A444 implementation already exists")
    if any(path.exists() for path in (RESULT, CAUSAL, REPORT)):
        raise FileExistsError("A444 evaluation artifact exists before implementation freeze")
    design = load_design()
    a375, a439, a442, _runtime = load_sources()
    if not TEST.exists() or not REPRO.exists():
        raise FileNotFoundError("A444 tests and reproducer must precede freeze")
    payload: dict[str, Any] = {
        "schema": "chacha20-round20-w52-crossfit-density-reader-transfer-a444-implementation-v1",
        "attempt_id": ATTEMPT_ID,
        "commitment_state": "complete_crossfit_density_model_selection_transfer_and_authentic_Causal_code_frozen_before_any_A444_evaluation_W52_order_or_candidate_execution",
        "design_sha256": DESIGN_SHA256,
        "operators": list(OPERATORS),
        "learned_operators": sorted(LEARNED_OPERATORS),
        "model_role_order": list(MODEL_ROLES),
        "selection_key": design["calibration_contract"]["selection_key"],
        "source_A375_selection_commitment_sha256": a375["selection_commitment_sha256"],
        "source_A439_result_commitment_sha256": a439["result_commitment_sha256"],
        "source_A442_result_commitment_sha256": a442["result_commitment_sha256"],
        "A444_evaluation_available_at_freeze": False,
        "A444_W52_orders_available_at_freeze": False,
        "A426_A438_A440_A443_target_outcome_or_progress_read": False,
        "target_labels_used_for_W52": 0,
        "W52_model_refits": 0,
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
        raise RuntimeError("A444 implementation hash differs")
    value = json.loads(IMPLEMENTATION.read_bytes())
    if (
        value.get("schema")
        != "chacha20-round20-w52-crossfit-density-reader-transfer-a444-implementation-v1"
        or value.get("attempt_id") != ATTEMPT_ID
        or value.get("design_sha256") != DESIGN_SHA256
        or tuple(value.get("operators", [])) != OPERATORS
        or tuple(value.get("model_role_order", [])) != MODEL_ROLES
        or value.get("A444_evaluation_available_at_freeze") is not False
        or value.get("A444_W52_orders_available_at_freeze") is not False
        or value.get("A426_A438_A440_A443_target_outcome_or_progress_read") is not False
        or value.get("target_labels_used_for_W52") != 0
        or value.get("W52_model_refits") != 0
        or value.get("candidate_assignments_executed") != 0
    ):
        raise RuntimeError("A444 implementation semantics differ")
    for row in value["anchors"].values():
        anchor(path_from_ref(row["path"]), row["sha256"])
    unsigned = {
        key: item
        for key, item in value.items()
        if key != "implementation_commitment_sha256"
    }
    if value.get("implementation_commitment_sha256") != canonical_sha256(unsigned):
        raise RuntimeError("A444 implementation commitment differs")
    return value


def build_causal(payload: Mapping[str, Any]) -> dict[str, Any]:
    if str(DOTCAUSAL_SRC) not in sys.path:
        sys.path.insert(0, str(DOTCAUSAL_SRC))
    from dotcausal.io import CausalReader, CausalWriter

    recovery_ready = bool(payload["recovery_ready"])
    terminal = (
        "A444:crossfit_density_W52_recovery_ready"
        if recovery_ready
        else "A444:crossfit_density_representation_boundary"
    )
    writer = CausalWriter(api_id="a444dens")
    writer._rules = []
    writer.add_rule(
        name="four_readers_to_crossfit_density_atlas",
        description="Cross-fit five density-ratio families and three fixed geometries over eight disjoint held blocks.",
        pattern=["A375_four_positive_diverse_readers"],
        conclusion="A444_crossfit_density_operator_atlas",
        confidence_modifier=1.0,
    )
    writer.add_rule(
        name="crossfit_atlas_to_frozen_model",
        description="Apply the frozen worst-block-first selection key and refit only on the complete Known-key calibration corpus.",
        pattern=["A444_crossfit_density_operator_atlas"],
        conclusion="A444_selected_full_calibration_model",
        confidence_modifier=1.0,
    )
    writer.add_rule(
        name="frozen_model_to_target_blind_W52_schedule",
        description="Apply the committed normalized-rank model identically to both W52 axes with no target label or W52 refit.",
        pattern=["A444_selected_full_calibration_model", "A439_eight_W52_source_orders"],
        conclusion="A444_complete_W52_pair_schedule",
        confidence_modifier=1.0,
    )
    writer.add_rule(
        name="crossfit_and_pair_diversity_to_execution_decision",
        description="Require eight positive held blocks, nonbaseline selection and exact complete-pair diversity before opening another recovery trajectory.",
        pattern=["A444_complete_W52_pair_schedule"],
        conclusion=terminal.replace(":", "_"),
        confidence_modifier=1.0,
    )
    writer.add_triplet(
        trigger="A375:four_positive_diverse_readers",
        mechanism="eight_operator_crossfit_density_ratio_and_multiobjective_atlas",
        outcome="A444:crossfit_density_operator_atlas",
        confidence=1.0,
        source=payload["calibration_sha256"],
        quantification=json.dumps(payload["operator_summary"], sort_keys=True),
        evidence=json.dumps(payload["calibration_contract"], sort_keys=True),
        domain="Known-key full-round ChaCha20 Reader calibration",
        quality_score=1.0,
    )
    writer.add_triplet(
        trigger="A444:crossfit_density_operator_atlas",
        mechanism="minimum_held_block_gain_then_balanced_corpus_frozen_selection_key",
        outcome="A444:selected_full_calibration_model",
        confidence=1.0,
        source=payload["selection_sha256"],
        quantification=payload["selected_operator"],
        evidence=payload["selected_full_model_sha256"],
        domain="cross-fitted nonlinear Reader selection",
        quality_score=1.0,
    )
    writer.add_triplet(
        trigger="A444:selected_full_calibration_model",
        mechanism="normalized_rank_density_transfer_without_target_labels_or_W52_refits",
        outcome="A444:complete_W52_pair_schedule",
        confidence=1.0,
        source=payload["pair_schedule_sha256"],
        quantification=json.dumps(payload["W52_transfer"], sort_keys=True),
        evidence=payload["pair_stream_uint16be_uint16be_sha256"],
        domain="target-blind full-round ChaCha20 W52 ordering",
        quality_score=1.0,
    )
    writer.add_triplet(
        trigger="A444:complete_W52_pair_schedule",
        mechanism="held_block_retention_plus_exact_pair_diversity_gate",
        outcome=terminal,
        confidence=1.0,
        source=payload["decision_sha256"],
        quantification=json.dumps(payload["decision"], sort_keys=True),
        evidence=str(recovery_ready),
        domain="W52 recovery trajectory decision",
        quality_score=1.0,
    )
    writer.add_triplet(
        trigger="A375:four_positive_diverse_readers",
        mechanism="materialized_crossfit_density_transfer_decision_closure",
        outcome=terminal,
        confidence=1.0,
        source="materialized:A444_crossfit_density_chain",
        quantification="exact retained closure",
        evidence=payload["evidence_stage"],
        domain="AI-native retained inference",
        quality_score=1.0,
        is_inferred=True,
    )
    writer.add_cluster(
        name="A444 crossfit density Reader transfer",
        entities=[
            "A375:four_positive_diverse_readers",
            "A444:crossfit_density_operator_atlas",
            "A444:selected_full_calibration_model",
            "A444:complete_W52_pair_schedule",
            terminal,
        ],
    )
    writer.add_gap(
        subject=terminal,
        predicate="next_required_object",
        expected_object_type=(
            "qualified_recovery_execution"
            if recovery_ready
            else "non_rank_feature_family"
        ),
        confidence=1.0,
        suggested_queries=[
            (
                "Freeze the selected model and execute it only after the higher-priority queued recovery schedules close."
                if recovery_ready
                else "The cross-fitted rank copula did not open a qualified trajectory; move to propagation or contradiction features."
            )
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
        reader.api_id != "a444dens"
        or len(explicit) != 4
        or len(all_rows) != 5
        or len(inferred) != 1
        or len(reader._rules) != 4
        or len(reader._clusters) != 1
        or len(reader._gaps) != 1
    ):
        raise RuntimeError("A444 authentic Causal reopen gate failed")
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
        raise FileExistsError("A444 result already exists")
    design = load_design()
    implementation = load_implementation(expected_implementation_sha256)
    a375, a439, a442, runtime = load_sources()
    target_ranks, truths, blocks, reconstructed_hashes = reconstruct_panel(a375, runtime)
    evaluations, selected, fields = evaluate_operators(target_ranks, truths)
    if fields["borda_sum_baseline"].shape != (TARGETS, CELLS):
        raise RuntimeError("A444 Borda baseline field differs")
    if evaluations["borda_sum_baseline"]["rank_field_sha256"] != A442_BORDA_FIELD_SHA256:
        raise RuntimeError("A444 Borda baseline does not reproduce A442")

    all_targets = list(range(TARGETS))
    selected_model = fit_operator(selected, target_ranks, truths, all_targets)
    selected_model_sha = selected_model["model_sha256"]
    prefix_sources = {
        role: a439["axes"]["prefix"]["source_orders"][role]
        for role in MODEL_ROLES
    }
    off_sources = {
        role: a439["axes"]["off_axis"]["source_orders"][role]
        for role in MODEL_ROLES
    }
    prefix = transfer_axis(prefix_sources, selected, selected_model, runtime)
    off_axis = transfer_axis(off_sources, selected, selected_model, runtime)
    pair_stream_sha = runtime.pair_stream_sha256(prefix["order"], off_axis["order"])
    selected_pair_rank = runtime.reference_square_rank_vector(
        prefix["order"], off_axis["order"]
    )
    a439_pair_rank = runtime.reference_square_rank_vector(
        a439["axes"]["prefix"]["portfolio_order"],
        a439["axes"]["off_axis"]["portfolio_order"],
    )
    comparison_a439 = runtime.compare_rank_orders(selected_pair_rank, a439_pair_rank)
    del a439_pair_rank
    a442_pair_rank = runtime.reference_square_rank_vector(
        a442["prefix_order"], a442["off_axis_order"]
    )
    comparison_a442 = runtime.compare_rank_orders(selected_pair_rank, a442_pair_rank)
    del a442_pair_rank, selected_pair_rank
    top65536_overlap_a442 = (
        comparison_a442["top_k_overlap"]["65536"]["intersection"] / 65536
    )
    material_a442 = (
        comparison_a442["spearman_rank_correlation"] < MATERIAL_SPEARMAN_MAX
        or top65536_overlap_a442 < MATERIAL_TOP65536_OVERLAP_MAX
    )
    selected_evaluation = evaluations[selected]
    borda_evaluation = evaluations["borda_sum_baseline"]
    nonbaseline = selected != "borda_sum_baseline"
    eight_positive = selected_evaluation["positive_fixed_block_count"] == BLOCKS
    retained_minimum = (
        float(selected_evaluation["minimum_fixed_block_bit_gain"])
        >= float(borda_evaluation["minimum_fixed_block_bit_gain"])
    )
    recovery_ready = nonbaseline and eight_positive and retained_minimum and material_a442
    decision = {
        "selected_operator_is_nonbaseline": nonbaseline,
        "positive_held_blocks": selected_evaluation["positive_fixed_block_count"],
        "required_positive_held_blocks": BLOCKS,
        "selected_minimum_held_block_gain": selected_evaluation[
            "minimum_fixed_block_bit_gain"
        ],
        "borda_minimum_fixed_block_gain": borda_evaluation[
            "minimum_fixed_block_bit_gain"
        ],
        "minimum_gain_retained_or_improved": retained_minimum,
        "material_pair_diversity_vs_A442": material_a442,
        "top65536_overlap_vs_A442": top65536_overlap_a442,
        "recovery_ready": recovery_ready,
    }
    operator_summary = {
        operator: {
            key: value
            for key, value in evaluations[operator].items()
            if key
            not in {
                "truth_ranks",
                "fixed_block_bit_gains",
                "corpus_bit_gains",
                "fold_ledger",
            }
        }
        for operator in OPERATORS
    }
    evidence_stage = (
        "CROSSFIT_DENSITY_READER_RETAINED_MATERIALLY_ORTHOGONAL_W52_RECOVERY_READY"
        if recovery_ready
        else "CROSSFIT_DENSITY_READER_EXACT_REPRESENTATION_BOUNDARY_RETAINED"
    )
    calibration_contract = {
        "targets": TARGETS,
        "cells_per_target": CELLS,
        "fixed_blocks": BLOCKS,
        "targets_per_block": BLOCK_SIZE,
        "block_labels": blocks,
        "operator_families_frozen_before_evaluation": True,
        "learned_evaluation": "eight-fold block-exclusive crossfit",
        "score_quantization_decimals": SCORE_DECIMALS,
        "selection_key": design["calibration_contract"]["selection_key"],
        "reconstructed_model_rank_field_sha256": reconstructed_hashes,
        "borda_baseline_expected_sha256": A442_BORDA_FIELD_SHA256,
        "borda_baseline_observed_sha256": evaluations["borda_sum_baseline"][
            "rank_field_sha256"
        ],
    }
    transfer = {
        "selected_operator": selected,
        "selected_full_model_sha256": selected_model_sha,
        "prefix": {key: value for key, value in prefix.items() if key != "order"},
        "off_axis": {key: value for key, value in off_axis.items() if key != "order"},
        "prefix_comparison_to_A439": runtime.axis_comparison(
            prefix["order"], a439["axes"]["prefix"]["portfolio_order"]
        ),
        "off_axis_comparison_to_A439": runtime.axis_comparison(
            off_axis["order"], a439["axes"]["off_axis"]["portfolio_order"]
        ),
        "prefix_comparison_to_A442": runtime.axis_comparison(
            prefix["order"], a442["prefix_order"]
        ),
        "off_axis_comparison_to_A442": runtime.axis_comparison(
            off_axis["order"], a442["off_axis_order"]
        ),
        "pair_cells": PAIR_CELLS,
        "target_labels_used": 0,
        "W52_model_refits": 0,
        "candidate_assignments_executed": 0,
    }
    core: dict[str, Any] = {
        "schema": "chacha20-round20-w52-crossfit-density-reader-transfer-a444-v1",
        "attempt_id": ATTEMPT_ID,
        "evidence_stage": evidence_stage,
        "design_sha256": DESIGN_SHA256,
        "implementation_sha256": expected_implementation_sha256,
        "implementation_commitment_sha256": implementation[
            "implementation_commitment_sha256"
        ],
        "calibration_contract": calibration_contract,
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
        "pair_comparison_to_A439": comparison_a439,
        "pair_comparison_to_A442": comparison_a442,
        "material_pair_diversity_vs_A442": material_a442,
        "decision": decision,
        "recovery_ready": recovery_ready,
        "target_labels_used_for_W52": 0,
        "W52_model_refits": 0,
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
            "runner": anchor(Path(__file__)),
            "test": anchor(TEST),
            "reproducer": anchor(REPRO),
        },
    }
    core["calibration_sha256"] = canonical_sha256(
        {"contract": calibration_contract, "evaluations": evaluations}
    )
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
    core["pair_diversity_sha256"] = canonical_sha256(
        {"A439": comparison_a439, "A442": comparison_a442}
    )
    core["decision_sha256"] = canonical_sha256(decision)
    core["result_commitment_sha256"] = canonical_sha256(
        {
            "design_sha256": DESIGN_SHA256,
            "implementation_commitment_sha256": core[
                "implementation_commitment_sha256"
            ],
            "calibration_sha256": core["calibration_sha256"],
            "selection_sha256": core["selection_sha256"],
            "pair_schedule_sha256": core["pair_schedule_sha256"],
            "pair_diversity_sha256": core["pair_diversity_sha256"],
            "decision_sha256": core["decision_sha256"],
            "target_labels_used_for_W52": 0,
            "W52_model_refits": 0,
            "candidate_assignments_executed": 0,
        }
    )
    core["causal"] = build_causal(core)
    atomic_json(RESULT, core)
    report = (
        "# A444 — Cross-fitted density Reader transfer to W52\n\n"
        f"Evidence stage: **{evidence_stage}**\n\n"
        f"- Selected operator: **{selected}**\n"
        f"- Minimum held-block gain: **{selected_evaluation['minimum_fixed_block_bit_gain']:.9f} bits**\n"
        f"- Balanced two-corpus gain: **{selected_evaluation['balanced_two_corpus_bit_gain']:.9f} bits**\n"
        f"- All-128 gain: **{selected_evaluation['all128_bit_gain']:.9f} bits**\n"
        f"- Pair Spearman versus A439: **{comparison_a439['spearman_rank_correlation']:.9f}**\n"
        f"- Pair Spearman versus A442: **{comparison_a442['spearman_rank_correlation']:.9f}**\n"
        f"- Top-65,536 overlap versus A442: **{top65536_overlap_a442:.9f}**\n"
        f"- Qualified recovery trajectory: **{recovery_ready}**\n"
        f"- Pair-stream SHA-256: **{pair_stream_sha}**\n"
        "- W52 target labels / W52 refits / candidate executions: **0 / 0 / 0**\n"
        "- Authentic AI-native Causal gate: **4 explicit + 1 inferred**\n"
    )
    atomic_bytes(REPORT, report.encode())
    return core


def build_result(*, expected_implementation_sha256: str) -> dict[str, Any]:
    if any(path.exists() for path in (RESULT, CAUSAL, REPORT)):
        raise FileExistsError("A444 result already exists")
    try:
        return _build_result_once(
            expected_implementation_sha256=expected_implementation_sha256
        )
    except BaseException:
        RESULT.unlink(missing_ok=True)
        CAUSAL.unlink(missing_ok=True)
        REPORT.unlink(missing_ok=True)
        raise


def load_result(expected_sha256: str) -> dict[str, Any]:
    if file_sha256(RESULT) != expected_sha256:
        raise RuntimeError("A444 result hash differs")
    value = json.loads(RESULT.read_bytes())
    if (
        value.get("schema")
        != "chacha20-round20-w52-crossfit-density-reader-transfer-a444-v1"
        or value.get("attempt_id") != ATTEMPT_ID
        or value.get("selected_operator") not in OPERATORS
        or len(value.get("prefix_order", [])) != AXIS_CELLS
        or len(value.get("off_axis_order", [])) != AXIS_CELLS
        or value.get("target_labels_used_for_W52") != 0
        or value.get("W52_model_refits") != 0
        or value.get("candidate_assignments_executed") != 0
    ):
        raise RuntimeError("A444 result semantics differ")
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
        payload = build_result(
            expected_implementation_sha256=args.expected_implementation_sha256
        )
    else:
        payload = analyze()
    print(json.dumps(payload, indent=2, sort_keys=True), flush=True)


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""A408: nested Fisher learning over complete W50 Direct12 fields."""

from __future__ import annotations

import argparse
import importlib.util
import inspect
import json
import os
import sys
from collections import Counter
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

import numpy as np

ROOT = Path(__file__).parents[2]
RESEARCH = ROOT / "research"
CONFIGS = RESEARCH / "configs"
RESULTS = RESEARCH / "results/v1"

DESIGN = CONFIGS / "chacha20_round20_w50_knownkey_nested_fisher_reader_a408_design_v1.json"
IMPLEMENTATION = (
    CONFIGS / "chacha20_round20_w50_knownkey_nested_fisher_reader_a408_implementation_v1.json"
)
RESULT = RESULTS / "chacha20_round20_w50_knownkey_nested_fisher_reader_a408_v1.json"
CAUSAL = RESULT.with_suffix(".causal")
REPORT = RESULT.with_suffix(".md")
TEST = ROOT / "tests/test_chacha20_round20_w50_knownkey_nested_fisher_reader_a408.py"
REPRO = ROOT / "scripts/reproduce_chacha20_round20_w50_knownkey_nested_fisher_reader_a408.sh"

A406_RUNNER = RESEARCH / "experiments/chacha20_round20_w50_knownkey_weighted_reader_a406.py"
A401_RUNNER = RESEARCH / "experiments/chacha20_round20_w50_knownkey_direct12_learning_a401.py"
A406_RESULT = RESULTS / "chacha20_round20_w50_knownkey_weighted_reader_a406_v1.json"
A388_ORDER = RESULTS / "chacha20_round20_w50_public_output_direct12_factor3_a388_order_v1.json"

ATTEMPT_ID = "A408"
DESIGN_SHA256 = "92e95a7a45025f5fdbb88d755f0a10b034e4f96bc2a07fe97cd6b53b38edb037"
A406_RUNNER_SHA256 = "7db8f5234cc2d03c685d2f42babe1274438add56cc0bcde28f66c2e32520e2b9"
A406_IMPLEMENTATION_SHA256 = "f6a6e539ee84e03899817e072d09d2b55756419580113990f629f358e93b9236"
A401_RUNNER_SHA256 = "2238b99504883cd0b722b7b92254b3dc02255a6b53c9851f35264daad3f21bee"
A401_IMPLEMENTATION_SHA256 = "4a08686d34674525bd08938d96783c6772ce4cd004fffbe04d11dc972cf63df1"
A401_PROTOCOL_SHA256 = "18aaad488842ce9fb52a77cef01c89bfeb8c901001a86fd56e23bbf594c7a4f3"
A388_ORDER_SHA256 = "3c56ce8521b1ced20e1e3a90999810c2e563c4de941701c86274f0828b5d01b8"
FEATURE_FAMILIES = (
    ("rank_log_16", 16),
    ("rank_log_recip_24", 24),
    ("rank_log_recip_absdiff_52", 52),
    ("rank_log_recip_absdiff_product_80", 80),
)
LAMBDAS = (0.0001, 0.001, 0.01, 0.1, 1.0, 10.0, 100.0)
CANDIDATE_COUNT = len(FEATURE_FAMILIES) * len(LAMBDAS)
DOTCAUSAL_SRC = Path("/Users/bhkmie/Documents/Forschung/O1/vendor/fabel/dotcausal_package/src")


def load_module(path: Path, name: str) -> Any:
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot import A408 dependency {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


A406 = load_module(A406_RUNNER, "a408_a406")
A401 = A406.A401
A402 = A406.A402

file_sha256 = A401.file_sha256
canonical_sha256 = A401.canonical_sha256
atomic_json = A401.atomic_json
atomic_bytes = A401.atomic_bytes
relative = A401.relative
path_from_ref = A401.path_from_ref
anchor = A401.anchor

TARGETS = A401.TARGETS
VIEW_NAMES = A401.VIEW_NAMES
CELLS = A401.CELLS
PAIRS = tuple(
    (left, right) for left in range(len(VIEW_NAMES)) for right in range(left + 1, len(VIEW_NAMES))
)


def candidate_rows() -> list[dict[str, Any]]:
    rows = []
    for family_index, (family, dimension) in enumerate(FEATURE_FAMILIES):
        for lambda_index, ridge_lambda in enumerate(LAMBDAS):
            rows.append(
                {
                    "feature_family": family,
                    "feature_family_index": family_index,
                    "feature_dimension": dimension,
                    "ridge_lambda": ridge_lambda,
                    "ridge_lambda_index": lambda_index,
                }
            )
    if len(rows) != CANDIDATE_COUNT:
        raise RuntimeError("A408 candidate family size differs")
    return rows


def feature_matrix(rank_matrix: np.ndarray) -> np.ndarray:
    ranks = np.asarray(rank_matrix, dtype=np.float64)
    if ranks.ndim != 2 or ranks.shape[0] != len(VIEW_NAMES):
        raise ValueError("A408 rank matrix shape differs")
    if np.any(ranks <= 0):
        raise ValueError("A408 ranks must be positive")
    rank = (ranks / float(ranks.shape[1])).T
    log = (np.log2(ranks) / np.log2(float(ranks.shape[1]))).T
    reciprocal = np.reciprocal(np.sqrt(ranks)).T
    absdiff = np.stack([np.abs(log[:, left] - log[:, right]) for left, right in PAIRS], axis=1)
    product = np.stack([log[:, left] * log[:, right] for left, right in PAIRS], axis=1)
    result = np.concatenate((rank, log, reciprocal, absdiff, product), axis=1)
    if result.shape != (ranks.shape[1], 80) or not np.isfinite(result).all():
        raise RuntimeError("A408 feature matrix differs")
    return result


def target_stats(features: np.ndarray, true_cell: int) -> dict[str, Any]:
    matrix = np.asarray(features, dtype=np.float64)
    if matrix.ndim != 2 or matrix.shape[1] != 80:
        raise ValueError("A408 target feature shape differs")
    if not 0 <= true_cell < matrix.shape[0]:
        raise ValueError("A408 true cell lies outside field")
    return {
        "count": matrix.shape[0],
        "sum": matrix.sum(axis=0),
        "xtx": np.dot(matrix.T, matrix),
        "positive": matrix[true_cell].copy(),
    }


def fit_directions(
    stats: Mapping[int, Mapping[str, Any]],
    train: Sequence[int],
    dimension: int,
) -> np.ndarray:
    indices = tuple(int(value) for value in train)
    if not indices or dimension not in {value for _name, value in FEATURE_FAMILIES}:
        raise ValueError("A408 Fisher fit contract differs")
    count = sum(int(stats[index]["count"]) for index in indices)
    total = sum(
        (np.asarray(stats[index]["sum"], dtype=np.float64)[:dimension] for index in indices),
        start=np.zeros(dimension, dtype=np.float64),
    )
    xtx = sum(
        (
            np.asarray(stats[index]["xtx"], dtype=np.float64)[:dimension, :dimension]
            for index in indices
        ),
        start=np.zeros((dimension, dimension), dtype=np.float64),
    )
    positive = sum(
        (np.asarray(stats[index]["positive"], dtype=np.float64)[:dimension] for index in indices),
        start=np.zeros(dimension, dtype=np.float64),
    )
    mean_background = total / count
    covariance = xtx / count - np.outer(mean_background, mean_background)
    covariance = (covariance + covariance.T) * 0.5
    delta = positive / len(indices) - mean_background
    scale = float(np.trace(covariance) / dimension)
    if not np.isfinite(scale) or scale <= 0:
        raise RuntimeError("A408 covariance ridge scale differs")
    eigenvalues, eigenvectors = np.linalg.eigh(covariance)
    eigenvalues = np.maximum(eigenvalues, 0.0)
    projected = np.dot(eigenvectors.T, delta)
    directions = np.column_stack(
        [
            np.dot(
                eigenvectors,
                projected / (eigenvalues + ridge_lambda * scale),
            )
            for ridge_lambda in LAMBDAS
        ]
    )
    magnitudes = np.max(np.abs(directions), axis=0)
    if np.any(magnitudes <= 0):
        raise RuntimeError("A408 Fisher direction magnitude differs")
    directions = directions / magnitudes
    if directions.shape != (dimension, len(LAMBDAS)) or not np.isfinite(directions).all():
        raise RuntimeError("A408 Fisher directions differ")
    return directions


def true_ranks_for_directions(
    features: np.ndarray, true_cell: int, directions: np.ndarray
) -> np.ndarray:
    matrix = np.asarray(features, dtype=np.float64)
    weights = np.asarray(directions, dtype=np.float64)
    if matrix.ndim != 2 or weights.ndim != 2 or matrix.shape[1] != weights.shape[0]:
        raise ValueError("A408 scoring shape differs")
    scores = np.dot(matrix, weights)
    truth = scores[true_cell]
    cells = np.arange(matrix.shape[0])[:, None]
    better = scores > truth
    tied_lower = (scores == truth) & (cells < true_cell)
    return 1 + np.count_nonzero(better | tied_lower, axis=0)


def select_candidate(
    candidates: Sequence[Mapping[str, Any]], truth: np.ndarray, rows: Sequence[int]
) -> int:
    if len(candidates) != CANDIDATE_COUNT or truth.shape[1] != CANDIDATE_COUNT:
        raise ValueError("A408 selection table differs")
    values = truth[np.asarray(tuple(rows), dtype=np.int64)]
    mean_log = np.log2(values.astype(np.float64)).mean(axis=0)
    worst = values.max(axis=0)
    return min(
        range(CANDIDATE_COUNT),
        key=lambda index: (
            float(mean_log[index]),
            int(worst[index]),
            int(candidates[index]["feature_dimension"]),
            int(candidates[index]["ridge_lambda_index"]),
        ),
    )


def load_design() -> dict[str, Any]:
    if file_sha256(DESIGN) != DESIGN_SHA256:
        raise RuntimeError("A408 design hash differs")
    value = json.loads(DESIGN.read_bytes())
    corpus = value.get("corpus_contract", {})
    feature = value.get("feature_contract", {})
    model = value.get("model_contract", {})
    production = value.get("production_contract", {})
    boundary = value.get("information_boundary", {})
    if (
        value.get("schema") != "chacha20-round20-w50-knownkey-nested-fisher-reader-a408-design-v1"
        or value.get("attempt_id") != ATTEMPT_ID
        or value.get("design_state")
        != "frozen_during_A401_measurement_before_A401_selection_result_A406_result_or_any_A408_label_score"
        or tuple(corpus.get("target_indices", [])) != TARGETS
        or corpus.get("outer_folds") != len(TARGETS)
        or corpus.get("inner_folds_per_outer_fold") != len(TARGETS) - 1
        or tuple(feature.get("base_view_order", [])) != VIEW_NAMES
        or tuple(feature.get("feature_family_order", []))
        != tuple(name for name, _dimension in FEATURE_FAMILIES)
        or tuple(model.get("ridge_lambda_order", [])) != LAMBDAS
        or model.get("candidate_count") != CANDIDATE_COUNT
        or production.get("target_labels_used") != 0
        or production.get("new_solver_stages") != 0
        or boundary.get("A401_selection_holdout_or_result_available_at_design_freeze") is not False
        or boundary.get("A406_result_or_weighted_score_available_at_design_freeze") is not False
        or boundary.get("A408_label_scores_available_at_design_freeze") is not False
    ):
        raise RuntimeError("A408 frozen design semantics differ")
    for key, source_path in value["source_anchors"].items():
        if key.endswith("_path"):
            expected = value["source_anchors"][key.removesuffix("_path") + "_sha256"]
            anchor(ROOT / source_path, expected)
    return value


def freeze_implementation() -> dict[str, Any]:
    if any(path.exists() for path in (IMPLEMENTATION, RESULT, CAUSAL, REPORT)):
        raise FileExistsError("A408 implementation or result already exists")
    if A401.SELECTION.exists() or A401.RESULT.exists() or A406_RESULT.exists():
        raise RuntimeError("A408 code freeze must precede A401 and A406 results")
    load_design()
    candidates = candidate_rows()
    if not TEST.exists() or not REPRO.exists():
        raise FileNotFoundError("A408 test and reproducer must precede freeze")
    payload: dict[str, Any] = {
        "schema": "chacha20-round20-w50-knownkey-nested-fisher-reader-a408-implementation-v1",
        "attempt_id": ATTEMPT_ID,
        "commitment_state": "complete_nested_fisher_code_frozen_before_A401_A406_results_or_A408_label_score",
        "design_sha256": DESIGN_SHA256,
        "feature_dimension": 80,
        "candidate_count": len(candidates),
        "candidate_family_commitment_sha256": canonical_sha256(candidates),
        "A401_A406_results_available_at_freeze": False,
        "A408_label_scores_available_at_freeze": False,
        "anchors": {
            "design": anchor(DESIGN, DESIGN_SHA256),
            "A401_design": anchor(A401.DESIGN, A401.DESIGN_SHA256),
            "A401_runner": anchor(A401_RUNNER, A401_RUNNER_SHA256),
            "A401_implementation": anchor(A401.IMPLEMENTATION, A401_IMPLEMENTATION_SHA256),
            "A401_public_corpus": anchor(A401.PROTOCOL, A401_PROTOCOL_SHA256),
            "A406_runner": anchor(A406_RUNNER, A406_RUNNER_SHA256),
            "A406_implementation": anchor(A406.IMPLEMENTATION, A406_IMPLEMENTATION_SHA256),
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
        raise RuntimeError("A408 implementation hash differs")
    value = json.loads(IMPLEMENTATION.read_bytes())
    if (
        value.get("schema")
        != "chacha20-round20-w50-knownkey-nested-fisher-reader-a408-implementation-v1"
        or value.get("attempt_id") != ATTEMPT_ID
        or value.get("commitment_state")
        != "complete_nested_fisher_code_frozen_before_A401_A406_results_or_A408_label_score"
        or value.get("feature_dimension") != 80
        or value.get("candidate_count") != CANDIDATE_COUNT
        or value.get("A401_A406_results_available_at_freeze") is not False
        or value.get("A408_label_scores_available_at_freeze") is not False
    ):
        raise RuntimeError("A408 implementation semantics differ")
    for row in value["anchors"].values():
        anchor(path_from_ref(row["path"]), row["sha256"])
    unsigned = {
        key: item for key, item in value.items() if key != "implementation_commitment_sha256"
    }
    if value.get("implementation_commitment_sha256") != canonical_sha256(unsigned):
        raise RuntimeError("A408 implementation commitment differs")
    return value


def load_a406_result(expected_sha256: str) -> dict[str, Any]:
    if file_sha256(A406_RESULT) != expected_sha256:
        raise RuntimeError("A408 A406 result hash differs")
    value = json.loads(A406_RESULT.read_bytes())
    ranks = value.get("leaveoneout", {}).get("weighted_panel", {}).get("ranks", [])
    if (
        value.get("schema") != "chacha20-round20-w50-knownkey-weighted-reader-a406-result-v1"
        or value.get("attempt_id") != "A406"
        or len(ranks) != len(TARGETS)
        or any(not 1 <= int(rank) <= CELLS for rank in ranks)
        or value.get("production_target_labels_used") != 0
        or value.get("new_solver_stages") != 0
    ):
        raise RuntimeError("A408 A406 baseline semantics differ")
    return value


def nested_evaluate(
    features: Mapping[int, np.ndarray], true_cells: Mapping[int, int]
) -> dict[str, Any]:
    candidates = candidate_rows()
    stats = {index: target_stats(features[index], int(true_cells[index])) for index in TARGETS}
    prospective = np.empty((len(TARGETS), CANDIDATE_COUNT), dtype=np.int64)
    for heldout in TARGETS:
        train = tuple(index for index in TARGETS if index != heldout)
        for family_index, (_family, dimension) in enumerate(FEATURE_FAMILIES):
            directions = fit_directions(stats, train, dimension)
            ranks = true_ranks_for_directions(
                features[heldout][:, :dimension],
                int(true_cells[heldout]),
                directions,
            )
            start = family_index * len(LAMBDAS)
            prospective[heldout, start : start + len(LAMBDAS)] = ranks

    folds = []
    nested_ranks = []
    winners = []
    for outer_heldout in TARGETS:
        outer_train = tuple(index for index in TARGETS if index != outer_heldout)
        inner_truth = np.empty((len(outer_train), CANDIDATE_COUNT), dtype=np.int64)
        for row_index, inner_heldout in enumerate(outer_train):
            inner_train = tuple(index for index in outer_train if index != inner_heldout)
            for family_index, (_family, dimension) in enumerate(FEATURE_FAMILIES):
                directions = fit_directions(stats, inner_train, dimension)
                ranks = true_ranks_for_directions(
                    features[inner_heldout][:, :dimension],
                    int(true_cells[inner_heldout]),
                    directions,
                )
                start = family_index * len(LAMBDAS)
                inner_truth[row_index, start : start + len(LAMBDAS)] = ranks
        selected = select_candidate(candidates, inner_truth, tuple(range(len(outer_train))))
        outer_rank = int(prospective[outer_heldout, selected])
        nested_ranks.append(outer_rank)
        winners.append(selected)
        folds.append(
            {
                "outer_heldout_target": outer_heldout,
                "outer_training_targets": list(outer_train),
                "inner_selected_candidate_index": selected,
                "inner_selected_candidate": candidates[selected],
                "outer_heldout_rank": outer_rank,
                "inner_rank_panel": A401.metric_panel(inner_truth[:, selected]),
            }
        )
    fullfit_index = select_candidate(candidates, prospective, TARGETS)
    return {
        "folds": folds,
        "nested_panel": A401.metric_panel(nested_ranks),
        "nested_winner_frequency": dict(sorted(Counter(winners).items())),
        "prospective_fixed_candidate_rank_table_int32le_sha256": A401.sha256(
            prospective.astype("<i4").tobytes()
        ),
        "prospective_fixed_candidate_panels": [
            {
                **candidates[index],
                "ranks": [int(value) for value in prospective[:, index]],
                "panel": A401.metric_panel(prospective[:, index]),
            }
            for index in range(CANDIDATE_COUNT)
        ],
        "fullfit_candidate_index": fullfit_index,
        "fullfit_candidate": candidates[fullfit_index],
        "fullfit_crossvalidated_panel": A401.metric_panel(prospective[:, fullfit_index]),
        "stats": stats,
    }


def fit_full_model(
    evaluation: Mapping[str, Any],
    features: Mapping[int, np.ndarray],
    true_cells: Mapping[int, int],
) -> np.ndarray:
    candidate = evaluation["fullfit_candidate"]
    dimension = int(candidate["feature_dimension"])
    stats = {index: target_stats(features[index], int(true_cells[index])) for index in TARGETS}
    directions = fit_directions(stats, TARGETS, dimension)
    return directions[:, int(candidate["ridge_lambda_index"])]


def production_order(features: np.ndarray, direction: np.ndarray) -> list[int]:
    scores = np.dot(features[:, : direction.shape[0]], direction)
    cells = np.arange(features.shape[0], dtype=np.int64)
    order = np.lexsort((cells, -scores)).tolist()
    if len(order) != CELLS or set(order) != set(range(CELLS)):
        raise RuntimeError("A408 production order differs")
    return [int(value) for value in order]


def build_causal(payload: Mapping[str, Any]) -> dict[str, Any]:
    sys.path.insert(0, str(DOTCAUSAL_SRC))
    from dotcausal.io import CausalReader, CausalWriter

    qualified = bool(payload["comparison"]["qualified"])
    terminal = (
        "A408_nested_Fisher_qualified_production_order"
        if qualified
        else "A408_nested_Fisher_boundary_retained"
    )
    writer = CausalWriter(api_id="a408w50")
    writer._rules = []
    writer.add_rule(
        name="complete_fields_to_nested_Fisher_panel",
        description="Each outer key is scored by a Fisher Reader whose family and ridge were selected only through inner folds on the other fifteen keys.",
        pattern=["A401_sixteen_complete_fields", "A408_frozen_nested_Fisher_family"],
        conclusion="A408_nested_outoffold_panel",
        confidence_modifier=1.0,
    )
    writer.add_rule(
        name="nested_gate_to_production",
        description="Only strict improvement over A406 permits all-sixteen fit and zero-refit A388 application.",
        pattern=["A408_nested_outoffold_panel", "A406_weighted_outoffold_panel"],
        conclusion=terminal,
        confidence_modifier=1.0,
    )
    writer.add_triplet(
        trigger="A401:sixteen_complete_knownkey_fields",
        mechanism="nested_background_covariance_Fisher_learning",
        outcome="A408:nested_outoffold_panel",
        confidence=1.0,
        source=payload["measurement_sha256"],
        quantification=json.dumps(payload["nested_evaluation"], sort_keys=True),
        evidence="A408 design and code froze before any A401, A406 or A408 label score",
        domain="nested learned W50 Fisher Reader",
        quality_score=1.0,
    )
    writer.add_triplet(
        trigger="A408:nested_outoffold_panel",
        mechanism="strict_A406_gate_then_all_sixteen_fit_zero_refit_application",
        outcome=f"A408:{terminal}",
        confidence=1.0,
        source=payload["deployment_commitment_sha256"],
        quantification=json.dumps(payload["comparison"], sort_keys=True),
        evidence="zero production labels, refits, candidates, stages, or live outcomes",
        domain="nested Fisher production Reader",
        quality_score=1.0,
    )
    writer.add_triplet(
        trigger="A401:sixteen_complete_knownkey_fields",
        mechanism="materialized_nested_Fisher_to_production_chain",
        outcome=f"A408:{terminal}",
        confidence=1.0,
        source="materialized:A408_nested_Fisher_chain",
        quantification="exact retained closure",
        evidence="pre-result A408 design and implementation commitments",
        domain="AI-native retained inference",
        quality_score=1.0,
        is_inferred=True,
    )
    writer.add_cluster(
        name="A408 nested Fisher W50 Reader",
        entities=[
            "A401:sixteen_complete_knownkey_fields",
            "A408:nested_outoffold_panel",
            f"A408:{terminal}",
        ],
    )
    writer.add_gap(
        subject=f"A408:{terminal}",
        predicate="next_required_object",
        expected_object_type=(
            "deduplicated_complete_group_recovery"
            if qualified
            else "nonlinear_or_graph_regularized_readout"
        ),
        confidence=1.0,
        suggested_queries=[
            "Execute the distinct qualified order with matched control."
            if qualified
            else "Use nested fold residuals to freeze a nonlinear or graph-regularized Reader."
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
        reader.api_id != "a408w50"
        or len(explicit) != 2
        or len(all_rows) != 3
        or len(inferred) != 1
        or len(reader._rules) != 2
        or len(reader._clusters) != 1
        or len(reader._gaps) != 1
    ):
        raise RuntimeError("A408 authentic Causal reopen gate failed")
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
            "nested_learning": explicit[0],
            "deployment": explicit[1],
            "terminal_chain": all_rows[-1],
            "next_gap": reader._gaps[0],
        },
    }


def materialize(
    *,
    expected_implementation_sha256: str,
    expected_a401_result_sha256: str,
    expected_a401_selection_sha256: str,
    expected_a406_result_sha256: str,
) -> dict[str, Any]:
    if RESULT.exists() or CAUSAL.exists() or REPORT.exists():
        raise FileExistsError("A408 result already exists")
    implementation = load_implementation(expected_implementation_sha256)
    a401_result, _selection = A402.load_a401_result(
        expected_result_sha256=expected_a401_result_sha256,
        expected_selection_sha256=expected_a401_selection_sha256,
    )
    a406 = load_a406_result(expected_a406_result_sha256)
    train = A401.load_label_file(
        A401.TRAIN_LABELS,
        "chacha20-round20-w50-knownkey-direct12-learning-a401-selection-labels-v1",
        A401.TRAIN_TARGETS,
    )
    holdout = A401.load_label_file(
        A401.HOLDOUT_LABELS,
        "chacha20-round20-w50-knownkey-direct12-learning-a401-holdout-labels-v1",
        A401.HOLDOUT_TARGETS,
    )
    labels = {**train, **holdout}
    features = {}
    field_commitments = {}
    for index in TARGETS:
        ranks, field_commitments[str(index)] = A401.view_rank_matrix(index)
        features[index] = feature_matrix(ranks)
    true_cells = {index: int(labels[index]["true_direct12_cell"]) for index in TARGETS}
    evaluation = nested_evaluate(features, true_cells)
    stats = evaluation.pop("stats")
    nested_panel = evaluation["nested_panel"]
    weighted_panel = a406["leaveoneout"]["weighted_panel"]
    factor = weighted_panel["geometric_mean_rank"] / nested_panel["geometric_mean_rank"]
    gain = (
        nested_panel["bit_gain_vs_complete_4096_cover"]
        - weighted_panel["bit_gain_vs_complete_4096_cover"]
    )
    qualified = factor > 1.0 and gain > 0.0
    comparison = {
        "qualified": qualified,
        "A406_weighted_ranks": weighted_panel["ranks"],
        "nested_Fisher_ranks": nested_panel["ranks"],
        "geometric_rank_improvement_factor": factor,
        "additional_bit_gain": gain,
        "nested_better_folds": sum(
            left < right
            for left, right in zip(nested_panel["ranks"], weighted_panel["ranks"], strict=True)
        ),
        "nested_equal_folds": sum(
            left == right
            for left, right in zip(nested_panel["ranks"], weighted_panel["ranks"], strict=True)
        ),
        "nested_worse_folds": sum(
            left > right
            for left, right in zip(nested_panel["ranks"], weighted_panel["ranks"], strict=True)
        ),
    }
    selected = evaluation["fullfit_candidate"] if qualified else None
    order = None
    production_metadata = None
    diversity = None
    direction_sha = None
    if selected is not None:
        direction = fit_full_model(evaluation, features, true_cells)
        direction_sha = A401.sha256(np.asarray(direction, dtype="<f8").tobytes())
        production_ranks, view_orders, production_metadata = A402.production_rank_matrix()
        order = production_order(feature_matrix(production_ranks), direction)
        diversity = {
            name: A401.A388.A351.diversity_panel(order, view_orders[name]) for name in VIEW_NAMES
        }
    stable_stats = {
        str(index): {
            "count": int(stats[index]["count"]),
            "sum_sha256": A401.sha256(np.asarray(stats[index]["sum"], dtype="<f8").tobytes()),
            "xtx_sha256": A401.sha256(np.asarray(stats[index]["xtx"], dtype="<f8").tobytes()),
            "positive_sha256": A401.sha256(
                np.asarray(stats[index]["positive"], dtype="<f8").tobytes()
            ),
        }
        for index in TARGETS
    }
    payload: dict[str, Any] = {
        "schema": "chacha20-round20-w50-knownkey-nested-fisher-reader-a408-result-v1",
        "attempt_id": ATTEMPT_ID,
        "evidence_stage": (
            "NESTED_FISHER_OUTOFFOLD_BEATS_A406_AND_APPLIES_ZERO_REFIT_TO_A388"
            if qualified
            else "NESTED_FISHER_OUTOFFOLD_BOUNDARY_RETAINED_AGAINST_A406"
        ),
        "design_sha256": DESIGN_SHA256,
        "implementation_sha256": expected_implementation_sha256,
        "implementation_commitment_sha256": implementation["implementation_commitment_sha256"],
        "A401_result_sha256": expected_a401_result_sha256,
        "A401_selection_sha256": expected_a401_selection_sha256,
        "A401_result_evidence_stage": a401_result["evidence_stage"],
        "A406_result_sha256": expected_a406_result_sha256,
        "nested_evaluation": evaluation,
        "comparison": comparison,
        "fullfit_candidate": selected,
        "fullfit_direction_float64le_sha256": direction_sha,
        "production_order": order,
        "production_order_uint16be_sha256": (
            A401.A400_uint16_sha(order) if order is not None else None
        ),
        "production_view_metadata": production_metadata,
        "production_operator_diversity": diversity,
        "knownkey_sufficient_statistic_commitments": stable_stats,
        "knownkey_field_commitments": field_commitments,
        "production_target_labels_used": 0,
        "production_reader_refits": 0,
        "production_candidate_assignments_executed": 0,
        "new_solver_stages": 0,
        "live_recovery_progress_filter_outcomes_or_results_consumed": False,
        "anchors": {
            "design": anchor(DESIGN, DESIGN_SHA256),
            "implementation": anchor(IMPLEMENTATION, expected_implementation_sha256),
            "A401_result": anchor(A401.RESULT, expected_a401_result_sha256),
            "A401_selection": anchor(A401.SELECTION, expected_a401_selection_sha256),
            "A406_result": anchor(A406_RESULT, expected_a406_result_sha256),
            "A388_order": anchor(A388_ORDER, A388_ORDER_SHA256),
            "runner": anchor(Path(__file__)),
        },
    }
    payload["measurement_sha256"] = canonical_sha256(
        {
            "nested_evaluation": evaluation,
            "comparison": comparison,
            "sufficient_statistics": stable_stats,
        }
    )
    payload["deployment_commitment_sha256"] = canonical_sha256(
        {
            "comparison": comparison,
            "fullfit_candidate": selected,
            "direction_sha256": direction_sha,
            "production_order": order,
            "production_view_metadata": production_metadata,
        }
    )
    payload["causal"] = build_causal(payload)
    atomic_json(RESULT, payload)
    atomic_bytes(
        REPORT,
        (
            "# A408 — Nested Fisher W50 Reader\n\n"
            f"Evidence stage: **{payload['evidence_stage']}**\n\n"
            f"- Nested ranks: **{nested_panel['ranks']}**\n"
            f"- A406 weighted ranks: **{weighted_panel['ranks']}**\n"
            f"- Geometric rank improvement: **{factor:.9f}x**\n"
            f"- Additional bit gain: **{gain:.9f} bits**\n"
            f"- Better / equal / worse folds: **{comparison['nested_better_folds']} / {comparison['nested_equal_folds']} / {comparison['nested_worse_folds']}**\n"
            f"- Full-fit candidate: **{selected}**\n"
            f"- Production order SHA-256: **{payload['production_order_uint16be_sha256']}**\n"
            "- Production labels / refits / candidates / new solver stages: **0 / 0 / 0 / 0**\n"
            "- Authentic AI-native Causal readback: **2 explicit + 1 inferred chain**\n"
        ).encode(),
    )
    return payload


def analyze() -> dict[str, Any]:
    payload: dict[str, Any] = {
        "attempt_id": ATTEMPT_ID,
        "design_sha256": DESIGN_SHA256,
        "implementation_frozen": IMPLEMENTATION.exists(),
        "A401_result_available": A401.RESULT.exists(),
        "A406_result_available": A406_RESULT.exists(),
        "result_complete": RESULT.exists(),
    }
    if IMPLEMENTATION.exists():
        payload["implementation_sha256"] = file_sha256(IMPLEMENTATION)
    if RESULT.exists():
        value = json.loads(RESULT.read_bytes())
        payload["result_sha256"] = file_sha256(RESULT)
        payload["comparison"] = value["comparison"]
        payload["production_order_uint16be_sha256"] = value["production_order_uint16be_sha256"]
    return payload


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    action = parser.add_mutually_exclusive_group(required=True)
    action.add_argument("--freeze-implementation", action="store_true")
    action.add_argument("--materialize", action="store_true")
    action.add_argument("--analyze", action="store_true")
    parser.add_argument("--expected-implementation-sha256")
    parser.add_argument("--expected-a401-result-sha256")
    parser.add_argument("--expected-a401-selection-sha256")
    parser.add_argument("--expected-a406-result-sha256")
    args = parser.parse_args()
    if args.freeze_implementation:
        payload = freeze_implementation()
    elif args.materialize:
        required = (
            args.expected_implementation_sha256,
            args.expected_a401_result_sha256,
            args.expected_a401_selection_sha256,
            args.expected_a406_result_sha256,
        )
        if not all(required):
            parser.error("--materialize requires four expected SHA-256 arguments")
        payload = materialize(
            expected_implementation_sha256=args.expected_implementation_sha256,
            expected_a401_result_sha256=args.expected_a401_result_sha256,
            expected_a401_selection_sha256=args.expected_a401_selection_sha256,
            expected_a406_result_sha256=args.expected_a406_result_sha256,
        )
    else:
        payload = analyze()
    print(json.dumps(payload, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""A410: nested nonlinear prototype-manifold learning over W50 Direct12 fields."""

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

DESIGN = CONFIGS / "chacha20_round20_w50_knownkey_nested_prototype_reader_a410_design_v1.json"
IMPLEMENTATION = (
    CONFIGS / "chacha20_round20_w50_knownkey_nested_prototype_reader_a410_implementation_v1.json"
)
RESULT = RESULTS / "chacha20_round20_w50_knownkey_nested_prototype_reader_a410_v1.json"
CAUSAL = RESULT.with_suffix(".causal")
REPORT = RESULT.with_suffix(".md")
TEST = ROOT / "tests/test_chacha20_round20_w50_knownkey_nested_prototype_reader_a410.py"
REPRO = ROOT / "scripts/reproduce_chacha20_round20_w50_knownkey_nested_prototype_reader_a410.sh"

A408_RUNNER = RESEARCH / "experiments/chacha20_round20_w50_knownkey_nested_fisher_reader_a408.py"
A408_RESULT = RESULTS / "chacha20_round20_w50_knownkey_nested_fisher_reader_a408_v1.json"
A408_IMPLEMENTATION = (
    CONFIGS / "chacha20_round20_w50_knownkey_nested_fisher_reader_a408_implementation_v1.json"
)
A401_RUNNER = RESEARCH / "experiments/chacha20_round20_w50_knownkey_direct12_learning_a401.py"
A401_IMPLEMENTATION = (
    CONFIGS / "chacha20_round20_w50_knownkey_direct12_learning_a401_implementation_v1.json"
)
A401_PROTOCOL = (
    CONFIGS / "chacha20_round20_w50_knownkey_direct12_learning_a401_public_corpus_v1.json"
)
A388_ORDER = RESULTS / "chacha20_round20_w50_public_output_direct12_factor3_a388_order_v1.json"

ATTEMPT_ID = "A410"
DESIGN_SHA256 = "7569d8cb6a0b0ac8cba2298752085d568f84937623b1677dbad7506d31f3e273"
A408_RUNNER_SHA256 = "a398bc6b1b8f669bc2b3b0b8666c5f03c12c4f46fb79c1d5eaf8de13f392b5ab"
A408_IMPLEMENTATION_SHA256 = "999ac2e2ffa9536d977e93932bc197451d0307e516060f8bae8d0df70dce9e5c"
A401_RUNNER_SHA256 = "2238b99504883cd0b722b7b92254b3dc02255a6b53c9851f35264daad3f21bee"
A401_IMPLEMENTATION_SHA256 = "4a08686d34674525bd08938d96783c6772ce4cd004fffbe04d11dc972cf63df1"
A401_PROTOCOL_SHA256 = "18aaad488842ce9fb52a77cef01c89bfeb8c901001a86fd56e23bbf594c7a4f3"
A388_ORDER_SHA256 = "3c56ce8521b1ced20e1e3a90999810c2e563c4de941701c86274f0828b5d01b8"

REPRESENTATIONS = (
    ("log8", 8),
    ("reciprocal_sqrt8", 8),
    ("log_reciprocal16", 16),
    ("log_absdiff36", 36),
    ("log_reciprocal_absdiff44", 44),
)
METRICS = ("mean_absolute_L1", "mean_squared_L2")
NEIGHBOURS: tuple[int | None, ...] = (1, 3, 7, None)
CANDIDATE_COUNT = len(REPRESENTATIONS) * len(METRICS) * len(NEIGHBOURS)
DOTCAUSAL_SRC = Path("/Users/bhkmie/Documents/Forschung/O1/vendor/fabel/dotcausal_package/src")


def load_module(path: Path, name: str) -> Any:
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot import A410 dependency {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


A408 = load_module(A408_RUNNER, "a410_a408")
A401 = A408.A401
A402 = A408.A402

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


def candidate_rows() -> list[dict[str, Any]]:
    rows = []
    for representation_index, (representation, dimension) in enumerate(REPRESENTATIONS):
        for metric_index, metric in enumerate(METRICS):
            for neighbour_index, neighbours in enumerate(NEIGHBOURS):
                rows.append(
                    {
                        "representation": representation,
                        "representation_index": representation_index,
                        "feature_dimension": dimension,
                        "metric": metric,
                        "metric_index": metric_index,
                        "neighbours": (
                            "all_training_prototypes" if neighbours is None else neighbours
                        ),
                        "neighbour_index": neighbour_index,
                    }
                )
    if len(rows) != CANDIDATE_COUNT:
        raise RuntimeError("A410 candidate family size differs")
    return rows


def representation_matrices(rank_matrix: np.ndarray) -> dict[str, np.ndarray]:
    features = A408.feature_matrix(rank_matrix)
    log = features[:, 8:16]
    reciprocal = features[:, 16:24]
    absdiff = features[:, 24:52]
    matrices = {
        "log8": log,
        "reciprocal_sqrt8": reciprocal,
        "log_reciprocal16": np.concatenate((log, reciprocal), axis=1),
        "log_absdiff36": np.concatenate((log, absdiff), axis=1),
        "log_reciprocal_absdiff44": np.concatenate((log, reciprocal, absdiff), axis=1),
    }
    expected = dict(REPRESENTATIONS)
    if tuple(matrices) != tuple(expected):
        raise RuntimeError("A410 representation order differs")
    for name, matrix in matrices.items():
        if matrix.shape != (rank_matrix.shape[1], expected[name]):
            raise RuntimeError(f"A410 {name} representation shape differs")
        if not np.isfinite(matrix).all() or np.any(matrix < 0.0) or np.any(matrix > 1.0):
            raise RuntimeError(f"A410 {name} representation range differs")
    return matrices


def distance_rows(field: np.ndarray, prototypes: np.ndarray, metric: str) -> np.ndarray:
    matrix = np.asarray(field, dtype=np.float64)
    points = np.asarray(prototypes, dtype=np.float64)
    if matrix.ndim != 2 or points.ndim != 2 or matrix.shape[1] != points.shape[1]:
        raise ValueError("A410 distance shapes differ")
    rows = np.empty((points.shape[0], matrix.shape[0]), dtype=np.float64)
    for index, point in enumerate(points):
        delta = matrix - point
        if metric == "mean_absolute_L1":
            rows[index] = np.mean(np.abs(delta), axis=1)
        elif metric == "mean_squared_L2":
            rows[index] = np.mean(np.square(delta), axis=1)
        else:
            raise ValueError(f"unknown A410 metric {metric}")
    if not np.isfinite(rows).all() or np.any(rows < 0.0):
        raise RuntimeError("A410 distances differ")
    return rows


def score_panel(distances: np.ndarray) -> np.ndarray:
    rows = np.asarray(distances, dtype=np.float64)
    if rows.ndim != 2 or rows.shape[0] < 1:
        raise ValueError("A410 distance panel shape differs")
    ordered = np.sort(rows, axis=0, kind="stable")
    cumulative = np.cumsum(ordered, axis=0)
    result = []
    for neighbours in NEIGHBOURS:
        count = rows.shape[0] if neighbours is None else min(neighbours, rows.shape[0])
        result.append(cumulative[count - 1] / float(count))
    scores = np.stack(result, axis=1)
    if scores.shape != (rows.shape[1], len(NEIGHBOURS)):
        raise RuntimeError("A410 score panel differs")
    return scores


def true_ranks(scores: np.ndarray, true_cell: int) -> np.ndarray:
    matrix = np.asarray(scores, dtype=np.float64)
    if matrix.ndim != 2 or not 0 <= true_cell < matrix.shape[0]:
        raise ValueError("A410 scoring contract differs")
    truth = matrix[true_cell]
    cells = np.arange(matrix.shape[0])[:, None]
    better = matrix < truth
    tied_lower = (matrix == truth) & (cells < true_cell)
    return 1 + np.count_nonzero(better | tied_lower, axis=0)


def select_candidate(candidates: Sequence[Mapping[str, Any]], truth: np.ndarray) -> int:
    values = np.asarray(truth, dtype=np.int64)
    if len(candidates) != CANDIDATE_COUNT or values.ndim != 2 or values.shape[1] != CANDIDATE_COUNT:
        raise ValueError("A410 selection table differs")
    mean_log = np.log2(values.astype(np.float64)).mean(axis=0)
    worst = values.max(axis=0)
    return min(
        range(CANDIDATE_COUNT),
        key=lambda index: (
            float(mean_log[index]),
            int(worst[index]),
            int(candidates[index]["representation_index"]),
            int(candidates[index]["metric_index"]),
            int(candidates[index]["neighbour_index"]),
        ),
    )


def load_design() -> dict[str, Any]:
    if file_sha256(DESIGN) != DESIGN_SHA256:
        raise RuntimeError("A410 design hash differs")
    value = json.loads(DESIGN.read_bytes())
    corpus = value.get("corpus_contract", {})
    model = value.get("model_contract", {})
    boundary = value.get("information_boundary", {})
    if (
        value.get("schema")
        != "chacha20-round20-w50-knownkey-nested-prototype-reader-a410-design-v1"
        or value.get("attempt_id") != ATTEMPT_ID
        or value.get("design_state")
        != "frozen_during_A401_target13plus_measurement_before_A401_selection_result_A408_result_or_any_A410_label_score"
        or corpus.get("outer_folds") != len(TARGETS)
        or corpus.get("inner_folds_per_outer_fold") != len(TARGETS) - 1
        or model.get("candidate_count") != CANDIDATE_COUNT
        or boundary.get("A401_completed_targets_visible_at_design_freeze") != 13
        or boundary.get("A401_selection_holdout_or_result_available_at_design_freeze") is not False
        or boundary.get("A408_result_or_nested_score_available_at_design_freeze") is not False
        or boundary.get("A410_label_scores_available_at_design_freeze") is not False
    ):
        raise RuntimeError("A410 frozen design semantics differ")
    for key, source_path in value["source_anchors"].items():
        if key.endswith("_path"):
            expected = value["source_anchors"][key.removesuffix("_path") + "_sha256"]
            anchor(ROOT / source_path, expected)
    return value


def freeze_implementation() -> dict[str, Any]:
    if any(path.exists() for path in (IMPLEMENTATION, RESULT, CAUSAL, REPORT)):
        raise FileExistsError("A410 implementation or result artifact already exists")
    if A401.RESULT.exists() or A401.SELECTION.exists() or A408_RESULT.exists():
        raise RuntimeError("A410 code freeze must precede A401 and A408 results")
    load_design()
    if not TEST.exists() or not REPRO.exists():
        raise FileNotFoundError("A410 test and reproducer must precede freeze")
    payload: dict[str, Any] = {
        "schema": "chacha20-round20-w50-knownkey-nested-prototype-reader-a410-implementation-v1",
        "attempt_id": ATTEMPT_ID,
        "commitment_state": "complete_nested_prototype_reader_frozen_before_A401_selection_result_A408_result_or_any_A410_label_score",
        "design_sha256": DESIGN_SHA256,
        "candidate_count": CANDIDATE_COUNT,
        "A401_selection_or_result_available_at_freeze": False,
        "A408_result_available_at_freeze": False,
        "A410_label_score_or_production_order_available_at_freeze": False,
        "anchors": {
            "design": anchor(DESIGN, DESIGN_SHA256),
            "A408_runner": anchor(A408_RUNNER, A408_RUNNER_SHA256),
            "A408_implementation": anchor(A408_IMPLEMENTATION, A408_IMPLEMENTATION_SHA256),
            "A401_runner": anchor(A401_RUNNER, A401_RUNNER_SHA256),
            "A401_implementation": anchor(A401_IMPLEMENTATION, A401_IMPLEMENTATION_SHA256),
            "A401_public_corpus": anchor(A401_PROTOCOL, A401_PROTOCOL_SHA256),
            "A388_order": anchor(A388_ORDER, A388_ORDER_SHA256),
            "runner": anchor(Path(__file__)),
            "test": anchor(TEST),
            "reproducer": anchor(REPRO),
        },
    }
    payload["candidate_family_commitment_sha256"] = canonical_sha256(candidate_rows())
    payload["implementation_commitment_sha256"] = canonical_sha256(payload)
    atomic_json(IMPLEMENTATION, payload)
    return payload


def load_implementation(expected_sha256: str | None = None) -> dict[str, Any]:
    if expected_sha256 is not None and file_sha256(IMPLEMENTATION) != expected_sha256:
        raise RuntimeError("A410 implementation hash differs")
    value = json.loads(IMPLEMENTATION.read_bytes())
    if (
        value.get("schema")
        != "chacha20-round20-w50-knownkey-nested-prototype-reader-a410-implementation-v1"
        or value.get("attempt_id") != ATTEMPT_ID
        or value.get("candidate_count") != CANDIDATE_COUNT
        or value.get("A401_selection_or_result_available_at_freeze") is not False
        or value.get("A408_result_available_at_freeze") is not False
        or value.get("A410_label_score_or_production_order_available_at_freeze") is not False
        or value.get("candidate_family_commitment_sha256") != canonical_sha256(candidate_rows())
    ):
        raise RuntimeError("A410 implementation semantics differ")
    for row in value["anchors"].values():
        anchor(path_from_ref(row["path"]), row["sha256"])
    unsigned = {
        key: item for key, item in value.items() if key != "implementation_commitment_sha256"
    }
    if value.get("implementation_commitment_sha256") != canonical_sha256(unsigned):
        raise RuntimeError("A410 implementation commitment differs")
    return value


def load_a408_result(expected_sha256: str) -> dict[str, Any]:
    if file_sha256(A408_RESULT) != expected_sha256:
        raise RuntimeError("A410 A408 result hash differs")
    value = json.loads(A408_RESULT.read_bytes())
    ranks = value.get("nested_evaluation", {}).get("nested_panel", {}).get("ranks", [])
    if (
        value.get("schema") != "chacha20-round20-w50-knownkey-nested-fisher-reader-a408-result-v1"
        or value.get("attempt_id") != "A408"
        or len(ranks) != len(TARGETS)
        or any(not 1 <= int(rank) <= CELLS for rank in ranks)
        or value.get("production_target_labels_used") != 0
        or value.get("new_solver_stages") != 0
    ):
        raise RuntimeError("A410 A408 baseline semantics differ")
    return value


def nested_evaluate(
    representations: Mapping[int, Mapping[str, np.ndarray]],
    true_cells: Mapping[int, int],
) -> dict[str, Any]:
    candidates = candidate_rows()
    prospective = np.empty((len(TARGETS), CANDIDATE_COUNT), dtype=np.int64)
    inner_tables = {
        outer: np.empty((len(TARGETS) - 1, CANDIDATE_COUNT), dtype=np.int64) for outer in TARGETS
    }
    inner_row = {
        outer: {
            target: row for row, target in enumerate(index for index in TARGETS if index != outer)
        }
        for outer in TARGETS
    }
    prototype_commitments: dict[str, str] = {}
    for representation_index, (name, _dimension) in enumerate(REPRESENTATIONS):
        prototypes = np.stack(
            [representations[index][name][int(true_cells[index])] for index in TARGETS]
        )
        prototype_commitments[name] = A401.sha256(np.asarray(prototypes, dtype="<f8").tobytes())
        for metric_index, metric in enumerate(METRICS):
            start = representation_index * len(METRICS) * len(NEIGHBOURS) + metric_index * len(
                NEIGHBOURS
            )
            for heldout in TARGETS:
                distances = distance_rows(representations[heldout][name], prototypes, metric)
                outer_train = [index for index in TARGETS if index != heldout]
                prospective[heldout, start : start + len(NEIGHBOURS)] = true_ranks(
                    score_panel(distances[outer_train]), int(true_cells[heldout])
                )
                for outer in TARGETS:
                    if outer == heldout:
                        continue
                    inner_train = [index for index in TARGETS if index not in {outer, heldout}]
                    inner_tables[outer][
                        inner_row[outer][heldout], start : start + len(NEIGHBOURS)
                    ] = true_ranks(score_panel(distances[inner_train]), int(true_cells[heldout]))
    folds = []
    nested_ranks = []
    winners = []
    for outer in TARGETS:
        selected = select_candidate(candidates, inner_tables[outer])
        rank = int(prospective[outer, selected])
        nested_ranks.append(rank)
        winners.append(selected)
        folds.append(
            {
                "outer_heldout_target": outer,
                "outer_training_targets": [index for index in TARGETS if index != outer],
                "inner_selected_candidate_index": selected,
                "inner_selected_candidate": candidates[selected],
                "outer_heldout_rank": rank,
                "inner_rank_panel": A401.metric_panel(inner_tables[outer][:, selected]),
            }
        )
    fullfit_index = select_candidate(candidates, prospective)
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
        "prototype_commitments": prototype_commitments,
    }


def production_order(
    candidate: Mapping[str, Any],
    known: Mapping[int, Mapping[str, np.ndarray]],
    true_cells: Mapping[int, int],
    production: Mapping[str, np.ndarray],
) -> tuple[list[int], str]:
    name = str(candidate["representation"])
    prototypes = np.stack([known[index][name][int(true_cells[index])] for index in TARGETS])
    distances = distance_rows(production[name], prototypes, str(candidate["metric"]))
    neighbour_index = int(candidate["neighbour_index"])
    scores = score_panel(distances)[:, neighbour_index]
    cells = np.arange(scores.shape[0], dtype=np.int64)
    order = np.lexsort((cells, scores)).tolist()
    if len(order) != CELLS or set(order) != set(range(CELLS)):
        raise RuntimeError("A410 production order differs")
    prototype_sha = A401.sha256(np.asarray(prototypes, dtype="<f8").tobytes())
    return [int(value) for value in order], prototype_sha


def build_causal(payload: Mapping[str, Any]) -> dict[str, Any]:
    sys.path.insert(0, str(DOTCAUSAL_SRC))
    from dotcausal.io import CausalReader, CausalWriter

    terminal = "A410:nonlinear_prototype_reader_boundary"
    writer = CausalWriter(api_id="a410w50")
    writer._rules = []
    writer.add_rule(
        name="knownkey_prototypes_to_nested_geometry",
        description="Disjoint known-key positives define a fixed nonlinear prototype manifold whose Reader is selected entirely inside each outer fold.",
        pattern=["A401:complete_knownkey_fields", "A410:positive_prototype_manifold"],
        conclusion="A410:nested_outoffold_rank_panel",
        confidence_modifier=1.0,
    )
    writer.add_rule(
        name="nested_comparison_to_production_boundary",
        description="Strict improvement over A408 permits one all-known-key fit and zero-target-refit application to A388; otherwise the nonlinear boundary is retained.",
        pattern=["A410:nested_outoffold_rank_panel", "A408:nested_Fisher_rank_panel"],
        conclusion="A410:nonlinear_prototype_reader_boundary",
        confidence_modifier=1.0,
    )
    writer.add_triplet(
        trigger="A401:complete_knownkey_fields",
        mechanism="nested_positive_prototype_manifold_learning",
        outcome="A410:nested_outoffold_rank_panel",
        confidence=1.0,
        source=payload["measurement_sha256"],
        quantification=json.dumps(payload["comparison"], sort_keys=True),
        evidence=payload["evidence_stage"],
        domain="full-round ChaCha20 W50 known-key Reader learning",
        quality_score=1.0,
    )
    writer.add_triplet(
        trigger="A410:nested_outoffold_rank_panel",
        mechanism="strict_matched_A408_comparison_and_zero_refit_gate",
        outcome=terminal,
        confidence=1.0,
        source=payload["deployment_commitment_sha256"],
        quantification=json.dumps(payload["fullfit_candidate"], sort_keys=True),
        evidence=payload["evidence_stage"],
        domain="prospective nonlinear Reader boundary",
        quality_score=1.0,
    )
    writer.add_triplet(
        trigger="A401:complete_knownkey_fields",
        mechanism="materialized_nested_prototype_comparison_closure",
        outcome=terminal,
        confidence=1.0,
        source="materialized:A410_nested_prototype_chain",
        quantification="exact retained closure",
        evidence=payload["evidence_stage"],
        domain="AI-native retained inference",
        quality_score=1.0,
        is_inferred=True,
    )
    writer.add_cluster(
        name="A410 nonlinear prototype Reader",
        entities=[
            "A401:complete_knownkey_fields",
            "A410:positive_prototype_manifold",
            "A410:nested_outoffold_rank_panel",
            terminal,
        ],
    )
    writer.add_gap(
        subject=terminal,
        predicate="next_required_object",
        expected_object_type="qualified_distinct_production_order_or_representation_boundary",
        confidence=1.0,
        suggested_queries=[
            "Execute a qualified distinct order, or derive the next Reader from the measured prototype-versus-Fisher boundary."
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
        reader.api_id != "a410w50"
        or len(explicit) != 2
        or len(all_rows) != 3
        or len(inferred) != 1
        or len(reader._rules) != 2
        or len(reader._clusters) != 1
        or len(reader._gaps) != 1
    ):
        raise RuntimeError("A410 authentic Causal reopen gate failed")
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
            "boundary": explicit[1],
            "terminal_chain": all_rows[-1],
            "next_gap": reader._gaps[0],
        },
    }


def materialize(
    *,
    expected_implementation_sha256: str,
    expected_a401_result_sha256: str,
    expected_a401_selection_sha256: str,
    expected_a408_result_sha256: str,
) -> dict[str, Any]:
    if RESULT.exists() or CAUSAL.exists() or REPORT.exists():
        raise FileExistsError("A410 result already exists")
    implementation = load_implementation(expected_implementation_sha256)
    a401_result, _selection = A402.load_a401_result(
        expected_result_sha256=expected_a401_result_sha256,
        expected_selection_sha256=expected_a401_selection_sha256,
    )
    a408 = load_a408_result(expected_a408_result_sha256)
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
    representations = {}
    field_commitments = {}
    for index in TARGETS:
        ranks, field_commitments[str(index)] = A401.view_rank_matrix(index)
        representations[index] = representation_matrices(ranks)
    true_cells = {index: int(labels[index]["true_direct12_cell"]) for index in TARGETS}
    evaluation = nested_evaluate(representations, true_cells)
    prototype_commitments = evaluation.pop("prototype_commitments")
    nested_panel = evaluation["nested_panel"]
    fisher_panel = a408["nested_evaluation"]["nested_panel"]
    factor = fisher_panel["geometric_mean_rank"] / nested_panel["geometric_mean_rank"]
    gain = (
        nested_panel["bit_gain_vs_complete_4096_cover"]
        - fisher_panel["bit_gain_vs_complete_4096_cover"]
    )
    qualified = factor > 1.0 and gain > 0.0
    comparison = {
        "qualified": qualified,
        "A408_nested_Fisher_ranks": fisher_panel["ranks"],
        "A410_nested_prototype_ranks": nested_panel["ranks"],
        "geometric_rank_improvement_factor": factor,
        "additional_bit_gain": gain,
        "prototype_better_folds": sum(
            left < right
            for left, right in zip(nested_panel["ranks"], fisher_panel["ranks"], strict=True)
        ),
        "prototype_equal_folds": sum(
            left == right
            for left, right in zip(nested_panel["ranks"], fisher_panel["ranks"], strict=True)
        ),
        "prototype_worse_folds": sum(
            left > right
            for left, right in zip(nested_panel["ranks"], fisher_panel["ranks"], strict=True)
        ),
    }
    selected = evaluation["fullfit_candidate"] if qualified else None
    order = None
    production_metadata = None
    diversity = None
    production_prototype_sha = None
    if selected is not None:
        production_ranks, view_orders, production_metadata = A402.production_rank_matrix()
        order, production_prototype_sha = production_order(
            selected,
            representations,
            true_cells,
            representation_matrices(production_ranks),
        )
        diversity = {
            name: A401.A388.A351.diversity_panel(order, view_orders[name]) for name in VIEW_NAMES
        }
    payload: dict[str, Any] = {
        "schema": "chacha20-round20-w50-knownkey-nested-prototype-reader-a410-result-v1",
        "attempt_id": ATTEMPT_ID,
        "evidence_stage": (
            "NESTED_PROTOTYPE_OUTOFFOLD_BEATS_A408_AND_APPLIES_ZERO_REFIT_TO_A388"
            if qualified
            else "NESTED_PROTOTYPE_OUTOFFOLD_BOUNDARY_RETAINED_AGAINST_A408"
        ),
        "design_sha256": DESIGN_SHA256,
        "implementation_sha256": expected_implementation_sha256,
        "implementation_commitment_sha256": implementation["implementation_commitment_sha256"],
        "A401_result_sha256": expected_a401_result_sha256,
        "A401_selection_sha256": expected_a401_selection_sha256,
        "A401_result_evidence_stage": a401_result["evidence_stage"],
        "A408_result_sha256": expected_a408_result_sha256,
        "nested_evaluation": evaluation,
        "comparison": comparison,
        "fullfit_candidate": selected,
        "production_order": order,
        "production_order_uint16be_sha256": (
            A401.A400_uint16_sha(order) if order is not None else None
        ),
        "production_prototype_float64le_sha256": production_prototype_sha,
        "production_view_metadata": production_metadata,
        "production_operator_diversity": diversity,
        "knownkey_prototype_commitments": prototype_commitments,
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
            "A408_result": anchor(A408_RESULT, expected_a408_result_sha256),
            "A388_order": anchor(A388_ORDER, A388_ORDER_SHA256),
            "runner": anchor(Path(__file__)),
        },
    }
    payload["measurement_sha256"] = canonical_sha256(
        {
            "nested_evaluation": evaluation,
            "comparison": comparison,
            "prototype_commitments": prototype_commitments,
        }
    )
    payload["deployment_commitment_sha256"] = canonical_sha256(
        {
            "comparison": comparison,
            "fullfit_candidate": selected,
            "production_prototype_sha256": production_prototype_sha,
            "production_order": order,
            "production_view_metadata": production_metadata,
        }
    )
    payload["causal"] = build_causal(payload)
    atomic_json(RESULT, payload)
    atomic_bytes(
        REPORT,
        (
            "# A410 — Nested nonlinear prototype Reader\n\n"
            f"Evidence stage: **{payload['evidence_stage']}**\n\n"
            f"- Nested prototype ranks: **{nested_panel['ranks']}**\n"
            f"- A408 nested Fisher ranks: **{fisher_panel['ranks']}**\n"
            f"- Geometric rank improvement: **{factor:.9f}x**\n"
            f"- Additional bit gain: **{gain:.9f} bits**\n"
            f"- Better / equal / worse folds: **{comparison['prototype_better_folds']} / {comparison['prototype_equal_folds']} / {comparison['prototype_worse_folds']}**\n"
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
        "A408_result_available": A408_RESULT.exists(),
        "result_complete": RESULT.exists(),
    }
    if IMPLEMENTATION.exists():
        payload["implementation_sha256"] = file_sha256(IMPLEMENTATION)
    if RESULT.exists():
        value = json.loads(RESULT.read_bytes())
        payload["result_sha256"] = file_sha256(RESULT)
        payload["evidence_stage"] = value["evidence_stage"]
        payload["comparison"] = value["comparison"]
        payload["fullfit_candidate"] = value["fullfit_candidate"]
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
    parser.add_argument("--expected-a408-result-sha256")
    args = parser.parse_args()
    if args.freeze_implementation:
        payload = freeze_implementation()
    elif args.materialize:
        required = (
            args.expected_implementation_sha256,
            args.expected_a401_result_sha256,
            args.expected_a401_selection_sha256,
            args.expected_a408_result_sha256,
        )
        if not all(required):
            parser.error("--materialize requires four expected SHA-256 arguments")
        payload = materialize(
            expected_implementation_sha256=args.expected_implementation_sha256,
            expected_a401_result_sha256=args.expected_a401_result_sha256,
            expected_a401_selection_sha256=args.expected_a401_selection_sha256,
            expected_a408_result_sha256=args.expected_a408_result_sha256,
        )
    else:
        payload = analyze()
    print(json.dumps(payload, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()

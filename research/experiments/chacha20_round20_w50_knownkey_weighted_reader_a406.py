#!/usr/bin/env python3
"""A406: weighted algebraic W50 Reader learning with sixteen-fold validation."""

from __future__ import annotations

import argparse
import importlib.util
import inspect
import json
import math
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

DESIGN = CONFIGS / "chacha20_round20_w50_knownkey_weighted_reader_a406_design_v1.json"
IMPLEMENTATION = (
    CONFIGS / "chacha20_round20_w50_knownkey_weighted_reader_a406_implementation_v1.json"
)
RESULT = RESULTS / "chacha20_round20_w50_knownkey_weighted_reader_a406_v1.json"
CAUSAL = RESULT.with_suffix(".causal")
REPORT = RESULT.with_suffix(".md")
TEST = ROOT / "tests/test_chacha20_round20_w50_knownkey_weighted_reader_a406.py"
REPRO = ROOT / "scripts/reproduce_chacha20_round20_w50_knownkey_weighted_reader_a406.sh"

A404_RUNNER = RESEARCH / "experiments/chacha20_round20_w50_knownkey_leaveoneout_reader_a404.py"
A401_RUNNER = RESEARCH / "experiments/chacha20_round20_w50_knownkey_direct12_learning_a401.py"
A388_ORDER = RESULTS / "chacha20_round20_w50_public_output_direct12_factor3_a388_order_v1.json"

ATTEMPT_ID = "A406"
DESIGN_SHA256 = "aaa67ce789ff3623c22e2d2965cbd5c19aa5f4d9aaa2911797eb2d019e0fd2a0"
A404_RUNNER_SHA256 = "d7743e0bc4996c15189876dafa014fec6a8a13398f90885c0284e9c585192bc7"
A404_IMPLEMENTATION_SHA256 = "4a60f4704397d4f3978756a91194efd16f3561c636aedb8ed3a078cba4e4def9"
A401_RUNNER_SHA256 = "2238b99504883cd0b722b7b92254b3dc02255a6b53c9851f35264daad3f21bee"
A401_IMPLEMENTATION_SHA256 = "4a08686d34674525bd08938d96783c6772ce4cd004fffbe04d11dc972cf63df1"
A401_PROTOCOL_SHA256 = "18aaad488842ce9fb52a77cef01c89bfeb8c901001a86fd56e23bbf594c7a4f3"
A388_ORDER_SHA256 = "3c56ce8521b1ced20e1e3a90999810c2e563c4de941701c86274f0828b5d01b8"
TRANSFORMS = (
    "weighted_rank_sum",
    "weighted_log2_rank_sum",
    "weighted_reciprocal_rank_sum",
)
WEIGHT_BUDGET = 8
WEIGHT_COUNT = 12323
CANDIDATE_COUNT = WEIGHT_COUNT * len(TRANSFORMS)
CHUNK_SIZE = 256
DOTCAUSAL_SRC = Path("/Users/bhkmie/Documents/Forschung/O1/vendor/fabel/dotcausal_package/src")


def load_module(path: Path, name: str) -> Any:
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot import A406 dependency {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


A404 = load_module(A404_RUNNER, "a406_a404")
A401 = A404.A401
A402 = A404.A402

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


def compositions(total: int, width: int, prefix: tuple[int, ...] = ()):
    if width == 1:
        yield prefix + (total,)
        return
    for value in range(total + 1):
        yield from compositions(total - value, width - 1, prefix + (value,))


def canonical_weights() -> list[tuple[int, ...]]:
    rows = []
    for total in range(1, WEIGHT_BUDGET + 1):
        for weights in compositions(total, len(VIEW_NAMES)):
            divisor = 0
            for value in weights:
                divisor = math.gcd(divisor, value)
            if divisor == 1:
                rows.append(weights)
    if len(rows) != WEIGHT_COUNT or len(set(rows)) != WEIGHT_COUNT:
        raise RuntimeError("A406 canonical weight family differs")
    return rows


def candidate_rows(weights: Sequence[Sequence[int]]) -> list[dict[str, Any]]:
    rows = []
    for vector in weights:
        normalized = tuple(int(value) for value in vector)
        if len(normalized) != len(VIEW_NAMES):
            raise ValueError("A406 weight width differs")
        for transform_index, transform in enumerate(TRANSFORMS):
            rows.append(
                {
                    "weights": list(normalized),
                    "active_view_indices": [
                        index for index, value in enumerate(normalized) if value
                    ],
                    "active_view_names": [
                        VIEW_NAMES[index] for index, value in enumerate(normalized) if value
                    ],
                    "l1_weight": sum(normalized),
                    "transform": transform,
                    "transform_index": transform_index,
                }
            )
    if len(rows) != CANDIDATE_COUNT:
        raise RuntimeError("A406 weighted candidate family size differs")
    return rows


def transformed_features(rank_matrix: np.ndarray, transform: str) -> np.ndarray:
    ranks = np.asarray(rank_matrix)
    if ranks.ndim != 2 or ranks.shape[0] != len(VIEW_NAMES):
        raise ValueError("A406 rank matrix shape differs")
    if np.any(ranks <= 0):
        raise ValueError("A406 ranks must be positive")
    if transform == "weighted_rank_sum":
        return ranks.astype(np.int64, copy=False)
    if transform == "weighted_log2_rank_sum":
        return np.log2(ranks.astype(np.float64))
    if transform == "weighted_reciprocal_rank_sum":
        return -np.reciprocal(ranks.astype(np.float64))
    raise ValueError("A406 transform differs")


def weighted_true_ranks(
    rank_matrix: np.ndarray,
    true_cell: int,
    weight_matrix: np.ndarray,
    transform: str,
    *,
    chunk_size: int = CHUNK_SIZE,
) -> np.ndarray:
    features = transformed_features(rank_matrix, transform)
    if not 0 <= true_cell < features.shape[1]:
        raise ValueError("A406 true cell lies outside field")
    weights = np.asarray(weight_matrix, dtype=np.int64)
    if weights.ndim != 2 or weights.shape[1] != features.shape[0]:
        raise ValueError("A406 weight matrix shape differs")
    if chunk_size <= 0:
        raise ValueError("A406 chunk size must be positive")
    delta = features - features[:, [true_cell]]
    lower_cells = np.arange(features.shape[1]) < true_cell
    result = np.empty(weights.shape[0], dtype=np.int64)
    for start in range(0, weights.shape[0], chunk_size):
        stop = min(start + chunk_size, weights.shape[0])
        score_delta = weights[start:stop] @ delta
        better = score_delta < 0
        tied_lower = (score_delta == 0) & lower_cells
        result[start:stop] = 1 + np.count_nonzero(better | tied_lower, axis=1)
    return result


def weighted_order(rank_matrix: np.ndarray, weights: Sequence[int], transform: str) -> list[int]:
    features = transformed_features(rank_matrix, transform)
    vector = np.asarray(tuple(int(value) for value in weights), dtype=np.int64)
    if vector.shape != (features.shape[0],):
        raise ValueError("A406 production weight shape differs")
    scores = vector @ features
    cells = np.arange(features.shape[1], dtype=np.int64)
    order = np.lexsort((cells, scores)).tolist()
    if len(order) != CELLS or set(order) != set(range(CELLS)):
        raise RuntimeError("A406 production order is not one complete permutation")
    return [int(value) for value in order]


def load_design() -> dict[str, Any]:
    if file_sha256(DESIGN) != DESIGN_SHA256:
        raise RuntimeError("A406 design hash differs")
    value = json.loads(DESIGN.read_bytes())
    corpus = value.get("corpus_contract", {})
    candidate = value.get("weighted_candidate_contract", {})
    baseline = value.get("matched_baseline_contract", {})
    production = value.get("production_contract", {})
    boundary = value.get("information_boundary", {})
    if (
        value.get("schema") != "chacha20-round20-w50-knownkey-weighted-reader-a406-design-v1"
        or value.get("attempt_id") != ATTEMPT_ID
        or value.get("design_state")
        != "frozen_during_A401_target_6_measurement_before_A401_selection_result_or_any_A406_label_score"
        or tuple(corpus.get("target_indices", [])) != TARGETS
        or corpus.get("fold_count") != len(TARGETS)
        or tuple(candidate.get("complete_view_order", [])) != VIEW_NAMES
        or tuple(candidate.get("transform_order", [])) != TRANSFORMS
        or candidate.get("canonical_weight_vector_count") != WEIGHT_COUNT
        or candidate.get("candidate_count") != CANDIDATE_COUNT
        or baseline.get("candidate_count") != 765
        or production.get("target_labels_used") != 0
        or production.get("new_solver_stages") != 0
        or boundary.get("A401_selection_holdout_or_result_available_at_design_freeze") is not False
        or boundary.get("A406_label_scores_available_at_design_freeze") is not False
    ):
        raise RuntimeError("A406 frozen design semantics differ")
    for key, source_path in value["source_anchors"].items():
        if key.endswith("_path"):
            expected = value["source_anchors"][key.removesuffix("_path") + "_sha256"]
            anchor(ROOT / source_path, expected)
    return value


def freeze_implementation() -> dict[str, Any]:
    if any(path.exists() for path in (IMPLEMENTATION, RESULT, CAUSAL, REPORT)):
        raise FileExistsError("A406 implementation or result already exists")
    if A401.SELECTION.exists() or A401.RESULT.exists():
        raise RuntimeError("A406 code freeze must precede A401 selection and result")
    load_design()
    weights = canonical_weights()
    candidates = candidate_rows(weights)
    if not TEST.exists() or not REPRO.exists():
        raise FileNotFoundError("A406 test and reproducer must precede freeze")
    payload: dict[str, Any] = {
        "schema": "chacha20-round20-w50-knownkey-weighted-reader-a406-implementation-v1",
        "attempt_id": ATTEMPT_ID,
        "commitment_state": "complete_weighted_reader_code_frozen_before_A401_selection_result_or_A406_label_score",
        "design_sha256": DESIGN_SHA256,
        "canonical_weight_vector_count": len(weights),
        "candidate_count": len(candidates),
        "weight_family_commitment_sha256": canonical_sha256(weights),
        "candidate_family_commitment_sha256": canonical_sha256(candidates),
        "A401_selection_or_result_available_at_freeze": False,
        "A406_label_scores_available_at_freeze": False,
        "anchors": {
            "design": anchor(DESIGN, DESIGN_SHA256),
            "A401_design": anchor(A401.DESIGN, A401.DESIGN_SHA256),
            "A401_runner": anchor(A401_RUNNER, A401_RUNNER_SHA256),
            "A401_implementation": anchor(A401.IMPLEMENTATION, A401_IMPLEMENTATION_SHA256),
            "A401_public_corpus": anchor(A401.PROTOCOL, A401_PROTOCOL_SHA256),
            "A404_runner": anchor(A404_RUNNER, A404_RUNNER_SHA256),
            "A404_implementation": anchor(A404.IMPLEMENTATION, A404_IMPLEMENTATION_SHA256),
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
        raise RuntimeError("A406 implementation hash differs")
    value = json.loads(IMPLEMENTATION.read_bytes())
    if (
        value.get("schema")
        != "chacha20-round20-w50-knownkey-weighted-reader-a406-implementation-v1"
        or value.get("attempt_id") != ATTEMPT_ID
        or value.get("commitment_state")
        != "complete_weighted_reader_code_frozen_before_A401_selection_result_or_A406_label_score"
        or value.get("canonical_weight_vector_count") != WEIGHT_COUNT
        or value.get("candidate_count") != CANDIDATE_COUNT
        or value.get("A401_selection_or_result_available_at_freeze") is not False
        or value.get("A406_label_scores_available_at_freeze") is not False
    ):
        raise RuntimeError("A406 implementation semantics differ")
    for row in value["anchors"].values():
        anchor(path_from_ref(row["path"]), row["sha256"])
    unsigned = {
        key: item for key, item in value.items() if key != "implementation_commitment_sha256"
    }
    if value.get("implementation_commitment_sha256") != canonical_sha256(unsigned):
        raise RuntimeError("A406 implementation commitment differs")
    return value


def weighted_selection_index(
    candidates: Sequence[Mapping[str, Any]],
    truth: np.ndarray,
    train: Sequence[int],
) -> int:
    if len(candidates) != CANDIDATE_COUNT or truth.shape != (
        len(TARGETS),
        CANDIDATE_COUNT,
    ):
        raise ValueError("A406 weighted selection table differs")
    indices = np.asarray(tuple(int(value) for value in train), dtype=np.int64)
    ranks = truth[indices]
    means = np.log2(ranks.astype(np.float64)).mean(axis=0)
    worst = ranks.max(axis=0)
    l1 = np.asarray([row["l1_weight"] for row in candidates], dtype=np.int64)
    active = np.asarray([len(row["active_view_indices"]) for row in candidates], dtype=np.int64)
    transforms = np.asarray([row["transform_index"] for row in candidates], dtype=np.int64)
    weights = np.asarray([row["weights"] for row in candidates], dtype=np.int64)
    keys: list[np.ndarray] = [weights[:, index] for index in reversed(range(weights.shape[1]))]
    keys.extend([transforms, active, l1, worst, means])
    return int(np.lexsort(tuple(keys))[0])


def leaveoneout(
    weighted_candidates: Sequence[Mapping[str, Any]],
    weighted_truth: np.ndarray,
    baseline_candidates: Sequence[Mapping[str, Any]],
    baseline_truth: np.ndarray,
) -> dict[str, Any]:
    if len(baseline_candidates) != 765 or baseline_truth.shape != (
        len(TARGETS),
        765,
    ):
        raise ValueError("A406 baseline table differs")
    folds = []
    weighted_ranks = []
    baseline_ranks = []
    weighted_winners = []
    baseline_winners = []
    for heldout in TARGETS:
        train = tuple(index for index in TARGETS if index != heldout)
        weighted_index = weighted_selection_index(weighted_candidates, weighted_truth, train)
        baseline_index = min(
            range(len(baseline_candidates)),
            key=lambda index: A404.selection_key(baseline_candidates, baseline_truth, index, train),
        )
        weighted_rank = int(weighted_truth[heldout, weighted_index])
        baseline_rank = int(baseline_truth[heldout, baseline_index])
        weighted_ranks.append(weighted_rank)
        baseline_ranks.append(baseline_rank)
        weighted_winners.append(weighted_index)
        baseline_winners.append(baseline_index)
        folds.append(
            {
                "heldout_target": heldout,
                "training_targets": list(train),
                "weighted_candidate_index": weighted_index,
                "weighted_candidate": dict(weighted_candidates[weighted_index]),
                "weighted_heldout_rank": weighted_rank,
                "baseline_candidate_index": baseline_index,
                "baseline_candidate": {
                    key: baseline_candidates[baseline_index][key]
                    for key in (
                        "aggregator",
                        "aggregator_index",
                        "view_indices",
                        "view_names",
                    )
                },
                "baseline_heldout_rank": baseline_rank,
            }
        )
    weighted_panel = A401.metric_panel(weighted_ranks)
    baseline_panel = A401.metric_panel(baseline_ranks)
    factor = baseline_panel["geometric_mean_rank"] / weighted_panel["geometric_mean_rank"]
    additional_gain = (
        weighted_panel["bit_gain_vs_complete_4096_cover"]
        - baseline_panel["bit_gain_vs_complete_4096_cover"]
    )
    qualified = factor > 1.0 and additional_gain > 0.0
    return {
        "folds": folds,
        "weighted_panel": weighted_panel,
        "complete_765_baseline_panel": baseline_panel,
        "geometric_rank_improvement_factor": factor,
        "additional_bit_gain": additional_gain,
        "weighted_better_folds": sum(
            left < right for left, right in zip(weighted_ranks, baseline_ranks, strict=True)
        ),
        "weighted_equal_folds": sum(
            left == right for left, right in zip(weighted_ranks, baseline_ranks, strict=True)
        ),
        "weighted_worse_folds": sum(
            left > right for left, right in zip(weighted_ranks, baseline_ranks, strict=True)
        ),
        "weighted_winner_frequency": dict(sorted(Counter(weighted_winners).items())),
        "baseline_winner_frequency": dict(sorted(Counter(baseline_winners).items())),
        "qualified": qualified,
    }


def build_tables() -> tuple[
    list[dict[str, Any]],
    np.ndarray,
    list[dict[str, Any]],
    np.ndarray,
    dict[str, Any],
]:
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
    rank_matrices = {}
    field_commitments = {}
    for index in TARGETS:
        rank_matrices[index], field_commitments[str(index)] = A401.view_rank_matrix(index)
    weights = canonical_weights()
    weight_matrix = np.asarray(weights, dtype=np.int64)
    weighted_candidates = candidate_rows(weights)
    weighted_truth = np.empty((len(TARGETS), CANDIDATE_COUNT), dtype=np.int64)
    for target in TARGETS:
        true_cell = int(labels[target]["true_direct12_cell"])
        for transform_index, transform in enumerate(TRANSFORMS):
            weighted_truth[target, transform_index :: len(TRANSFORMS)] = weighted_true_ranks(
                rank_matrices[target], true_cell, weight_matrix, transform
            )
    baseline_candidates = A402.candidate_rows(rank_matrices, labels)
    baseline_truth = np.asarray(
        [row["fullfit_true_ranks"] for row in baseline_candidates], dtype=np.int64
    ).T
    return (
        weighted_candidates,
        weighted_truth,
        baseline_candidates,
        baseline_truth,
        {
            "weight_family_commitment_sha256": canonical_sha256(weights),
            "weighted_candidate_family_commitment_sha256": canonical_sha256(weighted_candidates),
            "weighted_truth_rank_table_int32le_sha256": A401.sha256(
                weighted_truth.astype("<i4").tobytes()
            ),
            "baseline_candidate_family_commitment_sha256": canonical_sha256(baseline_candidates),
            "baseline_truth_rank_table_int32le_sha256": A401.sha256(
                baseline_truth.astype("<i4").tobytes()
            ),
            "knownkey_field_commitments": field_commitments,
            "combined_label_commitment_sha256": canonical_sha256(
                [labels[index] for index in TARGETS]
            ),
        },
    )


def fullfit_candidate(candidates: Sequence[Mapping[str, Any]], truth: np.ndarray) -> dict[str, Any]:
    index = weighted_selection_index(candidates, truth, TARGETS)
    ranks = [int(value) for value in truth[:, index]]
    row = dict(candidates[index])
    row.update(
        {
            "candidate_index": index,
            "fullfit_true_ranks": ranks,
            "fullfit_panel": A401.metric_panel(ranks),
        }
    )
    return row


def build_causal(payload: Mapping[str, Any]) -> dict[str, Any]:
    sys.path.insert(0, str(DOTCAUSAL_SRC))
    from dotcausal.io import CausalReader, CausalWriter

    qualified = bool(payload["leaveoneout"]["qualified"])
    terminal = (
        "A406_weighted_outoffold_qualified_production_order"
        if qualified
        else "A406_weighted_reader_boundary_retained"
    )
    writer = CausalWriter(api_id="a406w50")
    writer._rules = []
    writer.add_rule(
        name="complete_fields_to_weighted_outoffold_panel",
        description="Thirty-six thousand nine hundred sixty-nine frozen weighted algebraic Readers fit on fifteen keys and score one unseen key per fold.",
        pattern=["A401_sixteen_complete_fields", "A406_frozen_weighted_family"],
        conclusion="A406_weighted_outoffold_panel",
        confidence_modifier=1.0,
    )
    writer.add_rule(
        name="weighted_gate_to_production",
        description="Only improvement beyond the complete 765-Reader baseline permits full fit and zero-refit A388 application.",
        pattern=["A406_weighted_outoffold_panel", "A388_complete_unlabeled_W50_field"],
        conclusion=terminal,
        confidence_modifier=1.0,
    )
    writer.add_triplet(
        trigger="A401:sixteen_complete_knownkey_fields",
        mechanism="weighted_rank_logrank_reciprocal_leaveoneout_selection",
        outcome="A406:weighted_outoffold_panel",
        confidence=1.0,
        source=payload["candidate_table_commitment_sha256"],
        quantification=json.dumps(payload["leaveoneout"], sort_keys=True),
        evidence="A406 design and code froze before any A401 or A406 label score",
        domain="known-key W50 weighted Reader validation",
        quality_score=1.0,
    )
    writer.add_triplet(
        trigger="A406:weighted_outoffold_panel",
        mechanism="strict_complete_baseline_gate_then_zero_refit_application",
        outcome=f"A406:{terminal}",
        confidence=1.0,
        source=payload["deployment_commitment_sha256"],
        quantification=json.dumps(payload.get("fullfit_candidate"), sort_keys=True),
        evidence="zero production labels, refits, candidates, stages, or live outcomes",
        domain="weighted algebraic production Reader",
        quality_score=1.0,
    )
    writer.add_triplet(
        trigger="A401:sixteen_complete_knownkey_fields",
        mechanism="materialized_weighted_learning_to_production_chain",
        outcome=f"A406:{terminal}",
        confidence=1.0,
        source="materialized:A406_weighted_reader_chain",
        quantification="exact retained closure",
        evidence="pre-result A406 design and implementation commitments",
        domain="AI-native retained inference",
        quality_score=1.0,
        is_inferred=True,
    )
    writer.add_cluster(
        name="A406 weighted algebraic W50 Reader",
        entities=[
            "A401:sixteen_complete_knownkey_fields",
            "A406:weighted_outoffold_panel",
            f"A406:{terminal}",
        ],
    )
    writer.add_gap(
        subject=f"A406:{terminal}",
        predicate="next_required_object",
        expected_object_type=(
            "deduplicated_complete_group_recovery"
            if qualified
            else "signed_or_interaction_weight_family"
        ),
        confidence=1.0,
        suggested_queries=[
            "Execute the distinct qualified order with matched control."
            if qualified
            else "Use fold residuals to freeze a signed or interaction Reader family."
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
        reader.api_id != "a406w50"
        or len(explicit) != 2
        or len(all_rows) != 3
        or len(inferred) != 1
        or len(reader._rules) != 2
        or len(reader._clusters) != 1
        or len(reader._gaps) != 1
    ):
        raise RuntimeError("A406 authentic Causal reopen gate failed")
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
            "leaveoneout": explicit[0],
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
) -> dict[str, Any]:
    if RESULT.exists() or CAUSAL.exists() or REPORT.exists():
        raise FileExistsError("A406 result already exists")
    implementation = load_implementation(expected_implementation_sha256)
    a401_result, _selection = A402.load_a401_result(
        expected_result_sha256=expected_a401_result_sha256,
        expected_selection_sha256=expected_a401_selection_sha256,
    )
    (
        weighted_candidates,
        weighted_truth,
        baseline_candidates,
        baseline_truth,
        table_metadata,
    ) = build_tables()
    validation = leaveoneout(
        weighted_candidates,
        weighted_truth,
        baseline_candidates,
        baseline_truth,
    )
    winner = (
        fullfit_candidate(weighted_candidates, weighted_truth) if validation["qualified"] else None
    )
    production_order = None
    production_metadata = None
    diversity = None
    if winner is not None:
        ranks, view_orders, production_metadata = A402.production_rank_matrix()
        production_order = weighted_order(ranks, winner["weights"], winner["transform"])
        diversity = {
            name: A401.A388.A351.diversity_panel(production_order, view_orders[name])
            for name in VIEW_NAMES
        }
    payload: dict[str, Any] = {
        "schema": "chacha20-round20-w50-knownkey-weighted-reader-a406-result-v1",
        "attempt_id": ATTEMPT_ID,
        "evidence_stage": (
            "WEIGHTED_OUTOFFOLD_BEATS_COMPLETE_765_BASELINE_AND_APPLIES_ZERO_REFIT_TO_A388"
            if validation["qualified"]
            else "WEIGHTED_OUTOFFOLD_BOUNDARY_RETAINED_AGAINST_COMPLETE_765_BASELINE"
        ),
        "design_sha256": DESIGN_SHA256,
        "implementation_sha256": expected_implementation_sha256,
        "implementation_commitment_sha256": implementation["implementation_commitment_sha256"],
        "A401_result_sha256": expected_a401_result_sha256,
        "A401_selection_sha256": expected_a401_selection_sha256,
        "A401_result_evidence_stage": a401_result["evidence_stage"],
        "candidate_table_commitment_sha256": canonical_sha256(table_metadata),
        "candidate_table_metadata": table_metadata,
        "leaveoneout": validation,
        "fullfit_candidate": winner,
        "production_order": production_order,
        "production_order_uint16be_sha256": (
            A401.A400_uint16_sha(production_order) if production_order is not None else None
        ),
        "production_view_metadata": production_metadata,
        "production_operator_diversity": diversity,
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
            "A388_order": anchor(A388_ORDER, A388_ORDER_SHA256),
            "runner": anchor(Path(__file__)),
        },
    }
    payload["deployment_commitment_sha256"] = canonical_sha256(
        {
            "leaveoneout": validation,
            "fullfit_candidate": winner,
            "production_order": production_order,
            "production_view_metadata": production_metadata,
        }
    )
    payload["causal"] = build_causal(payload)
    atomic_json(RESULT, payload)
    atomic_bytes(
        REPORT,
        (
            "# A406 — Weighted algebraic W50 Reader\n\n"
            f"Evidence stage: **{payload['evidence_stage']}**\n\n"
            f"- Weighted candidates: **{CANDIDATE_COUNT:,}**\n"
            f"- Out-of-fold qualification: **{validation['qualified']}**\n"
            f"- Weighted ranks: **{validation['weighted_panel']['ranks']}**\n"
            f"- Complete-765 baseline ranks: **{validation['complete_765_baseline_panel']['ranks']}**\n"
            f"- Geometric rank improvement: **{validation['geometric_rank_improvement_factor']:.9f}x**\n"
            f"- Additional bit gain: **{validation['additional_bit_gain']:.9f} bits**\n"
            f"- Better / equal / worse folds: **{validation['weighted_better_folds']} / {validation['weighted_equal_folds']} / {validation['weighted_worse_folds']}**\n"
            f"- Full-fit candidate: **{winner}**\n"
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
        "result_complete": RESULT.exists(),
    }
    if IMPLEMENTATION.exists():
        payload["implementation_sha256"] = file_sha256(IMPLEMENTATION)
    if RESULT.exists():
        value = json.loads(RESULT.read_bytes())
        payload["result_sha256"] = file_sha256(RESULT)
        payload["leaveoneout"] = value["leaveoneout"]
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
    args = parser.parse_args()
    if args.freeze_implementation:
        payload = freeze_implementation()
    elif args.materialize:
        required = (
            args.expected_implementation_sha256,
            args.expected_a401_result_sha256,
            args.expected_a401_selection_sha256,
        )
        if not all(required):
            parser.error("--materialize requires all three expected SHA-256 arguments")
        payload = materialize(
            expected_implementation_sha256=args.expected_implementation_sha256,
            expected_a401_result_sha256=args.expected_a401_result_sha256,
            expected_a401_selection_sha256=args.expected_a401_selection_sha256,
        )
    else:
        payload = analyze()
    print(json.dumps(payload, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()

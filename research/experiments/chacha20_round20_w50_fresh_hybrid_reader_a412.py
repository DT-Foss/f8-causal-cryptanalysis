#!/usr/bin/env python3
"""A412: fresh 16/16 holdout for A404/A410 hybrid W50 Readers."""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import inspect
import json
import math
import os
import statistics
import sys
import time
from collections.abc import Iterator, Mapping, Sequence
from contextlib import contextmanager
from pathlib import Path
from typing import Any

import numpy as np

ROOT = Path(__file__).parents[2]
RESEARCH = ROOT / "research"
CONFIGS = RESEARCH / "configs"
RESULTS = RESEARCH / "results/v1"
ARTIFACTS = RESEARCH / "artifacts/a412_chacha20_r20_w50_fresh_hybrid"
MEASUREMENTS = RESULTS / "chacha20_round20_w50_fresh_hybrid_reader_a412_v1"

DESIGN = CONFIGS / "chacha20_round20_w50_fresh_hybrid_reader_a412_design_v1.json"
IMPLEMENTATION = CONFIGS / "chacha20_round20_w50_fresh_hybrid_reader_a412_implementation_v1.json"
PROTOCOL = CONFIGS / "chacha20_round20_w50_fresh_hybrid_reader_a412_public_corpus_v1.json"
SELECTION_LABELS = CONFIGS / "chacha20_round20_w50_fresh_hybrid_reader_a412_selection_labels_v1.json"
HOLDOUT_LABELS = CONFIGS / "chacha20_round20_w50_fresh_hybrid_reader_a412_holdout_labels_v1.json"
SELECTION = CONFIGS / "chacha20_round20_w50_fresh_hybrid_reader_a412_selection_v1.json"
PROGRESS = RESULTS / "chacha20_round20_w50_fresh_hybrid_reader_a412_progress_v1.json"
RESULT = RESULTS / "chacha20_round20_w50_fresh_hybrid_reader_a412_v1.json"
CAUSAL = RESULT.with_suffix(".causal")
REPORT = RESULT.with_suffix(".md")
TEST = ROOT / "tests/test_chacha20_round20_w50_fresh_hybrid_reader_a412.py"
REPRO = ROOT / "scripts/reproduce_chacha20_round20_w50_fresh_hybrid_reader_a412.sh"

A410_RUNNER = RESEARCH / "experiments/chacha20_round20_w50_knownkey_nested_prototype_reader_a410.py"
A401_RESULT = RESULTS / "chacha20_round20_w50_knownkey_direct12_learning_a401_v1.json"
A404_RESULT = RESULTS / "chacha20_round20_w50_knownkey_leaveoneout_reader_a404_v1.json"
A410_RESULT = RESULTS / "chacha20_round20_w50_knownkey_nested_prototype_reader_a410_v1.json"
A388_ORDER = RESULTS / "chacha20_round20_w50_public_output_direct12_factor3_a388_order_v1.json"

ATTEMPT_ID = "A412"
DESIGN_SHA256 = "709f6b7f2e0eae4cfaad7599d31fd30c160e7444a3f9b9f43006c9536e6764cf"
A401_RUNNER_SHA256 = "2238b99504883cd0b722b7b92254b3dc02255a6b53c9851f35264daad3f21bee"
A401_RESULT_SHA256 = "347b3756833df4c6dd3e7d8af41f1d48ea6813822de38900e8e42969f4bfe702"
A404_RESULT_SHA256 = "ded81a43fed7318ab8a0d32787d5e41e1c51b70e473dfc415dae30b44f4080e1"
A410_RESULT_SHA256 = "d631fcc57f1659455417789c58f277aa6d78118eb361281137bdcb846bae284e"
A388_ORDER_SHA256 = "3c56ce8521b1ced20e1e3a90999810c2e563c4de941701c86274f0828b5d01b8"

TARGETS = tuple(range(32))
SELECTION_TARGETS = tuple(range(16))
HOLDOUT_TARGETS = tuple(range(16, 32))
CELLS = 4096
WIDTH = 50
MASK50 = (1 << WIDTH) - 1
DEFAULT_SLICE_WORKERS = 8
DOTCAUSAL_SRC = Path("/Users/bhkmie/Documents/Forschung/O1/vendor/fabel/dotcausal_package/src")


def load_module(path: Path, name: str) -> Any:
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot import A412 dependency {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


A410 = load_module(A410_RUNNER, "a412_a410")
A401 = A410.A401
A402 = A410.A402
ORIGINAL_A401_ARTIFACTS = A401.ARTIFACTS
ORIGINAL_A401_MEASUREMENTS = A401.MEASUREMENTS

file_sha256 = A401.file_sha256
canonical_sha256 = A401.canonical_sha256
atomic_json = A401.atomic_json
atomic_bytes = A401.atomic_bytes
relative = A401.relative
anchor = A401.anchor
sha256 = A401.sha256


@contextmanager
def a401_paths(artifacts: Path, measurements: Path) -> Iterator[None]:
    previous_artifacts = A401.ARTIFACTS
    previous_measurements = A401.MEASUREMENTS
    A401.ARTIFACTS = artifacts
    A401.MEASUREMENTS = measurements
    try:
        yield
    finally:
        A401.ARTIFACTS = previous_artifacts
        A401.MEASUREMENTS = previous_measurements


def load_design() -> dict[str, Any]:
    if file_sha256(DESIGN) != DESIGN_SHA256:
        raise RuntimeError("A412 design hash differs")
    value = json.loads(DESIGN.read_bytes())
    corpus = value.get("corpus_contract", {})
    measurement = value.get("measurement_contract", {})
    reader = value.get("reader_contract", {})
    boundary = value.get("information_boundary", {})
    if (
        value.get("schema") != "chacha20-round20-w50-fresh-hybrid-reader-a412-design-v1"
        or value.get("attempt_id") != ATTEMPT_ID
        or value.get("design_state")
        != "frozen_after_A404_A410_source_results_before_any_A412_challenge_measurement_label_score_or_candidate"
        or tuple(corpus.get("target_indices", [])) != TARGETS
        or tuple(corpus.get("selection_indices", [])) != SELECTION_TARGETS
        or tuple(corpus.get("holdout_indices", [])) != HOLDOUT_TARGETS
        or corpus.get("rounds") != 20
        or corpus.get("feedforward") is not True
        or corpus.get("unknown_key_bits") != WIDTH
        or measurement.get("complete_direct12_cells_per_target") != CELLS
        or measurement.get("total_solver_stages") != len(TARGETS) * CELLS * 4
        or measurement.get("measurement_must_not_read_either_label_ledger") is not True
        or reader.get("candidate_count") != 35
        or boundary.get("A412_public_challenge_or_label_available_at_design_freeze") is not False
        or boundary.get("A412_measurement_or_score_available_at_design_freeze") is not False
        or boundary.get("selection_reads_holdout_labels") is not False
        or boundary.get("production_target_labels_used") != 0
    ):
        raise RuntimeError("A412 frozen design semantics differ")
    for key, path in value["source_contract"].items():
        if key.endswith("_path"):
            stem = key.removesuffix("_path")
            anchor(ROOT / path, value["source_contract"][f"{stem}_sha256"])
    return value


def candidate_rows() -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for weight in range(17):
        rows.append(
            {
                "candidate_index": len(rows),
                "family": "weighted_borda",
                "family_index": 0,
                "A404_weight": weight,
                "A410_weight": 16 - weight,
                "singleton": weight in {0, 16},
            }
        )
    for weight in range(1, 16):
        rows.append(
            {
                "candidate_index": len(rows),
                "family": "weighted_reciprocal",
                "family_index": 1,
                "A404_weight": weight,
                "A410_weight": 16 - weight,
                "singleton": False,
            }
        )
    for family_index, family in enumerate(
        ("geometric_product", "minimum_rank_wavefront", "maximum_rank_intersection"),
        start=2,
    ):
        rows.append(
            {
                "candidate_index": len(rows),
                "family": family,
                "family_index": family_index,
                "A404_weight": 8,
                "A410_weight": 8,
                "singleton": False,
            }
        )
    if len(rows) != 35 or [row["candidate_index"] for row in rows] != list(range(35)):
        raise RuntimeError("A412 candidate family differs")
    return rows


def exact_ranks(values: Sequence[int]) -> np.ndarray:
    ranks = np.asarray(values, dtype=np.int64)
    if ranks.shape != (CELLS,) or set(ranks.tolist()) != set(range(1, CELLS + 1)):
        raise ValueError("A412 rank vector differs")
    return ranks


def hybrid_order(
    a404_ranks: Sequence[int], a410_ranks: Sequence[int], candidate: Mapping[str, Any]
) -> list[int]:
    left = exact_ranks(a404_ranks)
    right = exact_ranks(a410_ranks)
    cells = np.arange(CELLS, dtype=np.int64)
    family = str(candidate["family"])
    left_weight = int(candidate["A404_weight"])
    right_weight = int(candidate["A410_weight"])
    weighted_sum = left_weight * left + right_weight * right
    if family == "weighted_borda":
        order = np.lexsort((cells, weighted_sum))
    elif family == "weighted_reciprocal":
        reciprocal = left_weight / left.astype(np.float64) + right_weight / right.astype(
            np.float64
        )
        order = np.lexsort((cells, weighted_sum, -reciprocal))
    elif family == "geometric_product":
        order = np.lexsort((cells, left + right, left * right))
    elif family == "minimum_rank_wavefront":
        order = np.lexsort((cells, left + right, np.minimum(left, right)))
    elif family == "maximum_rank_intersection":
        order = np.lexsort((cells, left + right, np.maximum(left, right)))
    else:
        raise ValueError(f"unknown A412 candidate family {family}")
    return A401.exact_order(order.tolist())


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


def deterministic_assignment(index: int) -> int:
    if index not in TARGETS:
        raise ValueError("A412 target index differs")
    label = f"A412|W50-fresh-hybrid-assignment|v1|target-{index:02d}"
    return int.from_bytes(hashlib.shake_256(label.encode()).digest(8), "little") & MASK50


def public_material_label(index: int) -> str:
    if index not in TARGETS:
        raise ValueError("A412 target index differs")
    return f"A412|W50-fresh-hybrid-public-material|v1|target-{index:02d}"


def build_corpus_payloads() -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    challenges = []
    selection_rows = []
    holdout_rows = []
    source_assignments = {A401.deterministic_assignment(index) for index in A401.TARGETS}
    assignments = [deterministic_assignment(index) for index in TARGETS]
    if len(set(assignments)) != len(assignments) or set(assignments) & source_assignments:
        raise RuntimeError("A412 fresh assignment separation differs")
    for index, assignment in zip(TARGETS, assignments, strict=True):
        challenge = A401.A385.challenge_from_assignment(
            label=public_material_label(index), assignment=assignment
        )
        A401.A385.validate_challenge(challenge)
        if "assignment" in challenge or challenge.get("unknown_assignment_included") is not False:
            raise RuntimeError("A412 public challenge contains a label")
        challenges.append(
            {
                "target_index": index,
                "public_challenge": challenge,
                "public_challenge_sha256": canonical_sha256(challenge),
            }
        )
        cell = A401.true_cell(assignment)
        row = {
            "target_index": index,
            "assignment": assignment,
            "assignment_hex": f"{assignment:013x}",
            "true_direct12_cell": cell,
            "true_direct12_cell_hex": f"{cell:03x}",
            "assignment_derivation_sha256": sha256(
                f"A412|W50-fresh-hybrid-assignment|v1|target-{index:02d}".encode()
            ),
        }
        (selection_rows if index in SELECTION_TARGETS else holdout_rows).append(row)
    selection = {
        "schema": "chacha20-round20-w50-fresh-hybrid-reader-a412-selection-labels-v1",
        "attempt_id": ATTEMPT_ID,
        "target_indices": list(SELECTION_TARGETS),
        "labels": selection_rows,
    }
    selection["label_commitment_sha256"] = canonical_sha256(selection)
    holdout = {
        "schema": "chacha20-round20-w50-fresh-hybrid-reader-a412-holdout-labels-v1",
        "attempt_id": ATTEMPT_ID,
        "target_indices": list(HOLDOUT_TARGETS),
        "labels": holdout_rows,
    }
    holdout["label_commitment_sha256"] = canonical_sha256(holdout)
    public = {
        "schema": "chacha20-round20-w50-fresh-hybrid-reader-a412-public-corpus-v1",
        "attempt_id": ATTEMPT_ID,
        "design_sha256": DESIGN_SHA256,
        "target_indices": list(TARGETS),
        "selection_indices": list(SELECTION_TARGETS),
        "holdout_indices": list(HOLDOUT_TARGETS),
        "challenges": challenges,
        "selection_label_commitment_sha256": selection["label_commitment_sha256"],
        "holdout_label_commitment_sha256": holdout["label_commitment_sha256"],
        "assignments_or_true_cells_in_public_corpus": False,
    }
    public["public_corpus_commitment_sha256"] = canonical_sha256(public)
    return public, selection, holdout


def freeze_implementation() -> dict[str, Any]:
    outputs = (
        IMPLEMENTATION,
        PROTOCOL,
        SELECTION_LABELS,
        HOLDOUT_LABELS,
        SELECTION,
        RESULT,
        CAUSAL,
        REPORT,
    )
    if any(path.exists() for path in outputs) or ARTIFACTS.exists() or MEASUREMENTS.exists():
        raise FileExistsError("A412 implementation or generated artifact already exists")
    load_design()
    if not TEST.exists() or not REPRO.exists():
        raise FileNotFoundError("A412 test and reproducer must precede freeze")
    public, selection, holdout = build_corpus_payloads()
    payload: dict[str, Any] = {
        "schema": "chacha20-round20-w50-fresh-hybrid-reader-a412-implementation-v1",
        "attempt_id": ATTEMPT_ID,
        "commitment_state": "frozen_before_A412_corpus_measurement_selection_or_holdout_evaluation",
        "design_sha256": DESIGN_SHA256,
        "candidate_family": candidate_rows(),
        "candidate_family_commitment_sha256": canonical_sha256(candidate_rows()),
        "selection_label_commitment_sha256": selection["label_commitment_sha256"],
        "holdout_label_commitment_sha256": holdout["label_commitment_sha256"],
        "public_corpus_commitment_sha256": public["public_corpus_commitment_sha256"],
        "anchors": {
            "design": anchor(DESIGN, DESIGN_SHA256),
            "A401_runner": anchor(A401.ROOT / "research/experiments/chacha20_round20_w50_knownkey_direct12_learning_a401.py", A401_RUNNER_SHA256),
            "A401_result": anchor(A401_RESULT, A401_RESULT_SHA256),
            "A404_result": anchor(A404_RESULT, A404_RESULT_SHA256),
            "A410_result": anchor(A410_RESULT, A410_RESULT_SHA256),
            "A388_order": anchor(A388_ORDER, A388_ORDER_SHA256),
            "runner": anchor(Path(__file__)),
            "test": anchor(TEST),
            "reproducer": anchor(REPRO),
        },
    }
    payload["implementation_commitment_sha256"] = canonical_sha256(payload)
    atomic_json(IMPLEMENTATION, payload)
    public["implementation_sha256"] = file_sha256(IMPLEMENTATION)
    public["implementation_commitment_sha256"] = payload["implementation_commitment_sha256"]
    public["anchors"] = {
        "design": anchor(DESIGN, DESIGN_SHA256),
        "implementation": anchor(IMPLEMENTATION),
        "runner": anchor(Path(__file__)),
    }
    public["protocol_commitment_sha256"] = canonical_sha256(public)
    atomic_json(SELECTION_LABELS, selection)
    atomic_json(HOLDOUT_LABELS, holdout)
    atomic_json(PROTOCOL, public)
    return payload


def load_implementation(expected_sha256: str | None = None) -> dict[str, Any]:
    if expected_sha256 is not None and file_sha256(IMPLEMENTATION) != expected_sha256:
        raise RuntimeError("A412 implementation hash differs")
    value = json.loads(IMPLEMENTATION.read_bytes())
    if (
        value.get("schema")
        != "chacha20-round20-w50-fresh-hybrid-reader-a412-implementation-v1"
        or value.get("attempt_id") != ATTEMPT_ID
        or value.get("design_sha256") != DESIGN_SHA256
        or value.get("candidate_family") != candidate_rows()
        or value.get("candidate_family_commitment_sha256")
        != canonical_sha256(candidate_rows())
    ):
        raise RuntimeError("A412 implementation semantics differ")
    for row in value["anchors"].values():
        anchor(ROOT / row["path"], row["sha256"])
    unsigned = {
        key: item for key, item in value.items() if key != "implementation_commitment_sha256"
    }
    if value.get("implementation_commitment_sha256") != canonical_sha256(unsigned):
        raise RuntimeError("A412 implementation commitment differs")
    return value


def load_protocol(expected_sha256: str | None = None) -> dict[str, Any]:
    if expected_sha256 is not None and file_sha256(PROTOCOL) != expected_sha256:
        raise RuntimeError("A412 public corpus hash differs")
    value = json.loads(PROTOCOL.read_bytes())
    if (
        value.get("schema") != "chacha20-round20-w50-fresh-hybrid-reader-a412-public-corpus-v1"
        or value.get("attempt_id") != ATTEMPT_ID
        or tuple(value.get("target_indices", [])) != TARGETS
        or tuple(value.get("selection_indices", [])) != SELECTION_TARGETS
        or tuple(value.get("holdout_indices", [])) != HOLDOUT_TARGETS
        or value.get("assignments_or_true_cells_in_public_corpus") is not False
        or len(value.get("challenges", [])) != len(TARGETS)
    ):
        raise RuntimeError("A412 public corpus semantics differ")
    for index, row in enumerate(value["challenges"]):
        if (
            row.get("target_index") != index
            or canonical_sha256(row["public_challenge"]) != row.get("public_challenge_sha256")
        ):
            raise RuntimeError("A412 public challenge commitment differs")
        A401.A385.validate_challenge(row["public_challenge"])
    load_implementation(value["implementation_sha256"])
    return value


def load_label(path: Path, schema: str, targets: Sequence[int]) -> dict[int, dict[str, Any]]:
    value = json.loads(path.read_bytes())
    if (
        value.get("schema") != schema
        or value.get("attempt_id") != ATTEMPT_ID
        or tuple(value.get("target_indices", [])) != tuple(targets)
    ):
        raise RuntimeError("A412 label ledger differs")
    unsigned = {key: item for key, item in value.items() if key != "label_commitment_sha256"}
    if value.get("label_commitment_sha256") != canonical_sha256(unsigned):
        raise RuntimeError("A412 label commitment differs")
    rows = {int(row["target_index"]): dict(row) for row in value["labels"]}
    if tuple(rows) != tuple(targets):
        raise RuntimeError("A412 label target order differs")
    return rows


def fresh_complete_path(index: int) -> Path:
    return MEASUREMENTS / f"target_{index:02d}/complete_v1.json"


def load_fresh_complete(index: int, protocol: Mapping[str, Any]) -> dict[str, Any]:
    with a401_paths(ARTIFACTS, MEASUREMENTS):
        value = A401.load_target_complete(index)
    if value.get("public_challenge_sha256") != protocol["challenges"][index][
        "public_challenge_sha256"
    ]:
        raise RuntimeError("A412 measured challenge differs")
    return value


def measure_all(*, expected_protocol_sha256: str, slice_workers: int) -> dict[str, Any]:
    if not 1 <= slice_workers <= 10:
        raise ValueError("A412 slice workers must lie in 1..10")
    protocol = load_protocol(expected_protocol_sha256)
    started = time.perf_counter()
    completed: list[int] = []
    for index in TARGETS:
        with a401_paths(ARTIFACTS, MEASUREMENTS):
            A401.measure_target(index, protocol, slice_workers)
        complete = load_fresh_complete(index, protocol)
        completed.append(index)
        atomic_json(
            PROGRESS,
            {
                "schema": "chacha20-round20-w50-fresh-hybrid-reader-a412-progress-v1",
                "attempt_id": ATTEMPT_ID,
                "protocol_sha256": expected_protocol_sha256,
                "completed_target_indices": completed,
                "completed_targets": len(completed),
                "target_count": len(TARGETS),
                "complete_direct12_cells": len(completed) * CELLS,
                "solver_stages": len(completed) * CELLS * 4,
                "selection_or_holdout_labels_opened": False,
                "candidate_assignments_executed": 0,
                "latest_target_measurement_sha256": complete["measurement_sha256"],
                "volatile_wall_seconds": time.perf_counter() - started,
            },
        )
    return json.loads(PROGRESS.read_bytes())


def fresh_rank_matrix(index: int) -> tuple[np.ndarray, dict[str, Any]]:
    with a401_paths(ARTIFACTS, MEASUREMENTS):
        return A401.view_rank_matrix(index)


def source_bundle() -> dict[str, Any]:
    if (
        file_sha256(A401_RESULT) != A401_RESULT_SHA256
        or file_sha256(A404_RESULT) != A404_RESULT_SHA256
        or file_sha256(A410_RESULT) != A410_RESULT_SHA256
    ):
        raise RuntimeError("A412 source result hash differs")
    a404 = json.loads(A404_RESULT.read_bytes())
    a410 = json.loads(A410_RESULT.read_bytes())
    a404_candidate = a404.get("fullfit_candidate")
    a410_candidate = a410.get("fullfit_candidate")
    if (
        a404.get("leaveoneout", {}).get("qualified") is not True
        or a404_candidate is None
        or a404_candidate.get("aggregator") != "minimum_rank_then_sum"
        or a404_candidate.get("view_indices") != [0, 3, 7]
        or a410.get("comparison", {}).get("qualified") is not True
        or a410_candidate is None
        or a410_candidate.get("representation") != "log_absdiff36"
        or a410_candidate.get("metric") != "mean_squared_L2"
        or a410_candidate.get("neighbours") != "all_training_prototypes"
    ):
        raise RuntimeError("A412 source Reader identity differs")
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
    source_representations: dict[int, np.ndarray] = {}
    source_field_commitments: dict[str, Any] = {}
    with a401_paths(ORIGINAL_A401_ARTIFACTS, ORIGINAL_A401_MEASUREMENTS):
        for index in A401.TARGETS:
            ranks, source_field_commitments[str(index)] = A401.view_rank_matrix(index)
            source_representations[index] = A410.representation_matrices(ranks)[
                "log_absdiff36"
            ]
    prototypes = np.stack(
        [
            source_representations[index][int(labels[index]["true_direct12_cell"])]
            for index in A401.TARGETS
        ]
    )
    if prototypes.shape != (16, 36) or not np.isfinite(prototypes).all():
        raise RuntimeError("A412 source prototype matrix differs")
    prototype_sha = sha256(np.asarray(prototypes, dtype="<f8").tobytes())
    if prototype_sha != a410.get("production_prototype_float64le_sha256"):
        raise RuntimeError("A412 reconstructed prototype commitment differs")
    return {
        "A404_candidate": a404_candidate,
        "A410_candidate": a410_candidate,
        "prototypes": prototypes,
        "prototype_float64le_sha256": prototype_sha,
        "source_field_commitments": source_field_commitments,
    }


def reader_orders(
    rank_matrix: np.ndarray, bundle: Mapping[str, Any]
) -> tuple[list[int], list[int], dict[str, str]]:
    a404_candidate = bundle["A404_candidate"]
    a404_order = A401.candidate_order(
        rank_matrix,
        a404_candidate["view_indices"],
        str(a404_candidate["aggregator"]),
    )
    field = A410.representation_matrices(rank_matrix)["log_absdiff36"]
    distances = A410.distance_rows(field, bundle["prototypes"], "mean_squared_L2")
    scores = A410.score_panel(distances)[:, 3]
    cells = np.arange(CELLS, dtype=np.int64)
    a410_order = A401.exact_order(np.lexsort((cells, scores)).tolist())
    return (
        a404_order,
        a410_order,
        {
            "A404_order_uint16be_sha256": A401.A400_uint16_sha(a404_order),
            "A410_order_uint16be_sha256": A401.A400_uint16_sha(a410_order),
            "A410_score_float64le_sha256": sha256(
                np.asarray(scores, dtype="<f8").tobytes()
            ),
        },
    )


def field_truth_ranks(
    rank_matrix: np.ndarray,
    bundle: Mapping[str, Any],
    true_cell: int,
    candidates: Sequence[Mapping[str, Any]],
) -> tuple[list[int], dict[str, Any]]:
    a404_order, a410_order, metadata = reader_orders(rank_matrix, bundle)
    a404_ranks = A401.rank_vector(a404_order)
    a410_ranks = A401.rank_vector(a410_order)
    truth = []
    order_hashes = []
    for candidate in candidates:
        order = hybrid_order(a404_ranks, a410_ranks, candidate)
        truth.append(int(A401.rank_vector(order)[true_cell]))
        order_hashes.append(A401.A400_uint16_sha(order))
    metadata.update(
        {
            "candidate_order_uint16be_sha256": order_hashes,
            "candidate_order_commitment_sha256": canonical_sha256(order_hashes),
        }
    )
    return truth, metadata


def freeze_selection(*, expected_implementation_sha256: str) -> dict[str, Any]:
    if SELECTION.exists() or RESULT.exists() or CAUSAL.exists() or REPORT.exists():
        raise FileExistsError("A412 selection or result already exists")
    implementation = load_implementation(expected_implementation_sha256)
    protocol = load_protocol()
    for index in TARGETS:
        load_fresh_complete(index, protocol)
    labels = load_label(
        SELECTION_LABELS,
        "chacha20-round20-w50-fresh-hybrid-reader-a412-selection-labels-v1",
        SELECTION_TARGETS,
    )
    candidates = implementation["candidate_family"]
    bundle = source_bundle()
    truth = np.empty((len(SELECTION_TARGETS), len(candidates)), dtype=np.int64)
    field_commitments: dict[str, Any] = {}
    reader_commitments: dict[str, Any] = {}
    for row_index, target in enumerate(SELECTION_TARGETS):
        ranks, field_commitments[str(target)] = fresh_rank_matrix(target)
        values, reader_commitments[str(target)] = field_truth_ranks(
            ranks, bundle, int(labels[target]["true_direct12_cell"]), candidates
        )
        truth[row_index] = values
    candidate_metrics = []
    for index, candidate in enumerate(candidates):
        panel = metric_panel(truth[:, index].tolist())
        candidate_metrics.append({**candidate, "selection_panel": panel})
    winner_index = min(
        range(len(candidates)),
        key=lambda index: (
            candidate_metrics[index]["selection_panel"]["mean_log2_rank"],
            candidate_metrics[index]["selection_panel"]["worst_rank"],
            candidate_metrics[index]["family_index"],
            candidate_metrics[index]["A404_weight"],
        ),
    )
    payload: dict[str, Any] = {
        "schema": "chacha20-round20-w50-fresh-hybrid-reader-a412-selection-v1",
        "attempt_id": ATTEMPT_ID,
        "selection_state": "frozen_after_fresh_targets_0_15_before_holdout_labels_or_scores",
        "design_sha256": DESIGN_SHA256,
        "implementation_sha256": expected_implementation_sha256,
        "implementation_commitment_sha256": implementation[
            "implementation_commitment_sha256"
        ],
        "selection_label_commitment_sha256": implementation[
            "selection_label_commitment_sha256"
        ],
        "holdout_label_commitment_sha256": implementation["holdout_label_commitment_sha256"],
        "candidate_family_commitment_sha256": implementation[
            "candidate_family_commitment_sha256"
        ],
        "selected_candidate": candidate_metrics[winner_index],
        "selected_candidate_index": winner_index,
        "candidate_metrics": candidate_metrics,
        "selection_truth_rank_table_int32le_sha256": sha256(
            truth.astype("<i4").tobytes()
        ),
        "selection_field_commitments": field_commitments,
        "selection_reader_commitments": reader_commitments,
        "source_prototype_float64le_sha256": bundle["prototype_float64le_sha256"],
        "holdout_labels_or_scores_consumed": False,
        "production_target_labels_used": 0,
        "live_recovery_progress_filter_outcomes_or_results_consumed": False,
        "anchors": {
            "design": anchor(DESIGN, DESIGN_SHA256),
            "implementation": anchor(IMPLEMENTATION, expected_implementation_sha256),
            "protocol": anchor(PROTOCOL),
            "selection_labels": anchor(SELECTION_LABELS),
            "A401_result": anchor(A401_RESULT, A401_RESULT_SHA256),
            "A404_result": anchor(A404_RESULT, A404_RESULT_SHA256),
            "A410_result": anchor(A410_RESULT, A410_RESULT_SHA256),
            "runner": anchor(Path(__file__)),
        },
    }
    payload["selection_commitment_sha256"] = canonical_sha256(
        {
            "candidate_family_commitment_sha256": payload[
                "candidate_family_commitment_sha256"
            ],
            "selected_candidate": payload["selected_candidate"],
            "selection_truth_rank_table_int32le_sha256": payload[
                "selection_truth_rank_table_int32le_sha256"
            ],
            "source_prototype_float64le_sha256": payload[
                "source_prototype_float64le_sha256"
            ],
        }
    )
    atomic_json(SELECTION, payload)
    return payload


def load_selection(expected_sha256: str | None = None) -> dict[str, Any]:
    if expected_sha256 is not None and file_sha256(SELECTION) != expected_sha256:
        raise RuntimeError("A412 selection hash differs")
    value = json.loads(SELECTION.read_bytes())
    if (
        value.get("schema") != "chacha20-round20-w50-fresh-hybrid-reader-a412-selection-v1"
        or value.get("attempt_id") != ATTEMPT_ID
        or value.get("selection_state")
        != "frozen_after_fresh_targets_0_15_before_holdout_labels_or_scores"
        or value.get("holdout_labels_or_scores_consumed") is not False
        or value.get("selected_candidate") not in value.get("candidate_metrics", [])
    ):
        raise RuntimeError("A412 selection semantics differ")
    load_implementation(value["implementation_sha256"])
    return value


def build_causal(payload: Mapping[str, Any]) -> dict[str, Any]:
    sys.path.insert(0, str(DOTCAUSAL_SRC))
    from dotcausal.io import CausalReader, CausalWriter

    qualified = bool(payload["holdout_comparison"]["qualified"])
    terminal = (
        "A412_fresh_holdout_qualified_production_order"
        if qualified
        else "A412_fresh_holdout_boundary_retained"
    )
    writer = CausalWriter(api_id="a412w50")
    writer._rules = []
    writer.add_rule(
        name="source_readers_to_frozen_hybrid_family",
        description="A404 and A410 fix two complementary cell orders and thirty-five deterministic rank-space compositions before any A412 field exists.",
        pattern=["A404_rank_fusion_reader", "A410_prototype_manifold_reader"],
        conclusion="A412_frozen_hybrid_family",
        confidence_modifier=1.0,
    )
    writer.add_rule(
        name="fresh_selection_to_single_candidate",
        description="Sixteen new complete fields select one byte-frozen candidate before the separate holdout ledger opens.",
        pattern=["A412_frozen_hybrid_family", "A412_fresh_selection_fields_0_15"],
        conclusion="A412_selected_reader",
        confidence_modifier=1.0,
    )
    writer.add_rule(
        name="fresh_holdout_to_production_boundary",
        description="The selected Reader is scored unchanged on sixteen further fresh fields; only strict singleton-beating transfer permits zero-refit A388 deployment.",
        pattern=["A412_selected_reader", "A412_fresh_holdout_fields_16_31"],
        conclusion=terminal,
        confidence_modifier=1.0,
    )
    writer.add_triplet(
        trigger="A404:rank_fusion_plus_A410:prototype_manifold",
        mechanism="frozen_thirtyfive_member_rank_space_composition",
        outcome="A412:frozen_hybrid_reader_family",
        confidence=1.0,
        source=payload["candidate_family_commitment_sha256"],
        quantification=json.dumps(payload["selection"]["selected_candidate"], sort_keys=True),
        evidence="candidate family precedes every A412 challenge, measurement and label score",
        domain="full-round ChaCha20 W50 known-key Reader transfer",
        quality_score=1.0,
    )
    writer.add_triplet(
        trigger="A412:frozen_hybrid_reader_family",
        mechanism="sixteen_fresh_selection_then_sixteen_fresh_untouched_holdout",
        outcome=f"A412:{terminal}",
        confidence=1.0,
        source=payload["measurement_sha256"],
        quantification=json.dumps(payload["holdout_comparison"], sort_keys=True),
        evidence="holdout labels unopened until one candidate was hash-frozen",
        domain="fresh same-width independent holdout",
        quality_score=1.0,
    )
    writer.add_triplet(
        trigger="A404:rank_fusion_plus_A410:prototype_manifold",
        mechanism="materialized_fresh_selection_holdout_closure",
        outcome=f"A412:{terminal}",
        confidence=1.0,
        source="materialized:A412_fresh_hybrid_chain",
        quantification="exact retained closure",
        evidence="A412 design, implementation, selection and holdout commitments",
        domain="AI-native retained inference",
        quality_score=1.0,
        is_inferred=True,
    )
    writer.add_cluster(
        name="A412 fresh W50 hybrid Reader transfer",
        entities=[
            "A404:rank_fusion_plus_A410:prototype_manifold",
            "A412:frozen_hybrid_reader_family",
            f"A412:{terminal}",
        ],
    )
    writer.add_gap(
        subject=f"A412:{terminal}",
        predicate="next_required_object",
        expected_object_type=(
            "complete_group_recovery_in_the_fresh_holdout_qualified_order"
            if qualified
            else "new_disjoint_knownkey_corpus_or_reader_geometry"
        ),
        confidence=1.0,
        suggested_queries=[
            "Execute the exact A412 production order with matched control."
            if qualified
            else "Use the fresh selection and holdout residuals to freeze the next Reader family."
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
        reader.api_id != "a412w50"
        or len(explicit) != 2
        or len(all_rows) != 3
        or len(inferred) != 1
        or len(reader._rules) != 3
        or len(reader._clusters) != 1
        or len(reader._gaps) != 1
    ):
        raise RuntimeError("A412 authentic Causal reopen gate failed")
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
            "family": explicit[0],
            "fresh_holdout": explicit[1],
            "terminal_chain": all_rows[-1],
            "next_gap": reader._gaps[0],
        },
    }


def materialize(
    *, expected_implementation_sha256: str, expected_selection_sha256: str
) -> dict[str, Any]:
    if RESULT.exists() or CAUSAL.exists() or REPORT.exists():
        raise FileExistsError("A412 result already exists")
    implementation = load_implementation(expected_implementation_sha256)
    selection = load_selection(expected_selection_sha256)
    load_protocol()
    labels = load_label(
        HOLDOUT_LABELS,
        "chacha20-round20-w50-fresh-hybrid-reader-a412-holdout-labels-v1",
        HOLDOUT_TARGETS,
    )
    bundle = source_bundle()
    candidate = selection["selected_candidate"]
    selected_ranks = []
    a404_ranks = []
    a410_ranks = []
    field_commitments: dict[str, Any] = {}
    reader_commitments: dict[str, Any] = {}
    for target in HOLDOUT_TARGETS:
        rank_matrix, field_commitments[str(target)] = fresh_rank_matrix(target)
        left_order, right_order, metadata = reader_orders(rank_matrix, bundle)
        left = A401.rank_vector(left_order)
        right = A401.rank_vector(right_order)
        selected_order = hybrid_order(left, right, candidate)
        cell = int(labels[target]["true_direct12_cell"])
        a404_ranks.append(int(left[cell]))
        a410_ranks.append(int(right[cell]))
        selected_ranks.append(int(A401.rank_vector(selected_order)[cell]))
        metadata["selected_order_uint16be_sha256"] = A401.A400_uint16_sha(selected_order)
        reader_commitments[str(target)] = metadata
    selected_panel = metric_panel(selected_ranks)
    a404_panel = metric_panel(a404_ranks)
    a410_panel = metric_panel(a410_ranks)
    baseline_name, baseline_panel = min(
        (("A404", a404_panel), ("A410", a410_panel)),
        key=lambda item: (item[1]["mean_log2_rank"], item[0]),
    )
    factor = baseline_panel["geometric_mean_rank"] / selected_panel["geometric_mean_rank"]
    gain = (
        selected_panel["bit_gain_vs_complete_4096_cover"]
        - baseline_panel["bit_gain_vs_complete_4096_cover"]
    )
    qualified = candidate["singleton"] is False and factor > 1.0 and gain > 0.0
    comparison = {
        "qualified": qualified,
        "selected_candidate_is_non_singleton": candidate["singleton"] is False,
        "best_singleton": baseline_name,
        "selected_panel": selected_panel,
        "A404_singleton_panel": a404_panel,
        "A410_singleton_panel": a410_panel,
        "geometric_rank_improvement_factor": factor,
        "additional_bit_gain": gain,
        "selected_better_holdouts": sum(
            left < right
            for left, right in zip(selected_ranks, baseline_panel["ranks"], strict=True)
        ),
        "selected_equal_holdouts": sum(
            left == right
            for left, right in zip(selected_ranks, baseline_panel["ranks"], strict=True)
        ),
        "selected_worse_holdouts": sum(
            left > right
            for left, right in zip(selected_ranks, baseline_panel["ranks"], strict=True)
        ),
    }
    production_order = None
    production_metadata = None
    production_diversity = None
    if qualified:
        with a401_paths(ORIGINAL_A401_ARTIFACTS, ORIGINAL_A401_MEASUREMENTS):
            production_ranks, view_orders, production_metadata = A402.production_rank_matrix()
        left_order, right_order, source_metadata = reader_orders(production_ranks, bundle)
        production_order = hybrid_order(
            A401.rank_vector(left_order), A401.rank_vector(right_order), candidate
        )
        production_metadata = {**production_metadata, **source_metadata}
        production_diversity = {
            "A404": A401.A388.A351.diversity_panel(production_order, left_order),
            "A410": A401.A388.A351.diversity_panel(production_order, right_order),
            **{
                name: A401.A388.A351.diversity_panel(production_order, view_orders[name])
                for name in A401.VIEW_NAMES
            },
        }
    payload: dict[str, Any] = {
        "schema": "chacha20-round20-w50-fresh-hybrid-reader-a412-result-v1",
        "attempt_id": ATTEMPT_ID,
        "evidence_stage": (
            "FRESH_SIXTEEN_KEY_HOLDOUT_QUALIFIED_HYBRID_APPLIED_ZERO_REFIT_TO_A388"
            if qualified
            else "FRESH_SIXTEEN_KEY_HOLDOUT_READER_BOUNDARY_RETAINED"
        ),
        "design_sha256": DESIGN_SHA256,
        "implementation_sha256": expected_implementation_sha256,
        "implementation_commitment_sha256": implementation[
            "implementation_commitment_sha256"
        ],
        "selection_sha256": expected_selection_sha256,
        "selection": {
            "selection_state": selection["selection_state"],
            "selected_candidate": candidate,
            "selection_commitment_sha256": selection["selection_commitment_sha256"],
        },
        "holdout_comparison": comparison,
        "production_order": production_order,
        "production_order_uint16be_sha256": (
            A401.A400_uint16_sha(production_order) if production_order is not None else None
        ),
        "production_view_metadata": production_metadata,
        "production_operator_diversity": production_diversity,
        "candidate_family_commitment_sha256": implementation[
            "candidate_family_commitment_sha256"
        ],
        "source_prototype_float64le_sha256": bundle["prototype_float64le_sha256"],
        "source_field_commitments": bundle["source_field_commitments"],
        "fresh_holdout_field_commitments": field_commitments,
        "fresh_holdout_reader_commitments": reader_commitments,
        "complete_targets_measured": len(TARGETS),
        "complete_direct12_cells_measured": len(TARGETS) * CELLS,
        "solver_stages_measured": len(TARGETS) * CELLS * 4,
        "measurement_target_labels_used": 0,
        "reader_refits_during_measurement": 0,
        "production_target_labels_used": 0,
        "production_reader_refits": 0,
        "production_candidate_assignments_executed": 0,
        "live_recovery_progress_filter_outcomes_or_results_consumed": False,
        "anchors": {
            "design": anchor(DESIGN, DESIGN_SHA256),
            "implementation": anchor(IMPLEMENTATION, expected_implementation_sha256),
            "protocol": anchor(PROTOCOL),
            "selection": anchor(SELECTION, expected_selection_sha256),
            "A401_result": anchor(A401_RESULT, A401_RESULT_SHA256),
            "A404_result": anchor(A404_RESULT, A404_RESULT_SHA256),
            "A410_result": anchor(A410_RESULT, A410_RESULT_SHA256),
            "A388_order": anchor(A388_ORDER, A388_ORDER_SHA256),
            "runner": anchor(Path(__file__)),
        },
    }
    payload["measurement_sha256"] = canonical_sha256(
        {
            "selection_commitment_sha256": selection["selection_commitment_sha256"],
            "holdout_comparison": comparison,
            "fresh_holdout_field_commitments": field_commitments,
            "fresh_holdout_reader_commitments": reader_commitments,
        }
    )
    payload["deployment_commitment_sha256"] = canonical_sha256(
        {
            "holdout_comparison": comparison,
            "selected_candidate": candidate,
            "production_order": production_order,
            "production_view_metadata": production_metadata,
        }
    )
    payload["causal"] = build_causal(payload)
    atomic_json(RESULT, payload)
    atomic_bytes(
        REPORT,
        (
            "# A412 — Fresh 16/16 W50 hybrid Reader holdout\n\n"
            f"Evidence stage: **{payload['evidence_stage']}**\n\n"
            f"- Selected candidate: **{candidate}**\n"
            f"- Fresh selected holdout ranks: **{selected_panel['ranks']}**\n"
            f"- Fresh A404 ranks: **{a404_panel['ranks']}**\n"
            f"- Fresh A410 ranks: **{a410_panel['ranks']}**\n"
            f"- Improvement factor: **{factor:.9f}**\n"
            f"- Additional bit gain: **{gain:.9f}**\n"
            "- Measurement labels / production labels / production refits: **0 / 0 / 0**\n"
            "- Authentic AI-native Causal readback: **2 explicit + 1 inferred chain**\n"
        ).encode(),
    )
    return payload


def analyze() -> dict[str, Any]:
    payload: dict[str, Any] = {
        "attempt_id": ATTEMPT_ID,
        "design_sha256": DESIGN_SHA256,
        "implementation_frozen": IMPLEMENTATION.exists(),
        "protocol_frozen": PROTOCOL.exists(),
        "selection_frozen": SELECTION.exists(),
        "progress_exists": PROGRESS.exists(),
        "result_complete": RESULT.exists(),
    }
    if IMPLEMENTATION.exists():
        payload["implementation_sha256"] = file_sha256(IMPLEMENTATION)
    if PROTOCOL.exists():
        payload["protocol_sha256"] = file_sha256(PROTOCOL)
    if PROGRESS.exists():
        progress = json.loads(PROGRESS.read_bytes())
        payload["completed_targets"] = progress["completed_targets"]
        payload["target_count"] = progress["target_count"]
    if SELECTION.exists():
        selection = load_selection()
        payload["selection_sha256"] = file_sha256(SELECTION)
        payload["selected_candidate"] = selection["selected_candidate"]
    if RESULT.exists():
        value = json.loads(RESULT.read_bytes())
        payload["result_sha256"] = file_sha256(RESULT)
        payload["evidence_stage"] = value["evidence_stage"]
        payload["holdout_comparison"] = value["holdout_comparison"]
    return payload


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    action = parser.add_mutually_exclusive_group(required=True)
    action.add_argument("--analyze", action="store_true")
    action.add_argument("--freeze-implementation", action="store_true")
    action.add_argument("--measure", action="store_true")
    action.add_argument("--freeze-selection", action="store_true")
    action.add_argument("--materialize", action="store_true")
    action.add_argument("--run", action="store_true")
    parser.add_argument("--expected-implementation-sha256")
    parser.add_argument("--expected-protocol-sha256")
    parser.add_argument("--expected-selection-sha256")
    parser.add_argument("--slice-workers", type=int, default=DEFAULT_SLICE_WORKERS)
    args = parser.parse_args()
    if args.freeze_implementation:
        payload = freeze_implementation()
    elif args.measure:
        if not args.expected_protocol_sha256:
            parser.error("--measure requires --expected-protocol-sha256")
        payload = measure_all(
            expected_protocol_sha256=args.expected_protocol_sha256,
            slice_workers=args.slice_workers,
        )
    elif args.freeze_selection:
        if not args.expected_implementation_sha256:
            parser.error("--freeze-selection requires --expected-implementation-sha256")
        payload = freeze_selection(
            expected_implementation_sha256=args.expected_implementation_sha256
        )
    elif args.materialize:
        if not args.expected_implementation_sha256 or not args.expected_selection_sha256:
            parser.error("--materialize requires implementation and selection SHA-256")
        payload = materialize(
            expected_implementation_sha256=args.expected_implementation_sha256,
            expected_selection_sha256=args.expected_selection_sha256,
        )
    elif args.run:
        if not IMPLEMENTATION.exists():
            freeze_implementation()
        implementation_sha = file_sha256(IMPLEMENTATION)
        protocol_sha = file_sha256(PROTOCOL)
        measure_all(expected_protocol_sha256=protocol_sha, slice_workers=args.slice_workers)
        if not SELECTION.exists():
            freeze_selection(expected_implementation_sha256=implementation_sha)
        if not RESULT.exists():
            materialize(
                expected_implementation_sha256=implementation_sha,
                expected_selection_sha256=file_sha256(SELECTION),
            )
        payload = analyze()
    else:
        payload = analyze()
    print(json.dumps(payload, indent=2, sort_keys=True), flush=True)


if __name__ == "__main__":
    main()

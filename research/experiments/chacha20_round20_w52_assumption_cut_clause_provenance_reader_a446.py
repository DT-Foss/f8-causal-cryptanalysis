#!/usr/bin/env python3
"""A446: cross-fit assumption-cut clause provenance and transfer it to W52."""

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
import zstandard

ROOT = Path(__file__).parents[2]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from arx_carry_leak import assumption_cut_provenance as PROVENANCE  # noqa: E402

RESEARCH = ROOT / "research"
CONFIGS = RESEARCH / "configs"
RESULTS = RESEARCH / "results/v1"

DESIGN = CONFIGS / "chacha20_round20_w52_assumption_cut_clause_provenance_reader_a446_design_v1.json"
IMPLEMENTATION = CONFIGS / "chacha20_round20_w52_assumption_cut_clause_provenance_reader_a446_implementation_v1.json"
RESULT = RESULTS / "chacha20_round20_w52_assumption_cut_clause_provenance_reader_a446_v1.json"
CAUSAL = RESULT.with_suffix(".causal")
REPORT = RESULT.with_suffix(".md")
TEST = ROOT / "tests/test_chacha20_round20_w52_assumption_cut_clause_provenance_reader_a446.py"
PROVENANCE_TEST = ROOT / "tests/test_assumption_cut_provenance.py"
REPRO = ROOT / "scripts/reproduce_chacha20_round20_w52_assumption_cut_clause_provenance_reader_a446.sh"
PROVENANCE_SOURCE = SRC / "arx_carry_leak/assumption_cut_provenance.py"

A359_RESULT = RESULTS / "chacha20_round20_w46_corrected_knownkey_slice_corpus_a359_v1.json"
A363_RESULT = RESULTS / "chacha20_round20_w46_polarity_invariant_validation_a363_v1.json"
A367_RESULT = RESULTS / "chacha20_round20_w46_cross_corpus_invariant_validation_a367_v1.json"
A442_RESULT = RESULTS / "chacha20_round20_w52_knownkey_meta_reader_transfer_a442_v1.json"
A445_RUNNER = RESEARCH / "experiments/chacha20_round20_w52_crossfit_raw_shape_reader_transfer_a445.py"
A445_RESULT = RESULTS / "chacha20_round20_w52_crossfit_raw_shape_reader_transfer_a445_v1.json"
A445_CAUSAL = A445_RESULT.with_suffix(".causal")
A445_READBACK = RESEARCH / "reports/CAUSAL_CHACHA20_A445_PERSONAL_READER_READBACK_V1.md"

ATTEMPT_ID = "A446"
DESIGN_SHA256 = "57e41c29599a8e025f472fd2861220a28b250554bb748b5c88bfbd448c899da6"
A359_RESULT_SHA256 = "3259526ee94241f5e4858b59cb52cb93a9ef8dbe8dc8bf40deaf4d7757db7a3f"
A363_RESULT_SHA256 = "d2601ca3190a18fe2ce13bf436d14fafd4d9a2493df13dc68d353e500d7cb09b"
A367_RESULT_SHA256 = "bb60cb96295b7ba06d46f20ff1537287b1059e990162d3ee3dedfd8909aee568"
A442_RESULT_SHA256 = "8c8222528dc3ef12ffc0fbda513061b39243daade51a70a17f0bd89c65b53b1d"
A445_RUNNER_SHA256 = "b4a9bd42262e8d038ba3e1faf83f5af603dea9c7c48a7ec86e68b2de7846f074"
A445_RESULT_SHA256 = "0c6baab83ec5a96b9efb993ecaeef9ee2b7fc6996bf89884627e4c84a3429a5f"
A445_CAUSAL_SHA256 = "93b3509521998978da0d348f2cc1fc99bfdd0639df6cbf0246d53d0aa79d4323"
A445_READBACK_SHA256 = "fc410f8479a8d325287b436877da0c81058c12b40be9962429fd2977d2f7b725"
A442_BORDA_FIELD_SHA256 = "64cb6aad1f9621df5ff6ef44bb7e06cfc2dd86871483df83195382b2abf899b0"

OPERATORS = (
    "borda_sum_baseline",
    "provenance_best_single",
    "provenance_borda_top4",
    "provenance_borda_top8",
    "provenance_borda_top16",
    "provenance_borda_top32",
    "provenance_reciprocal_top8",
    "provenance_vote_top16",
    "hybrid_borda_top8_base2",
    "hybrid_borda_top8_equal",
    "hybrid_borda_top8_prov2",
    "hybrid_borda_top16_equal",
    "hybrid_reciprocal_top8_equal",
)
TARGETS = 128
CELLS = 256
BLOCKS = 8
BLOCK_SIZE = 16
SLICES = tuple(range(16))
AXIS_CELLS = 4096
PAIR_CELLS = 1 << 24
VOTE_THRESHOLD = 64
MATERIAL_SPEARMAN_MAX = 0.98
MATERIAL_TOP65536_OVERLAP_MAX = 0.90
DOTCAUSAL_SRC = Path("/Users/bhkmie/Documents/Forschung/O1/vendor/fabel/dotcausal_package/src")


def load_module(path: Path, name: str) -> Any:
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot import A446 dependency {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


A445 = load_module(A445_RUNNER, "a446_a445")
file_sha256 = A445.file_sha256
canonical_sha256 = A445.canonical_sha256
atomic_bytes = A445.atomic_bytes
atomic_json = A445.atomic_json
relative = A445.relative
path_from_ref = A445.path_from_ref
anchor = A445.anchor
exact_order = A445.exact_order
order_to_ranks = A445.order_to_ranks
calibration_statistics = A445.calibration_statistics


def canonical_bytes(value: Any) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("ascii")


def array_sha256(value: np.ndarray, dtype: str) -> str:
    return hashlib.sha256(np.asarray(value, dtype=dtype).tobytes()).hexdigest()


def _read_measurement(ledger: Mapping[str, Any]) -> dict[str, Any]:
    path = path_from_ref(str(ledger["path"]))
    compressed = path.read_bytes()
    if hashlib.sha256(compressed).hexdigest() != ledger["compressed_sha256"]:
        raise RuntimeError(f"A446 compressed measurement differs: {path.name}")
    raw = zstandard.ZstdDecompressor().decompress(compressed)
    if hashlib.sha256(raw).hexdigest() != ledger["raw_sha256"]:
        raise RuntimeError(f"A446 raw measurement differs: {path.name}")
    value = json.loads(raw)
    run = value.get("run", {})
    if (
        canonical_bytes(value) != raw
        or value.get("complete_candidate_cover") is not True
        or run.get("learned_clause_identity_complete") is not True
        or run.get("bounded_variable_addition_enabled") is not False
        or len(run.get("stages", [])) != CELLS * len(PROVENANCE.HORIZONS)
        or len(run.get("cells", [])) != CELLS
    ):
        raise RuntimeError(f"A446 measurement semantics differ: {path.name}")
    return value


def load_calibration_measurements() -> tuple[list[dict[str, Any]], np.ndarray, list[str], dict[str, str]]:
    sources = (
        (A359_RESULT, A359_RESULT_SHA256, 32, ("A359_selection", "A359_holdout")),
        (A363_RESULT, A363_RESULT_SHA256, 32, ("A363_validation_a", "A363_validation_b")),
        (
            A367_RESULT,
            A367_RESULT_SHA256,
            64,
            ("A367_validation_a", "A367_validation_b", "A367_validation_c", "A367_validation_d"),
        ),
    )
    measurements: list[dict[str, Any]] = []
    truths: list[int] = []
    blocks: list[str] = []
    source_hashes: dict[str, str] = {}
    for path, expected_hash, expected_targets, source_blocks in sources:
        anchor(path, expected_hash)
        result = json.loads(path.read_bytes())
        ledgers = sorted(result.get("measurement_ledger", []), key=lambda row: int(row["index"]))
        labels = sorted(result.get("postclosure_labels", []), key=lambda row: int(row["index"]))
        if (
            len(ledgers) != expected_targets
            or len(labels) != expected_targets
            or [int(row["index"]) for row in ledgers] != list(range(expected_targets))
            or [int(row["index"]) for row in labels] != list(range(expected_targets))
            or any(row.get("label_revealed_after_complete_target_cover") is not True for row in labels)
        ):
            raise RuntimeError(f"A446 source ledger differs: {path.name}")
        for ledger, label in zip(ledgers, labels, strict=True):
            measurements.append(_read_measurement(ledger))
            truths.append(int(label["true_high8"]))
        blocks.extend(source_blocks)
        source_hashes[path.stem] = expected_hash
    labels_array = np.asarray(truths, dtype=np.int16)
    if len(measurements) != TARGETS or labels_array.shape != (TARGETS,) or len(blocks) != BLOCKS:
        raise RuntimeError("A446 calibration cover differs")
    return measurements, labels_array, blocks, source_hashes


def provenance_panel(
    measurements: Sequence[Mapping[str, Any]],
) -> tuple[np.ndarray, tuple[str, ...], list[str], list[str]]:
    fields: list[np.ndarray] = []
    matrix_hashes: list[str] = []
    rank_hashes: list[str] = []
    feature_names: tuple[str, ...] | None = None
    for measurement in measurements:
        matrix, names = PROVENANCE.extract_assumption_cut_matrix(measurement)
        if feature_names is None:
            feature_names = names
        elif names != feature_names:
            raise RuntimeError("A446 feature ledger differs across targets")
        normalized = PROVENANCE.target_normalize(matrix)
        ranks = PROVENANCE.exact_absolute_rank_fields(normalized)
        fields.append(ranks)
        matrix_hashes.append(array_sha256(normalized, "<f8"))
        rank_hashes.append(array_sha256(ranks, "<i2"))
    if feature_names is None:
        raise RuntimeError("A446 empty provenance panel")
    tensor = np.stack(fields)
    if tensor.shape != (TARGETS, len(feature_names), CELLS):
        raise RuntimeError("A446 provenance rank panel geometry differs")
    return tensor, feature_names, matrix_hashes, rank_hashes


def fold_partition(block: int) -> tuple[np.ndarray, np.ndarray]:
    if not 0 <= block < BLOCKS:
        raise ValueError("A446 held block differs")
    all_targets = np.arange(TARGETS, dtype=np.int64)
    start = block * BLOCK_SIZE
    stop = start + BLOCK_SIZE
    held = all_targets[start:stop]
    train = np.concatenate((all_targets[:start], all_targets[stop:]))
    if np.intersect1d(train, held).size or train.size != TARGETS - BLOCK_SIZE:
        raise RuntimeError("A446 crossfit partition leaks held targets")
    return train, held


def feature_selection(
    rank_fields: np.ndarray,
    truths: np.ndarray,
    train_indices: Sequence[int],
) -> tuple[np.ndarray, dict[str, Any]]:
    fields = np.asarray(rank_fields, dtype=np.int64)
    labels = np.asarray(truths, dtype=np.int64)
    train = np.asarray([int(value) for value in train_indices], dtype=np.int64)
    if (
        fields.ndim != 3
        or fields.shape[0] != TARGETS
        or fields.shape[2] != CELLS
        or labels.shape != (TARGETS,)
        or np.unique(train).size != train.size
        or np.any(train < 0)
        or np.any(train >= TARGETS)
    ):
        raise ValueError("A446 feature-selection panel differs")
    true_ranks = np.stack([fields[target, :, labels[target]] for target in train])
    uniform = sum(math.log2(rank) for rank in range(1, CELLS + 1)) / CELLS
    logs = np.log2(true_ranks.astype(np.float64))
    training_blocks = sorted({int(target) // BLOCK_SIZE for target in train})
    block_gains = np.stack(
        [
            uniform
            - logs[np.asarray([int(target) // BLOCK_SIZE == block for target in train])].mean(axis=0)
            for block in training_blocks
        ]
    )
    positive = np.count_nonzero(block_gains > 0.0, axis=0)
    minimum = block_gains.min(axis=0)
    all_gain = uniform - logs.mean(axis=0)
    feature_ids = np.arange(fields.shape[1], dtype=np.int64)
    order = np.lexsort((feature_ids, -all_gain, -minimum, -positive))
    ledger = {
        "training_targets": int(train.size),
        "training_target_index_sha256": hashlib.sha256(train.astype(">u2").tobytes()).hexdigest(),
        "training_blocks": training_blocks,
        "feature_count": int(fields.shape[1]),
        "feature_order_sha256": hashlib.sha256(order.astype(">u2").tobytes()).hexdigest(),
        "best_feature_index": int(order[0]),
        "best_feature_positive_training_blocks": int(positive[order[0]]),
        "best_feature_minimum_training_block_gain": float(minimum[order[0]]),
        "best_feature_all_training_gain": float(all_gain[order[0]]),
    }
    return order, ledger


def _ascending_order(primary: np.ndarray, baseline_ranks: np.ndarray) -> np.ndarray:
    values = np.asarray(primary)
    baseline = np.asarray(baseline_ranks, dtype=np.int64)
    cells = values.size
    if baseline.shape != (cells,) or np.unique(baseline).size != cells:
        raise ValueError("A446 baseline tie field differs")
    return exact_order(np.lexsort((np.arange(cells), baseline, values)), cells)


def _provenance_component(
    target_fields: np.ndarray,
    feature_order: np.ndarray,
    kind: str,
    count: int,
    baseline_ranks: np.ndarray,
) -> np.ndarray:
    selected = np.asarray(feature_order[:count], dtype=np.int64)
    ranks = np.asarray(target_fields, dtype=np.int64)[selected]
    if kind == "best":
        primary = ranks[0]
    elif kind == "borda":
        primary = ranks.sum(axis=0)
    elif kind == "reciprocal":
        primary = -(1.0 / ranks.astype(np.float64)).sum(axis=0)
    elif kind == "vote":
        votes = np.count_nonzero(ranks <= VOTE_THRESHOLD, axis=0)
        primary = -votes.astype(np.int64) * (count * CELLS + 1) + ranks.sum(axis=0)
    else:
        raise ValueError(f"A446 provenance component differs: {kind}")
    return order_to_ranks(_ascending_order(primary, baseline_ranks), CELLS)


def operator_order(
    target_fields: np.ndarray,
    baseline_ranks: np.ndarray,
    feature_order: np.ndarray,
    operator: str,
) -> np.ndarray:
    baseline = np.asarray(baseline_ranks, dtype=np.int64)
    if operator == "borda_sum_baseline":
        return exact_order(np.argsort(baseline, kind="stable"), CELLS)
    if operator == "provenance_best_single":
        provenance = _provenance_component(target_fields, feature_order, "best", 1, baseline)
        return _ascending_order(provenance, baseline)
    if operator.startswith("provenance_borda_top"):
        count = int(operator.removeprefix("provenance_borda_top"))
        provenance = _provenance_component(target_fields, feature_order, "borda", count, baseline)
        return _ascending_order(provenance, baseline)
    if operator == "provenance_reciprocal_top8":
        provenance = _provenance_component(target_fields, feature_order, "reciprocal", 8, baseline)
        return _ascending_order(provenance, baseline)
    if operator == "provenance_vote_top16":
        provenance = _provenance_component(target_fields, feature_order, "vote", 16, baseline)
        return _ascending_order(provenance, baseline)
    if operator.startswith("hybrid_borda_top"):
        suffix = operator.removeprefix("hybrid_borda_top")
        count_text, weights = suffix.split("_", 1)
        count = int(count_text)
        provenance = _provenance_component(target_fields, feature_order, "borda", count, baseline)
        base_weight, provenance_weight = {
            "base2": (2, 1),
            "equal": (1, 1),
            "prov2": (1, 2),
        }[weights]
        return _ascending_order(base_weight * baseline + provenance_weight * provenance, baseline)
    if operator == "hybrid_reciprocal_top8_equal":
        provenance = _provenance_component(target_fields, feature_order, "reciprocal", 8, baseline)
        return _ascending_order(baseline + provenance, baseline)
    raise ValueError(f"A446 unknown operator {operator}")


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
    rank_fields: np.ndarray,
    truths: np.ndarray,
    borda_field: np.ndarray,
    feature_names: Sequence[str],
) -> tuple[dict[str, Any], str, dict[str, np.ndarray]]:
    fields = {operator: np.empty((TARGETS, CELLS), dtype=np.int16) for operator in OPERATORS}
    fields["borda_sum_baseline"][:] = np.asarray(borda_field, dtype=np.int16)
    ledgers: dict[str, list[dict[str, Any]]] = {operator: [] for operator in OPERATORS}
    exact = np.arange(1, CELLS + 1, dtype=np.int16)
    for block in range(BLOCKS):
        train, held = fold_partition(block)
        feature_order, model = feature_selection(rank_fields, truths, train)
        model = {
            **model,
            "held_block": block,
            "held_target_indices": held.tolist(),
            "top32_feature_indices": feature_order[:32].tolist(),
            "top32_feature_names": [str(feature_names[index]) for index in feature_order[:32]],
        }
        model["model_sha256"] = canonical_sha256(model)
        ledgers["borda_sum_baseline"].append(
            {
                "held_block": block,
                "held_target_indices": held.tolist(),
                "training_targets": 0,
                "model_sha256": "fixed:A442_borda_sum",
            }
        )
        for operator in OPERATORS[1:]:
            for target in held:
                order = operator_order(
                    rank_fields[target], borda_field[target], feature_order, operator
                )
                fields[operator][target, order] = exact
            ledgers[operator].append(model)
    evaluations: dict[str, Any] = {}
    for operator in OPERATORS:
        field = fields[operator]
        if any(
            np.unique(field[target]).size != CELLS
            or int(field[target].min()) != 1
            or int(field[target].max()) != CELLS
            for target in range(TARGETS)
        ):
            raise RuntimeError(f"A446 nonexact rank field: {operator}")
        evaluations[operator] = {
            "operator": operator,
            "evaluation_mode": "fixed_no_fit" if operator == OPERATORS[0] else "eight_fold_block_exclusive_crossfit",
            **calibration_statistics(field, truths),
            "rank_field_sha256": hashlib.sha256(field.tobytes()).hexdigest(),
            "fold_ledger": ledgers[operator],
        }
    selected = min(OPERATORS, key=lambda operator: selection_key(evaluations[operator]))
    return evaluations, selected, fields


def load_design() -> dict[str, Any]:
    if file_sha256(DESIGN) != DESIGN_SHA256:
        raise RuntimeError("A446 design hash differs")
    value = json.loads(DESIGN.read_bytes())
    calibration = value.get("calibration_contract", {})
    transfer = value.get("W52_transfer_contract", {})
    boundary = value.get("information_boundary", {})
    if (
        value.get("schema") != "chacha20-round20-w52-assumption-cut-clause-provenance-reader-a446-design-v1"
        or value.get("attempt_id") != ATTEMPT_ID
        or tuple(calibration.get("fixed_operator_order", [])) != OPERATORS
        or calibration.get("targets") != TARGETS
        or calibration.get("cells_per_target") != CELLS
        or calibration.get("fixed_blocks") != BLOCKS
        or calibration.get("all_feature_families_operators_hyperparameters_and_ties_defined_before_evaluation") is not True
        or transfer.get("axis_cells") != AXIS_CELLS
        or transfer.get("pair_cells") != PAIR_CELLS
        or transfer.get("W52_target_labels_used") != 0
        or transfer.get("W52_model_refits") != 0
        or transfer.get("new_solver_stages") != 0
        or transfer.get("candidate_assignments_executed") != 0
        or boundary.get("A445_authentic_Causal_personally_read") is not True
        or boundary.get("A446_feature_values_or_label_associations_known_before_design_freeze") is not False
        or boundary.get("A446_operator_results_known_before_design_freeze") is not False
        or boundary.get("A446_W52_orders_known_before_design_freeze") is not False
    ):
        raise RuntimeError("A446 design semantics differ")
    anchors = value["source_anchors"]
    for key, path_value in anchors.items():
        if key.endswith("_path"):
            stem = key.removesuffix("_path")
            anchor(ROOT / path_value, anchors[f"{stem}_sha256"])
    return value


def load_sources() -> tuple[dict[str, Any], dict[str, Any], dict[str, Any], dict[str, Any], Any]:
    anchor(A445_RUNNER, A445_RUNNER_SHA256)
    anchor(A445_RESULT, A445_RESULT_SHA256)
    anchor(A445_CAUSAL, A445_CAUSAL_SHA256)
    anchor(A445_READBACK, A445_READBACK_SHA256)
    a375, a439, a442, _a444, runtime = A445.load_sources()
    a445 = A445.load_result(A445_RESULT_SHA256)
    if (
        a445.get("selected_operator") != "borda_sum_baseline"
        or a445.get("recovery_ready") is not False
        or a445.get("target_labels_used_for_W52") != 0
        or a445.get("W52_model_refits") != 0
        or a445.get("new_solver_stages") != 0
        or a445.get("candidate_assignments_executed") != 0
    ):
        raise RuntimeError("A446 A445 boundary semantics differ")
    return a375, a439, a442, a445, runtime


def freeze_implementation() -> dict[str, Any]:
    if any(path.exists() for path in (IMPLEMENTATION, RESULT, CAUSAL, REPORT)):
        raise FileExistsError("A446 implementation or result already exists")
    design = load_design()
    _a375, _a439, a442, a445, _runtime = load_sources()
    if not TEST.exists() or not PROVENANCE_TEST.exists() or not REPRO.exists():
        raise FileNotFoundError("A446 tests and reproducer must precede freeze")
    payload: dict[str, Any] = {
        "schema": "chacha20-round20-w52-assumption-cut-clause-provenance-reader-a446-implementation-v1",
        "attempt_id": ATTEMPT_ID,
        "commitment_state": "complete_assumption_cut_feature_extraction_crossfit_selection_W52_transfer_and_authentic_Causal_code_frozen_before_any_A446_feature_or_operator_evaluation",
        "design_sha256": DESIGN_SHA256,
        "operators": list(OPERATORS),
        "selection_key": design["calibration_contract"]["selection_key"],
        "source_A442_result_commitment_sha256": a442["result_commitment_sha256"],
        "source_A445_result_commitment_sha256": a445["result_commitment_sha256"],
        "A446_feature_or_operator_evaluation_available_at_freeze": False,
        "A446_W52_orders_available_at_freeze": False,
        "A426_A438_A440_A443_target_outcome_or_progress_read": False,
        "target_labels_used_for_W52": 0,
        "W52_model_refits": 0,
        "new_solver_stages": 0,
        "candidate_assignments_executed": 0,
        "anchors": {
            "design": anchor(DESIGN, DESIGN_SHA256),
            "provenance_source": anchor(PROVENANCE_SOURCE),
            "A359_result": anchor(A359_RESULT, A359_RESULT_SHA256),
            "A363_result": anchor(A363_RESULT, A363_RESULT_SHA256),
            "A367_result": anchor(A367_RESULT, A367_RESULT_SHA256),
            "A442_result": anchor(A442_RESULT, A442_RESULT_SHA256),
            "A445_runner": anchor(A445_RUNNER, A445_RUNNER_SHA256),
            "A445_result": anchor(A445_RESULT, A445_RESULT_SHA256),
            "A445_causal": anchor(A445_CAUSAL, A445_CAUSAL_SHA256),
            "A445_personal_readback": anchor(A445_READBACK, A445_READBACK_SHA256),
            "runner": anchor(Path(__file__)),
            "test": anchor(TEST),
            "provenance_test": anchor(PROVENANCE_TEST),
            "reproducer": anchor(REPRO),
        },
    }
    payload["implementation_commitment_sha256"] = canonical_sha256(payload)
    atomic_json(IMPLEMENTATION, payload)
    return payload


def load_implementation(expected_sha256: str) -> dict[str, Any]:
    if file_sha256(IMPLEMENTATION) != expected_sha256:
        raise RuntimeError("A446 implementation hash differs")
    value = json.loads(IMPLEMENTATION.read_bytes())
    if (
        value.get("schema") != "chacha20-round20-w52-assumption-cut-clause-provenance-reader-a446-implementation-v1"
        or value.get("attempt_id") != ATTEMPT_ID
        or tuple(value.get("operators", [])) != OPERATORS
        or value.get("A446_feature_or_operator_evaluation_available_at_freeze") is not False
        or value.get("A446_W52_orders_available_at_freeze") is not False
        or value.get("target_labels_used_for_W52") != 0
        or value.get("W52_model_refits") != 0
        or value.get("new_solver_stages") != 0
        or value.get("candidate_assignments_executed") != 0
    ):
        raise RuntimeError("A446 implementation semantics differ")
    for row in value["anchors"].values():
        anchor(path_from_ref(row["path"]), row["sha256"])
    unsigned = {key: item for key, item in value.items() if key != "implementation_commitment_sha256"}
    if value.get("implementation_commitment_sha256") != canonical_sha256(unsigned):
        raise RuntimeError("A446 implementation commitment differs")
    return value


def transfer_axis(
    *,
    axis_name: str,
    source: Mapping[str, Any],
    source_module: Any,
    a439: Mapping[str, Any],
    a442: Mapping[str, Any],
    selected: str,
    feature_order: np.ndarray,
    expected_feature_names: Sequence[str],
    a439_runtime: Any,
    a442_runtime: Any,
) -> dict[str, Any]:
    measurements = a439_runtime.load_axis_measurements(source, source_module, axis_name)
    within_orders: dict[int, list[int]] = {}
    feature_matrix_hashes: dict[str, str] = {}
    feature_rank_hashes: dict[str, str] = {}
    for low4 in SLICES:
        matrix, names = PROVENANCE.extract_assumption_cut_matrix(measurements[low4])
        if tuple(names) != tuple(expected_feature_names):
            raise RuntimeError(f"A446 {axis_name} feature ledger differs")
        normalized = PROVENANCE.target_normalize(matrix)
        ranks = PROVENANCE.exact_absolute_rank_fields(normalized)
        feature_matrix_hashes[str(low4)] = array_sha256(normalized, "<f8")
        feature_rank_hashes[str(low4)] = array_sha256(ranks, "<i2")
        baseline = A445._slice_borda_ranks(a439, axis_name, low4, a442_runtime)  # noqa: SLF001
        within_orders[low4] = operator_order(ranks, baseline, feature_order, selected).tolist()
    reference = np.asarray(a442[f"{axis_name}_order"], dtype=np.int64)
    order = (
        exact_order(reference, AXIS_CELLS)
        if selected == "borda_sum_baseline"
        else exact_order(a439_runtime.A376.A361.compose_round_robin(within_orders), AXIS_CELLS)
    )
    return {
        "order": order.tolist(),
        "order_uint16be_sha256": a442_runtime.order_sha256(order),
        "first_16_cells": order[:16].tolist(),
        "last_16_cells": order[-16:].tolist(),
        "exact_cells": AXIS_CELLS,
        "feature_matrix_sha256": feature_matrix_hashes,
        "feature_matrix_set_sha256": canonical_sha256(feature_matrix_hashes),
        "feature_rank_sha256": feature_rank_hashes,
        "feature_rank_set_sha256": canonical_sha256(feature_rank_hashes),
        "within_slice_orders_sha256": canonical_sha256(within_orders),
        "target_labels_used": 0,
        "W52_model_refits": 0,
        "new_solver_stages": 0,
        "candidate_assignments_executed": 0,
    }


def build_causal(payload: Mapping[str, Any]) -> dict[str, Any]:
    if str(DOTCAUSAL_SRC) not in sys.path:
        sys.path.insert(0, str(DOTCAUSAL_SRC))
    from dotcausal.io import CausalReader, CausalWriter

    ready = bool(payload["recovery_ready"])
    terminal = "A446:assumption_cut_W52_recovery_ready" if ready else "A446:assumption_cut_provenance_boundary"
    writer = CausalWriter(api_id="a446cut")
    writer._rules = []
    writer.add_rule(
        name="clause_identity_to_assumption_cut_hypergraph",
        description="Retain candidate-relative assumption provenance, typed overlap, complement, resolution and horizon edges without raw candidate values.",
        pattern=["A359_A363_A367_complete_clause_identity_corpus"],
        conclusion="A446_assumption_cut_provenance_rank_panel",
        confidence_modifier=1.0,
    )
    writer.add_rule(
        name="crossfit_hypergraph_to_frozen_operator",
        description="Cross-fit feature selection and thirteen fixed pure or hybrid rank operators over eight complete held blocks.",
        pattern=["A446_assumption_cut_provenance_rank_panel"],
        conclusion="A446_selected_full_provenance_operator",
        confidence_modifier=1.0,
    )
    writer.add_rule(
        name="frozen_operator_to_W52",
        description="Transfer the frozen operator to all 32 W52 clause measurements without labels, refits, solver stages or candidate execution.",
        pattern=["A446_selected_full_provenance_operator", "A439_complete_W52_clause_measurements"],
        conclusion="A446_complete_W52_pair_schedule",
        confidence_modifier=1.0,
    )
    writer.add_rule(
        name="retention_diversity_to_execution",
        description="Require held-block retention and complete pair-space diversity before opening a recovery executor.",
        pattern=["A446_complete_W52_pair_schedule"],
        conclusion=terminal.replace(":", "_"),
        confidence_modifier=1.0,
    )
    writer.add_triplet(
        trigger="A359_A363_A367:complete_clause_identity_corpus",
        mechanism="candidate_relative_assumption_cut_overlap_complement_resolution_and_horizon_hypergraph",
        outcome="A446:assumption_cut_provenance_rank_panel",
        confidence=1.0,
        source=payload["panel_sha256"],
        quantification=json.dumps(payload["feature_contract"], sort_keys=True),
        evidence=payload["measurement_cover_sha256"],
        domain="Known-key full-round ChaCha20 clause provenance",
        quality_score=1.0,
    )
    writer.add_triplet(
        trigger="A446:assumption_cut_provenance_rank_panel",
        mechanism="eight_fold_worst_block_first_pure_and_hybrid_rank_selection",
        outcome="A446:selected_full_provenance_operator",
        confidence=1.0,
        source=payload["selection_sha256"],
        quantification=payload["selected_operator"],
        evidence=payload["selected_full_model_sha256"],
        domain="cross-fitted provenance Reader selection",
        quality_score=1.0,
    )
    writer.add_triplet(
        trigger="A446:selected_full_provenance_operator",
        mechanism="complete_32_slice_target_blind_provenance_transfer",
        outcome="A446:complete_W52_pair_schedule",
        confidence=1.0,
        source=payload["pair_schedule_sha256"],
        quantification=json.dumps(payload["W52_transfer"], sort_keys=True),
        evidence=payload["pair_stream_uint16be_uint16be_sha256"],
        domain="target-blind full-round ChaCha20 W52 ordering",
        quality_score=1.0,
    )
    writer.add_triplet(
        trigger="A446:complete_W52_pair_schedule",
        mechanism="held_block_retention_plus_exact_pair_diversity_gate",
        outcome=terminal,
        confidence=1.0,
        source=payload["decision_sha256"],
        quantification=json.dumps(payload["decision"], sort_keys=True),
        evidence=str(ready),
        domain="W52 recovery trajectory decision",
        quality_score=1.0,
    )
    writer.add_triplet(
        trigger="A359_A363_A367:complete_clause_identity_corpus",
        mechanism="materialized_assumption_cut_transfer_decision_closure",
        outcome=terminal,
        confidence=1.0,
        source="materialized:A446_assumption_cut_chain",
        quantification="exact retained closure",
        evidence=payload["evidence_stage"],
        domain="AI-native retained inference",
        quality_score=1.0,
        is_inferred=True,
    )
    writer.add_cluster(
        name="A446 assumption-cut clause provenance",
        entities=[
            "A359_A363_A367:complete_clause_identity_corpus",
            "A446:assumption_cut_provenance_rank_panel",
            "A446:selected_full_provenance_operator",
            "A446:complete_W52_pair_schedule",
            terminal,
        ],
    )
    writer.add_gap(
        subject=terminal,
        predicate="next_required_object",
        expected_object_type="qualified_recovery_execution" if ready else "proof_producing_conflict_analysis_or_clause_antecedent_instrumentation",
        confidence=1.0,
        suggested_queries=[
            "Execute the qualified schedule after the existing recovery queue closes."
            if ready
            else "The assumption cut is exhausted at clause-output level; instrument conflict antecedents or proof-producing contradiction depth next."
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
        reader.api_id != "a446cut"
        or len(explicit) != 4
        or len(all_rows) != 5
        or len(inferred) != 1
        or len(reader._rules) != 4
        or len(reader._clusters) != 1
        or len(reader._gaps) != 1
    ):
        raise RuntimeError("A446 authentic Causal reopen gate failed")
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
            "panel": explicit[0],
            "selection": explicit[1],
            "W52_transfer": explicit[2],
            "decision": explicit[3],
            "terminal_chain": all_rows[-1],
            "next_gap": reader._gaps[0],
        },
    }


def _build_result_once(*, expected_implementation_sha256: str) -> dict[str, Any]:
    if any(path.exists() for path in (RESULT, CAUSAL, REPORT)):
        raise FileExistsError("A446 result already exists")
    design = load_design()
    implementation = load_implementation(expected_implementation_sha256)
    a375, a439, a442, a445, runtime = load_sources()
    measurements, truths, blocks, source_hashes = load_calibration_measurements()
    rank_fields, feature_names, matrix_hashes, rank_hashes = provenance_panel(measurements)
    matrices, baseline_truths, baseline_blocks, borda, _names, reconstructed_hashes = A445.reconstruct_calibration_panel(a375, runtime)
    del matrices
    if not np.array_equal(truths, baseline_truths) or blocks != baseline_blocks:
        raise RuntimeError("A446 calibration label alignment differs")
    if hashlib.sha256(borda.tobytes()).hexdigest() != A442_BORDA_FIELD_SHA256:
        raise RuntimeError("A446 Borda baseline differs")
    evaluations, selected, _fields = evaluate_operators(rank_fields, truths, borda, feature_names)
    full_feature_order, full_model = feature_selection(rank_fields, truths, list(range(TARGETS)))
    selected_full_model = {
        **full_model,
        "selected_operator": selected,
        "feature_names_sha256": canonical_sha256(feature_names),
        "complete_feature_order": full_feature_order.tolist(),
        "complete_feature_order_names": [str(feature_names[index]) for index in full_feature_order],
    }
    selected_full_model["model_sha256"] = canonical_sha256(selected_full_model)

    a439_runtime = load_module(A445.A439_RUNNER, "a446_a439_runtime")
    _source_a375, a432, a433, _a436 = a439_runtime.load_source_metadata()
    prefix = transfer_axis(
        axis_name="prefix",
        source=a433,
        source_module=a439_runtime.A433,
        a439=a439,
        a442=a442,
        selected=selected,
        feature_order=full_feature_order,
        expected_feature_names=feature_names,
        a439_runtime=a439_runtime,
        a442_runtime=runtime,
    )
    off_axis = transfer_axis(
        axis_name="off_axis",
        source=a432,
        source_module=a439_runtime.A432,
        a439=a439,
        a442=a442,
        selected=selected,
        feature_order=full_feature_order,
        expected_feature_names=feature_names,
        a439_runtime=a439_runtime,
        a442_runtime=runtime,
    )
    pair_stream_sha = runtime.pair_stream_sha256(prefix["order"], off_axis["order"])
    selected_pair_rank = runtime.reference_square_rank_vector(prefix["order"], off_axis["order"])
    comparisons: dict[str, Any] = {}
    references = {
        "A439": (a439["axes"]["prefix"]["portfolio_order"], a439["axes"]["off_axis"]["portfolio_order"]),
        "A442": (a442["prefix_order"], a442["off_axis_order"]),
        "A445": (a445["prefix_order"], a445["off_axis_order"]),
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
        "CROSSFIT_ASSUMPTION_CUT_PROVENANCE_READER_RETAINED_MATERIALLY_ORTHOGONAL_W52_RECOVERY_READY"
        if recovery_ready
        else "CROSSFIT_ASSUMPTION_CUT_PROVENANCE_EXACT_REPRESENTATION_BOUNDARY_RETAINED"
    )
    feature_contract = {
        "features": len(feature_names),
        "feature_names": list(feature_names),
        "feature_names_sha256": canonical_sha256(feature_names),
        "candidate_raw_value_features": 0,
        "horizons": list(PROVENANCE.HORIZONS),
        "typed_object": design["new_representation"]["object"],
    }
    panel_contract = {
        "targets": TARGETS,
        "cells_per_target": CELLS,
        "blocks": blocks,
        "source_result_sha256": source_hashes,
        "feature_contract": feature_contract,
        "normalized_matrix_sha256": matrix_hashes,
        "rank_field_sha256": rank_hashes,
        "reconstructed_A375_model_rank_field_sha256": reconstructed_hashes,
        "borda_baseline_sha256": A442_BORDA_FIELD_SHA256,
    }
    transfer = {
        "selected_operator": selected,
        "selected_full_model_sha256": selected_full_model["model_sha256"],
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
        "schema": "chacha20-round20-w52-assumption-cut-clause-provenance-reader-a446-v1",
        "attempt_id": ATTEMPT_ID,
        "evidence_stage": evidence_stage,
        "design_sha256": DESIGN_SHA256,
        "implementation_sha256": expected_implementation_sha256,
        "implementation_commitment_sha256": implementation["implementation_commitment_sha256"],
        "feature_contract": feature_contract,
        "panel_contract": panel_contract,
        "operator_evaluations": evaluations,
        "operator_summary": operator_summary,
        "selected_operator": selected,
        "selected_evaluation": selected_evaluation,
        "selected_full_model": selected_full_model,
        "selected_full_model_sha256": selected_full_model["model_sha256"],
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
            "provenance_source": anchor(PROVENANCE_SOURCE),
            "A359_result": anchor(A359_RESULT, A359_RESULT_SHA256),
            "A363_result": anchor(A363_RESULT, A363_RESULT_SHA256),
            "A367_result": anchor(A367_RESULT, A367_RESULT_SHA256),
            "A442_result": anchor(A442_RESULT, A442_RESULT_SHA256),
            "A445_runner": anchor(A445_RUNNER, A445_RUNNER_SHA256),
            "A445_result": anchor(A445_RESULT, A445_RESULT_SHA256),
            "A445_causal": anchor(A445_CAUSAL, A445_CAUSAL_SHA256),
            "A445_personal_readback": anchor(A445_READBACK, A445_READBACK_SHA256),
            "runner": anchor(Path(__file__)),
            "test": anchor(TEST),
            "provenance_test": anchor(PROVENANCE_TEST),
            "reproducer": anchor(REPRO),
        },
    }
    core["measurement_cover_sha256"] = canonical_sha256(
        [row.get("raw_sha256") for path in (A359_RESULT, A363_RESULT, A367_RESULT) for row in json.loads(path.read_bytes())["measurement_ledger"]]
    )
    core["panel_sha256"] = canonical_sha256(panel_contract)
    core["selection_sha256"] = canonical_sha256(
        {
            "selected_operator": selected,
            "selected_evaluation": selected_evaluation,
            "selected_full_model_sha256": selected_full_model["model_sha256"],
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
            "panel_sha256": core["panel_sha256"],
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
        "# A446 — Assumption-cut clause-provenance Reader transfer to W52\n\n"
        f"Evidence stage: **{evidence_stage}**\n\n"
        f"- Typed provenance features: **{len(feature_names)}**\n"
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
        raise FileExistsError("A446 result already exists")
    try:
        return _build_result_once(expected_implementation_sha256=expected_implementation_sha256)
    except BaseException:
        RESULT.unlink(missing_ok=True)
        CAUSAL.unlink(missing_ok=True)
        REPORT.unlink(missing_ok=True)
        raise


def load_result(expected_sha256: str) -> dict[str, Any]:
    if file_sha256(RESULT) != expected_sha256:
        raise RuntimeError("A446 result hash differs")
    value = json.loads(RESULT.read_bytes())
    if (
        value.get("schema") != "chacha20-round20-w52-assumption-cut-clause-provenance-reader-a446-v1"
        or value.get("attempt_id") != ATTEMPT_ID
        or value.get("selected_operator") not in OPERATORS
        or value.get("target_labels_used_for_W52") != 0
        or value.get("W52_model_refits") != 0
        or value.get("new_solver_stages") != 0
        or value.get("candidate_assignments_executed") != 0
    ):
        raise RuntimeError("A446 result semantics differ")
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

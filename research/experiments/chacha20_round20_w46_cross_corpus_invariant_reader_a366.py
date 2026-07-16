#!/usr/bin/env python3
"""A366: freeze a cross-corpus invariant W46 Reader portfolio."""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import inspect
import itertools
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

DESIGN = CONFIGS / "chacha20_round20_w46_cross_corpus_invariant_reader_a366_design_v1.json"
IMPLEMENTATION = (
    CONFIGS / "chacha20_round20_w46_cross_corpus_invariant_reader_a366_implementation_v1.json"
)
RESULT = RESULTS / "chacha20_round20_w46_cross_corpus_invariant_reader_a366_v1.json"
CAUSAL = RESULT.with_suffix(".causal")
REPORT = RESULT.with_suffix(".md")
TEST = ROOT / "tests/test_chacha20_round20_w46_cross_corpus_invariant_reader_a366.py"
REPRO = ROOT / "scripts/reproduce_chacha20_round20_w46_cross_corpus_invariant_reader_a366.sh"

A362_RUNNER = RESEARCH / "experiments/chacha20_round20_w46_polarity_invariant_reader_a362.py"
A363_RUNNER = (
    RESEARCH / "experiments/chacha20_round20_w46_polarity_invariant_validation_a363.py"
)
A359_RESULT = RESULTS / "chacha20_round20_w46_corrected_knownkey_slice_corpus_a359_v1.json"
A363_RESULT = RESULTS / "chacha20_round20_w46_polarity_invariant_validation_a363_v1.json"

ATTEMPT_ID = "A366"
DESIGN_SHA256 = "f21e2488dcad6062d32dc7cc23116bc94dbcbed067406459195078ed951df989"
A359_RESULT_SHA256 = "3259526ee94241f5e4858b59cb52cb93a9ef8dbe8dc8bf40deaf4d7757db7a3f"
A363_RESULT_SHA256 = "d2601ca3190a18fe2ce13bf436d14fafd4d9a2493df13dc68d353e500d7cb09b"
A362_RUNNER_SHA256 = "171e44f83c35d53217fd52c0bee11a2df5e8c22080ac8e00a8bd9c1dd5a25b92"
A363_RUNNER_SHA256 = "8ee599e444715170b7f2b55645812e5129d990856408bf81129b0bb9da87b538"

TARGETS = 64
BLOCKS = 4
BLOCK_SIZE = 16
CELLS = 256
FEATURES = 532
MEMBER_COUNTS = (2, 3, 4)
AGGREGATORS = ("borda", "linf_intersection", "min_rank_wavefront")
MAX_DIVERSE_CORRELATION = 0.35
DOTCAUSAL_SRC = Path("/Users/bhkmie/Documents/Forschung/O1/vendor/fabel/dotcausal_package/src")


def load_module(path: Path, name: str) -> Any:
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot import A366 dependency {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


A362 = load_module(A362_RUNNER, "a366_a362")
A363 = load_module(A363_RUNNER, "a366_a363")
A360 = A362.A360
A275 = A362.A275

file_sha256 = A360.file_sha256
canonical_sha256 = A360.canonical_sha256
atomic_json = A360.atomic_json
atomic_bytes = A360.atomic_bytes
relative = A360.relative
path_from_ref = A360.path_from_ref
anchor = A360.anchor


def _uniform_mean_log2_rank() -> float:
    return sum(math.log2(rank) for rank in range(1, CELLS + 1)) / CELLS


def load_design() -> dict[str, Any]:
    if file_sha256(DESIGN) != DESIGN_SHA256:
        raise RuntimeError("A366 design hash differs")
    value = json.loads(DESIGN.read_bytes())
    calibration = value.get("calibration_contract", {})
    prospective = value.get("prospective_A367_contract", {})
    boundary = value.get("information_boundary", {})
    if (
        value.get("schema")
        != "chacha20-round20-w46-cross-corpus-invariant-reader-a366-design-v1"
        or value.get("attempt_id") != ATTEMPT_ID
        or value.get("design_state")
        != "frozen_after_A363_complete_calibration_before_any_A367_validation_artifact"
        or calibration.get("targets") != TARGETS
        or calibration.get("fixed_blocks") != BLOCKS
        or calibration.get("targets_per_block") != BLOCK_SIZE
        or calibration.get("cells_per_target") != CELLS
        or calibration.get("feature_universe") != FEATURES
        or tuple(calibration.get("ensemble_member_counts", [])) != MEMBER_COUNTS
        or tuple(calibration.get("ensemble_aggregators", [])) != AGGREGATORS
        or prospective.get("new_targets") != TARGETS
        or prospective.get("fixed_validation_blocks") != BLOCKS
        or prospective.get("targets_per_block") != BLOCK_SIZE
        or prospective.get("reader_refits") != 0
        or boundary.get("A366_is_claimed_prospective_on_A359_or_A363") is not False
        or boundary.get("A367_target_artifacts_available_at_design_freeze") != 0
        or boundary.get("A367_solver_measurements_available_at_design_freeze") != 0
        or boundary.get("A367_assignments_or_labels_available_at_design_freeze") is not False
        or boundary.get("A361_measurement_shard_content_opened_by_A366") is not False
        or boundary.get("A361_secret_or_true_prefix_available_to_A366") is not False
    ):
        raise RuntimeError("A366 frozen design semantics differ")
    for name, path_value in value["source_anchors"].items():
        if name.endswith("_path"):
            stem = name.removesuffix("_path")
            anchor(ROOT / path_value, value["source_anchors"][f"{stem}_sha256"])
    return value


def freeze_implementation() -> dict[str, Any]:
    if IMPLEMENTATION.exists():
        raise FileExistsError("A366 implementation already exists")
    if any(path.exists() for path in (RESULT, CAUSAL, REPORT)):
        raise RuntimeError("A366 implementation must precede formal selection")
    load_design()
    if not TEST.exists() or not REPRO.exists():
        raise FileNotFoundError("A366 test and reproducer must exist before freeze")
    validation_artifacts = sorted(
        str(path.relative_to(ROOT))
        for path in ROOT.glob("research/**/*a367*")
        if path.is_file()
    )
    if validation_artifacts:
        raise RuntimeError("A366 implementation must precede every A367 artifact")
    payload: dict[str, Any] = {
        "schema": "chacha20-round20-w46-cross-corpus-invariant-reader-a366-implementation-v1",
        "attempt_id": ATTEMPT_ID,
        "commitment_state": "frozen_before_formal_A366_selection_and_every_A367_artifact",
        "design_sha256": DESIGN_SHA256,
        "A367_artifacts_available_at_freeze": [],
        "A361_measurement_shard_content_opened_by_A366": False,
        "anchors": {
            "design": anchor(DESIGN, DESIGN_SHA256),
            "A359_result": anchor(A359_RESULT, A359_RESULT_SHA256),
            "A363_result": anchor(A363_RESULT, A363_RESULT_SHA256),
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
        raise RuntimeError("A366 implementation artifact hash differs")
    value = json.loads(IMPLEMENTATION.read_bytes())
    if (
        value.get("schema")
        != "chacha20-round20-w46-cross-corpus-invariant-reader-a366-implementation-v1"
        or value.get("attempt_id") != ATTEMPT_ID
        or value.get("commitment_state")
        != "frozen_before_formal_A366_selection_and_every_A367_artifact"
        or value.get("design_sha256") != DESIGN_SHA256
        or value.get("A367_artifacts_available_at_freeze") != []
        or value.get("A361_measurement_shard_content_opened_by_A366") is not False
    ):
        raise RuntimeError("A366 frozen implementation semantics differ")
    for name, path in {
        "design": DESIGN,
        "A359_result": A359_RESULT,
        "A363_result": A363_RESULT,
        "runner": Path(__file__),
        "test": TEST,
        "reproducer": REPRO,
    }.items():
        row = value["anchors"][name]
        if row["path"] != relative(path) or row["sha256"] != file_sha256(path):
            raise RuntimeError(f"A366 implementation anchor differs: {name}")
    unsigned = {
        key: item for key, item in value.items() if key != "implementation_commitment_sha256"
    }
    if value["implementation_commitment_sha256"] != canonical_sha256(unsigned):
        raise RuntimeError("A366 implementation commitment differs")
    return value


def _load_calibration_panel() -> tuple[np.ndarray, np.ndarray, list[str]]:
    anchor(A359_RESULT, A359_RESULT_SHA256)
    anchor(A363_RESULT, A363_RESULT_SHA256)
    old_matrices, old_truths, _ = A362._load_calibration_panel()  # noqa: SLF001
    a363_result = json.loads(A363_RESULT.read_bytes())
    a363_prepared = json.loads(A363.PREPARED.read_bytes())
    if (
        a363_result.get("attempt_id") != "A363"
        or a363_result.get("prepared_sha256") != file_sha256(A363.PREPARED)
        or len(a363_result.get("measurement_ledger", [])) != 32
        or len(a363_prepared.get("rows", [])) != 32
    ):
        raise RuntimeError("A366 A363 calibration anchor differs")
    new_matrices: list[np.ndarray] = []
    new_truths: list[int] = []
    for source, ledger in zip(
        a363_prepared["rows"], a363_result["measurement_ledger"], strict=True
    ):
        measurement = A363._read_measurement(  # noqa: SLF001
            path_from_ref(ledger["path"]),
            expected_prepared_sha256=a363_result["prepared_sha256"],
            ledger=ledger,
        )
        new_matrices.append(A360.target_normalize(A275._target_feature_matrix(measurement)))  # noqa: SLF001
        new_truths.append(int(source["true_high8"]))
    matrices = np.stack([*old_matrices, *new_matrices])
    truths = np.asarray([*old_truths, *new_truths], dtype=np.int16)
    block_labels = [
        "A359_selection",
        "A359_holdout",
        "A363_validation_a",
        "A363_validation_b",
    ]
    if (
        matrices.shape != (TARGETS, CELLS, FEATURES)
        or truths.shape != (TARGETS,)
        or not np.isfinite(matrices).all()
        or np.any(truths < 0)
        or np.any(truths >= CELLS)
    ):
        raise RuntimeError("A366 calibration panel geometry differs")
    return matrices, truths, block_labels


def _exact_abs_rank_fields(matrices: np.ndarray) -> np.ndarray:
    values = np.asarray(matrices, dtype=np.float64)
    if values.shape != (TARGETS, CELLS, FEATURES):
        raise ValueError("A366 feature-panel geometry differs")
    cells = np.arange(CELLS, dtype=np.int16)
    result = np.empty((TARGETS, FEATURES, CELLS), dtype=np.int16)
    exact_ranks = np.arange(1, CELLS + 1, dtype=np.int16)
    for target in range(TARGETS):
        for feature in range(FEATURES):
            order = np.lexsort((cells, -np.abs(values[target, :, feature])))
            result[target, feature, order] = exact_ranks
    return result


def _statistics(rank_fields: np.ndarray, truths: np.ndarray) -> dict[str, Any]:
    fields = np.asarray(rank_fields, dtype=np.int16)
    labels = np.asarray(truths, dtype=np.int16)
    if fields.shape != (TARGETS, CELLS) or labels.shape != (TARGETS,):
        raise ValueError("A366 candidate evaluation geometry differs")
    true_ranks = fields[np.arange(TARGETS), labels].astype(np.int64)
    logs = np.log2(true_ranks.astype(np.float64))
    uniform = _uniform_mean_log2_rank()
    block_gains = [
        float(uniform - logs[start : start + BLOCK_SIZE].mean())
        for start in range(0, TARGETS, BLOCK_SIZE)
    ]
    return {
        "truth_ranks": true_ranks.tolist(),
        "fixed_block_bit_gains": block_gains,
        "stable_min_block_bit_gain": min(block_gains),
        "all64_bit_gain": float(uniform - logs.mean()),
        "targets_at_or_above_median_rank": int(np.count_nonzero(true_ranks <= 128)),
        "worst_rank": int(true_ranks.max()),
    }


def _stable_gain_by_shared_xor(rank_fields: np.ndarray, truths: np.ndarray) -> np.ndarray:
    fields = np.asarray(rank_fields, dtype=np.int16)
    labels = np.asarray(truths, dtype=np.int16)
    offsets = np.arange(CELLS, dtype=np.int16)
    mean_logs = np.zeros((BLOCKS, CELLS), dtype=np.float64)
    for target in range(TARGETS):
        block = target // BLOCK_SIZE
        shifted = np.bitwise_xor(offsets, labels[target])
        mean_logs[block] += np.log2(fields[target, shifted].astype(np.float64))
    mean_logs /= BLOCK_SIZE
    return np.min(_uniform_mean_log2_rank() - mean_logs, axis=0)


def _primitive_pool(
    all_fields: np.ndarray, truths: np.ndarray
) -> tuple[np.ndarray, list[dict[str, Any]], list[dict[str, Any]]]:
    names = tuple(A275.FEATURE_NAMES)
    if len(names) != FEATURES or len(set(names)) != FEATURES:
        raise RuntimeError("A366 feature ledger differs")
    admitted: list[dict[str, Any]] = []
    unique_rows: list[dict[str, Any]] = []
    unique_fields: list[np.ndarray] = []
    seen: dict[str, int] = {}
    for feature_index in range(FEATURES):
        field = all_fields[:, feature_index, :]
        stats = _statistics(field, truths)
        if stats["stable_min_block_bit_gain"] <= 0.0:
            continue
        digest = hashlib.sha256(field.tobytes()).hexdigest()
        row = {
            "feature_index": feature_index,
            "feature_name": names[feature_index],
            "rank_field_sha256": digest,
            **{key: value for key, value in stats.items() if key != "truth_ranks"},
        }
        admitted.append(row)
        if digest in seen:
            row["duplicate_of_feature_index"] = seen[digest]
            continue
        seen[digest] = feature_index
        row["primitive_index"] = len(unique_rows)
        unique_rows.append(row)
        unique_fields.append(field.copy())
    if not unique_fields:
        raise RuntimeError("A366 invariant primitive pool is empty")
    return np.stack(unique_fields, axis=1), admitted, unique_rows


def reader_definitions(unique_rows: Sequence[Mapping[str, Any]]) -> list[dict[str, Any]]:
    feature_indices = [int(row["feature_index"]) for row in unique_rows]
    definitions: list[dict[str, Any]] = [
        {
            "name": f"abs_primitive::{feature_index:03d}::{A275.FEATURE_NAMES[feature_index]}",
            "kind": "abs_primitive",
            "members": [primitive_index],
            "member_feature_indices": [feature_index],
        }
        for primitive_index, feature_index in enumerate(feature_indices)
    ]
    for count in MEMBER_COUNTS:
        for members in itertools.combinations(range(len(feature_indices)), count):
            selected_features = [feature_indices[index] for index in members]
            label = "-".join(f"{index:03d}" for index in selected_features)
            for aggregator in AGGREGATORS:
                definitions.append(
                    {
                        "name": f"ensemble::{aggregator}::{label}",
                        "kind": "ensemble",
                        "aggregator": aggregator,
                        "members": list(members),
                        "member_feature_indices": selected_features,
                    }
                )
    if len({definition["name"] for definition in definitions}) != len(definitions):
        raise RuntimeError("A366 candidate definitions are not unique")
    return definitions


def candidate_rank_field(
    primitive_fields: np.ndarray, definition: Mapping[str, Any]
) -> np.ndarray:
    primitives = np.asarray(primitive_fields, dtype=np.int16)
    if primitives.ndim != 3 or primitives.shape[0] != TARGETS or primitives.shape[2] != CELLS:
        raise ValueError("A366 primitive-panel geometry differs")
    members = tuple(int(value) for value in definition["members"])
    if not members or any(not 0 <= value < primitives.shape[1] for value in members):
        raise ValueError("A366 candidate members differ")
    if definition["kind"] == "abs_primitive":
        if len(members) != 1:
            raise RuntimeError("A366 primitive arity differs")
        return primitives[:, members[0], :].copy()
    selected = primitives[:, np.asarray(members, dtype=np.int64), :].astype(np.int32)
    result = np.empty((TARGETS, CELLS), dtype=np.int16)
    cells = np.arange(CELLS, dtype=np.int16)
    exact_ranks = np.arange(1, CELLS + 1, dtype=np.int16)
    aggregator = str(definition["aggregator"])
    for target in range(TARGETS):
        values = selected[target]
        total = values.sum(axis=0)
        components = tuple(values[index] for index in range(len(members) - 1, -1, -1))
        if aggregator == "borda":
            keys = (cells, *components, total)
        elif aggregator == "linf_intersection":
            keys = (cells, *components, total, values.max(axis=0))
        elif aggregator == "min_rank_wavefront":
            keys = (cells, *components, total, values.min(axis=0))
        else:
            raise ValueError(f"A366 unknown aggregator {aggregator}")
        order = np.lexsort(keys)
        result[target, order] = exact_ranks
    return result


def _selection_key(row: Mapping[str, Any]) -> tuple[Any, ...]:
    return (
        -float(row["stable_min_block_bit_gain"]),
        -float(row["all64_bit_gain"]),
        -int(row["targets_at_or_above_median_rank"]),
        int(row["worst_rank"]),
        str(row["name"]),
    )


def _coverage_key(row: Mapping[str, Any]) -> tuple[Any, ...]:
    return (
        -int(row["targets_at_or_above_median_rank"]),
        -float(row["stable_min_block_bit_gain"]),
        -float(row["all64_bit_gain"]),
        int(row["worst_rank"]),
        str(row["name"]),
    )


def _field_correlation(left: np.ndarray, right: np.ndarray) -> float:
    value = float(np.corrcoef(left.astype(np.float64).ravel(), right.astype(np.float64).ravel())[0, 1])
    if not math.isfinite(value):
        raise RuntimeError("A366 rank-field correlation is non-finite")
    return value


def select_reader() -> dict[str, Any]:
    matrices, truths, block_labels = _load_calibration_panel()
    all_fields = _exact_abs_rank_fields(matrices)
    primitive_fields, admitted, unique_rows = _primitive_pool(all_fields, truths)
    definitions = reader_definitions(unique_rows)
    family_best = np.full(CELLS, -np.inf, dtype=np.float64)
    ledger: list[dict[str, Any]] = []
    primary_index = -1
    best_single_index = -1
    primary_field: np.ndarray | None = None
    best_single_field: np.ndarray | None = None
    for index, definition in enumerate(definitions):
        field = candidate_rank_field(primitive_fields, definition)
        stats = _statistics(field, truths)
        shifted = _stable_gain_by_shared_xor(field, truths)
        family_best = np.maximum(family_best, shifted)
        row = {
            "index": index,
            "name": definition["name"],
            **{key: value for key, value in stats.items() if key != "truth_ranks"},
        }
        ledger.append(row)
        if primary_index < 0 or _selection_key(row) < _selection_key(ledger[primary_index]):
            primary_index = index
            primary_field = field.copy()
        if definition["kind"] == "abs_primitive" and (
            best_single_index < 0
            or _selection_key(row) < _selection_key(ledger[best_single_index])
        ):
            best_single_index = index
            best_single_field = field.copy()
    if primary_field is None or best_single_field is None:
        raise RuntimeError("A366 primary selection failed")
    diverse_index = -1
    coverage_index = -1
    diverse_field: np.ndarray | None = None
    coverage_field: np.ndarray | None = None
    correlation_ledger: list[dict[str, Any]] = []
    for index, definition in enumerate(definitions):
        if index == primary_index:
            continue
        row = ledger[index]
        if float(row["stable_min_block_bit_gain"]) <= 0.0:
            continue
        field = candidate_rank_field(primitive_fields, definition)
        correlation = _field_correlation(primary_field, field)
        if abs(correlation) > MAX_DIVERSE_CORRELATION:
            continue
        correlation_ledger.append(
            {"index": index, "name": row["name"], "correlation_to_primary": correlation}
        )
        if diverse_index < 0 or _selection_key(row) < _selection_key(ledger[diverse_index]):
            diverse_index = index
            diverse_field = field.copy()
        if coverage_index < 0 or _coverage_key(row) < _coverage_key(ledger[coverage_index]):
            coverage_index = index
            coverage_field = field.copy()
    if diverse_field is None or coverage_field is None:
        raise RuntimeError("A366 companion selection failed")

    selected_rows: dict[str, dict[str, Any]] = {}
    selected_sources = {
        "primary": (primary_index, primary_field),
        "diverse_companion": (diverse_index, diverse_field),
        "coverage_companion": (coverage_index, coverage_field),
        "best_single": (best_single_index, best_single_field),
    }
    for role, (index, field) in selected_sources.items():
        stats = _statistics(field, truths)
        shifted = _stable_gain_by_shared_xor(field, truths)
        observed = float(stats["stable_min_block_bit_gain"])
        selected_rows[role] = {
            "definition": definitions[index],
            **stats,
            "rank_field_sha256": hashlib.sha256(field.tobytes()).hexdigest(),
            "correlation_to_primary": 1.0 if role == "primary" else _field_correlation(primary_field, field),
            "fixed_exact_shared_xor_p": float(
                np.count_nonzero(shifted >= observed - 1e-15) / CELLS
            ),
            "calibration_familywise_exact_shared_xor_p": float(
                np.count_nonzero(family_best >= observed - 1e-15) / CELLS
            ),
        }
    selection_commitment = canonical_sha256(
        {
            "A359_result_sha256": A359_RESULT_SHA256,
            "A363_result_sha256": A363_RESULT_SHA256,
            "admitted_primitives": admitted,
            "unique_primitives": unique_rows,
            "definition_ledger_sha256": canonical_sha256(definitions),
            "candidate_ledger_sha256": canonical_sha256(ledger),
            "selected_readers": selected_rows,
        }
    )
    return {
        "calibration_targets": TARGETS,
        "block_labels": block_labels,
        "uniform_mean_log2_rank_reference": _uniform_mean_log2_rank(),
        "admitted_primitive_count_before_deduplication": len(admitted),
        "unique_primitive_count": len(unique_rows),
        "admitted_primitives": admitted,
        "unique_primitives": unique_rows,
        "candidate_count": len(definitions),
        "definition_ledger_sha256": canonical_sha256(definitions),
        "candidate_ledger_sha256": canonical_sha256(ledger),
        "candidate_ledger": ledger,
        "familywise_best_stable_gain_by_shared_xor_offset": family_best.tolist(),
        "diverse_candidate_count": len(correlation_ledger),
        "diverse_correlation_ledger_sha256": canonical_sha256(correlation_ledger),
        "selected_readers": selected_rows,
        "selection_commitment_sha256": selection_commitment,
    }


def build_causal(payload: Mapping[str, Any]) -> dict[str, Any]:
    sys.path.insert(0, str(DOTCAUSAL_SRC))
    from dotcausal.io import CausalReader, CausalWriter

    boundary = "A363:prospective_reader_gate_boundary"
    pool = "A366:four_block_invariant_feature_pool"
    portfolio = "A366:frozen_cross_corpus_reader_portfolio"
    validation = "A367:new_64_target_familywise_validation"
    writer = CausalWriter(api_id="a366xcc")
    writer._rules = []
    writer.add_rule(
        name="boundary_to_cross_corpus_pool",
        description="The A363 orientation boundary expands calibration to all 532 target-local absolute feature fields across four fixed blocks.",
        pattern=[boundary],
        conclusion=pool,
        confidence_modifier=1.0,
    )
    writer.add_rule(
        name="pool_to_frozen_portfolio",
        description="Strict four-block positivity, exact deduplication and frozen robust/diverse selection produce four immutable Readers.",
        pattern=[pool],
        conclusion=portfolio,
        confidence_modifier=1.0,
    )
    writer.add_rule(
        name="portfolio_to_new_validation",
        description="Only a new 64-target corpus may authorize sealed A361 deployment.",
        pattern=[portfolio],
        conclusion=validation,
        confidence_modifier=1.0,
    )
    writer.add_triplet(
        trigger=boundary,
        mechanism="expand_from_A362_16_feature_family_to_complete_532_feature_absolute_rank_atlas",
        outcome=pool,
        confidence=1.0,
        source=A363_RESULT_SHA256,
        quantification=json.dumps(payload["pool_summary"], sort_keys=True),
        evidence="A359 plus prospectively measured A363 complete target-local fields",
        domain="ChaCha20 R20 W46 cross-corpus Reader calibration",
        quality_score=1.0,
    )
    writer.add_triplet(
        trigger=pool,
        mechanism="four_fixed_block_minimax_selection_plus_rank_field_diversity",
        outcome=portfolio,
        confidence=1.0,
        source=payload["reader_selection"]["selection_commitment_sha256"],
        quantification=json.dumps(payload["selection_summary"], sort_keys=True),
        evidence="complete deduplicated candidate family",
        domain="Frozen invariant Reader portfolio",
        quality_score=1.0,
    )
    writer.add_triplet(
        trigger=portfolio,
        mechanism="immutable_zero_refit_four_model_familywise_shared_xor_gate",
        outcome=validation,
        confidence=1.0,
        source=payload["reader_selection"]["selection_commitment_sha256"],
        quantification=json.dumps(payload["future_validation_gate"], sort_keys=True),
        evidence="A367 absent at A366 implementation freeze",
        domain="Prospective disjoint validation",
        quality_score=1.0,
    )
    writer.add_triplet(
        trigger=boundary,
        mechanism="materialized_boundary_pool_portfolio_validation_chain",
        outcome=validation,
        confidence=1.0,
        source="materialized:A366_cross_corpus_chain",
        quantification="exact retained closure",
        evidence=payload["evidence_stage"],
        domain="AI-native retained inference",
        quality_score=1.0,
        is_inferred=True,
    )
    writer.add_cluster(
        name="A366 cross-corpus invariant Reader",
        entities=[boundary, pool, portfolio, validation],
    )
    writer.add_gap(
        subject=validation,
        predicate="next_required_object",
        expected_object_type="new_balanced_64_target_zero_refit_familywise_validation",
        confidence=1.0,
        suggested_queries=[
            "Generate A367 only after this portfolio is frozen; open sealed A361 only for Readers passing the predeclared familywise gate."
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
        reader.api_id != "a366xcc"
        or len(explicit) != 3
        or len(all_rows) != 4
        or len(inferred) != 1
        or len(reader._rules) != 3
        or len(reader._clusters) != 1
        or len(reader._gaps) != 1
    ):
        raise RuntimeError("A366 authentic Causal reopen gate failed")
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
            "first_relation": explicit[0],
            "terminal_relation": explicit[-1],
            "materialized_chain": all_rows[-1],
            "next_gap": reader._gaps[0],
        },
    }


def run_selection(*, expected_implementation_sha256: str) -> dict[str, Any]:
    if any(path.exists() for path in (RESULT, CAUSAL, REPORT)):
        raise FileExistsError("A366 formal selection already exists")
    design = load_design()
    load_implementation(expected_implementation_sha256)
    selection = select_reader()
    selected = selection["selected_readers"]
    selection_summary = {
        role: {
            "name": row["definition"]["name"],
            "member_feature_indices": row["definition"]["member_feature_indices"],
            "fixed_block_bit_gains": row["fixed_block_bit_gains"],
            "stable_min_block_bit_gain": row["stable_min_block_bit_gain"],
            "all64_bit_gain": row["all64_bit_gain"],
            "targets_at_or_above_median_rank": row["targets_at_or_above_median_rank"],
            "worst_rank": row["worst_rank"],
            "correlation_to_primary": row["correlation_to_primary"],
            "fixed_exact_shared_xor_p": row["fixed_exact_shared_xor_p"],
            "calibration_familywise_exact_shared_xor_p": row[
                "calibration_familywise_exact_shared_xor_p"
            ],
        }
        for role, row in selected.items()
    }
    pool_summary = {
        "feature_universe": FEATURES,
        "admitted_before_deduplication": selection[
            "admitted_primitive_count_before_deduplication"
        ],
        "unique_admitted_primitives": selection["unique_primitive_count"],
        "candidate_readers": selection["candidate_count"],
        "fixed_calibration_blocks": BLOCKS,
        "targets": TARGETS,
    }
    payload: dict[str, Any] = {
        "schema": "chacha20-round20-w46-cross-corpus-invariant-reader-a366-v1",
        "attempt_id": ATTEMPT_ID,
        "evidence_stage": "CROSS_CORPUS_CALIBRATED_READER_PORTFOLIO_FROZEN_BEFORE_A367",
        "design_sha256": DESIGN_SHA256,
        "implementation_sha256": expected_implementation_sha256,
        "pool_summary": pool_summary,
        "selection_summary": selection_summary,
        "reader_selection": selection,
        "future_validation_gate": design["prospective_A367_contract"],
        "information_boundary": design["information_boundary"],
        "anchors": {
            "design": anchor(DESIGN, DESIGN_SHA256),
            "implementation": anchor(IMPLEMENTATION, expected_implementation_sha256),
            "A359_result": anchor(A359_RESULT, A359_RESULT_SHA256),
            "A363_result": anchor(A363_RESULT, A363_RESULT_SHA256),
            "runner": anchor(Path(__file__)),
            "test": anchor(TEST),
            "reproducer": anchor(REPRO),
        },
    }
    payload["result_sha256"] = canonical_sha256(
        {
            "evidence_stage": payload["evidence_stage"],
            "design_sha256": DESIGN_SHA256,
            "implementation_sha256": expected_implementation_sha256,
            "pool_summary": pool_summary,
            "selection_commitment_sha256": selection["selection_commitment_sha256"],
            "selection_summary": selection_summary,
            "future_validation_gate": payload["future_validation_gate"],
            "information_boundary": payload["information_boundary"],
        }
    )
    payload["causal"] = build_causal(payload)
    atomic_json(RESULT, payload)
    atomic_bytes(
        REPORT,
        (
            "# A366 — cross-corpus invariant W46 Reader\n\n"
            f"Evidence stage: **{payload['evidence_stage']}**\n\n"
            f"- Complete calibration targets: **{TARGETS}**\n"
            f"- Admitted / unique primitives: **{pool_summary['admitted_before_deduplication']} / {pool_summary['unique_admitted_primitives']}**\n"
            f"- Exhaustive candidate Readers: **{pool_summary['candidate_readers']:,}**\n"
            f"- Primary: **{selection_summary['primary']['name']}**\n"
            f"- Primary four-block gains: **{selection_summary['primary']['fixed_block_bit_gains']}**\n"
            f"- Primary median hits: **{selection_summary['primary']['targets_at_or_above_median_rank']} / {TARGETS}**\n"
            "- A367 validation targets available at freeze: **0**\n"
            "- A361 measurement shards opened: **0**\n"
            "- Authentic AI-native Causal readback: **3 explicit + 1 inferred**\n"
        ).encode(),
    )
    return payload


def analyze() -> dict[str, Any]:
    return {
        "attempt_id": ATTEMPT_ID,
        "design_sha256": DESIGN_SHA256,
        "implementation_frozen": IMPLEMENTATION.exists(),
        "implementation_sha256": file_sha256(IMPLEMENTATION) if IMPLEMENTATION.exists() else None,
        "result_complete": RESULT.exists(),
        "result_sha256": file_sha256(RESULT) if RESULT.exists() else None,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    action = parser.add_mutually_exclusive_group(required=True)
    action.add_argument("--analyze", action="store_true")
    action.add_argument("--freeze-implementation", action="store_true")
    action.add_argument("--select", action="store_true")
    parser.add_argument("--expected-implementation-sha256")
    args = parser.parse_args()
    if args.freeze_implementation:
        payload = freeze_implementation()
    elif args.select:
        if not args.expected_implementation_sha256:
            parser.error("--select requires --expected-implementation-sha256")
        payload = run_selection(
            expected_implementation_sha256=args.expected_implementation_sha256
        )
        payload = {
            "attempt_id": payload["attempt_id"],
            "evidence_stage": payload["evidence_stage"],
            "pool_summary": payload["pool_summary"],
            "selection_summary": payload["selection_summary"],
            "result_sha256": payload["result_sha256"],
            "causal": payload["causal"],
        }
    else:
        payload = analyze()
    print(json.dumps(payload, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()

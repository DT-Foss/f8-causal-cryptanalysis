#!/usr/bin/env python3
"""A362: freeze a polarity-invariant W46 within-slice Reader."""

from __future__ import annotations

import argparse
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

DESIGN = CONFIGS / "chacha20_round20_w46_polarity_invariant_reader_a362_design_v1.json"
IMPLEMENTATION = (
    CONFIGS / "chacha20_round20_w46_polarity_invariant_reader_a362_implementation_v1.json"
)
RESULT = RESULTS / "chacha20_round20_w46_polarity_invariant_reader_a362_v1.json"
CAUSAL = RESULT.with_suffix(".causal")
REPORT = RESULT.with_suffix(".md")
TEST = ROOT / "tests/test_chacha20_round20_w46_polarity_invariant_reader_a362.py"
REPRO = ROOT / "scripts/reproduce_chacha20_round20_w46_polarity_invariant_reader_a362.sh"

A359_RUNNER = RESEARCH / "experiments/chacha20_round20_w46_corrected_knownkey_slice_corpus_a359.py"
A360_RUNNER = RESEARCH / "experiments/chacha20_round20_w46_within_slice_reader_selection_a360.py"
A359_RESULT = RESULTS / "chacha20_round20_w46_corrected_knownkey_slice_corpus_a359_v1.json"
A360_RESULT = RESULTS / "chacha20_round20_w46_within_slice_reader_selection_a360_v1.json"
A361_PROTOCOL = CONFIGS / "chacha20_round20_w46_fresh_a360_reader_deployment_a361_protocol_v1.json"
A361_PREFLIGHT = (
    RESULTS / "chacha20_round20_w46_fresh_a360_reader_deployment_a361_preflight_v1.json"
)
A361_MEASUREMENTS = RESULTS / "chacha20_round20_w46_fresh_a360_reader_deployment_a361_v1"

ATTEMPT_ID = "A362"
DESIGN_SHA256 = "e18527c7677319bc538530e449800b2793500103b0ac7486cb214693a43c9216"
A359_RESULT_SHA256 = "3259526ee94241f5e4858b59cb52cb93a9ef8dbe8dc8bf40deaf4d7757db7a3f"
A360_RESULT_SHA256 = "17af9e3c30bebc0af944bbf988eba4120f0a900073bd0bb5dc1e547235fe3b89"
A361_PROTOCOL_SHA256 = "3396559ab6fde25ef12f5fdcae68e33585234926885b88b136c1f4af47c13228"
A361_PREFLIGHT_SHA256 = "9158edea44ff3884d60308517a7ede1df6b0c0faff2732d520ab61efa88d3d0a"
PRIMITIVE_FEATURE_INDICES = (
    2,
    3,
    73,
    84,
    85,
    239,
    247,
    289,
    300,
    301,
    355,
    380,
    388,
    452,
    460,
    479,
)
EXPECTED_FEATURE_NAMES = {
    2: "conflicts__profile_h1__xor_gradient_l2",
    3: "conflicts__profile_h1__xor_gradient_maxabs",
    73: "search_propagations__profile_h1__xor_laplacian",
    84: "search_propagations__profile_h8__raw_z",
    85: "search_propagations__profile_h8__xor_laplacian",
    239: "learned_clause_accepted_stage__first_difference_2_4__xor_gradient_maxabs",
    247: "learned_clause_accepted_stage__second_difference_1_2_4__xor_gradient_maxabs",
    289: "learned_clause_rejected_large_stage__profile_h1__xor_laplacian",
    300: "learned_clause_rejected_large_stage__profile_h8__raw_z",
    301: "learned_clause_rejected_large_stage__profile_h8__xor_laplacian",
    355: "learned_literal_count_stage__second_difference_1_2_4__xor_gradient_maxabs",
    380: "learned_clause_length_mean__first_difference_2_4__raw_z",
    388: "learned_clause_length_mean__second_difference_1_2_4__raw_z",
    452: "learned_clause_length_max__first_difference_2_4__raw_z",
    460: "learned_clause_length_max__second_difference_1_2_4__raw_z",
    479: "ratio_decisions_versus_conflicts__h4__xor_gradient_maxabs",
}
AGGREGATORS = ("borda", "linf_intersection", "min_rank_wavefront")
MEMBER_COUNTS = (2, 3, 4)
PRIMITIVES = len(PRIMITIVE_FEATURE_INDICES)
ENSEMBLES = 7500
CANDIDATES = PRIMITIVES + ENSEMBLES
TARGETS = 32
HALF = 16
CELLS = 256
FEATURES = 532
DOTCAUSAL_SRC = Path("/Users/bhkmie/Documents/Forschung/O1/vendor/fabel/dotcausal_package/src")


def load_module(path: Path, name: str) -> Any:
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot import A362 dependency {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


A360 = load_module(A360_RUNNER, "a362_a360")
A359 = A360.A359
A275 = A360.A275

file_sha256 = A360.file_sha256
canonical_sha256 = A360.canonical_sha256
atomic_json = A360.atomic_json
atomic_bytes = A360.atomic_bytes
relative = A360.relative
path_from_ref = A360.path_from_ref
anchor = A360.anchor


def feature_ledger() -> list[dict[str, Any]]:
    names = tuple(A275.FEATURE_NAMES)
    if len(names) != FEATURES or len(set(names)) != FEATURES:
        raise RuntimeError("A362 A275 feature ledger differs")
    rows = []
    for primitive_index, feature_index in enumerate(PRIMITIVE_FEATURE_INDICES):
        name = names[feature_index]
        if name != EXPECTED_FEATURE_NAMES[feature_index]:
            raise RuntimeError(f"A362 feature identity differs at {feature_index}")
        rows.append(
            {
                "primitive_index": primitive_index,
                "feature_index": feature_index,
                "feature_name": name,
            }
        )
    return rows


def reader_definitions() -> list[dict[str, Any]]:
    ledger = feature_ledger()
    definitions: list[dict[str, Any]] = [
        {
            "name": f"abs_primitive::{row['feature_index']:03d}::{row['feature_name']}",
            "kind": "abs_primitive",
            "members": [row["primitive_index"]],
            "member_feature_indices": [row["feature_index"]],
        }
        for row in ledger
    ]
    for count in MEMBER_COUNTS:
        for members in itertools.combinations(range(PRIMITIVES), count):
            feature_indices = [PRIMITIVE_FEATURE_INDICES[index] for index in members]
            member_label = "-".join(f"{index:03d}" for index in feature_indices)
            for aggregator in AGGREGATORS:
                definitions.append(
                    {
                        "name": f"ensemble::{aggregator}::{member_label}",
                        "kind": "ensemble",
                        "aggregator": aggregator,
                        "members": list(members),
                        "member_feature_indices": feature_indices,
                    }
                )
    if (
        len(definitions) != CANDIDATES
        or len({definition["name"] for definition in definitions}) != CANDIDATES
        or sum(definition["kind"] == "ensemble" for definition in definitions) != ENSEMBLES
    ):
        raise RuntimeError("A362 candidate definition cover differs")
    return definitions


def load_design() -> dict[str, Any]:
    if file_sha256(DESIGN) != DESIGN_SHA256:
        raise RuntimeError("A362 design hash differs")
    value = json.loads(DESIGN.read_bytes())
    family = value.get("candidate_family", {})
    selection = value.get("selection_contract", {})
    boundary = value.get("information_boundary", {})
    if (
        value.get("schema") != "chacha20-round20-w46-polarity-invariant-reader-a362-design-v1"
        or value.get("attempt_id") != ATTEMPT_ID
        or value.get("design_state")
        != "frozen_after_A360_boundary_and_A359_all32_calibration_before_any_new_validation_target"
        or value.get("primitive_feature_indices") != list(PRIMITIVE_FEATURE_INDICES)
        or family.get("primitive_readers") != PRIMITIVES
        or family.get("ensemble_readers") != ENSEMBLES
        or family.get("candidate_readers") != CANDIDATES
        or family.get("ensemble_member_counts") != list(MEMBER_COUNTS)
        or tuple(family.get("ensemble_aggregators", [])) != AGGREGATORS
        or selection.get("calibration_targets") != TARGETS
        or selection.get("shared_xor_offsets") != CELLS
        or boundary.get("A359_all32_measurements_opened_for_calibration") is not True
        or boundary.get("A361_secret_or_true_prefix_available_to_A362") is not False
        or boundary.get("new_validation_corpus_exists_at_design_freeze") is not False
        or boundary.get("A362_is_claimed_prospective_on_A359") is not False
        or boundary.get("A362_is_frozen_for_the_new_validation_corpus") is not True
    ):
        raise RuntimeError("A362 frozen design semantics differ")
    for name, path_value in value["source_anchors"].items():
        if name.endswith("_path"):
            stem = name.removesuffix("_path")
            anchor(ROOT / path_value, value["source_anchors"][f"{stem}_sha256"])
    feature_ledger()
    reader_definitions()
    return value


def exact_rank_vector(key_rows: Sequence[tuple[Any, ...]]) -> np.ndarray:
    if len(key_rows) != CELLS:
        raise ValueError("A362 order-key cover differs")
    order = sorted(range(CELLS), key=lambda cell: (*key_rows[cell], cell))
    ranks = np.empty(CELLS, dtype=np.int16)
    for rank, cell in enumerate(order, 1):
        ranks[cell] = rank
    if set(int(value) for value in ranks) != set(range(1, CELLS + 1)):
        raise RuntimeError("A362 rank field is not an exact permutation")
    return ranks


def primitive_rank_fields(matrix: np.ndarray) -> np.ndarray:
    values = np.asarray(matrix, dtype=np.float64)
    if values.shape != (CELLS, FEATURES) or not np.isfinite(values).all():
        raise ValueError("A362 normalized target matrix differs")
    result = np.empty((PRIMITIVES, CELLS), dtype=np.int16)
    for primitive, feature_index in enumerate(PRIMITIVE_FEATURE_INDICES):
        scores = np.abs(values[:, feature_index])
        result[primitive] = exact_rank_vector([(-float(score),) for score in scores])
    return result


def candidate_rank_field(primitive_ranks: np.ndarray, definition: Mapping[str, Any]) -> np.ndarray:
    ranks = np.asarray(primitive_ranks, dtype=np.int16)
    if ranks.shape != (PRIMITIVES, CELLS):
        raise ValueError("A362 primitive-rank geometry differs")
    members = tuple(int(value) for value in definition["members"])
    if not members or any(not 0 <= value < PRIMITIVES for value in members):
        raise ValueError("A362 candidate member set differs")
    if definition["kind"] == "abs_primitive":
        if len(members) != 1:
            raise RuntimeError("A362 primitive definition arity differs")
        return ranks[members[0]].copy()
    selected = ranks[np.asarray(members, dtype=np.int64)].astype(np.int32)
    aggregator = str(definition["aggregator"])
    rows: list[tuple[Any, ...]] = []
    for cell in range(CELLS):
        components = tuple(int(selected[index, cell]) for index in range(len(members)))
        total = sum(components)
        if aggregator == "borda":
            rows.append((total, components))
        elif aggregator == "linf_intersection":
            rows.append((max(components), total, components))
        elif aggregator == "min_rank_wavefront":
            rows.append((min(components), total, components))
        else:
            raise ValueError(f"A362 unknown aggregator {aggregator}")
    return exact_rank_vector(rows)


def _uniform_mean_log2_rank() -> float:
    return sum(math.log2(rank) for rank in range(1, CELLS + 1)) / CELLS


def _candidate_statistics(rank_fields: np.ndarray, truths: np.ndarray) -> dict[str, Any]:
    fields = np.asarray(rank_fields, dtype=np.int16)
    labels = np.asarray(truths, dtype=np.int16)
    if fields.shape != (TARGETS, CELLS) or labels.shape != (TARGETS,):
        raise ValueError("A362 candidate evaluation geometry differs")
    true_ranks = fields[np.arange(TARGETS), labels].astype(np.int64)
    uniform = _uniform_mean_log2_rank()
    logs = np.log2(true_ranks.astype(np.float64))
    half_gains = [float(uniform - logs[:HALF].mean()), float(uniform - logs[HALF:].mean())]
    return {
        "truth_ranks": true_ranks.tolist(),
        "half_bit_gains": half_gains,
        "stable_min_half_bit_gain": min(half_gains),
        "all32_bit_gain": float(uniform - logs.mean()),
        "worst_rank": int(true_ranks.max()),
        "targets_at_or_above_median_rank": int(np.count_nonzero(true_ranks <= 128)),
    }


def _stable_gain_by_shared_xor(rank_fields: np.ndarray, truths: np.ndarray) -> np.ndarray:
    fields = np.asarray(rank_fields, dtype=np.int16)
    labels = np.asarray(truths, dtype=np.int16)
    offsets = np.arange(CELLS, dtype=np.int16)
    mean_logs = np.zeros((2, CELLS), dtype=np.float64)
    for target in range(TARGETS):
        shifted = np.bitwise_xor(offsets, labels[target])
        half_index = 0 if target < HALF else 1
        mean_logs[half_index] += np.log2(fields[target, shifted].astype(np.float64))
    mean_logs /= HALF
    uniform = _uniform_mean_log2_rank()
    return np.minimum(uniform - mean_logs[0], uniform - mean_logs[1])


def _selection_key(row: Mapping[str, Any]) -> tuple[Any, ...]:
    return (
        -float(row["stable_min_half_bit_gain"]),
        -float(row["all32_bit_gain"]),
        int(row["worst_rank"]),
        str(row["name"]),
    )


def _rank_field_correlation(left: np.ndarray, right: np.ndarray) -> float:
    a = np.asarray(left, dtype=np.float64).ravel()
    b = np.asarray(right, dtype=np.float64).ravel()
    value = float(np.corrcoef(a, b)[0, 1])
    if not math.isfinite(value):
        raise RuntimeError("A362 rank-field correlation is non-finite")
    return value


def select_reader(matrices: Sequence[np.ndarray], truths: Sequence[int]) -> dict[str, Any]:
    if len(matrices) != TARGETS or len(truths) != TARGETS:
        raise ValueError("A362 calibration panel geometry differs")
    labels = np.asarray(truths, dtype=np.int16)
    if np.any(labels < 0) or np.any(labels >= CELLS):
        raise ValueError("A362 high8 truth label differs")
    primitive_fields = np.stack([primitive_rank_fields(matrix) for matrix in matrices])
    if primitive_fields.shape != (TARGETS, PRIMITIVES, CELLS):
        raise RuntimeError("A362 primitive panel geometry differs")
    definitions = reader_definitions()
    family_best = np.full(CELLS, -np.inf, dtype=np.float64)
    ledger: list[dict[str, Any]] = []
    primary_fields: np.ndarray | None = None
    best_single_fields: np.ndarray | None = None
    primary_row: dict[str, Any] | None = None
    best_single_row: dict[str, Any] | None = None
    for index, definition in enumerate(definitions):
        fields = np.stack(
            [
                candidate_rank_field(primitive_fields[target], definition)
                for target in range(TARGETS)
            ]
        )
        stats = _candidate_statistics(fields, labels)
        shifted_stable = _stable_gain_by_shared_xor(fields, labels)
        family_best = np.maximum(family_best, shifted_stable)
        row = {"index": index, "name": definition["name"], **stats}
        ledger.append(row)
        if primary_row is None or _selection_key(row) < _selection_key(primary_row):
            primary_row = row
            primary_fields = fields.copy()
        if definition["kind"] == "abs_primitive" and (
            best_single_row is None or _selection_key(row) < _selection_key(best_single_row)
        ):
            best_single_row = row
            best_single_fields = fields.copy()
    if (
        primary_row is None
        or primary_fields is None
        or best_single_row is None
        or best_single_fields is None
    ):
        raise RuntimeError("A362 Reader selection did not produce a winner")
    primary_definition = definitions[int(primary_row["index"])]
    primary_shifted = _stable_gain_by_shared_xor(primary_fields, labels)
    observed = float(primary_row["stable_min_half_bit_gain"])
    familywise_p = float(np.count_nonzero(family_best >= observed - 1e-15) / CELLS)
    fixed_primary_p = float(np.count_nonzero(primary_shifted >= observed - 1e-15) / CELLS)
    companion_rows: dict[str, Any] = {}
    if primary_definition["kind"] == "ensemble":
        members = list(primary_definition["members"])
        feature_indices = list(primary_definition["member_feature_indices"])
        for aggregator in AGGREGATORS:
            definition = {
                "name": (
                    f"ensemble::{aggregator}::"
                    + "-".join(f"{index:03d}" for index in feature_indices)
                ),
                "kind": "ensemble",
                "aggregator": aggregator,
                "members": members,
                "member_feature_indices": feature_indices,
            }
            fields = np.stack(
                [
                    candidate_rank_field(primitive_fields[target], definition)
                    for target in range(TARGETS)
                ]
            )
            companion_rows[aggregator] = {
                "definition": definition,
                **_candidate_statistics(fields, labels),
                "rank_field_correlation_to_primary": _rank_field_correlation(
                    primary_fields, fields
                ),
            }
    return {
        "candidate_count": len(definitions),
        "definition_ledger_sha256": canonical_sha256(definitions),
        "feature_ledger": feature_ledger(),
        "feature_ledger_sha256": canonical_sha256(feature_ledger()),
        "uniform_mean_log2_rank_reference": _uniform_mean_log2_rank(),
        "candidate_ledger": ledger,
        "familywise_best_stable_gain_by_shared_xor_offset": family_best.tolist(),
        "exact_familywise_shared_xor_p": familywise_p,
        "primary_fixed_exact_shared_xor_p": fixed_primary_p,
        "primary": {
            "definition": primary_definition,
            **{key: value for key, value in primary_row.items() if key not in {"index", "name"}},
        },
        "best_single": {
            "definition": definitions[int(best_single_row["index"])],
            **{
                key: value for key, value in best_single_row.items() if key not in {"index", "name"}
            },
            "rank_field_correlation_to_primary": _rank_field_correlation(
                primary_fields, best_single_fields
            ),
        },
        "same_member_companions": companion_rows,
    }


def freeze_implementation() -> dict[str, Any]:
    if IMPLEMENTATION.exists():
        raise FileExistsError("A362 implementation already exists")
    if any(path.exists() for path in (RESULT, CAUSAL, REPORT)):
        raise RuntimeError("A362 implementation must precede Reader selection")
    load_design()
    if not TEST.exists() or not REPRO.exists():
        raise FileNotFoundError("A362 test and reproducer must exist before freeze")
    validation_artifacts = sorted(
        str(path.relative_to(ROOT)) for path in ROOT.glob("research/**/*a363*") if path.is_file()
    )
    if validation_artifacts:
        raise RuntimeError("A362 implementation must precede every A363 validation artifact")
    available_a361_shards = sorted(path.name for path in A361_MEASUREMENTS.glob("slice_*.json.zst"))
    definitions = reader_definitions()
    payload: dict[str, Any] = {
        "schema": "chacha20-round20-w46-polarity-invariant-reader-a362-implementation-v1",
        "attempt_id": ATTEMPT_ID,
        "commitment_state": "frozen_before_A362_selection_and_every_A363_validation_artifact",
        "design_sha256": DESIGN_SHA256,
        "candidate_count": len(definitions),
        "definition_ledger_sha256": canonical_sha256(definitions),
        "feature_ledger_sha256": canonical_sha256(feature_ledger()),
        "A361_measurement_shards_physically_available_at_freeze": len(available_a361_shards),
        "A361_measurement_shard_names_physically_available_at_freeze": available_a361_shards,
        "A361_measurement_shard_content_opened_by_A362_before_freeze": False,
        "A363_validation_artifacts_available_at_freeze": [],
        "anchors": {
            "design": anchor(DESIGN, DESIGN_SHA256),
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
        raise RuntimeError("A362 implementation artifact hash differs")
    value = json.loads(IMPLEMENTATION.read_bytes())
    if (
        value.get("schema")
        != "chacha20-round20-w46-polarity-invariant-reader-a362-implementation-v1"
        or value.get("attempt_id") != ATTEMPT_ID
        or value.get("commitment_state")
        != "frozen_before_A362_selection_and_every_A363_validation_artifact"
        or value.get("design_sha256") != DESIGN_SHA256
        or value.get("candidate_count") != CANDIDATES
        or value.get("definition_ledger_sha256") != canonical_sha256(reader_definitions())
        or value.get("feature_ledger_sha256") != canonical_sha256(feature_ledger())
        or value.get("A361_measurement_shard_content_opened_by_A362_before_freeze") is not False
        or value.get("A363_validation_artifacts_available_at_freeze") != []
    ):
        raise RuntimeError("A362 frozen implementation semantics differ")
    for name, path in {
        "design": DESIGN,
        "runner": Path(__file__),
        "test": TEST,
        "reproducer": REPRO,
    }.items():
        row = value["anchors"][name]
        if row["path"] != relative(path) or row["sha256"] != file_sha256(path):
            raise RuntimeError(f"A362 implementation anchor differs: {name}")
    unsigned = {
        key: item for key, item in value.items() if key != "implementation_commitment_sha256"
    }
    if value["implementation_commitment_sha256"] != canonical_sha256(unsigned):
        raise RuntimeError("A362 implementation commitment differs")
    return value


def _load_calibration_panel() -> tuple[list[np.ndarray], list[int], list[dict[str, Any]]]:
    anchor(A359_RESULT, A359_RESULT_SHA256)
    anchor(A360_RESULT, A360_RESULT_SHA256)
    matrices, truths, ledgers = A360._load_target_panel(  # noqa: SLF001
        range(TARGETS), expected_prepared_sha256=A360.A359_PREPARED_SHA256
    )
    return matrices, truths, ledgers


def build_causal(payload: Mapping[str, Any]) -> dict[str, Any]:
    sys.path.insert(0, str(DOTCAUSAL_SRC))
    from dotcausal.io import CausalReader, CausalWriter

    boundary = "A360:signed_linear_orientation_boundary"
    invariant = "A362:polarity_invariant_absolute_rank_family"
    selected = "A362:stable_two_half_frozen_primary"
    validation = "A363:new_disjoint_knownkey_validation_gate"
    writer = CausalWriter(api_id="a362inv")
    writer._rules = []
    writer.add_rule(
        name="signed_boundary_to_invariant_symmetry",
        description="The A360 cross-key orientation change replaces signed projection with target-local absolute ranks.",
        pattern=[boundary],
        conclusion=invariant,
        confidence_modifier=1.0,
    )
    writer.add_rule(
        name="invariant_family_to_stable_primary",
        description="All 7,516 frozen candidates compete by their weaker A359 half before any new validation target exists.",
        pattern=[invariant],
        conclusion=selected,
        confidence_modifier=1.0,
    )
    writer.add_rule(
        name="stable_primary_to_new_validation",
        description="The frozen label-free operator advances unchanged to a newly generated balanced known-key corpus.",
        pattern=[selected],
        conclusion=validation,
        confidence_modifier=1.0,
    )
    writer.add_triplet(
        trigger=boundary,
        mechanism="replace_key_variant_signed_direction_with_absolute_target_local_extremeness",
        outcome=invariant,
        confidence=1.0,
        source=A360_RESULT_SHA256,
        quantification=json.dumps(payload["boundary_resolution"], sort_keys=True),
        evidence="A360 disjoint holdout sign-orientation boundary",
        domain="ChaCha20 R20 W46 causal Reader symmetry",
        quality_score=1.0,
    )
    writer.add_triplet(
        trigger=invariant,
        mechanism="complete_stable_min_half_competition_with_exact_shared_xor_family_null",
        outcome=selected,
        confidence=1.0,
        source=payload["selection_commitment_sha256"],
        quantification=json.dumps(payload["selection_summary"], sort_keys=True),
        evidence="32 complete A359 calibration covers and 7,516 exact candidate definitions",
        domain="Polarity-invariant Reader calibration",
        quality_score=1.0,
    )
    writer.add_triplet(
        trigger=selected,
        mechanism="immutable_zero_refit_transfer_to_new_balanced_keys_before_A361_deployment",
        outcome=validation,
        confidence=1.0,
        source=payload["selection_commitment_sha256"],
        quantification=json.dumps(payload["future_validation_gate"], sort_keys=True),
        evidence="new validation assignments absent at A362 implementation freeze",
        domain="Prospective disjoint validation",
        quality_score=1.0,
    )
    writer.add_triplet(
        trigger=boundary,
        mechanism="materialized_boundary_revision_selection_validation_chain",
        outcome=validation,
        confidence=1.0,
        source="materialized:A362_polarity_invariant_chain",
        quantification="exact retained closure",
        evidence="A362 frozen before A363",
        domain="AI-native retained inference",
        quality_score=1.0,
        is_inferred=True,
    )
    writer.add_cluster(
        name="A362 polarity-invariant Reader", entities=[boundary, invariant, selected, validation]
    )
    writer.add_gap(
        subject=validation,
        predicate="next_required_object",
        expected_object_type="new_balanced_32_target_zero_refit_validation_corpus",
        confidence=1.0,
        suggested_queries=[
            "Generate A363 only after this selection is frozen, validate the primary unchanged, then deploy on sealed A361 only if the gate passes."
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
        reader.api_id != "a362inv"
        or len(explicit) != 3
        or len(all_rows) != 4
        or len(inferred) != 1
        or len(reader._rules) != 3
        or len(reader._clusters) != 1
        or len(reader._gaps) != 1
    ):
        raise RuntimeError("A362 authentic Causal reopen gate failed")
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


def freeze_selection(*, expected_implementation_sha256: str) -> dict[str, Any]:
    if any(path.exists() for path in (RESULT, CAUSAL, REPORT)):
        raise FileExistsError("A362 selection result already exists")
    design = load_design()
    implementation = load_implementation(expected_implementation_sha256)
    matrices, truths, ledgers = _load_calibration_panel()
    selection = select_reader(matrices, truths)
    primary = selection["primary"]
    a360_primary = json.loads(A360_RESULT.read_bytes())["view_evaluations"]["primary_reader"]
    boundary_resolution = {
        "A360_signed_primary_holdout_bit_gain": a360_primary[
            "within_slice_mean_log2_rank_bit_gain"
        ],
        "A360_signed_primary_holdout_exact_shared_xor_p": a360_primary["exact_shared_xor_p"],
        "revised_primary_calibration_stable_min_half_bit_gain": primary["stable_min_half_bit_gain"],
        "revised_primary_calibration_all32_bit_gain": primary["all32_bit_gain"],
        "symmetry_change": "signed_projection_to_absolute_rank_extremeness",
    }
    selection_summary = {
        "candidate_count": selection["candidate_count"],
        "primary_name": primary["definition"]["name"],
        "primary_member_feature_indices": primary["definition"]["member_feature_indices"],
        "primary_half_bit_gains": primary["half_bit_gains"],
        "primary_stable_min_half_bit_gain": primary["stable_min_half_bit_gain"],
        "primary_all32_bit_gain": primary["all32_bit_gain"],
        "primary_truth_ranks": primary["truth_ranks"],
        "primary_targets_at_or_above_median": primary["targets_at_or_above_median_rank"],
        "exact_familywise_shared_xor_p": selection["exact_familywise_shared_xor_p"],
        "primary_fixed_exact_shared_xor_p": selection["primary_fixed_exact_shared_xor_p"],
        "best_single_name": selection["best_single"]["definition"]["name"],
        "best_single_stable_min_half_bit_gain": selection["best_single"][
            "stable_min_half_bit_gain"
        ],
    }
    future_gate = design["future_validation_contract"]["primary_gate"]
    payload: dict[str, Any] = {
        "schema": "chacha20-round20-w46-polarity-invariant-reader-a362-v1",
        "attempt_id": ATTEMPT_ID,
        "evidence_stage": "POLARITY_INVARIANT_READER_FROZEN_BEFORE_NEW_DISJOINT_VALIDATION_CORPUS",
        "design_sha256": DESIGN_SHA256,
        "implementation_sha256": expected_implementation_sha256,
        "implementation_commitment_sha256": implementation["implementation_commitment_sha256"],
        "calibration_target_indices": list(range(TARGETS)),
        "calibration_measurement_ledger": ledgers,
        "calibration_measurement_sha256": canonical_sha256(ledgers),
        "boundary_resolution": boundary_resolution,
        "selection_summary": selection_summary,
        "reader_selection": selection,
        "future_validation_gate": future_gate,
        "reader_refits_after_selection_freeze": 0,
        "A361_measurement_content_opened_by_A362": False,
        "new_validation_targets_available_at_selection_freeze": 0,
        "information_boundary": design["information_boundary"],
        "anchors": {
            "design": anchor(DESIGN, DESIGN_SHA256),
            "implementation": anchor(IMPLEMENTATION, expected_implementation_sha256),
            "A359_result": anchor(A359_RESULT, A359_RESULT_SHA256),
            "A360_result": anchor(A360_RESULT, A360_RESULT_SHA256),
            "A361_protocol": anchor(A361_PROTOCOL, A361_PROTOCOL_SHA256),
            "A361_preflight": anchor(A361_PREFLIGHT, A361_PREFLIGHT_SHA256),
            "runner": anchor(Path(__file__)),
            "test": anchor(TEST),
            "reproducer": anchor(REPRO),
        },
    }
    payload["selection_commitment_sha256"] = canonical_sha256(
        {
            "design_sha256": DESIGN_SHA256,
            "implementation_commitment_sha256": payload["implementation_commitment_sha256"],
            "calibration_measurement_sha256": payload["calibration_measurement_sha256"],
            "reader_selection": selection,
            "future_validation_gate": future_gate,
            "A361_measurement_content_opened_by_A362": False,
            "new_validation_targets_available_at_selection_freeze": 0,
        }
    )
    payload["causal"] = build_causal(payload)
    atomic_json(RESULT, payload)
    atomic_bytes(
        REPORT,
        (
            "# A362 — polarity-invariant W46 Reader\n\n"
            f"Evidence stage: **{payload['evidence_stage']}**\n\n"
            f"- Frozen candidates: **{CANDIDATES:,}**\n"
            f"- Primary: **{selection_summary['primary_name']}**\n"
            f"- Calibration half gains: **{selection_summary['primary_half_bit_gains']} bits**\n"
            f"- Stable minimum / all32 gain: **{selection_summary['primary_stable_min_half_bit_gain']:.9f} / {selection_summary['primary_all32_bit_gain']:.9f} bits**\n"
            f"- Truth ranks: **{selection_summary['primary_truth_ranks']}**\n"
            f"- Exact familywise / fixed-primary XOR p: **{selection_summary['exact_familywise_shared_xor_p']:.9f} / {selection_summary['primary_fixed_exact_shared_xor_p']:.9f}**\n"
            "- Numeric fitted weights: **0**\n"
            "- Sign-flip invariance: **exact by construction**\n"
            "- A361 measurement content reads / new validation targets at freeze: **0 / 0**\n"
            "- Authentic AI-native Causal readback: **3 explicit + 1 inferred**\n"
        ).encode(),
    )
    return payload


def load_result(expected_sha256: str) -> dict[str, Any]:
    if file_sha256(RESULT) != expected_sha256:
        raise RuntimeError("A362 frozen selection result hash differs")
    value = json.loads(RESULT.read_bytes())
    selection = value.get("reader_selection", {})
    if (
        value.get("schema") != "chacha20-round20-w46-polarity-invariant-reader-a362-v1"
        or value.get("attempt_id") != ATTEMPT_ID
        or value.get("evidence_stage")
        != "POLARITY_INVARIANT_READER_FROZEN_BEFORE_NEW_DISJOINT_VALIDATION_CORPUS"
        or value.get("design_sha256") != DESIGN_SHA256
        or selection.get("candidate_count") != CANDIDATES
        or selection.get("definition_ledger_sha256") != canonical_sha256(reader_definitions())
        or value.get("reader_refits_after_selection_freeze") != 0
        or value.get("A361_measurement_content_opened_by_A362") is not False
        or value.get("new_validation_targets_available_at_selection_freeze") != 0
    ):
        raise RuntimeError("A362 frozen selection semantics differ")
    for artifact in value["anchors"].values():
        anchor(path_from_ref(artifact["path"]), artifact["sha256"])
    anchor(CAUSAL, value["causal"]["sha256"])
    return value


def analyze() -> dict[str, Any]:
    return {
        "attempt_id": ATTEMPT_ID,
        "design_sha256": DESIGN_SHA256,
        "candidate_count": CANDIDATES,
        "implementation_frozen": IMPLEMENTATION.exists(),
        "implementation_sha256": file_sha256(IMPLEMENTATION) if IMPLEMENTATION.exists() else None,
        "selection_frozen": RESULT.exists(),
        "selection_sha256": file_sha256(RESULT) if RESULT.exists() else None,
        "A361_measurement_shard_count": len(list(A361_MEASUREMENTS.glob("slice_*.json.zst"))),
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    action = parser.add_mutually_exclusive_group(required=True)
    action.add_argument("--analyze", action="store_true")
    action.add_argument("--freeze-implementation", action="store_true")
    action.add_argument("--freeze-selection", action="store_true")
    parser.add_argument("--expected-implementation-sha256")
    args = parser.parse_args()
    if args.freeze_implementation:
        payload = freeze_implementation()
    elif args.freeze_selection:
        if not args.expected_implementation_sha256:
            parser.error("--freeze-selection requires --expected-implementation-sha256")
        payload = freeze_selection(
            expected_implementation_sha256=args.expected_implementation_sha256
        )
    else:
        payload = analyze()
    print(json.dumps(payload, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()

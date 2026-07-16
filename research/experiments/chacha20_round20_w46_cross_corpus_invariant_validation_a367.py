#!/usr/bin/env python3
"""A367: prospectively validate the frozen A366 Reader portfolio on 64 new targets."""

from __future__ import annotations

import argparse
import concurrent.futures
import hashlib
import importlib.util
import inspect
import json
import math
import os
import sys
import tempfile
import time
from collections.abc import Mapping
from pathlib import Path
from typing import Any

import numpy as np

ROOT = Path(__file__).parents[2]
RESEARCH = ROOT / "research"
CONFIGS = RESEARCH / "configs"
RESULTS = RESEARCH / "results/v1"
ARTIFACTS = RESEARCH / "artifacts/a367_chacha20_r20_w46_cross_corpus_validation"
MEASUREMENTS = RESULTS / "chacha20_round20_w46_cross_corpus_invariant_validation_a367_v1"

DESIGN = CONFIGS / "chacha20_round20_w46_cross_corpus_invariant_validation_a367_design_v1.json"
IMPLEMENTATION = (
    CONFIGS / "chacha20_round20_w46_cross_corpus_invariant_validation_a367_implementation_v1.json"
)
PREPARED = RESULTS / "chacha20_round20_w46_cross_corpus_invariant_validation_a367_prepared_v1.json"
RESULT = RESULTS / "chacha20_round20_w46_cross_corpus_invariant_validation_a367_v1.json"
CAUSAL = RESULT.with_suffix(".causal")
REPORT = RESULT.with_suffix(".md")
TEST = ROOT / "tests/test_chacha20_round20_w46_cross_corpus_invariant_validation_a367.py"
REPRO = ROOT / "scripts/reproduce_chacha20_round20_w46_cross_corpus_invariant_validation_a367.sh"

A363_RUNNER = (
    RESEARCH / "experiments/chacha20_round20_w46_polarity_invariant_validation_a363.py"
)
A366_RUNNER = RESEARCH / "experiments/chacha20_round20_w46_cross_corpus_invariant_reader_a366.py"
A366_RESULT = RESULTS / "chacha20_round20_w46_cross_corpus_invariant_reader_a366_v1.json"

ATTEMPT_ID = "A367"
DESIGN_SHA256 = "d6b45f81ff3fce2ac187578388d218983b9725397b1d2385749ea57572616259"
A366_RESULT_FILE_SHA256 = "0a961b742c721e9ad0b09803224422c9bb03fc272695ed90b62752f24dc169c8"
A366_RESULT_SHA256 = "9dc6b3bd482dbe589769943126f28c4325dffb85d990acade59885e7c5b6bf47"
A366_SELECTION_COMMITMENT_SHA256 = (
    "b5fc9d9147cf5dc2c07f7534d57584046d58be53e98115c210c2512a2cba9faa"
)
GENERATION_SEED = "A367|new-disjoint-cross-corpus-invariant-validation|v1|2026-07-15"
ROW_MANIFEST_SHA256 = "2402d6980c90793797583a5bbae4cfc6fcb928b8a2b67c3a5943e7ec27c26419"
ASSIGNMENT_VECTOR_SHA256 = "171f7fdae11c5da8763052cf6cdded23163e0e7e4cc250aa94851b6efadcf51a"
HIGH8_VECTOR_SHA256 = "a2cdceb46a5bed1109786face785ee67b292968e13b73ba524de54bcd95f1957"
MODEL_ROLES = ("primary", "diverse_companion", "coverage_companion", "best_single")
TARGETS = 64
BLOCKS = 4
BLOCK_SIZE = 16
WIDTH = 46
LOW_BITS = 4
HIGH_BITS = 8
CELLS = 1 << HIGH_BITS
TOTAL_CELLS = TARGETS * CELLS
EXPORT_WORKERS = 2
MEASUREMENT_WORKERS = 4
LOW4_COORDINATES = (23, 22, 21, 20)
HIGH8_COORDINATES = (31, 30, 29, 28, 27, 26, 25, 24)
SYNTHETIC_SOURCE_INDICES = (*range(12), *range(24, 32))
MASK46 = (1 << WIDTH) - 1
DOTCAUSAL_SRC = Path("/Users/bhkmie/Documents/Forschung/O1/vendor/fabel/dotcausal_package/src")


def load_module(path: Path, name: str) -> Any:
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot import A367 dependency {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


BASE = load_module(A363_RUNNER, "a367_a363_base")
A366 = load_module(A366_RUNNER, "a367_a366")
A359 = BASE.A359
A355 = BASE.A355
A340 = BASE.A340
A223 = BASE.A223
WRAPPER = BASE.WRAPPER
A360 = BASE.A360
A275 = BASE.A275

file_sha256 = BASE.file_sha256
canonical_sha256 = BASE.canonical_sha256
canonical_bytes = BASE.canonical_bytes
atomic_json = BASE.atomic_json
atomic_bytes = BASE.atomic_bytes
relative = BASE.relative
path_from_ref = BASE.path_from_ref
anchor = BASE.anchor
sha256 = BASE.sha256

# Reuse the qualified A363 formula/mapping/measurement engine under new immutable paths.
BASE.ATTEMPT_ID = ATTEMPT_ID
BASE.MEASUREMENTS = MEASUREMENTS
BASE.TARGETS = TARGETS
BASE.HALF = TARGETS // 2
BASE.TOTAL_CELLS = TOTAL_CELLS


def generate_rows() -> list[dict[str, Any]]:
    split_names = ("validation_a", "validation_b", "validation_c", "validation_d")
    rows: list[dict[str, Any]] = []
    for index in range(TARGETS):
        label = f"{GENERATION_SEED}|target-{index:02d}"
        assignment = (
            int.from_bytes(hashlib.shake_256(f"{label}|assignment".encode()).digest(8), "little")
            & MASK46
        )
        true_low4 = index % (1 << LOW_BITS)
        true_high8 = (37 + 157 * index) & 0xFF
        assignment = (assignment & ~(0xFFF << 20)) | (true_high8 << 24) | (true_low4 << 20)
        true_prefix12 = (true_high8 << LOW_BITS) | true_low4
        rows.append(
            {
                "assignment": assignment,
                "assignment_hex": f"{assignment:012x}",
                "index": index,
                "label": label,
                "split": split_names[index // BLOCK_SIZE],
                "true_high8": true_high8,
                "true_low4": true_low4,
                "true_prefix12": true_prefix12,
                "true_prefix12_hex": f"{true_prefix12:03x}",
            }
        )
    if canonical_sha256(rows) != ROW_MANIFEST_SHA256:
        raise RuntimeError("A367 deterministic row-manifest commitment differs")
    if canonical_sha256([row["assignment"] for row in rows]) != ASSIGNMENT_VECTOR_SHA256:
        raise RuntimeError("A367 deterministic assignment-vector commitment differs")
    if canonical_sha256([row["true_high8"] for row in rows]) != HIGH8_VECTOR_SHA256:
        raise RuntimeError("A367 deterministic high8-vector commitment differs")
    if len({row["assignment"] for row in rows}) != TARGETS:
        raise RuntimeError("A367 assignments are not unique")
    if len({row["true_high8"] for row in rows}) != TARGETS:
        raise RuntimeError("A367 high8 values are not unique")
    for block in range(BLOCKS):
        subset = rows[block * BLOCK_SIZE : (block + 1) * BLOCK_SIZE]
        if [row["true_low4"] for row in subset] != list(range(16)):
            raise RuntimeError("A367 low4 block balance differs")
    return rows


def _load_a366_result() -> dict[str, Any]:
    anchor(A366_RESULT, A366_RESULT_FILE_SHA256)
    value = json.loads(A366_RESULT.read_bytes())
    selected = value.get("reader_selection", {}).get("selected_readers", {})
    if (
        value.get("attempt_id") != "A366"
        or value.get("result_sha256") != A366_RESULT_SHA256
        or value.get("reader_selection", {}).get("selection_commitment_sha256")
        != A366_SELECTION_COMMITMENT_SHA256
        or tuple(selected) != tuple(sorted(MODEL_ROLES))
    ):
        raise RuntimeError("A367 frozen A366 result differs")
    return value


def load_design() -> dict[str, Any]:
    if file_sha256(DESIGN) != DESIGN_SHA256:
        raise RuntimeError("A367 design hash differs")
    value = json.loads(DESIGN.read_bytes())
    corpus = value.get("corpus_contract", {})
    measurement = value.get("measurement_contract", {})
    reader = value.get("reader_validation_contract", {})
    boundary = value.get("information_boundary", {})
    gates = value.get("preparation_gates", {})
    if (
        value.get("schema")
        != "chacha20-round20-w46-cross-corpus-invariant-validation-a367-design-v1"
        or value.get("attempt_id") != ATTEMPT_ID
        or value.get("design_state")
        != "frozen_after_A366_portfolio_before_any_A367_formula_export_measurement_or_label_readback"
        or corpus.get("generation_seed") != GENERATION_SEED
        or corpus.get("row_manifest_canonical_sha256") != ROW_MANIFEST_SHA256
        or corpus.get("assignment_vector_canonical_sha256") != ASSIGNMENT_VECTOR_SHA256
        or corpus.get("high8_vector_canonical_sha256") != HIGH8_VECTOR_SHA256
        or corpus.get("targets") != TARGETS
        or corpus.get("fixed_blocks") != BLOCKS
        or corpus.get("targets_per_block") != BLOCK_SIZE
        or measurement.get("cells_per_target") != CELLS
        or measurement.get("total_cells") != TOTAL_CELLS
        or measurement.get("maximum_solver_stages") != TOTAL_CELLS * len(BASE.HORIZONS)
        or measurement.get("concurrent_export_workers") != EXPORT_WORKERS
        or measurement.get("concurrent_measurement_workers") != MEASUREMENT_WORKERS
        or measurement.get("mapping_exports_per_target") != 1 + math.ceil(math.log2(WIDTH))
        or measurement.get("fixed_low4_coordinates_high_to_low") != list(LOW4_COORDINATES)
        or measurement.get("candidate_high8_coordinates_high_to_low")
        != list(HIGH8_COORDINATES)
        or measurement.get("synthetic_reader_mapping_source_indices")
        != list(SYNTHETIC_SOURCE_INDICES)
        or reader.get("A366_result_file_sha256") != A366_RESULT_FILE_SHA256
        or reader.get("A366_result_sha256") != A366_RESULT_SHA256
        or reader.get("A366_selection_commitment_sha256")
        != A366_SELECTION_COMMITMENT_SHA256
        or tuple(reader.get("model_roles", [])) != MODEL_ROLES
        or reader.get("reader_refits") != 0
        or boundary.get("A366_portfolio_frozen_before_A367_design") is not True
        or boundary.get("A367_target_artifacts_available_at_design_freeze") != 0
        or boundary.get("A367_solver_measurements_available_at_design_freeze") != 0
        or boundary.get("reader_definition_changed_after_A366_freeze") is not False
        or boundary.get("A361_measurement_shards_used_to_select_or_validate_A366_readers")
        is not False
        or gates.get("coordinate_mapping_decoded_independently_for_every_target") is not True
        or gates.get("true_known_assignment_must_be_SAT_for_every_target") is not True
        or gates.get("one_bit_flip_of_known_assignment_must_be_UNSAT_for_every_target")
        is not True
    ):
        raise RuntimeError("A367 frozen design semantics differ")
    for name, path_value in value["source_anchors"].items():
        if name.endswith("_path"):
            stem = name.removesuffix("_path")
            anchor(ROOT / path_value, value["source_anchors"][f"{stem}_sha256"])
    generate_rows()
    _load_a366_result()
    return value


def freeze_implementation() -> dict[str, Any]:
    if IMPLEMENTATION.exists():
        raise FileExistsError("A367 implementation already exists")
    if any(path.exists() for path in (ARTIFACTS, MEASUREMENTS, PREPARED, RESULT, CAUSAL, REPORT)):
        raise RuntimeError("A367 implementation must precede every generated target artifact")
    load_design()
    a366 = _load_a366_result()
    selected = a366["reader_selection"]["selected_readers"]
    if not TEST.exists() or not REPRO.exists():
        raise FileNotFoundError("A367 test and reproducer must exist before freeze")
    payload: dict[str, Any] = {
        "schema": "chacha20-round20-w46-cross-corpus-invariant-validation-a367-implementation-v1",
        "attempt_id": ATTEMPT_ID,
        "commitment_state": "frozen_before_any_A367_target_formula_export_measurement_or_label_readback",
        "design_sha256": DESIGN_SHA256,
        "row_manifest_canonical_sha256": ROW_MANIFEST_SHA256,
        "assignment_vector_canonical_sha256": ASSIGNMENT_VECTOR_SHA256,
        "high8_vector_canonical_sha256": HIGH8_VECTOR_SHA256,
        "A366_result_file_sha256": A366_RESULT_FILE_SHA256,
        "A366_selection_commitment_sha256": A366_SELECTION_COMMITMENT_SHA256,
        "frozen_model_definitions": {
            role: selected[role]["definition"] for role in MODEL_ROLES
        },
        "reader_refits": 0,
        "candidate_assignments_executed": 0,
        "anchors": {
            "design": anchor(DESIGN, DESIGN_SHA256),
            "A366_result": anchor(A366_RESULT, A366_RESULT_FILE_SHA256),
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
        raise RuntimeError("A367 implementation artifact hash differs")
    value = json.loads(IMPLEMENTATION.read_bytes())
    if (
        value.get("schema")
        != "chacha20-round20-w46-cross-corpus-invariant-validation-a367-implementation-v1"
        or value.get("attempt_id") != ATTEMPT_ID
        or value.get("commitment_state")
        != "frozen_before_any_A367_target_formula_export_measurement_or_label_readback"
        or value.get("design_sha256") != DESIGN_SHA256
        or value.get("row_manifest_canonical_sha256") != ROW_MANIFEST_SHA256
        or value.get("assignment_vector_canonical_sha256") != ASSIGNMENT_VECTOR_SHA256
        or value.get("high8_vector_canonical_sha256") != HIGH8_VECTOR_SHA256
        or value.get("A366_result_file_sha256") != A366_RESULT_FILE_SHA256
        or value.get("A366_selection_commitment_sha256")
        != A366_SELECTION_COMMITMENT_SHA256
        or value.get("reader_refits") != 0
        or value.get("candidate_assignments_executed") != 0
    ):
        raise RuntimeError("A367 frozen implementation semantics differ")
    for name, path in {
        "design": DESIGN,
        "A366_result": A366_RESULT,
        "runner": Path(__file__),
        "test": TEST,
        "reproducer": REPRO,
    }.items():
        row = value["anchors"][name]
        if row["path"] != relative(path) or row["sha256"] != file_sha256(path):
            raise RuntimeError(f"A367 implementation anchor differs: {name}")
    unsigned = {
        key: item for key, item in value.items() if key != "implementation_commitment_sha256"
    }
    if value["implementation_commitment_sha256"] != canonical_sha256(unsigned):
        raise RuntimeError("A367 implementation commitment differs")
    return value


def _without_volatile(value: Any) -> Any:
    if isinstance(value, dict):
        return {
            key: _without_volatile(item)
            for key, item in value.items()
            if not key.startswith("volatile_")
        }
    if isinstance(value, list):
        return [_without_volatile(item) for item in value]
    return value


def prepare(*, expected_implementation_sha256: str) -> dict[str, Any]:
    if any(path.exists() for path in (ARTIFACTS, PREPARED, MEASUREMENTS, RESULT, CAUSAL, REPORT)):
        raise FileExistsError("A367 preparation or measurement artifacts already exist")
    design = load_design()
    implementation = load_implementation(expected_implementation_sha256)
    rows = generate_rows()
    config = json.loads(BASE.A223_CONFIG.read_bytes())
    A223._toolchain_gates(config)  # noqa: SLF001
    if not BASE.CADICAL.is_file():
        raise FileNotFoundError("A367 CaDiCaL CLI is unavailable")
    started = time.perf_counter()
    ARTIFACTS.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="a367_prepare_", dir=ARTIFACTS.parent) as temporary:
        stage = Path(temporary) / ARTIFACTS.name
        stage.mkdir(parents=False, exist_ok=False)
        with concurrent.futures.ThreadPoolExecutor(max_workers=EXPORT_WORKERS) as executor:
            exports = list(
                executor.map(lambda row: BASE._export_target(row, stage=stage, config=config), rows)  # noqa: SLF001
            )
        exports.sort(key=lambda row: row["index"])
        if [row["index"] for row in exports] != list(range(TARGETS)):
            raise RuntimeError("A367 target export cover differs")
        with concurrent.futures.ThreadPoolExecutor(max_workers=EXPORT_WORKERS) as executor:
            mappings = list(
                executor.map(
                    lambda pair: BASE._mapping_for(  # noqa: SLF001
                        pair[0], pair[1], stage=stage, config=config
                    ),
                    zip(rows, exports, strict=True),
                )
            )
        mappings.sort(key=lambda row: row["index"])
        correction = json.loads(BASE.A354_RESULT.read_bytes())["corrected_successor_contract"]
        if (
            correction["synthetic_reader_mapping_source_indices"]
            != list(SYNTHETIC_SOURCE_INDICES)
            or correction["low4_fixed_unit_coordinates_high_to_low"]
            != list(LOW4_COORDINATES)
            or correction["high8_assumption_coordinates_high_to_low"]
            != list(HIGH8_COORDINATES)
        ):
            raise RuntimeError("A367 corrected coordinate semantics differ")
        for mapping in mappings:
            source_mapping = mapping["source_one_literals_bit0_upward"]
            if len(source_mapping) != WIDTH or len({abs(value) for value in source_mapping}) != WIDTH:
                raise RuntimeError(f"A367 target {mapping['index']} source map is not bijective")
            corrected = A355.corrected_synthetic_mapping(source_mapping)
            mapping["corrected_synthetic_reader_mapping"] = corrected
            mapping["corrected_synthetic_reader_mapping_sha256"] = canonical_sha256(corrected)
        with concurrent.futures.ThreadPoolExecutor(max_workers=EXPORT_WORKERS) as executor:
            semantics = list(
                executor.map(
                    lambda pair: A359._semantic_and_slice(  # noqa: SLF001
                        pair[0],
                        stage=stage,
                        source_mapping=pair[1]["source_one_literals_bit0_upward"],
                    ),
                    zip(rows, mappings, strict=True),
                )
            )
        semantics.sort(key=lambda row: row["index"])
        os.replace(stage, ARTIFACTS)
    prepared_rows = []
    for source, exported, mapping, semantic in zip(rows, exports, mappings, semantics, strict=True):
        target_dir = ARTIFACTS / f"target_{source['index']:02d}"
        prepared_rows.append(
            {
                **source,
                "public_challenge": anchor(target_dir / "public_challenge.json"),
                "public_challenge_canonical_sha256": exported["challenge_canonical_sha256"],
                "bridge_challenge_sha256": exported["bridge_challenge_sha256"],
                "formula_bytes": exported["formula_bytes"],
                "formula_sha256": exported["formula_sha256"],
                "base_CNF": anchor(target_dir / "base.cnf", exported["base_export"]["sha256"]),
                "base_CNF_header": exported["base_export"]["header"],
                "base_CNF_body_sha256": exported["base_body_sha256"],
                "base_CNF_variable_count": exported["variable_count"],
                "base_CNF_clause_count": exported["clause_count"],
                "base_CNF_export": exported["base_export"],
                "slice_CNF": anchor(target_dir / "slice.cnf", semantic["slice_sha256"]),
                "source_one_literals_bit0_upward": mapping["source_one_literals_bit0_upward"],
                "source_mapping_sha256": mapping["source_mapping_sha256"],
                "corrected_synthetic_reader_mapping": mapping[
                    "corrected_synthetic_reader_mapping"
                ],
                "corrected_synthetic_reader_mapping_sha256": mapping[
                    "corrected_synthetic_reader_mapping_sha256"
                ],
                "coordinate_probe_rows": mapping["probe_rows"],
                "semantic_mapping_gate": {
                    "flip_bit": semantic["flip_bit"],
                    "true_assignment": semantic["true_assignment_gate"],
                    "one_bit_flip": semantic["one_bit_flip_gate"],
                },
            }
        )
    mapping_contract = {
        "decoded_target_indices": list(range(TARGETS)),
        "mapping_exports_per_target": 1 + math.ceil(math.log2(WIDTH)),
        "mapping_exports_total": TARGETS * (1 + math.ceil(math.log2(WIDTH))),
        "source_mapping_sha256_by_target": [row["source_mapping_sha256"] for row in mappings],
        "corrected_mapping_sha256_by_target": [
            row["corrected_synthetic_reader_mapping_sha256"] for row in mappings
        ],
        "unique_source_mapping_hashes": len({row["source_mapping_sha256"] for row in mappings}),
        "literal_ids_allowed_to_be_target_specific": True,
        "all_target_mappings_decoded": True,
        "all_target_mappings_bijective": True,
        "matches_A354_corrected_coordinate_semantics": True,
    }
    payload: dict[str, Any] = {
        "schema": "chacha20-round20-w46-cross-corpus-invariant-validation-a367-prepared-v1",
        "attempt_id": ATTEMPT_ID,
        "evidence_stage": "NEW_64_TARGET_VALIDATION_CORPUS_PREPARED_BEFORE_SOLVER_MEASUREMENT",
        "design_sha256": DESIGN_SHA256,
        "implementation_sha256": expected_implementation_sha256,
        "implementation_commitment_sha256": implementation[
            "implementation_commitment_sha256"
        ],
        "row_manifest_canonical_sha256": ROW_MANIFEST_SHA256,
        "assignment_vector_canonical_sha256": ASSIGNMENT_VECTOR_SHA256,
        "high8_vector_canonical_sha256": HIGH8_VECTOR_SHA256,
        "mapping_contract": mapping_contract,
        "rows": prepared_rows,
        "fixed_validation_blocks": BLOCKS,
        "targets_per_block": BLOCK_SIZE,
        "solver_measurement_started": False,
        "preparation_commitment_sha256": canonical_sha256(
            {
                "design_sha256": DESIGN_SHA256,
                "row_manifest_canonical_sha256": ROW_MANIFEST_SHA256,
                "assignment_vector_canonical_sha256": ASSIGNMENT_VECTOR_SHA256,
                "high8_vector_canonical_sha256": HIGH8_VECTOR_SHA256,
                "mapping_contract": mapping_contract,
                "rows": _without_volatile(prepared_rows),
                "solver_measurement_started": False,
            }
        ),
        "information_boundary": design["information_boundary"],
        "anchors": {
            "design": anchor(DESIGN, DESIGN_SHA256),
            "implementation": anchor(IMPLEMENTATION, expected_implementation_sha256),
            "A366_result": anchor(A366_RESULT, A366_RESULT_FILE_SHA256),
            "runner": anchor(Path(__file__)),
            "test": anchor(TEST),
            "reproducer": anchor(REPRO),
            "cadical": anchor(BASE.CADICAL),
        },
        "volatile_wall_seconds": time.perf_counter() - started,
    }
    atomic_json(PREPARED, payload)
    return {
        "attempt_id": ATTEMPT_ID,
        "prepared": relative(PREPARED),
        "prepared_sha256": file_sha256(PREPARED),
        "preparation_commitment_sha256": payload["preparation_commitment_sha256"],
        "targets": TARGETS,
        "slice_CNF_count": len(prepared_rows),
        "mapping_panel_sha256": canonical_sha256(mapping_contract),
        "all_true_assignments_SAT": True,
        "all_one_bit_flips_UNSAT": True,
        "solver_measurement_started": False,
    }


def load_prepared(expected_sha256: str) -> dict[str, Any]:
    if file_sha256(PREPARED) != expected_sha256:
        raise RuntimeError("A367 prepared manifest hash differs")
    value = json.loads(PREPARED.read_bytes())
    if (
        value.get("schema")
        != "chacha20-round20-w46-cross-corpus-invariant-validation-a367-prepared-v1"
        or value.get("attempt_id") != ATTEMPT_ID
        or value.get("design_sha256") != DESIGN_SHA256
        or value.get("row_manifest_canonical_sha256") != ROW_MANIFEST_SHA256
        or value.get("assignment_vector_canonical_sha256") != ASSIGNMENT_VECTOR_SHA256
        or value.get("high8_vector_canonical_sha256") != HIGH8_VECTOR_SHA256
        or value.get("solver_measurement_started") is not False
        or len(value.get("rows", [])) != TARGETS
        or value.get("mapping_contract", {}).get("all_target_mappings_decoded") is not True
        or value.get("mapping_contract", {}).get("all_target_mappings_bijective") is not True
    ):
        raise RuntimeError("A367 prepared manifest semantics differ")
    for expected, row in zip(generate_rows(), value["rows"], strict=True):
        if any(row.get(key) != expected[key] for key in expected):
            raise RuntimeError(f"A367 prepared row identity differs: {expected['index']}")
        source = [int(item) for item in row["source_one_literals_bit0_upward"]]
        corrected = [int(item) for item in row["corrected_synthetic_reader_mapping"]]
        if (
            len(source) != WIDTH
            or len({abs(item) for item in source}) != WIDTH
            or row["source_mapping_sha256"] != canonical_sha256(source)
            or corrected != A355.corrected_synthetic_mapping(source)
            or row["corrected_synthetic_reader_mapping_sha256"] != canonical_sha256(corrected)
        ):
            raise RuntimeError(f"A367 prepared mapping differs: {expected['index']}")
        for name in ("public_challenge", "base_CNF", "slice_CNF"):
            artifact = row[name]
            anchor(path_from_ref(artifact["path"]), artifact["sha256"])
    for name, artifact in value["anchors"].items():
        if name == "cadical":
            anchor(Path(artifact["path"]), artifact["sha256"])
        else:
            anchor(path_from_ref(artifact["path"]), artifact["sha256"])
    return value


def _evaluate_model(
    fields: np.ndarray, truths: np.ndarray, low4_values: list[int]
) -> dict[str, Any]:
    stats = A366._statistics(fields, truths)  # noqa: SLF001
    stable_by_offset = A366._stable_gain_by_shared_xor(fields, truths)  # noqa: SLF001
    global_ranks = [
        16 * (int(rank) - 1) + int(low4) + 1
        for rank, low4 in zip(stats["truth_ranks"], low4_values, strict=True)
    ]
    return {
        **stats,
        "stable_min_block_gain_by_shared_xor_offset": stable_by_offset.tolist(),
        "fixed_exact_shared_xor_p": float(
            np.count_nonzero(
                stable_by_offset >= float(stats["stable_min_block_bit_gain"]) - 1e-15
            )
            / CELLS
        ),
        "global_round_robin_group_ranks": global_ranks,
        "global_round_robin_geometric_mean_domain_reduction": float(
            4096 / math.exp(sum(math.log(rank) for rank in global_ranks) / TARGETS)
        ),
    }


def build_causal(payload: Mapping[str, Any]) -> dict[str, Any]:
    sys.path.insert(0, str(DOTCAUSAL_SRC))
    from dotcausal.io import CausalReader, CausalWriter

    source = "A366:frozen_cross_corpus_reader_portfolio"
    prepared = "A367:new_64_target_semantically_gated_corpus"
    measured = "A367:complete_label_blind_candidate_fields"
    evaluated = "A367:zero_refit_four_model_rank_panel"
    terminal = "A367:familywise_reader_gate"
    writer = CausalWriter(api_id="a367val")
    writer._rules = []
    rules = [
        ("frozen_portfolio_to_new_corpus", [source], prepared),
        ("new_corpus_to_complete_fields", [prepared], measured),
        ("complete_fields_to_zero_refit_panel", [measured], evaluated),
        ("rank_panel_to_familywise_gate", [evaluated], terminal),
    ]
    for name, pattern, conclusion in rules:
        writer.add_rule(
            name=name,
            description=name.replace("_", " "),
            pattern=pattern,
            conclusion=conclusion,
            confidence_modifier=1.0,
        )
    triplets = [
        (
            source,
            "immutable_A366_portfolio_precedes_A367_manifest_and_formula_exports",
            prepared,
            A366_SELECTION_COMMITMENT_SHA256,
            payload["preparation_summary"],
        ),
        (
            prepared,
            "complete_numeric_256_cell_cover_without_label_reader_or_candidate_execution",
            measured,
            payload["measurement_sha256"],
            payload["measurement_summary"],
        ),
        (
            measured,
            "apply_four_frozen_target_local_rank_models_without_refit",
            evaluated,
            payload["result_sha256"],
            payload["model_summary"],
        ),
        (
            evaluated,
            "predeclared_four_model_familywise_shared_xor_and_four_block_gate",
            terminal,
            payload["result_sha256"],
            payload["retention_gate"],
        ),
    ]
    for trigger, mechanism, outcome, source_hash, quantification in triplets:
        writer.add_triplet(
            trigger=trigger,
            mechanism=mechanism,
            outcome=outcome,
            confidence=1.0,
            source=source_hash,
            quantification=json.dumps(quantification, sort_keys=True),
            evidence=payload["evidence_stage"],
            domain="ChaCha20 R20 W46 prospective cross-corpus Reader validation",
            quality_score=1.0,
        )
    writer.add_triplet(
        trigger=source,
        mechanism="materialized_frozen_portfolio_new_corpus_familywise_gate_chain",
        outcome=terminal,
        confidence=1.0,
        source="materialized:A367_validation_chain",
        quantification="exact retained closure",
        evidence=payload["evidence_stage"],
        domain="AI-native retained inference",
        quality_score=1.0,
        is_inferred=True,
    )
    writer.add_cluster(
        name="A367 prospective cross-corpus Reader validation",
        entities=[source, prepared, measured, evaluated, terminal],
    )
    writer.add_gap(
        subject=terminal,
        predicate="next_required_object",
        expected_object_type=(
            "sealed_A361_reader_portfolio_order_and_W46_recovery"
            if payload["retention_gate"]["passed"]
            else "cross_corpus_reader_mechanism_revision"
        ),
        confidence=1.0,
        suggested_queries=[payload["retention_gate"]["next_query"]],
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
        reader.api_id != "a367val"
        or len(explicit) != 4
        or len(all_rows) != 5
        or len(inferred) != 1
        or len(reader._rules) != 4
        or len(reader._clusters) != 1
        or len(reader._gaps) != 1
    ):
        raise RuntimeError("A367 authentic Causal reopen gate failed")
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


def measure_and_validate(*, expected_prepared_sha256: str) -> dict[str, Any]:
    if any(path.exists() for path in (RESULT, CAUSAL, REPORT)):
        raise FileExistsError("A367 result already exists")
    design = load_design()
    prepared = load_prepared(expected_prepared_sha256)
    a366 = _load_a366_result()
    selected = a366["reader_selection"]["selected_readers"]
    definitions = {role: selected[role]["definition"] for role in MODEL_ROLES}
    unique_feature_indices = [
        int(row["feature_index"]) for row in a366["reader_selection"]["unique_primitives"]
    ]
    _a275, _model, _a291, indices, helper = A340.A296._reader_stack()  # noqa: SLF001
    WRAPPER._load_base_wrapper()  # noqa: SLF001
    if list(indices) != A340.FEATURE_INDICES:
        raise RuntimeError("A367 selected Reader feature identity differs")
    jobs = [
        {
            "index": int(row["index"]),
            "label": str(row["label"]),
            "split": str(row["split"]),
            "true_low4": int(row["true_low4"]),
            "slice_CNF_path": row["slice_CNF"]["path"],
            "slice_CNF_sha256": row["slice_CNF"]["sha256"],
            "corrected_reader_mapping": [
                int(value) for value in row["corrected_synthetic_reader_mapping"]
            ],
            "corrected_reader_mapping_sha256": row[
                "corrected_synthetic_reader_mapping_sha256"
            ],
        }
        for row in prepared["rows"]
    ]
    MEASUREMENTS.mkdir(parents=True, exist_ok=True)
    started = time.perf_counter()
    completed = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=MEASUREMENT_WORKERS) as executor:
        futures = [
            executor.submit(
                BASE._run_target,  # noqa: SLF001
                job,
                helper=helper,
                key_mapping=job["corrected_reader_mapping"],
                prepared_sha256=expected_prepared_sha256,
            )
            for job in jobs
        ]
        for future in concurrent.futures.as_completed(futures):
            completed.append(future.result())
    completed.sort(key=lambda row: row["index"])
    if [row["index"] for row in completed] != list(range(TARGETS)):
        raise RuntimeError("A367 target measurement cover differs")
    measurements = [
        BASE._read_measurement(  # noqa: SLF001
            path_from_ref(row["ledger"]["path"]),
            expected_prepared_sha256=expected_prepared_sha256,
            ledger=row["ledger"],
        )
        for row in completed
    ]
    source_rows = generate_rows()
    status_counts = {status: 0 for status in ("sat", "unknown", "unsat")}
    stage_count = 0
    matrices = []
    truths = []
    low4_values = []
    postclosure_labels = []
    for source, measurement in zip(source_rows, measurements, strict=True):
        cells = measurement["run"]["cells"]
        if [int(cell["cell_index"]) for cell in cells] != list(range(CELLS)):
            raise RuntimeError(f"A367 target {source['index']} cell cover differs")
        stage_count += len(measurement["run"]["stages"])
        for cell in cells:
            status_counts[cell["final_status"]] += 1
        matrices.append(A360.target_normalize(A275._target_feature_matrix(measurement)))  # noqa: SLF001
        truths.append(int(source["true_high8"]))
        low4_values.append(int(source["true_low4"]))
        postclosure_labels.append(
            {
                "index": source["index"],
                "split": source["split"],
                "true_low4": source["true_low4"],
                "true_high8": source["true_high8"],
                "true_prefix12": source["true_prefix12"],
                "label_revealed_after_complete_target_cover": True,
            }
        )
    if sum(status_counts.values()) != TOTAL_CELLS:
        raise RuntimeError("A367 status cover differs")
    matrix_panel = np.stack(matrices)
    truth_vector = np.asarray(truths, dtype=np.int16)
    all_fields = A366._exact_abs_rank_fields(matrix_panel)  # noqa: SLF001
    primitive_fields = all_fields[:, np.asarray(unique_feature_indices, dtype=np.int64), :]
    model_fields = {
        role: A366.candidate_rank_field(primitive_fields, definitions[role])
        for role in MODEL_ROLES
    }
    evaluations = {
        role: _evaluate_model(fields, truth_vector, low4_values)
        for role, fields in model_fields.items()
    }
    familywise_best = np.max(
        np.stack(
            [
                np.asarray(
                    evaluations[role]["stable_min_block_gain_by_shared_xor_offset"],
                    dtype=np.float64,
                )
                for role in MODEL_ROLES
            ]
        ),
        axis=0,
    )
    contract = design["reader_validation_contract"]["retention_gate"]
    retained_roles = []
    for role in MODEL_ROLES:
        row = evaluations[role]
        observed = float(row["stable_min_block_bit_gain"])
        familywise_p = float(
            np.count_nonzero(familywise_best >= observed - 1e-15) / CELLS
        )
        row["familywise_exact_shared_xor_p"] = familywise_p
        passed = (
            familywise_p <= contract["familywise_shared_xor_p_maximum"]
            and observed > contract["minimum_four_block_log2_rank_gain_exclusive"]
            and row["all64_bit_gain"] > contract["all64_log2_rank_gain_exclusive"]
            and row["targets_at_or_above_median_rank"]
            >= contract["targets_at_or_above_median_minimum"]
        )
        row["passed"] = passed
        if passed:
            retained_roles.append(role)
    passed = bool(retained_roles)
    retention_gate = {
        "passed": passed,
        "contract": contract,
        "retained_model_roles": retained_roles,
        "retained_model_count": len(retained_roles),
        "familywise_best_stable_gain_by_shared_xor_offset": familywise_best.tolist(),
        "deployment_rule": design["reader_validation_contract"]["deployment_rule"],
        "next_query": (
            "Apply every retained frozen A366 Reader to the complete sealed A361 field; freeze their exact factor-k wavefront order and execute it with the qualified A324 engine."
            if passed
            else "Use the complete A367 rank panel to revise the cross-corpus invariant mechanism before any A361 shard is opened."
        ),
    }
    ledgers = [
        {**row["ledger"], "index": row["index"], "resumed": row["resumed"]}
        for row in completed
    ]
    scientific_ledgers = [
        {key: value for key, value in row.items() if key != "resumed"} for row in ledgers
    ]
    measurement_summary = {
        "targets": TARGETS,
        "fixed_validation_blocks": BLOCKS,
        "targets_per_block": BLOCK_SIZE,
        "cells_per_target": CELLS,
        "total_cells": TOTAL_CELLS,
        "solver_stages": stage_count,
        "status_counts": status_counts,
        "concurrent_workers": MEASUREMENT_WORKERS,
        "true_high8_labels_used_during_measurement": 0,
        "A366_reader_reads_during_measurement": 0,
        "reader_refits": 0,
        "candidate_assignments_executed": 0,
    }
    preparation_summary = {
        "targets": TARGETS,
        "semantic_true_assignment_SAT": TARGETS,
        "semantic_one_bit_flip_UNSAT": TARGETS,
        "mapping_decoded_target_count": TARGETS,
        "mapping_exports_total": TARGETS * (1 + math.ceil(math.log2(WIDTH))),
        "unique_source_mapping_hashes": prepared["mapping_contract"][
            "unique_source_mapping_hashes"
        ],
        "corrected_coordinate_interval": [20, 31],
    }
    model_summary = {
        role: {
            "name": definitions[role]["name"],
            "fixed_block_bit_gains": row["fixed_block_bit_gains"],
            "stable_min_block_bit_gain": row["stable_min_block_bit_gain"],
            "all64_bit_gain": row["all64_bit_gain"],
            "targets_at_or_above_median_rank": row[
                "targets_at_or_above_median_rank"
            ],
            "worst_rank": row["worst_rank"],
            "fixed_exact_shared_xor_p": row["fixed_exact_shared_xor_p"],
            "familywise_exact_shared_xor_p": row["familywise_exact_shared_xor_p"],
            "global_round_robin_geometric_mean_domain_reduction": row[
                "global_round_robin_geometric_mean_domain_reduction"
            ],
            "passed": row["passed"],
        }
        for role, row in evaluations.items()
    }
    measurement_sha = canonical_sha256(
        {"summary": measurement_summary, "ledger": scientific_ledgers}
    )
    payload: dict[str, Any] = {
        "schema": "chacha20-round20-w46-cross-corpus-invariant-validation-a367-v1",
        "attempt_id": ATTEMPT_ID,
        "evidence_stage": (
            "PROSPECTIVE_NEW_64_TARGET_CROSS_CORPUS_READER_PORTFOLIO_RETAINED"
            if passed
            else "PROSPECTIVE_NEW_64_TARGET_CROSS_CORPUS_READER_BOUNDARY_RETAINED"
        ),
        "design_sha256": DESIGN_SHA256,
        "prepared_sha256": expected_prepared_sha256,
        "A366_result_file_sha256": A366_RESULT_FILE_SHA256,
        "A366_selection_commitment_sha256": A366_SELECTION_COMMITMENT_SHA256,
        "preparation_summary": preparation_summary,
        "measurement_summary": measurement_summary,
        "measurement_ledger": ledgers,
        "measurement_sha256": measurement_sha,
        "postclosure_labels": postclosure_labels,
        "model_evaluations": evaluations,
        "model_summary": model_summary,
        "retention_gate": retention_gate,
        "reader_refits_after_A366_selection_freeze": 0,
        "information_boundary": design["information_boundary"],
        "anchors": {
            "design": anchor(DESIGN, DESIGN_SHA256),
            "prepared": anchor(PREPARED, expected_prepared_sha256),
            "A366_result": anchor(A366_RESULT, A366_RESULT_FILE_SHA256),
            "runner": anchor(Path(__file__)),
            "test": anchor(TEST),
            "reproducer": anchor(REPRO),
        },
        "volatile_wall_seconds": time.perf_counter() - started,
    }
    payload["result_sha256"] = canonical_sha256(
        {
            "evidence_stage": payload["evidence_stage"],
            "prepared_sha256": expected_prepared_sha256,
            "A366_selection_commitment_sha256": A366_SELECTION_COMMITMENT_SHA256,
            "measurement_sha256": measurement_sha,
            "postclosure_labels": postclosure_labels,
            "model_evaluations": evaluations,
            "retention_gate": retention_gate,
            "reader_refits_after_A366_selection_freeze": 0,
            "information_boundary": payload["information_boundary"],
        }
    )
    payload["causal"] = build_causal(payload)
    atomic_json(RESULT, payload)
    atomic_bytes(
        REPORT,
        (
            "# A367 — prospective 64-target cross-corpus Reader validation\n\n"
            f"Evidence stage: **{payload['evidence_stage']}**\n\n"
            f"- New targets / complete cells: **{TARGETS} / {TOTAL_CELLS:,}**\n"
            f"- Retained frozen Readers: **{retained_roles}**\n"
            f"- Model summary: **{json.dumps(model_summary, sort_keys=True)}**\n"
            f"- Familywise gate: **{passed}**\n"
            "- Reader refits / candidate assignments: **0 / 0**\n"
            "- Authentic AI-native Causal readback: **4 explicit + 1 inferred**\n"
        ).encode(),
    )
    return payload


def analyze() -> dict[str, Any]:
    return {
        "attempt_id": ATTEMPT_ID,
        "design_sha256": DESIGN_SHA256,
        "implementation_frozen": IMPLEMENTATION.exists(),
        "implementation_sha256": file_sha256(IMPLEMENTATION) if IMPLEMENTATION.exists() else None,
        "prepared": PREPARED.exists(),
        "prepared_sha256": file_sha256(PREPARED) if PREPARED.exists() else None,
        "artifact_target_count": len(list(ARTIFACTS.glob("target_*"))) if ARTIFACTS.exists() else 0,
        "measurement_shard_count": len(list(MEASUREMENTS.glob("target_*.json.zst")))
        if MEASUREMENTS.exists()
        else 0,
        "result_complete": RESULT.exists(),
        "result_sha256": file_sha256(RESULT) if RESULT.exists() else None,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    action = parser.add_mutually_exclusive_group(required=True)
    action.add_argument("--analyze", action="store_true")
    action.add_argument("--freeze-implementation", action="store_true")
    action.add_argument("--prepare", action="store_true")
    action.add_argument("--measure-and-validate", action="store_true")
    parser.add_argument("--expected-implementation-sha256")
    parser.add_argument("--expected-prepared-sha256")
    args = parser.parse_args()
    if args.freeze_implementation:
        payload = freeze_implementation()
    elif args.prepare:
        if not args.expected_implementation_sha256:
            parser.error("--prepare requires --expected-implementation-sha256")
        payload = prepare(expected_implementation_sha256=args.expected_implementation_sha256)
    elif args.measure_and_validate:
        if not args.expected_prepared_sha256:
            parser.error("--measure-and-validate requires --expected-prepared-sha256")
        payload = measure_and_validate(expected_prepared_sha256=args.expected_prepared_sha256)
        payload = {
            "attempt_id": payload["attempt_id"],
            "evidence_stage": payload["evidence_stage"],
            "measurement_summary": payload["measurement_summary"],
            "model_summary": payload["model_summary"],
            "retention_gate": {
                key: value
                for key, value in payload["retention_gate"].items()
                if key != "familywise_best_stable_gain_by_shared_xor_offset"
            },
            "result_sha256": payload["result_sha256"],
            "causal": payload["causal"],
        }
    else:
        payload = analyze()
    print(json.dumps(payload, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()

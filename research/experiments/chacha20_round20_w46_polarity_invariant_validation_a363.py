#!/usr/bin/env python3
"""A363: prospectively validate A362 on thirty-two new W46 known-key targets."""

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
import threading
import time
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

import numpy as np
import zstandard

ROOT = Path(__file__).parents[2]
RESEARCH = ROOT / "research"
CONFIGS = RESEARCH / "configs"
RESULTS = RESEARCH / "results/v1"
ARTIFACTS = RESEARCH / "artifacts/a363_chacha20_r20_w46_polarity_invariant_validation"
MEASUREMENTS = RESULTS / "chacha20_round20_w46_polarity_invariant_validation_a363_v1"

DESIGN = CONFIGS / "chacha20_round20_w46_polarity_invariant_validation_a363_design_v1.json"
IMPLEMENTATION = (
    CONFIGS / "chacha20_round20_w46_polarity_invariant_validation_a363_implementation_v1.json"
)
PREPARED = RESULTS / "chacha20_round20_w46_polarity_invariant_validation_a363_prepared_v1.json"
RESULT = RESULTS / "chacha20_round20_w46_polarity_invariant_validation_a363_v1.json"
CAUSAL = RESULT.with_suffix(".causal")
REPORT = RESULT.with_suffix(".md")
TEST = ROOT / "tests/test_chacha20_round20_w46_polarity_invariant_validation_a363.py"
REPRO = ROOT / "scripts/reproduce_chacha20_round20_w46_polarity_invariant_validation_a363.sh"

A359_RUNNER = RESEARCH / "experiments/chacha20_round20_w46_corrected_knownkey_slice_corpus_a359.py"
A362_RUNNER = RESEARCH / "experiments/chacha20_round20_w46_polarity_invariant_reader_a362.py"
A362_RESULT = RESULTS / "chacha20_round20_w46_polarity_invariant_reader_a362_v1.json"
A223_CONFIG = CONFIGS / "chacha20_round20_capacity_moonshot_a223_v1.json"
A354_RESULT = RESULTS / "chacha20_round20_w46_direct12_coordinate_codec_audit_a354_v1.json"

ATTEMPT_ID = "A363"
DESIGN_SHA256 = "b4c8fb70a62b40788e8d8cbb100806ae5fcc33c18f83e2aef295432cf9f97fb6"
A362_RESULT_SHA256 = "6c7ffb32effc2c0141e9f7ce02776a75e4e4772f18126a87bc84c61c6d45705e"
A362_SELECTION_COMMITMENT_SHA256 = (
    "4791833558d170ec540c7045b273e10e78a9f954c91c5a1d6f14bbc891a24032"
)
GENERATION_SEED = "A363|new-disjoint-polarity-invariant-validation|v1|2026-07-15"
ROW_MANIFEST_SHA256 = "40773e7cfe275d5afa256d6c607220945722626591dead0b42e84c72446b3cc2"
ASSIGNMENT_VECTOR_SHA256 = "fb19407af7294d09a3a1412dcaf956d12b1b6198255f867c21b43b5ff0918897"
PRIMARY_NAME = "ensemble::linf_intersection::073-355-380-479"
PRIMARY_FEATURE_INDICES = (73, 355, 380, 479)
TARGETS = 32
HALF = 16
WIDTH = 46
HIGH_BITS = 8
LOW_BITS = 4
CELLS = 1 << HIGH_BITS
TOTAL_CELLS = TARGETS * CELLS
HORIZONS = [1, 2, 4, 8]
WATCHDOG_SECONDS = 2.0
EXPORT_WORKERS = 2
MEASUREMENT_WORKERS = 4
LOW4_COORDINATES = (23, 22, 21, 20)
HIGH8_COORDINATES = (31, 30, 29, 28, 27, 26, 25, 24)
SYNTHETIC_SOURCE_INDICES = (*range(12), *range(24, 32))
MASK46 = (1 << WIDTH) - 1
ZSTD_LEVEL = 10
CADICAL = Path("/opt/homebrew/bin/cadical")
DOTCAUSAL_SRC = Path("/Users/bhkmie/Documents/Forschung/O1/vendor/fabel/dotcausal_package/src")
FORMULA_LOCK = threading.Lock()


def load_module(path: Path, name: str) -> Any:
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot import A363 dependency {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


A359 = load_module(A359_RUNNER, "a363_a359")
A362 = load_module(A362_RUNNER, "a363_a362")
A360 = A362.A360
A275 = A362.A275
A355 = A359.A355
A340 = A359.A340
A325 = A359.A325
A223 = A359.A223
WRAPPER = A359.WRAPPER

file_sha256 = A359.file_sha256
canonical_sha256 = A359.canonical_sha256
canonical_bytes = A359.canonical_bytes
atomic_json = A359.atomic_json
atomic_bytes = A359.atomic_bytes
relative = A359.relative
path_from_ref = A359.path_from_ref
anchor = A359.anchor
sha256 = A359.sha256


def generate_rows() -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for index in range(TARGETS):
        label = f"{GENERATION_SEED}|target-{index:02d}"
        assignment = (
            int.from_bytes(hashlib.shake_256(f"{label}|assignment".encode()).digest(8), "little")
            & MASK46
        )
        true_low4 = index % (1 << LOW_BITS)
        true_high8 = (61 + 149 * index) & 0xFF
        assignment = (assignment & ~(0xFFF << 20)) | (true_high8 << 24) | (true_low4 << 20)
        true_prefix12 = (true_high8 << LOW_BITS) | true_low4
        rows.append(
            {
                "assignment": assignment,
                "assignment_hex": f"{assignment:012x}",
                "index": index,
                "label": label,
                "split": "validation_a" if index < HALF else "validation_b",
                "true_high8": true_high8,
                "true_low4": true_low4,
                "true_prefix12": true_prefix12,
                "true_prefix12_hex": f"{true_prefix12:03x}",
            }
        )
    if canonical_sha256(rows) != ROW_MANIFEST_SHA256:
        raise RuntimeError("A363 deterministic row-manifest commitment differs")
    if canonical_sha256([row["assignment"] for row in rows]) != ASSIGNMENT_VECTOR_SHA256:
        raise RuntimeError("A363 deterministic assignment-vector commitment differs")
    if len({row["assignment"] for row in rows}) != TARGETS:
        raise RuntimeError("A363 assignments are not unique")
    return rows


def load_design() -> dict[str, Any]:
    if file_sha256(DESIGN) != DESIGN_SHA256:
        raise RuntimeError("A363 design hash differs")
    value = json.loads(DESIGN.read_bytes())
    corpus = value.get("corpus_contract", {})
    measurement = value.get("measurement_contract", {})
    reader = value.get("reader_validation_contract", {})
    boundary = value.get("information_boundary", {})
    gates = value.get("preparation_gates", {})
    if (
        value.get("schema") != "chacha20-round20-w46-polarity-invariant-validation-a363-design-v1"
        or value.get("attempt_id") != ATTEMPT_ID
        or value.get("design_state")
        != "frozen_after_A362_selection_before_any_A363_formula_export_solver_measurement_or_reader_validation"
        or corpus.get("generation_seed") != GENERATION_SEED
        or corpus.get("row_manifest_canonical_sha256") != ROW_MANIFEST_SHA256
        or corpus.get("assignment_vector_canonical_sha256") != ASSIGNMENT_VECTOR_SHA256
        or corpus.get("targets") != TARGETS
        or measurement.get("cells_per_target") != CELLS
        or measurement.get("total_cells") != TOTAL_CELLS
        or measurement.get("solver_stages") != TOTAL_CELLS * len(HORIZONS)
        or measurement.get("concurrent_export_workers") != EXPORT_WORKERS
        or measurement.get("concurrent_measurement_workers") != MEASUREMENT_WORKERS
        or measurement.get("mapping_exports_per_target") != 1 + math.ceil(math.log2(WIDTH))
        or measurement.get("fixed_low4_coordinates_high_to_low") != list(LOW4_COORDINATES)
        or measurement.get("candidate_high8_coordinates_high_to_low") != list(HIGH8_COORDINATES)
        or measurement.get("synthetic_reader_mapping_source_indices")
        != list(SYNTHETIC_SOURCE_INDICES)
        or reader.get("A362_result_sha256") != A362_RESULT_SHA256
        or reader.get("A362_selection_commitment_sha256") != A362_SELECTION_COMMITMENT_SHA256
        or reader.get("primary_definition") != PRIMARY_NAME
        or reader.get("primary_member_feature_indices") != list(PRIMARY_FEATURE_INDICES)
        or reader.get("reader_refits") != 0
        or boundary.get("A362_selection_frozen_before_A363_design") is not True
        or boundary.get("A363_target_artifacts_available_at_design_freeze") != 0
        or boundary.get("A363_solver_measurements_available_at_design_freeze") != 0
        or boundary.get("reader_definition_changed_after_A362_freeze") is not False
        or boundary.get("true_high8_label_used_to_add_CNF_units_or_change_candidate_order")
        is not False
        or boundary.get("A361_measurements_used_to_select_or_validate_A362_reader") is not False
        or gates.get("coordinate_mapping_decoded_independently_for_every_target") is not True
        or gates.get("coordinate_mapping_must_be_bijective_for_every_target") is not True
        or gates.get("true_known_assignment_must_be_SAT_for_every_target") is not True
        or gates.get("one_bit_flip_of_known_assignment_must_be_UNSAT_for_every_target") is not True
    ):
        raise RuntimeError("A363 frozen design semantics differ")
    for name, path_value in value["source_anchors"].items():
        if name.endswith("_path"):
            stem = name.removesuffix("_path")
            anchor(ROOT / path_value, value["source_anchors"][f"{stem}_sha256"])
    generate_rows()
    return value


def freeze_implementation() -> dict[str, Any]:
    if IMPLEMENTATION.exists():
        raise FileExistsError("A363 implementation already exists")
    if any(path.exists() for path in (ARTIFACTS, MEASUREMENTS, PREPARED, RESULT, CAUSAL, REPORT)):
        raise RuntimeError("A363 implementation must precede every target artifact")
    load_design()
    a362 = A362.load_result(A362_RESULT_SHA256)
    primary = a362["reader_selection"]["primary"]["definition"]
    if (
        a362["selection_commitment_sha256"] != A362_SELECTION_COMMITMENT_SHA256
        or primary["name"] != PRIMARY_NAME
        or primary["member_feature_indices"] != list(PRIMARY_FEATURE_INDICES)
    ):
        raise RuntimeError("A363 frozen A362 Reader differs")
    if not TEST.exists() or not REPRO.exists():
        raise FileNotFoundError("A363 test and reproducer must exist before freeze")
    payload: dict[str, Any] = {
        "schema": "chacha20-round20-w46-polarity-invariant-validation-a363-implementation-v1",
        "attempt_id": ATTEMPT_ID,
        "commitment_state": "frozen_before_any_A363_target_formula_export_measurement_or_label_readback",
        "design_sha256": DESIGN_SHA256,
        "row_manifest_canonical_sha256": ROW_MANIFEST_SHA256,
        "assignment_vector_canonical_sha256": ASSIGNMENT_VECTOR_SHA256,
        "A362_result_sha256": A362_RESULT_SHA256,
        "A362_selection_commitment_sha256": A362_SELECTION_COMMITMENT_SHA256,
        "primary_definition": primary,
        "reader_refits": 0,
        "anchors": {
            "design": anchor(DESIGN, DESIGN_SHA256),
            "A362_result": anchor(A362_RESULT, A362_RESULT_SHA256),
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
        raise RuntimeError("A363 implementation artifact hash differs")
    value = json.loads(IMPLEMENTATION.read_bytes())
    if (
        value.get("schema")
        != "chacha20-round20-w46-polarity-invariant-validation-a363-implementation-v1"
        or value.get("attempt_id") != ATTEMPT_ID
        or value.get("commitment_state")
        != "frozen_before_any_A363_target_formula_export_measurement_or_label_readback"
        or value.get("design_sha256") != DESIGN_SHA256
        or value.get("row_manifest_canonical_sha256") != ROW_MANIFEST_SHA256
        or value.get("assignment_vector_canonical_sha256") != ASSIGNMENT_VECTOR_SHA256
        or value.get("A362_result_sha256") != A362_RESULT_SHA256
        or value.get("A362_selection_commitment_sha256") != A362_SELECTION_COMMITMENT_SHA256
        or value.get("primary_definition", {}).get("name") != PRIMARY_NAME
        or value.get("reader_refits") != 0
    ):
        raise RuntimeError("A363 frozen implementation semantics differ")
    for name, path in {
        "design": DESIGN,
        "A362_result": A362_RESULT,
        "runner": Path(__file__),
        "test": TEST,
        "reproducer": REPRO,
    }.items():
        row = value["anchors"][name]
        if row["path"] != relative(path) or row["sha256"] != file_sha256(path):
            raise RuntimeError(f"A363 implementation anchor differs: {name}")
    unsigned = {
        key: item for key, item in value.items() if key != "implementation_commitment_sha256"
    }
    if value["implementation_commitment_sha256"] != canonical_sha256(unsigned):
        raise RuntimeError("A363 implementation commitment differs")
    return value


def a363_bridge_challenge(challenge: Mapping[str, Any]) -> dict[str, Any]:
    bridge = A340.bridge_challenge({"public_challenge": challenge})
    bridge["generation_entropy_source"] = "deterministic_SHAKE256_A363_validation_corpus_v1"
    bridge["secret_discarded_after_target_construction"] = False
    bridge["known_assignment_retained_outside_public_bridge"] = True
    return bridge


def validate_a363_bridge(bridge: Mapping[str, Any]) -> None:
    targets = bridge.get("target_words", [])
    hashes = bridge.get("target_block_sha256", [])
    control = bridge.get("control_target_words", [])
    masks = A223._expected_known_masks(WIDTH)  # noqa: SLF001
    values = bridge.get("known_key_value_words", [])
    if (
        bridge.get("rounds") != 20
        or bridge.get("block_count") != 8
        or bridge.get("counter_schedule") != "base_plus_block_index_mod_2^32"
        or bridge.get("unknown_key_bits") != WIDTH
        or bridge.get("known_key_bits") != 256 - WIDTH
        or bridge.get("unknown_global_bit_interval") != [0, WIDTH - 1]
        or bridge.get("unknown_assignment_included") is not False
        or bridge.get("full_key_included") is not False
        or bridge.get("generation_entropy_source")
        != "deterministic_SHAKE256_A363_validation_corpus_v1"
        or bridge.get("secret_discarded_after_target_construction") is not False
        or bridge.get("known_assignment_retained_outside_public_bridge") is not True
        or bridge.get("known_key_mask_words") != masks
        or len(values) != 8
        or any(value & ~mask for value, mask in zip(values, masks, strict=True))
        or len(bridge.get("nonce_words", [])) != 3
        or len(targets) != 8
        or any(len(block) != 16 for block in targets)
        or len(hashes) != 8
        or len(control) != 16
        or control[0] != (targets[0][0] ^ 1)
        or control[1:] != targets[0][1:]
    ):
        raise RuntimeError("A363 deterministic known-key bridge structural gate failed")
    for block, digest in zip(targets, hashes, strict=True):
        if sha256(A223.P1._word_bytes(block)) != digest:  # noqa: SLF001
            raise RuntimeError("A363 target fingerprint differs")
    if sha256(A223.P1._word_bytes(control)) != bridge["control_target_block_sha256"]:  # noqa: SLF001
        raise RuntimeError("A363 control fingerprint differs")


def a363_w46_source_formula(bridge: dict[str, Any]) -> str:
    with FORMULA_LOCK:
        original = int(A223.BLOCK_COUNT)
        formula = A340.w46_source_formula(A223, bridge)
        if A223.BLOCK_COUNT != original:
            raise RuntimeError("A363 A223 block-count restoration gate failed")
        return formula


def _export_target(
    row: Mapping[str, Any], *, stage: Path, config: Mapping[str, Any]
) -> dict[str, Any]:
    target_dir = stage / f"target_{int(row['index']):02d}"
    target_dir.mkdir(parents=True, exist_ok=False)
    challenge = A325.challenge_from_assignment(
        label=str(row["label"]), assignment=int(row["assignment"])
    )
    A325.validate_challenge(challenge)
    bridge = a363_bridge_challenge(challenge)
    validate_a363_bridge(bridge)
    formula = a363_w46_source_formula(bridge)
    base = target_dir / "base.cnf"
    export = A223._export_cnf(  # noqa: SLF001
        formula=formula,
        output=base,
        config=dict(config),
        label=f"A363_W46_TARGET_{int(row['index']):02d}_B1",
    )
    lines = base.read_bytes().splitlines(keepends=True)
    header = lines[0].split() if lines else []
    if len(header) != 4 or header[:2] != [b"p", b"cnf"]:
        raise RuntimeError(f"A363 target {row['index']} base CNF header differs")
    atomic_json(target_dir / "public_challenge.json", challenge)
    return {
        "index": int(row["index"]),
        "bridge_challenge_sha256": canonical_sha256(bridge),
        "challenge_canonical_sha256": canonical_sha256(challenge),
        "formula_bytes": len(formula.encode()),
        "formula_sha256": sha256(formula.encode()),
        "base_body_sha256": sha256(b"".join(lines[1:])),
        "variable_count": int(header[2]),
        "clause_count": int(header[3]),
        "base_export": export,
    }


def _mapping_for(
    row: Mapping[str, Any], export: Mapping[str, Any], *, stage: Path, config: Mapping[str, Any]
) -> dict[str, Any]:
    target_dir = stage / f"target_{int(row['index']):02d}"
    challenge = A325.challenge_from_assignment(
        label=str(row["label"]), assignment=int(row["assignment"])
    )
    bridge = a363_bridge_challenge(challenge)
    validate_a363_bridge(bridge)
    formula = a363_w46_source_formula(bridge)
    base = target_dir / "base.cnf"
    raw = base.read_bytes()
    lines = raw.splitlines(keepends=True)
    context = {
        "width": WIDTH,
        "formula": formula,
        "formula_bytes": len(formula.encode()),
        "formula_sha256": sha256(formula.encode()),
        "base_path": base,
        "base_raw": raw,
        "base_body": b"".join(lines[1:]),
        "base_body_sha256": sha256(b"".join(lines[1:])),
        "variable_count": int(lines[0].split()[2]),
        "clause_count": int(lines[0].split()[3]),
        "base_export": export["base_export"],
    }
    directory = target_dir / "mapping_probes"
    directory.mkdir(parents=True, exist_ok=False)
    probes = [
        A223._coordinate_probe(  # noqa: SLF001
            context=context, dimension=dimension, config=dict(config), directory=directory
        )
        for dimension in range(-1, math.ceil(math.log2(WIDTH)))
    ]
    mapping = A223._decode_mapping(  # noqa: SLF001
        [(dimension, units) for _, dimension, units, _ in probes], width=WIDTH
    )
    directory.rmdir()
    return {
        "index": int(row["index"]),
        "source_one_literals_bit0_upward": mapping,
        "source_mapping_sha256": canonical_sha256(mapping),
        "probe_rows": [probe[3] for probe in probes],
    }


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
        raise FileExistsError("A363 preparation or measurement artifacts already exist")
    design = load_design()
    implementation = load_implementation(expected_implementation_sha256)
    rows = generate_rows()
    config = json.loads(A223_CONFIG.read_bytes())
    A223._toolchain_gates(config)  # noqa: SLF001
    if not CADICAL.is_file():
        raise FileNotFoundError("A363 CaDiCaL CLI is unavailable")
    started = time.perf_counter()
    ARTIFACTS.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="a363_prepare_", dir=ARTIFACTS.parent) as temporary:
        stage = Path(temporary) / ARTIFACTS.name
        stage.mkdir(parents=False, exist_ok=False)
        with concurrent.futures.ThreadPoolExecutor(max_workers=EXPORT_WORKERS) as executor:
            exports = list(
                executor.map(lambda row: _export_target(row, stage=stage, config=config), rows)
            )
        exports.sort(key=lambda row: row["index"])
        if [row["index"] for row in exports] != list(range(TARGETS)):
            raise RuntimeError("A363 target export cover differs")
        with concurrent.futures.ThreadPoolExecutor(max_workers=EXPORT_WORKERS) as executor:
            mappings = list(
                executor.map(
                    lambda pair: _mapping_for(pair[0], pair[1], stage=stage, config=config),
                    zip(rows, exports, strict=True),
                )
            )
        mappings.sort(key=lambda row: row["index"])
        correction = json.loads(A354_RESULT.read_bytes())["corrected_successor_contract"]
        if (
            correction["synthetic_reader_mapping_source_indices"] != list(SYNTHETIC_SOURCE_INDICES)
            or correction["low4_fixed_unit_coordinates_high_to_low"] != list(LOW4_COORDINATES)
            or correction["high8_assumption_coordinates_high_to_low"] != list(HIGH8_COORDINATES)
        ):
            raise RuntimeError("A363 A354 corrected coordinate semantics differ")
        for mapping in mappings:
            source_mapping = mapping["source_one_literals_bit0_upward"]
            if (
                len(source_mapping) != WIDTH
                or len({abs(value) for value in source_mapping}) != WIDTH
            ):
                raise RuntimeError(f"A363 target {mapping['index']} source map is not bijective")
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
                "corrected_synthetic_reader_mapping": mapping["corrected_synthetic_reader_mapping"],
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
        "A354_synthetic_reader_mapping_source_indices": list(SYNTHETIC_SOURCE_INDICES),
        "matches_A354_corrected_coordinate_semantics": True,
    }
    payload: dict[str, Any] = {
        "schema": "chacha20-round20-w46-polarity-invariant-validation-a363-prepared-v1",
        "attempt_id": ATTEMPT_ID,
        "evidence_stage": "NEW_DISJOINT_VALIDATION_CORPUS_PREPARED_BEFORE_SOLVER_MEASUREMENT",
        "design_sha256": DESIGN_SHA256,
        "implementation_sha256": expected_implementation_sha256,
        "implementation_commitment_sha256": implementation["implementation_commitment_sha256"],
        "row_manifest_canonical_sha256": ROW_MANIFEST_SHA256,
        "assignment_vector_canonical_sha256": ASSIGNMENT_VECTOR_SHA256,
        "mapping_contract": mapping_contract,
        "rows": prepared_rows,
        "validation_a_targets": HALF,
        "validation_b_targets": HALF,
        "solver_measurement_started": False,
        "preparation_commitment_sha256": canonical_sha256(
            {
                "design_sha256": DESIGN_SHA256,
                "row_manifest_canonical_sha256": ROW_MANIFEST_SHA256,
                "assignment_vector_canonical_sha256": ASSIGNMENT_VECTOR_SHA256,
                "mapping_contract": mapping_contract,
                "rows": _without_volatile(prepared_rows),
                "solver_measurement_started": False,
            }
        ),
        "information_boundary": design["information_boundary"],
        "anchors": {
            "design": anchor(DESIGN, DESIGN_SHA256),
            "implementation": anchor(IMPLEMENTATION, expected_implementation_sha256),
            "A362_result": anchor(A362_RESULT, A362_RESULT_SHA256),
            "runner": anchor(Path(__file__)),
            "test": anchor(TEST),
            "reproducer": anchor(REPRO),
            "cadical": anchor(CADICAL),
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
        raise RuntimeError("A363 prepared manifest hash differs")
    value = json.loads(PREPARED.read_bytes())
    if (
        value.get("schema") != "chacha20-round20-w46-polarity-invariant-validation-a363-prepared-v1"
        or value.get("attempt_id") != ATTEMPT_ID
        or value.get("design_sha256") != DESIGN_SHA256
        or value.get("row_manifest_canonical_sha256") != ROW_MANIFEST_SHA256
        or value.get("assignment_vector_canonical_sha256") != ASSIGNMENT_VECTOR_SHA256
        or value.get("solver_measurement_started") is not False
        or len(value.get("rows", [])) != TARGETS
        or value.get("mapping_contract", {}).get("all_target_mappings_decoded") is not True
        or value.get("mapping_contract", {}).get("all_target_mappings_bijective") is not True
    ):
        raise RuntimeError("A363 prepared manifest semantics differ")
    for expected, row in zip(generate_rows(), value["rows"], strict=True):
        if any(row.get(key) != expected[key] for key in expected):
            raise RuntimeError(f"A363 prepared row identity differs: {expected['index']}")
        source = [int(item) for item in row["source_one_literals_bit0_upward"]]
        corrected = [int(item) for item in row["corrected_synthetic_reader_mapping"]]
        if (
            len(source) != WIDTH
            or len({abs(item) for item in source}) != WIDTH
            or row["source_mapping_sha256"] != canonical_sha256(source)
            or corrected != A355.corrected_synthetic_mapping(source)
            or row["corrected_synthetic_reader_mapping_sha256"] != canonical_sha256(corrected)
        ):
            raise RuntimeError(f"A363 prepared mapping differs: {expected['index']}")
        for name in ("public_challenge", "base_CNF", "slice_CNF"):
            artifact = row[name]
            anchor(path_from_ref(artifact["path"]), artifact["sha256"])
    for name, artifact in value["anchors"].items():
        if name == "cadical":
            anchor(Path(artifact["path"]), artifact["sha256"])
        else:
            anchor(path_from_ref(artifact["path"]), artifact["sha256"])
    return value


def _measurement_path(index: int) -> Path:
    return MEASUREMENTS / f"target_{index:02d}.json.zst"


def _write_measurement(path: Path, value: Mapping[str, Any]) -> dict[str, Any]:
    raw = canonical_bytes(value)
    compressed = zstandard.ZstdCompressor(
        level=ZSTD_LEVEL,
        threads=0,
        write_checksum=True,
        write_content_size=True,
        write_dict_id=False,
    ).compress(raw)
    atomic_bytes(path, compressed)
    return {
        "path": relative(path),
        "raw_bytes": len(raw),
        "raw_sha256": sha256(raw),
        "compressed_bytes": len(compressed),
        "compressed_sha256": sha256(compressed),
    }


def _read_measurement(
    path: Path, *, expected_prepared_sha256: str, ledger: Mapping[str, Any] | None = None
) -> dict[str, Any]:
    compressed = path.read_bytes()
    if ledger is not None and sha256(compressed) != ledger["compressed_sha256"]:
        raise RuntimeError("A363 compressed measurement hash differs")
    raw = zstandard.ZstdDecompressor().decompress(compressed)
    if ledger is not None and sha256(raw) != ledger["raw_sha256"]:
        raise RuntimeError("A363 raw measurement hash differs")
    value = json.loads(raw)
    run = value.get("run", {})
    cells = run.get("cells", [])
    if (
        value.get("schema") != "chacha20-round20-w46-polarity-invariant-validation-a363-shard-v1"
        or value.get("attempt_id") != ATTEMPT_ID
        or value.get("prepared_sha256") != expected_prepared_sha256
        or value.get("complete_candidate_cover") is not True
        or value.get("true_high8_available_during_measurement") is not False
        or len(cells) != CELLS
        or [int(cell.get("cell_index", -1)) for cell in cells] != list(range(CELLS))
        or not 1 <= len(run.get("stages", [])) <= CELLS * len(HORIZONS)
        or run.get("all_watchdogs_clear") is not True
        or value.get("candidate_order") != "numeric_0_through_255"
        or value.get("reader_refits") != 0
        or canonical_bytes(value) != raw
    ):
        raise RuntimeError(f"A363 measurement shard gate failed: {path.name}")
    return value


def _run_target(
    job: Mapping[str, Any], *, helper: Path, key_mapping: Sequence[int], prepared_sha256: str
) -> dict[str, Any]:
    index = int(job["index"])
    mapping = [int(value) for value in key_mapping]
    if (
        len(mapping) != 20
        or len({abs(value) for value in mapping}) != 20
        or canonical_sha256(mapping) != job["corrected_reader_mapping_sha256"]
    ):
        raise RuntimeError(f"A363 target {index} Reader mapping gate differs")
    path = _measurement_path(index)
    if path.exists():
        value = _read_measurement(path, expected_prepared_sha256=prepared_sha256)
        if (
            value["label"] != job["label"]
            or value["true_low4"] != job["true_low4"]
            or value["corrected_reader_mapping_sha256"] != job["corrected_reader_mapping_sha256"]
        ):
            raise RuntimeError(f"A363 resumed target identity differs: {index}")
        return {"index": index, "resumed": True, "ledger": _write_measurement(path, value)}
    started = time.perf_counter()
    raw_run = WRAPPER.run_fresh_clause_identity(
        helper=helper,
        cnf=path_from_ref(str(job["slice_CNF_path"])),
        mode=f"A363_W46_validation_target_{index:02d}",
        order=[f"{value:08b}" for value in range(CELLS)],
        key_one_literals_bit0_through_bit19=mapping,
        conflict_horizons=HORIZONS,
        watchdog_seconds=WATCHDOG_SECONDS,
        external_timeout_seconds=3600.0,
    )
    stable = {
        key: value
        for key, value in raw_run.items()
        if key not in {"command", "process_elapsed_seconds"}
    }
    measurement = {
        "schema": "chacha20-round20-w46-polarity-invariant-validation-a363-shard-v1",
        "attempt_id": ATTEMPT_ID,
        "prepared_sha256": prepared_sha256,
        "index": index,
        "label": str(job["label"]),
        "split": str(job["split"]),
        "true_low4": int(job["true_low4"]),
        "slice_CNF_sha256": str(job["slice_CNF_sha256"]),
        "corrected_reader_mapping_sha256": str(job["corrected_reader_mapping_sha256"]),
        "run": stable,
        "complete_candidate_cover": len(stable.get("cells", [])) == CELLS,
        "candidate_order": "numeric_0_through_255",
        "true_high8_available_during_measurement": False,
        "true_high8_used_for_candidate_order_or_early_stop": False,
        "A362_reader_available_during_measurement": False,
        "reader_refits": 0,
        "volatile_process_elapsed_seconds": time.perf_counter() - started,
    }
    if (
        measurement["complete_candidate_cover"] is not True
        or stable.get("all_watchdogs_clear") is not True
        or len(stable.get("stages", [])) < 1
    ):
        raise RuntimeError(f"A363 target measurement gate failed: {index}")
    return {"index": index, "resumed": False, "ledger": _write_measurement(path, measurement)}


def _evaluate_rank_fields(
    fields: np.ndarray, truths: Sequence[int], low4_values: Sequence[int]
) -> dict[str, Any]:
    ranks = np.asarray(fields, dtype=np.int16)
    labels = np.asarray(truths, dtype=np.int16)
    if ranks.shape != (TARGETS, CELLS) or labels.shape != (TARGETS,):
        raise ValueError("A363 validation rank-field geometry differs")
    true_ranks = ranks[np.arange(TARGETS), labels].astype(np.int64)
    uniform = sum(math.log2(rank) for rank in range(1, CELLS + 1)) / CELLS
    logs = np.log2(true_ranks.astype(np.float64))
    half_gains = [float(uniform - logs[:HALF].mean()), float(uniform - logs[HALF:].mean())]
    offsets = np.arange(CELLS, dtype=np.int16)
    shifted_mean_logs = np.zeros(CELLS, dtype=np.float64)
    for target in range(TARGETS):
        shifted_mean_logs += np.log2(
            ranks[target, np.bitwise_xor(offsets, labels[target])].astype(np.float64)
        )
    shifted_mean_logs /= TARGETS
    observed_mean_log = float(logs.mean())
    global_ranks = [
        16 * (int(rank) - 1) + int(low4) + 1
        for rank, low4 in zip(true_ranks, low4_values, strict=True)
    ]
    return {
        "within_slice_ranks": true_ranks.tolist(),
        "within_slice_uniform_mean_log2_rank_reference": uniform,
        "within_slice_mean_log2_rank": observed_mean_log,
        "within_slice_mean_log2_rank_bit_gain": float(uniform - observed_mean_log),
        "fixed_half_bit_gains": half_gains,
        "stable_min_half_bit_gain": min(half_gains),
        "targets_at_or_above_median_rank_threshold": int(np.count_nonzero(true_ranks <= 128)),
        "shared_xor_offset_mean_log2_ranks": shifted_mean_logs.tolist(),
        "exact_shared_xor_p": float(
            np.count_nonzero(shifted_mean_logs <= observed_mean_log + 1e-15) / CELLS
        ),
        "best_shared_xor_offset": int(np.argmin(shifted_mean_logs)),
        "global_round_robin_group_ranks": global_ranks,
        "global_round_robin_geometric_mean_domain_reduction": float(
            4096 / math.exp(sum(math.log(rank) for rank in global_ranks) / TARGETS)
        ),
        "global_group_rank_formula": "16*(within_rank-1)+true_low4+1",
    }


def build_causal(payload: Mapping[str, Any]) -> dict[str, Any]:
    sys.path.insert(0, str(DOTCAUSAL_SRC))
    from dotcausal.io import CausalReader, CausalWriter

    source = "A362:frozen_polarity_invariant_primary"
    prepared = "A363:new_balanced_semantically_gated_targets"
    measured = "A363:complete_label_blind_candidate_fields"
    validated = "A363:zero_refit_primary_rank_panel"
    terminal = "A363:prospective_reader_gate"
    writer = CausalWriter(api_id="a363val")
    writer._rules = []
    rules = [
        (
            "frozen_reader_to_new_targets",
            "The A362 primary is immutable before the deterministic A363 rows are exported.",
            [source],
            prepared,
        ),
        (
            "new_targets_to_complete_fields",
            "Every target covers all 256 high8 cells before its high8 label or Reader is read.",
            [prepared],
            measured,
        ),
        (
            "complete_fields_to_zero_refit_panel",
            "The frozen absolute-rank L-infinity operator scores all complete fields without refit.",
            [measured],
            validated,
        ),
        (
            "rank_panel_to_gate",
            "Exact shared-XOR and fixed-half criteria decide A361 deployment eligibility.",
            [validated],
            terminal,
        ),
    ]
    for name, description, pattern, conclusion in rules:
        writer.add_rule(
            name=name,
            description=description,
            pattern=pattern,
            conclusion=conclusion,
            confidence_modifier=1.0,
        )
    triplets = [
        (
            source,
            "immutable_A362_selection_precedes_A363_manifest_and_formula_exports",
            prepared,
            A362_SELECTION_COMMITMENT_SHA256,
            payload["preparation_summary"],
            "frozen Reader plus new semantic gates",
        ),
        (
            prepared,
            "complete_numeric_256_cell_cover_without_label_reader_or_candidate_execution",
            measured,
            payload["measurement_sha256"],
            payload["measurement_summary"],
            "32 complete target-local covers",
        ),
        (
            measured,
            "absolute_primitive_ranks_plus_frozen_linf_intersection_without_refit",
            validated,
            payload["result_sha256"],
            payload["view_summary"],
            "prospective zero-refit rank panel",
        ),
        (
            validated,
            "predeclared_exact_shared_xor_fixed_half_and_median_rank_gate",
            terminal,
            payload["result_sha256"],
            payload["retention_gate"],
            payload["evidence_stage"],
        ),
    ]
    for trigger, mechanism, outcome, source_hash, quantification, evidence in triplets:
        writer.add_triplet(
            trigger=trigger,
            mechanism=mechanism,
            outcome=outcome,
            confidence=1.0,
            source=source_hash,
            quantification=json.dumps(quantification, sort_keys=True),
            evidence=evidence,
            domain="ChaCha20 R20 W46 prospective polarity-invariant validation",
            quality_score=1.0,
        )
    writer.add_triplet(
        trigger=source,
        mechanism="materialized_frozen_reader_new_corpus_validation_gate_chain",
        outcome=terminal,
        confidence=1.0,
        source="materialized:A363_validation_chain",
        quantification="exact retained closure",
        evidence=payload["evidence_stage"],
        domain="AI-native retained inference",
        quality_score=1.0,
        is_inferred=True,
    )
    writer.add_cluster(
        name="A363 prospective invariant Reader validation",
        entities=[source, prepared, measured, validated, terminal],
    )
    next_type = (
        "sealed_A361_full_direct12_order_and_W46_recovery"
        if payload["retention_gate"]["passed"]
        else "polarity_invariant_reader_mechanism_revision"
    )
    writer.add_gap(
        subject=terminal,
        predicate="next_required_object",
        expected_object_type=next_type,
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
        reader.api_id != "a363val"
        or len(explicit) != 4
        or len(all_rows) != 5
        or len(inferred) != 1
        or len(reader._rules) != 4
        or len(reader._clusters) != 1
        or len(reader._gaps) != 1
    ):
        raise RuntimeError("A363 authentic Causal reopen gate failed")
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
        raise FileExistsError("A363 result already exists")
    design = load_design()
    prepared = load_prepared(expected_prepared_sha256)
    a362 = A362.load_result(A362_RESULT_SHA256)
    primary_definition = a362["reader_selection"]["primary"]["definition"]
    best_single_definition = a362["reader_selection"]["best_single"]["definition"]
    borda_definition = a362["reader_selection"]["same_member_companions"]["borda"]["definition"]
    if (
        primary_definition["name"] != PRIMARY_NAME
        or primary_definition["member_feature_indices"] != list(PRIMARY_FEATURE_INDICES)
        or a362["selection_commitment_sha256"] != A362_SELECTION_COMMITMENT_SHA256
    ):
        raise RuntimeError("A363 A362 Reader identity differs")
    _a275, _model, _a291, indices, helper = A340.A296._reader_stack()  # noqa: SLF001
    WRAPPER._load_base_wrapper()  # noqa: SLF001
    if list(indices) != A340.FEATURE_INDICES:
        raise RuntimeError("A363 selected Reader feature identity differs")
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
            "corrected_reader_mapping_sha256": row["corrected_synthetic_reader_mapping_sha256"],
        }
        for row in prepared["rows"]
    ]
    MEASUREMENTS.mkdir(parents=True, exist_ok=True)
    started = time.perf_counter()
    completed = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=MEASUREMENT_WORKERS) as executor:
        futures = [
            executor.submit(
                _run_target,
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
        raise RuntimeError("A363 target measurement cover differs")
    measurements = [
        _read_measurement(
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
            raise RuntimeError(f"A363 target {source['index']} cell cover differs")
        stage_count += len(measurement["run"]["stages"])
        for cell in cells:
            status_counts[cell["final_status"]] += 1
        matrix = A360.target_normalize(A275._target_feature_matrix(measurement))  # noqa: SLF001
        matrices.append(matrix)
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
        raise RuntimeError("A363 status cover differs")
    primitive_fields = np.stack([A362.primitive_rank_fields(matrix) for matrix in matrices])
    view_fields = {
        "A362_primary_linf_intersection": np.stack(
            [
                A362.candidate_rank_field(primitive_fields[target], primary_definition)
                for target in range(TARGETS)
            ]
        ),
        "same_members_borda": np.stack(
            [
                A362.candidate_rank_field(primitive_fields[target], borda_definition)
                for target in range(TARGETS)
            ]
        ),
        "A362_best_single_abs_feature_085": np.stack(
            [
                A362.candidate_rank_field(primitive_fields[target], best_single_definition)
                for target in range(TARGETS)
            ]
        ),
        "numeric_control": np.tile(np.arange(1, CELLS + 1, dtype=np.int16), (TARGETS, 1)),
    }
    evaluations = {
        name: _evaluate_rank_fields(fields, truths, low4_values)
        for name, fields in view_fields.items()
    }
    primary = evaluations["A362_primary_linf_intersection"]
    gate_contract = design["reader_validation_contract"]["primary_gate"]
    passed = (
        primary["exact_shared_xor_p"] <= gate_contract["exact_shared_xor_p_maximum"]
        and primary["within_slice_mean_log2_rank_bit_gain"]
        > gate_contract["mean_log2_rank_bit_gain_minimum_exclusive"]
        and all(gain > 0.0 for gain in primary["fixed_half_bit_gains"])
        and primary["targets_at_or_above_median_rank_threshold"]
        >= gate_contract["targets_at_or_above_median_rank_threshold_minimum"]
    )
    retention_gate = {
        "passed": passed,
        "contract": gate_contract,
        "observed": {
            "exact_shared_xor_p": primary["exact_shared_xor_p"],
            "within_slice_mean_log2_rank_bit_gain": primary["within_slice_mean_log2_rank_bit_gain"],
            "fixed_half_bit_gains": primary["fixed_half_bit_gains"],
            "targets_at_or_above_median_rank_threshold": primary[
                "targets_at_or_above_median_rank_threshold"
            ],
        },
        "next_query": (
            "Apply the frozen A362 primary to all sixteen complete A361 slices, freeze the exact 4,096-group order, and execute it with the A324 W46 engine."
            if passed
            else "Use the complete A363 per-target rank fields to identify the remaining polarity-invariant boundary before any new deployment."
        ),
    }
    ledgers = [
        {**row["ledger"], "index": row["index"], "resumed": row["resumed"]} for row in completed
    ]
    scientific_ledgers = [
        {key: value for key, value in row.items() if key != "resumed"} for row in ledgers
    ]
    measurement_summary = {
        "targets": TARGETS,
        "validation_a_targets": HALF,
        "validation_b_targets": HALF,
        "cells_per_target": CELLS,
        "total_cells": TOTAL_CELLS,
        "solver_stages": stage_count,
        "status_counts": status_counts,
        "concurrent_workers": MEASUREMENT_WORKERS,
        "true_high8_labels_used_during_measurement": 0,
        "A362_reader_reads_during_measurement": 0,
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
    view_summary = {
        name: {
            "within_slice_mean_log2_rank_bit_gain": row["within_slice_mean_log2_rank_bit_gain"],
            "fixed_half_bit_gains": row["fixed_half_bit_gains"],
            "exact_shared_xor_p": row["exact_shared_xor_p"],
            "targets_at_or_above_median_rank_threshold": row[
                "targets_at_or_above_median_rank_threshold"
            ],
            "global_round_robin_geometric_mean_domain_reduction": row[
                "global_round_robin_geometric_mean_domain_reduction"
            ],
        }
        for name, row in evaluations.items()
    }
    measurement_sha = canonical_sha256(
        {"summary": measurement_summary, "ledger": scientific_ledgers}
    )
    payload: dict[str, Any] = {
        "schema": "chacha20-round20-w46-polarity-invariant-validation-a363-v1",
        "attempt_id": ATTEMPT_ID,
        "evidence_stage": (
            "PROSPECTIVE_NEW_CORPUS_POLARITY_INVARIANT_READER_RETAINED"
            if passed
            else "PROSPECTIVE_NEW_CORPUS_POLARITY_INVARIANT_BOUNDARY_RETAINED"
        ),
        "design_sha256": DESIGN_SHA256,
        "prepared_sha256": expected_prepared_sha256,
        "A362_result_sha256": A362_RESULT_SHA256,
        "A362_selection_commitment_sha256": A362_SELECTION_COMMITMENT_SHA256,
        "preparation_summary": preparation_summary,
        "measurement_summary": measurement_summary,
        "measurement_ledger": ledgers,
        "measurement_sha256": measurement_sha,
        "postclosure_labels": postclosure_labels,
        "view_evaluations": evaluations,
        "view_summary": view_summary,
        "retention_gate": retention_gate,
        "reader_refits_after_A362_selection_freeze": 0,
        "information_boundary": design["information_boundary"],
        "anchors": {
            "design": anchor(DESIGN, DESIGN_SHA256),
            "prepared": anchor(PREPARED, expected_prepared_sha256),
            "A362_result": anchor(A362_RESULT, A362_RESULT_SHA256),
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
            "A362_selection_commitment_sha256": A362_SELECTION_COMMITMENT_SHA256,
            "measurement_sha256": measurement_sha,
            "postclosure_labels": postclosure_labels,
            "view_evaluations": evaluations,
            "retention_gate": retention_gate,
            "reader_refits_after_A362_selection_freeze": 0,
            "information_boundary": payload["information_boundary"],
        }
    )
    payload["causal"] = build_causal(payload)
    atomic_json(RESULT, payload)
    atomic_bytes(
        REPORT,
        (
            "# A363 — prospective polarity-invariant Reader validation\n\n"
            f"Evidence stage: **{payload['evidence_stage']}**\n\n"
            f"- New validation targets / complete cells: **{TARGETS} / {TOTAL_CELLS:,}**\n"
            f"- Primary ranks: **{primary['within_slice_ranks']}**\n"
            f"- Primary half / all gains: **{primary['fixed_half_bit_gains']} / {primary['within_slice_mean_log2_rank_bit_gain']:.9f} bits**\n"
            f"- Exact shared-XOR p: **{primary['exact_shared_xor_p']:.9f}**\n"
            f"- At-or-above-median targets: **{primary['targets_at_or_above_median_rank_threshold']} / {TARGETS}**\n"
            f"- Global geometric domain reduction: **{primary['global_round_robin_geometric_mean_domain_reduction']:.9f}x**\n"
            f"- Retention gate: **{passed}**\n"
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
    else:
        payload = analyze()
    print(json.dumps(payload, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""A359: build a corrected-coordinate W46 known-key within-slice corpus."""

from __future__ import annotations

import argparse
import concurrent.futures
import hashlib
import importlib.util
import inspect
import json
import math
import os
import subprocess
import sys
import tempfile
import threading
import time
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

import zstandard

ROOT = Path(__file__).parents[2]
RESEARCH = ROOT / "research"
CONFIGS = RESEARCH / "configs"
RESULTS = RESEARCH / "results/v1"
ARTIFACTS = RESEARCH / "artifacts/a359_chacha20_r20_w46_corrected_knownkey_slices"
MEASUREMENTS = RESULTS / "chacha20_round20_w46_corrected_knownkey_slice_corpus_a359_v1"

DESIGN = CONFIGS / "chacha20_round20_w46_corrected_knownkey_slice_corpus_a359_design_v1.json"
IMPLEMENTATION = (
    CONFIGS / "chacha20_round20_w46_corrected_knownkey_slice_corpus_a359_implementation_v1.json"
)
PREPARED = RESULTS / "chacha20_round20_w46_corrected_knownkey_slice_corpus_a359_prepared_v1.json"
RESULT = RESULTS / "chacha20_round20_w46_corrected_knownkey_slice_corpus_a359_v1.json"
CAUSAL = RESULT.with_suffix(".causal")
REPORT = RESULTS / "chacha20_round20_w46_corrected_knownkey_slice_corpus_a359_v1.md"
TEST = ROOT / "tests/test_chacha20_round20_w46_corrected_knownkey_slice_corpus_a359.py"
REPRO = ROOT / "scripts/reproduce_chacha20_round20_w46_corrected_knownkey_slice_corpus_a359.sh"

A325_RUNNER = RESEARCH / "experiments/chacha20_round20_holdout_selected_w46_recovery_a325.py"
A355_RUNNER = RESEARCH / "experiments/chacha20_round20_w46_corrected_group_direct12_reader_a355.py"
A223_RUNNER = RESEARCH / "experiments/chacha20_round20_capacity_moonshot_a223.py"
A223_CONFIG = CONFIGS / "chacha20_round20_capacity_moonshot_a223_v1.json"
A354_RESULT = RESULTS / "chacha20_round20_w46_direct12_coordinate_codec_audit_a354_v1.json"

ATTEMPT_ID = "A359"
DESIGN_SHA256 = "8bbfc9853a9bcd2f42001411d1a46f722d7d8c0bf8038e95994ea3e414b7f7f9"
ROW_MANIFEST_SHA256 = "680fa9510ec8dc433bce2383ca3544da7dec56de57a75223830b6884e60fe8b1"
GENERATION_SEED = "A359|corrected-W46-known-key-slice-corpus|v1|2026-07-15"
WIDTH = 46
TARGETS = 32
SPLIT_TARGETS = 16
HIGH_BITS = 8
LOW_BITS = 4
CELLS_PER_TARGET = 1 << HIGH_BITS
TOTAL_CELLS = TARGETS * CELLS_PER_TARGET
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
        raise RuntimeError(f"cannot import A359 dependency {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


A355 = load_module(A355_RUNNER, "a359_a355")
A325 = load_module(A325_RUNNER, "a359_a325")
A223 = load_module(A223_RUNNER, "a359_a223")
A340 = A355.A348.A340
WRAPPER = A355.A348.WRAPPER

file_sha256 = A355.file_sha256
canonical_sha256 = A355.canonical_sha256
canonical_bytes = A355.canonical_bytes
atomic_json = A355.atomic_json
atomic_bytes = A355.atomic_bytes
relative = A355.relative
path_from_ref = A355.path_from_ref
anchor = A355.anchor
sha256 = A355.sha256


def generate_rows() -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for index in range(TARGETS):
        label = f"{GENERATION_SEED}|target-{index:02d}"
        assignment = (
            int.from_bytes(hashlib.shake_256(f"{label}|assignment".encode()).digest(8), "little")
            & MASK46
        )
        true_low4 = index % (1 << LOW_BITS)
        true_high8 = (19 + 73 * index) & 0xFF
        assignment = (assignment & ~(0xFFF << 20)) | (true_high8 << 24) | (true_low4 << 20)
        true_prefix12 = (true_high8 << LOW_BITS) | true_low4
        rows.append(
            {
                "assignment": assignment,
                "assignment_hex": f"{assignment:012x}",
                "index": index,
                "label": label,
                "split": "selection" if index < SPLIT_TARGETS else "holdout",
                "true_high8": true_high8,
                "true_low4": true_low4,
                "true_prefix12": true_prefix12,
                "true_prefix12_hex": f"{true_prefix12:03x}",
            }
        )
    if canonical_sha256(rows) != ROW_MANIFEST_SHA256:
        raise RuntimeError("A359 deterministic row-manifest commitment differs")
    return rows


def load_design() -> dict[str, Any]:
    if file_sha256(DESIGN) != DESIGN_SHA256:
        raise RuntimeError("A359 design hash differs")
    value = json.loads(DESIGN.read_bytes())
    corpus = value.get("corpus_contract", {})
    measurement = value.get("measurement_contract", {})
    boundary = value.get("information_boundary", {})
    gates = value.get("preparation_gates", {})
    if (
        value.get("schema") != "chacha20-round20-w46-corrected-knownkey-slice-corpus-a359-design-v1"
        or value.get("attempt_id") != ATTEMPT_ID
        or value.get("design_state")
        != "frozen_before_any_A359_target_formula_export_or_solver_measurement"
        or corpus.get("row_manifest_canonical_sha256") != ROW_MANIFEST_SHA256
        or corpus.get("targets") != TARGETS
        or corpus.get("selection_targets") != SPLIT_TARGETS
        or corpus.get("holdout_targets") != SPLIT_TARGETS
        or measurement.get("cells_per_target") != CELLS_PER_TARGET
        or measurement.get("total_cells") != TOTAL_CELLS
        or measurement.get("conflict_horizons") != HORIZONS
        or measurement.get("concurrent_export_workers") != EXPORT_WORKERS
        or measurement.get("concurrent_measurement_workers") != MEASUREMENT_WORKERS
        or measurement.get("mapping_exports_per_target") != 1 + math.ceil(math.log2(WIDTH))
        or measurement.get("mapping_exports_total") != TARGETS * (1 + math.ceil(math.log2(WIDTH)))
        or measurement.get("fixed_low4_coordinates_high_to_low") != list(LOW4_COORDINATES)
        or measurement.get("candidate_high8_coordinates_high_to_low") != list(HIGH8_COORDINATES)
        or measurement.get("synthetic_reader_mapping_source_indices")
        != list(SYNTHETIC_SOURCE_INDICES)
        or boundary.get("true_high8_label_used_to_add_CNF_units_or_change_candidate_order")
        is not False
        or boundary.get("true_high8_value_used_for_knownkey_output_generation") is not True
        or boundary.get("reader_refits_during_measurement") != 0
        or gates.get("coordinate_mapping_decoded_independently_for_every_target") is not True
        or gates.get("coordinate_mapping_literal_ids_may_be_target_specific") is not True
        or gates.get("coordinate_mapping_must_be_bijective_for_every_target") is not True
        or gates.get("coordinate_semantics_must_match_A354_source_indices") is not True
        or gates.get("true_known_assignment_must_be_SAT_for_every_target") is not True
        or gates.get("one_bit_flip_of_known_assignment_must_be_UNSAT_for_every_target") is not True
    ):
        raise RuntimeError("A359 frozen design semantics differ")
    sources = value["source_anchors"]
    for name, path_value in sources.items():
        if name.endswith("_path"):
            stem = name.removesuffix("_path")
            anchor(ROOT / path_value, sources[f"{stem}_sha256"])
    generate_rows()
    return value


def freeze_implementation() -> dict[str, Any]:
    if IMPLEMENTATION.exists():
        raise FileExistsError("A359 implementation already exists")
    if any(path.exists() for path in (ARTIFACTS, MEASUREMENTS, PREPARED, RESULT, CAUSAL, REPORT)):
        raise RuntimeError("A359 implementation must precede every preparation and measurement")
    load_design()
    if not TEST.exists() or not REPRO.exists():
        raise FileNotFoundError("A359 test and reproducer must exist before freeze")
    payload: dict[str, Any] = {
        "schema": "chacha20-round20-w46-corrected-knownkey-slice-corpus-a359-implementation-v1",
        "attempt_id": ATTEMPT_ID,
        "commitment_state": "frozen_before_any_A359_formula_export_or_solver_measurement",
        "design_sha256": DESIGN_SHA256,
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
        raise RuntimeError("A359 implementation artifact hash differs")
    value = json.loads(IMPLEMENTATION.read_bytes())
    if (
        value.get("schema")
        != "chacha20-round20-w46-corrected-knownkey-slice-corpus-a359-implementation-v1"
        or value.get("attempt_id") != ATTEMPT_ID
        or value.get("commitment_state")
        != "frozen_before_any_A359_formula_export_or_solver_measurement"
        or value.get("design_sha256") != DESIGN_SHA256
    ):
        raise RuntimeError("A359 implementation semantics differ")
    expected = {"design": DESIGN, "runner": Path(__file__), "test": TEST, "reproducer": REPRO}
    for name, path in expected.items():
        row = value.get("anchors", {}).get(name, {})
        if row.get("path") != relative(path) or row.get("sha256") != file_sha256(path):
            raise RuntimeError(f"A359 implementation anchor differs: {name}")
    unsigned = {
        key: item for key, item in value.items() if key != "implementation_commitment_sha256"
    }
    if value.get("implementation_commitment_sha256") != canonical_sha256(unsigned):
        raise RuntimeError("A359 implementation commitment differs")
    return value


def assignment_unit_literals(assignment: int, source_mapping: Sequence[int]) -> list[int]:
    if not 0 <= assignment <= MASK46 or len(source_mapping) != WIDTH:
        raise ValueError("A359 assignment or source mapping differs")
    units = [
        int(one_literal) if (assignment >> bit) & 1 else -int(one_literal)
        for bit, one_literal in enumerate(source_mapping)
    ]
    if len({abs(value) for value in units}) != WIDTH:
        raise RuntimeError("A359 assignment unit variables alias")
    return units


def render_assignment_cnf(
    base_raw: bytes, *, assignment: int, source_mapping: Sequence[int]
) -> bytes:
    variables, clauses, body = A355.A348._base_cnf_parts(base_raw)  # noqa: SLF001
    units = assignment_unit_literals(assignment, source_mapping)
    suffix = b"".join(f"{literal} 0\n".encode("ascii") for literal in units)
    return f"p cnf {variables} {clauses + len(units)}\n".encode() + body + suffix


def a359_bridge_challenge(challenge: Mapping[str, Any]) -> dict[str, Any]:
    bridge = A340.bridge_challenge({"public_challenge": challenge})
    bridge["generation_entropy_source"] = "deterministic_SHAKE256_A359_knownkey_corpus_v1"
    bridge["secret_discarded_after_target_construction"] = False
    bridge["known_assignment_retained_outside_public_bridge"] = True
    return bridge


def validate_a359_bridge(bridge: Mapping[str, Any]) -> None:
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
        or bridge.get("unknown_assignment_value_included") is not False
        or bridge.get("full_key_included") is not False
        or bridge.get("generation_entropy_source")
        != "deterministic_SHAKE256_A359_knownkey_corpus_v1"
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
        raise RuntimeError("A359 deterministic known-key bridge structural gate failed")
    for block, digest in zip(targets, hashes, strict=True):
        if sha256(A223.P1._word_bytes(block)) != digest:  # noqa: SLF001
            raise RuntimeError("A359 deterministic known-key target fingerprint differs")
    if sha256(A223.P1._word_bytes(control)) != bridge["control_target_block_sha256"]:  # noqa: SLF001
        raise RuntimeError("A359 deterministic known-key control fingerprint differs")


def a359_w46_source_formula(bridge: dict[str, Any]) -> str:
    # A296 temporarily changes A223.BLOCK_COUNT while emitting a one-block
    # formula.  Serialize only that short mutation; Bitwuzla exports remain
    # parallel and the global is checked after every call.
    with FORMULA_LOCK:
        original = int(A223.BLOCK_COUNT)
        formula = A340.w46_source_formula(A223, bridge)
        if A223.BLOCK_COUNT != original:
            raise RuntimeError("A359 A223 block-count restoration gate failed")
        return formula


def _cadical_status(path: Path) -> dict[str, Any]:
    command = [str(CADICAL), "-q", "-n", "-t", "30", str(path)]
    started = time.perf_counter()
    result = subprocess.run(command, text=True, capture_output=True, timeout=40, check=False)
    status_by_returncode = {10: "SAT", 20: "UNSAT"}
    if result.returncode not in status_by_returncode:
        raise RuntimeError(
            f"A359 CaDiCaL semantic gate failed: rc={result.returncode}, "
            f"stdout={result.stdout[:200]!r}, stderr={result.stderr[:200]!r}"
        )
    return {
        "status": status_by_returncode[result.returncode],
        "returncode": result.returncode,
        "command_sha256": canonical_sha256(command[:-1]),
        "stdout_sha256": sha256(result.stdout.encode()),
        "stderr_sha256": sha256(result.stderr.encode()),
        "volatile_seconds": time.perf_counter() - started,
    }


def _export_target(
    row: Mapping[str, Any], *, stage: Path, config: Mapping[str, Any]
) -> dict[str, Any]:
    target_dir = stage / f"target_{int(row['index']):02d}"
    target_dir.mkdir(parents=True, exist_ok=False)
    challenge = A325.challenge_from_assignment(
        label=str(row["label"]), assignment=int(row["assignment"])
    )
    A325.validate_challenge(challenge)
    bridge = a359_bridge_challenge(challenge)
    validate_a359_bridge(bridge)
    formula = a359_w46_source_formula(bridge)
    base = target_dir / "base.cnf"
    export = A223._export_cnf(  # noqa: SLF001
        formula=formula,
        output=base,
        config=dict(config),
        label=f"A359_W46_TARGET_{int(row['index']):02d}_B1",
    )
    lines = base.read_bytes().splitlines(keepends=True)
    header = lines[0].split() if lines else []
    if len(header) != 4 or header[:2] != [b"p", b"cnf"]:
        raise RuntimeError(f"A359 target {row['index']} base CNF header differs")
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
    bridge = a359_bridge_challenge(challenge)
    validate_a359_bridge(bridge)
    formula = a359_w46_source_formula(bridge)
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


def _semantic_and_slice(
    row: Mapping[str, Any], *, stage: Path, source_mapping: Sequence[int]
) -> dict[str, Any]:
    index = int(row["index"])
    target_dir = stage / f"target_{index:02d}"
    base = target_dir / "base.cnf"
    raw = base.read_bytes()
    true_path = target_dir / ".semantic_true.cnf"
    flip_path = target_dir / ".semantic_flip.cnf"
    assignment = int(row["assignment"])
    flip_bit = (5 + 17 * index) % WIDTH
    atomic_bytes(
        true_path,
        render_assignment_cnf(raw, assignment=assignment, source_mapping=source_mapping),
    )
    atomic_bytes(
        flip_path,
        render_assignment_cnf(
            raw, assignment=assignment ^ (1 << flip_bit), source_mapping=source_mapping
        ),
    )
    true_gate = _cadical_status(true_path)
    flip_gate = _cadical_status(flip_path)
    true_path.unlink(missing_ok=True)
    flip_path.unlink(missing_ok=True)
    if true_gate["status"] != "SAT" or flip_gate["status"] != "UNSAT":
        raise RuntimeError(f"A359 target {index} semantic mapping gate differs")
    slice_path = target_dir / "slice.cnf"
    slice_raw = A355.render_slice_cnf(
        raw, low4=int(row["true_low4"]), source_mapping=source_mapping
    )
    atomic_bytes(slice_path, slice_raw)
    return {
        "index": index,
        "flip_bit": flip_bit,
        "true_assignment_gate": true_gate,
        "one_bit_flip_gate": flip_gate,
        "slice_sha256": sha256(slice_raw),
        "slice_bytes": len(slice_raw),
    }


def _without_volatile(value: Any) -> Any:
    if isinstance(value, dict):
        return {
            key: _without_volatile(item)
            for key, item in value.items()
            if not key.startswith("volatile_") and key not in {"volatile_seconds", "command_sha256"}
        }
    if isinstance(value, list):
        return [_without_volatile(item) for item in value]
    return value


def prepare(*, expected_implementation_sha256: str) -> dict[str, Any]:
    if any(path.exists() for path in (ARTIFACTS, PREPARED, MEASUREMENTS, RESULT, CAUSAL, REPORT)):
        raise FileExistsError("A359 preparation or measurement artifacts already exist")
    design = load_design()
    implementation = load_implementation(expected_implementation_sha256)
    rows = generate_rows()
    config = json.loads(A223_CONFIG.read_bytes())
    A223._toolchain_gates(config)  # noqa: SLF001
    if not CADICAL.is_file():
        raise FileNotFoundError("A359 CaDiCaL CLI is unavailable")
    started = time.perf_counter()
    ARTIFACTS.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="a359_prepare_", dir=ARTIFACTS.parent) as temporary:
        stage = Path(temporary) / ARTIFACTS.name
        stage.mkdir(parents=False, exist_ok=False)
        with concurrent.futures.ThreadPoolExecutor(max_workers=EXPORT_WORKERS) as executor:
            exports = list(
                executor.map(lambda row: _export_target(row, stage=stage, config=config), rows)
            )
        exports.sort(key=lambda row: row["index"])
        if [row["index"] for row in exports] != list(range(TARGETS)):
            raise RuntimeError("A359 target export cover differs")

        with concurrent.futures.ThreadPoolExecutor(max_workers=EXPORT_WORKERS) as executor:
            mappings = list(
                executor.map(
                    lambda pair: _mapping_for(pair[0], pair[1], stage=stage, config=config),
                    zip(rows, exports, strict=True),
                )
            )
        mappings.sort(key=lambda row: row["index"])
        if [row["index"] for row in mappings] != list(range(TARGETS)):
            raise RuntimeError("A359 per-target coordinate mapping cover differs")
        correction = json.loads(A354_RESULT.read_bytes())["corrected_successor_contract"]
        if (
            correction["synthetic_reader_mapping_source_indices"] != list(SYNTHETIC_SOURCE_INDICES)
            or correction["low4_fixed_unit_coordinates_high_to_low"] != list(LOW4_COORDINATES)
            or correction["high8_assumption_coordinates_high_to_low"] != list(HIGH8_COORDINATES)
        ):
            raise RuntimeError("A359 A354 corrected coordinate semantics differ")
        for mapping in mappings:
            source_mapping = mapping["source_one_literals_bit0_upward"]
            if (
                len(source_mapping) != WIDTH
                or len({abs(value) for value in source_mapping}) != WIDTH
            ):
                raise RuntimeError(
                    f"A359 target {mapping['index']} source mapping is not bijective"
                )
            corrected_mapping = A355.corrected_synthetic_mapping(source_mapping)
            mapping["corrected_synthetic_reader_mapping"] = corrected_mapping
            mapping["corrected_synthetic_reader_mapping_sha256"] = canonical_sha256(
                corrected_mapping
            )

        with concurrent.futures.ThreadPoolExecutor(max_workers=EXPORT_WORKERS) as executor:
            semantics = list(
                executor.map(
                    lambda pair: _semantic_and_slice(
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
        "source_mapping_sha256_by_target": [
            mapping["source_mapping_sha256"] for mapping in mappings
        ],
        "corrected_mapping_sha256_by_target": [
            mapping["corrected_synthetic_reader_mapping_sha256"] for mapping in mappings
        ],
        "unique_source_mapping_hashes": len(
            {mapping["source_mapping_sha256"] for mapping in mappings}
        ),
        "literal_ids_allowed_to_be_target_specific": True,
        "all_target_mappings_decoded": True,
        "all_target_mappings_bijective": True,
        "A354_synthetic_reader_mapping_source_indices": list(SYNTHETIC_SOURCE_INDICES),
        "matches_A354_corrected_coordinate_semantics": True,
    }
    scientific_rows = _without_volatile(prepared_rows)
    payload: dict[str, Any] = {
        "schema": "chacha20-round20-w46-corrected-knownkey-slice-corpus-a359-prepared-v1",
        "attempt_id": ATTEMPT_ID,
        "evidence_stage": "CORRECTED_COORDINATE_KNOWNKEY_CORPUS_PREPARED_BEFORE_MEASUREMENT",
        "design_sha256": DESIGN_SHA256,
        "implementation_sha256": expected_implementation_sha256,
        "implementation_commitment_sha256": implementation["implementation_commitment_sha256"],
        "row_manifest_canonical_sha256": ROW_MANIFEST_SHA256,
        "mapping_contract": mapping_contract,
        "rows": prepared_rows,
        "selection_targets": SPLIT_TARGETS,
        "holdout_targets": SPLIT_TARGETS,
        "solver_measurement_started": False,
        "preparation_commitment_sha256": canonical_sha256(
            {
                "design_sha256": DESIGN_SHA256,
                "row_manifest_canonical_sha256": ROW_MANIFEST_SHA256,
                "mapping_contract": mapping_contract,
                "rows": scientific_rows,
                "solver_measurement_started": False,
            }
        ),
        "information_boundary": design["information_boundary"],
        "anchors": {
            "design": anchor(DESIGN, DESIGN_SHA256),
            "implementation": anchor(IMPLEMENTATION, expected_implementation_sha256),
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
        raise RuntimeError("A359 prepared manifest hash differs")
    value = json.loads(PREPARED.read_bytes())
    if (
        value.get("schema")
        != "chacha20-round20-w46-corrected-knownkey-slice-corpus-a359-prepared-v1"
        or value.get("attempt_id") != ATTEMPT_ID
        or value.get("design_sha256") != DESIGN_SHA256
        or value.get("row_manifest_canonical_sha256") != ROW_MANIFEST_SHA256
        or value.get("solver_measurement_started") is not False
        or len(value.get("rows", [])) != TARGETS
        or value.get("mapping_contract", {}).get("all_target_mappings_decoded") is not True
        or value.get("mapping_contract", {}).get("all_target_mappings_bijective") is not True
    ):
        raise RuntimeError("A359 prepared manifest semantics differ")
    expected_rows = generate_rows()
    for expected, row in zip(expected_rows, value["rows"], strict=True):
        if any(row.get(key) != expected[key] for key in expected):
            raise RuntimeError(f"A359 prepared row identity differs: {expected['index']}")
        source_mapping = [int(value) for value in row["source_one_literals_bit0_upward"]]
        corrected_mapping = [int(value) for value in row["corrected_synthetic_reader_mapping"]]
        if (
            len(source_mapping) != WIDTH
            or len({abs(value) for value in source_mapping}) != WIDTH
            or row["source_mapping_sha256"] != canonical_sha256(source_mapping)
            or corrected_mapping != A355.corrected_synthetic_mapping(source_mapping)
            or row["corrected_synthetic_reader_mapping_sha256"]
            != canonical_sha256(corrected_mapping)
        ):
            raise RuntimeError(f"A359 prepared target mapping differs: {expected['index']}")
        for name in ("public_challenge", "base_CNF", "slice_CNF"):
            artifact = row[name]
            anchor(path_from_ref(artifact["path"]), artifact["sha256"])
    for name, artifact in value["anchors"].items():
        if name != "cadical":
            anchor(path_from_ref(artifact["path"]), artifact["sha256"])
        else:
            anchor(Path(artifact["path"]), artifact["sha256"])
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
        raise RuntimeError("A359 compressed measurement hash differs")
    raw = zstandard.ZstdDecompressor().decompress(compressed)
    if ledger is not None and sha256(raw) != ledger["raw_sha256"]:
        raise RuntimeError("A359 raw measurement hash differs")
    value = json.loads(raw)
    run = value.get("run", {})
    cells = run.get("cells", [])
    if (
        value.get("schema") != "chacha20-round20-w46-corrected-knownkey-slice-corpus-a359-shard-v1"
        or value.get("attempt_id") != ATTEMPT_ID
        or value.get("prepared_sha256") != expected_prepared_sha256
        or value.get("complete_candidate_cover") is not True
        or value.get("true_high8_available_during_measurement") is not False
        or len(cells) != CELLS_PER_TARGET
        or [int(cell.get("cell_index", -1)) for cell in cells] != list(range(CELLS_PER_TARGET))
        or not 1 <= len(run.get("stages", [])) <= CELLS_PER_TARGET * len(HORIZONS)
        or run.get("all_watchdogs_clear") is not True
        or value.get("candidate_order") != "numeric_0_through_255"
        or value.get("reader_refits") != 0
        or canonical_bytes(value) != raw
    ):
        raise RuntimeError(f"A359 measurement shard gate failed: {path.name}")
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
        raise RuntimeError(f"A359 target {index} Reader mapping gate differs")
    path = _measurement_path(index)
    if path.exists():
        value = _read_measurement(path, expected_prepared_sha256=prepared_sha256)
        if (
            value["label"] != job["label"]
            or value["true_low4"] != job["true_low4"]
            or value["corrected_reader_mapping_sha256"] != job["corrected_reader_mapping_sha256"]
        ):
            raise RuntimeError(f"A359 resumed target identity differs: {index}")
        return {"index": index, "resumed": True, "ledger": _write_measurement(path, value)}
    started = time.perf_counter()
    raw_run = WRAPPER.run_fresh_clause_identity(
        helper=helper,
        cnf=path_from_ref(str(job["slice_CNF_path"])),
        mode=f"A359_W46_knownkey_slice_target_{index:02d}",
        order=[f"{value:08b}" for value in range(CELLS_PER_TARGET)],
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
        "schema": "chacha20-round20-w46-corrected-knownkey-slice-corpus-a359-shard-v1",
        "attempt_id": ATTEMPT_ID,
        "prepared_sha256": prepared_sha256,
        "index": index,
        "label": str(job["label"]),
        "split": str(job["split"]),
        "true_low4": int(job["true_low4"]),
        "slice_CNF_sha256": str(job["slice_CNF_sha256"]),
        "corrected_reader_mapping_sha256": str(job["corrected_reader_mapping_sha256"]),
        "run": stable,
        "complete_candidate_cover": len(stable.get("cells", [])) == CELLS_PER_TARGET,
        "candidate_order": "numeric_0_through_255",
        "true_high8_available_during_measurement": False,
        "true_high8_used_for_candidate_order_or_early_stop": False,
        "reader_refits": 0,
        "volatile_process_elapsed_seconds": time.perf_counter() - started,
    }
    if (
        measurement["complete_candidate_cover"] is not True
        or stable.get("all_watchdogs_clear") is not True
        or len(stable.get("stages", [])) < 1
    ):
        raise RuntimeError(f"A359 target measurement gate failed: {index}")
    return {"index": index, "resumed": False, "ledger": _write_measurement(path, measurement)}


def build_causal(payload: Mapping[str, Any]) -> dict[str, Any]:
    sys.path.insert(0, str(DOTCAUSAL_SRC))
    from dotcausal.io import CausalReader, CausalWriter

    source = "A359:deterministic_balanced_knownkey_manifest"
    prepared = "A359:prepared_corrected_coordinate_targets"
    measured = "A359:complete_within_slice_measurement_corpus"
    terminal = "A359:selection_holdout_reader_corpus_ready"
    writer = CausalWriter(api_id="a359corp")
    writer._rules = []
    writer.add_rule(
        name="balanced_manifest_to_corrected_targets",
        description="The deterministic 32-target manifest creates disjoint, low4-balanced selection and holdout targets under the exact corrected Metal coordinate contract.",
        pattern=[source],
        conclusion=prepared,
        confidence_modifier=1.0,
    )
    writer.add_rule(
        name="corrected_targets_to_complete_measurements",
        description="Every target fixes only its declared low4 slice and covers every high8 candidate before its high8 label enters readout.",
        pattern=[prepared],
        conclusion=measured,
        confidence_modifier=1.0,
    )
    writer.add_rule(
        name="complete_measurements_to_reader_corpus",
        description="Complete selection and holdout shards expose a zero-refit training and prospective validation substrate for A360.",
        pattern=[measured],
        conclusion=terminal,
        confidence_modifier=1.0,
    )
    writer.add_triplet(
        trigger=source,
        mechanism="deterministic_fullround_challenge_generation_plus_exact_per_target_coordinate_decode",
        outcome=prepared,
        confidence=1.0,
        source=payload["prepared_sha256"],
        quantification=json.dumps(payload["preparation_summary"], sort_keys=True),
        evidence="32 semantic SAT gates and 32 one-bit-flip UNSAT controls",
        domain="ChaCha20 R20 W46 corrected-coordinate known-key corpus",
        quality_score=1.0,
    )
    writer.add_triplet(
        trigger=prepared,
        mechanism="fixed_true_low4_slice_cross_complete_numeric_high8_cover",
        outcome=measured,
        confidence=1.0,
        source=payload["measurement_sha256"],
        quantification=json.dumps(payload["measurement_summary"], sort_keys=True),
        evidence="complete target-local candidate cover before high8 label readback",
        domain="Full-round solver-trajectory measurement",
        quality_score=1.0,
    )
    writer.add_triplet(
        trigger=measured,
        mechanism="disjoint_selection_holdout_partition_with_postclosure_labels",
        outcome=terminal,
        confidence=1.0,
        source=payload["result_sha256"],
        quantification=json.dumps(payload["postclosure_label_summary"], sort_keys=True),
        evidence=payload["evidence_stage"],
        domain="Prospective Reader learning substrate",
        quality_score=1.0,
    )
    writer.add_triplet(
        trigger=source,
        mechanism="materialized_balanced_manifest_measurement_validation_chain",
        outcome=terminal,
        confidence=1.0,
        source="materialized:A359_corrected_knownkey_corpus_chain",
        quantification="exact retained closure",
        evidence=payload["evidence_stage"],
        domain="AI-native retained inference",
        quality_score=1.0,
        is_inferred=True,
    )
    writer.add_cluster(
        name="A359 corrected known-key corpus", entities=[source, prepared, measured, terminal]
    )
    writer.add_gap(
        subject=terminal,
        predicate="next_required_object",
        expected_object_type="frozen_selection_trained_holdout_validated_within_slice_reader",
        confidence=1.0,
        suggested_queries=[
            "Train diverse high8 Readers on the sixteen selection targets and evaluate without refit on the sixteen holdout targets."
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
        reader.api_id != "a359corp"
        or len(explicit) != 3
        or len(all_rows) != 4
        or len(inferred) != 1
        or len(reader._rules) != 3
        or len(reader._clusters) != 1
        or len(reader._gaps) != 1
    ):
        raise RuntimeError("A359 authentic Causal reopen gate failed")
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


def measure(*, expected_prepared_sha256: str) -> dict[str, Any]:
    if any(path.exists() for path in (RESULT, CAUSAL, REPORT)):
        raise FileExistsError("A359 result already exists")
    design = load_design()
    prepared = load_prepared(expected_prepared_sha256)
    _a275, _model, _a291, indices, helper = A340.A296._reader_stack()  # noqa: SLF001
    WRAPPER._load_base_wrapper()  # noqa: SLF001
    if list(indices) != A340.FEATURE_INDICES:
        raise RuntimeError("A359 selected Reader feature identity differs")
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
        raise RuntimeError("A359 target measurement cover differs")

    measurements = [
        _read_measurement(
            path_from_ref(row["ledger"]["path"]),
            expected_prepared_sha256=expected_prepared_sha256,
            ledger=row["ledger"],
        )
        for row in completed
    ]
    status_counts = {status: 0 for status in ("sat", "unknown", "unsat")}
    stage_count = 0
    postclosure_labels = []
    source_rows = generate_rows()
    for source, measurement in zip(source_rows, measurements, strict=True):
        cells = measurement["run"]["cells"]
        cells_by_index = {int(cell["cell_index"]): cell for cell in cells}
        if set(cells_by_index) != set(range(CELLS_PER_TARGET)):
            raise RuntimeError(f"A359 target {source['index']} cell identity cover differs")
        stage_count += len(measurement["run"]["stages"])
        for cell in cells:
            status_counts[cell["final_status"]] += 1
        truth = int(source["true_high8"])
        postclosure_labels.append(
            {
                "index": source["index"],
                "split": source["split"],
                "true_low4": source["true_low4"],
                "true_high8": truth,
                "true_prefix12": source["true_prefix12"],
                "true_cell_final_status": cells_by_index[truth]["final_status"],
                "label_revealed_after_complete_target_cover": True,
            }
        )
    if sum(status_counts.values()) != TOTAL_CELLS:
        raise RuntimeError("A359 status cover differs")
    ledgers = [
        {**row["ledger"], "index": row["index"], "resumed": row["resumed"]} for row in completed
    ]
    scientific_ledgers = [
        {key: value for key, value in row.items() if key != "resumed"} for row in ledgers
    ]
    measurement_summary = {
        "targets": TARGETS,
        "selection_targets": SPLIT_TARGETS,
        "holdout_targets": SPLIT_TARGETS,
        "cells_per_target": CELLS_PER_TARGET,
        "total_cells": TOTAL_CELLS,
        "solver_stages": stage_count,
        "status_counts": status_counts,
        "concurrent_workers": MEASUREMENT_WORKERS,
        "true_high8_labels_used_during_measurement": 0,
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
        "per_target_mapping_used_for_slice_and_reader": True,
        "corrected_coordinate_interval": [20, 31],
    }
    postclosure_label_summary = {
        "selection_low4_cover": sorted(
            row["true_low4"] for row in postclosure_labels if row["split"] == "selection"
        ),
        "holdout_low4_cover": sorted(
            row["true_low4"] for row in postclosure_labels if row["split"] == "holdout"
        ),
        "unique_high8_labels": len({row["true_high8"] for row in postclosure_labels}),
        "labels_revealed_only_after_target_local_complete_cover": True,
    }
    payload: dict[str, Any] = {
        "schema": "chacha20-round20-w46-corrected-knownkey-slice-corpus-a359-v1",
        "attempt_id": ATTEMPT_ID,
        "evidence_stage": "CORRECTED_COORDINATE_KNOWNKEY_SELECTION_HOLDOUT_CORPUS_RETAINED",
        "design_sha256": DESIGN_SHA256,
        "prepared_sha256": expected_prepared_sha256,
        "preparation_summary": preparation_summary,
        "measurement_summary": measurement_summary,
        "measurement_ledger": ledgers,
        "measurement_sha256": canonical_sha256(
            {"summary": measurement_summary, "ledger": scientific_ledgers}
        ),
        "postclosure_labels": postclosure_labels,
        "postclosure_label_summary": postclosure_label_summary,
        "information_boundary": design["information_boundary"],
        "anchors": {
            "design": anchor(DESIGN, DESIGN_SHA256),
            "prepared": anchor(PREPARED, expected_prepared_sha256),
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
            "preparation_summary": preparation_summary,
            "measurement_sha256": payload["measurement_sha256"],
            "postclosure_labels": postclosure_labels,
            "postclosure_label_summary": postclosure_label_summary,
            "information_boundary": payload["information_boundary"],
        }
    )
    payload["causal"] = build_causal(payload)
    atomic_json(RESULT, payload)
    atomic_bytes(
        REPORT,
        (
            "# A359 — corrected-coordinate W46 known-key slice corpus\n\n"
            f"Evidence stage: **{payload['evidence_stage']}**\n\n"
            f"- Selection / holdout targets: **{SPLIT_TARGETS} / {SPLIT_TARGETS}**\n"
            f"- Complete cells / solver stages: **{TOTAL_CELLS:,} / {stage_count:,}**\n"
            f"- Status counts: **{status_counts}**\n"
            "- Coordinate mapping: **32 independent exact decodes / 224 mapping exports**\n"
            "- Semantic preparation gates: **32 true SAT / 32 one-bit-flip UNSAT**\n"
            "- Low4 coverage: **0..15 exactly once per split**\n"
            "- High8 labels: **32 unique; withheld until complete target-local cover**\n"
            "- Candidate assignments / Reader refits during measurement: **0 / 0**\n"
            "- Authentic AI-native Causal readback: **3 explicit + 1 inferred**\n"
            "- Next gate: **A360 selection-trained, zero-refit holdout Reader**\n"
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
    action.add_argument("--measure", action="store_true")
    parser.add_argument("--expected-implementation-sha256")
    parser.add_argument("--expected-prepared-sha256")
    args = parser.parse_args()
    if args.freeze_implementation:
        payload = freeze_implementation()
    elif args.prepare:
        if not args.expected_implementation_sha256:
            parser.error("--prepare requires --expected-implementation-sha256")
        payload = prepare(expected_implementation_sha256=args.expected_implementation_sha256)
    elif args.measure:
        if not args.expected_prepared_sha256:
            parser.error("--measure requires --expected-prepared-sha256")
        payload = measure(expected_prepared_sha256=args.expected_prepared_sha256)
    else:
        payload = analyze()
    print(json.dumps(payload, indent=2, sort_keys=True), flush=True)


if __name__ == "__main__":
    main()

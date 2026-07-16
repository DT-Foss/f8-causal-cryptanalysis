#!/usr/bin/env python3
"""A401: learn and hold out a W50 Direct12 rank-fusion Reader."""

from __future__ import annotations

import argparse
import concurrent.futures
import hashlib
import importlib.util
import inspect
import json
import math
import os
import statistics
import sys
import tempfile
import time
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

import numpy as np

ROOT = Path(__file__).parents[2]
RESEARCH = ROOT / "research"
CONFIGS = RESEARCH / "configs"
RESULTS = RESEARCH / "results/v1"
ARTIFACTS = RESEARCH / "artifacts/a401_chacha20_r20_w50_knownkey_direct12"
MEASUREMENTS = RESULTS / "chacha20_round20_w50_knownkey_direct12_learning_a401_v1"

DESIGN = CONFIGS / "chacha20_round20_w50_knownkey_direct12_learning_a401_design_v1.json"
IMPLEMENTATION = (
    CONFIGS / "chacha20_round20_w50_knownkey_direct12_learning_a401_implementation_v1.json"
)
PROTOCOL = CONFIGS / "chacha20_round20_w50_knownkey_direct12_learning_a401_public_corpus_v1.json"
TRAIN_LABELS = (
    CONFIGS / "chacha20_round20_w50_knownkey_direct12_learning_a401_selection_labels_v1.json"
)
HOLDOUT_LABELS = (
    CONFIGS / "chacha20_round20_w50_knownkey_direct12_learning_a401_holdout_labels_v1.json"
)
SELECTION = CONFIGS / "chacha20_round20_w50_knownkey_direct12_learning_a401_selection_v1.json"
PROGRESS = RESULTS / "chacha20_round20_w50_knownkey_direct12_learning_a401_progress_v1.json"
RESULT = RESULTS / "chacha20_round20_w50_knownkey_direct12_learning_a401_v1.json"
CAUSAL = RESULT.with_suffix(".causal")
REPORT = RESULT.with_suffix(".md")
TEST = ROOT / "tests/test_chacha20_round20_w50_knownkey_direct12_learning_a401.py"
REPRO = ROOT / "scripts/reproduce_chacha20_round20_w50_knownkey_direct12_learning_a401.sh"

A388_RUNNER = RESEARCH / "experiments/chacha20_round20_w50_public_output_direct12_factor3_a388.py"
A388_PREFLIGHT = (
    RESULTS / "chacha20_round20_w50_public_output_direct12_factor3_a388_preflight_v1.json"
)
A385_RUNNER = RESEARCH / "experiments/chacha20_round20_fresh_w50_pretarget_transfer_a385.py"
A400_RESULT = RESULTS / "chacha20_round20_w50_direct12_transfer_diversity_schedule_a400_v1.json"

ATTEMPT_ID = "A401"
DESIGN_SHA256 = "bb8127e6d2fbe5c99a38847ab16e2a97a79168781bcecb0b14bef93fc958aa7c"
A388_RUNNER_SHA256 = "36c933ae5003f92f2b96efb2e30d97c30bf8301bfcaa790333a6712f3041b5a9"
A388_PREFLIGHT_SHA256 = "6919b9071b5c9de85f050a7921d4a82fa0e55db6e02ca531590afdfdc57cc115"
A385_RUNNER_SHA256 = "b6827f779a8a7997bbee6c04a6a28f9f3c5ec5718ac942b0171c8b4174a928f3"
A400_RESULT_SHA256 = "1d4ca3f053ce566fad4808751767c1549aa6d6625dced16bd65d13d6d97c2215"

VIEW_NAMES = (
    "A340_selected8_global_raw",
    "A340_selected8_slice_z",
    "A341_selected_single_global_raw",
    "A341_selected_single_slice_z",
    "A342_selected_pair_global_raw",
    "A342_selected_pair_slice_z",
    "A342_selected_triple_global_raw",
    "A342_selected_triple_slice_z",
)
AGGREGATORS = ("borda_sum", "reciprocal_rank_sum", "minimum_rank_then_sum")
TARGETS = tuple(range(16))
TRAIN_TARGETS = tuple(range(8))
HOLDOUT_TARGETS = tuple(range(8, 16))
CELLS = 4096
SLICES = tuple(range(16))
WIDTH = 50
MASK50 = (1 << WIDTH) - 1
DEFAULT_SLICE_WORKERS = 8
DOTCAUSAL_SRC = Path("/Users/bhkmie/Documents/Forschung/O1/vendor/fabel/dotcausal_package/src")


def load_module(path: Path, name: str) -> Any:
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot import A401 dependency {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


A388 = load_module(A388_RUNNER, "a401_a388")
A385 = A388.A385

file_sha256 = A388.file_sha256
canonical_sha256 = A388.canonical_sha256
canonical_bytes = A388.canonical_bytes
atomic_json = A388.atomic_json
atomic_bytes = A388.atomic_bytes
relative = A388.relative
path_from_ref = A388.path_from_ref
anchor = A388.anchor
sha256 = A388.sha256


def deterministic_assignment(index: int) -> int:
    if index not in TARGETS:
        raise ValueError("A401 target index differs")
    label = f"A401|W50-knownkey-assignment|v1|target-{index:02d}"
    return int.from_bytes(hashlib.shake_256(label.encode()).digest(8), "little") & MASK50


def public_material_label(index: int) -> str:
    if index not in TARGETS:
        raise ValueError("A401 target index differs")
    return f"A401|W50-knownkey-public-material|v1|target-{index:02d}"


def true_cell(assignment: int) -> int:
    if not 0 <= assignment <= MASK50:
        raise ValueError("A401 W50 assignment differs")
    return (assignment >> 38) & (CELLS - 1)


def exact_order(values: Sequence[int]) -> list[int]:
    order = [int(value) for value in values]
    if len(order) != CELLS or set(order) != set(range(CELLS)):
        raise ValueError("A401 order is not one exact 4,096-cell permutation")
    return order


def rank_vector(order: Sequence[int]) -> np.ndarray:
    result = np.empty(CELLS, dtype=np.int64)
    for rank, cell in enumerate(exact_order(order), 1):
        result[cell] = rank
    return result


def load_design() -> dict[str, Any]:
    if file_sha256(DESIGN) != DESIGN_SHA256:
        raise RuntimeError("A401 design hash differs")
    value = json.loads(DESIGN.read_bytes())
    corpus = value.get("corpus_contract", {})
    measurement = value.get("measurement_contract", {})
    reader = value.get("reader_contract", {})
    boundary = value.get("information_boundary", {})
    if (
        value.get("schema") != "chacha20-round20-w50-knownkey-direct12-learning-a401-design-v1"
        or value.get("attempt_id") != ATTEMPT_ID
        or value.get("design_state")
        != "frozen_before_any_A401_public_challenge_label_measurement_reader_selection_or_holdout_score"
        or tuple(corpus.get("target_indices", [])) != TARGETS
        or tuple(corpus.get("selection_indices", [])) != TRAIN_TARGETS
        or tuple(corpus.get("holdout_indices", [])) != HOLDOUT_TARGETS
        or corpus.get("rounds") != 20
        or corpus.get("feedforward") is not True
        or corpus.get("unknown_key_bits") != WIDTH
        or measurement.get("complete_direct_prefix_cells_per_target") != CELLS
        or measurement.get("low4_slices_per_target") != len(SLICES)
        or measurement.get("solver_stages_per_target") != CELLS * 4
        or measurement.get("measurement_must_not_read_label_ledger") is not True
        or tuple(reader.get("complete_view_order", [])) != VIEW_NAMES
        or tuple(reader.get("aggregator_order", [])) != AGGREGATORS
        or reader.get("candidate_count") != ((1 << len(VIEW_NAMES)) - 1) * len(AGGREGATORS)
        or boundary.get("A385_production_assignment_or_true_prefix_consumed") is not False
        or boundary.get("A387_A397_A399_progress_filter_outcomes_or_results_consumed") is not False
        or boundary.get("A401_measurement_target_labels_used") != 0
        or boundary.get("A401_candidate_assignments_executed") != 0
    ):
        raise RuntimeError("A401 frozen design semantics differ")
    for key, path in value["source_anchors"].items():
        if key.endswith("_path"):
            stem = key.removesuffix("_path")
            anchor(ROOT / path, value["source_anchors"][f"{stem}_sha256"])
    return value


def build_corpus_payloads() -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    challenges = []
    train_rows = []
    holdout_rows = []
    for index in TARGETS:
        assignment = deterministic_assignment(index)
        challenge = A385.challenge_from_assignment(
            label=public_material_label(index), assignment=assignment
        )
        A385.validate_challenge(challenge)
        if "assignment" in challenge or challenge.get("unknown_assignment_included") is not False:
            raise RuntimeError("A401 public challenge contains a label")
        challenges.append(
            {
                "target_index": index,
                "public_challenge": challenge,
                "public_challenge_sha256": canonical_sha256(challenge),
            }
        )
        row = {
            "target_index": index,
            "assignment": assignment,
            "assignment_hex": f"{assignment:013x}",
            "true_direct12_cell": true_cell(assignment),
            "true_direct12_cell_hex": f"{true_cell(assignment):03x}",
            "assignment_derivation_sha256": sha256(
                f"A401|W50-knownkey-assignment|v1|target-{index:02d}".encode()
            ),
        }
        (train_rows if index in TRAIN_TARGETS else holdout_rows).append(row)
    train = {
        "schema": "chacha20-round20-w50-knownkey-direct12-learning-a401-selection-labels-v1",
        "attempt_id": ATTEMPT_ID,
        "target_indices": list(TRAIN_TARGETS),
        "labels": train_rows,
    }
    train["label_commitment_sha256"] = canonical_sha256(train)
    holdout = {
        "schema": "chacha20-round20-w50-knownkey-direct12-learning-a401-holdout-labels-v1",
        "attempt_id": ATTEMPT_ID,
        "target_indices": list(HOLDOUT_TARGETS),
        "labels": holdout_rows,
    }
    holdout["label_commitment_sha256"] = canonical_sha256(holdout)
    public = {
        "schema": "chacha20-round20-w50-knownkey-direct12-learning-a401-public-corpus-v1",
        "attempt_id": ATTEMPT_ID,
        "design_sha256": DESIGN_SHA256,
        "target_indices": list(TARGETS),
        "selection_indices": list(TRAIN_TARGETS),
        "holdout_indices": list(HOLDOUT_TARGETS),
        "challenges": challenges,
        "selection_label_commitment_sha256": train["label_commitment_sha256"],
        "holdout_label_commitment_sha256": holdout["label_commitment_sha256"],
        "assignments_or_true_cells_in_public_corpus": False,
    }
    public["public_corpus_commitment_sha256"] = canonical_sha256(public)
    return public, train, holdout


def freeze_implementation() -> dict[str, Any]:
    outputs = (
        IMPLEMENTATION,
        PROTOCOL,
        TRAIN_LABELS,
        HOLDOUT_LABELS,
        SELECTION,
        RESULT,
        CAUSAL,
        REPORT,
    )
    if any(path.exists() for path in outputs) or ARTIFACTS.exists() or MEASUREMENTS.exists():
        raise FileExistsError("A401 implementation or generated artifacts already exist")
    design = load_design()
    if not TEST.exists() or not REPRO.exists():
        raise FileNotFoundError("A401 test and reproducer must precede freeze")
    public, train, holdout = build_corpus_payloads()
    payload: dict[str, Any] = {
        "schema": "chacha20-round20-w50-knownkey-direct12-learning-a401-implementation-v1",
        "attempt_id": ATTEMPT_ID,
        "commitment_state": "frozen_before_A401_corpus_measurement_selection_or_holdout_evaluation",
        "design_sha256": DESIGN_SHA256,
        "selection_label_commitment_sha256": train["label_commitment_sha256"],
        "holdout_label_commitment_sha256": holdout["label_commitment_sha256"],
        "public_corpus_commitment_sha256": public["public_corpus_commitment_sha256"],
        "candidate_count": design["reader_contract"]["candidate_count"],
        "anchors": {
            "design": anchor(DESIGN, DESIGN_SHA256),
            "A388_runner": anchor(A388_RUNNER, A388_RUNNER_SHA256),
            "A388_preflight": anchor(A388_PREFLIGHT, A388_PREFLIGHT_SHA256),
            "A385_runner": anchor(A385_RUNNER, A385_RUNNER_SHA256),
            "A400_result": anchor(A400_RESULT, A400_RESULT_SHA256),
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
    atomic_json(TRAIN_LABELS, train)
    atomic_json(HOLDOUT_LABELS, holdout)
    atomic_json(PROTOCOL, public)
    return payload


def load_implementation(expected_sha256: str | None = None) -> dict[str, Any]:
    if expected_sha256 is not None and file_sha256(IMPLEMENTATION) != expected_sha256:
        raise RuntimeError("A401 implementation hash differs")
    value = json.loads(IMPLEMENTATION.read_bytes())
    if (
        value.get("schema")
        != "chacha20-round20-w50-knownkey-direct12-learning-a401-implementation-v1"
        or value.get("attempt_id") != ATTEMPT_ID
        or value.get("design_sha256") != DESIGN_SHA256
        or value.get("candidate_count") != 765
    ):
        raise RuntimeError("A401 implementation semantics differ")
    for row in value["anchors"].values():
        anchor(ROOT / row["path"], row["sha256"])
    unsigned = {
        key: item for key, item in value.items() if key != "implementation_commitment_sha256"
    }
    if value.get("implementation_commitment_sha256") != canonical_sha256(unsigned):
        raise RuntimeError("A401 implementation commitment differs")
    return value


def load_protocol(expected_sha256: str | None = None) -> dict[str, Any]:
    if expected_sha256 is not None and file_sha256(PROTOCOL) != expected_sha256:
        raise RuntimeError("A401 public corpus file hash differs")
    value = json.loads(PROTOCOL.read_bytes())
    if (
        value.get("schema")
        != "chacha20-round20-w50-knownkey-direct12-learning-a401-public-corpus-v1"
        or value.get("attempt_id") != ATTEMPT_ID
        or tuple(value.get("target_indices", [])) != TARGETS
        or tuple(value.get("selection_indices", [])) != TRAIN_TARGETS
        or tuple(value.get("holdout_indices", [])) != HOLDOUT_TARGETS
        or value.get("assignments_or_true_cells_in_public_corpus") is not False
        or len(value.get("challenges", [])) != len(TARGETS)
    ):
        raise RuntimeError("A401 public corpus semantics differ")
    for index, row in enumerate(value["challenges"]):
        challenge = row["public_challenge"]
        if row.get("target_index") != index or canonical_sha256(challenge) != row.get(
            "public_challenge_sha256"
        ):
            raise RuntimeError("A401 public challenge commitment differs")
        A385.validate_challenge(challenge)
    load_implementation(value["implementation_sha256"])
    return value


def target_dir(index: int) -> Path:
    return ARTIFACTS / f"target_{index:02d}"


def target_measurement_dir(index: int) -> Path:
    return MEASUREMENTS / f"target_{index:02d}"


def target_preflight_path(index: int) -> Path:
    return target_dir(index) / "preflight_v1.json"


def target_complete_path(index: int) -> Path:
    return target_measurement_dir(index) / "complete_v1.json"


def validate_coordinate_mapping(
    mapping: Sequence[int], variable_count: int, observations: Sequence[Mapping[str, Any]]
) -> list[int]:
    values = [int(value) for value in mapping]
    expected_dimensions = tuple(range(-1, math.ceil(math.log2(WIDTH))))
    if (
        len(values) != WIDTH
        or any(value == 0 or abs(value) > variable_count for value in values)
        or len({abs(value) for value in values}) != WIDTH
        or tuple(int(row.get("dimension", -99)) for row in observations) != expected_dimensions
        or any(row.get("unit_count") != WIDTH for row in observations)
        or any(row.get("exact_unit_delta") is not True for row in observations)
    ):
        raise RuntimeError("A401 per-target semantic coordinate gate failed")
    return values


def prepare_target(index: int, protocol: Mapping[str, Any]) -> dict[str, Any]:
    row = protocol["challenges"][index]
    challenge = row["public_challenge"]
    directory = target_dir(index)
    base = directory / "base.cnf"
    preflight_path = target_preflight_path(index)
    if preflight_path.exists():
        value = json.loads(preflight_path.read_bytes())
        if (
            value.get("schema")
            != "chacha20-round20-w50-knownkey-direct12-learning-a401-preflight-v1"
            or value.get("target_index") != index
            or value.get("public_challenge_sha256") != row["public_challenge_sha256"]
            or value.get("coordinate_probe_ledger_sha256")
            != canonical_sha256(value.get("coordinate_probe_ledger", []))
        ):
            raise RuntimeError(f"A401 target {index} preflight differs")
        validate_coordinate_mapping(
            value["source_one_literals_bit0_upward"],
            int(value["variable_count"]),
            value["coordinate_probe_ledger"],
        )
        if value["synthetic_reader_mapping"] != A388.A340.A296.synthetic_reader_mapping(
            value["source_one_literals_bit0_upward"], WIDTH
        ):
            raise RuntimeError(f"A401 target {index} synthetic mapping differs")
        anchor(base, value["base_CNF"]["sha256"])
        return value
    bridge = A388.bridge_challenge({"public_challenge": challenge})
    bridge["challenge_id"] = f"A401-knownkey-target-{index:02d}"
    a223 = A388.A340.load_module(A388.A340.A223_SOURCE, f"a401_a223_preflight_{index:02d}")
    config = json.loads(A388.A340.A223_CONFIG.read_bytes())
    a223._toolchain_gates(config)  # noqa: SLF001
    a223._validate_challenge(bridge, width=WIDTH)  # noqa: SLF001
    formula = A388.w50_source_formula(a223, bridge)
    directory.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(
        prefix=f"a401_t{index:02d}_", dir=directory.parent
    ) as temporary:
        temporary_dir = Path(temporary)
        temporary_base = temporary_dir / "base.cnf"
        export = a223._export_cnf(  # noqa: SLF001
            formula=formula,
            output=temporary_base,
            config=config,
            label=f"A401_W50_KNOWNKEY_{index:02d}",
        )
        raw = temporary_base.read_bytes()
        lines = raw.splitlines(keepends=True)
        header = lines[0].split() if lines else []
        if len(header) != 4 or header[:2] != [b"p", b"cnf"]:
            raise RuntimeError("A401 base CNF header differs")
        context = {
            "width": WIDTH,
            "formula": formula,
            "formula_bytes": len(formula.encode()),
            "formula_sha256": sha256(formula.encode()),
            "base_path": temporary_base,
            "base_raw": raw,
            "base_body": b"".join(lines[1:]),
            "base_body_sha256": sha256(b"".join(lines[1:])),
            "variable_count": int(header[2]),
            "clause_count": int(header[3]),
            "base_export": export,
        }
        probes = [
            a223._coordinate_probe(  # noqa: SLF001
                context=context,
                dimension=dimension,
                config=config,
                directory=temporary_dir,
            )
            for dimension in range(-1, math.ceil(math.log2(WIDTH)))
        ]
        mapping = a223._decode_mapping(  # noqa: SLF001
            [(dimension, units) for _, dimension, units, _ in probes], width=WIDTH
        )
        observations = [observation for _, _, _, observation in probes]
        mapping = validate_coordinate_mapping(mapping, int(context["variable_count"]), observations)
        directory.mkdir(parents=False, exist_ok=False)
        atomic_bytes(base, raw)
    synthetic = A388.A340.A296.synthetic_reader_mapping(mapping, WIDTH)
    value = {
        "schema": "chacha20-round20-w50-knownkey-direct12-learning-a401-preflight-v1",
        "attempt_id": ATTEMPT_ID,
        "target_index": index,
        "public_challenge_sha256": row["public_challenge_sha256"],
        "bridge_challenge_sha256": canonical_sha256(bridge),
        "formula_sha256": sha256(formula.encode()),
        "base_CNF": anchor(base, export["sha256"]),
        "CNF_header": export["header"],
        "variable_count": int(context["variable_count"]),
        "source_one_literals_bit0_upward": mapping,
        "synthetic_reader_mapping": synthetic,
        "coordinate_probe_ledger": observations,
        "coordinate_probe_ledger_sha256": canonical_sha256(observations),
        "coordinate_portability_contract": "per_target_exact_unit_delta_not_cross_instance_literal_identity",
        "label_ledger_opened": False,
        "target_labels_used": 0,
        "reader_refits": 0,
    }
    atomic_json(preflight_path, value)
    return value


def measure_target(index: int, protocol: Mapping[str, Any], slice_workers: int) -> dict[str, Any]:
    complete_path = target_complete_path(index)
    if complete_path.exists():
        return load_target_complete(index)
    preflight = prepare_target(index, protocol)
    base_raw = path_from_ref(preflight["base_CNF"]["path"]).read_bytes()
    source_mapping = preflight["source_one_literals_bit0_upward"]
    measurement_dir = target_measurement_dir(index)
    measurement_dir.mkdir(parents=True, exist_ok=True)
    _a275, _model, _a291, _indices, helper = A388.A340.A296._reader_stack()  # noqa: SLF001
    A388.WRAPPER._load_base_wrapper()  # noqa: SLF001
    started = time.perf_counter()
    with tempfile.TemporaryDirectory(
        prefix=f"a401_t{index:02d}_slices_", dir=target_dir(index)
    ) as temporary:
        temporary_dir = Path(temporary)
        rows = []
        for low4 in SLICES:
            cnf_path = temporary_dir / f"slice_{low4:02x}.cnf"
            atomic_bytes(
                cnf_path,
                A388.render_slice_cnf(base_raw, low4=low4, source_mapping=source_mapping),
            )
            rows.append(
                {
                    "low4": low4,
                    "unit_literals": A388.low4_unit_literals(low4, source_mapping),
                    "cnf": anchor(cnf_path),
                    "measurement_path": str(measurement_dir / f"slice_{low4:02x}.json.zst"),
                }
            )
        completed = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=slice_workers) as executor:
            futures = [
                executor.submit(
                    A388._run_slice,  # noqa: SLF001
                    row,
                    helper=helper,
                    key_mapping=preflight["synthetic_reader_mapping"],
                )
                for row in rows
            ]
            for future in concurrent.futures.as_completed(futures):
                completed.append(future.result())
    completed.sort(key=lambda value: value["low4"])
    if [row["low4"] for row in completed] != list(SLICES):
        raise RuntimeError(f"A401 target {index} slice cover differs")
    ledger = [{**row["ledger"], "low4": row["low4"]} for row in completed]
    value = {
        "schema": "chacha20-round20-w50-knownkey-direct12-learning-a401-target-complete-v1",
        "attempt_id": ATTEMPT_ID,
        "target_index": index,
        "public_challenge_sha256": protocol["challenges"][index]["public_challenge_sha256"],
        "preflight_sha256": file_sha256(target_preflight_path(index)),
        "measurement_ledger": ledger,
        "measurement_sha256": canonical_sha256(ledger),
        "complete_direct12_cells": CELLS,
        "solver_stages": CELLS * 4,
        "label_ledger_opened": False,
        "target_labels_used": 0,
        "reader_refits": 0,
        "candidate_assignments_executed": 0,
        "volatile_wall_seconds": time.perf_counter() - started,
    }
    atomic_json(complete_path, value)
    return value


def load_target_complete(index: int) -> dict[str, Any]:
    value = json.loads(target_complete_path(index).read_bytes())
    if (
        value.get("schema")
        != "chacha20-round20-w50-knownkey-direct12-learning-a401-target-complete-v1"
        or value.get("target_index") != index
        or len(value.get("measurement_ledger", [])) != len(SLICES)
        or value.get("complete_direct12_cells") != CELLS
        or value.get("solver_stages") != CELLS * 4
        or value.get("label_ledger_opened") is not False
        or value.get("target_labels_used") != 0
        or value.get("candidate_assignments_executed") != 0
    ):
        raise RuntimeError(f"A401 target {index} completion semantics differ")
    for row in value["measurement_ledger"]:
        measurement = A388._read_measurement(path_from_ref(row["path"]), row)  # noqa: SLF001
        A388._validate_measurement(measurement, int(row["low4"]))  # noqa: SLF001
    return value


def measure_all(*, expected_protocol_sha256: str, slice_workers: int) -> dict[str, Any]:
    if SELECTION.exists() or RESULT.exists():
        raise RuntimeError("A401 measurement must precede selection and result")
    if not 1 <= slice_workers <= 10:
        raise ValueError("A401 slice workers must lie in 1..10")
    protocol = load_protocol(expected_protocol_sha256)
    completed = []
    started = time.perf_counter()
    for index in TARGETS:
        measure_target(index, protocol, slice_workers)
        completed.append(index)
        atomic_json(
            PROGRESS,
            {
                "schema": "chacha20-round20-w50-knownkey-direct12-learning-a401-progress-v1",
                "attempt_id": ATTEMPT_ID,
                "status": "running" if len(completed) < len(TARGETS) else "measurement_complete",
                "completed_target_indices": completed,
                "completed_targets": len(completed),
                "target_count": len(TARGETS),
                "complete_direct12_cells": len(completed) * CELLS,
                "solver_stages": len(completed) * CELLS * 4,
                "selection_or_holdout_labels_opened": False,
                "volatile_wall_seconds": time.perf_counter() - started,
            },
        )
    return json.loads(PROGRESS.read_bytes())


def load_measurements(index: int) -> dict[int, dict[str, Any]]:
    complete = load_target_complete(index)
    result = {}
    for row in complete["measurement_ledger"]:
        low4 = int(row["low4"])
        result[low4] = A388._read_measurement(path_from_ref(row["path"]), row)  # noqa: SLF001
    return result


def view_rank_matrix(index: int) -> tuple[np.ndarray, dict[str, Any]]:
    measurements = load_measurements(index)
    _selection, _a272, model, groups = A388.A341.reconstruct_known_key_selection(
        json.loads(A388.A341.DESIGN.read_bytes())
    )
    fields = A388.A348._all_view_scores(measurements, model, groups)  # noqa: SLF001
    if tuple(fields) != VIEW_NAMES:
        raise RuntimeError("A401 reconstructed view family differs")
    orders = {
        name: exact_order(A388.A348._rank_order(fields[name]))  # noqa: SLF001
        for name in VIEW_NAMES
    }
    ranks = np.stack([rank_vector(orders[name]) for name in VIEW_NAMES], axis=0)
    return ranks, {
        "view_order_uint16be_sha256": {name: A400_uint16_sha(orders[name]) for name in VIEW_NAMES},
        "view_score_field_sha256": {
            name: canonical_sha256(np.asarray(fields[name], dtype=np.float64).tolist())
            for name in VIEW_NAMES
        },
    }


def A400_uint16_sha(order: Sequence[int]) -> str:
    raw = b"".join(int(value).to_bytes(2, "big") for value in exact_order(order))
    return hashlib.sha256(raw).hexdigest()


def candidate_rank(ranks: np.ndarray, subset: Sequence[int], aggregator: str, cell: int) -> int:
    indices = np.asarray(tuple(int(value) for value in subset), dtype=np.int64)
    selected = np.asarray(ranks[indices], dtype=np.int64)
    cells = np.arange(CELLS, dtype=np.int64)
    sums = selected.sum(axis=0)
    if aggregator == "borda_sum":
        primary = sums.astype(np.float64)
        secondary = np.zeros(CELLS, dtype=np.float64)
    elif aggregator == "reciprocal_rank_sum":
        primary = -np.reciprocal(selected.astype(np.float64)).sum(axis=0)
        secondary = sums.astype(np.float64)
    elif aggregator == "minimum_rank_then_sum":
        primary = selected.min(axis=0).astype(np.float64)
        secondary = sums.astype(np.float64)
    else:
        raise ValueError("A401 aggregator differs")
    p = primary[cell]
    s = secondary[cell]
    better = (primary < p) | ((primary == p) & (secondary < s))
    tied = (primary == p) & (secondary == s) & (cells < cell)
    return int(1 + np.count_nonzero(better | tied))


def candidate_order(ranks: np.ndarray, subset: Sequence[int], aggregator: str) -> list[int]:
    indices = np.asarray(tuple(int(value) for value in subset), dtype=np.int64)
    selected = np.asarray(ranks[indices], dtype=np.int64)
    sums = selected.sum(axis=0)
    cells = np.arange(CELLS, dtype=np.int64)
    if aggregator == "borda_sum":
        permutation = np.lexsort((cells, sums))
    elif aggregator == "reciprocal_rank_sum":
        reciprocal = np.reciprocal(selected.astype(np.float64)).sum(axis=0)
        permutation = np.lexsort((cells, sums, -reciprocal))
    elif aggregator == "minimum_rank_then_sum":
        permutation = np.lexsort((cells, sums, selected.min(axis=0)))
    else:
        raise ValueError("A401 aggregator differs")
    return exact_order(permutation.tolist())


def load_label_file(path: Path, schema: str, targets: Sequence[int]) -> dict[int, dict[str, Any]]:
    value = json.loads(path.read_bytes())
    if (
        value.get("schema") != schema
        or value.get("attempt_id") != ATTEMPT_ID
        or tuple(value.get("target_indices", [])) != tuple(targets)
    ):
        raise RuntimeError("A401 label ledger differs")
    unsigned = {key: item for key, item in value.items() if key != "label_commitment_sha256"}
    if value.get("label_commitment_sha256") != canonical_sha256(unsigned):
        raise RuntimeError("A401 label commitment differs")
    rows = {int(row["target_index"]): dict(row) for row in value["labels"]}
    if tuple(rows) != tuple(targets):
        raise RuntimeError("A401 label target order differs")
    return rows


def freeze_selection(*, expected_implementation_sha256: str) -> dict[str, Any]:
    if SELECTION.exists() or RESULT.exists() or CAUSAL.exists() or REPORT.exists():
        raise FileExistsError("A401 selection or result already exists")
    implementation = load_implementation(expected_implementation_sha256)
    load_protocol()
    for index in TARGETS:
        load_target_complete(index)
    train_labels = load_label_file(
        TRAIN_LABELS,
        "chacha20-round20-w50-knownkey-direct12-learning-a401-selection-labels-v1",
        TRAIN_TARGETS,
    )
    rank_matrices: dict[int, np.ndarray] = {}
    field_commits: dict[str, Any] = {}
    for index in TRAIN_TARGETS:
        rank_matrices[index], field_commits[str(index)] = view_rank_matrix(index)
    candidates = []
    for mask in range(1, 1 << len(VIEW_NAMES)):
        subset = tuple(index for index in range(len(VIEW_NAMES)) if mask & (1 << index))
        for aggregator_index, aggregator in enumerate(AGGREGATORS):
            truth_ranks = [
                candidate_rank(
                    rank_matrices[index],
                    subset,
                    aggregator,
                    train_labels[index]["true_direct12_cell"],
                )
                for index in TRAIN_TARGETS
            ]
            mean_log2 = statistics.fmean(math.log2(rank) for rank in truth_ranks)
            candidates.append(
                {
                    "aggregator": aggregator,
                    "aggregator_index": aggregator_index,
                    "view_indices": list(subset),
                    "view_names": [VIEW_NAMES[value] for value in subset],
                    "selection_true_ranks": truth_ranks,
                    "selection_mean_log2_rank": mean_log2,
                    "selection_bit_gain_vs_complete_4096_cover": 12.0 - mean_log2,
                    "selection_worst_rank": max(truth_ranks),
                }
            )
    if len(candidates) != 765:
        raise RuntimeError("A401 candidate family size differs")
    winner = min(
        candidates,
        key=lambda row: (
            row["selection_mean_log2_rank"],
            row["selection_worst_rank"],
            len(row["view_indices"]),
            row["aggregator_index"],
            tuple(row["view_indices"]),
        ),
    )
    payload: dict[str, Any] = {
        "schema": "chacha20-round20-w50-knownkey-direct12-learning-a401-selection-v1",
        "attempt_id": ATTEMPT_ID,
        "selection_state": "frozen_after_targets_0_7_only_before_holdout_labels_or_scores",
        "design_sha256": DESIGN_SHA256,
        "implementation_sha256": expected_implementation_sha256,
        "implementation_commitment_sha256": implementation["implementation_commitment_sha256"],
        "public_corpus_sha256": file_sha256(PROTOCOL),
        "selection_label_sha256": file_sha256(TRAIN_LABELS),
        "holdout_label_file_opened": False,
        "candidate_count": len(candidates),
        "candidate_family_commitment_sha256": canonical_sha256(candidates),
        "selected_candidate": winner,
        "selected_candidate_commitment_sha256": canonical_sha256(winner),
        "selection_view_field_commitments": field_commits,
        "complete_measurement_target_indices": list(TARGETS),
        "anchors": {
            "design": anchor(DESIGN, DESIGN_SHA256),
            "implementation": anchor(IMPLEMENTATION, expected_implementation_sha256),
            "public_corpus": anchor(PROTOCOL),
            "selection_labels": anchor(TRAIN_LABELS),
            "runner": anchor(Path(__file__)),
        },
    }
    payload["selection_commitment_sha256"] = canonical_sha256(payload)
    atomic_json(SELECTION, payload)
    return payload


def load_selection(expected_sha256: str) -> dict[str, Any]:
    if file_sha256(SELECTION) != expected_sha256:
        raise RuntimeError("A401 selection hash differs")
    value = json.loads(SELECTION.read_bytes())
    winner = value.get("selected_candidate", {})
    if (
        value.get("schema") != "chacha20-round20-w50-knownkey-direct12-learning-a401-selection-v1"
        or value.get("attempt_id") != ATTEMPT_ID
        or value.get("selection_state")
        != "frozen_after_targets_0_7_only_before_holdout_labels_or_scores"
        or value.get("holdout_label_file_opened") is not False
        or value.get("candidate_count") != 765
        or winner.get("aggregator") not in AGGREGATORS
        or not winner.get("view_indices")
        or value.get("selected_candidate_commitment_sha256") != canonical_sha256(winner)
    ):
        raise RuntimeError("A401 frozen selection semantics differ")
    for row in value["anchors"].values():
        anchor(ROOT / row["path"], row["sha256"])
    return value


def metric_panel(ranks: Sequence[int]) -> dict[str, Any]:
    values = [int(value) for value in ranks]
    mean_log2 = statistics.fmean(math.log2(value) for value in values)
    return {
        "ranks": values,
        "mean_log2_rank": mean_log2,
        "geometric_mean_rank": 2.0**mean_log2,
        "bit_gain_vs_complete_4096_cover": 12.0 - mean_log2,
        "median_rank": statistics.median(values),
        "worst_rank": max(values),
        "top_quartile_targets": sum(value <= 1024 for value in values),
    }


def build_causal(payload: Mapping[str, Any]) -> dict[str, Any]:
    sys.path.insert(0, str(DOTCAUSAL_SRC))
    from dotcausal.io import CausalReader, CausalWriter

    writer = CausalWriter(api_id="a401w50")
    writer._rules = []
    writer.add_rule(
        name="complete_knownkey_fields_to_selection",
        description="Sixteen complete W50 Direct12 fields close before the first label ledger opens; targets zero through seven select one frozen rank-fusion Reader.",
        pattern=["A401_complete_unlabeled_W50_fields", "A401_selection_labels_0_7"],
        conclusion="A401_frozen_W50_rank_fusion_reader",
        confidence_modifier=1.0,
    )
    writer.add_rule(
        name="frozen_reader_to_holdout",
        description="The byte-frozen Reader scores targets eight through fifteen without parameter, subset, aggregator, or threshold changes.",
        pattern=["A401_frozen_W50_rank_fusion_reader", "A401_holdout_labels_8_15"],
        conclusion="A401_independent_W50_holdout_panel",
        confidence_modifier=1.0,
    )
    writer.add_rule(
        name="holdout_to_production_application",
        description="A target-independent holdout-qualified Reader can be applied unchanged to the already complete assignment-free A388 W50 field.",
        pattern=["A401_independent_W50_holdout_panel", "A388_complete_unlabeled_W50_field"],
        conclusion="A402_frozen_reader_application_ready",
        confidence_modifier=1.0,
    )
    writer.add_triplet(
        trigger="A401:sixteen_complete_unlabeled_W50_Direct12_fields",
        mechanism="train_only_exhaustive_255_subset_three_aggregator_selection",
        outcome="A401:frozen_W50_rank_fusion_reader",
        confidence=1.0,
        source=payload["selection_sha256"],
        quantification=json.dumps(payload["selected_candidate"], sort_keys=True),
        evidence="holdout label ledger unopened at selection freeze",
        domain="known-key full-round ChaCha20 W50 Reader learning",
        quality_score=1.0,
    )
    writer.add_triplet(
        trigger="A401:frozen_W50_rank_fusion_reader",
        mechanism="unchanged_eight_target_holdout_scoring",
        outcome="A401:independent_W50_holdout_panel",
        confidence=1.0,
        source=payload["measurement_sha256"],
        quantification=json.dumps(payload["holdout_selected_panel"], sort_keys=True),
        evidence=json.dumps(payload["holdout_baseline_panels"], sort_keys=True),
        domain="prospective W50 Reader holdout",
        quality_score=1.0,
    )
    writer.add_triplet(
        trigger="A401:independent_W50_holdout_panel",
        mechanism="materialized_zero_refit_application_chain",
        outcome="A402:frozen_reader_application_ready",
        confidence=1.0,
        source="materialized:A401_to_A402_chain",
        quantification="exact retained closure",
        evidence="production A385 assignment and every live recovery outcome remained unused",
        domain="AI-native retained inference",
        quality_score=1.0,
        is_inferred=True,
    )
    writer.add_cluster(
        name="A401 W50 known-key rank-fusion learning and holdout",
        entities=[
            "A401:sixteen_complete_unlabeled_W50_Direct12_fields",
            "A401:frozen_W50_rank_fusion_reader",
            "A401:independent_W50_holdout_panel",
            "A402:frozen_reader_application_ready",
        ],
    )
    writer.add_gap(
        subject="A402:frozen_reader_application_ready",
        predicate="next_required_object",
        expected_object_type="zero_refit_order_on_the_assignment_free_A388_W50_field",
        confidence=1.0,
        suggested_queries=[
            "Apply the frozen A401 subset and aggregator unchanged to A388's complete W50 field."
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
        reader.api_id != "a401w50"
        or len(explicit) != 2
        or len(all_rows) != 3
        or len(inferred) != 1
        or len(reader._rules) != 3
        or len(reader._clusters) != 1
        or len(reader._gaps) != 1
    ):
        raise RuntimeError("A401 authentic Causal reopen gate failed")
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
            "selection": explicit[0],
            "holdout": explicit[1],
            "terminal_chain": all_rows[-1],
            "next_gap": reader._gaps[0],
        },
    }


def evaluate_holdout(*, expected_selection_sha256: str) -> dict[str, Any]:
    if RESULT.exists() or CAUSAL.exists() or REPORT.exists():
        raise FileExistsError("A401 holdout result already exists")
    selection = load_selection(expected_selection_sha256)
    holdout_labels = load_label_file(
        HOLDOUT_LABELS,
        "chacha20-round20-w50-knownkey-direct12-learning-a401-holdout-labels-v1",
        HOLDOUT_TARGETS,
    )
    winner = selection["selected_candidate"]
    subset = tuple(int(value) for value in winner["view_indices"])
    aggregator = str(winner["aggregator"])
    selected_ranks = []
    individual: dict[str, list[int]] = {name: [] for name in VIEW_NAMES}
    pair_triple: dict[str, list[int]] = {name: [] for name in AGGREGATORS}
    field_commits: dict[str, Any] = {}
    for index in HOLDOUT_TARGETS:
        ranks, field_commits[str(index)] = view_rank_matrix(index)
        cell = int(holdout_labels[index]["true_direct12_cell"])
        selected_ranks.append(candidate_rank(ranks, subset, aggregator, cell))
        for view_index, name in enumerate(VIEW_NAMES):
            individual[name].append(int(ranks[view_index, cell]))
        for name in AGGREGATORS:
            pair_triple[name].append(candidate_rank(ranks, (5, 7), name, cell))
    selected_panel = metric_panel(selected_ranks)
    baselines = {
        **{name: metric_panel(values) for name, values in individual.items()},
        **{
            f"pair_slice_plus_triple_slice::{name}": metric_panel(values)
            for name, values in pair_triple.items()
        },
    }
    best_baseline_name, best_baseline = min(
        baselines.items(), key=lambda item: (item[1]["mean_log2_rank"], item[0])
    )
    comparison = {
        "best_baseline": best_baseline_name,
        "selected_geometric_rank_improvement_factor": best_baseline["geometric_mean_rank"]
        / selected_panel["geometric_mean_rank"],
        "selected_additional_bit_gain": selected_panel["bit_gain_vs_complete_4096_cover"]
        - best_baseline["bit_gain_vs_complete_4096_cover"],
        "selected_better_targets": sum(
            left < right for left, right in zip(selected_ranks, best_baseline["ranks"], strict=True)
        ),
        "selected_equal_targets": sum(
            left == right
            for left, right in zip(selected_ranks, best_baseline["ranks"], strict=True)
        ),
        "selected_worse_targets": sum(
            left > right for left, right in zip(selected_ranks, best_baseline["ranks"], strict=True)
        ),
    }
    payload: dict[str, Any] = {
        "schema": "chacha20-round20-w50-knownkey-direct12-learning-a401-result-v1",
        "attempt_id": ATTEMPT_ID,
        "evidence_stage": "COMPLETE_W50_KNOWNKEY_DIRECT12_TRAIN_ONLY_SELECTION_AND_EIGHT_TARGET_HOLDOUT_RETAINED",
        "design_sha256": DESIGN_SHA256,
        "implementation_sha256": selection["implementation_sha256"],
        "selection_sha256": expected_selection_sha256,
        "selection_commitment_sha256": selection["selection_commitment_sha256"],
        "selected_candidate": winner,
        "holdout_selected_panel": selected_panel,
        "holdout_baseline_panels": baselines,
        "holdout_comparison": comparison,
        "holdout_view_field_commitments": field_commits,
        "complete_targets_measured": len(TARGETS),
        "complete_direct12_cells_measured": len(TARGETS) * CELLS,
        "solver_stages_measured": len(TARGETS) * CELLS * 4,
        "measurement_target_labels_used": 0,
        "reader_refits_during_measurement": 0,
        "holdout_refits": 0,
        "candidate_assignments_executed": 0,
        "A385_production_assignment_or_true_prefix_consumed": False,
        "live_recovery_progress_or_outcomes_consumed": False,
        "anchors": {
            "design": anchor(DESIGN, DESIGN_SHA256),
            "implementation": anchor(IMPLEMENTATION, selection["implementation_sha256"]),
            "public_corpus": anchor(PROTOCOL),
            "selection": anchor(SELECTION, expected_selection_sha256),
            "holdout_labels": anchor(HOLDOUT_LABELS),
            "runner": anchor(Path(__file__)),
        },
    }
    payload["measurement_sha256"] = canonical_sha256(
        {
            "selection": winner,
            "selected_panel": selected_panel,
            "baselines": baselines,
            "field_commits": field_commits,
        }
    )
    payload["causal"] = build_causal(payload)
    atomic_json(RESULT, payload)
    atomic_bytes(
        REPORT,
        (
            "# A401 — W50 known-key Direct12 learning\n\n"
            f"Evidence stage: **{payload['evidence_stage']}**\n\n"
            f"- Selected aggregator: **{aggregator}**\n"
            f"- Selected views: **{winner['view_names']}**\n"
            f"- Selection ranks: **{winner['selection_true_ranks']}**\n"
            f"- Holdout ranks: **{selected_panel['ranks']}**\n"
            f"- Holdout geometric mean rank: **{selected_panel['geometric_mean_rank']:.6f} / 4,096**\n"
            f"- Holdout bit gain: **{selected_panel['bit_gain_vs_complete_4096_cover']:.9f} bits**\n"
            f"- Best frozen baseline: **{best_baseline_name}**\n"
            f"- Improvement over best baseline: **{comparison['selected_geometric_rank_improvement_factor']:.9f}x / {comparison['selected_additional_bit_gain']:.9f} bits**\n"
            f"- Better / equal / worse holdouts: **{comparison['selected_better_targets']} / {comparison['selected_equal_targets']} / {comparison['selected_worse_targets']}**\n"
            f"- Complete fields / cells / stages: **16 / {len(TARGETS) * CELLS:,} / {len(TARGETS) * CELLS * 4:,}**\n"
            "- Measurement labels / refits / candidate assignments: **0 / 0 / 0**\n"
            "- Authentic AI-native Causal readback: **2 explicit + 1 inferred chain**\n"
        ).encode(),
    )
    return payload


def analyze() -> dict[str, Any]:
    payload: dict[str, Any] = {
        "attempt_id": ATTEMPT_ID,
        "design_sha256": DESIGN_SHA256,
        "implementation_frozen": IMPLEMENTATION.exists(),
        "public_corpus_frozen": PROTOCOL.exists(),
        "selection_frozen": SELECTION.exists(),
        "result_complete": RESULT.exists(),
    }
    if PROGRESS.exists():
        payload["progress"] = json.loads(PROGRESS.read_bytes())
    if SELECTION.exists():
        value = json.loads(SELECTION.read_bytes())
        payload["selection_sha256"] = file_sha256(SELECTION)
        payload["selected_candidate"] = value["selected_candidate"]
    if RESULT.exists():
        value = json.loads(RESULT.read_bytes())
        payload["result_sha256"] = file_sha256(RESULT)
        payload["holdout_selected_panel"] = value["holdout_selected_panel"]
        payload["holdout_comparison"] = value["holdout_comparison"]
    return payload


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    action = parser.add_mutually_exclusive_group(required=True)
    action.add_argument("--freeze-implementation", action="store_true")
    action.add_argument("--measure-all", action="store_true")
    action.add_argument("--freeze-selection", action="store_true")
    action.add_argument("--evaluate-holdout", action="store_true")
    action.add_argument("--analyze", action="store_true")
    parser.add_argument("--expected-implementation-sha256")
    parser.add_argument("--expected-protocol-sha256")
    parser.add_argument("--expected-selection-sha256")
    parser.add_argument("--slice-workers", type=int, default=DEFAULT_SLICE_WORKERS)
    args = parser.parse_args()
    if args.freeze_implementation:
        payload = freeze_implementation()
    elif args.measure_all:
        if not args.expected_protocol_sha256:
            parser.error("--measure-all requires --expected-protocol-sha256")
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
    elif args.evaluate_holdout:
        if not args.expected_selection_sha256:
            parser.error("--evaluate-holdout requires --expected-selection-sha256")
        payload = evaluate_holdout(expected_selection_sha256=args.expected_selection_sha256)
    else:
        payload = analyze()
    print(json.dumps(payload, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()

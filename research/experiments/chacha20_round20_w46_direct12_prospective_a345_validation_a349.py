#!/usr/bin/env python3
"""A349: prospectively apply A348's selected direct12 reader to A345."""

from __future__ import annotations

import argparse
import concurrent.futures
import importlib.util
import inspect
import json
import math
import os
import sys
import tempfile
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
ARTIFACTS = RESEARCH / "artifacts/a349_chacha20_r20_w46_direct12_a345"
MEASUREMENTS = RESULTS / "chacha20_round20_w46_direct12_prospective_a345_validation_a349_v1"

DESIGN = CONFIGS / "chacha20_round20_w46_direct12_prospective_a345_validation_a349_design_v1.json"
SELECTION = CONFIGS / "chacha20_round20_w46_direct12_prospective_a345_validation_a349_selection_v1.json"
IMPLEMENTATION = CONFIGS / "chacha20_round20_w46_direct12_prospective_a345_validation_a349_implementation_v1.json"
PREFLIGHT = RESULTS / "chacha20_round20_w46_direct12_prospective_a345_validation_a349_preflight_v1.json"
ORDER = RESULTS / "chacha20_round20_w46_direct12_prospective_a345_validation_a349_order_v1.json"
RESULT = RESULTS / "chacha20_round20_w46_direct12_prospective_a345_validation_a349_v1.json"
CAUSAL = RESULT.with_suffix(".causal")
REPORT = RESULTS / "chacha20_round20_w46_direct12_prospective_a345_validation_a349_v1.md"
BASE_CNF = ARTIFACTS / "a349_a345_public_output_w46_b1.cnf"
TEST = ROOT / "tests/test_chacha20_round20_w46_direct12_prospective_a345_validation_a349.py"
REPRO = ROOT / "scripts/reproduce_chacha20_round20_w46_direct12_prospective_a345_validation_a349.sh"

A345_PROTOCOL = CONFIGS / "chacha20_round20_fresh_w46_factor2_replication_a345_v1.json"
A345_RESULT = RESULTS / "chacha20_round20_fresh_w46_factor2_replication_a345_v1.json"
A348_RUNNER = RESEARCH / "experiments/chacha20_round20_w46_direct12_sliced_reader_a348.py"
A348_RESULT = RESULTS / "chacha20_round20_w46_direct12_sliced_reader_a348_v1.json"
A342_RESULT = RESULTS / "chacha20_round20_w46_exhaustive_reader_ensemble_a342_v1.json"

ATTEMPT_ID = "A349"
DESIGN_SHA256 = "f4c8a512def4c115b0a6be0e8a86754764c3a6f835ccc8cfcfcf562cc80f164a"
SELECTION_SHA256 = "4f33a99b859044ed79d933b813486dba195e37438bc9afcf32b21d31d2d6c422"
A345_PROTOCOL_SHA256 = "8e4280d6603f1eacac0345df634113ed1b550f5d5292c2bed75cc31b19a07f95"
A345_PUBLIC_CHALLENGE_SHA256 = "622f7b7218d022167e50efef459983e54207165078c49f0bb253c70545e3231f"
A348_RESULT_SHA256 = "f09bba039b26c8b78804f48169df62db167a9d95fbfff91e7099a01c1be1c812"
A342_RESULT_SHA256 = "8d6d6f99b89d67d7eff186037934bfa515cf93a00af10b244826f44056b4cebb"

WIDTH = 46
PREFIX_BITS = 12
LOW_BITS = 4
CELLS = 1 << PREFIX_BITS
COARSE_CELLS = 256
SLICES = tuple(range(16))
HORIZONS = [1, 2, 4, 8]
WORKERS = 8
WATCHDOG_SECONDS = 2.0
ZSTD_LEVEL = 10
SELECTED_VIEW = "A342_selected_pair_slice_z"

DOTCAUSAL_SRC = Path("/Users/bhkmie/Documents/Forschung/O1/vendor/fabel/dotcausal_package/src")


def load_module(path: Path, name: str) -> Any:
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot import A349 dependency {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


A348 = load_module(A348_RUNNER, "a349_a348")
A340 = A348.A340
A341 = A348.A341
A342 = A348.A342
WRAPPER = A348.WRAPPER
A275 = A348.A275

file_sha256 = A348.file_sha256
canonical_sha256 = A348.canonical_sha256
canonical_bytes = A348.canonical_bytes
atomic_json = A348.atomic_json
atomic_bytes = A348.atomic_bytes
relative = A348.relative
path_from_ref = A348.path_from_ref
anchor = A348.anchor
sha256 = A348.sha256


def assert_a345_result_absent() -> None:
    if A345_RESULT.exists():
        raise RuntimeError("A349 prospective freeze requires A345 result absence")


def load_design_selection() -> tuple[dict[str, Any], dict[str, Any]]:
    if file_sha256(DESIGN) != DESIGN_SHA256 or file_sha256(SELECTION) != SELECTION_SHA256:
        raise RuntimeError("A349 design or selection hash differs")
    design = json.loads(DESIGN.read_bytes())
    selection = json.loads(SELECTION.read_bytes())
    if (
        design.get("schema")
        != "chacha20-round20-w46-direct12-prospective-a345-validation-a349-design-v1"
        or design.get("attempt_id") != ATTEMPT_ID
        or design.get("information_boundary", {}).get(
            "A345_candidate_or_prefix_available_at_design_freeze"
        )
        is not False
        or selection.get("schema")
        != "chacha20-round20-w46-direct12-prospective-a345-validation-a349-selection-v1"
        or selection.get("selected_view") != SELECTED_VIEW
        or selection.get("information_boundary", {}).get(
            "A345_candidate_or_prefix_available_at_selection_freeze"
        )
        is not False
        or selection.get("selected_view_A325_calibration", {}).get("rank_one_based") != 298
        or selection.get("selected_view_algorithm", {}).get("reader_refits") != 0
    ):
        raise RuntimeError("A349 frozen design or selection semantics differ")
    for value in (design, selection):
        for key, path in value.get("source_anchors", {}).items():
            if key.endswith("_path"):
                anchor(
                    ROOT / path,
                    value["source_anchors"][key.removesuffix("_path") + "_sha256"],
                )
    return design, selection


def load_a345_protocol() -> dict[str, Any]:
    if file_sha256(A345_PROTOCOL) != A345_PROTOCOL_SHA256:
        raise RuntimeError("A349 A345 protocol hash differs")
    value = json.loads(A345_PROTOCOL.read_bytes())
    challenge = value.get("public_challenge", {})
    if (
        value.get("schema")
        != "chacha20-round20-fresh-w46-factor2-replication-a345-protocol-v1"
        or value.get("attempt_id") != "A345"
        or value.get("public_challenge_sha256") != A345_PUBLIC_CHALLENGE_SHA256
        or canonical_sha256(challenge) != A345_PUBLIC_CHALLENGE_SHA256
        or challenge.get("unknown_key_bits") != WIDTH
        or challenge.get("unknown_assignment_included") is not False
        or "assignment" in challenge
        or "candidate" in challenge
        or "prefix12" in challenge
    ):
        raise RuntimeError("A349 A345 public challenge boundary differs")
    return value


def freeze_implementation() -> dict[str, Any]:
    if IMPLEMENTATION.exists():
        raise FileExistsError("A349 implementation already exists")
    if any(path.exists() for path in (PREFLIGHT, ORDER, RESULT, CAUSAL, REPORT, MEASUREMENTS)):
        raise RuntimeError("A349 implementation must precede target measurement artifacts")
    assert_a345_result_absent()
    load_design_selection()
    load_a345_protocol()
    if not TEST.exists() or not REPRO.exists():
        raise FileNotFoundError("A349 test and reproducer must precede freeze")
    payload: dict[str, Any] = {
        "schema": "chacha20-round20-w46-direct12-prospective-a345-validation-a349-implementation-v1",
        "attempt_id": ATTEMPT_ID,
        "commitment_state": "frozen_before_A345_direct12_CNF_measurement_order_candidate_or_prefix",
        "design_sha256": DESIGN_SHA256,
        "selection_sha256": SELECTION_SHA256,
        "selected_view": SELECTED_VIEW,
        "anchors": {
            "design": anchor(DESIGN, DESIGN_SHA256),
            "selection": anchor(SELECTION, SELECTION_SHA256),
            "A345_protocol": anchor(A345_PROTOCOL, A345_PROTOCOL_SHA256),
            "runner": anchor(Path(__file__)),
            "test": anchor(TEST),
            "reproducer": anchor(REPRO),
        },
        "A345_result_available_at_implementation_freeze": False,
    }
    payload["implementation_commitment_sha256"] = canonical_sha256(payload)
    atomic_json(IMPLEMENTATION, payload)
    assert_a345_result_absent()
    return payload


def load_implementation(expected_sha256: str) -> dict[str, Any]:
    if file_sha256(IMPLEMENTATION) != expected_sha256:
        raise RuntimeError("A349 implementation artifact hash differs")
    value = json.loads(IMPLEMENTATION.read_bytes())
    if (
        value.get("schema")
        != "chacha20-round20-w46-direct12-prospective-a345-validation-a349-implementation-v1"
        or value.get("attempt_id") != ATTEMPT_ID
        or value.get("selected_view") != SELECTED_VIEW
        or value.get("design_sha256") != DESIGN_SHA256
        or value.get("selection_sha256") != SELECTION_SHA256
        or value.get("A345_result_available_at_implementation_freeze") is not False
    ):
        raise RuntimeError("A349 implementation semantics differ")
    expected = {
        "design": DESIGN,
        "selection": SELECTION,
        "A345_protocol": A345_PROTOCOL,
        "runner": Path(__file__),
        "test": TEST,
        "reproducer": REPRO,
    }
    for name, path in expected.items():
        row = value["anchors"][name]
        if row.get("path") != relative(path) or row.get("sha256") != file_sha256(path):
            raise RuntimeError(f"A349 implementation anchor differs: {name}")
    unsigned = {key: item for key, item in value.items() if key != "implementation_commitment_sha256"}
    if value.get("implementation_commitment_sha256") != canonical_sha256(unsigned):
        raise RuntimeError("A349 implementation commitment differs")
    return value


def preflight(*, expected_implementation_sha256: str) -> dict[str, Any]:
    if PREFLIGHT.exists() or ARTIFACTS.exists():
        raise FileExistsError("A349 preflight artifacts already exist")
    assert_a345_result_absent()
    load_implementation(expected_implementation_sha256)
    protocol = load_a345_protocol()
    bridge = A340.bridge_challenge(protocol)
    bridge["challenge_id"] = "A349-bridge-" + str(protocol["public_challenge"]["challenge_id"])
    a223 = A340.load_module(A340.A223_SOURCE, "a349_a223_preflight")
    config = json.loads(A340.A223_CONFIG.read_bytes())
    a223._toolchain_gates(config)  # noqa: SLF001
    a223._validate_challenge(bridge, width=WIDTH)  # noqa: SLF001
    formula = A340.w46_source_formula(a223, bridge)
    ARTIFACTS.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="a349_w46_b1_", dir=ARTIFACTS.parent) as temporary:
        directory = Path(temporary)
        temporary_cnf = directory / "base.cnf"
        export = a223._export_cnf(  # noqa: SLF001
            formula=formula,
            output=temporary_cnf,
            config=config,
            label="A349_A345_W46_B1_DIRECT12",
        )
        raw = temporary_cnf.read_bytes()
        header = raw.splitlines()[0].split()
        if len(header) != 4 or header[:2] != [b"p", b"cnf"]:
            raise RuntimeError("A349 base CNF header differs")
        context = {
            "width": WIDTH,
            "formula": formula,
            "formula_bytes": len(formula.encode()),
            "formula_sha256": sha256(formula.encode()),
            "base_path": temporary_cnf,
            "base_raw": raw,
            "base_body": b"\n".join(raw.splitlines()[1:]) + b"\n",
            "base_body_sha256": sha256(b"\n".join(raw.splitlines()[1:]) + b"\n"),
            "variable_count": int(header[2]),
            "clause_count": int(header[3]),
            "base_export": export,
        }
        probes = [
            a223._coordinate_probe(  # noqa: SLF001
                context=context, dimension=dimension, config=config, directory=directory
            )
            for dimension in range(-1, math.ceil(math.log2(WIDTH)))
        ]
        mapping = a223._decode_mapping(  # noqa: SLF001
            [(dimension, units) for _, dimension, units, _ in probes], width=WIDTH
        )
        ARTIFACTS.mkdir(parents=False, exist_ok=False)
        atomic_bytes(BASE_CNF, raw)
    synthetic = A340.A296.synthetic_reader_mapping(mapping, WIDTH)
    if len(mapping) != WIDTH or len(synthetic) != 20:
        raise RuntimeError("A349 source or synthetic mapping differs")
    payload: dict[str, Any] = {
        "schema": "chacha20-round20-w46-direct12-prospective-a345-validation-a349-preflight-v1",
        "attempt_id": ATTEMPT_ID,
        "evidence_stage": "PRE_A345_RESULT_PUBLIC_OUTPUT_DIRECT12_CNF_AND_READER_FROZEN",
        "implementation_sha256": expected_implementation_sha256,
        "A345_protocol_sha256": A345_PROTOCOL_SHA256,
        "A345_public_challenge_sha256": A345_PUBLIC_CHALLENGE_SHA256,
        "bridge_challenge_sha256": canonical_sha256(bridge),
        "formula_sha256": sha256(formula.encode()),
        "CNF": anchor(BASE_CNF, export["sha256"]),
        "CNF_header": export["header"],
        "source_one_literals_bit0_upward": mapping,
        "source_mapping_sha256": canonical_sha256(mapping),
        "synthetic_reader_mapping": synthetic,
        "synthetic_reader_mapping_sha256": canonical_sha256(synthetic),
        "selected_view": SELECTED_VIEW,
        "target_labels_used": 0,
        "reader_refits": 0,
        "A345_result_available_at_preflight": False,
        "anchors": {
            "implementation": anchor(IMPLEMENTATION, expected_implementation_sha256),
            "A345_protocol": anchor(A345_PROTOCOL, A345_PROTOCOL_SHA256),
            "A348_result": anchor(A348_RESULT, A348_RESULT_SHA256),
            "A342_result": anchor(A342_RESULT, A342_RESULT_SHA256),
            "runner": anchor(Path(__file__)),
        },
    }
    payload["preflight_commitment_sha256"] = canonical_sha256(payload)
    atomic_json(PREFLIGHT, payload)
    assert_a345_result_absent()
    return payload


def load_preflight(expected_sha256: str) -> dict[str, Any]:
    if file_sha256(PREFLIGHT) != expected_sha256:
        raise RuntimeError("A349 preflight hash differs")
    value = json.loads(PREFLIGHT.read_bytes())
    if (
        value.get("schema")
        != "chacha20-round20-w46-direct12-prospective-a345-validation-a349-preflight-v1"
        or value.get("selected_view") != SELECTED_VIEW
        or value.get("A345_result_available_at_preflight") is not False
        or value.get("target_labels_used") != 0
        or value.get("reader_refits") != 0
    ):
        raise RuntimeError("A349 preflight semantics differ")
    anchor(BASE_CNF, value["CNF"]["sha256"])
    return value


def _slice_paths(low4: int) -> tuple[Path, Path]:
    return ARTIFACTS / f"slice_{low4:02x}.cnf", MEASUREMENTS / f"slice_{low4:02x}.json.zst"


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


def _read_measurement(path: Path, ledger: Mapping[str, Any] | None = None) -> dict[str, Any]:
    compressed = path.read_bytes()
    if ledger is not None and sha256(compressed) != ledger["compressed_sha256"]:
        raise RuntimeError("A349 compressed slice hash differs")
    raw = zstandard.ZstdDecompressor().decompress(compressed)
    if ledger is not None and sha256(raw) != ledger["raw_sha256"]:
        raise RuntimeError("A349 raw slice hash differs")
    value = json.loads(raw)
    if canonical_bytes(value) != raw:
        raise RuntimeError("A349 slice is not canonical")
    return value


def _prepare_slices(preflight_value: Mapping[str, Any]) -> list[dict[str, Any]]:
    base_raw = BASE_CNF.read_bytes()
    mapping = preflight_value["source_one_literals_bit0_upward"]
    rows = []
    for low4 in SLICES:
        cnf_path, measurement_path = _slice_paths(low4)
        expected = A348.render_slice_cnf(base_raw, low4=low4, source_mapping=mapping)
        if cnf_path.exists() and cnf_path.read_bytes() != expected:
            raise RuntimeError(f"A349 slice CNF differs: {low4}")
        if not cnf_path.exists():
            atomic_bytes(cnf_path, expected)
        rows.append(
            {
                "low4": low4,
                "unit_literals": A348.low4_unit_literals(low4, mapping),
                "cnf": anchor(cnf_path),
                "measurement_path": measurement_path,
            }
        )
    return rows


def _validate_measurement(value: Mapping[str, Any], low4: int) -> None:
    run = value.get("run", {})
    if (
        value.get("schema")
        != "chacha20-round20-w46-direct12-prospective-a345-validation-a349-slice-v1"
        or value.get("low4") != low4
        or value.get("target_label_available_to_measurement") is not False
        or value.get("complete_candidate_cover") is not True
        or len(run.get("cells", [])) != COARSE_CELLS
        or len(run.get("stages", [])) != COARSE_CELLS * len(HORIZONS)
        or any(cell.get("final_status") != "unknown" for cell in run["cells"])
        or run.get("all_watchdogs_clear") is not True
    ):
        raise RuntimeError(f"A349 prospective slice gate failed: {low4}")


def _run_slice(row: Mapping[str, Any], *, helper: Path, key_mapping: Sequence[int]) -> dict[str, Any]:
    low4 = int(row["low4"])
    path = Path(row["measurement_path"])
    if path.exists():
        value = _read_measurement(path)
        _validate_measurement(value, low4)
        return {"low4": low4, "resumed": True, "ledger": _write_measurement(path, value)}
    started = time.perf_counter()
    raw_run = WRAPPER.run_fresh_clause_identity(
        helper=helper,
        cnf=path_from_ref(row["cnf"]["path"]),
        mode=f"A349_A345_direct12_low4_{low4:02x}",
        order=[f"{value:08b}" for value in range(COARSE_CELLS)],
        key_one_literals_bit0_through_bit19=key_mapping,
        conflict_horizons=HORIZONS,
        watchdog_seconds=WATCHDOG_SECONDS,
        external_timeout_seconds=3600.0,
    )
    stable = {
        key: value for key, value in raw_run.items() if key not in {"command", "process_elapsed_seconds"}
    }
    value = {
        "schema": "chacha20-round20-w46-direct12-prospective-a345-validation-a349-slice-v1",
        "attempt_id": ATTEMPT_ID,
        "low4": low4,
        "fixed_unit_literals": list(row["unit_literals"]),
        "cnf_sha256": row["cnf"]["sha256"],
        "run": stable,
        "volatile_process_elapsed_seconds": time.perf_counter() - started,
        "target_label_available_to_measurement": False,
        "label_used_for_feature_construction_or_scoring": False,
        "complete_candidate_cover": len(stable.get("cells", [])) == COARSE_CELLS,
    }
    _validate_measurement(value, low4)
    return {"low4": low4, "resumed": False, "ledger": _write_measurement(path, value)}


def selected_pair_slice_z_scores(
    measurements: Mapping[int, Mapping[str, Any]], model: Any, groups: Mapping[str, Sequence[int]]
) -> np.ndarray:
    selection = json.loads(A342_RESULT.read_bytes())["selection"]["pair"]
    indices = [int(value) for value in selection["selected_indices"]]
    if selection["selected_views"] != json.loads(SELECTION.read_bytes())[
        "selected_view_algorithm"
    ]["selected_known_key_views"]:
        raise RuntimeError("A349 selected pair identity differs")
    field = np.empty(CELLS, dtype=np.float64)
    for low4 in SLICES:
        matrix = A275._target_feature_matrix(measurements[low4])  # noqa: SLF001
        contributions = A341.standardized_contributions(
            matrix,
            means=model.means,
            scales=model.scales,
            coefficients=model.coefficients,
        )
        grouped = A341.grouped_scores(contributions, groups)
        names = []
        views: dict[str, np.ndarray] = {}
        for group in sorted(groups):
            direct = f"{group}::direct_additive_contribution"
            local = f"{group}::normalized_8cube_graph_laplacian"
            names.extend([direct, local])
            views[direct] = grouped[group]
            views[local] = A341.local_pairwise_residual(grouped[group])
        ranks = np.stack(
            [A342.midrank_vector_descending(views[name]) for name in names], axis=0
        )
        pair = -ranks[indices].sum(axis=0)
        for high8 in range(COARSE_CELLS):
            field[A348.slice_cell(high8, low4)] = pair[high8]
    return A348._slice_zscores(field)  # noqa: SLF001


def measure(*, expected_implementation_sha256: str, expected_preflight_sha256: str) -> dict[str, Any]:
    if ORDER.exists() or RESULT.exists() or CAUSAL.exists() or REPORT.exists():
        raise FileExistsError("A349 order or result already exists")
    assert_a345_result_absent()
    implementation = load_implementation(expected_implementation_sha256)
    frozen = load_preflight(expected_preflight_sha256)
    rows = _prepare_slices(frozen)
    _a275, _model, _a291, _indices, helper = A340.A296._reader_stack()  # noqa: SLF001
    WRAPPER._load_base_wrapper()  # noqa: SLF001
    MEASUREMENTS.mkdir(parents=True, exist_ok=True)
    started = time.perf_counter()
    completed = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=WORKERS) as executor:
        futures = [
            executor.submit(
                _run_slice,
                row,
                helper=helper,
                key_mapping=frozen["synthetic_reader_mapping"],
            )
            for row in rows
        ]
        for future in concurrent.futures.as_completed(futures):
            completed.append(future.result())
    completed.sort(key=lambda row: row["low4"])
    if [row["low4"] for row in completed] != list(SLICES):
        raise RuntimeError("A349 complete slice cover differs")
    measurements = {
        row["low4"]: _read_measurement(path_from_ref(row["ledger"]["path"]), row["ledger"])
        for row in completed
    }
    for low4, value in measurements.items():
        _validate_measurement(value, low4)
    _selection, _a272, model, groups = A341.reconstruct_known_key_selection(
        json.loads(A341.DESIGN.read_bytes())
    )
    scores = selected_pair_slice_z_scores(measurements, model, groups)
    order = A348._rank_order(scores)  # noqa: SLF001
    order_hash = sha256(b"".join(cell.to_bytes(2, "big") for cell in order))
    ledgers = [
        {**row["ledger"], "low4": row["low4"], "resumed": row["resumed"]}
        for row in completed
    ]
    assert_a345_result_absent()
    payload: dict[str, Any] = {
        "schema": "chacha20-round20-w46-direct12-prospective-a345-validation-a349-order-v1",
        "attempt_id": ATTEMPT_ID,
        "evidence_stage": "PRE_A345_RESULT_COMPLETE_PUBLIC_OUTPUT_CONDITIONED_DIRECT12_ORDER_FROZEN",
        "implementation_sha256": expected_implementation_sha256,
        "implementation_commitment_sha256": implementation[
            "implementation_commitment_sha256"
        ],
        "preflight_sha256": expected_preflight_sha256,
        "design_sha256": DESIGN_SHA256,
        "selection_sha256": SELECTION_SHA256,
        "selected_view": SELECTED_VIEW,
        "A345_protocol_sha256": A345_PROTOCOL_SHA256,
        "A345_public_challenge_sha256": A345_PUBLIC_CHALLENGE_SHA256,
        "complete_direct12_cells": CELLS,
        "solver_stages": CELLS * len(HORIZONS),
        "measurement_ledger": ledgers,
        "measurement_sha256": canonical_sha256(ledgers),
        "score_field_sha256": canonical_sha256(scores.tolist()),
        "selected_order": order,
        "selected_order_uint16be_sha256": order_hash,
        "target_labels_used": 0,
        "reader_refits": 0,
        "A345_result_available_at_order_freeze": False,
        "A345_candidate_or_prefix_read_before_order_freeze": False,
        "volatile_wall_seconds": time.perf_counter() - started,
        "anchors": {
            "design": anchor(DESIGN, DESIGN_SHA256),
            "selection": anchor(SELECTION, SELECTION_SHA256),
            "implementation": anchor(IMPLEMENTATION, expected_implementation_sha256),
            "preflight": anchor(PREFLIGHT, expected_preflight_sha256),
            "A345_protocol": anchor(A345_PROTOCOL, A345_PROTOCOL_SHA256),
            "A348_result": anchor(A348_RESULT, A348_RESULT_SHA256),
            "A342_result": anchor(A342_RESULT, A342_RESULT_SHA256),
            "runner": anchor(Path(__file__)),
        },
    }
    payload["order_commitment_sha256"] = canonical_sha256(
        {
            "selected_view": SELECTED_VIEW,
            "A345_public_challenge_sha256": A345_PUBLIC_CHALLENGE_SHA256,
            "measurement_sha256": payload["measurement_sha256"],
            "score_field_sha256": payload["score_field_sha256"],
            "selected_order_uint16be_sha256": order_hash,
            "target_labels_used": 0,
            "reader_refits": 0,
        }
    )
    atomic_json(ORDER, payload)
    if A345_RESULT.exists() and A345_RESULT.stat().st_mtime_ns <= ORDER.stat().st_mtime_ns:
        raise RuntimeError("A349 A345 result did not postdate the order commitment")
    return payload


def _build_causal(payload: Mapping[str, Any]) -> dict[str, Any]:
    sys.path.insert(0, str(DOTCAUSAL_SRC))
    from dotcausal.io import CausalReader, CausalWriter

    writer = CausalWriter(api_id="a349val")
    writer._rules = []
    writer.add_rule(
        name="frozen_reader_to_unlabeled_A345_order",
        description="The A348-selected pair reader consumes all A345 public-output direct12 trajectories without refit or target labels.",
        pattern=["A348_frozen_pair_reader", "A345_public_output_direct12_grid"],
        conclusion="A349_pre_result_A345_order",
        confidence_modifier=1.0,
    )
    writer.add_rule(
        name="confirmed_prefix_to_prospective_rank",
        description="Only after dual full-output confirmation is the A345 prefix looked up in the immutable A349 order.",
        pattern=["A349_pre_result_A345_order", "A345_dual_confirmed_prefix"],
        conclusion="A349_prospective_transfer_rank",
        confidence_modifier=1.0,
    )
    writer.add_triplet(
        trigger="A348:frozen_selected_pair_reader",
        mechanism="zero_refit_complete_A345_public_output_direct12_measurement",
        outcome="A349:pre_result_A345_order",
        confidence=1.0,
        source=payload["order_commitment_sha256"],
        quantification=json.dumps(payload["order_gate"], sort_keys=True),
        evidence="target label free exact 4096-cell order",
        domain="prospective W46 reader transfer",
        quality_score=1.0,
    )
    writer.add_triplet(
        trigger="A349:pre_result_A345_order",
        mechanism="postconfirmation_exact_prefix_lookup",
        outcome="A349:prospective_transfer_rank",
        confidence=1.0,
        source=payload["measurement_sha256"],
        quantification=json.dumps(payload["rank_evaluation"], sort_keys=True),
        evidence=payload["evidence_stage"],
        domain="confirmed prospective W46 transfer",
        quality_score=1.0,
    )
    writer.add_triplet(
        trigger="A348:frozen_selected_pair_reader",
        mechanism="materialized_reader_transfer_and_confirmation_closure",
        outcome="A349:prospective_transfer_rank",
        confidence=1.0,
        source="materialized:A349_transfer_chain",
        quantification="exact retained closure",
        evidence=payload["evidence_stage"],
        domain="AI-native retained inference",
        quality_score=1.0,
        is_inferred=True,
    )
    writer.add_cluster(
        name="A349 prospective direct12 transfer",
        entities=[
            "A348:frozen_selected_pair_reader",
            "A349:pre_result_A345_order",
            "A349:prospective_transfer_rank",
        ],
    )
    writer.add_gap(
        subject="A349:prospective_transfer_rank",
        predicate="next_required_object",
        expected_object_type="fresh_recovery_executed_in_target_conditioned_order",
        confidence=1.0,
        suggested_queries=["Execute a new W46/W47 recovery under the frozen target-conditioned reader."],
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
        reader.api_id != "a349val"
        or len(explicit) != 2
        or len(all_rows) != 3
        or len(inferred) != 1
        or len(reader._rules) != 2
        or len(reader._clusters) != 1
        or len(reader._gaps) != 1
    ):
        raise RuntimeError("A349 authentic Causal reopen gate failed")
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
        "personal_semantic_readback": {"terminal_chain": all_rows[-1], "next_gap": reader._gaps[0]},
    }


def evaluate(*, expected_order_sha256: str, expected_a345_result_sha256: str) -> dict[str, Any]:
    if RESULT.exists() or CAUSAL.exists() or REPORT.exists():
        raise FileExistsError("A349 evaluation already exists")
    if file_sha256(ORDER) != expected_order_sha256:
        raise RuntimeError("A349 order artifact hash differs")
    if file_sha256(A345_RESULT) != expected_a345_result_sha256:
        raise RuntimeError("A349 A345 result hash differs")
    order = json.loads(ORDER.read_bytes())
    a345 = json.loads(A345_RESULT.read_bytes())
    confirmation = a345.get("confirmation", {})
    if (
        order.get("A345_result_available_at_order_freeze") is not False
        or order.get("target_labels_used") != 0
        or order.get("reader_refits") != 0
        or confirmation.get("all_blocks_match") is not True
        or confirmation.get("total_cross_implementation_output_bits_checked") != 8192
    ):
        raise RuntimeError("A349 prospective order or A345 confirmation gate failed")
    candidate = int(a345["discovery"]["candidate"])
    prefix = (candidate & 0xFFFFFFFF) >> 20
    if prefix != int(a345["discovery"]["prefix12"]):
        raise RuntimeError("A349 confirmed A345 prefix codec differs")
    selected = A348.exact_order(order["selected_order"], "A349 selected order")
    rank = selected.index(prefix) + 1
    evaluation = {
        "confirmed_prefix12": prefix,
        "confirmed_prefix12_hex": f"{prefix:03x}",
        "rank_one_based": rank,
        "gain_bits_vs_complete_4096_group_cover": math.log2(CELLS / rank),
        "domain_reduction_factor_at_rank": CELLS / rank,
        "complete_group_assignment_bound": rank * (1 << 34),
        "complete_W46_domain_assignments": 1 << 46,
    }
    payload: dict[str, Any] = {
        "schema": "chacha20-round20-w46-direct12-prospective-a345-validation-a349-result-v1",
        "attempt_id": ATTEMPT_ID,
        "evidence_stage": "PROSPECTIVE_ZERO_REFIT_PUBLIC_OUTPUT_DIRECT12_A345_TRANSFER_EVALUATED",
        "order_sha256": expected_order_sha256,
        "order_commitment_sha256": order["order_commitment_sha256"],
        "A345_result_sha256": expected_a345_result_sha256,
        "selected_view": SELECTED_VIEW,
        "order_gate": {
            "complete_direct12_cells": order["complete_direct12_cells"],
            "solver_stages": order["solver_stages"],
            "target_labels_used": order["target_labels_used"],
            "reader_refits": order["reader_refits"],
            "A345_result_available_at_order_freeze": order[
                "A345_result_available_at_order_freeze"
            ],
        },
        "rank_evaluation": evaluation,
        "measurement_sha256": order["measurement_sha256"],
        "score_field_sha256": order["score_field_sha256"],
        "selected_order_uint16be_sha256": order[
            "selected_order_uint16be_sha256"
        ],
        "anchors": {
            "order": anchor(ORDER, expected_order_sha256),
            "A345_result": anchor(A345_RESULT, expected_a345_result_sha256),
            "selection": anchor(SELECTION, SELECTION_SHA256),
            "runner": anchor(Path(__file__)),
        },
    }
    payload["result_commitment_sha256"] = canonical_sha256(payload)
    payload["causal"] = _build_causal(payload)
    atomic_json(RESULT, payload)
    atomic_bytes(
        REPORT,
        (
            "# A349 — prospective direct12 transfer to A345\n\n"
            f"Evidence stage: **{payload['evidence_stage']}**\n\n"
            f"- Frozen reader: **{SELECTED_VIEW}**\n"
            f"- Directly measured A345 cells: **{CELLS:,}**\n"
            f"- A345 confirmed prefix rank: **{rank} / {CELLS}**\n"
            f"- Search-gain bits at rank: **{evaluation['gain_bits_vs_complete_4096_group_cover']:.9f}**\n"
            "- A345 target labels / reader refits before order freeze: **0 / 0**\n"
            "- Authentic AI-native Causal readback: **2 explicit + 1 inferred**\n"
        ).encode(),
    )
    return payload


def analyze() -> dict[str, Any]:
    return {
        "attempt_id": ATTEMPT_ID,
        "design_sha256": DESIGN_SHA256,
        "selection_sha256": SELECTION_SHA256,
        "implementation_frozen": IMPLEMENTATION.exists(),
        "preflight_complete": PREFLIGHT.exists(),
        "slice_measurement_count": len(list(MEASUREMENTS.glob("slice_*.json.zst")))
        if MEASUREMENTS.exists()
        else 0,
        "order_frozen": ORDER.exists(),
        "result_complete": RESULT.exists(),
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    action = parser.add_mutually_exclusive_group(required=True)
    action.add_argument("--analyze", action="store_true")
    action.add_argument("--freeze-implementation", action="store_true")
    action.add_argument("--preflight", action="store_true")
    action.add_argument("--measure", action="store_true")
    action.add_argument("--evaluate", action="store_true")
    parser.add_argument("--expected-implementation-sha256")
    parser.add_argument("--expected-preflight-sha256")
    parser.add_argument("--expected-order-sha256")
    parser.add_argument("--expected-a345-result-sha256")
    args = parser.parse_args()
    if args.freeze_implementation:
        payload = freeze_implementation()
    elif args.preflight:
        if not args.expected_implementation_sha256:
            parser.error("--preflight requires --expected-implementation-sha256")
        payload = preflight(expected_implementation_sha256=args.expected_implementation_sha256)
    elif args.measure:
        if not args.expected_implementation_sha256 or not args.expected_preflight_sha256:
            parser.error("--measure requires implementation and preflight hashes")
        payload = measure(
            expected_implementation_sha256=args.expected_implementation_sha256,
            expected_preflight_sha256=args.expected_preflight_sha256,
        )
    elif args.evaluate:
        if not args.expected_order_sha256 or not args.expected_a345_result_sha256:
            parser.error("--evaluate requires order and A345 result hashes")
        payload = evaluate(
            expected_order_sha256=args.expected_order_sha256,
            expected_a345_result_sha256=args.expected_a345_result_sha256,
        )
    else:
        payload = analyze()
    print(json.dumps(payload, indent=2, sort_keys=True), flush=True)


if __name__ == "__main__":
    main()

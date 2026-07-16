#!/usr/bin/env python3
"""A356: freeze a corrected word0-prefix Reader order on the unresolved A345 target."""

from __future__ import annotations

import argparse
import concurrent.futures
import importlib.util
import inspect
import json
import os
import sys
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
ARTIFACTS = RESEARCH / "artifacts/a356_chacha20_r20_w46_corrected_group_a345"
MEASUREMENTS = RESULTS / "chacha20_round20_w46_corrected_group_a345_transfer_a356_v1"

DESIGN = CONFIGS / "chacha20_round20_w46_corrected_group_a345_transfer_a356_design_v1.json"
IMPLEMENTATION = CONFIGS / "chacha20_round20_w46_corrected_group_a345_transfer_a356_implementation_v1.json"
MEASUREMENT = RESULTS / "chacha20_round20_w46_corrected_group_a345_transfer_a356_measurement_v1.json"
ORDER = RESULTS / "chacha20_round20_w46_corrected_group_a345_transfer_a356_order_v1.json"
CAUSAL = ORDER.with_suffix(".causal")
REPORT = RESULTS / "chacha20_round20_w46_corrected_group_a345_transfer_a356_order_v1.md"
TEST = ROOT / "tests/test_chacha20_round20_w46_corrected_group_a345_transfer_a356.py"
REPRO = ROOT / "scripts/reproduce_chacha20_round20_w46_corrected_group_a345_transfer_a356.sh"

A355_RUNNER = RESEARCH / "experiments/chacha20_round20_w46_corrected_group_direct12_reader_a355.py"
A355_RESULT = RESULTS / "chacha20_round20_w46_corrected_group_direct12_reader_a355_v1.json"
A345_PROTOCOL = CONFIGS / "chacha20_round20_fresh_w46_factor2_replication_a345_v1.json"
A345_RESULT = RESULTS / "chacha20_round20_fresh_w46_factor2_replication_a345_v1.json"
A349_PREFLIGHT = (
    RESULTS / "chacha20_round20_w46_direct12_prospective_a345_validation_a349_preflight_v1.json"
)
A349_BASE_CNF = (
    RESEARCH
    / "artifacts/a349_chacha20_r20_w46_direct12_a345/a349_a345_public_output_w46_b1.cnf"
)

ATTEMPT_ID = "A356"
DESIGN_SHA256 = "776e0a33fe1f88c7e3c785b2e422630802eb672f35321034ee6b4d2c43ad1f05"
WIDTH = 46
CELLS = 4096
COARSE_CELLS = 256
SLICES = tuple(range(16))
HORIZONS = [1, 2, 4, 8]
WATCHDOG_SECONDS = 2.0
WORKERS = 8
ZSTD_LEVEL = 10
DOTCAUSAL_SRC = Path("/Users/bhkmie/Documents/Forschung/O1/vendor/fabel/dotcausal_package/src")


def load_module(path: Path, name: str) -> Any:
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot import A356 dependency {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


A355 = load_module(A355_RUNNER, "a356_a355")
A348 = A355.A348
file_sha256 = A355.file_sha256
canonical_sha256 = A355.canonical_sha256
canonical_bytes = A355.canonical_bytes
atomic_json = A355.atomic_json
atomic_bytes = A355.atomic_bytes
relative = A355.relative
path_from_ref = A355.path_from_ref
anchor = A355.anchor
sha256 = A355.sha256


def assert_a345_result_absent() -> None:
    if A345_RESULT.exists():
        raise RuntimeError("A356 prospective freeze requires the A345 result to remain absent")


def load_design() -> dict[str, Any]:
    if file_sha256(DESIGN) != DESIGN_SHA256:
        raise RuntimeError("A356 design hash differs")
    value = json.loads(DESIGN.read_bytes())
    measurement = value.get("measurement_contract", {})
    boundary = value.get("information_boundary", {})
    if (
        value.get("schema")
        != "chacha20-round20-w46-corrected-group-a345-transfer-a356-design-v1"
        or value.get("attempt_id") != ATTEMPT_ID
        or value.get("design_state")
        != "frozen_before_A355_result_and_before_A345_result_candidate_or_prefix"
        or measurement.get("low4_fixed_unit_coordinates") != [23, 22, 21, 20]
        or measurement.get("high8_assumption_coordinates")
        != [31, 30, 29, 28, 27, 26, 25, 24]
        or measurement.get("complete_direct_prefix_cells") != CELLS
        or measurement.get("measurement_must_close_before_A355_selected_view_is_read")
        is not True
        or boundary.get("A355_result_available_at_design_freeze") is not False
        or boundary.get("A345_result_available_at_design_freeze") is not False
        or boundary.get("target_labels_from_A345_used") != 0
        or boundary.get("reader_refits_on_A345") != 0
    ):
        raise RuntimeError("A356 frozen design semantics differ")
    sources = value["source_anchors"]
    for name, path_value in sources.items():
        if name.endswith("_path"):
            stem = name.removesuffix("_path")
            anchor(ROOT / path_value, sources[f"{stem}_sha256"])
    protocol = json.loads(A345_PROTOCOL.read_bytes())
    if protocol.get("public_challenge_sha256") != sources["A345_public_challenge_sha256"]:
        raise RuntimeError("A356 public A345 challenge hash differs")
    return value


def freeze_implementation() -> dict[str, Any]:
    if IMPLEMENTATION.exists():
        raise FileExistsError("A356 implementation already exists")
    if any(path.exists() for path in (MEASUREMENT, ORDER, CAUSAL, REPORT, MEASUREMENTS)):
        raise RuntimeError("A356 implementation must precede every measurement")
    assert_a345_result_absent()
    load_design()
    if not TEST.exists() or not REPRO.exists():
        raise FileNotFoundError("A356 test and reproducer must exist before freeze")
    payload: dict[str, Any] = {
        "schema": "chacha20-round20-w46-corrected-group-a345-transfer-a356-implementation-v1",
        "attempt_id": ATTEMPT_ID,
        "commitment_state": "frozen_before_A356_measurement_and_before_A345_result",
        "design_sha256": DESIGN_SHA256,
        "A345_result_available_at_implementation_freeze": False,
        "anchors": {
            "design": anchor(DESIGN, DESIGN_SHA256),
            "runner": anchor(Path(__file__)),
            "test": anchor(TEST),
            "reproducer": anchor(REPRO),
            "A345_protocol": anchor(A345_PROTOCOL),
            "A349_preflight": anchor(A349_PREFLIGHT),
            "A349_base_CNF": anchor(A349_BASE_CNF),
        },
    }
    payload["implementation_commitment_sha256"] = canonical_sha256(payload)
    atomic_json(IMPLEMENTATION, payload)
    assert_a345_result_absent()
    return payload


def load_implementation(expected_sha256: str) -> dict[str, Any]:
    if file_sha256(IMPLEMENTATION) != expected_sha256:
        raise RuntimeError("A356 implementation hash differs")
    value = json.loads(IMPLEMENTATION.read_bytes())
    if (
        value.get("schema")
        != "chacha20-round20-w46-corrected-group-a345-transfer-a356-implementation-v1"
        or value.get("commitment_state")
        != "frozen_before_A356_measurement_and_before_A345_result"
        or value.get("A345_result_available_at_implementation_freeze") is not False
        or value.get("design_sha256") != DESIGN_SHA256
    ):
        raise RuntimeError("A356 implementation semantics differ")
    expected = {
        "design": DESIGN,
        "runner": Path(__file__),
        "test": TEST,
        "reproducer": REPRO,
        "A345_protocol": A345_PROTOCOL,
        "A349_preflight": A349_PREFLIGHT,
        "A349_base_CNF": A349_BASE_CNF,
    }
    for name, path in expected.items():
        row = value["anchors"][name]
        if row.get("path") != relative(path) or row.get("sha256") != file_sha256(path):
            raise RuntimeError(f"A356 implementation anchor differs: {name}")
    unsigned = {key: item for key, item in value.items() if key != "implementation_commitment_sha256"}
    if value.get("implementation_commitment_sha256") != canonical_sha256(unsigned):
        raise RuntimeError("A356 implementation commitment differs")
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
        raise RuntimeError("A356 compressed slice hash differs")
    raw = zstandard.ZstdDecompressor().decompress(compressed)
    if ledger is not None and sha256(raw) != ledger["raw_sha256"]:
        raise RuntimeError("A356 raw slice hash differs")
    value = json.loads(raw)
    if canonical_bytes(value) != raw:
        raise RuntimeError("A356 slice is not canonical")
    return value


def _prepare_slices(preflight: Mapping[str, Any]) -> list[dict[str, Any]]:
    base_raw = A349_BASE_CNF.read_bytes()
    mapping = [int(value) for value in preflight["source_one_literals_bit0_upward"]]
    ARTIFACTS.mkdir(parents=True, exist_ok=True)
    rows = []
    for low4 in SLICES:
        cnf_path, measurement_path = _slice_paths(low4)
        expected = A355.render_slice_cnf(base_raw, low4=low4, source_mapping=mapping)
        if cnf_path.exists() and cnf_path.read_bytes() != expected:
            raise RuntimeError(f"A356 existing slice CNF differs: {low4}")
        if not cnf_path.exists():
            atomic_bytes(cnf_path, expected)
        rows.append(
            {
                "low4": low4,
                "fixed_unit_literals": A355.low4_unit_literals(low4, mapping),
                "cnf": anchor(cnf_path),
                "measurement_path": measurement_path,
            }
        )
    return rows


def _validate_slice(value: Mapping[str, Any], low4: int) -> None:
    run = value.get("run", {})
    if (
        value.get("schema")
        != "chacha20-round20-w46-corrected-group-a345-transfer-a356-slice-v1"
        or value.get("attempt_id") != ATTEMPT_ID
        or value.get("low4") != low4
        or value.get("target_label_available_to_measurement") is not False
        or value.get("selected_A355_view_available_to_measurement") is not False
        or value.get("complete_candidate_cover") is not True
        or len(run.get("cells", [])) != COARSE_CELLS
        or not 1 <= len(run.get("stages", [])) <= COARSE_CELLS * len(HORIZONS)
        or run.get("all_watchdogs_clear") is not True
    ):
        raise RuntimeError(f"A356 slice measurement gate failed: {low4}")


def _run_slice(row: Mapping[str, Any], *, helper: Path, key_mapping: Sequence[int]) -> dict[str, Any]:
    low4 = int(row["low4"])
    path = Path(row["measurement_path"])
    if path.exists():
        value = _read_measurement(path)
        _validate_slice(value, low4)
        return {"low4": low4, "resumed": True, "ledger": _write_measurement(path, value)}
    started = time.perf_counter()
    raw_run = A348.WRAPPER.run_fresh_clause_identity(
        helper=helper,
        cnf=path_from_ref(row["cnf"]["path"]),
        mode=f"A356_A345_group_direct12_low4_{low4:02x}",
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
        "schema": "chacha20-round20-w46-corrected-group-a345-transfer-a356-slice-v1",
        "attempt_id": ATTEMPT_ID,
        "low4": low4,
        "fixed_unit_literals": list(row["fixed_unit_literals"]),
        "cnf_sha256": row["cnf"]["sha256"],
        "run": stable,
        "volatile_process_elapsed_seconds": time.perf_counter() - started,
        "target_label_available_to_measurement": False,
        "selected_A355_view_available_to_measurement": False,
        "label_used_for_feature_construction_or_scoring": False,
        "complete_candidate_cover": len(stable.get("cells", [])) == COARSE_CELLS,
    }
    _validate_slice(value, low4)
    return {"low4": low4, "resumed": False, "ledger": _write_measurement(path, value)}


def measure_unlabeled(*, expected_implementation_sha256: str) -> dict[str, Any]:
    if MEASUREMENT.exists() or ORDER.exists() or CAUSAL.exists() or REPORT.exists():
        raise FileExistsError("A356 measurement/order already exists")
    assert_a345_result_absent()
    design = load_design()
    implementation = load_implementation(expected_implementation_sha256)
    preflight = json.loads(A349_PREFLIGHT.read_bytes())
    source_mapping = [int(value) for value in preflight["source_one_literals_bit0_upward"]]
    synthetic_mapping = A355.corrected_synthetic_mapping(source_mapping)
    rows = _prepare_slices(preflight)
    _a275, _model, _a291, _indices, helper = A348.A340.A296._reader_stack()  # noqa: SLF001
    A348.WRAPPER._load_base_wrapper()  # noqa: SLF001
    MEASUREMENTS.mkdir(parents=True, exist_ok=True)
    started = time.perf_counter()
    completed = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=WORKERS) as executor:
        futures = [
            executor.submit(_run_slice, row, helper=helper, key_mapping=synthetic_mapping)
            for row in rows
        ]
        for future in concurrent.futures.as_completed(futures):
            completed.append(future.result())
    completed.sort(key=lambda row: row["low4"])
    if [row["low4"] for row in completed] != list(SLICES):
        raise RuntimeError("A356 complete slice cover differs")
    status_counts = {status: 0 for status in ("sat", "unknown", "unsat")}
    stage_count = 0
    ledgers = []
    for row in completed:
        value = _read_measurement(path_from_ref(row["ledger"]["path"]), row["ledger"])
        _validate_slice(value, row["low4"])
        stage_count += len(value["run"]["stages"])
        for cell in value["run"]["cells"]:
            status_counts[cell["final_status"]] += 1
        ledgers.append({**row["ledger"], "low4": row["low4"], "resumed": row["resumed"]})
    if sum(status_counts.values()) != CELLS:
        raise RuntimeError("A356 status cover differs")
    summary = {
        "complete_direct12_cells": CELLS,
        "low4_slices": len(SLICES),
        "high8_cells_per_slice": COARSE_CELLS,
        "solver_stages": stage_count,
        "status_counts": status_counts,
        "measured_assignment_bit_interval": [20, 31],
        "target_labels_used": 0,
        "reader_refits": 0,
        "candidate_assignments_executed": 0,
        "A355_selected_view_read": False,
    }
    payload: dict[str, Any] = {
        "schema": "chacha20-round20-w46-corrected-group-a345-transfer-a356-measurement-v1",
        "attempt_id": ATTEMPT_ID,
        "evidence_stage": "PRE_A345_RESULT_COMPLETE_UNLABELED_CORRECTED_GROUP_MEASUREMENT",
        "design_sha256": DESIGN_SHA256,
        "implementation_sha256": expected_implementation_sha256,
        "implementation_commitment_sha256": implementation[
            "implementation_commitment_sha256"
        ],
        "A345_public_challenge_sha256": design["source_anchors"]["A345_public_challenge_sha256"],
        "measurement_summary": summary,
        "measurement_ledger": ledgers,
        "synthetic_reader_mapping_sha256": canonical_sha256(synthetic_mapping),
        "volatile_wall_seconds": time.perf_counter() - started,
        "anchors": {
            "design": anchor(DESIGN, DESIGN_SHA256),
            "implementation": anchor(IMPLEMENTATION, expected_implementation_sha256),
            "A345_protocol": anchor(A345_PROTOCOL),
            "A349_preflight": anchor(A349_PREFLIGHT),
            "A349_base_CNF": anchor(A349_BASE_CNF),
            "runner": anchor(Path(__file__)),
        },
    }
    payload["measurement_commitment_sha256"] = canonical_sha256(
        {
            "evidence_stage": payload["evidence_stage"],
            "A345_public_challenge_sha256": payload["A345_public_challenge_sha256"],
            "measurement_summary": summary,
            "measurement_ledger": ledgers,
            "synthetic_reader_mapping_sha256": payload["synthetic_reader_mapping_sha256"],
        }
    )
    assert_a345_result_absent()
    atomic_json(MEASUREMENT, payload)
    return payload


def _measurement_map(payload: Mapping[str, Any]) -> dict[int, dict[str, Any]]:
    result = {
        int(row["low4"]): _read_measurement(path_from_ref(row["path"]), row)
        for row in payload["measurement_ledger"]
    }
    if set(result) != set(SLICES):
        raise RuntimeError("A356 measurement ledger slice cover differs")
    for low4, value in result.items():
        _validate_slice(value, low4)
    return result


def build_causal(payload: Mapping[str, Any]) -> dict[str, Any]:
    sys.path.insert(0, str(DOTCAUSAL_SRC))
    from dotcausal.io import CausalReader, CausalWriter

    terminal = "A356:frozen_corrected_A345_word0_prefix_order"
    writer = CausalWriter(api_id="a356xfr")
    writer._rules = []
    writer.add_rule(
        name="unlabeled_grid_to_selected_reader_field",
        description="Only after all corrected A345 word0-prefix cells close is the independently calibrated A355 Reader identity loaded without refit.",
        pattern=["A356_complete_unlabeled_group_grid", "A355_frozen_selected_view"],
        conclusion="A356_selected_score_field",
        confidence_modifier=1.0,
    )
    writer.add_rule(
        name="score_field_to_prospective_order",
        description="Descending score with ascending cell tie-break freezes the complete order before any A345 candidate or prefix exists.",
        pattern=["A356_selected_score_field", "A356_fixed_tie_rule"],
        conclusion=terminal,
        confidence_modifier=1.0,
    )
    writer.add_triplet(
        trigger="A345:public_output_CNF",
        mechanism="corrected_coordinates20_through31_complete_unlabeled_measurement",
        outcome="A356:complete_word0_prefix_grid",
        confidence=1.0,
        source=payload["measurement_sha256"],
        quantification=json.dumps(payload["measurement_gate"], sort_keys=True),
        evidence="4096 cells before selected Reader access",
        domain="prospective ChaCha20 R20 W46 transfer",
        quality_score=1.0,
    )
    writer.add_triplet(
        trigger="A356:complete_word0_prefix_grid",
        mechanism="zero_refit_A355_selected_reader",
        outcome="A356:selected_corrected_group_score_field",
        confidence=1.0,
        source=payload["A355_result_sha256"],
        quantification=json.dumps(payload["selected_view"], sort_keys=True),
        evidence="A355 calibration transferred unchanged",
        domain="prospective Reader transfer",
        quality_score=1.0,
    )
    writer.add_triplet(
        trigger="A356:selected_corrected_group_score_field",
        mechanism="descending_score_then_ascending_cell_id",
        outcome=terminal,
        confidence=1.0,
        source=payload["order_commitment_sha256"],
        quantification=payload["selected_order_uint16be_sha256"],
        evidence=payload["evidence_stage"],
        domain="frozen recovery order",
        quality_score=1.0,
    )
    writer.add_triplet(
        trigger="A345:public_output_CNF",
        mechanism="materialized_corrected_measurement_transfer_order_chain",
        outcome=terminal,
        confidence=1.0,
        source="materialized:A356_corrected_transfer_chain",
        quantification="exact retained closure",
        evidence=payload["evidence_stage"],
        domain="AI-native retained inference",
        quality_score=1.0,
        is_inferred=True,
    )
    writer.add_cluster(
        name="A356 corrected A345 transfer",
        entities=[
            "A345:public_output_CNF",
            "A356:complete_word0_prefix_grid",
            "A356:selected_corrected_group_score_field",
            terminal,
        ],
    )
    writer.add_gap(
        subject=terminal,
        predicate="next_required_object",
        expected_object_type="prospective_recovery_or_confirmed_A345_rank",
        confidence=1.0,
        suggested_queries=["Execute or evaluate the frozen corrected order after independent confirmation."],
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
        reader.api_id != "a356xfr"
        or len(explicit) != 3
        or len(all_rows) != 4
        or len(inferred) != 1
        or len(reader._rules) != 2
        or len(reader._clusters) != 1
        or len(reader._gaps) != 1
    ):
        raise RuntimeError("A356 authentic Causal reopen gate failed")
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
            "transfer_relation": explicit[1],
            "terminal_chain": all_rows[-1],
            "next_gap": reader._gaps[0],
        },
    }


def freeze_order(
    *, expected_implementation_sha256: str, expected_measurement_sha256: str, expected_a355_result_sha256: str
) -> dict[str, Any]:
    if ORDER.exists() or CAUSAL.exists() or REPORT.exists():
        raise FileExistsError("A356 order already exists")
    assert_a345_result_absent()
    design = load_design()
    implementation = load_implementation(expected_implementation_sha256)
    if file_sha256(MEASUREMENT) != expected_measurement_sha256:
        raise RuntimeError("A356 measurement artifact hash differs")
    if file_sha256(A355_RESULT) != expected_a355_result_sha256:
        raise RuntimeError("A356 A355 result artifact hash differs")
    measurement = json.loads(MEASUREMENT.read_bytes())
    a355 = json.loads(A355_RESULT.read_bytes())
    if (
        measurement.get("measurement_summary", {}).get("A355_selected_view_read") is not False
        or measurement.get("measurement_summary", {}).get("target_labels_used") != 0
        or measurement.get("measurement_summary", {}).get("complete_direct12_cells") != CELLS
        or a355.get("confirmed_prefix_revealed_only_after_complete_measurement") is not True
    ):
        raise RuntimeError("A356 measurement or A355 selection gate failed")
    measurements = _measurement_map(measurement)
    selected_name = str(a355["selected_view"]["name"])
    if selected_name == "hard_terminal_partition":
        order = A355._hard_partition(  # noqa: SLF001
            measurements, design["source_anchors"]["A345_public_challenge_sha256"]
        )
        score_sha = None
    else:
        _selection, _a272, model, groups = A348.A341.reconstruct_known_key_selection(
            json.loads(A348.A341.DESIGN.read_bytes())
        )
        score_fields = A348._all_view_scores(measurements, model, groups)  # noqa: SLF001
        if selected_name not in score_fields:
            raise RuntimeError("A356 A355 selected view is unavailable")
        field = np.asarray(score_fields[selected_name], dtype=np.float64)
        order = A348._rank_order(field)  # noqa: SLF001
        score_sha = canonical_sha256(field.tolist())
    order_hash = sha256(b"".join(cell.to_bytes(2, "big") for cell in order))
    assert_a345_result_absent()
    payload: dict[str, Any] = {
        "schema": "chacha20-round20-w46-corrected-group-a345-transfer-a356-order-v1",
        "attempt_id": ATTEMPT_ID,
        "evidence_stage": "PRE_A345_RESULT_ZERO_REFIT_CORRECTED_GROUP_ORDER_FROZEN",
        "design_sha256": DESIGN_SHA256,
        "implementation_sha256": expected_implementation_sha256,
        "implementation_commitment_sha256": implementation[
            "implementation_commitment_sha256"
        ],
        "measurement_sha256": expected_measurement_sha256,
        "measurement_commitment_sha256": measurement["measurement_commitment_sha256"],
        "A355_result_sha256": expected_a355_result_sha256,
        "A355_selection_commitment_sha256": a355["selection_commitment_sha256"],
        "selected_view": a355["selected_view"],
        "selected_score_field_sha256": score_sha,
        "selected_order": order,
        "selected_order_uint16be_sha256": order_hash,
        "measurement_gate": measurement["measurement_summary"],
        "target_labels_used": 0,
        "reader_refits": 0,
        "candidate_assignments_executed": 0,
        "A345_result_available_at_order_freeze": False,
        "A345_candidate_or_prefix_read_before_order_freeze": False,
        "anchors": {
            "design": anchor(DESIGN, DESIGN_SHA256),
            "implementation": anchor(IMPLEMENTATION, expected_implementation_sha256),
            "measurement": anchor(MEASUREMENT, expected_measurement_sha256),
            "A355_result": anchor(A355_RESULT, expected_a355_result_sha256),
            "A345_protocol": anchor(A345_PROTOCOL),
            "runner": anchor(Path(__file__)),
        },
    }
    payload["order_commitment_sha256"] = canonical_sha256(
        {
            "evidence_stage": payload["evidence_stage"],
            "A345_public_challenge_sha256": design["source_anchors"][
                "A345_public_challenge_sha256"
            ],
            "measurement_commitment_sha256": payload["measurement_commitment_sha256"],
            "A355_selection_commitment_sha256": payload["A355_selection_commitment_sha256"],
            "selected_view": payload["selected_view"],
            "selected_score_field_sha256": score_sha,
            "selected_order_uint16be_sha256": order_hash,
            "target_labels_used": 0,
            "reader_refits": 0,
        }
    )
    payload["causal"] = build_causal(payload)
    atomic_json(ORDER, payload)
    assert_a345_result_absent()
    atomic_bytes(
        REPORT,
        (
            "# A356 — corrected group-coordinate transfer to unresolved A345\n\n"
            f"- Selected A355 Reader: **{selected_name}**\n"
            f"- Exact A345 word0-prefix cells: **{CELLS:,}**\n"
            f"- Frozen order SHA-256: **{order_hash}**\n"
            "- A345 target labels / Reader refits / candidate executions: **0 / 0 / 0**\n"
            "- A345 result or prefix available at freeze: **no**\n"
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
        "slice_measurement_count": len(list(MEASUREMENTS.glob("slice_*.json.zst")))
        if MEASUREMENTS.exists()
        else 0,
        "measurement_complete": MEASUREMENT.exists(),
        "measurement_sha256": file_sha256(MEASUREMENT) if MEASUREMENT.exists() else None,
        "order_complete": ORDER.exists(),
        "order_sha256": file_sha256(ORDER) if ORDER.exists() else None,
        "A345_result_available": A345_RESULT.exists(),
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    action = parser.add_mutually_exclusive_group(required=True)
    action.add_argument("--analyze", action="store_true")
    action.add_argument("--freeze-implementation", action="store_true")
    action.add_argument("--measure-unlabeled", action="store_true")
    action.add_argument("--freeze-order", action="store_true")
    parser.add_argument("--expected-implementation-sha256")
    parser.add_argument("--expected-measurement-sha256")
    parser.add_argument("--expected-a355-result-sha256")
    args = parser.parse_args()
    if args.freeze_implementation:
        payload = freeze_implementation()
    elif args.measure_unlabeled:
        if not args.expected_implementation_sha256:
            parser.error("--measure-unlabeled requires --expected-implementation-sha256")
        payload = measure_unlabeled(
            expected_implementation_sha256=args.expected_implementation_sha256
        )
    elif args.freeze_order:
        required = (
            args.expected_implementation_sha256,
            args.expected_measurement_sha256,
            args.expected_a355_result_sha256,
        )
        if not all(required):
            parser.error("--freeze-order requires all three expected SHA-256 values")
        payload = freeze_order(
            expected_implementation_sha256=args.expected_implementation_sha256,
            expected_measurement_sha256=args.expected_measurement_sha256,
            expected_a355_result_sha256=args.expected_a355_result_sha256,
        )
    else:
        payload = analyze()
    print(json.dumps(payload, indent=2, sort_keys=True), flush=True)


if __name__ == "__main__":
    main()

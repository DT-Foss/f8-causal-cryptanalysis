#!/usr/bin/env python3
"""A355: measure the exact W46 Metal group coordinates, word0 bits 20 through 31."""

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
ARTIFACTS = RESEARCH / "artifacts/a355_chacha20_r20_w46_corrected_group_direct12"
MEASUREMENTS = RESULTS / "chacha20_round20_w46_corrected_group_direct12_reader_a355_v1"

DESIGN = CONFIGS / "chacha20_round20_w46_corrected_group_direct12_reader_a355_design_v1.json"
IMPLEMENTATION = (
    CONFIGS / "chacha20_round20_w46_corrected_group_direct12_reader_a355_implementation_v1.json"
)
RESULT = RESULTS / "chacha20_round20_w46_corrected_group_direct12_reader_a355_v1.json"
CAUSAL = RESULT.with_suffix(".causal")
REPORT = RESULTS / "chacha20_round20_w46_corrected_group_direct12_reader_a355_v1.md"
TEST = ROOT / "tests/test_chacha20_round20_w46_corrected_group_direct12_reader_a355.py"
REPRO = ROOT / "scripts/reproduce_chacha20_round20_w46_corrected_group_direct12_reader_a355.sh"

A348_RUNNER = RESEARCH / "experiments/chacha20_round20_w46_direct12_sliced_reader_a348.py"
A354_RESULT = RESULTS / "chacha20_round20_w46_direct12_coordinate_codec_audit_a354_v1.json"
A325_RESULT = RESULTS / "chacha20_round20_holdout_selected_w46_recovery_a325_v1.json"
A340_PREFLIGHT = (
    RESULTS / "chacha20_round20_w46_target_conditioned_causal_order_a340_preflight_v1.json"
)
A340_BASE_CNF = (
    RESEARCH
    / "artifacts/a340_chacha20_r20_w46_target_conditioned_causal/a340_chacha20_r20_w46_b1_base.cnf"
)

ATTEMPT_ID = "A355"
DESIGN_SHA256 = "0bcf7533fa8a9f2ef33546d9aec8d190bf1e1435b9dd9eb5dbec4a0399cc5aae"
WIDTH = 46
PREFIX_BITS = 12
HIGH_BITS = 8
LOW_BITS = 4
CELLS = 1 << PREFIX_BITS
COARSE_CELLS = 1 << HIGH_BITS
SLICES = tuple(range(1 << LOW_BITS))
LOW4_COORDINATES = (23, 22, 21, 20)
HIGH8_COORDINATES = (31, 30, 29, 28, 27, 26, 25, 24)
SYNTHETIC_SOURCE_INDICES = (*range(12), *range(24, 32))
HORIZONS = [1, 2, 4, 8]
WATCHDOG_SECONDS = 2.0
WORKERS = 8
ZSTD_LEVEL = 10
DOTCAUSAL_SRC = Path("/Users/bhkmie/Documents/Forschung/O1/vendor/fabel/dotcausal_package/src")


def load_module(path: Path, name: str) -> Any:
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot import A355 dependency {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


A348 = load_module(A348_RUNNER, "a355_a348")
file_sha256 = A348.file_sha256
canonical_sha256 = A348.canonical_sha256
canonical_bytes = A348.canonical_bytes
atomic_json = A348.atomic_json
atomic_bytes = A348.atomic_bytes
relative = A348.relative
path_from_ref = A348.path_from_ref
anchor = A348.anchor
sha256 = A348.sha256


def load_design() -> dict[str, Any]:
    if file_sha256(DESIGN) != DESIGN_SHA256:
        raise RuntimeError("A355 design hash differs")
    value = json.loads(DESIGN.read_bytes())
    measurement = value.get("measurement_contract", {})
    boundary = value.get("information_boundary", {})
    if (
        value.get("schema")
        != "chacha20-round20-w46-corrected-group-direct12-reader-a355-design-v1"
        or value.get("attempt_id") != ATTEMPT_ID
        or value.get("design_state")
        != "post_A354_corrected_group_coordinate_contract_frozen_before_measurement"
        or measurement.get("complete_direct_prefix_cells") != CELLS
        or measurement.get("low4_fixed_unit_coordinates") != list(LOW4_COORDINATES)
        or measurement.get("high8_assumption_coordinates") != list(HIGH8_COORDINATES)
        or measurement.get("synthetic_reader_mapping_source_indices")
        != list(SYNTHETIC_SOURCE_INDICES)
        or measurement.get("conflict_horizons") != HORIZONS
        or boundary.get("target_labels_used_during_measurement") != 0
        or boundary.get("candidate_assignments_executed") != 0
        or boundary.get("all_4096_cells_must_close_before_confirmed_prefix_lookup") is not True
    ):
        raise RuntimeError("A355 frozen design semantics differ")
    sources = value["source_anchors"]
    for name, path_value in sources.items():
        if name.endswith("_path"):
            stem = name.removesuffix("_path")
            anchor(ROOT / path_value, sources[f"{stem}_sha256"])
    return value


def freeze_implementation() -> dict[str, Any]:
    if IMPLEMENTATION.exists():
        raise FileExistsError("A355 implementation already exists")
    if RESULT.exists() or CAUSAL.exists() or REPORT.exists() or MEASUREMENTS.exists():
        raise RuntimeError("A355 implementation must precede every measurement")
    load_design()
    if not TEST.exists() or not REPRO.exists():
        raise FileNotFoundError("A355 test and reproducer must exist before freeze")
    payload: dict[str, Any] = {
        "schema": "chacha20-round20-w46-corrected-group-direct12-reader-a355-implementation-v1",
        "attempt_id": ATTEMPT_ID,
        "commitment_state": "frozen_before_any_corrected_group_direct12_measurement",
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
        raise RuntimeError("A355 implementation artifact hash differs")
    value = json.loads(IMPLEMENTATION.read_bytes())
    if (
        value.get("schema")
        != "chacha20-round20-w46-corrected-group-direct12-reader-a355-implementation-v1"
        or value.get("commitment_state")
        != "frozen_before_any_corrected_group_direct12_measurement"
        or value.get("design_sha256") != DESIGN_SHA256
    ):
        raise RuntimeError("A355 implementation semantics differ")
    expected = {"design": DESIGN, "runner": Path(__file__), "test": TEST, "reproducer": REPRO}
    for name, path in expected.items():
        row = value.get("anchors", {}).get(name, {})
        if row.get("path") != relative(path) or row.get("sha256") != file_sha256(path):
            raise RuntimeError(f"A355 implementation anchor differs: {name}")
    unsigned = {key: item for key, item in value.items() if key != "implementation_commitment_sha256"}
    if value.get("implementation_commitment_sha256") != canonical_sha256(unsigned):
        raise RuntimeError("A355 implementation commitment differs")
    return value


def corrected_synthetic_mapping(source_mapping: Sequence[int]) -> list[int]:
    source = [int(value) for value in source_mapping]
    if len(source) != WIDTH or len({abs(value) for value in source}) != WIDTH:
        raise ValueError("A355 source mapping differs")
    result = [source[index] for index in SYNTHETIC_SOURCE_INDICES]
    if len(result) != 20 or len({abs(value) for value in result}) != 20:
        raise RuntimeError("A355 corrected synthetic mapping aliases")
    return result


def low4_unit_literals(low4: int, source_mapping: Sequence[int]) -> list[int]:
    if low4 not in SLICES or len(source_mapping) != WIDTH:
        raise ValueError("A355 low4 slice or source mapping differs")
    result = []
    for offset, coordinate in enumerate(LOW4_COORDINATES):
        one_literal = int(source_mapping[coordinate])
        bit = (low4 >> (LOW_BITS - 1 - offset)) & 1
        result.append(one_literal if bit else -one_literal)
    if len({abs(value) for value in result}) != LOW_BITS:
        raise RuntimeError("A355 low4 unit variables alias")
    return result


def render_slice_cnf(base_raw: bytes, *, low4: int, source_mapping: Sequence[int]) -> bytes:
    variables, clauses, body = A348._base_cnf_parts(base_raw)  # noqa: SLF001
    units = low4_unit_literals(low4, source_mapping)
    suffix = b"".join(f"{literal} 0\n".encode("ascii") for literal in units)
    return f"p cnf {variables} {clauses + len(units)}\n".encode() + body + suffix


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
        raise RuntimeError("A355 compressed slice hash differs")
    raw = zstandard.ZstdDecompressor().decompress(compressed)
    if ledger is not None and sha256(raw) != ledger["raw_sha256"]:
        raise RuntimeError("A355 raw slice hash differs")
    value = json.loads(raw)
    if canonical_bytes(value) != raw:
        raise RuntimeError("A355 slice measurement is not canonical")
    return value


def _prepare_slices(preflight: Mapping[str, Any]) -> list[dict[str, Any]]:
    base_raw = A340_BASE_CNF.read_bytes()
    mapping = [int(value) for value in preflight["source_one_literals_bit0_upward"]]
    ARTIFACTS.mkdir(parents=True, exist_ok=True)
    rows = []
    for low4 in SLICES:
        cnf_path, measurement_path = _slice_paths(low4)
        expected = render_slice_cnf(base_raw, low4=low4, source_mapping=mapping)
        if cnf_path.exists() and cnf_path.read_bytes() != expected:
            raise RuntimeError(f"A355 existing slice CNF differs: {low4}")
        if not cnf_path.exists():
            atomic_bytes(cnf_path, expected)
        rows.append(
            {
                "low4": low4,
                "low4_binary": f"{low4:04b}",
                "unit_literals": low4_unit_literals(low4, mapping),
                "cnf": anchor(cnf_path),
                "measurement_path": measurement_path,
            }
        )
    return rows


def _validate_slice_measurement(value: Mapping[str, Any], low4: int) -> None:
    run = value.get("run", {})
    cells = run.get("cells", [])
    stages = run.get("stages", [])
    if (
        value.get("schema")
        != "chacha20-round20-w46-corrected-group-direct12-a355-slice-v1"
        or value.get("attempt_id") != ATTEMPT_ID
        or value.get("low4") != low4
        or value.get("target_label_available_to_measurement") is not False
        or value.get("label_used_for_feature_construction_or_scoring") is not False
        or value.get("complete_candidate_cover") is not True
        or len(cells) != COARSE_CELLS
        or not 1 <= len(stages) <= COARSE_CELLS * len(HORIZONS)
        or run.get("all_watchdogs_clear") is not True
    ):
        raise RuntimeError(f"A355 slice measurement gate failed: {low4}")


def _run_slice(row: Mapping[str, Any], *, helper: Path, key_mapping: Sequence[int]) -> dict[str, Any]:
    low4 = int(row["low4"])
    path = Path(row["measurement_path"])
    if path.exists():
        value = _read_measurement(path)
        _validate_slice_measurement(value, low4)
        return {"low4": low4, "resumed": True, "ledger": _write_measurement(path, value)}
    started = time.perf_counter()
    raw_run = A348.WRAPPER.run_fresh_clause_identity(
        helper=helper,
        cnf=path_from_ref(row["cnf"]["path"]),
        mode=f"A355_W46_group_direct12_low4_{low4:02x}",
        order=[f"{value:08b}" for value in range(COARSE_CELLS)],
        key_one_literals_bit0_through_bit19=key_mapping,
        conflict_horizons=HORIZONS,
        watchdog_seconds=WATCHDOG_SECONDS,
        external_timeout_seconds=3600.0,
    )
    stable = {
        key: value for key, value in raw_run.items() if key not in {"command", "process_elapsed_seconds"}
    }
    measurement = {
        "schema": "chacha20-round20-w46-corrected-group-direct12-a355-slice-v1",
        "attempt_id": ATTEMPT_ID,
        "low4": low4,
        "low4_binary": f"{low4:04b}",
        "fixed_unit_literals": list(row["unit_literals"]),
        "cnf_sha256": row["cnf"]["sha256"],
        "run": stable,
        "volatile_process_elapsed_seconds": time.perf_counter() - started,
        "target_label_available_to_measurement": False,
        "label_used_for_feature_construction_or_scoring": False,
        "complete_candidate_cover": len(stable.get("cells", [])) == COARSE_CELLS,
    }
    _validate_slice_measurement(measurement, low4)
    return {"low4": low4, "resumed": False, "ledger": _write_measurement(path, measurement)}


def _hard_partition(measurements: Mapping[int, Mapping[str, Any]], public_seed: str) -> list[int]:
    statuses: dict[str, list[int]] = {"sat": [], "unknown": [], "unsat": []}
    for low4 in SLICES:
        for high8, row in enumerate(measurements[low4]["run"]["cells"]):
            statuses[row["final_status"]].append(A348.slice_cell(high8, low4))
    seed = bytes.fromhex(public_seed)
    unknown = sorted(
        statuses["unknown"],
        key=lambda cell: hashlib.sha256(
            b"A355|hard-partition|" + seed + cell.to_bytes(2, "big")
        ).digest(),
    )
    return [*statuses["sat"], *unknown, *statuses["unsat"]]


def build_causal(payload: Mapping[str, Any]) -> dict[str, Any]:
    sys.path.insert(0, str(DOTCAUSAL_SRC))
    from dotcausal.io import CausalReader, CausalWriter

    terminal = "A355:corrected_group_coordinate_reader_selected"
    writer = CausalWriter(api_id="a355grp")
    writer._rules = []
    writer.add_rule(
        name="corrected_slices_to_word0_group_grid",
        description="Low4 coordinates 23..20 crossed with high8 coordinates 31..24 cover every Metal word0 prefix group exactly once.",
        pattern=["A354_corrected_coordinate_contract", "sixteen_A355_low4_slices"],
        conclusion="A355_complete_word0_group_grid",
        confidence_modifier=1.0,
    )
    writer.add_rule(
        name="group_grid_to_rank_panel",
        description="Eight frozen Reader views score the complete corrected grid before the confirmed A325 group label is read.",
        pattern=["A355_complete_word0_group_grid", "frozen_A340_A342_reader_panel"],
        conclusion="A355_corrected_group_rank_panel",
        confidence_modifier=1.0,
    )
    writer.add_rule(
        name="rank_panel_to_future_view",
        description="The minimum confirmed A325 rank with lexicographic tie-break freezes one view for zero-refit A345 transfer.",
        pattern=["A355_corrected_group_rank_panel", "A355_frozen_selection_rule"],
        conclusion=terminal,
        confidence_modifier=1.0,
    )
    writer.add_triplet(
        trigger="A354:corrected_word0_bits20_through31_reader_contract",
        mechanism="sixteen_exact_low4_slices_cross_all_high8_assumptions",
        outcome="A355:complete_word0_group_grid",
        confidence=1.0,
        source=payload["measurement_sha256"],
        quantification=json.dumps(payload["measurement_summary"], sort_keys=True),
        evidence="complete target-label-free 4096-cell measurement",
        domain="ChaCha20 R20 W46 Metal group inference",
        quality_score=1.0,
    )
    writer.add_triplet(
        trigger="A355:complete_word0_group_grid",
        mechanism="frozen_eight_view_reader_panel_then_postclosure_prefix_lookup",
        outcome="A355:corrected_group_rank_panel",
        confidence=1.0,
        source=payload["result_sha256"],
        quantification=json.dumps(payload["rank_panel"], sort_keys=True),
        evidence=payload["evidence_stage"],
        domain="corrected-coordinate mechanism calibration",
        quality_score=1.0,
    )
    writer.add_triplet(
        trigger="A355:corrected_group_rank_panel",
        mechanism="minimum_rank_then_lexicographic_tie_break",
        outcome=terminal,
        confidence=1.0,
        source=payload["selection_commitment_sha256"],
        quantification=json.dumps(payload["selected_view"], sort_keys=True),
        evidence="selection after complete measurement and before A356 construction",
        domain="prospective Reader selection",
        quality_score=1.0,
    )
    writer.add_triplet(
        trigger="A354:corrected_word0_bits20_through31_reader_contract",
        mechanism="materialized_corrected_measurement_scoring_selection_chain",
        outcome=terminal,
        confidence=1.0,
        source="materialized:A355_corrected_group_reader_chain",
        quantification="exact retained closure",
        evidence=payload["evidence_stage"],
        domain="AI-native retained inference",
        quality_score=1.0,
        is_inferred=True,
    )
    writer.add_cluster(
        name="A355 corrected W46 group Reader",
        entities=[
            "A354:corrected_word0_bits20_through31_reader_contract",
            "A355:complete_word0_group_grid",
            "A355:corrected_group_rank_panel",
            terminal,
        ],
    )
    writer.add_gap(
        subject=terminal,
        predicate="next_required_object",
        expected_object_type="zero_refit_corrected_A345_group_order",
        confidence=1.0,
        suggested_queries=["Apply the frozen A355 view to the unresolved A345 public-output CNF."],
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
        reader.api_id != "a355grp"
        or len(explicit) != 3
        or len(all_rows) != 4
        or len(inferred) != 1
        or len(reader._rules) != 3
        or len(reader._clusters) != 1
        or len(reader._gaps) != 1
    ):
        raise RuntimeError("A355 authentic Causal reopen gate failed")
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
            "selected_relation": explicit[-1],
            "terminal_chain": all_rows[-1],
            "next_gap": reader._gaps[0],
        },
    }


def measure(*, expected_implementation_sha256: str) -> dict[str, Any]:
    if RESULT.exists() or CAUSAL.exists() or REPORT.exists():
        raise FileExistsError("A355 result already exists")
    design = load_design()
    implementation = load_implementation(expected_implementation_sha256)
    preflight = json.loads(A340_PREFLIGHT.read_bytes())
    source_mapping = [int(value) for value in preflight["source_one_literals_bit0_upward"]]
    if (
        len(source_mapping) != WIDTH
        or preflight.get("source_mapping_sha256") != canonical_sha256(source_mapping)
    ):
        raise RuntimeError("A355 A340 source mapping differs")
    synthetic_mapping = corrected_synthetic_mapping(source_mapping)
    correction = json.loads(A354_RESULT.read_bytes())["corrected_successor_contract"]
    if canonical_sha256(synthetic_mapping) != correction["synthetic_reader_mapping_sha256"]:
        raise RuntimeError("A355 mapping differs from A354 correction")

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
        raise RuntimeError("A355 slice completion cover differs")

    measurements = {
        row["low4"]: _read_measurement(path_from_ref(row["ledger"]["path"]), row["ledger"])
        for row in completed
    }
    status_counts = {status: 0 for status in ("sat", "unknown", "unsat")}
    stage_count = 0
    for low4, value in measurements.items():
        _validate_slice_measurement(value, low4)
        stage_count += len(value["run"]["stages"])
        for cell in value["run"]["cells"]:
            status_counts[cell["final_status"]] += 1
    if sum(status_counts.values()) != CELLS:
        raise RuntimeError("A355 direct12 status cover differs")

    a325 = json.loads(A325_RESULT.read_bytes())
    candidate = int(a325["discovery"]["candidate"])
    confirmed_prefix = ((candidate & 0xFFFFFFFF) >> 20) & 0xFFF
    if confirmed_prefix != int(a325["discovery"]["prefix12"]):
        raise RuntimeError("A355 confirmed A325 prefix codec differs")

    orders: dict[str, list[int]] = {}
    score_hashes: dict[str, str] = {}
    if status_counts["sat"] or status_counts["unsat"]:
        name = "hard_terminal_partition"
        orders[name] = _hard_partition(measurements, preflight["A325_public_challenge_sha256"])
        evidence_stage = "CORRECTED_GROUP_DIRECT12_HARD_PARTITION_RETAINED"
    else:
        _selection, _a272, model, groups = A348.A341.reconstruct_known_key_selection(
            json.loads(A348.A341.DESIGN.read_bytes())
        )
        score_fields = A348._all_view_scores(measurements, model, groups)  # noqa: SLF001
        expected_views = tuple(design["scoring_contract"]["candidate_views"])
        if tuple(score_fields) != expected_views:
            raise RuntimeError("A355 frozen score-view sequence differs")
        for name, field in score_fields.items():
            orders[name] = A348._rank_order(field)  # noqa: SLF001
            score_hashes[name] = canonical_sha256(np.asarray(field).tolist())
        evidence_stage = "CORRECTED_GROUP_DIRECT12_MULTIVIEW_CALIBRATION_RETAINED"

    rank_panel: dict[str, Any] = {}
    for name, order in orders.items():
        rank = order.index(confirmed_prefix) + 1
        rank_panel[name] = {
            "rank_one_based": rank,
            "gain_bits_vs_uniform_complete_4096_cover": math.log2(CELLS / rank),
            "domain_reduction_factor_at_rank": CELLS / rank,
            "order_uint16be_sha256": sha256(
                b"".join(cell.to_bytes(2, "big") for cell in order)
            ),
        }
    selected_name, selected_metrics = min(
        rank_panel.items(), key=lambda item: (item[1]["rank_one_based"], item[0])
    )
    selected_view = {"name": selected_name, **selected_metrics}
    selection_commitment = canonical_sha256(
        {
            "selection_rule": design["scoring_contract"]["primary_selection"],
            "tie_break": design["scoring_contract"]["selection_tie_break"],
            "confirmed_prefix12": confirmed_prefix,
            "rank_panel": rank_panel,
            "selected_view": selected_view,
        }
    )

    ledgers = [
        {
            **row["ledger"],
            "low4": row["low4"],
            "low4_binary": f"{row['low4']:04b}",
            "resumed": row["resumed"],
        }
        for row in completed
    ]
    measurement_summary = {
        "low4_slices": len(SLICES),
        "high8_cells_per_slice": COARSE_CELLS,
        "complete_direct12_cells": CELLS,
        "solver_stages": stage_count,
        "status_counts": status_counts,
        "concurrent_workers": WORKERS,
        "target_labels_used_during_measurement": 0,
        "candidate_assignments_executed": 0,
        "measured_assignment_bit_interval": [20, 31],
    }
    payload: dict[str, Any] = {
        "schema": "chacha20-round20-w46-corrected-group-direct12-reader-a355-v1",
        "attempt_id": ATTEMPT_ID,
        "evidence_stage": evidence_stage,
        "design_sha256": DESIGN_SHA256,
        "implementation_sha256": expected_implementation_sha256,
        "implementation_commitment_sha256": implementation[
            "implementation_commitment_sha256"
        ],
        "coordinate_contract": {
            "low4_fixed_unit_coordinates_high_to_low": list(LOW4_COORDINATES),
            "high8_assumption_coordinates_high_to_low": list(HIGH8_COORDINATES),
            "synthetic_reader_mapping_source_indices": list(SYNTHETIC_SOURCE_INDICES),
            "synthetic_reader_mapping_sha256": canonical_sha256(synthetic_mapping),
        },
        "measurement_summary": measurement_summary,
        "measurement_ledger": ledgers,
        "measurement_sha256": canonical_sha256(
            {"summary": measurement_summary, "ledger": ledgers}
        ),
        "confirmed_prefix12": confirmed_prefix,
        "confirmed_prefix12_hex": f"{confirmed_prefix:03x}",
        "confirmed_prefix_revealed_only_after_complete_measurement": True,
        "rank_panel": rank_panel,
        "orders": orders,
        "score_field_sha256": score_hashes,
        "selected_view": selected_view,
        "selection_commitment_sha256": selection_commitment,
        "information_boundary": design["information_boundary"],
        "volatile_wall_seconds": time.perf_counter() - started,
        "anchors": {
            "design": anchor(DESIGN, DESIGN_SHA256),
            "implementation": anchor(IMPLEMENTATION, expected_implementation_sha256),
            "A325_result": anchor(A325_RESULT, design["source_anchors"]["A325_result_sha256"]),
            "A340_preflight": anchor(
                A340_PREFLIGHT, design["source_anchors"]["A340_preflight_sha256"]
            ),
            "A340_base_CNF": anchor(
                A340_BASE_CNF, design["source_anchors"]["A340_base_cnf_sha256"]
            ),
            "A354_result": anchor(A354_RESULT, design["source_anchors"]["A354_result_sha256"]),
            "runner": anchor(Path(__file__)),
            "test": anchor(TEST),
            "reproducer": anchor(REPRO),
        },
    }
    payload["result_sha256"] = canonical_sha256(
        {
            "evidence_stage": evidence_stage,
            "coordinate_contract": payload["coordinate_contract"],
            "measurement_sha256": payload["measurement_sha256"],
            "confirmed_prefix12": confirmed_prefix,
            "rank_panel": rank_panel,
            "score_field_sha256": score_hashes,
            "selected_view": selected_view,
            "selection_commitment_sha256": selection_commitment,
            "information_boundary": payload["information_boundary"],
        }
    )
    payload["causal"] = build_causal(payload)
    atomic_json(RESULT, payload)
    atomic_bytes(
        REPORT,
        (
            "# A355 — corrected W46 Metal-group direct12 Reader\n\n"
            f"Evidence stage: **{evidence_stage}**\n\n"
            f"- Exact measured assignment coordinates: **20–31**\n"
            f"- Complete cells / solver stages: **{CELLS:,} / {stage_count:,}**\n"
            f"- Status counts: **{status_counts}**\n"
            f"- Confirmed A325 Metal group after closure: **0x{confirmed_prefix:03x}**\n"
            f"- Selected corrected Reader: **{selected_name}**, rank "
            f"**{selected_metrics['rank_one_based']} / {CELLS}**\n"
            "- Candidate assignments / target labels / Reader refits: **0 / 0 / 0**\n"
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
        "slice_CNF_count": len(list(ARTIFACTS.glob("slice_*.cnf"))) if ARTIFACTS.exists() else 0,
        "slice_measurement_count": len(list(MEASUREMENTS.glob("slice_*.json.zst")))
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
    action.add_argument("--measure", action="store_true")
    parser.add_argument("--expected-implementation-sha256")
    args = parser.parse_args()
    if args.freeze_implementation:
        payload = freeze_implementation()
    elif args.measure:
        if not args.expected_implementation_sha256:
            parser.error("--measure requires --expected-implementation-sha256")
        payload = measure(expected_implementation_sha256=args.expected_implementation_sha256)
    else:
        payload = analyze()
    print(json.dumps(payload, indent=2, sort_keys=True), flush=True)


if __name__ == "__main__":
    main()

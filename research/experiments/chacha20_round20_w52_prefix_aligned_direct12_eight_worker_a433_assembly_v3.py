#!/usr/bin/env python3
"""A433 assembly V3: retain V2 measurements and emit the native Causal/result closure."""

from __future__ import annotations

import argparse
import importlib.util
import inspect
import json
import os
import sys
import time
from collections.abc import Mapping
from pathlib import Path
from typing import Any

import numpy as np
import zstandard

ROOT = Path(__file__).parents[2]
RESEARCH = ROOT / "research"
CONFIGS = RESEARCH / "configs"
RESULTS = RESEARCH / "results/v1"

V2_RUNNER = (
    RESEARCH / "experiments/chacha20_round20_w52_prefix_aligned_direct12_eight_worker_a433_v2.py"
)
DESIGN = CONFIGS / "chacha20_round20_w52_prefix_aligned_direct12_eight_worker_a433_design_v1.json"
V2_IMPLEMENTATION = (
    CONFIGS
    / "chacha20_round20_w52_prefix_aligned_direct12_eight_worker_a433_implementation_v2.json"
)
V2_PREFLIGHT = (
    RESULTS / "chacha20_round20_w52_prefix_aligned_direct12_eight_worker_a433_preflight_v2.json"
)
ASSEMBLY_IMPLEMENTATION = (
    CONFIGS
    / "chacha20_round20_w52_prefix_aligned_direct12_eight_worker_a433_assembly_v3_implementation_v1.json"
)
RESULT = RESULTS / "chacha20_round20_w52_prefix_aligned_direct12_eight_worker_a433_v2.json"
CAUSAL = RESULT.with_suffix(".causal")
REPORT = RESULT.with_suffix(".md")
V1_PREFLIGHT_FAILURE = (
    RESULTS
    / "chacha20_round20_w52_prefix_aligned_direct12_eight_worker_a433_preflight_failure_v1.json"
)
V2_CAUSAL_FAILURE = (
    RESULTS
    / "chacha20_round20_w52_prefix_aligned_direct12_eight_worker_a433_causal_reopen_failure_v2.json"
)
V2_CAUSAL_PRESERVED = (
    RESULTS
    / "chacha20_round20_w52_prefix_aligned_direct12_eight_worker_a433_causal_reopen_failure_v2.causal"
)
TEST = (
    ROOT
    / "tests/test_chacha20_round20_w52_prefix_aligned_direct12_eight_worker_a433_assembly_v3.py"
)
REPRO = (
    ROOT
    / "scripts/reproduce_chacha20_round20_w52_prefix_aligned_direct12_eight_worker_a433_assembly_v3.sh"
)

ATTEMPT_ID = "A433"
ASSEMBLY_REVISION = 3
DESIGN_SHA256 = "7024b47b2e591a96723d4a1ff26ec1193c47ddff67aeb270660b3705380f3100"
V2_RUNNER_SHA256 = "17a466cbb7be143e4ed77c48d975ac54c1cc860aee5964dfd5c7ca4f020b7442"
V2_IMPLEMENTATION_SHA256 = "aef8c643d85fd5f3702549f1856ed42aa0f3d318edd1ecfc3b324f8573b5609e"
V2_PREFLIGHT_SHA256 = "c1edef54740c77031a33e87f500df40a5da9db1e98ca1f0d6a07782cdaccb6c4"
V1_PREFLIGHT_FAILURE_SHA256 = "3f79244479ae5271c5cad6b94c81708dcb8405041a26eb91f5a6532e5334dc08"
V2_CAUSAL_FAILURE_SHA256 = "20f696c4493a5270aa1c807762a4fd94f2396e3f07ab3b2493371a084c21f166"
V2_CAUSAL_PRESERVED_SHA256 = "2571615d7a18db57e3d769a6c72c78ab38ebefb6b6521d4f9014fb451afc0104"
EXPECTED_ORDER_COMMITMENT = "bc28f9bd5a2a23dbc5506cc1524a0cb9cf325f64615ecfed33d0512a8af291f4"
EXPECTED_SCHEDULE_COMMITMENT = "0fbb2144abb03f6786d276fe9ee7ee330c61931868644b5a9f6401387c072725"
DOTCAUSAL_SRC = Path("/Users/bhkmie/Documents/Forschung/O1/vendor/fabel/dotcausal_package/src")


def load_module(path: Path, name: str) -> Any:
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot import A433 assembly dependency {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


V2 = load_module(V2_RUNNER, "a433_assembly_v2")
file_sha256 = V2.file_sha256
canonical_sha256 = V2.canonical_sha256
canonical_bytes = V2.canonical_bytes
atomic_json = V2.atomic_json
atomic_bytes = V2.atomic_bytes
relative = V2.relative
anchor = V2.anchor
path_from_ref = V2.path_from_ref
sha256 = V2.sha256


def verify_sources() -> None:
    anchor(DESIGN, DESIGN_SHA256)
    anchor(V2_RUNNER, V2_RUNNER_SHA256)
    anchor(V2_IMPLEMENTATION, V2_IMPLEMENTATION_SHA256)
    anchor(V2_PREFLIGHT, V2_PREFLIGHT_SHA256)
    anchor(V1_PREFLIGHT_FAILURE, V1_PREFLIGHT_FAILURE_SHA256)
    anchor(V2_CAUSAL_FAILURE, V2_CAUSAL_FAILURE_SHA256)
    anchor(V2_CAUSAL_PRESERVED, V2_CAUSAL_PRESERVED_SHA256)
    V2.load_design()
    V2.load_implementation(V2_IMPLEMENTATION_SHA256)
    V2.load_preflight(V2_PREFLIGHT_SHA256, V2.A426_PROTOCOL_SHA256)
    V2.load_a355_selection()
    V2.load_a422_protocol()


def measurement_manifest() -> tuple[list[dict[str, Any]], dict[int, dict[str, Any]]]:
    ledgers = []
    measurements = {}
    for low4 in V2.SLICES:
        _cnf_path, path = V2.slice_paths(low4)
        compressed = path.read_bytes()
        raw = zstandard.ZstdDecompressor().decompress(compressed)
        value = json.loads(raw)
        if canonical_bytes(value) != raw:
            raise RuntimeError(f"A433 assembly slice is not canonical: {low4}")
        V2.validate_measurement(value, low4)
        ledger = {
            "path": relative(path),
            "raw_bytes": len(raw),
            "raw_sha256": sha256(raw),
            "compressed_bytes": len(compressed),
            "compressed_sha256": sha256(compressed),
            "low4": low4,
            "resumed": False,
        }
        ledgers.append(ledger)
        measurements[low4] = value
    if len(ledgers) != len(V2.SLICES):
        raise RuntimeError("A433 assembly measurement cover differs")
    return ledgers, measurements


def reconstruct() -> dict[str, Any]:
    verify_sources()
    protocol = V2.load_a426_protocol()
    ledgers, measurements = measurement_manifest()
    status_counts = {status: 0 for status in ("sat", "unknown", "unsat")}
    stage_count = 0
    for low4, value in measurements.items():
        V2.validate_measurement(value, low4)
        stage_count += len(value["run"]["stages"])
        for cell in value["run"]["cells"]:
            status_counts[cell["final_status"]] += 1
    if sum(status_counts.values()) != V2.CELLS or stage_count != V2.CELLS * len(V2.HORIZONS):
        raise RuntimeError("A433 assembly complete measurement cover differs")

    _selection, _a272, model, groups = V2.A388.A341.reconstruct_known_key_selection(
        json.loads(V2.A388.A341.DESIGN.read_bytes())
    )
    fields = V2.A388.A348._all_view_scores(measurements, model, groups)  # noqa: SLF001
    if tuple(fields) != V2.VIEW_NAMES:
        raise RuntimeError("A433 assembly frozen view sequence differs")
    score_fields = {name: np.asarray(field, dtype=np.float64) for name, field in fields.items()}
    view_orders = {
        name: V2.A388.A348._rank_order(field)  # noqa: SLF001
        for name, field in score_fields.items()
    }
    scores = score_fields[V2.SELECTED_VIEW]
    direct_order = view_orders[V2.SELECTED_VIEW]
    schedule = V2.direct_eight_worker_schedule(direct_order)
    comparison = V2.comparison_panel(direct_order, schedule["cell_epoch_one_based"])
    diversity = V2.view_diversity_panel(view_orders)
    score_hashes = {name: canonical_sha256(field.tolist()) for name, field in score_fields.items()}
    order_hashes = {name: V2.A388.A351.order_sha256(order) for name, order in view_orders.items()}
    measurement_summary = {
        "complete_direct12_cells": V2.CELLS,
        "low4_slices": len(V2.SLICES),
        "high8_cells_per_slice": V2.COARSE_CELLS,
        "solver_stages": stage_count,
        "status_counts": status_counts,
        "concurrent_workers": V2.WORKERS,
        "measured_assignment_bit_interval": [20, 31],
        "cell_identity": "cell_equals_word0_bits31_through20",
        "all_4096_cells_match_A422_group_ids": True,
        "frozen_reader_views_materialized": len(V2.VIEW_NAMES),
        "target_labels_used": 0,
        "reader_refits": 0,
        "candidate_assignments_executed": 0,
    }
    essential = {
        "selected_view": V2.SELECTED_VIEW,
        "A355_selection_commitment_sha256": V2.A355_SELECTION_COMMITMENT_SHA256,
        "A426_public_challenge_sha256": protocol["public_challenge_sha256"],
        "measurement_sha256": canonical_sha256(ledgers),
        "score_field_sha256": canonical_sha256(scores.tolist()),
        "all_view_score_field_sha256": score_hashes,
        "all_view_order_uint16be_sha256": order_hashes,
        "W52_prefix_aligned_direct12_order_uint16be_sha256": schedule[
            "global_order_uint16be_sha256"
        ],
        "worker_cell_order_uint16be_sha256": schedule["worker_cell_order_uint16be_sha256"],
        "worker_task_list_sha256": schedule["worker_task_list_sha256"],
        "schedule_proof": schedule["proof"],
        "target_labels_used": 0,
        "reader_refits": 0,
        "candidate_assignments_executed": 0,
        "A426_progress_or_filter_outcomes_consumed": False,
    }
    order_commitment = canonical_sha256(essential)
    schedule_commitment = canonical_sha256(
        {
            "order": schedule["global_order_uint16be_sha256"],
            "workers": schedule["worker_cell_order_uint16be_sha256"],
            "tasks": schedule["worker_task_list_sha256"],
            "epochs": schedule["cell_epoch_one_based"],
        }
    )
    if (
        order_commitment != EXPECTED_ORDER_COMMITMENT
        or schedule_commitment != EXPECTED_SCHEDULE_COMMITMENT
    ):
        raise RuntimeError("A433 assembly differs from the preserved native-graph commitments")
    return {
        "protocol": protocol,
        "ledgers": ledgers,
        "measurement_summary": measurement_summary,
        "essential": essential,
        "schedule": schedule,
        "comparison": comparison,
        "diversity": diversity,
        "order_commitment_sha256": order_commitment,
        "schedule_commitment_sha256": schedule_commitment,
    }


def build_causal_at(path: Path, payload: Mapping[str, Any]) -> dict[str, Any]:
    sys.path.insert(0, str(DOTCAUSAL_SRC))
    from dotcausal.io import CausalReader, CausalWriter

    audit = "A354:corrected_word0_bits20_through31_reader_contract"
    off_axis = "A432:complete_unlabeled_W52_off_axis_field"
    axis = "A433:word0_bits31_through20_prefix_axis_contract"
    reader = "A355:frozen_A340_selected8_global_raw_reader"
    field = "A433:complete_unlabeled_W52_prefix_aligned_field"
    schedule = "A433:exact_prefix_aligned_eight_worker_schedule"
    executor = "A434:dual_axis_W52_subcell_executor"
    writer = CausalWriter(api_id="a433w52")
    writer._rules = []
    writer.add_rule(
        name="codec_audit_separates_the_two_W52_axes",
        description="A354 separates A432 word1 bits 19 through 8 from the A422 and A433 word0 bits 31 through 20 production prefix.",
        pattern=[
            "A354_corrected_word0_bits20_through31_reader_contract",
            "A432_complete_unlabeled_W52_off_axis_field",
        ],
        conclusion="A433_word0_bits31_through20_prefix_axis_contract",
        confidence_modifier=1.0,
    )
    writer.add_rule(
        name="frozen_reader_to_complete_prefix_field",
        description="The frozen A355 Reader scores all 4,096 exact W52 prefix-axis cells with zero labels and zero refits.",
        pattern=[
            "A355_frozen_A340_selected8_global_raw_reader",
            "A433_word0_bits31_through20_prefix_axis_contract",
        ],
        conclusion="A433_complete_unlabeled_W52_prefix_aligned_field",
        confidence_modifier=1.0,
    )
    writer.add_rule(
        name="orthogonal_fields_to_dual_axis_executor",
        description="The prefix field and complementary off-axis field define an exact 24-bit grid of 2^28-candidate Metal subcells.",
        pattern=[
            "A433_complete_unlabeled_W52_prefix_aligned_field",
            "A432_complete_unlabeled_W52_off_axis_field",
        ],
        conclusion="A434_dual_axis_W52_subcell_executor",
        confidence_modifier=1.0,
    )
    writer.add_triplet(
        trigger=audit,
        mechanism="separates_word1_19_8_from_word0_31_20",
        outcome=axis,
        confidence=1.0,
        source=V2.A354_RESULT_SHA256,
        quantification="A432 interval 40..51; A433 and A422 interval 20..31",
        evidence=f"preflight={V2_PREFLIGHT_SHA256}; mapping={payload['coordinate_contract']['synthetic_reader_mapping_sha256']}",
        domain="ChaCha20 W52 coordinate codec",
        quality_score=1.0,
    )
    writer.add_triplet(
        trigger=reader,
        mechanism="zero_refit_complete_prefix_axis_measurement",
        outcome=field,
        confidence=1.0,
        source=payload["order_commitment_sha256"],
        quantification="4096 cells; 16384 stages; 8 frozen views; all cells unknown",
        evidence=f"measurement={payload['measurement_sha256']}; labels=0; refits=0; candidates=0",
        domain="full-round ChaCha20 W52 public-output inference",
        quality_score=1.0,
    )
    writer.add_triplet(
        trigger=field,
        mechanism="exact_position_modulo_eight_partition",
        outcome=schedule,
        confidence=1.0,
        source=payload["schedule_commitment_sha256"],
        quantification="4096 cells; 8 workers; 512 epochs; D=ceil(R/8)",
        evidence=f"comparison={canonical_sha256(payload['unlabeled_schedule_comparison'])}",
        domain="complete W52 recovery scheduling",
        quality_score=1.0,
    )
    writer.add_triplet(
        trigger=audit,
        mechanism="materialized_two_axis_reader_to_executor_chain",
        outcome=executor,
        confidence=1.0,
        source="materialized:A433_A434_dual_axis_chain",
        quantification="word0 high12 x word1 high12 leaves 28 residual bits",
        evidence=payload["evidence_stage"],
        domain="AI-native retained inference",
        quality_score=1.0,
        is_inferred=True,
    )
    writer.add_cluster(
        name="A433 to A434 dual-axis W52 chain",
        entities=[audit, off_axis, axis, reader, field, schedule, executor],
    )
    writer.add_gap(
        subject=executor,
        predicate="next_required_object",
        expected_object_type="qualified_and_executed_dual_axis_2pow28_subcell_recovery",
        confidence=1.0,
        suggested_queries=[
            "Qualify the exact Metal subcell adapter, then stream the frozen 24-bit square-wavefront as A435."
        ],
    )
    temporary = path.with_name(f".{path.name}.tmp")
    temporary.unlink(missing_ok=True)
    stats = writer.save(str(temporary))
    os.replace(temporary, path)
    causal_reader = CausalReader(str(path), verify_integrity=True)
    explicit = causal_reader.get_all_triplets(include_inferred=False)
    all_rows = causal_reader.get_all_triplets(include_inferred=True)
    inferred = [row for row in causal_reader._triplets if row.get("is_inferred", False)]
    if (
        causal_reader.api_id != "a433w52"
        or len(explicit) != 3
        or len(all_rows) != 4
        or len(inferred) != 1
        or len(causal_reader._rules) != 3
        or len(causal_reader._clusters) != 1
        or len(causal_reader._gaps) != 1
    ):
        raise RuntimeError("A433 assembly authentic Causal reopen gate failed")
    return {
        "format": "authentic_dotcausal_v1_AI_native",
        "path": relative(path) if path.is_relative_to(ROOT) else str(path),
        "sha256": file_sha256(path),
        "api_id": causal_reader.api_id,
        "explicit_triplets": len(explicit),
        "materialized_inferred_triplets": len(inferred),
        "embedded_rules": len(causal_reader._rules),
        "clusters": len(causal_reader._clusters),
        "gaps": len(causal_reader._gaps),
        "reader_source": anchor(Path(inspect.getsourcefile(CausalReader) or "")),
        "writer_stats": stats,
        "personal_semantic_readback": {
            "codec_edge": explicit[0],
            "reader_edge": explicit[1],
            "schedule_edge": explicit[2],
            "inferred_dual_axis_edge": inferred[0],
            "next_gap": causal_reader._gaps[0],
        },
    }


def freeze_assembly() -> dict[str, Any]:
    if ASSEMBLY_IMPLEMENTATION.exists() or RESULT.exists() or REPORT.exists():
        raise FileExistsError("A433 assembly implementation or result already exists")
    V2.assert_pre_a426_result()
    reconstructed = reconstruct()
    if not TEST.exists() or not REPRO.exists():
        raise FileNotFoundError("A433 assembly tests and reproducer must precede freeze")
    payload: dict[str, Any] = {
        "schema": "chacha20-round20-w52-prefix-aligned-direct12-a433-assembly-v3-implementation-v1",
        "attempt_id": ATTEMPT_ID,
        "assembly_revision": ASSEMBLY_REVISION,
        "commitment_state": "post_measurement_hash_bound_assembly_frozen_before_result_A426_outcome_or_any_candidate",
        "measurement_manifest_sha256": reconstructed["essential"]["measurement_sha256"],
        "expected_order_commitment_sha256": EXPECTED_ORDER_COMMITMENT,
        "expected_schedule_commitment_sha256": EXPECTED_SCHEDULE_COMMITMENT,
        "target_labels_used": 0,
        "reader_refits": 0,
        "candidate_assignments_executed": 0,
        "A426_progress_or_filter_outcomes_consumed": False,
        "anchors": {
            "design": anchor(DESIGN, DESIGN_SHA256),
            "V2_runner": anchor(V2_RUNNER, V2_RUNNER_SHA256),
            "V2_implementation": anchor(V2_IMPLEMENTATION, V2_IMPLEMENTATION_SHA256),
            "V2_preflight": anchor(V2_PREFLIGHT, V2_PREFLIGHT_SHA256),
            "V1_preflight_failure": anchor(V1_PREFLIGHT_FAILURE, V1_PREFLIGHT_FAILURE_SHA256),
            "V2_causal_failure": anchor(V2_CAUSAL_FAILURE, V2_CAUSAL_FAILURE_SHA256),
            "V2_preserved_causal": anchor(V2_CAUSAL_PRESERVED, V2_CAUSAL_PRESERVED_SHA256),
            "runner": anchor(Path(__file__)),
            "test": anchor(TEST),
            "reproducer": anchor(REPRO),
        },
    }
    payload["implementation_commitment_sha256"] = canonical_sha256(payload)
    atomic_json(ASSEMBLY_IMPLEMENTATION, payload)
    V2.assert_pre_a426_result()
    return payload


def load_assembly(expected_sha256: str) -> dict[str, Any]:
    if file_sha256(ASSEMBLY_IMPLEMENTATION) != expected_sha256:
        raise RuntimeError("A433 assembly implementation hash differs")
    value = json.loads(ASSEMBLY_IMPLEMENTATION.read_bytes())
    if (
        value.get("schema")
        != "chacha20-round20-w52-prefix-aligned-direct12-a433-assembly-v3-implementation-v1"
        or value.get("assembly_revision") != ASSEMBLY_REVISION
        or value.get("expected_order_commitment_sha256") != EXPECTED_ORDER_COMMITMENT
        or value.get("expected_schedule_commitment_sha256") != EXPECTED_SCHEDULE_COMMITMENT
        or value.get("target_labels_used") != 0
        or value.get("reader_refits") != 0
        or value.get("candidate_assignments_executed") != 0
        or value.get("A426_progress_or_filter_outcomes_consumed") is not False
    ):
        raise RuntimeError("A433 assembly implementation semantics differ")
    for row in value["anchors"].values():
        anchor(path_from_ref(row["path"]), row["sha256"])
    unsigned = {
        key: item for key, item in value.items() if key != "implementation_commitment_sha256"
    }
    if value.get("implementation_commitment_sha256") != canonical_sha256(unsigned):
        raise RuntimeError("A433 assembly implementation commitment differs")
    return value


def assemble(*, expected_assembly_sha256: str) -> dict[str, Any]:
    if RESULT.exists() or REPORT.exists():
        raise FileExistsError("A433 assembled result already exists")
    if not CAUSAL.exists() or file_sha256(CAUSAL) != V2_CAUSAL_PRESERVED_SHA256:
        raise RuntimeError("A433 failed V2 Causal target differs before corrected replacement")
    V2.assert_pre_a426_result()
    started = time.perf_counter()
    assembly = load_assembly(expected_assembly_sha256)
    reconstructed = reconstruct()
    essential = reconstructed["essential"]
    schedule = reconstructed["schedule"]
    payload: dict[str, Any] = {
        "schema": "chacha20-round20-w52-prefix-aligned-direct12-eight-worker-a433-result-v2",
        "attempt_id": ATTEMPT_ID,
        "revision": 2,
        "assembly_revision": ASSEMBLY_REVISION,
        "evidence_stage": "PRE_A426_OUTCOME_COMPLETE_PREFIX_ALIGNED_WORD0_DIRECT12_W52_EIGHT_WORKER_SCHEDULE_FROZEN",
        "design_sha256": DESIGN_SHA256,
        "implementation_sha256": V2_IMPLEMENTATION_SHA256,
        "implementation_commitment_sha256": json.loads(V2_IMPLEMENTATION.read_bytes())[
            "implementation_commitment_sha256"
        ],
        "preflight_sha256": V2_PREFLIGHT_SHA256,
        "A426_protocol_sha256": V2.A426_PROTOCOL_SHA256,
        "assembly_implementation_sha256": expected_assembly_sha256,
        "assembly_implementation_commitment_sha256": assembly["implementation_commitment_sha256"],
        **essential,
        "coordinate_contract": {
            "A432_off_axis_measured_assignment_bit_interval": [40, 51],
            "A433_prefix_aligned_measured_assignment_bit_interval": [20, 31],
            "low4_fixed_unit_coordinates_high_to_low": list(V2.LOW4_COORDINATES),
            "high8_assumption_coordinates_high_to_low": list(V2.HIGH8_COORDINATES),
            "synthetic_reader_mapping_source_indices": list(V2.SYNTHETIC_SOURCE_INDICES),
            "synthetic_reader_mapping_sha256": json.loads(V2_PREFLIGHT.read_bytes())[
                "synthetic_reader_mapping_sha256"
            ],
            "cell_identity": "cell_equals_word0_bits31_through20_equals_assignment_word0_right_shift20",
            "A422_first_word0_identity": "first_word0_equals_cell_left_shift20",
            "all_4096_cells_match_A422_group_ids": True,
        },
        "measurement_summary": reconstructed["measurement_summary"],
        "measurement_ledger": reconstructed["ledgers"],
        "W52_prefix_aligned_direct12_order": schedule["global_order"],
        "worker_roles": schedule["worker_roles"],
        "worker_cell_orders": schedule["worker_cell_orders"],
        "worker_tasks": schedule["worker_tasks"],
        "cell_epoch_one_based": schedule["cell_epoch_one_based"],
        "cell_worker_role": schedule["cell_worker_role"],
        "schedule_proof": schedule["proof"],
        "unlabeled_schedule_comparison": reconstructed["comparison"],
        "unlabeled_reader_view_diversity": reconstructed["diversity"],
        "order_commitment_sha256": reconstructed["order_commitment_sha256"],
        "schedule_commitment_sha256": reconstructed["schedule_commitment_sha256"],
        "A426_result_or_true_prefix_available_at_schedule_freeze": False,
        "A426_progress_or_filter_outcomes_consumed": False,
        "V2_measurements_reused_without_reexecution": True,
        "volatile_assembly_wall_seconds": time.perf_counter() - started,
        "anchors": {
            "design": anchor(DESIGN, DESIGN_SHA256),
            "V2_implementation": anchor(V2_IMPLEMENTATION, V2_IMPLEMENTATION_SHA256),
            "V2_preflight": anchor(V2_PREFLIGHT, V2_PREFLIGHT_SHA256),
            "V2_runner": anchor(V2_RUNNER, V2_RUNNER_SHA256),
            "assembly_implementation": anchor(ASSEMBLY_IMPLEMENTATION, expected_assembly_sha256),
            "V1_preflight_failure": anchor(V1_PREFLIGHT_FAILURE, V1_PREFLIGHT_FAILURE_SHA256),
            "V2_causal_failure": anchor(V2_CAUSAL_FAILURE, V2_CAUSAL_FAILURE_SHA256),
            "V2_preserved_causal": anchor(V2_CAUSAL_PRESERVED, V2_CAUSAL_PRESERVED_SHA256),
            "A354_result": anchor(V2.A354_RESULT, V2.A354_RESULT_SHA256),
            "A355_result": anchor(V2.A355_RESULT, V2.A355_RESULT_SHA256),
            "A355_causal": anchor(V2.A355_CAUSAL, V2.A355_CAUSAL_SHA256),
            "A422_protocol": anchor(V2.A422_PROTOCOL, V2.A422_PROTOCOL_SHA256),
            "A428_result": anchor(V2.A428_RESULT, V2.A428_RESULT_SHA256),
            "A432_result": anchor(V2.A432_RESULT, V2.A432_RESULT_SHA256),
            "A432_causal": anchor(V2.A432_CAUSAL, V2.A432_CAUSAL_SHA256),
            "runner": anchor(Path(__file__)),
            "test": anchor(TEST),
            "reproducer": anchor(REPRO),
        },
    }
    payload["causal"] = build_causal_at(CAUSAL, payload)
    atomic_json(RESULT, payload)
    V2.assert_pre_a426_result()
    comparison = reconstructed["comparison"]
    atomic_bytes(
        REPORT,
        (
            "# A433 — exact W52 prefix-axis Reader and schedule\n\n"
            f"Evidence stage: **{payload['evidence_stage']}**\n\n"
            f"- Complete prefix cells / solver stages: **{V2.CELLS:,} / {reconstructed['measurement_summary']['solver_stages']:,}**\n"
            f"- Measured assignment coordinates: **20–31 = word0[31:20]**\n"
            f"- Selected frozen Reader: **{V2.SELECTED_VIEW}**\n"
            f"- Prefix-axis/A432 off-axis Spearman: **{comparison['prefix_aligned_vs_A432_off_axis_spearman']:.9f}**\n"
            f"- Prefix-axis/A428 Spearman: **{comparison['prefix_aligned_vs_A428_spearman']:.9f}**\n"
            "- Target labels / Reader refits / candidate assignments: **0 / 0 / 0**\n"
            "- V2 measurements reused without re-execution: **yes**\n"
            "- Authentic AI-native Causal readback: **3 explicit + 1 inferred**\n"
        ).encode(),
    )
    return payload


def analyze() -> dict[str, Any]:
    return {
        "attempt_id": ATTEMPT_ID,
        "assembly_revision": ASSEMBLY_REVISION,
        "measurement_slices": len(list(V2.MEASUREMENTS.glob("slice_*.json.zst"))),
        "assembly_frozen": ASSEMBLY_IMPLEMENTATION.exists(),
        "assembly_sha256": file_sha256(ASSEMBLY_IMPLEMENTATION)
        if ASSEMBLY_IMPLEMENTATION.exists()
        else None,
        "result_complete": RESULT.exists(),
        "result_sha256": file_sha256(RESULT) if RESULT.exists() else None,
        "causal_sha256": file_sha256(CAUSAL) if CAUSAL.exists() else None,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    action = parser.add_mutually_exclusive_group(required=True)
    action.add_argument("--analyze", action="store_true")
    action.add_argument("--freeze-assembly", action="store_true")
    action.add_argument("--assemble", action="store_true")
    parser.add_argument("--expected-assembly-sha256")
    args = parser.parse_args()
    if args.freeze_assembly:
        payload = freeze_assembly()
    elif args.assemble:
        if not args.expected_assembly_sha256:
            parser.error("--assemble requires --expected-assembly-sha256")
        payload = assemble(expected_assembly_sha256=args.expected_assembly_sha256)
    else:
        payload = analyze()
    print(json.dumps(payload, indent=2, sort_keys=True), flush=True)


if __name__ == "__main__":
    main()

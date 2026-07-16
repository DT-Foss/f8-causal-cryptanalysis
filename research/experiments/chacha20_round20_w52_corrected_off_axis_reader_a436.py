#!/usr/bin/env python3
"""A436: reassemble A432 under A354's corrected off-axis calibration."""

from __future__ import annotations

import argparse
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

ROOT = Path(__file__).parents[2]
RESEARCH = ROOT / "research"
CONFIGS = RESEARCH / "configs"
RESULTS = RESEARCH / "results/v1"

STEM = "chacha20_round20_w52_corrected_off_axis_reader_a436"
DESIGN = CONFIGS / f"{STEM}_design_v1.json"
IMPLEMENTATION = CONFIGS / f"{STEM}_implementation_v1.json"
RESULT = RESULTS / f"{STEM}_v1.json"
CAUSAL = RESULT.with_suffix(".causal")
REPORT = RESULT.with_suffix(".md")
TEST = ROOT / f"tests/test_{STEM}.py"
REPRO = ROOT / f"scripts/reproduce_{STEM}.sh"

A354_RESULT = RESULTS / "chacha20_round20_w46_direct12_coordinate_codec_audit_a354_v1.json"
A355_RESULT = RESULTS / "chacha20_round20_w46_corrected_group_direct12_reader_a355_v1.json"
A432_RESULT = RESULTS / "chacha20_round20_w52_public_output_direct12_eight_worker_a432_v1.json"
A432_RUNNER = (
    RESEARCH / "experiments/chacha20_round20_w52_public_output_direct12_eight_worker_a432.py"
)
A426_RESULT = RESULTS / "chacha20_round20_w52_a416_fresh_shared_stop_recovery_a426_v1.json"
A426_STOP = (
    RESULTS / "chacha20_round20_w52_a416_fresh_shared_stop_recovery_a426_confirmed_stop_v1.json"
)

ATTEMPT_ID = "A436"
DESIGN_SHA256 = "741f1684d5108a793ef689b84338996554cc749ba0c868c5f9c580c0876c11a8"
A354_RESULT_SHA256 = "9fc3487266aee3f4e637b9a1afc0b434a5f0c56fa430e9aa14b576cfe8782ac4"
A355_RESULT_SHA256 = "b197ba0145e85119fabfc32d14116836a905e260f70fc4bb7dc779924077b686"
A432_RESULT_SHA256 = "3d0ed27a25288db589ddb6608407314d1fa32f4cb678806e142eb819159a7e6d"
A432_RUNNER_SHA256 = "22b00e57cf06fd6c6e5e5e5be1766101ce1500d4e47dbe035a257ec271a0270e"

SELECTED_VIEW = "A342_selected_pair_global_raw"
ORIGINAL_VIEW = "A342_selected_pair_slice_z"
EXPECTED_CORRECTED_RANK = 561
EXPECTED_ORIGINAL_CORRECTED_RANK = 567
CELLS = 4096
VIEWS = (
    "A340_selected8_global_raw",
    "A340_selected8_slice_z",
    "A341_selected_single_global_raw",
    "A341_selected_single_slice_z",
    "A342_selected_pair_global_raw",
    "A342_selected_pair_slice_z",
    "A342_selected_triple_global_raw",
    "A342_selected_triple_slice_z",
)
DOTCAUSAL_SRC = Path("/Users/bhkmie/Documents/Forschung/O1/vendor/fabel/dotcausal_package/src")


def load_module(path: Path, name: str) -> Any:
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot import A436 dependency {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


A432 = load_module(A432_RUNNER, "a436_a432")
file_sha256 = A432.file_sha256
canonical_sha256 = A432.canonical_sha256
atomic_json = A432.atomic_json
anchor = A432.anchor
path_from_ref = A432.path_from_ref
relative = A432.relative


def atomic_bytes(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    temporary.write_bytes(data)
    os.replace(temporary, path)


def assert_pre_a426_outcome() -> None:
    paths = [
        A426_RESULT,
        A426_STOP,
        *(
            RESULTS
            / f"chacha20_round20_w52_a416_fresh_shared_stop_recovery_a426_worker_{index}_progress_v1.json"
            for index in range(8)
        ),
    ]
    if any(path.exists() for path in paths):
        raise RuntimeError("A436 prospective assembly must precede every A426 outcome")


def load_design() -> dict[str, Any]:
    if file_sha256(DESIGN) != DESIGN_SHA256:
        raise RuntimeError("A436 design hash differs")
    value = json.loads(DESIGN.read_bytes())
    coordinate = value.get("coordinate_contract", {})
    selection = value.get("selection_contract", {})
    assembly = value.get("assembly_contract", {})
    boundary = value.get("information_boundary", {})
    causal = value.get("causal_contract", {})
    if (
        value.get("schema") != "chacha20-round20-w52-corrected-off-axis-reader-a436-design-v1"
        or value.get("attempt_id") != ATTEMPT_ID
        or value.get("design_state")
        != "frozen_after_A354_coordinate_correction_A355_prefix_reader_A432_complete_unlabeled_W52_field_and_A433_prefix_field_before_any_A426_candidate_progress_filter_outcome_or_result"
        or coordinate.get("A348_actual_W46_calibration_cell") != 1916
        or coordinate.get("historically_declared_but_unmeasured_Metal_cell") != 2990
        or coordinate.get("cells_are_distinct") is not True
        or tuple(selection.get("candidate_views", [])) != VIEWS
        or selection.get("selection_rule")
        != "minimum_one_based_rank_at_actual_measured_cell_then_lexicographic_view_name"
        or selection.get("expected_selected_view") != SELECTED_VIEW
        or selection.get("expected_selected_rank_one_based") != EXPECTED_CORRECTED_RANK
        or selection.get("original_A432_view") != ORIGINAL_VIEW
        or selection.get("original_A432_corrected_rank_one_based")
        != EXPECTED_ORIGINAL_CORRECTED_RANK
        or assembly.get("reuse_all_sixteen_A432_measurement_slices_without_reexecution") is not True
        or assembly.get("reconstruct_all_eight_frozen_reader_views") is not True
        or assembly.get("complete_cells") != CELLS
        or assembly.get("solver_stages_reused") != 16384
        or assembly.get("new_solver_stages") != 0
        or assembly.get("target_labels_used") != 0
        or assembly.get("reader_refits") != 0
        or assembly.get("candidate_assignments_executed") != 0
        or boundary.get("A426_target_label_or_true_assignment_available") is not False
        or boundary.get("A426_progress_or_filter_outcomes_consumed") is not False
        or boundary.get("A432_W52_measurements_contain_target_labels") is not False
        or causal.get("authentic_dotcausal_v1_required") is not True
        or causal.get("reader_reopen_required") is not True
    ):
        raise RuntimeError("A436 frozen design semantics differ")
    return value


def corrected_selection() -> dict[str, Any]:
    if file_sha256(A354_RESULT) != A354_RESULT_SHA256:
        raise RuntimeError("A436 A354 result hash differs")
    value = json.loads(A354_RESULT.read_bytes())
    if (
        value.get("schema") != "chacha20-round20-w46-direct12-coordinate-codec-audit-a354-v1"
        or value.get("candidate_codec_witness", {}).get(
            "A348_actual_measured_cell_bits34_through45"
        )
        != 1916
        or value.get("candidate_codec_witness", {}).get("Metal_group_cell_word0_bits20_through31")
        != 2990
        or value.get("candidate_codec_witness", {}).get("cells_are_distinct") is not True
    ):
        raise RuntimeError("A436 A354 coordinate semantics differ")
    panel = value["corrected_A348_rank_panel"]
    ranks = {
        name: int(row["rank_at_actual_A348_measured_cell"]["rank_one_based"])
        for name, row in panel.items()
    }
    selected_name, selected_rank = min(ranks.items(), key=lambda item: (item[1], item[0]))
    if (
        tuple(ranks) != VIEWS
        or selected_name != SELECTED_VIEW
        or selected_rank != EXPECTED_CORRECTED_RANK
        or ranks[ORIGINAL_VIEW] != EXPECTED_ORIGINAL_CORRECTED_RANK
    ):
        raise RuntimeError("A436 corrected selection differs")
    return {
        "selection_source": "A354_corrected_A348_rank_panel",
        "actual_measured_cell": 1916,
        "distinct_unmeasured_Metal_cell": 2990,
        "view_rank_one_based": ranks,
        "selected_view": selected_name,
        "selected_rank_one_based": selected_rank,
        "original_A432_view": ORIGINAL_VIEW,
        "original_A432_corrected_rank_one_based": ranks[ORIGINAL_VIEW],
        "selection_commitment_sha256": canonical_sha256(
            {
                "source": A354_RESULT_SHA256,
                "cell": 1916,
                "ranks": ranks,
                "selected_view": selected_name,
                "selected_rank_one_based": selected_rank,
            }
        ),
    }


def measurement_manifest() -> tuple[
    dict[str, Any], list[dict[str, Any]], dict[int, dict[str, Any]]
]:
    if file_sha256(A432_RESULT) != A432_RESULT_SHA256:
        raise RuntimeError("A436 A432 result hash differs")
    source = json.loads(A432_RESULT.read_bytes())
    if (
        source.get("schema")
        != "chacha20-round20-w52-public-output-direct12-eight-worker-a432-result-v1"
        or source.get("selected_view") != ORIGINAL_VIEW
        or source.get("target_labels_used") != 0
        or source.get("reader_refits") != 0
        or source.get("candidate_assignments_executed") != 0
        or source.get("A426_progress_or_filter_outcomes_consumed") is not False
        or len(source.get("measurement_ledger", [])) != 16
    ):
        raise RuntimeError("A436 A432 source semantics differ")
    ledgers = []
    measurements: dict[int, dict[str, Any]] = {}
    for row in source["measurement_ledger"]:
        low4 = int(row["low4"])
        path = path_from_ref(row["path"])
        if file_sha256(path) != row["compressed_sha256"] or path.stat().st_size != int(
            row["compressed_bytes"]
        ):
            raise RuntimeError("A436 A432 compressed measurement manifest differs")
        measurement = A432.read_measurement(path, row)
        A432.validate_measurement(measurement, low4)
        ledgers.append(dict(row))
        measurements[low4] = measurement
    ledgers.sort(key=lambda row: int(row["low4"]))
    if [int(row["low4"]) for row in ledgers] != list(range(16)) or canonical_sha256(
        ledgers
    ) != source["measurement_sha256"]:
        raise RuntimeError("A436 A432 complete measurement cover differs")
    return source, ledgers, measurements


def rank_vector(order: Sequence[int]) -> np.ndarray:
    exact = A432.exact_order(order, "A436 comparison order")
    result = np.empty(CELLS, dtype=np.int64)
    for rank, cell in enumerate(exact):
        result[cell] = rank
    return result


def comparison_panel(
    selected_order: Sequence[int], original_order: Sequence[int]
) -> dict[str, Any]:
    selected = A432.exact_order(selected_order, "A436 selected order")
    original = A432.exact_order(original_order, "A436 original order")
    left = rank_vector(selected)
    right = rank_vector(original)
    return {
        "population": "all_4096_unlabeled_off_axis_cells",
        "selected_vs_original_spearman": float(np.corrcoef(left, right)[0, 1]),
        "selected_vs_original_top32_overlap": len(set(selected[:32]) & set(original[:32])),
        "selected_vs_original_top128_overlap": len(set(selected[:128]) & set(original[:128])),
        "earlier_equal_later": [
            int(np.count_nonzero(left < right)),
            int(np.count_nonzero(left == right)),
            int(np.count_nonzero(left > right)),
        ],
        "target_labels_used": 0,
    }


def reconstruct() -> dict[str, Any]:
    source, ledgers, measurements = measurement_manifest()
    status_counts = {status: 0 for status in ("sat", "unknown", "unsat")}
    stage_count = 0
    for value in measurements.values():
        stage_count += len(value["run"]["stages"])
        for cell in value["run"]["cells"]:
            status_counts[cell["final_status"]] += 1
    if sum(status_counts.values()) != CELLS or stage_count != 16384:
        raise RuntimeError("A436 reused measurement counts differ")
    _selection, _a272, model, groups = A432.A388.A341.reconstruct_known_key_selection(
        json.loads(A432.A388.A341.DESIGN.read_bytes())
    )
    fields = A432.A388.A348._all_view_scores(measurements, model, groups)  # noqa: SLF001
    if tuple(fields) != VIEWS:
        raise RuntimeError("A436 reconstructed view sequence differs")
    score_fields = {name: np.asarray(field, dtype=np.float64) for name, field in fields.items()}
    if any(
        field.shape != (CELLS,) or not np.isfinite(field).all() for field in score_fields.values()
    ):
        raise RuntimeError("A436 score field shape or finiteness differs")
    orders = {
        name: A432.A388.A348._rank_order(field)  # noqa: SLF001
        for name, field in score_fields.items()
    }
    score_hashes = {name: canonical_sha256(field.tolist()) for name, field in score_fields.items()}
    order_hashes = {name: A432.uint16be_sha256(order) for name, order in orders.items()}
    if (
        score_hashes[ORIGINAL_VIEW] != source["score_field_sha256"]
        or order_hashes[ORIGINAL_VIEW] != source["W52_public_output_direct12_order_uint16be_sha256"]
        or orders[ORIGINAL_VIEW] != source["W52_public_output_direct12_order"]
    ):
        raise RuntimeError("A436 original A432 reconstruction differs")
    selected_order = orders[SELECTED_VIEW]
    schedule = A432.direct_eight_worker_schedule(selected_order)
    return {
        "source": source,
        "ledgers": ledgers,
        "status_counts": status_counts,
        "solver_stages_reused": stage_count,
        "score_hashes": score_hashes,
        "order_hashes": order_hashes,
        "orders": orders,
        "selected_scores": score_fields[SELECTED_VIEW],
        "selected_order": selected_order,
        "schedule": schedule,
        "comparison": comparison_panel(selected_order, orders[ORIGINAL_VIEW]),
    }


def freeze_implementation() -> dict[str, Any]:
    if IMPLEMENTATION.exists() or RESULT.exists() or CAUSAL.exists() or REPORT.exists():
        raise FileExistsError("A436 implementation or result artifact exists")
    assert_pre_a426_outcome()
    load_design()
    selection = corrected_selection()
    if file_sha256(A355_RESULT) != A355_RESULT_SHA256:
        raise RuntimeError("A436 A355 result hash differs")
    if file_sha256(A432_RUNNER) != A432_RUNNER_SHA256:
        raise RuntimeError("A436 A432 runner hash differs")
    if not TEST.exists() or not REPRO.exists():
        raise FileNotFoundError("A436 tests and reproducer must precede freeze")
    payload: dict[str, Any] = {
        "schema": "chacha20-round20-w52-corrected-off-axis-reader-a436-implementation-v1",
        "attempt_id": ATTEMPT_ID,
        "commitment_state": "complete_zero_reexecution_A432_reassembly_and_authentic_causal_writer_frozen_before_any_A426_or_A436_candidate_progress_filter_outcome_or_result",
        "design_sha256": DESIGN_SHA256,
        "selection_commitment_sha256": selection["selection_commitment_sha256"],
        "selected_view": SELECTED_VIEW,
        "A426_outcome_available_at_freeze": False,
        "A436_candidate_or_progress_available_at_freeze": False,
        "target_labels_used": 0,
        "reader_refits": 0,
        "candidate_assignments_executed": 0,
        "anchors": {
            "design": anchor(DESIGN, DESIGN_SHA256),
            "A354_result": anchor(A354_RESULT, A354_RESULT_SHA256),
            "A355_result": anchor(A355_RESULT, A355_RESULT_SHA256),
            "A432_result": anchor(A432_RESULT, A432_RESULT_SHA256),
            "A432_runner": anchor(A432_RUNNER, A432_RUNNER_SHA256),
            "runner": anchor(Path(__file__)),
            "test": anchor(TEST),
            "reproducer": anchor(REPRO),
        },
    }
    payload["implementation_commitment_sha256"] = canonical_sha256(payload)
    atomic_json(IMPLEMENTATION, payload)
    assert_pre_a426_outcome()
    return payload


def load_implementation(expected_sha256: str) -> dict[str, Any]:
    if file_sha256(IMPLEMENTATION) != expected_sha256:
        raise RuntimeError("A436 implementation hash differs")
    value = json.loads(IMPLEMENTATION.read_bytes())
    if (
        value.get("schema")
        != "chacha20-round20-w52-corrected-off-axis-reader-a436-implementation-v1"
        or value.get("attempt_id") != ATTEMPT_ID
        or value.get("design_sha256") != DESIGN_SHA256
        or value.get("selected_view") != SELECTED_VIEW
        or value.get("A426_outcome_available_at_freeze") is not False
        or value.get("A436_candidate_or_progress_available_at_freeze") is not False
        or value.get("target_labels_used") != 0
        or value.get("reader_refits") != 0
        or value.get("candidate_assignments_executed") != 0
    ):
        raise RuntimeError("A436 implementation semantics differ")
    for row in value["anchors"].values():
        anchor(path_from_ref(row["path"]), row["sha256"])
    unsigned = {
        key: item for key, item in value.items() if key != "implementation_commitment_sha256"
    }
    if value.get("implementation_commitment_sha256") != canonical_sha256(unsigned):
        raise RuntimeError("A436 implementation commitment differs")
    return value


def build_causal(payload: Mapping[str, Any]) -> dict[str, Any]:
    if str(DOTCAUSAL_SRC) not in sys.path:
        sys.path.insert(0, str(DOTCAUSAL_SRC))
    from dotcausal.io import CausalReader, CausalWriter

    terminal = "A436:corrected_off_axis_W52_order"
    writer = CausalWriter(api_id="a436off")
    writer._rules = []
    writer.add_rule(
        name="coordinate_audit_to_actual_off_axis_calibration",
        description="A354 maps A348/A432 cells to assignment bits34-through45 and separates actual cell 0x77c from the old word0 Metal cell 0xbae.",
        pattern=["A354_exact_coordinate_codec_audit"],
        conclusion="A436_actual_off_axis_calibration_cell",
        confidence_modifier=1.0,
    )
    writer.add_rule(
        name="corrected_calibration_to_view_selection",
        description="Minimum corrected W46 rank selects A342 pair global raw at rank 561 rather than the slice-z view selected at the distinct cell.",
        pattern=["A436_actual_off_axis_calibration_cell", "A354_corrected_rank_panel"],
        conclusion="A436_corrected_pair_global_raw_selection",
        confidence_modifier=1.0,
    )
    writer.add_rule(
        name="selection_and_reused_field_to_W52_order",
        description="Reassemble all eight frozen views from A432's sixteen immutable unlabeled slices and emit the selected complete W52 off-axis order without a solver rerun.",
        pattern=["A436_corrected_pair_global_raw_selection", "A432_complete_unlabeled_W52_field"],
        conclusion="A436_corrected_off_axis_W52_order",
        confidence_modifier=1.0,
    )
    writer.add_triplet(
        trigger="A354:exact_coordinate_codec_audit",
        mechanism="assignment_bits34_through45_backprojection",
        outcome="A436:actual_off_axis_calibration_cell_0x77c",
        confidence=1.0,
        source=A354_RESULT_SHA256,
        quantification=json.dumps(payload["coordinate_selection"], sort_keys=True),
        evidence=payload["evidence_stage"],
        domain="ChaCha20 W46-to-W52 coordinate transfer",
        quality_score=1.0,
    )
    writer.add_triplet(
        trigger="A436:actual_off_axis_calibration_cell_0x77c",
        mechanism="minimum_corrected_rank_across_eight_frozen_views",
        outcome="A436:corrected_pair_global_raw_selection",
        confidence=1.0,
        source=payload["selection_commitment_sha256"],
        quantification=json.dumps(payload["coordinate_selection"], sort_keys=True),
        evidence=SELECTED_VIEW,
        domain="corrected known-key off-axis calibration",
        quality_score=1.0,
    )
    writer.add_triplet(
        trigger="A432:complete_unlabeled_W52_off_axis_field",
        mechanism="zero_reexecution_eight_view_reassembly_under_corrected_selection",
        outcome=terminal,
        confidence=1.0,
        source=payload["measurement_sha256"],
        quantification=json.dumps(payload["measurement_summary"], sort_keys=True),
        evidence=json.dumps(payload["unlabeled_order_comparison"], sort_keys=True),
        domain="public-output-derived W52 off-axis ordering",
        quality_score=1.0,
    )
    writer.add_triplet(
        trigger="A354:exact_coordinate_codec_audit",
        mechanism="materialized_coordinate_correction_selection_and_W52_reassembly",
        outcome=terminal,
        confidence=1.0,
        source="materialized:A436_corrected_off_axis_chain",
        quantification="exact retained closure",
        evidence=payload["evidence_stage"],
        domain="AI-native retained inference",
        quality_score=1.0,
        is_inferred=True,
    )
    writer.add_cluster(
        name="A436 corrected off-axis W52 reader",
        entities=[
            "A354:exact_coordinate_codec_audit",
            "A436:actual_off_axis_calibration_cell_0x77c",
            "A436:corrected_pair_global_raw_selection",
            "A432:complete_unlabeled_W52_off_axis_field",
            terminal,
        ],
    )
    writer.add_gap(
        subject=terminal,
        predicate="next_required_object",
        expected_object_type="calibration_balanced_dual_axis_wavefront",
        confidence=1.0,
        suggested_queries=[
            "Combine A436's corrected rank-561 off-axis calibration with A355's rank-418 prefix calibration in an exact anisotropic rectangle-growth wavefront."
        ],
    )
    temporary = CAUSAL.with_name(f".{CAUSAL.name}.{os.getpid()}.tmp")
    temporary.unlink(missing_ok=True)
    stats = writer.save(str(temporary))
    os.replace(temporary, CAUSAL)
    reader = CausalReader(str(CAUSAL), verify_integrity=True)
    explicit = reader.get_all_triplets(include_inferred=False)
    all_rows = reader.get_all_triplets(include_inferred=True)
    inferred = [row for row in reader._triplets if row.get("is_inferred", False)]
    if (
        reader.api_id != "a436off"
        or len(explicit) != 3
        or len(all_rows) != 4
        or len(inferred) != 1
        or len(reader._rules) != 3
        or len(reader._clusters) != 1
        or len(reader._gaps) != 1
    ):
        raise RuntimeError("A436 authentic Causal reopen gate failed")
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
            "coordinate_correction": explicit[0],
            "selection": explicit[1],
            "W52_transfer": explicit[2],
            "terminal_chain": all_rows[-1],
            "next_gap": reader._gaps[0],
        },
    }


def assemble(*, expected_implementation_sha256: str) -> dict[str, Any]:
    if RESULT.exists() or CAUSAL.exists() or REPORT.exists():
        raise FileExistsError("A436 result artifact exists")
    assert_pre_a426_outcome()
    implementation = load_implementation(expected_implementation_sha256)
    selection = corrected_selection()
    started = time.perf_counter()
    reconstructed = reconstruct()
    source = reconstructed["source"]
    schedule = reconstructed["schedule"]
    measurement_summary = {
        "complete_off_axis_cells": CELLS,
        "low4_slices": 16,
        "high8_cells_per_slice": 256,
        "solver_stages_reused": reconstructed["solver_stages_reused"],
        "new_solver_stages": 0,
        "status_counts": reconstructed["status_counts"],
        "frozen_reader_views_reconstructed": len(VIEWS),
        "target_labels_used": 0,
        "reader_refits": 0,
        "candidate_assignments_executed": 0,
    }
    essential = {
        "selected_view": SELECTED_VIEW,
        "selection_commitment_sha256": selection["selection_commitment_sha256"],
        "A426_public_challenge_sha256": source["A426_public_challenge_sha256"],
        "measurement_sha256": source["measurement_sha256"],
        "score_field_sha256": reconstructed["score_hashes"][SELECTED_VIEW],
        "W52_corrected_off_axis_order_uint16be_sha256": schedule["global_order_uint16be_sha256"],
        "worker_cell_order_uint16be_sha256": schedule["worker_cell_order_uint16be_sha256"],
        "worker_task_list_sha256": schedule["worker_task_list_sha256"],
        "target_labels_used": 0,
        "reader_refits": 0,
        "candidate_assignments_executed": 0,
        "A426_progress_or_filter_outcomes_consumed": False,
    }
    payload: dict[str, Any] = {
        "schema": "chacha20-round20-w52-corrected-off-axis-reader-a436-result-v1",
        "attempt_id": ATTEMPT_ID,
        "evidence_stage": "CORRECTED_COORDINATE_CALIBRATED_COMPLETE_PUBLIC_OUTPUT_OFF_AXIS_W52_ORDER_RETAINED",
        "design_sha256": DESIGN_SHA256,
        "implementation_sha256": expected_implementation_sha256,
        "implementation_commitment_sha256": implementation["implementation_commitment_sha256"],
        "source_A354_result_sha256": A354_RESULT_SHA256,
        "source_A355_result_sha256": A355_RESULT_SHA256,
        "source_A432_result_sha256": A432_RESULT_SHA256,
        **essential,
        "coordinate_selection": selection,
        "measurement_summary": measurement_summary,
        "measurement_ledger": reconstructed["ledgers"],
        "all_view_score_field_sha256": reconstructed["score_hashes"],
        "all_view_order_uint16be_sha256": reconstructed["order_hashes"],
        "W52_corrected_off_axis_order": schedule["global_order"],
        "worker_roles": schedule["worker_roles"],
        "worker_cell_orders": schedule["worker_cell_orders"],
        "worker_tasks": schedule["worker_tasks"],
        "cell_epoch_one_based": schedule["cell_epoch_one_based"],
        "cell_worker_role": schedule["cell_worker_role"],
        "schedule_proof": schedule["proof"],
        "unlabeled_order_comparison": reconstructed["comparison"],
        "A432_measurements_reused_without_reexecution": True,
        "A426_result_or_true_assignment_available_at_assembly": False,
        "A426_progress_or_filter_outcomes_consumed": False,
        "volatile_assembly_wall_seconds": time.perf_counter() - started,
        "anchors": {
            "design": anchor(DESIGN, DESIGN_SHA256),
            "implementation": anchor(IMPLEMENTATION, expected_implementation_sha256),
            "A354_result": anchor(A354_RESULT, A354_RESULT_SHA256),
            "A355_result": anchor(A355_RESULT, A355_RESULT_SHA256),
            "A432_result": anchor(A432_RESULT, A432_RESULT_SHA256),
            "A432_runner": anchor(A432_RUNNER, A432_RUNNER_SHA256),
            "runner": anchor(Path(__file__)),
            "test": anchor(TEST),
            "reproducer": anchor(REPRO),
        },
    }
    payload["order_commitment_sha256"] = canonical_sha256(essential)
    payload["schedule_commitment_sha256"] = canonical_sha256(
        {
            "order": schedule["global_order_uint16be_sha256"],
            "workers": schedule["worker_cell_order_uint16be_sha256"],
            "tasks": schedule["worker_task_list_sha256"],
            "epochs": schedule["cell_epoch_one_based"],
        }
    )
    payload["causal"] = build_causal(payload)
    atomic_json(RESULT, payload)
    atomic_bytes(
        REPORT,
        (
            "# A436 — Corrected off-axis W52 Reader\n\n"
            f"Evidence stage: **{payload['evidence_stage']}**\n\n"
            "- A354 actual off-axis calibration cell: **0x77c**\n"
            "- Distinct historical Metal cell: **0xbae**\n"
            f"- Corrected selected view: **{SELECTED_VIEW}**\n"
            f"- Corrected W46 calibration rank: **{EXPECTED_CORRECTED_RANK} / 4096**\n"
            f"- Original A432 view at the corrected cell: **{EXPECTED_ORIGINAL_CORRECTED_RANK} / 4096**\n"
            "- Reused A432 measurements: **16 slices, 16,384 solver stages**\n"
            "- New solver stages / target labels / refits / candidates: **0 / 0 / 0 / 0**\n"
            "- Authentic AI-native Causal readback: **3 explicit + 1 inferred chain**\n"
        ).encode(),
    )
    assert_pre_a426_outcome()
    return payload


def analyze() -> dict[str, Any]:
    payload: dict[str, Any] = {
        "attempt_id": ATTEMPT_ID,
        "design_sha256": DESIGN_SHA256,
        "implementation_frozen": IMPLEMENTATION.exists(),
        "result_complete": RESULT.exists(),
        "selected_view": SELECTED_VIEW,
    }
    load_design()
    payload["corrected_selection"] = corrected_selection()
    if IMPLEMENTATION.exists():
        payload["implementation_sha256"] = file_sha256(IMPLEMENTATION)
        load_implementation(payload["implementation_sha256"])
    if RESULT.exists():
        value = json.loads(RESULT.read_bytes())
        payload["result_sha256"] = file_sha256(RESULT)
        payload["evidence_stage"] = value["evidence_stage"]
        payload["order_sha256"] = value["W52_corrected_off_axis_order_uint16be_sha256"]
    return payload


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    action = parser.add_mutually_exclusive_group(required=True)
    action.add_argument("--analyze", action="store_true")
    action.add_argument("--freeze-implementation", action="store_true")
    action.add_argument("--assemble", action="store_true")
    parser.add_argument("--expected-implementation-sha256")
    args = parser.parse_args()
    if args.freeze_implementation:
        payload = freeze_implementation()
    elif args.assemble:
        if not args.expected_implementation_sha256:
            parser.error("--assemble requires implementation hash")
        payload = assemble(expected_implementation_sha256=args.expected_implementation_sha256)
    else:
        payload = analyze()
    print(json.dumps(payload, indent=2, sort_keys=True), flush=True)


if __name__ == "__main__":
    main()

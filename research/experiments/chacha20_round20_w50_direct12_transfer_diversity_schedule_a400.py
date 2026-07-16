#!/usr/bin/env python3
"""A400: select a W50 Direct12 companion by frozen transfer/diversity rules."""

from __future__ import annotations

import argparse
import importlib.util
import inspect
import json
import math
import os
import statistics
import sys
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

import numpy as np

ROOT = Path(__file__).parents[2]
RESEARCH = ROOT / "research"
CONFIGS = RESEARCH / "configs"
RESULTS = RESEARCH / "results/v1"

DESIGN = CONFIGS / "chacha20_round20_w50_direct12_transfer_diversity_schedule_a400_design_v1.json"
IMPLEMENTATION = CONFIGS / "chacha20_round20_w50_direct12_transfer_diversity_schedule_a400_implementation_v1.json"
RESULT = RESULTS / "chacha20_round20_w50_direct12_transfer_diversity_schedule_a400_v1.json"
CAUSAL = RESULT.with_suffix(".causal")
REPORT = RESULT.with_suffix(".md")
TEST = ROOT / "tests/test_chacha20_round20_w50_direct12_transfer_diversity_schedule_a400.py"
REPRO = ROOT / "scripts/reproduce_chacha20_round20_w50_direct12_transfer_diversity_schedule_a400.sh"

A398_RUNNER = RESEARCH / "experiments/chacha20_round20_w50_dual_direct12_eight_reader_a398.py"
A350_RESULT = RESULTS / "chacha20_round20_w46_a349_order_prospective_recovery_a350_v1.json"
A354_RESULT = RESULTS / "chacha20_round20_w46_direct12_coordinate_codec_audit_a354_v1.json"
A396_RESULT = RESULTS / "chacha20_round20_w50_expanded_seven_reader_eight_worker_a396_v1.json"
A398_RESULT = RESULTS / "chacha20_round20_w50_dual_direct12_eight_reader_a398_v1.json"
A388_ORDER = RESULTS / "chacha20_round20_w50_public_output_direct12_factor3_a388_order_v1.json"
A342_RESULT = RESULTS / "chacha20_round20_w46_exhaustive_reader_ensemble_a342_v1.json"
A385_PROTOCOL = CONFIGS / "chacha20_round20_fresh_w50_pretarget_transfer_a385_v1.json"

ATTEMPT_ID = "A400"
DESIGN_SHA256 = "1ad673a38b18d0e4f27e45b789dc7c1c0b3d558ff9a182c0c886c0fcde461bdf"
A398_RUNNER_SHA256 = "a93b2dbff677d06ccb15e3766a9c60c5b647672089e6763fc59b5e397dd1feee"
A350_RESULT_SHA256 = "a51919d30fc66ee5e581c87d6f2c5dc32cdabe71b51ce79c0a56a12e7325b3f3"
A354_RESULT_SHA256 = "9fc3487266aee3f4e637b9a1afc0b434a5f0c56fa430e9aa14b576cfe8782ac4"
A396_RESULT_SHA256 = "0dd39b595bd111c88b1c94c325c1039a041211e8e11e1e79f71c6470cc8edff8"
A398_RESULT_SHA256 = "fe37839fe18e71166a5d727cb14be96eca53bb6cce2cc3824f5bc4bd885dfd42"
A388_ORDER_SHA256 = "3c56ce8521b1ced20e1e3a90999810c2e563c4de941701c86274f0828b5d01b8"
A342_RESULT_SHA256 = "8d6d6f99b89d67d7eff186037934bfa515cf93a00af10b244826f44056b4cebb"
A385_PROTOCOL_SHA256 = "801831f2daabe41476c9bf1ec676907f11c1b5465a193ba61d8d1877eb3b0b4b"

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
PRIMARY_VIEW = "A342_selected_pair_slice_z"
PRIMITIVE_ROLES = (
    "A379_target_free",
    "A380_target_conditioned",
    "wide_vote",
    "sparse_reciprocal",
    "broad_quantile",
    "broad_intersection",
)
ROLE_PAIR = "A388_W50_public_output_direct12_pair"
ROLE_COMPANION = "A400_W50_public_output_direct12_companion"
SOURCE_ROLES = (*PRIMITIVE_ROLES, ROLE_PAIR, ROLE_COMPANION)
CELLS = 4096
WORKERS = 8
OPTIMAL_EPOCHS = 512
ELIGIBILITY_RANK = 1024
DOTCAUSAL_SRC = Path("/Users/bhkmie/Documents/Forschung/O1/vendor/fabel/dotcausal_package/src")


def load_module(path: Path, name: str) -> Any:
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot import A400 dependency {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


A398 = load_module(A398_RUNNER, "a400_a398")
A396 = A398.A396
A388 = A398.A388

file_sha256 = A398.file_sha256
canonical_sha256 = A398.canonical_sha256
atomic_json = A398.atomic_json
atomic_bytes = A398.atomic_bytes
relative = A398.relative
anchor = A398.anchor
uint16be_sha256 = A398.uint16be_sha256
quantiles = A398.quantiles


def exact_order(values: Sequence[int]) -> list[int]:
    result = [int(value) for value in values]
    if len(result) != CELLS or set(result) != set(range(CELLS)):
        raise ValueError("A400 order is not one exact 4,096-cell permutation")
    return result


def load_design() -> dict[str, Any]:
    if file_sha256(DESIGN) != DESIGN_SHA256:
        raise RuntimeError("A400 design hash differs")
    value = json.loads(DESIGN.read_bytes())
    views = value.get("direct12_view_contract", {})
    selection = value.get("selection_contract", {})
    source = value.get("source_contract", {})
    worker = value.get("worker_contract", {})
    boundary = value.get("information_boundary", {})
    if (
        value.get("schema")
        != "chacha20-round20-w50-direct12-transfer-diversity-schedule-a400-design-v1"
        or value.get("attempt_id") != ATTEMPT_ID
        or value.get("design_state")
        != "frozen_before_materializing_the_complete_W50_Direct12_view_atlas_companion_selection_or_A400_schedule"
        or tuple(views.get("complete_view_order", [])) != VIEW_NAMES
        or views.get("new_solver_stages") != 0
        or views.get("reader_refits") != 0
        or views.get("target_labels") != 0
        or selection.get("locked_primary_view") != PRIMARY_VIEW
        or selection.get("eligibility_threshold_rank_one_based") != ELIGIBILITY_RANK
        or selection.get("selection_after_measurement") is not True
        or selection.get("selection_after_target_label_or_candidate_execution") is not False
        or source.get("source_orders") != len(SOURCE_ROLES)
        or source.get("cells_per_order") != CELLS
        or worker.get("workers") != WORKERS
        or worker.get("target_makespan_epochs") != OPTIMAL_EPOCHS
        or worker.get("theoretical_minimum_epochs") != OPTIMAL_EPOCHS
        or boundary.get("candidate_assignments_executed") != 0
        or boundary.get("new_solver_stages") != 0
        or boundary.get("reader_refits") != 0
        or boundary.get("target_labels_used") != 0
        or boundary.get("A385_unknown_assignment_or_true_prefix_consumed") is not False
        or boundary.get(
            "A387_A389_A391_A393_A395_A397_A399_progress_filter_outcomes_or_results_consumed"
        )
        is not False
    ):
        raise RuntimeError("A400 frozen design semantics differ")
    for key, path in value["source_anchors"].items():
        if key.endswith("_path"):
            stem = key.removesuffix("_path")
            anchor(ROOT / path, value["source_anchors"][f"{stem}_sha256"])
    return value


def load_fixed_artifacts() -> dict[str, dict[str, Any]]:
    anchors = {
        "A398_runner": (A398_RUNNER, A398_RUNNER_SHA256),
        "A350": (A350_RESULT, A350_RESULT_SHA256),
        "A354": (A354_RESULT, A354_RESULT_SHA256),
        "A396": (A396_RESULT, A396_RESULT_SHA256),
        "A398": (A398_RESULT, A398_RESULT_SHA256),
        "A388": (A388_ORDER, A388_ORDER_SHA256),
        "A342": (A342_RESULT, A342_RESULT_SHA256),
        "A385": (A385_PROTOCOL, A385_PROTOCOL_SHA256),
    }
    for path, expected in anchors.values():
        anchor(path, expected)
    values = {
        name: json.loads(path.read_bytes())
        for name, (path, _expected) in anchors.items()
        if name != "A398_runner"
    }
    a350 = values["A350"]
    a354 = values["A354"]
    a396 = values["A396"]
    a398 = values["A398"]
    a388 = values["A388"]
    a342 = values["A342"]
    a385 = values["A385"]
    if (
        a350.get("schema")
        != "chacha20-round20-w46-a349-order-prospective-recovery-a350-result-v1"
        or a350.get("rank_analysis", {}).get("selected_rank_one_based") != 445
        or a350.get("confirmation", {}).get("all_blocks_match") is not True
        or a354.get("schema")
        != "chacha20-round20-w46-direct12-coordinate-codec-audit-a354-v1"
        or a354.get("candidate_assignments_executed") != 0
        or a396.get("candidate_assignments_executed") != 0
        or a398.get("candidate_assignments_executed") != 0
        or a398.get("target_labels_used") != 0
        or a398.get("reader_refits") != 0
        or a388.get("candidate_assignments_executed") != 0
        or a388.get("target_labels_used") != 0
        or a388.get("reader_refits") != 0
        or a342.get("schema")
        != "chacha20-round20-w46-exhaustive-reader-ensemble-a342-result-v1"
        or a385.get("public_challenge", {}).get("unknown_assignment_included") is not False
        or a385.get("public_challenge", {}).get("unknown_key_bits") != 50
    ):
        raise RuntimeError("A400 fixed-artifact information boundary differs")
    return values


def reconstruct_view_atlas() -> tuple[dict[str, list[int]], dict[str, Any]]:
    fixed = load_fixed_artifacts()
    a388 = fixed["A388"]
    measurements = A398.load_measurements(a388)
    _selection, _a272, model, groups = A388.A341.reconstruct_known_key_selection(
        json.loads(A388.A341.DESIGN.read_bytes())
    )
    fields = A388.A348._all_view_scores(measurements, model, groups)  # noqa: SLF001
    if tuple(fields) != VIEW_NAMES:
        raise RuntimeError("A400 reconstructed Direct12 view family differs")
    orders = {
        name: exact_order(A388.A348._rank_order(field))  # noqa: SLF001
        for name, field in fields.items()
    }
    if (
        orders[PRIMARY_VIEW] != exact_order(a388["W50_public_output_direct12_order"])
        or uint16be_sha256(orders[PRIMARY_VIEW])
        != a388["W50_public_output_direct12_order_uint16be_sha256"]
    ):
        raise RuntimeError("A400 reconstructed primary bytes differ from A388")

    rank_panel = fixed["A354"]["corrected_A348_rank_panel"]
    corrected_ranks = {
        name: int(rank_panel[name]["rank_at_actual_A348_measured_cell"]["rank_one_based"])
        for name in VIEW_NAMES
    }
    atlas: dict[str, Any] = {}
    for left_index, left in enumerate(VIEW_NAMES):
        for right in VIEW_NAMES[left_index + 1 :]:
            atlas[f"{left}__vs__{right}"] = A388.A351.diversity_panel(
                orders[left], orders[right]
            )
    candidates: list[dict[str, Any]] = []
    for name in VIEW_NAMES:
        if name == PRIMARY_VIEW:
            continue
        diversity = A388.A351.diversity_panel(orders[PRIMARY_VIEW], orders[name])
        rank = corrected_ranks[name]
        candidates.append(
            {
                "view": name,
                "corrected_W46_rank_one_based": rank,
                "eligible": rank <= ELIGIBILITY_RANK,
                "absolute_W50_spearman_to_primary": abs(
                    float(diversity["spearman_rank_correlation"])
                ),
                "W50_diversity_to_primary": diversity,
            }
        )
    eligible = [row for row in candidates if row["eligible"]]
    if not eligible:
        raise RuntimeError("A400 frozen eligibility rule produced no companion")
    winner = min(
        eligible,
        key=lambda row: (
            row["absolute_W50_spearman_to_primary"],
            row["corrected_W46_rank_one_based"],
            row["view"],
        ),
    )
    metadata = {
        "view_score_field_sha256": {
            name: canonical_sha256(np.asarray(fields[name], dtype=np.float64).tolist())
            for name in VIEW_NAMES
        },
        "view_order_uint16be_sha256": {
            name: uint16be_sha256(orders[name]) for name in VIEW_NAMES
        },
        "corrected_W46_rank_one_based": corrected_ranks,
        "pairwise_W50_diversity_atlas": atlas,
        "companion_candidates": candidates,
        "selected_companion": winner,
        "measurement_sha256": a388["measurement_sha256"],
    }
    return orders, metadata


def load_source_orders() -> tuple[dict[str, list[int]], dict[str, Any]]:
    direct, metadata = reconstruct_view_atlas()
    _a382, inherited, _a388_loaded = A396.load_sources()
    orders = {role: exact_order(inherited[role]) for role in PRIMITIVE_ROLES}
    orders[ROLE_PAIR] = direct[PRIMARY_VIEW]
    orders[ROLE_COMPANION] = direct[metadata["selected_companion"]["view"]]
    if tuple(orders) != SOURCE_ROLES or orders[ROLE_PAIR] == orders[ROLE_COMPANION]:
        raise RuntimeError("A400 selected source family differs")
    return orders, metadata


def prove_schedule(
    owners: Mapping[str, Any], work: Mapping[str, Any], orders: Mapping[str, Sequence[int]]
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    fixed = load_fixed_artifacts()
    old396 = [int(value) for value in fixed["A396"]["cell_epoch_one_based"]]
    old398 = [int(value) for value in fixed["A398"]["cell_epoch_one_based"]]
    serial_order = exact_order(fixed["A388"]["selected_order"])
    serial_rank = [0] * CELLS
    for rank, cell in enumerate(serial_order, 1):
        serial_rank[cell] = rank
    epochs = [int(value) for value in work["cell_epoch_one_based"]]
    owner_depths = [int(value) for value in owners["owner_lane_depth_one_based"]]
    ranks = owners["source_ranks_one_based"]
    comparison_counts = {
        "A396": {"earlier": 0, "equal": 0, "later": 0},
        "A398": {"earlier": 0, "equal": 0, "later": 0},
    }
    ratios396: list[float] = []
    ratios398: list[float] = []
    serial_speedups: list[float] = []
    depth_ratios: list[float] = []
    work_ratios: list[float] = []
    per_cell: list[dict[str, Any]] = []
    companion_owned = 0
    for cell in range(CELLS):
        best_rank = min(int(ranks[role][cell]) for role in SOURCE_ROLES)
        owner = str(owners["owner_role"][cell])
        owner_rank = int(ranks[owner][cell])
        owner_depth = owner_depths[cell]
        epoch = epochs[cell]
        total_work = min(WORKERS * epoch, CELLS)
        if owner_rank != best_rank or epoch > owner_depth or owner_depth > best_rank:
            raise RuntimeError("A400 minimum-rank depth theorem failed")
        if total_work > WORKERS * best_rank:
            raise RuntimeError("A400 total-work theorem failed")
        for label, old in (("A396", old396[cell]), ("A398", old398[cell])):
            relation = "earlier" if epoch < old else "equal" if epoch == old else "later"
            comparison_counts[label][relation] += 1
        companion_owned += owner == ROLE_COMPANION
        ratios396.append(old396[cell] / epoch)
        ratios398.append(old398[cell] / epoch)
        serial_speedups.append(serial_rank[cell] / epoch)
        depth_ratios.append(epoch / best_rank)
        work_ratios.append(total_work / (WORKERS * best_rank))
        per_cell.append(
            {
                "cell": cell,
                "owner": owner,
                "best_source_rank_one_based": best_rank,
                "owner_lane_depth_one_based": owner_depth,
                "A400_epoch_one_based": epoch,
                "A398_epoch_one_based": old398[cell],
                "A396_epoch_one_based": old396[cell],
                "A388_serial_wavefront_rank_one_based": serial_rank[cell],
                "total_unique_work_at_A400_epoch": total_work,
            }
        )
    proof = {
        "cells_checked": CELLS,
        "complete_cover_cells": work["complete_cover_cells"],
        "duplicate_cells": work["duplicate_cells"],
        "uncovered_cells": work["uncovered_cells"],
        "owner_queue_order_preservation_violations": 0,
        "depth_bound": "D_A400(c) <= D_owner(c) <= min_i R_i(c)",
        "depth_bound_violations": 0,
        "maximum_depth_to_best_source_ratio": max(depth_ratios),
        "total_work_bound": "W_A400(c) <= 8*min_i R_i(c)",
        "total_work_bound_violations": 0,
        "maximum_total_work_to_bound_ratio": max(work_ratios),
        "makespan_epochs": work["epochs"],
        "theoretical_minimum_epochs": work["theoretical_minimum_epochs"],
        "makespan_optimal": work["epochs"] == work["theoretical_minimum_epochs"],
        "comparison_counts": comparison_counts,
        "selected_companion_owned_cells": companion_owned,
        "geometric_mean_A396_to_A400_epoch_ratio": math.exp(
            statistics.fmean(math.log(value) for value in ratios396)
        ),
        "geometric_mean_A398_to_A400_epoch_ratio": math.exp(
            statistics.fmean(math.log(value) for value in ratios398)
        ),
        "geometric_mean_A388_serial_to_A400_epoch_speedup": math.exp(
            statistics.fmean(math.log(value) for value in serial_speedups)
        ),
        "A400_epoch_quantiles": quantiles(epochs),
        "A396_to_A400_epoch_ratio_quantiles": quantiles(ratios396),
        "A398_to_A400_epoch_ratio_quantiles": quantiles(ratios398),
        "A388_serial_to_A400_speedup_quantiles": quantiles(serial_speedups),
    }
    if (
        proof["complete_cover_cells"] != CELLS
        or proof["duplicate_cells"] != 0
        or proof["uncovered_cells"] != 0
        or proof["makespan_epochs"] != OPTIMAL_EPOCHS
        or not proof["makespan_optimal"]
        or set(work["worker_task_counts"].values()) != {OPTIMAL_EPOCHS}
    ):
        raise RuntimeError("A400 complete optimal-makespan proof failed")
    return proof, per_cell


def freeze_implementation() -> dict[str, Any]:
    if any(path.exists() for path in (IMPLEMENTATION, RESULT, CAUSAL, REPORT)):
        raise FileExistsError("A400 implementation or result already exists")
    design = load_design()
    orders, metadata = load_source_orders()
    if not TEST.exists() or not REPRO.exists():
        raise FileNotFoundError("A400 test and reproducer must precede freeze")
    payload: dict[str, Any] = {
        "schema": "chacha20-round20-w50-direct12-transfer-diversity-schedule-a400-implementation-v1",
        "attempt_id": ATTEMPT_ID,
        "commitment_state": "frozen_after_complete_unlabeled_W50_atlas_and_rule_selection_before_A400_schedule_or_candidate_execution",
        "design_sha256": DESIGN_SHA256,
        "selection_contract": design["selection_contract"],
        "selected_companion": metadata["selected_companion"],
        "view_order_uint16be_sha256": metadata["view_order_uint16be_sha256"],
        "source_order_uint16be_sha256": {
            role: uint16be_sha256(orders[role]) for role in SOURCE_ROLES
        },
        "atlas_commitment_sha256": canonical_sha256(
            metadata["pairwise_W50_diversity_atlas"]
        ),
        "candidate_assignments_available_at_freeze": 0,
        "anchors": {
            "design": anchor(DESIGN, DESIGN_SHA256),
            "A398_runner": anchor(A398_RUNNER, A398_RUNNER_SHA256),
            "A350_result": anchor(A350_RESULT, A350_RESULT_SHA256),
            "A354_result": anchor(A354_RESULT, A354_RESULT_SHA256),
            "A396_result": anchor(A396_RESULT, A396_RESULT_SHA256),
            "A398_result": anchor(A398_RESULT, A398_RESULT_SHA256),
            "A388_order": anchor(A388_ORDER, A388_ORDER_SHA256),
            "A342_result": anchor(A342_RESULT, A342_RESULT_SHA256),
            "A385_protocol": anchor(A385_PROTOCOL, A385_PROTOCOL_SHA256),
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
        raise RuntimeError("A400 implementation hash differs")
    value = json.loads(IMPLEMENTATION.read_bytes())
    if (
        value.get("schema")
        != "chacha20-round20-w50-direct12-transfer-diversity-schedule-a400-implementation-v1"
        or value.get("attempt_id") != ATTEMPT_ID
        or value.get("design_sha256") != DESIGN_SHA256
        or set(value.get("source_order_uint16be_sha256", {})) != set(SOURCE_ROLES)
        or value.get("candidate_assignments_available_at_freeze") != 0
    ):
        raise RuntimeError("A400 implementation semantics differ")
    for ref in value["anchors"].values():
        anchor(ROOT / ref["path"], ref["sha256"])
    unsigned = {key: item for key, item in value.items() if key != "implementation_commitment_sha256"}
    if value.get("implementation_commitment_sha256") != canonical_sha256(unsigned):
        raise RuntimeError("A400 implementation commitment differs")
    return value


def build_causal(payload: Mapping[str, Any]) -> dict[str, Any]:
    sys.path.insert(0, str(DOTCAUSAL_SRC))
    from dotcausal.io import CausalReader, CausalWriter

    writer = CausalWriter(api_id="a400w50")
    writer._rules = []
    writer.add_rule(
        name="complete_measurement_to_eight_view_atlas",
        description="Eight frozen Direct12 transforms read the same complete unlabeled W50 measurement field without refit or new solver stages.",
        pattern=["A388_complete_W50_Direct12_measurement", "A340_A342_frozen_reader_family"],
        conclusion="A400_complete_W50_Direct12_atlas",
        confidence_modifier=1.0,
    )
    writer.add_rule(
        name="transfer_gate_and_diversity_to_companion",
        description="The prospective pair-slice Reader remains fixed; the companion first passes the corrected W46 top-quartile gate and then minimizes absolute W50 Spearman correlation.",
        pattern=["A350_confirmed_pair_slice", "A354_corrected_W46_ranks", "A400_complete_W50_Direct12_atlas"],
        conclusion="A400_selected_complementary_Direct12_reader",
        confidence_modifier=1.0,
    )
    writer.add_rule(
        name="eight_sources_to_optimal_schedule",
        description="Six inherited primitive Readers plus the fixed pair and selected companion induce exact min-rank owner lanes and an optimal 512-epoch eight-worker cover.",
        pattern=["A396_six_primitive_orders", "A350_confirmed_pair_slice", "A400_selected_complementary_Direct12_reader"],
        conclusion="A400_optimal_eight_worker_schedule",
        confidence_modifier=1.0,
    )
    writer.add_rule(
        name="schedule_to_executor",
        description="The exact task lists are ready for a shared-stop complete W50 executor without changing source order or prefix coverage.",
        pattern=["A400_optimal_eight_worker_schedule", "A384_qualified_complete_W50_engine"],
        conclusion="A401_recovery_executor_ready",
        confidence_modifier=1.0,
    )
    writer.add_triplet(
        trigger="A388:complete_unlabeled_W50_Direct12_field",
        mechanism="eight_frozen_zero_refit_reader_transforms",
        outcome="A400:complete_W50_Direct12_diversity_atlas",
        confidence=1.0,
        source=payload["atlas_commitment_sha256"],
        quantification=json.dumps(payload["view_order_uint16be_sha256"], sort_keys=True),
        evidence="zero new solver stages, target labels, candidate assignments, or reader refits",
        domain="full-round ChaCha20 W50 public-output Reader transfer",
        quality_score=1.0,
    )
    writer.add_triplet(
        trigger="A350:confirmed_pair_slice_plus_A354:corrected_transfer_panel",
        mechanism="frozen_top_quartile_gate_then_minimum_absolute_W50_spearman",
        outcome="A400:selected_complementary_Direct12_reader",
        confidence=1.0,
        source=payload["source_commitment_sha256"],
        quantification=json.dumps(payload["selected_companion"], sort_keys=True),
        evidence=json.dumps(payload["companion_candidates"], sort_keys=True),
        domain="transfer-qualified Reader diversity selection",
        quality_score=1.0,
    )
    writer.add_triplet(
        trigger="A396:six_primitives_plus_A388:pair_plus_A400:companion",
        mechanism="minimum_rank_owner_partition_and_static_longest_remaining_work_stealing",
        outcome="A400:optimal_512_epoch_eight_worker_schedule",
        confidence=1.0,
        source=payload["schedule_commitment_sha256"],
        quantification=json.dumps(payload["proof"], sort_keys=True),
        evidence=json.dumps(payload["owner_lane_sizes"], sort_keys=True),
        domain="bounded complete W50 recovery schedule",
        quality_score=1.0,
    )
    writer.add_triplet(
        trigger="A400:optimal_schedule_plus_A384:qualified_engine",
        mechanism="materialized_shared_stop_eight_worker_execution_chain",
        outcome="A401:complete_W50_recovery_ready",
        confidence=1.0,
        source="materialized:A400_W50_chain",
        quantification="exact retained closure",
        evidence="every worker has 512 complete prefix groups and all 4096 groups occur exactly once",
        domain="AI-native retained inference",
        quality_score=1.0,
        is_inferred=True,
    )
    writer.add_cluster(
        name="A400 W50 transfer-qualified Direct12 Reader portfolio",
        entities=[
            "A350:confirmed_pair_slice",
            "A354:corrected_W46_ranks",
            "A400:complete_W50_Direct12_diversity_atlas",
            "A400:selected_complementary_Direct12_reader",
            "A400:optimal_512_epoch_eight_worker_schedule",
            "A401:complete_W50_recovery_ready",
        ],
    )
    writer.add_gap(
        subject="A401:complete_W50_recovery_ready",
        predicate="next_required_object",
        expected_object_type="executed_fullround_W50_recovery_in_frozen_A400_worker_lists",
        confidence=1.0,
        suggested_queries=["Execute the first available frozen A400 worker list with shared-stop semantics."],
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
        reader.api_id != "a400w50"
        or len(explicit) != 3
        or len(all_rows) != 4
        or len(inferred) != 1
        or len(reader._rules) != 4
        or len(reader._clusters) != 1
        or len(reader._gaps) != 1
    ):
        raise RuntimeError("A400 authentic Causal reopen gate failed")
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
            "atlas": explicit[0],
            "selection": explicit[1],
            "schedule": explicit[2],
            "terminal_chain": all_rows[-1],
            "next_gap": reader._gaps[0],
        },
    }


def materialize(*, expected_implementation_sha256: str) -> dict[str, Any]:
    if any(path.exists() for path in (RESULT, CAUSAL, REPORT)):
        raise FileExistsError("A400 result artifact already exists")
    implementation = load_implementation(expected_implementation_sha256)
    orders, metadata = load_source_orders()
    hashes = {role: uint16be_sha256(orders[role]) for role in SOURCE_ROLES}
    if (
        hashes != implementation["source_order_uint16be_sha256"]
        or metadata["selected_companion"] != implementation["selected_companion"]
        or canonical_sha256(metadata["pairwise_W50_diversity_atlas"])
        != implementation["atlas_commitment_sha256"]
    ):
        raise RuntimeError("A400 recomputed atlas or selection differs from freeze")
    owners = A396.minimum_rank_owner_lanes(orders, SOURCE_ROLES, size=CELLS)
    work = A398.balanced_equal_worker_schedule(owners["owner_lane_orders"], SOURCE_ROLES)
    proof, per_cell = prove_schedule(owners, work, orders)
    source_commitment = canonical_sha256(
        {
            "source_role_order": list(SOURCE_ROLES),
            "source_order_uint16be_sha256": hashes,
            "selected_companion": metadata["selected_companion"],
            "atlas_commitment_sha256": implementation["atlas_commitment_sha256"],
        }
    )
    owner_commitment = canonical_sha256(
        {
            "owner_lane_sizes": owners["owner_lane_sizes"],
            "owner_lane_order_uint16be_sha256": owners["owner_lane_order_uint16be_sha256"],
        }
    )
    schedule_commitment = canonical_sha256(
        {
            "worker_role_order": list(SOURCE_ROLES),
            "worker_cell_order_uint16be_sha256": work["worker_cell_order_uint16be_sha256"],
            "worker_task_list_sha256": work["worker_task_list_sha256"],
            "proof": proof,
        }
    )
    payload: dict[str, Any] = {
        "schema": "chacha20-round20-w50-direct12-transfer-diversity-schedule-a400-result-v1",
        "attempt_id": ATTEMPT_ID,
        "evidence_stage": "EXACT_TRANSFER_QUALIFIED_W50_DIRECT12_ATLAS_AND_OPTIMAL_EIGHT_WORKER_SCHEDULE_RETAINED",
        "design_sha256": DESIGN_SHA256,
        "implementation_sha256": expected_implementation_sha256,
        "implementation_commitment_sha256": implementation["implementation_commitment_sha256"],
        "view_score_field_sha256": metadata["view_score_field_sha256"],
        "view_order_uint16be_sha256": metadata["view_order_uint16be_sha256"],
        "corrected_W46_rank_one_based": metadata["corrected_W46_rank_one_based"],
        "pairwise_W50_diversity_atlas": metadata["pairwise_W50_diversity_atlas"],
        "atlas_commitment_sha256": implementation["atlas_commitment_sha256"],
        "companion_candidates": metadata["companion_candidates"],
        "selected_companion": metadata["selected_companion"],
        "source_role_order": list(SOURCE_ROLES),
        "worker_role_order": list(SOURCE_ROLES),
        "source_order_uint16be_sha256": hashes,
        "owner_lane_orders": owners["owner_lane_orders"],
        "owner_lane_sizes": owners["owner_lane_sizes"],
        "owner_lane_order_uint16be_sha256": owners["owner_lane_order_uint16be_sha256"],
        "worker_tasks": work["worker_tasks"],
        "worker_cell_orders": work["worker_cell_orders"],
        "worker_cell_order_uint16be_sha256": work["worker_cell_order_uint16be_sha256"],
        "worker_task_list_sha256": work["worker_task_list_sha256"],
        "worker_task_counts": work["worker_task_counts"],
        "worker_stolen_task_counts": work["worker_stolen_task_counts"],
        "cell_epoch_one_based": work["cell_epoch_one_based"],
        "cell_worker_role": work["cell_worker_role"],
        "cell_owner_queue_role": work["cell_owner_queue_role"],
        "cell_owner_queue_position_one_based": work["cell_owner_queue_position_one_based"],
        "proof": proof,
        "per_cell_proof": per_cell,
        "source_commitment_sha256": source_commitment,
        "owner_lane_commitment_sha256": owner_commitment,
        "schedule_commitment_sha256": schedule_commitment,
        "candidate_assignments_executed": 0,
        "target_labels_used": 0,
        "reader_refits": 0,
        "new_solver_stages": 0,
        "progress_or_filter_outcomes_consumed": 0,
        "anchors": implementation["anchors"],
    }
    payload["measurement_sha256"] = canonical_sha256(
        {
            "source_commitment_sha256": source_commitment,
            "owner_lane_commitment_sha256": owner_commitment,
            "schedule_commitment_sha256": schedule_commitment,
            "proof": proof,
            "candidate_assignments_executed": 0,
            "target_labels_used": 0,
            "new_solver_stages": 0,
        }
    )
    payload["causal"] = build_causal(payload)
    atomic_json(RESULT, payload)
    selected = metadata["selected_companion"]
    atomic_bytes(
        REPORT,
        (
            "# A400 — transfer-qualified W50 Direct12 Reader portfolio\n\n"
            f"Evidence stage: **{payload['evidence_stage']}**\n\n"
            f"- Frozen-rule companion: **{selected['view']}**\n"
            f"- Corrected W46 rank / 4,096: **{selected['corrected_W46_rank_one_based']}**\n"
            f"- Absolute W50 Spearman to confirmed Pair-slice: **{selected['absolute_W50_spearman_to_primary']:.9f}**\n"
            f"- Complete owner-lane sizes: **{owners['owner_lane_sizes']}**\n"
            f"- Worker task counts: **{work['worker_task_counts']}**\n"
            f"- Makespan / theoretical minimum: **{proof['makespan_epochs']} / {proof['theoretical_minimum_epochs']} epochs**\n"
            f"- Earlier / equal / later than A398: **{proof['comparison_counts']['A398']['earlier']} / {proof['comparison_counts']['A398']['equal']} / {proof['comparison_counts']['A398']['later']}**\n"
            f"- Earlier / equal / later than A396: **{proof['comparison_counts']['A396']['earlier']} / {proof['comparison_counts']['A396']['equal']} / {proof['comparison_counts']['A396']['later']}**\n"
            f"- Geometric A388-serial-to-A400 speedup: **{proof['geometric_mean_A388_serial_to_A400_epoch_speedup']:.9f}x**\n"
            "- Duplicate / uncovered prefixes: **0 / 0**\n"
            "- New solver stages / candidates / labels / refits: **0 / 0 / 0 / 0**\n"
            "- Authentic AI-native Causal readback: **3 explicit + 1 inferred chain**\n"
        ).encode(),
    )
    return payload


def analyze() -> dict[str, Any]:
    payload: dict[str, Any] = {
        "attempt_id": ATTEMPT_ID,
        "design_sha256": DESIGN_SHA256,
        "implementation_frozen": IMPLEMENTATION.exists(),
        "result_complete": RESULT.exists(),
    }
    if IMPLEMENTATION.exists():
        payload["implementation_sha256"] = file_sha256(IMPLEMENTATION)
    if RESULT.exists():
        value = json.loads(RESULT.read_bytes())
        payload.update(
            {
                "result_sha256": file_sha256(RESULT),
                "evidence_stage": value["evidence_stage"],
                "selected_companion": value["selected_companion"],
                "schedule_commitment_sha256": value["schedule_commitment_sha256"],
                "owner_lane_sizes": value["owner_lane_sizes"],
                "proof": value["proof"],
            }
        )
    return payload


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    action = parser.add_mutually_exclusive_group(required=True)
    action.add_argument("--freeze-implementation", action="store_true")
    action.add_argument("--materialize", action="store_true")
    action.add_argument("--analyze", action="store_true")
    parser.add_argument("--expected-implementation-sha256")
    args = parser.parse_args()
    if args.freeze_implementation:
        payload = freeze_implementation()
    elif args.materialize:
        if not args.expected_implementation_sha256:
            parser.error("--materialize requires --expected-implementation-sha256")
        payload = materialize(expected_implementation_sha256=args.expected_implementation_sha256)
    else:
        payload = analyze()
    print(json.dumps(payload, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()

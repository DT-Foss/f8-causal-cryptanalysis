#!/usr/bin/env python3
"""A428: turn A427's eight Reader ranks into a global exact worker wavefront."""

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

ROOT = Path(__file__).parents[2]
RESEARCH = ROOT / "research"
CONFIGS = RESEARCH / "configs"
RESULTS = RESEARCH / "results/v1"
STEM = "chacha20_round20_w50_global_best_rank_wavefront_a428"
DESIGN = CONFIGS / f"{STEM}_design_v1.json"
IMPLEMENTATION = CONFIGS / f"{STEM}_implementation_v1.json"
RESULT = RESULTS / f"{STEM}_v1.json"
CAUSAL = RESULT.with_suffix(".causal")
REPORT = RESULT.with_suffix(".md")
TEST = ROOT / "tests/test_chacha20_round20_w50_global_best_rank_wavefront_a428.py"
REPRO = ROOT / "scripts/reproduce_chacha20_round20_w50_global_best_rank_wavefront_a428.sh"
A427_RUNNER = RESEARCH / "experiments/chacha20_round20_w50_majority_3to1_complete_portfolio_a427.py"
A427_RESULT = RESULTS / "chacha20_round20_w50_majority_3to1_complete_portfolio_a427_v1.json"
A427_CAUSAL = A427_RESULT.with_suffix(".causal")
A427_MODEL = CONFIGS / "chacha20_round20_w50_majority_3to1_complete_portfolio_a427_model_v1.json"
A416_RESULT = RESULTS / "chacha20_round20_w50_folded_xor_portfolio_a416_v1.json"
A412_PROTOCOL = CONFIGS / "chacha20_round20_w50_fresh_hybrid_reader_a412_public_corpus_v1.json"

ATTEMPT_ID = "A428"
DESIGN_SHA256 = "f9c1ab5b129b874572fb17c8799309a41beee9a8d246c30003739103f97735f0"
A427_RUNNER_SHA256 = "cb8d8c9a12799a7fe1ccd37f0ec0af72234104ffbf8b6081b2c0ec13d4271cb8"
A427_RESULT_SHA256 = "8255e600234731179a1431a1f1e36e4ab1cdab6082bea52191b8a4eb79f1c248"
A427_CAUSAL_SHA256 = "c05aa4fc5158c20000a4c6903e29e2f82753638f221a086dd54f105605b7da64"
A427_MODEL_SHA256 = "e9080666d97dd714c1ba6ee40070c1d1a1ad6789597f0fd0b48f831f18b3eb08"
A416_RESULT_SHA256 = "7623bd8d1a11d00c771e8aa24e2e3847dafe92ebbfffa34e761434a09a24b686"
A412_PROTOCOL_SHA256 = "f7859b381d5cf6a5f1a765b4abb44192d3bd73539c681a9a40d8c0a48dd365a2"
CELLS = 4096
WORKERS = 8
EPOCHS = 512
DOTCAUSAL_SRC = Path("/Users/bhkmie/Documents/Forschung/O1/vendor/fabel/dotcausal_package/src")


def load_module(path: Path, name: str) -> Any:
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot import A428 dependency {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


A427 = load_module(A427_RUNNER, "a428_a427")
A416 = A427.A416
A412 = A427.A412
A401 = A427.A401
file_sha256 = A427.file_sha256
canonical_sha256 = A427.canonical_sha256
atomic_json = A427.atomic_json
atomic_bytes = A427.atomic_bytes
relative = A427.relative
anchor = A427.anchor
uint16be_sha256 = A427.uint16be_sha256
exact_order = A427.exact_order


def path_from_ref(value: str | Path) -> Path:
    path = Path(value)
    return path if path.is_absolute() else ROOT / path


def load_design() -> dict[str, Any]:
    if file_sha256(DESIGN) != DESIGN_SHA256:
        raise RuntimeError("A428 design hash differs")
    value = json.loads(DESIGN.read_bytes())
    mechanism = value.get("mechanism", {})
    evaluation = value.get("evaluation_contract", {})
    boundary = value.get("information_boundary", {})
    if (
        value.get("schema")
        != "chacha20-round20-w50-global-best-rank-wavefront-a428-design-v1"
        or value.get("attempt_id") != ATTEMPT_ID
        or value.get("design_state")
        != "frozen_after_A427_and_scheduler_depth_diagnostic_before_any_A428_candidate_schedule_measurement_or_production_execution"
        or mechanism.get("cells") != CELLS
        or mechanism.get("workers") != WORKERS
        or mechanism.get("complete_epochs") != EPOCHS
        or mechanism.get("reader_refits") != 0
        or mechanism.get("new_solver_stages") != 0
        or evaluation.get("production_execution_in_this_attempt") is not False
        or boundary.get("A428_global_wavefront_target_epochs_available_at_design_freeze") is not False
        or boundary.get("A428_candidate_schedule_available_at_design_freeze") is not False
        or boundary.get("A428_production_target_label_used") != 0
        or boundary.get("A428_production_candidate_assignments_executed") != 0
        or boundary.get("live_recovery_progress_or_filter_outcomes_used_for_schedule") is not False
    ):
        raise RuntimeError("A428 frozen design semantics differ")
    for key, item in value["source_anchors"].items():
        if key.endswith("_path"):
            stem = key.removesuffix("_path")
            anchor(ROOT / item, value["source_anchors"][f"{stem}_sha256"])
    return value


def rank_vectors(source_orders: Mapping[str, Sequence[int]], roles: Sequence[str]) -> dict[str, list[int]]:
    frozen_roles = tuple(str(role) for role in roles)
    if frozen_roles != tuple(source_orders) or len(frozen_roles) != WORKERS:
        raise ValueError("A428 source-role order differs")
    ranks: dict[str, list[int]] = {}
    for role in frozen_roles:
        order = exact_order(source_orders[role])
        vector = [0] * CELLS
        for rank, cell in enumerate(order, 1):
            vector[cell] = rank
        ranks[role] = vector
    return ranks


def global_best_rank_wavefront(source_orders: Mapping[str, Sequence[int]], roles: Sequence[str]) -> dict[str, Any]:
    frozen_roles = tuple(str(role) for role in roles)
    ranks = rank_vectors(source_orders, frozen_roles)

    def score(cell: int) -> tuple[Any, ...]:
        ordered = tuple(ranks[role][cell] for role in frozen_roles)
        best = min(ordered)
        return best, tuple(sorted(ordered)), ordered.index(best), cell

    global_order = sorted(range(CELLS), key=score)
    if len(global_order) != CELLS or set(global_order) != set(range(CELLS)):
        raise RuntimeError("A428 global order is not one complete permutation")
    worker_tasks: dict[str, list[dict[str, Any]]] = {role: [] for role in frozen_roles}
    worker_orders: dict[str, list[int]] = {role: [] for role in frozen_roles}
    cell_epoch = [0] * CELLS
    cell_worker = [""] * CELLS
    cell_best_rank = [0] * CELLS
    cell_support_rank_vector: list[list[int]] = [[] for _ in range(CELLS)]
    for index, cell in enumerate(global_order):
        epoch = index // WORKERS + 1
        worker_index = index % WORKERS
        worker = frozen_roles[worker_index]
        ordered = [ranks[role][cell] for role in frozen_roles]
        row = {
            "cell": cell,
            "epoch": epoch,
            "worker_role": worker,
            "worker_step_one_based": len(worker_tasks[worker]) + 1,
            "global_position_one_based": index + 1,
            "best_source_rank_one_based": min(ordered),
            "best_source_role": frozen_roles[ordered.index(min(ordered))],
        }
        worker_tasks[worker].append(row)
        worker_orders[worker].append(cell)
        cell_epoch[cell] = epoch
        cell_worker[cell] = worker
        cell_best_rank[cell] = min(ordered)
        cell_support_rank_vector[cell] = sorted(ordered)
    depth_violations = sum(
        cell_epoch[cell] > cell_best_rank[cell] for cell in range(CELLS)
    )
    work_violations = sum(
        min(CELLS, WORKERS * cell_epoch[cell]) > WORKERS * cell_best_rank[cell]
        for cell in range(CELLS)
    )
    if depth_violations or work_violations:
        raise RuntimeError("A428 global wavefront theorem failed")
    return {
        "source_role_order": list(frozen_roles),
        "global_order": global_order,
        "global_order_uint16be_sha256": uint16be_sha256(global_order),
        "worker_tasks": worker_tasks,
        "worker_cell_orders": worker_orders,
        "worker_task_counts": {role: len(worker_tasks[role]) for role in frozen_roles},
        "worker_task_list_sha256": {
            role: canonical_sha256(worker_tasks[role]) for role in frozen_roles
        },
        "worker_cell_order_uint16be_sha256": {
            role: uint16be_sha256(worker_orders[role]) for role in frozen_roles
        },
        "cell_epoch_one_based": cell_epoch,
        "cell_worker_role": cell_worker,
        "cell_best_source_rank_one_based": cell_best_rank,
        "cell_support_rank_vector": cell_support_rank_vector,
        "proof": {
            "cells_checked": CELLS,
            "complete_cover_cells": len(global_order),
            "duplicate_cells": len(global_order) - len(set(global_order)),
            "uncovered_cells": CELLS - len(set(global_order)),
            "workers": WORKERS,
            "worker_tasks_each": EPOCHS,
            "makespan_epochs": max(cell_epoch),
            "theoretical_minimum_epochs": math.ceil(CELLS / WORKERS),
            "makespan_optimal": max(cell_epoch) == math.ceil(CELLS / WORKERS),
            "depth_bound": "D_A428(c) <= min_i R_i(c)",
            "depth_bound_violations": depth_violations,
            "total_work_bound": "W_A428(c) <= 8*min_i R_i(c)",
            "total_work_bound_violations": work_violations,
            "maximum_depth_to_best_source_ratio": max(
                cell_epoch[cell] / cell_best_rank[cell] for cell in range(CELLS)
            ),
        },
    }


def owner_schedule(source_orders: Mapping[str, Sequence[int]]) -> dict[str, Any]:
    roles = tuple(source_orders)
    owners = A416.A414.minimum_rank_owner_lanes(source_orders, roles)
    return A416.A414.balanced_static_worker_schedule(owners["owner_lane_orders"], roles)


def geometric_mean(values: Sequence[int]) -> float:
    return math.exp(statistics.fmean(math.log(int(value)) for value in values))


def panel_summary(rows: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    a416 = [int(row["A416_owner_epoch"]) for row in rows]
    a427 = [int(row["A427_owner_epoch"]) for row in rows]
    a428 = [int(row["A428_global_epoch"]) for row in rows]
    gm416, gm427, gm428 = map(geometric_mean, (a416, a427, a428))
    return {
        "targets": len(rows),
        "A416_owner_epoch_geometric_mean": gm416,
        "A427_owner_epoch_geometric_mean": gm427,
        "A428_global_epoch_geometric_mean": gm428,
        "A416_to_A428_factor": gm416 / gm428,
        "A416_to_A428_gain_bits": math.log2(gm416 / gm428),
        "A427_to_A428_factor": gm427 / gm428,
        "A427_to_A428_gain_bits": math.log2(gm427 / gm428),
        "A428_vs_A427_better_equal_worse": [
            sum(new < old for old, new in zip(a427, a428, strict=True)),
            sum(new == old for old, new in zip(a427, a428, strict=True)),
            sum(new > old for old, new in zip(a427, a428, strict=True)),
        ],
        "A428_vs_A416_better_equal_worse": [
            sum(new < old for old, new in zip(a416, a428, strict=True)),
            sum(new == old for old, new in zip(a416, a428, strict=True)),
            sum(new > old for old, new in zip(a416, a428, strict=True)),
        ],
        "maximum_A427_backlog_removed_epochs": max(old - new for old, new in zip(a427, a428, strict=True)),
        "rows": [dict(row) for row in rows],
    }


def freeze_implementation() -> dict[str, Any]:
    if any(path.exists() for path in (IMPLEMENTATION, RESULT, CAUSAL, REPORT)):
        raise FileExistsError("A428 implementation or result already exists")
    design = load_design()
    if not TEST.exists() or not REPRO.exists():
        raise FileNotFoundError("A428 test and reproducer must precede freeze")
    payload: dict[str, Any] = {
        "schema": "chacha20-round20-w50-global-best-rank-wavefront-a428-implementation-v1",
        "attempt_id": ATTEMPT_ID,
        "commitment_state": "complete_global_wavefront_frozen_before_any_A428_candidate_schedule_measurement_or_production_execution",
        "design_sha256": DESIGN_SHA256,
        "mechanism": design["mechanism"],
        "evaluation_contract": design["evaluation_contract"],
        "A428_candidate_schedule_measurements_available_at_freeze": 0,
        "A428_production_candidate_assignments_available_at_freeze": 0,
        "anchors": {
            "design": anchor(DESIGN, DESIGN_SHA256),
            "A427_runner": anchor(A427_RUNNER, A427_RUNNER_SHA256),
            "A427_result": anchor(A427_RESULT, A427_RESULT_SHA256),
            "A427_causal": anchor(A427_CAUSAL, A427_CAUSAL_SHA256),
            "A427_model": anchor(A427_MODEL, A427_MODEL_SHA256),
            "A416_result": anchor(A416_RESULT, A416_RESULT_SHA256),
            "A412_protocol": anchor(A412_PROTOCOL, A412_PROTOCOL_SHA256),
            "runner": anchor(Path(__file__)),
            "test": anchor(TEST),
            "reproducer": anchor(REPRO),
        },
    }
    payload["implementation_commitment_sha256"] = canonical_sha256(payload)
    atomic_json(IMPLEMENTATION, payload)
    return payload


def load_implementation(expected_sha256: str | None = None) -> dict[str, Any]:
    if expected_sha256 is not None and file_sha256(IMPLEMENTATION) != expected_sha256:
        raise RuntimeError("A428 implementation hash differs")
    value = json.loads(IMPLEMENTATION.read_bytes())
    if (
        value.get("schema")
        != "chacha20-round20-w50-global-best-rank-wavefront-a428-implementation-v1"
        or value.get("attempt_id") != ATTEMPT_ID
        or value.get("design_sha256") != DESIGN_SHA256
        or value.get("A428_candidate_schedule_measurements_available_at_freeze") != 0
        or value.get("A428_production_candidate_assignments_available_at_freeze") != 0
    ):
        raise RuntimeError("A428 implementation semantics differ")
    for row in value["anchors"].values():
        anchor(path_from_ref(row["path"]), row["sha256"])
    unsigned = {key: item for key, item in value.items() if key != "implementation_commitment_sha256"}
    if value["implementation_commitment_sha256"] != canonical_sha256(unsigned):
        raise RuntimeError("A428 implementation commitment differs")
    return value


def evaluate_target(target: int, labels: Mapping[int, Mapping[str, Any]], model: Mapping[str, Any], library: Mapping[str, Any], protocol: Mapping[str, Any]) -> dict[str, Any]:
    A412.load_fresh_complete(target, protocol)
    rank_matrix, field = A412.fresh_rank_matrix(target)
    cell = int(labels[target]["true_direct12_cell"])
    base_orders = A416.portfolio_orders(rank_matrix, model)
    source_orders, polarity = A427.portfolio_orders(rank_matrix, model, library)
    a416_work = owner_schedule(base_orders)
    a427_work = owner_schedule(source_orders)
    a428_work = global_best_rank_wavefront(source_orders, tuple(source_orders))
    return {
        "target": target,
        "true_cell": cell,
        "A416_owner_epoch": int(a416_work["cell_epoch_one_based"][cell]),
        "A427_owner_epoch": int(a427_work["cell_epoch_one_based"][cell]),
        "A428_global_epoch": int(a428_work["cell_epoch_one_based"][cell]),
        "A427_best_source_rank": int(a428_work["cell_best_source_rank_one_based"][cell]),
        "A428_global_position_one_based": int(a428_work["global_order"].index(cell) + 1),
        "field_commitment_sha256": canonical_sha256(field),
        "polarity_decision": int(polarity["majority_decision"]),
    }


def build_causal(payload: Mapping[str, Any]) -> dict[str, Any]:
    sys.path.insert(0, str(DOTCAUSAL_SRC))
    from dotcausal.io import CausalReader, CausalWriter

    reader_gain = "A427:external_reader_rank_gain"
    backlog = "A428:owner_lane_backlog_localized"
    global_wave = "A428:global_best_rank_eight_worker_wavefront"
    production = "A429:production_recovery_executor"
    writer = CausalWriter(api_id="a428w50")
    writer._rules = []
    writer.add_rule(name="rank_gain_to_scheduler_diagnostic", description="Exact epoch reconstruction separates Reader gain from owner-lane backlog.", pattern=["A427_external_reader_rank_gain"], conclusion="A428_owner_lane_backlog_localized", confidence_modifier=1.0)
    writer.add_rule(name="backlog_to_global_wavefront", description="Global best-rank ordering removes lane-local waiting while retaining complete eight-worker coverage.", pattern=["A428_owner_lane_backlog_localized"], conclusion="A428_global_best_rank_eight_worker_wavefront", confidence_modifier=1.0)
    writer.add_rule(name="qualified_wavefront_to_recovery", description="A qualified zero-refit production schedule is ready for the existing full-round W50 challenge.", pattern=["A428_global_best_rank_eight_worker_wavefront"], conclusion="A429_production_recovery_executor", confidence_modifier=1.0)
    writer.add_triplet(trigger=reader_gain, mechanism="exact_static_epoch_readback", outcome=backlog, confidence=1.0, source=payload["measurement_sha256"], quantification=json.dumps(payload["diagnostic_external_panel"], sort_keys=True), evidence="32 complete known-key fields; no production label", domain="ChaCha20 W50 scheduler diagnosis", quality_score=1.0)
    writer.add_triplet(trigger=backlog, mechanism="global_minimum_source_rank_with_full_support_tie_break", outcome=global_wave, confidence=1.0, source=payload["production_schedule_commitment_sha256"], quantification=json.dumps(payload["production_schedule_proof"], sort_keys=True), evidence="exact 4,096-cell cover in 512 epochs", domain="complete full-round W50 scheduling", quality_score=1.0)
    writer.add_triplet(trigger=reader_gain, mechanism="materialized_rank_to_epoch_to_production_chain", outcome=production, confidence=1.0, source="materialized:A428_global_wavefront_chain", quantification="exact retained closure", evidence=payload["evidence_stage"], domain="AI-native retained inference", quality_score=1.0, is_inferred=True)
    writer.add_cluster(name="A428 Reader-rank to worker-epoch repair", entities=[reader_gain, backlog, global_wave, production])
    writer.add_gap(subject=production, predicate="next_required_object", expected_object_type="complete_group_shared_stop_execution_of_A428_schedule", confidence=1.0, suggested_queries=["Execute the exact A428 production worker lists on the existing sealed W50 challenge with matched control and dual confirmation."])
    CAUSAL.parent.mkdir(parents=True, exist_ok=True)
    temporary = CAUSAL.with_name(f".{CAUSAL.name}.tmp")
    temporary.unlink(missing_ok=True)
    stats = writer.save(str(temporary))
    os.replace(temporary, CAUSAL)
    reader = CausalReader(str(CAUSAL), verify_integrity=True)
    explicit = reader.get_all_triplets(include_inferred=False)
    all_rows = reader.get_all_triplets(include_inferred=True)
    inferred = [row for row in reader._triplets if row.get("is_inferred", False)]
    if (
        len(explicit) != 2
        or len(all_rows) != 3
        or len(inferred) != 1
        or reader.api_id != "a428w50"
        or len(reader._rules) != 3
        or len(reader._clusters) != 1
        or len(reader._gaps) != 1
    ):
        raise RuntimeError("A428 authentic Causal reopen gate failed")
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
            "diagnostic": explicit[0],
            "scheduler": explicit[1],
            "terminal_chain": all_rows[-1],
            "next_gap": reader._gaps[0],
        },
    }


def measure(*, expected_implementation_sha256: str) -> dict[str, Any]:
    if any(path.exists() for path in (RESULT, CAUSAL, REPORT)):
        raise FileExistsError("A428 result already exists")
    implementation = load_implementation(expected_implementation_sha256)
    model = A416.load_model(A427.A416_MODEL_SHA256)
    library = A427.A419.A417.load_library(A427.A419.A417_LIBRARY_SHA256)
    protocol = A412.load_protocol(A427.A412_PROTOCOL_SHA256)
    selection_labels = A412.load_label(A412.SELECTION_LABELS, "chacha20-round20-w50-fresh-hybrid-reader-a412-selection-labels-v1", A412.SELECTION_TARGETS)
    holdout_labels = A412.load_label(A412.HOLDOUT_LABELS, "chacha20-round20-w50-fresh-hybrid-reader-a412-holdout-labels-v1", A412.HOLDOUT_TARGETS)
    selection_rows = [evaluate_target(target, selection_labels, model, library, protocol) for target in A412.SELECTION_TARGETS]
    holdout_rows = [evaluate_target(target, holdout_labels, model, library, protocol) for target in A412.HOLDOUT_TARGETS]
    selection = panel_summary(selection_rows)
    external = panel_summary(holdout_rows)
    qualified = external["A427_to_A428_factor"] > 1.0 and external["A416_to_A428_factor"] > 1.0
    with A412.a401_paths(A412.ORIGINAL_A401_ARTIFACTS, A412.ORIGINAL_A401_MEASUREMENTS):
        production_ranks, _views, production_metadata = A416.A402.production_rank_matrix()
    production_orders, production_polarity = A427.portfolio_orders(production_ranks, model, library)
    production = global_best_rank_wavefront(production_orders, tuple(production_orders))
    payload: dict[str, Any] = {
        "schema": "chacha20-round20-w50-global-best-rank-wavefront-a428-result-v1",
        "attempt_id": ATTEMPT_ID,
        "evidence_stage": "EXACT_GLOBAL_WAVEFRONT_QUALIFIED" if qualified else "EXACT_GLOBAL_WAVEFRONT_BOUNDARY",
        "design_sha256": DESIGN_SHA256,
        "implementation_sha256": expected_implementation_sha256,
        "implementation_commitment_sha256": implementation["implementation_commitment_sha256"],
        "selection_panel": selection,
        "diagnostic_external_panel": external,
        "qualified": qualified,
        "production_execution_enabled": qualified,
        "source_role_order": list(production_orders),
        "production_global_order": production["global_order"],
        "production_global_order_uint16be_sha256": production["global_order_uint16be_sha256"],
        "production_worker_tasks": production["worker_tasks"],
        "production_worker_cell_orders": production["worker_cell_orders"],
        "production_worker_task_counts": production["worker_task_counts"],
        "production_worker_task_list_sha256": production["worker_task_list_sha256"],
        "production_worker_cell_order_uint16be_sha256": production["worker_cell_order_uint16be_sha256"],
        "production_cell_epoch_one_based": production["cell_epoch_one_based"],
        "production_cell_worker_role": production["cell_worker_role"],
        "production_cell_best_source_rank_one_based": production["cell_best_source_rank_one_based"],
        "production_schedule_proof": production["proof"],
        "production_schedule_commitment_sha256": canonical_sha256({"tasks": production["worker_task_list_sha256"], "epochs": production["cell_epoch_one_based"], "order": production["global_order_uint16be_sha256"]}),
        "production_view_metadata": production_metadata,
        "production_polarity_metadata": production_polarity,
        "production_target_labels_used": 0,
        "production_candidate_assignments_executed": 0,
        "live_recovery_progress_or_filter_outcomes_consumed": False,
        "anchors": {
            "design": anchor(DESIGN, DESIGN_SHA256),
            "implementation": anchor(IMPLEMENTATION, expected_implementation_sha256),
            "A427_result": anchor(A427_RESULT, A427_RESULT_SHA256),
            "A427_causal": anchor(A427_CAUSAL, A427_CAUSAL_SHA256),
            "A427_model": anchor(A427_MODEL, A427_MODEL_SHA256),
            "A416_result": anchor(A416_RESULT, A416_RESULT_SHA256),
            "A412_protocol": anchor(A412_PROTOCOL, A412_PROTOCOL_SHA256),
            "runner": anchor(Path(__file__)),
        },
    }
    payload["measurement_sha256"] = canonical_sha256({"selection": selection, "external": external})
    payload["causal"] = build_causal(payload)
    atomic_json(RESULT, payload)
    REPORT.write_text(
        "# A428 — global best-rank worker wavefront\n\n"
        f"- Qualified: **{qualified}**\n"
        f"- External A427 owner -> A428 global factor: **{external['A427_to_A428_factor']:.9f}x** ({external['A427_to_A428_gain_bits']:+.9f} bit)\n"
        f"- External A416 owner -> A428 global factor: **{external['A416_to_A428_factor']:.9f}x** ({external['A416_to_A428_gain_bits']:+.9f} bit)\n"
        f"- A428 vs A427 better/equal/worse: **{external['A428_vs_A427_better_equal_worse']}**\n"
        f"- Production schedule: **{production['proof']['complete_cover_cells']} cells / {production['proof']['makespan_epochs']} epochs / zero duplicates**\n"
        f"- Production schedule commitment: `{payload['production_schedule_commitment_sha256']}`\n"
        f"- Native Causal: `{payload['causal']['sha256']}`\n",
        encoding="utf-8",
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
        load_implementation(payload["implementation_sha256"])
    if RESULT.exists():
        value = json.loads(RESULT.read_bytes())
        payload.update({
            "result_sha256": file_sha256(RESULT),
            "qualified": value["qualified"],
            "external_A427_to_A428_factor": value["diagnostic_external_panel"]["A427_to_A428_factor"],
            "production_schedule_commitment_sha256": value["production_schedule_commitment_sha256"],
            "causal_sha256": file_sha256(CAUSAL),
        })
    return payload


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--freeze-implementation", action="store_true")
    parser.add_argument("--measure", action="store_true")
    parser.add_argument("--expected-implementation-sha256")
    args = parser.parse_args()
    if args.freeze_implementation:
        print(json.dumps(freeze_implementation(), indent=2, sort_keys=True))
    elif args.measure:
        if not args.expected_implementation_sha256:
            parser.error("--measure requires --expected-implementation-sha256")
        print(json.dumps(measure(expected_implementation_sha256=args.expected_implementation_sha256), indent=2, sort_keys=True))
    else:
        print(json.dumps(analyze(), indent=2, sort_keys=True))


if __name__ == "__main__":
    main()

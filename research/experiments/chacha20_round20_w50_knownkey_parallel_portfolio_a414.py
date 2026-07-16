#!/usr/bin/env python3
"""A414: eight learned W50 Readers as one externally tested parallel scheduler."""

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

DESIGN = CONFIGS / "chacha20_round20_w50_knownkey_parallel_portfolio_a414_design_v1.json"
IMPLEMENTATION = (
    CONFIGS / "chacha20_round20_w50_knownkey_parallel_portfolio_a414_implementation_v1.json"
)
PORTFOLIO = CONFIGS / "chacha20_round20_w50_knownkey_parallel_portfolio_a414_model_v1.json"
RESULT = RESULTS / "chacha20_round20_w50_knownkey_parallel_portfolio_a414_v1.json"
CAUSAL = RESULT.with_suffix(".causal")
REPORT = RESULT.with_suffix(".md")
TEST = ROOT / "tests/test_chacha20_round20_w50_knownkey_parallel_portfolio_a414.py"
REPRO = ROOT / "scripts/reproduce_chacha20_round20_w50_knownkey_parallel_portfolio_a414.sh"

A413_RUNNER = RESEARCH / "experiments/chacha20_round20_w50_knownkey_kernel_density_reader_a413.py"
A413_IMPLEMENTATION = (
    CONFIGS / "chacha20_round20_w50_knownkey_kernel_density_reader_a413_implementation_v1.json"
)
A413_MODEL = CONFIGS / "chacha20_round20_w50_knownkey_kernel_density_reader_a413_model_v1.json"
A412_RUNNER = RESEARCH / "experiments/chacha20_round20_w50_fresh_hybrid_reader_a412.py"
A412_IMPLEMENTATION = (
    CONFIGS / "chacha20_round20_w50_fresh_hybrid_reader_a412_implementation_v1.json"
)
A412_PROTOCOL = CONFIGS / "chacha20_round20_w50_fresh_hybrid_reader_a412_public_corpus_v1.json"
A388_ORDER = RESULTS / "chacha20_round20_w50_public_output_direct12_factor3_a388_order_v1.json"

ATTEMPT_ID = "A414"
DESIGN_SHA256 = "20736bdbcf84f47a288d56dd040f03f0c8002b3592d13310cf61e57cdc3120b5"
A413_RUNNER_SHA256 = "e8f939d84cf53364bbbb4c729c1e9fa7fd5dce2742cd24fcc6e3e6a559c804d4"
A413_IMPLEMENTATION_SHA256 = "715aa6660bff6f3c6b3b3336cc3b755581c528898ca75defb6cbe8fea539e693"
A413_MODEL_SHA256 = "71141bdac6a3f4bea95980e21777eb00a774ecde88a29028c441453dc62b7cf8"
A412_RUNNER_SHA256 = "cc8813f29f29aed8f28b682c959d7655437faa7c5e9c713cbe9e2183e8641b96"
A412_IMPLEMENTATION_SHA256 = "f08665ec5f0b79bf96f33617d10966e59895e6adfb284c5b6c70e5fc47527067"
A412_PROTOCOL_SHA256 = "f7859b381d5cf6a5f1a765b4abb44192d3bd73539c681a9a40d8c0a48dd365a2"
A388_ORDER_SHA256 = "3c56ce8521b1ced20e1e3a90999810c2e563c4de941701c86274f0828b5d01b8"

SELECTED_INDICES = (123, 20, 152, 100, 91, 144, 49, 35)
EXPECTED_TRAIN_RANKS = (397, 66, 471, 3597, 122, 1325, 935, 4012, 10, 1291, 2440, 1932, 3, 402, 131, 3055)
EXPECTED_TRAIN_GM = 415.5514623998885
FRESH_TARGETS = tuple(range(32))
CELLS = 4096
WORKERS = 8
OPTIMAL_EPOCHS = 512
SOURCE_ROLES = tuple(f"A413_candidate_{index:03d}" for index in SELECTED_INDICES)
DOTCAUSAL_SRC = Path("/Users/bhkmie/Documents/Forschung/O1/vendor/fabel/dotcausal_package/src")


def load_module(path: Path, name: str) -> Any:
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot import A414 dependency {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


A413 = load_module(A413_RUNNER, "a414_a413")
A412 = A413.A412
A410 = A413.A410
A401 = A413.A401
A402 = A413.A402

file_sha256 = A413.file_sha256
canonical_sha256 = A413.canonical_sha256
atomic_json = A413.atomic_json
atomic_bytes = A413.atomic_bytes
relative = A413.relative
anchor = A413.anchor
sha256 = A413.sha256


def metric_panel(ranks: Sequence[int]) -> dict[str, Any]:
    values = [int(value) for value in ranks]
    mean_log = statistics.fmean(math.log2(value) for value in values)
    return {
        "ranks": values,
        "geometric_mean_rank": 2.0**mean_log,
        "mean_log2_rank": mean_log,
        "bit_gain_vs_complete_4096_cover": 12.0 - mean_log,
        "median_rank": statistics.median(values),
        "top_quartile_targets": sum(value <= 1024 for value in values),
        "worst_rank": max(values),
    }


def exact_order(values: Sequence[int], *, size: int = CELLS) -> list[int]:
    order = [int(value) for value in values]
    if len(order) != size or set(order) != set(range(size)):
        raise ValueError("A414 order is not one exact permutation")
    return order


def uint16be_sha256(values: Sequence[int]) -> str:
    raw = b"".join(int(value).to_bytes(2, "big") for value in values)
    return sha256(raw)


def load_leaveoneout_rank_matrix() -> np.ndarray:
    rows = []
    for target in A413.TARGETS:
        path = A413.training_rank_path(target, None)
        value = json.loads(path.read_bytes())
        if (
            value.get("schema")
            != "chacha20-round20-w50-knownkey-kernel-density-reader-a413-training-ranks-v1"
            or value.get("validation_target") != target
            or value.get("excluded_outer_target") is not None
            or len(value.get("candidate_true_ranks", [])) != A413.CANDIDATE_COUNT
            or value.get("A412_labels_or_reader_scores_consumed") is not False
        ):
            raise RuntimeError("A414 A413 leave-one-out source differs")
        rows.append([int(rank) for rank in value["candidate_true_ranks"]])
    matrix = np.asarray(rows, dtype=np.int64)
    if matrix.shape != (16, A413.CANDIDATE_COUNT):
        raise RuntimeError("A414 leave-one-out matrix shape differs")
    return matrix


def derive_portfolio() -> dict[str, Any]:
    matrix = load_leaveoneout_rank_matrix()
    selected: list[int] = []
    steps = []
    current: np.ndarray | None = None
    for step in range(WORKERS):
        choices = []
        for candidate in range(A413.CANDIDATE_COUNT):
            if candidate in selected:
                continue
            panel = matrix[:, candidate] if current is None else np.minimum(current, matrix[:, candidate])
            mean_log = float(np.log2(panel.astype(np.float64)).mean())
            choices.append((mean_log, int(panel.max()), candidate, panel))
        mean_log, worst, winner, panel = min(choices, key=lambda row: row[:3])
        selected.append(winner)
        current = panel.copy()
        steps.append(
            {
                "step": step,
                "selected_candidate_index": winner,
                "geometric_mean_parallel_rank": 2.0**mean_log,
                "worst_parallel_rank": worst,
                "pointwise_minimum_ranks": panel.tolist(),
            }
        )
    if tuple(selected) != SELECTED_INDICES or tuple(int(value) for value in current) != EXPECTED_TRAIN_RANKS:
        raise RuntimeError("A414 frozen greedy portfolio differs")
    if not math.isclose(2.0 ** float(np.log2(current.astype(np.float64)).mean()), EXPECTED_TRAIN_GM):
        raise RuntimeError("A414 frozen training geometric mean differs")
    candidates = A413.candidate_rows()
    return {
        "selected_candidate_indices": selected,
        "selected_candidates": [candidates[index] for index in selected],
        "steps": steps,
        "pointwise_minimum_panel": metric_panel(current.tolist()),
        "leaveoneout_rank_matrix_int32le_sha256": sha256(matrix.astype("<i4").tobytes()),
    }


def load_design() -> dict[str, Any]:
    if file_sha256(DESIGN) != DESIGN_SHA256:
        raise RuntimeError("A414 design hash differs")
    value = json.loads(DESIGN.read_bytes())
    selection = value.get("training_selection_contract", {})
    boundary = value.get("information_boundary", {})
    production = value.get("production_schedule_contract", {})
    if (
        value.get("schema")
        != "chacha20-round20-w50-knownkey-parallel-portfolio-a414-design-v1"
        or value.get("attempt_id") != ATTEMPT_ID
        or tuple(selection.get("selected_candidate_indices_in_order", [])) != SELECTED_INDICES
        or selection.get("portfolio_size") != WORKERS
        or production.get("target_makespan_epochs") != OPTIMAL_EPOCHS
        or boundary.get("A412_complete_or_partial_measurements_consumed") is not False
        or boundary.get("A412_selection_or_holdout_label_ledger_opened") is not False
        or boundary.get("A412_reader_score_or_true_rank_consumed") is not False
    ):
        raise RuntimeError("A414 frozen design semantics differ")
    for key, path in value["source_anchors"].items():
        if key.endswith("_path"):
            stem = key.removesuffix("_path")
            anchor(ROOT / path, value["source_anchors"][f"{stem}_sha256"])
    return value


def freeze_implementation() -> dict[str, Any]:
    if any(path.exists() for path in (IMPLEMENTATION, PORTFOLIO, RESULT, CAUSAL, REPORT)):
        raise FileExistsError("A414 implementation or generated artifact already exists")
    load_design()
    derived = derive_portfolio()
    if not TEST.exists() or not REPRO.exists():
        raise FileNotFoundError("A414 test and reproducer must precede freeze")
    payload: dict[str, Any] = {
        "schema": "chacha20-round20-w50-knownkey-parallel-portfolio-a414-implementation-v1",
        "attempt_id": ATTEMPT_ID,
        "commitment_state": "frozen_before_A414_model_fit_or_any_A412_label_or_reader_score",
        "design_sha256": DESIGN_SHA256,
        "portfolio_size": WORKERS,
        "selected_candidate_indices": list(SELECTED_INDICES),
        "selected_portfolio_commitment_sha256": canonical_sha256(derived),
        "A412_labels_or_reader_scores_consumed": False,
        "anchors": {
            "design": anchor(DESIGN, DESIGN_SHA256),
            "A413_runner": anchor(A413_RUNNER, A413_RUNNER_SHA256),
            "A413_implementation": anchor(A413_IMPLEMENTATION, A413_IMPLEMENTATION_SHA256),
            "A413_model": anchor(A413_MODEL, A413_MODEL_SHA256),
            "A412_runner": anchor(A412_RUNNER, A412_RUNNER_SHA256),
            "A412_implementation": anchor(A412_IMPLEMENTATION, A412_IMPLEMENTATION_SHA256),
            "A412_protocol": anchor(A412_PROTOCOL, A412_PROTOCOL_SHA256),
            "A388_order": anchor(A388_ORDER, A388_ORDER_SHA256),
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
        raise RuntimeError("A414 implementation hash differs")
    value = json.loads(IMPLEMENTATION.read_bytes())
    if (
        value.get("schema")
        != "chacha20-round20-w50-knownkey-parallel-portfolio-a414-implementation-v1"
        or value.get("attempt_id") != ATTEMPT_ID
        or tuple(value.get("selected_candidate_indices", [])) != SELECTED_INDICES
        or value.get("selected_portfolio_commitment_sha256") != canonical_sha256(derive_portfolio())
        or value.get("A412_labels_or_reader_scores_consumed") is not False
    ):
        raise RuntimeError("A414 implementation semantics differ")
    for row in value["anchors"].values():
        anchor(ROOT / row["path"], row["sha256"])
    unsigned = {
        key: item for key, item in value.items() if key != "implementation_commitment_sha256"
    }
    if value.get("implementation_commitment_sha256") != canonical_sha256(unsigned):
        raise RuntimeError("A414 implementation commitment differs")
    return value


def freeze_portfolio(*, expected_implementation_sha256: str) -> dict[str, Any]:
    if PORTFOLIO.exists() or RESULT.exists() or CAUSAL.exists() or REPORT.exists():
        raise FileExistsError("A414 portfolio or result already exists")
    implementation = load_implementation(expected_implementation_sha256)
    derived = derive_portfolio()
    bundle = A413.training_bundle()
    candidates = A413.candidate_rows()
    representations = bundle["representations"]
    true_cells = bundle["true_cells"]
    models = []
    for position, candidate_index in enumerate(SELECTED_INDICES):
        candidate = candidates[candidate_index]
        prototypes = np.stack(
            [
                representations[index][candidate["representation"]][int(true_cells[index])]
                for index in A413.TARGETS
            ]
        )
        frozen = A413.fit_frozen_model(prototypes, candidate)
        models.append(
            {
                "portfolio_position": position,
                "source_role": SOURCE_ROLES[position],
                "candidate_index": candidate_index,
                "frozen_model": frozen,
            }
        )
    payload: dict[str, Any] = {
        "schema": "chacha20-round20-w50-knownkey-parallel-portfolio-a414-model-v1",
        "attempt_id": ATTEMPT_ID,
        "model_state": "eight_models_fixed_from_A401_before_any_A412_label_or_reader_score",
        "design_sha256": DESIGN_SHA256,
        "implementation_sha256": expected_implementation_sha256,
        "implementation_commitment_sha256": implementation[
            "implementation_commitment_sha256"
        ],
        "selected_portfolio_commitment_sha256": implementation[
            "selected_portfolio_commitment_sha256"
        ],
        "training_selection": derived,
        "models": models,
        "knownkey_field_commitments": bundle["field_commitments"],
        "knownkey_prototype_commitments": bundle["prototype_commitments"],
        "A412_target_labels_used": 0,
        "A412_reader_scores_used": 0,
        "live_recovery_progress_filter_outcomes_or_results_consumed": False,
        "anchors": {
            "design": anchor(DESIGN, DESIGN_SHA256),
            "implementation": anchor(IMPLEMENTATION, expected_implementation_sha256),
            "A413_model": anchor(A413_MODEL, A413_MODEL_SHA256),
            "A412_protocol": anchor(A412_PROTOCOL, A412_PROTOCOL_SHA256),
            "runner": anchor(Path(__file__)),
        },
    }
    payload["portfolio_model_commitment_sha256"] = canonical_sha256(payload)
    atomic_json(PORTFOLIO, payload)
    return payload


def load_portfolio(expected_sha256: str | None = None) -> dict[str, Any]:
    if expected_sha256 is not None and file_sha256(PORTFOLIO) != expected_sha256:
        raise RuntimeError("A414 portfolio hash differs")
    value = json.loads(PORTFOLIO.read_bytes())
    if (
        value.get("schema") != "chacha20-round20-w50-knownkey-parallel-portfolio-a414-model-v1"
        or value.get("attempt_id") != ATTEMPT_ID
        or value.get("model_state")
        != "eight_models_fixed_from_A401_before_any_A412_label_or_reader_score"
        or [row.get("candidate_index") for row in value.get("models", [])]
        != list(SELECTED_INDICES)
        or [row.get("source_role") for row in value.get("models", [])]
        != list(SOURCE_ROLES)
        or value.get("selected_portfolio_commitment_sha256")
        != canonical_sha256(derive_portfolio())
        or value.get("A412_target_labels_used") != 0
        or value.get("A412_reader_scores_used") != 0
    ):
        raise RuntimeError("A414 portfolio semantics differ")
    load_implementation(value["implementation_sha256"])
    for row in value["anchors"].values():
        anchor(ROOT / row["path"], row["sha256"])
    unsigned = {
        key: item for key, item in value.items() if key != "portfolio_model_commitment_sha256"
    }
    if value.get("portfolio_model_commitment_sha256") != canonical_sha256(unsigned):
        raise RuntimeError("A414 portfolio commitment differs")
    return value


def portfolio_orders(rank_matrix: np.ndarray, portfolio: Mapping[str, Any]) -> dict[str, list[int]]:
    representations = A410.representation_matrices(rank_matrix)
    orders = {}
    for row in portfolio["models"]:
        frozen = row["frozen_model"]
        representation = str(frozen["candidate"]["representation"])
        scores = A413.score_frozen_model(representations[representation], frozen)
        orders[str(row["source_role"])] = A413.exact_score_order(scores)
    if tuple(orders) != SOURCE_ROLES:
        raise RuntimeError("A414 portfolio order roles differ")
    return orders


def minimum_rank_owner_lanes(
    source_orders: Mapping[str, Sequence[int]], role_order: Sequence[str]
) -> dict[str, Any]:
    roles = tuple(str(role) for role in role_order)
    if len(roles) != WORKERS or len(set(roles)) != WORKERS or set(roles) != set(source_orders):
        raise ValueError("A414 source role contract differs")
    orders = {role: exact_order(source_orders[role]) for role in roles}
    ranks = {role: [0] * CELLS for role in roles}
    for role in roles:
        for rank, cell in enumerate(orders[role], 1):
            ranks[role][cell] = rank
    owner = [
        min(roles, key=lambda role: (ranks[role][cell], roles.index(role)))
        for cell in range(CELLS)
    ]
    lanes = {
        role: sorted(
            (cell for cell in range(CELLS) if owner[cell] == role),
            key=lambda cell: ranks[role][cell],
        )
        for role in roles
    }
    owner_depth = [0] * CELLS
    for role in roles:
        for depth, cell in enumerate(lanes[role], 1):
            owner_depth[cell] = depth
    if sum(map(len, lanes.values())) != CELLS or any(depth == 0 for depth in owner_depth):
        raise RuntimeError("A414 owner lanes do not cover the domain")
    return {
        "role_order": list(roles),
        "source_orders": orders,
        "source_ranks_one_based": ranks,
        "owner_role": owner,
        "owner_lane_orders": lanes,
        "owner_lane_sizes": {role: len(lanes[role]) for role in roles},
        "owner_lane_depth_one_based": owner_depth,
        "source_order_uint16be_sha256": {
            role: uint16be_sha256(orders[role]) for role in roles
        },
        "owner_lane_order_uint16be_sha256": {
            role: uint16be_sha256(lanes[role]) for role in roles
        },
    }


def balanced_static_worker_schedule(
    owner_lanes: Mapping[str, Sequence[int]], role_order: Sequence[str]
) -> dict[str, Any]:
    roles = tuple(str(role) for role in role_order)
    if len(roles) != WORKERS or set(roles) != set(owner_lanes):
        raise ValueError("A414 worker/source role contract differs")
    lanes = {role: [int(cell) for cell in owner_lanes[role]] for role in roles}
    flattened = [cell for role in roles for cell in lanes[role]]
    if len(flattened) != CELLS or set(flattened) != set(range(CELLS)):
        raise ValueError("A414 owner lanes are not one exact disjoint cover")
    role_index = {role: index for index, role in enumerate(roles)}
    pointers = {role: 0 for role in roles}
    tasks: dict[str, list[dict[str, Any]]] = {role: [] for role in roles}
    cell_epoch = [0] * CELLS
    cell_worker = [""] * CELLS
    cell_owner = [""] * CELLS
    cell_owner_position = [0] * CELLS
    epoch = 0
    claimed = 0
    while claimed < CELLS:
        epoch += 1
        for worker in roles:
            if claimed == CELLS:
                break
            if pointers[worker] < len(lanes[worker]):
                donor = worker
            else:
                remaining = {role: len(lanes[role]) - pointers[role] for role in roles}
                donor = max(roles, key=lambda role: (remaining[role], -role_index[role]))
                if remaining[donor] <= 0:
                    raise RuntimeError("A414 longest-remaining donor selection failed")
            owner_position = pointers[donor] + 1
            cell = lanes[donor][pointers[donor]]
            pointers[donor] += 1
            claimed += 1
            row = {
                "cell": cell,
                "epoch": epoch,
                "worker_role": worker,
                "worker_step_one_based": len(tasks[worker]) + 1,
                "owner_queue_role": donor,
                "owner_queue_position_one_based": owner_position,
                "stolen": donor != worker,
            }
            tasks[worker].append(row)
            cell_epoch[cell] = epoch
            cell_worker[cell] = worker
            cell_owner[cell] = donor
            cell_owner_position[cell] = owner_position
    for owner in roles:
        observed = [
            row["cell"]
            for epoch_value in range(1, epoch + 1)
            for worker in roles
            for row in tasks[worker]
            if row["epoch"] == epoch_value and row["owner_queue_role"] == owner
        ]
        if observed != lanes[owner]:
            raise RuntimeError(f"A414 {owner} owner queue order was not preserved")
    worker_orders = {worker: [row["cell"] for row in tasks[worker]] for worker in roles}
    flattened_workers = [cell for order in worker_orders.values() for cell in order]
    return {
        "worker_role_order": list(roles),
        "cells": CELLS,
        "workers": WORKERS,
        "epochs": epoch,
        "theoretical_minimum_epochs": math.ceil(CELLS / WORKERS),
        "worker_tasks": tasks,
        "worker_cell_orders": worker_orders,
        "worker_task_counts": {worker: len(tasks[worker]) for worker in roles},
        "worker_stolen_task_counts": {
            worker: sum(row["stolen"] for row in tasks[worker]) for worker in roles
        },
        "worker_cell_order_uint16be_sha256": {
            worker: uint16be_sha256(worker_orders[worker]) for worker in roles
        },
        "worker_task_list_sha256": {
            worker: canonical_sha256(tasks[worker]) for worker in roles
        },
        "cell_epoch_one_based": cell_epoch,
        "cell_worker_role": cell_worker,
        "cell_owner_queue_role": cell_owner,
        "cell_owner_queue_position_one_based": cell_owner_position,
        "complete_cover_cells": len(flattened_workers),
        "duplicate_cells": len(flattened_workers) - len(set(flattened_workers)),
        "uncovered_cells": CELLS - len(set(flattened_workers)),
    }


def prove_schedule(owners: Mapping[str, Any], work: Mapping[str, Any]) -> dict[str, Any]:
    ranks = owners["source_ranks_one_based"]
    owner_depths = [int(value) for value in owners["owner_lane_depth_one_based"]]
    epochs = [int(value) for value in work["cell_epoch_one_based"]]
    depth_ratios = []
    work_ratios = []
    for cell in range(CELLS):
        best = min(int(ranks[role][cell]) for role in SOURCE_ROLES)
        owner = owners["owner_role"][cell]
        owner_rank = int(ranks[owner][cell])
        owner_depth = owner_depths[cell]
        epoch = epochs[cell]
        total_work = min(WORKERS * epoch, CELLS)
        if owner_rank != best or epoch > owner_depth or owner_depth > best:
            raise RuntimeError("A414 minimum-rank depth theorem failed")
        if total_work > WORKERS * best:
            raise RuntimeError("A414 total-work theorem failed")
        depth_ratios.append(epoch / best)
        work_ratios.append(total_work / (WORKERS * best))
    proof = {
        "cells_checked": CELLS,
        "complete_cover_cells": work["complete_cover_cells"],
        "duplicate_cells": work["duplicate_cells"],
        "uncovered_cells": work["uncovered_cells"],
        "owner_queue_order_preservation_violations": 0,
        "depth_bound": "D_A414(c) <= D_owner(c) <= min_i R_i(c)",
        "depth_bound_violations": 0,
        "maximum_depth_to_best_source_ratio": max(depth_ratios),
        "total_work_bound": "W_A414(c) <= 8*min_i R_i(c)",
        "total_work_bound_violations": 0,
        "maximum_total_work_to_bound_ratio": max(work_ratios),
        "makespan_epochs": work["epochs"],
        "theoretical_minimum_epochs": work["theoretical_minimum_epochs"],
        "makespan_optimal": work["epochs"] == work["theoretical_minimum_epochs"],
    }
    if (
        proof["complete_cover_cells"] != CELLS
        or proof["duplicate_cells"] != 0
        or proof["uncovered_cells"] != 0
        or proof["makespan_epochs"] != OPTIMAL_EPOCHS
        or proof["makespan_optimal"] is not True
    ):
        raise RuntimeError("A414 complete schedule proof failed")
    return proof


def build_causal(payload: Mapping[str, Any]) -> dict[str, Any]:
    sys.path.insert(0, str(DOTCAUSAL_SRC))
    from dotcausal.io import CausalReader, CausalWriter

    qualified = bool(payload["external_transfer"]["qualified"])
    terminal = (
        "A414_external_portfolio_qualified_optimal_scheduler"
        if qualified
        else "A414_external_portfolio_boundary_retained_scheduler_map"
    )
    writer = CausalWriter(api_id="a414w50")
    writer._rules = []
    writer.add_rule(
        name="A413_reader_family_to_eight_member_portfolio",
        description="Greedy pointwise-minimum selection on sixteen A401 LOO panels fixes eight distinct Readers before any A412 label opens.",
        pattern=["A413_155_reader_family", "A401_sixteen_LOO_rank_panels"],
        conclusion="A414_fixed_eight_reader_portfolio",
        confidence_modifier=1.0,
    )
    writer.add_rule(
        name="fixed_portfolio_to_external_parallel_panel",
        description="Eight fixed models score all thirty-two A412 fields without model choice or refit and are compared at equal worker count with eight raw Direct12 views.",
        pattern=["A414_fixed_eight_reader_portfolio", "A412_thirtytwo_fresh_fields"],
        conclusion="A414_external_parallel_panel",
        confidence_modifier=1.0,
    )
    writer.add_rule(
        name="portfolio_orders_to_optimal_scheduler",
        description="Minimum-rank ownership plus order-preserving longest-remaining stealing maps all 4,096 production cells into eight exact 512-task workers.",
        pattern=["A414_fixed_eight_reader_portfolio", "A388_assignment_free_field"],
        conclusion=terminal,
        confidence_modifier=1.0,
    )
    writer.add_triplet(
        trigger="A413:155_fixed_candidate_geometries",
        mechanism="greedy_eight_member_pointwise_minimum_LOO_selection",
        outcome="A414:fixed_eight_reader_portfolio",
        confidence=1.0,
        source=payload["portfolio_model_sha256"],
        quantification=json.dumps(payload["training_selection"], sort_keys=True),
        evidence="all eight models freeze before any A412 label or Reader score",
        domain="known-key Reader portfolio learning",
        quality_score=1.0,
    )
    writer.add_triplet(
        trigger="A414:fixed_eight_reader_portfolio",
        mechanism="thirtytwo_key_equal_worker_external_panel_plus_minrank_ownership",
        outcome=f"A414:{terminal}",
        confidence=1.0,
        source=payload["external_measurement_sha256"],
        quantification=json.dumps(payload["external_transfer"], sort_keys=True),
        evidence="zero external model choices/refits and complete 4,096-cell scheduler proof",
        domain="full-round ChaCha20 W50 parallel recovery scheduling",
        quality_score=1.0,
    )
    writer.add_triplet(
        trigger="A413:155_fixed_candidate_geometries",
        mechanism="materialized_external_portfolio_scheduler_closure",
        outcome=f"A414:{terminal}",
        confidence=1.0,
        source="materialized:A414_portfolio_scheduler_chain",
        quantification="exact retained closure",
        evidence="design, implementation, model, external panel and scheduler commitments",
        domain="AI-native retained inference",
        quality_score=1.0,
        is_inferred=True,
    )
    writer.add_cluster(
        name="A414 learned eight-Reader W50 scheduler",
        entities=[
            "A413:155_fixed_candidate_geometries",
            "A414:fixed_eight_reader_portfolio",
            f"A414:{terminal}",
        ],
    )
    writer.add_gap(
        subject=f"A414:{terminal}",
        predicate="next_required_object",
        expected_object_type=(
            "shared_stop_complete_group_execution_of_eight_frozen_worker_lists"
            if qualified
            else "conditional_or_polyphase_reader_portfolio"
        ),
        confidence=1.0,
        suggested_queries=[
            "Execute the exact eight A414 worker lists with one shared confirmed stop."
            if qualified
            else "Freeze the next portfolio from conditional phase-coded known-key geometry."
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
        reader.api_id != "a414w50"
        or len(explicit) != 2
        or len(all_rows) != 3
        or len(inferred) != 1
        or len(reader._rules) != 3
        or len(reader._clusters) != 1
        or len(reader._gaps) != 1
    ):
        raise RuntimeError("A414 authentic Causal reopen gate failed")
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
            "portfolio": explicit[0],
            "external_scheduler": explicit[1],
            "terminal_chain": all_rows[-1],
            "next_gap": reader._gaps[0],
        },
    }


def evaluate_external(
    *, expected_implementation_sha256: str, expected_portfolio_sha256: str
) -> dict[str, Any]:
    if RESULT.exists() or CAUSAL.exists() or REPORT.exists():
        raise FileExistsError("A414 result already exists")
    implementation = load_implementation(expected_implementation_sha256)
    portfolio = load_portfolio(expected_portfolio_sha256)
    protocol = A412.load_protocol(A412_PROTOCOL_SHA256)
    for target in FRESH_TARGETS:
        A412.load_fresh_complete(target, protocol)
    selection_labels = A412.load_label(
        A412.SELECTION_LABELS,
        "chacha20-round20-w50-fresh-hybrid-reader-a412-selection-labels-v1",
        A412.SELECTION_TARGETS,
    )
    holdout_labels = A412.load_label(
        A412.HOLDOUT_LABELS,
        "chacha20-round20-w50-fresh-hybrid-reader-a412-holdout-labels-v1",
        A412.HOLDOUT_TARGETS,
    )
    labels = {**selection_labels, **holdout_labels}
    learned_depths = []
    baseline_depths = []
    field_commitments: dict[str, Any] = {}
    reader_commitments: dict[str, Any] = {}
    for target in FRESH_TARGETS:
        rank_matrix, field_commitments[str(target)] = A412.fresh_rank_matrix(target)
        cell = int(labels[target]["true_direct12_cell"])
        orders = portfolio_orders(rank_matrix, portfolio)
        learned_ranks = {
            role: int(A401.rank_vector(order)[cell]) for role, order in orders.items()
        }
        raw_ranks = [int(rank_matrix[index, cell]) for index in range(rank_matrix.shape[0])]
        learned_depths.append(min(learned_ranks.values()))
        baseline_depths.append(min(raw_ranks))
        reader_commitments[str(target)] = {
            "learned_order_uint16be_sha256": {
                role: uint16be_sha256(order) for role, order in orders.items()
            },
            "learned_true_ranks": learned_ranks,
            "baseline_raw_view_true_ranks": raw_ranks,
        }
    learned_panel = metric_panel(learned_depths)
    baseline_panel = metric_panel(baseline_depths)
    factor = baseline_panel["geometric_mean_rank"] / learned_panel["geometric_mean_rank"]
    gain = (
        learned_panel["bit_gain_vs_complete_4096_cover"]
        - baseline_panel["bit_gain_vs_complete_4096_cover"]
    )
    qualified = factor > 1.0 and gain > 0.0
    external = {
        "qualified": qualified,
        "learned_eight_reader_panel": learned_panel,
        "matched_raw_eight_view_panel": baseline_panel,
        "selection_half_learned_panel": metric_panel(learned_depths[:16]),
        "holdout_half_learned_panel": metric_panel(learned_depths[16:]),
        "geometric_parallel_rank_improvement_factor": factor,
        "additional_bit_gain": gain,
        "learned_better_targets": sum(
            left < right for left, right in zip(learned_depths, baseline_depths, strict=True)
        ),
        "learned_equal_targets": sum(
            left == right for left, right in zip(learned_depths, baseline_depths, strict=True)
        ),
        "learned_worse_targets": sum(
            left > right for left, right in zip(learned_depths, baseline_depths, strict=True)
        ),
        "equal_worker_count": WORKERS,
        "external_model_choices": 0,
        "external_model_refits": 0,
        "new_solver_stages": 0,
    }
    with A412.a401_paths(A412.ORIGINAL_A401_ARTIFACTS, A412.ORIGINAL_A401_MEASUREMENTS):
        production_ranks, baseline_view_orders, production_metadata = A402.production_rank_matrix()
    production_orders = portfolio_orders(production_ranks, portfolio)
    owners = minimum_rank_owner_lanes(production_orders, SOURCE_ROLES)
    work = balanced_static_worker_schedule(owners["owner_lane_orders"], SOURCE_ROLES)
    proof = prove_schedule(owners, work)
    baseline_roles = tuple(f"raw_view_{index}" for index in range(len(A401.VIEW_NAMES)))
    baseline_orders = {
        baseline_roles[index]: exact_order(baseline_view_orders[name])
        for index, name in enumerate(A401.VIEW_NAMES)
    }
    baseline_owners = minimum_rank_owner_lanes(baseline_orders, baseline_roles)
    baseline_work = balanced_static_worker_schedule(
        baseline_owners["owner_lane_orders"], baseline_roles
    )
    baseline_epochs = [int(value) for value in baseline_work["cell_epoch_one_based"]]
    learned_epochs = [int(value) for value in work["cell_epoch_one_based"]]
    comparison = {
        "learned_strictly_earlier_cells": sum(
            left < right for left, right in zip(learned_epochs, baseline_epochs, strict=True)
        ),
        "equal_cells": sum(
            left == right for left, right in zip(learned_epochs, baseline_epochs, strict=True)
        ),
        "learned_later_cells": sum(
            left > right for left, right in zip(learned_epochs, baseline_epochs, strict=True)
        ),
        "geometric_mean_raw_to_learned_epoch_factor": math.exp(
            statistics.fmean(
                math.log(raw / learned)
                for raw, learned in zip(baseline_epochs, learned_epochs, strict=True)
            )
        ),
        "baseline_makespan_epochs": baseline_work["epochs"],
        "learned_makespan_epochs": work["epochs"],
    }
    owner_commitment = canonical_sha256(
        {
            "owner_lane_sizes": owners["owner_lane_sizes"],
            "owner_lane_order_uint16be_sha256": owners["owner_lane_order_uint16be_sha256"],
        }
    )
    schedule_commitment = canonical_sha256(
        {
            "worker_task_counts": work["worker_task_counts"],
            "worker_stolen_task_counts": work["worker_stolen_task_counts"],
            "worker_task_list_sha256": work["worker_task_list_sha256"],
            "cell_epoch_one_based": work["cell_epoch_one_based"],
        }
    )
    payload: dict[str, Any] = {
        "schema": "chacha20-round20-w50-knownkey-parallel-portfolio-a414-result-v1",
        "attempt_id": ATTEMPT_ID,
        "evidence_stage": (
            "THIRTYTWO_KEY_EXTERNAL_PARALLEL_TRANSFER_QUALIFIED_OPTIMAL_512_EPOCH_SCHEDULER"
            if qualified
            else "THIRTYTWO_KEY_EXTERNAL_PARALLEL_BOUNDARY_WITH_COMPLETE_SCHEDULER_MAP"
        ),
        "design_sha256": DESIGN_SHA256,
        "implementation_sha256": expected_implementation_sha256,
        "implementation_commitment_sha256": implementation[
            "implementation_commitment_sha256"
        ],
        "portfolio_model_sha256": expected_portfolio_sha256,
        "portfolio_model_commitment_sha256": portfolio[
            "portfolio_model_commitment_sha256"
        ],
        "training_selection": portfolio["training_selection"],
        "external_transfer": external,
        "source_role_order": list(SOURCE_ROLES),
        "source_order_uint16be_sha256": owners["source_order_uint16be_sha256"],
        "owner_lane_orders": owners["owner_lane_orders"],
        "owner_lane_sizes": owners["owner_lane_sizes"],
        "owner_lane_order_uint16be_sha256": owners[
            "owner_lane_order_uint16be_sha256"
        ],
        "worker_tasks": work["worker_tasks"],
        "worker_cell_orders": work["worker_cell_orders"],
        "worker_task_counts": work["worker_task_counts"],
        "worker_stolen_task_counts": work["worker_stolen_task_counts"],
        "worker_cell_order_uint16be_sha256": work[
            "worker_cell_order_uint16be_sha256"
        ],
        "worker_task_list_sha256": work["worker_task_list_sha256"],
        "cell_epoch_one_based": work["cell_epoch_one_based"],
        "cell_worker_role": work["cell_worker_role"],
        "cell_owner_queue_role": work["cell_owner_queue_role"],
        "cell_owner_queue_position_one_based": work[
            "cell_owner_queue_position_one_based"
        ],
        "schedule_proof": proof,
        "matched_raw_schedule_proof": {
            "complete_cover_cells": baseline_work["complete_cover_cells"],
            "duplicate_cells": baseline_work["duplicate_cells"],
            "uncovered_cells": baseline_work["uncovered_cells"],
            "makespan_epochs": baseline_work["epochs"],
            "theoretical_minimum_epochs": baseline_work["theoretical_minimum_epochs"],
        },
        "matched_raw_schedule_comparison": comparison,
        "production_execution_enabled": qualified,
        "owner_lane_commitment_sha256": owner_commitment,
        "schedule_commitment_sha256": schedule_commitment,
        "production_view_metadata": production_metadata,
        "fresh_field_commitments": field_commitments,
        "fresh_reader_commitments": reader_commitments,
        "complete_external_targets": len(FRESH_TARGETS),
        "external_target_labels_used_for_model_selection": 0,
        "external_reader_refits": 0,
        "production_target_labels_used": 0,
        "production_reader_refits": 0,
        "production_candidate_assignments_executed": 0,
        "live_recovery_progress_filter_outcomes_or_results_consumed": False,
        "anchors": {
            "design": anchor(DESIGN, DESIGN_SHA256),
            "implementation": anchor(IMPLEMENTATION, expected_implementation_sha256),
            "portfolio": anchor(PORTFOLIO, expected_portfolio_sha256),
            "A413_model": anchor(A413_MODEL, A413_MODEL_SHA256),
            "A412_protocol": anchor(A412_PROTOCOL, A412_PROTOCOL_SHA256),
            "A388_order": anchor(A388_ORDER, A388_ORDER_SHA256),
            "runner": anchor(Path(__file__)),
        },
    }
    payload["external_measurement_sha256"] = canonical_sha256(
        {
            "external_transfer": external,
            "fresh_field_commitments": field_commitments,
            "fresh_reader_commitments": reader_commitments,
        }
    )
    payload["deployment_commitment_sha256"] = canonical_sha256(
        {
            "external_transfer": external,
            "owner_lane_commitment_sha256": owner_commitment,
            "schedule_commitment_sha256": schedule_commitment,
            "schedule_proof": proof,
        }
    )
    payload["causal"] = build_causal(payload)
    atomic_json(RESULT, payload)
    atomic_bytes(
        REPORT,
        (
            "# A414 — learned eight-Reader W50 scheduler\n\n"
            f"Evidence stage: **{payload['evidence_stage']}**\n\n"
            f"- Learned external ranks: **{learned_panel['ranks']}**\n"
            f"- Matched raw eight-view ranks: **{baseline_panel['ranks']}**\n"
            f"- External improvement factor: **{factor:.9f}**\n"
            f"- External additional bit gain: **{gain:.9f}**\n"
            f"- Owner-lane sizes: **{owners['owner_lane_sizes']}**\n"
            f"- Worker tasks: **{work['worker_task_counts']}**\n"
            "- Coverage / duplicate / depth / work violations: **0 / 0 / 0 / 0**\n"
            "- Makespan: **512 epochs, exact theoretical minimum**\n"
            "- Authentic AI-native Causal readback: **2 explicit + 1 inferred chain**\n"
        ).encode(),
    )
    return payload


def analyze() -> dict[str, Any]:
    payload: dict[str, Any] = {
        "attempt_id": ATTEMPT_ID,
        "design_sha256": DESIGN_SHA256,
        "implementation_frozen": IMPLEMENTATION.exists(),
        "portfolio_frozen": PORTFOLIO.exists(),
        "result_complete": RESULT.exists(),
    }
    if IMPLEMENTATION.exists():
        payload["implementation_sha256"] = file_sha256(IMPLEMENTATION)
    if PORTFOLIO.exists():
        portfolio = load_portfolio()
        payload["portfolio_sha256"] = file_sha256(PORTFOLIO)
        payload["selected_candidate_indices"] = [
            row["candidate_index"] for row in portfolio["models"]
        ]
        payload["training_parallel_panel"] = portfolio["training_selection"][
            "pointwise_minimum_panel"
        ]
    if RESULT.exists():
        result = json.loads(RESULT.read_bytes())
        payload["result_sha256"] = file_sha256(RESULT)
        payload["evidence_stage"] = result["evidence_stage"]
        payload["external_transfer"] = result["external_transfer"]
        payload["schedule_proof"] = result["schedule_proof"]
    return payload


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    action = parser.add_mutually_exclusive_group(required=True)
    action.add_argument("--analyze", action="store_true")
    action.add_argument("--freeze-implementation", action="store_true")
    action.add_argument("--freeze-portfolio", action="store_true")
    action.add_argument("--evaluate-external", action="store_true")
    parser.add_argument("--expected-implementation-sha256")
    parser.add_argument("--expected-portfolio-sha256")
    args = parser.parse_args()
    if args.freeze_implementation:
        payload = freeze_implementation()
    elif args.freeze_portfolio:
        if not args.expected_implementation_sha256:
            parser.error("--freeze-portfolio requires --expected-implementation-sha256")
        payload = freeze_portfolio(
            expected_implementation_sha256=args.expected_implementation_sha256
        )
    elif args.evaluate_external:
        if not args.expected_implementation_sha256 or not args.expected_portfolio_sha256:
            parser.error("--evaluate-external requires implementation and portfolio SHA-256")
        payload = evaluate_external(
            expected_implementation_sha256=args.expected_implementation_sha256,
            expected_portfolio_sha256=args.expected_portfolio_sha256,
        )
    else:
        payload = analyze()
    print(json.dumps(payload, indent=2, sort_keys=True), flush=True)


if __name__ == "__main__":
    main()

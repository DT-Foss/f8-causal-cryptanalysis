#!/usr/bin/env python3
"""A396: expand seven primitive W50 Readers into eight exact workers."""

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

DESIGN = (
    CONFIGS
    / "chacha20_round20_w50_expanded_seven_reader_eight_worker_a396_design_v1.json"
)
IMPLEMENTATION = (
    CONFIGS
    / "chacha20_round20_w50_expanded_seven_reader_eight_worker_a396_implementation_v1.json"
)
RESULT = (
    RESULTS / "chacha20_round20_w50_expanded_seven_reader_eight_worker_a396_v1.json"
)
CAUSAL = RESULT.with_suffix(".causal")
REPORT = RESULT.with_suffix(".md")
TEST = (
    ROOT
    / "tests/test_chacha20_round20_w50_expanded_seven_reader_eight_worker_a396.py"
)
REPRO = (
    ROOT
    / "scripts/reproduce_chacha20_round20_w50_expanded_seven_reader_eight_worker_a396.sh"
)

A394_RUNNER = (
    RESEARCH
    / "experiments/chacha20_round20_w50_order_preserving_work_stealing_a394.py"
)
A382_ORDER = (
    RESULTS / "chacha20_round20_w49_crosswidth_wide_consensus_factor6_a382_order_v1.json"
)
A382_CAUSAL = A382_ORDER.with_suffix(".causal")
A388_ORDER = (
    RESULTS / "chacha20_round20_w50_public_output_direct12_factor3_a388_order_v1.json"
)
A388_CAUSAL = A388_ORDER.with_suffix(".causal")
A394_RESULT = (
    RESULTS / "chacha20_round20_w50_order_preserving_work_stealing_a394_v1.json"
)
A394_CAUSAL = A394_RESULT.with_suffix(".causal")

ATTEMPT_ID = "A396"
DESIGN_SHA256 = "40a644024d56e21d489cb1d9b14e89390f2018f2dfb28115c1f2a95f427b976f"
A394_RUNNER_SHA256 = "6905a2d37b7731f63ce23b39dd3f637505a6143ffd762fae9e8aa19a9cec3d47"
A382_ORDER_SHA256 = "f705549d15be9f4ed98e8548b837524dae8603bff384ab30648c5917dfb82c0c"
A382_CAUSAL_SHA256 = "a079ddb6c492761f110090a019d7442bd093aa94f104859d2ea8b63b3b76472b"
A388_ORDER_SHA256 = "3c56ce8521b1ced20e1e3a90999810c2e563c4de941701c86274f0828b5d01b8"
A388_CAUSAL_SHA256 = "095e4a05b86df98b27899c3055d4ff4c5ea2eab5ffa5961cfb36747320090e3a"
A394_RESULT_SHA256 = "9f29fecdf60a9b1b128487609b009b3def8f2b4bf7d45329e95bd5dae8ccef6d"
A394_CAUSAL_SHA256 = "63b95b39f91957337ec3dcd9bed55fa50642afc538ab3cd355e57dedf22c2890"
ROLE_DIRECT = "A388_W50_public_output_direct12"
SOURCE_ROLES = (
    "A379_target_free",
    "A380_target_conditioned",
    "wide_vote",
    "sparse_reciprocal",
    "broad_quantile",
    "broad_intersection",
    ROLE_DIRECT,
)
SPARE_ROLE = "A396_spare_longest_remaining"
WORKER_ROLES = (*SOURCE_ROLES, SPARE_ROLE)
CELLS = 4096
WORKERS = 8
OPTIMAL_EPOCHS = 512
DOTCAUSAL_SRC = Path(
    "/Users/bhkmie/Documents/Forschung/O1/vendor/fabel/dotcausal_package/src"
)


def load_module(path: Path, name: str) -> Any:
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot import A396 dependency {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


A394 = load_module(A394_RUNNER, "a396_a394")
file_sha256 = A394.file_sha256
canonical_sha256 = A394.canonical_sha256
atomic_json = A394.atomic_json
atomic_bytes = A394.atomic_bytes
relative = A394.relative
path_from_ref = A394.path_from_ref
anchor = A394.anchor
uint16be_sha256 = A394.uint16be_sha256
quantiles = A394.quantiles


def exact_order(values: Sequence[int], *, size: int = CELLS) -> list[int]:
    order = [int(value) for value in values]
    if len(order) != size or set(order) != set(range(size)):
        raise ValueError("A396 source order is not one exact permutation")
    return order


def task_list_sha256(values: Sequence[Mapping[str, Any]]) -> str:
    return canonical_sha256([dict(value) for value in values])


def minimum_rank_owner_lanes(
    source_orders: Mapping[str, Sequence[int]],
    role_order: Sequence[str],
    *,
    size: int,
) -> dict[str, Any]:
    roles = tuple(str(role) for role in role_order)
    if not roles or len(roles) != len(set(roles)) or set(roles) != set(source_orders):
        raise ValueError("A396 source role contract differs")
    orders = {role: exact_order(source_orders[role], size=size) for role in roles}
    ranks = {
        role: [0] * size
        for role in roles
    }
    for role in roles:
        for rank, cell in enumerate(orders[role], 1):
            ranks[role][cell] = rank
    owner = [
        min(roles, key=lambda role: (ranks[role][cell], roles.index(role)))
        for cell in range(size)
    ]
    lanes = {
        role: sorted(
            (cell for cell in range(size) if owner[cell] == role),
            key=lambda cell: ranks[role][cell],
        )
        for role in roles
    }
    owner_depth = [0] * size
    for role in roles:
        for depth, cell in enumerate(lanes[role], 1):
            owner_depth[cell] = depth
    if sum(map(len, lanes.values())) != size:
        raise RuntimeError("A396 owner lanes do not cover the domain")
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
    owner_lanes: Mapping[str, Sequence[int]],
    source_role_order: Sequence[str],
    worker_role_order: Sequence[str],
) -> dict[str, Any]:
    sources = tuple(str(role) for role in source_role_order)
    workers = tuple(str(role) for role in worker_role_order)
    if (
        not sources
        or set(sources) != set(owner_lanes)
        or len(sources) != len(set(sources))
        or len(workers) <= len(sources)
        or len(workers) != len(set(workers))
        or tuple(workers[: len(sources)]) != sources
    ):
        raise ValueError("A396 worker/source role contract differs")
    lanes = {role: [int(cell) for cell in owner_lanes[role]] for role in sources}
    flattened = [cell for role in sources for cell in lanes[role]]
    size = len(flattened)
    if len(set(flattened)) != size or set(flattened) != set(range(size)):
        raise ValueError("A396 owner lanes are not one exact disjoint cover")
    role_index = {role: index for index, role in enumerate(sources)}
    pointers = {role: 0 for role in sources}
    tasks: dict[str, list[dict[str, Any]]] = {worker: [] for worker in workers}
    cell_epoch = [0] * size
    cell_worker = [""] * size
    cell_owner = [""] * size
    cell_owner_position = [0] * size
    epoch = 0
    claimed = 0
    while claimed < size:
        epoch += 1
        for worker in workers:
            if claimed == size:
                break
            if worker in sources and pointers[worker] < len(lanes[worker]):
                donor = worker
            else:
                remaining = {
                    role: len(lanes[role]) - pointers[role] for role in sources
                }
                donor = max(
                    sources,
                    key=lambda role: (remaining[role], -role_index[role]),
                )
                if remaining[donor] <= 0:
                    raise RuntimeError("A396 longest-remaining donor selection failed")
            owner_position = pointers[donor] + 1
            cell = lanes[donor][pointers[donor]]
            pointers[donor] += 1
            claimed += 1
            worker_step = len(tasks[worker]) + 1
            row = {
                "cell": cell,
                "epoch": epoch,
                "worker_role": worker,
                "worker_step_one_based": worker_step,
                "owner_queue_role": donor,
                "owner_queue_position_one_based": owner_position,
                "stolen": donor != worker,
            }
            tasks[worker].append(row)
            cell_epoch[cell] = epoch
            cell_worker[cell] = worker
            cell_owner[cell] = donor
            cell_owner_position[cell] = owner_position
    for owner in sources:
        observed = [
            row["cell"]
            for epoch_value in range(1, epoch + 1)
            for worker in workers
            for row in tasks[worker]
            if row["epoch"] == epoch_value and row["owner_queue_role"] == owner
        ]
        if observed != lanes[owner]:
            raise RuntimeError(f"A396 {owner} owner queue order was not preserved")
    worker_orders = {
        worker: [row["cell"] for row in tasks[worker]] for worker in workers
    }
    return {
        "source_role_order": list(sources),
        "worker_role_order": list(workers),
        "cells": size,
        "workers": len(workers),
        "epochs": epoch,
        "theoretical_minimum_epochs": math.ceil(size / len(workers)),
        "worker_tasks": tasks,
        "worker_cell_orders": worker_orders,
        "worker_task_counts": {
            worker: len(tasks[worker]) for worker in workers
        },
        "worker_stolen_task_counts": {
            worker: sum(row["stolen"] for row in tasks[worker])
            for worker in workers
        },
        "worker_cell_order_uint16be_sha256": {
            worker: uint16be_sha256(worker_orders[worker]) for worker in workers
        },
        "worker_task_list_sha256": {
            worker: task_list_sha256(tasks[worker]) for worker in workers
        },
        "cell_epoch_one_based": cell_epoch,
        "cell_worker_role": cell_worker,
        "cell_owner_queue_role": cell_owner,
        "cell_owner_queue_position_one_based": cell_owner_position,
        "complete_cover_cells": claimed,
        "duplicate_cells": claimed - len(set(cell_worker_index(worker_orders))),
        "uncovered_cells": size - len(set(cell_worker_index(worker_orders))),
    }


def cell_worker_index(worker_orders: Mapping[str, Sequence[int]]) -> list[int]:
    return [int(cell) for order in worker_orders.values() for cell in order]


def load_design() -> dict[str, Any]:
    if file_sha256(DESIGN) != DESIGN_SHA256:
        raise RuntimeError("A396 design hash differs")
    value = json.loads(DESIGN.read_bytes())
    source = value.get("source_contract", {})
    worker = value.get("worker_contract", {})
    boundary = value.get("information_boundary", {})
    if (
        value.get("schema")
        != "chacha20-round20-w50-expanded-seven-reader-eight-worker-a396-design-v1"
        or value.get("attempt_id") != ATTEMPT_ID
        or value.get("design_state")
        != "frozen_after_target_blind_source_geometry_exploration_before_any_A396_materialized_artifact_or_candidate_execution"
        or tuple(source.get("source_role_order", [])) != SOURCE_ROLES
        or source.get("source_orders") != len(SOURCE_ROLES)
        or source.get("cells_per_order") != CELLS
        or tuple(worker.get("worker_role_order", [])) != WORKER_ROLES
        or worker.get("workers") != WORKERS
        or worker.get("target_makespan_epochs") != OPTIMAL_EPOCHS
        or worker.get("theoretical_minimum_epochs") != OPTIMAL_EPOCHS
        or worker.get("preserve_each_owner_queue_order") is not True
        or boundary.get("target_labels_used") != 0
        or boundary.get("reader_refits") != 0
        or boundary.get("candidate_assignments_executed") != 0
        or boundary.get(
            "A387_A389_A391_A393_A395_progress_or_filter_outcomes_consumed"
        )
        is not False
        or boundary.get("proof_covers_all_4096_possible_target_cells") is not True
        or boundary.get("exploratory_source_geometry_was_seen_before_design_freeze")
        is not True
        or boundary.get("target_assignment_or_target_rank_was_seen_before_design_freeze")
        is not False
    ):
        raise RuntimeError("A396 frozen design semantics differ")
    for name, source_path in value["source_anchors"].items():
        if name.endswith("_path"):
            stem = name.removesuffix("_path")
            anchor(ROOT / source_path, value["source_anchors"][f"{stem}_sha256"])
    return value


def load_sources() -> tuple[dict[str, Any], dict[str, list[int]], dict[str, Any]]:
    anchor(A382_ORDER, A382_ORDER_SHA256)
    anchor(A382_CAUSAL, A382_CAUSAL_SHA256)
    anchor(A388_ORDER, A388_ORDER_SHA256)
    anchor(A388_CAUSAL, A388_CAUSAL_SHA256)
    a382 = json.loads(A382_ORDER.read_bytes())
    a388 = json.loads(A388_ORDER.read_bytes())
    if (
        a382.get("schema")
        != "chacha20-round20-w49-crosswidth-wide-consensus-factor6-a382-order-v1"
        or tuple(a382.get("source_role_order", [])) != SOURCE_ROLES[:-1]
        or a382.get("candidate_assignments_executed") != 0
        or a382.get("target_labels_used") != 0
        or a382.get("reader_refits") != 0
        or a388.get("schema")
        != "chacha20-round20-w50-public-output-direct12-factor3-a388-order-v1"
        or a388.get("candidate_assignments_executed") != 0
        or a388.get("target_labels_used") != 0
        or a388.get("reader_refits") != 0
        or a388.get("A387_progress_or_filter_outcomes_consumed") is not False
    ):
        raise RuntimeError("A396 source information boundary differs")
    orders = {
        role: exact_order(a382["source_orders"][role])
        for role in SOURCE_ROLES[:-1]
    }
    orders[ROLE_DIRECT] = exact_order(a388["W50_public_output_direct12_order"])
    for role in SOURCE_ROLES[:-1]:
        expected = a382["source_order_summary"][role][
            "selected_order_uint16be_sha256"
        ]
        if uint16be_sha256(orders[role]) != expected:
            raise RuntimeError(f"A396 {role} source order bytes differ")
    if (
        uint16be_sha256(orders[ROLE_DIRECT])
        != a388["W50_public_output_direct12_order_uint16be_sha256"]
    ):
        raise RuntimeError("A396 Direct12 source order bytes differ")
    return a382, orders, a388


def prove_schedule(
    owners: Mapping[str, Any],
    work: Mapping[str, Any],
    a388: Mapping[str, Any],
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    anchor(A394_RESULT, A394_RESULT_SHA256)
    anchor(A394_CAUSAL, A394_CAUSAL_SHA256)
    a394 = json.loads(A394_RESULT.read_bytes())
    old_epochs = [int(value) for value in a394["cell_epoch_one_based"]]
    epochs = [int(value) for value in work["cell_epoch_one_based"]]
    owner_depths = [int(value) for value in owners["owner_lane_depth_one_based"]]
    ranks = owners["source_ranks_one_based"]
    serial_rank = [0] * CELLS
    for rank, cell in enumerate(exact_order(a388["selected_order"]), 1):
        serial_rank[cell] = rank
    per_cell: list[dict[str, Any]] = []
    depth_ratios: list[float] = []
    work_ratios: list[float] = []
    old_speedups: list[float] = []
    serial_speedups: list[float] = []
    strict_vs_old = 0
    equal_old = 0
    worse_old = 0
    for cell in range(CELLS):
        best_rank = min(int(ranks[role][cell]) for role in SOURCE_ROLES)
        owner = owners["owner_role"][cell]
        owner_source_rank = int(ranks[owner][cell])
        owner_depth = owner_depths[cell]
        epoch = epochs[cell]
        total_work = min(WORKERS * epoch, CELLS)
        if owner_source_rank != best_rank:
            raise RuntimeError("A396 minimum-rank owner theorem failed")
        if epoch > owner_depth or owner_depth > best_rank:
            raise RuntimeError("A396 depth theorem failed")
        if total_work > WORKERS * best_rank:
            raise RuntimeError("A396 total-work theorem failed")
        if epoch < old_epochs[cell]:
            strict_vs_old += 1
        elif epoch == old_epochs[cell]:
            equal_old += 1
        else:
            worse_old += 1
        depth_ratios.append(epoch / best_rank)
        work_ratios.append(total_work / (WORKERS * best_rank))
        old_speedups.append(old_epochs[cell] / epoch)
        serial_speedups.append(serial_rank[cell] / epoch)
        per_cell.append(
            {
                "cell": cell,
                "owner": owner,
                "best_source_rank_one_based": best_rank,
                "owner_lane_depth_one_based": owner_depth,
                "A396_epoch_one_based": epoch,
                "A394_epoch_one_based": old_epochs[cell],
                "A388_serial_wavefront_rank_one_based": serial_rank[cell],
                "total_unique_work_at_A396_epoch": total_work,
            }
        )
    proof = {
        "cells_checked": CELLS,
        "complete_cover_cells": work["complete_cover_cells"],
        "duplicate_cells": work["duplicate_cells"],
        "uncovered_cells": work["uncovered_cells"],
        "owner_queue_order_preservation_violations": 0,
        "depth_bound": "D_A396(c) <= D_owner(c) <= min_i R_i(c)",
        "depth_bound_violations": 0,
        "maximum_depth_to_best_source_ratio": max(depth_ratios),
        "total_work_bound": "W_A396(c) <= 8*min_i R_i(c)",
        "total_work_bound_violations": 0,
        "maximum_total_work_to_bound_ratio": max(work_ratios),
        "makespan_epochs": work["epochs"],
        "theoretical_minimum_epochs": work["theoretical_minimum_epochs"],
        "makespan_optimal": work["epochs"] == work["theoretical_minimum_epochs"],
        "A396_strictly_faster_than_A394_cells": strict_vs_old,
        "A396_equal_to_A394_cells": equal_old,
        "A396_slower_than_A394_cells": worse_old,
        "geometric_mean_A394_to_A396_epoch_speedup": math.exp(
            statistics.fmean(math.log(value) for value in old_speedups)
        ),
        "geometric_mean_A388_serial_to_A396_epoch_speedup": math.exp(
            statistics.fmean(math.log(value) for value in serial_speedups)
        ),
        "A396_epoch_quantiles": quantiles(epochs),
        "A394_to_A396_speedup_quantiles": quantiles(old_speedups),
        "A388_serial_to_A396_speedup_quantiles": quantiles(serial_speedups),
    }
    if proof["A396_slower_than_A394_cells"] != 0:
        raise RuntimeError("A396 pointwise A394 dominance failed")
    return proof, per_cell


def freeze_implementation() -> dict[str, Any]:
    if any(path.exists() for path in (IMPLEMENTATION, RESULT, CAUSAL, REPORT)):
        raise FileExistsError("A396 implementation or result already exists")
    design = load_design()
    _a382, orders, _a388 = load_sources()
    if not TEST.exists() or not REPRO.exists():
        raise FileNotFoundError("A396 test and reproducer must precede freeze")
    payload: dict[str, Any] = {
        "schema": "chacha20-round20-w50-expanded-seven-reader-eight-worker-a396-implementation-v1",
        "attempt_id": ATTEMPT_ID,
        "commitment_state": "frozen_before_A396_materialization_or_candidate_execution",
        "design_sha256": DESIGN_SHA256,
        "source_contract": design["source_contract"],
        "worker_contract": design["worker_contract"],
        "source_order_uint16be_sha256": {
            role: uint16be_sha256(orders[role]) for role in SOURCE_ROLES
        },
        "A396_candidate_assignments_available_at_freeze": 0,
        "anchors": {
            "design": anchor(DESIGN, DESIGN_SHA256),
            "A394_runner": anchor(A394_RUNNER, A394_RUNNER_SHA256),
            "A382_order": anchor(A382_ORDER, A382_ORDER_SHA256),
            "A382_causal": anchor(A382_CAUSAL, A382_CAUSAL_SHA256),
            "A388_order": anchor(A388_ORDER, A388_ORDER_SHA256),
            "A388_causal": anchor(A388_CAUSAL, A388_CAUSAL_SHA256),
            "A394_result": anchor(A394_RESULT, A394_RESULT_SHA256),
            "A394_causal": anchor(A394_CAUSAL, A394_CAUSAL_SHA256),
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
        raise RuntimeError("A396 implementation hash differs")
    value = json.loads(IMPLEMENTATION.read_bytes())
    if (
        value.get("schema")
        != "chacha20-round20-w50-expanded-seven-reader-eight-worker-a396-implementation-v1"
        or value.get("attempt_id") != ATTEMPT_ID
        or value.get("design_sha256") != DESIGN_SHA256
        or value.get("A396_candidate_assignments_available_at_freeze") != 0
    ):
        raise RuntimeError("A396 implementation semantics differ")
    for row in value["anchors"].values():
        anchor(path_from_ref(row["path"]), row["sha256"])
    unsigned = {
        key: item
        for key, item in value.items()
        if key != "implementation_commitment_sha256"
    }
    if value.get("implementation_commitment_sha256") != canonical_sha256(unsigned):
        raise RuntimeError("A396 implementation commitment differs")
    return value


def build_causal(payload: Mapping[str, Any]) -> dict[str, Any]:
    sys.path.insert(0, str(DOTCAUSAL_SRC))
    from dotcausal.io import CausalReader, CausalWriter

    sources = "A396:seven_primitive_assignment_blind_reader_orders"
    lanes = "A396:seven_minimum_rank_owner_queues"
    theorem = "A396:optimal_512_epoch_pointwise_A394_dominance_theorem"
    ready = "A397:eight_worker_W50_executor_ready"
    writer = CausalWriter(api_id="a396w50")
    writer._rules = []
    writer.add_rule(
        name="primitive_orders_to_expanded_reader_set",
        description="Six unchanged A382 primitive orders and the independent W50 Direct12 order form seven complete assignment-blind source permutations.",
        pattern=["A382_six_primitive_orders", "A388_W50_Direct12_order"],
        conclusion="A396_seven_primitive_assignment_blind_reader_orders",
        confidence_modifier=1.0,
    )
    writer.add_rule(
        name="expanded_readers_to_minimum_rank_owner_queues",
        description="Every cell is assigned once to its minimum-rank primitive Reader and each owner queue preserves that Reader's order.",
        pattern=["A396_seven_primitive_assignment_blind_reader_orders"],
        conclusion="A396_seven_minimum_rank_owner_queues",
        confidence_modifier=1.0,
    )
    writer.add_rule(
        name="owner_queues_to_optimal_eight_worker_schedule",
        description="Seven home workers plus one longest-remaining spare consume all 4,096 groups in exactly 512 epochs while preserving every owner queue.",
        pattern=["A396_seven_minimum_rank_owner_queues"],
        conclusion="A396_optimal_512_epoch_pointwise_A394_dominance_theorem",
        confidence_modifier=1.0,
    )
    writer.add_rule(
        name="frozen_static_lists_to_executor",
        description="Eight hash-bound static worker lists remove runtime claim races and are ready for complete-group shared-stop execution.",
        pattern=["A396_optimal_512_epoch_pointwise_A394_dominance_theorem"],
        conclusion="A397_eight_worker_W50_executor_ready",
        confidence_modifier=1.0,
    )
    writer.add_triplet(
        trigger="A382:six_primitive_orders_plus_A388:W50_Direct12",
        mechanism="assignment_blind_source_expansion_without_composite_dilution",
        outcome=sources,
        confidence=1.0,
        source=payload["source_commitment_sha256"],
        quantification=json.dumps(payload["source_order_uint16be_sha256"], sort_keys=True),
        evidence="zero target labels, Reader refits, candidates or recovery feedback",
        domain="full-round ChaCha20 W50 expanded Reader portfolio",
        quality_score=1.0,
    )
    writer.add_triplet(
        trigger=sources,
        mechanism="minimum_source_rank_Voronoi_ownership",
        outcome=lanes,
        confidence=1.0,
        source=payload["owner_lane_commitment_sha256"],
        quantification=json.dumps(payload["owner_lane_sizes"], sort_keys=True),
        evidence="one exact disjoint 4,096-cell cover",
        domain="expanded Reader owner partition",
        quality_score=1.0,
    )
    writer.add_triplet(
        trigger=lanes,
        mechanism="seven_home_plus_one_spare_order_preserving_work_stealing",
        outcome=theorem,
        confidence=1.0,
        source=payload["measurement_sha256"],
        quantification=json.dumps(payload["proof"], sort_keys=True),
        evidence="512 optimal epochs and pointwise zero regressions versus A394",
        domain="exact eight-worker scheduling theorem",
        quality_score=1.0,
    )
    writer.add_triplet(
        trigger="A382:six_primitive_orders_plus_A388:W50_Direct12",
        mechanism="materialized_expansion_partition_schedule_theorem_chain",
        outcome=ready,
        confidence=1.0,
        source="materialized:A396_expanded_eight_worker_chain",
        quantification="exact retained closure",
        evidence=payload["evidence_stage"],
        domain="AI-native retained inference",
        quality_score=1.0,
        is_inferred=True,
    )
    writer.add_cluster(
        name="A396 expanded seven-Reader eight-worker scheduler",
        entities=[sources, lanes, theorem, ready],
    )
    writer.add_gap(
        subject=ready,
        predicate="next_required_object",
        expected_object_type="complete_group_shared_stop_execution_of_eight_static_worker_lists",
        confidence=1.0,
        suggested_queries=[
            "Execute the eight disjoint A396 worker lists with complete W50 groups, matched control and one shared independently confirmed stop."
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
        reader.api_id != "a396w50"
        or len(explicit) != 3
        or len(all_rows) != 4
        or len(inferred) != 1
        or len(reader._rules) != 4
        or len(reader._clusters) != 1
        or len(reader._gaps) != 1
    ):
        raise RuntimeError("A396 authentic Causal reopen gate failed")
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
            "source_expansion": explicit[0],
            "owner_partition": explicit[1],
            "schedule_theorem": explicit[2],
            "terminal_chain": all_rows[-1],
            "next_gap": reader._gaps[0],
        },
    }


def materialize(*, expected_implementation_sha256: str) -> dict[str, Any]:
    if any(path.exists() for path in (RESULT, CAUSAL, REPORT)):
        raise FileExistsError("A396 result artifact already exists")
    implementation = load_implementation(expected_implementation_sha256)
    _a382, orders, a388 = load_sources()
    owners = minimum_rank_owner_lanes(orders, SOURCE_ROLES, size=CELLS)
    work = balanced_static_worker_schedule(
        owners["owner_lane_orders"], SOURCE_ROLES, WORKER_ROLES
    )
    proof, per_cell = prove_schedule(owners, work, a388)
    source_commitment = canonical_sha256(
        {
            "source_role_order": list(SOURCE_ROLES),
            "source_order_uint16be_sha256": owners[
                "source_order_uint16be_sha256"
            ],
        }
    )
    owner_commitment = canonical_sha256(
        {
            "owner_lane_sizes": owners["owner_lane_sizes"],
            "owner_lane_order_uint16be_sha256": owners[
                "owner_lane_order_uint16be_sha256"
            ],
        }
    )
    schedule_commitment = canonical_sha256(
        {
            "worker_role_order": list(WORKER_ROLES),
            "worker_cell_order_uint16be_sha256": work[
                "worker_cell_order_uint16be_sha256"
            ],
            "worker_task_list_sha256": work["worker_task_list_sha256"],
            "proof": proof,
        }
    )
    payload: dict[str, Any] = {
        "schema": "chacha20-round20-w50-expanded-seven-reader-eight-worker-a396-result-v1",
        "attempt_id": ATTEMPT_ID,
        "evidence_stage": "EXACT_ASSIGNMENT_BLIND_EXPANDED_SEVEN_READER_OPTIMAL_EIGHT_WORKER_SCHEDULER_RETAINED",
        "design_sha256": DESIGN_SHA256,
        "implementation_sha256": expected_implementation_sha256,
        "implementation_commitment_sha256": implementation[
            "implementation_commitment_sha256"
        ],
        "source_role_order": list(SOURCE_ROLES),
        "worker_role_order": list(WORKER_ROLES),
        "source_order_uint16be_sha256": owners[
            "source_order_uint16be_sha256"
        ],
        "owner_lane_orders": owners["owner_lane_orders"],
        "owner_lane_sizes": owners["owner_lane_sizes"],
        "owner_lane_order_uint16be_sha256": owners[
            "owner_lane_order_uint16be_sha256"
        ],
        "worker_tasks": work["worker_tasks"],
        "worker_cell_orders": work["worker_cell_orders"],
        "worker_cell_order_uint16be_sha256": work[
            "worker_cell_order_uint16be_sha256"
        ],
        "worker_task_list_sha256": work["worker_task_list_sha256"],
        "worker_task_counts": work["worker_task_counts"],
        "worker_stolen_task_counts": work["worker_stolen_task_counts"],
        "cell_epoch_one_based": work["cell_epoch_one_based"],
        "cell_worker_role": work["cell_worker_role"],
        "cell_owner_queue_role": work["cell_owner_queue_role"],
        "cell_owner_queue_position_one_based": work[
            "cell_owner_queue_position_one_based"
        ],
        "proof": proof,
        "per_cell_proof": per_cell,
        "source_commitment_sha256": source_commitment,
        "owner_lane_commitment_sha256": owner_commitment,
        "schedule_commitment_sha256": schedule_commitment,
        "candidate_assignments_executed": 0,
        "target_labels_used": 0,
        "reader_refits": 0,
        "progress_or_filter_outcomes_consumed": 0,
        "exploratory_source_geometry_seen_before_design_freeze": True,
        "target_assignment_or_rank_seen_before_design_freeze": False,
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
        }
    )
    payload["causal"] = build_causal(payload)
    atomic_json(RESULT, payload)
    atomic_bytes(
        REPORT,
        (
            "# A396 — expanded seven-Reader/eight-worker W50 scheduler\n\n"
            f"Evidence stage: **{payload['evidence_stage']}**\n\n"
            f"- Owner-lane sizes: **{owners['owner_lane_sizes']}**\n"
            f"- Worker task counts: **{work['worker_task_counts']}**\n"
            f"- Makespan: **{proof['makespan_epochs']} epochs**\n"
            f"- Theoretical minimum: **{proof['theoretical_minimum_epochs']} epochs**\n"
            f"- Cells strictly earlier than A394: **{proof['A396_strictly_faster_than_A394_cells']} / {CELLS}**\n"
            f"- Geometric A394-to-A396 speedup: **{proof['geometric_mean_A394_to_A396_epoch_speedup']:.9f}x**\n"
            "- Cells later than A394: **zero**\n"
            "- Duplicate / uncovered prefixes: **0 / 0**\n"
            "- Depth / total-work / owner-order violations: **0 / 0 / 0**\n"
            "- Candidate assignments / target labels / refits: **0 / 0 / 0**\n"
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
        payload["result_sha256"] = file_sha256(RESULT)
        payload["evidence_stage"] = value["evidence_stage"]
        payload["schedule_commitment_sha256"] = value[
            "schedule_commitment_sha256"
        ]
    return payload


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    action = parser.add_mutually_exclusive_group(required=True)
    action.add_argument("--analyze", action="store_true")
    action.add_argument("--freeze-implementation", action="store_true")
    action.add_argument("--materialize", action="store_true")
    parser.add_argument("--expected-implementation-sha256")
    args = parser.parse_args()
    if args.freeze_implementation:
        payload = freeze_implementation()
    elif args.materialize:
        if not args.expected_implementation_sha256:
            parser.error("--materialize requires --expected-implementation-sha256")
        payload = materialize(
            expected_implementation_sha256=args.expected_implementation_sha256
        )
    else:
        payload = analyze()
    print(json.dumps(payload, indent=2, sort_keys=True), flush=True)


if __name__ == "__main__":
    main()

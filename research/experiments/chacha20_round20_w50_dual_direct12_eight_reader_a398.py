#!/usr/bin/env python3
"""A398: add the frozen Direct12 triple Reader to an exact eight-source W50 schedule."""

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

DESIGN = CONFIGS / "chacha20_round20_w50_dual_direct12_eight_reader_a398_design_v1.json"
IMPLEMENTATION = (
    CONFIGS / "chacha20_round20_w50_dual_direct12_eight_reader_a398_implementation_v1.json"
)
RESULT = RESULTS / "chacha20_round20_w50_dual_direct12_eight_reader_a398_v1.json"
CAUSAL = RESULT.with_suffix(".causal")
REPORT = RESULT.with_suffix(".md")
TEST = ROOT / "tests/test_chacha20_round20_w50_dual_direct12_eight_reader_a398.py"
REPRO = ROOT / "scripts/reproduce_chacha20_round20_w50_dual_direct12_eight_reader_a398.sh"

A396_RUNNER = (
    RESEARCH / "experiments/chacha20_round20_w50_expanded_seven_reader_eight_worker_a396.py"
)
A388_RUNNER = (
    RESEARCH / "experiments/chacha20_round20_w50_public_output_direct12_factor3_a388.py"
)
A396_RESULT = RESULTS / "chacha20_round20_w50_expanded_seven_reader_eight_worker_a396_v1.json"
A388_ORDER = RESULTS / "chacha20_round20_w50_public_output_direct12_factor3_a388_order_v1.json"
A342_RESULT = RESULTS / "chacha20_round20_w46_exhaustive_reader_ensemble_a342_v1.json"
A385_PROTOCOL = CONFIGS / "chacha20_round20_fresh_w50_pretarget_transfer_a385_v1.json"

ATTEMPT_ID = "A398"
DESIGN_SHA256 = "817defc870a84276d51a094e12e477c09394b88c0ffc34c532275e768d3c70bd"
A396_RUNNER_SHA256 = "1de7350d841de615b74c6732e4767fda64f7ac07356de4ecba48953657419734"
A388_RUNNER_SHA256 = "36c933ae5003f92f2b96efb2e30d97c30bf8301bfcaa790333a6712f3041b5a9"
A396_RESULT_SHA256 = "0dd39b595bd111c88b1c94c325c1039a041211e8e11e1e79f71c6470cc8edff8"
A388_ORDER_SHA256 = "3c56ce8521b1ced20e1e3a90999810c2e563c4de941701c86274f0828b5d01b8"
A342_RESULT_SHA256 = "8d6d6f99b89d67d7eff186037934bfa515cf93a00af10b244826f44056b4cebb"
A385_PROTOCOL_SHA256 = "801831f2daabe41476c9bf1ec676907f11c1b5465a193ba61d8d1877eb3b0b4b"

ROLE_PAIR = "A388_W50_public_output_direct12_pair"
ROLE_TRIPLE = "A398_W50_public_output_direct12_triple"
SOURCE_ROLES = (
    "A379_target_free",
    "A380_target_conditioned",
    "wide_vote",
    "sparse_reciprocal",
    "broad_quantile",
    "broad_intersection",
    ROLE_PAIR,
    ROLE_TRIPLE,
)
CELLS = 4096
WORKERS = 8
OPTIMAL_EPOCHS = 512
TOP_K = (32, 64, 128, 256, 512, 1024)
DOTCAUSAL_SRC = Path(
    "/Users/bhkmie/Documents/Forschung/O1/vendor/fabel/dotcausal_package/src"
)


def load_module(path: Path, name: str) -> Any:
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot import A398 dependency {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


A396 = load_module(A396_RUNNER, "a398_a396")
A388 = load_module(A388_RUNNER, "a398_a388")

file_sha256 = A396.file_sha256
canonical_sha256 = A396.canonical_sha256
atomic_json = A396.atomic_json
atomic_bytes = A396.atomic_bytes
relative = A396.relative
anchor = A396.anchor
uint16be_sha256 = A396.uint16be_sha256
quantiles = A396.quantiles


def exact_order(values: Sequence[int]) -> list[int]:
    order = [int(value) for value in values]
    if len(order) != CELLS or set(order) != set(range(CELLS)):
        raise ValueError("A398 source is not one exact 4,096-cell permutation")
    return order


def task_list_sha256(values: Sequence[Mapping[str, Any]]) -> str:
    return canonical_sha256([dict(value) for value in values])


def load_design() -> dict[str, Any]:
    if file_sha256(DESIGN) != DESIGN_SHA256:
        raise RuntimeError("A398 design hash differs")
    value = json.loads(DESIGN.read_bytes())
    source = value.get("source_contract", {})
    worker = value.get("worker_contract", {})
    boundary = value.get("information_boundary", {})
    triple = source.get("triple_source", {})
    if (
        value.get("schema")
        != "chacha20-round20-w50-dual-direct12-eight-reader-a398-design-v1"
        or value.get("attempt_id") != ATTEMPT_ID
        or value.get("design_state")
        != "frozen_before_W50_triple_order_A398_owner_partition_schedule_or_recovery_outcome"
        or tuple(source.get("source_role_order", [])) != SOURCE_ROLES
        or source.get("source_orders") != len(SOURCE_ROLES)
        or source.get("cells_per_order") != CELLS
        or tuple(worker.get("worker_role_order", [])) != SOURCE_ROLES
        or worker.get("workers") != WORKERS
        or worker.get("target_makespan_epochs") != OPTIMAL_EPOCHS
        or worker.get("theoretical_minimum_epochs") != OPTIMAL_EPOCHS
        or worker.get("preserve_each_owner_queue_order") is not True
        or triple.get("selected_indices") != [17, 27, 33]
        or triple.get("reader_refits") != 0
        or triple.get("target_labels") != 0
        or boundary.get("candidate_assignments_executed") != 0
        or boundary.get("new_solver_stages") != 0
        or boundary.get("reader_refits") != 0
        or boundary.get("target_labels_used") != 0
        or boundary.get(
            "A387_A389_A391_A393_A395_A397_progress_filter_outcomes_or_results_consumed"
        )
        is not False
        or boundary.get("A385_unknown_assignment_or_true_prefix_consumed") is not False
    ):
        raise RuntimeError("A398 frozen design semantics differ")
    for key, path in value["source_anchors"].items():
        if key.endswith("_path"):
            stem = key.removesuffix("_path")
            anchor(ROOT / path, value["source_anchors"][f"{stem}_sha256"])
    return value


def load_fixed_artifacts() -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    anchor(A396_RUNNER, A396_RUNNER_SHA256)
    anchor(A388_RUNNER, A388_RUNNER_SHA256)
    anchor(A396_RESULT, A396_RESULT_SHA256)
    anchor(A388_ORDER, A388_ORDER_SHA256)
    anchor(A342_RESULT, A342_RESULT_SHA256)
    anchor(A385_PROTOCOL, A385_PROTOCOL_SHA256)
    a396 = json.loads(A396_RESULT.read_bytes())
    a388 = json.loads(A388_ORDER.read_bytes())
    a342 = json.loads(A342_RESULT.read_bytes())
    protocol = json.loads(A385_PROTOCOL.read_bytes())
    boundary = protocol.get("public_challenge", {})
    if (
        a396.get("schema")
        != "chacha20-round20-w50-expanded-seven-reader-eight-worker-a396-result-v1"
        or a396.get("candidate_assignments_executed") != 0
        or a396.get("target_labels_used") != 0
        or a396.get("reader_refits") != 0
        or a396.get("progress_or_filter_outcomes_consumed") != 0
        or a388.get("schema")
        != "chacha20-round20-w50-public-output-direct12-factor3-a388-order-v1"
        or a388.get("candidate_assignments_executed") != 0
        or a388.get("target_labels_used") != 0
        or a388.get("reader_refits") != 0
        or a388.get("A387_progress_or_filter_outcomes_consumed") is not False
        or a342.get("schema")
        != "chacha20-round20-w46-exhaustive-reader-ensemble-a342-result-v1"
        or protocol.get("schema")
        != "chacha20-round20-fresh-w50-pretarget-transfer-a385-protocol-v1"
        or boundary.get("unknown_assignment_included") is not False
        or boundary.get("unknown_key_bits") != 50
        or boundary.get("rounds") != 20
        or boundary.get("feedforward") is not True
    ):
        raise RuntimeError("A398 fixed-artifact information boundary differs")
    return a396, a388, a342


def load_measurements(a388: Mapping[str, Any]) -> dict[int, dict[str, Any]]:
    ledger = a388.get("measurement_ledger", [])
    if len(ledger) != 16 or sorted(int(row["low4"]) for row in ledger) != list(range(16)):
        raise RuntimeError("A398 A388 measurement ledger differs")
    measurements: dict[int, dict[str, Any]] = {}
    for row in ledger:
        low4 = int(row["low4"])
        value = A388._read_measurement(A388.path_from_ref(row["path"]), row)  # noqa: SLF001
        A388._validate_measurement(value, low4)  # noqa: SLF001
        measurements[low4] = value
    return measurements


def selected_triple_slice_z_scores(
    measurements: Mapping[int, Mapping[str, Any]],
    a342: Mapping[str, Any],
) -> np.ndarray:
    design = load_design()
    frozen = design["source_contract"]["triple_source"]
    selection = a342["selection"]["triple"]
    indices = [int(value) for value in selection["selected_indices"]]
    selected_names = [str(value) for value in selection["selected_views"]]
    if indices != frozen["selected_indices"] or selected_names != frozen["selected_views"]:
        raise RuntimeError("A398 frozen A342 triple identity differs")
    _selection, _a272, model, groups = A388.A341.reconstruct_known_key_selection(
        json.loads(A388.A341.DESIGN.read_bytes())
    )
    field = np.empty(CELLS, dtype=np.float64)
    for low4 in range(16):
        matrix = A388.A349.A275._target_feature_matrix(measurements[low4])  # noqa: SLF001
        contributions = A388.A341.standardized_contributions(
            matrix,
            means=model.means,
            scales=model.scales,
            coefficients=model.coefficients,
        )
        grouped = A388.A341.grouped_scores(contributions, groups)
        names: list[str] = []
        views: dict[str, np.ndarray] = {}
        for group in sorted(groups):
            direct = f"{group}::direct_additive_contribution"
            local = f"{group}::normalized_8cube_graph_laplacian"
            names.extend([direct, local])
            views[direct] = grouped[group]
            views[local] = A388.A341.local_pairwise_residual(grouped[group])
        if [names[index] for index in indices] != selected_names:
            raise RuntimeError("A398 triple view index-to-name map differs")
        ranks = np.stack(
            [A388.A349.A342.midrank_vector_descending(views[name]) for name in names],
            axis=0,
        )
        triple = -ranks[indices].sum(axis=0)
        for high8 in range(256):
            field[A388.A348.slice_cell(high8, low4)] = triple[high8]
    return A388.A348._slice_zscores(field)  # noqa: SLF001


def load_source_orders() -> tuple[dict[str, list[int]], dict[str, Any]]:
    a396_result, a388, a342 = load_fixed_artifacts()
    _a382, inherited, _a388_loaded = A396.load_sources()
    measurements = load_measurements(a388)
    scores = selected_triple_slice_z_scores(measurements, a342)
    triple_order = exact_order(A388.A348._rank_order(scores))  # noqa: SLF001
    pair_order = exact_order(a388["W50_public_output_direct12_order"])
    roles6 = SOURCE_ROLES[:6]
    orders = {role: exact_order(inherited[role]) for role in roles6}
    orders[ROLE_PAIR] = pair_order
    orders[ROLE_TRIPLE] = triple_order
    for role in roles6:
        if uint16be_sha256(orders[role]) != a396_result["source_order_uint16be_sha256"][role]:
            raise RuntimeError(f"A398 inherited {role} bytes differ")
    if (
        uint16be_sha256(pair_order)
        != a388["W50_public_output_direct12_order_uint16be_sha256"]
        or pair_order == triple_order
    ):
        raise RuntimeError("A398 pair/triple order identity differs")
    metadata = {
        "A388_measurement_sha256": a388["measurement_sha256"],
        "A388_measurement_ledger": a388["measurement_ledger"],
        "triple_score_field_sha256": canonical_sha256(scores.tolist()),
        "triple_order_uint16be_sha256": uint16be_sha256(triple_order),
        "pair_order_uint16be_sha256": uint16be_sha256(pair_order),
        "pair_triple_diversity": {
            f"{ROLE_PAIR}__vs__{ROLE_TRIPLE}": A388.A351.diversity_panel(
                pair_order, triple_order
            )
        },
        "new_solver_stages": 0,
        "candidate_assignments_executed": 0,
        "target_labels_used": 0,
        "reader_refits": 0,
    }
    return orders, metadata


def balanced_equal_worker_schedule(
    owner_lanes: Mapping[str, Sequence[int]], role_order: Sequence[str]
) -> dict[str, Any]:
    roles = tuple(str(role) for role in role_order)
    if (
        len(roles) != WORKERS
        or len(set(roles)) != WORKERS
        or set(roles) != set(owner_lanes)
    ):
        raise ValueError("A398 equal-worker role contract differs")
    lanes = {role: [int(cell) for cell in owner_lanes[role]] for role in roles}
    flattened = [cell for role in roles for cell in lanes[role]]
    if len(flattened) != CELLS or set(flattened) != set(range(CELLS)):
        raise ValueError("A398 owner lanes are not one exact disjoint cover")
    role_index = {role: index for index, role in enumerate(roles)}
    pointers = {role: 0 for role in roles}
    tasks: dict[str, list[dict[str, Any]]] = {role: [] for role in roles}
    chronology: list[dict[str, Any]] = []
    cell_epoch = [0] * CELLS
    cell_worker = [""] * CELLS
    cell_owner = [""] * CELLS
    cell_owner_position = [0] * CELLS
    claimed = 0
    epoch = 0
    while claimed < CELLS:
        epoch += 1
        for worker in roles:
            if pointers[worker] < len(lanes[worker]):
                donor = worker
            else:
                remaining = {role: len(lanes[role]) - pointers[role] for role in roles}
                donor = max(roles, key=lambda role: (remaining[role], -role_index[role]))
                if remaining[donor] <= 0:
                    raise RuntimeError("A398 longest-remaining donor selection failed")
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
            chronology.append(row)
            cell_epoch[cell] = epoch
            cell_worker[cell] = worker
            cell_owner[cell] = donor
            cell_owner_position[cell] = owner_position
    for owner in roles:
        observed = [row["cell"] for row in chronology if row["owner_queue_role"] == owner]
        if observed != lanes[owner]:
            raise RuntimeError(f"A398 {owner} owner queue order was not preserved")
    worker_orders = {worker: [row["cell"] for row in tasks[worker]] for worker in roles}
    flat_workers = [cell for worker in roles for cell in worker_orders[worker]]
    return {
        "source_role_order": list(roles),
        "worker_role_order": list(roles),
        "cells": CELLS,
        "workers": WORKERS,
        "epochs": epoch,
        "theoretical_minimum_epochs": math.ceil(CELLS / WORKERS),
        "worker_tasks": tasks,
        "worker_cell_orders": worker_orders,
        "worker_task_counts": {worker: len(tasks[worker]) for worker in roles},
        "worker_stolen_task_counts": {
            worker: sum(bool(row["stolen"]) for row in tasks[worker]) for worker in roles
        },
        "worker_cell_order_uint16be_sha256": {
            worker: uint16be_sha256(worker_orders[worker]) for worker in roles
        },
        "worker_task_list_sha256": {
            worker: task_list_sha256(tasks[worker]) for worker in roles
        },
        "cell_epoch_one_based": cell_epoch,
        "cell_worker_role": cell_worker,
        "cell_owner_queue_role": cell_owner,
        "cell_owner_queue_position_one_based": cell_owner_position,
        "complete_cover_cells": len(set(flat_workers)),
        "duplicate_cells": len(flat_workers) - len(set(flat_workers)),
        "uncovered_cells": CELLS - len(set(flat_workers)),
    }


def prove_schedule(
    owners: Mapping[str, Any],
    work: Mapping[str, Any],
    orders: Mapping[str, Sequence[int]],
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    a396 = json.loads(A396_RESULT.read_bytes())
    a388 = json.loads(A388_ORDER.read_bytes())
    old_epochs = [int(value) for value in a396["cell_epoch_one_based"]]
    epochs = [int(value) for value in work["cell_epoch_one_based"]]
    owner_depths = [int(value) for value in owners["owner_lane_depth_one_based"]]
    ranks = owners["source_ranks_one_based"]
    serial_rank = [0] * CELLS
    for rank, cell in enumerate(exact_order(a388["selected_order"]), 1):
        serial_rank[cell] = rank
    strict = equal = slower = triple_owned = 0
    depth_ratios: list[float] = []
    work_ratios: list[float] = []
    old_ratios: list[float] = []
    serial_speedups: list[float] = []
    per_cell: list[dict[str, Any]] = []
    for cell in range(CELLS):
        best_rank = min(int(ranks[role][cell]) for role in SOURCE_ROLES)
        owner = str(owners["owner_role"][cell])
        owner_rank = int(ranks[owner][cell])
        owner_depth = owner_depths[cell]
        epoch = epochs[cell]
        total_work = min(WORKERS * epoch, CELLS)
        if owner_rank != best_rank:
            raise RuntimeError("A398 minimum-rank owner theorem failed")
        if epoch > owner_depth or owner_depth > best_rank:
            raise RuntimeError("A398 depth theorem failed")
        if total_work > WORKERS * best_rank:
            raise RuntimeError("A398 total-work theorem failed")
        if epoch < old_epochs[cell]:
            strict += 1
        elif epoch == old_epochs[cell]:
            equal += 1
        else:
            slower += 1
        triple_owned += owner == ROLE_TRIPLE
        depth_ratios.append(epoch / best_rank)
        work_ratios.append(total_work / (WORKERS * best_rank))
        old_ratios.append(old_epochs[cell] / epoch)
        serial_speedups.append(serial_rank[cell] / epoch)
        per_cell.append(
            {
                "cell": cell,
                "owner": owner,
                "best_source_rank_one_based": best_rank,
                "owner_lane_depth_one_based": owner_depth,
                "A398_epoch_one_based": epoch,
                "A396_epoch_one_based": old_epochs[cell],
                "A388_serial_wavefront_rank_one_based": serial_rank[cell],
                "total_unique_work_at_A398_epoch": total_work,
            }
        )
    proof = {
        "cells_checked": CELLS,
        "complete_cover_cells": work["complete_cover_cells"],
        "duplicate_cells": work["duplicate_cells"],
        "uncovered_cells": work["uncovered_cells"],
        "owner_queue_order_preservation_violations": 0,
        "depth_bound": "D_A398(c) <= D_owner(c) <= min_i R_i(c)",
        "depth_bound_violations": 0,
        "maximum_depth_to_best_source_ratio": max(depth_ratios),
        "total_work_bound": "W_A398(c) <= 8*min_i R_i(c)",
        "total_work_bound_violations": 0,
        "maximum_total_work_to_bound_ratio": max(work_ratios),
        "makespan_epochs": work["epochs"],
        "theoretical_minimum_epochs": work["theoretical_minimum_epochs"],
        "makespan_optimal": work["epochs"] == work["theoretical_minimum_epochs"],
        "A398_strictly_faster_than_A396_cells": strict,
        "A398_equal_to_A396_cells": equal,
        "A398_slower_than_A396_cells": slower,
        "A398_triple_owned_cells": triple_owned,
        "geometric_mean_A396_to_A398_epoch_ratio": math.exp(
            statistics.fmean(math.log(value) for value in old_ratios)
        ),
        "geometric_mean_A388_serial_to_A398_epoch_speedup": math.exp(
            statistics.fmean(math.log(value) for value in serial_speedups)
        ),
        "A398_epoch_quantiles": quantiles(epochs),
        "A396_to_A398_epoch_ratio_quantiles": quantiles(old_ratios),
        "A388_serial_to_A398_speedup_quantiles": quantiles(serial_speedups),
    }
    if (
        proof["complete_cover_cells"] != CELLS
        or proof["duplicate_cells"] != 0
        or proof["uncovered_cells"] != 0
        or proof["makespan_epochs"] != OPTIMAL_EPOCHS
        or not proof["makespan_optimal"]
        or set(work["worker_task_counts"].values()) != {OPTIMAL_EPOCHS}
    ):
        raise RuntimeError("A398 complete optimal-makespan proof failed")
    return proof, per_cell


def freeze_implementation() -> dict[str, Any]:
    if any(path.exists() for path in (IMPLEMENTATION, RESULT, CAUSAL, REPORT)):
        raise FileExistsError("A398 implementation or result already exists")
    design = load_design()
    orders, metadata = load_source_orders()
    if not TEST.exists() or not REPRO.exists():
        raise FileNotFoundError("A398 test and reproducer must precede freeze")
    payload: dict[str, Any] = {
        "schema": "chacha20-round20-w50-dual-direct12-eight-reader-a398-implementation-v1",
        "attempt_id": ATTEMPT_ID,
        "commitment_state": "frozen_before_A398_owner_partition_schedule_or_candidate_execution",
        "design_sha256": DESIGN_SHA256,
        "source_contract": design["source_contract"],
        "worker_contract": design["worker_contract"],
        "source_order_uint16be_sha256": {
            role: uint16be_sha256(orders[role]) for role in SOURCE_ROLES
        },
        "triple_score_field_sha256": metadata["triple_score_field_sha256"],
        "pair_triple_diversity": metadata["pair_triple_diversity"],
        "A388_measurement_sha256": metadata["A388_measurement_sha256"],
        "A398_candidate_assignments_available_at_freeze": 0,
        "anchors": {
            "design": anchor(DESIGN, DESIGN_SHA256),
            "A396_runner": anchor(A396_RUNNER, A396_RUNNER_SHA256),
            "A388_runner": anchor(A388_RUNNER, A388_RUNNER_SHA256),
            "A396_result": anchor(A396_RESULT, A396_RESULT_SHA256),
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
        raise RuntimeError("A398 implementation hash differs")
    value = json.loads(IMPLEMENTATION.read_bytes())
    if (
        value.get("schema")
        != "chacha20-round20-w50-dual-direct12-eight-reader-a398-implementation-v1"
        or value.get("attempt_id") != ATTEMPT_ID
        or value.get("design_sha256") != DESIGN_SHA256
        or set(value.get("source_order_uint16be_sha256", {})) != set(SOURCE_ROLES)
        or len(value.get("source_order_uint16be_sha256", {})) != len(SOURCE_ROLES)
        or value.get("A398_candidate_assignments_available_at_freeze") != 0
    ):
        raise RuntimeError("A398 implementation semantics differ")
    for ref in value["anchors"].values():
        anchor(ROOT / ref["path"], ref["sha256"])
    return value


def build_causal(payload: Mapping[str, Any]) -> dict[str, Any]:
    sys.path.insert(0, str(DOTCAUSAL_SRC))
    from dotcausal.io import CausalReader, CausalWriter

    sources = "A398:eight_frozen_assignment_blind_reader_orders"
    lanes = "A398:eight_minimum_rank_owner_queues"
    theorem = "A398:optimal_512_epoch_eight_reader_schedule"
    ready = "A399:eight_worker_dual_Direct12_executor_ready"
    writer = CausalWriter(api_id="a398w50")
    writer._rules = []
    writer.add_rule(
        name="frozen_pair_triple_to_eight_reader_set",
        description="The known-key-selected pair and triple readouts reuse the same complete W50 Direct12 measurements beside six frozen primitive readers.",
        pattern=["A396_six_primitive_orders", "A388_pair_order", "A398_triple_order"],
        conclusion="A398_eight_frozen_assignment_blind_reader_orders",
        confidence_modifier=1.0,
    )
    writer.add_rule(
        name="eight_readers_to_minimum_rank_owner_queues",
        description="Every cell is assigned exactly once to its minimum-rank source and each owner queue preserves that source order.",
        pattern=["A398_eight_frozen_assignment_blind_reader_orders"],
        conclusion="A398_eight_minimum_rank_owner_queues",
        confidence_modifier=1.0,
    )
    writer.add_rule(
        name="owner_queues_to_optimal_equal_worker_schedule",
        description="Eight home workers consume or order-preservingly steal all 4,096 groups in the theoretical minimum 512 epochs.",
        pattern=["A398_eight_minimum_rank_owner_queues"],
        conclusion="A398_optimal_512_epoch_eight_reader_schedule",
        confidence_modifier=1.0,
    )
    writer.add_rule(
        name="static_lists_to_dual_reader_executor",
        description="Eight hash-bound lists are directly executable through the already qualified complete-group engine and shared confirmation stop.",
        pattern=["A398_optimal_512_epoch_eight_reader_schedule"],
        conclusion="A399_eight_worker_dual_Direct12_executor_ready",
        confidence_modifier=1.0,
    )
    writer.add_triplet(
        trigger="A396:six_primitive_orders_plus_A388:pair_plus_A342:frozen_triple",
        mechanism="zero_refit_dual_Direct12_readout_from_one_complete_W50_measurement_field",
        outcome=sources,
        confidence=1.0,
        source=payload["source_commitment_sha256"],
        quantification=json.dumps(payload["source_order_uint16be_sha256"], sort_keys=True),
        evidence="zero new solver stages, target labels, refits, candidates or recovery feedback",
        domain="full-round ChaCha20 W50 multi-Reader portfolio",
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
        domain="eight-Reader owner partition",
        quality_score=1.0,
    )
    writer.add_triplet(
        trigger=lanes,
        mechanism="eight_home_worker_order_preserving_longest_remaining_stealing",
        outcome=theorem,
        confidence=1.0,
        source=payload["measurement_sha256"],
        quantification=json.dumps(payload["proof"], sort_keys=True),
        evidence="512 optimal epochs with exact depth and total-work bounds",
        domain="exact eight-worker scheduling theorem",
        quality_score=1.0,
    )
    writer.add_triplet(
        trigger="A396:six_primitive_orders_plus_A388:pair_plus_A342:frozen_triple",
        mechanism="materialized_dual_reader_partition_schedule_chain",
        outcome=ready,
        confidence=1.0,
        source="materialized:A398_dual_Direct12_eight_worker_chain",
        quantification="exact retained closure",
        evidence=payload["evidence_stage"],
        domain="AI-native retained inference",
        quality_score=1.0,
        is_inferred=True,
    )
    writer.add_cluster(
        name="A398 dual-Direct12 eight-Reader scheduler",
        entities=[sources, lanes, theorem, ready],
    )
    writer.add_gap(
        subject=ready,
        predicate="next_required_object",
        expected_object_type="complete_group_shared_stop_execution_of_A398_static_worker_lists",
        confidence=1.0,
        suggested_queries=[
            "Execute A398's eight static lists with complete W50 groups, matched control and dual confirmation."
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
        reader.api_id != "a398w50"
        or len(explicit) != 3
        or len(all_rows) != 4
        or len(inferred) != 1
        or len(reader._rules) != 4
        or len(reader._clusters) != 1
        or len(reader._gaps) != 1
    ):
        raise RuntimeError("A398 authentic Causal reopen gate failed")
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
        raise FileExistsError("A398 result artifact already exists")
    implementation = load_implementation(expected_implementation_sha256)
    orders, metadata = load_source_orders()
    hashes = {role: uint16be_sha256(orders[role]) for role in SOURCE_ROLES}
    if hashes != implementation["source_order_uint16be_sha256"]:
        raise RuntimeError("A398 recomputed source order bytes differ from freeze")
    owners = A396.minimum_rank_owner_lanes(orders, SOURCE_ROLES, size=CELLS)
    work = balanced_equal_worker_schedule(owners["owner_lane_orders"], SOURCE_ROLES)
    proof, per_cell = prove_schedule(owners, work, orders)
    source_commitment = canonical_sha256(
        {
            "source_role_order": list(SOURCE_ROLES),
            "source_order_uint16be_sha256": hashes,
            "triple_score_field_sha256": metadata["triple_score_field_sha256"],
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
            "worker_role_order": list(SOURCE_ROLES),
            "worker_cell_order_uint16be_sha256": work[
                "worker_cell_order_uint16be_sha256"
            ],
            "worker_task_list_sha256": work["worker_task_list_sha256"],
            "proof": proof,
        }
    )
    payload: dict[str, Any] = {
        "schema": "chacha20-round20-w50-dual-direct12-eight-reader-a398-result-v1",
        "attempt_id": ATTEMPT_ID,
        "evidence_stage": "EXACT_ASSIGNMENT_BLIND_DUAL_DIRECT12_EIGHT_READER_OPTIMAL_EIGHT_WORKER_SCHEDULER_RETAINED",
        "design_sha256": DESIGN_SHA256,
        "implementation_sha256": expected_implementation_sha256,
        "implementation_commitment_sha256": implementation[
            "implementation_commitment_sha256"
        ],
        "source_role_order": list(SOURCE_ROLES),
        "worker_role_order": list(SOURCE_ROLES),
        "source_order_uint16be_sha256": hashes,
        "triple_score_field_sha256": metadata["triple_score_field_sha256"],
        "pair_triple_diversity": metadata["pair_triple_diversity"],
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
        "new_solver_stages": 0,
        "progress_or_filter_outcomes_consumed": 0,
        "W50_triple_order_or_schedule_seen_before_design_freeze": False,
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
    atomic_bytes(
        REPORT,
        (
            "# A398 — dual-Direct12 eight-Reader/eight-worker W50 scheduler\n\n"
            f"Evidence stage: **{payload['evidence_stage']}**\n\n"
            f"- Pair/triple owner-lane sizes: **{owners['owner_lane_sizes'][ROLE_PAIR]} / {owners['owner_lane_sizes'][ROLE_TRIPLE]}**\n"
            f"- Complete owner-lane sizes: **{owners['owner_lane_sizes']}**\n"
            f"- Worker task counts: **{work['worker_task_counts']}**\n"
            f"- Makespan / theoretical minimum: **{proof['makespan_epochs']} / {proof['theoretical_minimum_epochs']} epochs**\n"
            f"- Earlier / equal / later than A396: **{proof['A398_strictly_faster_than_A396_cells']} / {proof['A398_equal_to_A396_cells']} / {proof['A398_slower_than_A396_cells']}**\n"
            f"- Geometric A396-to-A398 epoch ratio: **{proof['geometric_mean_A396_to_A398_epoch_ratio']:.9f}x**\n"
            f"- Geometric A388-serial-to-A398 speedup: **{proof['geometric_mean_A388_serial_to_A398_epoch_speedup']:.9f}x**\n"
            "- Duplicate / uncovered prefixes: **0 / 0**\n"
            "- Depth / total-work / owner-order violations: **0 / 0 / 0**\n"
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
        payload = materialize(
            expected_implementation_sha256=args.expected_implementation_sha256
        )
    else:
        payload = analyze()
    print(json.dumps(payload, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()

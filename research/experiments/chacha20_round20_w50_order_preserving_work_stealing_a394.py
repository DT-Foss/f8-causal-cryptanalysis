#!/usr/bin/env python3
"""A394: balance A392 lanes by exact order-preserving work stealing."""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import inspect
import json
import math
import os
import statistics
import struct
import sys
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

ROOT = Path(__file__).parents[2]
RESEARCH = ROOT / "research"
CONFIGS = RESEARCH / "configs"
RESULTS = RESEARCH / "results/v1"

DESIGN = CONFIGS / "chacha20_round20_w50_order_preserving_work_stealing_a394_design_v1.json"
IMPLEMENTATION = (
    CONFIGS
    / "chacha20_round20_w50_order_preserving_work_stealing_a394_implementation_v1.json"
)
RESULT = RESULTS / "chacha20_round20_w50_order_preserving_work_stealing_a394_v1.json"
CAUSAL = RESULT.with_suffix(".causal")
REPORT = RESULT.with_suffix(".md")
TEST = ROOT / "tests/test_chacha20_round20_w50_order_preserving_work_stealing_a394.py"
REPRO = ROOT / "scripts/reproduce_chacha20_round20_w50_order_preserving_work_stealing_a394.sh"

A393_RUNNER = (
    RESEARCH / "experiments/chacha20_round20_w50_disjoint_parallel_recovery_a393.py"
)
A392_RESULT = (
    RESULTS / "chacha20_round20_w50_disjoint_parallel_reader_scheduler_a392_v1.json"
)
A392_CAUSAL = A392_RESULT.with_suffix(".causal")
A393_PROTOCOL = CONFIGS / "chacha20_round20_w50_disjoint_parallel_recovery_a393_v1.json"

ATTEMPT_ID = "A394"
DESIGN_SHA256 = "946ec44c302f1768bb4ffc3895e1841396f8b258b119ca5566e6a156c652f2d6"
A393_RUNNER_SHA256 = "31c9eb2da2ab59d7e7fb1eb20a1cf04d9ff036aabd05301f082ab135541dfddc"
A392_RESULT_SHA256 = "950d6376cf05a32f2e7a2043b5662c1b33b375b567e695aaf2e4db494c1d725a"
A392_CAUSAL_SHA256 = "9482fea926e3f32235c668290410b420f27ab301a8c6cc418b192095473ab793"
A393_PROTOCOL_SHA256 = "005482f5409889561ebc96b7c6d78ca3508d66a238e597bdafd26e47f7fefe99"
SCHEDULE_NAME = "three_lane_A385_Direct12_A386"
ROLE_A385 = "A385_pretarget_six_view"
ROLE_DIRECT = "A388_W50_public_output_direct12"
ROLE_A386 = "A386_calibrated_target_blind_transfer"
ROLES = (ROLE_A385, ROLE_DIRECT, ROLE_A386)
CELLS = 4096
WORKERS = 3
OPTIMAL_EPOCHS = math.ceil(CELLS / WORKERS)
DOTCAUSAL_SRC = Path(
    "/Users/bhkmie/Documents/Forschung/O1/vendor/fabel/dotcausal_package/src"
)


def load_module(path: Path, name: str) -> Any:
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot import A394 dependency {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


A393 = load_module(A393_RUNNER, "a394_a393")
file_sha256 = A393.file_sha256
canonical_sha256 = A393.canonical_sha256
atomic_json = A393.atomic_json
atomic_bytes = A393.atomic_bytes
relative = A393.relative
path_from_ref = A393.path_from_ref
anchor = A393.anchor


def uint16be_sha256(values: Sequence[int]) -> str:
    payload = b"".join(struct.pack(">H", int(value)) for value in values)
    return hashlib.sha256(payload).hexdigest()


def quantiles(values: Sequence[float]) -> dict[str, float]:
    ordered = sorted(float(value) for value in values)
    if not ordered:
        raise ValueError("A394 quantiles require values")

    def pick(q: float) -> float:
        return ordered[round(q * (len(ordered) - 1))]

    return {
        "minimum": ordered[0],
        "p25": pick(0.25),
        "median": pick(0.5),
        "p75": pick(0.75),
        "p90": pick(0.9),
        "p99": pick(0.99),
        "maximum": ordered[-1],
    }


def order_preserving_work_stealing(
    owner_lanes: Mapping[str, Sequence[int]],
    role_order: Sequence[str],
) -> dict[str, Any]:
    roles = tuple(str(role) for role in role_order)
    if not roles or set(roles) != set(owner_lanes) or len(roles) != len(set(roles)):
        raise ValueError("A394 work-stealing role contract differs")
    lanes = {role: [int(cell) for cell in owner_lanes[role]] for role in roles}
    flattened = [cell for role in roles for cell in lanes[role]]
    size = len(flattened)
    if (
        len(set(flattened)) != size
        or set(flattened) != set(range(size))
        or any(len(set(lanes[role])) != len(lanes[role]) for role in roles)
    ):
        raise ValueError("A394 owner lanes are not one exact disjoint cover")
    role_index = {role: index for index, role in enumerate(roles)}
    pointers = {role: 0 for role in roles}
    worker_tasks: dict[str, list[dict[str, Any]]] = {role: [] for role in roles}
    claimed: list[int] = []
    cell_epoch = [0] * size
    cell_worker = [""] * size
    cell_owner = [""] * size
    epoch = 0
    while len(claimed) < size:
        epoch += 1
        for worker in roles:
            if len(claimed) == size:
                break
            if pointers[worker] < len(lanes[worker]):
                donor = worker
            else:
                remaining = {
                    role: len(lanes[role]) - pointers[role] for role in roles
                }
                donor = max(
                    roles,
                    key=lambda role: (remaining[role], -role_index[role]),
                )
                if remaining[donor] <= 0:
                    raise RuntimeError("A394 work-conserving donor selection failed")
            owner_position = pointers[donor] + 1
            cell = lanes[donor][pointers[donor]]
            pointers[donor] += 1
            worker_step = len(worker_tasks[worker]) + 1
            task = {
                "cell": cell,
                "epoch": epoch,
                "worker_role": worker,
                "worker_step_one_based": worker_step,
                "owner_queue_role": donor,
                "owner_queue_position_one_based": owner_position,
                "stolen": donor != worker,
            }
            worker_tasks[worker].append(task)
            claimed.append(cell)
            cell_epoch[cell] = epoch
            cell_worker[cell] = worker
            cell_owner[cell] = donor
    if len(claimed) != size or len(set(claimed)) != size:
        raise RuntimeError("A394 claimed cover differs")
    for owner in roles:
        observed = [
            task["cell"]
            for epoch_value in range(1, epoch + 1)
            for worker in roles
            for task in worker_tasks[worker]
            if task["epoch"] == epoch_value and task["owner_queue_role"] == owner
        ]
        if observed != lanes[owner]:
            raise RuntimeError(f"A394 {owner} queue order was not preserved")
    return {
        "role_order": list(roles),
        "cells": size,
        "workers": len(roles),
        "epochs": epoch,
        "theoretical_minimum_epochs": math.ceil(size / len(roles)),
        "worker_tasks": worker_tasks,
        "worker_cell_orders": {
            worker: [task["cell"] for task in worker_tasks[worker]]
            for worker in roles
        },
        "worker_cell_order_uint16be_sha256": {
            worker: uint16be_sha256(
                [task["cell"] for task in worker_tasks[worker]]
            )
            for worker in roles
        },
        "worker_owner_role_vector_sha256": {
            worker: hashlib.sha256(
                bytes(role_index[task["owner_queue_role"]] for task in worker_tasks[worker])
            ).hexdigest()
            for worker in roles
        },
        "worker_task_counts": {
            worker: len(worker_tasks[worker]) for worker in roles
        },
        "worker_stolen_task_counts": {
            worker: sum(task["stolen"] for task in worker_tasks[worker])
            for worker in roles
        },
        "cell_epoch_one_based": cell_epoch,
        "cell_worker_role": cell_worker,
        "cell_owner_queue_role": cell_owner,
        "complete_cover_cells": len(claimed),
        "duplicate_cells": len(claimed) - len(set(claimed)),
        "uncovered_cells": size - len(set(claimed)),
    }


def prove_schedule(
    work: Mapping[str, Any], source: Mapping[str, Any]
) -> dict[str, Any]:
    fixed = source["schedules"][SCHEDULE_NAME]
    per_cell = fixed["per_cell_proof"]
    epochs = [int(value) for value in work["cell_epoch_one_based"]]
    depth_ratios: list[float] = []
    serial_speedups: list[float] = []
    fixed_speedups: list[float] = []
    work_ratios: list[float] = []
    strict_vs_serial = 0
    strict_vs_fixed = 0
    for cell, epoch in enumerate(epochs):
        row = per_cell[cell]
        if int(row["cell"]) != cell:
            raise RuntimeError("A394 A392 cell proof order differs")
        owner_depth = int(row["owner_lane_depth_one_based"])
        best_rank = int(row["best_source_rank_one_based"])
        serial_rank = int(row["serial_wavefront_rank_one_based"])
        total_work = min(WORKERS * epoch, CELLS)
        if epoch > owner_depth or owner_depth > best_rank:
            raise RuntimeError("A394 best-reader depth theorem failed")
        if total_work > WORKERS * best_rank:
            raise RuntimeError("A394 total-work theorem failed")
        depth_ratios.append(epoch / best_rank)
        serial_speedups.append(serial_rank / epoch)
        fixed_speedups.append(owner_depth / epoch)
        work_ratios.append(total_work / (WORKERS * best_rank))
        strict_vs_serial += serial_rank > epoch
        strict_vs_fixed += owner_depth > epoch
    return {
        "cells_checked": CELLS,
        "complete_cover_cells": work["complete_cover_cells"],
        "duplicate_cells": work["duplicate_cells"],
        "uncovered_cells": work["uncovered_cells"],
        "owner_queue_order_preservation_violations": 0,
        "depth_bound": "D_A394(c) <= D_A392_owner(c) <= min_i R_i(c)",
        "depth_bound_violations": 0,
        "maximum_depth_to_best_source_ratio": max(depth_ratios),
        "total_work_bound": "W_A394(c) <= 3*min_i R_i(c)",
        "total_work_bound_violations": 0,
        "maximum_total_work_to_bound_ratio": max(work_ratios),
        "makespan_epochs": work["epochs"],
        "theoretical_minimum_epochs": work["theoretical_minimum_epochs"],
        "makespan_optimal": work["epochs"] == work["theoretical_minimum_epochs"],
        "cells_strictly_faster_than_A388_serial_wavefront": strict_vs_serial,
        "cells_strictly_faster_than_A392_fixed_owner_lanes": strict_vs_fixed,
        "geometric_mean_A388_serial_to_A394_epoch_speedup": math.exp(
            statistics.fmean(math.log(value) for value in serial_speedups)
        ),
        "geometric_mean_A392_fixed_to_A394_epoch_speedup": math.exp(
            statistics.fmean(math.log(value) for value in fixed_speedups)
        ),
        "A394_epoch_quantiles": quantiles(epochs),
        "A388_serial_to_A394_speedup_quantiles": quantiles(serial_speedups),
        "A392_fixed_to_A394_speedup_quantiles": quantiles(fixed_speedups),
    }


def load_design() -> dict[str, Any]:
    if file_sha256(DESIGN) != DESIGN_SHA256:
        raise RuntimeError("A394 design hash differs")
    value = json.loads(DESIGN.read_bytes())
    scheduler = value.get("scheduler_contract", {})
    boundary = value.get("information_boundary", {})
    if (
        value.get("schema")
        != "chacha20-round20-w50-order-preserving-work-stealing-a394-design-v1"
        or value.get("attempt_id") != ATTEMPT_ID
        or value.get("design_state")
        != "frozen_after_A392_exact_owner_lanes_before_any_A394_schedule_or_candidate_execution"
        or scheduler.get("workers") != WORKERS
        or scheduler.get("cells") != CELLS
        or tuple(scheduler.get("home_role_order", [])) != ROLES
        or scheduler.get("target_makespan_epochs") != OPTIMAL_EPOCHS
        or scheduler.get("theoretical_minimum_epochs") != OPTIMAL_EPOCHS
        or scheduler.get("zero_duplicate_prefixes") is not True
        or scheduler.get("complete_cover") is not True
        or scheduler.get("preserve_each_owner_queue_order") is not True
        or boundary.get("target_labels_used") != 0
        or boundary.get("reader_refits") != 0
        or boundary.get("candidate_assignments_executed") != 0
        or boundary.get("A393_or_other_recovery_progress_filter_outcomes_consumed")
        is not False
    ):
        raise RuntimeError("A394 frozen design semantics differ")
    for name, source_path in value["source_anchors"].items():
        if name.endswith("_path"):
            stem = name.removesuffix("_path")
            anchor(ROOT / source_path, value["source_anchors"][f"{stem}_sha256"])
    return value


def load_a392() -> tuple[dict[str, Any], dict[str, list[int]]]:
    anchor(A392_RESULT, A392_RESULT_SHA256)
    anchor(A392_CAUSAL, A392_CAUSAL_SHA256)
    value = json.loads(A392_RESULT.read_bytes())
    schedule = value.get("schedules", {}).get(SCHEDULE_NAME, {})
    raw = schedule.get("lane_orders", {})
    if (
        value.get("schema")
        != "chacha20-round20-w50-disjoint-parallel-reader-scheduler-a392-result-v1"
        or tuple(schedule.get("role_order", [])) != ROLES
        or schedule.get("proof", {}).get("duplicate_cells") != 0
        or schedule.get("proof", {}).get("uncovered_cells") != 0
        or set(raw) != set(ROLES)
        or value.get("candidate_assignments_executed") != 0
    ):
        raise RuntimeError("A394 A392 source semantics differ")
    lanes = {role: [int(cell) for cell in raw[role]] for role in ROLES}
    return value, lanes


def freeze_implementation() -> dict[str, Any]:
    if any(path.exists() for path in (IMPLEMENTATION, RESULT, CAUSAL, REPORT)):
        raise FileExistsError("A394 implementation or result already exists")
    design = load_design()
    source, lanes = load_a392()
    if not TEST.exists() or not REPRO.exists():
        raise FileNotFoundError("A394 test and reproducer must precede freeze")
    payload: dict[str, Any] = {
        "schema": "chacha20-round20-w50-order-preserving-work-stealing-a394-implementation-v1",
        "attempt_id": ATTEMPT_ID,
        "commitment_state": "frozen_before_A394_schedule_or_candidate_execution",
        "design_sha256": DESIGN_SHA256,
        "scheduler_contract": design["scheduler_contract"],
        "A392_schedule_commitment_sha256": source[
            "schedule_commitment_sha256"
        ],
        "A392_lane_order_uint16be_sha256": {
            role: uint16be_sha256(lanes[role]) for role in ROLES
        },
        "A394_candidate_assignments_available_at_freeze": 0,
        "anchors": {
            "design": anchor(DESIGN, DESIGN_SHA256),
            "A393_runner": anchor(A393_RUNNER, A393_RUNNER_SHA256),
            "A392_result": anchor(A392_RESULT, A392_RESULT_SHA256),
            "A392_causal": anchor(A392_CAUSAL, A392_CAUSAL_SHA256),
            "A393_protocol": anchor(A393_PROTOCOL, A393_PROTOCOL_SHA256),
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
        raise RuntimeError("A394 implementation hash differs")
    value = json.loads(IMPLEMENTATION.read_bytes())
    if (
        value.get("schema")
        != "chacha20-round20-w50-order-preserving-work-stealing-a394-implementation-v1"
        or value.get("attempt_id") != ATTEMPT_ID
        or value.get("design_sha256") != DESIGN_SHA256
        or value.get("A394_candidate_assignments_available_at_freeze") != 0
    ):
        raise RuntimeError("A394 implementation semantics differ")
    for row in value["anchors"].values():
        anchor(path_from_ref(row["path"]), row["sha256"])
    unsigned = {
        key: item
        for key, item in value.items()
        if key != "implementation_commitment_sha256"
    }
    if value.get("implementation_commitment_sha256") != canonical_sha256(unsigned):
        raise RuntimeError("A394 implementation commitment differs")
    return value


def build_causal(payload: Mapping[str, Any]) -> dict[str, Any]:
    sys.path.insert(0, str(DOTCAUSAL_SRC))
    from dotcausal.io import CausalReader, CausalWriter

    scheduler = "A394:order_preserving_work_stealing_schedule"
    theorem = "A394:optimal_makespan_best_reader_depth_theorem"
    ready = "A395:work_stealing_W50_executor_ready"
    writer = CausalWriter(api_id="a394w50")
    writer._rules = []
    writer.add_rule(
        name="imbalanced_owner_lanes_to_order_preserving_stealing",
        description="Workers retain their home queues and, only after exhaustion, claim the next item from the longest remaining owner queue.",
        pattern=["A392_exact_disjoint_owner_lanes"],
        conclusion="A394_order_preserving_work_stealing_schedule",
        confidence_modifier=1.0,
    )
    writer.add_rule(
        name="order_preservation_to_optimal_makespan_and_bounds",
        description="The work-conserving schedule reaches ceil(4096/3) epochs without delaying any owner-queue item beyond its original local rank.",
        pattern=["A394_order_preserving_work_stealing_schedule"],
        conclusion="A394_optimal_makespan_best_reader_depth_theorem",
        confidence_modifier=1.0,
    )
    writer.add_rule(
        name="frozen_worker_schedules_to_executor",
        description="Three static worker task lists reproduce the work-stealing epochs without a runtime claim race and are ready for a shared-stop W50 executor.",
        pattern=["A394_optimal_makespan_best_reader_depth_theorem"],
        conclusion="A395_work_stealing_W50_executor_ready",
        confidence_modifier=1.0,
    )
    writer.add_triplet(
        trigger="A392:exact_disjoint_owner_lanes",
        mechanism="deterministic_home_first_longest_remaining_work_stealing",
        outcome=scheduler,
        confidence=1.0,
        source=payload["schedule_commitment_sha256"],
        quantification=json.dumps(payload["worker_task_counts"], sort_keys=True),
        evidence=json.dumps(payload["worker_stolen_task_counts"], sort_keys=True),
        domain="target-blind full-round ChaCha20 W50 load balancing",
        quality_score=1.0,
    )
    writer.add_triplet(
        trigger=scheduler,
        mechanism="complete_4096_cell_epoch_depth_and_total_work_proof",
        outcome=theorem,
        confidence=1.0,
        source=payload["measurement_sha256"],
        quantification=json.dumps(payload["proof"], sort_keys=True),
        evidence="zero depth, total-work, queue-order, duplicate or coverage violations",
        domain="exact multi-operator work-stealing theorem",
        quality_score=1.0,
    )
    writer.add_triplet(
        trigger="A392:exact_disjoint_owner_lanes",
        mechanism="materialized_work_stealing_schedule_and_theorem_chain",
        outcome=ready,
        confidence=1.0,
        source="materialized:A394_work_stealing_chain",
        quantification="exact retained closure",
        evidence=payload["evidence_stage"],
        domain="AI-native retained inference",
        quality_score=1.0,
        is_inferred=True,
    )
    writer.add_cluster(
        name="A394 order-preserving work-stealing scheduler",
        entities=["A392:exact_disjoint_owner_lanes", scheduler, theorem, ready],
    )
    writer.add_gap(
        subject=ready,
        predicate="next_required_object",
        expected_object_type="complete_group_shared_stop_execution_of_three_static_worker_lists",
        confidence=1.0,
        suggested_queries=[
            "Execute the three balanced static A394 worker lists with complete W50 groups and one shared independently confirmed stop."
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
        reader.api_id != "a394w50"
        or len(explicit) != 2
        or len(all_rows) != 3
        or len(inferred) != 1
        or len(reader._rules) != 3
        or len(reader._clusters) != 1
        or len(reader._gaps) != 1
    ):
        raise RuntimeError("A394 authentic Causal reopen gate failed")
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
            "schedule_relation": explicit[0],
            "theorem_relation": explicit[1],
            "terminal_chain": all_rows[-1],
            "next_gap": reader._gaps[0],
        },
    }


def materialize(*, expected_implementation_sha256: str) -> dict[str, Any]:
    if any(path.exists() for path in (RESULT, CAUSAL, REPORT)):
        raise FileExistsError("A394 result artifact already exists")
    implementation = load_implementation(expected_implementation_sha256)
    source, lanes = load_a392()
    work = order_preserving_work_stealing(lanes, ROLES)
    proof = prove_schedule(work, source)
    essential = {
        "role_order": work["role_order"],
        "epochs": work["epochs"],
        "worker_cell_order_uint16be_sha256": work[
            "worker_cell_order_uint16be_sha256"
        ],
        "worker_owner_role_vector_sha256": work[
            "worker_owner_role_vector_sha256"
        ],
        "proof": proof,
    }
    payload: dict[str, Any] = {
        "schema": "chacha20-round20-w50-order-preserving-work-stealing-a394-result-v1",
        "attempt_id": ATTEMPT_ID,
        "evidence_stage": "EXACT_TARGET_BLIND_ORDER_PRESERVING_OPTIMAL_MAKESPAN_WORK_STEALING_RETAINED",
        "design_sha256": DESIGN_SHA256,
        "implementation_sha256": expected_implementation_sha256,
        "implementation_commitment_sha256": implementation[
            "implementation_commitment_sha256"
        ],
        "A392_result_sha256": A392_RESULT_SHA256,
        "A392_schedule_commitment_sha256": source[
            "schedule_commitment_sha256"
        ],
        "role_order": work["role_order"],
        "worker_tasks": work["worker_tasks"],
        "worker_cell_orders": work["worker_cell_orders"],
        "worker_cell_order_uint16be_sha256": work[
            "worker_cell_order_uint16be_sha256"
        ],
        "worker_owner_role_vector_sha256": work[
            "worker_owner_role_vector_sha256"
        ],
        "worker_task_counts": work["worker_task_counts"],
        "worker_stolen_task_counts": work["worker_stolen_task_counts"],
        "cell_epoch_one_based": work["cell_epoch_one_based"],
        "cell_worker_role": work["cell_worker_role"],
        "cell_owner_queue_role": work["cell_owner_queue_role"],
        "proof": proof,
        "candidate_assignments_executed": 0,
        "target_labels_used": 0,
        "reader_refits": 0,
        "progress_or_filter_outcomes_consumed": 0,
        "anchors": implementation["anchors"],
    }
    payload["schedule_commitment_sha256"] = canonical_sha256(essential)
    payload["measurement_sha256"] = canonical_sha256(
        {
            "schedule_commitment_sha256": payload["schedule_commitment_sha256"],
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
            "# A394 — exact order-preserving W50 work stealing\n\n"
            f"Evidence stage: **{payload['evidence_stage']}**\n\n"
            f"- Worker task counts: **{work['worker_task_counts']}**\n"
            f"- Stolen task counts: **{work['worker_stolen_task_counts']}**\n"
            f"- Makespan: **{proof['makespan_epochs']} epochs**\n"
            f"- Theoretical minimum: **{proof['theoretical_minimum_epochs']} epochs**\n"
            f"- Geometric speedup over serial A388: **{proof['geometric_mean_A388_serial_to_A394_epoch_speedup']:.9f}x**\n"
            f"- Extra geometric speedup over fixed A392 lanes: **{proof['geometric_mean_A392_fixed_to_A394_epoch_speedup']:.9f}x**\n"
            "- Duplicate / uncovered prefixes: **0 / 0**\n"
            "- Depth / total-work / queue-order violations: **0 / 0 / 0**\n"
            "- Candidate assignments / target labels / refits: **0 / 0 / 0**\n"
            "- Authentic AI-native Causal readback: **2 explicit + 1 inferred chain**\n"
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

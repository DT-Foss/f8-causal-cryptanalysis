#!/usr/bin/env python3
"""A399: execute A398's eight exact dual-Direct12 W50 worker lists."""

from __future__ import annotations

import argparse
import importlib.util
import inspect
import json
import math
import os
import sys
import time
from collections.abc import Callable, Mapping, Sequence
from pathlib import Path
from typing import Any

import numpy as np

ROOT = Path(__file__).parents[2]
RESEARCH = ROOT / "research"
CONFIGS = RESEARCH / "configs"
RESULTS = RESEARCH / "results/v1"

DESIGN = (
    CONFIGS / "chacha20_round20_w50_dual_direct12_eight_worker_recovery_a399_design_v1.json"
)
IMPLEMENTATION = (
    CONFIGS
    / "chacha20_round20_w50_dual_direct12_eight_worker_recovery_a399_implementation_v1.json"
)
PROTOCOL = (
    CONFIGS / "chacha20_round20_w50_dual_direct12_eight_worker_recovery_a399_v1.json"
)
RESULT = RESULTS / "chacha20_round20_w50_dual_direct12_eight_worker_recovery_a399_v1.json"
CAUSAL = RESULT.with_suffix(".causal")
REPORT = RESULT.with_suffix(".md")
TEST = ROOT / "tests/test_chacha20_round20_w50_dual_direct12_eight_worker_recovery_a399.py"
REPRO = ROOT / "scripts/reproduce_chacha20_round20_w50_dual_direct12_eight_worker_recovery_a399.sh"

A397_RUNNER = (
    RESEARCH / "experiments/chacha20_round20_w50_expanded_eight_worker_recovery_a397.py"
)
A397_PROTOCOL = (
    CONFIGS / "chacha20_round20_w50_expanded_eight_worker_recovery_a397_v1.json"
)
A398_RESULT = RESULTS / "chacha20_round20_w50_dual_direct12_eight_reader_a398_v1.json"
A398_CAUSAL = A398_RESULT.with_suffix(".causal")

ATTEMPT_ID = "A399"
DESIGN_SHA256 = "34c16528dd0abe1c289259295a8b8bff9596d829ef68e6135d703565a232960a"
A397_RUNNER_SHA256 = "099bc92d9b91228ff1563c251ba47a6d4101da48a3dc193cf57a4e4be2f2e8c5"
A397_PROTOCOL_SHA256 = "447baf5e4784d0210f51e194f1a241b7fbfbf1ab239fe16582effdb4b435fb32"
A398_RESULT_SHA256 = "fe37839fe18e71166a5d727cb14be96eca53bb6cce2cc3824f5bc4bd885dfd42"
A398_CAUSAL_SHA256 = "50d7f00989a4aa7288ef41e4a720b7f500d5d3ce4d966a65d445642d69b5d071"

ROLES = (
    "A379_target_free",
    "A380_target_conditioned",
    "wide_vote",
    "sparse_reciprocal",
    "broad_quantile",
    "broad_intersection",
    "A388_W50_public_output_direct12_pair",
    "A398_W50_public_output_direct12_triple",
)
SLUG_TO_ROLE = {
    "a379": ROLES[0],
    "a380": ROLES[1],
    "wide": ROLES[2],
    "sparse": ROLES[3],
    "quantile": ROLES[4],
    "intersection": ROLES[5],
    "pair": ROLES[6],
    "triple": ROLES[7],
}
ROLE_TO_SLUG = {role: slug for slug, role in SLUG_TO_ROLE.items()}
EXPECTED_WORKER_TASKS = {role: 512 for role in ROLES}
CELLS = 4096
WORKERS = 8
STATIC_EPOCHS = 512
GROUP_SIZE = 1 << 38
DOMAIN_SIZE = 1 << 50
WORD0_SUFFIX_BITS = 20
HOST_REFRESH_GROUPS = 8
DOTCAUSAL_SRC = Path(
    "/Users/bhkmie/Documents/Forschung/O1/vendor/fabel/dotcausal_package/src"
)


def load_module(path: Path, name: str) -> Any:
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot import A399 dependency {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


A397 = load_module(A397_RUNNER, "a399_a397")
file_sha256 = A397.file_sha256
canonical_sha256 = A397.canonical_sha256
atomic_json = A397.atomic_json
atomic_bytes = A397.atomic_bytes
relative = A397.relative
path_from_ref = A397.path_from_ref
anchor = A397.anchor


def progress_path(worker: str) -> Path:
    if worker not in ROLE_TO_SLUG:
        raise ValueError(f"A399 unknown worker role {worker}")
    return RESULTS / (
        "chacha20_round20_w50_dual_direct12_eight_worker_recovery_"
        f"a399_{ROLE_TO_SLUG[worker]}_progress_v1.json"
    )


def worker_order_sha256(values: Sequence[int]) -> str:
    return A397.A395.A393.lane_sha256([int(value) for value in values])


def task_list_sha256(values: Sequence[Mapping[str, Any]]) -> str:
    return canonical_sha256([dict(value) for value in values])


def exact_worker_schedule(
    values: Sequence[int], tasks: Sequence[Mapping[str, Any]], worker: str
) -> tuple[list[int], list[dict[str, Any]]]:
    if worker not in EXPECTED_WORKER_TASKS:
        raise ValueError(f"A399 unknown worker {worker}")
    order = [int(value) for value in values]
    rows = [dict(value) for value in tasks]
    expected = EXPECTED_WORKER_TASKS[worker]
    if (
        len(order) != expected
        or len(rows) != expected
        or len(set(order)) != expected
        or any(not 0 <= cell < CELLS for cell in order)
    ):
        raise ValueError(f"A399 {worker} schedule geometry differs")
    for index, (cell, row) in enumerate(zip(order, rows, strict=True), 1):
        owner = row.get("owner_queue_role")
        if (
            int(row.get("cell", -1)) != cell
            or int(row.get("epoch", -1)) != index
            or row.get("worker_role") != worker
            or int(row.get("worker_step_one_based", -1)) != index
            or owner not in ROLES
            or int(row.get("owner_queue_position_one_based", 0)) < 1
            or row.get("stolen") is not (owner != worker)
        ):
            raise ValueError(f"A399 {worker} task semantics differ at step {index}")
    return order, rows


def load_design() -> dict[str, Any]:
    if file_sha256(DESIGN) != DESIGN_SHA256:
        raise RuntimeError("A399 design hash differs")
    value = json.loads(DESIGN.read_bytes())
    contract = value.get("execution_contract", {})
    launch = value.get("launch_contract", {})
    boundary = value.get("information_boundary", {})
    if (
        value.get("schema")
        != "chacha20-round20-w50-dual-direct12-eight-worker-recovery-a399-design-v1"
        or value.get("attempt_id") != ATTEMPT_ID
        or value.get("design_state")
        != "frozen_after_A398_exact_scheduler_before_any_A399_candidate_progress_or_result"
        or contract.get("workers") != WORKERS
        or contract.get("static_schedule_epochs") != STATIC_EPOCHS
        or contract.get("worker_task_counts") != EXPECTED_WORKER_TASKS
        or launch.get("first_A399_available_slot_worker") != ROLES[-1]
        or launch.get("A397_first_available_slot_contract_remains_prior") is not True
        or launch.get("live_recoveries_must_not_be_interrupted") is not True
        or boundary.get("A399_candidate_or_progress_available_at_design_freeze")
        is not False
        or boundary.get("A397_progress_filter_result_or_true_prefix_consumed")
        is not False
        or boundary.get("target_labels_used_for_schedule_construction") != 0
        or boundary.get("reader_refits") != 0
    ):
        raise RuntimeError("A399 frozen design semantics differ")
    for key, path in value["source_anchors"].items():
        if key.endswith("_path"):
            stem = key.removesuffix("_path")
            anchor(ROOT / path, value["source_anchors"][f"{stem}_sha256"])
    return value


def load_execution_base() -> dict[str, Any]:
    anchor(A397_RUNNER, A397_RUNNER_SHA256)
    anchor(A397_PROTOCOL, A397_PROTOCOL_SHA256)
    value = A397.load_protocol(A397_PROTOCOL_SHA256)
    challenge = value.get("public_challenge", {})
    if (
        challenge.get("unknown_key_bits") != 50
        or challenge.get("rounds") != 20
        or challenge.get("feedforward") is not True
        or challenge.get("unknown_assignment_included") is not False
        or value.get("public_challenge_sha256") != canonical_sha256(challenge)
    ):
        raise RuntimeError("A399 A397 execution base differs")
    return value


def load_schedule() -> tuple[
    dict[str, Any], dict[str, list[int]], dict[str, list[dict[str, Any]]]
]:
    anchor(A398_RESULT, A398_RESULT_SHA256)
    anchor(A398_CAUSAL, A398_CAUSAL_SHA256)
    value = json.loads(A398_RESULT.read_bytes())
    raw_orders = value.get("worker_cell_orders", {})
    raw_tasks = value.get("worker_tasks", {})
    proof = value.get("proof", {})
    if (
        value.get("schema")
        != "chacha20-round20-w50-dual-direct12-eight-reader-a398-result-v1"
        or value.get("candidate_assignments_executed") != 0
        or value.get("target_labels_used") != 0
        or value.get("reader_refits") != 0
        or value.get("new_solver_stages") != 0
        or value.get("progress_or_filter_outcomes_consumed") != 0
        or tuple(value.get("worker_role_order", [])) != ROLES
        or value.get("worker_task_counts") != EXPECTED_WORKER_TASKS
        or set(raw_orders) != set(ROLES)
        or set(raw_tasks) != set(ROLES)
        or proof.get("makespan_epochs") != STATIC_EPOCHS
        or proof.get("theoretical_minimum_epochs") != STATIC_EPOCHS
        or proof.get("makespan_optimal") is not True
        or proof.get("duplicate_cells") != 0
        or proof.get("uncovered_cells") != 0
        or proof.get("owner_queue_order_preservation_violations") != 0
        or proof.get("depth_bound_violations") != 0
        or proof.get("total_work_bound_violations") != 0
    ):
        raise RuntimeError("A399 A398 schedule semantics differ")
    orders: dict[str, list[int]] = {}
    tasks: dict[str, list[dict[str, Any]]] = {}
    for worker in ROLES:
        orders[worker], tasks[worker] = exact_worker_schedule(
            raw_orders[worker], raw_tasks[worker], worker
        )
        if (
            worker_order_sha256(orders[worker])
            != value["worker_cell_order_uint16be_sha256"][worker]
            or task_list_sha256(tasks[worker])
            != value["worker_task_list_sha256"][worker]
        ):
            raise RuntimeError(f"A399 {worker} schedule bytes differ")
    flattened = [cell for worker in ROLES for cell in orders[worker]]
    if len(flattened) != CELLS or set(flattened) != set(range(CELLS)):
        raise RuntimeError("A399 static worker cover differs")
    owner_positions: dict[str, list[int]] = {role: [] for role in ROLES}
    for epoch in range(1, STATIC_EPOCHS + 1):
        for worker in ROLES:
            row = tasks[worker][epoch - 1]
            cell = int(row["cell"])
            if (
                int(value["cell_epoch_one_based"][cell]) != epoch
                or value["cell_worker_role"][cell] != worker
                or value["cell_owner_queue_role"][cell]
                != row["owner_queue_role"]
                or int(value["cell_owner_queue_position_one_based"][cell])
                != int(row["owner_queue_position_one_based"])
            ):
                raise RuntimeError("A399 cell-indexed schedule differs")
            owner_positions[str(row["owner_queue_role"])].append(
                int(row["owner_queue_position_one_based"])
            )
    for owner, positions in owner_positions.items():
        if positions != list(range(1, len(positions) + 1)):
            raise RuntimeError(f"A399 {owner} owner queue order differs")
    return value, orders, tasks


def assert_pre_execution() -> None:
    if RESULT.exists() or CAUSAL.exists() or REPORT.exists():
        raise RuntimeError("A399 freeze must precede result artifacts")
    if any(progress_path(worker).exists() for worker in ROLES):
        raise RuntimeError("A399 freeze must precede every worker progress artifact")


def freeze_implementation() -> dict[str, Any]:
    if IMPLEMENTATION.exists() or PROTOCOL.exists():
        raise FileExistsError("A399 implementation or protocol already exists")
    assert_pre_execution()
    design = load_design()
    schedule, orders, tasks = load_schedule()
    base = load_execution_base()
    qualification = A397.A395.A393.A389.A385.load_a384_qualification(
        base["A384_qualification_sha256"]
    )
    if qualification["matched_control_empty"] is not True:
        raise RuntimeError("A399 W50 qualification differs")
    if not TEST.exists() or not REPRO.exists():
        raise FileNotFoundError("A399 test and reproducer must precede freeze")
    payload: dict[str, Any] = {
        "schema": "chacha20-round20-w50-dual-direct12-eight-worker-recovery-a399-implementation-v1",
        "attempt_id": ATTEMPT_ID,
        "commitment_state": "frozen_before_any_A399_candidate_progress_or_result",
        "design_sha256": DESIGN_SHA256,
        "execution_contract": design["execution_contract"],
        "launch_contract": design["launch_contract"],
        "A398_schedule_commitment_sha256": schedule["schedule_commitment_sha256"],
        "worker_order_uint16be_sha256": {
            worker: worker_order_sha256(orders[worker]) for worker in ROLES
        },
        "worker_task_list_sha256": {
            worker: task_list_sha256(tasks[worker]) for worker in ROLES
        },
        "A399_candidate_or_progress_available_at_implementation_freeze": False,
        "anchors": {
            "design": anchor(DESIGN, DESIGN_SHA256),
            "A397_runner": anchor(A397_RUNNER, A397_RUNNER_SHA256),
            "A397_protocol": anchor(A397_PROTOCOL, A397_PROTOCOL_SHA256),
            "A398_result": anchor(A398_RESULT, A398_RESULT_SHA256),
            "A398_causal": anchor(A398_CAUSAL, A398_CAUSAL_SHA256),
            "A384_qualification": anchor(
                A397.A395.A393.A389.A384_QUALIFICATION,
                base["A384_qualification_sha256"],
            ),
            "A385_protocol": anchor(
                A397.A395.A393.A389.A385_PROTOCOL,
                base["A385_protocol_sha256"],
            ),
            "runner": anchor(Path(__file__)),
            "test": anchor(TEST),
            "reproducer": anchor(REPRO),
        },
    }
    payload["implementation_commitment_sha256"] = canonical_sha256(payload)
    atomic_json(IMPLEMENTATION, payload)
    assert_pre_execution()
    return payload


def load_implementation(expected_sha256: str) -> dict[str, Any]:
    if file_sha256(IMPLEMENTATION) != expected_sha256:
        raise RuntimeError("A399 implementation hash differs")
    value = json.loads(IMPLEMENTATION.read_bytes())
    if (
        value.get("schema")
        != "chacha20-round20-w50-dual-direct12-eight-worker-recovery-a399-implementation-v1"
        or value.get("attempt_id") != ATTEMPT_ID
        or value.get("design_sha256") != DESIGN_SHA256
        or value.get("A399_candidate_or_progress_available_at_implementation_freeze")
        is not False
    ):
        raise RuntimeError("A399 implementation semantics differ")
    for row in value["anchors"].values():
        anchor(path_from_ref(row["path"]), row["sha256"])
    unsigned = {
        key: item
        for key, item in value.items()
        if key != "implementation_commitment_sha256"
    }
    if value.get("implementation_commitment_sha256") != canonical_sha256(unsigned):
        raise RuntimeError("A399 implementation commitment differs")
    return value


def freeze_protocol(*, expected_implementation_sha256: str) -> dict[str, Any]:
    if PROTOCOL.exists():
        raise FileExistsError("A399 protocol already exists")
    assert_pre_execution()
    implementation = load_implementation(expected_implementation_sha256)
    schedule, orders, tasks = load_schedule()
    base = load_execution_base()
    payload: dict[str, Any] = {
        "schema": "chacha20-round20-w50-dual-direct12-eight-worker-recovery-a399-protocol-v1",
        "attempt_id": ATTEMPT_ID,
        "protocol_state": "eight_static_A398_workers_bound_before_any_A399_candidate_progress_or_result",
        "design_sha256": DESIGN_SHA256,
        "implementation_sha256": expected_implementation_sha256,
        "implementation_commitment_sha256": implementation[
            "implementation_commitment_sha256"
        ],
        "A384_qualification_sha256": base["A384_qualification_sha256"],
        "A384_semantic_qualification_sha256": base[
            "A384_semantic_qualification_sha256"
        ],
        "A385_protocol_sha256": base["A385_protocol_sha256"],
        "A398_result_sha256": A398_RESULT_SHA256,
        "A398_schedule_commitment_sha256": schedule[
            "schedule_commitment_sha256"
        ],
        "public_challenge_sha256": base["public_challenge_sha256"],
        "public_challenge": base["public_challenge"],
        "worker_role_order": list(ROLES),
        "worker_order_uint16be_sha256": {
            worker: worker_order_sha256(orders[worker]) for worker in ROLES
        },
        "worker_task_list_sha256": {
            worker: task_list_sha256(tasks[worker]) for worker in ROLES
        },
        "worker_cell_orders": orders,
        "worker_tasks": tasks,
        "execution_contract": load_design()["execution_contract"],
        "launch_contract": load_design()["launch_contract"],
        "information_boundary": {
            "A399_candidate_or_progress_available_at_protocol_freeze": False,
            "A398_static_schedules_frozen_before_A399_execution": True,
            "A385_assignment_absent_from_protocol": True,
            "target_labels_used_for_schedule_construction": 0,
            "reader_refits": 0,
            "candidate_assignments_executed_for_schedule_construction": 0,
            "A397_progress_filter_result_or_true_prefix_consumed": False,
            "all_live_or_queued_recovery_progress_filter_results_or_true_prefixes_consumed": False,
        },
        "anchors": {
            "design": anchor(DESIGN, DESIGN_SHA256),
            "implementation": anchor(IMPLEMENTATION, expected_implementation_sha256),
            "A397_runner": anchor(A397_RUNNER, A397_RUNNER_SHA256),
            "A397_protocol": anchor(A397_PROTOCOL, A397_PROTOCOL_SHA256),
            "A398_result": anchor(A398_RESULT, A398_RESULT_SHA256),
            "A398_causal": anchor(A398_CAUSAL, A398_CAUSAL_SHA256),
            "A384_qualification": anchor(
                A397.A395.A393.A389.A384_QUALIFICATION,
                base["A384_qualification_sha256"],
            ),
            "A385_protocol": anchor(
                A397.A395.A393.A389.A385_PROTOCOL,
                base["A385_protocol_sha256"],
            ),
            "runner": anchor(Path(__file__)),
            "test": anchor(TEST),
            "reproducer": anchor(REPRO),
        },
    }
    payload["protocol_commitment_sha256"] = canonical_sha256(
        {
            "implementation_commitment_sha256": payload[
                "implementation_commitment_sha256"
            ],
            "A384_qualification_sha256": payload["A384_qualification_sha256"],
            "A398_schedule_commitment_sha256": payload[
                "A398_schedule_commitment_sha256"
            ],
            "public_challenge_sha256": payload["public_challenge_sha256"],
            "worker_order_uint16be_sha256": payload[
                "worker_order_uint16be_sha256"
            ],
            "worker_task_list_sha256": payload["worker_task_list_sha256"],
            "launch_contract": payload["launch_contract"],
            "information_boundary": payload["information_boundary"],
        }
    )
    atomic_json(PROTOCOL, payload)
    assert_pre_execution()
    return payload


def load_protocol(expected_sha256: str) -> dict[str, Any]:
    if file_sha256(PROTOCOL) != expected_sha256:
        raise RuntimeError("A399 protocol hash differs")
    value = json.loads(PROTOCOL.read_bytes())
    raw_orders = value.get("worker_cell_orders", {})
    raw_tasks = value.get("worker_tasks", {})
    if set(raw_orders) != set(ROLES) or set(raw_tasks) != set(ROLES):
        raise RuntimeError("A399 protocol worker role set differs")
    source, source_orders, source_tasks = load_schedule()
    orders: dict[str, list[int]] = {}
    tasks: dict[str, list[dict[str, Any]]] = {}
    for worker in ROLES:
        orders[worker], tasks[worker] = exact_worker_schedule(
            raw_orders[worker], raw_tasks[worker], worker
        )
        if (
            orders[worker] != source_orders[worker]
            or tasks[worker] != source_tasks[worker]
            or worker_order_sha256(orders[worker])
            != value.get("worker_order_uint16be_sha256", {}).get(worker)
            or task_list_sha256(tasks[worker])
            != value.get("worker_task_list_sha256", {}).get(worker)
        ):
            raise RuntimeError(f"A399 protocol {worker} schedule differs")
    flattened = [cell for worker in ROLES for cell in orders[worker]]
    boundary = value.get("information_boundary", {})
    if (
        value.get("schema")
        != "chacha20-round20-w50-dual-direct12-eight-worker-recovery-a399-protocol-v1"
        or value.get("attempt_id") != ATTEMPT_ID
        or tuple(value.get("worker_role_order", [])) != ROLES
        or value.get("A398_schedule_commitment_sha256")
        != source["schedule_commitment_sha256"]
        or len(flattened) != CELLS
        or set(flattened) != set(range(CELLS))
        or boundary.get("A399_candidate_or_progress_available_at_protocol_freeze")
        is not False
        or boundary.get("target_labels_used_for_schedule_construction") != 0
        or boundary.get("reader_refits") != 0
        or boundary.get("A397_progress_filter_result_or_true_prefix_consumed")
        is not False
        or canonical_sha256(value.get("public_challenge"))
        != value.get("public_challenge_sha256")
    ):
        raise RuntimeError("A399 protocol semantics differ")
    for row in value["anchors"].values():
        anchor(path_from_ref(row["path"]), row["sha256"])
    load_implementation(value["implementation_sha256"])
    A397.A395.A393.A389.A385.validate_challenge(value["public_challenge"])
    expected_commitment = canonical_sha256(
        {
            "implementation_commitment_sha256": value[
                "implementation_commitment_sha256"
            ],
            "A384_qualification_sha256": value["A384_qualification_sha256"],
            "A398_schedule_commitment_sha256": value[
                "A398_schedule_commitment_sha256"
            ],
            "public_challenge_sha256": value["public_challenge_sha256"],
            "worker_order_uint16be_sha256": value[
                "worker_order_uint16be_sha256"
            ],
            "worker_task_list_sha256": value["worker_task_list_sha256"],
            "launch_contract": value["launch_contract"],
            "information_boundary": value["information_boundary"],
        }
    )
    if value.get("protocol_commitment_sha256") != expected_commitment:
        raise RuntimeError("A399 protocol commitment differs")
    return value


def load_resume(
    *, worker: str, protocol_sha256: str, order_sha: str, tasks_sha: str
) -> tuple[int, float, int, dict[str, Any] | None]:
    path = progress_path(worker)
    if not path.exists():
        return 0, 0.0, 0, None
    value = json.loads(path.read_bytes())
    if (
        value.get("schema")
        != "chacha20-round20-w50-dual-direct12-eight-worker-recovery-a399-progress-v1"
        or value.get("attempt_id") != ATTEMPT_ID
        or value.get("worker_role") != worker
        or value.get("protocol_sha256") != protocol_sha256
        or value.get("worker_order_uint16be_sha256") != order_sha
        or value.get("worker_task_list_sha256") != tasks_sha
        or value.get("matched_control_candidates") != 0
    ):
        raise RuntimeError("A399 progress fingerprint differs")
    status = value.get("status")
    if status == "candidate_found":
        excluded = {
            "schema",
            "attempt_id",
            "worker_role",
            "worker_slug",
            "protocol_sha256",
            "worker_order_uint16be_sha256",
            "worker_task_list_sha256",
            "status",
        }
        return 0, 0.0, 0, {
            key: item for key, item in value.items() if key not in excluded
        }
    completed = int(value.get("executed_worker_prefix_groups", -1))
    if (
        status not in {"running", "worker_exhausted"}
        or not 0 <= completed <= EXPECTED_WORKER_TASKS[worker]
        or value.get("factual_filter_candidates") != 0
    ):
        raise RuntimeError("A399 resumable progress state differs")
    if status == "worker_exhausted":
        return completed, float(value.get("gpu_seconds", 0.0)), int(
            value.get("host_instances", 0)
        ), {"status": "worker_exhausted", **value}
    return (
        completed,
        float(value.get("gpu_seconds", 0.0)),
        int(value.get("host_instances", 0)),
        None,
    )


def ordered_worker_discovery(
    *,
    worker: str,
    host_factory: Callable[[], Any],
    challenge: Mapping[str, Any],
    worker_order: Sequence[int],
    worker_tasks: Sequence[Mapping[str, Any]],
    peer_result_exists: Callable[[], bool],
    start_group: int = 0,
    prior_gpu_seconds: float = 0.0,
    prior_host_instances: int = 0,
    progress_callback: Callable[[Mapping[str, Any]], None] | None = None,
) -> dict[str, Any]:
    order, tasks = exact_worker_schedule(worker_order, worker_tasks, worker)
    if not 0 <= start_group <= len(order):
        raise ValueError("A399 resume group lies outside worker schedule")
    if peer_result_exists():
        return {
            "status": "peer_confirmed",
            "worker_role": worker,
            "executed_worker_prefix_groups": start_group,
            "worker_prefix_groups": len(order),
            "gpu_seconds": prior_gpu_seconds,
            "host_instances": prior_host_instances,
        }
    target = np.asarray(challenge["target_words"][0], dtype=np.uint32)
    control = np.asarray(challenge["control_target_words"], dtype=np.uint32)
    host: Any | None = None
    host_instances = prior_host_instances
    gpu_seconds = prior_gpu_seconds
    started = time.perf_counter()
    try:
        for worker_index in range(start_group, len(order)):
            if peer_result_exists():
                return {
                    "status": "peer_confirmed",
                    "worker_role": worker,
                    "executed_worker_prefix_groups": worker_index,
                    "worker_prefix_groups": len(order),
                    "gpu_seconds": gpu_seconds,
                    "host_instances": host_instances,
                    "volatile_wall_seconds": time.perf_counter() - started,
                }
            task = tasks[worker_index]
            prefix = order[worker_index]
            if worker_index == start_group or worker_index % HOST_REFRESH_GROUPS == 0:
                if host is not None:
                    host.close()
                host = host_factory()
                host_instances += 1
            observed = A397.A395.A393.A389.A384.filter_complete_prefix(
                host=host,
                challenge=challenge,
                prefix=prefix,
                target=target,
                control=control,
            )
            factual = [int(value) for value in observed["factual_candidates"]]
            controls = [int(value) for value in observed["control_candidates"]]
            gpu_seconds += float(observed["gpu_seconds"])
            groups = worker_index + 1
            if controls:
                raise RuntimeError("A399 matched control produced a candidate")
            progress = {
                "executed_worker_prefix_groups": groups,
                "worker_prefix_groups": len(order),
                "executed_worker_assignments": groups * GROUP_SIZE,
                "static_schedule_epoch": int(task["epoch"]),
                "matched_control_candidates": 0,
                "gpu_seconds": gpu_seconds,
                "host_instances": host_instances,
                "last_completed_prefix12": prefix,
                "last_owner_queue_role": task["owner_queue_role"],
                "last_owner_queue_position_one_based": task[
                    "owner_queue_position_one_based"
                ],
                "last_task_stolen": task["stolen"],
            }
            if not factual:
                if progress_callback is not None:
                    progress_callback(
                        {"status": "running", "factual_filter_candidates": 0, **progress}
                    )
                continue
            if len(factual) != 1:
                raise RuntimeError("A399 complete W50 group produced multiple filters")
            candidate = factual[0]
            if ((candidate >> WORD0_SUFFIX_BITS) & (CELLS - 1)) != prefix:
                raise RuntimeError("A399 candidate prefix differs")
            decoded = A397.A395.A393.A389.A384.decode_assignment(candidate)
            found = {
                "status": "candidate_found",
                "worker_role": worker,
                "worker_slug": ROLE_TO_SLUG[worker],
                "candidate": candidate,
                "candidate_hex": f"{candidate:013x}",
                "key_word0": decoded["word0"],
                "key_word1_low18": decoded["word1_low18"],
                "prefix12": prefix,
                "prefix12_hex": f"{prefix:03x}",
                "worker_step_one_based": groups,
                "owner_queue_role": task["owner_queue_role"],
                "owner_queue_position_one_based": task[
                    "owner_queue_position_one_based"
                ],
                "task_stolen": task["stolen"],
                "executed_worker_group_dispatches": groups * 128,
                "complete_W50_group_execution_before_stop": True,
                "early_stop_inside_group": False,
                "factual_filter_candidates": factual,
                "control_filter_candidates": [],
                "host_refresh_interval_prefix_groups": HOST_REFRESH_GROUPS,
                "volatile_wall_seconds": time.perf_counter() - started,
                **progress,
            }
            if progress_callback is not None:
                progress_callback(found)
            return found
    finally:
        if host is not None:
            host.close()
    exhausted = {
        "status": "worker_exhausted",
        "worker_role": worker,
        "worker_slug": ROLE_TO_SLUG[worker],
        "executed_worker_prefix_groups": len(order),
        "worker_prefix_groups": len(order),
        "executed_worker_assignments": len(order) * GROUP_SIZE,
        "static_schedule_epoch": len(order),
        "matched_control_candidates": 0,
        "factual_filter_candidates": 0,
        "gpu_seconds": gpu_seconds,
        "host_instances": host_instances,
        "volatile_wall_seconds": time.perf_counter() - started,
    }
    if progress_callback is not None:
        progress_callback(exhausted)
    return exhausted


def progress_snapshot(protocol: Mapping[str, Any]) -> dict[str, Any]:
    panel: dict[str, Any] = {}
    total_groups = 0
    max_epoch = 0
    all_control_zero = True
    for worker in ROLES:
        path = progress_path(worker)
        if not path.exists():
            panel[worker] = {
                "status": "not_started",
                "executed_worker_prefix_groups": 0,
                "worker_prefix_groups": STATIC_EPOCHS,
            }
            continue
        value = json.loads(path.read_bytes())
        if (
            value.get("protocol_sha256") != file_sha256(PROTOCOL)
            or value.get("worker_role") != worker
            or value.get("worker_order_uint16be_sha256")
            != protocol["worker_order_uint16be_sha256"][worker]
            or value.get("worker_task_list_sha256")
            != protocol["worker_task_list_sha256"][worker]
        ):
            raise RuntimeError("A399 progress snapshot fingerprint differs")
        groups = int(value.get("executed_worker_prefix_groups", 0))
        total_groups += groups
        max_epoch = max(max_epoch, int(value.get("static_schedule_epoch", 0)))
        all_control_zero &= value.get("matched_control_candidates") == 0
        panel[worker] = {
            "status": value.get("status"),
            "executed_worker_prefix_groups": groups,
            "worker_prefix_groups": STATIC_EPOCHS,
            "static_schedule_epoch": int(value.get("static_schedule_epoch", 0)),
            "gpu_seconds": float(value.get("gpu_seconds", 0.0)),
            "matched_control_candidates": value.get("matched_control_candidates"),
        }
    return {
        "workers": panel,
        "total_unique_prefix_groups_evaluated": total_groups,
        "total_unique_assignments_evaluated": total_groups * GROUP_SIZE,
        "maximum_completed_static_schedule_epoch": max_epoch,
        "theoretical_complete_schedule_epochs": STATIC_EPOCHS,
        "complete_domain_assignments": DOMAIN_SIZE,
        "all_observed_matched_controls_empty": all_control_zero,
        "prefix_sets_are_disjoint_by_A398_construction": True,
    }


def rank_panel(prefix: int, worker: str, protocol: Mapping[str, Any]) -> dict[str, Any]:
    source, _orders, _tasks = load_schedule()
    epoch = int(source["cell_epoch_one_based"][prefix])
    if source["cell_worker_role"][prefix] != worker:
        raise RuntimeError("A399 confirmed prefix worker differs")
    task = protocol["worker_tasks"][worker][epoch - 1]
    row = source["per_cell_proof"][prefix]
    if int(task["cell"]) != prefix or int(row["cell"]) != prefix:
        raise RuntimeError("A399 confirmed task/proof lookup differs")
    return {
        **row,
        "A398_worker_role": worker,
        "A398_worker_step_one_based": int(task["worker_step_one_based"]),
        "A398_owner_queue_role": task["owner_queue_role"],
        "A398_owner_queue_position_one_based": int(
            task["owner_queue_position_one_based"]
        ),
        "A398_task_stolen": task["stolen"],
        "exact_depth_chain_holds": (
            epoch
            <= int(row["owner_lane_depth_one_based"])
            <= int(row["best_source_rank_one_based"])
        ),
        "ranks_computed_only_after_independent_confirmation": True,
    }


def build_causal(payload: Mapping[str, Any]) -> dict[str, Any]:
    sys.path.insert(0, str(DOTCAUSAL_SRC))
    from dotcausal.io import CausalReader, CausalWriter

    terminal = "A399:confirmed_dual_Direct12_eight_worker_W50_recovery"
    writer = CausalWriter(api_id="a399w50")
    writer._rules = []
    writer.add_rule(
        name="dual_reader_schedule_and_engine_to_model",
        description="A398's eight disjoint static lists execute complete qualified W50 groups with one shared confirmed-success stop.",
        pattern=["A398_exact_dual_Direct12_W50_schedule", "A384_exact_W50_group_engine"],
        conclusion="A399_sole_factual_W50_model",
        confidence_modifier=1.0,
    )
    writer.add_rule(
        name="model_to_confirmed_dual_reader_recovery",
        description="The sole factual model passes the matched control and dual independent eight-block confirmation.",
        pattern=["A399_sole_factual_W50_model"],
        conclusion="A399_confirmed_dual_Direct12_eight_worker_W50_recovery",
        confidence_modifier=1.0,
    )
    writer.add_triplet(
        trigger="A398:exact_dual_Direct12_W50_schedule",
        mechanism="qualified_eight_worker_complete_group_search_with_shared_stop",
        outcome="A399:sole_factual_W50_model",
        confidence=1.0,
        source=payload["execution_sha256"],
        quantification=json.dumps(payload["aggregate_execution"], sort_keys=True),
        evidence=json.dumps(payload["rank_analysis"], sort_keys=True),
        domain="fresh full-round ChaCha20 W50 dual-Direct12 parallel recovery",
        quality_score=1.0,
    )
    writer.add_triplet(
        trigger="A399:sole_factual_W50_model",
        mechanism="matched_control_rejection_and_dual_eight_block_confirmation",
        outcome=terminal,
        confidence=1.0,
        source=payload["measurement_sha256"],
        quantification=json.dumps(payload["confirmation"], sort_keys=True),
        evidence=payload["evidence_stage"],
        domain="confirmed full-round ChaCha20 W50 dual-Direct12 recovery",
        quality_score=1.0,
    )
    writer.add_triplet(
        trigger="A398:exact_dual_Direct12_W50_schedule",
        mechanism="materialized_dual_reader_search_and_confirmation_closure",
        outcome=terminal,
        confidence=1.0,
        source="materialized:A399_dual_Direct12_W50_recovery_chain",
        quantification="exact retained closure",
        evidence=payload["evidence_stage"],
        domain="AI-native retained inference",
        quality_score=1.0,
        is_inferred=True,
    )
    writer.add_cluster(
        name="A399 dual-Direct12 eight-worker W50 recovery",
        entities=[
            "A398:exact_dual_Direct12_W50_schedule",
            "A399:sole_factual_W50_model",
            terminal,
        ],
    )
    writer.add_gap(
        subject=terminal,
        predicate="next_required_object",
        expected_object_type="W51_dual_Direct12_parallel_transfer",
        confidence=1.0,
        suggested_queries=[
            "Transfer both frozen Direct12 readouts after W51 engine qualification and fresh W51 measurement."
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
        reader.api_id != "a399w50"
        or len(explicit) != 2
        or len(all_rows) != 3
        or len(inferred) != 1
        or len(reader._rules) != 2
        or len(reader._clusters) != 1
        or len(reader._gaps) != 1
    ):
        raise RuntimeError("A399 authentic Causal reopen gate failed")
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
            "terminal_chain": all_rows[-1],
            "next_gap": reader._gaps[0],
        },
    }


def recover_worker(*, worker: str, expected_protocol_sha256: str) -> dict[str, Any]:
    if RESULT.exists():
        return {
            "status": "peer_confirmed",
            "worker_role": worker,
            "result_sha256": file_sha256(RESULT),
        }
    protocol = load_protocol(expected_protocol_sha256)
    qualification = A397.A395.A393.A389.A385.load_a384_qualification(
        protocol["A384_qualification_sha256"]
    )
    engine_protocol = A397.A395.A393.A389.A384.load_protocol(
        A397.A395.A393.A389.A384_PROTOCOL_SHA256
    )
    executable_row = engine_protocol["anchors"]["grouped_executable"]
    executable = path_from_ref(executable_row["path"])
    anchor(executable, executable_row["sha256"])
    challenge = protocol["public_challenge"]
    order, tasks = exact_worker_schedule(
        protocol["worker_cell_orders"][worker],
        protocol["worker_tasks"][worker],
        worker,
    )
    placeholder = np.asarray([0, 0], dtype=np.uint32)

    def host_factory() -> Any:
        return A397.A395.A393.A389.A384.A378.A371.A346.A324.A311.A307.A304.GroupedMetalHost(
            executable,
            A397.A395.A393.A389.A384.initial_for_slab(challenge, 0),
            placeholder,
            placeholder,
        )

    order_hash = protocol["worker_order_uint16be_sha256"][worker]
    tasks_hash = protocol["worker_task_list_sha256"][worker]

    def write_progress(row: Mapping[str, Any]) -> None:
        atomic_json(
            progress_path(worker),
            {
                "schema": "chacha20-round20-w50-dual-direct12-eight-worker-recovery-a399-progress-v1",
                "attempt_id": ATTEMPT_ID,
                "worker_role": worker,
                "worker_slug": ROLE_TO_SLUG[worker],
                "protocol_sha256": expected_protocol_sha256,
                "worker_order_uint16be_sha256": order_hash,
                "worker_task_list_sha256": tasks_hash,
                "A384_qualification_sha256": protocol[
                    "A384_qualification_sha256"
                ],
                **dict(row),
            },
        )

    start, prior_gpu, prior_hosts, completed = load_resume(
        worker=worker,
        protocol_sha256=expected_protocol_sha256,
        order_sha=order_hash,
        tasks_sha=tasks_hash,
    )
    if completed is not None:
        return completed
    discovery = ordered_worker_discovery(
        worker=worker,
        host_factory=host_factory,
        challenge=challenge,
        worker_order=order,
        worker_tasks=tasks,
        peer_result_exists=RESULT.exists,
        start_group=start,
        prior_gpu_seconds=prior_gpu,
        prior_host_instances=prior_hosts,
        progress_callback=write_progress,
    )
    if discovery["status"] in {"peer_confirmed", "worker_exhausted"}:
        if discovery["status"] == "worker_exhausted":
            exhausted = sum(
                path.exists()
                and json.loads(path.read_bytes()).get("status") == "worker_exhausted"
                for path in (progress_path(other) for other in ROLES)
            )
            if exhausted == len(ROLES) and not RESULT.exists():
                raise RuntimeError("A399 all static workers exhausted without a model")
        return discovery
    candidate = int(discovery["candidate"])
    confirmation = A397.A395.A393.A389.A385.confirm(challenge, candidate)
    if confirmation["all_blocks_match"] is not True:
        raise RuntimeError("A399 dual independent confirmation failed")
    ranks = rank_panel(int(discovery["prefix12"]), worker, protocol)
    if (
        int(ranks["A398_epoch_one_based"])
        != discovery["static_schedule_epoch"]
        or ranks["A398_worker_step_one_based"]
        != discovery["executed_worker_prefix_groups"]
        or ranks["exact_depth_chain_holds"] is not True
    ):
        raise RuntimeError("A399 discovery depth differs from A398 schedule")
    aggregate = progress_snapshot(protocol)
    unique_groups = int(aggregate["total_unique_prefix_groups_evaluated"])
    if not 1 <= unique_groups <= CELLS:
        raise RuntimeError("A399 aggregate unique group count differs")
    strict_subset = unique_groups < CELLS
    aggregate["strict_subset_of_complete_domain"] = strict_subset
    aggregate["domain_reduction_factor"] = CELLS / unique_groups
    aggregate["search_gain_bits"] = math.log2(CELLS / unique_groups)
    evidence_stage = (
        "FULLROUND_R20_DUAL_DIRECT12_EIGHT_WORKER_W50_STRICT_SUBSET_RECOVERY_CONFIRMED"
        if strict_subset
        else "FULLROUND_R20_DUAL_DIRECT12_EIGHT_WORKER_W50_COMPLETE_DOMAIN_RECOVERY_CONFIRMED"
    )
    payload: dict[str, Any] = {
        "schema": "chacha20-round20-w50-dual-direct12-eight-worker-recovery-a399-result-v1",
        "attempt_id": ATTEMPT_ID,
        "evidence_stage": evidence_stage,
        "protocol_sha256": expected_protocol_sha256,
        "design_sha256": DESIGN_SHA256,
        "implementation_sha256": protocol["implementation_sha256"],
        "A384_qualification_sha256": protocol["A384_qualification_sha256"],
        "A385_protocol_sha256": protocol["A385_protocol_sha256"],
        "A398_result_sha256": protocol["A398_result_sha256"],
        "A398_schedule_commitment_sha256": protocol[
            "A398_schedule_commitment_sha256"
        ],
        "public_challenge_sha256": protocol["public_challenge_sha256"],
        "winning_worker_role": worker,
        "winning_worker_slug": ROLE_TO_SLUG[worker],
        "discovery": discovery,
        "aggregate_execution": aggregate,
        "rank_analysis": ranks,
        "confirmation": confirmation,
        "strict_subset_of_complete_domain": strict_subset,
        "qualification_gate": {
            "evidence_stage": qualification["evidence_stage"],
            "qualification_sha256": qualification["qualification_sha256"],
            "complete_W50_group_candidates": qualification["complete_group_gate"][
                "logical_candidates"
            ],
            "synthetic_filter_exact": qualification["synthetic_filter_exact"],
            "production_target_used": False,
        },
        "information_boundary": protocol["information_boundary"],
        "anchors": protocol["anchors"],
    }
    stable_discovery = {
        key: item
        for key, item in discovery.items()
        if not key.startswith("volatile_")
    }
    payload["execution_sha256"] = canonical_sha256(
        {
            "winning_worker_role": worker,
            "winning_worker_order_uint16be_sha256": order_hash,
            "winning_worker_task_list_sha256": tasks_hash,
            "discovery": stable_discovery,
            "aggregate_execution": aggregate,
            "A384_qualification_sha256": protocol["A384_qualification_sha256"],
        }
    )
    payload["measurement_sha256"] = canonical_sha256(
        {
            "discovery": stable_discovery,
            "aggregate_execution": aggregate,
            "rank_analysis": ranks,
            "confirmation": confirmation,
            "qualification_gate": payload["qualification_gate"],
            "information_boundary": payload["information_boundary"],
        }
    )
    payload["causal"] = build_causal(payload)
    atomic_json(RESULT, payload)
    atomic_bytes(
        REPORT,
        (
            "# A399 — dual-Direct12 eight-worker full-round ChaCha20 W50 recovery\n\n"
            f"Evidence stage: **{evidence_stage}**\n\n"
            f"- Winning worker: **{worker}**\n"
            f"- Static schedule epoch: **{ranks['A398_epoch_one_based']} / {STATIC_EPOCHS}**\n"
            f"- Exact unique prefix groups evaluated: **{unique_groups} / {CELLS}**\n"
            f"- Complete candidate evaluations: **{aggregate['total_unique_assignments_evaluated']:,} / {DOMAIN_SIZE:,}**\n"
            f"- Recovered W50 assignment: **0x{candidate:013x}**\n"
            "- Standard ChaCha20: **20 rounds plus feed-forward**\n"
            "- Every prefix: **128 complete 2^31 slabs before outcome evaluation**\n"
            "- Duplicate A399 prefix groups: **zero by construction**\n"
            "- Matched one-bit control: **zero candidates**\n"
            "- Dual independent confirmation: **8,192 checked bits**\n"
            "- Authentic AI-native Causal readback: **2 explicit + 1 inferred chain**\n"
        ).encode(),
    )
    return payload


def analyze() -> dict[str, Any]:
    payload: dict[str, Any] = {
        "attempt_id": ATTEMPT_ID,
        "design_sha256": DESIGN_SHA256,
        "implementation_frozen": IMPLEMENTATION.exists(),
        "protocol_frozen": PROTOCOL.exists(),
        "result_complete": RESULT.exists(),
    }
    if IMPLEMENTATION.exists():
        payload["implementation_sha256"] = file_sha256(IMPLEMENTATION)
    if PROTOCOL.exists():
        payload["protocol_sha256"] = file_sha256(PROTOCOL)
        protocol = json.loads(PROTOCOL.read_bytes())
        payload["worker_progress"] = progress_snapshot(protocol)
    if RESULT.exists():
        value = json.loads(RESULT.read_bytes())
        payload["result_sha256"] = file_sha256(RESULT)
        payload["evidence_stage"] = value["evidence_stage"]
    return payload


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    action = parser.add_mutually_exclusive_group(required=True)
    action.add_argument("--analyze", action="store_true")
    action.add_argument("--freeze-implementation", action="store_true")
    action.add_argument("--freeze-protocol", action="store_true")
    action.add_argument("--recover-worker", choices=tuple(SLUG_TO_ROLE))
    parser.add_argument("--expected-implementation-sha256")
    parser.add_argument("--expected-protocol-sha256")
    args = parser.parse_args()
    if args.freeze_implementation:
        payload = freeze_implementation()
    elif args.freeze_protocol:
        if not args.expected_implementation_sha256:
            parser.error("--freeze-protocol requires --expected-implementation-sha256")
        payload = freeze_protocol(
            expected_implementation_sha256=args.expected_implementation_sha256
        )
    elif args.recover_worker:
        if not args.expected_protocol_sha256:
            parser.error("--recover-worker requires --expected-protocol-sha256")
        payload = recover_worker(
            worker=SLUG_TO_ROLE[args.recover_worker],
            expected_protocol_sha256=args.expected_protocol_sha256,
        )
    else:
        payload = analyze()
    print(json.dumps(payload, indent=2, sort_keys=True), flush=True)


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""A429: execute A428's qualified global W50 wavefront on the sealed A385 target."""

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
STEM = "chacha20_round20_w50_a428_global_wavefront_recovery_a429"
DESIGN = CONFIGS / f"{STEM}_design_v1.json"
IMPLEMENTATION = CONFIGS / f"{STEM}_implementation_v1.json"
PROTOCOL = CONFIGS / f"{STEM}_v1.json"
RESULT = RESULTS / f"{STEM}_v1.json"
CAUSAL = RESULT.with_suffix(".causal")
REPORT = RESULT.with_suffix(".md")
TEST = ROOT / "tests/test_chacha20_round20_w50_a428_global_wavefront_recovery_a429.py"
REPRO = ROOT / "scripts/reproduce_chacha20_round20_w50_a428_global_wavefront_recovery_a429.sh"
A428_RUNNER = RESEARCH / "experiments/chacha20_round20_w50_global_best_rank_wavefront_a428.py"
A428_RESULT = RESULTS / "chacha20_round20_w50_global_best_rank_wavefront_a428_v1.json"
A428_CAUSAL = A428_RESULT.with_suffix(".causal")
A428_IMPLEMENTATION = CONFIGS / "chacha20_round20_w50_global_best_rank_wavefront_a428_implementation_v1.json"
A397_RUNNER = RESEARCH / "experiments/chacha20_round20_w50_expanded_eight_worker_recovery_a397.py"
A397_PROTOCOL = CONFIGS / "chacha20_round20_w50_expanded_eight_worker_recovery_a397_v1.json"
A385_PROTOCOL = CONFIGS / "chacha20_round20_fresh_w50_pretarget_transfer_a385_v1.json"
A384_QUALIFICATION = RESULTS / "chacha20_round20_w50_onehundredtwentyeight_slab_grouped_engine_a384_qualification_v1.json"

ATTEMPT_ID = "A429"
DESIGN_SHA256 = "30afe397bd6eb4cf52954accf47f1c6445f951ec4294631d3d6b8c0358cf36c9"
A428_RUNNER_SHA256 = "f7f60c7e4fdf68fbde9de7563ba4a3b2498054ecddb0e9be17a43489c591c705"
A428_RESULT_SHA256 = "dbf8fd33558bfde4e8e6833e6d69df1b57fcf8732fec28d35828b39e3cce0584"
A428_CAUSAL_SHA256 = "52a61beb8605fe54b9db66a5ba156b683dfc7dc0270e2a8a202a6f7a70ab0762"
A428_IMPLEMENTATION_SHA256 = "d74f72befa1b13f2be211aa1db161ea6ce51d580c290d68efdecb8250a5e7283"
A397_RUNNER_SHA256 = "099bc92d9b91228ff1563c251ba47a6d4101da48a3dc193cf57a4e4be2f2e8c5"
A397_PROTOCOL_SHA256 = "447baf5e4784d0210f51e194f1a241b7fbfbf1ab239fe16582effdb4b435fb32"
A385_PROTOCOL_SHA256 = "801831f2daabe41476c9bf1ec676907f11c1b5465a193ba61d8d1877eb3b0b4b"
A384_QUALIFICATION_SHA256 = "0e31d4d7b0e0bb0e45cd815d975e2898c60eeea16e04498d720f0a58dd41dc30"
SCHEDULE_COMMITMENT_SHA256 = "0b0e684b95d16c1f17c994be1fe0443af5fe55bc359f3d416f787f0540e2500c"
CELLS = 4096
WORKERS = 8
STATIC_EPOCHS = 512
GROUP_SIZE = 1 << 38
DOMAIN_SIZE = 1 << 50
WORD0_SUFFIX_BITS = 20
HOST_REFRESH_GROUPS = 8
DOTCAUSAL_SRC = Path("/Users/bhkmie/Documents/Forschung/O1/vendor/fabel/dotcausal_package/src")


def load_module(path: Path, name: str) -> Any:
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot import A429 dependency {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


A428 = load_module(A428_RUNNER, "a429_a428")
A397 = load_module(A397_RUNNER, "a429_a397")
ROLES = tuple(A428.A427.SOURCE_ROLES)
ROLE_TO_SLUG = {
    "majority_polarity_3to1_complete": "polarity",
    "A413_candidate_123": "c123",
    "A413_candidate_035": "c035",
    "A413_candidate_100": "c100",
    "A413_candidate_153": "c153",
    "A413_candidate_091": "c091",
    "A413_candidate_049": "c049",
    "A413_candidate_144": "c144",
}
SLUG_TO_ROLE = {slug: role for role, slug in ROLE_TO_SLUG.items()}
file_sha256 = A397.file_sha256
canonical_sha256 = A397.canonical_sha256
atomic_json = A397.atomic_json
atomic_bytes = A397.atomic_bytes
relative = A397.relative
path_from_ref = A397.path_from_ref
anchor = A397.anchor


def progress_path(worker: str) -> Path:
    if worker not in ROLE_TO_SLUG:
        raise ValueError(f"A429 unknown worker {worker}")
    return RESULTS / f"{STEM}_{ROLE_TO_SLUG[worker]}_progress_v1.json"


def load_design() -> dict[str, Any]:
    if file_sha256(DESIGN) != DESIGN_SHA256:
        raise RuntimeError("A429 design hash differs")
    value = json.loads(DESIGN.read_bytes())
    execution = value.get("execution_contract", {})
    schedule = value.get("schedule_contract", {})
    boundary = value.get("information_boundary", {})
    if (
        value.get("schema")
        != "chacha20-round20-w50-a428-global-wavefront-recovery-a429-design-v1"
        or value.get("attempt_id") != ATTEMPT_ID
        or value.get("design_state")
        != "frozen_after_A428_qualification_before_any_A429_candidate_progress_or_filter_outcome"
        or execution.get("full_rounds") != 20
        or execution.get("feedforward_included") is not True
        or execution.get("unknown_key_bits") != 50
        or execution.get("workers") != WORKERS
        or execution.get("worker_tasks_each") != STATIC_EPOCHS
        or execution.get("complete_group_before_success_evaluation") is not True
        or schedule.get("schedule_commitment_sha256") != SCHEDULE_COMMITMENT_SHA256
        or schedule.get("copy_all_eight_worker_orders_and_tasks_byte_identically") is not True
        or schedule.get("A429_target_labels_used") != 0
        or schedule.get("A429_candidate_assignments_used") != 0
        or boundary.get("A429_candidate_or_progress_available_at_design_freeze") is not False
        or boundary.get("A429_target_assignment_or_true_prefix_available_at_design_freeze") is not False
        or boundary.get("prior_live_recovery_filter_outcomes_consumed") is not False
    ):
        raise RuntimeError("A429 frozen design semantics differ")
    for key, item in value["source_anchors"].items():
        if key.endswith("_path"):
            stem = key.removesuffix("_path")
            anchor(ROOT / item, value["source_anchors"][f"{stem}_sha256"])
    return value


def exact_worker_schedule(values: Sequence[int], tasks: Sequence[Mapping[str, Any]], worker: str) -> tuple[list[int], list[dict[str, Any]]]:
    if worker not in ROLES:
        raise ValueError(f"A429 unknown worker {worker}")
    order = [int(value) for value in values]
    rows = [dict(value) for value in tasks]
    if len(order) != STATIC_EPOCHS or len(rows) != STATIC_EPOCHS or len(set(order)) != STATIC_EPOCHS:
        raise ValueError(f"A429 {worker} schedule geometry differs")
    for step, (cell, row) in enumerate(zip(order, rows, strict=True), 1):
        if (
            int(row.get("cell", -1)) != cell
            or int(row.get("epoch", -1)) != step
            or row.get("worker_role") != worker
            or int(row.get("worker_step_one_based", -1)) != step
            or int(row.get("global_position_one_based", -1)) != (step - 1) * WORKERS + ROLES.index(worker) + 1
            or int(row.get("best_source_rank_one_based", 0)) < 1
            or row.get("best_source_role") not in ROLES
        ):
            raise ValueError(f"A429 {worker} task semantics differ at step {step}")
    return order, rows


def load_source_schedule() -> tuple[dict[str, Any], dict[str, list[int]], dict[str, list[dict[str, Any]]]]:
    anchor(A428_RESULT, A428_RESULT_SHA256)
    anchor(A428_CAUSAL, A428_CAUSAL_SHA256)
    source = json.loads(A428_RESULT.read_bytes())
    if (
        source.get("schema")
        != "chacha20-round20-w50-global-best-rank-wavefront-a428-result-v1"
        or source.get("attempt_id") != "A428"
        or source.get("qualified") is not True
        or source.get("production_execution_enabled") is not True
        or source.get("production_schedule_commitment_sha256") != SCHEDULE_COMMITMENT_SHA256
        or tuple(source.get("source_role_order", [])) != ROLES
        or source.get("production_target_labels_used") != 0
        or source.get("production_candidate_assignments_executed") != 0
        or source.get("live_recovery_progress_or_filter_outcomes_consumed") is not False
    ):
        raise RuntimeError("A429 A428 source semantics differ")
    proof = source["production_schedule_proof"]
    if (
        proof.get("complete_cover_cells") != CELLS
        or proof.get("duplicate_cells") != 0
        or proof.get("uncovered_cells") != 0
        or proof.get("makespan_epochs") != STATIC_EPOCHS
        or proof.get("depth_bound_violations") != 0
        or proof.get("total_work_bound_violations") != 0
    ):
        raise RuntimeError("A429 A428 schedule proof differs")
    orders: dict[str, list[int]] = {}
    tasks: dict[str, list[dict[str, Any]]] = {}
    for worker in ROLES:
        orders[worker], tasks[worker] = exact_worker_schedule(
            source["production_worker_cell_orders"][worker],
            source["production_worker_tasks"][worker],
            worker,
        )
        if A428.uint16be_sha256(orders[worker]) != source["production_worker_cell_order_uint16be_sha256"][worker]:
            raise RuntimeError(f"A429 {worker} source order commitment differs")
        if canonical_sha256(tasks[worker]) != source["production_worker_task_list_sha256"][worker]:
            raise RuntimeError(f"A429 {worker} source task commitment differs")
    flattened = [cell for worker in ROLES for cell in orders[worker]]
    if len(flattened) != CELLS or len(set(flattened)) != CELLS or set(flattened) != set(range(CELLS)):
        raise RuntimeError("A429 source worker lists are not one exact disjoint cover")
    return source, orders, tasks


def freeze_implementation() -> dict[str, Any]:
    if any(path.exists() for path in (IMPLEMENTATION, PROTOCOL, RESULT, CAUSAL, REPORT)):
        raise FileExistsError("A429 implementation or downstream artifact already exists")
    design = load_design()
    source, orders, tasks = load_source_schedule()
    A397.load_protocol(A397_PROTOCOL_SHA256)
    if not TEST.exists() or not REPRO.exists():
        raise FileNotFoundError("A429 test and reproducer must precede freeze")
    payload: dict[str, Any] = {
        "schema": "chacha20-round20-w50-a428-global-wavefront-recovery-a429-implementation-v1",
        "attempt_id": ATTEMPT_ID,
        "commitment_state": "complete_A428_schedule_executor_frozen_before_any_A429_candidate_progress_or_filter_outcome",
        "design_sha256": DESIGN_SHA256,
        "execution_contract": design["execution_contract"],
        "schedule_contract": design["schedule_contract"],
        "source_A428_result_sha256": A428_RESULT_SHA256,
        "source_A428_schedule_commitment_sha256": source["production_schedule_commitment_sha256"],
        "source_worker_order_uint16be_sha256": {role: A428.uint16be_sha256(orders[role]) for role in ROLES},
        "source_worker_task_list_sha256": {role: canonical_sha256(tasks[role]) for role in ROLES},
        "A429_candidate_or_progress_available_at_freeze": False,
        "A429_target_assignment_or_true_prefix_available_at_freeze": False,
        "prior_live_recovery_filter_outcomes_consumed": False,
        "anchors": {
            "design": anchor(DESIGN, DESIGN_SHA256),
            "A428_runner": anchor(A428_RUNNER, A428_RUNNER_SHA256),
            "A428_result": anchor(A428_RESULT, A428_RESULT_SHA256),
            "A428_causal": anchor(A428_CAUSAL, A428_CAUSAL_SHA256),
            "A428_implementation": anchor(A428_IMPLEMENTATION, A428_IMPLEMENTATION_SHA256),
            "A397_runner": anchor(A397_RUNNER, A397_RUNNER_SHA256),
            "A397_protocol": anchor(A397_PROTOCOL, A397_PROTOCOL_SHA256),
            "A385_protocol": anchor(A385_PROTOCOL, A385_PROTOCOL_SHA256),
            "A384_qualification": anchor(A384_QUALIFICATION, A384_QUALIFICATION_SHA256),
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
        raise RuntimeError("A429 implementation hash differs")
    value = json.loads(IMPLEMENTATION.read_bytes())
    if (
        value.get("schema")
        != "chacha20-round20-w50-a428-global-wavefront-recovery-a429-implementation-v1"
        or value.get("attempt_id") != ATTEMPT_ID
        or value.get("design_sha256") != DESIGN_SHA256
        or value.get("source_A428_result_sha256") != A428_RESULT_SHA256
        or value.get("source_A428_schedule_commitment_sha256") != SCHEDULE_COMMITMENT_SHA256
        or value.get("A429_candidate_or_progress_available_at_freeze") is not False
        or value.get("A429_target_assignment_or_true_prefix_available_at_freeze") is not False
        or value.get("prior_live_recovery_filter_outcomes_consumed") is not False
    ):
        raise RuntimeError("A429 implementation semantics differ")
    for row in value["anchors"].values():
        anchor(path_from_ref(row["path"]), row["sha256"])
    unsigned = {key: item for key, item in value.items() if key != "implementation_commitment_sha256"}
    if value["implementation_commitment_sha256"] != canonical_sha256(unsigned):
        raise RuntimeError("A429 implementation commitment differs")
    return value


def freeze_protocol(*, expected_implementation_sha256: str) -> dict[str, Any]:
    if any(path.exists() for path in (PROTOCOL, RESULT, CAUSAL, REPORT)):
        raise FileExistsError("A429 protocol or execution artifact already exists")
    implementation = load_implementation(expected_implementation_sha256)
    source, orders, tasks = load_source_schedule()
    base = A397.load_protocol(A397_PROTOCOL_SHA256)
    challenge = dict(base["public_challenge"])
    A397.A395.A393.A389.A385.validate_challenge(challenge)
    payload: dict[str, Any] = {
        "schema": "chacha20-round20-w50-a428-global-wavefront-recovery-a429-protocol-v1",
        "attempt_id": ATTEMPT_ID,
        "protocol_state": "A428_global_wavefront_and_A385_public_challenge_bound_before_any_A429_candidate_progress_or_filter_outcome",
        "design_sha256": DESIGN_SHA256,
        "implementation_sha256": expected_implementation_sha256,
        "implementation_commitment_sha256": implementation["implementation_commitment_sha256"],
        "A428_result_sha256": A428_RESULT_SHA256,
        "A428_schedule_commitment_sha256": SCHEDULE_COMMITMENT_SHA256,
        "A397_protocol_sha256": A397_PROTOCOL_SHA256,
        "A385_protocol_sha256": A385_PROTOCOL_SHA256,
        "A384_qualification_sha256": A384_QUALIFICATION_SHA256,
        "public_challenge": challenge,
        "public_challenge_sha256": canonical_sha256(challenge),
        "worker_roles": list(ROLES),
        "worker_cell_orders": orders,
        "worker_tasks": tasks,
        "worker_order_uint16be_sha256": {role: A428.uint16be_sha256(orders[role]) for role in ROLES},
        "worker_task_list_sha256": {role: canonical_sha256(tasks[role]) for role in ROLES},
        "workers": WORKERS,
        "worker_tasks_each": STATIC_EPOCHS,
        "complete_domain_assignments": DOMAIN_SIZE,
        "information_boundary": {
            "A385_assignment_absent_from_protocol": True,
            "A385_true_prefix_absent_from_protocol": True,
            "A428_schedule_frozen_before_A429_execution": True,
            "A429_candidate_or_progress_available_at_protocol_freeze": False,
            "A429_target_labels_used_for_schedule": 0,
            "A429_reader_refits": 0,
            "prior_live_recovery_filter_outcomes_consumed": False,
        },
        "anchors": {
            "implementation": anchor(IMPLEMENTATION, expected_implementation_sha256),
            "A428_result": anchor(A428_RESULT, A428_RESULT_SHA256),
            "A428_causal": anchor(A428_CAUSAL, A428_CAUSAL_SHA256),
            "A397_protocol": anchor(A397_PROTOCOL, A397_PROTOCOL_SHA256),
            "A385_protocol": anchor(A385_PROTOCOL, A385_PROTOCOL_SHA256),
            "A384_qualification": anchor(A384_QUALIFICATION, A384_QUALIFICATION_SHA256),
            "runner": anchor(Path(__file__)),
        },
    }
    payload["protocol_commitment_sha256"] = canonical_sha256(payload)
    atomic_json(PROTOCOL, payload)
    return payload


def load_protocol(expected_sha256: str) -> dict[str, Any]:
    if file_sha256(PROTOCOL) != expected_sha256:
        raise RuntimeError("A429 protocol hash differs")
    value = json.loads(PROTOCOL.read_bytes())
    boundary = value.get("information_boundary", {})
    if (
        value.get("schema")
        != "chacha20-round20-w50-a428-global-wavefront-recovery-a429-protocol-v1"
        or value.get("attempt_id") != ATTEMPT_ID
        or value.get("A428_result_sha256") != A428_RESULT_SHA256
        or value.get("A428_schedule_commitment_sha256") != SCHEDULE_COMMITMENT_SHA256
        or value.get("A385_protocol_sha256") != A385_PROTOCOL_SHA256
        or value.get("A384_qualification_sha256") != A384_QUALIFICATION_SHA256
        or tuple(value.get("worker_roles", [])) != ROLES
        or value.get("workers") != WORKERS
        or value.get("worker_tasks_each") != STATIC_EPOCHS
        or boundary.get("A385_assignment_absent_from_protocol") is not True
        or boundary.get("A385_true_prefix_absent_from_protocol") is not True
        or boundary.get("A429_candidate_or_progress_available_at_protocol_freeze") is not False
        or boundary.get("A429_target_labels_used_for_schedule") != 0
        or boundary.get("A429_reader_refits") != 0
        or boundary.get("prior_live_recovery_filter_outcomes_consumed") is not False
    ):
        raise RuntimeError("A429 protocol semantics differ")
    if canonical_sha256(value["public_challenge"]) != value["public_challenge_sha256"]:
        raise RuntimeError("A429 public challenge commitment differs")
    A397.A395.A393.A389.A385.validate_challenge(value["public_challenge"])
    _source, source_orders, source_tasks = load_source_schedule()
    for worker in ROLES:
        order, tasks = exact_worker_schedule(value["worker_cell_orders"][worker], value["worker_tasks"][worker], worker)
        if order != source_orders[worker] or tasks != source_tasks[worker]:
            raise RuntimeError(f"A429 {worker} byte-identical A428 transfer differs")
        if A428.uint16be_sha256(order) != value["worker_order_uint16be_sha256"][worker]:
            raise RuntimeError(f"A429 {worker} order commitment differs")
        if canonical_sha256(tasks) != value["worker_task_list_sha256"][worker]:
            raise RuntimeError(f"A429 {worker} task commitment differs")
    for row in value["anchors"].values():
        anchor(path_from_ref(row["path"]), row["sha256"])
    unsigned = {key: item for key, item in value.items() if key != "protocol_commitment_sha256"}
    if value["protocol_commitment_sha256"] != canonical_sha256(unsigned):
        raise RuntimeError("A429 protocol commitment differs")
    load_implementation(value["implementation_sha256"])
    return value


def load_resume(worker: str, protocol_sha256: str, order_sha: str, tasks_sha: str) -> tuple[int, float, int, dict[str, Any] | None]:
    path = progress_path(worker)
    if not path.exists():
        return 0, 0.0, 0, None
    value = json.loads(path.read_bytes())
    if (
        value.get("schema") != "chacha20-round20-w50-a428-global-wavefront-recovery-a429-progress-v1"
        or value.get("attempt_id") != ATTEMPT_ID
        or value.get("worker_role") != worker
        or value.get("protocol_sha256") != protocol_sha256
        or value.get("worker_order_uint16be_sha256") != order_sha
        or value.get("worker_task_list_sha256") != tasks_sha
    ):
        raise RuntimeError("A429 progress fingerprint differs")
    completed = int(value.get("executed_worker_prefix_groups", -1))
    if not 0 <= completed <= STATIC_EPOCHS:
        raise RuntimeError("A429 resumable progress count differs")
    status = value.get("status")
    if status in {"candidate_found", "worker_exhausted", "peer_confirmed"}:
        return completed, float(value.get("gpu_seconds", 0.0)), int(value.get("host_instances", 0)), value
    if status != "running":
        raise RuntimeError("A429 resumable progress status differs")
    return completed, float(value.get("gpu_seconds", 0.0)), int(value.get("host_instances", 0)), None


def ordered_worker_discovery(*, worker: str, host_factory: Callable[[], Any], challenge: Mapping[str, Any], worker_order: Sequence[int], worker_tasks: Sequence[Mapping[str, Any]], peer_result_exists: Callable[[], bool], start_group: int = 0, prior_gpu_seconds: float = 0.0, prior_host_instances: int = 0, progress_callback: Callable[[Mapping[str, Any]], None] | None = None) -> dict[str, Any]:
    order, tasks = exact_worker_schedule(worker_order, worker_tasks, worker)
    if not 0 <= start_group <= len(order):
        raise ValueError("A429 resume group lies outside worker schedule")
    if peer_result_exists():
        return {"status": "peer_confirmed", "worker_role": worker, "executed_worker_prefix_groups": start_group, "worker_prefix_groups": len(order), "gpu_seconds": prior_gpu_seconds, "host_instances": prior_host_instances}
    target = np.asarray(challenge["target_words"][0], dtype=np.uint32)
    control = np.asarray(challenge["control_target_words"], dtype=np.uint32)
    host: Any | None = None
    host_instances = prior_host_instances
    gpu_seconds = prior_gpu_seconds
    started = time.perf_counter()
    try:
        for index in range(start_group, len(order)):
            if peer_result_exists():
                return {"status": "peer_confirmed", "worker_role": worker, "executed_worker_prefix_groups": index, "worker_prefix_groups": len(order), "gpu_seconds": gpu_seconds, "host_instances": host_instances, "volatile_wall_seconds": time.perf_counter() - started}
            task = tasks[index]
            prefix = order[index]
            if index == start_group or index % HOST_REFRESH_GROUPS == 0:
                if host is not None:
                    host.close()
                host = host_factory()
                host_instances += 1
            observed = A397.A395.A393.A389.A384.filter_complete_prefix(host=host, challenge=challenge, prefix=prefix, target=target, control=control)
            factual = [int(value) for value in observed["factual_candidates"]]
            controls = [int(value) for value in observed["control_candidates"]]
            gpu_seconds += float(observed["gpu_seconds"])
            groups = index + 1
            if controls:
                raise RuntimeError("A429 matched control produced a candidate")
            progress = {
                "executed_worker_prefix_groups": groups,
                "worker_prefix_groups": len(order),
                "executed_worker_assignments": groups * GROUP_SIZE,
                "static_schedule_epoch": int(task["epoch"]),
                "global_position_one_based": int(task["global_position_one_based"]),
                "matched_control_candidates": 0,
                "gpu_seconds": gpu_seconds,
                "host_instances": host_instances,
                "last_completed_prefix12": prefix,
                "last_best_source_rank_one_based": int(task["best_source_rank_one_based"]),
                "last_best_source_role": task["best_source_role"],
            }
            if not factual:
                if progress_callback is not None:
                    progress_callback({"status": "running", "factual_filter_candidates": 0, **progress})
                continue
            if len(factual) != 1:
                raise RuntimeError("A429 complete W50 group produced multiple factual filters")
            candidate = factual[0]
            if ((candidate >> WORD0_SUFFIX_BITS) & (CELLS - 1)) != prefix:
                raise RuntimeError("A429 candidate prefix differs")
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
    exhausted = {"status": "worker_exhausted", "worker_role": worker, "worker_slug": ROLE_TO_SLUG[worker], "executed_worker_prefix_groups": len(order), "worker_prefix_groups": len(order), "executed_worker_assignments": len(order) * GROUP_SIZE, "static_schedule_epoch": len(order), "matched_control_candidates": 0, "factual_filter_candidates": 0, "gpu_seconds": gpu_seconds, "host_instances": host_instances, "volatile_wall_seconds": time.perf_counter() - started}
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
            panel[worker] = {"status": "not_started", "executed_worker_prefix_groups": 0, "worker_prefix_groups": STATIC_EPOCHS}
            continue
        value = json.loads(path.read_bytes())
        if (
            value.get("protocol_sha256") != file_sha256(PROTOCOL)
            or value.get("worker_role") != worker
            or value.get("worker_order_uint16be_sha256") != protocol["worker_order_uint16be_sha256"][worker]
            or value.get("worker_task_list_sha256") != protocol["worker_task_list_sha256"][worker]
        ):
            raise RuntimeError("A429 progress snapshot fingerprint differs")
        groups = int(value.get("executed_worker_prefix_groups", 0))
        total_groups += groups
        max_epoch = max(max_epoch, int(value.get("static_schedule_epoch", 0)))
        all_control_zero &= value.get("matched_control_candidates") == 0
        panel[worker] = {"status": value.get("status"), "executed_worker_prefix_groups": groups, "worker_prefix_groups": STATIC_EPOCHS, "static_schedule_epoch": int(value.get("static_schedule_epoch", 0)), "gpu_seconds": float(value.get("gpu_seconds", 0.0)), "matched_control_candidates": value.get("matched_control_candidates")}
    return {"workers": panel, "total_unique_prefix_groups_evaluated": total_groups, "total_unique_assignments_evaluated": total_groups * GROUP_SIZE, "maximum_completed_static_schedule_epoch": max_epoch, "theoretical_complete_schedule_epochs": STATIC_EPOCHS, "complete_domain_assignments": DOMAIN_SIZE, "all_observed_matched_controls_empty": all_control_zero, "prefix_sets_are_disjoint_by_A428_construction": True}


def rank_panel(prefix: int, worker: str, protocol: Mapping[str, Any]) -> dict[str, Any]:
    source, _orders, _tasks = load_source_schedule()
    epoch = int(source["production_cell_epoch_one_based"][prefix])
    if source["production_cell_worker_role"][prefix] != worker:
        raise RuntimeError("A429 confirmed prefix worker differs")
    global_position = source["production_global_order"].index(prefix) + 1
    task = protocol["worker_tasks"][worker][epoch - 1]
    if int(task["cell"]) != prefix or int(task["global_position_one_based"]) != global_position:
        raise RuntimeError("A429 confirmed task lookup differs")
    best_rank = int(source["production_cell_best_source_rank_one_based"][prefix])
    return {
        "cell": prefix,
        "A428_global_epoch_one_based": epoch,
        "A428_global_position_one_based": global_position,
        "A428_worker_role": worker,
        "A428_worker_step_one_based": int(task["worker_step_one_based"]),
        "best_source_rank_one_based": best_rank,
        "best_source_role": task["best_source_role"],
        "exact_depth_chain_holds": epoch <= best_rank,
        "ranks_computed_only_after_independent_confirmation": True,
    }


def build_causal(payload: Mapping[str, Any]) -> dict[str, Any]:
    sys.path.insert(0, str(DOTCAUSAL_SRC))
    from dotcausal.io import CausalReader, CausalWriter

    terminal = "A429:confirmed_global_wavefront_W50_recovery"
    writer = CausalWriter(api_id="a429w50")
    writer._rules = []
    writer.add_rule(name="wavefront_and_engine_to_model", description="A428's exact static worker lists execute complete qualified W50 groups with one shared confirmed-success stop.", pattern=["A428_global_best_rank_wavefront", "A384_exact_W50_group_engine"], conclusion="A429_sole_factual_W50_model", confidence_modifier=1.0)
    writer.add_rule(name="model_to_confirmed_recovery", description="The sole factual model passes the matched control and dual independent eight-block confirmation.", pattern=["A429_sole_factual_W50_model"], conclusion="A429_confirmed_global_wavefront_W50_recovery", confidence_modifier=1.0)
    writer.add_triplet(trigger="A428:global_best_rank_wavefront", mechanism="qualified_eight_worker_complete_group_search_with_shared_stop", outcome="A429:sole_factual_W50_model", confidence=1.0, source=payload["execution_sha256"], quantification=json.dumps(payload["aggregate_execution"], sort_keys=True), evidence=json.dumps(payload["rank_analysis"], sort_keys=True), domain="sealed full-round ChaCha20 W50 global-wavefront recovery", quality_score=1.0)
    writer.add_triplet(trigger="A429:sole_factual_W50_model", mechanism="matched_control_rejection_and_dual_eight_block_confirmation", outcome=terminal, confidence=1.0, source=payload["measurement_sha256"], quantification=json.dumps(payload["confirmation"], sort_keys=True), evidence=payload["evidence_stage"], domain="confirmed full-round ChaCha20 W50 recovery", quality_score=1.0)
    writer.add_triplet(trigger="A428:global_best_rank_wavefront", mechanism="materialized_search_and_confirmation_closure", outcome=terminal, confidence=1.0, source="materialized:A429_global_wavefront_recovery_chain", quantification="exact retained closure", evidence=payload["evidence_stage"], domain="AI-native retained inference", quality_score=1.0, is_inferred=True)
    writer.add_cluster(name="A429 global-wavefront W50 recovery", entities=["A428:global_best_rank_wavefront", "A429:sole_factual_W50_model", terminal])
    writer.add_gap(subject=terminal, predicate="next_required_object", expected_object_type="W51_global_wavefront_transfer", confidence=1.0, suggested_queries=["Transfer the global best-rank scheduler after W51 engine qualification and a fresh W51 public-output field."])
    temporary = CAUSAL.with_name(f".{CAUSAL.name}.tmp")
    temporary.unlink(missing_ok=True)
    stats = writer.save(str(temporary))
    os.replace(temporary, CAUSAL)
    reader = CausalReader(str(CAUSAL), verify_integrity=True)
    explicit = reader.get_all_triplets(include_inferred=False)
    all_rows = reader.get_all_triplets(include_inferred=True)
    inferred = [row for row in reader._triplets if row.get("is_inferred", False)]
    if reader.api_id != "a429w50" or len(explicit) != 2 or len(all_rows) != 3 or len(inferred) != 1 or len(reader._rules) != 2 or len(reader._clusters) != 1 or len(reader._gaps) != 1:
        raise RuntimeError("A429 authentic Causal reopen gate failed")
    return {"format": "authentic_dotcausal_v1_AI_native", "path": relative(CAUSAL), "sha256": file_sha256(CAUSAL), "api_id": reader.api_id, "explicit_triplets": len(explicit), "materialized_inferred_triplets": len(inferred), "embedded_rules": len(reader._rules), "clusters": len(reader._clusters), "gaps": len(reader._gaps), "reader_source": anchor(Path(inspect.getsourcefile(CausalReader) or "")), "writer_stats": stats, "personal_semantic_readback": {"terminal_chain": all_rows[-1], "next_gap": reader._gaps[0]}}


def recover_worker(*, worker: str, expected_protocol_sha256: str) -> dict[str, Any]:
    if RESULT.exists():
        return {"status": "peer_confirmed", "worker_role": worker, "result_sha256": file_sha256(RESULT)}
    protocol = load_protocol(expected_protocol_sha256)
    qualification = A397.A395.A393.A389.A385.load_a384_qualification(protocol["A384_qualification_sha256"])
    engine_protocol = A397.A395.A393.A389.A384.load_protocol(A397.A395.A393.A389.A384_PROTOCOL_SHA256)
    executable_row = engine_protocol["anchors"]["grouped_executable"]
    executable = path_from_ref(executable_row["path"])
    anchor(executable, executable_row["sha256"])
    challenge = protocol["public_challenge"]
    order, tasks = exact_worker_schedule(protocol["worker_cell_orders"][worker], protocol["worker_tasks"][worker], worker)
    placeholder = np.asarray([0, 0], dtype=np.uint32)

    def host_factory() -> Any:
        return A397.A395.A393.A389.A384.A378.A371.A346.A324.A311.A307.A304.GroupedMetalHost(executable, A397.A395.A393.A389.A384.initial_for_slab(challenge, 0), placeholder, placeholder)

    order_hash = protocol["worker_order_uint16be_sha256"][worker]
    tasks_hash = protocol["worker_task_list_sha256"][worker]

    def write_progress(row: Mapping[str, Any]) -> None:
        atomic_json(progress_path(worker), {"schema": "chacha20-round20-w50-a428-global-wavefront-recovery-a429-progress-v1", "attempt_id": ATTEMPT_ID, "worker_role": worker, "worker_slug": ROLE_TO_SLUG[worker], "protocol_sha256": expected_protocol_sha256, "worker_order_uint16be_sha256": order_hash, "worker_task_list_sha256": tasks_hash, "A384_qualification_sha256": protocol["A384_qualification_sha256"], **dict(row)})

    start, prior_gpu, prior_hosts, completed = load_resume(worker, expected_protocol_sha256, order_hash, tasks_hash)
    if completed is not None and completed.get("status") in {"worker_exhausted", "peer_confirmed"}:
        return completed
    discovery = completed if completed is not None else ordered_worker_discovery(worker=worker, host_factory=host_factory, challenge=challenge, worker_order=order, worker_tasks=tasks, peer_result_exists=RESULT.exists, start_group=start, prior_gpu_seconds=prior_gpu, prior_host_instances=prior_hosts, progress_callback=write_progress)
    if discovery["status"] in {"peer_confirmed", "worker_exhausted"}:
        if discovery["status"] == "worker_exhausted":
            exhausted = sum(progress_path(other).exists() and json.loads(progress_path(other).read_bytes()).get("status") == "worker_exhausted" for other in ROLES)
            if exhausted == len(ROLES) and not RESULT.exists():
                raise RuntimeError("A429 all static workers exhausted without a model")
        return discovery
    candidate = int(discovery["candidate"])
    confirmation = A397.A395.A393.A389.A385.confirm(challenge, candidate)
    if confirmation["all_blocks_match"] is not True:
        raise RuntimeError("A429 dual independent confirmation failed")
    if RESULT.exists():
        return {"status": "peer_confirmed", "worker_role": worker, "result_sha256": file_sha256(RESULT)}
    ranks = rank_panel(int(discovery["prefix12"]), worker, protocol)
    if int(ranks["A428_global_epoch_one_based"]) != discovery["static_schedule_epoch"] or ranks["A428_worker_step_one_based"] != discovery["executed_worker_prefix_groups"] or ranks["exact_depth_chain_holds"] is not True:
        raise RuntimeError("A429 discovery depth differs from A428 schedule")
    aggregate = progress_snapshot(protocol)
    unique_groups = int(aggregate["total_unique_prefix_groups_evaluated"])
    if not 1 <= unique_groups <= CELLS:
        raise RuntimeError("A429 aggregate unique group count differs")
    strict_subset = unique_groups < CELLS
    aggregate["strict_subset_of_complete_domain"] = strict_subset
    aggregate["domain_reduction_factor"] = CELLS / unique_groups
    aggregate["search_gain_bits"] = math.log2(CELLS / unique_groups)
    evidence_stage = "FULLROUND_R20_GLOBAL_WAVEFRONT_W50_STRICT_SUBSET_RECOVERY_CONFIRMED" if strict_subset else "FULLROUND_R20_GLOBAL_WAVEFRONT_W50_COMPLETE_DOMAIN_RECOVERY_CONFIRMED"
    payload: dict[str, Any] = {
        "schema": "chacha20-round20-w50-a428-global-wavefront-recovery-a429-result-v1",
        "attempt_id": ATTEMPT_ID,
        "evidence_stage": evidence_stage,
        "protocol_sha256": expected_protocol_sha256,
        "design_sha256": DESIGN_SHA256,
        "implementation_sha256": protocol["implementation_sha256"],
        "A384_qualification_sha256": protocol["A384_qualification_sha256"],
        "A385_protocol_sha256": protocol["A385_protocol_sha256"],
        "A428_result_sha256": protocol["A428_result_sha256"],
        "A428_schedule_commitment_sha256": protocol["A428_schedule_commitment_sha256"],
        "public_challenge_sha256": protocol["public_challenge_sha256"],
        "winning_worker_role": worker,
        "winning_worker_slug": ROLE_TO_SLUG[worker],
        "discovery": discovery,
        "aggregate_execution": aggregate,
        "rank_analysis": ranks,
        "confirmation": confirmation,
        "strict_subset_of_complete_domain": strict_subset,
        "qualification_gate": {"evidence_stage": qualification["evidence_stage"], "qualification_sha256": qualification["qualification_sha256"], "complete_W50_group_candidates": qualification["complete_group_gate"]["logical_candidates"], "synthetic_filter_exact": qualification["synthetic_filter_exact"], "production_target_used": False},
        "information_boundary": protocol["information_boundary"],
        "anchors": protocol["anchors"],
    }
    stable_discovery = {key: item for key, item in discovery.items() if not key.startswith("volatile_")}
    payload["execution_sha256"] = canonical_sha256({"winning_worker_role": worker, "winning_worker_order_uint16be_sha256": order_hash, "winning_worker_task_list_sha256": tasks_hash, "discovery": stable_discovery, "aggregate_execution": aggregate, "A384_qualification_sha256": protocol["A384_qualification_sha256"]})
    payload["measurement_sha256"] = canonical_sha256({"discovery": stable_discovery, "aggregate_execution": aggregate, "rank_analysis": ranks, "confirmation": confirmation, "qualification_gate": payload["qualification_gate"], "information_boundary": payload["information_boundary"]})
    payload["causal"] = build_causal(payload)
    atomic_json(RESULT, payload)
    atomic_bytes(REPORT, ("# A429 — global-wavefront full-round ChaCha20 W50 recovery\n\n" f"Evidence stage: **{evidence_stage}**\n\n" f"- Winning worker: **{worker}**\n" f"- A428 global epoch: **{ranks['A428_global_epoch_one_based']} / {STATIC_EPOCHS}**\n" f"- Exact unique prefix groups evaluated: **{unique_groups} / {CELLS}**\n" f"- Complete candidate evaluations: **{aggregate['total_unique_assignments_evaluated']:,} / {DOMAIN_SIZE:,}**\n" f"- Recovered W50 assignment: **0x{candidate:013x}**\n" "- Standard ChaCha20: **20 rounds plus feed-forward**\n" "- Every prefix: **128 complete 2^31 slabs before outcome evaluation**\n" "- Duplicate A429 prefix groups: **zero by construction**\n" "- Matched one-bit control: **zero candidates**\n" "- Dual independent confirmation: **8,192 checked bits**\n" "- Authentic AI-native Causal readback: **2 explicit + 1 inferred chain**\n").encode())
    return payload


def analyze() -> dict[str, Any]:
    payload: dict[str, Any] = {"attempt_id": ATTEMPT_ID, "design_sha256": DESIGN_SHA256, "implementation_frozen": IMPLEMENTATION.exists(), "protocol_frozen": PROTOCOL.exists(), "result_complete": RESULT.exists(), "worker_progress": {}}
    if IMPLEMENTATION.exists():
        payload["implementation_sha256"] = file_sha256(IMPLEMENTATION)
    if PROTOCOL.exists():
        payload["protocol_sha256"] = file_sha256(PROTOCOL)
    for worker in ROLES:
        path = progress_path(worker)
        if path.exists():
            payload["worker_progress"][worker] = json.loads(path.read_bytes())
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
        payload = freeze_protocol(expected_implementation_sha256=args.expected_implementation_sha256)
    elif args.recover_worker:
        if not args.expected_protocol_sha256:
            parser.error("--recover-worker requires --expected-protocol-sha256")
        payload = recover_worker(worker=SLUG_TO_ROLE[args.recover_worker], expected_protocol_sha256=args.expected_protocol_sha256)
    else:
        payload = analyze()
    print(json.dumps(payload, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()

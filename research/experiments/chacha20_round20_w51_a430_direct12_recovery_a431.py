#!/usr/bin/env python3
"""A431: execute A430's zero-refit W51 Direct12 schedule on the sealed A425 target."""

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
STEM = "chacha20_round20_w51_a430_direct12_recovery_a431"
DESIGN = CONFIGS / f"{STEM}_design_v1.json"
IMPLEMENTATION = CONFIGS / f"{STEM}_implementation_v1.json"
PROTOCOL = CONFIGS / f"{STEM}_v1.json"
RESULT = RESULTS / f"{STEM}_v1.json"
STOP = RESULTS / f"{STEM}_confirmed_stop_v1.json"
CAUSAL = RESULT.with_suffix(".causal")
REPORT = RESULT.with_suffix(".md")
TEST = ROOT / f"tests/test_{STEM}.py"
REPRO = ROOT / f"scripts/reproduce_{STEM}.sh"

A430_RUNNER = (
    RESEARCH / "experiments/chacha20_round20_w51_public_output_direct12_eight_worker_a430.py"
)
A430_DESIGN = (
    CONFIGS / "chacha20_round20_w51_public_output_direct12_eight_worker_a430_design_v1.json"
)
A430_IMPLEMENTATION = (
    CONFIGS / "chacha20_round20_w51_public_output_direct12_eight_worker_a430_implementation_v1.json"
)
A430_PREFLIGHT = (
    RESULTS / "chacha20_round20_w51_public_output_direct12_eight_worker_a430_preflight_v1.json"
)
A430_RESULT = RESULTS / "chacha20_round20_w51_public_output_direct12_eight_worker_a430_v1.json"
A430_CAUSAL = A430_RESULT.with_suffix(".causal")
A425_RUNNER = RESEARCH / "experiments/chacha20_round20_w51_a416_fresh_shared_stop_recovery_a425.py"
A425_IMPLEMENTATION = (
    CONFIGS / "chacha20_round20_w51_a416_fresh_shared_stop_recovery_a425_implementation_v1.json"
)
A425_PROTOCOL = CONFIGS / "chacha20_round20_w51_a416_fresh_shared_stop_recovery_a425_v1.json"
A425_RESULT = RESULTS / "chacha20_round20_w51_a416_fresh_shared_stop_recovery_a425_v1.json"
A390_RUNNER = (
    RESEARCH / "experiments/chacha20_round20_w51_twohundredfiftysix_slab_grouped_engine_a390.py"
)
A390_PROTOCOL = CONFIGS / "chacha20_round20_w51_twohundredfiftysix_slab_grouped_engine_a390_v1.json"
A390_QUALIFICATION = (
    RESULTS
    / "chacha20_round20_w51_twohundredfiftysix_slab_grouped_engine_a390_qualification_v1.json"
)

ATTEMPT_ID = "A431"
DESIGN_SHA256 = "776e4af0e1e3cfcf1dade8bed568e810dde3578eca08f42bfa80f98cc1a42c0e"
A430_RUNNER_SHA256 = "9170de08db7beab18eb83527778d74506b49f3d65238b598577b592a8101b54b"
A430_DESIGN_SHA256 = "4c776b7fae5a90087f13847f182ea6eadf493f4e949779751ba1fd88a84b1372"
A430_IMPLEMENTATION_SHA256 = "9ea7306c15e95806b04e6e64aa008e6d9995a1b8e26dca3af5ba3dbe66db414c"
A430_PREFLIGHT_SHA256 = "ca4f6ad583e99f1793de680ce633f25a25cdbc2713b175ef4c7b9262e213f0ae"
A430_RESULT_SHA256 = "12c3f60fbc7dde8bbaa32ff7d13272a422b094d999a3c99ae16f1efd4c21f89a"
A430_CAUSAL_SHA256 = "3e55b2bc31bc005d0857f1135bfc9565d49cb069cb887f8decd382626c2db987"
A430_SCHEDULE_COMMITMENT_SHA256 = "f09ba710b03e70dc772ec3436be30cd90b64efae4bc0af5a5b055ff996cf052c"
A425_RUNNER_SHA256 = "5d8956a56f8f2f1634e73dad90596de9b0ee369c1d716b45d0d8714588a8f78b"
A425_IMPLEMENTATION_SHA256 = "5a15e774b0e3606d2b33c9ba014efd63d9350b8da9846def54cd5fe603178a1a"
A425_PROTOCOL_SHA256 = "a36b7352e8553c7e9989190877958976957a8c96022abff406f65aecf6417d0e"
A390_RUNNER_SHA256 = "1864f7ecd5fb448219784b1a9e514cfddfb3f77f16e46f0d6104f8a778338330"
A390_PROTOCOL_SHA256 = "d13d5c0b34de900bdc2d3abe26706b508091685e6a1c7a640168ab5496e479d0"

WIDTH = 51
CELLS = 1 << 12
WORKERS = 8
STATIC_EPOCHS = CELLS // WORKERS
GROUP_SIZE = 1 << 39
DOMAIN_SIZE = 1 << WIDTH
SLABS = 256
WORD0_SUFFIX_BITS = 20
HOST_REFRESH_GROUPS = 2
ROLES = tuple(f"direct_wave_{index}" for index in range(WORKERS))
ROLE_TO_INDEX = {role: index for index, role in enumerate(ROLES)}
DOTCAUSAL_SRC = Path("/Users/bhkmie/Documents/Forschung/O1/vendor/fabel/dotcausal_package/src")


def load_module(path: Path, name: str) -> Any:
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot import A431 dependency {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


A430 = load_module(A430_RUNNER, "a431_a430")
A425 = load_module(A425_RUNNER, "a431_a425")
file_sha256 = A425.file_sha256
canonical_sha256 = A425.canonical_sha256
atomic_json = A425.atomic_json
atomic_bytes = A425.atomic_bytes
relative = A425.relative
path_from_ref = A425.path_from_ref
anchor = A425.anchor


def progress_path(worker: str) -> Path:
    if worker not in ROLE_TO_INDEX:
        raise ValueError(f"A431 unknown worker {worker}")
    return RESULTS / f"{STEM}_worker_{ROLE_TO_INDEX[worker]}_progress_v1.json"


def no_downstream_artifacts() -> bool:
    return not any(
        path.exists()
        for path in (
            PROTOCOL,
            RESULT,
            STOP,
            CAUSAL,
            REPORT,
            *(progress_path(role) for role in ROLES),
        )
    )


def assert_no_A425_outcome() -> None:
    paths = (
        A425_RESULT,
        A425.STOP,
        *(A425.progress_path(index) for index in range(A425.WORKERS)),
    )
    if any(path.exists() for path in paths):
        raise RuntimeError(
            "A431 freeze must precede every A425 result, stop, progress, or filter outcome"
        )


def load_design() -> dict[str, Any]:
    if file_sha256(DESIGN) != DESIGN_SHA256:
        raise RuntimeError("A431 design hash differs")
    value = json.loads(DESIGN.read_bytes())
    execution = value.get("execution_contract", {})
    schedule = value.get("schedule_contract", {})
    engine = value.get("engine_gate_contract", {})
    boundary = value.get("information_boundary", {})
    if (
        value.get("schema") != "chacha20-round20-w51-a430-direct12-recovery-a431-design-v1"
        or value.get("attempt_id") != ATTEMPT_ID
        or value.get("design_state")
        != "frozen_after_A430_public_output_schedule_before_any_A425_or_A431_candidate_progress_or_filter_outcome"
        or execution.get("full_rounds") != 20
        or execution.get("feedforward_included") is not True
        or execution.get("unknown_key_bits") != WIDTH
        or execution.get("complete_prefix_groups") != CELLS
        or execution.get("candidates_per_prefix_group") != GROUP_SIZE
        or execution.get("complete_domain_assignments") != DOMAIN_SIZE
        or execution.get("slabs_per_prefix_group") != SLABS
        or execution.get("workers") != WORKERS
        or execution.get("worker_tasks_each") != STATIC_EPOCHS
        or execution.get("complete_group_before_success_evaluation") is not True
        or execution.get("shared_stop_only_after_independent_confirmation") is not True
        or schedule.get("source_result_available_at_design_freeze") is not True
        or schedule.get("source_result_sha256") != A430_RESULT_SHA256
        or schedule.get("source_causal_sha256") != A430_CAUSAL_SHA256
        or schedule.get("source_schedule_commitment_sha256") != A430_SCHEDULE_COMMITMENT_SHA256
        or schedule.get("source_reader_refits_on_A425") != 0
        or schedule.get("source_target_labels_used") != 0
        or schedule.get("source_candidate_assignments_executed") != 0
        or schedule.get(
            "copy_all_eight_worker_orders_and_tasks_byte_identically_after_A430_completion"
        )
        is not True
        or engine.get("qualification_available_at_design_freeze") is not False
        or boundary.get("A430_result_available_at_design_freeze") is not True
        or boundary.get("A430_result_contains_target_label_or_true_prefix") is not False
        or boundary.get("A430_result_target_labels_used") != 0
        or boundary.get("A430_result_reader_refits") != 0
        or boundary.get("A430_result_candidate_assignments_executed") != 0
        or boundary.get("A425_result_available_at_design_freeze") is not False
        or boundary.get("A425_progress_or_filter_outcomes_available_at_design_freeze") is not False
        or boundary.get("A431_candidate_or_progress_available_at_design_freeze") is not False
        or boundary.get("A431_target_assignment_or_true_prefix_available_at_design_freeze")
        is not False
        or boundary.get("A431_target_labels_used_for_schedule") != 0
        or boundary.get("A431_reader_refits") != 0
        or boundary.get("prior_live_recovery_filter_outcomes_consumed") is not False
    ):
        raise RuntimeError("A431 frozen design semantics differ")
    for key, item in value["source_anchors"].items():
        if key.endswith("_path"):
            stem = key.removesuffix("_path")
            anchor(ROOT / item, value["source_anchors"][f"{stem}_sha256"])
    return value


def exact_worker_schedule(
    values: Sequence[int],
    tasks: Sequence[Mapping[str, Any]],
    worker: str,
) -> tuple[list[int], list[dict[str, Any]]]:
    if worker not in ROLE_TO_INDEX:
        raise ValueError(f"A431 unknown worker {worker}")
    order = [int(value) for value in values]
    rows = [dict(value) for value in tasks]
    if (
        len(order) != STATIC_EPOCHS
        or len(rows) != STATIC_EPOCHS
        or len(set(order)) != STATIC_EPOCHS
        or any(not 0 <= cell < CELLS for cell in order)
    ):
        raise ValueError(f"A431 {worker} schedule geometry differs")
    worker_index = ROLE_TO_INDEX[worker]
    for step, (cell, row) in enumerate(zip(order, rows, strict=True), 1):
        global_position = (step - 1) * WORKERS + worker_index + 1
        if (
            int(row.get("cell", -1)) != cell
            or int(row.get("epoch", -1)) != step
            or row.get("worker_role") != worker
            or int(row.get("worker_step_one_based", -1)) != step
            or int(row.get("global_position_one_based", -1)) != global_position
            or int(row.get("direct12_rank_one_based", -1)) != global_position
        ):
            raise ValueError(f"A431 {worker} task semantics differ at step {step}")
    return order, rows


def load_source_schedule(
    expected_result_sha256: str | None = None,
) -> tuple[dict[str, Any], dict[str, list[int]], dict[str, list[dict[str, Any]]]]:
    if expected_result_sha256 is not None:
        anchor(A430_RESULT, expected_result_sha256)
    source = json.loads(A430_RESULT.read_bytes())
    if (
        source.get("schema")
        != "chacha20-round20-w51-public-output-direct12-eight-worker-a430-result-v1"
        or source.get("attempt_id") != "A430"
        or source.get("evidence_stage")
        != "PRE_A425_RESULT_COMPLETE_PUBLIC_OUTPUT_DIRECT12_W51_EIGHT_WORKER_SCHEDULE_FROZEN"
        or source.get("A425_protocol_sha256") != A425_PROTOCOL_SHA256
        or source.get("A425_result_or_true_prefix_available_at_schedule_freeze") is not False
        or source.get("A425_progress_or_filter_outcomes_consumed") is not False
        or source.get("target_labels_used") != 0
        or source.get("reader_refits") != 0
        or source.get("candidate_assignments_executed") != 0
        or tuple(source.get("worker_roles", [])) != ROLES
    ):
        raise RuntimeError("A431 A430 source semantics differ")
    proof = source.get("schedule_proof", {})
    if (
        proof.get("complete_cover_cells") != CELLS
        or proof.get("duplicate_cells") != 0
        or proof.get("uncovered_cells") != 0
        or proof.get("workers") != WORKERS
        or proof.get("worker_tasks_each") != STATIC_EPOCHS
        or proof.get("makespan_epochs") != STATIC_EPOCHS
        or proof.get("makespan_optimal") is not True
        or proof.get("depth_identity") != "D_A430(c) = ceil(R_Direct12(c)/8)"
        or proof.get("depth_identity_violations") != 0
    ):
        raise RuntimeError("A431 A430 schedule proof differs")
    orders: dict[str, list[int]] = {}
    tasks: dict[str, list[dict[str, Any]]] = {}
    for worker in ROLES:
        orders[worker], tasks[worker] = exact_worker_schedule(
            source["worker_cell_orders"][worker],
            source["worker_tasks"][worker],
            worker,
        )
        if (
            A430.uint16be_sha256(orders[worker])
            != source["worker_cell_order_uint16be_sha256"][worker]
        ):
            raise RuntimeError(f"A431 {worker} source order commitment differs")
        if canonical_sha256(tasks[worker]) != source["worker_task_list_sha256"][worker]:
            raise RuntimeError(f"A431 {worker} source task commitment differs")
    flattened = [cell for worker in ROLES for cell in orders[worker]]
    if (
        len(flattened) != CELLS
        or len(set(flattened)) != CELLS
        or set(flattened) != set(range(CELLS))
    ):
        raise RuntimeError("A431 source worker lists are not one exact disjoint cover")
    schedule_commitment = canonical_sha256(
        {
            "order": source["W51_public_output_direct12_order_uint16be_sha256"],
            "workers": source["worker_cell_order_uint16be_sha256"],
            "tasks": source["worker_task_list_sha256"],
            "epochs": source["cell_epoch_one_based"],
        }
    )
    if schedule_commitment != source.get("schedule_commitment_sha256"):
        raise RuntimeError("A431 A430 schedule commitment differs")
    return source, orders, tasks


def freeze_implementation() -> dict[str, Any]:
    if IMPLEMENTATION.exists() or not no_downstream_artifacts():
        raise FileExistsError("A431 implementation or downstream artifact already exists")
    assert_no_A425_outcome()
    design = load_design()
    source, orders, tasks = load_source_schedule(A430_RESULT_SHA256)
    anchor(A430_CAUSAL, A430_CAUSAL_SHA256)
    if source["schedule_commitment_sha256"] != A430_SCHEDULE_COMMITMENT_SHA256:
        raise RuntimeError("A431 implementation source schedule differs")
    A425.load_protocol(A425_PROTOCOL_SHA256)
    if A390_QUALIFICATION.exists():
        raise RuntimeError("A431 implementation freeze must precede A390 qualification")
    if not TEST.exists() or not REPRO.exists():
        raise FileNotFoundError("A431 test and reproducer must precede implementation freeze")
    payload: dict[str, Any] = {
        "schema": "chacha20-round20-w51-a430-direct12-recovery-a431-implementation-v1",
        "attempt_id": ATTEMPT_ID,
        "commitment_state": "complete_A430_schedule_executor_frozen_after_public_schedule_before_any_A425_or_A431_candidate_progress_or_filter_outcome",
        "design_sha256": DESIGN_SHA256,
        "execution_contract": design["execution_contract"],
        "schedule_contract": design["schedule_contract"],
        "A430_result_available_at_freeze": True,
        "source_A430_result_sha256": A430_RESULT_SHA256,
        "source_A430_causal_sha256": A430_CAUSAL_SHA256,
        "source_A430_schedule_commitment_sha256": A430_SCHEDULE_COMMITMENT_SHA256,
        "source_worker_order_uint16be_sha256": {
            role: A430.uint16be_sha256(orders[role]) for role in ROLES
        },
        "source_worker_task_list_sha256": {role: canonical_sha256(tasks[role]) for role in ROLES},
        "A430_target_labels_used": 0,
        "A430_reader_refits": 0,
        "A430_candidate_assignments_executed": 0,
        "A390_qualification_available_at_freeze": False,
        "A425_result_or_progress_available_at_freeze": False,
        "A431_candidate_or_progress_available_at_freeze": False,
        "A431_target_labels_used": 0,
        "A431_reader_refits": 0,
        "prior_live_recovery_filter_outcomes_consumed": False,
        "anchors": {
            "design": anchor(DESIGN, DESIGN_SHA256),
            "A430_design": anchor(A430_DESIGN, A430_DESIGN_SHA256),
            "A430_implementation": anchor(A430_IMPLEMENTATION, A430_IMPLEMENTATION_SHA256),
            "A430_preflight": anchor(A430_PREFLIGHT, A430_PREFLIGHT_SHA256),
            "A430_runner": anchor(A430_RUNNER, A430_RUNNER_SHA256),
            "A430_result": anchor(A430_RESULT, A430_RESULT_SHA256),
            "A430_causal": anchor(A430_CAUSAL, A430_CAUSAL_SHA256),
            "A425_implementation": anchor(A425_IMPLEMENTATION, A425_IMPLEMENTATION_SHA256),
            "A425_protocol": anchor(A425_PROTOCOL, A425_PROTOCOL_SHA256),
            "A425_runner": anchor(A425_RUNNER, A425_RUNNER_SHA256),
            "A390_protocol": anchor(A390_PROTOCOL, A390_PROTOCOL_SHA256),
            "A390_runner": anchor(A390_RUNNER, A390_RUNNER_SHA256),
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
        raise RuntimeError("A431 implementation hash differs")
    value = json.loads(IMPLEMENTATION.read_bytes())
    if (
        value.get("schema") != "chacha20-round20-w51-a430-direct12-recovery-a431-implementation-v1"
        or value.get("attempt_id") != ATTEMPT_ID
        or value.get("commitment_state")
        != "complete_A430_schedule_executor_frozen_after_public_schedule_before_any_A425_or_A431_candidate_progress_or_filter_outcome"
        or value.get("design_sha256") != DESIGN_SHA256
        or value.get("A430_result_available_at_freeze") is not True
        or value.get("source_A430_result_sha256") != A430_RESULT_SHA256
        or value.get("source_A430_causal_sha256") != A430_CAUSAL_SHA256
        or value.get("source_A430_schedule_commitment_sha256") != A430_SCHEDULE_COMMITMENT_SHA256
        or value.get("A430_target_labels_used") != 0
        or value.get("A430_reader_refits") != 0
        or value.get("A430_candidate_assignments_executed") != 0
        or value.get("A390_qualification_available_at_freeze") is not False
        or value.get("A425_result_or_progress_available_at_freeze") is not False
        or value.get("A431_candidate_or_progress_available_at_freeze") is not False
        or value.get("A431_target_labels_used") != 0
        or value.get("A431_reader_refits") != 0
        or value.get("prior_live_recovery_filter_outcomes_consumed") is not False
    ):
        raise RuntimeError("A431 implementation semantics differ")
    for row in value["anchors"].values():
        anchor(path_from_ref(row["path"]), row["sha256"])
    unsigned = {
        key: item for key, item in value.items() if key != "implementation_commitment_sha256"
    }
    if value["implementation_commitment_sha256"] != canonical_sha256(unsigned):
        raise RuntimeError("A431 implementation commitment differs")
    return value


def freeze_protocol(
    *,
    expected_implementation_sha256: str,
    expected_a430_result_sha256: str,
) -> dict[str, Any]:
    if not no_downstream_artifacts():
        raise FileExistsError("A431 protocol or execution artifact already exists")
    assert_no_A425_outcome()
    implementation = load_implementation(expected_implementation_sha256)
    source, orders, tasks = load_source_schedule(expected_a430_result_sha256)
    base = A425.load_protocol(A425_PROTOCOL_SHA256)
    challenge = dict(base["public_challenge"])
    A425.validate_challenge(challenge)
    if canonical_sha256(challenge) != source["A425_public_challenge_sha256"]:
        raise RuntimeError("A431 A430/A425 public challenge identity differs")
    payload: dict[str, Any] = {
        "schema": "chacha20-round20-w51-a430-direct12-recovery-a431-protocol-v1",
        "attempt_id": ATTEMPT_ID,
        "protocol_state": "A430_zero_refit_Direct12_schedule_and_A425_public_challenge_bound_before_any_A425_or_A431_candidate_progress_or_filter_outcome",
        "design_sha256": DESIGN_SHA256,
        "implementation_sha256": expected_implementation_sha256,
        "implementation_commitment_sha256": implementation["implementation_commitment_sha256"],
        "A430_result_sha256": expected_a430_result_sha256,
        "A430_causal_sha256": file_sha256(A430_CAUSAL),
        "A430_schedule_commitment_sha256": source["schedule_commitment_sha256"],
        "A425_protocol_sha256": A425_PROTOCOL_SHA256,
        "A390_protocol_sha256": A390_PROTOCOL_SHA256,
        "public_challenge": challenge,
        "public_challenge_sha256": canonical_sha256(challenge),
        "worker_roles": list(ROLES),
        "worker_cell_orders": orders,
        "worker_tasks": tasks,
        "worker_order_uint16be_sha256": {
            role: A430.uint16be_sha256(orders[role]) for role in ROLES
        },
        "worker_task_list_sha256": {role: canonical_sha256(tasks[role]) for role in ROLES},
        "workers": WORKERS,
        "worker_tasks_each": STATIC_EPOCHS,
        "candidates_per_complete_group": GROUP_SIZE,
        "complete_domain_assignments": DOMAIN_SIZE,
        "information_boundary": {
            "A425_assignment_absent_from_protocol": True,
            "A425_true_prefix_absent_from_protocol": True,
            "A430_schedule_frozen_before_A431_execution": True,
            "A425_result_or_progress_available_at_protocol_freeze": False,
            "A431_candidate_or_progress_available_at_protocol_freeze": False,
            "A431_target_labels_used_for_schedule": 0,
            "A431_reader_refits": 0,
            "prior_live_recovery_filter_outcomes_consumed": False,
        },
        "anchors": {
            "implementation": anchor(IMPLEMENTATION, expected_implementation_sha256),
            "A430_result": anchor(A430_RESULT, expected_a430_result_sha256),
            "A430_causal": anchor(A430_CAUSAL),
            "A425_protocol": anchor(A425_PROTOCOL, A425_PROTOCOL_SHA256),
            "A390_protocol": anchor(A390_PROTOCOL, A390_PROTOCOL_SHA256),
            "runner": anchor(Path(__file__)),
        },
    }
    payload["protocol_commitment_sha256"] = canonical_sha256(payload)
    atomic_json(PROTOCOL, payload)
    return payload


def load_protocol(expected_sha256: str) -> dict[str, Any]:
    if file_sha256(PROTOCOL) != expected_sha256:
        raise RuntimeError("A431 protocol hash differs")
    value = json.loads(PROTOCOL.read_bytes())
    boundary = value.get("information_boundary", {})
    if (
        value.get("schema") != "chacha20-round20-w51-a430-direct12-recovery-a431-protocol-v1"
        or value.get("attempt_id") != ATTEMPT_ID
        or value.get("A425_protocol_sha256") != A425_PROTOCOL_SHA256
        or value.get("A390_protocol_sha256") != A390_PROTOCOL_SHA256
        or tuple(value.get("worker_roles", [])) != ROLES
        or value.get("workers") != WORKERS
        or value.get("worker_tasks_each") != STATIC_EPOCHS
        or value.get("candidates_per_complete_group") != GROUP_SIZE
        or value.get("complete_domain_assignments") != DOMAIN_SIZE
        or boundary.get("A425_assignment_absent_from_protocol") is not True
        or boundary.get("A425_true_prefix_absent_from_protocol") is not True
        or boundary.get("A425_result_or_progress_available_at_protocol_freeze") is not False
        or boundary.get("A431_candidate_or_progress_available_at_protocol_freeze") is not False
        or boundary.get("A431_target_labels_used_for_schedule") != 0
        or boundary.get("A431_reader_refits") != 0
        or boundary.get("prior_live_recovery_filter_outcomes_consumed") is not False
    ):
        raise RuntimeError("A431 protocol semantics differ")
    if canonical_sha256(value["public_challenge"]) != value["public_challenge_sha256"]:
        raise RuntimeError("A431 public challenge commitment differs")
    A425.validate_challenge(value["public_challenge"])
    source, source_orders, source_tasks = load_source_schedule(value["A430_result_sha256"])
    if value["A430_schedule_commitment_sha256"] != source["schedule_commitment_sha256"] or value[
        "A430_causal_sha256"
    ] != file_sha256(A430_CAUSAL):
        raise RuntimeError("A431 A430 source binding differs")
    for worker in ROLES:
        order, tasks = exact_worker_schedule(
            value["worker_cell_orders"][worker],
            value["worker_tasks"][worker],
            worker,
        )
        if order != source_orders[worker] or tasks != source_tasks[worker]:
            raise RuntimeError(f"A431 {worker} byte-identical A430 transfer differs")
        if A430.uint16be_sha256(order) != value["worker_order_uint16be_sha256"][worker]:
            raise RuntimeError(f"A431 {worker} order commitment differs")
        if canonical_sha256(tasks) != value["worker_task_list_sha256"][worker]:
            raise RuntimeError(f"A431 {worker} task commitment differs")
    for row in value["anchors"].values():
        anchor(path_from_ref(row["path"]), row["sha256"])
    unsigned = {key: item for key, item in value.items() if key != "protocol_commitment_sha256"}
    if value["protocol_commitment_sha256"] != canonical_sha256(unsigned):
        raise RuntimeError("A431 protocol commitment differs")
    load_implementation(value["implementation_sha256"])
    return value


def load_resume(
    worker: str,
    protocol_sha256: str,
    qualification_sha256: str,
    order_sha: str,
    tasks_sha: str,
) -> tuple[int, float, int, dict[str, Any] | None]:
    path = progress_path(worker)
    if not path.exists():
        return 0, 0.0, 0, None
    value = json.loads(path.read_bytes())
    if (
        value.get("schema") != "chacha20-round20-w51-a430-direct12-recovery-a431-progress-v1"
        or value.get("attempt_id") != ATTEMPT_ID
        or value.get("worker_role") != worker
        or value.get("protocol_sha256") != protocol_sha256
        or value.get("A390_qualification_sha256") != qualification_sha256
        or value.get("worker_order_uint16be_sha256") != order_sha
        or value.get("worker_task_list_sha256") != tasks_sha
        or value.get("matched_control_candidates") != 0
    ):
        raise RuntimeError("A431 progress fingerprint differs")
    status = value.get("status")
    completed = int(value.get("executed_worker_prefix_groups", -1))
    factual = value.get("factual_filter_candidates")
    if (
        status not in {"running", "candidate_found", "worker_exhausted", "peer_confirmed"}
        or not 0 <= completed <= STATIC_EPOCHS
        or (status == "candidate_found" and (not isinstance(factual, list) or len(factual) != 1))
        or (status != "candidate_found" and factual != 0)
    ):
        raise RuntimeError("A431 resumable progress state differs")
    if status in {"candidate_found", "worker_exhausted", "peer_confirmed"}:
        return (
            completed,
            float(value.get("gpu_seconds", 0.0)),
            int(value.get("host_instances", 0)),
            dict(value),
        )
    return (
        completed,
        float(value.get("gpu_seconds", 0.0)),
        int(value.get("host_instances", 0)),
        None,
    )


def ordered_worker_discovery(
    *,
    worker: str,
    order: Sequence[int],
    tasks: Sequence[Mapping[str, Any]],
    challenge: Mapping[str, Any],
    host_factory: Callable[[], Any],
    start_group: int,
    prior_gpu_seconds: float,
    prior_host_instances: int,
    progress_callback: Callable[[Mapping[str, Any]], None],
) -> dict[str, Any]:
    if (
        len(order) != STATIC_EPOCHS
        or len(tasks) != STATIC_EPOCHS
        or not 0 <= start_group <= STATIC_EPOCHS
    ):
        raise ValueError("A431 worker schedule geometry differs")
    target = np.asarray(challenge["target_words"][0], dtype=np.uint32)
    control = np.asarray(challenge["control_target_words"], dtype=np.uint32)
    host: Any | None = None
    gpu_seconds = prior_gpu_seconds
    host_instances = prior_host_instances
    started = time.perf_counter()
    try:
        for position in range(start_group, STATIC_EPOCHS):
            if STOP.exists() or RESULT.exists():
                return {
                    "status": "peer_confirmed",
                    "worker_role": worker,
                    "executed_worker_prefix_groups": position,
                    "worker_prefix_groups": STATIC_EPOCHS,
                    "executed_worker_assignments": position * GROUP_SIZE,
                    "static_schedule_epoch": position,
                    "factual_filter_candidates": 0,
                    "matched_control_candidates": 0,
                    "gpu_seconds": gpu_seconds,
                    "host_instances": host_instances,
                    "volatile_wall_seconds": time.perf_counter() - started,
                }
            prefix = int(order[position])
            task = tasks[position]
            if position == start_group or position % HOST_REFRESH_GROUPS == 0:
                if host is not None:
                    host.close()
                host = host_factory()
                host_instances += 1
            observed = A425.A390.filter_complete_prefix(
                host=host,
                challenge=challenge,
                prefix=prefix,
                target=target,
                control=control,
            )
            factual = [int(item) for item in observed["factual_candidates"]]
            controls = [int(item) for item in observed["control_candidates"]]
            gpu_seconds += float(observed["gpu_seconds"])
            groups = position + 1
            if controls:
                raise RuntimeError("A431 matched control produced a candidate")
            common = {
                "executed_worker_prefix_groups": groups,
                "worker_prefix_groups": STATIC_EPOCHS,
                "executed_worker_assignments": groups * GROUP_SIZE,
                "static_schedule_epoch": int(task["epoch"]),
                "global_position_one_based": int(task["global_position_one_based"]),
                "direct12_rank_one_based": int(task["direct12_rank_one_based"]),
                "matched_control_candidates": 0,
                "gpu_seconds": gpu_seconds,
                "host_instances": host_instances,
                "last_completed_prefix12": prefix,
            }
            if not factual:
                progress_callback({"status": "running", "factual_filter_candidates": 0, **common})
                continue
            if len(factual) != 1:
                raise RuntimeError("A431 complete W51 group produced multiple factual filters")
            candidate = factual[0]
            if ((candidate >> WORD0_SUFFIX_BITS) & (CELLS - 1)) != prefix:
                raise RuntimeError("A431 candidate prefix differs")
            decoded = A425.A390.decode_assignment(candidate)
            found = {
                "status": "candidate_found",
                "worker_role": worker,
                "candidate": candidate,
                "candidate_hex": f"{candidate:013x}",
                "key_word0": decoded["word0"],
                "key_word1_low19": decoded["word1_low19"],
                "prefix12": prefix,
                "prefix12_hex": f"{prefix:03x}",
                "worker_step_one_based": groups,
                "executed_worker_group_dispatches": groups * SLABS,
                "complete_W51_group_execution_before_stop": True,
                "early_stop_inside_group": False,
                "factual_filter_candidates": factual,
                "control_filter_candidates": [],
                "host_refresh_interval_prefix_groups": HOST_REFRESH_GROUPS,
                "volatile_wall_seconds": time.perf_counter() - started,
                **common,
            }
            progress_callback(found)
            return found
    finally:
        if host is not None:
            host.close()
    exhausted = {
        "status": "worker_exhausted",
        "worker_role": worker,
        "executed_worker_prefix_groups": STATIC_EPOCHS,
        "worker_prefix_groups": STATIC_EPOCHS,
        "executed_worker_assignments": STATIC_EPOCHS * GROUP_SIZE,
        "static_schedule_epoch": STATIC_EPOCHS,
        "matched_control_candidates": 0,
        "factual_filter_candidates": 0,
        "gpu_seconds": gpu_seconds,
        "host_instances": host_instances,
        "volatile_wall_seconds": time.perf_counter() - started,
    }
    progress_callback(exhausted)
    return exhausted


def mark_peer_confirmed(
    protocol: Mapping[str, Any], qualification_sha256: str, worker: str
) -> dict[str, Any]:
    path = progress_path(worker)
    if not path.exists():
        return {
            "status": "peer_confirmed",
            "worker_role": worker,
            "worker_was_not_started": True,
        }
    value = json.loads(path.read_bytes())
    if (
        value.get("protocol_sha256") != file_sha256(PROTOCOL)
        or value.get("A390_qualification_sha256") != qualification_sha256
        or value.get("worker_role") != worker
    ):
        raise RuntimeError("A431 peer progress fingerprint differs")
    if value.get("status") not in {
        "running",
        "peer_confirmed",
        "worker_exhausted",
        "candidate_found",
    }:
        raise RuntimeError("A431 peer progress status differs")
    if value.get("status") in {"running", "peer_confirmed"}:
        value["status"] = "peer_confirmed"
        value["confirmed_stop_sha256"] = file_sha256(STOP)
        value["factual_filter_candidates"] = 0
        atomic_json(path, value)
    return {"status": "peer_confirmed", "worker_role": worker}


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
            or value.get("worker_task_list_sha256") != protocol["worker_task_list_sha256"][worker]
        ):
            raise RuntimeError("A431 progress snapshot fingerprint differs")
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
        "prefix_sets_are_disjoint_by_A430_construction": True,
    }


def active_started_workers_terminal() -> bool:
    owner = str(json.loads(STOP.read_bytes())["worker_role"])
    for worker in ROLES:
        path = progress_path(worker)
        if not path.exists():
            continue
        status = json.loads(path.read_bytes()).get("status")
        if worker == owner and status == "candidate_found":
            continue
        if status not in {"peer_confirmed", "worker_exhausted"}:
            return False
    return True


def rank_panel(prefix: int, worker: str, protocol: Mapping[str, Any]) -> dict[str, Any]:
    source, _orders, _tasks = load_source_schedule(protocol["A430_result_sha256"])
    epoch = int(source["cell_epoch_one_based"][prefix])
    if source["cell_worker_role"][prefix] != worker:
        raise RuntimeError("A431 confirmed prefix worker differs")
    task = protocol["worker_tasks"][worker][epoch - 1]
    direct_rank = int(task["direct12_rank_one_based"])
    if (
        int(task["cell"]) != prefix
        or direct_rank != int(task["global_position_one_based"])
        or epoch != math.ceil(direct_rank / WORKERS)
    ):
        raise RuntimeError("A431 confirmed Direct12 task lookup differs")
    return {
        "cell": prefix,
        "A430_Direct12_rank_one_based": direct_rank,
        "A430_eight_worker_epoch_one_based": epoch,
        "A430_worker_role": worker,
        "A430_worker_step_one_based": int(task["worker_step_one_based"]),
        "exact_depth_identity_holds": epoch == math.ceil(direct_rank / WORKERS),
        "ranks_computed_only_after_independent_confirmation": True,
    }


def build_causal(payload: Mapping[str, Any]) -> dict[str, Any]:
    if str(DOTCAUSAL_SRC) not in sys.path:
        sys.path.insert(0, str(DOTCAUSAL_SRC))
    from dotcausal.io import CausalReader, CausalWriter

    terminal = "A431:confirmed_Direct12_W51_recovery"
    writer = CausalWriter(api_id="a431w51")
    writer._rules = []
    writer.add_rule(
        name="A430_schedule_and_A390_engine_to_model",
        description="A430's zero-refit Direct12 worker lists execute disjoint complete W51 groups through the exact A390 engine.",
        pattern=["A430_exact_direct_eight_worker_schedule", "A390_exact_W51_group_engine"],
        conclusion="A431_sole_factual_W51_model",
        confidence_modifier=1.0,
    )
    writer.add_rule(
        name="W51_model_to_confirmed_recovery",
        description="The sole factual model passes the matched control and dual independent eight-block confirmation.",
        pattern=["A431_sole_factual_W51_model"],
        conclusion="A431_confirmed_Direct12_W51_recovery",
        confidence_modifier=1.0,
    )
    writer.add_triplet(
        trigger="A430:exact_direct_eight_worker_schedule",
        mechanism="qualified_disjoint_complete_2^39_group_search_with_confirmed_shared_stop",
        outcome="A431:sole_factual_W51_model",
        confidence=1.0,
        source=payload["execution_sha256"],
        quantification=json.dumps(payload["aggregate_execution"], sort_keys=True),
        evidence=json.dumps(payload["rank_analysis"], sort_keys=True),
        domain="sealed full-round ChaCha20 W51 Direct12 recovery",
        quality_score=1.0,
    )
    writer.add_triplet(
        trigger="A431:sole_factual_W51_model",
        mechanism="matched_control_rejection_and_dual_eight_block_confirmation",
        outcome=terminal,
        confidence=1.0,
        source=payload["measurement_sha256"],
        quantification=json.dumps(payload["confirmation"], sort_keys=True),
        evidence=payload["evidence_stage"],
        domain="confirmed full-round ChaCha20 W51 recovery",
        quality_score=1.0,
    )
    writer.add_triplet(
        trigger="A430:exact_direct_eight_worker_schedule",
        mechanism="materialized_search_and_confirmation_closure",
        outcome=terminal,
        confidence=1.0,
        source="materialized:A431_Direct12_W51_recovery_chain",
        quantification="exact retained closure",
        evidence=payload["evidence_stage"],
        domain="AI-native retained inference",
        quality_score=1.0,
        is_inferred=True,
    )
    writer.add_cluster(
        name="A431 Direct12 W51 recovery",
        entities=[
            "A430:exact_direct_eight_worker_schedule",
            "A431:sole_factual_W51_model",
            terminal,
        ],
    )
    writer.add_gap(
        subject=terminal,
        predicate="next_required_object",
        expected_object_type="fresh_W52_public_output_Direct12_transfer",
        confidence=1.0,
        suggested_queries=[
            "Measure the unchanged Direct12 Reader over a fresh sealed W52 public-output field and execute the resulting exact schedule."
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
        reader.api_id != "a431w51"
        or len(explicit) != 2
        or len(all_rows) != 3
        or len(inferred) != 1
        or len(reader._rules) != 2
        or len(reader._clusters) != 1
        or len(reader._gaps) != 1
    ):
        raise RuntimeError("A431 authentic Causal reopen gate failed")
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
            "execution": explicit[0],
            "confirmation": explicit[1],
            "terminal_chain": all_rows[-1],
            "next_gap": reader._gaps[0],
        },
    }


def finalize_confirmed_stop(
    protocol: Mapping[str, Any], qualification_sha256: str
) -> dict[str, Any]:
    if RESULT.exists():
        return {"status": "peer_confirmed", "result_sha256": file_sha256(RESULT)}
    stop = json.loads(STOP.read_bytes())
    if (
        stop.get("schema") != "chacha20-round20-w51-a430-direct12-recovery-a431-confirmed-stop-v1"
        or stop.get("attempt_id") != ATTEMPT_ID
        or stop.get("protocol_sha256") != file_sha256(PROTOCOL)
        or stop.get("A390_qualification_sha256") != qualification_sha256
        or stop.get("confirmation", {}).get("all_blocks_match") is not True
        or stop.get("discovery", {}).get("control_filter_candidates") != []
    ):
        raise RuntimeError("A431 confirmed stop fingerprint differs")
    while not active_started_workers_terminal():
        time.sleep(5)
    aggregate = progress_snapshot(protocol)
    unique_groups = int(aggregate["total_unique_prefix_groups_evaluated"])
    if not 1 <= unique_groups <= CELLS:
        raise RuntimeError("A431 aggregate unique group count differs")
    strict_subset = unique_groups < CELLS
    aggregate["strict_subset_of_complete_domain"] = strict_subset
    aggregate["domain_reduction_factor"] = CELLS / unique_groups
    aggregate["search_gain_bits"] = math.log2(CELLS / unique_groups)
    discovery = stop["discovery"]
    ranks = rank_panel(int(discovery["prefix12"]), discovery["worker_role"], protocol)
    if (
        ranks["A430_eight_worker_epoch_one_based"] != discovery["static_schedule_epoch"]
        or ranks["A430_worker_step_one_based"] != discovery["worker_step_one_based"]
        or ranks["exact_depth_identity_holds"] is not True
    ):
        raise RuntimeError("A431 discovery depth differs from A430 schedule")
    qualification = A425.load_a390_qualification(qualification_sha256)
    evidence_stage = (
        "FULLROUND_R20_ZERO_REFIT_DIRECT12_W51_STRICT_SUBSET_RECOVERY_CONFIRMED"
        if strict_subset
        else "FULLROUND_R20_ZERO_REFIT_DIRECT12_W51_COMPLETE_DOMAIN_RECOVERY_CONFIRMED"
    )
    stable_discovery = {
        key: item for key, item in discovery.items() if not key.startswith("volatile_")
    }
    payload: dict[str, Any] = {
        "schema": "chacha20-round20-w51-a430-direct12-recovery-a431-result-v1",
        "attempt_id": ATTEMPT_ID,
        "evidence_stage": evidence_stage,
        "design_sha256": DESIGN_SHA256,
        "implementation_sha256": protocol["implementation_sha256"],
        "implementation_commitment_sha256": protocol["implementation_commitment_sha256"],
        "protocol_sha256": file_sha256(PROTOCOL),
        "protocol_commitment_sha256": protocol["protocol_commitment_sha256"],
        "A430_result_sha256": protocol["A430_result_sha256"],
        "A430_causal_sha256": protocol["A430_causal_sha256"],
        "A430_schedule_commitment_sha256": protocol["A430_schedule_commitment_sha256"],
        "A425_protocol_sha256": protocol["A425_protocol_sha256"],
        "A390_qualification_sha256": qualification_sha256,
        "public_challenge_sha256": protocol["public_challenge_sha256"],
        "discovery": discovery,
        "confirmation": stop["confirmation"],
        "aggregate_execution": aggregate,
        "rank_analysis": ranks,
        "matched_control_candidates": 0,
        "factual_candidates": 1,
        "all_8192_cross_implementation_output_bits_match": True,
        "complete_group_before_stop": True,
        "early_stop_inside_group": False,
        "production_target_labels_used": 0,
        "production_reader_refits": 0,
        "prior_public_assignment_reused": False,
        "prior_live_recovery_filter_outcomes_consumed": False,
        "qualification_gate": {
            "evidence_stage": qualification["evidence_stage"],
            "complete_W51_group_candidates": qualification["complete_group_gate"][
                "logical_candidates"
            ],
            "synthetic_filter_exact": qualification["synthetic_filter_exact"],
            "matched_control_empty": qualification["matched_control_empty"],
            "production_target_used": False,
        },
        "information_boundary": protocol["information_boundary"],
        "anchors": {
            **protocol["anchors"],
            "confirmed_stop": anchor(STOP, file_sha256(STOP)),
            "A390_qualification": anchor(A390_QUALIFICATION, qualification_sha256),
        },
    }
    payload["execution_sha256"] = canonical_sha256(
        {
            "discovery": stable_discovery,
            "aggregate_execution": aggregate,
            "rank_analysis": ranks,
            "A430_schedule_commitment_sha256": protocol["A430_schedule_commitment_sha256"],
        }
    )
    payload["measurement_sha256"] = canonical_sha256(
        {
            "confirmation": stop["confirmation"],
            "matched_control_candidates": 0,
            "qualification_gate": payload["qualification_gate"],
            "information_boundary": payload["information_boundary"],
        }
    )
    payload["causal"] = build_causal(payload)
    atomic_json(RESULT, payload)
    atomic_bytes(
        REPORT,
        (
            "# A431 — zero-refit Direct12 full-round ChaCha20 W51 recovery\n\n"
            f"Evidence stage: **{evidence_stage}**\n\n"
            f"- A430 Direct12 rank: **{ranks['A430_Direct12_rank_one_based']} / {CELLS}**\n"
            f"- Exact eight-worker epoch: **{ranks['A430_eight_worker_epoch_one_based']} / {STATIC_EPOCHS}**\n"
            f"- Exact unique W51 groups evaluated: **{unique_groups} / {CELLS}**\n"
            f"- Complete candidate evaluations: **{aggregate['total_unique_assignments_evaluated']:,} / {DOMAIN_SIZE:,}**\n"
            f"- Recovered W51 assignment: **0x{int(discovery['candidate']):013x}**\n"
            "- Standard ChaCha20: **20 rounds plus feed-forward**\n"
            "- Every prefix: **256 complete 2^31 slabs before outcome evaluation**\n"
            "- Factual / matched-control candidates: **1 / 0**\n"
            "- Dual independent confirmation: **8,192 checked bits**\n"
            "- Reader refits / target labels: **0 / 0**\n"
            "- Authentic AI-native Causal readback: **2 explicit + 1 inferred chain**\n"
        ).encode(),
    )
    return payload


def recover_worker(
    *,
    worker: str,
    expected_protocol_sha256: str,
    expected_a390_qualification_sha256: str,
) -> dict[str, Any]:
    if worker not in ROLE_TO_INDEX:
        raise ValueError(f"A431 unknown worker {worker}")
    protocol = load_protocol(expected_protocol_sha256)
    A425.load_a390_qualification(expected_a390_qualification_sha256)
    if RESULT.exists():
        return {
            "status": "peer_confirmed",
            "worker_role": worker,
            "result_sha256": file_sha256(RESULT),
        }
    if STOP.exists():
        stop = json.loads(STOP.read_bytes())
        if stop.get("worker_role") == worker:
            return finalize_confirmed_stop(protocol, expected_a390_qualification_sha256)
        return mark_peer_confirmed(protocol, expected_a390_qualification_sha256, worker)
    order, tasks = exact_worker_schedule(
        protocol["worker_cell_orders"][worker],
        protocol["worker_tasks"][worker],
        worker,
    )
    engine_protocol = A425.A390.load_protocol(A390_PROTOCOL_SHA256)
    executable_row = engine_protocol["anchors"]["grouped_executable"]
    executable = path_from_ref(executable_row["path"])
    anchor(executable, executable_row["sha256"])
    challenge = protocol["public_challenge"]
    placeholder = np.asarray([0, 0], dtype=np.uint32)

    def host_factory() -> Any:
        return A425.A390.A384.A378.A371.A346.A324.A311.A307.A304.GroupedMetalHost(
            executable,
            A425.A390.initial_for_slab(challenge, 0),
            placeholder,
            placeholder,
        )

    order_sha = protocol["worker_order_uint16be_sha256"][worker]
    tasks_sha = protocol["worker_task_list_sha256"][worker]

    def write_progress(row: Mapping[str, Any]) -> None:
        atomic_json(
            progress_path(worker),
            {
                "schema": "chacha20-round20-w51-a430-direct12-recovery-a431-progress-v1",
                "attempt_id": ATTEMPT_ID,
                "worker_role": worker,
                "worker_index": ROLE_TO_INDEX[worker],
                "protocol_sha256": expected_protocol_sha256,
                "A390_qualification_sha256": expected_a390_qualification_sha256,
                "worker_order_uint16be_sha256": order_sha,
                "worker_task_list_sha256": tasks_sha,
                "matched_control_candidates": 0,
                **dict(row),
            },
        )

    start, prior_gpu, prior_hosts, completed = load_resume(
        worker,
        expected_protocol_sha256,
        expected_a390_qualification_sha256,
        order_sha,
        tasks_sha,
    )
    if completed is not None:
        if completed.get("status") == "candidate_found" and not STOP.exists():
            discovery = completed
        elif STOP.exists():
            return recover_worker(
                worker=worker,
                expected_protocol_sha256=expected_protocol_sha256,
                expected_a390_qualification_sha256=expected_a390_qualification_sha256,
            )
        else:
            return completed
    else:
        write_progress(
            {
                "status": "running",
                "executed_worker_prefix_groups": start,
                "worker_prefix_groups": STATIC_EPOCHS,
                "executed_worker_assignments": start * GROUP_SIZE,
                "static_schedule_epoch": start,
                "factual_filter_candidates": 0,
                "gpu_seconds": prior_gpu,
                "host_instances": prior_hosts,
            }
        )
        discovery = ordered_worker_discovery(
            worker=worker,
            order=order,
            tasks=tasks,
            challenge=challenge,
            host_factory=host_factory,
            start_group=start,
            prior_gpu_seconds=prior_gpu,
            prior_host_instances=prior_hosts,
            progress_callback=write_progress,
        )
    if discovery["status"] in {"peer_confirmed", "worker_exhausted"}:
        write_progress(discovery)
        if discovery["status"] == "worker_exhausted":
            exhausted = sum(
                progress_path(other).exists()
                and json.loads(progress_path(other).read_bytes()).get("status")
                == "worker_exhausted"
                for other in ROLES
            )
            if exhausted == WORKERS:
                raise RuntimeError("A431 all disjoint workers exhausted without a model")
        return discovery
    candidate = int(discovery["candidate"])
    confirmation = A425.confirm(challenge, candidate)
    if confirmation.get("all_blocks_match") is not True:
        raise RuntimeError("A431 dual-reference eight-block confirmation failed")
    if discovery.get("control_filter_candidates") != []:
        raise RuntimeError("A431 matched control produced a candidate")
    if STOP.exists():
        return mark_peer_confirmed(protocol, expected_a390_qualification_sha256, worker)
    atomic_json(
        STOP,
        {
            "schema": "chacha20-round20-w51-a430-direct12-recovery-a431-confirmed-stop-v1",
            "attempt_id": ATTEMPT_ID,
            "protocol_sha256": expected_protocol_sha256,
            "A390_qualification_sha256": expected_a390_qualification_sha256,
            "worker_role": worker,
            "worker_index": ROLE_TO_INDEX[worker],
            "discovery": discovery,
            "confirmation": confirmation,
        },
    )
    return finalize_confirmed_stop(protocol, expected_a390_qualification_sha256)


def analyze() -> dict[str, Any]:
    payload: dict[str, Any] = {
        "attempt_id": ATTEMPT_ID,
        "design_sha256": DESIGN_SHA256,
        "implementation_frozen": IMPLEMENTATION.exists(),
        "A430_result_complete": A430_RESULT.exists(),
        "A390_qualification_complete": A390_QUALIFICATION.exists(),
        "protocol_frozen": PROTOCOL.exists(),
        "confirmed_stop_available": STOP.exists(),
        "result_complete": RESULT.exists(),
        "candidate_group_size": GROUP_SIZE,
        "complete_domain_assignments": DOMAIN_SIZE,
        "worker_progress": {},
    }
    load_design()
    if IMPLEMENTATION.exists():
        payload["implementation_sha256"] = file_sha256(IMPLEMENTATION)
        load_implementation(payload["implementation_sha256"])
    if A430_RESULT.exists():
        payload["A430_result_sha256"] = file_sha256(A430_RESULT)
        source, _orders, _tasks = load_source_schedule(payload["A430_result_sha256"])
        payload["A430_schedule_commitment_sha256"] = source["schedule_commitment_sha256"]
    if A390_QUALIFICATION.exists():
        payload["A390_qualification_sha256"] = file_sha256(A390_QUALIFICATION)
    if PROTOCOL.exists():
        payload["protocol_sha256"] = file_sha256(PROTOCOL)
        protocol = load_protocol(payload["protocol_sha256"])
        payload["public_challenge_sha256"] = protocol["public_challenge_sha256"]
        payload["progress"] = progress_snapshot(protocol)
    for worker in ROLES:
        path = progress_path(worker)
        if path.exists():
            payload["worker_progress"][worker] = json.loads(path.read_bytes())
    if RESULT.exists():
        result = json.loads(RESULT.read_bytes())
        payload["result_sha256"] = file_sha256(RESULT)
        payload["evidence_stage"] = result["evidence_stage"]
        payload["aggregate_execution"] = result["aggregate_execution"]
        payload["rank_analysis"] = result["rank_analysis"]
        payload["causal"] = result["causal"]
    return payload


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    action = parser.add_mutually_exclusive_group(required=True)
    action.add_argument("--analyze", action="store_true")
    action.add_argument("--freeze-implementation", action="store_true")
    action.add_argument("--freeze-protocol", action="store_true")
    action.add_argument("--recover-worker", choices=ROLES)
    parser.add_argument("--expected-implementation-sha256")
    parser.add_argument("--expected-a430-result-sha256")
    parser.add_argument("--expected-protocol-sha256")
    parser.add_argument("--expected-a390-qualification-sha256")
    args = parser.parse_args()
    if args.freeze_implementation:
        payload = freeze_implementation()
    elif args.freeze_protocol:
        if not args.expected_implementation_sha256 or not args.expected_a430_result_sha256:
            parser.error("--freeze-protocol requires implementation and A430 result hashes")
        payload = freeze_protocol(
            expected_implementation_sha256=args.expected_implementation_sha256,
            expected_a430_result_sha256=args.expected_a430_result_sha256,
        )
    elif args.recover_worker:
        if not args.expected_protocol_sha256 or not args.expected_a390_qualification_sha256:
            parser.error("--recover-worker requires protocol and A390 qualification hashes")
        payload = recover_worker(
            worker=args.recover_worker,
            expected_protocol_sha256=args.expected_protocol_sha256,
            expected_a390_qualification_sha256=args.expected_a390_qualification_sha256,
        )
    else:
        payload = analyze()
    print(json.dumps(payload, indent=2, sort_keys=True), flush=True)


if __name__ == "__main__":
    main()

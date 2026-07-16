#!/usr/bin/env python3
"""A435: execute A434's exact dual-axis wavefront on the A426 W52 challenge."""

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

STEM = "chacha20_round20_w52_dual_axis_square_wavefront_recovery_a435"
DESIGN = CONFIGS / f"{STEM}_design_v1.json"
IMPLEMENTATION = CONFIGS / f"{STEM}_implementation_v1.json"
PROTOCOL = CONFIGS / f"{STEM}_v1.json"
RESULT = RESULTS / f"{STEM}_v1.json"
STOP = RESULTS / f"{STEM}_confirmed_stop_v1.json"
CAUSAL = RESULT.with_suffix(".causal")
REPORT = RESULT.with_suffix(".md")
TEST = ROOT / f"tests/test_{STEM}.py"
REPRO = ROOT / f"scripts/reproduce_{STEM}.sh"

A434_PROTOCOL = CONFIGS / "chacha20_round20_w52_dual_axis_square_wavefront_a434_v1.json"
A434_QUALIFICATION = (
    RESULTS / "chacha20_round20_w52_dual_axis_square_wavefront_a434_qualification_v1.json"
)
A434_RUNNER = RESEARCH / "experiments/chacha20_round20_w52_dual_axis_square_wavefront_a434.py"
A426_PROTOCOL = CONFIGS / "chacha20_round20_w52_a416_fresh_shared_stop_recovery_a426_v1.json"
A426_RUNNER = RESEARCH / "experiments/chacha20_round20_w52_a416_fresh_shared_stop_recovery_a426.py"

ATTEMPT_ID = "A435"
DESIGN_SHA256 = "4f34b5d674d49cfda7b04a56da1078debc89df6f09f738020bd6a95924d3dd44"
A434_PROTOCOL_SHA256 = "fca88cf01efdf2dde2ca56b87ae2d3b2bb0b320318c1201faa3f54b6af50acba"
A434_RUNNER_SHA256 = "feb01a654135ed03451c3207d4f10195de0bc81ec26ce755d5e0d1eeb7ce9a1b"
A426_PROTOCOL_SHA256 = "746c880115464383247ee0ef8d52d6095195f26fa4b69178a8de281cd4c483a3"
A426_RUNNER_SHA256 = "d849065a0bc33f1d3eff3f5b7638948c86b683f8020bfd8a0f5ed0e9ca449637"

WIDTH = 52
KNOWN_KEY_BITS = 256 - WIDTH
AXIS_BITS = 12
AXIS_CELLS = 1 << AXIS_BITS
PAIR_CELLS = 1 << (2 * AXIS_BITS)
CELL_ASSIGNMENTS = 1 << (WIDTH - 2 * AXIS_BITS)
DOMAIN_ASSIGNMENTS = 1 << WIDTH
WORKERS = 8
WORKER_TASKS = PAIR_CELLS // WORKERS
HOST_REFRESH_CELLS = 1
BLOCK_COUNT = 8
DOTCAUSAL_SRC = Path("/Users/bhkmie/Documents/Forschung/O1/vendor/fabel/dotcausal_package/src")


def load_module(path: Path, name: str) -> Any:
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot import A435 dependency {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


A434 = load_module(A434_RUNNER, "a435_a434")
A426 = load_module(A426_RUNNER, "a435_a426")
A422 = A434.A422
file_sha256 = A434.file_sha256
canonical_sha256 = A434.canonical_sha256
atomic_json = A434.atomic_json
anchor = A434.anchor
path_from_ref = A434.path_from_ref
relative = A434.relative


def atomic_bytes(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    temporary.write_bytes(data)
    os.replace(temporary, path)


def progress_path(worker_index: int) -> Path:
    if not 0 <= worker_index < WORKERS:
        raise ValueError("A435 worker index differs")
    return RESULTS / f"{STEM}_worker_{worker_index}_progress_v1.json"


def no_downstream_artifacts() -> bool:
    return not any(
        path.exists()
        for path in (
            PROTOCOL,
            RESULT,
            STOP,
            CAUSAL,
            REPORT,
            *(progress_path(index) for index in range(WORKERS)),
        )
    )


def load_design() -> dict[str, Any]:
    if file_sha256(DESIGN) != DESIGN_SHA256:
        raise RuntimeError("A435 design hash differs")
    value = json.loads(DESIGN.read_bytes())
    execution = value.get("execution_contract", {})
    schedule = value.get("schedule_transfer_contract", {})
    challenge = value.get("challenge_contract", {})
    qualification = value.get("qualification_contract", {})
    boundary = value.get("information_boundary", {})
    if (
        value.get("schema")
        != "chacha20-round20-w52-dual-axis-square-wavefront-recovery-a435-design-v1"
        or value.get("attempt_id") != ATTEMPT_ID
        or value.get("design_state")
        != "frozen_after_A434_complete_unlabeled_dual_axis_protocol_and_A426_public_challenge_before_A422_A434_qualification_A426_outcome_or_any_A435_candidate_progress_or_filter_outcome"
        or execution.get("full_rounds") != 20
        or execution.get("feedforward_included") is not True
        or execution.get("unknown_key_bits") != WIDTH
        or execution.get("known_key_bits") != KNOWN_KEY_BITS
        or execution.get("pair_cells") != PAIR_CELLS
        or execution.get("candidates_per_complete_pair_cell") != CELL_ASSIGNMENTS
        or execution.get("complete_domain_assignments") != DOMAIN_ASSIGNMENTS
        or execution.get("workers") != WORKERS
        or execution.get("worker_tasks_each") != WORKER_TASKS
        or execution.get("complete_pair_cell_before_success_evaluation") is not True
        or execution.get("early_stop_inside_pair_cell") is not False
        or execution.get("shared_stop_only_after_independent_confirmation") is not True
        or schedule.get("source_attempt") != "A434"
        or schedule.get("source_pair_stream_complete") is not True
        or schedule.get("source_pair_stream_cells") != PAIR_CELLS
        or schedule.get("copy_pair_at_and_worker_modulo_mapping_without_refit") is not True
        or schedule.get("target_labels_used") != 0
        or schedule.get("reader_refits") != 0
        or challenge.get("source_attempt") != "A426"
        or challenge.get("reuse_existing_public_W52_challenge") is not True
        or challenge.get("secret_assignment_absent_from_protocol") is not True
        or qualification.get("requires_A434_target_free_dual_axis_subcell_qualification")
        is not True
        or boundary.get("A434_protocol_available_at_design_freeze") is not True
        or boundary.get("A426_public_challenge_available_at_design_freeze") is not True
        or boundary.get("A422_qualification_available_at_design_freeze") is not False
        or boundary.get("A434_qualification_available_at_design_freeze") is not False
        or boundary.get("A426_candidate_or_progress_available_at_design_freeze") is not False
        or boundary.get("A426_outcome_available_at_design_freeze") is not False
        or boundary.get("A435_candidate_or_progress_available_at_design_freeze") is not False
        or boundary.get("A435_target_labels_used_for_schedule") != 0
        or boundary.get("A435_reader_refits") != 0
        or boundary.get("prior_live_recovery_filter_outcomes_consumed") is not False
    ):
        raise RuntimeError("A435 frozen design semantics differ")
    return value


def load_source_protocols() -> tuple[
    dict[str, Any],
    dict[str, Any],
    list[int],
    list[int],
]:
    if file_sha256(A434_RUNNER) != A434_RUNNER_SHA256:
        raise RuntimeError("A435 A434 runner hash differs")
    if file_sha256(A426_RUNNER) != A426_RUNNER_SHA256:
        raise RuntimeError("A435 A426 runner hash differs")
    a434 = A434.load_protocol(A434_PROTOCOL_SHA256)
    a426 = A426.load_protocol(A426_PROTOCOL_SHA256)
    _a433, prefix_order = A434.load_prefix_order(a434["A433_result_sha256"])
    _a432, off_axis_order = A434.load_off_axis_order()
    schedule = a434["schedule"]
    if (
        schedule.get("cells") != PAIR_CELLS
        or schedule.get("assignments_per_cell") != CELL_ASSIGNMENTS
        or schedule.get("complete_domain_assignments") != DOMAIN_ASSIGNMENTS
        or schedule.get("workers") != WORKERS
        or schedule.get("worker_tasks_each") != WORKER_TASKS
        or A434.pair_stream_sha256(prefix_order, off_axis_order)
        != schedule.get("pair_stream_uint16be_uint16be_sha256")
    ):
        raise RuntimeError("A435 A434 source schedule differs")
    if (
        a426.get("complete_domain_assignments") != DOMAIN_ASSIGNMENTS
        or a426.get("public_challenge", {}).get("unknown_key_bits") != WIDTH
        or a426.get("public_challenge", {}).get("unknown_assignment_included") is not False
    ):
        raise RuntimeError("A435 A426 public challenge scope differs")
    return a434, a426, prefix_order, off_axis_order


def freeze_implementation() -> dict[str, Any]:
    if IMPLEMENTATION.exists() or not no_downstream_artifacts():
        raise FileExistsError("A435 implementation or downstream artifact exists")
    A434.assert_no_a426_outcome()
    if A434_QUALIFICATION.exists():
        raise RuntimeError("A435 implementation freeze must precede A434 qualification")
    design = load_design()
    a434, a426, prefix_order, off_axis_order = load_source_protocols()
    if not TEST.exists() or not REPRO.exists():
        raise FileNotFoundError("A435 tests and reproducer must precede freeze")
    payload: dict[str, Any] = {
        "schema": "chacha20-round20-w52-dual-axis-square-wavefront-recovery-a435-implementation-v1",
        "attempt_id": ATTEMPT_ID,
        "commitment_state": "complete_restart_safe_eight_worker_A434_executor_frozen_before_A434_qualification_A426_outcome_or_any_A435_candidate_progress_or_filter_outcome",
        "design_sha256": DESIGN_SHA256,
        "execution_contract": design["execution_contract"],
        "schedule_transfer_contract": design["schedule_transfer_contract"],
        "challenge_contract": design["challenge_contract"],
        "source_A434_protocol_sha256": A434_PROTOCOL_SHA256,
        "source_A434_schedule_commitment_sha256": a434["schedule_commitment_sha256"],
        "source_A434_pair_stream_sha256": a434["schedule"]["pair_stream_uint16be_uint16be_sha256"],
        "source_A426_protocol_sha256": A426_PROTOCOL_SHA256,
        "source_A426_public_challenge_sha256": a426["public_challenge_sha256"],
        "prefix_order_uint16be_sha256": a434["schedule"]["prefix_order_uint16be_sha256"],
        "off_axis_order_uint16be_sha256": a434["schedule"]["off_axis_order_uint16be_sha256"],
        "source_pair_cells": len(prefix_order) * len(off_axis_order),
        "A434_qualification_available_at_freeze": False,
        "A426_outcome_available_at_freeze": False,
        "A435_candidate_or_progress_available_at_freeze": False,
        "production_target_labels_used": 0,
        "production_reader_refits": 0,
        "prior_live_recovery_filter_outcomes_consumed": False,
        "anchors": {
            "design": anchor(DESIGN, DESIGN_SHA256),
            "A434_protocol": anchor(A434_PROTOCOL, A434_PROTOCOL_SHA256),
            "A434_runner": anchor(A434_RUNNER, A434_RUNNER_SHA256),
            "A426_protocol": anchor(A426_PROTOCOL, A426_PROTOCOL_SHA256),
            "A426_runner": anchor(A426_RUNNER, A426_RUNNER_SHA256),
            "runner": anchor(Path(__file__)),
            "test": anchor(TEST),
            "reproducer": anchor(REPRO),
        },
    }
    payload["implementation_commitment_sha256"] = canonical_sha256(payload)
    atomic_json(IMPLEMENTATION, payload)
    A434.assert_no_a426_outcome()
    return payload


def load_implementation(expected_sha256: str) -> dict[str, Any]:
    if file_sha256(IMPLEMENTATION) != expected_sha256:
        raise RuntimeError("A435 implementation hash differs")
    value = json.loads(IMPLEMENTATION.read_bytes())
    if (
        value.get("schema")
        != "chacha20-round20-w52-dual-axis-square-wavefront-recovery-a435-implementation-v1"
        or value.get("attempt_id") != ATTEMPT_ID
        or value.get("design_sha256") != DESIGN_SHA256
        or value.get("source_A434_protocol_sha256") != A434_PROTOCOL_SHA256
        or value.get("source_A426_protocol_sha256") != A426_PROTOCOL_SHA256
        or value.get("source_pair_cells") != PAIR_CELLS
        or value.get("A434_qualification_available_at_freeze") is not False
        or value.get("A426_outcome_available_at_freeze") is not False
        or value.get("A435_candidate_or_progress_available_at_freeze") is not False
        or value.get("production_target_labels_used") != 0
        or value.get("production_reader_refits") != 0
        or value.get("prior_live_recovery_filter_outcomes_consumed") is not False
    ):
        raise RuntimeError("A435 implementation semantics differ")
    for row in value["anchors"].values():
        anchor(path_from_ref(row["path"]), row["sha256"])
    unsigned = {
        key: item for key, item in value.items() if key != "implementation_commitment_sha256"
    }
    if value.get("implementation_commitment_sha256") != canonical_sha256(unsigned):
        raise RuntimeError("A435 implementation commitment differs")
    return value


def freeze_protocol(*, expected_implementation_sha256: str) -> dict[str, Any]:
    if not no_downstream_artifacts():
        raise FileExistsError("A435 protocol or execution artifact exists")
    A434.assert_no_a426_outcome()
    if A434_QUALIFICATION.exists():
        raise RuntimeError("A435 protocol freeze must precede A434 qualification")
    implementation = load_implementation(expected_implementation_sha256)
    a434, a426, _prefix_order, _off_axis_order = load_source_protocols()
    challenge = dict(a426["public_challenge"])
    A426.validate_challenge(challenge)
    schedule = {
        "algorithm": "A434_square_wavefront_prefix_front_shell_order",
        "pair_stream_uint16be_uint16be_sha256": a434["schedule"][
            "pair_stream_uint16be_uint16be_sha256"
        ],
        "A434_schedule_commitment_sha256": a434["schedule_commitment_sha256"],
        "prefix_order_uint16be_sha256": a434["schedule"]["prefix_order_uint16be_sha256"],
        "off_axis_order_uint16be_sha256": a434["schedule"]["off_axis_order_uint16be_sha256"],
        "pair_cells": PAIR_CELLS,
        "assignments_per_complete_pair_cell": CELL_ASSIGNMENTS,
        "complete_domain_assignments": DOMAIN_ASSIGNMENTS,
        "workers": WORKERS,
        "worker_tasks_each": WORKER_TASKS,
        "worker_global_index_formula": "worker_index + 8 * zero_based_worker_step",
        "worker_role_formula": "dual_axis_wave_{worker_index}",
        "pair_at_formula": "A434.square_pair_at(global_index)",
        "complete_cover_identity": "disjoint residues modulo 8 over [0,2^24)",
        "shell_first_index_identity": "m^2",
        "shell_size_identity": "2m+1",
        "pair_rank_upper_bound": "max(R_prefix,R_off_axis)^2",
        "sentinels": a434["schedule"]["sentinels"],
    }
    payload: dict[str, Any] = {
        "schema": "chacha20-round20-w52-dual-axis-square-wavefront-recovery-a435-protocol-v1",
        "attempt_id": ATTEMPT_ID,
        "protocol_state": "A434_exact_dual_axis_schedule_and_A426_public_challenge_bound_before_A434_qualification_A426_outcome_or_any_A435_candidate_progress_or_filter_outcome",
        "design_sha256": DESIGN_SHA256,
        "implementation_sha256": expected_implementation_sha256,
        "implementation_commitment_sha256": implementation["implementation_commitment_sha256"],
        "A434_protocol_sha256": A434_PROTOCOL_SHA256,
        "A426_protocol_sha256": A426_PROTOCOL_SHA256,
        "public_challenge": challenge,
        "public_challenge_sha256": a426["public_challenge_sha256"],
        "schedule": schedule,
        "schedule_commitment_sha256": canonical_sha256(schedule),
        "worker_roles": [f"dual_axis_wave_{index}" for index in range(WORKERS)],
        "information_boundary": {
            "A434_schedule_frozen_before_A435_challenge_binding": True,
            "A434_qualification_available_at_A435_protocol_freeze": False,
            "A426_assignment_absent_from_protocol": True,
            "A426_candidate_or_progress_available_at_A435_protocol_freeze": False,
            "A426_outcome_available_at_A435_protocol_freeze": False,
            "A435_candidate_or_progress_available_at_protocol_freeze": False,
            "A435_target_labels_used_for_schedule": 0,
            "A435_reader_refits": 0,
            "prior_live_recovery_filter_outcomes_consumed": False,
        },
        "production_execution_enabled": False,
        "candidate_assignments_executed": 0,
        "anchors": {
            "design": anchor(DESIGN, DESIGN_SHA256),
            "implementation": anchor(IMPLEMENTATION, expected_implementation_sha256),
            "A434_protocol": anchor(A434_PROTOCOL, A434_PROTOCOL_SHA256),
            "A426_protocol": anchor(A426_PROTOCOL, A426_PROTOCOL_SHA256),
            "runner": anchor(Path(__file__)),
        },
    }
    payload["protocol_commitment_sha256"] = canonical_sha256(payload)
    atomic_json(PROTOCOL, payload)
    A434.assert_no_a426_outcome()
    return payload


def load_protocol(expected_sha256: str) -> dict[str, Any]:
    if file_sha256(PROTOCOL) != expected_sha256:
        raise RuntimeError("A435 protocol hash differs")
    value = json.loads(PROTOCOL.read_bytes())
    boundary = value.get("information_boundary", {})
    schedule = value.get("schedule", {})
    if (
        value.get("schema")
        != "chacha20-round20-w52-dual-axis-square-wavefront-recovery-a435-protocol-v1"
        or value.get("attempt_id") != ATTEMPT_ID
        or value.get("design_sha256") != DESIGN_SHA256
        or value.get("A434_protocol_sha256") != A434_PROTOCOL_SHA256
        or value.get("A426_protocol_sha256") != A426_PROTOCOL_SHA256
        or schedule.get("pair_cells") != PAIR_CELLS
        or schedule.get("assignments_per_complete_pair_cell") != CELL_ASSIGNMENTS
        or schedule.get("complete_domain_assignments") != DOMAIN_ASSIGNMENTS
        or schedule.get("workers") != WORKERS
        or schedule.get("worker_tasks_each") != WORKER_TASKS
        or schedule.get("A434_schedule_commitment_sha256")
        != json.loads(A434_PROTOCOL.read_bytes())["schedule_commitment_sha256"]
        or value.get("schedule_commitment_sha256") != canonical_sha256(schedule)
        or value.get("worker_roles") != [f"dual_axis_wave_{index}" for index in range(WORKERS)]
        or boundary.get("A434_schedule_frozen_before_A435_challenge_binding") is not True
        or boundary.get("A434_qualification_available_at_A435_protocol_freeze") is not False
        or boundary.get("A426_assignment_absent_from_protocol") is not True
        or boundary.get("A426_candidate_or_progress_available_at_A435_protocol_freeze") is not False
        or boundary.get("A426_outcome_available_at_A435_protocol_freeze") is not False
        or boundary.get("A435_candidate_or_progress_available_at_protocol_freeze") is not False
        or boundary.get("A435_target_labels_used_for_schedule") != 0
        or boundary.get("A435_reader_refits") != 0
        or boundary.get("prior_live_recovery_filter_outcomes_consumed") is not False
        or value.get("production_execution_enabled") is not False
        or value.get("candidate_assignments_executed") != 0
    ):
        raise RuntimeError("A435 protocol semantics differ")
    for row in value["anchors"].values():
        anchor(path_from_ref(row["path"]), row["sha256"])
    load_implementation(value["implementation_sha256"])
    a434, a426, _prefix_order, _off_axis_order = load_source_protocols()
    if (
        schedule["pair_stream_uint16be_uint16be_sha256"]
        != a434["schedule"]["pair_stream_uint16be_uint16be_sha256"]
        or value["public_challenge"] != a426["public_challenge"]
        or value["public_challenge_sha256"] != canonical_sha256(value["public_challenge"])
    ):
        raise RuntimeError("A435 source binding differs")
    A426.validate_challenge(value["public_challenge"])
    unsigned = {key: item for key, item in value.items() if key != "protocol_commitment_sha256"}
    if value.get("protocol_commitment_sha256") != canonical_sha256(unsigned):
        raise RuntimeError("A435 protocol commitment differs")
    return value


def load_a434_qualification(expected_sha256: str) -> dict[str, Any]:
    if file_sha256(A434_QUALIFICATION) != expected_sha256:
        raise RuntimeError("A435 A434 qualification hash differs")
    value = json.loads(A434_QUALIFICATION.read_bytes())
    if (
        value.get("schema")
        != "chacha20-round20-w52-dual-axis-square-wavefront-a434-qualification-v1"
        or value.get("attempt_id") != "A434"
        or value.get("evidence_stage")
        != "TARGET_FREE_DUAL_AXIS_2POW28_SUBCELL_ADAPTER_EXACTLY_QUALIFIED"
        or value.get("protocol_sha256") != A434_PROTOCOL_SHA256
        or value.get("synthetic_filter_exact") is not True
        or value.get("matched_control_empty") is not True
        or value.get("production_W52_challenge_used") is not False
        or value.get("production_W52_candidate_used") is not False
    ):
        raise RuntimeError("A435 A434 qualification semantics differ")
    for row in value["anchors"].values():
        anchor(path_from_ref(row["path"]), row["sha256"])
    unsigned = {
        key: item for key, item in value.items() if key != "qualification_commitment_sha256"
    }
    if value.get("qualification_commitment_sha256") != canonical_sha256(unsigned):
        raise RuntimeError("A435 A434 qualification commitment differs")
    return value


def worker_global_index(worker_index: int, zero_based_worker_step: int) -> int:
    if not 0 <= worker_index < WORKERS:
        raise ValueError("A435 worker index differs")
    if not 0 <= zero_based_worker_step < WORKER_TASKS:
        raise ValueError("A435 worker step differs")
    return worker_index + WORKERS * zero_based_worker_step


def worker_pair_at(
    worker_index: int,
    zero_based_worker_step: int,
    prefix_order: Sequence[int],
    off_axis_order: Sequence[int],
) -> tuple[int, int, int]:
    global_index = worker_global_index(worker_index, zero_based_worker_step)
    prefix, off_axis = A434.square_pair_at(global_index, prefix_order, off_axis_order)
    return global_index, prefix, off_axis


def load_resume(
    *,
    worker_index: int,
    protocol_sha256: str,
    qualification_sha256: str,
) -> tuple[int, float, int, dict[str, Any] | None]:
    path = progress_path(worker_index)
    if not path.exists():
        return 0, 0.0, 0, None
    value = json.loads(path.read_bytes())
    if (
        value.get("schema")
        != "chacha20-round20-w52-dual-axis-square-wavefront-recovery-a435-progress-v1"
        or value.get("attempt_id") != ATTEMPT_ID
        or value.get("worker_index") != worker_index
        or value.get("worker_role") != f"dual_axis_wave_{worker_index}"
        or value.get("protocol_sha256") != protocol_sha256
        or value.get("A434_qualification_sha256") != qualification_sha256
        or value.get("matched_control_candidates") != 0
    ):
        raise RuntimeError("A435 progress fingerprint differs")
    status = value.get("status")
    completed = int(value.get("executed_worker_pair_cells", -1))
    factual = value.get("factual_filter_candidates")
    if (
        status not in {"running", "candidate_found", "worker_exhausted", "peer_confirmed"}
        or not 0 <= completed <= WORKER_TASKS
        or (status == "candidate_found" and (not isinstance(factual, list) or len(factual) != 1))
        or (status != "candidate_found" and factual != 0)
    ):
        raise RuntimeError("A435 resumable progress state differs")
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
    worker_index: int,
    challenge: Mapping[str, Any],
    prefix_order: Sequence[int],
    off_axis_order: Sequence[int],
    host_factory: Callable[[], Any],
    start_cell: int,
    prior_gpu_seconds: float,
    prior_host_instances: int,
    progress_callback: Callable[[Mapping[str, Any]], None],
    filter_fn: Callable[..., Mapping[str, Any]] | None = None,
) -> dict[str, Any]:
    if not 0 <= start_cell <= WORKER_TASKS:
        raise ValueError("A435 start cell differs")
    operation = A434.filter_subcell if filter_fn is None else filter_fn
    target = np.asarray(challenge["target_words"][0], dtype=np.uint32)
    control = np.asarray(challenge["control_target_words"], dtype=np.uint32)
    role = f"dual_axis_wave_{worker_index}"
    host: Any | None = None
    gpu_seconds = prior_gpu_seconds
    host_instances = prior_host_instances
    started = time.perf_counter()
    try:
        for position in range(start_cell, WORKER_TASKS):
            if STOP.exists() or RESULT.exists():
                peer = {
                    "status": "peer_confirmed",
                    "worker_index": worker_index,
                    "worker_role": role,
                    "executed_worker_pair_cells": position,
                    "worker_pair_cells": WORKER_TASKS,
                    "executed_worker_assignments": position * CELL_ASSIGNMENTS,
                    "static_parallel_depth": position,
                    "factual_filter_candidates": 0,
                    "matched_control_candidates": 0,
                    "gpu_seconds": gpu_seconds,
                    "host_instances": host_instances,
                    "volatile_wall_seconds": time.perf_counter() - started,
                }
                progress_callback(peer)
                return peer
            global_index, prefix, off_axis = worker_pair_at(
                worker_index, position, prefix_order, off_axis_order
            )
            if position == start_cell or position % HOST_REFRESH_CELLS == 0:
                if host is not None:
                    host.close()
                host = host_factory()
                host_instances += 1
            observed = operation(
                host=host,
                challenge=challenge,
                prefix=prefix,
                off_axis=off_axis,
                target=target,
                control=control,
            )
            factual = [int(item) for item in observed["factual_candidates"]]
            controls = [int(item) for item in observed["control_candidates"]]
            if (
                observed.get("complete_declared_subcell") is not True
                or int(observed.get("logical_candidates_executed", -1)) != CELL_ASSIGNMENTS
            ):
                raise RuntimeError("A435 incomplete pair cell execution")
            gpu_seconds += float(observed["gpu_seconds"])
            completed = position + 1
            if controls:
                raise RuntimeError("A435 matched control produced a candidate")
            common = {
                "executed_worker_pair_cells": completed,
                "worker_pair_cells": WORKER_TASKS,
                "executed_worker_assignments": completed * CELL_ASSIGNMENTS,
                "static_parallel_depth": completed,
                "last_global_index_zero_based": global_index,
                "last_global_rank_one_based": global_index + 1,
                "last_shell_zero_based": math.isqrt(global_index),
                "last_prefix12": prefix,
                "last_off_axis12": off_axis,
                "matched_control_candidates": 0,
                "gpu_seconds": gpu_seconds,
                "host_instances": host_instances,
            }
            if not factual:
                progress_callback({"status": "running", "factual_filter_candidates": 0, **common})
                continue
            if len(factual) != 1:
                raise RuntimeError("A435 complete pair cell produced multiple candidates")
            candidate = factual[0]
            decoded = A422.decode_assignment(candidate)
            if (
                decoded["word0"] >> A434.WORD0_SUFFIX_BITS != prefix
                or decoded["word1_low20"] >> 8 != off_axis
            ):
                raise RuntimeError("A435 candidate left its declared pair cell")
            found = {
                "status": "candidate_found",
                "worker_index": worker_index,
                "worker_role": role,
                "candidate": candidate,
                "candidate_hex": f"{candidate:013x}",
                "key_word0": decoded["word0"],
                "key_word1_low20": decoded["word1_low20"],
                "prefix12": prefix,
                "prefix12_hex": f"{prefix:03x}",
                "off_axis12": off_axis,
                "off_axis12_hex": f"{off_axis:03x}",
                "worker_step_one_based": completed,
                "global_rank_one_based": global_index + 1,
                "complete_2pow28_pair_cell_before_stop": True,
                "early_stop_inside_pair_cell": False,
                "factual_filter_candidates": factual,
                "control_filter_candidates": [],
                "host_refresh_interval_pair_cells": HOST_REFRESH_CELLS,
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
        "worker_index": worker_index,
        "worker_role": role,
        "executed_worker_pair_cells": WORKER_TASKS,
        "worker_pair_cells": WORKER_TASKS,
        "executed_worker_assignments": WORKER_TASKS * CELL_ASSIGNMENTS,
        "static_parallel_depth": WORKER_TASKS,
        "matched_control_candidates": 0,
        "factual_filter_candidates": 0,
        "gpu_seconds": gpu_seconds,
        "host_instances": host_instances,
        "volatile_wall_seconds": time.perf_counter() - started,
    }
    progress_callback(exhausted)
    return exhausted


def mark_peer_confirmed(
    protocol_sha256: str, qualification_sha256: str, worker_index: int
) -> dict[str, Any]:
    path = progress_path(worker_index)
    if not path.exists():
        return {
            "status": "peer_confirmed",
            "worker_index": worker_index,
            "worker_was_not_started": True,
        }
    value = json.loads(path.read_bytes())
    if (
        value.get("protocol_sha256") != protocol_sha256
        or value.get("A434_qualification_sha256") != qualification_sha256
        or value.get("worker_index") != worker_index
    ):
        raise RuntimeError("A435 peer progress fingerprint differs")
    if value.get("status") in {"running", "peer_confirmed"}:
        value["status"] = "peer_confirmed"
        value["factual_filter_candidates"] = 0
        value["confirmed_stop_sha256"] = file_sha256(STOP)
        atomic_json(path, value)
    elif value.get("status") not in {"worker_exhausted", "candidate_found"}:
        raise RuntimeError("A435 peer progress status differs")
    return {"status": "peer_confirmed", "worker_index": worker_index}


def progress_snapshot(protocol_sha256: str, qualification_sha256: str) -> dict[str, Any]:
    panel: dict[str, Any] = {}
    total = 0
    max_depth = 0
    all_controls_empty = True
    for index in range(WORKERS):
        role = f"dual_axis_wave_{index}"
        path = progress_path(index)
        if not path.exists():
            panel[role] = {
                "status": "not_started",
                "executed_worker_pair_cells": 0,
                "worker_pair_cells": WORKER_TASKS,
            }
            continue
        value = json.loads(path.read_bytes())
        if (
            value.get("protocol_sha256") != protocol_sha256
            or value.get("A434_qualification_sha256") != qualification_sha256
            or value.get("worker_index") != index
        ):
            raise RuntimeError("A435 progress snapshot fingerprint differs")
        cells = int(value.get("executed_worker_pair_cells", 0))
        total += cells
        max_depth = max(max_depth, int(value.get("static_parallel_depth", 0)))
        all_controls_empty &= value.get("matched_control_candidates") == 0
        panel[role] = {
            "status": value.get("status"),
            "executed_worker_pair_cells": cells,
            "worker_pair_cells": WORKER_TASKS,
            "static_parallel_depth": int(value.get("static_parallel_depth", 0)),
            "gpu_seconds": float(value.get("gpu_seconds", 0.0)),
            "matched_control_candidates": value.get("matched_control_candidates"),
        }
    return {
        "workers": panel,
        "total_unique_pair_cells_evaluated": total,
        "total_unique_assignments_evaluated": total * CELL_ASSIGNMENTS,
        "maximum_completed_static_parallel_depth": max_depth,
        "theoretical_complete_parallel_depth": WORKER_TASKS,
        "complete_domain_assignments": DOMAIN_ASSIGNMENTS,
        "all_observed_matched_controls_empty": all_controls_empty,
        "pair_cell_sets_are_disjoint_by_modulo_8_construction": True,
    }


def active_started_workers_terminal() -> bool:
    owner = int(json.loads(STOP.read_bytes())["worker_index"])
    for index in range(WORKERS):
        path = progress_path(index)
        if not path.exists():
            continue
        status = json.loads(path.read_bytes()).get("status")
        if index == owner and status == "candidate_found":
            continue
        if status not in {"peer_confirmed", "worker_exhausted"}:
            return False
    return True


def build_causal(payload: Mapping[str, Any]) -> dict[str, Any]:
    if str(DOTCAUSAL_SRC) not in sys.path:
        sys.path.insert(0, str(DOTCAUSAL_SRC))
    from dotcausal.io import CausalReader, CausalWriter

    strict = payload["strict_subset_of_complete_domain"]
    terminal = (
        "confirmed_strict_subset_dual_axis_W52_recovery"
        if strict
        else "confirmed_complete_domain_dual_axis_W52_recovery"
    )
    writer = CausalWriter(api_id="a435w52")
    writer._rules = []
    writer.add_rule(
        name="complementary_axes_and_exact_subcell_engine_to_model",
        description="Execute A434's prospectively frozen complementary prefix/off-axis square wavefront as disjoint complete 2^28 cells.",
        pattern=["A434_exact_dual_axis_wavefront", "A434_exact_2pow28_subcell_engine"],
        conclusion="A435_sole_factual_W52_model",
        confidence_modifier=1.0,
    )
    writer.add_rule(
        name="dual_axis_model_to_confirmed_recovery",
        description="Require an empty matched control and dual independent eight-block confirmation before retaining the W52 recovery.",
        pattern=["A435_sole_factual_W52_model"],
        conclusion=f"A435_{terminal}",
        confidence_modifier=1.0,
    )
    writer.add_triplet(
        trigger="A434:exact_complementary_dual_axis_wavefront",
        mechanism="eight_disjoint_complete_2pow28_subcell_streams_with_confirmed_shared_stop",
        outcome="A435:sole_factual_W52_model",
        confidence=1.0,
        source=payload["execution_sha256"],
        quantification=json.dumps(payload["aggregate_execution"], sort_keys=True),
        evidence=json.dumps(payload["rank_analysis"], sort_keys=True),
        domain="full-round ChaCha20 W52 dual-axis recovery",
        quality_score=1.0,
    )
    writer.add_triplet(
        trigger="A435:sole_factual_W52_model",
        mechanism="matched_control_rejection_and_dual_reference_eight_block_confirmation",
        outcome=f"A435:{terminal}",
        confidence=1.0,
        source=payload["measurement_sha256"],
        quantification=json.dumps(payload["confirmation"], sort_keys=True),
        evidence=payload["evidence_stage"],
        domain="confirmed full-round ChaCha20 W52 recovery",
        quality_score=1.0,
    )
    writer.add_triplet(
        trigger="A434:exact_complementary_dual_axis_wavefront",
        mechanism="materialized_dual_axis_search_and_confirmation_closure",
        outcome=f"A435:{terminal}",
        confidence=1.0,
        source="materialized:A435_dual_axis_W52_recovery_chain",
        quantification="exact retained closure",
        evidence=payload["evidence_stage"],
        domain="AI-native retained inference",
        quality_score=1.0,
        is_inferred=True,
    )
    writer.add_cluster(
        name="A435 dual-axis W52 recovery",
        entities=[
            "A434:exact_complementary_dual_axis_wavefront",
            "A435:sole_factual_W52_model",
            f"A435:{terminal}",
        ],
    )
    writer.add_gap(
        subject=f"A435:{terminal}",
        predicate="next_required_object",
        expected_object_type="higher_width_multiaxis_or_score_fused_recovery",
        confidence=1.0,
        suggested_queries=[
            "Transfer the complementary-axis decomposition to the next width or replace neutral square shells with a prospectively learned joint calibration order."
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
        reader.api_id != "a435w52"
        or len(explicit) != 2
        or len(all_rows) != 3
        or len(inferred) != 1
        or len(reader._rules) != 2
        or len(reader._clusters) != 1
        or len(reader._gaps) != 1
    ):
        raise RuntimeError("A435 authentic Causal reopen gate failed")
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
        stop.get("schema")
        != "chacha20-round20-w52-dual-axis-square-wavefront-recovery-a435-confirmed-stop-v1"
        or stop.get("attempt_id") != ATTEMPT_ID
        or stop.get("protocol_sha256") != file_sha256(PROTOCOL)
        or stop.get("A434_qualification_sha256") != qualification_sha256
        or stop.get("confirmation", {}).get("all_blocks_match") is not True
        or stop.get("discovery", {}).get("control_filter_candidates") != []
    ):
        raise RuntimeError("A435 confirmed stop fingerprint differs")
    while not active_started_workers_terminal():
        time.sleep(5)
    aggregate = progress_snapshot(file_sha256(PROTOCOL), qualification_sha256)
    unique_cells = int(aggregate["total_unique_pair_cells_evaluated"])
    if not 1 <= unique_cells <= PAIR_CELLS:
        raise RuntimeError("A435 aggregate unique pair-cell count differs")
    strict_subset = unique_cells < PAIR_CELLS
    aggregate["strict_subset_of_complete_domain"] = strict_subset
    aggregate["domain_reduction_factor"] = PAIR_CELLS / unique_cells
    aggregate["search_gain_bits"] = math.log2(PAIR_CELLS / unique_cells)
    aggregate["equivalent_complete_2pow40_A426_groups"] = unique_cells / AXIS_CELLS
    discovery = stop["discovery"]
    _a434, _a426, prefix_order, off_axis_order = load_source_protocols()
    prefix = int(discovery["prefix12"])
    off_axis = int(discovery["off_axis12"])
    global_index = A434.pair_global_index(prefix, off_axis, prefix_order, off_axis_order)
    prefix_rank = prefix_order.index(prefix) + 1
    off_axis_rank = off_axis_order.index(off_axis) + 1
    if (
        global_index + 1 != int(discovery["global_rank_one_based"])
        or int(discovery["worker_index"]) != global_index % WORKERS
        or int(discovery["worker_step_one_based"]) != global_index // WORKERS + 1
    ):
        raise RuntimeError("A435 discovery rank identity differs")
    rank_analysis = {
        "prefix12": prefix,
        "off_axis12": off_axis,
        "prefix_rank_one_based": prefix_rank,
        "off_axis_rank_one_based": off_axis_rank,
        "square_shell_one_based": max(prefix_rank, off_axis_rank),
        "global_pair_rank_one_based": global_index + 1,
        "pair_rank_upper_bound": max(prefix_rank, off_axis_rank) ** 2,
        "pair_rank_upper_bound_holds": global_index + 1 <= max(prefix_rank, off_axis_rank) ** 2,
        "winning_worker_index": int(discovery["worker_index"]),
        "winning_worker_step_one_based": int(discovery["worker_step_one_based"]),
        "aggregate_unique_pair_cells_before_confirmed_stop": unique_cells,
        "ranks_computed_only_after_independent_confirmation": True,
    }
    evidence_stage = (
        "FULLROUND_R20_DUAL_AXIS_W52_STRICT_SUBSET_RECOVERY_CONFIRMED"
        if strict_subset
        else "FULLROUND_R20_DUAL_AXIS_W52_COMPLETE_DOMAIN_RECOVERY_CONFIRMED"
    )
    payload: dict[str, Any] = {
        "schema": "chacha20-round20-w52-dual-axis-square-wavefront-recovery-a435-result-v1",
        "attempt_id": ATTEMPT_ID,
        "evidence_stage": evidence_stage,
        "design_sha256": DESIGN_SHA256,
        "implementation_sha256": protocol["implementation_sha256"],
        "implementation_commitment_sha256": protocol["implementation_commitment_sha256"],
        "protocol_sha256": file_sha256(PROTOCOL),
        "protocol_commitment_sha256": protocol["protocol_commitment_sha256"],
        "A434_protocol_sha256": A434_PROTOCOL_SHA256,
        "A434_qualification_sha256": qualification_sha256,
        "A426_protocol_sha256": A426_PROTOCOL_SHA256,
        "public_challenge_sha256": protocol["public_challenge_sha256"],
        "discovery": discovery,
        "confirmation": stop["confirmation"],
        "aggregate_execution": aggregate,
        "rank_analysis": rank_analysis,
        "strict_subset_of_complete_domain": strict_subset,
        "matched_control_candidates": 0,
        "factual_candidates": 1,
        "all_8192_cross_implementation_output_bits_match": True,
        "complete_2pow28_pair_cell_before_stop": True,
        "early_stop_inside_pair_cell": False,
        "production_target_labels_used": 0,
        "production_reader_refits": 0,
        "prior_live_recovery_filter_outcomes_consumed": False,
        "anchors": {
            "design": anchor(DESIGN, DESIGN_SHA256),
            "implementation": anchor(IMPLEMENTATION, protocol["implementation_sha256"]),
            "protocol": anchor(PROTOCOL, file_sha256(PROTOCOL)),
            "confirmed_stop": anchor(STOP, file_sha256(STOP)),
            "A434_protocol": anchor(A434_PROTOCOL, A434_PROTOCOL_SHA256),
            "A434_qualification": anchor(A434_QUALIFICATION, qualification_sha256),
            "A426_protocol": anchor(A426_PROTOCOL, A426_PROTOCOL_SHA256),
            "runner": anchor(Path(__file__)),
        },
    }
    stable_discovery = {
        key: item for key, item in discovery.items() if not key.startswith("volatile_")
    }
    payload["execution_sha256"] = canonical_sha256(
        {
            "discovery": stable_discovery,
            "aggregate_execution": aggregate,
            "rank_analysis": rank_analysis,
        }
    )
    payload["measurement_sha256"] = canonical_sha256(
        {
            "confirmation": stop["confirmation"],
            "matched_control_candidates": 0,
        }
    )
    payload["causal"] = build_causal(payload)
    atomic_json(RESULT, payload)
    atomic_bytes(
        REPORT,
        (
            "# A435 — Dual-axis full-round ChaCha20 W52 recovery\n\n"
            f"Evidence stage: **{evidence_stage}**\n\n"
            "- Frozen complementary schedule: **A434 prefix x off-axis square wavefront**\n"
            f"- Exact unique 2^28 pair cells evaluated: **{unique_cells:,} / {PAIR_CELLS:,}**\n"
            f"- Complete assignments evaluated: **{aggregate['total_unique_assignments_evaluated']:,} / {DOMAIN_ASSIGNMENTS:,}**\n"
            f"- Search gain: **{aggregate['search_gain_bits']:.9f} bits**\n"
            f"- Prefix / off-axis ranks: **{prefix_rank} / {off_axis_rank}**\n"
            f"- Global dual-axis pair rank: **{global_index + 1}**\n"
            "- Factual / matched-control candidates: **1 / 0**\n"
            "- Standard ChaCha20: **20 rounds plus feed-forward**\n"
            "- Independent confirmation: **two implementations, eight blocks, 8,192 checked output bits**\n"
            "- Authentic AI-native Causal readback: **2 explicit + 1 inferred chain**\n"
        ).encode(),
    )
    return payload


def recover_worker(
    *,
    worker_index: int,
    expected_protocol_sha256: str,
    expected_a434_qualification_sha256: str,
) -> dict[str, Any]:
    if not 0 <= worker_index < WORKERS:
        raise ValueError("A435 worker index differs")
    protocol = load_protocol(expected_protocol_sha256)
    load_a434_qualification(expected_a434_qualification_sha256)
    if RESULT.exists():
        return {"status": "peer_confirmed", "result_sha256": file_sha256(RESULT)}
    if STOP.exists():
        stop = json.loads(STOP.read_bytes())
        if int(stop.get("worker_index", -1)) == worker_index:
            return finalize_confirmed_stop(protocol, expected_a434_qualification_sha256)
        return mark_peer_confirmed(
            expected_protocol_sha256,
            expected_a434_qualification_sha256,
            worker_index,
        )
    _a434, _a426, prefix_order, off_axis_order = load_source_protocols()
    engine_protocol = A422.load_protocol(A434.A422_PROTOCOL_SHA256)
    executable_row = engine_protocol["anchors"]["grouped_executable"]
    executable = path_from_ref(executable_row["path"])
    anchor(executable, executable_row["sha256"])
    challenge = protocol["public_challenge"]
    placeholder = np.asarray([0, 0], dtype=np.uint32)

    def host_factory() -> Any:
        return A422.A390.A384.A378.A371.A346.A324.A311.A307.A304.GroupedMetalHost(
            executable,
            A422.initial_for_slab(challenge, 0),
            placeholder,
            placeholder,
        )

    role = f"dual_axis_wave_{worker_index}"

    def write_progress(row: Mapping[str, Any]) -> None:
        atomic_json(
            progress_path(worker_index),
            {
                "schema": "chacha20-round20-w52-dual-axis-square-wavefront-recovery-a435-progress-v1",
                "attempt_id": ATTEMPT_ID,
                "worker_index": worker_index,
                "worker_role": role,
                "protocol_sha256": expected_protocol_sha256,
                "A434_qualification_sha256": expected_a434_qualification_sha256,
                "A434_schedule_commitment_sha256": protocol["schedule"][
                    "A434_schedule_commitment_sha256"
                ],
                "matched_control_candidates": 0,
                **dict(row),
            },
        )

    start, prior_gpu, prior_hosts, completed = load_resume(
        worker_index=worker_index,
        protocol_sha256=expected_protocol_sha256,
        qualification_sha256=expected_a434_qualification_sha256,
    )
    if completed is not None:
        if completed.get("status") == "candidate_found" and not STOP.exists():
            discovery = completed
        elif STOP.exists():
            return recover_worker(
                worker_index=worker_index,
                expected_protocol_sha256=expected_protocol_sha256,
                expected_a434_qualification_sha256=expected_a434_qualification_sha256,
            )
        else:
            return completed
    else:
        write_progress(
            {
                "status": "running",
                "executed_worker_pair_cells": start,
                "worker_pair_cells": WORKER_TASKS,
                "executed_worker_assignments": start * CELL_ASSIGNMENTS,
                "static_parallel_depth": start,
                "factual_filter_candidates": 0,
                "gpu_seconds": prior_gpu,
                "host_instances": prior_hosts,
            }
        )
        discovery = ordered_worker_discovery(
            worker_index=worker_index,
            challenge=challenge,
            prefix_order=prefix_order,
            off_axis_order=off_axis_order,
            host_factory=host_factory,
            start_cell=start,
            prior_gpu_seconds=prior_gpu,
            prior_host_instances=prior_hosts,
            progress_callback=write_progress,
        )
    if discovery["status"] in {"peer_confirmed", "worker_exhausted"}:
        write_progress(discovery)
        if discovery["status"] == "worker_exhausted":
            exhausted = sum(
                progress_path(index).exists()
                and json.loads(progress_path(index).read_bytes()).get("status")
                == "worker_exhausted"
                for index in range(WORKERS)
            )
            if exhausted == WORKERS:
                raise RuntimeError("A435 all disjoint workers exhausted without a model")
        return discovery
    candidate = int(discovery["candidate"])
    confirmation = A426.confirm(challenge, candidate)
    if confirmation.get("all_blocks_match") is not True:
        raise RuntimeError("A435 dual-reference eight-block confirmation failed")
    if discovery.get("control_filter_candidates") != []:
        raise RuntimeError("A435 matched control produced a candidate")
    if STOP.exists():
        return mark_peer_confirmed(
            expected_protocol_sha256,
            expected_a434_qualification_sha256,
            worker_index,
        )
    atomic_json(
        STOP,
        {
            "schema": "chacha20-round20-w52-dual-axis-square-wavefront-recovery-a435-confirmed-stop-v1",
            "attempt_id": ATTEMPT_ID,
            "protocol_sha256": expected_protocol_sha256,
            "A434_qualification_sha256": expected_a434_qualification_sha256,
            "worker_index": worker_index,
            "worker_role": role,
            "discovery": discovery,
            "confirmation": confirmation,
        },
    )
    return finalize_confirmed_stop(protocol, expected_a434_qualification_sha256)


def analyze() -> dict[str, Any]:
    payload: dict[str, Any] = {
        "attempt_id": ATTEMPT_ID,
        "design_sha256": DESIGN_SHA256,
        "implementation_frozen": IMPLEMENTATION.exists(),
        "protocol_frozen": PROTOCOL.exists(),
        "A434_qualification_complete": A434_QUALIFICATION.exists(),
        "confirmed_stop_available": STOP.exists(),
        "result_complete": RESULT.exists(),
        "pair_cells": PAIR_CELLS,
        "assignments_per_complete_pair_cell": CELL_ASSIGNMENTS,
        "complete_domain_assignments": DOMAIN_ASSIGNMENTS,
        "worker_progress": {},
    }
    load_design()
    if IMPLEMENTATION.exists():
        payload["implementation_sha256"] = file_sha256(IMPLEMENTATION)
        load_implementation(payload["implementation_sha256"])
    if PROTOCOL.exists():
        payload["protocol_sha256"] = file_sha256(PROTOCOL)
        load_protocol(payload["protocol_sha256"])
    if A434_QUALIFICATION.exists():
        payload["A434_qualification_sha256"] = file_sha256(A434_QUALIFICATION)
        load_a434_qualification(payload["A434_qualification_sha256"])
    for index in range(WORKERS):
        path = progress_path(index)
        if path.exists():
            payload["worker_progress"][str(index)] = json.loads(path.read_bytes())
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
    action.add_argument("--recover-worker", type=int, choices=range(WORKERS))
    parser.add_argument("--expected-implementation-sha256")
    parser.add_argument("--expected-protocol-sha256")
    parser.add_argument("--expected-a434-qualification-sha256")
    args = parser.parse_args()
    if args.freeze_implementation:
        payload = freeze_implementation()
    elif args.freeze_protocol:
        if not args.expected_implementation_sha256:
            parser.error("--freeze-protocol requires implementation hash")
        payload = freeze_protocol(
            expected_implementation_sha256=args.expected_implementation_sha256
        )
    elif args.recover_worker is not None:
        if not args.expected_protocol_sha256 or not args.expected_a434_qualification_sha256:
            parser.error("--recover-worker requires protocol and qualification hashes")
        payload = recover_worker(
            worker_index=args.recover_worker,
            expected_protocol_sha256=args.expected_protocol_sha256,
            expected_a434_qualification_sha256=args.expected_a434_qualification_sha256,
        )
    else:
        payload = analyze()
    print(json.dumps(payload, indent=2, sort_keys=True), flush=True)


if __name__ == "__main__":
    main()

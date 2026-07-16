#!/usr/bin/env python3
"""A420: execute the best qualified A418/A419 W50 schedule with shared stop."""

from __future__ import annotations

import argparse
import importlib.util
import inspect
import json
import math
import os
import sys
import time
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

import numpy as np

ROOT = Path(__file__).parents[2]
RESEARCH = ROOT / "research"
CONFIGS = RESEARCH / "configs"
RESULTS = RESEARCH / "results/v1"

DESIGN = CONFIGS / "chacha20_round20_w50_external_reader_shared_stop_recovery_a420_design_v1.json"
IMPLEMENTATION = CONFIGS / "chacha20_round20_w50_external_reader_shared_stop_recovery_a420_implementation_v1.json"
PROTOCOL = CONFIGS / "chacha20_round20_w50_external_reader_shared_stop_recovery_a420_v1.json"
RESULT = RESULTS / "chacha20_round20_w50_external_reader_shared_stop_recovery_a420_v1.json"
STOP = RESULTS / "chacha20_round20_w50_external_reader_shared_stop_recovery_a420_confirmed_stop_v1.json"
CAUSAL = RESULT.with_suffix(".causal")
REPORT = RESULT.with_suffix(".md")
TEST = ROOT / "tests/test_chacha20_round20_w50_external_reader_shared_stop_recovery_a420.py"
REPRO = ROOT / "scripts/reproduce_chacha20_round20_w50_external_reader_shared_stop_recovery_a420.sh"

A397_RUNNER = RESEARCH / "experiments/chacha20_round20_w50_expanded_eight_worker_recovery_a397.py"
A397_PROTOCOL = CONFIGS / "chacha20_round20_w50_expanded_eight_worker_recovery_a397_v1.json"
A418_RESULT = RESULTS / "chacha20_round20_w50_selection_calibrated_portfolio_repair_a418_v1.json"
A419_RESULT = RESULTS / "chacha20_round20_w50_majority_polarity_portfolio_a419_v1.json"
A418_DESIGN = CONFIGS / "chacha20_round20_w50_selection_calibrated_portfolio_repair_a418_design_v1.json"
A418_IMPLEMENTATION = CONFIGS / "chacha20_round20_w50_selection_calibrated_portfolio_repair_a418_implementation_v1.json"
A419_DESIGN = CONFIGS / "chacha20_round20_w50_majority_polarity_portfolio_a419_design_v1.json"
A419_IMPLEMENTATION = CONFIGS / "chacha20_round20_w50_majority_polarity_portfolio_a419_implementation_v1.json"
A419_MODEL = CONFIGS / "chacha20_round20_w50_majority_polarity_portfolio_a419_model_v1.json"

ATTEMPT_ID = "A420"
DESIGN_SHA256 = "888d518a423f858ce8e7e64e25786229f9671594cd6937f54f4742edb5fc2746"
A397_RUNNER_SHA256 = "099bc92d9b91228ff1563c251ba47a6d4101da48a3dc193cf57a4e4be2f2e8c5"
A397_PROTOCOL_SHA256 = "447baf5e4784d0210f51e194f1a241b7fbfbf1ab239fe16582effdb4b435fb32"
A418_DESIGN_SHA256 = "61c9eab12666229c19aaac936b2ac00710101e831088264968ef47933cae7053"
A418_IMPLEMENTATION_SHA256 = "e527d38d457ddc2ec6940963d0a1899d977511a2653d21852298a2a5958e579d"
A419_DESIGN_SHA256 = "d57e1b16eb917bcb0e755075a4a0405ab67fadbf2205ece5b87dc8b5c52344b4"
A419_IMPLEMENTATION_SHA256 = "ddcdb9262c1711913dca304cbfeb79162a3b4cfee3d6e2fabb7d2f732670a148"
A419_MODEL_SHA256 = "aa68b6c0f9098b445a63822b2e5e7b0a26263eb7073073549c04158911f303c7"

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
        raise RuntimeError(f"cannot import A420 dependency {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


A397 = load_module(A397_RUNNER, "a420_a397")
file_sha256 = A397.file_sha256
canonical_sha256 = A397.canonical_sha256
atomic_json = A397.atomic_json
atomic_bytes = A397.atomic_bytes
relative = A397.relative
path_from_ref = A397.path_from_ref
anchor = A397.anchor


def progress_path(worker_index: int) -> Path:
    if not 0 <= worker_index < WORKERS:
        raise ValueError("A420 worker index differs")
    return RESULTS / f"chacha20_round20_w50_external_reader_shared_stop_recovery_a420_worker_{worker_index}_progress_v1.json"


def load_design() -> dict[str, Any]:
    if file_sha256(DESIGN) != DESIGN_SHA256:
        raise RuntimeError("A420 design hash differs")
    value = json.loads(DESIGN.read_bytes())
    execution = value.get("execution_contract", {})
    boundary = value.get("information_boundary", {})
    if (
        value.get("schema")
        != "chacha20-round20-w50-external-reader-shared-stop-recovery-a420-design-v1"
        or value.get("attempt_id") != ATTEMPT_ID
        or value.get("design_state")
        != "frozen_before_A418_A419_external_results_or_any_A420_candidate_progress_or_result"
        or execution.get("unknown_key_bits") != 50
        or execution.get("workers") != WORKERS
        or execution.get("worker_tasks_each") != STATIC_EPOCHS
        or execution.get("candidates_per_prefix_group") != GROUP_SIZE
        or execution.get("complete_domain_assignments") != DOMAIN_SIZE
        or execution.get("complete_group_before_stop") is not True
        or execution.get("shared_stop_only_after_confirmation") is not True
        or boundary.get("A418_result_available_at_design_freeze") is not False
        or boundary.get("A419_result_available_at_design_freeze") is not False
        or boundary.get("A420_candidate_or_progress_available_at_design_freeze") is not False
        or boundary.get("production_target_labels_used_for_schedule_selection") != 0
        or boundary.get("prior_live_recovery_filter_outcomes_consumed") is not False
        or boundary.get("live_recoveries_must_not_be_interrupted") is not True
    ):
        raise RuntimeError("A420 frozen design semantics differ")
    sources = value["source_anchors"]
    for key, item in sources.items():
        if key.endswith("_path"):
            stem = key.removesuffix("_path")
            anchor(ROOT / item, sources[f"{stem}_sha256"])
    return value


def freeze_implementation() -> dict[str, Any]:
    if any(path.exists() for path in (IMPLEMENTATION, PROTOCOL, RESULT, STOP, CAUSAL, REPORT)):
        raise FileExistsError("A420 implementation or downstream artifact already exists")
    if A418_RESULT.exists() or A419_RESULT.exists():
        raise RuntimeError("A420 code freeze must precede A418 and A419 external results")
    if any(progress_path(index).exists() for index in range(WORKERS)):
        raise RuntimeError("A420 code freeze must precede every progress artifact")
    load_design()
    if not TEST.exists() or not REPRO.exists():
        raise FileNotFoundError("A420 test and reproducer must precede implementation freeze")
    payload: dict[str, Any] = {
        "schema": "chacha20-round20-w50-external-reader-shared-stop-recovery-a420-implementation-v1",
        "attempt_id": ATTEMPT_ID,
        "commitment_state": "complete_executor_frozen_before_A418_A419_results_or_any_A420_candidate",
        "design_sha256": DESIGN_SHA256,
        "source_selection_rule": load_design()["source_selection_rule"],
        "A418_result_available_at_freeze": False,
        "A419_result_available_at_freeze": False,
        "A420_candidate_or_progress_available_at_freeze": False,
        "production_target_labels_used": 0,
        "production_reader_refits": 0,
        "prior_live_recovery_filter_outcomes_consumed": False,
        "anchors": {
            "design": anchor(DESIGN, DESIGN_SHA256),
            "A397_runner": anchor(A397_RUNNER, A397_RUNNER_SHA256),
            "A397_protocol": anchor(A397_PROTOCOL, A397_PROTOCOL_SHA256),
            "A418_design": anchor(A418_DESIGN, A418_DESIGN_SHA256),
            "A418_implementation": anchor(A418_IMPLEMENTATION, A418_IMPLEMENTATION_SHA256),
            "A419_design": anchor(A419_DESIGN, A419_DESIGN_SHA256),
            "A419_implementation": anchor(A419_IMPLEMENTATION, A419_IMPLEMENTATION_SHA256),
            "A419_model": anchor(A419_MODEL, A419_MODEL_SHA256),
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
        raise RuntimeError("A420 implementation hash differs")
    value = json.loads(IMPLEMENTATION.read_bytes())
    if (
        value.get("schema")
        != "chacha20-round20-w50-external-reader-shared-stop-recovery-a420-implementation-v1"
        or value.get("attempt_id") != ATTEMPT_ID
        or value.get("commitment_state")
        != "complete_executor_frozen_before_A418_A419_results_or_any_A420_candidate"
        or value.get("A418_result_available_at_freeze") is not False
        or value.get("A419_result_available_at_freeze") is not False
        or value.get("A420_candidate_or_progress_available_at_freeze") is not False
        or value.get("production_target_labels_used") != 0
        or value.get("production_reader_refits") != 0
        or value.get("prior_live_recovery_filter_outcomes_consumed") is not False
    ):
        raise RuntimeError("A420 implementation semantics differ")
    for row in value["anchors"].values():
        anchor(ROOT / row["path"], row["sha256"])
    unsigned = {
        key: item for key, item in value.items() if key != "implementation_commitment_sha256"
    }
    if value.get("implementation_commitment_sha256") != canonical_sha256(unsigned):
        raise RuntimeError("A420 implementation commitment differs")
    return value


def source_summary(attempt_id: str, value: Mapping[str, Any]) -> dict[str, Any]:
    if attempt_id == "A418":
        schema = "chacha20-round20-w50-selection-calibrated-portfolio-repair-a418-result-v1"
        panel_key = "primary_untouched_holdout_A418_panel"
    elif attempt_id == "A419":
        schema = "chacha20-round20-w50-majority-polarity-portfolio-a419-result-v1"
        panel_key = "primary_untouched_holdout_A419_panel"
    else:
        raise ValueError("A420 source attempt differs")
    external = value.get("external_transfer", {})
    panel = external.get(panel_key, {})
    proof = value.get("schedule_proof", {})
    roles = tuple(value.get("source_role_order", []))
    orders = value.get("worker_cell_orders", {})
    tasks = value.get("worker_tasks", {})
    complete = [int(cell) for role in roles for cell in orders.get(role, [])]
    valid_schedule = (
        value.get("schema") == schema
        and value.get("attempt_id") == attempt_id
        and value.get("production_execution_enabled") is True
        and len(roles) == WORKERS
        and len(set(roles)) == WORKERS
        and set(orders) == set(roles)
        and set(tasks) == set(roles)
        and all(len(orders[role]) == STATIC_EPOCHS for role in roles)
        and all(len(tasks[role]) == STATIC_EPOCHS for role in roles)
        and len(complete) == CELLS
        and set(complete) == set(range(CELLS))
        and proof.get("complete_cover_cells") == CELLS
        and proof.get("duplicate_cells") == 0
        and proof.get("uncovered_cells") == 0
        and proof.get("owner_queue_order_preservation_violations") == 0
        and proof.get("depth_bound_violations") == 0
        and proof.get("total_work_bound_violations") == 0
        and proof.get("makespan_epochs") == STATIC_EPOCHS
        and proof.get("makespan_optimal") is True
        and value.get("production_target_labels_used") == 0
        and value.get("production_reader_refits") == 0
        and value.get("production_candidate_assignments_executed") == 0
    )
    qualified = (
        external.get("qualified") is True
        and valid_schedule
        and isinstance(panel.get("mean_log2_rank"), (int, float))
        and isinstance(panel.get("worst_rank"), int)
    )
    return {
        "attempt_id": attempt_id,
        "qualified": qualified,
        "valid_schedule": valid_schedule,
        "mean_log2_rank": panel.get("mean_log2_rank"),
        "geometric_mean_rank": panel.get("geometric_mean_rank"),
        "worst_rank": panel.get("worst_rank"),
        "worker_roles": list(roles),
    }


def choose_source(
    a418: Mapping[str, Any], a419: Mapping[str, Any]
) -> tuple[dict[str, Any], Mapping[str, Any]]:
    rows = [source_summary("A418", a418), source_summary("A419", a419)]
    eligible = [row for row in rows if row["qualified"]]
    if not eligible:
        raise RuntimeError("A420 has no externally qualified eight-worker source")
    selected = min(
        eligible,
        key=lambda row: (
            float(row["mean_log2_rank"]),
            int(row["worst_rank"]),
            -int(str(row["attempt_id"])[1:]),
        ),
    )
    source = a418 if selected["attempt_id"] == "A418" else a419
    return {
        "selected": selected,
        "candidates": rows,
        "selection_key": [
            selected["mean_log2_rank"],
            selected["worst_rank"],
            selected["attempt_id"],
        ],
    }, source


def worker_order_sha256(values: Sequence[int]) -> str:
    return A397.worker_order_sha256([int(value) for value in values])


def task_list_sha256(values: Sequence[Mapping[str, Any]]) -> str:
    return canonical_sha256([dict(value) for value in values])


def exact_worker_schedule(
    *, worker_index: int, worker_role: str, values: Sequence[int], tasks: Sequence[Mapping[str, Any]], roles: Sequence[str]
) -> tuple[list[int], list[dict[str, Any]]]:
    if not 0 <= worker_index < WORKERS or roles[worker_index] != worker_role:
        raise ValueError("A420 worker identity differs")
    order = [int(value) for value in values]
    rows = [dict(value) for value in tasks]
    if (
        len(order) != STATIC_EPOCHS
        or len(rows) != STATIC_EPOCHS
        or len(set(order)) != STATIC_EPOCHS
        or any(not 0 <= cell < CELLS for cell in order)
    ):
        raise ValueError("A420 worker schedule geometry differs")
    for step, (cell, row) in enumerate(zip(order, rows, strict=True), 1):
        owner = row.get("owner_queue_role")
        if (
            int(row.get("cell", -1)) != cell
            or int(row.get("epoch", -1)) != step
            or row.get("worker_role") != worker_role
            or int(row.get("worker_step_one_based", -1)) != step
            or owner not in roles
            or int(row.get("owner_queue_position_one_based", 0)) < 1
            or row.get("stolen") is not (owner != worker_role)
        ):
            raise ValueError(f"A420 task semantics differ at worker {worker_index} step {step}")
    return order, rows


def freeze_protocol(
    *, expected_implementation_sha256: str, expected_a418_result_sha256: str, expected_a419_result_sha256: str
) -> dict[str, Any]:
    if any(path.exists() for path in (PROTOCOL, RESULT, STOP, CAUSAL, REPORT)):
        raise FileExistsError("A420 protocol or execution artifact already exists")
    if any(progress_path(index).exists() for index in range(WORKERS)):
        raise RuntimeError("A420 protocol freeze must precede every progress artifact")
    implementation = load_implementation(expected_implementation_sha256)
    if file_sha256(A418_RESULT) != expected_a418_result_sha256:
        raise RuntimeError("A420 A418 result hash differs")
    if file_sha256(A419_RESULT) != expected_a419_result_sha256:
        raise RuntimeError("A420 A419 result hash differs")
    a418 = json.loads(A418_RESULT.read_bytes())
    a419 = json.loads(A419_RESULT.read_bytes())
    selection, source = choose_source(a418, a419)
    selected_attempt = selection["selected"]["attempt_id"]
    selected_path = A418_RESULT if selected_attempt == "A418" else A419_RESULT
    selected_sha = (
        expected_a418_result_sha256 if selected_attempt == "A418" else expected_a419_result_sha256
    )
    base_protocol = A397.load_protocol(A397_PROTOCOL_SHA256)
    roles = [str(role) for role in source["source_role_order"]]
    orders: dict[str, list[int]] = {}
    tasks: dict[str, list[dict[str, Any]]] = {}
    for index, role in enumerate(roles):
        orders[role], tasks[role] = exact_worker_schedule(
            worker_index=index,
            worker_role=role,
            values=source["worker_cell_orders"][role],
            tasks=source["worker_tasks"][role],
            roles=roles,
        )
    if set(cell for role in roles for cell in orders[role]) != set(range(CELLS)):
        raise RuntimeError("A420 protocol complete cell cover differs")
    payload: dict[str, Any] = {
        "schema": "chacha20-round20-w50-external-reader-shared-stop-recovery-a420-protocol-v1",
        "attempt_id": ATTEMPT_ID,
        "protocol_state": "best_external_schedule_bound_before_any_A420_candidate_progress_or_result",
        "design_sha256": DESIGN_SHA256,
        "implementation_sha256": expected_implementation_sha256,
        "implementation_commitment_sha256": implementation["implementation_commitment_sha256"],
        "source_selection": selection,
        "selected_source_attempt_id": selected_attempt,
        "selected_source_result_sha256": selected_sha,
        "worker_roles": roles,
        "worker_cell_orders": orders,
        "worker_tasks": tasks,
        "worker_order_uint16be_sha256": {
            role: worker_order_sha256(orders[role]) for role in roles
        },
        "worker_task_list_sha256": {
            role: task_list_sha256(tasks[role]) for role in roles
        },
        "public_challenge": base_protocol["public_challenge"],
        "A384_qualification_sha256": base_protocol["A384_qualification_sha256"],
        "A385_protocol_sha256": base_protocol["A385_protocol_sha256"],
        "grouped_engine_protocol_sha256": A397.A395.A393.A389.A384_PROTOCOL_SHA256,
        "complete_cover_cells": CELLS,
        "duplicate_cells": 0,
        "uncovered_cells": 0,
        "workers": WORKERS,
        "worker_tasks_each": STATIC_EPOCHS,
        "complete_domain_assignments": DOMAIN_SIZE,
        "candidate_or_progress_available_at_protocol_freeze": False,
        "production_target_labels_used": 0,
        "production_reader_refits": 0,
        "production_candidate_assignments_executed_before_protocol": 0,
        "prior_live_recovery_filter_outcomes_consumed": False,
        "anchors": {
            "design": anchor(DESIGN, DESIGN_SHA256),
            "implementation": anchor(IMPLEMENTATION, expected_implementation_sha256),
            "A397_runner": anchor(A397_RUNNER, A397_RUNNER_SHA256),
            "A397_protocol": anchor(A397_PROTOCOL, A397_PROTOCOL_SHA256),
            "A418_result": anchor(A418_RESULT, expected_a418_result_sha256),
            "A419_result": anchor(A419_RESULT, expected_a419_result_sha256),
            "selected_source_result": anchor(selected_path, selected_sha),
            "runner": anchor(Path(__file__)),
        },
    }
    payload["protocol_commitment_sha256"] = canonical_sha256(payload)
    atomic_json(PROTOCOL, payload)
    return payload


def load_protocol(expected_sha256: str | None = None) -> dict[str, Any]:
    if expected_sha256 is not None and file_sha256(PROTOCOL) != expected_sha256:
        raise RuntimeError("A420 protocol hash differs")
    value = json.loads(PROTOCOL.read_bytes())
    roles = tuple(value.get("worker_roles", []))
    if (
        value.get("schema")
        != "chacha20-round20-w50-external-reader-shared-stop-recovery-a420-protocol-v1"
        or value.get("attempt_id") != ATTEMPT_ID
        or value.get("protocol_state")
        != "best_external_schedule_bound_before_any_A420_candidate_progress_or_result"
        or len(roles) != WORKERS
        or len(set(roles)) != WORKERS
        or value.get("complete_cover_cells") != CELLS
        or value.get("duplicate_cells") != 0
        or value.get("uncovered_cells") != 0
        or value.get("worker_tasks_each") != STATIC_EPOCHS
        or value.get("complete_domain_assignments") != DOMAIN_SIZE
        or value.get("candidate_or_progress_available_at_protocol_freeze") is not False
        or value.get("production_target_labels_used") != 0
        or value.get("production_reader_refits") != 0
        or value.get("production_candidate_assignments_executed_before_protocol") != 0
        or value.get("prior_live_recovery_filter_outcomes_consumed") is not False
    ):
        raise RuntimeError("A420 protocol semantics differ")
    load_implementation(value["implementation_sha256"])
    complete: list[int] = []
    for index, role in enumerate(roles):
        order, tasks = exact_worker_schedule(
            worker_index=index,
            worker_role=role,
            values=value["worker_cell_orders"][role],
            tasks=value["worker_tasks"][role],
            roles=roles,
        )
        if (
            worker_order_sha256(order) != value["worker_order_uint16be_sha256"][role]
            or task_list_sha256(tasks) != value["worker_task_list_sha256"][role]
        ):
            raise RuntimeError("A420 protocol worker commitment differs")
        complete.extend(order)
    if len(complete) != CELLS or set(complete) != set(range(CELLS)):
        raise RuntimeError("A420 protocol complete cover differs")
    for row in value["anchors"].values():
        anchor(ROOT / row["path"], row["sha256"])
    unsigned = {key: item for key, item in value.items() if key != "protocol_commitment_sha256"}
    if value.get("protocol_commitment_sha256") != canonical_sha256(unsigned):
        raise RuntimeError("A420 protocol commitment differs")
    A397.A395.A393.A389.A385.validate_challenge(value["public_challenge"])
    return value


def load_resume(
    *, worker_index: int, protocol_sha256: str, order_sha: str, tasks_sha: str
) -> tuple[int, float, int, dict[str, Any] | None]:
    path = progress_path(worker_index)
    if not path.exists():
        return 0, 0.0, 0, None
    value = json.loads(path.read_bytes())
    if (
        value.get("schema")
        != "chacha20-round20-w50-external-reader-shared-stop-recovery-a420-progress-v1"
        or value.get("attempt_id") != ATTEMPT_ID
        or value.get("worker_index") != worker_index
        or value.get("protocol_sha256") != protocol_sha256
        or value.get("worker_order_uint16be_sha256") != order_sha
        or value.get("worker_task_list_sha256") != tasks_sha
        or value.get("matched_control_candidates") != 0
    ):
        raise RuntimeError("A420 progress fingerprint differs")
    status = value.get("status")
    completed = int(value.get("executed_worker_prefix_groups", 0))
    if not 0 <= completed <= STATIC_EPOCHS:
        raise RuntimeError("A420 progress group count differs")
    terminal = status in {"candidate_found", "peer_confirmed", "worker_exhausted"}
    if status not in {"running", "candidate_found", "peer_confirmed", "worker_exhausted"}:
        raise RuntimeError("A420 progress status differs")
    return (
        completed,
        float(value.get("gpu_seconds", 0.0)),
        int(value.get("host_instances", 0)),
        dict(value) if terminal else None,
    )


def progress_snapshot(protocol: Mapping[str, Any]) -> dict[str, Any]:
    panel: dict[str, Any] = {}
    total_groups = 0
    maximum_epoch = 0
    for index, role in enumerate(protocol["worker_roles"]):
        path = progress_path(index)
        if not path.exists():
            panel[role] = {
                "worker_index": index,
                "status": "not_started",
                "executed_worker_prefix_groups": 0,
            }
            continue
        value = json.loads(path.read_bytes())
        if (
            value.get("protocol_sha256") != file_sha256(PROTOCOL)
            or value.get("worker_index") != index
            or value.get("worker_role") != role
        ):
            raise RuntimeError("A420 progress snapshot fingerprint differs")
        groups = int(value.get("executed_worker_prefix_groups", 0))
        total_groups += groups
        maximum_epoch = max(maximum_epoch, int(value.get("static_schedule_epoch", 0)))
        panel[role] = {
            "worker_index": index,
            "status": value.get("status"),
            "executed_worker_prefix_groups": groups,
            "static_schedule_epoch": int(value.get("static_schedule_epoch", 0)),
            "gpu_seconds": float(value.get("gpu_seconds", 0.0)),
            "matched_control_candidates": value.get("matched_control_candidates"),
        }
    return {
        "workers": panel,
        "total_unique_prefix_groups_evaluated": total_groups,
        "total_unique_assignments_evaluated": total_groups * GROUP_SIZE,
        "maximum_completed_static_schedule_epoch": maximum_epoch,
        "theoretical_complete_schedule_epochs": STATIC_EPOCHS,
        "complete_domain_assignments": DOMAIN_SIZE,
        "all_observed_matched_controls_empty": all(
            row.get("matched_control_candidates") in {None, 0}
            for row in panel.values()
        ),
        "prefix_sets_are_disjoint_by_source_construction": True,
    }


def active_started_workers_terminal(protocol: Mapping[str, Any]) -> bool:
    for index, _role in enumerate(protocol["worker_roles"]):
        path = progress_path(index)
        if not path.exists():
            continue
        status = json.loads(path.read_bytes()).get("status")
        if status not in {"candidate_found", "peer_confirmed", "worker_exhausted"}:
            return False
    return True


def build_causal(payload: Mapping[str, Any]) -> dict[str, Any]:
    sys.path.insert(0, str(DOTCAUSAL_SRC))
    from dotcausal.io import CausalReader, CausalWriter

    terminal = "A420_confirmed_external_reader_W50_strict_subset_recovery"
    writer = CausalWriter(api_id="a420w50")
    writer._rules = []
    writer.add_rule(
        name="external_reader_schedule_and_group_engine_to_model",
        description="Execute the prospectively selected eight-reader schedule as disjoint complete W50 groups with one confirmed shared stop.",
        pattern=["A420_frozen_external_reader_schedule", "A384_exact_W50_group_engine"],
        conclusion="A420_sole_factual_W50_model",
        confidence_modifier=1.0,
    )
    writer.add_rule(
        name="model_to_confirmed_strict_subset_recovery",
        description="Require empty matched control, independent eight-block confirmation and fewer than 4,096 unique groups before the shared stop.",
        pattern=["A420_sole_factual_W50_model"],
        conclusion=terminal,
        confidence_modifier=1.0,
    )
    writer.add_triplet(
        trigger="A420:frozen_external_reader_schedule",
        mechanism="disjoint_complete_group_execution_with_confirmed_shared_stop",
        outcome="A420:sole_factual_W50_model",
        confidence=1.0,
        source=payload["execution_sha256"],
        quantification=json.dumps(payload["aggregate_execution"], sort_keys=True),
        evidence=json.dumps(payload["rank_analysis"], sort_keys=True),
        domain="full-round ChaCha20 W50 external Reader recovery",
        quality_score=1.0,
    )
    writer.add_triplet(
        trigger="A420:sole_factual_W50_model",
        mechanism="matched_control_rejection_and_independent_eight_block_confirmation",
        outcome=f"A420:{terminal}",
        confidence=1.0,
        source=payload["measurement_sha256"],
        quantification=json.dumps(payload["confirmation"], sort_keys=True),
        evidence=payload["evidence_stage"],
        domain="confirmed full-round ChaCha20 W50 strict-subset recovery",
        quality_score=1.0,
    )
    writer.add_triplet(
        trigger="A420:frozen_external_reader_schedule",
        mechanism="materialized_external_reader_search_and_confirmation_closure",
        outcome=f"A420:{terminal}",
        confidence=1.0,
        source="materialized:A420_external_reader_recovery_chain",
        quantification="exact retained closure",
        evidence=payload["evidence_stage"],
        domain="AI-native retained inference",
        quality_score=1.0,
        is_inferred=True,
    )
    writer.add_cluster(
        name="A420 external Reader W50 recovery",
        entities=[
            "A420:frozen_external_reader_schedule",
            "A420:sole_factual_W50_model",
            f"A420:{terminal}",
        ],
    )
    writer.add_gap(
        subject=f"A420:{terminal}",
        predicate="next_required_object",
        expected_object_type="W51_or_wider_external_reader_shared_stop_transfer",
        confidence=1.0,
        suggested_queries=[
            "Transfer the externally qualified Reader scheduler to the next exact grouped-engine width."
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
        reader.api_id != "a420w50"
        or len(explicit) != 2
        or len(all_rows) != 3
        or len(inferred) != 1
        or len(reader._rules) != 2
        or len(reader._clusters) != 1
        or len(reader._gaps) != 1
    ):
        raise RuntimeError("A420 authentic Causal reopen gate failed")
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


def finalize_confirmed_stop(protocol: Mapping[str, Any]) -> dict[str, Any]:
    if RESULT.exists():
        return {"status": "peer_confirmed", "result_sha256": file_sha256(RESULT)}
    stop = json.loads(STOP.read_bytes())
    if (
        stop.get("schema")
        != "chacha20-round20-w50-external-reader-shared-stop-recovery-a420-confirmed-stop-v1"
        or stop.get("attempt_id") != ATTEMPT_ID
        or stop.get("protocol_sha256") != file_sha256(PROTOCOL)
        or stop.get("confirmation", {}).get("all_blocks_match") is not True
        or stop.get("discovery", {}).get("control_filter_candidates") != []
    ):
        raise RuntimeError("A420 confirmed stop fingerprint differs")
    while not active_started_workers_terminal(protocol):
        time.sleep(5)
    aggregate = progress_snapshot(protocol)
    unique_groups = int(aggregate["total_unique_prefix_groups_evaluated"])
    if not 1 <= unique_groups <= CELLS:
        raise RuntimeError("A420 aggregate unique group count differs")
    strict_subset = unique_groups < CELLS
    aggregate["strict_subset_of_complete_domain"] = strict_subset
    aggregate["domain_reduction_factor"] = CELLS / unique_groups
    aggregate["search_gain_bits"] = math.log2(CELLS / unique_groups)
    if not strict_subset:
        raise RuntimeError("A420 externally qualified schedule did not stop on a strict subset")
    discovery = stop["discovery"]
    prefix = int(discovery["prefix12"])
    source = json.loads(
        (A418_RESULT if protocol["selected_source_attempt_id"] == "A418" else A419_RESULT).read_bytes()
    )
    rank_analysis = {
        "prefix12": prefix,
        "prefix12_hex": f"{prefix:03x}",
        "selected_source_attempt_id": protocol["selected_source_attempt_id"],
        "source_worker_role": source["cell_worker_role"][prefix],
        "source_schedule_epoch_one_based": int(source["cell_epoch_one_based"][prefix]),
        "source_owner_queue_role": source["cell_owner_queue_role"][prefix],
        "source_owner_queue_position_one_based": int(
            source["cell_owner_queue_position_one_based"][prefix]
        ),
        "executed_winner_worker_step_one_based": int(discovery["worker_step_one_based"]),
        "aggregate_unique_groups_before_confirmed_stop": unique_groups,
    }
    payload: dict[str, Any] = {
        "schema": "chacha20-round20-w50-external-reader-shared-stop-recovery-a420-result-v1",
        "attempt_id": ATTEMPT_ID,
        "evidence_stage": "FULLROUND_R20_EXTERNAL_READER_W50_STRICT_SUBSET_RECOVERY_CONFIRMED",
        "design_sha256": DESIGN_SHA256,
        "implementation_sha256": protocol["implementation_sha256"],
        "implementation_commitment_sha256": protocol["implementation_commitment_sha256"],
        "protocol_sha256": file_sha256(PROTOCOL),
        "protocol_commitment_sha256": protocol["protocol_commitment_sha256"],
        "selected_source_attempt_id": protocol["selected_source_attempt_id"],
        "selected_source_result_sha256": protocol["selected_source_result_sha256"],
        "source_selection": protocol["source_selection"],
        "discovery": discovery,
        "confirmation": stop["confirmation"],
        "aggregate_execution": aggregate,
        "rank_analysis": rank_analysis,
        "matched_control_candidates": 0,
        "factual_candidates": 1,
        "all_4096_output_bits_match": True,
        "complete_group_before_stop": True,
        "early_stop_inside_group": False,
        "production_target_labels_used": 0,
        "production_reader_refits": 0,
        "prior_live_recovery_filter_outcomes_consumed": False,
        "execution_sha256": canonical_sha256(
            {"discovery": discovery, "aggregate_execution": aggregate, "rank_analysis": rank_analysis}
        ),
        "measurement_sha256": canonical_sha256(
            {"confirmation": stop["confirmation"], "matched_control_candidates": 0}
        ),
        "anchors": {
            "design": anchor(DESIGN, DESIGN_SHA256),
            "implementation": anchor(IMPLEMENTATION, protocol["implementation_sha256"]),
            "protocol": anchor(PROTOCOL, file_sha256(PROTOCOL)),
            "confirmed_stop": anchor(STOP, file_sha256(STOP)),
            "selected_source_result": anchor(
                A418_RESULT if protocol["selected_source_attempt_id"] == "A418" else A419_RESULT,
                protocol["selected_source_result_sha256"],
            ),
            "runner": anchor(Path(__file__)),
        },
    }
    payload["causal"] = build_causal(payload)
    atomic_json(RESULT, payload)
    atomic_bytes(
        REPORT,
        (
            "# A420 — External Reader full-round ChaCha20 W50 recovery\n\n"
            f"Evidence stage: **{payload['evidence_stage']}**\n\n"
            f"- Selected external schedule: **{protocol['selected_source_attempt_id']}**\n"
            f"- Aggregate unique W50 groups evaluated: **{unique_groups} / 4096**\n"
            f"- Residual-domain reduction factor: **{aggregate['domain_reduction_factor']:.9f}x**\n"
            f"- Search gain: **{aggregate['search_gain_bits']:.9f} bits**\n"
            "- Factual / matched-control candidates: **1 / 0**\n"
            "- Independent confirmation: **all eight blocks, all 4,096 output bits**\n"
            "- Authentic AI-native Causal readback: **2 explicit + 1 inferred chain**\n"
        ).encode(),
    )
    return payload


def recover_worker(*, worker_index: int, expected_protocol_sha256: str) -> dict[str, Any]:
    if RESULT.exists():
        return {"status": "peer_confirmed", "result_sha256": file_sha256(RESULT)}
    protocol = load_protocol(expected_protocol_sha256)
    if STOP.exists():
        stop = json.loads(STOP.read_bytes())
        if int(stop.get("worker_index", -1)) == worker_index:
            return finalize_confirmed_stop(protocol)
        return {
            "status": "peer_confirmed",
            "worker_index": worker_index,
            "result_pending_from_confirmed_stop_owner": True,
        }
    roles = tuple(protocol["worker_roles"])
    role = roles[worker_index]
    order, tasks = exact_worker_schedule(
        worker_index=worker_index,
        worker_role=role,
        values=protocol["worker_cell_orders"][role],
        tasks=protocol["worker_tasks"][role],
        roles=roles,
    )
    qualification = A397.A395.A393.A389.A385.load_a384_qualification(
        protocol["A384_qualification_sha256"]
    )
    if qualification.get("qualified") is not True:
        raise RuntimeError("A420 exact grouped engine is not qualified")
    engine_protocol = A397.A395.A393.A389.A384.load_protocol(
        protocol["grouped_engine_protocol_sha256"]
    )
    executable_row = engine_protocol["anchors"]["grouped_executable"]
    executable = path_from_ref(executable_row["path"])
    anchor(executable, executable_row["sha256"])
    challenge = protocol["public_challenge"]
    placeholder = np.asarray([0, 0], dtype=np.uint32)

    def host_factory() -> Any:
        return A397.A395.A393.A389.A384.A378.A371.A346.A324.A311.A307.A304.GroupedMetalHost(
            executable,
            A397.A395.A393.A389.A384.initial_for_slab(challenge, 0),
            placeholder,
            placeholder,
        )

    order_sha = protocol["worker_order_uint16be_sha256"][role]
    tasks_sha = protocol["worker_task_list_sha256"][role]

    def write_progress(row: Mapping[str, Any]) -> None:
        atomic_json(
            progress_path(worker_index),
            {
                "schema": "chacha20-round20-w50-external-reader-shared-stop-recovery-a420-progress-v1",
                "attempt_id": ATTEMPT_ID,
                "worker_index": worker_index,
                "worker_role": role,
                "protocol_sha256": expected_protocol_sha256,
                "worker_order_uint16be_sha256": order_sha,
                "worker_task_list_sha256": tasks_sha,
                "A384_qualification_sha256": protocol["A384_qualification_sha256"],
                "matched_control_candidates": 0,
                **dict(row),
            },
        )

    start, prior_gpu, prior_hosts, completed = load_resume(
        worker_index=worker_index,
        protocol_sha256=expected_protocol_sha256,
        order_sha=order_sha,
        tasks_sha=tasks_sha,
    )
    if completed is not None:
        if completed["status"] == "candidate_found" and not STOP.exists():
            discovery = completed
        elif STOP.exists():
            return finalize_confirmed_stop(protocol)
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
        A397.EXPECTED_WORKER_TASKS = {name: STATIC_EPOCHS for name in roles}
        A397.SOURCE_ROLES = roles
        A397.ROLES = roles
        A397.ROLE_TO_SLUG = {name: f"worker_{index}" for index, name in enumerate(roles)}
        discovery = A397.ordered_worker_discovery(
            worker=role,
            host_factory=host_factory,
            challenge=challenge,
            worker_order=order,
            worker_tasks=tasks,
            peer_result_exists=lambda: STOP.exists() or RESULT.exists(),
            start_group=start,
            prior_gpu_seconds=prior_gpu,
            prior_host_instances=prior_hosts,
            progress_callback=write_progress,
        )
    if discovery["status"] in {"peer_confirmed", "worker_exhausted"}:
        write_progress(discovery)
        if discovery["status"] == "worker_exhausted":
            exhausted = sum(
                progress_path(index).exists()
                and json.loads(progress_path(index).read_bytes()).get("status") == "worker_exhausted"
                for index in range(WORKERS)
            )
            if exhausted == WORKERS:
                raise RuntimeError("A420 all disjoint workers exhausted without a model")
        return discovery
    candidate = int(discovery["candidate"])
    confirmation = A397.A395.A393.A389.A385.confirm(challenge, candidate)
    if confirmation.get("all_blocks_match") is not True:
        raise RuntimeError("A420 independent eight-block confirmation failed")
    if discovery.get("control_filter_candidates") != []:
        raise RuntimeError("A420 matched control produced a candidate")
    atomic_json(
        STOP,
        {
            "schema": "chacha20-round20-w50-external-reader-shared-stop-recovery-a420-confirmed-stop-v1",
            "attempt_id": ATTEMPT_ID,
            "protocol_sha256": expected_protocol_sha256,
            "worker_index": worker_index,
            "worker_role": role,
            "discovery": discovery,
            "confirmation": confirmation,
        },
    )
    return finalize_confirmed_stop(protocol)


def analyze() -> dict[str, Any]:
    payload: dict[str, Any] = {
        "attempt_id": ATTEMPT_ID,
        "design_sha256": DESIGN_SHA256,
        "implementation_frozen": IMPLEMENTATION.exists(),
        "A418_result_available": A418_RESULT.exists(),
        "A419_result_available": A419_RESULT.exists(),
        "protocol_frozen": PROTOCOL.exists(),
        "confirmed_stop_available": STOP.exists(),
        "result_complete": RESULT.exists(),
    }
    if IMPLEMENTATION.exists():
        payload["implementation_sha256"] = file_sha256(IMPLEMENTATION)
        load_implementation(payload["implementation_sha256"])
    if A418_RESULT.exists() and A419_RESULT.exists():
        a418 = json.loads(A418_RESULT.read_bytes())
        a419 = json.loads(A419_RESULT.read_bytes())
        payload["source_candidates"] = [
            source_summary("A418", a418), source_summary("A419", a419)
        ]
        try:
            payload["prospective_source_choice"] = choose_source(a418, a419)[0]
        except RuntimeError as exc:
            payload["source_boundary"] = str(exc)
    if PROTOCOL.exists():
        payload["protocol_sha256"] = file_sha256(PROTOCOL)
        protocol = load_protocol(payload["protocol_sha256"])
        payload["selected_source_attempt_id"] = protocol["selected_source_attempt_id"]
        payload["progress"] = progress_snapshot(protocol)
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
    action.add_argument("--recover-worker", type=int)
    parser.add_argument("--expected-implementation-sha256")
    parser.add_argument("--expected-a418-result-sha256")
    parser.add_argument("--expected-a419-result-sha256")
    parser.add_argument("--expected-protocol-sha256")
    args = parser.parse_args()
    if args.freeze_implementation:
        payload = freeze_implementation()
    elif args.freeze_protocol:
        if (
            not args.expected_implementation_sha256
            or not args.expected_a418_result_sha256
            or not args.expected_a419_result_sha256
        ):
            parser.error("--freeze-protocol requires implementation, A418 and A419 hashes")
        payload = freeze_protocol(
            expected_implementation_sha256=args.expected_implementation_sha256,
            expected_a418_result_sha256=args.expected_a418_result_sha256,
            expected_a419_result_sha256=args.expected_a419_result_sha256,
        )
    elif args.recover_worker is not None:
        if not args.expected_protocol_sha256:
            parser.error("--recover-worker requires --expected-protocol-sha256")
        payload = recover_worker(
            worker_index=args.recover_worker,
            expected_protocol_sha256=args.expected_protocol_sha256,
        )
    else:
        payload = analyze()
    print(json.dumps(payload, indent=2, sort_keys=True), flush=True)


if __name__ == "__main__":
    main()

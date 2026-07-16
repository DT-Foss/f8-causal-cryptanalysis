#!/usr/bin/env python3
"""A393: execute A392's disjoint W50 lanes with one shared confirmed stop."""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import inspect
import json
import math
import os
import struct
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

DESIGN = CONFIGS / "chacha20_round20_w50_disjoint_parallel_recovery_a393_design_v1.json"
IMPLEMENTATION = (
    CONFIGS / "chacha20_round20_w50_disjoint_parallel_recovery_a393_implementation_v1.json"
)
PROTOCOL = CONFIGS / "chacha20_round20_w50_disjoint_parallel_recovery_a393_v1.json"
RESULT = RESULTS / "chacha20_round20_w50_disjoint_parallel_recovery_a393_v1.json"
CAUSAL = RESULT.with_suffix(".causal")
REPORT = RESULT.with_suffix(".md")
TEST = ROOT / "tests/test_chacha20_round20_w50_disjoint_parallel_recovery_a393.py"
REPRO = ROOT / "scripts/reproduce_chacha20_round20_w50_disjoint_parallel_recovery_a393.sh"

A389_RUNNER = (
    RESEARCH
    / "experiments/chacha20_round20_w50_public_output_factor3_recovery_a389.py"
)
A392_RESULT = (
    RESULTS / "chacha20_round20_w50_disjoint_parallel_reader_scheduler_a392_v1.json"
)
A392_CAUSAL = A392_RESULT.with_suffix(".causal")

ATTEMPT_ID = "A393"
DESIGN_SHA256 = "b37b8e973d95a7f3317cbe565dfd133e3e94c85faf70ef27ced8b3a5c2699512"
A389_RUNNER_SHA256 = "23602ef77bba32a019b78f776f1fa6a60d6ab13160c79644e4796b5ffe3e9ca5"
A392_RESULT_SHA256 = "950d6376cf05a32f2e7a2043b5662c1b33b375b567e695aaf2e4db494c1d725a"
A392_CAUSAL_SHA256 = "9482fea926e3f32235c668290410b420f27ab301a8c6cc418b192095473ab793"
SCHEDULE_NAME = "three_lane_A385_Direct12_A386"
ROLE_A385 = "A385_pretarget_six_view"
ROLE_DIRECT = "A388_W50_public_output_direct12"
ROLE_A386 = "A386_calibrated_target_blind_transfer"
ROLES = (ROLE_A385, ROLE_DIRECT, ROLE_A386)
SLUG_TO_ROLE = {
    "a385": ROLE_A385,
    "direct12": ROLE_DIRECT,
    "a386": ROLE_A386,
}
ROLE_TO_SLUG = {role: slug for slug, role in SLUG_TO_ROLE.items()}
EXPECTED_LANE_SIZES = {
    ROLE_A385: 1050,
    ROLE_DIRECT: 1821,
    ROLE_A386: 1225,
}
CELLS = 4096
GROUP_SIZE = 1 << 38
DOMAIN_SIZE = 1 << 50
WORD0_SUFFIX_BITS = 20
HOST_REFRESH_GROUPS = 8
DOTCAUSAL_SRC = Path(
    "/Users/bhkmie/Documents/Forschung/O1/vendor/fabel/dotcausal_package/src"
)


def progress_path(role: str) -> Path:
    if role not in ROLE_TO_SLUG:
        raise ValueError(f"A393 unknown lane role {role}")
    return RESULTS / (
        "chacha20_round20_w50_disjoint_parallel_recovery_"
        f"a393_{ROLE_TO_SLUG[role]}_progress_v1.json"
    )


def load_module(path: Path, name: str) -> Any:
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot import A393 dependency {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


A389 = load_module(A389_RUNNER, "a393_a389")
file_sha256 = A389.file_sha256
canonical_sha256 = A389.canonical_sha256
atomic_json = A389.atomic_json
atomic_bytes = A389.atomic_bytes
relative = A389.relative
path_from_ref = A389.path_from_ref
anchor = A389.anchor


def exact_lane(values: Sequence[int], role: str) -> list[int]:
    if role not in EXPECTED_LANE_SIZES:
        raise ValueError(f"A393 unknown lane {role}")
    lane = [int(value) for value in values]
    if (
        len(lane) != EXPECTED_LANE_SIZES[role]
        or len(set(lane)) != len(lane)
        or any(not 0 <= cell < CELLS for cell in lane)
    ):
        raise ValueError(f"A393 {role} lane geometry differs")
    return lane


def lane_sha256(values: Sequence[int]) -> str:
    payload = b"".join(struct.pack(">H", int(value)) for value in values)
    return hashlib.sha256(payload).hexdigest()


def load_design() -> dict[str, Any]:
    if file_sha256(DESIGN) != DESIGN_SHA256:
        raise RuntimeError("A393 design hash differs")
    value = json.loads(DESIGN.read_bytes())
    execution = value.get("execution_contract", {})
    lanes = value.get("lane_contract", {})
    boundary = value.get("information_boundary", {})
    if (
        value.get("schema")
        != "chacha20-round20-w50-disjoint-parallel-recovery-a393-design-v1"
        or value.get("attempt_id") != ATTEMPT_ID
        or value.get("design_state")
        != "frozen_after_A392_exact_scheduler_before_any_A393_lane_candidate_prefix_progress_or_result"
        or execution.get("unknown_key_bits") != 50
        or execution.get("candidates_per_prefix_group") != GROUP_SIZE
        or execution.get("complete_domain_assignments") != DOMAIN_SIZE
        or execution.get("slabs_per_prefix_group") != 128
        or lanes.get("schedule_name") != SCHEDULE_NAME
        or tuple(lanes.get("roles", [])) != ROLES
        or lanes.get("partition_sizes") != EXPECTED_LANE_SIZES
        or lanes.get("complete_cover_cells") != CELLS
        or lanes.get("duplicate_cells") != 0
        or lanes.get("uncovered_cells") != 0
        or boundary.get("target_labels_used_for_lane_construction") != 0
        or boundary.get("reader_refits") != 0
        or boundary.get("candidate_assignments_executed_for_lane_construction")
        != 0
        or boundary.get("A387_A389_A391_progress_or_filter_outcomes_consumed")
        is not False
    ):
        raise RuntimeError("A393 frozen design semantics differ")
    for name, source_path in value["source_anchors"].items():
        if name.endswith("_path"):
            stem = name.removesuffix("_path")
            anchor(ROOT / source_path, value["source_anchors"][f"{stem}_sha256"])
    return value


def load_schedule() -> tuple[dict[str, Any], dict[str, list[int]]]:
    anchor(A392_RESULT, A392_RESULT_SHA256)
    anchor(A392_CAUSAL, A392_CAUSAL_SHA256)
    value = json.loads(A392_RESULT.read_bytes())
    schedule = value.get("schedules", {}).get(SCHEDULE_NAME, {})
    raw_lanes = schedule.get("lane_orders", {})
    if (
        value.get("schema")
        != "chacha20-round20-w50-disjoint-parallel-reader-scheduler-a392-result-v1"
        or value.get("target_labels_used") != 0
        or value.get("reader_refits") != 0
        or value.get("candidate_assignments_executed") != 0
        or tuple(schedule.get("role_order", [])) != ROLES
        or schedule.get("proof", {}).get("duplicate_cells") != 0
        or schedule.get("proof", {}).get("uncovered_cells") != 0
        or schedule.get("proof", {}).get("wall_depth_violations") != 0
        or schedule.get("proof", {}).get("total_unique_work_violations") != 0
        or set(raw_lanes) != set(ROLES)
    ):
        raise RuntimeError("A393 A392 schedule semantics differ")
    lanes = {role: exact_lane(raw_lanes[role], role) for role in ROLES}
    flattened = [cell for role in ROLES for cell in lanes[role]]
    if len(flattened) != CELLS or set(flattened) != set(range(CELLS)):
        raise RuntimeError("A393 lane cover differs")
    expected_hashes = schedule["lane_order_uint16be_sha256"]
    if any(lane_sha256(lanes[role]) != expected_hashes[role] for role in ROLES):
        raise RuntimeError("A393 lane bytes differ")
    return value, lanes


def assert_pre_execution() -> None:
    if RESULT.exists() or CAUSAL.exists() or REPORT.exists():
        raise RuntimeError("A393 freeze must precede result artifacts")
    if any(progress_path(role).exists() for role in ROLES):
        raise RuntimeError("A393 freeze must precede every lane progress artifact")


def freeze_implementation() -> dict[str, Any]:
    if IMPLEMENTATION.exists() or PROTOCOL.exists():
        raise FileExistsError("A393 implementation or protocol already exists")
    assert_pre_execution()
    design = load_design()
    schedule, lanes = load_schedule()
    source, _order, qualification, _sources = A389.load_sources()
    if source["public_challenge"]["unknown_key_bits"] != 50:
        raise RuntimeError("A393 A385 challenge width differs")
    if qualification["matched_control_empty"] is not True:
        raise RuntimeError("A393 W50 engine qualification differs")
    if not TEST.exists() or not REPRO.exists():
        raise FileNotFoundError("A393 test and reproducer must precede freeze")
    payload: dict[str, Any] = {
        "schema": "chacha20-round20-w50-disjoint-parallel-recovery-a393-implementation-v1",
        "attempt_id": ATTEMPT_ID,
        "commitment_state": "frozen_before_any_A393_lane_candidate_prefix_progress_or_result",
        "design_sha256": DESIGN_SHA256,
        "execution_contract": design["execution_contract"],
        "lane_order_uint16be_sha256": {
            role: lane_sha256(lanes[role]) for role in ROLES
        },
        "A392_schedule_commitment_sha256": schedule[
            "schedule_commitment_sha256"
        ],
        "A393_candidate_or_prefix_available_at_implementation_freeze": False,
        "anchors": {
            "design": anchor(DESIGN, DESIGN_SHA256),
            "A389_runner": anchor(A389_RUNNER, A389_RUNNER_SHA256),
            "A392_result": anchor(A392_RESULT, A392_RESULT_SHA256),
            "A392_causal": anchor(A392_CAUSAL, A392_CAUSAL_SHA256),
            "A384_qualification": anchor(
                A389.A384_QUALIFICATION, A389.A384_QUALIFICATION_SHA256
            ),
            "A385_protocol": anchor(A389.A385_PROTOCOL, A389.A385_PROTOCOL_SHA256),
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
        raise RuntimeError("A393 implementation hash differs")
    value = json.loads(IMPLEMENTATION.read_bytes())
    if (
        value.get("schema")
        != "chacha20-round20-w50-disjoint-parallel-recovery-a393-implementation-v1"
        or value.get("attempt_id") != ATTEMPT_ID
        or value.get("design_sha256") != DESIGN_SHA256
        or value.get("A393_candidate_or_prefix_available_at_implementation_freeze")
        is not False
    ):
        raise RuntimeError("A393 implementation semantics differ")
    for row in value["anchors"].values():
        anchor(path_from_ref(row["path"]), row["sha256"])
    unsigned = {
        key: item
        for key, item in value.items()
        if key != "implementation_commitment_sha256"
    }
    if value.get("implementation_commitment_sha256") != canonical_sha256(unsigned):
        raise RuntimeError("A393 implementation commitment differs")
    return value


def freeze_protocol(*, expected_implementation_sha256: str) -> dict[str, Any]:
    if PROTOCOL.exists():
        raise FileExistsError("A393 protocol already exists")
    assert_pre_execution()
    implementation = load_implementation(expected_implementation_sha256)
    schedule, lanes = load_schedule()
    source, _order, qualification, _sources = A389.load_sources()
    payload: dict[str, Any] = {
        "schema": "chacha20-round20-w50-disjoint-parallel-recovery-a393-protocol-v1",
        "attempt_id": ATTEMPT_ID,
        "protocol_state": "three_disjoint_A392_lanes_bound_before_any_A393_candidate_prefix_progress_or_result",
        "design_sha256": DESIGN_SHA256,
        "implementation_sha256": expected_implementation_sha256,
        "implementation_commitment_sha256": implementation[
            "implementation_commitment_sha256"
        ],
        "A384_qualification_sha256": A389.A384_QUALIFICATION_SHA256,
        "A384_semantic_qualification_sha256": qualification["qualification_sha256"],
        "A385_protocol_sha256": A389.A385_PROTOCOL_SHA256,
        "A392_result_sha256": A392_RESULT_SHA256,
        "A392_schedule_commitment_sha256": schedule[
            "schedule_commitment_sha256"
        ],
        "public_challenge_sha256": source["public_challenge_sha256"],
        "public_challenge": source["public_challenge"],
        "schedule_name": SCHEDULE_NAME,
        "lane_role_order": list(ROLES),
        "lane_order_uint16be_sha256": {
            role: lane_sha256(lanes[role]) for role in ROLES
        },
        "lane_orders": lanes,
        "execution_contract": load_design()["execution_contract"],
        "information_boundary": {
            "A393_candidate_or_prefix_available_at_protocol_freeze": False,
            "A392_lanes_frozen_before_A393_execution": True,
            "A385_assignment_absent_from_protocol": True,
            "target_labels_used_for_lane_construction": 0,
            "reader_refits": 0,
            "candidate_assignments_executed_for_lane_construction": 0,
            "A387_A389_A391_progress_or_filter_outcomes_consumed": False,
        },
        "anchors": {
            "design": anchor(DESIGN, DESIGN_SHA256),
            "implementation": anchor(
                IMPLEMENTATION, expected_implementation_sha256
            ),
            "A392_result": anchor(A392_RESULT, A392_RESULT_SHA256),
            "A392_causal": anchor(A392_CAUSAL, A392_CAUSAL_SHA256),
            "A384_qualification": anchor(
                A389.A384_QUALIFICATION, A389.A384_QUALIFICATION_SHA256
            ),
            "A385_protocol": anchor(A389.A385_PROTOCOL, A389.A385_PROTOCOL_SHA256),
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
            "A392_schedule_commitment_sha256": payload[
                "A392_schedule_commitment_sha256"
            ],
            "public_challenge_sha256": payload["public_challenge_sha256"],
            "lane_order_uint16be_sha256": payload[
                "lane_order_uint16be_sha256"
            ],
            "information_boundary": payload["information_boundary"],
        }
    )
    atomic_json(PROTOCOL, payload)
    assert_pre_execution()
    return payload


def load_protocol(expected_sha256: str) -> dict[str, Any]:
    if file_sha256(PROTOCOL) != expected_sha256:
        raise RuntimeError("A393 protocol hash differs")
    value = json.loads(PROTOCOL.read_bytes())
    raw_lanes = value.get("lane_orders", {})
    if set(raw_lanes) != set(ROLES):
        raise RuntimeError("A393 protocol lane role set differs")
    lanes = {role: exact_lane(raw_lanes[role], role) for role in ROLES}
    flattened = [cell for role in ROLES for cell in lanes[role]]
    boundary = value.get("information_boundary", {})
    if (
        value.get("schema")
        != "chacha20-round20-w50-disjoint-parallel-recovery-a393-protocol-v1"
        or value.get("attempt_id") != ATTEMPT_ID
        or value.get("schedule_name") != SCHEDULE_NAME
        or tuple(value.get("lane_role_order", [])) != ROLES
        or any(
            lane_sha256(lanes[role])
            != value.get("lane_order_uint16be_sha256", {}).get(role)
            for role in ROLES
        )
        or len(flattened) != CELLS
        or set(flattened) != set(range(CELLS))
        or len(flattened) != len(set(flattened))
        or boundary.get("A393_candidate_or_prefix_available_at_protocol_freeze")
        is not False
        or boundary.get("target_labels_used_for_lane_construction") != 0
        or canonical_sha256(value.get("public_challenge"))
        != value.get("public_challenge_sha256")
    ):
        raise RuntimeError("A393 protocol semantics differ")
    for row in value["anchors"].values():
        anchor(path_from_ref(row["path"]), row["sha256"])
    load_implementation(value["implementation_sha256"])
    A389.A385.validate_challenge(value["public_challenge"])
    return value


def load_resume(
    *, role: str, protocol_sha256: str, lane_sha: str
) -> tuple[int, float, int, dict[str, Any] | None]:
    path = progress_path(role)
    if not path.exists():
        return 0, 0.0, 0, None
    value = json.loads(path.read_bytes())
    if (
        value.get("schema")
        != "chacha20-round20-w50-disjoint-parallel-recovery-a393-progress-v1"
        or value.get("attempt_id") != ATTEMPT_ID
        or value.get("lane_role") != role
        or value.get("protocol_sha256") != protocol_sha256
        or value.get("lane_order_uint16be_sha256") != lane_sha
        or value.get("matched_control_candidates") != 0
    ):
        raise RuntimeError("A393 progress fingerprint differs")
    status = value.get("status")
    if status == "candidate_found":
        excluded = {
            "schema",
            "attempt_id",
            "lane_role",
            "lane_slug",
            "protocol_sha256",
            "lane_order_uint16be_sha256",
            "status",
        }
        return 0, 0.0, 0, {
            key: item for key, item in value.items() if key not in excluded
        }
    completed = int(value.get("executed_lane_prefix_groups", -1))
    if (
        status not in {"running", "lane_exhausted"}
        or not 0 <= completed <= EXPECTED_LANE_SIZES[role]
        or value.get("factual_filter_candidates") != 0
    ):
        raise RuntimeError("A393 resumable progress state differs")
    if status == "lane_exhausted":
        return completed, float(value.get("gpu_seconds", 0.0)), int(
            value.get("host_instances", 0)
        ), {"status": "lane_exhausted", **value}
    return (
        completed,
        float(value.get("gpu_seconds", 0.0)),
        int(value.get("host_instances", 0)),
        None,
    )


def ordered_lane_discovery(
    *,
    role: str,
    host_factory: Callable[[], Any],
    challenge: Mapping[str, Any],
    lane_order: Sequence[int],
    peer_result_exists: Callable[[], bool],
    start_group: int = 0,
    prior_gpu_seconds: float = 0.0,
    prior_host_instances: int = 0,
    progress_callback: Callable[[Mapping[str, Any]], None] | None = None,
) -> dict[str, Any]:
    lane = exact_lane(lane_order, role)
    if not 0 <= start_group <= len(lane):
        raise ValueError("A393 resume group lies outside lane")
    if peer_result_exists():
        return {
            "status": "peer_confirmed",
            "lane_role": role,
            "executed_lane_prefix_groups": start_group,
            "lane_prefix_groups": len(lane),
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
        for lane_index in range(start_group, len(lane)):
            if peer_result_exists():
                return {
                    "status": "peer_confirmed",
                    "lane_role": role,
                    "executed_lane_prefix_groups": lane_index,
                    "lane_prefix_groups": len(lane),
                    "gpu_seconds": gpu_seconds,
                    "host_instances": host_instances,
                    "volatile_wall_seconds": time.perf_counter() - started,
                }
            prefix = lane[lane_index]
            if lane_index == start_group or lane_index % HOST_REFRESH_GROUPS == 0:
                if host is not None:
                    host.close()
                host = host_factory()
                host_instances += 1
            observed = A389.A384.filter_complete_prefix(
                host=host,
                challenge=challenge,
                prefix=prefix,
                target=target,
                control=control,
            )
            factual = [int(value) for value in observed["factual_candidates"]]
            controls = [int(value) for value in observed["control_candidates"]]
            gpu_seconds += float(observed["gpu_seconds"])
            groups = lane_index + 1
            if controls:
                raise RuntimeError("A393 matched control produced a candidate")
            if not factual:
                if progress_callback is not None:
                    progress_callback(
                        {
                            "status": "running",
                            "executed_lane_prefix_groups": groups,
                            "lane_prefix_groups": len(lane),
                            "executed_lane_assignments": groups * GROUP_SIZE,
                            "matched_control_candidates": 0,
                            "factual_filter_candidates": 0,
                            "gpu_seconds": gpu_seconds,
                            "host_instances": host_instances,
                            "last_completed_prefix12": prefix,
                        }
                    )
                continue
            if len(factual) != 1:
                raise RuntimeError("A393 complete W50 group produced multiple filters")
            candidate = factual[0]
            if ((candidate >> WORD0_SUFFIX_BITS) & (CELLS - 1)) != prefix:
                raise RuntimeError("A393 candidate prefix differs")
            decoded = A389.A384.decode_assignment(candidate)
            found = {
                "status": "candidate_found",
                "lane_role": role,
                "lane_slug": ROLE_TO_SLUG[role],
                "candidate": candidate,
                "candidate_hex": f"{candidate:013x}",
                "key_word0": decoded["word0"],
                "key_word1_low18": decoded["word1_low18"],
                "prefix12": prefix,
                "prefix12_hex": f"{prefix:03x}",
                "executed_lane_prefix_groups": groups,
                "lane_prefix_groups": len(lane),
                "executed_lane_group_dispatches": groups * 128,
                "executed_lane_assignments": groups * GROUP_SIZE,
                "complete_W50_group_execution_before_stop": True,
                "early_stop_inside_group": False,
                "factual_filter_candidates": factual,
                "matched_control_candidates": 0,
                "control_filter_candidates": [],
                "host_refresh_interval_prefix_groups": HOST_REFRESH_GROUPS,
                "host_instances": host_instances,
                "gpu_seconds": gpu_seconds,
                "volatile_wall_seconds": time.perf_counter() - started,
            }
            if progress_callback is not None:
                progress_callback(found)
            return found
    finally:
        if host is not None:
            host.close()
    exhausted = {
        "status": "lane_exhausted",
        "lane_role": role,
        "lane_slug": ROLE_TO_SLUG[role],
        "executed_lane_prefix_groups": len(lane),
        "lane_prefix_groups": len(lane),
        "executed_lane_assignments": len(lane) * GROUP_SIZE,
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
    all_control_zero = True
    for role in ROLES:
        path = progress_path(role)
        if not path.exists():
            panel[role] = {
                "status": "not_started",
                "executed_lane_prefix_groups": 0,
                "lane_prefix_groups": len(protocol["lane_orders"][role]),
            }
            continue
        value = json.loads(path.read_bytes())
        if (
            value.get("protocol_sha256") != file_sha256(PROTOCOL)
            or value.get("lane_role") != role
            or value.get("lane_order_uint16be_sha256")
            != protocol["lane_order_uint16be_sha256"][role]
        ):
            raise RuntimeError("A393 progress snapshot fingerprint differs")
        groups = int(value.get("executed_lane_prefix_groups", 0))
        total_groups += groups
        all_control_zero &= value.get("matched_control_candidates") == 0
        panel[role] = {
            "status": value.get("status"),
            "executed_lane_prefix_groups": groups,
            "lane_prefix_groups": len(protocol["lane_orders"][role]),
            "gpu_seconds": float(value.get("gpu_seconds", 0.0)),
            "matched_control_candidates": value.get("matched_control_candidates"),
        }
    return {
        "lanes": panel,
        "total_unique_prefix_groups_evaluated": total_groups,
        "total_unique_assignments_evaluated": total_groups * GROUP_SIZE,
        "complete_domain_assignments": DOMAIN_SIZE,
        "all_observed_matched_controls_empty": all_control_zero,
        "prefix_sets_are_disjoint_by_A392_construction": True,
    }


def rank_panel(prefix: int, role: str, schedule: Mapping[str, Any]) -> dict[str, Any]:
    rows = schedule["schedules"][SCHEDULE_NAME]["per_cell_proof"]
    row = rows[prefix]
    if int(row["cell"]) != prefix or row["owner"] != role:
        raise RuntimeError("A393 confirmed prefix owner differs")
    return {
        **row,
        "owner_lane_order_uint16be_sha256": schedule["schedules"][SCHEDULE_NAME][
            "lane_order_uint16be_sha256"
        ][role],
        "ranks_computed_only_after_independent_confirmation": True,
    }


def build_causal(payload: Mapping[str, Any]) -> dict[str, Any]:
    sys.path.insert(0, str(DOTCAUSAL_SRC))
    from dotcausal.io import CausalReader, CausalWriter

    terminal = "A393:confirmed_disjoint_parallel_W50_recovery"
    writer = CausalWriter(api_id="a393w50")
    writer._rules = []
    writer.add_rule(
        name="disjoint_lanes_and_engine_to_model",
        description="A392 owner lanes execute complete qualified W50 groups with no duplicated prefixes and one shared success stop.",
        pattern=["A392_exact_disjoint_W50_lanes", "A384_exact_W50_group_engine"],
        conclusion="A393_sole_factual_W50_model",
        confidence_modifier=1.0,
    )
    writer.add_rule(
        name="model_to_confirmed_parallel_recovery",
        description="The sole factual model passes matched control and dual independent eight-block confirmation.",
        pattern=["A393_sole_factual_W50_model"],
        conclusion="A393_confirmed_disjoint_parallel_W50_recovery",
        confidence_modifier=1.0,
    )
    writer.add_triplet(
        trigger="A392:exact_disjoint_W50_lanes",
        mechanism="qualified_parallel_complete_group_search_with_shared_stop",
        outcome="A393:sole_factual_W50_model",
        confidence=1.0,
        source=payload["execution_sha256"],
        quantification=json.dumps(payload["aggregate_execution"], sort_keys=True),
        evidence=json.dumps(payload["rank_analysis"], sort_keys=True),
        domain="fresh full-round ChaCha20 W50 disjoint parallel recovery",
        quality_score=1.0,
    )
    writer.add_triplet(
        trigger="A393:sole_factual_W50_model",
        mechanism="matched_control_rejection_and_dual_eight_block_confirmation",
        outcome=terminal,
        confidence=1.0,
        source=payload["measurement_sha256"],
        quantification=json.dumps(payload["confirmation"], sort_keys=True),
        evidence=payload["evidence_stage"],
        domain="confirmed full-round ChaCha20 W50 parallel recovery",
        quality_score=1.0,
    )
    writer.add_triplet(
        trigger="A392:exact_disjoint_W50_lanes",
        mechanism="materialized_parallel_search_and_confirmation_closure",
        outcome=terminal,
        confidence=1.0,
        source="materialized:A393_disjoint_parallel_W50_recovery_chain",
        quantification="exact retained closure",
        evidence=payload["evidence_stage"],
        domain="AI-native retained inference",
        quality_score=1.0,
        is_inferred=True,
    )
    writer.add_cluster(
        name="A393 disjoint parallel W50 recovery",
        entities=["A392:exact_disjoint_W50_lanes", "A393:sole_factual_W50_model", terminal],
    )
    writer.add_gap(
        subject=terminal,
        predicate="next_required_object",
        expected_object_type="W51_disjoint_parallel_transfer",
        confidence=1.0,
        suggested_queries=[
            "Transfer the no-duplicate owner-lane executor after exact W51 engine qualification and a fresh W51 Direct12 order."
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
        reader.api_id != "a393w50"
        or len(explicit) != 2
        or len(all_rows) != 3
        or len(inferred) != 1
        or len(reader._rules) != 2
        or len(reader._clusters) != 1
        or len(reader._gaps) != 1
    ):
        raise RuntimeError("A393 authentic Causal reopen gate failed")
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


def recover_lane(*, role: str, expected_protocol_sha256: str) -> dict[str, Any]:
    if RESULT.exists():
        return {
            "status": "peer_confirmed",
            "lane_role": role,
            "result_sha256": file_sha256(RESULT),
        }
    protocol = load_protocol(expected_protocol_sha256)
    qualification = A389.A385.load_a384_qualification(
        protocol["A384_qualification_sha256"]
    )
    engine_protocol = A389.A384.load_protocol(A389.A384_PROTOCOL_SHA256)
    executable_row = engine_protocol["anchors"]["grouped_executable"]
    executable = path_from_ref(executable_row["path"])
    anchor(executable, executable_row["sha256"])
    challenge = protocol["public_challenge"]
    lane = exact_lane(protocol["lane_orders"][role], role)
    placeholder = np.asarray([0, 0], dtype=np.uint32)

    def host_factory() -> Any:
        return A389.A384.A378.A371.A346.A324.A311.A307.A304.GroupedMetalHost(
            executable,
            A389.A384.initial_for_slab(challenge, 0),
            placeholder,
            placeholder,
        )

    lane_hash = protocol["lane_order_uint16be_sha256"][role]

    def write_progress(row: Mapping[str, Any]) -> None:
        atomic_json(
            progress_path(role),
            {
                "schema": "chacha20-round20-w50-disjoint-parallel-recovery-a393-progress-v1",
                "attempt_id": ATTEMPT_ID,
                "lane_role": role,
                "lane_slug": ROLE_TO_SLUG[role],
                "protocol_sha256": expected_protocol_sha256,
                "lane_order_uint16be_sha256": lane_hash,
                "A384_qualification_sha256": protocol[
                    "A384_qualification_sha256"
                ],
                **dict(row),
            },
        )

    start, prior_gpu, prior_hosts, completed = load_resume(
        role=role,
        protocol_sha256=expected_protocol_sha256,
        lane_sha=lane_hash,
    )
    if completed is not None:
        return completed
    discovery = ordered_lane_discovery(
        role=role,
        host_factory=host_factory,
        challenge=challenge,
        lane_order=lane,
        peer_result_exists=RESULT.exists,
        start_group=start,
        prior_gpu_seconds=prior_gpu,
        prior_host_instances=prior_hosts,
        progress_callback=write_progress,
    )
    if discovery["status"] in {"peer_confirmed", "lane_exhausted"}:
        if discovery["status"] == "lane_exhausted":
            exhausted = 0
            for lane_role in ROLES:
                path = progress_path(lane_role)
                if path.exists() and json.loads(path.read_bytes()).get("status") == "lane_exhausted":
                    exhausted += 1
            if exhausted == len(ROLES) and not RESULT.exists():
                raise RuntimeError("A393 all disjoint lanes exhausted without a factual model")
        return discovery
    candidate = int(discovery["candidate"])
    confirmation = A389.A385.confirm(challenge, candidate)
    if confirmation["all_blocks_match"] is not True:
        raise RuntimeError("A393 dual independent confirmation failed")
    schedule = json.loads(A392_RESULT.read_bytes())
    ranks = rank_panel(int(discovery["prefix12"]), role, schedule)
    if ranks["owner_lane_depth_one_based"] != discovery[
        "executed_lane_prefix_groups"
    ]:
        raise RuntimeError("A393 discovery depth differs from A392 owner lane")
    aggregate = progress_snapshot(protocol)
    unique_groups = int(aggregate["total_unique_prefix_groups_evaluated"])
    if not 1 <= unique_groups <= CELLS:
        raise RuntimeError("A393 aggregate unique group count differs")
    strict_subset = unique_groups < CELLS
    aggregate["strict_subset_of_complete_domain"] = strict_subset
    aggregate["domain_reduction_factor"] = CELLS / unique_groups
    aggregate["search_gain_bits"] = math.log2(CELLS / unique_groups)
    evidence_stage = (
        "FULLROUND_R20_DISJOINT_PARALLEL_W50_STRICT_SUBSET_RECOVERY_CONFIRMED"
        if strict_subset
        else "FULLROUND_R20_DISJOINT_PARALLEL_W50_COMPLETE_DOMAIN_RECOVERY_CONFIRMED"
    )
    payload: dict[str, Any] = {
        "schema": "chacha20-round20-w50-disjoint-parallel-recovery-a393-result-v1",
        "attempt_id": ATTEMPT_ID,
        "evidence_stage": evidence_stage,
        "protocol_sha256": expected_protocol_sha256,
        "design_sha256": DESIGN_SHA256,
        "implementation_sha256": protocol["implementation_sha256"],
        "A384_qualification_sha256": protocol["A384_qualification_sha256"],
        "A385_protocol_sha256": protocol["A385_protocol_sha256"],
        "A392_result_sha256": protocol["A392_result_sha256"],
        "A392_schedule_commitment_sha256": protocol[
            "A392_schedule_commitment_sha256"
        ],
        "public_challenge_sha256": protocol["public_challenge_sha256"],
        "winning_lane_role": role,
        "winning_lane_slug": ROLE_TO_SLUG[role],
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
        key: item for key, item in discovery.items() if not key.startswith("volatile_")
    }
    payload["execution_sha256"] = canonical_sha256(
        {
            "winning_lane_role": role,
            "winning_lane_order_uint16be_sha256": lane_hash,
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
            "# A393 — disjoint parallel full-round ChaCha20 W50 recovery\n\n"
            f"Evidence stage: **{evidence_stage}**\n\n"
            f"- Winning lane: **{role}**\n"
            f"- Owner-lane depth: **{ranks['owner_lane_depth_one_based']} / {EXPECTED_LANE_SIZES[role]}**\n"
            f"- Exact unique prefix groups evaluated: **{unique_groups} / {CELLS}**\n"
            f"- Complete candidate evaluations: **{aggregate['total_unique_assignments_evaluated']:,} / {DOMAIN_SIZE:,}**\n"
            f"- Recovered W50 assignment: **0x{candidate:013x}**\n"
            "- Standard ChaCha20: **20 rounds plus feed-forward**\n"
            "- Every prefix: **128 complete 2^31 slabs before outcome evaluation**\n"
            "- Duplicate A393 prefix groups: **zero by construction**\n"
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
        "lane_progress": {},
    }
    if IMPLEMENTATION.exists():
        payload["implementation_sha256"] = file_sha256(IMPLEMENTATION)
    if PROTOCOL.exists():
        payload["protocol_sha256"] = file_sha256(PROTOCOL)
    for role in ROLES:
        path = progress_path(role)
        if path.exists():
            payload["lane_progress"][role] = json.loads(path.read_bytes())
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
    action.add_argument("--recover-lane", choices=tuple(SLUG_TO_ROLE))
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
    elif args.recover_lane:
        if not args.expected_protocol_sha256:
            parser.error("--recover-lane requires --expected-protocol-sha256")
        payload = recover_lane(
            role=SLUG_TO_ROLE[args.recover_lane],
            expected_protocol_sha256=args.expected_protocol_sha256,
        )
    else:
        payload = analyze()
    print(json.dumps(payload, indent=2, sort_keys=True), flush=True)


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""A389: execute A388's public-output factor-three order over fresh ChaCha20 W50."""

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

DESIGN = CONFIGS / "chacha20_round20_w50_public_output_factor3_recovery_a389_design_v1.json"
IMPLEMENTATION = CONFIGS / "chacha20_round20_w50_public_output_factor3_recovery_a389_implementation_v1.json"
PROTOCOL = CONFIGS / "chacha20_round20_w50_public_output_factor3_recovery_a389_v1.json"
PROGRESS = RESULTS / "chacha20_round20_w50_public_output_factor3_recovery_a389_progress_v1.json"
RESULT = RESULTS / "chacha20_round20_w50_public_output_factor3_recovery_a389_v1.json"
CAUSAL = RESULT.with_suffix(".causal")
REPORT = RESULT.with_suffix(".md")
TEST = ROOT / "tests/test_chacha20_round20_w50_public_output_factor3_recovery_a389.py"
REPRO = ROOT / "scripts/reproduce_chacha20_round20_w50_public_output_factor3_recovery_a389.sh"

A384_RUNNER = RESEARCH / "experiments/chacha20_round20_w50_onehundredtwentyeight_slab_grouped_engine_a384.py"
A384_PROTOCOL = CONFIGS / "chacha20_round20_w50_onehundredtwentyeight_slab_grouped_engine_a384_v1.json"
A384_QUALIFICATION = RESULTS / "chacha20_round20_w50_onehundredtwentyeight_slab_grouped_engine_a384_qualification_v1.json"
A385_RUNNER = RESEARCH / "experiments/chacha20_round20_fresh_w50_pretarget_transfer_a385.py"
A385_IMPLEMENTATION = CONFIGS / "chacha20_round20_fresh_w50_pretarget_transfer_a385_implementation_v1.json"
A385_ORDER = RESULTS / "chacha20_round20_fresh_w50_pretarget_transfer_a385_order_v1.json"
A385_PROTOCOL = CONFIGS / "chacha20_round20_fresh_w50_pretarget_transfer_a385_v1.json"
A388_RUNNER = RESEARCH / "experiments/chacha20_round20_w50_public_output_direct12_factor3_a388.py"
A388_DESIGN = CONFIGS / "chacha20_round20_w50_public_output_direct12_factor3_a388_design_v1.json"
A388_IMPLEMENTATION = CONFIGS / "chacha20_round20_w50_public_output_direct12_factor3_a388_implementation_v1.json"
A388_PREFLIGHT = RESULTS / "chacha20_round20_w50_public_output_direct12_factor3_a388_preflight_v1.json"
A388_ORDER = RESULTS / "chacha20_round20_w50_public_output_direct12_factor3_a388_order_v1.json"
A388_CAUSAL = A388_ORDER.with_suffix(".causal")
A386_ORDER = RESULTS / "chacha20_round20_w49_calibrated_ticketed_hierarchical_factor3_a386_order_v1.json"
A386_CAUSAL = A386_ORDER.with_suffix(".causal")

ATTEMPT_ID = "A389"
DESIGN_SHA256 = "72b3ad885623737147cafd716d485ac64806ecba5c44ec50dc20b3847cdf3812"
A384_RUNNER_SHA256 = "60352d5f0d09fad8272e87f5a202d6f62274911d7bdd154738a47bac04b6264f"
A384_PROTOCOL_SHA256 = "1bd9a1e572906ff98aab30b52b547f48f4b1d61785ccc0ca8082ae4c6bd13fcb"
A384_QUALIFICATION_SHA256 = "0e31d4d7b0e0bb0e45cd815d975e2898c60eeea16e04498d720f0a58dd41dc30"
A385_RUNNER_SHA256 = "b6827f779a8a7997bbee6c04a6a28f9f3c5ec5718ac942b0171c8b4174a928f3"
A385_IMPLEMENTATION_SHA256 = "05b6b0403a852abf686bdb2b45f13f5a1997c9970ce2e328cc779aaeee818263"
A385_ORDER_SHA256 = "3d694c17590c063bc14edc925f75adbc2f05e4a941195956a89d18287805af38"
A385_PROTOCOL_SHA256 = "801831f2daabe41476c9bf1ec676907f11c1b5465a193ba61d8d1877eb3b0b4b"
A385_ORDER_UINT16BE_SHA256 = "bcd1f2920aaa6dce6b8e91fcf6cf2ef48748ecad4cb00af2ac5af175641125d2"
A386_ORDER_SHA256 = "eda2ec6b995d2ad7ecb8198ff33616c9129fceb04b28a51b0f2123303ba6a5c4"
A386_CAUSAL_SHA256 = "b08f42a5202f79d754783b34dae16f76f41608282b18be4bfb36cb67be4397a3"
A386_ORDER_UINT16BE_SHA256 = "7420e2bf5467390ba236eaea8357e8cdf4c14f1537c38a4c98e6d88dca2c4061"
A388_DESIGN_SHA256 = "c59c68725caf161fd653a7728472da3f6ac7857c30f26c1a6625827822cb4782"
A388_IMPLEMENTATION_SHA256 = "5a3eb08ad5087bd7ebd744548eec7f65f26a70af1679340aede196ea50e4a8b6"
A388_PREFLIGHT_SHA256 = "6919b9071b5c9de85f050a7921d4a82fa0e55db6e02ca531590afdfdc57cc115"
A388_RUNNER_SHA256 = "36c933ae5003f92f2b96efb2e30d97c30bf8301bfcaa790333a6712f3041b5a9"
A388_ORDER_SHA256 = "3c56ce8521b1ced20e1e3a90999810c2e563c4de941701c86274f0828b5d01b8"
A388_CAUSAL_SHA256 = "095e4a05b86df98b27899c3055d4ff4c5ea2eab5ffa5961cfb36747320090e3a"
A388_ORDER_UINT16BE_SHA256 = "f9869fe30cedc2fe3280443f388b97143b9b649a88195f8397838862acbce8bf"

WIDTH = 50
PREFIX_BITS = 12
WORD0_SUFFIX_BITS = 20
CELLS = 1 << PREFIX_BITS
GROUP_SIZE = 1 << (WIDTH - PREFIX_BITS)
DOMAIN_SIZE = 1 << WIDTH
MASK32 = 0xFFFFFFFF
HOST_REFRESH_GROUPS = 8
SELECTED_OPERATOR = "A388_public_output_Direct12_three_view_factor3_W50_wavefront"
SOURCE_ROLES = (
    "A385_pretarget_six_view",
    "A388_W50_public_output_direct12",
    "A386_calibrated_target_blind_transfer",
)
DOTCAUSAL_SRC = Path("/Users/bhkmie/Documents/Forschung/O1/vendor/fabel/dotcausal_package/src")


def load_module(path: Path, name: str) -> Any:
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot import A389 dependency {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


A385 = load_module(A385_RUNNER, "a389_a385")
A384 = A385.A384
file_sha256 = A385.file_sha256
canonical_sha256 = A385.canonical_sha256
atomic_json = A385.atomic_json
relative = A385.relative
path_from_ref = A385.path_from_ref
anchor = A385.anchor


def atomic_bytes(path: Path, payload: bytes) -> None:
    temporary = path.with_name(f".{path.name}.tmp")
    temporary.write_bytes(payload)
    os.replace(temporary, path)


def exact_order(values: Sequence[int], label: str) -> list[int]:
    order = [int(value) for value in values]
    if len(order) != CELLS or set(order) != set(range(CELLS)):
        raise ValueError(f"A389 {label} is not an exact 4,096-cell order")
    return order


def order_sha256(order: Sequence[int]) -> str:
    return A385.order_sha256(exact_order(order, "hash"))


def rank_vector(order: Sequence[int]) -> list[int]:
    ranks = [0] * CELLS
    for rank, cell in enumerate(exact_order(order, "rank vector"), 1):
        ranks[cell] = rank
    return ranks


def load_design() -> dict[str, Any]:
    if file_sha256(DESIGN) != DESIGN_SHA256:
        raise RuntimeError("A389 design hash differs")
    value = json.loads(DESIGN.read_bytes())
    execution = value.get("execution_contract", {})
    boundary = value.get("information_boundary", {})
    order = value.get("order_contract", {})
    if (
        value.get("schema") != "chacha20-round20-w50-public-output-factor3-recovery-a389-design-v1"
        or value.get("attempt_id") != ATTEMPT_ID
        or value.get("design_state")
        != "frozen_while_A388_complete_measurement_runs_after_A388_implementation_and_preflight_before_A388_order_or_any_A389_candidate_prefix_or_result"
        or execution.get("unknown_key_bits") != WIDTH
        or execution.get("candidates_per_prefix_group") != GROUP_SIZE
        or execution.get("complete_domain_assignments") != DOMAIN_SIZE
        or execution.get("slabs_per_prefix_group") != 128
        or order.get("source_count") != 3
        or order.get("pointwise_bound")
        != "R_A388(c) <= 3*min(R_A385(c),R_Direct12(c),R_A386(c)) for all 4096 cells"
        or order.get("parameter_refits_at_W50") != 0
        or order.get("target_labels_used") != 0
        or boundary.get("A385_assignment_absent_from_protocol") is not True
        or boundary.get("A388_measurement_running_at_design_freeze") is not True
        or boundary.get("A388_order_available_at_design_freeze") is not False
        or boundary.get("A387_result_or_true_prefix_available_at_design_freeze") is not False
        or boundary.get("A387_progress_or_filter_outcomes_consumed") is not False
        or boundary.get("A389_candidate_or_prefix_available_at_design_freeze") is not False
    ):
        raise RuntimeError("A389 frozen design semantics differ")
    for key, source_path in value["source_anchors"].items():
        if key.endswith("_path"):
            expected = value["source_anchors"][key.removesuffix("_path") + "_sha256"]
            anchor(ROOT / source_path, expected)
    return value


def assert_pre_execution() -> None:
    if PROGRESS.exists() or RESULT.exists() or CAUSAL.exists() or REPORT.exists():
        raise RuntimeError("A389 frozen artifacts must precede every W50 candidate and result")


def load_sources() -> tuple[dict[str, Any], dict[str, Any], dict[str, Any], dict[str, list[int]]]:
    protocol = A385.load_protocol(A385_PROTOCOL_SHA256)
    qualification = A385.load_a384_qualification(A384_QUALIFICATION_SHA256)
    anchor(A388_ORDER, A388_ORDER_SHA256)
    anchor(A388_CAUSAL, A388_CAUSAL_SHA256)
    order = json.loads(A388_ORDER.read_bytes())
    selected = exact_order(order.get("selected_order", []), "A388 selected order")
    raw_sources = order.get("source_orders", {})
    if set(raw_sources) != set(SOURCE_ROLES):
        raise RuntimeError("A389 A388 source-role set differs")
    source_orders = {
        role: exact_order(raw_sources[role], role) for role in SOURCE_ROLES
    }
    if (
        protocol.get("public_challenge", {}).get("unknown_key_bits") != WIDTH
        or protocol.get("information_boundary", {}).get("A385_assignment_absent_from_protocol")
        is not True
        or order.get("schema")
        != "chacha20-round20-w50-public-output-direct12-factor3-a388-order-v1"
        or order.get("attempt_id") != "A388"
        or order.get("A385_public_challenge_sha256")
        != protocol.get("public_challenge_sha256")
        or order.get("target_labels_used") != 0
        or order.get("reader_refits") != 0
        or order.get("candidate_assignments_executed") != 0
        or order.get("A387_progress_or_filter_outcomes_consumed") is not False
        or order.get("pointwise_factor3_proof", {}).get("violations") != 0
        or order.get("pointwise_factor3_proof", {}).get("source_count") != 3
        or order_sha256(selected) != A388_ORDER_UINT16BE_SHA256
        or order_sha256(source_orders[SOURCE_ROLES[0]]) != A385_ORDER_UINT16BE_SHA256
        or order_sha256(source_orders[SOURCE_ROLES[2]]) != A386_ORDER_UINT16BE_SHA256
        or qualification.get("matched_control_empty") is not True
        or qualification.get("complete_group_gate", {}).get("logical_candidates")
        != GROUP_SIZE
    ):
        raise RuntimeError("A389 source semantics differ")
    return protocol, order, qualification, source_orders


def freeze_implementation() -> dict[str, Any]:
    if any(path.exists() for path in (IMPLEMENTATION, PROTOCOL, PROGRESS, RESULT, CAUSAL, REPORT)):
        raise FileExistsError("A389 implementation or execution artifact already exists")
    assert_pre_execution()
    load_design()
    load_sources()
    if not TEST.exists() or not REPRO.exists():
        raise FileNotFoundError("A389 test and reproducer must precede implementation freeze")
    payload: dict[str, Any] = {
        "schema": "chacha20-round20-w50-public-output-factor3-recovery-a389-implementation-v1",
        "attempt_id": ATTEMPT_ID,
        "commitment_state": "frozen_after_A388_complete_factor3_order_before_A389_candidate_prefix_or_result",
        "design_sha256": DESIGN_SHA256,
        "selected_operator": SELECTED_OPERATOR,
        "A389_candidate_or_prefix_available_at_implementation_freeze": False,
        "anchors": {
            "design": anchor(DESIGN, DESIGN_SHA256),
            "A384_runner": anchor(A384_RUNNER, A384_RUNNER_SHA256),
            "A384_protocol": anchor(A384_PROTOCOL, A384_PROTOCOL_SHA256),
            "A384_qualification": anchor(A384_QUALIFICATION, A384_QUALIFICATION_SHA256),
            "A385_runner": anchor(A385_RUNNER, A385_RUNNER_SHA256),
            "A385_implementation": anchor(A385_IMPLEMENTATION, A385_IMPLEMENTATION_SHA256),
            "A385_order": anchor(A385_ORDER, A385_ORDER_SHA256),
            "A385_protocol": anchor(A385_PROTOCOL, A385_PROTOCOL_SHA256),
            "A388_design": anchor(A388_DESIGN, A388_DESIGN_SHA256),
            "A388_implementation": anchor(
                A388_IMPLEMENTATION, A388_IMPLEMENTATION_SHA256
            ),
            "A388_preflight": anchor(A388_PREFLIGHT, A388_PREFLIGHT_SHA256),
            "A388_order": anchor(A388_ORDER, A388_ORDER_SHA256),
            "A388_causal": anchor(A388_CAUSAL, A388_CAUSAL_SHA256),
            "A388_runner": anchor(A388_RUNNER, A388_RUNNER_SHA256),
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
        raise RuntimeError("A389 implementation hash differs")
    value = json.loads(IMPLEMENTATION.read_bytes())
    if (
        value.get("schema")
        != "chacha20-round20-w50-public-output-factor3-recovery-a389-implementation-v1"
        or value.get("attempt_id") != ATTEMPT_ID
        or value.get("design_sha256") != DESIGN_SHA256
        or value.get("selected_operator") != SELECTED_OPERATOR
        or value.get("A389_candidate_or_prefix_available_at_implementation_freeze")
        is not False
    ):
        raise RuntimeError("A389 implementation semantics differ")
    for row in value["anchors"].values():
        anchor(path_from_ref(row["path"]), row["sha256"])
    unsigned = {key: item for key, item in value.items() if key != "implementation_commitment_sha256"}
    if value.get("implementation_commitment_sha256") != canonical_sha256(unsigned):
        raise RuntimeError("A389 implementation commitment differs")
    return value


def freeze_protocol(*, expected_implementation_sha256: str) -> dict[str, Any]:
    if any(path.exists() for path in (PROTOCOL, PROGRESS, RESULT, CAUSAL, REPORT)):
        raise FileExistsError("A389 protocol or execution artifact already exists")
    assert_pre_execution()
    implementation = load_implementation(expected_implementation_sha256)
    source, order, qualification, source_orders = load_sources()
    selected = exact_order(order["selected_order"], "protocol selected")
    payload: dict[str, Any] = {
        "schema": "chacha20-round20-w50-public-output-factor3-recovery-a389-protocol-v1",
        "attempt_id": ATTEMPT_ID,
        "protocol_state": "A388_public_output_factor3_order_bound_before_any_A389_candidate_prefix_or_result",
        "design_sha256": DESIGN_SHA256,
        "implementation_sha256": expected_implementation_sha256,
        "implementation_commitment_sha256": implementation[
            "implementation_commitment_sha256"
        ],
        "A384_qualification_sha256": A384_QUALIFICATION_SHA256,
        "A384_semantic_qualification_sha256": qualification["qualification_sha256"],
        "A385_protocol_sha256": A385_PROTOCOL_SHA256,
        "A388_order_sha256": A388_ORDER_SHA256,
        "A388_order_commitment_sha256": order["order_commitment_sha256"],
        "public_challenge_sha256": source["public_challenge_sha256"],
        "public_challenge": source["public_challenge"],
        "selected_operator": SELECTED_OPERATOR,
        "selected_order_uint16be_sha256": order_sha256(selected),
        "selected_order": selected,
        "source_orders_sha256": canonical_sha256(source_orders),
        "source_orders": source_orders,
        "pointwise_factor3_proof": order["pointwise_factor3_proof"],
        "execution_contract": load_design()["execution_contract"],
        "information_boundary": {
            "A389_candidate_or_prefix_available_at_protocol_freeze": False,
            "A388_order_frozen_before_A389_candidate_or_prefix": True,
            "A385_assignment_absent_from_protocol": True,
            "target_labels_used_for_order_construction": 0,
            "reader_refits": 0,
            "candidate_assignments_executed_for_order": 0,
            "A387_progress_or_filter_outcomes_consumed_for_order": False,
            "parameter_refits_at_W50": 0,
        },
        "anchors": {
            "design": anchor(DESIGN, DESIGN_SHA256),
            "implementation": anchor(IMPLEMENTATION, expected_implementation_sha256),
            "A384_protocol": anchor(A384_PROTOCOL, A384_PROTOCOL_SHA256),
            "A384_qualification": anchor(A384_QUALIFICATION, A384_QUALIFICATION_SHA256),
            "A385_protocol": anchor(A385_PROTOCOL, A385_PROTOCOL_SHA256),
            "A388_order": anchor(A388_ORDER, A388_ORDER_SHA256),
            "A388_causal": anchor(A388_CAUSAL, A388_CAUSAL_SHA256),
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
            "A384_qualification_sha256": A384_QUALIFICATION_SHA256,
            "A385_protocol_sha256": A385_PROTOCOL_SHA256,
            "selected_order_uint16be_sha256": payload[
                "selected_order_uint16be_sha256"
            ],
            "source_orders_sha256": payload["source_orders_sha256"],
            "public_challenge_sha256": payload["public_challenge_sha256"],
            "information_boundary": payload["information_boundary"],
        }
    )
    atomic_json(PROTOCOL, payload)
    assert_pre_execution()
    return payload


def load_protocol(expected_sha256: str) -> dict[str, Any]:
    if file_sha256(PROTOCOL) != expected_sha256:
        raise RuntimeError("A389 protocol hash differs")
    value = json.loads(PROTOCOL.read_bytes())
    selected = exact_order(value.get("selected_order", []), "stored selected")
    raw_sources = value.get("source_orders", {})
    if set(raw_sources) != set(SOURCE_ROLES):
        raise RuntimeError("A389 stored source-role set differs")
    source_orders = {
        role: exact_order(raw_sources[role], role) for role in SOURCE_ROLES
    }
    if (
        value.get("schema")
        != "chacha20-round20-w50-public-output-factor3-recovery-a389-protocol-v1"
        or value.get("attempt_id") != ATTEMPT_ID
        or value.get("selected_operator") != SELECTED_OPERATOR
        or value.get("selected_order_uint16be_sha256") != order_sha256(selected)
        or value.get("selected_order_uint16be_sha256")
        != A388_ORDER_UINT16BE_SHA256
        or value.get("source_orders_sha256") != canonical_sha256(source_orders)
        or value.get("pointwise_factor3_proof", {}).get("violations") != 0
        or value.get("information_boundary", {}).get(
            "A389_candidate_or_prefix_available_at_protocol_freeze"
        )
        is not False
        or value.get("information_boundary", {}).get(
            "target_labels_used_for_order_construction"
        )
        != 0
        or canonical_sha256(value.get("public_challenge"))
        != value.get("public_challenge_sha256")
    ):
        raise RuntimeError("A389 protocol semantics differ")
    for row in value["anchors"].values():
        anchor(path_from_ref(row["path"]), row["sha256"])
    load_implementation(value["implementation_sha256"])
    A385.validate_challenge(value["public_challenge"])
    return value


def load_resume(
    *, protocol_sha256: str, order_sha: str, qualification_sha256: str
) -> tuple[int, float, int, dict[str, Any] | None]:
    if not PROGRESS.exists():
        return 0, 0.0, 0, None
    value = json.loads(PROGRESS.read_bytes())
    if (
        value.get("schema")
        != "chacha20-round20-w50-public-output-factor3-recovery-a389-progress-v1"
        or value.get("attempt_id") != ATTEMPT_ID
        or value.get("protocol_sha256") != protocol_sha256
        or value.get("selected_order_uint16be_sha256") != order_sha
        or value.get("A384_qualification_sha256") != qualification_sha256
        or value.get("matched_control_candidates") != 0
    ):
        raise RuntimeError("A389 progress fingerprint differs")
    if value.get("status") == "candidate_found":
        excluded = {
            "schema",
            "attempt_id",
            "protocol_sha256",
            "selected_operator",
            "selected_order_uint16be_sha256",
            "A384_qualification_sha256",
            "status",
        }
        return 0, 0.0, 0, {
            key: item for key, item in value.items() if key not in excluded
        }
    completed = int(value.get("executed_prefix_groups", -1))
    if not 0 <= completed < CELLS or value.get("factual_filter_candidates") != 0:
        raise RuntimeError("A389 resumable progress state differs")
    return (
        completed,
        float(value.get("gpu_seconds", 0.0)),
        int(value.get("host_instances", 0)),
        None,
    )


def ordered_discovery(
    *,
    host_factory: Callable[[], Any],
    challenge: Mapping[str, Any],
    order: Sequence[int],
    start_group: int = 0,
    prior_gpu_seconds: float = 0.0,
    prior_host_instances: int = 0,
    progress_callback: Callable[[Mapping[str, Any]], None] | None = None,
) -> dict[str, Any]:
    """Execute exact complete W50 groups in the frozen prefix order."""
    values = exact_order(order, "recovery order")
    if not 0 <= start_group < CELLS:
        raise ValueError("A389 resume group lies outside the prefix cover")
    target = np.asarray(challenge["target_words"][0], dtype=np.uint32)
    control = np.asarray(challenge["control_target_words"], dtype=np.uint32)
    host: Any | None = None
    host_instances = prior_host_instances
    gpu_seconds = prior_gpu_seconds
    started = time.perf_counter()
    try:
        for group_index in range(start_group, CELLS):
            prefix = values[group_index]
            if group_index == start_group or group_index % HOST_REFRESH_GROUPS == 0:
                if host is not None:
                    host.close()
                host = host_factory()
                host_instances += 1
            observed = A384.filter_complete_prefix(
                host=host,
                challenge=challenge,
                prefix=prefix,
                target=target,
                control=control,
            )
            factual = [int(value) for value in observed["factual_candidates"]]
            controls = [int(value) for value in observed["control_candidates"]]
            gpu_seconds += float(observed["gpu_seconds"])
            groups = group_index + 1
            if controls:
                raise RuntimeError("A389 matched control produced a candidate")
            if not factual:
                if progress_callback is not None:
                    progress_callback(
                        {
                            "status": "running",
                            "executed_prefix_groups": groups,
                            "complete_prefix_groups": CELLS,
                            "executed_assignments": groups * GROUP_SIZE,
                            "complete_domain_assignments": DOMAIN_SIZE,
                            "matched_control_candidates": 0,
                            "factual_filter_candidates": 0,
                            "gpu_seconds": gpu_seconds,
                            "host_instances": host_instances,
                            "last_completed_prefix12": prefix,
                        }
                    )
                continue
            if len(factual) != 1:
                raise RuntimeError("A389 complete W50 group produced multiple filters")
            candidate = factual[0]
            if ((candidate >> WORD0_SUFFIX_BITS) & (CELLS - 1)) != prefix:
                raise RuntimeError("A389 candidate prefix differs")
            decoded = A384.decode_assignment(candidate)
            found = {
                "candidate": candidate,
                "candidate_hex": f"{candidate:013x}",
                "key_word0": decoded["word0"],
                "key_word1_low18": decoded["word1_low18"],
                "prefix12": prefix,
                "prefix12_hex": f"{prefix:03x}",
                "executed_prefix_groups": groups,
                "executed_group_dispatches": groups * 128,
                "executed_assignments": groups * GROUP_SIZE,
                "complete_domain_assignments": DOMAIN_SIZE,
                "complete_W50_group_execution_before_stop": True,
                "early_stop_inside_group": False,
                "strict_subset_of_complete_domain": groups < CELLS,
                "search_gain_bits": math.log2(CELLS / groups),
                "factual_filter_candidates": factual,
                "matched_control_candidates": 0,
                "control_filter_candidates": [],
                "host_refresh_interval_prefix_groups": HOST_REFRESH_GROUPS,
                "host_instances": host_instances,
                "gpu_seconds": gpu_seconds,
                "volatile_wall_seconds": time.perf_counter() - started,
            }
            if progress_callback is not None:
                progress_callback({"status": "candidate_found", **found})
            return found
    finally:
        if host is not None:
            host.close()
    raise RuntimeError("A389 exact frozen order exhausted without a factual filter")


def rank_panel(prefix: int, protocol: Mapping[str, Any]) -> dict[str, Any]:
    selected_rank = rank_vector(protocol["selected_order"])[prefix]
    source_ranks = {
        role: rank_vector(protocol["source_orders"][role])[prefix]
        for role in SOURCE_ROLES
    }
    return {
        "prefix12": prefix,
        "prefix12_hex": f"{prefix:03x}",
        "A388_executed_factor3_rank_one_based": selected_rank,
        "source_ranks_one_based": source_ranks,
        "selected_gain_bits_vs_complete_domain": math.log2(CELLS / selected_rank),
        "selected_domain_reduction_factor": CELLS / selected_rank,
        "best_source_rank_one_based": min(source_ranks.values()),
        "selected_rank_ratio_to_best_source": selected_rank
        / min(source_ranks.values()),
        "ranks_computed_only_after_independent_confirmation": True,
    }


def build_causal(payload: Mapping[str, Any]) -> dict[str, Any]:
    sys.path.insert(0, str(DOTCAUSAL_SRC))
    from dotcausal.io import CausalReader, CausalWriter

    terminal = "A389:confirmed_public_output_factor3_W50_recovery"
    writer = CausalWriter(api_id="a389w50")
    writer._rules = []
    writer.add_rule(
        name="public_output_factor3_order_and_W50_engine_to_model",
        description="The A388 order built without labels, refits, candidate assignments or A387 progress executes complete one-hundred-twenty-eight-slab groups until a sole factual model appears.",
        pattern=["A388_frozen_public_output_factor3_W50_order", "A384_exact_W50_group_engine"],
        conclusion="A389_sole_factual_W50_model",
        confidence_modifier=1.0,
    )
    writer.add_rule(
        name="model_to_confirmed_recovery",
        description="The factual model is independently confirmed across all eight standard ChaCha20 blocks.",
        pattern=["A389_sole_factual_W50_model"],
        conclusion="A389_confirmed_public_output_factor3_W50_recovery",
        confidence_modifier=1.0,
    )
    writer.add_triplet(
        trigger="A388:public_output_Direct12_factor3_W50_order",
        mechanism="qualified_ordered_complete_onehundredtwentyeight_slab_search",
        outcome="A389:sole_factual_W50_model",
        confidence=1.0,
        source=payload["execution_sha256"],
        quantification=json.dumps(payload["discovery"], sort_keys=True),
        evidence=json.dumps(payload["rank_analysis"], sort_keys=True),
        domain="fresh full-round ChaCha20 W50 public-output factor-three recovery",
        quality_score=1.0,
    )
    writer.add_triplet(
        trigger="A389:sole_factual_W50_model",
        mechanism="dual_independent_eight_block_confirmation",
        outcome=terminal,
        confidence=1.0,
        source=payload["measurement_sha256"],
        quantification=json.dumps(payload["confirmation"], sort_keys=True),
        evidence=payload["evidence_stage"],
        domain="confirmed full-round ChaCha20 W50 recovery",
        quality_score=1.0,
    )
    writer.add_triplet(
        trigger="A388:public_output_Direct12_factor3_W50_order",
        mechanism="materialized_W50_search_and_confirmation_closure",
        outcome=terminal,
        confidence=1.0,
        source="materialized:A389_public_output_factor3_W50_recovery_chain",
        quantification="exact retained closure",
        evidence=payload["evidence_stage"],
        domain="AI-native retained inference",
        quality_score=1.0,
        is_inferred=True,
    )
    writer.add_cluster(
        name="A389 public-output factor-three W50 recovery",
        entities=[
            "A388:public_output_Direct12_factor3_W50_order",
            "A389:sole_factual_W50_model",
            terminal,
        ],
    )
    writer.add_gap(
        subject=terminal,
        predicate="next_required_object",
        expected_object_type="W51_engine_or_second_fresh_W50_operator_replication",
        confidence=1.0,
        suggested_queries=[
            "Lift the exact engine to W51 or execute the same operator family on a second fresh W50 challenge."
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
        reader.api_id != "a389w50"
        or len(explicit) != 2
        or len(all_rows) != 3
        or len(inferred) != 1
        or len(reader._rules) != 2
        or len(reader._clusters) != 1
        or len(reader._gaps) != 1
    ):
        raise RuntimeError("A389 authentic Causal reopen gate failed")
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


def recover(*, expected_protocol_sha256: str) -> dict[str, Any]:
    if any(path.exists() for path in (RESULT, CAUSAL, REPORT)):
        raise FileExistsError("A389 result artifact already exists")
    protocol = load_protocol(expected_protocol_sha256)
    qualification = A385.load_a384_qualification(protocol["A384_qualification_sha256"])
    engine_protocol = A384.load_protocol(A384_PROTOCOL_SHA256)
    executable_row = engine_protocol["anchors"]["grouped_executable"]
    executable = path_from_ref(executable_row["path"])
    anchor(executable, executable_row["sha256"])
    challenge = protocol["public_challenge"]
    placeholder = np.asarray([0, 0], dtype=np.uint32)

    def host_factory() -> Any:
        return A384.A378.A371.A346.A324.A311.A307.A304.GroupedMetalHost(
            executable,
            A384.initial_for_slab(challenge, 0),
            placeholder,
            placeholder,
        )

    def write_progress(row: Mapping[str, Any]) -> None:
        atomic_json(
            PROGRESS,
            {
                "schema": "chacha20-round20-w50-public-output-factor3-recovery-a389-progress-v1",
                "attempt_id": ATTEMPT_ID,
                "protocol_sha256": expected_protocol_sha256,
                "selected_operator": SELECTED_OPERATOR,
                "selected_order_uint16be_sha256": protocol[
                    "selected_order_uint16be_sha256"
                ],
                "A384_qualification_sha256": protocol[
                    "A384_qualification_sha256"
                ],
                **dict(row),
            },
        )

    start, prior_gpu, prior_hosts, completed_discovery = load_resume(
        protocol_sha256=expected_protocol_sha256,
        order_sha=protocol["selected_order_uint16be_sha256"],
        qualification_sha256=protocol["A384_qualification_sha256"],
    )
    discovery = completed_discovery or ordered_discovery(
        host_factory=host_factory,
        challenge=challenge,
        order=protocol["selected_order"],
        start_group=start,
        prior_gpu_seconds=prior_gpu,
        prior_host_instances=prior_hosts,
        progress_callback=write_progress,
    )
    if discovery["matched_control_candidates"] != 0:
        raise RuntimeError("A389 matched control produced a candidate")
    candidate = int(discovery["candidate"])
    confirmation = A385.confirm(challenge, candidate)
    if confirmation["all_blocks_match"] is not True:
        raise RuntimeError("A389 dual independent confirmation failed")
    ranks = rank_panel(int(discovery["prefix12"]), protocol)
    if ranks["A388_executed_factor3_rank_one_based"] != discovery[
        "executed_prefix_groups"
    ]:
        raise RuntimeError("A389 discovery rank differs from selected order")
    strict_subset = discovery["executed_prefix_groups"] < CELLS
    evidence_stage = (
        "FULLROUND_R20_PUBLIC_OUTPUT_FACTOR3_W50_STRICT_SUBSET_RECOVERY_CONFIRMED"
        if strict_subset
        else "FULLROUND_R20_PUBLIC_OUTPUT_FACTOR3_W50_COMPLETE_DOMAIN_RECOVERY_CONFIRMED"
    )
    payload: dict[str, Any] = {
        "schema": "chacha20-round20-w50-public-output-factor3-recovery-a389-result-v1",
        "attempt_id": ATTEMPT_ID,
        "evidence_stage": evidence_stage,
        "protocol_sha256": expected_protocol_sha256,
        "design_sha256": DESIGN_SHA256,
        "implementation_sha256": protocol["implementation_sha256"],
        "A384_qualification_sha256": protocol["A384_qualification_sha256"],
        "A385_protocol_sha256": protocol["A385_protocol_sha256"],
        "A388_order_sha256": protocol["A388_order_sha256"],
        "public_challenge_sha256": protocol["public_challenge_sha256"],
        "selected_operator": SELECTED_OPERATOR,
        "selected_order_uint16be_sha256": protocol[
            "selected_order_uint16be_sha256"
        ],
        "pointwise_factor3_proof": protocol["pointwise_factor3_proof"],
        "qualification_gate": {
            "evidence_stage": qualification["evidence_stage"],
            "qualification_sha256": qualification["qualification_sha256"],
            "complete_W50_group_candidates": qualification["complete_group_gate"][
                "logical_candidates"
            ],
            "synthetic_filter_exact": qualification["synthetic_filter_exact"],
            "production_target_used": False,
        },
        "discovery": discovery,
        "rank_analysis": ranks,
        "confirmation": confirmation,
        "strict_subset_of_complete_domain": strict_subset,
        "information_boundary": protocol["information_boundary"],
        "anchors": protocol["anchors"],
    }
    stable_discovery = {
        key: item for key, item in discovery.items() if not key.startswith("volatile_")
    }
    payload["execution_sha256"] = canonical_sha256(
        {
            "selected_operator": SELECTED_OPERATOR,
            "selected_order_uint16be_sha256": protocol[
                "selected_order_uint16be_sha256"
            ],
            "discovery": stable_discovery,
            "A384_qualification_sha256": protocol["A384_qualification_sha256"],
        }
    )
    payload["measurement_sha256"] = canonical_sha256(
        {
            "discovery": stable_discovery,
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
            "# A389 — public-output factor-three full-round ChaCha20 W50 recovery\n\n"
            f"Evidence stage: **{evidence_stage}**\n\n"
            f"- W50 execution rank: **{ranks['A388_executed_factor3_rank_one_based']} / {CELLS}**\n"
            f"- Best constituent-source rank: **{ranks['best_source_rank_one_based']} / {CELLS}**\n"
            f"- Complete candidate evaluations: **{discovery['executed_assignments']:,} / {DOMAIN_SIZE:,}**\n"
            f"- Recovered W50 assignment: **0x{candidate:013x}**\n"
            "- Standard ChaCha20: **20 rounds plus feed-forward**\n"
            "- Every prefix: **128 complete 2^31 slabs before outcome evaluation**\n"
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
        "progress_exists": PROGRESS.exists(),
        "result_complete": RESULT.exists(),
    }
    if IMPLEMENTATION.exists():
        payload["implementation_sha256"] = file_sha256(IMPLEMENTATION)
    if PROTOCOL.exists():
        payload["protocol_sha256"] = file_sha256(PROTOCOL)
    if PROGRESS.exists():
        payload["progress"] = json.loads(PROGRESS.read_bytes())
    if RESULT.exists():
        payload["result_sha256"] = file_sha256(RESULT)
        payload["evidence_stage"] = json.loads(RESULT.read_bytes())[
            "evidence_stage"
        ]
    return payload


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    action = parser.add_mutually_exclusive_group(required=True)
    action.add_argument("--analyze", action="store_true")
    action.add_argument("--freeze-implementation", action="store_true")
    action.add_argument("--freeze-protocol", action="store_true")
    action.add_argument("--recover", action="store_true")
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
    elif args.recover:
        if not args.expected_protocol_sha256:
            parser.error("--recover requires --expected-protocol-sha256")
        payload = recover(expected_protocol_sha256=args.expected_protocol_sha256)
    else:
        payload = analyze()
    print(json.dumps(payload, indent=2, sort_keys=True), flush=True)


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""A421: transfer A420's frozen external Reader schedule to a fresh exact W51 recovery."""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import inspect
import json
import math
import os
import secrets
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

DESIGN = CONFIGS / "chacha20_round20_w51_external_reader_shared_stop_recovery_a421_design_v1.json"
IMPLEMENTATION = CONFIGS / "chacha20_round20_w51_external_reader_shared_stop_recovery_a421_implementation_v1.json"
PROTOCOL = CONFIGS / "chacha20_round20_w51_external_reader_shared_stop_recovery_a421_v1.json"
RESULT = RESULTS / "chacha20_round20_w51_external_reader_shared_stop_recovery_a421_v1.json"
STOP = RESULTS / "chacha20_round20_w51_external_reader_shared_stop_recovery_a421_confirmed_stop_v1.json"
CAUSAL = RESULT.with_suffix(".causal")
REPORT = RESULT.with_suffix(".md")
TEST = ROOT / "tests/test_chacha20_round20_w51_external_reader_shared_stop_recovery_a421.py"
REPRO = ROOT / "scripts/reproduce_chacha20_round20_w51_external_reader_shared_stop_recovery_a421.sh"

A390_RUNNER = RESEARCH / "experiments/chacha20_round20_w51_twohundredfiftysix_slab_grouped_engine_a390.py"
A390_DESIGN = CONFIGS / "chacha20_round20_w51_twohundredfiftysix_slab_grouped_engine_a390_design_v1.json"
A390_PROTOCOL = CONFIGS / "chacha20_round20_w51_twohundredfiftysix_slab_grouped_engine_a390_v1.json"
A390_QUALIFICATION = RESULTS / "chacha20_round20_w51_twohundredfiftysix_slab_grouped_engine_a390_qualification_v1.json"
A420_RUNNER = RESEARCH / "experiments/chacha20_round20_w50_external_reader_shared_stop_recovery_a420.py"
A420_DESIGN = CONFIGS / "chacha20_round20_w50_external_reader_shared_stop_recovery_a420_design_v1.json"
A420_IMPLEMENTATION = CONFIGS / "chacha20_round20_w50_external_reader_shared_stop_recovery_a420_implementation_v1.json"
A420_PROTOCOL = CONFIGS / "chacha20_round20_w50_external_reader_shared_stop_recovery_a420_v1.json"
A420_RESULT = RESULTS / "chacha20_round20_w50_external_reader_shared_stop_recovery_a420_v1.json"

ATTEMPT_ID = "A421"
DESIGN_SHA256 = "67665bb0c99ed4a28895f8ab8a9ebe2154b1fa067199c273f3b7941765fe5b52"
A390_DESIGN_SHA256 = "feffc7944535d9785392489de843247d15dab660f6ba2df9f9cfeec9f2595870"
A390_PROTOCOL_SHA256 = "d13d5c0b34de900bdc2d3abe26706b508091685e6a1c7a640168ab5496e479d0"
A390_RUNNER_SHA256 = "1864f7ecd5fb448219784b1a9e514cfddfb3f77f16e46f0d6104f8a778338330"
A420_DESIGN_SHA256 = "888d518a423f858ce8e7e64e25786229f9671594cd6937f54f4742edb5fc2746"
A420_IMPLEMENTATION_SHA256 = "a34d3cd61683fbb451dfb53022210e87b32d33e1cea7d07feaf0b9777be0394b"
A420_RUNNER_SHA256 = "3a34577a648c8df1b083bd0d0e66a6361a18411879b18d5d296a654f34d73048"

WIDTH = 51
KNOWN_KEY_BITS = 256 - WIDTH
PREFIX_BITS = 12
WORD0_SUFFIX_BITS = 20
WORD1_LOW_BITS = 19
CELLS = 1 << PREFIX_BITS
WORKERS = 8
STATIC_EPOCHS = CELLS // WORKERS
GROUP_SIZE = 1 << (WIDTH - PREFIX_BITS)
DOMAIN_SIZE = 1 << WIDTH
SLABS = 256
HOST_REFRESH_GROUPS = 2
BLOCK_COUNT = 8
MASK32 = 0xFFFFFFFF
WORD1_KNOWN_MASK = MASK32 ^ ((1 << WORD1_LOW_BITS) - 1)
DOTCAUSAL_SRC = Path("/Users/bhkmie/Documents/Forschung/O1/vendor/fabel/dotcausal_package/src")


def load_module(path: Path, name: str) -> Any:
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot import A421 dependency {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


A390 = load_module(A390_RUNNER, "a421_a390")
A420 = load_module(A420_RUNNER, "a421_a420")
W43 = A390.W43
file_sha256 = A390.file_sha256
canonical_sha256 = A390.canonical_sha256
atomic_json = A390.atomic_json
atomic_bytes = A420.atomic_bytes
relative = A390.relative
anchor = A390.anchor
path_from_ref = A390.path_from_ref


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def progress_path(worker_index: int) -> Path:
    if not 0 <= worker_index < WORKERS:
        raise ValueError("A421 worker index differs")
    return RESULTS / f"chacha20_round20_w51_external_reader_shared_stop_recovery_a421_worker_{worker_index}_progress_v1.json"


def no_execution_artifacts() -> bool:
    return not any(
        path.exists()
        for path in (PROTOCOL, RESULT, STOP, CAUSAL, REPORT, *(progress_path(i) for i in range(WORKERS)))
    )


def load_design() -> dict[str, Any]:
    if file_sha256(DESIGN) != DESIGN_SHA256:
        raise RuntimeError("A421 design hash differs")
    value = json.loads(DESIGN.read_bytes())
    execution = value.get("execution_contract", {})
    transfer = value.get("schedule_transfer_contract", {})
    boundary = value.get("information_boundary", {})
    if (
        value.get("schema")
        != "chacha20-round20-w51-external-reader-shared-stop-recovery-a421-design-v1"
        or value.get("attempt_id") != ATTEMPT_ID
        or value.get("design_state")
        != "frozen_after_A390_target_free_protocol_and_A420_executor_before_A390_qualification_A420_protocol_A420_result_or_any_W51_challenge_assignment_candidate_progress_or_filter_outcome"
        or execution.get("unknown_key_bits") != WIDTH
        or execution.get("candidates_per_prefix_group") != GROUP_SIZE
        or execution.get("complete_domain_assignments") != DOMAIN_SIZE
        or execution.get("complete_prefix_groups") != CELLS
        or execution.get("workers") != WORKERS
        or execution.get("worker_tasks_each") != STATIC_EPOCHS
        or execution.get("slabs_per_prefix_group") != SLABS
        or execution.get("complete_group_before_success_evaluation") is not True
        or execution.get("shared_stop_only_after_independent_confirmation") is not True
        or transfer.get("copy_all_eight_worker_orders_and_tasks_byte_identically") is not True
        or transfer.get("parameter_refit_on_W51_target") is not False
        or boundary.get("A390_qualification_available_at_A421_design_freeze") is not False
        or boundary.get("A420_protocol_available_at_A421_design_freeze") is not False
        or boundary.get("A420_result_available_at_A421_design_freeze") is not False
        or boundary.get("W51_production_challenge_available_at_A421_design_freeze") is not False
        or boundary.get("prior_live_recovery_filter_outcomes_consumed") is not False
    ):
        raise RuntimeError("A421 frozen design semantics differ")
    sources = value["source_anchors"]
    for key, item in sources.items():
        if key.endswith("_path"):
            stem = key.removesuffix("_path")
            anchor(ROOT / item, sources[f"{stem}_sha256"])
    return value


def freeze_implementation() -> dict[str, Any]:
    if IMPLEMENTATION.exists() or not no_execution_artifacts():
        raise FileExistsError("A421 implementation or downstream artifact already exists")
    if A390_QUALIFICATION.exists() or A420_PROTOCOL.exists() or A420_RESULT.exists():
        raise RuntimeError("A421 code freeze must precede A390 qualification, A420 protocol and A420 result")
    design = load_design()
    if not TEST.exists() or not REPRO.exists():
        raise FileNotFoundError("A421 test and reproducer must precede implementation freeze")
    payload: dict[str, Any] = {
        "schema": "chacha20-round20-w51-external-reader-shared-stop-recovery-a421-implementation-v1",
        "attempt_id": ATTEMPT_ID,
        "commitment_state": "complete_W51_executor_and_fresh_challenge_factory_frozen_before_A390_qualification_A420_protocol_A420_result_or_any_W51_target",
        "design_sha256": DESIGN_SHA256,
        "execution_contract": design["execution_contract"],
        "schedule_transfer_contract": design["schedule_transfer_contract"],
        "fresh_challenge_contract": design["fresh_challenge_contract"],
        "A390_qualification_available_at_freeze": False,
        "A420_protocol_available_at_freeze": False,
        "A420_result_available_at_freeze": False,
        "W51_challenge_or_assignment_available_at_freeze": False,
        "W51_candidate_or_progress_available_at_freeze": False,
        "production_target_labels_used": 0,
        "production_reader_refits": 0,
        "prior_live_recovery_filter_outcomes_consumed": False,
        "anchors": {
            "design": anchor(DESIGN, DESIGN_SHA256),
            "A390_design": anchor(A390_DESIGN, A390_DESIGN_SHA256),
            "A390_protocol": anchor(A390_PROTOCOL, A390_PROTOCOL_SHA256),
            "A390_runner": anchor(A390_RUNNER, A390_RUNNER_SHA256),
            "A420_design": anchor(A420_DESIGN, A420_DESIGN_SHA256),
            "A420_implementation": anchor(A420_IMPLEMENTATION, A420_IMPLEMENTATION_SHA256),
            "A420_runner": anchor(A420_RUNNER, A420_RUNNER_SHA256),
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
        raise RuntimeError("A421 implementation hash differs")
    value = json.loads(IMPLEMENTATION.read_bytes())
    if (
        value.get("schema")
        != "chacha20-round20-w51-external-reader-shared-stop-recovery-a421-implementation-v1"
        or value.get("attempt_id") != ATTEMPT_ID
        or value.get("commitment_state")
        != "complete_W51_executor_and_fresh_challenge_factory_frozen_before_A390_qualification_A420_protocol_A420_result_or_any_W51_target"
        or value.get("A390_qualification_available_at_freeze") is not False
        or value.get("A420_protocol_available_at_freeze") is not False
        or value.get("A420_result_available_at_freeze") is not False
        or value.get("W51_challenge_or_assignment_available_at_freeze") is not False
        or value.get("production_target_labels_used") != 0
        or value.get("production_reader_refits") != 0
    ):
        raise RuntimeError("A421 implementation semantics differ")
    for row in value["anchors"].values():
        anchor(ROOT / row["path"], row["sha256"])
    unsigned = {key: item for key, item in value.items() if key != "implementation_commitment_sha256"}
    if value.get("implementation_commitment_sha256") != canonical_sha256(unsigned):
        raise RuntimeError("A421 implementation commitment differs")
    return value


def apply_assignment(known_zeroed_key_words: Sequence[int], assignment: int) -> list[int]:
    if len(known_zeroed_key_words) != 8:
        raise ValueError("A421 requires eight ChaCha20 key words")
    if not 0 <= assignment < DOMAIN_SIZE:
        raise ValueError("A421 assignment exceeds W51")
    key = [int(word) & MASK32 for word in known_zeroed_key_words]
    if key[0] != 0 or key[1] & ((1 << WORD1_LOW_BITS) - 1):
        raise ValueError("A421 known key does not zero the W51 interval")
    key[0] = assignment & MASK32
    key[1] |= assignment >> 32
    return key


def challenge_from_assignment(*, label: str, assignment: int) -> dict[str, Any]:
    if not 0 <= assignment < DOMAIN_SIZE:
        raise ValueError("A421 assignment exceeds W51")
    derived = hashlib.shake_256(label.encode()).digest(48)
    words = [int(value) for value in W43._words(derived)]  # noqa: SLF001
    known = words[:8]
    known[0] = 0
    known[1] &= WORD1_KNOWN_MASK
    counter = words[8]
    nonce = words[9:12]
    full_key = apply_assignment(known, assignment)
    targets = W43._reference_outputs(full_key, counter, nonce)  # noqa: SLF001
    hashes = [sha256(W43._word_bytes(block)) for block in targets]  # noqa: SLF001
    control = [int(value) for value in targets[0]]
    control[0] ^= 1
    return {
        "challenge_id": "chacha20-r20-w51-a421-fresh-external-reader-transfer-v1",
        "primitive": "RFC8439_ChaCha20_block_function",
        "rounds": 20,
        "feedforward": True,
        "known_material_derivation_label": label,
        "known_material_derivation_sha256": sha256(derived),
        "known_zeroed_key_words": known,
        "known_key_bits": KNOWN_KEY_BITS,
        "unknown_key_bits": WIDTH,
        "unknown_layout": "key_word0_all32_plus_key_word1_low19",
        "unknown_assignment_included": False,
        "counter_start": counter,
        "nonce_words": nonce,
        "target_words": [[int(value) for value in block] for block in targets],
        "target_block_sha256": hashes,
        "control_target_words": control,
        "control_target_block_sha256": sha256(W43._word_bytes(control)),  # noqa: SLF001
        "public_output_blocks": BLOCK_COUNT,
        "public_output_bits": BLOCK_COUNT * 512,
        "filter_words": 2,
        "filter_bits": 64,
    }


def validate_challenge(challenge: Mapping[str, Any]) -> None:
    if (
        challenge.get("challenge_id")
        != "chacha20-r20-w51-a421-fresh-external-reader-transfer-v1"
        or challenge.get("primitive") != "RFC8439_ChaCha20_block_function"
        or challenge.get("rounds") != 20
        or challenge.get("feedforward") is not True
        or challenge.get("known_key_bits") != KNOWN_KEY_BITS
        or challenge.get("unknown_key_bits") != WIDTH
        or challenge.get("unknown_layout") != "key_word0_all32_plus_key_word1_low19"
        or challenge.get("unknown_assignment_included") is not False
        or challenge.get("public_output_blocks") != BLOCK_COUNT
        or challenge.get("public_output_bits") != BLOCK_COUNT * 512
        or len(challenge.get("known_zeroed_key_words", [])) != 8
        or len(challenge.get("nonce_words", [])) != 3
        or len(challenge.get("target_words", [])) != BLOCK_COUNT
        or any(len(block) != 16 for block in challenge.get("target_words", []))
        or "assignment" in challenge
    ):
        raise RuntimeError("A421 public challenge shape differs")
    label = str(challenge["known_material_derivation_label"])
    derived = hashlib.shake_256(label.encode()).digest(48)
    words = [int(value) for value in W43._words(derived)]  # noqa: SLF001
    expected_known = words[:8]
    expected_known[0] = 0
    expected_known[1] &= WORD1_KNOWN_MASK
    targets = [[int(word) & MASK32 for word in block] for block in challenge["target_words"]]
    control = [int(word) & MASK32 for word in challenge["control_target_words"]]
    if (
        sha256(derived) != challenge["known_material_derivation_sha256"]
        or expected_known != challenge["known_zeroed_key_words"]
        or words[8] != challenge["counter_start"]
        or words[9:12] != challenge["nonce_words"]
        or expected_known[0] != 0
        or expected_known[1] & ((1 << WORD1_LOW_BITS) - 1)
        or [sha256(W43._word_bytes(block)) for block in targets]  # noqa: SLF001
        != challenge["target_block_sha256"]
        or control[0] != (targets[0][0] ^ 1)
        or control[1:] != targets[0][1:]
        or sha256(W43._word_bytes(control))  # noqa: SLF001
        != challenge["control_target_block_sha256"]
    ):
        raise RuntimeError("A421 public challenge identity differs")


def fresh_challenge() -> dict[str, Any]:
    label = f"A421|fresh-W51-external-reader-transfer|{secrets.token_hex(32)}"
    assignment = secrets.randbits(WIDTH)
    challenge = challenge_from_assignment(label=label, assignment=assignment)
    del assignment
    validate_challenge(challenge)
    return challenge


def confirm(challenge: Mapping[str, Any], assignment: int) -> dict[str, Any]:
    key_words = apply_assignment(challenge["known_zeroed_key_words"], assignment)
    target_words = challenge["target_words"]
    byte_outputs = W43._reference_outputs(  # noqa: SLF001
        key_words, int(challenge["counter_start"]), challenge["nonce_words"]
    )
    word_outputs = [
        W43.A223.P1._chacha_block(  # noqa: SLF001
            key_words=key_words,
            counter=(int(challenge["counter_start"]) + block) & MASK32,
            nonce_words=challenge["nonce_words"],
            rounds=20,
        )
        for block in range(BLOCK_COUNT)
    ]
    byte_matches = [a == b for a, b in zip(byte_outputs, target_words, strict=True)]
    word_matches = [a == b for a, b in zip(word_outputs, target_words, strict=True)]
    return {
        "assignment": assignment,
        "recovered_key_words": key_words,
        "recovered_key_words_hex": [f"{word:08x}" for word in key_words],
        "byte_reference_block_matches": byte_matches,
        "word_reference_block_matches": word_matches,
        "all_blocks_match": all(byte_matches) and all(word_matches),
        "output_bits_checked_per_reference": BLOCK_COUNT * 512,
        "total_cross_implementation_output_bits_checked": BLOCK_COUNT * 512 * 2,
        "byte_reference_sha256": [sha256(W43._word_bytes(block)) for block in byte_outputs],  # noqa: SLF001
        "word_reference_sha256": [sha256(W43._word_bytes(block)) for block in word_outputs],  # noqa: SLF001
    }


def exact_schedule(source: Mapping[str, Any]) -> tuple[list[str], dict[str, list[int]], dict[str, list[dict[str, Any]]]]:
    roles = [str(role) for role in source.get("worker_roles", [])]
    if len(roles) != WORKERS or len(set(roles)) != WORKERS:
        raise RuntimeError("A421 source worker roles differ")
    orders: dict[str, list[int]] = {}
    tasks: dict[str, list[dict[str, Any]]] = {}
    for index, role in enumerate(roles):
        orders[role], tasks[role] = A420.exact_worker_schedule(
            worker_index=index,
            worker_role=role,
            values=source["worker_cell_orders"][role],
            tasks=source["worker_tasks"][role],
            roles=roles,
        )
    flat = [cell for role in roles for cell in orders[role]]
    if len(flat) != CELLS or set(flat) != set(range(CELLS)):
        raise RuntimeError("A421 source schedule cover differs")
    return roles, orders, tasks


def materialize_protocol(*, expected_implementation_sha256: str, expected_a420_protocol_sha256: str) -> dict[str, Any]:
    if not no_execution_artifacts():
        raise FileExistsError("A421 protocol or execution artifact already exists")
    if A420_RESULT.exists():
        raise RuntimeError("A421 fresh W51 challenge must precede the A420 recovery outcome")
    if A390_QUALIFICATION.exists():
        raise RuntimeError("A421 protocol is declared before the A390 qualification outcome")
    implementation = load_implementation(expected_implementation_sha256)
    source = A420.load_protocol(expected_a420_protocol_sha256)
    roles, orders, tasks = exact_schedule(source)
    challenge = fresh_challenge()
    public_sha = canonical_sha256(challenge)
    payload: dict[str, Any] = {
        "schema": "chacha20-round20-w51-external-reader-shared-stop-recovery-a421-protocol-v1",
        "attempt_id": ATTEMPT_ID,
        "protocol_state": "fresh_W51_challenge_and_byte_identical_A420_schedule_frozen_before_A390_qualification_A420_result_or_any_A421_candidate",
        "design_sha256": DESIGN_SHA256,
        "implementation_sha256": expected_implementation_sha256,
        "implementation_commitment_sha256": implementation["implementation_commitment_sha256"],
        "A390_protocol_sha256": A390_PROTOCOL_SHA256,
        "source_A420_protocol_sha256": expected_a420_protocol_sha256,
        "source_A420_selected_attempt_id": source["selected_source_attempt_id"],
        "source_A420_source_selection": source["source_selection"],
        "worker_roles": roles,
        "worker_cell_orders": orders,
        "worker_tasks": tasks,
        "worker_order_uint16be_sha256": {role: A420.worker_order_sha256(orders[role]) for role in roles},
        "worker_task_list_sha256": {role: A420.task_list_sha256(tasks[role]) for role in roles},
        "public_challenge": challenge,
        "public_challenge_sha256": public_sha,
        "complete_cover_cells": CELLS,
        "duplicate_cells": 0,
        "uncovered_cells": 0,
        "workers": WORKERS,
        "worker_tasks_each": STATIC_EPOCHS,
        "candidates_per_complete_group": GROUP_SIZE,
        "complete_domain_assignments": DOMAIN_SIZE,
        "information_boundary": {
            "A420_schedule_frozen_before_W51_challenge": True,
            "A420_result_available_at_protocol_freeze": False,
            "A390_qualification_available_at_protocol_freeze": False,
            "A421_assignment_absent_from_protocol": True,
            "A421_candidate_or_progress_available_at_protocol_freeze": False,
            "W51_target_labels_used_for_schedule": 0,
            "W51_reader_refits": 0,
            "prior_live_recovery_filter_outcomes_consumed": False,
        },
        "anchors": {
            "design": anchor(DESIGN, DESIGN_SHA256),
            "implementation": anchor(IMPLEMENTATION, expected_implementation_sha256),
            "A390_protocol": anchor(A390_PROTOCOL, A390_PROTOCOL_SHA256),
            "source_A420_protocol": anchor(A420_PROTOCOL, expected_a420_protocol_sha256),
            "runner": anchor(Path(__file__)),
        },
    }
    payload["protocol_commitment_sha256"] = canonical_sha256(payload)
    atomic_json(PROTOCOL, payload)
    return payload


def load_protocol(expected_sha256: str | None = None) -> dict[str, Any]:
    if expected_sha256 is not None and file_sha256(PROTOCOL) != expected_sha256:
        raise RuntimeError("A421 protocol hash differs")
    value = json.loads(PROTOCOL.read_bytes())
    boundary = value.get("information_boundary", {})
    if (
        value.get("schema")
        != "chacha20-round20-w51-external-reader-shared-stop-recovery-a421-protocol-v1"
        or value.get("attempt_id") != ATTEMPT_ID
        or value.get("protocol_state")
        != "fresh_W51_challenge_and_byte_identical_A420_schedule_frozen_before_A390_qualification_A420_result_or_any_A421_candidate"
        or value.get("A390_protocol_sha256") != A390_PROTOCOL_SHA256
        or value.get("complete_cover_cells") != CELLS
        or value.get("duplicate_cells") != 0
        or value.get("uncovered_cells") != 0
        or value.get("workers") != WORKERS
        or value.get("worker_tasks_each") != STATIC_EPOCHS
        or value.get("candidates_per_complete_group") != GROUP_SIZE
        or value.get("complete_domain_assignments") != DOMAIN_SIZE
        or boundary.get("A420_result_available_at_protocol_freeze") is not False
        or boundary.get("A390_qualification_available_at_protocol_freeze") is not False
        or boundary.get("A421_assignment_absent_from_protocol") is not True
        or boundary.get("W51_target_labels_used_for_schedule") != 0
        or canonical_sha256(value.get("public_challenge")) != value.get("public_challenge_sha256")
    ):
        raise RuntimeError("A421 protocol semantics differ")
    load_implementation(value["implementation_sha256"])
    source = A420.load_protocol(value["source_A420_protocol_sha256"])
    roles, orders, tasks = exact_schedule(value)
    source_roles, source_orders, source_tasks = exact_schedule(source)
    if roles != source_roles:
        raise RuntimeError("A421 source role order differs")
    for role in roles:
        if (
            orders[role] != source_orders[role]
            or tasks[role] != source_tasks[role]
            or A420.worker_order_sha256(orders[role]) != value["worker_order_uint16be_sha256"][role]
            or A420.task_list_sha256(tasks[role]) != value["worker_task_list_sha256"][role]
        ):
            raise RuntimeError(f"A421 byte-identical schedule transfer differs for {role}")
    for row in value["anchors"].values():
        anchor(ROOT / row["path"], row["sha256"])
    unsigned = {key: item for key, item in value.items() if key != "protocol_commitment_sha256"}
    if value.get("protocol_commitment_sha256") != canonical_sha256(unsigned):
        raise RuntimeError("A421 protocol commitment differs")
    validate_challenge(value["public_challenge"])
    return value


def load_a390_qualification(expected_sha256: str) -> dict[str, Any]:
    A390.load_protocol(A390_PROTOCOL_SHA256)
    if file_sha256(A390_QUALIFICATION) != expected_sha256:
        raise RuntimeError("A421 A390 qualification file hash differs")
    value = json.loads(A390_QUALIFICATION.read_bytes())
    group = value.get("complete_group_gate", {})
    unsigned = {
        "boundary_full_block_rows": value.get("boundary_full_block_rows"),
        "complete_group_gate": group,
        "expected_synthetic_assignment": value.get("expected_synthetic_assignment"),
        "source_executable_sha256": value.get("source_executable_sha256"),
        "production_W51_challenge_used": False,
    }
    if (
        value.get("schema")
        != "chacha20-round20-w51-twohundredfiftysix-slab-grouped-engine-a390-qualification-v1"
        or value.get("attempt_id") != "A390"
        or value.get("evidence_stage") != "TARGET_FREE_COMPLETE_W51_GROUP_ENGINE_EXACTLY_QUALIFIED"
        or value.get("protocol_sha256") != A390_PROTOCOL_SHA256
        or value.get("production_W51_challenge_used") is not False
        or value.get("production_W51_candidate_used") is not False
        or value.get("synthetic_filter_exact") is not True
        or value.get("matched_control_empty") is not True
        or group.get("logical_candidates") != GROUP_SIZE
        or group.get("complete_W51_group_before_outcome_evaluation") is not True
        or group.get("slabs_executed") != list(range(SLABS))
        or len(group.get("factual_candidates", [])) != 1
        or group.get("control_candidates") != []
        or value.get("qualification_sha256") != canonical_sha256(unsigned)
    ):
        raise RuntimeError("A421 A390 target-free qualification semantics differ")
    return value


def load_resume(
    *, worker_index: int, protocol_sha256: str, qualification_sha256: str, order_sha: str, tasks_sha: str
) -> tuple[int, float, int, dict[str, Any] | None]:
    path = progress_path(worker_index)
    if not path.exists():
        return 0, 0.0, 0, None
    value = json.loads(path.read_bytes())
    if (
        value.get("schema") != "chacha20-round20-w51-external-reader-shared-stop-recovery-a421-progress-v1"
        or value.get("attempt_id") != ATTEMPT_ID
        or value.get("worker_index") != worker_index
        or value.get("protocol_sha256") != protocol_sha256
        or value.get("A390_qualification_sha256") != qualification_sha256
        or value.get("worker_order_uint16be_sha256") != order_sha
        or value.get("worker_task_list_sha256") != tasks_sha
        or value.get("matched_control_candidates") != 0
    ):
        raise RuntimeError("A421 progress fingerprint differs")
    status = value.get("status")
    completed = int(value.get("executed_worker_prefix_groups", -1))
    factual = value.get("factual_filter_candidates")
    if (
        status not in {"running", "candidate_found", "worker_exhausted", "peer_confirmed"}
        or not 0 <= completed <= STATIC_EPOCHS
        or (status == "candidate_found" and (not isinstance(factual, list) or len(factual) != 1))
        or (status != "candidate_found" and factual != 0)
    ):
        raise RuntimeError("A421 resumable progress state differs")
    if status in {"candidate_found", "worker_exhausted", "peer_confirmed"}:
        return completed, float(value.get("gpu_seconds", 0.0)), int(value.get("host_instances", 0)), dict(value)
    return completed, float(value.get("gpu_seconds", 0.0)), int(value.get("host_instances", 0)), None


def ordered_worker_discovery(
    *,
    worker_index: int,
    worker_role: str,
    order: Sequence[int],
    tasks: Sequence[Mapping[str, Any]],
    challenge: Mapping[str, Any],
    host_factory: Callable[[], Any],
    start_group: int,
    prior_gpu_seconds: float,
    prior_host_instances: int,
    progress_callback: Callable[[Mapping[str, Any]], None],
) -> dict[str, Any]:
    if len(order) != STATIC_EPOCHS or len(tasks) != STATIC_EPOCHS or not 0 <= start_group <= STATIC_EPOCHS:
        raise ValueError("A421 worker schedule geometry differs")
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
                    "worker_index": worker_index,
                    "worker_role": worker_role,
                    "executed_worker_prefix_groups": position,
                    "worker_prefix_groups": STATIC_EPOCHS,
                    "factual_filter_candidates": 0,
                    "matched_control_candidates": 0,
                    "gpu_seconds": gpu_seconds,
                    "host_instances": host_instances,
                    "static_schedule_epoch": position,
                    "volatile_wall_seconds": time.perf_counter() - started,
                }
            prefix = int(order[position])
            task = tasks[position]
            if position == start_group or position % HOST_REFRESH_GROUPS == 0:
                if host is not None:
                    host.close()
                host = host_factory()
                host_instances += 1
            observed = A390.filter_complete_prefix(
                host=host, challenge=challenge, prefix=prefix, target=target, control=control
            )
            factual = [int(item) for item in observed["factual_candidates"]]
            controls = [int(item) for item in observed["control_candidates"]]
            gpu_seconds += float(observed["gpu_seconds"])
            groups = position + 1
            if controls:
                raise RuntimeError("A421 matched control produced a candidate")
            common = {
                "executed_worker_prefix_groups": groups,
                "worker_prefix_groups": STATIC_EPOCHS,
                "executed_worker_assignments": groups * GROUP_SIZE,
                "static_schedule_epoch": int(task["epoch"]),
                "matched_control_candidates": 0,
                "gpu_seconds": gpu_seconds,
                "host_instances": host_instances,
                "last_completed_prefix12": prefix,
                "last_owner_queue_role": task["owner_queue_role"],
                "last_owner_queue_position_one_based": task["owner_queue_position_one_based"],
                "last_task_stolen": task["stolen"],
            }
            if not factual:
                progress_callback({"status": "running", "factual_filter_candidates": 0, **common})
                continue
            if len(factual) != 1:
                raise RuntimeError("A421 complete W51 group produced multiple factual filters")
            candidate = factual[0]
            if ((candidate >> WORD0_SUFFIX_BITS) & (CELLS - 1)) != prefix:
                raise RuntimeError("A421 candidate prefix differs")
            decoded = A390.decode_assignment(candidate)
            found = {
                "status": "candidate_found",
                "worker_index": worker_index,
                "worker_role": worker_role,
                "candidate": candidate,
                "candidate_hex": f"{candidate:013x}",
                "key_word0": decoded["word0"],
                "key_word1_low19": decoded["word1_low19"],
                "prefix12": prefix,
                "prefix12_hex": f"{prefix:03x}",
                "worker_step_one_based": groups,
                "owner_queue_role": task["owner_queue_role"],
                "owner_queue_position_one_based": task["owner_queue_position_one_based"],
                "task_stolen": task["stolen"],
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
        "worker_index": worker_index,
        "worker_role": worker_role,
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


def mark_peer_confirmed(protocol: Mapping[str, Any], qualification_sha256: str, worker_index: int) -> dict[str, Any]:
    path = progress_path(worker_index)
    if not path.exists():
        return {"status": "peer_confirmed", "worker_index": worker_index, "worker_was_not_started": True}
    value = json.loads(path.read_bytes())
    if (
        value.get("protocol_sha256") != file_sha256(PROTOCOL)
        or value.get("A390_qualification_sha256") != qualification_sha256
        or value.get("worker_index") != worker_index
    ):
        raise RuntimeError("A421 peer progress fingerprint differs")
    if value.get("status") not in {"running", "peer_confirmed", "worker_exhausted", "candidate_found"}:
        raise RuntimeError("A421 peer progress status differs")
    if value.get("status") in {"running", "peer_confirmed"}:
        value["status"] = "peer_confirmed"
        value["confirmed_stop_sha256"] = file_sha256(STOP)
        value["factual_filter_candidates"] = 0
        atomic_json(path, value)
    return {"status": "peer_confirmed", "worker_index": worker_index}


def progress_snapshot(protocol: Mapping[str, Any]) -> dict[str, Any]:
    panel: dict[str, Any] = {}
    total = 0
    max_epoch = 0
    all_controls_empty = True
    roles = protocol["worker_roles"]
    for index, role in enumerate(roles):
        path = progress_path(index)
        if not path.exists():
            panel[role] = {"status": "not_started", "executed_worker_prefix_groups": 0, "worker_prefix_groups": STATIC_EPOCHS}
            continue
        value = json.loads(path.read_bytes())
        if value.get("protocol_sha256") != file_sha256(PROTOCOL) or value.get("worker_role") != role:
            raise RuntimeError("A421 progress snapshot fingerprint differs")
        groups = int(value.get("executed_worker_prefix_groups", 0))
        total += groups
        max_epoch = max(max_epoch, int(value.get("static_schedule_epoch", 0)))
        all_controls_empty &= value.get("matched_control_candidates") == 0
        panel[role] = {
            "status": value.get("status"),
            "executed_worker_prefix_groups": groups,
            "worker_prefix_groups": STATIC_EPOCHS,
            "static_schedule_epoch": int(value.get("static_schedule_epoch", 0)),
            "gpu_seconds": float(value.get("gpu_seconds", 0.0)),
            "matched_control_candidates": value.get("matched_control_candidates"),
        }
    return {
        "workers": panel,
        "total_unique_prefix_groups_evaluated": total,
        "total_unique_assignments_evaluated": total * GROUP_SIZE,
        "maximum_completed_static_schedule_epoch": max_epoch,
        "theoretical_complete_schedule_epochs": STATIC_EPOCHS,
        "complete_domain_assignments": DOMAIN_SIZE,
        "all_observed_matched_controls_empty": all_controls_empty,
        "prefix_sets_are_disjoint_by_A420_construction": True,
    }


def active_started_workers_terminal(protocol: Mapping[str, Any]) -> bool:
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

    terminal = "confirmed_strict_subset_W51_recovery" if payload["aggregate_execution"]["strict_subset_of_complete_domain"] else "confirmed_complete_domain_W51_recovery"
    writer = CausalWriter(api_id="a421w51")
    writer._rules = []
    writer.add_rule(
        name="external_reader_schedule_and_exact_W51_engine_to_model",
        description="Execute the byte-identical externally selected eight-reader schedule as disjoint complete W51 groups with one confirmed shared stop.",
        pattern=["A421_frozen_fresh_W51_schedule", "A390_exact_W51_group_engine"],
        conclusion="A421_sole_factual_W51_model",
        confidence_modifier=1.0,
    )
    writer.add_rule(
        name="W51_model_to_confirmed_recovery",
        description="Require empty matched control and independent eight-block confirmation before retaining either strict-subset or complete-domain W51 recovery.",
        pattern=["A421_sole_factual_W51_model"],
        conclusion=f"A421_{terminal}",
        confidence_modifier=1.0,
    )
    writer.add_triplet(
        trigger="A421:frozen_fresh_W51_external_reader_schedule",
        mechanism="disjoint_complete_2^39_group_execution_with_confirmed_shared_stop",
        outcome="A421:sole_factual_W51_model",
        confidence=1.0,
        source=payload["execution_sha256"],
        quantification=json.dumps(payload["aggregate_execution"], sort_keys=True),
        evidence=json.dumps(payload["rank_analysis"], sort_keys=True),
        domain="full-round ChaCha20 W51 external Reader recovery",
        quality_score=1.0,
    )
    writer.add_triplet(
        trigger="A421:sole_factual_W51_model",
        mechanism="matched_control_rejection_and_dual_reference_eight_block_confirmation",
        outcome=f"A421:{terminal}",
        confidence=1.0,
        source=payload["measurement_sha256"],
        quantification=json.dumps(payload["confirmation"], sort_keys=True),
        evidence=payload["evidence_stage"],
        domain="confirmed full-round ChaCha20 W51 recovery",
        quality_score=1.0,
    )
    writer.add_triplet(
        trigger="A421:frozen_fresh_W51_external_reader_schedule",
        mechanism="materialized_external_reader_W51_search_and_confirmation_closure",
        outcome=f"A421:{terminal}",
        confidence=1.0,
        source="materialized:A421_external_reader_W51_recovery_chain",
        quantification="exact retained closure",
        evidence=payload["evidence_stage"],
        domain="AI-native retained inference",
        quality_score=1.0,
        is_inferred=True,
    )
    writer.add_cluster(
        name="A421 external Reader W51 recovery",
        entities=["A421:frozen_fresh_W51_external_reader_schedule", "A421:sole_factual_W51_model", f"A421:{terminal}"],
    )
    writer.add_gap(
        subject=f"A421:{terminal}",
        predicate="next_required_object",
        expected_object_type="W52_or_wider_external_reader_shared_stop_transfer",
        confidence=1.0,
        suggested_queries=["Qualify the next exact grouped-engine width and preserve the same frozen external Reader transfer boundary."],
    )
    temporary = CAUSAL.with_name(f".{CAUSAL.name}.tmp")
    temporary.unlink(missing_ok=True)
    stats = writer.save(str(temporary))
    os.replace(temporary, CAUSAL)
    reader = CausalReader(str(CAUSAL), verify_integrity=True)
    explicit = reader.get_all_triplets(include_inferred=False)
    all_rows = reader.get_all_triplets(include_inferred=True)
    inferred = [row for row in reader._triplets if row.get("is_inferred", False)]
    if reader.api_id != "a421w51" or len(explicit) != 2 or len(all_rows) != 3 or len(inferred) != 1 or len(reader._rules) != 2 or len(reader._clusters) != 1 or len(reader._gaps) != 1:
        raise RuntimeError("A421 authentic Causal reopen gate failed")
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


def finalize_confirmed_stop(protocol: Mapping[str, Any], qualification_sha256: str) -> dict[str, Any]:
    if RESULT.exists():
        return {"status": "peer_confirmed", "result_sha256": file_sha256(RESULT)}
    stop = json.loads(STOP.read_bytes())
    if (
        stop.get("schema") != "chacha20-round20-w51-external-reader-shared-stop-recovery-a421-confirmed-stop-v1"
        or stop.get("attempt_id") != ATTEMPT_ID
        or stop.get("protocol_sha256") != file_sha256(PROTOCOL)
        or stop.get("A390_qualification_sha256") != qualification_sha256
        or stop.get("confirmation", {}).get("all_blocks_match") is not True
        or stop.get("discovery", {}).get("control_filter_candidates") != []
    ):
        raise RuntimeError("A421 confirmed stop fingerprint differs")
    while not active_started_workers_terminal(protocol):
        time.sleep(5)
    aggregate = progress_snapshot(protocol)
    unique_groups = int(aggregate["total_unique_prefix_groups_evaluated"])
    if not 1 <= unique_groups <= CELLS:
        raise RuntimeError("A421 aggregate unique group count differs")
    strict_subset = unique_groups < CELLS
    aggregate["strict_subset_of_complete_domain"] = strict_subset
    aggregate["domain_reduction_factor"] = CELLS / unique_groups
    aggregate["search_gain_bits"] = math.log2(CELLS / unique_groups)
    discovery = stop["discovery"]
    rank_analysis = {
        "prefix12": int(discovery["prefix12"]),
        "prefix12_hex": discovery["prefix12_hex"],
        "source_A420_selected_attempt_id": protocol["source_A420_selected_attempt_id"],
        "source_worker_role": discovery["worker_role"],
        "source_schedule_epoch_one_based": int(discovery["static_schedule_epoch"]),
        "source_owner_queue_role": discovery["owner_queue_role"],
        "source_owner_queue_position_one_based": int(discovery["owner_queue_position_one_based"]),
        "executed_winner_worker_step_one_based": int(discovery["worker_step_one_based"]),
        "aggregate_unique_groups_before_confirmed_stop": unique_groups,
    }
    evidence_stage = (
        "FULLROUND_R20_EXTERNAL_READER_W51_STRICT_SUBSET_RECOVERY_CONFIRMED"
        if strict_subset
        else "FULLROUND_R20_EXTERNAL_READER_W51_COMPLETE_DOMAIN_RECOVERY_CONFIRMED"
    )
    payload: dict[str, Any] = {
        "schema": "chacha20-round20-w51-external-reader-shared-stop-recovery-a421-result-v1",
        "attempt_id": ATTEMPT_ID,
        "evidence_stage": evidence_stage,
        "design_sha256": DESIGN_SHA256,
        "implementation_sha256": protocol["implementation_sha256"],
        "implementation_commitment_sha256": protocol["implementation_commitment_sha256"],
        "protocol_sha256": file_sha256(PROTOCOL),
        "protocol_commitment_sha256": protocol["protocol_commitment_sha256"],
        "A390_qualification_sha256": qualification_sha256,
        "source_A420_protocol_sha256": protocol["source_A420_protocol_sha256"],
        "source_A420_selected_attempt_id": protocol["source_A420_selected_attempt_id"],
        "discovery": discovery,
        "confirmation": stop["confirmation"],
        "aggregate_execution": aggregate,
        "rank_analysis": rank_analysis,
        "matched_control_candidates": 0,
        "factual_candidates": 1,
        "all_4096_output_bits_match_in_both_references": True,
        "complete_group_before_stop": True,
        "early_stop_inside_group": False,
        "production_target_labels_used": 0,
        "production_reader_refits": 0,
        "prior_W50_public_assignment_bit_reused": False,
        "prior_live_recovery_filter_outcomes_consumed": False,
        "execution_sha256": canonical_sha256({"discovery": discovery, "aggregate_execution": aggregate, "rank_analysis": rank_analysis}),
        "measurement_sha256": canonical_sha256({"confirmation": stop["confirmation"], "matched_control_candidates": 0}),
        "anchors": {
            "design": anchor(DESIGN, DESIGN_SHA256),
            "implementation": anchor(IMPLEMENTATION, protocol["implementation_sha256"]),
            "protocol": anchor(PROTOCOL, file_sha256(PROTOCOL)),
            "confirmed_stop": anchor(STOP, file_sha256(STOP)),
            "A390_qualification": anchor(A390_QUALIFICATION, qualification_sha256),
            "source_A420_protocol": anchor(A420_PROTOCOL, protocol["source_A420_protocol_sha256"]),
            "runner": anchor(Path(__file__)),
        },
    }
    payload["causal"] = build_causal(payload)
    atomic_json(RESULT, payload)
    atomic_bytes(
        REPORT,
        (
            "# A421 — External Reader full-round ChaCha20 W51 recovery\n\n"
            f"Evidence stage: **{evidence_stage}**\n\n"
            f"- Externally selected schedule: **{protocol['source_A420_selected_attempt_id']} via A420**\n"
            f"- Exact unique W51 groups evaluated: **{unique_groups} / 4096**\n"
            f"- Complete assignments evaluated: **{aggregate['total_unique_assignments_evaluated']:,} / {DOMAIN_SIZE:,}**\n"
            f"- Search gain: **{aggregate['search_gain_bits']:.9f} bits**\n"
            "- Factual / matched-control candidates: **1 / 0**\n"
            "- Independent confirmation: **two implementations, eight blocks, 8,192 checked output bits**\n"
            "- Authentic AI-native Causal readback: **2 explicit + 1 inferred chain**\n"
        ).encode(),
    )
    return payload


def recover_worker(*, worker_index: int, expected_protocol_sha256: str, expected_a390_qualification_sha256: str) -> dict[str, Any]:
    if RESULT.exists():
        return {"status": "peer_confirmed", "result_sha256": file_sha256(RESULT)}
    protocol = load_protocol(expected_protocol_sha256)
    load_a390_qualification(expected_a390_qualification_sha256)
    if STOP.exists():
        stop = json.loads(STOP.read_bytes())
        if int(stop.get("worker_index", -1)) == worker_index:
            return finalize_confirmed_stop(protocol, expected_a390_qualification_sha256)
        return mark_peer_confirmed(protocol, expected_a390_qualification_sha256, worker_index)
    roles = protocol["worker_roles"]
    role = roles[worker_index]
    order, tasks = A420.exact_worker_schedule(
        worker_index=worker_index,
        worker_role=role,
        values=protocol["worker_cell_orders"][role],
        tasks=protocol["worker_tasks"][role],
        roles=roles,
    )
    engine_protocol = A390.load_protocol(A390_PROTOCOL_SHA256)
    executable_row = engine_protocol["anchors"]["grouped_executable"]
    executable = path_from_ref(executable_row["path"])
    anchor(executable, executable_row["sha256"])
    challenge = protocol["public_challenge"]
    placeholder = np.asarray([0, 0], dtype=np.uint32)

    def host_factory() -> Any:
        return A390.A384.A378.A371.A346.A324.A311.A307.A304.GroupedMetalHost(
            executable, A390.initial_for_slab(challenge, 0), placeholder, placeholder
        )

    order_sha = protocol["worker_order_uint16be_sha256"][role]
    tasks_sha = protocol["worker_task_list_sha256"][role]

    def write_progress(row: Mapping[str, Any]) -> None:
        atomic_json(
            progress_path(worker_index),
            {
                "schema": "chacha20-round20-w51-external-reader-shared-stop-recovery-a421-progress-v1",
                "attempt_id": ATTEMPT_ID,
                "worker_index": worker_index,
                "worker_role": role,
                "protocol_sha256": expected_protocol_sha256,
                "A390_qualification_sha256": expected_a390_qualification_sha256,
                "worker_order_uint16be_sha256": order_sha,
                "worker_task_list_sha256": tasks_sha,
                "matched_control_candidates": 0,
                **dict(row),
            },
        )

    start, prior_gpu, prior_hosts, completed = load_resume(
        worker_index=worker_index,
        protocol_sha256=expected_protocol_sha256,
        qualification_sha256=expected_a390_qualification_sha256,
        order_sha=order_sha,
        tasks_sha=tasks_sha,
    )
    if completed is not None:
        if completed.get("status") == "candidate_found" and not STOP.exists():
            discovery = completed
        elif STOP.exists():
            return recover_worker(
                worker_index=worker_index,
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
            worker_index=worker_index,
            worker_role=role,
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
                progress_path(index).exists()
                and json.loads(progress_path(index).read_bytes()).get("status") == "worker_exhausted"
                for index in range(WORKERS)
            )
            if exhausted == WORKERS:
                raise RuntimeError("A421 all disjoint workers exhausted without a model")
        return discovery
    candidate = int(discovery["candidate"])
    confirmation = confirm(challenge, candidate)
    if confirmation.get("all_blocks_match") is not True:
        raise RuntimeError("A421 dual-reference eight-block confirmation failed")
    if discovery.get("control_filter_candidates") != []:
        raise RuntimeError("A421 matched control produced a candidate")
    atomic_json(
        STOP,
        {
            "schema": "chacha20-round20-w51-external-reader-shared-stop-recovery-a421-confirmed-stop-v1",
            "attempt_id": ATTEMPT_ID,
            "protocol_sha256": expected_protocol_sha256,
            "A390_qualification_sha256": expected_a390_qualification_sha256,
            "worker_index": worker_index,
            "worker_role": role,
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
        "A390_qualification_complete": A390_QUALIFICATION.exists(),
        "A420_protocol_available": A420_PROTOCOL.exists(),
        "A420_result_available": A420_RESULT.exists(),
        "protocol_frozen": PROTOCOL.exists(),
        "confirmed_stop_available": STOP.exists(),
        "result_complete": RESULT.exists(),
        "candidate_group_size": GROUP_SIZE,
        "complete_domain_assignments": DOMAIN_SIZE,
    }
    if IMPLEMENTATION.exists():
        payload["implementation_sha256"] = file_sha256(IMPLEMENTATION)
        load_implementation(payload["implementation_sha256"])
    if A390_QUALIFICATION.exists():
        payload["A390_qualification_sha256"] = file_sha256(A390_QUALIFICATION)
        load_a390_qualification(payload["A390_qualification_sha256"])
    if PROTOCOL.exists():
        payload["protocol_sha256"] = file_sha256(PROTOCOL)
        protocol = load_protocol(payload["protocol_sha256"])
        payload["source_A420_selected_attempt_id"] = protocol["source_A420_selected_attempt_id"]
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
    action.add_argument("--materialize-protocol", action="store_true")
    action.add_argument("--recover-worker", type=int)
    parser.add_argument("--expected-implementation-sha256")
    parser.add_argument("--expected-a420-protocol-sha256")
    parser.add_argument("--expected-protocol-sha256")
    parser.add_argument("--expected-a390-qualification-sha256")
    args = parser.parse_args()
    if args.freeze_implementation:
        payload = freeze_implementation()
    elif args.materialize_protocol:
        if not args.expected_implementation_sha256 or not args.expected_a420_protocol_sha256:
            parser.error("--materialize-protocol requires implementation and A420 protocol hashes")
        payload = materialize_protocol(
            expected_implementation_sha256=args.expected_implementation_sha256,
            expected_a420_protocol_sha256=args.expected_a420_protocol_sha256,
        )
    elif args.recover_worker is not None:
        if not args.expected_protocol_sha256 or not args.expected_a390_qualification_sha256:
            parser.error("--recover-worker requires protocol and A390 qualification hashes")
        payload = recover_worker(
            worker_index=args.recover_worker,
            expected_protocol_sha256=args.expected_protocol_sha256,
            expected_a390_qualification_sha256=args.expected_a390_qualification_sha256,
        )
    else:
        payload = analyze()
    print(json.dumps(payload, indent=2, sort_keys=True), flush=True)


if __name__ == "__main__":
    main()

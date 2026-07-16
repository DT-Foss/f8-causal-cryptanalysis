#!/usr/bin/env python3
"""A423: transfer A420's frozen external Reader schedule to a fresh exact W52 recovery."""

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
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

import numpy as np

ROOT = Path(__file__).parents[2]
RESEARCH = ROOT / "research"
CONFIGS = RESEARCH / "configs"
RESULTS = RESEARCH / "results/v1"

DESIGN = CONFIGS / "chacha20_round20_w52_external_reader_shared_stop_recovery_a423_design_v1.json"
IMPLEMENTATION = CONFIGS / "chacha20_round20_w52_external_reader_shared_stop_recovery_a423_implementation_v1.json"
PROTOCOL = CONFIGS / "chacha20_round20_w52_external_reader_shared_stop_recovery_a423_v1.json"
RESULT = RESULTS / "chacha20_round20_w52_external_reader_shared_stop_recovery_a423_v1.json"
STOP = RESULTS / "chacha20_round20_w52_external_reader_shared_stop_recovery_a423_confirmed_stop_v1.json"
CAUSAL = RESULT.with_suffix(".causal")
REPORT = RESULT.with_suffix(".md")
TEST = ROOT / "tests/test_chacha20_round20_w52_external_reader_shared_stop_recovery_a423.py"
REPRO = ROOT / "scripts/reproduce_chacha20_round20_w52_external_reader_shared_stop_recovery_a423.sh"

A422_RUNNER = RESEARCH / "experiments/chacha20_round20_w52_fivehundredtwelve_slab_grouped_engine_a422.py"
A422_DESIGN = CONFIGS / "chacha20_round20_w52_fivehundredtwelve_slab_grouped_engine_a422_design_v1.json"
A422_PROTOCOL = CONFIGS / "chacha20_round20_w52_fivehundredtwelve_slab_grouped_engine_a422_v1.json"
A422_QUALIFICATION = RESULTS / "chacha20_round20_w52_fivehundredtwelve_slab_grouped_engine_a422_qualification_v1.json"
A420_RUNNER = RESEARCH / "experiments/chacha20_round20_w50_external_reader_shared_stop_recovery_a420.py"
A420_DESIGN = CONFIGS / "chacha20_round20_w50_external_reader_shared_stop_recovery_a420_design_v1.json"
A420_IMPLEMENTATION = CONFIGS / "chacha20_round20_w50_external_reader_shared_stop_recovery_a420_implementation_v1.json"
A420_PROTOCOL = CONFIGS / "chacha20_round20_w50_external_reader_shared_stop_recovery_a420_v1.json"
A420_RESULT = RESULTS / "chacha20_round20_w50_external_reader_shared_stop_recovery_a420_v1.json"
A421_RUNNER = RESEARCH / "experiments/chacha20_round20_w51_external_reader_shared_stop_recovery_a421.py"
A421_IMPLEMENTATION = CONFIGS / "chacha20_round20_w51_external_reader_shared_stop_recovery_a421_implementation_v1.json"
A421_RESULT = RESULTS / "chacha20_round20_w51_external_reader_shared_stop_recovery_a421_v1.json"

ATTEMPT_ID = "A423"
DESIGN_SHA256 = "925b46937f13b75e126a48dad990a0f38029d8d8d6d206da393cdd480bc04a89"
A422_DESIGN_SHA256 = "eec874d7b680e65c34322e0a1b7a4cabccde3082b6c911944486ec968633cc68"
A422_PROTOCOL_SHA256 = "1c50ef355d5b1fe0a13a6860d57923ed3e380b5c069e0587d84535c7f89d6dd6"
A422_RUNNER_SHA256 = "379c300d3ba8ad4399e4c726aee7473e946e62ac5d9d331bab01e733842f881a"
A420_DESIGN_SHA256 = "888d518a423f858ce8e7e64e25786229f9671594cd6937f54f4742edb5fc2746"
A420_IMPLEMENTATION_SHA256 = "a34d3cd61683fbb451dfb53022210e87b32d33e1cea7d07feaf0b9777be0394b"
A420_RUNNER_SHA256 = "3a34577a648c8df1b083bd0d0e66a6361a18411879b18d5d296a654f34d73048"
A421_IMPLEMENTATION_SHA256 = "e867ddbf0bb1964a7ea07311f2b42d27146e17234a8bcc3e23111622ff7ce37d"
A421_RUNNER_SHA256 = "7e6d811c8b058021c1f330e67621868bdd5c4d825affa1687b9c97070029fcbb"

WIDTH = 52
KNOWN_KEY_BITS = 256 - WIDTH
PREFIX_BITS = 12
WORD0_SUFFIX_BITS = 20
WORD1_LOW_BITS = 20
CELLS = 1 << PREFIX_BITS
WORKERS = 8
STATIC_EPOCHS = CELLS // WORKERS
GROUP_SIZE = 1 << (WIDTH - PREFIX_BITS)
DOMAIN_SIZE = 1 << WIDTH
SLABS = 512
HOST_REFRESH_GROUPS = 1
BLOCK_COUNT = 8
MASK32 = 0xFFFFFFFF
WORD1_KNOWN_MASK = MASK32 ^ ((1 << WORD1_LOW_BITS) - 1)
DOTCAUSAL_SRC = Path("/Users/bhkmie/Documents/Forschung/O1/vendor/fabel/dotcausal_package/src")


def load_module(path: Path, name: str) -> Any:
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot import A423 dependency {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


A422 = load_module(A422_RUNNER, "a423_a422")
A420 = load_module(A420_RUNNER, "a423_a420")
A421 = load_module(A421_RUNNER, "a423_a421")
W43 = A422.W43
file_sha256 = A422.file_sha256
canonical_sha256 = A422.canonical_sha256
atomic_json = A422.atomic_json
atomic_bytes = A421.atomic_bytes
relative = A422.relative
anchor = A422.anchor
path_from_ref = A422.path_from_ref


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def progress_path(worker_index: int) -> Path:
    if not 0 <= worker_index < WORKERS:
        raise ValueError("A423 worker index differs")
    return RESULTS / f"chacha20_round20_w52_external_reader_shared_stop_recovery_a423_worker_{worker_index}_progress_v1.json"


def no_execution_artifacts() -> bool:
    return not any(
        path.exists()
        for path in (PROTOCOL, RESULT, STOP, CAUSAL, REPORT, *(progress_path(i) for i in range(WORKERS)))
    )


def load_design() -> dict[str, Any]:
    if file_sha256(DESIGN) != DESIGN_SHA256:
        raise RuntimeError("A423 design hash differs")
    value = json.loads(DESIGN.read_bytes())
    execution = value.get("execution_contract", {})
    transfer = value.get("schedule_transfer_contract", {})
    boundary = value.get("information_boundary", {})
    if (
        value.get("schema") != "chacha20-round20-w52-external-reader-shared-stop-recovery-a423-design-v1"
        or value.get("attempt_id") != ATTEMPT_ID
        or value.get("design_state")
        != "frozen_after_A422_target_free_protocol_and_A420_executor_before_A420_protocol_A420_result_A421_result_A422_qualification_or_any_W52_challenge_assignment_candidate_progress_or_filter_outcome"
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
        or transfer.get("parameter_refit_on_W52_target") is not False
        or boundary.get("A422_qualification_available_at_A423_design_freeze") is not False
        or boundary.get("A420_protocol_available_at_A423_design_freeze") is not False
        or boundary.get("A420_result_available_at_A423_design_freeze") is not False
        or boundary.get("A421_result_available_at_A423_design_freeze") is not False
        or boundary.get("W52_production_challenge_available_at_A423_design_freeze") is not False
        or boundary.get("prior_live_recovery_filter_outcomes_consumed") is not False
    ):
        raise RuntimeError("A423 frozen design semantics differ")
    sources = value["source_anchors"]
    for key, item in sources.items():
        if key.endswith("_path"):
            stem = key.removesuffix("_path")
            anchor(ROOT / item, sources[f"{stem}_sha256"])
    return value


def freeze_implementation() -> dict[str, Any]:
    if IMPLEMENTATION.exists() or not no_execution_artifacts():
        raise FileExistsError("A423 implementation or downstream artifact already exists")
    if A422_QUALIFICATION.exists() or A420_PROTOCOL.exists() or A420_RESULT.exists() or A421_RESULT.exists():
        raise RuntimeError("A423 code freeze must precede A422 qualification, A420 protocol and narrower recovery results")
    design = load_design()
    if not TEST.exists() or not REPRO.exists():
        raise FileNotFoundError("A423 test and reproducer must precede implementation freeze")
    payload: dict[str, Any] = {
        "schema": "chacha20-round20-w52-external-reader-shared-stop-recovery-a423-implementation-v1",
        "attempt_id": ATTEMPT_ID,
        "commitment_state": "complete_W52_executor_and_fresh_challenge_factory_frozen_before_A422_qualification_A420_protocol_or_any_narrower_recovery_result",
        "design_sha256": DESIGN_SHA256,
        "execution_contract": design["execution_contract"],
        "schedule_transfer_contract": design["schedule_transfer_contract"],
        "fresh_challenge_contract": design["fresh_challenge_contract"],
        "A422_qualification_available_at_freeze": False,
        "A420_protocol_available_at_freeze": False,
        "A420_result_available_at_freeze": False,
        "A421_result_available_at_freeze": False,
        "W52_challenge_or_assignment_available_at_freeze": False,
        "W52_candidate_or_progress_available_at_freeze": False,
        "production_target_labels_used": 0,
        "production_reader_refits": 0,
        "prior_live_recovery_filter_outcomes_consumed": False,
        "shared_stop_core": "byte-identical frozen A421 runner functions with an explicit A422 engine facade",
        "anchors": {
            "design": anchor(DESIGN, DESIGN_SHA256),
            "A422_design": anchor(A422_DESIGN, A422_DESIGN_SHA256),
            "A422_protocol": anchor(A422_PROTOCOL, A422_PROTOCOL_SHA256),
            "A422_runner": anchor(A422_RUNNER, A422_RUNNER_SHA256),
            "A420_design": anchor(A420_DESIGN, A420_DESIGN_SHA256),
            "A420_implementation": anchor(A420_IMPLEMENTATION, A420_IMPLEMENTATION_SHA256),
            "A420_runner": anchor(A420_RUNNER, A420_RUNNER_SHA256),
            "A421_implementation": anchor(A421_IMPLEMENTATION, A421_IMPLEMENTATION_SHA256),
            "A421_runner": anchor(A421_RUNNER, A421_RUNNER_SHA256),
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
        raise RuntimeError("A423 implementation hash differs")
    value = json.loads(IMPLEMENTATION.read_bytes())
    if (
        value.get("schema") != "chacha20-round20-w52-external-reader-shared-stop-recovery-a423-implementation-v1"
        or value.get("attempt_id") != ATTEMPT_ID
        or value.get("commitment_state")
        != "complete_W52_executor_and_fresh_challenge_factory_frozen_before_A422_qualification_A420_protocol_or_any_narrower_recovery_result"
        or value.get("A422_qualification_available_at_freeze") is not False
        or value.get("A420_protocol_available_at_freeze") is not False
        or value.get("A420_result_available_at_freeze") is not False
        or value.get("A421_result_available_at_freeze") is not False
        or value.get("W52_challenge_or_assignment_available_at_freeze") is not False
        or value.get("production_target_labels_used") != 0
        or value.get("production_reader_refits") != 0
    ):
        raise RuntimeError("A423 implementation semantics differ")
    for row in value["anchors"].values():
        anchor(ROOT / row["path"], row["sha256"])
    unsigned = {key: item for key, item in value.items() if key != "implementation_commitment_sha256"}
    if value.get("implementation_commitment_sha256") != canonical_sha256(unsigned):
        raise RuntimeError("A423 implementation commitment differs")
    return value


def apply_assignment(known_zeroed_key_words: Sequence[int], assignment: int) -> list[int]:
    if len(known_zeroed_key_words) != 8:
        raise ValueError("A423 requires eight ChaCha20 key words")
    if not 0 <= assignment < DOMAIN_SIZE:
        raise ValueError("A423 assignment exceeds W52")
    key = [int(word) & MASK32 for word in known_zeroed_key_words]
    if key[0] != 0 or key[1] & ((1 << WORD1_LOW_BITS) - 1):
        raise ValueError("A423 known key does not zero the W52 interval")
    key[0] = assignment & MASK32
    key[1] |= assignment >> 32
    return key


def challenge_from_assignment(*, label: str, assignment: int) -> dict[str, Any]:
    if not 0 <= assignment < DOMAIN_SIZE:
        raise ValueError("A423 assignment exceeds W52")
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
        "challenge_id": "chacha20-r20-w52-a423-fresh-external-reader-transfer-v1",
        "primitive": "RFC8439_ChaCha20_block_function",
        "rounds": 20,
        "feedforward": True,
        "known_material_derivation_label": label,
        "known_material_derivation_sha256": sha256(derived),
        "known_zeroed_key_words": known,
        "known_key_bits": KNOWN_KEY_BITS,
        "unknown_key_bits": WIDTH,
        "unknown_layout": "key_word0_all32_plus_key_word1_low20",
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
        challenge.get("challenge_id") != "chacha20-r20-w52-a423-fresh-external-reader-transfer-v1"
        or challenge.get("primitive") != "RFC8439_ChaCha20_block_function"
        or challenge.get("rounds") != 20
        or challenge.get("feedforward") is not True
        or challenge.get("known_key_bits") != KNOWN_KEY_BITS
        or challenge.get("unknown_key_bits") != WIDTH
        or challenge.get("unknown_layout") != "key_word0_all32_plus_key_word1_low20"
        or challenge.get("unknown_assignment_included") is not False
        or challenge.get("public_output_blocks") != BLOCK_COUNT
        or challenge.get("public_output_bits") != BLOCK_COUNT * 512
        or len(challenge.get("known_zeroed_key_words", [])) != 8
        or len(challenge.get("nonce_words", [])) != 3
        or len(challenge.get("target_words", [])) != BLOCK_COUNT
        or any(len(block) != 16 for block in challenge.get("target_words", []))
        or "assignment" in challenge
    ):
        raise RuntimeError("A423 public challenge shape differs")
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
        or [sha256(W43._word_bytes(block)) for block in targets] != challenge["target_block_sha256"]  # noqa: SLF001
        or control[0] != (targets[0][0] ^ 1)
        or control[1:] != targets[0][1:]
        or sha256(W43._word_bytes(control)) != challenge["control_target_block_sha256"]  # noqa: SLF001
    ):
        raise RuntimeError("A423 public challenge identity differs")


def fresh_challenge() -> dict[str, Any]:
    label = f"A423|fresh-W52-external-reader-transfer|{secrets.token_hex(32)}"
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
    return A421.exact_schedule(source)


def materialize_protocol(*, expected_implementation_sha256: str, expected_a420_protocol_sha256: str) -> dict[str, Any]:
    if not no_execution_artifacts():
        raise FileExistsError("A423 protocol or execution artifact already exists")
    if A420_RESULT.exists() or A421_RESULT.exists() or A422_QUALIFICATION.exists():
        raise RuntimeError("A423 fresh W52 challenge must precede narrower outcomes and A422 qualification")
    implementation = load_implementation(expected_implementation_sha256)
    source = A420.load_protocol(expected_a420_protocol_sha256)
    roles, orders, tasks = exact_schedule(source)
    challenge = fresh_challenge()
    public_sha = canonical_sha256(challenge)
    payload: dict[str, Any] = {
        "schema": "chacha20-round20-w52-external-reader-shared-stop-recovery-a423-protocol-v1",
        "attempt_id": ATTEMPT_ID,
        "protocol_state": "fresh_W52_challenge_and_byte_identical_A420_schedule_frozen_before_A422_qualification_or_any_narrower_recovery_result",
        "design_sha256": DESIGN_SHA256,
        "implementation_sha256": expected_implementation_sha256,
        "implementation_commitment_sha256": implementation["implementation_commitment_sha256"],
        "A422_protocol_sha256": A422_PROTOCOL_SHA256,
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
            "A420_schedule_frozen_before_W52_challenge": True,
            "A420_result_available_at_protocol_freeze": False,
            "A421_result_available_at_protocol_freeze": False,
            "A422_qualification_available_at_protocol_freeze": False,
            "A423_assignment_absent_from_protocol": True,
            "A423_candidate_or_progress_available_at_protocol_freeze": False,
            "W52_target_labels_used_for_schedule": 0,
            "W52_reader_refits": 0,
            "prior_live_recovery_filter_outcomes_consumed": False,
        },
        "anchors": {
            "design": anchor(DESIGN, DESIGN_SHA256),
            "implementation": anchor(IMPLEMENTATION, expected_implementation_sha256),
            "A422_protocol": anchor(A422_PROTOCOL, A422_PROTOCOL_SHA256),
            "source_A420_protocol": anchor(A420_PROTOCOL, expected_a420_protocol_sha256),
            "A421_shared_stop_runner": anchor(A421_RUNNER, A421_RUNNER_SHA256),
            "runner": anchor(Path(__file__)),
        },
    }
    payload["protocol_commitment_sha256"] = canonical_sha256(payload)
    atomic_json(PROTOCOL, payload)
    return payload


def load_protocol(expected_sha256: str | None = None) -> dict[str, Any]:
    if expected_sha256 is not None and file_sha256(PROTOCOL) != expected_sha256:
        raise RuntimeError("A423 protocol hash differs")
    value = json.loads(PROTOCOL.read_bytes())
    boundary = value.get("information_boundary", {})
    if (
        value.get("schema") != "chacha20-round20-w52-external-reader-shared-stop-recovery-a423-protocol-v1"
        or value.get("attempt_id") != ATTEMPT_ID
        or value.get("protocol_state")
        != "fresh_W52_challenge_and_byte_identical_A420_schedule_frozen_before_A422_qualification_or_any_narrower_recovery_result"
        or value.get("A422_protocol_sha256") != A422_PROTOCOL_SHA256
        or value.get("complete_cover_cells") != CELLS
        or value.get("duplicate_cells") != 0
        or value.get("uncovered_cells") != 0
        or value.get("workers") != WORKERS
        or value.get("worker_tasks_each") != STATIC_EPOCHS
        or value.get("candidates_per_complete_group") != GROUP_SIZE
        or value.get("complete_domain_assignments") != DOMAIN_SIZE
        or boundary.get("A420_result_available_at_protocol_freeze") is not False
        or boundary.get("A421_result_available_at_protocol_freeze") is not False
        or boundary.get("A422_qualification_available_at_protocol_freeze") is not False
        or boundary.get("A423_assignment_absent_from_protocol") is not True
        or boundary.get("W52_target_labels_used_for_schedule") != 0
        or canonical_sha256(value.get("public_challenge")) != value.get("public_challenge_sha256")
    ):
        raise RuntimeError("A423 protocol semantics differ")
    load_implementation(value["implementation_sha256"])
    source = A420.load_protocol(value["source_A420_protocol_sha256"])
    roles, orders, tasks = exact_schedule(value)
    source_roles, source_orders, source_tasks = exact_schedule(source)
    if roles != source_roles:
        raise RuntimeError("A423 source role order differs")
    for role in roles:
        if (
            orders[role] != source_orders[role]
            or tasks[role] != source_tasks[role]
            or A420.worker_order_sha256(orders[role]) != value["worker_order_uint16be_sha256"][role]
            or A420.task_list_sha256(tasks[role]) != value["worker_task_list_sha256"][role]
        ):
            raise RuntimeError(f"A423 byte-identical schedule transfer differs for {role}")
    for row in value["anchors"].values():
        anchor(ROOT / row["path"], row["sha256"])
    unsigned = {key: item for key, item in value.items() if key != "protocol_commitment_sha256"}
    if value.get("protocol_commitment_sha256") != canonical_sha256(unsigned):
        raise RuntimeError("A423 protocol commitment differs")
    validate_challenge(value["public_challenge"])
    return value


def load_a422_qualification(expected_sha256: str) -> dict[str, Any]:
    A422.load_protocol(A422_PROTOCOL_SHA256)
    if file_sha256(A422_QUALIFICATION) != expected_sha256:
        raise RuntimeError("A423 A422 qualification file hash differs")
    value = json.loads(A422_QUALIFICATION.read_bytes())
    group = value.get("complete_group_gate", {})
    unsigned = {
        "boundary_full_block_rows": value.get("boundary_full_block_rows"),
        "complete_group_gate": group,
        "expected_synthetic_assignment": value.get("expected_synthetic_assignment"),
        "source_executable_sha256": value.get("source_executable_sha256"),
        "A390_qualification_file_sha256": value.get("A390_qualification_file_sha256"),
        "production_W52_challenge_used": False,
    }
    if (
        value.get("schema") != "chacha20-round20-w52-fivehundredtwelve-slab-grouped-engine-a422-qualification-v1"
        or value.get("attempt_id") != "A422"
        or value.get("evidence_stage") != "TARGET_FREE_COMPLETE_W52_GROUP_ENGINE_EXACTLY_QUALIFIED"
        or value.get("protocol_sha256") != A422_PROTOCOL_SHA256
        or value.get("production_W52_challenge_used") is not False
        or value.get("production_W52_candidate_used") is not False
        or value.get("synthetic_filter_exact") is not True
        or value.get("matched_control_empty") is not True
        or group.get("logical_candidates") != GROUP_SIZE
        or group.get("complete_W52_group_before_outcome_evaluation") is not True
        or group.get("slabs_executed") != list(range(SLABS))
        or len(group.get("factual_candidates", [])) != 1
        or group.get("control_candidates") != []
        or value.get("qualification_sha256") != canonical_sha256(unsigned)
    ):
        raise RuntimeError("A423 A422 target-free qualification semantics differ")
    return value


class A422EngineFacade:
    """Exact W52 engine surface expected by A421's frozen shared-stop loop."""

    filter_complete_prefix = staticmethod(A422.filter_complete_prefix)

    @staticmethod
    def decode_assignment(assignment: int) -> dict[str, int]:
        decoded = A422.decode_assignment(assignment)
        return {**decoded, "word1_low19": decoded["word1_low20"]}


def configure_shared_stop_core() -> None:
    A421.A390 = A422EngineFacade
    A421.STOP = STOP
    A421.RESULT = RESULT
    A421.PROTOCOL = PROTOCOL
    A421.GROUP_SIZE = GROUP_SIZE
    A421.DOMAIN_SIZE = DOMAIN_SIZE
    A421.SLABS = SLABS
    A421.HOST_REFRESH_GROUPS = HOST_REFRESH_GROUPS
    A421.progress_path = progress_path


def ordered_worker_discovery(**kwargs: Any) -> dict[str, Any]:
    configure_shared_stop_core()
    value = A421.ordered_worker_discovery(**kwargs)
    if value.get("status") == "candidate_found":
        value["key_word1_low20"] = value.pop("key_word1_low19")
        value["complete_W52_group_execution_before_stop"] = value.pop(
            "complete_W51_group_execution_before_stop"
        )
    return value


def load_resume(
    *, worker_index: int, protocol_sha256: str, qualification_sha256: str, order_sha: str, tasks_sha: str
) -> tuple[int, float, int, dict[str, Any] | None]:
    path = progress_path(worker_index)
    if not path.exists():
        return 0, 0.0, 0, None
    value = json.loads(path.read_bytes())
    if (
        value.get("schema") != "chacha20-round20-w52-external-reader-shared-stop-recovery-a423-progress-v1"
        or value.get("attempt_id") != ATTEMPT_ID
        or value.get("worker_index") != worker_index
        or value.get("protocol_sha256") != protocol_sha256
        or value.get("A422_qualification_sha256") != qualification_sha256
        or value.get("worker_order_uint16be_sha256") != order_sha
        or value.get("worker_task_list_sha256") != tasks_sha
        or value.get("matched_control_candidates") != 0
    ):
        raise RuntimeError("A423 progress fingerprint differs")
    status = value.get("status")
    completed = int(value.get("executed_worker_prefix_groups", -1))
    factual = value.get("factual_filter_candidates")
    if (
        status not in {"running", "candidate_found", "worker_exhausted", "peer_confirmed"}
        or not 0 <= completed <= STATIC_EPOCHS
        or (status == "candidate_found" and (not isinstance(factual, list) or len(factual) != 1))
        or (status != "candidate_found" and factual != 0)
    ):
        raise RuntimeError("A423 resumable progress state differs")
    terminal = status in {"candidate_found", "worker_exhausted", "peer_confirmed"}
    return (
        completed,
        float(value.get("gpu_seconds", 0.0)),
        int(value.get("host_instances", 0)),
        dict(value) if terminal else None,
    )


def mark_peer_confirmed(qualification_sha256: str, worker_index: int) -> dict[str, Any]:
    path = progress_path(worker_index)
    if not path.exists():
        return {"status": "peer_confirmed", "worker_index": worker_index, "worker_was_not_started": True}
    value = json.loads(path.read_bytes())
    if (
        value.get("protocol_sha256") != file_sha256(PROTOCOL)
        or value.get("A422_qualification_sha256") != qualification_sha256
        or value.get("worker_index") != worker_index
    ):
        raise RuntimeError("A423 peer progress fingerprint differs")
    if value.get("status") not in {"running", "peer_confirmed", "worker_exhausted", "candidate_found"}:
        raise RuntimeError("A423 peer progress status differs")
    if value.get("status") in {"running", "peer_confirmed"}:
        value["status"] = "peer_confirmed"
        value["confirmed_stop_sha256"] = file_sha256(STOP)
        value["factual_filter_candidates"] = 0
        atomic_json(path, value)
    return {"status": "peer_confirmed", "worker_index": worker_index}


def progress_snapshot(protocol: Mapping[str, Any]) -> dict[str, Any]:
    configure_shared_stop_core()
    return A421.progress_snapshot(protocol)


def active_started_workers_terminal(protocol: Mapping[str, Any]) -> bool:
    configure_shared_stop_core()
    return A421.active_started_workers_terminal(protocol)


def build_causal(payload: Mapping[str, Any]) -> dict[str, Any]:
    if str(DOTCAUSAL_SRC) not in sys.path:
        sys.path.insert(0, str(DOTCAUSAL_SRC))
    from dotcausal.io import CausalReader, CausalWriter

    terminal = "confirmed_strict_subset_W52_recovery" if payload["aggregate_execution"]["strict_subset_of_complete_domain"] else "confirmed_complete_domain_W52_recovery"
    writer = CausalWriter(api_id="a423w52")
    writer._rules = []
    writer.add_rule(
        name="external_reader_schedule_and_exact_W52_engine_to_model",
        description="Execute the byte-identical externally selected eight-reader schedule as disjoint complete W52 groups with one confirmed shared stop.",
        pattern=["A423_frozen_fresh_W52_schedule", "A422_exact_W52_group_engine"],
        conclusion="A423_sole_factual_W52_model",
        confidence_modifier=1.0,
    )
    writer.add_rule(
        name="W52_model_to_confirmed_recovery",
        description="Require empty matched control and independent eight-block confirmation before retaining either strict-subset or complete-domain W52 recovery.",
        pattern=["A423_sole_factual_W52_model"],
        conclusion=f"A423_{terminal}",
        confidence_modifier=1.0,
    )
    writer.add_triplet(
        trigger="A423:frozen_fresh_W52_external_reader_schedule",
        mechanism="disjoint_complete_2^40_group_execution_with_confirmed_shared_stop",
        outcome="A423:sole_factual_W52_model",
        confidence=1.0,
        source=payload["execution_sha256"],
        quantification=json.dumps(payload["aggregate_execution"], sort_keys=True),
        evidence=json.dumps(payload["rank_analysis"], sort_keys=True),
        domain="full-round ChaCha20 W52 external Reader recovery",
        quality_score=1.0,
    )
    writer.add_triplet(
        trigger="A423:sole_factual_W52_model",
        mechanism="matched_control_rejection_and_dual_reference_eight_block_confirmation",
        outcome=f"A423:{terminal}",
        confidence=1.0,
        source=payload["measurement_sha256"],
        quantification=json.dumps(payload["confirmation"], sort_keys=True),
        evidence=payload["evidence_stage"],
        domain="confirmed full-round ChaCha20 W52 recovery",
        quality_score=1.0,
    )
    writer.add_triplet(
        trigger="A423:frozen_fresh_W52_external_reader_schedule",
        mechanism="materialized_external_reader_W52_search_and_confirmation_closure",
        outcome=f"A423:{terminal}",
        confidence=1.0,
        source="materialized:A423_external_reader_W52_recovery_chain",
        quantification="exact retained closure",
        evidence=payload["evidence_stage"],
        domain="AI-native retained inference",
        quality_score=1.0,
        is_inferred=True,
    )
    writer.add_cluster(
        name="A423 external Reader W52 recovery",
        entities=["A423:frozen_fresh_W52_external_reader_schedule", "A423:sole_factual_W52_model", f"A423:{terminal}"],
    )
    writer.add_gap(
        subject=f"A423:{terminal}",
        predicate="next_required_object",
        expected_object_type="W53_or_wider_external_reader_shared_stop_transfer",
        confidence=1.0,
        suggested_queries=["Qualify the next exact grouped-engine width and retain the frozen external Reader transfer boundary."],
    )
    temporary = CAUSAL.with_name(f".{CAUSAL.name}.tmp")
    temporary.unlink(missing_ok=True)
    stats = writer.save(str(temporary))
    os.replace(temporary, CAUSAL)
    reader = CausalReader(str(CAUSAL), verify_integrity=True)
    explicit = reader.get_all_triplets(include_inferred=False)
    all_rows = reader.get_all_triplets(include_inferred=True)
    inferred = [row for row in reader._triplets if row.get("is_inferred", False)]
    if reader.api_id != "a423w52" or len(explicit) != 2 or len(all_rows) != 3 or len(inferred) != 1 or len(reader._rules) != 2 or len(reader._clusters) != 1 or len(reader._gaps) != 1:
        raise RuntimeError("A423 authentic Causal reopen gate failed")
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
        stop.get("schema") != "chacha20-round20-w52-external-reader-shared-stop-recovery-a423-confirmed-stop-v1"
        or stop.get("attempt_id") != ATTEMPT_ID
        or stop.get("protocol_sha256") != file_sha256(PROTOCOL)
        or stop.get("A422_qualification_sha256") != qualification_sha256
        or stop.get("confirmation", {}).get("all_blocks_match") is not True
        or stop.get("discovery", {}).get("control_filter_candidates") != []
    ):
        raise RuntimeError("A423 confirmed stop fingerprint differs")
    while not active_started_workers_terminal(protocol):
        time.sleep(5)
    aggregate = progress_snapshot(protocol)
    unique_groups = int(aggregate["total_unique_prefix_groups_evaluated"])
    if not 1 <= unique_groups <= CELLS:
        raise RuntimeError("A423 aggregate unique group count differs")
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
        "FULLROUND_R20_EXTERNAL_READER_W52_STRICT_SUBSET_RECOVERY_CONFIRMED"
        if strict_subset
        else "FULLROUND_R20_EXTERNAL_READER_W52_COMPLETE_DOMAIN_RECOVERY_CONFIRMED"
    )
    payload: dict[str, Any] = {
        "schema": "chacha20-round20-w52-external-reader-shared-stop-recovery-a423-result-v1",
        "attempt_id": ATTEMPT_ID,
        "evidence_stage": evidence_stage,
        "design_sha256": DESIGN_SHA256,
        "implementation_sha256": protocol["implementation_sha256"],
        "implementation_commitment_sha256": protocol["implementation_commitment_sha256"],
        "protocol_sha256": file_sha256(PROTOCOL),
        "protocol_commitment_sha256": protocol["protocol_commitment_sha256"],
        "A422_qualification_sha256": qualification_sha256,
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
        "prior_narrower_public_assignment_bits_reused": False,
        "prior_live_recovery_filter_outcomes_consumed": False,
        "execution_sha256": canonical_sha256({"discovery": discovery, "aggregate_execution": aggregate, "rank_analysis": rank_analysis}),
        "measurement_sha256": canonical_sha256({"confirmation": stop["confirmation"], "matched_control_candidates": 0}),
        "anchors": {
            "design": anchor(DESIGN, DESIGN_SHA256),
            "implementation": anchor(IMPLEMENTATION, protocol["implementation_sha256"]),
            "protocol": anchor(PROTOCOL, file_sha256(PROTOCOL)),
            "confirmed_stop": anchor(STOP, file_sha256(STOP)),
            "A422_qualification": anchor(A422_QUALIFICATION, qualification_sha256),
            "source_A420_protocol": anchor(A420_PROTOCOL, protocol["source_A420_protocol_sha256"]),
            "A421_shared_stop_runner": anchor(A421_RUNNER, A421_RUNNER_SHA256),
            "runner": anchor(Path(__file__)),
        },
    }
    payload["causal"] = build_causal(payload)
    atomic_json(RESULT, payload)
    atomic_bytes(
        REPORT,
        (
            "# A423 — External Reader full-round ChaCha20 W52 recovery\n\n"
            f"Evidence stage: **{evidence_stage}**\n\n"
            f"- Externally selected schedule: **{protocol['source_A420_selected_attempt_id']} via A420**\n"
            f"- Exact unique W52 groups evaluated: **{unique_groups} / 4096**\n"
            f"- Complete assignments evaluated: **{aggregate['total_unique_assignments_evaluated']:,} / {DOMAIN_SIZE:,}**\n"
            f"- Search gain: **{aggregate['search_gain_bits']:.9f} bits**\n"
            "- Factual / matched-control candidates: **1 / 0**\n"
            "- Independent confirmation: **two implementations, eight blocks, 8,192 checked output bits**\n"
            "- Authentic AI-native Causal readback: **2 explicit + 1 inferred chain**\n"
        ).encode(),
    )
    return payload


def recover_worker(*, worker_index: int, expected_protocol_sha256: str, expected_a422_qualification_sha256: str) -> dict[str, Any]:
    if RESULT.exists():
        return {"status": "peer_confirmed", "result_sha256": file_sha256(RESULT)}
    protocol = load_protocol(expected_protocol_sha256)
    load_a422_qualification(expected_a422_qualification_sha256)
    if STOP.exists():
        stop = json.loads(STOP.read_bytes())
        if int(stop.get("worker_index", -1)) == worker_index:
            return finalize_confirmed_stop(protocol, expected_a422_qualification_sha256)
        return mark_peer_confirmed(expected_a422_qualification_sha256, worker_index)
    roles = protocol["worker_roles"]
    role = roles[worker_index]
    order, tasks = A420.exact_worker_schedule(
        worker_index=worker_index,
        worker_role=role,
        values=protocol["worker_cell_orders"][role],
        tasks=protocol["worker_tasks"][role],
        roles=roles,
    )
    engine_protocol = A422.load_protocol(A422_PROTOCOL_SHA256)
    executable_row = engine_protocol["anchors"]["grouped_executable"]
    executable = path_from_ref(executable_row["path"])
    anchor(executable, executable_row["sha256"])
    challenge = protocol["public_challenge"]
    placeholder = np.asarray([0, 0], dtype=np.uint32)

    def host_factory() -> Any:
        return A422.A390.A384.A378.A371.A346.A324.A311.A307.A304.GroupedMetalHost(
            executable, A422.initial_for_slab(challenge, 0), placeholder, placeholder
        )

    order_sha = protocol["worker_order_uint16be_sha256"][role]
    tasks_sha = protocol["worker_task_list_sha256"][role]

    def write_progress(row: Mapping[str, Any]) -> None:
        atomic_json(
            progress_path(worker_index),
            {
                "schema": "chacha20-round20-w52-external-reader-shared-stop-recovery-a423-progress-v1",
                "attempt_id": ATTEMPT_ID,
                "worker_index": worker_index,
                "worker_role": role,
                "protocol_sha256": expected_protocol_sha256,
                "A422_qualification_sha256": expected_a422_qualification_sha256,
                "worker_order_uint16be_sha256": order_sha,
                "worker_task_list_sha256": tasks_sha,
                "matched_control_candidates": 0,
                **dict(row),
            },
        )

    start, prior_gpu, prior_hosts, completed = load_resume(
        worker_index=worker_index,
        protocol_sha256=expected_protocol_sha256,
        qualification_sha256=expected_a422_qualification_sha256,
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
                expected_a422_qualification_sha256=expected_a422_qualification_sha256,
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
                raise RuntimeError("A423 all disjoint workers exhausted without a model")
        return discovery
    candidate = int(discovery["candidate"])
    confirmation = confirm(challenge, candidate)
    if confirmation.get("all_blocks_match") is not True:
        raise RuntimeError("A423 dual-reference eight-block confirmation failed")
    if discovery.get("control_filter_candidates") != []:
        raise RuntimeError("A423 matched control produced a candidate")
    atomic_json(
        STOP,
        {
            "schema": "chacha20-round20-w52-external-reader-shared-stop-recovery-a423-confirmed-stop-v1",
            "attempt_id": ATTEMPT_ID,
            "protocol_sha256": expected_protocol_sha256,
            "A422_qualification_sha256": expected_a422_qualification_sha256,
            "worker_index": worker_index,
            "worker_role": role,
            "discovery": discovery,
            "confirmation": confirmation,
        },
    )
    return finalize_confirmed_stop(protocol, expected_a422_qualification_sha256)


def analyze() -> dict[str, Any]:
    payload: dict[str, Any] = {
        "attempt_id": ATTEMPT_ID,
        "design_sha256": DESIGN_SHA256,
        "implementation_frozen": IMPLEMENTATION.exists(),
        "A422_qualification_complete": A422_QUALIFICATION.exists(),
        "A420_protocol_available": A420_PROTOCOL.exists(),
        "A420_result_available": A420_RESULT.exists(),
        "A421_result_available": A421_RESULT.exists(),
        "protocol_frozen": PROTOCOL.exists(),
        "confirmed_stop_available": STOP.exists(),
        "result_complete": RESULT.exists(),
        "candidate_group_size": GROUP_SIZE,
        "complete_domain_assignments": DOMAIN_SIZE,
    }
    if IMPLEMENTATION.exists():
        payload["implementation_sha256"] = file_sha256(IMPLEMENTATION)
        load_implementation(payload["implementation_sha256"])
    if A422_QUALIFICATION.exists():
        payload["A422_qualification_sha256"] = file_sha256(A422_QUALIFICATION)
        load_a422_qualification(payload["A422_qualification_sha256"])
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
    parser.add_argument("--expected-a422-qualification-sha256")
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
        if not args.expected_protocol_sha256 or not args.expected_a422_qualification_sha256:
            parser.error("--recover-worker requires protocol and A422 qualification hashes")
        payload = recover_worker(
            worker_index=args.recover_worker,
            expected_protocol_sha256=args.expected_protocol_sha256,
            expected_a422_qualification_sha256=args.expected_a422_qualification_sha256,
        )
    else:
        payload = analyze()
    print(json.dumps(payload, indent=2, sort_keys=True), flush=True)


if __name__ == "__main__":
    main()

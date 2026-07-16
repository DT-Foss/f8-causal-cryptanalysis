#!/usr/bin/env python3
"""A425: execute the qualified A416 schedule on a fresh W51 challenge."""

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

STEM = "chacha20_round20_w51_a416_fresh_shared_stop_recovery_a425"
DESIGN = CONFIGS / f"{STEM}_design_v1.json"
IMPLEMENTATION = CONFIGS / f"{STEM}_implementation_v1.json"
PROTOCOL = CONFIGS / f"{STEM}_v1.json"
RESULT = RESULTS / f"{STEM}_v1.json"
STOP = RESULTS / f"{STEM}_confirmed_stop_v1.json"
CAUSAL = RESULT.with_suffix(".causal")
REPORT = RESULT.with_suffix(".md")
TEST = ROOT / f"tests/test_{STEM}.py"
REPRO = ROOT / f"scripts/reproduce_{STEM}.sh"

A416_RESULT = RESULTS / "chacha20_round20_w50_folded_xor_portfolio_a416_v1.json"
A416_DESIGN = CONFIGS / "chacha20_round20_w50_folded_xor_portfolio_a416_design_v1.json"
A416_IMPLEMENTATION = CONFIGS / "chacha20_round20_w50_folded_xor_portfolio_a416_implementation_v1.json"
A416_MODEL = CONFIGS / "chacha20_round20_w50_folded_xor_portfolio_a416_model_v1.json"
A416_RUNNER = RESEARCH / "experiments/chacha20_round20_w50_folded_xor_portfolio_a416.py"
A390_PROTOCOL = CONFIGS / "chacha20_round20_w51_twohundredfiftysix_slab_grouped_engine_a390_v1.json"
A390_QUALIFICATION = RESULTS / "chacha20_round20_w51_twohundredfiftysix_slab_grouped_engine_a390_qualification_v1.json"
A390_RUNNER = RESEARCH / "experiments/chacha20_round20_w51_twohundredfiftysix_slab_grouped_engine_a390.py"

ATTEMPT_ID = "A425"
DESIGN_SHA256 = "797307788a9fe80985afb47256f41c95d7d83fe16f224b033602839152c9a89a"
A416_RESULT_SHA256 = "7623bd8d1a11d00c771e8aa24e2e3847dafe92ebbfffa34e761434a09a24b686"
A416_DESIGN_SHA256 = "c73166ba4a4f1103555fa6d18cf44e427127fa0ebcaefdbd2a26629d1c64ab5f"
A416_IMPLEMENTATION_SHA256 = "b99b3626efa18655dda2aafb3f0cb78cb8f744e93c131f1a471ec7fc9ce83dd2"
A416_MODEL_SHA256 = "ed927419a04f39f16ffb2679ff51544a43288821744cf2558cd97e45e45a6c58"
A416_RUNNER_SHA256 = "6d4f3e144d4d2c7a689b1b4808537379e96091ca5d106ac4cbc00d20d378ce76"
A390_PROTOCOL_SHA256 = "d13d5c0b34de900bdc2d3abe26706b508091685e6a1c7a640168ab5496e479d0"
A390_RUNNER_SHA256 = "1864f7ecd5fb448219784b1a9e514cfddfb3f77f16e46f0d6104f8a778338330"

WIDTH = 51
PREFIX_BITS = 12
WORD0_SUFFIX_BITS = 20
WORD1_LOW_BITS = 19
WORD1_KNOWN_MASK = 0xFFF80000
KNOWN_KEY_BITS = 256 - WIDTH
CELLS = 1 << PREFIX_BITS
WORKERS = 8
STATIC_EPOCHS = CELLS // WORKERS
GROUP_SIZE = 1 << (WIDTH - PREFIX_BITS)
DOMAIN_SIZE = 1 << WIDTH
SLABS = 256
HOST_REFRESH_GROUPS = 2
BLOCK_COUNT = 8
MASK32 = 0xFFFFFFFF
DOTCAUSAL_SRC = Path("/Users/bhkmie/Documents/Forschung/O1/vendor/fabel/dotcausal_package/src")


def load_module(path: Path, name: str) -> Any:
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot import A425 dependency {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


A390 = load_module(A390_RUNNER, "a425_a390")
W43 = A390.W43
file_sha256 = A390.file_sha256
canonical_sha256 = A390.canonical_sha256
atomic_json = A390.atomic_json
relative = A390.relative
anchor = A390.anchor
path_from_ref = A390.path_from_ref


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def atomic_bytes(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    temporary.write_bytes(data)
    os.replace(temporary, path)


def progress_path(worker_index: int) -> Path:
    if not 0 <= worker_index < WORKERS:
        raise ValueError("A425 worker index differs")
    return RESULTS / f"{STEM}_worker_{worker_index}_progress_v1.json"


def no_execution_artifacts() -> bool:
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
        raise RuntimeError("A425 design hash differs")
    value = json.loads(DESIGN.read_bytes())
    execution = value.get("execution_contract", {})
    transfer = value.get("schedule_transfer_contract", {})
    fresh = value.get("fresh_challenge_contract", {})
    boundary = value.get("information_boundary", {})
    if (
        value.get("schema")
        != "chacha20-round20-w51-a416-fresh-shared-stop-recovery-a425-design-v1"
        or value.get("attempt_id") != ATTEMPT_ID
        or value.get("design_state")
        != "frozen_after_A416_external_qualification_and_A390_target_free_protocol_before_A390_qualification_any_A424_outcome_or_any_A425_challenge_assignment_candidate_progress_or_filter_outcome"
        or execution.get("full_rounds") != 20
        or execution.get("feedforward_included") is not True
        or execution.get("unknown_key_bits") != WIDTH
        or execution.get("known_key_bits") != KNOWN_KEY_BITS
        or execution.get("complete_prefix_groups") != CELLS
        or execution.get("candidates_per_prefix_group") != GROUP_SIZE
        or execution.get("complete_domain_assignments") != DOMAIN_SIZE
        or execution.get("slabs_per_prefix_group") != SLABS
        or execution.get("workers") != WORKERS
        or execution.get("worker_tasks_each") != STATIC_EPOCHS
        or execution.get("complete_group_before_success_evaluation") is not True
        or execution.get("shared_stop_only_after_independent_confirmation") is not True
        or transfer.get("source_external_holdout_qualified") is not True
        or transfer.get("copy_all_eight_worker_orders_and_tasks_byte_identically") is not True
        or transfer.get("parameter_refit_on_A425_target") is not False
        or fresh.get("materialize_only_after_complete_A425_implementation_freeze") is not True
        or fresh.get("secret_assignment_absent_from_protocol") is not True
        or boundary.get("A416_result_available_at_A425_design_freeze") is not True
        or boundary.get("A390_qualification_available_at_A425_design_freeze") is not False
        or boundary.get("A424_result_available_at_A425_design_freeze") is not False
        or boundary.get("A425_production_challenge_available_at_design_freeze") is not False
        or boundary.get("A425_target_assignment_available_at_design_freeze") is not False
        or boundary.get("A425_candidate_or_progress_available_at_design_freeze") is not False
        or boundary.get("A425_target_labels_used_for_schedule") != 0
        or boundary.get("prior_live_recovery_filter_outcomes_consumed") is not False
    ):
        raise RuntimeError("A425 frozen design semantics differ")
    sources = value["source_anchors"]
    for key, item in sources.items():
        if key.endswith("_path"):
            stem = key.removesuffix("_path")
            anchor(ROOT / item, sources[f"{stem}_sha256"])
    return value


def validate_worker_schedule(
    *,
    worker_index: int,
    worker_role: str,
    values: Sequence[int],
    tasks: Sequence[Mapping[str, Any]],
    roles: Sequence[str],
) -> tuple[list[int], list[dict[str, Any]]]:
    if not 0 <= worker_index < WORKERS or roles[worker_index] != worker_role:
        raise ValueError("A425 worker identity differs")
    order = [int(value) for value in values]
    rows = [dict(value) for value in tasks]
    if (
        len(order) != STATIC_EPOCHS
        or len(rows) != STATIC_EPOCHS
        or len(set(order)) != STATIC_EPOCHS
        or any(not 0 <= cell < CELLS for cell in order)
    ):
        raise ValueError("A425 worker schedule geometry differs")
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
            raise ValueError(
                f"A425 task semantics differ at worker {worker_index} step {step}"
            )
    return order, rows


def worker_order_sha256(values: Sequence[int]) -> str:
    array = np.asarray([int(value) for value in values], dtype=">u2")
    return sha256(array.tobytes())


def task_list_sha256(values: Sequence[Mapping[str, Any]]) -> str:
    return canonical_sha256([dict(value) for value in values])


def load_a416_schedule() -> tuple[
    dict[str, Any], list[str], dict[str, list[int]], dict[str, list[dict[str, Any]]]
]:
    if file_sha256(A416_RESULT) != A416_RESULT_SHA256:
        raise RuntimeError("A425 A416 result hash differs")
    value = json.loads(A416_RESULT.read_bytes())
    external = value.get("external_transfer", {})
    proof = value.get("schedule_proof", {})
    roles = [str(role) for role in value.get("source_role_order", [])]
    raw_orders = value.get("worker_cell_orders", {})
    raw_tasks = value.get("worker_tasks", {})
    if (
        value.get("schema")
        != "chacha20-round20-w50-folded-xor-portfolio-a416-result-v1"
        or value.get("attempt_id") != "A416"
        or value.get("evidence_stage")
        != "UNTOUCHED_HOLDOUT_QUALIFIED_SINGLE_WORKER_FOLD_OPTIMAL_SCHEDULER"
        or value.get("production_execution_enabled") is not True
        or external.get("qualified") is not True
        or value.get("production_target_labels_used") != 0
        or value.get("external_reader_refits") != 0
        or value.get("production_candidate_assignments_executed") != 0
        or value.get("target_specific_polarity_choices") != 0
        or len(roles) != WORKERS
        or len(set(roles)) != WORKERS
        or set(raw_orders) != set(roles)
        or set(raw_tasks) != set(roles)
        or proof.get("complete_cover_cells") != CELLS
        or proof.get("duplicate_cells") != 0
        or proof.get("uncovered_cells") != 0
        or proof.get("owner_queue_order_preservation_violations") != 0
        or proof.get("depth_bound_violations") != 0
        or proof.get("total_work_bound_violations") != 0
        or proof.get("makespan_epochs") != STATIC_EPOCHS
        or proof.get("makespan_optimal") is not True
    ):
        raise RuntimeError("A425 A416 source semantics differ")
    orders: dict[str, list[int]] = {}
    tasks: dict[str, list[dict[str, Any]]] = {}
    for index, role in enumerate(roles):
        orders[role], tasks[role] = validate_worker_schedule(
            worker_index=index,
            worker_role=role,
            values=raw_orders[role],
            tasks=raw_tasks[role],
            roles=roles,
        )
    flat = [cell for role in roles for cell in orders[role]]
    if len(flat) != CELLS or len(set(flat)) != CELLS or set(flat) != set(range(CELLS)):
        raise RuntimeError("A425 A416 schedule cover differs")
    return value, roles, orders, tasks


def load_a390_qualification(expected_sha256: str) -> dict[str, Any]:
    if file_sha256(A390_QUALIFICATION) != expected_sha256:
        raise RuntimeError("A425 A390 qualification artifact hash differs")
    value = json.loads(A390_QUALIFICATION.read_bytes())
    group = value.get("complete_group_gate", {})
    if (
        value.get("schema")
        != "chacha20-round20-w51-twohundredfiftysix-slab-grouped-engine-a390-qualification-v1"
        or value.get("attempt_id") != "A390"
        or value.get("evidence_stage")
        != "TARGET_FREE_COMPLETE_W51_GROUP_ENGINE_EXACTLY_QUALIFIED"
        or value.get("protocol_sha256") != A390_PROTOCOL_SHA256
        or value.get("production_W51_challenge_used") is not False
        or value.get("production_W51_candidate_used") is not False
        or value.get("synthetic_filter_exact") is not True
        or value.get("matched_control_empty") is not True
        or group.get("logical_candidates") != GROUP_SIZE
        or group.get("complete_W51_group_before_outcome_evaluation") is not True
        or len(group.get("factual_candidates", [])) != 1
        or group.get("control_candidates") != []
    ):
        raise RuntimeError("A425 A390 qualification semantics differ")
    return value


def freeze_implementation() -> dict[str, Any]:
    if IMPLEMENTATION.exists() or not no_execution_artifacts():
        raise FileExistsError("A425 implementation or downstream artifact already exists")
    design = load_design()
    _source, roles, orders, tasks = load_a416_schedule()
    if A390_QUALIFICATION.exists():
        raise RuntimeError("A425 implementation freeze must precede A390 qualification")
    if not TEST.exists() or not REPRO.exists():
        raise FileNotFoundError("A425 test and reproducer must precede implementation freeze")
    payload: dict[str, Any] = {
        "schema": "chacha20-round20-w51-a416-fresh-shared-stop-recovery-a425-implementation-v1",
        "attempt_id": ATTEMPT_ID,
        "commitment_state": "complete_A416_schedule_executor_and_fresh_W51_challenge_factory_frozen_before_any_A425_challenge_assignment_candidate_or_progress",
        "design_sha256": DESIGN_SHA256,
        "execution_contract": design["execution_contract"],
        "schedule_transfer_contract": design["schedule_transfer_contract"],
        "fresh_challenge_contract": design["fresh_challenge_contract"],
        "source_A416_result_sha256": A416_RESULT_SHA256,
        "source_A416_worker_roles": roles,
        "source_A416_schedule_sha256": canonical_sha256(
            {"roles": roles, "orders": orders, "tasks": tasks}
        ),
        "A390_qualification_available_at_freeze": False,
        "A425_challenge_or_assignment_available_at_freeze": False,
        "A425_candidate_or_progress_available_at_freeze": False,
        "production_target_labels_used": 0,
        "production_reader_refits": 0,
        "prior_live_recovery_filter_outcomes_consumed": False,
        "anchors": {
            "design": anchor(DESIGN, DESIGN_SHA256),
            "A416_result": anchor(A416_RESULT, A416_RESULT_SHA256),
            "A416_design": anchor(A416_DESIGN, A416_DESIGN_SHA256),
            "A416_implementation": anchor(
                A416_IMPLEMENTATION, A416_IMPLEMENTATION_SHA256
            ),
            "A416_model": anchor(A416_MODEL, A416_MODEL_SHA256),
            "A416_runner": anchor(A416_RUNNER, A416_RUNNER_SHA256),
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


def load_implementation(expected_sha256: str | None = None) -> dict[str, Any]:
    if expected_sha256 is not None and file_sha256(IMPLEMENTATION) != expected_sha256:
        raise RuntimeError("A425 implementation hash differs")
    value = json.loads(IMPLEMENTATION.read_bytes())
    if (
        value.get("schema")
        != "chacha20-round20-w51-a416-fresh-shared-stop-recovery-a425-implementation-v1"
        or value.get("attempt_id") != ATTEMPT_ID
        or value.get("commitment_state")
        != "complete_A416_schedule_executor_and_fresh_W51_challenge_factory_frozen_before_any_A425_challenge_assignment_candidate_or_progress"
        or value.get("design_sha256") != DESIGN_SHA256
        or value.get("source_A416_result_sha256") != A416_RESULT_SHA256
        or value.get("A390_qualification_available_at_freeze") is not False
        or value.get("A425_challenge_or_assignment_available_at_freeze") is not False
        or value.get("A425_candidate_or_progress_available_at_freeze") is not False
        or value.get("production_target_labels_used") != 0
        or value.get("production_reader_refits") != 0
        or value.get("prior_live_recovery_filter_outcomes_consumed") is not False
    ):
        raise RuntimeError("A425 implementation semantics differ")
    for row in value["anchors"].values():
        anchor(ROOT / row["path"], row["sha256"])
    unsigned = {
        key: item
        for key, item in value.items()
        if key != "implementation_commitment_sha256"
    }
    if value.get("implementation_commitment_sha256") != canonical_sha256(unsigned):
        raise RuntimeError("A425 implementation commitment differs")
    return value


def apply_assignment(
    known_zeroed_key_words: Sequence[int], assignment: int
) -> list[int]:
    if len(known_zeroed_key_words) != 8:
        raise ValueError("A425 requires eight ChaCha20 key words")
    if not 0 <= assignment < DOMAIN_SIZE:
        raise ValueError("A425 assignment exceeds W51")
    key = [int(word) & MASK32 for word in known_zeroed_key_words]
    if key[0] != 0 or key[1] & ((1 << WORD1_LOW_BITS) - 1):
        raise ValueError("A425 known key does not zero the W51 interval")
    key[0] = assignment & MASK32
    key[1] |= assignment >> 32
    return key


def challenge_from_assignment(*, label: str, assignment: int) -> dict[str, Any]:
    if not 0 <= assignment < DOMAIN_SIZE:
        raise ValueError("A425 assignment exceeds W51")
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
        "challenge_id": "chacha20-r20-w51-a425-fresh-a416-transfer-v1",
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
        != "chacha20-r20-w51-a425-fresh-a416-transfer-v1"
        or challenge.get("primitive") != "RFC8439_ChaCha20_block_function"
        or challenge.get("rounds") != 20
        or challenge.get("feedforward") is not True
        or challenge.get("known_key_bits") != KNOWN_KEY_BITS
        or challenge.get("unknown_key_bits") != WIDTH
        or challenge.get("unknown_layout")
        != "key_word0_all32_plus_key_word1_low19"
        or challenge.get("unknown_assignment_included") is not False
        or challenge.get("public_output_blocks") != BLOCK_COUNT
        or challenge.get("public_output_bits") != BLOCK_COUNT * 512
        or len(challenge.get("known_zeroed_key_words", [])) != 8
        or len(challenge.get("nonce_words", [])) != 3
        or len(challenge.get("target_words", [])) != BLOCK_COUNT
        or any(len(block) != 16 for block in challenge.get("target_words", []))
        or "assignment" in challenge
    ):
        raise RuntimeError("A425 public challenge shape differs")
    label = str(challenge["known_material_derivation_label"])
    derived = hashlib.shake_256(label.encode()).digest(48)
    words = [int(value) for value in W43._words(derived)]  # noqa: SLF001
    expected_known = words[:8]
    expected_known[0] = 0
    expected_known[1] &= WORD1_KNOWN_MASK
    targets = [
        [int(word) & MASK32 for word in block]
        for block in challenge["target_words"]
    ]
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
        raise RuntimeError("A425 public challenge identity differs")


def fresh_challenge() -> dict[str, Any]:
    label = f"A425|fresh-W51-A416-transfer|{secrets.token_hex(32)}"
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
    byte_matches = [
        left == right
        for left, right in zip(byte_outputs, target_words, strict=True)
    ]
    word_matches = [
        left == right
        for left, right in zip(word_outputs, target_words, strict=True)
    ]
    return {
        "assignment": assignment,
        "recovered_key_words": key_words,
        "recovered_key_words_hex": [f"{word:08x}" for word in key_words],
        "byte_reference_block_matches": byte_matches,
        "word_reference_block_matches": word_matches,
        "all_blocks_match": all(byte_matches) and all(word_matches),
        "output_bits_checked_per_reference": BLOCK_COUNT * 512,
        "total_cross_implementation_output_bits_checked": BLOCK_COUNT * 512 * 2,
        "byte_reference_sha256": [
            sha256(W43._word_bytes(block)) for block in byte_outputs  # noqa: SLF001
        ],
        "word_reference_sha256": [
            sha256(W43._word_bytes(block)) for block in word_outputs  # noqa: SLF001
        ],
    }


def materialize_protocol(
    *,
    expected_implementation_sha256: str,
    expected_a416_result_sha256: str,
) -> dict[str, Any]:
    if not no_execution_artifacts():
        raise FileExistsError("A425 protocol or execution artifact already exists")
    if expected_a416_result_sha256 != A416_RESULT_SHA256:
        raise RuntimeError("A425 expected A416 result hash differs")
    implementation = load_implementation(expected_implementation_sha256)
    _source, roles, orders, tasks = load_a416_schedule()
    if A390_QUALIFICATION.exists():
        raise RuntimeError("A425 protocol must precede A390 qualification")
    challenge = fresh_challenge()
    public_sha = canonical_sha256(challenge)
    schedule_sha = canonical_sha256(
        {"roles": roles, "orders": orders, "tasks": tasks}
    )
    if schedule_sha != implementation["source_A416_schedule_sha256"]:
        raise RuntimeError("A425 source schedule changed after implementation freeze")
    payload: dict[str, Any] = {
        "schema": "chacha20-round20-w51-a416-fresh-shared-stop-recovery-a425-protocol-v1",
        "attempt_id": ATTEMPT_ID,
        "protocol_state": "fresh_W51_challenge_and_byte_identical_A416_schedule_frozen_before_A390_qualification_any_A424_outcome_or_any_A425_candidate_progress_or_filter_outcome",
        "design_sha256": DESIGN_SHA256,
        "implementation_sha256": expected_implementation_sha256,
        "implementation_commitment_sha256": implementation[
            "implementation_commitment_sha256"
        ],
        "source_A416_result_sha256": expected_a416_result_sha256,
        "A390_protocol_sha256": A390_PROTOCOL_SHA256,
        "A390_qualification_available_at_protocol_freeze": False,
        "worker_roles": roles,
        "worker_cell_orders": orders,
        "worker_tasks": tasks,
        "worker_order_uint16be_sha256": {
            role: worker_order_sha256(orders[role]) for role in roles
        },
        "worker_task_list_sha256": {
            role: task_list_sha256(tasks[role]) for role in roles
        },
        "schedule_sha256": schedule_sha,
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
            "A416_schedule_frozen_before_A425_challenge": True,
            "A390_qualification_available_at_A425_protocol_freeze": False,
            "A424_result_available_at_A425_protocol_freeze": False,
            "A425_assignment_absent_from_protocol": True,
            "A425_candidate_or_progress_available_at_protocol_freeze": False,
            "A425_target_labels_used_for_schedule": 0,
            "A425_reader_refits": 0,
            "prior_live_recovery_filter_outcomes_consumed": False,
        },
        "anchors": {
            "design": anchor(DESIGN, DESIGN_SHA256),
            "implementation": anchor(
                IMPLEMENTATION, expected_implementation_sha256
            ),
            "source_A416_result": anchor(
                A416_RESULT, expected_a416_result_sha256
            ),
            "A390_protocol": anchor(A390_PROTOCOL, A390_PROTOCOL_SHA256),
            "runner": anchor(Path(__file__)),
        },
    }
    payload["protocol_commitment_sha256"] = canonical_sha256(payload)
    atomic_json(PROTOCOL, payload)
    return payload


def load_protocol(expected_sha256: str | None = None) -> dict[str, Any]:
    if expected_sha256 is not None and file_sha256(PROTOCOL) != expected_sha256:
        raise RuntimeError("A425 protocol hash differs")
    value = json.loads(PROTOCOL.read_bytes())
    boundary = value.get("information_boundary", {})
    if (
        value.get("schema")
        != "chacha20-round20-w51-a416-fresh-shared-stop-recovery-a425-protocol-v1"
        or value.get("attempt_id") != ATTEMPT_ID
        or value.get("protocol_state")
        != "fresh_W51_challenge_and_byte_identical_A416_schedule_frozen_before_A390_qualification_any_A424_outcome_or_any_A425_candidate_progress_or_filter_outcome"
        or value.get("design_sha256") != DESIGN_SHA256
        or value.get("source_A416_result_sha256") != A416_RESULT_SHA256
        or value.get("A390_protocol_sha256") != A390_PROTOCOL_SHA256
        or value.get("A390_qualification_available_at_protocol_freeze") is not False
        or value.get("complete_cover_cells") != CELLS
        or value.get("duplicate_cells") != 0
        or value.get("uncovered_cells") != 0
        or value.get("workers") != WORKERS
        or value.get("worker_tasks_each") != STATIC_EPOCHS
        or value.get("candidates_per_complete_group") != GROUP_SIZE
        or value.get("complete_domain_assignments") != DOMAIN_SIZE
        or boundary.get("A425_assignment_absent_from_protocol") is not True
        or boundary.get("A425_candidate_or_progress_available_at_protocol_freeze")
        is not False
        or boundary.get("A425_target_labels_used_for_schedule") != 0
        or boundary.get("A425_reader_refits") != 0
        or boundary.get("A390_qualification_available_at_A425_protocol_freeze") is not False
        or boundary.get("A424_result_available_at_A425_protocol_freeze") is not False
    ):
        raise RuntimeError("A425 protocol semantics differ")
    for row in value["anchors"].values():
        anchor(ROOT / row["path"], row["sha256"])
    validate_challenge(value["public_challenge"])
    if canonical_sha256(value["public_challenge"]) != value["public_challenge_sha256"]:
        raise RuntimeError("A425 public challenge commitment differs")
    _source, roles, source_orders, source_tasks = load_a416_schedule()
    if value["worker_roles"] != roles:
        raise RuntimeError("A425 worker role transfer differs")
    orders: dict[str, list[int]] = {}
    tasks: dict[str, list[dict[str, Any]]] = {}
    for index, role in enumerate(roles):
        orders[role], tasks[role] = validate_worker_schedule(
            worker_index=index,
            worker_role=role,
            values=value["worker_cell_orders"][role],
            tasks=value["worker_tasks"][role],
            roles=roles,
        )
        if orders[role] != source_orders[role] or tasks[role] != source_tasks[role]:
            raise RuntimeError("A425 byte-identical A416 transfer differs")
        if worker_order_sha256(orders[role]) != value[
            "worker_order_uint16be_sha256"
        ][role]:
            raise RuntimeError("A425 worker order commitment differs")
        if task_list_sha256(tasks[role]) != value["worker_task_list_sha256"][role]:
            raise RuntimeError("A425 task commitment differs")
    schedule_sha = canonical_sha256(
        {"roles": roles, "orders": orders, "tasks": tasks}
    )
    if schedule_sha != value["schedule_sha256"]:
        raise RuntimeError("A425 schedule commitment differs")
    unsigned = {
        key: item
        for key, item in value.items()
        if key != "protocol_commitment_sha256"
    }
    if value.get("protocol_commitment_sha256") != canonical_sha256(unsigned):
        raise RuntimeError("A425 protocol commitment differs")
    load_implementation(value["implementation_sha256"])
    return value


def load_resume(
    *,
    worker_index: int,
    protocol_sha256: str,
    qualification_sha256: str,
    order_sha: str,
    tasks_sha: str,
) -> tuple[int, float, int, dict[str, Any] | None]:
    path = progress_path(worker_index)
    if not path.exists():
        return 0, 0.0, 0, None
    value = json.loads(path.read_bytes())
    if (
        value.get("schema")
        != "chacha20-round20-w51-a416-fresh-shared-stop-recovery-a425-progress-v1"
        or value.get("attempt_id") != ATTEMPT_ID
        or value.get("worker_index") != worker_index
        or value.get("protocol_sha256") != protocol_sha256
        or value.get("A390_qualification_sha256") != qualification_sha256
        or value.get("worker_order_uint16be_sha256") != order_sha
        or value.get("worker_task_list_sha256") != tasks_sha
        or value.get("matched_control_candidates") != 0
    ):
        raise RuntimeError("A425 progress fingerprint differs")
    status = value.get("status")
    completed = int(value.get("executed_worker_prefix_groups", -1))
    factual = value.get("factual_filter_candidates")
    if (
        status not in {
            "running",
            "candidate_found",
            "worker_exhausted",
            "peer_confirmed",
        }
        or not 0 <= completed <= STATIC_EPOCHS
        or (
            status == "candidate_found"
            and (not isinstance(factual, list) or len(factual) != 1)
        )
        or (status != "candidate_found" and factual != 0)
    ):
        raise RuntimeError("A425 resumable progress state differs")
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
    if (
        len(order) != STATIC_EPOCHS
        or len(tasks) != STATIC_EPOCHS
        or not 0 <= start_group <= STATIC_EPOCHS
    ):
        raise ValueError("A425 worker schedule geometry differs")
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
                raise RuntimeError("A425 matched control produced a candidate")
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
                "last_owner_queue_position_one_based": task[
                    "owner_queue_position_one_based"
                ],
                "last_task_stolen": task["stolen"],
            }
            if not factual:
                progress_callback(
                    {"status": "running", "factual_filter_candidates": 0, **common}
                )
                continue
            if len(factual) != 1:
                raise RuntimeError(
                    "A425 complete W51 group produced multiple factual filters"
                )
            candidate = factual[0]
            if ((candidate >> WORD0_SUFFIX_BITS) & (CELLS - 1)) != prefix:
                raise RuntimeError("A425 candidate prefix differs")
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
                "owner_queue_position_one_based": task[
                    "owner_queue_position_one_based"
                ],
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


def mark_peer_confirmed(
    protocol: Mapping[str, Any], qualification_sha256: str, worker_index: int
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
        value.get("protocol_sha256") != file_sha256(PROTOCOL)
        or value.get("A390_qualification_sha256") != qualification_sha256
        or value.get("worker_index") != worker_index
        or value.get("worker_role") != protocol["worker_roles"][worker_index]
    ):
        raise RuntimeError("A425 peer progress fingerprint differs")
    if value.get("status") not in {
        "running",
        "peer_confirmed",
        "worker_exhausted",
        "candidate_found",
    }:
        raise RuntimeError("A425 peer progress status differs")
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
            panel[role] = {
                "status": "not_started",
                "executed_worker_prefix_groups": 0,
                "worker_prefix_groups": STATIC_EPOCHS,
            }
            continue
        value = json.loads(path.read_bytes())
        if (
            value.get("protocol_sha256") != file_sha256(PROTOCOL)
            or value.get("worker_role") != role
        ):
            raise RuntimeError("A425 progress snapshot fingerprint differs")
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
        "prefix_sets_are_disjoint_by_A416_construction": True,
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

    strict = payload["aggregate_execution"]["strict_subset_of_complete_domain"]
    terminal = (
        "confirmed_strict_subset_W51_recovery"
        if strict
        else "confirmed_complete_domain_W51_recovery"
    )
    writer = CausalWriter(api_id="a425w51")
    writer._rules = []
    writer.add_rule(
        name="qualified_A416_schedule_and_exact_W51_engine_to_model",
        description="Execute the byte-identical, externally qualified A416 eight-reader schedule as disjoint complete W51 groups with one confirmed shared stop.",
        pattern=["A425_frozen_fresh_W51_schedule", "A390_exact_W51_group_engine"],
        conclusion="A425_sole_factual_W51_model",
        confidence_modifier=1.0,
    )
    writer.add_rule(
        name="W51_model_to_confirmed_recovery",
        description="Require an empty matched control and independent eight-block confirmation before retaining the W51 recovery.",
        pattern=["A425_sole_factual_W51_model"],
        conclusion=f"A425_{terminal}",
        confidence_modifier=1.0,
    )
    writer.add_triplet(
        trigger="A425:frozen_fresh_W51_A416_schedule",
        mechanism="disjoint_complete_2^38_group_execution_with_confirmed_shared_stop",
        outcome="A425:sole_factual_W51_model",
        confidence=1.0,
        source=payload["execution_sha256"],
        quantification=json.dumps(payload["aggregate_execution"], sort_keys=True),
        evidence=json.dumps(payload["rank_analysis"], sort_keys=True),
        domain="full-round ChaCha20 W51 qualified Reader recovery",
        quality_score=1.0,
    )
    writer.add_triplet(
        trigger="A425:sole_factual_W51_model",
        mechanism="matched_control_rejection_and_dual_reference_eight_block_confirmation",
        outcome=f"A425:{terminal}",
        confidence=1.0,
        source=payload["measurement_sha256"],
        quantification=json.dumps(payload["confirmation"], sort_keys=True),
        evidence=payload["evidence_stage"],
        domain="confirmed full-round ChaCha20 W51 recovery",
        quality_score=1.0,
    )
    writer.add_triplet(
        trigger="A425:frozen_fresh_W51_A416_schedule",
        mechanism="materialized_A416_W51_search_and_confirmation_closure",
        outcome=f"A425:{terminal}",
        confidence=1.0,
        source="materialized:A425_A416_W51_recovery_chain",
        quantification="exact retained closure",
        evidence=payload["evidence_stage"],
        domain="AI-native retained inference",
        quality_score=1.0,
        is_inferred=True,
    )
    writer.add_cluster(
        name="A425 qualified A416 W51 recovery",
        entities=[
            "A425:frozen_fresh_W51_A416_schedule",
            "A425:sole_factual_W51_model",
            f"A425:{terminal}",
        ],
    )
    writer.add_gap(
        subject=f"A425:{terminal}",
        predicate="next_required_object",
        expected_object_type="fresh_W51_or_W52_byte_identical_A416_schedule_transfer",
        confidence=1.0,
        suggested_queries=[
            "Transfer the same frozen A416 schedule to the next exact grouped-engine width without using the A425 outcome for schedule selection."
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
        reader.api_id != "a425w51"
        or len(explicit) != 2
        or len(all_rows) != 3
        or len(inferred) != 1
        or len(reader._rules) != 2
        or len(reader._clusters) != 1
        or len(reader._gaps) != 1
    ):
        raise RuntimeError("A425 authentic Causal reopen gate failed")
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
        != "chacha20-round20-w51-a416-fresh-shared-stop-recovery-a425-confirmed-stop-v1"
        or stop.get("attempt_id") != ATTEMPT_ID
        or stop.get("protocol_sha256") != file_sha256(PROTOCOL)
        or stop.get("A390_qualification_sha256") != qualification_sha256
        or stop.get("confirmation", {}).get("all_blocks_match") is not True
        or stop.get("discovery", {}).get("control_filter_candidates") != []
    ):
        raise RuntimeError("A425 confirmed stop fingerprint differs")
    while not active_started_workers_terminal(protocol):
        time.sleep(5)
    aggregate = progress_snapshot(protocol)
    unique_groups = int(aggregate["total_unique_prefix_groups_evaluated"])
    if not 1 <= unique_groups <= CELLS:
        raise RuntimeError("A425 aggregate unique group count differs")
    strict_subset = unique_groups < CELLS
    aggregate["strict_subset_of_complete_domain"] = strict_subset
    aggregate["domain_reduction_factor"] = CELLS / unique_groups
    aggregate["search_gain_bits"] = math.log2(CELLS / unique_groups)
    discovery = stop["discovery"]
    rank_analysis = {
        "prefix12": int(discovery["prefix12"]),
        "prefix12_hex": discovery["prefix12_hex"],
        "source_schedule_attempt_id": "A416",
        "source_worker_role": discovery["worker_role"],
        "source_schedule_epoch_one_based": int(
            discovery["static_schedule_epoch"]
        ),
        "source_owner_queue_role": discovery["owner_queue_role"],
        "source_owner_queue_position_one_based": int(
            discovery["owner_queue_position_one_based"]
        ),
        "executed_winner_worker_step_one_based": int(
            discovery["worker_step_one_based"]
        ),
        "aggregate_unique_groups_before_confirmed_stop": unique_groups,
    }
    evidence_stage = (
        "FULLROUND_R20_A416_READER_W51_STRICT_SUBSET_RECOVERY_CONFIRMED"
        if strict_subset
        else "FULLROUND_R20_A416_READER_W51_COMPLETE_DOMAIN_RECOVERY_CONFIRMED"
    )
    payload: dict[str, Any] = {
        "schema": "chacha20-round20-w51-a416-fresh-shared-stop-recovery-a425-result-v1",
        "attempt_id": ATTEMPT_ID,
        "evidence_stage": evidence_stage,
        "design_sha256": DESIGN_SHA256,
        "implementation_sha256": protocol["implementation_sha256"],
        "implementation_commitment_sha256": protocol[
            "implementation_commitment_sha256"
        ],
        "protocol_sha256": file_sha256(PROTOCOL),
        "protocol_commitment_sha256": protocol["protocol_commitment_sha256"],
        "source_A416_result_sha256": protocol["source_A416_result_sha256"],
        "A390_qualification_sha256": qualification_sha256,
        "discovery": discovery,
        "confirmation": stop["confirmation"],
        "aggregate_execution": aggregate,
        "rank_analysis": rank_analysis,
        "matched_control_candidates": 0,
        "factual_candidates": 1,
        "all_8192_cross_implementation_output_bits_match": True,
        "complete_group_before_stop": True,
        "early_stop_inside_group": False,
        "production_target_labels_used": 0,
        "production_reader_refits": 0,
        "prior_public_assignment_reused": False,
        "prior_live_recovery_filter_outcomes_consumed": False,
        "execution_sha256": canonical_sha256(
            {
                "discovery": discovery,
                "aggregate_execution": aggregate,
                "rank_analysis": rank_analysis,
            }
        ),
        "measurement_sha256": canonical_sha256(
            {
                "confirmation": stop["confirmation"],
                "matched_control_candidates": 0,
            }
        ),
        "anchors": {
            "design": anchor(DESIGN, DESIGN_SHA256),
            "implementation": anchor(
                IMPLEMENTATION, protocol["implementation_sha256"]
            ),
            "protocol": anchor(PROTOCOL, file_sha256(PROTOCOL)),
            "confirmed_stop": anchor(STOP, file_sha256(STOP)),
            "source_A416_result": anchor(
                A416_RESULT, protocol["source_A416_result_sha256"]
            ),
            "A390_qualification": anchor(
                A390_QUALIFICATION, qualification_sha256
            ),
            "runner": anchor(Path(__file__)),
        },
    }
    payload["causal"] = build_causal(payload)
    atomic_json(RESULT, payload)
    atomic_bytes(
        REPORT,
        (
            "# A425 — Qualified A416 full-round ChaCha20 W51 recovery\n\n"
            f"Evidence stage: **{evidence_stage}**\n\n"
            "- Frozen external scheduler: **A416**\n"
            f"- Exact unique W51 groups evaluated: **{unique_groups} / 4096**\n"
            f"- Complete assignments evaluated: **{aggregate['total_unique_assignments_evaluated']:,} / {DOMAIN_SIZE:,}**\n"
            f"- Search gain: **{aggregate['search_gain_bits']:.9f} bits**\n"
            "- Factual / matched-control candidates: **1 / 0**\n"
            "- Independent confirmation: **two implementations, eight blocks, 8,192 checked output bits**\n"
            "- Authentic AI-native Causal readback: **2 explicit + 1 inferred chain**\n"
        ).encode(),
    )
    return payload


def recover_worker(
    *,
    worker_index: int,
    expected_protocol_sha256: str,
    expected_a390_qualification_sha256: str,
) -> dict[str, Any]:
    if not 0 <= worker_index < WORKERS:
        raise ValueError("A425 worker index differs")
    protocol = load_protocol(expected_protocol_sha256)
    load_a390_qualification(expected_a390_qualification_sha256)
    if RESULT.exists():
        return {"status": "peer_confirmed", "result_sha256": file_sha256(RESULT)}
    if STOP.exists():
        stop = json.loads(STOP.read_bytes())
        if int(stop.get("worker_index", -1)) == worker_index:
            return finalize_confirmed_stop(
                protocol, expected_a390_qualification_sha256
            )
        return mark_peer_confirmed(
            protocol, expected_a390_qualification_sha256, worker_index
        )
    roles = protocol["worker_roles"]
    role = roles[worker_index]
    order, tasks = validate_worker_schedule(
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
            executable,
            A390.initial_for_slab(challenge, 0),
            placeholder,
            placeholder,
        )

    order_sha = protocol["worker_order_uint16be_sha256"][role]
    tasks_sha = protocol["worker_task_list_sha256"][role]

    def write_progress(row: Mapping[str, Any]) -> None:
        atomic_json(
            progress_path(worker_index),
            {
                "schema": "chacha20-round20-w51-a416-fresh-shared-stop-recovery-a425-progress-v1",
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
                and json.loads(progress_path(index).read_bytes()).get("status")
                == "worker_exhausted"
                for index in range(WORKERS)
            )
            if exhausted == WORKERS:
                raise RuntimeError(
                    "A425 all disjoint workers exhausted without a model"
                )
        return discovery
    candidate = int(discovery["candidate"])
    confirmation = confirm(challenge, candidate)
    if confirmation.get("all_blocks_match") is not True:
        raise RuntimeError("A425 dual-reference eight-block confirmation failed")
    if discovery.get("control_filter_candidates") != []:
        raise RuntimeError("A425 matched control produced a candidate")
    if STOP.exists():
        return mark_peer_confirmed(
            protocol, expected_a390_qualification_sha256, worker_index
        )
    atomic_json(
        STOP,
        {
            "schema": "chacha20-round20-w51-a416-fresh-shared-stop-recovery-a425-confirmed-stop-v1",
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
        "A416_source_qualified": True,
        "A390_qualification_complete": A390_QUALIFICATION.exists(),
        "protocol_frozen": PROTOCOL.exists(),
        "confirmed_stop_available": STOP.exists(),
        "result_complete": RESULT.exists(),
        "candidate_group_size": GROUP_SIZE,
        "complete_domain_assignments": DOMAIN_SIZE,
    }
    load_design()
    _source, roles, _orders, _tasks = load_a416_schedule()
    payload["source_worker_roles"] = roles
    if IMPLEMENTATION.exists():
        payload["implementation_sha256"] = file_sha256(IMPLEMENTATION)
        load_implementation(payload["implementation_sha256"])
    if A390_QUALIFICATION.exists():
        payload["A390_qualification_sha256"] = file_sha256(A390_QUALIFICATION)
        load_a390_qualification(payload["A390_qualification_sha256"])
    if PROTOCOL.exists():
        payload["protocol_sha256"] = file_sha256(PROTOCOL)
        protocol = load_protocol(payload["protocol_sha256"])
        payload["public_challenge_sha256"] = protocol["public_challenge_sha256"]
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
    parser.add_argument("--expected-a416-result-sha256")
    parser.add_argument("--expected-protocol-sha256")
    parser.add_argument("--expected-a390-qualification-sha256")
    args = parser.parse_args()
    if args.freeze_implementation:
        payload = freeze_implementation()
    elif args.materialize_protocol:
        if (
            not args.expected_implementation_sha256
            or not args.expected_a416_result_sha256
        ):
            parser.error(
                "--materialize-protocol requires implementation and A416 result hashes"
            )
        payload = materialize_protocol(
            expected_implementation_sha256=args.expected_implementation_sha256,
            expected_a416_result_sha256=args.expected_a416_result_sha256,
        )
    elif args.recover_worker is not None:
        if (
            not args.expected_protocol_sha256
            or not args.expected_a390_qualification_sha256
        ):
            parser.error(
                "--recover-worker requires protocol and A390 qualification hashes"
            )
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

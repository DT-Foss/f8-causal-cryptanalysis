#!/usr/bin/env python3
"""A379: bind an unchanged pre-target order to a fresh full-round W49 challenge."""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import secrets
import sys
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

ROOT = Path(__file__).parents[2]
RESEARCH = ROOT / "research"
CONFIGS = RESEARCH / "configs"
RESULTS = RESEARCH / "results/v1"

DESIGN = CONFIGS / "chacha20_round20_fresh_w49_pretarget_transfer_a379_design_v1.json"
IMPLEMENTATION = CONFIGS / "chacha20_round20_fresh_w49_pretarget_transfer_a379_implementation_v1.json"
ORDER = RESULTS / "chacha20_round20_fresh_w49_pretarget_transfer_a379_order_v1.json"
PROTOCOL = CONFIGS / "chacha20_round20_fresh_w49_pretarget_transfer_a379_v1.json"
TEST = ROOT / "tests/test_chacha20_round20_fresh_w49_pretarget_transfer_a379.py"
REPRO = ROOT / "scripts/reproduce_chacha20_round20_fresh_w49_pretarget_transfer_a379.sh"

A373_RESULT = RESULTS / "chacha20_round20_w48_target_conditioned_factor2_a373_order_v1.json"
A373_RUNNER = RESEARCH / "experiments/chacha20_round20_w48_target_conditioned_factor2_a373.py"
A378_RUNNER = RESEARCH / "experiments/chacha20_round20_w49_sixtyfour_slab_grouped_engine_a378.py"
A378_DESIGN = CONFIGS / "chacha20_round20_w49_sixtyfour_slab_grouped_engine_a378_design_v1.json"
A378_PROTOCOL = CONFIGS / "chacha20_round20_w49_sixtyfour_slab_grouped_engine_a378_v1.json"

ATTEMPT_ID = "A379"
DESIGN_SHA256 = "881496c77ebf9fb909d8683b551ca7e83b29d1cf8c73fdf8cd9b102626629ed6"
A373_RESULT_SHA256 = "5631b0f2f05a015a9ad07b938a2f2862862214171d3066397da3524afe8e9264"
A373_RUNNER_SHA256 = "0d4a1c5a454f2697562b006963327364bb393d8bc546f9a9a6f5933eec1bc38b"
A373_ORDER_UINT16BE_SHA256 = "05e306514ae8796aec995f4a1863d9c3ea038b3cb3f76809813caaf53fd9a837"
A373_ORDER_COMMITMENT_SHA256 = "7c169a7d580af9a25b6ac2a943fc5d1269161b5811fa203a82c983baee4af690"
A378_DESIGN_SHA256 = "bcd9045320c615bab830d9db9a8591607653b89352d181f07f44b2c068137913"
A378_PROTOCOL_SHA256 = "c926f6474c7cb54909e0204182941d7d1c63889fd892e92f0fbc4c5c48305af3"
A378_RUNNER_SHA256 = "16e2832e49925a4c8d73580f2656788b22da3cb9e5a6e33281ffc5dbe4194c27"

WIDTH = 49
KNOWN_KEY_BITS = 256 - WIDTH
PREFIX_BITS = 12
WORD0_SUFFIX_BITS = 20
WORD1_LOW_BITS = 17
CELLS = 1 << PREFIX_BITS
GROUP_SIZE = 1 << (WIDTH - PREFIX_BITS)
DOMAIN_SIZE = 1 << WIDTH
BLOCK_COUNT = 8
MASK32 = 0xFFFFFFFF
WORD1_KNOWN_MASK = MASK32 ^ ((1 << WORD1_LOW_BITS) - 1)


def load_module(path: Path, name: str) -> Any:
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot import A379 dependency {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


A378 = load_module(A378_RUNNER, "a379_a378_common")
W43 = A378.W43
file_sha256 = A378.file_sha256
canonical_sha256 = A378.canonical_sha256
atomic_json = A378.atomic_json
relative = A378.relative
path_from_ref = A378.path_from_ref
anchor = A378.anchor


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def exact_order(values: Sequence[int], label: str) -> list[int]:
    order = [int(value) for value in values]
    if len(order) != CELLS or set(order) != set(range(CELLS)):
        raise ValueError(f"A379 {label} is not an exact 4,096-cell order")
    return order


def order_sha256(order: Sequence[int]) -> str:
    return sha256(
        b"".join(value.to_bytes(2, "big") for value in exact_order(order, "hash"))
    )


def load_design() -> dict[str, Any]:
    if file_sha256(DESIGN) != DESIGN_SHA256:
        raise RuntimeError("A379 design hash differs")
    value = json.loads(DESIGN.read_bytes())
    contract = value.get("execution_contract", {})
    transfer = value.get("order_transfer_contract", {})
    boundary = value.get("information_boundary", {})
    if (
        value.get("schema")
        != "chacha20-round20-fresh-w49-pretarget-transfer-a379-design-v1"
        or value.get("attempt_id") != ATTEMPT_ID
        or value.get("design_state")
        != "frozen_after_A373_order_and_A378_protocol_while_A378_target_free_qualification_runs_before_any_W49_production_challenge_assignment_candidate_prefix_or_filter_outcome"
        or contract.get("unknown_key_bits") != WIDTH
        or contract.get("candidates_per_prefix_group") != GROUP_SIZE
        or contract.get("complete_domain_assignments") != DOMAIN_SIZE
        or contract.get("slabs_per_prefix_group") != 64
        or transfer.get("source_result_sha256") != A373_RESULT_SHA256
        or transfer.get("source_order_uint16be_sha256") != A373_ORDER_UINT16BE_SHA256
        or transfer.get("parameter_refit_at_W49") is not False
        or boundary.get("A378_qualification_outcome_available_at_A379_design") is not False
        or boundary.get("W49_production_challenge_available_at_design_freeze") is not False
        or boundary.get("W49_target_assignment_available_at_design_freeze") is not False
    ):
        raise RuntimeError("A379 design semantics differ")
    for key, source_path in value["source_anchors"].items():
        if key.endswith("_path"):
            expected = value["source_anchors"][key.removesuffix("_path") + "_sha256"]
            anchor(ROOT / source_path, expected)
    return value


def load_a373_source_order() -> dict[str, Any]:
    if file_sha256(A373_RESULT) != A373_RESULT_SHA256:
        raise RuntimeError("A379 A373 source result hash differs")
    value = json.loads(A373_RESULT.read_bytes())
    selected = exact_order(value.get("selected_order", []), "A373 source")
    if (
        value.get("schema")
        != "chacha20-round20-w48-target-conditioned-factor2-a373-order-v1"
        or value.get("attempt_id") != "A373"
        or value.get("selected_order_uint16be_sha256") != A373_ORDER_UINT16BE_SHA256
        or order_sha256(selected) != A373_ORDER_UINT16BE_SHA256
        or value.get("order_commitment_sha256") != A373_ORDER_COMMITMENT_SHA256
        or value.get("candidate_assignments_executed") != 0
        or value.get("target_labels_used") != 0
        or value.get("reader_refits") != 0
        or value.get("pointwise_factor2_proof", {}).get("violations") != 0
        or value.get("W48_recovery_available_at_order_freeze") is not False
    ):
        raise RuntimeError("A379 A373 source order semantics differ")
    return value


def load_a378_qualification(expected_file_sha256: str) -> dict[str, Any]:
    A378.load_protocol(A378_PROTOCOL_SHA256)
    if file_sha256(A378.QUALIFICATION) != expected_file_sha256:
        raise RuntimeError("A379 A378 qualification file hash differs")
    value = json.loads(A378.QUALIFICATION.read_bytes())
    group = value.get("complete_group_gate", {})
    if (
        value.get("schema")
        != "chacha20-round20-w49-sixtyfour-slab-grouped-engine-a378-qualification-v1"
        or value.get("attempt_id") != "A378"
        or value.get("protocol_sha256") != A378_PROTOCOL_SHA256
        or value.get("production_W49_challenge_used") is not False
        or value.get("production_W49_candidate_used") is not False
        or value.get("synthetic_filter_exact") is not True
        or value.get("matched_control_empty") is not True
        or group.get("logical_candidates") != GROUP_SIZE
        or group.get("complete_W49_group_before_outcome_evaluation") is not True
        or group.get("slabs_executed") != list(range(64))
        or len(group.get("factual_candidates", [])) != 1
        or group.get("control_candidates") != []
    ):
        raise RuntimeError("A379 A378 qualification semantics differ")
    return value


def freeze_implementation(*, expected_a378_qualification_sha256: str) -> dict[str, Any]:
    if any(path.exists() for path in (IMPLEMENTATION, ORDER, PROTOCOL)):
        raise FileExistsError("A379 implementation/order/protocol already exists")
    design = load_design()
    source = load_a373_source_order()
    qualification = load_a378_qualification(expected_a378_qualification_sha256)
    if not TEST.exists() or not REPRO.exists():
        raise FileNotFoundError("A379 test and reproducer must precede implementation freeze")
    anchors = {
        "design": anchor(DESIGN, DESIGN_SHA256),
        "A373_source_order": anchor(A373_RESULT, A373_RESULT_SHA256),
        "A373_runner": anchor(A373_RUNNER, A373_RUNNER_SHA256),
        "A378_design": anchor(A378_DESIGN, A378_DESIGN_SHA256),
        "A378_protocol": anchor(A378_PROTOCOL, A378_PROTOCOL_SHA256),
        "A378_qualification": anchor(
            A378.QUALIFICATION, expected_a378_qualification_sha256
        ),
        "A378_runner": anchor(A378_RUNNER, A378_RUNNER_SHA256),
        "runner": anchor(Path(__file__)),
        "test": anchor(TEST),
        "reproducer": anchor(REPRO),
    }
    boundary = {
        **design["information_boundary"],
        "A373_source_order_verified_at_implementation_freeze": True,
        "A378_qualification_verified_at_implementation_freeze": True,
        "W49_production_challenge_available_at_implementation_freeze": False,
        "W49_target_assignment_available_at_implementation_freeze": False,
        "W49_candidate_or_prefix_available_at_implementation_freeze": False,
    }
    payload: dict[str, Any] = {
        "schema": "chacha20-round20-fresh-w49-pretarget-transfer-a379-implementation-v1",
        "attempt_id": ATTEMPT_ID,
        "commitment_state": "complete_code_and_dependencies_frozen_after_W49_engine_qualification_before_W49_production_challenge",
        "design_sha256": DESIGN_SHA256,
        "source_order_uint16be_sha256": A373_ORDER_UINT16BE_SHA256,
        "source_order_commitment_sha256": source["order_commitment_sha256"],
        "A378_qualification_file_sha256": expected_a378_qualification_sha256,
        "A378_qualification_sha256": qualification["qualification_sha256"],
        "information_boundary": boundary,
        "anchors": anchors,
    }
    payload["implementation_commitment_sha256"] = canonical_sha256(payload)
    atomic_json(IMPLEMENTATION, payload)
    return payload


def load_implementation() -> dict[str, Any]:
    value = json.loads(IMPLEMENTATION.read_bytes())
    if (
        value.get("schema")
        != "chacha20-round20-fresh-w49-pretarget-transfer-a379-implementation-v1"
        or value.get("attempt_id") != ATTEMPT_ID
        or value.get("commitment_state")
        != "complete_code_and_dependencies_frozen_after_W49_engine_qualification_before_W49_production_challenge"
        or value.get("design_sha256") != DESIGN_SHA256
        or value.get("source_order_uint16be_sha256") != A373_ORDER_UINT16BE_SHA256
    ):
        raise RuntimeError("A379 implementation semantics differ")
    for row in value["anchors"].values():
        anchor(path_from_ref(row["path"]), row["sha256"])
    unsigned = {
        key: item
        for key, item in value.items()
        if key != "implementation_commitment_sha256"
    }
    if value.get("implementation_commitment_sha256") != canonical_sha256(unsigned):
        raise RuntimeError("A379 implementation commitment differs")
    load_a373_source_order()
    load_a378_qualification(value["A378_qualification_file_sha256"])
    return value


def freeze_order() -> dict[str, Any]:
    if ORDER.exists() or PROTOCOL.exists():
        raise FileExistsError("A379 order or protocol already exists")
    implementation = load_implementation()
    source = load_a373_source_order()
    selected = exact_order(source["selected_order"], "copied pretarget source")
    payload: dict[str, Any] = {
        "schema": "chacha20-round20-fresh-w49-pretarget-transfer-a379-order-v1",
        "attempt_id": ATTEMPT_ID,
        "order_state": "byte_identical_A373_wavefront_frozen_before_W49_challenge",
        "selected_operator": "unchanged_A373_factor2_wavefront_pre_target_W49_transfer",
        "selected_order_uint16be_sha256": order_sha256(selected),
        "selected_order": selected,
        "source_A373_result_sha256": A373_RESULT_SHA256,
        "source_A373_order_commitment_sha256": source["order_commitment_sha256"],
        "source_pointwise_factor2_proof": source["pointwise_factor2_proof"],
        "implementation_sha256": file_sha256(IMPLEMENTATION),
        "implementation_commitment_sha256": implementation[
            "implementation_commitment_sha256"
        ],
        "information_boundary": {
            "W49_production_challenge_available_at_order_freeze": False,
            "W49_target_assignment_available_at_order_freeze": False,
            "W49_candidate_or_prefix_available_at_order_freeze": False,
            "W49_filter_outcome_available_at_order_freeze": False,
            "target_labels_used": 0,
            "parameter_refits": 0,
        },
    }
    payload["order_commitment_sha256"] = canonical_sha256(
        {
            "selected_order_uint16be_sha256": payload[
                "selected_order_uint16be_sha256"
            ],
            "source_A373_result_sha256": A373_RESULT_SHA256,
            "source_A373_order_commitment_sha256": source[
                "order_commitment_sha256"
            ],
            "implementation_commitment_sha256": payload[
                "implementation_commitment_sha256"
            ],
            "information_boundary": payload["information_boundary"],
        }
    )
    atomic_json(ORDER, payload)
    return payload


def load_order() -> dict[str, Any]:
    value = json.loads(ORDER.read_bytes())
    selected = exact_order(value.get("selected_order", []), "stored order")
    expected = canonical_sha256(
        {
            "selected_order_uint16be_sha256": value[
                "selected_order_uint16be_sha256"
            ],
            "source_A373_result_sha256": value["source_A373_result_sha256"],
            "source_A373_order_commitment_sha256": value[
                "source_A373_order_commitment_sha256"
            ],
            "implementation_commitment_sha256": value[
                "implementation_commitment_sha256"
            ],
            "information_boundary": value["information_boundary"],
        }
    )
    if (
        value.get("schema")
        != "chacha20-round20-fresh-w49-pretarget-transfer-a379-order-v1"
        or value.get("attempt_id") != ATTEMPT_ID
        or order_sha256(selected) != A373_ORDER_UINT16BE_SHA256
        or value.get("selected_order_uint16be_sha256") != A373_ORDER_UINT16BE_SHA256
        or value.get("order_commitment_sha256") != expected
        or value.get("information_boundary", {}).get(
            "W49_production_challenge_available_at_order_freeze"
        )
        is not False
    ):
        raise RuntimeError("A379 stored order semantics differ")
    load_implementation()
    load_a373_source_order()
    return value


def apply_assignment(known_zeroed_key_words: Sequence[int], assignment: int) -> list[int]:
    if len(known_zeroed_key_words) != 8:
        raise ValueError("A379 requires eight ChaCha20 key words")
    if not 0 <= assignment < DOMAIN_SIZE:
        raise ValueError("A379 assignment exceeds W49")
    key = [int(word) & MASK32 for word in known_zeroed_key_words]
    if key[0] != 0 or key[1] & ((1 << WORD1_LOW_BITS) - 1):
        raise ValueError("A379 known key does not zero the W49 interval")
    key[0] = assignment & MASK32
    key[1] |= assignment >> 32
    return key


def challenge_from_assignment(*, label: str, assignment: int) -> dict[str, Any]:
    if not 0 <= assignment < DOMAIN_SIZE:
        raise ValueError("A379 assignment exceeds W49")
    derived = hashlib.shake_256(label.encode()).digest(48)
    words = W43._words(derived)  # noqa: SLF001
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
        "challenge_id": "chacha20-r20-w49-a379-fresh-pretarget-transfer-v1",
        "primitive": "RFC8439_ChaCha20_block_function",
        "rounds": 20,
        "feedforward": True,
        "known_material_derivation_label": label,
        "known_material_derivation_sha256": sha256(derived),
        "known_zeroed_key_words": [int(value) for value in known],
        "known_key_bits": KNOWN_KEY_BITS,
        "unknown_key_bits": WIDTH,
        "unknown_layout": "key_word0_all32_plus_key_word1_low17",
        "unknown_assignment_included": False,
        "counter_start": int(counter),
        "nonce_words": [int(value) for value in nonce],
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
        != "chacha20-r20-w49-a379-fresh-pretarget-transfer-v1"
        or challenge.get("primitive") != "RFC8439_ChaCha20_block_function"
        or challenge.get("rounds") != 20
        or challenge.get("feedforward") is not True
        or challenge.get("unknown_key_bits") != WIDTH
        or challenge.get("known_key_bits") != KNOWN_KEY_BITS
        or challenge.get("unknown_assignment_included") is not False
        or challenge.get("public_output_blocks") != BLOCK_COUNT
        or len(challenge.get("known_zeroed_key_words", [])) != 8
        or len(challenge.get("nonce_words", [])) != 3
        or len(challenge.get("target_words", [])) != BLOCK_COUNT
        or any(len(block) != 16 for block in challenge.get("target_words", []))
    ):
        raise RuntimeError("A379 public challenge shape differs")
    label = str(challenge["known_material_derivation_label"])
    derived = hashlib.shake_256(label.encode()).digest(48)
    words = W43._words(derived)  # noqa: SLF001
    expected_key = words[:8]
    expected_key[0] = 0
    expected_key[1] &= WORD1_KNOWN_MASK
    targets = [[int(word) & MASK32 for word in block] for block in challenge["target_words"]]
    control = [int(word) & MASK32 for word in challenge["control_target_words"]]
    if (
        sha256(derived) != challenge["known_material_derivation_sha256"]
        or expected_key != challenge["known_zeroed_key_words"]
        or words[8] != challenge["counter_start"]
        or words[9:12] != challenge["nonce_words"]
        or expected_key[0] != 0
        or expected_key[1] & ((1 << WORD1_LOW_BITS) - 1)
        or [sha256(W43._word_bytes(block)) for block in targets]  # noqa: SLF001
        != challenge["target_block_sha256"]
        or control[0] != (targets[0][0] ^ 1)
        or control[1:] != targets[0][1:]
        or sha256(W43._word_bytes(control))  # noqa: SLF001
        != challenge["control_target_block_sha256"]
    ):
        raise RuntimeError("A379 public challenge identity differs")


def fresh_challenge() -> dict[str, Any]:
    label = f"A379|fresh-W49-pretarget-transfer|{secrets.token_hex(32)}"
    assignment = secrets.randbits(WIDTH)
    challenge = challenge_from_assignment(label=label, assignment=assignment)
    del assignment
    validate_challenge(challenge)
    return challenge


def materialize(*, expected_a378_qualification_sha256: str) -> dict[str, Any]:
    if PROTOCOL.exists():
        raise FileExistsError("A379 protocol already exists")
    design = load_design()
    implementation = load_implementation()
    order = load_order()
    if implementation["A378_qualification_file_sha256"] != expected_a378_qualification_sha256:
        raise RuntimeError("A379 qualification differs from implementation freeze")
    qualification = load_a378_qualification(expected_a378_qualification_sha256)
    challenge = fresh_challenge()
    public_sha = canonical_sha256(challenge)
    boundary = {
        **design["information_boundary"],
        "implementation_frozen_before_W49_challenge": True,
        "selected_order_frozen_before_W49_challenge": True,
        "A378_qualification_verified_before_W49_challenge": True,
        "A379_assignment_absent_from_protocol": True,
        "A379_candidate_or_prefix_available_at_protocol_freeze": False,
        "A379_target_labels_used_for_order_construction": 0,
        "orders_refit_on_A379_target": False,
    }
    payload: dict[str, Any] = {
        "schema": "chacha20-round20-fresh-w49-pretarget-transfer-a379-protocol-v1",
        "attempt_id": ATTEMPT_ID,
        "protocol_state": "fresh_W49_target_frozen_after_exact_engine_qualification_implementation_and_unchanged_order_before_candidate_or_prefix",
        "design_sha256": DESIGN_SHA256,
        "implementation_sha256": file_sha256(IMPLEMENTATION),
        "implementation_commitment_sha256": implementation[
            "implementation_commitment_sha256"
        ],
        "order_sha256": file_sha256(ORDER),
        "order_commitment_sha256": order["order_commitment_sha256"],
        "A378_qualification_file_sha256": expected_a378_qualification_sha256,
        "A378_semantic_qualification_sha256": qualification["qualification_sha256"],
        "selected_operator": order["selected_operator"],
        "selected_order_uint16be_sha256": order["selected_order_uint16be_sha256"],
        "selected_order": order["selected_order"],
        "source_A373_result_sha256": A373_RESULT_SHA256,
        "source_A373_order_commitment_sha256": A373_ORDER_COMMITMENT_SHA256,
        "source_pointwise_factor2_proof": order["source_pointwise_factor2_proof"],
        "public_challenge": challenge,
        "public_challenge_sha256": public_sha,
        "execution_contract": design["execution_contract"],
        "order_transfer_contract": design["order_transfer_contract"],
        "information_boundary": boundary,
        "anchors": {
            "design": anchor(DESIGN, DESIGN_SHA256),
            "implementation": anchor(IMPLEMENTATION),
            "order": anchor(ORDER),
            "A373_source_order": anchor(A373_RESULT, A373_RESULT_SHA256),
            "A378_protocol": anchor(A378_PROTOCOL, A378_PROTOCOL_SHA256),
            "A378_qualification": anchor(
                A378.QUALIFICATION, expected_a378_qualification_sha256
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
            "order_commitment_sha256": payload["order_commitment_sha256"],
            "A378_qualification_file_sha256": expected_a378_qualification_sha256,
            "selected_order_uint16be_sha256": payload[
                "selected_order_uint16be_sha256"
            ],
            "public_challenge_sha256": public_sha,
            "execution_contract": payload["execution_contract"],
            "information_boundary": boundary,
        }
    )
    atomic_json(PROTOCOL, payload)
    return payload


def load_protocol(expected_sha256: str) -> dict[str, Any]:
    if file_sha256(PROTOCOL) != expected_sha256:
        raise RuntimeError("A379 protocol hash differs")
    value = json.loads(PROTOCOL.read_bytes())
    selected = exact_order(value.get("selected_order", []), "protocol order")
    if (
        value.get("schema")
        != "chacha20-round20-fresh-w49-pretarget-transfer-a379-protocol-v1"
        or value.get("attempt_id") != ATTEMPT_ID
        or value.get("selected_order_uint16be_sha256") != order_sha256(selected)
        or value.get("selected_order_uint16be_sha256") != A373_ORDER_UINT16BE_SHA256
        or canonical_sha256(value.get("public_challenge"))
        != value.get("public_challenge_sha256")
        or value.get("information_boundary", {}).get("A379_assignment_absent_from_protocol")
        is not True
    ):
        raise RuntimeError("A379 protocol semantics differ")
    for row in value["anchors"].values():
        anchor(path_from_ref(row["path"]), row["sha256"])
    load_implementation()
    load_order()
    load_a378_qualification(value["A378_qualification_file_sha256"])
    validate_challenge(value["public_challenge"])
    return value


def confirm(challenge: Mapping[str, Any], assignment: int) -> dict[str, Any]:
    key_words = apply_assignment(challenge["known_zeroed_key_words"], assignment)
    target_words = challenge["target_words"]
    byte_outputs = W43._reference_outputs(  # noqa: SLF001
        key_words,
        int(challenge["counter_start"]),
        challenge["nonce_words"],
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
        observed == expected
        for observed, expected in zip(byte_outputs, target_words, strict=True)
    ]
    word_matches = [
        observed == expected
        for observed, expected in zip(word_outputs, target_words, strict=True)
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


def analyze() -> dict[str, Any]:
    payload: dict[str, Any] = {
        "attempt_id": ATTEMPT_ID,
        "design": load_design(),
        "source_order": {
            "path": relative(A373_RESULT),
            "sha256": file_sha256(A373_RESULT),
            "selected_order_uint16be_sha256": load_a373_source_order()[
                "selected_order_uint16be_sha256"
            ],
        },
        "A378_protocol_sha256": file_sha256(A378_PROTOCOL),
        "A378_qualification_exists": A378.QUALIFICATION.exists(),
        "implementation_exists": IMPLEMENTATION.exists(),
        "order_exists": ORDER.exists(),
        "protocol_exists": PROTOCOL.exists(),
    }
    if A378.QUALIFICATION.exists():
        payload["A378_qualification"] = {
            "path": relative(A378.QUALIFICATION),
            "sha256": file_sha256(A378.QUALIFICATION),
            "qualification_sha256": load_a378_qualification(
                file_sha256(A378.QUALIFICATION)
            )["qualification_sha256"],
        }
    if PROTOCOL.exists():
        payload["protocol_sha256"] = file_sha256(PROTOCOL)
        payload["protocol"] = load_protocol(payload["protocol_sha256"])
    return payload


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--analyze", action="store_true")
    group.add_argument("--freeze-implementation", action="store_true")
    group.add_argument("--freeze-order", action="store_true")
    group.add_argument("--materialize", action="store_true")
    parser.add_argument("--expected-a378-qualification-sha256")
    args = parser.parse_args()
    if args.freeze_implementation:
        if not args.expected_a378_qualification_sha256:
            parser.error(
                "--freeze-implementation requires --expected-a378-qualification-sha256"
            )
        payload = freeze_implementation(
            expected_a378_qualification_sha256=args.expected_a378_qualification_sha256
        )
    elif args.freeze_order:
        payload = freeze_order()
    elif args.materialize:
        if not args.expected_a378_qualification_sha256:
            parser.error("--materialize requires --expected-a378-qualification-sha256")
        payload = materialize(
            expected_a378_qualification_sha256=args.expected_a378_qualification_sha256
        )
    else:
        payload = analyze()
    print(json.dumps(payload, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()

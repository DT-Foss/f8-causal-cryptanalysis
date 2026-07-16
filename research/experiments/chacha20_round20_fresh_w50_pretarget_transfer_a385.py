#!/usr/bin/env python3
"""A385: bind an unchanged pre-target order to a fresh full-round W50 challenge."""

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

DESIGN = CONFIGS / "chacha20_round20_fresh_w50_pretarget_transfer_a385_design_v1.json"
IMPLEMENTATION = CONFIGS / "chacha20_round20_fresh_w50_pretarget_transfer_a385_implementation_v1.json"
ORDER = RESULTS / "chacha20_round20_fresh_w50_pretarget_transfer_a385_order_v1.json"
PROTOCOL = CONFIGS / "chacha20_round20_fresh_w50_pretarget_transfer_a385_v1.json"
TEST = ROOT / "tests/test_chacha20_round20_fresh_w50_pretarget_transfer_a385.py"
REPRO = ROOT / "scripts/reproduce_chacha20_round20_fresh_w50_pretarget_transfer_a385.sh"

A382_RESULT = (
    RESULTS / "chacha20_round20_w49_crosswidth_wide_consensus_factor6_a382_order_v1.json"
)
A382_RUNNER = (
    RESEARCH / "experiments/chacha20_round20_w49_crosswidth_wide_consensus_factor6_a382.py"
)
A384_RUNNER = (
    RESEARCH
    / "experiments/chacha20_round20_w50_onehundredtwentyeight_slab_grouped_engine_a384.py"
)
A384_DESIGN = (
    CONFIGS
    / "chacha20_round20_w50_onehundredtwentyeight_slab_grouped_engine_a384_design_v1.json"
)
A384_PROTOCOL = (
    CONFIGS / "chacha20_round20_w50_onehundredtwentyeight_slab_grouped_engine_a384_v1.json"
)

ATTEMPT_ID = "A385"
DESIGN_SHA256 = "0e4c1d7b5f2a89245728fcc3f5d6d66ebb20c3cefccb127f03d9b58a57125687"
A382_RESULT_SHA256 = "f705549d15be9f4ed98e8548b837524dae8603bff384ab30648c5917dfb82c0c"
A382_RUNNER_SHA256 = "46601c0e4fc5e20ee2ab85c4140b1fadd33b149f189e8335a0a6ef815bcbdc9f"
A382_ORDER_UINT16BE_SHA256 = "bcd1f2920aaa6dce6b8e91fcf6cf2ef48748ecad4cb00af2ac5af175641125d2"
A382_ORDER_COMMITMENT_SHA256 = "f829d1c3390ff3d685aa1bcf7d1cf2b42bd07063f0e59f2f872d74d470095bcb"
A384_DESIGN_SHA256 = "9ca2dacdff315b4f117113bea1046a1c11764213f66464fc8f65f07223e8cd2c"
A384_PROTOCOL_SHA256 = "1bd9a1e572906ff98aab30b52b547f48f4b1d61785ccc0ca8082ae4c6bd13fcb"
A384_RUNNER_SHA256 = "60352d5f0d09fad8272e87f5a202d6f62274911d7bdd154738a47bac04b6264f"

WIDTH = 50
KNOWN_KEY_BITS = 256 - WIDTH
PREFIX_BITS = 12
WORD0_SUFFIX_BITS = 20
WORD1_LOW_BITS = 18
CELLS = 1 << PREFIX_BITS
GROUP_SIZE = 1 << (WIDTH - PREFIX_BITS)
DOMAIN_SIZE = 1 << WIDTH
BLOCK_COUNT = 8
MASK32 = 0xFFFFFFFF
WORD1_KNOWN_MASK = MASK32 ^ ((1 << WORD1_LOW_BITS) - 1)


def load_module(path: Path, name: str) -> Any:
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot import A385 dependency {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


A384 = load_module(A384_RUNNER, "a385_a384_common")
W43 = A384.W43
file_sha256 = A384.file_sha256
canonical_sha256 = A384.canonical_sha256
atomic_json = A384.atomic_json
relative = A384.relative
path_from_ref = A384.path_from_ref
anchor = A384.anchor


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def exact_order(values: Sequence[int], label: str) -> list[int]:
    order = [int(value) for value in values]
    if len(order) != CELLS or set(order) != set(range(CELLS)):
        raise ValueError(f"A385 {label} is not an exact 4,096-cell order")
    return order


def order_sha256(order: Sequence[int]) -> str:
    return sha256(
        b"".join(value.to_bytes(2, "big") for value in exact_order(order, "hash"))
    )


def load_design() -> dict[str, Any]:
    if file_sha256(DESIGN) != DESIGN_SHA256:
        raise RuntimeError("A385 design hash differs")
    value = json.loads(DESIGN.read_bytes())
    contract = value.get("execution_contract", {})
    transfer = value.get("order_transfer_contract", {})
    boundary = value.get("information_boundary", {})
    if (
        value.get("schema")
        != "chacha20-round20-fresh-w50-pretarget-transfer-a385-design-v1"
        or value.get("attempt_id") != ATTEMPT_ID
        or value.get("design_state")
        != "frozen_after_A382_order_and_A384_protocol_while_A384_target_free_qualification_runs_before_any_W50_production_challenge_assignment_candidate_prefix_or_filter_outcome"
        or contract.get("unknown_key_bits") != WIDTH
        or contract.get("candidates_per_prefix_group") != GROUP_SIZE
        or contract.get("complete_domain_assignments") != DOMAIN_SIZE
        or contract.get("slabs_per_prefix_group") != 128
        or transfer.get("source_result_sha256") != A382_RESULT_SHA256
        or transfer.get("source_order_uint16be_sha256") != A382_ORDER_UINT16BE_SHA256
        or transfer.get("parameter_refit_at_W50") is not False
        or boundary.get("A384_qualification_outcome_available_at_A385_design") is not False
        or boundary.get("W50_production_challenge_available_at_design_freeze") is not False
        or boundary.get("W50_target_assignment_available_at_design_freeze") is not False
    ):
        raise RuntimeError("A385 design semantics differ")
    for key, source_path in value["source_anchors"].items():
        if key.endswith("_path"):
            expected = value["source_anchors"][key.removesuffix("_path") + "_sha256"]
            anchor(ROOT / source_path, expected)
    return value


def load_a382_source_order() -> dict[str, Any]:
    if file_sha256(A382_RESULT) != A382_RESULT_SHA256:
        raise RuntimeError("A385 A382 source result hash differs")
    value = json.loads(A382_RESULT.read_bytes())
    selected = exact_order(value.get("selected_order", []), "A382 source")
    if (
        value.get("schema")
        != "chacha20-round20-w49-crosswidth-wide-consensus-factor6-a382-order-v1"
        or value.get("attempt_id") != "A382"
        or value.get("selected_order_uint16be_sha256") != A382_ORDER_UINT16BE_SHA256
        or order_sha256(selected) != A382_ORDER_UINT16BE_SHA256
        or value.get("order_commitment_sha256") != A382_ORDER_COMMITMENT_SHA256
        or value.get("candidate_assignments_executed") != 0
        or value.get("target_labels_used") != 0
        or value.get("reader_refits") != 0
        or value.get("pointwise_factor6_proof", {}).get("violations") != 0
        or value.get("pointwise_factor6_proof", {}).get("source_count") != 6
        or value.get("information_boundary", {}).get(
            "A381_result_or_true_prefix_used"
        )
        is not False
    ):
        raise RuntimeError("A385 A382 source order semantics differ")
    return value


def load_a384_qualification(expected_file_sha256: str) -> dict[str, Any]:
    A384.load_protocol(A384_PROTOCOL_SHA256)
    if file_sha256(A384.QUALIFICATION) != expected_file_sha256:
        raise RuntimeError("A385 A384 qualification file hash differs")
    value = json.loads(A384.QUALIFICATION.read_bytes())
    group = value.get("complete_group_gate", {})
    if (
        value.get("schema")
        != "chacha20-round20-w50-onehundredtwentyeight-slab-grouped-engine-a384-qualification-v1"
        or value.get("attempt_id") != "A384"
        or value.get("protocol_sha256") != A384_PROTOCOL_SHA256
        or value.get("production_W50_challenge_used") is not False
        or value.get("production_W50_candidate_used") is not False
        or value.get("synthetic_filter_exact") is not True
        or value.get("matched_control_empty") is not True
        or group.get("logical_candidates") != GROUP_SIZE
        or group.get("complete_W50_group_before_outcome_evaluation") is not True
        or group.get("slabs_executed") != list(range(128))
        or len(group.get("factual_candidates", [])) != 1
        or group.get("control_candidates") != []
    ):
        raise RuntimeError("A385 A384 qualification semantics differ")
    return value


def freeze_implementation(*, expected_a384_qualification_sha256: str) -> dict[str, Any]:
    if any(path.exists() for path in (IMPLEMENTATION, ORDER, PROTOCOL)):
        raise FileExistsError("A385 implementation/order/protocol already exists")
    design = load_design()
    source = load_a382_source_order()
    qualification = load_a384_qualification(expected_a384_qualification_sha256)
    if not TEST.exists() or not REPRO.exists():
        raise FileNotFoundError("A385 test and reproducer must precede implementation freeze")
    anchors = {
        "design": anchor(DESIGN, DESIGN_SHA256),
        "A382_source_order": anchor(A382_RESULT, A382_RESULT_SHA256),
        "A382_runner": anchor(A382_RUNNER, A382_RUNNER_SHA256),
        "A384_design": anchor(A384_DESIGN, A384_DESIGN_SHA256),
        "A384_protocol": anchor(A384_PROTOCOL, A384_PROTOCOL_SHA256),
        "A384_qualification": anchor(
            A384.QUALIFICATION, expected_a384_qualification_sha256
        ),
        "A384_runner": anchor(A384_RUNNER, A384_RUNNER_SHA256),
        "runner": anchor(Path(__file__)),
        "test": anchor(TEST),
        "reproducer": anchor(REPRO),
    }
    boundary = {
        **design["information_boundary"],
        "A382_source_order_verified_at_implementation_freeze": True,
        "A384_qualification_verified_at_implementation_freeze": True,
        "W50_production_challenge_available_at_implementation_freeze": False,
        "W50_target_assignment_available_at_implementation_freeze": False,
        "W50_candidate_or_prefix_available_at_implementation_freeze": False,
    }
    payload: dict[str, Any] = {
        "schema": "chacha20-round20-fresh-w50-pretarget-transfer-a385-implementation-v1",
        "attempt_id": ATTEMPT_ID,
        "commitment_state": "complete_code_and_dependencies_frozen_after_W50_engine_qualification_before_W50_production_challenge",
        "design_sha256": DESIGN_SHA256,
        "source_order_uint16be_sha256": A382_ORDER_UINT16BE_SHA256,
        "source_order_commitment_sha256": source["order_commitment_sha256"],
        "A384_qualification_file_sha256": expected_a384_qualification_sha256,
        "A384_qualification_sha256": qualification["qualification_sha256"],
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
        != "chacha20-round20-fresh-w50-pretarget-transfer-a385-implementation-v1"
        or value.get("attempt_id") != ATTEMPT_ID
        or value.get("commitment_state")
        != "complete_code_and_dependencies_frozen_after_W50_engine_qualification_before_W50_production_challenge"
        or value.get("design_sha256") != DESIGN_SHA256
        or value.get("source_order_uint16be_sha256") != A382_ORDER_UINT16BE_SHA256
    ):
        raise RuntimeError("A385 implementation semantics differ")
    for row in value["anchors"].values():
        anchor(path_from_ref(row["path"]), row["sha256"])
    unsigned = {
        key: item
        for key, item in value.items()
        if key != "implementation_commitment_sha256"
    }
    if value.get("implementation_commitment_sha256") != canonical_sha256(unsigned):
        raise RuntimeError("A385 implementation commitment differs")
    load_a382_source_order()
    load_a384_qualification(value["A384_qualification_file_sha256"])
    return value


def freeze_order() -> dict[str, Any]:
    if ORDER.exists() or PROTOCOL.exists():
        raise FileExistsError("A385 order or protocol already exists")
    implementation = load_implementation()
    source = load_a382_source_order()
    selected = exact_order(source["selected_order"], "copied pretarget source")
    payload: dict[str, Any] = {
        "schema": "chacha20-round20-fresh-w50-pretarget-transfer-a385-order-v1",
        "attempt_id": ATTEMPT_ID,
        "order_state": "byte_identical_A382_wavefront_frozen_before_W50_challenge",
        "selected_operator": "unchanged_A382_six_view_factor6_wavefront_pre_target_W50_transfer",
        "selected_order_uint16be_sha256": order_sha256(selected),
        "selected_order": selected,
        "source_A382_result_sha256": A382_RESULT_SHA256,
        "source_A382_order_commitment_sha256": source["order_commitment_sha256"],
        "source_pointwise_factor6_proof": source["pointwise_factor6_proof"],
        "implementation_sha256": file_sha256(IMPLEMENTATION),
        "implementation_commitment_sha256": implementation[
            "implementation_commitment_sha256"
        ],
        "information_boundary": {
            "W50_production_challenge_available_at_order_freeze": False,
            "W50_target_assignment_available_at_order_freeze": False,
            "W50_candidate_or_prefix_available_at_order_freeze": False,
            "W50_filter_outcome_available_at_order_freeze": False,
            "target_labels_used": 0,
            "parameter_refits": 0,
        },
    }
    payload["order_commitment_sha256"] = canonical_sha256(
        {
            "selected_order_uint16be_sha256": payload[
                "selected_order_uint16be_sha256"
            ],
            "source_A382_result_sha256": A382_RESULT_SHA256,
            "source_A382_order_commitment_sha256": source[
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
            "source_A382_result_sha256": value["source_A382_result_sha256"],
            "source_A382_order_commitment_sha256": value[
                "source_A382_order_commitment_sha256"
            ],
            "implementation_commitment_sha256": value[
                "implementation_commitment_sha256"
            ],
            "information_boundary": value["information_boundary"],
        }
    )
    if (
        value.get("schema")
        != "chacha20-round20-fresh-w50-pretarget-transfer-a385-order-v1"
        or value.get("attempt_id") != ATTEMPT_ID
        or order_sha256(selected) != A382_ORDER_UINT16BE_SHA256
        or value.get("selected_order_uint16be_sha256") != A382_ORDER_UINT16BE_SHA256
        or value.get("order_commitment_sha256") != expected
        or value.get("information_boundary", {}).get(
            "W50_production_challenge_available_at_order_freeze"
        )
        is not False
    ):
        raise RuntimeError("A385 stored order semantics differ")
    load_implementation()
    load_a382_source_order()
    return value


def apply_assignment(known_zeroed_key_words: Sequence[int], assignment: int) -> list[int]:
    if len(known_zeroed_key_words) != 8:
        raise ValueError("A385 requires eight ChaCha20 key words")
    if not 0 <= assignment < DOMAIN_SIZE:
        raise ValueError("A385 assignment exceeds W50")
    key = [int(word) & MASK32 for word in known_zeroed_key_words]
    if key[0] != 0 or key[1] & ((1 << WORD1_LOW_BITS) - 1):
        raise ValueError("A385 known key does not zero the W50 interval")
    key[0] = assignment & MASK32
    key[1] |= assignment >> 32
    return key


def challenge_from_assignment(*, label: str, assignment: int) -> dict[str, Any]:
    if not 0 <= assignment < DOMAIN_SIZE:
        raise ValueError("A385 assignment exceeds W50")
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
        "challenge_id": "chacha20-r20-w50-a385-fresh-pretarget-transfer-v1",
        "primitive": "RFC8439_ChaCha20_block_function",
        "rounds": 20,
        "feedforward": True,
        "known_material_derivation_label": label,
        "known_material_derivation_sha256": sha256(derived),
        "known_zeroed_key_words": [int(value) for value in known],
        "known_key_bits": KNOWN_KEY_BITS,
        "unknown_key_bits": WIDTH,
        "unknown_layout": "key_word0_all32_plus_key_word1_low18",
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
        != "chacha20-r20-w50-a385-fresh-pretarget-transfer-v1"
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
        raise RuntimeError("A385 public challenge shape differs")
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
        raise RuntimeError("A385 public challenge identity differs")


def fresh_challenge() -> dict[str, Any]:
    label = f"A385|fresh-W50-pretarget-transfer|{secrets.token_hex(32)}"
    assignment = secrets.randbits(WIDTH)
    challenge = challenge_from_assignment(label=label, assignment=assignment)
    del assignment
    validate_challenge(challenge)
    return challenge


def materialize(*, expected_a384_qualification_sha256: str) -> dict[str, Any]:
    if PROTOCOL.exists():
        raise FileExistsError("A385 protocol already exists")
    design = load_design()
    implementation = load_implementation()
    order = load_order()
    if implementation["A384_qualification_file_sha256"] != expected_a384_qualification_sha256:
        raise RuntimeError("A385 qualification differs from implementation freeze")
    qualification = load_a384_qualification(expected_a384_qualification_sha256)
    challenge = fresh_challenge()
    public_sha = canonical_sha256(challenge)
    boundary = {
        **design["information_boundary"],
        "implementation_frozen_before_W50_challenge": True,
        "selected_order_frozen_before_W50_challenge": True,
        "A384_qualification_verified_before_W50_challenge": True,
        "A385_assignment_absent_from_protocol": True,
        "A385_candidate_or_prefix_available_at_protocol_freeze": False,
        "A385_target_labels_used_for_order_construction": 0,
        "orders_refit_on_A385_target": False,
    }
    payload: dict[str, Any] = {
        "schema": "chacha20-round20-fresh-w50-pretarget-transfer-a385-protocol-v1",
        "attempt_id": ATTEMPT_ID,
        "protocol_state": "fresh_W50_target_frozen_after_exact_engine_qualification_implementation_and_unchanged_order_before_candidate_or_prefix",
        "design_sha256": DESIGN_SHA256,
        "implementation_sha256": file_sha256(IMPLEMENTATION),
        "implementation_commitment_sha256": implementation[
            "implementation_commitment_sha256"
        ],
        "order_sha256": file_sha256(ORDER),
        "order_commitment_sha256": order["order_commitment_sha256"],
        "A384_qualification_file_sha256": expected_a384_qualification_sha256,
        "A384_semantic_qualification_sha256": qualification["qualification_sha256"],
        "selected_operator": order["selected_operator"],
        "selected_order_uint16be_sha256": order["selected_order_uint16be_sha256"],
        "selected_order": order["selected_order"],
        "source_A382_result_sha256": A382_RESULT_SHA256,
        "source_A382_order_commitment_sha256": A382_ORDER_COMMITMENT_SHA256,
        "source_pointwise_factor6_proof": order["source_pointwise_factor6_proof"],
        "public_challenge": challenge,
        "public_challenge_sha256": public_sha,
        "execution_contract": design["execution_contract"],
        "order_transfer_contract": design["order_transfer_contract"],
        "information_boundary": boundary,
        "anchors": {
            "design": anchor(DESIGN, DESIGN_SHA256),
            "implementation": anchor(IMPLEMENTATION),
            "order": anchor(ORDER),
            "A382_source_order": anchor(A382_RESULT, A382_RESULT_SHA256),
            "A384_protocol": anchor(A384_PROTOCOL, A384_PROTOCOL_SHA256),
            "A384_qualification": anchor(
                A384.QUALIFICATION, expected_a384_qualification_sha256
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
            "A384_qualification_file_sha256": expected_a384_qualification_sha256,
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
        raise RuntimeError("A385 protocol hash differs")
    value = json.loads(PROTOCOL.read_bytes())
    selected = exact_order(value.get("selected_order", []), "protocol order")
    if (
        value.get("schema")
        != "chacha20-round20-fresh-w50-pretarget-transfer-a385-protocol-v1"
        or value.get("attempt_id") != ATTEMPT_ID
        or value.get("selected_order_uint16be_sha256") != order_sha256(selected)
        or value.get("selected_order_uint16be_sha256") != A382_ORDER_UINT16BE_SHA256
        or canonical_sha256(value.get("public_challenge"))
        != value.get("public_challenge_sha256")
        or value.get("information_boundary", {}).get("A385_assignment_absent_from_protocol")
        is not True
    ):
        raise RuntimeError("A385 protocol semantics differ")
    for row in value["anchors"].values():
        anchor(path_from_ref(row["path"]), row["sha256"])
    load_implementation()
    load_order()
    load_a384_qualification(value["A384_qualification_file_sha256"])
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
            "path": relative(A382_RESULT),
            "sha256": file_sha256(A382_RESULT),
            "selected_order_uint16be_sha256": load_a382_source_order()[
                "selected_order_uint16be_sha256"
            ],
        },
        "A384_protocol_sha256": file_sha256(A384_PROTOCOL),
        "A384_qualification_exists": A384.QUALIFICATION.exists(),
        "implementation_exists": IMPLEMENTATION.exists(),
        "order_exists": ORDER.exists(),
        "protocol_exists": PROTOCOL.exists(),
    }
    if A384.QUALIFICATION.exists():
        payload["A384_qualification"] = {
            "path": relative(A384.QUALIFICATION),
            "sha256": file_sha256(A384.QUALIFICATION),
            "qualification_sha256": load_a384_qualification(
                file_sha256(A384.QUALIFICATION)
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
    parser.add_argument("--expected-a384-qualification-sha256")
    args = parser.parse_args()
    if args.freeze_implementation:
        if not args.expected_a384_qualification_sha256:
            parser.error(
                "--freeze-implementation requires --expected-a384-qualification-sha256"
            )
        payload = freeze_implementation(
            expected_a384_qualification_sha256=args.expected_a384_qualification_sha256
        )
    elif args.freeze_order:
        payload = freeze_order()
    elif args.materialize:
        if not args.expected_a384_qualification_sha256:
            parser.error("--materialize requires --expected-a384-qualification-sha256")
        payload = materialize(
            expected_a384_qualification_sha256=args.expected_a384_qualification_sha256
        )
    else:
        payload = analyze()
    print(json.dumps(payload, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()

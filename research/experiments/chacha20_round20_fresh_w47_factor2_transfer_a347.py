#!/usr/bin/env python3
"""A347: transfer the pre-target A345 factor-two order unchanged to fresh W47."""

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

DESIGN = CONFIGS / "chacha20_round20_fresh_w47_factor2_transfer_a347_design_v1.json"
IMPLEMENTATION = CONFIGS / "chacha20_round20_fresh_w47_factor2_transfer_a347_implementation_v1.json"
ORDER = RESULTS / "chacha20_round20_fresh_w47_factor2_transfer_a347_order_v1.json"
PROTOCOL = CONFIGS / "chacha20_round20_fresh_w47_factor2_transfer_a347_v1.json"
PROGRESS = RESULTS / "chacha20_round20_fresh_w47_factor2_transfer_a347_progress_v1.json"
RESULT = RESULTS / "chacha20_round20_fresh_w47_factor2_transfer_a347_v1.json"
CAUSAL = RESULT.with_suffix(".causal")
REPORT = RESULTS / "chacha20_round20_fresh_w47_factor2_transfer_a347_v1.md"
TEST = ROOT / "tests/test_chacha20_round20_fresh_w47_factor2_transfer_a347.py"
REPRO = ROOT / "scripts/reproduce_chacha20_round20_fresh_w47_factor2_transfer_a347.sh"

A345_RUNNER = RESEARCH / "experiments/chacha20_round20_fresh_w46_factor2_replication_a345.py"
A346_RUNNER = RESEARCH / "experiments/chacha20_round20_w47_sixteen_slab_grouped_engine_a346.py"
A345_ORDER = RESULTS / "chacha20_round20_fresh_w46_factor2_replication_a345_order_v1.json"
A345_RESULT = RESULTS / "chacha20_round20_fresh_w46_factor2_replication_a345_v1.json"

ATTEMPT_ID = "A347"
DESIGN_SHA256 = "78e3406ca48af0c81f002c0f5329c1b7267481eca579ac9544b5188ee3cbe102"
A345_ORDER_SHA256 = "9f0a7a1773894b4a265a6e456bd3489c10fd5f44e7ef9d40dc4706699fa0107d"
A345_DESIGN_SHA256 = "03e4b2bc1cc98601d10a504a7d5e4730150e8b907a09a33df77134acda9c4f8f"
A346_PROTOCOL_SHA256 = "4cb6c1c7e0a9719cf4ac04e870d9f5190772664b786d541a0fc4c7c7ea86e3ca"
A346_RUNNER_SHA256 = "b022a3c19de0e5c0ab09cee68fa738e2fb3586823f5155d087441361588156d2"
SELECTED_ORDER_SHA256 = "649375a3990b84ec9e6de7d186ca96e70a22461753e3528088d3b1047851b6ae"

WIDTH = 47
KNOWN_KEY_BITS = 256 - WIDTH
PREFIX_BITS = 12
WORD0_SUFFIX_BITS = 20
WORD1_LOW_BITS = 15
CELLS = 1 << PREFIX_BITS
GROUP_SIZE = 1 << (WIDTH - PREFIX_BITS)
DOMAIN_SIZE = 1 << WIDTH
HOST_REFRESH_GROUPS = 32
BLOCK_COUNT = 8
MASK32 = 0xFFFFFFFF


def load_module(path: Path, name: str) -> Any:
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot import A347 dependency {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


A345 = load_module(A345_RUNNER, "a347_a345_common")
A346 = load_module(A346_RUNNER, "a347_a346_common")
W43 = A345.W43
file_sha256 = A345.file_sha256
canonical_sha256 = A345.canonical_sha256
sha256 = A345.sha256
atomic_json = A345.atomic_json
atomic_bytes = A345.atomic_bytes
relative = A345.relative
path_from_ref = A345.path_from_ref
anchor = A345.anchor
DOTCAUSAL_SRC = A345.DOTCAUSAL_SRC


def exact_order(values: Sequence[int], label: str) -> list[int]:
    order = [int(value) for value in values]
    if len(order) != CELLS or set(order) != set(range(CELLS)):
        raise ValueError(f"A347 {label} is not an exact 4,096-cell order")
    return order


def order_sha256(order: Sequence[int]) -> str:
    return sha256(
        b"".join(value.to_bytes(2, "big") for value in exact_order(order, "hash"))
    )


def rank_vector(order: Sequence[int]) -> list[int]:
    ranks = [0] * CELLS
    for rank, cell in enumerate(exact_order(order, "rank vector"), 1):
        ranks[cell] = rank
    return ranks


def load_design() -> dict[str, Any]:
    if file_sha256(DESIGN) != DESIGN_SHA256:
        raise RuntimeError("A347 design hash differs")
    value = json.loads(DESIGN.read_bytes())
    execution = value.get("execution_contract", {})
    transfer = value.get("order_transfer_contract", {})
    boundary = value.get("information_boundary", {})
    if (
        value.get("schema")
        != "chacha20-round20-fresh-w47-factor2-transfer-a347-design-v1"
        or value.get("attempt_id") != ATTEMPT_ID
        or value.get("design_state")
        != "frozen_while_A345_runs_after_target_free_A346_protocol_before_A345_result_A346_qualification_or_any_W47_challenge"
        or execution.get("unknown_key_bits") != WIDTH
        or execution.get("candidates_per_prefix_group") != GROUP_SIZE
        or execution.get("complete_domain_assignments") != DOMAIN_SIZE
        or execution.get("slabs_per_prefix_group") != 16
        or execution.get("prefix_groups") != CELLS
        or execution.get("complete_group_before_success_evaluation") is not True
        or execution.get("early_stop_inside_group") is not False
        or transfer.get("parameter_refit_at_W47") is not False
        or transfer.get("source_order_sha256") != A345_ORDER_SHA256
        or transfer.get("source_order_uint16be_sha256") != SELECTED_ORDER_SHA256
        or boundary.get("A345_result_available_at_design_freeze") is not False
        or boundary.get("A346_qualification_available_at_design_freeze") is not False
        or boundary.get("A347_fresh_challenge_available_at_design_freeze") is not False
        or boundary.get("A347_candidate_or_prefix_available_at_design_freeze") is not False
        or boundary.get("A347_target_labels_used_for_order_construction") != 0
        or boundary.get("orders_refit_on_A347_target") is not False
    ):
        raise RuntimeError("A347 frozen design semantics differ")
    anchors = value["source_anchors"]
    for key, source_path in anchors.items():
        if key.endswith("_path"):
            anchor(
                path_from_ref(source_path),
                anchors[key.removesuffix("_path") + "_sha256"],
            )
    return value


def freeze_implementation() -> dict[str, Any]:
    if IMPLEMENTATION.exists():
        raise FileExistsError("A347 implementation commitment already exists")
    if any(path.exists() for path in (ORDER, PROTOCOL, PROGRESS, RESULT, CAUSAL, REPORT)):
        raise RuntimeError("A347 implementation must precede every order/target artifact")
    load_design()
    if not TEST.exists() or not REPRO.exists():
        raise FileNotFoundError("A347 test and reproducer must precede commitment")
    payload = {
        "schema": "chacha20-round20-fresh-w47-factor2-transfer-a347-implementation-v1",
        "attempt_id": ATTEMPT_ID,
        "commitment_state": "frozen_before_A345_result_A346_qualification_A347_order_challenge_candidate_or_prefix",
        "design_sha256": DESIGN_SHA256,
        "A345_result_available_at_commitment": A345_RESULT.exists(),
        "A346_qualification_available_at_commitment": A346.QUALIFICATION.exists(),
        "A347_order_available_at_commitment": False,
        "A347_fresh_challenge_available_at_commitment": False,
        "A347_candidate_or_prefix_available_at_commitment": False,
        "anchors": {
            "design": anchor(DESIGN, DESIGN_SHA256),
            "runner": anchor(Path(__file__)),
            "test": anchor(TEST),
            "reproducer": anchor(REPRO),
        },
    }
    if payload["A345_result_available_at_commitment"] is not False:
        raise RuntimeError("A347 implementation missed the pre-A345-result boundary")
    if payload["A346_qualification_available_at_commitment"] is not False:
        raise RuntimeError("A347 implementation missed the pre-A346-qualification boundary")
    payload["implementation_commitment_sha256"] = canonical_sha256(payload)
    atomic_json(IMPLEMENTATION, payload)
    return payload


def load_implementation() -> dict[str, Any]:
    value = json.loads(IMPLEMENTATION.read_bytes())
    if (
        value.get("schema")
        != "chacha20-round20-fresh-w47-factor2-transfer-a347-implementation-v1"
        or value.get("attempt_id") != ATTEMPT_ID
        or value.get("commitment_state")
        != "frozen_before_A345_result_A346_qualification_A347_order_challenge_candidate_or_prefix"
        or value.get("design_sha256") != DESIGN_SHA256
        or value.get("A345_result_available_at_commitment") is not False
        or value.get("A346_qualification_available_at_commitment") is not False
        or value.get("A347_order_available_at_commitment") is not False
        or value.get("A347_fresh_challenge_available_at_commitment") is not False
        or value.get("A347_candidate_or_prefix_available_at_commitment") is not False
    ):
        raise RuntimeError("A347 implementation commitment semantics differ")
    expected = {"design": DESIGN, "runner": Path(__file__), "test": TEST, "reproducer": REPRO}
    for name, path in expected.items():
        row = value.get("anchors", {}).get(name, {})
        if row.get("path") != relative(path) or row.get("sha256") != file_sha256(path):
            raise RuntimeError(f"A347 implementation anchor differs: {name}")
    semantic = canonical_sha256(
        {key: item for key, item in value.items() if key != "implementation_commitment_sha256"}
    )
    if value.get("implementation_commitment_sha256") != semantic:
        raise RuntimeError("A347 implementation semantic commitment differs")
    return value


def load_a345_source_order() -> dict[str, Any]:
    if file_sha256(A345_ORDER) != A345_ORDER_SHA256:
        raise RuntimeError("A347 A345 pre-target order hash differs")
    value = A345.load_order()
    selected = exact_order(value["selected_order"], "A345 selected source")
    if (
        value.get("order_state")
        != "frozen_before_A345_fresh_challenge_candidate_or_prefix"
        or value.get("selected_order_uint16be_sha256") != SELECTED_ORDER_SHA256
        or order_sha256(selected) != SELECTED_ORDER_SHA256
        or value.get("information_boundary", {}).get(
            "A345_fresh_challenge_available_at_order_freeze"
        )
        is not False
        or value.get("information_boundary", {}).get(
            "A345_target_labels_used_for_order_construction"
        )
        != 0
    ):
        raise RuntimeError("A347 A345 order source semantics differ")
    return value


def freeze_order() -> dict[str, Any]:
    if ORDER.exists():
        raise FileExistsError("A347 order commitment already exists")
    if any(path.exists() for path in (PROTOCOL, PROGRESS, RESULT, CAUSAL, REPORT)):
        raise RuntimeError("A347 order must precede every W47 target artifact")
    design = load_design()
    implementation = load_implementation()
    source = load_a345_source_order()
    selected = exact_order(source["selected_order"], "unchanged W47 transfer")
    payload: dict[str, Any] = {
        "schema": "chacha20-round20-fresh-w47-factor2-transfer-a347-order-v1",
        "attempt_id": ATTEMPT_ID,
        "order_state": "unchanged_A345_factor2_order_frozen_before_A345_result_A346_qualification_or_any_W47_target",
        "design_sha256": DESIGN_SHA256,
        "implementation_sha256": file_sha256(IMPLEMENTATION),
        "implementation_commitment_sha256": implementation[
            "implementation_commitment_sha256"
        ],
        "source_A345_order_sha256": A345_ORDER_SHA256,
        "source_order_uint16be_sha256": SELECTED_ORDER_SHA256,
        "selected_operator": "unchanged_A345_raw_Linf_plus_current_consistency_wavefront_factor2",
        "selected_order_uint16be_sha256": SELECTED_ORDER_SHA256,
        "selected_order": selected,
        "raw_order": source["raw_order"],
        "consistency_order": source["consistency_order"],
        "source_pointwise_factor2_proof": source["pointwise_factor2_proof"],
        "information_boundary": {
            **design["information_boundary"],
            "A345_result_available_at_order_freeze": A345_RESULT.exists(),
            "A346_qualification_available_at_order_freeze": A346.QUALIFICATION.exists(),
            "A347_fresh_challenge_available_at_order_freeze": False,
            "A347_candidate_or_prefix_available_at_order_freeze": False,
            "A347_target_labels_used_for_order_construction": 0,
            "orders_refit_on_A347_target": False,
        },
        "anchors": {
            "design": anchor(DESIGN, DESIGN_SHA256),
            "implementation": anchor(IMPLEMENTATION),
            "A345_order": anchor(A345_ORDER, A345_ORDER_SHA256),
            "A346_protocol": anchor(A346.PROTOCOL, A346_PROTOCOL_SHA256),
        },
    }
    if payload["information_boundary"]["A345_result_available_at_order_freeze"] is not False:
        raise RuntimeError("A347 order missed the pre-A345-result boundary")
    if payload["information_boundary"]["A346_qualification_available_at_order_freeze"] is not False:
        raise RuntimeError("A347 order missed the pre-A346-qualification boundary")
    payload["order_commitment_sha256"] = canonical_sha256(
        {
            "source_A345_order_sha256": A345_ORDER_SHA256,
            "source_order_uint16be_sha256": SELECTED_ORDER_SHA256,
            "selected_operator": payload["selected_operator"],
            "selected_order_uint16be_sha256": SELECTED_ORDER_SHA256,
            "source_pointwise_factor2_proof": payload["source_pointwise_factor2_proof"],
            "information_boundary": payload["information_boundary"],
        }
    )
    atomic_json(ORDER, payload)
    return payload


def load_order() -> dict[str, Any]:
    value = json.loads(ORDER.read_bytes())
    source = load_a345_source_order()
    if (
        value.get("schema")
        != "chacha20-round20-fresh-w47-factor2-transfer-a347-order-v1"
        or value.get("attempt_id") != ATTEMPT_ID
        or value.get("selected_order_uint16be_sha256") != SELECTED_ORDER_SHA256
        or value.get("source_A345_order_sha256") != A345_ORDER_SHA256
        or exact_order(value["selected_order"], "stored W47 order")
        != exact_order(source["selected_order"], "source W46 order")
        or value.get("information_boundary", {}).get(
            "A345_result_available_at_order_freeze"
        )
        is not False
        or value.get("information_boundary", {}).get(
            "A346_qualification_available_at_order_freeze"
        )
        is not False
        or value.get("information_boundary", {}).get(
            "A347_target_labels_used_for_order_construction"
        )
        != 0
    ):
        raise RuntimeError("A347 frozen order semantics differ")
    for row in value["anchors"].values():
        anchor(path_from_ref(row["path"]), row["sha256"])
    load_implementation()
    return value


def load_a346_qualification(expected_sha256: str) -> dict[str, Any]:
    A346.load_protocol(A346_PROTOCOL_SHA256)
    if file_sha256(A346.QUALIFICATION) != expected_sha256:
        raise RuntimeError("A347 A346 qualification artifact hash differs")
    value = json.loads(A346.QUALIFICATION.read_bytes())
    group = value.get("complete_group_gate", {})
    if (
        value.get("schema")
        != "chacha20-round20-w47-sixteen-slab-grouped-engine-a346-qualification-v1"
        or value.get("protocol_sha256") != A346_PROTOCOL_SHA256
        or value.get("production_W47_challenge_used") is not False
        or value.get("production_W47_candidate_used") is not False
        or value.get("synthetic_filter_exact") is not True
        or value.get("matched_control_empty") is not True
        or group.get("logical_candidates") != GROUP_SIZE
        or group.get("complete_W47_group_before_outcome_evaluation") is not True
        or group.get("slabs_executed") != list(range(16))
        or group.get("control_candidates") != []
    ):
        raise RuntimeError("A347 A346 qualification semantics differ")
    return value


def apply_assignment(known_zeroed_key_words: Sequence[int], assignment: int) -> list[int]:
    if len(known_zeroed_key_words) != 8:
        raise ValueError("A347 requires eight ChaCha20 key words")
    if not 0 <= assignment < DOMAIN_SIZE:
        raise ValueError("A347 assignment exceeds W47")
    key = [int(word) & MASK32 for word in known_zeroed_key_words]
    if key[0] != 0 or key[1] & 0x7FFF:
        raise ValueError("A347 known key does not zero the W47 interval")
    key[0] = assignment & MASK32
    key[1] |= assignment >> 32
    return key


def challenge_from_assignment(*, label: str, assignment: int) -> dict[str, Any]:
    if not 0 <= assignment < DOMAIN_SIZE:
        raise ValueError("A347 assignment exceeds W47")
    derived = hashlib.shake_256(label.encode()).digest(48)
    words = W43._words(derived)  # noqa: SLF001
    known = words[:8]
    known[0] = 0
    known[1] &= 0xFFFF8000
    counter = words[8]
    nonce = words[9:12]
    full_key = apply_assignment(known, assignment)
    targets = W43._reference_outputs(full_key, counter, nonce)  # noqa: SLF001
    hashes = [sha256(W43._word_bytes(block)) for block in targets]  # noqa: SLF001
    control = [int(value) for value in targets[0]]
    control[0] ^= 1
    return {
        "challenge_id": "chacha20-r20-w47-a347-fresh-transfer-v1",
        "primitive": "RFC8439_ChaCha20_block_function",
        "rounds": 20,
        "feedforward": True,
        "known_material_derivation_label": label,
        "known_material_derivation_sha256": sha256(derived),
        "known_zeroed_key_words": [int(value) for value in known],
        "known_key_bits": KNOWN_KEY_BITS,
        "unknown_key_bits": WIDTH,
        "unknown_layout": "key_word0_all32_plus_key_word1_low15",
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
        challenge.get("challenge_id") != "chacha20-r20-w47-a347-fresh-transfer-v1"
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
        raise RuntimeError("A347 public challenge shape differs")
    label = str(challenge["known_material_derivation_label"])
    derived = hashlib.shake_256(label.encode()).digest(48)
    words = W43._words(derived)  # noqa: SLF001
    expected_key = words[:8]
    expected_key[0] = 0
    expected_key[1] &= 0xFFFF8000
    targets = [[int(word) & MASK32 for word in block] for block in challenge["target_words"]]
    control = [int(word) & MASK32 for word in challenge["control_target_words"]]
    if (
        sha256(derived) != challenge["known_material_derivation_sha256"]
        or expected_key != challenge["known_zeroed_key_words"]
        or words[8] != challenge["counter_start"]
        or words[9:12] != challenge["nonce_words"]
        or expected_key[0] != 0
        or expected_key[1] & 0x7FFF
        or [sha256(W43._word_bytes(block)) for block in targets]  # noqa: SLF001
        != challenge["target_block_sha256"]
        or control[0] != (targets[0][0] ^ 1)
        or control[1:] != targets[0][1:]
        or sha256(W43._word_bytes(control))  # noqa: SLF001
        != challenge["control_target_block_sha256"]
    ):
        raise RuntimeError("A347 public challenge identity differs")


def fresh_challenge() -> dict[str, Any]:
    label = f"A347|fresh-W47-factor2-transfer|{secrets.token_hex(32)}"
    assignment = secrets.randbits(WIDTH)
    challenge = challenge_from_assignment(label=label, assignment=assignment)
    del assignment
    validate_challenge(challenge)
    return challenge


def materialize(*, expected_a346_qualification_sha256: str) -> dict[str, Any]:
    if any(path.exists() for path in (PROTOCOL, PROGRESS, RESULT, CAUSAL, REPORT)):
        raise FileExistsError("A347 target artifacts already exist")
    design = load_design()
    implementation = load_implementation()
    order = load_order()
    qualification = load_a346_qualification(expected_a346_qualification_sha256)
    challenge = fresh_challenge()
    public_sha = canonical_sha256(challenge)
    boundary = {
        **design["information_boundary"],
        "implementation_frozen_before_W47_challenge": True,
        "selected_order_frozen_before_W47_challenge": True,
        "A346_qualification_verified_before_W47_challenge": True,
        "A347_assignment_absent_from_protocol": True,
        "A347_candidate_or_prefix_available_at_protocol_freeze": False,
        "A347_target_labels_used_for_order_construction": 0,
        "orders_refit_on_A347_target": False,
    }
    payload: dict[str, Any] = {
        "schema": "chacha20-round20-fresh-w47-factor2-transfer-a347-protocol-v1",
        "attempt_id": ATTEMPT_ID,
        "protocol_state": "fresh_W47_target_frozen_after_engine_qualification_implementation_and_unchanged_order_before_candidate_or_prefix",
        "design_sha256": DESIGN_SHA256,
        "implementation_sha256": file_sha256(IMPLEMENTATION),
        "implementation_commitment_sha256": implementation[
            "implementation_commitment_sha256"
        ],
        "order_sha256": file_sha256(ORDER),
        "order_commitment_sha256": order["order_commitment_sha256"],
        "A346_qualification_sha256": expected_a346_qualification_sha256,
        "A346_semantic_qualification_sha256": qualification["qualification_sha256"],
        "selected_operator": order["selected_operator"],
        "selected_order_uint16be_sha256": SELECTED_ORDER_SHA256,
        "selected_order": order["selected_order"],
        "source_A345_order_sha256": A345_ORDER_SHA256,
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
            "A345_order": anchor(A345_ORDER, A345_ORDER_SHA256),
            "A346_protocol": anchor(A346.PROTOCOL, A346_PROTOCOL_SHA256),
            "A346_qualification": anchor(
                A346.QUALIFICATION, expected_a346_qualification_sha256
            ),
            "runner": anchor(Path(__file__)),
            "test": anchor(TEST),
            "reproducer": anchor(REPRO),
        },
    }
    payload["measurement_sha256"] = canonical_sha256(
        {
            "design_sha256": DESIGN_SHA256,
            "implementation_sha256": payload["implementation_sha256"],
            "order_sha256": payload["order_sha256"],
            "order_commitment_sha256": payload["order_commitment_sha256"],
            "A346_qualification_sha256": expected_a346_qualification_sha256,
            "selected_order_uint16be_sha256": SELECTED_ORDER_SHA256,
            "public_challenge_sha256": public_sha,
            "execution_contract": payload["execution_contract"],
            "information_boundary": boundary,
        }
    )
    atomic_json(PROTOCOL, payload)
    return {
        "protocol": relative(PROTOCOL),
        "protocol_sha256": file_sha256(PROTOCOL),
        "public_challenge_sha256": public_sha,
        "selected_operator": payload["selected_operator"],
        "selected_order_uint16be_sha256": SELECTED_ORDER_SHA256,
    }


def load_protocol(expected_protocol_sha256: str) -> dict[str, Any]:
    if file_sha256(PROTOCOL) != expected_protocol_sha256:
        raise RuntimeError("A347 protocol hash differs")
    value = json.loads(PROTOCOL.read_bytes())
    if (
        value.get("schema")
        != "chacha20-round20-fresh-w47-factor2-transfer-a347-protocol-v1"
        or value.get("attempt_id") != ATTEMPT_ID
        or value.get("protocol_state")
        != "fresh_W47_target_frozen_after_engine_qualification_implementation_and_unchanged_order_before_candidate_or_prefix"
        or value.get("selected_order_uint16be_sha256") != SELECTED_ORDER_SHA256
        or value.get("information_boundary", {}).get(
            "A347_assignment_absent_from_protocol"
        )
        is not True
        or value.get("information_boundary", {}).get(
            "A347_candidate_or_prefix_available_at_protocol_freeze"
        )
        is not False
        or value.get("information_boundary", {}).get(
            "A347_target_labels_used_for_order_construction"
        )
        != 0
        or canonical_sha256(value.get("public_challenge"))
        != value.get("public_challenge_sha256")
    ):
        raise RuntimeError("A347 frozen protocol semantics differ")
    for row in value["anchors"].values():
        anchor(path_from_ref(row["path"]), row["sha256"])
    order = load_order()
    if exact_order(value["selected_order"], "protocol selected") != order[
        "selected_order"
    ]:
        raise RuntimeError("A347 protocol/order reconstruction differs")
    validate_challenge(value["public_challenge"])
    return value


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
    values = exact_order(order, "recovery order")
    if not 0 <= start_group < CELLS:
        raise ValueError("A347 resume group lies outside the prefix cover")
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
            observed = A346.filter_complete_prefix(
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
                raise RuntimeError("A347 matched control produced a candidate")
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
                raise RuntimeError("A347 complete W47 group produced multiple filters")
            candidate = factual[0]
            if ((candidate >> WORD0_SUFFIX_BITS) & (CELLS - 1)) != prefix:
                raise RuntimeError("A347 candidate prefix differs")
            found = {
                "candidate": candidate,
                "candidate_hex": f"{candidate:012x}",
                "key_word0": candidate & MASK32,
                "key_word1_low15": candidate >> 32,
                "prefix12": prefix,
                "prefix12_hex": f"{prefix:03x}",
                "executed_prefix_groups": groups,
                "executed_group_dispatches": groups * 16,
                "executed_assignments": groups * GROUP_SIZE,
                "complete_domain_assignments": DOMAIN_SIZE,
                "complete_W47_group_execution_before_stop": True,
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
    raise RuntimeError("A347 exact frozen order exhausted without a factual filter")


def _load_resume(
    *, protocol_sha256: str, order_sha256: str, qualification_sha256: str
) -> tuple[int, float, int, dict[str, Any] | None]:
    if not PROGRESS.exists():
        return 0, 0.0, 0, None
    value = json.loads(PROGRESS.read_bytes())
    if (
        value.get("schema")
        != "chacha20-round20-fresh-w47-factor2-transfer-a347-progress-v1"
        or value.get("protocol_sha256") != protocol_sha256
        or value.get("selected_order_uint16be_sha256") != order_sha256
        or value.get("A346_qualification_sha256") != qualification_sha256
        or value.get("matched_control_candidates") != 0
    ):
        raise RuntimeError("A347 progress fingerprint differs")
    if value.get("status") == "candidate_found":
        excluded = {
            "schema",
            "attempt_id",
            "protocol_sha256",
            "selected_operator",
            "selected_order_uint16be_sha256",
            "A346_qualification_sha256",
            "status",
        }
        return 0, 0.0, 0, {key: item for key, item in value.items() if key not in excluded}
    completed = int(value.get("executed_prefix_groups", -1))
    if not 0 <= completed < CELLS or value.get("factual_filter_candidates") != 0:
        raise RuntimeError("A347 resumable progress state differs")
    return (
        completed,
        float(value.get("gpu_seconds", 0.0)),
        int(value.get("host_instances", 0)),
        None,
    )


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


def rank_panel(prefix: int, order: Mapping[str, Any]) -> dict[str, Any]:
    ranks = {
        "raw_Linf": rank_vector(order["raw_order"])[prefix],
        "current_consistency": rank_vector(order["consistency_order"])[prefix],
        "factor2_wavefront": rank_vector(order["selected_order"])[prefix],
    }
    return {
        "prefix12": prefix,
        "prefix12_hex": f"{prefix:03x}",
        "prefix_ranks_one_based": ranks,
        "selected_rank_one_based": ranks["factor2_wavefront"],
        "selected_gain_bits_vs_complete_domain": math.log2(
            CELLS / ranks["factor2_wavefront"]
        ),
        "selected_domain_reduction_factor": CELLS / ranks["factor2_wavefront"],
        "factor2_bound_for_confirmed_prefix": ranks["factor2_wavefront"]
        <= 2 * min(ranks["raw_Linf"], ranks["current_consistency"]),
        "ranks_computed_only_after_independent_confirmation": True,
    }


def build_causal(payload: Mapping[str, Any]) -> dict[str, Any]:
    sys.path.insert(0, str(DOTCAUSAL_SRC))
    from dotcausal.io import CausalReader, CausalWriter

    terminal = "A347:confirmed_unchanged_factor2_W47_transfer"
    writer = CausalWriter(api_id="a347w47")
    writer._rules = []
    writer.add_rule(
        name="pre_target_W46_order_to_unchanged_W47_order",
        description="The exact A345 pre-target 4096-cell wavefront is copied unchanged before A345 result, A346 qualification or any W47 challenge.",
        pattern=["A345_pre_target_factor2_order", "unchanged_word0_prefix_codec"],
        conclusion="A347_frozen_W47_order",
        confidence_modifier=1.0,
    )
    writer.add_rule(
        name="qualified_sixteen_slab_search_to_factual_model",
        description="Every selected W47 prefix executes sixteen complete 2^31 slabs before any outcome is inspected.",
        pattern=["A347_frozen_W47_order", "A346_exact_W47_group_engine"],
        conclusion="A347_factual_W47_model",
        confidence_modifier=1.0,
    )
    writer.add_rule(
        name="factual_W47_model_to_dual_confirmation",
        description="Independent byte and word implementations confirm all eight full-round output blocks.",
        pattern=["A347_factual_W47_model", "dual_eight_block_confirmation"],
        conclusion=terminal.replace(":", "_"),
        confidence_modifier=1.0,
    )
    writer.add_triplet(
        trigger="A345:pre_target_factor2_W46_order",
        mechanism="unchanged_4096_cell_copy_with_identical_word0_prefix_codec",
        outcome="A347:frozen_factor2_W47_order",
        confidence=1.0,
        source=payload["order_commitment_sha256"],
        quantification=json.dumps(payload["source_pointwise_factor2_proof"], sort_keys=True),
        evidence=json.dumps(payload["information_boundary"], sort_keys=True),
        domain="prospective cross-width order transfer",
        quality_score=1.0,
    )
    writer.add_triplet(
        trigger="A347:frozen_factor2_W47_order",
        mechanism="ordered_complete_sixteen_slab_fullround_search",
        outcome="A347:sole_factual_W47_model",
        confidence=1.0,
        source=payload["execution_sha256"],
        quantification=json.dumps(payload["discovery"], sort_keys=True),
        evidence=json.dumps(payload["rank_analysis"], sort_keys=True),
        domain="fresh full-round ChaCha20 W47 transfer",
        quality_score=1.0,
    )
    writer.add_triplet(
        trigger="A347:sole_factual_W47_model",
        mechanism="dual_independent_eight_block_confirmation",
        outcome=terminal,
        confidence=1.0,
        source=payload["measurement_sha256"],
        quantification=json.dumps(payload["confirmation"], sort_keys=True),
        evidence=payload["evidence_stage"],
        domain="confirmed full-round ChaCha20 W47 transfer",
        quality_score=1.0,
    )
    writer.add_triplet(
        trigger="A345:pre_target_factor2_W46_order",
        mechanism="materialized_unchanged_W47_transfer_confirmation_chain",
        outcome=terminal,
        confidence=1.0,
        source="materialized:A347_unchanged_W47_transfer_chain",
        quantification="exact retained closure",
        evidence=payload["evidence_stage"],
        domain="AI-native retained inference",
        quality_score=1.0,
        is_inferred=True,
    )
    writer.add_cluster(
        name="A347 unchanged factor-two W47 transfer",
        entities=[
            "A345:pre_target_factor2_W46_order",
            "A347:frozen_factor2_W47_order",
            "A347:sole_factual_W47_model",
            terminal,
        ],
    )
    writer.add_gap(
        subject=terminal,
        predicate="next_required_object",
        expected_object_type="W48_transfer_or_second_fresh_W47_replication",
        confidence=1.0,
        suggested_queries=[
            "Does the unchanged wavefront continue to W48 under a target-free 32-slab engine?"
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
        reader.api_id != "a347w47"
        or len(explicit) != 3
        or len(all_rows) != 4
        or len(inferred) != 1
        or len(reader._rules) != 3
        or len(reader._clusters) != 1
        or len(reader._gaps) != 1
    ):
        raise RuntimeError("A347 authentic Causal reopen gate failed")
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


def recover(
    *, expected_protocol_sha256: str, expected_a346_qualification_sha256: str
) -> dict[str, Any]:
    if any(path.exists() for path in (RESULT, CAUSAL, REPORT)):
        raise FileExistsError("A347 result artifacts already exist")
    protocol = load_protocol(expected_protocol_sha256)
    qualification = load_a346_qualification(expected_a346_qualification_sha256)
    if protocol["A346_qualification_sha256"] != expected_a346_qualification_sha256:
        raise RuntimeError("A347 protocol qualification anchor differs")
    order = load_order()
    challenge = protocol["public_challenge"]
    a346_protocol = A346.load_protocol(A346_PROTOCOL_SHA256)
    executable_row = a346_protocol["anchors"]["grouped_executable"]
    executable = path_from_ref(executable_row["path"])
    anchor(executable, executable_row["sha256"])
    placeholder = np.asarray([0, 0], dtype=np.uint32)

    def host_factory() -> Any:
        return A346.A324.A311.A307.A304.GroupedMetalHost(
            executable,
            A346.initial_for_slab(challenge, 0),
            placeholder,
            placeholder,
        )

    def write_progress(row: Mapping[str, Any]) -> None:
        atomic_json(
            PROGRESS,
            {
                "schema": "chacha20-round20-fresh-w47-factor2-transfer-a347-progress-v1",
                "attempt_id": ATTEMPT_ID,
                "protocol_sha256": expected_protocol_sha256,
                "selected_operator": protocol["selected_operator"],
                "selected_order_uint16be_sha256": SELECTED_ORDER_SHA256,
                "A346_qualification_sha256": expected_a346_qualification_sha256,
                **dict(row),
            },
        )

    start, prior_gpu, prior_hosts, completed_discovery = _load_resume(
        protocol_sha256=expected_protocol_sha256,
        order_sha256=SELECTED_ORDER_SHA256,
        qualification_sha256=expected_a346_qualification_sha256,
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
        raise RuntimeError("A347 matched control produced a candidate")
    candidate = int(discovery["candidate"])
    confirmation = confirm(challenge, candidate)
    if confirmation["all_blocks_match"] is not True:
        raise RuntimeError("A347 dual independent confirmation failed")
    ranks = rank_panel(int(discovery["prefix12"]), order)
    if ranks["selected_rank_one_based"] != discovery["executed_prefix_groups"]:
        raise RuntimeError("A347 discovery rank differs from selected order")
    strict_subset = discovery["executed_prefix_groups"] < CELLS
    evidence_stage = (
        "FULLROUND_R20_UNCHANGED_FACTOR2_W47_STRICT_SUBSET_TRANSFER_CONFIRMED"
        if strict_subset
        else "FULLROUND_R20_UNCHANGED_FACTOR2_W47_COMPLETE_DOMAIN_TRANSFER_CONFIRMED"
    )
    payload: dict[str, Any] = {
        "schema": "chacha20-round20-fresh-w47-factor2-transfer-a347-result-v1",
        "attempt_id": ATTEMPT_ID,
        "evidence_stage": evidence_stage,
        "protocol_sha256": expected_protocol_sha256,
        "design_sha256": DESIGN_SHA256,
        "implementation_sha256": protocol["implementation_sha256"],
        "order_sha256": protocol["order_sha256"],
        "order_commitment_sha256": protocol["order_commitment_sha256"],
        "source_A345_order_sha256": A345_ORDER_SHA256,
        "A346_qualification_sha256": expected_a346_qualification_sha256,
        "public_challenge_sha256": protocol["public_challenge_sha256"],
        "selected_operator": protocol["selected_operator"],
        "selected_order_uint16be_sha256": SELECTED_ORDER_SHA256,
        "source_pointwise_factor2_proof": protocol["source_pointwise_factor2_proof"],
        "qualification_gate": {
            "evidence_stage": qualification["evidence_stage"],
            "qualification_sha256": qualification["qualification_sha256"],
            "complete_W47_group_candidates": qualification["complete_group_gate"][
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
            "selected_operator": protocol["selected_operator"],
            "selected_order_uint16be_sha256": SELECTED_ORDER_SHA256,
            "discovery": stable_discovery,
            "A346_qualification_sha256": expected_a346_qualification_sha256,
        }
    )
    payload["measurement_sha256"] = canonical_sha256(
        {
            "discovery": stable_discovery,
            "rank_analysis": ranks,
            "confirmation": confirmation,
            "qualification_gate": payload["qualification_gate"],
            "source_pointwise_factor2_proof": payload["source_pointwise_factor2_proof"],
            "information_boundary": payload["information_boundary"],
        }
    )
    payload["causal"] = build_causal(payload)
    atomic_json(RESULT, payload)
    atomic_bytes(
        REPORT,
        (
            "# A347 — unchanged factor-two full-round ChaCha20 W47 transfer\n\n"
            f"Evidence stage: **{evidence_stage}**\n\n"
            f"- Pre-target selected operator: **{protocol['selected_operator']}**\n"
            f"- W47 execution rank: **{ranks['selected_rank_one_based']} / 4,096**\n"
            f"- Complete candidate evaluations: **{discovery['executed_assignments']:,} / {DOMAIN_SIZE:,}**\n"
            f"- Recovered W47 assignment: **0x{candidate:012x}**\n"
            "- Standard ChaCha20: **20 rounds plus feed-forward**\n"
            "- Every prefix: **sixteen complete 2^31 slabs before outcome evaluation**\n"
            "- Matched one-bit control: **zero candidates**\n"
            "- Dual independent confirmation: **8,192 checked bits**\n"
            "- Authentic AI-native Causal readback: **3 explicit + 1 inferred chain**\n"
        ).encode(),
    )
    return payload


def analyze() -> dict[str, Any]:
    response: dict[str, Any] = {
        "attempt_id": ATTEMPT_ID,
        "design_sha256": DESIGN_SHA256,
        "implementation_frozen": IMPLEMENTATION.exists(),
        "order_frozen": ORDER.exists(),
        "A346_qualification_complete": A346.QUALIFICATION.exists(),
        "protocol_frozen": PROTOCOL.exists(),
        "progress_exists": PROGRESS.exists(),
        "result_complete": RESULT.exists(),
    }
    if ORDER.exists():
        response["order_sha256"] = file_sha256(ORDER)
        response["selected_order_uint16be_sha256"] = SELECTED_ORDER_SHA256
    if PROTOCOL.exists():
        response["protocol_sha256"] = file_sha256(PROTOCOL)
        response["public_challenge_sha256"] = json.loads(PROTOCOL.read_bytes())[
            "public_challenge_sha256"
        ]
    if PROGRESS.exists():
        response["progress"] = json.loads(PROGRESS.read_bytes())
    if RESULT.exists():
        response["result_sha256"] = file_sha256(RESULT)
        response["evidence_stage"] = json.loads(RESULT.read_bytes())["evidence_stage"]
    return response


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    action = parser.add_mutually_exclusive_group(required=True)
    action.add_argument("--analyze", action="store_true")
    action.add_argument("--freeze-implementation", action="store_true")
    action.add_argument("--freeze-order", action="store_true")
    action.add_argument("--materialize", action="store_true")
    action.add_argument("--recover", action="store_true")
    parser.add_argument("--expected-protocol-sha256")
    parser.add_argument("--expected-a346-qualification-sha256")
    args = parser.parse_args()
    if args.freeze_implementation:
        payload = freeze_implementation()
    elif args.freeze_order:
        payload = freeze_order()
    elif args.materialize:
        if not args.expected_a346_qualification_sha256:
            parser.error("--materialize requires --expected-a346-qualification-sha256")
        payload = materialize(
            expected_a346_qualification_sha256=args.expected_a346_qualification_sha256
        )
    elif args.recover:
        if not args.expected_protocol_sha256 or not args.expected_a346_qualification_sha256:
            parser.error(
                "--recover requires --expected-protocol-sha256 and --expected-a346-qualification-sha256"
            )
        payload = recover(
            expected_protocol_sha256=args.expected_protocol_sha256,
            expected_a346_qualification_sha256=args.expected_a346_qualification_sha256,
        )
    else:
        payload = analyze()
    print(json.dumps(payload, indent=2, sort_keys=True), flush=True)


if __name__ == "__main__":
    main()

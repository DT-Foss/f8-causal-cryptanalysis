#!/usr/bin/env python3
"""A345: fresh W46 replication with a pre-target factor-two order portfolio."""

from __future__ import annotations

import argparse
import importlib.util
import inspect
import json
import math
import os
import secrets
import sys
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

import numpy as np

ROOT = Path(__file__).parents[2]
RESEARCH = ROOT / "research"
CONFIGS = RESEARCH / "configs"
RESULTS = RESEARCH / "results/v1"

DESIGN = CONFIGS / "chacha20_round20_fresh_w46_factor2_replication_a345_design_v1.json"
IMPLEMENTATION = CONFIGS / "chacha20_round20_fresh_w46_factor2_replication_a345_implementation_v1.json"
ORDER = RESULTS / "chacha20_round20_fresh_w46_factor2_replication_a345_order_v1.json"
PROTOCOL = CONFIGS / "chacha20_round20_fresh_w46_factor2_replication_a345_v1.json"
PROGRESS = RESULTS / "chacha20_round20_fresh_w46_factor2_replication_a345_progress_v1.json"
RESULT = RESULTS / "chacha20_round20_fresh_w46_factor2_replication_a345_v1.json"
CAUSAL = RESULT.with_suffix(".causal")
REPORT = RESULTS / "chacha20_round20_fresh_w46_factor2_replication_a345_v1.md"
TEST = ROOT / "tests/test_chacha20_round20_fresh_w46_factor2_replication_a345.py"
REPRO = ROOT / "scripts/reproduce_chacha20_round20_fresh_w46_factor2_replication_a345.sh"

A325_RUNNER = RESEARCH / "experiments/chacha20_round20_holdout_selected_w46_recovery_a325.py"
A343_PANEL = RESULTS / "chacha20_round20_w46_pre_result_operator_panel_a343_v1.json"
A344_RESULT = RESULTS / "chacha20_round20_w46_a343_corrected_evaluation_a344_v1.json"
A325_RESULT = RESULTS / "chacha20_round20_holdout_selected_w46_recovery_a325_v1.json"
A324_QUALIFICATION = RESULTS / "chacha20_round20_w46_eight_slab_grouped_engine_a324_qualification_v1.json"

ATTEMPT_ID = "A345"
DESIGN_SHA256 = "03e4b2bc1cc98601d10a504a7d5e4730150e8b907a09a33df77134acda9c4f8f"
A343_PANEL_SHA256 = "aac9c6ec5a46115ea3c0ddc2a15dd0abe5f7a83d4f23c60c6c2d266de8f63525"
A344_RESULT_SHA256 = "8a4176cf2e04ff7d21144778cb28dd6264a05a6ee1360e17a7f4e87e57738fa0"
A325_RESULT_SHA256 = "534d2d769f387bca90b9ab1f2c43a98a6030c1e3c1039270c1d2e109a38d7ce2"
A324_QUALIFICATION_SHA256 = "996dcddfc5f9b9e91f7c77c01aa10747af8f291795dfa04d3e7eaf890047296a"
RAW_ALIAS = "A339/A325_raw_linf_baseline"
CONSISTENCY_ALIAS = "A334/current_consistency_borda_only"
RAW_ORDER_SHA256 = "5d1afc37614fdbe050e9853413a3de7b850b876e9bc5649d3dffcf3e23c9780a"
CONSISTENCY_ORDER_SHA256 = "5a95ee94b89471fe4812f3df4a117ebf4488173a9c48ca2b563bb19224b38b51"
WAVEFRONT_ORDER_SHA256 = "649375a3990b84ec9e6de7d186ca96e70a22461753e3528088d3b1047851b6ae"

WIDTH = 46
PREFIX_BITS = 12
WORD0_SUFFIX_BITS = 20
CELLS = 1 << PREFIX_BITS
GROUP_SIZE = 1 << (WIDTH - PREFIX_BITS)
DOMAIN_SIZE = 1 << WIDTH
HOST_REFRESH_GROUPS = 64
BLOCK_COUNT = 8
MASK32 = 0xFFFFFFFF


def load_module(path: Path, name: str) -> Any:
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot import A345 dependency {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


A325 = load_module(A325_RUNNER, "a345_a325_common")
A324 = A325.A324
W43 = A325.W43
file_sha256 = A325.file_sha256
canonical_sha256 = A325.canonical_sha256
sha256 = A325.sha256
atomic_json = A325.atomic_json
atomic_bytes = A325.atomic_bytes
relative = A325.relative
path_from_ref = A325.path_from_ref
anchor = A325.anchor
DOTCAUSAL_SRC = A325.DOTCAUSAL_SRC


def exact_order(values: Sequence[int], label: str) -> list[int]:
    order = [int(value) for value in values]
    if len(order) != CELLS or set(order) != set(range(CELLS)):
        raise ValueError(f"A345 {label} is not an exact 4,096-cell order")
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


def factor2_wavefront(raw: Sequence[int], consistency: Sequence[int]) -> list[int]:
    raw_ranks = rank_vector(raw)
    consistency_ranks = rank_vector(consistency)
    return exact_order(
        sorted(
            range(CELLS),
            key=lambda cell: (
                min(raw_ranks[cell], consistency_ranks[cell]),
                raw_ranks[cell] + consistency_ranks[cell],
                raw_ranks[cell],
                consistency_ranks[cell],
                cell,
            ),
        ),
        "factor-two wavefront",
    )


def load_design() -> dict[str, Any]:
    if file_sha256(DESIGN) != DESIGN_SHA256:
        raise RuntimeError("A345 design hash differs")
    value = json.loads(DESIGN.read_bytes())
    execution = value.get("execution_contract", {})
    order = value.get("order_contract", {})
    boundary = value.get("information_boundary", {})
    if (
        value.get("schema")
        != "chacha20-round20-fresh-w46-factor2-replication-a345-design-v1"
        or value.get("attempt_id") != ATTEMPT_ID
        or value.get("design_state")
        != "frozen_after_A325_A344_before_A345_implementation_order_fresh_challenge_or_candidate"
        or execution.get("unknown_key_bits") != WIDTH
        or execution.get("candidates_per_prefix_group") != GROUP_SIZE
        or execution.get("complete_domain_assignments") != DOMAIN_SIZE
        or execution.get("prefix_groups") != CELLS
        or execution.get("complete_group_before_success_evaluation") is not True
        or execution.get("early_stop_inside_group") is not False
        or execution.get("full_rounds") != 20
        or execution.get("feedforward_included") is not True
        or order.get("raw_alias") != RAW_ALIAS
        or order.get("consistency_alias") != CONSISTENCY_ALIAS
        or order.get("raw_order_uint16be_sha256") != RAW_ORDER_SHA256
        or order.get("consistency_order_uint16be_sha256")
        != CONSISTENCY_ORDER_SHA256
        or order.get("wavefront_order_uint16be_sha256") != WAVEFRONT_ORDER_SHA256
        or order.get("factor_bound") != 2
        or boundary.get("A345_fresh_challenge_available_at_design_freeze") is not False
        or boundary.get("A345_candidate_or_prefix_available_at_design_freeze") is not False
        or boundary.get("A345_target_labels_used_for_order_construction") != 0
        or boundary.get(
            "fresh_challenge_generated_only_after_implementation_and_order_commitments"
        )
        is not True
        or boundary.get("orders_refit_on_A345_target") is not False
    ):
        raise RuntimeError("A345 frozen design semantics differ")
    anchors = value["source_anchors"]
    for key, source_path in anchors.items():
        if key.endswith("_path"):
            anchor(
                path_from_ref(source_path),
                anchors[key.removesuffix("_path") + "_sha256"],
            )
    return value


def source_orders() -> tuple[list[int], list[int], list[int], dict[str, Any]]:
    if file_sha256(A343_PANEL) != A343_PANEL_SHA256:
        raise RuntimeError("A345 immutable A343 panel hash differs")
    if file_sha256(A344_RESULT) != A344_RESULT_SHA256:
        raise RuntimeError("A345 A344 evaluation hash differs")
    if file_sha256(A325_RESULT) != A325_RESULT_SHA256:
        raise RuntimeError("A345 A325 result hash differs")
    panel = json.loads(A343_PANEL.read_bytes())
    evaluation = json.loads(A344_RESULT.read_bytes())
    if (
        panel.get("schema") != "chacha20-round20-w46-pre-result-operator-panel-a343-v1"
        or panel.get("alias_count") != 73
        or panel.get("unique_order_count") != 57
        or evaluation.get("best_noncontrol_descriptive_winner", {}).get("alias")
        != CONSISTENCY_ALIAS
        or evaluation.get("best_noncontrol_descriptive_winner", {}).get(
            "rank_one_based"
        )
        != 32
        or evaluation.get("alias_rank_panel", {}).get(RAW_ALIAS, {}).get(
            "rank_one_based"
        )
        != 77
    ):
        raise RuntimeError("A345 source selection semantics differ")

    def order_for(alias: str) -> list[int]:
        unique_id = panel["alias_to_unique_id"][alias]
        row = next(
            item for item in panel["unique_orders"] if item["unique_id"] == unique_id
        )
        order = exact_order(row["W46_order"], alias)
        if order_sha256(order) != row["W46_order_uint16be_sha256"]:
            raise RuntimeError(f"A345 frozen source order differs: {alias}")
        return order

    raw = order_for(RAW_ALIAS)
    consistency = order_for(CONSISTENCY_ALIAS)
    wavefront = factor2_wavefront(raw, consistency)
    if (
        order_sha256(raw) != RAW_ORDER_SHA256
        or order_sha256(consistency) != CONSISTENCY_ORDER_SHA256
        or order_sha256(wavefront) != WAVEFRONT_ORDER_SHA256
    ):
        raise RuntimeError("A345 source or wavefront order hash differs")
    raw_ranks = rank_vector(raw)
    consistency_ranks = rank_vector(consistency)
    wavefront_ranks = rank_vector(wavefront)
    ratios = [
        wavefront_ranks[cell] / min(raw_ranks[cell], consistency_ranks[cell])
        for cell in range(CELLS)
    ]
    violations = [cell for cell, ratio in enumerate(ratios) if ratio > 2.0]
    if violations or max(ratios) != 2.0:
        raise RuntimeError("A345 exact factor-two pointwise proof differs")
    proof = {
        "cells_checked": CELLS,
        "violations": len(violations),
        "maximum_ratio": max(ratios),
        "bound": "R_wavefront(cell) <= 2*min(R_raw(cell),R_consistency(cell))",
        "A325_confirmed_prefix12": 0xBAE,
        "A325_raw_rank_one_based": raw_ranks[0xBAE],
        "A325_consistency_rank_one_based": consistency_ranks[0xBAE],
        "A325_wavefront_rank_one_based": wavefront_ranks[0xBAE],
    }
    if proof["A325_wavefront_rank_one_based"] != 62:
        raise RuntimeError("A345 A325 descriptive wavefront rank differs")
    return raw, consistency, wavefront, proof


def freeze_implementation() -> dict[str, Any]:
    if IMPLEMENTATION.exists():
        raise FileExistsError("A345 implementation commitment already exists")
    if any(path.exists() for path in (ORDER, PROTOCOL, PROGRESS, RESULT, CAUSAL, REPORT)):
        raise RuntimeError("A345 implementation must precede every target/order artifact")
    load_design()
    if not TEST.exists() or not REPRO.exists():
        raise FileNotFoundError("A345 test and reproducer must precede commitment")
    payload = {
        "schema": "chacha20-round20-fresh-w46-factor2-replication-a345-implementation-v1",
        "attempt_id": ATTEMPT_ID,
        "commitment_state": "frozen_before_A345_order_fresh_challenge_candidate_or_prefix",
        "design_sha256": DESIGN_SHA256,
        "A345_order_available_at_commitment": False,
        "A345_fresh_challenge_available_at_commitment": False,
        "A345_candidate_or_prefix_available_at_commitment": False,
        "anchors": {
            "design": anchor(DESIGN, DESIGN_SHA256),
            "runner": anchor(Path(__file__)),
            "test": anchor(TEST),
            "reproducer": anchor(REPRO),
        },
    }
    payload["implementation_commitment_sha256"] = canonical_sha256(payload)
    atomic_json(IMPLEMENTATION, payload)
    return payload


def load_implementation() -> dict[str, Any]:
    value = json.loads(IMPLEMENTATION.read_bytes())
    if (
        value.get("schema")
        != "chacha20-round20-fresh-w46-factor2-replication-a345-implementation-v1"
        or value.get("attempt_id") != ATTEMPT_ID
        or value.get("commitment_state")
        != "frozen_before_A345_order_fresh_challenge_candidate_or_prefix"
        or value.get("design_sha256") != DESIGN_SHA256
        or value.get("A345_order_available_at_commitment") is not False
        or value.get("A345_fresh_challenge_available_at_commitment") is not False
        or value.get("A345_candidate_or_prefix_available_at_commitment") is not False
    ):
        raise RuntimeError("A345 implementation commitment semantics differ")
    expected = {"design": DESIGN, "runner": Path(__file__), "test": TEST, "reproducer": REPRO}
    for name, path in expected.items():
        row = value.get("anchors", {}).get(name, {})
        if row.get("path") != relative(path) or row.get("sha256") != file_sha256(path):
            raise RuntimeError(f"A345 implementation anchor differs: {name}")
    expected_commitment = canonical_sha256(
        {key: item for key, item in value.items() if key != "implementation_commitment_sha256"}
    )
    if value.get("implementation_commitment_sha256") != expected_commitment:
        raise RuntimeError("A345 implementation semantic commitment differs")
    return value


def freeze_order() -> dict[str, Any]:
    if ORDER.exists():
        raise FileExistsError("A345 order commitment already exists")
    if any(path.exists() for path in (PROTOCOL, PROGRESS, RESULT, CAUSAL, REPORT)):
        raise RuntimeError("A345 order must precede every target artifact")
    design = load_design()
    implementation = load_implementation()
    raw, consistency, wavefront, proof = source_orders()
    payload: dict[str, Any] = {
        "schema": "chacha20-round20-fresh-w46-factor2-replication-a345-order-v1",
        "attempt_id": ATTEMPT_ID,
        "order_state": "frozen_before_A345_fresh_challenge_candidate_or_prefix",
        "design_sha256": DESIGN_SHA256,
        "implementation_sha256": file_sha256(IMPLEMENTATION),
        "implementation_commitment_sha256": implementation[
            "implementation_commitment_sha256"
        ],
        "selected_operator": "raw_Linf_plus_current_consistency_min_rank_wavefront_factor2",
        "raw_alias": RAW_ALIAS,
        "consistency_alias": CONSISTENCY_ALIAS,
        "raw_order_uint16be_sha256": RAW_ORDER_SHA256,
        "consistency_order_uint16be_sha256": CONSISTENCY_ORDER_SHA256,
        "selected_order_uint16be_sha256": WAVEFRONT_ORDER_SHA256,
        "raw_order": raw,
        "consistency_order": consistency,
        "selected_order": wavefront,
        "pointwise_factor2_proof": proof,
        "information_boundary": {
            **design["information_boundary"],
            "A345_fresh_challenge_available_at_order_freeze": False,
            "A345_candidate_or_prefix_available_at_order_freeze": False,
            "A345_target_labels_used_for_order_construction": 0,
            "orders_refit_on_A345_target": False,
        },
        "anchors": {
            "design": anchor(DESIGN, DESIGN_SHA256),
            "implementation": anchor(IMPLEMENTATION),
            "A343_panel": anchor(A343_PANEL, A343_PANEL_SHA256),
            "A344_result": anchor(A344_RESULT, A344_RESULT_SHA256),
            "A325_result": anchor(A325_RESULT, A325_RESULT_SHA256),
        },
    }
    payload["order_commitment_sha256"] = canonical_sha256(
        {
            "selected_operator": payload["selected_operator"],
            "raw_order_uint16be_sha256": RAW_ORDER_SHA256,
            "consistency_order_uint16be_sha256": CONSISTENCY_ORDER_SHA256,
            "selected_order_uint16be_sha256": WAVEFRONT_ORDER_SHA256,
            "pointwise_factor2_proof": proof,
            "information_boundary": payload["information_boundary"],
        }
    )
    atomic_json(ORDER, payload)
    return payload


def load_order() -> dict[str, Any]:
    value = json.loads(ORDER.read_bytes())
    if (
        value.get("schema")
        != "chacha20-round20-fresh-w46-factor2-replication-a345-order-v1"
        or value.get("attempt_id") != ATTEMPT_ID
        or value.get("order_state")
        != "frozen_before_A345_fresh_challenge_candidate_or_prefix"
        or value.get("design_sha256") != DESIGN_SHA256
        or value.get("selected_order_uint16be_sha256") != WAVEFRONT_ORDER_SHA256
        or value.get("information_boundary", {}).get(
            "A345_fresh_challenge_available_at_order_freeze"
        )
        is not False
        or value.get("information_boundary", {}).get(
            "A345_target_labels_used_for_order_construction"
        )
        != 0
    ):
        raise RuntimeError("A345 frozen order semantics differ")
    raw, consistency, wavefront, proof = source_orders()
    if (
        exact_order(value["raw_order"], "stored raw") != raw
        or exact_order(value["consistency_order"], "stored consistency") != consistency
        or exact_order(value["selected_order"], "stored selected") != wavefront
        or value.get("pointwise_factor2_proof") != proof
    ):
        raise RuntimeError("A345 stored order reconstruction differs")
    for row in value["anchors"].values():
        anchor(path_from_ref(row["path"]), row["sha256"])
    load_implementation()
    return value


def challenge_from_assignment(*, label: str, assignment: int) -> dict[str, Any]:
    challenge = A325.challenge_from_assignment(label=label, assignment=assignment)
    challenge["challenge_id"] = "chacha20-r20-w46-a345-fresh-replication-v1"
    return challenge


def validate_challenge(challenge: Mapping[str, Any]) -> None:
    if challenge.get("challenge_id") != "chacha20-r20-w46-a345-fresh-replication-v1":
        raise RuntimeError("A345 public challenge id differs")
    translated = dict(challenge)
    translated["challenge_id"] = "chacha20-r20-w46-a325-fresh-v1"
    A325.validate_challenge(translated)


def fresh_challenge() -> dict[str, Any]:
    label = f"A345|fresh-W46-factor2-replication|{secrets.token_hex(32)}"
    assignment = secrets.randbits(WIDTH)
    challenge = challenge_from_assignment(label=label, assignment=assignment)
    del assignment
    validate_challenge(challenge)
    return challenge


def materialize(*, expected_a324_qualification_sha256: str) -> dict[str, Any]:
    if any(path.exists() for path in (PROTOCOL, PROGRESS, RESULT, CAUSAL, REPORT)):
        raise FileExistsError("A345 target artifacts already exist")
    design = load_design()
    implementation = load_implementation()
    order = load_order()
    qualification = A325.load_a324_qualification(expected_a324_qualification_sha256)
    if expected_a324_qualification_sha256 != A324_QUALIFICATION_SHA256:
        raise RuntimeError("A345 qualification hash differs from design")
    challenge = fresh_challenge()
    public_sha = canonical_sha256(challenge)
    boundary = {
        **design["information_boundary"],
        "implementation_frozen_before_A345_challenge": True,
        "selected_order_frozen_before_A345_challenge": True,
        "A345_assignment_absent_from_protocol": True,
        "A345_candidate_or_prefix_available_at_protocol_freeze": False,
        "A345_target_labels_used_for_order_construction": 0,
        "orders_refit_on_A345_target": False,
    }
    payload: dict[str, Any] = {
        "schema": "chacha20-round20-fresh-w46-factor2-replication-a345-protocol-v1",
        "attempt_id": ATTEMPT_ID,
        "protocol_state": "fresh_W46_target_frozen_after_implementation_and_factor2_order_before_candidate_or_prefix",
        "design_sha256": DESIGN_SHA256,
        "implementation_sha256": file_sha256(IMPLEMENTATION),
        "implementation_commitment_sha256": implementation[
            "implementation_commitment_sha256"
        ],
        "order_sha256": file_sha256(ORDER),
        "order_commitment_sha256": order["order_commitment_sha256"],
        "A324_qualification_sha256": expected_a324_qualification_sha256,
        "A324_semantic_qualification_sha256": qualification["qualification_sha256"],
        "selected_operator": order["selected_operator"],
        "selected_order_uint16be_sha256": WAVEFRONT_ORDER_SHA256,
        "selected_order": order["selected_order"],
        "source_order_hashes": {
            "raw_Linf": RAW_ORDER_SHA256,
            "current_consistency": CONSISTENCY_ORDER_SHA256,
        },
        "pointwise_factor2_proof": order["pointwise_factor2_proof"],
        "public_challenge": challenge,
        "public_challenge_sha256": public_sha,
        "execution_contract": design["execution_contract"],
        "information_boundary": boundary,
        "anchors": {
            "design": anchor(DESIGN, DESIGN_SHA256),
            "implementation": anchor(IMPLEMENTATION),
            "order": anchor(ORDER),
            "A324_qualification": anchor(
                A324_QUALIFICATION, expected_a324_qualification_sha256
            ),
            "A343_panel": anchor(A343_PANEL, A343_PANEL_SHA256),
            "A344_result": anchor(A344_RESULT, A344_RESULT_SHA256),
            "A325_result": anchor(A325_RESULT, A325_RESULT_SHA256),
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
            "A324_qualification_sha256": expected_a324_qualification_sha256,
            "selected_order_uint16be_sha256": WAVEFRONT_ORDER_SHA256,
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
        "selected_order_uint16be_sha256": WAVEFRONT_ORDER_SHA256,
    }


def load_protocol(expected_protocol_sha256: str) -> dict[str, Any]:
    if file_sha256(PROTOCOL) != expected_protocol_sha256:
        raise RuntimeError("A345 protocol hash differs")
    value = json.loads(PROTOCOL.read_bytes())
    if (
        value.get("schema")
        != "chacha20-round20-fresh-w46-factor2-replication-a345-protocol-v1"
        or value.get("attempt_id") != ATTEMPT_ID
        or value.get("protocol_state")
        != "fresh_W46_target_frozen_after_implementation_and_factor2_order_before_candidate_or_prefix"
        or value.get("selected_order_uint16be_sha256") != WAVEFRONT_ORDER_SHA256
        or value.get("information_boundary", {}).get(
            "A345_assignment_absent_from_protocol"
        )
        is not True
        or value.get("information_boundary", {}).get(
            "A345_candidate_or_prefix_available_at_protocol_freeze"
        )
        is not False
        or value.get("information_boundary", {}).get(
            "A345_target_labels_used_for_order_construction"
        )
        != 0
        or canonical_sha256(value.get("public_challenge"))
        != value.get("public_challenge_sha256")
    ):
        raise RuntimeError("A345 frozen protocol semantics differ")
    for row in value["anchors"].values():
        anchor(path_from_ref(row["path"]), row["sha256"])
    order = load_order()
    if (
        exact_order(value["selected_order"], "protocol selected")
        != order["selected_order"]
        or value["order_commitment_sha256"] != order["order_commitment_sha256"]
    ):
        raise RuntimeError("A345 protocol/order reconstruction differs")
    validate_challenge(value["public_challenge"])
    return value


def _load_resume(
    *, protocol_sha256: str, order_sha256: str, qualification_sha256: str
) -> tuple[int, float, int, dict[str, Any] | None]:
    if not PROGRESS.exists():
        return 0, 0.0, 0, None
    value = json.loads(PROGRESS.read_bytes())
    if (
        value.get("schema")
        != "chacha20-round20-fresh-w46-factor2-replication-a345-progress-v1"
        or value.get("protocol_sha256") != protocol_sha256
        or value.get("selected_order_uint16be_sha256") != order_sha256
        or value.get("A324_qualification_sha256") != qualification_sha256
        or value.get("matched_control_candidates") != 0
    ):
        raise RuntimeError("A345 progress fingerprint differs")
    if value.get("status") == "candidate_found":
        excluded = {
            "schema",
            "attempt_id",
            "protocol_sha256",
            "selected_operator",
            "selected_order_uint16be_sha256",
            "A324_qualification_sha256",
            "status",
        }
        return 0, 0.0, 0, {key: item for key, item in value.items() if key not in excluded}
    completed = int(value.get("executed_prefix_groups", -1))
    if not 0 <= completed < CELLS or value.get("factual_filter_candidates") != 0:
        raise RuntimeError("A345 resumable progress state differs")
    return (
        completed,
        float(value.get("gpu_seconds", 0.0)),
        int(value.get("host_instances", 0)),
        None,
    )


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

    terminal = "A345:confirmed_fresh_factor2_W46_replication"
    writer = CausalWriter(api_id="a345rep")
    writer._rules = []
    writer.add_rule(
        name="immutable_sources_to_pre_target_factor2_order",
        description="The A325 raw-Linf order and A334 consistency order form a pointwise factor-two wavefront before the fresh target exists.",
        pattern=["A343_immutable_source_orders", "A344_replication_selection"],
        conclusion="A345_pre_target_factor2_order",
        confidence_modifier=1.0,
    )
    writer.add_rule(
        name="complete_group_search_to_factual_model",
        description="Every selected prefix executes eight complete slabs before a factual or control outcome is inspected.",
        pattern=["A345_pre_target_factor2_order", "A324_exact_W46_group_engine"],
        conclusion="A345_factual_W46_model",
        confidence_modifier=1.0,
    )
    writer.add_rule(
        name="factual_model_to_dual_confirmation",
        description="Independent byte and word implementations confirm all eight full-round output blocks.",
        pattern=["A345_factual_W46_model", "dual_eight_block_confirmation"],
        conclusion=terminal.replace(":", "_"),
        confidence_modifier=1.0,
    )
    writer.add_triplet(
        trigger="A343:immutable_raw_and_consistency_orders",
        mechanism="pre_target_min_rank_wavefront_with_exact_factor2_bound",
        outcome="A345:frozen_factor2_W46_replication_order",
        confidence=1.0,
        source=payload["order_commitment_sha256"],
        quantification=json.dumps(payload["pointwise_factor2_proof"], sort_keys=True),
        evidence=json.dumps(payload["information_boundary"], sort_keys=True),
        domain="prospective W46 order construction",
        quality_score=1.0,
    )
    writer.add_triplet(
        trigger="A345:frozen_factor2_W46_replication_order",
        mechanism="ordered_complete_eight_slab_fullround_search",
        outcome="A345:sole_factual_W46_model",
        confidence=1.0,
        source=payload["execution_sha256"],
        quantification=json.dumps(payload["discovery"], sort_keys=True),
        evidence=json.dumps(payload["rank_analysis"], sort_keys=True),
        domain="fresh full-round ChaCha20 W46 replication",
        quality_score=1.0,
    )
    writer.add_triplet(
        trigger="A345:sole_factual_W46_model",
        mechanism="dual_independent_eight_block_confirmation",
        outcome=terminal,
        confidence=1.0,
        source=payload["measurement_sha256"],
        quantification=json.dumps(payload["confirmation"], sort_keys=True),
        evidence=payload["evidence_stage"],
        domain="confirmed full-round ChaCha20 W46 replication",
        quality_score=1.0,
    )
    writer.add_triplet(
        trigger="A343:immutable_raw_and_consistency_orders",
        mechanism="materialized_pre_target_order_to_confirmed_replication_chain",
        outcome=terminal,
        confidence=1.0,
        source="materialized:A345_factor2_W46_replication_chain",
        quantification="exact retained closure",
        evidence=payload["evidence_stage"],
        domain="AI-native retained inference",
        quality_score=1.0,
        is_inferred=True,
    )
    writer.add_cluster(
        name="A345 fresh factor-two W46 replication",
        entities=[
            "A343:immutable_raw_and_consistency_orders",
            "A345:frozen_factor2_W46_replication_order",
            "A345:sole_factual_W46_model",
            terminal,
        ],
    )
    writer.add_gap(
        subject=terminal,
        predicate="next_required_object",
        expected_object_type="W47_factor2_transfer_or_second_fresh_W46_replication",
        confidence=1.0,
        suggested_queries=[
            "Does the unchanged factor-two order transfer to W47 under a target-free 16-slab engine?"
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
        reader.api_id != "a345rep"
        or len(explicit) != 3
        or len(all_rows) != 4
        or len(inferred) != 1
        or len(reader._rules) != 3
        or len(reader._clusters) != 1
        or len(reader._gaps) != 1
    ):
        raise RuntimeError("A345 authentic Causal reopen gate failed")
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
    *, expected_protocol_sha256: str, expected_a324_qualification_sha256: str
) -> dict[str, Any]:
    if any(path.exists() for path in (RESULT, CAUSAL, REPORT)):
        raise FileExistsError("A345 result artifacts already exist")
    protocol = load_protocol(expected_protocol_sha256)
    qualification = A325.load_a324_qualification(
        expected_a324_qualification_sha256
    )
    if protocol["A324_qualification_sha256"] != expected_a324_qualification_sha256:
        raise RuntimeError("A345 protocol qualification anchor differs")
    order = load_order()
    challenge = protocol["public_challenge"]
    a324_protocol = A324.load_protocol(A325.A324_PROTOCOL_SHA256)
    executable_row = a324_protocol["anchors"]["grouped_executable"]
    executable = path_from_ref(executable_row["path"])
    anchor(executable, executable_row["sha256"])
    placeholder = np.asarray([0, 0], dtype=np.uint32)

    def host_factory() -> Any:
        return A324.A311.A307.A304.GroupedMetalHost(
            executable,
            A324.initial_for_slab(challenge, 0),
            placeholder,
            placeholder,
        )

    def write_progress(row: Mapping[str, Any]) -> None:
        atomic_json(
            PROGRESS,
            {
                "schema": "chacha20-round20-fresh-w46-factor2-replication-a345-progress-v1",
                "attempt_id": ATTEMPT_ID,
                "protocol_sha256": expected_protocol_sha256,
                "selected_operator": protocol["selected_operator"],
                "selected_order_uint16be_sha256": protocol[
                    "selected_order_uint16be_sha256"
                ],
                "A324_qualification_sha256": expected_a324_qualification_sha256,
                **dict(row),
            },
        )

    start, prior_gpu, prior_hosts, completed_discovery = _load_resume(
        protocol_sha256=expected_protocol_sha256,
        order_sha256=protocol["selected_order_uint16be_sha256"],
        qualification_sha256=expected_a324_qualification_sha256,
    )
    discovery = completed_discovery or A325.ordered_discovery(
        host_factory=host_factory,
        challenge=challenge,
        order=protocol["selected_order"],
        start_group=start,
        prior_gpu_seconds=prior_gpu,
        prior_host_instances=prior_hosts,
        progress_callback=write_progress,
    )
    if discovery["matched_control_candidates"] != 0:
        raise RuntimeError("A345 matched control produced a candidate")
    candidate = int(discovery["candidate"])
    confirmation = A325.confirm(challenge, candidate)
    if confirmation["all_blocks_match"] is not True:
        raise RuntimeError("A345 dual independent confirmation failed")
    ranks = rank_panel(int(discovery["prefix12"]), order)
    if ranks["selected_rank_one_based"] != discovery["executed_prefix_groups"]:
        raise RuntimeError("A345 discovery rank differs from selected order")
    strict_subset = discovery["executed_prefix_groups"] < CELLS
    evidence_stage = (
        "FULLROUND_R20_FRESH_FACTOR2_W46_STRICT_SUBSET_REPLICATION_CONFIRMED"
        if strict_subset
        else "FULLROUND_R20_FRESH_FACTOR2_W46_COMPLETE_DOMAIN_REPLICATION_CONFIRMED"
    )
    payload: dict[str, Any] = {
        "schema": "chacha20-round20-fresh-w46-factor2-replication-a345-result-v1",
        "attempt_id": ATTEMPT_ID,
        "evidence_stage": evidence_stage,
        "protocol_sha256": expected_protocol_sha256,
        "design_sha256": DESIGN_SHA256,
        "implementation_sha256": protocol["implementation_sha256"],
        "order_sha256": protocol["order_sha256"],
        "order_commitment_sha256": protocol["order_commitment_sha256"],
        "A324_qualification_sha256": expected_a324_qualification_sha256,
        "public_challenge_sha256": protocol["public_challenge_sha256"],
        "selected_operator": protocol["selected_operator"],
        "selected_order_uint16be_sha256": WAVEFRONT_ORDER_SHA256,
        "source_order_hashes": protocol["source_order_hashes"],
        "pointwise_factor2_proof": protocol["pointwise_factor2_proof"],
        "qualification_gate": {
            "evidence_stage": qualification["evidence_stage"],
            "qualification_sha256": qualification["qualification_sha256"],
            "complete_W46_group_candidates": qualification["complete_group_gate"][
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
            "selected_order_uint16be_sha256": WAVEFRONT_ORDER_SHA256,
            "discovery": stable_discovery,
            "A324_qualification_sha256": expected_a324_qualification_sha256,
        }
    )
    payload["measurement_sha256"] = canonical_sha256(
        {
            "discovery": stable_discovery,
            "rank_analysis": ranks,
            "confirmation": confirmation,
            "qualification_gate": payload["qualification_gate"],
            "pointwise_factor2_proof": payload["pointwise_factor2_proof"],
            "information_boundary": payload["information_boundary"],
        }
    )
    payload["causal"] = build_causal(payload)
    atomic_json(RESULT, payload)
    atomic_bytes(
        REPORT,
        (
            "# A345 — fresh factor-two full-round ChaCha20 W46 replication\n\n"
            f"Evidence stage: **{evidence_stage}**\n\n"
            f"- Pre-target selected operator: **{protocol['selected_operator']}**\n"
            f"- W46 execution rank: **{ranks['selected_rank_one_based']} / 4,096**\n"
            f"- Complete candidate evaluations: **{discovery['executed_assignments']:,} / {DOMAIN_SIZE:,}**\n"
            f"- Recovered W46 assignment: **0x{candidate:012x}**\n"
            "- Standard ChaCha20: **20 rounds plus feed-forward**\n"
            "- Every prefix: **eight complete 2^31 slabs before outcome evaluation**\n"
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
        "protocol_frozen": PROTOCOL.exists(),
        "progress_exists": PROGRESS.exists(),
        "result_complete": RESULT.exists(),
    }
    if ORDER.exists():
        response["order_sha256"] = file_sha256(ORDER)
        response["selected_order_uint16be_sha256"] = WAVEFRONT_ORDER_SHA256
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
    parser.add_argument(
        "--expected-a324-qualification-sha256", default=A324_QUALIFICATION_SHA256
    )
    args = parser.parse_args()
    if args.freeze_implementation:
        payload = freeze_implementation()
    elif args.freeze_order:
        payload = freeze_order()
    elif args.materialize:
        payload = materialize(
            expected_a324_qualification_sha256=args.expected_a324_qualification_sha256
        )
    elif args.recover:
        if not args.expected_protocol_sha256:
            parser.error("--recover requires --expected-protocol-sha256")
        payload = recover(
            expected_protocol_sha256=args.expected_protocol_sha256,
            expected_a324_qualification_sha256=args.expected_a324_qualification_sha256,
        )
    else:
        payload = analyze()
    print(json.dumps(payload, indent=2, sort_keys=True), flush=True)


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""A377: execute A376's sealed-target factor-four W46 order and confirm the model."""

from __future__ import annotations

import argparse
import importlib.util
import inspect
import json
import math
import os
import sys
from collections.abc import Mapping
from pathlib import Path
from typing import Any

import numpy as np

ROOT = Path(__file__).parents[2]
RESEARCH = ROOT / "research"
CONFIGS = RESEARCH / "configs"
RESULTS = RESEARCH / "results/v1"

DESIGN = CONFIGS / "chacha20_round20_w46_a376_order_recovery_a377_design_v1.json"
IMPLEMENTATION = CONFIGS / "chacha20_round20_w46_a376_order_recovery_a377_implementation_v1.json"
PROGRESS = RESULTS / "chacha20_round20_w46_a376_order_recovery_a377_progress_v1.json"
RESULT = RESULTS / "chacha20_round20_w46_a376_order_recovery_a377_v1.json"
CAUSAL = RESULT.with_suffix(".causal")
REPORT = RESULT.with_suffix(".md")
TEST = ROOT / "tests/test_chacha20_round20_w46_a376_order_recovery_a377.py"
REPRO = ROOT / "scripts/reproduce_chacha20_round20_w46_a376_order_recovery_a377.sh"

A361_RUNNER = RESEARCH / "experiments/chacha20_round20_w46_fresh_a360_reader_deployment_a361.py"
A376_RUNNER = RESEARCH / "experiments/chacha20_round20_w46_a375_reader_sealed_a361_order_a376.py"
A361_PROTOCOL = CONFIGS / "chacha20_round20_w46_fresh_a360_reader_deployment_a361_protocol_v1.json"
A324_QUALIFICATION = (
    RESULTS / "chacha20_round20_w46_eight_slab_grouped_engine_a324_qualification_v1.json"
)
A376_DESIGN = CONFIGS / "chacha20_round20_w46_a375_reader_sealed_a361_order_a376_design_v1.json"
A376_IMPLEMENTATION = (
    CONFIGS / "chacha20_round20_w46_a375_reader_sealed_a361_order_a376_implementation_v1.json"
)
A376_ORDER = RESULTS / "chacha20_round20_w46_a375_reader_sealed_a361_order_a376_v1.json"

ATTEMPT_ID = "A377"
DESIGN_SHA256 = "b52928233edd7aed7e75917ee31832d6bd1f184bef0b0e35f519b92bed5afa51"
A361_PROTOCOL_SHA256 = "3396559ab6fde25ef12f5fdcae68e33585234926885b88b136c1f4af47c13228"
A324_QUALIFICATION_SHA256 = "996dcddfc5f9b9e91f7c77c01aa10747af8f291795dfa04d3e7eaf890047296a"
A376_DESIGN_SHA256 = "d382730a341bc46e5de68cb3b6d4fc0d7c1e21df4be7732f3dc95bca9bc9cffb"
A376_IMPLEMENTATION_SHA256 = "978f9611107ead21d13583f3b748732e5f62d043df085a9f96b159a18b09ec38"
A376_ORDER_SHA256 = "a10bbd8aa3e41ae230e30c435f6966665007322c2b02f82cdc678254d44b6bf3"
GROUPS = 4096
DOMAIN_SIZE = 1 << 46
SELECTED_OPERATOR = "A375_wide_consensus_factor4_wavefront"
DOTCAUSAL_SRC = Path("/Users/bhkmie/Documents/Forschung/O1/vendor/fabel/dotcausal_package/src")


def load_module(path: Path, name: str) -> Any:
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot import A377 dependency {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


A361 = load_module(A361_RUNNER, "a377_a361")
A376 = load_module(A376_RUNNER, "a377_a376")
A325 = A361.A325
A324 = A361.A324
file_sha256 = A361.file_sha256
canonical_sha256 = A361.canonical_sha256
atomic_json = A361.atomic_json
atomic_bytes = A361.atomic_bytes
relative = A361.relative
path_from_ref = A361.path_from_ref
anchor = A361.anchor


def load_design() -> dict[str, Any]:
    if file_sha256(DESIGN) != DESIGN_SHA256:
        raise RuntimeError("A377 design hash differs")
    value = json.loads(DESIGN.read_bytes())
    execution = value.get("execution_contract", {})
    ranks = value.get("rank_contract", {})
    confirmation = value.get("confirmation_contract", {})
    boundary = value.get("information_boundary", {})
    if (
        value.get("schema") != "chacha20-round20-w46-a376-order-recovery-a377-design-v1"
        or value.get("attempt_id") != ATTEMPT_ID
        or value.get("design_state")
        != "frozen_after_A376_factor4_order_before_any_A377_candidate_prefix_or_recovery_execution"
        or execution.get("rounds") != 20
        or execution.get("feed_forward") is not True
        or execution.get("public_output_blocks") != 8
        or execution.get("unknown_key_bits") != 46
        or execution.get("complete_group_suffix_bits") != 34
        or execution.get("group_count") != GROUPS
        or execution.get("maximum_complete_domain_assignments") != DOMAIN_SIZE
        or ranks.get("pointwise_factor4_check")
        != "selected_portfolio_rank <= 4 * best_source_rank"
        or ranks.get("rank_readback_only_after_independent_confirmation") is not True
        or confirmation.get("all_eight_output_blocks_required") is not True
        or confirmation.get("total_cross_implementation_output_bits_required") != 8192
        or confirmation.get("matched_control_candidates_required") != 0
        or boundary.get("A376_order_available_at_design_freeze") is not True
        or boundary.get("A376_order_file_sha256") != A376_ORDER_SHA256
        or boundary.get("A361_secret_or_true_prefix_available_at_design_freeze") is not False
        or boundary.get("A377_candidate_or_prefix_available_at_design_freeze") is not False
        or boundary.get("A377_candidate_assignments_executed_at_design_freeze") != 0
        or boundary.get("reader_refits") != 0
        or boundary.get("target_labels_used_for_A376_order") != 0
    ):
        raise RuntimeError("A377 frozen design semantics differ")
    for name, path_value in value["source_anchors"].items():
        if name.endswith("_path"):
            stem = name.removesuffix("_path")
            anchor(ROOT / path_value, value["source_anchors"][f"{stem}_sha256"])
    return value


def freeze_implementation() -> dict[str, Any]:
    if IMPLEMENTATION.exists():
        raise FileExistsError("A377 implementation already exists")
    if any(path.exists() for path in (PROGRESS, RESULT, CAUSAL, REPORT)):
        raise RuntimeError("A377 implementation must precede every recovery artifact")
    load_design()
    order = A376.load_order(A376_ORDER_SHA256)
    if not TEST.exists() or not REPRO.exists():
        raise FileNotFoundError("A377 test and reproducer must exist before freeze")
    payload: dict[str, Any] = {
        "schema": "chacha20-round20-w46-a376-order-recovery-a377-implementation-v1",
        "attempt_id": ATTEMPT_ID,
        "commitment_state": "frozen_after_A376_order_before_A377_candidate_prefix_or_execution",
        "design_sha256": DESIGN_SHA256,
        "A376_order_file_sha256": A376_ORDER_SHA256,
        "A376_order_commitment_sha256": order["order_commitment_sha256"],
        "selected_order_uint16be_sha256": order["selected_order_uint16be_sha256"],
        "source_orders_sha256": order["source_orders_sha256"],
        "model_role_order": order["model_role_order"],
        "A361_secret_or_true_prefix_available_at_implementation_freeze": False,
        "candidate_or_prefix_available_at_implementation_freeze": False,
        "candidate_assignments_executed_at_implementation_freeze": 0,
        "anchors": {
            "design": anchor(DESIGN, DESIGN_SHA256),
            "A361_protocol": anchor(A361_PROTOCOL, A361_PROTOCOL_SHA256),
            "A324_qualification": anchor(A324_QUALIFICATION, A324_QUALIFICATION_SHA256),
            "A376_design": anchor(A376_DESIGN, A376_DESIGN_SHA256),
            "A376_implementation": anchor(A376_IMPLEMENTATION, A376_IMPLEMENTATION_SHA256),
            "A376_order": anchor(A376_ORDER, A376_ORDER_SHA256),
            "runner": anchor(Path(__file__)),
            "test": anchor(TEST),
            "reproducer": anchor(REPRO),
        },
    }
    payload["implementation_commitment_sha256"] = canonical_sha256(payload)
    atomic_json(IMPLEMENTATION, payload)
    if PROGRESS.exists() or RESULT.exists():
        IMPLEMENTATION.unlink(missing_ok=True)
        raise RuntimeError("A377 implementation did not precede recovery execution")
    return payload


def load_implementation(expected_sha256: str) -> dict[str, Any]:
    if file_sha256(IMPLEMENTATION) != expected_sha256:
        raise RuntimeError("A377 implementation hash differs")
    value = json.loads(IMPLEMENTATION.read_bytes())
    if (
        value.get("schema")
        != "chacha20-round20-w46-a376-order-recovery-a377-implementation-v1"
        or value.get("attempt_id") != ATTEMPT_ID
        or value.get("commitment_state")
        != "frozen_after_A376_order_before_A377_candidate_prefix_or_execution"
        or value.get("design_sha256") != DESIGN_SHA256
        or value.get("A376_order_file_sha256") != A376_ORDER_SHA256
        or value.get("A361_secret_or_true_prefix_available_at_implementation_freeze")
        is not False
        or value.get("candidate_or_prefix_available_at_implementation_freeze") is not False
        or value.get("candidate_assignments_executed_at_implementation_freeze") != 0
    ):
        raise RuntimeError("A377 implementation semantics differ")
    paths = {
        "design": DESIGN,
        "A361_protocol": A361_PROTOCOL,
        "A324_qualification": A324_QUALIFICATION,
        "A376_design": A376_DESIGN,
        "A376_implementation": A376_IMPLEMENTATION,
        "A376_order": A376_ORDER,
        "runner": Path(__file__),
        "test": TEST,
        "reproducer": REPRO,
    }
    for name, path in paths.items():
        row = value["anchors"][name]
        if row.get("path") != relative(path) or row.get("sha256") != file_sha256(path):
            raise RuntimeError(f"A377 implementation anchor differs: {name}")
    unsigned = {key: item for key, item in value.items() if key != "implementation_commitment_sha256"}
    if value.get("implementation_commitment_sha256") != canonical_sha256(unsigned):
        raise RuntimeError("A377 implementation commitment differs")
    return value


def load_resume(
    *, protocol_sha256: str, order_file_sha256: str, order_hash: str, qualification_sha256: str
) -> tuple[int, float, int, dict[str, Any] | None]:
    if not PROGRESS.exists():
        return 0, 0.0, 0, None
    value = json.loads(PROGRESS.read_bytes())
    if (
        value.get("schema") != "chacha20-round20-w46-a376-order-recovery-a377-progress-v1"
        or value.get("attempt_id") != ATTEMPT_ID
        or value.get("protocol_sha256") != protocol_sha256
        or value.get("A376_order_file_sha256") != order_file_sha256
        or value.get("selected_order_uint16be_sha256") != order_hash
        or value.get("A324_qualification_sha256") != qualification_sha256
        or value.get("matched_control_candidates") != 0
    ):
        raise RuntimeError("A377 progress fingerprint differs")
    if value.get("status") == "candidate_found":
        excluded = {
            "schema",
            "attempt_id",
            "protocol_sha256",
            "selected_operator",
            "A376_order_file_sha256",
            "selected_order_uint16be_sha256",
            "source_orders_sha256",
            "A324_qualification_sha256",
            "status",
        }
        return 0, 0.0, 0, {key: item for key, item in value.items() if key not in excluded}
    completed = int(value.get("executed_prefix_groups", -1))
    if not 0 <= completed < GROUPS or value.get("factual_filter_candidates") != 0:
        raise RuntimeError("A377 resumable progress state differs")
    return (
        completed,
        float(value.get("gpu_seconds", 0.0)),
        int(value.get("host_instances", 0)),
        None,
    )


def build_causal(payload: Mapping[str, Any]) -> dict[str, Any]:
    sys.path.insert(0, str(DOTCAUSAL_SRC))
    from dotcausal.io import CausalReader, CausalWriter

    portfolio = "A375:frozen_four_reader_portfolio"
    ordered = "A376:sealed_target_exact_factor4_group_order"
    searched = "A377:complete_group_execution_with_matched_control"
    model = "A377:factual_W46_model"
    confirmed = "A377:independent_full_output_confirmation"
    writer = CausalWriter(api_id="a377rec")
    writer._rules = []
    for name, pattern, conclusion in (
        ("portfolio_to_factor4_order", [portfolio], ordered),
        ("factor4_order_to_group_search", [ordered], searched),
        ("group_search_to_model", [searched], model),
        ("model_to_confirmation", [model], confirmed),
    ):
        writer.add_rule(
            name=name,
            description=name.replace("_", " "),
            pattern=pattern,
            conclusion=conclusion,
            confidence_modifier=1.0,
        )
    rows = (
        (
            portfolio,
            "frozen_refit_free_four_reader_factor4_order",
            ordered,
            payload["A376_order_commitment_sha256"],
            payload["pointwise_factor4_proof"],
        ),
        (
            ordered,
            "ordered_complete_eight_slab_group_search_with_one_bit_control",
            searched,
            payload["execution_sha256"],
            payload["discovery"],
        ),
        (
            searched,
            "sole_factual_filter_candidate_zero_control_and_factor4_rank_readback",
            model,
            payload["measurement_sha256"],
            payload["rank_analysis"],
        ),
        (
            model,
            "dual_independent_eight_block_RFC8439_confirmation",
            confirmed,
            payload["measurement_sha256"],
            payload["confirmation"],
        ),
    )
    for trigger, mechanism, outcome, source, quantification in rows:
        writer.add_triplet(
            trigger=trigger,
            mechanism=mechanism,
            outcome=outcome,
            confidence=1.0,
            source=source,
            quantification=json.dumps(quantification, sort_keys=True),
            evidence=payload["evidence_stage"],
            domain="ChaCha20 R20 W46 wide-consensus Reader portfolio recovery",
            quality_score=1.0,
        )
    writer.add_triplet(
        trigger=portfolio,
        mechanism="materialized_portfolio_factor4_search_model_confirmation_chain",
        outcome=confirmed,
        confidence=1.0,
        source="materialized:A377_recovery_chain",
        quantification="exact retained closure",
        evidence=payload["evidence_stage"],
        domain="AI-native retained inference",
        quality_score=1.0,
        is_inferred=True,
    )
    writer.add_cluster(
        name="A377 sealed-target wide-consensus recovery",
        entities=[portfolio, ordered, searched, model, confirmed],
    )
    writer.add_gap(
        subject=confirmed,
        predicate="next_required_object",
        expected_object_type="second_fresh_W46_replication_or_width_transfer",
        confidence=1.0,
        suggested_queries=[
            "Replicate the frozen wide-consensus Reader portfolio on a second sealed W46 target or transfer the same mechanism to a qualified wider engine."
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
        reader.api_id != "a377rec"
        or len(explicit) != 4
        or len(all_rows) != 5
        or len(inferred) != 1
        or len(reader._rules) != 4
        or len(reader._clusters) != 1
        or len(reader._gaps) != 1
    ):
        raise RuntimeError("A377 authentic Causal reopen gate failed")
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
            "first_relation": explicit[0],
            "terminal_relation": explicit[-1],
            "materialized_chain": all_rows[-1],
            "next_gap": reader._gaps[0],
        },
    }


def recover(
    *,
    expected_implementation_sha256: str,
    expected_order_sha256: str,
    expected_a324_qualification_sha256: str,
) -> dict[str, Any]:
    if any(path.exists() for path in (RESULT, CAUSAL, REPORT)):
        raise FileExistsError("A377 result already exists")
    design = load_design()
    implementation = load_implementation(expected_implementation_sha256)
    protocol = A361.load_protocol(A361_PROTOCOL_SHA256)
    order_value = A376.load_order(expected_order_sha256)
    qualification = A325.load_a324_qualification(expected_a324_qualification_sha256)
    if expected_a324_qualification_sha256 != A324_QUALIFICATION_SHA256:
        raise RuntimeError("A377 qualification hash differs")
    roles = [str(role) for role in order_value["model_role_order"]]
    source_orders = {
        role: [int(value) for value in order_value["source_orders"][role]] for role in roles
    }
    selected_order = [int(value) for value in order_value["selected_order"]]
    proof = order_value["pointwise_factor4_proof"]
    if (
        len(roles) != 4
        or proof.get("reader_count") != 4
        or proof.get("cells_checked") != GROUPS
        or proof.get("violations") != 0
    ):
        raise RuntimeError("A377 factor-four order proof differs")
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
                "schema": "chacha20-round20-w46-a376-order-recovery-a377-progress-v1",
                "attempt_id": ATTEMPT_ID,
                "protocol_sha256": A361_PROTOCOL_SHA256,
                "selected_operator": SELECTED_OPERATOR,
                "A376_order_file_sha256": expected_order_sha256,
                "selected_order_uint16be_sha256": order_value[
                    "selected_order_uint16be_sha256"
                ],
                "source_orders_sha256": order_value["source_orders_sha256"],
                "A324_qualification_sha256": expected_a324_qualification_sha256,
                **dict(row),
            },
        )

    start, prior_gpu, prior_hosts, completed_discovery = load_resume(
        protocol_sha256=A361_PROTOCOL_SHA256,
        order_file_sha256=expected_order_sha256,
        order_hash=order_value["selected_order_uint16be_sha256"],
        qualification_sha256=expected_a324_qualification_sha256,
    )
    discovery = completed_discovery or A325.ordered_discovery(
        host_factory=host_factory,
        challenge=challenge,
        order=selected_order,
        start_group=start,
        prior_gpu_seconds=prior_gpu,
        prior_host_instances=prior_hosts,
        progress_callback=write_progress,
    )
    if discovery["matched_control_candidates"] != 0:
        raise RuntimeError("A377 matched control produced a candidate")
    candidate = int(discovery["candidate"])
    confirmation = A325.confirm(challenge, candidate)
    if (
        confirmation["all_blocks_match"] is not True
        or confirmation["total_cross_implementation_output_bits_checked"] != 8192
    ):
        raise RuntimeError("A377 independent confirmation failed")
    prefix = int(discovery["prefix12"])
    portfolio_rank = selected_order.index(prefix) + 1
    if portfolio_rank != discovery["executed_prefix_groups"]:
        raise RuntimeError("A377 discovery rank differs from frozen portfolio order")
    source_ranks = {role: source_orders[role].index(prefix) + 1 for role in roles}
    best_source_rank = min(source_ranks.values())
    best_source_roles = sorted(
        role for role, rank in source_ranks.items() if rank == best_source_rank
    )
    if portfolio_rank > 4 * best_source_rank:
        raise RuntimeError("A377 confirmed rank violates A376 factor-four pointwise bound")
    strict_subset = portfolio_rank < GROUPS
    rank_analysis = {
        "prefix12": prefix,
        "prefix12_hex": f"{prefix:03x}",
        "true_low4": prefix & 0xF,
        "true_high8": prefix >> 4,
        "portfolio_group_rank_one_based": portfolio_rank,
        "source_reader_group_ranks_one_based": source_ranks,
        "best_source_group_rank_one_based": best_source_rank,
        "best_source_roles": best_source_roles,
        "reader_count": 4,
        "portfolio_to_best_source_rank_ratio": portfolio_rank / best_source_rank,
        "portfolio_rank_minus_best_source_rank": portfolio_rank - best_source_rank,
        "pointwise_factor4_bound": proof["bound"],
        "pointwise_factor4_bound_satisfied_at_confirmed_prefix": True,
        "pointwise_factor4_proof_checked_cells": proof["cells_checked"],
        "pointwise_factor4_proof_maximum_ratio": proof["maximum_ratio"],
        "gain_bits_vs_complete_domain": math.log2(GROUPS / portfolio_rank),
        "domain_reduction_factor": GROUPS / portfolio_rank,
        "best_source_gain_bits_vs_complete_domain": math.log2(GROUPS / best_source_rank),
        "best_source_domain_reduction_factor": GROUPS / best_source_rank,
        "ranks_computed_only_after_independent_confirmation": True,
    }
    evidence_stage = (
        "FULLROUND_R20_WIDE_CONSENSUS_READER_PORTFOLIO_W46_STRICT_SUBSET_RECOVERY_CONFIRMED"
        if strict_subset
        else "FULLROUND_R20_WIDE_CONSENSUS_READER_PORTFOLIO_W46_COMPLETE_DOMAIN_RECOVERY_CONFIRMED"
    )
    stable_discovery = {
        key: item for key, item in discovery.items() if not key.startswith("volatile_")
    }
    payload: dict[str, Any] = {
        "schema": "chacha20-round20-w46-a376-order-recovery-a377-v1",
        "attempt_id": ATTEMPT_ID,
        "evidence_stage": evidence_stage,
        "design_sha256": DESIGN_SHA256,
        "implementation_sha256": expected_implementation_sha256,
        "implementation_commitment_sha256": implementation[
            "implementation_commitment_sha256"
        ],
        "protocol_sha256": A361_PROTOCOL_SHA256,
        "protocol_commitment_sha256": protocol["protocol_commitment_sha256"],
        "public_challenge_sha256": protocol["public_challenge_sha256"],
        "A376_order_sha256": expected_order_sha256,
        "A376_order_commitment_sha256": order_value["order_commitment_sha256"],
        "A375_selection_commitment_sha256": order_value[
            "A375_selection_commitment_sha256"
        ],
        "A324_qualification_sha256": expected_a324_qualification_sha256,
        "selected_operator": SELECTED_OPERATOR,
        "model_role_order": roles,
        "model_definitions": order_value["model_definitions"],
        "source_orders_sha256": order_value["source_orders_sha256"],
        "selected_order_uint16be_sha256": order_value[
            "selected_order_uint16be_sha256"
        ],
        "pointwise_factor4_proof": proof,
        "discovery": discovery,
        "rank_analysis": rank_analysis,
        "confirmation": confirmation,
        "strict_subset_of_complete_domain": strict_subset,
        "reader_refits": 0,
        "target_labels_used_for_order": 0,
        "qualification_gate": {
            "evidence_stage": qualification["evidence_stage"],
            "qualification_sha256": qualification["qualification_sha256"],
            "complete_W46_group_candidates": qualification["complete_group_gate"][
                "logical_candidates"
            ],
            "synthetic_filter_exact": qualification["synthetic_filter_exact"],
            "production_target_used": False,
        },
        "information_boundary": design["information_boundary"],
        "anchors": {
            "design": anchor(DESIGN, DESIGN_SHA256),
            "implementation": anchor(IMPLEMENTATION, expected_implementation_sha256),
            "protocol": anchor(A361_PROTOCOL, A361_PROTOCOL_SHA256),
            "order": anchor(A376_ORDER, expected_order_sha256),
            "A324_qualification": anchor(
                A324_QUALIFICATION, expected_a324_qualification_sha256
            ),
            "runner": anchor(Path(__file__)),
            "test": anchor(TEST),
            "reproducer": anchor(REPRO),
        },
    }
    payload["execution_sha256"] = canonical_sha256(
        {
            "selected_operator": SELECTED_OPERATOR,
            "selected_order_uint16be_sha256": payload[
                "selected_order_uint16be_sha256"
            ],
            "source_orders_sha256": payload["source_orders_sha256"],
            "discovery": stable_discovery,
            "A324_qualification_sha256": expected_a324_qualification_sha256,
        }
    )
    payload["measurement_sha256"] = canonical_sha256(
        {
            "discovery": stable_discovery,
            "rank_analysis": rank_analysis,
            "confirmation": confirmation,
            "qualification_gate": payload["qualification_gate"],
            "pointwise_factor4_proof": proof,
            "reader_refits": 0,
            "target_labels_used_for_order": 0,
        }
    )
    payload["causal"] = build_causal(payload)
    atomic_json(RESULT, payload)
    atomic_bytes(
        REPORT,
        (
            "# A377 — wide-consensus Reader-portfolio W46 recovery\n\n"
            f"Evidence stage: **{evidence_stage}**\n\n"
            f"- Frozen Readers: **{roles}**\n"
            f"- W46 portfolio rank: **{portfolio_rank} / {GROUPS:,} groups**\n"
            f"- Source Reader ranks: **{source_ranks}**\n"
            f"- Exact factor-four contract: **{proof['bound']}**\n"
            f"- Domain reduction: **{rank_analysis['domain_reduction_factor']:.9f}x**\n"
            f"- Search-gain bits: **{rank_analysis['gain_bits_vs_complete_domain']:.9f}**\n"
            f"- Complete candidate evaluations: **{discovery['executed_assignments']:,} / {DOMAIN_SIZE:,}**\n"
            f"- Recovered W46 assignment: **0x{candidate:012x}**\n"
            "- Standard ChaCha20: **20 rounds plus feed-forward**\n"
            "- Matched one-bit control: **zero candidates**\n"
            "- Dual independent confirmation: **8,192 checked bits**\n"
            "- Reader refits / target labels: **0 / 0**\n"
            "- Authentic AI-native Causal readback: **4 explicit + 1 inferred**\n"
        ).encode(),
    )
    return payload


def analyze() -> dict[str, Any]:
    payload = {
        "attempt_id": ATTEMPT_ID,
        "design_sha256": DESIGN_SHA256,
        "implementation_frozen": IMPLEMENTATION.exists(),
        "progress_available": PROGRESS.exists(),
        "result_complete": RESULT.exists(),
    }
    if IMPLEMENTATION.exists():
        payload["implementation_sha256"] = file_sha256(IMPLEMENTATION)
    if PROGRESS.exists():
        payload["progress"] = json.loads(PROGRESS.read_bytes())
    if RESULT.exists():
        payload["result_sha256"] = file_sha256(RESULT)
    return payload


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    action = parser.add_mutually_exclusive_group(required=True)
    action.add_argument("--analyze", action="store_true")
    action.add_argument("--freeze-implementation", action="store_true")
    action.add_argument("--recover", action="store_true")
    parser.add_argument("--expected-implementation-sha256")
    parser.add_argument("--expected-order-sha256")
    parser.add_argument("--expected-a324-qualification-sha256")
    args = parser.parse_args()
    if args.freeze_implementation:
        payload = freeze_implementation()
    elif args.recover:
        required = (
            args.expected_implementation_sha256,
            args.expected_order_sha256,
            args.expected_a324_qualification_sha256,
        )
        if not all(required):
            parser.error(
                "--recover requires implementation, A376 order and A324 qualification hashes"
            )
        payload = recover(
            expected_implementation_sha256=args.expected_implementation_sha256,
            expected_order_sha256=args.expected_order_sha256,
            expected_a324_qualification_sha256=args.expected_a324_qualification_sha256,
        )
    else:
        payload = analyze()
    print(json.dumps(payload, indent=2, sort_keys=True), flush=True)


if __name__ == "__main__":
    main()

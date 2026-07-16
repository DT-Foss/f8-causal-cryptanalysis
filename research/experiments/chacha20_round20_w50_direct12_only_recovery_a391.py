#!/usr/bin/env python3
"""A391: execute the frozen W50 public-output Direct12 order without dilution."""

from __future__ import annotations

import argparse
import importlib.util
import inspect
import json
import math
import os
import sys
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

import numpy as np

ROOT = Path(__file__).parents[2]
RESEARCH = ROOT / "research"
CONFIGS = RESEARCH / "configs"
RESULTS = RESEARCH / "results/v1"

DESIGN = CONFIGS / "chacha20_round20_w50_direct12_only_recovery_a391_design_v1.json"
IMPLEMENTATION = (
    CONFIGS / "chacha20_round20_w50_direct12_only_recovery_a391_implementation_v1.json"
)
PROTOCOL = CONFIGS / "chacha20_round20_w50_direct12_only_recovery_a391_v1.json"
PROGRESS = RESULTS / "chacha20_round20_w50_direct12_only_recovery_a391_progress_v1.json"
RESULT = RESULTS / "chacha20_round20_w50_direct12_only_recovery_a391_v1.json"
CAUSAL = RESULT.with_suffix(".causal")
REPORT = RESULT.with_suffix(".md")
TEST = ROOT / "tests/test_chacha20_round20_w50_direct12_only_recovery_a391.py"
REPRO = ROOT / "scripts/reproduce_chacha20_round20_w50_direct12_only_recovery_a391.sh"

A389_RUNNER = (
    RESEARCH
    / "experiments/chacha20_round20_w50_public_output_factor3_recovery_a389.py"
)
A388_ORDER = (
    RESULTS / "chacha20_round20_w50_public_output_direct12_factor3_a388_order_v1.json"
)
A388_CAUSAL = A388_ORDER.with_suffix(".causal")
A350_RESULT = (
    RESULTS / "chacha20_round20_w46_a349_order_prospective_recovery_a350_v1.json"
)
A370_RESULT = RESULTS / "chacha20_round20_w46_a350_pre_result_order_rank_panel_a370_v1.json"

ATTEMPT_ID = "A391"
DESIGN_SHA256 = "16797e88cfad5a23ecc69b056839e7a437619a2c89d4766cdaaf55a03e00d284"
A389_RUNNER_SHA256 = "23602ef77bba32a019b78f776f1fa6a60d6ab13160c79644e4796b5ffe3e9ca5"
A388_ORDER_SHA256 = "3c56ce8521b1ced20e1e3a90999810c2e563c4de941701c86274f0828b5d01b8"
A388_CAUSAL_SHA256 = "095e4a05b86df98b27899c3055d4ff4c5ea2eab5ffa5961cfb36747320090e3a"
A350_RESULT_SHA256 = "a51919d30fc66ee5e581c87d6f2c5dc32cdabe71b51ce79c0a56a12e7325b3f3"
A370_RESULT_SHA256 = "13f6480a0b82440c5a77b13a80d46601abd355569007055d241fc863e6dcb593"
DIRECT_ORDER_SHA256 = "0094ac40b27b065888b56adce115bf4d54c0f0ba86dc1c7e87dff09f2f745f70"
DIRECT_ROLE = "A388_W50_public_output_direct12"
SELECTED_OPERATOR = "A342_selected_pair_slice_z_on_complete_A385_W50_direct12_grid"
CELLS = 4096
GROUP_SIZE = 1 << 38
DOMAIN_SIZE = 1 << 50
DOTCAUSAL_SRC = Path(
    "/Users/bhkmie/Documents/Forschung/O1/vendor/fabel/dotcausal_package/src"
)


def load_module(path: Path, name: str) -> Any:
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot import A391 dependency {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


A389 = load_module(A389_RUNNER, "a391_a389")
file_sha256 = A389.file_sha256
canonical_sha256 = A389.canonical_sha256
atomic_json = A389.atomic_json
atomic_bytes = A389.atomic_bytes
relative = A389.relative
path_from_ref = A389.path_from_ref
anchor = A389.anchor


def exact_order(values: Sequence[int], label: str) -> list[int]:
    return A389.exact_order(values, f"A391 {label}")


def order_sha256(values: Sequence[int]) -> str:
    return A389.order_sha256(exact_order(values, "order hash"))


def rank_vector(values: Sequence[int]) -> list[int]:
    return A389.rank_vector(exact_order(values, "rank vector"))


def load_design() -> dict[str, Any]:
    if file_sha256(DESIGN) != DESIGN_SHA256:
        raise RuntimeError("A391 design hash differs")
    value = json.loads(DESIGN.read_bytes())
    execution = value.get("execution_contract", {})
    boundary = value.get("information_boundary", {})
    order = value.get("order_contract", {})
    selection = value.get("selection_rationale", {})
    if (
        value.get("schema")
        != "chacha20-round20-w50-direct12-only-recovery-a391-design-v1"
        or value.get("attempt_id") != ATTEMPT_ID
        or value.get("design_state")
        != "frozen_after_A388_complete_direct12_order_before_A387_A389_or_A391_result_and_before_any_A391_candidate_or_prefix"
        or execution.get("unknown_key_bits") != 50
        or execution.get("candidates_per_prefix_group") != GROUP_SIZE
        or execution.get("complete_domain_assignments") != DOMAIN_SIZE
        or execution.get("slabs_per_prefix_group") != 128
        or order.get("source_role") != DIRECT_ROLE
        or order.get("selected_order_uint16be_sha256") != DIRECT_ORDER_SHA256
        or order.get("parameter_refits_at_W50") != 0
        or order.get("target_labels_used") != 0
        or selection.get("prior_direct12_rank_one_based") != 445
        or selection.get("prior_target_free_rank_one_based") != 2409
        or boundary.get("A387_progress_or_filter_outcomes_consumed") is not False
        or boundary.get("A387_result_or_true_prefix_available_at_design_freeze")
        is not False
        or boundary.get("A389_candidate_or_prefix_available_at_design_freeze")
        is not False
        or boundary.get("A391_candidate_or_prefix_available_at_design_freeze")
        is not False
    ):
        raise RuntimeError("A391 frozen design semantics differ")
    for name, source_path in value["source_anchors"].items():
        if name.endswith("_path"):
            stem = name.removesuffix("_path")
            anchor(ROOT / source_path, value["source_anchors"][f"{stem}_sha256"])
    return value


def assert_pre_execution() -> None:
    if any(path.exists() for path in (PROGRESS, RESULT, CAUSAL, REPORT)):
        raise RuntimeError("A391 freeze must precede every candidate and result")


def load_sources() -> tuple[dict[str, Any], dict[str, Any], dict[str, Any], list[int]]:
    source, order, qualification, source_orders = A389.load_sources()
    anchor(A350_RESULT, A350_RESULT_SHA256)
    anchor(A370_RESULT, A370_RESULT_SHA256)
    a350 = json.loads(A350_RESULT.read_bytes())
    a370 = json.loads(A370_RESULT.read_bytes())
    direct = exact_order(source_orders[DIRECT_ROLE], "W50 Direct12 source")
    comparison = a370.get("winner_and_comparisons", {})
    if (
        order.get("target_labels_used") != 0
        or order.get("reader_refits") != 0
        or order.get("candidate_assignments_executed") != 0
        or order.get("A387_progress_or_filter_outcomes_consumed") is not False
        or order_sha256(direct) != DIRECT_ORDER_SHA256
        or a350.get("selected_operator")
        != "A342_selected_pair_slice_z_on_complete_A345_direct12_grid"
        or a350.get("rank_analysis", {}).get("selected_rank_one_based") != 445
        or comparison.get("winner", {}).get("exact_group_rank_one_based") != 445
        or comparison.get("primary_target_free_baseline", {}).get(
            "A349_rank_improvement_factor"
        )
        != 5.413483146067415
        or qualification.get("matched_control_empty") is not True
        or qualification.get("complete_group_gate", {}).get("logical_candidates")
        != GROUP_SIZE
    ):
        raise RuntimeError("A391 source or disjoint selection evidence differs")
    return source, order, qualification, direct


def freeze_implementation() -> dict[str, Any]:
    if any(path.exists() for path in (IMPLEMENTATION, PROTOCOL, PROGRESS, RESULT, CAUSAL, REPORT)):
        raise FileExistsError("A391 implementation or execution artifact already exists")
    assert_pre_execution()
    load_design()
    load_sources()
    if not TEST.exists() or not REPRO.exists():
        raise FileNotFoundError("A391 test and reproducer must precede implementation freeze")
    payload: dict[str, Any] = {
        "schema": "chacha20-round20-w50-direct12-only-recovery-a391-implementation-v1",
        "attempt_id": ATTEMPT_ID,
        "commitment_state": "frozen_after_A388_Direct12_order_before_any_A391_candidate_prefix_or_result",
        "design_sha256": DESIGN_SHA256,
        "selected_operator": SELECTED_OPERATOR,
        "A391_candidate_or_prefix_available_at_implementation_freeze": False,
        "anchors": {
            "design": anchor(DESIGN, DESIGN_SHA256),
            "A389_runner": anchor(A389_RUNNER, A389_RUNNER_SHA256),
            "A388_order": anchor(A388_ORDER, A388_ORDER_SHA256),
            "A388_causal": anchor(A388_CAUSAL, A388_CAUSAL_SHA256),
            "A350_result": anchor(A350_RESULT, A350_RESULT_SHA256),
            "A370_result": anchor(A370_RESULT, A370_RESULT_SHA256),
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
        raise RuntimeError("A391 implementation hash differs")
    value = json.loads(IMPLEMENTATION.read_bytes())
    if (
        value.get("schema")
        != "chacha20-round20-w50-direct12-only-recovery-a391-implementation-v1"
        or value.get("attempt_id") != ATTEMPT_ID
        or value.get("design_sha256") != DESIGN_SHA256
        or value.get("selected_operator") != SELECTED_OPERATOR
        or value.get("A391_candidate_or_prefix_available_at_implementation_freeze")
        is not False
    ):
        raise RuntimeError("A391 implementation semantics differ")
    for row in value["anchors"].values():
        anchor(path_from_ref(row["path"]), row["sha256"])
    unsigned = {
        key: item
        for key, item in value.items()
        if key != "implementation_commitment_sha256"
    }
    if value.get("implementation_commitment_sha256") != canonical_sha256(unsigned):
        raise RuntimeError("A391 implementation commitment differs")
    return value


def freeze_protocol(*, expected_implementation_sha256: str) -> dict[str, Any]:
    if any(path.exists() for path in (PROTOCOL, PROGRESS, RESULT, CAUSAL, REPORT)):
        raise FileExistsError("A391 protocol or execution artifact already exists")
    assert_pre_execution()
    implementation = load_implementation(expected_implementation_sha256)
    source, order, qualification, direct = load_sources()
    payload: dict[str, Any] = {
        "schema": "chacha20-round20-w50-direct12-only-recovery-a391-protocol-v1",
        "attempt_id": ATTEMPT_ID,
        "protocol_state": "A388_Direct12_order_bound_before_any_A391_candidate_prefix_or_result",
        "design_sha256": DESIGN_SHA256,
        "implementation_sha256": expected_implementation_sha256,
        "implementation_commitment_sha256": implementation[
            "implementation_commitment_sha256"
        ],
        "A384_qualification_sha256": A389.A384_QUALIFICATION_SHA256,
        "A384_semantic_qualification_sha256": qualification["qualification_sha256"],
        "A385_protocol_sha256": A389.A385_PROTOCOL_SHA256,
        "A388_order_sha256": A388_ORDER_SHA256,
        "A388_order_commitment_sha256": order["order_commitment_sha256"],
        "public_challenge_sha256": source["public_challenge_sha256"],
        "public_challenge": source["public_challenge"],
        "selected_operator": SELECTED_OPERATOR,
        "selected_order_uint16be_sha256": order_sha256(direct),
        "selected_order": direct,
        "execution_contract": load_design()["execution_contract"],
        "information_boundary": {
            "A391_candidate_or_prefix_available_at_protocol_freeze": False,
            "A388_order_frozen_before_A391_candidate_or_prefix": True,
            "A385_assignment_absent_from_protocol": True,
            "target_labels_used_for_order_construction": 0,
            "reader_refits": 0,
            "candidate_assignments_executed_for_order": 0,
            "A387_progress_or_filter_outcomes_consumed_for_order": False,
            "A389_candidate_or_prefix_consumed_for_order": False,
            "parameter_refits_at_W50": 0,
        },
        "anchors": {
            "design": anchor(DESIGN, DESIGN_SHA256),
            "implementation": anchor(
                IMPLEMENTATION, expected_implementation_sha256
            ),
            "A388_order": anchor(A388_ORDER, A388_ORDER_SHA256),
            "A388_causal": anchor(A388_CAUSAL, A388_CAUSAL_SHA256),
            "A350_result": anchor(A350_RESULT, A350_RESULT_SHA256),
            "A370_result": anchor(A370_RESULT, A370_RESULT_SHA256),
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
            "selected_order_uint16be_sha256": payload[
                "selected_order_uint16be_sha256"
            ],
            "public_challenge_sha256": payload["public_challenge_sha256"],
            "information_boundary": payload["information_boundary"],
        }
    )
    atomic_json(PROTOCOL, payload)
    assert_pre_execution()
    return payload


def load_protocol(expected_sha256: str) -> dict[str, Any]:
    if file_sha256(PROTOCOL) != expected_sha256:
        raise RuntimeError("A391 protocol hash differs")
    value = json.loads(PROTOCOL.read_bytes())
    selected = exact_order(value.get("selected_order", []), "stored order")
    boundary = value.get("information_boundary", {})
    if (
        value.get("schema")
        != "chacha20-round20-w50-direct12-only-recovery-a391-protocol-v1"
        or value.get("attempt_id") != ATTEMPT_ID
        or value.get("selected_operator") != SELECTED_OPERATOR
        or value.get("selected_order_uint16be_sha256") != order_sha256(selected)
        or value.get("selected_order_uint16be_sha256") != DIRECT_ORDER_SHA256
        or boundary.get("A391_candidate_or_prefix_available_at_protocol_freeze")
        is not False
        or boundary.get("target_labels_used_for_order_construction") != 0
        or boundary.get("A387_progress_or_filter_outcomes_consumed_for_order")
        is not False
        or canonical_sha256(value.get("public_challenge"))
        != value.get("public_challenge_sha256")
    ):
        raise RuntimeError("A391 protocol semantics differ")
    for row in value["anchors"].values():
        anchor(path_from_ref(row["path"]), row["sha256"])
    load_implementation(value["implementation_sha256"])
    A389.A385.validate_challenge(value["public_challenge"])
    return value


def load_resume(
    *, protocol_sha256: str, order_sha: str, qualification_sha256: str
) -> tuple[int, float, int, dict[str, Any] | None]:
    if not PROGRESS.exists():
        return 0, 0.0, 0, None
    value = json.loads(PROGRESS.read_bytes())
    if (
        value.get("schema")
        != "chacha20-round20-w50-direct12-only-recovery-a391-progress-v1"
        or value.get("attempt_id") != ATTEMPT_ID
        or value.get("protocol_sha256") != protocol_sha256
        or value.get("selected_order_uint16be_sha256") != order_sha
        or value.get("A384_qualification_sha256") != qualification_sha256
        or value.get("matched_control_candidates") != 0
    ):
        raise RuntimeError("A391 progress fingerprint differs")
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
        raise RuntimeError("A391 resumable progress state differs")
    return (
        completed,
        float(value.get("gpu_seconds", 0.0)),
        int(value.get("host_instances", 0)),
        None,
    )


def rank_panel(prefix: int, direct: Sequence[int], a388: Mapping[str, Any]) -> dict[str, Any]:
    source_orders = a388["source_orders"]
    source_ranks = {
        role: rank_vector(values)[prefix] for role, values in source_orders.items()
    }
    direct_rank = rank_vector(direct)[prefix]
    factor3_rank = rank_vector(a388["selected_order"])[prefix]
    return {
        "prefix12": prefix,
        "prefix12_hex": f"{prefix:03x}",
        "A391_executed_Direct12_rank_one_based": direct_rank,
        "A388_factor3_rank_one_based": factor3_rank,
        "A388_source_ranks_one_based": source_ranks,
        "Direct12_gain_bits_vs_complete_domain": math.log2(CELLS / direct_rank),
        "Direct12_domain_reduction_factor": CELLS / direct_rank,
        "Direct12_rank_ratio_to_A388_factor3": direct_rank / factor3_rank,
        "ranks_computed_only_after_independent_confirmation": True,
    }


def build_causal(payload: Mapping[str, Any]) -> dict[str, Any]:
    sys.path.insert(0, str(DOTCAUSAL_SRC))
    from dotcausal.io import CausalReader, CausalWriter

    terminal = "A391:confirmed_Direct12_only_W50_recovery"
    writer = CausalWriter(api_id="a391w50")
    writer._rules = []
    writer.add_rule(
        name="public_output_Direct12_order_and_W50_engine_to_model",
        description="The zero-refit W50 Direct12 order executes qualified complete 128-slab groups until the sole factual model appears.",
        pattern=["A388_W50_public_output_Direct12_order", "A384_exact_W50_group_engine"],
        conclusion="A391_sole_factual_W50_model",
        confidence_modifier=1.0,
    )
    writer.add_rule(
        name="model_to_confirmed_Direct12_recovery",
        description="The factual model is independently confirmed across all eight standard ChaCha20 blocks.",
        pattern=["A391_sole_factual_W50_model"],
        conclusion="A391_confirmed_Direct12_only_W50_recovery",
        confidence_modifier=1.0,
    )
    writer.add_triplet(
        trigger="A388:W50_public_output_Direct12_order",
        mechanism="qualified_Direct12_ordered_complete_onehundredtwentyeight_slab_search",
        outcome="A391:sole_factual_W50_model",
        confidence=1.0,
        source=payload["execution_sha256"],
        quantification=json.dumps(payload["discovery"], sort_keys=True),
        evidence=json.dumps(payload["rank_analysis"], sort_keys=True),
        domain="fresh full-round ChaCha20 W50 Direct12-only recovery",
        quality_score=1.0,
    )
    writer.add_triplet(
        trigger="A391:sole_factual_W50_model",
        mechanism="dual_independent_eight_block_confirmation",
        outcome=terminal,
        confidence=1.0,
        source=payload["measurement_sha256"],
        quantification=json.dumps(payload["confirmation"], sort_keys=True),
        evidence=payload["evidence_stage"],
        domain="confirmed full-round ChaCha20 W50 Direct12-only recovery",
        quality_score=1.0,
    )
    writer.add_triplet(
        trigger="A388:W50_public_output_Direct12_order",
        mechanism="materialized_Direct12_search_and_confirmation_closure",
        outcome=terminal,
        confidence=1.0,
        source="materialized:A391_Direct12_only_W50_recovery_chain",
        quantification="exact retained closure",
        evidence=payload["evidence_stage"],
        domain="AI-native retained inference",
        quality_score=1.0,
        is_inferred=True,
    )
    writer.add_cluster(
        name="A391 Direct12-only W50 recovery",
        entities=[
            "A388:W50_public_output_Direct12_order",
            "A391:sole_factual_W50_model",
            terminal,
        ],
    )
    writer.add_gap(
        subject=terminal,
        predicate="next_required_object",
        expected_object_type="crosswidth_Direct12_truth_rank_curve_or_W51_transfer",
        confidence=1.0,
        suggested_queries=[
            "Compare the independently confirmed W46-W50 Direct12 truth ranks and transfer the frozen Reader after W51 qualification."
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
        reader.api_id != "a391w50"
        or len(explicit) != 2
        or len(all_rows) != 3
        or len(inferred) != 1
        or len(reader._rules) != 2
        or len(reader._clusters) != 1
        or len(reader._gaps) != 1
    ):
        raise RuntimeError("A391 authentic Causal reopen gate failed")
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
        raise FileExistsError("A391 result artifact already exists")
    protocol = load_protocol(expected_protocol_sha256)
    qualification = A389.A385.load_a384_qualification(
        protocol["A384_qualification_sha256"]
    )
    engine_protocol = A389.A384.load_protocol(A389.A384_PROTOCOL_SHA256)
    executable_row = engine_protocol["anchors"]["grouped_executable"]
    executable = path_from_ref(executable_row["path"])
    anchor(executable, executable_row["sha256"])
    challenge = protocol["public_challenge"]
    placeholder = np.asarray([0, 0], dtype=np.uint32)

    def host_factory() -> Any:
        return A389.A384.A378.A371.A346.A324.A311.A307.A304.GroupedMetalHost(
            executable,
            A389.A384.initial_for_slab(challenge, 0),
            placeholder,
            placeholder,
        )

    def write_progress(row: Mapping[str, Any]) -> None:
        atomic_json(
            PROGRESS,
            {
                "schema": "chacha20-round20-w50-direct12-only-recovery-a391-progress-v1",
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
    discovery = completed_discovery or A389.ordered_discovery(
        host_factory=host_factory,
        challenge=challenge,
        order=protocol["selected_order"],
        start_group=start,
        prior_gpu_seconds=prior_gpu,
        prior_host_instances=prior_hosts,
        progress_callback=write_progress,
    )
    if discovery["matched_control_candidates"] != 0:
        raise RuntimeError("A391 matched control produced a candidate")
    candidate = int(discovery["candidate"])
    confirmation = A389.A385.confirm(challenge, candidate)
    if confirmation["all_blocks_match"] is not True:
        raise RuntimeError("A391 dual independent confirmation failed")
    a388 = json.loads(A388_ORDER.read_bytes())
    ranks = rank_panel(
        int(discovery["prefix12"]), protocol["selected_order"], a388
    )
    if ranks["A391_executed_Direct12_rank_one_based"] != discovery[
        "executed_prefix_groups"
    ]:
        raise RuntimeError("A391 discovery rank differs from Direct12 order")
    strict_subset = discovery["executed_prefix_groups"] < CELLS
    evidence_stage = (
        "FULLROUND_R20_DIRECT12_ONLY_W50_STRICT_SUBSET_RECOVERY_CONFIRMED"
        if strict_subset
        else "FULLROUND_R20_DIRECT12_ONLY_W50_COMPLETE_DOMAIN_RECOVERY_CONFIRMED"
    )
    payload: dict[str, Any] = {
        "schema": "chacha20-round20-w50-direct12-only-recovery-a391-result-v1",
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
            "# A391 — Direct12-only full-round ChaCha20 W50 recovery\n\n"
            f"Evidence stage: **{evidence_stage}**\n\n"
            f"- Direct12 execution rank: **{ranks['A391_executed_Direct12_rank_one_based']} / {CELLS}**\n"
            f"- A388 factor-three comparison rank: **{ranks['A388_factor3_rank_one_based']} / {CELLS}**\n"
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
        payload["evidence_stage"] = json.loads(RESULT.read_bytes())["evidence_stage"]
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

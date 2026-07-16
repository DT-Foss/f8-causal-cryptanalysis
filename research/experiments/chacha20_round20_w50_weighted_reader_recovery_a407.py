#!/usr/bin/env python3
"""A407: execute a qualified distinct A406 weighted W50 production order."""

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

DESIGN = CONFIGS / "chacha20_round20_w50_weighted_reader_recovery_a407_design_v1.json"
IMPLEMENTATION = (
    CONFIGS / "chacha20_round20_w50_weighted_reader_recovery_a407_implementation_v1.json"
)
PROTOCOL = CONFIGS / "chacha20_round20_w50_weighted_reader_recovery_a407_v1.json"
PROGRESS = RESULTS / "chacha20_round20_w50_weighted_reader_recovery_a407_progress_v1.json"
RESULT = RESULTS / "chacha20_round20_w50_weighted_reader_recovery_a407_v1.json"
CAUSAL = RESULT.with_suffix(".causal")
REPORT = RESULT.with_suffix(".md")
TEST = ROOT / "tests/test_chacha20_round20_w50_weighted_reader_recovery_a407.py"
REPRO = ROOT / "scripts/reproduce_chacha20_round20_w50_weighted_reader_recovery_a407.sh"

A405_RUNNER = RESEARCH / "experiments/chacha20_round20_w50_leaveoneout_reader_recovery_a405.py"
A406_RUNNER = RESEARCH / "experiments/chacha20_round20_w50_knownkey_weighted_reader_a406.py"
A406_DESIGN = CONFIGS / "chacha20_round20_w50_knownkey_weighted_reader_a406_design_v1.json"
A406_IMPLEMENTATION = (
    CONFIGS / "chacha20_round20_w50_knownkey_weighted_reader_a406_implementation_v1.json"
)
A406_RESULT = RESULTS / "chacha20_round20_w50_knownkey_weighted_reader_a406_v1.json"
A402_RESULT = RESULTS / "chacha20_round20_w50_knownkey_fullfit_production_reader_a402_v1.json"
A404_RESULT = RESULTS / "chacha20_round20_w50_knownkey_leaveoneout_reader_a404_v1.json"

ATTEMPT_ID = "A407"
DESIGN_SHA256 = "076a93c87104414d48c631e1cc864a40bf5411e1314997cbc289bb26556f4e23"
A405_RUNNER_SHA256 = "09fa3dce7790f4795cd0fa10c2cbebcb82f05c083494358775dd146ec67bf6e2"
A406_RUNNER_SHA256 = "7db8f5234cc2d03c685d2f42babe1274438add56cc0bcde28f66c2e32520e2b9"
A406_DESIGN_SHA256 = "aaa67ce789ff3623c22e2d2965cbd5c19aa5f4d9aaa2911797eb2d019e0fd2a0"
A406_IMPLEMENTATION_SHA256 = "f6a6e539ee84e03899817e072d09d2b55756419580113990f629f358e93b9236"
A384_QUALIFICATION_SHA256 = "0e31d4d7b0e0bb0e45cd815d975e2898c60eeea16e04498d720f0a58dd41dc30"
A385_PROTOCOL_SHA256 = "801831f2daabe41476c9bf1ec676907f11c1b5465a193ba61d8d1877eb3b0b4b"
SELECTED_OPERATOR = "A406_weighted_outoffold_qualified_fullfit_production_reader"
CELLS = 4096
GROUP_SIZE = 1 << 38
DOMAIN_SIZE = 1 << 50
DOTCAUSAL_SRC = Path("/Users/bhkmie/Documents/Forschung/O1/vendor/fabel/dotcausal_package/src")


def load_module(path: Path, name: str) -> Any:
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot import A407 dependency {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


A405 = load_module(A405_RUNNER, "a407_a405")
A406 = load_module(A406_RUNNER, "a407_a406")
A391 = A405.A391

file_sha256 = A391.file_sha256
canonical_sha256 = A391.canonical_sha256
atomic_json = A391.atomic_json
atomic_bytes = A391.atomic_bytes
relative = A391.relative
path_from_ref = A391.path_from_ref
anchor = A391.anchor


def exact_order(values: Sequence[int], label: str) -> list[int]:
    return A391.exact_order(values, f"A407 {label}")


def order_sha256(values: Sequence[int]) -> str:
    return A391.order_sha256(exact_order(values, "order hash"))


def rank_vector(values: Sequence[int]) -> list[int]:
    return A391.rank_vector(exact_order(values, "rank vector"))


def load_design() -> dict[str, Any]:
    if file_sha256(DESIGN) != DESIGN_SHA256:
        raise RuntimeError("A407 design hash differs")
    value = json.loads(DESIGN.read_bytes())
    source = value.get("source_order_contract", {})
    duplicate = value.get("duplicate_execution_contract", {})
    execution = value.get("execution_contract", {})
    boundary = value.get("information_boundary", {})
    if (
        value.get("schema") != "chacha20-round20-w50-weighted-reader-recovery-a407-design-v1"
        or value.get("attempt_id") != ATTEMPT_ID
        or value.get("design_state")
        != "frozen_during_A401_measurement_after_A406_implementation_freeze_before_A401_A402_A404_A406_results_or_any_A407_candidate_prefix"
        or source.get("required_A406_qualification") is not True
        or source.get("required_order_cells") != CELLS
        or source.get("target_labels_used_for_order") != 0
        or tuple(duplicate.get("comparison_results_required_before_A407_protocol_decision", []))
        != ("A402", "A404")
        or execution.get("complete_prefix_groups") != CELLS
        or execution.get("candidates_per_prefix_group") != GROUP_SIZE
        or execution.get("complete_domain_assignments") != DOMAIN_SIZE
        or execution.get("slabs_per_prefix_group") != 128
        or boundary.get("A401_selection_or_result_available_at_design_freeze") is not False
        or boundary.get("A402_A404_A406_result_or_production_order_available_at_design_freeze")
        is not False
        or boundary.get("A407_candidate_or_prefix_available_at_design_freeze") is not False
    ):
        raise RuntimeError("A407 frozen design semantics differ")
    for key, source_path in value["source_anchors"].items():
        if key.endswith("_path"):
            expected = value["source_anchors"][key.removesuffix("_path") + "_sha256"]
            anchor(ROOT / source_path, expected)
    return value


def freeze_implementation() -> dict[str, Any]:
    outputs = (IMPLEMENTATION, PROTOCOL, PROGRESS, RESULT, CAUSAL, REPORT)
    if any(path.exists() for path in outputs):
        raise FileExistsError("A407 implementation or execution artifact already exists")
    if (
        A402_RESULT.exists()
        or A404_RESULT.exists()
        or A406_RESULT.exists()
        or A406.A401.RESULT.exists()
        or A406.A401.SELECTION.exists()
    ):
        raise RuntimeError("A407 code freeze must precede A401/A402/A404/A406 results")
    load_design()
    A391.A389.load_sources()
    if not TEST.exists() or not REPRO.exists():
        raise FileNotFoundError("A407 test and reproducer must precede freeze")
    payload: dict[str, Any] = {
        "schema": "chacha20-round20-w50-weighted-reader-recovery-a407-implementation-v1",
        "attempt_id": ATTEMPT_ID,
        "commitment_state": "complete_weighted_executor_and_prior_order_dedup_gate_frozen_before_A401_A402_A404_A406_results_or_A407_candidate",
        "design_sha256": DESIGN_SHA256,
        "selected_operator": SELECTED_OPERATOR,
        "A401_A402_A404_A406_results_available_at_freeze": False,
        "A407_candidate_or_prefix_available_at_freeze": False,
        "anchors": {
            "design": anchor(DESIGN, DESIGN_SHA256),
            "A405_runner": anchor(A405_RUNNER, A405_RUNNER_SHA256),
            "A406_design": anchor(A406_DESIGN, A406_DESIGN_SHA256),
            "A406_runner": anchor(A406_RUNNER, A406_RUNNER_SHA256),
            "A406_implementation": anchor(A406_IMPLEMENTATION, A406_IMPLEMENTATION_SHA256),
            "A384_qualification": anchor(A391.A389.A384_QUALIFICATION, A384_QUALIFICATION_SHA256),
            "A385_protocol": anchor(A391.A389.A385_PROTOCOL, A385_PROTOCOL_SHA256),
            "runner": anchor(Path(__file__)),
            "test": anchor(TEST),
            "reproducer": anchor(REPRO),
        },
    }
    payload["implementation_commitment_sha256"] = canonical_sha256(payload)
    atomic_json(IMPLEMENTATION, payload)
    return payload


def load_implementation(expected_sha256: str) -> dict[str, Any]:
    if file_sha256(IMPLEMENTATION) != expected_sha256:
        raise RuntimeError("A407 implementation file hash differs")
    value = json.loads(IMPLEMENTATION.read_bytes())
    if (
        value.get("schema")
        != "chacha20-round20-w50-weighted-reader-recovery-a407-implementation-v1"
        or value.get("attempt_id") != ATTEMPT_ID
        or value.get("commitment_state")
        != "complete_weighted_executor_and_prior_order_dedup_gate_frozen_before_A401_A402_A404_A406_results_or_A407_candidate"
        or value.get("selected_operator") != SELECTED_OPERATOR
        or value.get("A401_A402_A404_A406_results_available_at_freeze") is not False
        or value.get("A407_candidate_or_prefix_available_at_freeze") is not False
    ):
        raise RuntimeError("A407 implementation semantics differ")
    for row in value["anchors"].values():
        anchor(path_from_ref(row["path"]), row["sha256"])
    unsigned = {
        key: item for key, item in value.items() if key != "implementation_commitment_sha256"
    }
    if value.get("implementation_commitment_sha256") != canonical_sha256(unsigned):
        raise RuntimeError("A407 implementation commitment differs")
    return value


def load_a406_order(expected_result_sha256: str) -> tuple[dict[str, Any], list[int]]:
    if file_sha256(A406_RESULT) != expected_result_sha256:
        raise RuntimeError("A407 A406 result hash differs")
    value = json.loads(A406_RESULT.read_bytes())
    order = exact_order(value.get("production_order", []), "A406 production order")
    source = load_design()["source_order_contract"]
    if (
        value.get("schema") != "chacha20-round20-w50-knownkey-weighted-reader-a406-result-v1"
        or value.get("attempt_id") != "A406"
        or value.get("evidence_stage") != source["required_A406_evidence_stage"]
        or value.get("leaveoneout", {}).get("qualified") is not True
        or value.get("production_order_uint16be_sha256") != order_sha256(order)
        or value.get("production_target_labels_used") != 0
        or value.get("production_reader_refits") != 0
        or value.get("production_candidate_assignments_executed") != 0
        or value.get("new_solver_stages") != 0
        or value.get("live_recovery_progress_filter_outcomes_or_results_consumed") is not False
    ):
        raise RuntimeError("A407 A406 qualified-order semantics differ")
    return value, order


def load_a404_comparison(
    expected_result_sha256: str,
) -> tuple[dict[str, Any], list[int] | None]:
    if file_sha256(A404_RESULT) != expected_result_sha256:
        raise RuntimeError("A407 A404 comparison result hash differs")
    value = json.loads(A404_RESULT.read_bytes())
    qualified = value.get("leaveoneout", {}).get("qualified") is True
    if qualified:
        return A405.load_a404_order(expected_result_sha256)
    if (
        value.get("schema") != "chacha20-round20-w50-knownkey-leaveoneout-reader-a404-result-v1"
        or value.get("attempt_id") != "A404"
        or value.get("evidence_stage")
        != "SIXTEEN_FOLD_LEAVEONEOUT_BOUNDARY_RETAINED_NO_PRODUCTION_DEPLOYMENT"
        or value.get("production_order") is not None
        or value.get("production_order_uint16be_sha256") is not None
        or value.get("production_target_labels_used") != 0
        or value.get("production_reader_refits") != 0
        or value.get("production_candidate_assignments_executed") != 0
        or value.get("new_solver_stages") != 0
    ):
        raise RuntimeError("A407 A404 boundary semantics differ")
    return value, None


def execution_decision(
    weighted_order: Sequence[int],
    a402_order: Sequence[int] | None,
    a404_order: Sequence[int] | None,
) -> dict[str, Any]:
    selected_sha = order_sha256(weighted_order)
    comparisons = {
        "A402": order_sha256(a402_order) if a402_order is not None else None,
        "A404": order_sha256(a404_order) if a404_order is not None else None,
    }
    matches = [name for name, digest in comparisons.items() if digest == selected_sha]
    return {
        "execution_enabled": not matches,
        "duplicate_prior_orders": matches,
        "selected_order_uint16be_sha256": selected_sha,
        "comparison_order_uint16be_sha256": comparisons,
    }


def freeze_protocol(
    *,
    expected_implementation_sha256: str,
    expected_a406_result_sha256: str,
    expected_a402_result_sha256: str,
    expected_a404_result_sha256: str,
) -> dict[str, Any]:
    if any(path.exists() for path in (PROTOCOL, PROGRESS, RESULT, CAUSAL, REPORT)):
        raise FileExistsError("A407 protocol or execution artifact already exists")
    implementation = load_implementation(expected_implementation_sha256)
    a406, weighted_order = load_a406_order(expected_a406_result_sha256)
    a402, a402_order = A405.load_a402_comparison(expected_a402_result_sha256)
    a404, a404_order = load_a404_comparison(expected_a404_result_sha256)
    decision = execution_decision(weighted_order, a402_order, a404_order)
    source, _a388, qualification, _source_orders = A391.A389.load_sources()
    payload: dict[str, Any] = {
        "schema": "chacha20-round20-w50-weighted-reader-recovery-a407-protocol-v1",
        "attempt_id": ATTEMPT_ID,
        "protocol_state": (
            "weighted_A406_order_distinct_and_bound_before_any_A407_candidate"
            if decision["execution_enabled"]
            else "weighted_A406_order_prior_equivalence_only_no_duplicate_execution"
        ),
        **decision,
        "design_sha256": DESIGN_SHA256,
        "implementation_sha256": expected_implementation_sha256,
        "implementation_commitment_sha256": implementation["implementation_commitment_sha256"],
        "A406_result_sha256": expected_a406_result_sha256,
        "A406_deployment_commitment_sha256": a406["deployment_commitment_sha256"],
        "A402_result_sha256": expected_a402_result_sha256,
        "A404_result_sha256": expected_a404_result_sha256,
        "comparison_qualification": {
            "A402": a402["qualification"]["qualified"],
            "A404": a404["leaveoneout"]["qualified"],
        },
        "A384_qualification_sha256": A384_QUALIFICATION_SHA256,
        "A384_semantic_qualification_sha256": qualification["qualification_sha256"],
        "A385_protocol_sha256": A385_PROTOCOL_SHA256,
        "public_challenge_sha256": source["public_challenge_sha256"],
        "public_challenge": source["public_challenge"],
        "selected_operator": SELECTED_OPERATOR,
        "selected_order": weighted_order,
        "execution_contract": load_design()["execution_contract"],
        "information_boundary": {
            "A407_candidate_or_prefix_available_at_protocol_freeze": False,
            "A406_order_bound_without_mutation": True,
            "A385_assignment_absent_from_protocol": True,
            "target_labels_used_for_order_construction": 0,
            "production_reader_refits": 0,
            "candidate_assignments_executed_for_order": 0,
            "live_recovery_progress_filter_outcomes_or_results_consumed_for_order": False,
        },
        "anchors": {
            "design": anchor(DESIGN, DESIGN_SHA256),
            "implementation": anchor(IMPLEMENTATION, expected_implementation_sha256),
            "A406_result": anchor(A406_RESULT, expected_a406_result_sha256),
            "A402_result": anchor(A402_RESULT, expected_a402_result_sha256),
            "A404_result": anchor(A404_RESULT, expected_a404_result_sha256),
            "A384_qualification": anchor(A391.A389.A384_QUALIFICATION, A384_QUALIFICATION_SHA256),
            "A385_protocol": anchor(A391.A389.A385_PROTOCOL, A385_PROTOCOL_SHA256),
            "runner": anchor(Path(__file__)),
            "test": anchor(TEST),
            "reproducer": anchor(REPRO),
        },
    }
    payload["protocol_commitment_sha256"] = canonical_sha256(
        {
            "implementation_commitment_sha256": payload["implementation_commitment_sha256"],
            "A406_deployment_commitment_sha256": payload["A406_deployment_commitment_sha256"],
            "comparison_order_uint16be_sha256": payload["comparison_order_uint16be_sha256"],
            "duplicate_prior_orders": payload["duplicate_prior_orders"],
            "execution_enabled": payload["execution_enabled"],
            "A384_qualification_sha256": payload["A384_qualification_sha256"],
            "selected_order_uint16be_sha256": payload["selected_order_uint16be_sha256"],
            "public_challenge_sha256": payload["public_challenge_sha256"],
        }
    )
    atomic_json(PROTOCOL, payload)
    return payload


def load_protocol(expected_sha256: str) -> dict[str, Any]:
    if file_sha256(PROTOCOL) != expected_sha256:
        raise RuntimeError("A407 protocol file hash differs")
    value = json.loads(PROTOCOL.read_bytes())
    order = exact_order(value.get("selected_order", []), "protocol order")
    duplicate = list(value.get("duplicate_prior_orders", []))
    expected_state = (
        "weighted_A406_order_prior_equivalence_only_no_duplicate_execution"
        if duplicate
        else "weighted_A406_order_distinct_and_bound_before_any_A407_candidate"
    )
    expected_commitment = canonical_sha256(
        {
            "implementation_commitment_sha256": value.get("implementation_commitment_sha256"),
            "A406_deployment_commitment_sha256": value.get("A406_deployment_commitment_sha256"),
            "comparison_order_uint16be_sha256": value.get("comparison_order_uint16be_sha256"),
            "duplicate_prior_orders": duplicate,
            "execution_enabled": value.get("execution_enabled"),
            "A384_qualification_sha256": value.get("A384_qualification_sha256"),
            "selected_order_uint16be_sha256": value.get("selected_order_uint16be_sha256"),
            "public_challenge_sha256": value.get("public_challenge_sha256"),
        }
    )
    if (
        value.get("schema") != "chacha20-round20-w50-weighted-reader-recovery-a407-protocol-v1"
        or value.get("attempt_id") != ATTEMPT_ID
        or value.get("selected_operator") != SELECTED_OPERATOR
        or value.get("protocol_state") != expected_state
        or value.get("execution_enabled") is bool(duplicate)
        or value.get("protocol_commitment_sha256") != expected_commitment
        or value.get("selected_order_uint16be_sha256") != order_sha256(order)
        or value.get("information_boundary", {}).get(
            "A407_candidate_or_prefix_available_at_protocol_freeze"
        )
        is not False
        or value.get("information_boundary", {}).get("target_labels_used_for_order_construction")
        != 0
        or canonical_sha256(value.get("public_challenge")) != value.get("public_challenge_sha256")
    ):
        raise RuntimeError("A407 protocol semantics differ")
    for row in value["anchors"].values():
        anchor(path_from_ref(row["path"]), row["sha256"])
    load_implementation(value["implementation_sha256"])
    a406, expected_order = load_a406_order(value["A406_result_sha256"])
    a402, a402_order = A405.load_a402_comparison(value["A402_result_sha256"])
    a404, a404_order = load_a404_comparison(value["A404_result_sha256"])
    decision = execution_decision(expected_order, a402_order, a404_order)
    if (
        order != expected_order
        or value["execution_enabled"] != decision["execution_enabled"]
        or duplicate != decision["duplicate_prior_orders"]
        or value["comparison_order_uint16be_sha256"] != decision["comparison_order_uint16be_sha256"]
        or value["comparison_qualification"]
        != {
            "A402": a402["qualification"]["qualified"],
            "A404": a404["leaveoneout"]["qualified"],
        }
        or value["A406_deployment_commitment_sha256"] != a406["deployment_commitment_sha256"]
    ):
        raise RuntimeError("A407 protocol no longer equals its sources")
    A391.A389.A385.validate_challenge(value["public_challenge"])
    return value


def load_resume(
    *, protocol_sha256: str, order_sha: str, qualification_sha256: str
) -> tuple[int, float, int, dict[str, Any] | None]:
    if not PROGRESS.exists():
        return 0, 0.0, 0, None
    value = json.loads(PROGRESS.read_bytes())
    if (
        value.get("schema") != "chacha20-round20-w50-weighted-reader-recovery-a407-progress-v1"
        or value.get("attempt_id") != ATTEMPT_ID
        or value.get("protocol_sha256") != protocol_sha256
        or value.get("selected_order_uint16be_sha256") != order_sha
        or value.get("A384_qualification_sha256") != qualification_sha256
        or value.get("matched_control_candidates") != 0
    ):
        raise RuntimeError("A407 progress fingerprint differs")
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
        return 0, 0.0, 0, {key: item for key, item in value.items() if key not in excluded}
    completed = int(value.get("executed_prefix_groups", -1))
    if not 0 <= completed < CELLS or value.get("factual_filter_candidates") != 0:
        raise RuntimeError("A407 resumable progress state differs")
    return (
        completed,
        float(value.get("gpu_seconds", 0.0)),
        int(value.get("host_instances", 0)),
        None,
    )


def rank_panel(prefix: int, weighted: Sequence[int]) -> dict[str, Any]:
    a388 = json.loads(A391.A388_ORDER.read_bytes())
    weighted_rank = rank_vector(weighted)[prefix]
    direct_rank = rank_vector(a388["W50_public_output_direct12_order"])[prefix]
    factor3_rank = rank_vector(a388["selected_order"])[prefix]
    return {
        "prefix12": prefix,
        "prefix12_hex": f"{prefix:03x}",
        "A407_weighted_rank_one_based": weighted_rank,
        "A391_Direct12_comparison_rank_one_based": direct_rank,
        "A388_factor3_comparison_rank_one_based": factor3_rank,
        "weighted_gain_bits_vs_complete_domain": math.log2(CELLS / weighted_rank),
        "weighted_domain_reduction_factor": CELLS / weighted_rank,
        "weighted_rank_ratio_to_Direct12": weighted_rank / direct_rank,
        "weighted_rank_ratio_to_A388_factor3": weighted_rank / factor3_rank,
        "ranks_computed_only_after_independent_confirmation": True,
    }


def build_causal(payload: Mapping[str, Any]) -> dict[str, Any]:
    sys.path.insert(0, str(DOTCAUSAL_SRC))
    from dotcausal.io import CausalReader, CausalWriter

    terminal = "A407:confirmed_weighted_reader_W50_recovery"
    writer = CausalWriter(api_id="a407w50")
    writer._rules = []
    writer.add_rule(
        name="weighted_reader_and_complete_engine_to_model",
        description="The A406 weighted out-of-fold-qualified order executes complete W50 groups until the sole factual model appears.",
        pattern=["A406_weighted_qualified_production_order", "A384_exact_W50_group_engine"],
        conclusion="A407_sole_factual_W50_model",
        confidence_modifier=1.0,
    )
    writer.add_rule(
        name="model_to_confirmed_recovery",
        description="The factual model passes matched control and dual independent confirmation across all eight standard blocks.",
        pattern=["A407_sole_factual_W50_model"],
        conclusion="A407_confirmed_weighted_reader_W50_recovery",
        confidence_modifier=1.0,
    )
    writer.add_triplet(
        trigger="A406:weighted_qualified_production_order",
        mechanism="qualified_complete_onehundredtwentyeight_slab_group_search",
        outcome="A407:sole_factual_W50_model",
        confidence=1.0,
        source=payload["execution_sha256"],
        quantification=json.dumps(payload["discovery"], sort_keys=True),
        evidence=json.dumps(payload["rank_analysis"], sort_keys=True),
        domain="fresh full-round ChaCha20 W50 weighted Reader recovery",
        quality_score=1.0,
    )
    writer.add_triplet(
        trigger="A407:sole_factual_W50_model",
        mechanism="matched_control_plus_dual_independent_eight_block_confirmation",
        outcome=terminal,
        confidence=1.0,
        source=payload["measurement_sha256"],
        quantification=json.dumps(payload["confirmation"], sort_keys=True),
        evidence=payload["evidence_stage"],
        domain="confirmed full-round ChaCha20 W50 weighted Reader recovery",
        quality_score=1.0,
    )
    writer.add_triplet(
        trigger="A406:weighted_qualified_production_order",
        mechanism="materialized_weighted_search_and_confirmation_closure",
        outcome=terminal,
        confidence=1.0,
        source="materialized:A407_weighted_reader_W50_recovery_chain",
        quantification="exact retained closure",
        evidence=payload["evidence_stage"],
        domain="AI-native retained inference",
        quality_score=1.0,
        is_inferred=True,
    )
    writer.add_cluster(
        name="A407 weighted learned W50 recovery",
        entities=[
            "A406:weighted_qualified_production_order",
            "A407:sole_factual_W50_model",
            terminal,
        ],
    )
    writer.add_gap(
        subject=terminal,
        predicate="next_required_object",
        expected_object_type="cross_target_weighted_rank_curve_or_W51_transfer",
        confidence=1.0,
        suggested_queries=[
            "Compare the confirmed production rank to all sixteen weighted out-of-fold ranks and transfer after W51 qualification."
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
        reader.api_id != "a407w50"
        or len(explicit) != 2
        or len(all_rows) != 3
        or len(inferred) != 1
        or len(reader._rules) != 2
        or len(reader._clusters) != 1
        or len(reader._gaps) != 1
    ):
        raise RuntimeError("A407 authentic Causal reopen gate failed")
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
            "recovery": explicit[0],
            "confirmation": explicit[1],
            "terminal_chain": all_rows[-1],
            "next_gap": reader._gaps[0],
        },
    }


def recover(*, expected_protocol_sha256: str) -> dict[str, Any]:
    if any(path.exists() for path in (RESULT, CAUSAL, REPORT)):
        raise FileExistsError("A407 result artifact already exists")
    protocol = load_protocol(expected_protocol_sha256)
    if protocol["execution_enabled"] is not True:
        raise RuntimeError("A407 prior-equivalent order is execution-disabled")
    qualification = A391.A389.A385.load_a384_qualification(protocol["A384_qualification_sha256"])
    engine_protocol = A391.A389.A384.load_protocol(A391.A389.A384_PROTOCOL_SHA256)
    executable_row = engine_protocol["anchors"]["grouped_executable"]
    executable = path_from_ref(executable_row["path"])
    anchor(executable, executable_row["sha256"])
    challenge = protocol["public_challenge"]
    placeholder = np.asarray([0, 0], dtype=np.uint32)

    def host_factory() -> Any:
        return A391.A389.A384.A378.A371.A346.A324.A311.A307.A304.GroupedMetalHost(
            executable,
            A391.A389.A384.initial_for_slab(challenge, 0),
            placeholder,
            placeholder,
        )

    def write_progress(row: Mapping[str, Any]) -> None:
        atomic_json(
            PROGRESS,
            {
                "schema": "chacha20-round20-w50-weighted-reader-recovery-a407-progress-v1",
                "attempt_id": ATTEMPT_ID,
                "protocol_sha256": expected_protocol_sha256,
                "selected_operator": SELECTED_OPERATOR,
                "selected_order_uint16be_sha256": protocol["selected_order_uint16be_sha256"],
                "A384_qualification_sha256": protocol["A384_qualification_sha256"],
                **dict(row),
            },
        )

    start, prior_gpu, prior_hosts, completed = load_resume(
        protocol_sha256=expected_protocol_sha256,
        order_sha=protocol["selected_order_uint16be_sha256"],
        qualification_sha256=protocol["A384_qualification_sha256"],
    )
    discovery = completed or A391.A389.ordered_discovery(
        host_factory=host_factory,
        challenge=challenge,
        order=protocol["selected_order"],
        start_group=start,
        prior_gpu_seconds=prior_gpu,
        prior_host_instances=prior_hosts,
        progress_callback=write_progress,
    )
    if discovery["matched_control_candidates"] != 0:
        raise RuntimeError("A407 matched control produced a candidate")
    candidate = int(discovery["candidate"])
    confirmation = A391.A389.A385.confirm(challenge, candidate)
    if confirmation["all_blocks_match"] is not True:
        raise RuntimeError("A407 dual independent confirmation failed")
    ranks = rank_panel(int(discovery["prefix12"]), protocol["selected_order"])
    if ranks["A407_weighted_rank_one_based"] != discovery["executed_prefix_groups"]:
        raise RuntimeError("A407 discovery rank differs from weighted order")
    strict_subset = discovery["executed_prefix_groups"] < CELLS
    evidence_stage = (
        "FULLROUND_R20_WEIGHTED_OUTOFFOLD_LEARNED_W50_STRICT_SUBSET_RECOVERY_CONFIRMED"
        if strict_subset
        else "FULLROUND_R20_WEIGHTED_OUTOFFOLD_LEARNED_W50_COMPLETE_DOMAIN_RECOVERY_CONFIRMED"
    )
    payload: dict[str, Any] = {
        "schema": "chacha20-round20-w50-weighted-reader-recovery-a407-result-v1",
        "attempt_id": ATTEMPT_ID,
        "evidence_stage": evidence_stage,
        "protocol_sha256": expected_protocol_sha256,
        "design_sha256": DESIGN_SHA256,
        "implementation_sha256": protocol["implementation_sha256"],
        "A406_result_sha256": protocol["A406_result_sha256"],
        "A406_deployment_commitment_sha256": protocol["A406_deployment_commitment_sha256"],
        "A402_result_sha256": protocol["A402_result_sha256"],
        "A404_result_sha256": protocol["A404_result_sha256"],
        "A384_qualification_sha256": protocol["A384_qualification_sha256"],
        "A385_protocol_sha256": protocol["A385_protocol_sha256"],
        "public_challenge_sha256": protocol["public_challenge_sha256"],
        "selected_operator": SELECTED_OPERATOR,
        "selected_order_uint16be_sha256": protocol["selected_order_uint16be_sha256"],
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
            "selected_order_uint16be_sha256": protocol["selected_order_uint16be_sha256"],
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
            "# A407 — Weighted learned full-round ChaCha20 W50 recovery\n\n"
            f"Evidence stage: **{evidence_stage}**\n\n"
            f"- Weighted execution rank: **{ranks['A407_weighted_rank_one_based']} / {CELLS}**\n"
            f"- Direct12 comparison rank: **{ranks['A391_Direct12_comparison_rank_one_based']} / {CELLS}**\n"
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
        "A406_result_available": A406_RESULT.exists(),
        "protocol_frozen": PROTOCOL.exists(),
        "progress_exists": PROGRESS.exists(),
        "result_complete": RESULT.exists(),
    }
    if IMPLEMENTATION.exists():
        payload["implementation_sha256"] = file_sha256(IMPLEMENTATION)
    if PROTOCOL.exists():
        value = json.loads(PROTOCOL.read_bytes())
        payload["protocol_sha256"] = file_sha256(PROTOCOL)
        payload["execution_enabled"] = value["execution_enabled"]
        payload["duplicate_prior_orders"] = value["duplicate_prior_orders"]
    if PROGRESS.exists():
        payload["progress"] = json.loads(PROGRESS.read_bytes())
    if RESULT.exists():
        value = json.loads(RESULT.read_bytes())
        payload["result_sha256"] = file_sha256(RESULT)
        payload["evidence_stage"] = value["evidence_stage"]
        payload["rank_analysis"] = value["rank_analysis"]
    return payload


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    action = parser.add_mutually_exclusive_group(required=True)
    action.add_argument("--freeze-implementation", action="store_true")
    action.add_argument("--freeze-protocol", action="store_true")
    action.add_argument("--recover", action="store_true")
    action.add_argument("--analyze", action="store_true")
    parser.add_argument("--expected-implementation-sha256")
    parser.add_argument("--expected-a406-result-sha256")
    parser.add_argument("--expected-a402-result-sha256")
    parser.add_argument("--expected-a404-result-sha256")
    parser.add_argument("--expected-protocol-sha256")
    args = parser.parse_args()
    if args.freeze_implementation:
        payload = freeze_implementation()
    elif args.freeze_protocol:
        required = (
            args.expected_implementation_sha256,
            args.expected_a406_result_sha256,
            args.expected_a402_result_sha256,
            args.expected_a404_result_sha256,
        )
        if not all(required):
            parser.error("--freeze-protocol requires four expected SHA-256 arguments")
        payload = freeze_protocol(
            expected_implementation_sha256=args.expected_implementation_sha256,
            expected_a406_result_sha256=args.expected_a406_result_sha256,
            expected_a402_result_sha256=args.expected_a402_result_sha256,
            expected_a404_result_sha256=args.expected_a404_result_sha256,
        )
    elif args.recover:
        if not args.expected_protocol_sha256:
            parser.error("--recover requires --expected-protocol-sha256")
        payload = recover(expected_protocol_sha256=args.expected_protocol_sha256)
    else:
        payload = analyze()
    print(json.dumps(payload, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()

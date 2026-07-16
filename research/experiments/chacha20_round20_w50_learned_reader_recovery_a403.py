#!/usr/bin/env python3
"""A403: execute a heldout-qualified A402 learned W50 production order."""

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

DESIGN = CONFIGS / "chacha20_round20_w50_learned_reader_recovery_a403_design_v1.json"
IMPLEMENTATION = (
    CONFIGS / "chacha20_round20_w50_learned_reader_recovery_a403_implementation_v1.json"
)
PROTOCOL = CONFIGS / "chacha20_round20_w50_learned_reader_recovery_a403_v1.json"
PROGRESS = RESULTS / "chacha20_round20_w50_learned_reader_recovery_a403_progress_v1.json"
RESULT = RESULTS / "chacha20_round20_w50_learned_reader_recovery_a403_v1.json"
CAUSAL = RESULT.with_suffix(".causal")
REPORT = RESULT.with_suffix(".md")
TEST = ROOT / "tests/test_chacha20_round20_w50_learned_reader_recovery_a403.py"
REPRO = ROOT / "scripts/reproduce_chacha20_round20_w50_learned_reader_recovery_a403.sh"

A391_RUNNER = RESEARCH / "experiments/chacha20_round20_w50_direct12_only_recovery_a391.py"
A402_RUNNER = (
    RESEARCH / "experiments/chacha20_round20_w50_knownkey_fullfit_production_reader_a402.py"
)
A402_DESIGN = (
    CONFIGS / "chacha20_round20_w50_knownkey_fullfit_production_reader_a402_design_v1.json"
)
A402_IMPLEMENTATION = (
    CONFIGS / "chacha20_round20_w50_knownkey_fullfit_production_reader_a402_implementation_v1.json"
)
A402_RESULT = RESULTS / "chacha20_round20_w50_knownkey_fullfit_production_reader_a402_v1.json"

ATTEMPT_ID = "A403"
DESIGN_SHA256 = "d3d2ade7fafdde71f5ac78204bab6c76542764b7ed39e73c0ef8a6e2cc2e22f3"
A391_RUNNER_SHA256 = "d39eaaf6aabae9beb4ddf561a713ac5c943a67700e8e77084606bf457c3380df"
A402_RUNNER_SHA256 = "ecd409f1894fc5a9ca5781fc70f040c6b8eae02878b69f936c5fe399f42d0473"
A402_DESIGN_SHA256 = "15111ce7c820cfc7bebebeff5feaacbc7d8cde68bc4b09ffcd0d216c668134d8"
A402_IMPLEMENTATION_SHA256 = "c90231169d9e94ee8cb398e2a16fa5904e4fd574ce06f3bf1250b85a4f60428e"
A384_QUALIFICATION_SHA256 = "0e31d4d7b0e0bb0e45cd815d975e2898c60eeea16e04498d720f0a58dd41dc30"
A385_PROTOCOL_SHA256 = "801831f2daabe41476c9bf1ec676907f11c1b5465a193ba61d8d1877eb3b0b4b"
SELECTED_OPERATOR = "A402_heldout_qualified_sixteen_target_fullfit_production_reader"
CELLS = 4096
GROUP_SIZE = 1 << 38
DOMAIN_SIZE = 1 << 50
DOTCAUSAL_SRC = Path("/Users/bhkmie/Documents/Forschung/O1/vendor/fabel/dotcausal_package/src")


def load_module(path: Path, name: str) -> Any:
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot import A403 dependency {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


A391 = load_module(A391_RUNNER, "a403_a391")
A402 = load_module(A402_RUNNER, "a403_a402")

file_sha256 = A391.file_sha256
canonical_sha256 = A391.canonical_sha256
atomic_json = A391.atomic_json
atomic_bytes = A391.atomic_bytes
relative = A391.relative
path_from_ref = A391.path_from_ref
anchor = A391.anchor


def exact_order(values: Sequence[int], label: str) -> list[int]:
    return A391.exact_order(values, f"A403 {label}")


def order_sha256(values: Sequence[int]) -> str:
    return A391.order_sha256(exact_order(values, "order hash"))


def rank_vector(values: Sequence[int]) -> list[int]:
    return A391.rank_vector(exact_order(values, "rank vector"))


def load_design() -> dict[str, Any]:
    if file_sha256(DESIGN) != DESIGN_SHA256:
        raise RuntimeError("A403 design hash differs")
    value = json.loads(DESIGN.read_bytes())
    source = value.get("source_order_contract", {})
    execution = value.get("execution_contract", {})
    boundary = value.get("information_boundary", {})
    if (
        value.get("schema") != "chacha20-round20-w50-learned-reader-recovery-a403-design-v1"
        or value.get("attempt_id") != ATTEMPT_ID
        or value.get("design_state")
        != "frozen_while_A401_measurement_was_running_before_A401_selection_result_A402_result_or_any_A403_candidate_prefix"
        or source.get("required_A402_qualification") is not True
        or source.get("required_order_cells") != CELLS
        or source.get("target_labels_used_for_order") != 0
        or execution.get("unknown_key_bits") != 50
        or execution.get("complete_prefix_groups") != CELLS
        or execution.get("candidates_per_prefix_group") != GROUP_SIZE
        or execution.get("complete_domain_assignments") != DOMAIN_SIZE
        or execution.get("slabs_per_prefix_group") != 128
        or boundary.get("A401_selection_or_result_available_at_design_freeze") is not False
        or boundary.get("A402_result_or_production_order_available_at_design_freeze") is not False
        or boundary.get("A403_candidate_or_prefix_available_at_design_freeze") is not False
    ):
        raise RuntimeError("A403 frozen design semantics differ")
    for key, source_path in value["source_anchors"].items():
        if key.endswith("_path"):
            expected = value["source_anchors"][key.removesuffix("_path") + "_sha256"]
            anchor(ROOT / source_path, expected)
    return value


def freeze_implementation() -> dict[str, Any]:
    outputs = (IMPLEMENTATION, PROTOCOL, PROGRESS, RESULT, CAUSAL, REPORT)
    if any(path.exists() for path in outputs):
        raise FileExistsError("A403 implementation or execution artifact already exists")
    if A402_RESULT.exists() or A402.A401.RESULT.exists() or A402.A401.SELECTION.exists():
        raise RuntimeError("A403 code freeze must precede A401 and A402 results")
    load_design()
    A391.A389.load_sources()
    if not TEST.exists() or not REPRO.exists():
        raise FileNotFoundError("A403 test and reproducer must precede freeze")
    payload: dict[str, Any] = {
        "schema": "chacha20-round20-w50-learned-reader-recovery-a403-implementation-v1",
        "attempt_id": ATTEMPT_ID,
        "commitment_state": "complete_executor_frozen_before_A401_selection_A402_result_order_or_A403_candidate",
        "design_sha256": DESIGN_SHA256,
        "selected_operator": SELECTED_OPERATOR,
        "A401_selection_or_result_available_at_freeze": False,
        "A402_result_or_order_available_at_freeze": False,
        "A403_candidate_or_prefix_available_at_freeze": False,
        "anchors": {
            "design": anchor(DESIGN, DESIGN_SHA256),
            "A391_runner": anchor(A391_RUNNER, A391_RUNNER_SHA256),
            "A402_design": anchor(A402_DESIGN, A402_DESIGN_SHA256),
            "A402_runner": anchor(A402_RUNNER, A402_RUNNER_SHA256),
            "A402_implementation": anchor(A402_IMPLEMENTATION, A402_IMPLEMENTATION_SHA256),
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
        raise RuntimeError("A403 implementation file hash differs")
    value = json.loads(IMPLEMENTATION.read_bytes())
    if (
        value.get("schema") != "chacha20-round20-w50-learned-reader-recovery-a403-implementation-v1"
        or value.get("attempt_id") != ATTEMPT_ID
        or value.get("commitment_state")
        != "complete_executor_frozen_before_A401_selection_A402_result_order_or_A403_candidate"
        or value.get("selected_operator") != SELECTED_OPERATOR
        or value.get("A401_selection_or_result_available_at_freeze") is not False
        or value.get("A402_result_or_order_available_at_freeze") is not False
        or value.get("A403_candidate_or_prefix_available_at_freeze") is not False
    ):
        raise RuntimeError("A403 implementation semantics differ")
    for row in value["anchors"].values():
        anchor(path_from_ref(row["path"]), row["sha256"])
    unsigned = {
        key: item for key, item in value.items() if key != "implementation_commitment_sha256"
    }
    if value.get("implementation_commitment_sha256") != canonical_sha256(unsigned):
        raise RuntimeError("A403 implementation commitment differs")
    return value


def load_a402_order(expected_result_sha256: str) -> tuple[dict[str, Any], list[int]]:
    if file_sha256(A402_RESULT) != expected_result_sha256:
        raise RuntimeError("A403 A402 result hash differs")
    value = json.loads(A402_RESULT.read_bytes())
    order = exact_order(value.get("production_order", []), "A402 production order")
    source = load_design()["source_order_contract"]
    if (
        value.get("schema")
        != "chacha20-round20-w50-knownkey-fullfit-production-reader-a402-result-v1"
        or value.get("attempt_id") != "A402"
        or value.get("evidence_stage") != source["required_A402_evidence_stage"]
        or value.get("qualification", {}).get("qualified") is not True
        or value.get("production_order_uint16be_sha256") != order_sha256(order)
        or value.get("production_target_labels_used") != 0
        or value.get("production_reader_refits") != 0
        or value.get("production_candidate_assignments_executed") != 0
        or value.get("new_solver_stages") != 0
        or value.get("live_recovery_progress_filter_outcomes_or_results_consumed") is not False
    ):
        raise RuntimeError("A403 A402 qualified-order semantics differ")
    return value, order


def freeze_protocol(
    *, expected_implementation_sha256: str, expected_a402_result_sha256: str
) -> dict[str, Any]:
    if any(path.exists() for path in (PROTOCOL, PROGRESS, RESULT, CAUSAL, REPORT)):
        raise FileExistsError("A403 protocol or execution artifact already exists")
    implementation = load_implementation(expected_implementation_sha256)
    a402, learned_order = load_a402_order(expected_a402_result_sha256)
    source, _a388, qualification, _source_orders = A391.A389.load_sources()
    payload: dict[str, Any] = {
        "schema": "chacha20-round20-w50-learned-reader-recovery-a403-protocol-v1",
        "attempt_id": ATTEMPT_ID,
        "protocol_state": "heldout_qualified_A402_order_bound_before_any_A403_candidate_prefix_or_result",
        "design_sha256": DESIGN_SHA256,
        "implementation_sha256": expected_implementation_sha256,
        "implementation_commitment_sha256": implementation["implementation_commitment_sha256"],
        "A402_result_sha256": expected_a402_result_sha256,
        "A402_deployment_commitment_sha256": a402["deployment_commitment_sha256"],
        "A384_qualification_sha256": A384_QUALIFICATION_SHA256,
        "A384_semantic_qualification_sha256": qualification["qualification_sha256"],
        "A385_protocol_sha256": A385_PROTOCOL_SHA256,
        "public_challenge_sha256": source["public_challenge_sha256"],
        "public_challenge": source["public_challenge"],
        "selected_operator": SELECTED_OPERATOR,
        "selected_order_uint16be_sha256": order_sha256(learned_order),
        "selected_order": learned_order,
        "execution_contract": load_design()["execution_contract"],
        "information_boundary": {
            "A403_candidate_or_prefix_available_at_protocol_freeze": False,
            "A402_order_bound_without_mutation": True,
            "A385_assignment_absent_from_protocol": True,
            "target_labels_used_for_order_construction": 0,
            "production_reader_refits": 0,
            "candidate_assignments_executed_for_order": 0,
            "live_recovery_progress_filter_outcomes_or_results_consumed_for_order": False,
        },
        "anchors": {
            "design": anchor(DESIGN, DESIGN_SHA256),
            "implementation": anchor(IMPLEMENTATION, expected_implementation_sha256),
            "A402_result": anchor(A402_RESULT, expected_a402_result_sha256),
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
            "A402_deployment_commitment_sha256": payload["A402_deployment_commitment_sha256"],
            "A384_qualification_sha256": payload["A384_qualification_sha256"],
            "selected_order_uint16be_sha256": payload["selected_order_uint16be_sha256"],
            "public_challenge_sha256": payload["public_challenge_sha256"],
            "information_boundary": payload["information_boundary"],
        }
    )
    atomic_json(PROTOCOL, payload)
    return payload


def load_protocol(expected_sha256: str) -> dict[str, Any]:
    if file_sha256(PROTOCOL) != expected_sha256:
        raise RuntimeError("A403 protocol hash differs")
    value = json.loads(PROTOCOL.read_bytes())
    order = exact_order(value.get("selected_order", []), "stored order")
    boundary = value.get("information_boundary", {})
    if (
        value.get("schema") != "chacha20-round20-w50-learned-reader-recovery-a403-protocol-v1"
        or value.get("attempt_id") != ATTEMPT_ID
        or value.get("selected_operator") != SELECTED_OPERATOR
        or value.get("selected_order_uint16be_sha256") != order_sha256(order)
        or boundary.get("A403_candidate_or_prefix_available_at_protocol_freeze") is not False
        or boundary.get("A402_order_bound_without_mutation") is not True
        or boundary.get("target_labels_used_for_order_construction") != 0
        or canonical_sha256(value.get("public_challenge")) != value.get("public_challenge_sha256")
    ):
        raise RuntimeError("A403 protocol semantics differ")
    for row in value["anchors"].values():
        anchor(path_from_ref(row["path"]), row["sha256"])
    load_implementation(value["implementation_sha256"])
    a402, expected_order = load_a402_order(value["A402_result_sha256"])
    if (
        order != expected_order
        or value["A402_deployment_commitment_sha256"] != a402["deployment_commitment_sha256"]
    ):
        raise RuntimeError("A403 protocol no longer equals A402")
    A391.A389.A385.validate_challenge(value["public_challenge"])
    return value


def load_resume(
    *, protocol_sha256: str, order_sha: str, qualification_sha256: str
) -> tuple[int, float, int, dict[str, Any] | None]:
    if not PROGRESS.exists():
        return 0, 0.0, 0, None
    value = json.loads(PROGRESS.read_bytes())
    if (
        value.get("schema") != "chacha20-round20-w50-learned-reader-recovery-a403-progress-v1"
        or value.get("attempt_id") != ATTEMPT_ID
        or value.get("protocol_sha256") != protocol_sha256
        or value.get("selected_order_uint16be_sha256") != order_sha
        or value.get("A384_qualification_sha256") != qualification_sha256
        or value.get("matched_control_candidates") != 0
    ):
        raise RuntimeError("A403 progress fingerprint differs")
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
        raise RuntimeError("A403 resumable progress state differs")
    return (
        completed,
        float(value.get("gpu_seconds", 0.0)),
        int(value.get("host_instances", 0)),
        None,
    )


def rank_panel(prefix: int, learned: Sequence[int]) -> dict[str, Any]:
    a388 = json.loads(A391.A388_ORDER.read_bytes())
    learned_rank = rank_vector(learned)[prefix]
    direct_rank = rank_vector(a388["W50_public_output_direct12_order"])[prefix]
    factor3_rank = rank_vector(a388["selected_order"])[prefix]
    return {
        "prefix12": prefix,
        "prefix12_hex": f"{prefix:03x}",
        "A403_learned_rank_one_based": learned_rank,
        "A391_Direct12_comparison_rank_one_based": direct_rank,
        "A388_factor3_comparison_rank_one_based": factor3_rank,
        "learned_gain_bits_vs_complete_domain": math.log2(CELLS / learned_rank),
        "learned_domain_reduction_factor": CELLS / learned_rank,
        "learned_rank_ratio_to_Direct12": learned_rank / direct_rank,
        "learned_rank_ratio_to_A388_factor3": learned_rank / factor3_rank,
        "ranks_computed_only_after_independent_confirmation": True,
    }


def build_causal(payload: Mapping[str, Any]) -> dict[str, Any]:
    sys.path.insert(0, str(DOTCAUSAL_SRC))
    from dotcausal.io import CausalReader, CausalWriter

    terminal = "A403:confirmed_learned_reader_W50_recovery"
    writer = CausalWriter(api_id="a403w50")
    writer._rules = []
    writer.add_rule(
        name="heldout_qualified_reader_and_complete_engine_to_model",
        description="The A402 learned order executes complete qualified W50 groups until the sole factual model appears.",
        pattern=["A402_heldout_qualified_production_order", "A384_exact_W50_group_engine"],
        conclusion="A403_sole_factual_W50_model",
        confidence_modifier=1.0,
    )
    writer.add_rule(
        name="model_to_confirmed_recovery",
        description="The factual model passes matched control and dual independent confirmation across all eight standard blocks.",
        pattern=["A403_sole_factual_W50_model"],
        conclusion="A403_confirmed_learned_reader_W50_recovery",
        confidence_modifier=1.0,
    )
    writer.add_triplet(
        trigger="A402:heldout_qualified_production_order",
        mechanism="qualified_complete_onehundredtwentyeight_slab_group_search",
        outcome="A403:sole_factual_W50_model",
        confidence=1.0,
        source=payload["execution_sha256"],
        quantification=json.dumps(payload["discovery"], sort_keys=True),
        evidence=json.dumps(payload["rank_analysis"], sort_keys=True),
        domain="fresh full-round ChaCha20 W50 learned-Reader recovery",
        quality_score=1.0,
    )
    writer.add_triplet(
        trigger="A403:sole_factual_W50_model",
        mechanism="matched_control_plus_dual_independent_eight_block_confirmation",
        outcome=terminal,
        confidence=1.0,
        source=payload["measurement_sha256"],
        quantification=json.dumps(payload["confirmation"], sort_keys=True),
        evidence=payload["evidence_stage"],
        domain="confirmed full-round ChaCha20 W50 learned-Reader recovery",
        quality_score=1.0,
    )
    writer.add_triplet(
        trigger="A402:heldout_qualified_production_order",
        mechanism="materialized_learned_search_and_confirmation_closure",
        outcome=terminal,
        confidence=1.0,
        source="materialized:A403_learned_reader_W50_recovery_chain",
        quantification="exact retained closure",
        evidence=payload["evidence_stage"],
        domain="AI-native retained inference",
        quality_score=1.0,
        is_inferred=True,
    )
    writer.add_cluster(
        name="A403 heldout-qualified learned W50 recovery",
        entities=[
            "A402:heldout_qualified_production_order",
            "A403:sole_factual_W50_model",
            terminal,
        ],
    )
    writer.add_gap(
        subject=terminal,
        predicate="next_required_object",
        expected_object_type="cross_target_learned_rank_curve_or_W51_transfer",
        confidence=1.0,
        suggested_queries=[
            "Compare the confirmed production rank to all sixteen known-key ranks and transfer after W51 qualification."
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
        reader.api_id != "a403w50"
        or len(explicit) != 2
        or len(all_rows) != 3
        or len(inferred) != 1
        or len(reader._rules) != 2
        or len(reader._clusters) != 1
        or len(reader._gaps) != 1
    ):
        raise RuntimeError("A403 authentic Causal reopen gate failed")
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
        raise FileExistsError("A403 result artifact already exists")
    protocol = load_protocol(expected_protocol_sha256)
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
                "schema": "chacha20-round20-w50-learned-reader-recovery-a403-progress-v1",
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
        raise RuntimeError("A403 matched control produced a candidate")
    candidate = int(discovery["candidate"])
    confirmation = A391.A389.A385.confirm(challenge, candidate)
    if confirmation["all_blocks_match"] is not True:
        raise RuntimeError("A403 dual independent confirmation failed")
    ranks = rank_panel(int(discovery["prefix12"]), protocol["selected_order"])
    if ranks["A403_learned_rank_one_based"] != discovery["executed_prefix_groups"]:
        raise RuntimeError("A403 discovery rank differs from learned order")
    strict_subset = discovery["executed_prefix_groups"] < CELLS
    evidence_stage = (
        "FULLROUND_R20_HELDOUT_QUALIFIED_LEARNED_W50_STRICT_SUBSET_RECOVERY_CONFIRMED"
        if strict_subset
        else "FULLROUND_R20_HELDOUT_QUALIFIED_LEARNED_W50_COMPLETE_DOMAIN_RECOVERY_CONFIRMED"
    )
    payload: dict[str, Any] = {
        "schema": "chacha20-round20-w50-learned-reader-recovery-a403-result-v1",
        "attempt_id": ATTEMPT_ID,
        "evidence_stage": evidence_stage,
        "protocol_sha256": expected_protocol_sha256,
        "design_sha256": DESIGN_SHA256,
        "implementation_sha256": protocol["implementation_sha256"],
        "A402_result_sha256": protocol["A402_result_sha256"],
        "A402_deployment_commitment_sha256": protocol["A402_deployment_commitment_sha256"],
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
            "# A403 — Heldout-qualified learned full-round ChaCha20 W50 recovery\n\n"
            f"Evidence stage: **{evidence_stage}**\n\n"
            f"- Learned execution rank: **{ranks['A403_learned_rank_one_based']} / {CELLS}**\n"
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
        "A402_result_available": A402_RESULT.exists(),
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
        value = json.loads(RESULT.read_bytes())
        payload["result_sha256"] = file_sha256(RESULT)
        payload["evidence_stage"] = value["evidence_stage"]
    return payload


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    action = parser.add_mutually_exclusive_group(required=True)
    action.add_argument("--analyze", action="store_true")
    action.add_argument("--freeze-implementation", action="store_true")
    action.add_argument("--freeze-protocol", action="store_true")
    action.add_argument("--recover", action="store_true")
    parser.add_argument("--expected-implementation-sha256")
    parser.add_argument("--expected-a402-result-sha256")
    parser.add_argument("--expected-protocol-sha256")
    args = parser.parse_args()
    if args.freeze_implementation:
        payload = freeze_implementation()
    elif args.freeze_protocol:
        if not args.expected_implementation_sha256 or not args.expected_a402_result_sha256:
            parser.error("--freeze-protocol requires implementation and A402 result SHA-256")
        payload = freeze_protocol(
            expected_implementation_sha256=args.expected_implementation_sha256,
            expected_a402_result_sha256=args.expected_a402_result_sha256,
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

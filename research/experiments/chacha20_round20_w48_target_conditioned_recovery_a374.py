#!/usr/bin/env python3
"""A374: execute the frozen A373 W48 portfolio with the qualified 32-slab engine."""

from __future__ import annotations

import argparse
import importlib.util
import inspect
import json
import math
import os
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

DESIGN = CONFIGS / "chacha20_round20_w48_target_conditioned_recovery_a374_design_v1.json"
IMPLEMENTATION = CONFIGS / "chacha20_round20_w48_target_conditioned_recovery_a374_implementation_v1.json"
PROTOCOL = CONFIGS / "chacha20_round20_w48_target_conditioned_recovery_a374_v1.json"
PROGRESS = RESULTS / "chacha20_round20_w48_target_conditioned_recovery_a374_progress_v1.json"
RESULT = RESULTS / "chacha20_round20_w48_target_conditioned_recovery_a374_v1.json"
CAUSAL = RESULT.with_suffix(".causal")
REPORT = RESULT.with_suffix(".md")
TEST = ROOT / "tests/test_chacha20_round20_w48_target_conditioned_recovery_a374.py"
REPRO = ROOT / "scripts/reproduce_chacha20_round20_w48_target_conditioned_recovery_a374.sh"

A371_PROTOCOL = CONFIGS / "chacha20_round20_w48_thirtytwo_slab_grouped_engine_a371_v1.json"
A371_QUALIFICATION = RESULTS / "chacha20_round20_w48_thirtytwo_slab_grouped_engine_a371_qualification_v1.json"
A372_RUNNER = RESEARCH / "experiments/chacha20_round20_fresh_w48_pretarget_transfer_a372.py"
A372_DESIGN = CONFIGS / "chacha20_round20_fresh_w48_pretarget_transfer_a372_design_v1.json"
A372_IMPLEMENTATION = CONFIGS / "chacha20_round20_fresh_w48_pretarget_transfer_a372_implementation_v1.json"
A372_ORDER = RESULTS / "chacha20_round20_fresh_w48_pretarget_transfer_a372_order_v1.json"
A372_PROTOCOL = CONFIGS / "chacha20_round20_fresh_w48_pretarget_transfer_a372_v1.json"
A373_RUNNER = RESEARCH / "experiments/chacha20_round20_w48_target_conditioned_factor2_a373.py"
A373_DESIGN = CONFIGS / "chacha20_round20_w48_target_conditioned_factor2_a373_design_v1.json"
A373_IMPLEMENTATION = CONFIGS / "chacha20_round20_w48_target_conditioned_factor2_a373_implementation_v1.json"
A373_ORDER = RESULTS / "chacha20_round20_w48_target_conditioned_factor2_a373_order_v1.json"

ATTEMPT_ID = "A374"
DESIGN_SHA256 = "22f02caa3a0bd91e524605da7f970b3ce805d4b152f9dea0bba5de5cb5678cde"
A371_PROTOCOL_SHA256 = "edd943f71990299312c7b7bc154015102af25eede97ea4784140a2b652e971f3"
A371_QUALIFICATION_SHA256 = "2094ca66fcd3ba068994ab2cd8b792f991920862a5e94ce24246900c75c2ee2c"
A372_DESIGN_SHA256 = "baf1bb8f5a4236268d9933ebd1a8dea3897eb608b424f935ce75b8b2597a3a8c"
A372_IMPLEMENTATION_SHA256 = "5676abd7674309aeb7c390c4516380caaccca173dcf1748317e7d4f1b368b50e"
A372_ORDER_SHA256 = "bbc5e61fb0867125c08b08e31f166c686accf1d41c73f27e0b2774371483e3f5"
A372_PROTOCOL_SHA256 = "9223d8a9da09112f62e85f8c3d8ae8a737d3793661b9eb563944191411be846f"
A373_DESIGN_SHA256 = "3af5902d6ec1a8520c73905c64372560f44a0a6781c615789da0840011a0ce67"
A373_IMPLEMENTATION_SHA256 = "7079aa0ec4e5605a8cd0c73de3a8f022376d7e3a9be35ca01f6bdb80cec05b6a"
A373_ORDER_SHA256 = "5631b0f2f05a015a9ad07b938a2f2862862214171d3066397da3524afe8e9264"

WIDTH = 48
PREFIX_BITS = 12
WORD0_SUFFIX_BITS = 20
CELLS = 1 << PREFIX_BITS
GROUP_SIZE = 1 << (WIDTH - PREFIX_BITS)
DOMAIN_SIZE = 1 << WIDTH
MASK32 = 0xFFFFFFFF
HOST_REFRESH_GROUPS = 16
SELECTED_OPERATOR = "A373_W48_target_conditioned_plus_A372_target_free_factor2_wavefront"
DOTCAUSAL_SRC = Path("/Users/bhkmie/Documents/Forschung/O1/vendor/fabel/dotcausal_package/src")


def load_module(path: Path, name: str) -> Any:
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot import A374 dependency {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


A372 = load_module(A372_RUNNER, "a374_a372")
A373 = load_module(A373_RUNNER, "a374_a373")
file_sha256 = A372.file_sha256
canonical_sha256 = A372.canonical_sha256
atomic_json = A372.atomic_json
atomic_bytes = A372.A347.atomic_bytes
relative = A372.relative
path_from_ref = A372.path_from_ref
anchor = A372.anchor


def exact_order(values: Sequence[int], label: str) -> list[int]:
    order = [int(value) for value in values]
    if len(order) != CELLS or set(order) != set(range(CELLS)):
        raise ValueError(f"A374 {label} is not an exact 4,096-cell order")
    return order


def order_sha256(order: Sequence[int]) -> str:
    return A373.A351.order_sha256(exact_order(order, "hash"))


def rank_vector(order: Sequence[int]) -> list[int]:
    ranks = [0] * CELLS
    for rank, cell in enumerate(exact_order(order, "rank vector"), 1):
        ranks[cell] = rank
    return ranks


def load_design() -> dict[str, Any]:
    if file_sha256(DESIGN) != DESIGN_SHA256:
        raise RuntimeError("A374 design hash differs")
    value = json.loads(DESIGN.read_bytes())
    boundary = value.get("information_boundary", {})
    execution = value.get("execution_contract", {})
    order = value.get("order_contract", {})
    if (
        value.get("schema") != "chacha20-round20-w48-target-conditioned-recovery-a374-design-v1"
        or value.get("attempt_id") != ATTEMPT_ID
        or value.get("design_state")
        != "frozen_after_A371_qualification_A372_protocol_A373_order_before_any_W48_candidate_prefix_or_result"
        or boundary.get("A371_qualification_available_at_design_freeze") is not True
        or boundary.get("A372_protocol_available_at_design_freeze") is not True
        or boundary.get("A373_order_available_at_design_freeze") is not True
        or boundary.get("A374_candidate_or_prefix_available_at_design_freeze") is not False
        or execution.get("unknown_key_bits") != WIDTH
        or execution.get("candidates_per_prefix_group") != GROUP_SIZE
        or execution.get("complete_domain_assignments") != DOMAIN_SIZE
        or execution.get("slabs_per_prefix_group") != 32
        or order.get("target_labels_used") != 0
        or order.get("reader_refits") != 0
    ):
        raise RuntimeError("A374 frozen design semantics differ")
    for key, source_path in value["source_anchors"].items():
        if key.endswith("_path"):
            expected = value["source_anchors"][key.removesuffix("_path") + "_sha256"]
            anchor(ROOT / source_path, expected)
    return value


def assert_pre_execution() -> None:
    if PROGRESS.exists() or RESULT.exists():
        raise RuntimeError("A374 frozen artifacts must precede every W48 candidate and result")


def freeze_implementation() -> dict[str, Any]:
    if any(path.exists() for path in (IMPLEMENTATION, PROTOCOL, PROGRESS, RESULT, CAUSAL, REPORT)):
        raise FileExistsError("A374 implementation or execution artifacts already exist")
    assert_pre_execution()
    load_design()
    if not TEST.exists() or not REPRO.exists():
        raise FileNotFoundError("A374 test and reproducer must precede implementation freeze")
    payload: dict[str, Any] = {
        "schema": "chacha20-round20-w48-target-conditioned-recovery-a374-implementation-v1",
        "attempt_id": ATTEMPT_ID,
        "commitment_state": "frozen_after_A371_qualification_A372_protocol_A373_order_before_A374_candidate_prefix_or_result",
        "design_sha256": DESIGN_SHA256,
        "selected_operator": SELECTED_OPERATOR,
        "A371_qualification_available_at_implementation_freeze": True,
        "A372_protocol_available_at_implementation_freeze": True,
        "A373_order_available_at_implementation_freeze": True,
        "A374_candidate_or_prefix_available_at_implementation_freeze": False,
        "anchors": {
            "design": anchor(DESIGN, DESIGN_SHA256),
            "A371_protocol": anchor(A371_PROTOCOL, A371_PROTOCOL_SHA256),
            "A371_qualification": anchor(A371_QUALIFICATION, A371_QUALIFICATION_SHA256),
            "A372_design": anchor(A372_DESIGN, A372_DESIGN_SHA256),
            "A372_implementation": anchor(A372_IMPLEMENTATION, A372_IMPLEMENTATION_SHA256),
            "A372_order": anchor(A372_ORDER, A372_ORDER_SHA256),
            "A372_protocol": anchor(A372_PROTOCOL, A372_PROTOCOL_SHA256),
            "A372_runner": anchor(A372_RUNNER),
            "A373_design": anchor(A373_DESIGN, A373_DESIGN_SHA256),
            "A373_implementation": anchor(A373_IMPLEMENTATION, A373_IMPLEMENTATION_SHA256),
            "A373_order": anchor(A373_ORDER, A373_ORDER_SHA256),
            "A373_runner": anchor(A373_RUNNER),
            "runner": anchor(Path(__file__)),
            "test": anchor(TEST),
            "reproducer": anchor(REPRO),
        },
    }
    payload["implementation_commitment_sha256"] = canonical_sha256(payload)
    atomic_json(IMPLEMENTATION, payload)
    try:
        assert_pre_execution()
    except Exception:
        IMPLEMENTATION.unlink(missing_ok=True)
        raise
    return payload


def load_implementation(expected_sha256: str) -> dict[str, Any]:
    if file_sha256(IMPLEMENTATION) != expected_sha256:
        raise RuntimeError("A374 implementation hash differs")
    value = json.loads(IMPLEMENTATION.read_bytes())
    if (
        value.get("schema")
        != "chacha20-round20-w48-target-conditioned-recovery-a374-implementation-v1"
        or value.get("attempt_id") != ATTEMPT_ID
        or value.get("commitment_state")
        != "frozen_after_A371_qualification_A372_protocol_A373_order_before_A374_candidate_prefix_or_result"
        or value.get("design_sha256") != DESIGN_SHA256
        or value.get("selected_operator") != SELECTED_OPERATOR
        or value.get("A371_qualification_available_at_implementation_freeze") is not True
        or value.get("A372_protocol_available_at_implementation_freeze") is not True
        or value.get("A373_order_available_at_implementation_freeze") is not True
    ):
        raise RuntimeError("A374 implementation semantics differ")
    expected = {
        "design": DESIGN,
        "A371_protocol": A371_PROTOCOL,
        "A371_qualification": A371_QUALIFICATION,
        "A372_design": A372_DESIGN,
        "A372_implementation": A372_IMPLEMENTATION,
        "A372_order": A372_ORDER,
        "A372_protocol": A372_PROTOCOL,
        "A372_runner": A372_RUNNER,
        "A373_design": A373_DESIGN,
        "A373_implementation": A373_IMPLEMENTATION,
        "A373_order": A373_ORDER,
        "A373_runner": A373_RUNNER,
        "runner": Path(__file__),
        "test": TEST,
        "reproducer": REPRO,
    }
    for name, path in expected.items():
        row = value["anchors"][name]
        if row.get("path") != relative(path) or row.get("sha256") != file_sha256(path):
            raise RuntimeError(f"A374 implementation anchor differs: {name}")
    unsigned = {key: item for key, item in value.items() if key != "implementation_commitment_sha256"}
    if value.get("implementation_commitment_sha256") != canonical_sha256(unsigned):
        raise RuntimeError("A374 implementation commitment differs")
    return value


def load_a373_order(expected_sha256: str, expected_a372_protocol_sha256: str) -> dict[str, Any]:
    if file_sha256(A373_ORDER) != expected_sha256:
        raise RuntimeError("A374 A373 order artifact hash differs")
    value = json.loads(A373_ORDER.read_bytes())
    selected = exact_order(value.get("selected_order", []), "A373 selected order")
    target = exact_order(value.get("target_conditioned_order", []), "A373 target-conditioned order")
    source = exact_order(A372.load_order()["selected_order"], "A372 source order")
    if (
        value.get("schema") != "chacha20-round20-w48-target-conditioned-factor2-a373-order-v1"
        or value.get("A372_protocol_sha256") != expected_a372_protocol_sha256
        or value.get("W48_recovery_available_at_order_freeze") is not False
        or value.get("target_labels_used") != 0
        or value.get("reader_refits") != 0
        or value.get("candidate_assignments_executed") != 0
        or value.get("selected_order_uint16be_sha256") != order_sha256(selected)
        or value.get("target_conditioned_order_uint16be_sha256") != order_sha256(target)
        or selected != A373.A351.factor2_wavefront(source, target)
        or value.get("pointwise_factor2_proof")
        != A373.A351.factor2_proof(source, target, selected)
    ):
        raise RuntimeError("A374 A373 order semantics differ")
    return value


def freeze_protocol(
    *,
    expected_implementation_sha256: str,
    expected_a372_protocol_sha256: str,
    expected_a373_order_sha256: str,
    expected_a371_qualification_sha256: str,
) -> dict[str, Any]:
    if any(path.exists() for path in (PROTOCOL, PROGRESS, RESULT, CAUSAL, REPORT)):
        raise FileExistsError("A374 protocol or execution artifacts already exist")
    assert_pre_execution()
    implementation = load_implementation(expected_implementation_sha256)
    source_protocol = A372.load_protocol(expected_a372_protocol_sha256)
    order = load_a373_order(expected_a373_order_sha256, expected_a372_protocol_sha256)
    qualification = A372.load_a371_qualification(expected_a371_qualification_sha256)
    selected = exact_order(order["selected_order"], "protocol selected")
    payload: dict[str, Any] = {
        "schema": "chacha20-round20-w48-target-conditioned-recovery-a374-protocol-v1",
        "attempt_id": ATTEMPT_ID,
        "protocol_state": "A373_order_bound_after_public_measurement_before_any_A374_candidate_prefix_or_result",
        "design_sha256": DESIGN_SHA256,
        "implementation_sha256": expected_implementation_sha256,
        "implementation_commitment_sha256": implementation["implementation_commitment_sha256"],
        "A371_qualification_sha256": expected_a371_qualification_sha256,
        "A371_semantic_qualification_sha256": qualification["qualification_sha256"],
        "A372_protocol_sha256": expected_a372_protocol_sha256,
        "A373_order_sha256": expected_a373_order_sha256,
        "A373_order_commitment_sha256": order["order_commitment_sha256"],
        "public_challenge_sha256": source_protocol["public_challenge_sha256"],
        "public_challenge": source_protocol["public_challenge"],
        "selected_operator": SELECTED_OPERATOR,
        "selected_order_uint16be_sha256": order_sha256(selected),
        "selected_order": selected,
        "target_conditioned_order_uint16be_sha256": order[
            "target_conditioned_order_uint16be_sha256"
        ],
        "pointwise_factor2_proof": order["pointwise_factor2_proof"],
        "operator_diversity": order["operator_diversity"],
        "execution_contract": load_design()["execution_contract"],
        "information_boundary": {
            "A374_candidate_or_prefix_available_at_protocol_freeze": False,
            "A373_order_frozen_before_protocol": True,
            "target_labels_used_for_order_construction": 0,
            "reader_refits": 0,
        },
        "anchors": {
            "design": anchor(DESIGN, DESIGN_SHA256),
            "implementation": anchor(IMPLEMENTATION, expected_implementation_sha256),
            "A371_protocol": anchor(A371_PROTOCOL, A371_PROTOCOL_SHA256),
            "A371_qualification": anchor(A371_QUALIFICATION, expected_a371_qualification_sha256),
            "A372_protocol": anchor(A372_PROTOCOL, expected_a372_protocol_sha256),
            "A372_order": anchor(A372_ORDER, A372_ORDER_SHA256),
            "A373_order": anchor(A373_ORDER, expected_a373_order_sha256),
            "runner": anchor(Path(__file__)),
            "test": anchor(TEST),
            "reproducer": anchor(REPRO),
        },
    }
    payload["protocol_commitment_sha256"] = canonical_sha256(
        {
            "implementation_commitment_sha256": payload["implementation_commitment_sha256"],
            "A372_protocol_sha256": expected_a372_protocol_sha256,
            "A373_order_sha256": expected_a373_order_sha256,
            "A373_order_commitment_sha256": payload["A373_order_commitment_sha256"],
            "selected_order_uint16be_sha256": payload["selected_order_uint16be_sha256"],
            "public_challenge_sha256": payload["public_challenge_sha256"],
            "A371_qualification_sha256": expected_a371_qualification_sha256,
            "information_boundary": payload["information_boundary"],
        }
    )
    atomic_json(PROTOCOL, payload)
    if PROGRESS.exists() or RESULT.exists():
        PROTOCOL.unlink(missing_ok=True)
        raise RuntimeError("A374 protocol did not precede A374 execution")
    return payload


def load_protocol(expected_sha256: str) -> dict[str, Any]:
    if file_sha256(PROTOCOL) != expected_sha256:
        raise RuntimeError("A374 protocol hash differs")
    value = json.loads(PROTOCOL.read_bytes())
    selected = exact_order(value.get("selected_order", []), "stored protocol order")
    if (
        value.get("schema") != "chacha20-round20-w48-target-conditioned-recovery-a374-protocol-v1"
        or value.get("attempt_id") != ATTEMPT_ID
        or value.get("selected_operator") != SELECTED_OPERATOR
        or value.get("selected_order_uint16be_sha256") != order_sha256(selected)
        or value.get("information_boundary", {}).get(
            "A374_candidate_or_prefix_available_at_protocol_freeze"
        )
        is not False
        or value.get("information_boundary", {}).get("target_labels_used_for_order_construction")
        != 0
        or canonical_sha256(value.get("public_challenge")) != value.get("public_challenge_sha256")
    ):
        raise RuntimeError("A374 protocol semantics differ")
    for row in value["anchors"].values():
        anchor(path_from_ref(row["path"]), row["sha256"])
    load_implementation(value["implementation_sha256"])
    load_a373_order(value["A373_order_sha256"], value["A372_protocol_sha256"])
    A372.validate_challenge(value["public_challenge"])
    return value


def load_resume(
    *, protocol_sha256: str, order_sha: str, qualification_sha256: str
) -> tuple[int, float, int, dict[str, Any] | None]:
    if not PROGRESS.exists():
        return 0, 0.0, 0, None
    value = json.loads(PROGRESS.read_bytes())
    if (
        value.get("schema") != "chacha20-round20-w48-target-conditioned-recovery-a374-progress-v1"
        or value.get("attempt_id") != ATTEMPT_ID
        or value.get("protocol_sha256") != protocol_sha256
        or value.get("selected_order_uint16be_sha256") != order_sha
        or value.get("A371_qualification_sha256") != qualification_sha256
        or value.get("matched_control_candidates") != 0
    ):
        raise RuntimeError("A374 progress fingerprint differs")
    if value.get("status") == "candidate_found":
        excluded = {
            "schema",
            "attempt_id",
            "protocol_sha256",
            "selected_operator",
            "selected_order_uint16be_sha256",
            "A371_qualification_sha256",
            "status",
        }
        return 0, 0.0, 0, {key: item for key, item in value.items() if key not in excluded}
    completed = int(value.get("executed_prefix_groups", -1))
    if not 0 <= completed < CELLS or value.get("factual_filter_candidates") != 0:
        raise RuntimeError("A374 resumable progress state differs")
    return completed, float(value.get("gpu_seconds", 0.0)), int(value.get("host_instances", 0)), None


def rank_panel(prefix: int, protocol: Mapping[str, Any], a373_order: Mapping[str, Any]) -> dict[str, Any]:
    source = exact_order(A372.load_order()["selected_order"], "A372 rank source")
    target = exact_order(a373_order["target_conditioned_order"], "target-conditioned rank source")
    selected = exact_order(protocol["selected_order"], "selected rank source")
    ranks = {
        "A372_target_free": rank_vector(source)[prefix],
        "A373_target_conditioned": rank_vector(target)[prefix],
        "A374_executed_factor2_portfolio": rank_vector(selected)[prefix],
    }
    best = min(ranks["A372_target_free"], ranks["A373_target_conditioned"])
    return {
        "prefix12": prefix,
        "prefix12_hex": f"{prefix:03x}",
        "prefix_ranks_one_based": ranks,
        "selected_rank_one_based": ranks["A374_executed_factor2_portfolio"],
        "selected_gain_bits_vs_complete_domain": math.log2(
            CELLS / ranks["A374_executed_factor2_portfolio"]
        ),
        "selected_domain_reduction_factor": CELLS / ranks["A374_executed_factor2_portfolio"],
        "factor2_bound_for_confirmed_prefix": ranks["A374_executed_factor2_portfolio"] <= 2 * best,
        "portfolio_overhead_vs_better_source": ranks["A374_executed_factor2_portfolio"] / best,
        "ranks_computed_only_after_independent_confirmation": True,
    }


def build_causal(payload: Mapping[str, Any]) -> dict[str, Any]:
    sys.path.insert(0, str(DOTCAUSAL_SRC))
    from dotcausal.io import CausalReader, CausalWriter

    terminal = "A374:confirmed_target_conditioned_W48_recovery"
    writer = CausalWriter(api_id="a374w48")
    writer._rules = []
    writer.add_rule(
        name="public_W48_reader_to_bounded_order",
        description="The pre-target A373 implementation turns the public W48 output into a zero-refit order and merges it with A372 under a pointwise factor-two bound.",
        pattern=["A373_public_output_reader", "A372_target_free_order"],
        conclusion="A374_frozen_W48_recovery_order",
        confidence_modifier=1.0,
    )
    writer.add_rule(
        name="complete_thirtytwo_slab_search_to_confirmed_model",
        description="Every selected prefix executes thirty-two complete slabs before the factual model is independently confirmed across all eight blocks.",
        pattern=["A374_frozen_W48_recovery_order", "A371_exact_W48_group_engine"],
        conclusion="A374_confirmed_target_conditioned_W48_recovery",
        confidence_modifier=1.0,
    )
    writer.add_triplet(
        trigger="A373:public_output_conditioned_factor2_order",
        mechanism="qualified_ordered_complete_thirtytwo_slab_search",
        outcome="A374:sole_factual_W48_model",
        confidence=1.0,
        source=payload["execution_sha256"],
        quantification=json.dumps(payload["discovery"], sort_keys=True),
        evidence=json.dumps(payload["rank_analysis"], sort_keys=True),
        domain="fresh full-round ChaCha20 W48 target-conditioned recovery",
        quality_score=1.0,
    )
    writer.add_triplet(
        trigger="A374:sole_factual_W48_model",
        mechanism="dual_independent_eight_block_confirmation",
        outcome=terminal,
        confidence=1.0,
        source=payload["measurement_sha256"],
        quantification=json.dumps(payload["confirmation"], sort_keys=True),
        evidence=payload["evidence_stage"],
        domain="confirmed full-round ChaCha20 W48 recovery",
        quality_score=1.0,
    )
    writer.add_triplet(
        trigger="A373:public_output_conditioned_factor2_order",
        mechanism="materialized_W48_search_and_confirmation_closure",
        outcome=terminal,
        confidence=1.0,
        source="materialized:A374_W48_recovery_chain",
        quantification="exact retained closure",
        evidence=payload["evidence_stage"],
        domain="AI-native retained inference",
        quality_score=1.0,
        is_inferred=True,
    )
    writer.add_cluster(
        name="A374 target-conditioned W48 recovery",
        entities=[
            "A373:public_output_conditioned_factor2_order",
            "A374:sole_factual_W48_model",
            terminal,
        ],
    )
    writer.add_gap(
        subject=terminal,
        predicate="next_required_object",
        expected_object_type="W48_target_conditioned_transfer_or_second_fresh_W48_replication",
        confidence=1.0,
        suggested_queries=["Replicate the complete W48 target-conditioned portfolio on a second fresh challenge or qualify the next width."],
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
        reader.api_id != "a374w48"
        or len(explicit) != 2
        or len(all_rows) != 3
        or len(inferred) != 1
        or len(reader._rules) != 2
        or len(reader._clusters) != 1
        or len(reader._gaps) != 1
    ):
        raise RuntimeError("A374 authentic Causal reopen gate failed")
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
        "personal_semantic_readback": {"terminal_chain": all_rows[-1], "next_gap": reader._gaps[0]},
    }


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
    """Execute exact complete W48 groups in the frozen prefix order."""
    values = exact_order(order, "recovery order")
    if not 0 <= start_group < CELLS:
        raise ValueError("A374 resume group lies outside the prefix cover")
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
            observed = A372.A371.filter_complete_prefix(
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
                raise RuntimeError("A374 matched control produced a candidate")
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
                raise RuntimeError("A374 complete W48 group produced multiple filters")
            candidate = factual[0]
            if ((candidate >> WORD0_SUFFIX_BITS) & (CELLS - 1)) != prefix:
                raise RuntimeError("A374 candidate prefix differs")
            found = {
                "candidate": candidate,
                "candidate_hex": f"{candidate:012x}",
                "key_word0": candidate & MASK32,
                "key_word1_low16": candidate >> 32,
                "prefix12": prefix,
                "prefix12_hex": f"{prefix:03x}",
                "executed_prefix_groups": groups,
                "executed_group_dispatches": groups * 32,
                "executed_assignments": groups * GROUP_SIZE,
                "complete_domain_assignments": DOMAIN_SIZE,
                "complete_W48_group_execution_before_stop": True,
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
    raise RuntimeError("A374 exact frozen order exhausted without a factual filter")


def recover(*, expected_protocol_sha256: str) -> dict[str, Any]:
    if any(path.exists() for path in (RESULT, CAUSAL, REPORT)):
        raise FileExistsError("A374 result artifacts already exist")
    protocol = load_protocol(expected_protocol_sha256)
    qualification = A372.load_a371_qualification(protocol["A371_qualification_sha256"])
    a373_order = load_a373_order(protocol["A373_order_sha256"], protocol["A372_protocol_sha256"])
    a371_protocol = A372.A371.load_protocol(A371_PROTOCOL_SHA256)
    executable_row = a371_protocol["anchors"]["grouped_executable"]
    executable = path_from_ref(executable_row["path"])
    anchor(executable, executable_row["sha256"])
    challenge = protocol["public_challenge"]
    placeholder = np.asarray([0, 0], dtype=np.uint32)

    def host_factory() -> Any:
        return A372.A371.A346.A324.A311.A307.A304.GroupedMetalHost(
            executable,
            A372.A371.initial_for_slab(challenge, 0),
            placeholder,
            placeholder,
        )

    def write_progress(row: Mapping[str, Any]) -> None:
        atomic_json(
            PROGRESS,
            {
                "schema": "chacha20-round20-w48-target-conditioned-recovery-a374-progress-v1",
                "attempt_id": ATTEMPT_ID,
                "protocol_sha256": expected_protocol_sha256,
                "selected_operator": SELECTED_OPERATOR,
                "selected_order_uint16be_sha256": protocol["selected_order_uint16be_sha256"],
                "A371_qualification_sha256": protocol["A371_qualification_sha256"],
                **dict(row),
            },
        )

    start, prior_gpu, prior_hosts, completed_discovery = load_resume(
        protocol_sha256=expected_protocol_sha256,
        order_sha=protocol["selected_order_uint16be_sha256"],
        qualification_sha256=protocol["A371_qualification_sha256"],
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
        raise RuntimeError("A374 matched control produced a candidate")
    candidate = int(discovery["candidate"])
    confirmation = A372.confirm(challenge, candidate)
    if confirmation["all_blocks_match"] is not True:
        raise RuntimeError("A374 dual independent confirmation failed")
    ranks = rank_panel(int(discovery["prefix12"]), protocol, a373_order)
    if ranks["selected_rank_one_based"] != discovery["executed_prefix_groups"]:
        raise RuntimeError("A374 discovery rank differs from selected order")
    strict_subset = discovery["executed_prefix_groups"] < CELLS
    evidence_stage = (
        "FULLROUND_R20_TARGET_CONDITIONED_W48_STRICT_SUBSET_RECOVERY_CONFIRMED"
        if strict_subset
        else "FULLROUND_R20_TARGET_CONDITIONED_W48_COMPLETE_DOMAIN_RECOVERY_CONFIRMED"
    )
    payload: dict[str, Any] = {
        "schema": "chacha20-round20-w48-target-conditioned-recovery-a374-result-v1",
        "attempt_id": ATTEMPT_ID,
        "evidence_stage": evidence_stage,
        "protocol_sha256": expected_protocol_sha256,
        "design_sha256": DESIGN_SHA256,
        "implementation_sha256": protocol["implementation_sha256"],
        "A371_qualification_sha256": protocol["A371_qualification_sha256"],
        "A372_protocol_sha256": protocol["A372_protocol_sha256"],
        "A373_order_sha256": protocol["A373_order_sha256"],
        "A373_order_commitment_sha256": protocol["A373_order_commitment_sha256"],
        "public_challenge_sha256": protocol["public_challenge_sha256"],
        "selected_operator": SELECTED_OPERATOR,
        "selected_order_uint16be_sha256": protocol["selected_order_uint16be_sha256"],
        "pointwise_factor2_proof": protocol["pointwise_factor2_proof"],
        "operator_diversity": protocol["operator_diversity"],
        "qualification_gate": {
            "evidence_stage": qualification["evidence_stage"],
            "qualification_sha256": qualification["qualification_sha256"],
            "complete_W48_group_candidates": qualification["complete_group_gate"]["logical_candidates"],
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
    stable_discovery = {key: item for key, item in discovery.items() if not key.startswith("volatile_")}
    payload["execution_sha256"] = canonical_sha256(
        {
            "selected_operator": SELECTED_OPERATOR,
            "selected_order_uint16be_sha256": protocol["selected_order_uint16be_sha256"],
            "discovery": stable_discovery,
            "A371_qualification_sha256": protocol["A371_qualification_sha256"],
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
            "# A374 — target-conditioned full-round ChaCha20 W48 recovery\n\n"
            f"Evidence stage: **{evidence_stage}**\n\n"
            f"- Selected operator: **{SELECTED_OPERATOR}**\n"
            f"- W48 execution rank: **{ranks['selected_rank_one_based']} / {CELLS}**\n"
            f"- Complete candidate evaluations: **{discovery['executed_assignments']:,} / {DOMAIN_SIZE:,}**\n"
            f"- Recovered W48 assignment: **0x{candidate:012x}**\n"
            "- Standard ChaCha20: **20 rounds plus feed-forward**\n"
            "- Every prefix: **thirty-two complete 2^31 slabs before outcome evaluation**\n"
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
    parser.add_argument("--expected-a372-protocol-sha256")
    parser.add_argument("--expected-a373-order-sha256")
    parser.add_argument("--expected-a371-qualification-sha256")
    parser.add_argument("--expected-protocol-sha256")
    args = parser.parse_args()
    if args.freeze_implementation:
        payload = freeze_implementation()
    elif args.freeze_protocol:
        required = (
            args.expected_implementation_sha256,
            args.expected_a372_protocol_sha256,
            args.expected_a373_order_sha256,
            args.expected_a371_qualification_sha256,
        )
        if not all(required):
            parser.error("--freeze-protocol requires implementation, A372, A373 and qualification hashes")
        payload = freeze_protocol(
            expected_implementation_sha256=args.expected_implementation_sha256,
            expected_a372_protocol_sha256=args.expected_a372_protocol_sha256,
            expected_a373_order_sha256=args.expected_a373_order_sha256,
            expected_a371_qualification_sha256=args.expected_a371_qualification_sha256,
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

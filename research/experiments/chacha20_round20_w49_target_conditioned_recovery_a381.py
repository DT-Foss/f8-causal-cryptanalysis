#!/usr/bin/env python3
"""A381: execute the frozen A380 W49 portfolio with the qualified 64-slab engine."""

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

DESIGN = CONFIGS / "chacha20_round20_w49_target_conditioned_recovery_a381_design_v1.json"
IMPLEMENTATION = CONFIGS / "chacha20_round20_w49_target_conditioned_recovery_a381_implementation_v1.json"
PROTOCOL = CONFIGS / "chacha20_round20_w49_target_conditioned_recovery_a381_v1.json"
PROGRESS = RESULTS / "chacha20_round20_w49_target_conditioned_recovery_a381_progress_v1.json"
RESULT = RESULTS / "chacha20_round20_w49_target_conditioned_recovery_a381_v1.json"
CAUSAL = RESULT.with_suffix(".causal")
REPORT = RESULT.with_suffix(".md")
TEST = ROOT / "tests/test_chacha20_round20_w49_target_conditioned_recovery_a381.py"
REPRO = ROOT / "scripts/reproduce_chacha20_round20_w49_target_conditioned_recovery_a381.sh"

A378_PROTOCOL = CONFIGS / "chacha20_round20_w49_sixtyfour_slab_grouped_engine_a378_v1.json"
A378_QUALIFICATION = RESULTS / "chacha20_round20_w49_sixtyfour_slab_grouped_engine_a378_qualification_v1.json"
A379_RUNNER = RESEARCH / "experiments/chacha20_round20_fresh_w49_pretarget_transfer_a379.py"
A379_DESIGN = CONFIGS / "chacha20_round20_fresh_w49_pretarget_transfer_a379_design_v1.json"
A379_IMPLEMENTATION = CONFIGS / "chacha20_round20_fresh_w49_pretarget_transfer_a379_implementation_v1.json"
A379_ORDER = RESULTS / "chacha20_round20_fresh_w49_pretarget_transfer_a379_order_v1.json"
A379_PROTOCOL = CONFIGS / "chacha20_round20_fresh_w49_pretarget_transfer_a379_v1.json"
A380_RUNNER = RESEARCH / "experiments/chacha20_round20_w49_target_conditioned_factor2_a380.py"
A380_DESIGN = CONFIGS / "chacha20_round20_w49_target_conditioned_factor2_a380_design_v1.json"
A380_IMPLEMENTATION = CONFIGS / "chacha20_round20_w49_target_conditioned_factor2_a380_implementation_v1.json"
A380_ORDER = RESULTS / "chacha20_round20_w49_target_conditioned_factor2_a380_order_v1.json"

ATTEMPT_ID = "A381"
DESIGN_SHA256 = "369a43e8d7fdd2c99cfc9c8834b5305c33bfcd350341c9d6e01b28ff15941f1f"
A378_PROTOCOL_SHA256 = "c926f6474c7cb54909e0204182941d7d1c63889fd892e92f0fbc4c5c48305af3"
A378_QUALIFICATION_SHA256 = "1e020ac18d86279e327cd5584d43fdafc4b6245d8df522c4b179951d820872e9"
A379_DESIGN_SHA256 = "881496c77ebf9fb909d8683b551ca7e83b29d1cf8c73fdf8cd9b102626629ed6"
A379_IMPLEMENTATION_SHA256 = "bf2945db89fb13ef2975398ab7819d05b9582f3753a689a256bc0e2226d255cf"
A379_ORDER_SHA256 = "90e06848c9f608ae484b9cdf95d0ebcc64a0776b976470df436e82392caf02a5"
A379_PROTOCOL_SHA256 = "673b44d81f1e25490fd778b48d1ef0c6423ddda6716354c03f5212f68888903a"
A380_DESIGN_SHA256 = "329ee11f49229f88b0e585bca8548eb346b8009e0c14fd4959c333071c8347f4"
A380_IMPLEMENTATION_SHA256 = "75ebf5375d5cca6d52380aa5125cba7cc694380717a3ecebb7f5a7dde152c4e2"
A380_ORDER_SHA256 = "a5cc83121e8c0f58b91046e5d9d6f6b2476008984efae19675ee652e5c656ed8"

WIDTH = 49
PREFIX_BITS = 12
WORD0_SUFFIX_BITS = 20
CELLS = 1 << PREFIX_BITS
GROUP_SIZE = 1 << (WIDTH - PREFIX_BITS)
DOMAIN_SIZE = 1 << WIDTH
MASK32 = 0xFFFFFFFF
HOST_REFRESH_GROUPS = 8
SELECTED_OPERATOR = "A380_W49_target_conditioned_plus_A379_target_free_factor2_wavefront"
DOTCAUSAL_SRC = Path("/Users/bhkmie/Documents/Forschung/O1/vendor/fabel/dotcausal_package/src")


def load_module(path: Path, name: str) -> Any:
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot import A381 dependency {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


A379 = load_module(A379_RUNNER, "a381_a379")
A380 = load_module(A380_RUNNER, "a381_a380")
file_sha256 = A379.file_sha256
canonical_sha256 = A379.canonical_sha256
atomic_json = A379.atomic_json
atomic_bytes = A380.atomic_bytes
relative = A379.relative
path_from_ref = A379.path_from_ref
anchor = A379.anchor


def exact_order(values: Sequence[int], label: str) -> list[int]:
    order = [int(value) for value in values]
    if len(order) != CELLS or set(order) != set(range(CELLS)):
        raise ValueError(f"A381 {label} is not an exact 4,096-cell order")
    return order


def order_sha256(order: Sequence[int]) -> str:
    return A380.A351.order_sha256(exact_order(order, "hash"))


def rank_vector(order: Sequence[int]) -> list[int]:
    ranks = [0] * CELLS
    for rank, cell in enumerate(exact_order(order, "rank vector"), 1):
        ranks[cell] = rank
    return ranks


def load_design() -> dict[str, Any]:
    if file_sha256(DESIGN) != DESIGN_SHA256:
        raise RuntimeError("A381 design hash differs")
    value = json.loads(DESIGN.read_bytes())
    boundary = value.get("information_boundary", {})
    execution = value.get("execution_contract", {})
    order = value.get("order_contract", {})
    if (
        value.get("schema") != "chacha20-round20-w49-target-conditioned-recovery-a381-design-v1"
        or value.get("attempt_id") != ATTEMPT_ID
        or value.get("design_state")
        != "frozen_after_A378_qualification_A379_protocol_A380_order_before_any_W49_candidate_prefix_or_result"
        or boundary.get("A378_qualification_available_at_design_freeze") is not True
        or boundary.get("A379_protocol_available_at_design_freeze") is not True
        or boundary.get("A380_order_available_at_design_freeze") is not True
        or boundary.get("A381_candidate_or_prefix_available_at_design_freeze") is not False
        or execution.get("unknown_key_bits") != WIDTH
        or execution.get("candidates_per_prefix_group") != GROUP_SIZE
        or execution.get("complete_domain_assignments") != DOMAIN_SIZE
        or execution.get("slabs_per_prefix_group") != 64
        or order.get("target_labels_used") != 0
        or order.get("reader_refits") != 0
    ):
        raise RuntimeError("A381 frozen design semantics differ")
    for key, source_path in value["source_anchors"].items():
        if key.endswith("_path"):
            expected = value["source_anchors"][key.removesuffix("_path") + "_sha256"]
            anchor(ROOT / source_path, expected)
    return value


def assert_pre_execution() -> None:
    if PROGRESS.exists() or RESULT.exists():
        raise RuntimeError("A381 frozen artifacts must precede every W49 candidate and result")


def freeze_implementation() -> dict[str, Any]:
    if any(path.exists() for path in (IMPLEMENTATION, PROTOCOL, PROGRESS, RESULT, CAUSAL, REPORT)):
        raise FileExistsError("A381 implementation or execution artifacts already exist")
    assert_pre_execution()
    load_design()
    if not TEST.exists() or not REPRO.exists():
        raise FileNotFoundError("A381 test and reproducer must precede implementation freeze")
    payload: dict[str, Any] = {
        "schema": "chacha20-round20-w49-target-conditioned-recovery-a381-implementation-v1",
        "attempt_id": ATTEMPT_ID,
        "commitment_state": "frozen_after_A378_qualification_A379_protocol_A380_order_before_A381_candidate_prefix_or_result",
        "design_sha256": DESIGN_SHA256,
        "selected_operator": SELECTED_OPERATOR,
        "A378_qualification_available_at_implementation_freeze": True,
        "A379_protocol_available_at_implementation_freeze": True,
        "A380_order_available_at_implementation_freeze": True,
        "A381_candidate_or_prefix_available_at_implementation_freeze": False,
        "anchors": {
            "design": anchor(DESIGN, DESIGN_SHA256),
            "A378_protocol": anchor(A378_PROTOCOL, A378_PROTOCOL_SHA256),
            "A378_qualification": anchor(A378_QUALIFICATION, A378_QUALIFICATION_SHA256),
            "A379_design": anchor(A379_DESIGN, A379_DESIGN_SHA256),
            "A379_implementation": anchor(A379_IMPLEMENTATION, A379_IMPLEMENTATION_SHA256),
            "A379_order": anchor(A379_ORDER, A379_ORDER_SHA256),
            "A379_protocol": anchor(A379_PROTOCOL, A379_PROTOCOL_SHA256),
            "A379_runner": anchor(A379_RUNNER),
            "A380_design": anchor(A380_DESIGN, A380_DESIGN_SHA256),
            "A380_implementation": anchor(A380_IMPLEMENTATION, A380_IMPLEMENTATION_SHA256),
            "A380_order": anchor(A380_ORDER, A380_ORDER_SHA256),
            "A380_runner": anchor(A380_RUNNER),
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
        raise RuntimeError("A381 implementation hash differs")
    value = json.loads(IMPLEMENTATION.read_bytes())
    if (
        value.get("schema")
        != "chacha20-round20-w49-target-conditioned-recovery-a381-implementation-v1"
        or value.get("attempt_id") != ATTEMPT_ID
        or value.get("commitment_state")
        != "frozen_after_A378_qualification_A379_protocol_A380_order_before_A381_candidate_prefix_or_result"
        or value.get("design_sha256") != DESIGN_SHA256
        or value.get("selected_operator") != SELECTED_OPERATOR
        or value.get("A378_qualification_available_at_implementation_freeze") is not True
        or value.get("A379_protocol_available_at_implementation_freeze") is not True
        or value.get("A380_order_available_at_implementation_freeze") is not True
    ):
        raise RuntimeError("A381 implementation semantics differ")
    expected = {
        "design": DESIGN,
        "A378_protocol": A378_PROTOCOL,
        "A378_qualification": A378_QUALIFICATION,
        "A379_design": A379_DESIGN,
        "A379_implementation": A379_IMPLEMENTATION,
        "A379_order": A379_ORDER,
        "A379_protocol": A379_PROTOCOL,
        "A379_runner": A379_RUNNER,
        "A380_design": A380_DESIGN,
        "A380_implementation": A380_IMPLEMENTATION,
        "A380_order": A380_ORDER,
        "A380_runner": A380_RUNNER,
        "runner": Path(__file__),
        "test": TEST,
        "reproducer": REPRO,
    }
    for name, path in expected.items():
        row = value["anchors"][name]
        if row.get("path") != relative(path) or row.get("sha256") != file_sha256(path):
            raise RuntimeError(f"A381 implementation anchor differs: {name}")
    unsigned = {key: item for key, item in value.items() if key != "implementation_commitment_sha256"}
    if value.get("implementation_commitment_sha256") != canonical_sha256(unsigned):
        raise RuntimeError("A381 implementation commitment differs")
    return value


def load_a380_order(expected_sha256: str, expected_a379_protocol_sha256: str) -> dict[str, Any]:
    if file_sha256(A380_ORDER) != expected_sha256:
        raise RuntimeError("A381 A380 order artifact hash differs")
    value = json.loads(A380_ORDER.read_bytes())
    selected = exact_order(value.get("selected_order", []), "A380 selected order")
    target = exact_order(value.get("target_conditioned_order", []), "A380 target-conditioned order")
    source = exact_order(A379.load_order()["selected_order"], "A379 source order")
    if (
        value.get("schema") != "chacha20-round20-w49-target-conditioned-factor2-a380-order-v1"
        or value.get("A379_protocol_sha256") != expected_a379_protocol_sha256
        or value.get("W49_recovery_available_at_order_freeze") is not False
        or value.get("target_labels_used") != 0
        or value.get("reader_refits") != 0
        or value.get("candidate_assignments_executed") != 0
        or value.get("selected_order_uint16be_sha256") != order_sha256(selected)
        or value.get("target_conditioned_order_uint16be_sha256") != order_sha256(target)
        or selected != A380.A351.factor2_wavefront(source, target)
        or value.get("pointwise_factor2_proof")
        != A380.A351.factor2_proof(source, target, selected)
    ):
        raise RuntimeError("A381 A380 order semantics differ")
    return value


def freeze_protocol(
    *,
    expected_implementation_sha256: str,
    expected_a379_protocol_sha256: str,
    expected_a380_order_sha256: str,
    expected_a378_qualification_sha256: str,
) -> dict[str, Any]:
    if any(path.exists() for path in (PROTOCOL, PROGRESS, RESULT, CAUSAL, REPORT)):
        raise FileExistsError("A381 protocol or execution artifacts already exist")
    assert_pre_execution()
    implementation = load_implementation(expected_implementation_sha256)
    source_protocol = A379.load_protocol(expected_a379_protocol_sha256)
    order = load_a380_order(expected_a380_order_sha256, expected_a379_protocol_sha256)
    qualification = A379.load_a378_qualification(expected_a378_qualification_sha256)
    selected = exact_order(order["selected_order"], "protocol selected")
    payload: dict[str, Any] = {
        "schema": "chacha20-round20-w49-target-conditioned-recovery-a381-protocol-v1",
        "attempt_id": ATTEMPT_ID,
        "protocol_state": "A380_order_bound_after_public_measurement_before_any_A381_candidate_prefix_or_result",
        "design_sha256": DESIGN_SHA256,
        "implementation_sha256": expected_implementation_sha256,
        "implementation_commitment_sha256": implementation["implementation_commitment_sha256"],
        "A378_qualification_sha256": expected_a378_qualification_sha256,
        "A378_semantic_qualification_sha256": qualification["qualification_sha256"],
        "A379_protocol_sha256": expected_a379_protocol_sha256,
        "A380_order_sha256": expected_a380_order_sha256,
        "A380_order_commitment_sha256": order["order_commitment_sha256"],
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
            "A381_candidate_or_prefix_available_at_protocol_freeze": False,
            "A380_order_frozen_before_protocol": True,
            "target_labels_used_for_order_construction": 0,
            "reader_refits": 0,
        },
        "anchors": {
            "design": anchor(DESIGN, DESIGN_SHA256),
            "implementation": anchor(IMPLEMENTATION, expected_implementation_sha256),
            "A378_protocol": anchor(A378_PROTOCOL, A378_PROTOCOL_SHA256),
            "A378_qualification": anchor(A378_QUALIFICATION, expected_a378_qualification_sha256),
            "A379_protocol": anchor(A379_PROTOCOL, expected_a379_protocol_sha256),
            "A379_order": anchor(A379_ORDER, A379_ORDER_SHA256),
            "A380_order": anchor(A380_ORDER, expected_a380_order_sha256),
            "runner": anchor(Path(__file__)),
            "test": anchor(TEST),
            "reproducer": anchor(REPRO),
        },
    }
    payload["protocol_commitment_sha256"] = canonical_sha256(
        {
            "implementation_commitment_sha256": payload["implementation_commitment_sha256"],
            "A379_protocol_sha256": expected_a379_protocol_sha256,
            "A380_order_sha256": expected_a380_order_sha256,
            "A380_order_commitment_sha256": payload["A380_order_commitment_sha256"],
            "selected_order_uint16be_sha256": payload["selected_order_uint16be_sha256"],
            "public_challenge_sha256": payload["public_challenge_sha256"],
            "A378_qualification_sha256": expected_a378_qualification_sha256,
            "information_boundary": payload["information_boundary"],
        }
    )
    atomic_json(PROTOCOL, payload)
    if PROGRESS.exists() or RESULT.exists():
        PROTOCOL.unlink(missing_ok=True)
        raise RuntimeError("A381 protocol did not precede A381 execution")
    return payload


def load_protocol(expected_sha256: str) -> dict[str, Any]:
    if file_sha256(PROTOCOL) != expected_sha256:
        raise RuntimeError("A381 protocol hash differs")
    value = json.loads(PROTOCOL.read_bytes())
    selected = exact_order(value.get("selected_order", []), "stored protocol order")
    if (
        value.get("schema") != "chacha20-round20-w49-target-conditioned-recovery-a381-protocol-v1"
        or value.get("attempt_id") != ATTEMPT_ID
        or value.get("selected_operator") != SELECTED_OPERATOR
        or value.get("selected_order_uint16be_sha256") != order_sha256(selected)
        or value.get("information_boundary", {}).get(
            "A381_candidate_or_prefix_available_at_protocol_freeze"
        )
        is not False
        or value.get("information_boundary", {}).get("target_labels_used_for_order_construction")
        != 0
        or canonical_sha256(value.get("public_challenge")) != value.get("public_challenge_sha256")
    ):
        raise RuntimeError("A381 protocol semantics differ")
    for row in value["anchors"].values():
        anchor(path_from_ref(row["path"]), row["sha256"])
    load_implementation(value["implementation_sha256"])
    load_a380_order(value["A380_order_sha256"], value["A379_protocol_sha256"])
    A379.validate_challenge(value["public_challenge"])
    return value


def load_resume(
    *, protocol_sha256: str, order_sha: str, qualification_sha256: str
) -> tuple[int, float, int, dict[str, Any] | None]:
    if not PROGRESS.exists():
        return 0, 0.0, 0, None
    value = json.loads(PROGRESS.read_bytes())
    if (
        value.get("schema") != "chacha20-round20-w49-target-conditioned-recovery-a381-progress-v1"
        or value.get("attempt_id") != ATTEMPT_ID
        or value.get("protocol_sha256") != protocol_sha256
        or value.get("selected_order_uint16be_sha256") != order_sha
        or value.get("A378_qualification_sha256") != qualification_sha256
        or value.get("matched_control_candidates") != 0
    ):
        raise RuntimeError("A381 progress fingerprint differs")
    if value.get("status") == "candidate_found":
        excluded = {
            "schema",
            "attempt_id",
            "protocol_sha256",
            "selected_operator",
            "selected_order_uint16be_sha256",
            "A378_qualification_sha256",
            "status",
        }
        return 0, 0.0, 0, {key: item for key, item in value.items() if key not in excluded}
    completed = int(value.get("executed_prefix_groups", -1))
    if not 0 <= completed < CELLS or value.get("factual_filter_candidates") != 0:
        raise RuntimeError("A381 resumable progress state differs")
    return completed, float(value.get("gpu_seconds", 0.0)), int(value.get("host_instances", 0)), None


def rank_panel(prefix: int, protocol: Mapping[str, Any], a380_order: Mapping[str, Any]) -> dict[str, Any]:
    source = exact_order(A379.load_order()["selected_order"], "A379 rank source")
    target = exact_order(a380_order["target_conditioned_order"], "target-conditioned rank source")
    selected = exact_order(protocol["selected_order"], "selected rank source")
    ranks = {
        "A379_target_free": rank_vector(source)[prefix],
        "A380_target_conditioned": rank_vector(target)[prefix],
        "A381_executed_factor2_portfolio": rank_vector(selected)[prefix],
    }
    best = min(ranks["A379_target_free"], ranks["A380_target_conditioned"])
    return {
        "prefix12": prefix,
        "prefix12_hex": f"{prefix:03x}",
        "prefix_ranks_one_based": ranks,
        "selected_rank_one_based": ranks["A381_executed_factor2_portfolio"],
        "selected_gain_bits_vs_complete_domain": math.log2(
            CELLS / ranks["A381_executed_factor2_portfolio"]
        ),
        "selected_domain_reduction_factor": CELLS / ranks["A381_executed_factor2_portfolio"],
        "factor2_bound_for_confirmed_prefix": ranks["A381_executed_factor2_portfolio"] <= 2 * best,
        "portfolio_overhead_vs_better_source": ranks["A381_executed_factor2_portfolio"] / best,
        "ranks_computed_only_after_independent_confirmation": True,
    }


def build_causal(payload: Mapping[str, Any]) -> dict[str, Any]:
    sys.path.insert(0, str(DOTCAUSAL_SRC))
    from dotcausal.io import CausalReader, CausalWriter

    terminal = "A381:confirmed_target_conditioned_W49_recovery"
    writer = CausalWriter(api_id="a381w49")
    writer._rules = []
    writer.add_rule(
        name="public_W49_reader_to_bounded_order",
        description="The pre-target A380 implementation turns the public W49 output into a zero-refit order and merges it with A379 under a pointwise factor-two bound.",
        pattern=["A380_public_output_reader", "A379_target_free_order"],
        conclusion="A381_frozen_W49_recovery_order",
        confidence_modifier=1.0,
    )
    writer.add_rule(
        name="complete_sixtyfour_slab_search_to_confirmed_model",
        description="Every selected prefix executes sixty-four complete slabs before the factual model is independently confirmed across all eight blocks.",
        pattern=["A381_frozen_W49_recovery_order", "A378_exact_W49_group_engine"],
        conclusion="A381_confirmed_target_conditioned_W49_recovery",
        confidence_modifier=1.0,
    )
    writer.add_triplet(
        trigger="A380:public_output_conditioned_factor2_order",
        mechanism="qualified_ordered_complete_sixtyfour_slab_search",
        outcome="A381:sole_factual_W49_model",
        confidence=1.0,
        source=payload["execution_sha256"],
        quantification=json.dumps(payload["discovery"], sort_keys=True),
        evidence=json.dumps(payload["rank_analysis"], sort_keys=True),
        domain="fresh full-round ChaCha20 W49 target-conditioned recovery",
        quality_score=1.0,
    )
    writer.add_triplet(
        trigger="A381:sole_factual_W49_model",
        mechanism="dual_independent_eight_block_confirmation",
        outcome=terminal,
        confidence=1.0,
        source=payload["measurement_sha256"],
        quantification=json.dumps(payload["confirmation"], sort_keys=True),
        evidence=payload["evidence_stage"],
        domain="confirmed full-round ChaCha20 W49 recovery",
        quality_score=1.0,
    )
    writer.add_triplet(
        trigger="A380:public_output_conditioned_factor2_order",
        mechanism="materialized_W49_search_and_confirmation_closure",
        outcome=terminal,
        confidence=1.0,
        source="materialized:A381_W49_recovery_chain",
        quantification="exact retained closure",
        evidence=payload["evidence_stage"],
        domain="AI-native retained inference",
        quality_score=1.0,
        is_inferred=True,
    )
    writer.add_cluster(
        name="A381 target-conditioned W49 recovery",
        entities=[
            "A380:public_output_conditioned_factor2_order",
            "A381:sole_factual_W49_model",
            terminal,
        ],
    )
    writer.add_gap(
        subject=terminal,
        predicate="next_required_object",
        expected_object_type="W49_target_conditioned_transfer_or_second_fresh_W49_replication",
        confidence=1.0,
        suggested_queries=["Replicate the complete W49 target-conditioned portfolio on a second fresh challenge or qualify the next width."],
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
        reader.api_id != "a381w49"
        or len(explicit) != 2
        or len(all_rows) != 3
        or len(inferred) != 1
        or len(reader._rules) != 2
        or len(reader._clusters) != 1
        or len(reader._gaps) != 1
    ):
        raise RuntimeError("A381 authentic Causal reopen gate failed")
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
    """Execute exact complete W49 groups in the frozen prefix order."""
    values = exact_order(order, "recovery order")
    if not 0 <= start_group < CELLS:
        raise ValueError("A381 resume group lies outside the prefix cover")
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
            observed = A379.A378.filter_complete_prefix(
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
                raise RuntimeError("A381 matched control produced a candidate")
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
                raise RuntimeError("A381 complete W49 group produced multiple filters")
            candidate = factual[0]
            if ((candidate >> WORD0_SUFFIX_BITS) & (CELLS - 1)) != prefix:
                raise RuntimeError("A381 candidate prefix differs")
            found = {
                "candidate": candidate,
                "candidate_hex": f"{candidate:013x}",
                "key_word0": candidate & MASK32,
                "key_word1_low17": candidate >> 32,
                "prefix12": prefix,
                "prefix12_hex": f"{prefix:03x}",
                "executed_prefix_groups": groups,
                "executed_group_dispatches": groups * 64,
                "executed_assignments": groups * GROUP_SIZE,
                "complete_domain_assignments": DOMAIN_SIZE,
                "complete_W49_group_execution_before_stop": True,
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
    raise RuntimeError("A381 exact frozen order exhausted without a factual filter")


def recover(*, expected_protocol_sha256: str) -> dict[str, Any]:
    if any(path.exists() for path in (RESULT, CAUSAL, REPORT)):
        raise FileExistsError("A381 result artifacts already exist")
    protocol = load_protocol(expected_protocol_sha256)
    qualification = A379.load_a378_qualification(protocol["A378_qualification_sha256"])
    a380_order = load_a380_order(protocol["A380_order_sha256"], protocol["A379_protocol_sha256"])
    a378_protocol = A379.A378.load_protocol(A378_PROTOCOL_SHA256)
    executable_row = a378_protocol["anchors"]["grouped_executable"]
    executable = path_from_ref(executable_row["path"])
    anchor(executable, executable_row["sha256"])
    challenge = protocol["public_challenge"]
    placeholder = np.asarray([0, 0], dtype=np.uint32)

    def host_factory() -> Any:
        return A379.A378.A371.A346.A324.A311.A307.A304.GroupedMetalHost(
            executable,
            A379.A378.initial_for_slab(challenge, 0),
            placeholder,
            placeholder,
        )

    def write_progress(row: Mapping[str, Any]) -> None:
        atomic_json(
            PROGRESS,
            {
                "schema": "chacha20-round20-w49-target-conditioned-recovery-a381-progress-v1",
                "attempt_id": ATTEMPT_ID,
                "protocol_sha256": expected_protocol_sha256,
                "selected_operator": SELECTED_OPERATOR,
                "selected_order_uint16be_sha256": protocol["selected_order_uint16be_sha256"],
                "A378_qualification_sha256": protocol["A378_qualification_sha256"],
                **dict(row),
            },
        )

    start, prior_gpu, prior_hosts, completed_discovery = load_resume(
        protocol_sha256=expected_protocol_sha256,
        order_sha=protocol["selected_order_uint16be_sha256"],
        qualification_sha256=protocol["A378_qualification_sha256"],
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
        raise RuntimeError("A381 matched control produced a candidate")
    candidate = int(discovery["candidate"])
    confirmation = A379.confirm(challenge, candidate)
    if confirmation["all_blocks_match"] is not True:
        raise RuntimeError("A381 dual independent confirmation failed")
    ranks = rank_panel(int(discovery["prefix12"]), protocol, a380_order)
    if ranks["selected_rank_one_based"] != discovery["executed_prefix_groups"]:
        raise RuntimeError("A381 discovery rank differs from selected order")
    strict_subset = discovery["executed_prefix_groups"] < CELLS
    evidence_stage = (
        "FULLROUND_R20_TARGET_CONDITIONED_W49_STRICT_SUBSET_RECOVERY_CONFIRMED"
        if strict_subset
        else "FULLROUND_R20_TARGET_CONDITIONED_W49_COMPLETE_DOMAIN_RECOVERY_CONFIRMED"
    )
    payload: dict[str, Any] = {
        "schema": "chacha20-round20-w49-target-conditioned-recovery-a381-result-v1",
        "attempt_id": ATTEMPT_ID,
        "evidence_stage": evidence_stage,
        "protocol_sha256": expected_protocol_sha256,
        "design_sha256": DESIGN_SHA256,
        "implementation_sha256": protocol["implementation_sha256"],
        "A378_qualification_sha256": protocol["A378_qualification_sha256"],
        "A379_protocol_sha256": protocol["A379_protocol_sha256"],
        "A380_order_sha256": protocol["A380_order_sha256"],
        "A380_order_commitment_sha256": protocol["A380_order_commitment_sha256"],
        "public_challenge_sha256": protocol["public_challenge_sha256"],
        "selected_operator": SELECTED_OPERATOR,
        "selected_order_uint16be_sha256": protocol["selected_order_uint16be_sha256"],
        "pointwise_factor2_proof": protocol["pointwise_factor2_proof"],
        "operator_diversity": protocol["operator_diversity"],
        "qualification_gate": {
            "evidence_stage": qualification["evidence_stage"],
            "qualification_sha256": qualification["qualification_sha256"],
            "complete_W49_group_candidates": qualification["complete_group_gate"]["logical_candidates"],
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
            "A378_qualification_sha256": protocol["A378_qualification_sha256"],
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
            "# A381 — target-conditioned full-round ChaCha20 W49 recovery\n\n"
            f"Evidence stage: **{evidence_stage}**\n\n"
            f"- Selected operator: **{SELECTED_OPERATOR}**\n"
            f"- W49 execution rank: **{ranks['selected_rank_one_based']} / {CELLS}**\n"
            f"- Complete candidate evaluations: **{discovery['executed_assignments']:,} / {DOMAIN_SIZE:,}**\n"
            f"- Recovered W49 assignment: **0x{candidate:013x}**\n"
            "- Standard ChaCha20: **20 rounds plus feed-forward**\n"
            "- Every prefix: **sixty-four complete 2^31 slabs before outcome evaluation**\n"
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
    parser.add_argument("--expected-a379-protocol-sha256")
    parser.add_argument("--expected-a380-order-sha256")
    parser.add_argument("--expected-a378-qualification-sha256")
    parser.add_argument("--expected-protocol-sha256")
    args = parser.parse_args()
    if args.freeze_implementation:
        payload = freeze_implementation()
    elif args.freeze_protocol:
        required = (
            args.expected_implementation_sha256,
            args.expected_a379_protocol_sha256,
            args.expected_a380_order_sha256,
            args.expected_a378_qualification_sha256,
        )
        if not all(required):
            parser.error("--freeze-protocol requires implementation, A379, A380 and qualification hashes")
        payload = freeze_protocol(
            expected_implementation_sha256=args.expected_implementation_sha256,
            expected_a379_protocol_sha256=args.expected_a379_protocol_sha256,
            expected_a380_order_sha256=args.expected_a380_order_sha256,
            expected_a378_qualification_sha256=args.expected_a378_qualification_sha256,
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

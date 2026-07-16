#!/usr/bin/env python3
"""A353: execute the pre-recovery A352 W47 portfolio with the qualified 16-slab engine."""

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

DESIGN = CONFIGS / "chacha20_round20_w47_target_conditioned_recovery_a353_design_v1.json"
IMPLEMENTATION = CONFIGS / "chacha20_round20_w47_target_conditioned_recovery_a353_implementation_v1.json"
PROTOCOL = CONFIGS / "chacha20_round20_w47_target_conditioned_recovery_a353_v1.json"
PROGRESS = RESULTS / "chacha20_round20_w47_target_conditioned_recovery_a353_progress_v1.json"
RESULT = RESULTS / "chacha20_round20_w47_target_conditioned_recovery_a353_v1.json"
CAUSAL = RESULT.with_suffix(".causal")
REPORT = RESULT.with_suffix(".md")
TEST = ROOT / "tests/test_chacha20_round20_w47_target_conditioned_recovery_a353.py"
REPRO = ROOT / "scripts/reproduce_chacha20_round20_w47_target_conditioned_recovery_a353.sh"

A346_PROTOCOL = CONFIGS / "chacha20_round20_w47_sixteen_slab_grouped_engine_a346_v1.json"
A346_QUALIFICATION = RESULTS / "chacha20_round20_w47_sixteen_slab_grouped_engine_a346_qualification_v1.json"
A347_RUNNER = RESEARCH / "experiments/chacha20_round20_fresh_w47_factor2_transfer_a347.py"
A347_DESIGN = CONFIGS / "chacha20_round20_fresh_w47_factor2_transfer_a347_design_v1.json"
A347_IMPLEMENTATION = CONFIGS / "chacha20_round20_fresh_w47_factor2_transfer_a347_implementation_v1.json"
A347_ORDER = RESULTS / "chacha20_round20_fresh_w47_factor2_transfer_a347_order_v1.json"
A347_PROTOCOL = CONFIGS / "chacha20_round20_fresh_w47_factor2_transfer_a347_v1.json"
A347_PROGRESS = RESULTS / "chacha20_round20_fresh_w47_factor2_transfer_a347_progress_v1.json"
A347_RESULT = RESULTS / "chacha20_round20_fresh_w47_factor2_transfer_a347_v1.json"
A352_RUNNER = RESEARCH / "experiments/chacha20_round20_w47_target_conditioned_factor2_a352.py"
A352_DESIGN = CONFIGS / "chacha20_round20_w47_target_conditioned_factor2_a352_design_v1.json"
A352_IMPLEMENTATION = CONFIGS / "chacha20_round20_w47_target_conditioned_factor2_a352_implementation_v1.json"
A352_ORDER = RESULTS / "chacha20_round20_w47_target_conditioned_factor2_a352_order_v1.json"

ATTEMPT_ID = "A353"
DESIGN_SHA256 = "6e441e8a372a024c5bd932f56104ced2ae6bf703900ee1528b0a4a14ed781d99"
A346_PROTOCOL_SHA256 = "4cb6c1c7e0a9719cf4ac04e870d9f5190772664b786d541a0fc4c7c7ea86e3ca"
A347_DESIGN_SHA256 = "78e3406ca48af0c81f002c0f5329c1b7267481eca579ac9544b5188ee3cbe102"
A347_IMPLEMENTATION_SHA256 = "2d951320541a4b5e3606fb289541369c635c9ecc96d92961a57df228494af3c7"
A347_ORDER_SHA256 = "5a287c0985ed249e15d3d1a9b351d30e70503b15ccd6199e33944a633144a2a6"
A352_DESIGN_SHA256 = "3136952bbef9cbaaa168eb83d2c281a1980092087ec626eb821c0f46e816f241"
A352_IMPLEMENTATION_SHA256 = "5c5015b8d082fd8a0988110abd7522aee1dcaacaf7014f023eb5a0b6e3b665a2"

WIDTH = 47
PREFIX_BITS = 12
CELLS = 1 << PREFIX_BITS
GROUP_SIZE = 1 << (WIDTH - PREFIX_BITS)
DOMAIN_SIZE = 1 << WIDTH
SELECTED_OPERATOR = "A352_W47_target_conditioned_plus_A347_target_free_factor2_wavefront"
DOTCAUSAL_SRC = Path("/Users/bhkmie/Documents/Forschung/O1/vendor/fabel/dotcausal_package/src")


def load_module(path: Path, name: str) -> Any:
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot import A353 dependency {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


A347 = load_module(A347_RUNNER, "a353_a347")
A352 = load_module(A352_RUNNER, "a353_a352")
file_sha256 = A347.file_sha256
canonical_sha256 = A347.canonical_sha256
atomic_json = A347.atomic_json
atomic_bytes = A347.atomic_bytes
relative = A347.relative
path_from_ref = A347.path_from_ref
anchor = A347.anchor


def exact_order(values: Sequence[int], label: str) -> list[int]:
    order = [int(value) for value in values]
    if len(order) != CELLS or set(order) != set(range(CELLS)):
        raise ValueError(f"A353 {label} is not an exact 4,096-cell order")
    return order


def order_sha256(order: Sequence[int]) -> str:
    return A352.A351.order_sha256(exact_order(order, "hash"))


def rank_vector(order: Sequence[int]) -> list[int]:
    ranks = [0] * CELLS
    for rank, cell in enumerate(exact_order(order, "rank vector"), 1):
        ranks[cell] = rank
    return ranks


def load_design() -> dict[str, Any]:
    if file_sha256(DESIGN) != DESIGN_SHA256:
        raise RuntimeError("A353 design hash differs")
    value = json.loads(DESIGN.read_bytes())
    boundary = value.get("information_boundary", {})
    execution = value.get("execution_contract", {})
    order = value.get("order_contract", {})
    if (
        value.get("schema") != "chacha20-round20-w47-target-conditioned-recovery-a353-design-v1"
        or value.get("attempt_id") != ATTEMPT_ID
        or value.get("design_state")
        != "frozen_before_A346_qualification_A347_protocol_A352_order_or_any_W47_candidate_prefix_result"
        or boundary.get("A347_protocol_available_at_design_freeze") is not False
        or boundary.get("A352_order_available_at_design_freeze") is not False
        or boundary.get("A353_candidate_or_prefix_available_at_design_freeze") is not False
        or execution.get("unknown_key_bits") != WIDTH
        or execution.get("candidates_per_prefix_group") != GROUP_SIZE
        or execution.get("complete_domain_assignments") != DOMAIN_SIZE
        or execution.get("slabs_per_prefix_group") != 16
        or order.get("target_labels_used") != 0
        or order.get("reader_refits") != 0
    ):
        raise RuntimeError("A353 frozen design semantics differ")
    for key, source_path in value["source_anchors"].items():
        if key.endswith("_path"):
            expected = value["source_anchors"][key.removesuffix("_path") + "_sha256"]
            anchor(ROOT / source_path, expected)
    return value


def assert_pre_target_sources() -> None:
    if A347_PROTOCOL.exists() or A352_ORDER.exists() or A347_PROGRESS.exists() or A347_RESULT.exists():
        raise RuntimeError("A353 implementation must precede W47 target, order and recovery")


def freeze_implementation() -> dict[str, Any]:
    if any(path.exists() for path in (IMPLEMENTATION, PROTOCOL, PROGRESS, RESULT, CAUSAL, REPORT)):
        raise FileExistsError("A353 implementation or execution artifacts already exist")
    assert_pre_target_sources()
    load_design()
    if not TEST.exists() or not REPRO.exists():
        raise FileNotFoundError("A353 test and reproducer must precede implementation freeze")
    payload: dict[str, Any] = {
        "schema": "chacha20-round20-w47-target-conditioned-recovery-a353-implementation-v1",
        "attempt_id": ATTEMPT_ID,
        "commitment_state": "frozen_before_A347_protocol_A352_order_candidate_prefix_or_result",
        "design_sha256": DESIGN_SHA256,
        "selected_operator": SELECTED_OPERATOR,
        "A347_protocol_available_at_implementation_freeze": False,
        "A352_order_available_at_implementation_freeze": False,
        "A353_candidate_or_prefix_available_at_implementation_freeze": False,
        "anchors": {
            "design": anchor(DESIGN, DESIGN_SHA256),
            "A346_protocol": anchor(A346_PROTOCOL, A346_PROTOCOL_SHA256),
            "A347_design": anchor(A347_DESIGN, A347_DESIGN_SHA256),
            "A347_implementation": anchor(A347_IMPLEMENTATION, A347_IMPLEMENTATION_SHA256),
            "A347_order": anchor(A347_ORDER, A347_ORDER_SHA256),
            "A347_runner": anchor(A347_RUNNER),
            "A352_design": anchor(A352_DESIGN, A352_DESIGN_SHA256),
            "A352_implementation": anchor(A352_IMPLEMENTATION, A352_IMPLEMENTATION_SHA256),
            "A352_runner": anchor(A352_RUNNER),
            "runner": anchor(Path(__file__)),
            "test": anchor(TEST),
            "reproducer": anchor(REPRO),
        },
    }
    payload["implementation_commitment_sha256"] = canonical_sha256(payload)
    atomic_json(IMPLEMENTATION, payload)
    try:
        assert_pre_target_sources()
    except Exception:
        IMPLEMENTATION.unlink(missing_ok=True)
        raise
    return payload


def load_implementation(expected_sha256: str) -> dict[str, Any]:
    if file_sha256(IMPLEMENTATION) != expected_sha256:
        raise RuntimeError("A353 implementation hash differs")
    value = json.loads(IMPLEMENTATION.read_bytes())
    if (
        value.get("schema")
        != "chacha20-round20-w47-target-conditioned-recovery-a353-implementation-v1"
        or value.get("attempt_id") != ATTEMPT_ID
        or value.get("commitment_state")
        != "frozen_before_A347_protocol_A352_order_candidate_prefix_or_result"
        or value.get("design_sha256") != DESIGN_SHA256
        or value.get("selected_operator") != SELECTED_OPERATOR
        or value.get("A347_protocol_available_at_implementation_freeze") is not False
        or value.get("A352_order_available_at_implementation_freeze") is not False
    ):
        raise RuntimeError("A353 implementation semantics differ")
    expected = {
        "design": DESIGN,
        "A346_protocol": A346_PROTOCOL,
        "A347_design": A347_DESIGN,
        "A347_implementation": A347_IMPLEMENTATION,
        "A347_order": A347_ORDER,
        "A347_runner": A347_RUNNER,
        "A352_design": A352_DESIGN,
        "A352_implementation": A352_IMPLEMENTATION,
        "A352_runner": A352_RUNNER,
        "runner": Path(__file__),
        "test": TEST,
        "reproducer": REPRO,
    }
    for name, path in expected.items():
        row = value["anchors"][name]
        if row.get("path") != relative(path) or row.get("sha256") != file_sha256(path):
            raise RuntimeError(f"A353 implementation anchor differs: {name}")
    unsigned = {key: item for key, item in value.items() if key != "implementation_commitment_sha256"}
    if value.get("implementation_commitment_sha256") != canonical_sha256(unsigned):
        raise RuntimeError("A353 implementation commitment differs")
    return value


def load_a352_order(expected_sha256: str, expected_a347_protocol_sha256: str) -> dict[str, Any]:
    if file_sha256(A352_ORDER) != expected_sha256:
        raise RuntimeError("A353 A352 order artifact hash differs")
    value = json.loads(A352_ORDER.read_bytes())
    selected = exact_order(value.get("selected_order", []), "A352 selected order")
    target = exact_order(value.get("target_conditioned_order", []), "A352 target-conditioned order")
    source = exact_order(A347.load_order()["selected_order"], "A347 source order")
    if (
        value.get("schema") != "chacha20-round20-w47-target-conditioned-factor2-a352-order-v1"
        or value.get("A347_protocol_sha256") != expected_a347_protocol_sha256
        or value.get("A347_recovery_available_at_order_freeze") is not False
        or value.get("target_labels_used") != 0
        or value.get("reader_refits") != 0
        or value.get("candidate_assignments_executed") != 0
        or value.get("selected_order_uint16be_sha256") != order_sha256(selected)
        or value.get("target_conditioned_order_uint16be_sha256") != order_sha256(target)
        or selected != A352.A351.factor2_wavefront(source, target)
        or value.get("pointwise_factor2_proof")
        != A352.A351.factor2_proof(source, target, selected)
    ):
        raise RuntimeError("A353 A352 order semantics differ")
    return value


def freeze_protocol(
    *,
    expected_implementation_sha256: str,
    expected_a347_protocol_sha256: str,
    expected_a352_order_sha256: str,
    expected_a346_qualification_sha256: str,
) -> dict[str, Any]:
    if any(path.exists() for path in (PROTOCOL, PROGRESS, RESULT, CAUSAL, REPORT)):
        raise FileExistsError("A353 protocol or execution artifacts already exist")
    if A347_PROGRESS.exists() or A347_RESULT.exists():
        raise RuntimeError("A353 protocol must precede A347 recovery")
    implementation = load_implementation(expected_implementation_sha256)
    source_protocol = A347.load_protocol(expected_a347_protocol_sha256)
    order = load_a352_order(expected_a352_order_sha256, expected_a347_protocol_sha256)
    qualification = A347.load_a346_qualification(expected_a346_qualification_sha256)
    selected = exact_order(order["selected_order"], "protocol selected")
    payload: dict[str, Any] = {
        "schema": "chacha20-round20-w47-target-conditioned-recovery-a353-protocol-v1",
        "attempt_id": ATTEMPT_ID,
        "protocol_state": "A352_order_bound_after_public_measurement_before_any_A347_or_A353_candidate_prefix_or_result",
        "design_sha256": DESIGN_SHA256,
        "implementation_sha256": expected_implementation_sha256,
        "implementation_commitment_sha256": implementation["implementation_commitment_sha256"],
        "A346_qualification_sha256": expected_a346_qualification_sha256,
        "A346_semantic_qualification_sha256": qualification["qualification_sha256"],
        "A347_protocol_sha256": expected_a347_protocol_sha256,
        "A352_order_sha256": expected_a352_order_sha256,
        "A352_order_commitment_sha256": order["order_commitment_sha256"],
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
            "A347_recovery_available_at_protocol_freeze": False,
            "A353_candidate_or_prefix_available_at_protocol_freeze": False,
            "A352_order_frozen_before_protocol": True,
            "target_labels_used_for_order_construction": 0,
            "reader_refits": 0,
        },
        "anchors": {
            "design": anchor(DESIGN, DESIGN_SHA256),
            "implementation": anchor(IMPLEMENTATION, expected_implementation_sha256),
            "A346_protocol": anchor(A346_PROTOCOL, A346_PROTOCOL_SHA256),
            "A346_qualification": anchor(A346_QUALIFICATION, expected_a346_qualification_sha256),
            "A347_protocol": anchor(A347_PROTOCOL, expected_a347_protocol_sha256),
            "A347_order": anchor(A347_ORDER, A347_ORDER_SHA256),
            "A352_order": anchor(A352_ORDER, expected_a352_order_sha256),
            "runner": anchor(Path(__file__)),
            "test": anchor(TEST),
            "reproducer": anchor(REPRO),
        },
    }
    payload["protocol_commitment_sha256"] = canonical_sha256(
        {
            "implementation_commitment_sha256": payload["implementation_commitment_sha256"],
            "A347_protocol_sha256": expected_a347_protocol_sha256,
            "A352_order_sha256": expected_a352_order_sha256,
            "A352_order_commitment_sha256": payload["A352_order_commitment_sha256"],
            "selected_order_uint16be_sha256": payload["selected_order_uint16be_sha256"],
            "public_challenge_sha256": payload["public_challenge_sha256"],
            "A346_qualification_sha256": expected_a346_qualification_sha256,
            "information_boundary": payload["information_boundary"],
        }
    )
    atomic_json(PROTOCOL, payload)
    if A347_PROGRESS.exists() or A347_RESULT.exists():
        PROTOCOL.unlink(missing_ok=True)
        raise RuntimeError("A353 protocol did not precede A347 recovery")
    return payload


def load_protocol(expected_sha256: str) -> dict[str, Any]:
    if file_sha256(PROTOCOL) != expected_sha256:
        raise RuntimeError("A353 protocol hash differs")
    value = json.loads(PROTOCOL.read_bytes())
    selected = exact_order(value.get("selected_order", []), "stored protocol order")
    if (
        value.get("schema") != "chacha20-round20-w47-target-conditioned-recovery-a353-protocol-v1"
        or value.get("attempt_id") != ATTEMPT_ID
        or value.get("selected_operator") != SELECTED_OPERATOR
        or value.get("selected_order_uint16be_sha256") != order_sha256(selected)
        or value.get("information_boundary", {}).get("A347_recovery_available_at_protocol_freeze")
        is not False
        or value.get("information_boundary", {}).get("target_labels_used_for_order_construction")
        != 0
        or canonical_sha256(value.get("public_challenge")) != value.get("public_challenge_sha256")
    ):
        raise RuntimeError("A353 protocol semantics differ")
    for row in value["anchors"].values():
        anchor(path_from_ref(row["path"]), row["sha256"])
    load_implementation(value["implementation_sha256"])
    load_a352_order(value["A352_order_sha256"], value["A347_protocol_sha256"])
    A347.validate_challenge(value["public_challenge"])
    return value


def load_resume(
    *, protocol_sha256: str, order_sha: str, qualification_sha256: str
) -> tuple[int, float, int, dict[str, Any] | None]:
    if not PROGRESS.exists():
        return 0, 0.0, 0, None
    value = json.loads(PROGRESS.read_bytes())
    if (
        value.get("schema") != "chacha20-round20-w47-target-conditioned-recovery-a353-progress-v1"
        or value.get("attempt_id") != ATTEMPT_ID
        or value.get("protocol_sha256") != protocol_sha256
        or value.get("selected_order_uint16be_sha256") != order_sha
        or value.get("A346_qualification_sha256") != qualification_sha256
        or value.get("matched_control_candidates") != 0
    ):
        raise RuntimeError("A353 progress fingerprint differs")
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
        raise RuntimeError("A353 resumable progress state differs")
    return completed, float(value.get("gpu_seconds", 0.0)), int(value.get("host_instances", 0)), None


def rank_panel(prefix: int, protocol: Mapping[str, Any], a352_order: Mapping[str, Any]) -> dict[str, Any]:
    source = exact_order(A347.load_order()["selected_order"], "A347 rank source")
    target = exact_order(a352_order["target_conditioned_order"], "target-conditioned rank source")
    selected = exact_order(protocol["selected_order"], "selected rank source")
    ranks = {
        "A347_target_free": rank_vector(source)[prefix],
        "A352_target_conditioned": rank_vector(target)[prefix],
        "A353_executed_factor2_portfolio": rank_vector(selected)[prefix],
    }
    best = min(ranks["A347_target_free"], ranks["A352_target_conditioned"])
    return {
        "prefix12": prefix,
        "prefix12_hex": f"{prefix:03x}",
        "prefix_ranks_one_based": ranks,
        "selected_rank_one_based": ranks["A353_executed_factor2_portfolio"],
        "selected_gain_bits_vs_complete_domain": math.log2(
            CELLS / ranks["A353_executed_factor2_portfolio"]
        ),
        "selected_domain_reduction_factor": CELLS / ranks["A353_executed_factor2_portfolio"],
        "factor2_bound_for_confirmed_prefix": ranks["A353_executed_factor2_portfolio"] <= 2 * best,
        "portfolio_overhead_vs_better_source": ranks["A353_executed_factor2_portfolio"] / best,
        "ranks_computed_only_after_independent_confirmation": True,
    }


def build_causal(payload: Mapping[str, Any]) -> dict[str, Any]:
    sys.path.insert(0, str(DOTCAUSAL_SRC))
    from dotcausal.io import CausalReader, CausalWriter

    terminal = "A353:confirmed_target_conditioned_W47_recovery"
    writer = CausalWriter(api_id="a353w47")
    writer._rules = []
    writer.add_rule(
        name="public_W47_reader_to_bounded_order",
        description="The pre-target A352 implementation turns the public W47 output into a zero-refit order and merges it with A347 under a pointwise factor-two bound.",
        pattern=["A352_public_output_reader", "A347_target_free_order"],
        conclusion="A353_frozen_W47_recovery_order",
        confidence_modifier=1.0,
    )
    writer.add_rule(
        name="complete_sixteen_slab_search_to_confirmed_model",
        description="Every selected prefix executes sixteen complete slabs before the factual model is independently confirmed across all eight blocks.",
        pattern=["A353_frozen_W47_recovery_order", "A346_exact_W47_group_engine"],
        conclusion="A353_confirmed_target_conditioned_W47_recovery",
        confidence_modifier=1.0,
    )
    writer.add_triplet(
        trigger="A352:public_output_conditioned_factor2_order",
        mechanism="qualified_ordered_complete_sixteen_slab_search",
        outcome="A353:sole_factual_W47_model",
        confidence=1.0,
        source=payload["execution_sha256"],
        quantification=json.dumps(payload["discovery"], sort_keys=True),
        evidence=json.dumps(payload["rank_analysis"], sort_keys=True),
        domain="fresh full-round ChaCha20 W47 target-conditioned recovery",
        quality_score=1.0,
    )
    writer.add_triplet(
        trigger="A353:sole_factual_W47_model",
        mechanism="dual_independent_eight_block_confirmation",
        outcome=terminal,
        confidence=1.0,
        source=payload["measurement_sha256"],
        quantification=json.dumps(payload["confirmation"], sort_keys=True),
        evidence=payload["evidence_stage"],
        domain="confirmed full-round ChaCha20 W47 recovery",
        quality_score=1.0,
    )
    writer.add_triplet(
        trigger="A352:public_output_conditioned_factor2_order",
        mechanism="materialized_W47_search_and_confirmation_closure",
        outcome=terminal,
        confidence=1.0,
        source="materialized:A353_W47_recovery_chain",
        quantification="exact retained closure",
        evidence=payload["evidence_stage"],
        domain="AI-native retained inference",
        quality_score=1.0,
        is_inferred=True,
    )
    writer.add_cluster(
        name="A353 target-conditioned W47 recovery",
        entities=[
            "A352:public_output_conditioned_factor2_order",
            "A353:sole_factual_W47_model",
            terminal,
        ],
    )
    writer.add_gap(
        subject=terminal,
        predicate="next_required_object",
        expected_object_type="W48_target_conditioned_transfer_or_second_fresh_W47_replication",
        confidence=1.0,
        suggested_queries=["Lift the complete target-conditioned portfolio to a qualified W48 engine."],
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
        reader.api_id != "a353w47"
        or len(explicit) != 2
        or len(all_rows) != 3
        or len(inferred) != 1
        or len(reader._rules) != 2
        or len(reader._clusters) != 1
        or len(reader._gaps) != 1
    ):
        raise RuntimeError("A353 authentic Causal reopen gate failed")
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


def recover(*, expected_protocol_sha256: str) -> dict[str, Any]:
    if any(path.exists() for path in (RESULT, CAUSAL, REPORT)):
        raise FileExistsError("A353 result artifacts already exist")
    protocol = load_protocol(expected_protocol_sha256)
    qualification = A347.load_a346_qualification(protocol["A346_qualification_sha256"])
    a352_order = load_a352_order(protocol["A352_order_sha256"], protocol["A347_protocol_sha256"])
    a346_protocol = A347.A346.load_protocol(A346_PROTOCOL_SHA256)
    executable_row = a346_protocol["anchors"]["grouped_executable"]
    executable = path_from_ref(executable_row["path"])
    anchor(executable, executable_row["sha256"])
    challenge = protocol["public_challenge"]
    placeholder = np.asarray([0, 0], dtype=np.uint32)

    def host_factory() -> Any:
        return A347.A346.A324.A311.A307.A304.GroupedMetalHost(
            executable,
            A347.A346.initial_for_slab(challenge, 0),
            placeholder,
            placeholder,
        )

    def write_progress(row: Mapping[str, Any]) -> None:
        atomic_json(
            PROGRESS,
            {
                "schema": "chacha20-round20-w47-target-conditioned-recovery-a353-progress-v1",
                "attempt_id": ATTEMPT_ID,
                "protocol_sha256": expected_protocol_sha256,
                "selected_operator": SELECTED_OPERATOR,
                "selected_order_uint16be_sha256": protocol["selected_order_uint16be_sha256"],
                "A346_qualification_sha256": protocol["A346_qualification_sha256"],
                **dict(row),
            },
        )

    start, prior_gpu, prior_hosts, completed_discovery = load_resume(
        protocol_sha256=expected_protocol_sha256,
        order_sha=protocol["selected_order_uint16be_sha256"],
        qualification_sha256=protocol["A346_qualification_sha256"],
    )
    discovery = completed_discovery or A347.ordered_discovery(
        host_factory=host_factory,
        challenge=challenge,
        order=protocol["selected_order"],
        start_group=start,
        prior_gpu_seconds=prior_gpu,
        prior_host_instances=prior_hosts,
        progress_callback=write_progress,
    )
    if discovery["matched_control_candidates"] != 0:
        raise RuntimeError("A353 matched control produced a candidate")
    candidate = int(discovery["candidate"])
    confirmation = A347.confirm(challenge, candidate)
    if confirmation["all_blocks_match"] is not True:
        raise RuntimeError("A353 dual independent confirmation failed")
    ranks = rank_panel(int(discovery["prefix12"]), protocol, a352_order)
    if ranks["selected_rank_one_based"] != discovery["executed_prefix_groups"]:
        raise RuntimeError("A353 discovery rank differs from selected order")
    strict_subset = discovery["executed_prefix_groups"] < CELLS
    evidence_stage = (
        "FULLROUND_R20_TARGET_CONDITIONED_W47_STRICT_SUBSET_RECOVERY_CONFIRMED"
        if strict_subset
        else "FULLROUND_R20_TARGET_CONDITIONED_W47_COMPLETE_DOMAIN_RECOVERY_CONFIRMED"
    )
    payload: dict[str, Any] = {
        "schema": "chacha20-round20-w47-target-conditioned-recovery-a353-result-v1",
        "attempt_id": ATTEMPT_ID,
        "evidence_stage": evidence_stage,
        "protocol_sha256": expected_protocol_sha256,
        "design_sha256": DESIGN_SHA256,
        "implementation_sha256": protocol["implementation_sha256"],
        "A346_qualification_sha256": protocol["A346_qualification_sha256"],
        "A347_protocol_sha256": protocol["A347_protocol_sha256"],
        "A352_order_sha256": protocol["A352_order_sha256"],
        "A352_order_commitment_sha256": protocol["A352_order_commitment_sha256"],
        "public_challenge_sha256": protocol["public_challenge_sha256"],
        "selected_operator": SELECTED_OPERATOR,
        "selected_order_uint16be_sha256": protocol["selected_order_uint16be_sha256"],
        "pointwise_factor2_proof": protocol["pointwise_factor2_proof"],
        "operator_diversity": protocol["operator_diversity"],
        "qualification_gate": {
            "evidence_stage": qualification["evidence_stage"],
            "qualification_sha256": qualification["qualification_sha256"],
            "complete_W47_group_candidates": qualification["complete_group_gate"]["logical_candidates"],
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
            "A346_qualification_sha256": protocol["A346_qualification_sha256"],
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
            "# A353 — target-conditioned full-round ChaCha20 W47 recovery\n\n"
            f"Evidence stage: **{evidence_stage}**\n\n"
            f"- Selected operator: **{SELECTED_OPERATOR}**\n"
            f"- W47 execution rank: **{ranks['selected_rank_one_based']} / {CELLS}**\n"
            f"- Complete candidate evaluations: **{discovery['executed_assignments']:,} / {DOMAIN_SIZE:,}**\n"
            f"- Recovered W47 assignment: **0x{candidate:012x}**\n"
            "- Standard ChaCha20: **20 rounds plus feed-forward**\n"
            "- Every prefix: **sixteen complete 2^31 slabs before outcome evaluation**\n"
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
    parser.add_argument("--expected-a347-protocol-sha256")
    parser.add_argument("--expected-a352-order-sha256")
    parser.add_argument("--expected-a346-qualification-sha256")
    parser.add_argument("--expected-protocol-sha256")
    args = parser.parse_args()
    if args.freeze_implementation:
        payload = freeze_implementation()
    elif args.freeze_protocol:
        required = (
            args.expected_implementation_sha256,
            args.expected_a347_protocol_sha256,
            args.expected_a352_order_sha256,
            args.expected_a346_qualification_sha256,
        )
        if not all(required):
            parser.error("--freeze-protocol requires implementation, A347, A352 and qualification hashes")
        payload = freeze_protocol(
            expected_implementation_sha256=args.expected_implementation_sha256,
            expected_a347_protocol_sha256=args.expected_a347_protocol_sha256,
            expected_a352_order_sha256=args.expected_a352_order_sha256,
            expected_a346_qualification_sha256=args.expected_a346_qualification_sha256,
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

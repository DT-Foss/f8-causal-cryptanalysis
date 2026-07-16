#!/usr/bin/env python3
"""A382: transfer A375's four frozen Readers to W49 and build an exact factor-six order."""

from __future__ import annotations

import argparse
import importlib.util
import inspect
import json
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

DESIGN = CONFIGS / "chacha20_round20_w49_crosswidth_wide_consensus_factor6_a382_design_v1.json"
IMPLEMENTATION = (
    CONFIGS / "chacha20_round20_w49_crosswidth_wide_consensus_factor6_a382_implementation_v1.json"
)
ORDER = RESULTS / "chacha20_round20_w49_crosswidth_wide_consensus_factor6_a382_order_v1.json"
CAUSAL = ORDER.with_suffix(".causal")
REPORT = ORDER.with_suffix(".md")
TEST = ROOT / "tests/test_chacha20_round20_w49_crosswidth_wide_consensus_factor6_a382.py"
REPRO = ROOT / "scripts/reproduce_chacha20_round20_w49_crosswidth_wide_consensus_factor6_a382.sh"

A375_RESULT = RESULTS / "chacha20_round20_w46_wide_consensus_reader_a375_v1.json"
A375_RUNNER = RESEARCH / "experiments/chacha20_round20_w46_wide_consensus_reader_a375.py"
A376_RUNNER = RESEARCH / "experiments/chacha20_round20_w46_a375_reader_sealed_a361_order_a376.py"
A379_ORDER = RESULTS / "chacha20_round20_fresh_w49_pretarget_transfer_a379_order_v1.json"
A379_PROTOCOL = CONFIGS / "chacha20_round20_fresh_w49_pretarget_transfer_a379_v1.json"
A380_RUNNER = RESEARCH / "experiments/chacha20_round20_w49_target_conditioned_factor2_a380.py"
A380_ORDER = RESULTS / "chacha20_round20_w49_target_conditioned_factor2_a380_order_v1.json"
A380_CAUSAL = A380_ORDER.with_suffix(".causal")
A383_PROGRESS = RESULTS / "chacha20_round20_w49_factor6_recovery_a383_progress_v1.json"
A383_RESULT = RESULTS / "chacha20_round20_w49_factor6_recovery_a383_v1.json"

ATTEMPT_ID = "A382"
DESIGN_SHA256 = "c332e7c4fc8953384a208657a440324d7fa0f98ed6c85efb8d91b6705b8bd3d1"
A375_RESULT_SHA256 = "fc7135af9e001eb8cd83a55902e48f5776dc24a4eb86a162d7d783a115b38ef1"
A375_RUNNER_SHA256 = "e41a91b225b861abd669280a4044dddf5e2b24e8f6e8c66e7eee6d5a149ec9f1"
A376_RUNNER_SHA256 = "8a74a7cd015e77806809bacb2417ced7ea1deb0f4df7c8c51a06fa4b3daf8a31"
A379_ORDER_SHA256 = "90e06848c9f608ae484b9cdf95d0ebcc64a0776b976470df436e82392caf02a5"
A379_PROTOCOL_SHA256 = "673b44d81f1e25490fd778b48d1ef0c6423ddda6716354c03f5212f68888903a"
A380_RUNNER_SHA256 = "15ea505092459036f92f56d8628aecee7bfe48790e8f14b9aebc9befc0f3a20b"
A380_ORDER_SHA256 = "a5cc83121e8c0f58b91046e5d9d6f6b2476008984efae19675ee652e5c656ed8"
A380_CAUSAL_SHA256 = "dc72f6663fa4389fc667fe3d70b423da9471a8ee829680b4f61820f18a652f39"

MODEL_ROLES = ("wide_vote", "sparse_reciprocal", "broad_quantile", "broad_intersection")
SOURCE_ROLES = ("A379_target_free", "A380_target_conditioned", *MODEL_ROLES)
SLICES = tuple(range(16))
CELLS = 4096
WITHIN_CELLS = 256
FEATURES = 532
DOTCAUSAL_SRC = Path("/Users/bhkmie/Documents/Forschung/O1/vendor/fabel/dotcausal_package/src")


def load_module(path: Path, name: str) -> Any:
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot import A382 dependency {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


A376 = load_module(A376_RUNNER, "a382_a376")
A380 = load_module(A380_RUNNER, "a382_a380")
file_sha256 = A376.file_sha256
canonical_sha256 = A376.canonical_sha256
atomic_json = A376.atomic_json
atomic_bytes = A376.atomic_bytes
relative = A376.relative
path_from_ref = A376.path_from_ref
anchor = A376.anchor


def exact_order(values: Sequence[int], label: str) -> list[int]:
    order = [int(value) for value in values]
    if len(order) != CELLS or set(order) != set(range(CELLS)):
        raise ValueError(f"A382 {label} is not an exact 4,096-cell order")
    return order


def order_sha256(values: Sequence[int]) -> str:
    return A376.order_sha256(exact_order(values, "hash"))


def rank_vector(order: Sequence[int]) -> list[int]:
    ranks = [0] * CELLS
    for rank, cell in enumerate(exact_order(order, "rank vector"), 1):
        ranks[cell] = rank
    return ranks


def factor_k_wavefront(
    source_orders: Mapping[str, Sequence[int]], role_order: Sequence[str]
) -> list[int]:
    roles = tuple(str(role) for role in role_order)
    if not roles or set(roles) != set(source_orders) or len(roles) != len(set(roles)):
        raise ValueError("A382 source-role cover differs")
    ranks = {role: rank_vector(source_orders[role]) for role in roles}
    return exact_order(
        sorted(
            range(CELLS),
            key=lambda cell: (
                min(ranks[role][cell] for role in roles),
                sum(ranks[role][cell] for role in roles),
                *(ranks[role][cell] for role in roles),
                cell,
            ),
        ),
        "factor-k wavefront",
    )


def factor_k_proof(
    source_orders: Mapping[str, Sequence[int]],
    role_order: Sequence[str],
    portfolio: Sequence[int],
) -> dict[str, Any]:
    roles = tuple(str(role) for role in role_order)
    source_ranks = {role: rank_vector(source_orders[role]) for role in roles}
    portfolio_ranks = rank_vector(portfolio)
    k = len(roles)
    ratios = [
        portfolio_ranks[cell] / min(source_ranks[role][cell] for role in roles)
        for cell in range(CELLS)
    ]
    violations = [cell for cell, ratio in enumerate(ratios) if ratio > k + 1e-15]
    if violations:
        raise RuntimeError("A382 factor-k pointwise proof failed")
    return {
        "bound": f"R_A382(c) <= {k}*min_source_R(c)",
        "source_count": k,
        "cells_checked": CELLS,
        "maximum_ratio": max(ratios),
        "mean_ratio": float(np.mean(ratios)),
        "violations": 0,
    }


def load_design() -> dict[str, Any]:
    if file_sha256(DESIGN) != DESIGN_SHA256:
        raise RuntimeError("A382 design hash differs")
    value = json.loads(DESIGN.read_bytes())
    boundary = value.get("information_boundary", {})
    reader = value.get("reader_contract", {})
    order = value.get("order_contract", {})
    if (
        value.get("schema")
        != "chacha20-round20-w49-crosswidth-wide-consensus-factor6-a382-design-v1"
        or value.get("attempt_id") != ATTEMPT_ID
        or value.get("design_state")
        != "frozen_after_A375_selection_and_A380_complete_public_measurement_before_A382_W49_reader_scoring_order_candidate_prefix_or_recovery"
        or tuple(reader.get("fixed_model_roles", [])) != MODEL_ROLES
        or reader.get("reader_refits_on_W49") != 0
        or reader.get("target_labels_used") != 0
        or tuple(order.get("source_roles", [])) != SOURCE_ROLES
        or order.get("pointwise_bound_checked_cells") != CELLS
        or boundary.get("A381_result_available_at_design_freeze") is not False
        or boundary.get("A382_reader_scores_available_at_design_freeze") is not False
        or boundary.get("A382_candidate_assignments_executed_at_design_freeze") != 0
        or boundary.get("A382_true_prefix_or_assignment_available_at_design_freeze") is not False
    ):
        raise RuntimeError("A382 frozen design semantics differ")
    for name, path_value in value["source_anchors"].items():
        if name.endswith("_path"):
            stem = name.removesuffix("_path")
            anchor(ROOT / path_value, value["source_anchors"][f"{stem}_sha256"])
    return value


def assert_pre_order() -> None:
    if any(path.exists() for path in (ORDER, CAUSAL, REPORT, A383_PROGRESS, A383_RESULT)):
        raise RuntimeError("A382 must precede every A382 order and A383 candidate execution")


def load_a375_result() -> dict[str, Any]:
    return A376.load_a375_result(A375_RESULT_SHA256)


def load_a380_order() -> dict[str, Any]:
    if file_sha256(A380_ORDER) != A380_ORDER_SHA256:
        raise RuntimeError("A382 A380 order hash differs")
    value = json.loads(A380_ORDER.read_bytes())
    target = exact_order(value.get("target_conditioned_order", []), "A380 target-conditioned")
    selected = exact_order(value.get("selected_order", []), "A380 selected")
    if (
        value.get("schema") != "chacha20-round20-w49-target-conditioned-factor2-a380-order-v1"
        or value.get("target_labels_used") != 0
        or value.get("reader_refits") != 0
        or value.get("candidate_assignments_executed") != 0
        or value.get("W49_recovery_available_at_order_freeze") is not False
        or value.get("target_conditioned_order_uint16be_sha256") != order_sha256(target)
        or value.get("selected_order_uint16be_sha256") != order_sha256(selected)
        or len(value.get("measurement_ledger", [])) != len(SLICES)
    ):
        raise RuntimeError("A382 A380 order semantics differ")
    anchor(A380_CAUSAL, A380_CAUSAL_SHA256)
    return value


def freeze_implementation() -> dict[str, Any]:
    if IMPLEMENTATION.exists():
        raise FileExistsError("A382 implementation already exists")
    assert_pre_order()
    load_design()
    a375 = load_a375_result()
    a380 = load_a380_order()
    if not TEST.exists() or not REPRO.exists():
        raise FileNotFoundError("A382 test and reproducer must precede implementation freeze")
    payload: dict[str, Any] = {
        "schema": "chacha20-round20-w49-crosswidth-wide-consensus-factor6-a382-implementation-v1",
        "attempt_id": ATTEMPT_ID,
        "commitment_state": "frozen_before_A375_scoring_of_A380_W49_measurements_A382_order_or_A383_candidate",
        "design_sha256": DESIGN_SHA256,
        "model_role_order": list(MODEL_ROLES),
        "source_role_order": list(SOURCE_ROLES),
        "model_definitions": a375["model_definitions"],
        "A375_selection_commitment_sha256": a375["selection_commitment_sha256"],
        "A380_measurement_sha256": a380["measurement_sha256"],
        "A382_reader_scores_available_at_implementation_freeze": False,
        "A382_true_prefix_or_assignment_available_at_implementation_freeze": False,
        "A382_candidate_assignments_executed_at_implementation_freeze": 0,
        "reader_refits_on_W49": 0,
        "target_labels_used": 0,
        "anchors": {
            "design": anchor(DESIGN, DESIGN_SHA256),
            "A375_result": anchor(A375_RESULT, A375_RESULT_SHA256),
            "A375_runner": anchor(A375_RUNNER, A375_RUNNER_SHA256),
            "A376_runner": anchor(A376_RUNNER, A376_RUNNER_SHA256),
            "A379_order": anchor(A379_ORDER, A379_ORDER_SHA256),
            "A379_protocol": anchor(A379_PROTOCOL, A379_PROTOCOL_SHA256),
            "A380_order": anchor(A380_ORDER, A380_ORDER_SHA256),
            "A380_causal": anchor(A380_CAUSAL, A380_CAUSAL_SHA256),
            "A380_runner": anchor(A380_RUNNER, A380_RUNNER_SHA256),
            "runner": anchor(Path(__file__)),
            "test": anchor(TEST),
            "reproducer": anchor(REPRO),
        },
    }
    payload["implementation_commitment_sha256"] = canonical_sha256(payload)
    atomic_json(IMPLEMENTATION, payload)
    assert_pre_order()
    return payload


def load_implementation(expected_sha256: str) -> dict[str, Any]:
    if file_sha256(IMPLEMENTATION) != expected_sha256:
        raise RuntimeError("A382 implementation hash differs")
    value = json.loads(IMPLEMENTATION.read_bytes())
    if (
        value.get("schema")
        != "chacha20-round20-w49-crosswidth-wide-consensus-factor6-a382-implementation-v1"
        or value.get("attempt_id") != ATTEMPT_ID
        or value.get("commitment_state")
        != "frozen_before_A375_scoring_of_A380_W49_measurements_A382_order_or_A383_candidate"
        or value.get("design_sha256") != DESIGN_SHA256
        or tuple(value.get("model_role_order", [])) != MODEL_ROLES
        or tuple(value.get("source_role_order", [])) != SOURCE_ROLES
        or value.get("A382_reader_scores_available_at_implementation_freeze") is not False
        or value.get("A382_true_prefix_or_assignment_available_at_implementation_freeze") is not False
        or value.get("A382_candidate_assignments_executed_at_implementation_freeze") != 0
        or value.get("reader_refits_on_W49") != 0
        or value.get("target_labels_used") != 0
    ):
        raise RuntimeError("A382 implementation semantics differ")
    expected = {
        "design": DESIGN,
        "A375_result": A375_RESULT,
        "A375_runner": A375_RUNNER,
        "A376_runner": A376_RUNNER,
        "A379_order": A379_ORDER,
        "A379_protocol": A379_PROTOCOL,
        "A380_order": A380_ORDER,
        "A380_causal": A380_CAUSAL,
        "A380_runner": A380_RUNNER,
        "runner": Path(__file__),
        "test": TEST,
        "reproducer": REPRO,
    }
    for name, path in expected.items():
        row = value["anchors"][name]
        if row.get("path") != relative(path) or row.get("sha256") != file_sha256(path):
            raise RuntimeError(f"A382 implementation anchor differs: {name}")
    unsigned = {key: item for key, item in value.items() if key != "implementation_commitment_sha256"}
    if value.get("implementation_commitment_sha256") != canonical_sha256(unsigned):
        raise RuntimeError("A382 implementation commitment differs")
    return value


def load_measurements(a380: Mapping[str, Any]) -> dict[int, dict[str, Any]]:
    result: dict[int, dict[str, Any]] = {}
    for row in a380["measurement_ledger"]:
        low4 = int(row["low4"])
        value = A380._read_measurement(path_from_ref(row["path"]), row)  # noqa: SLF001
        A380._validate_measurement(value, low4)  # noqa: SLF001
        result[low4] = value
    if set(result) != set(SLICES):
        raise RuntimeError("A382 complete A380 slice cover differs")
    return result


def pairwise_diversity(source_orders: Mapping[str, Sequence[int]]) -> dict[str, Any]:
    panel: dict[str, Any] = {}
    for left_index, left in enumerate(SOURCE_ROLES):
        for right in SOURCE_ROLES[left_index + 1 :]:
            panel[f"{left}__vs__{right}"] = A380.A351.diversity_panel(
                source_orders[left], source_orders[right]
            )
    return panel


def build_causal(payload: Mapping[str, Any]) -> dict[str, Any]:
    sys.path.insert(0, str(DOTCAUSAL_SRC))
    from dotcausal.io import CausalReader, CausalWriter

    portfolio = "A382:exact_crosswidth_factor6_W49_order"
    ready = "A383:factor6_W49_recovery_ready"
    writer = CausalWriter(api_id="a382w49")
    writer._rules = []
    writer.add_rule(
        name="frozen_W46_models_to_W49_orders",
        description="Four A375 model definitions are applied unchanged to the complete public A380 W49 trajectory field.",
        pattern=["A375_frozen_W46_reader_portfolio", "A380_complete_public_W49_field"],
        conclusion="A382_four_crosswidth_W49_orders",
        confidence_modifier=1.0,
    )
    writer.add_rule(
        name="six_orders_to_exact_factor6",
        description="The four cross-width orders and the two frozen A379/A380 orders form a direct min-rank wavefront with a checked pointwise factor-six bound.",
        pattern=["A382_four_crosswidth_W49_orders", "A379_A380_two_W49_orders"],
        conclusion="A382_exact_crosswidth_factor6_W49_order",
        confidence_modifier=1.0,
    )
    writer.add_rule(
        name="factor6_to_recovery",
        description="The frozen order is directly executable by the qualified sixty-four-slab W49 engine.",
        pattern=["A382_exact_crosswidth_factor6_W49_order"],
        conclusion="A383_factor6_W49_recovery_ready",
        confidence_modifier=1.0,
    )
    writer.add_triplet(
        trigger="A375:frozen_W46_cross_corpus_reader_portfolio",
        mechanism="unchanged_532_feature_rank_transfer_over_complete_A380_W49_field",
        outcome="A382:four_crosswidth_W49_reader_orders",
        confidence=1.0,
        source=payload["order_commitment_sha256"],
        quantification=json.dumps(payload["reader_transfer_summary"], sort_keys=True),
        evidence=json.dumps(payload["source_order_summary"], sort_keys=True),
        domain="cross-width ChaCha20 R20 Reader transfer",
        quality_score=1.0,
    )
    writer.add_triplet(
        trigger="A382:four_crosswidth_W49_reader_orders",
        mechanism="direct_min_rank_merge_with_A379_target_free_and_A380_target_conditioned_orders",
        outcome=portfolio,
        confidence=1.0,
        source=payload["order_commitment_sha256"],
        quantification=json.dumps(payload["pointwise_factor6_proof"], sort_keys=True),
        evidence=json.dumps(payload["pairwise_diversity_summary"], sort_keys=True),
        domain="bounded six-view W49 recovery order",
        quality_score=1.0,
    )
    writer.add_triplet(
        trigger=portfolio,
        mechanism="freeze_before_A383_candidate_execution",
        outcome=ready,
        confidence=1.0,
        source=payload["order_commitment_sha256"],
        quantification="zero target labels, zero refits, zero candidate assignments",
        evidence=payload["evidence_stage"],
        domain="prospective W49 recovery orchestration",
        quality_score=1.0,
    )
    writer.add_triplet(
        trigger="A375:frozen_W46_cross_corpus_reader_portfolio",
        mechanism="materialized_crosswidth_reader_factor6_recovery_ready_chain",
        outcome=ready,
        confidence=1.0,
        source="materialized:A382_crosswidth_factor6_chain",
        quantification="exact retained closure",
        evidence=payload["evidence_stage"],
        domain="AI-native retained inference",
        quality_score=1.0,
        is_inferred=True,
    )
    writer.add_cluster(
        name="A382 cross-width six-view W49 portfolio",
        entities=[
            "A375:frozen_W46_cross_corpus_reader_portfolio",
            "A382:four_crosswidth_W49_reader_orders",
            portfolio,
            ready,
        ],
    )
    writer.add_gap(
        subject=ready,
        predicate="next_required_object",
        expected_object_type="executed_fullround_W49_recovery_in_frozen_A382_order",
        confidence=1.0,
        suggested_queries=["Execute the qualified sixty-four-slab W49 engine in the exact A382 factor-six order."],
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
        reader.api_id != "a382w49"
        or len(explicit) != 3
        or len(all_rows) != 4
        or len(inferred) != 1
        or len(reader._rules) != 3
        or len(reader._clusters) != 1
        or len(reader._gaps) != 1
    ):
        raise RuntimeError("A382 authentic Causal reopen gate failed")
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


def freeze_order(*, expected_implementation_sha256: str) -> dict[str, Any]:
    assert_pre_order()
    implementation = load_implementation(expected_implementation_sha256)
    a375 = load_a375_result()
    a380 = load_a380_order()
    if implementation["model_definitions"] != a375["model_definitions"]:
        raise RuntimeError("A382 frozen model definitions differ")
    measurements = load_measurements(a380)
    rank_fields: dict[str, dict[int, list[int]]] = {role: {} for role in MODEL_ROLES}
    within_orders: dict[str, dict[int, list[int]]] = {role: {} for role in MODEL_ROLES}
    for low4 in SLICES:
        matrix = A376.A375.A360.target_normalize(  # noqa: SLF001
            A376.A375.A275._target_feature_matrix(measurements[low4])  # noqa: SLF001
        )
        feature_fields = A376.slice_feature_rank_fields(matrix)
        for role in MODEL_ROLES:
            ranks = A376.aggregate_slice_rank_field(feature_fields, a375["model_definitions"][role])
            rank_fields[role][low4] = [int(value) for value in ranks]
            within_orders[role][low4] = A376.within_order(ranks)
    wide_orders = {
        role: A376.A361.compose_round_robin(within_orders[role]) for role in MODEL_ROLES
    }
    source_orders = {
        "A379_target_free": exact_order(
            A380.A379.load_order()["selected_order"], "A379 target-free"
        ),
        "A380_target_conditioned": exact_order(
            a380["target_conditioned_order"], "A380 target-conditioned"
        ),
        **wide_orders,
    }
    selected = factor_k_wavefront(source_orders, SOURCE_ROLES)
    proof = factor_k_proof(source_orders, SOURCE_ROLES, selected)
    diversity = pairwise_diversity(source_orders)
    source_summary = {
        role: {
            "selected_order_uint16be_sha256": order_sha256(source_orders[role]),
            "first_16_groups": source_orders[role][:16],
            "model_name": (
                a375["model_definitions"][role]["name"] if role in MODEL_ROLES else role
            ),
            "member_feature_count": (
                len(a375["model_definitions"][role]["member_feature_indices"])
                if role in MODEL_ROLES
                else None
            ),
        }
        for role in SOURCE_ROLES
    }
    pairwise_summary = {
        key: {
            "spearman_rank_correlation": value["spearman_rank_correlation"],
            "top32_overlap": value["top_k_overlap"]["32"]["intersection"],
        }
        for key, value in diversity.items()
    }
    essential = {
        "A375_selection_commitment_sha256": a375["selection_commitment_sha256"],
        "A380_measurement_sha256": a380["measurement_sha256"],
        "source_role_order": list(SOURCE_ROLES),
        "source_orders_sha256": canonical_sha256(source_orders),
        "selected_order_uint16be_sha256": order_sha256(selected),
        "pointwise_factor6_proof": proof,
        "reader_refits": 0,
        "target_labels_used": 0,
        "candidate_assignments_executed": 0,
    }
    payload: dict[str, Any] = {
        "schema": "chacha20-round20-w49-crosswidth-wide-consensus-factor6-a382-order-v1",
        "attempt_id": ATTEMPT_ID,
        "evidence_stage": "PRE_RECOVERY_CROSSWIDTH_W49_SIX_VIEW_FACTOR6_ORDER_FROZEN",
        "design_sha256": DESIGN_SHA256,
        "implementation_sha256": expected_implementation_sha256,
        "implementation_commitment_sha256": implementation[
            "implementation_commitment_sha256"
        ],
        **essential,
        "model_role_order": list(MODEL_ROLES),
        "model_definitions": a375["model_definitions"],
        "within_slice_rank_fields": rank_fields,
        "within_slice_rank_fields_sha256": canonical_sha256(rank_fields),
        "within_slice_orders": within_orders,
        "within_slice_orders_sha256": canonical_sha256(within_orders),
        "source_orders": source_orders,
        "source_order_summary": source_summary,
        "selected_order": selected,
        "pairwise_diversity": diversity,
        "pairwise_diversity_summary": pairwise_summary,
        "reader_transfer_summary": {
            "source_width": 46,
            "target_width": 49,
            "complete_low4_slices": len(SLICES),
            "complete_direct12_cells": CELLS,
            "features_per_cell": FEATURES,
            "fixed_models": len(MODEL_ROLES),
            "reader_refits": 0,
            "target_labels_used": 0,
        },
        "information_boundary": {
            "A375_models_frozen_before_A380_W49_scoring": True,
            "A382_implementation_frozen_before_A380_W49_scoring": True,
            "A381_result_or_true_prefix_used": False,
            "A382_candidate_or_prefix_available_at_order_freeze": False,
            "A382_candidate_assignments_executed_at_order_freeze": 0,
            "A383_candidate_assignments_executed_at_order_freeze": 0,
        },
        "anchors": {
            "design": anchor(DESIGN, DESIGN_SHA256),
            "implementation": anchor(IMPLEMENTATION, expected_implementation_sha256),
            "A375_result": anchor(A375_RESULT, A375_RESULT_SHA256),
            "A376_runner": anchor(A376_RUNNER, A376_RUNNER_SHA256),
            "A379_order": anchor(A379_ORDER, A379_ORDER_SHA256),
            "A379_protocol": anchor(A379_PROTOCOL, A379_PROTOCOL_SHA256),
            "A380_order": anchor(A380_ORDER, A380_ORDER_SHA256),
            "A380_causal": anchor(A380_CAUSAL, A380_CAUSAL_SHA256),
            "runner": anchor(Path(__file__)),
            "test": anchor(TEST),
            "reproducer": anchor(REPRO),
        },
    }
    payload["order_commitment_sha256"] = canonical_sha256(essential)
    payload["causal"] = build_causal(payload)
    atomic_json(ORDER, payload)
    atomic_bytes(
        REPORT,
        (
            "# A382 — cross-width wide-consensus W49 factor-six order\n\n"
            f"Evidence stage: **{payload['evidence_stage']}**\n\n"
            f"- Frozen W46 Readers transferred unchanged: **{len(MODEL_ROLES)}**\n"
            f"- Complete W49 direct12 cells: **{CELLS:,}**\n"
            f"- Combined source orders: **{len(SOURCE_ROLES)}**\n"
            f"- Exact pointwise bound: **{proof['bound']}**\n"
            f"- Maximum observed ratio: **{proof['maximum_ratio']:.9f}**\n"
            "- Target labels / Reader refits / candidates: **0 / 0 / 0**\n"
            "- Authentic AI-native Causal readback: **3 explicit + 1 inferred**\n"
        ).encode(),
    )
    return payload


def load_order(expected_sha256: str) -> dict[str, Any]:
    if file_sha256(ORDER) != expected_sha256:
        raise RuntimeError("A382 order hash differs")
    value = json.loads(ORDER.read_bytes())
    source_orders = {
        role: exact_order(order, f"stored source {role}")
        for role, order in value.get("source_orders", {}).items()
    }
    selected = exact_order(value.get("selected_order", []), "stored selected")
    if (
        value.get("schema")
        != "chacha20-round20-w49-crosswidth-wide-consensus-factor6-a382-order-v1"
        or tuple(value.get("source_role_order", [])) != SOURCE_ROLES
        or value.get("reader_refits") != 0
        or value.get("target_labels_used") != 0
        or value.get("candidate_assignments_executed") != 0
        or value.get("source_orders_sha256") != canonical_sha256(source_orders)
        or selected != factor_k_wavefront(source_orders, SOURCE_ROLES)
        or value.get("pointwise_factor6_proof")
        != factor_k_proof(source_orders, SOURCE_ROLES, selected)
        or value.get("selected_order_uint16be_sha256") != order_sha256(selected)
        or value.get("information_boundary", {}).get(
            "A382_candidate_or_prefix_available_at_order_freeze"
        )
        is not False
    ):
        raise RuntimeError("A382 frozen order semantics differ")
    for row in value["anchors"].values():
        anchor(path_from_ref(row["path"]), row["sha256"])
    anchor(path_from_ref(value["causal"]["path"]), value["causal"]["sha256"])
    load_implementation(value["implementation_sha256"])
    return value


def analyze() -> dict[str, Any]:
    payload: dict[str, Any] = {
        "attempt_id": ATTEMPT_ID,
        "design_sha256": DESIGN_SHA256,
        "implementation_frozen": IMPLEMENTATION.exists(),
        "order_frozen": ORDER.exists(),
    }
    if IMPLEMENTATION.exists():
        payload["implementation_sha256"] = file_sha256(IMPLEMENTATION)
    if ORDER.exists():
        payload["order_sha256"] = file_sha256(ORDER)
        value = json.loads(ORDER.read_bytes())
        payload["evidence_stage"] = value["evidence_stage"]
        payload["selected_order_uint16be_sha256"] = value[
            "selected_order_uint16be_sha256"
        ]
    return payload


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    action = parser.add_mutually_exclusive_group(required=True)
    action.add_argument("--analyze", action="store_true")
    action.add_argument("--freeze-implementation", action="store_true")
    action.add_argument("--freeze-order", action="store_true")
    parser.add_argument("--expected-implementation-sha256")
    args = parser.parse_args()
    if args.freeze_implementation:
        payload = freeze_implementation()
    elif args.freeze_order:
        if not args.expected_implementation_sha256:
            parser.error("--freeze-order requires --expected-implementation-sha256")
        payload = freeze_order(expected_implementation_sha256=args.expected_implementation_sha256)
    else:
        payload = analyze()
    print(json.dumps(payload, indent=2, sort_keys=True), flush=True)


if __name__ == "__main__":
    main()

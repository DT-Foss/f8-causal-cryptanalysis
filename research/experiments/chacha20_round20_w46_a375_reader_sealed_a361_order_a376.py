#!/usr/bin/env python3
"""A376: deploy the frozen A375 wide Reader portfolio on sealed A361."""

from __future__ import annotations

import argparse
import hashlib
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

DESIGN = CONFIGS / "chacha20_round20_w46_a375_reader_sealed_a361_order_a376_design_v1.json"
IMPLEMENTATION = (
    CONFIGS / "chacha20_round20_w46_a375_reader_sealed_a361_order_a376_implementation_v1.json"
)
ORDER = RESULTS / "chacha20_round20_w46_a375_reader_sealed_a361_order_a376_v1.json"
CAUSAL = ORDER.with_suffix(".causal")
REPORT = ORDER.with_suffix(".md")
TEST = ROOT / "tests/test_chacha20_round20_w46_a375_reader_sealed_a361_order_a376.py"
REPRO = ROOT / "scripts/reproduce_chacha20_round20_w46_a375_reader_sealed_a361_order_a376.sh"

A375_RUNNER = RESEARCH / "experiments/chacha20_round20_w46_wide_consensus_reader_a375.py"
A375_RESULT = RESULTS / "chacha20_round20_w46_wide_consensus_reader_a375_v1.json"
A375_IMPLEMENTATION = (
    CONFIGS / "chacha20_round20_w46_wide_consensus_reader_a375_implementation_v1.json"
)
A361_RUNNER = RESEARCH / "experiments/chacha20_round20_w46_fresh_a360_reader_deployment_a361.py"
A361_PROTOCOL = CONFIGS / "chacha20_round20_w46_fresh_a360_reader_deployment_a361_protocol_v1.json"
A361_PREFLIGHT = RESULTS / "chacha20_round20_w46_fresh_a360_reader_deployment_a361_preflight_v1.json"
A361_MEASUREMENT = RESULTS / "chacha20_round20_w46_fresh_a360_reader_deployment_a361_measurement_v1.json"
A377_RESULT = RESULTS / "chacha20_round20_w46_a376_order_recovery_a377_v1.json"

ATTEMPT_ID = "A376"
DESIGN_SHA256 = "d382730a341bc46e5de68cb3b6d4fc0d7c1e21df4be7732f3dc95bca9bc9cffb"
A375_RESULT_SHA256 = "fc7135af9e001eb8cd83a55902e48f5776dc24a4eb86a162d7d783a115b38ef1"
A375_IMPLEMENTATION_SHA256 = "72a96c7231659587652a538d4c27e52d2e79e8a13a3055c20de6779964db2326"
A375_RUNNER_SHA256 = "e41a91b225b861abd669280a4044dddf5e2b24e8f6e8c66e7eee6d5a149ec9f1"
A361_RUNNER_SHA256 = "0c287c1f4e037e1fdb3d87455a43471023600556d14f6cc5bfe0ef36022f38f7"
A361_PROTOCOL_SHA256 = "3396559ab6fde25ef12f5fdcae68e33585234926885b88b136c1f4af47c13228"
A361_PREFLIGHT_SHA256 = "9158edea44ff3884d60308517a7ede1df6b0c0faff2732d520ab61efa88d3d0a"
A361_MEASUREMENT_SHA256 = "a074afc4da9ab4476acf1f09dd752fdc9937486f4a458d8594ef7815046c89dc"
A361_MEASUREMENT_COMMITMENT_SHA256 = (
    "9fc46a4e78b849f3e0d64b5dc591431e531682563907f78d0b80caa12e500b55"
)

MODEL_ROLES = ("wide_vote", "sparse_reciprocal", "broad_quantile", "broad_intersection")
SLICES = tuple(range(16))
WITHIN_CELLS = 256
FEATURES = 532
GROUPS = 4096
DOTCAUSAL_SRC = Path("/Users/bhkmie/Documents/Forschung/O1/vendor/fabel/dotcausal_package/src")


def load_module(path: Path, name: str) -> Any:
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot import A376 dependency {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


A375 = load_module(A375_RUNNER, "a376_a375")
A361 = load_module(A361_RUNNER, "a376_a361")
file_sha256 = A375.file_sha256
canonical_sha256 = A375.canonical_sha256
atomic_json = A375.atomic_json
atomic_bytes = A375.atomic_bytes
relative = A375.relative
path_from_ref = A375.path_from_ref
anchor = A375.anchor


def assert_pre_order() -> None:
    if ORDER.exists() or A377_RESULT.exists():
        raise RuntimeError("A376 implementation must precede every A376 order and A377 recovery")


def load_design() -> dict[str, Any]:
    if file_sha256(DESIGN) != DESIGN_SHA256:
        raise RuntimeError("A376 design hash differs")
    value = json.loads(DESIGN.read_bytes())
    reader = value.get("reader_contract", {})
    sealed = value.get("sealed_measurement_contract", {})
    order = value.get("order_contract", {})
    boundary = value.get("information_boundary", {})
    if (
        value.get("schema")
        != "chacha20-round20-w46-a375-reader-sealed-a361-order-a376-design-v1"
        or value.get("attempt_id") != ATTEMPT_ID
        or value.get("design_state")
        != "frozen_after_A375_selection_before_any_A361_compressed_shard_content_read_A376_order_candidate_or_prefix"
        or tuple(reader.get("model_roles", [])) != MODEL_ROLES
        or reader.get("model_count") != len(MODEL_ROLES)
        or reader.get("all_models_positive_in_every_fixed_calibration_block") is not True
        or reader.get("reader_refits_on_A361") != 0
        or sealed.get("A361_measurement_sha256") != A361_MEASUREMENT_SHA256
        or sealed.get("A361_measurement_commitment_sha256")
        != A361_MEASUREMENT_COMMITMENT_SHA256
        or sealed.get("complete_low4_slices") != len(SLICES)
        or sealed.get("complete_direct12_cells") != GROUPS
        or sealed.get("compressed_shard_content_read_before_A376_implementation_freeze")
        is not False
        or order.get("pointwise_bound_checked_cells") != GROUPS
        or order.get("candidate_or_prefix_available_at_order_freeze") is not False
        or order.get("candidate_assignments_executed") != 0
        or boundary.get("A375_selection_available_at_design_freeze") is not True
        or boundary.get("A361_compressed_measurement_shard_content_opened_at_design_freeze")
        is not False
        or boundary.get("A361_secret_or_true_prefix_available_to_A376") is not False
        or boundary.get("A376_candidate_or_prefix_available_at_design_freeze") is not False
    ):
        raise RuntimeError("A376 frozen design semantics differ")
    for name, path_value in value["source_anchors"].items():
        if name.endswith("_path"):
            stem = name.removesuffix("_path")
            anchor(ROOT / path_value, value["source_anchors"][f"{stem}_sha256"])
    return value


def load_a375_result(expected_sha256: str) -> dict[str, Any]:
    if file_sha256(A375_RESULT) != expected_sha256:
        raise RuntimeError("A376 A375 result hash differs")
    value = json.loads(A375_RESULT.read_bytes())
    definitions = value.get("model_definitions", {})
    evaluations = value.get("model_evaluations", {})
    if (
        value.get("schema") != "chacha20-round20-w46-wide-consensus-reader-a375-v1"
        or value.get("attempt_id") != "A375"
        or set(definitions) != set(MODEL_ROLES)
        or set(evaluations) != set(MODEL_ROLES)
        or any(evaluations[role].get("positive_fixed_block_count") != 8 for role in MODEL_ROLES)
        or any(evaluations[role].get("minimum_fixed_block_bit_gain", 0.0) <= 0.0 for role in MODEL_ROLES)
        or value.get("candidate_assignments_executed") != 0
        or value.get("information_boundary", {}).get(
            "A361_compressed_measurement_shard_content_opened_at_result_freeze"
        )
        is not False
    ):
        raise RuntimeError("A376 frozen A375 portfolio differs")
    anchor(path_from_ref(value["causal"]["path"]), value["causal"]["sha256"])
    return value


def freeze_implementation() -> dict[str, Any]:
    if IMPLEMENTATION.exists():
        raise FileExistsError("A376 implementation already exists")
    if any(path.exists() for path in (ORDER, CAUSAL, REPORT)):
        raise RuntimeError("A376 implementation must precede its order")
    design = load_design()
    a375 = load_a375_result(A375_RESULT_SHA256)
    if not TEST.exists() or not REPRO.exists():
        raise FileNotFoundError("A376 test and reproducer must exist before freeze")
    payload: dict[str, Any] = {
        "schema": "chacha20-round20-w46-a375-reader-sealed-a361-order-a376-implementation-v1",
        "attempt_id": ATTEMPT_ID,
        "commitment_state": (
            "frozen_after_A375_before_any_A361_compressed_shard_content_read_order_candidate_or_prefix"
        ),
        "design_sha256": DESIGN_SHA256,
        "A375_result_sha256": A375_RESULT_SHA256,
        "A375_selection_commitment_sha256": a375["selection_commitment_sha256"],
        "model_role_order": list(MODEL_ROLES),
        "model_definitions": a375["model_definitions"],
        "A361_measurement_sha256": A361_MEASUREMENT_SHA256,
        "A361_measurement_commitment_sha256": A361_MEASUREMENT_COMMITMENT_SHA256,
        "A361_compressed_measurement_shard_content_opened_at_implementation_freeze": False,
        "A361_secret_or_true_prefix_available_at_implementation_freeze": False,
        "candidate_or_prefix_available_at_implementation_freeze": False,
        "candidate_assignments_executed_at_implementation_freeze": 0,
        "anchors": {
            "design": anchor(DESIGN, DESIGN_SHA256),
            "A375_result": anchor(A375_RESULT, A375_RESULT_SHA256),
            "A375_implementation": anchor(A375_IMPLEMENTATION, A375_IMPLEMENTATION_SHA256),
            "A375_runner": anchor(A375_RUNNER, A375_RUNNER_SHA256),
            "A361_protocol": anchor(A361_PROTOCOL, A361_PROTOCOL_SHA256),
            "A361_preflight": anchor(A361_PREFLIGHT, A361_PREFLIGHT_SHA256),
            "A361_measurement": anchor(A361_MEASUREMENT, A361_MEASUREMENT_SHA256),
            "A361_runner": anchor(A361_RUNNER, A361_RUNNER_SHA256),
            "runner": anchor(Path(__file__)),
            "test": anchor(TEST),
            "reproducer": anchor(REPRO),
        },
        "order_contract": design["order_contract"],
    }
    payload["implementation_commitment_sha256"] = canonical_sha256(payload)
    atomic_json(IMPLEMENTATION, payload)
    assert_pre_order()
    return payload


def load_implementation(expected_sha256: str) -> dict[str, Any]:
    if file_sha256(IMPLEMENTATION) != expected_sha256:
        raise RuntimeError("A376 implementation hash differs")
    value = json.loads(IMPLEMENTATION.read_bytes())
    if (
        value.get("schema")
        != "chacha20-round20-w46-a375-reader-sealed-a361-order-a376-implementation-v1"
        or value.get("attempt_id") != ATTEMPT_ID
        or value.get("commitment_state")
        != "frozen_after_A375_before_any_A361_compressed_shard_content_read_order_candidate_or_prefix"
        or value.get("design_sha256") != DESIGN_SHA256
        or value.get("A375_result_sha256") != A375_RESULT_SHA256
        or tuple(value.get("model_role_order", [])) != MODEL_ROLES
        or value.get("A361_measurement_sha256") != A361_MEASUREMENT_SHA256
        or value.get("A361_compressed_measurement_shard_content_opened_at_implementation_freeze")
        is not False
        or value.get("A361_secret_or_true_prefix_available_at_implementation_freeze") is not False
        or value.get("candidate_or_prefix_available_at_implementation_freeze") is not False
        or value.get("candidate_assignments_executed_at_implementation_freeze") != 0
    ):
        raise RuntimeError("A376 implementation semantics differ")
    expected = {
        "design": DESIGN,
        "A375_result": A375_RESULT,
        "A375_implementation": A375_IMPLEMENTATION,
        "A375_runner": A375_RUNNER,
        "A361_protocol": A361_PROTOCOL,
        "A361_preflight": A361_PREFLIGHT,
        "A361_measurement": A361_MEASUREMENT,
        "A361_runner": A361_RUNNER,
        "runner": Path(__file__),
        "test": TEST,
        "reproducer": REPRO,
    }
    for name, path in expected.items():
        row = value["anchors"][name]
        if row.get("path") != relative(path) or row.get("sha256") != file_sha256(path):
            raise RuntimeError(f"A376 implementation anchor differs: {name}")
    unsigned = {key: item for key, item in value.items() if key != "implementation_commitment_sha256"}
    if value.get("implementation_commitment_sha256") != canonical_sha256(unsigned):
        raise RuntimeError("A376 implementation commitment differs")
    return value


def exact_order(values: Sequence[int], label: str) -> list[int]:
    order = [int(value) for value in values]
    if len(order) != GROUPS or set(order) != set(range(GROUPS)):
        raise ValueError(f"A376 {label} is not an exact 4,096-cell order")
    return order


def order_sha256(values: Sequence[int]) -> str:
    raw = b"".join(value.to_bytes(2, "big") for value in exact_order(values, "hash"))
    return hashlib.sha256(raw).hexdigest()


def rank_vector(order: Sequence[int]) -> list[int]:
    ranks = [0] * GROUPS
    for rank, cell in enumerate(exact_order(order, "rank vector"), 1):
        ranks[cell] = rank
    return ranks


def factor_k_wavefront(
    source_orders: Mapping[str, Sequence[int]], role_order: Sequence[str]
) -> list[int]:
    roles = [str(role) for role in role_order]
    if not roles or set(roles) != set(source_orders) or len(roles) != len(set(roles)):
        raise ValueError("A376 source-role cover differs")
    ranks = {role: rank_vector(source_orders[role]) for role in roles}
    return exact_order(
        sorted(
            range(GROUPS),
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
    roles = [str(role) for role in role_order]
    source_ranks = {role: rank_vector(source_orders[role]) for role in roles}
    portfolio_ranks = rank_vector(portfolio)
    k = len(roles)
    ratios = [
        portfolio_ranks[cell] / min(source_ranks[role][cell] for role in roles)
        for cell in range(GROUPS)
    ]
    violations = [cell for cell, ratio in enumerate(ratios) if ratio > k + 1e-15]
    if violations:
        raise RuntimeError("A376 factor-k pointwise proof failed")
    return {
        "bound": f"R_A376(c) <= {k}*min_frozen_A375_reader_rank(c)",
        "reader_count": k,
        "cells_checked": GROUPS,
        "maximum_ratio": max(ratios),
        "mean_ratio": float(np.mean(ratios)),
        "violations": 0,
    }


def slice_feature_rank_fields(matrix: np.ndarray) -> np.ndarray:
    values = np.asarray(matrix, dtype=np.float64)
    if values.shape != (WITHIN_CELLS, FEATURES) or not np.isfinite(values).all():
        raise ValueError("A376 normalized slice matrix differs")
    cells = np.arange(WITHIN_CELLS, dtype=np.int16)
    exact = np.arange(1, WITHIN_CELLS + 1, dtype=np.int16)
    result = np.empty((FEATURES, WITHIN_CELLS), dtype=np.int16)
    for feature in range(FEATURES):
        order = np.lexsort((cells, -np.abs(values[:, feature])))
        result[feature, order] = exact
    return result


def aggregate_slice_rank_field(
    feature_fields: np.ndarray, definition: Mapping[str, Any]
) -> np.ndarray:
    fields = np.asarray(feature_fields, dtype=np.int16)
    members = np.asarray(definition["member_feature_indices"], dtype=np.int64)
    if (
        fields.shape != (FEATURES, WITHIN_CELLS)
        or not len(members)
        or np.any(members < 0)
        or np.any(members >= FEATURES)
        or len(set(members.tolist())) != len(members)
    ):
        raise ValueError("A376 frozen model geometry differs")
    selected = fields[members].astype(np.float64)
    mean_rank = selected.mean(axis=0)
    aggregator = str(definition["aggregator"])
    if aggregator == "maximum_member_rank":
        primary = selected.max(axis=0)
        descending = False
    elif aggregator == "member_rank_quantile_0.75":
        primary = np.quantile(selected, 0.75, axis=0, method="linear")
        descending = False
    elif aggregator == "reciprocal_rank_sum":
        primary = (1.0 / selected).sum(axis=0)
        descending = True
    elif aggregator == "top64_vote_then_mean_rank":
        primary = (selected <= 64).sum(axis=0).astype(np.float64)
        descending = True
    else:
        raise ValueError(f"A376 unknown frozen aggregator {aggregator}")
    cells = np.arange(WITHIN_CELLS, dtype=np.int16)
    signed = -primary if descending else primary
    order = np.lexsort((cells, mean_rank, signed))
    result = np.empty(WITHIN_CELLS, dtype=np.int16)
    result[order] = np.arange(1, WITHIN_CELLS + 1, dtype=np.int16)
    return result


def within_order(ranks: Sequence[int]) -> list[int]:
    values = [int(value) for value in ranks]
    if len(values) != WITHIN_CELLS or set(values) != set(range(1, WITHIN_CELLS + 1)):
        raise ValueError("A376 within-slice rank field differs")
    return sorted(range(WITHIN_CELLS), key=lambda cell: (values[cell], cell))


def build_causal(payload: Mapping[str, Any]) -> dict[str, Any]:
    sys.path.insert(0, str(DOTCAUSAL_SRC))
    from dotcausal.io import CausalReader, CausalWriter

    portfolio = "A375:frozen_four_reader_portfolio"
    sealed = "A361:complete_sealed_unlabeled_direct12_field"
    sources = "A376:four_refit_free_source_orders"
    order = "A376:exact_factor4_4096_group_order"
    recovery = "A377:frozen_order_recovery_ready"
    writer = CausalWriter(api_id="a376ord")
    writer._rules = []
    for name, pattern, conclusion in (
        ("portfolio_unlocks_sealed_read", [portfolio], sealed),
        ("sealed_field_to_source_orders", [sealed], sources),
        ("source_orders_to_factor4", [sources], order),
        ("factor4_to_recovery", [order], recovery),
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
            "unlock_only_after_A375_selection_and_A376_implementation_freeze",
            sealed,
            payload["A375_selection_commitment_sha256"],
            payload["information_boundary"],
        ),
        (
            sealed,
            "apply_all_four_frozen_A375_readers_without_refit",
            sources,
            payload["source_orders_sha256"],
            payload["source_order_summary"],
        ),
        (
            sources,
            "stable_min_source_rank_wavefront_with_exact_pointwise_factor4_proof",
            order,
            payload["order_commitment_sha256"],
            payload["pointwise_factor4_proof"],
        ),
        (
            order,
            "freeze_before_candidate_prefix_or_assignment_execution",
            recovery,
            payload["order_commitment_sha256"],
            payload["order_summary"],
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
            domain="ChaCha20 R20 W46 wide-consensus sealed-target Reader deployment",
            quality_score=1.0,
        )
    writer.add_triplet(
        trigger=portfolio,
        mechanism="materialized_portfolio_sealed_field_factor4_recovery_ready_chain",
        outcome=recovery,
        confidence=1.0,
        source="materialized:A376_order_chain",
        quantification="exact retained closure",
        evidence=payload["evidence_stage"],
        domain="AI-native retained inference",
        quality_score=1.0,
        is_inferred=True,
    )
    writer.add_cluster(
        name="A376 sealed A361 wide-consensus order",
        entities=[portfolio, sealed, sources, order, recovery],
    )
    writer.add_gap(
        subject=recovery,
        predicate="next_required_object",
        expected_object_type="A377_complete_group_recovery_with_matched_control",
        confidence=1.0,
        suggested_queries=[
            "Execute the exact A376 order from rank one with the qualified complete W46 engine and independently confirm any sole factual model."
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
        reader.api_id != "a376ord"
        or len(explicit) != 4
        or len(all_rows) != 5
        or len(inferred) != 1
        or len(reader._rules) != 4
        or len(reader._clusters) != 1
        or len(reader._gaps) != 1
    ):
        raise RuntimeError("A376 authentic Causal reopen gate failed")
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


def freeze_order(
    *, expected_implementation_sha256: str, expected_a375_result_sha256: str
) -> dict[str, Any]:
    if any(path.exists() for path in (ORDER, CAUSAL, REPORT)):
        raise FileExistsError("A376 order already exists")
    implementation = load_implementation(expected_implementation_sha256)
    a375 = load_a375_result(expected_a375_result_sha256)
    if a375["model_definitions"] != implementation["model_definitions"]:
        raise RuntimeError("A376 frozen model definitions differ")

    # This is the first permitted A361 compressed-shard read in the A375 branch.
    measurement = A361.load_measurement(
        A361_MEASUREMENT_SHA256,
        expected_protocol_sha256=A361_PROTOCOL_SHA256,
    )
    if (
        measurement["measurement_commitment_sha256"]
        != A361_MEASUREMENT_COMMITMENT_SHA256
        or measurement["measurement_summary"].get("reader_scoring_eligible") is not True
    ):
        raise RuntimeError("A376 sealed A361 measurement differs")
    measurements = A361._measurement_map(  # noqa: SLF001
        measurement,
        protocol_sha256=A361_PROTOCOL_SHA256,
    )

    rank_fields: dict[str, dict[int, list[int]]] = {role: {} for role in MODEL_ROLES}
    within_orders: dict[str, dict[int, list[int]]] = {role: {} for role in MODEL_ROLES}
    for low4 in SLICES:
        matrix = A375.A360.target_normalize(  # noqa: SLF001
            A375.A275._target_feature_matrix(measurements[low4])
        )
        feature_fields = slice_feature_rank_fields(matrix)
        for role in MODEL_ROLES:
            ranks = aggregate_slice_rank_field(feature_fields, a375["model_definitions"][role])
            rank_fields[role][low4] = [int(value) for value in ranks]
            within_orders[role][low4] = within_order(ranks)

    source_orders = {
        role: A361.compose_round_robin(within_orders[role]) for role in MODEL_ROLES
    }
    selected_order = factor_k_wavefront(source_orders, MODEL_ROLES)
    proof = factor_k_proof(source_orders, MODEL_ROLES, selected_order)
    selected_hash = order_sha256(selected_order)
    source_summary = {
        role: {
            "name": a375["model_definitions"][role]["name"],
            "aggregator": a375["model_definitions"][role]["aggregator"],
            "member_feature_count": len(
                a375["model_definitions"][role]["member_feature_indices"]
            ),
            "selected_order_uint16be_sha256": order_sha256(source_orders[role]),
            "first_16_groups": source_orders[role][:16],
        }
        for role in MODEL_ROLES
    }
    payload: dict[str, Any] = {
        "schema": "chacha20-round20-w46-a375-reader-sealed-a361-order-a376-v1",
        "attempt_id": ATTEMPT_ID,
        "evidence_stage": "A375_WIDE_CONSENSUS_SEALED_A361_EXACT_FACTOR4_ORDER_FROZEN",
        "design_sha256": DESIGN_SHA256,
        "implementation_sha256": expected_implementation_sha256,
        "implementation_commitment_sha256": implementation[
            "implementation_commitment_sha256"
        ],
        "A375_result_sha256": expected_a375_result_sha256,
        "A375_selection_commitment_sha256": a375["selection_commitment_sha256"],
        "A375_model_evaluations": a375["model_evaluations"],
        "model_role_order": list(MODEL_ROLES),
        "model_definitions": a375["model_definitions"],
        "A361_protocol_sha256": A361_PROTOCOL_SHA256,
        "A361_measurement_sha256": A361_MEASUREMENT_SHA256,
        "A361_measurement_commitment_sha256": A361_MEASUREMENT_COMMITMENT_SHA256,
        "A361_measurement_ledger_sha256": measurement["measurement_ledger_sha256"],
        "within_slice_rank_fields": rank_fields,
        "within_slice_rank_fields_sha256": canonical_sha256(rank_fields),
        "within_slice_orders": within_orders,
        "within_slice_orders_sha256": canonical_sha256(within_orders),
        "source_orders": source_orders,
        "source_orders_sha256": canonical_sha256(source_orders),
        "source_order_summary": source_summary,
        "selected_order": selected_order,
        "selected_order_uint16be_sha256": selected_hash,
        "pointwise_factor4_proof": proof,
        "order_summary": {
            "groups": GROUPS,
            "reader_count": len(MODEL_ROLES),
            "first_32_groups": selected_order[:32],
            "last_32_groups": selected_order[-32:],
            "selected_order_uint16be_sha256": selected_hash,
            "candidate_or_prefix_available_at_order_freeze": False,
            "candidate_assignments_executed": 0,
        },
        "A361_shard_content_read_only_after_A376_implementation_freeze": True,
        "reader_refits": 0,
        "candidate_or_prefix_available_at_order_freeze": False,
        "candidate_assignments_executed": 0,
        "information_boundary": {
            "A375_selection_frozen_before_A361_shard_read": True,
            "A376_implementation_frozen_before_A361_shard_read": True,
            "A361_target_labels_used": 0,
            "A361_secret_or_true_prefix_available_to_A376": False,
            "A376_reader_refits": 0,
            "A376_candidate_or_prefix_available_at_order_freeze": False,
            "A376_candidate_assignments_executed_at_order_freeze": 0,
        },
        "anchors": {
            "design": anchor(DESIGN, DESIGN_SHA256),
            "implementation": anchor(IMPLEMENTATION, expected_implementation_sha256),
            "A375_result": anchor(A375_RESULT, expected_a375_result_sha256),
            "A375_implementation": anchor(A375_IMPLEMENTATION, A375_IMPLEMENTATION_SHA256),
            "A361_protocol": anchor(A361_PROTOCOL, A361_PROTOCOL_SHA256),
            "A361_preflight": anchor(A361_PREFLIGHT, A361_PREFLIGHT_SHA256),
            "A361_measurement": anchor(A361_MEASUREMENT, A361_MEASUREMENT_SHA256),
            "runner": anchor(Path(__file__)),
            "test": anchor(TEST),
            "reproducer": anchor(REPRO),
        },
    }
    payload["order_commitment_sha256"] = canonical_sha256(
        {
            "implementation_commitment_sha256": payload[
                "implementation_commitment_sha256"
            ],
            "A375_selection_commitment_sha256": payload[
                "A375_selection_commitment_sha256"
            ],
            "A361_measurement_commitment_sha256": A361_MEASUREMENT_COMMITMENT_SHA256,
            "model_role_order": list(MODEL_ROLES),
            "source_orders_sha256": payload["source_orders_sha256"],
            "selected_order_uint16be_sha256": selected_hash,
            "pointwise_factor4_proof": proof,
            "candidate_or_prefix_available_at_order_freeze": False,
            "candidate_assignments_executed": 0,
        }
    )
    payload["causal"] = build_causal(payload)
    atomic_json(ORDER, payload)
    atomic_bytes(
        REPORT,
        (
            "# A376 — sealed A361 wide-consensus factor-four order\n\n"
            f"Evidence stage: **{payload['evidence_stage']}**\n\n"
            f"- Frozen Readers: **{list(MODEL_ROLES)}**\n"
            f"- Exact groups: **{GROUPS:,}**\n"
            f"- Pointwise bound: **{proof['bound']}**\n"
            f"- Maximum proof ratio: **{proof['maximum_ratio']}**\n"
            f"- Order SHA-256: **{selected_hash}**\n"
            "- Reader refits / candidate executions: **0 / 0**\n"
            "- Secret or true prefix available: **False**\n"
            "- Authentic AI-native Causal readback: **4 explicit + 1 inferred**\n"
        ).encode(),
    )
    return payload


def load_order(expected_sha256: str) -> dict[str, Any]:
    if file_sha256(ORDER) != expected_sha256:
        raise RuntimeError("A376 order hash differs")
    value = json.loads(ORDER.read_bytes())
    roles = tuple(value.get("model_role_order", []))
    source_orders = {
        role: exact_order(order, f"source {role}")
        for role, order in value.get("source_orders", {}).items()
    }
    selected = exact_order(value.get("selected_order", []), "selected")
    if (
        value.get("schema") != "chacha20-round20-w46-a375-reader-sealed-a361-order-a376-v1"
        or value.get("attempt_id") != ATTEMPT_ID
        or roles != MODEL_ROLES
        or set(source_orders) != set(MODEL_ROLES)
        or value.get("reader_refits") != 0
        or selected != factor_k_wavefront(source_orders, MODEL_ROLES)
        or value.get("pointwise_factor4_proof")
        != factor_k_proof(source_orders, MODEL_ROLES, selected)
        or value.get("selected_order_uint16be_sha256") != order_sha256(selected)
        or value.get("source_orders_sha256") != canonical_sha256(source_orders)
        or value.get("A361_shard_content_read_only_after_A376_implementation_freeze")
        is not True
        or value.get("candidate_or_prefix_available_at_order_freeze") is not False
        or value.get("candidate_assignments_executed") != 0
    ):
        raise RuntimeError("A376 frozen order semantics differ")
    for artifact in value["anchors"].values():
        anchor(path_from_ref(artifact["path"]), artifact["sha256"])
    anchor(path_from_ref(value["causal"]["path"]), value["causal"]["sha256"])
    return value


def analyze() -> dict[str, Any]:
    payload = {
        "attempt_id": ATTEMPT_ID,
        "design_sha256": DESIGN_SHA256,
        "implementation_frozen": IMPLEMENTATION.exists(),
        "order_frozen": ORDER.exists(),
        "A377_result_available": A377_RESULT.exists(),
    }
    if IMPLEMENTATION.exists():
        payload["implementation_sha256"] = file_sha256(IMPLEMENTATION)
    if ORDER.exists():
        value = json.loads(ORDER.read_bytes())
        payload["order_sha256"] = file_sha256(ORDER)
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
    parser.add_argument("--expected-a375-result-sha256")
    args = parser.parse_args()
    if args.freeze_implementation:
        payload = freeze_implementation()
    elif args.freeze_order:
        if not args.expected_implementation_sha256 or not args.expected_a375_result_sha256:
            parser.error(
                "--freeze-order requires --expected-implementation-sha256 and --expected-a375-result-sha256"
            )
        payload = freeze_order(
            expected_implementation_sha256=args.expected_implementation_sha256,
            expected_a375_result_sha256=args.expected_a375_result_sha256,
        )
    else:
        payload = analyze()
    print(json.dumps(payload, indent=2, sort_keys=True), flush=True)


if __name__ == "__main__":
    main()

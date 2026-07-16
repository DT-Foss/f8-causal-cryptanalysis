#!/usr/bin/env python3
"""A368: conditionally freeze the validated A367 Reader portfolio on sealed A361."""

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

DESIGN = CONFIGS / "chacha20_round20_w46_a367_reader_portfolio_sealed_a361_order_a368_design_v1.json"
IMPLEMENTATION = (
    CONFIGS
    / "chacha20_round20_w46_a367_reader_portfolio_sealed_a361_order_a368_implementation_v1.json"
)
ORDER = RESULTS / "chacha20_round20_w46_a367_reader_portfolio_sealed_a361_order_a368_v1.json"
CAUSAL = ORDER.with_suffix(".causal")
REPORT = ORDER.with_suffix(".md")
TEST = ROOT / "tests/test_chacha20_round20_w46_a367_reader_portfolio_sealed_a361_order_a368.py"
REPRO = ROOT / "scripts/reproduce_chacha20_round20_w46_a367_reader_portfolio_sealed_a361_order_a368.sh"

A361_RUNNER = RESEARCH / "experiments/chacha20_round20_w46_fresh_a360_reader_deployment_a361.py"
A366_RUNNER = RESEARCH / "experiments/chacha20_round20_w46_cross_corpus_invariant_reader_a366.py"
A367_RUNNER = (
    RESEARCH / "experiments/chacha20_round20_w46_cross_corpus_invariant_validation_a367.py"
)
A361_PROTOCOL = CONFIGS / "chacha20_round20_w46_fresh_a360_reader_deployment_a361_protocol_v1.json"
A361_PREFLIGHT = RESULTS / "chacha20_round20_w46_fresh_a360_reader_deployment_a361_preflight_v1.json"
A361_MEASUREMENT = RESULTS / "chacha20_round20_w46_fresh_a360_reader_deployment_a361_measurement_v1.json"
A366_RESULT = RESULTS / "chacha20_round20_w46_cross_corpus_invariant_reader_a366_v1.json"

ATTEMPT_ID = "A368"
DESIGN_SHA256 = "8b537866befe488e532245b8e3c0593b22cf8814b13a3515701a88dec0f376f0"
A361_PROTOCOL_SHA256 = "3396559ab6fde25ef12f5fdcae68e33585234926885b88b136c1f4af47c13228"
A361_PREFLIGHT_SHA256 = "9158edea44ff3884d60308517a7ede1df6b0c0faff2732d520ab61efa88d3d0a"
A361_MEASUREMENT_SHA256 = "a074afc4da9ab4476acf1f09dd752fdc9937486f4a458d8594ef7815046c89dc"
A361_MEASUREMENT_COMMITMENT_SHA256 = (
    "9fc46a4e78b849f3e0d64b5dc591431e531682563907f78d0b80caa12e500b55"
)
A366_RESULT_FILE_SHA256 = "0a961b742c721e9ad0b09803224422c9bb03fc272695ed90b62752f24dc169c8"
A366_SELECTION_COMMITMENT_SHA256 = (
    "b5fc9d9147cf5dc2c07f7534d57584046d58be53e98115c210c2512a2cba9faa"
)
MODEL_ROLES = ("primary", "diverse_companion", "coverage_companion", "best_single")
SLICES = tuple(range(16))
WITHIN_CELLS = 256
GROUPS = 4096
DOTCAUSAL_SRC = Path("/Users/bhkmie/Documents/Forschung/O1/vendor/fabel/dotcausal_package/src")


def load_module(path: Path, name: str) -> Any:
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot import A368 dependency {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


A361 = load_module(A361_RUNNER, "a368_a361")
A366 = load_module(A366_RUNNER, "a368_a366")
A367 = load_module(A367_RUNNER, "a368_a367")
A360 = A366.A360
A275 = A366.A275

file_sha256 = A366.file_sha256
canonical_sha256 = A366.canonical_sha256
atomic_json = A366.atomic_json
atomic_bytes = A366.atomic_bytes
relative = A366.relative
path_from_ref = A366.path_from_ref
anchor = A366.anchor


def load_design() -> dict[str, Any]:
    if file_sha256(DESIGN) != DESIGN_SHA256:
        raise RuntimeError("A368 design hash differs")
    value = json.loads(DESIGN.read_bytes())
    gate = value.get("gate_contract", {})
    reader = value.get("reader_contract", {})
    measurement = value.get("sealed_measurement_contract", {})
    order = value.get("order_contract", {})
    boundary = value.get("information_boundary", {})
    if (
        value.get("schema")
        != "chacha20-round20-w46-a367-reader-portfolio-sealed-a361-order-a368-design-v1"
        or value.get("attempt_id") != ATTEMPT_ID
        or value.get("design_state")
        != "frozen_after_A366_and_A361_measurement_before_A367_result_or_A361_shard_content_read"
        or gate.get("required_attempt") != "A367"
        or gate.get("retention_gate_passed_required") is not True
        or gate.get("minimum_retained_model_count") != 1
        or gate.get("A367_result_available_at_A368_design_freeze") is not False
        or reader.get("A366_result_file_sha256") != A366_RESULT_FILE_SHA256
        or reader.get("A366_selection_commitment_sha256")
        != A366_SELECTION_COMMITMENT_SHA256
        or tuple(reader.get("eligible_model_roles", [])) != MODEL_ROLES
        or reader.get("reader_refits") != 0
        or measurement.get("A361_measurement_sha256") != A361_MEASUREMENT_SHA256
        or measurement.get("A361_measurement_commitment_sha256")
        != A361_MEASUREMENT_COMMITMENT_SHA256
        or measurement.get("complete_low4_slices") != len(SLICES)
        or measurement.get("complete_direct12_cells") != GROUPS
        or measurement.get("compressed_shard_semantics_read_before_A367_gate") is not False
        or order.get("pointwise_bound_checked_cells") != GROUPS
        or order.get("group_count") != GROUPS
        or order.get("candidate_or_prefix_available_at_order_freeze") is not False
        or order.get("candidate_assignments_executed") != 0
        or boundary.get("A361_secret_or_true_prefix_available") is not False
        or boundary.get("A361_compressed_measurement_shard_content_opened_before_A367_gate")
        is not False
        or boundary.get("A367_result_available_at_design_freeze") is not False
        or boundary.get("order_available_at_design_freeze") is not False
    ):
        raise RuntimeError("A368 frozen design semantics differ")
    for name, path_value in value["source_anchors"].items():
        if name.endswith("_path"):
            stem = name.removesuffix("_path")
            anchor(ROOT / path_value, value["source_anchors"][f"{stem}_sha256"])
    return value


def _load_a366_result() -> dict[str, Any]:
    anchor(A366_RESULT, A366_RESULT_FILE_SHA256)
    value = json.loads(A366_RESULT.read_bytes())
    if (
        value.get("attempt_id") != "A366"
        or value.get("reader_selection", {}).get("selection_commitment_sha256")
        != A366_SELECTION_COMMITMENT_SHA256
        or tuple(sorted(value.get("reader_selection", {}).get("selected_readers", {})))
        != tuple(sorted(MODEL_ROLES))
    ):
        raise RuntimeError("A368 frozen A366 portfolio differs")
    return value


def freeze_implementation() -> dict[str, Any]:
    if IMPLEMENTATION.exists():
        raise FileExistsError("A368 implementation already exists")
    if any(path.exists() for path in (ORDER, CAUSAL, REPORT)):
        raise RuntimeError("A368 implementation must precede its order")
    if A367.RESULT.exists():
        raise RuntimeError("A368 implementation must freeze before the A367 result")
    load_design()
    a366 = _load_a366_result()
    if not TEST.exists() or not REPRO.exists():
        raise FileNotFoundError("A368 test and reproducer must exist before freeze")
    payload: dict[str, Any] = {
        "schema": "chacha20-round20-w46-a367-reader-portfolio-sealed-a361-order-a368-implementation-v1",
        "attempt_id": ATTEMPT_ID,
        "commitment_state": "frozen_before_A367_result_A361_shard_read_order_candidate_or_prefix",
        "design_sha256": DESIGN_SHA256,
        "A366_result_file_sha256": A366_RESULT_FILE_SHA256,
        "A366_selection_commitment_sha256": A366_SELECTION_COMMITMENT_SHA256,
        "eligible_model_definitions": {
            role: a366["reader_selection"]["selected_readers"][role]["definition"]
            for role in MODEL_ROLES
        },
        "A361_measurement_sha256": A361_MEASUREMENT_SHA256,
        "A361_measurement_commitment_sha256": A361_MEASUREMENT_COMMITMENT_SHA256,
        "A367_result_available_at_implementation_freeze": False,
        "A361_compressed_measurement_shard_content_opened_before_implementation_freeze": False,
        "candidate_or_prefix_available_at_implementation_freeze": False,
        "candidate_assignments_executed_at_implementation_freeze": 0,
        "anchors": {
            "design": anchor(DESIGN, DESIGN_SHA256),
            "A361_protocol": anchor(A361_PROTOCOL, A361_PROTOCOL_SHA256),
            "A361_preflight": anchor(A361_PREFLIGHT, A361_PREFLIGHT_SHA256),
            "A361_measurement": anchor(A361_MEASUREMENT, A361_MEASUREMENT_SHA256),
            "A366_result": anchor(A366_RESULT, A366_RESULT_FILE_SHA256),
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
        raise RuntimeError("A368 implementation hash differs")
    value = json.loads(IMPLEMENTATION.read_bytes())
    if (
        value.get("schema")
        != "chacha20-round20-w46-a367-reader-portfolio-sealed-a361-order-a368-implementation-v1"
        or value.get("attempt_id") != ATTEMPT_ID
        or value.get("commitment_state")
        != "frozen_before_A367_result_A361_shard_read_order_candidate_or_prefix"
        or value.get("design_sha256") != DESIGN_SHA256
        or value.get("A366_result_file_sha256") != A366_RESULT_FILE_SHA256
        or value.get("A366_selection_commitment_sha256")
        != A366_SELECTION_COMMITMENT_SHA256
        or value.get("A361_measurement_sha256") != A361_MEASUREMENT_SHA256
        or value.get("A367_result_available_at_implementation_freeze") is not False
        or value.get(
            "A361_compressed_measurement_shard_content_opened_before_implementation_freeze"
        )
        is not False
        or value.get("candidate_or_prefix_available_at_implementation_freeze") is not False
        or value.get("candidate_assignments_executed_at_implementation_freeze") != 0
    ):
        raise RuntimeError("A368 frozen implementation semantics differ")
    for name, path in {
        "design": DESIGN,
        "A361_protocol": A361_PROTOCOL,
        "A361_preflight": A361_PREFLIGHT,
        "A361_measurement": A361_MEASUREMENT,
        "A366_result": A366_RESULT,
        "runner": Path(__file__),
        "test": TEST,
        "reproducer": REPRO,
    }.items():
        row = value["anchors"][name]
        if row["path"] != relative(path) or row["sha256"] != file_sha256(path):
            raise RuntimeError(f"A368 implementation anchor differs: {name}")
    unsigned = {
        key: item for key, item in value.items() if key != "implementation_commitment_sha256"
    }
    if value["implementation_commitment_sha256"] != canonical_sha256(unsigned):
        raise RuntimeError("A368 implementation commitment differs")
    return value


def _validate_a367_gate(expected_sha256: str) -> dict[str, Any]:
    if file_sha256(A367.RESULT) != expected_sha256:
        raise RuntimeError("A368 A367 result hash differs")
    value = json.loads(A367.RESULT.read_bytes())
    retained = value.get("retention_gate", {}).get("retained_model_roles", [])
    if (
        value.get("schema")
        != "chacha20-round20-w46-cross-corpus-invariant-validation-a367-v1"
        or value.get("attempt_id") != "A367"
        or value.get("evidence_stage")
        != "PROSPECTIVE_NEW_64_TARGET_CROSS_CORPUS_READER_PORTFOLIO_RETAINED"
        or value.get("A366_result_file_sha256") != A366_RESULT_FILE_SHA256
        or value.get("A366_selection_commitment_sha256")
        != A366_SELECTION_COMMITMENT_SHA256
        or value.get("retention_gate", {}).get("passed") is not True
        or not retained
        or any(role not in MODEL_ROLES for role in retained)
        or value.get("reader_refits_after_A366_selection_freeze") != 0
    ):
        raise RuntimeError("A368 A367 retention gate did not pass")
    for artifact in value["anchors"].values():
        anchor(path_from_ref(artifact["path"]), artifact["sha256"])
    anchor(path_from_ref(value["causal"]["path"]), value["causal"]["sha256"])
    return value


def _exact_order(values: Sequence[int], label: str) -> list[int]:
    order = [int(value) for value in values]
    if len(order) != GROUPS or set(order) != set(range(GROUPS)):
        raise ValueError(f"A368 {label} is not an exact 4,096-cell order")
    return order


def order_sha256(values: Sequence[int]) -> str:
    raw = b"".join(value.to_bytes(2, "big") for value in _exact_order(values, "hash"))
    return hashlib.sha256(raw).hexdigest()


def rank_vector(order: Sequence[int]) -> list[int]:
    ranks = [0] * GROUPS
    for rank, cell in enumerate(_exact_order(order, "rank vector"), 1):
        ranks[cell] = rank
    return ranks


def factor_k_wavefront(source_orders: Mapping[str, Sequence[int]], role_order: Sequence[str]) -> list[int]:
    roles = [str(role) for role in role_order]
    if not roles or set(roles) != set(source_orders) or len(roles) != len(set(roles)):
        raise ValueError("A368 source-role cover differs")
    ranks = {role: rank_vector(source_orders[role]) for role in roles}
    return _exact_order(
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
    source_orders: Mapping[str, Sequence[int]], role_order: Sequence[str], portfolio: Sequence[int]
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
        raise RuntimeError("A368 factor-k pointwise proof failed")
    return {
        "bound": f"R_portfolio(c) <= {k}*min_retained_reader_rank(c)",
        "retained_reader_count": k,
        "cells_checked": GROUPS,
        "maximum_ratio": max(ratios),
        "mean_ratio": float(np.mean(ratios)),
        "violations": 0,
    }


def _single_primitive_fields(matrix: np.ndarray, feature_indices: Sequence[int]) -> np.ndarray:
    values = np.asarray(matrix, dtype=np.float64)
    features = [int(value) for value in feature_indices]
    if values.shape != (WITHIN_CELLS, A366.FEATURES):
        raise ValueError("A368 normalized slice matrix differs")
    cells = np.arange(WITHIN_CELLS, dtype=np.int16)
    exact_ranks = np.arange(1, WITHIN_CELLS + 1, dtype=np.int16)
    result = np.empty((len(features), WITHIN_CELLS), dtype=np.int16)
    for primitive, feature in enumerate(features):
        order = np.lexsort((cells, -np.abs(values[:, feature])))
        result[primitive, order] = exact_ranks
    return result


def _single_candidate_rank_field(
    primitive_fields: np.ndarray, definition: Mapping[str, Any]
) -> np.ndarray:
    primitives = np.asarray(primitive_fields, dtype=np.int16)
    members = tuple(int(value) for value in definition["members"])
    if primitives.ndim != 2 or primitives.shape[1] != WITHIN_CELLS:
        raise ValueError("A368 primitive rank geometry differs")
    if not members or any(not 0 <= member < primitives.shape[0] for member in members):
        raise ValueError("A368 candidate member set differs")
    if definition["kind"] == "abs_primitive":
        return primitives[members[0]].copy()
    selected = primitives[np.asarray(members, dtype=np.int64)].astype(np.int32)
    total = selected.sum(axis=0)
    cells = np.arange(WITHIN_CELLS, dtype=np.int16)
    components = tuple(selected[index] for index in range(len(members) - 1, -1, -1))
    aggregator = str(definition["aggregator"])
    if aggregator == "borda":
        keys = (cells, *components, total)
    elif aggregator == "linf_intersection":
        keys = (cells, *components, total, selected.max(axis=0))
    elif aggregator == "min_rank_wavefront":
        keys = (cells, *components, total, selected.min(axis=0))
    else:
        raise ValueError(f"A368 unknown aggregator {aggregator}")
    order = np.lexsort(keys)
    result = np.empty(WITHIN_CELLS, dtype=np.int16)
    result[order] = np.arange(1, WITHIN_CELLS + 1, dtype=np.int16)
    return result


def _within_order(ranks: Sequence[int]) -> list[int]:
    values = [int(value) for value in ranks]
    if len(values) != WITHIN_CELLS or set(values) != set(range(1, WITHIN_CELLS + 1)):
        raise ValueError("A368 within-slice rank field differs")
    return sorted(range(WITHIN_CELLS), key=lambda cell: (values[cell], cell))


def build_causal(payload: Mapping[str, Any]) -> dict[str, Any]:
    sys.path.insert(0, str(DOTCAUSAL_SRC))
    from dotcausal.io import CausalReader, CausalWriter

    gated = "A367:prospective_familywise_reader_gate_passed"
    sealed = "A361:complete_sealed_unlabeled_direct12_field"
    sources = "A368:retained_reader_source_orders"
    ordered = "A368:exact_factor_k_4096_group_order"
    writer = CausalWriter(api_id="a368ord")
    writer._rules = []
    rules = [
        ("gate_to_shard_read", [gated], sealed),
        ("sealed_field_to_source_orders", [sealed], sources),
        ("source_orders_to_factor_k_wavefront", [sources], ordered),
    ]
    for name, pattern, conclusion in rules:
        writer.add_rule(
            name=name,
            description=name.replace("_", " "),
            pattern=pattern,
            conclusion=conclusion,
            confidence_modifier=1.0,
        )
    triplets = [
        (
            gated,
            "conditional_unlock_after_prospective_A367_familywise_gate",
            sealed,
            payload["A367_result_sha256"],
            payload["A367_retention_gate"],
        ),
        (
            sealed,
            "apply_every_retained_frozen_A366_reader_without_refit",
            sources,
            payload["source_orders_sha256"],
            payload["source_order_summary"],
        ),
        (
            sources,
            "stable_min_source_rank_wavefront_with_complete_pointwise_factor_k_proof",
            ordered,
            payload["order_commitment_sha256"],
            payload["pointwise_factor_k_proof"],
        ),
    ]
    for trigger, mechanism, outcome, source, quantification in triplets:
        writer.add_triplet(
            trigger=trigger,
            mechanism=mechanism,
            outcome=outcome,
            confidence=1.0,
            source=source,
            quantification=json.dumps(quantification, sort_keys=True),
            evidence=payload["evidence_stage"],
            domain="ChaCha20 R20 W46 sealed-target Reader portfolio deployment",
            quality_score=1.0,
        )
    writer.add_triplet(
        trigger=gated,
        mechanism="materialized_gate_sealed_field_reader_portfolio_order_chain",
        outcome=ordered,
        confidence=1.0,
        source="materialized:A368_order_chain",
        quantification="exact retained closure",
        evidence=payload["evidence_stage"],
        domain="AI-native retained inference",
        quality_score=1.0,
        is_inferred=True,
    )
    writer.add_cluster(name="A368 sealed A361 portfolio order", entities=[gated, sealed, sources, ordered])
    writer.add_gap(
        subject=ordered,
        predicate="next_required_object",
        expected_object_type="A369_complete_group_recovery_with_matched_control",
        confidence=1.0,
        suggested_queries=[
            "Execute the exact A368 order from rank one with the qualified A324 engine and independently confirm any sole factual model."
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
        reader.api_id != "a368ord"
        or len(explicit) != 3
        or len(all_rows) != 4
        or len(inferred) != 1
        or len(reader._rules) != 3
        or len(reader._clusters) != 1
        or len(reader._gaps) != 1
    ):
        raise RuntimeError("A368 authentic Causal reopen gate failed")
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
    *, expected_implementation_sha256: str, expected_a367_result_sha256: str
) -> dict[str, Any]:
    if any(path.exists() for path in (ORDER, CAUSAL, REPORT)):
        raise FileExistsError("A368 order already exists")
    design = load_design()
    implementation = load_implementation(expected_implementation_sha256)
    a367 = _validate_a367_gate(expected_a367_result_sha256)
    measurement = A361.load_measurement(
        A361_MEASUREMENT_SHA256, expected_protocol_sha256=A361_PROTOCOL_SHA256
    )
    if (
        measurement["measurement_commitment_sha256"] != A361_MEASUREMENT_COMMITMENT_SHA256
        or measurement["measurement_summary"]["reader_scoring_eligible"] is not True
    ):
        raise RuntimeError("A368 sealed A361 measurement differs")
    measurements = A361._measurement_map(  # noqa: SLF001
        measurement, protocol_sha256=A361_PROTOCOL_SHA256
    )
    a366 = _load_a366_result()
    retained_roles = [str(role) for role in a367["retention_gate"]["retained_model_roles"]]
    if not retained_roles or any(role not in MODEL_ROLES for role in retained_roles):
        raise RuntimeError("A368 retained Reader role cover differs")
    definitions = {
        role: a366["reader_selection"]["selected_readers"][role]["definition"]
        for role in retained_roles
    }
    unique_feature_indices = [
        int(row["feature_index"]) for row in a366["reader_selection"]["unique_primitives"]
    ]
    rank_fields: dict[str, dict[int, list[int]]] = {role: {} for role in retained_roles}
    within_orders: dict[str, dict[int, list[int]]] = {role: {} for role in retained_roles}
    for low4 in SLICES:
        matrix = A360.target_normalize(A275._target_feature_matrix(measurements[low4]))  # noqa: SLF001
        primitives = _single_primitive_fields(matrix, unique_feature_indices)
        for role in retained_roles:
            ranks = _single_candidate_rank_field(primitives, definitions[role])
            rank_fields[role][low4] = [int(value) for value in ranks]
            within_orders[role][low4] = _within_order(ranks)
    source_orders = {
        role: A361.compose_round_robin(within_orders[role]) for role in retained_roles
    }
    selected_order = factor_k_wavefront(source_orders, retained_roles)
    proof = factor_k_proof(source_orders, retained_roles, selected_order)
    selected_order_hash = order_sha256(selected_order)
    source_order_summary = {
        role: {
            "name": definitions[role]["name"],
            "selected_order_uint16be_sha256": order_sha256(source_orders[role]),
            "first_16_groups": source_orders[role][:16],
        }
        for role in retained_roles
    }
    payload: dict[str, Any] = {
        "schema": "chacha20-round20-w46-a367-reader-portfolio-sealed-a361-order-a368-v1",
        "attempt_id": ATTEMPT_ID,
        "evidence_stage": "A367_GATED_SEALED_A361_FACTOR_K_READER_PORTFOLIO_ORDER_FROZEN",
        "design_sha256": DESIGN_SHA256,
        "implementation_sha256": expected_implementation_sha256,
        "implementation_commitment_sha256": implementation["implementation_commitment_sha256"],
        "A367_result_sha256": expected_a367_result_sha256,
        "A367_result_commitment_sha256": a367["result_sha256"],
        "A367_retention_gate": a367["retention_gate"],
        "A361_protocol_sha256": A361_PROTOCOL_SHA256,
        "A361_measurement_sha256": A361_MEASUREMENT_SHA256,
        "A361_measurement_commitment_sha256": A361_MEASUREMENT_COMMITMENT_SHA256,
        "A366_result_file_sha256": A366_RESULT_FILE_SHA256,
        "A366_selection_commitment_sha256": A366_SELECTION_COMMITMENT_SHA256,
        "retained_model_roles": retained_roles,
        "retained_model_definitions": definitions,
        "reader_refits": 0,
        "within_slice_rank_fields": rank_fields,
        "within_slice_rank_fields_sha256": canonical_sha256(rank_fields),
        "within_slice_orders": within_orders,
        "within_slice_orders_sha256": canonical_sha256(within_orders),
        "source_orders": source_orders,
        "source_orders_sha256": canonical_sha256(source_orders),
        "source_order_summary": source_order_summary,
        "selected_order": selected_order,
        "selected_order_uint16be_sha256": selected_order_hash,
        "pointwise_factor_k_proof": proof,
        "order_summary": {
            "groups": GROUPS,
            "retained_reader_count": len(retained_roles),
            "first_32_groups": selected_order[:32],
            "last_32_groups": selected_order[-32:],
            "selected_order_uint16be_sha256": selected_order_hash,
            "candidate_assignments_executed": 0,
        },
        "A361_shard_content_read_only_after_A367_gate": True,
        "candidate_or_prefix_available_at_order_freeze": False,
        "candidate_assignments_executed": 0,
        "information_boundary": design["information_boundary"],
        "anchors": {
            "design": anchor(DESIGN, DESIGN_SHA256),
            "implementation": anchor(IMPLEMENTATION, expected_implementation_sha256),
            "A361_protocol": anchor(A361_PROTOCOL, A361_PROTOCOL_SHA256),
            "A361_preflight": anchor(A361_PREFLIGHT, A361_PREFLIGHT_SHA256),
            "A361_measurement": anchor(A361_MEASUREMENT, A361_MEASUREMENT_SHA256),
            "A366_result": anchor(A366_RESULT, A366_RESULT_FILE_SHA256),
            "A367_result": anchor(A367.RESULT, expected_a367_result_sha256),
            "runner": anchor(Path(__file__)),
            "test": anchor(TEST),
            "reproducer": anchor(REPRO),
        },
    }
    payload["order_commitment_sha256"] = canonical_sha256(
        {
            "implementation_commitment_sha256": payload["implementation_commitment_sha256"],
            "A367_result_commitment_sha256": payload["A367_result_commitment_sha256"],
            "A361_measurement_commitment_sha256": A361_MEASUREMENT_COMMITMENT_SHA256,
            "A366_selection_commitment_sha256": A366_SELECTION_COMMITMENT_SHA256,
            "retained_model_roles": retained_roles,
            "source_orders_sha256": payload["source_orders_sha256"],
            "selected_order_uint16be_sha256": selected_order_hash,
            "pointwise_factor_k_proof": proof,
            "candidate_or_prefix_available_at_order_freeze": False,
            "candidate_assignments_executed": 0,
        }
    )
    payload["causal"] = build_causal(payload)
    atomic_json(ORDER, payload)
    atomic_bytes(
        REPORT,
        (
            "# A368 — sealed A361 factor-k Reader portfolio order\n\n"
            f"Evidence stage: **{payload['evidence_stage']}**\n\n"
            f"- Retained Readers: **{retained_roles}**\n"
            f"- Exact groups: **{GROUPS:,}**\n"
            f"- Pointwise bound: **{proof['bound']}**\n"
            f"- Maximum observed proof ratio: **{proof['maximum_ratio']}**\n"
            f"- Order SHA-256: **{selected_order_hash}**\n"
            "- Reader refits / candidate executions: **0 / 0**\n"
            "- Candidate or prefix available at freeze: **False**\n"
            "- Authentic AI-native Causal readback: **3 explicit + 1 inferred**\n"
        ).encode(),
    )
    return payload


def load_order(expected_sha256: str) -> dict[str, Any]:
    if file_sha256(ORDER) != expected_sha256:
        raise RuntimeError("A368 order hash differs")
    value = json.loads(ORDER.read_bytes())
    selected = _exact_order(value.get("selected_order", []), "selected")
    source_orders = {
        role: _exact_order(order, f"source {role}")
        for role, order in value.get("source_orders", {}).items()
    }
    roles = [str(role) for role in value.get("retained_model_roles", [])]
    if (
        value.get("schema")
        != "chacha20-round20-w46-a367-reader-portfolio-sealed-a361-order-a368-v1"
        or value.get("attempt_id") != ATTEMPT_ID
        or value.get("A367_retention_gate", {}).get("passed") is not True
        or not roles
        or set(roles) != set(source_orders)
        or value.get("reader_refits") != 0
        or selected != factor_k_wavefront(source_orders, roles)
        or value.get("pointwise_factor_k_proof") != factor_k_proof(source_orders, roles, selected)
        or value.get("selected_order_uint16be_sha256") != order_sha256(selected)
        or value.get("A361_shard_content_read_only_after_A367_gate") is not True
        or value.get("candidate_or_prefix_available_at_order_freeze") is not False
        or value.get("candidate_assignments_executed") != 0
    ):
        raise RuntimeError("A368 frozen order semantics differ")
    for artifact in value["anchors"].values():
        anchor(path_from_ref(artifact["path"]), artifact["sha256"])
    anchor(path_from_ref(value["causal"]["path"]), value["causal"]["sha256"])
    return value


def analyze() -> dict[str, Any]:
    return {
        "attempt_id": ATTEMPT_ID,
        "design_sha256": DESIGN_SHA256,
        "implementation_frozen": IMPLEMENTATION.exists(),
        "implementation_sha256": file_sha256(IMPLEMENTATION) if IMPLEMENTATION.exists() else None,
        "A367_result_available": A367.RESULT.exists(),
        "order_frozen": ORDER.exists(),
        "order_sha256": file_sha256(ORDER) if ORDER.exists() else None,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    action = parser.add_mutually_exclusive_group(required=True)
    action.add_argument("--analyze", action="store_true")
    action.add_argument("--freeze-implementation", action="store_true")
    action.add_argument("--freeze-order", action="store_true")
    parser.add_argument("--expected-implementation-sha256")
    parser.add_argument("--expected-a367-result-sha256")
    args = parser.parse_args()
    if args.freeze_implementation:
        payload = freeze_implementation()
    elif args.freeze_order:
        if not args.expected_implementation_sha256 or not args.expected_a367_result_sha256:
            parser.error(
                "--freeze-order requires --expected-implementation-sha256 and --expected-a367-result-sha256"
            )
        payload = freeze_order(
            expected_implementation_sha256=args.expected_implementation_sha256,
            expected_a367_result_sha256=args.expected_a367_result_sha256,
        )
    else:
        payload = analyze()
    print(json.dumps(payload, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()

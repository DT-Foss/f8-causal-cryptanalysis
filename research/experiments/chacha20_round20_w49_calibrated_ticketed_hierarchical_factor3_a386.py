#!/usr/bin/env python3
"""A386: calibrate an exact ticketed Reader wavefront and bind a W49 factor-three order."""

from __future__ import annotations

import argparse
import importlib.util
import inspect
import itertools
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

DESIGN = CONFIGS / "chacha20_round20_w49_calibrated_ticketed_hierarchical_factor3_a386_design_v1.json"
IMPLEMENTATION = CONFIGS / "chacha20_round20_w49_calibrated_ticketed_hierarchical_factor3_a386_implementation_v1.json"
CALIBRATION = RESULTS / "chacha20_round20_w49_calibrated_ticketed_hierarchical_factor3_a386_calibration_v1.json"
ORDER = RESULTS / "chacha20_round20_w49_calibrated_ticketed_hierarchical_factor3_a386_order_v1.json"
CAUSAL = ORDER.with_suffix(".causal")
REPORT = ORDER.with_suffix(".md")
TEST = ROOT / "tests/test_chacha20_round20_w49_calibrated_ticketed_hierarchical_factor3_a386.py"
REPRO = ROOT / "scripts/reproduce_chacha20_round20_w49_calibrated_ticketed_hierarchical_factor3_a386.sh"

A375_RUNNER = RESEARCH / "experiments/chacha20_round20_w46_wide_consensus_reader_a375.py"
A375_RESULT = RESULTS / "chacha20_round20_w46_wide_consensus_reader_a375_v1.json"
A382_RUNNER = RESEARCH / "experiments/chacha20_round20_w49_crosswidth_wide_consensus_factor6_a382.py"
A382_ORDER = RESULTS / "chacha20_round20_w49_crosswidth_wide_consensus_factor6_a382_order_v1.json"
A382_CAUSAL = A382_ORDER.with_suffix(".causal")
A381_RESULT = RESULTS / "chacha20_round20_w49_target_conditioned_recovery_a381_v1.json"
A383_RESULT = RESULTS / "chacha20_round20_w49_factor6_recovery_a383_v1.json"

ATTEMPT_ID = "A386"
DESIGN_SHA256 = "6a7f75dcfaa93eb4041a6485208575ed0ac5dbd3394960d11a109b8afcf08196"
A375_RUNNER_SHA256 = "e41a91b225b861abd669280a4044dddf5e2b24e8f6e8c66e7eee6d5a149ec9f1"
A375_RESULT_SHA256 = "fc7135af9e001eb8cd83a55902e48f5776dc24a4eb86a162d7d783a115b38ef1"
A382_RUNNER_SHA256 = "46601c0e4fc5e20ee2ab85c4140b1fadd33b149f189e8335a0a6ef815bcbdc9f"
A382_ORDER_SHA256 = "f705549d15be9f4ed98e8548b837524dae8603bff384ab30648c5917dfb82c0c"
A382_CAUSAL_SHA256 = "a079ddb6c492761f110090a019d7442bd093aa94f104859d2ea8b63b3b76472b"

MODEL_ROLES = ("wide_vote", "sparse_reciprocal", "broad_quantile", "broad_intersection")
OUTER_ROLES = ("A379_target_free", "A380_target_conditioned", "A386_calibrated_weighted_wide")
TARGETS = 128
CALIBRATION_CELLS = 256
BLOCK_SIZE = 16
BLOCKS = 8
W49_CELLS = 4096
TICKET_MIN = 1
TICKET_MAX = 8
NORMALIZED_TICKET_VECTORS = 3823
DOTCAUSAL_SRC = Path("/Users/bhkmie/Documents/Forschung/O1/vendor/fabel/dotcausal_package/src")


def load_module(path: Path, name: str) -> Any:
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot import A386 dependency {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


A375 = load_module(A375_RUNNER, "a386_a375")
A382 = load_module(A382_RUNNER, "a386_a382")
file_sha256 = A382.file_sha256
canonical_sha256 = A382.canonical_sha256
atomic_json = A382.atomic_json
atomic_bytes = A382.atomic_bytes
relative = A382.relative
path_from_ref = A382.path_from_ref
anchor = A382.anchor


def exact_order(values: Sequence[int], size: int, label: str) -> list[int]:
    order = [int(value) for value in values]
    if len(order) != size or set(order) != set(range(size)):
        raise ValueError(f"A386 {label} is not an exact {size:,}-cell order")
    return order


def rank_vector(order: Sequence[int], size: int) -> list[int]:
    ranks = [0] * size
    for rank, cell in enumerate(exact_order(order, size, "rank vector"), 1):
        ranks[cell] = rank
    return ranks


def order_sha256(order: Sequence[int]) -> str:
    return A382.order_sha256(exact_order(order, W49_CELLS, "order hash"))


def ticket_vectors() -> list[tuple[int, ...]]:
    rows = [
        tuple(int(value) for value in values)
        for values in itertools.product(range(TICKET_MIN, TICKET_MAX + 1), repeat=len(MODEL_ROLES))
        if math.gcd(*values) == 1
    ]
    if len(rows) != NORMALIZED_TICKET_VECTORS:
        raise RuntimeError("A386 normalized ticket-space cardinality differs")
    return rows


def ticketed_wavefront(
    source_orders: Mapping[str, Sequence[int]],
    role_order: Sequence[str],
    tickets: Sequence[int],
    *,
    size: int,
) -> list[int]:
    roles = tuple(str(role) for role in role_order)
    ticket_tuple = tuple(int(value) for value in tickets)
    if (
        not roles
        or set(roles) != set(source_orders)
        or len(roles) != len(set(roles))
        or len(ticket_tuple) != len(roles)
        or any(value <= 0 for value in ticket_tuple)
    ):
        raise ValueError("A386 ticketed source contract differs")
    ranks = {role: rank_vector(source_orders[role], size) for role in roles}
    return exact_order(
        sorted(
            range(size),
            key=lambda cell: (
                min(
                    (ranks[role][cell] + ticket - 1) // ticket
                    for role, ticket in zip(roles, ticket_tuple, strict=True)
                ),
                sum(ranks[role][cell] for role in roles),
                *(ranks[role][cell] for role in roles),
                cell,
            ),
        ),
        size,
        "ticketed wavefront",
    )


def ticketed_pointwise_proof(
    source_orders: Mapping[str, Sequence[int]],
    role_order: Sequence[str],
    tickets: Sequence[int],
    selected: Sequence[int],
    *,
    size: int,
) -> dict[str, Any]:
    roles = tuple(str(role) for role in role_order)
    ticket_tuple = tuple(int(value) for value in tickets)
    source_ranks = {role: rank_vector(source_orders[role], size) for role in roles}
    selected_ranks = rank_vector(selected, size)
    total = sum(ticket_tuple)
    panel: dict[str, Any] = {}
    for role, ticket in zip(roles, ticket_tuple, strict=True):
        bounds = [
            total * ((source_ranks[role][cell] + ticket - 1) // ticket)
            for cell in range(size)
        ]
        violations = [
            cell for cell in range(size) if selected_ranks[cell] > bounds[cell]
        ]
        if violations:
            raise RuntimeError(f"A386 ticketed pointwise bound failed for {role}")
        panel[role] = {
            "ticket": ticket,
            "bound": f"R_weighted(c) <= {total}*ceil(R_{role}(c)/{ticket})",
            "maximum_bound_fraction": max(
                selected_ranks[cell] / bounds[cell] for cell in range(size)
            ),
            "violations": 0,
        }
    return {
        "cells_checked": size,
        "reader_count": len(roles),
        "ticket_vector": list(ticket_tuple),
        "total_tickets": total,
        "per_reader": panel,
        "violations": 0,
    }


def factor3_wavefront(source_orders: Mapping[str, Sequence[int]]) -> list[int]:
    ranks = {role: rank_vector(source_orders[role], W49_CELLS) for role in OUTER_ROLES}
    return exact_order(
        sorted(
            range(W49_CELLS),
            key=lambda cell: (
                min(ranks[role][cell] for role in OUTER_ROLES),
                sum(ranks[role][cell] for role in OUTER_ROLES),
                *(ranks[role][cell] for role in OUTER_ROLES),
                cell,
            ),
        ),
        W49_CELLS,
        "outer factor-three wavefront",
    )


def factor3_proof(
    source_orders: Mapping[str, Sequence[int]], selected: Sequence[int]
) -> dict[str, Any]:
    source_ranks = {role: rank_vector(source_orders[role], W49_CELLS) for role in OUTER_ROLES}
    selected_ranks = rank_vector(selected, W49_CELLS)
    ratios = [
        selected_ranks[cell] / min(source_ranks[role][cell] for role in OUTER_ROLES)
        for cell in range(W49_CELLS)
    ]
    violations = [cell for cell, ratio in enumerate(ratios) if ratio > 3.0 + 1e-15]
    if violations:
        raise RuntimeError("A386 outer factor-three pointwise proof failed")
    return {
        "bound": "R_A386(c) <= 3*min(R_A379(c),R_A380(c),R_weighted_wide(c))",
        "cells_checked": W49_CELLS,
        "maximum_ratio": max(ratios),
        "mean_ratio": float(np.mean(ratios)),
        "source_count": len(OUTER_ROLES),
        "violations": 0,
    }


def load_design() -> dict[str, Any]:
    if file_sha256(DESIGN) != DESIGN_SHA256:
        raise RuntimeError("A386 design hash differs")
    value = json.loads(DESIGN.read_bytes())
    calibration = value.get("calibration_contract", {})
    boundary = value.get("information_boundary", {})
    weighted = value.get("weighted_wavefront_contract", {})
    outer = value.get("outer_order_contract", {})
    if (
        value.get("schema")
        != "chacha20-round20-w49-calibrated-ticketed-hierarchical-factor3-a386-design-v1"
        or value.get("attempt_id") != ATTEMPT_ID
        or value.get("design_state")
        != "frozen_after_independent_A375_ticket_hypothesis_generation_before_formal_A386_calibration_recomputation_W49_order_or_target_reveal"
        or calibration.get("candidate_ticket_vectors") != NORMALIZED_TICKET_VECTORS
        or calibration.get("targets") != TARGETS
        or calibration.get("fixed_blocks") != BLOCKS
        or tuple(weighted.get("reader_role_order", [])) != MODEL_ROLES
        or tuple(outer.get("source_roles", [])) != OUTER_ROLES
        or outer.get("pointwise_bound_checked_cells") != W49_CELLS
        or boundary.get("A381_result_available_at_design_freeze") is not False
        or boundary.get("A383_result_available_at_design_freeze") is not False
        or boundary.get("W49_secret_assignment_or_true_prefix_available_to_A386") is not False
        or boundary.get("A381_or_A383_progress_or_filter_outcomes_consumed") is not False
    ):
        raise RuntimeError("A386 frozen design semantics differ")
    for name, path_value in value["source_anchors"].items():
        if name.endswith("_path"):
            stem = name.removesuffix("_path")
            anchor(ROOT / path_value, value["source_anchors"][f"{stem}_sha256"])
    return value


def assert_target_unrevealed() -> None:
    if A381_RESULT.exists() or A383_RESULT.exists():
        raise RuntimeError("A386 prospective freeze must precede every W49 recovery result")


def assert_before_local_artifact(*paths: Path) -> None:
    if any(path.exists() for path in paths):
        raise FileExistsError("A386 destination artifact already exists")


def load_a375_result() -> dict[str, Any]:
    anchor(A375_RESULT, A375_RESULT_SHA256)
    value = json.loads(A375_RESULT.read_bytes())
    if (
        value.get("schema") != "chacha20-round20-w46-wide-consensus-reader-a375-v1"
        or set(value.get("model_definitions", {})) != set(MODEL_ROLES)
        or len(value.get("model_definitions", {})) != len(MODEL_ROLES)
        or value.get("candidate_assignments_executed") != 0
    ):
        raise RuntimeError("A386 A375 result semantics differ")
    return value


def load_a382_order() -> dict[str, Any]:
    anchor(A382_ORDER, A382_ORDER_SHA256)
    anchor(A382_CAUSAL, A382_CAUSAL_SHA256)
    return A382.load_order(A382_ORDER_SHA256)


def calibration_rank_cube() -> tuple[np.ndarray, np.ndarray, list[str]]:
    result = load_a375_result()
    matrices, truths, block_labels = A375.load_panel()
    fields = A375.exact_abs_rank_fields(matrices)
    model_fields = [
        A375.aggregate_rank_field(
            fields,
            result["model_definitions"][role]["member_feature_indices"],
            result["model_definitions"][role]["aggregator"],
        )
        for role in MODEL_ROLES
    ]
    cube = np.stack(model_fields, axis=1).astype(np.int16)
    labels = np.asarray(truths, dtype=np.int16)
    if cube.shape != (TARGETS, len(MODEL_ROLES), CALIBRATION_CELLS):
        raise RuntimeError("A386 calibration rank-cube geometry differs")
    return cube, labels, block_labels


def calibration_truth_ranks(
    rank_cube: np.ndarray, truths: np.ndarray, tickets: Sequence[int]
) -> np.ndarray:
    ticket_array = np.asarray([int(value) for value in tickets], dtype=np.int16)
    if rank_cube.shape != (TARGETS, len(MODEL_ROLES), CALIBRATION_CELLS):
        raise ValueError("A386 rank-cube geometry differs")
    if ticket_array.shape != (len(MODEL_ROLES),) or np.any(ticket_array <= 0):
        raise ValueError("A386 ticket vector differs")
    levels = (rank_cube + ticket_array[None, :, None] - 1) // ticket_array[None, :, None]
    cells = np.arange(CALIBRATION_CELLS, dtype=np.int16)
    result = np.empty(TARGETS, dtype=np.int16)
    for target in range(TARGETS):
        order = np.lexsort(
            (
                cells,
                rank_cube[target, 3],
                rank_cube[target, 2],
                rank_cube[target, 1],
                rank_cube[target, 0],
                rank_cube[target].sum(axis=0),
                levels[target].min(axis=0),
            )
        )
        positions = np.empty(CALIBRATION_CELLS, dtype=np.int16)
        positions[order] = np.arange(1, CALIBRATION_CELLS + 1, dtype=np.int16)
        result[target] = positions[int(truths[target])]
    return result


def rank_metrics(truth_ranks: Sequence[int]) -> dict[str, Any]:
    ranks = np.asarray([int(value) for value in truth_ranks], dtype=np.int16)
    if ranks.shape != (TARGETS,) or np.any(ranks < 1) or np.any(ranks > CALIBRATION_CELLS):
        raise ValueError("A386 truth-rank vector differs")
    logs = np.log2(ranks.astype(np.float64))
    block_means = [
        float(logs[start : start + BLOCK_SIZE].mean())
        for start in range(0, TARGETS, BLOCK_SIZE)
    ]
    return {
        "maximum_fixed_block_mean_log2_truth_rank": max(block_means),
        "all128_mean_log2_truth_rank": float(logs.mean()),
        "worst_truth_rank": int(ranks.max()),
        "fixed_block_mean_log2_truth_ranks": block_means,
        "truth_ranks": ranks.tolist(),
    }


def exhaustive_ticket_calibration() -> dict[str, Any]:
    rank_cube, truths, block_labels = calibration_rank_cube()
    rows: list[dict[str, Any]] = []
    for tickets in ticket_vectors():
        metrics = rank_metrics(calibration_truth_ranks(rank_cube, truths, tickets))
        rows.append(
            {
                "ticket_vector": list(tickets),
                "maximum_fixed_block_mean_log2_truth_rank": metrics[
                    "maximum_fixed_block_mean_log2_truth_rank"
                ],
                "all128_mean_log2_truth_rank": metrics["all128_mean_log2_truth_rank"],
                "worst_truth_rank": metrics["worst_truth_rank"],
            }
        )
    ordered = sorted(
        rows,
        key=lambda row: (
            float(row["maximum_fixed_block_mean_log2_truth_rank"]),
            float(row["all128_mean_log2_truth_rank"]),
            int(row["worst_truth_rank"]),
            tuple(int(value) for value in row["ticket_vector"]),
        ),
    )
    selected_tickets = tuple(int(value) for value in ordered[0]["ticket_vector"])
    selected_metrics = rank_metrics(
        calibration_truth_ranks(rank_cube, truths, selected_tickets)
    )
    equal_metrics = rank_metrics(
        calibration_truth_ranks(rank_cube, truths, (1, 1, 1, 1))
    )
    single_model_metrics = {
        role: rank_metrics(
            rank_cube[:, role_index, :][np.arange(TARGETS), truths].tolist()
        )
        for role_index, role in enumerate(MODEL_ROLES)
    }
    best_single_max = min(
        value["maximum_fixed_block_mean_log2_truth_rank"]
        for value in single_model_metrics.values()
    )
    return {
        "source_panel": {
            "targets": TARGETS,
            "cells_per_target": CALIBRATION_CELLS,
            "fixed_blocks": BLOCKS,
            "fixed_block_labels": block_labels,
            "model_roles": list(MODEL_ROLES),
        },
        "search": {
            "ticket_min": TICKET_MIN,
            "ticket_max": TICKET_MAX,
            "normalized_vectors_evaluated": len(rows),
            "grid_ledger_sha256": canonical_sha256(rows),
            "top20": ordered[:20],
        },
        "selected_ticket_vector": list(selected_tickets),
        "selected_metrics": selected_metrics,
        "equal_ticket_baseline": equal_metrics,
        "single_model_baselines": single_model_metrics,
        "selected_minimax_gain_over_equal_bits": float(
            equal_metrics["maximum_fixed_block_mean_log2_truth_rank"]
            - selected_metrics["maximum_fixed_block_mean_log2_truth_rank"]
        ),
        "selected_minimax_gain_over_best_single_bits": float(
            best_single_max
            - selected_metrics["maximum_fixed_block_mean_log2_truth_rank"]
        ),
        "W49_target_labels_used": 0,
        "W49_candidate_or_filter_outcomes_used": 0,
    }


def freeze_implementation() -> dict[str, Any]:
    assert_before_local_artifact(IMPLEMENTATION, CALIBRATION, ORDER, CAUSAL, REPORT)
    assert_target_unrevealed()
    design = load_design()
    load_a375_result()
    load_a382_order()
    if not TEST.exists() or not REPRO.exists():
        raise FileNotFoundError("A386 test and reproducer must precede implementation freeze")
    payload: dict[str, Any] = {
        "schema": "chacha20-round20-w49-calibrated-ticketed-hierarchical-factor3-a386-implementation-v1",
        "attempt_id": ATTEMPT_ID,
        "commitment_state": "frozen_before_formal_ticket_grid_calibration_A386_W49_order_or_W49_target_reveal",
        "design_sha256": DESIGN_SHA256,
        "calibration_contract": design["calibration_contract"],
        "weighted_wavefront_contract": design["weighted_wavefront_contract"],
        "outer_order_contract": design["outer_order_contract"],
        "A381_or_A383_progress_or_filter_outcomes_consumed": False,
        "W49_secret_assignment_or_true_prefix_available": False,
        "candidate_assignments_executed_by_A386": 0,
        "anchors": {
            "design": anchor(DESIGN, DESIGN_SHA256),
            "A375_runner": anchor(A375_RUNNER, A375_RUNNER_SHA256),
            "A375_result": anchor(A375_RESULT, A375_RESULT_SHA256),
            "A382_runner": anchor(A382_RUNNER, A382_RUNNER_SHA256),
            "A382_order": anchor(A382_ORDER, A382_ORDER_SHA256),
            "A382_causal": anchor(A382_CAUSAL, A382_CAUSAL_SHA256),
            "runner": anchor(Path(__file__)),
            "test": anchor(TEST),
            "reproducer": anchor(REPRO),
        },
    }
    payload["implementation_commitment_sha256"] = canonical_sha256(payload)
    atomic_json(IMPLEMENTATION, payload)
    assert_target_unrevealed()
    return payload


def load_implementation(expected_sha256: str) -> dict[str, Any]:
    if file_sha256(IMPLEMENTATION) != expected_sha256:
        raise RuntimeError("A386 implementation hash differs")
    value = json.loads(IMPLEMENTATION.read_bytes())
    if (
        value.get("schema")
        != "chacha20-round20-w49-calibrated-ticketed-hierarchical-factor3-a386-implementation-v1"
        or value.get("attempt_id") != ATTEMPT_ID
        or value.get("commitment_state")
        != "frozen_before_formal_ticket_grid_calibration_A386_W49_order_or_W49_target_reveal"
        or value.get("design_sha256") != DESIGN_SHA256
        or value.get("A381_or_A383_progress_or_filter_outcomes_consumed") is not False
        or value.get("W49_secret_assignment_or_true_prefix_available") is not False
        or value.get("candidate_assignments_executed_by_A386") != 0
    ):
        raise RuntimeError("A386 implementation semantics differ")
    expected = {
        "design": DESIGN,
        "A375_runner": A375_RUNNER,
        "A375_result": A375_RESULT,
        "A382_runner": A382_RUNNER,
        "A382_order": A382_ORDER,
        "A382_causal": A382_CAUSAL,
        "runner": Path(__file__),
        "test": TEST,
        "reproducer": REPRO,
    }
    for name, path in expected.items():
        row = value["anchors"][name]
        if row.get("path") != relative(path) or row.get("sha256") != file_sha256(path):
            raise RuntimeError(f"A386 implementation anchor differs: {name}")
    unsigned = {key: item for key, item in value.items() if key != "implementation_commitment_sha256"}
    if value.get("implementation_commitment_sha256") != canonical_sha256(unsigned):
        raise RuntimeError("A386 implementation commitment differs")
    return value


def freeze_calibration(*, expected_implementation_sha256: str) -> dict[str, Any]:
    assert_before_local_artifact(CALIBRATION, ORDER, CAUSAL, REPORT)
    assert_target_unrevealed()
    implementation = load_implementation(expected_implementation_sha256)
    result = exhaustive_ticket_calibration()
    essential = {
        "design_sha256": DESIGN_SHA256,
        "implementation_sha256": expected_implementation_sha256,
        "selected_ticket_vector": result["selected_ticket_vector"],
        "selected_metrics": result["selected_metrics"],
        "grid_ledger_sha256": result["search"]["grid_ledger_sha256"],
        "W49_target_labels_used": 0,
        "W49_candidate_or_filter_outcomes_used": 0,
    }
    payload: dict[str, Any] = {
        "schema": "chacha20-round20-w49-calibrated-ticketed-hierarchical-factor3-a386-calibration-v1",
        "attempt_id": ATTEMPT_ID,
        "evidence_stage": "INDEPENDENT_A375_KNOWNKEY_TICKET_CALIBRATION_FROZEN_BEFORE_A386_W49_ORDER_OR_TARGET_REVEAL",
        "implementation_commitment_sha256": implementation[
            "implementation_commitment_sha256"
        ],
        **essential,
        **result,
        "information_boundary": {
            "calibration_source": "A375 disjoint W46 known-key panel only",
            "A381_or_A383_progress_or_filter_outcomes_consumed": False,
            "A381_or_A383_result_available_at_freeze": False,
            "W49_secret_assignment_or_true_prefix_available": False,
            "A386_candidate_assignments_executed": 0,
        },
        "anchors": {
            "design": anchor(DESIGN, DESIGN_SHA256),
            "implementation": anchor(IMPLEMENTATION, expected_implementation_sha256),
            "A375_runner": anchor(A375_RUNNER, A375_RUNNER_SHA256),
            "A375_result": anchor(A375_RESULT, A375_RESULT_SHA256),
            "runner": anchor(Path(__file__)),
            "test": anchor(TEST),
            "reproducer": anchor(REPRO),
        },
    }
    payload["calibration_commitment_sha256"] = canonical_sha256(essential)
    atomic_json(CALIBRATION, payload)
    assert_target_unrevealed()
    return payload


def load_calibration(expected_sha256: str) -> dict[str, Any]:
    if file_sha256(CALIBRATION) != expected_sha256:
        raise RuntimeError("A386 calibration hash differs")
    value = json.loads(CALIBRATION.read_bytes())
    if (
        value.get("schema")
        != "chacha20-round20-w49-calibrated-ticketed-hierarchical-factor3-a386-calibration-v1"
        or value.get("attempt_id") != ATTEMPT_ID
        or value.get("search", {}).get("normalized_vectors_evaluated")
        != NORMALIZED_TICKET_VECTORS
        or value.get("selected_ticket_vector") != [7, 2, 1, 5]
        or value.get("W49_target_labels_used") != 0
        or value.get("W49_candidate_or_filter_outcomes_used") != 0
        or value.get("information_boundary", {}).get(
            "W49_secret_assignment_or_true_prefix_available"
        )
        is not False
    ):
        raise RuntimeError("A386 frozen calibration semantics differ")
    for row in value["anchors"].values():
        anchor(path_from_ref(row["path"]), row["sha256"])
    load_implementation(value["implementation_sha256"])
    return value


def diversity_panel(source_orders: Mapping[str, Sequence[int]]) -> dict[str, Any]:
    roles = list(source_orders)
    result: dict[str, Any] = {}
    for left_index, left in enumerate(roles):
        for right in roles[left_index + 1 :]:
            result[f"{left}__vs__{right}"] = A382.A380.A351.diversity_panel(
                source_orders[left], source_orders[right]
            )
    return result


def build_causal(payload: Mapping[str, Any]) -> dict[str, Any]:
    sys.path.insert(0, str(DOTCAUSAL_SRC))
    from dotcausal.io import CausalReader, CausalWriter

    calibration = "A386:exhaustive_128_target_ticket_calibration"
    weighted = "A386:calibrated_ticketed_W49_wide_order"
    selected = "A386:exact_hierarchical_factor3_W49_order"
    ready = "A387:target_blind_next_width_transfer_ready"
    writer = CausalWriter(api_id="a386w49")
    writer._rules = []
    writer.add_rule(
        name="knownkey_panel_to_ticket_schedule",
        description="The complete A375 rank panel selects one normalized integer ticket vector by a frozen minimax objective.",
        pattern=["A375_complete_128_target_rank_panel"],
        conclusion=calibration,
        confidence_modifier=1.0,
    )
    writer.add_rule(
        name="tickets_and_four_orders_to_weighted_order",
        description="The ticket schedule prioritizes four unchanged W49 Reader orders under per-reader pointwise bounds.",
        pattern=[calibration, "A382_four_crosswidth_W49_orders"],
        conclusion=weighted,
        confidence_modifier=1.0,
    )
    writer.add_rule(
        name="weighted_and_fresh_orders_to_factor3",
        description="The calibrated weighted order joins A379 and A380 in an exact three-source min-rank wavefront.",
        pattern=[weighted, "A379_A380_two_W49_orders"],
        conclusion=selected,
        confidence_modifier=1.0,
    )
    writer.add_rule(
        name="factor3_to_next_width",
        description="The frozen target-blind order is ready for byte-identical transfer to the next qualified width.",
        pattern=[selected],
        conclusion=ready,
        confidence_modifier=1.0,
    )
    rows = (
        (
            "A375:complete_128_target_rank_panel",
            "exhaustive_normalized_integer_ticket_search_under_fixed_block_minimax_objective",
            calibration,
            payload["calibration_summary"],
        ),
        (
            calibration,
            "ticketed_integer_wavefront_over_four_unchanged_crosswidth_reader_orders",
            weighted,
            payload["weighted_pointwise_proof"],
        ),
        (
            weighted,
            "direct_min_rank_merge_with_A379_target_free_and_A380_target_conditioned_orders",
            selected,
            payload["outer_factor3_proof"],
        ),
        (
            selected,
            "freeze_before_W49_target_reveal_for_next_width_transfer",
            ready,
            payload["information_boundary"],
        ),
    )
    for trigger, mechanism, outcome, quantification in rows:
        writer.add_triplet(
            trigger=trigger,
            mechanism=mechanism,
            outcome=outcome,
            confidence=1.0,
            source=payload["order_commitment_sha256"],
            quantification=json.dumps(quantification, sort_keys=True),
            evidence=payload["evidence_stage"],
            domain="calibrated target-blind ChaCha20 R20 W49 order",
            quality_score=1.0,
        )
    writer.add_triplet(
        trigger="A375:complete_128_target_rank_panel",
        mechanism="materialized_calibration_weighted_order_factor3_next_width_chain",
        outcome=ready,
        confidence=1.0,
        source="materialized:A386_ticketed_hierarchical_chain",
        quantification="exact retained closure",
        evidence=payload["evidence_stage"],
        domain="AI-native retained inference",
        quality_score=1.0,
        is_inferred=True,
    )
    writer.add_cluster(
        name="A386 calibrated hierarchical W49 order",
        entities=[calibration, weighted, selected, ready],
    )
    writer.add_gap(
        subject=ready,
        predicate="next_required_object",
        expected_object_type="fresh_W50_or_later_challenge_bound_to_A386_order",
        confidence=1.0,
        suggested_queries=[
            "Transfer the frozen A386 order byte-identically after the next complete-group engine qualification."
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
        reader.api_id != "a386w49"
        or len(explicit) != 4
        or len(all_rows) != 5
        or len(inferred) != 1
        or len(reader._rules) != 4
        or len(reader._clusters) != 1
        or len(reader._gaps) != 1
    ):
        raise RuntimeError("A386 authentic Causal reopen gate failed")
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
            "calibration_relation": explicit[0],
            "weighted_relation": explicit[1],
            "terminal_chain": all_rows[-1],
            "next_gap": reader._gaps[0],
        },
    }


def freeze_order(
    *, expected_implementation_sha256: str, expected_calibration_sha256: str
) -> dict[str, Any]:
    assert_before_local_artifact(ORDER, CAUSAL, REPORT)
    assert_target_unrevealed()
    implementation = load_implementation(expected_implementation_sha256)
    calibration = load_calibration(expected_calibration_sha256)
    a382 = load_a382_order()
    tickets = tuple(int(value) for value in calibration["selected_ticket_vector"])
    wide_sources = {
        role: exact_order(a382["source_orders"][role], W49_CELLS, role)
        for role in MODEL_ROLES
    }
    weighted_order = ticketed_wavefront(
        wide_sources, MODEL_ROLES, tickets, size=W49_CELLS
    )
    weighted_proof = ticketed_pointwise_proof(
        wide_sources, MODEL_ROLES, tickets, weighted_order, size=W49_CELLS
    )
    outer_sources = {
        "A379_target_free": exact_order(
            a382["source_orders"]["A379_target_free"], W49_CELLS, "A379"
        ),
        "A380_target_conditioned": exact_order(
            a382["source_orders"]["A380_target_conditioned"], W49_CELLS, "A380"
        ),
        "A386_calibrated_weighted_wide": weighted_order,
    }
    selected = factor3_wavefront(outer_sources)
    outer_proof = factor3_proof(outer_sources, selected)
    diversity = diversity_panel(
        {
            **outer_sources,
            "A382_equal_six_view": exact_order(
                a382["selected_order"], W49_CELLS, "A382 selected"
            ),
        }
    )
    calibration_summary = {
        "selected_ticket_vector": list(tickets),
        "vectors_evaluated": calibration["search"]["normalized_vectors_evaluated"],
        "selected_maximum_fixed_block_mean_log2_truth_rank": calibration[
            "selected_metrics"
        ]["maximum_fixed_block_mean_log2_truth_rank"],
        "minimax_gain_over_equal_bits": calibration[
            "selected_minimax_gain_over_equal_bits"
        ],
        "minimax_gain_over_best_single_bits": calibration[
            "selected_minimax_gain_over_best_single_bits"
        ],
    }
    essential = {
        "design_sha256": DESIGN_SHA256,
        "implementation_sha256": expected_implementation_sha256,
        "calibration_sha256": expected_calibration_sha256,
        "selected_ticket_vector": list(tickets),
        "weighted_order_uint16be_sha256": order_sha256(weighted_order),
        "selected_order_uint16be_sha256": order_sha256(selected),
        "weighted_pointwise_proof": weighted_proof,
        "outer_factor3_proof": outer_proof,
        "W49_target_labels_used": 0,
        "W49_candidate_or_filter_outcomes_used": 0,
        "candidate_assignments_executed_by_A386": 0,
    }
    payload: dict[str, Any] = {
        "schema": "chacha20-round20-w49-calibrated-ticketed-hierarchical-factor3-a386-order-v1",
        "attempt_id": ATTEMPT_ID,
        "evidence_stage": "PRE_TARGET_REVEAL_CALIBRATED_TICKETED_W49_HIERARCHICAL_FACTOR3_ORDER_FROZEN",
        "implementation_commitment_sha256": implementation[
            "implementation_commitment_sha256"
        ],
        "calibration_commitment_sha256": calibration[
            "calibration_commitment_sha256"
        ],
        **essential,
        "calibration_summary": calibration_summary,
        "model_role_order": list(MODEL_ROLES),
        "outer_source_role_order": list(OUTER_ROLES),
        "wide_source_orders": wide_sources,
        "wide_source_orders_sha256": canonical_sha256(wide_sources),
        "weighted_wide_order": weighted_order,
        "outer_source_orders": outer_sources,
        "outer_source_orders_sha256": canonical_sha256(outer_sources),
        "selected_order": selected,
        "diversity_panel": diversity,
        "information_boundary": {
            "calibration_uses_A375_knownkey_panel_only": True,
            "A382_four_W49_reader_orders_reused_without_refit": True,
            "A381_or_A383_progress_or_filter_outcomes_consumed": False,
            "A381_or_A383_result_available_at_order_freeze": False,
            "W49_secret_assignment_or_true_prefix_available": False,
            "W49_target_labels_used": 0,
            "candidate_assignments_executed_by_A386": 0,
        },
        "anchors": {
            "design": anchor(DESIGN, DESIGN_SHA256),
            "implementation": anchor(IMPLEMENTATION, expected_implementation_sha256),
            "calibration": anchor(CALIBRATION, expected_calibration_sha256),
            "A375_result": anchor(A375_RESULT, A375_RESULT_SHA256),
            "A382_runner": anchor(A382_RUNNER, A382_RUNNER_SHA256),
            "A382_order": anchor(A382_ORDER, A382_ORDER_SHA256),
            "A382_causal": anchor(A382_CAUSAL, A382_CAUSAL_SHA256),
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
            "# A386 — calibrated ticketed W49 hierarchical factor-three order\n\n"
            f"Evidence stage: **{payload['evidence_stage']}**\n\n"
            f"- Exhaustive normalized ticket vectors: **{calibration_summary['vectors_evaluated']:,}**\n"
            f"- Selected Reader tickets `{list(tickets)}` for `{list(MODEL_ROLES)}`\n"
            f"- Minimax gain over equal tickets: **{calibration_summary['minimax_gain_over_equal_bits']:+.6f} bit**\n"
            f"- Minimax gain over best single Reader: **{calibration_summary['minimax_gain_over_best_single_bits']:+.6f} bit**\n"
            f"- Weighted per-reader pointwise violations: **{weighted_proof['violations']}**\n"
            f"- Outer exact bound: **{outer_proof['bound']}**, violations **{outer_proof['violations']}**\n"
            "- W49 labels / W49 recovery outcomes / A386 candidates: **0 / 0 / 0**\n"
            "- Authentic AI-native Causal readback: **4 explicit + 1 inferred**\n"
        ).encode(),
    )
    assert_target_unrevealed()
    return payload


def load_order(expected_sha256: str) -> dict[str, Any]:
    if file_sha256(ORDER) != expected_sha256:
        raise RuntimeError("A386 order hash differs")
    value = json.loads(ORDER.read_bytes())
    wide_sources = {
        role: exact_order(order, W49_CELLS, f"stored wide {role}")
        for role, order in value.get("wide_source_orders", {}).items()
    }
    outer_sources = {
        role: exact_order(order, W49_CELLS, f"stored outer {role}")
        for role, order in value.get("outer_source_orders", {}).items()
    }
    weighted = exact_order(value.get("weighted_wide_order", []), W49_CELLS, "stored weighted")
    selected = exact_order(value.get("selected_order", []), W49_CELLS, "stored selected")
    tickets = tuple(int(item) for item in value.get("selected_ticket_vector", []))
    if (
        value.get("schema")
        != "chacha20-round20-w49-calibrated-ticketed-hierarchical-factor3-a386-order-v1"
        or tuple(value.get("model_role_order", [])) != MODEL_ROLES
        or tuple(value.get("outer_source_role_order", [])) != OUTER_ROLES
        or value.get("W49_target_labels_used") != 0
        or value.get("W49_candidate_or_filter_outcomes_used") != 0
        or value.get("candidate_assignments_executed_by_A386") != 0
        or value.get("wide_source_orders_sha256") != canonical_sha256(wide_sources)
        or value.get("outer_source_orders_sha256") != canonical_sha256(outer_sources)
        or weighted
        != ticketed_wavefront(wide_sources, MODEL_ROLES, tickets, size=W49_CELLS)
        or value.get("weighted_pointwise_proof")
        != ticketed_pointwise_proof(
            wide_sources, MODEL_ROLES, tickets, weighted, size=W49_CELLS
        )
        or selected != factor3_wavefront(outer_sources)
        or value.get("outer_factor3_proof") != factor3_proof(outer_sources, selected)
        or value.get("selected_order_uint16be_sha256") != order_sha256(selected)
    ):
        raise RuntimeError("A386 frozen order semantics differ")
    for row in value["anchors"].values():
        anchor(path_from_ref(row["path"]), row["sha256"])
    anchor(path_from_ref(value["causal"]["path"]), value["causal"]["sha256"])
    load_calibration(value["calibration_sha256"])
    return value


def analyze() -> dict[str, Any]:
    payload: dict[str, Any] = {
        "attempt_id": ATTEMPT_ID,
        "design_sha256": DESIGN_SHA256,
        "implementation_frozen": IMPLEMENTATION.exists(),
        "calibration_frozen": CALIBRATION.exists(),
        "order_frozen": ORDER.exists(),
    }
    if IMPLEMENTATION.exists():
        payload["implementation_sha256"] = file_sha256(IMPLEMENTATION)
    if CALIBRATION.exists():
        payload["calibration_sha256"] = file_sha256(CALIBRATION)
        payload["selected_ticket_vector"] = json.loads(CALIBRATION.read_bytes())[
            "selected_ticket_vector"
        ]
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
    action.add_argument("--freeze-calibration", action="store_true")
    action.add_argument("--freeze-order", action="store_true")
    parser.add_argument("--expected-implementation-sha256")
    parser.add_argument("--expected-calibration-sha256")
    args = parser.parse_args()
    if args.freeze_implementation:
        payload = freeze_implementation()
    elif args.freeze_calibration:
        if not args.expected_implementation_sha256:
            parser.error("--freeze-calibration requires --expected-implementation-sha256")
        payload = freeze_calibration(
            expected_implementation_sha256=args.expected_implementation_sha256
        )
    elif args.freeze_order:
        if not args.expected_implementation_sha256 or not args.expected_calibration_sha256:
            parser.error(
                "--freeze-order requires --expected-implementation-sha256 and --expected-calibration-sha256"
            )
        payload = freeze_order(
            expected_implementation_sha256=args.expected_implementation_sha256,
            expected_calibration_sha256=args.expected_calibration_sha256,
        )
    else:
        payload = analyze()
    print(json.dumps(payload, indent=2, sort_keys=True), flush=True)


if __name__ == "__main__":
    main()

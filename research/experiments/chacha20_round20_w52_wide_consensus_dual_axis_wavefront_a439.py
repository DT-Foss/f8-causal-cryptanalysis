#!/usr/bin/env python3
"""A439: refit-free A375 wide-consensus transfer to both W52 axes."""

from __future__ import annotations

import argparse
import hashlib
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

DESIGN = (
    CONFIGS
    / "chacha20_round20_w52_wide_consensus_dual_axis_wavefront_a439_design_v1.json"
)
IMPLEMENTATION = (
    CONFIGS
    / "chacha20_round20_w52_wide_consensus_dual_axis_wavefront_a439_implementation_v1.json"
)
RESULT = (
    RESULTS
    / "chacha20_round20_w52_wide_consensus_dual_axis_wavefront_a439_v1.json"
)
CAUSAL = RESULT.with_suffix(".causal")
REPORT = RESULT.with_suffix(".md")
TEST = (
    ROOT
    / "tests/test_chacha20_round20_w52_wide_consensus_dual_axis_wavefront_a439.py"
)
REPRO = (
    ROOT
    / "scripts/reproduce_chacha20_round20_w52_wide_consensus_dual_axis_wavefront_a439.sh"
)

A375_RUNNER = RESEARCH / "experiments/chacha20_round20_w46_wide_consensus_reader_a375.py"
A375_RESULT = RESULTS / "chacha20_round20_w46_wide_consensus_reader_a375_v1.json"
A375_CAUSAL = A375_RESULT.with_suffix(".causal")
A376_RUNNER = (
    RESEARCH
    / "experiments/chacha20_round20_w46_a375_reader_sealed_a361_order_a376.py"
)
A432_RUNNER = (
    RESEARCH
    / "experiments/chacha20_round20_w52_public_output_direct12_eight_worker_a432.py"
)
A432_RESULT = (
    RESULTS / "chacha20_round20_w52_public_output_direct12_eight_worker_a432_v1.json"
)
A432_CAUSAL = A432_RESULT.with_suffix(".causal")
A433_RUNNER = (
    RESEARCH
    / "experiments/chacha20_round20_w52_prefix_aligned_direct12_eight_worker_a433_v2.py"
)
A433_RESULT = (
    RESULTS / "chacha20_round20_w52_prefix_aligned_direct12_eight_worker_a433_v2.json"
)
A433_CAUSAL = A433_RESULT.with_suffix(".causal")
A434_RUNNER = (
    RESEARCH / "experiments/chacha20_round20_w52_dual_axis_square_wavefront_a434.py"
)
A436_RUNNER = (
    RESEARCH / "experiments/chacha20_round20_w52_corrected_off_axis_reader_a436.py"
)
A436_RESULT = RESULTS / "chacha20_round20_w52_corrected_off_axis_reader_a436_v1.json"
A436_CAUSAL = A436_RESULT.with_suffix(".causal")

ATTEMPT_ID = "A439"
DESIGN_SHA256 = "b8a57f3ae46d394ef70c66bd6d75bc8fbd284500a9e8d4447c0a89723c8daecf"
A375_RUNNER_SHA256 = "e41a91b225b861abd669280a4044dddf5e2b24e8f6e8c66e7eee6d5a149ec9f1"
A375_RESULT_SHA256 = "fc7135af9e001eb8cd83a55902e48f5776dc24a4eb86a162d7d783a115b38ef1"
A375_CAUSAL_SHA256 = "adc5fc921da7c7429407fabc637ff03c27e15705fde6ea157fc31acae25f9825"
A376_RUNNER_SHA256 = "8a74a7cd015e77806809bacb2417ced7ea1deb0f4df7c8c51a06fa4b3daf8a31"
A432_RUNNER_SHA256 = "22b00e57cf06fd6c6e5e5e5be1766101ce1500d4e47dbe035a257ec271a0270e"
A432_RESULT_SHA256 = "3d0ed27a25288db589ddb6608407314d1fa32f4cb678806e142eb819159a7e6d"
A432_CAUSAL_SHA256 = "e08948ffcb85766c0c4dcf74ce4c965c77003358ab3e5e6a0755fbbbaee2ea72"
A433_RUNNER_SHA256 = "17a466cbb7be143e4ed77c48d975ac54c1cc860aee5964dfd5c7ca4f020b7442"
A433_RESULT_SHA256 = "3ffa28081437ed12276bac868ca1de780fe2d419ea986c68fba52098c0649e07"
A433_CAUSAL_SHA256 = "3c9ac990753e6763c8d61fbfa773f75e023edf5f60613eca36f5ebc1ea07f818"
A434_RUNNER_SHA256 = "feb01a654135ed03451c3207d4f10195de0bc81ec26ce755d5e0d1eeb7ce9a1b"
A436_RUNNER_SHA256 = "ea2d0d85dd59947d074babd60779ffe679c635c25f19ef0ee1bcc404b365fef0"
A436_RESULT_SHA256 = "28e35b1bc2cefbf90c7358ca09f61f8028e9ebdcda6fbf69e3107c3389eb2baf"
A436_CAUSAL_SHA256 = "2dce03d1fed10da0c22618f37cad6242a67598ad3c3c64498b572a2ecded672d"

MODEL_ROLES = ("wide_vote", "sparse_reciprocal", "broad_quantile", "broad_intersection")
SLICES = tuple(range(16))
WITHIN_CELLS = 256
FEATURES = 532
AXIS_CELLS = 4096
PAIR_CELLS = AXIS_CELLS * AXIS_CELLS
CELL_ASSIGNMENTS = 1 << 28
DOMAIN_ASSIGNMENTS = PAIR_CELLS * CELL_ASSIGNMENTS
WORKERS = 8
WORKER_TASKS = PAIR_CELLS // WORKERS
TOP_KS = (16, 64, 256)
DOTCAUSAL_SRC = Path(
    "/Users/bhkmie/Documents/Forschung/O1/vendor/fabel/dotcausal_package/src"
)


def load_module(path: Path, name: str) -> Any:
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot import A439 dependency {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


A375 = load_module(A375_RUNNER, "a439_a375")
A376 = load_module(A376_RUNNER, "a439_a376")
A432 = load_module(A432_RUNNER, "a439_a432")
A433 = load_module(A433_RUNNER, "a439_a433")
A434 = load_module(A434_RUNNER, "a439_a434")

file_sha256 = A375.file_sha256
canonical_sha256 = A375.canonical_sha256
atomic_json = A375.atomic_json
atomic_bytes = A375.atomic_bytes
anchor = A375.anchor
path_from_ref = A375.path_from_ref
relative = A375.relative


def exact_axis_order(values: Sequence[int], label: str) -> list[int]:
    order = [int(value) for value in values]
    if len(order) != AXIS_CELLS or set(order) != set(range(AXIS_CELLS)):
        raise ValueError(f"A439 {label} is not an exact 4,096-cell order")
    return order


def order_sha256(values: Sequence[int]) -> str:
    order = exact_axis_order(values, "hash input")
    return hashlib.sha256(
        b"".join(value.to_bytes(2, "big") for value in order)
    ).hexdigest()


def rank_vector(order: Sequence[int]) -> np.ndarray:
    values = exact_axis_order(order, "rank vector")
    ranks = np.empty(AXIS_CELLS, dtype=np.int64)
    for rank, cell in enumerate(values, 1):
        ranks[cell] = rank
    return ranks


def load_design() -> dict[str, Any]:
    if file_sha256(DESIGN) != DESIGN_SHA256:
        raise RuntimeError("A439 design hash differs")
    value = json.loads(DESIGN.read_bytes())
    reader = value.get("reader_contract", {})
    axes = value.get("axis_contract", {})
    pair = value.get("pair_schedule_contract", {})
    boundary = value.get("information_boundary", {})
    if (
        value.get("schema")
        != "chacha20-round20-w52-wide-consensus-dual-axis-wavefront-a439-design-v1"
        or value.get("attempt_id") != ATTEMPT_ID
        or tuple(reader.get("model_roles", [])) != MODEL_ROLES
        or reader.get("features_per_cell") != FEATURES
        or reader.get("within_slice_cells") != WITHIN_CELLS
        or reader.get("slices_per_axis") != len(SLICES)
        or reader.get("cells_per_axis") != AXIS_CELLS
        or reader.get("reader_refits") != 0
        or reader.get("target_labels_used") != 0
        or axes.get("each_axis_pointwise_bound")
        != "R_axis_portfolio(c) <= 4 * min_reader R_reader(c)"
        or pair.get("pair_cells") != PAIR_CELLS
        or pair.get("residual_assignments_per_pair_cell") != CELL_ASSIGNMENTS
        or pair.get("complete_domain_assignments") != DOMAIN_ASSIGNMENTS
        or pair.get("workers") != WORKERS
        or pair.get("worker_tasks_each") != WORKER_TASKS
        or pair.get("duplicate_free_complete_cover") is not True
        or boundary.get("A375_models_frozen_before_A432_or_A433_measurement") is not True
        or boundary.get("A375_models_changed_or_refit_for_A439") is not False
        or boundary.get("A426_secret_true_pair_result_stop_or_worker_progress_read_for_A439_design")
        is not False
        or boundary.get("A439_target_labels_used") != 0
        or boundary.get("A439_reader_refits") != 0
        or boundary.get("A439_candidate_assignments_executed") != 0
    ):
        raise RuntimeError("A439 frozen design semantics differ")
    sources = value["source_anchors"]
    for key, item in sources.items():
        if key.endswith("_path"):
            stem = key.removesuffix("_path")
            anchor(ROOT / item, sources[f"{stem}_sha256"])
    return value


def load_source_metadata() -> tuple[dict[str, Any], dict[str, Any], dict[str, Any], dict[str, Any]]:
    anchor(A375_RESULT, A375_RESULT_SHA256)
    anchor(A375_CAUSAL, A375_CAUSAL_SHA256)
    anchor(A432_RESULT, A432_RESULT_SHA256)
    anchor(A432_CAUSAL, A432_CAUSAL_SHA256)
    anchor(A433_RESULT, A433_RESULT_SHA256)
    anchor(A433_CAUSAL, A433_CAUSAL_SHA256)
    anchor(A436_RESULT, A436_RESULT_SHA256)
    anchor(A436_CAUSAL, A436_CAUSAL_SHA256)
    a375 = json.loads(A375_RESULT.read_bytes())
    a432 = json.loads(A432_RESULT.read_bytes())
    a433 = json.loads(A433_RESULT.read_bytes())
    a436 = json.loads(A436_RESULT.read_bytes())
    definitions = a375.get("model_definitions", {})
    evaluations = a375.get("model_evaluations", {})
    if (
        a375.get("schema") != "chacha20-round20-w46-wide-consensus-reader-a375-v1"
        or set(definitions) != set(MODEL_ROLES)
        or set(evaluations) != set(MODEL_ROLES)
        or any(evaluations[role].get("positive_fixed_block_count") != 8 for role in MODEL_ROLES)
        or any(evaluations[role].get("minimum_fixed_block_bit_gain", 0.0) <= 0.0 for role in MODEL_ROLES)
        or a375.get("candidate_assignments_executed") != 0
    ):
        raise RuntimeError("A439 A375 portfolio semantics differ")
    if (
        a432.get("schema")
        != "chacha20-round20-w52-public-output-direct12-eight-worker-a432-result-v1"
        or len(a432.get("measurement_ledger", [])) != len(SLICES)
        or a432.get("measurement_summary", {}).get("complete_direct12_cells") != AXIS_CELLS
        or a432.get("target_labels_used") != 0
        or a432.get("reader_refits") != 0
        or a432.get("candidate_assignments_executed") != 0
        or a432.get("A426_progress_or_filter_outcomes_consumed") is not False
    ):
        raise RuntimeError("A439 A432 field semantics differ")
    coordinate = a433.get("coordinate_contract", {})
    if (
        a433.get("schema")
        != "chacha20-round20-w52-prefix-aligned-direct12-eight-worker-a433-result-v2"
        or len(a433.get("measurement_ledger", [])) != len(SLICES)
        or coordinate.get("A433_prefix_aligned_measured_assignment_bit_interval")
        != [20, 31]
        or coordinate.get("A432_off_axis_measured_assignment_bit_interval") != [40, 51]
        or coordinate.get("all_4096_cells_match_A422_group_ids") is not True
        or a433.get("target_labels_used") != 0
        or a433.get("reader_refits") != 0
        or a433.get("candidate_assignments_executed") != 0
        or a433.get("A426_progress_or_filter_outcomes_consumed") is not False
    ):
        raise RuntimeError("A439 A433 field semantics differ")
    if (
        a436.get("schema") != "chacha20-round20-w52-corrected-off-axis-reader-a436-result-v1"
        or a436.get("selected_view") != "A342_selected_pair_global_raw"
        or a436.get("measurement_summary", {}).get("complete_off_axis_cells") != AXIS_CELLS
        or a436.get("measurement_summary", {}).get("new_solver_stages") != 0
        or a436.get("target_labels_used") != 0
        or a436.get("reader_refits") != 0
        or a436.get("candidate_assignments_executed") != 0
        or a436.get("A426_progress_or_filter_outcomes_consumed") is not False
        or a436.get("A426_result_or_true_assignment_available_at_assembly") is not False
    ):
        raise RuntimeError("A439 A436 coordinate correction semantics differ")
    return a375, a432, a433, a436


def freeze_implementation() -> dict[str, Any]:
    if any(path.exists() for path in (IMPLEMENTATION, RESULT, CAUSAL, REPORT)):
        raise FileExistsError("A439 implementation or result already exists")
    design = load_design()
    a375, a432, a433, a436 = load_source_metadata()
    if not TEST.exists() or not REPRO.exists():
        raise FileNotFoundError("A439 tests and reproducer must precede implementation freeze")
    payload: dict[str, Any] = {
        "schema": "chacha20-round20-w52-wide-consensus-dual-axis-wavefront-a439-implementation-v1",
        "attempt_id": ATTEMPT_ID,
        "commitment_state": "frozen_after_geometry_only_probe_before_A375_scoring_source_orders_axis_portfolios_pair_schedule_or_candidates",
        "design_sha256": DESIGN_SHA256,
        "A375_result_sha256": A375_RESULT_SHA256,
        "A375_selection_commitment_sha256": a375["selection_commitment_sha256"],
        "model_role_order": list(MODEL_ROLES),
        "model_definitions": a375["model_definitions"],
        "A432_measurement_sha256": a432["measurement_sha256"],
        "A433_measurement_sha256": a433["measurement_sha256"],
        "A436_selection_commitment_sha256": a436["selection_commitment_sha256"],
        "pre_design_compatibility_probe": design["information_boundary"]["pre_design_open_scope"],
        "A375_scores_or_A439_orders_computed_at_implementation_freeze": False,
        "A426_secret_true_pair_result_stop_or_worker_progress_read": False,
        "target_labels_used": 0,
        "reader_refits": 0,
        "candidate_assignments_executed": 0,
        "anchors": {
            "design": anchor(DESIGN, DESIGN_SHA256),
            "A375_runner": anchor(A375_RUNNER, A375_RUNNER_SHA256),
            "A375_result": anchor(A375_RESULT, A375_RESULT_SHA256),
            "A375_causal": anchor(A375_CAUSAL, A375_CAUSAL_SHA256),
            "A376_runner": anchor(A376_RUNNER, A376_RUNNER_SHA256),
            "A432_runner": anchor(A432_RUNNER, A432_RUNNER_SHA256),
            "A432_result": anchor(A432_RESULT, A432_RESULT_SHA256),
            "A432_causal": anchor(A432_CAUSAL, A432_CAUSAL_SHA256),
            "A433_runner": anchor(A433_RUNNER, A433_RUNNER_SHA256),
            "A433_result": anchor(A433_RESULT, A433_RESULT_SHA256),
            "A433_causal": anchor(A433_CAUSAL, A433_CAUSAL_SHA256),
            "A434_runner": anchor(A434_RUNNER, A434_RUNNER_SHA256),
            "A436_runner": anchor(A436_RUNNER, A436_RUNNER_SHA256),
            "A436_result": anchor(A436_RESULT, A436_RESULT_SHA256),
            "A436_causal": anchor(A436_CAUSAL, A436_CAUSAL_SHA256),
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
        raise RuntimeError("A439 implementation hash differs")
    value = json.loads(IMPLEMENTATION.read_bytes())
    if (
        value.get("schema")
        != "chacha20-round20-w52-wide-consensus-dual-axis-wavefront-a439-implementation-v1"
        or value.get("attempt_id") != ATTEMPT_ID
        or value.get("design_sha256") != DESIGN_SHA256
        or tuple(value.get("model_role_order", [])) != MODEL_ROLES
        or value.get("A375_scores_or_A439_orders_computed_at_implementation_freeze") is not False
        or value.get("A426_secret_true_pair_result_stop_or_worker_progress_read") is not False
        or value.get("target_labels_used") != 0
        or value.get("reader_refits") != 0
        or value.get("candidate_assignments_executed") != 0
    ):
        raise RuntimeError("A439 frozen implementation semantics differ")
    for row in value["anchors"].values():
        anchor(path_from_ref(row["path"]), row["sha256"])
    unsigned = {
        key: item for key, item in value.items() if key != "implementation_commitment_sha256"
    }
    if value.get("implementation_commitment_sha256") != canonical_sha256(unsigned):
        raise RuntimeError("A439 implementation commitment differs")
    return value


def load_axis_measurements(
    source: Mapping[str, Any], module: Any, axis_name: str
) -> dict[int, dict[str, Any]]:
    ledgers = sorted(source["measurement_ledger"], key=lambda row: int(row["low4"]))
    if [int(row["low4"]) for row in ledgers] != list(SLICES):
        raise RuntimeError(f"A439 {axis_name} ledger cover differs")
    result: dict[int, dict[str, Any]] = {}
    for ledger in ledgers:
        low4 = int(ledger["low4"])
        value = module.read_measurement(path_from_ref(ledger["path"]), ledger)
        module.validate_measurement(value, low4)
        result[low4] = value
    return result


def build_axis(
    *,
    axis_name: str,
    source: Mapping[str, Any],
    module: Any,
    model_definitions: Mapping[str, Mapping[str, Any]],
) -> dict[str, Any]:
    measurements = load_axis_measurements(source, module, axis_name)
    normalized_slice_sha256: dict[int, str] = {}
    within_slice_rank_fields: dict[str, dict[int, list[int]]] = {
        role: {} for role in MODEL_ROLES
    }
    within_slice_orders: dict[str, dict[int, list[int]]] = {
        role: {} for role in MODEL_ROLES
    }
    for low4 in SLICES:
        matrix = A375.A275._target_feature_matrix(measurements[low4])  # noqa: SLF001
        normalized = np.asarray(A375.A360.target_normalize(matrix), dtype=np.float64)
        if normalized.shape != (WITHIN_CELLS, FEATURES) or not np.isfinite(normalized).all():
            raise RuntimeError(f"A439 {axis_name} normalized slice geometry differs")
        normalized_slice_sha256[low4] = hashlib.sha256(
            np.asarray(normalized, dtype="<f8").tobytes()
        ).hexdigest()
        feature_fields = A376.slice_feature_rank_fields(normalized)
        for role in MODEL_ROLES:
            ranks = A376.aggregate_slice_rank_field(
                feature_fields, model_definitions[role]
            )
            within_slice_rank_fields[role][low4] = [int(value) for value in ranks]
            within_slice_orders[role][low4] = A376.within_order(ranks)
    source_orders = {
        role: exact_axis_order(
            A376.A361.compose_round_robin(within_slice_orders[role]),
            f"{axis_name} source {role}",
        )
        for role in MODEL_ROLES
    }
    portfolio = exact_axis_order(
        A376.factor_k_wavefront(source_orders, MODEL_ROLES),
        f"{axis_name} factor-four portfolio",
    )
    proof = A376.factor_k_proof(source_orders, MODEL_ROLES, portfolio)
    if proof.get("maximum_ratio", math.inf) > 4.0 or proof.get("violations") != 0:
        raise RuntimeError(f"A439 {axis_name} factor-four proof failed")
    return {
        "axis": axis_name,
        "normalized_slice_sha256": normalized_slice_sha256,
        "normalized_slice_set_sha256": canonical_sha256(normalized_slice_sha256),
        "within_slice_rank_fields": within_slice_rank_fields,
        "within_slice_rank_fields_sha256": canonical_sha256(within_slice_rank_fields),
        "within_slice_orders": within_slice_orders,
        "within_slice_orders_sha256": canonical_sha256(within_slice_orders),
        "source_orders": source_orders,
        "source_order_uint16be_sha256": {
            role: order_sha256(source_orders[role]) for role in MODEL_ROLES
        },
        "source_orders_sha256": canonical_sha256(source_orders),
        "portfolio_order": portfolio,
        "portfolio_order_uint16be_sha256": order_sha256(portfolio),
        "pointwise_factor4_proof": proof,
        "reader_refits": 0,
        "target_labels_used": 0,
        "candidate_assignments_executed": 0,
    }


def order_pair_metrics(left: Sequence[int], right: Sequence[int]) -> dict[str, Any]:
    left_order = exact_axis_order(left, "diversity left")
    right_order = exact_axis_order(right, "diversity right")
    left_ranks = rank_vector(left_order).astype(np.float64)
    right_ranks = rank_vector(right_order).astype(np.float64)
    correlation = float(np.corrcoef(left_ranks, right_ranks)[0, 1])
    if not math.isfinite(correlation):
        raise RuntimeError("A439 diversity correlation is non-finite")
    result: dict[str, Any] = {"spearman_rank_correlation": correlation}
    for k in TOP_KS:
        overlap = len(set(left_order[:k]).intersection(right_order[:k]))
        result[f"top{k}_overlap"] = overlap
        result[f"top{k}_jaccard"] = overlap / (2 * k - overlap)
    return result


def diversity_panel(
    prefix: Mapping[str, Any],
    off_axis: Mapping[str, Any],
    a433: Mapping[str, Any],
    a436: Mapping[str, Any],
) -> dict[str, Any]:
    within_axis: dict[str, dict[str, Any]] = {}
    for axis_name, axis in (("prefix", prefix), ("off_axis", off_axis)):
        roles: dict[str, Any] = {}
        for left_index, left in enumerate(MODEL_ROLES):
            for right in MODEL_ROLES[left_index + 1 :]:
                roles[f"{left}__{right}"] = order_pair_metrics(
                    axis["source_orders"][left], axis["source_orders"][right]
                )
        within_axis[axis_name] = roles
    cross_axis = {
        role: order_pair_metrics(
            prefix["source_orders"][role], off_axis["source_orders"][role]
        )
        for role in MODEL_ROLES
    }
    existing = {
        "prefix_portfolio_vs_A433_selected": order_pair_metrics(
            prefix["portfolio_order"], a433["W52_prefix_aligned_direct12_order"]
        ),
        "off_axis_portfolio_vs_A436_selected": order_pair_metrics(
            off_axis["portfolio_order"], a436["W52_corrected_off_axis_order"]
        ),
    }
    return {
        "within_axis_pairwise": within_axis,
        "cross_axis_same_role": cross_axis,
        "portfolio_vs_existing_single_view": existing,
        "target_labels_used": 0,
    }


def square_rank_one_based_from_zero_ranks(left: np.ndarray, right: np.ndarray) -> np.ndarray:
    left_values = np.asarray(left, dtype=np.int64)
    right_values = np.asarray(right, dtype=np.int64)
    shell = np.maximum(left_values, right_values)
    index = np.where(
        left_values == shell,
        shell * shell + right_values,
        shell * shell + shell + 1 + left_values,
    )
    return index + 1


def factor16_shell_proof(
    prefix_source_orders: Mapping[str, Sequence[int]],
    off_axis_source_orders: Mapping[str, Sequence[int]],
    prefix_portfolio: Sequence[int],
    off_axis_portfolio: Sequence[int],
) -> dict[str, Any]:
    if set(prefix_source_orders) != set(MODEL_ROLES) or set(off_axis_source_orders) != set(
        MODEL_ROLES
    ):
        raise ValueError("A439 factor-sixteen source-role cover differs")
    prefix_min = np.min(
        np.stack([rank_vector(prefix_source_orders[role]) for role in MODEL_ROLES]),
        axis=0,
    )
    off_axis_min = np.min(
        np.stack([rank_vector(off_axis_source_orders[role]) for role in MODEL_ROLES]),
        axis=0,
    )
    prefix_rank = rank_vector(prefix_portfolio)
    off_axis_rank = rank_vector(off_axis_portfolio)
    violations = 0
    maximum_ratio = 0.0
    ratio_sum = 0.0
    maximum_slack = 0
    for prefix_cell in range(AXIS_CELLS):
        left = np.full(AXIS_CELLS, prefix_rank[prefix_cell] - 1, dtype=np.int64)
        right = off_axis_rank - 1
        pair_rank = square_rank_one_based_from_zero_ranks(left, right)
        ideal_shell = np.maximum(prefix_min[prefix_cell], off_axis_min)
        envelope = 16 * ideal_shell * ideal_shell
        delta = pair_rank - envelope
        violations += int(np.count_nonzero(delta > 0))
        maximum_slack = max(maximum_slack, int(np.max(envelope - pair_rank)))
        ratios = pair_rank.astype(np.float64) / (ideal_shell.astype(np.float64) ** 2)
        maximum_ratio = max(maximum_ratio, float(np.max(ratios)))
        ratio_sum += float(np.sum(ratios))
    if violations or maximum_ratio > 16.0 + 1e-12:
        raise RuntimeError("A439 factor-sixteen shell proof failed")
    return {
        "bound": "R_A439_pair(x,y) <= 16*max(min_i R_prefix_i(x),min_j R_off_j(y))^2",
        "prefix_reader_count": len(MODEL_ROLES),
        "off_axis_reader_count": len(MODEL_ROLES),
        "pair_cells_checked": PAIR_CELLS,
        "maximum_ratio_to_best_reader_shell_squared": maximum_ratio,
        "mean_ratio_to_best_reader_shell_squared": ratio_sum / PAIR_CELLS,
        "maximum_envelope_slack_cells": maximum_slack,
        "violations": violations,
    }


def worker_location(global_index: int) -> dict[str, int | str]:
    if not 0 <= global_index < PAIR_CELLS:
        raise ValueError("A439 worker index exceeds exact pair cover")
    worker = global_index % WORKERS
    step = global_index // WORKERS + 1
    return {
        "worker_index": worker,
        "worker_role": f"wide_consensus_dual_axis_wave_{worker}",
        "worker_step_one_based": step,
        "global_rank_one_based": global_index + 1,
        "exact_parallel_depth": step,
    }


def build_causal(payload: Mapping[str, Any]) -> dict[str, Any]:
    sys.path.insert(0, str(DOTCAUSAL_SRC))
    from dotcausal.io import CausalReader, CausalWriter

    portfolio = "A375:frozen_four_reader_128_knownkey_portfolio"
    prefix_field = "A433:complete_W52_prefix_axis_field"
    off_field = "A432_A436:complete_corrected_W52_off_axis_field"
    source_orders = "A439:eight_refit_free_W52_source_orders"
    axis_orders = "A439:two_exact_factor4_axis_portfolios"
    pair_schedule = "A439:exact_factor16_shell_dual_axis_schedule"
    recovery = "A440:wide_consensus_W52_recovery_ready"
    writer = CausalWriter(api_id="a439wc2")
    writer._rules = []
    rule_rows = (
        ("portfolio_to_sources", [portfolio], source_orders),
        ("prefix_field_to_sources", [prefix_field], source_orders),
        ("off_field_to_sources", [off_field], source_orders),
        ("sources_to_axes", [source_orders], axis_orders),
        ("axes_to_pair_schedule", [axis_orders], pair_schedule),
        ("pair_schedule_to_recovery", [pair_schedule], recovery),
    )
    for name, pattern, conclusion in rule_rows:
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
            "apply_all_four_frozen_A375_readers_without_refit_to_both_axes",
            source_orders,
            {
                "knownkey_targets": 128,
                "models_per_axis": 4,
                "source_orders": 8,
                "reader_refits": 0,
            },
        ),
        (
            prefix_field,
            "normalize_all_16_complete_256x532_slices_and_score_with_frozen_models",
            source_orders,
            {
                "axis": "word0_bits31_through20",
                "cells": AXIS_CELLS,
                "solver_stages_reused": 16384,
            },
        ),
        (
            off_field,
            "normalize_all_16_complete_256x532_slices_under_corrected_coordinate_codec",
            source_orders,
            {
                "axis": "synthetic_coordinates51_through40",
                "cells": AXIS_CELLS,
                "solver_stages_reused": 16384,
            },
        ),
        (
            source_orders,
            "stable_minimum_source_rank_wavefront_with_two_complete_factor4_proofs",
            axis_orders,
            {
                "prefix": payload["axes"]["prefix"]["pointwise_factor4_proof"],
                "off_axis": payload["axes"]["off_axis"]["pointwise_factor4_proof"],
            },
        ),
        (
            axis_orders,
            "exact_neutral_square_wavefront_with_complete_pointwise_factor16_shell_proof",
            pair_schedule,
            payload["pair_schedule"]["pointwise_factor16_shell_proof"],
        ),
        (
            pair_schedule,
            "freeze_duplicate_free_2power24_pair_stream_before_any_candidate_or_target_outcome",
            recovery,
            {
                "pair_stream_sha256": payload["pair_schedule"]["pair_stream_uint16be_uint16be_sha256"],
                "pair_cells": PAIR_CELLS,
                "workers": WORKERS,
                "candidate_assignments_executed": 0,
            },
        ),
    )
    for trigger, mechanism, outcome, quantification in rows:
        writer.add_triplet(
            trigger=trigger,
            mechanism=mechanism,
            outcome=outcome,
            confidence=1.0,
            source=payload["result_commitment_sha256"],
            quantification=json.dumps(quantification, sort_keys=True),
            evidence=payload["evidence_stage"],
            domain="ChaCha20 R20 W52 wide-consensus dual-axis search",
            quality_score=1.0,
        )
    writer.add_triplet(
        trigger=portfolio,
        mechanism="materialized_frozen_reader_to_factor16_schedule_recovery_chain",
        outcome=recovery,
        confidence=1.0,
        source="materialized:A439_wide_consensus_dual_axis_chain",
        quantification="exact retained closure",
        evidence=payload["evidence_stage"],
        domain="AI-native retained inference",
        quality_score=1.0,
        is_inferred=True,
    )
    writer.add_cluster(
        name="A439 refit-free cross-width dual-axis Reader transfer",
        entities=[portfolio, prefix_field, off_field, source_orders, axis_orders, pair_schedule, recovery],
    )
    writer.add_gap(
        subject=recovery,
        predicate="next_required_object",
        expected_object_type="A440_complete_W52_recovery_with_matched_control_and_independent_confirmation",
        confidence=1.0,
        suggested_queries=[
            "Execute the frozen A439 pair stream with the qualified W52 Metal adapter, shared stop, matched control and independent eight-block confirmation."
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
        reader.api_id != "a439wc2"
        or len(explicit) != 6
        or len(all_rows) != 7
        or len(inferred) != 1
        or len(reader._rules) != 6
        or len(reader._clusters) != 1
        or len(reader._gaps) != 1
    ):
        raise RuntimeError("A439 authentic Causal reopen gate failed")
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
            "frozen_reader_relation": explicit[0],
            "prefix_field_relation": explicit[1],
            "off_axis_field_relation": explicit[2],
            "factor4_relation": explicit[3],
            "factor16_relation": explicit[4],
            "recovery_relation": explicit[5],
            "materialized_chain": all_rows[-1],
            "next_gap": reader._gaps[0],
        },
    }


def build_result(*, expected_implementation_sha256: str) -> dict[str, Any]:
    if any(path.exists() for path in (RESULT, CAUSAL, REPORT)):
        raise FileExistsError("A439 result already exists")
    design = load_design()
    implementation = load_implementation(expected_implementation_sha256)
    a375, a432, a433, a436 = load_source_metadata()
    prefix = build_axis(
        axis_name="prefix",
        source=a433,
        module=A433,
        model_definitions=implementation["model_definitions"],
    )
    off_axis = build_axis(
        axis_name="off_axis",
        source=a432,
        module=A432,
        model_definitions=implementation["model_definitions"],
    )
    diversity = diversity_panel(prefix, off_axis, a433, a436)
    factor16 = factor16_shell_proof(
        prefix["source_orders"],
        off_axis["source_orders"],
        prefix["portfolio_order"],
        off_axis["portfolio_order"],
    )
    stream_sha = A434.pair_stream_sha256(
        prefix["portfolio_order"], off_axis["portfolio_order"]
    )
    sentinels = [0, 1, 2, 3, 15, 16, 12345, PAIR_CELLS // 2, PAIR_CELLS - 2, PAIR_CELLS - 1]
    direct_inverse = []
    for index in sentinels:
        pair = A434.square_pair_at(
            index, prefix["portfolio_order"], off_axis["portfolio_order"]
        )
        recovered = A434.pair_global_index(
            pair[0], pair[1], prefix["portfolio_order"], off_axis["portfolio_order"]
        )
        if recovered != index:
            raise RuntimeError("A439 square-wavefront direct/inverse gate failed")
        direct_inverse.append({"global_index": index, "prefix": pair[0], "off_axis": pair[1]})
    pair_schedule = {
        "algorithm": "A434 exact neutral square wavefront over A439 factor-four axis portfolios",
        "pair_cells": PAIR_CELLS,
        "assignments_per_pair_cell": CELL_ASSIGNMENTS,
        "complete_domain_assignments": DOMAIN_ASSIGNMENTS,
        "workers": WORKERS,
        "worker_tasks_each": WORKER_TASKS,
        "worker_partition": "global_index_modulo_8",
        "prefix_portfolio_order_uint16be_sha256": prefix["portfolio_order_uint16be_sha256"],
        "off_axis_portfolio_order_uint16be_sha256": off_axis["portfolio_order_uint16be_sha256"],
        "pair_stream_uint16be_uint16be_sha256": stream_sha,
        "pointwise_factor16_shell_proof": factor16,
        "direct_inverse_sentinels": direct_inverse,
        "first_pair": A434.square_pair_at(
            0, prefix["portfolio_order"], off_axis["portfolio_order"]
        ),
        "last_pair": A434.square_pair_at(
            PAIR_CELLS - 1, prefix["portfolio_order"], off_axis["portfolio_order"]
        ),
        "worker_first_locations": [worker_location(index) for index in range(WORKERS)],
        "worker_last_locations": [
            worker_location(PAIR_CELLS - WORKERS + index) for index in range(WORKERS)
        ],
        "duplicate_free_complete_cover": True,
        "streaming_generation": True,
    }
    core = {
        "schema": "chacha20-round20-w52-wide-consensus-dual-axis-wavefront-a439-v1",
        "attempt_id": ATTEMPT_ID,
        "evidence_stage": "REFIT_FREE_128_KNOWNKEY_FOUR_READER_CROSS_WIDTH_DUAL_AXIS_TRANSFER_WITH_EXACT_FACTOR16_SHELL_SCHEDULE_FROZEN",
        "design_sha256": DESIGN_SHA256,
        "implementation_sha256": expected_implementation_sha256,
        "implementation_commitment_sha256": implementation[
            "implementation_commitment_sha256"
        ],
        "A375_selection_commitment_sha256": a375["selection_commitment_sha256"],
        "model_role_order": list(MODEL_ROLES),
        "model_definitions": implementation["model_definitions"],
        "model_evaluations": a375["model_evaluations"],
        "axes": {"prefix": prefix, "off_axis": off_axis},
        "diversity": diversity,
        "pair_schedule": pair_schedule,
        "information_boundary": {
            **design["information_boundary"],
            "A375_scores_first_computed_after_A439_implementation_freeze": True,
            "A439_source_orders_first_computed_after_implementation_freeze": True,
            "A439_pair_schedule_first_computed_after_implementation_freeze": True,
            "A426_secret_true_pair_result_stop_or_worker_progress_read": False,
            "target_labels_used": 0,
            "reader_refits": 0,
            "candidate_assignments_executed": 0,
        },
        "target_labels_used": 0,
        "reader_refits": 0,
        "candidate_assignments_executed": 0,
        "anchors": {
            "design": anchor(DESIGN, DESIGN_SHA256),
            "implementation": anchor(IMPLEMENTATION, expected_implementation_sha256),
            "A375_runner": anchor(A375_RUNNER, A375_RUNNER_SHA256),
            "A375_result": anchor(A375_RESULT, A375_RESULT_SHA256),
            "A375_causal": anchor(A375_CAUSAL, A375_CAUSAL_SHA256),
            "A376_runner": anchor(A376_RUNNER, A376_RUNNER_SHA256),
            "A432_runner": anchor(A432_RUNNER, A432_RUNNER_SHA256),
            "A432_result": anchor(A432_RESULT, A432_RESULT_SHA256),
            "A432_causal": anchor(A432_CAUSAL, A432_CAUSAL_SHA256),
            "A433_runner": anchor(A433_RUNNER, A433_RUNNER_SHA256),
            "A433_result": anchor(A433_RESULT, A433_RESULT_SHA256),
            "A433_causal": anchor(A433_CAUSAL, A433_CAUSAL_SHA256),
            "A434_runner": anchor(A434_RUNNER, A434_RUNNER_SHA256),
            "A436_runner": anchor(A436_RUNNER, A436_RUNNER_SHA256),
            "A436_result": anchor(A436_RESULT, A436_RESULT_SHA256),
            "A436_causal": anchor(A436_CAUSAL, A436_CAUSAL_SHA256),
            "runner": anchor(Path(__file__)),
            "test": anchor(TEST),
            "reproducer": anchor(REPRO),
        },
    }
    core["result_commitment_sha256"] = canonical_sha256(
        {
            "design_sha256": DESIGN_SHA256,
            "implementation_commitment_sha256": core["implementation_commitment_sha256"],
            "A375_selection_commitment_sha256": core["A375_selection_commitment_sha256"],
            "prefix_source_orders_sha256": prefix["source_orders_sha256"],
            "off_axis_source_orders_sha256": off_axis["source_orders_sha256"],
            "prefix_portfolio_order_uint16be_sha256": prefix[
                "portfolio_order_uint16be_sha256"
            ],
            "off_axis_portfolio_order_uint16be_sha256": off_axis[
                "portfolio_order_uint16be_sha256"
            ],
            "pair_stream_uint16be_uint16be_sha256": stream_sha,
            "pointwise_factor16_shell_proof": factor16,
            "target_labels_used": 0,
            "reader_refits": 0,
            "candidate_assignments_executed": 0,
        }
    )
    core["causal"] = build_causal(core)
    atomic_json(RESULT, core)
    correlations = [
        row["spearman_rank_correlation"]
        for axis in diversity["within_axis_pairwise"].values()
        for row in axis.values()
    ]
    report = (
        "# A439 — refit-free wide-consensus dual-axis W52 schedule\n\n"
        f"Evidence stage: **{core['evidence_stage']}**\n\n"
        "- Frozen calibration: **128 disjoint Known-key W46 targets, four Readers**\n"
        "- W52 transfer: **two complete 4,096-cell axes, eight refit-free source orders**\n"
        f"- Prefix factor-four maximum ratio: **{prefix['pointwise_factor4_proof']['maximum_ratio']}**\n"
        f"- Off-axis factor-four maximum ratio: **{off_axis['pointwise_factor4_proof']['maximum_ratio']}**\n"
        f"- Pair factor-sixteen maximum ratio: **{factor16['maximum_ratio_to_best_reader_shell_squared']:.12f}**\n"
        f"- Pair cells proved / streamed: **{PAIR_CELLS:,} / {PAIR_CELLS:,}**\n"
        f"- Pair-stream SHA-256: **{stream_sha}**\n"
        f"- Within-axis Spearman range: **[{min(correlations):.6f}, {max(correlations):.6f}]**\n"
        "- Target labels / Reader refits / candidate executions: **0 / 0 / 0**\n"
        "- Authentic AI-native Causal readback: **6 explicit + 1 inferred**\n"
    )
    atomic_bytes(REPORT, report.encode())
    return core


def load_result(expected_sha256: str) -> dict[str, Any]:
    if file_sha256(RESULT) != expected_sha256:
        raise RuntimeError("A439 result hash differs")
    value = json.loads(RESULT.read_bytes())
    if (
        value.get("schema")
        != "chacha20-round20-w52-wide-consensus-dual-axis-wavefront-a439-v1"
        or tuple(value.get("model_role_order", [])) != MODEL_ROLES
        or value.get("pair_schedule", {}).get("pair_cells") != PAIR_CELLS
        or value.get("pair_schedule", {}).get("pointwise_factor16_shell_proof", {}).get(
            "violations"
        )
        != 0
        or value.get("target_labels_used") != 0
        or value.get("reader_refits") != 0
        or value.get("candidate_assignments_executed") != 0
    ):
        raise RuntimeError("A439 result semantics differ")
    for axis_name in ("prefix", "off_axis"):
        axis = value["axes"][axis_name]
        exact_axis_order(axis["portfolio_order"], f"stored {axis_name} portfolio")
        if axis["pointwise_factor4_proof"].get("violations") != 0:
            raise RuntimeError(f"A439 stored {axis_name} proof differs")
    for row in value["anchors"].values():
        anchor(path_from_ref(row["path"]), row["sha256"])
    anchor(path_from_ref(value["causal"]["path"]), value["causal"]["sha256"])
    return value


def analyze() -> dict[str, Any]:
    value: dict[str, Any] = {
        "attempt_id": ATTEMPT_ID,
        "design_sha256": file_sha256(DESIGN) if DESIGN.exists() else None,
        "implementation_frozen": IMPLEMENTATION.exists(),
        "result_frozen": RESULT.exists(),
    }
    if IMPLEMENTATION.exists():
        value["implementation_sha256"] = file_sha256(IMPLEMENTATION)
    if RESULT.exists():
        value["result_sha256"] = file_sha256(RESULT)
        stored = json.loads(RESULT.read_bytes())
        value["evidence_stage"] = stored["evidence_stage"]
        value["pair_stream_sha256"] = stored["pair_schedule"][
            "pair_stream_uint16be_uint16be_sha256"
        ]
        value["factor16_proof"] = stored["pair_schedule"][
            "pointwise_factor16_shell_proof"
        ]
        value["causal_sha256"] = stored["causal"]["sha256"]
    return value


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--freeze-implementation", action="store_true")
    parser.add_argument("--build-result", action="store_true")
    parser.add_argument("--expected-implementation-sha256")
    parser.add_argument("--analyze", action="store_true")
    args = parser.parse_args()
    actions = sum((args.freeze_implementation, args.build_result, args.analyze))
    if actions != 1:
        parser.error("choose exactly one action")
    if args.freeze_implementation:
        payload = freeze_implementation()
    elif args.build_result:
        if not args.expected_implementation_sha256:
            parser.error("--build-result requires --expected-implementation-sha256")
        payload = build_result(
            expected_implementation_sha256=args.expected_implementation_sha256
        )
    else:
        payload = analyze()
    print(json.dumps(payload, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()

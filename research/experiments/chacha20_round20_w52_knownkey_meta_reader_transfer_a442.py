#!/usr/bin/env python3
"""A442: calibrate fixed four-Reader rank geometries and transfer one to W52."""

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
    CONFIGS / "chacha20_round20_w52_knownkey_meta_reader_transfer_a442_design_v1.json"
)
IMPLEMENTATION = (
    CONFIGS
    / "chacha20_round20_w52_knownkey_meta_reader_transfer_a442_implementation_v1.json"
)
RESULT = RESULTS / "chacha20_round20_w52_knownkey_meta_reader_transfer_a442_v1.json"
CAUSAL = RESULT.with_suffix(".causal")
REPORT = RESULT.with_suffix(".md")
TEST = ROOT / "tests/test_chacha20_round20_w52_knownkey_meta_reader_transfer_a442.py"
REPRO = ROOT / "scripts/reproduce_chacha20_round20_w52_knownkey_meta_reader_transfer_a442.sh"

A375_RUNNER = RESEARCH / "experiments/chacha20_round20_w46_wide_consensus_reader_a375.py"
A375_RESULT = RESULTS / "chacha20_round20_w46_wide_consensus_reader_a375_v1.json"
A375_CAUSAL = A375_RESULT.with_suffix(".causal")
A439_RUNNER = (
    RESEARCH
    / "experiments/chacha20_round20_w52_wide_consensus_dual_axis_wavefront_a439.py"
)
A439_RESULT = (
    RESULTS / "chacha20_round20_w52_wide_consensus_dual_axis_wavefront_a439_v1.json"
)
A439_CAUSAL = A439_RESULT.with_suffix(".causal")
A441_RUNNER = (
    RESEARCH
    / "experiments/chacha20_round20_w52_direct_product_reader_pair_portfolio_a441.py"
)
A441_RESULT = (
    RESULTS / "chacha20_round20_w52_direct_product_reader_pair_portfolio_a441_v1.json"
)
A441_CAUSAL = A441_RESULT.with_suffix(".causal")
A434_RUNNER = (
    RESEARCH / "experiments/chacha20_round20_w52_dual_axis_square_wavefront_a434.py"
)

ATTEMPT_ID = "A442"
DESIGN_SHA256 = "75715e8f0f6f9ecd89c4e2fcafe45f859945b58c5ce1ca162a6fc69c93cd5786"
A375_RUNNER_SHA256 = "e41a91b225b861abd669280a4044dddf5e2b24e8f6e8c66e7eee6d5a149ec9f1"
A375_RESULT_SHA256 = "fc7135af9e001eb8cd83a55902e48f5776dc24a4eb86a162d7d783a115b38ef1"
A375_CAUSAL_SHA256 = "adc5fc921da7c7429407fabc637ff03c27e15705fde6ea157fc31acae25f9825"
A439_RUNNER_SHA256 = "6cb94c2c8e8e404b25b2b41c51e4fd68b038e447616c740dba549464b5f490fb"
A439_RESULT_SHA256 = "b141fb882bd1a1cdc6a22de424370fe3118c9a4eb90565eaa0c8225321b9f869"
A439_CAUSAL_SHA256 = "f27c9d0d8311d633cfa46237df44ef1daa0cf375c99ddd1f85e37cc79f26f27c"
A439_RESULT_COMMITMENT_SHA256 = (
    "391ed0597f413d31eed60d235e6bebc90b8d7cabda486c6979631a4e753c9f0f"
)
A439_PAIR_STREAM_SHA256 = "e71f783d1a6176d9f3c75443bb8d41ed5812a6f331a57c07a473ba9f2c91bc15"
A441_RUNNER_SHA256 = "7d3107eb060298d18f01e0d8278d9d2eaaa0a8baab757291cd5eede0cde1c83c"
A441_RESULT_SHA256 = "884fef4dbe25cb1bbb6cb61f7fb3697d4609a084ff8c1f75d97066538e31dafb"
A441_CAUSAL_SHA256 = "2b2f62b2761d48a2249de44e9f1d62b45440f904e425dc8128560197d1fbbe7b"
A434_RUNNER_SHA256 = "feb01a654135ed03451c3207d4f10195de0bc81ec26ce755d5e0d1eeb7ce9a1b"

MODEL_ROLES = (
    "wide_vote",
    "sparse_reciprocal",
    "broad_quantile",
    "broad_intersection",
)
OPERATORS = (
    "union_min",
    "borda_sum",
    "intersection_max",
    "upper_median",
    "geometric_mean",
    "reciprocal_sum",
    "top64_consensus",
)
CALIBRATION_TARGETS = 128
CALIBRATION_CELLS = 256
FIXED_BLOCKS = 8
AXIS_CELLS = 4096
PAIR_CELLS = 1 << 24
MATERIAL_SPEARMAN_MAX = 0.98
MATERIAL_TOP65536_OVERLAP_MAX = 0.90
METRIC_CHUNK_PAIRS = 1 << 18
TOP_KS = (256, 4096, 65536, 1048576)
DOTCAUSAL_SRC = Path(
    "/Users/bhkmie/Documents/Forschung/O1/vendor/fabel/dotcausal_package/src"
)

SENSITIVE = (
    RESULTS / "chacha20_round20_w52_a416_fresh_shared_stop_recovery_a426_v1.json",
    RESULTS
    / "chacha20_round20_w52_a416_fresh_shared_stop_recovery_a426_confirmed_stop_v1.json",
    RESULTS
    / "chacha20_round20_w52_calibration_balanced_wavefront_recovery_a438_v1.json",
    RESULTS
    / "chacha20_round20_w52_calibration_balanced_wavefront_recovery_a438_confirmed_stop_v1.json",
    RESULTS / "chacha20_round20_w52_wide_consensus_wavefront_recovery_a440_v1.json",
    RESULTS
    / "chacha20_round20_w52_wide_consensus_wavefront_recovery_a440_confirmed_stop_v1.json",
)


def load_module(path: Path, name: str) -> Any:
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot import A442 dependency {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def canonical_sha256(value: Any) -> str:
    raw = json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("ascii")
    return hashlib.sha256(raw).hexdigest()


def atomic_bytes(path: Path, raw: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    temporary.write_bytes(raw)
    os.replace(temporary, path)


def atomic_json(path: Path, value: Any) -> None:
    atomic_bytes(
        path,
        json.dumps(
            value,
            indent=2,
            sort_keys=True,
            ensure_ascii=True,
            allow_nan=False,
        ).encode("ascii")
        + b"\n",
    )


def relative(path: Path) -> str:
    resolved = path.resolve()
    try:
        return str(resolved.relative_to(ROOT.resolve()))
    except ValueError:
        return str(resolved)


def path_from_ref(value: str | Path) -> Path:
    candidate = Path(value)
    return candidate if candidate.is_absolute() else ROOT / candidate


def anchor(path: Path, expected: str | None = None) -> dict[str, str]:
    observed = file_sha256(path)
    if expected is not None and observed != expected:
        raise RuntimeError(f"A442 anchor differs: {path}")
    return {"path": relative(path), "sha256": observed}


def progress_paths() -> list[Path]:
    values: list[Path] = []
    for stem in (
        "chacha20_round20_w52_a416_fresh_shared_stop_recovery_a426",
        "chacha20_round20_w52_calibration_balanced_wavefront_recovery_a438",
        "chacha20_round20_w52_wide_consensus_wavefront_recovery_a440",
    ):
        values.extend(
            RESULTS / f"{stem}_worker_{index}_progress_v1.json"
            for index in range(8)
        )
    return values


def assert_pre_evaluation() -> None:
    if any(path.exists() for path in (*SENSITIVE, *progress_paths())):
        raise RuntimeError("A442 freeze must precede A426/A438/A440 target outcomes or progress")
    if any(path.exists() for path in (RESULT, CAUSAL, REPORT)):
        raise RuntimeError("A442 result already exists")


def exact_order(values: Sequence[int] | np.ndarray, cells: int) -> np.ndarray:
    order = np.asarray([int(value) for value in values], dtype=np.int64)
    if (
        order.shape != (cells,)
        or int(order.min(initial=0)) != 0
        or int(order.max(initial=-1)) != cells - 1
        or np.unique(order).size != cells
    ):
        raise ValueError("A442 order is not exact")
    return order


def order_to_ranks(order: Sequence[int] | np.ndarray, cells: int) -> np.ndarray:
    values = exact_order(order, cells)
    ranks = np.empty(cells, dtype=np.int64)
    ranks[values] = np.arange(1, cells + 1, dtype=np.int64)
    return ranks


def order_sha256(order: Sequence[int] | np.ndarray) -> str:
    values = exact_order(order, AXIS_CELLS)
    return hashlib.sha256(values.astype(">u2", copy=False).tobytes()).hexdigest()


def pair_stream_sha256(
    prefix_order: Sequence[int] | np.ndarray,
    off_axis_order: Sequence[int] | np.ndarray,
) -> str:
    prefix = exact_order(prefix_order, AXIS_CELLS)
    off_axis = exact_order(off_axis_order, AXIS_CELLS)
    digest = hashlib.sha256()
    chunk = bytearray()
    count = 0
    for shell in range(AXIS_CELLS):
        for off_rank in range(shell + 1):
            chunk.extend(int(prefix[shell]).to_bytes(2, "big"))
            chunk.extend(int(off_axis[off_rank]).to_bytes(2, "big"))
            count += 1
        for prefix_rank in range(shell):
            chunk.extend(int(prefix[prefix_rank]).to_bytes(2, "big"))
            chunk.extend(int(off_axis[shell]).to_bytes(2, "big"))
            count += 1
        if len(chunk) >= 1 << 20:
            digest.update(chunk)
            chunk.clear()
    digest.update(chunk)
    if count != PAIR_CELLS:
        raise RuntimeError("A442 pair-stream cover differs")
    return digest.hexdigest()


def reference_square_rank_vector(
    prefix_order: Sequence[int] | np.ndarray,
    off_axis_order: Sequence[int] | np.ndarray,
) -> np.ndarray:
    prefix_ranks = order_to_ranks(prefix_order, AXIS_CELLS) - 1
    off_ranks = order_to_ranks(off_axis_order, AXIS_CELLS) - 1
    output = np.empty(PAIR_CELLS, dtype=np.uint32)
    off_cells = np.arange(AXIS_CELLS, dtype=np.int64)
    right = off_ranks[off_cells]
    for prefix in range(AXIS_CELLS):
        left = np.full(AXIS_CELLS, prefix_ranks[prefix], dtype=np.int64)
        shell = np.maximum(left, right)
        rank = np.where(
            left == shell,
            shell * shell + right,
            shell * shell + shell + 1 + left,
        ) + 1
        start = prefix * AXIS_CELLS
        output[start : start + AXIS_CELLS] = rank.astype(np.uint32)
    if (
        int(output.min()) != 1
        or int(output.max()) != PAIR_CELLS
        or int(output.astype(np.uint64).sum())
        != PAIR_CELLS * (PAIR_CELLS + 1) // 2
    ):
        raise RuntimeError("A442 square-wavefront rank vector is not exact")
    return output


def compare_rank_orders(
    direct_rank: np.ndarray, reference_rank: np.ndarray
) -> dict[str, Any]:
    if direct_rank.shape != reference_rank.shape or direct_rank.ndim != 1:
        raise ValueError("A442 pair-rank comparison shape differs")
    pair_cells = direct_rank.size
    earlier = int(np.count_nonzero(direct_rank < reference_rank))
    equal = int(np.count_nonzero(direct_rank == reference_rank))
    later = pair_cells - earlier - equal
    mean = (pair_cells + 1.0) / 2.0
    variance = (pair_cells * pair_cells - 1.0) / 12.0
    covariance_sum = 0.0
    ratio = np.empty(pair_cells, dtype=np.float32)
    for start in range(0, pair_cells, METRIC_CHUNK_PAIRS):
        stop = min(start + METRIC_CHUNK_PAIRS, pair_cells)
        direct = direct_rank[start:stop].astype(np.float64)
        reference = reference_rank[start:stop].astype(np.float64)
        covariance_sum += float(np.dot(direct - mean, reference - mean))
        ratio[start:stop] = (direct / reference).astype(np.float32)
    spearman = covariance_sum / (pair_cells * variance)
    quantiles = np.quantile(
        ratio, [0.0, 0.01, 0.1, 0.25, 0.5, 0.75, 0.9, 0.99, 1.0]
    )
    top_k = {
        str(k): {
            "intersection": int(
                np.count_nonzero((direct_rank <= k) & (reference_rank <= k))
            ),
            "union": int(
                np.count_nonzero((direct_rank <= k) | (reference_rank <= k))
            ),
        }
        for k in TOP_KS
        if k <= pair_cells
    }
    return {
        "pair_cells": pair_cells,
        "direct_earlier": earlier,
        "equal": equal,
        "direct_later": later,
        "direct_earlier_fraction": earlier / pair_cells,
        "direct_later_fraction": later / pair_cells,
        "spearman_rank_correlation": spearman,
        "direct_over_A439_rank_ratio_quantiles": {
            label: float(value)
            for label, value in zip(
                ("min", "p01", "p10", "p25", "p50", "p75", "p90", "p99", "max"),
                quantiles,
                strict=True,
            )
        },
        "maximum_direct_gain_bits": float(-math.log2(float(np.min(ratio)))),
        "maximum_direct_loss_bits": float(math.log2(float(np.max(ratio)))),
        "top_k_overlap": top_k,
    }


def _lexicographic_order(
    primary: np.ndarray, secondary: Sequence[np.ndarray], cells: int
) -> np.ndarray:
    cell_ids = np.arange(cells, dtype=np.int64)
    keys: list[np.ndarray] = [cell_ids]
    keys.extend(np.asarray(key) for key in reversed(tuple(secondary)))
    keys.append(np.asarray(primary))
    return exact_order(np.lexsort(tuple(keys)), cells)


def meta_order(rank_matrix: np.ndarray, operator: str) -> np.ndarray:
    ranks = np.asarray(rank_matrix, dtype=np.int64)
    if (
        ranks.ndim != 2
        or ranks.shape[0] != len(MODEL_ROLES)
        or np.any(ranks < 1)
    ):
        raise ValueError("A442 meta-rank matrix differs")
    cells = ranks.shape[1]
    if any(np.unique(row).size != cells or int(row.max()) != cells for row in ranks):
        raise ValueError("A442 source rank row is not exact")
    minimum = ranks.min(axis=0)
    maximum = ranks.max(axis=0)
    rank_sum = ranks.sum(axis=0)
    source_rows = [ranks[index] for index in range(ranks.shape[0])]
    if operator == "union_min":
        return _lexicographic_order(minimum, [rank_sum, *source_rows], cells)
    if operator == "borda_sum":
        return _lexicographic_order(
            rank_sum, [maximum, minimum, *source_rows], cells
        )
    if operator == "intersection_max":
        return _lexicographic_order(
            maximum, [rank_sum, minimum, *source_rows], cells
        )
    if operator == "upper_median":
        upper = np.sort(ranks, axis=0)[2]
        return _lexicographic_order(
            upper, [rank_sum, maximum, minimum, *source_rows], cells
        )
    if operator == "geometric_mean":
        product = np.prod(ranks.astype(np.uint64), axis=0)
        return _lexicographic_order(
            product, [rank_sum, maximum, minimum, *source_rows], cells
        )
    if operator == "reciprocal_sum":
        reciprocal = (1.0 / ranks.astype(np.float64)).sum(axis=0)
        return _lexicographic_order(
            -reciprocal, [rank_sum, maximum, minimum, *source_rows], cells
        )
    if operator == "top64_consensus":
        threshold = max(1, cells // 4)
        votes = (ranks <= threshold).sum(axis=0)
        return _lexicographic_order(
            -votes, [rank_sum, maximum, minimum, *source_rows], cells
        )
    raise ValueError(f"A442 unknown meta operator {operator}")


def meta_rank_field(model_fields: Mapping[str, np.ndarray], operator: str) -> np.ndarray:
    if set(model_fields) != set(MODEL_ROLES):
        raise ValueError("A442 model-field role cover differs")
    shape = model_fields[MODEL_ROLES[0]].shape
    if shape != (CALIBRATION_TARGETS, CALIBRATION_CELLS):
        raise ValueError("A442 calibration field geometry differs")
    output = np.empty(shape, dtype=np.int16)
    exact = np.arange(1, CALIBRATION_CELLS + 1, dtype=np.int16)
    for target in range(CALIBRATION_TARGETS):
        ranks = np.stack(
            [model_fields[role][target].astype(np.int64) for role in MODEL_ROLES]
        )
        order = meta_order(ranks, operator)
        output[target, order] = exact
    return output


def selection_key(row: Mapping[str, Any]) -> tuple[float | int, ...]:
    return (
        -float(row["minimum_fixed_block_bit_gain"]),
        -float(row["balanced_two_corpus_bit_gain"]),
        -float(row["all128_bit_gain"]),
        -int(row["targets_at_or_above_median_rank"]),
        int(row["worst_rank"]),
        OPERATORS.index(str(row["operator"])),
    )


def load_design() -> dict[str, Any]:
    if file_sha256(DESIGN) != DESIGN_SHA256:
        raise RuntimeError("A442 design hash differs")
    value = json.loads(DESIGN.read_bytes())
    calibration = value.get("knownkey_calibration_contract", {})
    transfer = value.get("W52_transfer_contract", {})
    decision = value.get("decision_contract", {})
    boundary = value.get("information_boundary", {})
    if (
        value.get("schema")
        != "chacha20-round20-w52-knownkey-meta-reader-transfer-a442-design-v1"
        or value.get("attempt_id") != ATTEMPT_ID
        or tuple(calibration.get("fixed_meta_operators", [])) != OPERATORS
        or calibration.get("targets") != CALIBRATION_TARGETS
        or calibration.get("fixed_blocks") != FIXED_BLOCKS
        or calibration.get("operators_defined_before_meta_evaluation") is not True
        or transfer.get("axis_cells") != AXIS_CELLS
        or transfer.get("pair_cells") != PAIR_CELLS
        or transfer.get("W52_target_labels_used") != 0
        or transfer.get("W52_reader_refits") != 0
        or transfer.get("candidate_assignments_executed") != 0
        or decision.get("do_not_launch_recovery_until_pair_diversity_is_measured")
        is not True
        or boundary.get("A441_authentic_Causal_personally_read") is not True
        or boundary.get("A442_meta_operator_results_known_before_design_freeze")
        is not False
        or boundary.get("A442_W52_orders_known_before_design_freeze") is not False
        or boundary.get("A442_target_labels_used") != 0
        or boundary.get("A442_reader_refits") != 0
        or boundary.get("A442_candidate_assignments_executed") != 0
    ):
        raise RuntimeError("A442 design semantics differ")
    anchors = value["source_anchors"]
    for key, item in anchors.items():
        if key.endswith("_path"):
            stem = key.removesuffix("_path")
            anchor(ROOT / item, anchors[f"{stem}_sha256"])
    return value


def load_sources() -> tuple[dict[str, Any], dict[str, Any]]:
    anchor(A375_RUNNER, A375_RUNNER_SHA256)
    anchor(A375_RESULT, A375_RESULT_SHA256)
    anchor(A375_CAUSAL, A375_CAUSAL_SHA256)
    anchor(A439_RUNNER, A439_RUNNER_SHA256)
    anchor(A439_RESULT, A439_RESULT_SHA256)
    anchor(A439_CAUSAL, A439_CAUSAL_SHA256)
    anchor(A441_RUNNER, A441_RUNNER_SHA256)
    anchor(A441_RESULT, A441_RESULT_SHA256)
    anchor(A441_CAUSAL, A441_CAUSAL_SHA256)
    a375 = json.loads(A375_RESULT.read_bytes())
    a439 = json.loads(A439_RESULT.read_bytes())
    if (
        a375.get("schema")
        != "chacha20-round20-w46-wide-consensus-reader-a375-v1"
        or a375.get("candidate_assignments_executed") != 0
        or a439.get("schema")
        != "chacha20-round20-w52-wide-consensus-dual-axis-wavefront-a439-v1"
        or a439.get("result_commitment_sha256")
        != A439_RESULT_COMMITMENT_SHA256
        or a439.get("pair_schedule", {}).get(
            "pair_stream_uint16be_uint16be_sha256"
        )
        != A439_PAIR_STREAM_SHA256
        or a439.get("target_labels_used") != 0
        or a439.get("reader_refits") != 0
        or a439.get("candidate_assignments_executed") != 0
    ):
        raise RuntimeError("A442 source semantics differ")
    for axis_name in ("prefix", "off_axis"):
        axis = a439["axes"][axis_name]
        exact_order(axis["portfolio_order"], AXIS_CELLS)
        if axis["pointwise_factor4_proof"].get("violations") != 0:
            raise RuntimeError(f"A442 A439 {axis_name} proof differs")
    for row in a439["anchors"].values():
        anchor(path_from_ref(row["path"]), row["sha256"])
    anchor(path_from_ref(a439["causal"]["path"]), a439["causal"]["sha256"])
    return a375, a439


def reconstruct_model_fields(
    a375: Mapping[str, Any],
) -> tuple[dict[str, np.ndarray], np.ndarray, list[str], dict[str, str]]:
    a375_runtime = load_module(A375_RUNNER, "a442_a375_runtime")
    matrices, truths, blocks = a375_runtime.load_panel()
    absolute = a375_runtime.exact_abs_rank_fields(matrices)
    model_fields: dict[str, np.ndarray] = {}
    hashes: dict[str, str] = {}
    for role in MODEL_ROLES:
        definition = a375["model_definitions"][role]
        field = a375_runtime.aggregate_rank_field(
            absolute,
            definition["member_feature_indices"],
            definition["aggregator"],
        )
        observed = hashlib.sha256(field.tobytes()).hexdigest()
        expected = a375["model_evaluations"][role]["rank_field_sha256"]
        if observed != expected:
            raise RuntimeError(f"A442 reconstructed A375 field differs: {role}")
        model_fields[role] = field
        hashes[role] = observed
    return model_fields, truths, blocks, hashes


def calibration_field_statistics(
    rank_field: np.ndarray, truths: np.ndarray
) -> dict[str, Any]:
    field = np.asarray(rank_field, dtype=np.int16)
    labels = np.asarray(truths, dtype=np.int16)
    if field.shape != (CALIBRATION_TARGETS, CALIBRATION_CELLS) or labels.shape != (
        CALIBRATION_TARGETS,
    ):
        raise ValueError("A442 calibration rank-field geometry differs")
    true_ranks = field[np.arange(CALIBRATION_TARGETS), labels].astype(np.int64)
    logs = np.log2(true_ranks.astype(np.float64))
    uniform = sum(
        math.log2(rank) for rank in range(1, CALIBRATION_CELLS + 1)
    ) / CALIBRATION_CELLS
    block_size = CALIBRATION_TARGETS // FIXED_BLOCKS
    blocks = [
        float(uniform - logs[start : start + block_size].mean())
        for start in range(0, CALIBRATION_TARGETS, block_size)
    ]
    corpus_size = CALIBRATION_TARGETS // 2
    corpus = [
        float(uniform - logs[:corpus_size].mean()),
        float(uniform - logs[corpus_size:].mean()),
    ]
    return {
        "truth_ranks": true_ranks.tolist(),
        "fixed_block_bit_gains": blocks,
        "minimum_fixed_block_bit_gain": min(blocks),
        "positive_fixed_block_count": sum(value > 0.0 for value in blocks),
        "corpus_bit_gains": corpus,
        "balanced_two_corpus_bit_gain": min(corpus),
        "all128_bit_gain": float(uniform - logs.mean()),
        "targets_at_or_above_median_rank": int(
            np.count_nonzero(true_ranks <= CALIBRATION_CELLS // 2)
        ),
        "worst_rank": int(true_ranks.max()),
    }


def evaluate_operators(
    model_fields: Mapping[str, np.ndarray], truths: np.ndarray
) -> tuple[dict[str, Any], str, dict[str, np.ndarray]]:
    evaluations: dict[str, Any] = {}
    fields: dict[str, np.ndarray] = {}
    for operator in OPERATORS:
        field = meta_rank_field(model_fields, operator)
        stats = calibration_field_statistics(field, truths)
        evaluations[operator] = {
            "operator": operator,
            **stats,
            "rank_field_sha256": hashlib.sha256(field.tobytes()).hexdigest(),
        }
        fields[operator] = field
    selected = min(OPERATORS, key=lambda operator: selection_key(evaluations[operator]))
    if selected != sorted(evaluations.values(), key=selection_key)[0]["operator"]:
        raise RuntimeError("A442 frozen selection key differs")
    return evaluations, selected, fields


def transfer_axis(
    source_orders: Mapping[str, Sequence[int]], operator: str
) -> dict[str, Any]:
    if set(source_orders) != set(MODEL_ROLES):
        raise ValueError("A442 W52 source-order role cover differs")
    rank_matrix = np.stack(
        [order_to_ranks(source_orders[role], AXIS_CELLS) for role in MODEL_ROLES]
    )
    order = meta_order(rank_matrix, operator)
    return {
        "order": [int(value) for value in order],
        "order_uint16be_sha256": order_sha256(order),
        "first_16_cells": [int(value) for value in order[:16]],
        "last_16_cells": [int(value) for value in order[-16:]],
        "exact_cells": AXIS_CELLS,
    }


def axis_comparison(left: Sequence[int], right: Sequence[int]) -> dict[str, Any]:
    left_order = exact_order(left, AXIS_CELLS)
    right_order = exact_order(right, AXIS_CELLS)
    left_ranks = order_to_ranks(left_order, AXIS_CELLS)
    right_ranks = order_to_ranks(right_order, AXIS_CELLS)
    top_k = {}
    for k in (16, 64, 256, 1024):
        intersection = int(
            np.count_nonzero((left_ranks <= k) & (right_ranks <= k))
        )
        top_k[str(k)] = {
            "intersection": intersection,
            "overlap_fraction": intersection / k,
        }
    return {
        "spearman_rank_correlation": float(
            np.corrcoef(left_ranks.astype(np.float64), right_ranks.astype(np.float64))[0, 1]
        ),
        "top_k_overlap": top_k,
    }


def freeze_implementation() -> dict[str, Any]:
    if IMPLEMENTATION.exists():
        raise FileExistsError("A442 implementation already exists")
    assert_pre_evaluation()
    design = load_design()
    a375, a439 = load_sources()
    if not TEST.exists() or not REPRO.exists():
        raise FileNotFoundError("A442 tests and reproducer must precede freeze")
    payload: dict[str, Any] = {
        "schema": "chacha20-round20-w52-knownkey-meta-reader-transfer-a442-implementation-v1",
        "attempt_id": ATTEMPT_ID,
        "commitment_state": "complete_seven_operator_calibration_selection_transfer_and_Causal_code_frozen_before_any_A442_evaluation_W52_order_or_target_progress",
        "design_sha256": DESIGN_SHA256,
        "operators": list(OPERATORS),
        "model_role_order": list(MODEL_ROLES),
        "selection_key": design["knownkey_calibration_contract"]["selection_key"],
        "source_A375_selection_commitment_sha256": a375[
            "selection_commitment_sha256"
        ],
        "source_A439_result_commitment_sha256": a439[
            "result_commitment_sha256"
        ],
        "A442_evaluation_available_at_freeze": False,
        "A442_W52_orders_available_at_freeze": False,
        "A426_A438_A440_target_outcome_or_progress_available_at_freeze": False,
        "target_labels_used_for_W52": 0,
        "reader_refits_on_W52": 0,
        "candidate_assignments_executed": 0,
        "anchors": {
            "design": anchor(DESIGN, DESIGN_SHA256),
            "A375_runner": anchor(A375_RUNNER, A375_RUNNER_SHA256),
            "A375_result": anchor(A375_RESULT, A375_RESULT_SHA256),
            "A375_causal": anchor(A375_CAUSAL, A375_CAUSAL_SHA256),
            "A439_runner": anchor(A439_RUNNER, A439_RUNNER_SHA256),
            "A439_result": anchor(A439_RESULT, A439_RESULT_SHA256),
            "A439_causal": anchor(A439_CAUSAL, A439_CAUSAL_SHA256),
            "A441_runner": anchor(A441_RUNNER, A441_RUNNER_SHA256),
            "A441_result": anchor(A441_RESULT, A441_RESULT_SHA256),
            "A441_causal": anchor(A441_CAUSAL, A441_CAUSAL_SHA256),
            "A434_runner": anchor(A434_RUNNER, A434_RUNNER_SHA256),
            "runner": anchor(Path(__file__)),
            "test": anchor(TEST),
            "reproducer": anchor(REPRO),
        },
    }
    payload["implementation_commitment_sha256"] = canonical_sha256(payload)
    atomic_json(IMPLEMENTATION, payload)
    assert_pre_evaluation()
    return payload


def load_implementation(expected_sha256: str) -> dict[str, Any]:
    if file_sha256(IMPLEMENTATION) != expected_sha256:
        raise RuntimeError("A442 implementation hash differs")
    value = json.loads(IMPLEMENTATION.read_bytes())
    if (
        value.get("schema")
        != "chacha20-round20-w52-knownkey-meta-reader-transfer-a442-implementation-v1"
        or value.get("attempt_id") != ATTEMPT_ID
        or value.get("design_sha256") != DESIGN_SHA256
        or tuple(value.get("operators", [])) != OPERATORS
        or tuple(value.get("model_role_order", [])) != MODEL_ROLES
        or value.get("A442_evaluation_available_at_freeze") is not False
        or value.get("A442_W52_orders_available_at_freeze") is not False
        or value.get("A426_A438_A440_target_outcome_or_progress_available_at_freeze")
        is not False
        or value.get("target_labels_used_for_W52") != 0
        or value.get("reader_refits_on_W52") != 0
        or value.get("candidate_assignments_executed") != 0
    ):
        raise RuntimeError("A442 implementation semantics differ")
    for row in value["anchors"].values():
        anchor(path_from_ref(row["path"]), row["sha256"])
    unsigned = {
        key: item
        for key, item in value.items()
        if key != "implementation_commitment_sha256"
    }
    if value.get("implementation_commitment_sha256") != canonical_sha256(unsigned):
        raise RuntimeError("A442 implementation commitment differs")
    return value


def build_causal(payload: Mapping[str, Any]) -> dict[str, Any]:
    if str(DOTCAUSAL_SRC) not in sys.path:
        sys.path.insert(0, str(DOTCAUSAL_SRC))
    from dotcausal.io import CausalReader, CausalWriter

    material = bool(payload["material_pair_diversity"])
    terminal = (
        "A442:orthogonal_W52_recovery_ready"
        if material
        else "A442:consensus_transfer_representation_boundary"
    )
    writer = CausalWriter(api_id="a442meta")
    writer._rules = []
    writer.add_rule(
        name="frozen_readers_to_meta_operator_atlas",
        description="Evaluate seven predeclared rank geometries over the exact frozen 128-target A375 panel.",
        pattern=["A375_four_positive_diverse_readers"],
        conclusion="A442_seven_operator_knownkey_atlas",
        confidence_modifier=1.0,
    )
    writer.add_rule(
        name="atlas_to_frozen_meta_operator",
        description="Apply the frozen lexicographic robustness key to retain one aggregation geometry.",
        pattern=["A442_seven_operator_knownkey_atlas"],
        conclusion="A442_selected_meta_operator",
        confidence_modifier=1.0,
    )
    writer.add_rule(
        name="meta_operator_to_target_blind_W52_transfer",
        description="Apply the selected geometry identically to both complete W52 source-order fields without labels or refits.",
        pattern=["A442_selected_meta_operator", "A439_eight_W52_source_orders"],
        conclusion="A442_complete_W52_pair_schedule",
        confidence_modifier=1.0,
    )
    writer.add_rule(
        name="pair_diversity_to_execution_decision",
        description="Use exact complete-pair Spearman and top-k overlap to decide whether the transfer opens a new recovery trajectory.",
        pattern=["A442_complete_W52_pair_schedule"],
        conclusion=terminal.replace(":", "_"),
        confidence_modifier=1.0,
    )
    writer.add_triplet(
        trigger="A375:four_positive_diverse_readers",
        mechanism="seven_predeclared_exact_rank_aggregation_geometries",
        outcome="A442:seven_operator_knownkey_atlas",
        confidence=1.0,
        source=payload["calibration_sha256"],
        quantification=json.dumps(payload["operator_summary"], sort_keys=True),
        evidence=json.dumps(payload["calibration_contract"], sort_keys=True),
        domain="Known-key full-round ChaCha20 Reader calibration",
        quality_score=1.0,
    )
    writer.add_triplet(
        trigger="A442:seven_operator_knownkey_atlas",
        mechanism="minimum_block_gain_then_balanced_corpus_frozen_selection_key",
        outcome="A442:selected_meta_operator",
        confidence=1.0,
        source=payload["selection_sha256"],
        quantification=payload["selected_operator"],
        evidence=json.dumps(payload["selected_evaluation"], sort_keys=True),
        domain="robust meta-Reader selection",
        quality_score=1.0,
    )
    writer.add_triplet(
        trigger="A442:selected_meta_operator",
        mechanism="identical_refit_free_transfer_to_prefix_and_off_axis_rank_fields",
        outcome="A442:complete_W52_pair_schedule",
        confidence=1.0,
        source=payload["pair_schedule_sha256"],
        quantification=json.dumps(payload["W52_transfer"], sort_keys=True),
        evidence=payload["pair_stream_uint16be_uint16be_sha256"],
        domain="target-blind full-round ChaCha20 W52 ordering",
        quality_score=1.0,
    )
    writer.add_triplet(
        trigger="A442:complete_W52_pair_schedule",
        mechanism="exact_all_pair_rank_diversity_gate_against_A439",
        outcome=terminal,
        confidence=1.0,
        source=payload["pair_diversity_sha256"],
        quantification=json.dumps(payload["pair_comparison_to_A439"], sort_keys=True),
        evidence=str(payload["material_pair_diversity"]),
        domain="W52 recovery trajectory decision",
        quality_score=1.0,
    )
    writer.add_triplet(
        trigger="A375:four_positive_diverse_readers",
        mechanism="materialized_meta_calibration_transfer_diversity_closure",
        outcome=terminal,
        confidence=1.0,
        source="materialized:A442_meta_reader_transfer_chain",
        quantification="exact retained closure",
        evidence=payload["evidence_stage"],
        domain="AI-native retained inference",
        quality_score=1.0,
        is_inferred=True,
    )
    writer.add_cluster(
        name="A442 Known-key meta-Reader transfer",
        entities=[
            "A375:four_positive_diverse_readers",
            "A442:seven_operator_knownkey_atlas",
            "A442:selected_meta_operator",
            "A442:complete_W52_pair_schedule",
            terminal,
        ],
    )
    writer.add_gap(
        subject=terminal,
        predicate="next_required_object",
        expected_object_type=(
            "qualified_recovery_execution"
            if material
            else "new_feature_family_or_non_rank_aggregation"
        ),
        confidence=1.0,
        suggested_queries=[
            (
                "Freeze an executor only if this schedule remains materially orthogonal after the exact pair-space gate."
                if material
                else "The fixed rank-aggregation family did not open a new trajectory; move to an orthogonal feature family rather than another rank re-tie."
            )
        ],
    )
    temporary = CAUSAL.with_name(f".{CAUSAL.name}.{os.getpid()}.tmp")
    temporary.unlink(missing_ok=True)
    stats = writer.save(str(temporary))
    os.replace(temporary, CAUSAL)
    reader = CausalReader(str(CAUSAL), verify_integrity=True)
    explicit = reader.get_all_triplets(include_inferred=False)
    all_rows = reader.get_all_triplets(include_inferred=True)
    inferred = [row for row in reader._triplets if row.get("is_inferred", False)]
    if (
        reader.api_id != "a442meta"
        or len(explicit) != 4
        or len(all_rows) != 5
        or len(inferred) != 1
        or len(reader._rules) != 4
        or len(reader._clusters) != 1
        or len(reader._gaps) != 1
    ):
        raise RuntimeError("A442 authentic Causal reopen gate failed")
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
            "operator_atlas": explicit[0],
            "selection": explicit[1],
            "W52_transfer": explicit[2],
            "diversity_decision": explicit[3],
            "terminal_chain": all_rows[-1],
            "next_gap": reader._gaps[0],
        },
    }


def _build_result_once(*, expected_implementation_sha256: str) -> dict[str, Any]:
    if any(path.exists() for path in (RESULT, CAUSAL, REPORT)):
        raise FileExistsError("A442 result already exists")
    design = load_design()
    implementation = load_implementation(expected_implementation_sha256)
    a375, a439 = load_sources()
    model_fields, truths, blocks, reconstructed_hashes = reconstruct_model_fields(a375)
    evaluations, selected, _meta_fields = evaluate_operators(model_fields, truths)
    prefix_sources = {
        role: a439["axes"]["prefix"]["source_orders"][role]
        for role in MODEL_ROLES
    }
    off_sources = {
        role: a439["axes"]["off_axis"]["source_orders"][role]
        for role in MODEL_ROLES
    }
    prefix = transfer_axis(prefix_sources, selected)
    off_axis = transfer_axis(off_sources, selected)
    prefix_comparison = axis_comparison(
        prefix["order"], a439["axes"]["prefix"]["portfolio_order"]
    )
    off_comparison = axis_comparison(
        off_axis["order"], a439["axes"]["off_axis"]["portfolio_order"]
    )
    pair_stream_sha = pair_stream_sha256(prefix["order"], off_axis["order"])
    selected_pair_rank = reference_square_rank_vector(
        prefix["order"], off_axis["order"]
    )
    a439_pair_rank = reference_square_rank_vector(
        a439["axes"]["prefix"]["portfolio_order"],
        a439["axes"]["off_axis"]["portfolio_order"],
    )
    pair_comparison = compare_rank_orders(selected_pair_rank, a439_pair_rank)
    top65536_overlap = (
        pair_comparison["top_k_overlap"]["65536"]["intersection"] / 65536
    )
    material = (
        pair_comparison["spearman_rank_correlation"] < MATERIAL_SPEARMAN_MAX
        or top65536_overlap < MATERIAL_TOP65536_OVERLAP_MAX
    )
    operator_summary = {
        operator: {
            key: value
            for key, value in evaluations[operator].items()
            if key not in {"truth_ranks", "fixed_block_bit_gains", "corpus_bit_gains"}
        }
        for operator in OPERATORS
    }
    evidence_stage = (
        "KNOWNKEY_SELECTED_META_READER_MATERIALLY_ORTHOGONAL_W52_PAIR_SCHEDULE_RECOVERY_READY"
        if material
        else "KNOWNKEY_META_READER_TRANSFER_REPRESENTATION_BOUNDARY_LOCALIZED"
    )
    calibration_contract = {
        "targets": CALIBRATION_TARGETS,
        "cells_per_target": CALIBRATION_CELLS,
        "fixed_blocks": FIXED_BLOCKS,
        "block_labels": blocks,
        "operators_defined_before_evaluation": True,
        "selection_key": design["knownkey_calibration_contract"]["selection_key"],
        "reconstructed_model_rank_field_sha256": reconstructed_hashes,
    }
    transfer = {
        "selected_operator": selected,
        "prefix": {key: value for key, value in prefix.items() if key != "order"},
        "off_axis": {key: value for key, value in off_axis.items() if key != "order"},
        "prefix_comparison_to_A439": prefix_comparison,
        "off_axis_comparison_to_A439": off_comparison,
        "pair_cells": PAIR_CELLS,
        "target_labels_used": 0,
        "reader_refits": 0,
        "candidate_assignments_executed": 0,
    }
    core: dict[str, Any] = {
        "schema": "chacha20-round20-w52-knownkey-meta-reader-transfer-a442-v1",
        "attempt_id": ATTEMPT_ID,
        "evidence_stage": evidence_stage,
        "design_sha256": DESIGN_SHA256,
        "implementation_sha256": expected_implementation_sha256,
        "implementation_commitment_sha256": implementation[
            "implementation_commitment_sha256"
        ],
        "calibration_contract": calibration_contract,
        "operator_evaluations": evaluations,
        "operator_summary": operator_summary,
        "selected_operator": selected,
        "selected_evaluation": evaluations[selected],
        "W52_transfer": transfer,
        "prefix_order": prefix["order"],
        "off_axis_order": off_axis["order"],
        "pair_stream_uint16be_uint16be_sha256": pair_stream_sha,
        "pair_comparison_to_A439": pair_comparison,
        "material_pair_diversity": material,
        "material_diversity_gate": {
            "spearman_less_than": MATERIAL_SPEARMAN_MAX,
            "top65536_overlap_less_than": MATERIAL_TOP65536_OVERLAP_MAX,
            "observed_top65536_overlap": top65536_overlap,
        },
        "target_labels_used_for_W52": 0,
        "reader_refits_on_W52": 0,
        "candidate_assignments_executed": 0,
        "A426_A438_A440_secret_result_stop_or_worker_progress_read": False,
        "anchors": {
            "design": anchor(DESIGN, DESIGN_SHA256),
            "implementation": anchor(
                IMPLEMENTATION, expected_implementation_sha256
            ),
            "A375_runner": anchor(A375_RUNNER, A375_RUNNER_SHA256),
            "A375_result": anchor(A375_RESULT, A375_RESULT_SHA256),
            "A375_causal": anchor(A375_CAUSAL, A375_CAUSAL_SHA256),
            "A439_runner": anchor(A439_RUNNER, A439_RUNNER_SHA256),
            "A439_result": anchor(A439_RESULT, A439_RESULT_SHA256),
            "A439_causal": anchor(A439_CAUSAL, A439_CAUSAL_SHA256),
            "A441_runner": anchor(A441_RUNNER, A441_RUNNER_SHA256),
            "A441_result": anchor(A441_RESULT, A441_RESULT_SHA256),
            "A441_causal": anchor(A441_CAUSAL, A441_CAUSAL_SHA256),
            "A434_runner": anchor(A434_RUNNER, A434_RUNNER_SHA256),
            "runner": anchor(Path(__file__)),
            "test": anchor(TEST),
            "reproducer": anchor(REPRO),
        },
    }
    core["calibration_sha256"] = canonical_sha256(
        {"contract": calibration_contract, "evaluations": evaluations}
    )
    core["selection_sha256"] = canonical_sha256(
        {"selected_operator": selected, "selected_evaluation": evaluations[selected]}
    )
    core["pair_schedule_sha256"] = canonical_sha256(
        {
            "prefix_order_sha256": prefix["order_uint16be_sha256"],
            "off_axis_order_sha256": off_axis["order_uint16be_sha256"],
            "pair_stream_sha256": pair_stream_sha,
        }
    )
    core["pair_diversity_sha256"] = canonical_sha256(pair_comparison)
    core["result_commitment_sha256"] = canonical_sha256(
        {
            "design_sha256": DESIGN_SHA256,
            "implementation_commitment_sha256": core[
                "implementation_commitment_sha256"
            ],
            "calibration_sha256": core["calibration_sha256"],
            "selection_sha256": core["selection_sha256"],
            "pair_schedule_sha256": core["pair_schedule_sha256"],
            "pair_diversity_sha256": core["pair_diversity_sha256"],
            "target_labels_used_for_W52": 0,
            "reader_refits_on_W52": 0,
            "candidate_assignments_executed": 0,
        }
    )
    core["causal"] = build_causal(core)
    atomic_json(RESULT, core)
    selected_stats = evaluations[selected]
    report = (
        "# A442 — Known-key meta-Reader transfer to W52\n\n"
        f"Evidence stage: **{evidence_stage}**\n\n"
        f"- Selected operator: **{selected}**\n"
        f"- Minimum fixed-block gain: **{selected_stats['minimum_fixed_block_bit_gain']:.9f} bits**\n"
        f"- Balanced two-corpus gain: **{selected_stats['balanced_two_corpus_bit_gain']:.9f} bits**\n"
        f"- Pair Spearman versus A439: **{pair_comparison['spearman_rank_correlation']:.9f}**\n"
        f"- Top-65,536 overlap versus A439: **{top65536_overlap:.9f}**\n"
        f"- Materially orthogonal recovery trajectory: **{material}**\n"
        f"- Pair-stream SHA-256: **{pair_stream_sha}**\n"
        "- W52 target labels / Reader refits / candidate executions: **0 / 0 / 0**\n"
        "- Authentic AI-native Causal readback: **4 explicit + 1 inferred**\n"
    )
    atomic_bytes(REPORT, report.encode())
    return core


def build_result(*, expected_implementation_sha256: str) -> dict[str, Any]:
    if any(path.exists() for path in (RESULT, CAUSAL, REPORT)):
        raise FileExistsError("A442 result already exists")
    try:
        return _build_result_once(
            expected_implementation_sha256=expected_implementation_sha256
        )
    except BaseException:
        RESULT.unlink(missing_ok=True)
        CAUSAL.unlink(missing_ok=True)
        REPORT.unlink(missing_ok=True)
        raise


def load_result(expected_sha256: str) -> dict[str, Any]:
    if file_sha256(RESULT) != expected_sha256:
        raise RuntimeError("A442 result hash differs")
    value = json.loads(RESULT.read_bytes())
    if (
        value.get("schema")
        != "chacha20-round20-w52-knownkey-meta-reader-transfer-a442-v1"
        or value.get("attempt_id") != ATTEMPT_ID
        or value.get("selected_operator") not in OPERATORS
        or len(value.get("prefix_order", [])) != AXIS_CELLS
        or len(value.get("off_axis_order", [])) != AXIS_CELLS
        or value.get("target_labels_used_for_W52") != 0
        or value.get("reader_refits_on_W52") != 0
        or value.get("candidate_assignments_executed") != 0
    ):
        raise RuntimeError("A442 result semantics differ")
    exact_order(value["prefix_order"], AXIS_CELLS)
    exact_order(value["off_axis_order"], AXIS_CELLS)
    for row in value["anchors"].values():
        anchor(path_from_ref(row["path"]), row["sha256"])
    anchor(path_from_ref(value["causal"]["path"]), value["causal"]["sha256"])
    return value


def analyze() -> dict[str, Any]:
    payload: dict[str, Any] = {
        "attempt_id": ATTEMPT_ID,
        "design_sha256": file_sha256(DESIGN) if DESIGN.exists() else None,
        "implementation_frozen": IMPLEMENTATION.exists(),
        "result_complete": RESULT.exists(),
        "operators": list(OPERATORS),
        "pair_cells": PAIR_CELLS,
    }
    load_design()
    if IMPLEMENTATION.exists():
        payload["implementation_sha256"] = file_sha256(IMPLEMENTATION)
        load_implementation(payload["implementation_sha256"])
    if RESULT.exists():
        payload["result_sha256"] = file_sha256(RESULT)
        value = load_result(payload["result_sha256"])
        payload["evidence_stage"] = value["evidence_stage"]
        payload["selected_operator"] = value["selected_operator"]
        payload["material_pair_diversity"] = value["material_pair_diversity"]
    return payload


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    action = parser.add_mutually_exclusive_group(required=True)
    action.add_argument("--analyze", action="store_true")
    action.add_argument("--freeze-implementation", action="store_true")
    action.add_argument("--build-result", action="store_true")
    parser.add_argument("--expected-implementation-sha256")
    args = parser.parse_args()
    if args.freeze_implementation:
        payload = freeze_implementation()
    elif args.build_result:
        if not args.expected_implementation_sha256:
            parser.error("--build-result requires implementation hash")
        payload = build_result(
            expected_implementation_sha256=args.expected_implementation_sha256
        )
    else:
        payload = analyze()
    print(json.dumps(payload, indent=2, sort_keys=True), flush=True)


if __name__ == "__main__":
    main()

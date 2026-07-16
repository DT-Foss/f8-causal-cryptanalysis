#!/usr/bin/env python3
"""A441: preserve all sixteen A439 Reader products in one exact W52 pair order."""

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
ARTIFACTS = RESEARCH / "artifacts/a441_chacha20_r20_w52_direct_product_reader_pair_portfolio_v1"

DESIGN = (
    CONFIGS
    / "chacha20_round20_w52_direct_product_reader_pair_portfolio_a441_design_v1.json"
)
IMPLEMENTATION = (
    CONFIGS
    / "chacha20_round20_w52_direct_product_reader_pair_portfolio_a441_implementation_v1.json"
)
RESULT = (
    RESULTS
    / "chacha20_round20_w52_direct_product_reader_pair_portfolio_a441_v1.json"
)
CAUSAL = RESULT.with_suffix(".causal")
REPORT = RESULT.with_suffix(".md")
ORDER_ARTIFACT = ARTIFACTS / "direct_product_factor16_order_u16be_u16be_v1.bin"
TEST = (
    ROOT
    / "tests/test_chacha20_round20_w52_direct_product_reader_pair_portfolio_a441.py"
)
REPRO = (
    ROOT
    / "scripts/reproduce_chacha20_round20_w52_direct_product_reader_pair_portfolio_a441.sh"
)

A439_RUNNER = (
    RESEARCH
    / "experiments/chacha20_round20_w52_wide_consensus_dual_axis_wavefront_a439.py"
)
A439_DESIGN = (
    CONFIGS
    / "chacha20_round20_w52_wide_consensus_dual_axis_wavefront_a439_design_v1.json"
)
A439_IMPLEMENTATION = (
    CONFIGS
    / "chacha20_round20_w52_wide_consensus_dual_axis_wavefront_a439_implementation_v1.json"
)
A439_RESULT = (
    RESULTS / "chacha20_round20_w52_wide_consensus_dual_axis_wavefront_a439_v1.json"
)
A439_CAUSAL = A439_RESULT.with_suffix(".causal")
A434_RUNNER = (
    RESEARCH / "experiments/chacha20_round20_w52_dual_axis_square_wavefront_a434.py"
)

ATTEMPT_ID = "A441"
DESIGN_SHA256 = "2ff84e9e2995d293bf3cd681e0af150291a121d0cf80cb1e9fa0f6084d9eb431"
A439_RUNNER_SHA256 = "6cb94c2c8e8e404b25b2b41c51e4fd68b038e447616c740dba549464b5f490fb"
A439_DESIGN_SHA256 = "b8a57f3ae46d394ef70c66bd6d75bc8fbd284500a9e8d4447c0a89723c8daecf"
A439_IMPLEMENTATION_SHA256 = (
    "6c0e6114620b2a3c129779c5e2624b3499f4827d31bab8eff4417b95b6595530"
)
A439_RESULT_SHA256 = "b141fb882bd1a1cdc6a22de424370fe3118c9a4eb90565eaa0c8225321b9f869"
A439_CAUSAL_SHA256 = "f27c9d0d8311d633cfa46237df44ef1daa0cf375c99ddd1f85e37cc79f26f27c"
A439_RESULT_COMMITMENT_SHA256 = (
    "391ed0597f413d31eed60d235e6bebc90b8d7cabda486c6979631a4e753c9f0f"
)
A439_PAIR_STREAM_SHA256 = "e71f783d1a6176d9f3c75443bb8d41ed5812a6f331a57c07a473ba9f2c91bc15"
A434_RUNNER_SHA256 = "feb01a654135ed03451c3207d4f10195de0bc81ec26ce755d5e0d1eeb7ce9a1b"

MODEL_ROLES = (
    "wide_vote",
    "sparse_reciprocal",
    "broad_quantile",
    "broad_intersection",
)
AXIS_CELLS = 1 << 12
PAIR_CELLS = AXIS_CELLS * AXIS_CELLS
PRODUCT_READERS = len(MODEL_ROLES) ** 2
ARTIFACT_BYTES = PAIR_CELLS * 4
DEFAULT_CHUNK_RANKS = 1 << 15
METRIC_CHUNK_PAIRS = 1 << 18
TOP_KS = (256, 4096, 65536, 1048576)
DOTCAUSAL_SRC = Path(
    "/Users/bhkmie/Documents/Forschung/O1/vendor/fabel/dotcausal_package/src"
)

A426_SENSITIVE = (
    RESULTS / "chacha20_round20_w52_a416_fresh_shared_stop_recovery_a426_v1.json",
    RESULTS
    / "chacha20_round20_w52_a416_fresh_shared_stop_recovery_a426_confirmed_stop_v1.json",
)
A438_SENSITIVE = (
    RESULTS
    / "chacha20_round20_w52_calibration_balanced_wavefront_recovery_a438_v1.json",
    RESULTS
    / "chacha20_round20_w52_calibration_balanced_wavefront_recovery_a438_confirmed_stop_v1.json",
)
A440_SENSITIVE = (
    RESULTS / "chacha20_round20_w52_wide_consensus_wavefront_recovery_a440_v1.json",
    RESULTS
    / "chacha20_round20_w52_wide_consensus_wavefront_recovery_a440_confirmed_stop_v1.json",
)


def load_module(path: Path, name: str) -> Any:
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot import A441 dependency {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


A439 = load_module(A439_RUNNER, "a441_a439")
A434 = A439.A434
file_sha256 = A439.file_sha256
canonical_sha256 = A439.canonical_sha256
atomic_json = A439.atomic_json
atomic_bytes = A439.atomic_bytes
anchor = A439.anchor
path_from_ref = A439.path_from_ref
relative = A439.relative


def target_progress_paths() -> list[Path]:
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


def assert_pre_pair_order() -> None:
    sensitive = (*A426_SENSITIVE, *A438_SENSITIVE, *A440_SENSITIVE, *target_progress_paths())
    if any(path.exists() for path in sensitive):
        raise RuntimeError("A441 freeze must precede all A426/A438/A440 target outcomes or progress")
    if any(path.exists() for path in (RESULT, CAUSAL, REPORT, ORDER_ARTIFACT)):
        raise RuntimeError("A441 pair-order artifact already exists")


def exact_axis_order(
    values: Sequence[int], label: str, axis_cells: int = AXIS_CELLS
) -> np.ndarray:
    order = np.asarray([int(value) for value in values], dtype=np.int64)
    if (
        order.shape != (axis_cells,)
        or int(order.min(initial=0)) != 0
        or int(order.max(initial=-1)) != axis_cells - 1
        or np.unique(order).size != axis_cells
    ):
        raise ValueError(f"A441 {label} is not an exact axis order")
    return order


def rank_vector(order: Sequence[int] | np.ndarray, axis_cells: int) -> np.ndarray:
    values = exact_axis_order(order, "rank-vector source", axis_cells)
    ranks = np.empty(axis_cells, dtype=np.int64)
    ranks[values] = np.arange(1, axis_cells + 1, dtype=np.int64)
    return ranks


def product_roles(role_order: Sequence[str]) -> tuple[tuple[str, str], ...]:
    roles = tuple(str(role) for role in role_order)
    if not roles or len(roles) != len(set(roles)):
        raise ValueError("A441 role order differs")
    return tuple((prefix, off_axis) for prefix in roles for off_axis in roles)


def corrected_isqrt(values: np.ndarray) -> np.ndarray:
    source = np.asarray(values, dtype=np.int64)
    roots = np.floor(np.sqrt(source.astype(np.float64))).astype(np.int64)
    roots -= (roots * roots > source).astype(np.int64)
    roots += (((roots + 1) * (roots + 1)) <= source).astype(np.int64)
    if np.any(roots * roots > source) or np.any((roots + 1) * (roots + 1) <= source):
        raise RuntimeError("A441 vectorized integer square root differs")
    return roots


def square_rank_coordinates(global_indices: np.ndarray) -> tuple[np.ndarray, np.ndarray]:
    indices = np.asarray(global_indices, dtype=np.int64)
    shell = corrected_isqrt(indices)
    offset = indices - shell * shell
    prefix_rank_zero = np.where(offset <= shell, shell, offset - shell - 1)
    off_axis_rank_zero = np.where(offset <= shell, offset, shell)
    return prefix_rank_zero, off_axis_rank_zero


def product_stream_dense(
    global_indices: np.ndarray,
    prefix_orders: Mapping[str, Sequence[int]],
    off_axis_orders: Mapping[str, Sequence[int]],
    role_order: Sequence[str],
    axis_cells: int,
) -> np.ndarray:
    pairs = product_roles(role_order)
    prefix_rank_zero, off_axis_rank_zero = square_rank_coordinates(global_indices)
    prefix_arrays = {
        role: exact_axis_order(prefix_orders[role], f"prefix {role}", axis_cells)
        for role in role_order
    }
    off_arrays = {
        role: exact_axis_order(off_axis_orders[role], f"off-axis {role}", axis_cells)
        for role in role_order
    }
    output = np.empty((len(global_indices), len(pairs)), dtype=np.int64)
    for column, (prefix_role, off_role) in enumerate(pairs):
        prefix = prefix_arrays[prefix_role][prefix_rank_zero]
        off_axis = off_arrays[off_role][off_axis_rank_zero]
        output[:, column] = prefix * axis_cells + off_axis
    return output


def source_pair_rank_matrix(
    dense_pairs: np.ndarray,
    prefix_ranks: Mapping[str, np.ndarray],
    off_axis_ranks: Mapping[str, np.ndarray],
    role_order: Sequence[str],
    axis_cells: int,
) -> np.ndarray:
    dense = np.asarray(dense_pairs, dtype=np.int64)
    prefix = dense // axis_cells
    off_axis = dense % axis_cells
    pairs = product_roles(role_order)
    output = np.empty((dense.size, len(pairs)), dtype=np.uint32)
    for column, (prefix_role, off_role) in enumerate(pairs):
        left = prefix_ranks[prefix_role][prefix] - 1
        right = off_axis_ranks[off_role][off_axis] - 1
        shell = np.maximum(left, right)
        rank = np.where(
            left == shell,
            shell * shell + right,
            shell * shell + shell + 1 + left,
        ) + 1
        output[:, column] = rank.astype(np.uint32)
    return output


def encode_pairs(dense_pairs: np.ndarray, axis_cells: int) -> np.ndarray:
    dense = np.asarray(dense_pairs, dtype=np.int64)
    prefix = dense // axis_cells
    off_axis = dense % axis_cells
    if (
        np.any(prefix < 0)
        or np.any(prefix >= axis_cells)
        or np.any(off_axis < 0)
        or np.any(off_axis >= axis_cells)
        or axis_cells > (1 << 16)
    ):
        raise ValueError("A441 pair encoding differs")
    return ((prefix.astype(np.uint32) << 16) | off_axis.astype(np.uint32)).astype(
        ">u4"
    )


def decode_words(words: np.ndarray) -> tuple[np.ndarray, np.ndarray]:
    values = np.asarray(words, dtype=np.uint32)
    return (values >> 16).astype(np.int64), (values & 0xFFFF).astype(np.int64)


def build_direct_product_order(
    *,
    prefix_orders: Mapping[str, Sequence[int]],
    off_axis_orders: Mapping[str, Sequence[int]],
    role_order: Sequence[str],
    axis_cells: int,
    output_path: Path,
    chunk_ranks: int,
) -> tuple[np.ndarray, dict[str, Any]]:
    if chunk_ranks <= 0:
        raise ValueError("A441 chunk size differs")
    roles = tuple(str(role) for role in role_order)
    if set(prefix_orders) != set(roles) or set(off_axis_orders) != set(roles):
        raise ValueError("A441 source-order role cover differs")
    prefix_arrays = {
        role: exact_axis_order(prefix_orders[role], f"prefix {role}", axis_cells)
        for role in roles
    }
    off_arrays = {
        role: exact_axis_order(off_axis_orders[role], f"off-axis {role}", axis_cells)
        for role in roles
    }
    prefix_ranks = {
        role: rank_vector(prefix_arrays[role], axis_cells) for role in roles
    }
    off_ranks = {role: rank_vector(off_arrays[role], axis_cells) for role in roles}
    pair_cells = axis_cells * axis_cells
    reader_count = len(roles) ** 2
    seen = np.zeros(pair_cells, dtype=np.bool_)
    inverse_rank = np.zeros(pair_cells, dtype=np.uint32)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    temporary = output_path.with_name(f".{output_path.name}.{os.getpid()}.tmp")
    temporary.unlink(missing_ok=True)
    hasher = hashlib.sha256()
    written = 0
    chunks = 0
    max_new_pairs = 0
    try:
        with temporary.open("wb") as handle:
            for start in range(0, pair_cells, chunk_ranks):
                stop = min(start + chunk_ranks, pair_cells)
                global_indices = np.arange(start, stop, dtype=np.int64)
                streams = product_stream_dense(
                    global_indices,
                    prefix_arrays,
                    off_arrays,
                    roles,
                    axis_cells,
                )
                flat = streams.reshape(-1)
                eligible_positions = np.flatnonzero(~seen[flat])
                if eligible_positions.size == 0:
                    chunks += 1
                    continue
                eligible_dense = flat[eligible_positions]
                _unique_dense, first = np.unique(eligible_dense, return_index=True)
                selected_positions = eligible_positions[first]
                selected_dense = flat[selected_positions]
                minimum_rank = (
                    start + selected_positions // reader_count + 1
                ).astype(np.uint32)
                ranks = source_pair_rank_matrix(
                    selected_dense,
                    prefix_ranks,
                    off_ranks,
                    roles,
                    axis_cells,
                )
                if not np.array_equal(ranks.min(axis=1), minimum_rank):
                    raise RuntimeError("A441 minimum source-rank bucket differs")
                rank_sum = ranks.astype(np.uint64).sum(axis=1)
                prefix = selected_dense // axis_cells
                off_axis = selected_dense % axis_cells
                keys: list[np.ndarray] = [off_axis, prefix]
                keys.extend(ranks[:, index] for index in reversed(range(reader_count)))
                keys.extend((rank_sum, minimum_rank))
                order = np.lexsort(tuple(keys))
                ordered_dense = selected_dense[order]
                if np.any(seen[ordered_dense]):
                    raise RuntimeError("A441 duplicate pair escaped the seen set")
                seen[ordered_dense] = True
                next_rank = np.arange(
                    written + 1, written + ordered_dense.size + 1, dtype=np.uint32
                )
                inverse_rank[ordered_dense] = next_rank
                encoded = encode_pairs(ordered_dense, axis_cells)
                raw = encoded.tobytes(order="C")
                handle.write(raw)
                hasher.update(raw)
                written += ordered_dense.size
                max_new_pairs = max(max_new_pairs, int(ordered_dense.size))
                chunks += 1
            handle.flush()
            os.fsync(handle.fileno())
        if written != pair_cells or int(np.count_nonzero(seen)) != pair_cells:
            raise RuntimeError("A441 direct portfolio is not a complete pair cover")
        if (
            np.any(inverse_rank == 0)
            or int(inverse_rank.min()) != 1
            or int(inverse_rank.max()) != pair_cells
        ):
            raise RuntimeError("A441 inverse rank is not an exact permutation")
        if temporary.stat().st_size != pair_cells * 4:
            raise RuntimeError("A441 order artifact byte length differs")
        os.replace(temporary, output_path)
    except BaseException:
        temporary.unlink(missing_ok=True)
        raise
    return inverse_rank, {
        "axis_cells": axis_cells,
        "pair_cells": pair_cells,
        "product_readers": reader_count,
        "chunk_ranks": chunk_ranks,
        "chunks": chunks,
        "maximum_new_pairs_in_one_chunk": max_new_pairs,
        "pairs_written": written,
        "artifact_bytes": output_path.stat().st_size,
        "artifact_sha256": hasher.hexdigest(),
        "duplicate_free_complete_cover": True,
    }


def reference_square_rank_vector(
    prefix_order: Sequence[int], off_axis_order: Sequence[int], axis_cells: int
) -> np.ndarray:
    prefix_ranks = rank_vector(prefix_order, axis_cells) - 1
    off_ranks = rank_vector(off_axis_order, axis_cells) - 1
    output = np.empty(axis_cells * axis_cells, dtype=np.uint32)
    off_cells = np.arange(axis_cells, dtype=np.int64)
    right = off_ranks[off_cells]
    for prefix in range(axis_cells):
        left = np.full(axis_cells, prefix_ranks[prefix], dtype=np.int64)
        shell = np.maximum(left, right)
        rank = np.where(
            left == shell,
            shell * shell + right,
            shell * shell + shell + 1 + left,
        ) + 1
        start = prefix * axis_cells
        output[start : start + axis_cells] = rank.astype(np.uint32)
    if (
        int(output.min()) != 1
        or int(output.max()) != axis_cells * axis_cells
        or int(output.astype(np.uint64).sum())
        != (axis_cells * axis_cells) * (axis_cells * axis_cells + 1) // 2
    ):
        raise RuntimeError("A441 A439 reference rank vector is not exact")
    return output


def factor_k_pair_proof(
    *,
    portfolio_rank: np.ndarray,
    prefix_orders: Mapping[str, Sequence[int]],
    off_axis_orders: Mapping[str, Sequence[int]],
    role_order: Sequence[str],
    axis_cells: int,
    chunk_pairs: int,
) -> dict[str, Any]:
    roles = tuple(str(role) for role in role_order)
    prefix_ranks = {
        role: rank_vector(prefix_orders[role], axis_cells) for role in roles
    }
    off_ranks = {
        role: rank_vector(off_axis_orders[role], axis_cells) for role in roles
    }
    pair_cells = axis_cells * axis_cells
    reader_count = len(roles) ** 2
    violations = 0
    maximum_ratio = 0.0
    ratio_sum = 0.0
    maximum_slack = 0
    for start in range(0, pair_cells, chunk_pairs):
        stop = min(start + chunk_pairs, pair_cells)
        dense = np.arange(start, stop, dtype=np.int64)
        ranks = source_pair_rank_matrix(
            dense, prefix_ranks, off_ranks, roles, axis_cells
        )
        best = ranks.min(axis=1).astype(np.uint64)
        observed = portfolio_rank[start:stop].astype(np.uint64)
        envelope = reader_count * best
        violations += int(np.count_nonzero(observed > envelope))
        slack = envelope.astype(np.int64) - observed.astype(np.int64)
        maximum_slack = max(maximum_slack, int(np.max(slack)))
        ratios = observed.astype(np.float64) / best.astype(np.float64)
        maximum_ratio = max(maximum_ratio, float(np.max(ratios)))
        ratio_sum += float(np.sum(ratios))
    if violations or maximum_ratio > reader_count + 1e-12:
        raise RuntimeError("A441 pointwise factor-k proof failed")
    return {
        "bound": "R_A441(x,y) <= 16*min_product_reader_pair_rank(x,y)",
        "reader_count": reader_count,
        "pair_cells_checked": pair_cells,
        "maximum_ratio": maximum_ratio,
        "mean_ratio": ratio_sum / pair_cells,
        "maximum_envelope_slack_cells": maximum_slack,
        "violations": violations,
    }


def compare_rank_orders(
    direct_rank: np.ndarray, reference_rank: np.ndarray
) -> dict[str, Any]:
    if direct_rank.shape != reference_rank.shape or direct_rank.ndim != 1:
        raise ValueError("A441 rank comparison shape differs")
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


def load_design() -> dict[str, Any]:
    if file_sha256(DESIGN) != DESIGN_SHA256:
        raise RuntimeError("A441 design hash differs")
    value = json.loads(DESIGN.read_bytes())
    source = value.get("source_contract", {})
    pair = value.get("pair_order_contract", {})
    boundary = value.get("information_boundary", {})
    if (
        value.get("schema")
        != "chacha20-round20-w52-direct-product-reader-pair-portfolio-a441-design-v1"
        or value.get("attempt_id") != ATTEMPT_ID
        or tuple(source.get("model_role_order", [])) != MODEL_ROLES
        or source.get("direct_product_pair_orders") != PRODUCT_READERS
        or source.get("W52_reader_refits") != 0
        or source.get("target_labels_used") != 0
        or source.get("candidate_assignments_executed") != 0
        or pair.get("axis_cells") != AXIS_CELLS
        or pair.get("pair_cells") != PAIR_CELLS
        or pair.get("artifact_bytes") != ARTIFACT_BYTES
        or pair.get("duplicate_free_complete_cover_required") is not True
        or boundary.get("A441_pair_order_computed_before_design_freeze") is not False
        or boundary.get("A426_secret_true_pair_result_stop_or_worker_progress_read")
        is not False
        or boundary.get("A438_result_stop_or_worker_progress_read") is not False
        or boundary.get("A440_result_stop_or_worker_progress_read") is not False
        or boundary.get("target_labels_used") != 0
        or boundary.get("reader_refits") != 0
    ):
        raise RuntimeError("A441 design semantics differ")
    anchors = value["source_anchors"]
    for key, item in anchors.items():
        if key.endswith("_path"):
            stem = key.removesuffix("_path")
            anchor(ROOT / item, anchors[f"{stem}_sha256"])
    return value


def load_a439() -> tuple[dict[str, Any], dict[str, list[int]], dict[str, list[int]]]:
    anchor(A439_RUNNER, A439_RUNNER_SHA256)
    anchor(A439_DESIGN, A439_DESIGN_SHA256)
    anchor(A439_IMPLEMENTATION, A439_IMPLEMENTATION_SHA256)
    anchor(A439_RESULT, A439_RESULT_SHA256)
    anchor(A439_CAUSAL, A439_CAUSAL_SHA256)
    value = A439.load_result(A439_RESULT_SHA256)
    prefix = {
        role: [int(item) for item in value["axes"]["prefix"]["source_orders"][role]]
        for role in MODEL_ROLES
    }
    off_axis = {
        role: [int(item) for item in value["axes"]["off_axis"]["source_orders"][role]]
        for role in MODEL_ROLES
    }
    if (
        value.get("result_commitment_sha256") != A439_RESULT_COMMITMENT_SHA256
        or value.get("pair_schedule", {}).get(
            "pair_stream_uint16be_uint16be_sha256"
        )
        != A439_PAIR_STREAM_SHA256
        or tuple(value.get("model_role_order", [])) != MODEL_ROLES
        or value.get("target_labels_used") != 0
        or value.get("reader_refits") != 0
        or value.get("candidate_assignments_executed") != 0
    ):
        raise RuntimeError("A441 A439 source semantics differ")
    for role in MODEL_ROLES:
        exact_axis_order(prefix[role], f"A439 prefix {role}")
        exact_axis_order(off_axis[role], f"A439 off-axis {role}")
    return value, prefix, off_axis


def freeze_implementation() -> dict[str, Any]:
    if IMPLEMENTATION.exists():
        raise FileExistsError("A441 implementation already exists")
    assert_pre_pair_order()
    design = load_design()
    a439, prefix, off_axis = load_a439()
    if not TEST.exists() or not REPRO.exists():
        raise FileNotFoundError("A441 tests and reproducer must precede freeze")
    payload: dict[str, Any] = {
        "schema": "chacha20-round20-w52-direct-product-reader-pair-portfolio-a441-implementation-v1",
        "attempt_id": ATTEMPT_ID,
        "commitment_state": "complete_direct_product_factor16_generator_frozen_before_any_A441_order_artifact_A426_A438_A440_target_outcome_or_progress",
        "design_sha256": DESIGN_SHA256,
        "source_A439_result_sha256": A439_RESULT_SHA256,
        "source_A439_result_commitment_sha256": a439[
            "result_commitment_sha256"
        ],
        "source_prefix_orders_sha256": canonical_sha256(prefix),
        "source_off_axis_orders_sha256": canonical_sha256(off_axis),
        "model_role_order": list(MODEL_ROLES),
        "product_role_order": [list(pair) for pair in product_roles(MODEL_ROLES)],
        "axis_cells": AXIS_CELLS,
        "pair_cells": PAIR_CELLS,
        "artifact_encoding": "uint16be_prefix_then_uint16be_off_axis",
        "artifact_bytes": ARTIFACT_BYTES,
        "default_chunk_ranks": DEFAULT_CHUNK_RANKS,
        "A441_pair_order_available_at_freeze": False,
        "A426_A438_A440_target_outcome_or_progress_available_at_freeze": False,
        "target_labels_used": 0,
        "reader_refits": 0,
        "candidate_assignments_executed": 0,
        "anchors": {
            "design": anchor(DESIGN, DESIGN_SHA256),
            "A439_runner": anchor(A439_RUNNER, A439_RUNNER_SHA256),
            "A439_design": anchor(A439_DESIGN, A439_DESIGN_SHA256),
            "A439_implementation": anchor(
                A439_IMPLEMENTATION, A439_IMPLEMENTATION_SHA256
            ),
            "A439_result": anchor(A439_RESULT, A439_RESULT_SHA256),
            "A439_causal": anchor(A439_CAUSAL, A439_CAUSAL_SHA256),
            "A434_runner": anchor(A434_RUNNER, A434_RUNNER_SHA256),
            "runner": anchor(Path(__file__)),
            "test": anchor(TEST),
            "reproducer": anchor(REPRO),
        },
        "design_contract": design["pair_order_contract"],
    }
    payload["implementation_commitment_sha256"] = canonical_sha256(payload)
    atomic_json(IMPLEMENTATION, payload)
    assert_pre_pair_order()
    return payload


def load_implementation(expected_sha256: str) -> dict[str, Any]:
    if file_sha256(IMPLEMENTATION) != expected_sha256:
        raise RuntimeError("A441 implementation hash differs")
    value = json.loads(IMPLEMENTATION.read_bytes())
    if (
        value.get("schema")
        != "chacha20-round20-w52-direct-product-reader-pair-portfolio-a441-implementation-v1"
        or value.get("attempt_id") != ATTEMPT_ID
        or value.get("design_sha256") != DESIGN_SHA256
        or value.get("source_A439_result_sha256") != A439_RESULT_SHA256
        or value.get("source_A439_result_commitment_sha256")
        != A439_RESULT_COMMITMENT_SHA256
        or tuple(value.get("model_role_order", [])) != MODEL_ROLES
        or value.get("axis_cells") != AXIS_CELLS
        or value.get("pair_cells") != PAIR_CELLS
        or value.get("artifact_bytes") != ARTIFACT_BYTES
        or value.get("A441_pair_order_available_at_freeze") is not False
        or value.get("A426_A438_A440_target_outcome_or_progress_available_at_freeze")
        is not False
        or value.get("target_labels_used") != 0
        or value.get("reader_refits") != 0
        or value.get("candidate_assignments_executed") != 0
    ):
        raise RuntimeError("A441 implementation semantics differ")
    for row in value["anchors"].values():
        anchor(path_from_ref(row["path"]), row["sha256"])
    unsigned = {
        key: item
        for key, item in value.items()
        if key != "implementation_commitment_sha256"
    }
    if value.get("implementation_commitment_sha256") != canonical_sha256(unsigned):
        raise RuntimeError("A441 implementation commitment differs")
    return value


def artifact_sentinels(path: Path, pair_cells: int, axis_cells: int) -> list[dict[str, int]]:
    words = np.memmap(path, dtype=">u4", mode="r", shape=(pair_cells,))
    sentinels = sorted(
        {0, 1, 2, 15, 16, 12345, pair_cells // 2, pair_cells - 2, pair_cells - 1}
    )
    output: list[dict[str, int]] = []
    for index in sentinels:
        word = int(words[index])
        prefix = word >> 16
        off_axis = word & 0xFFFF
        if not 0 <= prefix < axis_cells or not 0 <= off_axis < axis_cells:
            raise RuntimeError("A441 artifact sentinel left the pair domain")
        output.append(
            {
                "global_index": index,
                "prefix": prefix,
                "off_axis": off_axis,
            }
        )
    return output


def build_causal(payload: Mapping[str, Any]) -> dict[str, Any]:
    if str(DOTCAUSAL_SRC) not in sys.path:
        sys.path.insert(0, str(DOTCAUSAL_SRC))
    from dotcausal.io import CausalReader, CausalWriter

    writer = CausalWriter(api_id="a441pair")
    writer._rules = []
    writer.add_rule(
        name="frozen_axis_readers_to_sixteen_product_pair_orders",
        description="Cross four frozen prefix Readers with four frozen off-axis Readers before any axis-first collapse.",
        pattern=["A439_eight_refit_free_axis_orders"],
        conclusion="A441_sixteen_direct_product_pair_orders",
        confidence_modifier=1.0,
    )
    writer.add_rule(
        name="product_pair_orders_to_exact_factor16_portfolio",
        description="Stable minimum-rank wavefront merging yields a duplicate-free complete order with a pointwise factor-sixteen bound.",
        pattern=["A441_sixteen_direct_product_pair_orders"],
        conclusion="A441_exact_factor16_pair_portfolio",
        confidence_modifier=1.0,
    )
    writer.add_rule(
        name="direct_and_factorized_divergence_to_operator_diversity",
        description="Exact all-pair rank comparison measures information lost by axis-first factorization.",
        pattern=["A441_exact_factor16_pair_portfolio", "A439_factorized_pair_portfolio"],
        conclusion="A441_measured_pair_representation_diversity",
        confidence_modifier=1.0,
    )
    writer.add_rule(
        name="exact_portfolio_to_recovery_ready_schedule",
        description="The committed 64-MiB pair stream can be consumed directly by the qualified complete W52 subcell engine.",
        pattern=["A441_exact_factor16_pair_portfolio"],
        conclusion="A441_W52_recovery_ready",
        confidence_modifier=1.0,
    )
    writer.add_triplet(
        trigger="A439:eight_refit_free_axis_orders",
        mechanism="four_by_four_cross_axis_product_before_factorization",
        outcome="A441:sixteen_direct_product_pair_orders",
        confidence=1.0,
        source=payload["result_commitment_sha256"],
        quantification="4 prefix Readers x 4 off-axis Readers = 16 exact pair permutations",
        evidence=payload["source_product_contract_sha256"],
        domain="target-blind full-round ChaCha20 W52 ordering",
        quality_score=1.0,
    )
    writer.add_triplet(
        trigger="A441:sixteen_direct_product_pair_orders",
        mechanism="stable_minimum_rank_bucket_merge_with_exact_tie_key",
        outcome="A441:exact_factor16_pair_portfolio",
        confidence=1.0,
        source=payload["pair_order_sha256"],
        quantification=json.dumps(payload["pointwise_factor16_proof"], sort_keys=True),
        evidence=json.dumps(payload["artifact"], sort_keys=True),
        domain="exact complete 2^24 pair schedule",
        quality_score=1.0,
    )
    writer.add_triplet(
        trigger="A441:exact_factor16_pair_portfolio",
        mechanism="exact_all_pair_rank_comparison_against_axis_first_A439",
        outcome="A441:measured_pair_representation_diversity",
        confidence=1.0,
        source=payload["comparison_sha256"],
        quantification=json.dumps(payload["comparison_to_A439"], sort_keys=True),
        evidence="all 16,777,216 pair cells",
        domain="operator diversity in W52 pair space",
        quality_score=1.0,
    )
    writer.add_triplet(
        trigger="A441:exact_factor16_pair_portfolio",
        mechanism="memory_mappable_exact_pair_at_codec",
        outcome="A441:W52_recovery_ready",
        confidence=1.0,
        source=payload["pair_order_sha256"],
        quantification="16,777,216 duplicate-free cells; uint16be prefix + uint16be off-axis",
        evidence=payload["artifact"]["sha256"],
        domain="qualified A434 2^28-subcell execution",
        quality_score=1.0,
    )
    writer.add_triplet(
        trigger="A439:eight_refit_free_axis_orders",
        mechanism="materialized_direct_product_factor16_closure",
        outcome="A441:W52_recovery_ready",
        confidence=1.0,
        source="materialized:A441_direct_product_recovery_ready_chain",
        quantification="exact retained closure",
        evidence=payload["evidence_stage"],
        domain="AI-native retained inference",
        quality_score=1.0,
        is_inferred=True,
    )
    writer.add_cluster(
        name="A441 direct product Reader portfolio",
        entities=[
            "A439:eight_refit_free_axis_orders",
            "A441:sixteen_direct_product_pair_orders",
            "A441:exact_factor16_pair_portfolio",
            "A441:measured_pair_representation_diversity",
            "A441:W52_recovery_ready",
        ],
    )
    writer.add_gap(
        subject="A441:W52_recovery_ready",
        predicate="next_required_object",
        expected_object_type="factor2_union_with_A439_or_direct_recovery_execution",
        confidence=1.0,
        suggested_queries=[
            "If neither exact order dominates globally, construct a target-blind factor-two merger of A439 and A441 before allocating another W52 recovery run."
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
        reader.api_id != "a441pair"
        or len(explicit) != 4
        or len(all_rows) != 5
        or len(inferred) != 1
        or len(reader._rules) != 4
        or len(reader._clusters) != 1
        or len(reader._gaps) != 1
    ):
        raise RuntimeError("A441 authentic Causal reopen gate failed")
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
            "source_products": explicit[0],
            "factor16_order": explicit[1],
            "representation_diversity": explicit[2],
            "recovery_ready": explicit[3],
            "terminal_chain": all_rows[-1],
            "next_gap": reader._gaps[0],
        },
    }


def _build_result(*, expected_implementation_sha256: str) -> dict[str, Any]:
    if any(path.exists() for path in (RESULT, CAUSAL, REPORT, ORDER_ARTIFACT)):
        raise FileExistsError("A441 result or order artifact already exists")
    load_design()
    implementation = load_implementation(expected_implementation_sha256)
    a439, prefix_orders, off_axis_orders = load_a439()
    direct_rank, generation = build_direct_product_order(
        prefix_orders=prefix_orders,
        off_axis_orders=off_axis_orders,
        role_order=MODEL_ROLES,
        axis_cells=AXIS_CELLS,
        output_path=ORDER_ARTIFACT,
        chunk_ranks=DEFAULT_CHUNK_RANKS,
    )
    if file_sha256(ORDER_ARTIFACT) != generation["artifact_sha256"]:
        raise RuntimeError("A441 reopened artifact hash differs")
    reference_rank = reference_square_rank_vector(
        a439["axes"]["prefix"]["portfolio_order"],
        a439["axes"]["off_axis"]["portfolio_order"],
        AXIS_CELLS,
    )
    proof = factor_k_pair_proof(
        portfolio_rank=direct_rank,
        prefix_orders=prefix_orders,
        off_axis_orders=off_axis_orders,
        role_order=MODEL_ROLES,
        axis_cells=AXIS_CELLS,
        chunk_pairs=METRIC_CHUNK_PAIRS,
    )
    comparison = compare_rank_orders(direct_rank, reference_rank)
    sentinels = artifact_sentinels(ORDER_ARTIFACT, PAIR_CELLS, AXIS_CELLS)
    artifact = {
        "path": relative(ORDER_ARTIFACT),
        "sha256": generation["artifact_sha256"],
        "encoding": "uint16be_prefix_then_uint16be_off_axis",
        "bytes": ORDER_ARTIFACT.stat().st_size,
        "pair_cells": PAIR_CELLS,
        "direct_inverse_sentinels": sentinels,
        "memory_mappable": True,
        "reproducible_from_committed_source_orders": True,
    }
    core: dict[str, Any] = {
        "schema": "chacha20-round20-w52-direct-product-reader-pair-portfolio-a441-v1",
        "attempt_id": ATTEMPT_ID,
        "evidence_stage": "TARGET_BLIND_DIRECT_16_PRODUCT_READER_EXACT_FACTOR16_W52_PAIR_PORTFOLIO_RECOVERY_READY",
        "design_sha256": DESIGN_SHA256,
        "implementation_sha256": expected_implementation_sha256,
        "implementation_commitment_sha256": implementation[
            "implementation_commitment_sha256"
        ],
        "A439_result_sha256": A439_RESULT_SHA256,
        "A439_result_commitment_sha256": A439_RESULT_COMMITMENT_SHA256,
        "model_role_order": list(MODEL_ROLES),
        "product_role_order": [list(pair) for pair in product_roles(MODEL_ROLES)],
        "source_product_contract_sha256": canonical_sha256(
            {
                "prefix_orders_sha256": canonical_sha256(prefix_orders),
                "off_axis_orders_sha256": canonical_sha256(off_axis_orders),
                "product_role_order": product_roles(MODEL_ROLES),
            }
        ),
        "generation": generation,
        "artifact": artifact,
        "pointwise_factor16_proof": proof,
        "comparison_to_A439": comparison,
        "target_labels_used": 0,
        "reader_refits": 0,
        "candidate_assignments_executed": 0,
        "A426_A438_A440_secret_result_stop_or_worker_progress_read": False,
        "anchors": {
            "design": anchor(DESIGN, DESIGN_SHA256),
            "implementation": anchor(
                IMPLEMENTATION, expected_implementation_sha256
            ),
            "A439_runner": anchor(A439_RUNNER, A439_RUNNER_SHA256),
            "A439_result": anchor(A439_RESULT, A439_RESULT_SHA256),
            "A439_causal": anchor(A439_CAUSAL, A439_CAUSAL_SHA256),
            "A434_runner": anchor(A434_RUNNER, A434_RUNNER_SHA256),
            "runner": anchor(Path(__file__)),
            "test": anchor(TEST),
            "reproducer": anchor(REPRO),
        },
    }
    core["pair_order_sha256"] = canonical_sha256(
        {
            "artifact": artifact,
            "generation": generation,
            "pointwise_factor16_proof": proof,
        }
    )
    core["comparison_sha256"] = canonical_sha256(comparison)
    core["result_commitment_sha256"] = canonical_sha256(
        {
            "design_sha256": DESIGN_SHA256,
            "implementation_commitment_sha256": core[
                "implementation_commitment_sha256"
            ],
            "source_product_contract_sha256": core[
                "source_product_contract_sha256"
            ],
            "pair_order_sha256": core["pair_order_sha256"],
            "comparison_sha256": core["comparison_sha256"],
            "target_labels_used": 0,
            "reader_refits": 0,
            "candidate_assignments_executed": 0,
        }
    )
    core["causal"] = build_causal(core)
    atomic_json(RESULT, core)
    ratios = comparison["direct_over_A439_rank_ratio_quantiles"]
    report = (
        "# A441 — direct product-Reader W52 pair portfolio\n\n"
        f"Evidence stage: **{core['evidence_stage']}**\n\n"
        "- Frozen source Readers: **4 prefix x 4 off-axis = 16 direct product orders**\n"
        f"- Exact pair cells: **{PAIR_CELLS:,}**\n"
        f"- Pointwise factor-16 violations: **{proof['violations']}**\n"
        f"- Direct earlier / equal / later than A439: **{comparison['direct_earlier']:,} / {comparison['equal']:,} / {comparison['direct_later']:,}**\n"
        f"- Spearman versus A439: **{comparison['spearman_rank_correlation']:.9f}**\n"
        f"- Median direct/A439 rank ratio: **{ratios['p50']:.9f}**\n"
        f"- Exact artifact SHA-256: **{artifact['sha256']}**\n"
        "- Target labels / Reader refits / candidate executions: **0 / 0 / 0**\n"
        "- Authentic AI-native Causal readback: **4 explicit + 1 inferred**\n"
    )
    atomic_bytes(REPORT, report.encode())
    return core


def build_result(*, expected_implementation_sha256: str) -> dict[str, Any]:
    try:
        return _build_result(
            expected_implementation_sha256=expected_implementation_sha256
        )
    except BaseException:
        for path in (RESULT, CAUSAL, REPORT, ORDER_ARTIFACT):
            path.unlink(missing_ok=True)
        raise


def load_result(expected_sha256: str) -> dict[str, Any]:
    if file_sha256(RESULT) != expected_sha256:
        raise RuntimeError("A441 result hash differs")
    value = json.loads(RESULT.read_bytes())
    if (
        value.get("schema")
        != "chacha20-round20-w52-direct-product-reader-pair-portfolio-a441-v1"
        or value.get("attempt_id") != ATTEMPT_ID
        or value.get("pointwise_factor16_proof", {}).get("violations") != 0
        or value.get("artifact", {}).get("bytes") != ARTIFACT_BYTES
        or value.get("artifact", {}).get("pair_cells") != PAIR_CELLS
        or value.get("target_labels_used") != 0
        or value.get("reader_refits") != 0
        or value.get("candidate_assignments_executed") != 0
    ):
        raise RuntimeError("A441 result semantics differ")
    for row in value["anchors"].values():
        anchor(path_from_ref(row["path"]), row["sha256"])
    anchor(path_from_ref(value["artifact"]["path"]), value["artifact"]["sha256"])
    anchor(path_from_ref(value["causal"]["path"]), value["causal"]["sha256"])
    return value


def analyze() -> dict[str, Any]:
    payload: dict[str, Any] = {
        "attempt_id": ATTEMPT_ID,
        "design_sha256": file_sha256(DESIGN) if DESIGN.exists() else None,
        "implementation_frozen": IMPLEMENTATION.exists(),
        "order_artifact_complete": ORDER_ARTIFACT.exists(),
        "result_complete": RESULT.exists(),
        "axis_cells": AXIS_CELLS,
        "pair_cells": PAIR_CELLS,
        "product_readers": PRODUCT_READERS,
    }
    load_design()
    if IMPLEMENTATION.exists():
        payload["implementation_sha256"] = file_sha256(IMPLEMENTATION)
        load_implementation(payload["implementation_sha256"])
    if ORDER_ARTIFACT.exists():
        payload["order_artifact_sha256"] = file_sha256(ORDER_ARTIFACT)
        payload["order_artifact_bytes"] = ORDER_ARTIFACT.stat().st_size
    if RESULT.exists():
        payload["result_sha256"] = file_sha256(RESULT)
        value = load_result(payload["result_sha256"])
        payload["evidence_stage"] = value["evidence_stage"]
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

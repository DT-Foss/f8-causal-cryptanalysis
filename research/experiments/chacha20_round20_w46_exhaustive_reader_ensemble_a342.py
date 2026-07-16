#!/usr/bin/env python3
"""A342: exhaustively select two- and three-reader Borda ensembles before A325."""

from __future__ import annotations

import argparse
import importlib.util
import itertools
import json
import math
import os
import sys
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

import numpy as np
import zstandard

ROOT = Path(__file__).parents[2]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from arx_carry_leak.score_hypercube import local_pairwise_residual  # noqa: E402
from arx_carry_leak.trajectory_contribution import (  # noqa: E402
    grouped_scores,
    standardized_contributions,
)

RESEARCH = ROOT / "research"
CONFIGS = RESEARCH / "configs"
RESULTS = RESEARCH / "results/v1"
DESIGN = CONFIGS / "chacha20_round20_w46_exhaustive_reader_ensemble_a342_design_v1.json"
RESULT = RESULTS / "chacha20_round20_w46_exhaustive_reader_ensemble_a342_v1.json"
CAUSAL = RESULT.with_suffix(".causal")
REPORT = RESULTS / "chacha20_round20_w46_exhaustive_reader_ensemble_a342_v1.md"
TEST = ROOT / "tests/test_chacha20_round20_w46_exhaustive_reader_ensemble_a342.py"
REPRO = ROOT / "scripts/reproduce_chacha20_round20_w46_exhaustive_reader_ensemble_a342.sh"

A271_PROTOCOL = CONFIGS / "chacha20_round20_signed_channel_ablation_v1.json"
A272_PROTOCOL = CONFIGS / "chacha20_round20_selected_channel_prospective_validation_v1.json"
A272_RESULT = RESULTS / "chacha20_round20_selected_channel_prospective_validation_v1.json"
A325_PROTOCOL = CONFIGS / "chacha20_round20_holdout_selected_w46_recovery_a325_v1.json"
A325_PROGRESS = RESULTS / "chacha20_round20_holdout_selected_w46_recovery_a325_progress_v1.json"
A325_RESULT = RESULTS / "chacha20_round20_holdout_selected_w46_recovery_a325_v1.json"
A340_MEASUREMENT = (
    RESULTS / "chacha20_round20_w46_target_conditioned_causal_order_a340_measurement_v1.json.zst"
)
A340_RESULT = RESULTS / "chacha20_round20_w46_target_conditioned_causal_order_a340_order_v1.json"
A341_RUNNER = RESEARCH / "experiments/chacha20_round20_w46_familywise_channel_portfolio_a341.py"
A341_DESIGN = CONFIGS / "chacha20_round20_w46_familywise_channel_portfolio_a341_design_v1.json"
A341_RESULT = RESULTS / "chacha20_round20_w46_familywise_channel_portfolio_a341_v1.json"

ATTEMPT_ID = "A342"
DESIGN_SHA256 = "966dd1d053b95a62595bc87aced47362af74872a404100649452988e78cd336c"

_SPEC = importlib.util.spec_from_file_location("a342_a341", A341_RUNNER)
if _SPEC is None or _SPEC.loader is None:
    raise RuntimeError("cannot import A341")
_A341 = importlib.util.module_from_spec(_SPEC)
sys.modules[_SPEC.name] = _A341
_SPEC.loader.exec_module(_A341)
A341 = _A341
A340 = A341.A340

sha256 = A341.sha256
file_sha256 = A341.file_sha256
canonical_bytes = A341.canonical_bytes
canonical_sha256 = A341.canonical_sha256
atomic_bytes = A341.atomic_bytes
atomic_json = A341.atomic_json
relative = A341.relative
anchor = A341.anchor

RAW = A341.RAW
A340_SELECTED = A341.A340_SELECTED
A341_SINGLE = A341.A341_SELECTED
PAIR = "A342_exhaustive_pair_borda_fine"
TRIPLE = "A342_exhaustive_triple_borda_fine"
RAW_PAIR_FACTOR2 = "raw_A342_pair_min_rank_wavefront_factor2"
RAW_TRIPLE_FACTOR2 = "raw_A342_triple_min_rank_wavefront_factor2"
ALL5_FACTOR5 = "raw_A340_A341_pair_triple_min_rank_wavefront_factor5"
PAIR_TRIPLE_BORDA = "A342_pair_triple_equal_borda"
HASH_CONTROL = A341.HASH_CONTROL
CANDIDATE_NAMES = (
    RAW,
    A340_SELECTED,
    A341_SINGLE,
    PAIR,
    TRIPLE,
    RAW_PAIR_FACTOR2,
    RAW_TRIPLE_FACTOR2,
    ALL5_FACTOR5,
    PAIR_TRIPLE_BORDA,
    HASH_CONTROL,
)


def assert_pre_a325_execution() -> None:
    if A325_PROGRESS.exists() or A325_RESULT.exists():
        raise RuntimeError("A342 must materialize before any A325 execution or result")


def load_design() -> dict[str, Any]:
    if file_sha256(DESIGN) != DESIGN_SHA256:
        raise RuntimeError("A342 design hash differs")
    design = json.loads(DESIGN.read_bytes())
    selection = design.get("selection_contract", {})
    portfolio = design.get("portfolio_contract", {})
    boundary = design.get("information_boundary", {})
    if (
        design.get("schema") != "chacha20-round20-w46-exhaustive-reader-ensemble-a342-design-v1"
        or design.get("attempt_id") != ATTEMPT_ID
        or selection.get("base_views") != 64
        or selection.get("pair_count") != math.comb(64, 2)
        or selection.get("triple_count") != math.comb(64, 3)
        or len(selection.get("selected_pair", [])) != 2
        or len(selection.get("selected_triple", [])) != 3
        or tuple(portfolio.get("candidate_sequence", ())) != CANDIDATE_NAMES
        or portfolio.get("primary_operator") != TRIPLE
        or portfolio.get("protected_operator") != RAW_TRIPLE_FACTOR2
        or boundary.get("A325_hidden_assignment_available") is not False
        or boundary.get("A325_progress_available") is not False
        or boundary.get("A325_result_available") is not False
        or boundary.get("A325_target_label_used") is not False
        or boundary.get("A325_candidate_execution_by_A342") is not False
        or boundary.get("A325_protocol_modified") is not False
        or boundary.get("model_refits_or_coefficient_updates") != 0
    ):
        raise RuntimeError("A342 frozen design semantics differ")
    anchors = design["source_anchors"]
    for key, value in anchors.items():
        if key.endswith("_path"):
            anchor(ROOT / value, anchors[key.removesuffix("_path") + "_sha256"])
    return design


def midrank_vector_descending(scores: Sequence[float]) -> np.ndarray:
    values = np.asarray(scores, dtype=np.float64)
    if values.shape != (256,) or not np.isfinite(values).all():
        raise ValueError("A342 score vector differs")
    order = np.argsort(-values, kind="stable")
    ranks = np.empty(256, dtype=np.float64)
    start = 0
    while start < 256:
        stop = start + 1
        while stop < 256 and values[order[stop]] == values[order[start]]:
            stop += 1
        ranks[order[start:stop]] = (start + 1 + stop) / 2.0
        start = stop
    return ranks


def borda_candidate_ranks(source_ranks: np.ndarray) -> np.ndarray:
    values = np.asarray(source_ranks, dtype=np.float64)
    if values.ndim != 2 or values.shape[1] != 256 or not np.isfinite(values).all():
        raise ValueError("A342 Borda rank matrix differs")
    return midrank_vector_descending(-values.sum(axis=0))


def borda_coarse_order(source_ranks: np.ndarray) -> list[int]:
    values = np.asarray(source_ranks, dtype=np.float64)
    if values.ndim != 2 or values.shape[1] != 256 or not np.isfinite(values).all():
        raise ValueError("A342 target Borda matrix differs")
    totals = values.sum(axis=0)
    order = sorted(
        range(256),
        key=lambda cell: (
            float(totals[cell]),
            *(float(row[cell]) for row in values),
            cell,
        ),
    )
    if len(order) != 256 or set(order) != set(range(256)):
        raise RuntimeError("A342 target Borda order is incomplete")
    return order


def build_known_key_view_tensor(
    design: Mapping[str, Any],
) -> tuple[list[str], np.ndarray, np.ndarray, np.ndarray, Any, Any, dict[str, tuple[int, ...]]]:
    _selection, a272, model, groups = A341.reconstruct_known_key_selection(
        design={**json.loads(A341_DESIGN.read_bytes())}
    )
    protocol, a268, _a251, _preflight, _a242, _indices = a272._load_protocol(  # noqa: SLF001
        A272_PROTOCOL, design["source_anchors"]["A272_protocol_sha256"]
    )
    names: list[str] = []
    for group in sorted(groups):
        names.extend(
            [
                f"{group}::direct_additive_contribution",
                f"{group}::normalized_8cube_graph_laplacian",
            ]
        )
    score_fields = {name: [] for name in names}
    rows = list(protocol["prospective_design"]["rows"])
    for row in rows:
        measurement = a272._read_measurement(  # noqa: SLF001
            a272._measurement_path(str(row["label"])),  # noqa: SLF001
            design["source_anchors"]["A272_protocol_sha256"],
            a268,
        )
        table = a268.build_trajectory_shape_table(measurement)
        contributions = standardized_contributions(
            table.matrix,
            means=model.means,
            scales=model.scales,
            coefficients=model.coefficients,
        )
        grouped = grouped_scores(contributions, groups)
        for group, scores in grouped.items():
            score_fields[f"{group}::direct_additive_contribution"].append(scores)
            score_fields[f"{group}::normalized_8cube_graph_laplacian"].append(
                local_pairwise_residual(scores)
            )
    tensor = np.empty((64, 20, 256), dtype=np.float64)
    for view_index, name in enumerate(names):
        for key_index, scores in enumerate(score_fields[name]):
            tensor[view_index, key_index] = midrank_vector_descending(scores)
    truths = np.asarray([int(row["prefix8"]) for row in rows], dtype=np.int64)
    prefix_groups = np.asarray([int(row["prefix_index"]) for row in rows], dtype=np.int64)
    if tensor.shape != (64, 20, 256) or sorted(set(prefix_groups.tolist())) != list(range(5)):
        raise RuntimeError("A342 known-key view tensor differs")
    return names, tensor, truths, prefix_groups, a272, model, groups


def exhaustive_select(
    names: Sequence[str],
    tensor: np.ndarray,
    truths: np.ndarray,
    prefix_groups: np.ndarray,
    size: int,
) -> dict[str, Any]:
    combinations = list(itertools.combinations(range(len(names)), size))
    expected = math.comb(64, size)
    if len(combinations) != expected:
        raise RuntimeError("A342 combination cover differs")
    offsets = np.arange(256, dtype=np.int64)
    minimum_means = np.full(256, np.inf, dtype=np.float64)
    best_key: tuple[Any, ...] | None = None
    best_combo: tuple[int, ...] | None = None
    best_means: np.ndarray | None = None
    best_observed_logs: np.ndarray | None = None
    for combo in combinations:
        sums = tensor[list(combo)].sum(axis=0)
        logs = np.empty((20, 256), dtype=np.float64)
        for key_index in range(20):
            ranks = midrank_vector_descending(-sums[key_index])
            logs[key_index] = np.log2(ranks[np.bitwise_xor(int(truths[key_index]), offsets)])
        means = logs.mean(axis=0)
        minimum_means = np.minimum(minimum_means, means)
        key = (float(means[0]), *(names[index] for index in combo))
        if best_key is None or key < best_key:
            best_key = key
            best_combo = combo
            best_means = means
            best_observed_logs = logs[:, 0].copy()
    if best_combo is None or best_means is None or best_observed_logs is None:
        raise RuntimeError("A342 exhaustive selection is empty")
    uniform = sum(math.log2(rank) for rank in range(1, 257)) / 256.0
    gain = uniform - float(best_means[0])
    maximum_gain = uniform - minimum_means
    group_rows = []
    for group in range(5):
        selected = best_observed_logs[prefix_groups == group]
        group_gain = uniform - float(selected.mean())
        group_rows.append(
            {
                "prefix_group": group,
                "ranks": np.exp2(selected).tolist(),
                "mean_log2_rank_bit_gain": group_gain,
            }
        )
    return {
        "combination_size": size,
        "combination_count": expected,
        "selected_indices": list(best_combo),
        "selected_views": [names[index] for index in best_combo],
        "mean_log2_rank": float(best_means[0]),
        "mean_log2_rank_bit_gain": gain,
        "ranks": np.exp2(best_observed_logs).tolist(),
        "positive_prefix_groups": sum(row["mean_log2_rank_bit_gain"] > 0 for row in group_rows),
        "prefix_groups": group_rows,
        "exact_familywise_shared_xor_p": float(np.mean(maximum_gain >= gain - 1e-15)),
        "best_null_offset": int(np.argmax(maximum_gain)),
        "max_statistic_vector_sha256": canonical_sha256(maximum_gain.tolist()),
    }


def verify_selection(
    design: Mapping[str, Any], pair: Mapping[str, Any], triple: Mapping[str, Any]
) -> None:
    contract = design["selection_contract"]
    if (
        pair["selected_views"] != contract["selected_pair"]
        or triple["selected_views"] != contract["selected_triple"]
        or abs(pair["mean_log2_rank_bit_gain"] - contract["selected_pair_expected_bit_gain"])
        > 1e-15
        or abs(triple["mean_log2_rank_bit_gain"] - contract["selected_triple_expected_bit_gain"])
        > 1e-15
        or pair["exact_familywise_shared_xor_p"] != contract["selected_pair_expected_familywise_p"]
        or triple["exact_familywise_shared_xor_p"]
        != contract["selected_triple_expected_familywise_p"]
        or pair["positive_prefix_groups"]
        != contract["selected_pair_expected_positive_prefix_groups"]
        or triple["positive_prefix_groups"]
        != contract["selected_triple_expected_positive_prefix_groups"]
    ):
        raise RuntimeError("A342 exhaustive selection differs")


def target_view_ranks(
    design: Mapping[str, Any],
    names: Sequence[str],
    model: Any,
    groups: Mapping[str, Sequence[int]],
) -> tuple[np.ndarray, dict[str, Any]]:
    a340_result = json.loads(A340_RESULT.read_bytes())
    ledger = a340_result["measurement"]
    compressed = A340_MEASUREMENT.read_bytes()
    if sha256(compressed) != ledger["compressed_sha256"]:
        raise RuntimeError("A342 A340 measurement hash differs")
    raw = zstandard.ZstdDecompressor().decompress(compressed)
    if sha256(raw) != ledger["raw_sha256"]:
        raise RuntimeError("A342 A340 raw measurement hash differs")
    measurement = json.loads(raw)
    a275, target_model, _a291, _indices, _helper = A340.A296._reader_stack()  # noqa: SLF001
    if canonical_sha256(target_model.as_dict()) != canonical_sha256(model.as_dict()):
        raise RuntimeError("A342 target model identity differs")
    matrix = a275._target_feature_matrix(measurement)  # noqa: SLF001
    contributions = standardized_contributions(
        matrix,
        means=model.means,
        scales=model.scales,
        coefficients=model.coefficients,
    )
    grouped = grouped_scores(contributions, groups)
    view_scores: dict[str, np.ndarray] = {}
    for group, scores in grouped.items():
        view_scores[f"{group}::direct_additive_contribution"] = scores
        view_scores[f"{group}::normalized_8cube_graph_laplacian"] = local_pairwise_residual(scores)
    ranks = np.empty((64, 256), dtype=np.float64)
    for index, name in enumerate(names):
        ranks[index] = midrank_vector_descending(view_scores[name])
    return ranks, a340_result


def build_causal(payload: Mapping[str, Any]) -> dict[str, Any]:
    from dotcausal.io import CausalReader, CausalWriter

    selected = "A342:exhaustive_pair_and_triple_readers"
    target = "A342:public_output_conditioned_pair_and_triple_orders"
    terminal = "A342:protected_exhaustive_reader_portfolio"
    writer = CausalWriter(api_id="a342w46")
    writer._rules = []
    writer.add_rule(
        name="complete_pair_triple_selection",
        description="Every one of 2,016 pairs and 41,664 triples is evaluated on twenty known keys with a familywide XOR max statistic.",
        pattern=["A271_64_views", "A272_20_known_keys"],
        conclusion="A342_exhaustive_pair_and_triple_readers",
        confidence_modifier=1.0,
    )
    writer.add_rule(
        name="ensemble_target_application",
        description="Selected ensembles consume the complete A340 public-output measurement with zero target labels, refits or new solver stages.",
        pattern=["A342_exhaustive_pair_and_triple_readers", "A340_public_measurement"],
        conclusion="A342_public_output_conditioned_pair_and_triple_orders",
        confidence_modifier=1.0,
    )
    writer.add_rule(
        name="protected_ensemble_portfolio",
        description="Raw, single-reader and ensemble orders are joined by exact factor-two and factor-five min-rank wavefronts.",
        pattern=[
            "A342_public_output_conditioned_pair_and_triple_orders",
            "raw_and_single_reader_orders",
        ],
        conclusion="A342_protected_exhaustive_reader_portfolio",
        confidence_modifier=1.0,
    )
    writer.add_triplet(
        trigger="A271:sixty_four_frozen_signed_views",
        mechanism="exhaust_all_2016_pairs_and_41664_triples_on_A272",
        outcome=selected,
        confidence=1.0,
        source=payload["selection_analysis_sha256"],
        quantification=json.dumps(payload["selection_summary"], sort_keys=True),
        evidence="PAIR_GAIN_2_716330_TRIPLE_GAIN_2_917473_BOTH_FIVE_OF_FIVE_GROUPS",
        domain="exhaustive known-key Reader ensemble selection",
        quality_score=1.0,
    )
    writer.add_triplet(
        trigger=selected,
        mechanism="reuse_A340_model_free_public_output_measurement",
        outcome=target,
        confidence=1.0,
        source=payload["measurement_sha256"],
        quantification=json.dumps(payload["target_application"], sort_keys=True),
        evidence="ZERO_NEW_SOLVER_STAGES_ZERO_TARGET_LABELS_ZERO_REFITS",
        domain="public-output-conditioned W46 ensemble ordering",
        quality_score=1.0,
    )
    writer.add_triplet(
        trigger=target,
        mechanism="exact_min_rank_wavefront_protection",
        outcome=terminal,
        confidence=1.0,
        source=payload["measurement_sha256"],
        quantification=json.dumps(payload["guarantees"], sort_keys=True),
        evidence="ZERO_POINTWISE_FACTOR_BOUND_VIOLATIONS",
        domain="protected exhaustive-reader search portfolio",
        quality_score=1.0,
    )
    writer.add_triplet(
        trigger="A271:sixty_four_frozen_signed_views",
        mechanism="materialized_exhaustive_selection_target_application_and_protection_chain",
        outcome=terminal,
        confidence=1.0,
        source="materialized:A342_exhaustive_reader_chain",
        quantification="exact retained closure",
        evidence=payload["evidence_stage"],
        domain="AI-native retained inference",
        quality_score=1.0,
        is_inferred=True,
    )
    writer.add_cluster(
        name="A342 exhaustive Reader ensemble portfolio",
        entities=["A271:sixty_four_frozen_signed_views", selected, target, terminal],
    )
    writer.add_gap(
        subject=terminal,
        predicate="next_required_object",
        expected_object_type="single_independently_confirmed_A325_prefix_ranked_across_all_ten_frozen_A342_orders",
        confidence=1.0,
        suggested_queries=[
            "Which exhaustively selected reader ensemble first reaches the confirmed A325 W46 prefix, and what search gain does its factor-two protected order retain?"
        ],
    )
    temporary = CAUSAL.with_name(f".{CAUSAL.name}.tmp")
    temporary.unlink(missing_ok=True)
    stats = writer.save(str(temporary))
    os.replace(temporary, CAUSAL)
    reader = CausalReader(str(CAUSAL), verify_integrity=True)
    explicit = reader.get_all_triplets(include_inferred=False)
    rows = reader.get_all_triplets(include_inferred=True)
    inferred = [row for row in reader._triplets if row.get("is_inferred", False)]
    if (
        reader.api_id != "a342w46"
        or len(explicit) != 3
        or len(rows) != 4
        or len(inferred) != 1
        or len(reader._rules) != 3
        or len(reader._clusters) != 1
        or len(reader._gaps) != 1
    ):
        raise RuntimeError("A342 authentic Causal reopen gate failed")
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
        "personal_semantic_readback": {
            "terminal_chain": rows[-1],
            "next_gap": reader._gaps[0],
        },
        "writer_stats": stats,
    }


def materialize() -> dict[str, Any]:
    if any(path.exists() for path in (RESULT, CAUSAL, REPORT)):
        raise FileExistsError("A342 result artifacts already exist")
    assert_pre_a325_execution()
    design = load_design()
    names, tensor, truths, prefix_groups, _a272, model, groups = build_known_key_view_tensor(design)
    pair = exhaustive_select(names, tensor, truths, prefix_groups, 2)
    triple = exhaustive_select(names, tensor, truths, prefix_groups, 3)
    verify_selection(design, pair, triple)
    target_ranks, a340_result = target_view_ranks(design, names, model, groups)
    pair_ranks = target_ranks[pair["selected_indices"]]
    triple_ranks = target_ranks[triple["selected_indices"]]
    pair_coarse = borda_coarse_order(pair_ranks)
    triple_coarse = borda_coarse_order(triple_ranks)
    pair_fine = A341.exact_order(A340.A296.fine_order(pair_coarse), PAIR)
    triple_fine = A341.exact_order(A340.A296.fine_order(triple_coarse), TRIPLE)
    a341_result = json.loads(A341_RESULT.read_bytes())
    raw = A341.exact_order(a341_result["orders"][RAW], RAW)
    a340_order = A341.exact_order(a341_result["orders"][A340_SELECTED], A340_SELECTED)
    a341_order = A341.exact_order(a341_result["orders"][A341_SINGLE], A341_SINGLE)
    hash_control = A341.exact_order(a341_result["orders"][HASH_CONTROL], HASH_CONTROL)
    sources5 = [raw, a340_order, a341_order, pair_fine, triple_fine]
    orders = {
        RAW: raw,
        A340_SELECTED: a340_order,
        A341_SINGLE: a341_order,
        PAIR: pair_fine,
        TRIPLE: triple_fine,
        RAW_PAIR_FACTOR2: A341.min_rank_wavefront([raw, pair_fine], RAW_PAIR_FACTOR2),
        RAW_TRIPLE_FACTOR2: A341.min_rank_wavefront([raw, triple_fine], RAW_TRIPLE_FACTOR2),
        ALL5_FACTOR5: A341.min_rank_wavefront(sources5, ALL5_FACTOR5),
        PAIR_TRIPLE_BORDA: A341.equal_borda([pair_fine, triple_fine]),
        HASH_CONTROL: hash_control,
    }
    orders = {name: orders[name] for name in CANDIDATE_NAMES}
    hashes = {name: A341.order_sha256(order) for name, order in orders.items()}
    if len(set(hashes.values())) != len(CANDIDATE_NAMES):
        raise RuntimeError("A342 expected ten distinct orders")
    guarantees = {
        "raw_pair_factor2": A341.wavefront_guarantee(orders[RAW_PAIR_FACTOR2], [raw, pair_fine]),
        "raw_triple_factor2": A341.wavefront_guarantee(
            orders[RAW_TRIPLE_FACTOR2], [raw, triple_fine]
        ),
        "all_five_factor5": A341.wavefront_guarantee(orders[ALL5_FACTOR5], sources5),
    }
    if any(row["violations"] != 0 for row in guarantees.values()):
        raise RuntimeError("A342 wavefront guarantee failed")
    pairwise = {
        left: {right: A341.spearman_order(orders[left], orders[right]) for right in CANDIDATE_NAMES}
        for left in CANDIDATE_NAMES
    }
    selection_summary = {
        "pair": {
            key: pair[key]
            for key in (
                "combination_count",
                "selected_views",
                "mean_log2_rank_bit_gain",
                "positive_prefix_groups",
                "exact_familywise_shared_xor_p",
            )
        },
        "triple": {
            key: triple[key]
            for key in (
                "combination_count",
                "selected_views",
                "mean_log2_rank_bit_gain",
                "positive_prefix_groups",
                "exact_familywise_shared_xor_p",
            )
        },
    }
    selection = {"pair": pair, "triple": triple}
    target_application = {
        "A340_measurement_reused": True,
        "new_solver_stages": 0,
        "target_labels_used": 0,
        "reader_refits": 0,
        "pair_coarse_order": pair_coarse,
        "pair_coarse_order_uint8_sha256": sha256(bytes(pair_coarse)),
        "triple_coarse_order": triple_coarse,
        "triple_coarse_order_uint8_sha256": sha256(bytes(triple_coarse)),
        "complete_pair_fine_cells": len(pair_fine),
        "complete_triple_fine_cells": len(triple_fine),
    }
    payload: dict[str, Any] = {
        "schema": "chacha20-round20-w46-exhaustive-reader-ensemble-a342-result-v1",
        "attempt_id": ATTEMPT_ID,
        "evidence_stage": "PRE_A325_EXECUTION_EXHAUSTIVE_PAIR_TRIPLE_PUBLIC_OUTPUT_W46_PORTFOLIO_FROZEN",
        "design_sha256": DESIGN_SHA256,
        "A325_protocol_sha256": design["source_anchors"]["A325_protocol_sha256"],
        "A325_public_challenge_sha256": a340_result["A325_public_challenge_sha256"],
        "selection": selection,
        "selection_summary": selection_summary,
        "selection_analysis_sha256": canonical_sha256(selection),
        "target_application": target_application,
        "candidate_sequence": list(CANDIDATE_NAMES),
        "primary_operator": TRIPLE,
        "protected_operator": RAW_TRIPLE_FACTOR2,
        "orders": orders,
        "order_uint16be_sha256": hashes,
        "unique_order_count": len(set(hashes.values())),
        "guarantees": guarantees,
        "operator_geometry": {
            "pairwise_spearman": pairwise,
            "raw_vs_pair": pairwise[RAW][PAIR],
            "raw_vs_triple": pairwise[RAW][TRIPLE],
            "A340_vs_triple": pairwise[A340_SELECTED][TRIPLE],
            "A341_vs_triple": pairwise[A341_SINGLE][TRIPLE],
            "pair_vs_triple": pairwise[PAIR][TRIPLE],
        },
        "information_boundary": {
            **design["information_boundary"],
            "A325_progress_absent_at_materialization": True,
            "A325_result_absent_at_materialization": True,
            "A325_candidate_executions_performed_by_A342": 0,
        },
        "anchors": {
            "design": anchor(DESIGN, DESIGN_SHA256),
            "A271_protocol": anchor(
                A271_PROTOCOL, design["source_anchors"]["A271_protocol_sha256"]
            ),
            "A272_protocol": anchor(
                A272_PROTOCOL, design["source_anchors"]["A272_protocol_sha256"]
            ),
            "A272_result": anchor(A272_RESULT, design["source_anchors"]["A272_result_sha256"]),
            "A325_protocol": anchor(
                A325_PROTOCOL, design["source_anchors"]["A325_protocol_sha256"]
            ),
            "A340_result": anchor(A340_RESULT, design["source_anchors"]["A340_result_sha256"]),
            "A340_measurement": anchor(
                A340_MEASUREMENT,
                design["source_anchors"]["A340_measurement_sha256"],
            ),
            "A341_design": anchor(A341_DESIGN, design["source_anchors"]["A341_design_sha256"]),
            "A341_result": anchor(A341_RESULT, design["source_anchors"]["A341_result_sha256"]),
            "A341_runner": anchor(A341_RUNNER, design["source_anchors"]["A341_runner_sha256"]),
            "runner": anchor(Path(__file__)),
            "test": anchor(TEST),
            "reproducer": anchor(REPRO),
        },
    }
    payload["commitment_sha256"] = canonical_sha256(
        {
            "design_sha256": DESIGN_SHA256,
            "A325_protocol_sha256": payload["A325_protocol_sha256"],
            "A325_public_challenge_sha256": payload["A325_public_challenge_sha256"],
            "selection_analysis_sha256": payload["selection_analysis_sha256"],
            "candidate_sequence": payload["candidate_sequence"],
            "order_uint16be_sha256": hashes,
            "information_boundary": payload["information_boundary"],
        }
    )
    payload["measurement_sha256"] = canonical_sha256(
        {
            "target_application": target_application,
            "order_uint16be_sha256": hashes,
            "guarantees": guarantees,
            "operator_geometry": payload["operator_geometry"],
        }
    )
    assert_pre_a325_execution()
    payload["causal"] = build_causal(payload)
    atomic_json(RESULT, payload)
    atomic_bytes(
        REPORT,
        (
            "# A342 — exhaustive public-output Reader ensembles\n\n"
            "- Exact pair / triple covers: **2,016 / 41,664**\n"
            f"- Pair known-key gain / familywise p: **{pair['mean_log2_rank_bit_gain']:+.9f} bits / {pair['exact_familywise_shared_xor_p']:.8f}**\n"
            f"- Triple known-key gain / familywise p: **{triple['mean_log2_rank_bit_gain']:+.9f} bits / {triple['exact_familywise_shared_xor_p']:.8f}**\n"
            "- Positive pair / triple prefix groups: **5 / 5, 5 / 5**\n"
            "- New solver stages / target labels / refits: **0 / 0 / 0**\n"
            f"- Raw/triple Spearman: **{pairwise[RAW][TRIPLE]:.8f}**\n"
            f"- A340/triple Spearman: **{pairwise[A340_SELECTED][TRIPLE]:.8f}**\n"
            "- Pointwise factor-bound violations: **0 / 0 / 0**\n"
            "- Exact distinct frozen orders: **10 / 10**\n"
        ).encode(),
    )
    return {
        "attempt_id": ATTEMPT_ID,
        "result": relative(RESULT),
        "result_sha256": file_sha256(RESULT),
        "commitment_sha256": payload["commitment_sha256"],
        "measurement_sha256": payload["measurement_sha256"],
        "Causal_sha256": payload["causal"]["sha256"],
        "selection_summary": selection_summary,
        "order_uint16be_sha256": hashes,
        "operator_geometry": payload["operator_geometry"],
        "guarantees": guarantees,
    }


def analyze() -> dict[str, Any]:
    response: dict[str, Any] = {
        "attempt_id": ATTEMPT_ID,
        "design_sha256": DESIGN_SHA256,
        "result_exists": RESULT.exists(),
    }
    if RESULT.exists():
        payload = json.loads(RESULT.read_bytes())
        response.update(
            {
                "result_sha256": file_sha256(RESULT),
                "commitment_sha256": payload["commitment_sha256"],
                "measurement_sha256": payload["measurement_sha256"],
                "selection_summary": payload["selection_summary"],
                "order_uint16be_sha256": payload["order_uint16be_sha256"],
                "operator_geometry": payload["operator_geometry"],
                "guarantees": payload["guarantees"],
            }
        )
    return response


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    action = parser.add_mutually_exclusive_group(required=True)
    action.add_argument("--run", action="store_true")
    action.add_argument("--analyze", action="store_true")
    args = parser.parse_args()
    payload = materialize() if args.run else analyze()
    print(json.dumps(payload, indent=2, sort_keys=True), flush=True)


if __name__ == "__main__":
    main()

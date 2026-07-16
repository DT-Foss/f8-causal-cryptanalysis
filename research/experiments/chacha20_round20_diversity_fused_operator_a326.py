#!/usr/bin/env python3
"""A326: turn A323 operator complementarity into executable fused orders."""

from __future__ import annotations

import argparse
import importlib.util
import inspect
import json
import math
import os
import sys
from collections.abc import Mapping, Sequence
from decimal import ROUND_HALF_UP, Decimal
from pathlib import Path
from typing import Any

ROOT = Path(__file__).parents[2]
RESEARCH = ROOT / "research"
CONFIGS = RESEARCH / "configs"
RESULTS = RESEARCH / "results/v1"

DESIGN = CONFIGS / "chacha20_round20_diversity_fused_operator_a326_design_v1.json"
ORDER = RESULTS / "chacha20_round20_diversity_fused_operator_a326_order_v1.json"
CAUSAL = RESULTS / "chacha20_round20_diversity_fused_operator_a326_order_v1.causal"
REPORT = RESULTS / "chacha20_round20_diversity_fused_operator_a326_order_v1.md"

A321_RUNNER = RESEARCH / "experiments/chacha20_round20_holdout_selected_w45_operator_a321.py"
A313_RESULT = RESULTS / "chacha20_round20_w44_width_conditioned_fine_portfolio_a313_v1.json"
A323_RESULT = RESULTS / "chacha20_round20_cross_width_operator_stability_a323_v1.json"
A322_RESULT = RESULTS / "chacha20_round20_holdout_selected_w45_recovery_a322_v1.json"
A325_PROGRESS = RESULTS / "chacha20_round20_holdout_selected_w46_recovery_a325_progress_v1.json"
A325_RESULT = RESULTS / "chacha20_round20_holdout_selected_w46_recovery_a325_v1.json"
A326_TEST = ROOT / "tests/test_chacha20_round20_diversity_fused_operator_a326.py"
A326_REPRO = ROOT / "scripts/reproduce_chacha20_round20_diversity_fused_operator_a326.sh"

ATTEMPT_ID = "A326"
DESIGN_SHA256 = "264623129a5d9fd247988b6710e50a3d0a444378b008e015011ed319593dd902"
A313_RESULT_SHA256 = "ec18ee284da633589d1c35fe8f02257438f83fb4f255553667ebc3a0b0452b9a"
A323_RESULT_SHA256 = "a4cb0e040eccbe0f4c586b3ae28f5ab2b07be70f4942f608a99617e2160b603f"
CELLS = 1 << 12
RRF_K = 60
RRF_NUMERATOR = 1 << 48
WEIGHT_SCALE = 1_000_000
FUSION_NAMES = (
    "min_rank_wavefront",
    "top2_rank_sum",
    "borda_rank_sum",
    "fixed_point_rrf_k60",
    "stability_weighted_borda",
    "stability_weighted_fixed_point_rrf_k60",
)


def load_module(path: Path, name: str) -> Any:
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot import A326 dependency {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


A321 = load_module(A321_RUNNER, "a326_a321_common")
file_sha256 = A321.file_sha256
canonical_sha256 = A321.canonical_sha256
atomic_json = A321.atomic_json
atomic_bytes = A321.atomic_bytes
relative = A321.relative
path_from_ref = A321.path_from_ref
anchor = A321.anchor
DOTCAUSAL_SRC = A321.DOTCAUSAL_SRC


def _exact_order(values: Sequence[int], label: str) -> list[int]:
    order = [int(value) for value in values]
    if len(order) != CELLS or set(order) != set(range(CELLS)):
        raise ValueError(f"A326 {label} is not an exact 4,096-cell cover")
    return order


def _order_sha(values: Sequence[int]) -> str:
    return A321._order_sha(_exact_order(values, "order hash"))  # noqa: SLF001


def rank_vector(order: Sequence[int]) -> list[int]:
    ranks = [0] * CELLS
    for rank, cell in enumerate(_exact_order(order, "rank vector"), 1):
        ranks[cell] = rank
    return ranks


def spearman(left: Sequence[int], right: Sequence[int]) -> float:
    x = rank_vector(left)
    y = rank_vector(right)
    mean = (CELLS + 1) / 2.0
    numerator = sum((a - mean) * (b - mean) for a, b in zip(x, y, strict=True))
    denominator = math.sqrt(
        sum((a - mean) ** 2 for a in x) * sum((b - mean) ** 2 for b in y)
    )
    return numerator / denominator


def load_design() -> dict[str, Any]:
    if file_sha256(DESIGN) != DESIGN_SHA256:
        raise RuntimeError("A326 design hash differs")
    design = json.loads(DESIGN.read_bytes())
    fusion = design.get("fusion_contract", {})
    selection = design.get("selection_contract", {})
    boundary = design.get("information_boundary", {})
    if (
        design.get("schema")
        != "chacha20-round20-diversity-fused-operator-a326-design-v1"
        or design.get("attempt_id") != ATTEMPT_ID
        or design.get("design_state")
        != "frozen_while_A322_is_running_before_any_A322_result_and_before_any_A325_execution_or_result"
        or tuple(fusion.get("source_operator_sequence", ())) != A321.CANDIDATE_NAMES
        or tuple(fusion.get("candidate_sequence_and_tie_break", ())) != FUSION_NAMES
        or fusion.get("rrf_k") != RRF_K
        or fusion.get("rrf_fixed_point_numerator") != RRF_NUMERATOR
        or fusion.get("target_labels_used_to_construct_fusions") != 0
        or fusion.get("candidate_execution") is not False
        or selection.get("selection_rule")
        != "minimum_A313_rank_then_frozen_fusion_index"
        or selection.get("A322_progress_or_result_used") is not False
        or selection.get("A325_public_challenge_features_used") is not False
        or selection.get("A325_target_label_prefix_filter_or_result_used") is not False
        or boundary.get("A322_result_available_at_design_freeze") is not False
        or boundary.get("A322_progress_used_for_any_fusion_or_selection") is not False
        or boundary.get("A325_execution_started_at_design_freeze") is not False
        or boundary.get(
            "A325_progress_result_candidate_or_prefix_rank_available_at_design_freeze"
        )
        is not False
        or boundary.get("target_labels_used_from_A322_or_A325") != 0
    ):
        raise RuntimeError("A326 frozen design semantics differ")
    for key, value in design["source_anchors"].items():
        if key.endswith("_path"):
            anchor(
                path_from_ref(value),
                design["source_anchors"][key.removesuffix("_path") + "_sha256"],
            )
    return design


def stability_weights(
    pairs: Sequence[Mapping[str, Any]], a323: Mapping[str, Any]
) -> dict[str, int]:
    correlations = a323["analysis"]["cross_width_spearman"]
    weights: dict[str, int] = {}
    for row in pairs:
        value = Decimal(str(correlations[row["name"]])) * WEIGHT_SCALE
        weights[row["name"]] = max(1, int(value.quantize(Decimal("1"), rounding=ROUND_HALF_UP)))
    return weights


def fusion_order(
    source_orders: Sequence[Sequence[int]],
    *,
    fusion_name: str,
    weights: Sequence[int],
) -> list[int]:
    if fusion_name not in FUSION_NAMES:
        raise ValueError(f"unknown A326 fusion {fusion_name}")
    rank_rows = [rank_vector(order) for order in source_orders]
    if len(rank_rows) != len(A321.CANDIDATE_NAMES) or len(weights) != len(rank_rows):
        raise ValueError("A326 fusion requires exactly eight source orders and weights")

    def metrics(cell: int) -> dict[str, Any]:
        ranks = [row[cell] for row in rank_rows]
        ordered = sorted(ranks)
        rank_sum = sum(ranks)
        fixed_rrf = sum(RRF_NUMERATOR // (RRF_K + rank) for rank in ranks)
        weighted_rank_sum = sum(
            weight * rank for weight, rank in zip(weights, ranks, strict=True)
        )
        weighted_fixed_rrf = sum(
            weight * (RRF_NUMERATOR // (RRF_K + rank))
            for weight, rank in zip(weights, ranks, strict=True)
        )
        return {
            "ordered": ordered,
            "rank_sum": rank_sum,
            "fixed_rrf": fixed_rrf,
            "weighted_rank_sum": weighted_rank_sum,
            "weighted_fixed_rrf": weighted_fixed_rrf,
        }

    rows = [(cell, metrics(cell)) for cell in range(CELLS)]
    if fusion_name == "min_rank_wavefront":
        rows.sort(key=lambda row: (row[1]["ordered"], row[1]["rank_sum"], row[0]))
    elif fusion_name == "top2_rank_sum":
        rows.sort(
            key=lambda row: (
                sum(row[1]["ordered"][:2]),
                row[1]["ordered"][0],
                row[1]["rank_sum"],
                row[0],
            )
        )
    elif fusion_name == "borda_rank_sum":
        rows.sort(
            key=lambda row: (row[1]["rank_sum"], row[1]["ordered"][0], row[0])
        )
    elif fusion_name == "fixed_point_rrf_k60":
        rows.sort(key=lambda row: (-row[1]["fixed_rrf"], row[1]["rank_sum"], row[0]))
    elif fusion_name == "stability_weighted_borda":
        rows.sort(
            key=lambda row: (
                row[1]["weighted_rank_sum"],
                row[1]["rank_sum"],
                row[0],
            )
        )
    else:
        rows.sort(
            key=lambda row: (
                -row[1]["weighted_fixed_rrf"],
                row[1]["rank_sum"],
                row[0],
            )
        )
    return _exact_order([cell for cell, _metrics in rows], fusion_name)


def build_fusions() -> dict[str, Any]:
    design = load_design()
    pairs = A321.candidate_pairs()
    a323 = json.loads(A323_RESULT.read_bytes())
    if (
        file_sha256(A323_RESULT) != A323_RESULT_SHA256
        or a323.get("attempt_id") != "A323"
        or a323.get("analysis", {}).get("operator_sequence") != list(A321.CANDIDATE_NAMES)
        or a323.get("analysis", {}).get("target_labels_used") != 0
        or a323.get("analysis", {}).get("candidate_execution") is not False
    ):
        raise RuntimeError("A326 A323 source differs")
    weights_by_name = stability_weights(pairs, a323)
    weights = [weights_by_name[row["name"]] for row in pairs]
    fused: dict[str, Any] = {}
    for name in FUSION_NAMES:
        w44 = fusion_order(
            [row["W44_order"] for row in pairs], fusion_name=name, weights=weights
        )
        w45 = fusion_order(
            [row["W45_order"] for row in pairs], fusion_name=name, weights=weights
        )
        fused[name] = {
            "W44_order": w44,
            "W45_order": w45,
            "W44_order_uint16be_sha256": _order_sha(w44),
            "W45_order_uint16be_sha256": _order_sha(w45),
            "cross_width_spearman": spearman(w44, w45),
        }

    source_ranks = {
        row["name"]: rank_vector(row["W44_order"]) for row in pairs
    }
    wavefront_ranks = rank_vector(fused["min_rank_wavefront"]["W44_order"])
    maximum_ratio = 0.0
    maximum_cell = 0
    violations = 0
    for cell in range(CELLS):
        best = min(source_ranks[name][cell] for name in A321.CANDIDATE_NAMES)
        ratio = wavefront_ranks[cell] / best
        if ratio > maximum_ratio:
            maximum_ratio = ratio
            maximum_cell = cell
        if wavefront_ranks[cell] > len(A321.CANDIDATE_NAMES) * best:
            violations += 1
    return {
        "design": design,
        "pairs": pairs,
        "weights_by_operator": weights_by_name,
        "fused": fused,
        "wavefront_guarantee": {
            "statement": "rank_wavefront(cell) <= 8 * min_source_rank(cell)",
            "checked_cells": CELLS,
            "violations": violations,
            "maximum_observed_ratio": maximum_ratio,
            "maximum_observed_ratio_cell": maximum_cell,
        },
    }


def select_on_a313(fused: Mapping[str, Mapping[str, Any]]) -> dict[str, Any]:
    if file_sha256(A313_RESULT) != A313_RESULT_SHA256:
        raise RuntimeError("A326 A313 result hash differs")
    a313 = json.loads(A313_RESULT.read_bytes())
    if (
        a313.get("attempt_id") != "A313"
        or a313.get("confirmation", {}).get("all_blocks_match") is not True
        or a313.get("discovery", {}).get("prefix12")
        != a313.get("rank_analysis", {}).get("prefix12")
    ):
        raise RuntimeError("A326 A313 confirmation differs")
    prefix = int(a313["discovery"]["prefix12"])
    ranks = [fused[name]["W44_order"].index(prefix) + 1 for name in FUSION_NAMES]
    selected_index = min(range(len(FUSION_NAMES)), key=lambda index: (ranks[index], index))
    selected_name = FUSION_NAMES[selected_index]
    selected = fused[selected_name]
    return {
        "calibration_prefix12": prefix,
        "calibration_prefix12_hex": f"{prefix:03x}",
        "candidate_ranks_one_based": {
            name: ranks[index] for index, name in enumerate(FUSION_NAMES)
        },
        "selected_fusion_index": selected_index,
        "selected_fusion": selected_name,
        "selected_calibration_rank_one_based": ranks[selected_index],
        "selected_W44_order_uint16be_sha256": selected["W44_order_uint16be_sha256"],
        "selected_W45_order_uint16be_sha256": selected["W45_order_uint16be_sha256"],
        "selected_W45_order": selected["W45_order"],
        "selection_rule": "minimum_A313_rank_then_frozen_fusion_index",
    }


def build_causal(payload: Mapping[str, Any]) -> dict[str, Any]:
    sys.path.insert(0, str(DOTCAUSAL_SRC))
    from dotcausal.io import CausalReader, CausalWriter

    terminal = "A326:frozen_diversity_fused_W45_execution_order"
    writer = CausalWriter(api_id="a326fuse")
    writer._rules = []
    writer.add_rule(
        name="operator_complementarity_to_executable_fusion_family",
        description="The eight exact A323 rank fields are fused by six predeclared duplicate-free deterministic schedules.",
        pattern=["A323_complete_operator_complementarity_map", "six_frozen_fusion_rules"],
        conclusion="A326_six_exact_W44_W45_fusion_pairs",
        confidence_modifier=1.0,
    )
    writer.add_rule(
        name="independent_W44_calibration_to_fusion_selection",
        description="The independently confirmed A313 prefix selects the earliest of the six predeclared W44 fusion orders with a frozen-index tie-break.",
        pattern=["A313_independently_confirmed_W44_prefix", "A326_six_predeclared_W44_fusions"],
        conclusion="A326_selected_fusion_identity",
        confidence_modifier=1.0,
    )
    writer.add_rule(
        name="selected_fusion_to_unchanged_W45_order",
        description="The exact paired W45 fusion order is copied without A322 or A325 labels, refits, progress or manual override.",
        pattern=["A326_selected_fusion_identity", "paired_target_blind_W45_fusion_order"],
        conclusion=terminal.replace(":", "_"),
        confidence_modifier=1.0,
    )
    writer.add_triplet(
        trigger="A323:target_blind_cross_width_operator_stability_map",
        mechanism="six_predeclared_duplicate_free_rank_fusion_rules",
        outcome="A326:six_exact_executable_W44_W45_fusion_pairs",
        confidence=1.0,
        source=payload["measurement_sha256"],
        quantification=json.dumps(
            {
                "fusion_names": list(FUSION_NAMES),
                "weights_by_operator": payload["weights_by_operator"],
                "wavefront_guarantee": payload["wavefront_guarantee"],
            },
            sort_keys=True,
        ),
        evidence="TARGET_BLIND_COMPLEMENTARITY_CONVERTED_TO_EXECUTABLE_EXACT_ORDERS",
        domain="AI-native executable operator fusion",
        quality_score=1.0,
    )
    writer.add_triplet(
        trigger="A313:independently_confirmed_W44_prefix",
        mechanism="minimum_rank_across_six_predeclared_fusions_with_frozen_tie_break",
        outcome="A326:selected_fusion_identity",
        confidence=1.0,
        source=A313_RESULT_SHA256,
        quantification=json.dumps(payload["selection"], sort_keys=True),
        evidence=json.dumps(payload["information_boundary"], sort_keys=True),
        domain="independent W44 calibration of executable fusion",
        quality_score=1.0,
    )
    writer.add_triplet(
        trigger="A326:selected_fusion_identity",
        mechanism="exact_paired_W45_order_copy_without_A322_or_A325_outcome",
        outcome=terminal,
        confidence=1.0,
        source=payload["order_commitment_sha256"],
        quantification=json.dumps(
            {
                "selected_fusion": payload["selection"]["selected_fusion"],
                "selected_W45_order_uint16be_sha256": payload["selection"][
                    "selected_W45_order_uint16be_sha256"
                ],
                "prefix_cells": CELLS,
            },
            sort_keys=True,
        ),
        evidence=payload["evidence_stage"],
        domain="prospective fused ChaCha20 prefix-order deployment",
        quality_score=1.0,
    )
    writer.add_triplet(
        trigger="A313:independently_confirmed_W44_prefix",
        mechanism="materialized_fusion_selection_and_cross_width_deployment_chain",
        outcome=terminal,
        confidence=1.0,
        source="materialized:A326_fusion_selection_chain",
        quantification="exact retained closure",
        evidence=payload["evidence_stage"],
        domain="AI-native retained inference",
        quality_score=1.0,
        is_inferred=True,
    )
    writer.add_cluster(
        name="A326 executable diversity-fused deployment order",
        entities=[
            "A323:target_blind_cross_width_operator_stability_map",
            "A326:six_exact_executable_W44_W45_fusion_pairs",
            "A326:selected_fusion_identity",
            terminal,
        ],
    )
    writer.add_gap(
        subject=terminal,
        predicate="next_required_object",
        expected_object_type="fresh_W46_rank_or_execution_comparison_without_duplicate_candidate_search",
        confidence=1.0,
        suggested_queries=[
            "After independent W46 confirmation, does the frozen A326 fusion rank the target earlier than the already frozen A325 single-operator order?"
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
        reader.api_id != "a326fuse"
        or len(explicit) != 3
        or len(all_rows) != 4
        or len(inferred) != 1
        or len(reader._rules) != 3
        or len(reader._clusters) != 1
        or len(reader._gaps) != 1
    ):
        raise RuntimeError("A326 authentic Causal reopen gate failed")
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


def materialize() -> dict[str, Any]:
    if any(path.exists() for path in (ORDER, CAUSAL, REPORT)):
        raise FileExistsError("A326 artifacts already exist")
    if A322_RESULT.exists():
        raise RuntimeError("A326 must freeze before any A322 result exists")
    if A325_PROGRESS.exists() or A325_RESULT.exists():
        raise RuntimeError("A326 must freeze before any A325 execution or result exists")
    built = build_fusions()
    selection = select_on_a313(built["fused"])
    pairwise_w44_spearman: dict[str, float] = {}
    for left_index, left in enumerate(FUSION_NAMES):
        for right in FUSION_NAMES[left_index + 1 :]:
            pairwise_w44_spearman[f"{left}__vs__{right}"] = spearman(
                built["fused"][left]["W44_order"],
                built["fused"][right]["W44_order"],
            )
    payload: dict[str, Any] = {
        "schema": "chacha20-round20-diversity-fused-operator-a326-order-v1",
        "attempt_id": ATTEMPT_ID,
        "evidence_stage": "INDEPENDENT_W44_SELECTED_EXECUTABLE_DIVERSITY_FUSED_W45_ORDER_RETAINED",
        "design_sha256": DESIGN_SHA256,
        "source_operator_sequence": list(A321.CANDIDATE_NAMES),
        "source_order_hashes": {
            row["name"]: {
                "W44_order_uint16be_sha256": row["W44_order_uint16be_sha256"],
                "W45_order_uint16be_sha256": row["W45_order_uint16be_sha256"],
            }
            for row in built["pairs"]
        },
        "weights_by_operator": built["weights_by_operator"],
        "fusion_orders": built["fused"],
        "selection": selection,
        "wavefront_guarantee": built["wavefront_guarantee"],
        "operator_diversity_audit": {
            "pairwise_W44_spearman": pairwise_w44_spearman,
            "minimum_pairwise_W44_spearman": min(pairwise_w44_spearman.values()),
            "maximum_pairwise_W44_spearman": max(pairwise_w44_spearman.values()),
        },
        "information_boundary": built["design"]["information_boundary"],
        "anchors": {
            "design": anchor(DESIGN, DESIGN_SHA256),
            "A313_result": anchor(A313_RESULT, A313_RESULT_SHA256),
            "A323_result": anchor(A323_RESULT, A323_RESULT_SHA256),
            "A321_runner": anchor(A321_RUNNER),
            "runner": anchor(Path(__file__)),
            "test": anchor(A326_TEST),
            "reproducer": anchor(A326_REPRO),
        },
    }
    payload["order_commitment_sha256"] = canonical_sha256(
        {
            "source_order_hashes": payload["source_order_hashes"],
            "weights_by_operator": payload["weights_by_operator"],
            "fusion_order_hashes": {
                name: {
                    "W44": payload["fusion_orders"][name][
                        "W44_order_uint16be_sha256"
                    ],
                    "W45": payload["fusion_orders"][name][
                        "W45_order_uint16be_sha256"
                    ],
                }
                for name in FUSION_NAMES
            },
            "selection": {
                key: value
                for key, value in selection.items()
                if key != "selected_W45_order"
            },
            "information_boundary": payload["information_boundary"],
        }
    )
    payload["measurement_sha256"] = canonical_sha256(
        {
            "order_commitment_sha256": payload["order_commitment_sha256"],
            "wavefront_guarantee": payload["wavefront_guarantee"],
            "operator_diversity_audit": payload["operator_diversity_audit"],
        }
    )
    payload["causal"] = build_causal(payload)
    atomic_json(ORDER, payload)
    atomic_bytes(
        REPORT,
        (
            "# A326 — executable diversity-fused ChaCha20 prefix order\n\n"
            f"- Selected fusion: **{selection['selected_fusion']}**\n"
            f"- Independent A313 calibration rank: **{selection['selected_calibration_rank_one_based']} / 4,096**\n"
            f"- Selected W45 order SHA: **{selection['selected_W45_order_uint16be_sha256']}**\n"
            f"- Exact fused W44/W45 order pairs: **{len(FUSION_NAMES)}**\n"
            "- A322/A325 labels, refits and candidate executions used: **zero**\n"
            f"- Wavefront factor-eight guarantee violations: **{built['wavefront_guarantee']['violations']}**\n"
            "- Authentic AI-native Causal readback: **3 explicit + 1 inferred chain**\n"
        ).encode(),
    )
    return payload


def analyze() -> dict[str, Any]:
    response: dict[str, Any] = {
        "attempt_id": ATTEMPT_ID,
        "design_sha256": DESIGN_SHA256,
        "A322_result_exists": A322_RESULT.exists(),
        "A325_progress_exists": A325_PROGRESS.exists(),
        "A325_result_exists": A325_RESULT.exists(),
        "order_exists": ORDER.exists(),
    }
    if ORDER.exists():
        payload = json.loads(ORDER.read_bytes())
        response.update(
            {
                "order_sha256": file_sha256(ORDER),
                "evidence_stage": payload["evidence_stage"],
                "selected_fusion": payload["selection"]["selected_fusion"],
                "selected_calibration_rank_one_based": payload["selection"][
                    "selected_calibration_rank_one_based"
                ],
                "selected_W45_order_uint16be_sha256": payload["selection"][
                    "selected_W45_order_uint16be_sha256"
                ],
            }
        )
    return response


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    action = parser.add_mutually_exclusive_group(required=True)
    action.add_argument("--analyze", action="store_true")
    action.add_argument("--materialize", action="store_true")
    args = parser.parse_args()
    payload = analyze() if args.analyze else materialize()
    print(json.dumps(payload, indent=2, sort_keys=True), flush=True)


if __name__ == "__main__":
    main()

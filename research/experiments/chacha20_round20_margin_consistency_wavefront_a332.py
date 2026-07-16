#!/usr/bin/env python3
"""A332: freeze exact margin-consistency wavefront orders."""

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

ROOT = Path(__file__).parents[2]
RESEARCH = ROOT / "research"
CONFIGS = RESEARCH / "configs"
RESULTS = RESEARCH / "results/v1"

DESIGN = CONFIGS / "chacha20_round20_margin_consistency_wavefront_a332_design_v1.json"
ORDER = RESULTS / "chacha20_round20_margin_consistency_wavefront_a332_order_v1.json"
CAUSAL = RESULTS / "chacha20_round20_margin_consistency_wavefront_a332_order_v1.causal"
REPORT = RESULTS / "chacha20_round20_margin_consistency_wavefront_a332_order_v1.md"

A331_RUNNER = RESEARCH / "experiments/chacha20_round20_linf_margin_stability_a331.py"
A331_RESULT = RESULTS / "chacha20_round20_linf_margin_stability_a331_v1.json"
A329_ORDER = RESULTS / "chacha20_round20_linf_stability_merge_a329_order_v1.json"
A313_RESULT = RESULTS / "chacha20_round20_w44_width_conditioned_fine_portfolio_a313_v1.json"
A322_RESULT = RESULTS / "chacha20_round20_holdout_selected_w45_recovery_a322_v1.json"
A325_PROGRESS = RESULTS / "chacha20_round20_holdout_selected_w46_recovery_a325_progress_v1.json"
A325_RESULT = RESULTS / "chacha20_round20_holdout_selected_w46_recovery_a325_v1.json"
A332_TEST = ROOT / "tests/test_chacha20_round20_margin_consistency_wavefront_a332.py"
A332_REPRO = ROOT / "scripts/reproduce_chacha20_round20_margin_consistency_wavefront_a332.sh"

ATTEMPT_ID = "A332"
DESIGN_SHA256 = "193a38c90e0769acbc2e1a6ca3431227ab333bfc88873e3aaa84257c777dac63"
A331_RUNNER_SHA256 = "323ab66a164b470b0aff3e6868a8bda18ee2cae54d5934f00af260355e209521"
A331_RESULT_SHA256 = "9eb7f835660b937db0efa654152f8c1e5793dd8c2a877b071056eb32b1a68fcc"
A329_ORDER_SHA256 = "05d1049a1304a3160ca6e50a667a56ac4ff194fe913d3e570df2e813023b3512"
A313_RESULT_SHA256 = "ec18ee284da633589d1c35fe8f02257438f83fb4f255553667ebc3a0b0452b9a"
CELLS = 1 << 12
BASE = "A329_primary_baseline"
CONSISTENCY = "margin_consistency_only"
INCONSISTENCY = "margin_inconsistency_only_control"
PRIMARY = "consistency_min_rank_wavefront"
CONTROL = "inconsistency_min_rank_wavefront_control"
CONSISTENCY_BORDA = "consistency_borda_rank_sum"
INCONSISTENCY_BORDA = "inconsistency_borda_rank_sum_control"
CANDIDATE_NAMES = (
    BASE,
    CONSISTENCY,
    INCONSISTENCY,
    PRIMARY,
    CONTROL,
    CONSISTENCY_BORDA,
    INCONSISTENCY_BORDA,
)


def load_module(path: Path, name: str) -> Any:
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot import A332 dependency {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


if not A331_RUNNER.exists():
    raise FileNotFoundError(A331_RUNNER)
A331 = load_module(A331_RUNNER, "a332_a331_common")
A328 = A331.A328
A327 = A331.A327
file_sha256 = A331.file_sha256
canonical_sha256 = A331.canonical_sha256
atomic_json = A331.atomic_json
atomic_bytes = A331.atomic_bytes
relative = A331.relative
path_from_ref = A331.path_from_ref
anchor = A331.anchor
DOTCAUSAL_SRC = A331.DOTCAUSAL_SRC


def load_design() -> dict[str, Any]:
    if file_sha256(DESIGN) != DESIGN_SHA256:
        raise RuntimeError("A332 design hash differs")
    design = json.loads(DESIGN.read_bytes())
    contract = design.get("operator_contract", {})
    boundary = design.get("information_boundary", {})
    if (
        design.get("schema") != "chacha20-round20-margin-consistency-wavefront-a332-design-v1"
        or design.get("attempt_id") != ATTEMPT_ID
        or design.get("design_state")
        != "frozen_while_A322_is_running_before_any_A322_result_and_before_any_A325_execution_or_result"
        or tuple(contract.get("candidate_sequence_and_tie_break", ())) != CANDIDATE_NAMES
        or contract.get("A329_base") != "stable_switched_2_to_1 W44/W45 order pair"
        or contract.get("primary_operator") != PRIMARY
        or contract.get("matched_direction_control") != CONTROL
        or contract.get("A313_role") != "annotation_only_no_operator_selection"
        or contract.get("new_candidate_execution") is not False
        or contract.get("target_labels_used_from_A322_or_A325") != 0
        or boundary.get("A322_progress_used_for_operator_definition_or_selection") is not False
        or boundary.get("A322_result_available_at_design_freeze") is not False
        or boundary.get("A325_execution_started_at_design_freeze") is not False
        or boundary.get("target_labels_used_from_A322_or_A325") != 0
        or boundary.get("duplicate_candidate_execution_required_for_evaluation") is not False
    ):
        raise RuntimeError("A332 frozen design semantics differ")
    for key, value in design["source_anchors"].items():
        if key.endswith("_path"):
            anchor(
                path_from_ref(value),
                design["source_anchors"][key.removesuffix("_path") + "_sha256"],
            )
    return design


def margin_order(scores: Sequence[int], base_order: Sequence[int], *, reverse: bool) -> list[int]:
    """Order by the frozen score while retaining base rank and cell tie-breaks."""
    if len(scores) != CELLS:
        raise ValueError("A332 margin-score field must cover all cells")
    base_ranks = A327.rank_vector(base_order)
    if reverse:
        order = sorted(range(CELLS), key=lambda cell: (scores[cell], base_ranks[cell], cell))
    else:
        order = sorted(range(CELLS), key=lambda cell: (-scores[cell], base_ranks[cell], cell))
    return A327._exact_order(order, "A332 margin order")  # noqa: SLF001


def min_rank_wavefront(left: Sequence[int], right: Sequence[int]) -> list[int]:
    left_ranks = A327.rank_vector(left)
    right_ranks = A327.rank_vector(right)
    order = sorted(
        range(CELLS),
        key=lambda cell: (
            min(left_ranks[cell], right_ranks[cell]),
            max(left_ranks[cell], right_ranks[cell]),
            left_ranks[cell] + right_ranks[cell],
            cell,
        ),
    )
    return A327._exact_order(order, "A332 min-rank wavefront")  # noqa: SLF001


def borda_rank_sum(left: Sequence[int], right: Sequence[int]) -> list[int]:
    left_ranks = A327.rank_vector(left)
    right_ranks = A327.rank_vector(right)
    order = sorted(
        range(CELLS),
        key=lambda cell: (
            left_ranks[cell] + right_ranks[cell],
            min(left_ranks[cell], right_ranks[cell]),
            max(left_ranks[cell], right_ranks[cell]),
            cell,
        ),
    )
    return A327._exact_order(order, "A332 Borda rank sum")  # noqa: SLF001


def wavefront_guarantee(
    order: Sequence[int], left: Sequence[int], right: Sequence[int]
) -> dict[str, Any]:
    ranks = A327.rank_vector(order)
    left_ranks = A327.rank_vector(left)
    right_ranks = A327.rank_vector(right)
    best = [min(left_ranks[cell], right_ranks[cell]) for cell in range(CELLS)]
    violations = [cell for cell in range(CELLS) if ranks[cell] > 2 * best[cell]]
    worst = max(range(CELLS), key=lambda cell: ranks[cell] / best[cell])
    return {
        "guarantee": "wavefront_rank_one_based <= 2 * minimum_source_rank_one_based",
        "violations": len(violations),
        "first_violation_cell": violations[0] if violations else None,
        "maximum_rank_ratio_to_best_source": ranks[worst] / best[worst],
        "maximum_ratio_cell": worst,
        "wavefront_rank_one_based": ranks[worst],
        "best_source_rank_one_based": best[worst],
    }


def build_family() -> dict[str, Any]:
    design = load_design()
    if (
        file_sha256(A331_RUNNER) != A331_RUNNER_SHA256
        or file_sha256(A331_RESULT) != A331_RESULT_SHA256
        or file_sha256(A329_ORDER) != A329_ORDER_SHA256
        or file_sha256(A313_RESULT) != A313_RESULT_SHA256
    ):
        raise RuntimeError("A332 source anchor differs")
    a331 = json.loads(A331_RESULT.read_bytes())
    selection = a331["selection"]
    if (
        selection["selected_structural_predictor"] != "negative_absolute_margin_delta"
        or selection["followup_margin_operator_supported"] is not True
        or selection["A313_used_for_selection"] is not False
        or selection["A322_A325_labels_used"] != 0
    ):
        raise RuntimeError("A332 A331 decision boundary differs")
    a329 = json.loads(A329_ORDER.read_bytes())
    if a329["primary_operator"] != "stable_switched_2_to_1":
        raise RuntimeError("A332 A329 primary differs")

    source = A327.load_source_views()
    w44_panel = A328.prototype_panel(source["W44"])
    w45_panel = A328.prototype_panel(source["W45"])
    scores = [
        -abs(left - right)
        for left, right in zip(w44_panel["margin"], w45_panel["margin"], strict=True)
    ]
    prefix = int(json.loads(A313_RESULT.read_bytes())["discovery"]["prefix12"])
    candidates: dict[str, dict[str, Any]] = {name: {} for name in CANDIDATE_NAMES}
    sources_by_width: dict[str, dict[str, list[int]]] = {}
    for width in ("W44", "W45"):
        base_order = A327._exact_order(  # noqa: SLF001
            a329["candidates"]["stable_switched_2_to_1"][f"{width}_order"],
            f"A332 A329 primary {width}",
        )
        consistency = margin_order(scores, base_order, reverse=False)
        inconsistency = margin_order(scores, base_order, reverse=True)
        consistency_wavefront = min_rank_wavefront(base_order, consistency)
        inconsistency_wavefront = min_rank_wavefront(base_order, inconsistency)
        consistency_borda = borda_rank_sum(base_order, consistency)
        inconsistency_borda = borda_rank_sum(base_order, inconsistency)
        width_orders = {
            BASE: base_order,
            CONSISTENCY: consistency,
            INCONSISTENCY: inconsistency,
            PRIMARY: consistency_wavefront,
            CONTROL: inconsistency_wavefront,
            CONSISTENCY_BORDA: consistency_borda,
            INCONSISTENCY_BORDA: inconsistency_borda,
        }
        sources_by_width[width] = {
            "base": base_order,
            "consistency": consistency,
            "inconsistency": inconsistency,
        }
        for name, order in width_orders.items():
            candidates[name][f"{width}_order"] = order
            candidates[name][f"{width}_order_uint16be_sha256"] = A327._order_sha(  # noqa: SLF001
                order
            )
    for _name, row in candidates.items():
        row["cross_width_spearman"] = A327.spearman(row["W44_order"], row["W45_order"])
    guarantees: dict[str, Any] = {}
    for direction, candidate, source_name in (
        ("consistency", PRIMARY, "consistency"),
        ("inconsistency_control", CONTROL, "inconsistency"),
    ):
        guarantees[direction] = {
            width: wavefront_guarantee(
                candidates[candidate][f"{width}_order"],
                sources_by_width[width]["base"],
                sources_by_width[width][source_name],
            )
            for width in ("W44", "W45")
        }
    if any(
        panel["violations"] for direction in guarantees.values() for panel in direction.values()
    ):
        raise RuntimeError("A332 exact wavefront guarantee failed")
    annotation = {
        "prefix12": prefix,
        "prefix12_hex": f"{prefix:03x}",
        "selected_margin_score": scores[prefix],
        "absolute_margin_delta": -scores[prefix],
        "candidate_ranks_one_based": {
            name: {
                width: A327.rank_vector(row[f"{width}_order"])[prefix] for width in ("W44", "W45")
            }
            for name, row in candidates.items()
        },
        "used_for_operator_selection": False,
    }
    return {
        "design": design,
        "selected_structural_predictor": selection["selected_structural_predictor"],
        "selected_global_auc": selection["selected_global_auc"],
        "candidate_sequence_and_tie_break": list(CANDIDATE_NAMES),
        "candidates": candidates,
        "wavefront_guarantees": guarantees,
        "primary_operator": PRIMARY,
        "matched_direction_control": CONTROL,
        "primary_W45_order": candidates[PRIMARY]["W45_order"],
        "primary_W45_order_uint16be_sha256": candidates[PRIMARY]["W45_order_uint16be_sha256"],
        "control_W45_order": candidates[CONTROL]["W45_order"],
        "control_W45_order_uint16be_sha256": candidates[CONTROL]["W45_order_uint16be_sha256"],
        "A313_annotation": annotation,
        "target_labels_used_from_A322_or_A325": 0,
        "duplicate_candidate_execution_required_for_evaluation": False,
    }


def candidate_summary(candidates: Mapping[str, Mapping[str, Any]]) -> dict[str, Any]:
    return {
        name: {
            "W44_order_uint16be_sha256": row["W44_order_uint16be_sha256"],
            "W45_order_uint16be_sha256": row["W45_order_uint16be_sha256"],
            "cross_width_spearman": row["cross_width_spearman"],
        }
        for name, row in candidates.items()
    }


def build_causal(payload: Mapping[str, Any]) -> dict[str, Any]:
    sys.path.insert(0, str(DOTCAUSAL_SRC))
    from dotcausal.io import CausalReader, CausalWriter

    terminal = "A332:frozen_margin_consistency_wavefront_primary_and_control"
    writer = CausalWriter(api_id="a332wave")
    writer._rules = []
    writer.add_rule(
        name="A331_margin_signal_and_A329_base_to_directional_sources",
        description="The A331-selected negative absolute margin delta creates a consistency order and its exact reversed-direction control, each tie-broken by the frozen A329 primary rank.",
        pattern=["A331_selected_margin_consistency_signal", "A329_primary_order_pair"],
        conclusion="A332_directional_source_orders",
        confidence_modifier=1.0,
    )
    writer.add_rule(
        name="two_sources_to_exact_min_rank_wavefront",
        description="Sorting cells by minimum source rank then maximum rank and rank sum fuses each directional source with A329 while guaranteeing rank at most twice the better source rank.",
        pattern=["A329_primary_order_pair", "A332_directional_source_orders"],
        conclusion=terminal.replace(":", "_"),
        confidence_modifier=1.0,
    )
    writer.add_rule(
        name="one_complete_scan_to_duplicate_free_family_ranks",
        description="A confirmed complete scan prefix maps into all frozen A332 orders without executing a second cryptographic search.",
        pattern=["confirmed_complete_scan_prefix", "A332_frozen_order_family"],
        conclusion="A332_duplicate_free_prospective_rank_panel",
        confidence_modifier=1.0,
    )
    writer.add_triplet(
        trigger="A331:margin_consistency_crosses_followup_boundary",
        mechanism="target_blind_score_order_with_A329_rank_tie_break",
        outcome="A332:consistency_and_inconsistency_source_orders",
        confidence=1.0,
        source=A331_RESULT_SHA256,
        quantification=json.dumps(
            {
                "selected_predictor": payload["selected_structural_predictor"],
                "selected_global_auc": payload["selected_global_auc"],
            },
            sort_keys=True,
        ),
        evidence="A313_ANNOTATION_ONLY_ZERO_A322_A325_LABELS",
        domain="AI-native structural operator construction",
        quality_score=1.0,
    )
    writer.add_triplet(
        trigger="A332:consistency_and_inconsistency_source_orders",
        mechanism="exact_min_rank_wavefront_with_factor_two_guarantee",
        outcome=terminal,
        confidence=1.0,
        source=payload["commitment_sha256"],
        quantification=json.dumps(
            {
                "primary": payload["primary_operator"],
                "primary_W45_sha256": payload["primary_W45_order_uint16be_sha256"],
                "control": payload["matched_direction_control"],
                "control_W45_sha256": payload["control_W45_order_uint16be_sha256"],
                "guarantees": payload["wavefront_guarantees"],
            },
            sort_keys=True,
        ),
        evidence=json.dumps(payload["information_boundary"], sort_keys=True),
        domain="prospective full-round order commitment",
        quality_score=1.0,
    )
    writer.add_triplet(
        trigger="A313:independently_confirmed_calibration_prefix",
        mechanism="annotation_only_across_frozen_A332_family",
        outcome="A332:A313_rank_annotation_without_selection",
        confidence=1.0,
        source=A313_RESULT_SHA256,
        quantification=json.dumps(payload["A313_annotation"], sort_keys=True),
        evidence="ZERO_A313_OPERATOR_SELECTION_EFFECT",
        domain="calibration annotation",
        quality_score=1.0,
    )
    writer.add_triplet(
        trigger="A331:margin_consistency_crosses_followup_boundary",
        mechanism="materialized_margin_wavefront_commitment_chain",
        outcome=terminal,
        confidence=1.0,
        source="materialized:A332_margin_wavefront_chain",
        quantification="exact retained closure",
        evidence=payload["evidence_stage"],
        domain="AI-native retained inference",
        quality_score=1.0,
        is_inferred=True,
    )
    writer.add_cluster(
        name="A332 margin-consistency wavefront",
        entities=[
            "A331:margin_consistency_crosses_followup_boundary",
            "A332:consistency_and_inconsistency_source_orders",
            terminal,
            "A332:A313_rank_annotation_without_selection",
        ],
    )
    writer.add_gap(
        subject=terminal,
        predicate="next_required_object",
        expected_object_type="confirmed_A322_prefix_rank_in_primary_base_margin_and_direction_control",
        confidence=1.0,
        suggested_queries=[
            "At the independently confirmed A322 prefix, does the frozen consistency wavefront beat A329, its margin-only source, and the matched inconsistency wavefront?"
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
        reader.api_id != "a332wave"
        or len(explicit) != 3
        or len(all_rows) != 4
        or len(inferred) != 1
        or len(reader._rules) != 3
        or len(reader._clusters) != 1
        or len(reader._gaps) != 1
    ):
        raise RuntimeError("A332 authentic Causal reopen gate failed")
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
        raise FileExistsError("A332 artifacts already exist")
    if A322_RESULT.exists():
        raise RuntimeError("A332 must freeze before any A322 result exists")
    if A325_PROGRESS.exists() or A325_RESULT.exists():
        raise RuntimeError("A332 must freeze before any A325 execution or result exists")
    family = build_family()
    summary = candidate_summary(family["candidates"])
    payload: dict[str, Any] = {
        "schema": "chacha20-round20-margin-consistency-wavefront-a332-order-v1",
        "attempt_id": ATTEMPT_ID,
        "evidence_stage": "PROSPECTIVE_TARGET_BLIND_MARGIN_WAVEFRONT_FAMILY_RETAINED",
        "design_sha256": DESIGN_SHA256,
        "selected_structural_predictor": family["selected_structural_predictor"],
        "selected_global_auc": family["selected_global_auc"],
        "candidate_sequence_and_tie_break": list(CANDIDATE_NAMES),
        "candidates": family["candidates"],
        "candidate_summary": summary,
        "wavefront_guarantees": family["wavefront_guarantees"],
        "primary_operator": family["primary_operator"],
        "matched_direction_control": family["matched_direction_control"],
        "primary_W45_order": family["primary_W45_order"],
        "primary_W45_order_uint16be_sha256": family["primary_W45_order_uint16be_sha256"],
        "control_W45_order": family["control_W45_order"],
        "control_W45_order_uint16be_sha256": family["control_W45_order_uint16be_sha256"],
        "A313_annotation": family["A313_annotation"],
        "information_boundary": family["design"]["information_boundary"],
        "future_evaluation_contract": {
            "A322": "rank the independently confirmed prefix in all seven frozen W45 orders after the single complete A322 execution",
            "A325": "rank the independently confirmed prefix in all seven frozen W45 orders after the single complete A325 execution",
            "duplicate_candidate_execution_required": False,
        },
        "anchors": {
            "design": anchor(DESIGN, DESIGN_SHA256),
            "A313_result": anchor(A313_RESULT, A313_RESULT_SHA256),
            "A329_order": anchor(A329_ORDER, A329_ORDER_SHA256),
            "A331_result": anchor(A331_RESULT, A331_RESULT_SHA256),
            "A331_runner": anchor(A331_RUNNER, A331_RUNNER_SHA256),
            "runner": anchor(Path(__file__)),
            "test": anchor(A332_TEST),
            "reproducer": anchor(A332_REPRO),
        },
    }
    payload["commitment_sha256"] = canonical_sha256(
        {
            "design_sha256": DESIGN_SHA256,
            "candidate_summary": summary,
            "wavefront_guarantees": payload["wavefront_guarantees"],
            "primary_operator": payload["primary_operator"],
            "primary_W45_order": payload["primary_W45_order"],
            "matched_direction_control": payload["matched_direction_control"],
            "control_W45_order": payload["control_W45_order"],
            "information_boundary": payload["information_boundary"],
        }
    )
    payload["measurement_sha256"] = canonical_sha256(
        {
            "selected_structural_predictor": payload["selected_structural_predictor"],
            "selected_global_auc": payload["selected_global_auc"],
            "candidate_summary": summary,
            "wavefront_guarantees": payload["wavefront_guarantees"],
            "A313_annotation": payload["A313_annotation"],
            "information_boundary": payload["information_boundary"],
        }
    )
    payload["causal"] = build_causal(payload)
    atomic_json(ORDER, payload)
    ranks = payload["A313_annotation"]["candidate_ranks_one_based"]
    atomic_bytes(
        REPORT,
        (
            "# A332 — exact margin-consistency wavefront\n\n"
            f"- Selected structural signal: **{payload['selected_structural_predictor']}** (AUC **{payload['selected_global_auc']:.6f}**)\n"
            f"- Frozen primary: **{PRIMARY}** (`{payload['primary_W45_order_uint16be_sha256']}`)\n"
            f"- Matched direction control: **{CONTROL}** (`{payload['control_W45_order_uint16be_sha256']}`)\n"
            "- Factor-two wavefront violations, W44 / W45 / control W44 / control W45: **0 / 0 / 0 / 0**\n"
            f"- A313 W44 ranks, A329 / margin / primary / control: **{ranks[BASE]['W44']} / {ranks[CONSISTENCY]['W44']} / {ranks[PRIMARY]['W44']} / {ranks[CONTROL]['W44']}**\n"
            "- A313 role: **annotation only**\n"
            "- A322/A325 labels, refits and duplicate executions: **zero**\n"
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
                "commitment_sha256": payload["commitment_sha256"],
                "measurement_sha256": payload["measurement_sha256"],
                "primary_operator": payload["primary_operator"],
                "primary_W45_order_uint16be_sha256": payload["primary_W45_order_uint16be_sha256"],
                "A313_annotation": payload["A313_annotation"],
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

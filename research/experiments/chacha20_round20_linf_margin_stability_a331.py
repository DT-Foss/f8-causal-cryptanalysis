#!/usr/bin/env python3
"""A331: measure whether exact Linf prototype margin predicts region stability."""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import inspect
import json
import os
import sys
from collections import defaultdict
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

ROOT = Path(__file__).parents[2]
RESEARCH = ROOT / "research"
CONFIGS = RESEARCH / "configs"
RESULTS = RESEARCH / "results/v1"

DESIGN = CONFIGS / "chacha20_round20_linf_margin_stability_a331_design_v1.json"
RESULT = RESULTS / "chacha20_round20_linf_margin_stability_a331_v1.json"
CAUSAL = RESULTS / "chacha20_round20_linf_margin_stability_a331_v1.causal"
REPORT = RESULTS / "chacha20_round20_linf_margin_stability_a331_v1.md"

A328_RUNNER = RESEARCH / "experiments/chacha20_round20_linf_voronoi_transfer_a328.py"
A328_RESULT = RESULTS / "chacha20_round20_linf_voronoi_transfer_a328_v1.json"
A313_RESULT = RESULTS / "chacha20_round20_w44_width_conditioned_fine_portfolio_a313_v1.json"
A322_RESULT = RESULTS / "chacha20_round20_holdout_selected_w45_recovery_a322_v1.json"
A325_PROGRESS = RESULTS / "chacha20_round20_holdout_selected_w46_recovery_a325_progress_v1.json"
A325_RESULT = RESULTS / "chacha20_round20_holdout_selected_w46_recovery_a325_v1.json"
A331_TEST = ROOT / "tests/test_chacha20_round20_linf_margin_stability_a331.py"
A331_REPRO = ROOT / "scripts/reproduce_chacha20_round20_linf_margin_stability_a331.sh"

ATTEMPT_ID = "A331"
DESIGN_SHA256 = "7953e9e376bc34fee4fd7a97e2a61fae5b55ffb60dfa9400b4a9d2d066ef68ee"
A328_RUNNER_SHA256 = "d7daf79a6e491bbd60b8fc48fcd44eea17ecc6ab4f6b15e22b890b0e8a94ca02"
A328_RESULT_SHA256 = "93c507e6fa4faeaae30618a35d0a933139246cdf8a57f45fb3760982c796a1b4"
A313_RESULT_SHA256 = "ec18ee284da633589d1c35fe8f02257438f83fb4f255553667ebc3a0b0452b9a"
CELLS = 1 << 12
PROTOTYPES = 4
PREDICTOR_NAMES = (
    "W44_margin",
    "W45_margin",
    "minimum_margin",
    "maximum_margin",
    "sum_margin",
    "product_margin",
    "negative_absolute_margin_delta",
    "deterministic_cell_hash_null",
)
ELIGIBLE_PREDICTOR_NAMES = PREDICTOR_NAMES[:-1]
FOLLOWUP_AUC = 0.55
BINS = 5


def load_module(path: Path, name: str) -> Any:
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot import A331 dependency {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


if not A328_RUNNER.exists():
    raise FileNotFoundError(A328_RUNNER)
A328 = load_module(A328_RUNNER, "a331_a328_common")
A327 = A328.A327
file_sha256 = A328.file_sha256
canonical_sha256 = A328.canonical_sha256
atomic_json = A328.atomic_json
atomic_bytes = A328.atomic_bytes
relative = A328.relative
path_from_ref = A328.path_from_ref
anchor = A328.anchor
DOTCAUSAL_SRC = A328.DOTCAUSAL_SRC


def load_design() -> dict[str, Any]:
    if file_sha256(DESIGN) != DESIGN_SHA256:
        raise RuntimeError("A331 design hash differs")
    design = json.loads(DESIGN.read_bytes())
    contract = design.get("predictor_contract", {})
    boundary = design.get("information_boundary", {})
    if (
        design.get("schema")
        != "chacha20-round20-linf-margin-stability-a331-design-v1"
        or design.get("attempt_id") != ATTEMPT_ID
        or design.get("design_state")
        != "frozen_while_A322_is_running_before_any_A322_result_and_before_any_A325_execution_or_result"
        or tuple(design.get("predictor_sequence_and_tie_break", ())) != PREDICTOR_NAMES
        or contract.get("positive_label")
        != "same nearest-prototype index at W44 and W45"
        or contract.get("selection_rule")
        != "maximum exact global tie-aware AUC among the first seven non-null predictors then frozen predictor index"
        or contract.get("deterministic_cell_hash_null_eligible_for_selection") is not False
        or contract.get("minimum_AUC_for_followup_operator") != FOLLOWUP_AUC
        or contract.get("new_execution_order") is not False
        or contract.get("candidate_execution") is not False
        or contract.get("target_labels_used_from_A322_or_A325") != 0
        or boundary.get("A322_progress_used_for_predictor_definition_or_selection")
        is not False
        or boundary.get("A322_result_available_at_design_freeze") is not False
        or boundary.get("A325_execution_started_at_design_freeze") is not False
        or boundary.get("target_labels_used_from_A322_or_A325") != 0
    ):
        raise RuntimeError("A331 frozen design semantics differ")
    for key, value in design["source_anchors"].items():
        if key.endswith("_path"):
            anchor(
                path_from_ref(value),
                design["source_anchors"][key.removesuffix("_path") + "_sha256"],
            )
    return design


def hash_null_score(cell: int) -> int:
    digest = hashlib.sha256(f"A331:{cell}".encode()).digest()
    return int.from_bytes(digest[:8], "big")


def exact_auc(scores: Sequence[int], labels: Sequence[bool]) -> dict[str, Any]:
    if len(scores) != len(labels) or not scores:
        raise ValueError("A331 AUC inputs differ or are empty")
    grouped: dict[int, list[int]] = defaultdict(lambda: [0, 0])
    positives = 0
    negatives = 0
    for score, label in zip(scores, labels, strict=True):
        if label:
            grouped[int(score)][0] += 1
            positives += 1
        else:
            grouped[int(score)][1] += 1
            negatives += 1
    if positives == 0 or negatives == 0:
        return {
            "positive_cells": positives,
            "negative_cells": negatives,
            "twice_concordant_numerator": None,
            "twice_pair_denominator": None,
            "auc": None,
        }
    lower_negatives = 0
    numerator = 0
    for score in sorted(grouped):
        positive_count, negative_count = grouped[score]
        numerator += 2 * positive_count * lower_negatives
        numerator += positive_count * negative_count
        lower_negatives += negative_count
    denominator = 2 * positives * negatives
    return {
        "positive_cells": positives,
        "negative_cells": negatives,
        "twice_concordant_numerator": numerator,
        "twice_pair_denominator": denominator,
        "auc": numerator / denominator,
    }


def score_bins(scores: Sequence[int], labels: Sequence[bool]) -> list[dict[str, Any]]:
    ordered = sorted(range(len(scores)), key=lambda cell: (-scores[cell], cell))
    bins: list[dict[str, Any]] = []
    for index in range(BINS):
        start = index * len(ordered) // BINS
        end = (index + 1) * len(ordered) // BINS
        cells = ordered[start:end]
        stable = sum(labels[cell] for cell in cells)
        bins.append(
            {
                "bin": index + 1,
                "direction": "highest_score_first",
                "cells": len(cells),
                "stable_cells": stable,
                "stable_fraction": stable / len(cells),
                "maximum_score": scores[cells[0]],
                "minimum_score": scores[cells[-1]],
            }
        )
    return bins


def empirical_midrank_percentile(scores: Sequence[int], value: int) -> dict[str, Any]:
    lower = sum(score < value for score in scores)
    equal = sum(score == value for score in scores)
    return {
        "score": value,
        "strictly_lower_cells": lower,
        "equal_score_cells": equal,
        "midrank_percentile": (lower + equal / 2) / len(scores),
    }


def build_analysis() -> dict[str, Any]:
    design = load_design()
    if (
        file_sha256(A328_RUNNER) != A328_RUNNER_SHA256
        or file_sha256(A328_RESULT) != A328_RESULT_SHA256
        or file_sha256(A313_RESULT) != A313_RESULT_SHA256
    ):
        raise RuntimeError("A331 source anchor differs")
    source = A327.load_source_views()
    w44 = A328.prototype_panel(source["W44"])
    w45 = A328.prototype_panel(source["W45"])
    labels = [
        left == right
        for left, right in zip(w44["assignment"], w45["assignment"], strict=True)
    ]
    a328 = json.loads(A328_RESULT.read_bytes())
    if sum(labels) != a328["analysis"]["stable_cells"]:
        raise RuntimeError("A331 stable labels differ from A328")
    predictors: dict[str, list[int]] = {
        "W44_margin": list(w44["margin"]),
        "W45_margin": list(w45["margin"]),
        "minimum_margin": [
            min(left, right)
            for left, right in zip(w44["margin"], w45["margin"], strict=True)
        ],
        "maximum_margin": [
            max(left, right)
            for left, right in zip(w44["margin"], w45["margin"], strict=True)
        ],
        "sum_margin": [
            left + right
            for left, right in zip(w44["margin"], w45["margin"], strict=True)
        ],
        "product_margin": [
            left * right
            for left, right in zip(w44["margin"], w45["margin"], strict=True)
        ],
        "negative_absolute_margin_delta": [
            -abs(left - right)
            for left, right in zip(w44["margin"], w45["margin"], strict=True)
        ],
        "deterministic_cell_hash_null": [hash_null_score(cell) for cell in range(CELLS)],
    }
    panels: dict[str, Any] = {}
    for name in PREDICTOR_NAMES:
        scores = predictors[name]
        global_auc = exact_auc(scores, labels)
        reverse_auc = exact_auc([-score for score in scores], labels)
        if (
            global_auc["twice_concordant_numerator"]
            + reverse_auc["twice_concordant_numerator"]
            != global_auc["twice_pair_denominator"]
        ):
            raise RuntimeError(f"A331 reversed-score identity failed for {name}")
        strata: list[dict[str, Any]] = []
        stratified_numerator = 0
        stratified_denominator = 0
        for prototype in range(PROTOTYPES):
            cells = [
                cell for cell in range(CELLS) if w44["assignment"][cell] == prototype
            ]
            panel = exact_auc(
                [scores[cell] for cell in cells], [labels[cell] for cell in cells]
            )
            strata.append({"W44_prototype_index": prototype, **panel})
            if panel["auc"] is not None:
                stratified_numerator += panel["twice_concordant_numerator"]
                stratified_denominator += panel["twice_pair_denominator"]
        panels[name] = {
            "global": global_auc,
            "reversed_score_global_auc": reverse_auc["auc"],
            "reversed_score_exact_identity": True,
            "per_W44_prototype": strata,
            "pair_weighted_stratified": {
                "twice_concordant_numerator": stratified_numerator,
                "twice_pair_denominator": stratified_denominator,
                "auc": stratified_numerator / stratified_denominator,
            },
        }
    eligible = list(ELIGIBLE_PREDICTOR_NAMES)
    selected = max(
        eligible,
        key=lambda name: (
            panels[name]["global"]["auc"],
            -eligible.index(name),
        ),
    )
    selected_auc = panels[selected]["global"]["auc"]
    a313 = json.loads(A313_RESULT.read_bytes())
    prefix = int(a313["discovery"]["prefix12"])
    annotation = {
        "prefix12": prefix,
        "prefix12_hex": f"{prefix:03x}",
        "stable_label": labels[prefix],
        "W44_prototype_index": w44["assignment"][prefix],
        "W45_same_cell_prototype_index": w45["assignment"][prefix],
        "predictors": {
            name: empirical_midrank_percentile(predictors[name], predictors[name][prefix])
            for name in PREDICTOR_NAMES
        },
        "used_for_predictor_selection": False,
    }
    return {
        "design": design,
        "stable_cells": sum(labels),
        "switched_cells": CELLS - sum(labels),
        "predictor_panels": panels,
        "selected_structural_predictor": selected,
        "selected_global_auc": selected_auc,
        "minimum_AUC_for_followup_operator": FOLLOWUP_AUC,
        "followup_margin_operator_supported": selected_auc >= FOLLOWUP_AUC,
        "selected_predictor_score_bins": score_bins(predictors[selected], labels),
        "A313_annotation": annotation,
        "target_labels_used_from_A322_or_A325": 0,
        "new_execution_order": False,
        "candidate_execution": False,
    }


def build_causal(payload: Mapping[str, Any]) -> dict[str, Any]:
    sys.path.insert(0, str(DOTCAUSAL_SRC))
    from dotcausal.io import CausalReader, CausalWriter

    terminal = "A331:exact_margin_to_region_stability_boundary"
    writer = CausalWriter(api_id="a331marg")
    writer._rules = []
    writer.add_rule(
        name="exact_margins_and_region_labels_to_AUC_panel",
        description="Eight fixed score views are compared against the complete A328 stable/switched labels with exact tie-aware Mann-Whitney numerators.",
        pattern=["A328_exact_W44_W45_margins", "A328_complete_region_stability_labels"],
        conclusion="A331_exact_predictor_AUC_panel",
        confidence_modifier=1.0,
    )
    writer.add_rule(
        name="best_non_null_AUC_to_followup_boundary",
        description="The highest-AUC non-null margin predictor is selected by frozen index tie-break and compared with the predeclared 0.55 operator threshold.",
        pattern=["A331_exact_predictor_AUC_panel", "A331_predeclared_0_55_threshold"],
        conclusion=terminal.replace(":", "_"),
        confidence_modifier=1.0,
    )
    writer.add_rule(
        name="confirmed_A313_prefix_to_annotation",
        description="The confirmed A313 prefix receives predictor percentiles after structural selection and cannot alter the selected predictor or boundary.",
        pattern=["A313_confirmed_prefix", "A331_selected_structural_predictor"],
        conclusion="A331_A313_margin_annotation",
        confidence_modifier=1.0,
    )
    writer.add_triplet(
        trigger="A328:exact_W44_W45_margin_and_region_fields",
        mechanism="complete_tie_aware_global_and_stratified_AUC",
        outcome="A331:eight_predictor_margin_stability_panel",
        confidence=1.0,
        source=payload["measurement_sha256"],
        quantification=json.dumps(payload["predictor_summary"], sort_keys=True),
        evidence="COMPLETE_4096_CELL_STRUCTURAL_LABEL_PANEL",
        domain="AI-native margin stability inference",
        quality_score=1.0,
    )
    writer.add_triplet(
        trigger="A331:eight_predictor_margin_stability_panel",
        mechanism="frozen_non_null_selection_and_0_55_boundary",
        outcome=terminal,
        confidence=1.0,
        source=payload["measurement_sha256"],
        quantification=json.dumps(payload["selection"], sort_keys=True),
        evidence=json.dumps(payload["information_boundary"], sort_keys=True),
        domain="mechanistic operator decision",
        quality_score=1.0,
    )
    writer.add_triplet(
        trigger="A313:independently_confirmed_W44_prefix",
        mechanism="annotation_after_structural_predictor_selection",
        outcome="A331:A313_margin_percentile_annotation",
        confidence=1.0,
        source=A313_RESULT_SHA256,
        quantification=json.dumps(payload["A313_annotation"], sort_keys=True),
        evidence="ANNOTATION_ONLY_ZERO_PREDICTOR_SELECTION_EFFECT",
        domain="independent calibration annotation",
        quality_score=1.0,
    )
    writer.add_triplet(
        trigger="A328:exact_W44_W45_margin_and_region_fields",
        mechanism="materialized_margin_stability_decision_chain",
        outcome=terminal,
        confidence=1.0,
        source="materialized:A331_margin_stability_chain",
        quantification="exact retained closure",
        evidence=payload["evidence_stage"],
        domain="AI-native retained inference",
        quality_score=1.0,
        is_inferred=True,
    )
    writer.add_cluster(
        name="A331 exact margin stability boundary",
        entities=[
            "A328:exact_W44_W45_margin_and_region_fields",
            "A331:eight_predictor_margin_stability_panel",
            terminal,
            "A331:A313_margin_percentile_annotation",
        ],
    )
    expected = (
        "prospectively_frozen_margin_conditioned_operator"
        if payload["selection"]["followup_margin_operator_supported"]
        else "retain_A329_region_stability_operator_without_margin_refit"
    )
    writer.add_gap(
        subject=terminal,
        predicate="next_required_object",
        expected_object_type=expected,
        confidence=1.0,
        suggested_queries=[
            "Does the exact structural AUC cross the predeclared margin-operator threshold, and what unchanged next operator follows from that binary boundary?"
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
        reader.api_id != "a331marg"
        or len(explicit) != 3
        or len(all_rows) != 4
        or len(inferred) != 1
        or len(reader._rules) != 3
        or len(reader._clusters) != 1
        or len(reader._gaps) != 1
    ):
        raise RuntimeError("A331 authentic Causal reopen gate failed")
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
    if any(path.exists() for path in (RESULT, CAUSAL, REPORT)):
        raise FileExistsError("A331 artifacts already exist")
    if A322_RESULT.exists():
        raise RuntimeError("A331 must freeze before any A322 result exists")
    if A325_PROGRESS.exists() or A325_RESULT.exists():
        raise RuntimeError("A331 must freeze before any A325 execution or result exists")
    built = build_analysis()
    predictor_summary = {
        name: {
            "global_auc": panel["global"]["auc"],
            "global_twice_concordant_numerator": panel["global"][
                "twice_concordant_numerator"
            ],
            "global_twice_pair_denominator": panel["global"][
                "twice_pair_denominator"
            ],
            "pair_weighted_stratified_auc": panel["pair_weighted_stratified"][
                "auc"
            ],
            "reversed_score_global_auc": panel["reversed_score_global_auc"],
        }
        for name, panel in built["predictor_panels"].items()
    }
    selection = {
        "selected_structural_predictor": built["selected_structural_predictor"],
        "selected_global_auc": built["selected_global_auc"],
        "minimum_AUC_for_followup_operator": FOLLOWUP_AUC,
        "followup_margin_operator_supported": built[
            "followup_margin_operator_supported"
        ],
        "A313_used_for_selection": False,
        "A322_A325_labels_used": 0,
    }
    payload: dict[str, Any] = {
        "schema": "chacha20-round20-linf-margin-stability-a331-result-v1",
        "attempt_id": ATTEMPT_ID,
        "evidence_stage": "COMPLETE_TARGET_BLIND_MARGIN_STABILITY_BOUNDARY_RETAINED",
        "design_sha256": DESIGN_SHA256,
        "stable_cells": built["stable_cells"],
        "switched_cells": built["switched_cells"],
        "predictor_sequence_and_tie_break": list(PREDICTOR_NAMES),
        "predictor_panels": built["predictor_panels"],
        "predictor_summary": predictor_summary,
        "selection": selection,
        "selected_predictor_score_bins": built["selected_predictor_score_bins"],
        "A313_annotation": built["A313_annotation"],
        "information_boundary": built["design"]["information_boundary"],
        "new_execution_order": False,
        "candidate_execution": False,
        "anchors": {
            "design": anchor(DESIGN, DESIGN_SHA256),
            "A313_result": anchor(A313_RESULT, A313_RESULT_SHA256),
            "A328_result": anchor(A328_RESULT, A328_RESULT_SHA256),
            "A328_runner": anchor(A328_RUNNER, A328_RUNNER_SHA256),
            "runner": anchor(Path(__file__)),
            "test": anchor(A331_TEST),
            "reproducer": anchor(A331_REPRO),
        },
    }
    payload["measurement_sha256"] = canonical_sha256(
        {
            "stable_cells": payload["stable_cells"],
            "switched_cells": payload["switched_cells"],
            "predictor_summary": predictor_summary,
            "selection": selection,
            "selected_predictor_score_bins": payload[
                "selected_predictor_score_bins"
            ],
            "A313_annotation": payload["A313_annotation"],
            "information_boundary": payload["information_boundary"],
        }
    )
    payload["causal"] = build_causal(payload)
    atomic_json(RESULT, payload)
    atomic_bytes(
        REPORT,
        (
            "# A331 — exact Linf-margin stability boundary\n\n"
            f"- Selected non-null predictor: **{selection['selected_structural_predictor']}**\n"
            f"- Exact global AUC: **{selection['selected_global_auc']:.6f}**\n"
            f"- Predeclared followup threshold: **{FOLLOWUP_AUC:.2f}**\n"
            f"- Margin-conditioned operator supported: **{selection['followup_margin_operator_supported']}**\n"
            f"- Deterministic cell-hash null AUC: **{predictor_summary['deterministic_cell_hash_null']['global_auc']:.6f}**\n"
            "- A313 role: **annotation only**\n"
            "- A322/A325 labels, refits and candidate executions: **zero**\n"
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
        "result_exists": RESULT.exists(),
    }
    if RESULT.exists():
        payload = json.loads(RESULT.read_bytes())
        response.update(
            {
                "result_sha256": file_sha256(RESULT),
                "measurement_sha256": payload["measurement_sha256"],
                "selection": payload["selection"],
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

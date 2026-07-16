#!/usr/bin/env python3
"""A328: decompose raw Linf transfer into stable and switched prototype regions."""

from __future__ import annotations

import argparse
import importlib.util
import inspect
import json
import math
import os
import sys
from collections import Counter
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

ROOT = Path(__file__).parents[2]
RESEARCH = ROOT / "research"
CONFIGS = RESEARCH / "configs"
RESULTS = RESEARCH / "results/v1"

DESIGN = CONFIGS / "chacha20_round20_linf_voronoi_transfer_a328_design_v1.json"
RESULT = RESULTS / "chacha20_round20_linf_voronoi_transfer_a328_v1.json"
CAUSAL = RESULTS / "chacha20_round20_linf_voronoi_transfer_a328_v1.causal"
REPORT = RESULTS / "chacha20_round20_linf_voronoi_transfer_a328_v1.md"

A327_RUNNER = RESEARCH / "experiments/chacha20_round20_hierarchical_linf_operator_a327.py"
A317_ORDER = RESULTS / "chacha20_round20_w44_multiview_operator_atlas_a317_order_v1.json"
A318_ORDER = RESULTS / "chacha20_round20_w45_multiview_operator_atlas_a318_order_v1.json"
A327_ORDER = RESULTS / "chacha20_round20_hierarchical_linf_operator_a327_order_v1.json"
A313_RESULT = RESULTS / "chacha20_round20_w44_width_conditioned_fine_portfolio_a313_v1.json"
A322_RESULT = RESULTS / "chacha20_round20_holdout_selected_w45_recovery_a322_v1.json"
A325_PROGRESS = RESULTS / "chacha20_round20_holdout_selected_w46_recovery_a325_progress_v1.json"
A325_RESULT = RESULTS / "chacha20_round20_holdout_selected_w46_recovery_a325_v1.json"
A328_TEST = ROOT / "tests/test_chacha20_round20_linf_voronoi_transfer_a328.py"
A328_REPRO = ROOT / "scripts/reproduce_chacha20_round20_linf_voronoi_transfer_a328.sh"

ATTEMPT_ID = "A328"
DESIGN_SHA256 = "58e41a238e8bc8e5ac042b51aa478190327e22c038f0585f444a01c7ae792f31"
A317_ORDER_SHA256 = "3c3779cb26ace4e4361399969a89461eb69e443e8b4630f953cb0a8892f672a2"
A318_ORDER_SHA256 = "25c36b4412cedcd37243057535109b36e79ded5172eba642bb84dd50f1de49f0"
A327_ORDER_SHA256 = "7c077a4e8eeb3ab83c4fae931f94882c87369cedb18bd19b2766e04e9b72c90f"
A313_RESULT_SHA256 = "ec18ee284da633589d1c35fe8f02257438f83fb4f255553667ebc3a0b0452b9a"
CELLS = 1 << 12
PROTOTYPES = 4
QUANTILES = (0.0, 0.25, 0.5, 0.75, 0.9, 1.0)


def load_module(path: Path, name: str) -> Any:
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot import A328 dependency {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


A327 = load_module(A327_RUNNER, "a328_a327_common")
file_sha256 = A327.file_sha256
canonical_sha256 = A327.canonical_sha256
atomic_json = A327.atomic_json
atomic_bytes = A327.atomic_bytes
relative = A327.relative
path_from_ref = A327.path_from_ref
anchor = A327.anchor
DOTCAUSAL_SRC = A327.DOTCAUSAL_SRC


def load_design() -> dict[str, Any]:
    if file_sha256(DESIGN) != DESIGN_SHA256:
        raise RuntimeError("A328 design hash differs")
    design = json.loads(DESIGN.read_bytes())
    analysis = design.get("analysis_contract", {})
    boundary = design.get("information_boundary", {})
    if (
        design.get("schema") != "chacha20-round20-linf-voronoi-transfer-a328-design-v1"
        or design.get("attempt_id") != ATTEMPT_ID
        or design.get("design_state")
        != "frozen_while_A322_is_running_before_any_A322_result_and_before_any_A325_execution_or_result"
        or analysis.get("prototype_assignment_tie_break")
        != "lowest frozen A317 prototype index"
        or tuple(analysis.get("margin_quantiles", ())) != QUANTILES
        or analysis.get("operator_refit") is not False
        or analysis.get("new_execution_order") is not False
        or analysis.get("candidate_execution") is not False
        or analysis.get("target_labels_used_from_A322_or_A325") != 0
        or boundary.get("A322_progress_used_for_any_analysis_definition") is not False
        or boundary.get("A322_result_available_at_design_freeze") is not False
        or boundary.get("A325_execution_started_at_design_freeze") is not False
        or boundary.get(
            "A325_progress_result_candidate_or_prefix_rank_available_at_design_freeze"
        )
        is not False
        or boundary.get("target_labels_used_from_A322_or_A325") != 0
    ):
        raise RuntimeError("A328 frozen design semantics differ")
    for key, value in design["source_anchors"].items():
        if key.endswith("_path"):
            anchor(
                path_from_ref(value),
                design["source_anchors"][key.removesuffix("_path") + "_sha256"],
            )
    return design


def nearest_index_quantiles(values: Sequence[int]) -> list[dict[str, Any]]:
    ordered = sorted(int(value) for value in values)
    if not ordered:
        return []
    return [
        {
            "probability": probability,
            "zero_based_index": round((len(ordered) - 1) * probability),
            "value": ordered[round((len(ordered) - 1) * probability)],
        }
        for probability in QUANTILES
    ]


def subset_spearman(
    left_ranks: Sequence[int], right_ranks: Sequence[int], cells: Sequence[int]
) -> float | None:
    if len(cells) < 2:
        return None
    x = [float(left_ranks[cell]) for cell in cells]
    y = [float(right_ranks[cell]) for cell in cells]
    mean_x = sum(x) / len(x)
    mean_y = sum(y) / len(y)
    numerator = sum(
        (a - mean_x) * (b - mean_y) for a, b in zip(x, y, strict=True)
    )
    denominator = math.sqrt(
        sum((a - mean_x) ** 2 for a in x) * sum((b - mean_y) ** 2 for b in y)
    )
    return numerator / denominator if denominator else None


def prototype_panel(source: Mapping[str, Sequence[int]]) -> dict[str, list[int]]:
    ranks = A327._coordinates(source)  # noqa: SLF001
    assignment: list[int] = []
    nearest_distance: list[int] = []
    margin: list[int] = []
    for cell in range(CELLS):
        point = (ranks["fine"][cell], ranks["coarse"][cell], ranks["numeric"][cell])
        distances = [
            max(A327._deviations(point, prototype))  # noqa: SLF001
            for prototype in A327.A317.PROTOTYPES
        ]
        ordered = sorted((distance, index) for index, distance in enumerate(distances))
        assignment.append(ordered[0][1])
        nearest_distance.append(ordered[0][0])
        margin.append(ordered[1][0] - ordered[0][0])
    return {
        "assignment": assignment,
        "nearest_distance": nearest_distance,
        "margin": margin,
    }


def analyze_voronoi() -> dict[str, Any]:
    design = load_design()
    if (
        file_sha256(A317_ORDER) != A317_ORDER_SHA256
        or file_sha256(A318_ORDER) != A318_ORDER_SHA256
        or file_sha256(A327_ORDER) != A327_ORDER_SHA256
    ):
        raise RuntimeError("A328 order anchor differs")
    source = A327.load_source_views()
    w44 = prototype_panel(source["W44"])
    w45 = prototype_panel(source["W45"])
    raw44 = A327.rank_vector(source["original_W44_linf"])
    raw45 = A327.rank_vector(source["original_W45_linf"])
    transition = [[0 for _ in range(PROTOTYPES)] for _ in range(PROTOTYPES)]
    for left, right in zip(w44["assignment"], w45["assignment"], strict=True):
        transition[left][right] += 1
    stable_cells = [
        cell
        for cell in range(CELLS)
        if w44["assignment"][cell] == w45["assignment"][cell]
    ]
    stable_set = set(stable_cells)
    switched_cells = [cell for cell in range(CELLS) if cell not in stable_set]
    occupancy44 = Counter(w44["assignment"])
    occupancy45 = Counter(w45["assignment"])
    per_source = []
    for prototype in range(PROTOTYPES):
        source_cells = [cell for cell in range(CELLS) if w44["assignment"][cell] == prototype]
        stable = sum(cell in stable_set for cell in source_cells)
        per_source.append(
            {
                "W44_prototype_index": prototype,
                "W44_cells": len(source_cells),
                "stable_same_prototype_cells": stable,
                "stable_fraction": stable / len(source_cells),
                "W45_destination_counts": transition[prototype],
            }
        )
    if file_sha256(A313_RESULT) != A313_RESULT_SHA256:
        raise RuntimeError("A328 A313 result hash differs")
    a313 = json.loads(A313_RESULT.read_bytes())
    prefix = int(a313["discovery"]["prefix12"])
    return {
        "design": design,
        "prototype_coordinates_one_based": [list(row) for row in A327.A317.PROTOTYPES],
        "W44_occupancy": [occupancy44[index] for index in range(PROTOTYPES)],
        "W45_occupancy": [occupancy45[index] for index in range(PROTOTYPES)],
        "transition_matrix_W44_rows_W45_columns": transition,
        "stable_cells": len(stable_cells),
        "switched_cells": len(switched_cells),
        "stable_fraction": len(stable_cells) / CELLS,
        "switched_fraction": len(switched_cells) / CELLS,
        "raw_Linf_cross_width_spearman_all": A327.spearman(
            source["original_W44_linf"], source["original_W45_linf"]
        ),
        "raw_Linf_cross_width_spearman_stable_subset": subset_spearman(
            raw44, raw45, stable_cells
        ),
        "raw_Linf_cross_width_spearman_switched_subset": subset_spearman(
            raw44, raw45, switched_cells
        ),
        "per_W44_source_prototype": per_source,
        "margin_panels": {
            "W44_all": nearest_index_quantiles(w44["margin"]),
            "W45_all": nearest_index_quantiles(w45["margin"]),
            "W44_stable": nearest_index_quantiles([w44["margin"][cell] for cell in stable_cells]),
            "W45_stable": nearest_index_quantiles([w45["margin"][cell] for cell in stable_cells]),
            "W44_switched": nearest_index_quantiles(
                [w44["margin"][cell] for cell in switched_cells]
            ),
            "W45_switched": nearest_index_quantiles(
                [w45["margin"][cell] for cell in switched_cells]
            ),
        },
        "A313_calibration_annotation": {
            "prefix12": prefix,
            "prefix12_hex": f"{prefix:03x}",
            "W44_prototype_index": w44["assignment"][prefix],
            "W45_same_cell_prototype_index": w45["assignment"][prefix],
            "prototype_identity_stable_on_same_cell": w44["assignment"][prefix]
            == w45["assignment"][prefix],
            "W44_nearest_distance": w44["nearest_distance"][prefix],
            "W45_same_cell_nearest_distance": w45["nearest_distance"][prefix],
            "W44_margin": w44["margin"][prefix],
            "W45_same_cell_margin": w45["margin"][prefix],
            "W44_raw_Linf_rank_one_based": raw44[prefix],
            "W45_same_cell_raw_Linf_rank_one_based": raw45[prefix],
        },
        "target_labels_used_from_A322_or_A325": 0,
        "candidate_execution": False,
        "operator_refits": 0,
    }


def build_causal(payload: Mapping[str, Any]) -> dict[str, Any]:
    sys.path.insert(0, str(DOTCAUSAL_SRC))
    from dotcausal.io import CausalReader, CausalWriter

    terminal = "A328:Linf_cross_width_Voronoi_transfer_map"
    writer = CausalWriter(api_id="a328voro")
    writer._rules = []
    writer.add_rule(
        name="exact_rank_coordinates_to_Linf_Voronoi_regions",
        description="Each W44 and W45 prefix cell is assigned to its nearest unchanged A317 prototype under exact Linf distance with a frozen index tie-break.",
        pattern=["exact_Fine_Coarse_Numeric_rank_coordinates", "unchanged_A317_prototypes"],
        conclusion="A328_complete_W44_W45_prototype_assignment",
        confidence_modifier=1.0,
    )
    writer.add_rule(
        name="paired_region_assignments_to_transfer_decomposition",
        description="The complete 4x4 transition matrix separates same-prototype stability from cross-prototype switching and measures rank correlation on each subset.",
        pattern=["complete_W44_region_assignment", "complete_W45_region_assignment"],
        conclusion=terminal.replace(":", "_"),
        confidence_modifier=1.0,
    )
    writer.add_rule(
        name="confirmed_A313_prefix_to_region_annotation",
        description="The independently confirmed A313 prefix annotates one calibration cell without changing regions, prototypes or future orders.",
        pattern=["A313_confirmed_prefix", "A328_target_blind_region_map"],
        conclusion="A328_A313_calibration_region_annotation",
        confidence_modifier=1.0,
    )
    writer.add_triplet(
        trigger="A317_A318:exact_target_blind_rank_coordinate_fields",
        mechanism="unchanged_four_prototype_Linf_Voronoi_assignment",
        outcome="A328:complete_W44_W45_prototype_assignment",
        confidence=1.0,
        source=payload["measurement_sha256"],
        quantification=json.dumps(
            {
                "W44_occupancy": payload["analysis"]["W44_occupancy"],
                "W45_occupancy": payload["analysis"]["W45_occupancy"],
                "transition_matrix": payload["analysis"][
                    "transition_matrix_W44_rows_W45_columns"
                ],
            },
            sort_keys=True,
        ),
        evidence="COMPLETE_4096_CELL_EXACT_VORONOI_ASSIGNMENT",
        domain="AI-native cross-width Linf geometry",
        quality_score=1.0,
    )
    writer.add_triplet(
        trigger="A328:complete_W44_W45_prototype_assignment",
        mechanism="stable_vs_switched_region_rank_correlation_decomposition",
        outcome=terminal,
        confidence=1.0,
        source=payload["measurement_sha256"],
        quantification=json.dumps(
            {
                key: payload["analysis"][key]
                for key in (
                    "stable_cells",
                    "switched_cells",
                    "stable_fraction",
                    "raw_Linf_cross_width_spearman_all",
                    "raw_Linf_cross_width_spearman_stable_subset",
                    "raw_Linf_cross_width_spearman_switched_subset",
                    "per_W44_source_prototype",
                )
            },
            sort_keys=True,
        ),
        evidence=json.dumps(payload["information_boundary"], sort_keys=True),
        domain="mechanistic Linf transfer decomposition",
        quality_score=1.0,
    )
    writer.add_triplet(
        trigger="A313:independently_confirmed_W44_prefix",
        mechanism="post_confirmation_annotation_in_frozen_Voronoi_map",
        outcome="A328:A313_calibration_region_annotation",
        confidence=1.0,
        source=A313_RESULT_SHA256,
        quantification=json.dumps(
            payload["analysis"]["A313_calibration_annotation"], sort_keys=True
        ),
        evidence="ANNOTATION_ONLY_ZERO_REFIT_ZERO_ORDER_CHANGE",
        domain="independent calibration annotation",
        quality_score=1.0,
    )
    writer.add_triplet(
        trigger="A317_A318:exact_target_blind_rank_coordinate_fields",
        mechanism="materialized_complete_Voronoi_transfer_chain",
        outcome=terminal,
        confidence=1.0,
        source="materialized:A328_Linf_Voronoi_transfer_chain",
        quantification="exact retained closure",
        evidence=payload["evidence_stage"],
        domain="AI-native retained inference",
        quality_score=1.0,
        is_inferred=True,
    )
    writer.add_cluster(
        name="A328 Linf cross-width Voronoi transfer",
        entities=[
            "A317_A318:exact_target_blind_rank_coordinate_fields",
            "A328:complete_W44_W45_prototype_assignment",
            terminal,
            "A328:A313_calibration_region_annotation",
        ],
    )
    writer.add_gap(
        subject=terminal,
        predicate="next_required_object",
        expected_object_type="prospective_margin_or_region_stability_operator_if_mechanistically_selected",
        confidence=1.0,
        suggested_queries=[
            "Does a predeclared stable-region or prototype-margin operator improve a future untouched target without displacing raw Linf by posthoc choice?"
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
        reader.api_id != "a328voro"
        or len(explicit) != 3
        or len(all_rows) != 4
        or len(inferred) != 1
        or len(reader._rules) != 3
        or len(reader._clusters) != 1
        or len(reader._gaps) != 1
    ):
        raise RuntimeError("A328 authentic Causal reopen gate failed")
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
        raise FileExistsError("A328 artifacts already exist")
    if A322_RESULT.exists():
        raise RuntimeError("A328 must freeze before any A322 result exists")
    if A325_PROGRESS.exists() or A325_RESULT.exists():
        raise RuntimeError("A328 must freeze before any A325 execution or result exists")
    analysis = analyze_voronoi()
    payload: dict[str, Any] = {
        "schema": "chacha20-round20-linf-voronoi-transfer-a328-result-v1",
        "attempt_id": ATTEMPT_ID,
        "evidence_stage": "COMPLETE_TARGET_BLIND_LINF_VORONOI_TRANSFER_MAP_RETAINED",
        "design_sha256": DESIGN_SHA256,
        "analysis": {key: value for key, value in analysis.items() if key != "design"},
        "information_boundary": analysis["design"]["information_boundary"],
        "anchors": {
            "design": anchor(DESIGN, DESIGN_SHA256),
            "A313_result": anchor(A313_RESULT, A313_RESULT_SHA256),
            "A317_order": anchor(A317_ORDER, A317_ORDER_SHA256),
            "A318_order": anchor(A318_ORDER, A318_ORDER_SHA256),
            "A327_order": anchor(A327_ORDER, A327_ORDER_SHA256),
            "runner": anchor(Path(__file__)),
            "test": anchor(A328_TEST),
            "reproducer": anchor(A328_REPRO),
        },
    }
    payload["measurement_sha256"] = canonical_sha256(
        {
            "analysis": payload["analysis"],
            "information_boundary": payload["information_boundary"],
        }
    )
    payload["causal"] = build_causal(payload)
    atomic_json(RESULT, payload)
    annotation = payload["analysis"]["A313_calibration_annotation"]
    atomic_bytes(
        REPORT,
        (
            "# A328 — raw-Linf Voronoi transfer map\n\n"
            f"- Stable same-prototype cells: **{payload['analysis']['stable_cells']:,} / 4,096 ({payload['analysis']['stable_fraction']:.3%})**\n"
            f"- Switched cells: **{payload['analysis']['switched_cells']:,} / 4,096**\n"
            f"- Raw-Linf W44→W45 Spearman, all cells: **{payload['analysis']['raw_Linf_cross_width_spearman_all']:.6f}**\n"
            f"- Stable subset Spearman: **{payload['analysis']['raw_Linf_cross_width_spearman_stable_subset']:.6f}**\n"
            f"- Switched subset Spearman: **{payload['analysis']['raw_Linf_cross_width_spearman_switched_subset']:.6f}**\n"
            f"- A313 same-cell prototype transition: **{annotation['W44_prototype_index']} → {annotation['W45_same_cell_prototype_index']}**\n"
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
                "evidence_stage": payload["evidence_stage"],
                "stable_cells": payload["analysis"]["stable_cells"],
                "stable_fraction": payload["analysis"]["stable_fraction"],
                "raw_Linf_cross_width_spearman_stable_subset": payload["analysis"][
                    "raw_Linf_cross_width_spearman_stable_subset"
                ],
                "raw_Linf_cross_width_spearman_switched_subset": payload["analysis"][
                    "raw_Linf_cross_width_spearman_switched_subset"
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

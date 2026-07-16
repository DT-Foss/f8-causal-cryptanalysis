#!/usr/bin/env python3
"""A327: refine raw Linf only inside exact Chebyshev tie plateaus."""

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

DESIGN = CONFIGS / "chacha20_round20_hierarchical_linf_operator_a327_design_v1.json"
ORDER = RESULTS / "chacha20_round20_hierarchical_linf_operator_a327_order_v1.json"
CAUSAL = RESULTS / "chacha20_round20_hierarchical_linf_operator_a327_order_v1.causal"
REPORT = RESULTS / "chacha20_round20_hierarchical_linf_operator_a327_order_v1.md"

A317_RUNNER = RESEARCH / "experiments/chacha20_round20_w44_multiview_operator_atlas_a317.py"
A317_ORDER = RESULTS / "chacha20_round20_w44_multiview_operator_atlas_a317_order_v1.json"
A318_ORDER = RESULTS / "chacha20_round20_w45_multiview_operator_atlas_a318_order_v1.json"
A321_ORDER = RESULTS / "chacha20_round20_holdout_selected_w45_operator_a321_order_v1.json"
A313_RESULT = RESULTS / "chacha20_round20_w44_width_conditioned_fine_portfolio_a313_v1.json"
A322_RESULT = RESULTS / "chacha20_round20_holdout_selected_w45_recovery_a322_v1.json"
A325_PROGRESS = RESULTS / "chacha20_round20_holdout_selected_w46_recovery_a325_progress_v1.json"
A325_RESULT = RESULTS / "chacha20_round20_holdout_selected_w46_recovery_a325_v1.json"
A327_TEST = ROOT / "tests/test_chacha20_round20_hierarchical_linf_operator_a327.py"
A327_REPRO = ROOT / "scripts/reproduce_chacha20_round20_hierarchical_linf_operator_a327.sh"

ATTEMPT_ID = "A327"
DESIGN_SHA256 = "e876bf9ac31bd3479d40f0f35c5ef86944d23199fca4e98af6fd92b392f0208b"
A317_ORDER_SHA256 = "3c3779cb26ace4e4361399969a89461eb69e443e8b4630f953cb0a8892f672a2"
A318_ORDER_SHA256 = "25c36b4412cedcd37243057535109b36e79ded5172eba642bb84dd50f1de49f0"
A321_ORDER_SHA256 = "8ace2e5af5ce1a132e78926f317dadaf63ada13a10c0338a56ddf62713a9d9d2"
A313_RESULT_SHA256 = "ec18ee284da633589d1c35fe8f02257438f83fb4f255553667ebc3a0b0452b9a"
CELLS = 1 << 12
CANDIDATE_NAMES = (
    "original_linf",
    "linf_then_l1_then_l2",
    "linf_then_l2_then_l1",
    "lexicographic_deviation_profile",
)


def load_module(path: Path, name: str) -> Any:
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot import A327 dependency {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


A317 = load_module(A317_RUNNER, "a327_a317_common")
file_sha256 = A317.file_sha256
canonical_sha256 = A317.canonical_sha256
atomic_json = A317.atomic_json
atomic_bytes = A317.atomic_bytes
relative = A317.relative
path_from_ref = A317.path_from_ref
anchor = A317.anchor
DOTCAUSAL_SRC = A317.DOTCAUSAL_SRC


def _exact_order(values: Sequence[int], label: str) -> list[int]:
    return A317._exact_order(values, f"A327 {label}")  # noqa: SLF001


def _order_sha(values: Sequence[int]) -> str:
    return A317.sha256(
        b"".join(value.to_bytes(2, "big") for value in _exact_order(values, "hash"))
    )


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
        raise RuntimeError("A327 design hash differs")
    design = json.loads(DESIGN.read_bytes())
    operator = design.get("operator_contract", {})
    selection = design.get("selection_contract", {})
    boundary = design.get("information_boundary", {})
    if (
        design.get("schema")
        != "chacha20-round20-hierarchical-linf-operator-a327-design-v1"
        or design.get("attempt_id") != ATTEMPT_ID
        or design.get("design_state")
        != "frozen_while_A322_is_running_before_any_A322_result_and_before_any_A325_execution_or_result"
        or tuple(operator.get("candidate_sequence_and_tie_break", ())) != CANDIDATE_NAMES
        or operator.get("primary_distance_changed") is not False
        or operator.get("prototype_refit") is not False
        or operator.get("coordinate_refit") is not False
        or operator.get("candidate_execution") is not False
        or operator.get("target_labels_used_to_construct_orders") != 0
        or selection.get("selection_rule")
        != "minimum_A313_rank_then_frozen_candidate_index"
        or selection.get("A322_progress_or_result_used") is not False
        or selection.get("A325_public_challenge_features_used") is not False
        or selection.get("A325_target_label_prefix_filter_or_result_used") is not False
        or boundary.get("A322_progress_used_for_any_order_or_selection") is not False
        or boundary.get("A322_result_available_at_design_freeze") is not False
        or boundary.get("A325_execution_started_at_design_freeze") is not False
        or boundary.get(
            "A325_progress_result_candidate_or_prefix_rank_available_at_design_freeze"
        )
        is not False
        or boundary.get("target_labels_used_from_A322_or_A325") != 0
    ):
        raise RuntimeError("A327 frozen design semantics differ")
    for key, value in design["source_anchors"].items():
        if key.endswith("_path"):
            anchor(
                path_from_ref(value),
                design["source_anchors"][key.removesuffix("_path") + "_sha256"],
            )
    return design


def load_source_views() -> dict[str, Any]:
    if file_sha256(A317_ORDER) != A317_ORDER_SHA256:
        raise RuntimeError("A327 A317 order hash differs")
    if file_sha256(A318_ORDER) != A318_ORDER_SHA256:
        raise RuntimeError("A327 A318 order hash differs")
    if file_sha256(A321_ORDER) != A321_ORDER_SHA256:
        raise RuntimeError("A327 A321 order hash differs")
    a317 = json.loads(A317_ORDER.read_bytes())
    a318 = json.loads(A318_ORDER.read_bytes())
    a321 = json.loads(A321_ORDER.read_bytes())
    if (
        a317.get("prototype_coordinates_one_based")
        != [list(row) for row in A317.PROTOTYPES]
        or a318.get("prototype_coordinates_one_based")
        != [list(row) for row in A317.PROTOTYPES]
        or a318.get("coordinate_source_orders") is None
        or a321.get("selection", {}).get("selected_operator")
        != "raw_nearest_prototype_Linf"
    ):
        raise RuntimeError("A327 source semantics differ")
    w44 = {
        name: _exact_order(
            a317["coordinate_source_orders"][name], f"W44 {name} source"
        )
        for name in ("fine", "coarse", "numeric")
    }
    w45 = {
        name: _exact_order(
            a318["coordinate_source_orders"][name], f"W45 {name} source"
        )
        for name in ("fine", "coarse", "numeric")
    }
    original_w44 = _exact_order(
        a317["atlas_orders"]["nearest_prototype_Linf"], "original W44 Linf"
    )
    original_w45 = _exact_order(
        a318["atlas_orders"]["nearest_prototype_Linf"], "original W45 Linf"
    )
    if (
        _order_sha(original_w44)
        != a317["order_uint16be_sha256"]["nearest_prototype_Linf"]
        or _order_sha(original_w45)
        != a318["order_uint16be_sha256"]["nearest_prototype_Linf"]
        or _order_sha(original_w45)
        != a321["selection"]["selected_W45_order_uint16be_sha256"]
    ):
        raise RuntimeError("A327 original Linf identity differs")
    return {
        "W44": w44,
        "W45": w45,
        "original_W44_linf": original_w44,
        "original_W45_linf": original_w45,
    }


def _coordinates(source: Mapping[str, Sequence[int]]) -> dict[str, list[int]]:
    return {name: rank_vector(source[name]) for name in ("fine", "coarse", "numeric")}


def _deviations(point: Sequence[int], prototype: Sequence[int]) -> tuple[int, int, int]:
    return tuple(
        abs(int(left) - int(right))
        for left, right in zip(point, prototype, strict=True)
    )


def _score(
    deviations: tuple[int, int, int], prototype_index: int, candidate_name: str
) -> tuple[int, int, int, int]:
    maximum = max(deviations)
    l1 = sum(deviations)
    l2 = sum(value * value for value in deviations)
    if candidate_name == "linf_then_l1_then_l2":
        return maximum, l1, l2, prototype_index
    if candidate_name == "linf_then_l2_then_l1":
        return maximum, l2, l1, prototype_index
    if candidate_name == "lexicographic_deviation_profile":
        ordered = sorted(deviations, reverse=True)
        return ordered[0], ordered[1], ordered[2], prototype_index
    raise ValueError(f"A327 unknown hierarchical candidate {candidate_name}")


def hierarchical_order(
    source: Mapping[str, Sequence[int]], candidate_name: str
) -> list[int]:
    if candidate_name not in CANDIDATE_NAMES[1:]:
        raise ValueError("A327 hierarchical_order requires a refined candidate")
    ranks = _coordinates(source)

    def key(cell: int) -> tuple[int, ...]:
        point = (ranks["fine"][cell], ranks["coarse"][cell], ranks["numeric"][cell])
        scores = [
            _score(_deviations(point, prototype), index, candidate_name)
            for index, prototype in enumerate(A317.PROTOTYPES)
        ]
        best = min(scores)
        return (*best, point[0], point[1], point[2], cell)

    return _exact_order(sorted(range(CELLS), key=key), candidate_name)


def primary_linf_plateaus(source: Mapping[str, Sequence[int]]) -> dict[str, Any]:
    ranks = _coordinates(source)
    distances: list[int] = []
    for cell in range(CELLS):
        point = (ranks["fine"][cell], ranks["coarse"][cell], ranks["numeric"][cell])
        distances.append(
            min(max(_deviations(point, prototype)) for prototype in A317.PROTOTYPES)
        )
    counts = Counter(distances)
    return {
        "cells": CELLS,
        "unique_primary_linf_distances": len(counts),
        "tied_primary_distance_values": sum(count > 1 for count in counts.values()),
        "cells_in_tied_primary_plateaus": sum(
            count for count in counts.values() if count > 1
        ),
        "maximum_primary_plateau_size": max(counts.values()),
    }


def build_candidates() -> dict[str, Any]:
    design = load_design()
    source = load_source_views()
    candidates: dict[str, Any] = {}
    for name in CANDIDATE_NAMES:
        if name == "original_linf":
            w44 = source["original_W44_linf"]
            w45 = source["original_W45_linf"]
        else:
            w44 = hierarchical_order(source["W44"], name)
            w45 = hierarchical_order(source["W45"], name)
        candidates[name] = {
            "W44_order": w44,
            "W45_order": w45,
            "W44_order_uint16be_sha256": _order_sha(w44),
            "W45_order_uint16be_sha256": _order_sha(w45),
            "cross_width_spearman": spearman(w44, w45),
        }
    return {
        "design": design,
        "source": source,
        "candidates": candidates,
        "W44_primary_linf_plateaus": primary_linf_plateaus(source["W44"]),
        "W45_primary_linf_plateaus": primary_linf_plateaus(source["W45"]),
    }


def select_on_a313(candidates: Mapping[str, Mapping[str, Any]]) -> dict[str, Any]:
    if file_sha256(A313_RESULT) != A313_RESULT_SHA256:
        raise RuntimeError("A327 A313 result hash differs")
    a313 = json.loads(A313_RESULT.read_bytes())
    if (
        a313.get("attempt_id") != "A313"
        or a313.get("confirmation", {}).get("all_blocks_match") is not True
        or a313.get("discovery", {}).get("prefix12")
        != a313.get("rank_analysis", {}).get("prefix12")
    ):
        raise RuntimeError("A327 A313 confirmation differs")
    prefix = int(a313["discovery"]["prefix12"])
    ranks = [candidates[name]["W44_order"].index(prefix) + 1 for name in CANDIDATE_NAMES]
    selected_index = min(range(len(CANDIDATE_NAMES)), key=lambda index: (ranks[index], index))
    selected_name = CANDIDATE_NAMES[selected_index]
    selected = candidates[selected_name]
    return {
        "calibration_prefix12": prefix,
        "calibration_prefix12_hex": f"{prefix:03x}",
        "candidate_ranks_one_based": {
            name: ranks[index] for index, name in enumerate(CANDIDATE_NAMES)
        },
        "selected_candidate_index": selected_index,
        "selected_operator": selected_name,
        "selected_calibration_rank_one_based": ranks[selected_index],
        "selected_W44_order_uint16be_sha256": selected["W44_order_uint16be_sha256"],
        "selected_W45_order_uint16be_sha256": selected["W45_order_uint16be_sha256"],
        "selected_W45_order": selected["W45_order"],
        "selection_rule": "minimum_A313_rank_then_frozen_candidate_index",
    }


def build_causal(payload: Mapping[str, Any]) -> dict[str, Any]:
    sys.path.insert(0, str(DOTCAUSAL_SRC))
    from dotcausal.io import CausalReader, CausalWriter

    terminal = "A327:frozen_hierarchical_Linf_W45_execution_order"
    writer = CausalWriter(api_id="a327linf")
    writer._rules = []
    writer.add_rule(
        name="Linf_plateaus_to_hierarchical_exact_orders",
        description="The retained Linf maximum remains primary while exact L1, L2 or ordered-deviation profiles resolve its integer tie plateaus.",
        pattern=["A317_raw_Linf_operator", "exact_primary_distance_plateaus"],
        conclusion="A327_four_exact_hierarchical_W44_W45_pairs",
        confidence_modifier=1.0,
    )
    writer.add_rule(
        name="independent_W44_calibration_to_hierarchical_selection",
        description="A313 selects the earliest of the original Linf and three predeclared hierarchical refinements with a frozen-index tie-break.",
        pattern=["A313_independently_confirmed_W44_prefix", "A327_four_predeclared_W44_orders"],
        conclusion="A327_selected_hierarchical_identity",
        confidence_modifier=1.0,
    )
    writer.add_rule(
        name="selected_hierarchical_identity_to_paired_W45_order",
        description="The exact paired W45 order is copied without A322 or A325 progress, labels, results, refits or manual override.",
        pattern=["A327_selected_hierarchical_identity", "paired_target_blind_W45_order"],
        conclusion=terminal.replace(":", "_"),
        confidence_modifier=1.0,
    )
    writer.add_triplet(
        trigger="A317:raw_nearest_prototype_Linf",
        mechanism="exact_hierarchical_resolution_of_primary_Linf_tie_plateaus",
        outcome="A327:four_exact_hierarchical_W44_W45_order_pairs",
        confidence=1.0,
        source=payload["measurement_sha256"],
        quantification=json.dumps(
            {
                "W44": payload["W44_primary_linf_plateaus"],
                "W45": payload["W45_primary_linf_plateaus"],
                "candidate_names": list(CANDIDATE_NAMES),
            },
            sort_keys=True,
        ),
        evidence="PRIMARY_LINF_PRESERVED_SECONDARY_DISTANCE_STRUCTURE_ONLY",
        domain="AI-native hierarchical nearest-prototype geometry",
        quality_score=1.0,
    )
    writer.add_triplet(
        trigger="A313:independently_confirmed_W44_prefix",
        mechanism="minimum_rank_across_predeclared_hierarchical_Linf_family",
        outcome="A327:selected_hierarchical_identity",
        confidence=1.0,
        source=A313_RESULT_SHA256,
        quantification=json.dumps(payload["selection"], sort_keys=True),
        evidence=json.dumps(payload["information_boundary"], sort_keys=True),
        domain="independent W44 calibration of hierarchical Linf",
        quality_score=1.0,
    )
    writer.add_triplet(
        trigger="A327:selected_hierarchical_identity",
        mechanism="exact_paired_W45_order_copy_without_A322_or_A325_outcome",
        outcome=terminal,
        confidence=1.0,
        source=payload["order_commitment_sha256"],
        quantification=json.dumps(
            {
                "selected_operator": payload["selection"]["selected_operator"],
                "selected_W45_order_uint16be_sha256": payload["selection"][
                    "selected_W45_order_uint16be_sha256"
                ],
                "prefix_cells": CELLS,
            },
            sort_keys=True,
        ),
        evidence=payload["evidence_stage"],
        domain="prospective hierarchical ChaCha20 prefix-order deployment",
        quality_score=1.0,
    )
    writer.add_triplet(
        trigger="A313:independently_confirmed_W44_prefix",
        mechanism="materialized_hierarchical_selection_and_cross_width_deployment_chain",
        outcome=terminal,
        confidence=1.0,
        source="materialized:A327_hierarchical_Linf_chain",
        quantification="exact retained closure",
        evidence=payload["evidence_stage"],
        domain="AI-native retained inference",
        quality_score=1.0,
        is_inferred=True,
    )
    writer.add_cluster(
        name="A327 hierarchical Linf deployment order",
        entities=[
            "A317:raw_nearest_prototype_Linf",
            "A327:four_exact_hierarchical_W44_W45_order_pairs",
            "A327:selected_hierarchical_identity",
            terminal,
        ],
    )
    writer.add_gap(
        subject=terminal,
        predicate="next_required_object",
        expected_object_type="fresh_W46_hierarchical_Linf_rank_comparison_without_duplicate_search",
        confidence=1.0,
        suggested_queries=[
            "After independent W46 confirmation, does the frozen hierarchical Linf refinement rank the target earlier than original Linf?"
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
        reader.api_id != "a327linf"
        or len(explicit) != 3
        or len(all_rows) != 4
        or len(inferred) != 1
        or len(reader._rules) != 3
        or len(reader._clusters) != 1
        or len(reader._gaps) != 1
    ):
        raise RuntimeError("A327 authentic Causal reopen gate failed")
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
        raise FileExistsError("A327 artifacts already exist")
    if A322_RESULT.exists():
        raise RuntimeError("A327 must freeze before any A322 result exists")
    if A325_PROGRESS.exists() or A325_RESULT.exists():
        raise RuntimeError("A327 must freeze before any A325 execution or result exists")
    built = build_candidates()
    selection = select_on_a313(built["candidates"])
    payload: dict[str, Any] = {
        "schema": "chacha20-round20-hierarchical-linf-operator-a327-order-v1",
        "attempt_id": ATTEMPT_ID,
        "evidence_stage": "INDEPENDENT_W44_SELECTED_HIERARCHICAL_LINF_W45_ORDER_RETAINED",
        "design_sha256": DESIGN_SHA256,
        "prototype_coordinates_one_based": [list(row) for row in A317.PROTOTYPES],
        "candidate_orders": built["candidates"],
        "selection": selection,
        "W44_primary_linf_plateaus": built["W44_primary_linf_plateaus"],
        "W45_primary_linf_plateaus": built["W45_primary_linf_plateaus"],
        "information_boundary": built["design"]["information_boundary"],
        "anchors": {
            "design": anchor(DESIGN, DESIGN_SHA256),
            "A313_result": anchor(A313_RESULT, A313_RESULT_SHA256),
            "A317_order": anchor(A317_ORDER, A317_ORDER_SHA256),
            "A318_order": anchor(A318_ORDER, A318_ORDER_SHA256),
            "A321_order": anchor(A321_ORDER, A321_ORDER_SHA256),
            "runner": anchor(Path(__file__)),
            "test": anchor(A327_TEST),
            "reproducer": anchor(A327_REPRO),
        },
    }
    payload["order_commitment_sha256"] = canonical_sha256(
        {
            "prototype_coordinates_one_based": payload[
                "prototype_coordinates_one_based"
            ],
            "candidate_order_hashes": {
                name: {
                    "W44": payload["candidate_orders"][name][
                        "W44_order_uint16be_sha256"
                    ],
                    "W45": payload["candidate_orders"][name][
                        "W45_order_uint16be_sha256"
                    ],
                }
                for name in CANDIDATE_NAMES
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
            "W44_primary_linf_plateaus": payload["W44_primary_linf_plateaus"],
            "W45_primary_linf_plateaus": payload["W45_primary_linf_plateaus"],
            "cross_width_spearman": {
                name: payload["candidate_orders"][name]["cross_width_spearman"]
                for name in CANDIDATE_NAMES
            },
        }
    )
    payload["causal"] = build_causal(payload)
    atomic_json(ORDER, payload)
    atomic_bytes(
        REPORT,
        (
            "# A327 — hierarchical Linf operator refinement\n\n"
            f"- Selected operator: **{selection['selected_operator']}**\n"
            f"- Independent A313 calibration rank: **{selection['selected_calibration_rank_one_based']} / 4,096**\n"
            f"- Selected W45 order SHA: **{selection['selected_W45_order_uint16be_sha256']}**\n"
            f"- W44 cells in tied primary Linf plateaus: **{built['W44_primary_linf_plateaus']['cells_in_tied_primary_plateaus']:,} / 4,096**\n"
            f"- W45 cells in tied primary Linf plateaus: **{built['W45_primary_linf_plateaus']['cells_in_tied_primary_plateaus']:,} / 4,096**\n"
            "- A322/A325 labels, progress-driven tuning and candidate executions: **zero**\n"
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
                "selected_operator": payload["selection"]["selected_operator"],
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

#!/usr/bin/env python3
"""A334: walk-forward select a temporal-structural W46 ensemble order."""

from __future__ import annotations

import argparse
import hashlib
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

DESIGN = CONFIGS / "chacha20_round20_walk_forward_structural_ensemble_a334_design_v1.json"
ORDER = RESULTS / "chacha20_round20_walk_forward_structural_ensemble_a334_order_v1.json"
CAUSAL = RESULTS / "chacha20_round20_walk_forward_structural_ensemble_a334_order_v1.causal"
REPORT = RESULTS / "chacha20_round20_walk_forward_structural_ensemble_a334_order_v1.md"

A300_ORDER = RESULTS / "chacha20_round20_w43_three_operator_portfolio_a300_order_v1.json"
A317_ORDER = RESULTS / "chacha20_round20_w44_multiview_operator_atlas_a317_order_v1.json"
A317_RUNNER = RESEARCH / "experiments/chacha20_round20_w44_multiview_operator_atlas_a317.py"
A318_ORDER = RESULTS / "chacha20_round20_w45_multiview_operator_atlas_a318_order_v1.json"
A329_ORDER = RESULTS / "chacha20_round20_linf_stability_merge_a329_order_v1.json"
A332_ORDER = RESULTS / "chacha20_round20_margin_consistency_wavefront_a332_order_v1.json"
A333_ORDER = RESULTS / "chacha20_round20_cross_width_rank_velocity_a333_order_v1.json"
A322_RESULT = RESULTS / "chacha20_round20_holdout_selected_w45_recovery_a322_v1.json"
A325_PROGRESS = RESULTS / "chacha20_round20_holdout_selected_w46_recovery_a325_progress_v1.json"
A325_RESULT = RESULTS / "chacha20_round20_holdout_selected_w46_recovery_a325_v1.json"
A334_TEST = ROOT / "tests/test_chacha20_round20_walk_forward_structural_ensemble_a334.py"
A334_REPRO = ROOT / "scripts/reproduce_chacha20_round20_walk_forward_structural_ensemble_a334.sh"

ATTEMPT_ID = "A334"
DESIGN_SHA256 = "6c45c5ca414046e2b43d01be0325c0ca0b6b28344dbc6415be1697023bed0b21"
A300_ORDER_SHA256 = "76af63fd14613520bda54316e242c16e4530af22ddb2ec9e5a7a6e6df5afefd1"
A317_ORDER_SHA256 = "3c3779cb26ace4e4361399969a89461eb69e443e8b4630f953cb0a8892f672a2"
A317_RUNNER_SHA256 = "07aaf434153249ccc12826098bb3de1e8734a37c8649108045e00fb9e7614fa2"
A318_ORDER_SHA256 = "25c36b4412cedcd37243057535109b36e79ded5172eba642bb84dd50f1de49f0"
A329_ORDER_SHA256 = "05d1049a1304a3160ca6e50a667a56ac4ff194fe913d3e570df2e813023b3512"
A332_ORDER_SHA256 = "b6e0a5ca2a819194cde74dacda51ce0ac7b8e7d051e5dc854ad3599b545353ad"
A333_ORDER_SHA256 = "4cd1c0ce67e50df687548d0cf6a5f921ff91767c077d25f39b158a4263de4b5c"
CELLS = 1 << 12
METRIC = "nearest_prototype_Linf"
TEMPORAL = "temporal_midpoint_only"
STABILITY = "current_stability_2_to_1_only"
CONSISTENCY = "current_consistency_borda_only"
TEMPORAL_STABILITY = "temporal_plus_stability_borda"
TEMPORAL_MARGIN = "temporal_plus_margin_consistency_borda"
TEMPORAL_CONSISTENCY = "temporal_plus_consistency_borda"
SWITCHED_CONTROL = "temporal_plus_switched_control_borda"
INCONSISTENCY_CONTROL = "temporal_plus_margin_inconsistency_control_borda"
CANDIDATE_NAMES = (
    TEMPORAL,
    STABILITY,
    CONSISTENCY,
    TEMPORAL_STABILITY,
    TEMPORAL_MARGIN,
    TEMPORAL_CONSISTENCY,
    SWITCHED_CONTROL,
    INCONSISTENCY_CONTROL,
)
ELIGIBLE_NAMES = CANDIDATE_NAMES[:6]
CONTROL_NAMES = CANDIDATE_NAMES[6:]


def load_module(path: Path, name: str) -> Any:
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot import A334 dependency {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


if not A317_RUNNER.exists():
    raise FileNotFoundError(A317_RUNNER)
A317 = load_module(A317_RUNNER, "a334_a317_common")
file_sha256 = A317.file_sha256
canonical_sha256 = A317.canonical_sha256
atomic_json = A317.atomic_json
atomic_bytes = A317.atomic_bytes
relative = A317.relative
path_from_ref = A317.path_from_ref
anchor = A317.anchor
DOTCAUSAL_SRC = A317.DOTCAUSAL_SRC


def exact_order(values: Sequence[int], label: str) -> list[int]:
    order = [int(value) for value in values]
    if len(order) != CELLS or set(order) != set(range(CELLS)):
        raise ValueError(f"A334 {label} is not an exact 4,096-cell cover")
    return order


def rank_vector(order: Sequence[int]) -> list[int]:
    ranks = [0] * CELLS
    for rank, cell in enumerate(exact_order(order, "rank vector"), 1):
        ranks[cell] = rank
    return ranks


def order_sha(order: Sequence[int]) -> str:
    return hashlib.sha256(
        b"".join(cell.to_bytes(2, "big") for cell in exact_order(order, "hash"))
    ).hexdigest()


def spearman(left: Sequence[int], right: Sequence[int]) -> float:
    left_ranks = rank_vector(left)
    right_ranks = rank_vector(right)
    squared = sum((a - b) ** 2 for a, b in zip(left_ranks, right_ranks, strict=True))
    return 1.0 - (6.0 * squared) / (CELLS * (CELLS * CELLS - 1))


def load_design() -> dict[str, Any]:
    if file_sha256(DESIGN) != DESIGN_SHA256:
        raise RuntimeError("A334 design hash differs")
    design = json.loads(DESIGN.read_bytes())
    contract = design.get("forecast_contract", {})
    boundary = design.get("information_boundary", {})
    if (
        design.get("schema") != "chacha20-round20-walk-forward-structural-ensemble-a334-design-v1"
        or design.get("attempt_id") != ATTEMPT_ID
        or design.get("design_state")
        != "frozen_while_A322_is_running_before_any_A322_result_and_before_any_A325_execution_or_result"
        or tuple(contract.get("candidate_sequence", ())) != CANDIDATE_NAMES
        or tuple(contract.get("selection_eligible_sequence", ())) != ELIGIBLE_NAMES
        or tuple(contract.get("fixed_direction_controls", ())) != CONTROL_NAMES
        or contract.get("A313_role") != "none"
        or contract.get("A322_progress_or_result_role") != "none"
        or contract.get("A325_W46_challenge_or_result_role") != "none"
        or contract.get("new_candidate_execution") is not False
        or contract.get("target_labels_used_from_A313_A322_or_A325") != 0
        or boundary.get("training_pair_W43_W44_uses_any_W45_field") is not False
        or boundary.get("deployment_pair_W44_W45_uses_any_W46_challenge_feature") is not False
        or boundary.get("A322_progress_used_for_candidate_definition_selection_or_order")
        is not False
        or boundary.get("A322_result_available_at_design_freeze") is not False
        or boundary.get("A325_execution_started_at_design_freeze") is not False
        or boundary.get("A325_challenge_feature_candidate_prefix_or_result_used") is not False
        or boundary.get("target_labels_used_from_A313_A322_or_A325") != 0
    ):
        raise RuntimeError("A334 frozen design semantics differ")
    for key, value in design["source_anchors"].items():
        if key.endswith("_path"):
            anchor(
                path_from_ref(value),
                design["source_anchors"][key.removesuffix("_path") + "_sha256"],
            )
    return design


def component_fields() -> dict[str, dict[str, list[int]]]:
    if (
        file_sha256(A300_ORDER) != A300_ORDER_SHA256
        or file_sha256(A317_ORDER) != A317_ORDER_SHA256
        or file_sha256(A317_RUNNER) != A317_RUNNER_SHA256
        or file_sha256(A318_ORDER) != A318_ORDER_SHA256
        or file_sha256(A329_ORDER) != A329_ORDER_SHA256
        or file_sha256(A332_ORDER) != A332_ORDER_SHA256
        or file_sha256(A333_ORDER) != A333_ORDER_SHA256
    ):
        raise RuntimeError("A334 source anchor differs")
    a300 = json.loads(A300_ORDER.read_bytes())
    a317 = json.loads(A317_ORDER.read_bytes())
    a318 = json.loads(A318_ORDER.read_bytes())
    raw = {
        "W43": {
            "fine": a300["component_orders"]["A295_fine_selected_channel"],
            "coarse": a300["component_orders"]["A297_coarse_high8_then_reflected_Gray4"],
            "numeric": a300["component_orders"]["numeric_word0_prefix12"],
        },
        "W44": a317["coordinate_source_orders"],
        "W45": a318["coordinate_source_orders"],
    }
    fields: dict[str, dict[str, list[int]]] = {}
    for width, components in raw.items():
        fields[width] = {
            name: exact_order(components[name], f"{width} {name}")
            for name in ("fine", "coarse", "numeric")
        }
    return fields


def prototype_panel(components: Mapping[str, Sequence[int]]) -> dict[str, list[int]]:
    ranks = {name: rank_vector(components[name]) for name in ("fine", "coarse", "numeric")}
    assignment: list[int] = []
    nearest_distance: list[int] = []
    margin: list[int] = []
    for cell in range(CELLS):
        point = (ranks["fine"][cell], ranks["coarse"][cell], ranks["numeric"][cell])
        distances = [
            max(abs(left - right) for left, right in zip(point, prototype, strict=True))
            for prototype in A317.PROTOTYPES
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


def interleave(
    left: Sequence[int], right: Sequence[int], left_quota: int, right_quota: int
) -> list[int]:
    output: list[int] = []
    left_index = 0
    right_index = 0
    while left_index < len(left) and right_index < len(right):
        left_end = min(len(left), left_index + left_quota)
        output.extend(left[left_index:left_end])
        left_index = left_end
        right_end = min(len(right), right_index + right_quota)
        output.extend(right[right_index:right_end])
        right_index = right_end
    output.extend(left[left_index:])
    output.extend(right[right_index:])
    return exact_order(output, "interleave")


def margin_order(scores: Sequence[int], base_order: Sequence[int], *, reverse: bool) -> list[int]:
    base_ranks = rank_vector(base_order)
    if reverse:
        order = sorted(range(CELLS), key=lambda cell: (scores[cell], base_ranks[cell], cell))
    else:
        order = sorted(range(CELLS), key=lambda cell: (-scores[cell], base_ranks[cell], cell))
    return exact_order(order, "margin order")


def borda(left: Sequence[int], right: Sequence[int]) -> list[int]:
    left_ranks = rank_vector(left)
    right_ranks = rank_vector(right)
    order = sorted(
        range(CELLS),
        key=lambda cell: (
            left_ranks[cell] + right_ranks[cell],
            min(left_ranks[cell], right_ranks[cell]),
            max(left_ranks[cell], right_ranks[cell]),
            cell,
        ),
    )
    return exact_order(order, "Borda")


def temporal_midpoint(previous: Sequence[int], current: Sequence[int]) -> list[int]:
    previous_ranks = rank_vector(previous)
    current_ranks = rank_vector(current)
    order = sorted(
        range(CELLS),
        key=lambda cell: (
            previous_ranks[cell] + current_ranks[cell],
            current_ranks[cell],
            previous_ranks[cell],
            cell,
        ),
    )
    return exact_order(order, "temporal midpoint")


def pair_state(
    previous: Mapping[str, Sequence[int]], current: Mapping[str, Sequence[int]]
) -> dict[str, Any]:
    previous_raw = A317.atlas_order(
        fine=previous["fine"],
        coarse=previous["coarse"],
        numeric=previous["numeric"],
        metric=METRIC,
    )
    current_raw = A317.atlas_order(
        fine=current["fine"],
        coarse=current["coarse"],
        numeric=current["numeric"],
        metric=METRIC,
    )
    previous_panel = prototype_panel(previous)
    current_panel = prototype_panel(current)
    stable_mask = [
        left == right
        for left, right in zip(
            previous_panel["assignment"], current_panel["assignment"], strict=True
        )
    ]
    stable = [cell for cell in current_raw if stable_mask[cell]]
    switched = [cell for cell in current_raw if not stable_mask[cell]]
    stability = interleave(stable, switched, 2, 1)
    switched_control = interleave(switched, stable, 2, 1)
    scores = [
        -abs(left - right)
        for left, right in zip(previous_panel["margin"], current_panel["margin"], strict=True)
    ]
    margin_consistency = margin_order(scores, stability, reverse=False)
    margin_inconsistency = margin_order(scores, stability, reverse=True)
    consistency_borda = borda(stability, margin_consistency)
    temporal = temporal_midpoint(previous_raw, current_raw)
    return {
        "previous_raw": previous_raw,
        "current_raw": current_raw,
        "previous_assignment": previous_panel["assignment"],
        "current_assignment": current_panel["assignment"],
        "previous_margin": previous_panel["margin"],
        "current_margin": current_panel["margin"],
        "stable_cells": sum(stable_mask),
        "switched_cells": CELLS - sum(stable_mask),
        "temporal": temporal,
        "stability": stability,
        "switched_control": switched_control,
        "margin_consistency": margin_consistency,
        "margin_inconsistency": margin_inconsistency,
        "consistency_borda": consistency_borda,
    }


def candidate_orders(state: Mapping[str, Sequence[int]]) -> dict[str, list[int]]:
    return {
        TEMPORAL: exact_order(state["temporal"], TEMPORAL),
        STABILITY: exact_order(state["stability"], STABILITY),
        CONSISTENCY: exact_order(state["consistency_borda"], CONSISTENCY),
        TEMPORAL_STABILITY: borda(state["temporal"], state["stability"]),
        TEMPORAL_MARGIN: borda(state["temporal"], state["margin_consistency"]),
        TEMPORAL_CONSISTENCY: borda(state["temporal"], state["consistency_borda"]),
        SWITCHED_CONTROL: borda(state["temporal"], state["switched_control"]),
        INCONSISTENCY_CONTROL: borda(state["temporal"], state["margin_inconsistency"]),
    }


def metrics(order: Sequence[int], target: Sequence[int]) -> dict[str, Any]:
    ranks = rank_vector(order)
    target_ranks = rank_vector(target)
    errors = [abs(a - b) for a, b in zip(ranks, target_ranks, strict=True)]
    return {
        "spearman": spearman(order, target),
        "mean_absolute_rank_error": sum(errors) / CELLS,
        "maximum_absolute_rank_error": max(errors),
        "top_k_overlap": {
            str(limit): len(set(order[:limit]) & set(target[:limit]))
            for limit in (16, 64, 256, 1024)
        },
    }


def pair_summary(state: Mapping[str, Any]) -> dict[str, Any]:
    order_keys = (
        "previous_raw",
        "current_raw",
        "temporal",
        "stability",
        "switched_control",
        "margin_consistency",
        "margin_inconsistency",
        "consistency_borda",
    )
    return {
        "stable_cells": state["stable_cells"],
        "switched_cells": state["switched_cells"],
        "order_uint16be_sha256": {key: order_sha(state[key]) for key in order_keys},
        "previous_assignment_sha256": canonical_sha256(state["previous_assignment"]),
        "current_assignment_sha256": canonical_sha256(state["current_assignment"]),
        "previous_margin_sha256": canonical_sha256(state["previous_margin"]),
        "current_margin_sha256": canonical_sha256(state["current_margin"]),
    }


def deployment_identity_gates(state: Mapping[str, Any]) -> dict[str, Any]:
    a329 = json.loads(A329_ORDER.read_bytes())
    a332 = json.loads(A332_ORDER.read_bytes())
    a333 = json.loads(A333_ORDER.read_bytes())
    expected = {
        "current_raw": a333["source_order_uint16be_sha256"]["W45"],
        "temporal": a333["selected_W46_order_uint16be_sha256"],
        "stability": a329["candidates"]["stable_switched_2_to_1"]["W45_order_uint16be_sha256"],
        "switched_control": a329["candidates"]["switched_stable_2_to_1_control"][
            "W45_order_uint16be_sha256"
        ],
        "margin_consistency": a332["candidates"]["margin_consistency_only"][
            "W45_order_uint16be_sha256"
        ],
        "margin_inconsistency": a332["candidates"]["margin_inconsistency_only_control"][
            "W45_order_uint16be_sha256"
        ],
        "consistency_borda": a332["candidates"]["consistency_borda_rank_sum"][
            "W45_order_uint16be_sha256"
        ],
    }
    observed = {name: order_sha(state[name]) for name in expected}
    gates = {
        name: {
            "observed_sha256": observed[name],
            "expected_sha256": expected[name],
            "match": observed[name] == expected[name],
        }
        for name in expected
    }
    if not all(row["match"] for row in gates.values()):
        raise RuntimeError("A334 deployment identity gate failed")
    return gates


def build_ensemble() -> dict[str, Any]:
    design = load_design()
    fields = component_fields()
    training_state = pair_state(fields["W43"], fields["W44"])
    deployment_state = pair_state(fields["W44"], fields["W45"])
    training_orders = candidate_orders(training_state)
    deployment_orders = candidate_orders(deployment_state)
    target_w45 = deployment_state["current_raw"]
    training = {
        name: {
            "candidate_index": CANDIDATE_NAMES.index(name),
            "selection_eligible": name in ELIGIBLE_NAMES,
            "predicted_W45_order": order,
            "predicted_W45_order_uint16be_sha256": order_sha(order),
            "metrics_against_complete_target_blind_W45_raw_field": metrics(order, target_w45),
        }
        for name, order in training_orders.items()
    }
    selected = max(
        ELIGIBLE_NAMES,
        key=lambda name: (
            training[name]["metrics_against_complete_target_blind_W45_raw_field"]["spearman"],
            -training[name]["metrics_against_complete_target_blind_W45_raw_field"][
                "mean_absolute_rank_error"
            ],
            -ELIGIBLE_NAMES.index(name),
        ),
    )
    deployment = {
        name: {
            "predicted_W46_order": order,
            "predicted_W46_order_uint16be_sha256": order_sha(order),
        }
        for name, order in deployment_orders.items()
    }
    return {
        "design": design,
        "training_pair": training_state,
        "training_pair_summary": pair_summary(training_state),
        "deployment_pair": deployment_state,
        "deployment_pair_summary": pair_summary(deployment_state),
        "deployment_identity_gates": deployment_identity_gates(deployment_state),
        "training": training,
        "deployment": deployment,
        "selected_operator": selected,
        "selected_training_metrics": training[selected][
            "metrics_against_complete_target_blind_W45_raw_field"
        ],
        "selected_W46_order": deployment[selected]["predicted_W46_order"],
        "selected_W46_order_uint16be_sha256": deployment[selected][
            "predicted_W46_order_uint16be_sha256"
        ],
        "target_labels_used_from_A313_A322_or_A325": 0,
        "duplicate_candidate_execution_required_for_evaluation": False,
    }


def compact_training(training: Mapping[str, Mapping[str, Any]]) -> dict[str, Any]:
    return {
        name: {
            "candidate_index": row["candidate_index"],
            "selection_eligible": row["selection_eligible"],
            "predicted_W45_order_uint16be_sha256": row["predicted_W45_order_uint16be_sha256"],
            "metrics_against_complete_target_blind_W45_raw_field": row[
                "metrics_against_complete_target_blind_W45_raw_field"
            ],
        }
        for name, row in training.items()
    }


def compact_deployment(
    deployment: Mapping[str, Mapping[str, Any]],
) -> dict[str, Any]:
    return {
        name: {"predicted_W46_order_uint16be_sha256": row["predicted_W46_order_uint16be_sha256"]}
        for name, row in deployment.items()
    }


def build_causal(payload: Mapping[str, Any]) -> dict[str, Any]:
    sys.path.insert(0, str(DOTCAUSAL_SRC))
    from dotcausal.io import CausalReader, CausalWriter

    terminal = "A334:frozen_walk_forward_selected_structural_W46_order"
    writer = CausalWriter(api_id="a334ensm")
    writer._rules = []
    writer.add_rule(
        name="pair_local_fields_to_recapitulated_mechanisms",
        description="Each adjacent-width pair independently rebuilds temporal midpoint, stability merge, margin consistency, Borda fusions and reversed-direction controls from that pair alone.",
        pattern=["adjacent_exact_Fine_Coarse_Numeric_fields", "A329_A333_fixed_mechanisms"],
        conclusion="A334_pair_local_structural_family",
        confidence_modifier=1.0,
    )
    writer.add_rule(
        name="W43_W44_family_to_clean_W45_selection",
        description="Candidate W45 forecasts are fully constructed without W45 fields, then scored against the complete target-blind W45 raw field under the frozen eligible-only rule.",
        pattern=["A334_W43_W44_candidate_family", "complete_target_blind_W45_raw_field"],
        conclusion="A334_walk_forward_selected_construction",
        confidence_modifier=1.0,
    )
    writer.add_rule(
        name="selected_construction_to_exact_W46_order",
        description="The selected construction is applied unchanged to the W44-W45 pair and emits an exact W46 order before any A325 execution or target access.",
        pattern=["A334_walk_forward_selected_construction", "A334_W44_W45_pair_state"],
        conclusion=terminal.replace(":", "_"),
        confidence_modifier=1.0,
    )
    writer.add_triplet(
        trigger="A334:pair_local_exact_fields",
        mechanism="recapitulated_temporal_stability_margin_operator_factory",
        outcome="A334:complete_W43_W44_walk_forward_candidate_family",
        confidence=1.0,
        source=payload["measurement_sha256"],
        quantification=json.dumps(
            {
                "training_pair_summary": payload["training_pair_summary"],
                "training_summary": payload["training_summary"],
            },
            sort_keys=True,
        ),
        evidence="TRAINING_CANDIDATES_CONSTRUCTED_WITH_ZERO_W45_FIELDS",
        domain="AI-native walk-forward operator factory",
        quality_score=1.0,
    )
    writer.add_triplet(
        trigger="A334:complete_W43_W44_walk_forward_candidate_family",
        mechanism="eligible_only_complete_W45_spearman_then_rank_error_selection",
        outcome="A334:selected_structural_construction",
        confidence=1.0,
        source=payload["commitment_sha256"],
        quantification=json.dumps(payload["selection"], sort_keys=True),
        evidence="CONTROLS_INELIGIBLE_ZERO_TARGET_PREFIX_LABELS",
        domain="target-blind structural walk-forward selection",
        quality_score=1.0,
    )
    writer.add_triplet(
        trigger="A334:selected_structural_construction",
        mechanism="unchanged_W44_W45_pair_local_deployment",
        outcome=terminal,
        confidence=1.0,
        source=payload["commitment_sha256"],
        quantification=json.dumps(
            {
                "selected_W46_order_uint16be_sha256": payload["selected_W46_order_uint16be_sha256"],
                "deployment_summary": payload["deployment_summary"],
                "identity_gates": payload["deployment_identity_gates"],
            },
            sort_keys=True,
        ),
        evidence=json.dumps(payload["information_boundary"], sort_keys=True),
        domain="prospective W46 structural ensemble commitment",
        quality_score=1.0,
    )
    writer.add_triplet(
        trigger="A334:pair_local_exact_fields",
        mechanism="materialized_walk_forward_structural_ensemble_chain",
        outcome=terminal,
        confidence=1.0,
        source="materialized:A334_structural_ensemble_chain",
        quantification="exact retained closure",
        evidence=payload["evidence_stage"],
        domain="AI-native retained inference",
        quality_score=1.0,
        is_inferred=True,
    )
    writer.add_cluster(
        name="A334 walk-forward structural ensemble",
        entities=[
            "A334:pair_local_exact_fields",
            "A334:complete_W43_W44_walk_forward_candidate_family",
            "A334:selected_structural_construction",
            terminal,
        ],
    )
    writer.add_gap(
        subject=terminal,
        predicate="next_required_object",
        expected_object_type="independently_confirmed_A325_prefix_rank_in_selected_sources_and_direction_controls",
        confidence=1.0,
        suggested_queries=[
            "After the single complete A325 execution, does the selected structural ensemble rank its confirmed prefix ahead of temporal-only, structural-only and both ineligible direction controls?"
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
        reader.api_id != "a334ensm"
        or len(explicit) != 3
        or len(all_rows) != 4
        or len(inferred) != 1
        or len(reader._rules) != 3
        or len(reader._clusters) != 1
        or len(reader._gaps) != 1
    ):
        raise RuntimeError("A334 authentic Causal reopen gate failed")
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
        raise FileExistsError("A334 artifacts already exist")
    if A322_RESULT.exists():
        raise RuntimeError("A334 must freeze before any A322 result exists")
    if A325_PROGRESS.exists() or A325_RESULT.exists():
        raise RuntimeError("A334 must freeze before any A325 execution or result exists")
    built = build_ensemble()
    training_summary = compact_training(built["training"])
    deployment_summary = compact_deployment(built["deployment"])
    selection = {
        "selected_operator": built["selected_operator"],
        "selected_training_metrics": built["selected_training_metrics"],
        "selection_eligible_sequence": list(ELIGIBLE_NAMES),
        "fixed_ineligible_direction_controls": list(CONTROL_NAMES),
        "selection_rule": "maximum W45 structural Spearman then minimum mean absolute rank error then frozen eligible index",
        "target_prefix_labels_used": 0,
    }
    payload: dict[str, Any] = {
        "schema": "chacha20-round20-walk-forward-structural-ensemble-a334-order-v1",
        "attempt_id": ATTEMPT_ID,
        "evidence_stage": "PROSPECTIVE_PAIR_LOCAL_WALK_FORWARD_SELECTED_W46_ENSEMBLE_RETAINED",
        "design_sha256": DESIGN_SHA256,
        "candidate_sequence": list(CANDIDATE_NAMES),
        "training_pair_summary": built["training_pair_summary"],
        "deployment_pair_summary": built["deployment_pair_summary"],
        "deployment_identity_gates": built["deployment_identity_gates"],
        "training": built["training"],
        "training_summary": training_summary,
        "deployment": built["deployment"],
        "deployment_summary": deployment_summary,
        "selection": selection,
        "selected_W46_order": built["selected_W46_order"],
        "selected_W46_order_uint16be_sha256": built["selected_W46_order_uint16be_sha256"],
        "information_boundary": built["design"]["information_boundary"],
        "future_evaluation_contract": {
            "A325": "rank the independently confirmed prefix in all eight frozen W46 orders after the single complete A325 execution",
            "duplicate_candidate_execution_required": False,
            "counterfactual_control_outcome_inference": False,
        },
        "anchors": {
            "design": anchor(DESIGN, DESIGN_SHA256),
            "A300_order": anchor(A300_ORDER, A300_ORDER_SHA256),
            "A317_order": anchor(A317_ORDER, A317_ORDER_SHA256),
            "A317_runner": anchor(A317_RUNNER, A317_RUNNER_SHA256),
            "A318_order": anchor(A318_ORDER, A318_ORDER_SHA256),
            "A329_order": anchor(A329_ORDER, A329_ORDER_SHA256),
            "A332_order": anchor(A332_ORDER, A332_ORDER_SHA256),
            "A333_order": anchor(A333_ORDER, A333_ORDER_SHA256),
            "runner": anchor(Path(__file__)),
            "test": anchor(A334_TEST),
            "reproducer": anchor(A334_REPRO),
        },
    }
    payload["commitment_sha256"] = canonical_sha256(
        {
            "design_sha256": DESIGN_SHA256,
            "training_pair_summary": payload["training_pair_summary"],
            "deployment_pair_summary": payload["deployment_pair_summary"],
            "deployment_identity_gates": payload["deployment_identity_gates"],
            "training_summary": training_summary,
            "deployment_summary": deployment_summary,
            "selection": selection,
            "selected_W46_order": payload["selected_W46_order"],
            "information_boundary": payload["information_boundary"],
        }
    )
    payload["measurement_sha256"] = canonical_sha256(
        {
            "training_pair_summary": payload["training_pair_summary"],
            "deployment_pair_summary": payload["deployment_pair_summary"],
            "training_summary": training_summary,
            "selection": selection,
            "information_boundary": payload["information_boundary"],
        }
    )
    payload["causal"] = build_causal(payload)
    atomic_json(ORDER, payload)
    selected = selection["selected_training_metrics"]
    temporal = training_summary[TEMPORAL]["metrics_against_complete_target_blind_W45_raw_field"]
    switched = training_summary[SWITCHED_CONTROL][
        "metrics_against_complete_target_blind_W45_raw_field"
    ]
    atomic_bytes(
        REPORT,
        (
            "# A334 — walk-forward temporal-structural W46 ensemble\n\n"
            f"- Selected construction: **{selection['selected_operator']}**\n"
            f"- Walk-forward W45 Spearman, selected / temporal-only / switched control: **{selected['spearman']:.8f} / {temporal['spearman']:.8f} / {switched['spearman']:.8f}**\n"
            f"- Selected W46 order SHA: **`{payload['selected_W46_order_uint16be_sha256']}`**\n"
            "- Deployment identity gates against A329/A332/A333: **7/7 exact**\n"
            "- A313/A322/A325 target labels, refits and duplicate executions: **zero**\n"
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
                "selection": payload["selection"],
                "selected_W46_order_uint16be_sha256": payload["selected_W46_order_uint16be_sha256"],
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

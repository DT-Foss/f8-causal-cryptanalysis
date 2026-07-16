#!/usr/bin/env python3
"""A333: select a cross-width rank-velocity forecast and freeze W46 orders."""

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
from fractions import Fraction
from pathlib import Path
from typing import Any

ROOT = Path(__file__).parents[2]
RESEARCH = ROOT / "research"
CONFIGS = RESEARCH / "configs"
RESULTS = RESEARCH / "results/v1"

DESIGN = CONFIGS / "chacha20_round20_cross_width_rank_velocity_a333_design_v1.json"
ORDER = RESULTS / "chacha20_round20_cross_width_rank_velocity_a333_order_v1.json"
CAUSAL = RESULTS / "chacha20_round20_cross_width_rank_velocity_a333_order_v1.causal"
REPORT = RESULTS / "chacha20_round20_cross_width_rank_velocity_a333_order_v1.md"

A300_ORDER = RESULTS / "chacha20_round20_w43_three_operator_portfolio_a300_order_v1.json"
A317_ORDER = RESULTS / "chacha20_round20_w44_multiview_operator_atlas_a317_order_v1.json"
A317_RUNNER = RESEARCH / "experiments/chacha20_round20_w44_multiview_operator_atlas_a317.py"
A327_ORDER = RESULTS / "chacha20_round20_hierarchical_linf_operator_a327_order_v1.json"
A322_RESULT = RESULTS / "chacha20_round20_holdout_selected_w45_recovery_a322_v1.json"
A325_PROGRESS = RESULTS / "chacha20_round20_holdout_selected_w46_recovery_a325_progress_v1.json"
A325_RESULT = RESULTS / "chacha20_round20_holdout_selected_w46_recovery_a325_v1.json"
A333_TEST = ROOT / "tests/test_chacha20_round20_cross_width_rank_velocity_a333.py"
A333_REPRO = ROOT / "scripts/reproduce_chacha20_round20_cross_width_rank_velocity_a333.sh"

ATTEMPT_ID = "A333"
DESIGN_SHA256 = "5bbe77840fe625fe4c56e0342b72f0ce11f94553a7364487bc2a1777da7f5aff"
A300_ORDER_SHA256 = "76af63fd14613520bda54316e242c16e4530af22ddb2ec9e5a7a6e6df5afefd1"
A317_ORDER_SHA256 = "3c3779cb26ace4e4361399969a89461eb69e443e8b4630f953cb0a8892f672a2"
A317_RUNNER_SHA256 = "07aaf434153249ccc12826098bb3de1e8734a37c8649108045e00fb9e7614fa2"
A327_ORDER_SHA256 = "7c077a4e8eeb3ab83c4fae931f94882c87369cedb18bd19b2766e04e9b72c90f"
CELLS = 1 << 12
METRIC = "nearest_prototype_Linf"
BASELINE = "carry_forward_alpha_0"
CONTROL = "reverse_velocity_alpha_minus_1"
COEFFICIENTS = (
    ("reverse_velocity_alpha_minus_1", -1, 1),
    ("midpoint_alpha_minus_1_over_2", -1, 2),
    ("carry_forward_alpha_0", 0, 1),
    ("damped_velocity_alpha_1_over_4", 1, 4),
    ("damped_velocity_alpha_1_over_2", 1, 2),
    ("linear_velocity_alpha_1", 1, 1),
    ("aggressive_velocity_alpha_2", 2, 1),
)


def load_module(path: Path, name: str) -> Any:
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot import A333 dependency {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


if not A317_RUNNER.exists():
    raise FileNotFoundError(A317_RUNNER)
A317 = load_module(A317_RUNNER, "a333_a317_common")
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
        raise ValueError(f"A333 {label} is not an exact 4,096-cell cover")
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
        raise RuntimeError("A333 design hash differs")
    design = json.loads(DESIGN.read_bytes())
    contract = design.get("forecast_contract", {})
    boundary = design.get("information_boundary", {})
    observed = tuple(
        (str(name), int(p), int(q))
        for name, p, q in contract.get("candidate_sequence_and_coefficients_p_over_q", ())
    )
    if (
        design.get("schema") != "chacha20-round20-cross-width-rank-velocity-a333-design-v1"
        or design.get("attempt_id") != ATTEMPT_ID
        or design.get("design_state")
        != "frozen_while_A322_is_running_before_any_A322_result_and_before_any_A325_execution_or_result"
        or observed != COEFFICIENTS
        or contract.get("fixed_baseline") != BASELINE
        or contract.get("fixed_direction_control") != CONTROL
        or contract.get("A313_role") != "none"
        or contract.get("A322_progress_or_result_role") != "none"
        or contract.get("A325_W46_challenge_or_result_role") != "none"
        or contract.get("new_candidate_execution") is not False
        or contract.get("target_labels_used_from_A313_A322_or_A325") != 0
        or boundary.get("A313_result_candidate_or_prefix_used") is not False
        or boundary.get("A322_progress_used_for_candidate_definition_selection_or_order")
        is not False
        or boundary.get("A322_result_available_at_design_freeze") is not False
        or boundary.get("A325_execution_started_at_design_freeze") is not False
        or boundary.get("A325_challenge_feature_candidate_prefix_or_result_used") is not False
        or boundary.get("target_labels_used_from_A313_A322_or_A325") != 0
    ):
        raise RuntimeError("A333 frozen design semantics differ")
    for key, value in design["source_anchors"].items():
        if key.endswith("_path"):
            anchor(
                path_from_ref(value),
                design["source_anchors"][key.removesuffix("_path") + "_sha256"],
            )
    return design


def source_fields() -> dict[str, list[int]]:
    if (
        file_sha256(A300_ORDER) != A300_ORDER_SHA256
        or file_sha256(A317_ORDER) != A317_ORDER_SHA256
        or file_sha256(A317_RUNNER) != A317_RUNNER_SHA256
        or file_sha256(A327_ORDER) != A327_ORDER_SHA256
    ):
        raise RuntimeError("A333 source anchor differs")
    a300 = json.loads(A300_ORDER.read_bytes())
    components = a300["component_orders"]
    for name, expected in a300["component_order_sha256"].items():
        if order_sha(components[name]) != expected:
            raise RuntimeError(f"A333 A300 component hash differs: {name}")
    w43 = A317.atlas_order(
        fine=components["A295_fine_selected_channel"],
        coarse=components["A297_coarse_high8_then_reflected_Gray4"],
        numeric=components["numeric_word0_prefix12"],
        metric=METRIC,
    )
    a317 = json.loads(A317_ORDER.read_bytes())
    w44 = exact_order(a317["atlas_orders"][METRIC], "W44 Linf")
    if order_sha(w44) != a317["order_uint16be_sha256"][METRIC]:
        raise RuntimeError("A333 W44 Linf hash differs")
    a327 = json.loads(A327_ORDER.read_bytes())
    w45_row = a327["candidate_orders"]["original_linf"]
    w45 = exact_order(w45_row["W45_order"], "W45 Linf")
    if order_sha(w45) != w45_row["W45_order_uint16be_sha256"]:
        raise RuntimeError("A333 W45 Linf hash differs")
    return {"W43": w43, "W44": w44, "W45": w45}


def forecast_order(previous: Sequence[int], current: Sequence[int], p: int, q: int) -> list[int]:
    if q <= 0 or math.gcd(p, q) != 1:
        raise ValueError("A333 coefficient must be a reduced fraction with positive q")
    previous_ranks = rank_vector(previous)
    current_ranks = rank_vector(current)
    order = sorted(
        range(CELLS),
        key=lambda cell: (
            q * current_ranks[cell] + p * (current_ranks[cell] - previous_ranks[cell]),
            current_ranks[cell],
            previous_ranks[cell],
            cell,
        ),
    )
    return exact_order(order, f"forecast {p}/{q}")


def forecast_metrics(forecast: Sequence[int], target: Sequence[int]) -> dict[str, Any]:
    forecast_ranks = rank_vector(forecast)
    target_ranks = rank_vector(target)
    absolute_errors = [
        abs(left - right) for left, right in zip(forecast_ranks, target_ranks, strict=True)
    ]
    return {
        "spearman": spearman(forecast, target),
        "mean_absolute_rank_error": sum(absolute_errors) / CELLS,
        "maximum_absolute_rank_error": max(absolute_errors),
        "top_k_overlap": {
            str(limit): len(set(forecast[:limit]) & set(target[:limit]))
            for limit in (16, 64, 256, 1024)
        },
    }


def build_forecast() -> dict[str, Any]:
    design = load_design()
    fields = source_fields()
    training: dict[str, Any] = {}
    deployments: dict[str, Any] = {}
    for index, (name, p, q) in enumerate(COEFFICIENTS):
        predicted_w45 = forecast_order(fields["W43"], fields["W44"], p, q)
        predicted_w46 = forecast_order(fields["W44"], fields["W45"], p, q)
        training[name] = {
            "candidate_index": index,
            "coefficient_p": p,
            "coefficient_q": q,
            "coefficient": float(Fraction(p, q)),
            "predicted_W45_order": predicted_w45,
            "predicted_W45_order_uint16be_sha256": order_sha(predicted_w45),
            "metrics_against_complete_target_blind_W45_field": forecast_metrics(
                predicted_w45, fields["W45"]
            ),
        }
        deployments[name] = {
            "coefficient_p": p,
            "coefficient_q": q,
            "predicted_W46_order": predicted_w46,
            "predicted_W46_order_uint16be_sha256": order_sha(predicted_w46),
        }
    selected = max(
        COEFFICIENTS,
        key=lambda row: (
            training[row[0]]["metrics_against_complete_target_blind_W45_field"]["spearman"],
            -abs(Fraction(row[1], row[2])),
            -training[row[0]]["candidate_index"],
        ),
    )[0]
    return {
        "design": design,
        "source_fields": fields,
        "source_order_uint16be_sha256": {
            width: order_sha(order) for width, order in fields.items()
        },
        "training": training,
        "deployments": deployments,
        "selected_operator": selected,
        "selected_coefficient_p": training[selected]["coefficient_p"],
        "selected_coefficient_q": training[selected]["coefficient_q"],
        "selected_training_metrics": training[selected][
            "metrics_against_complete_target_blind_W45_field"
        ],
        "selected_W46_order": deployments[selected]["predicted_W46_order"],
        "selected_W46_order_uint16be_sha256": deployments[selected][
            "predicted_W46_order_uint16be_sha256"
        ],
        "baseline_training_metrics": training[BASELINE][
            "metrics_against_complete_target_blind_W45_field"
        ],
        "control_training_metrics": training[CONTROL][
            "metrics_against_complete_target_blind_W45_field"
        ],
        "target_labels_used_from_A313_A322_or_A325": 0,
        "duplicate_candidate_execution_required_for_evaluation": False,
    }


def compact_training(training: Mapping[str, Mapping[str, Any]]) -> dict[str, Any]:
    return {
        name: {
            "candidate_index": row["candidate_index"],
            "coefficient_p": row["coefficient_p"],
            "coefficient_q": row["coefficient_q"],
            "predicted_W45_order_uint16be_sha256": row["predicted_W45_order_uint16be_sha256"],
            "metrics_against_complete_target_blind_W45_field": row[
                "metrics_against_complete_target_blind_W45_field"
            ],
        }
        for name, row in training.items()
    }


def compact_deployments(
    deployments: Mapping[str, Mapping[str, Any]],
) -> dict[str, Any]:
    return {
        name: {
            "coefficient_p": row["coefficient_p"],
            "coefficient_q": row["coefficient_q"],
            "predicted_W46_order_uint16be_sha256": row["predicted_W46_order_uint16be_sha256"],
        }
        for name, row in deployments.items()
    }


def build_causal(payload: Mapping[str, Any]) -> dict[str, Any]:
    sys.path.insert(0, str(DOTCAUSAL_SRC))
    from dotcausal.io import CausalReader, CausalWriter

    terminal = "A333:frozen_walk_forward_selected_W46_order"
    writer = CausalWriter(api_id="a333velo")
    writer._rules = []
    writer.add_rule(
        name="three_exact_width_fields_to_velocity_panel",
        description="The same frozen rational rank-velocity family is applied to exact W43-W44 and W44-W45 Linf fields with deterministic ties.",
        pattern=["exact_W43_W44_W45_Linf_fields", "A333_frozen_velocity_coefficients"],
        conclusion="A333_walk_forward_forecast_panel",
        confidence_modifier=1.0,
    )
    writer.add_rule(
        name="complete_W45_structural_target_to_selected_coefficient",
        description="Complete target-blind W45 Spearman selects one coefficient by the frozen tie-break without using any recovered target prefix.",
        pattern=["A333_walk_forward_forecast_panel", "complete_target_blind_W45_field"],
        conclusion="A333_selected_velocity_coefficient",
        confidence_modifier=1.0,
    )
    writer.add_rule(
        name="selected_coefficient_to_W46_order",
        description="The unchanged selected coefficient maps W44-W45 ranks into an exact W46 order before A325 execution or candidate access.",
        pattern=["A333_selected_velocity_coefficient", "exact_W44_W45_Linf_fields"],
        conclusion=terminal.replace(":", "_"),
        confidence_modifier=1.0,
    )
    writer.add_triplet(
        trigger="A333:exact_W43_W44_W45_Linf_fields",
        mechanism="seven_frozen_rational_rank_velocity_forecasts",
        outcome="A333:complete_walk_forward_W45_forecast_panel",
        confidence=1.0,
        source=payload["measurement_sha256"],
        quantification=json.dumps(payload["training_summary"], sort_keys=True),
        evidence="COMPLETE_4096_CELL_TARGET_BLIND_STRUCTURAL_FORECASTS",
        domain="AI-native cross-width rank dynamics",
        quality_score=1.0,
    )
    writer.add_triplet(
        trigger="A333:complete_walk_forward_W45_forecast_panel",
        mechanism="maximum_spearman_then_minimum_absolute_coefficient_then_frozen_index",
        outcome="A333:selected_velocity_coefficient",
        confidence=1.0,
        source=payload["commitment_sha256"],
        quantification=json.dumps(payload["selection"], sort_keys=True),
        evidence="ZERO_A313_A322_A325_TARGET_LABELS",
        domain="target-blind walk-forward selection",
        quality_score=1.0,
    )
    writer.add_triplet(
        trigger="A333:selected_velocity_coefficient",
        mechanism="unchanged_W44_W45_rank_velocity_deployment",
        outcome=terminal,
        confidence=1.0,
        source=payload["commitment_sha256"],
        quantification=json.dumps(
            {
                "selected_W46_order_uint16be_sha256": payload["selected_W46_order_uint16be_sha256"],
                "deployment_summary": payload["deployment_summary"],
            },
            sort_keys=True,
        ),
        evidence=json.dumps(payload["information_boundary"], sort_keys=True),
        domain="prospective W46 order commitment",
        quality_score=1.0,
    )
    writer.add_triplet(
        trigger="A333:exact_W43_W44_W45_Linf_fields",
        mechanism="materialized_walk_forward_velocity_chain",
        outcome=terminal,
        confidence=1.0,
        source="materialized:A333_rank_velocity_chain",
        quantification="exact retained closure",
        evidence=payload["evidence_stage"],
        domain="AI-native retained inference",
        quality_score=1.0,
        is_inferred=True,
    )
    writer.add_cluster(
        name="A333 cross-width rank velocity",
        entities=[
            "A333:exact_W43_W44_W45_Linf_fields",
            "A333:complete_walk_forward_W45_forecast_panel",
            "A333:selected_velocity_coefficient",
            terminal,
        ],
    )
    writer.add_gap(
        subject=terminal,
        predicate="next_required_object",
        expected_object_type="independently_confirmed_A325_prefix_rank_in_selected_baseline_and_control_W46_orders",
        confidence=1.0,
        suggested_queries=[
            "After the single complete A325 execution, where does its confirmed prefix rank in the frozen selected velocity order, carry-forward baseline and reverse-velocity control?"
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
        reader.api_id != "a333velo"
        or len(explicit) != 3
        or len(all_rows) != 4
        or len(inferred) != 1
        or len(reader._rules) != 3
        or len(reader._clusters) != 1
        or len(reader._gaps) != 1
    ):
        raise RuntimeError("A333 authentic Causal reopen gate failed")
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
        raise FileExistsError("A333 artifacts already exist")
    if A322_RESULT.exists():
        raise RuntimeError("A333 must freeze before any A322 result exists")
    if A325_PROGRESS.exists() or A325_RESULT.exists():
        raise RuntimeError("A333 must freeze before any A325 execution or result exists")
    built = build_forecast()
    training_summary = compact_training(built["training"])
    deployment_summary = compact_deployments(built["deployments"])
    selection = {
        "selected_operator": built["selected_operator"],
        "selected_coefficient_p": built["selected_coefficient_p"],
        "selected_coefficient_q": built["selected_coefficient_q"],
        "selected_training_metrics": built["selected_training_metrics"],
        "fixed_baseline": BASELINE,
        "baseline_training_metrics": built["baseline_training_metrics"],
        "fixed_direction_control": CONTROL,
        "control_training_metrics": built["control_training_metrics"],
        "selection_rule": "maximum W45 structural Spearman then minimum absolute alpha then frozen candidate index",
        "target_prefix_labels_used": 0,
    }
    payload: dict[str, Any] = {
        "schema": "chacha20-round20-cross-width-rank-velocity-a333-order-v1",
        "attempt_id": ATTEMPT_ID,
        "evidence_stage": "PROSPECTIVE_TARGET_BLIND_WALK_FORWARD_SELECTED_W46_ORDER_RETAINED",
        "design_sha256": DESIGN_SHA256,
        "source_order_uint16be_sha256": built["source_order_uint16be_sha256"],
        "candidate_sequence_and_coefficients_p_over_q": [list(row) for row in COEFFICIENTS],
        "training": built["training"],
        "training_summary": training_summary,
        "deployments": built["deployments"],
        "deployment_summary": deployment_summary,
        "selection": selection,
        "selected_W46_order": built["selected_W46_order"],
        "selected_W46_order_uint16be_sha256": built["selected_W46_order_uint16be_sha256"],
        "information_boundary": built["design"]["information_boundary"],
        "future_evaluation_contract": {
            "A325": "rank the independently confirmed prefix in all seven frozen W46 orders after the single complete A325 execution",
            "duplicate_candidate_execution_required": False,
            "counterfactual_control_outcome_inference": False,
        },
        "anchors": {
            "design": anchor(DESIGN, DESIGN_SHA256),
            "A300_order": anchor(A300_ORDER, A300_ORDER_SHA256),
            "A317_order": anchor(A317_ORDER, A317_ORDER_SHA256),
            "A317_runner": anchor(A317_RUNNER, A317_RUNNER_SHA256),
            "A327_order": anchor(A327_ORDER, A327_ORDER_SHA256),
            "runner": anchor(Path(__file__)),
            "test": anchor(A333_TEST),
            "reproducer": anchor(A333_REPRO),
        },
    }
    payload["commitment_sha256"] = canonical_sha256(
        {
            "design_sha256": DESIGN_SHA256,
            "source_order_uint16be_sha256": payload["source_order_uint16be_sha256"],
            "training_summary": training_summary,
            "deployment_summary": deployment_summary,
            "selection": selection,
            "selected_W46_order": payload["selected_W46_order"],
            "information_boundary": payload["information_boundary"],
        }
    )
    payload["measurement_sha256"] = canonical_sha256(
        {
            "source_order_uint16be_sha256": payload["source_order_uint16be_sha256"],
            "training_summary": training_summary,
            "selection": selection,
            "information_boundary": payload["information_boundary"],
        }
    )
    payload["causal"] = build_causal(payload)
    atomic_json(ORDER, payload)
    baseline_rho = selection["baseline_training_metrics"]["spearman"]
    selected_rho = selection["selected_training_metrics"]["spearman"]
    control_rho = selection["control_training_metrics"]["spearman"]
    atomic_bytes(
        REPORT,
        (
            "# A333 — cross-width rank-velocity walk-forward forecast\n\n"
            f"- Selected coefficient: **{selection['selected_operator']}** = **{selection['selected_coefficient_p']}/{selection['selected_coefficient_q']}**\n"
            f"- Walk-forward W45 Spearman, selected / carry-forward / reverse control: **{selected_rho:.8f} / {baseline_rho:.8f} / {control_rho:.8f}**\n"
            f"- Frozen selected W46 order SHA: **`{payload['selected_W46_order_uint16be_sha256']}`**\n"
            "- Source and deployment covers: **exact 4,096-cell permutations**\n"
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

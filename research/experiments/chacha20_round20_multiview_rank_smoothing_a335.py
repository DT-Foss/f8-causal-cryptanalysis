#!/usr/bin/env python3
"""A335: select cross-width rank smoothing across six exact views."""

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

DESIGN = CONFIGS / "chacha20_round20_multiview_rank_smoothing_a335_design_v1.json"
ORDER = RESULTS / "chacha20_round20_multiview_rank_smoothing_a335_order_v1.json"
CAUSAL = RESULTS / "chacha20_round20_multiview_rank_smoothing_a335_order_v1.causal"
REPORT = RESULTS / "chacha20_round20_multiview_rank_smoothing_a335_order_v1.md"

A300_ORDER = RESULTS / "chacha20_round20_w43_three_operator_portfolio_a300_order_v1.json"
A317_ORDER = RESULTS / "chacha20_round20_w44_multiview_operator_atlas_a317_order_v1.json"
A317_RUNNER = RESEARCH / "experiments/chacha20_round20_w44_multiview_operator_atlas_a317.py"
A318_ORDER = RESULTS / "chacha20_round20_w45_multiview_operator_atlas_a318_order_v1.json"
A333_ORDER = RESULTS / "chacha20_round20_cross_width_rank_velocity_a333_order_v1.json"
A322_RESULT = RESULTS / "chacha20_round20_holdout_selected_w45_recovery_a322_v1.json"
A325_PROGRESS = RESULTS / "chacha20_round20_holdout_selected_w46_recovery_a325_progress_v1.json"
A325_RESULT = RESULTS / "chacha20_round20_holdout_selected_w46_recovery_a325_v1.json"
A335_TEST = ROOT / "tests/test_chacha20_round20_multiview_rank_smoothing_a335.py"
A335_REPRO = ROOT / "scripts/reproduce_chacha20_round20_multiview_rank_smoothing_a335.sh"

ATTEMPT_ID = "A335"
DESIGN_SHA256 = "ab4b1beb25a31ca4cae7a307dc29b2b56ffdc3edffa49672d35fcc4dfd985ff5"
A300_ORDER_SHA256 = "76af63fd14613520bda54316e242c16e4530af22ddb2ec9e5a7a6e6df5afefd1"
A317_ORDER_SHA256 = "3c3779cb26ace4e4361399969a89461eb69e443e8b4630f953cb0a8892f672a2"
A317_RUNNER_SHA256 = "07aaf434153249ccc12826098bb3de1e8734a37c8649108045e00fb9e7614fa2"
A318_ORDER_SHA256 = "25c36b4412cedcd37243057535109b36e79ded5172eba642bb84dd50f1de49f0"
A333_ORDER_SHA256 = "4cd1c0ce67e50df687548d0cf6a5f921ff91767c077d25f39b158a4263de4b5c"
CELLS = 1 << 12
VIEWS = (
    "fine",
    "coarse",
    "numeric",
    "nearest_prototype_L1",
    "nearest_prototype_Linf",
    "nearest_prototype_squared_L2",
)
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
PRIMARY_VIEW = "nearest_prototype_Linf"


def load_module(path: Path, name: str) -> Any:
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot import A335 dependency {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


if not A317_RUNNER.exists():
    raise FileNotFoundError(A317_RUNNER)
A317 = load_module(A317_RUNNER, "a335_a317_common")
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
        raise ValueError(f"A335 {label} is not an exact 4,096-cell cover")
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
        raise RuntimeError("A335 design hash differs")
    design = json.loads(DESIGN.read_bytes())
    contract = design.get("forecast_contract", {})
    boundary = design.get("information_boundary", {})
    observed = tuple(
        (str(name), int(p), int(q))
        for name, p, q in contract.get("candidate_sequence_and_coefficients_p_over_q", ())
    )
    if (
        design.get("schema") != "chacha20-round20-multiview-rank-smoothing-a335-design-v1"
        or design.get("attempt_id") != ATTEMPT_ID
        or design.get("design_state")
        != "frozen_while_A322_is_running_before_any_A322_result_and_before_any_A325_execution_or_result"
        or tuple(contract.get("view_sequence", ())) != VIEWS
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
        raise RuntimeError("A335 frozen design semantics differ")
    for key, value in design["source_anchors"].items():
        if key.endswith("_path"):
            anchor(
                path_from_ref(value),
                design["source_anchors"][key.removesuffix("_path") + "_sha256"],
            )
    return design


def source_views() -> dict[str, dict[str, list[int]]]:
    if (
        file_sha256(A300_ORDER) != A300_ORDER_SHA256
        or file_sha256(A317_ORDER) != A317_ORDER_SHA256
        or file_sha256(A317_RUNNER) != A317_RUNNER_SHA256
        or file_sha256(A318_ORDER) != A318_ORDER_SHA256
        or file_sha256(A333_ORDER) != A333_ORDER_SHA256
    ):
        raise RuntimeError("A335 source anchor differs")
    a300 = json.loads(A300_ORDER.read_bytes())
    a317 = json.loads(A317_ORDER.read_bytes())
    a318 = json.loads(A318_ORDER.read_bytes())
    components = {
        "W43": {
            "fine": a300["component_orders"]["A295_fine_selected_channel"],
            "coarse": a300["component_orders"]["A297_coarse_high8_then_reflected_Gray4"],
            "numeric": a300["component_orders"]["numeric_word0_prefix12"],
        },
        "W44": a317["coordinate_source_orders"],
        "W45": a318["coordinate_source_orders"],
    }
    output: dict[str, dict[str, list[int]]] = {}
    for width, source in components.items():
        views = {name: exact_order(source[name], f"{width} {name}") for name in VIEWS[:3]}
        for metric in VIEWS[3:]:
            views[metric] = A317.atlas_order(
                fine=views["fine"],
                coarse=views["coarse"],
                numeric=views["numeric"],
                metric=metric,
            )
        output[width] = views
    for width, payload in (("W44", a317), ("W45", a318)):
        for view in VIEWS:
            if order_sha(output[width][view]) != payload["order_uint16be_sha256"][view]:
                raise RuntimeError(f"A335 {width} {view} source hash differs")
    return output


def forecast_order(previous: Sequence[int], current: Sequence[int], p: int, q: int) -> list[int]:
    if q <= 0 or math.gcd(p, q) != 1:
        raise ValueError("A335 coefficient must be reduced with positive q")
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


def view_metrics(order: Sequence[int], target: Sequence[int]) -> dict[str, Any]:
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


def build_panel() -> dict[str, Any]:
    design = load_design()
    sources = source_views()
    candidates: dict[str, Any] = {}
    for index, (name, p, q) in enumerate(COEFFICIENTS):
        per_view: dict[str, Any] = {}
        for view in VIEWS:
            forecast = forecast_order(sources["W43"][view], sources["W44"][view], p, q)
            per_view[view] = {
                "predicted_W45_order": forecast,
                "predicted_W45_order_uint16be_sha256": order_sha(forecast),
                "metrics": view_metrics(forecast, sources["W45"][view]),
            }
        rhos = [per_view[view]["metrics"]["spearman"] for view in VIEWS]
        maes = [per_view[view]["metrics"]["mean_absolute_rank_error"] for view in VIEWS]
        candidates[name] = {
            "candidate_index": index,
            "coefficient_p": p,
            "coefficient_q": q,
            "coefficient": float(Fraction(p, q)),
            "per_view": per_view,
            "macro": {
                "mean_spearman": sum(rhos) / len(rhos),
                "minimum_spearman": min(rhos),
                "maximum_spearman": max(rhos),
                "mean_of_view_mean_absolute_rank_errors": sum(maes) / len(maes),
            },
        }
    selected = max(
        COEFFICIENTS,
        key=lambda row: (
            candidates[row[0]]["macro"]["mean_spearman"],
            candidates[row[0]]["macro"]["minimum_spearman"],
            -abs(Fraction(row[1], row[2])),
            -candidates[row[0]]["candidate_index"],
        ),
    )[0]
    p = candidates[selected]["coefficient_p"]
    q = candidates[selected]["coefficient_q"]
    deployment = {
        view: {
            "predicted_W46_order": forecast_order(sources["W44"][view], sources["W45"][view], p, q)
        }
        for view in VIEWS
    }
    for row in deployment.values():
        row["predicted_W46_order_uint16be_sha256"] = order_sha(row["predicted_W46_order"])
    a333 = json.loads(A333_ORDER.read_bytes())
    a333_sha = a333["selected_W46_order_uint16be_sha256"]
    primary_sha = deployment[PRIMARY_VIEW]["predicted_W46_order_uint16be_sha256"]
    return {
        "design": design,
        "source_views": sources,
        "source_order_uint16be_sha256": {
            width: {view: order_sha(order) for view, order in rows.items()}
            for width, rows in sources.items()
        },
        "candidates": candidates,
        "selected_operator": selected,
        "selected_coefficient_p": p,
        "selected_coefficient_q": q,
        "selected_macro": candidates[selected]["macro"],
        "deployment": deployment,
        "primary_view": PRIMARY_VIEW,
        "primary_W46_order": deployment[PRIMARY_VIEW]["predicted_W46_order"],
        "primary_W46_order_uint16be_sha256": primary_sha,
        "A333_selected_W46_order_uint16be_sha256": a333_sha,
        "primary_W46_matches_A333": primary_sha == a333_sha,
        "target_labels_used_from_A313_A322_or_A325": 0,
        "duplicate_candidate_execution_required_for_evaluation": False,
    }


def candidate_summary(candidates: Mapping[str, Mapping[str, Any]]) -> dict[str, Any]:
    return {
        name: {
            "candidate_index": row["candidate_index"],
            "coefficient_p": row["coefficient_p"],
            "coefficient_q": row["coefficient_q"],
            "per_view": {
                view: {
                    "predicted_W45_order_uint16be_sha256": panel[
                        "predicted_W45_order_uint16be_sha256"
                    ],
                    "metrics": panel["metrics"],
                }
                for view, panel in row["per_view"].items()
            },
            "macro": row["macro"],
        }
        for name, row in candidates.items()
    }


def deployment_summary(deployment: Mapping[str, Mapping[str, Any]]) -> dict[str, str]:
    return {view: row["predicted_W46_order_uint16be_sha256"] for view, row in deployment.items()}


def build_causal(payload: Mapping[str, Any]) -> dict[str, Any]:
    sys.path.insert(0, str(DOTCAUSAL_SRC))
    from dotcausal.io import CausalReader, CausalWriter

    terminal = "A335:frozen_multiview_selected_W46_forecasts"
    writer = CausalWriter(api_id="a335mvis")
    writer._rules = []
    writer.add_rule(
        name="six_view_fields_to_42_walk_forward_forecasts",
        description="Seven frozen rational coefficients are applied independently to six exact W43-W44 view pairs and compared with their complete W45 counterparts.",
        pattern=["six_exact_W43_W44_W45_views", "A335_frozen_coefficient_family"],
        conclusion="A335_42_forecast_multiview_panel",
        confidence_modifier=1.0,
    )
    writer.add_rule(
        name="macro_view_panel_to_selected_smoothing",
        description="Macro mean Spearman, minimum-view Spearman, coefficient magnitude and frozen index select one target-prefix-blind smoothing coefficient.",
        pattern=["A335_42_forecast_multiview_panel", "A335_frozen_selection_rule"],
        conclusion="A335_selected_multiview_coefficient",
        confidence_modifier=1.0,
    )
    writer.add_rule(
        name="selected_coefficient_to_six_W46_views",
        description="The unchanged coefficient maps W44-W45 ranks into six exact W46 forecasts; independently selected Linf remains primary.",
        pattern=["A335_selected_multiview_coefficient", "six_exact_W44_W45_views"],
        conclusion=terminal.replace(":", "_"),
        confidence_modifier=1.0,
    )
    writer.add_triplet(
        trigger="A335:six_exact_W43_W44_W45_views",
        mechanism="forty_two_frozen_target_blind_walk_forward_forecasts",
        outcome="A335:complete_multiview_coefficient_panel",
        confidence=1.0,
        source=payload["measurement_sha256"],
        quantification=json.dumps(payload["candidate_summary"], sort_keys=True),
        evidence="SIX_COMPLETE_4096_CELL_VIEW_FOLDS_PER_COEFFICIENT",
        domain="AI-native multiview rank dynamics",
        quality_score=1.0,
    )
    writer.add_triplet(
        trigger="A335:complete_multiview_coefficient_panel",
        mechanism="macro_mean_then_minimum_view_then_coefficient_magnitude_selection",
        outcome="A335:selected_multiview_smoothing_coefficient",
        confidence=1.0,
        source=payload["commitment_sha256"],
        quantification=json.dumps(payload["selection"], sort_keys=True),
        evidence="ZERO_TARGET_PREFIX_LABELS",
        domain="target-blind multiview selection",
        quality_score=1.0,
    )
    writer.add_triplet(
        trigger="A335:selected_multiview_smoothing_coefficient",
        mechanism="unchanged_six_view_W44_W45_deployment",
        outcome=terminal,
        confidence=1.0,
        source=payload["commitment_sha256"],
        quantification=json.dumps(
            {
                "deployment_summary": payload["deployment_summary"],
                "primary_view": payload["primary_view"],
                "primary_W46_order_uint16be_sha256": payload["primary_W46_order_uint16be_sha256"],
                "primary_W46_matches_A333": payload["primary_W46_matches_A333"],
            },
            sort_keys=True,
        ),
        evidence=json.dumps(payload["information_boundary"], sort_keys=True),
        domain="prospective multiview W46 commitment",
        quality_score=1.0,
    )
    writer.add_triplet(
        trigger="A335:six_exact_W43_W44_W45_views",
        mechanism="materialized_multiview_smoothing_chain",
        outcome=terminal,
        confidence=1.0,
        source="materialized:A335_multiview_smoothing_chain",
        quantification="exact retained closure",
        evidence=payload["evidence_stage"],
        domain="AI-native retained inference",
        quality_score=1.0,
        is_inferred=True,
    )
    writer.add_cluster(
        name="A335 multiview rank smoothing",
        entities=[
            "A335:six_exact_W43_W44_W45_views",
            "A335:complete_multiview_coefficient_panel",
            "A335:selected_multiview_smoothing_coefficient",
            terminal,
        ],
    )
    writer.add_gap(
        subject=terminal,
        predicate="next_required_object",
        expected_object_type="independently_confirmed_A325_prefix_multiview_W46_rank_panel",
        confidence=1.0,
        suggested_queries=[
            "After the single complete A325 execution, where does its confirmed prefix rank in each frozen selected-coefficient W46 view?"
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
        reader.api_id != "a335mvis"
        or len(explicit) != 3
        or len(all_rows) != 4
        or len(inferred) != 1
        or len(reader._rules) != 3
        or len(reader._clusters) != 1
        or len(reader._gaps) != 1
    ):
        raise RuntimeError("A335 authentic Causal reopen gate failed")
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
        raise FileExistsError("A335 artifacts already exist")
    if A322_RESULT.exists():
        raise RuntimeError("A335 must freeze before any A322 result exists")
    if A325_PROGRESS.exists() or A325_RESULT.exists():
        raise RuntimeError("A335 must freeze before any A325 execution or result exists")
    built = build_panel()
    summary = candidate_summary(built["candidates"])
    deploy = deployment_summary(built["deployment"])
    selection = {
        "selected_operator": built["selected_operator"],
        "selected_coefficient_p": built["selected_coefficient_p"],
        "selected_coefficient_q": built["selected_coefficient_q"],
        "selected_macro": built["selected_macro"],
        "fixed_baseline": BASELINE,
        "baseline_macro": built["candidates"][BASELINE]["macro"],
        "fixed_direction_control": CONTROL,
        "control_macro": built["candidates"][CONTROL]["macro"],
        "selection_rule": "maximum macro mean Spearman then maximum minimum-view Spearman then minimum absolute alpha then frozen index",
        "target_prefix_labels_used": 0,
    }
    payload: dict[str, Any] = {
        "schema": "chacha20-round20-multiview-rank-smoothing-a335-order-v1",
        "attempt_id": ATTEMPT_ID,
        "evidence_stage": "COMPLETE_MULTIVIEW_WALK_FORWARD_SELECTED_W46_FORECASTS_RETAINED",
        "design_sha256": DESIGN_SHA256,
        "view_sequence": list(VIEWS),
        "candidate_sequence_and_coefficients_p_over_q": [list(row) for row in COEFFICIENTS],
        "source_order_uint16be_sha256": built["source_order_uint16be_sha256"],
        "candidates": built["candidates"],
        "candidate_summary": summary,
        "selection": selection,
        "deployment": built["deployment"],
        "deployment_summary": deploy,
        "primary_view": built["primary_view"],
        "primary_W46_order": built["primary_W46_order"],
        "primary_W46_order_uint16be_sha256": built["primary_W46_order_uint16be_sha256"],
        "A333_selected_W46_order_uint16be_sha256": built["A333_selected_W46_order_uint16be_sha256"],
        "primary_W46_matches_A333": built["primary_W46_matches_A333"],
        "information_boundary": built["design"]["information_boundary"],
        "future_evaluation_contract": {
            "A325": "rank the independently confirmed prefix in all six frozen selected-coefficient W46 view orders after the single complete A325 execution",
            "duplicate_candidate_execution_required": False,
            "counterfactual_control_outcome_inference": False,
        },
        "anchors": {
            "design": anchor(DESIGN, DESIGN_SHA256),
            "A300_order": anchor(A300_ORDER, A300_ORDER_SHA256),
            "A317_order": anchor(A317_ORDER, A317_ORDER_SHA256),
            "A317_runner": anchor(A317_RUNNER, A317_RUNNER_SHA256),
            "A318_order": anchor(A318_ORDER, A318_ORDER_SHA256),
            "A333_order": anchor(A333_ORDER, A333_ORDER_SHA256),
            "runner": anchor(Path(__file__)),
            "test": anchor(A335_TEST),
            "reproducer": anchor(A335_REPRO),
        },
    }
    payload["commitment_sha256"] = canonical_sha256(
        {
            "design_sha256": DESIGN_SHA256,
            "source_order_uint16be_sha256": payload["source_order_uint16be_sha256"],
            "candidate_summary": summary,
            "selection": selection,
            "deployment_summary": deploy,
            "primary_W46_order": payload["primary_W46_order"],
            "information_boundary": payload["information_boundary"],
        }
    )
    payload["measurement_sha256"] = canonical_sha256(
        {
            "source_order_uint16be_sha256": payload["source_order_uint16be_sha256"],
            "candidate_summary": summary,
            "selection": selection,
            "information_boundary": payload["information_boundary"],
        }
    )
    payload["causal"] = build_causal(payload)
    atomic_json(ORDER, payload)
    selected = selection["selected_macro"]
    baseline = selection["baseline_macro"]
    control = selection["control_macro"]
    atomic_bytes(
        REPORT,
        (
            "# A335 — six-view cross-width rank smoothing\n\n"
            f"- Selected coefficient: **{selection['selected_operator']}** = **{selection['selected_coefficient_p']}/{selection['selected_coefficient_q']}**\n"
            f"- Macro mean Spearman, selected / carry-forward / reverse control: **{selected['mean_spearman']:.8f} / {baseline['mean_spearman']:.8f} / {control['mean_spearman']:.8f}**\n"
            f"- Minimum-view Spearman, selected: **{selected['minimum_spearman']:.8f}**\n"
            f"- Primary Linf W46 order SHA: **`{payload['primary_W46_order_uint16be_sha256']}`**\n"
            f"- Primary Linf identity with A333: **{payload['primary_W46_matches_A333']}**\n"
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
                "primary_W46_order_uint16be_sha256": payload["primary_W46_order_uint16be_sha256"],
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

#!/usr/bin/env python3
"""A336: fuse A335 multiview forecasts and freeze a selected W46 order."""

from __future__ import annotations

import argparse
import hashlib
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

DESIGN = CONFIGS / "chacha20_round20_multiview_forecast_fusion_a336_design_v1.json"
ORDER = RESULTS / "chacha20_round20_multiview_forecast_fusion_a336_order_v1.json"
CAUSAL = RESULTS / "chacha20_round20_multiview_forecast_fusion_a336_order_v1.causal"
REPORT = RESULTS / "chacha20_round20_multiview_forecast_fusion_a336_order_v1.md"

A317_ORDER = RESULTS / "chacha20_round20_w44_multiview_operator_atlas_a317_order_v1.json"
A318_ORDER = RESULTS / "chacha20_round20_w45_multiview_operator_atlas_a318_order_v1.json"
A335_ORDER = RESULTS / "chacha20_round20_multiview_rank_smoothing_a335_order_v1.json"
A322_RESULT = RESULTS / "chacha20_round20_holdout_selected_w45_recovery_a322_v1.json"
A325_PROGRESS = RESULTS / "chacha20_round20_holdout_selected_w46_recovery_a325_progress_v1.json"
A325_RESULT = RESULTS / "chacha20_round20_holdout_selected_w46_recovery_a325_v1.json"
A336_TEST = ROOT / "tests/test_chacha20_round20_multiview_forecast_fusion_a336.py"
A336_REPRO = ROOT / "scripts/reproduce_chacha20_round20_multiview_forecast_fusion_a336.sh"

ATTEMPT_ID = "A336"
DESIGN_SHA256 = "dd71b06a2c7e0654ef37515cee6bc27b0e0d6a0ad3999b874e4648c456f39c36"
A317_ORDER_SHA256 = "3c3779cb26ace4e4361399969a89461eb69e443e8b4630f953cb0a8892f672a2"
A318_ORDER_SHA256 = "25c36b4412cedcd37243057535109b36e79ded5172eba642bb84dd50f1de49f0"
A335_ORDER_SHA256 = "80e63e65ca8139e2b893670c093ddfbd7451e6cf1e024b64aff18950b6344f75"
CELLS = 1 << 12
VIEWS = (
    "fine",
    "coarse",
    "numeric",
    "nearest_prototype_L1",
    "nearest_prototype_Linf",
    "nearest_prototype_squared_L2",
)
L1 = "nearest_prototype_L1"
LINF = "nearest_prototype_Linf"
L2 = "nearest_prototype_squared_L2"
MIDPOINT = "midpoint_alpha_minus_1_over_2"
BASELINE = "linf_midpoint_baseline"
L1_LINF = "l1_linf_equal_borda"
LINF_L2 = "linf_l2_equal_borda"
THREE_BORDA = "l1_linf_l2_equal_borda"
THREE_MEDIAN = "l1_linf_l2_rank_median"
ALL_SIX = "all_six_equal_borda"
WEAK_CONTROL = "fine_coarse_equal_borda_control"
CARRY_CONTROL = "W44_raw_linf_carry_forward_control"
CANDIDATE_NAMES = (
    BASELINE,
    L1_LINF,
    LINF_L2,
    THREE_BORDA,
    THREE_MEDIAN,
    ALL_SIX,
    WEAK_CONTROL,
    CARRY_CONTROL,
)
ELIGIBLE_NAMES = CANDIDATE_NAMES[:6]
CONTROL_NAMES = CANDIDATE_NAMES[6:]


sys.path.insert(
    0,
    str(Path("/Users/bhkmie/Documents/Forschung/O1/vendor/fabel/dotcausal_package/src")),
)


def file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def canonical_sha256(value: Any) -> str:
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()


def atomic_json(path: Path, payload: Any) -> None:
    temporary = path.with_name(f".{path.name}.tmp")
    temporary.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n")
    os.replace(temporary, path)


def atomic_bytes(path: Path, payload: bytes) -> None:
    temporary = path.with_name(f".{path.name}.tmp")
    temporary.write_bytes(payload)
    os.replace(temporary, path)


def relative(path: Path) -> str:
    try:
        return str(path.resolve().relative_to(ROOT.resolve()))
    except ValueError:
        return str(path.resolve())


def anchor(path: Path, expected: str | None = None) -> dict[str, str]:
    observed = file_sha256(path)
    if expected is not None and observed != expected:
        raise RuntimeError(f"A336 anchor differs: {path}")
    return {"path": relative(path), "sha256": observed}


def exact_order(values: Sequence[int], label: str) -> list[int]:
    order = [int(value) for value in values]
    if len(order) != CELLS or set(order) != set(range(CELLS)):
        raise ValueError(f"A336 {label} is not an exact 4,096-cell cover")
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
        raise RuntimeError("A336 design hash differs")
    design = json.loads(DESIGN.read_bytes())
    contract = design.get("fusion_contract", {})
    boundary = design.get("information_boundary", {})
    if (
        design.get("schema") != "chacha20-round20-multiview-forecast-fusion-a336-design-v1"
        or design.get("attempt_id") != ATTEMPT_ID
        or design.get("design_state")
        != "frozen_while_A322_is_running_before_any_A322_result_and_before_any_A325_execution_or_result"
        or tuple(contract.get("candidate_sequence", ())) != CANDIDATE_NAMES
        or tuple(contract.get("selection_eligible_sequence", ())) != ELIGIBLE_NAMES
        or tuple(contract.get("fixed_controls", ())) != CONTROL_NAMES
        or contract.get("A313_role") != "none"
        or contract.get("A322_progress_or_result_role") != "none"
        or contract.get("A325_W46_challenge_or_result_role") != "none"
        or contract.get("new_candidate_execution") is not False
        or contract.get("target_labels_used_from_A313_A322_or_A325") != 0
        or boundary.get(
            "all_training_candidate_orders_constructed_before_W45_target_field_is_loaded"
        )
        is not True
        or boundary.get("training_sources_use_any_W45_field") is not False
        or boundary.get("deployment_sources_use_any_W46_challenge_feature") is not False
        or boundary.get("A322_progress_used_for_candidate_definition_selection_or_order")
        is not False
        or boundary.get("A322_result_available_at_design_freeze") is not False
        or boundary.get("A325_execution_started_at_design_freeze") is not False
        or boundary.get("target_labels_used_from_A313_A322_or_A325") != 0
    ):
        raise RuntimeError("A336 frozen design semantics differ")
    for key, value in design["source_anchors"].items():
        if key.endswith("_path"):
            path = ROOT / value
            anchor(
                path,
                design["source_anchors"][key.removesuffix("_path") + "_sha256"],
            )
    return design


def borda(source: Mapping[str, Sequence[int]], names: Sequence[str]) -> list[int]:
    ranks = {name: rank_vector(source[name]) for name in names}
    order = sorted(
        range(CELLS),
        key=lambda cell: (
            sum(ranks[name][cell] for name in names),
            min(ranks[name][cell] for name in names),
            max(ranks[name][cell] for name in names),
            tuple(ranks[name][cell] for name in names),
            cell,
        ),
    )
    return exact_order(order, "Borda fusion")


def prototype_median(source: Mapping[str, Sequence[int]]) -> list[int]:
    ranks = {view: rank_vector(source[view]) for view in (L1, LINF, L2)}
    order = sorted(
        range(CELLS),
        key=lambda cell: (
            sorted((ranks[L1][cell], ranks[LINF][cell], ranks[L2][cell]))[1],
            ranks[L1][cell] + ranks[LINF][cell] + ranks[L2][cell],
            ranks[LINF][cell],
            ranks[L1][cell],
            ranks[L2][cell],
            cell,
        ),
    )
    return exact_order(order, "prototype median")


def candidate_orders(
    source: Mapping[str, Sequence[int]], carry: Sequence[int]
) -> dict[str, list[int]]:
    return {
        BASELINE: exact_order(source[LINF], BASELINE),
        L1_LINF: borda(source, (L1, LINF)),
        LINF_L2: borda(source, (LINF, L2)),
        THREE_BORDA: borda(source, (L1, LINF, L2)),
        THREE_MEDIAN: prototype_median(source),
        ALL_SIX: borda(source, VIEWS),
        WEAK_CONTROL: borda(source, ("fine", "coarse")),
        CARRY_CONTROL: exact_order(carry, CARRY_CONTROL),
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


def build_fusion() -> dict[str, Any]:
    design = load_design()
    if (
        file_sha256(A317_ORDER) != A317_ORDER_SHA256
        or file_sha256(A318_ORDER) != A318_ORDER_SHA256
        or file_sha256(A335_ORDER) != A335_ORDER_SHA256
    ):
        raise RuntimeError("A336 source anchor differs")
    a335 = json.loads(A335_ORDER.read_bytes())
    if a335["selection"]["selected_operator"] != MIDPOINT:
        raise RuntimeError("A336 A335 selected coefficient differs")
    training_sources = {
        view: exact_order(
            a335["candidates"][MIDPOINT]["per_view"][view]["predicted_W45_order"],
            f"training {view}",
        )
        for view in VIEWS
    }
    deployment_sources = {
        view: exact_order(
            a335["deployment"][view]["predicted_W46_order"],
            f"deployment {view}",
        )
        for view in VIEWS
    }
    a317 = json.loads(A317_ORDER.read_bytes())
    carry_w44 = exact_order(a317["atlas_orders"][LINF], "W44 raw Linf")
    training_orders = candidate_orders(training_sources, carry_w44)

    # The complete W45 target field is loaded only after every training order exists.
    a318 = json.loads(A318_ORDER.read_bytes())
    target_w45 = exact_order(a318["atlas_orders"][LINF], "W45 target Linf")
    deployment_orders = candidate_orders(deployment_sources, target_w45)
    training = {
        name: {
            "candidate_index": CANDIDATE_NAMES.index(name),
            "selection_eligible": name in ELIGIBLE_NAMES,
            "predicted_W45_order": order,
            "predicted_W45_order_uint16be_sha256": order_sha(order),
            "metrics_against_complete_target_blind_W45_Linf": metrics(order, target_w45),
        }
        for name, order in training_orders.items()
    }
    selected = max(
        ELIGIBLE_NAMES,
        key=lambda name: (
            training[name]["metrics_against_complete_target_blind_W45_Linf"]["spearman"],
            -training[name]["metrics_against_complete_target_blind_W45_Linf"][
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
    source_identity = {
        "training": {
            view: {
                "observed_sha256": order_sha(order),
                "expected_sha256": a335["candidates"][MIDPOINT]["per_view"][view][
                    "predicted_W45_order_uint16be_sha256"
                ],
            }
            for view, order in training_sources.items()
        },
        "deployment": {
            view: {
                "observed_sha256": order_sha(order),
                "expected_sha256": a335["deployment"][view]["predicted_W46_order_uint16be_sha256"],
            }
            for view, order in deployment_sources.items()
        },
    }
    for family in source_identity.values():
        for row in family.values():
            row["match"] = row["observed_sha256"] == row["expected_sha256"]
    if not all(row["match"] for family in source_identity.values() for row in family.values()):
        raise RuntimeError("A336 A335 source identity gate failed")
    return {
        "design": design,
        "source_identity_gates": source_identity,
        "training": training,
        "deployment": deployment,
        "selected_operator": selected,
        "selected_training_metrics": training[selected][
            "metrics_against_complete_target_blind_W45_Linf"
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
            "metrics_against_complete_target_blind_W45_Linf": row[
                "metrics_against_complete_target_blind_W45_Linf"
            ],
        }
        for name, row in training.items()
    }


def compact_deployment(
    deployment: Mapping[str, Mapping[str, Any]],
) -> dict[str, str]:
    return {name: row["predicted_W46_order_uint16be_sha256"] for name, row in deployment.items()}


def build_causal(payload: Mapping[str, Any]) -> dict[str, Any]:
    from dotcausal.io import CausalReader, CausalWriter

    terminal = "A336:frozen_selected_multiview_fusion_W46_order"
    writer = CausalWriter(api_id="a336fuse")
    writer._rules = []
    writer.add_rule(
        name="A335_midpoint_views_to_frozen_fusions",
        description="Six A335 midpoint forecasts are combined by fixed Borda and median operators before the W45 Linf target field is loaded.",
        pattern=["A335_six_midpoint_training_forecasts", "A336_frozen_fusion_family"],
        conclusion="A336_complete_training_fusion_orders",
        confidence_modifier=1.0,
    )
    writer.add_rule(
        name="complete_W45_Linf_to_selected_fusion",
        description="Complete target-blind W45 Linf rank geometry selects one eligible fusion by Spearman, rank error and frozen index.",
        pattern=["A336_complete_training_fusion_orders", "complete_target_blind_W45_Linf"],
        conclusion="A336_selected_fusion",
        confidence_modifier=1.0,
    )
    writer.add_rule(
        name="selected_fusion_to_W46_order",
        description="The unchanged named-view fusion maps A335 W46 source forecasts into an exact W46 order before A325 execution.",
        pattern=["A336_selected_fusion", "A335_six_W46_view_forecasts"],
        conclusion=terminal.replace(":", "_"),
        confidence_modifier=1.0,
    )
    writer.add_triplet(
        trigger="A335:six_selected_coefficient_training_forecasts",
        mechanism="eight_frozen_multiview_rank_fusions",
        outcome="A336:complete_W45_fusion_forecast_panel",
        confidence=1.0,
        source=payload["measurement_sha256"],
        quantification=json.dumps(payload["training_summary"], sort_keys=True),
        evidence="ALL_TRAINING_FUSIONS_CONSTRUCTED_BEFORE_W45_TARGET_LOAD",
        domain="AI-native multiview forecast fusion",
        quality_score=1.0,
    )
    writer.add_triplet(
        trigger="A336:complete_W45_fusion_forecast_panel",
        mechanism="eligible_only_spearman_then_rank_error_selection",
        outcome="A336:selected_multiview_forecast_fusion",
        confidence=1.0,
        source=payload["commitment_sha256"],
        quantification=json.dumps(payload["selection"], sort_keys=True),
        evidence="CONTROLS_INELIGIBLE_ZERO_TARGET_PREFIX_LABELS",
        domain="target-blind fusion selection",
        quality_score=1.0,
    )
    writer.add_triplet(
        trigger="A336:selected_multiview_forecast_fusion",
        mechanism="unchanged_named_view_W46_fusion",
        outcome=terminal,
        confidence=1.0,
        source=payload["commitment_sha256"],
        quantification=json.dumps(
            {
                "selected_W46_order_uint16be_sha256": payload["selected_W46_order_uint16be_sha256"],
                "deployment_summary": payload["deployment_summary"],
                "source_identity_gates": payload["source_identity_gates"],
            },
            sort_keys=True,
        ),
        evidence=json.dumps(payload["information_boundary"], sort_keys=True),
        domain="prospective W46 fusion commitment",
        quality_score=1.0,
    )
    writer.add_triplet(
        trigger="A335:six_selected_coefficient_training_forecasts",
        mechanism="materialized_multiview_fusion_chain",
        outcome=terminal,
        confidence=1.0,
        source="materialized:A336_multiview_fusion_chain",
        quantification="exact retained closure",
        evidence=payload["evidence_stage"],
        domain="AI-native retained inference",
        quality_score=1.0,
        is_inferred=True,
    )
    writer.add_cluster(
        name="A336 multiview forecast fusion",
        entities=[
            "A335:six_selected_coefficient_training_forecasts",
            "A336:complete_W45_fusion_forecast_panel",
            "A336:selected_multiview_forecast_fusion",
            terminal,
        ],
    )
    writer.add_gap(
        subject=terminal,
        predicate="next_required_object",
        expected_object_type="independently_confirmed_A325_prefix_rank_in_fusion_sources_and_controls",
        confidence=1.0,
        suggested_queries=[
            "After the single complete A325 execution, does the selected fusion rank its confirmed prefix ahead of Linf-only and both controls?"
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
        reader.api_id != "a336fuse"
        or len(explicit) != 3
        or len(all_rows) != 4
        or len(inferred) != 1
        or len(reader._rules) != 3
        or len(reader._clusters) != 1
        or len(reader._gaps) != 1
    ):
        raise RuntimeError("A336 authentic Causal reopen gate failed")
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
        raise FileExistsError("A336 artifacts already exist")
    if A322_RESULT.exists():
        raise RuntimeError("A336 must freeze before any A322 result exists")
    if A325_PROGRESS.exists() or A325_RESULT.exists():
        raise RuntimeError("A336 must freeze before any A325 execution or result exists")
    built = build_fusion()
    training_summary = compact_training(built["training"])
    deployment_summary = compact_deployment(built["deployment"])
    selection = {
        "selected_operator": built["selected_operator"],
        "selected_training_metrics": built["selected_training_metrics"],
        "selection_eligible_sequence": list(ELIGIBLE_NAMES),
        "fixed_controls": list(CONTROL_NAMES),
        "selection_rule": "maximum W45 Linf Spearman then minimum mean absolute rank error then frozen eligible index",
        "target_prefix_labels_used": 0,
    }
    payload: dict[str, Any] = {
        "schema": "chacha20-round20-multiview-forecast-fusion-a336-order-v1",
        "attempt_id": ATTEMPT_ID,
        "evidence_stage": "COMPLETE_TARGET_BLIND_MULTIVIEW_FUSION_SELECTED_W46_ORDER_RETAINED",
        "design_sha256": DESIGN_SHA256,
        "candidate_sequence": list(CANDIDATE_NAMES),
        "source_identity_gates": built["source_identity_gates"],
        "training": built["training"],
        "training_summary": training_summary,
        "deployment": built["deployment"],
        "deployment_summary": deployment_summary,
        "selection": selection,
        "selected_W46_order": built["selected_W46_order"],
        "selected_W46_order_uint16be_sha256": built["selected_W46_order_uint16be_sha256"],
        "information_boundary": built["design"]["information_boundary"],
        "future_evaluation_contract": {
            "A325": "rank the independently confirmed prefix in all eight frozen W46 fusion orders after the single complete A325 execution",
            "duplicate_candidate_execution_required": False,
            "counterfactual_control_outcome_inference": False,
        },
        "anchors": {
            "design": anchor(DESIGN, DESIGN_SHA256),
            "A317_order": anchor(A317_ORDER, A317_ORDER_SHA256),
            "A318_order": anchor(A318_ORDER, A318_ORDER_SHA256),
            "A335_order": anchor(A335_ORDER, A335_ORDER_SHA256),
            "runner": anchor(Path(__file__)),
            "test": anchor(A336_TEST),
            "reproducer": anchor(A336_REPRO),
        },
    }
    payload["commitment_sha256"] = canonical_sha256(
        {
            "design_sha256": DESIGN_SHA256,
            "source_identity_gates": payload["source_identity_gates"],
            "training_summary": training_summary,
            "deployment_summary": deployment_summary,
            "selection": selection,
            "selected_W46_order": payload["selected_W46_order"],
            "information_boundary": payload["information_boundary"],
        }
    )
    payload["measurement_sha256"] = canonical_sha256(
        {
            "training_summary": training_summary,
            "selection": selection,
            "information_boundary": payload["information_boundary"],
        }
    )
    payload["causal"] = build_causal(payload)
    atomic_json(ORDER, payload)
    selected = selection["selected_training_metrics"]
    baseline = training_summary[BASELINE]["metrics_against_complete_target_blind_W45_Linf"]
    weak = training_summary[WEAK_CONTROL]["metrics_against_complete_target_blind_W45_Linf"]
    atomic_bytes(
        REPORT,
        (
            "# A336 — target-blind multiview forecast fusion\n\n"
            f"- Selected fusion: **{selection['selected_operator']}**\n"
            f"- W45 Linf Spearman, selected / Linf-only / weak-view control: **{selected['spearman']:.8f} / {baseline['spearman']:.8f} / {weak['spearman']:.8f}**\n"
            f"- Selected W46 order SHA: **`{payload['selected_W46_order_uint16be_sha256']}`**\n"
            "- A335 source identity gates: **12/12 exact**\n"
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

#!/usr/bin/env python3
"""A337: learn an exact Linf/L2 rank-weight simplex and freeze its W46 order."""

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

DESIGN = CONFIGS / "chacha20_round20_linf_l2_weight_simplex_a337_design_v1.json"
ORDER = RESULTS / "chacha20_round20_linf_l2_weight_simplex_a337_order_v1.json"
CAUSAL = RESULTS / "chacha20_round20_linf_l2_weight_simplex_a337_order_v1.causal"
REPORT = RESULTS / "chacha20_round20_linf_l2_weight_simplex_a337_order_v1.md"

A318_ORDER = RESULTS / "chacha20_round20_w45_multiview_operator_atlas_a318_order_v1.json"
A335_ORDER = RESULTS / "chacha20_round20_multiview_rank_smoothing_a335_order_v1.json"
A336_ORDER = RESULTS / "chacha20_round20_multiview_forecast_fusion_a336_order_v1.json"
A322_RESULT = RESULTS / "chacha20_round20_holdout_selected_w45_recovery_a322_v1.json"
A325_PROGRESS = RESULTS / "chacha20_round20_holdout_selected_w46_recovery_a325_progress_v1.json"
A325_RESULT = RESULTS / "chacha20_round20_holdout_selected_w46_recovery_a325_v1.json"
A337_TEST = ROOT / "tests/test_chacha20_round20_linf_l2_weight_simplex_a337.py"
A337_REPRO = ROOT / "scripts/reproduce_chacha20_round20_linf_l2_weight_simplex_a337.sh"

ATTEMPT_ID = "A337"
DESIGN_SHA256 = "c961076e0bb9c6ba69046e76b8d4cc9875baa8b01f2140211636159819b4fded"
A318_ORDER_SHA256 = "25c36b4412cedcd37243057535109b36e79ded5172eba642bb84dd50f1de49f0"
A335_ORDER_SHA256 = "80e63e65ca8139e2b893670c093ddfbd7451e6cf1e024b64aff18950b6344f75"
A336_ORDER_SHA256 = "c8ab47d6de41740fb216861cf2d135568d4aadd1bbcf9bdf5e4fa20ea5344d4c"
CELLS = 1 << 12
RESOLUTION = 16
LINF = "nearest_prototype_Linf"
L2 = "nearest_prototype_squared_L2"
MIDPOINT = "midpoint_alpha_minus_1_over_2"
A336_EQUAL = "linf_l2_equal_borda"
WEIGHTS = tuple((linf_weight, RESOLUTION - linf_weight) for linf_weight in range(16, -1, -1))
CANDIDATE_NAMES = tuple(
    f"linf{linf_weight:02d}_l2_{l2_weight:02d}" for linf_weight, l2_weight in WEIGHTS
)
LINF_ENDPOINT = CANDIDATE_NAMES[0]
EQUAL_WEIGHT = CANDIDATE_NAMES[8]
L2_ENDPOINT = CANDIDATE_NAMES[-1]

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
        raise RuntimeError(f"A337 anchor differs: {path}")
    return {"path": relative(path), "sha256": observed}


def exact_order(values: Sequence[int], label: str) -> list[int]:
    order = [int(value) for value in values]
    if len(order) != CELLS or set(order) != set(range(CELLS)):
        raise ValueError(f"A337 {label} is not an exact 4,096-cell cover")
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


def candidate_name(linf_weight: int, l2_weight: int) -> str:
    return f"linf{linf_weight:02d}_l2_{l2_weight:02d}"


def load_design() -> dict[str, Any]:
    if file_sha256(DESIGN) != DESIGN_SHA256:
        raise RuntimeError("A337 design hash differs")
    design = json.loads(DESIGN.read_bytes())
    contract = design.get("weight_contract", {})
    boundary = design.get("information_boundary", {})
    candidates = contract.get("candidate_sequence", [])
    observed_weights = tuple(
        (int(row["linf_weight"]), int(row["l2_weight"])) for row in candidates
    )
    observed_names = tuple(str(row["name"]) for row in candidates)
    if (
        design.get("schema") != "chacha20-round20-linf-l2-weight-simplex-a337-design-v1"
        or design.get("attempt_id") != ATTEMPT_ID
        or design.get("design_state")
        != "frozen_while_A322_is_running_before_any_A322_result_and_before_any_A325_execution_or_result"
        or contract.get("resolution") != RESOLUTION
        or observed_weights != WEIGHTS
        or observed_names != CANDIDATE_NAMES
        or tuple(contract.get("selection_eligible_sequence", ())) != CANDIDATE_NAMES
        or contract.get("A313_role") != "none"
        or contract.get("A322_progress_or_result_role") != "none"
        or contract.get("A325_W46_challenge_or_result_role") != "none"
        or contract.get("new_candidate_execution") is not False
        or contract.get("target_labels_used_from_A313_A322_or_A325") != 0
        or boundary.get(
            "all_training_candidate_orders_constructed_before_W45_target_field_is_loaded"
        )
        is not True
        or boundary.get("training_sources_use_any_W45_target_field") is not False
        or boundary.get("deployment_sources_use_any_W46_challenge_feature") is not False
        or boundary.get("A322_progress_used_for_candidate_definition_selection_or_order")
        is not False
        or boundary.get("A322_result_available_at_design_freeze") is not False
        or boundary.get("A325_execution_started_at_design_freeze") is not False
        or boundary.get("target_labels_used_from_A313_A322_or_A325") != 0
    ):
        raise RuntimeError("A337 frozen design semantics differ")
    for key, value in design["source_anchors"].items():
        if key.endswith("_path"):
            anchor(
                ROOT / value,
                design["source_anchors"][key.removesuffix("_path") + "_sha256"],
            )
    return design


def weighted_borda(
    linf_order: Sequence[int],
    l2_order: Sequence[int],
    linf_weight: int,
    l2_weight: int,
) -> list[int]:
    if linf_weight < 0 or l2_weight < 0 or linf_weight + l2_weight != RESOLUTION:
        raise ValueError("A337 weights must be a nonnegative resolution-16 simplex point")
    linf_ranks = rank_vector(linf_order)
    l2_ranks = rank_vector(l2_order)
    order = sorted(
        range(CELLS),
        key=lambda cell: (
            linf_weight * linf_ranks[cell] + l2_weight * l2_ranks[cell],
            linf_ranks[cell] + l2_ranks[cell],
            min(linf_ranks[cell], l2_ranks[cell]),
            max(linf_ranks[cell], l2_ranks[cell]),
            linf_ranks[cell],
            l2_ranks[cell],
            cell,
        ),
    )
    return exact_order(order, candidate_name(linf_weight, l2_weight))


def candidate_orders(linf_order: Sequence[int], l2_order: Sequence[int]) -> dict[str, list[int]]:
    return {
        candidate_name(linf_weight, l2_weight): weighted_borda(
            linf_order, l2_order, linf_weight, l2_weight
        )
        for linf_weight, l2_weight in WEIGHTS
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


def build_simplex() -> dict[str, Any]:
    design = load_design()
    if file_sha256(A335_ORDER) != A335_ORDER_SHA256:
        raise RuntimeError("A337 A335 source anchor differs")
    a335 = json.loads(A335_ORDER.read_bytes())
    if a335["selection"]["selected_operator"] != MIDPOINT:
        raise RuntimeError("A337 A335 selected coefficient differs")

    training_linf = exact_order(
        a335["candidates"][MIDPOINT]["per_view"][LINF]["predicted_W45_order"],
        "training Linf",
    )
    training_l2 = exact_order(
        a335["candidates"][MIDPOINT]["per_view"][L2]["predicted_W45_order"],
        "training squared L2",
    )
    deployment_linf = exact_order(
        a335["deployment"][LINF]["predicted_W46_order"], "deployment Linf"
    )
    deployment_l2 = exact_order(
        a335["deployment"][L2]["predicted_W46_order"], "deployment squared L2"
    )

    # Every candidate is complete before the W45 target order is loaded.
    training_orders = candidate_orders(training_linf, training_l2)
    deployment_orders = candidate_orders(deployment_linf, deployment_l2)

    if file_sha256(A318_ORDER) != A318_ORDER_SHA256:
        raise RuntimeError("A337 A318 target anchor differs")
    a318 = json.loads(A318_ORDER.read_bytes())
    target_w45 = exact_order(a318["atlas_orders"][LINF], "complete target-blind W45 Linf")
    training = {
        name: {
            "candidate_index": CANDIDATE_NAMES.index(name),
            "linf_weight": WEIGHTS[CANDIDATE_NAMES.index(name)][0],
            "l2_weight": WEIGHTS[CANDIDATE_NAMES.index(name)][1],
            "predicted_W45_order": order,
            "predicted_W45_order_uint16be_sha256": order_sha(order),
            "metrics_against_complete_target_blind_W45_Linf": metrics(order, target_w45),
        }
        for name, order in training_orders.items()
    }
    selected = max(
        CANDIDATE_NAMES,
        key=lambda name: (
            training[name]["metrics_against_complete_target_blind_W45_Linf"]["spearman"],
            -training[name]["metrics_against_complete_target_blind_W45_Linf"][
                "mean_absolute_rank_error"
            ],
            -CANDIDATE_NAMES.index(name),
        ),
    )
    deployment = {
        name: {
            "linf_weight": WEIGHTS[CANDIDATE_NAMES.index(name)][0],
            "l2_weight": WEIGHTS[CANDIDATE_NAMES.index(name)][1],
            "predicted_W46_order": order,
            "predicted_W46_order_uint16be_sha256": order_sha(order),
        }
        for name, order in deployment_orders.items()
    }

    # A336 is loaded only after the A337 candidates and selection exist.
    if file_sha256(A336_ORDER) != A336_ORDER_SHA256:
        raise RuntimeError("A337 A336 identity anchor differs")
    a336 = json.loads(A336_ORDER.read_bytes())
    identity_gates = {
        "training_linf_endpoint_matches_A335": (
            training[LINF_ENDPOINT]["predicted_W45_order_uint16be_sha256"]
            == a335["candidates"][MIDPOINT]["per_view"][LINF][
                "predicted_W45_order_uint16be_sha256"
            ]
        ),
        "training_equal_matches_A336": (
            training[EQUAL_WEIGHT]["predicted_W45_order_uint16be_sha256"]
            == a336["training"][A336_EQUAL]["predicted_W45_order_uint16be_sha256"]
        ),
        "training_l2_endpoint_matches_A335": (
            training[L2_ENDPOINT]["predicted_W45_order_uint16be_sha256"]
            == a335["candidates"][MIDPOINT]["per_view"][L2][
                "predicted_W45_order_uint16be_sha256"
            ]
        ),
        "deployment_linf_endpoint_matches_A335": (
            deployment[LINF_ENDPOINT]["predicted_W46_order_uint16be_sha256"]
            == a335["deployment"][LINF]["predicted_W46_order_uint16be_sha256"]
        ),
        "deployment_equal_matches_A336": (
            deployment[EQUAL_WEIGHT]["predicted_W46_order_uint16be_sha256"]
            == a336["deployment"][A336_EQUAL]["predicted_W46_order_uint16be_sha256"]
        ),
        "deployment_l2_endpoint_matches_A335": (
            deployment[L2_ENDPOINT]["predicted_W46_order_uint16be_sha256"]
            == a335["deployment"][L2]["predicted_W46_order_uint16be_sha256"]
        ),
    }
    if not all(identity_gates.values()):
        raise RuntimeError("A337 endpoint/equal identity gate failed")
    return {
        "design": design,
        "training": training,
        "deployment": deployment,
        "identity_gates": identity_gates,
        "selected_operator": selected,
        "selected_weights": {
            "linf_weight": training[selected]["linf_weight"],
            "l2_weight": training[selected]["l2_weight"],
        },
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
            key: row[key]
            for key in (
                "candidate_index",
                "linf_weight",
                "l2_weight",
                "predicted_W45_order_uint16be_sha256",
                "metrics_against_complete_target_blind_W45_Linf",
            )
        }
        for name, row in training.items()
    }


def compact_deployment(deployment: Mapping[str, Mapping[str, Any]]) -> dict[str, Any]:
    return {
        name: {
            "linf_weight": row["linf_weight"],
            "l2_weight": row["l2_weight"],
            "predicted_W46_order_uint16be_sha256": row[
                "predicted_W46_order_uint16be_sha256"
            ],
        }
        for name, row in deployment.items()
    }


def build_causal(payload: Mapping[str, Any]) -> dict[str, Any]:
    from dotcausal.io import CausalReader, CausalWriter

    terminal = "A337:frozen_selected_weighted_W46_order"
    writer = CausalWriter(api_id="a337wgt")
    writer._rules = []
    writer.add_rule(
        name="A336_equal_gain_to_exact_weight_simplex",
        description="The retained equal Linf/L2 gain triggers an exact 17-point integer-weight response curve built before target load.",
        pattern=["A336_equal_fusion_gain", "A337_exact_weight_simplex"],
        conclusion="A337_complete_W45_weight_response_curve",
        confidence_modifier=1.0,
    )
    writer.add_rule(
        name="complete_weight_curve_to_selected_weight",
        description="The complete target-blind W45 Linf order selects one exact weight by Spearman, rank error and frozen index.",
        pattern=["A337_complete_W45_weight_response_curve", "complete_target_blind_W45_Linf"],
        conclusion="A337_selected_exact_weight",
        confidence_modifier=1.0,
    )
    writer.add_rule(
        name="selected_weight_to_W46_order",
        description="The selected weights and unchanged tie rule map A335 W46 forecasts into a frozen order before A325 execution.",
        pattern=["A337_selected_exact_weight", "A335_W46_Linf_L2_midpoint_forecasts"],
        conclusion=terminal.replace(":", "_"),
        confidence_modifier=1.0,
    )
    writer.add_triplet(
        trigger="A336:equal_Linf_L2_fusion_gain",
        mechanism="seventeen_point_exact_integer_weight_simplex",
        outcome="A337:complete_W45_weight_response_curve",
        confidence=1.0,
        source=payload["measurement_sha256"],
        quantification=json.dumps(payload["training_summary"], sort_keys=True),
        evidence="ALL_17_ORDERS_EXIST_BEFORE_W45_TARGET_LOAD",
        domain="AI-native exact rank-weight inference",
        quality_score=1.0,
    )
    writer.add_triplet(
        trigger="A337:complete_W45_weight_response_curve",
        mechanism="spearman_then_rank_error_selection",
        outcome="A337:selected_exact_Linf_L2_weight",
        confidence=1.0,
        source=payload["commitment_sha256"],
        quantification=json.dumps(payload["selection"], sort_keys=True),
        evidence="ZERO_A313_A322_A325_TARGET_LABELS",
        domain="target-blind exact weight learning",
        quality_score=1.0,
    )
    writer.add_triplet(
        trigger="A337:selected_exact_Linf_L2_weight",
        mechanism="unchanged_weight_and_tie_rule_on_W46_forecasts",
        outcome=terminal,
        confidence=1.0,
        source=payload["commitment_sha256"],
        quantification=json.dumps(
            {
                "selected_W46_order_uint16be_sha256": payload[
                    "selected_W46_order_uint16be_sha256"
                ],
                "identity_gates": payload["identity_gates"],
            },
            sort_keys=True,
        ),
        evidence=json.dumps(payload["information_boundary"], sort_keys=True),
        domain="prospective W46 exact-weight commitment",
        quality_score=1.0,
    )
    writer.add_triplet(
        trigger="A336:equal_Linf_L2_fusion_gain",
        mechanism="materialized_exact_weight_learning_chain",
        outcome=terminal,
        confidence=1.0,
        source="materialized:A337_exact_weight_learning_chain",
        quantification="exact retained closure",
        evidence=payload["evidence_stage"],
        domain="AI-native retained inference",
        quality_score=1.0,
        is_inferred=True,
    )
    writer.add_cluster(
        name="A337 exact Linf/L2 weight simplex",
        entities=[
            "A336:equal_Linf_L2_fusion_gain",
            "A337:complete_W45_weight_response_curve",
            "A337:selected_exact_Linf_L2_weight",
            terminal,
        ],
    )
    writer.add_gap(
        subject=terminal,
        predicate="next_required_object",
        expected_object_type="independently_confirmed_A325_prefix_rank_across_weight_simplex",
        confidence=1.0,
        suggested_queries=[
            "After A325 confirmation, does the selected exact weight rank the prefix ahead of both endpoints and the A336 equal-weight identity?"
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
        reader.api_id != "a337wgt"
        or len(explicit) != 3
        or len(all_rows) != 4
        or len(inferred) != 1
        or len(reader._rules) != 3
        or len(reader._clusters) != 1
        or len(reader._gaps) != 1
    ):
        raise RuntimeError("A337 authentic Causal reopen gate failed")
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
        raise FileExistsError("A337 artifacts already exist")
    if A322_RESULT.exists():
        raise RuntimeError("A337 must freeze before any A322 result exists")
    if A325_PROGRESS.exists() or A325_RESULT.exists():
        raise RuntimeError("A337 must freeze before any A325 execution or result exists")
    built = build_simplex()
    training_summary = compact_training(built["training"])
    deployment_summary = compact_deployment(built["deployment"])
    selection = {
        "selected_operator": built["selected_operator"],
        "selected_weights": built["selected_weights"],
        "selected_training_metrics": built["selected_training_metrics"],
        "selection_eligible_sequence": list(CANDIDATE_NAMES),
        "selection_rule": "maximum W45 Linf Spearman then minimum mean absolute rank error then frozen candidate index",
        "target_prefix_labels_used": 0,
    }
    payload: dict[str, Any] = {
        "schema": "chacha20-round20-linf-l2-weight-simplex-a337-order-v1",
        "attempt_id": ATTEMPT_ID,
        "evidence_stage": "COMPLETE_TARGET_BLIND_EXACT_WEIGHT_SELECTED_W46_ORDER_RETAINED",
        "design_sha256": DESIGN_SHA256,
        "candidate_sequence": list(CANDIDATE_NAMES),
        "identity_gates": built["identity_gates"],
        "training": built["training"],
        "training_summary": training_summary,
        "deployment": built["deployment"],
        "deployment_summary": deployment_summary,
        "selection": selection,
        "selected_W46_order": built["selected_W46_order"],
        "selected_W46_order_uint16be_sha256": built[
            "selected_W46_order_uint16be_sha256"
        ],
        "information_boundary": built["design"]["information_boundary"],
        "future_evaluation_contract": built["design"]["future_evaluation_contract"],
        "anchors": {
            "design": anchor(DESIGN, DESIGN_SHA256),
            "A318_order": anchor(A318_ORDER, A318_ORDER_SHA256),
            "A335_order": anchor(A335_ORDER, A335_ORDER_SHA256),
            "A336_order": anchor(A336_ORDER, A336_ORDER_SHA256),
            "runner": anchor(Path(__file__)),
            "test": anchor(A337_TEST),
            "reproducer": anchor(A337_REPRO),
        },
    }
    payload["commitment_sha256"] = canonical_sha256(
        {
            "design_sha256": DESIGN_SHA256,
            "identity_gates": payload["identity_gates"],
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
    linf = training_summary[LINF_ENDPOINT]["metrics_against_complete_target_blind_W45_Linf"]
    equal = training_summary[EQUAL_WEIGHT]["metrics_against_complete_target_blind_W45_Linf"]
    l2 = training_summary[L2_ENDPOINT]["metrics_against_complete_target_blind_W45_Linf"]
    atomic_bytes(
        REPORT,
        (
            "# A337 — exact Linf/L2 weight-simplex selection\n\n"
            f"- Selected exact weight: **{selection['selected_operator']}**\n"
            f"- W45 Linf Spearman, selected / Linf / equal / L2: **{selected['spearman']:.8f} / {linf['spearman']:.8f} / {equal['spearman']:.8f} / {l2['spearman']:.8f}**\n"
            f"- Selected W46 order SHA: **`{payload['selected_W46_order_uint16be_sha256']}`**\n"
            "- Endpoint/equal identity gates: **6/6 exact**\n"
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
                "selected_W46_order_uint16be_sha256": payload[
                    "selected_W46_order_uint16be_sha256"
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

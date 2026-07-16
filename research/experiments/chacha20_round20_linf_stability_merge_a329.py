#!/usr/bin/env python3
"""A329: freeze exact bounded-regret Linf stability-merge orders."""

from __future__ import annotations

import argparse
import importlib.util
import inspect
import json
import math
import os
import sys
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

ROOT = Path(__file__).parents[2]
RESEARCH = ROOT / "research"
CONFIGS = RESEARCH / "configs"
RESULTS = RESEARCH / "results/v1"

DESIGN = CONFIGS / "chacha20_round20_linf_stability_merge_a329_design_v1.json"
ORDER = RESULTS / "chacha20_round20_linf_stability_merge_a329_order_v1.json"
CAUSAL = RESULTS / "chacha20_round20_linf_stability_merge_a329_order_v1.causal"
REPORT = RESULTS / "chacha20_round20_linf_stability_merge_a329_order_v1.md"

A328_RUNNER = RESEARCH / "experiments/chacha20_round20_linf_voronoi_transfer_a328.py"
A328_RESULT = RESULTS / "chacha20_round20_linf_voronoi_transfer_a328_v1.json"
A327_ORDER = RESULTS / "chacha20_round20_hierarchical_linf_operator_a327_order_v1.json"
A321_ORDER = RESULTS / "chacha20_round20_holdout_selected_w45_operator_a321_order_v1.json"
A313_RESULT = RESULTS / "chacha20_round20_w44_width_conditioned_fine_portfolio_a313_v1.json"
A322_RESULT = RESULTS / "chacha20_round20_holdout_selected_w45_recovery_a322_v1.json"
A325_PROGRESS = RESULTS / "chacha20_round20_holdout_selected_w46_recovery_a325_progress_v1.json"
A325_RESULT = RESULTS / "chacha20_round20_holdout_selected_w46_recovery_a325_v1.json"
A329_TEST = ROOT / "tests/test_chacha20_round20_linf_stability_merge_a329.py"
A329_REPRO = ROOT / "scripts/reproduce_chacha20_round20_linf_stability_merge_a329.sh"

ATTEMPT_ID = "A329"
DESIGN_SHA256 = "0b1e92fd50437193f261b54bb6fb25422680e77d9af4977661a269b8311ea17a"
A328_RUNNER_SHA256 = "d7daf79a6e491bbd60b8fc48fcd44eea17ecc6ab4f6b15e22b890b0e8a94ca02"
A328_RESULT_SHA256 = "93c507e6fa4faeaae30618a35d0a933139246cdf8a57f45fb3760982c796a1b4"
A327_ORDER_SHA256 = "7c077a4e8eeb3ab83c4fae931f94882c87369cedb18bd19b2766e04e9b72c90f"
A321_ORDER_SHA256 = "8ace2e5af5ce1a132e78926f317dadaf63ada13a10c0338a56ddf62713a9d9d2"
A313_RESULT_SHA256 = "ec18ee284da633589d1c35fe8f02257438f83fb4f255553667ebc3a0b0452b9a"
RAW_W45_ORDER_SHA256 = "5d1afc37614fdbe050e9853413a3de7b850b876e9bc5649d3dffcf3e23c9780a"
CELLS = 1 << 12
CANDIDATE_NAMES = (
    "original_raw_linf",
    "stable_first",
    "stable_switched_1_to_1",
    "stable_switched_2_to_1",
    "switched_stable_2_to_1_control",
)
PRIMARY = "stable_switched_2_to_1"
CONTROL = "switched_stable_2_to_1_control"


def load_module(path: Path, name: str) -> Any:
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot import A329 dependency {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


if not A328_RUNNER.exists():
    raise FileNotFoundError(A328_RUNNER)
A328 = load_module(A328_RUNNER, "a329_a328_common")
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
        raise RuntimeError("A329 design hash differs")
    design = json.loads(DESIGN.read_bytes())
    operator = design.get("operator_contract", {})
    boundary = design.get("information_boundary", {})
    if (
        design.get("schema") != "chacha20-round20-linf-stability-merge-a329-design-v1"
        or design.get("attempt_id") != ATTEMPT_ID
        or design.get("design_state")
        != "frozen_while_A322_is_running_before_any_A322_result_and_before_any_A325_execution_or_result"
        or tuple(operator.get("candidate_sequence_and_tie_break", ())) != CANDIDATE_NAMES
        or operator.get("primary_operator") != PRIMARY
        or operator.get("matched_direction_control") != CONTROL
        or operator.get("A313_role") != "annotation_only_no_candidate_selection"
        or operator.get("new_candidate_execution") is not False
        or operator.get("operator_refit") is not False
        or operator.get("target_labels_used_from_A322_or_A325") != 0
        or boundary.get("A322_progress_used_for_any_operator_or_order") is not False
        or boundary.get("A322_result_available_at_design_freeze") is not False
        or boundary.get("A325_execution_started_at_design_freeze") is not False
        or boundary.get("target_labels_used_from_A322_or_A325") != 0
        or boundary.get("duplicate_candidate_execution_required_for_evaluation") is not False
    ):
        raise RuntimeError("A329 frozen design semantics differ")
    for key, value in design["source_anchors"].items():
        if key.endswith("_path"):
            anchor(
                path_from_ref(value),
                design["source_anchors"][key.removesuffix("_path") + "_sha256"],
            )
    return design


def interleave(
    left: Sequence[int], right: Sequence[int], left_quota: int, right_quota: int
) -> list[int]:
    if left_quota <= 0 or right_quota <= 0:
        raise ValueError("A329 quotas must be positive")
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
    return output


def candidate_order(
    name: str, base_order: Sequence[int], stable_mask: Sequence[bool]
) -> list[int]:
    stable = [cell for cell in base_order if stable_mask[cell]]
    switched = [cell for cell in base_order if not stable_mask[cell]]
    if name == "original_raw_linf":
        order = list(base_order)
    elif name == "stable_first":
        order = stable + switched
    elif name == "stable_switched_1_to_1":
        order = interleave(stable, switched, 1, 1)
    elif name == "stable_switched_2_to_1":
        order = interleave(stable, switched, 2, 1)
    elif name == "switched_stable_2_to_1_control":
        order = interleave(switched, stable, 2, 1)
    else:
        raise ValueError(f"unknown A329 candidate {name}")
    return A327._exact_order(order, name)  # noqa: SLF001


def maximum_ratio(
    candidate_ranks: Sequence[int], base_ranks: Sequence[int], cells: Sequence[int]
) -> dict[str, Any]:
    if not cells:
        raise RuntimeError("A329 ratio panel received an empty cell class")
    worst = max(cells, key=lambda cell: candidate_ranks[cell] / base_ranks[cell])
    return {
        "value": candidate_ranks[worst] / base_ranks[worst],
        "cell": worst,
        "candidate_rank_one_based": candidate_ranks[worst],
        "raw_Linf_rank_one_based": base_ranks[worst],
    }


def regret_panel(
    name: str,
    candidate_order_value: Sequence[int],
    base_order: Sequence[int],
    stable_mask: Sequence[bool],
) -> dict[str, Any]:
    candidate_ranks = A327.rank_vector(candidate_order_value)
    base_ranks = A327.rank_vector(base_order)
    stable_cells = [cell for cell in range(CELLS) if stable_mask[cell]]
    switched_cells = [cell for cell in range(CELLS) if not stable_mask[cell]]
    violations: dict[str, int]
    if name == "original_raw_linf":
        violations = {
            "global_rank_le_raw_rank": sum(
                candidate_ranks[cell] > base_ranks[cell] for cell in range(CELLS)
            )
        }
    elif name == "stable_first":
        violations = {
            "stable_rank_le_raw_rank": sum(
                candidate_ranks[cell] > base_ranks[cell] for cell in stable_cells
            )
        }
    elif name == "stable_switched_1_to_1":
        violations = {
            "global_rank_le_2x_raw_rank": sum(
                candidate_ranks[cell] > 2 * base_ranks[cell] for cell in range(CELLS)
            )
        }
    elif name == "stable_switched_2_to_1":
        violations = {
            "stable_rank_le_ceil_3r_over_2": sum(
                candidate_ranks[cell] > math.ceil(3 * base_ranks[cell] / 2)
                for cell in stable_cells
            ),
            "switched_rank_le_3x_raw_rank": sum(
                candidate_ranks[cell] > 3 * base_ranks[cell]
                for cell in switched_cells
            ),
        }
    elif name == "switched_stable_2_to_1_control":
        violations = {
            "switched_rank_le_ceil_3r_over_2": sum(
                candidate_ranks[cell] > math.ceil(3 * base_ranks[cell] / 2)
                for cell in switched_cells
            ),
            "stable_rank_le_3x_raw_rank": sum(
                candidate_ranks[cell] > 3 * base_ranks[cell]
                for cell in stable_cells
            ),
        }
    else:
        raise ValueError(name)
    return {
        "maximum_rank_ratio_all": maximum_ratio(
            candidate_ranks, base_ranks, list(range(CELLS))
        ),
        "maximum_rank_ratio_stable": maximum_ratio(
            candidate_ranks, base_ranks, stable_cells
        ),
        "maximum_rank_ratio_switched": maximum_ratio(
            candidate_ranks, base_ranks, switched_cells
        ),
        "guarantee_violations": violations,
    }


def build_family() -> dict[str, Any]:
    design = load_design()
    if (
        file_sha256(A328_RUNNER) != A328_RUNNER_SHA256
        or file_sha256(A328_RESULT) != A328_RESULT_SHA256
        or file_sha256(A327_ORDER) != A327_ORDER_SHA256
        or file_sha256(A321_ORDER) != A321_ORDER_SHA256
        or file_sha256(A313_RESULT) != A313_RESULT_SHA256
    ):
        raise RuntimeError("A329 source anchor differs")
    a328_result = json.loads(A328_RESULT.read_bytes())
    source = A327.load_source_views()
    w44 = A328.prototype_panel(source["W44"])
    w45 = A328.prototype_panel(source["W45"])
    stable_mask = [
        left == right
        for left, right in zip(w44["assignment"], w45["assignment"], strict=True)
    ]
    stable_cells = [cell for cell in range(CELLS) if stable_mask[cell]]
    switched_cells = [cell for cell in range(CELLS) if not stable_mask[cell]]
    if (
        len(stable_cells) != a328_result["analysis"]["stable_cells"]
        or len(switched_cells) != a328_result["analysis"]["switched_cells"]
    ):
        raise RuntimeError("A329 recomputed partition differs from A328")
    ratio = (
        a328_result["analysis"]["raw_Linf_cross_width_spearman_stable_subset"]
        / a328_result["analysis"]["raw_Linf_cross_width_spearman_switched_subset"]
    )
    if round(ratio, 4) != 1.7946:
        raise RuntimeError("A329 A328 correlation ratio differs")
    base_orders = {
        "W44": A327._exact_order(  # noqa: SLF001
            source["original_W44_linf"], "A329 raw W44 Linf"
        ),
        "W45": A327._exact_order(  # noqa: SLF001
            source["original_W45_linf"], "A329 raw W45 Linf"
        ),
    }
    if A327._order_sha(base_orders["W45"]) != RAW_W45_ORDER_SHA256:  # noqa: SLF001
        raise RuntimeError("A329 raw W45 order differs from A321 selection")
    candidates: dict[str, Any] = {}
    for name in CANDIDATE_NAMES:
        row: dict[str, Any] = {}
        for width, base_order in base_orders.items():
            order = candidate_order(name, base_order, stable_mask)
            row[f"{width}_order"] = order
            row[f"{width}_order_uint16be_sha256"] = A327._order_sha(order)  # noqa: SLF001
            row[f"{width}_regret"] = regret_panel(
                name, order, base_order, stable_mask
            )
        row["cross_width_spearman"] = A327.spearman(
            row["W44_order"], row["W45_order"]
        )
        candidates[name] = row
    a313 = json.loads(A313_RESULT.read_bytes())
    prefix = int(a313["discovery"]["prefix12"])
    annotation = {
        "prefix12": prefix,
        "prefix12_hex": f"{prefix:03x}",
        "stable_partition": stable_mask[prefix],
        "W44_prototype_index": w44["assignment"][prefix],
        "W45_same_cell_prototype_index": w45["assignment"][prefix],
        "candidate_ranks_one_based": {
            name: {
                "W44": A327.rank_vector(row["W44_order"])[prefix],
                "W45_same_cell": A327.rank_vector(row["W45_order"])[prefix],
            }
            for name, row in candidates.items()
        },
        "used_for_candidate_selection": False,
    }
    return {
        "design": design,
        "stable_cells": len(stable_cells),
        "switched_cells": len(switched_cells),
        "stable_fraction": len(stable_cells) / CELLS,
        "A328_stable_to_switched_rho_ratio": ratio,
        "candidates": candidates,
        "primary_operator": PRIMARY,
        "matched_direction_control": CONTROL,
        "primary_W45_order": candidates[PRIMARY]["W45_order"],
        "primary_W45_order_uint16be_sha256": candidates[PRIMARY][
            "W45_order_uint16be_sha256"
        ],
        "control_W45_order": candidates[CONTROL]["W45_order"],
        "control_W45_order_uint16be_sha256": candidates[CONTROL][
            "W45_order_uint16be_sha256"
        ],
        "A313_annotation": annotation,
        "target_labels_used_from_A322_or_A325": 0,
        "duplicate_candidate_execution_required_for_evaluation": False,
    }


def candidate_summary(candidates: Mapping[str, Mapping[str, Any]]) -> dict[str, Any]:
    return {
        name: {
            "W44_order_uint16be_sha256": row["W44_order_uint16be_sha256"],
            "W45_order_uint16be_sha256": row["W45_order_uint16be_sha256"],
            "W44_regret": row["W44_regret"],
            "W45_regret": row["W45_regret"],
            "cross_width_spearman": row["cross_width_spearman"],
        }
        for name, row in candidates.items()
    }


def build_causal(payload: Mapping[str, Any]) -> dict[str, Any]:
    sys.path.insert(0, str(DOTCAUSAL_SRC))
    from dotcausal.io import CausalReader, CausalWriter

    terminal = "A329:frozen_stability_merge_primary_and_direction_control"
    writer = CausalWriter(api_id="a329merg")
    writer._rules = []
    writer.add_rule(
        name="stable_partition_and_raw_streams_to_exact_merges",
        description="The exact A328 stable/switched partition filters each raw-Linf order into two streams and merges them under fixed schedules without changing within-stream order.",
        pattern=["A328_exact_stable_switched_partition", "raw_Linf_order_pair"],
        conclusion="A329_exact_merge_family",
        confidence_modifier=1.0,
    )
    writer.add_rule(
        name="measured_transfer_ratio_to_primary_and_control",
        description="A328's 1.7946 stable-to-switched rho ratio fixes the smallest integer stability-favoring schedule at 2:1 and pairs it with the symmetric 2:1 switched-first control.",
        pattern=["A328_stable_switched_rho_ratio", "A329_fixed_merge_family"],
        conclusion=terminal.replace(":", "_"),
        confidence_modifier=1.0,
    )
    writer.add_rule(
        name="single_complete_scan_to_duplicate_free_rank_panel",
        description="A later confirmed prefix maps into every frozen order, so the complete A322 or A325 scan evaluates the full family without executing any candidate twice.",
        pattern=["confirmed_complete_scan_prefix", "A329_frozen_order_family"],
        conclusion="A329_duplicate_free_prospective_rank_panel",
        confidence_modifier=1.0,
    )
    writer.add_triplet(
        trigger="A328:complete_target_blind_stable_switched_partition",
        mechanism="within_class_order_preserving_fixed_quota_merge",
        outcome="A329:five_exact_W44_W45_orders",
        confidence=1.0,
        source=payload["measurement_sha256"],
        quantification=json.dumps(payload["candidate_summary"], sort_keys=True),
        evidence="COMPLETE_DUPLICATE_FREE_4096_CELL_ORDERS",
        domain="AI-native stability-aware order construction",
        quality_score=1.0,
    )
    writer.add_triplet(
        trigger="A329:five_exact_W44_W45_orders",
        mechanism="predeclared_2_to_1_stability_direction_with_symmetric_control",
        outcome=terminal,
        confidence=1.0,
        source=payload["commitment_sha256"],
        quantification=json.dumps(
            {
                "primary": payload["primary_operator"],
                "primary_W45_order_uint16be_sha256": payload[
                    "primary_W45_order_uint16be_sha256"
                ],
                "control": payload["matched_direction_control"],
                "control_W45_order_uint16be_sha256": payload[
                    "control_W45_order_uint16be_sha256"
                ],
            },
            sort_keys=True,
        ),
        evidence=json.dumps(payload["information_boundary"], sort_keys=True),
        domain="prospective full-round order commitment",
        quality_score=1.0,
    )
    writer.add_triplet(
        trigger="A313:independently_confirmed_calibration_prefix",
        mechanism="annotation_only_across_frozen_A329_family",
        outcome="A329:A313_rank_annotation_without_selection",
        confidence=1.0,
        source=A313_RESULT_SHA256,
        quantification=json.dumps(payload["A313_annotation"], sort_keys=True),
        evidence="ZERO_A313_CANDIDATE_SELECTION_ZERO_A322_A325_LABELS",
        domain="calibration annotation",
        quality_score=1.0,
    )
    writer.add_triplet(
        trigger="A328:complete_target_blind_stable_switched_partition",
        mechanism="materialized_stability_merge_commitment_chain",
        outcome=terminal,
        confidence=1.0,
        source="materialized:A329_stability_merge_chain",
        quantification="exact retained closure",
        evidence=payload["evidence_stage"],
        domain="AI-native retained inference",
        quality_score=1.0,
        is_inferred=True,
    )
    writer.add_cluster(
        name="A329 bounded-regret stability merge",
        entities=[
            "A328:complete_target_blind_stable_switched_partition",
            "A329:five_exact_W44_W45_orders",
            terminal,
            "A329:A313_rank_annotation_without_selection",
        ],
    )
    writer.add_gap(
        subject=terminal,
        predicate="next_required_object",
        expected_object_type="confirmed_A322_prefix_rank_in_primary_raw_and_direction_control",
        confidence=1.0,
        suggested_queries=[
            "At the independently confirmed A322 prefix, does the prospectively frozen stable 2:1 primary beat raw Linf and the symmetric switched 2:1 control?"
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
        reader.api_id != "a329merg"
        or len(explicit) != 3
        or len(all_rows) != 4
        or len(inferred) != 1
        or len(reader._rules) != 3
        or len(reader._clusters) != 1
        or len(reader._gaps) != 1
    ):
        raise RuntimeError("A329 authentic Causal reopen gate failed")
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
        raise FileExistsError("A329 artifacts already exist")
    if A322_RESULT.exists():
        raise RuntimeError("A329 must freeze before any A322 result exists")
    if A325_PROGRESS.exists() or A325_RESULT.exists():
        raise RuntimeError("A329 must freeze before any A325 execution or result exists")
    family = build_family()
    summary = candidate_summary(family["candidates"])
    payload: dict[str, Any] = {
        "schema": "chacha20-round20-linf-stability-merge-a329-order-v1",
        "attempt_id": ATTEMPT_ID,
        "evidence_stage": "PROSPECTIVE_TARGET_BLIND_STABILITY_MERGE_FAMILY_RETAINED",
        "design_sha256": DESIGN_SHA256,
        "stable_cells": family["stable_cells"],
        "switched_cells": family["switched_cells"],
        "stable_fraction": family["stable_fraction"],
        "A328_stable_to_switched_rho_ratio": family[
            "A328_stable_to_switched_rho_ratio"
        ],
        "candidate_sequence_and_tie_break": list(CANDIDATE_NAMES),
        "candidates": family["candidates"],
        "candidate_summary": summary,
        "primary_operator": family["primary_operator"],
        "matched_direction_control": family["matched_direction_control"],
        "primary_W45_order": family["primary_W45_order"],
        "primary_W45_order_uint16be_sha256": family[
            "primary_W45_order_uint16be_sha256"
        ],
        "control_W45_order": family["control_W45_order"],
        "control_W45_order_uint16be_sha256": family[
            "control_W45_order_uint16be_sha256"
        ],
        "A313_annotation": family["A313_annotation"],
        "information_boundary": family["design"]["information_boundary"],
        "future_evaluation_contract": {
            "A322": "compute raw, primary, matched-control and comparator ranks only after independent confirmation of the single complete A322 execution",
            "A325": "compute the same frozen ranks only after independent confirmation of the single complete A325 execution",
            "duplicate_candidate_execution_required": False,
        },
        "anchors": {
            "design": anchor(DESIGN, DESIGN_SHA256),
            "A313_result": anchor(A313_RESULT, A313_RESULT_SHA256),
            "A321_order": anchor(A321_ORDER, A321_ORDER_SHA256),
            "A327_order": anchor(A327_ORDER, A327_ORDER_SHA256),
            "A328_result": anchor(A328_RESULT, A328_RESULT_SHA256),
            "A328_runner": anchor(A328_RUNNER, A328_RUNNER_SHA256),
            "runner": anchor(Path(__file__)),
            "test": anchor(A329_TEST),
            "reproducer": anchor(A329_REPRO),
        },
    }
    payload["commitment_sha256"] = canonical_sha256(
        {
            "design_sha256": DESIGN_SHA256,
            "candidate_summary": summary,
            "primary_operator": payload["primary_operator"],
            "primary_W45_order": payload["primary_W45_order"],
            "matched_direction_control": payload["matched_direction_control"],
            "control_W45_order": payload["control_W45_order"],
            "information_boundary": payload["information_boundary"],
        }
    )
    payload["measurement_sha256"] = canonical_sha256(
        {
            "stable_cells": payload["stable_cells"],
            "switched_cells": payload["switched_cells"],
            "A328_stable_to_switched_rho_ratio": payload[
                "A328_stable_to_switched_rho_ratio"
            ],
            "candidate_summary": summary,
            "A313_annotation": payload["A313_annotation"],
            "information_boundary": payload["information_boundary"],
        }
    )
    payload["causal"] = build_causal(payload)
    atomic_json(ORDER, payload)
    annotation = payload["A313_annotation"]["candidate_ranks_one_based"]
    atomic_bytes(
        REPORT,
        (
            "# A329 — bounded-regret Linf stability merge\n\n"
            f"- Stable/switched cells: **{payload['stable_cells']:,} / {payload['switched_cells']:,}**\n"
            f"- A328 stable/switched rho ratio: **{payload['A328_stable_to_switched_rho_ratio']:.6f}**\n"
            f"- Frozen primary: **{PRIMARY}** (`{payload['primary_W45_order_uint16be_sha256']}`)\n"
            f"- Matched direction control: **{CONTROL}** (`{payload['control_W45_order_uint16be_sha256']}`)\n"
            f"- A313 W44 ranks, raw / primary / control: **{annotation['original_raw_linf']['W44']} / {annotation[PRIMARY]['W44']} / {annotation[CONTROL]['W44']}**\n"
            "- Candidate selection from A313: **none**\n"
            "- A322/A325 labels, results, refits and duplicate executions: **zero**\n"
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
                "commitment_sha256": payload["commitment_sha256"],
                "primary_operator": payload["primary_operator"],
                "primary_W45_order_uint16be_sha256": payload[
                    "primary_W45_order_uint16be_sha256"
                ],
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

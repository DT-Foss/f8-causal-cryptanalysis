#!/usr/bin/env python3
"""A338: evaluate every A332-A337 W45 order frozen before the A322 result."""

from __future__ import annotations

import argparse
import hashlib
import inspect
import json
import math
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

DESIGN = CONFIGS / "chacha20_round20_extended_pre_result_rank_panel_a338_design_v1.json"
RESULT = RESULTS / "chacha20_round20_extended_pre_result_rank_panel_a338_v1.json"
CAUSAL = RESULTS / "chacha20_round20_extended_pre_result_rank_panel_a338_v1.causal"
REPORT = RESULTS / "chacha20_round20_extended_pre_result_rank_panel_a338_v1.md"

A322_RESULT = RESULTS / "chacha20_round20_holdout_selected_w45_recovery_a322_v1.json"
A330_EVALUATION = RESULTS / "chacha20_round20_w45_frozen_operator_panel_a330_evaluation_v1.json"
A332_ORDER = RESULTS / "chacha20_round20_margin_consistency_wavefront_a332_order_v1.json"
A333_ORDER = RESULTS / "chacha20_round20_cross_width_rank_velocity_a333_order_v1.json"
A334_ORDER = RESULTS / "chacha20_round20_walk_forward_structural_ensemble_a334_order_v1.json"
A335_ORDER = RESULTS / "chacha20_round20_multiview_rank_smoothing_a335_order_v1.json"
A336_ORDER = RESULTS / "chacha20_round20_multiview_forecast_fusion_a336_order_v1.json"
A337_ORDER = RESULTS / "chacha20_round20_linf_l2_weight_simplex_a337_order_v1.json"
A338_TEST = ROOT / "tests/test_chacha20_round20_extended_pre_result_rank_panel_a338.py"
A338_REPRO = ROOT / "scripts/reproduce_chacha20_round20_extended_pre_result_rank_panel_a338.sh"

ATTEMPT_ID = "A338"
DESIGN_SHA256 = "8d98b893bcf52419b1304024da64cc643069d3b78d22c48bc8f7a94f16298265"
ANCHOR_SHA256 = {
    A322_RESULT: "d5354b58cf558dee701d5cd81ed1c1103517997b88719136db82bdc0e2f0a687",
    A330_EVALUATION: "accf1d15369d600a8f53456db336b254f70d14da4b299fb9b9239eae739e66ca",
    A332_ORDER: "b6e0a5ca2a819194cde74dacda51ce0ac7b8e7d051e5dc854ad3599b545353ad",
    A333_ORDER: "4cd1c0ce67e50df687548d0cf6a5f921ff91767c077d25f39b158a4263de4b5c",
    A334_ORDER: "2cf5c72675f31be60a5e8a896735953dba12fb3a5864f3e9c6e700093bfc024e",
    A335_ORDER: "80e63e65ca8139e2b893670c093ddfbd7451e6cf1e024b64aff18950b6344f75",
    A336_ORDER: "c8ab47d6de41740fb216861cf2d135568d4aadd1bbcf9bdf5e4fa20ea5344d4c",
    A337_ORDER: "16b580081dd1dcea74ba0ca7357e2dfb14b5c50b66bc9f300bbc7d5577f8ceea",
}
CELLS = 1 << 12
CANDIDATES_PER_GROUP = 1 << 33
COMPLETE_DOMAIN = 1 << 45
EXPECTED_ALIAS_COUNT = 89
EXPECTED_UNIQUE_COUNT = 70
EXECUTED_RAW_RANK = 1459
EXECUTED_RAW_SHA = "5d1afc37614fdbe050e9853413a3de7b850b876e9bc5649d3dffcf3e23c9780a"
SELECTED_ALIASES = (
    "A332/consistency_min_rank_wavefront",
    "A333/midpoint_alpha_minus_1_over_2",
    "A334/temporal_midpoint_only",
    "A335/midpoint_alpha_minus_1_over_2/nearest_prototype_Linf",
    "A336/linf_l2_equal_borda",
    "A337/linf09_l2_07",
)

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
        raise RuntimeError(f"A338 anchor differs: {path}")
    return {"path": relative(path), "sha256": observed}


def exact_order(values: Sequence[int], label: str) -> list[int]:
    order = [int(value) for value in values]
    if len(order) != CELLS or set(order) != set(range(CELLS)):
        raise ValueError(f"A338 {label} is not an exact 4,096-cell cover")
    return order


def order_sha(order: Sequence[int]) -> str:
    return hashlib.sha256(
        b"".join(cell.to_bytes(2, "big") for cell in exact_order(order, "hash"))
    ).hexdigest()


def load_design() -> dict[str, Any]:
    if file_sha256(DESIGN) != DESIGN_SHA256:
        raise RuntimeError("A338 design hash differs")
    design = json.loads(DESIGN.read_bytes())
    contract = design.get("panel_contract", {})
    boundary = design.get("information_boundary", {})
    if (
        design.get("schema")
        != "chacha20-round20-extended-pre-result-rank-panel-a338-design-v1"
        or design.get("attempt_id") != ATTEMPT_ID
        or design.get("design_state")
        != "postconfirmation_evaluator_over_hash_frozen_pre_A322_result_orders"
        or contract.get("expected_alias_count") != EXPECTED_ALIAS_COUNT
        or contract.get("expected_unique_order_count") != EXPECTED_UNIQUE_COUNT
        or tuple(design.get("designated_selected_aliases", ())) != SELECTED_ALIASES
        or contract.get("global_descriptive_winner_is_prospectively_selected") is not False
        or contract.get("counterfactual_candidate_execution") is not False
        or contract.get("counterfactual_matched_control_outcome_inference") is not False
        or boundary.get("orders_refit_after_A322_result") is not False
        or boundary.get("new_candidate_orders_created_by_A338") is not False
        or boundary.get("duplicate_candidate_execution") is not False
        or boundary.get("matched_control_outcomes_inferred") is not False
    ):
        raise RuntimeError("A338 frozen evaluation design differs")
    for key, value in design["source_anchors"].items():
        if key.endswith("_path"):
            anchor(
                ROOT / value,
                design["source_anchors"][key.removesuffix("_path") + "_sha256"],
            )
    return design


def verify_pre_result_boundary(attempt: str, payload: Mapping[str, Any]) -> None:
    boundary = payload.get("information_boundary", {})
    if boundary.get("A322_result_available_at_design_freeze") is not False:
        raise RuntimeError(f"A338 {attempt} does not bind A322-result absence")
    progress_keys = [key for key in boundary if key.startswith("A322_progress_used")]
    if len(progress_keys) != 1 or boundary[progress_keys[0]] is not False:
        raise RuntimeError(f"A338 {attempt} progress-use boundary differs")
    label_keys = [key for key in boundary if key.startswith("target_labels_used")]
    if not label_keys or any(boundary[key] != 0 for key in label_keys):
        raise RuntimeError(f"A338 {attempt} target-label boundary differs")


def source_row(
    *,
    alias: str,
    order: Sequence[int],
    expected_sha256: str,
    source_attempt: str,
    role: str,
    selected: bool,
    eligible: bool,
    complete_field_spearman: float | None,
) -> dict[str, Any]:
    exact = exact_order(order, alias)
    observed = order_sha(exact)
    if observed != expected_sha256:
        raise RuntimeError(f"A338 source order hash differs: {alias}")
    return {
        "alias": alias,
        "source_attempt": source_attempt,
        "role": role,
        "prospectively_selected_in_source": selected,
        "source_selection_eligible": eligible,
        "complete_field_spearman": complete_field_spearman,
        "W45_order_uint16be_sha256": observed,
        "W45_order": exact,
    }


def extract_sources() -> list[dict[str, Any]]:
    for path, expected in ANCHOR_SHA256.items():
        anchor(path, expected)
    rows: list[dict[str, Any]] = []

    a332 = json.loads(A332_ORDER.read_bytes())
    verify_pre_result_boundary("A332", a332)
    for name, row in a332["candidates"].items():
        control = "control" in name
        rows.append(
            source_row(
                alias=f"A332/{name}",
                order=row["W45_order"],
                expected_sha256=row["W45_order_uint16be_sha256"],
                source_attempt="A332",
                role="fixed_control" if control else "candidate",
                selected=name == a332["primary_operator"],
                eligible=not control,
                complete_field_spearman=float(row["cross_width_spearman"]),
            )
        )

    a333 = json.loads(A333_ORDER.read_bytes())
    verify_pre_result_boundary("A333", a333)
    selected = a333["selection"]["selected_operator"]
    control = a333["selection"]["fixed_direction_control"]
    for name, row in a333["training"].items():
        rows.append(
            source_row(
                alias=f"A333/{name}",
                order=row["predicted_W45_order"],
                expected_sha256=row["predicted_W45_order_uint16be_sha256"],
                source_attempt="A333",
                role="fixed_direction_control" if name == control else "candidate",
                selected=name == selected,
                eligible=name != control,
                complete_field_spearman=float(
                    row["metrics_against_complete_target_blind_W45_field"]["spearman"]
                ),
            )
        )

    a334 = json.loads(A334_ORDER.read_bytes())
    verify_pre_result_boundary("A334", a334)
    selected = a334["selection"]["selected_operator"]
    for name, row in a334["training"].items():
        eligible = bool(row["selection_eligible"])
        rows.append(
            source_row(
                alias=f"A334/{name}",
                order=row["predicted_W45_order"],
                expected_sha256=row["predicted_W45_order_uint16be_sha256"],
                source_attempt="A334",
                role="candidate" if eligible else "fixed_direction_control",
                selected=name == selected,
                eligible=eligible,
                complete_field_spearman=float(
                    row["metrics_against_complete_target_blind_W45_raw_field"]["spearman"]
                ),
            )
        )

    a335 = json.loads(A335_ORDER.read_bytes())
    verify_pre_result_boundary("A335", a335)
    selected = a335["selection"]["selected_operator"]
    control = a335["selection"]["fixed_direction_control"]
    primary_view = a335["primary_view"]
    for coefficient, coefficient_row in a335["candidates"].items():
        for view, row in coefficient_row["per_view"].items():
            is_selected = coefficient == selected and view == primary_view
            if coefficient == control:
                role = "fixed_direction_control_view"
            elif coefficient == selected and view != primary_view:
                role = "selected_coefficient_other_view"
            else:
                role = "eligible_coefficient_view"
            rows.append(
                source_row(
                    alias=f"A335/{coefficient}/{view}",
                    order=row["predicted_W45_order"],
                    expected_sha256=row["predicted_W45_order_uint16be_sha256"],
                    source_attempt="A335",
                    role=role,
                    selected=is_selected,
                    eligible=coefficient != control,
                    complete_field_spearman=float(row["metrics"]["spearman"]),
                )
            )

    a336 = json.loads(A336_ORDER.read_bytes())
    verify_pre_result_boundary("A336", a336)
    selected = a336["selection"]["selected_operator"]
    for name, row in a336["training"].items():
        eligible = bool(row["selection_eligible"])
        rows.append(
            source_row(
                alias=f"A336/{name}",
                order=row["predicted_W45_order"],
                expected_sha256=row["predicted_W45_order_uint16be_sha256"],
                source_attempt="A336",
                role="candidate" if eligible else "fixed_control",
                selected=name == selected,
                eligible=eligible,
                complete_field_spearman=float(
                    row["metrics_against_complete_target_blind_W45_Linf"]["spearman"]
                ),
            )
        )

    a337 = json.loads(A337_ORDER.read_bytes())
    verify_pre_result_boundary("A337", a337)
    selected = a337["selection"]["selected_operator"]
    for name, row in a337["training"].items():
        rows.append(
            source_row(
                alias=f"A337/{name}",
                order=row["predicted_W45_order"],
                expected_sha256=row["predicted_W45_order_uint16be_sha256"],
                source_attempt="A337",
                role="exact_weight_candidate",
                selected=name == selected,
                eligible=True,
                complete_field_spearman=float(
                    row["metrics_against_complete_target_blind_W45_Linf"]["spearman"]
                ),
            )
        )

    if len(rows) != EXPECTED_ALIAS_COUNT:
        raise RuntimeError("A338 alias count differs")
    if tuple(row["alias"] for row in rows if row["prospectively_selected_in_source"]) != SELECTED_ALIASES:
        raise RuntimeError("A338 selected-alias identity differs")
    if len({row["W45_order_uint16be_sha256"] for row in rows}) != EXPECTED_UNIQUE_COUNT:
        raise RuntimeError("A338 unique-order count differs")
    return rows


def rank_metrics(rank: int) -> dict[str, Any]:
    return {
        "rank_one_based": rank,
        "counterfactual_complete_group_assignments": rank * CANDIDATES_PER_GROUP,
        "gain_bits_vs_complete_2pow45_domain": math.log2(CELLS / rank),
        "domain_reduction_factor": CELLS / rank,
        "speed_factor_vs_executed_raw_Linf": EXECUTED_RAW_RANK / rank,
        "candidate_execution_performed_for_this_order": False,
        "matched_control_outcome_inferred": False,
    }


def build_panel() -> dict[str, Any]:
    design = load_design()
    sources = extract_sources()
    a322 = json.loads(A322_RESULT.read_bytes())
    a330 = json.loads(A330_EVALUATION.read_bytes())
    if (
        a322.get("confirmation", {}).get("all_blocks_match") is not True
        or a322.get("discovery", {}).get("matched_control_candidates") != 0
        or a330.get("confirmed_prefix", {}).get("dual_confirmation") is not True
        or a330.get("designated_rank_comparisons", {})
        .get("executed_A322_order", {})
        .get("rank_one_based")
        != EXECUTED_RAW_RANK
    ):
        raise RuntimeError("A338 A322/A330 confirmation baseline differs")
    prefix = int(a322["discovery"]["prefix12"])
    alias_metrics: dict[str, Any] = {}
    groups: dict[str, list[str]] = defaultdict(list)
    source_orders: dict[str, list[int]] = {}
    for row in sources:
        rank = row["W45_order"].index(prefix) + 1
        alias_metrics[row["alias"]] = {
            key: row[key]
            for key in (
                "source_attempt",
                "role",
                "prospectively_selected_in_source",
                "source_selection_eligible",
                "complete_field_spearman",
                "W45_order_uint16be_sha256",
            )
        } | rank_metrics(rank)
        groups[row["W45_order_uint16be_sha256"]].append(row["alias"])
        source_orders[row["alias"]] = row["W45_order"]
    unique_panel = []
    for index, (sha, aliases) in enumerate(groups.items()):
        canonical = aliases[0]
        unique_panel.append(
            {
                "unique_id": f"u{index:02d}",
                "W45_order_uint16be_sha256": sha,
                "canonical_alias": canonical,
                "aliases": aliases,
                **rank_metrics(alias_metrics[canonical]["rank_one_based"]),
            }
        )
    family_winners = {}
    for attempt in ("A332", "A333", "A334", "A335", "A336", "A337"):
        aliases = [alias for alias in alias_metrics if alias.startswith(f"{attempt}/")]
        winner = min(aliases, key=lambda alias: (alias_metrics[alias]["rank_one_based"], alias))
        family_winners[attempt] = {"alias": winner, **alias_metrics[winner]}
    selected_metrics = {alias: alias_metrics[alias] for alias in SELECTED_ALIASES}
    global_winner = min(
        alias_metrics,
        key=lambda alias: (alias_metrics[alias]["rank_one_based"], alias),
    )
    top_aliases = sorted(
        alias_metrics,
        key=lambda alias: (alias_metrics[alias]["rank_one_based"], alias),
    )[:20]
    return {
        "design": design,
        "prefix": prefix,
        "alias_metrics": alias_metrics,
        "unique_panel": unique_panel,
        "family_winners": family_winners,
        "selected_metrics": selected_metrics,
        "global_winner": {"alias": global_winner, **alias_metrics[global_winner]},
        "top20": [{"alias": alias, **alias_metrics[alias]} for alias in top_aliases],
        "source_orders": source_orders,
    }


def build_causal(payload: Mapping[str, Any]) -> dict[str, Any]:
    from dotcausal.io import CausalReader, CausalWriter

    terminal = "A338:extended_pre_result_target_rank_boundary"
    writer = CausalWriter(api_id="a338ext")
    writer._rules = []
    writer.add_rule(
        name="frozen_sources_and_confirmed_prefix_to_extended_panel",
        description="All 89 hash-frozen pre-result orders receive the same independently confirmed A322 prefix lookup.",
        pattern=["A332_A337_hash_frozen_orders", "A322_confirmed_prefix"],
        conclusion="A338_89_alias_70_order_rank_panel",
        confidence_modifier=1.0,
    )
    writer.add_rule(
        name="selected_orders_to_localization_boundary",
        description="Source-selected complete-field operators are compared only through their already-frozen target-cell ranks.",
        pattern=["A338_selected_source_orders", "A338_exact_rank_panel"],
        conclusion="A338_complete_field_selection_target_cell_boundary",
        confidence_modifier=1.0,
    )
    writer.add_rule(
        name="descriptive_coarse_winner_to_W46_breadcrumb",
        description="The nonselected frozen coarse carry-forward winner becomes a prospective W46 counterfactual breadcrumb, not a retroactive A322 selection.",
        pattern=["A338_descriptive_coarse_winner", "A325_not_executed"],
        conclusion="freeze_W46_coarse_counterfactual_without_rewriting_A325",
        confidence_modifier=1.0,
    )
    writer.add_triplet(
        trigger="A332-A337:89_hash_frozen_pre_result_orders",
        mechanism="exact_confirmed_prefix_lookup_and_SHA_deduplication",
        outcome="A338:70_unique_order_rank_panel",
        confidence=1.0,
        source=payload["measurement_sha256"],
        quantification=json.dumps(
            {"aliases": payload["alias_count"], "unique_orders": payload["unique_order_count"]},
            sort_keys=True,
        ),
        evidence="ZERO_REFITS_ZERO_DUPLICATE_EXECUTION",
        domain="AI-native postconfirmation order inference",
        quality_score=1.0,
    )
    writer.add_triplet(
        trigger="A338:source_selected_complete_field_operators",
        mechanism="exact_A322_target_cell_rank_comparison",
        outcome=terminal,
        confidence=1.0,
        source=payload["measurement_sha256"],
        quantification=json.dumps(payload["selected_source_rank_panel"], sort_keys=True),
        evidence="COMPLETE_FIELD_TRANSFER_SELECTION_DOES_NOT_PREDICT_THIS_TARGET_CELL_RANK",
        domain="selection-localization boundary",
        quality_score=1.0,
    )
    writer.add_triplet(
        trigger="A335:pre_result_carry_forward_coarse_order",
        mechanism="rank_12_on_independently_confirmed_A322_prefix",
        outcome="A338:prospective_W46_coarse_counterfactual_breadcrumb",
        confidence=1.0,
        source=payload["commitment_sha256"],
        quantification=json.dumps(payload["global_descriptive_winner"], sort_keys=True),
        evidence="DESCRIPTIVE_NOT_PROSPECTIVELY_SELECTED_FOR_A322",
        domain="target-cell localization breadcrumb",
        quality_score=1.0,
    )
    writer.add_triplet(
        trigger="A332-A337:89_hash_frozen_pre_result_orders",
        mechanism="materialized_extended_rank_inference_chain",
        outcome=terminal,
        confidence=1.0,
        source="materialized:A338_extended_rank_chain",
        quantification="exact retained closure",
        evidence=payload["evidence_stage"],
        domain="AI-native retained inference",
        quality_score=1.0,
        is_inferred=True,
    )
    writer.add_cluster(
        name="A338 extended pre-result target-rank panel",
        entities=[
            "A332-A337:89_hash_frozen_pre_result_orders",
            "A338:70_unique_order_rank_panel",
            "A338:source_selected_complete_field_operators",
            terminal,
            "A335:pre_result_carry_forward_coarse_order",
            "A338:prospective_W46_coarse_counterfactual_breadcrumb",
        ],
    )
    writer.add_gap(
        subject="A338:prospective_W46_coarse_counterfactual_breadcrumb",
        predicate="next_required_object",
        expected_object_type="frozen_W46_coarse_carry_forward_and_raw_Linf_factor_two_portfolio",
        confidence=1.0,
        suggested_queries=[
            "Can the exact W45 coarse order be frozen as a W46 carry-forward counterfactual and paired with raw Linf before A325 execution without rewriting its protocol?"
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
        reader.api_id != "a338ext"
        or len(explicit) != 3
        or len(all_rows) != 4
        or len(inferred) != 1
        or len(reader._rules) != 3
        or len(reader._clusters) != 1
        or len(reader._gaps) != 1
    ):
        raise RuntimeError("A338 authentic Causal reopen gate failed")
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
        raise FileExistsError("A338 artifacts already exist")
    built = build_panel()
    winner = built["global_winner"]
    if winner["alias"] != "A335/carry_forward_alpha_0/coarse" or winner["rank_one_based"] != 12:
        raise RuntimeError("A338 predeclared exact winner identity differs")
    payload: dict[str, Any] = {
        "schema": "chacha20-round20-extended-pre-result-rank-panel-a338-v1",
        "attempt_id": ATTEMPT_ID,
        "evidence_stage": "POSTCONFIRMATION_EXTENDED_PRE_RESULT_TARGET_RANK_BOUNDARY_RETAINED",
        "design_sha256": DESIGN_SHA256,
        "A322_result_sha256": ANCHOR_SHA256[A322_RESULT],
        "confirmed_prefix": {
            "prefix12": built["prefix"],
            "prefix12_hex": f"{built['prefix']:03x}",
            "dual_confirmation": True,
        },
        "alias_count": len(built["alias_metrics"]),
        "unique_order_count": len(built["unique_panel"]),
        "alias_rank_panel": built["alias_metrics"],
        "unique_rank_panel": built["unique_panel"],
        "family_winners": built["family_winners"],
        "selected_source_rank_panel": built["selected_metrics"],
        "global_descriptive_winner": {
            **winner,
            "prospectively_selected_for_A322": False,
            "descriptive_breadcrumb_only": True,
        },
        "top20_aliases": built["top20"],
        "executed_raw_Linf_baseline": {
            "rank_one_based": EXECUTED_RAW_RANK,
            "W45_order_uint16be_sha256": EXECUTED_RAW_SHA,
            **rank_metrics(EXECUTED_RAW_RANK),
        },
        "interpretation": {
            "retained_boundary": "complete-field or cross-width global rank correlation is not a target-cell localization objective",
            "new_breadcrumb": "the frozen W44 coarse carry-forward order localizes this unseen W45 prefix at rank 12",
            "retroactive_selection_claimed": False,
            "next_action": "freeze W46 coarse carry-forward and raw-Linf factor-two portfolio before A325 execution without rewriting A325",
        },
        "evaluation_boundary": built["design"]["information_boundary"],
        "anchors": {
            "design": anchor(DESIGN, DESIGN_SHA256),
            "A322_result": anchor(A322_RESULT, ANCHOR_SHA256[A322_RESULT]),
            "A330_evaluation": anchor(A330_EVALUATION, ANCHOR_SHA256[A330_EVALUATION]),
            "A332_order": anchor(A332_ORDER, ANCHOR_SHA256[A332_ORDER]),
            "A333_order": anchor(A333_ORDER, ANCHOR_SHA256[A333_ORDER]),
            "A334_order": anchor(A334_ORDER, ANCHOR_SHA256[A334_ORDER]),
            "A335_order": anchor(A335_ORDER, ANCHOR_SHA256[A335_ORDER]),
            "A336_order": anchor(A336_ORDER, ANCHOR_SHA256[A336_ORDER]),
            "A337_order": anchor(A337_ORDER, ANCHOR_SHA256[A337_ORDER]),
            "runner": anchor(Path(__file__)),
            "test": anchor(A338_TEST),
            "reproducer": anchor(A338_REPRO),
        },
    }
    payload["commitment_sha256"] = canonical_sha256(
        {
            "design_sha256": DESIGN_SHA256,
            "A322_result_sha256": payload["A322_result_sha256"],
            "confirmed_prefix": payload["confirmed_prefix"],
            "alias_order_hashes": {
                alias: row["W45_order_uint16be_sha256"]
                for alias, row in payload["alias_rank_panel"].items()
            },
            "evaluation_boundary": payload["evaluation_boundary"],
        }
    )
    payload["measurement_sha256"] = canonical_sha256(
        {
            "alias_rank_panel": payload["alias_rank_panel"],
            "unique_rank_panel": payload["unique_rank_panel"],
            "family_winners": payload["family_winners"],
            "selected_source_rank_panel": payload["selected_source_rank_panel"],
            "global_descriptive_winner": payload["global_descriptive_winner"],
        }
    )
    payload["causal"] = build_causal(payload)
    atomic_json(RESULT, payload)
    raw = payload["executed_raw_Linf_baseline"]
    atomic_bytes(
        REPORT,
        (
            "# A338 — extended pre-result W45 target-rank panel\n\n"
            f"- Frozen aliases / unique orders: **{payload['alias_count']} / {payload['unique_order_count']}**\n"
            f"- Confirmed A322 prefix: **0x{built['prefix']:03x}**\n"
            f"- Descriptive pre-result winner: **{winner['alias']}**, rank **{winner['rank_one_based']} / 4,096**\n"
            f"- Candidate count to that prefix: **{winner['counterfactual_complete_group_assignments']:,}**\n"
            f"- Search gain / domain reduction: **{winner['gain_bits_vs_complete_2pow45_domain']:.8f} bits / {winner['domain_reduction_factor']:.3f}x**\n"
            f"- Relative to executed raw Linf: **{winner['speed_factor_vs_executed_raw_Linf']:.3f}x earlier**\n"
            f"- Executed raw-Linf rank: **{raw['rank_one_based']} / 4,096**\n"
            "- Winner role: **descriptive breadcrumb, not retroactive selection**\n"
            "- Duplicate candidate executions / inferred controls: **zero / zero**\n"
            "- Authentic AI-native Causal readback: **3 explicit + 1 inferred chain**\n"
        ).encode(),
    )
    return payload


def analyze() -> dict[str, Any]:
    response: dict[str, Any] = {
        "attempt_id": ATTEMPT_ID,
        "design_sha256": DESIGN_SHA256,
        "result_exists": RESULT.exists(),
    }
    if RESULT.exists():
        payload = json.loads(RESULT.read_bytes())
        response.update(
            {
                "result_sha256": file_sha256(RESULT),
                "commitment_sha256": payload["commitment_sha256"],
                "measurement_sha256": payload["measurement_sha256"],
                "alias_count": payload["alias_count"],
                "unique_order_count": payload["unique_order_count"],
                "global_descriptive_winner": payload["global_descriptive_winner"],
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

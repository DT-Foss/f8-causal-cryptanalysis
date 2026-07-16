#!/usr/bin/env python3
"""A343: freeze and later evaluate every pre-result W46 operator order."""

from __future__ import annotations

import argparse
import hashlib
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

DESIGN = CONFIGS / "chacha20_round20_w46_pre_result_operator_panel_a343_design_v1.json"
PANEL = RESULTS / "chacha20_round20_w46_pre_result_operator_panel_a343_v1.json"
PANEL_CAUSAL = RESULTS / "chacha20_round20_w46_pre_result_operator_panel_a343_v1.causal"
PANEL_REPORT = RESULTS / "chacha20_round20_w46_pre_result_operator_panel_a343_v1.md"
EVALUATION = RESULTS / "chacha20_round20_w46_pre_result_operator_panel_a343_evaluation_v1.json"
EVALUATION_CAUSAL = RESULTS / "chacha20_round20_w46_pre_result_operator_panel_a343_evaluation_v1.causal"
EVALUATION_REPORT = RESULTS / "chacha20_round20_w46_pre_result_operator_panel_a343_evaluation_v1.md"

A325_PROTOCOL = CONFIGS / "chacha20_round20_holdout_selected_w46_recovery_a325_v1.json"
A325_PROGRESS = RESULTS / "chacha20_round20_holdout_selected_w46_recovery_a325_progress_v1.json"
A325_RESULT = RESULTS / "chacha20_round20_holdout_selected_w46_recovery_a325_v1.json"
A333_ORDER = RESULTS / "chacha20_round20_cross_width_rank_velocity_a333_order_v1.json"
A334_ORDER = RESULTS / "chacha20_round20_walk_forward_structural_ensemble_a334_order_v1.json"
A335_ORDER = RESULTS / "chacha20_round20_multiview_rank_smoothing_a335_order_v1.json"
A336_ORDER = RESULTS / "chacha20_round20_multiview_forecast_fusion_a336_order_v1.json"
A337_ORDER = RESULTS / "chacha20_round20_linf_l2_weight_simplex_a337_order_v1.json"
A339_ORDER = RESULTS / "chacha20_round20_w46_coarse_carry_forward_a339_order_v1.json"
A340_ORDER = RESULTS / "chacha20_round20_w46_target_conditioned_causal_order_a340_order_v1.json"
A341_ORDER = RESULTS / "chacha20_round20_w46_familywise_channel_portfolio_a341_v1.json"
A342_ORDER = RESULTS / "chacha20_round20_w46_exhaustive_reader_ensemble_a342_v1.json"
A343_TEST = ROOT / "tests/test_chacha20_round20_w46_pre_result_operator_panel_a343.py"
A343_REPRO = ROOT / "scripts/reproduce_chacha20_round20_w46_pre_result_operator_panel_a343.sh"

ATTEMPT_ID = "A343"
DESIGN_SHA256 = "fc46cee8ff8f627e4458c49e11de7bd2512c29f3c8a240a450aa80ee93d24e84"
A325_PROTOCOL_SHA256 = "480fe15f22c87df1b9422c1dc8cfcf5a9add147f65b6631d25e94d66b5255a2c"
SOURCE_PATHS = {
    "A333": A333_ORDER,
    "A334": A334_ORDER,
    "A335": A335_ORDER,
    "A336": A336_ORDER,
    "A337": A337_ORDER,
    "A339": A339_ORDER,
    "A340": A340_ORDER,
    "A341": A341_ORDER,
    "A342": A342_ORDER,
}
SOURCE_SHA256 = {
    "A333": "4cd1c0ce67e50df687548d0cf6a5f921ff91767c077d25f39b158a4263de4b5c",
    "A334": "2cf5c72675f31be60a5e8a896735953dba12fb3a5864f3e9c6e700093bfc024e",
    "A335": "80e63e65ca8139e2b893670c093ddfbd7451e6cf1e024b64aff18950b6344f75",
    "A336": "c8ab47d6de41740fb216861cf2d135568d4aadd1bbcf9bdf5e4fa20ea5344d4c",
    "A337": "16b580081dd1dcea74ba0ca7357e2dfb14b5c50b66bc9f300bbc7d5577f8ceea",
    "A339": "7bdf6ee303f61b489cb491df91c30aa400928cf361eaef862945a25d58ac9b9b",
    "A340": "ecc69f2b8b536381d5c56c35a64328aae2c4e516cab10c3ce9c46ea84d1916a8",
    "A341": "4ebc8041d469a57e064a31eb3099a46cb8a8dd998090b9fef70a3e9233fef7d6",
    "A342": "8d6d6f99b89d67d7eff186037934bfa515cf93a00af10b244826f44056b4cebb",
}
FAMILY_ORDER = tuple(SOURCE_PATHS)
CELLS = 1 << 12
CANDIDATES_PER_GROUP = 1 << 34
COMPLETE_DOMAIN = 1 << 46
EXPECTED_ALIAS_COUNT = 73
EXPECTED_UNIQUE_COUNT = 57
RAW_ORDER_SHA256 = "5d1afc37614fdbe050e9853413a3de7b850b876e9bc5649d3dffcf3e23c9780a"
DOTCAUSAL_SRC = Path(
    "/Users/bhkmie/Documents/Forschung/O1/vendor/fabel/dotcausal_package/src"
)


def file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def canonical_sha256(value: Any) -> str:
    return hashlib.sha256(
        json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode()
    ).hexdigest()


def atomic_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.tmp")
    temporary.write_text(
        json.dumps(payload, indent=2, sort_keys=True, allow_nan=False) + "\n"
    )
    os.replace(temporary, path)


def atomic_bytes(path: Path, payload: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
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
        raise RuntimeError(f"A343 anchor differs: {path}")
    return {"path": relative(path), "sha256": observed}


def exact_order(values: Sequence[int], label: str) -> list[int]:
    order = [int(value) for value in values]
    if len(order) != CELLS or set(order) != set(range(CELLS)):
        raise ValueError(f"A343 {label} is not an exact 4,096-cell cover")
    return order


def order_sha(values: Sequence[int]) -> str:
    return hashlib.sha256(
        b"".join(
            value.to_bytes(2, "big") for value in exact_order(values, "order hash")
        )
    ).hexdigest()


def load_design() -> dict[str, Any]:
    if file_sha256(DESIGN) != DESIGN_SHA256:
        raise RuntimeError("A343 design hash differs")
    design = json.loads(DESIGN.read_bytes())
    dedup = design.get("deduplication_contract", {})
    gate = design.get("evaluation_gate", {})
    boundary = design.get("information_boundary", {})
    if (
        design.get("schema")
        != "chacha20-round20-w46-pre-result-operator-panel-a343-design-v1"
        or design.get("attempt_id") != ATTEMPT_ID
        or design.get("design_state")
        != "frozen_while_A325_is_running_before_any_A325_result_candidate_or_prefix"
        or tuple(design.get("source_alias_order", {})) != FAMILY_ORDER
        or dedup.get("expected_alias_count") != EXPECTED_ALIAS_COUNT
        or dedup.get("expected_unique_order_count") != EXPECTED_UNIQUE_COUNT
        or dedup.get("identity")
        != "uint16be SHA-256 of the complete 4096-cell order"
        or dedup.get("all_aliases_retained") is not True
        or dedup.get("duplicate_candidate_execution") is not False
        or gate.get("A325_result_sha256_required_as_argument") is not True
        or gate.get("independent_confirmation_required") is not True
        or gate.get("orders_refit_after_A325") is not False
        or gate.get("new_candidate_execution") is not False
        or gate.get("matched_control_counterfactual_not_inferred") is not True
        or boundary.get("A325_execution_running_at_design_freeze") is not True
        or boundary.get("A325_progress_used_for_panel_membership_order_or_metrics")
        is not False
        or boundary.get("A325_result_available_at_design_freeze") is not False
        or boundary.get("A325_candidate_or_prefix_available_at_design_freeze")
        is not False
        or boundary.get("target_labels_used_to_construct_orders") != 0
        or boundary.get("duplicate_candidate_execution_required") is not False
    ):
        raise RuntimeError("A343 design semantics differ")
    anchors = design["source_anchors"]
    anchor(A325_PROTOCOL, anchors["A325_protocol_sha256"])
    for family, path in SOURCE_PATHS.items():
        anchor(path, anchors[f"{family}_order_sha256"])
    return design


def source_container(family: str, payload: Mapping[str, Any]) -> Mapping[str, Any]:
    if family == "A333":
        return payload["deployments"]
    if family in {"A334", "A335", "A336", "A337"}:
        return payload["deployment"]
    return payload["orders"]


def source_primary(family: str, payload: Mapping[str, Any]) -> str:
    if family == "A335":
        return str(payload["primary_view"])
    if family in {"A333", "A334", "A336", "A337"}:
        return str(payload["selection"]["selected_operator"])
    return str(payload["primary_operator"])


def source_protected(family: str, payload: Mapping[str, Any]) -> str | None:
    if family in {"A339", "A340", "A341", "A342"}:
        return str(payload["protected_operator"])
    return None


def source_order_row(
    family: str,
    name: str,
    payload: Mapping[str, Any],
    container: Mapping[str, Any],
) -> tuple[list[int], str]:
    if family in {"A333", "A334", "A335", "A336", "A337"}:
        row = container[name]
        return (
            exact_order(row["predicted_W46_order"], f"{family}/{name}"),
            str(row["predicted_W46_order_uint16be_sha256"]),
        )
    return (
        exact_order(container[name], f"{family}/{name}"),
        str(payload["order_uint16be_sha256"][name]),
    )


def source_aliases(design: Mapping[str, Any]) -> list[dict[str, Any]]:
    aliases: list[dict[str, Any]] = []
    for family in FAMILY_ORDER:
        path = SOURCE_PATHS[family]
        anchor(path, SOURCE_SHA256[family])
        payload = json.loads(path.read_bytes())
        if payload.get("attempt_id") != family:
            raise RuntimeError(f"A343 source attempt differs: {family}")
        boundary = payload.get("information_boundary", {})
        if boundary.get("target_prefix_labels_used", 0) != 0:
            raise RuntimeError(f"A343 source target-label boundary differs: {family}")
        container = source_container(family, payload)
        names = list(design["source_alias_order"][family])
        if len(names) != len(container) or set(names) != set(container):
            raise RuntimeError(f"A343 source membership differs: {family}")
        primary = source_primary(family, payload)
        protected = source_protected(family, payload)
        for name in names:
            order, declared = source_order_row(family, name, payload, container)
            observed = order_sha(order)
            if observed != declared:
                raise RuntimeError(f"A343 source order hash differs: {family}/{name}")
            if name == primary:
                role = "source_primary"
            elif name == protected:
                role = "protected_portfolio"
            elif "control" in name.lower() or "public_hash" in name.lower():
                role = "fixed_control"
            else:
                role = "frozen_candidate"
            aliases.append(
                {
                    "alias": f"{family}/{name}",
                    "family": family,
                    "name": name,
                    "source_role": role,
                    "source_primary": name == primary,
                    "source_protected": name == protected,
                    "W46_order_uint16be_sha256": observed,
                    "W46_order": order,
                }
            )
    if len(aliases) != EXPECTED_ALIAS_COUNT:
        raise RuntimeError("A343 alias count differs")
    return aliases


def build_panel() -> dict[str, Any]:
    design = load_design()
    aliases = source_aliases(design)
    unique_by_hash: dict[str, dict[str, Any]] = {}
    unique_orders: list[dict[str, Any]] = []
    alias_to_unique: dict[str, str] = {}
    for row in aliases:
        digest = row["W46_order_uint16be_sha256"]
        unique = unique_by_hash.get(digest)
        if unique is None:
            unique = {
                "unique_id": f"u{len(unique_orders):02d}",
                "W46_order_uint16be_sha256": digest,
                "canonical_alias": row["alias"],
                "aliases": [],
                "W46_order": row["W46_order"],
            }
            unique_by_hash[digest] = unique
            unique_orders.append(unique)
        elif unique["W46_order"] != row["W46_order"]:
            raise RuntimeError("A343 SHA collision or inconsistent exact order")
        unique["aliases"].append(row["alias"])
        alias_to_unique[row["alias"]] = unique["unique_id"]
    if len(unique_orders) != EXPECTED_UNIQUE_COUNT:
        raise RuntimeError("A343 unique-order count differs")
    designated = design["designated_comparisons"]
    if not designated or any(alias not in alias_to_unique for alias in designated.values()):
        raise RuntimeError("A343 designated comparison is absent")
    family_counts = dict(Counter(row["family"] for row in aliases))
    return {
        "design": design,
        "aliases": aliases,
        "unique_orders": unique_orders,
        "alias_to_unique_id": alias_to_unique,
        "designated_comparisons": designated,
        "family_counts": family_counts,
    }


def build_panel_causal(payload: Mapping[str, Any]) -> dict[str, Any]:
    sys.path.insert(0, str(DOTCAUSAL_SRC))
    from dotcausal.io import CausalReader, CausalWriter

    terminal = "A343:frozen_57_order_W46_postconfirmation_evaluator"
    writer = CausalWriter(api_id="a343pnl")
    writer._rules = []
    writer.add_rule(
        name="nine_pre_result_families_to_exact_alias_panel",
        description="Every complete W46 order frozen by A333-A342 before the A325 result enters one fixed alias sequence.",
        pattern=["nine_frozen_W46_families", "fixed_73_alias_sequence"],
        conclusion="A343_73_alias_panel",
        confidence_modifier=1.0,
    )
    writer.add_rule(
        name="complete_order_hash_to_duplicate_free_panel",
        description="Complete uint16be order hashes merge byte-identical aliases while preserving all source identities.",
        pattern=["A343_73_alias_panel", "complete_order_SHA256_identity"],
        conclusion="A343_57_unique_orders",
        confidence_modifier=1.0,
    )
    writer.add_rule(
        name="future_confirmed_prefix_to_rank_panel",
        description="Only an independently confirmed A325 prefix may activate exact lookup in the frozen panel; no order refit or candidate execution is permitted.",
        pattern=["A325_independently_confirmed_prefix", "A343_57_unique_orders"],
        conclusion="A343_postconfirmation_rank_panel",
        confidence_modifier=1.0,
    )
    writer.add_triplet(
        trigger="A333-A342:all_pre_result_W46_orders",
        mechanism="fixed_family_alias_collection_and_exact_order_hashing",
        outcome="A343:73_retained_aliases",
        confidence=1.0,
        source=payload["panel_measurement_sha256"],
        quantification=json.dumps(payload["family_counts"], sort_keys=True),
        evidence="A325_RESULT_CANDIDATE_PREFIX_ABSENT_AT_PANEL_FREEZE",
        domain="prospective W46 operator portfolio",
        quality_score=1.0,
    )
    writer.add_triplet(
        trigger="A343:73_retained_aliases",
        mechanism="complete_uint16be_SHA256_deduplication",
        outcome="A343:57_unique_exact_W46_orders",
        confidence=1.0,
        source=payload["panel_commitment_sha256"],
        quantification=json.dumps(
            {
                "aliases": payload["alias_count"],
                "unique_orders": payload["unique_order_count"],
                "duplicates": payload["duplicate_alias_count"],
            },
            sort_keys=True,
        ),
        evidence="ZERO_ORDER_REFITS_ZERO_DUPLICATE_CANDIDATE_EXECUTION",
        domain="exact order identity",
        quality_score=1.0,
    )
    writer.add_triplet(
        trigger="A343:57_unique_exact_W46_orders",
        mechanism="explicit_A325_result_hash_and_dual_confirmation_gate",
        outcome=terminal,
        confidence=1.0,
        source=payload["panel_commitment_sha256"],
        quantification=json.dumps(payload["evaluation_gate"], sort_keys=True),
        evidence="ONLY_CONFIRMED_PREFIX_MAY_ENTER_FUTURE_LOOKUP",
        domain="postconfirmation evaluation boundary",
        quality_score=1.0,
    )
    writer.add_triplet(
        trigger="A333-A342:all_pre_result_W46_orders",
        mechanism="materialized_frozen_panel_chain",
        outcome=terminal,
        confidence=1.0,
        source="materialized:A343_frozen_panel_chain",
        quantification="exact retained closure",
        evidence=payload["evidence_stage"],
        domain="AI-native retained inference",
        quality_score=1.0,
        is_inferred=True,
    )
    writer.add_cluster(
        name="A343 frozen W46 operator panel",
        entities=[
            "A333-A342:all_pre_result_W46_orders",
            "A343:73_retained_aliases",
            "A343:57_unique_exact_W46_orders",
            terminal,
        ],
    )
    writer.add_gap(
        subject=terminal,
        predicate="next_required_object",
        expected_object_type="independently_confirmed_A325_prefix_and_exact_57_order_rank_panel",
        confidence=1.0,
        suggested_queries=[
            "After A325 dual confirmation, where does its prefix rank in every temporal, Causal, ensemble and protected W46 order frozen before the result?"
        ],
    )
    temporary = PANEL_CAUSAL.with_name(f".{PANEL_CAUSAL.name}.tmp")
    temporary.unlink(missing_ok=True)
    stats = writer.save(str(temporary))
    os.replace(temporary, PANEL_CAUSAL)
    reader = CausalReader(str(PANEL_CAUSAL), verify_integrity=True)
    explicit = reader.get_all_triplets(include_inferred=False)
    all_rows = reader.get_all_triplets(include_inferred=True)
    inferred = [row for row in reader._triplets if row.get("is_inferred", False)]
    if (
        reader.api_id != "a343pnl"
        or len(explicit) != 3
        or len(all_rows) != 4
        or len(inferred) != 1
        or len(reader._rules) != 3
        or len(reader._clusters) != 1
        or len(reader._gaps) != 1
    ):
        raise RuntimeError("A343 panel authentic Causal reopen gate failed")
    return {
        "format": "authentic_dotcausal_v1_AI_native",
        "path": relative(PANEL_CAUSAL),
        "sha256": file_sha256(PANEL_CAUSAL),
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


def materialize_panel() -> dict[str, Any]:
    if any(path.exists() for path in (PANEL, PANEL_CAUSAL, PANEL_REPORT)):
        raise FileExistsError("A343 panel artifacts already exist")
    if A325_RESULT.exists():
        raise RuntimeError("A343 panel must be frozen before the A325 result exists")
    if not A325_PROGRESS.exists():
        raise RuntimeError("A343 design requires the already-running A325 execution")
    built = build_panel()
    if A325_RESULT.exists():
        raise RuntimeError("A325 completed while the A343 panel was being built")
    compact_unique = [
        {
            key: row[key]
            for key in (
                "unique_id",
                "W46_order_uint16be_sha256",
                "canonical_alias",
                "aliases",
            )
        }
        for row in built["unique_orders"]
    ]
    payload: dict[str, Any] = {
        "schema": "chacha20-round20-w46-pre-result-operator-panel-a343-v1",
        "attempt_id": ATTEMPT_ID,
        "evidence_stage": "PROSPECTIVE_PRE_A325_RESULT_DUPLICATE_FREE_W46_PANEL_RETAINED",
        "design_sha256": DESIGN_SHA256,
        "A325_protocol_sha256": A325_PROTOCOL_SHA256,
        "alias_count": len(built["aliases"]),
        "unique_order_count": len(built["unique_orders"]),
        "duplicate_alias_count": len(built["aliases"]) - len(built["unique_orders"]),
        "family_counts": built["family_counts"],
        "source_alias_sequence": [row["alias"] for row in built["aliases"]],
        "source_alias_metadata": {
            row["alias"]: {
                key: row[key]
                for key in (
                    "family",
                    "name",
                    "source_role",
                    "source_primary",
                    "source_protected",
                    "W46_order_uint16be_sha256",
                )
            }
            for row in built["aliases"]
        },
        "unique_orders": built["unique_orders"],
        "unique_order_summary": compact_unique,
        "alias_to_unique_id": built["alias_to_unique_id"],
        "designated_comparisons": built["designated_comparisons"],
        "post_confirmation_metrics": built["design"]["post_confirmation_metrics"],
        "evaluation_gate": built["design"]["evaluation_gate"],
        "information_boundary": built["design"]["information_boundary"]
        | {
            "A325_progress_exists_at_panel_materialization": True,
            "A325_result_absent_before_and_after_panel_construction": True,
            "A325_progress_content_read_by_A343": False,
        },
        "anchors": {
            "design": anchor(DESIGN, DESIGN_SHA256),
            "A325_protocol": anchor(A325_PROTOCOL, A325_PROTOCOL_SHA256),
            **{
                f"{family}_order": anchor(SOURCE_PATHS[family], SOURCE_SHA256[family])
                for family in FAMILY_ORDER
            },
            "runner": anchor(Path(__file__)),
            "test": anchor(A343_TEST),
            "reproducer": anchor(A343_REPRO),
        },
    }
    payload["panel_commitment_sha256"] = canonical_sha256(
        {
            "design_sha256": DESIGN_SHA256,
            "A325_protocol_sha256": A325_PROTOCOL_SHA256,
            "unique_order_summary": compact_unique,
            "alias_to_unique_id": payload["alias_to_unique_id"],
            "designated_comparisons": payload["designated_comparisons"],
            "evaluation_gate": payload["evaluation_gate"],
            "information_boundary": payload["information_boundary"],
        }
    )
    payload["panel_measurement_sha256"] = canonical_sha256(
        {
            "alias_count": payload["alias_count"],
            "unique_order_count": payload["unique_order_count"],
            "duplicate_alias_count": payload["duplicate_alias_count"],
            "family_counts": payload["family_counts"],
            "unique_order_summary": compact_unique,
        }
    )
    payload["causal"] = build_panel_causal(payload)
    atomic_json(PANEL, payload)
    atomic_bytes(
        PANEL_REPORT,
        (
            "# A343 — frozen pre-result W46 operator panel\n\n"
            f"- Retained aliases: **{payload['alias_count']}**\n"
            f"- Unique exact orders: **{payload['unique_order_count']}**\n"
            f"- Byte-identical duplicate aliases: **{payload['duplicate_alias_count']}**\n"
            f"- Panel commitment: **{payload['panel_commitment_sha256']}**\n"
            "- A325 result/candidate/prefix used at panel freeze: **none**\n"
            "- A325 running progress content read by A343: **no**\n"
            "- Duplicate candidate execution required: **no**\n"
            "- Authentic AI-native Causal readback: **3 explicit + 1 inferred chain**\n"
        ).encode(),
    )
    return payload


def rank_metrics(rank: int, executed_rank: int) -> dict[str, Any]:
    return {
        "rank_one_based": rank,
        "counterfactual_complete_group_assignments": rank * CANDIDATES_PER_GROUP,
        "gain_bits_vs_complete_2pow46_domain": math.log2(CELLS / rank),
        "domain_reduction_factor": CELLS / rank,
        "speed_factor_vs_executed_raw_Linf": executed_rank / rank,
        "strict_subset_by_complete_groups": rank < CELLS,
        "candidate_execution_performed_for_this_order": False,
        "matched_control_outcome_inferred": False,
    }


def build_evaluation_causal(payload: Mapping[str, Any]) -> dict[str, Any]:
    sys.path.insert(0, str(DOTCAUSAL_SRC))
    from dotcausal.io import CausalReader, CausalWriter

    terminal = "A343:confirmed_57_order_W46_rank_panel"
    writer = CausalWriter(api_id="a343eval")
    writer._rules = []
    writer.add_rule(
        name="confirmed_A325_model_to_prefix",
        description="The independently confirmed W46 assignment determines exactly one high 12-bit prefix.",
        pattern=["A325_confirmed_assignment", "exact_W46_prefix_codec"],
        conclusion="A343_confirmed_prefix",
        confidence_modifier=1.0,
    )
    writer.add_rule(
        name="confirmed_prefix_and_frozen_panel_to_exact_ranks",
        description="The same confirmed prefix is located in all 57 pre-result exact orders without any repeated cipher execution.",
        pattern=["A343_confirmed_prefix", "A343_frozen_57_order_panel"],
        conclusion="A343_exact_rank_panel",
        confidence_modifier=1.0,
    )
    writer.add_rule(
        name="designated_temporal_causal_ensemble_comparison",
        description="The predeclared temporal, Causal, ensemble and protected orders receive exact ranks and complete-group candidate bounds.",
        pattern=["A343_exact_rank_panel", "A343_designated_comparisons"],
        conclusion="A343_retained_W46_localization_boundary",
        confidence_modifier=1.0,
    )
    writer.add_triplet(
        trigger="A325:independently_confirmed_W46_assignment",
        mechanism="exact_assignment_to_high12_prefix_codec",
        outcome="A343:confirmed_A325_prefix",
        confidence=1.0,
        source=payload["A325_result_sha256"],
        quantification=json.dumps(payload["confirmed_prefix"], sort_keys=True),
        evidence="A325_DUAL_EIGHT_BLOCK_CONFIRMATION",
        domain="confirmed full-round ChaCha20 recovery",
        quality_score=1.0,
    )
    writer.add_triplet(
        trigger="A343:confirmed_A325_prefix",
        mechanism="lookup_in_57_exact_pre_result_W46_orders",
        outcome="A343:exact_57_order_rank_panel",
        confidence=1.0,
        source=payload["evaluation_measurement_sha256"],
        quantification=json.dumps(payload["family_winners"], sort_keys=True),
        evidence="ZERO_DUPLICATE_CANDIDATE_EXECUTION",
        domain="postconfirmation order evaluation",
        quality_score=1.0,
    )
    writer.add_triplet(
        trigger="A343:exact_57_order_rank_panel",
        mechanism="predeclared_temporal_Causal_ensemble_protected_comparison",
        outcome=terminal,
        confidence=1.0,
        source=payload["evaluation_commitment_sha256"],
        quantification=json.dumps(payload["designated_rank_comparisons"], sort_keys=True),
        evidence=json.dumps(payload["evaluation_boundary"], sort_keys=True),
        domain="W46 search-localization boundary",
        quality_score=1.0,
    )
    writer.add_triplet(
        trigger="A325:independently_confirmed_W46_assignment",
        mechanism="materialized_confirmed_prefix_to_frozen_panel_chain",
        outcome=terminal,
        confidence=1.0,
        source="materialized:A343_confirmed_rank_chain",
        quantification="exact retained closure",
        evidence=payload["evidence_stage"],
        domain="AI-native retained inference",
        quality_score=1.0,
        is_inferred=True,
    )
    writer.add_cluster(
        name="A343 confirmed W46 operator rank panel",
        entities=[
            "A325:independently_confirmed_W46_assignment",
            "A343:confirmed_A325_prefix",
            "A343:exact_57_order_rank_panel",
            terminal,
        ],
    )
    writer.add_gap(
        subject=terminal,
        predicate="next_required_object",
        expected_object_type="fresh_prospective_replication_of_best_pre_result_noncontrol_operator",
        confidence=1.0,
        suggested_queries=[
            "Which pre-result operator localizes A325 earliest, and can that exact rule be selected prospectively on a fresh W46 target?"
        ],
    )
    temporary = EVALUATION_CAUSAL.with_name(f".{EVALUATION_CAUSAL.name}.tmp")
    temporary.unlink(missing_ok=True)
    stats = writer.save(str(temporary))
    os.replace(temporary, EVALUATION_CAUSAL)
    reader = CausalReader(str(EVALUATION_CAUSAL), verify_integrity=True)
    explicit = reader.get_all_triplets(include_inferred=False)
    all_rows = reader.get_all_triplets(include_inferred=True)
    inferred = [row for row in reader._triplets if row.get("is_inferred", False)]
    if (
        reader.api_id != "a343eval"
        or len(explicit) != 3
        or len(all_rows) != 4
        or len(inferred) != 1
        or len(reader._rules) != 3
        or len(reader._clusters) != 1
        or len(reader._gaps) != 1
    ):
        raise RuntimeError("A343 evaluation authentic Causal reopen gate failed")
    return {
        "format": "authentic_dotcausal_v1_AI_native",
        "path": relative(EVALUATION_CAUSAL),
        "sha256": file_sha256(EVALUATION_CAUSAL),
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


def evaluate(expected_a325_result_sha256: str) -> dict[str, Any]:
    if any(path.exists() for path in (EVALUATION, EVALUATION_CAUSAL, EVALUATION_REPORT)):
        raise FileExistsError("A343 evaluation artifacts already exist")
    if not PANEL.exists():
        raise FileNotFoundError("A343 frozen panel is absent")
    if not A325_RESULT.exists():
        raise FileNotFoundError("A343 evaluation waits for the A325 result")
    if file_sha256(A325_RESULT) != expected_a325_result_sha256:
        raise RuntimeError("A343 A325 result hash differs from explicit argument")
    panel = json.loads(PANEL.read_bytes())
    result = json.loads(A325_RESULT.read_bytes())
    discovery = result.get("discovery", {})
    confirmation = result.get("confirmation", {})
    if (
        result.get("schema")
        != "chacha20-round20-holdout-selected-w46-recovery-a325-result-v1"
        or result.get("protocol_sha256") != A325_PROTOCOL_SHA256
        or not str(result.get("evidence_stage", "")).endswith("RECOVERY_CONFIRMED")
        or confirmation.get("all_blocks_match") is not True
        or confirmation.get("total_cross_implementation_output_bits_checked") != 8192
        or discovery.get("matched_control_candidates") != 0
        or result.get("selected_W46_order_uint16be_sha256") != RAW_ORDER_SHA256
    ):
        raise RuntimeError("A343 A325 confirmation gate failed")
    prefix = int(discovery["prefix12"])
    candidate = int(discovery["candidate"])
    executed_rank = int(discovery["executed_prefix_groups"])
    if (
        not 0 <= prefix < CELLS
        or candidate >> 34 != prefix
        or not 1 <= executed_rank <= CELLS
        or int(confirmation["assignment"]) != candidate
    ):
        raise RuntimeError("A343 confirmed prefix mapping differs")
    unique_rank: dict[str, Any] = {}
    for row in panel["unique_orders"]:
        rank = row["W46_order"].index(prefix) + 1
        unique_rank[row["unique_id"]] = {
            "canonical_alias": row["canonical_alias"],
            "aliases": row["aliases"],
            "W46_order_uint16be_sha256": row["W46_order_uint16be_sha256"],
            "rank_one_based": rank,
        }
    alias_ranks = {
        alias: unique_rank[unique_id]["rank_one_based"]
        for alias, unique_id in panel["alias_to_unique_id"].items()
    }
    raw_alias = panel["designated_comparisons"]["executed_A325_raw_Linf"]
    if alias_ranks[raw_alias] != executed_rank:
        raise RuntimeError("A343 executed raw-Linf rank differs from A325")
    alias_metrics = {
        alias: rank_metrics(rank, executed_rank) for alias, rank in alias_ranks.items()
    }
    unique_metrics = {
        unique_id: {
            **row,
            **rank_metrics(row["rank_one_based"], executed_rank),
        }
        for unique_id, row in unique_rank.items()
    }
    family_winners: dict[str, Any] = {}
    for family in FAMILY_ORDER:
        family_aliases = [
            alias
            for alias in panel["source_alias_sequence"]
            if alias.startswith(f"{family}/")
        ]
        winner = min(
            family_aliases,
            key=lambda alias: (alias_ranks[alias], family_aliases.index(alias)),
        )
        family_winners[family] = {"alias": winner, **alias_metrics[winner]}
    global_winner = min(
        panel["source_alias_sequence"],
        key=lambda alias: (
            alias_ranks[alias],
            panel["source_alias_sequence"].index(alias),
        ),
    )
    designated = {
        key: {"alias": alias, **alias_metrics[alias]}
        for key, alias in panel["designated_comparisons"].items()
    }
    payload: dict[str, Any] = {
        "schema": "chacha20-round20-w46-pre-result-operator-panel-a343-evaluation-v1",
        "attempt_id": ATTEMPT_ID,
        "evidence_stage": "POSTCONFIRMATION_EXACT_DUPLICATE_FREE_W46_OPERATOR_RANK_PANEL_RETAINED",
        "design_sha256": DESIGN_SHA256,
        "panel_sha256": file_sha256(PANEL),
        "panel_commitment_sha256": panel["panel_commitment_sha256"],
        "A325_result_sha256": expected_a325_result_sha256,
        "confirmed_prefix": {
            "prefix12": prefix,
            "prefix12_hex": f"{prefix:03x}",
            "assignment": candidate,
            "assignment_hex": f"{candidate:012x}",
            "dual_confirmation": True,
            "cross_implementation_output_bits_checked": 8192,
        },
        "alias_rank_panel": alias_metrics,
        "unique_rank_panel": unique_metrics,
        "designated_rank_comparisons": designated,
        "family_winners": family_winners,
        "global_oracle_descriptive_winner": {
            "alias": global_winner,
            "prospectively_selected_for_A325": False,
            **alias_metrics[global_winner],
        },
        "evaluation_boundary": {
            "all_orders_frozen_before_A325_result": True,
            "only_secret_derived_input": "independently confirmed prefix12",
            "orders_refit_after_A325": False,
            "duplicate_candidate_execution": False,
            "counterfactual_candidate_counts_are_complete_group_rank_times_2pow34": True,
            "matched_control_outcomes_inferred_for_counterfactual_orders": False,
        },
        "anchors": {
            "design": anchor(DESIGN, DESIGN_SHA256),
            "panel": anchor(PANEL),
            "A325_result": anchor(A325_RESULT, expected_a325_result_sha256),
            "runner": anchor(Path(__file__)),
            "test": anchor(A343_TEST),
            "reproducer": anchor(A343_REPRO),
        },
    }
    payload["evaluation_commitment_sha256"] = canonical_sha256(
        {
            "panel_commitment_sha256": payload["panel_commitment_sha256"],
            "A325_result_sha256": payload["A325_result_sha256"],
            "confirmed_prefix": payload["confirmed_prefix"],
            "designated_rank_comparisons": designated,
            "evaluation_boundary": payload["evaluation_boundary"],
        }
    )
    payload["evaluation_measurement_sha256"] = canonical_sha256(
        {
            "alias_rank_panel": alias_metrics,
            "unique_rank_panel": unique_metrics,
            "family_winners": family_winners,
            "global_oracle_descriptive_winner": payload[
                "global_oracle_descriptive_winner"
            ],
        }
    )
    payload["causal"] = build_evaluation_causal(payload)
    atomic_json(EVALUATION, payload)
    raw = designated["executed_A325_raw_Linf"]
    best = payload["global_oracle_descriptive_winner"]
    atomic_bytes(
        EVALUATION_REPORT,
        (
            "# A343 — confirmed W46 pre-result operator rank panel\n\n"
            f"- Confirmed prefix: **0x{prefix:03x}**\n"
            f"- Executed raw-Linf rank: **{raw['rank_one_based']} / 4,096**\n"
            f"- Descriptive pre-result winner: **{best['alias']}**, rank **{best['rank_one_based']} / 4,096**\n"
            f"- Winner gain / domain reduction: **{best['gain_bits_vs_complete_2pow46_domain']:.8f} bits / {best['domain_reduction_factor']:.3f}x**\n"
            f"- Winner speed factor versus executed raw Linf: **{best['speed_factor_vs_executed_raw_Linf']:.3f}x**\n"
            "- Duplicate candidate executions: **zero**\n"
            "- Counterfactual matched-control outcomes inferred: **none**\n"
            "- Authentic AI-native Causal readback: **3 explicit + 1 inferred chain**\n"
        ).encode(),
    )
    return payload


def analyze() -> dict[str, Any]:
    response: dict[str, Any] = {
        "attempt_id": ATTEMPT_ID,
        "design_sha256": DESIGN_SHA256,
        "panel_exists": PANEL.exists(),
        "A325_progress_exists": A325_PROGRESS.exists(),
        "A325_result_exists": A325_RESULT.exists(),
        "evaluation_exists": EVALUATION.exists(),
    }
    if PANEL.exists():
        panel = json.loads(PANEL.read_bytes())
        response.update(
            {
                "panel_sha256": file_sha256(PANEL),
                "panel_commitment_sha256": panel["panel_commitment_sha256"],
                "alias_count": panel["alias_count"],
                "unique_order_count": panel["unique_order_count"],
            }
        )
    if EVALUATION.exists():
        evaluation = json.loads(EVALUATION.read_bytes())
        response.update(
            {
                "evaluation_sha256": file_sha256(EVALUATION),
                "confirmed_prefix": evaluation["confirmed_prefix"],
                "designated_rank_comparisons": evaluation[
                    "designated_rank_comparisons"
                ],
            }
        )
    return response


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    action = parser.add_mutually_exclusive_group(required=True)
    action.add_argument("--analyze", action="store_true")
    action.add_argument("--materialize-panel", action="store_true")
    action.add_argument("--evaluate", action="store_true")
    parser.add_argument("--expected-a325-result-sha256")
    args = parser.parse_args()
    if args.evaluate:
        if not args.expected_a325_result_sha256:
            parser.error("--evaluate requires --expected-a325-result-sha256")
        payload = evaluate(args.expected_a325_result_sha256)
    elif args.materialize_panel:
        payload = materialize_panel()
    else:
        payload = analyze()
    print(json.dumps(payload, indent=2, sort_keys=True), flush=True)


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""A330: freeze and later evaluate the complete pre-result W45 operator panel."""

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

DESIGN = CONFIGS / "chacha20_round20_w45_frozen_operator_panel_a330_design_v1.json"
PANEL = RESULTS / "chacha20_round20_w45_frozen_operator_panel_a330_v1.json"
PANEL_CAUSAL = RESULTS / "chacha20_round20_w45_frozen_operator_panel_a330_v1.causal"
PANEL_REPORT = RESULTS / "chacha20_round20_w45_frozen_operator_panel_a330_v1.md"
EVALUATION = RESULTS / "chacha20_round20_w45_frozen_operator_panel_a330_evaluation_v1.json"
EVALUATION_CAUSAL = RESULTS / "chacha20_round20_w45_frozen_operator_panel_a330_evaluation_v1.causal"
EVALUATION_REPORT = RESULTS / "chacha20_round20_w45_frozen_operator_panel_a330_evaluation_v1.md"

A322_RUNNER = RESEARCH / "experiments/chacha20_round20_holdout_selected_w45_recovery_a322.py"
A321_ORDER = RESULTS / "chacha20_round20_holdout_selected_w45_operator_a321_order_v1.json"
A322_PROTOCOL = CONFIGS / "chacha20_round20_holdout_selected_w45_recovery_a322_v1.json"
A322_RESULT = RESULTS / "chacha20_round20_holdout_selected_w45_recovery_a322_v1.json"
A326_ORDER = RESULTS / "chacha20_round20_diversity_fused_operator_a326_order_v1.json"
A327_ORDER = RESULTS / "chacha20_round20_hierarchical_linf_operator_a327_order_v1.json"
A329_ORDER = RESULTS / "chacha20_round20_linf_stability_merge_a329_order_v1.json"
A325_PROGRESS = RESULTS / "chacha20_round20_holdout_selected_w46_recovery_a325_progress_v1.json"
A325_RESULT = RESULTS / "chacha20_round20_holdout_selected_w46_recovery_a325_v1.json"
A330_TEST = ROOT / "tests/test_chacha20_round20_w45_frozen_operator_panel_a330.py"
A330_REPRO = ROOT / "scripts/reproduce_chacha20_round20_w45_frozen_operator_panel_a330.sh"

ATTEMPT_ID = "A330"
DESIGN_SHA256 = "75ed9e5b107177c5b0dff1142cd37ba0758fc6b33d723c09192af9043777577f"
A322_RUNNER_SHA256 = "37e72eb3f5c043b26a1308ea38337970ab48357b4c9b3aea9be2a5d1b99048e8"
A321_ORDER_SHA256 = "8ace2e5af5ce1a132e78926f317dadaf63ada13a10c0338a56ddf62713a9d9d2"
A322_PROTOCOL_SHA256 = "5fdd681b97ba452acf713b845423752c9413c07bcd5baf3dfa3c3c78eaa741a4"
A326_ORDER_SHA256 = "b45610e6439157002d4a3878e8ed9fec25a967f4efbc2e154738f76ff2875865"
A327_ORDER_SHA256 = "7c077a4e8eeb3ab83c4fae931f94882c87369cedb18bd19b2766e04e9b72c90f"
A329_ORDER_SHA256 = "05d1049a1304a3160ca6e50a667a56ac4ff194fe913d3e570df2e813023b3512"
CELLS = 1 << 12
CANDIDATES_PER_GROUP = 1 << 33
COMPLETE_DOMAIN = 1 << 45
FAMILY_ORDER = ("A321_A314", "A326", "A327", "A329")
EXPECTED_ALIAS_COUNT = 24
EXPECTED_UNIQUE_COUNT = 22


def load_module(path: Path, name: str) -> Any:
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot import A330 dependency {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


if not A322_RUNNER.exists():
    raise FileNotFoundError(A322_RUNNER)
A322 = load_module(A322_RUNNER, "a330_a322_common")
file_sha256 = A322.file_sha256
canonical_sha256 = A322.canonical_sha256
atomic_json = A322.atomic_json
atomic_bytes = A322.atomic_bytes
relative = A322.relative
path_from_ref = A322.path_from_ref
anchor = A322.anchor
DOTCAUSAL_SRC = A322.DOTCAUSAL_SRC


def load_design() -> dict[str, Any]:
    if file_sha256(DESIGN) != DESIGN_SHA256:
        raise RuntimeError("A330 design hash differs")
    design = json.loads(DESIGN.read_bytes())
    dedup = design.get("deduplication_contract", {})
    gate = design.get("evaluation_gate", {})
    boundary = design.get("information_boundary", {})
    if (
        design.get("schema")
        != "chacha20-round20-w45-frozen-operator-panel-a330-design-v1"
        or design.get("attempt_id") != ATTEMPT_ID
        or design.get("design_state")
        != "frozen_while_A322_is_running_before_any_A322_result_and_before_any_A325_execution_or_result"
        or tuple(design.get("source_alias_order", {})) != FAMILY_ORDER
        or dedup.get("identity")
        != "uint16be SHA-256 of the complete 4096-cell order"
        or dedup.get("all_aliases_retained") is not True
        or dedup.get("duplicate_candidate_execution") is not False
        or gate.get("A322_result_sha256_required_as_argument") is not True
        or gate.get("independent_confirmation_required") is not True
        or gate.get("orders_refit_after_A322") is not False
        or gate.get("new_candidate_execution") is not False
        or gate.get("matched_control_counterfactual_not_inferred") is not True
        or boundary.get("A322_progress_used_for_panel_membership_order_or_metrics")
        is not False
        or boundary.get("A322_result_available_at_design_freeze") is not False
        or boundary.get("A325_execution_started_at_design_freeze") is not False
        or boundary.get("target_labels_used_to_construct_orders") != 0
        or boundary.get("duplicate_candidate_execution_required") is not False
    ):
        raise RuntimeError("A330 frozen design semantics differ")
    for key, value in design["source_anchors"].items():
        if key.endswith("_path"):
            anchor(
                path_from_ref(value),
                design["source_anchors"][key.removesuffix("_path") + "_sha256"],
            )
    return design


def exact_order(values: Sequence[int], label: str) -> list[int]:
    return A322.A321._exact_order(values, label)  # noqa: SLF001


def order_sha(values: Sequence[int]) -> str:
    return A322.A321._order_sha(values)  # noqa: SLF001


def source_aliases(design: Mapping[str, Any]) -> list[dict[str, Any]]:
    if (
        file_sha256(A322_RUNNER) != A322_RUNNER_SHA256
        or file_sha256(A321_ORDER) != A321_ORDER_SHA256
        or file_sha256(A322_PROTOCOL) != A322_PROTOCOL_SHA256
        or file_sha256(A326_ORDER) != A326_ORDER_SHA256
        or file_sha256(A327_ORDER) != A327_ORDER_SHA256
        or file_sha256(A329_ORDER) != A329_ORDER_SHA256
    ):
        raise RuntimeError("A330 source anchor differs")
    a322_orders = A322.all_w45_orders()
    a326 = json.loads(A326_ORDER.read_bytes())["fusion_orders"]
    a327 = json.loads(A327_ORDER.read_bytes())["candidate_orders"]
    a329 = json.loads(A329_ORDER.read_bytes())["candidates"]
    source_maps: dict[str, Mapping[str, Any]] = {
        "A321_A314": {
            name: {"W45_order": order, "W45_order_uint16be_sha256": order_sha(order)}
            for name, order in a322_orders.items()
        },
        "A326": a326,
        "A327": a327,
        "A329": a329,
    }
    aliases: list[dict[str, Any]] = []
    for family in FAMILY_ORDER:
        names = list(design["source_alias_order"][family])
        if set(names) != set(source_maps[family]) or len(names) != len(source_maps[family]):
            raise RuntimeError(f"A330 {family} alias membership differs")
        for name in names:
            row = source_maps[family][name]
            order = exact_order(row["W45_order"], f"A330 {family}/{name}")
            digest = order_sha(order)
            if digest != row["W45_order_uint16be_sha256"]:
                raise RuntimeError(f"A330 {family}/{name} order hash differs")
            aliases.append(
                {
                    "alias": f"{family}/{name}",
                    "family": family,
                    "name": name,
                    "W45_order_uint16be_sha256": digest,
                    "W45_order": order,
                }
            )
    if len(aliases) != EXPECTED_ALIAS_COUNT:
        raise RuntimeError("A330 alias count differs")
    return aliases


def build_panel() -> dict[str, Any]:
    design = load_design()
    aliases = source_aliases(design)
    unique_by_hash: dict[str, dict[str, Any]] = {}
    unique_sequence: list[dict[str, Any]] = []
    alias_to_unique: dict[str, str] = {}
    for row in aliases:
        digest = row["W45_order_uint16be_sha256"]
        unique = unique_by_hash.get(digest)
        if unique is None:
            unique = {
                "unique_id": f"u{len(unique_sequence):02d}",
                "W45_order_uint16be_sha256": digest,
                "canonical_alias": row["alias"],
                "aliases": [],
                "W45_order": row["W45_order"],
            }
            unique_by_hash[digest] = unique
            unique_sequence.append(unique)
        elif unique["W45_order"] != row["W45_order"]:
            raise RuntimeError("A330 SHA collision or inconsistent order")
        unique["aliases"].append(row["alias"])
        alias_to_unique[row["alias"]] = unique["unique_id"]
    if len(unique_sequence) != EXPECTED_UNIQUE_COUNT:
        raise RuntimeError("A330 unique order count differs")
    for key, alias in design["designated_comparisons"].items():
        if alias not in alias_to_unique:
            raise RuntimeError(f"A330 designated comparison {key} is absent")
    return {
        "design": design,
        "source_aliases": aliases,
        "unique_orders": unique_sequence,
        "alias_to_unique_id": alias_to_unique,
        "alias_count": len(aliases),
        "unique_order_count": len(unique_sequence),
        "duplicate_alias_count": len(aliases) - len(unique_sequence),
        "designated_comparisons": design["designated_comparisons"],
    }


def build_panel_causal(payload: Mapping[str, Any]) -> dict[str, Any]:
    sys.path.insert(0, str(DOTCAUSAL_SRC))
    from dotcausal.io import CausalReader, CausalWriter

    terminal = "A330:frozen_duplicate_free_W45_operator_panel"
    writer = CausalWriter(api_id="a330pnl")
    writer._rules = []
    writer.add_rule(
        name="frozen_source_orders_to_alias_panel",
        description="All W45 orders retained by A321/A314, A326, A327 and A329 enter the panel in a fixed family and alias sequence before the A322 result exists.",
        pattern=["four_frozen_operator_families", "fixed_alias_sequence"],
        conclusion="A330_24_alias_orders",
        confidence_modifier=1.0,
    )
    writer.add_rule(
        name="complete_order_hash_to_exact_deduplication",
        description="Complete uint16be order hashes merge byte-identical aliases while retaining every source name and the first-alias canonical identity.",
        pattern=["A330_24_alias_orders", "complete_order_SHA256_identity"],
        conclusion="A330_22_unique_orders",
        confidence_modifier=1.0,
    )
    writer.add_rule(
        name="confirmed_prefix_to_duplicate_free_rank_panel",
        description="After independent A322 confirmation, one prefix index maps into every frozen order and yields exact complete-group candidate counts without another candidate execution.",
        pattern=["A322_independently_confirmed_prefix", "A330_frozen_unique_orders"],
        conclusion="A330_postconfirmation_rank_panel",
        confidence_modifier=1.0,
    )
    writer.add_triplet(
        trigger="A321_A314_A326_A327_A329:frozen_W45_orders",
        mechanism="fixed_family_and_alias_collection",
        outcome="A330:24_retained_alias_orders",
        confidence=1.0,
        source=payload["panel_measurement_sha256"],
        quantification=json.dumps(
            {
                "alias_count": payload["alias_count"],
                "family_counts": payload["family_counts"],
            },
            sort_keys=True,
        ),
        evidence="A322_RESULT_ABSENT_AT_PANEL_FREEZE",
        domain="pre-result operator panel",
        quality_score=1.0,
    )
    writer.add_triplet(
        trigger="A330:24_retained_alias_orders",
        mechanism="complete_uint16be_order_SHA256_deduplication",
        outcome=terminal,
        confidence=1.0,
        source=payload["panel_commitment_sha256"],
        quantification=json.dumps(
            {
                "unique_order_count": payload["unique_order_count"],
                "duplicate_alias_count": payload["duplicate_alias_count"],
                "alias_to_unique_id": payload["alias_to_unique_id"],
            },
            sort_keys=True,
        ),
        evidence=json.dumps(payload["information_boundary"], sort_keys=True),
        domain="duplicate-free exact order commitment",
        quality_score=1.0,
    )
    writer.add_triplet(
        trigger=terminal,
        mechanism="predeclared_confirmed_prefix_rank_metrics",
        outcome="A330:postconfirmation_evaluation_contract",
        confidence=1.0,
        source=DESIGN_SHA256,
        quantification=json.dumps(payload["post_confirmation_metrics"], sort_keys=True),
        evidence="NO_ORDER_REFIT_NO_DUPLICATE_CANDIDATE_EXECUTION",
        domain="prospective rank evaluation",
        quality_score=1.0,
    )
    writer.add_triplet(
        trigger="A321_A314_A326_A327_A329:frozen_W45_orders",
        mechanism="materialized_alias_deduplication_and_evaluation_chain",
        outcome="A330:postconfirmation_evaluation_contract",
        confidence=1.0,
        source="materialized:A330_frozen_panel_chain",
        quantification="exact retained closure",
        evidence=payload["evidence_stage"],
        domain="AI-native retained inference",
        quality_score=1.0,
        is_inferred=True,
    )
    writer.add_cluster(
        name="A330 frozen W45 operator panel",
        entities=[
            "A321_A314_A326_A327_A329:frozen_W45_orders",
            "A330:24_retained_alias_orders",
            terminal,
            "A330:postconfirmation_evaluation_contract",
        ],
    )
    writer.add_gap(
        subject="A330:postconfirmation_evaluation_contract",
        predicate="next_required_object",
        expected_object_type="independently_confirmed_A322_prefix_and_exact_22_order_rank_panel",
        confidence=1.0,
        suggested_queries=[
            "Which frozen order ranks the independently confirmed A322 prefix earliest, and how do the predeclared raw, A329-primary and direction-control comparisons resolve?"
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
        reader.api_id != "a330pnl"
        or len(explicit) != 3
        or len(all_rows) != 4
        or len(inferred) != 1
        or len(reader._rules) != 3
        or len(reader._clusters) != 1
        or len(reader._gaps) != 1
    ):
        raise RuntimeError("A330 panel Causal reopen gate failed")
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
        raise FileExistsError("A330 panel artifacts already exist")
    if A322_RESULT.exists():
        raise RuntimeError("A330 panel must freeze before any A322 result exists")
    if A325_PROGRESS.exists() or A325_RESULT.exists():
        raise RuntimeError("A330 panel must freeze before any A325 execution or result exists")
    built = build_panel()
    family_counts = {
        family: sum(row["family"] == family for row in built["source_aliases"])
        for family in FAMILY_ORDER
    }
    compact_unique = [
        {
            key: value
            for key, value in row.items()
            if key != "W45_order"
        }
        for row in built["unique_orders"]
    ]
    payload: dict[str, Any] = {
        "schema": "chacha20-round20-w45-frozen-operator-panel-a330-v1",
        "attempt_id": ATTEMPT_ID,
        "evidence_stage": "PROSPECTIVE_PRE_A322_RESULT_DUPLICATE_FREE_W45_PANEL_RETAINED",
        "design_sha256": DESIGN_SHA256,
        "alias_count": built["alias_count"],
        "unique_order_count": built["unique_order_count"],
        "duplicate_alias_count": built["duplicate_alias_count"],
        "family_counts": family_counts,
        "source_alias_sequence": [row["alias"] for row in built["source_aliases"]],
        "unique_orders": built["unique_orders"],
        "unique_order_summary": compact_unique,
        "alias_to_unique_id": built["alias_to_unique_id"],
        "designated_comparisons": built["designated_comparisons"],
        "post_confirmation_metrics": built["design"]["post_confirmation_metrics"],
        "evaluation_gate": built["design"]["evaluation_gate"],
        "information_boundary": built["design"]["information_boundary"],
        "anchors": {
            "design": anchor(DESIGN, DESIGN_SHA256),
            "A321_order": anchor(A321_ORDER, A321_ORDER_SHA256),
            "A322_protocol": anchor(A322_PROTOCOL, A322_PROTOCOL_SHA256),
            "A322_runner": anchor(A322_RUNNER, A322_RUNNER_SHA256),
            "A326_order": anchor(A326_ORDER, A326_ORDER_SHA256),
            "A327_order": anchor(A327_ORDER, A327_ORDER_SHA256),
            "A329_order": anchor(A329_ORDER, A329_ORDER_SHA256),
            "runner": anchor(Path(__file__)),
            "test": anchor(A330_TEST),
            "reproducer": anchor(A330_REPRO),
        },
    }
    payload["panel_commitment_sha256"] = canonical_sha256(
        {
            "design_sha256": DESIGN_SHA256,
            "unique_order_summary": compact_unique,
            "alias_to_unique_id": payload["alias_to_unique_id"],
            "designated_comparisons": payload["designated_comparisons"],
            "post_confirmation_metrics": payload["post_confirmation_metrics"],
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
            "# A330 — frozen W45 operator panel\n\n"
            f"- Retained aliases: **{payload['alias_count']}**\n"
            f"- Unique exact orders: **{payload['unique_order_count']}**\n"
            f"- Byte-identical duplicate aliases: **{payload['duplicate_alias_count']}**\n"
            f"- Panel commitment: **{payload['panel_commitment_sha256']}**\n"
            "- A322 result/prefix used at panel freeze: **none**\n"
            "- Duplicate candidate execution required: **no**\n"
            "- Authentic AI-native Causal readback: **3 explicit + 1 inferred chain**\n"
        ).encode(),
    )
    return payload


def rank_metrics(rank: int, executed_rank: int, baseline_rank: int) -> dict[str, Any]:
    return {
        "rank_one_based": rank,
        "counterfactual_complete_group_assignments": rank * CANDIDATES_PER_GROUP,
        "gain_bits_vs_complete_2pow45_domain": math.log2(CELLS / rank),
        "speed_factor_vs_executed_raw_Linf": executed_rank / rank,
        "speed_factor_vs_A314_baseline": baseline_rank / rank,
        "candidate_execution_performed_for_this_order": False,
        "matched_control_outcome_inferred": False,
    }


def build_evaluation_causal(payload: Mapping[str, Any]) -> dict[str, Any]:
    sys.path.insert(0, str(DOTCAUSAL_SRC))
    from dotcausal.io import CausalReader, CausalWriter

    terminal = "A330:confirmed_duplicate_free_W45_operator_rank_panel"
    writer = CausalWriter(api_id="a330eval")
    writer._rules = []
    writer.add_rule(
        name="confirmed_A322_model_to_prefix",
        description="The independently confirmed A322 assignment determines exactly one 12-bit prefix after dual eight-block confirmation.",
        pattern=["A322_confirmed_assignment", "exact_W45_prefix_codec"],
        conclusion="A330_confirmed_prefix",
        confidence_modifier=1.0,
    )
    writer.add_rule(
        name="prefix_and_frozen_orders_to_rank_panel",
        description="The confirmed prefix is located in each pre-result order; complete-group semantics map rank r to exactly r times 2^33 counterfactual evaluations.",
        pattern=["A330_confirmed_prefix", "A330_frozen_22_order_panel"],
        conclusion="A330_exact_rank_and_gain_panel",
        confidence_modifier=1.0,
    )
    writer.add_rule(
        name="designated_aliases_to_direction_test",
        description="The predeclared raw-Linf, A329 stable-primary and symmetric direction-control aliases form the prospectively frozen direction comparison.",
        pattern=["A330_exact_rank_and_gain_panel", "A330_designated_comparisons"],
        conclusion=terminal.replace(":", "_"),
        confidence_modifier=1.0,
    )
    writer.add_triplet(
        trigger="A322:independently_confirmed_W45_assignment",
        mechanism="exact_assignment_to_prefix12_codec",
        outcome="A330:confirmed_A322_prefix",
        confidence=1.0,
        source=payload["A322_result_sha256"],
        quantification=json.dumps(payload["confirmed_prefix"], sort_keys=True),
        evidence="A322_DUAL_EIGHT_BLOCK_CONFIRMATION",
        domain="confirmed full-round ChaCha20 recovery",
        quality_score=1.0,
    )
    writer.add_triplet(
        trigger="A330:confirmed_A322_prefix",
        mechanism="lookup_in_22_exact_pre_result_orders",
        outcome="A330:exact_22_order_rank_panel",
        confidence=1.0,
        source=payload["evaluation_measurement_sha256"],
        quantification=json.dumps(payload["unique_rank_panel"], sort_keys=True),
        evidence="ZERO_DUPLICATE_CANDIDATE_EXECUTION",
        domain="duplicate-free operator evaluation",
        quality_score=1.0,
    )
    writer.add_triplet(
        trigger="A330:exact_22_order_rank_panel",
        mechanism="predeclared_raw_primary_direction_control_comparison",
        outcome=terminal,
        confidence=1.0,
        source=payload["evaluation_commitment_sha256"],
        quantification=json.dumps(payload["designated_rank_comparisons"], sort_keys=True),
        evidence=json.dumps(payload["evaluation_boundary"], sort_keys=True),
        domain="prospective operator direction test",
        quality_score=1.0,
    )
    writer.add_triplet(
        trigger="A322:independently_confirmed_W45_assignment",
        mechanism="materialized_confirmed_prefix_to_frozen_panel_chain",
        outcome=terminal,
        confidence=1.0,
        source="materialized:A330_confirmed_rank_chain",
        quantification="exact retained closure",
        evidence=payload["evidence_stage"],
        domain="AI-native retained inference",
        quality_score=1.0,
        is_inferred=True,
    )
    writer.add_cluster(
        name="A330 confirmed W45 operator rank panel",
        entities=[
            "A322:independently_confirmed_W45_assignment",
            "A330:confirmed_A322_prefix",
            "A330:exact_22_order_rank_panel",
            terminal,
        ],
    )
    writer.add_gap(
        subject=terminal,
        predicate="next_required_object",
        expected_object_type="prospective_fresh_target_execution_of_best_predeclared_non_oracle_operator",
        confidence=1.0,
        suggested_queries=[
            "Which non-oracle operator was prospectively designated, and should its exact order be deployed unchanged on the next fresh full-round target?"
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
        reader.api_id != "a330eval"
        or len(explicit) != 3
        or len(all_rows) != 4
        or len(inferred) != 1
        or len(reader._rules) != 3
        or len(reader._clusters) != 1
        or len(reader._gaps) != 1
    ):
        raise RuntimeError("A330 evaluation Causal reopen gate failed")
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


def evaluate(expected_a322_result_sha256: str) -> dict[str, Any]:
    if any(path.exists() for path in (EVALUATION, EVALUATION_CAUSAL, EVALUATION_REPORT)):
        raise FileExistsError("A330 evaluation artifacts already exist")
    if not PANEL.exists():
        raise FileNotFoundError("A330 frozen panel is absent")
    if not A322_RESULT.exists():
        raise FileNotFoundError("A330 evaluation waits for A322 result")
    if file_sha256(A322_RESULT) != expected_a322_result_sha256:
        raise RuntimeError("A330 A322 result hash differs from explicit argument")
    panel = json.loads(PANEL.read_bytes())
    a322 = json.loads(A322_RESULT.read_bytes())
    if (
        a322.get("schema")
        != "chacha20-round20-holdout-selected-w45-recovery-a322-result-v1"
        or not str(a322.get("evidence_stage", "")).endswith("RECOVERY_CONFIRMED")
        or a322.get("confirmation", {}).get("all_blocks_match") is not True
        or a322.get("discovery", {}).get("matched_control_candidates") != 0
    ):
        raise RuntimeError("A330 A322 confirmation gate failed")
    prefix = int(a322["discovery"]["prefix12"])
    if not 0 <= prefix < CELLS:
        raise RuntimeError("A330 confirmed prefix is outside 12-bit domain")
    unique_rank: dict[str, Any] = {}
    for row in panel["unique_orders"]:
        rank = row["W45_order"].index(prefix) + 1
        unique_rank[row["unique_id"]] = {
            "canonical_alias": row["canonical_alias"],
            "aliases": row["aliases"],
            "W45_order_uint16be_sha256": row["W45_order_uint16be_sha256"],
            "rank_one_based": rank,
        }
    alias_ranks = {
        alias: unique_rank[unique_id]["rank_one_based"]
        for alias, unique_id in panel["alias_to_unique_id"].items()
    }
    comparison_aliases = panel["designated_comparisons"]
    executed_alias = comparison_aliases["executed_A322_order"]
    baseline_alias = comparison_aliases["A314_baseline"]
    executed_rank = alias_ranks[executed_alias]
    baseline_rank = alias_ranks[baseline_alias]
    alias_metrics = {
        alias: rank_metrics(rank, executed_rank, baseline_rank)
        for alias, rank in alias_ranks.items()
    }
    unique_metrics = {
        unique_id: {
            **row,
            **rank_metrics(row["rank_one_based"], executed_rank, baseline_rank),
        }
        for unique_id, row in unique_rank.items()
    }
    family_winners: dict[str, Any] = {}
    for family in FAMILY_ORDER:
        family_aliases = [
            alias for alias in panel["source_alias_sequence"] if alias.startswith(f"{family}/")
        ]
        winner = min(family_aliases, key=lambda alias: (alias_ranks[alias], family_aliases.index(alias)))
        family_winners[family] = {
            "alias": winner,
            **alias_metrics[winner],
        }
    global_winner = min(
        panel["source_alias_sequence"],
        key=lambda alias: (alias_ranks[alias], panel["source_alias_sequence"].index(alias)),
    )
    designated = {
        key: {"alias": alias, **alias_metrics[alias]}
        for key, alias in comparison_aliases.items()
    }
    payload: dict[str, Any] = {
        "schema": "chacha20-round20-w45-frozen-operator-panel-a330-evaluation-v1",
        "attempt_id": ATTEMPT_ID,
        "evidence_stage": "POSTCONFIRMATION_EXACT_DUPLICATE_FREE_W45_OPERATOR_RANK_PANEL_RETAINED",
        "design_sha256": DESIGN_SHA256,
        "panel_sha256": file_sha256(PANEL),
        "panel_commitment_sha256": panel["panel_commitment_sha256"],
        "A322_result_sha256": expected_a322_result_sha256,
        "confirmed_prefix": {
            "prefix12": prefix,
            "prefix12_hex": f"{prefix:03x}",
            "assignment": int(a322["discovery"]["candidate"]),
            "dual_confirmation": True,
        },
        "alias_rank_panel": alias_metrics,
        "unique_rank_panel": unique_metrics,
        "designated_rank_comparisons": designated,
        "family_winners": family_winners,
        "global_oracle_descriptive_winner": {
            "alias": global_winner,
            "prospectively_selected": False,
            **alias_metrics[global_winner],
        },
        "evaluation_boundary": {
            "orders_frozen_before_A322_result": True,
            "only_secret_derived_input": "independently confirmed prefix12",
            "orders_refit_after_A322": False,
            "duplicate_candidate_execution": False,
            "counterfactual_candidate_counts_are_complete_group_rank_times_2pow33": True,
            "matched_control_outcomes_inferred_for_counterfactual_orders": False,
        },
        "anchors": {
            "design": anchor(DESIGN, DESIGN_SHA256),
            "panel": anchor(PANEL),
            "A322_result": anchor(A322_RESULT, expected_a322_result_sha256),
            "runner": anchor(Path(__file__)),
            "test": anchor(A330_TEST),
            "reproducer": anchor(A330_REPRO),
        },
    }
    payload["evaluation_commitment_sha256"] = canonical_sha256(
        {
            "panel_commitment_sha256": payload["panel_commitment_sha256"],
            "A322_result_sha256": payload["A322_result_sha256"],
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
    primary = designated["A329_primary"]
    control = designated["A329_matched_direction_control"]
    raw = designated["executed_A322_order"]
    atomic_bytes(
        EVALUATION_REPORT,
        (
            "# A330 — confirmed W45 frozen-operator rank panel\n\n"
            f"- Confirmed prefix: **0x{prefix:03x}**\n"
            f"- Executed raw-Linf rank: **{raw['rank_one_based']} / 4,096**\n"
            f"- Frozen A329 primary rank: **{primary['rank_one_based']} / 4,096**\n"
            f"- Matched direction-control rank: **{control['rank_one_based']} / 4,096**\n"
            f"- Descriptive oracle alias: **{global_winner}** at rank **{alias_ranks[global_winner]}**\n"
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
        "A322_result_exists": A322_RESULT.exists(),
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
    parser.add_argument("--expected-a322-result-sha256")
    args = parser.parse_args()
    if args.evaluate:
        if not args.expected_a322_result_sha256:
            parser.error("--evaluate requires --expected-a322-result-sha256")
        payload = evaluate(args.expected_a322_result_sha256)
    elif args.materialize_panel:
        payload = materialize_panel()
    else:
        payload = analyze()
    print(json.dumps(payload, indent=2, sort_keys=True), flush=True)


if __name__ == "__main__":
    main()

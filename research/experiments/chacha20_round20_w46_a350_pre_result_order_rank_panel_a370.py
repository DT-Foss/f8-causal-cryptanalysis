#!/usr/bin/env python3
"""A370: exact postconfirmation rank panel for all frozen A345-target W46 orders."""

from __future__ import annotations

import argparse
import hashlib
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

DESIGN = CONFIGS / "chacha20_round20_w46_a350_pre_result_order_rank_panel_a370_design_v1.json"
RESULT = RESULTS / "chacha20_round20_w46_a350_pre_result_order_rank_panel_a370_v1.json"
CAUSAL = RESULT.with_suffix(".causal")
REPORT = RESULT.with_suffix(".md")
TEST = ROOT / "tests/test_chacha20_round20_w46_a350_pre_result_order_rank_panel_a370.py"
REPRO = ROOT / "scripts/reproduce_chacha20_round20_w46_a350_pre_result_order_rank_panel_a370.sh"

SOURCE_PATHS = {
    "A345": RESULTS / "chacha20_round20_fresh_w46_factor2_replication_a345_order_v1.json",
    "A349": RESULTS / "chacha20_round20_w46_direct12_prospective_a345_validation_a349_order_v1.json",
    "A351": RESULTS / "chacha20_round20_w46_dual_order_factor2_portfolio_a351_order_v1.json",
    "A356": RESULTS / "chacha20_round20_w46_corrected_group_a345_transfer_a356_order_v1.json",
    "A357": RESULTS / "chacha20_round20_w46_corrected_dual_order_factor2_portfolio_a357_order_v1.json",
}
A350_RESULT = RESULTS / "chacha20_round20_w46_a349_order_prospective_recovery_a350_v1.json"

ATTEMPT_ID = "A370"
DESIGN_SHA256 = "2f63d1733364900a6959d9fcc205ff4fe97f26af340ce2457dfde62b2f6ef31b"
GROUPS = 4096
GROUP_ASSIGNMENTS = 1 << 34
DOMAIN_SIZE = 1 << 46
DOTCAUSAL_SRC = Path("/Users/bhkmie/Documents/Forschung/O1/vendor/fabel/dotcausal_package/src")


def canonical_bytes(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def canonical_sha256(value: Any) -> str:
    return hashlib.sha256(canonical_bytes(value)).hexdigest()


def file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def relative(path: Path) -> str:
    try:
        return str(path.resolve().relative_to(ROOT.resolve()))
    except ValueError:
        return str(path.resolve())


def anchor(path: Path, expected: str | None = None) -> dict[str, str]:
    actual = file_sha256(path)
    if expected is not None and actual != expected:
        raise RuntimeError(f"A370 anchor differs: {path}")
    return {"path": relative(path), "sha256": actual}


def atomic_bytes(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.tmp")
    temporary.write_bytes(data)
    os.replace(temporary, path)


def atomic_json(path: Path, value: Mapping[str, Any]) -> None:
    atomic_bytes(path, json.dumps(value, indent=2, sort_keys=True).encode() + b"\n")


def exact_order(values: Sequence[int], label: str) -> list[int]:
    order = [int(value) for value in values]
    if len(order) != GROUPS or set(order) != set(range(GROUPS)):
        raise ValueError(f"A370 {label} is not an exact 4,096-group permutation")
    return order


def order_sha256(values: Sequence[int]) -> str:
    raw = b"".join(value.to_bytes(2, "big") for value in exact_order(values, "hash"))
    return hashlib.sha256(raw).hexdigest()


def load_design() -> dict[str, Any]:
    if file_sha256(DESIGN) != DESIGN_SHA256:
        raise RuntimeError("A370 design hash differs")
    value = json.loads(DESIGN.read_bytes())
    panel = value.get("panel_contract", {})
    boundary = value.get("information_boundary", {})
    aliases = value.get("order_aliases", [])
    if (
        value.get("schema")
        != "chacha20-round20-w46-a350-pre-result-order-rank-panel-a370-design-v1"
        or value.get("attempt_id") != ATTEMPT_ID
        or value.get("study_type")
        != "exact_postconfirmation_readback_of_immutable_pre_result_orders"
        or len(aliases) != 7
        or panel.get("duplicate_order_execution") != 0
        or panel.get("counterfactual_control_outcomes_inferred") != 0
        or panel.get("candidate_assignments_executed") != 0
        or boundary.get("all_order_bytes_frozen_before_A350_result") is not True
        or boundary.get("A350_prefix_used_only_for_exact_postconfirmation_lookup") is not True
        or boundary.get("orders_refit_after_A350") != 0
        or boundary.get("candidate_assignments_executed_by_A370") != 0
        or boundary.get("matched_control_outcomes_inferred_by_A370") != 0
    ):
        raise RuntimeError("A370 design semantics differ")
    for name, path_value in value["source_anchors"].items():
        if name.endswith("_path"):
            stem = name.removesuffix("_path")
            anchor(ROOT / path_value, value["source_anchors"][f"{stem}_sha256"])
    return value


def load_sources(design: Mapping[str, Any]) -> tuple[dict[str, Any], dict[str, Any]]:
    sources: dict[str, Any] = {}
    for name, path in SOURCE_PATHS.items():
        expected = design["source_anchors"][f"{name}_order_sha256"]
        anchor(path, expected)
        value = json.loads(path.read_bytes())
        if value.get("attempt_id") != name:
            raise RuntimeError(f"A370 source attempt differs: {name}")
        sources[name] = value
    anchor(A350_RESULT, design["source_anchors"]["A350_result_sha256"])
    a350 = json.loads(A350_RESULT.read_bytes())
    if (
        a350.get("attempt_id") != "A350"
        or a350.get("evidence_stage")
        != "FULLROUND_R20_PUBLIC_OUTPUT_CONDITIONED_W46_STRICT_SUBSET_RECOVERY_CONFIRMED"
        or a350.get("confirmation", {}).get("all_blocks_match") is not True
        or a350.get("confirmation", {}).get("total_cross_implementation_output_bits_checked")
        != 8192
        or a350.get("discovery", {}).get("matched_control_candidates") != 0
    ):
        raise RuntimeError("A370 A350 confirmation gate differs")
    return sources, a350


def build_causal(payload: Mapping[str, Any]) -> dict[str, Any]:
    sys.path.insert(0, str(DOTCAUSAL_SRC))
    from dotcausal.io import CausalReader, CausalWriter

    confirmed = "A350:independently_confirmed_W46_recovery"
    prefix = "A370:confirmed_Metal_prefix_0x794"
    frozen = "A370:seven_immutable_pre_result_orders"
    panel = "A370:exact_seven_order_rank_panel"
    winner = "A370:A349_executed_order_rank445_winner"
    writer = CausalWriter(api_id="a370rnk")
    writer._rules = []
    rules = [
        ("confirmation_to_prefix", [confirmed], prefix),
        ("prefix_and_orders_to_panel", [prefix, frozen], panel),
        ("panel_to_winner", [panel], winner),
    ]
    for name, pattern, conclusion in rules:
        writer.add_rule(
            name=name,
            description=name.replace("_", " "),
            pattern=pattern,
            conclusion=conclusion,
            confidence_modifier=1.0,
        )
    rows = [
        (
            confirmed,
            "dual_independent_confirmation_exposes_exact_prefix_only_for_postconfirmation_lookup",
            prefix,
            payload["A350_result_sha256"],
            payload["confirmed_recovery_identity"],
        ),
        (
            frozen,
            "exact_index_readback_without_refit_or_candidate_execution",
            panel,
            payload["panel_commitment_sha256"],
            payload["rank_panel"],
        ),
        (
            panel,
            "minimum_exact_rank_identifies_pre_result_executed_order",
            winner,
            payload["measurement_sha256"],
            payload["winner_and_comparisons"],
        ),
    ]
    for trigger, mechanism, outcome, source, quantification in rows:
        writer.add_triplet(
            trigger=trigger,
            mechanism=mechanism,
            outcome=outcome,
            confidence=1.0,
            source=source,
            quantification=json.dumps(quantification, sort_keys=True),
            evidence=payload["evidence_stage"],
            domain="ChaCha20 R20 W46 immutable pre-result order comparison",
            quality_score=1.0,
        )
    writer.add_triplet(
        trigger=confirmed,
        mechanism="materialized_confirmation_prefix_rank_panel_winner_chain",
        outcome=winner,
        confidence=1.0,
        source="materialized:A370_rank_panel",
        quantification="exact retained closure",
        evidence=payload["evidence_stage"],
        domain="AI-native retained inference",
        quality_score=1.0,
        is_inferred=True,
    )
    writer.add_cluster(
        name="A370 pre-result order panel", entities=[confirmed, prefix, frozen, panel, winner]
    )
    writer.add_gap(
        subject=winner,
        predicate="next_required_object",
        expected_object_type="fresh_cross_target_replication_or_W47_transfer",
        confidence=1.0,
        suggested_queries=[
            "Retain A349-style public-output conditioning only through a new prospectively validated cross-target Reader, then execute it on a fresh W46 target or qualified W47 engine."
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
        reader.api_id != "a370rnk"
        or len(explicit) != 3
        or len(all_rows) != 4
        or len(inferred) != 1
        or len(reader._rules) != 3
        or len(reader._clusters) != 1
        or len(reader._gaps) != 1
    ):
        raise RuntimeError("A370 authentic Causal reopen gate failed")
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
            "first_relation": explicit[0],
            "terminal_relation": explicit[-1],
            "materialized_chain": all_rows[-1],
            "next_gap": reader._gaps[0],
        },
    }


def run() -> dict[str, Any]:
    if any(path.exists() for path in (RESULT, CAUSAL, REPORT)):
        raise FileExistsError("A370 result already exists")
    design = load_design()
    sources, a350 = load_sources(design)
    prefix = int(a350["discovery"]["prefix12"])
    if prefix != int(a350["rank_analysis"]["confirmed_prefix12"]):
        raise RuntimeError("A370 confirmed prefix identity differs")
    panel: list[dict[str, Any]] = []
    for row in design["order_aliases"]:
        alias = str(row["alias"])
        source = str(row["source"])
        field = str(row["field"])
        order = exact_order(sources[source][field], alias)
        rank = order.index(prefix) + 1
        panel.append(
            {
                "alias": alias,
                "source_attempt": source,
                "field": field,
                "order_uint16be_sha256": order_sha256(order),
                "exact_group_rank_one_based": rank,
                "complete_group_assignment_bound": rank * GROUP_ASSIGNMENTS,
                "domain_reduction_factor": GROUPS / rank,
                "search_gain_bits": math.log2(GROUPS / rank),
            }
        )
    panel.sort(key=lambda row: (row["exact_group_rank_one_based"], row["alias"]))
    winner = panel[0]
    if (
        winner["alias"] != "A349.selected_order"
        or winner["exact_group_rank_one_based"]
        != int(a350["discovery"]["executed_prefix_groups"])
        or winner["complete_group_assignment_bound"]
        != int(a350["discovery"]["executed_assignments"])
    ):
        raise RuntimeError("A370 executed A349 identity gate failed")
    order_hashes = [row["order_uint16be_sha256"] for row in panel]
    if len(set(order_hashes)) != len(order_hashes):
        raise RuntimeError("A370 design unexpectedly contains duplicate order bytes")
    comparisons: dict[str, Any] = {}
    for row in panel[1:]:
        ratio = row["exact_group_rank_one_based"] / winner["exact_group_rank_one_based"]
        comparisons[row["alias"]] = {
            "A349_rank_improvement_factor": ratio,
            "A349_additional_gain_bits": math.log2(ratio),
            "complete_group_assignments_avoided_by_executed_A349": (
                row["exact_group_rank_one_based"]
                - winner["exact_group_rank_one_based"]
            )
            * GROUP_ASSIGNMENTS,
        }
    payload: dict[str, Any] = {
        "schema": "chacha20-round20-w46-a350-pre-result-order-rank-panel-a370-v1",
        "attempt_id": ATTEMPT_ID,
        "evidence_stage": "POSTCONFIRMATION_EXACT_PRE_RESULT_ORDER_PANEL_A349_EXECUTED_WINNER_RETAINED",
        "design_sha256": DESIGN_SHA256,
        "A350_result_sha256": file_sha256(A350_RESULT),
        "confirmed_recovery_identity": {
            "candidate": int(a350["discovery"]["candidate"]),
            "candidate_hex": str(a350["discovery"]["candidate_hex"]),
            "confirmed_prefix12": prefix,
            "confirmed_prefix12_hex": f"{prefix:03x}",
            "all_eight_blocks_match": True,
            "cross_implementation_output_bits_checked": 8192,
            "matched_control_candidates": 0,
        },
        "rank_panel": panel,
        "ranked_aliases": [row["alias"] for row in panel],
        "unique_order_count": len(set(order_hashes)),
        "winner_and_comparisons": {
            "winner": winner,
            "comparisons_to_executed_A349": comparisons,
            "primary_target_free_baseline": comparisons["A345.selected_order"],
            "corrected_coordinate_reader": comparisons["A356.selected_order"],
        },
        "duplicate_candidate_executions": 0,
        "counterfactual_control_outcomes_inferred": 0,
        "orders_refit_after_A350": 0,
        "information_boundary": design["information_boundary"],
        "anchors": {
            "design": anchor(DESIGN, DESIGN_SHA256),
            **{
                f"{name}_order": anchor(
                    path, design["source_anchors"][f"{name}_order_sha256"]
                )
                for name, path in SOURCE_PATHS.items()
            },
            "A350_result": anchor(
                A350_RESULT, design["source_anchors"]["A350_result_sha256"]
            ),
            "runner": anchor(Path(__file__)),
            "test": anchor(TEST),
            "reproducer": anchor(REPRO),
        },
    }
    payload["panel_commitment_sha256"] = canonical_sha256(
        {
            "design_sha256": DESIGN_SHA256,
            "A350_result_sha256": payload["A350_result_sha256"],
            "confirmed_prefix12": prefix,
            "rank_panel": panel,
            "duplicate_candidate_executions": 0,
            "counterfactual_control_outcomes_inferred": 0,
        }
    )
    payload["measurement_sha256"] = canonical_sha256(
        {
            "panel_commitment_sha256": payload["panel_commitment_sha256"],
            "winner_and_comparisons": payload["winner_and_comparisons"],
            "ranked_aliases": payload["ranked_aliases"],
        }
    )
    payload["causal"] = build_causal(payload)
    atomic_json(RESULT, payload)
    baseline = comparisons["A345.selected_order"]
    corrected = comparisons["A356.selected_order"]
    atomic_bytes(
        REPORT,
        (
            "# A370 — exact pre-result W46 order rank panel\n\n"
            f"Evidence stage: **{payload['evidence_stage']}**\n\n"
            f"- Executed winner: **{winner['alias']} at rank {winner['exact_group_rank_one_based']} / {GROUPS:,}**\n"
            f"- Target-free A345 selected order: **{baseline['A349_rank_improvement_factor']:.9f}x later**\n"
            f"- Corrected-coordinate A356 order: **{corrected['A349_rank_improvement_factor']:.9f}x later**\n"
            f"- Exact unique pre-result orders: **{payload['unique_order_count']}**\n"
            "- Duplicate candidate executions / inferred control outcomes: **0 / 0**\n"
            "- Authentic AI-native Causal readback: **3 explicit + 1 inferred**\n"
        ).encode(),
    )
    return payload


def analyze() -> dict[str, Any]:
    return {
        "attempt_id": ATTEMPT_ID,
        "design_sha256": DESIGN_SHA256,
        "result_complete": RESULT.exists(),
        "result_sha256": file_sha256(RESULT) if RESULT.exists() else None,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    action = parser.add_mutually_exclusive_group(required=True)
    action.add_argument("--run", action="store_true")
    action.add_argument("--analyze", action="store_true")
    args = parser.parse_args()
    payload = run() if args.run else analyze()
    print(json.dumps(payload, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()

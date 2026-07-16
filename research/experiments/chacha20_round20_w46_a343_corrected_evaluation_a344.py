#!/usr/bin/env python3
"""A344: correctly evaluate the immutable A343 W46 pre-result order panel."""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import inspect
import json
import math
import os
import sys
from collections.abc import Mapping
from pathlib import Path
from typing import Any

ROOT = Path(__file__).parents[2]
RESEARCH = ROOT / "research"
CONFIGS = RESEARCH / "configs"
RESULTS = RESEARCH / "results/v1"

DESIGN = CONFIGS / "chacha20_round20_w46_a343_corrected_evaluation_a344_design_v1.json"
RESULT = RESULTS / "chacha20_round20_w46_a343_corrected_evaluation_a344_v1.json"
CAUSAL = RESULT.with_suffix(".causal")
REPORT = RESULTS / "chacha20_round20_w46_a343_corrected_evaluation_a344_v1.md"
TEST = ROOT / "tests/test_chacha20_round20_w46_a343_corrected_evaluation_a344.py"
REPRO = ROOT / "scripts/reproduce_chacha20_round20_w46_a343_corrected_evaluation_a344.sh"

A343_RUNNER = RESEARCH / "experiments/chacha20_round20_w46_pre_result_operator_panel_a343.py"
A343_PANEL = RESULTS / "chacha20_round20_w46_pre_result_operator_panel_a343_v1.json"
A325_RESULT = RESULTS / "chacha20_round20_holdout_selected_w46_recovery_a325_v1.json"

ATTEMPT_ID = "A344"
DESIGN_SHA256 = "e7988f200afbaad949f60c437dc4004021b9392956c8a608cb2d9a930c3ab8b1"
A343_PANEL_SHA256 = "aac9c6ec5a46115ea3c0ddc2a15dd0abe5f7a83d4f23c60c6c2d266de8f63525"
A325_RESULT_SHA256 = "534d2d769f387bca90b9ab1f2c43a98a6030c1e3c1039270c1d2e109a38d7ce2"
A325_PROTOCOL_SHA256 = "480fe15f22c87df1b9422c1dc8cfcf5a9add147f65b6631d25e94d66b5255a2c"
A343_PANEL_COMMITMENT_SHA256 = "ff688da9533a4ced485e196e1ac5299a72b6a46fd6c46d21031d2a4ca1321f90"
CELLS = 1 << 12
CANDIDATES_PER_GROUP = 1 << 34
COMPLETE_DOMAIN = 1 << 46
WORD0_MASK = (1 << 32) - 1
WORD0_SUFFIX_BITS = 20
DOTCAUSAL_SRC = Path(
    "/Users/bhkmie/Documents/Forschung/O1/vendor/fabel/dotcausal_package/src"
)

_SPEC = importlib.util.spec_from_file_location("a344_a343", A343_RUNNER)
if _SPEC is None or _SPEC.loader is None:
    raise RuntimeError("cannot import the immutable A343 implementation")
_A343 = importlib.util.module_from_spec(_SPEC)
sys.modules[_SPEC.name] = _A343
_SPEC.loader.exec_module(_A343)
A343 = _A343


def file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def canonical_sha256(value: Any) -> str:
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()
    ).hexdigest()


def atomic_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.tmp")
    temporary.write_text(json.dumps(payload, indent=2, sort_keys=True, allow_nan=False) + "\n")
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
        raise RuntimeError(f"A344 anchor differs: {path}")
    return {"path": relative(path), "sha256": observed}


def decode_word0_prefix12(assignment: int) -> int:
    """Decode the A324/A325 group: word0 bits 20..31, not assignment bits 34..45."""
    if not 0 <= assignment < COMPLETE_DOMAIN:
        raise ValueError("A344 assignment exceeds the exact W46 domain")
    return ((assignment & WORD0_MASK) >> WORD0_SUFFIX_BITS) & (CELLS - 1)


def load_design() -> dict[str, Any]:
    anchor(DESIGN, DESIGN_SHA256)
    design = json.loads(DESIGN.read_bytes())
    correction = design.get("correction_contract", {})
    evaluation = design.get("evaluation_contract", {})
    boundary = design.get("information_boundary", {})
    if (
        design.get("schema")
        != "chacha20-round20-w46-a343-corrected-evaluation-a344-design-v1"
        or design.get("attempt_id") != ATTEMPT_ID
        or correction.get("affected_component") != "A343 postconfirmation evaluator only"
        or correction.get("frozen_A343_order_membership_changed") is not False
        or correction.get("frozen_A343_order_bytes_changed") is not False
        or correction.get("new_candidate_execution") is not False
        or correction.get("original_invalid_expression") != "assignment >> 34"
        or correction.get("replacement_expression")
        != "((assignment & 0xffffffff) >> 20)"
        or evaluation.get("alias_count") != 73
        or evaluation.get("unique_order_count") != 57
        or evaluation.get("duplicate_alias_count") != 16
        or evaluation.get("complete_candidate_domain") != COMPLETE_DOMAIN
        or evaluation.get("counterfactual_candidate_execution") is not False
        or evaluation.get("matched_control_outcome_inferred") is not False
        or boundary.get("A325_result_available_at_A343_panel_freeze") is not False
        or boundary.get("A343_panel_commitment_preserved") is not True
        or boundary.get("orders_refit_after_A325") is not False
        or boundary.get("target_labels_used_to_construct_A343_orders") != 0
    ):
        raise RuntimeError("A344 frozen correction semantics differ")
    anchors = design["source_anchors"]
    for key, value in anchors.items():
        if key.endswith("_path"):
            anchor(ROOT / value, anchors[key.removesuffix("_path") + "_sha256"])
    return design


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


def build_causal(payload: Mapping[str, Any]) -> dict[str, Any]:
    sys.path.insert(0, str(DOTCAUSAL_SRC))
    from dotcausal.io import CausalReader, CausalWriter

    terminal = "A344:correctly_evaluated_frozen_A343_W46_panel"
    writer = CausalWriter(api_id="a344fix")
    writer._rules = []
    writer.add_rule(
        name="A325_assignment_to_A324_word0_prefix",
        description="Decode assignment word0 bits 20..31 as the exact A324/A325 prefix group.",
        pattern=["A325_confirmed_assignment", "A324_W46_assignment_codec"],
        conclusion="A344_confirmed_word0_prefix12",
        confidence_modifier=1.0,
    )
    writer.add_rule(
        name="confirmed_prefix_to_frozen_A343_ranks",
        description="Locate one confirmed prefix in every immutable A343 exact order.",
        pattern=["A344_confirmed_word0_prefix12", "A343_frozen_57_order_panel"],
        conclusion="A344_exact_rank_panel",
        confidence_modifier=1.0,
    )
    writer.add_rule(
        name="corrected_rank_panel_to_replication_rule",
        description="Retain the best pre-result noncontrol operator as a descriptive replication candidate.",
        pattern=["A344_exact_rank_panel", "A344_noncontrol_filter"],
        conclusion="A344_replication_candidate",
        confidence_modifier=1.0,
    )
    writer.add_triplet(
        trigger="A325:independently_confirmed_W46_assignment",
        mechanism="A324_assignment_codec_word0_bits_20_through_31",
        outcome="A344:confirmed_word0_prefix12",
        confidence=1.0,
        source=payload["A325_result_sha256"],
        quantification=json.dumps(payload["confirmed_prefix"], sort_keys=True),
        evidence="THIRD_IMPLEMENTATION_AND_DUAL_REFERENCE_CONFIRMATION",
        domain="confirmed full-round ChaCha20 recovery",
        quality_score=1.0,
    )
    writer.add_triplet(
        trigger="A344:confirmed_word0_prefix12",
        mechanism="lookup_in_57_immutable_pre_result_orders",
        outcome="A344:exact_57_order_rank_panel",
        confidence=1.0,
        source=payload["evaluation_measurement_sha256"],
        quantification=json.dumps(payload["family_winners"], sort_keys=True),
        evidence="ZERO_REFITS_ZERO_DUPLICATE_CIPHER_EXECUTION",
        domain="postconfirmation order evaluation",
        quality_score=1.0,
    )
    writer.add_triplet(
        trigger="A344:exact_57_order_rank_panel",
        mechanism="exclude_public_hash_control_then_exact_rank_minimum",
        outcome=terminal,
        confidence=1.0,
        source=payload["evaluation_commitment_sha256"],
        quantification=json.dumps(payload["best_noncontrol_descriptive_winner"], sort_keys=True),
        evidence=json.dumps(payload["evaluation_boundary"], sort_keys=True),
        domain="W46 prospective replication frontier",
        quality_score=1.0,
    )
    writer.add_triplet(
        trigger="A325:independently_confirmed_W46_assignment",
        mechanism="materialized_correct_codec_to_frozen_panel_chain",
        outcome=terminal,
        confidence=1.0,
        source="materialized:A344_corrected_A343_evaluation_chain",
        quantification="exact retained closure",
        evidence=payload["evidence_stage"],
        domain="AI-native retained inference",
        quality_score=1.0,
        is_inferred=True,
    )
    writer.add_cluster(
        name="A344 corrected immutable A343 evaluation",
        entities=[
            "A325:independently_confirmed_W46_assignment",
            "A344:confirmed_word0_prefix12",
            "A344:exact_57_order_rank_panel",
            terminal,
        ],
    )
    writer.add_gap(
        subject=terminal,
        predicate="next_required_object",
        expected_object_type="fresh_prospective_W46_replication_or_W47_transfer",
        confidence=1.0,
        suggested_queries=[
            "Does the frozen best noncontrol A343 rule retain strict-subset concentration on a fresh target?"
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
        reader.api_id != "a344fix"
        or len(explicit) != 3
        or len(all_rows) != 4
        or len(inferred) != 1
        or len(reader._rules) != 3
        or len(reader._clusters) != 1
        or len(reader._gaps) != 1
    ):
        raise RuntimeError("A344 authentic Causal reopen gate failed")
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


def evaluate(expected_a325_result_sha256: str) -> dict[str, Any]:
    if any(path.exists() for path in (RESULT, CAUSAL, REPORT)):
        raise FileExistsError("A344 evaluation artifacts already exist")
    design = load_design()
    if expected_a325_result_sha256 != A325_RESULT_SHA256:
        raise RuntimeError("A344 explicit A325 result hash differs from the design anchor")
    anchor(A343_PANEL, A343_PANEL_SHA256)
    anchor(A325_RESULT, expected_a325_result_sha256)
    panel = json.loads(A343_PANEL.read_bytes())
    result = json.loads(A325_RESULT.read_bytes())
    discovery = result.get("discovery", {})
    confirmation = result.get("confirmation", {})
    if (
        panel.get("schema") != "chacha20-round20-w46-pre-result-operator-panel-a343-v1"
        or panel.get("panel_commitment_sha256") != A343_PANEL_COMMITMENT_SHA256
        or panel.get("alias_count") != 73
        or panel.get("unique_order_count") != 57
        or panel.get("duplicate_alias_count") != 16
        or result.get("schema")
        != "chacha20-round20-holdout-selected-w46-recovery-a325-result-v1"
        or result.get("protocol_sha256") != A325_PROTOCOL_SHA256
        or not str(result.get("evidence_stage", "")).endswith("RECOVERY_CONFIRMED")
        or confirmation.get("all_blocks_match") is not True
        or confirmation.get("total_cross_implementation_output_bits_checked") != 8192
        or discovery.get("matched_control_candidates") != 0
        or result.get("selected_W46_order_uint16be_sha256") != A343.RAW_ORDER_SHA256
    ):
        raise RuntimeError("A344 source confirmation gate failed")
    candidate = int(discovery["candidate"])
    prefix = int(discovery["prefix12"])
    executed_rank = int(discovery["executed_prefix_groups"])
    decoded_prefix = decode_word0_prefix12(candidate)
    if (
        decoded_prefix != prefix
        or int(confirmation["assignment"]) != candidate
        or not 1 <= executed_rank <= CELLS
        or executed_rank * CANDIDATES_PER_GROUP
        != int(discovery["executed_assignments"])
    ):
        raise RuntimeError("A344 confirmed A324/A325 prefix mapping differs")

    unique_rank: dict[str, Any] = {}
    for row in panel["unique_orders"]:
        order = A343.exact_order(row["W46_order"], row["unique_id"])
        if A343.order_sha(order) != row["W46_order_uint16be_sha256"]:
            raise RuntimeError("A344 immutable A343 order hash differs")
        rank = order.index(prefix) + 1
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
        raise RuntimeError("A344 executed raw-Linf rank differs from A325")
    alias_metrics = {
        alias: rank_metrics(rank, executed_rank) for alias, rank in alias_ranks.items()
    }
    unique_metrics = {
        unique_id: {**row, **rank_metrics(row["rank_one_based"], executed_rank)}
        for unique_id, row in unique_rank.items()
    }
    family_winners: dict[str, Any] = {}
    for family in A343.FAMILY_ORDER:
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
    control_alias = panel["designated_comparisons"]["public_hash_control"]
    noncontrol_aliases = [
        alias for alias in panel["source_alias_sequence"] if alias != control_alias
    ]
    best_noncontrol = min(
        noncontrol_aliases,
        key=lambda alias: (
            alias_ranks[alias],
            panel["source_alias_sequence"].index(alias),
        ),
    )
    designated = {
        key: {"alias": alias, **alias_metrics[alias]}
        for key, alias in panel["designated_comparisons"].items()
    }
    correction_audit = {
        "old_expression": "assignment >> 34",
        "old_expression_value": candidate >> 34,
        "correct_expression": "((assignment & 0xffffffff) >> 20)",
        "correct_expression_value": decoded_prefix,
        "A325_recorded_prefix12": prefix,
        "old_expression_rejected": candidate >> 34 != prefix,
        "correct_expression_matches": decoded_prefix == prefix,
        "A343_panel_or_orders_modified": False,
    }
    boundary = {
        "all_73_aliases_and_57_unique_orders_frozen_before_A325_result": True,
        "only_secret_derived_input": "independently confirmed word0 prefix12",
        "orders_refit_after_A325": False,
        "duplicate_candidate_execution": False,
        "counterfactual_candidate_counts_are_complete_group_rank_times_2pow34": True,
        "matched_control_outcomes_inferred_for_counterfactual_orders": False,
        "postconfirmation_codec_correction_changes_order_membership_or_bytes": False,
    }
    payload: dict[str, Any] = {
        "schema": "chacha20-round20-w46-a343-corrected-evaluation-a344-v1",
        "attempt_id": ATTEMPT_ID,
        "evidence_stage": "A343_IMMUTABLE_PRE_RESULT_W46_PANEL_CORRECTLY_EVALUATED_AFTER_A325_CONFIRMATION",
        "design_sha256": DESIGN_SHA256,
        "A343_panel_sha256": A343_PANEL_SHA256,
        "A343_panel_commitment_sha256": A343_PANEL_COMMITMENT_SHA256,
        "A325_result_sha256": expected_a325_result_sha256,
        "confirmed_prefix": {
            "prefix12": prefix,
            "prefix12_hex": f"{prefix:03x}",
            "assignment": candidate,
            "assignment_hex": f"{candidate:012x}",
            "codec": "word0=(assignment & 0xffffffff); prefix12=word0>>20",
            "dual_confirmation": True,
            "cross_implementation_output_bits_checked": 8192,
        },
        "codec_correction_audit": correction_audit,
        "alias_rank_panel": alias_metrics,
        "unique_rank_panel": unique_metrics,
        "designated_rank_comparisons": designated,
        "family_winners": family_winners,
        "global_oracle_descriptive_winner": {
            "alias": global_winner,
            "prospectively_selected_for_A325": False,
            **alias_metrics[global_winner],
        },
        "best_noncontrol_descriptive_winner": {
            "alias": best_noncontrol,
            "prospectively_selected_for_A325": False,
            **alias_metrics[best_noncontrol],
        },
        "evaluation_boundary": boundary,
        "anchors": {
            "design": anchor(DESIGN, DESIGN_SHA256),
            "A343_panel": anchor(A343_PANEL, A343_PANEL_SHA256),
            "A343_runner_immutable": anchor(A343_RUNNER, design["source_anchors"]["A343_runner_sha256"]),
            "A325_result": anchor(A325_RESULT, expected_a325_result_sha256),
            "runner": anchor(Path(__file__)),
            "test": anchor(TEST),
            "reproducer": anchor(REPRO),
        },
    }
    payload["evaluation_commitment_sha256"] = canonical_sha256(
        {
            "A343_panel_commitment_sha256": payload["A343_panel_commitment_sha256"],
            "A325_result_sha256": payload["A325_result_sha256"],
            "confirmed_prefix": payload["confirmed_prefix"],
            "codec_correction_audit": correction_audit,
            "designated_rank_comparisons": designated,
            "evaluation_boundary": boundary,
        }
    )
    payload["evaluation_measurement_sha256"] = canonical_sha256(
        {
            "alias_rank_panel": alias_metrics,
            "unique_rank_panel": unique_metrics,
            "family_winners": family_winners,
            "global_oracle_descriptive_winner": payload["global_oracle_descriptive_winner"],
            "best_noncontrol_descriptive_winner": payload["best_noncontrol_descriptive_winner"],
        }
    )
    payload["causal"] = build_causal(payload)
    atomic_json(RESULT, payload)
    raw = designated["executed_A325_raw_Linf"]
    best = payload["best_noncontrol_descriptive_winner"]
    atomic_bytes(
        REPORT,
        (
            "# A344 — corrected evaluation of the immutable A343 W46 panel\n\n"
            f"- Confirmed assignment: **0x{candidate:012x}**\n"
            f"- Correct A324/A325 word0 prefix: **0x{prefix:03x}**\n"
            f"- Executed raw-Linf rank: **{raw['rank_one_based']} / 4,096**\n"
            f"- Best pre-result noncontrol order: **{best['alias']}**\n"
            f"- Best noncontrol rank: **{best['rank_one_based']} / 4,096**\n"
            f"- Best noncontrol gain / domain reduction: **{best['gain_bits_vs_complete_2pow46_domain']:.8f} bits / {best['domain_reduction_factor']:.3f}x**\n"
            f"- Speed factor versus executed raw Linf: **{best['speed_factor_vs_executed_raw_Linf']:.3f}x**\n"
            "- A343 panel membership/order bytes changed: **no**\n"
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
        "A343_panel_sha256": file_sha256(A343_PANEL),
        "A325_result_sha256": file_sha256(A325_RESULT),
        "result_exists": RESULT.exists(),
    }
    if RESULT.exists():
        payload = json.loads(RESULT.read_bytes())
        response.update(
            {
                "result_sha256": file_sha256(RESULT),
                "confirmed_prefix": payload["confirmed_prefix"],
                "best_noncontrol_descriptive_winner": payload[
                    "best_noncontrol_descriptive_winner"
                ],
            }
        )
    return response


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    action = parser.add_mutually_exclusive_group(required=True)
    action.add_argument("--analyze", action="store_true")
    action.add_argument("--evaluate", action="store_true")
    parser.add_argument("--expected-a325-result-sha256")
    args = parser.parse_args()
    if args.evaluate:
        if not args.expected_a325_result_sha256:
            parser.error("--evaluate requires --expected-a325-result-sha256")
        payload = evaluate(args.expected_a325_result_sha256)
    else:
        payload = analyze()
    print(json.dumps(payload, indent=2, sort_keys=True), flush=True)


if __name__ == "__main__":
    main()

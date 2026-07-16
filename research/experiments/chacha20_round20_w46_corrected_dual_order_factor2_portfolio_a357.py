#!/usr/bin/env python3
"""A357: freeze the exact factor-two portfolio of A345 and corrected A356 orders."""

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
from pathlib import Path
from typing import Any

ROOT = Path(__file__).parents[2]
RESEARCH = ROOT / "research"
CONFIGS = RESEARCH / "configs"
RESULTS = RESEARCH / "results/v1"

DESIGN = CONFIGS / "chacha20_round20_w46_corrected_dual_order_factor2_portfolio_a357_design_v1.json"
ORDER = RESULTS / "chacha20_round20_w46_corrected_dual_order_factor2_portfolio_a357_order_v1.json"
ORDER_CAUSAL = ORDER.with_suffix(".causal")
ORDER_REPORT = ORDER.with_suffix(".md")
EVALUATION = RESULTS / "chacha20_round20_w46_corrected_dual_order_factor2_portfolio_a357_evaluation_v1.json"
EVALUATION_CAUSAL = EVALUATION.with_suffix(".causal")
EVALUATION_REPORT = EVALUATION.with_suffix(".md")
TEST = ROOT / "tests/test_chacha20_round20_w46_corrected_dual_order_factor2_portfolio_a357.py"
REPRO = ROOT / "scripts/reproduce_chacha20_round20_w46_corrected_dual_order_factor2_portfolio_a357.sh"

A351_RUNNER = RESEARCH / "experiments/chacha20_round20_w46_dual_order_factor2_portfolio_a351.py"
A345_ORDER = RESULTS / "chacha20_round20_fresh_w46_factor2_replication_a345_order_v1.json"
A345_PROTOCOL = CONFIGS / "chacha20_round20_fresh_w46_factor2_replication_a345_v1.json"
A345_PROGRESS = RESULTS / "chacha20_round20_fresh_w46_factor2_replication_a345_progress_v1.json"
A345_RESULT = RESULTS / "chacha20_round20_fresh_w46_factor2_replication_a345_v1.json"
A350_PROGRESS = RESULTS / "chacha20_round20_w46_a349_order_prospective_recovery_a350_progress_v1.json"
A350_RESULT = RESULTS / "chacha20_round20_w46_a349_order_prospective_recovery_a350_v1.json"
A356_ORDER = RESULTS / "chacha20_round20_w46_corrected_group_a345_transfer_a356_order_v1.json"

ATTEMPT_ID = "A357"
DESIGN_SHA256 = "d596669deb4b6c26132977fb181f0d251aee7bd8fd6ac8e3c9a99999584a2089"
A345_ORDER_SHA256 = "9f0a7a1773894b4a265a6e456bd3489c10fd5f44e7ef9d40dc4706699fa0107d"
A345_PROTOCOL_SHA256 = "8e4280d6603f1eacac0345df634113ed1b550f5d5292c2bed75cc31b19a07f95"
A356_ORDER_SHA256 = "2069c706d070ac1add659232a08c80a6b46d213cc9c6abb5ad9eebf99afc481a"
A356_SELECTED_ORDER_SHA256 = "436082dcc2a3b3f1be1ff5459c11b40de84aa57ef0bc160cc8fa57af17ae692f"
A345_PUBLIC_CHALLENGE_SHA256 = "622f7b7218d022167e50efef459983e54207165078c49f0bb253c70545e3231f"
CELLS = 1 << 12
DOTCAUSAL_SRC = Path("/Users/bhkmie/Documents/Forschung/O1/vendor/fabel/dotcausal_package/src")


def load_module(path: Path, name: str) -> Any:
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot import A357 dependency {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


A351 = load_module(A351_RUNNER, "a357_a351_common")
file_sha256 = A351.file_sha256
canonical_sha256 = A351.canonical_sha256
atomic_json = A351.atomic_json
atomic_bytes = A351.atomic_bytes
exact_order = A351.exact_order
order_sha256 = A351.order_sha256
rank_vector = A351.rank_vector
factor2_wavefront = A351.factor2_wavefront
diversity_panel = A351.diversity_panel


def factor2_proof(
    first: Sequence[int], second: Sequence[int], portfolio: Sequence[int]
) -> dict[str, Any]:
    proof = A351.factor2_proof(first, second, portfolio)
    proof["bound"] = "R_portfolio(c) <= 2*min(R_A345(c),R_A356(c))"
    return proof


def relative(path: Path) -> str:
    resolved = path.resolve()
    try:
        return str(resolved.relative_to(ROOT.resolve()))
    except ValueError:
        return str(resolved)


def anchor(path: Path, expected: str | None = None) -> dict[str, str]:
    digest = file_sha256(path)
    if expected is not None and digest != expected:
        raise RuntimeError(f"A357 anchor hash differs: {path}")
    return {"path": relative(path), "sha256": digest}


def load_design() -> dict[str, Any]:
    if file_sha256(DESIGN) != DESIGN_SHA256:
        raise RuntimeError("A357 design hash differs")
    value = json.loads(DESIGN.read_bytes())
    boundary = value.get("information_boundary", {})
    contract = value.get("portfolio_contract", {})
    if (
        value.get("schema")
        != "chacha20-round20-w46-corrected-dual-order-factor2-portfolio-a357-design-v1"
        or value.get("attempt_id") != ATTEMPT_ID
        or value.get("design_state")
        != "frozen_before_A345_or_A350_candidate_prefix_or_result"
        or contract.get("cells") != CELLS
        or boundary.get("A345_result_available_at_design_freeze") is not False
        or boundary.get("A350_result_available_at_design_freeze") is not False
        or boundary.get("A356_order_frozen_before_design") is not True
        or boundary.get("target_labels_used_for_portfolio_construction") != 0
    ):
        raise RuntimeError("A357 frozen design semantics differ")
    sources = value["source_anchors"]
    for name, path, digest in (
        ("A345_order", A345_ORDER, A345_ORDER_SHA256),
        ("A345_protocol", A345_PROTOCOL, A345_PROTOCOL_SHA256),
        ("A356_order", A356_ORDER, A356_ORDER_SHA256),
    ):
        if sources[f"{name}_path"] != relative(path):
            raise RuntimeError(f"A357 source path differs: {name}")
        anchor(path, digest)
    return value


def load_sources() -> tuple[dict[str, Any], dict[str, Any], list[int], list[int]]:
    load_design()
    a345 = json.loads(A345_ORDER.read_bytes())
    a356 = json.loads(A356_ORDER.read_bytes())
    protocol = json.loads(A345_PROTOCOL.read_bytes())
    first = exact_order(a345.get("selected_order", []), "A357 A345 source")
    second = exact_order(a356.get("selected_order", []), "A357 A356 source")
    if (
        order_sha256(first) != a345.get("selected_order_uint16be_sha256")
        or order_sha256(second) != A356_SELECTED_ORDER_SHA256
        or a356.get("schema")
        != "chacha20-round20-w46-corrected-group-a345-transfer-a356-order-v1"
        or a356.get("target_labels_used") != 0
        or a356.get("reader_refits") != 0
        or a356.get("A345_result_available_at_order_freeze") is not False
        or a356.get("A345_candidate_or_prefix_read_before_order_freeze") is not False
        or protocol.get("public_challenge_sha256") != A345_PUBLIC_CHALLENGE_SHA256
    ):
        raise RuntimeError("A357 source-order semantics differ")
    return a345, a356, first, second


def _candidate_free(path: Path, attempt_id: str) -> dict[str, Any]:
    if not path.exists():
        return {"available": False}
    raw = path.read_bytes()
    value = json.loads(raw)
    forbidden = {"candidate", "prefix12", "prefix12_hex"}
    if (
        value.get("attempt_id") != attempt_id
        or value.get("status") == "candidate_found"
        or value.get("factual_filter_candidates") != 0
        or value.get("matched_control_candidates") != 0
        or forbidden.intersection(value)
    ):
        raise RuntimeError(f"A357 {attempt_id} progress is no longer candidate-free")
    return {
        "available": True,
        "sha256": hashlib.sha256(raw).hexdigest(),
        "status": value.get("status"),
        "executed_prefix_groups": int(value.get("executed_prefix_groups", 0)),
        "mtime_ns": path.stat().st_mtime_ns,
    }


def candidate_free_snapshot() -> dict[str, Any]:
    if A345_RESULT.exists() or A350_RESULT.exists():
        raise RuntimeError("A357 freeze requires A345 and A350 result absence")
    return {
        "A345_result_available": False,
        "A350_result_available": False,
        "A345": _candidate_free(A345_PROGRESS, "A345"),
        "A350": _candidate_free(A350_PROGRESS, "A350"),
    }


def build_order_causal(payload: Mapping[str, Any]) -> dict[str, Any]:
    sys.path.insert(0, str(DOTCAUSAL_SRC))
    from dotcausal.io import CausalReader, CausalWriter

    writer = CausalWriter(api_id="a357pf2")
    writer._rules = []
    writer.add_rule(
        name="corrected_dual_order_to_factor2_wavefront",
        description="The target-free A345 order and corrected-coordinate A356 order induce an exact stable min-rank wavefront.",
        pattern=["A345_target_free_order", "A356_corrected_public_output_order"],
        conclusion="A357_corrected_dual_order_factor2_wavefront",
        confidence_modifier=1.0,
    )
    writer.add_rule(
        name="pointwise_bound_to_protected_recovery_order",
        description="The complete pointwise proof protects whichever source reaches every unseen Metal-group cell first within factor two.",
        pattern=["A357_corrected_dual_order_factor2_wavefront", "A357_complete_pointwise_proof"],
        conclusion="A357_protected_corrected_recovery_order",
        confidence_modifier=1.0,
    )
    writer.add_triplet(
        trigger="A345:target_free_factor2_order",
        mechanism="enters_complete_dual_source_order_set",
        outcome="A357:complete_dual_source_order_set",
        confidence=1.0,
        source=payload["order_commitment_sha256"],
        quantification=payload["source_orders"]["A345"]["selected_order_uint16be_sha256"],
        evidence="complete target-free 4096-cell source order",
        domain="prospective ChaCha20 R20 W46 Metal-group ordering",
        quality_score=1.0,
    )
    writer.add_triplet(
        trigger="A356:corrected_public_output_order",
        mechanism="enters_complete_dual_source_order_set",
        outcome="A357:complete_dual_source_order_set",
        confidence=1.0,
        source=payload["order_commitment_sha256"],
        quantification=json.dumps(payload["operator_diversity"], sort_keys=True),
        evidence="zero-label zero-refit source orders",
        domain="bounded multiview reader portfolio",
        quality_score=1.0,
    )
    writer.add_triplet(
        trigger="A357:complete_dual_source_order_set",
        mechanism="stable_min_rank_merge_with_complete_pointwise_proof",
        outcome="A357:corrected_dual_order_factor2_wavefront",
        confidence=1.0,
        source=payload["order_commitment_sha256"],
        quantification=json.dumps(payload["pointwise_factor2_proof"], sort_keys=True),
        evidence="all 4096 cells checked before any recovery result",
        domain="exact factor-two portfolio construction",
        quality_score=1.0,
    )
    writer.add_triplet(
        trigger="A357:corrected_dual_order_factor2_wavefront",
        mechanism="pointwise_factor2_protection_for_every_Metal_group_cell",
        outcome="A357:protected_corrected_recovery_order",
        confidence=1.0,
        source=payload["order_commitment_sha256"],
        quantification="zero violations; exact maximum ratio 2.0",
        evidence="PRE_A345_RESULT_EXACT_FACTOR2_PORTFOLIO_FROZEN",
        domain="prospective bounded recovery order",
        quality_score=1.0,
    )
    writer.add_triplet(
        trigger="A345:target_free_factor2_order",
        mechanism="materialized_corrected_dual_reader_factor2_closure",
        outcome="A357:protected_corrected_recovery_order",
        confidence=1.0,
        source="materialized:A357_corrected_dual_order_chain",
        quantification="exact retained closure",
        evidence="PRE_A345_RESULT_EXACT_FACTOR2_PORTFOLIO_FROZEN",
        domain="AI-native retained inference",
        quality_score=1.0,
        is_inferred=True,
    )
    writer.add_cluster(
        name="A357 corrected bounded dual-reader portfolio",
        entities=[
            "A345:target_free_factor2_order",
            "A356:corrected_public_output_order",
            "A357:complete_dual_source_order_set",
            "A357:corrected_dual_order_factor2_wavefront",
            "A357:protected_corrected_recovery_order",
        ],
    )
    writer.add_gap(
        subject="A357:protected_corrected_recovery_order",
        predicate="next_required_object",
        expected_object_type="confirmed_A345_prefix_rank_or_direct_execution",
        confidence=1.0,
        suggested_queries=[
            "Execute the corrected A356 order directly and evaluate all frozen source and portfolio ranks after independent confirmation."
        ],
    )
    temporary = ORDER_CAUSAL.with_name(f".{ORDER_CAUSAL.name}.tmp")
    temporary.unlink(missing_ok=True)
    stats = writer.save(str(temporary))
    os.replace(temporary, ORDER_CAUSAL)
    reader = CausalReader(str(ORDER_CAUSAL), verify_integrity=True)
    explicit = reader.get_all_triplets(include_inferred=False)
    rows = reader.get_all_triplets(include_inferred=True)
    inferred = [row for row in reader._triplets if row.get("is_inferred", False)]
    if (
        reader.api_id != "a357pf2"
        or len(explicit) != 4
        or len(rows) != 5
        or len(inferred) != 1
        or len(reader._rules) != 2
        or len(reader._clusters) != 1
        or len(reader._gaps) != 1
    ):
        raise RuntimeError("A357 authentic Causal reopen gate failed")
    return {
        "format": "authentic_dotcausal_v1_AI_native",
        "path": relative(ORDER_CAUSAL),
        "sha256": file_sha256(ORDER_CAUSAL),
        "api_id": reader.api_id,
        "explicit_triplets": len(explicit),
        "materialized_inferred_triplets": len(inferred),
        "embedded_rules": len(reader._rules),
        "clusters": len(reader._clusters),
        "gaps": len(reader._gaps),
        "reader_source": anchor(Path(inspect.getsourcefile(CausalReader) or "")),
        "writer_stats": stats,
        "personal_semantic_readback": {
            "terminal_chain": rows[-1],
            "next_gap": reader._gaps[0],
        },
    }


def freeze(*, replace_pre_execution_metadata: bool = False) -> dict[str, Any]:
    existing = [path for path in (ORDER, ORDER_CAUSAL, ORDER_REPORT) if path.exists()]
    superseded_sha256: str | None = None
    superseded_chain: list[str] = []
    if existing and not replace_pre_execution_metadata:
        raise FileExistsError("A357 order artifacts already exist")
    if replace_pre_execution_metadata:
        if not ORDER.exists():
            raise FileNotFoundError("A357 replacement requires the prior order artifact")
        prior = json.loads(ORDER.read_bytes())
        if (
            prior.get("attempt_id") != ATTEMPT_ID
            or prior.get("candidate_assignments_executed") != 0
            or prior.get("source_boundary_snapshot", {}).get("A345_result_available")
            is not False
            or prior.get("source_boundary_snapshot", {}).get("A350_result_available")
            is not False
        ):
            raise RuntimeError("A357 replacement gate rejected the prior artifact")
        superseded_chain.extend(
            prior.get("superseded_pre_execution_metadata_only_order_sha256_chain", [])
        )
        prior_scalar = prior.get("supersedes_pre_execution_metadata_only_order_sha256")
        if prior_scalar and prior_scalar not in superseded_chain:
            superseded_chain.append(prior_scalar)
        superseded_sha256 = file_sha256(ORDER)
        if superseded_sha256 not in superseded_chain:
            superseded_chain.append(superseded_sha256)
        for path in (ORDER, ORDER_CAUSAL, ORDER_REPORT):
            path.unlink(missing_ok=True)
    before = candidate_free_snapshot()
    a345, a356, first, second = load_sources()
    portfolio = factor2_wavefront(first, second)
    proof = factor2_proof(first, second, portfolio)
    diversity = diversity_panel(first, second)
    payload: dict[str, Any] = {
        "schema": "chacha20-round20-w46-corrected-dual-order-factor2-portfolio-a357-order-v1",
        "attempt_id": ATTEMPT_ID,
        "evidence_stage": "PRE_A345_RESULT_EXACT_FACTOR2_PORTFOLIO_FROZEN",
        "design_sha256": DESIGN_SHA256,
        "selected_operator": "A345_A356_corrected_min_rank_factor2_wavefront",
        "selected_order": portfolio,
        "selected_order_uint16be_sha256": order_sha256(portfolio),
        "source_orders": {
            "A345": {
                "order_commitment_sha256": a345["order_commitment_sha256"],
                "selected_order_uint16be_sha256": order_sha256(first),
            },
            "A356": {
                "order_commitment_sha256": a356["order_commitment_sha256"],
                "selected_order_uint16be_sha256": order_sha256(second),
            },
        },
        "pointwise_factor2_proof": proof,
        "operator_diversity": diversity,
        "target_labels_used": 0,
        "reader_refits": 0,
        "candidate_assignments_executed": 0,
        "source_boundary_snapshot": before,
        "anchors": {
            "design": anchor(DESIGN, DESIGN_SHA256),
            "A345_order": anchor(A345_ORDER, A345_ORDER_SHA256),
            "A345_protocol": anchor(A345_PROTOCOL, A345_PROTOCOL_SHA256),
            "A356_order": anchor(A356_ORDER, A356_ORDER_SHA256),
            "runner": anchor(Path(__file__)),
            "test": anchor(TEST),
            "reproducer": anchor(REPRO),
        },
    }
    if superseded_sha256 is not None:
        payload["supersedes_pre_execution_metadata_only_order_sha256"] = superseded_sha256
        payload["superseded_pre_execution_metadata_only_order_sha256_chain"] = superseded_chain
    payload["order_commitment_sha256"] = canonical_sha256(payload)
    try:
        payload["causal"] = build_order_causal(payload)
        atomic_json(ORDER, payload)
        atomic_bytes(
            ORDER_REPORT,
            (
                "# A357 — corrected-coordinate factor-two W46 portfolio\n\n"
                f"- Exact source-order Spearman correlation: **{diversity['spearman_rank_correlation']:.9f}**\n"
                f"- Pointwise cells checked: **{proof['cells_checked']:,}**\n"
                f"- Pointwise bound violations: **{proof['violations']}**\n"
                f"- Exact maximum ratio: **{proof['maximum_ratio']:.1f}**\n"
                "- Target labels / Reader refits / candidate executions: **0 / 0 / 0**\n"
                "- Frozen before any A345 or A350 candidate, prefix, or result.\n"
            ).encode(),
        )
        candidate_free_snapshot()
    except Exception:
        for path in (ORDER, ORDER_CAUSAL, ORDER_REPORT):
            path.unlink(missing_ok=True)
        raise
    return payload


def load_order() -> dict[str, Any]:
    value = json.loads(ORDER.read_bytes())
    _a345, _a356, first, second = load_sources()
    selected = exact_order(value.get("selected_order", []), "A357 selected")
    if (
        value.get("schema")
        != "chacha20-round20-w46-corrected-dual-order-factor2-portfolio-a357-order-v1"
        or value.get("attempt_id") != ATTEMPT_ID
        or value.get("design_sha256") != DESIGN_SHA256
        or selected != factor2_wavefront(first, second)
        or value.get("selected_order_uint16be_sha256") != order_sha256(selected)
        or value.get("pointwise_factor2_proof") != factor2_proof(first, second, selected)
        or value.get("target_labels_used") != 0
        or value.get("candidate_assignments_executed") != 0
    ):
        raise RuntimeError("A357 frozen order semantics differ")
    unsigned = {
        key: item
        for key, item in value.items()
        if key not in {"order_commitment_sha256", "causal"}
    }
    if value.get("order_commitment_sha256") != canonical_sha256(unsigned):
        raise RuntimeError("A357 order commitment differs")
    return value


def confirmed_prefix(result: Mapping[str, Any]) -> tuple[int, int]:
    if result.get("public_challenge_sha256") != A345_PUBLIC_CHALLENGE_SHA256:
        raise RuntimeError("A357 evaluation challenge differs")
    confirmation = result.get("confirmation", {})
    if (
        confirmation.get("all_blocks_match") is not True
        or confirmation.get("total_cross_implementation_output_bits_checked") != 8192
    ):
        raise RuntimeError("A357 evaluation requires dual 8192-bit confirmation")
    candidate = int(result.get("discovery", {}).get("candidate", -1))
    if candidate < 0:
        raise RuntimeError("A357 evaluation candidate absent")
    return (candidate & 0xFFFFFFFF) >> 20, candidate


def build_evaluation_causal(payload: Mapping[str, Any]) -> dict[str, Any]:
    sys.path.insert(0, str(DOTCAUSAL_SRC))
    from dotcausal.io import CausalReader, CausalWriter

    writer = CausalWriter(api_id="a357evl")
    writer.add_triplet(
        trigger="A357:pre_result_factor2_order",
        mechanism="independently_confirmed_A345_Metal_group_lookup",
        outcome="A357:prospective_prefix_rank_panel",
        confidence=1.0,
        source=payload["source_result_sha256"],
        quantification=json.dumps(payload["rank_panel"], sort_keys=True),
        evidence="rank-only evaluation after independent recovery",
        domain="prospective W46 operator evaluation",
        quality_score=1.0,
    )
    writer.add_gap(
        subject="A357:prospective_prefix_rank_panel",
        predicate="next_required_object",
        expected_object_type="fresh_W47_corrected_reader_transfer",
        confidence=1.0,
        suggested_queries=["Transfer the selected corrected-coordinate Reader family to a fresh W47 relation."],
    )
    temporary = EVALUATION_CAUSAL.with_name(f".{EVALUATION_CAUSAL.name}.tmp")
    temporary.unlink(missing_ok=True)
    stats = writer.save(str(temporary))
    os.replace(temporary, EVALUATION_CAUSAL)
    reader = CausalReader(str(EVALUATION_CAUSAL), verify_integrity=True)
    if len(reader.get_all_triplets(include_inferred=False)) != 1 or len(reader._gaps) != 1:
        raise RuntimeError("A357 evaluation Causal reopen gate failed")
    return {
        "format": "authentic_dotcausal_v1_AI_native",
        "path": relative(EVALUATION_CAUSAL),
        "sha256": file_sha256(EVALUATION_CAUSAL),
        "writer_stats": stats,
        "next_gap": reader._gaps[0],
    }


def evaluate(result_path: Path, expected_result_sha256: str) -> dict[str, Any]:
    if any(path.exists() for path in (EVALUATION, EVALUATION_CAUSAL, EVALUATION_REPORT)):
        raise FileExistsError("A357 evaluation artifacts already exist")
    if file_sha256(result_path) != expected_result_sha256:
        raise RuntimeError("A357 source result hash differs")
    result = json.loads(result_path.read_bytes())
    prefix, candidate = confirmed_prefix(result)
    order = load_order()
    _a345, _a356, first, second = load_sources()
    portfolio = exact_order(order["selected_order"], "A357 evaluation portfolio")
    ranks = {
        "A345_target_free": rank_vector(first)[prefix],
        "A356_corrected_public_output": rank_vector(second)[prefix],
        "A357_factor2_portfolio": rank_vector(portfolio)[prefix],
    }
    selected_rank = ranks["A357_factor2_portfolio"]
    best_source = min(ranks["A345_target_free"], ranks["A356_corrected_public_output"])
    panel = {
        "confirmed_prefix12": prefix,
        "confirmed_prefix12_hex": f"{prefix:03x}",
        "ranks_one_based": ranks,
        "factor2_bound_holds": selected_rank <= 2 * best_source,
        "overhead_vs_better_source": selected_rank / best_source,
        "gain_bits_vs_complete_4096_cover": math.log2(CELLS / selected_rank),
        "domain_reduction_factor_at_rank": CELLS / selected_rank,
    }
    payload: dict[str, Any] = {
        "schema": "chacha20-round20-w46-corrected-dual-order-factor2-portfolio-a357-evaluation-v1",
        "attempt_id": ATTEMPT_ID,
        "evidence_stage": "POST_INDEPENDENT_CONFIRMATION_EXACT_RANK_ONLY_EVALUATION",
        "design_sha256": DESIGN_SHA256,
        "order_sha256": file_sha256(ORDER),
        "order_commitment_sha256": order["order_commitment_sha256"],
        "source_result": relative(result_path),
        "source_result_sha256": expected_result_sha256,
        "confirmed_candidate": candidate,
        "rank_panel": panel,
        "candidate_assignments_executed": 0,
        "reader_refits": 0,
    }
    payload["evaluation_commitment_sha256"] = canonical_sha256(payload)
    payload["causal"] = build_evaluation_causal(payload)
    atomic_json(EVALUATION, payload)
    atomic_bytes(
        EVALUATION_REPORT,
        (
            "# A357 — post-confirmation exact rank panel\n\n"
            f"- Confirmed Metal-group prefix: **0x{prefix:03x}**\n"
            f"- A345 rank: **{ranks['A345_target_free']}**\n"
            f"- A356 rank: **{ranks['A356_corrected_public_output']}**\n"
            f"- A357 factor-two rank: **{selected_rank}**\n"
            f"- Pointwise guarantee observed: **{panel['factor2_bound_holds']}**\n"
        ).encode(),
    )
    return payload


def analyze() -> dict[str, Any]:
    response: dict[str, Any] = {
        "attempt_id": ATTEMPT_ID,
        "design_sha256": DESIGN_SHA256,
        "order_frozen": ORDER.exists(),
        "evaluation_complete": EVALUATION.exists(),
    }
    if ORDER.exists():
        value = load_order()
        response["order_sha256"] = file_sha256(ORDER)
        response["order_commitment_sha256"] = value["order_commitment_sha256"]
        response["selected_order_uint16be_sha256"] = value[
            "selected_order_uint16be_sha256"
        ]
    return response


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    action = parser.add_mutually_exclusive_group(required=True)
    action.add_argument("--freeze", action="store_true")
    action.add_argument("--replace-pre-execution-metadata", action="store_true")
    action.add_argument("--evaluate", action="store_true")
    action.add_argument("--analyze", action="store_true")
    parser.add_argument("--result-path", type=Path)
    parser.add_argument("--expected-result-sha256")
    args = parser.parse_args()
    if args.freeze or args.replace_pre_execution_metadata:
        payload = freeze(
            replace_pre_execution_metadata=args.replace_pre_execution_metadata
        )
    elif args.evaluate:
        if args.result_path is None or not args.expected_result_sha256:
            parser.error("--evaluate requires result path and SHA-256")
        payload = evaluate(args.result_path, args.expected_result_sha256)
    else:
        payload = analyze()
    print(json.dumps(payload, indent=2, sort_keys=True), flush=True)


if __name__ == "__main__":
    main()

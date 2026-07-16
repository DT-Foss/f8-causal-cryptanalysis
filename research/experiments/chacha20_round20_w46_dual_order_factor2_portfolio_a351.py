#!/usr/bin/env python3
"""A351: freeze and evaluate a factor-two portfolio of A345 and A349 orders."""

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

import numpy as np

ROOT = Path(__file__).parents[2]
RESEARCH = ROOT / "research"
CONFIGS = RESEARCH / "configs"
RESULTS = RESEARCH / "results/v1"

DESIGN = CONFIGS / "chacha20_round20_w46_dual_order_factor2_portfolio_a351_design_v1.json"
ORDER = RESULTS / "chacha20_round20_w46_dual_order_factor2_portfolio_a351_order_v1.json"
ORDER_CAUSAL = ORDER.with_suffix(".causal")
ORDER_REPORT = ORDER.with_suffix(".md")
EVALUATION = RESULTS / "chacha20_round20_w46_dual_order_factor2_portfolio_a351_evaluation_v1.json"
EVALUATION_CAUSAL = EVALUATION.with_suffix(".causal")
EVALUATION_REPORT = EVALUATION.with_suffix(".md")
TEST = ROOT / "tests/test_chacha20_round20_w46_dual_order_factor2_portfolio_a351.py"
REPRO = ROOT / "scripts/reproduce_chacha20_round20_w46_dual_order_factor2_portfolio_a351.sh"

A345_RUNNER = RESEARCH / "experiments/chacha20_round20_fresh_w46_factor2_replication_a345.py"
A345_ORDER = RESULTS / "chacha20_round20_fresh_w46_factor2_replication_a345_order_v1.json"
A345_PROTOCOL = CONFIGS / "chacha20_round20_fresh_w46_factor2_replication_a345_v1.json"
A345_PROGRESS = RESULTS / "chacha20_round20_fresh_w46_factor2_replication_a345_progress_v1.json"
A345_RESULT = RESULTS / "chacha20_round20_fresh_w46_factor2_replication_a345_v1.json"
A349_ORDER = RESULTS / "chacha20_round20_w46_direct12_prospective_a345_validation_a349_order_v1.json"
A350_PROTOCOL = CONFIGS / "chacha20_round20_w46_a349_order_prospective_recovery_a350_v1.json"
A350_PROGRESS = RESULTS / "chacha20_round20_w46_a349_order_prospective_recovery_a350_progress_v1.json"
A350_RESULT = RESULTS / "chacha20_round20_w46_a349_order_prospective_recovery_a350_v1.json"

ATTEMPT_ID = "A351"
DESIGN_SHA256 = "00cfbb39d90e9d9b685d53fa8f6344e7a4d27e12a6978891650e9446ec44e28e"
A345_ORDER_SHA256 = "9f0a7a1773894b4a265a6e456bd3489c10fd5f44e7ef9d40dc4706699fa0107d"
A345_PROTOCOL_SHA256 = "8e4280d6603f1eacac0345df634113ed1b550f5d5292c2bed75cc31b19a07f95"
A349_ORDER_SHA256 = "d2cbc5cbfe4765d7fd3681f92c4881a962d6b856d86a88bf9c9af716867dc96e"
A350_PROTOCOL_SHA256 = "ceab8292b5cfa61018cb7583a66a7ef6fa20df390b4e0f49992f76cec3a915ab"
CELLS = 1 << 12
DOTCAUSAL_SRC = Path("/Users/bhkmie/Documents/Forschung/O1/vendor/fabel/dotcausal_package/src")


def load_module(path: Path, name: str) -> Any:
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot import A351 dependency {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


A345 = load_module(A345_RUNNER, "a351_a345_common")
file_sha256 = A345.file_sha256
canonical_sha256 = A345.canonical_sha256
atomic_json = A345.atomic_json
atomic_bytes = A345.atomic_bytes


def relative(path: Path) -> str:
    resolved = path.resolve()
    try:
        return str(resolved.relative_to(ROOT.resolve()))
    except ValueError:
        return str(resolved)


def anchor(path: Path, expected: str | None = None) -> dict[str, str]:
    digest = file_sha256(path)
    if expected is not None and digest != expected:
        raise RuntimeError(f"A351 anchor hash differs: {path}")
    return {"path": relative(path), "sha256": digest}


def exact_order(values: Sequence[int], label: str) -> list[int]:
    order = [int(value) for value in values]
    if len(order) != CELLS or set(order) != set(range(CELLS)):
        raise ValueError(f"A351 {label} is not an exact 4,096-cell order")
    return order


def order_sha256(values: Sequence[int]) -> str:
    raw = b"".join(value.to_bytes(2, "big") for value in exact_order(values, "hash"))
    return hashlib.sha256(raw).hexdigest()


def rank_vector(order: Sequence[int]) -> list[int]:
    ranks = [0] * CELLS
    for rank, cell in enumerate(exact_order(order, "rank vector"), 1):
        ranks[cell] = rank
    return ranks


def factor2_wavefront(first: Sequence[int], second: Sequence[int]) -> list[int]:
    first_ranks = rank_vector(first)
    second_ranks = rank_vector(second)
    return exact_order(
        sorted(
            range(CELLS),
            key=lambda cell: (
                min(first_ranks[cell], second_ranks[cell]),
                first_ranks[cell] + second_ranks[cell],
                first_ranks[cell],
                second_ranks[cell],
                cell,
            ),
        ),
        "factor-two wavefront",
    )


def factor2_proof(first: Sequence[int], second: Sequence[int], portfolio: Sequence[int]) -> dict[str, Any]:
    first_ranks = rank_vector(first)
    second_ranks = rank_vector(second)
    portfolio_ranks = rank_vector(portfolio)
    ratios = [
        portfolio_ranks[cell] / min(first_ranks[cell], second_ranks[cell])
        for cell in range(CELLS)
    ]
    violations = [cell for cell, ratio in enumerate(ratios) if ratio > 2.0]
    if violations:
        raise RuntimeError("A351 factor-two pointwise proof failed")
    return {
        "bound": "R_portfolio(c) <= 2*min(R_A345(c),R_A349(c))",
        "cells_checked": CELLS,
        "maximum_ratio": max(ratios),
        "mean_ratio": float(np.mean(ratios)),
        "violations": 0,
    }


def diversity_panel(first: Sequence[int], second: Sequence[int]) -> dict[str, Any]:
    first_ranks = np.asarray(rank_vector(first), dtype=np.float64)
    second_ranks = np.asarray(rank_vector(second), dtype=np.float64)
    correlation = float(np.corrcoef(first_ranks, second_ranks)[0, 1])
    overlaps = {}
    first_order = exact_order(first, "diversity first")
    second_order = exact_order(second, "diversity second")
    for width in (32, 64, 128, 256, 512, 1024):
        overlap = len(set(first_order[:width]) & set(second_order[:width]))
        overlaps[str(width)] = {
            "intersection": overlap,
            "fraction_of_each_top_k": overlap / width,
        }
    return {
        "spearman_rank_correlation": correlation,
        "top_k_overlap": overlaps,
    }


def load_design() -> dict[str, Any]:
    if file_sha256(DESIGN) != DESIGN_SHA256:
        raise RuntimeError("A351 design hash differs")
    value = json.loads(DESIGN.read_bytes())
    boundary = value.get("information_boundary", {})
    portfolio = value.get("portfolio_contract", {})
    evaluation = value.get("evaluation_contract", {})
    if (
        value.get("schema")
        != "chacha20-round20-w46-dual-order-factor2-portfolio-a351-design-v1"
        or value.get("attempt_id") != ATTEMPT_ID
        or value.get("design_state")
        != "frozen_before_A345_or_A350_candidate_prefix_or_result"
        or portfolio.get("cells") != CELLS
        or boundary.get("A345_result_available_at_design_freeze") is not False
        or boundary.get("A350_result_available_at_design_freeze") is not False
        or boundary.get("target_labels_used_for_portfolio_construction") != 0
        or evaluation.get("candidate_assignments_executed_by_A351") != 0
        or evaluation.get("result_must_postdate_A351_order") is not True
    ):
        raise RuntimeError("A351 frozen design semantics differ")
    sources = value["source_anchors"]
    expected = {
        "A345_order": (A345_ORDER, A345_ORDER_SHA256),
        "A345_protocol": (A345_PROTOCOL, A345_PROTOCOL_SHA256),
        "A349_order": (A349_ORDER, A349_ORDER_SHA256),
        "A350_protocol": (A350_PROTOCOL, A350_PROTOCOL_SHA256),
    }
    for name, (path, digest) in expected.items():
        if sources[f"{name}_path"] != relative(path):
            raise RuntimeError(f"A351 source path differs: {name}")
        anchor(path, digest)
    return value


def load_sources() -> tuple[dict[str, Any], dict[str, Any], list[int], list[int]]:
    load_design()
    a345_order = json.loads(A345_ORDER.read_bytes())
    a349_order = json.loads(A349_ORDER.read_bytes())
    a345_protocol = json.loads(A345_PROTOCOL.read_bytes())
    a350_protocol = json.loads(A350_PROTOCOL.read_bytes())
    first = exact_order(a345_order.get("selected_order", []), "A345 selected order")
    second = exact_order(a349_order.get("selected_order", []), "A349 selected order")
    if (
        order_sha256(first) != a345_order.get("selected_order_uint16be_sha256")
        or order_sha256(second) != a349_order.get("selected_order_uint16be_sha256")
        or a349_order.get("target_labels_used") != 0
        or a349_order.get("reader_refits") != 0
        or a349_order.get("A345_result_available_at_order_freeze") is not False
        or a345_protocol.get("public_challenge_sha256")
        != a350_protocol.get("public_challenge_sha256")
        or a345_protocol.get("public_challenge_sha256")
        != a349_order.get("A345_public_challenge_sha256")
    ):
        raise RuntimeError("A351 source-order or challenge semantics differ")
    return a345_order, a349_order, first, second


def _candidate_free_progress(path: Path, attempt_id: str) -> dict[str, Any]:
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
        raise RuntimeError(f"A351 {attempt_id} progress is no longer candidate-free")
    return {
        "available": True,
        "sha256": hashlib.sha256(raw).hexdigest(),
        "status": value.get("status"),
        "executed_prefix_groups": int(value.get("executed_prefix_groups", 0)),
        "mtime_ns": path.stat().st_mtime_ns,
    }


def candidate_free_snapshot() -> dict[str, Any]:
    if A345_RESULT.exists() or A350_RESULT.exists():
        raise RuntimeError("A351 freeze requires A345 and A350 result absence")
    return {
        "A345_result_available": False,
        "A350_result_available": False,
        "A345": _candidate_free_progress(A345_PROGRESS, "A345"),
        "A350": _candidate_free_progress(A350_PROGRESS, "A350"),
    }


def _build_order_causal(payload: Mapping[str, Any]) -> dict[str, Any]:
    sys.path.insert(0, str(DOTCAUSAL_SRC))
    from dotcausal.io import CausalReader, CausalWriter

    writer = CausalWriter(api_id="a351pf2")
    writer._rules = []
    writer.add_rule(
        name="dual_order_to_factor2_wavefront",
        description="Two complete label-free permutations induce a stable min-rank wavefront with a pointwise factor-two bound.",
        pattern=["A345_target_free_order", "A349_public_output_conditioned_order"],
        conclusion="A351_dual_order_factor2_wavefront",
        confidence_modifier=1.0,
    )
    writer.add_rule(
        name="diverse_orders_to_robust_portfolio",
        description="Low rank correlation and bounded merge overhead retain whichever reader ranks an unseen prefix earlier.",
        pattern=["A351_dual_order_factor2_wavefront", "A351_measured_operator_diversity"],
        conclusion="A351_prospective_robust_portfolio",
        confidence_modifier=1.0,
    )
    writer.add_triplet(
        trigger="A345:target_free_factor2_order",
        mechanism="stable_min_rank_merge_with_A349_target_conditioned_order",
        outcome="A351:dual_order_factor2_wavefront",
        confidence=1.0,
        source=payload["order_commitment_sha256"],
        quantification=json.dumps(payload["pointwise_factor2_proof"], sort_keys=True),
        evidence="complete 4096-cell proof before either recovery result",
        domain="prospective ChaCha20 R20 W46 prefix ordering",
        quality_score=1.0,
    )
    writer.add_triplet(
        trigger="A349:public_output_conditioned_direct12_order",
        mechanism="rank_diverse_companion_in_bounded_dual_order_wavefront",
        outcome="A351:prospective_robust_portfolio",
        confidence=1.0,
        source=payload["order_commitment_sha256"],
        quantification=json.dumps(payload["operator_diversity"], sort_keys=True),
        evidence="target-label-free exact order comparison",
        domain="multiview reader portfolio",
        quality_score=1.0,
    )
    writer.add_triplet(
        trigger="A345:target_free_factor2_order",
        mechanism="materialized_dual_reader_factor2_closure",
        outcome="A351:prospective_robust_portfolio",
        confidence=1.0,
        source="materialized:A351_dual_order_chain",
        quantification="exact retained closure",
        evidence="frozen before A345 or A350 candidate, prefix, or result",
        domain="AI-native retained inference",
        quality_score=1.0,
        is_inferred=True,
    )
    writer.add_cluster(
        name="A351 bounded dual-reader portfolio",
        entities=[
            "A345:target_free_factor2_order",
            "A349:public_output_conditioned_direct12_order",
            "A351:dual_order_factor2_wavefront",
            "A351:prospective_robust_portfolio",
        ],
    )
    writer.add_gap(
        subject="A351:prospective_robust_portfolio",
        predicate="next_required_object",
        expected_object_type="confirmed_unseen_prefix_rank_or_W47_transfer",
        confidence=1.0,
        suggested_queries=[
            "What is the prospectively frozen A351 rank of the independently confirmed A345 prefix?",
            "Does the same bounded merge improve a fresh W47 target?",
        ],
    )
    temporary = ORDER_CAUSAL.with_name(f".{ORDER_CAUSAL.name}.tmp")
    temporary.unlink(missing_ok=True)
    stats = writer.save(str(temporary))
    os.replace(temporary, ORDER_CAUSAL)
    reader = CausalReader(str(ORDER_CAUSAL), verify_integrity=True)
    explicit = reader.get_all_triplets(include_inferred=False)
    all_rows = reader.get_all_triplets(include_inferred=True)
    inferred = [row for row in reader._triplets if row.get("is_inferred", False)]
    if (
        reader.api_id != "a351pf2"
        or len(explicit) != 2
        or len(all_rows) != 3
        or len(inferred) != 1
        or len(reader._rules) != 2
        or len(reader._clusters) != 1
        or len(reader._gaps) != 1
    ):
        raise RuntimeError("A351 authentic Causal reopen gate failed")
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
            "terminal_chain": all_rows[-1],
            "next_gap": reader._gaps[0],
        },
    }


def freeze() -> dict[str, Any]:
    if any(path.exists() for path in (ORDER, ORDER_CAUSAL, ORDER_REPORT, EVALUATION, EVALUATION_CAUSAL, EVALUATION_REPORT)):
        raise FileExistsError("A351 order or evaluation artifacts already exist")
    before = candidate_free_snapshot()
    design = load_design()
    a345_order, a349_order, first, second = load_sources()
    portfolio = factor2_wavefront(first, second)
    proof = factor2_proof(first, second, portfolio)
    diversity = diversity_panel(first, second)
    essential = {
        "selected_operator": "A345_A349_min_rank_factor2_wavefront",
        "A345_order_uint16be_sha256": order_sha256(first),
        "A349_order_uint16be_sha256": order_sha256(second),
        "selected_order_uint16be_sha256": order_sha256(portfolio),
        "pointwise_factor2_proof": proof,
        "operator_diversity": diversity,
        "target_labels_used": 0,
        "candidate_assignments_executed": 0,
        "information_boundary": design["information_boundary"],
    }
    payload: dict[str, Any] = {
        "schema": "chacha20-round20-w46-dual-order-factor2-portfolio-a351-order-v1",
        "attempt_id": ATTEMPT_ID,
        "evidence_stage": "PRE_A345_A350_RESULT_DUAL_ORDER_FACTOR2_PORTFOLIO_FROZEN",
        "design_sha256": DESIGN_SHA256,
        **essential,
        "selected_order": portfolio,
        "source_order_commitments": {
            "A345": a345_order["order_commitment_sha256"],
            "A349": a349_order["order_commitment_sha256"],
        },
        "freeze_boundary_before": before,
        "anchors": {
            "design": anchor(DESIGN, DESIGN_SHA256),
            "A345_order": anchor(A345_ORDER, A345_ORDER_SHA256),
            "A345_protocol": anchor(A345_PROTOCOL, A345_PROTOCOL_SHA256),
            "A349_order": anchor(A349_ORDER, A349_ORDER_SHA256),
            "A350_protocol": anchor(A350_PROTOCOL, A350_PROTOCOL_SHA256),
            "runner": anchor(Path(__file__)),
            "test": anchor(TEST),
            "reproducer": anchor(REPRO),
        },
    }
    payload["order_commitment_sha256"] = canonical_sha256(essential)
    try:
        payload["causal"] = _build_order_causal(payload)
        payload["freeze_boundary_after"] = candidate_free_snapshot()
        atomic_json(ORDER, payload)
        order_mtime = ORDER.stat().st_mtime_ns
        for result_path in (A345_RESULT, A350_RESULT):
            if result_path.exists() and result_path.stat().st_mtime_ns <= order_mtime:
                raise RuntimeError("A351 order did not precede the first recovery result")
        atomic_bytes(
            ORDER_REPORT,
            (
                "# A351 — bounded dual-reader W46 portfolio\n\n"
                f"Evidence stage: **{payload['evidence_stage']}**\n\n"
                f"- Cells: **{CELLS:,}**\n"
                f"- Exact pointwise bound: **{proof['bound']}**\n"
                f"- Maximum measured ratio: **{proof['maximum_ratio']:.6f}**\n"
                f"- Source-order Spearman correlation: **{diversity['spearman_rank_correlation']:.9f}**\n"
                "- Target labels used: **zero**\n"
                "- Candidate assignments executed: **zero**\n"
                "- Authentic AI-native Causal readback: **2 explicit + 1 inferred**\n"
            ).encode(),
        )
    except Exception:
        ORDER.unlink(missing_ok=True)
        ORDER_CAUSAL.unlink(missing_ok=True)
        ORDER_REPORT.unlink(missing_ok=True)
        raise
    return payload


def load_order() -> dict[str, Any]:
    value = json.loads(ORDER.read_bytes())
    selected = exact_order(value.get("selected_order", []), "stored portfolio")
    _a345, _a349, first, second = load_sources()
    if (
        value.get("schema")
        != "chacha20-round20-w46-dual-order-factor2-portfolio-a351-order-v1"
        or value.get("attempt_id") != ATTEMPT_ID
        or value.get("design_sha256") != DESIGN_SHA256
        or value.get("target_labels_used") != 0
        or value.get("candidate_assignments_executed") != 0
        or selected != factor2_wavefront(first, second)
        or value.get("selected_order_uint16be_sha256") != order_sha256(selected)
        or value.get("pointwise_factor2_proof") != factor2_proof(first, second, selected)
    ):
        raise RuntimeError("A351 frozen order semantics differ")
    for row in value["anchors"].values():
        anchor(ROOT / row["path"] if not Path(row["path"]).is_absolute() else Path(row["path"]), row["sha256"])
    return value


def _confirmed_prefix(result: Mapping[str, Any]) -> tuple[int, int, str]:
    schema = str(result.get("schema", ""))
    if schema not in {
        "chacha20-round20-fresh-w46-factor2-replication-a345-result-v1",
        "chacha20-round20-w46-a349-order-prospective-recovery-a350-result-v1",
    }:
        raise RuntimeError("A351 evaluation result schema differs")
    discovery = result.get("discovery", {})
    confirmation = result.get("confirmation", {})
    candidate = int(discovery.get("candidate", -1))
    prefix = int(discovery.get("prefix12", -1))
    if (
        not 0 <= candidate < (1 << 46)
        or not 0 <= prefix < CELLS
        or ((candidate & 0xFFFFFFFF) >> 20) != prefix
        or confirmation.get("all_blocks_match") is not True
        or discovery.get("matched_control_candidates") != 0
    ):
        raise RuntimeError("A351 confirmed result gate failed")
    return candidate, prefix, str(result.get("attempt_id"))


def _build_evaluation_causal(payload: Mapping[str, Any]) -> dict[str, Any]:
    sys.path.insert(0, str(DOTCAUSAL_SRC))
    from dotcausal.io import CausalReader, CausalWriter

    writer = CausalWriter(api_id="a351eval")
    writer._rules = []
    writer.add_rule(
        name="frozen_portfolio_plus_confirmed_prefix_to_rank",
        description="The independently confirmed prefix is looked up in the immutable pre-result A351 permutation.",
        pattern=["A351_pre_result_factor2_order", "confirmed_A345_target_prefix"],
        conclusion="A351_prospective_prefix_rank",
        confidence_modifier=1.0,
    )
    writer.add_triplet(
        trigger="A351:pre_result_factor2_order",
        mechanism="immutable_rank_lookup_after_independent_confirmation",
        outcome="A351:prospective_prefix_rank",
        confidence=1.0,
        source=payload["evaluation_sha256"],
        quantification=json.dumps(payload["rank_panel"], sort_keys=True),
        evidence=payload["evidence_stage"],
        domain="prospective ChaCha20 R20 W46 reader evaluation",
        quality_score=1.0,
    )
    writer.add_cluster(
        name="A351 prospective portfolio evaluation",
        entities=["A351:pre_result_factor2_order", "A351:prospective_prefix_rank"],
    )
    writer.add_gap(
        subject="A351:prospective_prefix_rank",
        predicate="next_required_object",
        expected_object_type="fresh_W47_target_conditioned_transfer",
        confidence=1.0,
        suggested_queries=["Can the frozen dual-reader construction be lifted to the W47 engine?"],
    )
    temporary = EVALUATION_CAUSAL.with_name(f".{EVALUATION_CAUSAL.name}.tmp")
    temporary.unlink(missing_ok=True)
    stats = writer.save(str(temporary))
    os.replace(temporary, EVALUATION_CAUSAL)
    reader = CausalReader(str(EVALUATION_CAUSAL), verify_integrity=True)
    explicit = reader.get_all_triplets(include_inferred=False)
    if (
        reader.api_id != "a351eval"
        or len(explicit) != 1
        or len(reader._rules) != 1
        or len(reader._clusters) != 1
        or len(reader._gaps) != 1
    ):
        raise RuntimeError("A351 evaluation Causal reopen gate failed")
    return {
        "format": "authentic_dotcausal_v1_AI_native",
        "path": relative(EVALUATION_CAUSAL),
        "sha256": file_sha256(EVALUATION_CAUSAL),
        "api_id": reader.api_id,
        "explicit_triplets": len(explicit),
        "embedded_rules": len(reader._rules),
        "clusters": len(reader._clusters),
        "gaps": len(reader._gaps),
        "reader_source": anchor(Path(inspect.getsourcefile(CausalReader) or "")),
        "writer_stats": stats,
        "personal_semantic_readback": {
            "terminal_chain": explicit[-1],
            "next_gap": reader._gaps[0],
        },
    }


def evaluate(*, result_path: Path, expected_result_sha256: str) -> dict[str, Any]:
    if any(path.exists() for path in (EVALUATION, EVALUATION_CAUSAL, EVALUATION_REPORT)):
        raise FileExistsError("A351 evaluation artifacts already exist")
    order = load_order()
    if file_sha256(result_path) != expected_result_sha256:
        raise RuntimeError("A351 recovery result hash differs")
    if result_path.stat().st_mtime_ns <= ORDER.stat().st_mtime_ns:
        raise RuntimeError("A351 evaluation source does not postdate the frozen order")
    result = json.loads(result_path.read_bytes())
    candidate, prefix, source_attempt = _confirmed_prefix(result)
    _a345, _a349, first, second = load_sources()
    portfolio = exact_order(order["selected_order"], "evaluation portfolio")
    ranks = {
        "A345_target_free": rank_vector(first)[prefix],
        "A349_public_output_conditioned": rank_vector(second)[prefix],
        "A351_factor2_portfolio": rank_vector(portfolio)[prefix],
    }
    best_source = min(ranks["A345_target_free"], ranks["A349_public_output_conditioned"])
    selected_rank = ranks["A351_factor2_portfolio"]
    rank_panel = {
        "confirmed_prefix12": prefix,
        "confirmed_prefix12_hex": f"{prefix:03x}",
        "ranks_one_based": ranks,
        "best_source_rank_one_based": best_source,
        "portfolio_overhead_vs_best_source": selected_rank / best_source,
        "factor2_bound_holds": selected_rank <= 2 * best_source,
        "gain_bits_vs_complete_4096_cover": math.log2(CELLS / selected_rank),
        "domain_reduction_factor_at_rank": CELLS / selected_rank,
    }
    payload: dict[str, Any] = {
        "schema": "chacha20-round20-w46-dual-order-factor2-portfolio-a351-evaluation-v1",
        "attempt_id": ATTEMPT_ID,
        "evidence_stage": "PRE_RESULT_FROZEN_DUAL_ORDER_EVALUATED_ON_INDEPENDENTLY_CONFIRMED_A345_TARGET",
        "design_sha256": DESIGN_SHA256,
        "order_sha256": file_sha256(ORDER),
        "order_commitment_sha256": order["order_commitment_sha256"],
        "source_recovery_attempt": source_attempt,
        "source_recovery_result_sha256": expected_result_sha256,
        "confirmed_candidate": candidate,
        "rank_panel": rank_panel,
        "target_labels_used_before_order_freeze": 0,
        "candidate_assignments_executed_by_A351": 0,
        "anchors": {
            "design": anchor(DESIGN, DESIGN_SHA256),
            "order": anchor(ORDER),
            "source_recovery_result": anchor(result_path, expected_result_sha256),
            "runner": anchor(Path(__file__)),
            "test": anchor(TEST),
            "reproducer": anchor(REPRO),
        },
    }
    payload["evaluation_sha256"] = canonical_sha256(
        {
            "order_commitment_sha256": payload["order_commitment_sha256"],
            "source_recovery_result_sha256": expected_result_sha256,
            "confirmed_candidate": candidate,
            "rank_panel": rank_panel,
            "target_labels_used_before_order_freeze": 0,
        }
    )
    payload["causal"] = _build_evaluation_causal(payload)
    atomic_json(EVALUATION, payload)
    atomic_bytes(
        EVALUATION_REPORT,
        (
            "# A351 — prospective dual-reader portfolio evaluation\n\n"
            f"Evidence stage: **{payload['evidence_stage']}**\n\n"
            f"- Confirmed prefix: **0x{prefix:03x}**\n"
            f"- A345 target-free rank: **{ranks['A345_target_free']} / {CELLS}**\n"
            f"- A349 target-conditioned rank: **{ranks['A349_public_output_conditioned']} / {CELLS}**\n"
            f"- A351 bounded portfolio rank: **{selected_rank} / {CELLS}**\n"
            f"- Saved search bits: **{rank_panel['gain_bits_vs_complete_4096_cover']:.9f}**\n"
            "- Candidate assignments executed by A351: **zero**\n"
        ).encode(),
    )
    return payload


def analyze() -> dict[str, Any]:
    payload: dict[str, Any] = {
        "attempt_id": ATTEMPT_ID,
        "design_sha256": DESIGN_SHA256,
        "order_frozen": ORDER.exists(),
        "evaluation_complete": EVALUATION.exists(),
    }
    if ORDER.exists():
        payload["order_sha256"] = file_sha256(ORDER)
        payload["evidence_stage"] = json.loads(ORDER.read_bytes())["evidence_stage"]
    if EVALUATION.exists():
        payload["evaluation_sha256"] = file_sha256(EVALUATION)
        payload["evaluation_evidence_stage"] = json.loads(EVALUATION.read_bytes())[
            "evidence_stage"
        ]
    return payload


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    action = parser.add_mutually_exclusive_group(required=True)
    action.add_argument("--analyze", action="store_true")
    action.add_argument("--freeze", action="store_true")
    action.add_argument("--evaluate", action="store_true")
    parser.add_argument("--result-path", type=Path)
    parser.add_argument("--expected-result-sha256")
    args = parser.parse_args()
    if args.freeze:
        payload = freeze()
    elif args.evaluate:
        if args.result_path is None or not args.expected_result_sha256:
            parser.error("--evaluate requires --result-path and --expected-result-sha256")
        payload = evaluate(
            result_path=args.result_path,
            expected_result_sha256=args.expected_result_sha256,
        )
    else:
        payload = analyze()
    print(json.dumps(payload, indent=2, sort_keys=True), flush=True)


if __name__ == "__main__":
    main()

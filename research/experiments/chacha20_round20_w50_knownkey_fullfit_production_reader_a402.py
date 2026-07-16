#!/usr/bin/env python3
"""A402: full-fit a held-out-qualified W50 Reader and deploy it target-blind."""

from __future__ import annotations

import argparse
import importlib.util
import inspect
import json
import math
import os
import statistics
import sys
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

import numpy as np

ROOT = Path(__file__).parents[2]
RESEARCH = ROOT / "research"
CONFIGS = RESEARCH / "configs"
RESULTS = RESEARCH / "results/v1"

DESIGN = CONFIGS / "chacha20_round20_w50_knownkey_fullfit_production_reader_a402_design_v1.json"
IMPLEMENTATION = (
    CONFIGS / "chacha20_round20_w50_knownkey_fullfit_production_reader_a402_implementation_v1.json"
)
RESULT = RESULTS / "chacha20_round20_w50_knownkey_fullfit_production_reader_a402_v1.json"
CAUSAL = RESULT.with_suffix(".causal")
REPORT = RESULT.with_suffix(".md")
TEST = ROOT / "tests/test_chacha20_round20_w50_knownkey_fullfit_production_reader_a402.py"
REPRO = ROOT / "scripts/reproduce_chacha20_round20_w50_knownkey_fullfit_production_reader_a402.sh"

A401_RUNNER = RESEARCH / "experiments/chacha20_round20_w50_knownkey_direct12_learning_a401.py"
A388_RUNNER = RESEARCH / "experiments/chacha20_round20_w50_public_output_direct12_factor3_a388.py"
A388_PREFLIGHT = (
    RESULTS / "chacha20_round20_w50_public_output_direct12_factor3_a388_preflight_v1.json"
)
A388_ORDER = RESULTS / "chacha20_round20_w50_public_output_direct12_factor3_a388_order_v1.json"

ATTEMPT_ID = "A402"
DESIGN_SHA256 = "15111ce7c820cfc7bebebeff5feaacbc7d8cde68bc4b09ffcd0d216c668134d8"
A401_RUNNER_SHA256 = "2238b99504883cd0b722b7b92254b3dc02255a6b53c9851f35264daad3f21bee"
A401_IMPLEMENTATION_SHA256 = "4a08686d34674525bd08938d96783c6772ce4cd004fffbe04d11dc972cf63df1"
A401_PROTOCOL_SHA256 = "18aaad488842ce9fb52a77cef01c89bfeb8c901001a86fd56e23bbf594c7a4f3"
A388_RUNNER_SHA256 = "36c933ae5003f92f2b96efb2e30d97c30bf8301bfcaa790333a6712f3041b5a9"
A388_PREFLIGHT_SHA256 = "6919b9071b5c9de85f050a7921d4a82fa0e55db6e02ca531590afdfdc57cc115"
A388_ORDER_SHA256 = "3c56ce8521b1ced20e1e3a90999810c2e563c4de941701c86274f0828b5d01b8"
DOTCAUSAL_SRC = Path("/Users/bhkmie/Documents/Forschung/O1/vendor/fabel/dotcausal_package/src")


def load_module(path: Path, name: str) -> Any:
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot import A402 dependency {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


A401 = load_module(A401_RUNNER, "a402_a401")
A388 = A401.A388

file_sha256 = A401.file_sha256
canonical_sha256 = A401.canonical_sha256
atomic_json = A401.atomic_json
atomic_bytes = A401.atomic_bytes
relative = A401.relative
path_from_ref = A401.path_from_ref
anchor = A401.anchor

VIEW_NAMES = A401.VIEW_NAMES
AGGREGATORS = A401.AGGREGATORS
TARGETS = A401.TARGETS
CELLS = A401.CELLS


def load_design() -> dict[str, Any]:
    if file_sha256(DESIGN) != DESIGN_SHA256:
        raise RuntimeError("A402 design hash differs")
    value = json.loads(DESIGN.read_bytes())
    fit = value.get("fullfit_contract", {})
    application = value.get("production_application_contract", {})
    boundary = value.get("information_boundary", {})
    if (
        value.get("schema")
        != "chacha20-round20-w50-knownkey-fullfit-production-reader-a402-design-v1"
        or value.get("attempt_id") != ATTEMPT_ID
        or value.get("design_state")
        != "frozen_while_A401_target_0_measurement_was_running_before_any_A401_complete_target_selection_holdout_score_or_result"
        or tuple(fit.get("target_indices", [])) != TARGETS
        or tuple(fit.get("complete_view_order", [])) != VIEW_NAMES
        or tuple(fit.get("aggregator_order", [])) != AGGREGATORS
        or fit.get("candidate_count") != 765
        or application.get("target_assignment_or_true_prefix_available") is not False
        or application.get("candidate_assignments_executed") != 0
        or application.get("new_solver_stages") != 0
        or boundary.get("A401_selection_or_holdout_scores_available_at_design_freeze") is not False
        or boundary.get("A385_production_assignment_or_true_prefix_consumed") is not False
    ):
        raise RuntimeError("A402 frozen design semantics differ")
    sources = value["source_anchors"]
    expected = {
        "A401_design": (A401.DESIGN, A401.DESIGN_SHA256),
        "A401_runner": (A401_RUNNER, A401_RUNNER_SHA256),
        "A401_implementation": (A401.IMPLEMENTATION, A401_IMPLEMENTATION_SHA256),
        "A401_public_corpus": (A401.PROTOCOL, A401_PROTOCOL_SHA256),
        "A388_runner": (A388_RUNNER, A388_RUNNER_SHA256),
        "A388_preflight": (A388_PREFLIGHT, A388_PREFLIGHT_SHA256),
        "A388_order": (A388_ORDER, A388_ORDER_SHA256),
    }
    for name, (path, digest) in expected.items():
        if sources.get(f"{name}_path") != relative(path) or sources.get(f"{name}_sha256") != digest:
            raise RuntimeError(f"A402 source declaration differs: {name}")
        anchor(path, digest)
    return value


def freeze_implementation() -> dict[str, Any]:
    if IMPLEMENTATION.exists() or RESULT.exists() or CAUSAL.exists() or REPORT.exists():
        raise FileExistsError("A402 implementation or result already exists")
    if A401.SELECTION.exists() or A401.RESULT.exists():
        raise RuntimeError("A402 code freeze must precede the A401 selection and result")
    design = load_design()
    if not TEST.exists() or not REPRO.exists():
        raise FileNotFoundError("A402 test and reproducer must precede freeze")
    payload: dict[str, Any] = {
        "schema": "chacha20-round20-w50-knownkey-fullfit-production-reader-a402-implementation-v1",
        "attempt_id": ATTEMPT_ID,
        "commitment_state": "complete_code_frozen_before_A401_selection_holdout_result_or_A402_production_order",
        "design_sha256": DESIGN_SHA256,
        "candidate_count": design["fullfit_contract"]["candidate_count"],
        "A401_selection_available_at_freeze": False,
        "A401_result_available_at_freeze": False,
        "A385_production_assignment_or_true_prefix_consumed": False,
        "anchors": {
            "design": anchor(DESIGN, DESIGN_SHA256),
            "A401_design": anchor(A401.DESIGN, A401.DESIGN_SHA256),
            "A401_runner": anchor(A401_RUNNER, A401_RUNNER_SHA256),
            "A401_implementation": anchor(A401.IMPLEMENTATION, A401_IMPLEMENTATION_SHA256),
            "A401_public_corpus": anchor(A401.PROTOCOL, A401_PROTOCOL_SHA256),
            "A388_runner": anchor(A388_RUNNER, A388_RUNNER_SHA256),
            "A388_preflight": anchor(A388_PREFLIGHT, A388_PREFLIGHT_SHA256),
            "A388_order": anchor(A388_ORDER, A388_ORDER_SHA256),
            "runner": anchor(Path(__file__)),
            "test": anchor(TEST),
            "reproducer": anchor(REPRO),
        },
    }
    payload["implementation_commitment_sha256"] = canonical_sha256(payload)
    atomic_json(IMPLEMENTATION, payload)
    return payload


def load_implementation(expected_sha256: str | None = None) -> dict[str, Any]:
    if expected_sha256 is not None and file_sha256(IMPLEMENTATION) != expected_sha256:
        raise RuntimeError("A402 implementation file hash differs")
    value = json.loads(IMPLEMENTATION.read_bytes())
    if (
        value.get("schema")
        != "chacha20-round20-w50-knownkey-fullfit-production-reader-a402-implementation-v1"
        or value.get("attempt_id") != ATTEMPT_ID
        or value.get("commitment_state")
        != "complete_code_frozen_before_A401_selection_holdout_result_or_A402_production_order"
        or value.get("candidate_count") != 765
        or value.get("A401_selection_available_at_freeze") is not False
        or value.get("A401_result_available_at_freeze") is not False
    ):
        raise RuntimeError("A402 implementation semantics differ")
    for row in value["anchors"].values():
        anchor(ROOT / row["path"], row["sha256"])
    unsigned = {
        key: item for key, item in value.items() if key != "implementation_commitment_sha256"
    }
    if value.get("implementation_commitment_sha256") != canonical_sha256(unsigned):
        raise RuntimeError("A402 implementation commitment differs")
    return value


def qualification_panel(a401_result: Mapping[str, Any]) -> dict[str, Any]:
    design = load_design()["qualification_contract"]
    comparison = a401_result.get("holdout_comparison", {})
    selected = a401_result.get("holdout_selected_panel", {})
    factor = float(comparison.get("selected_geometric_rank_improvement_factor", 0.0))
    gain = float(comparison.get("selected_additional_bit_gain", -math.inf))
    qualified = (
        a401_result.get("evidence_stage") == design["required_A401_result_state"]
        and factor
        > design[
            "selected_candidate_geometric_improvement_over_best_frozen_holdout_baseline_must_exceed"
        ]
        and gain > design["selected_candidate_additional_holdout_bit_gain_must_exceed"]
        and int(a401_result.get("holdout_refits", -1)) == 0
        and int(a401_result.get("measurement_target_labels_used", -1)) == 0
        and int(a401_result.get("candidate_assignments_executed", -1)) == 0
    )
    return {
        "qualified": qualified,
        "selected_geometric_rank_improvement_factor": factor,
        "selected_additional_bit_gain": gain,
        "selected_holdout_geometric_mean_rank": selected.get("geometric_mean_rank"),
        "selected_holdout_ranks": selected.get("ranks"),
    }


def load_a401_result(
    *, expected_result_sha256: str, expected_selection_sha256: str
) -> tuple[dict[str, Any], dict[str, Any]]:
    if file_sha256(A401.RESULT) != expected_result_sha256:
        raise RuntimeError("A402 A401 result hash differs")
    selection = A401.load_selection(expected_selection_sha256)
    value = json.loads(A401.RESULT.read_bytes())
    if (
        value.get("schema") != "chacha20-round20-w50-knownkey-direct12-learning-a401-result-v1"
        or value.get("attempt_id") != "A401"
        or value.get("selection_sha256") != expected_selection_sha256
        or value.get("complete_targets_measured") != len(TARGETS)
        or value.get("complete_direct12_cells_measured") != len(TARGETS) * CELLS
        or value.get("solver_stages_measured") != len(TARGETS) * CELLS * 4
        or value.get("A385_production_assignment_or_true_prefix_consumed") is not False
        or value.get("live_recovery_progress_or_outcomes_consumed") is not False
    ):
        raise RuntimeError("A402 A401 result semantics differ")
    return value, selection


def candidate_rows(
    rank_matrices: Mapping[int, np.ndarray], labels: Mapping[int, Mapping[str, Any]]
) -> list[dict[str, Any]]:
    if tuple(rank_matrices) != TARGETS or tuple(labels) != TARGETS:
        raise ValueError("A402 full-fit target cover differs")
    candidates = []
    for mask in range(1, 1 << len(VIEW_NAMES)):
        subset = tuple(index for index in range(len(VIEW_NAMES)) if mask & (1 << index))
        for aggregator_index, aggregator in enumerate(AGGREGATORS):
            truth_ranks = [
                A401.candidate_rank(
                    rank_matrices[index],
                    subset,
                    aggregator,
                    int(labels[index]["true_direct12_cell"]),
                )
                for index in TARGETS
            ]
            mean_log2 = statistics.fmean(math.log2(rank) for rank in truth_ranks)
            candidates.append(
                {
                    "aggregator": aggregator,
                    "aggregator_index": aggregator_index,
                    "view_indices": list(subset),
                    "view_names": [VIEW_NAMES[value] for value in subset],
                    "fullfit_true_ranks": truth_ranks,
                    "fullfit_mean_log2_rank": mean_log2,
                    "fullfit_bit_gain_vs_complete_4096_cover": 12.0 - mean_log2,
                    "fullfit_worst_rank": max(truth_ranks),
                }
            )
    if len(candidates) != 765:
        raise RuntimeError("A402 candidate family size differs")
    return candidates


def select_fullfit_candidate(candidates: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    if len(candidates) != 765:
        raise ValueError("A402 full-fit candidate count differs")
    return dict(
        min(
            candidates,
            key=lambda row: (
                row["fullfit_mean_log2_rank"],
                row["fullfit_worst_rank"],
                len(row["view_indices"]),
                row["aggregator_index"],
                tuple(row["view_indices"]),
            ),
        )
    )


def fullfit() -> tuple[dict[str, Any], dict[str, Any]]:
    train = A401.load_label_file(
        A401.TRAIN_LABELS,
        "chacha20-round20-w50-knownkey-direct12-learning-a401-selection-labels-v1",
        A401.TRAIN_TARGETS,
    )
    holdout = A401.load_label_file(
        A401.HOLDOUT_LABELS,
        "chacha20-round20-w50-knownkey-direct12-learning-a401-holdout-labels-v1",
        A401.HOLDOUT_TARGETS,
    )
    labels = {**train, **holdout}
    if tuple(labels) != TARGETS:
        raise RuntimeError("A402 combined known-key label cover differs")
    rank_matrices = {}
    field_commitments = {}
    for index in TARGETS:
        rank_matrices[index], field_commitments[str(index)] = A401.view_rank_matrix(index)
    candidates = candidate_rows(rank_matrices, labels)
    winner = select_fullfit_candidate(candidates)
    return winner, {
        "candidate_family_commitment_sha256": canonical_sha256(candidates),
        "knownkey_field_commitments": field_commitments,
        "combined_label_commitment_sha256": canonical_sha256([labels[index] for index in TARGETS]),
    }


def production_rank_matrix() -> tuple[np.ndarray, dict[str, list[int]], dict[str, Any]]:
    order_value = json.loads(A388_ORDER.read_bytes())
    if (
        file_sha256(A388_ORDER) != A388_ORDER_SHA256
        or order_value.get("attempt_id") != "A388"
        or order_value.get("target_labels_used") != 0
        or order_value.get("reader_refits") != 0
        or order_value.get("candidate_assignments_executed") != 0
        or order_value.get("A387_progress_or_filter_outcomes_consumed") is not False
    ):
        raise RuntimeError("A402 A388 production field boundary differs")
    measurements = {}
    for row in order_value["measurement_ledger"]:
        low4 = int(row["low4"])
        value = A388._read_measurement(path_from_ref(row["path"]), row)  # noqa: SLF001
        A388._validate_measurement(value, low4)  # noqa: SLF001
        measurements[low4] = value
    if tuple(measurements) != A388.SLICES:
        raise RuntimeError("A402 A388 production measurement cover differs")
    _selection, _a272, model, groups = A388.A341.reconstruct_known_key_selection(
        json.loads(A388.A341.DESIGN.read_bytes())
    )
    fields = A388.A348._all_view_scores(measurements, model, groups)  # noqa: SLF001
    if tuple(fields) != VIEW_NAMES:
        raise RuntimeError("A402 production view family differs")
    orders = {
        name: A401.exact_order(A388.A348._rank_order(fields[name]))  # noqa: SLF001
        for name in VIEW_NAMES
    }
    if (
        A401.A400_uint16_sha(orders[VIEW_NAMES[5]])
        != order_value["W50_public_output_direct12_order_uint16be_sha256"]
    ):
        raise RuntimeError("A402 production Pair-slice reconstruction differs")
    ranks = np.stack([A401.rank_vector(orders[name]) for name in VIEW_NAMES], axis=0)
    metadata = {
        "A388_measurement_sha256": order_value["measurement_sha256"],
        "view_order_uint16be_sha256": {
            name: A401.A400_uint16_sha(orders[name]) for name in VIEW_NAMES
        },
        "view_score_field_sha256": {
            name: canonical_sha256(np.asarray(fields[name], dtype=np.float64).tolist())
            for name in VIEW_NAMES
        },
    }
    return ranks, orders, metadata


def build_causal(payload: Mapping[str, Any]) -> dict[str, Any]:
    sys.path.insert(0, str(DOTCAUSAL_SRC))
    from dotcausal.io import CausalReader, CausalWriter

    qualified = bool(payload["qualification"]["qualified"])
    terminal = (
        "A403_fullround_W50_learned_reader_recovery_ready"
        if qualified
        else "A402_knownkey_learning_boundary_retained"
    )
    writer = CausalWriter(api_id="a402w50")
    writer._rules = []
    writer.add_rule(
        name="heldout_panel_to_qualification",
        description="A401's byte-frozen eight-target holdout applies the predeclared A402 deployment threshold.",
        pattern=["A401_frozen_reader", "A401_holdout_panel"],
        conclusion="A402_qualification_decision",
        confidence_modifier=1.0,
    )
    writer.add_rule(
        name="qualification_to_fullfit",
        description="A passing holdout gate permits the unchanged 765-candidate family to fit all sixteen known-key fields exactly once.",
        pattern=["A402_qualification_decision", "A401_all_sixteen_knownkey_fields"],
        conclusion="A402_fullfit_reader",
        confidence_modifier=1.0,
    )
    writer.add_rule(
        name="fullfit_to_unlabeled_production",
        description="The full-fit Reader applies without refit or target labels to the complete A388 production field.",
        pattern=["A402_fullfit_reader", "A388_complete_unlabeled_W50_field"],
        conclusion=terminal,
        confidence_modifier=1.0,
    )
    writer.add_triplet(
        trigger="A401:train_only_reader_plus_eight_target_holdout",
        mechanism="predeclared_strict_A402_qualification_gate",
        outcome=f"A402:qualification_{'pass' if qualified else 'boundary'}",
        confidence=1.0,
        source=payload["A401_result_sha256"],
        quantification=json.dumps(payload["qualification"], sort_keys=True),
        evidence="A402 design and code froze before A401 selection or result",
        domain="known-key W50 Reader qualification",
        quality_score=1.0,
    )
    writer.add_triplet(
        trigger=f"A402:qualification_{'pass' if qualified else 'boundary'}",
        mechanism="frozen_fullfit_then_zero_refit_production_application",
        outcome=f"A402:{terminal}",
        confidence=1.0,
        source=payload["deployment_commitment_sha256"],
        quantification=json.dumps(payload.get("fullfit_candidate"), sort_keys=True),
        evidence="zero production labels, refits, candidates, or live recovery outcomes",
        domain="AI-native learned Reader deployment",
        quality_score=1.0,
    )
    writer.add_triplet(
        trigger="A401:heldout_knownkey_learning",
        mechanism="materialized_A402_deployment_chain",
        outcome=f"A402:{terminal}",
        confidence=1.0,
        source="materialized:A401_to_A402_chain",
        quantification="exact retained closure",
        evidence="pre-result A402 design and implementation commitments",
        domain="AI-native retained inference",
        quality_score=1.0,
        is_inferred=True,
    )
    writer.add_cluster(
        name="A402 known-key full-fit to production transfer",
        entities=[
            "A401:train_only_reader_plus_eight_target_holdout",
            "A402:qualification_decision",
            "A402:fullfit_reader",
            f"A402:{terminal}",
        ],
    )
    writer.add_gap(
        subject=f"A402:{terminal}",
        predicate="next_required_object",
        expected_object_type=(
            "complete_group_execution_in_the_frozen_learned_order"
            if qualified
            else "new_predeclared_reader_family_with_independent_holdout"
        ),
        confidence=1.0,
        suggested_queries=[
            "Execute the exact learned production order with matched control."
            if qualified
            else "Use the retained boundary to design a different algebraic Reader family."
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
        reader.api_id != "a402w50"
        or len(explicit) != 2
        or len(all_rows) != 3
        or len(inferred) != 1
        or len(reader._rules) != 3
        or len(reader._clusters) != 1
        or len(reader._gaps) != 1
    ):
        raise RuntimeError("A402 authentic Causal reopen gate failed")
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
            "qualification": explicit[0],
            "deployment": explicit[1],
            "terminal_chain": all_rows[-1],
            "next_gap": reader._gaps[0],
        },
    }


def materialize(
    *,
    expected_implementation_sha256: str,
    expected_a401_result_sha256: str,
    expected_a401_selection_sha256: str,
) -> dict[str, Any]:
    if RESULT.exists() or CAUSAL.exists() or REPORT.exists():
        raise FileExistsError("A402 result already exists")
    implementation = load_implementation(expected_implementation_sha256)
    a401_result, selection = load_a401_result(
        expected_result_sha256=expected_a401_result_sha256,
        expected_selection_sha256=expected_a401_selection_sha256,
    )
    qualification = qualification_panel(a401_result)
    winner = None
    fit_metadata = None
    production_order = None
    production_metadata = None
    diversity = None
    if qualification["qualified"]:
        winner, fit_metadata = fullfit()
        ranks, view_orders, production_metadata = production_rank_matrix()
        production_order = A401.candidate_order(
            ranks,
            winner["view_indices"],
            winner["aggregator"],
        )
        diversity = {
            name: A388.A351.diversity_panel(production_order, view_orders[name])
            for name in VIEW_NAMES
        }
    payload: dict[str, Any] = {
        "schema": "chacha20-round20-w50-knownkey-fullfit-production-reader-a402-result-v1",
        "attempt_id": ATTEMPT_ID,
        "evidence_stage": (
            "HELDOUT_QUALIFIED_FULLFIT_W50_READER_APPLIED_ZERO_REFIT_TO_A388_PRODUCTION"
            if qualification["qualified"]
            else "A401_HELDOUT_QUALIFICATION_BOUNDARY_RETAINED_NO_PRODUCTION_RECOVERY_QUEUED"
        ),
        "design_sha256": DESIGN_SHA256,
        "implementation_sha256": expected_implementation_sha256,
        "implementation_commitment_sha256": implementation["implementation_commitment_sha256"],
        "A401_result_sha256": expected_a401_result_sha256,
        "A401_selection_sha256": expected_a401_selection_sha256,
        "A401_selected_candidate": selection["selected_candidate"],
        "qualification": qualification,
        "fullfit_candidate": winner,
        "fullfit_metadata": fit_metadata,
        "production_order": production_order,
        "production_order_uint16be_sha256": (
            A401.A400_uint16_sha(production_order) if production_order is not None else None
        ),
        "production_view_metadata": production_metadata,
        "production_operator_diversity": diversity,
        "production_target_labels_used": 0,
        "production_reader_refits": 0,
        "production_candidate_assignments_executed": 0,
        "new_solver_stages": 0,
        "live_recovery_progress_filter_outcomes_or_results_consumed": False,
        "A397_Direct12_first_free_slot_obligation_preserved": True,
        "anchors": {
            "design": anchor(DESIGN, DESIGN_SHA256),
            "implementation": anchor(IMPLEMENTATION, expected_implementation_sha256),
            "A401_result": anchor(A401.RESULT, expected_a401_result_sha256),
            "A401_selection": anchor(A401.SELECTION, expected_a401_selection_sha256),
            "A388_order": anchor(A388_ORDER, A388_ORDER_SHA256),
            "runner": anchor(Path(__file__)),
        },
    }
    payload["deployment_commitment_sha256"] = canonical_sha256(
        {
            "qualification": qualification,
            "fullfit_candidate": winner,
            "fullfit_metadata": fit_metadata,
            "production_order": production_order,
            "production_view_metadata": production_metadata,
        }
    )
    payload["causal"] = build_causal(payload)
    atomic_json(RESULT, payload)
    atomic_bytes(
        REPORT,
        (
            "# A402 — Known-key full-fit W50 production Reader\n\n"
            f"Evidence stage: **{payload['evidence_stage']}**\n\n"
            f"- Holdout qualification: **{qualification['qualified']}**\n"
            f"- Holdout improvement factor: **{qualification['selected_geometric_rank_improvement_factor']:.9f}x**\n"
            f"- Holdout additional bit gain: **{qualification['selected_additional_bit_gain']:.9f} bits**\n"
            f"- Full-fit candidate: **{winner}**\n"
            f"- Production order SHA-256: **{payload['production_order_uint16be_sha256']}**\n"
            "- Production labels / refits / candidates / new solver stages: **0 / 0 / 0 / 0**\n"
            "- Authentic AI-native Causal readback: **2 explicit + 1 inferred chain**\n"
        ).encode(),
    )
    return payload


def analyze() -> dict[str, Any]:
    payload: dict[str, Any] = {
        "attempt_id": ATTEMPT_ID,
        "design_sha256": DESIGN_SHA256,
        "implementation_frozen": IMPLEMENTATION.exists(),
        "A401_selection_available": A401.SELECTION.exists(),
        "A401_result_available": A401.RESULT.exists(),
        "result_complete": RESULT.exists(),
    }
    if IMPLEMENTATION.exists():
        payload["implementation_sha256"] = file_sha256(IMPLEMENTATION)
    if RESULT.exists():
        value = json.loads(RESULT.read_bytes())
        payload["result_sha256"] = file_sha256(RESULT)
        payload["qualification"] = value["qualification"]
        payload["fullfit_candidate"] = value["fullfit_candidate"]
        payload["production_order_uint16be_sha256"] = value["production_order_uint16be_sha256"]
    return payload


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    action = parser.add_mutually_exclusive_group(required=True)
    action.add_argument("--freeze-implementation", action="store_true")
    action.add_argument("--materialize", action="store_true")
    action.add_argument("--analyze", action="store_true")
    parser.add_argument("--expected-implementation-sha256")
    parser.add_argument("--expected-a401-result-sha256")
    parser.add_argument("--expected-a401-selection-sha256")
    args = parser.parse_args()
    if args.freeze_implementation:
        payload = freeze_implementation()
    elif args.materialize:
        required = (
            args.expected_implementation_sha256,
            args.expected_a401_result_sha256,
            args.expected_a401_selection_sha256,
        )
        if not all(required):
            parser.error("--materialize requires all three expected SHA-256 arguments")
        payload = materialize(
            expected_implementation_sha256=args.expected_implementation_sha256,
            expected_a401_result_sha256=args.expected_a401_result_sha256,
            expected_a401_selection_sha256=args.expected_a401_selection_sha256,
        )
    else:
        payload = analyze()
    print(json.dumps(payload, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()

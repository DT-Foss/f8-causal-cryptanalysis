#!/usr/bin/env python3
"""A418: immutable A417 holdout closure with explicit A414 model binding."""

from __future__ import annotations

import argparse
import importlib.util
import inspect
import json
import os
import sys
from collections.abc import Mapping
from pathlib import Path
from typing import Any

ROOT = Path(__file__).parents[2]
RESEARCH = ROOT / "research"
CONFIGS = RESEARCH / "configs"
RESULTS = RESEARCH / "results/v1"

DESIGN = CONFIGS / "chacha20_round20_w50_selection_calibrated_portfolio_repair_a418_design_v1.json"
IMPLEMENTATION = CONFIGS / "chacha20_round20_w50_selection_calibrated_portfolio_repair_a418_implementation_v1.json"
RESULT = RESULTS / "chacha20_round20_w50_selection_calibrated_portfolio_repair_a418_v1.json"
CAUSAL = RESULT.with_suffix(".causal")
REPORT = RESULT.with_suffix(".md")
TEST = ROOT / "tests/test_chacha20_round20_w50_selection_calibrated_portfolio_repair_a418.py"
REPRO = ROOT / "scripts/reproduce_chacha20_round20_w50_selection_calibrated_portfolio_repair_a418.sh"

A417_RUNNER = RESEARCH / "experiments/chacha20_round20_w50_selection_calibrated_portfolio_a417.py"
A417_IMPLEMENTATION = CONFIGS / "chacha20_round20_w50_selection_calibrated_portfolio_a417_implementation_v1.json"
A417_LIBRARY = CONFIGS / "chacha20_round20_w50_selection_calibrated_portfolio_a417_library_v1.json"
A417_SELECTION = CONFIGS / "chacha20_round20_w50_selection_calibrated_portfolio_a417_selection_v1.json"
A414_MODEL = CONFIGS / "chacha20_round20_w50_knownkey_parallel_portfolio_a414_model_v1.json"
A415_MODEL = CONFIGS / "chacha20_round20_w50_xor_landscape_portfolio_a415_model_v1.json"
A416_MODEL = CONFIGS / "chacha20_round20_w50_folded_xor_portfolio_a416_model_v1.json"
A412_PROTOCOL = CONFIGS / "chacha20_round20_w50_fresh_hybrid_reader_a412_public_corpus_v1.json"

ATTEMPT_ID = "A418"
DESIGN_SHA256 = "61c9eab12666229c19aaac936b2ac00710101e831088264968ef47933cae7053"
A417_RUNNER_SHA256 = "dcdb1999b9521b104b3a321da4c42c0e2e7678b53e0adec82af1f3c8d1cfde85"
A417_IMPLEMENTATION_SHA256 = "2f9279f8e1b0edd03353ecb864f47e4c56db6e98a2ced09baa039a87156175d7"
A417_LIBRARY_SHA256 = "53d142b8351a990e06a0e265581320a0df871f59bcc493e3e5ea0f961c391253"
A417_SELECTION_SHA256 = "dde2e8a9ec184e52ed353f33b7558f43c767cb8deece715caceffe6910922653"
A414_MODEL_SHA256 = "1e65ef99e4a49861ffcfe5e6f30ec3018516e7d91bbdb2a2539980efcaba6f0b"
A415_MODEL_SHA256 = "ed7d9e8b44c9dee4fecdb4d59de6a67911c3ed4fc0a0fdb09d7e17885e78e110"
A416_MODEL_SHA256 = "ed927419a04f39f16ffb2679ff51544a43288821744cf2558cd97e45e45a6c58"
A412_PROTOCOL_SHA256 = "f7859b381d5cf6a5f1a765b4abb44192d3bd73539c681a9a40d8c0a48dd365a2"
CELLS = 4096
WORKERS = 8
DOTCAUSAL_SRC = Path("/Users/bhkmie/Documents/Forschung/O1/vendor/fabel/dotcausal_package/src")


def load_module(path: Path, name: str) -> Any:
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot import A418 dependency {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


A417 = load_module(A417_RUNNER, "a418_a417")
file_sha256 = A417.file_sha256
canonical_sha256 = A417.canonical_sha256
atomic_json = A417.atomic_json
atomic_bytes = A417.atomic_bytes
relative = A417.relative
anchor = A417.anchor
uint16be_sha256 = A417.uint16be_sha256
metric_panel = A417.metric_panel


def load_design() -> dict[str, Any]:
    if file_sha256(DESIGN) != DESIGN_SHA256:
        raise RuntimeError("A418 design hash differs")
    value = json.loads(DESIGN.read_bytes())
    boundary = value.get("information_boundary", {})
    repair = value.get("repair_scope", {})
    if (
        value.get("schema")
        != "chacha20-round20-w50-selection-calibrated-portfolio-repair-a418-design-v1"
        or value.get("attempt_id") != ATTEMPT_ID
        or repair.get("selection_changed") is not False
        or repair.get("candidate_library_changed") is not False
        or repair.get("reader_order_changed") is not False
        or repair.get("holdout_boundary_changed") is not False
        or boundary.get("A412_holdout_fields_consumed_by_A417_or_A418_at_design_freeze") != 0
        or boundary.get("A412_holdout_labels_consumed_by_A417_or_A418_at_design_freeze") != 0
    ):
        raise RuntimeError("A418 frozen design semantics differ")
    frozen = value["frozen_inputs"]
    for key, item in frozen.items():
        if key.endswith("_path"):
            stem = key.removesuffix("_path")
            anchor(ROOT / item, frozen[f"{stem}_sha256"])
    return value


def freeze_implementation() -> dict[str, Any]:
    if any(path.exists() for path in (IMPLEMENTATION, RESULT, CAUSAL, REPORT)):
        raise FileExistsError("A418 implementation or downstream artifact already exists")
    design = load_design()
    if not TEST.exists() or not REPRO.exists():
        raise FileNotFoundError("A418 test and reproducer must precede implementation freeze")
    selection = A417.load_selection(A417_SELECTION_SHA256)
    payload: dict[str, Any] = {
        "schema": "chacha20-round20-w50-selection-calibrated-portfolio-repair-a418-implementation-v1",
        "attempt_id": ATTEMPT_ID,
        "commitment_state": "frozen_before_any_A418_A412_holdout_field_label_or_score",
        "design_sha256": DESIGN_SHA256,
        "repair_scope": design["repair_scope"],
        "selected_canonical_indices": selection["portfolio_selection"]["selected_canonical_indices"],
        "A412_holdout_fields_used": 0,
        "A412_holdout_labels_used": 0,
        "holdout_reader_refits": 0,
        "holdout_model_choices": 0,
        "anchors": {
            "design": anchor(DESIGN, DESIGN_SHA256),
            "A417_runner": anchor(A417_RUNNER, A417_RUNNER_SHA256),
            "A417_implementation": anchor(A417_IMPLEMENTATION, A417_IMPLEMENTATION_SHA256),
            "A417_library": anchor(A417_LIBRARY, A417_LIBRARY_SHA256),
            "A417_selection": anchor(A417_SELECTION, A417_SELECTION_SHA256),
            "A414_model": anchor(A414_MODEL, A414_MODEL_SHA256),
            "A415_model": anchor(A415_MODEL, A415_MODEL_SHA256),
            "A416_model": anchor(A416_MODEL, A416_MODEL_SHA256),
            "A412_protocol": anchor(A412_PROTOCOL, A412_PROTOCOL_SHA256),
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
        raise RuntimeError("A418 implementation hash differs")
    value = json.loads(IMPLEMENTATION.read_bytes())
    if (
        value.get("schema")
        != "chacha20-round20-w50-selection-calibrated-portfolio-repair-a418-implementation-v1"
        or value.get("attempt_id") != ATTEMPT_ID
        or value.get("A412_holdout_fields_used") != 0
        or value.get("A412_holdout_labels_used") != 0
        or value.get("holdout_reader_refits") != 0
        or value.get("holdout_model_choices") != 0
    ):
        raise RuntimeError("A418 implementation semantics differ")
    for row in value["anchors"].values():
        anchor(ROOT / row["path"], row["sha256"])
    unsigned = {
        key: item for key, item in value.items() if key != "implementation_commitment_sha256"
    }
    if value.get("implementation_commitment_sha256") != canonical_sha256(unsigned):
        raise RuntimeError("A418 implementation commitment differs")
    return value


def build_causal(payload: Mapping[str, Any]) -> dict[str, Any]:
    sys.path.insert(0, str(DOTCAUSAL_SRC))
    from dotcausal.io import CausalReader, CausalWriter

    qualified = bool(payload["external_transfer"]["qualified"])
    terminal = (
        "A418_holdout_qualified_selection_calibrated_scheduler"
        if qualified
        else "A418_holdout_boundary_retained_selection_signal"
    )
    writer = CausalWriter(api_id="a418w50")
    writer._rules = []
    writer.add_rule(
        name="immutable_selection_to_repaired_evaluator",
        description="Bind the immutable A417 portfolio to the explicit committed A414 model hash without changing any Reader or data boundary.",
        pattern=["A417_frozen_eight_reader_portfolio", "A418_explicit_A414_model_binding"],
        conclusion="A418_executable_external_evaluator",
        confidence_modifier=1.0,
    )
    writer.add_rule(
        name="untouched_holdout_to_external_transfer",
        description="Apply all frozen Readers unchanged to A412 targets sixteen through thirty-one.",
        pattern=["A418_executable_external_evaluator", "A412_untouched_holdout_16_31"],
        conclusion=terminal,
        confidence_modifier=1.0,
    )
    writer.add_rule(
        name="external_transfer_to_exact_scheduler",
        description="Materialize a complete eight-worker owner-lane schedule with exact 512-epoch makespan.",
        pattern=[terminal, "A417_frozen_production_orders"],
        conclusion=f"{terminal}_exact_scheduler",
        confidence_modifier=1.0,
    )
    writer.add_triplet(
        trigger="A417:frozen_eight_reader_portfolio",
        mechanism="explicit_committed_A414_model_hash_binding",
        outcome="A418:executable_external_evaluator",
        confidence=1.0,
        source=payload["implementation_sha256"],
        quantification="one namespace lookup repaired; zero selection, Reader, metric, or boundary changes",
        evidence="A417 selection replayed exactly before A418 implementation freeze",
        domain="full-round ChaCha20 W50 evaluator closure",
        quality_score=1.0,
    )
    writer.add_triplet(
        trigger="A418:executable_external_evaluator",
        mechanism="unchanged_eight_reader_transfer_to_untouched_A412_holdout",
        outcome=f"A418:{terminal}",
        confidence=1.0,
        source=payload["external_measurement_sha256"],
        quantification=json.dumps(payload["external_transfer"], sort_keys=True),
        evidence="sixteen holdout fields and labels opened only after terminal A412 closure",
        domain="full-round ChaCha20 W50 prospective Reader transfer",
        quality_score=1.0,
    )
    writer.add_triplet(
        trigger=f"A418:{terminal}",
        mechanism="minimum_rank_owner_lanes_plus_balanced_static_work_stealing",
        outcome=f"A418:{terminal}_exact_scheduler",
        confidence=1.0,
        source=payload["deployment_commitment_sha256"],
        quantification=json.dumps(payload["schedule_proof"], sort_keys=True),
        evidence="4,096 unique cells, eight workers, zero order/depth/work violations",
        domain="full-round ChaCha20 W50 recovery scheduling",
        quality_score=1.0,
    )
    writer.add_triplet(
        trigger="A417:frozen_eight_reader_portfolio",
        mechanism="repaired_external_transfer_and_scheduler_closure",
        outcome=f"A418:{terminal}_exact_scheduler",
        confidence=1.0,
        source="materialized:A418_repaired_external_chain",
        quantification="exact retained closure",
        evidence="immutable selection, untouched holdout, explicit baseline hash, exact scheduler",
        domain="AI-native retained inference",
        quality_score=1.0,
        is_inferred=True,
    )
    writer.add_cluster(
        name="A418 immutable A417 external closure",
        entities=[
            "A417:frozen_eight_reader_portfolio",
            "A418:executable_external_evaluator",
            f"A418:{terminal}",
            f"A418:{terminal}_exact_scheduler",
        ],
    )
    writer.add_gap(
        subject=f"A418:{terminal}_exact_scheduler",
        predicate="next_required_object",
        expected_object_type=(
            "shared_stop_execution_of_eight_frozen_A417_worker_lists"
            if qualified
            else "continuous_polarity_posterior_or_larger_selection_corpus"
        ),
        confidence=1.0,
        suggested_queries=[
            "Execute the exact eight-worker A418 schedule with one shared confirmed stop."
            if qualified
            else "Fit a continuous polarity posterior on selection-only data and freeze a new Reader before any new holdout."
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
        reader.api_id != "a418w50"
        or len(explicit) != 3
        or len(all_rows) != 4
        or len(inferred) != 1
        or len(reader._rules) != 3
        or len(reader._clusters) != 1
        or len(reader._gaps) != 1
    ):
        raise RuntimeError("A418 authentic Causal reopen gate failed")
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
            "repair": explicit[0],
            "external_transfer": explicit[1],
            "scheduler": explicit[2],
            "terminal_chain": all_rows[-1],
            "next_gap": reader._gaps[0],
        },
    }


def evaluate_external(*, expected_implementation_sha256: str) -> dict[str, Any]:
    if any(path.exists() for path in (RESULT, CAUSAL, REPORT)):
        raise FileExistsError("A418 result already exists")
    implementation = load_implementation(expected_implementation_sha256)
    library = A417.load_library(A417_LIBRARY_SHA256)
    selection = A417.load_selection(A417_SELECTION_SHA256)
    protocol = A417.A412.load_protocol(A412_PROTOCOL_SHA256)
    for target in A417.A412.TARGETS:
        A417.A412.load_fresh_complete(target, protocol)
    labels = A417.A412.load_label(
        A417.A412.HOLDOUT_LABELS,
        "chacha20-round20-w50-fresh-hybrid-reader-a412-holdout-labels-v1",
        A417.A412.HOLDOUT_TARGETS,
    )

    a414_model = A417.A414.load_portfolio(A414_MODEL_SHA256)
    a415_model = A417.A415.load_model(A415_MODEL_SHA256)
    a416_model = A417.A416.load_model(A416_MODEL_SHA256)
    learned_depths: list[int] = []
    baselines: dict[str, list[int]] = {"A414": [], "A415": [], "A416": []}
    field_commitments: dict[str, Any] = {}
    reader_commitments: dict[str, Any] = {}
    for target in A417.A412.HOLDOUT_TARGETS:
        rank_matrix, field_commitments[str(target)] = A417.A412.fresh_rank_matrix(target)
        cell = int(labels[target]["true_direct12_cell"])
        learned = A417.selected_orders(rank_matrix, library, selection)
        baseline_orders = {
            "A414": A417.A414.portfolio_orders(rank_matrix, a414_model),
            "A415": A417.A415.portfolio_orders(rank_matrix, a415_model),
            "A416": A417.A416.portfolio_orders(rank_matrix, a416_model),
        }
        learned_ranks = {
            role: int(A417.A401.rank_vector(order)[cell])
            for role, order in learned.items()
        }
        learned_depths.append(min(learned_ranks.values()))
        baseline_ranks: dict[str, dict[str, int]] = {}
        for name, orders in baseline_orders.items():
            row = {
                role: int(A417.A401.rank_vector(order)[cell])
                for role, order in orders.items()
            }
            baseline_ranks[name] = row
            baselines[name].append(min(row.values()))
        reader_commitments[str(target)] = {
            "A417_order_uint16be_sha256": {
                role: uint16be_sha256(order) for role, order in learned.items()
            },
            "A417_true_ranks": learned_ranks,
            "baseline_true_ranks": baseline_ranks,
        }
        print(f"A418 holdout target {target}/31 complete", flush=True)

    learned_panel = metric_panel(learned_depths)
    baseline_panels = {name: metric_panel(ranks) for name, ranks in baselines.items()}
    best_name = min(
        baseline_panels,
        key=lambda name: (
            baseline_panels[name]["mean_log2_rank"],
            baseline_panels[name]["worst_rank"],
            name,
        ),
    )
    best_panel = baseline_panels[best_name]
    factor = best_panel["geometric_mean_rank"] / learned_panel["geometric_mean_rank"]
    gain = (
        learned_panel["bit_gain_vs_complete_4096_cover"]
        - best_panel["bit_gain_vs_complete_4096_cover"]
    )
    qualified = factor > 1.0 and gain > 0.0
    external = {
        "qualified": qualified,
        "primary_untouched_holdout_A418_panel": learned_panel,
        "matched_baseline_panels": baseline_panels,
        "best_matched_baseline": best_name,
        "holdout_geometric_rank_improvement_factor": factor,
        "holdout_additional_bit_gain": gain,
        "holdout_better_targets": sum(
            left < right
            for left, right in zip(learned_depths, baselines[best_name], strict=True)
        ),
        "holdout_equal_targets": sum(
            left == right
            for left, right in zip(learned_depths, baselines[best_name], strict=True)
        ),
        "holdout_worse_targets": sum(
            left > right
            for left, right in zip(learned_depths, baselines[best_name], strict=True)
        ),
        "equal_worker_count": WORKERS,
        "holdout_model_choices": 0,
        "holdout_model_refits": 0,
        "new_solver_stages": 0,
    }

    with A417.A412.a401_paths(
        A417.A412.ORIGINAL_A401_ARTIFACTS,
        A417.A412.ORIGINAL_A401_MEASUREMENTS,
    ):
        production_ranks, _baseline_views, production_metadata = (
            A417.A402.production_rank_matrix()
        )
    production_orders = A417.selected_orders(production_ranks, library, selection)
    roles = tuple(production_orders)
    owners = A417.A414.minimum_rank_owner_lanes(production_orders, roles)
    work = A417.A414.balanced_static_worker_schedule(owners["owner_lane_orders"], roles)
    proof = A417.prove_schedule(owners, work, roles)
    owner_commitment = canonical_sha256(
        {
            "owner_lane_sizes": owners["owner_lane_sizes"],
            "owner_lane_order_uint16be_sha256": owners["owner_lane_order_uint16be_sha256"],
        }
    )
    schedule_commitment = canonical_sha256(
        {
            "worker_task_counts": work["worker_task_counts"],
            "worker_stolen_task_counts": work["worker_stolen_task_counts"],
            "worker_task_list_sha256": work["worker_task_list_sha256"],
            "cell_epoch_one_based": work["cell_epoch_one_based"],
        }
    )
    payload: dict[str, Any] = {
        "schema": "chacha20-round20-w50-selection-calibrated-portfolio-repair-a418-result-v1",
        "attempt_id": ATTEMPT_ID,
        "evidence_stage": (
            "UNTOUCHED_HOLDOUT_QUALIFIED_SELECTION_CALIBRATED_OPTIMAL_SCHEDULER"
            if qualified
            else "UNTOUCHED_HOLDOUT_BOUNDARY_WITH_RETAINED_SELECTION_SIGNAL"
        ),
        "design_sha256": DESIGN_SHA256,
        "implementation_sha256": expected_implementation_sha256,
        "implementation_commitment_sha256": implementation["implementation_commitment_sha256"],
        "A417_implementation_sha256": A417_IMPLEMENTATION_SHA256,
        "A417_library_sha256": A417_LIBRARY_SHA256,
        "A417_selection_sha256": A417_SELECTION_SHA256,
        "A417_selection_commitment_sha256": selection["selection_commitment_sha256"],
        "selection_summary": selection["portfolio_selection"],
        "repair_validation": {
            "identified_lookup": "A414.A414_MODEL_SHA256",
            "explicit_A414_model_sha256": A414_MODEL_SHA256,
            "loaded_A414_model_sha256": file_sha256(A414_MODEL),
            "selection_changed": False,
            "reader_order_changed": False,
            "metric_changed": False,
            "holdout_boundary_changed": False,
        },
        "external_transfer": external,
        "source_role_order": list(roles),
        "source_order_uint16be_sha256": owners["source_order_uint16be_sha256"],
        "owner_lane_orders": owners["owner_lane_orders"],
        "owner_lane_sizes": owners["owner_lane_sizes"],
        "owner_lane_order_uint16be_sha256": owners["owner_lane_order_uint16be_sha256"],
        "worker_tasks": work["worker_tasks"],
        "worker_cell_orders": work["worker_cell_orders"],
        "worker_task_counts": work["worker_task_counts"],
        "worker_stolen_task_counts": work["worker_stolen_task_counts"],
        "worker_cell_order_uint16be_sha256": work["worker_cell_order_uint16be_sha256"],
        "worker_task_list_sha256": work["worker_task_list_sha256"],
        "cell_epoch_one_based": work["cell_epoch_one_based"],
        "cell_worker_role": work["cell_worker_role"],
        "cell_owner_queue_role": work["cell_owner_queue_role"],
        "cell_owner_queue_position_one_based": work["cell_owner_queue_position_one_based"],
        "schedule_proof": proof,
        "production_execution_enabled": qualified,
        "owner_lane_commitment_sha256": owner_commitment,
        "schedule_commitment_sha256": schedule_commitment,
        "production_view_metadata": production_metadata,
        "holdout_field_commitments": field_commitments,
        "holdout_reader_commitments": reader_commitments,
        "A412_selection_fields_used_for_model_selection": 16,
        "A412_selection_labels_used_for_model_selection": 16,
        "A412_holdout_fields_used_for_model_selection": 0,
        "A412_holdout_labels_used_for_model_selection": 0,
        "A412_holdout_fields_used_for_external_evaluation": 16,
        "A412_holdout_labels_used_for_external_evaluation": 16,
        "holdout_reader_refits": 0,
        "production_target_labels_used": 0,
        "production_reader_refits": 0,
        "production_candidate_assignments_executed": 0,
        "live_recovery_filter_outcomes_or_results_consumed": False,
        "anchors": {
            "design": anchor(DESIGN, DESIGN_SHA256),
            "implementation": anchor(IMPLEMENTATION, expected_implementation_sha256),
            "A417_runner": anchor(A417_RUNNER, A417_RUNNER_SHA256),
            "A417_implementation": anchor(A417_IMPLEMENTATION, A417_IMPLEMENTATION_SHA256),
            "A417_library": anchor(A417_LIBRARY, A417_LIBRARY_SHA256),
            "A417_selection": anchor(A417_SELECTION, A417_SELECTION_SHA256),
            "A414_model": anchor(A414_MODEL, A414_MODEL_SHA256),
            "A415_model": anchor(A415_MODEL, A415_MODEL_SHA256),
            "A416_model": anchor(A416_MODEL, A416_MODEL_SHA256),
            "A412_protocol": anchor(A412_PROTOCOL, A412_PROTOCOL_SHA256),
            "runner": anchor(Path(__file__)),
        },
    }
    payload["external_measurement_sha256"] = canonical_sha256(
        {
            "external_transfer": external,
            "holdout_field_commitments": field_commitments,
            "holdout_reader_commitments": reader_commitments,
        }
    )
    payload["deployment_commitment_sha256"] = canonical_sha256(
        {
            "external_transfer": external,
            "owner_lane_commitment_sha256": owner_commitment,
            "schedule_commitment_sha256": schedule_commitment,
            "schedule_proof": proof,
        }
    )
    payload["causal"] = build_causal(payload)
    atomic_json(RESULT, payload)
    atomic_bytes(
        REPORT,
        (
            "# A418 — immutable A417 W50 external closure\n\n"
            f"Evidence stage: **{payload['evidence_stage']}**\n\n"
            "- Repair scope: **one explicit A414 model-hash namespace binding; zero Reader, selection, metric, or boundary changes**\n"
            f"- Selected canonical Readers: **{selection['portfolio_selection']['selected_canonical_indices']}**\n"
            f"- Untouched holdout A418 ranks: **{learned_panel['ranks']}**\n"
            f"- Best matched baseline: **{best_name} {best_panel['ranks']}**\n"
            f"- Holdout improvement factor: **{factor:.9f}**\n"
            f"- Holdout additional bit gain: **{gain:.9f}**\n"
            f"- Owner-lane sizes: **{owners['owner_lane_sizes']}**\n"
            "- Complete cover / duplicates / depth / work violations: **4096 / 0 / 0 / 0**\n"
            "- Makespan: **512 epochs, exact theoretical minimum**\n"
            "- Authentic AI-native Causal readback: **3 explicit + 1 inferred chain**\n"
        ).encode(),
    )
    return payload


def analyze() -> dict[str, Any]:
    load_design()
    selection = A417.load_selection(A417_SELECTION_SHA256)
    payload: dict[str, Any] = {
        "attempt_id": ATTEMPT_ID,
        "design_sha256": DESIGN_SHA256,
        "repair_scope": "explicit immutable A414 model hash binding",
        "A417_selection_sha256": A417_SELECTION_SHA256,
        "selected_canonical_indices": selection["portfolio_selection"]["selected_canonical_indices"],
        "selection_panel": selection["portfolio_selection"]["pointwise_minimum_panel"],
        "implementation_frozen": IMPLEMENTATION.exists(),
        "result_complete": RESULT.exists(),
    }
    if IMPLEMENTATION.exists():
        payload["implementation_sha256"] = file_sha256(IMPLEMENTATION)
        load_implementation(payload["implementation_sha256"])
    if RESULT.exists():
        value = json.loads(RESULT.read_bytes())
        payload["result_sha256"] = file_sha256(RESULT)
        payload["evidence_stage"] = value["evidence_stage"]
        payload["external_transfer"] = value["external_transfer"]
        payload["schedule_proof"] = value["schedule_proof"]
        payload["causal"] = value["causal"]
    return payload


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    action = parser.add_mutually_exclusive_group(required=True)
    action.add_argument("--analyze", action="store_true")
    action.add_argument("--freeze-implementation", action="store_true")
    action.add_argument("--evaluate-external", action="store_true")
    parser.add_argument("--expected-implementation-sha256")
    args = parser.parse_args()
    if args.freeze_implementation:
        payload = freeze_implementation()
    elif args.evaluate_external:
        if not args.expected_implementation_sha256:
            parser.error("--evaluate-external requires --expected-implementation-sha256")
        payload = evaluate_external(
            expected_implementation_sha256=args.expected_implementation_sha256
        )
    else:
        payload = analyze()
    print(json.dumps(payload, indent=2, sort_keys=True), flush=True)


if __name__ == "__main__":
    main()

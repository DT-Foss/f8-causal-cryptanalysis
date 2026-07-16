#!/usr/bin/env python3
"""A427: confidence-conserving 3:1 polarity Reader in the A416 W50 portfolio."""

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

import numpy as np

ROOT = Path(__file__).parents[2]
RESEARCH = ROOT / "research"
CONFIGS = RESEARCH / "configs"
RESULTS = RESEARCH / "results/v1"

DESIGN = CONFIGS / "chacha20_round20_w50_majority_3to1_complete_portfolio_a427_design_v1.json"
IMPLEMENTATION = (
    CONFIGS
    / "chacha20_round20_w50_majority_3to1_complete_portfolio_a427_implementation_v1.json"
)
MODEL = CONFIGS / "chacha20_round20_w50_majority_3to1_complete_portfolio_a427_model_v1.json"
RESULT = RESULTS / "chacha20_round20_w50_majority_3to1_complete_portfolio_a427_v1.json"
CAUSAL = RESULT.with_suffix(".causal")
REPORT = RESULT.with_suffix(".md")
TEST = ROOT / "tests/test_chacha20_round20_w50_majority_3to1_complete_portfolio_a427.py"
REPRO = ROOT / "scripts/reproduce_chacha20_round20_w50_majority_3to1_complete_portfolio_a427.sh"

A416_RUNNER = RESEARCH / "experiments/chacha20_round20_w50_folded_xor_portfolio_a416.py"
A416_MODEL = CONFIGS / "chacha20_round20_w50_folded_xor_portfolio_a416_model_v1.json"
A419_RUNNER = RESEARCH / "experiments/chacha20_round20_w50_majority_polarity_portfolio_a419.py"
A419_MODEL = CONFIGS / "chacha20_round20_w50_majority_polarity_portfolio_a419_model_v1.json"
A412_PROTOCOL = CONFIGS / "chacha20_round20_w50_fresh_hybrid_reader_a412_public_corpus_v1.json"

ATTEMPT_ID = "A427"
DESIGN_SHA256 = "66742ec3b2ff5705826e8344e9fad7befbccfc360c3370b79bf24c643c4ddb39"
A416_RUNNER_SHA256 = "6d4f3e144d4d2c7a689b1b4808537379e96091ca5d106ac4cbc00d20d378ce76"
A416_MODEL_SHA256 = "ed927419a04f39f16ffb2679ff51544a43288821744cf2558cd97e45e45a6c58"
A419_RUNNER_SHA256 = "2553725477539400e19d895384768ea6e6cd4818b232bad3868c01619d0d87c0"
A419_MODEL_SHA256 = "aa68b6c0f9098b445a63822b2e5e7b0a26263eb7073073549c04158911f303c7"
A412_PROTOCOL_SHA256 = "f7859b381d5cf6a5f1a765b4abb44192d3bd73539c681a9a40d8c0a48dd365a2"

CELLS = 4096
WORKERS = 8
PREFERRED_PER_CYCLE = 3
COUNTER_PER_CYCLE = 1
REPLACED_ROLE = "folded_xor_negative_first"
REPLACEMENT_ROLE = "majority_polarity_3to1_complete"
SOURCE_ROLES = (
    REPLACEMENT_ROLE,
    "A413_candidate_123",
    "A413_candidate_035",
    "A413_candidate_100",
    "A413_candidate_153",
    "A413_candidate_091",
    "A413_candidate_049",
    "A413_candidate_144",
)
EXPECTED_A416_SELECTION_RANKS = (
    1912, 703, 2326, 783, 210, 226, 876, 893,
    203, 28, 302, 1542, 35, 537, 1509, 418,
)
EXPECTED_READER_SELECTION_RANKS = (
    1274, 469, 3605, 807, 1070, 1355, 2262, 910,
    135, 18, 787, 1027, 263, 358, 1006, 646,
)
EXPECTED_A427_SELECTION_RANKS = (
    1274, 469, 2326, 783, 210, 226, 876, 893,
    135, 18, 302, 1027, 35, 358, 1006, 418,
)
EXPECTED_ORIENTATION_TRUTH = (1, -1, -1, 1, -1, -1, -1, 1, -1, 1, -1, 1, 1, -1, -1, 1)
EXPECTED_ORIENTATION_PREDICTIONS = (1, -1, 1, 1, -1, -1, -1, 1, -1, 1, -1, 1, 1, -1, -1, 1)
EXPECTED_SELECTION_FACTOR = 1.1970583603289995
EXPECTED_SELECTION_GAIN = 0.25949348987939835
DOTCAUSAL_SRC = Path("/Users/bhkmie/Documents/Forschung/O1/vendor/fabel/dotcausal_package/src")


def load_module(path: Path, name: str) -> Any:
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot import A427 dependency {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


A419 = load_module(A419_RUNNER, "a427_a419")
A416 = A419.A417.A416
A412 = A419.A417.A412
A401 = A416.A401

file_sha256 = A416.file_sha256
canonical_sha256 = A416.canonical_sha256
atomic_json = A416.atomic_json
atomic_bytes = A416.atomic_bytes
relative = A416.relative
anchor = A416.anchor
metric_panel = A416.metric_panel
uint16be_sha256 = A416.uint16be_sha256
exact_order = A416.exact_order


def load_design() -> dict[str, Any]:
    if file_sha256(DESIGN) != DESIGN_SHA256:
        raise RuntimeError("A427 design hash differs")
    value = json.loads(DESIGN.read_bytes())
    mechanism = value.get("mechanism", {})
    boundary = value.get("information_boundary", {})
    if (
        value.get("schema")
        != "chacha20-round20-w50-majority-3to1-complete-portfolio-a427-design-v1"
        or value.get("attempt_id") != ATTEMPT_ID
        or mechanism.get("preferred_tail_cells_per_cycle") != PREFERRED_PER_CYCLE
        or mechanism.get("counter_tail_cells_per_cycle") != COUNTER_PER_CYCLE
        or mechanism.get("replaced_A416_role") != REPLACED_ROLE
        or mechanism.get("replacement_role") != REPLACEMENT_ROLE
        or mechanism.get("total_worker_count") != WORKERS
        or boundary.get("A412_holdout_fields_consumed_by_A427_at_design_freeze") != 0
        or boundary.get("A412_holdout_labels_consumed_by_A427_at_design_freeze") != 0
        or boundary.get("A419_result_used_as_model_source") is not False
    ):
        raise RuntimeError("A427 frozen design semantics differ")
    anchors = value["source_anchors"]
    for key, item in anchors.items():
        if key.endswith("_path"):
            stem = key.removesuffix("_path")
            anchor(ROOT / item, anchors[f"{stem}_sha256"])
    return value


def complete_asymmetric_interleave(
    preferred: Sequence[int], counter: Sequence[int]
) -> list[int]:
    left = exact_order(preferred)
    right = exact_order(counter)
    seen = np.zeros(CELLS, dtype=np.bool_)
    result: list[int] = []
    left_index = 0
    right_index = 0

    def append_unseen(order: Sequence[int], index: int) -> int:
        while index < CELLS and seen[int(order[index])]:
            index += 1
        if index < CELLS:
            cell = int(order[index])
            seen[cell] = True
            result.append(cell)
            index += 1
        return index

    while len(result) < CELLS:
        before = len(result)
        for _ in range(PREFERRED_PER_CYCLE):
            left_index = append_unseen(left, left_index)
            if len(result) == CELLS:
                break
        for _ in range(COUNTER_PER_CYCLE):
            right_index = append_unseen(right, right_index)
            if len(result) == CELLS:
                break
        if len(result) == before:
            raise RuntimeError("A427 interleave stalled before complete coverage")
    return exact_order(result)


def portfolio_orders(
    rank_matrix: np.ndarray,
    a416_model: Mapping[str, Any],
    library: Mapping[str, Any],
) -> tuple[dict[str, list[int]], dict[str, Any]]:
    base = A416.portfolio_orders(rank_matrix, a416_model)
    _tail, metadata, positive, negative = A419.majority_tail(rank_matrix, library)
    decision = int(metadata["majority_decision"])
    preferred, counter = (positive, negative) if decision > 0 else (negative, positive)
    replacement = complete_asymmetric_interleave(preferred, counter)
    orders: dict[str, list[int]] = {REPLACEMENT_ROLE: replacement}
    for role, order in base.items():
        if role != REPLACED_ROLE:
            orders[role] = exact_order(order)
    if tuple(orders) != SOURCE_ROLES or len(orders) != WORKERS:
        raise RuntimeError("A427 portfolio roles differ")
    return orders, {
        **metadata,
        "preferred_tail": "positive" if decision > 0 else "negative",
        "preferred_per_cycle": PREFERRED_PER_CYCLE,
        "counter_per_cycle": COUNTER_PER_CYCLE,
        "replacement_order_uint16be_sha256": uint16be_sha256(replacement),
    }


def derive_selection() -> dict[str, Any]:
    a416_model = A416.load_model(A416_MODEL_SHA256)
    a419_model = json.loads(A419_MODEL.read_bytes())
    if file_sha256(A419_MODEL) != A419_MODEL_SHA256:
        raise RuntimeError("A427 A419 model hash differs")
    evidence = a419_model.get("selection_evidence", {})
    if (
        tuple(evidence.get("orientation_truth", [])) != EXPECTED_ORIENTATION_TRUTH
        or tuple(evidence.get("majority_orientation_predictions", []))
        != EXPECTED_ORIENTATION_PREDICTIONS
        or evidence.get("orientation_correct") != 15
    ):
        raise RuntimeError("A427 frozen A419 selection evidence differs")
    library = A419.A417.load_library(A419.A417_LIBRARY_SHA256)
    protocol = A412.load_protocol(A412_PROTOCOL_SHA256)
    labels = A412.load_label(
        A412.SELECTION_LABELS,
        "chacha20-round20-w50-fresh-hybrid-reader-a412-selection-labels-v1",
        A412.SELECTION_TARGETS,
    )
    base_ranks: list[int] = []
    reader_ranks: list[int] = []
    portfolio_ranks: list[int] = []
    predictions: list[int] = []
    orientations: list[int] = []
    target_commitments: dict[str, Any] = {}
    for target in A412.SELECTION_TARGETS:
        A412.load_fresh_complete(target, protocol)
        rank_matrix, field = A412.fresh_rank_matrix(target)
        cell = int(labels[target]["true_direct12_cell"])
        base = A416.portfolio_orders(rank_matrix, a416_model)
        orders, metadata = portfolio_orders(rank_matrix, a416_model, library)
        _unused, _meta, positive, negative = A419.majority_tail(rank_matrix, library)
        positive_rank = int(A401.rank_vector(positive)[cell])
        negative_rank = int(A401.rank_vector(negative)[cell])
        orientation = 1 if positive_rank < negative_rank else -1
        prediction = int(metadata["majority_decision"])
        base_rank = min(int(A401.rank_vector(order)[cell]) for order in base.values())
        truth_ranks = {
            role: int(A401.rank_vector(order)[cell]) for role, order in orders.items()
        }
        reader_rank = truth_ranks[REPLACEMENT_ROLE]
        portfolio_rank = min(truth_ranks.values())
        base_ranks.append(base_rank)
        reader_ranks.append(reader_rank)
        portfolio_ranks.append(portfolio_rank)
        predictions.append(prediction)
        orientations.append(orientation)
        target_commitments[str(target)] = {
            "field": field,
            "true_cell": cell,
            "orientation_truth": orientation,
            "orientation_prediction": prediction,
            "A416_rank": base_rank,
            "A427_reader_rank": reader_rank,
            "A427_portfolio_rank": portfolio_rank,
            "A427_order_uint16be_sha256": {
                role: uint16be_sha256(order) for role, order in orders.items()
            },
            "polarity": metadata,
        }
    if (
        tuple(base_ranks) != EXPECTED_A416_SELECTION_RANKS
        or tuple(reader_ranks) != EXPECTED_READER_SELECTION_RANKS
        or tuple(portfolio_ranks) != EXPECTED_A427_SELECTION_RANKS
        or tuple(predictions) != EXPECTED_ORIENTATION_PREDICTIONS
        or tuple(orientations) != EXPECTED_ORIENTATION_TRUTH
    ):
        raise RuntimeError("A427 selection panel differs")
    base_panel = metric_panel(base_ranks)
    reader_panel = metric_panel(reader_ranks)
    portfolio_panel = metric_panel(portfolio_ranks)
    factor = base_panel["geometric_mean_rank"] / portfolio_panel["geometric_mean_rank"]
    gain = math.log2(factor)
    if not math.isclose(factor, EXPECTED_SELECTION_FACTOR) or not math.isclose(
        gain, EXPECTED_SELECTION_GAIN
    ):
        raise RuntimeError("A427 selection improvement differs")
    return {
        "orientation_truth": orientations,
        "orientation_predictions": predictions,
        "orientation_correct": sum(
            left == right for left, right in zip(orientations, predictions, strict=True)
        ),
        "A416_panel": base_panel,
        "A427_complete_reader_panel": reader_panel,
        "A427_eight_reader_portfolio_panel": portfolio_panel,
        "geometric_rank_improvement_factor_vs_A416": factor,
        "additional_bit_gain_vs_A416": gain,
        "target_commitments": target_commitments,
    }


def freeze_implementation() -> dict[str, Any]:
    if any(path.exists() for path in (IMPLEMENTATION, MODEL, RESULT, CAUSAL, REPORT)):
        raise FileExistsError("A427 implementation or downstream artifact already exists")
    load_design()
    if not TEST.exists() or not REPRO.exists():
        raise FileNotFoundError("A427 test and reproducer must precede implementation freeze")
    payload: dict[str, Any] = {
        "schema": "chacha20-round20-w50-majority-3to1-complete-portfolio-a427-implementation-v1",
        "attempt_id": ATTEMPT_ID,
        "commitment_state": "frozen_after_selection_only_derivation_before_any_A427_holdout_field_label_or_score",
        "design_sha256": DESIGN_SHA256,
        "preferred_per_cycle": PREFERRED_PER_CYCLE,
        "counter_per_cycle": COUNTER_PER_CYCLE,
        "source_roles": list(SOURCE_ROLES),
        "A412_selection_fields_used": 16,
        "A412_selection_labels_used": 16,
        "A412_holdout_fields_used": 0,
        "A412_holdout_labels_used": 0,
        "anchors": {
            "design": anchor(DESIGN, DESIGN_SHA256),
            "A416_runner": anchor(A416_RUNNER, A416_RUNNER_SHA256),
            "A416_model": anchor(A416_MODEL, A416_MODEL_SHA256),
            "A419_runner": anchor(A419_RUNNER, A419_RUNNER_SHA256),
            "A419_model": anchor(A419_MODEL, A419_MODEL_SHA256),
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
        raise RuntimeError("A427 implementation hash differs")
    value = json.loads(IMPLEMENTATION.read_bytes())
    if (
        value.get("schema")
        != "chacha20-round20-w50-majority-3to1-complete-portfolio-a427-implementation-v1"
        or value.get("attempt_id") != ATTEMPT_ID
        or value.get("preferred_per_cycle") != PREFERRED_PER_CYCLE
        or value.get("counter_per_cycle") != COUNTER_PER_CYCLE
        or tuple(value.get("source_roles", [])) != SOURCE_ROLES
        or value.get("A412_holdout_fields_used") != 0
        or value.get("A412_holdout_labels_used") != 0
    ):
        raise RuntimeError("A427 implementation semantics differ")
    for row in value["anchors"].values():
        anchor(ROOT / row["path"], row["sha256"])
    unsigned = {
        key: item for key, item in value.items() if key != "implementation_commitment_sha256"
    }
    if value.get("implementation_commitment_sha256") != canonical_sha256(unsigned):
        raise RuntimeError("A427 implementation commitment differs")
    return value


def freeze_model(*, expected_implementation_sha256: str) -> dict[str, Any]:
    if any(path.exists() for path in (MODEL, RESULT, CAUSAL, REPORT)):
        raise FileExistsError("A427 model or downstream artifact already exists")
    implementation = load_implementation(expected_implementation_sha256)
    selection = derive_selection()
    payload: dict[str, Any] = {
        "schema": "chacha20-round20-w50-majority-3to1-complete-portfolio-a427-model-v1",
        "attempt_id": ATTEMPT_ID,
        "model_state": "selection_only_frozen_before_any_A427_holdout_field_label_or_score",
        "design_sha256": DESIGN_SHA256,
        "implementation_sha256": expected_implementation_sha256,
        "implementation_commitment_sha256": implementation[
            "implementation_commitment_sha256"
        ],
        "preferred_per_cycle": PREFERRED_PER_CYCLE,
        "counter_per_cycle": COUNTER_PER_CYCLE,
        "source_roles": list(SOURCE_ROLES),
        "selection_evidence": selection,
        "A412_selection_fields_used": 16,
        "A412_selection_labels_used": 16,
        "A412_holdout_fields_used": 0,
        "A412_holdout_labels_used": 0,
        "holdout_model_choices": 0,
        "holdout_reader_refits": 0,
        "anchors": {
            "design": anchor(DESIGN, DESIGN_SHA256),
            "implementation": anchor(IMPLEMENTATION, expected_implementation_sha256),
            "A416_model": anchor(A416_MODEL, A416_MODEL_SHA256),
            "A419_model": anchor(A419_MODEL, A419_MODEL_SHA256),
            "A412_protocol": anchor(A412_PROTOCOL, A412_PROTOCOL_SHA256),
            "runner": anchor(Path(__file__)),
        },
    }
    payload["model_commitment_sha256"] = canonical_sha256(payload)
    atomic_json(MODEL, payload)
    return payload


def load_model(expected_sha256: str | None = None) -> dict[str, Any]:
    if expected_sha256 is not None and file_sha256(MODEL) != expected_sha256:
        raise RuntimeError("A427 model hash differs")
    value = json.loads(MODEL.read_bytes())
    selection = value.get("selection_evidence", {})
    if (
        value.get("schema")
        != "chacha20-round20-w50-majority-3to1-complete-portfolio-a427-model-v1"
        or value.get("attempt_id") != ATTEMPT_ID
        or value.get("preferred_per_cycle") != PREFERRED_PER_CYCLE
        or value.get("counter_per_cycle") != COUNTER_PER_CYCLE
        or tuple(value.get("source_roles", [])) != SOURCE_ROLES
        or tuple(selection.get("A427_eight_reader_portfolio_panel", {}).get("ranks", []))
        != EXPECTED_A427_SELECTION_RANKS
        or value.get("A412_holdout_fields_used") != 0
        or value.get("A412_holdout_labels_used") != 0
    ):
        raise RuntimeError("A427 model semantics differ")
    load_implementation(value["implementation_sha256"])
    unsigned = {key: item for key, item in value.items() if key != "model_commitment_sha256"}
    if value.get("model_commitment_sha256") != canonical_sha256(unsigned):
        raise RuntimeError("A427 model commitment differs")
    return value


def build_causal(payload: Mapping[str, Any]) -> dict[str, Any]:
    sys.path.insert(0, str(DOTCAUSAL_SRC))
    from dotcausal.io import CausalReader, CausalWriter

    qualified = bool(payload["external_transfer"]["qualified"])
    terminal = (
        "A427_external_panel_qualified_complete_asymmetric_scheduler"
        if qualified
        else "A427_external_boundary_complete_asymmetric_reader"
    )
    writer = CausalWriter(api_id="a427w50")
    writer._rules = []
    writer.add_rule(
        name="majority_vote_to_complete_asymmetric_read",
        description="Use the frozen A419 public-field vote to consume three cells from the preferred XOR tail and one from the counter-tail, with first-occurrence deduplication until all cells are covered.",
        pattern=["A419_frozen_majority_vote", "A415_dual_XOR_tails"],
        conclusion="A427_complete_3to1_reader",
        confidence_modifier=1.0,
    )
    writer.add_rule(
        name="complete_asymmetric_read_to_equal_worker_portfolio",
        description="Replace only A416's balanced folded Reader and retain its seven frozen geometric Readers at the same eight-worker count.",
        pattern=["A427_complete_3to1_reader", "A416_seven_retained_readers"],
        conclusion="A427_fixed_eight_reader_portfolio",
        confidence_modifier=1.0,
    )
    writer.add_rule(
        name="selection_freeze_to_external_transfer",
        description="Freeze the ratio and voter before consuming any A427 external-panel field, label, or score, then compare against exact A416 at equal worker count.",
        pattern=["A427_selection_only_freeze", "A412_external_panel"],
        conclusion=terminal,
        confidence_modifier=1.0,
    )
    writer.add_triplet(
        trigger="A419:selection_majority_polarity_signal",
        mechanism="three_to_one_preferred_tail_with_exact_counter_tail_retention",
        outcome="A427:complete_asymmetric_polarity_reader",
        confidence=1.0,
        source=payload["model_sha256"],
        quantification=json.dumps(payload["selection_evidence"], sort_keys=True),
        evidence="15/16 selection orientation plus exact 4096-cell permutation and bounded counter-tail delay",
        domain="full-round ChaCha20 W50 public-field scheduling",
        quality_score=1.0,
    )
    writer.add_triplet(
        trigger="A427:complete_asymmetric_polarity_reader",
        mechanism="equal_worker_external_panel_transfer_and_exact_scheduler",
        outcome=f"A427:{terminal}",
        confidence=1.0,
        source=payload["external_measurement_sha256"],
        quantification=json.dumps(payload["external_transfer"], sort_keys=True),
        evidence="fixed 3:1 ratio, fixed voters, zero external refits or model choices",
        domain="full-round ChaCha20 W50 recovery scheduling",
        quality_score=1.0,
    )
    writer.add_triplet(
        trigger="A419:selection_majority_polarity_signal",
        mechanism="materialized_complete_asymmetric_transfer_chain",
        outcome=f"A427:{terminal}",
        confidence=1.0,
        source="materialized:A427_complete_asymmetric_chain",
        quantification="exact retained closure",
        evidence="design, model, external comparison, and scheduler commitments",
        domain="AI-native retained inference",
        quality_score=1.0,
        is_inferred=True,
    )
    writer.add_cluster(
        name="A427 confidence-conserving polarity scheduler",
        entities=[
            "A419:selection_majority_polarity_signal",
            "A427:complete_asymmetric_polarity_reader",
            f"A427:{terminal}",
        ],
    )
    writer.add_gap(
        subject=f"A427:{terminal}",
        predicate="next_required_object",
        expected_object_type=(
            "fresh_production_recovery_execution" if qualified else "new_disjoint_confirmation_panel"
        ),
        confidence=1.0,
        suggested_queries=[
            "Execute the exact A427 schedule on a fresh sealed W50 challenge."
            if qualified
            else "Measure the complete asymmetric Reader on a new disjoint key panel."
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
        reader.api_id != "a427w50"
        or len(explicit) != 2
        or len(all_rows) != 3
        or len(inferred) != 1
        or len(reader._rules) != 3
        or len(reader._clusters) != 1
        or len(reader._gaps) != 1
    ):
        raise RuntimeError("A427 authentic Causal reopen gate failed")
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
            "complete_reader": explicit[0],
            "external_transfer": explicit[1],
            "terminal_chain": all_rows[-1],
            "next_gap": reader._gaps[0],
        },
    }


def evaluate_external(
    *, expected_implementation_sha256: str, expected_model_sha256: str
) -> dict[str, Any]:
    if RESULT.exists() or CAUSAL.exists() or REPORT.exists():
        raise FileExistsError("A427 result already exists")
    implementation = load_implementation(expected_implementation_sha256)
    model = load_model(expected_model_sha256)
    a416_model = A416.load_model(A416_MODEL_SHA256)
    library = A419.A417.load_library(A419.A417_LIBRARY_SHA256)
    protocol = A412.load_protocol(A412_PROTOCOL_SHA256)
    labels = A412.load_label(
        A412.HOLDOUT_LABELS,
        "chacha20-round20-w50-fresh-hybrid-reader-a412-holdout-labels-v1",
        A412.HOLDOUT_TARGETS,
    )
    a427_ranks: list[int] = []
    a416_ranks: list[int] = []
    orientation_truth: list[int] = []
    orientation_predictions: list[int] = []
    field_commitments: dict[str, Any] = {}
    reader_commitments: dict[str, Any] = {}
    for target in A412.HOLDOUT_TARGETS:
        A412.load_fresh_complete(target, protocol)
        rank_matrix, field_commitments[str(target)] = A412.fresh_rank_matrix(target)
        cell = int(labels[target]["true_direct12_cell"])
        base = A416.portfolio_orders(rank_matrix, a416_model)
        orders, metadata = portfolio_orders(rank_matrix, a416_model, library)
        _unused, _meta, positive, negative = A419.majority_tail(rank_matrix, library)
        positive_rank = int(A401.rank_vector(positive)[cell])
        negative_rank = int(A401.rank_vector(negative)[cell])
        truth = 1 if positive_rank < negative_rank else -1
        prediction = int(metadata["majority_decision"])
        base_truth = {role: int(A401.rank_vector(order)[cell]) for role, order in base.items()}
        a427_truth = {
            role: int(A401.rank_vector(order)[cell]) for role, order in orders.items()
        }
        a416_ranks.append(min(base_truth.values()))
        a427_ranks.append(min(a427_truth.values()))
        orientation_truth.append(truth)
        orientation_predictions.append(prediction)
        reader_commitments[str(target)] = {
            "true_cell": cell,
            "orientation_truth": truth,
            "orientation_prediction": prediction,
            "A416_true_ranks": base_truth,
            "A427_true_ranks": a427_truth,
            "A427_order_uint16be_sha256": {
                role: uint16be_sha256(order) for role, order in orders.items()
            },
            "polarity": metadata,
        }
        print(f"A427 external target {target}/31 complete", flush=True)
    a427_panel = metric_panel(a427_ranks)
    a416_panel = metric_panel(a416_ranks)
    factor = a416_panel["geometric_mean_rank"] / a427_panel["geometric_mean_rank"]
    gain = math.log2(factor)
    qualified = factor > 1.0 and gain > 0.0
    external = {
        "qualified": qualified,
        "primary_A427_panel": a427_panel,
        "matched_A416_panel": a416_panel,
        "geometric_rank_improvement_factor_vs_A416": factor,
        "additional_bit_gain_vs_A416": gain,
        "orientation_truth": orientation_truth,
        "orientation_predictions": orientation_predictions,
        "orientation_correct": sum(
            left == right
            for left, right in zip(orientation_truth, orientation_predictions, strict=True)
        ),
        "equal_worker_count": WORKERS,
        "external_model_choices": 0,
        "external_reader_refits": 0,
        "target_specific_polarity_labels_used": 0,
        "new_solver_stages": 0,
    }
    with A412.a401_paths(A412.ORIGINAL_A401_ARTIFACTS, A412.ORIGINAL_A401_MEASUREMENTS):
        production_ranks, _views, production_metadata = A416.A402.production_rank_matrix()
    production_orders, production_polarity = portfolio_orders(
        production_ranks, a416_model, library
    )
    owners = A416.A414.minimum_rank_owner_lanes(production_orders, SOURCE_ROLES)
    work = A416.A414.balanced_static_worker_schedule(
        owners["owner_lane_orders"], SOURCE_ROLES
    )
    proof = A416.A415.prove_schedule(owners, work, SOURCE_ROLES)
    payload: dict[str, Any] = {
        "schema": "chacha20-round20-w50-majority-3to1-complete-portfolio-a427-result-v1",
        "attempt_id": ATTEMPT_ID,
        "evidence_stage": (
            "EXTERNAL_PANEL_QUALIFIED_COMPLETE_ASYMMETRIC_SCHEDULER"
            if qualified
            else "EXTERNAL_BOUNDARY_COMPLETE_ASYMMETRIC_READER"
        ),
        "design_sha256": DESIGN_SHA256,
        "implementation_sha256": expected_implementation_sha256,
        "implementation_commitment_sha256": implementation[
            "implementation_commitment_sha256"
        ],
        "model_sha256": expected_model_sha256,
        "model_commitment_sha256": model["model_commitment_sha256"],
        "selection_evidence": model["selection_evidence"],
        "external_transfer": external,
        "source_role_order": list(SOURCE_ROLES),
        "owner_lane_orders": owners["owner_lane_orders"],
        "owner_lane_sizes": owners["owner_lane_sizes"],
        "worker_tasks": work["worker_tasks"],
        "worker_cell_orders": work["worker_cell_orders"],
        "worker_task_counts": work["worker_task_counts"],
        "worker_stolen_task_counts": work["worker_stolen_task_counts"],
        "cell_epoch_one_based": work["cell_epoch_one_based"],
        "cell_worker_role": work["cell_worker_role"],
        "cell_owner_queue_role": work["cell_owner_queue_role"],
        "cell_owner_queue_position_one_based": work[
            "cell_owner_queue_position_one_based"
        ],
        "schedule_proof": proof,
        "production_execution_enabled": qualified,
        "production_polarity_metadata": production_polarity,
        "owner_lane_commitment_sha256": canonical_sha256(
            {
                "sizes": owners["owner_lane_sizes"],
                "orders": owners["owner_lane_order_uint16be_sha256"],
            }
        ),
        "schedule_commitment_sha256": canonical_sha256(
            {
                "tasks": work["worker_task_list_sha256"],
                "epochs": work["cell_epoch_one_based"],
            }
        ),
        "production_view_metadata": production_metadata,
        "external_field_commitments": field_commitments,
        "external_reader_commitments": reader_commitments,
        "external_targets": len(A412.HOLDOUT_TARGETS),
        "external_target_labels_used_for_model_selection": 0,
        "external_reader_refits": 0,
        "production_target_labels_used": 0,
        "production_candidate_assignments_executed": 0,
        "anchors": {
            "design": anchor(DESIGN, DESIGN_SHA256),
            "implementation": anchor(IMPLEMENTATION, expected_implementation_sha256),
            "model": anchor(MODEL, expected_model_sha256),
            "A416_model": anchor(A416_MODEL, A416_MODEL_SHA256),
            "A419_model": anchor(A419_MODEL, A419_MODEL_SHA256),
            "A412_protocol": anchor(A412_PROTOCOL, A412_PROTOCOL_SHA256),
            "runner": anchor(Path(__file__)),
        },
    }
    payload["external_measurement_sha256"] = canonical_sha256(
        {
            "external_transfer": external,
            "external_field_commitments": field_commitments,
            "external_reader_commitments": reader_commitments,
        }
    )
    payload["causal"] = build_causal(payload)
    atomic_json(RESULT, payload)
    atomic_bytes(
        REPORT,
        (
            "# A427 — confidence-conserving 3:1 polarity scheduler\n\n"
            f"Evidence stage: **{payload['evidence_stage']}**\n\n"
            f"- Selection A416 ranks: **{list(EXPECTED_A416_SELECTION_RANKS)}**\n"
            f"- Selection A427 ranks: **{list(EXPECTED_A427_SELECTION_RANKS)}**\n"
            f"- Selection factor: **{EXPECTED_SELECTION_FACTOR:.9f}**\n"
            f"- External A427 ranks: **{a427_panel['ranks']}**\n"
            f"- Matched external A416 ranks: **{a416_panel['ranks']}**\n"
            f"- External factor: **{factor:.9f}**\n"
            f"- External additional bit gain: **{gain:.9f}**\n"
            f"- External polarity accuracy: **{external['orientation_correct']}/16**\n"
            "- Complete schedule: **4,096 cells, zero duplicates, eight workers**\n"
            "- Authentic AI-native Causal readback: **2 explicit + 1 inferred chain**\n"
        ).encode(),
    )
    return payload


def analyze() -> dict[str, Any]:
    payload: dict[str, Any] = {
        "attempt_id": ATTEMPT_ID,
        "design_sha256": DESIGN_SHA256,
        "implementation_frozen": IMPLEMENTATION.exists(),
        "model_frozen": MODEL.exists(),
        "result_complete": RESULT.exists(),
    }
    if IMPLEMENTATION.exists():
        payload["implementation_sha256"] = file_sha256(IMPLEMENTATION)
    if MODEL.exists():
        payload["model_sha256"] = file_sha256(MODEL)
        payload["selection_evidence"] = load_model()["selection_evidence"]
    if RESULT.exists():
        result = json.loads(RESULT.read_bytes())
        payload["result_sha256"] = file_sha256(RESULT)
        payload["evidence_stage"] = result["evidence_stage"]
        payload["external_transfer"] = result["external_transfer"]
    return payload


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    action = parser.add_mutually_exclusive_group(required=True)
    action.add_argument("--freeze-implementation", action="store_true")
    action.add_argument("--freeze-model", action="store_true")
    action.add_argument("--evaluate", action="store_true")
    action.add_argument("--analyze", action="store_true")
    parser.add_argument("--expected-implementation-sha256")
    parser.add_argument("--expected-model-sha256")
    args = parser.parse_args()
    if args.freeze_implementation:
        payload = freeze_implementation()
    elif args.freeze_model:
        if not args.expected_implementation_sha256:
            parser.error("--freeze-model requires --expected-implementation-sha256")
        payload = freeze_model(
            expected_implementation_sha256=args.expected_implementation_sha256
        )
    elif args.evaluate:
        if not args.expected_implementation_sha256 or not args.expected_model_sha256:
            parser.error("--evaluate requires both expected hashes")
        payload = evaluate_external(
            expected_implementation_sha256=args.expected_implementation_sha256,
            expected_model_sha256=args.expected_model_sha256,
        )
    else:
        payload = analyze()
    print(json.dumps(payload, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""A419: three-pilot majority-polarity replacement in the A417 W50 portfolio."""

from __future__ import annotations

import argparse
import importlib.util
import inspect
import json
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

DESIGN = CONFIGS / "chacha20_round20_w50_majority_polarity_portfolio_a419_design_v1.json"
IMPLEMENTATION = CONFIGS / "chacha20_round20_w50_majority_polarity_portfolio_a419_implementation_v1.json"
MODEL = CONFIGS / "chacha20_round20_w50_majority_polarity_portfolio_a419_model_v1.json"
RESULT = RESULTS / "chacha20_round20_w50_majority_polarity_portfolio_a419_v1.json"
CAUSAL = RESULT.with_suffix(".causal")
REPORT = RESULT.with_suffix(".md")
TEST = ROOT / "tests/test_chacha20_round20_w50_majority_polarity_portfolio_a419.py"
REPRO = ROOT / "scripts/reproduce_chacha20_round20_w50_majority_polarity_portfolio_a419.sh"

A417_RUNNER = RESEARCH / "experiments/chacha20_round20_w50_selection_calibrated_portfolio_a417.py"
A417_IMPLEMENTATION = CONFIGS / "chacha20_round20_w50_selection_calibrated_portfolio_a417_implementation_v1.json"
A417_LIBRARY = CONFIGS / "chacha20_round20_w50_selection_calibrated_portfolio_a417_library_v1.json"
A417_SELECTION = CONFIGS / "chacha20_round20_w50_selection_calibrated_portfolio_a417_selection_v1.json"
A414_MODEL = CONFIGS / "chacha20_round20_w50_knownkey_parallel_portfolio_a414_model_v1.json"
A415_MODEL = CONFIGS / "chacha20_round20_w50_xor_landscape_portfolio_a415_model_v1.json"
A416_MODEL = CONFIGS / "chacha20_round20_w50_folded_xor_portfolio_a416_model_v1.json"
A412_PROTOCOL = CONFIGS / "chacha20_round20_w50_fresh_hybrid_reader_a412_public_corpus_v1.json"

ATTEMPT_ID = "A419"
DESIGN_SHA256 = "d57e1b16eb917bcb0e755075a4a0405ab67fadbf2205ece5b87dc8b5c52344b4"
A417_RUNNER_SHA256 = "dcdb1999b9521b104b3a321da4c42c0e2e7678b53e0adec82af1f3c8d1cfde85"
A417_IMPLEMENTATION_SHA256 = "2f9279f8e1b0edd03353ecb864f47e4c56db6e98a2ced09baa039a87156175d7"
A417_LIBRARY_SHA256 = "53d142b8351a990e06a0e265581320a0df871f59bcc493e3e5ea0f961c391253"
A417_SELECTION_SHA256 = "dde2e8a9ec184e52ed353f33b7558f43c767cb8deece715caceffe6910922653"
A414_MODEL_SHA256 = "1e65ef99e4a49861ffcfe5e6f30ec3018516e7d91bbdb2a2539980efcaba6f0b"
A415_MODEL_SHA256 = "ed7d9e8b44c9dee4fecdb4d59de6a67911c3ed4fc0a0fdb09d7e17885e78e110"
A416_MODEL_SHA256 = "ed927419a04f39f16ffb2679ff51544a43288821744cf2558cd97e45e45a6c58"
A412_PROTOCOL_SHA256 = "f7859b381d5cf6a5f1a765b4abb44192d3bd73539c681a9a40d8c0a48dd365a2"

VOTERS = (
    (11, 32, "uniform"),
    (19, 32, "uniform"),
    (63, 128, "uniform"),
)
REPLACED_ROLE = "A417_candidate_0388"
REPLACEMENT_ROLE = "A419_majority_polarity_11_19_63"
EXPECTED_SOURCE_RANKS = (
    956, 352, 2704, 606, 803, 1017, 1697, 683,
    102, 14, 591, 3326, 198, 269, 755, 485,
)
EXPECTED_MAJORITY_RANKS = (
    956, 352, 2704, 606, 803, 1017, 1697, 683,
    102, 14, 591, 771, 198, 269, 755, 485,
)
EXPECTED_PORTFOLIO_RANKS = (
    956, 352, 1393, 606, 211, 45, 149, 683,
    50, 6, 274, 771, 25, 269, 755, 385,
)
EXPECTED_ORIENTATION = (1, -1, -1, 1, -1, -1, -1, 1, -1, 1, -1, 1, 1, -1, -1, 1)
EXPECTED_PREDICTIONS = (1, -1, 1, 1, -1, -1, -1, 1, -1, 1, -1, 1, 1, -1, -1, 1)
CELLS = 4096
WORKERS = 8
DOTCAUSAL_SRC = Path("/Users/bhkmie/Documents/Forschung/O1/vendor/fabel/dotcausal_package/src")


def load_module(path: Path, name: str) -> Any:
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot import A419 dependency {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


A417 = load_module(A417_RUNNER, "a419_a417")
file_sha256 = A417.file_sha256
canonical_sha256 = A417.canonical_sha256
atomic_json = A417.atomic_json
atomic_bytes = A417.atomic_bytes
relative = A417.relative
anchor = A417.anchor
sha256 = A417.sha256
uint16be_sha256 = A417.uint16be_sha256
metric_panel = A417.metric_panel
exact_order = A417.exact_order


def load_design() -> dict[str, Any]:
    if file_sha256(DESIGN) != DESIGN_SHA256:
        raise RuntimeError("A419 design hash differs")
    value = json.loads(DESIGN.read_bytes())
    mechanism = value.get("mechanism", {})
    boundary = value.get("information_boundary", {})
    voters = tuple(
        (int(row["pilot_index"]), int(row["top_k"]), str(row["weight_family"]))
        for row in mechanism.get("voters", [])
    )
    if (
        value.get("schema")
        != "chacha20-round20-w50-majority-polarity-portfolio-a419-design-v1"
        or value.get("attempt_id") != ATTEMPT_ID
        or voters != VOTERS
        or mechanism.get("tie_possible") is not False
        or mechanism.get("target_specific_labels_used") is not False
        or boundary.get("A412_holdout_fields_used_at_design_freeze") != 0
        or boundary.get("A412_holdout_labels_used_at_design_freeze") != 0
    ):
        raise RuntimeError("A419 frozen design semantics differ")
    anchors = value["source_anchors"]
    for key, item in anchors.items():
        if key.endswith("_path"):
            stem = key.removesuffix("_path")
            anchor(ROOT / item, anchors[f"{stem}_sha256"])
    return value


def majority_sign(statistics: Sequence[float]) -> int:
    values = tuple(float(value) for value in statistics)
    if len(values) != 3 or not np.isfinite(values).all():
        raise ValueError("A419 majority requires three finite voter statistics")
    return 1 if sum(value >= 0.0 for value in values) >= 2 else -1


def majority_tail(
    rank_matrix: np.ndarray, library: Mapping[str, Any]
) -> tuple[list[int], dict[str, Any], list[int], list[int]]:
    scores, positive, negative, _folded = A417.landscape_orders(rank_matrix, library)
    pilots = sorted({pilot for pilot, _top_k, _family in VOTERS})
    orders, _ranks = A417.pilot_orders(rank_matrix, library, pilots)
    statistics: list[float] = []
    top_commitments: list[dict[str, Any]] = []
    for pilot, top_k, family in VOTERS:
        top = np.asarray(orders[pilot][:top_k], dtype=np.int64)
        statistic = float(
            np.dot(scores[top], A417.polarity_weights(top_k, family))
        )
        statistics.append(statistic)
        top_commitments.append(
            {
                "pilot_index": pilot,
                "top_k": top_k,
                "weight_family": family,
                "pilot_top_order_uint16be_sha256": uint16be_sha256(top.tolist()),
                "statistic": statistic,
                "vote": 1 if statistic >= 0.0 else -1,
            }
        )
    decision = majority_sign(statistics)
    order = positive if decision > 0 else negative
    return exact_order(order), {
        "voters": top_commitments,
        "majority_decision": decision,
        "positive_order_uint16be_sha256": uint16be_sha256(positive),
        "negative_order_uint16be_sha256": uint16be_sha256(negative),
        "selected_order_uint16be_sha256": uint16be_sha256(order),
    }, positive, negative


def replace_reader(
    source: Mapping[str, Sequence[int]], replacement: Sequence[int]
) -> dict[str, list[int]]:
    if REPLACED_ROLE not in source or len(source) != WORKERS:
        raise RuntimeError("A419 source portfolio differs")
    result: dict[str, list[int]] = {}
    for role, order in source.items():
        if role == REPLACED_ROLE:
            result[REPLACEMENT_ROLE] = exact_order(replacement)
        else:
            result[str(role)] = exact_order(order)
    if len(result) != WORKERS or REPLACEMENT_ROLE not in result:
        raise RuntimeError("A419 replacement portfolio differs")
    return result


def portfolio_orders(
    rank_matrix: np.ndarray,
    library: Mapping[str, Any],
    selection: Mapping[str, Any],
) -> tuple[dict[str, list[int]], dict[str, Any]]:
    source = A417.selected_orders(rank_matrix, library, selection)
    replacement, metadata, _positive, _negative = majority_tail(rank_matrix, library)
    return replace_reader(source, replacement), metadata


def freeze_implementation() -> dict[str, Any]:
    if any(path.exists() for path in (IMPLEMENTATION, MODEL, RESULT, CAUSAL, REPORT)):
        raise FileExistsError("A419 implementation or downstream artifact already exists")
    load_design()
    if not TEST.exists() or not REPRO.exists():
        raise FileNotFoundError("A419 test and reproducer must precede implementation freeze")
    selection = A417.load_selection(A417_SELECTION_SHA256)
    payload: dict[str, Any] = {
        "schema": "chacha20-round20-w50-majority-polarity-portfolio-a419-implementation-v1",
        "attempt_id": ATTEMPT_ID,
        "commitment_state": "frozen_before_any_A419_A412_holdout_field_label_or_score",
        "design_sha256": DESIGN_SHA256,
        "voters": [list(row) for row in VOTERS],
        "replaced_role": REPLACED_ROLE,
        "replacement_role": REPLACEMENT_ROLE,
        "A417_selected_canonical_indices": selection["portfolio_selection"]["selected_canonical_indices"],
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
        raise RuntimeError("A419 implementation hash differs")
    value = json.loads(IMPLEMENTATION.read_bytes())
    if (
        value.get("schema")
        != "chacha20-round20-w50-majority-polarity-portfolio-a419-implementation-v1"
        or value.get("attempt_id") != ATTEMPT_ID
        or tuple(tuple(row) for row in value.get("voters", [])) != VOTERS
        or value.get("replaced_role") != REPLACED_ROLE
        or value.get("replacement_role") != REPLACEMENT_ROLE
        or value.get("A412_holdout_fields_used") != 0
        or value.get("A412_holdout_labels_used") != 0
    ):
        raise RuntimeError("A419 implementation semantics differ")
    for row in value["anchors"].values():
        anchor(ROOT / row["path"], row["sha256"])
    unsigned = {
        key: item for key, item in value.items() if key != "implementation_commitment_sha256"
    }
    if value.get("implementation_commitment_sha256") != canonical_sha256(unsigned):
        raise RuntimeError("A419 implementation commitment differs")
    return value


def derive_selection() -> dict[str, Any]:
    library = A417.load_library(A417_LIBRARY_SHA256)
    selection = A417.load_selection(A417_SELECTION_SHA256)
    protocol = A417.A412.load_protocol(A412_PROTOCOL_SHA256)
    labels = A417.A412.load_label(
        A417.A412.SELECTION_LABELS,
        "chacha20-round20-w50-fresh-hybrid-reader-a412-selection-labels-v1",
        A417.A412.SELECTION_TARGETS,
    )
    source_ranks: list[int] = []
    majority_ranks: list[int] = []
    portfolio_ranks: list[int] = []
    orientations: list[int] = []
    predictions: list[int] = []
    target_commitments: dict[str, Any] = {}
    for target in A417.A412.SELECTION_TARGETS:
        A417.A412.load_fresh_complete(target, protocol)
        rank_matrix, field = A417.A412.fresh_rank_matrix(target)
        cell = int(labels[target]["true_direct12_cell"])
        source = A417.selected_orders(rank_matrix, library, selection)
        replacement, metadata, positive, negative = majority_tail(rank_matrix, library)
        portfolio = replace_reader(source, replacement)
        source_rank = int(A417.A401.rank_vector(source[REPLACED_ROLE])[cell])
        majority_rank = int(A417.A401.rank_vector(replacement)[cell])
        positive_rank = int(A417.A401.rank_vector(positive)[cell])
        negative_rank = int(A417.A401.rank_vector(negative)[cell])
        ranks = {
            role: int(A417.A401.rank_vector(order)[cell])
            for role, order in portfolio.items()
        }
        source_ranks.append(source_rank)
        majority_ranks.append(majority_rank)
        portfolio_ranks.append(min(ranks.values()))
        orientations.append(1 if positive_rank <= negative_rank else -1)
        predictions.append(int(metadata["majority_decision"]))
        target_commitments[str(target)] = {
            "field": field,
            "true_cell": cell,
            "positive_rank": positive_rank,
            "negative_rank": negative_rank,
            "source_rank": source_rank,
            "majority_rank": majority_rank,
            "portfolio_true_ranks": ranks,
            "majority": metadata,
        }
        print(f"A419 selection target {target}/15 complete", flush=True)
    if (
        tuple(source_ranks) != EXPECTED_SOURCE_RANKS
        or tuple(majority_ranks) != EXPECTED_MAJORITY_RANKS
        or tuple(portfolio_ranks) != EXPECTED_PORTFOLIO_RANKS
        or tuple(orientations) != EXPECTED_ORIENTATION
        or tuple(predictions) != EXPECTED_PREDICTIONS
    ):
        raise RuntimeError("A419 selection contract differs")
    return {
        "source_candidate_388_panel": metric_panel(source_ranks),
        "majority_reader_panel": metric_panel(majority_ranks),
        "eight_reader_portfolio_panel": metric_panel(portfolio_ranks),
        "orientation_truth": orientations,
        "majority_orientation_predictions": predictions,
        "orientation_correct": sum(
            left == right for left, right in zip(orientations, predictions, strict=True)
        ),
        "strictly_better_targets": sum(
            left < right for left, right in zip(majority_ranks, source_ranks, strict=True)
        ),
        "equal_targets": sum(
            left == right for left, right in zip(majority_ranks, source_ranks, strict=True)
        ),
        "worse_targets": sum(
            left > right for left, right in zip(majority_ranks, source_ranks, strict=True)
        ),
        "target_commitments": target_commitments,
    }


def freeze_model(*, expected_implementation_sha256: str) -> dict[str, Any]:
    if any(path.exists() for path in (MODEL, RESULT, CAUSAL, REPORT)):
        raise FileExistsError("A419 model or downstream artifact already exists")
    implementation = load_implementation(expected_implementation_sha256)
    selection_evidence = derive_selection()
    payload: dict[str, Any] = {
        "schema": "chacha20-round20-w50-majority-polarity-portfolio-a419-model-v1",
        "attempt_id": ATTEMPT_ID,
        "model_state": "selection_only_frozen_before_any_A419_holdout_field_label_or_score",
        "design_sha256": DESIGN_SHA256,
        "implementation_sha256": expected_implementation_sha256,
        "implementation_commitment_sha256": implementation["implementation_commitment_sha256"],
        "voters": [
            {"pilot_index": pilot, "top_k": top_k, "weight_family": family}
            for pilot, top_k, family in VOTERS
        ],
        "decision": "positive iff at least two of three frozen voter statistics are nonnegative",
        "replaced_role": REPLACED_ROLE,
        "replacement_role": REPLACEMENT_ROLE,
        "selection_evidence": selection_evidence,
        "A412_selection_fields_used": 16,
        "A412_selection_labels_used": 16,
        "A412_holdout_fields_used": 0,
        "A412_holdout_labels_used": 0,
        "holdout_reader_refits": 0,
        "holdout_model_choices": 0,
        "anchors": {
            "design": anchor(DESIGN, DESIGN_SHA256),
            "implementation": anchor(IMPLEMENTATION, expected_implementation_sha256),
            "A417_library": anchor(A417_LIBRARY, A417_LIBRARY_SHA256),
            "A417_selection": anchor(A417_SELECTION, A417_SELECTION_SHA256),
            "A412_protocol": anchor(A412_PROTOCOL, A412_PROTOCOL_SHA256),
            "runner": anchor(Path(__file__)),
        },
    }
    payload["model_commitment_sha256"] = canonical_sha256(payload)
    atomic_json(MODEL, payload)
    return payload


def load_model(expected_sha256: str | None = None) -> dict[str, Any]:
    if expected_sha256 is not None and file_sha256(MODEL) != expected_sha256:
        raise RuntimeError("A419 model hash differs")
    value = json.loads(MODEL.read_bytes())
    evidence = value.get("selection_evidence", {})
    if (
        value.get("schema")
        != "chacha20-round20-w50-majority-polarity-portfolio-a419-model-v1"
        or value.get("attempt_id") != ATTEMPT_ID
        or tuple(evidence.get("majority_reader_panel", {}).get("ranks", []))
        != EXPECTED_MAJORITY_RANKS
        or tuple(evidence.get("eight_reader_portfolio_panel", {}).get("ranks", []))
        != EXPECTED_PORTFOLIO_RANKS
        or evidence.get("orientation_correct") != 15
        or evidence.get("strictly_better_targets") != 1
        or evidence.get("equal_targets") != 15
        or evidence.get("worse_targets") != 0
        or value.get("A412_holdout_fields_used") != 0
        or value.get("A412_holdout_labels_used") != 0
    ):
        raise RuntimeError("A419 model semantics differ")
    load_implementation(value["implementation_sha256"])
    for row in value["anchors"].values():
        anchor(ROOT / row["path"], row["sha256"])
    unsigned = {key: item for key, item in value.items() if key != "model_commitment_sha256"}
    if value.get("model_commitment_sha256") != canonical_sha256(unsigned):
        raise RuntimeError("A419 model commitment differs")
    return value


def build_causal(payload: Mapping[str, Any]) -> dict[str, Any]:
    sys.path.insert(0, str(DOTCAUSAL_SRC))
    from dotcausal.io import CausalReader, CausalWriter

    qualified = bool(payload["external_transfer"]["qualified"])
    terminal = (
        "A419_holdout_qualified_majority_polarity_scheduler"
        if qualified
        else "A419_holdout_boundary_majority_polarity"
    )
    writer = CausalWriter(api_id="a419w50")
    writer._rules = []
    writer.add_rule(
        name="diverse_pilot_votes_to_majority_polarity",
        description="Combine three frozen target-blind pilot statistics by exact majority vote to orient the signed XOR landscape.",
        pattern=["pilot_11_tail_vote", "pilot_19_tail_vote", "pilot_63_tail_vote"],
        conclusion="A419_majority_polarity_reader",
        confidence_modifier=1.0,
    )
    writer.add_rule(
        name="selection_dominance_to_portfolio_replacement",
        description="Replace A417 candidate 388 after one strictly better and fifteen equal selection ranks with zero worse ranks.",
        pattern=["A419_majority_polarity_reader", "A417_candidate_0388"],
        conclusion="A419_frozen_eight_reader_portfolio",
        confidence_modifier=1.0,
    )
    writer.add_rule(
        name="frozen_portfolio_to_external_scheduler",
        description="Transfer the unchanged eight-worker portfolio to the untouched holdout and materialize the exact complete scheduler.",
        pattern=["A419_frozen_eight_reader_portfolio", "A412_untouched_holdout_16_31"],
        conclusion=terminal,
        confidence_modifier=1.0,
    )
    writer.add_triplet(
        trigger="A415:signed_XOR_landscape_plus_three_A413_pilot_orders",
        mechanism="three_voter_majority_polarity",
        outcome="A419:selection_strictly_dominant_reader",
        confidence=1.0,
        source=payload["model_sha256"],
        quantification=json.dumps(payload["training_selection"], sort_keys=True),
        evidence="15 of 16 orientation decisions correct; one better, fifteen equal, zero worse ranks versus replaced Reader",
        domain="full-round ChaCha20 W50 causal Reader composition",
        quality_score=1.0,
    )
    writer.add_triplet(
        trigger="A419:selection_strictly_dominant_reader",
        mechanism="equal_cost_replacement_of_A417_candidate_0388",
        outcome="A419:frozen_eight_reader_portfolio",
        confidence=1.0,
        source=payload["model_commitment_sha256"],
        quantification=json.dumps(payload["training_selection"]["eight_reader_portfolio_panel"], sort_keys=True),
        evidence="seven A417 Readers unchanged; worker count remains eight",
        domain="full-round ChaCha20 W50 portfolio learning",
        quality_score=1.0,
    )
    writer.add_triplet(
        trigger="A419:frozen_eight_reader_portfolio",
        mechanism="untouched_holdout_transfer_plus_exact_parallel_scheduler",
        outcome=f"A419:{terminal}",
        confidence=1.0,
        source=payload["external_measurement_sha256"],
        quantification=json.dumps(payload["external_transfer"], sort_keys=True),
        evidence="portfolio frozen before any A419 holdout field or label was consumed",
        domain="full-round ChaCha20 W50 parallel recovery scheduling",
        quality_score=1.0,
    )
    writer.add_triplet(
        trigger="A415:signed_XOR_landscape_plus_three_A413_pilot_orders",
        mechanism="materialized_majority_reader_external_scheduler_closure",
        outcome=f"A419:{terminal}",
        confidence=1.0,
        source="materialized:A419_majority_polarity_chain",
        quantification="exact retained closure",
        evidence="three pilot votes, strict selection dominance, untouched holdout, exact scheduler",
        domain="AI-native retained inference",
        quality_score=1.0,
        is_inferred=True,
    )
    writer.add_cluster(
        name="A419 majority-polarity W50 scheduler",
        entities=[
            "A415:signed_XOR_landscape_plus_three_A413_pilot_orders",
            "A419:selection_strictly_dominant_reader",
            "A419:frozen_eight_reader_portfolio",
            f"A419:{terminal}",
        ],
    )
    writer.add_gap(
        subject=f"A419:{terminal}",
        predicate="next_required_object",
        expected_object_type=(
            "shared_stop_execution_of_eight_frozen_A419_worker_lists"
            if qualified
            else "unanimous_wrong_orientation_detector_or_prospective_execution"
        ),
        confidence=1.0,
        suggested_queries=[
            "Execute the exact A419 worker lists with one shared confirmed stop."
            if qualified
            else "Use cross-view geometry to identify the remaining unanimous wrong-orientation class."
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
        reader.api_id != "a419w50"
        or len(explicit) != 3
        or len(all_rows) != 4
        or len(inferred) != 1
        or len(reader._rules) != 3
        or len(reader._clusters) != 1
        or len(reader._gaps) != 1
    ):
        raise RuntimeError("A419 authentic Causal reopen gate failed")
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
            "majority_mechanism": explicit[0],
            "portfolio_replacement": explicit[1],
            "external_scheduler": explicit[2],
            "terminal_chain": all_rows[-1],
            "next_gap": reader._gaps[0],
        },
    }


def evaluate_external(
    *, expected_implementation_sha256: str, expected_model_sha256: str
) -> dict[str, Any]:
    if any(path.exists() for path in (RESULT, CAUSAL, REPORT)):
        raise FileExistsError("A419 result already exists")
    implementation = load_implementation(expected_implementation_sha256)
    model = load_model(expected_model_sha256)
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
    depths: dict[str, list[int]] = {
        "A419": [], "A417": [], "A414": [], "A415": [], "A416": []
    }
    field_commitments: dict[str, Any] = {}
    reader_commitments: dict[str, Any] = {}
    for target in A417.A412.HOLDOUT_TARGETS:
        rank_matrix, field_commitments[str(target)] = A417.A412.fresh_rank_matrix(target)
        cell = int(labels[target]["true_direct12_cell"])
        a419_orders, majority_metadata = portfolio_orders(rank_matrix, library, selection)
        families = {
            "A419": a419_orders,
            "A417": A417.selected_orders(rank_matrix, library, selection),
            "A414": A417.A414.portfolio_orders(rank_matrix, a414_model),
            "A415": A417.A415.portfolio_orders(rank_matrix, a415_model),
            "A416": A417.A416.portfolio_orders(rank_matrix, a416_model),
        }
        truth_ranks: dict[str, dict[str, int]] = {}
        for name, orders in families.items():
            row = {
                role: int(A417.A401.rank_vector(order)[cell])
                for role, order in orders.items()
            }
            truth_ranks[name] = row
            depths[name].append(min(row.values()))
        reader_commitments[str(target)] = {
            "A419_order_uint16be_sha256": {
                role: uint16be_sha256(order) for role, order in a419_orders.items()
            },
            "majority": majority_metadata,
            "true_ranks": truth_ranks,
        }
        print(f"A419 holdout target {target}/31 complete", flush=True)
    panels = {name: metric_panel(ranks) for name, ranks in depths.items()}
    factor = panels["A417"]["geometric_mean_rank"] / panels["A419"]["geometric_mean_rank"]
    gain = (
        panels["A419"]["bit_gain_vs_complete_4096_cover"]
        - panels["A417"]["bit_gain_vs_complete_4096_cover"]
    )
    qualified = factor > 1.0 and gain > 0.0
    external = {
        "qualified": qualified,
        "primary_untouched_holdout_A419_panel": panels["A419"],
        "primary_matched_A417_panel": panels["A417"],
        "secondary_matched_baseline_panels": {
            name: panels[name] for name in ("A414", "A415", "A416")
        },
        "holdout_geometric_rank_improvement_factor_vs_A417": factor,
        "holdout_additional_bit_gain_vs_A417": gain,
        "holdout_better_targets": sum(
            left < right for left, right in zip(depths["A419"], depths["A417"], strict=True)
        ),
        "holdout_equal_targets": sum(
            left == right for left, right in zip(depths["A419"], depths["A417"], strict=True)
        ),
        "holdout_worse_targets": sum(
            left > right for left, right in zip(depths["A419"], depths["A417"], strict=True)
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
        production_ranks, _views, production_metadata = A417.A402.production_rank_matrix()
    production_orders, production_majority = portfolio_orders(
        production_ranks, library, selection
    )
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
        "schema": "chacha20-round20-w50-majority-polarity-portfolio-a419-result-v1",
        "attempt_id": ATTEMPT_ID,
        "evidence_stage": (
            "UNTOUCHED_HOLDOUT_QUALIFIED_MAJORITY_POLARITY_OPTIMAL_SCHEDULER"
            if qualified
            else "UNTOUCHED_HOLDOUT_BOUNDARY_WITH_RETAINED_SELECTION_DOMINANCE"
        ),
        "design_sha256": DESIGN_SHA256,
        "implementation_sha256": expected_implementation_sha256,
        "implementation_commitment_sha256": implementation["implementation_commitment_sha256"],
        "model_sha256": expected_model_sha256,
        "model_commitment_sha256": model["model_commitment_sha256"],
        "training_selection": model["selection_evidence"],
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
        "production_majority": production_majority,
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
            "model": anchor(MODEL, expected_model_sha256),
            "A417_runner": anchor(A417_RUNNER, A417_RUNNER_SHA256),
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
            "# A419 — three-pilot majority-polarity W50 portfolio\n\n"
            f"Evidence stage: **{payload['evidence_stage']}**\n\n"
            "- Selection orientation accuracy: **15/16**\n"
            "- Selection dominance versus replaced Reader: **1 better / 15 equal / 0 worse**\n"
            f"- Untouched holdout A419 ranks: **{panels['A419']['ranks']}**\n"
            f"- Matched A417 ranks: **{panels['A417']['ranks']}**\n"
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
    payload: dict[str, Any] = {
        "attempt_id": ATTEMPT_ID,
        "design_sha256": DESIGN_SHA256,
        "voters": [list(row) for row in VOTERS],
        "implementation_frozen": IMPLEMENTATION.exists(),
        "model_frozen": MODEL.exists(),
        "result_complete": RESULT.exists(),
    }
    if IMPLEMENTATION.exists():
        payload["implementation_sha256"] = file_sha256(IMPLEMENTATION)
        load_implementation(payload["implementation_sha256"])
    if MODEL.exists():
        payload["model_sha256"] = file_sha256(MODEL)
        model = load_model(payload["model_sha256"])
        payload["selection_evidence"] = model["selection_evidence"]
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
    action.add_argument("--freeze-model", action="store_true")
    action.add_argument("--evaluate-external", action="store_true")
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
    elif args.evaluate_external:
        if not args.expected_implementation_sha256 or not args.expected_model_sha256:
            parser.error("--evaluate-external requires implementation and model hashes")
        payload = evaluate_external(
            expected_implementation_sha256=args.expected_implementation_sha256,
            expected_model_sha256=args.expected_model_sha256,
        )
    else:
        payload = analyze()
    print(json.dumps(payload, indent=2, sort_keys=True), flush=True)


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""A416: fold both A415 XOR polarities into one exact W50 Reader."""

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

DESIGN = CONFIGS / "chacha20_round20_w50_folded_xor_portfolio_a416_design_v1.json"
IMPLEMENTATION = (
    CONFIGS / "chacha20_round20_w50_folded_xor_portfolio_a416_implementation_v1.json"
)
MODEL = CONFIGS / "chacha20_round20_w50_folded_xor_portfolio_a416_model_v1.json"
RESULT = RESULTS / "chacha20_round20_w50_folded_xor_portfolio_a416_v1.json"
CAUSAL = RESULT.with_suffix(".causal")
REPORT = RESULT.with_suffix(".md")
TEST = ROOT / "tests/test_chacha20_round20_w50_folded_xor_portfolio_a416.py"
REPRO = ROOT / "scripts/reproduce_chacha20_round20_w50_folded_xor_portfolio_a416.sh"

A415_RUNNER = RESEARCH / "experiments/chacha20_round20_w50_xor_landscape_portfolio_a415.py"
A415_IMPLEMENTATION = (
    CONFIGS / "chacha20_round20_w50_xor_landscape_portfolio_a415_implementation_v1.json"
)
A415_MODEL = CONFIGS / "chacha20_round20_w50_xor_landscape_portfolio_a415_model_v1.json"
A414_RUNNER = RESEARCH / "experiments/chacha20_round20_w50_knownkey_parallel_portfolio_a414.py"
A414_MODEL = CONFIGS / "chacha20_round20_w50_knownkey_parallel_portfolio_a414_model_v1.json"
A413_MODEL = CONFIGS / "chacha20_round20_w50_knownkey_kernel_density_reader_a413_model_v1.json"
A412_PROTOCOL = CONFIGS / "chacha20_round20_w50_fresh_hybrid_reader_a412_public_corpus_v1.json"
A388_ORDER = RESULTS / "chacha20_round20_w50_public_output_direct12_factor3_a388_order_v1.json"

ATTEMPT_ID = "A416"
DESIGN_SHA256 = "c73166ba4a4f1103555fa6d18cf44e427127fa0ebcaefdbd2a26629d1c64ab5f"
A415_RUNNER_SHA256 = "11ed184209e0540b9d8d0ee07e9793cc3c1f434767d8100b92706cbaa2c5760f"
A415_IMPLEMENTATION_SHA256 = "c955e764c1e6f3c869b13cb3762821b7dc165761f0ef6c0e36d06f5effe47876"
A415_MODEL_SHA256 = "ed7d9e8b44c9dee4fecdb4d59de6a67911c3ed4fc0a0fdb09d7e17885e78e110"
A414_RUNNER_SHA256 = "3c0eac31a79141b3c9c39c4c249d7c0a681576bfe652940d9a5151b45b7e9f23"
A414_MODEL_SHA256 = "1e65ef99e4a49861ffcfe5e6f30ec3018516e7d91bbdb2a2539980efcaba6f0b"
A413_MODEL_SHA256 = "71141bdac6a3f4bea95980e21777eb00a774ecde88a29028c441453dc62b7cf8"
A412_PROTOCOL_SHA256 = "f7859b381d5cf6a5f1a765b4abb44192d3bd73539c681a9a40d8c0a48dd365a2"
A388_ORDER_SHA256 = "3c56ce8521b1ced20e1e3a90999810c2e563c4de941701c86274f0828b5d01b8"

CELLS = 4096
WORKERS = 8
FOLDED_INDEX = 155
AVAILABLE_A413 = (5, 20, 35, 49, 91, 100, 123, 144, 152, 153)
SELECTED_INDICES = (155, 123, 35, 100, 153, 91, 49, 144)
SOURCE_ROLES = (
    "folded_xor_negative_first",
    "A413_candidate_123",
    "A413_candidate_035",
    "A413_candidate_100",
    "A413_candidate_153",
    "A413_candidate_091",
    "A413_candidate_049",
    "A413_candidate_144",
)
EXPECTED_FOLDED_RANKS = (
    931, 2091, 21, 420, 3557, 326, 3561, 3384,
    859, 3, 2565, 809, 3168, 3871, 1608, 1214,
)
EXPECTED_PORTFOLIO_RANKS = (
    397, 66, 21, 420, 122, 326, 935, 3384,
    10, 3, 2440, 809, 3, 402, 101, 1214,
)
EXPECTED_PORTFOLIO_GM = 163.25747947090397
DOTCAUSAL_SRC = Path("/Users/bhkmie/Documents/Forschung/O1/vendor/fabel/dotcausal_package/src")


def load_module(path: Path, name: str) -> Any:
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot import A416 dependency {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


A415 = load_module(A415_RUNNER, "a416_a415")
A414 = A415.A414
A413 = A415.A413
A412 = A415.A412
A410 = A415.A410
A401 = A415.A401
A402 = A415.A402

file_sha256 = A415.file_sha256
canonical_sha256 = A415.canonical_sha256
atomic_json = A415.atomic_json
atomic_bytes = A415.atomic_bytes
relative = A415.relative
anchor = A415.anchor
sha256 = A415.sha256
metric_panel = A415.metric_panel
exact_order = A415.exact_order
uint16be_sha256 = A415.uint16be_sha256


def load_design() -> dict[str, Any]:
    if file_sha256(DESIGN) != DESIGN_SHA256:
        raise RuntimeError("A416 design hash differs")
    value = json.loads(DESIGN.read_bytes())
    selection = value.get("training_selection_contract", {})
    boundary = value.get("information_boundary", {})
    if (
        value.get("schema") != "chacha20-round20-w50-folded-xor-portfolio-a416-design-v1"
        or value.get("attempt_id") != ATTEMPT_ID
        or tuple(selection.get("selected_canonical_indices", [])) != SELECTED_INDICES
        or tuple(selection.get("selected_roles", [])) != SOURCE_ROLES
        or tuple(selection.get("folded_LOO_ranks", [])) != EXPECTED_FOLDED_RANKS
        or boundary.get("A412_measurement_fields_or_reader_scores_consumed") is not False
        or boundary.get("A412_holdout_label_ledger_opened") is not False
    ):
        raise RuntimeError("A416 frozen design semantics differ")
    for key, path in value["source_anchors"].items():
        if key.endswith("_path"):
            stem = key.removesuffix("_path")
            anchor(ROOT / path, value["source_anchors"][f"{stem}_sha256"])
    return value


def folded_order(positive: Sequence[int], negative: Sequence[int]) -> list[int]:
    upper = exact_order(positive)
    lower = exact_order(negative)
    seen = np.zeros(CELLS, dtype=np.bool_)
    result: list[int] = []
    for low, high in zip(lower, upper, strict=True):
        if not seen[low]:
            seen[low] = True
            result.append(low)
        if not seen[high]:
            seen[high] = True
            result.append(high)
        if len(result) == CELLS:
            break
    return exact_order(result)


def folded_training_ranks() -> list[int]:
    training = A415.load_training()
    positive = np.asarray(training["positive_LOO_panel"]["ranks"], dtype=np.int64)
    negative = np.asarray(training["negative_LOO_panel"]["ranks"], dtype=np.int64)
    if np.any(positive + negative != CELLS + 1):
        raise RuntimeError("A416 polarity reversal/no-tie proof differs")
    folded = np.where(negative < positive, 2 * negative - 1, 2 * positive)
    if tuple(int(value) for value in folded) != EXPECTED_FOLDED_RANKS:
        raise RuntimeError("A416 folded rank panel differs")
    return folded.tolist()


def derive_portfolio() -> dict[str, Any]:
    base = A415.load_base_rank_matrix()
    canonical = (*AVAILABLE_A413, FOLDED_INDEX)
    matrix = np.column_stack(
        [*(base[:, index] for index in AVAILABLE_A413), folded_training_ranks()]
    ).astype(np.int64)
    selected_positions: list[int] = []
    selected_canonical: list[int] = []
    current: np.ndarray | None = None
    steps = []
    for step in range(WORKERS):
        choices = []
        for position, candidate in enumerate(canonical):
            if position in selected_positions:
                continue
            panel = matrix[:, position] if current is None else np.minimum(
                current, matrix[:, position]
            )
            mean_log = float(np.log2(panel.astype(np.float64)).mean())
            choices.append((mean_log, int(panel.max()), candidate, position, panel))
        mean_log, worst, candidate, position, panel = min(choices, key=lambda row: row[:3])
        selected_positions.append(position)
        selected_canonical.append(candidate)
        current = panel.copy()
        steps.append(
            {
                "step": step,
                "selected_canonical_index": candidate,
                "geometric_mean_parallel_rank": 2.0**mean_log,
                "worst_parallel_rank": worst,
                "pointwise_minimum_ranks": panel.tolist(),
            }
        )
    if (
        tuple(selected_canonical) != SELECTED_INDICES
        or tuple(int(value) for value in current) != EXPECTED_PORTFOLIO_RANKS
        or not math.isclose(
            2.0 ** float(np.log2(current.astype(np.float64)).mean()),
            EXPECTED_PORTFOLIO_GM,
        )
    ):
        raise RuntimeError("A416 frozen portfolio differs")
    return {
        "selected_canonical_indices": selected_canonical,
        "selected_roles": list(SOURCE_ROLES),
        "folded_LOO_panel": metric_panel(folded_training_ranks()),
        "steps": steps,
        "pointwise_minimum_panel": metric_panel(current.tolist()),
        "candidate_rank_matrix_int32le_sha256": sha256(matrix.astype("<i4").tobytes()),
    }


def source_models() -> dict[str, Any]:
    a415 = A415.load_model(A415_MODEL_SHA256)
    a414 = A414.load_portfolio(A414_MODEL_SHA256)
    available = dict(a415["A413_frozen_models"])
    for row in a414["models"]:
        available.setdefault(str(row["candidate_index"]), row["frozen_model"])
    required = {str(index) for index in SELECTED_INDICES if index != FOLDED_INDEX}
    if not required <= set(available):
        raise RuntimeError("A416 frozen A413 source model set differs")
    return {index: available[index] for index in sorted(required, key=int)}


def freeze_implementation() -> dict[str, Any]:
    if any(path.exists() for path in (IMPLEMENTATION, MODEL, RESULT, CAUSAL, REPORT)):
        raise FileExistsError("A416 implementation or downstream artifact already exists")
    load_design()
    derived = derive_portfolio()
    if not TEST.exists() or not REPRO.exists():
        raise FileNotFoundError("A416 test and reproducer must precede freeze")
    payload: dict[str, Any] = {
        "schema": "chacha20-round20-w50-folded-xor-portfolio-a416-implementation-v1",
        "attempt_id": ATTEMPT_ID,
        "commitment_state": "frozen_before_any_A412_measurement_field_or_reader_score",
        "design_sha256": DESIGN_SHA256,
        "portfolio_commitment_sha256": canonical_sha256(derived),
        "selected_canonical_indices": list(SELECTED_INDICES),
        "A412_measurement_fields_used": 0,
        "A412_reader_scores_used": 0,
        "anchors": {
            "design": anchor(DESIGN, DESIGN_SHA256),
            "A415_runner": anchor(A415_RUNNER, A415_RUNNER_SHA256),
            "A415_implementation": anchor(A415_IMPLEMENTATION, A415_IMPLEMENTATION_SHA256),
            "A415_model": anchor(A415_MODEL, A415_MODEL_SHA256),
            "A414_runner": anchor(A414_RUNNER, A414_RUNNER_SHA256),
            "A414_model": anchor(A414_MODEL, A414_MODEL_SHA256),
            "A413_model": anchor(A413_MODEL, A413_MODEL_SHA256),
            "A412_protocol": anchor(A412_PROTOCOL, A412_PROTOCOL_SHA256),
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
        raise RuntimeError("A416 implementation hash differs")
    value = json.loads(IMPLEMENTATION.read_bytes())
    if (
        value.get("schema")
        != "chacha20-round20-w50-folded-xor-portfolio-a416-implementation-v1"
        or tuple(value.get("selected_canonical_indices", [])) != SELECTED_INDICES
        or value.get("portfolio_commitment_sha256") != canonical_sha256(derive_portfolio())
        or value.get("A412_measurement_fields_used") != 0
        or value.get("A412_reader_scores_used") != 0
    ):
        raise RuntimeError("A416 implementation semantics differ")
    for row in value["anchors"].values():
        anchor(ROOT / row["path"], row["sha256"])
    unsigned = {
        key: item for key, item in value.items() if key != "implementation_commitment_sha256"
    }
    if value.get("implementation_commitment_sha256") != canonical_sha256(unsigned):
        raise RuntimeError("A416 implementation commitment differs")
    return value


def freeze_model(*, expected_implementation_sha256: str) -> dict[str, Any]:
    if any(path.exists() for path in (MODEL, RESULT, CAUSAL, REPORT)):
        raise FileExistsError("A416 model or downstream artifact already exists")
    implementation = load_implementation(expected_implementation_sha256)
    a415 = A415.load_model(A415_MODEL_SHA256)
    payload: dict[str, Any] = {
        "schema": "chacha20-round20-w50-folded-xor-portfolio-a416-model-v1",
        "attempt_id": ATTEMPT_ID,
        "model_state": "derived_from_frozen_A414_A415_before_any_A412_score",
        "design_sha256": DESIGN_SHA256,
        "implementation_sha256": expected_implementation_sha256,
        "implementation_commitment_sha256": implementation[
            "implementation_commitment_sha256"
        ],
        "portfolio_selection": derive_portfolio(),
        "selected_canonical_indices": list(SELECTED_INDICES),
        "source_roles": list(SOURCE_ROLES),
        "xor_template": a415["xor_template"],
        "xor_template_float64le_sha256": a415["xor_template_float64le_sha256"],
        "A413_frozen_models": source_models(),
        "A412_measurement_fields_used": 0,
        "A412_reader_scores_used": 0,
        "A412_holdout_labels_used": 0,
        "target_specific_polarity_choices": 0,
        "anchors": {
            "design": anchor(DESIGN, DESIGN_SHA256),
            "implementation": anchor(IMPLEMENTATION, expected_implementation_sha256),
            "A415_model": anchor(A415_MODEL, A415_MODEL_SHA256),
            "A414_model": anchor(A414_MODEL, A414_MODEL_SHA256),
            "A412_protocol": anchor(A412_PROTOCOL, A412_PROTOCOL_SHA256),
            "runner": anchor(Path(__file__)),
        },
    }
    payload["model_commitment_sha256"] = canonical_sha256(payload)
    atomic_json(MODEL, payload)
    return payload


def load_model(expected_sha256: str | None = None) -> dict[str, Any]:
    if expected_sha256 is not None and file_sha256(MODEL) != expected_sha256:
        raise RuntimeError("A416 model hash differs")
    value = json.loads(MODEL.read_bytes())
    if (
        value.get("schema") != "chacha20-round20-w50-folded-xor-portfolio-a416-model-v1"
        or tuple(value.get("selected_canonical_indices", [])) != SELECTED_INDICES
        or tuple(value.get("source_roles", [])) != SOURCE_ROLES
        or value.get("A412_measurement_fields_used") != 0
        or value.get("A412_reader_scores_used") != 0
        or value.get("target_specific_polarity_choices") != 0
    ):
        raise RuntimeError("A416 model semantics differ")
    load_implementation(value["implementation_sha256"])
    template = np.asarray(value["xor_template"], dtype=np.float64)
    if sha256(template.astype("<f8").tobytes()) != value["xor_template_float64le_sha256"]:
        raise RuntimeError("A416 XOR template differs")
    unsigned = {key: item for key, item in value.items() if key != "model_commitment_sha256"}
    if value.get("model_commitment_sha256") != canonical_sha256(unsigned):
        raise RuntimeError("A416 model commitment differs")
    return value


def portfolio_orders(rank_matrix: np.ndarray, model: Mapping[str, Any]) -> dict[str, list[int]]:
    ranks = np.asarray(rank_matrix, dtype=np.int64)
    representations = A410.representation_matrices(ranks)
    field = A415.standardize_landscape(ranks)
    scores = A415.xor_correlation_scores(
        field, np.asarray(model["xor_template"], dtype=np.float64)
    )
    positive, negative = A415.polarity_orders(scores)
    folded = folded_order(positive, negative)
    orders: dict[str, list[int]] = {}
    for index, role in zip(SELECTED_INDICES, SOURCE_ROLES, strict=True):
        if index == FOLDED_INDEX:
            orders[role] = folded
        else:
            frozen = model["A413_frozen_models"][str(index)]
            representation = str(frozen["candidate"]["representation"])
            candidate_scores = A413.score_frozen_model(
                representations[representation], frozen
            )
            orders[role] = A413.exact_score_order(candidate_scores)
    if tuple(orders) != SOURCE_ROLES:
        raise RuntimeError("A416 portfolio order roles differ")
    return orders


def build_causal(payload: Mapping[str, Any]) -> dict[str, Any]:
    sys.path.insert(0, str(DOTCAUSAL_SRC))
    from dotcausal.io import CausalReader, CausalWriter

    qualified = bool(payload["external_transfer"]["qualified"])
    terminal = (
        "A416_holdout_qualified_folded_scheduler"
        if qualified
        else "A416_external_boundary_retained_fold_guarantee"
    )
    writer = CausalWriter(api_id="a416w50")
    writer._rules = []
    writer.add_rule(
        name="dual_polarity_to_single_folded_reader",
        description="Interleave fixed negative and positive A415 tails with first-occurrence deduplication and no target-specific sign choice.",
        pattern=["A415_xor_negative_order", "A415_xor_positive_order"],
        conclusion="A416_single_folded_xor_reader",
        confidence_modifier=1.0,
    )
    writer.add_rule(
        name="folded_reader_to_equal_worker_portfolio",
        description="One folded landscape Reader plus seven already-frozen A413 geometries form an eight-worker A401-only portfolio.",
        pattern=["A416_single_folded_xor_reader", "A413_frozen_geometry_pool"],
        conclusion="A416_fixed_eight_reader_portfolio",
        confidence_modifier=1.0,
    )
    writer.add_rule(
        name="fixed_portfolio_to_external_scheduler",
        description="Untouched A412 holdout comparison controls deployment of the exact 512-epoch A388 schedule.",
        pattern=["A416_fixed_eight_reader_portfolio", "A412_untouched_holdout_and_A388"],
        conclusion=terminal,
        confidence_modifier=1.0,
    )
    writer.add_triplet(
        trigger="A415:fixed_dual_polarity_landscape_orders",
        mechanism="negative_first_exact_tail_interleaving",
        outcome="A416:single_worker_polarity_complete_reader",
        confidence=1.0,
        source=payload["model_sha256"],
        quantification=json.dumps(payload["training_selection"], sort_keys=True),
        evidence="rank bound and exact A401 folded panel fixed before external scores",
        domain="full-round ChaCha20 W50 polarity-invariant scheduling",
        quality_score=1.0,
    )
    writer.add_triplet(
        trigger="A416:single_worker_polarity_complete_reader",
        mechanism="untouched_holdout_equal_worker_transfer_plus_exact_scheduler",
        outcome=f"A416:{terminal}",
        confidence=1.0,
        source=payload["external_measurement_sha256"],
        quantification=json.dumps(payload["external_transfer"], sort_keys=True),
        evidence="zero external choices, refits, or polarity decisions",
        domain="full-round ChaCha20 W50 parallel recovery scheduling",
        quality_score=1.0,
    )
    writer.add_triplet(
        trigger="A415:fixed_dual_polarity_landscape_orders",
        mechanism="materialized_folded_external_scheduler_closure",
        outcome=f"A416:{terminal}",
        confidence=1.0,
        source="materialized:A416_folded_scheduler_chain",
        quantification="exact retained closure",
        evidence="design, model, external panel, and scheduler commitments",
        domain="AI-native retained inference",
        quality_score=1.0,
        is_inferred=True,
    )
    writer.add_cluster(
        name="A416 single-worker polarity-complete W50 scheduler",
        entities=[
            "A415:fixed_dual_polarity_landscape_orders",
            "A416:single_worker_polarity_complete_reader",
            f"A416:{terminal}",
        ],
    )
    writer.add_gap(
        subject=f"A416:{terminal}",
        predicate="next_required_object",
        expected_object_type=(
            "shared_stop_execution_of_A416_worker_lists"
            if qualified
            else "public_field_polarity_predictor"
        ),
        confidence=1.0,
        suggested_queries=[
            "Execute the exact A416 worker lists."
            if qualified
            else "Predict correlation polarity from assignment-free public field invariants."
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
        reader.api_id != "a416w50"
        or len(explicit) != 2
        or len(all_rows) != 3
        or len(inferred) != 1
        or len(reader._rules) != 3
        or len(reader._clusters) != 1
        or len(reader._gaps) != 1
    ):
        raise RuntimeError("A416 authentic Causal reopen gate failed")
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
            "fold": explicit[0],
            "external_scheduler": explicit[1],
            "terminal_chain": all_rows[-1],
            "next_gap": reader._gaps[0],
        },
    }


def evaluate_external(
    *, expected_implementation_sha256: str, expected_model_sha256: str
) -> dict[str, Any]:
    if RESULT.exists() or CAUSAL.exists() or REPORT.exists():
        raise FileExistsError("A416 result already exists")
    implementation = load_implementation(expected_implementation_sha256)
    model = load_model(expected_model_sha256)
    a414_model = A414.load_portfolio(A414_MODEL_SHA256)
    a415_model = A415.load_model(A415_MODEL_SHA256)
    protocol = A412.load_protocol(A412_PROTOCOL_SHA256)
    for target in range(32):
        A412.load_fresh_complete(target, protocol)
    selection_labels = A412.load_label(
        A412.SELECTION_LABELS,
        "chacha20-round20-w50-fresh-hybrid-reader-a412-selection-labels-v1",
        A412.SELECTION_TARGETS,
    )
    holdout_labels = A412.load_label(
        A412.HOLDOUT_LABELS,
        "chacha20-round20-w50-fresh-hybrid-reader-a412-holdout-labels-v1",
        A412.HOLDOUT_TARGETS,
    )
    labels = {**selection_labels, **holdout_labels}
    learned_depths = []
    a414_depths = []
    a415_depths = []
    field_commitments: dict[str, Any] = {}
    reader_commitments: dict[str, Any] = {}
    for target in range(32):
        rank_matrix, field_commitments[str(target)] = A412.fresh_rank_matrix(target)
        cell = int(labels[target]["true_direct12_cell"])
        families = {
            "A416": portfolio_orders(rank_matrix, model),
            "A414": A414.portfolio_orders(rank_matrix, a414_model),
            "A415": A415.portfolio_orders(rank_matrix, a415_model),
        }
        truth_ranks = {
            name: {
                role: int(A401.rank_vector(order)[cell]) for role, order in orders.items()
            }
            for name, orders in families.items()
        }
        learned_depths.append(min(truth_ranks["A416"].values()))
        a414_depths.append(min(truth_ranks["A414"].values()))
        a415_depths.append(min(truth_ranks["A415"].values()))
        reader_commitments[str(target)] = {
            "A416_order_uint16be_sha256": {
                role: uint16be_sha256(order) for role, order in families["A416"].items()
            },
            "true_ranks": truth_ranks,
        }
    learned_holdout = metric_panel(learned_depths[16:])
    baseline_holdout = metric_panel(a414_depths[16:])
    factor = baseline_holdout["geometric_mean_rank"] / learned_holdout[
        "geometric_mean_rank"
    ]
    gain = (
        learned_holdout["bit_gain_vs_complete_4096_cover"]
        - baseline_holdout["bit_gain_vs_complete_4096_cover"]
    )
    qualified = factor > 1.0 and gain > 0.0
    external = {
        "qualified": qualified,
        "primary_holdout_A416_panel": learned_holdout,
        "primary_holdout_A414_panel": baseline_holdout,
        "secondary_holdout_A415_panel": metric_panel(a415_depths[16:]),
        "selection_A416_panel": metric_panel(learned_depths[:16]),
        "all32_A416_panel": metric_panel(learned_depths),
        "holdout_geometric_rank_improvement_factor_vs_A414": factor,
        "holdout_additional_bit_gain_vs_A414": gain,
        "equal_worker_count": WORKERS,
        "external_model_choices": 0,
        "external_model_refits": 0,
        "target_specific_polarity_choices": 0,
        "new_solver_stages": 0,
    }
    with A412.a401_paths(A412.ORIGINAL_A401_ARTIFACTS, A412.ORIGINAL_A401_MEASUREMENTS):
        production_ranks, _views, production_metadata = A402.production_rank_matrix()
    production_orders = portfolio_orders(production_ranks, model)
    owners = A414.minimum_rank_owner_lanes(production_orders, SOURCE_ROLES)
    work = A414.balanced_static_worker_schedule(owners["owner_lane_orders"], SOURCE_ROLES)
    proof = A415.prove_schedule(owners, work, SOURCE_ROLES)
    payload: dict[str, Any] = {
        "schema": "chacha20-round20-w50-folded-xor-portfolio-a416-result-v1",
        "attempt_id": ATTEMPT_ID,
        "evidence_stage": (
            "UNTOUCHED_HOLDOUT_QUALIFIED_SINGLE_WORKER_FOLD_OPTIMAL_SCHEDULER"
            if qualified
            else "EXTERNAL_BOUNDARY_WITH_RETAINED_FOLD_GUARANTEE_AND_SCHEDULER"
        ),
        "design_sha256": DESIGN_SHA256,
        "implementation_sha256": expected_implementation_sha256,
        "implementation_commitment_sha256": implementation[
            "implementation_commitment_sha256"
        ],
        "model_sha256": expected_model_sha256,
        "model_commitment_sha256": model["model_commitment_sha256"],
        "training_selection": model["portfolio_selection"],
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
        "fresh_field_commitments": field_commitments,
        "fresh_reader_commitments": reader_commitments,
        "complete_external_targets": 32,
        "external_target_labels_used_for_model_selection": 0,
        "external_reader_refits": 0,
        "target_specific_polarity_choices": 0,
        "production_target_labels_used": 0,
        "production_candidate_assignments_executed": 0,
        "anchors": {
            "design": anchor(DESIGN, DESIGN_SHA256),
            "implementation": anchor(IMPLEMENTATION, expected_implementation_sha256),
            "model": anchor(MODEL, expected_model_sha256),
            "A415_model": anchor(A415_MODEL, A415_MODEL_SHA256),
            "A414_model": anchor(A414_MODEL, A414_MODEL_SHA256),
            "A412_protocol": anchor(A412_PROTOCOL, A412_PROTOCOL_SHA256),
            "A388_order": anchor(A388_ORDER, A388_ORDER_SHA256),
            "runner": anchor(Path(__file__)),
        },
    }
    payload["external_measurement_sha256"] = canonical_sha256(
        {
            "external_transfer": external,
            "fresh_field_commitments": field_commitments,
            "fresh_reader_commitments": reader_commitments,
        }
    )
    payload["causal"] = build_causal(payload)
    atomic_json(RESULT, payload)
    atomic_bytes(
        REPORT,
        (
            "# A416 — single-worker folded-XOR W50 scheduler\n\n"
            f"Evidence stage: **{payload['evidence_stage']}**\n\n"
            f"- Untouched holdout A416 ranks: **{learned_holdout['ranks']}**\n"
            f"- Matched A414 ranks: **{baseline_holdout['ranks']}**\n"
            f"- Holdout improvement factor: **{factor:.9f}**\n"
            f"- Holdout additional bit gain: **{gain:.9f}**\n"
            "- Folded landscape worker count: **1**\n"
            "- Complete schedule: **4,096 cells, 0 duplicates, 512 epochs**\n"
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
        "training_selection": derive_portfolio(),
    }
    if IMPLEMENTATION.exists():
        payload["implementation_sha256"] = file_sha256(IMPLEMENTATION)
    if MODEL.exists():
        payload["model_sha256"] = file_sha256(MODEL)
    if RESULT.exists():
        result = json.loads(RESULT.read_bytes())
        payload["result_sha256"] = file_sha256(RESULT)
        payload["evidence_stage"] = result["evidence_stage"]
        payload["external_transfer"] = result["external_transfer"]
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
            parser.error("--evaluate-external requires implementation and model SHA-256")
        payload = evaluate_external(
            expected_implementation_sha256=args.expected_implementation_sha256,
            expected_model_sha256=args.expected_model_sha256,
        )
    else:
        payload = analyze()
    print(json.dumps(payload, indent=2, sort_keys=True), flush=True)


if __name__ == "__main__":
    main()

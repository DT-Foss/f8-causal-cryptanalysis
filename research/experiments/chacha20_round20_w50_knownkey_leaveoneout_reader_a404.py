#!/usr/bin/env python3
"""A404: sixteen-fold leave-one-key-out validation and production transfer."""

from __future__ import annotations

import argparse
import importlib.util
import inspect
import json
import os
import sys
from collections import Counter
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

import numpy as np

ROOT = Path(__file__).parents[2]
RESEARCH = ROOT / "research"
CONFIGS = RESEARCH / "configs"
RESULTS = RESEARCH / "results/v1"

DESIGN = CONFIGS / "chacha20_round20_w50_knownkey_leaveoneout_reader_a404_design_v1.json"
IMPLEMENTATION = (
    CONFIGS / "chacha20_round20_w50_knownkey_leaveoneout_reader_a404_implementation_v1.json"
)
RESULT = RESULTS / "chacha20_round20_w50_knownkey_leaveoneout_reader_a404_v1.json"
CAUSAL = RESULT.with_suffix(".causal")
REPORT = RESULT.with_suffix(".md")
TEST = ROOT / "tests/test_chacha20_round20_w50_knownkey_leaveoneout_reader_a404.py"
REPRO = ROOT / "scripts/reproduce_chacha20_round20_w50_knownkey_leaveoneout_reader_a404.sh"

A401_RUNNER = RESEARCH / "experiments/chacha20_round20_w50_knownkey_direct12_learning_a401.py"
A402_RUNNER = (
    RESEARCH / "experiments/chacha20_round20_w50_knownkey_fullfit_production_reader_a402.py"
)
A388_ORDER = RESULTS / "chacha20_round20_w50_public_output_direct12_factor3_a388_order_v1.json"

ATTEMPT_ID = "A404"
DESIGN_SHA256 = "ecd0eb3d7f7b155dc4e87d56335890889eaa3dde57c6d3749e72cf321e71d1a1"
A401_RUNNER_SHA256 = "2238b99504883cd0b722b7b92254b3dc02255a6b53c9851f35264daad3f21bee"
A401_IMPLEMENTATION_SHA256 = "4a08686d34674525bd08938d96783c6772ce4cd004fffbe04d11dc972cf63df1"
A401_PROTOCOL_SHA256 = "18aaad488842ce9fb52a77cef01c89bfeb8c901001a86fd56e23bbf594c7a4f3"
A402_RUNNER_SHA256 = "ecd409f1894fc5a9ca5781fc70f040c6b8eae02878b69f936c5fe399f42d0473"
A388_ORDER_SHA256 = "3c56ce8521b1ced20e1e3a90999810c2e563c4de941701c86274f0828b5d01b8"
DOTCAUSAL_SRC = Path("/Users/bhkmie/Documents/Forschung/O1/vendor/fabel/dotcausal_package/src")


def load_module(path: Path, name: str) -> Any:
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot import A404 dependency {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


A401 = load_module(A401_RUNNER, "a404_a401")
A402 = load_module(A402_RUNNER, "a404_a402")

file_sha256 = A401.file_sha256
canonical_sha256 = A401.canonical_sha256
atomic_json = A401.atomic_json
atomic_bytes = A401.atomic_bytes
relative = A401.relative
path_from_ref = A401.path_from_ref
anchor = A401.anchor

TARGETS = A401.TARGETS
VIEW_NAMES = A401.VIEW_NAMES
AGGREGATORS = A401.AGGREGATORS
CELLS = A401.CELLS


def load_design() -> dict[str, Any]:
    if file_sha256(DESIGN) != DESIGN_SHA256:
        raise RuntimeError("A404 design hash differs")
    value = json.loads(DESIGN.read_bytes())
    corpus = value.get("corpus_contract", {})
    candidate = value.get("candidate_contract", {})
    baseline = value.get("baseline_contract", {})
    production = value.get("production_contract", {})
    boundary = value.get("information_boundary", {})
    if (
        value.get("schema") != "chacha20-round20-w50-knownkey-leaveoneout-reader-a404-design-v1"
        or value.get("attempt_id") != ATTEMPT_ID
        or value.get("design_state")
        != "frozen_during_A401_measurement_before_A401_selection_holdout_result_or_any_A404_label_score"
        or tuple(corpus.get("target_indices", [])) != TARGETS
        or corpus.get("fold_count") != len(TARGETS)
        or corpus.get("training_targets_per_fold") != len(TARGETS) - 1
        or tuple(candidate.get("complete_view_order", [])) != VIEW_NAMES
        or tuple(candidate.get("aggregator_order", [])) != AGGREGATORS
        or candidate.get("candidate_count") != 765
        or baseline.get("baseline_candidate_count") != 11
        or production.get("target_labels_used") != 0
        or production.get("new_solver_stages") != 0
        or boundary.get("A401_selection_holdout_or_result_available_at_design_freeze") is not False
        or boundary.get("A404_label_scores_available_at_design_freeze") is not False
    ):
        raise RuntimeError("A404 frozen design semantics differ")
    for key, source_path in value["source_anchors"].items():
        if key.endswith("_path"):
            expected = value["source_anchors"][key.removesuffix("_path") + "_sha256"]
            anchor(ROOT / source_path, expected)
    return value


def freeze_implementation() -> dict[str, Any]:
    if any(path.exists() for path in (IMPLEMENTATION, RESULT, CAUSAL, REPORT)):
        raise FileExistsError("A404 implementation or result already exists")
    if A401.SELECTION.exists() or A401.RESULT.exists():
        raise RuntimeError("A404 code freeze must precede A401 selection and result")
    load_design()
    if not TEST.exists() or not REPRO.exists():
        raise FileNotFoundError("A404 test and reproducer must precede freeze")
    payload: dict[str, Any] = {
        "schema": "chacha20-round20-w50-knownkey-leaveoneout-reader-a404-implementation-v1",
        "attempt_id": ATTEMPT_ID,
        "commitment_state": "complete_leaveoneout_code_frozen_before_A401_selection_result_or_A404_label_score",
        "design_sha256": DESIGN_SHA256,
        "candidate_count": 765,
        "baseline_candidate_count": 11,
        "A401_selection_or_result_available_at_freeze": False,
        "A404_label_scores_available_at_freeze": False,
        "anchors": {
            "design": anchor(DESIGN, DESIGN_SHA256),
            "A401_design": anchor(A401.DESIGN, A401.DESIGN_SHA256),
            "A401_runner": anchor(A401_RUNNER, A401_RUNNER_SHA256),
            "A401_implementation": anchor(A401.IMPLEMENTATION, A401_IMPLEMENTATION_SHA256),
            "A401_public_corpus": anchor(A401.PROTOCOL, A401_PROTOCOL_SHA256),
            "A402_runner": anchor(A402_RUNNER, A402_RUNNER_SHA256),
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
        raise RuntimeError("A404 implementation hash differs")
    value = json.loads(IMPLEMENTATION.read_bytes())
    if (
        value.get("schema")
        != "chacha20-round20-w50-knownkey-leaveoneout-reader-a404-implementation-v1"
        or value.get("attempt_id") != ATTEMPT_ID
        or value.get("commitment_state")
        != "complete_leaveoneout_code_frozen_before_A401_selection_result_or_A404_label_score"
        or value.get("candidate_count") != 765
        or value.get("baseline_candidate_count") != 11
        or value.get("A401_selection_or_result_available_at_freeze") is not False
        or value.get("A404_label_scores_available_at_freeze") is not False
    ):
        raise RuntimeError("A404 implementation semantics differ")
    for row in value["anchors"].values():
        anchor(path_from_ref(row["path"]), row["sha256"])
    unsigned = {
        key: item for key, item in value.items() if key != "implementation_commitment_sha256"
    }
    if value.get("implementation_commitment_sha256") != canonical_sha256(unsigned):
        raise RuntimeError("A404 implementation commitment differs")
    return value


def baseline_indices(candidates: Sequence[Mapping[str, Any]]) -> list[int]:
    selected = []
    for index, row in enumerate(candidates):
        views = tuple(int(value) for value in row["view_indices"])
        aggregator = str(row["aggregator"])
        if (len(views) == 1 and aggregator == "borda_sum") or views == (5, 7):
            selected.append(index)
    if len(selected) != 11:
        raise RuntimeError("A404 baseline family size differs")
    return selected


def selection_key(
    candidates: Sequence[Mapping[str, Any]],
    truth: np.ndarray,
    candidate_index: int,
    train: Sequence[int],
) -> tuple[Any, ...]:
    row = candidates[candidate_index]
    ranks = truth[np.asarray(tuple(train), dtype=np.int64), candidate_index]
    return (
        float(np.log2(ranks.astype(np.float64)).mean()),
        int(ranks.max()),
        len(row["view_indices"]),
        int(row["aggregator_index"]),
        tuple(int(value) for value in row["view_indices"]),
    )


def leaveoneout(candidates: Sequence[Mapping[str, Any]], truth: np.ndarray) -> dict[str, Any]:
    if len(candidates) != 765 or truth.shape != (len(TARGETS), 765):
        raise ValueError("A404 leave-one-out table shape differs")
    baselines = baseline_indices(candidates)
    folds = []
    learned_ranks = []
    baseline_ranks = []
    learned_winners = []
    baseline_winners = []
    for heldout in TARGETS:
        train = tuple(index for index in TARGETS if index != heldout)
        learned_index = min(
            range(len(candidates)),
            key=lambda index: selection_key(candidates, truth, index, train),
        )
        baseline_index = min(
            baselines,
            key=lambda index: selection_key(candidates, truth, index, train),
        )
        learned_rank = int(truth[heldout, learned_index])
        baseline_rank = int(truth[heldout, baseline_index])
        learned_ranks.append(learned_rank)
        baseline_ranks.append(baseline_rank)
        learned_winners.append(learned_index)
        baseline_winners.append(baseline_index)
        folds.append(
            {
                "heldout_target": heldout,
                "training_targets": list(train),
                "learned_candidate_index": learned_index,
                "learned_candidate": {
                    key: candidates[learned_index][key]
                    for key in ("aggregator", "aggregator_index", "view_indices", "view_names")
                },
                "learned_heldout_rank": learned_rank,
                "baseline_candidate_index": baseline_index,
                "baseline_candidate": {
                    key: candidates[baseline_index][key]
                    for key in ("aggregator", "aggregator_index", "view_indices", "view_names")
                },
                "baseline_heldout_rank": baseline_rank,
            }
        )
    learned_panel = A401.metric_panel(learned_ranks)
    baseline_panel = A401.metric_panel(baseline_ranks)
    factor = baseline_panel["geometric_mean_rank"] / learned_panel["geometric_mean_rank"]
    additional_gain = (
        learned_panel["bit_gain_vs_complete_4096_cover"]
        - baseline_panel["bit_gain_vs_complete_4096_cover"]
    )
    qualified = factor > 1.0 and additional_gain > 0.0
    return {
        "folds": folds,
        "learned_panel": learned_panel,
        "baseline_panel": baseline_panel,
        "geometric_rank_improvement_factor": factor,
        "additional_bit_gain": additional_gain,
        "learned_better_folds": sum(
            left < right for left, right in zip(learned_ranks, baseline_ranks, strict=True)
        ),
        "learned_equal_folds": sum(
            left == right for left, right in zip(learned_ranks, baseline_ranks, strict=True)
        ),
        "learned_worse_folds": sum(
            left > right for left, right in zip(learned_ranks, baseline_ranks, strict=True)
        ),
        "learned_winner_frequency": dict(sorted(Counter(learned_winners).items())),
        "baseline_winner_frequency": dict(sorted(Counter(baseline_winners).items())),
        "qualified": qualified,
    }


def build_candidate_table() -> tuple[list[dict[str, Any]], np.ndarray, dict[str, Any]]:
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
    rank_matrices = {}
    field_commitments = {}
    for index in TARGETS:
        rank_matrices[index], field_commitments[str(index)] = A401.view_rank_matrix(index)
    candidates = A402.candidate_rows(rank_matrices, labels)
    truth = np.asarray([row["fullfit_true_ranks"] for row in candidates], dtype=np.int64).T
    if truth.shape != (len(TARGETS), 765):
        raise RuntimeError("A404 candidate truth table differs")
    return (
        candidates,
        truth,
        {
            "candidate_family_commitment_sha256": canonical_sha256(candidates),
            "truth_rank_table_int32le_sha256": A401.sha256(truth.astype("<i4").tobytes()),
            "knownkey_field_commitments": field_commitments,
            "combined_label_commitment_sha256": canonical_sha256(
                [labels[index] for index in TARGETS]
            ),
        },
    )


def build_causal(payload: Mapping[str, Any]) -> dict[str, Any]:
    sys.path.insert(0, str(DOTCAUSAL_SRC))
    from dotcausal.io import CausalReader, CausalWriter

    qualified = bool(payload["leaveoneout"]["qualified"])
    terminal = (
        "A404_outoffold_qualified_production_order"
        if qualified
        else "A404_leaveoneout_boundary_retained"
    )
    writer = CausalWriter(api_id="a404w50")
    writer._rules = []
    writer.add_rule(
        name="complete_fields_to_leaveoneout",
        description="Each of sixteen folds fits on fifteen complete known-key fields and scores exactly one unseen key.",
        pattern=["A401_sixteen_complete_fields", "A404_frozen_candidate_family"],
        conclusion="A404_outoffold_panel",
        confidence_modifier=1.0,
    )
    writer.add_rule(
        name="outoffold_gate_to_production",
        description="Only an aggregate out-of-fold improvement permits a full fit and zero-refit A388 application.",
        pattern=["A404_outoffold_panel", "A388_complete_unlabeled_W50_field"],
        conclusion=terminal,
        confidence_modifier=1.0,
    )
    writer.add_triplet(
        trigger="A401:sixteen_complete_knownkey_fields",
        mechanism="sixteen_fold_leave_one_key_out_candidate_and_baseline_selection",
        outcome="A404:outoffold_panel",
        confidence=1.0,
        source=payload["candidate_table_commitment_sha256"],
        quantification=json.dumps(payload["leaveoneout"], sort_keys=True),
        evidence="A404 design and code froze before any A401 label score",
        domain="known-key W50 leave-one-out validation",
        quality_score=1.0,
    )
    writer.add_triplet(
        trigger="A404:outoffold_panel",
        mechanism="predeclared_gate_fullfit_and_zero_refit_application",
        outcome=f"A404:{terminal}",
        confidence=1.0,
        source=payload["deployment_commitment_sha256"],
        quantification=json.dumps(payload.get("fullfit_candidate"), sort_keys=True),
        evidence="zero production labels, refits, candidates, solver stages, or live outcomes",
        domain="out-of-fold-qualified production Reader",
        quality_score=1.0,
    )
    writer.add_triplet(
        trigger="A401:sixteen_complete_knownkey_fields",
        mechanism="materialized_leaveoneout_to_production_chain",
        outcome=f"A404:{terminal}",
        confidence=1.0,
        source="materialized:A404_leaveoneout_chain",
        quantification="exact retained closure",
        evidence="pre-result A404 design and implementation commitments",
        domain="AI-native retained inference",
        quality_score=1.0,
        is_inferred=True,
    )
    writer.add_cluster(
        name="A404 leave-one-key-out W50 Reader",
        entities=[
            "A401:sixteen_complete_knownkey_fields",
            "A404:outoffold_panel",
            f"A404:{terminal}",
        ],
    )
    writer.add_gap(
        subject=f"A404:{terminal}",
        predicate="next_required_object",
        expected_object_type=(
            "complete_group_recovery_in_the_outoffold_qualified_order"
            if qualified
            else "new_reader_family_or_larger_knownkey_corpus"
        ),
        confidence=1.0,
        suggested_queries=[
            "Execute the exact A404 production order with matched control."
            if qualified
            else "Use the fold traces to design a different predeclared Reader family."
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
        reader.api_id != "a404w50"
        or len(explicit) != 2
        or len(all_rows) != 3
        or len(inferred) != 1
        or len(reader._rules) != 2
        or len(reader._clusters) != 1
        or len(reader._gaps) != 1
    ):
        raise RuntimeError("A404 authentic Causal reopen gate failed")
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
            "leaveoneout": explicit[0],
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
        raise FileExistsError("A404 result already exists")
    implementation = load_implementation(expected_implementation_sha256)
    a401_result, _selection = A402.load_a401_result(
        expected_result_sha256=expected_a401_result_sha256,
        expected_selection_sha256=expected_a401_selection_sha256,
    )
    candidates, truth, table_metadata = build_candidate_table()
    validation = leaveoneout(candidates, truth)
    winner = A402.select_fullfit_candidate(candidates) if validation["qualified"] else None
    production_order = None
    production_metadata = None
    diversity = None
    if winner is not None:
        ranks, view_orders, production_metadata = A402.production_rank_matrix()
        production_order = A401.candidate_order(ranks, winner["view_indices"], winner["aggregator"])
        diversity = {
            name: A401.A388.A351.diversity_panel(production_order, view_orders[name])
            for name in VIEW_NAMES
        }
    payload: dict[str, Any] = {
        "schema": "chacha20-round20-w50-knownkey-leaveoneout-reader-a404-result-v1",
        "attempt_id": ATTEMPT_ID,
        "evidence_stage": (
            "SIXTEEN_FOLD_OUTOFFOLD_QUALIFIED_FULLFIT_READER_APPLIED_TO_A388"
            if validation["qualified"]
            else "SIXTEEN_FOLD_LEAVEONEOUT_BOUNDARY_RETAINED_NO_PRODUCTION_DEPLOYMENT"
        ),
        "design_sha256": DESIGN_SHA256,
        "implementation_sha256": expected_implementation_sha256,
        "implementation_commitment_sha256": implementation["implementation_commitment_sha256"],
        "A401_result_sha256": expected_a401_result_sha256,
        "A401_selection_sha256": expected_a401_selection_sha256,
        "A401_result_evidence_stage": a401_result["evidence_stage"],
        "candidate_table_commitment_sha256": canonical_sha256(
            {
                "candidate_family": table_metadata["candidate_family_commitment_sha256"],
                "truth_table": table_metadata["truth_rank_table_int32le_sha256"],
            }
        ),
        "candidate_table_metadata": table_metadata,
        "leaveoneout": validation,
        "fullfit_candidate": winner,
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
            "leaveoneout": validation,
            "fullfit_candidate": winner,
            "production_order": production_order,
            "production_view_metadata": production_metadata,
        }
    )
    payload["causal"] = build_causal(payload)
    atomic_json(RESULT, payload)
    atomic_bytes(
        REPORT,
        (
            "# A404 — Sixteen-fold leave-one-key-out W50 Reader\n\n"
            f"Evidence stage: **{payload['evidence_stage']}**\n\n"
            f"- Out-of-fold qualification: **{validation['qualified']}**\n"
            f"- Learned ranks: **{validation['learned_panel']['ranks']}**\n"
            f"- Fold-matched baseline ranks: **{validation['baseline_panel']['ranks']}**\n"
            f"- Geometric rank improvement: **{validation['geometric_rank_improvement_factor']:.9f}x**\n"
            f"- Additional bit gain: **{validation['additional_bit_gain']:.9f} bits**\n"
            f"- Better / equal / worse folds: **{validation['learned_better_folds']} / {validation['learned_equal_folds']} / {validation['learned_worse_folds']}**\n"
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
        "A401_result_available": A401.RESULT.exists(),
        "result_complete": RESULT.exists(),
    }
    if IMPLEMENTATION.exists():
        payload["implementation_sha256"] = file_sha256(IMPLEMENTATION)
    if RESULT.exists():
        value = json.loads(RESULT.read_bytes())
        payload["result_sha256"] = file_sha256(RESULT)
        payload["leaveoneout"] = value["leaveoneout"]
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

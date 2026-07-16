#!/usr/bin/env python3
"""A417: selection-calibrated polarity and rank-copula W50 portfolio."""

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

DESIGN = CONFIGS / "chacha20_round20_w50_selection_calibrated_portfolio_a417_design_v1.json"
IMPLEMENTATION = (
    CONFIGS / "chacha20_round20_w50_selection_calibrated_portfolio_a417_implementation_v1.json"
)
LIBRARY = CONFIGS / "chacha20_round20_w50_selection_calibrated_portfolio_a417_library_v1.json"
SELECTION = (
    CONFIGS / "chacha20_round20_w50_selection_calibrated_portfolio_a417_selection_v1.json"
)
RESULT = RESULTS / "chacha20_round20_w50_selection_calibrated_portfolio_a417_v1.json"
CAUSAL = RESULT.with_suffix(".causal")
REPORT = RESULT.with_suffix(".md")
TEST = ROOT / "tests/test_chacha20_round20_w50_selection_calibrated_portfolio_a417.py"
REPRO = ROOT / "scripts/reproduce_chacha20_round20_w50_selection_calibrated_portfolio_a417.sh"

A413_RUNNER = RESEARCH / "experiments/chacha20_round20_w50_knownkey_kernel_density_reader_a413.py"
A413_MODEL = CONFIGS / "chacha20_round20_w50_knownkey_kernel_density_reader_a413_model_v1.json"
A415_RUNNER = RESEARCH / "experiments/chacha20_round20_w50_xor_landscape_portfolio_a415.py"
A415_MODEL = CONFIGS / "chacha20_round20_w50_xor_landscape_portfolio_a415_model_v1.json"
A416_RUNNER = RESEARCH / "experiments/chacha20_round20_w50_folded_xor_portfolio_a416.py"
A416_MODEL = CONFIGS / "chacha20_round20_w50_folded_xor_portfolio_a416_model_v1.json"
A412_PROTOCOL = CONFIGS / "chacha20_round20_w50_fresh_hybrid_reader_a412_public_corpus_v1.json"
A388_ORDER = RESULTS / "chacha20_round20_w50_public_output_direct12_factor3_a388_order_v1.json"

ATTEMPT_ID = "A417"
DESIGN_SHA256 = "b725d94d57d55f5426657472608e8119cf15541bc70be39f3fad7f559ac6b263"
A413_RUNNER_SHA256 = "e8f939d84cf53364bbbb4c729c1e9fa7fd5dce2742cd24fcc6e3e6a559c804d4"
A413_MODEL_SHA256 = "71141bdac6a3f4bea95980e21777eb00a774ecde88a29028c441453dc62b7cf8"
A415_RUNNER_SHA256 = "11ed184209e0540b9d8d0ee07e9793cc3c1f434767d8100b92706cbaa2c5760f"
A415_MODEL_SHA256 = "ed7d9e8b44c9dee4fecdb4d59de6a67911c3ed4fc0a0fdb09d7e17885e78e110"
A416_RUNNER_SHA256 = "6d4f3e144d4d2c7a689b1b4808537379e96091ca5d106ac4cbc00d20d378ce76"
A416_MODEL_SHA256 = "ed927419a04f39f16ffb2679ff51544a43288821744cf2558cd97e45e45a6c58"
A412_PROTOCOL_SHA256 = "f7859b381d5cf6a5f1a765b4abb44192d3bd73539c681a9a40d8c0a48dd365a2"
A388_ORDER_SHA256 = "3c56ce8521b1ced20e1e3a90999810c2e563c4de941701c86274f0828b5d01b8"

CELLS = 4096
WORKERS = 8
A413_COUNT = 155
POSITIVE_INDEX = 155
NEGATIVE_INDEX = 156
FOLDED_INDEX = 157
POLARITY_START = 158
TOP_K = (16, 32, 64, 128, 256, 512)
WEIGHT_FAMILIES = ("uniform", "reciprocal_sqrt_rank")
COPULA_ALPHAS = (0.25, 0.5, 1.0, 2.0, 4.0)
POLARITY_COUNT = A413_COUNT * len(TOP_K) * len(WEIGHT_FAMILIES)
COPULA_START = POLARITY_START + POLARITY_COUNT
CANDIDATE_COUNT = COPULA_START + A413_COUNT * len(COPULA_ALPHAS)
DOTCAUSAL_SRC = Path("/Users/bhkmie/Documents/Forschung/O1/vendor/fabel/dotcausal_package/src")


def load_module(path: Path, name: str) -> Any:
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot import A417 dependency {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


A416 = load_module(A416_RUNNER, "a417_a416")
A415 = A416.A415
A414 = A416.A414
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
        raise RuntimeError("A417 design hash differs")
    value = json.loads(DESIGN.read_bytes())
    library = value.get("candidate_library", {})
    boundary = value.get("information_boundary", {})
    if (
        value.get("schema")
        != "chacha20-round20-w50-selection-calibrated-portfolio-a417-design-v1"
        or value.get("attempt_id") != ATTEMPT_ID
        or library.get("total_candidate_count") != CANDIDATE_COUNT
        or library.get("polarity_top_k") != list(TOP_K)
        or library.get("polarity_weight_families") != list(WEIGHT_FAMILIES)
        or library.get("rank_copula_alphas") != list(COPULA_ALPHAS)
        or boundary.get("A412_selection_reader_scores_consumed_by_A417_at_design_freeze") != 0
        or boundary.get("A412_holdout_label_ledger_opened_by_A417_at_design_freeze") is not False
    ):
        raise RuntimeError("A417 frozen design semantics differ")
    for key, path in value["source_anchors"].items():
        if key.endswith("_path"):
            stem = key.removesuffix("_path")
            anchor(ROOT / path, value["source_anchors"][f"{stem}_sha256"])
    return value


def candidate_specs() -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for pilot in range(A413_COUNT):
        rows.append(
            {
                "canonical_index": len(rows),
                "family": "A413_original",
                "pilot_index": pilot,
            }
        )
    rows.extend(
        [
            {"canonical_index": len(rows), "family": "xor_positive"},
            {"canonical_index": len(rows) + 1, "family": "xor_negative"},
            {"canonical_index": len(rows) + 2, "family": "xor_folded_negative_first"},
        ]
    )
    for pilot in range(A413_COUNT):
        for top_k in TOP_K:
            for weights in WEIGHT_FAMILIES:
                rows.append(
                    {
                        "canonical_index": len(rows),
                        "family": "pilot_calibrated_polarity",
                        "pilot_index": pilot,
                        "top_k": top_k,
                        "weight_family": weights,
                    }
                )
    for pilot in range(A413_COUNT):
        for alpha in COPULA_ALPHAS:
            rows.append(
                {
                    "canonical_index": len(rows),
                    "family": "pilot_fold_rank_copula",
                    "pilot_index": pilot,
                    "alpha": alpha,
                }
            )
    if (
        len(rows) != CANDIDATE_COUNT
        or rows[POSITIVE_INDEX]["family"] != "xor_positive"
        or rows[NEGATIVE_INDEX]["family"] != "xor_negative"
        or rows[FOLDED_INDEX]["family"] != "xor_folded_negative_first"
        or rows[POLARITY_START]["family"] != "pilot_calibrated_polarity"
        or rows[COPULA_START]["family"] != "pilot_fold_rank_copula"
        or any(row["canonical_index"] != index for index, row in enumerate(rows))
    ):
        raise RuntimeError("A417 canonical candidate family differs")
    return rows


def freeze_implementation() -> dict[str, Any]:
    if any(path.exists() for path in (IMPLEMENTATION, LIBRARY, SELECTION, RESULT, CAUSAL, REPORT)):
        raise FileExistsError("A417 implementation or downstream artifact already exists")
    load_design()
    if not TEST.exists() or not REPRO.exists():
        raise FileNotFoundError("A417 test and reproducer must precede implementation freeze")
    candidates = candidate_specs()
    payload: dict[str, Any] = {
        "schema": "chacha20-round20-w50-selection-calibrated-portfolio-a417-implementation-v1",
        "attempt_id": ATTEMPT_ID,
        "commitment_state": "frozen_before_any_A417_A412_selection_or_holdout_score",
        "design_sha256": DESIGN_SHA256,
        "candidate_count": CANDIDATE_COUNT,
        "candidate_family_commitment_sha256": canonical_sha256(candidates),
        "A412_selection_fields_used": 0,
        "A412_selection_labels_used": 0,
        "A412_holdout_fields_or_labels_used": 0,
        "anchors": {
            "design": anchor(DESIGN, DESIGN_SHA256),
            "A413_runner": anchor(A413_RUNNER, A413_RUNNER_SHA256),
            "A413_model": anchor(A413_MODEL, A413_MODEL_SHA256),
            "A415_runner": anchor(A415_RUNNER, A415_RUNNER_SHA256),
            "A415_model": anchor(A415_MODEL, A415_MODEL_SHA256),
            "A416_runner": anchor(A416_RUNNER, A416_RUNNER_SHA256),
            "A416_model": anchor(A416_MODEL, A416_MODEL_SHA256),
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
        raise RuntimeError("A417 implementation hash differs")
    value = json.loads(IMPLEMENTATION.read_bytes())
    if (
        value.get("schema")
        != "chacha20-round20-w50-selection-calibrated-portfolio-a417-implementation-v1"
        or value.get("attempt_id") != ATTEMPT_ID
        or value.get("candidate_count") != CANDIDATE_COUNT
        or value.get("candidate_family_commitment_sha256")
        != canonical_sha256(candidate_specs())
        or value.get("A412_selection_fields_used") != 0
        or value.get("A412_selection_labels_used") != 0
        or value.get("A412_holdout_fields_or_labels_used") != 0
    ):
        raise RuntimeError("A417 implementation semantics differ")
    for row in value["anchors"].values():
        anchor(ROOT / row["path"], row["sha256"])
    unsigned = {
        key: item for key, item in value.items() if key != "implementation_commitment_sha256"
    }
    if value.get("implementation_commitment_sha256") != canonical_sha256(unsigned):
        raise RuntimeError("A417 implementation commitment differs")
    return value


def fit_source_models() -> tuple[dict[str, Any], dict[str, Any]]:
    bundle = A413.training_bundle()
    candidates = A413.candidate_rows()
    true_cells = bundle["true_cells"]
    representations = bundle["representations"]
    models: dict[str, Any] = {}
    for index, candidate in enumerate(candidates):
        name = str(candidate["representation"])
        prototypes = np.stack(
            [
                representations[target][name][int(true_cells[target])]
                for target in A413.TARGETS
            ]
        )
        models[str(index)] = A413.fit_frozen_model(prototypes, candidate)
    if len(models) != A413_COUNT:
        raise RuntimeError("A417 A413 source-model count differs")
    return models, bundle


def freeze_library(*, expected_implementation_sha256: str) -> dict[str, Any]:
    if any(path.exists() for path in (LIBRARY, SELECTION, RESULT, CAUSAL, REPORT)):
        raise FileExistsError("A417 library or downstream artifact already exists")
    implementation = load_implementation(expected_implementation_sha256)
    models, bundle = fit_source_models()
    a415_model = A415.load_model(A415_MODEL_SHA256)
    payload: dict[str, Any] = {
        "schema": "chacha20-round20-w50-selection-calibrated-portfolio-a417-library-v1",
        "attempt_id": ATTEMPT_ID,
        "library_state": "A401_only_frozen_before_any_A417_A412_selection_score",
        "design_sha256": DESIGN_SHA256,
        "implementation_sha256": expected_implementation_sha256,
        "implementation_commitment_sha256": implementation[
            "implementation_commitment_sha256"
        ],
        "candidate_family_commitment_sha256": implementation[
            "candidate_family_commitment_sha256"
        ],
        "A413_source_models": models,
        "A413_source_model_count": len(models),
        "xor_template": a415_model["xor_template"],
        "xor_template_float64le_sha256": a415_model[
            "xor_template_float64le_sha256"
        ],
        "knownkey_field_commitments": bundle["field_commitments"],
        "knownkey_prototype_commitments": bundle["prototype_commitments"],
        "A412_selection_fields_used": 0,
        "A412_selection_labels_used": 0,
        "A412_holdout_fields_or_labels_used": 0,
        "anchors": {
            "design": anchor(DESIGN, DESIGN_SHA256),
            "implementation": anchor(IMPLEMENTATION, expected_implementation_sha256),
            "A413_model": anchor(A413_MODEL, A413_MODEL_SHA256),
            "A415_model": anchor(A415_MODEL, A415_MODEL_SHA256),
            "A416_model": anchor(A416_MODEL, A416_MODEL_SHA256),
            "A412_protocol": anchor(A412_PROTOCOL, A412_PROTOCOL_SHA256),
            "runner": anchor(Path(__file__)),
        },
    }
    payload["library_commitment_sha256"] = canonical_sha256(payload)
    atomic_json(LIBRARY, payload)
    return payload


def load_library(expected_sha256: str | None = None) -> dict[str, Any]:
    if expected_sha256 is not None and file_sha256(LIBRARY) != expected_sha256:
        raise RuntimeError("A417 library hash differs")
    value = json.loads(LIBRARY.read_bytes())
    template = np.asarray(value.get("xor_template"), dtype=np.float64)
    if (
        value.get("schema")
        != "chacha20-round20-w50-selection-calibrated-portfolio-a417-library-v1"
        or value.get("attempt_id") != ATTEMPT_ID
        or value.get("A413_source_model_count") != A413_COUNT
        or set(value.get("A413_source_models", {}))
        != {str(index) for index in range(A413_COUNT)}
        or template.shape != (CELLS, 8)
        or sha256(template.astype("<f8").tobytes())
        != value.get("xor_template_float64le_sha256")
        or value.get("A412_selection_fields_used") != 0
        or value.get("A412_selection_labels_used") != 0
        or value.get("A412_holdout_fields_or_labels_used") != 0
    ):
        raise RuntimeError("A417 library semantics differ")
    load_implementation(value["implementation_sha256"])
    unsigned = {key: item for key, item in value.items() if key != "library_commitment_sha256"}
    if value.get("library_commitment_sha256") != canonical_sha256(unsigned):
        raise RuntimeError("A417 library commitment differs")
    return value


def polarity_weights(top_k: int, family: str) -> np.ndarray:
    if top_k not in TOP_K or family not in WEIGHT_FAMILIES:
        raise ValueError("A417 polarity weight request differs")
    if family == "uniform":
        return np.ones(top_k, dtype=np.float64)
    return 1.0 / np.sqrt(np.arange(1, top_k + 1, dtype=np.float64))


def landscape_orders(
    rank_matrix: np.ndarray, library: Mapping[str, Any]
) -> tuple[np.ndarray, list[int], list[int], list[int]]:
    field = A415.standardize_landscape(rank_matrix)
    template = np.asarray(library["xor_template"], dtype=np.float64)
    scores = A415.xor_correlation_scores(field, template)
    positive, negative = A415.polarity_orders(scores)
    folded = A416.folded_order(positive, negative)
    return scores, positive, negative, folded


def pilot_orders(
    rank_matrix: np.ndarray,
    library: Mapping[str, Any],
    indices: Sequence[int],
) -> tuple[dict[int, list[int]], dict[int, np.ndarray]]:
    wanted = tuple(sorted({int(index) for index in indices}))
    if any(index < 0 or index >= A413_COUNT for index in wanted):
        raise ValueError("A417 pilot index differs")
    representations = A410.representation_matrices(np.asarray(rank_matrix, dtype=np.int64))
    orders: dict[int, list[int]] = {}
    ranks: dict[int, np.ndarray] = {}
    for index in wanted:
        model = library["A413_source_models"][str(index)]
        name = str(model["candidate"]["representation"])
        score = A413.score_frozen_model(representations[name], model)
        order = A413.exact_score_order(score)
        orders[index] = order
        ranks[index] = np.asarray(A401.rank_vector(order), dtype=np.int64)
    return orders, ranks


def exact_numeric_rank(values: np.ndarray, cell: int) -> int:
    scores = np.asarray(values, dtype=np.float64)
    if scores.shape != (CELLS,) or not np.isfinite(scores).all() or not 0 <= cell < CELLS:
        raise ValueError("A417 numeric rank input differs")
    target = scores[cell]
    cells = np.arange(CELLS, dtype=np.int64)
    return 1 + int(np.count_nonzero(scores < target)) + int(
        np.count_nonzero((scores == target) & (cells < cell))
    )


def field_truth_ranks(
    rank_matrix: np.ndarray, library: Mapping[str, Any], true_cell: int
) -> tuple[np.ndarray, dict[str, Any]]:
    if not 0 <= true_cell < CELLS:
        raise ValueError("A417 true cell differs")
    xor_scores, positive, negative, folded = landscape_orders(rank_matrix, library)
    orders, pilot_rank = pilot_orders(rank_matrix, library, range(A413_COUNT))
    positive_rank = np.asarray(A401.rank_vector(positive), dtype=np.int64)
    negative_rank = np.asarray(A401.rank_vector(negative), dtype=np.int64)
    folded_rank = np.asarray(A401.rank_vector(folded), dtype=np.int64)
    truth = np.empty(CANDIDATE_COUNT, dtype=np.int64)
    truth[:A413_COUNT] = [pilot_rank[index][true_cell] for index in range(A413_COUNT)]
    truth[POSITIVE_INDEX] = positive_rank[true_cell]
    truth[NEGATIVE_INDEX] = negative_rank[true_cell]
    truth[FOLDED_INDEX] = folded_rank[true_cell]
    cursor = POLARITY_START
    polarity_decisions: list[int] = []
    for pilot in range(A413_COUNT):
        order = np.asarray(orders[pilot], dtype=np.int64)
        for top_k in TOP_K:
            top = order[:top_k]
            for family in WEIGHT_FAMILIES:
                statistic = float(np.dot(xor_scores[top], polarity_weights(top_k, family)))
                choose_positive = statistic >= 0.0
                truth[cursor] = (
                    positive_rank[true_cell]
                    if choose_positive
                    else negative_rank[true_cell]
                )
                polarity_decisions.append(1 if choose_positive else -1)
                cursor += 1
    log_fold = np.log2(folded_rank.astype(np.float64))
    for pilot in range(A413_COUNT):
        log_pilot = np.log2(pilot_rank[pilot].astype(np.float64))
        for alpha in COPULA_ALPHAS:
            truth[cursor] = exact_numeric_rank(alpha * log_pilot + log_fold, true_cell)
            cursor += 1
    if cursor != CANDIDATE_COUNT or np.any(truth < 1) or np.any(truth > CELLS):
        raise RuntimeError("A417 candidate truth-rank table differs")
    pilot_rank_matrix = np.stack([pilot_rank[index] for index in range(A413_COUNT)])
    return truth, {
        "pilot_rank_matrix_int32le_sha256": sha256(
            pilot_rank_matrix.astype("<i4").tobytes()
        ),
        "xor_score_float64le_sha256": sha256(xor_scores.astype("<f8").tobytes()),
        "xor_positive_order_uint16be_sha256": uint16be_sha256(positive),
        "xor_negative_order_uint16be_sha256": uint16be_sha256(negative),
        "xor_folded_order_uint16be_sha256": uint16be_sha256(folded),
        "polarity_decision_int8_sha256": sha256(
            np.asarray(polarity_decisions, dtype=np.int8).tobytes()
        ),
        "candidate_truth_rank_int32le_sha256": sha256(truth.astype("<i4").tobytes()),
    }


def greedy_portfolio(rank_table: np.ndarray) -> dict[str, Any]:
    table = np.asarray(rank_table, dtype=np.int64)
    if table.ndim != 2 or table.shape[1] != CANDIDATE_COUNT:
        raise ValueError("A417 selection rank table differs")
    if np.any(table < 1) or np.any(table > CELLS):
        raise ValueError("A417 selection rank bounds differ")
    selected: list[int] = []
    current: np.ndarray | None = None
    steps = []
    for step in range(WORKERS):
        choices = []
        for candidate in range(CANDIDATE_COUNT):
            if candidate in selected:
                continue
            panel = table[:, candidate] if current is None else np.minimum(
                current, table[:, candidate]
            )
            mean_log = float(np.log2(panel.astype(np.float64)).mean())
            choices.append((mean_log, int(panel.max()), candidate, panel))
        mean_log, worst, winner, panel = min(choices, key=lambda row: row[:3])
        selected.append(winner)
        current = panel.copy()
        steps.append(
            {
                "step": step,
                "selected_canonical_index": winner,
                "selected_candidate": candidate_specs()[winner],
                "geometric_mean_parallel_rank": 2.0**mean_log,
                "worst_parallel_rank": worst,
                "pointwise_minimum_ranks": panel.tolist(),
            }
        )
    if current is None or len(selected) != WORKERS:
        raise RuntimeError("A417 greedy portfolio is empty")
    return {
        "selected_canonical_indices": selected,
        "selected_candidates": [candidate_specs()[index] for index in selected],
        "steps": steps,
        "pointwise_minimum_panel": metric_panel(current.tolist()),
    }


def freeze_selection(
    *, expected_implementation_sha256: str, expected_library_sha256: str
) -> dict[str, Any]:
    if any(path.exists() for path in (SELECTION, RESULT, CAUSAL, REPORT)):
        raise FileExistsError("A417 selection or downstream artifact already exists")
    implementation = load_implementation(expected_implementation_sha256)
    library = load_library(expected_library_sha256)
    protocol = A412.load_protocol(A412_PROTOCOL_SHA256)
    for target in A412.SELECTION_TARGETS:
        A412.load_fresh_complete(target, protocol)
    labels = A412.load_label(
        A412.SELECTION_LABELS,
        "chacha20-round20-w50-fresh-hybrid-reader-a412-selection-labels-v1",
        A412.SELECTION_TARGETS,
    )
    truth = np.empty((len(A412.SELECTION_TARGETS), CANDIDATE_COUNT), dtype=np.int64)
    field_commitments: dict[str, Any] = {}
    reader_commitments: dict[str, Any] = {}
    for row_index, target in enumerate(A412.SELECTION_TARGETS):
        rank_matrix, field_commitments[str(target)] = A412.fresh_rank_matrix(target)
        values, reader_commitments[str(target)] = field_truth_ranks(
            rank_matrix, library, int(labels[target]["true_direct12_cell"])
        )
        truth[row_index] = values
        print(f"A417 selection target {target}/15 complete", flush=True)
    portfolio = greedy_portfolio(truth)
    payload: dict[str, Any] = {
        "schema": "chacha20-round20-w50-selection-calibrated-portfolio-a417-selection-v1",
        "attempt_id": ATTEMPT_ID,
        "selection_state": "frozen_after_A412_targets_0_15_before_any_A417_holdout_field_label_or_score",
        "design_sha256": DESIGN_SHA256,
        "implementation_sha256": expected_implementation_sha256,
        "implementation_commitment_sha256": implementation[
            "implementation_commitment_sha256"
        ],
        "library_sha256": expected_library_sha256,
        "library_commitment_sha256": library["library_commitment_sha256"],
        "candidate_family_commitment_sha256": implementation[
            "candidate_family_commitment_sha256"
        ],
        "portfolio_selection": portfolio,
        "selection_truth_rank_table_int32le_sha256": sha256(
            truth.astype("<i4").tobytes()
        ),
        "selection_field_commitments": field_commitments,
        "selection_reader_commitments": reader_commitments,
        "A412_selection_fields_used": len(A412.SELECTION_TARGETS),
        "A412_selection_labels_used": len(A412.SELECTION_TARGETS),
        "A412_holdout_fields_used": 0,
        "A412_holdout_labels_used": 0,
        "selection_candidate_refits": 0,
        "anchors": {
            "design": anchor(DESIGN, DESIGN_SHA256),
            "implementation": anchor(IMPLEMENTATION, expected_implementation_sha256),
            "library": anchor(LIBRARY, expected_library_sha256),
            "protocol": anchor(A412_PROTOCOL, A412_PROTOCOL_SHA256),
            "selection_labels": anchor(A412.SELECTION_LABELS),
            "runner": anchor(Path(__file__)),
        },
    }
    payload["selection_commitment_sha256"] = canonical_sha256(payload)
    atomic_json(SELECTION, payload)
    return payload


def load_selection(expected_sha256: str | None = None) -> dict[str, Any]:
    if expected_sha256 is not None and file_sha256(SELECTION) != expected_sha256:
        raise RuntimeError("A417 selection hash differs")
    value = json.loads(SELECTION.read_bytes())
    portfolio = value.get("portfolio_selection", {})
    selected = tuple(portfolio.get("selected_canonical_indices", []))
    if (
        value.get("schema")
        != "chacha20-round20-w50-selection-calibrated-portfolio-a417-selection-v1"
        or value.get("attempt_id") != ATTEMPT_ID
        or len(selected) != WORKERS
        or len(set(selected)) != WORKERS
        or any(index < 0 or index >= CANDIDATE_COUNT for index in selected)
        or value.get("A412_selection_fields_used") != 16
        or value.get("A412_selection_labels_used") != 16
        or value.get("A412_holdout_fields_used") != 0
        or value.get("A412_holdout_labels_used") != 0
        or value.get("selection_candidate_refits") != 0
    ):
        raise RuntimeError("A417 selection semantics differ")
    load_implementation(value["implementation_sha256"])
    load_library(value["library_sha256"])
    unsigned = {
        key: item for key, item in value.items() if key != "selection_commitment_sha256"
    }
    if value.get("selection_commitment_sha256") != canonical_sha256(unsigned):
        raise RuntimeError("A417 selection commitment differs")
    return value


def selected_orders(
    rank_matrix: np.ndarray,
    library: Mapping[str, Any],
    selection: Mapping[str, Any],
) -> dict[str, list[int]]:
    specs = selection["portfolio_selection"]["selected_candidates"]
    pilots = [
        int(spec["pilot_index"])
        for spec in specs
        if "pilot_index" in spec
    ]
    xor_scores, positive, negative, folded = landscape_orders(rank_matrix, library)
    orders, ranks = pilot_orders(rank_matrix, library, pilots)
    folded_rank = np.asarray(A401.rank_vector(folded), dtype=np.int64)
    log_fold = np.log2(folded_rank.astype(np.float64))
    cells = np.arange(CELLS, dtype=np.int64)
    selected: dict[str, list[int]] = {}
    for spec in specs:
        index = int(spec["canonical_index"])
        family = str(spec["family"])
        role = f"A417_candidate_{index:04d}"
        if family == "A413_original":
            order = orders[int(spec["pilot_index"])]
        elif family == "xor_positive":
            order = positive
        elif family == "xor_negative":
            order = negative
        elif family == "xor_folded_negative_first":
            order = folded
        elif family == "pilot_calibrated_polarity":
            pilot = int(spec["pilot_index"])
            top_k = int(spec["top_k"])
            top = np.asarray(orders[pilot][:top_k], dtype=np.int64)
            statistic = float(
                np.dot(
                    xor_scores[top],
                    polarity_weights(top_k, str(spec["weight_family"])),
                )
            )
            order = positive if statistic >= 0.0 else negative
        elif family == "pilot_fold_rank_copula":
            pilot = int(spec["pilot_index"])
            score = (
                float(spec["alpha"])
                * np.log2(ranks[pilot].astype(np.float64))
                + log_fold
            )
            order = exact_order(np.lexsort((cells, score)).tolist())
        else:
            raise RuntimeError("A417 selected candidate family differs")
        selected[role] = exact_order(order)
    if len(selected) != WORKERS:
        raise RuntimeError("A417 selected order count differs")
    return selected


def prove_schedule(
    owners: Mapping[str, Any], work: Mapping[str, Any], roles: Sequence[str]
) -> dict[str, Any]:
    proof = A415.prove_schedule(owners, work, roles)
    proof["depth_bound"] = "D_A417(c) <= D_owner(c) <= min_i R_i(c)"
    proof["total_work_bound"] = "W_A417(c) <= 8*min_i R_i(c)"
    return proof


def build_causal(payload: Mapping[str, Any]) -> dict[str, Any]:
    sys.path.insert(0, str(DOTCAUSAL_SRC))
    from dotcausal.io import CausalReader, CausalWriter

    qualified = bool(payload["external_transfer"]["qualified"])
    terminal = (
        "A417_holdout_qualified_selection_calibrated_scheduler"
        if qualified
        else "A417_holdout_boundary_retained_selection_signal"
    )
    writer = CausalWriter(api_id="a417w50")
    writer._rules = []
    writer.add_rule(
        name="weak_location_to_landscape_polarity",
        description="Use a frozen A413 pilot order to calibrate the global sign of an A415 XOR-aligned landscape.",
        pattern=["A413_weak_location_order", "A415_signed_XOR_landscape"],
        conclusion="A417_pilot_calibrated_landscape_reader",
        confidence_modifier=1.0,
    )
    writer.add_rule(
        name="fresh_selection_to_eight_reader_portfolio",
        description="Select eight complementary Readers on A412 targets zero through fifteen while retaining the holdout boundary.",
        pattern=["A417_frozen_2793_reader_library", "A412_selection_fields_0_15"],
        conclusion="A417_frozen_eight_reader_portfolio",
        confidence_modifier=1.0,
    )
    writer.add_rule(
        name="frozen_portfolio_to_holdout_scheduler",
        description="Apply the selected portfolio unchanged to targets sixteen through thirty-one and materialize an exact eight-worker schedule.",
        pattern=["A417_frozen_eight_reader_portfolio", "A412_holdout_fields_16_31"],
        conclusion=terminal,
        confidence_modifier=1.0,
    )
    writer.add_triplet(
        trigger="A401:known_key_point_and_landscape_geometry",
        mechanism="pilot_localization_then_signed_landscape_calibration",
        outcome="A417:frozen_2793_reader_library",
        confidence=1.0,
        source=payload["library_sha256"],
        quantification=json.dumps(payload["selection_summary"], sort_keys=True),
        evidence="all source models and candidate formulas frozen before selection scoring",
        domain="full-round ChaCha20 W50 causal Reader composition",
        quality_score=1.0,
    )
    writer.add_triplet(
        trigger="A417:frozen_2793_reader_library",
        mechanism="fresh_selection_only_greedy_eight_reader_composition",
        outcome="A417:frozen_eight_reader_portfolio",
        confidence=1.0,
        source=payload["selection_sha256"],
        quantification=json.dumps(payload["selection_summary"], sort_keys=True),
        evidence="sixteen selection labels used; zero holdout fields, labels, refits, or assignments",
        domain="full-round ChaCha20 W50 prospective portfolio learning",
        quality_score=1.0,
    )
    writer.add_triplet(
        trigger="A417:frozen_eight_reader_portfolio",
        mechanism="untouched_holdout_transfer_plus_exact_parallel_scheduler",
        outcome=f"A417:{terminal}",
        confidence=1.0,
        source=payload["external_measurement_sha256"],
        quantification=json.dumps(payload["external_transfer"], sort_keys=True),
        evidence="portfolio frozen before any A417 holdout field or label was consumed",
        domain="full-round ChaCha20 W50 parallel recovery scheduling",
        quality_score=1.0,
    )
    writer.add_triplet(
        trigger="A401:known_key_point_and_landscape_geometry",
        mechanism="materialized_selection_calibrated_external_scheduler_closure",
        outcome=f"A417:{terminal}",
        confidence=1.0,
        source="materialized:A417_selection_calibrated_chain",
        quantification="exact retained closure",
        evidence="design, implementation, library, selection, holdout, and scheduler commitments",
        domain="AI-native retained inference",
        quality_score=1.0,
        is_inferred=True,
    )
    writer.add_cluster(
        name="A417 selection-calibrated W50 scheduler",
        entities=[
            "A401:known_key_point_and_landscape_geometry",
            "A417:frozen_2793_reader_library",
            "A417:frozen_eight_reader_portfolio",
            f"A417:{terminal}",
        ],
    )
    writer.add_gap(
        subject=f"A417:{terminal}",
        predicate="next_required_object",
        expected_object_type=(
            "shared_stop_execution_of_eight_frozen_A417_worker_lists"
            if qualified
            else "larger_selection_corpus_or_continuous_polarity_calibrator"
        ),
        confidence=1.0,
        suggested_queries=[
            "Execute the exact A417 worker lists with one shared confirmed stop."
            if qualified
            else "Expand the known-key selection corpus and replace hard polarity with calibrated posterior scheduling."
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
        reader.api_id != "a417w50"
        or len(explicit) != 3
        or len(all_rows) != 4
        or len(inferred) != 1
        or len(reader._rules) != 3
        or len(reader._clusters) != 1
        or len(reader._gaps) != 1
    ):
        raise RuntimeError("A417 authentic Causal reopen gate failed")
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
            "mechanism": explicit[0],
            "selection": explicit[1],
            "external_scheduler": explicit[2],
            "terminal_chain": all_rows[-1],
            "next_gap": reader._gaps[0],
        },
    }


def evaluate_external(
    *,
    expected_implementation_sha256: str,
    expected_library_sha256: str,
    expected_selection_sha256: str,
) -> dict[str, Any]:
    if any(path.exists() for path in (RESULT, CAUSAL, REPORT)):
        raise FileExistsError("A417 result already exists")
    implementation = load_implementation(expected_implementation_sha256)
    library = load_library(expected_library_sha256)
    selection = load_selection(expected_selection_sha256)
    protocol = A412.load_protocol(A412_PROTOCOL_SHA256)
    for target in A412.TARGETS:
        A412.load_fresh_complete(target, protocol)
    labels = A412.load_label(
        A412.HOLDOUT_LABELS,
        "chacha20-round20-w50-fresh-hybrid-reader-a412-holdout-labels-v1",
        A412.HOLDOUT_TARGETS,
    )
    a414_model = A414.load_portfolio(A414.A414_MODEL_SHA256)
    a415_model = A415.load_model(A415_MODEL_SHA256)
    a416_model = A416.load_model(A416_MODEL_SHA256)
    learned_depths: list[int] = []
    baselines: dict[str, list[int]] = {"A414": [], "A415": [], "A416": []}
    field_commitments: dict[str, Any] = {}
    reader_commitments: dict[str, Any] = {}
    for target in A412.HOLDOUT_TARGETS:
        rank_matrix, field_commitments[str(target)] = A412.fresh_rank_matrix(target)
        cell = int(labels[target]["true_direct12_cell"])
        learned = selected_orders(rank_matrix, library, selection)
        baseline_orders = {
            "A414": A414.portfolio_orders(rank_matrix, a414_model),
            "A415": A415.portfolio_orders(rank_matrix, a415_model),
            "A416": A416.portfolio_orders(rank_matrix, a416_model),
        }
        learned_ranks = {
            role: int(A401.rank_vector(order)[cell]) for role, order in learned.items()
        }
        learned_depths.append(min(learned_ranks.values()))
        baseline_ranks: dict[str, dict[str, int]] = {}
        for name, orders in baseline_orders.items():
            row = {
                role: int(A401.rank_vector(order)[cell]) for role, order in orders.items()
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
        "primary_untouched_holdout_A417_panel": learned_panel,
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
    with A412.a401_paths(A412.ORIGINAL_A401_ARTIFACTS, A412.ORIGINAL_A401_MEASUREMENTS):
        production_ranks, _baseline_views, production_metadata = A402.production_rank_matrix()
    production_orders = selected_orders(production_ranks, library, selection)
    roles = tuple(production_orders)
    owners = A414.minimum_rank_owner_lanes(production_orders, roles)
    work = A414.balanced_static_worker_schedule(owners["owner_lane_orders"], roles)
    proof = prove_schedule(owners, work, roles)
    owner_commitment = canonical_sha256(
        {
            "owner_lane_sizes": owners["owner_lane_sizes"],
            "owner_lane_order_uint16be_sha256": owners[
                "owner_lane_order_uint16be_sha256"
            ],
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
        "schema": "chacha20-round20-w50-selection-calibrated-portfolio-a417-result-v1",
        "attempt_id": ATTEMPT_ID,
        "evidence_stage": (
            "UNTOUCHED_HOLDOUT_QUALIFIED_SELECTION_CALIBRATED_OPTIMAL_SCHEDULER"
            if qualified
            else "UNTOUCHED_HOLDOUT_BOUNDARY_WITH_RETAINED_SELECTION_SIGNAL"
        ),
        "design_sha256": DESIGN_SHA256,
        "implementation_sha256": expected_implementation_sha256,
        "implementation_commitment_sha256": implementation[
            "implementation_commitment_sha256"
        ],
        "library_sha256": expected_library_sha256,
        "library_commitment_sha256": library["library_commitment_sha256"],
        "selection_sha256": expected_selection_sha256,
        "selection_commitment_sha256": selection["selection_commitment_sha256"],
        "selection_summary": selection["portfolio_selection"],
        "external_transfer": external,
        "source_role_order": list(roles),
        "source_order_uint16be_sha256": owners["source_order_uint16be_sha256"],
        "owner_lane_orders": owners["owner_lane_orders"],
        "owner_lane_sizes": owners["owner_lane_sizes"],
        "owner_lane_order_uint16be_sha256": owners[
            "owner_lane_order_uint16be_sha256"
        ],
        "worker_tasks": work["worker_tasks"],
        "worker_cell_orders": work["worker_cell_orders"],
        "worker_task_counts": work["worker_task_counts"],
        "worker_stolen_task_counts": work["worker_stolen_task_counts"],
        "worker_cell_order_uint16be_sha256": work[
            "worker_cell_order_uint16be_sha256"
        ],
        "worker_task_list_sha256": work["worker_task_list_sha256"],
        "cell_epoch_one_based": work["cell_epoch_one_based"],
        "cell_worker_role": work["cell_worker_role"],
        "cell_owner_queue_role": work["cell_owner_queue_role"],
        "cell_owner_queue_position_one_based": work[
            "cell_owner_queue_position_one_based"
        ],
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
        "holdout_reader_refits": 0,
        "production_target_labels_used": 0,
        "production_reader_refits": 0,
        "production_candidate_assignments_executed": 0,
        "live_recovery_filter_outcomes_or_results_consumed": False,
        "anchors": {
            "design": anchor(DESIGN, DESIGN_SHA256),
            "implementation": anchor(IMPLEMENTATION, expected_implementation_sha256),
            "library": anchor(LIBRARY, expected_library_sha256),
            "selection": anchor(SELECTION, expected_selection_sha256),
            "A412_protocol": anchor(A412_PROTOCOL, A412_PROTOCOL_SHA256),
            "A388_order": anchor(A388_ORDER, A388_ORDER_SHA256),
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
            "# A417 — selection-calibrated W50 portfolio\n\n"
            f"Evidence stage: **{payload['evidence_stage']}**\n\n"
            f"- Selected canonical Readers: **{selection['portfolio_selection']['selected_canonical_indices']}**\n"
            f"- Selection ranks: **{selection['portfolio_selection']['pointwise_minimum_panel']['ranks']}**\n"
            f"- Untouched holdout A417 ranks: **{learned_panel['ranks']}**\n"
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
    payload: dict[str, Any] = {
        "attempt_id": ATTEMPT_ID,
        "design_sha256": DESIGN_SHA256,
        "candidate_count": CANDIDATE_COUNT,
        "implementation_frozen": IMPLEMENTATION.exists(),
        "library_frozen": LIBRARY.exists(),
        "selection_frozen": SELECTION.exists(),
        "result_complete": RESULT.exists(),
    }
    if IMPLEMENTATION.exists():
        payload["implementation_sha256"] = file_sha256(IMPLEMENTATION)
        load_implementation(payload["implementation_sha256"])
    if LIBRARY.exists():
        payload["library_sha256"] = file_sha256(LIBRARY)
        load_library(payload["library_sha256"])
    if SELECTION.exists():
        payload["selection_sha256"] = file_sha256(SELECTION)
        selection = load_selection(payload["selection_sha256"])
        payload["portfolio_selection"] = selection["portfolio_selection"]
    if RESULT.exists():
        value = json.loads(RESULT.read_bytes())
        payload["evidence_stage"] = value["evidence_stage"]
        payload["external_transfer"] = value["external_transfer"]
        payload["schedule_proof"] = value["schedule_proof"]
        payload["causal"] = value["causal"]
    return payload


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--freeze-implementation", action="store_true")
    parser.add_argument("--freeze-library", action="store_true")
    parser.add_argument("--select", action="store_true")
    parser.add_argument("--evaluate-external", action="store_true")
    parser.add_argument("--analyze", action="store_true")
    parser.add_argument("--expected-implementation-sha256")
    parser.add_argument("--expected-library-sha256")
    parser.add_argument("--expected-selection-sha256")
    args = parser.parse_args()
    modes = sum(
        int(flag)
        for flag in (
            args.freeze_implementation,
            args.freeze_library,
            args.select,
            args.evaluate_external,
            args.analyze,
        )
    )
    if modes != 1:
        parser.error("choose exactly one A417 mode")
    if args.freeze_implementation:
        payload = freeze_implementation()
    elif args.freeze_library:
        if not args.expected_implementation_sha256:
            parser.error("--freeze-library requires --expected-implementation-sha256")
        payload = freeze_library(
            expected_implementation_sha256=args.expected_implementation_sha256
        )
    elif args.select:
        if not args.expected_implementation_sha256 or not args.expected_library_sha256:
            parser.error("--select requires implementation and library hashes")
        payload = freeze_selection(
            expected_implementation_sha256=args.expected_implementation_sha256,
            expected_library_sha256=args.expected_library_sha256,
        )
    elif args.evaluate_external:
        if (
            not args.expected_implementation_sha256
            or not args.expected_library_sha256
            or not args.expected_selection_sha256
        ):
            parser.error("--evaluate-external requires implementation, library, and selection hashes")
        payload = evaluate_external(
            expected_implementation_sha256=args.expected_implementation_sha256,
            expected_library_sha256=args.expected_library_sha256,
            expected_selection_sha256=args.expected_selection_sha256,
        )
    else:
        payload = analyze()
    print(json.dumps(payload, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""Evaluate the frozen A250 nonlinear fresh-state Product-of-Experts reader."""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import math
import os
import sys
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

import numpy as np

from arx_carry_leak.fresh_candidate_nonlinear import (
    DiagonalGaussianPoE,
    fit_diagonal_gaussian_poe,
)
from arx_carry_leak.fresh_candidate_reader import (
    FEATURE_NAMES,
    CandidateFeatureTable,
    build_feature_table,
    descending_midrank,
)

ROOT = Path(__file__).parents[2]
PROTOCOL = ROOT / "research/configs/chacha20_round20_fresh_nonlinear_poe_v1.json"
PROTOCOL_SHA256 = "4684a3ad7fba524069bcd6af5390e71e33b141f17de061068887e7a5af722aa4"
RESULT = ROOT / "research/results/v1/chacha20_round20_fresh_nonlinear_poe_v1.json"
CAUSAL = ROOT / "research/results/v1/chacha20_round20_fresh_nonlinear_poe_v1.causal"
REPORT = ROOT / "research/reports/CAUSAL_CHACHA20_ROUND20_FRESH_NONLINEAR_POE_V1.md"
DEFAULT_DOTCAUSAL_SRC = Path(
    "/Users/bhkmie/Documents/Forschung/O1/vendor/fabel/dotcausal_package/src"
)
ATTEMPT_ID = "A250"
SCHEMA = "chacha20-round20-fresh-nonlinear-poe-result-v1"


def _sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _file_sha256(path: Path) -> str:
    return _sha256(path.read_bytes())


def _canonical_bytes(value: Any) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode()


def _canonical_sha256(value: Any) -> str:
    return _sha256(_canonical_bytes(value))


def _atomic_bytes(path: Path, raw: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.tmp")
    with temporary.open("wb") as handle:
        handle.write(raw)
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(temporary, path)


def _atomic_json(path: Path, value: Any) -> None:
    _atomic_bytes(
        path,
        json.dumps(
            value,
            indent=2,
            sort_keys=True,
            ensure_ascii=True,
            allow_nan=False,
        ).encode()
        + b"\n",
    )


def _import_path(path: Path, name: str) -> Any:
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot import A250 dependency {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _load_protocol() -> tuple[dict[str, Any], Any]:
    if _file_sha256(PROTOCOL) != PROTOCOL_SHA256:
        raise RuntimeError("A250 protocol hash differs")
    protocol = json.loads(PROTOCOL.read_bytes())
    operator = protocol.get("operator", {})
    evaluation = protocol.get("evaluation", {})
    boundary = protocol.get("information_boundary", {})
    if (
        protocol.get("schema")
        != "chacha20-round20-fresh-nonlinear-poe-protocol-v1"
        or protocol.get("attempt_id") != ATTEMPT_ID
        or protocol.get("protocol_state")
        != "frozen_after_A249_personal_causal_readback_and_before_any_nonlinear_PoE_fit"
        or operator.get("feature_count", 144) != len(FEATURE_NAMES)
        or operator.get("candidate_numeric_value_or_bits_included") is not False
        or operator.get("prefix_suffix_label_or_low20_included_as_feature") is not False
        or operator.get("positive_variance_shrinkage_grid")
        != [0.0, 0.25, 0.5, 0.75, 0.9]
        or operator.get("expert_log_ratio_cap_grid") != [0.25, 0.5, 1.0, 2.0]
        or len(evaluation.get("outer_prefix_groups", [])) != 5
        or boundary.get("any_nonlinear_PoE_fit_before_protocol_freeze") is not False
        or boundary.get("candidate_identity_feature_available_to_model") is not False
        or boundary.get("prospective_unknown_target_generated_or_opened") is not False
    ):
        raise RuntimeError("A250 protocol semantic gate failed")
    anchors = protocol["anchors"]
    pairs = [
        ("A242_protocol_path", "A242_protocol_sha256"),
        ("A242_runner_path", "A242_runner_sha256"),
        ("A242_result_path", "A242_result_sha256"),
        ("A249_protocol_path", "A249_protocol_sha256"),
        ("A249_runner_path", "A249_runner_sha256"),
        ("A249_result_path", "A249_result_sha256"),
        ("A249_causal_path", "A249_causal_sha256"),
        ("feature_reader_path", "feature_reader_sha256"),
        ("nonlinear_reader_path", "nonlinear_reader_sha256"),
        ("nonlinear_reader_test_path", "nonlinear_reader_test_sha256"),
    ]
    if any(_file_sha256(ROOT / anchors[path]) != anchors[digest] for path, digest in pairs):
        raise RuntimeError("A250 anchor hash differs")
    a242 = _import_path(ROOT / anchors["A242_runner_path"], "a250_a242_reader")
    return protocol, a242


def analyze() -> dict[str, Any]:
    protocol, _ = _load_protocol()
    return {
        "attempt_id": ATTEMPT_ID,
        "protocol_sha256": PROTOCOL_SHA256,
        "operator_settings": len(protocol["operator"]["positive_variance_shrinkage_grid"])
        * len(protocol["operator"]["expert_log_ratio_cap_grid"]),
        "outer_prefix_folds": len(protocol["evaluation"]["outer_prefix_groups"]),
        "model_fit_started": False,
    }


def _load_tables(protocol: Mapping[str, Any], a242: Any) -> list[CandidateFeatureTable]:
    a242_protocol = json.loads((ROOT / protocol["anchors"]["A242_protocol_path"]).read_bytes())
    tables = []
    for label in a242_protocol["validation"]["labels"]:
        path = a242._measurement_path(label, "numeric")
        if not path.is_file():
            raise FileNotFoundError(f"A250 requires completed A242 shard: {path.name}")
        measurement = a242._read_measurement(path)
        if (
            measurement.get("label") != label
            or measurement.get("order_name") != "numeric"
            or measurement.get("complete_candidate_cover") is not True
        ):
            raise RuntimeError("A250 A242 measurement identity differs")
        tables.append(build_feature_table(measurement))
    if len(tables) != 20 or len({table.label for table in tables}) != 20:
        raise RuntimeError("A250 requires twenty unique feature tables")
    return tables


def _prefix_index(label: str) -> int:
    marker = "a220_select_p"
    if not label.startswith(marker):
        raise ValueError("A250 label is not a select-prefix row")
    return int(label[len(marker) : len(marker) + 2])


def _score_tables(
    model: DiagonalGaussianPoE, tables: Sequence[CandidateFeatureTable]
) -> list[dict[str, Any]]:
    rows = []
    for table in tables:
        scores = model.scores(table.matrix)
        rows.append(
            {
                "label": table.label,
                "prefix_index": _prefix_index(table.label),
                "true_prefix": table.true_prefix,
                "true_score": float(scores[table.true_prefix]),
                "midrank": descending_midrank(scores, table.true_prefix),
                "scores": [float(value) for value in scores],
            }
        )
    return rows


def _mean_log2(rows: Sequence[Mapping[str, Any]]) -> float:
    return sum(math.log2(float(row["midrank"])) for row in rows) / len(rows)


def _select_operator(
    training: Sequence[CandidateFeatureTable],
    shrinkages: Sequence[float],
    caps: Sequence[float],
) -> tuple[float, float, list[dict[str, Any]]]:
    groups = sorted({_prefix_index(table.label) for table in training})
    if len(groups) < 2:
        raise ValueError("A250 inner selection requires multiple prefix groups")
    ledger = []
    for shrinkage in shrinkages:
        for cap in caps:
            rows = []
            for test_group in groups:
                inner_train = [
                    table for table in training if _prefix_index(table.label) != test_group
                ]
                inner_test = [
                    table for table in training if _prefix_index(table.label) == test_group
                ]
                model = fit_diagonal_gaussian_poe(
                    inner_train,
                    positive_variance_shrinkage=shrinkage,
                    expert_log_ratio_cap=cap,
                )
                rows.extend(_score_tables(model, inner_test))
            ledger.append(
                {
                    "positive_variance_shrinkage": shrinkage,
                    "expert_log_ratio_cap": cap,
                    "inner_holdout_mean_log2_rank": _mean_log2(rows),
                    "inner_holdout_ranks": [
                        {
                            key: row[key]
                            for key in ("label", "prefix_index", "true_prefix", "midrank")
                        }
                        for row in rows
                    ],
                }
            )
    selected = min(
        ledger,
        key=lambda row: (
            row["inner_holdout_mean_log2_rank"],
            -row["positive_variance_shrinkage"],
            row["expert_log_ratio_cap"],
        ),
    )
    return (
        float(selected["positive_variance_shrinkage"]),
        float(selected["expert_log_ratio_cap"]),
        ledger,
    )


def nested_evaluate(
    tables: Sequence[CandidateFeatureTable],
    shrinkages: Sequence[float],
    caps: Sequence[float],
) -> dict[str, Any]:
    groups = sorted({_prefix_index(table.label) for table in tables})
    if len(tables) != 20 or groups != [0, 1, 2, 3, 4]:
        raise ValueError("A250 outer fold geometry differs")
    folds = []
    all_rows = []
    for outer_group in groups:
        training = [table for table in tables if _prefix_index(table.label) != outer_group]
        testing = [table for table in tables if _prefix_index(table.label) == outer_group]
        shrinkage, cap, inner_ledger = _select_operator(training, shrinkages, caps)
        model = fit_diagonal_gaussian_poe(
            training,
            positive_variance_shrinkage=shrinkage,
            expert_log_ratio_cap=cap,
        )
        scored = _score_tables(model, testing)
        model_dict = model.as_dict()
        fold = {
            "outer_prefix_index": outer_group,
            "outer_true_prefix": testing[0].true_prefix,
            "selected_positive_variance_shrinkage": shrinkage,
            "selected_expert_log_ratio_cap": cap,
            "inner_selection": inner_ledger,
            "model_sha256": _canonical_sha256(model_dict),
            "model": model_dict,
            "test_rows": scored,
            "test_mean_log2_rank": _mean_log2(scored),
        }
        folds.append(fold)
        all_rows.extend(scored)
    observed = _mean_log2(all_rows)
    shifted = []
    for xor_offset in range(256):
        ranks = []
        for row in all_rows:
            scores = np.asarray(row["scores"], dtype=np.float64)
            ranks.append(descending_midrank(scores, int(row["true_prefix"]) ^ xor_offset))
        shifted.append(sum(math.log2(rank) for rank in ranks) / len(ranks))
    uniform = sum(math.log2(rank) for rank in range(1, 257)) / 256.0
    exact_p = sum(value <= observed + 1e-15 for value in shifted) / 256.0
    return {
        "outer_folds": folds,
        "outer_holdout_rows": all_rows,
        "mean_log2_rank": observed,
        "uniform_mean_log2_rank_reference": uniform,
        "mean_log2_rank_bit_gain": uniform - observed,
        "outer_prefix_folds_with_positive_bit_gain": sum(
            uniform - fold["test_mean_log2_rank"] > 0 for fold in folds
        ),
        "shared_xor_offset_mean_log2_ranks": shifted,
        "exact_shared_xor_p": exact_p,
        "best_shared_xor_offset": min(range(256), key=shifted.__getitem__),
        "observed_offset": 0,
    }


def _build_causal(
    path: Path, payload: Mapping[str, Any], a242: Any, dotcausal_src: Path
) -> dict[str, Any]:
    CausalWriter, CausalReader, source = a242._load_dotcausal(dotcausal_src)
    evaluation = payload["evaluation"]
    retained = payload["retention_gate"]["passed"]
    outcome = (
        "A250:crossvalidated_nonlinear_PoE_signal"
        if retained
        else "A250:nonlinear_PoE_transfer_boundary"
    )
    writer = CausalWriter(api_id="a250")
    writer._rules = []
    writer.add_rule(
        name="band_shaped_candidate_signature",
        description="Class-conditional quadratic density ratios detect candidate signatures centered in a band rather than separated by one linear hyperplane.",
        pattern=["typed_orbit_features", "Gaussian_band_experts"],
        conclusion="nonlinear_candidate_evidence",
        confidence_modifier=1.0,
    )
    writer.add_rule(
        name="nested_prefix_blind_validation",
        description="Every outer prefix is scored by a PoE whose settings and parameters were selected without that prefix.",
        pattern=["inner_operator_selection", "unseen_outer_prefix"],
        conclusion="prefix_blind_nonlinear_transfer_evidence",
        confidence_modifier=1.0,
    )
    writer.add_triplet(
        trigger="A249:144_translation_equivariant_features",
        mechanism="per_feature_Gaussian_band_experts",
        outcome="A250:144_nonlinear_log_density_ratios",
        confidence=1.0,
        source=payload["protocol_sha256"],
        quantification="144 candidate-coordinate-free quadratic experts",
        evidence="Frozen after A249 causal readback and before any nonlinear PoE fit.",
        domain="nonlinear typed candidate readout",
        quality_score=1.0,
    )
    writer.add_triplet(
        trigger="A250:144_nonlinear_log_density_ratios",
        mechanism="clipped_product_of_experts",
        outcome="A250:prefix_blind_candidate_score",
        confidence=1.0,
        source=payload["analysis_sha256"],
        quantification="per-expert clipped LLR mean",
        evidence=json.dumps(payload["operator_grid"], sort_keys=True),
        domain="conditional multiview aggregation",
        quality_score=1.0,
    )
    writer.add_triplet(
        trigger="A250:prefix_blind_candidate_score",
        mechanism="nested_leave_one_prefix_out_selection",
        outcome="A250:five_unseen_prefix_models",
        confidence=1.0,
        source=payload["analysis_sha256"],
        quantification="five outer folds; twenty frozen operator settings selected only inside training folds",
        evidence=json.dumps(
            [
                {
                    "prefix": fold["outer_prefix_index"],
                    "shrinkage": fold["selected_positive_variance_shrinkage"],
                    "cap": fold["selected_expert_log_ratio_cap"],
                    "mean_log2_rank": fold["test_mean_log2_rank"],
                }
                for fold in evaluation["outer_folds"]
            ],
            sort_keys=True,
        ),
        domain="nested known-key reader selection",
        quality_score=1.0,
    )
    writer.add_triplet(
        trigger="A250:five_unseen_prefix_models",
        mechanism="unseen_prefix_ranks_plus_all_256_XOR_controls",
        outcome=outcome,
        confidence=1.0,
        source=payload["analysis_sha256"],
        quantification=(
            f"gain={evaluation['mean_log2_rank_bit_gain']:.12f}; "
            f"exact p={evaluation['exact_shared_xor_p']:.12f}"
        ),
        evidence=json.dumps(payload["retention_gate"], sort_keys=True),
        domain="exact XOR-invariant outer validation",
        quality_score=1.0,
    )
    writer.add_triplet(
        trigger="A249:144_translation_equivariant_features",
        mechanism="materialized_nonlinear_PoE_chain",
        outcome=outcome,
        confidence=1.0,
        source="materialized:band_shaped_candidate_signature+nested_prefix_blind_validation",
        quantification="four-edge closure retained in-file",
        evidence="Materialized after the complete nested outer evaluation and exact XOR controls.",
        domain="AI-native retained inference",
        quality_score=1.0,
        is_inferred=True,
    )
    writer.add_cluster(
        name="A250 nonlinear Product-of-Experts chain",
        entities=[
            "A249:144_translation_equivariant_features",
            "per_feature_Gaussian_band_experts",
            "A250:144_nonlinear_log_density_ratios",
            "clipped_product_of_experts",
            "A250:prefix_blind_candidate_score",
        ],
    )
    writer.add_cluster(
        name="A250 nested unseen-prefix chain",
        entities=[
            "nested_leave_one_prefix_out_selection",
            "A250:five_unseen_prefix_models",
            "unseen_prefix_ranks_plus_all_256_XOR_controls",
            outcome,
        ],
    )
    writer.add_gap(
        subject=outcome,
        predicate="next_required_intervention",
        expected_object_type=(
            "prospective_entirely_new_key_PoE_validation"
            if retained
            else "exact_propagated_variable_and_clause_identity_reader"
        ),
        confidence=1.0,
        suggested_queries=(
            [
                "Freeze this operator family and score entirely new disjoint prefix groups.",
                "If retained prospectively, use its frozen scores to order a new unknown target.",
            ]
            if retained
            else [
                "Which exact variable identities enter each candidate propagation cloud?",
                "Which learned-clause fingerprints recur only around correct candidate assumptions?",
            ]
        ),
    )
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.tmp")
    temporary.unlink(missing_ok=True)
    stats = writer.save(str(temporary))
    temporary.replace(path)
    reader = CausalReader(str(path), verify_integrity=True)
    explicit = reader.get_all_triplets(include_inferred=False)
    rows = reader.get_all_triplets(include_inferred=True)
    inferred = [row for row in reader._triplets if row.get("is_inferred", False)]
    if (
        reader.version != 1
        or reader.api_id != "a250"
        or len(explicit) != 4
        or len(rows) != 5
        or len(inferred) != 1
        or len(reader._rules) != 2
        or len(reader._clusters) != 2
        or len(reader._gaps) != 1
    ):
        raise RuntimeError("A250 authentic Causal Reader reopen gate failed")
    return {
        "format": "authentic_dotcausal_v1_AI_native",
        "file_sha256": _file_sha256(path),
        "file_bytes": path.stat().st_size,
        "api_id": reader.api_id,
        "explicit_triplets": len(explicit),
        "materialized_inferred_triplets": len(inferred),
        "embedded_rules": len(reader._rules),
        "clusters": len(reader._clusters),
        "gaps": len(reader._gaps),
        "integrity_verified_by_authoritative_reader": True,
        "reader_source": source,
        "writer_stats": stats,
        "personal_semantic_readback": {
            "terminal_chain": rows[-1],
            "next_gap": reader._gaps[0],
        },
    }


def _report(payload: Mapping[str, Any]) -> str:
    evaluation = payload["evaluation"]
    causal = payload["causal"]
    lines = [
        "# A250 — ChaCha20-R20 nonlinear fresh-state Product-of-Experts",
        "",
        "A frozen diagonal-Gaussian Product-of-Experts tests whether the typed A249 trajectory signal is band-shaped rather than linearly separable. Every outer prefix is absent from both model fitting and hyperparameter selection.",
        "",
        "## Result",
        "",
        f"- Evidence stage: **{payload['evidence_stage']}**",
        f"- Outer-holdout mean log2 rank: **{evaluation['mean_log2_rank']:.12f}**",
        f"- Uniform reference: **{evaluation['uniform_mean_log2_rank_reference']:.12f}**",
        f"- Rank-information gain: **{evaluation['mean_log2_rank_bit_gain']:.12f} bits**",
        f"- Exact shared-XOR p: **{evaluation['exact_shared_xor_p']:.12f}**",
        f"- Prefix folds with positive gain: **{evaluation['outer_prefix_folds_with_positive_bit_gain']} / 5**",
        f"- Best shared XOR offset: **{evaluation['best_shared_xor_offset']}**",
        "",
        "## Outer folds",
        "",
        "| Prefix | Shrinkage | Cap | Mean log2 rank | Model SHA-256 |",
        "|---:|---:|---:|---:|---|",
    ]
    for fold in evaluation["outer_folds"]:
        lines.append(
            f"| {fold['outer_prefix_index']} | {fold['selected_positive_variance_shrinkage']} | {fold['selected_expert_log_ratio_cap']} | {fold['test_mean_log2_rank']:.6f} | `{fold['model_sha256']}` |"
        )
    lines.extend(
        [
            "",
            "## Authentic AI-native Causal readback",
            "",
            f"- Reader integrity: **{causal['integrity_verified_by_authoritative_reader']}**",
            f"- Explicit / inferred: **{causal['explicit_triplets']} / {causal['materialized_inferred_triplets']}**",
            f"- Next gap: **{causal['personal_semantic_readback']['next_gap']['expected_object_type']}**",
        ]
    )
    return "\n".join(lines) + "\n"


def execute(*, dotcausal_src: Path = DEFAULT_DOTCAUSAL_SRC) -> dict[str, Any]:
    protocol, a242 = _load_protocol()
    tables = _load_tables(protocol, a242)
    operator = protocol["operator"]
    evaluation = nested_evaluate(
        tables,
        operator["positive_variance_shrinkage_grid"],
        operator["expert_log_ratio_cap_grid"],
    )
    gate = protocol["retention_gate"]
    retained = (
        evaluation["exact_shared_xor_p"] <= gate["maximum_exact_shared_xor_p"]
        and evaluation["mean_log2_rank_bit_gain"] > gate["minimum_aggregate_mean_log2_rank_bit_gain"]
        and evaluation["outer_prefix_folds_with_positive_bit_gain"]
        >= gate["minimum_outer_prefix_folds_with_positive_bit_gain"]
    )
    payload: dict[str, Any] = {
        "schema": SCHEMA,
        "attempt_id": ATTEMPT_ID,
        "evidence_stage": (
            "FULLROUND_R20_FRESH_NONLINEAR_POE_CROSSVALIDATED_SIGNAL"
            if retained
            else "FULLROUND_R20_FRESH_NONLINEAR_POE_BOUNDARY"
        ),
        "protocol_sha256": PROTOCOL_SHA256,
        "protocol_state": protocol["protocol_state"],
        "causal_derivation": protocol["causal_derivation"],
        "operator_grid": {
            "positive_variance_shrinkage": operator["positive_variance_shrinkage_grid"],
            "expert_log_ratio_cap": operator["expert_log_ratio_cap_grid"],
            "settings": len(operator["positive_variance_shrinkage_grid"])
            * len(operator["expert_log_ratio_cap_grid"]),
        },
        "evaluation": evaluation,
        "analysis_sha256": _canonical_sha256(evaluation),
        "retention_gate": {**gate, "passed": retained},
        "information_boundary": protocol["information_boundary"],
        "input_measurement_count": len(tables),
        "input_table_sha256": _canonical_sha256(
            [
                {
                    "label": table.label,
                    "true_prefix": table.true_prefix,
                    "matrix_sha256": _sha256(np.asarray(table.matrix, dtype="<f8").tobytes()),
                }
                for table in tables
            ]
        ),
    }
    payload["causal"] = _build_causal(CAUSAL, payload, a242, dotcausal_src)
    _atomic_json(RESULT, payload)
    _atomic_bytes(REPORT, _report(payload).encode())
    print(
        json.dumps(
            {
                "evidence_stage": payload["evidence_stage"],
                "mean_log2_rank": evaluation["mean_log2_rank"],
                "bit_gain": evaluation["mean_log2_rank_bit_gain"],
                "exact_shared_xor_p": evaluation["exact_shared_xor_p"],
                "positive_prefix_folds": evaluation[
                    "outer_prefix_folds_with_positive_bit_gain"
                ],
                "result": str(RESULT),
                "causal": str(CAUSAL),
            },
            indent=2,
        ),
        flush=True,
    )
    return payload


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run", action="store_true")
    parser.add_argument("--dotcausal-src", type=Path, default=DEFAULT_DOTCAUSAL_SRC)
    args = parser.parse_args()
    if args.run:
        execute(dotcausal_src=args.dotcausal_src)
    else:
        print(json.dumps(analyze(), indent=2, sort_keys=True))


if __name__ == "__main__":
    main()

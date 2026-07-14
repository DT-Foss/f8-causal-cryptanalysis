#!/usr/bin/env python3
"""Evaluate the frozen A249 multichannel fresh-state reader."""

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

from arx_carry_leak.fresh_candidate_reader import (
    FEATURE_NAMES,
    CandidateFeatureTable,
    build_feature_table,
    concatenate_training,
    descending_midrank,
)
from arx_carry_leak.key_atlas import RidgeLogisticModel, fit_ridge_logistic

ROOT = Path(__file__).parents[2]
PROTOCOL = ROOT / "research/configs/chacha20_round20_fresh_multichannel_reader_v1.json"
PROTOCOL_SHA256 = "1fb24cbf34150e21132b409bd3fc7c7dfb5a77fb5016d272994010e1feb7e261"
RESULT = ROOT / "research/results/v1/chacha20_round20_fresh_multichannel_reader_v1.json"
CAUSAL = ROOT / "research/results/v1/chacha20_round20_fresh_multichannel_reader_v1.causal"
REPORT = ROOT / "research/reports/CAUSAL_CHACHA20_ROUND20_FRESH_MULTICHANNEL_READER_V1.md"
DEFAULT_DOTCAUSAL_SRC = Path(
    "/Users/bhkmie/Documents/Forschung/O1/vendor/fabel/dotcausal_package/src"
)
ATTEMPT_ID = "A249"
SCHEMA = "chacha20-round20-fresh-multichannel-reader-result-v1"


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
        raise RuntimeError(f"cannot import A249 dependency {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _load_protocol() -> tuple[dict[str, Any], Any]:
    if _file_sha256(PROTOCOL) != PROTOCOL_SHA256:
        raise RuntimeError("A249 protocol hash differs")
    protocol = json.loads(PROTOCOL.read_bytes())
    evaluation = protocol.get("evaluation", {})
    features = protocol.get("feature_contract", {})
    boundary = protocol.get("information_boundary", {})
    if (
        protocol.get("schema")
        != "chacha20-round20-fresh-multichannel-reader-protocol-v1"
        or protocol.get("attempt_id") != ATTEMPT_ID
        or protocol.get("protocol_state")
        != "frozen_after_inspecting_only_A242_select_prefix_group_0_and_before_inspecting_groups_1_through_4_or_fitting_any_multichannel_model"
        or features.get("base_channel_count") != 36
        or features.get("final_feature_count") != len(FEATURE_NAMES)
        or features.get("candidate_numeric_value_or_bits_included") is not False
        or features.get("known_low20_prefix_suffix_or_label_included_as_feature")
        is not False
        or evaluation.get("ridge_lambda_grid") != [0.001, 0.01, 0.1, 1.0, 10.0]
        or len(evaluation.get("outer_prefix_groups", [])) != 5
        or boundary.get("any_multichannel_model_fit_before_protocol_freeze") is not False
        or boundary.get("candidate_identity_feature_available_to_model") is not False
        or boundary.get("prospective_unknown_target_generated_or_opened") is not False
    ):
        raise RuntimeError("A249 protocol semantic gate failed")
    anchors = protocol["anchors"]
    pairs = [
        ("A242_protocol_path", "A242_protocol_sha256"),
        ("A242_runner_path", "A242_runner_sha256_at_A249_freeze"),
        ("feature_reader_path", "feature_reader_sha256"),
        ("feature_reader_test_path", "feature_reader_test_sha256"),
        ("ridge_backend_path", "ridge_backend_sha256"),
    ]
    if any(_file_sha256(ROOT / anchors[path]) != anchors[digest] for path, digest in pairs):
        raise RuntimeError("A249 anchor hash differs")
    a242 = _import_path(ROOT / anchors["A242_runner_path"], "a249_a242_reader")
    return protocol, a242


def analyze() -> dict[str, Any]:
    protocol, _ = _load_protocol()
    return {
        "attempt_id": ATTEMPT_ID,
        "protocol_sha256": PROTOCOL_SHA256,
        "feature_count": len(FEATURE_NAMES),
        "outer_prefix_folds": len(protocol["evaluation"]["outer_prefix_groups"]),
        "model_fit_started": False,
    }


def _load_tables(protocol: Mapping[str, Any], a242: Any) -> list[CandidateFeatureTable]:
    a242_protocol = json.loads((ROOT / protocol["anchors"]["A242_protocol_path"]).read_bytes())
    tables = []
    for label in a242_protocol["validation"]["labels"]:
        path = a242._measurement_path(label, "numeric")
        if not path.is_file():
            raise FileNotFoundError(f"A249 requires completed A242 shard: {path.name}")
        measurement = a242._read_measurement(path)
        if (
            measurement.get("label") != label
            or measurement.get("order_name") != "numeric"
            or measurement.get("complete_candidate_cover") is not True
        ):
            raise RuntimeError("A249 A242 measurement identity differs")
        tables.append(build_feature_table(measurement))
    if len(tables) != 20 or len({table.label for table in tables}) != 20:
        raise RuntimeError("A249 requires twenty unique feature tables")
    return tables


def _prefix_index(label: str) -> int:
    marker = "a220_select_p"
    if not label.startswith(marker):
        raise ValueError("A249 label is not a select-prefix row")
    return int(label[len(marker) : len(marker) + 2])


def _fit(tables: Sequence[CandidateFeatureTable], ridge_lambda: float) -> RidgeLogisticModel:
    matrix, labels = concatenate_training(tables)
    return fit_ridge_logistic(
        matrix,
        labels,
        feature_names=FEATURE_NAMES,
        ridge_lambda=ridge_lambda,
    )


def _score_tables(
    model: RidgeLogisticModel, tables: Sequence[CandidateFeatureTable]
) -> list[dict[str, Any]]:
    result = []
    for table in tables:
        scores = model.logits(table.matrix)
        result.append(
            {
                "label": table.label,
                "prefix_index": _prefix_index(table.label),
                "true_prefix": table.true_prefix,
                "true_score": float(scores[table.true_prefix]),
                "midrank": descending_midrank(scores, table.true_prefix),
                "scores": [float(value) for value in scores],
            }
        )
    return result


def _mean_log2(rows: Sequence[Mapping[str, Any]]) -> float:
    return sum(math.log2(float(row["midrank"])) for row in rows) / len(rows)


def _select_lambda(
    training: Sequence[CandidateFeatureTable], lambdas: Sequence[float]
) -> tuple[float, list[dict[str, Any]]]:
    groups = sorted({_prefix_index(table.label) for table in training})
    if len(groups) < 2:
        raise ValueError("A249 inner selection requires multiple prefix groups")
    ledger = []
    for ridge_lambda in lambdas:
        rows = []
        for test_group in groups:
            inner_train = [table for table in training if _prefix_index(table.label) != test_group]
            inner_test = [table for table in training if _prefix_index(table.label) == test_group]
            model = _fit(inner_train, ridge_lambda)
            scored = _score_tables(model, inner_test)
            rows.extend(scored)
        ledger.append(
            {
                "ridge_lambda": ridge_lambda,
                "inner_holdout_mean_log2_rank": _mean_log2(rows),
                "inner_holdout_ranks": [
                    {key: row[key] for key in ("label", "prefix_index", "true_prefix", "midrank")}
                    for row in rows
                ],
            }
        )
    # Larger lambda is the frozen tie-break.
    selected = min(ledger, key=lambda row: (row["inner_holdout_mean_log2_rank"], -row["ridge_lambda"]))
    return float(selected["ridge_lambda"]), ledger


def nested_evaluate(
    tables: Sequence[CandidateFeatureTable], lambdas: Sequence[float]
) -> dict[str, Any]:
    groups = sorted({_prefix_index(table.label) for table in tables})
    if len(tables) != 20 or groups != [0, 1, 2, 3, 4]:
        raise ValueError("A249 outer fold geometry differs")
    folds = []
    all_rows = []
    model_hashes = []
    for outer_group in groups:
        training = [table for table in tables if _prefix_index(table.label) != outer_group]
        testing = [table for table in tables if _prefix_index(table.label) == outer_group]
        selected_lambda, inner_ledger = _select_lambda(training, lambdas)
        model = _fit(training, selected_lambda)
        scored = _score_tables(model, testing)
        model_dict = model.as_dict()
        model_sha = _canonical_sha256(model_dict)
        model_hashes.append(model_sha)
        fold_mean = _mean_log2(scored)
        folds.append(
            {
                "outer_prefix_index": outer_group,
                "outer_true_prefix": testing[0].true_prefix,
                "selected_ridge_lambda": selected_lambda,
                "inner_selection": inner_ledger,
                "model_sha256": model_sha,
                "model": model_dict,
                "test_rows": scored,
                "test_mean_log2_rank": fold_mean,
            }
        )
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
    fold_positive = sum(uniform - fold["test_mean_log2_rank"] > 0 for fold in folds)
    return {
        "outer_folds": folds,
        "outer_model_sha256s": model_hashes,
        "outer_holdout_rows": all_rows,
        "mean_log2_rank": observed,
        "uniform_mean_log2_rank_reference": uniform,
        "mean_log2_rank_bit_gain": uniform - observed,
        "outer_prefix_folds_with_positive_bit_gain": fold_positive,
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
        "A249:unseen_prefix_multichannel_concentration"
        if retained
        else "A249:linear_multichannel_transfer_boundary"
    )
    writer = CausalWriter(api_id="a249")
    writer._rules = []
    writer.add_rule(
        name="typed_multichannel_orbit_reader",
        description="Typed multihorizon solver-state channels plus XOR-neighborhood operators form a candidate-translation-equivariant reader.",
        pattern=["typed_multihorizon_channels", "xor_orbit_features"],
        conclusion="translation_equivariant_candidate_reader",
        confidence_modifier=1.0,
    )
    writer.add_rule(
        name="unseen_prefix_outer_validation",
        description="Nested leave-one-prefix-out scoring measures transfer without training on the tested prefix.",
        pattern=["nested_model_selection", "unseen_prefix_holdout"],
        conclusion="prefix_transfer_evidence",
        confidence_modifier=1.0,
    )
    writer.add_triplet(
        trigger="A242:fresh_candidate_trajectories",
        mechanism="typed_multihorizon_channels",
        outcome="A249:36_base_solver_channels",
        confidence=1.0,
        source=payload["feature_reader_sha256"],
        quantification="4 horizons x 9 typed channels",
        evidence=json.dumps(payload["feature_contract"], sort_keys=True),
        domain="fresh solver trajectory readout",
        quality_score=1.0,
    )
    writer.add_triplet(
        trigger="A249:36_base_solver_channels",
        mechanism="xor_orbit_features",
        outcome="A249:144_translation_equivariant_features",
        confidence=1.0,
        source=payload["feature_reader_sha256"],
        quantification="raw, hypercube Laplacian, RMS gradient, max gradient",
        evidence=json.dumps({"feature_count": len(FEATURE_NAMES)}),
        domain="XOR candidate geometry",
        quality_score=1.0,
    )
    writer.add_triplet(
        trigger="A249:144_translation_equivariant_features",
        mechanism="nested_model_selection",
        outcome="A249:five_outer_prefix_models",
        confidence=1.0,
        source=payload["evaluation_sha256"],
        quantification="5 outer folds; inner prefix-fold lambda selection",
        evidence=json.dumps(evaluation["outer_model_sha256s"]),
        domain="known-key learned reader",
        quality_score=1.0,
    )
    writer.add_triplet(
        trigger="A249:five_outer_prefix_models",
        mechanism="unseen_prefix_holdout",
        outcome=outcome,
        confidence=1.0,
        source=payload["evaluation_sha256"],
        quantification=f"mean log2 rank={evaluation['mean_log2_rank']:.12f}; exact p={evaluation['exact_shared_xor_p']:.12f}",
        evidence=json.dumps(
            {
                "bit_gain": evaluation["mean_log2_rank_bit_gain"],
                "positive_folds": evaluation["outer_prefix_folds_with_positive_bit_gain"],
                "best_xor_offset": evaluation["best_shared_xor_offset"],
            },
            sort_keys=True,
        ),
        domain="unseen-prefix transfer",
        quality_score=1.0,
    )
    writer.add_triplet(
        trigger="A242:fresh_candidate_trajectories",
        mechanism="materialized_typed_reader_chain",
        outcome=outcome,
        confidence=1.0,
        source="materialized:typed_multichannel_orbit_reader+unseen_prefix_outer_validation",
        quantification="four-edge closure retained in-file",
        evidence="Materialized after nested unseen-prefix evaluation and exact XOR controls.",
        domain="AI-native retained inference",
        quality_score=1.0,
        is_inferred=True,
    )
    writer.add_cluster(
        name="A249 typed feature chain",
        entities=[
            "A242:fresh_candidate_trajectories",
            "typed_multihorizon_channels",
            "A249:36_base_solver_channels",
            "xor_orbit_features",
            "A249:144_translation_equivariant_features",
        ],
    )
    writer.add_cluster(
        name="A249 unseen-prefix validation chain",
        entities=[
            "nested_model_selection",
            "A249:five_outer_prefix_models",
            "unseen_prefix_holdout",
            outcome,
        ],
    )
    writer.add_gap(
        subject=outcome,
        predicate="next_required_intervention",
        expected_object_type=(
            "prospective_unknown_target_reader"
            if retained
            else "nonlinear_or_clause_identity_typed_reader"
        ),
        confidence=1.0,
        suggested_queries=(
            ["Freeze one final reader and rank a prospectively generated R20 target."]
            if retained
            else [
                "Add exact propagated-variable and learned-clause identity channels.",
                "Test a nonlinear but prefix-blind reader under the same outer folds.",
            ]
        ),
    )
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.tmp")
    temporary.unlink(missing_ok=True)
    writer_stats = writer.save(str(temporary))
    temporary.replace(path)
    reader = CausalReader(str(path), verify_integrity=True)
    explicit = reader.get_all_triplets(include_inferred=False)
    all_rows = reader.get_all_triplets(include_inferred=True)
    inferred = [row for row in reader._triplets if row.get("is_inferred", False)]
    if (
        reader.api_id != "a249"
        or len(explicit) != 4
        or len(all_rows) != 5
        or len(inferred) != 1
        or len(reader._rules) != 2
        or len(reader._clusters) != 2
        or len(reader._gaps) != 1
    ):
        raise RuntimeError("A249 authentic Causal Reader gate failed")
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
        "writer_stats": writer_stats,
        "personal_semantic_readback": {
            "terminal_chain": all_rows[-1],
            "next_gap": reader._gaps[0],
        },
    }


def _report(payload: Mapping[str, Any]) -> str:
    result = payload["evaluation"]
    lines = [
        "# A249 — ChaCha20-R20 fresh multichannel XOR-orbit reader",
        "",
        "The reader combines thirty-six typed fresh-solver channels with four XOR-neighborhood operators and evaluates the resulting 144 features under nested leave-one-prefix-out validation.",
        "",
        "## Result",
        "",
        f"- Evidence stage: **{payload['evidence_stage']}**",
        f"- Outer-holdout mean log2 rank: **{result['mean_log2_rank']:.12f}**",
        f"- Uniform reference: **{result['uniform_mean_log2_rank_reference']:.12f}**",
        f"- Rank-information gain: **{result['mean_log2_rank_bit_gain']:.12f} bits**",
        f"- Exact shared-XOR p: **{result['exact_shared_xor_p']:.12f}**",
        f"- Prefix folds with positive gain: **{result['outer_prefix_folds_with_positive_bit_gain']} / 5**",
        f"- Best shared XOR offset: **{result['best_shared_xor_offset']}**",
        "",
        "## Outer folds",
        "",
        "| Prefix fold | Lambda | Mean log2 rank | Model SHA-256 |",
        "|---:|---:|---:|---|",
    ]
    for fold in result["outer_folds"]:
        lines.append(
            f"| {fold['outer_prefix_index']} | {fold['selected_ridge_lambda']} | {fold['test_mean_log2_rank']:.6f} | `{fold['model_sha256']}` |"
        )
    lines.extend(
        [
            "",
            "## Authentic AI-native Causal readback",
            "",
            f"- Reader integrity: **{payload['causal']['integrity_verified_by_authoritative_reader']}**",
            f"- Explicit / inferred: **{payload['causal']['explicit_triplets']} / {payload['causal']['materialized_inferred_triplets']}**",
            f"- Next gap: **{payload['causal']['personal_semantic_readback']['next_gap']['expected_object_type']}**",
        ]
    )
    return "\n".join(lines) + "\n"


def execute(dotcausal_src: Path = DEFAULT_DOTCAUSAL_SRC) -> dict[str, Any]:
    protocol, a242 = _load_protocol()
    tables = _load_tables(protocol, a242)
    evaluation = nested_evaluate(tables, protocol["evaluation"]["ridge_lambda_grid"])
    gate = protocol["retention_gate"]
    retained = (
        evaluation["exact_shared_xor_p"] <= gate["maximum_exact_shared_xor_p"]
        and evaluation["mean_log2_rank_bit_gain"]
        > gate["minimum_aggregate_mean_log2_rank_bit_gain"]
        and evaluation["outer_prefix_folds_with_positive_bit_gain"]
        >= gate["minimum_outer_prefix_folds_with_positive_bit_gain"]
    )
    payload: dict[str, Any] = {
        "schema": SCHEMA,
        "attempt_id": ATTEMPT_ID,
        "evidence_stage": (
            "FULLROUND_R20_FRESH_MULTICHANNEL_READER_RETAINED"
            if retained
            else "FULLROUND_R20_FRESH_MULTICHANNEL_LINEAR_BOUNDARY"
        ),
        "protocol_sha256": PROTOCOL_SHA256,
        "feature_contract": protocol["feature_contract"],
        "feature_reader_sha256": protocol["anchors"]["feature_reader_sha256"],
        "evaluation": evaluation,
        "evaluation_sha256": _canonical_sha256(evaluation),
        "retention_gate": {**gate, "passed": retained},
        "information_boundary": protocol["information_boundary"],
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
        )
    )
    return payload


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--analyze-only", action="store_true")
    parser.add_argument("--run", action="store_true")
    parser.add_argument("--dotcausal-src", type=Path, default=DEFAULT_DOTCAUSAL_SRC)
    args = parser.parse_args()
    if args.run:
        execute(args.dotcausal_src)
    else:
        print(json.dumps(analyze(), indent=2, sort_keys=True))


if __name__ == "__main__":
    main()

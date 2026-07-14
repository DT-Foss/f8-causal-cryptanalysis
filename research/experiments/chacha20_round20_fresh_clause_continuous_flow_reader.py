#!/usr/bin/env python3
"""Execute frozen A262 continuous matched-contrast flow reader."""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
import sys
import tempfile
import time
from collections.abc import Mapping
from pathlib import Path
from typing import Any

ROOT = Path(__file__).parents[2]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from arx_carry_leak.chacha20_continuous_flow import (  # noqa: E402
    build_continuous_flow_table,
    continuous_table_sha256,
    nested_continuous_flow_evaluate,
)

PROTOCOL = (
    ROOT
    / "research/configs/chacha20_round20_fresh_clause_continuous_flow_reader_v1.json"
)
PROTOCOL_SHA256 = "34bcf3b14ea748355e98cc6041d265aac01831dc5288a11a097f5b5ba3d6d0b5"
RESULT = (
    ROOT
    / "research/results/v1/chacha20_round20_fresh_clause_continuous_flow_reader_v1.json"
)
CAUSAL = (
    ROOT
    / "research/results/v1/chacha20_round20_fresh_clause_continuous_flow_reader_v1.causal"
)
REPORT = (
    ROOT
    / "research/reports/CAUSAL_CHACHA20_ROUND20_FRESH_CLAUSE_CONTINUOUS_FLOW_READER_V1.md"
)
DEFAULT_DOTCAUSAL_SRC = Path(
    "/Users/bhkmie/Documents/Forschung/O1/vendor/fabel/dotcausal_package/src"
)
ATTEMPT_ID = "A262"
RESULT_SCHEMA = "chacha20-round20-fresh-clause-continuous-flow-reader-result-v1"


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
        raise RuntimeError(f"cannot import A262 dependency {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _anchor_path(value: str) -> Path:
    path = Path(value)
    return path if path.is_absolute() else ROOT / path


def _load_protocol() -> tuple[dict[str, Any], Any, Any, Any, Any, Any, Any, Any]:
    if _file_sha256(PROTOCOL) != PROTOCOL_SHA256:
        raise RuntimeError("A262 frozen protocol hash differs")
    protocol = json.loads(PROTOCOL.read_bytes())
    feature = protocol.get("feature_contract", {})
    operator = protocol.get("operator", {})
    boundary = protocol.get("information_boundary", {})
    if (
        protocol.get("schema")
        != "chacha20-round20-fresh-clause-continuous-flow-reader-protocol-v1"
        or protocol.get("attempt_id") != ATTEMPT_ID
        or protocol.get("protocol_state")
        != "frozen_after_A261_personal_authentic_causal_readback_and_synthetic_continuous_matched_contrast_preflight_before_any_A251_clause_counter_reconstruction_or_continuous_model_fit"
        or feature.get("minimum_nonzero_candidates_per_key") != 4
        or feature.get("minimum_training_keys_per_feature") != 8
        or feature.get("minimum_training_prefix_groups_per_feature") != 2
        or feature.get("candidate_numeric_value_or_bits_included") is not False
        or operator.get("view_grid") != ["linear_l1", "log1p_l1", "sqrt_l1"]
        or operator.get("maximum_features_grid") != [16, 64, 256]
        or operator.get("ridge_grid") != [0.25, 1.0, 4.0]
        or operator.get("operator_setting_count") != 27
        or boundary.get("any_A251_measurement_shard_opened_by_A262_before_protocol_freeze")
        is not False
        or boundary.get("any_A251_clause_counter_reconstructed_by_A262_before_protocol_freeze")
        is not False
        or boundary.get("any_A262_continuous_feature_support_effect_rank_or_model_fit_known_before_protocol_freeze")
        is not False
        or boundary.get("future_prospective_unknown_target_generated_or_opened")
        is not False
    ):
        raise RuntimeError("A262 frozen protocol semantic gate failed")
    anchors = protocol["anchors"]
    for path_key, path_value in anchors.items():
        if not path_key.endswith("_path"):
            continue
        hash_key = f"{path_key.removesuffix('_path')}_sha256"
        expected = anchors.get(hash_key)
        if not isinstance(expected, str) or _file_sha256(_anchor_path(path_value)) != expected:
            raise RuntimeError(f"A262 anchored dependency hash differs: {path_key}")
    a261 = _import_path(ROOT / anchors["A261_runner_path"], "a262_a261")
    a261_protocol, preflight, a260, a259, a251, a242 = a261._load_protocol()
    return protocol, a261, a261_protocol, preflight, a260, a259, a251, a242


def analyze() -> dict[str, Any]:
    protocol, *_ = _load_protocol()
    return {
        "attempt_id": ATTEMPT_ID,
        "protocol_sha256": PROTOCOL_SHA256,
        "input_solver_measurements": protocol["input"]["required_key_count"] * 256,
        "new_solver_measurements_permitted": False,
        "operator_settings": protocol["operator"]["operator_setting_count"],
        "continuous_counter_reconstruction_started": False,
    }


def _load_tables(
    protocol: Mapping[str, Any],
    a251: Any,
    nearest: Any,
    graph: Any,
) -> tuple[list[Any], dict[str, Any]]:
    a251_protocol, _ = a251._load_protocol()
    labels = list(a251_protocol["input"]["labels"])
    minimum_nonzero = int(
        protocol["feature_contract"]["minimum_nonzero_candidates_per_key"]
    )
    tables = []
    accepted = 0
    rejected = 0
    exact_measurements = []
    table_ledger = []
    continuous_ledgers = []
    for label in labels:
        path = a251._measurement_path(label, "numeric")
        if not path.is_file():
            raise FileNotFoundError(f"A262 requires completed A251 shard: {path.name}")
        measurement = a251._read_measurement(path)
        accepted += int(measurement["run"]["summary"]["learned_clause_accepted_total"])
        rejected += int(
            measurement["run"]["summary"]["learned_clause_rejected_large_total"]
        )
        table, ledger = build_continuous_flow_table(
            measurement,
            nearest,
            graph,
            minimum_nonzero_candidates=minimum_nonzero,
        )
        table_sha256 = continuous_table_sha256(table)
        tables.append(table)
        exact_measurements.append(
            {
                "label": label,
                "compressed_sha256": _file_sha256(path),
                "raw_measurement_sha256": _canonical_sha256(measurement),
            }
        )
        table_ledger.append({"label": label, "table_sha256": table_sha256})
        continuous_ledgers.append({"label": label, **ledger})
        print(
            "A262_TABLE "
            + json.dumps(
                {
                    "label": label,
                    "retained_varying_features": ledger[
                        "retained_varying_feature_count"
                    ],
                    "table_sha256": table_sha256,
                },
                sort_keys=True,
            ),
            flush=True,
        )
    expected = protocol["input"]
    if (
        len(tables) != expected["required_key_count"]
        or accepted != expected["required_accepted_learned_clause_count"]
        or rejected != expected["required_rejected_over_64_literal_clause_count"]
    ):
        raise RuntimeError("A262 retained A251 clause corpus identity differs")
    return tables, {
        "accepted_learned_clauses": accepted,
        "rejected_over_64_literal_clauses": rejected,
        "exact_measurement_ledger": exact_measurements,
        "exact_measurement_ledger_sha256": _canonical_sha256(exact_measurements),
        "continuous_feature_ledgers": continuous_ledgers,
        "continuous_feature_ledger_sha256": _canonical_sha256(continuous_ledgers),
        "table_ledger": table_ledger,
        "table_ledger_sha256": _canonical_sha256(table_ledger),
        "true_prefix_used_during_counter_or_feature_retention": False,
    }


def _build_causal(
    path: Path,
    payload: Mapping[str, Any],
    a261: Any,
    dotcausal_src: Path,
) -> dict[str, Any]:
    CausalWriter, CausalReader, source = a261._load_dotcausal(dotcausal_src)
    retained = bool(payload["retention_gate"]["passed"])
    terminal = (
        "A262:continuous_flow_transfer_retained"
        if retained
        else "A262:continuous_flow_boundary"
    )
    writer = CausalWriter(api_id="a262")
    writer._rules = []
    writer.add_rule(
        name="continuous_residuals_preserve_flow_magnitude",
        description="Within-key centering removes common operation volume while retaining signed continuous distance from the complete-cover baseline.",
        pattern=["complete_256_candidate_cover", "continuous_l1_scaled_residual"],
        conclusion="continuous_target_blind_flow_coordinates",
        confidence_modifier=1.0,
    )
    writer.add_rule(
        name="group_consistent_matched_contrast",
        description="Feature signs and weights are learned from training prefix groups and applied to an entirely unseen prefix group.",
        pattern=["training_group_contrasts", "unseen_outer_prefix"],
        conclusion="prefix_blind_continuous_rank_evidence",
        confidence_modifier=1.0,
    )
    writer.add_triplet(
        trigger="A261:directed_flow_residual_boundary",
        mechanism="retain_signed_continuous_flow_counter_magnitude",
        outcome="A262:continuous_within_key_flow_tables",
        confidence=1.0,
        source=payload["continuous_clause_corpus"][
            "continuous_feature_ledger_sha256"
        ],
        quantification="20 keys; complete 256-candidate covers; three continuous views",
        evidence=json.dumps(
            [
                {
                    "label": row["label"],
                    "features": row["retained_varying_feature_count"],
                }
                for row in payload["continuous_clause_corpus"][
                    "continuous_feature_ledgers"
                ]
            ],
            sort_keys=True,
        ),
        domain="continuous learned-clause operation flow",
        quality_score=1.0,
    )
    writer.add_triplet(
        trigger="A262:continuous_within_key_flow_tables",
        mechanism="training_prefix_group_consistent_matched_contrast_weighting",
        outcome="A262:five_unseen_prefix_continuous_models",
        confidence=1.0,
        source=payload["analysis_sha256"],
        quantification="27 frozen settings; nested inner selection; five outer folds",
        evidence=json.dumps(
            [
                {
                    "prefix": fold["outer_prefix_index"],
                    "view": fold["selected_view"],
                    "features": fold["selected_maximum_features"],
                    "ridge": fold["selected_ridge"],
                    "rank": fold["test_mean_log2_rank"],
                }
                for fold in payload["evaluation"]["outer_folds"]
            ],
            sort_keys=True,
        ),
        domain="nested continuous known-key transfer",
        quality_score=1.0,
    )
    writer.add_triplet(
        trigger="A262:five_unseen_prefix_continuous_models",
        mechanism="unseen_prefix_ranks_plus_all_256_shared_XOR_controls",
        outcome=terminal,
        confidence=1.0,
        source=payload["analysis_sha256"],
        quantification=(
            f"gain={payload['evaluation']['mean_log2_rank_bit_gain']:.12f}; "
            f"exact_p={payload['evaluation']['exact_shared_xor_p']:.12f}"
        ),
        evidence=json.dumps(payload["retention_gate"], sort_keys=True),
        domain="exact XOR-invariant outer validation",
        quality_score=1.0,
    )
    writer.add_triplet(
        trigger="A261:directed_flow_residual_boundary",
        mechanism="materialized_continuous_matched_contrast_chain",
        outcome=terminal,
        confidence=1.0,
        source="materialized:continuous_flow_plus_nested_group_contrast",
        quantification="complete three-edge closure retained in-file",
        evidence="Materialized after continuous table construction, nested evaluation, and exact XOR controls.",
        domain="AI-native retained inference",
        quality_score=1.0,
        is_inferred=True,
    )
    writer.add_cluster(
        name="A262 continuous matched-contrast chain",
        entities=[
            "A261:directed_flow_residual_boundary",
            "retain_signed_continuous_flow_counter_magnitude",
            "A262:continuous_within_key_flow_tables",
            "training_prefix_group_consistent_matched_contrast_weighting",
            "A262:five_unseen_prefix_continuous_models",
            "unseen_prefix_ranks_plus_all_256_shared_XOR_controls",
            terminal,
        ],
    )
    writer.add_gap(
        subject=terminal,
        predicate="next_required_object",
        expected_object_type=(
            "prospective_disjoint_known_key_continuous_flow_validation"
            if retained
            else "exact_clause_continuous_frequency_contrast_or_solver_native_trajectory_delta"
        ),
        confidence=1.0,
        suggested_queries=(
            [
                "Freeze the selected continuous operator before generating disjoint keys.",
                "Does the rank gain survive entirely new known-key prefix groups?",
            ]
            if retained
            else [
                "Does continuous exact-clause frequency retain information lost by semantic projection?",
                "Do solver-native propagation and decision deltas transfer without clause tokenization?",
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
        or reader.api_id != "a262"
        or len(explicit) != 3
        or len(rows) != 4
        or len(inferred) != 1
        or len(reader._rules) != 2
        or len(reader._clusters) != 1
        or len(reader._gaps) != 1
        or rows[-1]["outcome"] != terminal
    ):
        raise RuntimeError("A262 authentic Causal Reader reopen gate failed")
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
        "amplified_state_materialized_in_file": True,
        "inference_recomputed_on_reader_open": False,
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
        "# A262 — ChaCha20-R20 continuous matched-contrast flow reader",
        "",
        "A262 preserves signed continuous magnitude from exact directed operation-flow counters, learns only from training prefix groups, and ranks four keys from an unseen prefix group in every outer fold.",
        "",
        "## Result",
        "",
        f"- Evidence stage: **{payload['evidence_stage']}**",
        f"- Mean log2 rank: **{evaluation['mean_log2_rank']:.12f}**",
        f"- Uniform reference: **{evaluation['uniform_mean_log2_rank_reference']:.12f}**",
        f"- Bit gain: **{evaluation['mean_log2_rank_bit_gain']:+.12f}**",
        f"- Positive outer folds: **{evaluation['outer_prefix_folds_with_positive_bit_gain']}/5**",
        f"- Exact shared-XOR p: **{evaluation['exact_shared_xor_p']:.12f}**",
        f"- Frozen gate passed: **{payload['retention_gate']['passed']}**",
        "",
        "## Authentic AI-native Causal readback",
        "",
        f"- Reader integrity: **{causal['integrity_verified_by_authoritative_reader']}**",
        f"- Explicit / materialized: **{causal['explicit_triplets']} / {causal['materialized_inferred_triplets']}**",
        f"- Next gap: **{causal['personal_semantic_readback']['next_gap']['expected_object_type']}**",
    ]
    return "\n".join(lines) + "\n"


def execute(*, dotcausal_src: Path = DEFAULT_DOTCAUSAL_SRC) -> dict[str, Any]:
    (
        protocol,
        a261,
        a261_protocol,
        preflight,
        a260,
        a259,
        a251,
        a242,
    ) = _load_protocol()
    started = time.perf_counter()
    with tempfile.TemporaryDirectory(prefix="a262_clause_continuous_flow_") as temporary:
        _topology, (nearest, graph), public_flow = a261._prepare_flow_reader(
            a261_protocol,
            preflight,
            a260,
            a259,
            a242,
            Path(temporary),
        )
        tables, corpus = _load_tables(protocol, a251, nearest, graph)
    operator = protocol["operator"]
    evaluation = nested_continuous_flow_evaluate(
        tables,
        views=operator["view_grid"],
        maximum_features_grid=operator["maximum_features_grid"],
        ridge_grid=operator["ridge_grid"],
    )
    gate = protocol["retention_gate"]
    retained = (
        evaluation["exact_shared_xor_p"] <= gate["maximum_exact_shared_xor_p"]
        and evaluation["mean_log2_rank_bit_gain"]
        > gate["minimum_aggregate_mean_log2_rank_bit_gain"]
        and evaluation["outer_prefix_folds_with_positive_bit_gain"]
        >= gate["minimum_outer_prefix_folds_with_positive_bit_gain"]
    )
    payload: dict[str, Any] = {
        "schema": RESULT_SCHEMA,
        "attempt_id": ATTEMPT_ID,
        "evidence_stage": (
            "FULLROUND_R20_CONTINUOUS_MATCHED_FLOW_CROSSVALIDATED_SIGNAL"
            if retained
            else "FULLROUND_R20_CONTINUOUS_MATCHED_FLOW_BOUNDARY"
        ),
        "protocol_sha256": PROTOCOL_SHA256,
        "protocol_state": protocol["protocol_state"],
        "causal_derivation": protocol["causal_derivation"],
        "public_flow_preflight": public_flow,
        "feature_contract": protocol["feature_contract"],
        "operator_grid": operator,
        "continuous_clause_corpus": corpus,
        "evaluation": evaluation,
        "analysis_sha256": _canonical_sha256(evaluation),
        "retention_gate": {**gate, "passed": retained},
        "new_solver_measurements": 0,
        "volatile_total_elapsed_seconds": time.perf_counter() - started,
        "information_boundary": protocol["information_boundary"],
    }
    payload["causal"] = _build_causal(CAUSAL, payload, a261, dotcausal_src)
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
                "new_solver_measurements": 0,
                "result": str(RESULT),
                "causal": str(CAUSAL),
                "report": str(REPORT),
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

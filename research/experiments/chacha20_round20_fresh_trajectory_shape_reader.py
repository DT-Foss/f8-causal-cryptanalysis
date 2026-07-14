#!/usr/bin/env python3
"""Execute frozen A267 scale-free solver trajectory-shape reader."""

from __future__ import annotations

import argparse
import hashlib
import importlib
import importlib.util
import inspect
import json
import os
import sys
import time
from collections.abc import Mapping
from pathlib import Path
from typing import Any

import numpy as np

ROOT = Path(__file__).parents[2]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from arx_carry_leak.solver_trajectory_shape import (  # noqa: E402
    BASE_FEATURE_NAMES,
    FEATURE_NAMES,
    build_trajectory_shape_table,
    nested_trajectory_shape_evaluate,
)

PROTOCOL = (
    ROOT / "research/configs/chacha20_round20_fresh_trajectory_shape_reader_v1.json"
)
PROTOCOL_SHA256 = "e3f70c2a0e1151ef727ad2bfc9fb85fed559237b593b6a8ffdce7f6ddf51d72d"
RESULT = (
    ROOT / "research/results/v1/chacha20_round20_fresh_trajectory_shape_reader_v1.json"
)
CAUSAL = (
    ROOT / "research/results/v1/chacha20_round20_fresh_trajectory_shape_reader_v1.causal"
)
REPORT = (
    ROOT / "research/reports/CAUSAL_CHACHA20_ROUND20_FRESH_TRAJECTORY_SHAPE_READER_V1.md"
)
DEFAULT_DOTCAUSAL_SRC = Path(
    "/Users/bhkmie/Documents/Forschung/O1/vendor/fabel/dotcausal_package/src"
)
ATTEMPT_ID = "A267"
RESULT_SCHEMA = "chacha20-round20-fresh-trajectory-shape-reader-result-v1"


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
        raise RuntimeError(f"cannot import A267 dependency {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _anchor_path(value: str) -> Path:
    path = Path(value)
    return path if path.is_absolute() else ROOT / path


def _load_protocol() -> tuple[dict[str, Any], Any, dict[str, Any]]:
    if _file_sha256(PROTOCOL) != PROTOCOL_SHA256:
        raise RuntimeError("A267 frozen protocol hash differs")
    protocol = json.loads(PROTOCOL.read_bytes())
    feature = protocol.get("feature_contract", {})
    operator = protocol.get("operator", {})
    boundary = protocol.get("information_boundary", {})
    if (
        protocol.get("schema")
        != "chacha20-round20-fresh-trajectory-shape-reader-protocol-v1"
        or protocol.get("attempt_id") != ATTEMPT_ID
        or protocol.get("protocol_state")
        != "frozen_after_A266_personal_authentic_causal_readback_and_synthetic_scale_free_trajectory_shape_preflight_before_any_A251_trajectory_shape_table_or_A267_model_fit"
        or feature.get("base_feature_count") != len(BASE_FEATURE_NAMES)
        or feature.get("final_feature_count") != len(FEATURE_NAMES)
        or feature.get("candidate_numeric_value_or_bits_included") is not False
        or feature.get("candidate_assumption_literal_values_included") is not False
        or feature.get("outer_test_true_prefix_used_for_fit_selection_or_weighting")
        is not False
        or operator.get("ridge_lambda_grid") != [0.01, 0.1, 1.0, 10.0]
        or operator.get("operator_setting_count") != 4
        or boundary.get("any_A251_trajectory_shape_table_constructed_before_protocol_freeze")
        is not False
        or boundary.get("any_A267_shape_coefficient_lambda_rank_or_outcome_known_before_protocol_freeze")
        is not False
        or boundary.get("future_prospective_unknown_target_generated_or_opened")
        is not False
    ):
        raise RuntimeError("A267 frozen protocol semantic gate failed")
    anchors = protocol["anchors"]
    for path_key, path_value in anchors.items():
        if not path_key.endswith("_path"):
            continue
        hash_key = f"{path_key.removesuffix('_path')}_sha256"
        expected = anchors.get(hash_key)
        if not isinstance(expected, str) or _file_sha256(_anchor_path(path_value)) != expected:
            raise RuntimeError(f"A267 anchored dependency hash differs: {path_key}")
    preflight = json.loads(_anchor_path(anchors["preflight_path"]).read_bytes())
    if (
        preflight.get("schema") != "chacha20-round20-trajectory-shape-preflight-v1"
        or preflight.get("attempt_id") != ATTEMPT_ID
        or preflight["geometry"]["base_feature_count"] != len(BASE_FEATURE_NAMES)
        or preflight["geometry"]["orbit_feature_count"] != len(FEATURE_NAMES)
        or preflight["information_boundary"]["used_any_A251_measurement_shard"]
        is not False
        or preflight["information_boundary"]["any_A267_operator_outcome_known"]
        is not False
    ):
        raise RuntimeError("A267 synthetic preflight gate failed")
    a251 = _import_path(ROOT / anchors["A251_runner_path"], "a267_a251")
    a251_protocol, _ = a251._load_protocol()
    return protocol, a251, a251_protocol


def analyze() -> dict[str, Any]:
    protocol, _, _ = _load_protocol()
    return {
        "attempt_id": ATTEMPT_ID,
        "protocol_sha256": PROTOCOL_SHA256,
        "known_key_count": protocol["input"]["required_key_count"],
        "candidate_measurements": protocol["input"]["required_key_count"] * 256,
        "base_feature_count": len(BASE_FEATURE_NAMES),
        "orbit_feature_count": len(FEATURE_NAMES),
        "operator_settings": protocol["operator"]["operator_setting_count"],
        "new_solver_measurements_permitted": False,
        "trajectory_shape_table_construction_started": False,
    }


def _table_sha256(table: Any) -> str:
    digest = hashlib.sha256()
    digest.update(table.label.encode())
    digest.update(int(table.true_prefix).to_bytes(1, "little"))
    digest.update("\n".join(table.feature_names).encode())
    digest.update(np.asarray(table.matrix, dtype="<f8").tobytes())
    return digest.hexdigest()


def _load_tables(
    protocol: Mapping[str, Any], a251: Any, a251_protocol: Mapping[str, Any]
) -> tuple[list[Any], dict[str, Any]]:
    labels = list(a251_protocol["input"]["labels"])
    tables = []
    accepted = 0
    rejected = 0
    measurement_ledger = []
    table_ledger = []
    for label in labels:
        path = a251._measurement_path(label, "numeric")
        if not path.is_file():
            raise FileNotFoundError(f"A267 requires completed A251 shard: {path.name}")
        measurement = a251._read_measurement(path)
        summary = measurement["run"]["summary"]
        accepted += int(summary["learned_clause_accepted_total"])
        rejected += int(summary["learned_clause_rejected_large_total"])
        table = build_trajectory_shape_table(measurement)
        digest = _table_sha256(table)
        tables.append(table)
        measurement_ledger.append(
            {
                "label": label,
                "compressed_sha256": _file_sha256(path),
                "raw_measurement_sha256": _canonical_sha256(measurement),
            }
        )
        table_ledger.append({"label": label, "table_sha256": digest})
        print(
            "A267_TABLE "
            + json.dumps(
                {
                    "label": label,
                    "matrix_shape": list(table.matrix.shape),
                    "table_sha256": digest,
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
        raise RuntimeError("A267 retained A251 solver corpus identity differs")
    return tables, {
        "known_keys": len(tables),
        "candidate_measurements": len(tables) * 256,
        "accepted_learned_clauses": accepted,
        "rejected_over_64_literal_clauses": rejected,
        "measurement_ledger": measurement_ledger,
        "measurement_ledger_sha256": _canonical_sha256(measurement_ledger),
        "table_ledger": table_ledger,
        "table_ledger_sha256": _canonical_sha256(table_ledger),
        "base_feature_count": len(BASE_FEATURE_NAMES),
        "orbit_feature_count": len(FEATURE_NAMES),
        "true_prefix_used_during_feature_construction_or_standardization": False,
    }


def _load_dotcausal(dotcausal_src: Path) -> tuple[Any, Any, dict[str, Any]]:
    try:
        io_module = importlib.import_module("dotcausal.io")
    except ModuleNotFoundError:
        if not dotcausal_src.is_dir():
            raise FileNotFoundError("dotcausal source is unavailable") from None
        sys.path.insert(0, str(dotcausal_src))
        io_module = importlib.import_module("dotcausal.io")
    writer = io_module.CausalWriter
    reader = io_module.CausalReader
    io_path = Path(inspect.getsourcefile(reader) or "")
    if not io_path.is_file():
        raise RuntimeError("A267 authoritative dotcausal.io source is unavailable")
    return writer, reader, {
        "module": "dotcausal.io",
        "io_path": str(io_path),
        "io_sha256": _file_sha256(io_path),
    }


def _build_causal(
    path: Path,
    payload: Mapping[str, Any],
    dotcausal_src: Path,
) -> dict[str, Any]:
    CausalWriter, CausalReader, source = _load_dotcausal(dotcausal_src)
    retained = bool(payload["retention_gate"]["passed"])
    terminal = (
        "A267:trajectory_shape_transfer_retained"
        if retained
        else "A267:trajectory_shape_transfer_boundary"
    )
    writer = CausalWriter(api_id="a267")
    writer._rules = []
    writer.add_rule(
        name="magnitude_free_event_shape",
        description="Each solver channel is divided by its four-horizon L1 magnitude before first and second horizon differences are formed.",
        pattern=["four_horizon_solver_events", "channel_L1_normalization"],
        conclusion="scale_free_solver_event_shape",
        confidence_modifier=1.0,
    )
    writer.add_rule(
        name="nested_unseen_prefix_shape_reader",
        description="Ridge selection and model coefficients use only training prefix groups; the complete unseen group supplies ranks only after fit.",
        pattern=["scale_free_solver_event_shape", "nested_prefix_holdout"],
        conclusion="prefix_blind_trajectory_shape_evidence",
        confidence_modifier=1.0,
    )
    writer.add_triplet(
        trigger="A266:exact_frequency_transfer_boundary",
        mechanism="replace_absolute_counts_with_scale_free_horizon_profiles_and_derivatives",
        outcome="A267:532_coordinate_trajectory_shape_tables",
        confidence=1.0,
        source=payload["trajectory_corpus"]["table_ledger_sha256"],
        quantification="20 keys; 256 candidates/key; 133 base coordinates; four XOR orbit reads",
        evidence=json.dumps(payload["trajectory_corpus"]["table_ledger"], sort_keys=True),
        domain="solver-native full-round R20 event shape",
        quality_score=1.0,
    )
    writer.add_triplet(
        trigger="A267:532_coordinate_trajectory_shape_tables",
        mechanism="nested_class_balanced_ridge_logistic_on_unseen_prefix_groups",
        outcome="A267:five_unseen_prefix_shape_models",
        confidence=1.0,
        source=payload["analysis_sha256"],
        quantification="four frozen ridge settings; five outer folds",
        evidence=json.dumps(
            [
                {
                    "prefix": fold["outer_prefix_index"],
                    "lambda": fold["selected_ridge_lambda"],
                    "rank": fold["test_mean_log2_rank"],
                }
                for fold in payload["evaluation"]["outer_folds"]
            ],
            sort_keys=True,
        ),
        domain="nested scale-free trajectory transfer",
        quality_score=1.0,
    )
    writer.add_triplet(
        trigger="A267:five_unseen_prefix_shape_models",
        mechanism="all_256_shared_XOR_controls_and_frozen_retention_gate",
        outcome=terminal,
        confidence=1.0,
        source=payload["analysis_sha256"],
        quantification=json.dumps(payload["retention_gate"], sort_keys=True),
        evidence=json.dumps(
            {
                key: payload["evaluation"][key]
                for key in (
                    "mean_log2_rank",
                    "mean_log2_rank_bit_gain",
                    "exact_shared_xor_p",
                    "outer_prefix_folds_with_positive_bit_gain",
                    "best_shared_xor_offset",
                )
            },
            sort_keys=True,
        ),
        domain="exact XOR-invariant outer validation",
        quality_score=1.0,
    )
    writer.add_triplet(
        trigger="A266:exact_frequency_transfer_boundary",
        mechanism="materialized_scale_free_trajectory_shape_chain",
        outcome=terminal,
        confidence=1.0,
        source="materialized:trajectory_shape_plus_nested_prefix_validation",
        quantification="complete three-edge closure retained in-file",
        evidence="Materialized after trajectory-shape construction, nested evaluation, and all 256 shared-XOR controls.",
        domain="AI-native retained inference",
        quality_score=1.0,
        is_inferred=True,
    )
    writer.add_cluster(
        name="A267 scale-free solver trajectory-shape chain",
        entities=[
            "A266:exact_frequency_transfer_boundary",
            "replace_absolute_counts_with_scale_free_horizon_profiles_and_derivatives",
            "A267:532_coordinate_trajectory_shape_tables",
            "nested_class_balanced_ridge_logistic_on_unseen_prefix_groups",
            "A267:five_unseen_prefix_shape_models",
            "all_256_shared_XOR_controls_and_frozen_retention_gate",
            terminal,
        ],
    )
    writer.add_gap(
        subject=terminal,
        predicate="next_required_object",
        expected_object_type=(
            "prospective_disjoint_known_key_trajectory_shape_validation"
            if retained
            else "pairwise_within_key_solver_intervention_or_ordered_clause_event_reader"
        ),
        confidence=1.0,
        suggested_queries=(
            [
                "Freeze the selected shape model before generating disjoint keys.",
                "Does its gain transfer prospectively to new prefix groups?",
            ]
            if retained
            else [
                "Do matched candidate pairs expose local transition effects hidden by global classification?",
                "Does ordered clause-event timing retain structure lost by aggregate horizon shapes?",
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
        or reader.api_id != "a267"
        or len(explicit) != 3
        or len(rows) != 4
        or len(inferred) != 1
        or len(reader._rules) != 2
        or len(reader._clusters) != 1
        or len(reader._gaps) != 1
        or rows[-1]["outcome"] != terminal
    ):
        raise RuntimeError("A267 authentic Causal Reader reopen gate failed")
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
        "# A267 — ChaCha20-R20 scale-free solver trajectory-shape reader",
        "",
        "A267 removes per-channel magnitude, reads four-horizon event profiles plus their first and second differences through four XOR-orbit operators, and evaluates a nested unseen-prefix model.",
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
    protocol, a251, a251_protocol = _load_protocol()
    started = time.perf_counter()
    tables, corpus = _load_tables(protocol, a251, a251_protocol)
    evaluation = nested_trajectory_shape_evaluate(
        tables,
        ridge_lambdas=protocol["operator"]["ridge_lambda_grid"],
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
            "FULLROUND_R20_SCALE_FREE_TRAJECTORY_SHAPE_CROSSVALIDATED_SIGNAL"
            if retained
            else "FULLROUND_R20_SCALE_FREE_TRAJECTORY_SHAPE_BOUNDARY"
        ),
        "protocol_sha256": PROTOCOL_SHA256,
        "protocol_state": protocol["protocol_state"],
        "runner_sha256": _file_sha256(Path(__file__)),
        "causal_derivation": protocol["causal_derivation"],
        "feature_contract": protocol["feature_contract"],
        "operator_grid": protocol["operator"],
        "trajectory_corpus": corpus,
        "evaluation": evaluation,
        "analysis_sha256": _canonical_sha256(evaluation),
        "retention_gate": {**gate, "passed": retained},
        "new_solver_measurements": 0,
        "volatile_total_elapsed_seconds": time.perf_counter() - started,
        "information_boundary": protocol["information_boundary"],
    }
    payload["causal"] = _build_causal(CAUSAL, payload, dotcausal_src)
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

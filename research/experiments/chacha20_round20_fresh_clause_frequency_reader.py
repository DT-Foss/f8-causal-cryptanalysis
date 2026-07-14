#!/usr/bin/env python3
"""Execute frozen A266 continuous exact learned-clause frequency reader."""

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

ROOT = Path(__file__).parents[2]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from arx_carry_leak.chacha20_clause_frequency import (  # noqa: E402
    build_clause_frequency_table,
)
from arx_carry_leak.chacha20_continuous_flow import (  # noqa: E402
    continuous_table_sha256,
    nested_continuous_flow_evaluate,
)

PROTOCOL = (
    ROOT / "research/configs/chacha20_round20_fresh_clause_frequency_reader_v1.json"
)
PROTOCOL_SHA256 = "560a8a415b60c582f818fc5fca5decadca69f38776a462c03b33262bca1a9767"
RESULT = (
    ROOT / "research/results/v1/chacha20_round20_fresh_clause_frequency_reader_v1.json"
)
CAUSAL = (
    ROOT / "research/results/v1/chacha20_round20_fresh_clause_frequency_reader_v1.causal"
)
REPORT = (
    ROOT / "research/reports/CAUSAL_CHACHA20_ROUND20_FRESH_CLAUSE_FREQUENCY_READER_V1.md"
)
DEFAULT_DOTCAUSAL_SRC = Path(
    "/Users/bhkmie/Documents/Forschung/O1/vendor/fabel/dotcausal_package/src"
)
ATTEMPT_ID = "A266"
RESULT_SCHEMA = "chacha20-round20-fresh-clause-frequency-reader-result-v1"


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
        raise RuntimeError(f"cannot import A266 dependency {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _anchor_path(value: str) -> Path:
    path = Path(value)
    return path if path.is_absolute() else ROOT / path


def _load_protocol() -> tuple[dict[str, Any], Any, dict[str, Any]]:
    if _file_sha256(PROTOCOL) != PROTOCOL_SHA256:
        raise RuntimeError("A266 frozen protocol hash differs")
    protocol = json.loads(PROTOCOL.read_bytes())
    feature = protocol.get("feature_contract", {})
    operator = protocol.get("operator", {})
    boundary = protocol.get("information_boundary", {})
    if (
        protocol.get("schema")
        != "chacha20-round20-fresh-clause-frequency-reader-protocol-v1"
        or protocol.get("attempt_id") != ATTEMPT_ID
        or protocol.get("protocol_state")
        != "frozen_after_A265_personal_authentic_causal_readback_and_synthetic_exact_frequency_preflight_before_any_A251_clause_frequency_table_construction_or_A266_model_fit"
        or feature.get("minimum_nonzero_candidates_per_key") != 4
        or feature.get("candidate_numeric_value_or_bits_included") is not False
        or feature.get("outer_test_true_prefix_used_for_fit_selection_or_weighting")
        is not False
        or operator.get("view_grid") != ["linear_l1", "log1p_l1", "sqrt_l1"]
        or operator.get("maximum_features_grid") != [16, 64, 256]
        or operator.get("ridge_grid") != [0.25, 1.0, 4.0]
        or operator.get("operator_setting_count") != 27
        or boundary.get("any_A251_frequency_table_constructed_by_A266_before_protocol_freeze")
        is not False
        or boundary.get("any_A266_frequency_support_effect_rank_or_model_fit_known_before_protocol_freeze")
        is not False
        or boundary.get("future_prospective_unknown_target_generated_or_opened")
        is not False
    ):
        raise RuntimeError("A266 frozen protocol semantic gate failed")
    anchors = protocol["anchors"]
    for path_key, path_value in anchors.items():
        if not path_key.endswith("_path"):
            continue
        hash_key = f"{path_key.removesuffix('_path')}_sha256"
        expected = anchors.get(hash_key)
        if not isinstance(expected, str) or _file_sha256(_anchor_path(path_value)) != expected:
            raise RuntimeError(f"A266 anchored dependency hash differs: {path_key}")
    preflight = json.loads(_anchor_path(anchors["preflight_path"]).read_bytes())
    if (
        preflight.get("schema")
        != "chacha20-round20-clause-frequency-preflight-v1"
        or preflight.get("attempt_id") != ATTEMPT_ID
        or preflight["information_boundary"]["used_any_A251_measurement_shard"]
        is not False
        or preflight["information_boundary"]["any_A266_operator_outcome_known"]
        is not False
    ):
        raise RuntimeError("A266 synthetic preflight gate failed")
    a251 = _import_path(ROOT / anchors["A251_runner_path"], "a266_a251")
    a251_protocol, _ = a251._load_protocol()
    return protocol, a251, a251_protocol


def analyze() -> dict[str, Any]:
    protocol, _, _ = _load_protocol()
    return {
        "attempt_id": ATTEMPT_ID,
        "protocol_sha256": PROTOCOL_SHA256,
        "known_key_count": protocol["input"]["required_key_count"],
        "candidate_measurements": protocol["input"]["required_key_count"] * 256,
        "operator_settings": protocol["operator"]["operator_setting_count"],
        "new_solver_measurements_permitted": False,
        "frequency_table_construction_started": False,
    }


def _load_tables(
    protocol: Mapping[str, Any], a251: Any, a251_protocol: Mapping[str, Any]
) -> tuple[list[Any], dict[str, Any]]:
    labels = list(a251_protocol["input"]["labels"])
    minimum_nonzero = int(
        protocol["feature_contract"]["minimum_nonzero_candidates_per_key"]
    )
    tables = []
    accepted = 0
    rejected = 0
    measurement_ledger = []
    table_ledger = []
    frequency_ledgers = []
    for label in labels:
        path = a251._measurement_path(label, "numeric")
        if not path.is_file():
            raise FileNotFoundError(f"A266 requires completed A251 shard: {path.name}")
        measurement = a251._read_measurement(path)
        summary = measurement["run"]["summary"]
        accepted += int(summary["learned_clause_accepted_total"])
        rejected += int(summary["learned_clause_rejected_large_total"])
        table, ledger = build_clause_frequency_table(
            measurement,
            minimum_nonzero_candidates=minimum_nonzero,
        )
        table_sha256 = continuous_table_sha256(table)
        tables.append(table)
        measurement_ledger.append(
            {
                "label": label,
                "compressed_sha256": _file_sha256(path),
                "raw_measurement_sha256": _canonical_sha256(measurement),
            }
        )
        table_ledger.append({"label": label, "table_sha256": table_sha256})
        frequency_ledgers.append({"label": label, **ledger})
        print(
            "A266_TABLE "
            + json.dumps(
                {
                    "label": label,
                    "raw_features": ledger["raw_feature_count"],
                    "retained_features": ledger[
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
        raise RuntimeError("A266 retained A251 clause corpus identity differs")
    return tables, {
        "known_keys": len(tables),
        "candidate_measurements": len(tables) * 256,
        "accepted_learned_clauses": accepted,
        "rejected_over_64_literal_clauses": rejected,
        "measurement_ledger": measurement_ledger,
        "measurement_ledger_sha256": _canonical_sha256(measurement_ledger),
        "frequency_feature_ledgers": frequency_ledgers,
        "frequency_feature_ledger_sha256": _canonical_sha256(frequency_ledgers),
        "table_ledger": table_ledger,
        "table_ledger_sha256": _canonical_sha256(table_ledger),
        "true_prefix_used_during_frequency_or_feature_retention": False,
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
        raise RuntimeError("A266 authoritative dotcausal.io source is unavailable")
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
        "A266:exact_frequency_transfer_retained"
        if retained
        else "A266:exact_frequency_transfer_boundary"
    )
    writer = CausalWriter(api_id="a266")
    writer._rules = []
    writer.add_rule(
        name="frequency_preserves_exact_identity_multiplicity",
        description="Repeated occurrences of exact signed variables, pairs, clauses, and lengths remain continuous coordinates instead of collapsing to presence bits.",
        pattern=["exact_learned_clause_stream", "assumption_projection"],
        conclusion="target_blind_exact_frequency_coordinates",
        confidence_modifier=1.0,
    )
    writer.add_rule(
        name="group_consistent_frequency_contrast",
        description="Feature weights and operator settings are learned only from training prefix groups and applied to the entirely unseen outer group.",
        pattern=["training_group_frequency_contrasts", "unseen_outer_prefix"],
        conclusion="prefix_blind_frequency_rank_evidence",
        confidence_modifier=1.0,
    )
    writer.add_triplet(
        trigger="A251:exact_shallow_learned_clause_corpus",
        mechanism="count_exact_identity_multiplicity_after_assumption_projection",
        outcome="A266:continuous_exact_frequency_tables",
        confidence=1.0,
        source=payload["frequency_clause_corpus"][
            "frequency_feature_ledger_sha256"
        ],
        quantification="20 keys; complete 256-candidate covers; ten exact frequency families",
        evidence=json.dumps(
            [
                {
                    "label": row["label"],
                    "features": row["retained_varying_feature_count"],
                    "families": row["retained_feature_families"],
                }
                for row in payload["frequency_clause_corpus"][
                    "frequency_feature_ledgers"
                ]
            ],
            sort_keys=True,
        ),
        domain="continuous exact learned-clause frequency",
        quality_score=1.0,
    )
    writer.add_triplet(
        trigger="A266:continuous_exact_frequency_tables",
        mechanism="nested_unseen_prefix_group_consistent_frequency_contrast",
        outcome="A266:five_unseen_prefix_frequency_models",
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
        domain="nested exact-frequency known-key transfer",
        quality_score=1.0,
    )
    writer.add_triplet(
        trigger="A266:five_unseen_prefix_frequency_models",
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
        trigger="A251:exact_shallow_learned_clause_corpus",
        mechanism="materialized_exact_frequency_plus_nested_group_contrast_chain",
        outcome=terminal,
        confidence=1.0,
        source="materialized:exact_clause_frequency_plus_nested_group_contrast",
        quantification="complete three-edge closure retained in-file",
        evidence="Materialized after exact frequency tables, nested evaluation, and all 256 shared-XOR controls.",
        domain="AI-native retained inference",
        quality_score=1.0,
        is_inferred=True,
    )
    writer.add_cluster(
        name="A266 continuous exact-frequency chain",
        entities=[
            "A251:exact_shallow_learned_clause_corpus",
            "count_exact_identity_multiplicity_after_assumption_projection",
            "A266:continuous_exact_frequency_tables",
            "nested_unseen_prefix_group_consistent_frequency_contrast",
            "A266:five_unseen_prefix_frequency_models",
            "all_256_shared_XOR_controls_and_frozen_retention_gate",
            terminal,
        ],
    )
    writer.add_gap(
        subject=terminal,
        predicate="next_required_object",
        expected_object_type=(
            "prospective_disjoint_known_key_exact_frequency_validation"
            if retained
            else "candidate_conditioned_solver_native_trajectory_delta_reader"
        ),
        confidence=1.0,
        suggested_queries=(
            [
                "Freeze the selected exact-frequency operator before generating disjoint keys.",
                "Does its rank gain survive entirely new prefix groups?",
            ]
            if retained
            else [
                "Which transition deltas between conflict horizons distinguish true candidates?",
                "Do solver-native event-shape derivatives transfer when absolute counts do not?",
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
        or reader.api_id != "a266"
        or len(explicit) != 3
        or len(rows) != 4
        or len(inferred) != 1
        or len(reader._rules) != 2
        or len(reader._clusters) != 1
        or len(reader._gaps) != 1
        or rows[-1]["outcome"] != terminal
    ):
        raise RuntimeError("A266 authentic Causal Reader reopen gate failed")
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
        "# A266 — ChaCha20-R20 continuous exact learned-clause frequency reader",
        "",
        "A266 retains exact learned-clause identity multiplicities after removing every candidate-assumption variable, then evaluates group-consistent continuous contrasts on an unseen prefix group in every outer fold.",
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
            "FULLROUND_R20_EXACT_FREQUENCY_CROSSVALIDATED_SIGNAL"
            if retained
            else "FULLROUND_R20_EXACT_FREQUENCY_BOUNDARY"
        ),
        "protocol_sha256": PROTOCOL_SHA256,
        "protocol_state": protocol["protocol_state"],
        "runner_sha256": _file_sha256(Path(__file__)),
        "causal_derivation": protocol["causal_derivation"],
        "feature_contract": protocol["feature_contract"],
        "operator_grid": operator,
        "frequency_clause_corpus": corpus,
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

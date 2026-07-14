#!/usr/bin/env python3
"""Execute frozen A261 directed operation-flow clause residuals."""

from __future__ import annotations

import argparse
import hashlib
import importlib
import importlib.util
import inspect
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

from arx_carry_leak.chacha20_operation_flow import (  # noqa: E402
    build_operation_flow_table,
    flow_graph_manifest,
    nearest_manifest,
    nearest_operation_taps,
    operation_flow_graph,
)

PROTOCOL = (
    ROOT
    / "research/configs/chacha20_round20_fresh_clause_operation_flow_reader_v1.json"
)
PROTOCOL_SHA256 = "24dac34de615def97167efb11405b8a7fc796ffad725e36340fd0067b46a54b9"
RESULT = (
    ROOT
    / "research/results/v1/chacha20_round20_fresh_clause_operation_flow_reader_v1.json"
)
CAUSAL = (
    ROOT
    / "research/results/v1/chacha20_round20_fresh_clause_operation_flow_reader_v1.causal"
)
REPORT = (
    ROOT
    / "research/reports/CAUSAL_CHACHA20_ROUND20_FRESH_CLAUSE_OPERATION_FLOW_READER_V1.md"
)
DEFAULT_DOTCAUSAL_SRC = Path(
    "/Users/bhkmie/Documents/Forschung/O1/vendor/fabel/dotcausal_package/src"
)
ATTEMPT_ID = "A261"
RESULT_SCHEMA = "chacha20-round20-fresh-clause-operation-flow-reader-result-v1"


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
    raw = json.dumps(
        value,
        indent=2,
        sort_keys=True,
        ensure_ascii=True,
        allow_nan=False,
    ).encode() + b"\n"
    _atomic_bytes(path, raw)


def _import_path(path: Path, name: str) -> Any:
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot import A261 dependency {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _anchor_path(value: str) -> Path:
    path = Path(value)
    return path if path.is_absolute() else ROOT / path


def _load_protocol() -> tuple[dict[str, Any], Any, Any, Any, Any, Any]:
    if _file_sha256(PROTOCOL) != PROTOCOL_SHA256:
        raise RuntimeError("A261 frozen protocol hash differs")
    protocol = json.loads(PROTOCOL.read_bytes())
    preflight_contract = protocol.get("public_preflight", {})
    feature = protocol.get("feature_contract", {})
    boundary = protocol.get("information_boundary", {})
    if (
        protocol.get("schema")
        != "chacha20-round20-fresh-clause-operation-flow-reader-protocol-v1"
        or protocol.get("attempt_id") != ATTEMPT_ID
        or protocol.get("protocol_state")
        != "frozen_after_A260_personal_authentic_causal_readback_and_target_blind_public_operation_flow_preflight_before_any_A251_clause_flow_projection_or_model_fit"
        or preflight_contract.get("operation_tap_count") != 640
        or preflight_contract.get("directed_edge_count") != 1232
        or preflight_contract.get("mapped_original_variables") != 80767
        or preflight_contract.get("mapped_fraction") != 1.0
        or feature.get("maximum_target_blind_high_dispersion_features_per_key") != 512
        or feature.get("residual_quantile_bins") != 8
        or feature.get("minimum_nonzero_candidates") != 4
        or feature.get("candidate_numeric_value_or_bits_included") is not False
        or feature.get("true_prefix_used_during_counter_residual_or_feature_selection")
        is not False
        or protocol.get("operator", {}).get("operator_setting_count") != 27
        or boundary.get("any_A251_measurement_shard_opened_by_A261_before_protocol_freeze")
        is not False
        or boundary.get("any_A251_learned_clause_projected_through_directed_flow_before_protocol_freeze")
        is not False
        or boundary.get("any_operation_flow_PoE_fit_before_protocol_freeze") is not False
        or boundary.get("future_prospective_unknown_target_generated_or_opened")
        is not False
    ):
        raise RuntimeError("A261 frozen protocol semantic gate failed")
    anchors = protocol["anchors"]
    for path_key, path_value in anchors.items():
        if not path_key.endswith("_path"):
            continue
        hash_key = f"{path_key.removesuffix('_path')}_sha256"
        expected = anchors.get(hash_key)
        if not isinstance(expected, str) or _file_sha256(_anchor_path(path_value)) != expected:
            raise RuntimeError(f"A261 anchored dependency hash differs: {path_key}")
    preflight = _import_path(
        ROOT / anchors["public_preflight_runner_path"], "a261_public_preflight"
    )
    a260 = _import_path(ROOT / anchors["A260_runner_path"], "a261_a260")
    a260_protocol, a259, a251, a242 = a260._load_protocol()
    return protocol, preflight, a260, a259, a251, a242


def analyze() -> dict[str, Any]:
    protocol, *_ = _load_protocol()
    return {
        "attempt_id": ATTEMPT_ID,
        "protocol_sha256": PROTOCOL_SHA256,
        "input_solver_measurements": protocol["input"]["required_key_count"] * 256,
        "new_solver_measurements_permitted": False,
        "directed_operation_edges": protocol["public_preflight"]["directed_edge_count"],
        "mapped_original_variables": protocol["public_preflight"][
            "mapped_original_variables"
        ],
        "clause_flow_projection_started": False,
    }


def _prepare_flow_reader(
    protocol: Mapping[str, Any],
    preflight: Any,
    a260: Any,
    a259: Any,
    a242: Any,
    directory: Path,
) -> tuple[Any, Any, dict[str, Any]]:
    a260_protocol, _a259, _a251, _a242 = a260._load_protocol()
    topology, mapping, topology_manifest, mapping_manifest = (
        preflight._prepare_with_exact_mapping(
            a260,
            a260_protocol,
            a259,
            a242,
            directory,
        )
    )
    graph = operation_flow_graph()
    nearest = nearest_operation_taps(topology, mapping)
    graph_geometry = flow_graph_manifest(graph)
    nearest_geometry = nearest_manifest(
        nearest,
        original_variable_count=int(
            protocol["public_preflight"]["original_variable_count"]
        ),
    )
    frozen = json.loads(
        (ROOT / protocol["anchors"]["public_preflight_path"]).read_bytes()
    )
    if (
        graph_geometry != frozen["operation_flow_graph"]
        or nearest_geometry != frozen["nearest_operation_taps"]
        or topology_manifest != frozen["operation_topology_manifest"]
        or mapping_manifest != frozen["operation_mapping_manifest"]
    ):
        raise RuntimeError("A261 public operation-flow preflight replay differs")
    return topology, (nearest, graph), {
        "flow_graph": graph_geometry,
        "nearest_operation_taps": nearest_geometry,
        "operation_mapping_manifest": mapping_manifest,
        "operation_topology_manifest": topology_manifest,
        "preflight_sha256": protocol["public_preflight"]["preflight_sha256"],
    }


def _load_tables(
    protocol: Mapping[str, Any],
    a251: Any,
    nearest: Any,
    graph: Any,
) -> tuple[list[Any], dict[str, Any]]:
    a251_protocol, _ = a251._load_protocol()
    labels = list(a251_protocol["input"]["labels"])
    feature = protocol["feature_contract"]
    tables = []
    accepted = 0
    rejected = 0
    exact_measurements = []
    table_ledger = []
    flow_ledgers = []
    token_counts = []
    for label in labels:
        path = a251._measurement_path(label, "numeric")
        if not path.is_file():
            raise FileNotFoundError(f"A261 requires completed A251 shard: {path.name}")
        measurement = a251._read_measurement(path)
        accepted += int(measurement["run"]["summary"]["learned_clause_accepted_total"])
        rejected += int(
            measurement["run"]["summary"]["learned_clause_rejected_large_total"]
        )
        table, flow_ledger = build_operation_flow_table(
            measurement,
            nearest,
            graph,
            maximum_features=int(
                feature["maximum_target_blind_high_dispersion_features_per_key"]
            ),
            quantile_bins=int(feature["residual_quantile_bins"]),
            minimum_nonzero_candidates=int(feature["minimum_nonzero_candidates"]),
        )
        tables.append(table)
        exact_measurements.append(
            {
                "label": label,
                "compressed_sha256": _file_sha256(path),
                "raw_measurement_sha256": _canonical_sha256(measurement),
            }
        )
        table_sha256 = a251._table_sha256(table)
        table_ledger.append({"label": label, "table_sha256": table_sha256})
        flow_ledgers.append({"label": label, **flow_ledger})
        token_count = sum(len(tokens) for tokens in table.candidate_tokens)
        token_counts.append(token_count)
        print(
            "A261_TABLE "
            + json.dumps(
                {
                    "label": label,
                    "tokens": token_count,
                    "selected_features": flow_ledger["residual_manifest"][
                        "selected_feature_count"
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
        raise RuntimeError("A261 retained A251 clause corpus identity differs")
    return tables, {
        "accepted_learned_clauses": accepted,
        "rejected_over_64_literal_clauses": rejected,
        "semantic_token_counts_per_key": token_counts,
        "exact_measurement_ledger": exact_measurements,
        "exact_measurement_ledger_sha256": _canonical_sha256(exact_measurements),
        "flow_ledger": flow_ledgers,
        "flow_ledger_sha256": _canonical_sha256(flow_ledgers),
        "table_ledger": table_ledger,
        "table_ledger_sha256": _canonical_sha256(table_ledger),
        "true_prefix_used_during_counter_residual_or_feature_selection": False,
    }


def _load_dotcausal(dotcausal_src: Path) -> tuple[Any, Any, dict[str, Any]]:
    try:
        io_module = importlib.import_module("dotcausal.io")
    except ModuleNotFoundError:
        if not dotcausal_src.is_dir():
            raise FileNotFoundError("dotcausal 0.3.1 source is unavailable") from None
        sys.path.insert(0, str(dotcausal_src))
        io_module = importlib.import_module("dotcausal.io")
    writer = io_module.CausalWriter
    reader = io_module.CausalReader
    io_path = Path(inspect.getsourcefile(reader) or "")
    if not io_path.is_file():
        raise RuntimeError("A261 authoritative dotcausal.io source is unavailable")
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
        "A261:directed_flow_residual_transfer_retained"
        if retained
        else "A261:directed_flow_residual_boundary"
    )
    writer = CausalWriter(api_id="a261")
    writer._rules = []
    writer.add_rule(
        name="directed_flow_replaces_nearest_node_semantics",
        description="Exact producer-to-consumer paths retain direction discarded by undirected nearest-anchor coordinates.",
        pattern=["exact_operation_DAG", "nearest_tap_bitsets"],
        conclusion="typed_clause_flow_coordinates",
        confidence_modifier=1.0,
    )
    writer.add_rule(
        name="within_key_residuals_remove_operation_class_baseline",
        description="Complete candidate-cover medians and quantiles separate candidate-specific deviations from common operation-class volume.",
        pattern=["complete_256_candidate_cover", "twice_median_residualization"],
        conclusion="target_blind_flow_residual_documents",
        confidence_modifier=1.0,
    )
    writer.add_triplet(
        trigger="A260:exact_operation_topology_boundary",
        mechanism="reconstruct_exact_directed_640_tap_operation_DAG",
        outcome="A261:typed_directed_operation_flow",
        confidence=1.0,
        source=payload["public_flow_preflight"]["flow_graph"][
            "directed_distance_sha256"
        ],
        quantification="640 taps; 1232 directed producer-to-consumer edges",
        evidence=json.dumps(payload["public_flow_preflight"]["flow_graph"], sort_keys=True),
        domain="ChaCha20-R20 operation semantics",
        quality_score=1.0,
    )
    writer.add_triplet(
        trigger="A261:typed_directed_operation_flow",
        mechanism="project_A251_clauses_and_subtract_complete_cover_median_baselines",
        outcome="A261:target_blind_flow_residual_documents",
        confidence=1.0,
        source=payload["semantic_clause_corpus"]["flow_ledger_sha256"],
        quantification="20 keys; 256 candidates/key; 8 typed token families",
        evidence=json.dumps(
            {
                "accepted_clauses": payload["semantic_clause_corpus"][
                    "accepted_learned_clauses"
                ],
                "token_counts": payload["semantic_clause_corpus"][
                    "semantic_token_counts_per_key"
                ],
            },
            sort_keys=True,
        ),
        domain="full-round learned-clause flow residuals",
        quality_score=1.0,
    )
    writer.add_triplet(
        trigger="A261:target_blind_flow_residual_documents",
        mechanism="nested_unseen_prefix_Bernoulli_product_of_experts",
        outcome="A261:five_outer_prefix_flow_models",
        confidence=1.0,
        source=payload["analysis_sha256"],
        quantification="five outer prefix folds; inner selection over 27 frozen settings",
        evidence=json.dumps(
            {
                key: payload["evaluation"][key]
                for key in (
                    "mean_log2_rank",
                    "mean_log2_rank_bit_gain",
                    "exact_shared_xor_p",
                    "outer_prefix_folds_with_positive_bit_gain",
                )
            },
            sort_keys=True,
        ),
        domain="nested known-key transfer",
        quality_score=1.0,
    )
    writer.add_triplet(
        trigger="A261:five_outer_prefix_flow_models",
        mechanism="frozen_retention_gate",
        outcome=terminal,
        confidence=1.0,
        source=payload["analysis_sha256"],
        quantification=json.dumps(payload["retention_gate"], sort_keys=True),
        evidence=json.dumps(
            {
                key: payload["evaluation"][key]
                for key in (
                    "observed_offset",
                    "best_shared_xor_offset",
                    "exact_shared_xor_p",
                )
            },
            sort_keys=True,
        ),
        domain="prospective-routing evidence",
        quality_score=1.0,
    )
    writer.add_triplet(
        trigger="A260:exact_operation_topology_boundary",
        mechanism="materialized_directed_flow_residual_chain",
        outcome=terminal,
        confidence=1.0,
        source="materialized:directed_flow_plus_within_key_residuals",
        quantification="complete four-edge closure retained in-file",
        evidence="Materialized after complete flow projection, nested evaluation, and exact XOR controls.",
        domain="AI-native retained inference",
        quality_score=1.0,
        is_inferred=True,
    )
    writer.add_cluster(
        name="A261 directed operation-flow chain",
        entities=[
            "A260:exact_operation_topology_boundary",
            "reconstruct_exact_directed_640_tap_operation_DAG",
            "A261:typed_directed_operation_flow",
            "project_A251_clauses_and_subtract_complete_cover_median_baselines",
            "A261:target_blind_flow_residual_documents",
            "nested_unseen_prefix_Bernoulli_product_of_experts",
            "A261:five_outer_prefix_flow_models",
            "frozen_retention_gate",
            terminal,
        ],
    )
    writer.add_gap(
        subject=terminal,
        predicate="next_required_object",
        expected_object_type=(
            "prospective_entirely_new_known_key_flow_validation"
            if retained
            else "continuous_matched_contrast_flow_score_without_token_discretization"
        ),
        confidence=1.0,
        suggested_queries=(
            [
                "Freeze the retained flow operator before generating disjoint keys.",
                "Does it preserve rank gain on entirely unseen prefix groups?",
            ]
            if retained
            else [
                "Does continuous signed residual magnitude transfer when quantile tokens do not?",
                "Which directed path counters separate true and matched wrong candidates within each training key?",
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
        or reader.api_id != "a261"
        or len(explicit) != 4
        or len(rows) != 5
        or len(inferred) != 1
        or len(reader._rules) != 2
        or len(reader._clusters) != 1
        or len(reader._gaps) != 1
        or rows[-1]["outcome"] != terminal
    ):
        raise RuntimeError("A261 authentic Causal Reader reopen gate failed")
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
        "# A261 — ChaCha20-R20 directed operation-flow residual reader",
        "",
        "The frozen reader maps the retained A251 clause corpus onto exact directed ChaCha20 operation paths, subtracts each counter's complete-cover baseline within every key, and evaluates the result on unseen prefix groups.",
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
        "## Public geometry",
        "",
        f"- Directed operation taps / edges: **{payload['public_flow_preflight']['flow_graph']['tap_count']} / {payload['public_flow_preflight']['flow_graph']['directed_edge_count']}**",
        f"- Mapped original CNF variables: **{payload['public_flow_preflight']['nearest_operation_taps']['mapped_original_variables']} / {payload['public_flow_preflight']['nearest_operation_taps']['original_variable_count']}**",
        "",
        "## Authentic AI-native Causal readback",
        "",
        f"- Reader integrity: **{causal['integrity_verified_by_authoritative_reader']}**",
        f"- Explicit / materialized: **{causal['explicit_triplets']} / {causal['materialized_inferred_triplets']}**",
        f"- Next gap: **{causal['personal_semantic_readback']['next_gap']['expected_object_type']}**",
    ]
    return "\n".join(lines) + "\n"


def execute(*, dotcausal_src: Path = DEFAULT_DOTCAUSAL_SRC) -> dict[str, Any]:
    protocol, preflight, a260, a259, a251, a242 = _load_protocol()
    started = time.perf_counter()
    with tempfile.TemporaryDirectory(prefix="a261_clause_operation_flow_") as temporary:
        _topology, (nearest, graph), public_flow = _prepare_flow_reader(
            protocol,
            preflight,
            a260,
            a259,
            a242,
            Path(temporary),
        )
        tables, corpus = _load_tables(protocol, a251, nearest, graph)
    operator = protocol["operator"]
    evaluation = a251.nested_evaluate(
        tables,
        operator["minimum_positive_support_grid"],
        operator["beta_smoothing_grid"],
        operator["token_log_odds_cap_grid"],
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
            "FULLROUND_R20_DIRECTED_OPERATION_FLOW_RESIDUAL_CROSSVALIDATED_SIGNAL"
            if retained
            else "FULLROUND_R20_DIRECTED_OPERATION_FLOW_RESIDUAL_BOUNDARY"
        ),
        "protocol_sha256": PROTOCOL_SHA256,
        "protocol_state": protocol["protocol_state"],
        "causal_derivation": protocol["causal_derivation"],
        "public_flow_preflight": public_flow,
        "feature_contract": protocol["feature_contract"],
        "operator_grid": {
            "minimum_positive_support": operator["minimum_positive_support_grid"],
            "beta_smoothing": operator["beta_smoothing_grid"],
            "token_log_odds_cap": operator["token_log_odds_cap_grid"],
            "settings": operator["operator_setting_count"],
        },
        "semantic_clause_corpus": corpus,
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

#!/usr/bin/env python3
"""Execute the frozen A259 public-CNF learned-clause topology reader."""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
import sys
import tempfile
import time
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

ROOT = Path(__file__).parents[2]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from arx_carry_leak.cnf_semantic_topology import (  # noqa: E402
    CNFSemanticTopology,
    build_topology_clause_table,
    topology_manifest,
)

PROTOCOL = ROOT / "research/configs/chacha20_round20_fresh_clause_topology_reader_v1.json"
PROTOCOL_SHA256 = "03e73b26025bbb5242c57596f7b0f5d826dd513cd51cf0d33f1694453e866f4c"
RESULT = ROOT / "research/results/v1/chacha20_round20_fresh_clause_topology_reader_v1.json"
CAUSAL = ROOT / "research/results/v1/chacha20_round20_fresh_clause_topology_reader_v1.causal"
REPORT = ROOT / "research/reports/CAUSAL_CHACHA20_ROUND20_FRESH_CLAUSE_TOPOLOGY_READER_V1.md"
DEFAULT_DOTCAUSAL_SRC = Path(
    "/Users/bhkmie/Documents/Forschung/O1/vendor/fabel/dotcausal_package/src"
)
ATTEMPT_ID = "A259"
RESULT_SCHEMA = "chacha20-round20-fresh-clause-topology-reader-result-v1"


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
        raise RuntimeError(f"cannot import A259 dependency {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _anchor_path(value: str) -> Path:
    path = Path(value)
    return path if path.is_absolute() else ROOT / path


def _load_protocol() -> tuple[dict[str, Any], Any, Any]:
    if _file_sha256(PROTOCOL) != PROTOCOL_SHA256:
        raise RuntimeError("A259 frozen protocol hash differs")
    protocol = json.loads(PROTOCOL.read_bytes())
    topology = protocol.get("public_topology", {})
    boundary = protocol.get("information_boundary", {})
    if (
        protocol.get("schema")
        != "chacha20-round20-fresh-clause-topology-reader-protocol-v1"
        or protocol.get("attempt_id") != ATTEMPT_ID
        or protocol.get("protocol_state")
        != "frozen_after_A251_personal_causal_readback_and_unlabeled_public_CNF_topology_preflight_before_any_A251_clause_topology_projection_or_model_fit"
        or protocol.get("input", {}).get("new_solver_measurements_permitted") is not False
        or topology.get("variable_count") != 80767
        or topology.get("clause_count") != 252375
        or topology.get("literal_occurrences") != 615979
        or topology.get("anchor_group_count") != 51
        or topology.get("raw_structural_coordinates_per_variable") != 59
        or topology.get("semantic_readout_feature_count_per_variable") != 9
        or protocol.get("operator", {}).get("operator_setting_count") != 27
        or boundary.get(
            "any_A251_learned_clause_projected_through_topology_before_protocol_freeze"
        )
        is not False
        or boundary.get("any_semantic_topology_PoE_fit_before_protocol_freeze")
        is not False
        or boundary.get("future_prospective_unknown_target_generated_or_opened")
        is not False
    ):
        raise RuntimeError("A259 frozen protocol semantic gate failed")
    anchors = protocol["anchors"]
    for path_key, path_value in anchors.items():
        if not path_key.endswith("_path"):
            continue
        hash_key = f"{path_key.removesuffix('_path')}_sha256"
        expected = anchors.get(hash_key)
        if not isinstance(expected, str) or _file_sha256(_anchor_path(path_value)) != expected:
            raise RuntimeError(f"A259 anchored dependency hash differs: {path_key}")
    a251 = _import_path(ROOT / anchors["A251_runner_path"], "a259_a251")
    _a251_protocol, a242 = a251._load_protocol()
    return protocol, a251, a242


def analyze() -> dict[str, Any]:
    protocol, _, _ = _load_protocol()
    return {
        "attempt_id": ATTEMPT_ID,
        "protocol_sha256": PROTOCOL_SHA256,
        "input_solver_measurements": protocol["input"]["required_key_count"] * 256,
        "new_solver_measurements_permitted": False,
        "public_topology_anchor_groups": protocol["public_topology"][
            "anchor_group_count"
        ],
        "operator_settings": protocol["operator"]["operator_setting_count"],
        "clause_topology_projection_started": False,
    }


def _anchor_groups(
    key_mapping: Sequence[int], output_mapping: Sequence[Sequence[int]]
) -> dict[str, list[int]]:
    if (
        len(key_mapping) != 20
        or len(output_mapping) != 16
        or any(len(row) != 32 for row in output_mapping)
    ):
        raise ValueError("A259 symbolic anchor geometry differs")
    key_variables = [abs(int(value)) for value in key_mapping]
    outputs = [[abs(int(value)) for value in row] for row in output_mapping]
    if len(set(key_variables)) != 20 or len({value for row in outputs for value in row}) != 512:
        raise ValueError("A259 symbolic anchor variables are not bijective")
    groups = {
        "key_suffix": key_variables[:12],
        "key_candidate_prefix": key_variables[12:],
        "output_all": [value for row in outputs for value in row],
    }
    groups.update(
        {f"output_lane_{lane:02d}": outputs[lane] for lane in range(16)}
    )
    groups.update(
        {
            f"output_bit_{bit:02d}": [outputs[lane][bit] for lane in range(16)]
            for bit in range(32)
        }
    )
    if len(groups) != 51:
        raise RuntimeError("A259 public topology anchor-group count differs")
    return groups


def _prepare_topology(
    protocol: Mapping[str, Any], a242: Any, directory: Path
) -> tuple[CNFSemanticTopology, dict[str, Any]]:
    a242_protocol = a242._load_protocol()
    prepared = a242._prepare(a242_protocol, directory)
    groups = _anchor_groups(prepared["key_mapping"], prepared["output_mapping"])
    started = time.perf_counter()
    topology = CNFSemanticTopology.from_dimacs(
        prepared["base_raw"],
        anchor_groups=groups,
        maximum_distance=int(protocol["public_topology"]["maximum_distance"]),
    )
    elapsed = time.perf_counter() - started
    manifest = topology_manifest(topology)
    expected = protocol["public_topology"]
    if (
        manifest["variable_count"] != expected["variable_count"]
        or manifest["clause_count"] != expected["clause_count"]
        or manifest["literal_occurrences"] != expected["literal_occurrences"]
        or manifest["structural_coordinate_count_per_variable"]
        != expected["raw_structural_coordinates_per_variable"]
        or manifest["semantic_readout_feature_count_per_variable"]
        != expected["semantic_readout_feature_count_per_variable"]
        or set(manifest["anchor_distance_sha256"]) != set(groups)
        or manifest["finite"] is not True
    ):
        raise RuntimeError("A259 public CNF topology manifest differs")
    manifest["volatile_build_elapsed_seconds"] = elapsed
    manifest["base_cnf_sha256"] = _sha256(prepared["base_raw"])
    manifest["anchor_groups_sha256"] = _canonical_sha256(groups)
    return topology, manifest


def _load_tables(
    protocol: Mapping[str, Any], a251: Any, topology: CNFSemanticTopology
) -> tuple[list[Any], dict[str, Any]]:
    a251_protocol = json.loads(
        (ROOT / protocol["anchors"]["A251_protocol_path"]).read_bytes()
    )
    labels = list(a251_protocol["input"]["labels"])
    tables = []
    accepted = 0
    rejected = 0
    exact_measurement_shas = []
    semantic_table_shas = []
    semantic_token_counts = []
    for label in labels:
        path = a251._measurement_path(label, "numeric")
        if not path.is_file():
            raise FileNotFoundError(f"A259 requires completed A251 shard: {path.name}")
        measurement = a251._read_measurement(path)
        accepted += int(measurement["run"]["summary"]["learned_clause_accepted_total"])
        rejected += int(
            measurement["run"]["summary"]["learned_clause_rejected_large_total"]
        )
        table = build_topology_clause_table(measurement, topology)
        tables.append(table)
        exact_measurement_shas.append(
            {
                "label": label,
                "compressed_sha256": _file_sha256(path),
                "raw_measurement_sha256": _canonical_sha256(measurement),
            }
        )
        semantic_table_shas.append(
            {"label": label, "table_sha256": a251._table_sha256(table)}
        )
        semantic_token_counts.append(sum(len(tokens) for tokens in table.candidate_tokens))
        print(
            "A259_TABLE "
            + json.dumps(
                {
                    "label": label,
                    "tokens": semantic_token_counts[-1],
                    "table_sha256": semantic_table_shas[-1]["table_sha256"],
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
        raise RuntimeError("A259 retained A251 clause corpus identity differs")
    return tables, {
        "accepted_learned_clauses": accepted,
        "rejected_over_64_literal_clauses": rejected,
        "semantic_token_counts_per_key": semantic_token_counts,
        "exact_measurement_ledger": exact_measurement_shas,
        "exact_measurement_ledger_sha256": _canonical_sha256(exact_measurement_shas),
        "semantic_table_ledger": semantic_table_shas,
        "semantic_table_ledger_sha256": _canonical_sha256(semantic_table_shas),
    }


def _build_causal(
    path: Path,
    payload: Mapping[str, Any],
    a242: Any,
    dotcausal_src: Path,
) -> dict[str, Any]:
    CausalWriter, CausalReader, source = a242._load_dotcausal(dotcausal_src)
    evaluation = payload["evaluation"]
    retained = payload["retention_gate"]["passed"]
    outcome = (
        "A259:public_CNF_clause_topology_transfer_retained"
        if retained
        else "A259:public_CNF_clause_topology_boundary"
    )
    writer = CausalWriter(api_id="a259")
    writer._rules = []
    writer.add_rule(
        name="public_topology_smooths_absolute_clause_identity",
        description="Variables that differ by absolute DIMACS ID can share candidate-independent local geometry and distances to key, output, lane, and bit-position anchors in the public CNF.",
        pattern=["exact_clause_identity_boundary", "public_CNF_semantic_coordinates"],
        conclusion="topology_smoothed_clause_evidence",
        confidence_modifier=1.0,
    )
    writer.add_rule(
        name="nested_unseen_prefix_topology_validation",
        description="Every outer prefix is scored by a topology PoE selected and fit without that prefix group.",
        pattern=["inner_topology_operator_selection", "unseen_outer_prefix"],
        conclusion="prefix_blind_topology_transfer_evidence",
        confidence_modifier=1.0,
    )
    writer.add_triplet(
        trigger="A251:exact_clause_identity_representation_boundary",
        mechanism="map_learned_literals_into_59_public_CNF_coordinates",
        outcome="A259:nine_semantic_variable_readouts",
        confidence=1.0,
        source=payload["topology_reader_sha256"],
        quantification="80,767 variables; 252,375 clauses; 51 anchor groups; maximum graph distance 8",
        evidence=json.dumps(payload["topology_manifest"], sort_keys=True),
        domain="public constraint-graph semantics",
        quality_score=1.0,
    )
    writer.add_triplet(
        trigger="A259:nine_semantic_variable_readouts",
        mechanism="semantic_clause_pair_and_horizon_tokenization",
        outcome="A259:candidate_blind_topology_token_corpus",
        confidence=1.0,
        source=payload["semantic_clause_corpus"]["semantic_table_ledger_sha256"],
        quantification="same 35,081 A251 accepted clauses; zero new solver measurements",
        evidence=json.dumps(payload["feature_contract"], sort_keys=True),
        domain="semantic learned-clause representation",
        quality_score=1.0,
    )
    writer.add_triplet(
        trigger="A259:candidate_blind_topology_token_corpus",
        mechanism="nested_Bernoulli_topology_product_of_experts",
        outcome="A259:five_unseen_prefix_topology_models",
        confidence=1.0,
        source=payload["analysis_sha256"],
        quantification="five outer folds; 27 settings selected only inside training folds",
        evidence=json.dumps(
            [
                {
                    "prefix": fold["outer_prefix_index"],
                    "support": fold["selected_minimum_positive_support"],
                    "smoothing": fold["selected_beta_smoothing"],
                    "cap": fold["selected_token_log_odds_cap"],
                    "mean_log2_rank": fold["test_mean_log2_rank"],
                }
                for fold in evaluation["outer_folds"]
            ],
            sort_keys=True,
        ),
        domain="nested known-key topology reader",
        quality_score=1.0,
    )
    writer.add_triplet(
        trigger="A259:five_unseen_prefix_topology_models",
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
        trigger="A251:exact_clause_identity_representation_boundary",
        mechanism="materialized_public_CNF_topology_chain",
        outcome=outcome,
        confidence=1.0,
        source="materialized:public_topology_smooths_absolute_clause_identity+nested_unseen_prefix_topology_validation",
        quantification="four-edge semantic closure retained in-file",
        evidence="Materialized after complete topology projection, nested outer evaluation, and exact XOR controls.",
        domain="AI-native retained inference",
        quality_score=1.0,
        is_inferred=True,
    )
    writer.add_cluster(
        name="A259 public CNF topology chain",
        entities=[
            "A251:exact_clause_identity_representation_boundary",
            "map_learned_literals_into_59_public_CNF_coordinates",
            "A259:nine_semantic_variable_readouts",
            "semantic_clause_pair_and_horizon_tokenization",
            "A259:candidate_blind_topology_token_corpus",
        ],
    )
    writer.add_cluster(
        name="A259 nested unseen-prefix chain",
        entities=[
            "nested_Bernoulli_topology_product_of_experts",
            "A259:five_unseen_prefix_topology_models",
            "unseen_prefix_ranks_plus_all_256_XOR_controls",
            outcome,
        ],
    )
    writer.add_gap(
        subject=outcome,
        predicate="next_required_intervention",
        expected_object_type=(
            "prospective_entirely_new_known_key_topology_validation"
            if retained
            else "exact_round_lane_bit_operation_anchor_reader"
        ),
        confidence=1.0,
        suggested_queries=(
            [
                "Freeze the topology operator before generating new prefix groups.",
                "If retained prospectively, use it to order a sealed unknown target.",
            ]
            if retained
            else [
                "Probe named SMT state words to map exact round, lane, bit, and operation anchors.",
                "Does operation-typed distance transfer where coarse public graph geometry does not?",
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
        or reader.api_id != "a259"
        or len(explicit) != 4
        or len(rows) != 5
        or len(inferred) != 1
        or len(reader._rules) != 2
        or len(reader._clusters) != 2
        or len(reader._gaps) != 1
    ):
        raise RuntimeError("A259 authentic Causal Reader reopen gate failed")
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
        "# A259 — ChaCha20-R20 public-CNF learned-clause topology reader",
        "",
        "The exact A251 clause corpus is reused without a single new solver measurement. Absolute learned variable IDs are replaced by candidate-independent public-CNF geometry relative to key, output, lane, and bit-position anchors.",
        "",
        "## Result",
        "",
        f"- Evidence stage: **{payload['evidence_stage']}**",
        f"- Outer-holdout mean log2 rank: **{evaluation['mean_log2_rank']:.12f}**",
        f"- Uniform reference: **{evaluation['uniform_mean_log2_rank_reference']:.12f}**",
        f"- Rank-information gain: **{evaluation['mean_log2_rank_bit_gain']:.12f} bits**",
        f"- Exact shared-XOR p: **{evaluation['exact_shared_xor_p']:.12f}**",
        f"- Prefix folds with positive gain: **{evaluation['outer_prefix_folds_with_positive_bit_gain']} / 5**",
        f"- Reused accepted learned clauses: **{payload['semantic_clause_corpus']['accepted_learned_clauses']}**",
        "- New solver measurements: **0**",
        "",
        "## Outer folds",
        "",
        "| Prefix | Min support | Beta | Cap | Retained tokens | Mean log2 rank |",
        "|---:|---:|---:|---:|---:|---:|",
    ]
    for fold in evaluation["outer_folds"]:
        lines.append(
            f"| {fold['outer_prefix_index']} | {fold['selected_minimum_positive_support']} | {fold['selected_beta_smoothing']} | {fold['selected_token_log_odds_cap']} | {fold['model']['retained_token_count']} | {fold['test_mean_log2_rank']:.6f} |"
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
    protocol, a251, a242 = _load_protocol()
    started = time.perf_counter()
    with tempfile.TemporaryDirectory(prefix="a259_clause_topology_") as temporary:
        topology, manifest = _prepare_topology(protocol, a242, Path(temporary))
        tables, corpus = _load_tables(protocol, a251, topology)
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
            "FULLROUND_R20_PUBLIC_CNF_CLAUSE_TOPOLOGY_CROSSVALIDATED_SIGNAL"
            if retained
            else "FULLROUND_R20_PUBLIC_CNF_CLAUSE_TOPOLOGY_BOUNDARY"
        ),
        "protocol_sha256": PROTOCOL_SHA256,
        "protocol_state": protocol["protocol_state"],
        "causal_derivation": protocol["causal_derivation"],
        "topology_manifest": manifest,
        "topology_reader_sha256": protocol["anchors"]["topology_reader_sha256"],
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
                "reused_accepted_clauses": corpus["accepted_learned_clauses"],
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

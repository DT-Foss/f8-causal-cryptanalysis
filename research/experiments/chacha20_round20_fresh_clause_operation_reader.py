#!/usr/bin/env python3
"""Execute frozen A260 exact-operation learned-clause semantics."""

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
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any

import numpy as np

ROOT = Path(__file__).parents[2]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from arx_carry_leak.chacha20_operation_taps import (  # noqa: E402
    MAPPING_DIMENSIONS,
    TAP_COUNT,
    WORD_BITS,
    CNFOperationTopology,
    augment_formula,
    decode_vectorized_mapping,
    mapping_assertions,
    operation_anchor_groups,
    operation_taps,
    operation_topology_manifest,
)
from arx_carry_leak.cnf_semantic_topology import (  # noqa: E402
    build_topology_clause_table,
)

PROTOCOL = ROOT / "research/configs/chacha20_round20_fresh_clause_operation_reader_v1.json"
PROTOCOL_SHA256 = "e77e6967cf9900039e5e1bf65460b74b897227f15bb6f984079fe3130d8600e2"
RESULT = ROOT / "research/results/v1/chacha20_round20_fresh_clause_operation_reader_v1.json"
CAUSAL = ROOT / "research/results/v1/chacha20_round20_fresh_clause_operation_reader_v1.causal"
REPORT = ROOT / "research/reports/CAUSAL_CHACHA20_ROUND20_FRESH_CLAUSE_OPERATION_READER_V1.md"
DEFAULT_DOTCAUSAL_SRC = Path(
    "/Users/bhkmie/Documents/Forschung/O1/vendor/fabel/dotcausal_package/src"
)
ATTEMPT_ID = "A260"
RESULT_SCHEMA = "chacha20-round20-fresh-clause-operation-reader-result-v1"


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
        raise RuntimeError(f"cannot import A260 dependency {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _anchor_path(value: str) -> Path:
    path = Path(value)
    return path if path.is_absolute() else ROOT / path


def _load_protocol() -> tuple[dict[str, Any], Any, Any, Any]:
    if _file_sha256(PROTOCOL) != PROTOCOL_SHA256:
        raise RuntimeError("A260 frozen protocol hash differs")
    protocol = json.loads(PROTOCOL.read_bytes())
    preflight = protocol.get("operation_tap_preflight", {})
    boundary = protocol.get("information_boundary", {})
    if (
        protocol.get("schema")
        != "chacha20-round20-fresh-clause-operation-reader-protocol-v1"
        or protocol.get("attempt_id") != ATTEMPT_ID
        or protocol.get("protocol_state")
        != "frozen_after_A259_personal_causal_readback_and_target_blind_640_operation_tap_preflight_before_any_A251_clause_operation_projection_or_model_fit"
        or protocol.get("input", {}).get("new_solver_measurements_permitted") is not False
        or preflight.get("named_word_count") != TAP_COUNT
        or preflight.get("operation_bit_count") != TAP_COUNT * WORD_BITS
        or preflight.get("mapping_export_count") != len(MAPPING_DIMENSIONS)
        or preflight.get("original_252375_clause_body_is_exact_augmented_prefix") is not True
        or preflight.get("total_anchor_group_count") != 141
        or preflight.get("semantic_readout_feature_count_per_variable") != 23
        or protocol.get("operator", {}).get("operator_setting_count") != 27
        or boundary.get("any_A251_learned_clause_projected_through_operation_topology_before_protocol_freeze")
        is not False
        or boundary.get("any_operation_topology_PoE_fit_before_protocol_freeze") is not False
        or boundary.get("future_prospective_unknown_target_generated_or_opened") is not False
    ):
        raise RuntimeError("A260 frozen protocol semantic gate failed")
    anchors = protocol["anchors"]
    for path_key, path_value in anchors.items():
        if not path_key.endswith("_path"):
            continue
        hash_key = f"{path_key.removesuffix('_path')}_sha256"
        expected = anchors.get(hash_key)
        if not isinstance(expected, str) or _file_sha256(_anchor_path(path_value)) != expected:
            raise RuntimeError(f"A260 anchored dependency hash differs: {path_key}")
    a259 = _import_path(ROOT / anchors["A259_runner_path"], "a260_a259")
    _a259_protocol, a251, a242 = a259._load_protocol()
    return protocol, a259, a251, a242


def analyze() -> dict[str, Any]:
    protocol, _, _, _ = _load_protocol()
    return {
        "attempt_id": ATTEMPT_ID,
        "protocol_sha256": PROTOCOL_SHA256,
        "input_solver_measurements": protocol["input"]["required_key_count"] * 256,
        "new_solver_measurements_permitted": False,
        "named_operation_words": protocol["operation_tap_preflight"]["named_word_count"],
        "exact_operation_bits": protocol["operation_tap_preflight"]["operation_bit_count"],
        "operation_projection_started": False,
    }


def _decode_header(raw: bytes) -> tuple[int, int, list[bytes]]:
    lines = raw.splitlines(keepends=True)
    fields = lines[0].split()
    if len(fields) != 4 or fields[:2] != [b"p", b"cnf"]:
        raise RuntimeError("A260 DIMACS header differs")
    return int(fields[2]), int(fields[3]), lines


def _prepare_operation_topology(
    protocol: Mapping[str, Any],
    a259: Any,
    a242: Any,
    directory: Path,
) -> tuple[CNFOperationTopology, dict[str, Any], dict[str, Any]]:
    a242_protocol = a242._load_protocol()
    prepared = a242._prepare(a242_protocol, directory)
    challenge = prepared["public"].build_known_challenge(
        prepared["public_material"], low20=int(prepared["rows"][0]["low20"])
    )
    formula = prepared["template"].symbolic_formula(prepared["public"], challenge)
    taps = operation_taps()
    augmented_formula = augment_formula(formula, taps)
    expected = protocol["operation_tap_preflight"]
    if (
        _sha256(formula.encode()) != expected["original_formula_sha256"]
        or _sha256(augmented_formula.encode()) != expected["augmented_formula_sha256"]
    ):
        raise RuntimeError("A260 symbolic formula identity differs")
    template_protocol = json.loads(
        (ROOT / a242_protocol["anchors"]["symbolic_template_protocol_path"]).read_bytes()
    )
    config = template_protocol["symbolic_R20_template"]
    augmented_path = directory / "a260_operation_augmented.cnf"
    base_export = prepared["template"]._export(
        formula=augmented_formula,
        output=augmented_path,
        arguments=config["arguments"],
        bitwuzla=config["Bitwuzla_path"],
    )
    augmented_raw = augmented_path.read_bytes()
    original_variables, original_clauses, original_lines = _decode_header(prepared["base_raw"])
    augmented_variables, augmented_clauses, augmented_lines = _decode_header(augmented_raw)
    original_body = original_lines[1:]
    augmented_body = augmented_lines[1:]
    if (
        base_export["status"] not in {"sat", "unknown"}
        or _sha256(prepared["base_raw"]) != expected["original_base_cnf_sha256"]
        or _sha256(augmented_raw) != expected["augmented_base_cnf_sha256"]
        or original_variables != expected["original_variable_count"]
        or original_clauses != expected["original_clause_count"]
        or augmented_variables != expected["augmented_variable_count"]
        or augmented_clauses != expected["augmented_clause_count"]
        or augmented_body[: len(original_body)] != original_body
    ):
        raise RuntimeError("A260 augmented CNF prefix gate failed")

    unit_count = TAP_COUNT * WORD_BITS

    def probe(dimension: int) -> tuple[int, list[int], dict[str, Any]]:
        assertions = mapping_assertions(taps, dimension)
        probe_formula = augmented_formula.replace(
            "(check-sat)", assertions + "\n(check-sat)", 1
        )
        output = directory / f"a260_operation_probe_{dimension}.cnf"
        exported = prepared["template"]._export(
            formula=probe_formula,
            output=output,
            arguments=config["arguments"],
            bitwuzla=config["Bitwuzla_path"],
        )
        raw = output.read_bytes()
        variable_count, clause_count, lines = _decode_header(raw)
        exact = (
            variable_count == augmented_variables
            and clause_count == augmented_clauses + unit_count
            and lines[1:-unit_count] == augmented_body
            and all(len(line.split()) == 2 and line.split()[1] == b"0" for line in lines[-unit_count:])
        )
        units = [int(line.split()[0]) for line in lines[-unit_count:]] if exact else []
        output.unlink(missing_ok=True)
        if not exact:
            raise RuntimeError(f"A260 operation mapping probe {dimension} is not an exact unit delta")
        return dimension, units, {
            "dimension": dimension,
            "status": exported["status"],
            "probe_cnf_sha256": _sha256(raw),
            "unit_int32le_sha256": _sha256(np.asarray(units, dtype="<i4").tobytes()),
            "exact_unit_delta": True,
        }

    with ThreadPoolExecutor(max_workers=4) as executor:
        rows = list(executor.map(probe, MAPPING_DIMENSIONS))
    mapping = decode_vectorized_mapping(
        {dimension: units for dimension, units, _ in rows}
    )
    mapping_sha256 = _sha256(np.asarray(mapping, dtype="<i4").tobytes())
    if mapping_sha256 != expected["signed_one_literal_matrix_sha256"]:
        raise RuntimeError("A260 operation mapping identity differs")
    operation_groups = operation_anchor_groups(mapping, taps)
    public_groups = a259._anchor_groups(
        prepared["key_mapping"], prepared["output_mapping"]
    )
    groups = {**public_groups, **operation_groups}
    if (
        len(public_groups) != expected["public_anchor_group_count"]
        or len(operation_groups) != expected["operation_anchor_group_count"]
        or len(groups) != expected["total_anchor_group_count"]
        or _canonical_sha256(groups) != expected["anchor_groups_sha256"]
    ):
        raise RuntimeError("A260 semantic anchor groups differ")
    topology = CNFOperationTopology.from_dimacs(
        augmented_raw,
        anchor_groups=groups,
        maximum_distance=int(expected["maximum_graph_distance"]),
    )
    manifest = operation_topology_manifest(topology)
    distance_ledger_sha256 = _canonical_sha256(manifest["anchor_distance_sha256"])
    if (
        manifest["variable_count"] != expected["augmented_variable_count"]
        or manifest["clause_count"] != expected["augmented_clause_count"]
        or manifest["literal_occurrences"] != expected["augmented_literal_occurrences"]
        or manifest["structural_coordinate_count_per_variable"]
        != expected["structural_coordinate_count_per_variable"]
        or manifest["semantic_readout_feature_count_per_variable"]
        != expected["semantic_readout_feature_count_per_variable"]
        or distance_ledger_sha256 != expected["anchor_distance_ledger_sha256"]
        or manifest["finite"] is not True
    ):
        raise RuntimeError("A260 operation topology manifest differs")
    mapping_ledger = [row for _, _, row in rows]
    return topology, manifest, {
        "base_export": base_export,
        "mapping_export_count": len(rows),
        "mapping_exports": mapping_ledger,
        "mapping_exports_sha256": _canonical_sha256(mapping_ledger),
        "signed_one_literal_matrix_sha256": mapping_sha256,
        "anchor_groups_sha256": _canonical_sha256(groups),
        "anchor_distance_ledger_sha256": distance_ledger_sha256,
        "original_clause_prefix_exact": True,
        "target_output_bit_values_used": False,
    }


def _load_tables(
    protocol: Mapping[str, Any],
    a251: Any,
    topology: CNFOperationTopology,
) -> tuple[list[Any], dict[str, Any]]:
    a251_protocol, _ = a251._load_protocol()
    labels = list(a251_protocol["input"]["labels"])
    tables = []
    accepted = 0
    rejected = 0
    exact_measurements = []
    semantic_tables = []
    token_counts = []
    for label in labels:
        path = a251._measurement_path(label, "numeric")
        if not path.is_file():
            raise FileNotFoundError(f"A260 requires completed A251 shard: {path.name}")
        measurement = a251._read_measurement(path)
        accepted += int(measurement["run"]["summary"]["learned_clause_accepted_total"])
        rejected += int(
            measurement["run"]["summary"]["learned_clause_rejected_large_total"]
        )
        table = build_topology_clause_table(measurement, topology)
        tables.append(table)
        exact_measurements.append(
            {
                "label": label,
                "compressed_sha256": _file_sha256(path),
                "raw_measurement_sha256": _canonical_sha256(measurement),
            }
        )
        semantic_tables.append(
            {"label": label, "table_sha256": a251._table_sha256(table)}
        )
        token_counts.append(sum(len(tokens) for tokens in table.candidate_tokens))
        print(
            "A260_TABLE "
            + json.dumps(
                {
                    "label": label,
                    "tokens": token_counts[-1],
                    "table_sha256": semantic_tables[-1]["table_sha256"],
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
        raise RuntimeError("A260 retained A251 clause corpus identity differs")
    return tables, {
        "accepted_learned_clauses": accepted,
        "rejected_over_64_literal_clauses": rejected,
        "semantic_token_counts_per_key": token_counts,
        "exact_measurement_ledger": exact_measurements,
        "exact_measurement_ledger_sha256": _canonical_sha256(exact_measurements),
        "semantic_table_ledger": semantic_tables,
        "semantic_table_ledger_sha256": _canonical_sha256(semantic_tables),
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
        "A260:exact_operation_topology_transfer_retained"
        if retained
        else "A260:exact_operation_topology_boundary"
    )
    writer = CausalWriter(api_id="a260")
    writer._rules = []
    writer.add_rule(
        name="named_operation_taps_preserve_original_CNF",
        description="Declared tap equalities retain the complete original CNF as a byte-exact clause prefix while exposing every named R20 operation bit as a target-blind semantic anchor.",
        pattern=["A259_topology_boundary", "exact_v0_through_v639_taps"],
        conclusion="round_lane_bit_operation_coordinates",
        confidence_modifier=1.0,
    )
    writer.add_rule(
        name="nested_unseen_prefix_operation_validation",
        description="Every outer prefix is scored by an operation-topology PoE selected and fit without that prefix group.",
        pattern=["inner_operation_operator_selection", "unseen_outer_prefix"],
        conclusion="prefix_blind_operation_transfer_evidence",
        confidence_modifier=1.0,
    )
    writer.add_triplet(
        trigger="A259:public_CNF_clause_topology_boundary",
        mechanism="add_640_exact_target_blind_named_operation_taps",
        outcome="A260:141_public_and_operation_anchor_groups",
        confidence=1.0,
        source=payload["operation_tap_reader_sha256"],
        quantification="640 words; 20,480 operation bits; 16 exact vectorized unit-delta mappings",
        evidence=json.dumps(payload["operation_mapping_manifest"], sort_keys=True),
        domain="exact ChaCha20-R20 operation semantics",
        quality_score=1.0,
    )
    writer.add_triplet(
        trigger="A260:141_public_and_operation_anchor_groups",
        mechanism="map_A251_clauses_into_23_operation_semantic_readouts",
        outcome="A260:candidate_blind_operation_clause_corpus",
        confidence=1.0,
        source=payload["semantic_clause_corpus"]["semantic_table_ledger_sha256"],
        quantification="same 35,081 accepted clauses; zero new solver measurements",
        evidence=json.dumps(payload["feature_contract"], sort_keys=True),
        domain="typed operation learned-clause representation",
        quality_score=1.0,
    )
    writer.add_triplet(
        trigger="A260:candidate_blind_operation_clause_corpus",
        mechanism="nested_Bernoulli_operation_product_of_experts",
        outcome="A260:five_unseen_prefix_operation_models",
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
        domain="nested known-key operation reader",
        quality_score=1.0,
    )
    writer.add_triplet(
        trigger="A260:five_unseen_prefix_operation_models",
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
        trigger="A259:public_CNF_clause_topology_boundary",
        mechanism="materialized_exact_operation_topology_chain",
        outcome=outcome,
        confidence=1.0,
        source="materialized:named_operation_taps_preserve_original_CNF+nested_unseen_prefix_operation_validation",
        quantification="four-edge semantic closure retained in-file",
        evidence="Materialized after exact operation mapping, complete clause projection, nested outer evaluation, and exact XOR controls.",
        domain="AI-native retained inference",
        quality_score=1.0,
        is_inferred=True,
    )
    writer.add_cluster(
        name="A260 exact operation coordinate chain",
        entities=[
            "A259:public_CNF_clause_topology_boundary",
            "add_640_exact_target_blind_named_operation_taps",
            "A260:141_public_and_operation_anchor_groups",
            "map_A251_clauses_into_23_operation_semantic_readouts",
            "A260:candidate_blind_operation_clause_corpus",
        ],
    )
    writer.add_cluster(
        name="A260 nested unseen-prefix chain",
        entities=[
            "nested_Bernoulli_operation_product_of_experts",
            "A260:five_unseen_prefix_operation_models",
            "unseen_prefix_ranks_plus_all_256_XOR_controls",
            outcome,
        ],
    )
    writer.add_gap(
        subject=outcome,
        predicate="next_required_intervention",
        expected_object_type=(
            "prospective_entirely_new_known_key_operation_validation"
            if retained
            else "typed_cross_round_operation_flow_and_clause_path_residual_reader"
        ),
        confidence=1.0,
        suggested_queries=(
            [
                "Freeze the operation operator before generating new prefix groups.",
                "If retained prospectively, use it to order a sealed unknown target.",
            ]
            if retained
            else [
                "Replace nearest-node semantics by directed producer-to-consumer operation-flow edges.",
                "Do learned-clause paths transfer after subtracting the operation-class baseline?",
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
        or reader.api_id != "a260"
        or len(explicit) != 4
        or len(rows) != 5
        or len(inferred) != 1
        or len(reader._rules) != 2
        or len(reader._clusters) != 2
        or len(reader._gaps) != 1
    ):
        raise RuntimeError("A260 authentic Causal Reader reopen gate failed")
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
        "# A260 — ChaCha20-R20 exact-operation learned-clause reader",
        "",
        "All 640 named split-18 operation words are exposed through target-blind taps while the original 252,375-clause CNF remains the byte-exact prefix. The same A251 clause corpus is projected without a new solver measurement.",
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
        f"- New solver measurements: **{payload['new_solver_measurements']}**",
        "",
        "## Outer folds",
        "",
        "| Prefix | Min support | Beta | Cap | Retained tokens | Mean log2 rank |",
        "|---:|---:|---:|---:|---:|---:|",
    ]
    for fold in evaluation["outer_folds"]:
        lines.append(
            "| {outer_prefix_index} | {selected_minimum_positive_support} | "
            "{selected_beta_smoothing} | {selected_token_log_odds_cap} | "
            "{retained} | {test_mean_log2_rank:.6f} |".format(
                retained=len(fold["model"]["token_weights"]), **fold
            )
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
    protocol, a259, a251, a242 = _load_protocol()
    started = time.perf_counter()
    with tempfile.TemporaryDirectory(prefix="a260_clause_operation_") as temporary:
        topology, topology_manifest, mapping_manifest = _prepare_operation_topology(
            protocol, a259, a242, Path(temporary)
        )
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
            "FULLROUND_R20_EXACT_OPERATION_CLAUSE_TOPOLOGY_CROSSVALIDATED_SIGNAL"
            if retained
            else "FULLROUND_R20_EXACT_OPERATION_CLAUSE_TOPOLOGY_BOUNDARY"
        ),
        "protocol_sha256": PROTOCOL_SHA256,
        "protocol_state": protocol["protocol_state"],
        "causal_derivation": protocol["causal_derivation"],
        "operation_mapping_manifest": mapping_manifest,
        "operation_topology_manifest": topology_manifest,
        "operation_tap_reader_sha256": protocol["anchors"]["operation_tap_reader_sha256"],
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

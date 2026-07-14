#!/usr/bin/env python3
"""A271: decompose the frozen R20 reader into signed semantic channels."""

from __future__ import annotations

import argparse
import hashlib
import importlib
import importlib.util
import inspect
import json
import os
import sys
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

import numpy as np

ROOT = Path(__file__).parents[2]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from arx_carry_leak.score_hypercube import local_pairwise_residual  # noqa: E402
from arx_carry_leak.trajectory_contribution import (  # noqa: E402
    familywise_best_gain,
    grouped_scores,
    score_view_statistics,
    signed_semantic_groups,
    standardized_contributions,
)

ATTEMPT_ID = "A271"
SCHEMA = "chacha20-round20-signed-channel-ablation-result-v1"
DEFAULT_PROTOCOL = ROOT / "research/configs/chacha20_round20_signed_channel_ablation_v1.json"
DEFAULT_RESULT = ROOT / "research/results/v1/chacha20_round20_signed_channel_ablation_v1.json"
DEFAULT_CAUSAL = DEFAULT_RESULT.with_suffix(".causal")
DEFAULT_REPORT = ROOT / "research/reports/CAUSAL_CHACHA20_ROUND20_SIGNED_CHANNEL_ABLATION_V1.md"
DEFAULT_DOTCAUSAL_SRC = Path(
    "/Users/bhkmie/Documents/Forschung/O1/vendor/fabel/dotcausal_package/src"
)


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
    ).encode("ascii")


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
        ).encode("ascii")
        + b"\n",
    )


def _anchor_path(value: str) -> Path:
    path = Path(value)
    return path if path.is_absolute() else ROOT / path


def _import_path(path: Path, name: str) -> Any:
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot import A271 dependency {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _load_protocol(
    protocol_path: Path, expected_protocol_sha256: str
) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any], Any, dict[str, Any], dict[str, Any]]:
    if _file_sha256(protocol_path) != expected_protocol_sha256:
        raise RuntimeError("A271 frozen protocol hash differs")
    protocol = json.loads(protocol_path.read_bytes())
    family = protocol.get("view_family", {})
    boundary = protocol.get("information_boundary", {})
    if (
        protocol.get("schema") != "chacha20-round20-signed-channel-ablation-protocol-v1"
        or protocol.get("attempt_id") != ATTEMPT_ID
        or protocol.get("protocol_state")
        != "frozen_after_A270_boundary_before_any_signed_channel_contribution_score_rank_or_XOR_control"
        or protocol.get("frozen_model", {}).get("feature_count") != 532
        or protocol.get("frozen_model", {}).get("nonzero_coefficient_count") != 476
        or family.get("group_count") != 32
        or family.get("view_count") != 64
        or family.get("modes")
        != ["direct_additive_contribution", "normalized_8cube_graph_laplacian"]
        or family.get("operator_family_selected_from_A268_or_A270_group_outcomes") is not False
        or family.get("all_views_retained_for_familywise_control") is not True
        or protocol.get("controls", {}).get("shared_XOR_offsets") != 256
        or boundary.get("any_A268_grouped_contribution_computed_at_freeze") is not False
        or boundary.get("any_signed_channel_rank_or_XOR_control_known_at_freeze") is not False
        or boundary.get("model_refit_or_coefficient_update_permitted") is not False
    ):
        raise RuntimeError("A271 frozen protocol semantic gate failed")
    anchors = protocol["anchors"]
    for path_key, path_value in anchors.items():
        if not path_key.endswith("_path"):
            continue
        hash_key = f"{path_key.removesuffix('_path')}_sha256"
        if _file_sha256(_anchor_path(path_value)) != anchors.get(hash_key):
            raise RuntimeError(f"A271 anchored dependency hash differs: {path_key}")
    a268_result = json.loads(_anchor_path(anchors["A268_result_path"]).read_bytes())
    a270_result = json.loads(_anchor_path(anchors["A270_result_path"]).read_bytes())
    if (
        a268_result.get("retention_gate", {}).get("passed") is not False
        or a270_result.get("retention_gate", {}).get("passed") is not False
        or a270_result.get("causal", {})
        .get("personal_semantic_readback", {})
        .get("next_gap", {})
        .get("expected_object_type")
        != "channel_signed_pairwise_ablation_without_model_refit"
    ):
        raise RuntimeError("A271 predecessor result gate failed")
    a268 = _import_path(_anchor_path(anchors["A268_runner_path"]), "a271_a268")
    a268_protocol, a268_preflight, _, _, _ = a268._load_protocol()
    model = a268._frozen_model(a268_protocol, a268_preflight)
    groups = signed_semantic_groups(model.feature_names, model.coefficients)
    frozen_rows = protocol["frozen_model"]["signed_semantic_groups"]
    if (
        frozen_rows
        != [{"name": name, "feature_indices": list(indices)} for name, indices in groups.items()]
        or _canonical_sha256(frozen_rows)
        != protocol["frozen_model"]["group_ledger_sha256"]
        or _canonical_sha256(model.as_dict()) != protocol["frozen_model"]["model_sha256"]
    ):
        raise RuntimeError("A271 frozen model/group ledger differs")
    return protocol, a268_result, a270_result, a268, a268_protocol, a268_preflight


def analyze(protocol_path: Path, expected_protocol_sha256: str) -> dict[str, Any]:
    protocol, _, _, _, _, _ = _load_protocol(protocol_path, expected_protocol_sha256)
    return {
        "attempt_id": ATTEMPT_ID,
        "protocol_sha256": expected_protocol_sha256,
        "signed_semantic_groups": protocol["view_family"]["group_count"],
        "frozen_views": protocol["view_family"]["view_count"],
        "grouped_contributions_computed": False,
        "model_refit_permitted": False,
    }


def _load_tables(
    a268: Any,
    a268_preflight: Mapping[str, Any],
    a268_result: Mapping[str, Any],
) -> tuple[list[Any], list[dict[str, Any]]]:
    result_rows = {
        row["label"]: row for row in a268_result["evaluation"]["prospective_rows"]
    }
    tables = []
    ledger = []
    for design in a268_preflight["prospective_design"]["rows"]:
        label = design["label"]
        path = a268._measurement_path(label)
        measurement = a268._read_measurement(path)
        table = a268.build_trajectory_shape_table(measurement)
        stored = result_rows[label]
        if table.true_prefix != stored["true_prefix"]:
            raise RuntimeError("A271 reconstructed true-prefix identity differs")
        tables.append(table)
        ledger.append(
            {
                "label": label,
                "compressed_path": str(path.relative_to(ROOT)),
                "compressed_sha256": _file_sha256(path),
                "table_sha256": a268._table_sha256(table),
            }
        )
    if len(tables) != 20 or set(result_rows) != {table.label for table in tables}:
        raise RuntimeError("A271 reconstructed table cover differs")
    return tables, ledger


def _evaluate(
    protocol: Mapping[str, Any],
    a268_result: Mapping[str, Any],
    a270_result: Mapping[str, Any],
    a268: Any,
    a268_protocol: Mapping[str, Any],
    a268_preflight: Mapping[str, Any],
) -> dict[str, Any]:
    model = a268._frozen_model(a268_protocol, a268_preflight)
    tables, ledger = _load_tables(a268, a268_preflight, a268_result)
    result_rows = {
        row["label"]: row for row in a268_result["evaluation"]["prospective_rows"]
    }
    groups = {
        row["name"]: tuple(row["feature_indices"])
        for row in protocol["frozen_model"]["signed_semantic_groups"]
    }
    true_prefixes = [table.true_prefix for table in tables]
    prefix_indices = [int(result_rows[table.label]["prefix_index"]) for table in tables]
    raw_fields = []
    grouped_fields = {name: [] for name in groups}
    reconstruction_max_abs_error = 0.0
    for table in tables:
        raw = model.logits(table.matrix)
        stored = np.asarray(result_rows[table.label]["scores"], dtype=np.float64)
        if not np.array_equal(raw, stored):
            raise RuntimeError("A271 exact A268 raw-logit reconstruction differs")
        contributions = standardized_contributions(
            table.matrix,
            means=model.means,
            scales=model.scales,
            coefficients=model.coefficients,
        )
        reconstructed = model.intercept + contributions.sum(axis=1)
        reconstruction_max_abs_error = max(
            reconstruction_max_abs_error,
            float(np.max(np.abs(reconstructed - raw))),
        )
        if not np.allclose(reconstructed, raw, rtol=1e-12, atol=1e-12):
            raise RuntimeError("A271 additive logit reconstruction differs")
        for name, scores in grouped_scores(contributions, groups).items():
            grouped_fields[name].append(scores)
        raw_fields.append(raw)

    raw_direct = score_view_statistics(
        raw_fields, true_prefixes=true_prefixes, prefix_indices=prefix_indices
    )
    raw_local = score_view_statistics(
        [local_pairwise_residual(field) for field in raw_fields],
        true_prefixes=true_prefixes,
        prefix_indices=prefix_indices,
    )
    if (
        abs(raw_direct["mean_log2_rank"] - a268_result["evaluation"]["mean_log2_rank"])
        > 1e-15
        or raw_direct["exact_shared_xor_p"]
        != a268_result["evaluation"]["exact_shared_xor_p"]
        or abs(
            raw_local["mean_log2_rank_bit_gain"]
            - a270_result["evaluation"]["local_mean_log2_rank_bit_gain"]
        )
        > 2e-15
        or raw_local["exact_shared_xor_p"]
        != a270_result["evaluation"]["exact_shared_xor_rank_p"]
    ):
        raise RuntimeError("A271 predecessor reconstruction gate failed")

    evaluations: dict[str, dict[str, Any]] = {}
    view_catalog = []
    for group_name in sorted(grouped_fields):
        fields = grouped_fields[group_name]
        direct_name = f"{group_name}::direct_additive_contribution"
        local_name = f"{group_name}::normalized_8cube_graph_laplacian"
        evaluations[direct_name] = score_view_statistics(
            fields, true_prefixes=true_prefixes, prefix_indices=prefix_indices
        )
        evaluations[local_name] = score_view_statistics(
            [local_pairwise_residual(field) for field in fields],
            true_prefixes=true_prefixes,
            prefix_indices=prefix_indices,
        )
        for name, mode in (
            (direct_name, "direct_additive_contribution"),
            (local_name, "normalized_8cube_graph_laplacian"),
        ):
            view_catalog.append(
                {
                    "name": name,
                    "group": group_name,
                    "mode": mode,
                    "feature_count": len(groups[group_name]),
                }
            )
    familywise = familywise_best_gain(evaluations)
    best_name = familywise["best_observed_view"]
    best = evaluations[best_name]
    return {
        "reconstruction": {
            "measurement_ledger": ledger,
            "measurement_ledger_sha256": _canonical_sha256(ledger),
            "table_count": len(tables),
            "candidate_score_count": len(tables) * 256,
            "maximum_abs_additive_logit_reconstruction_error": reconstruction_max_abs_error,
            "raw_A268_direct_reproduced": True,
            "raw_A270_local_reproduced": True,
        },
        "view_catalog": view_catalog,
        "view_catalog_sha256": _canonical_sha256(view_catalog),
        "raw_combined_reader": {"direct": raw_direct, "local": raw_local},
        "signed_channel_views": evaluations,
        "familywise": familywise,
        "best_view": {"name": best_name, **best},
    }


def _load_dotcausal(dotcausal_src: Path) -> tuple[Any, Any, dict[str, Any]]:
    try:
        io_module = importlib.import_module("dotcausal.io")
    except ModuleNotFoundError:
        if not dotcausal_src.is_dir():
            raise FileNotFoundError("dotcausal source is unavailable") from None
        sys.path.insert(0, str(dotcausal_src))
        io_module = importlib.import_module("dotcausal.io")
    source = Path(inspect.getsourcefile(io_module.CausalReader) or "")
    return io_module.CausalWriter, io_module.CausalReader, {
        "module": "dotcausal.io",
        "io_path": str(source),
        "io_sha256": _file_sha256(source),
    }


def _build_causal(
    path: Path, payload: Mapping[str, Any], dotcausal_src: Path
) -> dict[str, Any]:
    CausalWriter, CausalReader, source = _load_dotcausal(dotcausal_src)
    retained = bool(payload["retention_gate"]["passed"])
    terminal = (
        "A271:signed_channel_transfer_carrier"
        if retained
        else "A271:signed_channel_ablation_boundary"
    )
    writer = CausalWriter(api_id="a271")
    writer._rules = []
    writer.add_rule(
        name="frozen_additive_channel_decomposition",
        description="The frozen 532-coordinate A267 reader is split by semantic source and coefficient sign without refit, rescaling, or target-dependent selection.",
        pattern=["A270_local_boundary", "32_signed_semantic_groups"],
        conclusion="64_fixed_channel_views",
        confidence_modifier=1.0,
    )
    writer.add_rule(
        name="exact_familywise_shared_xor_control",
        description="One max statistic across all 64 frozen views is recomputed for every shared XOR label offset.",
        pattern=["64_fixed_channel_views", "256_shared_XOR_offsets"],
        conclusion="multiplicity_controlled_channel_evidence",
        confidence_modifier=1.0,
    )
    writer.add_triplet(
        trigger="A270:local_pairwise_intervention_boundary",
        mechanism="partition_frozen_A267_coefficients_by_semantic_source_and_sign",
        outcome="A271:32_signed_semantic_contribution_groups",
        confidence=1.0,
        source=payload["group_ledger_sha256"],
        quantification="476 nonzero coefficients partitioned exactly once into 32 groups",
        evidence=payload["evaluation"]["view_catalog_sha256"],
        domain="full-round R20 frozen-reader mechanism",
        quality_score=1.0,
    )
    writer.add_triplet(
        trigger="A271:32_signed_semantic_contribution_groups",
        mechanism="direct_and_local_reads_with_exact_64_view_max_statistic",
        outcome=terminal,
        confidence=1.0,
        source=payload["analysis_sha256"],
        quantification=json.dumps(payload["retention_gate"], sort_keys=True),
        evidence=json.dumps(payload["headline"], sort_keys=True),
        domain="exact familywise channel ablation",
        quality_score=1.0,
    )
    writer.add_triplet(
        trigger="A270:local_pairwise_intervention_boundary",
        mechanism="materialized_signed_channel_decomposition_and_familywise_control",
        outcome=terminal,
        confidence=1.0,
        source="materialized:A267_model_plus_A268_tables_plus_signed_groups_plus_XOR_max_control",
        quantification="complete two-edge closure retained in-file",
        evidence="Materialized after all 64 views and all 256 shared-XOR max controls.",
        domain="AI-native retained inference",
        quality_score=1.0,
        is_inferred=True,
    )
    writer.add_cluster(
        name="A271 signed-channel ablation",
        entities=[
            "A270:local_pairwise_intervention_boundary",
            "partition_frozen_A267_coefficients_by_semantic_source_and_sign",
            "A271:32_signed_semantic_contribution_groups",
            "direct_and_local_reads_with_exact_64_view_max_statistic",
            terminal,
        ],
    )
    writer.add_gap(
        subject=terminal,
        predicate="next_required_object",
        expected_object_type=(
            "prospective_disjoint_signed_channel_validation_without_refit"
            if retained
            else "ordered_clause_event_timing_reader_without_model_refit"
        ),
        confidence=1.0,
        suggested_queries=(
            [
                "Freeze the winning signed channel before generating another disjoint key panel.",
                "Does the isolated channel retain familywise-controlled rank gain prospectively?",
            ]
            if retained
            else [
                "Does ordered clause-event timing retain information lost by four-horizon aggregation?",
                "Which event transitions precede the candidate-conditioned solver phase change?",
            ]
        ),
    )
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.tmp")
    temporary.unlink(missing_ok=True)
    stats = writer.save(str(temporary))
    os.replace(temporary, path)
    reader = CausalReader(str(path), verify_integrity=True)
    explicit = reader.get_all_triplets(include_inferred=False)
    all_rows = reader.get_all_triplets(include_inferred=True)
    inferred = [row for row in reader._triplets if row.get("is_inferred", False)]
    if (
        reader.version != 1
        or reader.api_id != "a271"
        or len(explicit) != 2
        or len(all_rows) != 3
        or len(inferred) != 1
        or len(reader._rules) != 2
        or len(reader._clusters) != 1
        or len(reader._gaps) != 1
        or all_rows[-1]["outcome"] != terminal
    ):
        raise RuntimeError("A271 authentic Causal Reader reopen gate failed")
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
            "terminal_chain": all_rows[-1],
            "next_gap": reader._gaps[0],
        },
    }


def _report(payload: Mapping[str, Any]) -> str:
    headline = payload["headline"]
    causal = payload["causal"]
    return "\n".join(
        [
            "# A271 — ChaCha20-R20 signed-channel ablation",
            "",
            "The frozen A267 reader is decomposed into every nonempty semantic-source × coefficient-sign group. Both direct additive and normalized local reads are evaluated, and one exact shared-XOR max statistic controls the complete 64-view family.",
            "",
            "## Result",
            "",
            f"- Evidence stage: **{payload['evidence_stage']}**",
            f"- Best frozen view: **{headline['best_view']}**",
            f"- Best-view bit gain: **{headline['best_view_bit_gain']:+.12f}**",
            f"- Exact familywise XOR p: **{headline['exact_familywise_shared_xor_p']:.12f}**",
            f"- Best-view positive prefix groups: **{headline['best_view_positive_prefix_groups']}/5**",
            f"- Frozen gate passed: **{payload['retention_gate']['passed']}**",
            "",
            "## Authentic AI-native Causal readback",
            "",
            f"- Reader integrity: **{causal['integrity_verified_by_authoritative_reader']}**",
            f"- Explicit / materialized: **{causal['explicit_triplets']} / {causal['materialized_inferred_triplets']}**",
            f"- Next gap: **{causal['personal_semantic_readback']['next_gap']['expected_object_type']}**",
            "",
        ]
    )


def execute(
    *,
    protocol_path: Path,
    expected_protocol_sha256: str,
    output: Path,
    causal_output: Path,
    report_output: Path,
    dotcausal_src: Path,
) -> dict[str, Any]:
    protocol, a268_result, a270_result, a268, a268_protocol, a268_preflight = _load_protocol(
        protocol_path, expected_protocol_sha256
    )
    evaluation = _evaluate(
        protocol, a268_result, a270_result, a268, a268_protocol, a268_preflight
    )
    familywise = evaluation["familywise"]
    best = evaluation["best_view"]
    gate = protocol["retention_gate"]
    retained = (
        familywise["exact_familywise_shared_xor_p"]
        <= gate["maximum_exact_familywise_shared_xor_p"]
        and best["mean_log2_rank_bit_gain"]
        > a268_result["evaluation"]["mean_log2_rank_bit_gain"]
        and best["positive_prefix_groups"]
        >= gate["minimum_positive_prefix_groups_for_best_view"]
    )
    headline = {
        "best_view": best["name"],
        "best_view_bit_gain": best["mean_log2_rank_bit_gain"],
        "best_view_exact_unadjusted_shared_xor_p": best["exact_shared_xor_p"],
        "exact_familywise_shared_xor_p": familywise[
            "exact_familywise_shared_xor_p"
        ],
        "best_view_positive_prefix_groups": best["positive_prefix_groups"],
        "raw_A268_bit_gain": a268_result["evaluation"]["mean_log2_rank_bit_gain"],
        "view_count": familywise["view_count"],
    }
    payload: dict[str, Any] = {
        "schema": SCHEMA,
        "attempt_id": ATTEMPT_ID,
        "evidence_stage": (
            "FULLROUND_R20_SIGNED_CHANNEL_TRANSFER_CARRIER"
            if retained
            else "FULLROUND_R20_SIGNED_CHANNEL_ABLATION_BOUNDARY"
        ),
        "protocol_sha256": expected_protocol_sha256,
        "runner_sha256": _file_sha256(Path(__file__)),
        "group_ledger_sha256": protocol["frozen_model"]["group_ledger_sha256"],
        "A268_result_sha256": protocol["anchors"]["A268_result_sha256"],
        "A270_result_sha256": protocol["anchors"]["A270_result_sha256"],
        "evaluation": evaluation,
        "analysis_sha256": _canonical_sha256(evaluation),
        "headline": headline,
        "retention_gate": {**gate, "passed": retained},
        "information_boundary": protocol["information_boundary"],
    }
    payload["causal"] = _build_causal(causal_output, payload, dotcausal_src)
    _atomic_json(output, payload)
    _atomic_bytes(report_output, _report(payload).encode("utf-8"))
    return payload


def main(argv: Sequence[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--protocol", type=Path, default=DEFAULT_PROTOCOL)
    parser.add_argument("--expected-protocol-sha256", required=True)
    parser.add_argument("--analyze-only", action="store_true")
    parser.add_argument("--output", type=Path, default=DEFAULT_RESULT)
    parser.add_argument("--causal-output", type=Path, default=DEFAULT_CAUSAL)
    parser.add_argument("--report-output", type=Path, default=DEFAULT_REPORT)
    parser.add_argument("--dotcausal-src", type=Path, default=DEFAULT_DOTCAUSAL_SRC)
    args = parser.parse_args(argv)
    if args.analyze_only:
        print(
            json.dumps(
                analyze(args.protocol, args.expected_protocol_sha256),
                indent=2,
                sort_keys=True,
            )
        )
        return
    payload = execute(
        protocol_path=args.protocol,
        expected_protocol_sha256=args.expected_protocol_sha256,
        output=args.output,
        causal_output=args.causal_output,
        report_output=args.report_output,
        dotcausal_src=args.dotcausal_src,
    )
    print(
        json.dumps(
            {
                "evidence_stage": payload["evidence_stage"],
                **payload["headline"],
                "result": str(args.output),
                "result_sha256": _file_sha256(args.output),
                "causal": str(args.causal_output),
                "causal_sha256": _file_sha256(args.causal_output),
            },
            indent=2,
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    main()

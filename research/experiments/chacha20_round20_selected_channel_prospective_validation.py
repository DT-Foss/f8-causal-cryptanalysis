#!/usr/bin/env python3
"""Execute A272's frozen single-channel validation on a second disjoint panel."""

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
from collections.abc import Mapping, Sequence
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Any

import numpy as np
import zstandard

ROOT = Path(__file__).parents[2]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from arx_carry_leak.score_hypercube import descending_midrank  # noqa: E402
from arx_carry_leak.trajectory_contribution import (  # noqa: E402
    score_view_statistics,
    standardized_contributions,
)

ATTEMPT_ID = "A272"
RESULT_SCHEMA = "chacha20-round20-selected-channel-prospective-validation-result-v1"
SHARD_SCHEMA = "chacha20-round20-selected-channel-prospective-measurement-v1"
DEFAULT_PROTOCOL = (
    ROOT
    / "research/configs/chacha20_round20_selected_channel_prospective_validation_v1.json"
)
DEFAULT_RESULT = (
    ROOT
    / "research/results/v1/chacha20_round20_selected_channel_prospective_validation_v1.json"
)
DEFAULT_CAUSAL = DEFAULT_RESULT.with_suffix(".causal")
DEFAULT_REPORT = (
    ROOT
    / "research/reports/CAUSAL_CHACHA20_ROUND20_SELECTED_CHANNEL_PROSPECTIVE_VALIDATION_V1.md"
)
SHARD_ROOT = (
    ROOT
    / "research/results/v1/chacha20_round20_selected_channel_prospective_validation_v1"
)
DEFAULT_DOTCAUSAL_SRC = Path(
    "/Users/bhkmie/Documents/Forschung/O1/vendor/fabel/dotcausal_package/src"
)
ZSTD_LEVEL = 10


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
        raise RuntimeError(f"cannot import A272 dependency {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _load_protocol(
    protocol_path: Path, expected_protocol_sha256: str
) -> tuple[dict[str, Any], Any, dict[str, Any], dict[str, Any], Any, tuple[int, ...]]:
    if _file_sha256(protocol_path) != expected_protocol_sha256:
        raise RuntimeError("A272 frozen protocol hash differs")
    protocol = json.loads(protocol_path.read_bytes())
    selected = protocol.get("selected_hypothesis", {})
    measurement = protocol.get("measurement", {})
    boundary = protocol.get("information_boundary", {})
    if (
        protocol.get("schema")
        != "chacha20-round20-selected-channel-prospective-validation-protocol-v1"
        or protocol.get("attempt_id") != ATTEMPT_ID
        or protocol.get("protocol_state")
        != "frozen_after_A271_hypothesis_selection_and_second_disjoint_key_design_before_any_A272_target_CNF_solver_measurement_score_or_rank"
        or selected.get("view_name")
        != "ratio_learned_clause_accepted_stage_versus_conflicts::coefficient_positive::direct_additive_contribution"
        or selected.get("mode") != "direct_additive_contribution"
        or selected.get("feature_indices") != [502, 504, 505, 508, 509, 510, 511, 514]
        or selected.get("model_refit_or_coefficient_update_permitted") is not False
        or measurement.get("conflict_horizons") != [1, 2, 4, 8]
        or measurement.get("maximum_concurrent_key_processes") != 2
        or measurement.get("early_stop_permitted") is not False
        or measurement.get("bounded_variable_addition_enabled") is not False
        or protocol.get("controls", {}).get("view_count") != 1
        or protocol.get("controls", {}).get("shared_XOR_offsets") != 256
        or boundary.get("any_A272_target_block_or_CNF_generated_before_freeze") is not False
        or boundary.get("any_A272_solver_measurement_started_before_freeze") is not False
        or boundary.get("any_A272_selected_channel_score_rank_or_XOR_control_known_before_freeze")
        is not False
        or boundary.get("model_refit_or_coefficient_update_permitted") is not False
    ):
        raise RuntimeError("A272 frozen protocol semantic gate failed")
    anchors = protocol["anchors"]
    for path_key, path_value in anchors.items():
        if not path_key.endswith("_path"):
            continue
        hash_key = f"{path_key.removesuffix('_path')}_sha256"
        if _file_sha256(_anchor_path(path_value)) != anchors.get(hash_key):
            raise RuntimeError(f"A272 anchored dependency hash differs: {path_key}")
    a271 = json.loads(_anchor_path(anchors["A271_result_path"]).read_bytes())
    if (
        a271.get("headline", {}).get("best_view") != selected["view_name"]
        or a271.get("headline", {}).get("best_view_exact_unadjusted_shared_xor_p")
        != 0.03125
    ):
        raise RuntimeError("A272 selected A271 hypothesis identity differs")
    a268 = _import_path(_anchor_path(anchors["A268_runner_path"]), "a272_a268")
    a268_protocol, a268_preflight, a251, a251_protocol, a242 = a268._load_protocol()
    model = a268._frozen_model(a268_protocol, a268_preflight)
    if _canonical_sha256(model.as_dict()) != selected["model_sha256"]:
        raise RuntimeError("A272 frozen model differs")
    indices = tuple(int(value) for value in selected["feature_indices"])
    if [model.feature_names[index] for index in indices] != selected["feature_names"]:
        raise RuntimeError("A272 selected feature-name identity differs")
    rows = protocol["prospective_design"]["rows"]
    if len(rows) != 20 or _canonical_sha256(rows) != protocol["prospective_design"]["rows_sha256"]:
        raise RuntimeError("A272 prospective design ledger differs")
    return protocol, a268, a251_protocol, a268_preflight, a242, indices


def analyze(protocol_path: Path, expected_protocol_sha256: str) -> dict[str, Any]:
    protocol, _, _, _, _, indices = _load_protocol(
        protocol_path, expected_protocol_sha256
    )
    return {
        "attempt_id": ATTEMPT_ID,
        "protocol_sha256": expected_protocol_sha256,
        "selected_view": protocol["selected_hypothesis"]["view_name"],
        "selected_feature_count": len(indices),
        "prospective_key_count": len(protocol["prospective_design"]["rows"]),
        "candidate_measurements": len(protocol["prospective_design"]["rows"]) * 256,
        "solver_measurement_started": False,
    }


def _measurement_path(label: str) -> Path:
    return SHARD_ROOT / f"{label}.numeric.measurement.json.zst"


def _write_measurement(path: Path, measurement: Mapping[str, Any]) -> dict[str, Any]:
    raw = _canonical_bytes(measurement)
    compressed = zstandard.ZstdCompressor(
        level=ZSTD_LEVEL,
        threads=0,
        write_checksum=True,
        write_content_size=True,
        write_dict_id=False,
    ).compress(raw)
    _atomic_bytes(path, compressed)
    return {
        "path": str(path.relative_to(ROOT)),
        "raw_bytes": len(raw),
        "raw_sha256": _sha256(raw),
        "compressed_bytes": len(compressed),
        "compressed_sha256": _sha256(compressed),
    }


def _read_measurement(path: Path, expected_protocol_sha256: str, a268: Any) -> dict[str, Any]:
    compressed = path.read_bytes()
    raw = zstandard.ZstdDecompressor().decompress(compressed)
    value = json.loads(raw)
    if (
        value.get("schema") != SHARD_SCHEMA
        or value.get("attempt_id") != ATTEMPT_ID
        or value.get("protocol_sha256") != expected_protocol_sha256
        or value.get("complete_candidate_cover") is not True
        or _canonical_bytes(value) != raw
    ):
        raise RuntimeError(f"A272 measurement shard gate failed: {path.name}")
    a268.build_trajectory_shape_table(value)
    return value


def _execute_one(
    *,
    protocol: Mapping[str, Any],
    expected_protocol_sha256: str,
    prepared: Mapping[str, Any],
    a251: Any,
    a268: Any,
    row: Mapping[str, Any],
    order: Sequence[str],
    directory: Path,
) -> tuple[dict[str, Any], dict[str, Any]]:
    output = _measurement_path(str(row["label"]))
    if output.exists():
        measurement = _read_measurement(output, expected_protocol_sha256, a268)
        if measurement["label"] != row["label"]:
            raise RuntimeError("A272 resumable shard identity differs")
        compressed = output.read_bytes()
        raw = zstandard.ZstdDecompressor().decompress(compressed)
        return measurement, {
            "path": str(output.relative_to(ROOT)),
            "raw_bytes": len(raw),
            "raw_sha256": _sha256(raw),
            "compressed_bytes": len(compressed),
            "compressed_sha256": _sha256(compressed),
            "resumed": True,
        }
    public = prepared["public"]
    template = prepared["template"]
    challenge = public.build_known_challenge(
        prepared["public_material"], low20=int(row["low20"])
    )
    raw_cnf, _, instantiation = template.instantiate_output(
        prepared["base_raw"],
        prepared["output_mapping"],
        challenge["target_words"][0],
    )
    key_directory = directory / str(row["label"])
    key_directory.mkdir(parents=True, exist_ok=True)
    cnf = key_directory / "instance.cnf"
    _atomic_bytes(cnf, raw_cnf)
    if _file_sha256(cnf) != instantiation["sha256"]:
        raise RuntimeError("A272 instantiated CNF readback differs")
    started = time.perf_counter()
    run = prepared["clause_wrapper"].run_fresh_clause_identity(
        helper=prepared["clause_helper"],
        cnf=cnf,
        mode=f"A272_{row['label']}_numeric",
        order=order,
        key_one_literals_bit0_through_bit19=prepared["key_mapping"],
        conflict_horizons=protocol["measurement"]["conflict_horizons"],
        watchdog_seconds=float(protocol["measurement"]["watchdog_seconds_per_stage"]),
        external_timeout_seconds=900.0,
    )
    measurement = {
        "schema": SHARD_SCHEMA,
        "attempt_id": ATTEMPT_ID,
        "protocol_sha256": expected_protocol_sha256,
        "label": row["label"],
        "order_name": "numeric",
        "known_key_design": {
            key: row[key]
            for key in (
                "prefix_split",
                "prefix_index",
                "prefix8",
                "prefix8_binary",
                "suffix_split",
                "suffix_index",
                "suffix12",
                "low20",
            )
        },
        "public_target_block_sha256": list(challenge["target_block_sha256"]),
        "cnf_instantiation": instantiation,
        "run": a251._stable_run(run),
        "volatile_process_elapsed_seconds": time.perf_counter() - started,
        "label_used_only_after_fixed_measurement": True,
        "complete_candidate_cover": len(run["cells"]) == 256,
    }
    a268.build_trajectory_shape_table(measurement)
    ledger = _write_measurement(output, measurement)
    cnf.unlink(missing_ok=True)
    return measurement, {**ledger, "resumed": False}


def _evaluate_scores(
    rows: Sequence[Mapping[str, Any]], score_fields: Sequence[np.ndarray]
) -> dict[str, Any]:
    truths = [int(row["prefix8"]) for row in rows]
    prefix_indices = [int(row["prefix_index"]) for row in rows]
    base = score_view_statistics(
        score_fields, true_prefixes=truths, prefix_indices=prefix_indices
    )
    prospective_rows = [
        {
            "label": row["label"],
            "prefix_index": int(row["prefix_index"]),
            "true_prefix": int(row["prefix8"]),
            "midrank": descending_midrank(scores, int(row["prefix8"])),
            "scores": np.asarray(scores, dtype=np.float64).tolist(),
        }
        for row, scores in zip(rows, score_fields, strict=True)
    ]
    return {"prospective_rows": prospective_rows, **base}


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
        "A272:prospective_selected_channel_signal"
        if retained
        else "A272:prospective_selected_channel_boundary"
    )
    writer = CausalWriter(api_id="a272")
    writer._rules = []
    writer.add_rule(
        name="discovery_panel_selects_single_future_hypothesis",
        description="A271 selects exactly one signed channel; A272 freezes it and twenty second-panel keys before any new target, solver measurement, score, or rank exists.",
        pattern=["A271_selected_channel_hypothesis", "frozen_second_disjoint_panel"],
        conclusion="single_view_prospective_contract",
        confidence_modifier=1.0,
    )
    writer.add_rule(
        name="complete_second_panel_before_label_rank",
        description="All 5120 candidate measurements complete before the frozen eight-feature channel is scored and labels enter the exact XOR control.",
        pattern=["twenty_complete_second_panel_covers", "frozen_eight_feature_channel"],
        conclusion="prospective_selected_channel_evidence",
        confidence_modifier=1.0,
    )
    writer.add_triplet(
        trigger="A271:signed_channel_ablation_boundary",
        mechanism="select_best_A271_channel_then_freeze_before_second_panel",
        outcome="A272:frozen_eight_feature_clause_acceptance_conflict_channel",
        confidence=1.0,
        source=payload["A271_result_sha256"],
        quantification="one posthoc A271 hypothesis; eight frozen coefficients; zero refits",
        evidence=json.dumps(payload["selected_hypothesis"], sort_keys=True),
        domain="full-round R20 prospective channel validation",
        quality_score=1.0,
    )
    writer.add_triplet(
        trigger="A272:frozen_eight_feature_clause_acceptance_conflict_channel",
        mechanism="score_twenty_second_panel_complete_covers_and_all_256_XOR_controls",
        outcome=terminal,
        confidence=1.0,
        source=payload["analysis_sha256"],
        quantification=json.dumps(payload["retention_gate"], sort_keys=True),
        evidence=json.dumps(payload["headline"], sort_keys=True),
        domain="exact prospective single-view validation",
        quality_score=1.0,
    )
    writer.add_triplet(
        trigger="A271:signed_channel_ablation_boundary",
        mechanism="materialized_selected_channel_second_panel_and_exact_control_chain",
        outcome=terminal,
        confidence=1.0,
        source="materialized:A271_hypothesis_plus_A272_disjoint_covers_plus_XOR_control",
        quantification="complete two-edge closure retained in-file",
        evidence="Materialized only after all twenty complete candidate covers and all 256 XOR offsets.",
        domain="AI-native retained inference",
        quality_score=1.0,
        is_inferred=True,
    )
    writer.add_cluster(
        name="A272 selected-channel prospective validation",
        entities=[
            "A271:signed_channel_ablation_boundary",
            "select_best_A271_channel_then_freeze_before_second_panel",
            "A272:frozen_eight_feature_clause_acceptance_conflict_channel",
            "score_twenty_second_panel_complete_covers_and_all_256_XOR_controls",
            terminal,
        ],
    )
    writer.add_gap(
        subject=terminal,
        predicate="next_required_object",
        expected_object_type=(
            "frozen_selected_channel_candidate_order_on_separate_unknown_target"
            if retained
            else "ordered_clause_event_timing_reader_without_model_refit"
        ),
        confidence=1.0,
        suggested_queries=(
            [
                "Freeze the validated channel score as a candidate order before generating an unknown target.",
                "Does the channel reduce discovery rank under a separate target contract?",
            ]
            if retained
            else [
                "Does ordered clause-event timing retain signal lost by the selected aggregate channel?",
                "Which learned-clause transitions transfer across disjoint key panels?",
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
        or reader.api_id != "a272"
        or len(explicit) != 2
        or len(all_rows) != 3
        or len(inferred) != 1
        or len(reader._rules) != 2
        or len(reader._clusters) != 1
        or len(reader._gaps) != 1
        or all_rows[-1]["outcome"] != terminal
    ):
        raise RuntimeError("A272 authentic Causal Reader reopen gate failed")
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
            "# A272 — ChaCha20-R20 selected-channel prospective validation",
            "",
            "A271 generated one signed-channel hypothesis. A272 froze that eight-feature reader and a second disjoint twenty-key panel before any new target or solver measurement, then completed all 5120 candidate measurements without refit or early stop.",
            "",
            "## Result",
            "",
            f"- Evidence stage: **{payload['evidence_stage']}**",
            f"- Mean log2 rank: **{headline['mean_log2_rank']:.12f}**",
            f"- Bit gain: **{headline['bit_gain']:+.12f}**",
            f"- Exact shared-XOR p: **{headline['exact_shared_xor_p']:.12f}**",
            f"- Positive prefix groups: **{headline['positive_prefix_groups']}/5**",
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
    protocol, a268, a251_protocol, a268_preflight, a242, indices = _load_protocol(
        protocol_path, expected_protocol_sha256
    )
    _, _, a251, _, _ = a268._load_protocol()
    model = a268._frozen_model(
        json.loads(_anchor_path(protocol["anchors"]["A268_protocol_path"]).read_bytes()),
        a268_preflight,
    )
    rows = list(protocol["prospective_design"]["rows"])
    started = time.perf_counter()
    with tempfile.TemporaryDirectory(prefix="a272_selected_channel_") as temporary:
        directory = Path(temporary)
        prepared = a251._prepare(a251_protocol, a242, directory)
        order = prepared["fresh"].numeric_order()
        measurements: dict[str, dict[str, Any]] = {}
        ledgers: dict[str, dict[str, Any]] = {}
        with ThreadPoolExecutor(
            max_workers=int(protocol["measurement"]["maximum_concurrent_key_processes"])
        ) as executor:
            futures = {
                executor.submit(
                    _execute_one,
                    protocol=protocol,
                    expected_protocol_sha256=expected_protocol_sha256,
                    prepared=prepared,
                    a251=a251,
                    a268=a268,
                    row=row,
                    order=order,
                    directory=directory,
                ): str(row["label"])
                for row in rows
            }
            for future in as_completed(futures):
                label = futures[future]
                measurement, ledger = future.result()
                measurements[label] = measurement
                ledgers[label] = ledger
                print(
                    "A272_KEY "
                    + json.dumps(
                        {
                            "label": label,
                            "seconds": measurement["volatile_process_elapsed_seconds"],
                            "accepted_clauses": measurement["run"]["summary"][
                                "learned_clause_accepted_total"
                            ],
                            "resumed": ledger["resumed"],
                        },
                        sort_keys=True,
                    ),
                    flush=True,
                )
    ordered_measurements = [measurements[row["label"]] for row in rows]
    tables = [a268.build_trajectory_shape_table(item) for item in ordered_measurements]
    score_fields = []
    for table in tables:
        contributions = standardized_contributions(
            table.matrix,
            means=model.means,
            scales=model.scales,
            coefficients=model.coefficients,
        )
        score_fields.append(contributions[:, indices].sum(axis=1))
    evaluation = _evaluate_scores(rows, score_fields)
    gate = protocol["retention_gate"]
    retained = (
        evaluation["exact_shared_xor_p"] <= gate["maximum_exact_shared_xor_p"]
        and evaluation["mean_log2_rank_bit_gain"]
        > gate["minimum_mean_log2_rank_bit_gain"]
        and evaluation["positive_prefix_groups"]
        >= gate["minimum_positive_prefix_groups"]
    )
    measurement_ledger = [
        {"label": row["label"], **ledgers[row["label"]]} for row in rows
    ]
    table_ledger = [
        {"label": table.label, "table_sha256": a268._table_sha256(table)}
        for table in tables
    ]
    corpus = {
        "known_keys": len(tables),
        "candidate_measurements": len(tables) * 256,
        "complete_candidate_covers": all(
            item["complete_candidate_cover"] for item in ordered_measurements
        ),
        "accepted_learned_clauses": sum(
            item["run"]["summary"]["learned_clause_accepted_total"]
            for item in ordered_measurements
        ),
        "rejected_over_64_literal_clauses": sum(
            item["run"]["summary"]["learned_clause_rejected_large_total"]
            for item in ordered_measurements
        ),
        "measurement_ledger": measurement_ledger,
        "measurement_ledger_sha256": _canonical_sha256(measurement_ledger),
        "table_ledger": table_ledger,
        "table_ledger_sha256": _canonical_sha256(table_ledger),
        "model_refits": 0,
        "early_stops": 0,
    }
    headline = {
        "mean_log2_rank": evaluation["mean_log2_rank"],
        "bit_gain": evaluation["mean_log2_rank_bit_gain"],
        "exact_shared_xor_p": evaluation["exact_shared_xor_p"],
        "positive_prefix_groups": evaluation["positive_prefix_groups"],
        "best_shared_xor_offset": evaluation["best_shared_xor_offset"],
    }
    payload: dict[str, Any] = {
        "schema": RESULT_SCHEMA,
        "attempt_id": ATTEMPT_ID,
        "evidence_stage": (
            "FULLROUND_R20_PROSPECTIVE_SELECTED_CHANNEL_SIGNAL"
            if retained
            else "FULLROUND_R20_PROSPECTIVE_SELECTED_CHANNEL_BOUNDARY"
        ),
        "protocol_sha256": expected_protocol_sha256,
        "protocol_state": protocol["protocol_state"],
        "runner_sha256": _file_sha256(Path(__file__)),
        "A271_result_sha256": protocol["anchors"]["A271_result_sha256"],
        "selected_hypothesis": protocol["selected_hypothesis"],
        "prospective_design": protocol["prospective_design"],
        "prospective_corpus": corpus,
        "evaluation": evaluation,
        "analysis_sha256": _canonical_sha256(evaluation),
        "headline": headline,
        "retention_gate": {**gate, "passed": retained},
        "volatile_total_elapsed_seconds": time.perf_counter() - started,
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
    parser.add_argument("--run", action="store_true")
    parser.add_argument("--output", type=Path, default=DEFAULT_RESULT)
    parser.add_argument("--causal-output", type=Path, default=DEFAULT_CAUSAL)
    parser.add_argument("--report-output", type=Path, default=DEFAULT_REPORT)
    parser.add_argument("--dotcausal-src", type=Path, default=DEFAULT_DOTCAUSAL_SRC)
    args = parser.parse_args(argv)
    if not args.run:
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
        ),
        flush=True,
    )


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""Execute the frozen A242 fresh-state candidate-prefix validation.

The one declared development key selected exactly one readout: cumulative
search propagations after the second conflict horizon, with larger values
ranked first.  This runner applies that unchanged readout to twenty disjoint
known-key validation instances.  Every one of the 256 prefix candidates starts
from a copy of the same unsolved CaDiCaL base state.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib
import importlib.util
import inspect
import json
import math
import os
import sys
import tempfile
import time
from collections.abc import Mapping, Sequence
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Any

import zstandard

ROOT = Path(__file__).parents[2]
PROTOCOL = ROOT / "research/configs/chacha20_round20_fresh_candidate_probe_v1.json"
PROTOCOL_SHA256 = "cf53c0812b341b717f360477017c5449d56c0bf7bef9983ca11ff12e04682ac7"
RESULT = ROOT / "research/results/v1/chacha20_round20_fresh_candidate_probe_v1.json"
SHARD_ROOT = ROOT / "research/results/v1/chacha20_round20_fresh_candidate_probe_v1"
CAUSAL = ROOT / "research/results/v1/chacha20_round20_fresh_candidate_probe_v1.causal"
REPORT = ROOT / "research/reports/CAUSAL_CHACHA20_ROUND20_FRESH_CANDIDATE_PROBE_V1.md"
DEFAULT_DOTCAUSAL_SRC = Path(
    "/Users/bhkmie/Documents/Forschung/O1/vendor/fabel/dotcausal_package/src"
)
ATTEMPT_ID = "A242"
SHARD_SCHEMA = "chacha20-round20-fresh-candidate-probe-measurement-v1"
RESULT_SCHEMA = "chacha20-round20-fresh-candidate-probe-result-v1"
METRICS = ("conflicts", "decisions", "search_propagations")
PRIMARY_HORIZON = 2
PRIMARY_METRIC = "search_propagations"
ZSTD_LEVEL = 19


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
        raise RuntimeError(f"cannot import A242 dependency {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _load_protocol() -> dict[str, Any]:
    if _file_sha256(PROTOCOL) != PROTOCOL_SHA256:
        raise RuntimeError("A242 frozen protocol hash differs")
    protocol = json.loads(PROTOCOL.read_bytes())
    validation = protocol.get("validation", {})
    boundary = protocol.get("information_boundary", {})
    if (
        protocol.get("schema")
        != "chacha20-round20-fresh-candidate-probe-protocol-v1"
        or protocol.get("attempt_id") != ATTEMPT_ID
        or protocol.get("protocol_state")
        != "frozen_after_one_development_key_and_before_any_disjoint_validation_key_fresh_state_measurement"
        or validation.get("validation_key_count") != 20
        or len(validation.get("labels", [])) != 20
        or len(set(validation.get("labels", []))) != 20
        or validation.get("conflict_horizons") != [1, 2, 4, 8]
        or validation.get("primary_channel")
        != "cumulative_search_propagations_at_horizon_2"
        or validation.get("primary_direction") != "higher_is_better"
        or validation.get("maximum_concurrent_key_processes") != 2
        or boundary.get("validation_labels_selected_before_validation_execution")
        is not True
        or boundary.get("validation_true_prefix_used_by_solver_order_budget_or_stopping")
        is not False
        or boundary.get("early_stop_permitted") is not False
        or boundary.get("future_prospective_unknown_target_opened") is not False
    ):
        raise RuntimeError("A242 frozen protocol semantic gate failed")
    anchors = protocol["anchors"]
    path_hash_pairs = [
        ("A220_protocol_path", "A220_protocol_sha256"),
        ("symbolic_template_protocol_path", "symbolic_template_protocol_sha256"),
        ("public_core_path", "public_core_sha256"),
        ("symbolic_template_path", "symbolic_template_sha256"),
        ("factorial_design_path", "factorial_design_sha256"),
        ("fresh_wrapper_path", "fresh_wrapper_sha256"),
        ("fresh_native_source_path", "fresh_native_source_sha256"),
        ("fresh_wrapper_test_path", "fresh_wrapper_test_sha256"),
    ]
    observed = {
        path_key: _file_sha256(ROOT / anchors[path_key])
        for path_key, _ in path_hash_pairs
    }
    if any(observed[path_key] != anchors[hash_key] for path_key, hash_key in path_hash_pairs):
        raise RuntimeError("A242 anchored dependency hash differs")
    return protocol


def _prepare(protocol: Mapping[str, Any], directory: Path) -> dict[str, Any]:
    anchors = protocol["anchors"]
    public = _import_path(ROOT / anchors["public_core_path"], "a242_public")
    template = _import_path(ROOT / anchors["symbolic_template_path"], "a242_template")
    design = _import_path(ROOT / anchors["factorial_design_path"], "a242_design")
    fresh = _import_path(ROOT / anchors["fresh_wrapper_path"], "a242_fresh")
    a220 = json.loads((ROOT / anchors["A220_protocol_path"]).read_bytes())
    public_material = public.validate_public_template(a220["public_only_R20_material"])
    if _canonical_sha256(public_material) != anchors["public_only_R20_material_sha256"]:
        raise RuntimeError("A242 public material hash differs")
    ledger = design.factorial_ledger()
    design.validate_factorial_ledger(
        ledger,
        forbidden_low20=a220["factorial_design"]["prior_key_exclusion"]["sorted_low20"],
    )
    if design.ledger_sha256(ledger) != anchors["factorial_ledger_sha256"]:
        raise RuntimeError("A242 factorial ledger hash differs")
    by_label = {row["label"]: dict(row) for row in ledger}
    labels = protocol["validation"]["labels"]
    rows = [by_label[label] for label in labels]
    if (
        any(row["prefix_split"] != "select" or row["suffix_split"] != "fit" for row in rows)
        or len({row["prefix8"] for row in rows}) != 5
        or any(sum(other["prefix8"] == row["prefix8"] for other in rows) != 4 for row in rows)
    ):
        raise RuntimeError("A242 validation ledger slice differs")
    template_protocol = json.loads(
        (ROOT / anchors["symbolic_template_protocol_path"]).read_bytes()
    )
    reference = public.build_known_challenge(public_material, low20=int(rows[0]["low20"]))
    base_raw, key_mapping, output_mapping, template_manifest = template.compile_template(
        r20=public,
        public_challenge=reference,
        protocol=template_protocol,
        directory=directory,
    )
    build = fresh.compile_helper()
    helper = Path(build["binary_path"])
    if (
        build["source_sha256_started"] != anchors["fresh_native_source_sha256"]
        or build["source_sha256_finished"] != anchors["fresh_native_source_sha256"]
        or _file_sha256(helper) != build["binary_sha256"]
    ):
        raise RuntimeError("A242 fresh helper build gate failed")
    return {
        "public": public,
        "template": template,
        "fresh": fresh,
        "public_material": public_material,
        "rows": rows,
        "base_raw": base_raw,
        "key_mapping": key_mapping,
        "output_mapping": output_mapping,
        "template_manifest": template_manifest,
        "helper": helper,
        "helper_build": build,
    }


def analyze() -> dict[str, Any]:
    protocol = _load_protocol()
    return {
        "attempt_id": ATTEMPT_ID,
        "protocol_sha256": PROTOCOL_SHA256,
        "validation_labels": list(protocol["validation"]["labels"]),
        "primary_channel": protocol["validation"]["primary_channel"],
        "protocol_state": protocol["protocol_state"],
        "solver_execution_started": False,
    }


def _stable_run(run: Mapping[str, Any]) -> dict[str, Any]:
    omitted = {"command", "process_elapsed_seconds"}
    return {key: value for key, value in run.items() if key not in omitted}


def _measurement_path(label: str, order_name: str) -> Path:
    return SHARD_ROOT / f"{label}.{order_name}.measurement.json.zst"


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


def _read_measurement(path: Path) -> dict[str, Any]:
    compressed = path.read_bytes()
    raw = zstandard.ZstdDecompressor().decompress(compressed)
    value = json.loads(raw)
    if (
        value.get("schema") != SHARD_SCHEMA
        or value.get("attempt_id") != ATTEMPT_ID
        or value.get("protocol_sha256") != PROTOCOL_SHA256
        or _canonical_bytes(value) != raw
    ):
        raise RuntimeError(f"A242 measurement shard gate failed: {path.name}")
    return value


def _execute_one(
    *,
    protocol: Mapping[str, Any],
    prepared: Mapping[str, Any],
    row: Mapping[str, Any],
    order_name: str,
    order: Sequence[str],
    directory: Path,
) -> tuple[dict[str, Any], dict[str, Any]]:
    output = _measurement_path(str(row["label"]), order_name)
    if output.exists():
        measurement = _read_measurement(output)
        if measurement["label"] != row["label"] or measurement["order_name"] != order_name:
            raise RuntimeError("A242 resumable shard identity differs")
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
    fresh = prepared["fresh"]
    challenge = public.build_known_challenge(
        prepared["public_material"], low20=int(row["low20"])
    )
    raw_cnf, _, instantiation = template.instantiate_output(
        prepared["base_raw"], prepared["output_mapping"], challenge["target_words"][0]
    )
    key_directory = directory / f"{row['label']}_{order_name}"
    key_directory.mkdir(parents=True, exist_ok=True)
    cnf = key_directory / "instance.cnf"
    _atomic_bytes(cnf, raw_cnf)
    if _file_sha256(cnf) != instantiation["sha256"]:
        raise RuntimeError("A242 instantiated CNF readback differs")
    started = time.perf_counter()
    run = fresh.run_fresh_multihorizon(
        helper=prepared["helper"],
        cnf=cnf,
        mode=f"A242_{row['label']}_{order_name}",
        order=order,
        key_one_literals_bit0_through_bit19=prepared["key_mapping"],
        conflict_horizons=protocol["validation"]["conflict_horizons"],
        watchdog_seconds=float(protocol["validation"]["watchdog_seconds_per_stage"]),
        external_timeout_seconds=900.0,
    )
    measurement = {
        "schema": SHARD_SCHEMA,
        "attempt_id": ATTEMPT_ID,
        "protocol_sha256": PROTOCOL_SHA256,
        "label": row["label"],
        "order_name": order_name,
        "known_key_design": {
            "prefix_split": row["prefix_split"],
            "prefix_index": row["prefix_index"],
            "prefix8": row["prefix8"],
            "prefix8_binary": row["prefix8_binary"],
            "suffix_split": row["suffix_split"],
            "suffix_index": row["suffix_index"],
            "suffix12": row["suffix12"],
            "low20": row["low20"],
        },
        "public_target_block_sha256": list(challenge["target_block_sha256"]),
        "cnf_instantiation": instantiation,
        "run": _stable_run(run),
        "volatile_process_elapsed_seconds": time.perf_counter() - started,
        "label_used_only_after_fixed_measurement": True,
        "complete_candidate_cover": len(run["cells"]) == 256,
    }
    ledger = _write_measurement(output, measurement)
    cnf.unlink(missing_ok=True)
    return measurement, {**ledger, "resumed": False}


def _midrank(values: Mapping[int, int], true_prefix: int, *, higher: bool) -> float:
    target = values[true_prefix]
    better = sum(value > target if higher else value < target for value in values.values())
    ties = sum(value == target for value in values.values())
    return 1.0 + better + 0.5 * (ties - 1)


def _landscape(measurement: Mapping[str, Any], *, horizon: int, metric: str) -> dict[int, int]:
    index = METRICS.index(metric)
    result = {
        int(row["prefix8"], 2): int(row["metrics_cell_cumulative_delta"][index])
        for row in measurement["run"]["stages"]
        if row["horizon"] == horizon
    }
    if len(result) != 256:
        raise RuntimeError(
            f"A242 complete horizon landscape missing: {measurement['label']} h={horizon}"
        )
    return result


def _rank_analysis(
    measurements: Sequence[Mapping[str, Any]], *, horizon: int, metric: str, higher: bool
) -> dict[str, Any]:
    landscapes = [_landscape(item, horizon=horizon, metric=metric) for item in measurements]
    true_prefixes = [int(item["known_key_design"]["prefix8"]) for item in measurements]
    ranks = [
        _midrank(landscape, prefix, higher=higher)
        for landscape, prefix in zip(landscapes, true_prefixes, strict=True)
    ]
    observed = sum(math.log2(rank) for rank in ranks) / len(ranks)
    shifted = []
    for xor_offset in range(256):
        shifted_ranks = [
            _midrank(landscape, prefix ^ xor_offset, higher=higher)
            for landscape, prefix in zip(landscapes, true_prefixes, strict=True)
        ]
        shifted.append(sum(math.log2(rank) for rank in shifted_ranks) / len(shifted_ranks))
    exact_p = sum(value <= observed + 1e-15 for value in shifted) / 256.0
    uniform_reference = sum(math.log2(rank) for rank in range(1, 257)) / 256.0
    return {
        "horizon": horizon,
        "metric": metric,
        "direction": "higher_is_better" if higher else "lower_is_better",
        "per_key": [
            {
                "label": item["label"],
                "true_prefix8": prefix,
                "true_value": landscape[prefix],
                "midrank": rank,
                "log2_rank": math.log2(rank),
            }
            for item, landscape, prefix, rank in zip(
                measurements, landscapes, true_prefixes, ranks, strict=True
            )
        ],
        "mean_log2_rank": observed,
        "uniform_mean_log2_rank_reference": uniform_reference,
        "mean_log2_rank_bit_gain": uniform_reference - observed,
        "shared_xor_offset_mean_log2_ranks": shifted,
        "exact_shared_xor_p": exact_p,
        "best_shared_xor_offset": min(range(256), key=shifted.__getitem__),
        "observed_offset": 0,
    }


def _stable_order_view(measurement: Mapping[str, Any]) -> dict[str, Any]:
    def stable(row: Mapping[str, Any]) -> dict[str, Any]:
        return {
            key: value
            for key, value in row.items()
            if key not in {"mode", "cell_index", "elapsed_seconds"}
        }

    stages = sorted(
        (stable(row) for row in measurement["run"]["stages"]),
        key=lambda row: (row["prefix8"], row["horizon"]),
    )
    cells = sorted(
        (stable(row) for row in measurement["run"]["cells"]),
        key=lambda row: row["prefix8"],
    )
    return {"stages": stages, "cells": cells}


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
        raise RuntimeError("A242 authoritative dotcausal.io source is unavailable")
    return writer, reader, {
        "module": "dotcausal.io",
        "io_path": str(io_path),
        "io_sha256": _file_sha256(io_path),
    }


def _build_causal(path: Path, payload: Mapping[str, Any], dotcausal_src: Path) -> dict[str, Any]:
    CausalWriter, CausalReader, reader_source = _load_dotcausal(dotcausal_src)
    primary = payload["primary_analysis"]
    retained = payload["evidence_stage"] == "FULLROUND_R20_FRESH_PREFIX_SIGNAL_RETAINED"
    writer = CausalWriter(api_id="a242")
    writer._rules = []
    writer.add_rule(
        name="fresh_state_removes_candidate_history",
        description="Copying one unsolved base formula for every candidate removes learned-state and traversal-history carryover.",
        pattern=["unsolved_base_formula", "fresh_candidate_copy"],
        conclusion="candidate_history_removed",
        confidence_modifier=1.0,
    )
    writer.add_rule(
        name="disjoint_key_rank_transfer",
        description="A frozen candidate score that ranks true prefixes on disjoint known keys transfers prefix information beyond the development key.",
        pattern=["frozen_candidate_score", "disjoint_known_key_validation"],
        conclusion="transferable_prefix_concentration",
        confidence_modifier=1.0,
    )
    writer.add_triplet(
        trigger="A242:R20_unsolved_base_formula",
        mechanism="fresh_candidate_copy",
        outcome="A242:identical_start_state_for_256_prefixes",
        confidence=1.0,
        source=payload["native_source_sha256"],
        quantification="256 fresh CaDiCaL copies per key; no cross-candidate learned state",
        evidence=json.dumps(payload["fresh_state_gate"], sort_keys=True),
        domain="typed solver-state intervention",
        quality_score=1.0,
    )
    writer.add_triplet(
        trigger="A242:identical_start_state_for_256_prefixes",
        mechanism="fixed_horizon_2_candidate_assumption",
        outcome="A242:cumulative_propagation_landscape",
        confidence=1.0,
        source=payload["measurement_ledger_sha256"],
        quantification="20 disjoint keys x 256 candidates; conflict horizons 1,2,4,8",
        evidence=json.dumps({"metric": PRIMARY_METRIC, "horizon": PRIMARY_HORIZON}),
        domain="candidate-conditional propagation",
        quality_score=1.0,
    )
    writer.add_triplet(
        trigger="A242:cumulative_propagation_landscape",
        mechanism="frozen_higher_is_better_rank_reader",
        outcome="A242:disjoint_true_prefix_rank_distribution",
        confidence=1.0,
        source=payload["primary_analysis_sha256"],
        quantification=f"mean log2 rank {primary['mean_log2_rank']:.12f}; bit gain {primary['mean_log2_rank_bit_gain']:.12f}",
        evidence=json.dumps(primary["per_key"], sort_keys=True),
        domain="known-key prefix readout",
        quality_score=1.0,
    )
    writer.add_triplet(
        trigger="A242:disjoint_true_prefix_rank_distribution",
        mechanism="all_256_shared_XOR_label_controls",
        outcome=(
            "A242:transferable_prefix_concentration"
            if retained
            else "A242:single_channel_transfer_boundary"
        ),
        confidence=1.0,
        source=payload["primary_analysis_sha256"],
        quantification=f"exact p={primary['exact_shared_xor_p']:.12f}",
        evidence=json.dumps(
            {
                "bit_gain": primary["mean_log2_rank_bit_gain"],
                "best_offset": primary["best_shared_xor_offset"],
                "retained": retained,
            },
            sort_keys=True,
        ),
        domain="exact group-invariance control",
        quality_score=1.0,
    )
    writer.add_triplet(
        trigger="A242:numeric_and_reverse_candidate_orders",
        mechanism="fresh_state_order_replication",
        outcome="A242:nonvolatile_measurement_identity",
        confidence=1.0,
        source=payload["order_replication_sha256"],
        quantification="one full 256-candidate key replicated in reverse order",
        evidence=json.dumps(payload["order_replication"], sort_keys=True),
        domain="solver-history control",
        quality_score=1.0,
    )
    writer.add_triplet(
        trigger="A242:R20_unsolved_base_formula",
        mechanism="materialized_fresh_state_rank_chain",
        outcome=(
            "A242:transferable_prefix_concentration"
            if retained
            else "A242:single_channel_transfer_boundary"
        ),
        confidence=1.0,
        source="materialized:fresh_state_removes_candidate_history+disjoint_key_rank_transfer",
        quantification="retained two-stage inference stored in-file",
        evidence="Materialized after frozen disjoint-key validation and exact XOR controls.",
        domain="AI-native retained inference",
        quality_score=1.0,
        is_inferred=True,
    )
    writer.add_cluster(
        name="A242 fresh-state measurement chain",
        entities=[
            "A242:R20_unsolved_base_formula",
            "fresh_candidate_copy",
            "A242:identical_start_state_for_256_prefixes",
            "fixed_horizon_2_candidate_assumption",
            "A242:cumulative_propagation_landscape",
        ],
    )
    writer.add_cluster(
        name="A242 transfer and control chain",
        entities=[
            "A242:disjoint_true_prefix_rank_distribution",
            "all_256_shared_XOR_label_controls",
            "A242:numeric_and_reverse_candidate_orders",
            "fresh_state_order_replication",
        ],
    )
    writer.add_gap(
        subject=(
            "A242:transferable_prefix_concentration"
            if retained
            else "A242:single_channel_transfer_boundary"
        ),
        predicate="next_required_intervention",
        expected_object_type=(
            "prospective_unknown_target_prefix_ranking"
            if retained
            else "typed_multichannel_propagation_contradiction_reader"
        ),
        confidence=1.0,
        suggested_queries=(
            [
                "Does the frozen horizon-2 reader rank a prospectively generated unknown target prefix?",
                "How much complete 2^20 search can be removed at fixed success probability?",
            ]
            if retained
            else [
                "Which typed clause and variable transitions separate correct from wrong prefixes?",
                "Does a multihorizon nonlinear reader recover transfer absent from one scalar channel?",
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
        reader.version != 1
        or reader.api_id != "a242"
        or len(explicit) != 5
        or len(all_rows) != 6
        or len(inferred) != 1
        or len(reader._rules) != 2
        or len(reader._clusters) != 2
        or len(reader._gaps) != 1
    ):
        raise RuntimeError("A242 authentic Causal Reader reopen gate failed")
    return {
        "format": "authentic_dotcausal_v1_AI_native",
        "file_sha256": _file_sha256(path),
        "file_bytes": path.stat().st_size,
        "magic": path.read_bytes()[:8].decode("ascii", errors="replace"),
        "api_id": reader.api_id,
        "explicit_triplets": len(explicit),
        "materialized_inferred_triplets": len(inferred),
        "total_triplets": len(all_rows),
        "embedded_rules": len(reader._rules),
        "clusters": len(reader._clusters),
        "gaps": len(reader._gaps),
        "integrity_verified_by_authoritative_reader": True,
        "amplified_state_materialized_in_file": True,
        "reader_source": reader_source,
        "writer_stats": writer_stats,
        "personal_semantic_readback": {
            "terminal_chain": all_rows[-1],
            "next_gap": reader._gaps[0],
            "cluster_names": [cluster["name"] for cluster in reader._clusters],
        },
    }


def _report(payload: Mapping[str, Any]) -> str:
    primary = payload["primary_analysis"]
    causal = payload["causal"]
    lines = [
        "# A242 — ChaCha20-R20 fresh-state candidate-prefix reader",
        "",
        "Every one of the 256 eight-bit prefix candidates was applied to a fresh copy of the same unsolved full-round ChaCha20 CNF. The single development key selected cumulative search propagations after horizon 2; the score and direction were then frozen before twenty disjoint validation keys were executed.",
        "",
        "## Primary result",
        "",
        f"- Evidence stage: **{payload['evidence_stage']}**",
        f"- Validation keys: **{len(primary['per_key'])}**",
        f"- Mean log2 rank: **{primary['mean_log2_rank']:.12f}**",
        f"- Uniform reference: **{primary['uniform_mean_log2_rank_reference']:.12f}**",
        f"- Mean rank-information gain: **{primary['mean_log2_rank_bit_gain']:.12f} bits**",
        f"- Exact shared-XOR p-value: **{primary['exact_shared_xor_p']:.12f}**",
        f"- Best shared XOR offset: **{primary['best_shared_xor_offset']}** (observed label offset is 0)",
        "",
        "## Execution and controls",
        "",
        f"- Complete validation candidate cover: **{payload['fresh_state_gate']['candidate_measurements']}**",
        f"- Fresh solver instances: **{payload['fresh_state_gate']['fresh_solver_instances']}**",
        f"- Numeric/reverse nonvolatile identity: **{payload['order_replication']['nonvolatile_measurements_identical']}**",
        f"- Early stop: **{payload['fresh_state_gate']['early_stop_used']}**",
        "",
        "## Authentic AI-native Causal readback",
        "",
        f"- Reader integrity: **{causal['integrity_verified_by_authoritative_reader']}**",
        f"- Explicit / inferred triplets: **{causal['explicit_triplets']} / {causal['materialized_inferred_triplets']}**",
        f"- Rules / clusters / gaps: **{causal['embedded_rules']} / {causal['clusters']} / {causal['gaps']}**",
        f"- Next gap: **{causal['personal_semantic_readback']['next_gap']['expected_object_type']}**",
        "",
        "## Per-key primary ranks",
        "",
        "| Label | Prefix | Value | Midrank | log2 rank |",
        "|---|---:|---:|---:|---:|",
    ]
    for row in primary["per_key"]:
        lines.append(
            f"| `{row['label']}` | {row['true_prefix8']} | {row['true_value']} | {row['midrank']:.1f} | {row['log2_rank']:.6f} |"
        )
    return "\n".join(lines) + "\n"


def execute(*, dotcausal_src: Path = DEFAULT_DOTCAUSAL_SRC) -> dict[str, Any]:
    protocol = _load_protocol()
    started = time.perf_counter()
    with tempfile.TemporaryDirectory(prefix="a242_fresh_probe_") as temporary:
        directory = Path(temporary)
        prepared = _prepare(protocol, directory)
        numeric = prepared["fresh"].numeric_order()
        jobs = [
            (row, "numeric", numeric)
            for row in prepared["rows"]
        ]
        replicate_label = protocol["validation"]["order_replication"]["label"]
        replicate_row = next(row for row in prepared["rows"] if row["label"] == replicate_label)
        jobs.append((replicate_row, "reverse_numeric", list(reversed(numeric))))
        measurements: dict[tuple[str, str], dict[str, Any]] = {}
        ledgers: dict[tuple[str, str], dict[str, Any]] = {}
        with ThreadPoolExecutor(
            max_workers=int(protocol["validation"]["maximum_concurrent_key_processes"])
        ) as executor:
            futures = {
                executor.submit(
                    _execute_one,
                    protocol=protocol,
                    prepared=prepared,
                    row=row,
                    order_name=order_name,
                    order=order,
                    directory=directory,
                ): (row["label"], order_name)
                for row, order_name, order in jobs
            }
            for future in as_completed(futures):
                identity = futures[future]
                measurement, ledger = future.result()
                measurements[identity] = measurement
                ledgers[identity] = ledger
                print(
                    "A242_KEY "
                    + json.dumps(
                        {
                            "label": identity[0],
                            "order": identity[1],
                            "seconds": measurement["volatile_process_elapsed_seconds"],
                            "resumed": ledger["resumed"],
                        },
                        sort_keys=True,
                    ),
                    flush=True,
                )
    numeric_measurements = [
        measurements[(label, "numeric")] for label in protocol["validation"]["labels"]
    ]
    primary = _rank_analysis(
        numeric_measurements,
        horizon=PRIMARY_HORIZON,
        metric=PRIMARY_METRIC,
        higher=True,
    )
    secondary = [
        _rank_analysis(numeric_measurements, horizon=horizon, metric=metric, higher=higher)
        for horizon in protocol["validation"]["conflict_horizons"]
        for metric in METRICS
        for higher in (True, False)
        if not (horizon == PRIMARY_HORIZON and metric == PRIMARY_METRIC and higher)
    ]
    numeric_replication = measurements[(replicate_label, "numeric")]
    reverse_replication = measurements[(replicate_label, "reverse_numeric")]
    numeric_view = _stable_order_view(numeric_replication)
    reverse_view = _stable_order_view(reverse_replication)
    order_replication = {
        "label": replicate_label,
        "numeric_stable_sha256": _canonical_sha256(numeric_view),
        "reverse_stable_sha256": _canonical_sha256(reverse_view),
        "nonvolatile_measurements_identical": numeric_view == reverse_view,
    }
    gate = protocol["validation"]["retention_gate"]
    retained = (
        primary["exact_shared_xor_p"] <= gate["maximum_exact_shared_xor_p"]
        and primary["mean_log2_rank_bit_gain"] > gate["minimum_mean_log2_rank_bit_gain"]
        and order_replication["nonvolatile_measurements_identical"]
    )
    ordered_ledgers = [
        {
            "label": label,
            "order": order_name,
            **ledgers[(label, order_name)],
        }
        for label, order_name in [
            *((label, "numeric") for label in protocol["validation"]["labels"]),
            (replicate_label, "reverse_numeric"),
        ]
    ]
    payload: dict[str, Any] = {
        "schema": RESULT_SCHEMA,
        "attempt_id": ATTEMPT_ID,
        "evidence_stage": (
            "FULLROUND_R20_FRESH_PREFIX_SIGNAL_RETAINED"
            if retained
            else "FULLROUND_R20_FRESH_PREFIX_SINGLE_CHANNEL_BOUNDARY"
        ),
        "protocol_sha256": PROTOCOL_SHA256,
        "protocol_state": protocol["protocol_state"],
        "development_observation_used_only_for_channel_selection": protocol[
            "development_observation"
        ],
        "primary_analysis": primary,
        "primary_analysis_sha256": _canonical_sha256(primary),
        "secondary_diagnostics": secondary,
        "secondary_diagnostics_not_used_to_replace_primary": True,
        "order_replication": order_replication,
        "order_replication_sha256": _canonical_sha256(order_replication),
        "measurement_ledger": ordered_ledgers,
        "measurement_ledger_sha256": _canonical_sha256(ordered_ledgers),
        "fresh_state_gate": {
            "validation_keys": 20,
            "candidate_measurements": 20 * 256,
            "fresh_solver_instances": 20 * 256,
            "identical_base_snapshot_per_key": all(
                item["run"]["base_snapshot_identical_verified"]
                for item in numeric_measurements
            ),
            "complete_candidate_cover": all(
                item["complete_candidate_cover"] for item in numeric_measurements
            ),
            "early_stop_used": False,
        },
        "retention_gate": {
            **gate,
            "passed": retained,
        },
        "template_manifest": prepared["template_manifest"],
        "helper_binary_sha256": prepared["helper_build"]["binary_sha256"],
        "native_source_sha256": protocol["anchors"]["fresh_native_source_sha256"],
        "volatile_total_elapsed_seconds": time.perf_counter() - started,
        "information_boundary": protocol["information_boundary"],
    }
    payload["causal"] = _build_causal(CAUSAL, payload, dotcausal_src)
    _atomic_json(RESULT, payload)
    _atomic_bytes(REPORT, _report(payload).encode())
    print(json.dumps({
        "evidence_stage": payload["evidence_stage"],
        "mean_log2_rank": primary["mean_log2_rank"],
        "bit_gain": primary["mean_log2_rank_bit_gain"],
        "exact_shared_xor_p": primary["exact_shared_xor_p"],
        "result": str(RESULT),
        "causal": str(CAUSAL),
        "report": str(REPORT),
    }, indent=2), flush=True)
    return payload


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--analyze-only", action="store_true")
    parser.add_argument("--run", action="store_true")
    parser.add_argument("--dotcausal-src", type=Path, default=DEFAULT_DOTCAUSAL_SRC)
    args = parser.parse_args()
    if args.run:
        execute(dotcausal_src=args.dotcausal_src)
    else:
        print(json.dumps(analyze(), indent=2, sort_keys=True))


if __name__ == "__main__":
    main()

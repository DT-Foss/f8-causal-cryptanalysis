#!/usr/bin/env python3
"""Execute frozen A268 prospective trajectory-shape validation."""

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

import numpy as np
import zstandard

ROOT = Path(__file__).parents[2]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from arx_carry_leak.key_atlas import RidgeLogisticModel  # noqa: E402
from arx_carry_leak.solver_trajectory_shape import (  # noqa: E402
    FEATURE_NAMES,
    build_trajectory_shape_table,
)

PROTOCOL = (
    ROOT
    / "research/configs/chacha20_round20_prospective_trajectory_shape_validation_v1.json"
)
PROTOCOL_SHA256 = "274cdc5b4e2ef0a4887e67d13106b17b6011d0917d473de158e72cbc55f14221"
PREFLIGHT = (
    ROOT
    / "research/provenance/chacha20_round20_a268_prospective_trajectory_shape_preflight_v1.json"
)
RESULT = (
    ROOT
    / "research/results/v1/chacha20_round20_prospective_trajectory_shape_validation_v1.json"
)
CAUSAL = (
    ROOT
    / "research/results/v1/chacha20_round20_prospective_trajectory_shape_validation_v1.causal"
)
REPORT = (
    ROOT
    / "research/reports/CAUSAL_CHACHA20_ROUND20_PROSPECTIVE_TRAJECTORY_SHAPE_VALIDATION_V1.md"
)
SHARD_ROOT = (
    ROOT
    / "research/results/v1/chacha20_round20_prospective_trajectory_shape_validation_v1"
)
DEFAULT_DOTCAUSAL_SRC = Path(
    "/Users/bhkmie/Documents/Forschung/O1/vendor/fabel/dotcausal_package/src"
)
ATTEMPT_ID = "A268"
RESULT_SCHEMA = "chacha20-round20-prospective-trajectory-shape-validation-result-v1"
SHARD_SCHEMA = "chacha20-round20-prospective-trajectory-shape-measurement-v1"
ZSTD_LEVEL = 10
ORIGINAL_MEASUREMENT_RUNNER_SHA256 = (
    "c5f12ad564f9ebc10b388759226176ff77b8d33277a04290fdb44f5da733c287"
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
        raise RuntimeError(f"cannot import A268 dependency {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _anchor_path(value: str) -> Path:
    path = Path(value)
    return path if path.is_absolute() else ROOT / path


def _load_protocol() -> tuple[dict[str, Any], dict[str, Any], Any, dict[str, Any], Any]:
    if _file_sha256(PROTOCOL) != PROTOCOL_SHA256:
        raise RuntimeError("A268 frozen protocol hash differs")
    protocol = json.loads(PROTOCOL.read_bytes())
    measurement = protocol.get("measurement", {})
    reader = protocol.get("frozen_reader", {})
    boundary = protocol.get("information_boundary", {})
    if (
        protocol.get("schema")
        != "chacha20-round20-prospective-trajectory-shape-validation-protocol-v1"
        or protocol.get("attempt_id") != ATTEMPT_ID
        or protocol.get("protocol_state")
        != "frozen_after_A267_retention_and_full_training_model_plus_disjoint_key_design_preflight_before_any_A268_target_block_CNF_solver_measurement_or_rank"
        or measurement.get("conflict_horizons") != [1, 2, 4, 8]
        or measurement.get("maximum_concurrent_key_processes") != 2
        or measurement.get("early_stop_permitted") is not False
        or measurement.get("bounded_variable_addition_enabled") is not False
        or reader.get("feature_count") != len(FEATURE_NAMES)
        or reader.get("model_refit_or_coefficient_update_permitted") is not False
        or reader.get("lambda_reselection_permitted") is not False
        or reader.get("candidate_numeric_value_or_bits_included") is not False
        or boundary.get("any_A268_target_block_or_CNF_generated_before_protocol_freeze")
        is not False
        or boundary.get("any_A268_solver_measurement_started_before_protocol_freeze")
        is not False
        or boundary.get("any_A268_shape_table_logit_rank_or_XOR_control_known_before_protocol_freeze")
        is not False
        or boundary.get("early_stop_permitted") is not False
    ):
        raise RuntimeError("A268 frozen protocol semantic gate failed")
    anchors = protocol["anchors"]
    for path_key, path_value in anchors.items():
        if not path_key.endswith("_path"):
            continue
        hash_key = f"{path_key.removesuffix('_path')}_sha256"
        expected = anchors.get(hash_key)
        if not isinstance(expected, str) or _file_sha256(_anchor_path(path_value)) != expected:
            raise RuntimeError(f"A268 anchored dependency hash differs: {path_key}")
    preflight = json.loads(PREFLIGHT.read_bytes())
    frozen = protocol["frozen_preflight"]
    if (
        preflight.get("schema")
        != "chacha20-round20-prospective-trajectory-shape-preflight-v1"
        or preflight.get("attempt_id") != ATTEMPT_ID
        or preflight["frozen_model"]["selected_ridge_lambda"]
        != frozen["selected_ridge_lambda"]
        or preflight["frozen_model"]["model_sha256"] != frozen["model_sha256"]
        or preflight["prospective_design"]["rows_sha256"]
        != frozen["prospective_design_sha256"]
        or preflight["prospective_design"]["prefixes"]
        != frozen["prospective_prefixes"]
        or preflight["prospective_design"]["suffixes"]
        != frozen["prospective_suffixes"]
        or preflight["information_boundary"]["any_A268_target_block_or_CNF_generated"]
        is not False
        or preflight["information_boundary"]["any_A268_solver_measurement_started"]
        is not False
    ):
        raise RuntimeError("A268 frozen preflight semantic gate failed")
    a251 = _import_path(ROOT / anchors["A251_runner_path"], "a268_a251")
    a251_protocol, a242 = a251._load_protocol()
    return protocol, preflight, a251, a251_protocol, a242


def _frozen_model(protocol: Mapping[str, Any], preflight: Mapping[str, Any]) -> RidgeLogisticModel:
    value = preflight["frozen_model"]["model"]
    if _canonical_sha256(value) != protocol["frozen_preflight"]["model_sha256"]:
        raise RuntimeError("A268 frozen model hash differs")
    model = RidgeLogisticModel(
        feature_names=tuple(value["feature_names"]),
        means=tuple(float(item) for item in value["means"]),
        scales=tuple(float(item) for item in value["scales"]),
        intercept=float(value["intercept"]),
        coefficients=tuple(float(item) for item in value["coefficients"]),
        ridge_lambda=float(value["ridge_lambda"]),
        optimizer_iterations=int(value["optimizer_iterations"]),
        optimizer_gradient_norm=float(value["optimizer_gradient_norm"]),
    )
    if (
        model.feature_names != FEATURE_NAMES
        or model.ridge_lambda != protocol["frozen_preflight"]["selected_ridge_lambda"]
        or len(model.coefficients) != len(FEATURE_NAMES)
    ):
        raise RuntimeError("A268 frozen model geometry differs")
    return model


def analyze() -> dict[str, Any]:
    protocol, preflight, _, _, _ = _load_protocol()
    _frozen_model(protocol, preflight)
    return {
        "attempt_id": ATTEMPT_ID,
        "protocol_sha256": PROTOCOL_SHA256,
        "prospective_key_count": len(preflight["prospective_design"]["rows"]),
        "candidate_measurements": len(preflight["prospective_design"]["rows"]) * 256,
        "frozen_model_sha256": preflight["frozen_model"]["model_sha256"],
        "prospective_design_sha256": preflight["prospective_design"]["rows_sha256"],
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


def _read_measurement(path: Path) -> dict[str, Any]:
    compressed = path.read_bytes()
    raw = zstandard.ZstdDecompressor().decompress(compressed)
    value = json.loads(raw)
    if (
        value.get("schema") != SHARD_SCHEMA
        or value.get("attempt_id") != ATTEMPT_ID
        or value.get("protocol_sha256") != PROTOCOL_SHA256
        or value.get("complete_candidate_cover") is not True
        or _canonical_bytes(value) != raw
    ):
        raise RuntimeError(f"A268 measurement shard gate failed: {path.name}")
    build_trajectory_shape_table(value)
    return value


def _execute_one(
    *,
    protocol: Mapping[str, Any],
    prepared: Mapping[str, Any],
    a251: Any,
    row: Mapping[str, Any],
    order: Sequence[str],
    directory: Path,
) -> tuple[dict[str, Any], dict[str, Any]]:
    output = _measurement_path(str(row["label"]))
    if output.exists():
        measurement = _read_measurement(output)
        if measurement["label"] != row["label"]:
            raise RuntimeError("A268 resumable shard identity differs")
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
        raise RuntimeError("A268 instantiated CNF readback differs")
    started = time.perf_counter()
    run = prepared["clause_wrapper"].run_fresh_clause_identity(
        helper=prepared["clause_helper"],
        cnf=cnf,
        mode=f"A268_{row['label']}_numeric",
        order=order,
        key_one_literals_bit0_through_bit19=prepared["key_mapping"],
        conflict_horizons=protocol["measurement"]["conflict_horizons"],
        watchdog_seconds=float(protocol["measurement"]["watchdog_seconds_per_stage"]),
        external_timeout_seconds=900.0,
    )
    measurement = {
        "schema": SHARD_SCHEMA,
        "attempt_id": ATTEMPT_ID,
        "protocol_sha256": PROTOCOL_SHA256,
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
    build_trajectory_shape_table(measurement)
    ledger = _write_measurement(output, measurement)
    cnf.unlink(missing_ok=True)
    return measurement, {**ledger, "resumed": False}


def _table_sha256(table: Any) -> str:
    digest = hashlib.sha256()
    digest.update(table.label.encode())
    digest.update(int(table.true_prefix).to_bytes(1, "little"))
    digest.update("\n".join(table.feature_names).encode())
    digest.update(np.asarray(table.matrix, dtype="<f8").tobytes())
    return digest.hexdigest()


def _descending_midrank(scores: np.ndarray, candidate: int) -> float:
    target = float(scores[candidate])
    return float(
        1
        + np.count_nonzero(scores > target)
        + 0.5 * (np.count_nonzero(scores == target) - 1)
    )


def _prefix_index_from_label(label: str) -> int:
    marker = "_p"
    start = label.rfind(marker)
    encoded = label[start + len(marker) : start + len(marker) + 2]
    if start < 0 or len(encoded) != 2 or not encoded.isdigit():
        raise RuntimeError(f"A268 prospective label has no terminal prefix index: {label}")
    prefix_index = int(encoded)
    if prefix_index not in range(5) or not label.startswith("a268_prospective_"):
        raise RuntimeError(f"A268 prospective prefix index differs: {label}")
    return prefix_index


def _evaluate(model: RidgeLogisticModel, tables: Sequence[Any]) -> dict[str, Any]:
    rows = []
    for table in tables:
        scores = model.logits(table.matrix)
        prefix_index = _prefix_index_from_label(table.label)
        rows.append(
            {
                "label": table.label,
                "prefix_index": prefix_index,
                "true_prefix": table.true_prefix,
                "midrank": _descending_midrank(scores, table.true_prefix),
                "scores": scores.tolist(),
            }
        )
    if len(rows) != 20 or sorted({row["prefix_index"] for row in rows}) != list(range(5)):
        raise RuntimeError("A268 prospective score geometry differs")
    observed = sum(math.log2(row["midrank"]) for row in rows) / len(rows)
    shifted = []
    for xor_offset in range(256):
        ranks = [
            _descending_midrank(
                np.asarray(row["scores"], dtype=np.float64),
                int(row["true_prefix"]) ^ xor_offset,
            )
            for row in rows
        ]
        shifted.append(sum(math.log2(rank) for rank in ranks) / len(ranks))
    uniform = sum(math.log2(rank) for rank in range(1, 257)) / 256.0
    groups = []
    for prefix_index in range(5):
        group_rows = [row for row in rows if row["prefix_index"] == prefix_index]
        group_mean = sum(math.log2(row["midrank"]) for row in group_rows) / 4.0
        groups.append(
            {
                "prefix_index": prefix_index,
                "true_prefix": group_rows[0]["true_prefix"],
                "mean_log2_rank": group_mean,
                "bit_gain": uniform - group_mean,
                "ranks": [row["midrank"] for row in group_rows],
            }
        )
    return {
        "prospective_rows": rows,
        "prospective_prefix_groups": groups,
        "mean_log2_rank": observed,
        "uniform_mean_log2_rank_reference": uniform,
        "mean_log2_rank_bit_gain": uniform - observed,
        "prospective_prefix_groups_with_positive_bit_gain": sum(
            group["bit_gain"] > 0.0 for group in groups
        ),
        "shared_xor_offset_mean_log2_ranks": shifted,
        "exact_shared_xor_p": sum(
            value <= observed + 1e-15 for value in shifted
        )
        / 256.0,
        "best_shared_xor_offset": min(range(256), key=shifted.__getitem__),
        "observed_offset": 0,
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
        raise RuntimeError("A268 authoritative dotcausal.io source is unavailable")
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
        "A268:prospective_trajectory_shape_signal_retained"
        if retained
        else "A268:prospective_trajectory_shape_transfer_boundary"
    )
    writer = CausalWriter(api_id="a268")
    writer._rules = []
    writer.add_rule(
        name="frozen_model_precedes_disjoint_targets",
        description="The full-training coefficient vector and all twenty new key rows were hash-frozen before any new target block, CNF, solver measurement, or rank existed.",
        pattern=["A267_retained_shape_reader", "frozen_disjoint_key_design"],
        conclusion="prospective_shape_validation_contract",
        confidence_modifier=1.0,
    )
    writer.add_rule(
        name="complete_cover_before_rank",
        description="Every new key executes all 256 fresh-state candidates; the frozen model scores complete tables before labels enter ranks or XOR controls.",
        pattern=["twenty_complete_candidate_covers", "frozen_shape_model"],
        conclusion="prospective_unseen_key_rank_evidence",
        confidence_modifier=1.0,
    )
    writer.add_triplet(
        trigger="A267:trajectory_shape_transfer_retained",
        mechanism="fit_once_on_all_twenty_old_keys_and_hash_freeze_coefficients",
        outcome="A268:frozen_full_training_shape_model",
        confidence=1.0,
        source=payload["frozen_model"]["model_sha256"],
        quantification="532 coefficients; ridge lambda 10; twenty old training keys",
        evidence=json.dumps(payload["frozen_model"], sort_keys=True),
        domain="prospective full-round R20 reader transfer",
        quality_score=1.0,
    )
    writer.add_triplet(
        trigger="A268:frozen_full_training_shape_model",
        mechanism="score_twenty_disjoint_complete_candidate_covers_without_refit",
        outcome="A268:twenty_prospective_shape_score_vectors",
        confidence=1.0,
        source=payload["prospective_corpus"]["table_ledger_sha256"],
        quantification="five new prefixes; four new suffixes; 5120 fresh solver candidates",
        evidence=json.dumps(payload["prospective_corpus"]["table_ledger"], sort_keys=True),
        domain="prospective disjoint known-key validation",
        quality_score=1.0,
    )
    writer.add_triplet(
        trigger="A268:twenty_prospective_shape_score_vectors",
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
                    "prospective_prefix_groups_with_positive_bit_gain",
                    "best_shared_xor_offset",
                )
            },
            sort_keys=True,
        ),
        domain="exact prospective XOR-invariant validation",
        quality_score=1.0,
    )
    writer.add_triplet(
        trigger="A267:trajectory_shape_transfer_retained",
        mechanism="materialized_frozen_model_disjoint_measurement_and_exact_control_chain",
        outcome=terminal,
        confidence=1.0,
        source="materialized:A267_model_plus_A268_disjoint_covers_plus_exact_XOR_control",
        quantification="complete three-edge closure retained in-file",
        evidence="Materialized only after all twenty complete covers and all 256 shared-XOR offsets.",
        domain="AI-native retained inference",
        quality_score=1.0,
        is_inferred=True,
    )
    writer.add_cluster(
        name="A268 prospective trajectory-shape validation",
        entities=[
            "A267:trajectory_shape_transfer_retained",
            "fit_once_on_all_twenty_old_keys_and_hash_freeze_coefficients",
            "A268:frozen_full_training_shape_model",
            "score_twenty_disjoint_complete_candidate_covers_without_refit",
            "A268:twenty_prospective_shape_score_vectors",
            "all_256_shared_XOR_controls_and_frozen_retention_gate",
            terminal,
        ],
    )
    writer.add_gap(
        subject=terminal,
        predicate="next_required_object",
        expected_object_type=(
            "frozen_shape_logit_candidate_order_on_separate_unknown_target"
            if retained
            else "local_pairwise_intervention_on_A268_without_model_refit"
        ),
        confidence=1.0,
        suggested_queries=(
            [
                "Freeze a candidate-order transform derived only from the prospectively validated model.",
                "Does it reduce target discovery rank on a separately generated unknown-key challenge?",
            ]
            if retained
            else [
                "Which matched candidate-pair transition effects survive on the untouched A268 score tables?",
                "Can local interventions explain the discovery-to-prospective transfer boundary without refitting?",
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
        or reader.api_id != "a268"
        or len(explicit) != 3
        or len(rows) != 4
        or len(inferred) != 1
        or len(reader._rules) != 2
        or len(reader._clusters) != 1
        or len(reader._gaps) != 1
        or rows[-1]["outcome"] != terminal
    ):
        raise RuntimeError("A268 authentic Causal Reader reopen gate failed")
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
        "# A268 — Prospective ChaCha20-R20 trajectory-shape validation",
        "",
        "A single A267 model and twenty disjoint key rows were frozen before any A268 target or solver measurement. Every new key then executed a complete 256-candidate fresh-state cover and was scored without refit.",
        "",
        "## Result",
        "",
        f"- Evidence stage: **{payload['evidence_stage']}**",
        f"- Mean log2 rank: **{evaluation['mean_log2_rank']:.12f}**",
        f"- Uniform reference: **{evaluation['uniform_mean_log2_rank_reference']:.12f}**",
        f"- Bit gain: **{evaluation['mean_log2_rank_bit_gain']:+.12f}**",
        f"- Positive prospective prefix groups: **{evaluation['prospective_prefix_groups_with_positive_bit_gain']}/5**",
        f"- Exact shared-XOR p: **{evaluation['exact_shared_xor_p']:.12f}**",
        f"- Frozen gate passed: **{payload['retention_gate']['passed']}**",
        "",
        "## Authentic AI-native Causal readback",
        "",
        f"- Reader integrity: **{causal['integrity_verified_by_authoritative_reader']}**",
        f"- Explicit / materialized: **{causal['explicit_triplets']} / {causal['materialized_inferred_triplets']}**",
        f"- Next gap: **{causal['personal_semantic_readback']['next_gap']['expected_object_type']}**",
        "",
        "All twenty solver shards were complete before finalization. The retained "
        "result uses the corrected terminal `_pNN` label parser; no solver shard "
        "was recomputed for this parser-only correction.",
    ]
    return "\n".join(lines) + "\n"


def execute(*, dotcausal_src: Path = DEFAULT_DOTCAUSAL_SRC) -> dict[str, Any]:
    protocol, preflight, a251, a251_protocol, a242 = _load_protocol()
    model = _frozen_model(protocol, preflight)
    rows = list(preflight["prospective_design"]["rows"])
    started = time.perf_counter()
    with tempfile.TemporaryDirectory(prefix="a268_prospective_shape_") as temporary:
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
                    prepared=prepared,
                    a251=a251,
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
                    "A268_KEY "
                    + json.dumps(
                        {
                            "label": label,
                            "seconds": measurement[
                                "volatile_process_elapsed_seconds"
                            ],
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
    tables = [build_trajectory_shape_table(item) for item in ordered_measurements]
    table_ledger = [
        {"label": table.label, "table_sha256": _table_sha256(table)}
        for table in tables
    ]
    measurement_ledger = [
        {"label": row["label"], **ledgers[row["label"]]} for row in rows
    ]
    evaluation = _evaluate(model, tables)
    gate = protocol["retention_gate"]
    retained = (
        evaluation["exact_shared_xor_p"] <= gate["maximum_exact_shared_xor_p"]
        and evaluation["mean_log2_rank_bit_gain"]
        > gate["minimum_aggregate_mean_log2_rank_bit_gain"]
        and evaluation["prospective_prefix_groups_with_positive_bit_gain"]
        >= gate["minimum_prospective_prefix_groups_with_positive_bit_gain"]
    )
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
    payload: dict[str, Any] = {
        "schema": RESULT_SCHEMA,
        "attempt_id": ATTEMPT_ID,
        "evidence_stage": (
            "FULLROUND_R20_PROSPECTIVE_TRAJECTORY_SHAPE_SIGNAL"
            if retained
            else "FULLROUND_R20_PROSPECTIVE_TRAJECTORY_SHAPE_BOUNDARY"
        ),
        "protocol_sha256": PROTOCOL_SHA256,
        "protocol_state": protocol["protocol_state"],
        "runner_sha256": _file_sha256(Path(__file__)),
        "measurement_runner_sha256": (
            ORIGINAL_MEASUREMENT_RUNNER_SHA256
            if all(row["resumed"] for row in measurement_ledger)
            else _file_sha256(Path(__file__))
        ),
        "finalization_correction": {
            "scope": "terminal_prospective_prefix_label_parser_only",
            "original_parser": "first_occurrence_of__p",
            "corrected_parser": "terminal_occurrence_of__pNN_with_exact_gate",
            "original_measurement_runner_sha256": ORIGINAL_MEASUREMENT_RUNNER_SHA256,
            "corrected_finalizer_runner_sha256": _file_sha256(Path(__file__)),
            "all_twenty_measurement_shards_preexisted_and_were_resumed": all(
                row["resumed"] for row in measurement_ledger
            ),
            "solver_shards_recomputed_for_correction": False,
        },
        "frozen_model": {
            "model_sha256": preflight["frozen_model"]["model_sha256"],
            "selected_ridge_lambda": preflight["frozen_model"][
                "selected_ridge_lambda"
            ],
            "training_table_ledger_sha256": preflight["frozen_model"][
                "training_table_ledger_sha256"
            ],
            "coefficient_count": len(model.coefficients),
        },
        "prospective_design": preflight["prospective_design"],
        "prospective_corpus": corpus,
        "evaluation": evaluation,
        "analysis_sha256": _canonical_sha256(evaluation),
        "retention_gate": {**gate, "passed": retained},
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
                "positive_prefix_groups": evaluation[
                    "prospective_prefix_groups_with_positive_bit_gain"
                ],
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

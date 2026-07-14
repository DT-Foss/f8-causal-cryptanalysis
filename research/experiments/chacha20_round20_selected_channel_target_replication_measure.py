#!/usr/bin/env python3
"""Measure A275's frozen reader on one fresh unlabeled ChaCha20-R20 target."""

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
from pathlib import Path
from typing import Any

import numpy as np
import zstandard

ROOT = Path(__file__).parents[2]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from arx_carry_leak.solver_trajectory_shape import (  # noqa: E402
    BASE_FEATURE_NAMES,
    CHANNELS,
    FEATURE_NAMES,
    HORIZONS,
    _channel_value,
    _orbit_matrix,
    _shape_vector,
    _stage_rows,
)
from arx_carry_leak.trajectory_contribution import standardized_contributions  # noqa: E402

ATTEMPT_ID = "A275"
RESULT_SCHEMA = "chacha20-round20-selected-channel-target-replication-order-result-v1"
MEASUREMENT_SCHEMA = "chacha20-round20-selected-channel-target-replication-measurement-v1"
DEFAULT_PROTOCOL = ROOT / "research/configs/chacha20_round20_selected_channel_target_replication_v1.json"
DEFAULT_RESULT = (
    ROOT / "research/results/v1/chacha20_round20_selected_channel_target_replication_order_v1.json"
)
DEFAULT_CAUSAL = DEFAULT_RESULT.with_suffix(".causal")
DEFAULT_REPORT = (
    ROOT / "research/reports/CAUSAL_CHACHA20_ROUND20_SELECTED_CHANNEL_TARGET_REPLICATION_ORDER_V1.md"
)
DEFAULT_MEASUREMENT = (
    ROOT
    / "research/results/v1/chacha20_round20_selected_channel_target_replication_order_v1"
    / "target.numeric.measurement.json.zst"
)
DEFAULT_DOTCAUSAL_SRC = Path(
    "/Users/bhkmie/Documents/Forschung/O1/vendor/fabel/dotcausal_package/src"
)
ZSTD_LEVEL = 10
FORBIDDEN_SERIALIZED_KEYS = {
    "known_low20",
    "low20",
    "low20_hex",
    "recovered_unknown_low20",
    "recovered_unknown_low20_hex",
    "salt",
    "salt_hex",
    "secret_low20",
    "target_prefix8",
    "true_prefix",
    "unknown_assignment",
    "unknown_key_word0_low_value",
}


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
        json.dumps(value, indent=2, sort_keys=True, ensure_ascii=True, allow_nan=False).encode(
            "ascii"
        )
        + b"\n",
    )


def _anchor_path(value: str) -> Path:
    path = Path(value)
    return path if path.is_absolute() else ROOT / path


def _import_path(path: Path, name: str) -> Any:
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot import A275 dependency {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _assert_secret_free(value: Any) -> None:
    if isinstance(value, Mapping):
        for key, child in value.items():
            if str(key).lower() in FORBIDDEN_SERIALIZED_KEYS:
                raise RuntimeError(f"A275 secret-bearing field is forbidden: {key}")
            _assert_secret_free(child)
    elif isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        for child in value:
            _assert_secret_free(child)


def _load_protocol(
    protocol_path: Path, expected_protocol_sha256: str
) -> tuple[
    dict[str, Any],
    Any,
    Any,
    Any,
    dict[str, Any],
    Any,
    Any,
    tuple[int, ...],
]:
    if _file_sha256(protocol_path) != expected_protocol_sha256:
        raise RuntimeError("A275 frozen protocol hash differs")
    protocol = json.loads(protocol_path.read_bytes())
    measurement = protocol.get("measurement", {})
    readout = protocol.get("readout", {})
    boundary = protocol.get("information_boundary", {})
    if (
        protocol.get("schema")
        != "chacha20-round20-selected-channel-target-replication-protocol-v1"
        or protocol.get("attempt_id") != ATTEMPT_ID
        or protocol.get("protocol_state")
        != "frozen_after_A274_confirmed_recovery_and_fresh_replication_target_generation_with_ephemeral_label_discarded_before_any_target_CNF_measurement_score_order_or_recovery"
        or measurement.get("conflict_horizons") != [1, 2, 4, 8]
        or measurement.get("complete_256_candidate_cover_required_before_scoring") is not True
        or measurement.get("terminal_SAT_UNSAT_or_model_bits_permitted") is not False
        or measurement.get("early_stop_permitted") is not False
        or measurement.get("bounded_variable_addition_enabled") is not False
        or readout.get("feature_indices") != [502, 504, 505, 508, 509, 510, 511, 514]
        or readout.get("model_refit_or_coefficient_update_permitted") is not False
        or readout.get("target_label_available_to_readout") is not False
        or boundary.get("target_generation_label_discarded_before_protocol_serialization")
        is not True
        or boundary.get("any_target_CNF_or_solver_measurement_started_before_freeze")
        is not False
        or boundary.get("any_target_channel_score_or_candidate_order_known_before_freeze")
        is not False
        or boundary.get("target_label_used_for_feature_construction_scoring_order_or_stop")
        is not False
        or boundary.get("all_1024_shallow_stages_must_remain_unknown_and_model_free")
        is not True
        or boundary.get("A274_confirmed_recovery_completed_before_target_generation")
        is not True
        or boundary.get("target_generated_after_A274_confirmed_recovery") is not True
        or boundary.get("A273_public_challenge_explicitly_excluded") is not True
    ):
        raise RuntimeError("A275 frozen protocol semantic gate failed")
    _assert_secret_free(protocol)
    anchors = protocol["anchors"]
    for path_key, path_value in anchors.items():
        if not path_key.endswith("_path"):
            continue
        hash_key = f"{path_key.removesuffix('_path')}_sha256"
        if _file_sha256(_anchor_path(path_value)) != anchors.get(hash_key):
            raise RuntimeError(f"A275 anchored dependency hash differs: {path_key}")
    target = protocol["target"]
    if (
        _canonical_sha256(target["public_template"]) != target["public_template_sha256"]
        or _canonical_sha256(target["public_challenge"])
        != target["public_challenge_sha256"]
        or target["public_challenge"]["target_block_sha256"]
        != target["target_block_sha256"]
        or target["ephemeral_generation_label_returned_or_serialized"] is not False
        or target["public_challenge_sha256"]
        == target["excluded_A273_public_challenge_sha256"]
    ):
        raise RuntimeError("A275 frozen public target differs")
    public = _import_path(_anchor_path(anchors["public_core_path"]), "a275_public")
    public_template = public.validate_public_template(target["public_template"])
    public.P1._validate_challenge(target["public_challenge"])
    if _canonical_sha256(public_template) != target["public_template_sha256"]:
        raise RuntimeError("A275 public target template validation differs")
    a272 = _import_path(_anchor_path(anchors["A272_runner_path"]), "a275_a272")
    (
        a272_protocol,
        a268,
        a251_protocol,
        a268_preflight,
        a242,
        indices,
    ) = a272._load_protocol(
        _anchor_path(anchors["A272_protocol_path"]),
        anchors["A272_protocol_sha256"],
    )
    _, _, a251, _, _ = a268._load_protocol()
    model = a268._frozen_model(
        json.loads(_anchor_path(a272_protocol["anchors"]["A268_protocol_path"]).read_bytes()),
        a268_preflight,
    )
    if (
        tuple(readout["feature_indices"]) != indices
        or protocol["selected_hypothesis"] != a272_protocol["selected_hypothesis"]
        or [model.feature_names[index] for index in indices]
        != protocol["selected_hypothesis"]["feature_names"]
    ):
        raise RuntimeError("A275 frozen selected reader differs")
    a272_result = json.loads(_anchor_path(anchors["A272_result_path"]).read_bytes())
    if a272_result.get("retention_gate", {}).get("passed") is not True:
        raise RuntimeError("A275 A272 retention gate is not retained")
    return protocol, public, a272, a268, a251_protocol, a242, model, indices


def analyze(protocol_path: Path, expected_protocol_sha256: str) -> dict[str, Any]:
    protocol, _, _, _, _, _, _, indices = _load_protocol(
        protocol_path, expected_protocol_sha256
    )
    return {
        "attempt_id": ATTEMPT_ID,
        "protocol_sha256": expected_protocol_sha256,
        "public_challenge_sha256": protocol["target"]["public_challenge_sha256"],
        "selected_feature_count": len(indices),
        "candidate_measurements": 256,
        "target_label_available": False,
        "solver_measurement_started": False,
    }


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


def _read_measurement(
    path: Path, *, expected_protocol_sha256: str, expected_target_sha256: str
) -> tuple[dict[str, Any], dict[str, Any]]:
    compressed = path.read_bytes()
    raw = zstandard.ZstdDecompressor().decompress(compressed)
    value = json.loads(raw)
    if (
        value.get("schema") != MEASUREMENT_SCHEMA
        or value.get("attempt_id") != ATTEMPT_ID
        or value.get("protocol_sha256") != expected_protocol_sha256
        or value.get("public_challenge_sha256") != expected_target_sha256
        or value.get("complete_candidate_cover") is not True
        or value.get("target_label_available_to_measurement") is not False
        or _canonical_bytes(value) != raw
    ):
        raise RuntimeError("A275 target measurement shard gate failed")
    _assert_secret_free(value)
    _target_feature_matrix(value)
    return value, {
        "path": str(path.relative_to(ROOT)),
        "raw_bytes": len(raw),
        "raw_sha256": _sha256(raw),
        "compressed_bytes": len(compressed),
        "compressed_sha256": _sha256(compressed),
        "resumed": True,
    }


def _require_unresolved_measurement(measurement: Mapping[str, Any]) -> None:
    """Keep A275 strictly diagnostic: no SAT, model, or terminal cell may survive."""

    run = measurement.get("run", {})
    stages = run.get("stages", [])
    cells = run.get("cells", [])
    if (
        len(stages) != 256 * len(HORIZONS)
        or len(cells) != 256
        or any(
            stage.get("status") != "unknown"
            or stage.get("terminal") is not False
            or stage.get("model_bits_bit0_through_bit19") != []
            for stage in stages
        )
        or any(
            cell.get("final_status") != "unknown"
            or cell.get("terminal_stage_index") is not None
            or cell.get("stages_run") != len(HORIZONS)
            for cell in cells
        )
    ):
        raise RuntimeError(
            "A275 diagnostic measurement reached a terminal solver outcome or model"
        )


def _target_feature_matrix(measurement: Mapping[str, Any]) -> np.ndarray:
    run = measurement.get("run", {})
    if (
        run.get("learned_clause_identity_complete") is not True
        or run.get("bounded_variable_addition_enabled") is not False
        or measurement.get("complete_candidate_cover") is not True
    ):
        raise ValueError("A275 target trajectory measurement differs")
    _require_unresolved_measurement(measurement)
    rows = _stage_rows(measurement)
    base = np.empty((256, len(BASE_FEATURE_NAMES)), dtype=np.float64)
    for candidate in range(256):
        channel_values = {
            channel: np.asarray(
                [
                    _channel_value(rows[(candidate, horizon)], channel)
                    for horizon in HORIZONS
                ],
                dtype=np.float64,
            )
            for channel in CHANNELS
        }
        base[candidate] = _shape_vector(channel_values)
    result = _orbit_matrix(base)
    if result.shape != (256, len(FEATURE_NAMES)) or not np.isfinite(result).all():
        raise RuntimeError("A275 target trajectory feature matrix differs")
    return result


def _candidate_order(scores: Sequence[float]) -> list[int]:
    values = np.asarray(scores, dtype=np.float64)
    if values.shape != (256,) or not np.isfinite(values).all():
        raise ValueError("A275 candidate score field differs")
    order = sorted(range(256), key=lambda candidate: (-float(values[candidate]), candidate))
    if len(order) != 256 or set(order) != set(range(256)):
        raise RuntimeError("A275 candidate order is not a complete permutation")
    return order


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
    writer = CausalWriter(api_id="a275")
    writer._rules = []
    writer.add_rule(
        name="confirmed_first_target_precedes_distinct_replication_target",
        description="A274 confirms the first target-blind recovery before A275 generates and freezes a distinct second public target while keeping A272's reader unchanged.",
        pattern=["A274_confirmed_target_blind_recovery", "A275_distinct_unlabeled_public_target"],
        conclusion="A275_replication_reader_contract",
        confidence_modifier=1.0,
    )
    writer.add_rule(
        name="complete_target_cover_precedes_order",
        description="All 256 target candidate trajectories complete before the fixed eight-feature score is evaluated and converted to a total order.",
        pattern=["A275_complete_256_cell_target_cover", "A272_frozen_eight_feature_reader"],
        conclusion="A275_hash_frozen_target_order",
        confidence_modifier=1.0,
    )
    writer.add_triplet(
        trigger="A274:confirmed_fullround_R20_top128_recovery",
        mechanism="reuse_unchanged_A272_reader_then_generate_distinct_label_free_replication_target",
        outcome="A275:target_blind_reader_contract",
        confidence=1.0,
        source=payload["A274_result_sha256"],
        quantification="A274 strict-subdomain recovery precedes A275 target generation; A273 challenge hash excluded",
        evidence=json.dumps(payload["selected_hypothesis"], sort_keys=True),
        domain="full-round ChaCha20-R20 target transfer",
        quality_score=1.0,
    )
    writer.add_triplet(
        trigger="A275:target_blind_reader_contract",
        mechanism="measure_all_256_cells_then_apply_fixed_channel_and_hash_total_order",
        outcome="A275:hash_frozen_target_candidate_order",
        confidence=1.0,
        source=payload["analysis_sha256"],
        quantification="256/256 cells; one frozen view; zero labels; zero refits",
        evidence=json.dumps(payload["headline"], sort_keys=True),
        domain="label-free full-round target ranking",
        quality_score=1.0,
    )
    writer.add_triplet(
        trigger="A274:confirmed_fullround_R20_top128_recovery",
        mechanism="materialized_frozen_reader_plus_unlabeled_complete_target_cover_chain",
        outcome="A275:hash_frozen_target_candidate_order",
        confidence=1.0,
        source="materialized:A274_confirmation_plus_A275_complete_target_cover",
        quantification="two-edge prospective closure materialized in-file",
        evidence="The target-generation label is absent; the order exists before recovery.",
        domain="AI-native retained inference",
        quality_score=1.0,
        is_inferred=True,
    )
    writer.add_cluster(
        name="A275 target-blind selected-channel order",
        entities=[
            "A274:confirmed_fullround_R20_top128_recovery",
            "A275:target_blind_reader_contract",
            "A275:hash_frozen_target_candidate_order",
        ],
    )
    writer.add_gap(
        subject="A275:hash_frozen_target_candidate_order",
        predicate="next_required_object",
        expected_object_type="hash_frozen_top128_retained_state_replication_recovery",
        confidence=1.0,
        suggested_queries=[
            "Freeze the complete A275 order and execute only its first 128 prefix cells.",
            "Does retained-state CaDiCaL recover and independently confirm the target inside 2^19 assignments?",
        ],
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
        or reader.api_id != "a275"
        or len(explicit) != 2
        or len(all_rows) != 3
        or len(inferred) != 1
        or len(reader._rules) != 2
        or len(reader._clusters) != 1
        or len(reader._gaps) != 1
        or all_rows[-1]["outcome"] != "A275:hash_frozen_target_candidate_order"
    ):
        raise RuntimeError("A275 authentic Causal Reader reopen gate failed")
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
            "# A275 — ChaCha20-R20 target-blind selected-channel replication order",
            "",
            "After A274 confirmed the first target-blind recovery, A272's unchanged eight-feature reader was applied without refit to a distinct second public R20 target whose generation label was discarded before protocol serialization. All 256 prefix-cell trajectories completed before scoring.",
            "",
            "## Frozen target order",
            "",
            f"- Complete cells: **{headline['complete_candidate_cells']}/256**",
            f"- Top-128 logical assignment domain: **2^{headline['top128_assignment_bits']}**",
            f"- Complete order SHA-256: `{headline['complete_order_uint8_sha256']}`",
            f"- Target label available: **{headline['target_label_available']}**",
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
    measurement_output: Path,
    causal_output: Path,
    report_output: Path,
    dotcausal_src: Path,
) -> dict[str, Any]:
    (
        protocol,
        _,
        _,
        a268,
        a251_protocol,
        a242,
        model,
        indices,
    ) = _load_protocol(protocol_path, expected_protocol_sha256)
    _, _, a251, _, _ = a268._load_protocol()
    target = protocol["target"]
    if measurement_output.exists():
        measurement, ledger = _read_measurement(
            measurement_output,
            expected_protocol_sha256=expected_protocol_sha256,
            expected_target_sha256=target["public_challenge_sha256"],
        )
    else:
        with tempfile.TemporaryDirectory(prefix="a275_target_measurement_") as temporary:
            directory = Path(temporary)
            prepared = a251._prepare(a251_protocol, a242, directory)
            if _canonical_sha256(prepared["public_material"]) != target["public_template_sha256"]:
                raise RuntimeError("A275 prepared public material differs from frozen target")
            raw_cnf, _, instantiation = prepared["template"].instantiate_output(
                prepared["base_raw"],
                prepared["output_mapping"],
                target["public_challenge"]["target_words"][0],
            )
            cnf = directory / "a275_unlabeled_target.cnf"
            _atomic_bytes(cnf, raw_cnf)
            if _file_sha256(cnf) != instantiation["sha256"]:
                raise RuntimeError("A275 instantiated target CNF readback differs")
            started = time.perf_counter()
            run = prepared["clause_wrapper"].run_fresh_clause_identity(
                helper=prepared["clause_helper"],
                cnf=cnf,
                mode="A275_target_numeric_unlabeled",
                order=prepared["fresh"].numeric_order(),
                key_one_literals_bit0_through_bit19=prepared["key_mapping"],
                conflict_horizons=protocol["measurement"]["conflict_horizons"],
                watchdog_seconds=float(protocol["measurement"]["watchdog_seconds_per_stage"]),
                external_timeout_seconds=900.0,
            )
            measurement = {
                "schema": MEASUREMENT_SCHEMA,
                "attempt_id": ATTEMPT_ID,
                "protocol_sha256": expected_protocol_sha256,
                "public_challenge_sha256": target["public_challenge_sha256"],
                "public_target_block_sha256": target["target_block_sha256"],
                "order_name": "numeric",
                "cnf_instantiation": instantiation,
                "run": a251._stable_run(run),
                "volatile_process_elapsed_seconds": time.perf_counter() - started,
                "target_label_available_to_measurement": False,
                "label_used_for_feature_construction_or_scoring": False,
                "complete_candidate_cover": len(run["cells"]) == 256,
            }
            _assert_secret_free(measurement)
            _target_feature_matrix(measurement)
            ledger = {**_write_measurement(measurement_output, measurement), "resumed": False}
    matrix = _target_feature_matrix(measurement)
    contributions = standardized_contributions(
        matrix,
        means=model.means,
        scales=model.scales,
        coefficients=model.coefficients,
    )
    scores = contributions[:, indices].sum(axis=1)
    order = _candidate_order(scores)
    top128 = order[:128]
    analysis = {
        "score_field": scores.tolist(),
        "score_field_sha256": _canonical_sha256(scores.tolist()),
        "complete_cell_order": order,
        "complete_cell_order_uint8_sha256": _sha256(bytes(order)),
        "top128_cell_order": top128,
        "top128_cell_order_uint8_sha256": _sha256(bytes(top128)),
        "order_tiebreak": "descending_score_then_ascending_candidate",
        "selected_feature_indices": list(indices),
        "model_refits": 0,
        "target_labels_used": 0,
    }
    headline = {
        "complete_candidate_cells": len(order),
        "complete_order_uint8_sha256": analysis["complete_cell_order_uint8_sha256"],
        "top128_order_uint8_sha256": analysis["top128_cell_order_uint8_sha256"],
        "top128_assignment_bits": 19,
        "target_label_available": False,
    }
    payload: dict[str, Any] = {
        "schema": RESULT_SCHEMA,
        "attempt_id": ATTEMPT_ID,
        "evidence_stage": "FULLROUND_R20_TARGET_BLIND_SELECTED_CHANNEL_REPLICATION_ORDER_FROZEN",
        "protocol_sha256": expected_protocol_sha256,
        "protocol_state": protocol["protocol_state"],
        "runner_sha256": _file_sha256(Path(__file__)),
        "A272_result_sha256": protocol["anchors"]["A272_result_sha256"],
        "A274_result_sha256": protocol["anchors"]["A274_result_sha256"],
        "selected_hypothesis": protocol["selected_hypothesis"],
        "public_challenge_sha256": target["public_challenge_sha256"],
        "measurement": {
            **ledger,
            "complete_candidate_cover": measurement["complete_candidate_cover"],
            "accepted_learned_clauses": measurement["run"]["summary"][
                "learned_clause_accepted_total"
            ],
            "rejected_over_64_literal_clauses": measurement["run"]["summary"][
                "learned_clause_rejected_large_total"
            ],
        },
        "analysis": analysis,
        "analysis_sha256": _canonical_sha256(analysis),
        "headline": headline,
        "information_boundary": protocol["information_boundary"],
    }
    _assert_secret_free(payload)
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
    parser.add_argument("--measurement-output", type=Path, default=DEFAULT_MEASUREMENT)
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
        measurement_output=args.measurement_output,
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


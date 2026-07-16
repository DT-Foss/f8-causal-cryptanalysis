#!/usr/bin/env python3
"""A449: target-blind A448 proof-antecedent transfer to both W52 axes."""

from __future__ import annotations

import argparse
import concurrent.futures
import gc
import hashlib
import importlib.util
import inspect
import json
import os
import sys
import time
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

import numpy as np
import zstandard

ROOT = Path(__file__).parents[2]
RESEARCH = ROOT / "research"
CONFIGS = RESEARCH / "configs"
RESULTS = RESEARCH / "results/v1"
MEASUREMENTS = RESULTS / "chacha20_round20_w52_target_blind_proof_antecedent_trace_a449_v1"

STEM = "chacha20_round20_w52_target_blind_proof_antecedent_trace_a449"
DESIGN = CONFIGS / f"{STEM}_design_v1.json"
IMPLEMENTATION = CONFIGS / f"{STEM}_implementation_v1.json"
RESULT = RESULTS / f"{STEM}_v1.json"
CAUSAL = RESULT.with_suffix(".causal")
REPORT = RESULT.with_suffix(".md")
TEST = ROOT / "tests/test_chacha20_round20_w52_target_blind_proof_antecedent_trace_a449.py"
REPRO = ROOT / "scripts/reproduce_chacha20_round20_w52_target_blind_proof_antecedent_trace_a449.sh"

A448_RUNNER = RESEARCH / "experiments/chacha20_round20_w46_full128_proof_antecedent_transfer_a448.py"
A448_IMPLEMENTATION = CONFIGS / "chacha20_round20_w46_full128_proof_antecedent_transfer_a448_implementation_v1.json"
A448_RESULT = RESULTS / "chacha20_round20_w46_full128_proof_antecedent_transfer_a448_v1.json"
A448_CAUSAL = A448_RESULT.with_suffix(".causal")
A448_READBACK = RESEARCH / "reports/CAUSAL_CHACHA20_A448_PERSONAL_READER_READBACK_V1.md"
A442_RUNNER = RESEARCH / "experiments/chacha20_round20_w52_knownkey_meta_reader_transfer_a442.py"
A442_RESULT = RESULTS / "chacha20_round20_w52_knownkey_meta_reader_transfer_a442_v1.json"
A439_RUNNER = RESEARCH / "experiments/chacha20_round20_w52_wide_consensus_dual_axis_wavefront_a439.py"
A439_RESULT = RESULTS / "chacha20_round20_w52_wide_consensus_dual_axis_wavefront_a439_v1.json"
A432_PREFLIGHT = RESULTS / "chacha20_round20_w52_public_output_direct12_eight_worker_a432_preflight_v1.json"
A432_RESULT = RESULTS / "chacha20_round20_w52_public_output_direct12_eight_worker_a432_v1.json"
A433_PREFLIGHT = RESULTS / "chacha20_round20_w52_prefix_aligned_direct12_eight_worker_a433_preflight_v2.json"
A433_RESULT = RESULTS / "chacha20_round20_w52_prefix_aligned_direct12_eight_worker_a433_v2.json"
A432_ARTIFACTS = RESEARCH / "artifacts/a432_chacha20_r20_w52_public_output_direct12"
A433_ARTIFACTS = RESEARCH / "artifacts/a433_chacha20_r20_w52_prefix_aligned_direct12_v2"

ATTEMPT_ID = "A449"
DESIGN_SHA256 = "d5be9782d073626309226063119364cf50444cbf7dea9167d1364d2e921e471c"
A448_RUNNER_SHA256 = "33cf14799282e52a6e23857d15dba096ba61e003fdef8b53a2b6a93a5dcd9d60"
A448_IMPLEMENTATION_SHA256 = "0924803bf5f2d7168b51b205e125303a18165b72d8a9718fc57cb4f395251801"
A448_RESULT_SHA256 = "4f3bfbc7be7932917a40a3ad9ff3db76c1bf1ca8799d7a887025f3e98e5464db"
A448_CAUSAL_SHA256 = "3a3092311c7ba15ad4be27f53e6e7db2137edd045c8b6a818d9876310b0c564f"
A448_READBACK_SHA256 = "1f3914f78874754a74a71cc335581e310a0391e9326f310ae0c5f5126e4500b0"
A442_RESULT_SHA256 = "8c8222528dc3ef12ffc0fbda513061b39243daade51a70a17f0bd89c65b53b1d"
A439_RUNNER_SHA256 = "6cb94c2c8e8e404b25b2b41c51e4fd68b038e447616c740dba549464b5f490fb"
A439_RESULT_SHA256 = "b141fb882bd1a1cdc6a22de424370fe3118c9a4eb90565eaa0c8225321b9f869"
A432_PREFLIGHT_SHA256 = "b85713e6bde2791f59ce6bf7562e2096c4494e62061cef45d9ee88f3e573d377"
A432_RESULT_SHA256 = "3d0ed27a25288db589ddb6608407314d1fa32f4cb678806e142eb819159a7e6d"
A433_PREFLIGHT_SHA256 = "c1edef54740c77031a33e87f500df40a5da9db1e98ca1f0d6a07782cdaccb6c4"
A433_RESULT_SHA256 = "3ffa28081437ed12276bac868ca1de780fe2d419ea986c68fba52098c0649e07"

AXES = ("prefix", "off_axis")
SLICES = tuple(range(16))
CELLS = 256
AXIS_CELLS = 4096
PAIR_CELLS = AXIS_CELLS * AXIS_CELLS
HORIZONS = (1, 2, 4, 8)
WATCHDOG_SECONDS = 2.0
MEASUREMENT_WORKERS = 4
ZSTD_LEVEL = 10
PRIMARY_OPERATOR = "hybrid_proof_top16_equal"
PROSPECTIVE_OPERATOR = "hybrid_proof_top4_equal"
PROOF_OPERATORS = (
    "proof_best_single",
    "proof_borda_top4",
    "proof_borda_top8",
    "proof_borda_top16",
    "proof_borda_top32",
    "proof_reciprocal_top8",
    "proof_vote_top16",
    "hybrid_proof_top4_base2",
    "hybrid_proof_top4_equal",
    "hybrid_proof_top8_base2",
    "hybrid_proof_top8_equal",
    "hybrid_proof_top8_proof2",
    "hybrid_proof_top16_equal",
    "hybrid_reciprocal_top8_equal",
)
ALL_OPERATORS = ("borda_sum_baseline", *PROOF_OPERATORS)
MATERIAL_SPEARMAN_MAX = 0.98
MATERIAL_TOP65536_OVERLAP_MAX = 0.90
DOTCAUSAL_SRC = Path("/Users/bhkmie/Documents/Forschung/O1/vendor/fabel/dotcausal_package/src")


def load_module(path: Path, name: str) -> Any:
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot import A449 dependency {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


A448 = load_module(A448_RUNNER, "a449_a448")
A442 = load_module(A442_RUNNER, "a449_a442")
A439 = load_module(A439_RUNNER, "a449_a439")
A445 = A448.A447.A445
file_sha256 = A448.file_sha256
canonical_sha256 = A448.canonical_sha256
atomic_json = A448.atomic_json
atomic_bytes = A448.A447.atomic_bytes
relative = A448.relative
path_from_ref = A448.path_from_ref
anchor = A448.anchor
exact_order = A442.exact_order
order_to_ranks = A442.order_to_ranks


def canonical_bytes(value: Any) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("ascii")


def array_sha256(value: np.ndarray, dtype: str) -> str:
    return hashlib.sha256(np.asarray(value, dtype=dtype).tobytes()).hexdigest()


def load_design() -> dict[str, Any]:
    if file_sha256(DESIGN) != DESIGN_SHA256:
        raise RuntimeError("A449 design hash differs")
    value = json.loads(DESIGN.read_bytes())
    measurement = value.get("measurement_contract", {})
    reader = value.get("proof_reader_contract", {})
    transfer = value.get("transfer_contract", {})
    boundary = value.get("information_boundary", {})
    if (
        value.get("schema")
        != "chacha20-round20-w52-target-blind-proof-antecedent-trace-a449-design-v1"
        or value.get("attempt_id") != ATTEMPT_ID
        or measurement.get("total_slices") != len(AXES) * len(SLICES)
        or measurement.get("cells_per_slice") != CELLS
        or measurement.get("complete_axis_cells") != AXIS_CELLS
        or measurement.get("complete_pair_cells") != PAIR_CELLS
        or tuple(measurement.get("conflict_horizons", [])) != HORIZONS
        or measurement.get("complete_solver_stages") != len(AXES) * len(SLICES) * CELLS * len(HORIZONS)
        or measurement.get("measurement_workers") != MEASUREMENT_WORKERS
        or measurement.get("target_label_available_to_helper") is not False
        or reader.get("source_model_sha256")
        != "53a5b75a75a79e64c56482279868ecc3a400dbf0f0763b33b7d1655eadc35b06"
        or reader.get("source_feature_order_sha256")
        != "1d2cd257479bf5a492b80dbb37757da9830603061861a9232f3c9ee375042ae6"
        or reader.get("fixed_primary_operator") != PRIMARY_OPERATOR
        or reader.get("fixed_prospective_transfer_operator") != PROSPECTIVE_OPERATOR
        or tuple(reader.get("complete128_eligible_operator_order", [])) != PROOF_OPERATORS
        or reader.get("feature_refits_on_W52") != 0
        or reader.get("model_refits_on_W52") != 0
        or transfer.get("retain_A442_as_immutable_baseline_arm") is not True
        or transfer.get("W52_target_labels_used") != 0
        or transfer.get("W52_feature_refits") != 0
        or transfer.get("W52_model_refits") != 0
        or transfer.get("production_candidate_assignments_executed") != 0
        or boundary.get("A449_W52_proof_measurements_seen_before_design_freeze") != 0
        or boundary.get("A449_W52_orders_or_pair_metrics_seen_before_design_freeze") is not False
        or boundary.get("A426_A438_A440_A443_secret_result_stop_or_worker_progress_read") is not False
    ):
        raise RuntimeError("A449 frozen design semantics differ")
    for key, item in value["source_anchors"].items():
        if key.endswith("_path"):
            stem = key.removesuffix("_path")
            anchor(ROOT / item, value["source_anchors"][f"{stem}_sha256"])
    return value


def load_sources() -> dict[str, Any]:
    anchor(A448_RESULT, A448_RESULT_SHA256)
    anchor(A448_CAUSAL, A448_CAUSAL_SHA256)
    anchor(A448_READBACK, A448_READBACK_SHA256)
    anchor(A442_RESULT, A442_RESULT_SHA256)
    anchor(A439_RESULT, A439_RESULT_SHA256)
    anchor(A432_PREFLIGHT, A432_PREFLIGHT_SHA256)
    anchor(A432_RESULT, A432_RESULT_SHA256)
    anchor(A433_PREFLIGHT, A433_PREFLIGHT_SHA256)
    anchor(A433_RESULT, A433_RESULT_SHA256)
    a448 = A448.load_result(A448_RESULT_SHA256)
    a442 = json.loads(A442_RESULT.read_bytes())
    a439 = json.loads(A439_RESULT.read_bytes())
    p432 = json.loads(A432_PREFLIGHT.read_bytes())
    p433 = json.loads(A433_PREFLIGHT.read_bytes())
    _a375, a432, a433, _a436 = A439.load_source_metadata()
    if (
        a448.get("W52_proof_trace_ready") is not True
        or a448.get("final_complete128_model_sha256")
        != a448.get("final_complete128_model", {}).get("model_sha256")
        or a448.get("portfolio_decision", {}).get("portfolio_operator") != PRIMARY_OPERATOR
        or tuple(a448.get("portfolio_decision", {}).get("complete128_proof_eligible_operators", []))
        != PROOF_OPERATORS
        or a442.get("schema") != "chacha20-round20-w52-knownkey-meta-reader-transfer-a442-v1"
        or len(a442.get("prefix_order", [])) != AXIS_CELLS
        or len(a442.get("off_axis_order", [])) != AXIS_CELLS
        or a442.get("target_labels_used_for_W52") != 0
        or a442.get("reader_refits_on_W52") != 0
        or a442.get("candidate_assignments_executed") != 0
        or p432.get("schema")
        != "chacha20-round20-w52-public-output-direct12-eight-worker-a432-preflight-v1"
        or p433.get("schema")
        != "chacha20-round20-w52-prefix-aligned-direct12-eight-worker-a433-preflight-v2"
        or len(p432.get("synthetic_reader_mapping", [])) != 20
        or len(p433.get("synthetic_reader_mapping", [])) != 20
    ):
        raise RuntimeError("A449 source semantics differ")
    exact_order(a442["prefix_order"], AXIS_CELLS)
    exact_order(a442["off_axis_order"], AXIS_CELLS)
    return {
        "a448": a448,
        "a442": a442,
        "a439": a439,
        "p432": p432,
        "p433": p433,
        "a432": a432,
        "a433": a433,
    }


def source_manifest(sources: Mapping[str, Any] | None = None) -> list[dict[str, Any]]:
    values = dict(sources or load_sources())
    source_measurements = {
        "prefix": A439.load_axis_measurements(values["a433"], A439.A433, "prefix"),
        "off_axis": A439.load_axis_measurements(values["a432"], A439.A432, "off_axis"),
    }
    specs = {
        "prefix": (values["p433"], values["a433"], A433_ARTIFACTS),
        "off_axis": (values["p432"], values["a432"], A432_ARTIFACTS),
    }
    rows: list[dict[str, Any]] = []
    target_index = 0
    for axis in AXES:
        preflight, source_result, artifact_dir = specs[axis]
        mapping = [int(item) for item in preflight["synthetic_reader_mapping"]]
        mapping_hash = canonical_sha256(mapping)
        if (
            mapping_hash != preflight["synthetic_reader_mapping_sha256"]
            or len({abs(item) for item in mapping}) != 20
        ):
            raise RuntimeError(f"A449 {axis} mapping differs")
        ledgers = {int(row["low4"]): row for row in source_result["measurement_ledger"]}
        for low4 in SLICES:
            cnf = artifact_dir / f"slice_{low4:02x}.cnf"
            source_measurement = source_measurements[axis][low4]
            cnf_hash = file_sha256(cnf)
            if (
                cnf_hash != source_measurement.get("cnf_sha256")
                or source_measurement.get("target_label_available_to_measurement") is not False
                or source_measurement.get("complete_candidate_cover") is not True
            ):
                raise RuntimeError(f"A449 {axis} source slice differs: {low4}")
            ledger = ledgers[low4]
            rows.append(
                {
                    "target_index": target_index,
                    "axis": axis,
                    "low4": low4,
                    "slice_CNF_path": relative(cnf),
                    "slice_CNF_sha256": cnf_hash,
                    "reader_mapping": mapping,
                    "reader_mapping_sha256": mapping_hash,
                    "source_measurement_path": str(ledger["path"]),
                    "source_measurement_compressed_sha256": str(ledger["compressed_sha256"]),
                    "source_measurement_raw_sha256": str(ledger["raw_sha256"]),
                    "target_label_available": False,
                }
            )
            target_index += 1
    if (
        len(rows) != len(AXES) * len(SLICES)
        or [row["target_index"] for row in rows] != list(range(len(rows)))
        or any(sum(row["axis"] == axis for row in rows) != len(SLICES) for axis in AXES)
    ):
        raise RuntimeError("A449 source manifest cover differs")
    return rows


def measurement_path(axis: str, low4: int) -> Path:
    if axis not in AXES or low4 not in SLICES:
        raise ValueError("A449 measurement identity differs")
    return MEASUREMENTS / f"{axis}_slice_{low4:02x}.json.zst"


def measurement_ledger(path: Path, value: Mapping[str, Any], *, compressed: bytes | None = None, raw: bytes | None = None) -> dict[str, Any]:
    packed = path.read_bytes() if compressed is None else compressed
    unpacked = canonical_bytes(value) if raw is None else raw
    return {
        "target_index": int(value["target_index"]),
        "axis": str(value["axis"]),
        "low4": int(value["low4"]),
        "path": relative(path),
        "compressed_sha256": hashlib.sha256(packed).hexdigest(),
        "compressed_bytes": len(packed),
        "raw_sha256": hashlib.sha256(unpacked).hexdigest(),
        "raw_bytes": len(unpacked),
    }


def validate_measurement(value: Mapping[str, Any], job: Mapping[str, Any], implementation_sha256: str) -> None:
    run = value.get("run", {})
    if (
        value.get("schema") != "chacha20-round20-w52-target-blind-proof-antecedent-trace-a449-shard-v1"
        or value.get("attempt_id") != ATTEMPT_ID
        or value.get("design_sha256") != DESIGN_SHA256
        or value.get("implementation_sha256") != implementation_sha256
        or value.get("target_index") != job["target_index"]
        or value.get("axis") != job["axis"]
        or value.get("low4") != job["low4"]
        or value.get("slice_CNF_sha256") != job["slice_CNF_sha256"]
        or value.get("reader_mapping_sha256") != job["reader_mapping_sha256"]
        or value.get("target_label_available_to_helper") is not False
        or value.get("complete_candidate_cover") is not True
        or len(run.get("cells", [])) != CELLS
        or len(run.get("stages", [])) != CELLS * len(HORIZONS)
        or run.get("proof_missing_antecedent_total") != 0
        or run.get("all_watchdogs_clear") is not True
    ):
        raise RuntimeError(f"A449 measurement gate failed: {job['axis']} {job['low4']}")


def write_measurement(path: Path, value: Mapping[str, Any]) -> dict[str, Any]:
    raw = canonical_bytes(value)
    compressed = zstandard.ZstdCompressor(level=ZSTD_LEVEL).compress(raw)
    atomic_bytes(path, compressed)
    return measurement_ledger(path, value, compressed=compressed, raw=raw)


def read_measurement(path: Path, job: Mapping[str, Any], implementation_sha256: str, ledger: Mapping[str, Any] | None = None) -> dict[str, Any]:
    compressed = path.read_bytes()
    if ledger is not None and hashlib.sha256(compressed).hexdigest() != ledger["compressed_sha256"]:
        raise RuntimeError(f"A449 compressed measurement differs: {path.name}")
    raw = zstandard.ZstdDecompressor().decompress(compressed)
    if ledger is not None and hashlib.sha256(raw).hexdigest() != ledger["raw_sha256"]:
        raise RuntimeError(f"A449 raw measurement differs: {path.name}")
    value = json.loads(raw)
    if canonical_bytes(value) != raw:
        raise RuntimeError(f"A449 measurement is not canonical: {path.name}")
    validate_measurement(value, job, implementation_sha256)
    return value


def freeze_implementation() -> dict[str, Any]:
    if any(path.exists() for path in (IMPLEMENTATION, RESULT, CAUSAL, REPORT, MEASUREMENTS)):
        raise FileExistsError("A449 implementation or result already exists")
    load_design()
    sources = load_sources()
    manifest = source_manifest(sources)
    a448_implementation = A448.load_implementation(A448_IMPLEMENTATION_SHA256)
    helper = path_from_ref(a448_implementation["helper_path"])
    anchor(helper, a448_implementation["helper_sha256"])
    if not TEST.exists() or not REPRO.exists():
        raise FileNotFoundError("A449 tests and reproducer must precede implementation freeze")
    payload: dict[str, Any] = {
        "schema": "chacha20-round20-w52-target-blind-proof-antecedent-trace-a449-implementation-v1",
        "attempt_id": ATTEMPT_ID,
        "commitment_state": "complete_W52_proof_measurement_operator_portfolio_pair_geometry_and_authentic_Causal_code_frozen_before_any_A449_measurement_order_or_candidate_execution",
        "design_sha256": DESIGN_SHA256,
        "helper_path": relative(helper),
        "helper_sha256": a448_implementation["helper_sha256"],
        "source_manifest_sha256": canonical_sha256(manifest),
        "source_manifest": manifest,
        "proof_operator_order": list(PROOF_OPERATORS),
        "primary_operator": PRIMARY_OPERATOR,
        "prospective_operator": PROSPECTIVE_OPERATOR,
        "A449_measurements_available_at_freeze": 0,
        "A449_orders_or_pair_metrics_available_at_freeze": False,
        "A426_A438_A440_A443_secret_result_stop_or_worker_progress_read": False,
        "W52_target_labels_used": 0,
        "W52_feature_refits": 0,
        "W52_model_refits": 0,
        "production_candidate_assignments_executed": 0,
        "anchors": {
            "design": anchor(DESIGN, DESIGN_SHA256),
            "A448_runner": anchor(A448_RUNNER, A448_RUNNER_SHA256),
            "A448_implementation": anchor(A448_IMPLEMENTATION, A448_IMPLEMENTATION_SHA256),
            "A448_result": anchor(A448_RESULT, A448_RESULT_SHA256),
            "A448_causal": anchor(A448_CAUSAL, A448_CAUSAL_SHA256),
            "A448_personal_readback": anchor(A448_READBACK, A448_READBACK_SHA256),
            "A442_result": anchor(A442_RESULT, A442_RESULT_SHA256),
            "A439_runner": anchor(A439_RUNNER, A439_RUNNER_SHA256),
            "A439_result": anchor(A439_RESULT, A439_RESULT_SHA256),
            "A432_preflight": anchor(A432_PREFLIGHT, A432_PREFLIGHT_SHA256),
            "A432_result": anchor(A432_RESULT, A432_RESULT_SHA256),
            "A433_preflight": anchor(A433_PREFLIGHT, A433_PREFLIGHT_SHA256),
            "A433_result": anchor(A433_RESULT, A433_RESULT_SHA256),
            "helper": anchor(helper, a448_implementation["helper_sha256"]),
            "runner": anchor(Path(__file__)),
            "test": anchor(TEST),
            "reproducer": anchor(REPRO),
        },
    }
    payload["implementation_commitment_sha256"] = canonical_sha256(payload)
    atomic_json(IMPLEMENTATION, payload)
    return payload


def load_implementation(expected_sha256: str) -> dict[str, Any]:
    if file_sha256(IMPLEMENTATION) != expected_sha256:
        raise RuntimeError("A449 implementation hash differs")
    value = json.loads(IMPLEMENTATION.read_bytes())
    if (
        value.get("schema")
        != "chacha20-round20-w52-target-blind-proof-antecedent-trace-a449-implementation-v1"
        or value.get("attempt_id") != ATTEMPT_ID
        or value.get("design_sha256") != DESIGN_SHA256
        or tuple(value.get("proof_operator_order", [])) != PROOF_OPERATORS
        or value.get("primary_operator") != PRIMARY_OPERATOR
        or value.get("prospective_operator") != PROSPECTIVE_OPERATOR
        or value.get("A449_measurements_available_at_freeze") != 0
        or value.get("A449_orders_or_pair_metrics_available_at_freeze") is not False
        or value.get("A426_A438_A440_A443_secret_result_stop_or_worker_progress_read") is not False
        or value.get("W52_target_labels_used") != 0
        or value.get("W52_feature_refits") != 0
        or value.get("W52_model_refits") != 0
        or value.get("production_candidate_assignments_executed") != 0
    ):
        raise RuntimeError("A449 implementation semantics differ")
    for row in value["anchors"].values():
        anchor(path_from_ref(row["path"]), row["sha256"])
    if canonical_sha256(value["source_manifest"]) != value["source_manifest_sha256"]:
        raise RuntimeError("A449 manifest commitment differs")
    unsigned = {key: item for key, item in value.items() if key != "implementation_commitment_sha256"}
    if value.get("implementation_commitment_sha256") != canonical_sha256(unsigned):
        raise RuntimeError("A449 implementation commitment differs")
    return value


def run_slice(job: Mapping[str, Any], helper: Path, implementation_sha256: str) -> dict[str, Any]:
    path = measurement_path(str(job["axis"]), int(job["low4"]))
    if path.exists():
        value = read_measurement(path, job, implementation_sha256)
        return measurement_ledger(path, value)
    started = time.perf_counter()
    run = A448.A447.WRAPPER.run_fresh_clause_antecedents(
        helper=helper,
        cnf=path_from_ref(str(job["slice_CNF_path"])),
        mode=f"A449_W52_{job['axis']}_low4_{int(job['low4']):02x}",
        order=[f"{value:08b}" for value in range(CELLS)],
        key_one_literals_bit0_through_bit19=job["reader_mapping"],
        conflict_horizons=HORIZONS,
        watchdog_seconds=WATCHDOG_SECONDS,
        external_timeout_seconds=1200.0,
    )
    stable = {key: value for key, value in run.items() if key not in {"command", "process_elapsed_seconds"}}
    value = {
        "schema": "chacha20-round20-w52-target-blind-proof-antecedent-trace-a449-shard-v1",
        "attempt_id": ATTEMPT_ID,
        "design_sha256": DESIGN_SHA256,
        "implementation_sha256": implementation_sha256,
        "target_index": int(job["target_index"]),
        "axis": str(job["axis"]),
        "low4": int(job["low4"]),
        "slice_CNF_sha256": str(job["slice_CNF_sha256"]),
        "reader_mapping_sha256": str(job["reader_mapping_sha256"]),
        "run": stable,
        "complete_candidate_cover": len(stable.get("cells", [])) == CELLS,
        "candidate_order": "numeric_0_through_255",
        "target_label_available_to_helper": False,
        "target_label_used_for_order_or_early_stop": False,
        "A426_A438_A440_A443_secret_result_stop_or_worker_progress_read": False,
        "volatile_process_elapsed_seconds": time.perf_counter() - started,
    }
    validate_measurement(value, job, implementation_sha256)
    return write_measurement(path, value)


def measure(*, expected_implementation_sha256: str) -> dict[str, Any]:
    implementation = load_implementation(expected_implementation_sha256)
    jobs = implementation["source_manifest"]
    if len(jobs) != len(AXES) * len(SLICES):
        raise RuntimeError("A449 measurement job cover differs")
    helper = path_from_ref(implementation["helper_path"])
    A448.A447.WRAPPER._load_identity_wrapper()  # noqa: SLF001
    MEASUREMENTS.mkdir(parents=True, exist_ok=True)
    ledgers: list[dict[str, Any]] = []
    started = time.perf_counter()
    with concurrent.futures.ThreadPoolExecutor(max_workers=MEASUREMENT_WORKERS) as pool:
        futures = {
            pool.submit(run_slice, job, helper, expected_implementation_sha256): int(job["target_index"])
            for job in jobs
        }
        for future in concurrent.futures.as_completed(futures):
            ledger = future.result()
            ledgers.append(ledger)
            print(
                json.dumps(
                    {
                        "A449_slice_complete": f"{ledger['axis']}:{int(ledger['low4']):02x}",
                        "completed": len(ledgers),
                        "total": len(jobs),
                    },
                    sort_keys=True,
                ),
                flush=True,
            )
    ledgers.sort(key=lambda row: int(row["target_index"]))
    if [row["target_index"] for row in ledgers] != list(range(len(jobs))):
        raise RuntimeError("A449 measurement ledger cover differs")
    return {
        "attempt_id": ATTEMPT_ID,
        "implementation_sha256": expected_implementation_sha256,
        "measurement_ledger": ledgers,
        "measurement_cover_sha256": canonical_sha256(ledgers),
        "elapsed_seconds": time.perf_counter() - started,
    }


def load_measurements(implementation: Mapping[str, Any], expected_sha256: str) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    measurements: list[dict[str, Any]] = []
    ledgers: list[dict[str, Any]] = []
    for job in implementation["source_manifest"]:
        path = measurement_path(str(job["axis"]), int(job["low4"]))
        if not path.exists():
            raise FileNotFoundError(f"A449 measurement missing: {path.name}")
        value = read_measurement(path, job, expected_sha256)
        measurements.append(value)
        ledgers.append(measurement_ledger(path, value))
    return measurements, ledgers


def baseline_ranks(a439: Mapping[str, Any], axis: str, low4: int) -> np.ndarray:
    ranks = np.asarray(A445._slice_borda_ranks(a439, axis, low4, A442), dtype=np.int64)  # noqa: SLF001
    if ranks.shape != (CELLS,) or set(ranks.tolist()) != set(range(1, CELLS + 1)):
        raise RuntimeError(f"A449 {axis} baseline ranks differ: {low4}")
    return ranks


def build_slice_orders(
    measurement: Mapping[str, Any],
    baseline: np.ndarray,
    feature_order: np.ndarray,
    a448: Mapping[str, Any],
) -> tuple[dict[str, list[int]], dict[str, Any]]:
    matrix, names = A448.A447.PROOF_FEATURES.extract_proof_feature_matrix(measurement)
    normalized = A448.A447.PROOF_FEATURES.target_normalize(matrix)
    ranks, _generic = A448.A447.PROOF_FEATURES.exact_directional_rank_fields(normalized, baseline)
    directional_names = A448.A447.PROOF_FEATURES.directional_feature_names(names)
    contract = a448["feature_contract"]
    if (
        list(names) != contract["base_feature_names"]
        or len(directional_names) != a448["final_complete128_model"]["feature_count"]
        or canonical_sha256(directional_names) != contract["directional_feature_names_sha256"]
        or ranks.shape != (len(directional_names), CELLS)
    ):
        raise RuntimeError("A449 A448 feature ledger differs")
    orders = {
        operator: A448.A447.operator_order(ranks, baseline, feature_order, operator).tolist()
        for operator in ALL_OPERATORS
    }
    if any(set(order) != set(range(CELLS)) for order in orders.values()):
        raise RuntimeError("A449 within-slice order differs")
    return orders, {
        "matrix_sha256": array_sha256(matrix, "<f8"),
        "normalized_sha256": array_sha256(normalized, "<f8"),
        "directional_rank_sha256": array_sha256(ranks, "<i2"),
        "base_features": int(matrix.shape[1]),
        "directional_rank_fields": int(ranks.shape[0]),
        "proof_nodes": int(measurement["run"]["summary"]["proof_derived_total"]),
        "proof_antecedent_edges": int(measurement["run"]["summary"]["proof_antecedent_total"]),
        "missing_antecedents": int(measurement["run"]["summary"]["proof_missing_antecedent_total"]),
    }


def compose_axis(within_orders: Mapping[int, Sequence[int]]) -> np.ndarray:
    order = np.asarray(A439.A376.A361.compose_round_robin(within_orders), dtype=np.int64)
    return exact_order(order, AXIS_CELLS)


def calibration_summary(a448: Mapping[str, Any], operator: str) -> dict[str, Any]:
    row = a448["complete128_crossfit_evaluations"][operator]
    return {
        "positive_fixed_block_count": int(row["positive_fixed_block_count"]),
        "minimum_fixed_block_bit_gain": float(row["minimum_fixed_block_bit_gain"]),
        "balanced_eight_block_bit_gain": float(row["balanced_eight_block_bit_gain"]),
        "aggregate_bit_gain": float(row["aggregate_bit_gain"]),
        "rank_field_sha256": str(row["rank_field_sha256"]),
    }


def pair_is_material(comparison: Mapping[str, Any]) -> tuple[bool, float]:
    overlap = int(comparison["top_k_overlap"]["65536"]["intersection"])
    fraction = overlap / 65536.0
    material = (
        float(comparison["spearman_rank_correlation"]) < MATERIAL_SPEARMAN_MAX
        or fraction <= MATERIAL_TOP65536_OVERLAP_MAX
    )
    return material, fraction


def orthogonal_selection_key(row: Mapping[str, Any]) -> tuple[float | int, ...]:
    return (
        0 if row["material_pair_diversity_vs_A442"] else 1,
        float(row["top65536_overlap_fraction_vs_A442"]),
        float(row["pair_comparison_to_A442"]["spearman_rank_correlation"]),
        -float(row["A448_calibration"]["minimum_fixed_block_bit_gain"]),
        PROOF_OPERATORS.index(str(row["operator"])),
    )


def build_causal(payload: Mapping[str, Any]) -> dict[str, Any]:
    if str(DOTCAUSAL_SRC) not in sys.path:
        sys.path.insert(0, str(DOTCAUSAL_SRC))
    from dotcausal.io import CausalReader, CausalWriter

    ready = bool(payload["recovery_ready"])
    terminal = "A449:target_blind_W52_proof_recovery_ready" if ready else "A449:W52_proof_pair_geometry_boundary"
    writer = CausalWriter(api_id="a449w52")
    writer._rules = []
    writer.add_rule(
        name="complete128_model_to_W52_trace",
        description="Apply A448's immutable complete128 proof model to every cell of both complete W52 axes.",
        pattern=["A448_target_blind_W52_proof_trace_ready"],
        conclusion="A449_complete_W52_proof_antecedent_corpus",
        confidence_modifier=1.0,
    )
    writer.add_rule(
        name="proof_trace_to_operator_portfolio",
        description="Read all fourteen prequalified proof operators without labels or refits and compose exact axis schedules.",
        pattern=["A449_complete_W52_proof_antecedent_corpus"],
        conclusion="A449_complete_W52_proof_operator_portfolio",
        confidence_modifier=1.0,
    )
    writer.add_rule(
        name="axis_portfolio_to_pair_geometry",
        description="Compose exact square-wavefront pair streams and compare every stream with immutable A442.",
        pattern=["A449_complete_W52_proof_operator_portfolio"],
        conclusion="A449_target_blind_pair_geometry",
        confidence_modifier=1.0,
    )
    writer.add_rule(
        name="pair_geometry_to_execution_gate",
        description="Open a recovery arm only when the primary or target-blind orthogonal schedule is materially distinct from A442.",
        pattern=["A449_target_blind_pair_geometry"],
        conclusion=terminal.replace(":", "_"),
        confidence_modifier=1.0,
    )
    concise_decision = {
        "primary_operator": payload["primary_operator"],
        "primary_material": payload["primary_schedule"]["material_pair_diversity_vs_A442"],
        "orthogonal_operator": payload["orthogonal_operator"],
        "orthogonal_material": payload["orthogonal_schedule"]["material_pair_diversity_vs_A442"],
        "recovery_operator": payload["recovery_operator"],
        "recovery_ready": ready,
    }
    triplets = [
        (
            "A448:target_blind_W52_proof_trace_ready",
            "exact_solver_native_antecedent_trace_over_both_complete_W52_axes",
            "A449:complete_W52_proof_antecedent_corpus",
            payload["measurement_cover_sha256"],
            payload["measurement_summary"],
        ),
        (
            "A449:complete_W52_proof_antecedent_corpus",
            "frozen_complete128_feature_order_and_fourteen_operator_readout",
            "A449:complete_W52_proof_operator_portfolio",
            payload["operator_portfolio_sha256"],
            payload["operator_summary"],
        ),
        (
            "A449:complete_W52_proof_operator_portfolio",
            "exact_dual_axis_round_robin_and_square_wavefront_composition",
            "A449:target_blind_pair_geometry",
            payload["pair_geometry_sha256"],
            concise_decision,
        ),
        (
            "A449:target_blind_pair_geometry",
            "predeclared_material_diversity_execution_gate",
            terminal,
            payload["decision_sha256"],
            concise_decision,
        ),
    ]
    for trigger, mechanism, outcome, evidence, quantification in triplets:
        writer.add_triplet(
            trigger=trigger,
            mechanism=mechanism,
            outcome=outcome,
            confidence=1.0,
            source=str(evidence),
            quantification=json.dumps(quantification, sort_keys=True),
            evidence=str(evidence),
            domain="target-blind full-round ChaCha20 W52 proof-antecedent ordering",
            quality_score=1.0,
        )
    writer.add_triplet(
        trigger="A448:target_blind_W52_proof_trace_ready",
        mechanism="materialized_W52_proof_transfer_decision_closure",
        outcome=terminal,
        confidence=1.0,
        source="materialized:A449_W52_proof_chain",
        quantification="exact retained closure",
        evidence=payload["evidence_stage"],
        domain="AI-native retained inference",
        quality_score=1.0,
        is_inferred=True,
    )
    writer.add_cluster(
        name="A449 target-blind W52 proof trace",
        entities=[
            "A448:target_blind_W52_proof_trace_ready",
            "A449:complete_W52_proof_antecedent_corpus",
            "A449:complete_W52_proof_operator_portfolio",
            "A449:target_blind_pair_geometry",
            terminal,
        ],
    )
    writer.add_gap(
        subject=terminal,
        predicate="next_required_object",
        expected_object_type=(
            "qualified_W52_proof_portfolio_recovery_execution"
            if ready
            else "joint_axis_proof_trajectory_or_pair_causal_composition"
        ),
        confidence=1.0,
        suggested_queries=[
            "Execute the selected proof-derived W52 pair schedule under the existing challenge and stopping contract without replacing A442."
            if ready
            else "Construct a joint-axis proof trajectory from the retained exact W52 corpus rather than another scalar reweighting."
        ],
    )
    temporary = CAUSAL.with_name(f".{CAUSAL.name}.{os.getpid()}.tmp")
    temporary.unlink(missing_ok=True)
    stats = writer.save(str(temporary))
    os.replace(temporary, CAUSAL)
    reader = CausalReader(str(CAUSAL), verify_integrity=True)
    explicit = reader.get_all_triplets(include_inferred=False)
    all_rows = reader.get_all_triplets(include_inferred=True)
    inferred = [row for row in reader._triplets if row.get("is_inferred", False)]
    if (
        reader.api_id != "a449w52"
        or len(explicit) != 4
        or len(all_rows) != 5
        or len(inferred) != 1
        or len(reader._rules) != 4
        or len(reader._clusters) != 1
        or len(reader._gaps) != 1
    ):
        raise RuntimeError("A449 authentic Causal reopen gate failed")
    return {
        "format": "authentic_dotcausal_v1_AI_native",
        "path": relative(CAUSAL),
        "sha256": file_sha256(CAUSAL),
        "api_id": reader.api_id,
        "explicit_triplets": len(explicit),
        "materialized_inferred_triplets": len(inferred),
        "embedded_rules": len(reader._rules),
        "clusters": len(reader._clusters),
        "gaps": len(reader._gaps),
        "reader_source": anchor(Path(inspect.getsourcefile(CausalReader) or "")),
        "writer_stats": stats,
        "reader_gate_readback": {
            "measurement": explicit[0],
            "portfolio": explicit[1],
            "pair_geometry": explicit[2],
            "decision": explicit[3],
            "terminal_chain": all_rows[-1],
            "next_gap": reader._gaps[0],
        },
    }


def _build_result_once(*, expected_implementation_sha256: str) -> dict[str, Any]:
    load_design()
    implementation = load_implementation(expected_implementation_sha256)
    sources = load_sources()
    measurements, ledgers = load_measurements(implementation, expected_implementation_sha256)
    a448 = sources["a448"]
    a442 = sources["a442"]
    a439 = sources["a439"]
    model = a448["final_complete128_model"]
    feature_order = np.asarray(model["complete_feature_order"], dtype=np.int64)
    if (
        model.get("model_sha256") != "53a5b75a75a79e64c56482279868ecc3a400dbf0f0763b33b7d1655eadc35b06"
        or array_sha256(feature_order, ">u4") != model["feature_order_sha256"]
        or model.get("portfolio_operator") != PRIMARY_OPERATOR
        or feature_order.shape != (3051,)
        or set(feature_order.tolist()) != set(range(3051))
    ):
        raise RuntimeError("A449 frozen A448 model differs")

    by_identity = {(str(value["axis"]), int(value["low4"])): value for value in measurements}
    within_orders: dict[str, dict[str, dict[int, list[int]]]] = {
        operator: {axis: {} for axis in AXES} for operator in ALL_OPERATORS
    }
    slice_features: dict[str, dict[str, Any]] = {}
    for axis in AXES:
        for low4 in SLICES:
            measurement = by_identity[(axis, low4)]
            baseline = baseline_ranks(a439, axis, low4)
            orders, feature_row = build_slice_orders(measurement, baseline, feature_order, a448)
            slice_features[f"{axis}:{low4:02x}"] = feature_row
            for operator in ALL_OPERATORS:
                within_orders[operator][axis][low4] = orders[operator]

    schedules: dict[str, dict[str, Any]] = {}
    baseline_pair_rank = A442.reference_square_rank_vector(a442["prefix_order"], a442["off_axis_order"])
    baseline_pair_hash = A442.pair_stream_sha256(a442["prefix_order"], a442["off_axis_order"])
    if baseline_pair_hash != a442["pair_stream_uint16be_uint16be_sha256"]:
        raise RuntimeError("A449 A442 pair baseline differs")
    for operator in ALL_OPERATORS:
        if operator == "borda_sum_baseline":
            prefix = exact_order(a442["prefix_order"], AXIS_CELLS)
            off_axis = exact_order(a442["off_axis_order"], AXIS_CELLS)
        else:
            prefix = compose_axis(within_orders[operator]["prefix"])
            off_axis = compose_axis(within_orders[operator]["off_axis"])
        pair_hash = A442.pair_stream_sha256(prefix, off_axis)
        pair_rank = A442.reference_square_rank_vector(prefix, off_axis)
        comparison = A442.compare_rank_orders(pair_rank, baseline_pair_rank)
        material, top_fraction = pair_is_material(comparison)
        calibration = (
            {
                "positive_fixed_block_count": 8,
                "minimum_fixed_block_bit_gain": 0.3287263877670634,
                "balanced_eight_block_bit_gain": 0.5963104313759133,
                "aggregate_bit_gain": 0.5963104313759127,
                "rank_field_sha256": "64cb6aad1f9621df5ff6ef44bb7e06cfc2dd86871483df83195382b2abf899b0",
            }
            if operator == "borda_sum_baseline"
            else calibration_summary(a448, operator)
        )
        schedules[operator] = {
            "operator": operator,
            "A448_calibration": calibration,
            "prefix_order": prefix.tolist(),
            "off_axis_order": off_axis.tolist(),
            "prefix_order_uint16be_sha256": A442.order_sha256(prefix),
            "off_axis_order_uint16be_sha256": A442.order_sha256(off_axis),
            "within_prefix_orders_sha256": canonical_sha256(within_orders[operator]["prefix"]),
            "within_off_axis_orders_sha256": canonical_sha256(within_orders[operator]["off_axis"]),
            "pair_stream_uint16be_uint16be_sha256": pair_hash,
            "prefix_comparison_to_A442": A442.axis_comparison(prefix, a442["prefix_order"]),
            "off_axis_comparison_to_A442": A442.axis_comparison(off_axis, a442["off_axis_order"]),
            "pair_comparison_to_A442": comparison,
            "top65536_overlap_fraction_vs_A442": top_fraction,
            "material_pair_diversity_vs_A442": material,
        }
        del pair_rank
        gc.collect()

    proof_rows = [schedules[operator] for operator in PROOF_OPERATORS]
    orthogonal = min(proof_rows, key=orthogonal_selection_key)
    primary = schedules[PRIMARY_OPERATOR]
    recovery_ready = bool(
        primary["material_pair_diversity_vs_A442"]
        or orthogonal["material_pair_diversity_vs_A442"]
    )
    recovery_operator = (
        str(orthogonal["operator"])
        if orthogonal["material_pair_diversity_vs_A442"]
        else PRIMARY_OPERATOR
    )
    proof_nodes = sum(int(row["proof_nodes"]) for row in slice_features.values())
    proof_edges = sum(int(row["proof_antecedent_edges"]) for row in slice_features.values())
    proof_missing = sum(int(row["missing_antecedents"]) for row in slice_features.values())
    if proof_missing != 0:
        raise RuntimeError("A449 proof antecedent cover differs")
    operator_summary = {
        operator: {
            "pair_stream_sha256": schedules[operator]["pair_stream_uint16be_uint16be_sha256"],
            "pair_spearman_vs_A442": schedules[operator]["pair_comparison_to_A442"]["spearman_rank_correlation"],
            "top65536_overlap_fraction_vs_A442": schedules[operator]["top65536_overlap_fraction_vs_A442"],
            "material_pair_diversity_vs_A442": schedules[operator]["material_pair_diversity_vs_A442"],
        }
        for operator in ALL_OPERATORS
    }
    core: dict[str, Any] = {
        "schema": "chacha20-round20-w52-target-blind-proof-antecedent-trace-a449-v1",
        "attempt_id": ATTEMPT_ID,
        "evidence_stage": (
            "TARGET_BLIND_W52_PROOF_ANTECEDENT_RECOVERY_ARM_READY"
            if recovery_ready
            else "COMPLETE_W52_PROOF_ANTECEDENT_PAIR_GEOMETRY_BOUNDARY"
        ),
        "design_sha256": DESIGN_SHA256,
        "implementation_sha256": expected_implementation_sha256,
        "implementation_commitment_sha256": implementation["implementation_commitment_sha256"],
        "measurement_ledger": ledgers,
        "measurement_summary": {
            "slices": len(measurements),
            "axis_cells": AXIS_CELLS,
            "cells": len(measurements) * CELLS,
            "solver_stages": len(measurements) * CELLS * len(HORIZONS),
            "proof_nodes": proof_nodes,
            "proof_antecedent_edges": proof_edges,
            "missing_antecedents": proof_missing,
        },
        "slice_feature_ledger": slice_features,
        "frozen_A448_model_sha256": model["model_sha256"],
        "frozen_A448_feature_order_sha256": model["feature_order_sha256"],
        "operator_schedules": schedules,
        "operator_summary": operator_summary,
        "primary_operator": PRIMARY_OPERATOR,
        "primary_schedule": primary,
        "prospective_operator": PROSPECTIVE_OPERATOR,
        "prospective_schedule": schedules[PROSPECTIVE_OPERATOR],
        "orthogonal_operator": str(orthogonal["operator"]),
        "orthogonal_schedule": orthogonal,
        "recovery_operator": recovery_operator,
        "recovery_schedule": schedules[recovery_operator],
        "recovery_ready": recovery_ready,
        "A442_pair_stream_reproduced": True,
        "A426_A438_A440_A443_secret_result_stop_or_worker_progress_read": False,
        "W52_target_labels_used": 0,
        "W52_feature_refits": 0,
        "W52_model_refits": 0,
        "production_candidate_assignments_executed": 0,
        "anchors": {
            "design": anchor(DESIGN, DESIGN_SHA256),
            "implementation": anchor(IMPLEMENTATION, expected_implementation_sha256),
            "A448_result": anchor(A448_RESULT, A448_RESULT_SHA256),
            "A448_causal": anchor(A448_CAUSAL, A448_CAUSAL_SHA256),
            "A448_personal_readback": anchor(A448_READBACK, A448_READBACK_SHA256),
            "A442_result": anchor(A442_RESULT, A442_RESULT_SHA256),
            "A439_result": anchor(A439_RESULT, A439_RESULT_SHA256),
            "runner": anchor(Path(__file__)),
        },
    }
    core["measurement_cover_sha256"] = canonical_sha256(ledgers)
    core["slice_feature_cover_sha256"] = canonical_sha256(slice_features)
    core["operator_portfolio_sha256"] = canonical_sha256(operator_summary)
    core["pair_geometry_sha256"] = canonical_sha256(
        {
            operator: {
                "prefix": schedules[operator]["prefix_order_uint16be_sha256"],
                "off_axis": schedules[operator]["off_axis_order_uint16be_sha256"],
                "pair": schedules[operator]["pair_stream_uint16be_uint16be_sha256"],
                "comparison": schedules[operator]["pair_comparison_to_A442"],
            }
            for operator in ALL_OPERATORS
        }
    )
    core["decision_sha256"] = canonical_sha256(
        {
            "primary_operator": PRIMARY_OPERATOR,
            "primary_material": primary["material_pair_diversity_vs_A442"],
            "orthogonal_operator": core["orthogonal_operator"],
            "orthogonal_material": orthogonal["material_pair_diversity_vs_A442"],
            "recovery_operator": recovery_operator,
            "recovery_ready": recovery_ready,
        }
    )
    core["result_commitment_sha256"] = canonical_sha256(
        {
            "implementation_commitment_sha256": core["implementation_commitment_sha256"],
            "measurement_cover_sha256": core["measurement_cover_sha256"],
            "slice_feature_cover_sha256": core["slice_feature_cover_sha256"],
            "operator_portfolio_sha256": core["operator_portfolio_sha256"],
            "pair_geometry_sha256": core["pair_geometry_sha256"],
            "decision_sha256": core["decision_sha256"],
            "W52_target_labels_used": 0,
            "W52_feature_refits": 0,
            "W52_model_refits": 0,
            "production_candidate_assignments_executed": 0,
        }
    )
    core["causal"] = build_causal(core)
    atomic_json(RESULT, core)
    report = (
        "# A449 — Target-blind W52 proof-antecedent trace\n\n"
        f"Evidence stage: **{core['evidence_stage']}**\n\n"
        f"- Exact proof nodes / edges: **{proof_nodes:,} / {proof_edges:,}**\n"
        f"- Missing antecedents: **{proof_missing}**\n"
        f"- Primary operator: **{PRIMARY_OPERATOR}**\n"
        f"- Primary pair Spearman / top-65,536 overlap versus A442: "
        f"**{primary['pair_comparison_to_A442']['spearman_rank_correlation']:.9f} / "
        f"{primary['top65536_overlap_fraction_vs_A442']:.9f}**\n"
        f"- Orthogonal operator: **{core['orthogonal_operator']}**\n"
        f"- Orthogonal pair Spearman / top-65,536 overlap versus A442: "
        f"**{orthogonal['pair_comparison_to_A442']['spearman_rank_correlation']:.9f} / "
        f"{orthogonal['top65536_overlap_fraction_vs_A442']:.9f}**\n"
        f"- Recovery arm ready / operator: **{recovery_ready} / {recovery_operator}**\n"
        "- W52 labels / feature refits / model refits / production candidate executions: **0 / 0 / 0 / 0**\n"
    )
    atomic_bytes(REPORT, report.encode("utf-8"))
    return core


def build_result(*, expected_implementation_sha256: str) -> dict[str, Any]:
    if RESULT.exists():
        return load_result(file_sha256(RESULT))
    try:
        return _build_result_once(expected_implementation_sha256=expected_implementation_sha256)
    except Exception:
        if not RESULT.exists():
            CAUSAL.unlink(missing_ok=True)
            REPORT.unlink(missing_ok=True)
        raise


def load_result(expected_sha256: str) -> dict[str, Any]:
    if file_sha256(RESULT) != expected_sha256:
        raise RuntimeError("A449 result hash differs")
    value = json.loads(RESULT.read_bytes())
    if (
        value.get("schema") != "chacha20-round20-w52-target-blind-proof-antecedent-trace-a449-v1"
        or value.get("attempt_id") != ATTEMPT_ID
        or value.get("primary_operator") != PRIMARY_OPERATOR
        or value.get("orthogonal_operator") not in PROOF_OPERATORS
        or value.get("recovery_operator") not in PROOF_OPERATORS
        or set(value.get("operator_schedules", {})) != set(ALL_OPERATORS)
        or value.get("A442_pair_stream_reproduced") is not True
        or value.get("A426_A438_A440_A443_secret_result_stop_or_worker_progress_read") is not False
        or value.get("W52_target_labels_used") != 0
        or value.get("W52_feature_refits") != 0
        or value.get("W52_model_refits") != 0
        or value.get("production_candidate_assignments_executed") != 0
    ):
        raise RuntimeError("A449 result semantics differ")
    for row in value["anchors"].values():
        anchor(path_from_ref(row["path"]), row["sha256"])
    for schedule in value["operator_schedules"].values():
        exact_order(schedule["prefix_order"], AXIS_CELLS)
        exact_order(schedule["off_axis_order"], AXIS_CELLS)
    return value


def analyze() -> dict[str, Any]:
    load_design()
    payload: dict[str, Any] = {
        "attempt_id": ATTEMPT_ID,
        "design_sha256": DESIGN_SHA256,
        "implementation_frozen": IMPLEMENTATION.exists(),
        "measurements_present": sum(
            measurement_path(axis, low4).exists() for axis in AXES for low4 in SLICES
        ),
        "measurements_complete": all(
            measurement_path(axis, low4).exists() for axis in AXES for low4 in SLICES
        ),
        "result_complete": RESULT.exists(),
    }
    if IMPLEMENTATION.exists():
        payload["implementation_sha256"] = file_sha256(IMPLEMENTATION)
        load_implementation(payload["implementation_sha256"])
    if RESULT.exists():
        payload["result_sha256"] = file_sha256(RESULT)
        result = load_result(payload["result_sha256"])
        payload["evidence_stage"] = result["evidence_stage"]
        payload["primary_operator"] = result["primary_operator"]
        payload["orthogonal_operator"] = result["orthogonal_operator"]
        payload["recovery_operator"] = result["recovery_operator"]
        payload["recovery_ready"] = result["recovery_ready"]
    return payload


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    action = parser.add_mutually_exclusive_group(required=True)
    action.add_argument("--freeze-implementation", action="store_true")
    action.add_argument("--measure", action="store_true")
    action.add_argument("--build-result", action="store_true")
    action.add_argument("--analyze", action="store_true")
    parser.add_argument("--expected-implementation-sha256")
    args = parser.parse_args()
    if args.freeze_implementation:
        payload = freeze_implementation()
    elif args.measure:
        if not args.expected_implementation_sha256:
            parser.error("--measure requires implementation hash")
        payload = measure(expected_implementation_sha256=args.expected_implementation_sha256)
    elif args.build_result:
        if not args.expected_implementation_sha256:
            parser.error("--build-result requires implementation hash")
        payload = build_result(expected_implementation_sha256=args.expected_implementation_sha256)
    else:
        payload = analyze()
    print(json.dumps(payload, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()

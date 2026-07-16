#!/usr/bin/env python3
"""A447: exact proof-antecedent DAG calibration across eight R20 blocks."""

from __future__ import annotations

import argparse
import concurrent.futures
import hashlib
import importlib.util
import inspect
import json
import math
import os
import sys
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

from arx_carry_leak import proof_antecedent_features as PROOF_FEATURES  # noqa: E402

RESEARCH = ROOT / "research"
CONFIGS = RESEARCH / "configs"
RESULTS = RESEARCH / "results/v1"
MEASUREMENTS = RESULTS / "chacha20_round20_w46_proof_antecedent_calibration_a447_v1"

DESIGN = CONFIGS / "chacha20_round20_w46_proof_antecedent_calibration_a447_design_v1.json"
IMPLEMENTATION = CONFIGS / "chacha20_round20_w46_proof_antecedent_calibration_a447_implementation_v1.json"
RESULT = RESULTS / "chacha20_round20_w46_proof_antecedent_calibration_a447_v1.json"
CAUSAL = RESULT.with_suffix(".causal")
REPORT = RESULT.with_suffix(".md")
TEST = ROOT / "tests/test_chacha20_round20_w46_proof_antecedent_calibration_a447.py"
WRAPPER_TEST = ROOT / "tests/test_chacha20_fresh_clause_antecedents.py"
FEATURE_TEST = ROOT / "tests/test_proof_antecedent_features.py"
REPRO = ROOT / "scripts/reproduce_chacha20_round20_w46_proof_antecedent_calibration_a447.sh"

WRAPPER_PATH = RESEARCH / "experiments/chacha20_fresh_clause_antecedents.py"
IDENTITY_WRAPPER_PATH = RESEARCH / "experiments/chacha20_fresh_clause_identity.py"
MULTIHORIZON_WRAPPER_PATH = RESEARCH / "experiments/chacha20_fresh_multihorizon.py"
FEATURE_SOURCE = SRC / "arx_carry_leak/proof_antecedent_features.py"
NATIVE_SOURCE = RESEARCH / "native/cadical_fresh_clause_antecedents.cpp"
TRACER_HEADER = RESEARCH / "native/cadical_tracer_v3.hpp"
A445_RUNNER = RESEARCH / "experiments/chacha20_round20_w52_crossfit_raw_shape_reader_transfer_a445.py"
A442_RESULT = RESULTS / "chacha20_round20_w52_knownkey_meta_reader_transfer_a442_v1.json"
A446_RESULT = RESULTS / "chacha20_round20_w52_assumption_cut_clause_provenance_reader_a446_v1.json"
A446_CAUSAL = A446_RESULT.with_suffix(".causal")
A446_READBACK = RESEARCH / "reports/CAUSAL_CHACHA20_A446_PERSONAL_READER_READBACK_V1.md"
A447_IMPORT_INCIDENT = RESEARCH / "reports/A447_PREMEASUREMENT_IMPORT_RACE_INCIDENT_V1.md"

PREPARED = {
    "A359": RESULTS / "chacha20_round20_w46_corrected_knownkey_slice_corpus_a359_prepared_v1.json",
    "A363": RESULTS / "chacha20_round20_w46_polarity_invariant_validation_a363_prepared_v1.json",
    "A367": RESULTS / "chacha20_round20_w46_cross_corpus_invariant_validation_a367_prepared_v1.json",
}
PREPARED_SHA256 = {
    "A359": "3e508df1af059116eba9d288cd55d3c34800ff8c9d9f6dc17f7989229df5372e",
    "A363": "a8d90a57a934c7c5e7a289dc17f2aa543310c3536c5b58e872c58e6a1d3d7561",
    "A367": "26c5870671f5ca2aedddb50b4f924531b06e37a9083e1588d2cbd0128f1abf6a",
}
SOURCE_SELECTION = {
    "A359": tuple(range(0, 32, 4)),
    "A363": tuple(range(0, 32, 4)),
    "A367": tuple(range(0, 64, 4)),
}
SOURCE_GLOBAL_OFFSETS = {"A359": 0, "A363": 32, "A367": 64}
SOURCE_BLOCK_OFFSETS = {"A359": 0, "A363": 2, "A367": 4}

ATTEMPT_ID = "A447"
DESIGN_SHA256 = "16563220720977e05857e7ae663d6c86d35b18cb47ba69eab1d3fdf7aa5a88bd"
A445_RUNNER_SHA256 = "b4a9bd42262e8d038ba3e1faf83f5af603dea9c7c48a7ec86e68b2de7846f074"
A442_RESULT_SHA256 = "8c8222528dc3ef12ffc0fbda513061b39243daade51a70a17f0bd89c65b53b1d"
A446_RESULT_SHA256 = "f8a1d9e787c472c0e8d497c74f94ea69b923cfab3b2aa89d41219602f31f94fe"
A446_CAUSAL_SHA256 = "5ce958b43165d374a52b973ac48ba47edab07c5e8cbc5948e9d6dd132ab89636"
A446_READBACK_SHA256 = "f68deeface14b7bab2d1e04ba7423e9d27d75b2afd10d32c7ef539f352d9a672"
A442_BORDA_FIELD_SHA256 = "64cb6aad1f9621df5ff6ef44bb7e06cfc2dd86871483df83195382b2abf899b0"

TARGETS = 32
CELLS = 256
BLOCKS = 8
BLOCK_SIZE = 4
HORIZONS = (1, 2, 4, 8)
WATCHDOG_SECONDS = 2.0
MEASUREMENT_WORKERS = 4
ZSTD_LEVEL = 10
VOTE_THRESHOLD = 64
DOTCAUSAL_SRC = Path("/Users/bhkmie/Documents/Forschung/O1/vendor/fabel/dotcausal_package/src")
OPERATORS = (
    "borda_sum_baseline",
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


def load_module(path: Path, name: str) -> Any:
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot import A447 dependency {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


WRAPPER = load_module(WRAPPER_PATH, "a447_fresh_antecedents")
A445 = load_module(A445_RUNNER, "a447_a445")
file_sha256 = A445.file_sha256
canonical_sha256 = A445.canonical_sha256
atomic_bytes = A445.atomic_bytes
atomic_json = A445.atomic_json
relative = A445.relative
path_from_ref = A445.path_from_ref
anchor = A445.anchor
exact_order = A445.exact_order
order_to_ranks = A445.order_to_ranks


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
        raise RuntimeError("A447 design hash differs")
    value = json.loads(DESIGN.read_bytes())
    calibration = value.get("calibration_contract", {})
    boundary = value.get("information_boundary", {})
    if (
        value.get("schema") != "chacha20-round20-w46-proof-antecedent-calibration-a447-design-v1"
        or value.get("attempt_id") != ATTEMPT_ID
        or calibration.get("targets") != TARGETS
        or calibration.get("cells_per_target") != CELLS
        or calibration.get("fixed_blocks") != BLOCKS
        or calibration.get("targets_per_block") != BLOCK_SIZE
        or tuple(calibration.get("fixed_operator_order", [])) != OPERATORS
        or calibration.get("all_features_operators_directions_hyperparameters_and_ties_frozen_before_measurement") is not True
        or boundary.get("A447_target00_truth_rank_association_seen") is not False
        or boundary.get("A447_selected32_feature_values_or_truth_ranks_seen_before_design") is not False
        or boundary.get("A447_operator_results_seen_before_design") is not False
    ):
        raise RuntimeError("A447 frozen design semantics differ")
    expected_selection = {key: list(indices) for key, indices in SOURCE_SELECTION.items()}
    if calibration.get("source_targets") != expected_selection:
        raise RuntimeError("A447 target selection differs")
    return value


def selected_manifest() -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    target_index = 0
    for source in ("A359", "A363", "A367"):
        anchor(PREPARED[source], PREPARED_SHA256[source])
        prepared = json.loads(PREPARED[source].read_bytes())
        source_rows = {int(row["index"]): row for row in prepared["rows"]}
        for source_index in SOURCE_SELECTION[source]:
            row = source_rows[source_index]
            block = SOURCE_BLOCK_OFFSETS[source] + source_index // 16
            cnf = row["slice_CNF"]
            mapping = [int(value) for value in row["corrected_synthetic_reader_mapping"]]
            entry = {
                "target_index": target_index,
                "source": source,
                "source_index": source_index,
                "source_global_index": SOURCE_GLOBAL_OFFSETS[source] + source_index,
                "block": block,
                "label": str(row["label"]),
                "true_high8": int(row["true_high8"]),
                "true_low4": int(row["true_low4"]),
                "slice_CNF_path": str(cnf["path"]),
                "slice_CNF_sha256": str(cnf["sha256"]),
                "reader_mapping": mapping,
                "reader_mapping_sha256": str(row["corrected_synthetic_reader_mapping_sha256"]),
            }
            if (
                len(mapping) != 20
                or len({abs(value) for value in mapping}) != 20
                or canonical_sha256(mapping) != entry["reader_mapping_sha256"]
                or not 0 <= entry["true_high8"] < CELLS
            ):
                raise RuntimeError("A447 selected manifest mapping differs")
            anchor(path_from_ref(entry["slice_CNF_path"]), entry["slice_CNF_sha256"])
            rows.append(entry)
            target_index += 1
    blocks = [int(row["block"]) for row in rows]
    if (
        len(rows) != TARGETS
        or [blocks.count(block) for block in range(BLOCKS)] != [BLOCK_SIZE] * BLOCKS
        or [int(row["target_index"]) for row in rows] != list(range(TARGETS))
    ):
        raise RuntimeError("A447 selected manifest block cover differs")
    return rows


def measurement_path(target_index: int) -> Path:
    return MEASUREMENTS / f"target_{target_index:02d}.json.zst"


def write_measurement(path: Path, value: Mapping[str, Any]) -> dict[str, Any]:
    raw = canonical_bytes(value)
    compressed = zstandard.ZstdCompressor(level=ZSTD_LEVEL).compress(raw)
    path.parent.mkdir(parents=True, exist_ok=True)
    atomic_bytes(path, compressed)
    return measurement_ledger(path, value, raw=raw, compressed=compressed)


def measurement_ledger(
    path: Path,
    value: Mapping[str, Any],
    *,
    raw: bytes | None = None,
    compressed: bytes | None = None,
) -> dict[str, Any]:
    stable_raw = canonical_bytes(value) if raw is None else raw
    stable_compressed = path.read_bytes() if compressed is None else compressed
    if stable_compressed != path.read_bytes():
        raise RuntimeError("A447 measurement bytes differ from ledger input")
    return {
        "path": relative(path),
        "compressed_sha256": hashlib.sha256(stable_compressed).hexdigest(),
        "compressed_bytes": len(stable_compressed),
        "raw_sha256": hashlib.sha256(stable_raw).hexdigest(),
        "raw_bytes": len(stable_raw),
        "target_index": int(value["target_index"]),
        "source": str(value["source"]),
        "source_index": int(value["source_index"]),
        "block": int(value["block"]),
    }


def read_measurement(path: Path, ledger: Mapping[str, Any] | None = None) -> dict[str, Any]:
    compressed = path.read_bytes()
    if ledger is not None and hashlib.sha256(compressed).hexdigest() != ledger["compressed_sha256"]:
        raise RuntimeError("A447 compressed measurement differs")
    raw = zstandard.ZstdDecompressor().decompress(compressed)
    if ledger is not None and hashlib.sha256(raw).hexdigest() != ledger["raw_sha256"]:
        raise RuntimeError("A447 raw measurement differs")
    value = json.loads(raw)
    run = value.get("run", {})
    if (
        canonical_bytes(value) != raw
        or value.get("schema") != "chacha20-round20-w46-proof-antecedent-calibration-a447-shard-v1"
        or value.get("attempt_id") != ATTEMPT_ID
        or value.get("complete_candidate_cover") is not True
        or value.get("true_high8_used_for_order_or_early_stop") is not False
        or run.get("proof_antecedent_identity_complete") is not True
        or run.get("proof_missing_antecedent_total") != 0
        or len(run.get("cells", [])) != CELLS
        or len(run.get("stages", [])) != CELLS * len(HORIZONS)
    ):
        raise RuntimeError(f"A447 measurement semantics differ: {path.name}")
    return value


def freeze_implementation() -> dict[str, Any]:
    if IMPLEMENTATION.exists() or RESULT.exists() or CAUSAL.exists() or REPORT.exists():
        raise FileExistsError("A447 implementation or result already exists")
    if MEASUREMENTS.exists() and any(MEASUREMENTS.iterdir()):
        raise RuntimeError("A447 implementation must precede selected-target measurements")
    design = load_design()
    manifest = selected_manifest()
    for path in (TEST, WRAPPER_TEST, FEATURE_TEST, REPRO, A447_IMPORT_INCIDENT):
        if not path.exists():
            raise FileNotFoundError(f"A447 frozen artifact missing: {path}")
    anchor(A445_RUNNER, A445_RUNNER_SHA256)
    anchor(A442_RESULT, A442_RESULT_SHA256)
    anchor(A446_RESULT, A446_RESULT_SHA256)
    anchor(A446_CAUSAL, A446_CAUSAL_SHA256)
    anchor(A446_READBACK, A446_READBACK_SHA256)
    helper = WRAPPER.compile_helper()
    payload: dict[str, Any] = {
        "schema": "chacha20-round20-w46-proof-antecedent-calibration-a447-implementation-v1",
        "attempt_id": ATTEMPT_ID,
        "commitment_state": "complete_native_measurement_feature_crossfit_and_authentic_Causal_code_frozen_before_selected32_measurement",
        "design_sha256": DESIGN_SHA256,
        "manifest_sha256": canonical_sha256(manifest),
        "helper_build": helper,
        "operators": list(OPERATORS),
        "measurement_workers": MEASUREMENT_WORKERS,
        "A447_selected32_measurement_started_at_freeze": False,
        "A447_truth_rank_or_operator_result_available_at_freeze": False,
        "W52_target_labels_used": 0,
        "W52_model_refits": 0,
        "W52_new_solver_stages": 0,
        "candidate_assignments_executed": 0,
        "anchors": {
            "design": anchor(DESIGN, DESIGN_SHA256),
            "runner": anchor(Path(__file__)),
            "wrapper": anchor(WRAPPER_PATH),
            "identity_wrapper": anchor(IDENTITY_WRAPPER_PATH),
            "multihorizon_wrapper": anchor(MULTIHORIZON_WRAPPER_PATH),
            "native_source": anchor(NATIVE_SOURCE),
            "tracer_header": anchor(TRACER_HEADER),
            "feature_source": anchor(FEATURE_SOURCE),
            "test": anchor(TEST),
            "wrapper_test": anchor(WRAPPER_TEST),
            "feature_test": anchor(FEATURE_TEST),
            "reproducer": anchor(REPRO),
            "A442_result": anchor(A442_RESULT, A442_RESULT_SHA256),
            "A446_result": anchor(A446_RESULT, A446_RESULT_SHA256),
            "A446_causal": anchor(A446_CAUSAL, A446_CAUSAL_SHA256),
            "A446_personal_readback": anchor(A446_READBACK, A446_READBACK_SHA256),
            "A447_premeasurement_import_incident": anchor(A447_IMPORT_INCIDENT),
        },
        "design_contract": design["new_observation_boundary"],
    }
    payload["implementation_commitment_sha256"] = canonical_sha256(payload)
    atomic_json(IMPLEMENTATION, payload)
    return payload


def load_implementation(expected_sha256: str) -> dict[str, Any]:
    if file_sha256(IMPLEMENTATION) != expected_sha256:
        raise RuntimeError("A447 implementation hash differs")
    value = json.loads(IMPLEMENTATION.read_bytes())
    if (
        value.get("schema") != "chacha20-round20-w46-proof-antecedent-calibration-a447-implementation-v1"
        or value.get("attempt_id") != ATTEMPT_ID
        or value.get("manifest_sha256") != canonical_sha256(selected_manifest())
        or tuple(value.get("operators", [])) != OPERATORS
        or value.get("A447_selected32_measurement_started_at_freeze") is not False
        or value.get("A447_truth_rank_or_operator_result_available_at_freeze") is not False
    ):
        raise RuntimeError("A447 implementation semantics differ")
    for row in value["anchors"].values():
        anchor(path_from_ref(row["path"]), row["sha256"])
    helper = path_from_ref(value["helper_build"]["binary_path"])
    anchor(helper, value["helper_build"]["binary_sha256"])
    unsigned = {key: item for key, item in value.items() if key != "implementation_commitment_sha256"}
    if value.get("implementation_commitment_sha256") != canonical_sha256(unsigned):
        raise RuntimeError("A447 implementation commitment differs")
    return value


def run_target(job: Mapping[str, Any], helper: Path, implementation_sha256: str) -> dict[str, Any]:
    target_index = int(job["target_index"])
    path = measurement_path(target_index)
    if path.exists():
        value = read_measurement(path)
        if value["label"] != job["label"] or value["source_index"] != job["source_index"]:
            raise RuntimeError("A447 resumed measurement identity differs")
        return write_measurement(path, value)
    started = time.perf_counter()
    run = WRAPPER.run_fresh_clause_antecedents(
        helper=helper,
        cnf=path_from_ref(str(job["slice_CNF_path"])),
        mode=f"A447_{job['source']}_target_{int(job['source_index']):02d}",
        order=[f"{value:08b}" for value in range(CELLS)],
        key_one_literals_bit0_through_bit19=job["reader_mapping"],
        conflict_horizons=HORIZONS,
        watchdog_seconds=WATCHDOG_SECONDS,
        external_timeout_seconds=1200.0,
    )
    stable = {key: value for key, value in run.items() if key not in {"command", "process_elapsed_seconds"}}
    value = {
        "schema": "chacha20-round20-w46-proof-antecedent-calibration-a447-shard-v1",
        "attempt_id": ATTEMPT_ID,
        "design_sha256": DESIGN_SHA256,
        "implementation_sha256": implementation_sha256,
        "target_index": target_index,
        "source": str(job["source"]),
        "source_index": int(job["source_index"]),
        "source_global_index": int(job["source_global_index"]),
        "block": int(job["block"]),
        "label": str(job["label"]),
        "slice_CNF_sha256": str(job["slice_CNF_sha256"]),
        "reader_mapping_sha256": str(job["reader_mapping_sha256"]),
        "run": stable,
        "complete_candidate_cover": len(stable.get("cells", [])) == CELLS,
        "candidate_order": "numeric_0_through_255",
        "true_high8_available_to_native_helper": False,
        "true_high8_used_for_order_or_early_stop": False,
        "volatile_process_elapsed_seconds": time.perf_counter() - started,
    }
    if value["complete_candidate_cover"] is not True or stable.get("proof_missing_antecedent_total") != 0:
        raise RuntimeError("A447 target measurement gate failed")
    return write_measurement(path, value)


def measure(*, expected_implementation_sha256: str) -> dict[str, Any]:
    implementation = load_implementation(expected_implementation_sha256)
    helper = path_from_ref(implementation["helper_build"]["binary_path"])
    jobs = selected_manifest()
    MEASUREMENTS.mkdir(parents=True, exist_ok=True)
    ledgers: list[dict[str, Any]] = []
    started = time.perf_counter()
    with concurrent.futures.ThreadPoolExecutor(max_workers=MEASUREMENT_WORKERS) as pool:
        futures = {
            pool.submit(run_target, job, helper, expected_implementation_sha256): int(job["target_index"])
            for job in jobs
        }
        for future in concurrent.futures.as_completed(futures):
            ledger = future.result()
            ledgers.append(ledger)
            print(
                json.dumps(
                    {
                        "A447_target_complete": int(ledger["target_index"]),
                        "completed": len(ledgers),
                        "targets": TARGETS,
                    },
                    sort_keys=True,
                ),
                flush=True,
            )
    ledgers.sort(key=lambda row: int(row["target_index"]))
    if [int(row["target_index"]) for row in ledgers] != list(range(TARGETS)):
        raise RuntimeError("A447 measurement ledger cover differs")
    return {
        "attempt_id": ATTEMPT_ID,
        "implementation_sha256": expected_implementation_sha256,
        "measurement_ledger": ledgers,
        "measurement_cover_sha256": canonical_sha256(ledgers),
        "elapsed_seconds": time.perf_counter() - started,
    }


def load_measurements() -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    jobs = selected_manifest()
    measurements: list[dict[str, Any]] = []
    ledgers: list[dict[str, Any]] = []
    for job in jobs:
        path = measurement_path(int(job["target_index"]))
        if not path.exists():
            raise FileNotFoundError(f"A447 measurement missing: {path.name}")
        value = read_measurement(path)
        if (
            value["source"] != job["source"]
            or value["source_index"] != job["source_index"]
            or value["block"] != job["block"]
        ):
            raise RuntimeError("A447 measurement manifest binding differs")
        measurements.append(value)
        ledgers.append(measurement_ledger(path, value))
    return measurements, ledgers


def reconstruct_selected_borda() -> tuple[np.ndarray, dict[str, Any]]:
    anchor(A445_RUNNER, A445_RUNNER_SHA256)
    anchor(A442_RESULT, A442_RESULT_SHA256)
    a375, _a439, _a442, _a444, runtime = A445.load_sources()
    _matrices, truths, _blocks, borda, _names, hashes = A445.reconstruct_calibration_panel(a375, runtime)
    if hashlib.sha256(np.asarray(borda, dtype=np.int16).tobytes()).hexdigest() != A442_BORDA_FIELD_SHA256:
        raise RuntimeError("A447 full A442 Borda field differs")
    jobs = selected_manifest()
    indices = np.asarray([int(row["source_global_index"]) for row in jobs], dtype=np.int64)
    selected = np.asarray(borda, dtype=np.int16)[indices]
    selected_truths = np.asarray(truths, dtype=np.int16)[indices]
    manifest_truths = np.asarray([int(row["true_high8"]) for row in jobs], dtype=np.int16)
    if not np.array_equal(selected_truths, manifest_truths):
        raise RuntimeError("A447 selected Borda label alignment differs")
    return selected, {
        "full_borda_sha256": A442_BORDA_FIELD_SHA256,
        "selected_global_indices": indices.tolist(),
        "selected_global_indices_sha256": array_sha256(indices, ">u2"),
        "selected_borda_sha256": array_sha256(selected, "<i2"),
        "source_reconstruction_hashes": hashes,
    }


def build_rank_panel(
    measurements: Sequence[Mapping[str, Any]], borda: np.ndarray
) -> tuple[np.ndarray, tuple[str, ...], dict[str, Any]]:
    fields: list[np.ndarray] = []
    matrix_hashes: list[str] = []
    normalized_hashes: list[str] = []
    rank_hashes: list[str] = []
    base_names: tuple[str, ...] | None = None
    directional_names: tuple[str, ...] | None = None
    for target, measurement in enumerate(measurements):
        matrix, names = PROOF_FEATURES.extract_proof_feature_matrix(measurement)
        normalized = PROOF_FEATURES.target_normalize(matrix)
        ranks, _generic_names = PROOF_FEATURES.exact_directional_rank_fields(
            normalized, borda[target]
        )
        current_directional = PROOF_FEATURES.directional_feature_names(names)
        if base_names is None:
            base_names = names
            directional_names = current_directional
        elif names != base_names or current_directional != directional_names:
            raise RuntimeError("A447 feature ledger differs across targets")
        fields.append(ranks)
        matrix_hashes.append(array_sha256(matrix, "<f8"))
        normalized_hashes.append(array_sha256(normalized, "<f8"))
        rank_hashes.append(array_sha256(ranks, "<i2"))
    if base_names is None or directional_names is None:
        raise RuntimeError("A447 proof feature panel is empty")
    tensor = np.stack(fields)
    if tensor.shape != (TARGETS, len(directional_names), CELLS):
        raise RuntimeError("A447 proof rank panel geometry differs")
    return tensor, directional_names, {
        "base_feature_count": len(base_names),
        "directional_feature_count": len(directional_names),
        "base_feature_names": list(base_names),
        "directional_feature_names_sha256": canonical_sha256(directional_names),
        "matrix_hashes": matrix_hashes,
        "normalized_hashes": normalized_hashes,
        "rank_hashes": rank_hashes,
        "panel_sha256": array_sha256(tensor, "<i2"),
    }


def fold_partition(block: int) -> tuple[np.ndarray, np.ndarray]:
    if not 0 <= block < BLOCKS:
        raise ValueError("A447 held block differs")
    all_targets = np.arange(TARGETS, dtype=np.int64)
    held = all_targets[block * BLOCK_SIZE : (block + 1) * BLOCK_SIZE]
    train = np.concatenate((all_targets[: block * BLOCK_SIZE], all_targets[(block + 1) * BLOCK_SIZE :]))
    if train.size != TARGETS - BLOCK_SIZE or np.intersect1d(train, held).size:
        raise RuntimeError("A447 block partition differs")
    return train, held


def uniform_log_rank() -> float:
    return sum(math.log2(rank) for rank in range(1, CELLS + 1)) / CELLS


def feature_selection(
    rank_fields: np.ndarray, truths: np.ndarray, train_indices: Sequence[int]
) -> tuple[np.ndarray, dict[str, Any]]:
    fields = np.asarray(rank_fields, dtype=np.int64)
    labels = np.asarray(truths, dtype=np.int64)
    train = np.asarray(train_indices, dtype=np.int64)
    if fields.ndim != 3 or fields.shape[0] != TARGETS or fields.shape[2] != CELLS:
        raise ValueError("A447 feature-selection panel differs")
    true_ranks = np.stack([fields[target, :, labels[target]] for target in train])
    logs = np.log2(true_ranks.astype(np.float64))
    training_blocks = sorted({int(target) // BLOCK_SIZE for target in train})
    block_gains = np.stack(
        [
            uniform_log_rank()
            - logs[np.asarray([int(target) // BLOCK_SIZE == block for target in train])].mean(axis=0)
            for block in training_blocks
        ]
    )
    positive = np.count_nonzero(block_gains > 0.0, axis=0)
    minimum = block_gains.min(axis=0)
    all_gain = uniform_log_rank() - logs.mean(axis=0)
    ids = np.arange(fields.shape[1], dtype=np.int64)
    order = np.lexsort((ids, -all_gain, -minimum, -positive))
    return order, {
        "training_targets": int(train.size),
        "training_blocks": training_blocks,
        "training_target_index_sha256": array_sha256(train, ">u2"),
        "feature_count": int(fields.shape[1]),
        "feature_order_sha256": array_sha256(order, ">u4"),
        "best_feature_index": int(order[0]),
        "best_feature_positive_training_blocks": int(positive[order[0]]),
        "best_feature_minimum_training_block_gain": float(minimum[order[0]]),
        "best_feature_all_training_gain": float(all_gain[order[0]]),
    }


def ascending_order(primary: np.ndarray, baseline_ranks: np.ndarray) -> np.ndarray:
    values = np.asarray(primary)
    baseline = np.asarray(baseline_ranks, dtype=np.int64)
    return exact_order(np.lexsort((np.arange(CELLS), baseline, values)), CELLS)


def proof_component(
    target_fields: np.ndarray,
    feature_order: np.ndarray,
    kind: str,
    count: int,
    baseline: np.ndarray,
) -> np.ndarray:
    selected = np.asarray(feature_order[:count], dtype=np.int64)
    ranks = np.asarray(target_fields, dtype=np.int64)[selected]
    if kind == "best":
        primary = ranks[0]
    elif kind == "borda":
        primary = ranks.sum(axis=0)
    elif kind == "reciprocal":
        primary = -(1.0 / ranks.astype(np.float64)).sum(axis=0)
    elif kind == "vote":
        votes = np.count_nonzero(ranks <= VOTE_THRESHOLD, axis=0)
        primary = -votes.astype(np.int64) * (count * CELLS + 1) + ranks.sum(axis=0)
    else:
        raise ValueError(f"A447 proof component differs: {kind}")
    return order_to_ranks(ascending_order(primary, baseline), CELLS)


def operator_order(
    target_fields: np.ndarray,
    baseline_ranks: np.ndarray,
    feature_order: np.ndarray,
    operator: str,
) -> np.ndarray:
    baseline = np.asarray(baseline_ranks, dtype=np.int64)
    if operator == "borda_sum_baseline":
        return exact_order(np.argsort(baseline, kind="stable"), CELLS)
    if operator == "proof_best_single":
        proof = proof_component(target_fields, feature_order, "best", 1, baseline)
        return ascending_order(proof, baseline)
    if operator.startswith("proof_borda_top"):
        count = int(operator.removeprefix("proof_borda_top"))
        proof = proof_component(target_fields, feature_order, "borda", count, baseline)
        return ascending_order(proof, baseline)
    if operator == "proof_reciprocal_top8":
        proof = proof_component(target_fields, feature_order, "reciprocal", 8, baseline)
        return ascending_order(proof, baseline)
    if operator == "proof_vote_top16":
        proof = proof_component(target_fields, feature_order, "vote", 16, baseline)
        return ascending_order(proof, baseline)
    if operator.startswith("hybrid_proof_top"):
        suffix = operator.removeprefix("hybrid_proof_top")
        count_text, weights = suffix.split("_", 1)
        proof = proof_component(target_fields, feature_order, "borda", int(count_text), baseline)
        if weights == "base2":
            primary = 2 * baseline + proof
        elif weights == "equal":
            primary = baseline + proof
        elif weights == "proof2":
            primary = baseline + 2 * proof
        else:
            raise ValueError("A447 hybrid weights differ")
        return ascending_order(primary, baseline)
    if operator == "hybrid_reciprocal_top8_equal":
        proof = proof_component(target_fields, feature_order, "reciprocal", 8, baseline)
        return ascending_order(baseline + proof, baseline)
    raise ValueError(f"A447 operator differs: {operator}")


def calibration_statistics(field: np.ndarray, truths: np.ndarray) -> dict[str, Any]:
    ranks = np.asarray(field, dtype=np.int64)
    labels = np.asarray(truths, dtype=np.int64)
    true_ranks = np.asarray([ranks[target, labels[target]] for target in range(TARGETS)])
    logs = np.log2(true_ranks.astype(np.float64))
    block_gains = [
        uniform_log_rank() - float(logs[block * BLOCK_SIZE : (block + 1) * BLOCK_SIZE].mean())
        for block in range(BLOCKS)
    ]
    return {
        "truth_ranks": true_ranks.tolist(),
        "fixed_block_bit_gains": block_gains,
        "minimum_fixed_block_bit_gain": float(min(block_gains)),
        "balanced_eight_block_bit_gain": float(sum(block_gains) / BLOCKS),
        "all32_bit_gain": float(uniform_log_rank() - logs.mean()),
        "positive_fixed_block_count": sum(gain > 0.0 for gain in block_gains),
        "targets_at_or_above_median_rank": int(np.count_nonzero(true_ranks <= CELLS // 2)),
        "worst_rank": int(true_ranks.max()),
    }


def selection_key(row: Mapping[str, Any]) -> tuple[float | int, ...]:
    return (
        -float(row["minimum_fixed_block_bit_gain"]),
        -float(row["balanced_eight_block_bit_gain"]),
        -float(row["all32_bit_gain"]),
        -int(row["targets_at_or_above_median_rank"]),
        int(row["worst_rank"]),
        OPERATORS.index(str(row["operator"])),
    )


def evaluate_operators(
    rank_fields: np.ndarray,
    truths: np.ndarray,
    borda: np.ndarray,
    feature_names: Sequence[str],
) -> tuple[dict[str, Any], str, dict[str, np.ndarray]]:
    fields = {operator: np.empty((TARGETS, CELLS), dtype=np.int16) for operator in OPERATORS}
    fields[OPERATORS[0]][:] = np.asarray(borda, dtype=np.int16)
    ledgers: dict[str, list[dict[str, Any]]] = {operator: [] for operator in OPERATORS}
    exact = np.arange(1, CELLS + 1, dtype=np.int16)
    for block in range(BLOCKS):
        train, held = fold_partition(block)
        order, model = feature_selection(rank_fields, truths, train)
        model = {
            **model,
            "held_block": block,
            "held_target_indices": held.tolist(),
            "top32_feature_indices": order[:32].tolist(),
            "top32_feature_names": [str(feature_names[index]) for index in order[:32]],
        }
        model["model_sha256"] = canonical_sha256(model)
        ledgers[OPERATORS[0]].append(
            {
                "held_block": block,
                "held_target_indices": held.tolist(),
                "training_targets": 0,
                "model_sha256": "fixed:A442_borda_sum_selected_subset",
            }
        )
        for operator in OPERATORS[1:]:
            for target in held:
                cell_order = operator_order(rank_fields[target], borda[target], order, operator)
                fields[operator][target, cell_order] = exact
            ledgers[operator].append(model)
    evaluations: dict[str, Any] = {}
    for operator in OPERATORS:
        field = fields[operator]
        if any(set(field[target].tolist()) != set(range(1, CELLS + 1)) for target in range(TARGETS)):
            raise RuntimeError(f"A447 nonexact operator field: {operator}")
        evaluations[operator] = {
            "operator": operator,
            "evaluation_mode": "fixed_no_fit" if operator == OPERATORS[0] else "eight_fold_four_target_block_exclusive_crossfit",
            **calibration_statistics(field, truths),
            "rank_field_sha256": array_sha256(field, "<i2"),
            "fold_ledger": ledgers[operator],
        }
    selected = min(OPERATORS, key=lambda operator: selection_key(evaluations[operator]))
    return evaluations, selected, fields


def scale_decision(evaluations: Mapping[str, Mapping[str, Any]], selected: str) -> dict[str, Any]:
    baseline = evaluations[OPERATORS[0]]
    chosen = evaluations[selected]
    direct = (
        selected != OPERATORS[0]
        and int(chosen["positive_fixed_block_count"]) == BLOCKS
        and float(chosen["minimum_fixed_block_bit_gain"])
        >= float(baseline["minimum_fixed_block_bit_gain"])
    )
    mechanism_eligible = [
        operator
        for operator in OPERATORS[1:]
        if int(evaluations[operator]["positive_fixed_block_count"]) == BLOCKS
        and float(evaluations[operator]["minimum_fixed_block_bit_gain"]) > 0.0
        and float(evaluations[operator]["balanced_eight_block_bit_gain"]) >= 0.25
    ]
    best_mechanism = (
        min(mechanism_eligible, key=lambda operator: selection_key(evaluations[operator]))
        if mechanism_eligible
        else None
    )
    return {
        "selected_operator": selected,
        "direct_frontier_gate": direct,
        "mechanism_scale_gate": bool(mechanism_eligible),
        "mechanism_eligible_operators": mechanism_eligible,
        "best_mechanism_operator": best_mechanism,
        "full128_scale_ready": bool(direct or mechanism_eligible),
        "baseline_minimum_fixed_block_bit_gain": baseline["minimum_fixed_block_bit_gain"],
        "selected_minimum_fixed_block_bit_gain": chosen["minimum_fixed_block_bit_gain"],
    }


def build_causal(payload: Mapping[str, Any]) -> dict[str, Any]:
    if str(DOTCAUSAL_SRC) not in sys.path:
        sys.path.insert(0, str(DOTCAUSAL_SRC))
    from dotcausal.io import CausalReader, CausalWriter

    ready = bool(payload["scale_decision"]["full128_scale_ready"])
    terminal = "A447:proof_antecedent_full128_scale_ready" if ready else "A447:proof_antecedent_typed_subgraph_frontier"
    writer = CausalWriter(api_id="a447dag")
    writer._rules = []
    writer.add_rule(
        name="A446_gap_to_native_antecedents",
        description="Move the observation boundary before learned-clause output and retain exact LRAT parent IDs for every derived clause.",
        pattern=["A446_assumption_cut_provenance_boundary"],
        conclusion="A447_exact_proof_antecedent_corpus",
        confidence_modifier=1.0,
    )
    writer.add_rule(
        name="native_antecedents_to_typed_ranks",
        description="Reduce complete derivation DAGs into typed redundant, irredundant, assumption-ancestry and parent-reuse rank fields.",
        pattern=["A447_exact_proof_antecedent_corpus"],
        conclusion="A447_crossfit_proof_rank_panel",
        confidence_modifier=1.0,
    )
    writer.add_rule(
        name="block_crossfit_to_scale_decision",
        description="Hold out each four-target block and require cross-block retention before scaling proof tracing.",
        pattern=["A447_crossfit_proof_rank_panel"],
        conclusion=terminal.replace(":", "_"),
        confidence_modifier=1.0,
    )
    writer.add_triplet(
        trigger="A446:assumption_cut_provenance_boundary",
        mechanism="solver_native_LRAT_antecedent_instrumentation_before_clause_output",
        outcome="A447:exact_proof_antecedent_corpus",
        confidence=1.0,
        source=payload["measurement_cover_sha256"],
        quantification=json.dumps(payload["measurement_summary"], sort_keys=True),
        evidence=payload["proof_cover_sha256"],
        domain="full-round ChaCha20 R20 solver-native proof provenance",
        quality_score=1.0,
    )
    writer.add_triplet(
        trigger="A447:exact_proof_antecedent_corpus",
        mechanism="typed_DAG_feature_extraction_three_direction_exact_ranks",
        outcome="A447:crossfit_proof_rank_panel",
        confidence=1.0,
        source=payload["feature_contract_sha256"],
        quantification=json.dumps(payload["feature_contract"], sort_keys=True),
        evidence=payload["selected_full_model_sha256"],
        domain="proof-derived candidate Reader calibration",
        quality_score=1.0,
    )
    writer.add_triplet(
        trigger="A447:crossfit_proof_rank_panel",
        mechanism="eight_complete_block_worst_first_scale_gate",
        outcome=terminal,
        confidence=1.0,
        source=payload["scale_decision_sha256"],
        quantification=json.dumps(payload["scale_decision"], sort_keys=True),
        evidence=str(ready),
        domain="prospective full-corpus instrumentation decision",
        quality_score=1.0,
    )
    writer.add_triplet(
        trigger="A446:assumption_cut_provenance_boundary",
        mechanism="materialized_solver_native_antecedent_decision_closure",
        outcome=terminal,
        confidence=1.0,
        source="materialized:A447_proof_antecedent_chain",
        quantification="exact retained closure",
        evidence=payload["evidence_stage"],
        domain="AI-native retained inference",
        quality_score=1.0,
        is_inferred=True,
    )
    writer.add_cluster(
        name="A447 solver-native proof antecedents",
        entities=[
            "A446:assumption_cut_provenance_boundary",
            "A447:exact_proof_antecedent_corpus",
            "A447:crossfit_proof_rank_panel",
            terminal,
        ],
    )
    writer.add_gap(
        subject=terminal,
        predicate="next_required_object",
        expected_object_type="complete_128_target_proof_antecedent_corpus" if ready else "strongest_typed_subgraph_or_horizon_interaction",
        confidence=1.0,
        suggested_queries=[
            "Scale the frozen proof Reader to all 128 calibration targets before target-blind W52 tracing."
            if ready
            else "Resolve the strongest held-block proof family by typed subgraph and horizon interaction; do not return to clause-output reweighting."
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
        reader.api_id != "a447dag"
        or len(explicit) != 3
        or len(all_rows) != 4
        or len(inferred) != 1
        or len(reader._rules) != 3
        or len(reader._clusters) != 1
        or len(reader._gaps) != 1
    ):
        raise RuntimeError("A447 authentic Causal reopen gate failed")
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
            "features": explicit[1],
            "decision": explicit[2],
            "terminal_chain": all_rows[-1],
            "next_gap": reader._gaps[0],
        },
    }


def build_result(*, expected_implementation_sha256: str) -> dict[str, Any]:
    if RESULT.exists() or CAUSAL.exists() or REPORT.exists():
        raise FileExistsError("A447 result already exists")
    try:
        load_design()
        implementation = load_implementation(expected_implementation_sha256)
        measurements, ledgers = load_measurements()
        if any(value["implementation_sha256"] != expected_implementation_sha256 for value in measurements):
            raise RuntimeError("A447 measurement implementation binding differs")
        borda, borda_contract = reconstruct_selected_borda()
        truths = np.asarray([int(row["true_high8"]) for row in selected_manifest()], dtype=np.int16)
        rank_fields, feature_names, feature_contract = build_rank_panel(measurements, borda)
        evaluations, selected, _operator_fields = evaluate_operators(
            rank_fields, truths, borda, feature_names
        )
        full_order, full_model = feature_selection(rank_fields, truths, range(TARGETS))
        selected_full_model = {
            **full_model,
            "selected_operator": selected,
            "complete_feature_order": full_order.tolist(),
            "top64_feature_names": [str(feature_names[index]) for index in full_order[:64]],
        }
        selected_full_model["model_sha256"] = canonical_sha256(selected_full_model)
        decision = scale_decision(evaluations, selected)
        proof_nodes = sum(int(value["run"]["summary"]["proof_derived_total"]) for value in measurements)
        proof_edges = sum(int(value["run"]["summary"]["proof_antecedent_total"]) for value in measurements)
        proof_missing = sum(int(value["run"]["summary"]["proof_missing_antecedent_total"]) for value in measurements)
        if proof_missing != 0:
            raise RuntimeError("A447 proof cover contains missing antecedents")
        evidence_stage = (
            "EXACT_PROOF_ANTECEDENT_MECHANISM_FULL128_SCALE_READY"
            if decision["full128_scale_ready"]
            else "EXACT_PROOF_ANTECEDENT_TYPED_SUBGRAPH_FRONTIER_RETAINED"
        )
        core: dict[str, Any] = {
            "schema": "chacha20-round20-w46-proof-antecedent-calibration-a447-v1",
            "attempt_id": ATTEMPT_ID,
            "evidence_stage": evidence_stage,
            "design_sha256": DESIGN_SHA256,
            "implementation_sha256": expected_implementation_sha256,
            "implementation_commitment_sha256": implementation["implementation_commitment_sha256"],
            "measurement_ledger": ledgers,
            "measurement_summary": {
                "targets": TARGETS,
                "cells": TARGETS * CELLS,
                "solver_stages": TARGETS * CELLS * len(HORIZONS),
                "proof_nodes": proof_nodes,
                "proof_antecedent_edges": proof_edges,
                "missing_antecedents": proof_missing,
            },
            "borda_contract": borda_contract,
            "feature_contract": feature_contract,
            "operator_evaluations": evaluations,
            "selected_operator": selected,
            "selected_evaluation": evaluations[selected],
            "selected_full_model": selected_full_model,
            "selected_full_model_sha256": selected_full_model["model_sha256"],
            "scale_decision": decision,
            "full128_scale_ready": decision["full128_scale_ready"],
            "W52_target_labels_used": 0,
            "W52_model_refits": 0,
            "W52_new_solver_stages": 0,
            "candidate_assignments_executed": 0,
            "A426_A438_A440_A443_secret_result_stop_or_worker_progress_read": False,
            "anchors": {
                "design": anchor(DESIGN, DESIGN_SHA256),
                "implementation": anchor(IMPLEMENTATION, expected_implementation_sha256),
                "runner": anchor(Path(__file__)),
                "wrapper": anchor(WRAPPER_PATH),
                "identity_wrapper": anchor(IDENTITY_WRAPPER_PATH),
                "multihorizon_wrapper": anchor(MULTIHORIZON_WRAPPER_PATH),
                "native_source": anchor(NATIVE_SOURCE),
                "tracer_header": anchor(TRACER_HEADER),
                "feature_source": anchor(FEATURE_SOURCE),
                "A442_result": anchor(A442_RESULT, A442_RESULT_SHA256),
                "A446_result": anchor(A446_RESULT, A446_RESULT_SHA256),
                "A446_causal": anchor(A446_CAUSAL, A446_CAUSAL_SHA256),
                "A446_personal_readback": anchor(A446_READBACK, A446_READBACK_SHA256),
                "A447_premeasurement_import_incident": anchor(A447_IMPORT_INCIDENT),
            },
        }
        core["measurement_cover_sha256"] = canonical_sha256(ledgers)
        core["proof_cover_sha256"] = canonical_sha256(core["measurement_summary"])
        core["feature_contract_sha256"] = canonical_sha256(feature_contract)
        core["operator_evaluations_sha256"] = canonical_sha256(evaluations)
        core["scale_decision_sha256"] = canonical_sha256(decision)
        core["result_commitment_sha256"] = canonical_sha256(
            {
                "design_sha256": DESIGN_SHA256,
                "implementation_commitment_sha256": core["implementation_commitment_sha256"],
                "measurement_cover_sha256": core["measurement_cover_sha256"],
                "proof_cover_sha256": core["proof_cover_sha256"],
                "feature_contract_sha256": core["feature_contract_sha256"],
                "operator_evaluations_sha256": core["operator_evaluations_sha256"],
                "scale_decision_sha256": core["scale_decision_sha256"],
                "W52_target_labels_used": 0,
                "W52_model_refits": 0,
                "W52_new_solver_stages": 0,
                "candidate_assignments_executed": 0,
            }
        )
        core["causal"] = build_causal(core)
        atomic_json(RESULT, core)
        report = (
            "# A447 — Solver-native proof-antecedent calibration\n\n"
            f"Evidence stage: **{evidence_stage}**\n\n"
            f"- Exact proof nodes: **{proof_nodes:,}**\n"
            f"- Exact antecedent edges: **{proof_edges:,}**\n"
            f"- Missing antecedents: **{proof_missing}**\n"
            f"- Base / directional features: **{feature_contract['base_feature_count']} / {feature_contract['directional_feature_count']}**\n"
            f"- Selected operator: **{selected}**\n"
            f"- Minimum held-block gain: **{evaluations[selected]['minimum_fixed_block_bit_gain']:+.9f} bits**\n"
            f"- Balanced eight-block gain: **{evaluations[selected]['balanced_eight_block_bit_gain']:+.9f} bits**\n"
            f"- Full-128 scale ready: **{decision['full128_scale_ready']}**\n"
            "- W52 labels / refits / new stages / candidate executions: **0 / 0 / 0 / 0**\n"
        )
        atomic_bytes(REPORT, report.encode())
        return core
    except BaseException:
        RESULT.unlink(missing_ok=True)
        CAUSAL.unlink(missing_ok=True)
        REPORT.unlink(missing_ok=True)
        raise


def load_result(expected_sha256: str) -> dict[str, Any]:
    if file_sha256(RESULT) != expected_sha256:
        raise RuntimeError("A447 result hash differs")
    value = json.loads(RESULT.read_bytes())
    if (
        value.get("schema") != "chacha20-round20-w46-proof-antecedent-calibration-a447-v1"
        or value.get("attempt_id") != ATTEMPT_ID
        or value.get("selected_operator") not in OPERATORS
        or value.get("W52_target_labels_used") != 0
        or value.get("W52_model_refits") != 0
        or value.get("W52_new_solver_stages") != 0
        or value.get("candidate_assignments_executed") != 0
    ):
        raise RuntimeError("A447 result semantics differ")
    for row in value["anchors"].values():
        anchor(path_from_ref(row["path"]), row["sha256"])
    anchor(path_from_ref(value["causal"]["path"]), value["causal"]["sha256"])
    return value


def analyze() -> dict[str, Any]:
    load_design()
    payload: dict[str, Any] = {
        "attempt_id": ATTEMPT_ID,
        "design_sha256": file_sha256(DESIGN),
        "manifest_sha256": canonical_sha256(selected_manifest()),
        "implementation_frozen": IMPLEMENTATION.exists(),
        "measurements_complete": all(measurement_path(index).exists() for index in range(TARGETS)),
        "measurements_present": sum(measurement_path(index).exists() for index in range(TARGETS)),
        "result_complete": RESULT.exists(),
        "operators": list(OPERATORS),
    }
    if IMPLEMENTATION.exists():
        payload["implementation_sha256"] = file_sha256(IMPLEMENTATION)
        load_implementation(payload["implementation_sha256"])
    if RESULT.exists():
        payload["result_sha256"] = file_sha256(RESULT)
        value = load_result(payload["result_sha256"])
        payload["evidence_stage"] = value["evidence_stage"]
        payload["selected_operator"] = value["selected_operator"]
        payload["full128_scale_ready"] = value["full128_scale_ready"]
    return payload


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    action = parser.add_mutually_exclusive_group(required=True)
    action.add_argument("--analyze", action="store_true")
    action.add_argument("--freeze-implementation", action="store_true")
    action.add_argument("--measure", action="store_true")
    action.add_argument("--build-result", action="store_true")
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
    print(json.dumps(payload, indent=2, sort_keys=True), flush=True)


if __name__ == "__main__":
    main()

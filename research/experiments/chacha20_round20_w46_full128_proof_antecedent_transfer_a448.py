#!/usr/bin/env python3
"""A448: no-refit remaining96 transfer and complete-128 proof Reader."""

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
RESEARCH = ROOT / "research"
CONFIGS = RESEARCH / "configs"
RESULTS = RESEARCH / "results/v1"
MEASUREMENTS = RESULTS / "chacha20_round20_w46_full128_proof_antecedent_transfer_a448_v1"

DESIGN = CONFIGS / "chacha20_round20_w46_full128_proof_antecedent_transfer_a448_design_v1.json"
IMPLEMENTATION = CONFIGS / "chacha20_round20_w46_full128_proof_antecedent_transfer_a448_implementation_v1.json"
RESULT = RESULTS / "chacha20_round20_w46_full128_proof_antecedent_transfer_a448_v1.json"
CAUSAL = RESULT.with_suffix(".causal")
REPORT = RESULT.with_suffix(".md")
TEST = ROOT / "tests/test_chacha20_round20_w46_full128_proof_antecedent_transfer_a448.py"
REPRO = ROOT / "scripts/reproduce_chacha20_round20_w46_full128_proof_antecedent_transfer_a448.sh"

A447_RUNNER = RESEARCH / "experiments/chacha20_round20_w46_proof_antecedent_calibration_a447.py"
A447_DESIGN = CONFIGS / "chacha20_round20_w46_proof_antecedent_calibration_a447_design_v1.json"
A447_IMPLEMENTATION = CONFIGS / "chacha20_round20_w46_proof_antecedent_calibration_a447_implementation_v1.json"
A447_RESULT = RESULTS / "chacha20_round20_w46_proof_antecedent_calibration_a447_v1.json"
A447_CAUSAL = A447_RESULT.with_suffix(".causal")
A447_READBACK = RESEARCH / "reports/CAUSAL_CHACHA20_A447_PERSONAL_READER_READBACK_V1.md"
A442_RESULT = RESULTS / "chacha20_round20_w52_knownkey_meta_reader_transfer_a442_v1.json"

ATTEMPT_ID = "A448"
DESIGN_SHA256 = "482033be6c5d6e123f4efbe0c527933f832f73e4382bdb4b51172417f339f555"
A447_RUNNER_SHA256 = "732579d73de55d8f544f5acd99104b581bedcf51956d773b3652b3e4ae786ca4"
A447_DESIGN_SHA256 = "16563220720977e05857e7ae663d6c86d35b18cb47ba69eab1d3fdf7aa5a88bd"
A447_IMPLEMENTATION_SHA256 = "ba7a7c840dd2f5b842dceb9485c466d54976d4c48baaaf4be3a0eceaa40a9332"
A447_RESULT_SHA256 = "09836abe6618d42d544a327f009d7840e00bb9bfbf2e99eea296a7ed70cc6051"
A447_CAUSAL_SHA256 = "78cbbe380c50b5394e7262014853214ea39d265be94ea2e64daac2f004902da6"
A447_READBACK_SHA256 = "d944b58ffdbf9f30965ca13e66f8b2ec5c5b89c2b943249e9cc617e8039dc8e1"
A442_RESULT_SHA256 = "8c8222528dc3ef12ffc0fbda513061b39243daade51a70a17f0bd89c65b53b1d"
A442_BORDA_FIELD_SHA256 = "64cb6aad1f9621df5ff6ef44bb7e06cfc2dd86871483df83195382b2abf899b0"

TARGETS = 128
REUSED_TARGETS = 32
NEW_TARGETS = 96
CELLS = 256
BLOCKS = 8
BLOCK_SIZE = 16
REUSED_PER_BLOCK = 4
NEW_PER_BLOCK = 12
HORIZONS = (1, 2, 4, 8)
WATCHDOG_SECONDS = 2.0
MEASUREMENT_WORKERS = 4
ZSTD_LEVEL = 10
PRIMARY_OPERATOR = "hybrid_proof_top4_equal"
SIGNAL_GAIN_GATE = 0.25
DOTCAUSAL_SRC = Path("/Users/bhkmie/Documents/Forschung/O1/vendor/fabel/dotcausal_package/src")


def load_module(path: Path, name: str) -> Any:
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot import A448 dependency {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


A447 = load_module(A447_RUNNER, "a448_a447")
OPERATORS = A447.OPERATORS
file_sha256 = A447.file_sha256
canonical_sha256 = A447.canonical_sha256
atomic_bytes = A447.atomic_bytes
atomic_json = A447.atomic_json
relative = A447.relative
path_from_ref = A447.path_from_ref
anchor = A447.anchor
array_sha256 = A447.array_sha256
canonical_bytes = A447.canonical_bytes


def load_design() -> dict[str, Any]:
    if file_sha256(DESIGN) != DESIGN_SHA256:
        raise RuntimeError("A448 design hash differs")
    value = json.loads(DESIGN.read_bytes())
    corpus = value.get("corpus_contract", {})
    transfer = value.get("prospective_no_refit_transfer", {})
    boundary = value.get("information_boundary", {})
    if (
        value.get("schema")
        != "chacha20-round20-w46-full128-proof-antecedent-transfer-a448-design-v1"
        or value.get("attempt_id") != ATTEMPT_ID
        or corpus.get("targets") != TARGETS
        or corpus.get("fixed_blocks") != BLOCKS
        or corpus.get("targets_per_block") != BLOCK_SIZE
        or transfer.get("primary_operator") != PRIMARY_OPERATOR
        or tuple(transfer.get("fixed_diagnostic_operator_order", [])) != OPERATORS
        or boundary.get("A448_remaining96_proof_values_seen_before_design") is not False
        or boundary.get("A448_remaining96_truth_ranks_seen_before_design") is not False
        or boundary.get("A448_no_refit_operator_results_seen_before_design") is not False
    ):
        raise RuntimeError("A448 frozen design semantics differ")
    return value


def load_a447_result() -> dict[str, Any]:
    anchor(A447_RUNNER, A447_RUNNER_SHA256)
    anchor(A447_DESIGN, A447_DESIGN_SHA256)
    anchor(A447_IMPLEMENTATION, A447_IMPLEMENTATION_SHA256)
    anchor(A447_RESULT, A447_RESULT_SHA256)
    anchor(A447_CAUSAL, A447_CAUSAL_SHA256)
    anchor(A447_READBACK, A447_READBACK_SHA256)
    value = A447.load_result(A447_RESULT_SHA256)
    if (
        value.get("selected_operator") != PRIMARY_OPERATOR
        or value.get("full128_scale_ready") is not True
        or len(value.get("measurement_ledger", [])) != REUSED_TARGETS
        or value.get("selected_full_model_sha256")
        != value.get("selected_full_model", {}).get("model_sha256")
    ):
        raise RuntimeError("A448 A447 source semantics differ")
    return value


def complete_manifest() -> list[dict[str, Any]]:
    reused = {
        (str(row["source"]), int(row["source_index"])): row
        for row in A447.selected_manifest()
    }
    rows: list[dict[str, Any]] = []
    target_index = 0
    for source, count in (("A359", 32), ("A363", 32), ("A367", 64)):
        anchor(A447.PREPARED[source], A447.PREPARED_SHA256[source])
        prepared = json.loads(A447.PREPARED[source].read_bytes())
        source_rows = {int(row["index"]): row for row in prepared["rows"]}
        if set(source_rows) != set(range(count)):
            raise RuntimeError("A448 prepared source cover differs")
        for source_index in range(count):
            row = source_rows[source_index]
            mapping = [int(value) for value in row["corrected_synthetic_reader_mapping"]]
            cnf = row["slice_CNF"]
            reused_row = reused.get((source, source_index))
            entry = {
                "target_index": target_index,
                "source": source,
                "source_index": source_index,
                "block": A447.SOURCE_BLOCK_OFFSETS[source] + source_index // BLOCK_SIZE,
                "label": str(row["label"]),
                "true_high8": int(row["true_high8"]),
                "true_low4": int(row["true_low4"]),
                "slice_CNF_path": str(cnf["path"]),
                "slice_CNF_sha256": str(cnf["sha256"]),
                "reader_mapping": mapping,
                "reader_mapping_sha256": str(
                    row["corrected_synthetic_reader_mapping_sha256"]
                ),
                "reused_from_A447": reused_row is not None,
                "A447_target_index": (
                    int(reused_row["target_index"]) if reused_row is not None else None
                ),
            }
            if (
                len(mapping) != 20
                or canonical_sha256(mapping) != entry["reader_mapping_sha256"]
                or not 0 <= entry["true_high8"] < CELLS
            ):
                raise RuntimeError("A448 manifest mapping differs")
            anchor(path_from_ref(entry["slice_CNF_path"]), entry["slice_CNF_sha256"])
            rows.append(entry)
            target_index += 1
    if (
        len(rows) != TARGETS
        or sum(row["reused_from_A447"] for row in rows) != REUSED_TARGETS
        or [sum(row["block"] == block for row in rows) for block in range(BLOCKS)]
        != [BLOCK_SIZE] * BLOCKS
        or [
            sum(row["block"] == block and not row["reused_from_A447"] for row in rows)
            for block in range(BLOCKS)
        ]
        != [NEW_PER_BLOCK] * BLOCKS
    ):
        raise RuntimeError("A448 complete manifest geometry differs")
    return rows


def new_measurement_path(target_index: int) -> Path:
    return MEASUREMENTS / f"target_{target_index:03d}.json.zst"


def measurement_ledger(
    path: Path, value: Mapping[str, Any], *, raw: bytes | None = None, compressed: bytes | None = None
) -> dict[str, Any]:
    stable_raw = canonical_bytes(value) if raw is None else raw
    stable_compressed = path.read_bytes() if compressed is None else compressed
    if stable_compressed != path.read_bytes():
        raise RuntimeError("A448 measurement bytes differ from ledger input")
    return {
        "origin": "A448_new",
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


def write_new_measurement(path: Path, value: Mapping[str, Any]) -> dict[str, Any]:
    raw = canonical_bytes(value)
    compressed = zstandard.ZstdCompressor(level=ZSTD_LEVEL).compress(raw)
    path.parent.mkdir(parents=True, exist_ok=True)
    atomic_bytes(path, compressed)
    return measurement_ledger(path, value, raw=raw, compressed=compressed)


def read_new_measurement(path: Path, ledger: Mapping[str, Any] | None = None) -> dict[str, Any]:
    compressed = path.read_bytes()
    if ledger is not None and hashlib.sha256(compressed).hexdigest() != ledger["compressed_sha256"]:
        raise RuntimeError("A448 compressed measurement differs")
    raw = zstandard.ZstdDecompressor().decompress(compressed)
    if ledger is not None and hashlib.sha256(raw).hexdigest() != ledger["raw_sha256"]:
        raise RuntimeError("A448 raw measurement differs")
    value = json.loads(raw)
    run = value.get("run", {})
    if (
        canonical_bytes(value) != raw
        or value.get("schema")
        != "chacha20-round20-w46-full128-proof-antecedent-transfer-a448-shard-v1"
        or value.get("attempt_id") != ATTEMPT_ID
        or value.get("complete_candidate_cover") is not True
        or value.get("true_high8_used_for_order_or_early_stop") is not False
        or run.get("proof_antecedent_identity_complete") is not True
        or run.get("proof_missing_antecedent_total") != 0
        or len(run.get("cells", [])) != CELLS
        or len(run.get("stages", [])) != CELLS * len(HORIZONS)
    ):
        raise RuntimeError(f"A448 measurement semantics differ: {path.name}")
    return value


def freeze_implementation() -> dict[str, Any]:
    if IMPLEMENTATION.exists() or RESULT.exists() or CAUSAL.exists() or REPORT.exists():
        raise FileExistsError("A448 implementation or result already exists")
    if MEASUREMENTS.exists() and any(MEASUREMENTS.iterdir()):
        raise RuntimeError("A448 implementation must precede remaining96 measurements")
    design = load_design()
    manifest = complete_manifest()
    a447_result = load_a447_result()
    for path in (TEST, REPRO):
        if not path.exists():
            raise FileNotFoundError(f"A448 frozen artifact missing: {path}")
    a447_implementation = A447.load_implementation(A447_IMPLEMENTATION_SHA256)
    helper = path_from_ref(a447_implementation["helper_build"]["binary_path"])
    anchor(helper, a447_implementation["helper_build"]["binary_sha256"])
    payload: dict[str, Any] = {
        "schema": "chacha20-round20-w46-full128-proof-antecedent-transfer-a448-implementation-v1",
        "attempt_id": ATTEMPT_ID,
        "commitment_state": "complete_remaining96_measurement_no_refit_transfer_full128_crossfit_and_Causal_code_frozen_before_A448_measurement",
        "design_sha256": DESIGN_SHA256,
        "manifest_sha256": canonical_sha256(manifest),
        "operators": list(OPERATORS),
        "primary_operator": PRIMARY_OPERATOR,
        "A447_selected_full_model_sha256": a447_result["selected_full_model_sha256"],
        "A447_complete_feature_order_sha256": array_sha256(
            np.asarray(a447_result["selected_full_model"]["complete_feature_order"]), ">u4"
        ),
        "helper_path": relative(helper),
        "helper_sha256": a447_implementation["helper_build"]["binary_sha256"],
        "measurement_workers": MEASUREMENT_WORKERS,
        "A448_remaining96_measurement_started_at_freeze": False,
        "A448_transfer_result_available_at_freeze": False,
        "W52_target_labels_used": 0,
        "W52_model_refits": 0,
        "W52_new_solver_stages": 0,
        "candidate_assignments_executed": 0,
        "anchors": {
            "design": anchor(DESIGN, DESIGN_SHA256),
            "runner": anchor(Path(__file__)),
            "test": anchor(TEST),
            "reproducer": anchor(REPRO),
            "A447_runner": anchor(A447_RUNNER, A447_RUNNER_SHA256),
            "A447_design": anchor(A447_DESIGN, A447_DESIGN_SHA256),
            "A447_implementation": anchor(A447_IMPLEMENTATION, A447_IMPLEMENTATION_SHA256),
            "A447_result": anchor(A447_RESULT, A447_RESULT_SHA256),
            "A447_causal": anchor(A447_CAUSAL, A447_CAUSAL_SHA256),
            "A447_personal_readback": anchor(A447_READBACK, A447_READBACK_SHA256),
            "A442_result": anchor(A442_RESULT, A442_RESULT_SHA256),
            "proof_wrapper": anchor(A447.WRAPPER_PATH),
            "identity_wrapper": anchor(A447.IDENTITY_WRAPPER_PATH),
            "multihorizon_wrapper": anchor(A447.MULTIHORIZON_WRAPPER_PATH),
            "feature_source": anchor(A447.FEATURE_SOURCE),
            "native_source": anchor(A447.NATIVE_SOURCE),
            "tracer_header": anchor(A447.TRACER_HEADER),
        },
        "design_contract": design["prospective_no_refit_transfer"],
    }
    payload["implementation_commitment_sha256"] = canonical_sha256(payload)
    atomic_json(IMPLEMENTATION, payload)
    return payload


def load_implementation(expected_sha256: str) -> dict[str, Any]:
    if file_sha256(IMPLEMENTATION) != expected_sha256:
        raise RuntimeError("A448 implementation hash differs")
    value = json.loads(IMPLEMENTATION.read_bytes())
    if (
        value.get("schema")
        != "chacha20-round20-w46-full128-proof-antecedent-transfer-a448-implementation-v1"
        or value.get("attempt_id") != ATTEMPT_ID
        or value.get("manifest_sha256") != canonical_sha256(complete_manifest())
        or tuple(value.get("operators", [])) != OPERATORS
        or value.get("primary_operator") != PRIMARY_OPERATOR
        or value.get("A448_remaining96_measurement_started_at_freeze") is not False
        or value.get("A448_transfer_result_available_at_freeze") is not False
    ):
        raise RuntimeError("A448 implementation semantics differ")
    for row in value["anchors"].values():
        anchor(path_from_ref(row["path"]), row["sha256"])
    anchor(path_from_ref(value["helper_path"]), value["helper_sha256"])
    unsigned = {key: item for key, item in value.items() if key != "implementation_commitment_sha256"}
    if value.get("implementation_commitment_sha256") != canonical_sha256(unsigned):
        raise RuntimeError("A448 implementation commitment differs")
    return value


def run_target(job: Mapping[str, Any], helper: Path, implementation_sha256: str) -> dict[str, Any]:
    target_index = int(job["target_index"])
    path = new_measurement_path(target_index)
    if path.exists():
        value = read_new_measurement(path)
        if value["source"] != job["source"] or value["source_index"] != job["source_index"]:
            raise RuntimeError("A448 resumed measurement identity differs")
        return measurement_ledger(path, value)
    started = time.perf_counter()
    run = A447.WRAPPER.run_fresh_clause_antecedents(
        helper=helper,
        cnf=path_from_ref(str(job["slice_CNF_path"])),
        mode=f"A448_{job['source']}_target_{int(job['source_index']):02d}",
        order=[f"{value:08b}" for value in range(CELLS)],
        key_one_literals_bit0_through_bit19=job["reader_mapping"],
        conflict_horizons=HORIZONS,
        watchdog_seconds=WATCHDOG_SECONDS,
        external_timeout_seconds=1200.0,
    )
    stable = {key: value for key, value in run.items() if key not in {"command", "process_elapsed_seconds"}}
    value = {
        "schema": "chacha20-round20-w46-full128-proof-antecedent-transfer-a448-shard-v1",
        "attempt_id": ATTEMPT_ID,
        "design_sha256": DESIGN_SHA256,
        "implementation_sha256": implementation_sha256,
        "target_index": target_index,
        "source": str(job["source"]),
        "source_index": int(job["source_index"]),
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
        raise RuntimeError("A448 target measurement gate failed")
    return write_new_measurement(path, value)


def measure(*, expected_implementation_sha256: str) -> dict[str, Any]:
    implementation = load_implementation(expected_implementation_sha256)
    helper = path_from_ref(implementation["helper_path"])
    jobs = [row for row in complete_manifest() if not row["reused_from_A447"]]
    if len(jobs) != NEW_TARGETS:
        raise RuntimeError("A448 remaining96 job cover differs")
    A447.WRAPPER._load_identity_wrapper()  # noqa: SLF001
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
                        "A448_target_complete": int(ledger["target_index"]),
                        "completed": len(ledgers),
                        "new_targets": NEW_TARGETS,
                    },
                    sort_keys=True,
                ),
                flush=True,
            )
    ledgers.sort(key=lambda row: int(row["target_index"]))
    expected = [int(row["target_index"]) for row in jobs]
    if [int(row["target_index"]) for row in ledgers] != expected:
        raise RuntimeError("A448 remaining96 ledger cover differs")
    return {
        "attempt_id": ATTEMPT_ID,
        "implementation_sha256": expected_implementation_sha256,
        "new_measurement_ledger": ledgers,
        "new_measurement_cover_sha256": canonical_sha256(ledgers),
        "elapsed_seconds": time.perf_counter() - started,
    }


def load_complete_measurements() -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    manifest = complete_manifest()
    a447_result = load_a447_result()
    old_ledgers = {
        int(row["target_index"]): row for row in a447_result["measurement_ledger"]
    }
    measurements: list[dict[str, Any]] = []
    ledgers: list[dict[str, Any]] = []
    for job in manifest:
        if job["reused_from_A447"]:
            old_index = int(job["A447_target_index"])
            old_ledger = old_ledgers[old_index]
            path = path_from_ref(old_ledger["path"])
            value = A447.read_measurement(path, old_ledger)
            if value["source"] != job["source"] or value["source_index"] != job["source_index"]:
                raise RuntimeError("A448 reused A447 identity differs")
            ledger = {
                **old_ledger,
                "origin": "A447_reused",
                "A447_target_index": old_index,
                "target_index": int(job["target_index"]),
            }
        else:
            path = new_measurement_path(int(job["target_index"]))
            if not path.exists():
                raise FileNotFoundError(f"A448 measurement missing: {path.name}")
            value = read_new_measurement(path)
            if value["source"] != job["source"] or value["source_index"] != job["source_index"]:
                raise RuntimeError("A448 new measurement identity differs")
            ledger = measurement_ledger(path, value)
        measurements.append(value)
        ledgers.append(ledger)
    if len(measurements) != TARGETS or len(ledgers) != TARGETS:
        raise RuntimeError("A448 complete measurement cover differs")
    return measurements, ledgers


def reconstruct_borda() -> tuple[np.ndarray, np.ndarray, dict[str, Any]]:
    anchor(A442_RESULT, A442_RESULT_SHA256)
    a375, _a439, _a442, _a444, runtime = A447.A445.load_sources()
    _matrices, truths, _blocks, borda, _names, hashes = A447.A445.reconstruct_calibration_panel(
        a375, runtime
    )
    borda = np.asarray(borda, dtype=np.int16)
    truths = np.asarray(truths, dtype=np.int16)
    if (
        borda.shape != (TARGETS, CELLS)
        or truths.shape != (TARGETS,)
        or hashlib.sha256(borda.tobytes()).hexdigest() != A442_BORDA_FIELD_SHA256
        or not np.array_equal(
            truths, np.asarray([row["true_high8"] for row in complete_manifest()], dtype=np.int16)
        )
    ):
        raise RuntimeError("A448 full Borda reconstruction differs")
    return borda, truths, {
        "borda_field_sha256": A442_BORDA_FIELD_SHA256,
        "truths_sha256": array_sha256(truths, ">u2"),
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
        matrix, names = A447.PROOF_FEATURES.extract_proof_feature_matrix(measurement)
        normalized = A447.PROOF_FEATURES.target_normalize(matrix)
        ranks, _generic_names = A447.PROOF_FEATURES.exact_directional_rank_fields(
            normalized, borda[target]
        )
        current_directional = A447.PROOF_FEATURES.directional_feature_names(names)
        if base_names is None:
            base_names = names
            directional_names = current_directional
        elif names != base_names or current_directional != directional_names:
            raise RuntimeError("A448 feature ledger differs across targets")
        fields.append(ranks)
        matrix_hashes.append(array_sha256(matrix, "<f8"))
        normalized_hashes.append(array_sha256(normalized, "<f8"))
        rank_hashes.append(array_sha256(ranks, "<i2"))
    if base_names is None or directional_names is None:
        raise RuntimeError("A448 proof feature panel is empty")
    tensor = np.stack(fields)
    if tensor.shape != (TARGETS, len(directional_names), CELLS):
        raise RuntimeError("A448 proof rank panel geometry differs")
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


def uniform_log_rank() -> float:
    return sum(math.log2(rank) for rank in range(1, CELLS + 1)) / CELLS


def block_partition(block: int) -> tuple[np.ndarray, np.ndarray]:
    if not 0 <= block < BLOCKS:
        raise ValueError("A448 block differs")
    all_targets = np.arange(TARGETS, dtype=np.int64)
    held = all_targets[block * BLOCK_SIZE : (block + 1) * BLOCK_SIZE]
    train = np.concatenate((all_targets[: block * BLOCK_SIZE], all_targets[(block + 1) * BLOCK_SIZE :]))
    return train, held


def feature_selection(
    rank_fields: np.ndarray, truths: np.ndarray, train_indices: Sequence[int]
) -> tuple[np.ndarray, dict[str, Any]]:
    fields = np.asarray(rank_fields, dtype=np.int64)
    labels = np.asarray(truths, dtype=np.int64)
    train = np.asarray(train_indices, dtype=np.int64)
    if fields.ndim != 3 or fields.shape != (TARGETS, fields.shape[1], CELLS):
        raise ValueError("A448 feature-selection panel differs")
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
    aggregate = uniform_log_rank() - logs.mean(axis=0)
    ids = np.arange(fields.shape[1], dtype=np.int64)
    order = np.lexsort((ids, -aggregate, -minimum, -positive))
    return order, {
        "training_targets": int(train.size),
        "training_blocks": training_blocks,
        "training_target_index_sha256": array_sha256(train, ">u2"),
        "feature_count": int(fields.shape[1]),
        "feature_order_sha256": array_sha256(order, ">u4"),
        "best_feature_index": int(order[0]),
        "best_feature_positive_training_blocks": int(positive[order[0]]),
        "best_feature_minimum_training_block_gain": float(minimum[order[0]]),
        "best_feature_aggregate_training_gain": float(aggregate[order[0]]),
    }


def statistics(
    field: np.ndarray,
    truths: np.ndarray,
    target_indices: Sequence[int],
    *,
    evaluation_scope: str,
) -> dict[str, Any]:
    ranks = np.asarray(field, dtype=np.int64)
    labels = np.asarray(truths, dtype=np.int64)
    indices = np.asarray(target_indices, dtype=np.int64)
    true_ranks = np.asarray([ranks[target, labels[target]] for target in indices])
    if np.any(true_ranks < 1) or np.any(true_ranks > CELLS):
        raise RuntimeError("A448 statistic rank differs")
    logs = np.log2(true_ranks.astype(np.float64))
    manifest = complete_manifest()
    block_gains: list[float] = []
    for block in range(BLOCKS):
        positions = [position for position, target in enumerate(indices) if manifest[int(target)]["block"] == block]
        expected = NEW_PER_BLOCK if evaluation_scope == "remaining96" else BLOCK_SIZE
        if len(positions) != expected:
            raise RuntimeError("A448 statistic block cover differs")
        block_gains.append(uniform_log_rank() - float(logs[positions].mean()))
    return {
        "evaluation_scope": evaluation_scope,
        "evaluation_targets": int(indices.size),
        "truth_ranks": true_ranks.tolist(),
        "fixed_block_bit_gains": block_gains,
        "minimum_fixed_block_bit_gain": float(min(block_gains)),
        "balanced_eight_block_bit_gain": float(sum(block_gains) / BLOCKS),
        "aggregate_bit_gain": float(uniform_log_rank() - logs.mean()),
        "positive_fixed_block_count": sum(gain > 0.0 for gain in block_gains),
        "targets_at_or_above_median_rank": int(np.count_nonzero(true_ranks <= CELLS // 2)),
        "worst_rank": int(true_ranks.max()),
    }


def selection_key(row: Mapping[str, Any]) -> tuple[float | int, ...]:
    return (
        -float(row["minimum_fixed_block_bit_gain"]),
        -float(row["balanced_eight_block_bit_gain"]),
        -float(row["aggregate_bit_gain"]),
        -int(row["targets_at_or_above_median_rank"]),
        int(row["worst_rank"]),
        OPERATORS.index(str(row["operator"])),
    )


def fixed_no_refit_evaluation(
    rank_fields: np.ndarray,
    truths: np.ndarray,
    borda: np.ndarray,
    feature_names: Sequence[str],
    a447_result: Mapping[str, Any],
) -> tuple[dict[str, Any], dict[str, np.ndarray], np.ndarray]:
    order = np.asarray(a447_result["selected_full_model"]["complete_feature_order"], dtype=np.int64)
    if (
        order.shape != (rank_fields.shape[1],)
        or set(order.tolist()) != set(range(rank_fields.shape[1]))
        or [str(feature_names[index]) for index in order[:64]]
        != a447_result["selected_full_model"]["top64_feature_names"]
    ):
        raise RuntimeError("A448 fixed A447 feature order differs")
    remaining = np.asarray(
        [row["target_index"] for row in complete_manifest() if not row["reused_from_A447"]],
        dtype=np.int64,
    )
    fields = {operator: np.zeros((TARGETS, CELLS), dtype=np.int16) for operator in OPERATORS}
    fields[OPERATORS[0]][:] = borda
    exact = np.arange(1, CELLS + 1, dtype=np.int16)
    for operator in OPERATORS[1:]:
        for target in remaining:
            cell_order = A447.operator_order(rank_fields[target], borda[target], order, operator)
            fields[operator][target, cell_order] = exact
    evaluations: dict[str, Any] = {}
    for operator in OPERATORS:
        field = fields[operator]
        if any(set(field[target].tolist()) != set(range(1, CELLS + 1)) for target in remaining):
            raise RuntimeError(f"A448 nonexact fixed operator field: {operator}")
        evaluations[operator] = {
            "operator": operator,
            "evaluation_mode": "A447_fixed_model_no_refit_remaining96",
            **statistics(field, truths, remaining, evaluation_scope="remaining96"),
            "rank_field_sha256": array_sha256(field[remaining], "<i2"),
        }
    return evaluations, fields, order


def complete128_crossfit(
    rank_fields: np.ndarray,
    truths: np.ndarray,
    borda: np.ndarray,
    feature_names: Sequence[str],
) -> tuple[dict[str, Any], str, dict[str, np.ndarray]]:
    fields = {operator: np.empty((TARGETS, CELLS), dtype=np.int16) for operator in OPERATORS}
    fields[OPERATORS[0]][:] = borda
    ledgers: dict[str, list[dict[str, Any]]] = {operator: [] for operator in OPERATORS}
    exact = np.arange(1, CELLS + 1, dtype=np.int16)
    for block in range(BLOCKS):
        train, held = block_partition(block)
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
                "model_sha256": "fixed:A442_borda_sum_full128",
            }
        )
        for operator in OPERATORS[1:]:
            for target in held:
                cell_order = A447.operator_order(rank_fields[target], borda[target], order, operator)
                fields[operator][target, cell_order] = exact
            ledgers[operator].append(model)
    evaluations: dict[str, Any] = {}
    all_targets = np.arange(TARGETS, dtype=np.int64)
    for operator in OPERATORS:
        field = fields[operator]
        if any(set(field[target].tolist()) != set(range(1, CELLS + 1)) for target in all_targets):
            raise RuntimeError(f"A448 nonexact crossfit operator field: {operator}")
        evaluations[operator] = {
            "operator": operator,
            "evaluation_mode": "eight_fold_sixteen_target_block_exclusive_crossfit",
            **statistics(field, truths, all_targets, evaluation_scope="complete128"),
            "rank_field_sha256": array_sha256(field, "<i2"),
            "fold_ledger": ledgers[operator],
        }
    selected = min(OPERATORS, key=lambda operator: selection_key(evaluations[operator]))
    return evaluations, selected, fields


def signal_eligible(
    evaluations: Mapping[str, Mapping[str, Any]], baseline_operator: str
) -> list[str]:
    baseline_hash = evaluations[baseline_operator]["rank_field_sha256"]
    return [
        operator
        for operator in OPERATORS[1:]
        if int(evaluations[operator]["positive_fixed_block_count"]) == BLOCKS
        and float(evaluations[operator]["balanced_eight_block_bit_gain"]) >= SIGNAL_GAIN_GATE
        and evaluations[operator]["rank_field_sha256"] != baseline_hash
    ]


def build_causal(payload: Mapping[str, Any]) -> dict[str, Any]:
    if str(DOTCAUSAL_SRC) not in sys.path:
        sys.path.insert(0, str(DOTCAUSAL_SRC))
    from dotcausal.io import CausalReader, CausalWriter

    ready = bool(payload["W52_proof_trace_ready"])
    terminal = "A448:target_blind_W52_proof_trace_ready" if ready else "A448:typed_ancestry_subgraph_frontier"
    writer = CausalWriter(api_id="a448full")
    writer._rules = []
    writer.add_rule(
        name="A447_scale_to_complete128",
        description="Reuse the exact A447 32-target corpus and measure the disjoint remaining 96 targets with the frozen helper.",
        pattern=["A447_proof_antecedent_full128_scale_ready"],
        conclusion="A448_complete128_proof_antecedent_corpus",
        confidence_modifier=1.0,
    )
    writer.add_rule(
        name="frozen_model_to_no_refit_transfer",
        description="Apply A447's fixed feature order and operator to the 96 targets that did not participate in A447 fitting.",
        pattern=["A448_complete128_proof_antecedent_corpus"],
        conclusion="A448_remaining96_no_refit_transfer",
        confidence_modifier=1.0,
    )
    writer.add_rule(
        name="complete_corpus_to_crossfit_portfolio",
        description="Crossfit eight full sixteen-target blocks and fit the final complete128 feature order after prospective transfer evaluation.",
        pattern=["A448_remaining96_no_refit_transfer"],
        conclusion="A448_complete128_crossfit_portfolio",
        confidence_modifier=1.0,
    )
    writer.add_rule(
        name="signal_gates_to_W52",
        description="Open W52 only as a target-blind portfolio when fixed transfer or complete128 crossfit retains a proof-derived signal in all eight blocks.",
        pattern=["A448_complete128_crossfit_portfolio"],
        conclusion=terminal.replace(":", "_"),
        confidence_modifier=1.0,
    )
    triplets = [
        (
            "A447:proof_antecedent_full128_scale_ready",
            "frozen_helper_remaining96_measurement_plus_exact_A447_reuse",
            "A448:complete128_proof_antecedent_corpus",
            payload["measurement_cover_sha256"],
            payload["measurement_summary"],
        ),
        (
            "A448:complete128_proof_antecedent_corpus",
            "A447_fixed_model_no_refit_remaining96_evaluation",
            "A448:remaining96_no_refit_transfer",
            payload["fixed_transfer_sha256"],
            payload["primary_no_refit_evaluation"],
        ),
        (
            "A448:remaining96_no_refit_transfer",
            "eight_complete_block_crossfit_and_full128_fit",
            "A448:complete128_crossfit_portfolio",
            payload["complete128_crossfit_sha256"],
            payload["portfolio_decision"],
        ),
        (
            "A448:complete128_crossfit_portfolio",
            "predeclared_proof_signal_open_gate",
            terminal,
            payload["portfolio_decision_sha256"],
            payload["portfolio_decision"],
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
            domain="full-round ChaCha20 R20 proof-antecedent transfer",
            quality_score=1.0,
        )
    writer.add_triplet(
        trigger="A447:proof_antecedent_full128_scale_ready",
        mechanism="materialized_complete128_transfer_decision_closure",
        outcome=terminal,
        confidence=1.0,
        source="materialized:A448_complete128_chain",
        quantification="exact retained closure",
        evidence=payload["evidence_stage"],
        domain="AI-native retained inference",
        quality_score=1.0,
        is_inferred=True,
    )
    writer.add_cluster(
        name="A448 complete128 proof transfer",
        entities=[
            "A447:proof_antecedent_full128_scale_ready",
            "A448:complete128_proof_antecedent_corpus",
            "A448:remaining96_no_refit_transfer",
            "A448:complete128_crossfit_portfolio",
            terminal,
        ],
    )
    writer.add_gap(
        subject=terminal,
        predicate="next_required_object",
        expected_object_type=(
            "target_blind_W52_proof_antecedent_trace" if ready else "stable_h8_position5_position4_typed_subgraph"
        ),
        confidence=1.0,
        suggested_queries=[
            "Trace the frozen complete128 proof portfolio on W52 without labels, refits, or altered stopping."
            if ready
            else "Resolve the h8 position-5/position-4 ancestry path on the complete corpus before W52."
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
        reader.api_id != "a448full"
        or len(explicit) != 4
        or len(all_rows) != 5
        or len(inferred) != 1
        or len(reader._rules) != 4
        or len(reader._clusters) != 1
        or len(reader._gaps) != 1
    ):
        raise RuntimeError("A448 authentic Causal reopen gate failed")
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
            "no_refit_transfer": explicit[1],
            "crossfit": explicit[2],
            "decision": explicit[3],
            "terminal_chain": all_rows[-1],
            "next_gap": reader._gaps[0],
        },
    }


def build_result(*, expected_implementation_sha256: str) -> dict[str, Any]:
    if RESULT.exists() or CAUSAL.exists() or REPORT.exists():
        raise FileExistsError("A448 result already exists")
    try:
        load_design()
        implementation = load_implementation(expected_implementation_sha256)
        a447_result = load_a447_result()
        measurements, ledgers = load_complete_measurements()
        if any(
            not row["reused_from_A447"]
            and measurements[index]["implementation_sha256"] != expected_implementation_sha256
            for index, row in enumerate(complete_manifest())
        ):
            raise RuntimeError("A448 new measurement implementation binding differs")
        borda, truths, borda_contract = reconstruct_borda()
        rank_fields, feature_names, feature_contract = build_rank_panel(measurements, borda)

        fixed_evaluations, _fixed_fields, fixed_order = fixed_no_refit_evaluation(
            rank_fields, truths, borda, feature_names, a447_result
        )
        primary = fixed_evaluations[PRIMARY_OPERATOR]
        fixed_eligible = signal_eligible(fixed_evaluations, OPERATORS[0])
        best_fixed = (
            min(fixed_eligible, key=lambda operator: selection_key(fixed_evaluations[operator]))
            if fixed_eligible
            else None
        )

        crossfit_evaluations, crossfit_selected, _crossfit_fields = complete128_crossfit(
            rank_fields, truths, borda, feature_names
        )
        crossfit_eligible = signal_eligible(crossfit_evaluations, OPERATORS[0])
        best_crossfit = (
            min(
                crossfit_eligible,
                key=lambda operator: selection_key(crossfit_evaluations[operator]),
            )
            if crossfit_eligible
            else None
        )

        all_targets = np.arange(TARGETS, dtype=np.int64)
        full_order, full_model = feature_selection(rank_fields, truths, all_targets)
        portfolio_operator = best_crossfit or best_fixed
        final_model = {
            **full_model,
            "portfolio_operator": portfolio_operator,
            "complete_feature_order": full_order.tolist(),
            "top64_feature_names": [str(feature_names[index]) for index in full_order[:64]],
            "A447_fixed_feature_order_sha256": array_sha256(fixed_order, ">u4"),
        }
        final_model["model_sha256"] = canonical_sha256(final_model)

        proof_transfer_gate = bool(fixed_eligible)
        complete128_crossfit_gate = bool(crossfit_eligible)
        ready = bool(proof_transfer_gate or complete128_crossfit_gate)
        decision = {
            "primary_operator": PRIMARY_OPERATOR,
            "primary_no_refit_positive_blocks": primary["positive_fixed_block_count"],
            "primary_no_refit_minimum_bit_gain": primary["minimum_fixed_block_bit_gain"],
            "primary_no_refit_balanced_bit_gain": primary["balanced_eight_block_bit_gain"],
            "fixed_proof_eligible_operators": fixed_eligible,
            "best_fixed_proof_operator": best_fixed,
            "proof_transfer_gate": proof_transfer_gate,
            "complete128_crossfit_selected_operator": crossfit_selected,
            "complete128_proof_eligible_operators": crossfit_eligible,
            "best_complete128_proof_operator": best_crossfit,
            "complete128_crossfit_gate": complete128_crossfit_gate,
            "portfolio_operator": portfolio_operator,
            "W52_proof_trace_ready": ready,
        }
        proof_nodes = sum(int(value["run"]["summary"]["proof_derived_total"]) for value in measurements)
        proof_edges = sum(int(value["run"]["summary"]["proof_antecedent_total"]) for value in measurements)
        proof_missing = sum(int(value["run"]["summary"]["proof_missing_antecedent_total"]) for value in measurements)
        if proof_missing != 0:
            raise RuntimeError("A448 proof cover contains missing antecedents")
        evidence_stage = (
            "COMPLETE128_PROOF_ANTECEDENT_PORTFOLIO_W52_READY"
            if ready
            else "COMPLETE128_TYPED_ANCESTRY_SUBGRAPH_FRONTIER"
        )
        core: dict[str, Any] = {
            "schema": "chacha20-round20-w46-full128-proof-antecedent-transfer-a448-v1",
            "attempt_id": ATTEMPT_ID,
            "evidence_stage": evidence_stage,
            "design_sha256": DESIGN_SHA256,
            "implementation_sha256": expected_implementation_sha256,
            "implementation_commitment_sha256": implementation["implementation_commitment_sha256"],
            "measurement_ledger": ledgers,
            "measurement_summary": {
                "targets": TARGETS,
                "reused_A447_targets": REUSED_TARGETS,
                "new_A448_targets": NEW_TARGETS,
                "cells": TARGETS * CELLS,
                "solver_stages": TARGETS * CELLS * len(HORIZONS),
                "proof_nodes": proof_nodes,
                "proof_antecedent_edges": proof_edges,
                "missing_antecedents": proof_missing,
            },
            "borda_contract": borda_contract,
            "feature_contract": feature_contract,
            "fixed_A447_model_sha256": a447_result["selected_full_model_sha256"],
            "fixed_no_refit_evaluations": fixed_evaluations,
            "primary_no_refit_evaluation": primary,
            "complete128_crossfit_evaluations": crossfit_evaluations,
            "complete128_crossfit_selected_operator": crossfit_selected,
            "final_complete128_model": final_model,
            "final_complete128_model_sha256": final_model["model_sha256"],
            "portfolio_decision": decision,
            "W52_proof_trace_ready": ready,
            "W52_target_labels_used": 0,
            "W52_model_refits": 0,
            "W52_new_solver_stages": 0,
            "candidate_assignments_executed": 0,
            "A426_A438_A440_A443_secret_result_stop_or_worker_progress_read": False,
            "anchors": {
                "design": anchor(DESIGN, DESIGN_SHA256),
                "implementation": anchor(IMPLEMENTATION, expected_implementation_sha256),
                "runner": anchor(Path(__file__)),
                "A447_result": anchor(A447_RESULT, A447_RESULT_SHA256),
                "A447_causal": anchor(A447_CAUSAL, A447_CAUSAL_SHA256),
                "A447_personal_readback": anchor(A447_READBACK, A447_READBACK_SHA256),
                "A442_result": anchor(A442_RESULT, A442_RESULT_SHA256),
                "proof_wrapper": anchor(A447.WRAPPER_PATH),
                "feature_source": anchor(A447.FEATURE_SOURCE),
                "native_source": anchor(A447.NATIVE_SOURCE),
            },
        }
        core["measurement_cover_sha256"] = canonical_sha256(ledgers)
        core["proof_cover_sha256"] = canonical_sha256(core["measurement_summary"])
        core["feature_contract_sha256"] = canonical_sha256(feature_contract)
        core["fixed_transfer_sha256"] = canonical_sha256(fixed_evaluations)
        core["complete128_crossfit_sha256"] = canonical_sha256(crossfit_evaluations)
        core["portfolio_decision_sha256"] = canonical_sha256(decision)
        core["result_commitment_sha256"] = canonical_sha256(
            {
                "design_sha256": DESIGN_SHA256,
                "implementation_commitment_sha256": core["implementation_commitment_sha256"],
                "measurement_cover_sha256": core["measurement_cover_sha256"],
                "proof_cover_sha256": core["proof_cover_sha256"],
                "feature_contract_sha256": core["feature_contract_sha256"],
                "fixed_transfer_sha256": core["fixed_transfer_sha256"],
                "complete128_crossfit_sha256": core["complete128_crossfit_sha256"],
                "portfolio_decision_sha256": core["portfolio_decision_sha256"],
                "W52_target_labels_used": 0,
                "W52_model_refits": 0,
                "W52_new_solver_stages": 0,
                "candidate_assignments_executed": 0,
            }
        )
        core["causal"] = build_causal(core)
        atomic_json(RESULT, core)
        report = (
            "# A448 — Complete-128 proof-antecedent transfer\n\n"
            f"Evidence stage: **{evidence_stage}**\n\n"
            f"- Exact proof nodes / edges: **{proof_nodes:,} / {proof_edges:,}**\n"
            f"- Missing antecedents: **{proof_missing}**\n"
            f"- Fixed primary remaining96 minimum / balanced gain: **{primary['minimum_fixed_block_bit_gain']:+.9f} / {primary['balanced_eight_block_bit_gain']:+.9f} bits**\n"
            f"- Fixed proof-eligible operators: **{', '.join(fixed_eligible) or 'none'}**\n"
            f"- Complete128 proof-eligible operators: **{', '.join(crossfit_eligible) or 'none'}**\n"
            f"- W52 proof trace ready: **{ready}**\n"
            "- W52 labels / refits / stages / candidate executions: **0 / 0 / 0 / 0**\n"
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
        raise RuntimeError("A448 result hash differs")
    value = json.loads(RESULT.read_bytes())
    if (
        value.get("schema") != "chacha20-round20-w46-full128-proof-antecedent-transfer-a448-v1"
        or value.get("attempt_id") != ATTEMPT_ID
        or value.get("W52_target_labels_used") != 0
        or value.get("W52_model_refits") != 0
        or value.get("W52_new_solver_stages") != 0
        or value.get("candidate_assignments_executed") != 0
    ):
        raise RuntimeError("A448 result semantics differ")
    for row in value["anchors"].values():
        anchor(path_from_ref(row["path"]), row["sha256"])
    anchor(path_from_ref(value["causal"]["path"]), value["causal"]["sha256"])
    return value


def analyze() -> dict[str, Any]:
    load_design()
    manifest = complete_manifest()
    new_jobs = [row for row in manifest if not row["reused_from_A447"]]
    payload: dict[str, Any] = {
        "attempt_id": ATTEMPT_ID,
        "design_sha256": file_sha256(DESIGN),
        "manifest_sha256": canonical_sha256(manifest),
        "implementation_frozen": IMPLEMENTATION.exists(),
        "reused_A447_targets": REUSED_TARGETS,
        "new_measurements_present": sum(
            new_measurement_path(int(row["target_index"])).exists() for row in new_jobs
        ),
        "new_measurements_complete": all(
            new_measurement_path(int(row["target_index"])).exists() for row in new_jobs
        ),
        "result_complete": RESULT.exists(),
        "primary_operator": PRIMARY_OPERATOR,
    }
    if IMPLEMENTATION.exists():
        payload["implementation_sha256"] = file_sha256(IMPLEMENTATION)
        load_implementation(payload["implementation_sha256"])
    if RESULT.exists():
        payload["result_sha256"] = file_sha256(RESULT)
        result = load_result(payload["result_sha256"])
        payload["evidence_stage"] = result["evidence_stage"]
        payload["W52_proof_trace_ready"] = result["W52_proof_trace_ready"]
        payload["portfolio_operator"] = result["portfolio_decision"]["portfolio_operator"]
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

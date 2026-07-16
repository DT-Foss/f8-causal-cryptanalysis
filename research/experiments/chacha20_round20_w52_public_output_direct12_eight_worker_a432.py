#!/usr/bin/env python3
"""A432: build a zero-refit W52 Direct12 order and exact eight-worker schedule."""

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
import tempfile
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
ARTIFACTS = RESEARCH / "artifacts/a432_chacha20_r20_w52_public_output_direct12"
MEASUREMENTS = RESULTS / "chacha20_round20_w52_public_output_direct12_eight_worker_a432_v1"

STEM = "chacha20_round20_w52_public_output_direct12_eight_worker_a432"
DESIGN = CONFIGS / f"{STEM}_design_v1.json"
IMPLEMENTATION = CONFIGS / f"{STEM}_implementation_v1.json"
PREFLIGHT = RESULTS / f"{STEM}_preflight_v1.json"
RESULT = RESULTS / f"{STEM}_v1.json"
CAUSAL = RESULT.with_suffix(".causal")
REPORT = RESULT.with_suffix(".md")
BASE_CNF = ARTIFACTS / "a432_a426_public_output_w52_b1.cnf"
TEST = ROOT / "tests/test_chacha20_round20_w52_public_output_direct12_eight_worker_a432.py"
REPRO = ROOT / "scripts/reproduce_chacha20_round20_w52_public_output_direct12_eight_worker_a432.sh"

A426_PROTOCOL = CONFIGS / "chacha20_round20_w52_a416_fresh_shared_stop_recovery_a426_v1.json"
A426_RESULT = RESULTS / "chacha20_round20_w52_a416_fresh_shared_stop_recovery_a426_v1.json"
A426_STOP = (
    RESULTS / "chacha20_round20_w52_a416_fresh_shared_stop_recovery_a426_confirmed_stop_v1.json"
)
A426_RUNNER = RESEARCH / "experiments/chacha20_round20_w52_a416_fresh_shared_stop_recovery_a426.py"
A388_RUNNER = RESEARCH / "experiments/chacha20_round20_w50_public_output_direct12_factor3_a388.py"
A349_SELECTION = (
    CONFIGS / "chacha20_round20_w46_direct12_prospective_a345_validation_a349_selection_v1.json"
)
A342_RESULT = RESULTS / "chacha20_round20_w46_exhaustive_reader_ensemble_a342_v1.json"
A348_RESULT = RESULTS / "chacha20_round20_w46_direct12_sliced_reader_a348_v1.json"
A428_RESULT = RESULTS / "chacha20_round20_w50_global_best_rank_wavefront_a428_v1.json"
A428_CAUSAL = A428_RESULT.with_suffix(".causal")
A430_RESULT = RESULTS / "chacha20_round20_w51_public_output_direct12_eight_worker_a430_v1.json"
A430_CAUSAL = A430_RESULT.with_suffix(".causal")

ATTEMPT_ID = "A432"
DESIGN_SHA256 = "96276bae59562911398585bff6d8be5fc9f5c23008a0b50168a411468c5b388e"
A426_PROTOCOL_SHA256 = "746c880115464383247ee0ef8d52d6095195f26fa4b69178a8de281cd4c483a3"
A426_RUNNER_SHA256 = "d849065a0bc33f1d3eff3f5b7638948c86b683f8020bfd8a0f5ed0e9ca449637"
A388_RUNNER_SHA256 = "36c933ae5003f92f2b96efb2e30d97c30bf8301bfcaa790333a6712f3041b5a9"
A349_SELECTION_SHA256 = "4f33a99b859044ed79d933b813486dba195e37438bc9afcf32b21d31d2d6c422"
A342_RESULT_SHA256 = "8d6d6f99b89d67d7eff186037934bfa515cf93a00af10b244826f44056b4cebb"
A348_RESULT_SHA256 = "f09bba039b26c8b78804f48169df62db167a9d95fbfff91e7099a01c1be1c812"
A428_RESULT_SHA256 = "dbf8fd33558bfde4e8e6833e6d69df1b57fcf8732fec28d35828b39e3cce0584"
A428_CAUSAL_SHA256 = "52a61beb8605fe54b9db66a5ba156b683dfc7dc0270e2a8a202a6f7a70ab0762"
A430_RESULT_SHA256 = "12c3f60fbc7dde8bbaa32ff7d13272a422b094d999a3c99ae16f1efd4c21f89a"
A430_CAUSAL_SHA256 = "3e55b2bc31bc005d0857f1135bfc9565d49cb069cb887f8decd382626c2db987"

WIDTH = 52
PREFIX_BITS = 12
LOW_BITS = 4
CELLS = 1 << PREFIX_BITS
COARSE_CELLS = 1 << (PREFIX_BITS - LOW_BITS)
SLICES = tuple(range(1 << LOW_BITS))
HORIZONS = [1, 2, 4, 8]
WORKERS = 8
EPOCHS = CELLS // WORKERS
WORKER_ROLES = tuple(f"direct_wave_{index}" for index in range(WORKERS))
WATCHDOG_SECONDS = 2.0
ZSTD_LEVEL = 10
SELECTED_VIEW = "A342_selected_pair_slice_z"
MASK32 = 0xFFFFFFFF
DOTCAUSAL_SRC = Path("/Users/bhkmie/Documents/Forschung/O1/vendor/fabel/dotcausal_package/src")


def load_module(path: Path, name: str) -> Any:
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot import A432 dependency {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


A388 = load_module(A388_RUNNER, "a432_a388")
file_sha256 = A388.file_sha256
canonical_sha256 = A388.canonical_sha256
canonical_bytes = A388.canonical_bytes
atomic_json = A388.atomic_json
atomic_bytes = A388.atomic_bytes
relative = A388.relative
path_from_ref = A388.path_from_ref
anchor = A388.anchor
sha256 = A388.sha256


def load_design() -> dict[str, Any]:
    if file_sha256(DESIGN) != DESIGN_SHA256:
        raise RuntimeError("A432 design hash differs")
    value = json.loads(DESIGN.read_bytes())
    measurement = value.get("measurement_contract", {})
    reader = value.get("reader_contract", {})
    schedule = value.get("schedule_contract", {})
    boundary = value.get("information_boundary", {})
    if (
        value.get("schema")
        != "chacha20-round20-w52-public-output-direct12-eight-worker-a432-design-v1"
        or value.get("attempt_id") != ATTEMPT_ID
        or value.get("design_state")
        != "frozen_after_A426_public_challenge_and_A430_W51_transfer_before_any_A432_measurement_schedule_candidate_or_A426_recovery_outcome"
        or measurement.get("unknown_key_bits") != WIDTH
        or measurement.get("complete_direct_prefix_cells") != CELLS
        or measurement.get("complete_solver_stages") != CELLS * len(HORIZONS)
        or measurement.get("low4_fixed_unit_coordinates") != list(low4_coordinates(WIDTH))
        or reader.get("selected_view") != SELECTED_VIEW
        or reader.get("model_or_weight_refits_on_A426") != 0
        or schedule.get("workers") != WORKERS
        or schedule.get("worker_tasks_each") != EPOCHS
        or schedule.get("production_execution_in_A432") is not False
        or boundary.get("A426_assignment_or_true_prefix_available_at_design_freeze") is not False
        or boundary.get("A426_recovery_result_available_at_design_freeze") is not False
        or boundary.get("A426_progress_or_filter_outcomes_consumed") is not False
        or boundary.get("A432_target_labels_used") != 0
        or boundary.get("A432_reader_refits") != 0
        or boundary.get("A432_candidate_assignments_executed") != 0
    ):
        raise RuntimeError("A432 frozen design semantics differ")
    for key, item in value["source_anchors"].items():
        if key.endswith("_path"):
            stem = key.removesuffix("_path")
            anchor(ROOT / item, value["source_anchors"][f"{stem}_sha256"])
    return value


def assert_pre_a426_result() -> None:
    outcome_paths = [
        A426_RESULT,
        A426_STOP,
        *(
            RESULTS
            / f"chacha20_round20_w52_a416_fresh_shared_stop_recovery_a426_worker_{index}_progress_v1.json"
            for index in range(WORKERS)
        ),
    ]
    if any(path.exists() for path in outcome_paths):
        raise RuntimeError("A432 schedule construction must precede every A426 outcome")


def load_a426_protocol(expected_sha256: str = A426_PROTOCOL_SHA256) -> dict[str, Any]:
    if file_sha256(A426_PROTOCOL) != expected_sha256:
        raise RuntimeError("A432 A426 protocol hash differs")
    value = json.loads(A426_PROTOCOL.read_bytes())
    challenge = value.get("public_challenge", {})
    if (
        value.get("schema")
        != "chacha20-round20-w52-a416-fresh-shared-stop-recovery-a426-protocol-v1"
        or value.get("attempt_id") != "A426"
        or value.get("workers") != WORKERS
        or value.get("worker_tasks_each") != EPOCHS
        or value.get("complete_cover_cells") != CELLS
        or value.get("duplicate_cells") != 0
        or value.get("uncovered_cells") != 0
        or challenge.get("unknown_key_bits") != WIDTH
        or challenge.get("unknown_assignment_included") is not False
        or "assignment" in challenge
        or "candidate" in challenge
        or "prefix12" in challenge
        or canonical_sha256(challenge) != value.get("public_challenge_sha256")
    ):
        raise RuntimeError("A432 A426 public protocol semantics differ")
    return value


def freeze_implementation() -> dict[str, Any]:
    if any(
        path.exists()
        for path in (
            IMPLEMENTATION,
            PREFLIGHT,
            RESULT,
            CAUSAL,
            REPORT,
            MEASUREMENTS,
            ARTIFACTS,
        )
    ):
        raise FileExistsError("A432 implementation or target artifacts already exist")
    assert_pre_a426_result()
    load_design()
    load_a426_protocol()
    if not TEST.exists() or not REPRO.exists():
        raise FileNotFoundError("A432 test and reproducer must precede implementation freeze")
    payload: dict[str, Any] = {
        "schema": "chacha20-round20-w52-public-output-direct12-eight-worker-a432-implementation-v1",
        "attempt_id": ATTEMPT_ID,
        "commitment_state": "complete_W52_measurement_and_eight_worker_schedule_code_frozen_before_any_A432_measurement_candidate_or_A426_result",
        "design_sha256": DESIGN_SHA256,
        "selected_view": SELECTED_VIEW,
        "A426_result_available_at_implementation_freeze": False,
        "A432_measurements_available_at_implementation_freeze": 0,
        "A432_candidate_assignments_available_at_implementation_freeze": 0,
        "anchors": {
            "design": anchor(DESIGN, DESIGN_SHA256),
            "A426_protocol": anchor(A426_PROTOCOL, A426_PROTOCOL_SHA256),
            "A426_runner": anchor(A426_RUNNER, A426_RUNNER_SHA256),
            "A388_runner": anchor(A388_RUNNER, A388_RUNNER_SHA256),
            "A349_selection": anchor(A349_SELECTION, A349_SELECTION_SHA256),
            "A342_result": anchor(A342_RESULT, A342_RESULT_SHA256),
            "A348_result": anchor(A348_RESULT, A348_RESULT_SHA256),
            "A428_result": anchor(A428_RESULT, A428_RESULT_SHA256),
            "A428_causal": anchor(A428_CAUSAL, A428_CAUSAL_SHA256),
            "A430_result": anchor(A430_RESULT, A430_RESULT_SHA256),
            "A430_causal": anchor(A430_CAUSAL, A430_CAUSAL_SHA256),
            "runner": anchor(Path(__file__)),
            "test": anchor(TEST),
            "reproducer": anchor(REPRO),
        },
    }
    payload["implementation_commitment_sha256"] = canonical_sha256(payload)
    atomic_json(IMPLEMENTATION, payload)
    assert_pre_a426_result()
    return payload


def load_implementation(expected_sha256: str) -> dict[str, Any]:
    if file_sha256(IMPLEMENTATION) != expected_sha256:
        raise RuntimeError("A432 implementation hash differs")
    value = json.loads(IMPLEMENTATION.read_bytes())
    if (
        value.get("schema")
        != "chacha20-round20-w52-public-output-direct12-eight-worker-a432-implementation-v1"
        or value.get("attempt_id") != ATTEMPT_ID
        or value.get("design_sha256") != DESIGN_SHA256
        or value.get("selected_view") != SELECTED_VIEW
        or value.get("A426_result_available_at_implementation_freeze") is not False
        or value.get("A432_measurements_available_at_implementation_freeze") != 0
        or value.get("A432_candidate_assignments_available_at_implementation_freeze") != 0
    ):
        raise RuntimeError("A432 implementation semantics differ")
    for row in value["anchors"].values():
        anchor(path_from_ref(row["path"]), row["sha256"])
    unsigned = {
        key: item for key, item in value.items() if key != "implementation_commitment_sha256"
    }
    if value.get("implementation_commitment_sha256") != canonical_sha256(unsigned):
        raise RuntimeError("A432 implementation commitment differs")
    return value


def bridge_challenge(protocol: Mapping[str, Any]) -> dict[str, Any]:
    source = protocol["public_challenge"]
    remainder = WIDTH - 32
    masks = [0, (~((1 << remainder) - 1)) & MASK32, *([MASK32] * 6)]
    known = [int(value) & MASK32 for value in source["known_zeroed_key_words"]]
    values = [value & mask for value, mask in zip(known, masks, strict=True)]
    bridge = {
        "challenge_id": "A432-bridge-" + str(source["challenge_id"]),
        "rounds": 20,
        "block_count": 8,
        "counter_schedule": "base_plus_block_index_mod_2^32",
        "counter_start": int(source["counter_start"]),
        "nonce_words": [int(value) for value in source["nonce_words"]],
        "known_key_bits": 256 - WIDTH,
        "known_key_mask_words": masks,
        "known_key_value_words": values,
        "unknown_key_bits": WIDTH,
        "unknown_global_bit_interval": [0, WIDTH - 1],
        "unknown_bit_numbering": "little_endian_bit0_upward_across_key_words_k0_through_k7",
        "unknown_assignment_included": False,
        "unknown_assignment_value_included": False,
        "full_key_included": False,
        "secret_used_only_for_target_construction": True,
        "secret_discarded_after_target_construction": True,
        "generation_entropy_source": "python_secrets_token_bytes_OS_CSPRNG",
        "target_words": [
            [int(word) & MASK32 for word in block] for block in source["target_words"]
        ],
        "target_block_sha256": list(source["target_block_sha256"]),
        "control_target_words": [int(word) & MASK32 for word in source["control_target_words"]],
        "control_target_block_sha256": source["control_target_block_sha256"],
    }
    if bridge["known_key_mask_words"][1] != 0xFFF00000:
        raise RuntimeError("A432 W52 known-mask codec differs")
    return bridge


def w52_source_formula(a223: Any, challenge: dict[str, Any]) -> str:
    formula = A388.A340.A296.b1_formula(a223, challenge, WIDTH)
    remainder = WIDTH % 32
    word = WIDTH // 32
    known_width = 32 - remainder
    known = int(challenge["known_key_value_words"][word]) >> remainder
    generated = f"(assert (= ((_ extract 31 {remainder}) k{word}) #x{known:0{known_width // 4}x}))"
    corrected = f"(assert (= ((_ extract 31 {remainder}) k{word}) #b{known:0{known_width}b}))"
    if formula.count(generated) != 1 or corrected in formula:
        raise RuntimeError("A432 W52 known-suffix correction boundary differs")
    result = formula.replace(generated, corrected)
    if result.count(corrected) != 1 or generated in result:
        raise RuntimeError("A432 W52 known-suffix correction failed")
    return result


def preflight(
    *, expected_implementation_sha256: str, expected_a426_protocol_sha256: str
) -> dict[str, Any]:
    if PREFLIGHT.exists() or ARTIFACTS.exists():
        raise FileExistsError("A432 preflight artifacts already exist")
    assert_pre_a426_result()
    implementation = load_implementation(expected_implementation_sha256)
    protocol = load_a426_protocol(expected_a426_protocol_sha256)
    bridge = bridge_challenge(protocol)
    a223 = A388.A340.load_module(A388.A340.A223_SOURCE, "a432_a223_preflight")
    config = json.loads(A388.A340.A223_CONFIG.read_bytes())
    a223._toolchain_gates(config)  # noqa: SLF001
    a223._validate_challenge(bridge, width=WIDTH)  # noqa: SLF001
    formula = w52_source_formula(a223, bridge)
    ARTIFACTS.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="a432_w52_b1_", dir=ARTIFACTS.parent) as temporary:
        directory = Path(temporary)
        temporary_cnf = directory / "base.cnf"
        export = a223._export_cnf(  # noqa: SLF001
            formula=formula,
            output=temporary_cnf,
            config=config,
            label="A432_A426_W52_B1_DIRECT12",
        )
        raw = temporary_cnf.read_bytes()
        lines = raw.splitlines(keepends=True)
        header = lines[0].split() if lines else []
        if len(header) != 4 or header[:2] != [b"p", b"cnf"]:
            raise RuntimeError("A432 base CNF header differs")
        context = {
            "width": WIDTH,
            "formula": formula,
            "formula_bytes": len(formula.encode()),
            "formula_sha256": sha256(formula.encode()),
            "base_path": temporary_cnf,
            "base_raw": raw,
            "base_body": b"".join(lines[1:]),
            "base_body_sha256": sha256(b"".join(lines[1:])),
            "variable_count": int(header[2]),
            "clause_count": int(header[3]),
            "base_export": export,
        }
        probes = [
            a223._coordinate_probe(  # noqa: SLF001
                context=context,
                dimension=dimension,
                config=config,
                directory=directory,
            )
            for dimension in range(-1, math.ceil(math.log2(WIDTH)))
        ]
        mapping = a223._decode_mapping(  # noqa: SLF001
            [(dimension, units) for _, dimension, units, _ in probes], width=WIDTH
        )
        ARTIFACTS.mkdir(parents=False, exist_ok=False)
        atomic_bytes(BASE_CNF, raw)
    synthetic = A388.A340.A296.synthetic_reader_mapping(mapping, WIDTH)
    if len(mapping) != WIDTH or len(synthetic) != 20:
        raise RuntimeError("A432 source or synthetic mapping differs")
    payload: dict[str, Any] = {
        "schema": "chacha20-round20-w52-public-output-direct12-eight-worker-a432-preflight-v1",
        "attempt_id": ATTEMPT_ID,
        "evidence_stage": "PRE_W52_RECOVERY_PUBLIC_OUTPUT_DIRECT12_CNF_AND_READER_FROZEN",
        "implementation_sha256": expected_implementation_sha256,
        "implementation_commitment_sha256": implementation["implementation_commitment_sha256"],
        "A426_protocol_sha256": expected_a426_protocol_sha256,
        "A426_public_challenge_sha256": protocol["public_challenge_sha256"],
        "bridge_challenge_sha256": canonical_sha256(bridge),
        "formula_sha256": sha256(formula.encode()),
        "CNF": anchor(BASE_CNF, export["sha256"]),
        "CNF_header": export["header"],
        "source_one_literals_bit0_upward": mapping,
        "source_mapping_sha256": canonical_sha256(mapping),
        "synthetic_reader_mapping": synthetic,
        "synthetic_reader_mapping_sha256": canonical_sha256(synthetic),
        "low4_coordinates": list(low4_coordinates(WIDTH)),
        "selected_view": SELECTED_VIEW,
        "target_labels_used": 0,
        "reader_refits": 0,
        "candidate_assignments_executed": 0,
        "A426_result_available_at_preflight": False,
        "A426_progress_or_filter_outcomes_consumed": False,
        "anchors": {
            "implementation": anchor(IMPLEMENTATION, expected_implementation_sha256),
            "A426_protocol": anchor(A426_PROTOCOL, expected_a426_protocol_sha256),
            "A426_runner": anchor(A426_RUNNER, A426_RUNNER_SHA256),
            "A349_selection": anchor(A349_SELECTION, A349_SELECTION_SHA256),
            "A342_result": anchor(A342_RESULT, A342_RESULT_SHA256),
            "A348_result": anchor(A348_RESULT, A348_RESULT_SHA256),
            "A430_result": anchor(A430_RESULT, A430_RESULT_SHA256),
            "A430_causal": anchor(A430_CAUSAL, A430_CAUSAL_SHA256),
            "runner": anchor(Path(__file__)),
        },
    }
    payload["preflight_commitment_sha256"] = canonical_sha256(payload)
    atomic_json(PREFLIGHT, payload)
    assert_pre_a426_result()
    return payload


def load_preflight(expected_sha256: str, expected_a426_protocol_sha256: str) -> dict[str, Any]:
    if file_sha256(PREFLIGHT) != expected_sha256:
        raise RuntimeError("A432 preflight hash differs")
    value = json.loads(PREFLIGHT.read_bytes())
    if (
        value.get("schema")
        != "chacha20-round20-w52-public-output-direct12-eight-worker-a432-preflight-v1"
        or value.get("A426_protocol_sha256") != expected_a426_protocol_sha256
        or value.get("A426_result_available_at_preflight") is not False
        or value.get("A426_progress_or_filter_outcomes_consumed") is not False
        or value.get("low4_coordinates") != list(low4_coordinates(WIDTH))
        or value.get("target_labels_used") != 0
        or value.get("reader_refits") != 0
        or value.get("candidate_assignments_executed") != 0
    ):
        raise RuntimeError("A432 preflight semantics differ")
    anchor(BASE_CNF, value["CNF"]["sha256"])
    return value


def low4_coordinates(width: int) -> tuple[int, int, int, int]:
    if width < PREFIX_BITS:
        raise ValueError("A432 width is smaller than Direct12")
    values = tuple(range(width - 9, width - 13, -1))
    if len(values) != LOW_BITS:
        raise RuntimeError("A432 low4 coordinate derivation differs")
    return values  # type: ignore[return-value]


def low4_unit_literals(low4: int, source_mapping: Sequence[int], width: int = WIDTH) -> list[int]:
    mapping = [int(value) for value in source_mapping]
    if not 0 <= low4 < len(SLICES) or len(mapping) != width:
        raise ValueError("A432 low4 slice or source mapping differs")
    result = []
    for offset, coordinate in enumerate(low4_coordinates(width)):
        one_literal = mapping[coordinate]
        bit = (low4 >> (LOW_BITS - 1 - offset)) & 1
        result.append(one_literal if bit else -one_literal)
    if len({abs(value) for value in result}) != LOW_BITS:
        raise RuntimeError("A432 low4 unit variables alias")
    return result


def render_slice_cnf(base_raw: bytes, *, low4: int, source_mapping: Sequence[int]) -> bytes:
    variables, clauses, body = A388.A348._base_cnf_parts(base_raw)  # noqa: SLF001
    units = low4_unit_literals(low4, source_mapping)
    suffix = b"".join(f"{literal} 0\n".encode("ascii") for literal in units)
    return f"p cnf {variables} {clauses + len(units)}\n".encode("ascii") + body + suffix


def slice_paths(low4: int) -> tuple[Path, Path]:
    return (
        ARTIFACTS / f"slice_{low4:02x}.cnf",
        MEASUREMENTS / f"slice_{low4:02x}.json.zst",
    )


def write_measurement(path: Path, value: Mapping[str, Any]) -> dict[str, Any]:
    raw = canonical_bytes(value)
    compressed = zstandard.ZstdCompressor(
        level=ZSTD_LEVEL,
        threads=0,
        write_checksum=True,
        write_content_size=True,
        write_dict_id=False,
    ).compress(raw)
    atomic_bytes(path, compressed)
    return {
        "path": relative(path),
        "raw_bytes": len(raw),
        "raw_sha256": sha256(raw),
        "compressed_bytes": len(compressed),
        "compressed_sha256": sha256(compressed),
    }


def read_measurement(path: Path, ledger: Mapping[str, Any] | None = None) -> dict[str, Any]:
    compressed = path.read_bytes()
    if ledger is not None and sha256(compressed) != ledger["compressed_sha256"]:
        raise RuntimeError("A432 compressed slice hash differs")
    raw = zstandard.ZstdDecompressor().decompress(compressed)
    if ledger is not None and sha256(raw) != ledger["raw_sha256"]:
        raise RuntimeError("A432 raw slice hash differs")
    value = json.loads(raw)
    if canonical_bytes(value) != raw:
        raise RuntimeError("A432 slice is not canonical")
    return value


def prepare_slices(preflight_value: Mapping[str, Any]) -> list[dict[str, Any]]:
    base_raw = BASE_CNF.read_bytes()
    mapping = preflight_value["source_one_literals_bit0_upward"]
    rows = []
    for low4 in SLICES:
        cnf_path, measurement_path = slice_paths(low4)
        expected = render_slice_cnf(base_raw, low4=low4, source_mapping=mapping)
        if cnf_path.exists() and cnf_path.read_bytes() != expected:
            raise RuntimeError(f"A432 slice CNF differs: {low4}")
        if not cnf_path.exists():
            atomic_bytes(cnf_path, expected)
        rows.append(
            {
                "low4": low4,
                "unit_literals": low4_unit_literals(low4, mapping),
                "cnf": anchor(cnf_path),
                "measurement_path": measurement_path,
            }
        )
    return rows


def validate_measurement(value: Mapping[str, Any], low4: int) -> None:
    run = value.get("run", {})
    if (
        value.get("schema")
        != "chacha20-round20-w52-public-output-direct12-eight-worker-a432-slice-v1"
        or value.get("low4") != low4
        or value.get("target_label_available_to_measurement") is not False
        or value.get("complete_candidate_cover") is not True
        or len(run.get("cells", [])) != COARSE_CELLS
        or len(run.get("stages", [])) != COARSE_CELLS * len(HORIZONS)
        or any(cell.get("final_status") != "unknown" for cell in run["cells"])
        or run.get("all_watchdogs_clear") is not True
    ):
        raise RuntimeError(f"A432 prospective slice gate failed: {low4}")


def run_slice(
    row: Mapping[str, Any], *, helper: Path, key_mapping: Sequence[int]
) -> dict[str, Any]:
    low4 = int(row["low4"])
    path = Path(row["measurement_path"])
    if path.exists():
        value = read_measurement(path)
        validate_measurement(value, low4)
        return {
            "low4": low4,
            "resumed": True,
            "ledger": write_measurement(path, value),
        }
    started = time.perf_counter()
    raw_run = A388.WRAPPER.run_fresh_clause_identity(
        helper=helper,
        cnf=path_from_ref(row["cnf"]["path"]),
        mode=f"A432_A426_W52_direct12_low4_{low4:02x}",
        order=[f"{value:08b}" for value in range(COARSE_CELLS)],
        key_one_literals_bit0_through_bit19=key_mapping,
        conflict_horizons=HORIZONS,
        watchdog_seconds=WATCHDOG_SECONDS,
        external_timeout_seconds=3600.0,
    )
    stable = {
        key: value
        for key, value in raw_run.items()
        if key not in {"command", "process_elapsed_seconds"}
    }
    value = {
        "schema": "chacha20-round20-w52-public-output-direct12-eight-worker-a432-slice-v1",
        "attempt_id": ATTEMPT_ID,
        "low4": low4,
        "fixed_unit_literals": list(row["unit_literals"]),
        "cnf_sha256": row["cnf"]["sha256"],
        "run": stable,
        "volatile_process_elapsed_seconds": time.perf_counter() - started,
        "target_label_available_to_measurement": False,
        "label_used_for_feature_construction_or_scoring": False,
        "complete_candidate_cover": len(stable.get("cells", [])) == COARSE_CELLS,
    }
    validate_measurement(value, low4)
    return {
        "low4": low4,
        "resumed": False,
        "ledger": write_measurement(path, value),
    }


def exact_order(values: Sequence[int], label: str = "A432 order") -> list[int]:
    order = [int(value) for value in values]
    if len(order) != CELLS or set(order) != set(range(CELLS)):
        raise ValueError(f"{label} is not one complete 4096-cell permutation")
    return order


def rank_vector(order: Sequence[int]) -> list[int]:
    ranks = [0] * CELLS
    for rank, cell in enumerate(exact_order(order), 1):
        ranks[cell] = rank
    return ranks


def uint16be_sha256(values: Sequence[int]) -> str:
    raw = b"".join(int(value).to_bytes(2, "big") for value in values)
    return hashlib.sha256(raw).hexdigest()


def direct_eight_worker_schedule(order: Sequence[int]) -> dict[str, Any]:
    complete = exact_order(order, "A432 Direct12")
    worker_orders: dict[str, list[int]] = {role: [] for role in WORKER_ROLES}
    worker_tasks: dict[str, list[dict[str, Any]]] = {role: [] for role in WORKER_ROLES}
    cell_epoch = [0] * CELLS
    cell_worker = [""] * CELLS
    direct_ranks = rank_vector(complete)
    for index, cell in enumerate(complete):
        worker = WORKER_ROLES[index % WORKERS]
        epoch = index // WORKERS + 1
        task = {
            "cell": cell,
            "epoch": epoch,
            "worker_role": worker,
            "worker_step_one_based": len(worker_tasks[worker]) + 1,
            "global_position_one_based": index + 1,
            "direct12_rank_one_based": direct_ranks[cell],
        }
        worker_orders[worker].append(cell)
        worker_tasks[worker].append(task)
        cell_epoch[cell] = epoch
        cell_worker[cell] = worker
    covered = [cell for role in WORKER_ROLES for cell in worker_orders[role]]
    depth_violations = sum(
        cell_epoch[cell] != math.ceil(direct_ranks[cell] / WORKERS) for cell in range(CELLS)
    )
    if (
        len(covered) != CELLS
        or len(set(covered)) != CELLS
        or any(len(worker_orders[role]) != EPOCHS for role in WORKER_ROLES)
        or depth_violations
    ):
        raise RuntimeError("A432 direct eight-worker schedule proof failed")
    return {
        "global_order": complete,
        "global_order_uint16be_sha256": A388.A351.order_sha256(complete),
        "worker_roles": list(WORKER_ROLES),
        "worker_cell_orders": worker_orders,
        "worker_tasks": worker_tasks,
        "worker_cell_order_uint16be_sha256": {
            role: uint16be_sha256(worker_orders[role]) for role in WORKER_ROLES
        },
        "worker_task_list_sha256": {
            role: canonical_sha256(worker_tasks[role]) for role in WORKER_ROLES
        },
        "cell_epoch_one_based": cell_epoch,
        "cell_worker_role": cell_worker,
        "proof": {
            "cells_checked": CELLS,
            "complete_cover_cells": len(covered),
            "duplicate_cells": len(covered) - len(set(covered)),
            "uncovered_cells": CELLS - len(set(covered)),
            "workers": WORKERS,
            "worker_tasks_each": EPOCHS,
            "makespan_epochs": max(cell_epoch),
            "theoretical_minimum_epochs": math.ceil(CELLS / WORKERS),
            "makespan_optimal": max(cell_epoch) == math.ceil(CELLS / WORKERS),
            "depth_identity": "D_A432(c) = ceil(R_Direct12(c)/8)",
            "depth_identity_violations": depth_violations,
        },
    }


def baseline_epoch_vector(worker_orders: Mapping[str, Sequence[int]]) -> list[int]:
    epochs = [0] * CELLS
    seen: set[int] = set()
    for role, values in worker_orders.items():
        order = [int(value) for value in values]
        if len(order) != EPOCHS:
            raise RuntimeError(f"A432 baseline worker length differs: {role}")
        for step, cell in enumerate(order, 1):
            if not 0 <= cell < CELLS or cell in seen:
                raise RuntimeError("A432 baseline schedule is not disjoint")
            seen.add(cell)
            epochs[cell] = step
    if seen != set(range(CELLS)) or any(value == 0 for value in epochs):
        raise RuntimeError("A432 baseline schedule does not cover all cells")
    return epochs


def rank_correlation(left: Sequence[int], right: Sequence[int]) -> float:
    left_ranks = np.asarray(rank_vector(left), dtype=np.float64)
    right_ranks = np.asarray(rank_vector(right), dtype=np.float64)
    return float(np.corrcoef(left_ranks, right_ranks)[0, 1])


def comparison_panel(direct_order: Sequence[int], direct_epochs: Sequence[int]) -> dict[str, Any]:
    a426 = load_a426_protocol()
    a426_epochs = baseline_epoch_vector(a426["worker_cell_orders"])
    if file_sha256(A430_RESULT) != A430_RESULT_SHA256:
        raise RuntimeError("A432 A430 result hash differs")
    a430 = json.loads(A430_RESULT.read_bytes())
    a430_order = exact_order(
        a430["W51_public_output_direct12_order"], "A432 A430 W51 Direct12 order"
    )
    a430_epochs = [int(value) for value in a430["cell_epoch_one_based"]]
    a430_ranks = rank_vector(a430_order)
    if len(a430_epochs) != CELLS or any(
        a430_epochs[cell] != math.ceil(a430_ranks[cell] / WORKERS) for cell in range(CELLS)
    ):
        raise RuntimeError("A432 A430 epoch identity differs")
    a428 = json.loads(A428_RESULT.read_bytes())
    if file_sha256(A428_RESULT) != A428_RESULT_SHA256:
        raise RuntimeError("A432 A428 result hash differs")
    a428_order = exact_order(a428["production_global_order"], "A432 A428 production global order")
    a428_epochs = [int(value) for value in a428["production_cell_epoch_one_based"]]
    a428_ranks = rank_vector(a428_order)
    if len(a428_epochs) != CELLS or any(
        a428_epochs[cell] != math.ceil(a428_ranks[cell] / WORKERS) for cell in range(CELLS)
    ):
        raise RuntimeError("A432 A428 epoch identity differs")

    def counts(baseline: Sequence[int]) -> list[int]:
        return [
            sum(new < old for new, old in zip(direct_epochs, baseline, strict=True)),
            sum(new == old for new, old in zip(direct_epochs, baseline, strict=True)),
            sum(new > old for new, old in zip(direct_epochs, baseline, strict=True)),
        ]

    direct = exact_order(direct_order)
    return {
        "population": "all_4096_unlabeled_cells",
        "A432_vs_A426_earlier_equal_later": counts(a426_epochs),
        "A432_vs_A430_earlier_equal_later": counts(a430_epochs),
        "A432_vs_A428_earlier_equal_later": counts(a428_epochs),
        "Direct12_W52_vs_W51_spearman": rank_correlation(direct, a430_order),
        "Direct12_W52_vs_W51_top32_overlap": len(set(direct[:32]) & set(a430_order[:32])),
        "Direct12_W52_vs_W51_top128_overlap": len(set(direct[:128]) & set(a430_order[:128])),
        "Direct12_vs_A428_global_order_spearman": rank_correlation(direct, a428_order),
        "Direct12_vs_A428_top32_overlap": len(set(direct[:32]) & set(a428_order[:32])),
        "Direct12_vs_A428_top128_overlap": len(set(direct[:128]) & set(a428_order[:128])),
        "target_labels_used": 0,
        "A426_progress_or_filter_outcomes_consumed": False,
    }


def build_causal(payload: Mapping[str, Any]) -> dict[str, Any]:
    sys.path.insert(0, str(DOTCAUSAL_SRC))
    from dotcausal.io import CausalReader, CausalWriter

    reader = "A342:frozen_pair_slice_Direct12_reader"
    field = "A432:complete_unlabeled_W52_public_output_field"
    schedule = "A432:exact_direct_eight_worker_schedule"
    executor = "A433:qualified_W52_complete_group_executor"
    writer = CausalWriter(api_id="a432w52")
    writer._rules = []
    writer.add_rule(
        name="frozen_reader_to_W52_public_order",
        description="The unchanged A342 Direct12 Reader consumes all 4,096 W52 public-output cells with zero labels and zero refits.",
        pattern=[
            "A342_frozen_pair_slice_Direct12_reader",
            "A432_complete_unlabeled_W52_public_output_field",
        ],
        conclusion="A432_exact_direct_eight_worker_schedule",
        confidence_modifier=1.0,
    )
    writer.add_rule(
        name="direct_order_to_exact_worker_depth",
        description="Round-robin assignment of the complete Direct12 order to eight workers gives D(c)=ceil(R(c)/8) and 512 exact epochs.",
        pattern=["A432_exact_direct_eight_worker_schedule"],
        conclusion="A433_qualified_W52_complete_group_executor",
        confidence_modifier=1.0,
    )
    writer.add_triplet(
        trigger=reader,
        mechanism="zero_refit_complete_A426_public_output_Direct12_measurement",
        outcome=field,
        confidence=1.0,
        source=payload["order_commitment_sha256"],
        quantification=json.dumps(payload["measurement_summary"], sort_keys=True),
        evidence="4,096 cells and 16,384 solver stages; zero labels, refits, candidates or A426 outcomes",
        domain="full-round ChaCha20 W52 public-output inference",
        quality_score=1.0,
    )
    writer.add_triplet(
        trigger=field,
        mechanism="exact_position_modulo_eight_worker_partition",
        outcome=schedule,
        confidence=1.0,
        source=payload["schedule_commitment_sha256"],
        quantification=json.dumps(payload["schedule_proof"], sort_keys=True),
        evidence=json.dumps(payload["unlabeled_schedule_comparison"], sort_keys=True),
        domain="complete W52 recovery scheduling",
        quality_score=1.0,
    )
    writer.add_triplet(
        trigger=reader,
        mechanism="materialized_W52_reader_to_schedule_to_executor_chain",
        outcome=executor,
        confidence=1.0,
        source="materialized:A432_W52_Direct12_chain",
        quantification="exact retained closure",
        evidence=payload["evidence_stage"],
        domain="AI-native retained inference",
        quality_score=1.0,
        is_inferred=True,
    )
    writer.add_cluster(
        name="A432 W52 public-output Direct12 execution chain",
        entities=[reader, field, schedule, executor],
    )
    writer.add_gap(
        subject=executor,
        predicate="next_required_object",
        expected_object_type="executed_fullround_W52_recovery_in_A432_schedule",
        confidence=1.0,
        suggested_queries=[
            "After A422 qualification, execute the eight disjoint A432 worker lists on the sealed A426 W52 challenge as A433."
        ],
    )
    temporary = CAUSAL.with_name(f".{CAUSAL.name}.tmp")
    temporary.unlink(missing_ok=True)
    stats = writer.save(str(temporary))
    os.replace(temporary, CAUSAL)
    causal_reader = CausalReader(str(CAUSAL), verify_integrity=True)
    explicit = causal_reader.get_all_triplets(include_inferred=False)
    all_rows = causal_reader.get_all_triplets(include_inferred=True)
    inferred = [row for row in causal_reader._triplets if row.get("is_inferred", False)]
    if (
        causal_reader.api_id != "a432w52"
        or len(explicit) != 2
        or len(all_rows) != 3
        or len(inferred) != 1
        or len(causal_reader._rules) != 2
        or len(causal_reader._clusters) != 1
        or len(causal_reader._gaps) != 1
    ):
        raise RuntimeError("A432 authentic Causal reopen gate failed")
    return {
        "format": "authentic_dotcausal_v1_AI_native",
        "path": relative(CAUSAL),
        "sha256": file_sha256(CAUSAL),
        "api_id": causal_reader.api_id,
        "explicit_triplets": len(explicit),
        "materialized_inferred_triplets": len(inferred),
        "embedded_rules": len(causal_reader._rules),
        "clusters": len(causal_reader._clusters),
        "gaps": len(causal_reader._gaps),
        "reader_source": anchor(Path(inspect.getsourcefile(CausalReader) or "")),
        "writer_stats": stats,
        "personal_semantic_readback": {
            "terminal_chain": all_rows[-1],
            "next_gap": causal_reader._gaps[0],
        },
    }


def measure(
    *,
    expected_implementation_sha256: str,
    expected_preflight_sha256: str,
    expected_a426_protocol_sha256: str,
) -> dict[str, Any]:
    if RESULT.exists() or CAUSAL.exists() or REPORT.exists():
        raise FileExistsError("A432 result artifacts already exist")
    assert_pre_a426_result()
    implementation = load_implementation(expected_implementation_sha256)
    frozen = load_preflight(expected_preflight_sha256, expected_a426_protocol_sha256)
    protocol = load_a426_protocol(expected_a426_protocol_sha256)
    rows = prepare_slices(frozen)
    _a275, _model, _a291, _indices, helper = A388.A340.A296._reader_stack()  # noqa: SLF001
    A388.WRAPPER._load_base_wrapper()  # noqa: SLF001
    MEASUREMENTS.mkdir(parents=True, exist_ok=True)
    started = time.perf_counter()
    completed = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=WORKERS) as executor:
        futures = [
            executor.submit(
                run_slice,
                row,
                helper=helper,
                key_mapping=frozen["synthetic_reader_mapping"],
            )
            for row in rows
        ]
        for future in concurrent.futures.as_completed(futures):
            completed.append(future.result())
    completed.sort(key=lambda row: row["low4"])
    if [row["low4"] for row in completed] != list(SLICES):
        raise RuntimeError("A432 complete slice cover differs")
    measurements = {
        row["low4"]: read_measurement(path_from_ref(row["ledger"]["path"]), row["ledger"])
        for row in completed
    }
    for low4, value in measurements.items():
        validate_measurement(value, low4)
    _selection, _a272, model, groups = A388.A341.reconstruct_known_key_selection(
        json.loads(A388.A341.DESIGN.read_bytes())
    )
    scores = A388.A349.selected_pair_slice_z_scores(measurements, model, groups)
    direct_order = A388.A348._rank_order(scores)  # noqa: SLF001
    schedule = direct_eight_worker_schedule(direct_order)
    comparison = comparison_panel(direct_order, schedule["cell_epoch_one_based"])
    ledgers = [
        {
            **row["ledger"],
            "low4": row["low4"],
            "resumed": row["resumed"],
        }
        for row in completed
    ]
    measurement_summary = {
        "complete_direct12_cells": CELLS,
        "low4_slices": len(SLICES),
        "high8_cells_per_slice": COARSE_CELLS,
        "solver_stages": CELLS * len(HORIZONS),
        "target_labels_used": 0,
        "reader_refits": 0,
        "candidate_assignments_executed": 0,
    }
    essential = {
        "selected_view": SELECTED_VIEW,
        "A426_public_challenge_sha256": protocol["public_challenge_sha256"],
        "measurement_sha256": canonical_sha256(ledgers),
        "score_field_sha256": canonical_sha256(scores.tolist()),
        "W52_public_output_direct12_order_uint16be_sha256": schedule[
            "global_order_uint16be_sha256"
        ],
        "worker_cell_order_uint16be_sha256": schedule["worker_cell_order_uint16be_sha256"],
        "worker_task_list_sha256": schedule["worker_task_list_sha256"],
        "schedule_proof": schedule["proof"],
        "target_labels_used": 0,
        "reader_refits": 0,
        "candidate_assignments_executed": 0,
        "A426_progress_or_filter_outcomes_consumed": False,
    }
    assert_pre_a426_result()
    payload: dict[str, Any] = {
        "schema": "chacha20-round20-w52-public-output-direct12-eight-worker-a432-result-v1",
        "attempt_id": ATTEMPT_ID,
        "evidence_stage": "PRE_A426_RESULT_COMPLETE_PUBLIC_OUTPUT_DIRECT12_W52_EIGHT_WORKER_SCHEDULE_FROZEN",
        "design_sha256": DESIGN_SHA256,
        "implementation_sha256": expected_implementation_sha256,
        "implementation_commitment_sha256": implementation["implementation_commitment_sha256"],
        "preflight_sha256": expected_preflight_sha256,
        "A426_protocol_sha256": expected_a426_protocol_sha256,
        **essential,
        "measurement_summary": measurement_summary,
        "measurement_ledger": ledgers,
        "W52_public_output_direct12_order": schedule["global_order"],
        "worker_roles": schedule["worker_roles"],
        "worker_cell_orders": schedule["worker_cell_orders"],
        "worker_tasks": schedule["worker_tasks"],
        "cell_epoch_one_based": schedule["cell_epoch_one_based"],
        "cell_worker_role": schedule["cell_worker_role"],
        "schedule_proof": schedule["proof"],
        "unlabeled_schedule_comparison": comparison,
        "A426_result_or_true_prefix_available_at_schedule_freeze": False,
        "A426_progress_or_filter_outcomes_consumed": False,
        "volatile_wall_seconds": time.perf_counter() - started,
        "anchors": {
            "design": anchor(DESIGN, DESIGN_SHA256),
            "implementation": anchor(IMPLEMENTATION, expected_implementation_sha256),
            "preflight": anchor(PREFLIGHT, expected_preflight_sha256),
            "A426_protocol": anchor(A426_PROTOCOL, expected_a426_protocol_sha256),
            "A426_runner": anchor(A426_RUNNER, A426_RUNNER_SHA256),
            "A388_runner": anchor(A388_RUNNER, A388_RUNNER_SHA256),
            "A349_selection": anchor(A349_SELECTION, A349_SELECTION_SHA256),
            "A342_result": anchor(A342_RESULT, A342_RESULT_SHA256),
            "A348_result": anchor(A348_RESULT, A348_RESULT_SHA256),
            "A428_result": anchor(A428_RESULT, A428_RESULT_SHA256),
            "A428_causal": anchor(A428_CAUSAL, A428_CAUSAL_SHA256),
            "A430_result": anchor(A430_RESULT, A430_RESULT_SHA256),
            "A430_causal": anchor(A430_CAUSAL, A430_CAUSAL_SHA256),
            "runner": anchor(Path(__file__)),
            "test": anchor(TEST),
            "reproducer": anchor(REPRO),
        },
    }
    payload["order_commitment_sha256"] = canonical_sha256(essential)
    payload["schedule_commitment_sha256"] = canonical_sha256(
        {
            "order": schedule["global_order_uint16be_sha256"],
            "workers": schedule["worker_cell_order_uint16be_sha256"],
            "tasks": schedule["worker_task_list_sha256"],
            "epochs": schedule["cell_epoch_one_based"],
        }
    )
    payload["causal"] = build_causal(payload)
    atomic_json(RESULT, payload)
    assert_pre_a426_result()
    atomic_bytes(
        REPORT,
        (
            "# A432 — W52 public-output Direct12 exact eight-worker schedule\n\n"
            f"Evidence stage: **{payload['evidence_stage']}**\n\n"
            f"- Complete directly measured prefix cells: **{CELLS:,}**\n"
            f"- Solver stages: **{measurement_summary['solver_stages']:,}**\n"
            f"- Exact worker depth: **{schedule['proof']['depth_identity']}**\n"
            f"- Worker lists: **{WORKERS} x {EPOCHS} disjoint complete groups**\n"
            f"- Direct12 W52/W51 Spearman: **{comparison['Direct12_W52_vs_W51_spearman']:.9f}**\n"
            f"- Direct12/A428 Spearman: **{comparison['Direct12_vs_A428_global_order_spearman']:.9f}**\n"
            "- Target labels / Reader refits / candidate assignments: **0 / 0 / 0**\n"
            "- A426 progress or filter outcomes consumed: **zero**\n"
            "- Authentic AI-native Causal readback: **2 explicit + 1 inferred**\n"
        ).encode(),
    )
    return payload


def analyze() -> dict[str, Any]:
    payload: dict[str, Any] = {
        "attempt_id": ATTEMPT_ID,
        "design_sha256": DESIGN_SHA256,
        "implementation_frozen": IMPLEMENTATION.exists(),
        "A426_protocol_available": A426_PROTOCOL.exists(),
        "preflight_complete": PREFLIGHT.exists(),
        "slice_measurement_count": (
            len(list(MEASUREMENTS.glob("slice_*.json.zst"))) if MEASUREMENTS.exists() else 0
        ),
        "schedule_frozen": RESULT.exists(),
    }
    if IMPLEMENTATION.exists():
        payload["implementation_sha256"] = file_sha256(IMPLEMENTATION)
    if PREFLIGHT.exists():
        payload["preflight_sha256"] = file_sha256(PREFLIGHT)
    if RESULT.exists():
        value = json.loads(RESULT.read_bytes())
        payload["result_sha256"] = file_sha256(RESULT)
        payload["evidence_stage"] = value["evidence_stage"]
        payload["schedule_commitment_sha256"] = value["schedule_commitment_sha256"]
    return payload


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    action = parser.add_mutually_exclusive_group(required=True)
    action.add_argument("--analyze", action="store_true")
    action.add_argument("--freeze-implementation", action="store_true")
    action.add_argument("--preflight", action="store_true")
    action.add_argument("--measure", action="store_true")
    parser.add_argument("--expected-implementation-sha256")
    parser.add_argument("--expected-a426-protocol-sha256")
    parser.add_argument("--expected-preflight-sha256")
    args = parser.parse_args()
    if args.freeze_implementation:
        payload = freeze_implementation()
    elif args.preflight:
        if not args.expected_implementation_sha256 or not args.expected_a426_protocol_sha256:
            parser.error("--preflight requires implementation and A426 protocol hashes")
        payload = preflight(
            expected_implementation_sha256=args.expected_implementation_sha256,
            expected_a426_protocol_sha256=args.expected_a426_protocol_sha256,
        )
    elif args.measure:
        if (
            not args.expected_implementation_sha256
            or not args.expected_preflight_sha256
            or not args.expected_a426_protocol_sha256
        ):
            parser.error("--measure requires implementation, preflight and A426 protocol hashes")
        payload = measure(
            expected_implementation_sha256=args.expected_implementation_sha256,
            expected_preflight_sha256=args.expected_preflight_sha256,
            expected_a426_protocol_sha256=args.expected_a426_protocol_sha256,
        )
    else:
        payload = analyze()
    print(json.dumps(payload, indent=2, sort_keys=True), flush=True)


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""A352: build a zero-refit W47 direct12 reader and bounded A347 portfolio."""

from __future__ import annotations

import argparse
import concurrent.futures
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

import zstandard

ROOT = Path(__file__).parents[2]
RESEARCH = ROOT / "research"
CONFIGS = RESEARCH / "configs"
RESULTS = RESEARCH / "results/v1"
ARTIFACTS = RESEARCH / "artifacts/a352_chacha20_r20_w47_target_conditioned"
MEASUREMENTS = RESULTS / "chacha20_round20_w47_target_conditioned_factor2_a352_v1"

DESIGN = CONFIGS / "chacha20_round20_w47_target_conditioned_factor2_a352_design_v1.json"
IMPLEMENTATION = CONFIGS / "chacha20_round20_w47_target_conditioned_factor2_a352_implementation_v1.json"
PREFLIGHT = RESULTS / "chacha20_round20_w47_target_conditioned_factor2_a352_preflight_v1.json"
ORDER = RESULTS / "chacha20_round20_w47_target_conditioned_factor2_a352_order_v1.json"
CAUSAL = ORDER.with_suffix(".causal")
REPORT = ORDER.with_suffix(".md")
BASE_CNF = ARTIFACTS / "a352_a347_public_output_w47_b1.cnf"
TEST = ROOT / "tests/test_chacha20_round20_w47_target_conditioned_factor2_a352.py"
REPRO = ROOT / "scripts/reproduce_chacha20_round20_w47_target_conditioned_factor2_a352.sh"

A347_RUNNER = RESEARCH / "experiments/chacha20_round20_fresh_w47_factor2_transfer_a347.py"
A347_DESIGN = CONFIGS / "chacha20_round20_fresh_w47_factor2_transfer_a347_design_v1.json"
A347_IMPLEMENTATION = CONFIGS / "chacha20_round20_fresh_w47_factor2_transfer_a347_implementation_v1.json"
A347_ORDER = RESULTS / "chacha20_round20_fresh_w47_factor2_transfer_a347_order_v1.json"
A347_PROTOCOL = CONFIGS / "chacha20_round20_fresh_w47_factor2_transfer_a347_v1.json"
A347_PROGRESS = RESULTS / "chacha20_round20_fresh_w47_factor2_transfer_a347_progress_v1.json"
A347_RESULT = RESULTS / "chacha20_round20_fresh_w47_factor2_transfer_a347_v1.json"
A349_RUNNER = RESEARCH / "experiments/chacha20_round20_w46_direct12_prospective_a345_validation_a349.py"
A349_SELECTION = CONFIGS / "chacha20_round20_w46_direct12_prospective_a345_validation_a349_selection_v1.json"
A342_RESULT = RESULTS / "chacha20_round20_w46_exhaustive_reader_ensemble_a342_v1.json"
A348_RESULT = RESULTS / "chacha20_round20_w46_direct12_sliced_reader_a348_v1.json"
A351_RUNNER = RESEARCH / "experiments/chacha20_round20_w46_dual_order_factor2_portfolio_a351.py"
A351_ORDER = RESULTS / "chacha20_round20_w46_dual_order_factor2_portfolio_a351_order_v1.json"

ATTEMPT_ID = "A352"
DESIGN_SHA256 = "3136952bbef9cbaaa168eb83d2c281a1980092087ec626eb821c0f46e816f241"
A347_DESIGN_SHA256 = "78e3406ca48af0c81f002c0f5329c1b7267481eca579ac9544b5188ee3cbe102"
A347_IMPLEMENTATION_SHA256 = "2d951320541a4b5e3606fb289541369c635c9ecc96d92961a57df228494af3c7"
A347_ORDER_SHA256 = "5a287c0985ed249e15d3d1a9b351d30e70503b15ccd6199e33944a633144a2a6"
A347_RUNNER_SHA256 = "66054128dac2d1512a6f81f007341c4e8603a6a832b997417a21911f2f6eea1f"
A349_SELECTION_SHA256 = "4f33a99b859044ed79d933b813486dba195e37438bc9afcf32b21d31d2d6c422"
A342_RESULT_SHA256 = "8d6d6f99b89d67d7eff186037934bfa515cf93a00af10b244826f44056b4cebb"
A348_RESULT_SHA256 = "f09bba039b26c8b78804f48169df62db167a9d95fbfff91e7099a01c1be1c812"
A351_ORDER_SHA256 = "f1087d76e7b98e918e6d7ecca2ae1ac53761dde3f33452a8f3dc37feb68eb61c"

WIDTH = 47
PREFIX_BITS = 12
LOW_BITS = 4
CELLS = 1 << PREFIX_BITS
COARSE_CELLS = 1 << (PREFIX_BITS - LOW_BITS)
SLICES = tuple(range(1 << LOW_BITS))
HORIZONS = [1, 2, 4, 8]
WORKERS = 8
WATCHDOG_SECONDS = 2.0
ZSTD_LEVEL = 10
SELECTED_VIEW = "A342_selected_pair_slice_z"
MASK32 = 0xFFFFFFFF
DOTCAUSAL_SRC = Path("/Users/bhkmie/Documents/Forschung/O1/vendor/fabel/dotcausal_package/src")


def load_module(path: Path, name: str) -> Any:
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot import A352 dependency {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


A347 = load_module(A347_RUNNER, "a352_a347")
A349 = load_module(A349_RUNNER, "a352_a349")
A351 = load_module(A351_RUNNER, "a352_a351")
A348 = A349.A348
A340 = A349.A340
A341 = A349.A341
WRAPPER = A349.WRAPPER

file_sha256 = A349.file_sha256
canonical_sha256 = A349.canonical_sha256
canonical_bytes = A349.canonical_bytes
atomic_json = A349.atomic_json
atomic_bytes = A349.atomic_bytes
relative = A349.relative
path_from_ref = A349.path_from_ref
anchor = A349.anchor
sha256 = A349.sha256


def load_design() -> dict[str, Any]:
    if file_sha256(DESIGN) != DESIGN_SHA256:
        raise RuntimeError("A352 design hash differs")
    value = json.loads(DESIGN.read_bytes())
    boundary = value.get("information_boundary", {})
    measurement = value.get("measurement_contract", {})
    reader = value.get("reader_contract", {})
    if (
        value.get("schema")
        != "chacha20-round20-w47-target-conditioned-factor2-a352-design-v1"
        or value.get("attempt_id") != ATTEMPT_ID
        or value.get("design_state")
        != "frozen_before_A346_qualification_A347_protocol_challenge_candidate_prefix_or_result"
        or boundary.get("A347_protocol_available_at_design_freeze") is not False
        or boundary.get("A347_fresh_challenge_available_at_design_freeze") is not False
        or boundary.get("A347_candidate_or_prefix_available_at_design_freeze") is not False
        or boundary.get("target_labels_used_for_order_construction") != 0
        or measurement.get("complete_direct_prefix_cells") != CELLS
        or measurement.get("low4_fixed_unit_coordinates") != list(low4_coordinates(WIDTH))
        or measurement.get("high8_assumption_coordinates")
        != list(range(WIDTH - 1, WIDTH - 9, -1))
        or reader.get("selected_view") != SELECTED_VIEW
        or reader.get("reader_refits") != 0
    ):
        raise RuntimeError("A352 frozen design semantics differ")
    for key, source_path in value["source_anchors"].items():
        if key.endswith("_path"):
            expected = value["source_anchors"][key.removesuffix("_path") + "_sha256"]
            anchor(ROOT / source_path, expected)
    return value


def assert_pre_a347_recovery() -> None:
    if A347_PROGRESS.exists() or A347_RESULT.exists():
        raise RuntimeError("A352 order construction must precede A347 recovery execution")


def freeze_implementation() -> dict[str, Any]:
    if any(path.exists() for path in (IMPLEMENTATION, PREFLIGHT, ORDER, CAUSAL, REPORT, MEASUREMENTS, ARTIFACTS)):
        raise FileExistsError("A352 implementation or target artifacts already exist")
    if A347_PROTOCOL.exists():
        raise RuntimeError("A352 implementation must precede the fresh W47 protocol")
    load_design()
    assert_pre_a347_recovery()
    if not TEST.exists() or not REPRO.exists():
        raise FileNotFoundError("A352 test and reproducer must precede implementation freeze")
    payload: dict[str, Any] = {
        "schema": "chacha20-round20-w47-target-conditioned-factor2-a352-implementation-v1",
        "attempt_id": ATTEMPT_ID,
        "commitment_state": "frozen_before_A347_protocol_challenge_candidate_prefix_or_result",
        "design_sha256": DESIGN_SHA256,
        "selected_view": SELECTED_VIEW,
        "A347_protocol_available_at_implementation_freeze": False,
        "A347_candidate_or_prefix_available_at_implementation_freeze": False,
        "anchors": {
            "design": anchor(DESIGN, DESIGN_SHA256),
            "A347_design": anchor(A347_DESIGN, A347_DESIGN_SHA256),
            "A347_implementation": anchor(A347_IMPLEMENTATION, A347_IMPLEMENTATION_SHA256),
            "A347_order": anchor(A347_ORDER, A347_ORDER_SHA256),
            "A347_runner": anchor(A347_RUNNER, A347_RUNNER_SHA256),
            "A349_selection": anchor(A349_SELECTION, A349_SELECTION_SHA256),
            "A342_result": anchor(A342_RESULT, A342_RESULT_SHA256),
            "A348_result": anchor(A348_RESULT, A348_RESULT_SHA256),
            "A351_order": anchor(A351_ORDER, A351_ORDER_SHA256),
            "runner": anchor(Path(__file__)),
            "test": anchor(TEST),
            "reproducer": anchor(REPRO),
        },
    }
    payload["implementation_commitment_sha256"] = canonical_sha256(payload)
    atomic_json(IMPLEMENTATION, payload)
    if A347_PROTOCOL.exists():
        IMPLEMENTATION.unlink(missing_ok=True)
        raise RuntimeError("A352 implementation did not precede the W47 protocol")
    return payload


def load_implementation(expected_sha256: str) -> dict[str, Any]:
    if file_sha256(IMPLEMENTATION) != expected_sha256:
        raise RuntimeError("A352 implementation hash differs")
    value = json.loads(IMPLEMENTATION.read_bytes())
    if (
        value.get("schema")
        != "chacha20-round20-w47-target-conditioned-factor2-a352-implementation-v1"
        or value.get("attempt_id") != ATTEMPT_ID
        or value.get("commitment_state")
        != "frozen_before_A347_protocol_challenge_candidate_prefix_or_result"
        or value.get("design_sha256") != DESIGN_SHA256
        or value.get("selected_view") != SELECTED_VIEW
        or value.get("A347_protocol_available_at_implementation_freeze") is not False
    ):
        raise RuntimeError("A352 implementation semantics differ")
    expected = {
        "design": DESIGN,
        "A347_design": A347_DESIGN,
        "A347_implementation": A347_IMPLEMENTATION,
        "A347_order": A347_ORDER,
        "A347_runner": A347_RUNNER,
        "A349_selection": A349_SELECTION,
        "A342_result": A342_RESULT,
        "A348_result": A348_RESULT,
        "A351_order": A351_ORDER,
        "runner": Path(__file__),
        "test": TEST,
        "reproducer": REPRO,
    }
    for name, path in expected.items():
        row = value["anchors"][name]
        if row.get("path") != relative(path) or row.get("sha256") != file_sha256(path):
            raise RuntimeError(f"A352 implementation anchor differs: {name}")
    unsigned = {key: item for key, item in value.items() if key != "implementation_commitment_sha256"}
    if value.get("implementation_commitment_sha256") != canonical_sha256(unsigned):
        raise RuntimeError("A352 implementation commitment differs")
    return value


def load_a347_protocol(expected_sha256: str) -> dict[str, Any]:
    value = A347.load_protocol(expected_sha256)
    challenge = value.get("public_challenge", {})
    if (
        value.get("schema") != "chacha20-round20-fresh-w47-factor2-transfer-a347-protocol-v1"
        or challenge.get("unknown_key_bits") != WIDTH
        or challenge.get("unknown_assignment_included") is not False
        or "assignment" in challenge
        or "candidate" in challenge
        or "prefix12" in challenge
    ):
        raise RuntimeError("A352 A347 public challenge boundary differs")
    return value


def bridge_challenge(protocol: Mapping[str, Any]) -> dict[str, Any]:
    source = protocol["public_challenge"]
    remainder = WIDTH - 32
    masks = [0, (~((1 << remainder) - 1)) & MASK32, *([MASK32] * 6)]
    known = [int(value) & MASK32 for value in source["known_zeroed_key_words"]]
    values = [value & mask for value, mask in zip(known, masks, strict=True)]
    bridge = {
        "challenge_id": "A352-bridge-" + str(source["challenge_id"]),
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
        "target_words": [[int(word) & MASK32 for word in block] for block in source["target_words"]],
        "target_block_sha256": list(source["target_block_sha256"]),
        "control_target_words": [int(word) & MASK32 for word in source["control_target_words"]],
        "control_target_block_sha256": source["control_target_block_sha256"],
    }
    if bridge["known_key_mask_words"][1] != 0xFFFF8000:
        raise RuntimeError("A352 W47 known-mask codec differs")
    return bridge


def w47_source_formula(a223: Any, challenge: dict[str, Any]) -> str:
    formula = A340.A296.b1_formula(a223, challenge, WIDTH)
    remainder = WIDTH % 32
    word = WIDTH // 32
    known_width = 32 - remainder
    known = int(challenge["known_key_value_words"][word]) >> remainder
    generated = f"(assert (= ((_ extract 31 {remainder}) k{word}) #x{known:0{known_width // 4}x}))"
    corrected = f"(assert (= ((_ extract 31 {remainder}) k{word}) #b{known:0{known_width}b}))"
    if formula.count(generated) != 1 or corrected in formula:
        raise RuntimeError("A352 W47 known-suffix correction boundary differs")
    result = formula.replace(generated, corrected)
    if result.count(corrected) != 1 or generated in result:
        raise RuntimeError("A352 W47 known-suffix correction failed")
    return result


def preflight(*, expected_implementation_sha256: str, expected_a347_protocol_sha256: str) -> dict[str, Any]:
    if PREFLIGHT.exists() or ARTIFACTS.exists():
        raise FileExistsError("A352 preflight artifacts already exist")
    assert_pre_a347_recovery()
    implementation = load_implementation(expected_implementation_sha256)
    protocol = load_a347_protocol(expected_a347_protocol_sha256)
    bridge = bridge_challenge(protocol)
    a223 = A340.load_module(A340.A223_SOURCE, "a352_a223_preflight")
    config = json.loads(A340.A223_CONFIG.read_bytes())
    a223._toolchain_gates(config)  # noqa: SLF001
    a223._validate_challenge(bridge, width=WIDTH)  # noqa: SLF001
    formula = w47_source_formula(a223, bridge)
    ARTIFACTS.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="a352_w47_b1_", dir=ARTIFACTS.parent) as temporary:
        directory = Path(temporary)
        temporary_cnf = directory / "base.cnf"
        export = a223._export_cnf(  # noqa: SLF001
            formula=formula,
            output=temporary_cnf,
            config=config,
            label="A352_A347_W47_B1_DIRECT12",
        )
        raw = temporary_cnf.read_bytes()
        lines = raw.splitlines(keepends=True)
        header = lines[0].split() if lines else []
        if len(header) != 4 or header[:2] != [b"p", b"cnf"]:
            raise RuntimeError("A352 base CNF header differs")
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
    synthetic = A340.A296.synthetic_reader_mapping(mapping, WIDTH)
    if len(mapping) != WIDTH or len(synthetic) != 20:
        raise RuntimeError("A352 source or synthetic mapping differs")
    payload: dict[str, Any] = {
        "schema": "chacha20-round20-w47-target-conditioned-factor2-a352-preflight-v1",
        "attempt_id": ATTEMPT_ID,
        "evidence_stage": "PRE_A347_RECOVERY_PUBLIC_OUTPUT_DIRECT12_CNF_AND_READER_FROZEN",
        "implementation_sha256": expected_implementation_sha256,
        "implementation_commitment_sha256": implementation["implementation_commitment_sha256"],
        "A347_protocol_sha256": expected_a347_protocol_sha256,
        "A347_public_challenge_sha256": protocol["public_challenge_sha256"],
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
        "A347_recovery_available_at_preflight": False,
        "anchors": {
            "implementation": anchor(IMPLEMENTATION, expected_implementation_sha256),
            "A347_protocol": anchor(A347_PROTOCOL, expected_a347_protocol_sha256),
            "A347_order": anchor(A347_ORDER, A347_ORDER_SHA256),
            "A349_selection": anchor(A349_SELECTION, A349_SELECTION_SHA256),
            "A342_result": anchor(A342_RESULT, A342_RESULT_SHA256),
            "A348_result": anchor(A348_RESULT, A348_RESULT_SHA256),
            "runner": anchor(Path(__file__)),
        },
    }
    payload["preflight_commitment_sha256"] = canonical_sha256(payload)
    atomic_json(PREFLIGHT, payload)
    assert_pre_a347_recovery()
    return payload


def load_preflight(expected_sha256: str, expected_a347_protocol_sha256: str) -> dict[str, Any]:
    if file_sha256(PREFLIGHT) != expected_sha256:
        raise RuntimeError("A352 preflight hash differs")
    value = json.loads(PREFLIGHT.read_bytes())
    if (
        value.get("schema") != "chacha20-round20-w47-target-conditioned-factor2-a352-preflight-v1"
        or value.get("A347_protocol_sha256") != expected_a347_protocol_sha256
        or value.get("A347_recovery_available_at_preflight") is not False
        or value.get("low4_coordinates") != list(low4_coordinates(WIDTH))
        or value.get("target_labels_used") != 0
        or value.get("reader_refits") != 0
    ):
        raise RuntimeError("A352 preflight semantics differ")
    anchor(BASE_CNF, value["CNF"]["sha256"])
    return value


def low4_coordinates(width: int) -> tuple[int, int, int, int]:
    if width < PREFIX_BITS:
        raise ValueError("A352 width is smaller than direct12")
    values = tuple(range(width - 9, width - 13, -1))
    if len(values) != LOW_BITS:
        raise RuntimeError("A352 low4 coordinate derivation differs")
    return values  # type: ignore[return-value]


def low4_unit_literals(low4: int, source_mapping: Sequence[int], width: int = WIDTH) -> list[int]:
    mapping = [int(value) for value in source_mapping]
    if not 0 <= low4 < len(SLICES) or len(mapping) != width:
        raise ValueError("A352 low4 slice or source mapping differs")
    result = []
    for offset, coordinate in enumerate(low4_coordinates(width)):
        one_literal = mapping[coordinate]
        bit = (low4 >> (LOW_BITS - 1 - offset)) & 1
        result.append(one_literal if bit else -one_literal)
    if len({abs(value) for value in result}) != LOW_BITS:
        raise RuntimeError("A352 low4 unit variables alias")
    return result


def render_slice_cnf(base_raw: bytes, *, low4: int, source_mapping: Sequence[int]) -> bytes:
    variables, clauses, body = A348._base_cnf_parts(base_raw)  # noqa: SLF001
    units = low4_unit_literals(low4, source_mapping)
    suffix = b"".join(f"{literal} 0\n".encode("ascii") for literal in units)
    return f"p cnf {variables} {clauses + len(units)}\n".encode("ascii") + body + suffix


def _slice_paths(low4: int) -> tuple[Path, Path]:
    return ARTIFACTS / f"slice_{low4:02x}.cnf", MEASUREMENTS / f"slice_{low4:02x}.json.zst"


def _write_measurement(path: Path, value: Mapping[str, Any]) -> dict[str, Any]:
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


def _read_measurement(path: Path, ledger: Mapping[str, Any] | None = None) -> dict[str, Any]:
    compressed = path.read_bytes()
    if ledger is not None and sha256(compressed) != ledger["compressed_sha256"]:
        raise RuntimeError("A352 compressed slice hash differs")
    raw = zstandard.ZstdDecompressor().decompress(compressed)
    if ledger is not None and sha256(raw) != ledger["raw_sha256"]:
        raise RuntimeError("A352 raw slice hash differs")
    value = json.loads(raw)
    if canonical_bytes(value) != raw:
        raise RuntimeError("A352 slice is not canonical")
    return value


def _prepare_slices(preflight_value: Mapping[str, Any]) -> list[dict[str, Any]]:
    base_raw = BASE_CNF.read_bytes()
    mapping = preflight_value["source_one_literals_bit0_upward"]
    rows = []
    for low4 in SLICES:
        cnf_path, measurement_path = _slice_paths(low4)
        expected = render_slice_cnf(base_raw, low4=low4, source_mapping=mapping)
        if cnf_path.exists() and cnf_path.read_bytes() != expected:
            raise RuntimeError(f"A352 slice CNF differs: {low4}")
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


def _validate_measurement(value: Mapping[str, Any], low4: int) -> None:
    run = value.get("run", {})
    if (
        value.get("schema") != "chacha20-round20-w47-target-conditioned-factor2-a352-slice-v1"
        or value.get("low4") != low4
        or value.get("target_label_available_to_measurement") is not False
        or value.get("complete_candidate_cover") is not True
        or len(run.get("cells", [])) != COARSE_CELLS
        or len(run.get("stages", [])) != COARSE_CELLS * len(HORIZONS)
        or any(cell.get("final_status") != "unknown" for cell in run["cells"])
        or run.get("all_watchdogs_clear") is not True
    ):
        raise RuntimeError(f"A352 prospective slice gate failed: {low4}")


def _run_slice(row: Mapping[str, Any], *, helper: Path, key_mapping: Sequence[int]) -> dict[str, Any]:
    low4 = int(row["low4"])
    path = Path(row["measurement_path"])
    if path.exists():
        value = _read_measurement(path)
        _validate_measurement(value, low4)
        return {"low4": low4, "resumed": True, "ledger": _write_measurement(path, value)}
    started = time.perf_counter()
    raw_run = WRAPPER.run_fresh_clause_identity(
        helper=helper,
        cnf=path_from_ref(row["cnf"]["path"]),
        mode=f"A352_A347_W47_direct12_low4_{low4:02x}",
        order=[f"{value:08b}" for value in range(COARSE_CELLS)],
        key_one_literals_bit0_through_bit19=key_mapping,
        conflict_horizons=HORIZONS,
        watchdog_seconds=WATCHDOG_SECONDS,
        external_timeout_seconds=3600.0,
    )
    stable = {key: value for key, value in raw_run.items() if key not in {"command", "process_elapsed_seconds"}}
    value = {
        "schema": "chacha20-round20-w47-target-conditioned-factor2-a352-slice-v1",
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
    _validate_measurement(value, low4)
    return {"low4": low4, "resumed": False, "ledger": _write_measurement(path, value)}


def _build_causal(payload: Mapping[str, Any]) -> dict[str, Any]:
    sys.path.insert(0, str(DOTCAUSAL_SRC))
    from dotcausal.io import CausalReader, CausalWriter

    writer = CausalWriter(api_id="a352w47")
    writer._rules = []
    writer.add_rule(
        name="frozen_reader_to_unlabeled_W47_order",
        description="The A342 pair reader consumes every fresh W47 direct12 trajectory without refit or target labels.",
        pattern=["A342_frozen_pair_reader", "A347_public_output_direct12_grid"],
        conclusion="A352_W47_target_conditioned_order",
        confidence_modifier=1.0,
    )
    writer.add_rule(
        name="target_conditioned_and_target_free_to_factor2_portfolio",
        description="The complete A352 order and pre-target A347 order form a stable min-rank wavefront with an exact pointwise factor-two bound.",
        pattern=["A352_W47_target_conditioned_order", "A347_target_free_W47_order"],
        conclusion="A352_W47_factor2_portfolio",
        confidence_modifier=1.0,
    )
    writer.add_triplet(
        trigger="A342:frozen_selected_pair_reader",
        mechanism="zero_refit_complete_A347_public_output_direct12_measurement",
        outcome="A352:W47_target_conditioned_order",
        confidence=1.0,
        source=payload["order_commitment_sha256"],
        quantification=json.dumps(payload["measurement_summary"], sort_keys=True),
        evidence="target-label-free exact 4096-cell W47 order",
        domain="prospective ChaCha20 R20 W47 reader transfer",
        quality_score=1.0,
    )
    writer.add_triplet(
        trigger="A352:W47_target_conditioned_order",
        mechanism="stable_min_rank_merge_with_pre_target_A347_order",
        outcome="A352:W47_factor2_portfolio",
        confidence=1.0,
        source=payload["order_commitment_sha256"],
        quantification=json.dumps(payload["pointwise_factor2_proof"], sort_keys=True),
        evidence=json.dumps(payload["operator_diversity"], sort_keys=True),
        domain="bounded W47 multiview recovery order",
        quality_score=1.0,
    )
    writer.add_triplet(
        trigger="A342:frozen_selected_pair_reader",
        mechanism="materialized_W47_reader_and_factor2_portfolio_closure",
        outcome="A352:W47_factor2_portfolio",
        confidence=1.0,
        source="materialized:A352_W47_portfolio_chain",
        quantification="exact retained closure",
        evidence="frozen before A347 recovery candidate or prefix",
        domain="AI-native retained inference",
        quality_score=1.0,
        is_inferred=True,
    )
    writer.add_cluster(
        name="A352 W47 target-conditioned bounded portfolio",
        entities=[
            "A342:frozen_selected_pair_reader",
            "A352:W47_target_conditioned_order",
            "A352:W47_factor2_portfolio",
        ],
    )
    writer.add_gap(
        subject="A352:W47_factor2_portfolio",
        predicate="next_required_object",
        expected_object_type="executed_fullround_W47_recovery_in_frozen_A352_order",
        confidence=1.0,
        suggested_queries=["Execute the qualified sixteen-slab W47 engine in the frozen A352 order."],
    )
    temporary = CAUSAL.with_name(f".{CAUSAL.name}.tmp")
    temporary.unlink(missing_ok=True)
    stats = writer.save(str(temporary))
    os.replace(temporary, CAUSAL)
    reader = CausalReader(str(CAUSAL), verify_integrity=True)
    explicit = reader.get_all_triplets(include_inferred=False)
    all_rows = reader.get_all_triplets(include_inferred=True)
    inferred = [row for row in reader._triplets if row.get("is_inferred", False)]
    if (
        reader.api_id != "a352w47"
        or len(explicit) != 2
        or len(all_rows) != 3
        or len(inferred) != 1
        or len(reader._rules) != 2
        or len(reader._clusters) != 1
        or len(reader._gaps) != 1
    ):
        raise RuntimeError("A352 authentic Causal reopen gate failed")
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
        "personal_semantic_readback": {"terminal_chain": all_rows[-1], "next_gap": reader._gaps[0]},
    }


def measure(
    *,
    expected_implementation_sha256: str,
    expected_preflight_sha256: str,
    expected_a347_protocol_sha256: str,
) -> dict[str, Any]:
    if ORDER.exists() or CAUSAL.exists() or REPORT.exists():
        raise FileExistsError("A352 order artifacts already exist")
    assert_pre_a347_recovery()
    implementation = load_implementation(expected_implementation_sha256)
    frozen = load_preflight(expected_preflight_sha256, expected_a347_protocol_sha256)
    protocol = load_a347_protocol(expected_a347_protocol_sha256)
    rows = _prepare_slices(frozen)
    _a275, _model, _a291, _indices, helper = A340.A296._reader_stack()  # noqa: SLF001
    WRAPPER._load_base_wrapper()  # noqa: SLF001
    MEASUREMENTS.mkdir(parents=True, exist_ok=True)
    started = time.perf_counter()
    completed = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=WORKERS) as executor:
        futures = [
            executor.submit(
                _run_slice,
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
        raise RuntimeError("A352 complete slice cover differs")
    measurements = {
        row["low4"]: _read_measurement(path_from_ref(row["ledger"]["path"]), row["ledger"])
        for row in completed
    }
    for low4, value in measurements.items():
        _validate_measurement(value, low4)
    _selection, _a272, model, groups = A341.reconstruct_known_key_selection(
        json.loads(A341.DESIGN.read_bytes())
    )
    scores = A349.selected_pair_slice_z_scores(measurements, model, groups)
    target_order = A348._rank_order(scores)  # noqa: SLF001
    source_value = A347.load_order()
    source_order = A351.exact_order(source_value["selected_order"], "A347 target-free")
    portfolio = A351.factor2_wavefront(source_order, target_order)
    proof = A351.factor2_proof(source_order, target_order, portfolio)
    diversity = A351.diversity_panel(source_order, target_order)
    ledgers = [{**row["ledger"], "low4": row["low4"], "resumed": row["resumed"]} for row in completed]
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
        "A347_public_challenge_sha256": protocol["public_challenge_sha256"],
        "measurement_sha256": canonical_sha256(ledgers),
        "score_field_sha256": canonical_sha256(scores.tolist()),
        "target_conditioned_order_uint16be_sha256": A351.order_sha256(target_order),
        "A347_target_free_order_uint16be_sha256": A351.order_sha256(source_order),
        "selected_order_uint16be_sha256": A351.order_sha256(portfolio),
        "pointwise_factor2_proof": proof,
        "operator_diversity": diversity,
        "target_labels_used": 0,
        "reader_refits": 0,
    }
    assert_pre_a347_recovery()
    payload: dict[str, Any] = {
        "schema": "chacha20-round20-w47-target-conditioned-factor2-a352-order-v1",
        "attempt_id": ATTEMPT_ID,
        "evidence_stage": "PRE_A347_RECOVERY_COMPLETE_PUBLIC_OUTPUT_CONDITIONED_W47_FACTOR2_ORDER_FROZEN",
        "design_sha256": DESIGN_SHA256,
        "implementation_sha256": expected_implementation_sha256,
        "implementation_commitment_sha256": implementation["implementation_commitment_sha256"],
        "preflight_sha256": expected_preflight_sha256,
        "A347_protocol_sha256": expected_a347_protocol_sha256,
        **essential,
        "measurement_summary": measurement_summary,
        "measurement_ledger": ledgers,
        "target_conditioned_order": target_order,
        "selected_order": portfolio,
        "candidate_assignments_executed": 0,
        "A347_recovery_available_at_order_freeze": False,
        "volatile_wall_seconds": time.perf_counter() - started,
        "anchors": {
            "design": anchor(DESIGN, DESIGN_SHA256),
            "implementation": anchor(IMPLEMENTATION, expected_implementation_sha256),
            "preflight": anchor(PREFLIGHT, expected_preflight_sha256),
            "A347_protocol": anchor(A347_PROTOCOL, expected_a347_protocol_sha256),
            "A347_order": anchor(A347_ORDER, A347_ORDER_SHA256),
            "A349_selection": anchor(A349_SELECTION, A349_SELECTION_SHA256),
            "A342_result": anchor(A342_RESULT, A342_RESULT_SHA256),
            "A348_result": anchor(A348_RESULT, A348_RESULT_SHA256),
            "A351_order": anchor(A351_ORDER, A351_ORDER_SHA256),
            "runner": anchor(Path(__file__)),
            "test": anchor(TEST),
            "reproducer": anchor(REPRO),
        },
    }
    payload["order_commitment_sha256"] = canonical_sha256(essential)
    payload["causal"] = _build_causal(payload)
    atomic_json(ORDER, payload)
    if A347_PROGRESS.exists() or (A347_RESULT.exists() and A347_RESULT.stat().st_mtime_ns <= ORDER.stat().st_mtime_ns):
        raise RuntimeError("A352 order did not precede A347 recovery")
    atomic_bytes(
        REPORT,
        (
            "# A352 — W47 public-output-conditioned bounded portfolio\n\n"
            f"Evidence stage: **{payload['evidence_stage']}**\n\n"
            f"- Complete directly measured prefix cells: **{CELLS:,}**\n"
            f"- Solver stages: **{measurement_summary['solver_stages']:,}**\n"
            f"- Exact pointwise bound: **{proof['bound']}**\n"
            f"- Source-order Spearman correlation: **{diversity['spearman_rank_correlation']:.9f}**\n"
            "- Target labels / reader refits: **0 / 0**\n"
            "- Candidate assignments executed: **zero**\n"
            "- Authentic AI-native Causal readback: **2 explicit + 1 inferred**\n"
        ).encode(),
    )
    return payload


def analyze() -> dict[str, Any]:
    payload: dict[str, Any] = {
        "attempt_id": ATTEMPT_ID,
        "design_sha256": DESIGN_SHA256,
        "implementation_frozen": IMPLEMENTATION.exists(),
        "A347_protocol_available": A347_PROTOCOL.exists(),
        "preflight_complete": PREFLIGHT.exists(),
        "slice_measurement_count": len(list(MEASUREMENTS.glob("slice_*.json.zst"))) if MEASUREMENTS.exists() else 0,
        "order_frozen": ORDER.exists(),
    }
    if IMPLEMENTATION.exists():
        payload["implementation_sha256"] = file_sha256(IMPLEMENTATION)
    if PREFLIGHT.exists():
        payload["preflight_sha256"] = file_sha256(PREFLIGHT)
    if ORDER.exists():
        payload["order_sha256"] = file_sha256(ORDER)
        payload["evidence_stage"] = json.loads(ORDER.read_bytes())["evidence_stage"]
    return payload


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    action = parser.add_mutually_exclusive_group(required=True)
    action.add_argument("--analyze", action="store_true")
    action.add_argument("--freeze-implementation", action="store_true")
    action.add_argument("--preflight", action="store_true")
    action.add_argument("--measure", action="store_true")
    parser.add_argument("--expected-implementation-sha256")
    parser.add_argument("--expected-a347-protocol-sha256")
    parser.add_argument("--expected-preflight-sha256")
    args = parser.parse_args()
    if args.freeze_implementation:
        payload = freeze_implementation()
    elif args.preflight:
        if not args.expected_implementation_sha256 or not args.expected_a347_protocol_sha256:
            parser.error("--preflight requires implementation and A347 protocol hashes")
        payload = preflight(
            expected_implementation_sha256=args.expected_implementation_sha256,
            expected_a347_protocol_sha256=args.expected_a347_protocol_sha256,
        )
    elif args.measure:
        if not args.expected_implementation_sha256 or not args.expected_preflight_sha256 or not args.expected_a347_protocol_sha256:
            parser.error("--measure requires implementation, preflight and A347 protocol hashes")
        payload = measure(
            expected_implementation_sha256=args.expected_implementation_sha256,
            expected_preflight_sha256=args.expected_preflight_sha256,
            expected_a347_protocol_sha256=args.expected_a347_protocol_sha256,
        )
    else:
        payload = analyze()
    print(json.dumps(payload, indent=2, sort_keys=True), flush=True)


if __name__ == "__main__":
    main()

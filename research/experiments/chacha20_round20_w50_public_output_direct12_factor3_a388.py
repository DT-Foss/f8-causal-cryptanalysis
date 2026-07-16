#!/usr/bin/env python3
"""A388: build a zero-refit W50 Direct12 reader and exact three-view order."""

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
ARTIFACTS = RESEARCH / "artifacts/a388_chacha20_r20_w50_public_output_direct12"
MEASUREMENTS = RESULTS / "chacha20_round20_w50_public_output_direct12_factor3_a388_v1"

DESIGN = CONFIGS / "chacha20_round20_w50_public_output_direct12_factor3_a388_design_v1.json"
IMPLEMENTATION = CONFIGS / "chacha20_round20_w50_public_output_direct12_factor3_a388_implementation_v1.json"
PREFLIGHT = RESULTS / "chacha20_round20_w50_public_output_direct12_factor3_a388_preflight_v1.json"
ORDER = RESULTS / "chacha20_round20_w50_public_output_direct12_factor3_a388_order_v1.json"
CAUSAL = ORDER.with_suffix(".causal")
REPORT = ORDER.with_suffix(".md")
BASE_CNF = ARTIFACTS / "a388_a385_public_output_w50_b1.cnf"
TEST = ROOT / "tests/test_chacha20_round20_w50_public_output_direct12_factor3_a388.py"
REPRO = ROOT / "scripts/reproduce_chacha20_round20_w50_public_output_direct12_factor3_a388.sh"

A385_RUNNER = RESEARCH / "experiments/chacha20_round20_fresh_w50_pretarget_transfer_a385.py"
A385_DESIGN = CONFIGS / "chacha20_round20_fresh_w50_pretarget_transfer_a385_design_v1.json"
A385_IMPLEMENTATION = CONFIGS / "chacha20_round20_fresh_w50_pretarget_transfer_a385_implementation_v1.json"
A385_ORDER = RESULTS / "chacha20_round20_fresh_w50_pretarget_transfer_a385_order_v1.json"
A385_PROTOCOL = CONFIGS / "chacha20_round20_fresh_w50_pretarget_transfer_a385_v1.json"
A387_RESULT = RESULTS / "chacha20_round20_w50_pretarget_factor6_recovery_a387_v1.json"
A386_RUNNER = RESEARCH / "experiments/chacha20_round20_w49_calibrated_ticketed_hierarchical_factor3_a386.py"
A386_ORDER = RESULTS / "chacha20_round20_w49_calibrated_ticketed_hierarchical_factor3_a386_order_v1.json"
A349_RUNNER = RESEARCH / "experiments/chacha20_round20_w46_direct12_prospective_a345_validation_a349.py"
A349_SELECTION = CONFIGS / "chacha20_round20_w46_direct12_prospective_a345_validation_a349_selection_v1.json"
A342_RESULT = RESULTS / "chacha20_round20_w46_exhaustive_reader_ensemble_a342_v1.json"
A348_RESULT = RESULTS / "chacha20_round20_w46_direct12_sliced_reader_a348_v1.json"
A351_RUNNER = RESEARCH / "experiments/chacha20_round20_w46_dual_order_factor2_portfolio_a351.py"
A351_ORDER = RESULTS / "chacha20_round20_w46_dual_order_factor2_portfolio_a351_order_v1.json"

ATTEMPT_ID = "A388"
DESIGN_SHA256 = "c59c68725caf161fd653a7728472da3f6ac7857c30f26c1a6625827822cb4782"
A385_DESIGN_SHA256 = "0e4c1d7b5f2a89245728fcc3f5d6d66ebb20c3cefccb127f03d9b58a57125687"
A385_IMPLEMENTATION_SHA256 = "05b6b0403a852abf686bdb2b45f13f5a1997c9970ce2e328cc779aaeee818263"
A385_ORDER_SHA256 = "3d694c17590c063bc14edc925f75adbc2f05e4a941195956a89d18287805af38"
A385_PROTOCOL_SHA256 = "801831f2daabe41476c9bf1ec676907f11c1b5465a193ba61d8d1877eb3b0b4b"
A385_RUNNER_SHA256 = "b6827f779a8a7997bbee6c04a6a28f9f3c5ec5718ac942b0171c8b4174a928f3"
A386_ORDER_SHA256 = "eda2ec6b995d2ad7ecb8198ff33616c9129fceb04b28a51b0f2123303ba6a5c4"
A386_RUNNER_SHA256 = "56e7ebea65efd3436d52b7ff43ec1b327f4068fc3066ee280217f411b2738900"
A349_SELECTION_SHA256 = "4f33a99b859044ed79d933b813486dba195e37438bc9afcf32b21d31d2d6c422"
A342_RESULT_SHA256 = "8d6d6f99b89d67d7eff186037934bfa515cf93a00af10b244826f44056b4cebb"
A348_RESULT_SHA256 = "f09bba039b26c8b78804f48169df62db167a9d95fbfff91e7099a01c1be1c812"
A351_ORDER_SHA256 = "f1087d76e7b98e918e6d7ecca2ae1ac53761dde3f33452a8f3dc37feb68eb61c"
A386_SELECTED_ORDER_UINT16BE_SHA256 = "7420e2bf5467390ba236eaea8357e8cdf4c14f1537c38a4c98e6d88dca2c4061"

WIDTH = 50
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
FACTOR3_ROLES = (
    "A385_pretarget_six_view",
    "A388_W50_public_output_direct12",
    "A386_calibrated_target_blind_transfer",
)
MASK32 = 0xFFFFFFFF
DOTCAUSAL_SRC = Path("/Users/bhkmie/Documents/Forschung/O1/vendor/fabel/dotcausal_package/src")


def load_module(path: Path, name: str) -> Any:
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot import A388 dependency {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


A385 = load_module(A385_RUNNER, "a388_a385")
A349 = load_module(A349_RUNNER, "a388_a349")
A351 = load_module(A351_RUNNER, "a388_a351")
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
        raise RuntimeError("A388 design hash differs")
    value = json.loads(DESIGN.read_bytes())
    boundary = value.get("information_boundary", {})
    measurement = value.get("measurement_contract", {})
    reader = value.get("reader_contract", {})
    if (
        value.get("schema")
        != "chacha20-round20-w50-public-output-direct12-factor3-a388-design-v1"
        or value.get("attempt_id") != ATTEMPT_ID
        or value.get("design_state")
        != "frozen_after_A385_public_challenge_and_A387_protocol_before_A388_measurement_order_or_any_A387_result_or_true_prefix"
        or boundary.get("A385_public_challenge_available_at_design_freeze") is not True
        or boundary.get("A387_recovery_execution_started_at_design_freeze") is not True
        or boundary.get("A387_result_or_true_prefix_available_at_design_freeze") is not False
        or boundary.get("A387_progress_or_filter_outcomes_consumed") is not False
        or boundary.get("A388_target_labels_used_for_order_construction") != 0
        or boundary.get("A388_reader_refits") != 0
        or measurement.get("complete_direct_prefix_cells") != CELLS
        or measurement.get("low4_fixed_unit_coordinates") != list(low4_coordinates(WIDTH))
        or measurement.get("high8_assumption_coordinates")
        != list(range(WIDTH - 1, WIDTH - 9, -1))
        or reader.get("selected_view") != SELECTED_VIEW
        or reader.get("reader_refits") != 0
    ):
        raise RuntimeError("A388 frozen design semantics differ")
    for key, source_path in value["source_anchors"].items():
        if key.endswith("_path"):
            expected = value["source_anchors"][key.removesuffix("_path") + "_sha256"]
            anchor(ROOT / source_path, expected)
    return value


def assert_pre_w50_result() -> None:
    if A387_RESULT.exists():
        raise RuntimeError("A388 order construction must precede every A387 result or true prefix")


def freeze_implementation() -> dict[str, Any]:
    if any(path.exists() for path in (IMPLEMENTATION, PREFLIGHT, ORDER, CAUSAL, REPORT, MEASUREMENTS, ARTIFACTS)):
        raise FileExistsError("A388 implementation or target artifacts already exist")
    if not A385_PROTOCOL.exists():
        raise FileNotFoundError("A388 requires the frozen public A385 W50 protocol")
    load_design()
    assert_pre_w50_result()
    if not TEST.exists() or not REPRO.exists():
        raise FileNotFoundError("A388 test and reproducer must precede implementation freeze")
    payload: dict[str, Any] = {
        "schema": "chacha20-round20-w50-public-output-direct12-factor3-a388-implementation-v1",
        "attempt_id": ATTEMPT_ID,
        "commitment_state": "frozen_after_A385_public_challenge_and_A387_protocol_before_A388_measurement_order_or_any_A387_result_or_true_prefix",
        "design_sha256": DESIGN_SHA256,
        "selected_view": SELECTED_VIEW,
        "A385_protocol_available_at_implementation_freeze": True,
        "A387_recovery_execution_started_at_implementation_freeze": True,
        "A387_result_or_true_prefix_available_at_implementation_freeze": False,
        "A387_progress_or_filter_outcomes_consumed": False,
        "anchors": {
            "design": anchor(DESIGN, DESIGN_SHA256),
            "A385_design": anchor(A385_DESIGN, A385_DESIGN_SHA256),
            "A385_implementation": anchor(A385_IMPLEMENTATION, A385_IMPLEMENTATION_SHA256),
            "A385_order": anchor(A385_ORDER, A385_ORDER_SHA256),
            "A385_protocol": anchor(A385_PROTOCOL, A385_PROTOCOL_SHA256),
            "A385_runner": anchor(A385_RUNNER, A385_RUNNER_SHA256),
            "A386_order": anchor(A386_ORDER, A386_ORDER_SHA256),
            "A386_runner": anchor(A386_RUNNER, A386_RUNNER_SHA256),
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
    assert_pre_w50_result()
    return payload


def load_implementation(expected_sha256: str) -> dict[str, Any]:
    if file_sha256(IMPLEMENTATION) != expected_sha256:
        raise RuntimeError("A388 implementation hash differs")
    value = json.loads(IMPLEMENTATION.read_bytes())
    if (
        value.get("schema")
        != "chacha20-round20-w50-public-output-direct12-factor3-a388-implementation-v1"
        or value.get("attempt_id") != ATTEMPT_ID
        or value.get("commitment_state")
        != "frozen_after_A385_public_challenge_and_A387_protocol_before_A388_measurement_order_or_any_A387_result_or_true_prefix"
        or value.get("design_sha256") != DESIGN_SHA256
        or value.get("selected_view") != SELECTED_VIEW
        or value.get("A385_protocol_available_at_implementation_freeze") is not True
        or value.get("A387_recovery_execution_started_at_implementation_freeze") is not True
        or value.get("A387_result_or_true_prefix_available_at_implementation_freeze") is not False
        or value.get("A387_progress_or_filter_outcomes_consumed") is not False
    ):
        raise RuntimeError("A388 implementation semantics differ")
    expected = {
        "design": DESIGN,
        "A385_design": A385_DESIGN,
        "A385_implementation": A385_IMPLEMENTATION,
        "A385_order": A385_ORDER,
        "A385_protocol": A385_PROTOCOL,
        "A385_runner": A385_RUNNER,
        "A386_order": A386_ORDER,
        "A386_runner": A386_RUNNER,
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
            raise RuntimeError(f"A388 implementation anchor differs: {name}")
    unsigned = {key: item for key, item in value.items() if key != "implementation_commitment_sha256"}
    if value.get("implementation_commitment_sha256") != canonical_sha256(unsigned):
        raise RuntimeError("A388 implementation commitment differs")
    return value


def load_a385_protocol(expected_sha256: str) -> dict[str, Any]:
    value = A385.load_protocol(expected_sha256)
    challenge = value.get("public_challenge", {})
    if (
        value.get("schema") != "chacha20-round20-fresh-w50-pretarget-transfer-a385-protocol-v1"
        or challenge.get("unknown_key_bits") != WIDTH
        or challenge.get("unknown_assignment_included") is not False
        or "assignment" in challenge
        or "candidate" in challenge
        or "prefix12" in challenge
    ):
        raise RuntimeError("A388 A385 public challenge boundary differs")
    return value


def exact_order(values: Sequence[int], label: str) -> list[int]:
    return A351.exact_order(values, f"A388 {label}")


def rank_vector(order: Sequence[int]) -> list[int]:
    ranks = [0] * CELLS
    for rank, cell in enumerate(exact_order(order, "rank vector"), 1):
        ranks[cell] = rank
    return ranks


def load_a386_transfer_order() -> dict[str, Any]:
    anchor(A386_ORDER, A386_ORDER_SHA256)
    value = json.loads(A386_ORDER.read_bytes())
    selected = exact_order(value.get("selected_order", []), "A386 transfer")
    if (
        value.get("schema")
        != "chacha20-round20-w49-calibrated-ticketed-hierarchical-factor3-a386-order-v1"
        or value.get("attempt_id") != "A386"
        or value.get("candidate_assignments_executed_by_A386") != 0
        or value.get("W49_target_labels_used") != 0
        or value.get("W49_candidate_or_filter_outcomes_used") != 0
        or A351.order_sha256(selected) != A386_SELECTED_ORDER_UINT16BE_SHA256
        or value.get("selected_order_uint16be_sha256")
        != A386_SELECTED_ORDER_UINT16BE_SHA256
        or value.get("outer_factor3_proof", {}).get("violations") != 0
    ):
        raise RuntimeError("A388 A386 target-blind transfer semantics differ")
    return value


def factor3_wavefront(source_orders: Mapping[str, Sequence[int]]) -> list[int]:
    if tuple(source_orders) != FACTOR3_ROLES:
        raise ValueError("A388 factor-three source roles differ")
    ranks = {role: rank_vector(source_orders[role]) for role in FACTOR3_ROLES}
    return exact_order(
        sorted(
            range(CELLS),
            key=lambda cell: (
                min(ranks[role][cell] for role in FACTOR3_ROLES),
                sum(ranks[role][cell] for role in FACTOR3_ROLES),
                *(ranks[role][cell] for role in FACTOR3_ROLES),
                cell,
            ),
        ),
        "factor-three wavefront",
    )


def factor3_proof(
    source_orders: Mapping[str, Sequence[int]], selected: Sequence[int]
) -> dict[str, Any]:
    if tuple(source_orders) != FACTOR3_ROLES:
        raise ValueError("A388 factor-three proof roles differ")
    source_ranks = {role: rank_vector(source_orders[role]) for role in FACTOR3_ROLES}
    selected_ranks = rank_vector(selected)
    ratios = [
        selected_ranks[cell]
        / min(source_ranks[role][cell] for role in FACTOR3_ROLES)
        for cell in range(CELLS)
    ]
    violations = [cell for cell, ratio in enumerate(ratios) if ratio > 3.0 + 1e-15]
    if violations:
        raise RuntimeError("A388 factor-three pointwise proof failed")
    return {
        "bound": "R_A388(c) <= 3*min(R_A385(c),R_Direct12(c),R_A386(c))",
        "cells_checked": CELLS,
        "maximum_ratio": max(ratios),
        "mean_ratio": sum(ratios) / CELLS,
        "source_count": len(FACTOR3_ROLES),
        "violations": 0,
    }


def diversity_panel(source_orders: Mapping[str, Sequence[int]]) -> dict[str, Any]:
    if tuple(source_orders) != FACTOR3_ROLES:
        raise ValueError("A388 diversity source roles differ")
    panel: dict[str, Any] = {}
    for left_index, left in enumerate(FACTOR3_ROLES):
        for right in FACTOR3_ROLES[left_index + 1 :]:
            panel[f"{left}__vs__{right}"] = A351.diversity_panel(
                source_orders[left], source_orders[right]
            )
    return panel


def bridge_challenge(protocol: Mapping[str, Any]) -> dict[str, Any]:
    source = protocol["public_challenge"]
    remainder = WIDTH - 32
    masks = [0, (~((1 << remainder) - 1)) & MASK32, *([MASK32] * 6)]
    known = [int(value) & MASK32 for value in source["known_zeroed_key_words"]]
    values = [value & mask for value, mask in zip(known, masks, strict=True)]
    bridge = {
        "challenge_id": "A388-bridge-" + str(source["challenge_id"]),
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
    if bridge["known_key_mask_words"][1] != 0xFFFC0000:
        raise RuntimeError("A388 W50 known-mask codec differs")
    return bridge


def w50_source_formula(a223: Any, challenge: dict[str, Any]) -> str:
    formula = A340.A296.b1_formula(a223, challenge, WIDTH)
    remainder = WIDTH % 32
    word = WIDTH // 32
    known_width = 32 - remainder
    known = int(challenge["known_key_value_words"][word]) >> remainder
    generated = f"(assert (= ((_ extract 31 {remainder}) k{word}) #x{known:0{known_width // 4}x}))"
    corrected = f"(assert (= ((_ extract 31 {remainder}) k{word}) #b{known:0{known_width}b}))"
    if formula.count(generated) != 1 or corrected in formula:
        raise RuntimeError("A388 W50 known-suffix correction boundary differs")
    result = formula.replace(generated, corrected)
    if result.count(corrected) != 1 or generated in result:
        raise RuntimeError("A388 W50 known-suffix correction failed")
    return result


def preflight(*, expected_implementation_sha256: str, expected_a385_protocol_sha256: str) -> dict[str, Any]:
    if PREFLIGHT.exists() or ARTIFACTS.exists():
        raise FileExistsError("A388 preflight artifacts already exist")
    assert_pre_w50_result()
    implementation = load_implementation(expected_implementation_sha256)
    protocol = load_a385_protocol(expected_a385_protocol_sha256)
    bridge = bridge_challenge(protocol)
    a223 = A340.load_module(A340.A223_SOURCE, "a388_a223_preflight")
    config = json.loads(A340.A223_CONFIG.read_bytes())
    a223._toolchain_gates(config)  # noqa: SLF001
    a223._validate_challenge(bridge, width=WIDTH)  # noqa: SLF001
    formula = w50_source_formula(a223, bridge)
    ARTIFACTS.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="a388_w50_b1_", dir=ARTIFACTS.parent) as temporary:
        directory = Path(temporary)
        temporary_cnf = directory / "base.cnf"
        export = a223._export_cnf(  # noqa: SLF001
            formula=formula,
            output=temporary_cnf,
            config=config,
            label="A388_A385_W50_B1_DIRECT12",
        )
        raw = temporary_cnf.read_bytes()
        lines = raw.splitlines(keepends=True)
        header = lines[0].split() if lines else []
        if len(header) != 4 or header[:2] != [b"p", b"cnf"]:
            raise RuntimeError("A388 base CNF header differs")
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
        raise RuntimeError("A388 source or synthetic mapping differs")
    payload: dict[str, Any] = {
        "schema": "chacha20-round20-w50-public-output-direct12-factor3-a388-preflight-v1",
        "attempt_id": ATTEMPT_ID,
        "evidence_stage": "PRE_W50_RECOVERY_PUBLIC_OUTPUT_DIRECT12_CNF_AND_READER_FROZEN",
        "implementation_sha256": expected_implementation_sha256,
        "implementation_commitment_sha256": implementation["implementation_commitment_sha256"],
        "A385_protocol_sha256": expected_a385_protocol_sha256,
        "A385_public_challenge_sha256": protocol["public_challenge_sha256"],
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
        "A387_result_or_true_prefix_available_at_preflight": False,
        "A387_progress_or_filter_outcomes_consumed": False,
        "anchors": {
            "implementation": anchor(IMPLEMENTATION, expected_implementation_sha256),
            "A385_protocol": anchor(A385_PROTOCOL, expected_a385_protocol_sha256),
            "A385_order": anchor(A385_ORDER, A385_ORDER_SHA256),
            "A349_selection": anchor(A349_SELECTION, A349_SELECTION_SHA256),
            "A342_result": anchor(A342_RESULT, A342_RESULT_SHA256),
            "A348_result": anchor(A348_RESULT, A348_RESULT_SHA256),
            "runner": anchor(Path(__file__)),
        },
    }
    payload["preflight_commitment_sha256"] = canonical_sha256(payload)
    atomic_json(PREFLIGHT, payload)
    assert_pre_w50_result()
    return payload


def load_preflight(expected_sha256: str, expected_a385_protocol_sha256: str) -> dict[str, Any]:
    if file_sha256(PREFLIGHT) != expected_sha256:
        raise RuntimeError("A388 preflight hash differs")
    value = json.loads(PREFLIGHT.read_bytes())
    if (
        value.get("schema") != "chacha20-round20-w50-public-output-direct12-factor3-a388-preflight-v1"
        or value.get("A385_protocol_sha256") != expected_a385_protocol_sha256
        or value.get("A387_result_or_true_prefix_available_at_preflight") is not False
        or value.get("A387_progress_or_filter_outcomes_consumed") is not False
        or value.get("low4_coordinates") != list(low4_coordinates(WIDTH))
        or value.get("target_labels_used") != 0
        or value.get("reader_refits") != 0
    ):
        raise RuntimeError("A388 preflight semantics differ")
    anchor(BASE_CNF, value["CNF"]["sha256"])
    return value


def low4_coordinates(width: int) -> tuple[int, int, int, int]:
    if width < PREFIX_BITS:
        raise ValueError("A388 width is smaller than direct12")
    values = tuple(range(width - 9, width - 13, -1))
    if len(values) != LOW_BITS:
        raise RuntimeError("A388 low4 coordinate derivation differs")
    return values  # type: ignore[return-value]


def low4_unit_literals(low4: int, source_mapping: Sequence[int], width: int = WIDTH) -> list[int]:
    mapping = [int(value) for value in source_mapping]
    if not 0 <= low4 < len(SLICES) or len(mapping) != width:
        raise ValueError("A388 low4 slice or source mapping differs")
    result = []
    for offset, coordinate in enumerate(low4_coordinates(width)):
        one_literal = mapping[coordinate]
        bit = (low4 >> (LOW_BITS - 1 - offset)) & 1
        result.append(one_literal if bit else -one_literal)
    if len({abs(value) for value in result}) != LOW_BITS:
        raise RuntimeError("A388 low4 unit variables alias")
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
        raise RuntimeError("A388 compressed slice hash differs")
    raw = zstandard.ZstdDecompressor().decompress(compressed)
    if ledger is not None and sha256(raw) != ledger["raw_sha256"]:
        raise RuntimeError("A388 raw slice hash differs")
    value = json.loads(raw)
    if canonical_bytes(value) != raw:
        raise RuntimeError("A388 slice is not canonical")
    return value


def _prepare_slices(preflight_value: Mapping[str, Any]) -> list[dict[str, Any]]:
    base_raw = BASE_CNF.read_bytes()
    mapping = preflight_value["source_one_literals_bit0_upward"]
    rows = []
    for low4 in SLICES:
        cnf_path, measurement_path = _slice_paths(low4)
        expected = render_slice_cnf(base_raw, low4=low4, source_mapping=mapping)
        if cnf_path.exists() and cnf_path.read_bytes() != expected:
            raise RuntimeError(f"A388 slice CNF differs: {low4}")
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
        value.get("schema") != "chacha20-round20-w50-public-output-direct12-factor3-a388-slice-v1"
        or value.get("low4") != low4
        or value.get("target_label_available_to_measurement") is not False
        or value.get("complete_candidate_cover") is not True
        or len(run.get("cells", [])) != COARSE_CELLS
        or len(run.get("stages", [])) != COARSE_CELLS * len(HORIZONS)
        or any(cell.get("final_status") != "unknown" for cell in run["cells"])
        or run.get("all_watchdogs_clear") is not True
    ):
        raise RuntimeError(f"A388 prospective slice gate failed: {low4}")


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
        mode=f"A388_A385_W50_direct12_low4_{low4:02x}",
        order=[f"{value:08b}" for value in range(COARSE_CELLS)],
        key_one_literals_bit0_through_bit19=key_mapping,
        conflict_horizons=HORIZONS,
        watchdog_seconds=WATCHDOG_SECONDS,
        external_timeout_seconds=3600.0,
    )
    stable = {key: value for key, value in raw_run.items() if key not in {"command", "process_elapsed_seconds"}}
    value = {
        "schema": "chacha20-round20-w50-public-output-direct12-factor3-a388-slice-v1",
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

    writer = CausalWriter(api_id="a388w50")
    writer._rules = []
    writer.add_rule(
        name="frozen_reader_to_unlabeled_W50_order",
        description="The frozen A342 Reader consumes the complete fresh W50 Direct12 trajectory field without refit, secret labels, candidate assignments, or A387 progress.",
        pattern=["A342_frozen_pair_reader", "A385_public_output_direct12_grid"],
        conclusion="A388_W50_public_output_direct12_order",
        confidence_modifier=1.0,
    )
    writer.add_rule(
        name="three_complementary_orders_to_exact_factor3",
        description="The A385 pretarget order, W50 public-output Direct12 order, and A386 W50-target-blind transfer form a stable min-rank wavefront with an exact pointwise factor-three bound.",
        pattern=[
            "A385_pretarget_six_view_order",
            "A388_W50_public_output_direct12_order",
            "A386_calibrated_target_blind_transfer",
        ],
        conclusion="A388_W50_factor3_portfolio",
        confidence_modifier=1.0,
    )
    writer.add_rule(
        name="factor3_order_to_complete_W50_execution",
        description="The exact A388 order is ready for the qualified complete 128-slab W50 engine as an independent same-target recovery lane.",
        pattern=["A388_W50_factor3_portfolio", "A384_qualified_complete_W50_engine"],
        conclusion="A389_W50_factor3_recovery_ready",
        confidence_modifier=1.0,
    )
    writer.add_triplet(
        trigger="A342:frozen_selected_pair_reader",
        mechanism="zero_refit_complete_A385_public_output_direct12_measurement",
        outcome="A388:W50_public_output_direct12_order",
        confidence=1.0,
        source=payload["order_commitment_sha256"],
        quantification=json.dumps(payload["measurement_summary"], sort_keys=True),
        evidence="target-label-free exact 4096-cell W50 order; A387 progress and outcomes not consumed",
        domain="prospective ChaCha20 R20 W50 reader transfer",
        quality_score=1.0,
    )
    writer.add_triplet(
        trigger="A385:pretarget_order_plus_A386:calibrated_target_blind_transfer",
        mechanism="stable_three_source_min_rank_merge_with_public_output_Direct12_order",
        outcome="A388:W50_factor3_portfolio",
        confidence=1.0,
        source=payload["order_commitment_sha256"],
        quantification=json.dumps(payload["pointwise_factor3_proof"], sort_keys=True),
        evidence=json.dumps(payload["operator_diversity"], sort_keys=True),
        domain="bounded W50 multiview recovery order",
        quality_score=1.0,
    )
    writer.add_triplet(
        trigger="A342:frozen_selected_pair_reader",
        mechanism="materialized_W50_Direct12_reader_factor3_execution_chain",
        outcome="A389:W50_factor3_recovery_ready",
        confidence=1.0,
        source="materialized:A388_W50_factor3_chain",
        quantification="exact retained closure",
        evidence="A388 consumed zero target labels, zero Reader refits, zero candidate assignments, and zero A387 progress or filter outcomes",
        domain="AI-native retained inference",
        quality_score=1.0,
        is_inferred=True,
    )
    writer.add_cluster(
        name="A388 W50 public-output Direct12 exact factor-three portfolio",
        entities=[
            "A342:frozen_selected_pair_reader",
            "A385:pretarget_six_view_order",
            "A388:W50_public_output_direct12_order",
            "A386:calibrated_target_blind_transfer",
            "A388:W50_factor3_portfolio",
            "A389:W50_factor3_recovery_ready",
        ],
    )
    writer.add_gap(
        subject="A389:W50_factor3_recovery_ready",
        predicate="next_required_object",
        expected_object_type="executed_fullround_W50_recovery_in_frozen_A388_order",
        confidence=1.0,
        suggested_queries=["Execute the qualified one-hundred-twenty-eight-slab W50 engine in the frozen A388 order."],
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
        reader.api_id != "a388w50"
        or len(explicit) != 2
        or len(all_rows) != 3
        or len(inferred) != 1
        or len(reader._rules) != 3
        or len(reader._clusters) != 1
        or len(reader._gaps) != 1
    ):
        raise RuntimeError("A388 authentic Causal reopen gate failed")
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
    expected_a385_protocol_sha256: str,
) -> dict[str, Any]:
    if ORDER.exists() or CAUSAL.exists() or REPORT.exists():
        raise FileExistsError("A388 order artifacts already exist")
    assert_pre_w50_result()
    implementation = load_implementation(expected_implementation_sha256)
    frozen = load_preflight(expected_preflight_sha256, expected_a385_protocol_sha256)
    protocol = load_a385_protocol(expected_a385_protocol_sha256)
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
        raise RuntimeError("A388 complete slice cover differs")
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
    direct12_order = A348._rank_order(scores)  # noqa: SLF001
    source_value = A385.load_order()
    pretarget_order = exact_order(source_value["selected_order"], "A385 pretarget")
    calibrated_value = load_a386_transfer_order()
    calibrated_order = exact_order(
        calibrated_value["selected_order"], "A386 target-blind W50 transfer"
    )
    source_orders = {
        FACTOR3_ROLES[0]: pretarget_order,
        FACTOR3_ROLES[1]: direct12_order,
        FACTOR3_ROLES[2]: calibrated_order,
    }
    portfolio = factor3_wavefront(source_orders)
    proof = factor3_proof(source_orders, portfolio)
    diversity = diversity_panel(source_orders)
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
        "A385_public_challenge_sha256": protocol["public_challenge_sha256"],
        "measurement_sha256": canonical_sha256(ledgers),
        "score_field_sha256": canonical_sha256(scores.tolist()),
        "W50_public_output_direct12_order_uint16be_sha256": A351.order_sha256(
            direct12_order
        ),
        "A385_pretarget_order_uint16be_sha256": A351.order_sha256(pretarget_order),
        "A386_target_blind_transfer_order_uint16be_sha256": A351.order_sha256(
            calibrated_order
        ),
        "selected_order_uint16be_sha256": A351.order_sha256(portfolio),
        "source_orders_sha256": canonical_sha256(source_orders),
        "pointwise_factor3_proof": proof,
        "operator_diversity": diversity,
        "target_labels_used": 0,
        "reader_refits": 0,
        "A387_progress_or_filter_outcomes_consumed": False,
    }
    assert_pre_w50_result()
    payload: dict[str, Any] = {
        "schema": "chacha20-round20-w50-public-output-direct12-factor3-a388-order-v1",
        "attempt_id": ATTEMPT_ID,
        "evidence_stage": "PRE_A387_RESULT_COMPLETE_PUBLIC_OUTPUT_DIRECT12_W50_FACTOR3_ORDER_FROZEN",
        "design_sha256": DESIGN_SHA256,
        "implementation_sha256": expected_implementation_sha256,
        "implementation_commitment_sha256": implementation["implementation_commitment_sha256"],
        "preflight_sha256": expected_preflight_sha256,
        "A385_protocol_sha256": expected_a385_protocol_sha256,
        **essential,
        "measurement_summary": measurement_summary,
        "measurement_ledger": ledgers,
        "source_orders": source_orders,
        "W50_public_output_direct12_order": direct12_order,
        "selected_order": portfolio,
        "candidate_assignments_executed": 0,
        "A387_result_or_true_prefix_available_at_order_freeze": False,
        "A387_progress_or_filter_outcomes_consumed": False,
        "volatile_wall_seconds": time.perf_counter() - started,
        "anchors": {
            "design": anchor(DESIGN, DESIGN_SHA256),
            "implementation": anchor(IMPLEMENTATION, expected_implementation_sha256),
            "preflight": anchor(PREFLIGHT, expected_preflight_sha256),
            "A385_protocol": anchor(A385_PROTOCOL, expected_a385_protocol_sha256),
            "A385_order": anchor(A385_ORDER, A385_ORDER_SHA256),
            "A386_order": anchor(A386_ORDER, A386_ORDER_SHA256),
            "A386_runner": anchor(A386_RUNNER, A386_RUNNER_SHA256),
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
    assert_pre_w50_result()
    atomic_bytes(
        REPORT,
        (
            "# A388 — W50 public-output Direct12 exact factor-three portfolio\n\n"
            f"Evidence stage: **{payload['evidence_stage']}**\n\n"
            f"- Complete directly measured prefix cells: **{CELLS:,}**\n"
            f"- Solver stages: **{measurement_summary['solver_stages']:,}**\n"
            f"- Exact pointwise bound: **{proof['bound']}**\n"
            f"- Pairwise operator-diversity panels: **{len(diversity)}**\n"
            "- Target labels / reader refits: **0 / 0**\n"
            "- Candidate assignments executed: **zero**\n"
            "- A387 progress / filter outcomes consumed: **zero**\n"
            "- Authentic AI-native Causal readback: **2 explicit + 1 inferred**\n"
        ).encode(),
    )
    return payload


def analyze() -> dict[str, Any]:
    payload: dict[str, Any] = {
        "attempt_id": ATTEMPT_ID,
        "design_sha256": DESIGN_SHA256,
        "implementation_frozen": IMPLEMENTATION.exists(),
        "A385_protocol_available": A385_PROTOCOL.exists(),
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
    parser.add_argument("--expected-a385-protocol-sha256")
    parser.add_argument("--expected-preflight-sha256")
    args = parser.parse_args()
    if args.freeze_implementation:
        payload = freeze_implementation()
    elif args.preflight:
        if not args.expected_implementation_sha256 or not args.expected_a385_protocol_sha256:
            parser.error("--preflight requires implementation and A385 protocol hashes")
        payload = preflight(
            expected_implementation_sha256=args.expected_implementation_sha256,
            expected_a385_protocol_sha256=args.expected_a385_protocol_sha256,
        )
    elif args.measure:
        if not args.expected_implementation_sha256 or not args.expected_preflight_sha256 or not args.expected_a385_protocol_sha256:
            parser.error("--measure requires implementation, preflight and A385 protocol hashes")
        payload = measure(
            expected_implementation_sha256=args.expected_implementation_sha256,
            expected_preflight_sha256=args.expected_preflight_sha256,
            expected_a385_protocol_sha256=args.expected_a385_protocol_sha256,
        )
    else:
        payload = analyze()
    print(json.dumps(payload, indent=2, sort_keys=True), flush=True)


if __name__ == "__main__":
    main()

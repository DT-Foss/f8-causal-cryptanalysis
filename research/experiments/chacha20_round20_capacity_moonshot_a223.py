#!/usr/bin/env python3
"""Prospective A223 full-round ChaCha20 retained-state capacity portfolio.

This module composes the A187 shared-key eight-block construction with the A211
retained CaDiCaL state mechanism.  It deliberately separates three moments:

1. ``--analyze-only`` validates the frozen public protocol and builds no CNF.
2. ``--preflight-only`` derives exact CNF/literal maps, compiles the helper,
   measures load-only RSS, and freezes a launch manifest without solving cells.
3. ``--run`` accepts an explicit reviewed preflight SHA-256 and executes the
   seven predeclared portfolio arms.  Model spools remain unread until every
   arm in every predeclared memory-safe wave has terminated.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import math
import re
import subprocess
import sys
import tempfile
import time
from collections.abc import Sequence
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any

import numpy as np

ROOT = Path(__file__).parents[2]
RESEARCH = ROOT / "research"
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

A211_RUNNER = RESEARCH / "experiments" / "chacha20_round20_global_incremental_transfer.py"


def _import_a211() -> Any:
    spec = importlib.util.spec_from_file_location("a223_retained_a211_anchor", A211_RUNNER)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


A211 = _import_a211()
P1 = A211.P1

ATTEMPT_ID = "R20-A223-CAPACITY-MOONSHOT-V1"
CONFIG_SCHEMA = "chacha20-round20-capacity-moonshot-a223-protocol-v1"
PREFLIGHT_SCHEMA = "chacha20-round20-capacity-moonshot-a223-preflight-v1"
RESULT_SCHEMA = "chacha20-round20-capacity-moonshot-a223-result-v1"
CONFIG_FILENAME = "chacha20_round20_capacity_moonshot_a223_v1.json"
PREFLIGHT_FILENAME = "chacha20_round20_capacity_moonshot_a223_preflight_v1.json"
RESULT_FILENAME = "chacha20_round20_capacity_moonshot_a223_v1.json"
REPORT_FILENAME = "CAUSAL_CHACHA20_ROUND20_CAPACITY_MOONSHOT_A223_V1.md"

CONFIG_PATH = RESEARCH / "configs" / CONFIG_FILENAME
DEFAULT_PREFLIGHT_PATH = RESEARCH / "results" / "v1" / PREFLIGHT_FILENAME
DEFAULT_RESULT_PATH = RESEARCH / "results" / "v1" / RESULT_FILENAME
ARTIFACT_DIR = RESEARCH / "artifacts" / "a223_capacity_moonshot_v1"
HELPER_SOURCE = RESEARCH / "native" / "cadical_capacity_moonshot_a223.cpp"

WIDTHS = (32, 40, 64, 128, 256)
ROUNDS = 20
SPLIT = 18
BLOCK_COUNT = 8
PREFIX_BITS = 8
CELL_COUNT = 1 << PREFIX_BITS
SOLVER_LIMIT_SECONDS = 10
ARM_EXTERNAL_TIMEOUT_SECONDS = 3050
EXPORT_TIMEOUT_SECONDS = 60
MAX_EXPORT_PROCESSES = 6
MAX_ARM_PROCESSES = 7
RSS_MARGIN_BYTES = 2 * 1024**3
METRIC_NAMES = ("conflicts", "decisions", "search_propagations")

ARM_PLAN = (
    {"arm": "gray8_w40", "width": 40, "order": "reflected_gray8"},
    {"arm": "gray8_w256", "width": 256, "order": "reflected_gray8"},
    {"arm": "numeric_w40", "width": 40, "order": "numeric"},
    {"arm": "numeric_w256", "width": 256, "order": "numeric"},
    {"arm": "gray8_w32", "width": 32, "order": "reflected_gray8"},
    {"arm": "gray8_w64", "width": 64, "order": "reflected_gray8"},
    {"arm": "gray8_w128", "width": 128, "order": "reflected_gray8"},
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


def _atomic_write(path: Path, raw: bytes, *, executable: bool = False) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.tmp")
    temporary.write_bytes(raw)
    if executable:
        temporary.chmod(0o755)
    temporary.replace(path)


def _atomic_json(path: Path, value: Any) -> None:
    _atomic_write(
        path,
        json.dumps(value, indent=2, sort_keys=True, allow_nan=False).encode() + b"\n",
    )


def _relative(path: Path) -> str:
    return str(path.resolve().relative_to(ROOT.resolve()))


def _display_path(path: Path) -> str:
    try:
        return _relative(path)
    except ValueError:
        return str(path.resolve())


def _numeric_order() -> list[str]:
    return [f"{value:08b}" for value in range(CELL_COUNT)]


def _gray8_order() -> list[str]:
    return [f"{value ^ (value >> 1):08b}" for value in range(CELL_COUNT)]


def _order(name: str) -> list[str]:
    if name == "numeric":
        return _numeric_order()
    if name == "reflected_gray8":
        return _gray8_order()
    raise ValueError(f"unknown A223 cell order {name}")


def _expected_known_masks(width: int) -> list[int]:
    masks: list[int] = []
    for word in range(8):
        unknown = max(0, min(32, width - 32 * word))
        masks.append((~((1 << unknown) - 1)) & 0xFFFFFFFF if unknown else 0xFFFFFFFF)
    return masks


def _execution_plan() -> dict[str, Any]:
    return {
        "primitive": "standard_ChaCha20_20_rounds_with_feedforward",
        "mechanism_composition": "A187_shared_key_eight_block_split18_CNF_x_A211_retained_global_CaDiCaL_state",
        "rounds": ROUNDS,
        "split": SPLIT,
        "shared_key_target_blocks": BLOCK_COUNT,
        "target_output_bits_constrained_per_CNF": BLOCK_COUNT * 512,
        "independent_confirmation_output_bits": BLOCK_COUNT * 512,
        "unknown_widths": list(WIDTHS),
        "unknown_global_bit_interval_by_width": {str(width): [0, width - 1] for width in WIDTHS},
        "partition": {
            "fixed_coordinates_by_width": {
                str(width): list(range(width - 1, width - 9, -1)) for width in WIDTHS
            },
            "free_bits_by_width": {str(width): width - PREFIX_BITS for width in WIDTHS},
            "cells_per_arm": CELL_COUNT,
            "candidate_count_per_cell_by_width": {
                str(width): str(1 << (width - PREFIX_BITS)) for width in WIDTHS
            },
            "complete_domain_candidate_count_by_width": {
                str(width): str(1 << width) for width in WIDTHS
            },
            "complete_and_disjoint": True,
        },
        "phase1_arms_in_memory_wave_priority": [dict(row) for row in ARM_PLAN],
        "phase1_arm_count": len(ARM_PLAN),
        "portfolio_basis": "A217_low_correlated_Numeric_and_Gray_trajectories",
        "solver_processes_per_arm": 1,
        "maximum_concurrent_A223_arm_processes": MAX_ARM_PROCESSES,
        "A220_reserved_physical_cores": 2,
        "maximum_total_active_solver_processes_including_A220": 9,
        "one_physical_core_intentionally_idle": True,
        "solver_time_limit_seconds_per_cell": SOLVER_LIMIT_SECONDS,
        "external_timeout_seconds_per_arm": ARM_EXTERNAL_TIMEOUT_SECONDS,
        "complete_256_cell_order_required": True,
        "early_stop_permitted": False,
        "unknown_is_not_unsat": True,
        "retained_state_scope": "one_fresh_CaDiCaL_process_per_arm_across_all_256_cells",
        "model_disclosure_barrier": "model_spools_are_not_read_until_all_seven_arms_across_all_frozen_waves_terminate",
        "preflight_export_process_cap": MAX_EXPORT_PROCESSES,
        "RSS_schedule_rule": "load_each_width_CNF_without_solve_then_first_fit_in_frozen_arm_priority_under_sum_RSS_plus_2GiB_at_most_hw_memsize",
        "RSS_fixed_margin_bytes": RSS_MARGIN_BYTES,
        "full_key_arm": "gray8_w256_and_numeric_w256",
        "A184_scope_direct_comparison_arm": "gray8_w40_and_numeric_w40",
        "wallclock_excluded_from_canonical_scientific_hashes": True,
    }


def _challenge_map(config: dict[str, Any]) -> dict[int, dict[str, Any]]:
    return {int(row["width"]): row["public_challenge"] for row in config["challenges"]}


def _validate_challenge(challenge: dict[str, Any], *, width: int) -> None:
    targets = challenge.get("target_words", [])
    hashes = challenge.get("target_block_sha256", [])
    control = challenge.get("control_target_words", [])
    masks = _expected_known_masks(width)
    values = challenge.get("known_key_value_words", [])
    forbidden = {
        "key_words",
        "full_key_words",
        "secret_key_words",
        "unknown_assignment",
        "unknown_assignment_value",
        "unknown_key_value",
    }
    if forbidden & set(challenge):
        raise RuntimeError(f"A223 W{width} public challenge contains a secret field")
    if (
        challenge.get("rounds") != ROUNDS
        or challenge.get("block_count") != BLOCK_COUNT
        or challenge.get("counter_schedule") != "base_plus_block_index_mod_2^32"
        or challenge.get("unknown_key_bits") != width
        or challenge.get("known_key_bits") != 256 - width
        or challenge.get("unknown_global_bit_interval") != [0, width - 1]
        or challenge.get("unknown_bit_numbering")
        != "little_endian_bit0_upward_across_key_words_k0_through_k7"
        or challenge.get("unknown_assignment_included") is not False
        or challenge.get("unknown_assignment_value_included") is not False
        or challenge.get("full_key_included") is not False
        or challenge.get("secret_used_only_for_target_construction") is not True
        or challenge.get("secret_discarded_after_target_construction") is not True
        or challenge.get("generation_entropy_source") != "python_secrets_token_bytes_OS_CSPRNG"
        or challenge.get("known_key_mask_words") != masks
        or len(values) != 8
        or any(value & ~mask for value, mask in zip(values, masks, strict=True))
        or len(challenge.get("nonce_words", [])) != 3
        or len(targets) != BLOCK_COUNT
        or any(len(block) != 16 for block in targets)
        or len(hashes) != BLOCK_COUNT
        or len(control) != 16
        or control[0] != (targets[0][0] ^ 1)
        or control[1:] != targets[0][1:]
    ):
        raise RuntimeError(f"A223 W{width} public challenge structural gate failed")
    for block, digest in zip(targets, hashes, strict=True):
        if _sha256(P1._word_bytes(block)) != digest:
            raise RuntimeError(f"A223 W{width} target fingerprint differs")
    if _sha256(P1._word_bytes(control)) != challenge["control_target_block_sha256"]:
        raise RuntimeError(f"A223 W{width} control fingerprint differs")


def _anchor_gates(config: dict[str, Any]) -> dict[str, str]:
    observed: dict[str, str] = {}
    for row in config["anchors"]:
        path = ROOT / row["path"]
        digest = _file_sha256(path)
        if digest != row["sha256"]:
            raise RuntimeError(f"A223 anchor hash differs: {row['path']}")
        observed[row["label"]] = digest
    return observed


def _toolchain_gates(config: dict[str, Any]) -> dict[str, Any]:
    declared = config["toolchain"]
    paths = {
        "bitwuzla": Path(declared["Bitwuzla_path"]),
        "compiler": Path(declared["compiler"]),
        "cadical_header": Path(declared["cadical_header"]),
        "cadical_static_library": Path(declared["cadical_static_library"]),
        "helper_source": ROOT / declared["helper_source"],
    }
    hashes = {name: _file_sha256(path) for name, path in paths.items()}
    hash_fields = {
        "bitwuzla": "Bitwuzla_sha256",
        "compiler": "compiler_sha256",
        "cadical_header": "cadical_header_sha256",
        "cadical_static_library": "cadical_static_library_sha256",
        "helper_source": "helper_source_sha256",
    }
    if any(hashes[name] != declared[field] for name, field in hash_fields.items()):
        raise RuntimeError("A223 toolchain byte identity gate failed")
    bitwuzla = subprocess.run(
        [str(paths["bitwuzla"]), "--version"], text=True, capture_output=True, check=False
    )
    compiler = subprocess.run(
        [str(paths["compiler"]), "--version"], text=True, capture_output=True, check=False
    )
    compiler_first = compiler.stdout.splitlines()[0] if compiler.stdout.splitlines() else ""
    if (
        bitwuzla.returncode != 0
        or bitwuzla.stdout.strip() != declared["Bitwuzla_version"]
        or compiler.returncode != 0
        or compiler_first != declared["compiler_version_first_line"]
    ):
        raise RuntimeError("A223 toolchain version gate failed")
    return {
        **{f"{name}_sha256": digest for name, digest in hashes.items()},
        "Bitwuzla_version": bitwuzla.stdout.strip(),
        "compiler_version_first_line": compiler_first,
    }


def _load_config() -> dict[str, Any]:
    config = json.loads(CONFIG_PATH.read_bytes())
    plan = _execution_plan()
    if (
        config.get("schema") != CONFIG_SCHEMA
        or config.get("attempt_id") != ATTEMPT_ID
        or config.get("protocol_state")
        != "refrozen_after_outcome_free_b8_export_feasibility_before_any_A223_cell_solver_execution"
        or config.get("execution_plan") != plan
        or config.get("execution_plan_sha256") != _canonical_sha256(plan)
        or [int(row.get("width", -1)) for row in config.get("challenges", [])] != list(WIDTHS)
    ):
        raise RuntimeError("A223 frozen config identity gate failed")
    identifiers: set[str] = set()
    for row in config["challenges"]:
        width = int(row["width"])
        challenge = row["public_challenge"]
        _validate_challenge(challenge, width=width)
        if row.get("public_challenge_sha256") != _canonical_sha256(challenge):
            raise RuntimeError(f"A223 W{width} public challenge hash differs")
        identifiers.add(challenge["challenge_id"])
    if len(identifiers) != len(WIDTHS):
        raise RuntimeError("A223 challenges are not independently identified")
    boundary = config.get("information_boundary", {})
    if (
        boundary.get("fresh_independent_OS_random_target_key_per_width") is not True
        or boundary.get("secret_assignment_stored_in_config_runner_or_helper") is not False
        or boundary.get("target_model_available_to_cell_order") is not False
        or boundary.get("cell_outcome_available_when_protocol_frozen") is not False
        or boundary.get("model_spools_read_before_all_phase1_arms_terminate") is not False
        or boundary.get("early_stop_permitted") is not False
    ):
        raise RuntimeError("A223 information boundary gate failed")
    return config


def _symbolic_word_count(width: int) -> int:
    return (width + 31) // 32


def _initial_expressions(challenge: dict[str, Any], *, width: int, block: int) -> list[str]:
    key_words = [
        f"k{word}" if 32 * word < width else f"#x{challenge['known_key_value_words'][word]:08x}"
        for word in range(8)
    ]
    return [
        "#x61707865",
        "#x3320646e",
        "#x79622d32",
        "#x6b206574",
        *key_words,
        f"#x{(challenge['counter_start'] + block) & 0xFFFFFFFF:08x}",
        *[f"#x{value:08x}" for value in challenge["nonce_words"]],
    ]


def _source_formula(challenge: dict[str, Any], *, width: int) -> str:
    """Return one split18 formula jointly constraining all eight R20 blocks."""
    lines = [
        "(set-logic QF_BV)",
        "(set-option :produce-models true)",
        "(define-fun rotl16 ((x (_ BitVec 32))) (_ BitVec 32) (bvor (bvshl x #x00000010) (bvlshr x #x00000010)))",
        "(define-fun rotl12 ((x (_ BitVec 32))) (_ BitVec 32) (bvor (bvshl x #x0000000c) (bvlshr x #x00000014)))",
        "(define-fun rotl8 ((x (_ BitVec 32))) (_ BitVec 32) (bvor (bvshl x #x00000008) (bvlshr x #x00000018)))",
        "(define-fun rotl7 ((x (_ BitVec 32))) (_ BitVec 32) (bvor (bvshl x #x00000007) (bvlshr x #x00000019)))",
        "(define-fun rotr16 ((x (_ BitVec 32))) (_ BitVec 32) (rotl16 x))",
        "(define-fun rotr12 ((x (_ BitVec 32))) (_ BitVec 32) (bvor (bvlshr x #x0000000c) (bvshl x #x00000014)))",
        "(define-fun rotr8 ((x (_ BitVec 32))) (_ BitVec 32) (bvor (bvlshr x #x00000008) (bvshl x #x00000018)))",
        "(define-fun rotr7 ((x (_ BitVec 32))) (_ BitVec 32) (bvor (bvlshr x #x00000007) (bvshl x #x00000019)))",
    ]
    for word in range(_symbolic_word_count(width)):
        lines.append(f"(declare-fun k{word} () (_ BitVec 32))")
    assignment_counter = 0

    def assign(block: int, expression: str) -> str:
        nonlocal assignment_counter
        name = f"b{block}_v{assignment_counter}"
        assignment_counter += 1
        lines.append(f"(define-fun {name} () (_ BitVec 32) {expression})")
        return name

    def forward_qr(state: list[str], block: int, a: int, b: int, c: int, d: int) -> None:
        state[a] = assign(block, f"(bvadd {state[a]} {state[b]})")
        state[d] = assign(block, f"(rotl16 (bvxor {state[d]} {state[a]}))")
        state[c] = assign(block, f"(bvadd {state[c]} {state[d]})")
        state[b] = assign(block, f"(rotl12 (bvxor {state[b]} {state[c]}))")
        state[a] = assign(block, f"(bvadd {state[a]} {state[b]})")
        state[d] = assign(block, f"(rotl8 (bvxor {state[d]} {state[a]}))")
        state[c] = assign(block, f"(bvadd {state[c]} {state[d]})")
        state[b] = assign(block, f"(rotl7 (bvxor {state[b]} {state[c]}))")

    def inverse_qr(state: list[str], block: int, a: int, b: int, c: int, d: int) -> None:
        state[b] = assign(block, f"(bvxor (rotr7 {state[b]}) {state[c]})")
        state[c] = assign(block, f"(bvsub {state[c]} {state[d]})")
        state[d] = assign(block, f"(bvxor (rotr8 {state[d]}) {state[a]})")
        state[a] = assign(block, f"(bvsub {state[a]} {state[b]})")
        state[b] = assign(block, f"(bvxor (rotr12 {state[b]}) {state[c]})")
        state[c] = assign(block, f"(bvsub {state[c]} {state[d]})")
        state[d] = assign(block, f"(bvxor (rotr16 {state[d]}) {state[a]})")
        state[a] = assign(block, f"(bvsub {state[a]} {state[b]})")

    equalities: list[str] = []
    for block in range(BLOCK_COUNT):
        initial = _initial_expressions(challenge, width=width, block=block)
        forward = initial.copy()
        for round_index in range(SPLIT):
            for qr in P1._round_qrs(round_index):
                forward_qr(forward, block, *qr)
        backward = [
            f"(bvsub #x{expected:08x} {initial[lane]})"
            for lane, expected in enumerate(challenge["target_words"][block])
        ]
        for round_index in reversed(range(SPLIT, ROUNDS)):
            for qr in reversed(P1._round_qrs(round_index)):
                inverse_qr(backward, block, *qr)
        equalities.extend(f"(assert (= {forward[lane]} {backward[lane]}))" for lane in range(16))

    remainder = width % 32
    if remainder:
        word = width // 32
        known = challenge["known_key_value_words"][word] >> remainder
        known_width = 32 - remainder
        lines.append(
            f"(assert (= ((_ extract 31 {remainder}) k{word}) #x{known:0{known_width // 4}x}))"
        )
    lines.extend(equalities)
    symbols = " ".join(f"k{word}" for word in range(_symbolic_word_count(width)))
    lines.extend(["(check-sat)", f"(get-value ({symbols}))"])
    return "\n".join(lines) + "\n"


def _pattern(width: int, dimension: int) -> int:
    if dimension == -1:
        return 0
    return sum(1 << bit for bit in range(width) if (bit >> dimension) & 1)


def _pattern_assertions(width: int, dimension: int) -> str:
    pattern = _pattern(width, dimension)
    assertions: list[str] = []
    for word in range(_symbolic_word_count(width)):
        count = min(32, width - 32 * word)
        value = (pattern >> (32 * word)) & ((1 << count) - 1)
        if count == 32:
            assertions.append(f"(assert (= k{word} #x{value:08x}))")
        else:
            assertions.append(
                f"(assert (= ((_ extract {count - 1} 0) k{word}) #b{value:0{count}b}))"
            )
    return "\n".join(assertions)


def _decode_mapping(rows: Sequence[tuple[int, list[int]]], *, width: int) -> list[int]:
    dimensions = math.ceil(math.log2(width))
    by_dimension = {
        dimension: {abs(value): 1 if value > 0 else -1 for value in units}
        for dimension, units in rows
    }
    baseline_units = next(units for dimension, units in rows if dimension == -1)
    baseline = {abs(value): value for value in baseline_units}
    if len(baseline) != width or any(
        set(mapping) != set(baseline) for mapping in by_dimension.values()
    ):
        raise RuntimeError(f"A223 W{width} coordinate probes use different variables")
    result: list[int | None] = [None] * width
    for variable, baseline_literal in baseline.items():
        coordinate = 0
        baseline_sign = 1 if baseline_literal > 0 else -1
        for dimension in range(dimensions):
            if by_dimension[dimension][variable] != baseline_sign:
                coordinate |= 1 << dimension
        if coordinate >= width or result[coordinate] is not None:
            raise RuntimeError(f"A223 W{width} coordinate mapping is not bijective")
        result[coordinate] = -baseline_literal
    if any(value is None for value in result):
        raise RuntimeError(f"A223 W{width} coordinate mapping is incomplete")
    return [int(value) for value in result]


def analyze() -> dict[str, Any]:
    config = _load_config()
    challenges = _challenge_map(config)
    formulas = {width: _source_formula(challenges[width], width=width) for width in WIDTHS}
    return {
        "config": config,
        "config_sha256": _file_sha256(CONFIG_PATH),
        "anchor_gates": _anchor_gates(config),
        "toolchain_gates": _toolchain_gates(config),
        "public_challenge_sha256_by_width": {
            str(row["width"]): row["public_challenge_sha256"] for row in config["challenges"]
        },
        "source_formula_sha256_by_width": {
            str(width): _sha256(formulas[width].encode()) for width in WIDTHS
        },
        "source_formula_bytes_by_width": {
            str(width): len(formulas[width].encode()) for width in WIDTHS
        },
        "shared_key_block_count": BLOCK_COUNT,
        "joint_equality_constraint_count_per_width": BLOCK_COUNT * 16,
        "phase1_arms": [dict(row) for row in ARM_PLAN],
        "cell_solver_execution_started": False,
    }


def _as_text(value: str | bytes | None) -> str:
    if value is None:
        return ""
    return value.decode(errors="replace") if isinstance(value, bytes) else value


def _export_cnf(
    *, formula: str, output: Path, config: dict[str, Any], label: str
) -> dict[str, Any]:
    toolchain = config["toolchain"]
    command = [
        toolchain["Bitwuzla_path"],
        *toolchain["export_arguments"],
        f"--write-cnf={output}",
    ]
    started = time.perf_counter()
    try:
        result = subprocess.run(
            command,
            input=formula,
            text=True,
            capture_output=True,
            timeout=EXPORT_TIMEOUT_SECONDS,
            check=False,
        )
        stdout, stderr, returncode = result.stdout, result.stderr, result.returncode
        externally_timed_out = False
    except subprocess.TimeoutExpired as error:
        stdout = _as_text(error.stdout)
        stderr = _as_text(error.stderr)
        returncode = None
        externally_timed_out = True
    if returncode != 0 or externally_timed_out or not output.exists():
        raise RuntimeError(
            f"A223 CNF export failed for {label}: rc={returncode}, timeout={externally_timed_out}"
        )
    raw = output.read_bytes()
    lines = raw.splitlines()
    if not lines:
        raise RuntimeError(f"A223 CNF export is empty for {label}")
    return {
        "label": label,
        "bytes": len(raw),
        "sha256": _sha256(raw),
        "header": lines[0].decode(),
        "command_sha256": _canonical_sha256(command),
        "returncode": returncode,
        "externally_timed_out": False,
        "stdout_sha256": _sha256(stdout.encode()),
        "stderr_sha256": _sha256(stderr.encode()),
        "solver_status_redacted_and_not_used": True,
        "volatile_seconds": time.perf_counter() - started,
    }


def _compile_helper(*, config: dict[str, Any], output: Path, directory: Path) -> dict[str, Any]:
    toolchain = config["toolchain"]
    temporary = directory / "cadical_capacity_moonshot_a223"
    command = [
        toolchain["compiler"],
        *toolchain["compile_arguments"],
        str(ROOT / toolchain["helper_source"]),
        toolchain["cadical_static_library"],
        "-lpthread",
        "-o",
        str(temporary),
    ]
    started = time.perf_counter()
    result = subprocess.run(
        command, cwd=ROOT, text=True, capture_output=True, timeout=60, check=False
    )
    if result.returncode != 0 or result.stdout or result.stderr or not temporary.exists():
        raise RuntimeError(
            "A223 helper compilation failed: "
            f"rc={result.returncode}, stdout={result.stdout!r}, stderr={result.stderr!r}"
        )
    raw = temporary.read_bytes()
    _atomic_write(output, raw, executable=True)
    return {
        "artifact": _display_path(output),
        "binary_sha256": _sha256(raw),
        "command_sha256": _canonical_sha256(command[:-2]),
        "returncode": result.returncode,
        "stdout_sha256": _sha256(result.stdout.encode()),
        "stderr_sha256": _sha256(result.stderr.encode()),
        "volatile_seconds": time.perf_counter() - started,
    }


def _base_context(
    *, width: int, challenge: dict[str, Any], config: dict[str, Any], directory: Path
) -> dict[str, Any]:
    formula = _source_formula(challenge, width=width)
    base_path = directory / f"a223_w{width}_shared_b8_base.cnf"
    export = _export_cnf(
        formula=formula,
        output=base_path,
        config=config,
        label=f"W{width}_shared_b8_base",
    )
    raw = base_path.read_bytes()
    lines = raw.splitlines(keepends=True)
    fields = lines[0].split()
    if len(fields) != 4 or fields[:2] != [b"p", b"cnf"]:
        raise RuntimeError(f"A223 W{width} base DIMACS header is invalid")
    return {
        "width": width,
        "formula": formula,
        "formula_bytes": len(formula.encode()),
        "formula_sha256": _sha256(formula.encode()),
        "base_path": base_path,
        "base_raw": raw,
        "base_body": b"".join(lines[1:]),
        "base_body_sha256": _sha256(b"".join(lines[1:])),
        "variable_count": int(fields[2]),
        "clause_count": int(fields[3]),
        "base_export": export,
    }


def _coordinate_probe(
    *, context: dict[str, Any], dimension: int, config: dict[str, Any], directory: Path
) -> tuple[int, int, list[int], dict[str, Any]]:
    width = int(context["width"])
    assertions = _pattern_assertions(width, dimension)
    formula = context["formula"].replace("(check-sat)", assertions + "\n(check-sat)", 1)
    output = directory / f"a223_w{width}_coordinate_{dimension}.cnf"
    exported = _export_cnf(
        formula=formula,
        output=output,
        config=config,
        label=f"W{width}_coordinate_{dimension}",
    )
    lines = output.read_bytes().splitlines(keepends=True)
    header = lines[0].split()
    unit_lines = lines[-width:]
    units = [int(line.split()[0]) for line in unit_lines]
    exact = (
        int(header[2]) == context["variable_count"]
        and int(header[3]) == context["clause_count"] + width
        and b"".join(lines[1:-width]) == context["base_body"]
        and all(len(line.split()) == 2 and line.split()[1] == b"0" for line in unit_lines)
        and len({abs(value) for value in units}) == width
    )
    output.unlink()
    if not exact:
        raise RuntimeError(
            f"A223 W{width} coordinate {dimension} is not an exact {width}-unit delta"
        )
    observation = {
        "dimension": dimension,
        "pattern_sha256": _sha256(_pattern(width, dimension).to_bytes((width + 7) // 8, "little")),
        "unit_count": len(units),
        "unit_int32le_sha256": _sha256(np.asarray(units, dtype="<i4").tobytes()),
        "probe_cnf_sha256": exported["sha256"],
        "probe_stdout_sha256": exported["stdout_sha256"],
        "probe_stderr_sha256": exported["stderr_sha256"],
        "exact_unit_delta": True,
    }
    return width, dimension, units, observation


def _build_structural_cnf(
    *,
    context: dict[str, Any],
    source_one_literals: list[int],
    output: Path,
) -> dict[str, Any]:
    width = int(context["width"])
    raw = context["base_raw"]
    prefix_coordinates = list(range(width - 1, width - 9, -1))
    representative_literals = [source_one_literals[bit] for bit in prefix_coordinates]
    lines = raw.splitlines(keepends=True)
    fields = lines[0].decode().split()
    representative = (
        f"p cnf {fields[2]} {int(fields[3]) + PREFIX_BITS}\n".encode()
        + b"".join(lines[1:])
        + b"".join(f"{literal} 0\n".encode() for literal in representative_literals)
    )
    parsed = A211._parse_cnf(representative)
    ids = np.arange(1, parsed["variable_count"] + 1, dtype=np.int64)
    distances = A211._multi_source_bfs(parsed["graph"], parsed["units"])
    order = ids[np.lexsort((ids, -distances))]
    old_to_new = A211._old_to_new(order)
    inverse = np.zeros_like(old_to_new)
    inverse[old_to_new[1:]] = ids
    if not np.array_equal(np.sort(order), ids) or not np.array_equal(inverse[old_to_new[1:]], ids):
        raise RuntimeError(f"A223 W{width} BFS-far mapping is not a bijection")
    transformed = A211._reindex_cnf(raw, old_to_new)
    restored = A211._reindex_cnf(transformed, inverse)
    if restored != raw:
        raise RuntimeError(f"A223 W{width} inverse reindex is not byte exact")
    transformed_model = [
        int(old_to_new[abs(literal)]) if literal > 0 else -int(old_to_new[abs(literal)])
        for literal in source_one_literals
    ]
    transformed_prefix = [transformed_model[bit] for bit in prefix_coordinates]
    base_units = {
        abs(int(line.split()[0])) for line in transformed.splitlines()[1:] if len(line.split()) == 2
    }
    if {abs(value) for value in transformed_prefix} & base_units:
        raise RuntimeError(f"A223 W{width} prefix variables occur as base units")
    _atomic_write(output, transformed)
    return {
        "artifact": _relative(output),
        "derivation": "shared_b8_base_plus_positive_high8_unknown_literals_then_unit_multisource_BFS_far",
        "representative_added_one_literals": representative_literals,
        "prefix_global_bit_coordinates": prefix_coordinates,
        "variable_count": int(parsed["variable_count"]),
        "base_clause_count": int(fields[3]),
        "representative_clause_count": int(parsed["clause_count"]),
        "unit_source_count": len(parsed["units"]),
        "unit_distance_minimum": int(distances.min()),
        "unit_distance_maximum": int(distances.max()),
        "unit_distance_sha256": _sha256(distances.astype("<i8", copy=False).tobytes()),
        "order_sha256": _sha256(order.astype("<u4", copy=False).tobytes()),
        "old_to_new_sha256": _sha256(old_to_new.astype("<u4", copy=False).tobytes()),
        "inverse_sha256": _sha256(inverse.astype("<u4", copy=False).tobytes()),
        "bijection_proved": True,
        "inverse_reindex_byte_identical": True,
        "inverse_restored_sha256": _sha256(restored),
        "transformed_bytes": len(transformed),
        "transformed_sha256": _sha256(transformed),
        "transformed_model_one_literals_bit0_upward": transformed_model,
        "transformed_prefix_one_literals_high_to_low": transformed_prefix,
        "transformed_assumption_variables_absent_from_base_units": True,
        "complete_disjoint_cell_cover_candidate_count": str(1 << width),
    }


def _helper_args(mapping: dict[str, Any]) -> list[str]:
    return [
        "--assumption-one-literals",
        ",".join(str(value) for value in mapping["transformed_prefix_one_literals_high_to_low"]),
        "--model-one-literals",
        ",".join(str(value) for value in mapping["transformed_model_one_literals_bit0_upward"]),
    ]


def _load_only_RSS(
    *, width: int, cnf: Path, helper: Path, mapping: dict[str, Any]
) -> dict[str, Any]:
    command = [
        "/usr/bin/time",
        "-l",
        str(helper),
        "--cnf",
        str(cnf),
        "--arm",
        f"load_only_w{width}",
        *_helper_args(mapping),
        "--load-only",
        "1",
    ]
    result = subprocess.run(command, text=True, capture_output=True, timeout=120, check=False)
    load_lines = [
        line.removeprefix("A223_LOAD ")
        for line in result.stdout.splitlines()
        if line.startswith("A223_LOAD ")
    ]
    maximum = re.search(r"^\s*(\d+)\s+maximum resident set size$", result.stderr, re.M)
    peak = re.search(r"^\s*(\d+)\s+peak memory footprint$", result.stderr, re.M)
    if result.returncode != 0 or len(load_lines) != 1 or maximum is None:
        raise RuntimeError(f"A223 W{width} load-only RSS measurement failed")
    record = json.loads(load_lines[0])
    if record.get("model_width") != width or record.get("arm") != f"load_only_w{width}":
        raise RuntimeError(f"A223 W{width} load-only identity differs")
    return {
        "width": width,
        "maximum_resident_set_bytes": int(maximum.group(1)),
        "peak_memory_footprint_bytes": int(peak.group(1)) if peak else None,
        "load_record": record,
        "load_only_solve_calls": 0,
        "returncode": result.returncode,
        "stdout_sha256": _sha256(result.stdout.encode()),
        "stderr_sha256": _sha256(result.stderr.encode()),
    }


def _freeze_memory_waves(
    *, RSS_by_width: dict[int, dict[str, Any]], system_total_bytes: int
) -> dict[str, Any]:
    capacity = system_total_bytes - RSS_MARGIN_BYTES
    if capacity <= 0:
        raise RuntimeError("A223 RSS margin exceeds system memory")
    waves: list[dict[str, Any]] = []
    for arm in ARM_PLAN:
        required = int(RSS_by_width[int(arm["width"])]["maximum_resident_set_bytes"])
        if required > capacity:
            raise RuntimeError(f"A223 arm {arm['arm']} cannot fit with frozen RSS margin")
        selected = None
        for wave in waves:
            if (
                len(wave["arms"]) < MAX_ARM_PROCESSES
                and int(wave["aggregate_measured_RSS_bytes"]) + required <= capacity
            ):
                selected = wave
                break
        if selected is None:
            selected = {
                "wave_index": len(waves),
                "arms": [],
                "aggregate_measured_RSS_bytes": 0,
            }
            waves.append(selected)
        selected["arms"].append(dict(arm))
        selected["aggregate_measured_RSS_bytes"] += required
    for wave in waves:
        wave["aggregate_plus_margin_bytes"] = (
            int(wave["aggregate_measured_RSS_bytes"]) + RSS_MARGIN_BYTES
        )
        wave["fits_system_total_memory"] = (
            int(wave["aggregate_plus_margin_bytes"]) <= system_total_bytes
        )
    flattened = [arm["arm"] for wave in waves for arm in wave["arms"]]
    if sorted(flattened) != sorted(arm["arm"] for arm in ARM_PLAN):
        raise RuntimeError("A223 frozen wave schedule does not cover all arms")
    return {
        "rule": "priority_order_first_fit_under_measured_RSS_plus_fixed_margin",
        "priority": [arm["arm"] for arm in ARM_PLAN],
        "system_total_memory_bytes": system_total_bytes,
        "fixed_margin_bytes": RSS_MARGIN_BYTES,
        "usable_measured_RSS_capacity_bytes": capacity,
        "wave_count": len(waves),
        "waves": waves,
        "all_seven_arms_covered_once": True,
        "maximum_concurrent_A223_processes": max(len(wave["arms"]) for wave in waves),
        "A220_reserved_processes": 2,
        "at_least_one_physical_core_idle": max(len(wave["arms"]) for wave in waves) + 2 <= 9,
        "frozen_before_any_cell_solver_execution": True,
    }


def preflight(*, output: Path, artifact_dir: Path = ARTIFACT_DIR) -> dict[str, Any]:
    if output.exists():
        raise RuntimeError(f"A223 preflight output already exists: {output}")
    analysis = analyze()
    config = analysis["config"]
    challenges = _challenge_map(config)
    artifact_dir.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="a223-capacity-preflight-") as raw_directory:
        directory = Path(raw_directory)
        contexts = {
            width: _base_context(
                width=width,
                challenge=challenges[width],
                config=config,
                directory=directory,
            )
            for width in WIDTHS
        }
        tasks = [
            (width, dimension)
            for width in WIDTHS
            for dimension in range(-1, math.ceil(math.log2(width)))
        ]

        def probe(item: tuple[int, int]) -> tuple[int, int, list[int], dict[str, Any]]:
            width, dimension = item
            return _coordinate_probe(
                context=contexts[width],
                dimension=dimension,
                config=config,
                directory=directory,
            )

        with ThreadPoolExecutor(max_workers=MAX_EXPORT_PROCESSES) as executor:
            probe_rows = list(executor.map(probe, tasks))
        mappings: dict[int, dict[str, Any]] = {}
        for width in WIDTHS:
            width_rows = [
                (dimension, units)
                for row_width, dimension, units, _ in probe_rows
                if row_width == width
            ]
            one_literals = _decode_mapping(width_rows, width=width)
            expected_exports = 1 + math.ceil(math.log2(width))
            if len(width_rows) != expected_exports:
                raise RuntimeError(f"A223 W{width} coordinate export count differs")
            structural = _build_structural_cnf(
                context=contexts[width],
                source_one_literals=one_literals,
                output=artifact_dir / f"a223_w{width}_shared_b8_bfs_far.cnf",
            )
            mappings[width] = {
                "width": width,
                "mapping_method": "baseline_plus_binary_coordinate_patterns",
                "mapping_export_count": len(width_rows),
                "expected_mapping_export_count": expected_exports,
                "source_one_literals_bit0_upward": one_literals,
                "source_one_literals_int32le_sha256": _sha256(
                    np.asarray(one_literals, dtype="<i4").tobytes()
                ),
                "probe_rows": [
                    observation for row_width, _, _, observation in probe_rows if row_width == width
                ],
                "all_probes_exact_unit_deltas": True,
                "coordinate_mapping_bijective": True,
                "structural_CNF": structural,
            }
        helper_artifact = artifact_dir / "cadical_capacity_moonshot_a223"
        compilation = _compile_helper(config=config, output=helper_artifact, directory=directory)
        RSS_by_width = {
            width: _load_only_RSS(
                width=width,
                cnf=ROOT / mappings[width]["structural_CNF"]["artifact"],
                helper=helper_artifact,
                mapping=mappings[width]["structural_CNF"],
            )
            for width in WIDTHS
        }
    memsize = subprocess.run(
        ["/usr/sbin/sysctl", "-n", "hw.memsize"],
        text=True,
        capture_output=True,
        timeout=10,
        check=False,
    )
    if memsize.returncode != 0:
        raise RuntimeError("A223 cannot read hw.memsize")
    schedule = _freeze_memory_waves(
        RSS_by_width=RSS_by_width, system_total_bytes=int(memsize.stdout.strip())
    )
    arms = []
    for arm in ARM_PLAN:
        order = _order(str(arm["order"]))
        arms.append(
            {
                **arm,
                "cell_order_sha256": _canonical_sha256(order),
                "cells": len(order),
                "solver_seconds_per_cell": SOLVER_LIMIT_SECONDS,
                "complete_order_required": True,
                "early_stop_permitted": False,
            }
        )
    manifest = {
        "schema": PREFLIGHT_SCHEMA,
        "attempt_id": ATTEMPT_ID,
        "preflight_state": "frozen_after_exact_shared_b8_CNF_mapping_reindex_helper_compile_and_load_only_RSS_before_any_cell_solver_execution",
        "config": _relative(CONFIG_PATH),
        "config_sha256": analysis["config_sha256"],
        "runner": _relative(Path(__file__)),
        "runner_sha256": _file_sha256(Path(__file__)),
        "helper_source": _relative(HELPER_SOURCE),
        "helper_source_sha256": _file_sha256(HELPER_SOURCE),
        "anchor_gates": analysis["anchor_gates"],
        "toolchain_gates": analysis["toolchain_gates"],
        "mechanism_composition": _execution_plan()["mechanism_composition"],
        "public_challenge_sha256_by_width": analysis["public_challenge_sha256_by_width"],
        "source_formulas": {
            str(width): {
                "bytes": contexts[width]["formula_bytes"],
                "sha256": contexts[width]["formula_sha256"],
                "shared_key_block_count": BLOCK_COUNT,
                "joint_equality_constraint_count": BLOCK_COUNT * 16,
                "base_CNF_export": contexts[width]["base_export"],
                "base_CNF_body_sha256": contexts[width]["base_body_sha256"],
            }
            for width in WIDTHS
        },
        "mapping_export_process_cap": MAX_EXPORT_PROCESSES,
        "mapping_export_counts_by_width": {
            str(width): mappings[width]["mapping_export_count"] for width in WIDTHS
        },
        "width_preflights": {str(width): mappings[width] for width in WIDTHS},
        "native_helper": compilation,
        "load_only_RSS_by_width": {str(width): RSS_by_width[width] for width in WIDTHS},
        "frozen_memory_schedule": schedule,
        "phase1_arms": arms,
        "phase1_arm_count": len(arms),
        "model_disclosure_barrier": _execution_plan()["model_disclosure_barrier"],
        "cell_solver_execution_started": False,
        "any_model_spool_read": False,
        "outcomes_used_to_change_order_budget_or_schedule": False,
    }
    _atomic_json(output, manifest)
    return {
        "preflight": str(output),
        "preflight_sha256": _file_sha256(output),
        "widths": list(WIDTHS),
        "mapping_export_counts_by_width": manifest["mapping_export_counts_by_width"],
        "phase1_arm_count": len(arms),
        "memory_wave_count": schedule["wave_count"],
        "cell_solver_execution_started": False,
    }


def _load_preflight(path: Path, *, expected_sha256: str) -> dict[str, Any]:
    if not re.fullmatch(r"[0-9a-f]{64}", expected_sha256):
        raise RuntimeError("A223 launch requires an explicit 64-hex preflight SHA-256")
    if _file_sha256(path) != expected_sha256:
        raise RuntimeError("A223 reviewed preflight hash differs")
    manifest = json.loads(path.read_bytes())
    if (
        manifest.get("schema") != PREFLIGHT_SCHEMA
        or manifest.get("attempt_id") != ATTEMPT_ID
        or manifest.get("config_sha256") != _file_sha256(CONFIG_PATH)
        or manifest.get("runner_sha256") != _file_sha256(Path(__file__))
        or manifest.get("helper_source_sha256") != _file_sha256(HELPER_SOURCE)
        or manifest.get("cell_solver_execution_started") is not False
        or manifest.get("any_model_spool_read") is not False
        or manifest.get("phase1_arm_count") != len(ARM_PLAN)
    ):
        raise RuntimeError("A223 preflight identity gate failed")
    helper = ROOT / manifest["native_helper"]["artifact"]
    if _file_sha256(helper) != manifest["native_helper"]["binary_sha256"]:
        raise RuntimeError("A223 preflight helper binary differs")
    for width in WIDTHS:
        row = manifest["width_preflights"][str(width)]
        structural = row["structural_CNF"]
        cnf = ROOT / structural["artifact"]
        if (
            _file_sha256(cnf) != structural["transformed_sha256"]
            or len(row["source_one_literals_bit0_upward"]) != width
            or len(structural["transformed_model_one_literals_bit0_upward"]) != width
            or len(structural["transformed_prefix_one_literals_high_to_low"]) != PREFIX_BITS
        ):
            raise RuntimeError(f"A223 W{width} preflight artifact gate failed")
    scheduled = [
        arm["arm"] for wave in manifest["frozen_memory_schedule"]["waves"] for arm in wave["arms"]
    ]
    if sorted(scheduled) != sorted(arm["arm"] for arm in ARM_PLAN):
        raise RuntimeError("A223 preflight wave cover differs")
    return manifest


def _decode_model(
    challenge: dict[str, Any], *, width: int, model_bits: Sequence[int]
) -> dict[str, Any]:
    if len(model_bits) != width or any(value not in {0, 1} for value in model_bits):
        raise RuntimeError(f"A223 W{width} helper model is not {width} Boolean bits")
    key_words = list(challenge["known_key_value_words"])
    for global_bit, value in enumerate(model_bits):
        if value:
            key_words[global_bit // 32] |= 1 << (global_bit % 32)
    masks = challenge["known_key_mask_words"]
    known_match = all(
        candidate & mask == known
        for candidate, mask, known in zip(
            key_words, masks, challenge["known_key_value_words"], strict=True
        )
    )
    return {
        "unknown_width": width,
        "model_bits_bit0_upward": list(model_bits),
        "model_bits_sha256": _sha256(bytes(model_bits)),
        "recovered_key_words": key_words,
        "known_key_constraints_match": known_match,
    }


def _confirm_model(
    challenge: dict[str, Any], *, arm: str, prefix8: str, model: dict[str, Any]
) -> dict[str, Any]:
    width = int(model["unknown_width"])
    candidate_blocks = [
        P1._chacha_block(
            key_words=model["recovered_key_words"],
            counter=(challenge["counter_start"] + block) & 0xFFFFFFFF,
            nonce_words=challenge["nonce_words"],
            rounds=ROUNDS,
        )
        for block in range(BLOCK_COUNT)
    ]
    block_matches = [
        candidate == target
        for candidate, target in zip(candidate_blocks, challenge["target_words"], strict=True)
    ]
    hashes = [_sha256(P1._word_bytes(block)) for block in candidate_blocks]
    expected_prefix = "".join(
        str(model["model_bits_bit0_upward"][bit]) for bit in range(width - 1, width - 9, -1)
    )
    control_match = hashes[0] == challenge["control_target_block_sha256"]
    return {
        **model,
        "arm": arm,
        "prefix8": prefix8,
        "prefix8_match": expected_prefix == prefix8,
        "block_count_checked": len(candidate_blocks),
        "output_bits_checked": len(candidate_blocks) * 512,
        "block_matches": block_matches,
        "all_blocks_match": all(block_matches),
        "candidate_block_sha256": hashes,
        "control_first_block_match": control_match,
        "flipped_control_rejected": not control_match,
        "independently_confirmed": (
            all(block_matches)
            and not control_match
            and expected_prefix == prefix8
            and model["known_key_constraints_match"]
        ),
        "implementation": "independent_pure_Python_standard_ChaCha20_20_rounds_with_feedforward",
    }


def _invalid_observation(*, arm: str, prefix8: str, index: int, reason: str) -> dict[str, Any]:
    return {
        "arm": arm,
        "prefix8": prefix8,
        "cell_index": index,
        "status": "invalid",
        "returncode": None,
        "elapsed_seconds": None,
        "terminator_fired": False,
        "assumptions": [],
        "failed_assumptions": [],
        "model_buffered_for_post_arm_spool": False,
        "metrics_before": {},
        "metrics_after": {},
        "metrics_delta": {},
        "active_variables": None,
        "irredundant_clauses": None,
        "redundant_clauses": None,
        "invalid_reason": reason,
    }


def _json_lines(raw: str, prefix: str) -> list[dict[str, Any]]:
    return [
        json.loads(line.removeprefix(prefix))
        for line in raw.splitlines()
        if line.startswith(prefix)
    ]


def _parse_arm_after_global_barrier(
    *,
    arm_plan: dict[str, Any],
    stdout: str,
    stderr: str,
    spool: str,
    returncode: int | None,
    externally_timed_out: bool,
    preflight: dict[str, Any],
    challenge: dict[str, Any],
) -> dict[str, Any]:
    arm = str(arm_plan["arm"])
    width = int(arm_plan["width"])
    order = _order(str(arm_plan["order"]))
    malformed = False
    try:
        rows = _json_lines(stdout, "A223_RESULT ")
        summaries = _json_lines(stdout, "A223_SUMMARY ")
        model_rows = _json_lines(spool, "A223_MODEL ") if spool else []
    except (ValueError, TypeError, json.JSONDecodeError):
        rows, summaries, model_rows = [], [], []
        malformed = True
    recognized_stdout = sum(
        line.startswith(("A223_RESULT ", "A223_SUMMARY "))
        for line in stdout.splitlines()
        if line.strip()
    )
    if recognized_stdout != sum(bool(line.strip()) for line in stdout.splitlines()):
        malformed = True
    if "model_bits_bit0_upward" in stdout:
        malformed = True
    by_prefix = {row.get("prefix8"): row for row in rows}
    models_by_prefix = {row.get("prefix8"): row for row in model_rows}
    if len(by_prefix) != len(rows) or len(models_by_prefix) != len(model_rows):
        malformed = True
    reason = None
    if externally_timed_out:
        reason = "external_arm_timeout"
    elif returncode != 0:
        reason = "invalid_helper_returncode"
    elif stderr:
        reason = "unexpected_helper_stderr"
    elif malformed or len(summaries) != 1 or set(by_prefix) != set(order):
        reason = "malformed_or_incomplete_helper_output"
    mapping = preflight["width_preflights"][str(width)]["structural_CNF"]
    assumption_one = mapping["transformed_prefix_one_literals_high_to_low"]
    observations: list[dict[str, Any]] = []
    confirmations: list[dict[str, Any]] = []
    previous_after: list[int] | None = None
    if reason is None:
        for index, prefix8 in enumerate(order):
            raw = by_prefix[prefix8]
            expected_assumptions = [
                literal if bit == "1" else -literal
                for bit, literal in zip(prefix8, assumption_one, strict=True)
            ]
            status = raw.get("status")
            valid = (
                raw.get("arm") == arm
                and raw.get("cell_index") == index
                and status in {"sat", "unsat", "unknown"}
                and raw.get("assumptions") == expected_assumptions
                and raw.get("metric_names") == list(METRIC_NAMES)
                and len(raw.get("metrics_before", [])) == len(METRIC_NAMES)
                and len(raw.get("metrics_after", [])) == len(METRIC_NAMES)
                and len(raw.get("metrics_delta", [])) == len(METRIC_NAMES)
                and all(
                    after - before == delta
                    for before, after, delta in zip(
                        raw.get("metrics_before", []),
                        raw.get("metrics_after", []),
                        raw.get("metrics_delta", []),
                        strict=True,
                    )
                )
                and (previous_after is None or raw.get("metrics_before") == previous_after)
                and raw.get("model_buffered_for_post_arm_spool") == (status == "sat")
                and ((prefix8 in models_by_prefix) == (status == "sat"))
            )
            if not valid:
                observations.append(
                    _invalid_observation(
                        arm=arm,
                        prefix8=prefix8,
                        index=index,
                        reason="cell_schema_state_or_spool_gate_failed",
                    )
                )
                previous_after = None
                continue
            previous_after = raw["metrics_after"]
            observation = {
                **raw,
                "metrics_before": dict(zip(METRIC_NAMES, raw["metrics_before"], strict=True)),
                "metrics_after": dict(zip(METRIC_NAMES, raw["metrics_after"], strict=True)),
                "metrics_delta": dict(zip(METRIC_NAMES, raw["metrics_delta"], strict=True)),
                "model_disclosed_in_observation": False,
            }
            observations.append(observation)
            if status == "sat":
                model_row = models_by_prefix[prefix8]
                if (
                    model_row.get("arm") != arm
                    or model_row.get("cell_index") != index
                    or model_row.get("model_width") != width
                ):
                    observations[-1] = _invalid_observation(
                        arm=arm,
                        prefix8=prefix8,
                        index=index,
                        reason="model_spool_identity_gate_failed",
                    )
                    previous_after = None
                    continue
                decoded = _decode_model(
                    challenge,
                    width=width,
                    model_bits=model_row.get("model_bits_bit0_upward", []),
                )
                confirmations.append(
                    _confirm_model(
                        challenge,
                        arm=arm,
                        prefix8=prefix8,
                        model=decoded,
                    )
                )
    else:
        observations = [
            _invalid_observation(arm=arm, prefix8=prefix8, index=index, reason=reason)
            for index, prefix8 in enumerate(order)
        ]
    counts = {
        status: sum(row["status"] == status for row in observations)
        for status in ("sat", "unsat", "unknown", "invalid")
    }
    summary = summaries[0] if reason is None else None
    summary_valid = (
        summary is not None
        and summary.get("arm") == arm
        and summary.get("model_width") == width
        and summary.get("cells") == CELL_COUNT
        and summary.get("sat") == counts["sat"]
        and summary.get("unsat") == counts["unsat"]
        and summary.get("unknown") == counts["unknown"]
        and summary.get("model_records_spooled_after_complete_arm") == len(model_rows)
    )
    if reason is None and not summary_valid:
        observations = [
            _invalid_observation(
                arm=arm,
                prefix8=prefix8,
                index=index,
                reason="helper_summary_gate_failed",
            )
            for index, prefix8 in enumerate(order)
        ]
        confirmations = []
        counts = {"sat": 0, "unsat": 0, "unknown": 0, "invalid": CELL_COUNT}
    return {
        "arm": arm,
        "width": width,
        "order": arm_plan["order"],
        "returncode": returncode,
        "externally_timed_out": externally_timed_out,
        "stdout_sha256": _sha256(stdout.encode()),
        "stderr_sha256": _sha256(stderr.encode()),
        "model_spool_sha256": _sha256(spool.encode()),
        "model_spool_read_after_global_barrier": True,
        "helper_stdout_contains_no_model_bits": "model_bits_bit0_upward" not in stdout,
        "status_counts": counts,
        "observations": observations,
        "confirmations": confirmations,
        "summary": summary,
        "complete_valid_arm": counts["invalid"] == 0 and sum(counts.values()) == CELL_COUNT,
    }


def _arm_command(
    *,
    arm: dict[str, Any],
    preflight: dict[str, Any],
    helper: Path,
    spool: Path,
) -> list[str]:
    width = int(arm["width"])
    structural = preflight["width_preflights"][str(width)]["structural_CNF"]
    return [
        str(helper),
        "--cnf",
        str(ROOT / structural["artifact"]),
        "--arm",
        str(arm["arm"]),
        *_helper_args(structural),
        "--cell-order",
        ",".join(_order(str(arm["order"]))),
        "--seconds",
        str(SOLVER_LIMIT_SECONDS),
        "--model-spool",
        str(spool),
    ]


def _wait_process(
    item: tuple[str, subprocess.Popen[bytes]],
) -> tuple[str, int | None, bool]:
    arm, process = item
    try:
        returncode = process.wait(timeout=ARM_EXTERNAL_TIMEOUT_SECONDS)
        externally_timed_out = False
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=10)
        returncode = process.returncode
        externally_timed_out = True
    return arm, returncode, externally_timed_out


def run(*, preflight_path: Path, expected_preflight_sha256: str, output: Path) -> dict[str, Any]:
    if output.exists():
        raise RuntimeError(f"A223 result output already exists: {output}")
    config = _load_config()
    challenges = _challenge_map(config)
    preflight = _load_preflight(preflight_path, expected_sha256=expected_preflight_sha256)
    helper = ROOT / preflight["native_helper"]["artifact"]
    launch_started = time.perf_counter()
    process_records: dict[str, dict[str, Any]] = {}
    with tempfile.TemporaryDirectory(prefix="a223-capacity-phase1-") as raw_directory:
        directory = Path(raw_directory)
        for wave in preflight["frozen_memory_schedule"]["waves"]:
            launched: list[tuple[str, subprocess.Popen[bytes]]] = []
            opened: list[Any] = []
            for arm in wave["arms"]:
                arm_name = str(arm["arm"])
                stdout_path = directory / f"{arm_name}.stdout"
                stderr_path = directory / f"{arm_name}.stderr"
                spool_path = directory / f"{arm_name}.models"
                stdout_file = stdout_path.open("wb")
                stderr_file = stderr_path.open("wb")
                opened.extend((stdout_file, stderr_file))
                command = _arm_command(
                    arm=arm, preflight=preflight, helper=helper, spool=spool_path
                )
                process = subprocess.Popen(
                    command,
                    cwd=ROOT,
                    stdout=stdout_file,
                    stderr=stderr_file,
                )
                launched.append((arm_name, process))
                process_records[arm_name] = {
                    "arm": dict(arm),
                    "command_sha256": _canonical_sha256(command),
                    "stdout_path": stdout_path,
                    "stderr_path": stderr_path,
                    "spool_path": spool_path,
                    "wave_index": wave["wave_index"],
                }
            with ThreadPoolExecutor(max_workers=len(launched)) as executor:
                waited = list(executor.map(_wait_process, launched))
            for stream in opened:
                stream.close()
            for arm_name, returncode, externally_timed_out in waited:
                process_records[arm_name]["returncode"] = returncode
                process_records[arm_name]["externally_timed_out"] = externally_timed_out

        if set(process_records) != {arm["arm"] for arm in ARM_PLAN}:
            raise RuntimeError("A223 did not launch every frozen arm exactly once")

        global_barrier = {
            "all_seven_arms_terminated": True,
            "all_frozen_waves_completed": True,
            "model_spool_reads_before_barrier": 0,
            "model_disclosure_barrier_satisfied": True,
        }
        arm_results = []
        by_name = {arm["arm"]: arm for arm in ARM_PLAN}
        for arm_name in [arm["arm"] for arm in ARM_PLAN]:
            record = process_records[arm_name]
            stdout = record["stdout_path"].read_text()
            stderr = record["stderr_path"].read_text()
            spool = record["spool_path"].read_text() if record["spool_path"].exists() else ""
            parsed = _parse_arm_after_global_barrier(
                arm_plan=by_name[arm_name],
                stdout=stdout,
                stderr=stderr,
                spool=spool,
                returncode=record["returncode"],
                externally_timed_out=record["externally_timed_out"],
                preflight=preflight,
                challenge=challenges[int(by_name[arm_name]["width"])],
            )
            parsed["wave_index"] = record["wave_index"]
            parsed["command_sha256"] = record["command_sha256"]
            arm_results.append(parsed)

    confirmations = [confirmation for arm in arm_results for confirmation in arm["confirmations"]]
    confirmed = [row for row in confirmations if row["independently_confirmed"]]
    positive_arms = sorted({row["arm"] for row in confirmed})
    positive_widths = sorted({int(row["unknown_width"]) for row in confirmed})
    all_complete = all(arm["complete_valid_arm"] for arm in arm_results)
    any_terminal = any(
        arm["status_counts"]["sat"] + arm["status_counts"]["unsat"] > 0 for arm in arm_results
    )
    if positive_widths:
        evidence_stage = "FULLROUND_R20_SHARED_B8_RETAINED_CAPACITY_RECOVERY_RETAINED"
    elif any_terminal:
        evidence_stage = "FULLROUND_R20_SHARED_B8_RETAINED_CAPACITY_TERMINAL_TRANSFER_RETAINED"
    elif all_complete:
        evidence_stage = "FULLROUND_R20_SHARED_B8_RETAINED_CAPACITY_BOUNDARY_RETAINED"
    else:
        evidence_stage = "FULLROUND_R20_SHARED_B8_RETAINED_CAPACITY_INVALID_EXECUTION_RETAINED"
    payload = {
        "schema": RESULT_SCHEMA,
        "attempt_id": ATTEMPT_ID,
        "evidence_stage": evidence_stage,
        "result": "Seven prospectively frozen retained-state portfolio arms jointly constrain eight standard full-round ChaCha20 blocks at five unknown-key capacities.",
        "scope": "A187 shared-key b8 formula composition with A211 retained global CaDiCaL state; W40 directly matches the A184 unknown-bit scope and W256 is a full-key arm.",
        "config_sha256": _file_sha256(CONFIG_PATH),
        "preflight": _relative(preflight_path),
        "preflight_sha256": expected_preflight_sha256,
        "mechanism_composition": _execution_plan()["mechanism_composition"],
        "execution_plan": _execution_plan(),
        "frozen_memory_schedule": preflight["frozen_memory_schedule"],
        "global_model_disclosure_barrier": global_barrier,
        "arm_results": arm_results,
        "phase1_arm_count": len(arm_results),
        "cell_observation_count": sum(len(arm["observations"]) for arm in arm_results),
        "all_predeclared_arms_complete_and_valid": all_complete,
        "early_stop_used": False,
        "confirmations": confirmations,
        "independently_confirmed_model_count": len(confirmed),
        "positive_arms": positive_arms,
        "positive_widths": positive_widths,
        "W40_direct_A184_scope_positive": 40 in positive_widths,
        "W256_full_key_positive": 256 in positive_widths,
        "unknown_is_not_unsat": True,
        "outcomes_used_to_change_order_budget_or_schedule": False,
        "volatile_total_seconds": time.perf_counter() - launch_started,
    }
    _atomic_json(output, payload)
    return {
        "result": str(output),
        "result_sha256": _file_sha256(output),
        "evidence_stage": evidence_stage,
        "phase1_arm_count": len(arm_results),
        "cell_observation_count": payload["cell_observation_count"],
        "positive_arms": positive_arms,
        "positive_widths": positive_widths,
        "model_disclosure_barrier_satisfied": True,
    }


def main(argv: Sequence[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--analyze-only", action="store_true")
    mode.add_argument("--preflight-only", action="store_true")
    mode.add_argument("--run", action="store_true")
    parser.add_argument("--preflight-output", type=Path, default=DEFAULT_PREFLIGHT_PATH)
    parser.add_argument("--preflight", type=Path, default=DEFAULT_PREFLIGHT_PATH)
    parser.add_argument("--expected-preflight-sha256")
    parser.add_argument("--output", type=Path, default=DEFAULT_RESULT_PATH)
    args = parser.parse_args(argv)
    if args.analyze_only:
        analysis = analyze()
        summary = {
            "attempt_id": ATTEMPT_ID,
            "config_sha256": analysis["config_sha256"],
            "widths": list(WIDTHS),
            "shared_key_block_count": analysis["shared_key_block_count"],
            "joint_equality_constraint_count_per_width": analysis[
                "joint_equality_constraint_count_per_width"
            ],
            "phase1_arm_count": len(ARM_PLAN),
            "source_formula_sha256_by_width": analysis["source_formula_sha256_by_width"],
            "cell_solver_execution_started": False,
        }
    elif args.preflight_only:
        summary = preflight(output=args.preflight_output.resolve())
    else:
        if args.expected_preflight_sha256 is None:
            parser.error("--run requires --expected-preflight-sha256")
        summary = run(
            preflight_path=args.preflight.resolve(),
            expected_preflight_sha256=args.expected_preflight_sha256,
            output=args.output.resolve(),
        )
    print(json.dumps(summary, sort_keys=True))


if __name__ == "__main__":
    main()

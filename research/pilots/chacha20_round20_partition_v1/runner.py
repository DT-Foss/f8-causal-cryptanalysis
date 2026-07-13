#!/usr/bin/env python3
"""Frozen ChaCha20 round-20 width-20 split19 prefix-partition pilot."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
import sys
import time
from collections.abc import Sequence
from pathlib import Path
from typing import Any


PILOT_DIR = Path(__file__).resolve().parent
ROOT = PILOT_DIR.parents[2]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from arx_carry_leak.crypto_causal import CryptoCausalBuilder, CryptoCausalReader


PILOT_ID = "PILOT_CHACHA20_R20_PARTITION_V1"
SCHEMA = "chacha20-round20-width20-split19-partition-pilot-v1"
CONFIG_SCHEMA = "chacha20-round20-width20-split19-partition-protocol-v1"
ROUNDS = 20
SPLIT = 19
UNKNOWN_KEY_BITS = 20
KNOWN_KEY_BITS = 236
LOW_MASK = (1 << UNKNOWN_KEY_BITS) - 1
PREFIX_BITS = 5
FREE_BITS = 15
CELL_COUNT = 1 << PREFIX_BITS
TIME_LIMIT_MS = 10_000
EXTERNAL_TIMEOUT_SECONDS = 15
VARIANTS = tuple(f"prefix_{value:05b}" for value in range(CELL_COUNT))

CONFIG_PATH = PILOT_DIR / "config.json"
FORMULA_PLAN_PATH = PILOT_DIR / "formula_plan.json"
LEDGER_PATH = PILOT_DIR / "hash_ledger.json"
RESULT_PATH = PILOT_DIR / "result.json"
CAUSAL_PATH = PILOT_DIR / "result.causal"
README_PATH = PILOT_DIR / "README.md"
TEST_PATH = PILOT_DIR / "test_pilot.py"
REPRODUCE_PATH = PILOT_DIR / "reproduce.sh"
CRYPTO_CAUSAL_PATH = SRC / "arx_carry_leak" / "crypto_causal.py"


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


def _atomic_write(path: Path, raw: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.tmp")
    temporary.write_bytes(raw)
    temporary.replace(path)


def _atomic_json(path: Path, value: Any) -> None:
    raw = json.dumps(value, indent=2, sort_keys=True, allow_nan=False).encode() + b"\n"
    _atomic_write(path, raw)


def _word_bytes(words: Sequence[int]) -> bytes:
    return b"".join(int(word & 0xFFFFFFFF).to_bytes(4, "little") for word in words)


def _rol32(value: int, distance: int) -> int:
    value &= 0xFFFFFFFF
    return ((value << distance) | (value >> (32 - distance))) & 0xFFFFFFFF


def _quarter_round(state: list[int], a: int, b: int, c: int, d: int) -> None:
    state[a] = (state[a] + state[b]) & 0xFFFFFFFF
    state[d] = _rol32(state[d] ^ state[a], 16)
    state[c] = (state[c] + state[d]) & 0xFFFFFFFF
    state[b] = _rol32(state[b] ^ state[c], 12)
    state[a] = (state[a] + state[b]) & 0xFFFFFFFF
    state[d] = _rol32(state[d] ^ state[a], 8)
    state[c] = (state[c] + state[d]) & 0xFFFFFFFF
    state[b] = _rol32(state[b] ^ state[c], 7)


def _round_qrs(round_index: int) -> tuple[tuple[int, int, int, int], ...]:
    if round_index % 2 == 0:
        return (
            (0, 4, 8, 12),
            (1, 5, 9, 13),
            (2, 6, 10, 14),
            (3, 7, 11, 15),
        )
    return (
        (0, 5, 10, 15),
        (1, 6, 11, 12),
        (2, 7, 8, 13),
        (3, 4, 9, 14),
    )


def _chacha_block(
    *,
    key_words: Sequence[int],
    counter: int,
    nonce_words: Sequence[int],
    rounds: int = ROUNDS,
) -> list[int]:
    if len(key_words) != 8 or len(nonce_words) != 3:
        raise ValueError("ChaCha20 requires eight key words and three nonce words")
    initial = [
        0x61707865,
        0x3320646E,
        0x79622D32,
        0x6B206574,
        *[int(word) & 0xFFFFFFFF for word in key_words],
        int(counter) & 0xFFFFFFFF,
        *[int(word) & 0xFFFFFFFF for word in nonce_words],
    ]
    state = initial.copy()
    for round_index in range(rounds):
        for qr in _round_qrs(round_index):
            _quarter_round(state, *qr)
    return [
        (state[index] + initial[index]) & 0xFFFFFFFF for index in range(16)
    ]


def _execution_plan() -> dict[str, Any]:
    return {
        "complete_variant_plan_required": True,
        "early_stop_permitted": False,
        "execution_mode": "sequential_external_solver_complete_numeric_prefix_partition",
        "external_timeout_seconds_per_cell": EXTERNAL_TIMEOUT_SECONDS,
        "formula_representation": "portable_SMTLIB2_round20_split19_b1_complete_5bit_prefix_partition",
        "independent_confirmation": "pure_Python_ChaCha20_all_eight_512bit_blocks_plus_bitflip_control",
        "known_key_bits": KNOWN_KEY_BITS,
        "partition_cell_count": CELL_COUNT,
        "partition_cell_free_bits": FREE_BITS,
        "partition_fixed_bits": PREFIX_BITS,
        "partition_prefix_order": [f"{value:05b}" for value in range(CELL_COUNT)],
        "primitive": "standard_ChaCha20_block_function_with_feedforward",
        "rounds": ROUNDS,
        "solver": "Bitwuzla_0.9.1_bitblast_CaDiCaL",
        "solver_time_limit_milliseconds_per_cell": TIME_LIMIT_MS,
        "split": SPLIT,
        "target_blocks_published": 8,
        "target_output_bits_constrained_per_cell": 512,
        "unknown_assignment_available_to_runner_before_execution": False,
        "unknown_key_bits": UNKNOWN_KEY_BITS,
        "variant_execution_order": list(VARIANTS),
        "variants": list(VARIANTS),
        "wallclock_excluded_from_canonical_protocol_hashes": True,
    }


def _validate_challenge(challenge: dict[str, Any]) -> None:
    targets = challenge.get("target_words", [])
    target_hashes = challenge.get("target_block_sha256", [])
    control = challenge.get("control_target_words", [])
    if (
        challenge.get("rounds") != ROUNDS
        or challenge.get("block_count") != 8
        or challenge.get("counter_schedule")
        != "base_plus_block_index_mod_2^32"
        or challenge.get("unknown_assignment_bits") != UNKNOWN_KEY_BITS
        or challenge.get("unknown_assignment_included") is not False
        or challenge.get("unknown_secret_low20_included") is not False
        or challenge.get("unknown_key_word0_low_value_included") is not False
        or challenge.get("unknown_key_word0_low_bits") != UNKNOWN_KEY_BITS
        or challenge.get("known_key_word0_upper12", 1) & LOW_MASK
        or len(challenge.get("known_key_words_1_through_7", [])) != 7
        or len(challenge.get("nonce_words", [])) != 3
        or len(targets) != 8
        or any(len(block) != 16 for block in targets)
        or len(target_hashes) != 8
        or len(control) != 16
        or control[0] != (targets[0][0] ^ 1)
        or control[1:] != targets[0][1:]
    ):
        raise RuntimeError("pilot public challenge structural gate failed")
    public_seed = bytes.fromhex(challenge["public_seed_hex"])
    label = challenge["known_material_derivation_label"]
    if not label.endswith(challenge["public_seed_hex"]):
        raise RuntimeError("pilot known-material label is not bound to public seed")
    derived = hashlib.shake_256(label.encode()).digest(48)
    words = [
        int.from_bytes(derived[offset : offset + 4], "little")
        for offset in range(0, 48, 4)
    ]
    if (
        len(public_seed) != 32
        or _sha256(derived) != challenge["known_material_derivation_sha256"]
        or words[0] & ~LOW_MASK != challenge["known_key_word0_upper12"]
        or words[1:8] != challenge["known_key_words_1_through_7"]
        or words[8] != challenge["counter_start"]
        or words[9:12] != challenge["nonce_words"]
    ):
        raise RuntimeError("pilot known-material derivation gate failed")
    for block, expected_hash in zip(targets, target_hashes, strict=True):
        if _sha256(_word_bytes(block)) != expected_hash:
            raise RuntimeError("pilot target block byte fingerprint differs")
    if _sha256(_word_bytes(control)) != challenge["control_target_block_sha256"]:
        raise RuntimeError("pilot control target byte fingerprint differs")


def _load_config() -> dict[str, Any]:
    config = json.loads(CONFIG_PATH.read_bytes())
    challenge = config.get("public_challenge", {})
    plan = _execution_plan()
    boundary = config.get("information_boundary", {})
    if (
        config.get("schema") != CONFIG_SCHEMA
        or config.get("pilot_id") != PILOT_ID
        or config.get("protocol_state")
        != "frozen_before_any_round20_partition_solver_execution"
        or config.get("public_challenge_sha256") != _canonical_sha256(challenge)
        or config.get("execution_plan") != plan
        or config.get("execution_plan_sha256") != _canonical_sha256(plan)
        or boundary.get("secret_used_only_for_target_construction") is not True
        or boundary.get("secret_stored_in_config_or_runner") is not False
        or boundary.get("secret_available_to_runner_before_execution") is not False
        or boundary.get("phase1_solver_outcomes_used_before_freeze") is not False
        or boundary.get("cell_order_cut_or_budget_changed_after_any_phase1_outcome")
        is not False
        or boundary.get("early_stop_permitted") is not False
    ):
        raise RuntimeError("pilot frozen config identity gate failed")
    _validate_challenge(challenge)
    return config


def _initial_expressions(challenge: dict[str, Any]) -> list[str]:
    word1 = challenge["known_key_words_1_through_7"][0]
    return [
        "#x61707865",
        "#x3320646e",
        "#x79622d32",
        "#x6b206574",
        "k0",
        f"(concat #x{word1 >> 8:06x} lo8)",
        *[
            f"#x{value:08x}"
            for value in challenge["known_key_words_1_through_7"][1:]
        ],
        f"#x{challenge['counter_start']:08x}",
        *[f"#x{value:08x}" for value in challenge["nonce_words"]],
    ]


def _base_formula(challenge: dict[str, Any]) -> str:
    initial = _initial_expressions(challenge)
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
        "(declare-fun lo8 () (_ BitVec 8))",
        "(declare-fun k0 () (_ BitVec 32))",
    ]
    counter = 0

    def assign(expression: str) -> str:
        nonlocal counter
        name = f"v{counter}"
        counter += 1
        lines.append(f"(define-fun {name} () (_ BitVec 32) {expression})")
        return name

    def forward_qr(state: list[str], a: int, b: int, c: int, d: int) -> None:
        state[a] = assign(f"(bvadd {state[a]} {state[b]})")
        state[d] = assign(f"(rotl16 (bvxor {state[d]} {state[a]}))")
        state[c] = assign(f"(bvadd {state[c]} {state[d]})")
        state[b] = assign(f"(rotl12 (bvxor {state[b]} {state[c]}))")
        state[a] = assign(f"(bvadd {state[a]} {state[b]})")
        state[d] = assign(f"(rotl8 (bvxor {state[d]} {state[a]}))")
        state[c] = assign(f"(bvadd {state[c]} {state[d]})")
        state[b] = assign(f"(rotl7 (bvxor {state[b]} {state[c]}))")

    def inverse_qr(state: list[str], a: int, b: int, c: int, d: int) -> None:
        state[b] = assign(f"(bvxor (rotr7 {state[b]}) {state[c]})")
        state[c] = assign(f"(bvsub {state[c]} {state[d]})")
        state[d] = assign(f"(bvxor (rotr8 {state[d]}) {state[a]})")
        state[a] = assign(f"(bvsub {state[a]} {state[b]})")
        state[b] = assign(f"(bvxor (rotr12 {state[b]}) {state[c]})")
        state[c] = assign(f"(bvsub {state[c]} {state[d]})")
        state[d] = assign(f"(bvxor (rotr16 {state[d]}) {state[a]})")
        state[a] = assign(f"(bvsub {state[a]} {state[b]})")

    forward = initial.copy()
    for round_index in range(SPLIT):
        for qr in _round_qrs(round_index):
            forward_qr(forward, *qr)
    target = challenge["target_words"][0]
    backward = [
        f"(bvsub #x{expected:08x} {initial[lane]})"
        for lane, expected in enumerate(target)
    ]
    for round_index in reversed(range(SPLIT, ROUNDS)):
        for qr in reversed(_round_qrs(round_index)):
            inverse_qr(backward, *qr)
    word1 = challenge["known_key_words_1_through_7"][0]
    lines.append(f"(assert (= lo8 #x{word1 & 0xFF:02x}))")
    lines.append(
        "(assert (= ((_ extract 31 20) k0) "
        f"#x{challenge['known_key_word0_upper12'] >> 20:03x}))"
    )
    for lane in range(16):
        lines.append(f"(assert (= {forward[lane]} {backward[lane]}))")
    lines.extend(["(check-sat)", "(get-value (k0 lo8))"])
    return "\n".join(lines) + "\n"


def _prefix_value(variant: str) -> int:
    match = re.fullmatch(r"prefix_([01]{5})", variant)
    if match is None:
        raise ValueError(f"unknown pilot variant {variant}")
    return int(match.group(1), 2)


def _formula(base: str, variant: str) -> str:
    prefix = _prefix_value(variant)
    assertion = f"(assert (= ((_ extract 19 15) k0) #b{prefix:05b}))"
    return base.replace("(check-sat)", assertion + "\n(check-sat)")


def _formula_material(config: dict[str, Any]) -> tuple[dict[str, str], dict[str, Any]]:
    base = _base_formula(config["public_challenge"])
    formulas = {variant: _formula(base, variant) for variant in VARIANTS}
    rows = [
        {
            "bytes": len(formulas[variant].encode()),
            "candidate_count": 1 << FREE_BITS,
            "fixed_key_coordinates": [19, 18, 17, 16, 15],
            "free_bits": FREE_BITS,
            "free_key_coordinates": list(reversed(range(FREE_BITS))),
            "portable_smtlib2": True,
            "prefix": f"{_prefix_value(variant):05b}",
            "sha256": _sha256(formulas[variant].encode()),
            "solver_time_limit_milliseconds": TIME_LIMIT_MS,
            "split": SPLIT,
            "variant": variant,
        }
        for variant in VARIANTS
    ]
    plan = {
        "schema": "chacha20-round20-width20-split19-formula-plan-v1",
        "pilot_id": PILOT_ID,
        "complete_domain_candidate_count": sum(row["candidate_count"] for row in rows),
        "partition_complete_and_disjoint_by_construction": True,
        "rows": rows,
    }
    if (
        plan["complete_domain_candidate_count"] != 1 << UNKNOWN_KEY_BITS
        or [row["prefix"] for row in rows]
        != [f"{value:05b}" for value in range(CELL_COUNT)]
    ):
        raise RuntimeError("pilot formula plan does not cover the complete domain")
    return formulas, plan


def _solver_identity(config: dict[str, Any]) -> dict[str, Any]:
    declared = config["solver_binary"]
    path = Path(declared["path"])
    version = subprocess.run(
        [str(path), "--version"],
        check=True,
        capture_output=True,
        text=True,
    )
    identity = {
        "path": str(path),
        "sha256": _file_sha256(path),
        "version_stdout": version.stdout.strip(),
        "version_stdout_sha256": _sha256(version.stdout.encode()),
    }
    if identity != declared:
        raise RuntimeError("pilot Bitwuzla identity differs from frozen config")
    return identity


def _anchor_gates(config: dict[str, Any]) -> dict[str, str]:
    observed: dict[str, str] = {}
    for row in config["anchors"]:
        path = ROOT / row["path"]
        digest = _file_sha256(path)
        if digest != row["sha256"]:
            raise RuntimeError(f"pilot anchor hash differs: {row['path']}")
        observed[row["label"]] = digest
    return observed


def freeze() -> dict[str, Any]:
    if LEDGER_PATH.exists() or RESULT_PATH.exists() or CAUSAL_PATH.exists():
        raise RuntimeError("pilot freeze is one-shot; frozen or result artifacts already exist")
    config = _load_config()
    anchors = _anchor_gates(config)
    solver = _solver_identity(config)
    _, formula_plan = _formula_material(config)
    _atomic_json(FORMULA_PLAN_PATH, formula_plan)
    source_paths = [
        CONFIG_PATH,
        Path(__file__).resolve(),
        FORMULA_PLAN_PATH,
        README_PATH,
        TEST_PATH,
        REPRODUCE_PATH,
        CRYPTO_CAUSAL_PATH,
    ]
    artifacts = {
        str(path.relative_to(ROOT)): _file_sha256(path) for path in source_paths
    }
    ledger = {
        "schema": "chacha20-round20-width20-split19-freeze-ledger-v1",
        "pilot_id": PILOT_ID,
        "protocol_state": "frozen_before_any_round20_partition_solver_execution",
        "phase1_solver_execution_started": False,
        "artifacts": artifacts,
        "anchors": anchors,
        "solver_identity": solver,
        "public_challenge_sha256": config["public_challenge_sha256"],
        "execution_plan_sha256": config["execution_plan_sha256"],
        "formula_plan_sha256": _canonical_sha256(formula_plan),
        "formula_plan_file_sha256": _file_sha256(FORMULA_PLAN_PATH),
    }
    _atomic_json(LEDGER_PATH, ledger)
    return {
        "config_sha256": _file_sha256(CONFIG_PATH),
        "runner_sha256": _file_sha256(Path(__file__).resolve()),
        "public_challenge_sha256": config["public_challenge_sha256"],
        "execution_plan_sha256": config["execution_plan_sha256"],
        "formula_plan_sha256": ledger["formula_plan_sha256"],
        "formula_plan_file_sha256": ledger["formula_plan_file_sha256"],
        "hash_ledger_sha256": _file_sha256(LEDGER_PATH),
        "phase1_solver_execution_started": False,
    }


def analyze() -> dict[str, Any]:
    config = _load_config()
    ledger = json.loads(LEDGER_PATH.read_bytes())
    if (
        ledger.get("schema")
        != "chacha20-round20-width20-split19-freeze-ledger-v1"
        or ledger.get("pilot_id") != PILOT_ID
        or ledger.get("protocol_state")
        != "frozen_before_any_round20_partition_solver_execution"
        or ledger.get("phase1_solver_execution_started") is not False
        or ledger.get("public_challenge_sha256")
        != config["public_challenge_sha256"]
        or ledger.get("execution_plan_sha256") != config["execution_plan_sha256"]
    ):
        raise RuntimeError("pilot hash-ledger identity gate failed")
    for relative, expected in ledger["artifacts"].items():
        if _file_sha256(ROOT / relative) != expected:
            raise RuntimeError(f"pilot frozen artifact differs: {relative}")
    anchors = _anchor_gates(config)
    if anchors != ledger["anchors"]:
        raise RuntimeError("pilot anchor ledger differs")
    solver = _solver_identity(config)
    if solver != ledger["solver_identity"]:
        raise RuntimeError("pilot solver ledger differs")
    formulas, expected_plan = _formula_material(config)
    observed_plan = json.loads(FORMULA_PLAN_PATH.read_bytes())
    if (
        observed_plan != expected_plan
        or _canonical_sha256(observed_plan) != ledger["formula_plan_sha256"]
        or _file_sha256(FORMULA_PLAN_PATH) != ledger["formula_plan_file_sha256"]
    ):
        raise RuntimeError("pilot formula plan differs from pre-solver freeze")
    return {
        "config": config,
        "ledger": ledger,
        "anchors": anchors,
        "solver": solver,
        "formulas": formulas,
        "formula_plan": observed_plan,
        "solver_execution_started": False,
    }


def _run_cell(
    *,
    variant: str,
    formula: str,
    solver: dict[str, Any],
) -> dict[str, Any]:
    command = [
        solver["path"],
        "--lang",
        "smt2",
        "--time-limit",
        str(TIME_LIMIT_MS),
        "--produce-models",
        "--bv-output-format",
        "16",
        "--bv-solver",
        "bitblast",
        "--sat-solver",
        "cadical",
    ]
    started = time.perf_counter()
    try:
        completed = subprocess.run(
            command,
            input=formula,
            text=True,
            capture_output=True,
            timeout=EXTERNAL_TIMEOUT_SECONDS,
            check=False,
        )
        stdout = completed.stdout
        stderr = completed.stderr
        returncode: int | None = completed.returncode
        externally_timed_out = False
    except subprocess.TimeoutExpired as error:
        stdout = error.stdout or ""
        stderr = error.stderr or ""
        if isinstance(stdout, bytes):
            stdout = stdout.decode(errors="replace")
        if isinstance(stderr, bytes):
            stderr = stderr.decode(errors="replace")
        returncode = None
        externally_timed_out = True
    elapsed = time.perf_counter() - started
    status = next(
        (
            line.strip()
            for line in stdout.splitlines()
            if line.strip() in {"sat", "unsat", "unknown"}
        ),
        "external_timeout" if externally_timed_out else "invalid",
    )
    values = {
        name: int(raw, 16)
        for name, raw in re.findall(
            r"\((k0|lo8)\s+#x([0-9a-fA-F]+)\)", stdout
        )
    }
    model = None
    if status == "sat":
        if set(values) != {"k0", "lo8"}:
            raise RuntimeError(f"pilot {variant} SAT model parse failed")
        if (values["k0"] >> FREE_BITS) & 0b11111 != _prefix_value(variant):
            raise RuntimeError(f"pilot {variant} model violates prefix cell")
        model = {
            "combined_assignment": values["k0"],
            "key_word0": values["k0"],
            "key_word1_low_value": values["lo8"],
            "recovered_unknown_low20": values["k0"] & LOW_MASK,
        }
    row = {
        "candidate_count": 1 << FREE_BITS,
        "command": command,
        "externally_timed_out": externally_timed_out,
        "formula_bytes": len(formula.encode()),
        "formula_sha256": _sha256(formula.encode()),
        "free_bits": FREE_BITS,
        "model": model,
        "prefix": f"{_prefix_value(variant):05b}",
        "returncode": returncode,
        "solver_time_limit_milliseconds": TIME_LIMIT_MS,
        "status": status,
        "stderr_sha256": _sha256(stderr.encode()),
        "stdout_sha256": _sha256(stdout.encode()),
        "variant": variant,
        "volatile_seconds": elapsed,
    }
    print(
        f"{variant} status={status} seconds={elapsed:.6f}",
        file=sys.stderr,
        flush=True,
    )
    return row


def _confirm_model(
    challenge: dict[str, Any],
    variant: str,
    model: dict[str, int],
) -> dict[str, Any]:
    key_words = [model["key_word0"], *challenge["known_key_words_1_through_7"]]
    candidate_blocks = [
        _chacha_block(
            key_words=key_words,
            counter=(challenge["counter_start"] + index) & 0xFFFFFFFF,
            nonce_words=challenge["nonce_words"],
        )
        for index in range(challenge["block_count"])
    ]
    block_matches = [
        candidate == target
        for candidate, target in zip(
            candidate_blocks, challenge["target_words"], strict=True
        )
    ]
    candidate_hashes = [_sha256(_word_bytes(block)) for block in candidate_blocks]
    return {
        **model,
        "variant": variant,
        "prefix": f"{_prefix_value(variant):05b}",
        "known_key_constraints_match": (
            model["key_word0"] & ~LOW_MASK
            == challenge["known_key_word0_upper12"]
            and model["key_word1_low_value"]
            == challenge["known_key_words_1_through_7"][0] & 0xFF
        ),
        "block_count_checked": len(candidate_blocks),
        "block_matches": block_matches,
        "all_blocks_match": all(block_matches),
        "candidate_block_sha256": candidate_hashes,
        "control_first_block_match": candidate_hashes[0]
        == challenge["control_target_block_sha256"],
        "output_bits_checked": len(candidate_blocks) * 512,
        "minimum_required_confirmation_bits": 512,
        "implementation": "independent_pure_Python_standard_ChaCha20_block",
    }


def _build_causal(path: Path, payload: dict[str, Any]) -> dict[str, Any]:
    builder = CryptoCausalBuilder(
        experiment="chacha20_round20_width20_split19_partition_pilot",
        parameters={
            "pilot_id": PILOT_ID,
            "rounds": ROUNDS,
            "split": SPLIT,
            "unknown_key_bits": UNKNOWN_KEY_BITS,
            "partition_cells": CELL_COUNT,
        },
    )
    ids = [
        "pilot-r20-existing-fullround-and-prefix-partition-anchors",
        "pilot-r20-fresh-width20-public-challenge",
        "pilot-r20-complete-split19-prefix-cover",
        "pilot-r20-complete-numeric-cell-execution",
        "pilot-r20-independent-model-confirmation",
        "pilot-r20-novelty-and-uniqueness-boundary",
    ]
    triplets = [
        (
            "retained:ChaCha20_fullround_width40_recovery_and_A191_A194_partition_path",
            "hash_gate_prior_stronger_fullround_and_assignment_free_partition_artifacts",
            "pilot:direct_round20_partition_transfer_question",
            "retained_prior_artifact_scope",
            payload["freeze"]["hash_ledger_sha256"],
            {"anchors": payload["anchors"]},
        ),
        (
            "pilot:direct_round20_partition_transfer_question",
            "construct_fresh_OS_random_low20_target_then_discard_the_assignment",
            "pilot:frozen_public_round20_width20_challenge",
            "pre_solver_public_challenge_freeze",
            payload["public_challenge_sha256"],
            {"public_challenge": payload["public_challenge"]},
        ),
        (
            "pilot:frozen_public_round20_width20_challenge",
            "compile_split19_into_thirty_two_disjoint_numeric_prefix_cells",
            "pilot:complete_structural_2pow20_formula_cover",
            "assignment_free_complete_partition",
            payload["formula_plan_sha256"],
            {"formula_plan": payload["formula_plan"]},
        ),
        (
            "pilot:complete_structural_2pow20_formula_cover",
            "execute_all_cells_in_frozen_numeric_order_without_early_stop",
            "pilot:complete_round20_cell_execution",
            "complete_predeclared_cell_execution",
            payload["execution_sha256"],
            {"execution": payload["execution"]},
        ),
        (
            "pilot:complete_round20_cell_execution",
            "recompute_every_SAT_model_over_eight_full_ChaCha20_blocks_and_control",
            "pilot:independently_confirmed_round20_models",
            "independent_full_block_confirmation",
            payload["confirmation_sha256"],
            {"confirmations": payload["confirmations"]},
        ),
        (
            "pilot:independently_confirmed_round20_models",
            "separate_partition_mechanism_transfer_from_prior_stronger_width40_recovery_and_state_exact_uniqueness_limit",
            "pilot:round20_transfer_and_uniqueness_boundary",
            "scope_and_novelty_boundary",
            payload["comparison_sha256"],
            {"comparisons": payload["comparisons"]},
        ),
    ]
    for index, row in enumerate(triplets):
        trigger, mechanism, outcome, kind, source, attrs = row
        builder.add_triplet(
            edge_id=ids[index],
            trigger=trigger,
            mechanism=mechanism,
            outcome=outcome,
            confidence=1.0,
            evidence_kind=kind,
            source=source,
            provenance=[] if index == 0 else [ids[index - 1]],
            attrs=attrs,
        )
    stats = dict(builder.save(path))
    stats.pop("path", None)
    reader = CryptoCausalReader(path)
    rows = reader.triplets(include_inferred=False)
    by_id = {row["edge_id"]: row for row in rows}
    expected_provenance = [
        [],
        [ids[0]],
        [ids[1]],
        [ids[2]],
        [ids[3]],
        [ids[4]],
    ]
    if (
        len(rows) != len(ids)
        or set(by_id) != set(ids)
        or [by_id[edge_id]["provenance"] for edge_id in ids]
        != expected_provenance
        or not reader.verify_provenance()
    ):
        raise RuntimeError("pilot Causal provenance chain failed")
    return {
        "stats": stats,
        "explicit_triplets": len(rows),
        "provenance_verified": True,
        "file_sha256": reader.file_sha256,
        "graph_sha256": reader.graph_sha256,
    }


def run(*, output: Path, causal_output: Path) -> dict[str, Any]:
    analysis = analyze()
    observations = [
        _run_cell(
            variant=variant,
            formula=analysis["formulas"][variant],
            solver=analysis["solver"],
        )
        for variant in VARIANTS
    ]
    if [row["variant"] for row in observations] != list(VARIANTS):
        raise RuntimeError("pilot did not execute every cell in frozen numeric order")
    confirmations = [
        _confirm_model(
            analysis["config"]["public_challenge"],
            row["variant"],
            row["model"],
        )
        for row in observations
        if row["model"] is not None
    ]
    invalid_confirmations = [
        row
        for row in confirmations
        if (
            not row["known_key_constraints_match"]
            or not row["all_blocks_match"]
            or row["control_first_block_match"]
            or row["output_bits_checked"] < 512
        )
    ]
    confirmed = [row for row in confirmations if row not in invalid_confirmations]
    recovered = sorted({row["recovered_unknown_low20"] for row in confirmed})
    statuses = {row["variant"]: row["status"] for row in observations}
    status_counts = {
        status: sum(value == status for value in statuses.values())
        for status in ("sat", "unsat", "unknown", "invalid", "external_timeout")
    }
    complete_execution = len(observations) == CELL_COUNT
    structural_coverage = sum(row["candidate_count"] for row in observations)
    prediction_retained = bool(recovered)
    comparisons = {
        "complete_domain_candidate_count": structural_coverage,
        "original_domain_candidate_count": 1 << UNKNOWN_KEY_BITS,
        "partition_complete_and_disjoint_by_construction": True,
        "all_cells_executed_in_frozen_numeric_order": complete_execution,
        "confirmed_variants": [row["variant"] for row in confirmed],
        "fully_confirmed_unknown_low20_assignments": recovered,
        "phase1_prediction_retained": prediction_retained,
        "status_counts": status_counts,
        "statuses": statuses,
        "prior_stronger_fullround_width_bits": 40,
        "pilot_unknown_width_bits": UNKNOWN_KEY_BITS,
        "novelty": (
            "direct assignment-free complete split19 prefix-partition mechanism "
            "test at standard ChaCha20 round 20; not a wider recovery than the "
            "retained exhaustive 40-bit fullround result"
        ),
        "uniqueness_established": False,
        "uniqueness_boundary": (
            "Cell execution covers the full 2^20 domain structurally, but unknown "
            "cells are not UNSAT proofs and a SAT query returns only one model from "
            "its cell; exact uniqueness therefore requires complete UNSAT "
            "classification after blocking every confirmed model."
        ),
    }
    evidence_stage = (
        "PILOT_ROUND20_WIDTH20_COMPLETE_PARTITION_MODEL_RECOVERY"
        if prediction_retained
        else "PILOT_ROUND20_WIDTH20_COMPLETE_PARTITION_SOLVER_BOUNDARY"
    )
    execution = {
        "variant_order": list(VARIANTS),
        "complete_variant_plan_executed": complete_execution,
        "early_stop_used": False,
        "observations": observations,
        "returned_model_count": len(confirmations),
        "independently_confirmed_model_count": len(confirmed),
        "fully_confirmed_unknown_low20_assignments": recovered,
        "unknown_assignment_available_to_runner_before_execution": False,
        "total_volatile_seconds": sum(row["volatile_seconds"] for row in observations),
    }
    freeze_info = {
        "config_sha256": _file_sha256(CONFIG_PATH),
        "runner_sha256": _file_sha256(Path(__file__).resolve()),
        "formula_plan_file_sha256": _file_sha256(FORMULA_PLAN_PATH),
        "hash_ledger_sha256": _file_sha256(LEDGER_PATH),
    }
    payload: dict[str, Any] = {
        "schema": SCHEMA,
        "pilot_id": PILOT_ID,
        "evidence_stage": evidence_stage,
        "result": (
            "The frozen complete 32-cell split19 portfolio returned at least one "
            "independently confirmed model on a fresh standard ChaCha20 width-20 challenge."
            if prediction_retained
            else "The frozen complete 32-cell split19 portfolio executed the entire "
            "structural 2^20 cover without a confirmed model at 10 seconds per cell."
        ),
        "scope": (
            "Direct round-20 transfer test of the A191-A194 assignment-free prefix "
            "partition mechanism with 20 unknown and 236 known key bits. Existing "
            "fullround exhaustive 40-bit partial-key recovery remains the wider result."
        ),
        "parameters": {
            "rounds": ROUNDS,
            "split": SPLIT,
            "unknown_key_bits": UNKNOWN_KEY_BITS,
            "known_key_bits": KNOWN_KEY_BITS,
            "partition_cells": CELL_COUNT,
            "free_bits_per_cell": FREE_BITS,
            "variants": list(VARIANTS),
        },
        "freeze": freeze_info,
        "anchors": analysis["anchors"],
        "public_challenge": analysis["config"]["public_challenge"],
        "public_challenge_sha256": analysis["config"]["public_challenge_sha256"],
        "execution_plan": analysis["config"]["execution_plan"],
        "execution_plan_sha256": analysis["config"]["execution_plan_sha256"],
        "solver_identity": analysis["solver"],
        "formula_plan": analysis["formula_plan"],
        "formula_plan_sha256": _canonical_sha256(analysis["formula_plan"]),
        "execution": execution,
        "execution_sha256": _canonical_sha256(execution),
        "confirmations": confirmations,
        "confirmation_sha256": _canonical_sha256(confirmations),
        "comparisons": comparisons,
        "comparison_sha256": _canonical_sha256(comparisons),
    }
    causal = _build_causal(causal_output, payload)
    payload["causal"] = causal
    _atomic_json(output, payload)
    reader = CryptoCausalReader(causal_output)
    if (
        reader.file_sha256 != causal["file_sha256"]
        or reader.graph_sha256 != causal["graph_sha256"]
        or not reader.verify_provenance()
    ):
        raise RuntimeError("pilot final Causal reopen gate failed")
    return {
        "json_sha256": _file_sha256(output),
        "causal_sha256": reader.file_sha256,
        "causal_graph_sha256": reader.graph_sha256,
        "evidence_stage": evidence_stage,
        "status_counts": status_counts,
        "fully_confirmed_unknown_low20_assignments": recovered,
        "total_volatile_seconds": execution["total_volatile_seconds"],
        "output": str(output),
        "causal_output": str(causal_output),
    }


def main(argv: Sequence[str] | None = None) -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--freeze", action="store_true")
    parser.add_argument("--analyze-only", action="store_true")
    parser.add_argument("--output", type=Path, default=RESULT_PATH)
    parser.add_argument("--causal-output", type=Path, default=CAUSAL_PATH)
    args = parser.parse_args(argv)
    if args.freeze and args.analyze_only:
        raise ValueError("--freeze and --analyze-only are mutually exclusive")
    if args.freeze:
        print(json.dumps(freeze(), sort_keys=True))
        return
    if args.analyze_only:
        analysis = analyze()
        print(
            json.dumps(
                {
                    "config_sha256": _file_sha256(CONFIG_PATH),
                    "runner_sha256": _file_sha256(Path(__file__).resolve()),
                    "public_challenge_sha256": analysis["config"]["public_challenge_sha256"],
                    "execution_plan_sha256": analysis["config"]["execution_plan_sha256"],
                    "formula_plan_sha256": _canonical_sha256(analysis["formula_plan"]),
                    "formula_plan_file_sha256": _file_sha256(FORMULA_PLAN_PATH),
                    "hash_ledger_sha256": _file_sha256(LEDGER_PATH),
                    "formula_count": len(analysis["formulas"]),
                    "complete_domain_candidate_count": analysis["formula_plan"]["complete_domain_candidate_count"],
                    "solver_execution_started": False,
                },
                sort_keys=True,
            )
        )
        return
    if args.output.resolve() == args.causal_output.resolve():
        raise ValueError("JSON and Causal output paths must differ")
    print(
        json.dumps(
            run(
                output=args.output.resolve(),
                causal_output=args.causal_output.resolve(),
            ),
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    main()

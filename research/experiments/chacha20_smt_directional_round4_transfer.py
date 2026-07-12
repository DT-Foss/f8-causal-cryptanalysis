#!/usr/bin/env python3
"""Prospective ChaCha4 causal-direction transfer over 40 unknown key bits."""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import re
import shutil
import subprocess
import sys
from collections.abc import Sequence
from pathlib import Path
from typing import Any

import numpy as np

from arx_carry_leak.crypto_causal import CryptoCausalBuilder, CryptoCausalReader


def _import_sibling(filename: str, module_name: str) -> Any:
    path = Path(__file__).with_name(filename)
    spec = importlib.util.spec_from_file_location(module_name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


_A184 = _import_sibling(
    "chacha20_metal_width40_partial_key_recovery.py",
    "chacha20_direction_a184_anchor",
)
_A181 = _A184._A181
_A119 = _A184._A119

ATTEMPT_ID = "A185"
SCHEMA = "chacha20-smt-directional-round4-transfer-v1"
PROTOCOL_SCHEMA = "chacha20-smt-directional-round4-transfer-protocol-v1"
PROTOCOL_FILENAME = "chacha20_smt_directional_round4_transfer_v1.json"
PROTOCOL_SHA256 = "4132728bfd1a5ed6865d38e6adfa6ed2cc9e1e75073ec0960201d4076d323fa1"
A184_FILENAME = _A184.RESULT_FILENAME
A184_SHA256 = "d467c06105d4a4afba9efaa7bdf6c4e58754b034d4640907486c778ad17e12a9"
A184_CAUSAL_FILENAME = _A184.CAUSAL_FILENAME
A184_CAUSAL_SHA256 = "b37bc0234966185e06eb15ae6926502535b0c50271b01f0b6bd8fe5394dabd0f"
PUBLIC_RELATION_SHA256 = "d477f28da2dc9fb87e124127ba7518ef90083a0ac6bf10c61fd3ef91e50ff9f7"
ROUNDS = 4
UNKNOWN_KEY_BITS = 40
KNOWN_KEY_BITS = 216
VARIANTS = ("forward", "inverse", "split1", "split2", "split3")
RESULT_FILENAME = "chacha20_smt_directional_round4_transfer_v1.json"
CAUSAL_FILENAME = "chacha20_smt_directional_round4_transfer_v1.causal"


def _sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _canonical_sha256(value: Any) -> str:
    return _A184._canonical_sha256(value)


def _file_sha256(path: Path) -> str:
    return _A184._file_sha256(path)


def _load_protocol_gate() -> dict[str, Any]:
    path = Path(__file__).parents[1] / "configs" / PROTOCOL_FILENAME
    raw = path.read_bytes()
    if _sha256(raw) != PROTOCOL_SHA256:
        raise RuntimeError("A185 frozen protocol hash differs")
    protocol = json.loads(raw)
    boundary = protocol.get("information_boundary", {})
    if (
        protocol.get("schema") != PROTOCOL_SCHEMA
        or protocol.get("attempt_id") != ATTEMPT_ID
        or protocol.get("protocol_state") != "frozen_before_any_A185_solver_execution"
        or protocol.get("anchors", {}).get("A184", {}).get("sha256") != A184_SHA256
        or protocol.get("anchors", {}).get("A184", {}).get("causal_sha256")
        != A184_CAUSAL_SHA256
        or protocol.get("public_challenge_sha256") != PUBLIC_RELATION_SHA256
        or protocol.get("execution_plan", {}).get("variants") != list(VARIANTS)
        or boundary.get("unknown_assignment_in_protocol_or_source") is not False
        or boundary.get("unknown_assignment_available_to_runner_before_execution") is not False
        or boundary.get("A185_solver_outcomes_used_before_protocol_freeze") is not False
    ):
        raise RuntimeError("A185 frozen protocol identity gate failed")
    return protocol


def _load_anchor_gates(results_dir: Path) -> dict[str, Any]:
    result_path = results_dir / A184_FILENAME
    causal_path = results_dir / A184_CAUSAL_FILENAME
    observed = {
        "A184_result_sha256": _file_sha256(result_path),
        "A184_causal_sha256": _file_sha256(causal_path),
    }
    if observed != {
        "A184_result_sha256": A184_SHA256,
        "A184_causal_sha256": A184_CAUSAL_SHA256,
    }:
        raise RuntimeError("A185 A184 anchor hash gate failed")
    result = json.loads(result_path.read_bytes())
    if (
        result.get("schema") != _A184.SCHEMA
        or result.get("evidence_stage")
        != "CHACHA20_FULLROUND_40BIT_PARTIAL_KEY_RECOVERY_RETAINED"
        or result.get("execution", {}).get("complete_domain_executed") is not True
        or result.get("execution", {}).get("logical_candidate_count") != 1 << 40
    ):
        raise RuntimeError("A185 retained A184 result gate failed")
    reader = CryptoCausalReader(causal_path)
    if (
        reader.file_sha256 != A184_CAUSAL_SHA256
        or reader.graph_sha256 != result.get("causal", {}).get("graph_sha256")
        or not reader.verify_provenance()
    ):
        raise RuntimeError("A185 retained A184 Causal gate failed")
    return {
        **observed,
        "A184_causal_graph_sha256": reader.graph_sha256,
        "A184_causal_provenance_verified": True,
        "A184_complete_domain_executed": True,
    }


def _validate_public_challenge(challenge: dict[str, Any]) -> None:
    if (
        _canonical_sha256(challenge) != PUBLIC_RELATION_SHA256
        or challenge.get("rounds") != ROUNDS
        or challenge.get("unknown_assignment_bits") != UNKNOWN_KEY_BITS
        or challenge.get("unknown_assignment_included") is not False
        or challenge.get("unknown_key_word0_included") is not False
        or challenge.get("unknown_key_word1_low_value_included") is not False
        or challenge.get("known_key_word1_upper24", 1) & 0xFF
        or len(challenge.get("known_key_words_2_through_7", [])) != 6
        or len(challenge.get("nonce_words", [])) != 3
        or len(challenge.get("target_words", [])) != 16
        or len(challenge.get("control_target_words", [])) != 16
        or challenge["control_target_words"][0] != (challenge["target_words"][0] ^ 1)
        or challenge["control_target_words"][1:] != challenge["target_words"][1:]
    ):
        raise RuntimeError("A185 public challenge identity gate failed")
    derived = hashlib.shake_256(challenge["known_material_derivation_label"].encode()).digest(
        44
    )
    words = np.frombuffer(derived, dtype="<u4")
    if (
        _sha256(derived) != challenge["known_material_derivation_sha256"]
        or int(words[0]) & 0xFFFFFF00 != challenge["known_key_word1_upper24"]
        or [int(value) for value in words[1:7]]
        != challenge["known_key_words_2_through_7"]
        or int(words[7]) != challenge["counter"]
        or [int(value) for value in words[8:11]] != challenge["nonce_words"]
    ):
        raise RuntimeError("A185 known-material derivation gate failed")
    target = np.array(challenge["target_words"], dtype=np.uint32)
    control = np.array(challenge["control_target_words"], dtype=np.uint32)
    if (
        _sha256(target.astype("<u4").tobytes()) != challenge["target_block_sha256"]
        or _sha256(control.astype("<u4").tobytes())
        != challenge["control_target_block_sha256"]
    ):
        raise RuntimeError("A185 target byte fingerprint differs")


def _execution_plan() -> dict[str, Any]:
    return {
        "primitive": "ChaCha20_block_function",
        "rounds": ROUNDS,
        "unknown_key_bits": UNKNOWN_KEY_BITS,
        "known_key_bits": KNOWN_KEY_BITS,
        "target_output_bits": 512,
        "variants": list(VARIANTS),
        "variant_execution_order": list(VARIANTS),
        "execution_mode": "sequential_one_thread_external_Z3",
        "z3_version": "4.15.4",
        "timeout_milliseconds_per_variant": 30_000,
        "external_timeout_seconds_per_variant": 40,
        "formula_representation": "shared_define_fun_DAG",
        "complete_variant_plan_required": True,
        "early_stop_used": False,
        "independent_confirmation": "NumPy_ChaCha4_all_512_output_bits",
        "unknown_assignment_available_to_runner_before_execution": False,
        "wallclock_excluded_from_canonical_result": True,
    }


def analyze(results_dir: Path) -> dict[str, Any]:
    protocol = _load_protocol_gate()
    anchors = _load_anchor_gates(results_dir)
    challenge = protocol["public_challenge"]
    _validate_public_challenge(challenge)
    plan = _execution_plan()
    if (
        protocol["execution_plan"] != plan
        or protocol["execution_plan_sha256"] != _canonical_sha256(plan)
    ):
        raise RuntimeError("A185 execution plan differs from freeze")
    return {
        "protocol": protocol,
        "anchor_gates": anchors,
        "public_challenge": challenge,
        "execution_plan": plan,
        "solver_execution_started": False,
    }


def _initial_expressions(challenge: dict[str, Any]) -> list[str]:
    upper = challenge["known_key_word1_upper24"]
    return [
        "#x61707865",
        "#x3320646e",
        "#x79622d32",
        "#x6b206574",
        "k0",
        f"(concat #x{upper >> 8:06x} lo8)",
        *[f"#x{value:08x}" for value in challenge["known_key_words_2_through_7"]],
        f"#x{challenge['counter']:08x}",
        *[f"#x{value:08x}" for value in challenge["nonce_words"]],
    ]


def _formula(variant: str, challenge: dict[str, Any], timeout_ms: int) -> str:
    if variant not in VARIANTS:
        raise ValueError(f"unknown A185 variant {variant}")
    initial = _initial_expressions(challenge)
    lines = [
        "(set-logic QF_BV)",
        "(set-option :produce-models true)",
        f"(set-option :timeout {timeout_ms})",
        "(define-fun rotl16 ((x (_ BitVec 32))) (_ BitVec 32) (bvor (bvshl x #x00000010) (bvlshr x #x00000010)))",
        "(define-fun rotl12 ((x (_ BitVec 32))) (_ BitVec 32) (bvor (bvshl x #x0000000c) (bvlshr x #x00000014)))",
        "(define-fun rotl8 ((x (_ BitVec 32))) (_ BitVec 32) (bvor (bvshl x #x00000008) (bvlshr x #x00000018)))",
        "(define-fun rotl7 ((x (_ BitVec 32))) (_ BitVec 32) (bvor (bvshl x #x00000007) (bvlshr x #x00000019)))",
        "(define-fun rotr16 ((x (_ BitVec 32))) (_ BitVec 32) (rotl16 x))",
        "(define-fun rotr12 ((x (_ BitVec 32))) (_ BitVec 32) (bvor (bvlshr x #x0000000c) (bvshl x #x00000014)))",
        "(define-fun rotr8 ((x (_ BitVec 32))) (_ BitVec 32) (bvor (bvlshr x #x00000008) (bvshl x #x00000018)))",
        "(define-fun rotr7 ((x (_ BitVec 32))) (_ BitVec 32) (bvor (bvlshr x #x00000007) (bvshl x #x00000019)))",
        "(declare-fun k0 () (_ BitVec 32))",
        "(declare-fun lo8 () (_ BitVec 8))",
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

    def quarter_rounds(round_index: int) -> tuple[tuple[int, int, int, int], ...]:
        if round_index % 2 == 0:
            return ((0, 4, 8, 12), (1, 5, 9, 13), (2, 6, 10, 14), (3, 7, 11, 15))
        return ((0, 5, 10, 15), (1, 6, 11, 12), (2, 7, 8, 13), (3, 4, 9, 14))

    target = challenge["target_words"]
    if variant == "forward":
        state = initial.copy()
        for round_index in range(ROUNDS):
            for qr in quarter_rounds(round_index):
                forward_qr(state, *qr)
        for lane, expected in enumerate(target):
            lines.append(
                f"(assert (= (bvadd {state[lane]} {initial[lane]}) #x{expected:08x}))"
            )
    elif variant == "inverse":
        state = [
            f"(bvsub #x{expected:08x} {initial[lane]})"
            for lane, expected in enumerate(target)
        ]
        for round_index in reversed(range(ROUNDS)):
            for qr in reversed(quarter_rounds(round_index)):
                inverse_qr(state, *qr)
        for lane in range(16):
            lines.append(f"(assert (= {state[lane]} {initial[lane]}))")
    else:
        split = int(variant.removeprefix("split"))
        forward = initial.copy()
        for round_index in range(split):
            for qr in quarter_rounds(round_index):
                forward_qr(forward, *qr)
        backward = [
            f"(bvsub #x{expected:08x} {initial[lane]})"
            for lane, expected in enumerate(target)
        ]
        for round_index in reversed(range(split, ROUNDS)):
            for qr in reversed(quarter_rounds(round_index)):
                inverse_qr(backward, *qr)
        for lane in range(16):
            lines.append(f"(assert (= {forward[lane]} {backward[lane]}))")
    lines.extend(["(check-sat)", "(get-value (k0 lo8))"])
    return "\n".join(lines) + "\n"


def _solver_version(z3: Path) -> str:
    result = subprocess.run(
        [str(z3), "-version"],
        check=True,
        capture_output=True,
        text=True,
    )
    match = re.search(r"Z3 version ([0-9.]+)", result.stdout)
    if match is None:
        raise RuntimeError("A185 could not parse Z3 version")
    return match.group(1)


def _run_formula(
    z3: Path,
    variant: str,
    formula: str,
    external_timeout: int,
) -> dict[str, Any]:
    try:
        result = subprocess.run(
            [str(z3), "-in", "-st"],
            input=formula,
            text=True,
            capture_output=True,
            timeout=external_timeout,
            check=False,
        )
        externally_timed_out = False
    except subprocess.TimeoutExpired as error:
        return {
            "variant": variant,
            "formula_sha256": _sha256(formula.encode()),
            "formula_bytes": len(formula.encode()),
            "status": "external_timeout",
            "returncode": None,
            "externally_timed_out": True,
            "model": None,
            "statistics": {},
            "stderr_sha256": _sha256((error.stderr or "").encode()),
        }
    stdout = result.stdout
    first = stdout.splitlines()[0] if stdout.splitlines() else "missing"
    status = first if first in {"sat", "unsat", "unknown"} else "invalid"
    model_values = {
        name: int(raw, 16)
        for name, raw in re.findall(r"\((k0|lo8) #x([0-9a-fA-F]+)\)", stdout)
    }
    model = None
    if status == "sat":
        if set(model_values) != {"k0", "lo8"}:
            raise RuntimeError(f"A185 {variant} SAT model parse failed")
        model = {
            "key_word0": model_values["k0"],
            "key_word1_low_value": model_values["lo8"],
            "combined_assignment": (model_values["lo8"] << 32) | model_values["k0"],
        }
    statistics = {
        key: int(float(value))
        for key, value in re.findall(r":([\w-]+)\s+([0-9.]+)", stdout)
        if key
        in {
            "rlimit-count",
            "sat-conflicts",
            "sat-decisions",
            "sat-propagations-2ary",
            "sat-propagations-nary",
            "sat-restarts",
        }
    }
    return {
        "variant": variant,
        "formula_sha256": _sha256(formula.encode()),
        "formula_bytes": len(formula.encode()),
        "status": status,
        "returncode": result.returncode,
        "externally_timed_out": externally_timed_out,
        "model": model,
        "statistics": statistics,
        "stdout_sha256": _sha256(stdout.encode()),
        "stderr_sha256": _sha256(result.stderr.encode()),
    }


def _confirm(challenge: dict[str, Any], model: dict[str, int]) -> dict[str, Any]:
    initial = np.zeros((1, 16), dtype=np.uint32)
    initial[0, :4] = _A119.CONSTANTS
    initial[0, 4] = np.uint32(model["key_word0"])
    initial[0, 5] = np.uint32(
        challenge["known_key_word1_upper24"] | model["key_word1_low_value"]
    )
    initial[0, 6:12] = np.array(challenge["known_key_words_2_through_7"], dtype=np.uint32)
    initial[0, 12] = np.uint32(challenge["counter"])
    initial[0, 13:16] = np.array(challenge["nonce_words"], dtype=np.uint32)
    output = (_A119._core(initial.copy(), ROUNDS) + initial).astype(np.uint32)
    target = np.array(challenge["target_words"], dtype=np.uint32).reshape(1, 16)
    return {
        **model,
        "complete_block_match": bool(np.array_equal(output, target)),
        "output_bits_checked": 512,
        "candidate_block_sha256": _sha256(output.astype("<u4").tobytes()),
        "target_block_sha256": _sha256(target.astype("<u4").tobytes()),
        "implementation": "independent_NumPy_ChaCha4_block",
    }


def _build_causal(path: Path, payload: dict[str, Any]) -> dict[str, Any]:
    builder = CryptoCausalBuilder(
        experiment="chacha20_smt_directional_round4_transfer",
        parameters={
            "attempt_id": ATTEMPT_ID,
            "rounds": ROUNDS,
            "unknown_key_bits": UNKNOWN_KEY_BITS,
            "variants": list(VARIANTS),
        },
    )
    ids = [
        "chacha20-a184-width40-fullround-anchor",
        "chacha20-a185-fresh-round4-challenge",
        "chacha20-a185-five-causal-formula-views",
        "chacha20-a185-complete-directional-execution",
        "chacha20-a185-independent-directional-transfer",
    ]
    builder.add_triplet(
        edge_id=ids[0],
        trigger="A184:retained_fresh_fullround_40_bit_partial_key_recovery",
        mechanism="anchor_the_exact_40_bit_key_domain_and_standard_ChaCha_semantics",
        outcome="A185:causal_direction_transfer_question",
        confidence=1.0,
        evidence_kind="retained_A184_fullround_anchor",
        source=A184_CAUSAL_SHA256,
        attrs={"anchor_gates": payload["anchor_gates"]},
    )
    builder.add_triplet(
        edge_id=ids[1],
        trigger="A185:causal_direction_transfer_question",
        mechanism="freeze_a_fresh_round4_public_target_with_40_key_bits_omitted",
        outcome="A185:prospectively_frozen_round4_challenge",
        confidence=1.0,
        evidence_kind="pre_solver_public_challenge_freeze",
        source=PUBLIC_RELATION_SHA256,
        provenance=[ids[0]],
        attrs={"public_challenge": payload["public_challenge"]},
    )
    builder.add_triplet(
        edge_id=ids[2],
        trigger="A185:prospectively_frozen_round4_challenge",
        mechanism="compile_forward_inverse_and_three_midstate_split_DAGs_for_the_same_relation",
        outcome="A185:five_semantically_matched_causal_formula_views",
        confidence=1.0,
        evidence_kind="direction_and_midstate_representation_factorial",
        source=payload["formula_plan_sha256"],
        provenance=[ids[1]],
        attrs={"formula_plan": payload["formula_plan"]},
    )
    builder.add_triplet(
        edge_id=ids[3],
        trigger="A185:five_semantically_matched_causal_formula_views",
        mechanism="execute_every_frozen_view_sequentially_under_the_same_Z3_budget",
        outcome="A185:complete_directional_solver_frontier",
        confidence=1.0,
        evidence_kind="complete_predeclared_variant_execution",
        source=payload["execution_sha256"],
        provenance=[ids[2]],
        attrs={"execution": payload["execution"]},
    )
    builder.add_triplet(
        edge_id=ids[4],
        trigger="A185:complete_directional_solver_frontier",
        mechanism="confirm_every_SAT_model_with_independent_NumPy_over_all_512_output_bits",
        outcome="A185:prospective_causal_direction_transfer_result",
        confidence=1.0,
        evidence_kind="independent_complete_block_confirmation",
        source=payload["confirmation_sha256"],
        provenance=[ids[3]],
        attrs={"confirmations": payload["confirmations"]},
    )
    stats = dict(builder.save(path))
    stats.pop("path", None)
    reader = CryptoCausalReader(path)
    rows = reader.triplets(include_inferred=False)
    by_id = {row["edge_id"]: row for row in rows}
    if (
        len(rows) != len(ids)
        or set(by_id) != set(ids)
        or not reader.verify_provenance()
        or [by_id[edge_id]["provenance"] for edge_id in ids]
        != [[], [ids[0]], [ids[1]], [ids[2]], [ids[3]]]
    ):
        raise RuntimeError("A185 Causal provenance chain failed validation")
    return {
        "stats": stats,
        "explicit_triplets": len(rows),
        "provenance_verified": True,
        "file_sha256": reader.file_sha256,
        "graph_sha256": reader.graph_sha256,
    }


def _atomic_write(path: Path, raw: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.tmp")
    temporary.write_bytes(raw)
    temporary.replace(path)


def run(
    *,
    results_dir: Path,
    output: Path,
    causal_output: Path,
    z3_name: str,
) -> dict[str, Any]:
    analysis = analyze(results_dir)
    z3_raw = shutil.which(z3_name)
    if z3_raw is None:
        raise FileNotFoundError(f"Z3 executable not found: {z3_name}")
    z3 = Path(z3_raw)
    version = _solver_version(z3)
    if version != analysis["execution_plan"]["z3_version"]:
        raise RuntimeError(f"A185 requires Z3 4.15.4, observed {version}")
    formulas = {
        variant: _formula(
            variant,
            analysis["public_challenge"],
            analysis["execution_plan"]["timeout_milliseconds_per_variant"],
        )
        for variant in VARIANTS
    }
    formula_plan = [
        {
            "variant": variant,
            "sha256": _sha256(formulas[variant].encode()),
            "bytes": len(formulas[variant].encode()),
        }
        for variant in VARIANTS
    ]
    observations = [
        _run_formula(
            z3,
            variant,
            formulas[variant],
            analysis["execution_plan"]["external_timeout_seconds_per_variant"],
        )
        for variant in VARIANTS
    ]
    confirmations = [
        {"variant": row["variant"], **_confirm(analysis["public_challenge"], row["model"])}
        for row in observations
        if row["model"] is not None
    ]
    confirmed = [row for row in confirmations if row["complete_block_match"]]
    confirmed_directional = [
        row for row in confirmed if row["variant"] in {"inverse", "split1", "split2", "split3"}
    ]
    all_variants_executed = [row["variant"] for row in observations] == list(VARIANTS)
    if not all_variants_executed:
        raise RuntimeError("A185 did not execute the complete variant plan")
    confirmed_assignments = sorted({row["combined_assignment"] for row in confirmed})
    evidence_stage = (
        "PROSPECTIVE_CAUSAL_DIRECTION_TRANSFER_RETAINED"
        if confirmed_directional
        else "ROUND4_DIRECTIONAL_SOLVER_BOUNDARY_RETAINED"
    )
    execution = {
        "variant_order": list(VARIANTS),
        "complete_variant_plan_executed": all_variants_executed,
        "early_stop_used": False,
        "observations": observations,
        "confirmed_assignment_count": len(confirmed_assignments),
        "confirmed_assignments": confirmed_assignments,
        "confirmed_directional_variants": [row["variant"] for row in confirmed_directional],
        "unknown_assignment_available_to_runner_before_execution": False,
    }
    payload: dict[str, Any] = {
        "schema": SCHEMA,
        "attempt_id": ATTEMPT_ID,
        "evidence_stage": evidence_stage,
        "result": (
            "Five semantically matched forward, inverse, and split SMT views execute "
            "on a fresh four-round 40-bit ChaCha challenge; every SAT model is "
            "independently checked over the complete 512-bit block output."
        ),
        "scope": (
            "Prospective causal-direction transfer on four-round ChaCha with one full "
            "key word plus eight adjacent key bits unknown and 216 key bits known."
        ),
        "parameters": {
            "rounds": ROUNDS,
            "unknown_key_bits": UNKNOWN_KEY_BITS,
            "known_key_bits": KNOWN_KEY_BITS,
            "target_output_bits": 512,
            "variants": list(VARIANTS),
        },
        "protocol_gate": {
            "artifact_sha256": PROTOCOL_SHA256,
            "protocol_state": analysis["protocol"]["protocol_state"],
            "prospective_prediction": analysis["protocol"]["prospective_prediction"],
            "information_boundary": analysis["protocol"]["information_boundary"],
            "discovery_basis": analysis["protocol"]["discovery_basis"],
        },
        "anchor_gates": analysis["anchor_gates"],
        "public_challenge": analysis["public_challenge"],
        "public_challenge_sha256": PUBLIC_RELATION_SHA256,
        "execution_plan": analysis["execution_plan"],
        "execution_plan_sha256": _canonical_sha256(analysis["execution_plan"]),
        "solver": {"path": str(z3), "version": version},
        "formula_plan": formula_plan,
        "formula_plan_sha256": _canonical_sha256(formula_plan),
        "execution": execution,
        "execution_sha256": _canonical_sha256(execution),
        "confirmations": confirmations,
        "confirmation_sha256": _canonical_sha256(confirmations),
    }
    causal = _build_causal(causal_output, payload)
    payload["causal"] = causal
    raw = json.dumps(payload, indent=2, sort_keys=True, allow_nan=False).encode() + b"\n"
    _atomic_write(output, raw)
    reader = CryptoCausalReader(causal_output)
    if (
        _sha256(output.read_bytes()) != _sha256(raw)
        or reader.file_sha256 != causal["file_sha256"]
        or not reader.verify_provenance()
    ):
        raise RuntimeError("A185 final artifact reopen gate failed")
    return {
        "json_sha256": _sha256(raw),
        "causal_sha256": reader.file_sha256,
        "causal_graph_sha256": reader.graph_sha256,
        "evidence_stage": evidence_stage,
        "statuses": {row["variant"]: row["status"] for row in observations},
        "confirmed_assignments": confirmed_assignments,
        "confirmed_directional_variants": [row["variant"] for row in confirmed_directional],
        "output": str(output),
        "causal_output": str(causal_output),
    }


def main(argv: Sequence[str] | None = None) -> None:
    parser = argparse.ArgumentParser()
    research_root = Path(__file__).parents[1]
    parser.add_argument("--results-dir", type=Path, default=research_root / "results" / "v1")
    parser.add_argument("--analyze-only", action="store_true")
    parser.add_argument(
        "--output",
        type=Path,
        default=research_root / "results" / "v1" / RESULT_FILENAME,
    )
    parser.add_argument(
        "--causal-output",
        type=Path,
        default=research_root / "results" / "v1" / CAUSAL_FILENAME,
    )
    parser.add_argument("--z3", default="z3")
    args = parser.parse_args(argv)
    if args.analyze_only:
        analysis = analyze(args.results_dir.resolve())
        print(
            json.dumps(
                {
                    "protocol_sha256": PROTOCOL_SHA256,
                    "public_challenge_sha256": PUBLIC_RELATION_SHA256,
                    "execution_plan": analysis["execution_plan"],
                    "execution_plan_sha256": _canonical_sha256(
                        analysis["execution_plan"]
                    ),
                    "solver_execution_started": False,
                },
                sort_keys=True,
            )
        )
        return
    if args.output.resolve() == args.causal_output.resolve():
        raise ValueError("JSON and Causal outputs must be distinct")
    print(
        json.dumps(
            run(
                results_dir=args.results_dir.resolve(),
                output=args.output.resolve(),
                causal_output=args.causal_output.resolve(),
                z3_name=args.z3,
            ),
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    main()

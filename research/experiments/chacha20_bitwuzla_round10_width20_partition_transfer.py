#!/usr/bin/env python3
"""Prospective complete-prefix partition transfer for ChaCha10 width 20."""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import re
import subprocess
import sys
import time
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


_A194 = _import_sibling(
    "chacha20_bitwuzla_round9_width20_partition_transfer.py",
    "chacha20_round10_a194_anchor",
)
_A193 = _A194._A193
_A192 = _A194._A192
_A191 = _A194._A191
_A190 = _A194._A190
_A187 = _A190._A187
_A185 = _A190._A185
_A119 = _A190._A119

ATTEMPT_ID = "A195"
SCHEMA = "chacha20-bitwuzla-round10-width20-partition-transfer-v1"
PROTOCOL_SCHEMA = "chacha20-bitwuzla-round10-width20-partition-transfer-protocol-v1"
PROTOCOL_FILENAME = "chacha20_bitwuzla_round10_width20_partition_transfer_v1.json"
PROTOCOL_SHA256 = "5aa5d23084dd79258b4a5d7b76c3220c70ab4e77d725a6bcc020c6004e47b975"
A194_FILENAME = _A194.RESULT_FILENAME
A194_SHA256 = "d1a8b58f313467851d5162998d1ed8a71e250f64ee5d98d5ea6024c0e814227b"
A194_CAUSAL_FILENAME = _A194.CAUSAL_FILENAME
A194_CAUSAL_SHA256 = "a09e00b6815febc9e5a2713f98680e12b0b2d194172913f19caf55be06325a08"
PUBLIC_CHALLENGE_SHA256 = "5d17ed241b6b91224a4974f36b4b0b4ec5c677b9d975dd6bc8cec83b6ddbf86b"
ROUNDS = 10
UNKNOWN_KEY_BITS = 20
KNOWN_KEY_BITS = 236
LOW_MASK = (1 << UNKNOWN_KEY_BITS) - 1
PARTITION_FIXED_BITS = 5
PARTITION_FREE_BITS = 15
TIME_LIMIT_MS = 10_000
EXTERNAL_TIMEOUT_SECONDS = 15
VARIANTS = tuple(f"prefix_{value:05b}" for value in range(32))
RESULT_FILENAME = "chacha20_bitwuzla_round10_width20_partition_transfer_v1.json"
CAUSAL_FILENAME = "chacha20_bitwuzla_round10_width20_partition_transfer_v1.causal"


def _sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _canonical_sha256(value: Any) -> str:
    return _A194._canonical_sha256(value)


def _file_sha256(path: Path) -> str:
    return _A194._file_sha256(path)


def _load_protocol_gate() -> dict[str, Any]:
    path = Path(__file__).parents[1] / "configs" / PROTOCOL_FILENAME
    raw = path.read_bytes()
    if _sha256(raw) != PROTOCOL_SHA256:
        raise RuntimeError("A195 frozen protocol hash differs")
    protocol = json.loads(raw)
    boundary = protocol.get("information_boundary", {})
    if (
        protocol.get("schema") != PROTOCOL_SCHEMA
        or protocol.get("attempt_id") != ATTEMPT_ID
        or protocol.get("protocol_state")
        != "frozen_before_any_A195_solver_execution"
        or protocol.get("anchors", {}).get("A194", {}).get("sha256")
        != A194_SHA256
        or protocol.get("anchors", {}).get("A194", {}).get("causal_sha256")
        != A194_CAUSAL_SHA256
        or protocol.get("public_challenge_sha256") != PUBLIC_CHALLENGE_SHA256
        or protocol.get("execution_plan", {}).get("variants") != list(VARIANTS)
        or boundary.get("unknown_assignment_in_protocol_or_source") is not False
        or boundary.get("unknown_assignment_available_to_runner_before_execution")
        is not False
        or boundary.get("A195_solver_outcomes_used_before_protocol_freeze") is not False
        or boundary.get("cell_order_cut_or_budget_changed_after_any_outcome") is not False
        or boundary.get("early_stop_permitted") is not False
    ):
        raise RuntimeError("A195 frozen protocol identity gate failed")
    return protocol


def _load_anchor_gates(results_dir: Path) -> dict[str, Any]:
    result_path = results_dir / A194_FILENAME
    causal_path = results_dir / A194_CAUSAL_FILENAME
    observed = {
        "A194_result_sha256": _file_sha256(result_path),
        "A194_causal_sha256": _file_sha256(causal_path),
    }
    if observed != {
        "A194_result_sha256": A194_SHA256,
        "A194_causal_sha256": A194_CAUSAL_SHA256,
    }:
        raise RuntimeError("A195 A194 anchor hash gate failed")
    result = json.loads(result_path.read_bytes())
    confirmations = result.get("confirmations", [])
    if (
        result.get("schema") != _A194.SCHEMA
        or result.get("evidence_stage")
        != "PROSPECTIVE_ROUND9_WIDTH20_COMPLETE_PARTITION_RECOVERY_RETAINED"
        or result.get("execution", {}).get("complete_variant_plan_executed") is not True
        or result.get("comparisons", {}).get("prospective_prediction_retained")
        is not True
        or result.get("comparisons", {}).get("complete_domain_candidate_count")
        != 1 << 20
        or result.get("execution", {}).get(
            "fully_confirmed_unknown_low20_assignments"
        )
        != [550747]
        or len(confirmations) != 1
        or confirmations[0].get("all_blocks_match") is not True
        or confirmations[0].get("output_bits_checked") != 512
        or confirmations[0].get("control_first_block_match") is not False
    ):
        raise RuntimeError("A195 retained A194 partition recovery gate failed")
    reader = CryptoCausalReader(causal_path)
    if (
        reader.file_sha256 != A194_CAUSAL_SHA256
        or reader.graph_sha256 != result.get("causal", {}).get("graph_sha256")
        or not reader.verify_provenance()
    ):
        raise RuntimeError("A195 retained A194 Causal gate failed")
    return {
        **observed,
        "A194_causal_graph_sha256": reader.graph_sha256,
        "A194_causal_provenance_verified": True,
        "A194_prospective_complete_partition_recovery_retained": True,
    }


def _validate_public_challenge(challenge: dict[str, Any]) -> None:
    targets = challenge.get("target_words", [])
    target_hashes = challenge.get("target_block_sha256", [])
    if (
        _canonical_sha256(challenge) != PUBLIC_CHALLENGE_SHA256
        or challenge.get("rounds") != ROUNDS
        or challenge.get("block_count") != 8
        or challenge.get("counter_schedule")
        != "base_plus_block_index_mod_2^32"
        or challenge.get("unknown_assignment_bits") != UNKNOWN_KEY_BITS
        or challenge.get("unknown_assignment_included") is not False
        or challenge.get("unknown_key_word0_low_bits") != UNKNOWN_KEY_BITS
        or challenge.get("unknown_key_word0_low_value_included") is not False
        or challenge.get("known_key_word0_upper12", 1) & LOW_MASK
        or len(challenge.get("known_key_words_2_through_7", [])) != 6
        or len(challenge.get("nonce_words", [])) != 3
        or len(targets) != 8
        or any(len(row) != 16 for row in targets)
        or len(target_hashes) != 8
        or len(challenge.get("control_target_words", [])) != 16
        or challenge["control_target_words"][0] != (targets[0][0] ^ 1)
        or challenge["control_target_words"][1:] != targets[0][1:]
    ):
        raise RuntimeError("A195 public challenge identity gate failed")
    derived = hashlib.shake_256(
        challenge["known_material_derivation_label"].encode()
    ).digest(48)
    words = np.frombuffer(derived, dtype="<u4")
    if (
        _sha256(derived) != challenge["known_material_derivation_sha256"]
        or int(words[0]) & ~LOW_MASK != challenge["known_key_word0_upper12"]
        or int(words[1]) != challenge["known_key_word1"]
        or [int(value) for value in words[2:8]]
        != challenge["known_key_words_2_through_7"]
        or int(words[8]) != challenge["counter_start"]
        or [int(value) for value in words[9:12]] != challenge["nonce_words"]
    ):
        raise RuntimeError("A195 known-material derivation gate failed")
    for target, expected_hash in zip(targets, target_hashes, strict=True):
        raw = np.array(target, dtype=np.uint32).astype("<u4").tobytes()
        if _sha256(raw) != expected_hash:
            raise RuntimeError("A195 target byte fingerprint differs")
    control = np.array(challenge["control_target_words"], dtype=np.uint32)
    if _sha256(control.astype("<u4").tobytes()) != challenge[
        "control_target_block_sha256"
    ]:
        raise RuntimeError("A195 control byte fingerprint differs")


def _execution_plan() -> dict[str, Any]:
    return {
        "complete_variant_plan_required": True,
        "early_stop_used": False,
        "execution_mode": "sequential_external_solver_complete_prefix_partition",
        "external_timeout_seconds_per_cell": EXTERNAL_TIMEOUT_SECONDS,
        "formula_representation": (
            "portable_SMTLIB2_round10_split8_b1_complete_5bit_prefix_partition"
        ),
        "known_key_bits": KNOWN_KEY_BITS,
        "partition_cell_count": 32,
        "partition_cell_free_bits": PARTITION_FREE_BITS,
        "partition_fixed_bits": PARTITION_FIXED_BITS,
        "partition_prefix_order": [f"{value:05b}" for value in range(32)],
        "primitive": "ChaCha20_block_function",
        "rounds": ROUNDS,
        "solver": "Bitwuzla_0.9.1_bitblast_CaDiCaL",
        "solver_time_limit_milliseconds_per_cell": TIME_LIMIT_MS,
        "target_output_bits_per_cell": 512,
        "unknown_assignment_available_to_runner_before_execution": False,
        "unknown_key_bits": UNKNOWN_KEY_BITS,
        "variant_execution_order": list(VARIANTS),
        "variants": list(VARIANTS),
    }


def _prefix_value(variant: str) -> int:
    match = re.fullmatch(r"prefix_([01]{5})", variant)
    if match is None:
        raise ValueError(f"unknown A195 variant {variant}")
    return int(match.group(1), 2)


def _block_challenge(challenge: dict[str, Any]) -> dict[str, Any]:
    return {
        "rounds": ROUNDS,
        "known_key_word1_upper24": challenge["known_key_word1"] & 0xFFFFFF00,
        "known_key_words_2_through_7": challenge["known_key_words_2_through_7"],
        "counter": challenge["counter_start"],
        "nonce_words": challenge["nonce_words"],
        "target_words": challenge["target_words"][0],
    }


def _base_formula(challenge: dict[str, Any]) -> str:
    old_rounds = _A185.ROUNDS
    old_variants = _A185.VARIANTS
    try:
        _A185.ROUNDS = ROUNDS
        _A185.VARIANTS = (
            "forward",
            "inverse",
            "split1",
            "split2",
            "split3",
            "split4",
            "split5",
            "split6",
            "split7",
            "split8",
        )
        raw = _A185._formula("split8", _block_challenge(challenge), TIME_LIMIT_MS)
    finally:
        _A185.ROUNDS = old_rounds
        _A185.VARIANTS = old_variants
    header, definitions, assertions = _A187._split_formula(raw)
    header = [line for line in header if not line.startswith("(set-option :timeout ")]
    k0_index = header.index("(declare-fun k0 () (_ BitVec 32))")
    lo8_index = header.index("(declare-fun lo8 () (_ BitVec 8))")
    header[k0_index], header[lo8_index] = header[lo8_index], header[k0_index]
    lines = header
    lines.append(f"(assert (= lo8 #x{challenge['known_key_word1'] & 0xFF:02x}))")
    lines.append(
        "(assert (= ((_ extract 31 20) k0) "
        f"#x{challenge['known_key_word0_upper12'] >> 20:03x}))"
    )
    lines.extend(_A187._rename_block([*definitions, *assertions], 0))
    lines.extend(["(check-sat)", "(get-value (k0 lo8))"])
    return "\n".join(lines) + "\n"


def _formula(base: str, variant: str) -> str:
    prefix = _prefix_value(variant)
    assertion = f"(assert (= ((_ extract 19 15) k0) #b{prefix:05b}))"
    return base.replace("(check-sat)", assertion + "\n(check-sat)")


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
        raise RuntimeError("A195 execution plan differs from freeze")
    base = _base_formula(challenge)
    formulas = {variant: _formula(base, variant) for variant in VARIANTS}
    formula_plan = [
        {
            "variant": variant,
            "prefix": f"{_prefix_value(variant):05b}",
            "fixed_key_coordinates": [19, 18, 17, 16, 15],
            "free_key_coordinates": list(reversed(range(15))),
            "candidate_count": 1 << PARTITION_FREE_BITS,
            "bytes": len(formulas[variant].encode()),
            "sha256": _sha256(formulas[variant].encode()),
            "portable_smtlib2": True,
            "solver_time_limit_milliseconds": TIME_LIMIT_MS,
        }
        for variant in VARIANTS
    ]
    if (
        sum(row["candidate_count"] for row in formula_plan)
        != 1 << UNKNOWN_KEY_BITS
        or [row["prefix"] for row in formula_plan]
        != plan["partition_prefix_order"]
    ):
        raise RuntimeError("A195 complete partition coverage gate failed")
    return {
        "protocol": protocol,
        "anchor_gates": anchors,
        "public_challenge": challenge,
        "execution_plan": plan,
        "formulas": formulas,
        "formula_plan": formula_plan,
        "solver_execution_started": False,
    }


def _run_cell(
    variant: str, formula: str, identity: dict[str, Any]
) -> dict[str, Any]:
    command = [
        identity["path"], "--lang", "smt2", "--time-limit", str(TIME_LIMIT_MS),
        "--produce-models", "--bv-output-format", "16", "--bv-solver", "bitblast",
        "--sat-solver", "cadical",
    ]
    started = time.perf_counter()
    try:
        result = subprocess.run(
            command, input=formula, text=True, capture_output=True,
            timeout=EXTERNAL_TIMEOUT_SECONDS, check=False,
        )
        externally_timed_out = False
        stdout, stderr, returncode = result.stdout, result.stderr, result.returncode
    except subprocess.TimeoutExpired as error:
        externally_timed_out = True
        stdout, stderr, returncode = error.stdout or "", error.stderr or "", None
    status = next(
        (line for line in stdout.splitlines() if line in {"sat", "unsat", "unknown"}),
        "invalid",
    )
    values = {
        name: int(raw, 16)
        for name, raw in re.findall(r"\((k0|lo8)\s+#x([0-9a-fA-F]+)\)", stdout)
    }
    model = None
    if status == "sat":
        if set(values) != {"k0", "lo8"}:
            raise RuntimeError(f"A195 {variant} SAT model parse failed")
        if values["k0"] >> PARTITION_FREE_BITS & 0b11111 != _prefix_value(variant):
            raise RuntimeError(f"A195 {variant} model violates its partition cell")
        model = {
            "key_word0": values["k0"],
            "key_word1_low_value": values["lo8"],
            "combined_assignment": (values["lo8"] << 32) | values["k0"],
            "recovered_unknown_low20": values["k0"] & LOW_MASK,
        }
    return {
        "variant": variant,
        "prefix": f"{_prefix_value(variant):05b}",
        "free_bits": PARTITION_FREE_BITS,
        "candidate_count": 1 << PARTITION_FREE_BITS,
        "formula_sha256": _sha256(formula.encode()),
        "formula_bytes": len(formula.encode()),
        "solver_time_limit_milliseconds": TIME_LIMIT_MS,
        "command": command,
        "status": status,
        "returncode": returncode,
        "externally_timed_out": externally_timed_out,
        "volatile_seconds": time.perf_counter() - started,
        "model": model,
        "stdout_sha256": _sha256(stdout.encode()),
        "stderr_sha256": _sha256(stderr.encode()),
    }


def _confirm_model(challenge: dict[str, Any], model: dict[str, int]) -> dict[str, Any]:
    known_word1 = challenge["known_key_word1"]
    initial = np.zeros((1, 16), dtype=np.uint32)
    initial[0, :4] = _A119.CONSTANTS
    initial[0, 4] = np.uint32(model["key_word0"])
    initial[0, 5] = np.uint32(known_word1)
    initial[0, 6:12] = np.array(
        challenge["known_key_words_2_through_7"], dtype=np.uint32
    )
    initial[0, 12] = np.uint32(challenge["counter_start"])
    initial[0, 13:16] = np.array(challenge["nonce_words"], dtype=np.uint32)
    output = (_A119._core(initial.copy(), ROUNDS) + initial).astype(np.uint32)
    target = np.array(challenge["target_words"][0], dtype=np.uint32).reshape(1, 16)
    candidate_hash = _sha256(output.astype("<u4").tobytes())
    return {
        **model,
        "known_key_constraints_match": (
            model["key_word0"] & ~LOW_MASK
            == challenge["known_key_word0_upper12"]
            and model["key_word1_low_value"] == known_word1 & 0xFF
        ),
        "block_count_checked": 1,
        "block_matches": [bool(np.array_equal(output, target))],
        "all_blocks_match": bool(np.array_equal(output, target)),
        "candidate_block_sha256": [candidate_hash],
        "control_first_block_match": candidate_hash
        == challenge["control_target_block_sha256"],
        "output_bits_checked": 512,
        "implementation": "independent_NumPy_ChaCha10_block",
    }


def _build_causal(path: Path, payload: dict[str, Any]) -> dict[str, Any]:
    builder = CryptoCausalBuilder(
        experiment="chacha20_bitwuzla_round10_width20_partition_transfer",
        parameters={
            "attempt_id": ATTEMPT_ID, "rounds": ROUNDS,
            "unknown_key_bits": UNKNOWN_KEY_BITS, "partition_cells": len(VARIANTS),
        },
    )
    ids = [
        "chacha20-a194-round9-width20-partition-recovery-anchor",
        "chacha20-a195-fresh-round10-width20-challenge",
        "chacha20-a195-complete-split8-prefix-partition",
        "chacha20-a195-complete-cell-execution",
        "chacha20-a195-independent-model-confirmation",
        "chacha20-a195-prospective-depth-transfer",
    ]
    evidence = [
        ("A194:prospective_round9_width20_partition_recovery", "anchor_the_confirmed_complete_partition", "A195:round10_depth_transfer_question", "retained_A194_partition_anchor", A194_CAUSAL_SHA256, {"anchor_gates": payload["anchor_gates"]}),
        ("A195:round10_depth_transfer_question", "freeze_new_round10_targets_with_discarded_low20_assignment", "A195:fresh_round10_width20_challenge", "pre_solver_public_challenge_freeze", PUBLIC_CHALLENGE_SHA256, {"public_challenge": payload["public_challenge"]}),
        ("A195:fresh_round10_width20_challenge", "compile_split8_over_all_thirty_two_disjoint_prefixes", "A195:complete_disjoint_width15_formula_cover", "assignment_free_complete_partition", payload["formula_plan_sha256"], {"formula_plan": payload["formula_plan"]}),
        ("A195:complete_disjoint_width15_formula_cover", "execute_every_cell_in_numeric_order_without_early_stop", "A195:complete_partition_execution", "complete_predeclared_cell_execution", payload["execution_sha256"], {"execution": payload["execution"]}),
        ("A195:complete_partition_execution", "recompute_each_model_over_512_round10_target_bits_and_control", "A195:independently_confirmed_partition_models", "independent_complete_block_confirmation", payload["confirmation_sha256"], {"confirmations": payload["confirmations"]}),
        ("A195:independently_confirmed_partition_models", "apply_the_predeclared_round10_partition_success_rule", "A195:prospective_complete_partition_depth_result", "prospective_complete_partition_round_depth_transfer", payload["comparison_sha256"], {"comparisons": payload["comparisons"]}),
    ]
    for index, row in enumerate(evidence):
        trigger, mechanism, outcome, kind, source, attrs = row
        builder.add_triplet(
            edge_id=ids[index], trigger=trigger, mechanism=mechanism, outcome=outcome,
            confidence=1.0, evidence_kind=kind, source=source,
            provenance=[] if index == 0 else [ids[index - 1]], attrs=attrs,
        )
    stats = dict(builder.save(path))
    stats.pop("path", None)
    reader = CryptoCausalReader(path)
    rows = reader.triplets(include_inferred=False)
    by_id = {row["edge_id"]: row for row in rows}
    expected = [[], *[[ids[index - 1]] for index in range(1, len(ids))]]
    if (
        len(rows) != len(ids) or set(by_id) != set(ids)
        or [by_id[edge_id]["provenance"] for edge_id in ids] != expected
        or not reader.verify_provenance()
    ):
        raise RuntimeError("A195 Causal provenance chain failed validation")
    return {
        "stats": stats, "explicit_triplets": len(rows), "provenance_verified": True,
        "file_sha256": reader.file_sha256, "graph_sha256": reader.graph_sha256,
    }


def run(*, results_dir: Path, output: Path, causal_output: Path) -> dict[str, Any]:
    analysis = analyze(results_dir)
    identity = _A191._solver_gate(analysis["protocol"])
    observations = [
        _run_cell(variant, analysis["formulas"][variant], identity) for variant in VARIANTS
    ]
    if [row["variant"] for row in observations] != list(VARIANTS):
        raise RuntimeError("A195 did not execute the complete cell plan")
    confirmations = [
        {"variant": row["variant"], "prefix": row["prefix"], **_confirm_model(analysis["public_challenge"], row["model"])}
        for row in observations if row["model"] is not None
    ]
    if any(
        not row["known_key_constraints_match"] or not row["all_blocks_match"]
        or row["control_first_block_match"] or row["output_bits_checked"] != 512
        for row in confirmations
    ):
        raise RuntimeError("A195 returned model failed independent confirmation")
    recovered = sorted({row["recovered_unknown_low20"] for row in confirmations})
    prediction_retained = len(recovered) >= 1
    comparisons = {
        "complete_domain_candidate_count": sum(row["candidate_count"] for row in observations),
        "original_domain_candidate_count": 1 << UNKNOWN_KEY_BITS,
        "partition_complete_and_disjoint_by_construction": True,
        "confirmed_variants": [row["variant"] for row in confirmations],
        "fully_confirmed_unknown_low20_assignments": recovered,
        "prospective_prediction_retained": prediction_retained,
        "statuses": {row["variant"]: row["status"] for row in observations},
    }
    evidence_stage = (
        "PROSPECTIVE_ROUND10_WIDTH20_COMPLETE_PARTITION_RECOVERY_RETAINED"
        if prediction_retained else "ROUND10_WIDTH20_COMPLETE_PARTITION_BOUNDARY_RETAINED"
    )
    execution = {
        "variant_order": list(VARIANTS), "complete_variant_plan_executed": True,
        "early_stop_used": False, "observations": observations,
        "returned_model_count": len(confirmations),
        "fully_confirmed_unknown_assignment_count": len(recovered),
        "fully_confirmed_unknown_low20_assignments": recovered,
        "unknown_assignment_available_to_runner_before_execution": False,
    }
    payload: dict[str, Any] = {
        "schema": SCHEMA, "attempt_id": ATTEMPT_ID, "evidence_stage": evidence_stage,
        "result": "A complete assignment-free 32-cell split8 prefix partition prospectively transfers fresh ChaCha recovery to round 10 over 20 unknown key bits.",
        "scope": "Prospective reduced ChaCha10 partial-key recovery over the unchanged 2^20 domain represented as 32 disjoint width-15 cells.",
        "parameters": {"rounds": ROUNDS, "unknown_key_bits": UNKNOWN_KEY_BITS, "known_key_bits": KNOWN_KEY_BITS, "partition_cells": len(VARIANTS), "free_bits_per_cell": PARTITION_FREE_BITS, "variants": list(VARIANTS)},
        "protocol_gate": {"artifact_sha256": PROTOCOL_SHA256, "protocol_state": analysis["protocol"]["protocol_state"], "prospective_prediction": analysis["protocol"]["prospective_prediction"], "information_boundary": analysis["protocol"]["information_boundary"], "depth_discovery_basis": analysis["protocol"]["depth_discovery_basis"]},
        "anchor_gates": analysis["anchor_gates"], "public_challenge": analysis["public_challenge"],
        "public_challenge_sha256": PUBLIC_CHALLENGE_SHA256,
        "execution_plan": analysis["execution_plan"], "execution_plan_sha256": _canonical_sha256(analysis["execution_plan"]),
        "solver_identity": identity, "formula_plan": analysis["formula_plan"], "formula_plan_sha256": _canonical_sha256(analysis["formula_plan"]),
        "execution": execution, "execution_sha256": _canonical_sha256(execution),
        "confirmations": confirmations, "confirmation_sha256": _canonical_sha256(confirmations),
        "comparisons": comparisons, "comparison_sha256": _canonical_sha256(comparisons),
    }
    causal = _build_causal(causal_output, payload)
    payload["causal"] = causal
    raw = json.dumps(payload, indent=2, sort_keys=True, allow_nan=False).encode() + b"\n"
    _A185._atomic_write(output, raw)
    reader = CryptoCausalReader(causal_output)
    if _sha256(output.read_bytes()) != _sha256(raw) or reader.file_sha256 != causal["file_sha256"] or not reader.verify_provenance():
        raise RuntimeError("A195 final artifact reopen gate failed")
    return {"json_sha256": _sha256(raw), "causal_sha256": reader.file_sha256, "causal_graph_sha256": reader.graph_sha256, "evidence_stage": evidence_stage, "statuses": comparisons["statuses"], "fully_confirmed_unknown_low20_assignments": recovered, "comparisons": comparisons, "output": str(output), "causal_output": str(causal_output)}


def main(argv: Sequence[str] | None = None) -> None:
    parser = argparse.ArgumentParser()
    research_root = Path(__file__).parents[1]
    parser.add_argument("--results-dir", type=Path, default=research_root / "results" / "v1")
    parser.add_argument("--analyze-only", action="store_true")
    parser.add_argument("--output", type=Path, default=research_root / "results" / "v1" / RESULT_FILENAME)
    parser.add_argument("--causal-output", type=Path, default=research_root / "results" / "v1" / CAUSAL_FILENAME)
    args = parser.parse_args(argv)
    if args.analyze_only:
        analysis = analyze(args.results_dir.resolve())
        print(json.dumps({"protocol_sha256": PROTOCOL_SHA256, "public_challenge_sha256": PUBLIC_CHALLENGE_SHA256, "execution_plan_sha256": _canonical_sha256(analysis["execution_plan"]), "formula_plan": analysis["formula_plan"], "formula_plan_sha256": _canonical_sha256(analysis["formula_plan"]), "solver_execution_started": False}, sort_keys=True))
        return
    if args.output.resolve() == args.causal_output.resolve():
        raise ValueError("JSON and Causal outputs must be distinct")
    print(json.dumps(run(results_dir=args.results_dir.resolve(), output=args.output.resolve(), causal_output=args.causal_output.resolve()), sort_keys=True))


if __name__ == "__main__":
    main()

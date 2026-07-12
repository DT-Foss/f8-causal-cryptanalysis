#!/usr/bin/env python3
"""Prospective Bitwuzla transfer for fresh 40-bit ChaCha5 recovery."""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import re
import shutil
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


_A187 = _import_sibling(
    "chacha20_smt_shared_key_multiblock_transfer.py",
    "chacha20_bitwuzla_a187_anchor",
)
_A186 = _A187._A186
_A185 = _A187._A185

ATTEMPT_ID = "A188"
SCHEMA = "chacha20-bitwuzla-round5-transfer-v1"
PROTOCOL_SCHEMA = "chacha20-bitwuzla-round5-transfer-protocol-v1"
PROTOCOL_FILENAME = "chacha20_bitwuzla_round5_transfer_v1.json"
PROTOCOL_SHA256 = "73d029af9d75d6d463d03b311b8c5cff66fe42219685a35024a430b6f31cb2ef"
A187_FILENAME = _A187.RESULT_FILENAME
A187_SHA256 = "ec00786b9e778b3914cc2594919da11b763cfffa72f71fa110c2c90dc8e9e3e3"
A187_CAUSAL_FILENAME = _A187.CAUSAL_FILENAME
A187_CAUSAL_SHA256 = "6c3eda1c3f84cac90bf04e63267728cd88581f73f85fe18e971e72caa67fd68d"
PUBLIC_CHALLENGE_SHA256 = "231ca751d07fefffbd54ce0715d8bc35f7a6d444df0f5c6f482b5b407e69ff9c"
ROUNDS = 5
UNKNOWN_KEY_BITS = 40
KNOWN_KEY_BITS = 216
TIME_LIMIT_MS = 5_000
VARIANTS = (
    "bitwuzla_bitblast_b1",
    "bitwuzla_bitblast_b2",
    "bitwuzla_bitblast_b4",
    "bitwuzla_bitblast_b8",
    "bitwuzla_preprop_b4",
    "bitwuzla_prop_b4",
    "z3_bitblast_b4",
    "boolector_fun_b4",
)
RESULT_FILENAME = "chacha20_bitwuzla_round5_transfer_v1.json"
CAUSAL_FILENAME = "chacha20_bitwuzla_round5_transfer_v1.causal"


def _sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _canonical_sha256(value: Any) -> str:
    return _A187._canonical_sha256(value)


def _file_sha256(path: Path) -> str:
    return _A187._file_sha256(path)


def _load_protocol_gate() -> dict[str, Any]:
    path = Path(__file__).parents[1] / "configs" / PROTOCOL_FILENAME
    raw = path.read_bytes()
    if _sha256(raw) != PROTOCOL_SHA256:
        raise RuntimeError("A188 frozen protocol hash differs")
    protocol = json.loads(raw)
    boundary = protocol.get("information_boundary", {})
    if (
        protocol.get("schema") != PROTOCOL_SCHEMA
        or protocol.get("attempt_id") != ATTEMPT_ID
        or protocol.get("protocol_state") != "frozen_before_any_A188_solver_execution"
        or protocol.get("anchors", {}).get("A187", {}).get("sha256") != A187_SHA256
        or protocol.get("anchors", {}).get("A187", {}).get("causal_sha256")
        != A187_CAUSAL_SHA256
        or protocol.get("public_challenge_sha256") != PUBLIC_CHALLENGE_SHA256
        or protocol.get("execution_plan", {}).get("variants") != list(VARIANTS)
        or boundary.get("unknown_assignment_in_protocol_or_source") is not False
        or boundary.get("unknown_assignment_available_to_runner_before_execution") is not False
        or boundary.get("A188_solver_outcomes_used_before_protocol_freeze") is not False
        or boundary.get("variant_order_or_budget_changed_after_any_outcome") is not False
    ):
        raise RuntimeError("A188 frozen protocol identity gate failed")
    return protocol


def _load_anchor_gates(results_dir: Path) -> dict[str, Any]:
    result_path = results_dir / A187_FILENAME
    causal_path = results_dir / A187_CAUSAL_FILENAME
    observed = {
        "A187_result_sha256": _file_sha256(result_path),
        "A187_causal_sha256": _file_sha256(causal_path),
    }
    if observed != {
        "A187_result_sha256": A187_SHA256,
        "A187_causal_sha256": A187_CAUSAL_SHA256,
    }:
        raise RuntimeError("A188 A187 anchor hash gate failed")
    result = json.loads(result_path.read_bytes())
    comparisons = result.get("comparisons", {})
    if (
        result.get("schema") != _A187.SCHEMA
        or result.get("evidence_stage")
        != "PROSPECTIVE_SHARED_KEY_CAUSAL_STACKING_TRANSFER_RETAINED"
        or result.get("execution", {}).get("complete_variant_plan_executed") is not True
        or comparisons.get("prospective_prediction_retained") is not True
        or result.get("execution", {}).get("returned_model_count") != 0
    ):
        raise RuntimeError("A188 retained A187 result gate failed")
    reader = CryptoCausalReader(causal_path)
    if (
        reader.file_sha256 != A187_CAUSAL_SHA256
        or reader.graph_sha256 != result.get("causal", {}).get("graph_sha256")
        or not reader.verify_provenance()
    ):
        raise RuntimeError("A188 retained A187 Causal gate failed")
    return {
        **observed,
        "A187_causal_graph_sha256": reader.graph_sha256,
        "A187_causal_provenance_verified": True,
        "A187_prospective_stacking_transfer_retained": True,
    }


def _validate_public_challenge(challenge: dict[str, Any]) -> None:
    targets = challenge.get("target_words", [])
    target_hashes = challenge.get("target_block_sha256", [])
    if (
        _canonical_sha256(challenge) != PUBLIC_CHALLENGE_SHA256
        or challenge.get("rounds") != ROUNDS
        or challenge.get("block_count") != 8
        or challenge.get("counter_schedule") != "base_plus_block_index_mod_2^32"
        or challenge.get("unknown_assignment_bits") != UNKNOWN_KEY_BITS
        or challenge.get("unknown_assignment_included") is not False
        or challenge.get("unknown_key_word0_included") is not False
        or challenge.get("unknown_key_word1_low_value_included") is not False
        or challenge.get("known_key_word1_upper24", 1) & 0xFF
        or len(challenge.get("known_key_words_2_through_7", [])) != 6
        or len(challenge.get("nonce_words", [])) != 3
        or len(targets) != 8
        or any(len(row) != 16 for row in targets)
        or len(target_hashes) != 8
        or len(challenge.get("control_target_words", [])) != 16
        or challenge["control_target_words"][0] != (targets[0][0] ^ 1)
        or challenge["control_target_words"][1:] != targets[0][1:]
    ):
        raise RuntimeError("A188 public challenge identity gate failed")
    derived = hashlib.shake_256(challenge["known_material_derivation_label"].encode()).digest(
        44
    )
    words = np.frombuffer(derived, dtype="<u4")
    if (
        _sha256(derived) != challenge["known_material_derivation_sha256"]
        or int(words[0]) & 0xFFFFFF00 != challenge["known_key_word1_upper24"]
        or [int(value) for value in words[1:7]]
        != challenge["known_key_words_2_through_7"]
        or int(words[7]) != challenge["counter_start"]
        or [int(value) for value in words[8:11]] != challenge["nonce_words"]
    ):
        raise RuntimeError("A188 known-material derivation gate failed")
    for target, expected_hash in zip(targets, target_hashes, strict=True):
        raw = np.array(target, dtype=np.uint32).astype("<u4").tobytes()
        if _sha256(raw) != expected_hash:
            raise RuntimeError("A188 target byte fingerprint differs")
    control = np.array(challenge["control_target_words"], dtype=np.uint32)
    if (
        _sha256(control.astype("<u4").tobytes())
        != challenge["control_target_block_sha256"]
    ):
        raise RuntimeError("A188 control byte fingerprint differs")


def _execution_plan() -> dict[str, Any]:
    return {
        "primitive": "ChaCha20_block_function",
        "rounds": ROUNDS,
        "unknown_key_bits": UNKNOWN_KEY_BITS,
        "known_key_bits": KNOWN_KEY_BITS,
        "target_output_bits_per_block": 512,
        "variants": list(VARIANTS),
        "variant_execution_order": list(VARIANTS),
        "execution_mode": "sequential_external_solver_portfolio",
        "solver_time_limit_milliseconds_per_variant": TIME_LIMIT_MS,
        "external_timeout_seconds_per_variant": 8,
        "formula_representation": "portable_SMTLIB2_shared_define_fun_DAG",
        "complete_variant_plan_required": True,
        "early_stop_used": False,
        "unknown_assignment_available_to_runner_before_execution": False,
    }


def _block_challenges(challenge: dict[str, Any]) -> list[dict[str, Any]]:
    return [
        {
            "rounds": ROUNDS,
            "known_key_word1_upper24": challenge["known_key_word1_upper24"],
            "known_key_words_2_through_7": challenge["known_key_words_2_through_7"],
            "counter": (challenge["counter_start"] + index) & 0xFFFFFFFF,
            "nonce_words": challenge["nonce_words"],
            "target_words": target,
        }
        for index, target in enumerate(challenge["target_words"])
    ]


def _portable_formula(challenge: dict[str, Any], block_count: int) -> str:
    blocks = _block_challenges(challenge)[:block_count]
    parsed = [
        _A187._split_formula(_A186._formula("split4", block, TIME_LIMIT_MS))
        for block in blocks
    ]
    header = parsed[0][0].copy()
    header = [line for line in header if not line.startswith("(set-option :timeout ")]
    k0_index = header.index("(declare-fun k0 () (_ BitVec 32))")
    lo8_index = header.index("(declare-fun lo8 () (_ BitVec 8))")
    header[k0_index], header[lo8_index] = header[lo8_index], header[k0_index]
    lines = header
    for block_index in reversed(range(block_count)):
        _, definitions, assertions = parsed[block_index]
        lines.extend(_A187._rename_block([*definitions, *assertions], block_index))
    lines.extend(["(check-sat)", "(get-value (k0 lo8))"])
    return "\n".join(lines) + "\n"


def _variant_spec(variant: str) -> dict[str, Any]:
    match = re.fullmatch(r"bitwuzla_(bitblast|preprop|prop)_b(\d+)", variant)
    if match is not None:
        mode, raw_blocks = match.groups()
        return {"engine": "bitwuzla", "mode": mode, "block_count": int(raw_blocks)}
    match = re.fullmatch(r"(z3_bitblast|boolector_fun)_b(\d+)", variant)
    if match is None:
        raise ValueError(f"unknown A188 variant {variant}")
    engine_mode, raw_blocks = match.groups()
    engine, mode = engine_mode.split("_", 1)
    return {"engine": engine, "mode": mode, "block_count": int(raw_blocks)}


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
        raise RuntimeError("A188 execution plan differs from freeze")
    formulas: dict[str, str] = {}
    formula_plan = []
    for variant in VARIANTS:
        spec = _variant_spec(variant)
        formula = _portable_formula(challenge, spec["block_count"])
        formulas[variant] = formula
        formula_plan.append(
            {
                "variant": variant,
                **spec,
                "bytes": len(formula.encode()),
                "sha256": _sha256(formula.encode()),
                "declaration_order": ["lo8", "k0"],
                "block_definition_order": list(reversed(range(spec["block_count"]))),
                "portable_smtlib2": True,
            }
        )
    return {
        "protocol": protocol,
        "anchor_gates": anchors,
        "public_challenge": challenge,
        "execution_plan": plan,
        "formulas": formulas,
        "formula_plan": formula_plan,
        "solver_execution_started": False,
    }


def _solver_version(path: Path, engine: str) -> str:
    command = [str(path), "--version"] if engine != "z3" else [str(path), "-version"]
    result = subprocess.run(command, check=True, capture_output=True, text=True)
    if engine == "z3":
        match = re.search(r"Z3 version ([0-9.]+)", result.stdout)
        if match is None:
            raise RuntimeError("A188 could not parse Z3 version")
        return match.group(1)
    return result.stdout.strip().splitlines()[0]


def _solver_gates(protocol: dict[str, Any]) -> dict[str, dict[str, Any]]:
    identities = {}
    for engine in ("bitwuzla", "boolector", "z3"):
        raw_path = shutil.which(engine)
        if raw_path is None:
            raise FileNotFoundError(f"A188 solver executable not found: {engine}")
        path = Path(raw_path)
        version = _solver_version(path, engine)
        expected = protocol["solver_binaries"][engine]
        observed_hash = _file_sha256(path)
        if version != expected["version"] or observed_hash != expected["executable_sha256"]:
            raise RuntimeError(f"A188 frozen {engine} identity gate failed")
        identities[engine] = {
            "path": str(path),
            "version": version,
            "executable_sha256": observed_hash,
        }
    return identities


def _command(
    variant: str,
    identities: dict[str, dict[str, Any]],
) -> list[str]:
    spec = _variant_spec(variant)
    path = identities[spec["engine"]]["path"]
    if spec["engine"] == "bitwuzla":
        command = [
            path,
            "--lang",
            "smt2",
            "--time-limit",
            str(TIME_LIMIT_MS),
            "--produce-models",
            "--bv-output-format",
            "16",
            "--bv-solver",
            spec["mode"],
        ]
        if spec["mode"] in {"bitblast", "preprop"}:
            command.extend(["--sat-solver", "cadical"])
        return command
    if spec["engine"] == "boolector":
        return [
            path,
            "--smt2",
            f"--time={TIME_LIMIT_MS // 1000}",
            "--model-gen",
            "--hex",
            "--engine=fun",
            "--sat-engine=lingeling",
        ]
    return [path, "-in", "-st", f"-T:{TIME_LIMIT_MS // 1000}"]


def _run_variant(
    variant: str,
    formula: str,
    identities: dict[str, dict[str, Any]],
    external_timeout: int,
) -> dict[str, Any]:
    command = _command(variant, identities)
    started = time.perf_counter()
    try:
        result = subprocess.run(
            command,
            input=formula,
            text=True,
            capture_output=True,
            timeout=external_timeout,
            check=False,
        )
        externally_timed_out = False
        stdout = result.stdout
        stderr = result.stderr
        returncode = result.returncode
    except subprocess.TimeoutExpired as error:
        externally_timed_out = True
        stdout = error.stdout or ""
        stderr = error.stderr or ""
        returncode = None
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
            raise RuntimeError(f"A188 {variant} SAT model parse failed")
        model = {
            "key_word0": values["k0"],
            "key_word1_low_value": values["lo8"],
            "combined_assignment": (values["lo8"] << 32) | values["k0"],
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
        "engine": _variant_spec(variant)["engine"],
        "mode": _variant_spec(variant)["mode"],
        "block_count": _variant_spec(variant)["block_count"],
        "formula_sha256": _sha256(formula.encode()),
        "formula_bytes": len(formula.encode()),
        "command": command,
        "status": status,
        "returncode": returncode,
        "externally_timed_out": externally_timed_out,
        "volatile_seconds": time.perf_counter() - started,
        "model": model,
        "statistics": statistics,
        "stdout_sha256": _sha256(stdout.encode()),
        "stderr_sha256": _sha256(stderr.encode()),
    }


def _build_causal(path: Path, payload: dict[str, Any]) -> dict[str, Any]:
    builder = CryptoCausalBuilder(
        experiment="chacha20_bitwuzla_round5_transfer",
        parameters={
            "attempt_id": ATTEMPT_ID,
            "rounds": ROUNDS,
            "unknown_key_bits": UNKNOWN_KEY_BITS,
            "variants": list(VARIANTS),
        },
    )
    ids = [
        "chacha20-a187-prospective-stacking-anchor",
        "chacha20-a188-fresh-cross-engine-challenge",
        "chacha20-a188-portable-smtlib-formula-family",
        "chacha20-a188-complete-engine-portfolio",
        "chacha20-a188-independent-multiblock-confirmation",
        "chacha20-a188-prospective-engine-transfer",
    ]
    builder.add_triplet(
        edge_id=ids[0],
        trigger="A187:prospective_shared_key_stacking_transfer",
        mechanism="anchor_the_fresh_round5_search_shape_collapse",
        outcome="A188:cross_engine_transfer_question",
        confidence=1.0,
        evidence_kind="retained_A187_stacking_anchor",
        source=A187_CAUSAL_SHA256,
        attrs={"anchor_gates": payload["anchor_gates"]},
    )
    builder.add_triplet(
        edge_id=ids[1],
        trigger="A188:cross_engine_transfer_question",
        mechanism="freeze_eight_new_targets_from_one_discarded_40_bit_assignment",
        outcome="A188:prospectively_frozen_engine_transfer_challenge",
        confidence=1.0,
        evidence_kind="pre_solver_public_challenge_freeze",
        source=PUBLIC_CHALLENGE_SHA256,
        provenance=[ids[0]],
        attrs={"public_challenge": payload["public_challenge"]},
    )
    builder.add_triplet(
        edge_id=ids[2],
        trigger="A188:prospectively_frozen_engine_transfer_challenge",
        mechanism="compile_one_portable_split4_DAG_at_block_counts_one_two_four_eight",
        outcome="A188:portable_cross_engine_formula_family",
        confidence=1.0,
        evidence_kind="portable_SMTLIB2_formula_binding",
        source=payload["formula_plan_sha256"],
        provenance=[ids[1]],
        attrs={"formula_plan": payload["formula_plan"]},
    )
    builder.add_triplet(
        edge_id=ids[3],
        trigger="A188:portable_cross_engine_formula_family",
        mechanism="execute_all_frozen_Bitwuzla_Z3_and_Boolector_views_without_early_stop",
        outcome="A188:complete_engine_portfolio_frontier",
        confidence=1.0,
        evidence_kind="complete_predeclared_engine_execution",
        source=payload["execution_sha256"],
        provenance=[ids[2]],
        attrs={"execution": payload["execution"]},
    )
    builder.add_triplet(
        edge_id=ids[4],
        trigger="A188:complete_engine_portfolio_frontier",
        mechanism="recompute_every_model_over_each_constituent_512_bit_block_and_control",
        outcome="A188:independently_confirmed_engine_models",
        confidence=1.0,
        evidence_kind="independent_complete_block_confirmation",
        source=payload["confirmation_sha256"],
        provenance=[ids[3]],
        attrs={"confirmations": payload["confirmations"]},
    )
    builder.add_triplet(
        edge_id=ids[5],
        trigger="A188:independently_confirmed_engine_models",
        mechanism="compare_the_two_predeclared_Bitwuzla_b4_assignments",
        outcome="A188:prospective_cross_engine_recovery_transfer_result",
        confidence=1.0,
        evidence_kind="prospective_cross_engine_transfer",
        source=payload["comparison_sha256"],
        provenance=[ids[4]],
        attrs={"comparisons": payload["comparisons"]},
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
        != [[], [ids[0]], [ids[1]], [ids[2]], [ids[3]], [ids[4]]]
    ):
        raise RuntimeError("A188 Causal provenance chain failed validation")
    return {
        "stats": stats,
        "explicit_triplets": len(rows),
        "provenance_verified": True,
        "file_sha256": reader.file_sha256,
        "graph_sha256": reader.graph_sha256,
    }


def run(
    *,
    results_dir: Path,
    output: Path,
    causal_output: Path,
) -> dict[str, Any]:
    analysis = analyze(results_dir)
    identities = _solver_gates(analysis["protocol"])
    observations = [
        _run_variant(
            variant,
            analysis["formulas"][variant],
            identities,
            analysis["execution_plan"]["external_timeout_seconds_per_variant"],
        )
        for variant in VARIANTS
    ]
    confirmations = [
        {
            "variant": row["variant"],
            **_A187._confirm_model(
                analysis["public_challenge"], row["block_count"], row["model"]
            ),
        }
        for row in observations
        if row["model"] is not None
    ]
    if any(
        not row["all_blocks_match"] or row["control_first_block_match"]
        for row in confirmations
    ):
        raise RuntimeError("A188 returned model failed independent confirmation")
    confirmations_by_variant = {row["variant"]: row for row in confirmations}
    predicted = ("bitwuzla_bitblast_b4", "bitwuzla_preprop_b4")
    predicted_confirmations = [confirmations_by_variant.get(variant) for variant in predicted]
    same_assignment = (
        all(row is not None for row in predicted_confirmations)
        and len(
            {
                row["combined_assignment"]
                for row in predicted_confirmations
                if row is not None
            }
        )
        == 1
    )
    prediction_retained = same_assignment and all(
        row is not None and row["all_blocks_match"] and not row["control_first_block_match"]
        for row in predicted_confirmations
    )
    recovered_assignments = sorted(
        {row["combined_assignment"] for row in confirmations if row["all_blocks_match"]}
    )
    comparisons = {
        "predicted_variants": list(predicted),
        "predicted_variants_confirmed": [
            variant for variant in predicted if variant in confirmations_by_variant
        ],
        "predicted_assignments_identical": same_assignment,
        "prospective_prediction_retained": prediction_retained,
        "fully_confirmed_assignments": recovered_assignments,
    }
    evidence_stage = (
        "PROSPECTIVE_BITWUZLA_ROUND5_40BIT_RECOVERY_TRANSFER_RETAINED"
        if prediction_retained
        else "CROSS_ENGINE_ROUND5_RECOVERY_BOUNDARY_RETAINED"
    )
    all_variants_executed = [row["variant"] for row in observations] == list(VARIANTS)
    if not all_variants_executed:
        raise RuntimeError("A188 did not execute the complete variant plan")
    execution = {
        "variant_order": list(VARIANTS),
        "complete_variant_plan_executed": all_variants_executed,
        "early_stop_used": False,
        "observations": observations,
        "returned_model_count": len(confirmations),
        "fully_confirmed_assignment_count": len(recovered_assignments),
        "fully_confirmed_assignments": recovered_assignments,
        "unknown_assignment_available_to_runner_before_execution": False,
    }
    payload: dict[str, Any] = {
        "schema": SCHEMA,
        "attempt_id": ATTEMPT_ID,
        "evidence_stage": evidence_stage,
        "result": (
            "A frozen portable SMT-LIB2 portfolio prospectively transfers the A187 "
            "shared-key ChaCha5 relation across Bitwuzla, Z3, and Boolector."
        ),
        "scope": (
            "Prospective reduced five-round ChaCha partial-key recovery with one full "
            "key word plus eight adjacent bits unknown and 216 key bits known."
        ),
        "parameters": {
            "rounds": ROUNDS,
            "unknown_key_bits": UNKNOWN_KEY_BITS,
            "known_key_bits": KNOWN_KEY_BITS,
            "maximum_block_count": 8,
            "variants": list(VARIANTS),
            "solver_time_limit_milliseconds": TIME_LIMIT_MS,
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
        "public_challenge_sha256": PUBLIC_CHALLENGE_SHA256,
        "execution_plan": analysis["execution_plan"],
        "execution_plan_sha256": _canonical_sha256(analysis["execution_plan"]),
        "solver_identities": identities,
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
    raw = json.dumps(payload, indent=2, sort_keys=True, allow_nan=False).encode() + b"\n"
    _A185._atomic_write(output, raw)
    reader = CryptoCausalReader(causal_output)
    if (
        _sha256(output.read_bytes()) != _sha256(raw)
        or reader.file_sha256 != causal["file_sha256"]
        or not reader.verify_provenance()
    ):
        raise RuntimeError("A188 final artifact reopen gate failed")
    return {
        "json_sha256": _sha256(raw),
        "causal_sha256": reader.file_sha256,
        "causal_graph_sha256": reader.graph_sha256,
        "evidence_stage": evidence_stage,
        "statuses": {row["variant"]: row["status"] for row in observations},
        "fully_confirmed_assignments": recovered_assignments,
        "comparisons": comparisons,
        "output": str(output),
        "causal_output": str(causal_output),
    }


def main(argv: Sequence[str] | None = None) -> None:
    parser = argparse.ArgumentParser()
    research_root = Path(__file__).parents[1]
    parser.add_argument("--results-dir", type=Path, default=research_root / "results" / "v1")
    parser.add_argument("--analyze-only", action="store_true")
    parser.add_argument(
        "--output", type=Path, default=research_root / "results" / "v1" / RESULT_FILENAME
    )
    parser.add_argument(
        "--causal-output",
        type=Path,
        default=research_root / "results" / "v1" / CAUSAL_FILENAME,
    )
    args = parser.parse_args(argv)
    if args.analyze_only:
        analysis = analyze(args.results_dir.resolve())
        print(
            json.dumps(
                {
                    "protocol_sha256": PROTOCOL_SHA256,
                    "public_challenge_sha256": PUBLIC_CHALLENGE_SHA256,
                    "execution_plan_sha256": _canonical_sha256(
                        analysis["execution_plan"]
                    ),
                    "formula_plan": analysis["formula_plan"],
                    "formula_plan_sha256": _canonical_sha256(
                        analysis["formula_plan"]
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
            ),
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    main()

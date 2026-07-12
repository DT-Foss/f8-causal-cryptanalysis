#!/usr/bin/env python3
"""Prospective Bitwuzla ChaCha6 recovery over 20 unknown key bits."""

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


_A188 = _import_sibling(
    "chacha20_bitwuzla_round5_transfer.py",
    "chacha20_round6_a188_anchor",
)
_A187 = _A188._A187
_A185 = _A188._A185
_A119 = _A187._A119

ATTEMPT_ID = "A189"
SCHEMA = "chacha20-bitwuzla-round6-width20-transfer-v1"
PROTOCOL_SCHEMA = "chacha20-bitwuzla-round6-width20-transfer-protocol-v1"
PROTOCOL_FILENAME = "chacha20_bitwuzla_round6_width20_transfer_v1.json"
PROTOCOL_SHA256 = "88f9ba1cb557c1568689a46a42eaca69dc8f956de672fae99cb8d8988ae575cf"
A188_FILENAME = _A188.RESULT_FILENAME
A188_SHA256 = "d1a75d6456f75257cbd0be41864fad0810540508aa5c30239b16bd3998eef73a"
A188_CAUSAL_FILENAME = _A188.CAUSAL_FILENAME
A188_CAUSAL_SHA256 = "a717e615cfc005fe985a24059f7e6bedcd8008c460b274bb313f6ddfc53e7c78"
PUBLIC_CHALLENGE_SHA256 = "c9a75c6f80b07baa31768146a6b5f3549723da56d8bd16b07d74d255dac19d39"
ROUNDS = 6
UNKNOWN_KEY_BITS = 20
KNOWN_KEY_BITS = 236
VARIANTS = (
    "bitwuzla_bitblast_b1",
    "bitwuzla_bitblast_b2",
    "bitwuzla_bitblast_b4",
    "bitwuzla_bitblast_b8",
    "bitwuzla_preprop_b8",
    "bitwuzla_prop_b8",
    "z3_bitblast_b8",
    "boolector_fun_b8",
)
RESULT_FILENAME = "chacha20_bitwuzla_round6_width20_transfer_v1.json"
CAUSAL_FILENAME = "chacha20_bitwuzla_round6_width20_transfer_v1.causal"


def _sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _canonical_sha256(value: Any) -> str:
    return _A188._canonical_sha256(value)


def _file_sha256(path: Path) -> str:
    return _A188._file_sha256(path)


def _load_protocol_gate() -> dict[str, Any]:
    path = Path(__file__).parents[1] / "configs" / PROTOCOL_FILENAME
    raw = path.read_bytes()
    if _sha256(raw) != PROTOCOL_SHA256:
        raise RuntimeError("A189 frozen protocol hash differs")
    protocol = json.loads(raw)
    boundary = protocol.get("information_boundary", {})
    if (
        protocol.get("schema") != PROTOCOL_SCHEMA
        or protocol.get("attempt_id") != ATTEMPT_ID
        or protocol.get("protocol_state") != "frozen_before_any_A189_solver_execution"
        or protocol.get("anchors", {}).get("A188", {}).get("sha256") != A188_SHA256
        or protocol.get("anchors", {}).get("A188", {}).get("causal_sha256")
        != A188_CAUSAL_SHA256
        or protocol.get("public_challenge_sha256") != PUBLIC_CHALLENGE_SHA256
        or protocol.get("execution_plan", {}).get("variants") != list(VARIANTS)
        or boundary.get("unknown_assignment_in_protocol_or_source") is not False
        or boundary.get("unknown_assignment_available_to_runner_before_execution") is not False
        or boundary.get("A189_solver_outcomes_used_before_protocol_freeze") is not False
        or boundary.get("variant_order_or_budget_changed_after_any_outcome") is not False
    ):
        raise RuntimeError("A189 frozen protocol identity gate failed")
    return protocol


def _load_anchor_gates(results_dir: Path) -> dict[str, Any]:
    result_path = results_dir / A188_FILENAME
    causal_path = results_dir / A188_CAUSAL_FILENAME
    observed = {
        "A188_result_sha256": _file_sha256(result_path),
        "A188_causal_sha256": _file_sha256(causal_path),
    }
    if observed != {
        "A188_result_sha256": A188_SHA256,
        "A188_causal_sha256": A188_CAUSAL_SHA256,
    }:
        raise RuntimeError("A189 A188 anchor hash gate failed")
    result = json.loads(result_path.read_bytes())
    confirmations = result.get("confirmations", [])
    if (
        result.get("schema") != _A188.SCHEMA
        or result.get("execution", {}).get("complete_variant_plan_executed") is not True
        or result.get("execution", {}).get("fully_confirmed_assignments")
        != [357645702403]
        or len(confirmations) != 1
        or confirmations[0].get("variant") != "bitwuzla_bitblast_b8"
        or confirmations[0].get("all_blocks_match") is not True
        or confirmations[0].get("output_bits_checked") != 4096
        or confirmations[0].get("control_first_block_match") is not False
    ):
        raise RuntimeError("A189 retained A188 recovery gate failed")
    reader = CryptoCausalReader(causal_path)
    if (
        reader.file_sha256 != A188_CAUSAL_SHA256
        or reader.graph_sha256 != result.get("causal", {}).get("graph_sha256")
        or not reader.verify_provenance()
    ):
        raise RuntimeError("A189 retained A188 Causal gate failed")
    return {
        **observed,
        "A188_causal_graph_sha256": reader.graph_sha256,
        "A188_causal_provenance_verified": True,
        "A188_predeclared_b8_recovery_confirmed": True,
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
        or challenge.get("unknown_key_word0_low_bits") != UNKNOWN_KEY_BITS
        or challenge.get("unknown_key_word0_low_value_included") is not False
        or challenge.get("known_key_word0_upper12", 1) & 0x000FFFFF
        or len(challenge.get("known_key_words_2_through_7", [])) != 6
        or len(challenge.get("nonce_words", [])) != 3
        or len(targets) != 8
        or any(len(row) != 16 for row in targets)
        or len(target_hashes) != 8
        or len(challenge.get("control_target_words", [])) != 16
        or challenge["control_target_words"][0] != (targets[0][0] ^ 1)
        or challenge["control_target_words"][1:] != targets[0][1:]
    ):
        raise RuntimeError("A189 public challenge identity gate failed")
    derived = hashlib.shake_256(challenge["known_material_derivation_label"].encode()).digest(
        48
    )
    words = np.frombuffer(derived, dtype="<u4")
    if (
        _sha256(derived) != challenge["known_material_derivation_sha256"]
        or int(words[0]) & 0xFFF00000 != challenge["known_key_word0_upper12"]
        or int(words[1]) != challenge["known_key_word1"]
        or [int(value) for value in words[2:8]]
        != challenge["known_key_words_2_through_7"]
        or int(words[8]) != challenge["counter_start"]
        or [int(value) for value in words[9:12]] != challenge["nonce_words"]
    ):
        raise RuntimeError("A189 known-material derivation gate failed")
    for target, expected_hash in zip(targets, target_hashes, strict=True):
        raw = np.array(target, dtype=np.uint32).astype("<u4").tobytes()
        if _sha256(raw) != expected_hash:
            raise RuntimeError("A189 target byte fingerprint differs")
    control = np.array(challenge["control_target_words"], dtype=np.uint32)
    if (
        _sha256(control.astype("<u4").tobytes())
        != challenge["control_target_block_sha256"]
    ):
        raise RuntimeError("A189 control byte fingerprint differs")


def _execution_plan(protocol: dict[str, Any]) -> dict[str, Any]:
    return {
        "primitive": "ChaCha20_block_function",
        "rounds": ROUNDS,
        "unknown_key_bits": UNKNOWN_KEY_BITS,
        "known_key_bits": KNOWN_KEY_BITS,
        "target_output_bits_per_block": 512,
        "variants": list(VARIANTS),
        "variant_execution_order": list(VARIANTS),
        "execution_mode": "sequential_external_solver_portfolio",
        "solver_time_limit_milliseconds_by_variant": protocol["execution_plan"][
            "solver_time_limit_milliseconds_by_variant"
        ],
        "external_timeout_seconds_by_variant": protocol["execution_plan"][
            "external_timeout_seconds_by_variant"
        ],
        "formula_representation": "portable_SMTLIB2_round6_split5_shared_define_fun_DAG",
        "complete_variant_plan_required": True,
        "early_stop_used": False,
        "unknown_assignment_available_to_runner_before_execution": False,
    }


def _block_challenges(challenge: dict[str, Any]) -> list[dict[str, Any]]:
    key1 = challenge["known_key_word1"]
    return [
        {
            "rounds": ROUNDS,
            "known_key_word1_upper24": key1 & 0xFFFFFF00,
            "known_key_words_2_through_7": challenge["known_key_words_2_through_7"],
            "counter": (challenge["counter_start"] + index) & 0xFFFFFFFF,
            "nonce_words": challenge["nonce_words"],
            "target_words": target,
        }
        for index, target in enumerate(challenge["target_words"])
    ]


def _single_formula(block: dict[str, Any], timeout_ms: int) -> str:
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
        )
        return _A185._formula("split5", block, timeout_ms)
    finally:
        _A185.ROUNDS = old_rounds
        _A185.VARIANTS = old_variants


def _portable_formula(
    challenge: dict[str, Any], block_count: int, timeout_ms: int
) -> str:
    blocks = _block_challenges(challenge)[:block_count]
    parsed = [
        _A187._split_formula(_single_formula(block, timeout_ms)) for block in blocks
    ]
    header = [
        line for line in parsed[0][0] if not line.startswith("(set-option :timeout ")
    ]
    k0_index = header.index("(declare-fun k0 () (_ BitVec 32))")
    lo8_index = header.index("(declare-fun lo8 () (_ BitVec 8))")
    header[k0_index], header[lo8_index] = header[lo8_index], header[k0_index]
    lines = header
    lines.append(f"(assert (= lo8 #x{challenge['known_key_word1'] & 0xFF:02x}))")
    lines.append(
        "(assert (= ((_ extract 31 20) k0) "
        f"#x{challenge['known_key_word0_upper12'] >> 20:03x}))"
    )
    for block_index in reversed(range(block_count)):
        _, definitions, assertions = parsed[block_index]
        lines.extend(_A187._rename_block([*definitions, *assertions], block_index))
    lines.extend(["(check-sat)", "(get-value (k0 lo8))"])
    return "\n".join(lines) + "\n"


def analyze(results_dir: Path) -> dict[str, Any]:
    protocol = _load_protocol_gate()
    anchors = _load_anchor_gates(results_dir)
    challenge = protocol["public_challenge"]
    _validate_public_challenge(challenge)
    plan = _execution_plan(protocol)
    if (
        protocol["execution_plan"] != plan
        or protocol["execution_plan_sha256"] != _canonical_sha256(plan)
    ):
        raise RuntimeError("A189 execution plan differs from freeze")
    formulas = {}
    formula_plan = []
    for variant in VARIANTS:
        spec = _A188._variant_spec(variant)
        timeout_ms = plan["solver_time_limit_milliseconds_by_variant"][variant]
        formula = _portable_formula(challenge, spec["block_count"], timeout_ms)
        formulas[variant] = formula
        formula_plan.append(
            {
                "variant": variant,
                **spec,
                "logical_unknown_key_bits": UNKNOWN_KEY_BITS,
                "bytes": len(formula.encode()),
                "sha256": _sha256(formula.encode()),
                "declaration_order": ["lo8", "k0"],
                "block_definition_order": list(reversed(range(spec["block_count"]))),
                "portable_smtlib2": True,
                "solver_time_limit_milliseconds": timeout_ms,
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


def _command(
    variant: str,
    identities: dict[str, dict[str, Any]],
    timeout_ms: int,
) -> list[str]:
    spec = _A188._variant_spec(variant)
    path = identities[spec["engine"]]["path"]
    if spec["engine"] == "bitwuzla":
        command = [
            path,
            "--lang",
            "smt2",
            "--time-limit",
            str(timeout_ms),
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
            f"--time={timeout_ms // 1000}",
            "--model-gen",
            "--hex",
            "--engine=fun",
            "--sat-engine=lingeling",
        ]
    return [path, "-in", "-st", f"-T:{timeout_ms // 1000}"]


def _run_variant(
    variant: str,
    formula: str,
    identities: dict[str, dict[str, Any]],
    timeout_ms: int,
    external_timeout: int,
) -> dict[str, Any]:
    command = _command(variant, identities, timeout_ms)
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
            raise RuntimeError(f"A189 {variant} SAT model parse failed")
        model = {
            "key_word0": values["k0"],
            "key_word1_low_value": values["lo8"],
            "combined_assignment": (values["lo8"] << 32) | values["k0"],
            "recovered_unknown_low20": values["k0"] & 0x000FFFFF,
        }
    statistics = {
        key: int(float(value))
        for key, value in re.findall(r":([\w-]+)\s+([0-9.]+)", stdout)
        if key in {"rlimit-count", "sat-conflicts", "sat-decisions"}
    }
    spec = _A188._variant_spec(variant)
    return {
        "variant": variant,
        **spec,
        "formula_sha256": _sha256(formula.encode()),
        "formula_bytes": len(formula.encode()),
        "solver_time_limit_milliseconds": timeout_ms,
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


def _confirm_model(
    challenge: dict[str, Any], block_count: int, model: dict[str, int]
) -> dict[str, Any]:
    known_word1 = challenge["known_key_word1"]
    known_prefix_match = (
        model["key_word0"] & 0xFFF00000 == challenge["known_key_word0_upper12"]
        and model["key_word1_low_value"] == known_word1 & 0xFF
    )
    matches = []
    candidate_hashes = []
    for block in _block_challenges(challenge)[:block_count]:
        initial = np.zeros((1, 16), dtype=np.uint32)
        initial[0, :4] = _A119.CONSTANTS
        initial[0, 4] = np.uint32(model["key_word0"])
        initial[0, 5] = np.uint32(known_word1)
        initial[0, 6:12] = np.array(
            challenge["known_key_words_2_through_7"], dtype=np.uint32
        )
        initial[0, 12] = np.uint32(block["counter"])
        initial[0, 13:16] = np.array(challenge["nonce_words"], dtype=np.uint32)
        output = (_A119._core(initial.copy(), ROUNDS) + initial).astype(np.uint32)
        target = np.array(block["target_words"], dtype=np.uint32).reshape(1, 16)
        matches.append(bool(np.array_equal(output, target)))
        candidate_hashes.append(_sha256(output.astype("<u4").tobytes()))
    return {
        **model,
        "known_key_constraints_match": known_prefix_match,
        "block_count_checked": block_count,
        "block_matches": matches,
        "all_blocks_match": all(matches),
        "candidate_block_sha256": candidate_hashes,
        "control_first_block_match": candidate_hashes[0]
        == challenge["control_target_block_sha256"],
        "output_bits_checked": block_count * 512,
        "implementation": "independent_NumPy_ChaCha6_blocks",
    }


def _build_causal(path: Path, payload: dict[str, Any]) -> dict[str, Any]:
    builder = CryptoCausalBuilder(
        experiment="chacha20_bitwuzla_round6_width20_transfer",
        parameters={
            "attempt_id": ATTEMPT_ID,
            "rounds": ROUNDS,
            "unknown_key_bits": UNKNOWN_KEY_BITS,
            "variants": list(VARIANTS),
        },
    )
    ids = [
        "chacha20-a188-round5-b8-recovery-anchor",
        "chacha20-a189-fresh-round6-width20-challenge",
        "chacha20-a189-round6-split5-formula-family",
        "chacha20-a189-complete-engine-block-frontier",
        "chacha20-a189-independent-round6-confirmation",
        "chacha20-a189-prospective-depth-width-transfer",
    ]
    builder.add_triplet(
        edge_id=ids[0],
        trigger="A188:fresh_predeclared_b8_round5_40_bit_recovery",
        mechanism="anchor_the_independently_confirmed_eight_block_engine_transfer",
        outcome="A189:round6_depth_width_question",
        confidence=1.0,
        evidence_kind="retained_A188_recovery_anchor",
        source=A188_CAUSAL_SHA256,
        attrs={"anchor_gates": payload["anchor_gates"]},
    )
    builder.add_triplet(
        edge_id=ids[1],
        trigger="A189:round6_depth_width_question",
        mechanism="freeze_eight_round6_targets_with_one_discarded_low20_assignment",
        outcome="A189:prospectively_frozen_round6_width20_challenge",
        confidence=1.0,
        evidence_kind="pre_solver_public_challenge_freeze",
        source=PUBLIC_CHALLENGE_SHA256,
        provenance=[ids[0]],
        attrs={"public_challenge": payload["public_challenge"]},
    )
    builder.add_triplet(
        edge_id=ids[2],
        trigger="A189:prospectively_frozen_round6_width20_challenge",
        mechanism="compile_portable_split5_DAGs_at_block_counts_one_two_four_eight",
        outcome="A189:portable_round6_engine_formula_family",
        confidence=1.0,
        evidence_kind="portable_SMTLIB2_formula_binding",
        source=payload["formula_plan_sha256"],
        provenance=[ids[1]],
        attrs={"formula_plan": payload["formula_plan"]},
    )
    builder.add_triplet(
        edge_id=ids[3],
        trigger="A189:portable_round6_engine_formula_family",
        mechanism="execute_all_frozen_block_and_engine_views_without_early_stop",
        outcome="A189:complete_round6_depth_width_frontier",
        confidence=1.0,
        evidence_kind="complete_predeclared_engine_execution",
        source=payload["execution_sha256"],
        provenance=[ids[2]],
        attrs={"execution": payload["execution"]},
    )
    builder.add_triplet(
        edge_id=ids[4],
        trigger="A189:complete_round6_depth_width_frontier",
        mechanism="recompute_every_model_over_each_constituent_512_bit_block_and_control",
        outcome="A189:independently_confirmed_round6_models",
        confidence=1.0,
        evidence_kind="independent_complete_block_confirmation",
        source=payload["confirmation_sha256"],
        provenance=[ids[3]],
        attrs={"confirmations": payload["confirmations"]},
    )
    builder.add_triplet(
        edge_id=ids[5],
        trigger="A189:independently_confirmed_round6_models",
        mechanism="apply_the_predeclared_bitblast_b8_success_rule",
        outcome="A189:prospective_round6_depth_width_result",
        confidence=1.0,
        evidence_kind="prospective_depth_width_transfer",
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
        raise RuntimeError("A189 Causal provenance chain failed validation")
    return {
        "stats": stats,
        "explicit_triplets": len(rows),
        "provenance_verified": True,
        "file_sha256": reader.file_sha256,
        "graph_sha256": reader.graph_sha256,
    }


def run(
    *, results_dir: Path, output: Path, causal_output: Path
) -> dict[str, Any]:
    analysis = analyze(results_dir)
    identities = _A188._solver_gates(analysis["protocol"])
    plan = analysis["execution_plan"]
    observations = [
        _run_variant(
            variant,
            analysis["formulas"][variant],
            identities,
            plan["solver_time_limit_milliseconds_by_variant"][variant],
            plan["external_timeout_seconds_by_variant"][variant],
        )
        for variant in VARIANTS
    ]
    confirmations = [
        {
            "variant": row["variant"],
            **_confirm_model(
                analysis["public_challenge"], row["block_count"], row["model"]
            ),
        }
        for row in observations
        if row["model"] is not None
    ]
    if any(
        not row["known_key_constraints_match"]
        or not row["all_blocks_match"]
        or row["control_first_block_match"]
        for row in confirmations
    ):
        raise RuntimeError("A189 returned model failed independent confirmation")
    by_variant = {row["variant"]: row for row in confirmations}
    predicted = by_variant.get("bitwuzla_bitblast_b8")
    prediction_retained = (
        predicted is not None
        and predicted["all_blocks_match"]
        and not predicted["control_first_block_match"]
        and predicted["output_bits_checked"] == 4096
    )
    recovered_unknown = sorted(
        {row["recovered_unknown_low20"] for row in confirmations}
    )
    comparisons = {
        "predicted_variant": "bitwuzla_bitblast_b8",
        "predicted_variant_confirmed": prediction_retained,
        "prospective_prediction_retained": prediction_retained,
        "fully_confirmed_unknown_low20_assignments": recovered_unknown,
    }
    evidence_stage = (
        "PROSPECTIVE_BITWUZLA_ROUND6_20BIT_RECOVERY_TRANSFER_RETAINED"
        if prediction_retained
        else "ROUND6_WIDTH20_RECOVERY_BOUNDARY_RETAINED"
    )
    all_variants_executed = [row["variant"] for row in observations] == list(VARIANTS)
    if not all_variants_executed:
        raise RuntimeError("A189 did not execute the complete variant plan")
    execution = {
        "variant_order": list(VARIANTS),
        "complete_variant_plan_executed": all_variants_executed,
        "early_stop_used": False,
        "observations": observations,
        "returned_model_count": len(confirmations),
        "fully_confirmed_unknown_assignment_count": len(recovered_unknown),
        "fully_confirmed_unknown_low20_assignments": recovered_unknown,
        "unknown_assignment_available_to_runner_before_execution": False,
    }
    payload: dict[str, Any] = {
        "schema": SCHEMA,
        "attempt_id": ATTEMPT_ID,
        "evidence_stage": evidence_stage,
        "result": (
            "A frozen portable SMT-LIB2 portfolio prospectively transfers the "
            "shared-key Bitwuzla reader to six-round ChaCha over 20 unknown key bits."
        ),
        "scope": (
            "Prospective reduced six-round ChaCha partial-key recovery with the low "
            "20 bits of key word zero unknown and 236 key bits known."
        ),
        "parameters": {
            "rounds": ROUNDS,
            "unknown_key_bits": UNKNOWN_KEY_BITS,
            "known_key_bits": KNOWN_KEY_BITS,
            "maximum_block_count": 8,
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
        "public_challenge_sha256": PUBLIC_CHALLENGE_SHA256,
        "execution_plan": plan,
        "execution_plan_sha256": _canonical_sha256(plan),
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
        raise RuntimeError("A189 final artifact reopen gate failed")
    return {
        "json_sha256": _sha256(raw),
        "causal_sha256": reader.file_sha256,
        "causal_graph_sha256": reader.graph_sha256,
        "evidence_stage": evidence_stage,
        "statuses": {row["variant"]: row["status"] for row in observations},
        "fully_confirmed_unknown_low20_assignments": recovered_unknown,
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

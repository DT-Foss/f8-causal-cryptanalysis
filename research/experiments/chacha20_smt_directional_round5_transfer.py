#!/usr/bin/env python3
"""Prospective ChaCha5 causal-direction transfer over 40 unknown key bits."""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import shutil
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


_A185 = _import_sibling(
    "chacha20_smt_directional_round4_transfer.py",
    "chacha20_direction_a185_anchor",
)
_A119 = _A185._A119

ATTEMPT_ID = "A186"
SCHEMA = "chacha20-smt-directional-round5-transfer-v1"
PROTOCOL_SCHEMA = "chacha20-smt-directional-round5-transfer-protocol-v1"
PROTOCOL_FILENAME = "chacha20_smt_directional_round5_transfer_v1.json"
PROTOCOL_SHA256 = "67c27032eab51ac443dcb5446eca3fe46b1c42dd60a02fb13d2d7c0b97e3c6fe"
A185_FILENAME = _A185.RESULT_FILENAME
A185_SHA256 = "d87aefa46f4b85a71ab9fd2199401975075beb0fedf1545b9dc63842126c31e0"
A185_CAUSAL_FILENAME = _A185.CAUSAL_FILENAME
A185_CAUSAL_SHA256 = "ea490a5ea59838faacddfc11ca80390e6cb87ff35943eb1e294cd1006f1e77ac"
PUBLIC_CHALLENGE_SHA256 = "1ae9e4d48c61ec31513ae34024ebc4d1d0bebba81a32459265d94f54a06ab6af"
ROUNDS = 5
UNKNOWN_KEY_BITS = 40
KNOWN_KEY_BITS = 216
VARIANTS = ("forward", "inverse", "split1", "split2", "split3", "split4")
PREDICTED_VARIANTS = ("split1", "split2")
RESULT_FILENAME = "chacha20_smt_directional_round5_transfer_v1.json"
CAUSAL_FILENAME = "chacha20_smt_directional_round5_transfer_v1.causal"


def _sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _canonical_sha256(value: Any) -> str:
    return _A185._canonical_sha256(value)


def _file_sha256(path: Path) -> str:
    return _A185._file_sha256(path)


def _load_protocol_gate() -> dict[str, Any]:
    path = Path(__file__).parents[1] / "configs" / PROTOCOL_FILENAME
    raw = path.read_bytes()
    if _sha256(raw) != PROTOCOL_SHA256:
        raise RuntimeError("A186 frozen protocol hash differs")
    protocol = json.loads(raw)
    boundary = protocol.get("information_boundary", {})
    if (
        protocol.get("schema") != PROTOCOL_SCHEMA
        or protocol.get("attempt_id") != ATTEMPT_ID
        or protocol.get("protocol_state") != "frozen_before_any_A186_solver_execution"
        or protocol.get("anchors", {}).get("A185", {}).get("sha256") != A185_SHA256
        or protocol.get("anchors", {}).get("A185", {}).get("causal_sha256")
        != A185_CAUSAL_SHA256
        or protocol.get("public_challenge_sha256") != PUBLIC_CHALLENGE_SHA256
        or protocol.get("execution_plan", {}).get("variants") != list(VARIANTS)
        or boundary.get("unknown_assignment_in_protocol_or_source") is not False
        or boundary.get("unknown_assignment_available_to_runner_before_execution") is not False
        or boundary.get("A186_solver_outcomes_used_before_protocol_freeze") is not False
        or boundary.get("variant_order_or_budget_changed_after_any_outcome") is not False
    ):
        raise RuntimeError("A186 frozen protocol identity gate failed")
    return protocol


def _load_anchor_gates(results_dir: Path) -> dict[str, Any]:
    result_path = results_dir / A185_FILENAME
    causal_path = results_dir / A185_CAUSAL_FILENAME
    observed = {
        "A185_result_sha256": _file_sha256(result_path),
        "A185_causal_sha256": _file_sha256(causal_path),
    }
    if observed != {
        "A185_result_sha256": A185_SHA256,
        "A185_causal_sha256": A185_CAUSAL_SHA256,
    }:
        raise RuntimeError("A186 A185 anchor hash gate failed")
    result = json.loads(result_path.read_bytes())
    execution = result.get("execution", {})
    if (
        result.get("schema") != _A185.SCHEMA
        or result.get("evidence_stage")
        != "PROSPECTIVE_CAUSAL_DIRECTION_TRANSFER_RETAINED"
        or execution.get("complete_variant_plan_executed") is not True
        or execution.get("confirmed_directional_variants") != list(PREDICTED_VARIANTS)
        or execution.get("confirmed_assignment_count") != 1
    ):
        raise RuntimeError("A186 retained A185 result gate failed")
    reader = CryptoCausalReader(causal_path)
    if (
        reader.file_sha256 != A185_CAUSAL_SHA256
        or reader.graph_sha256 != result.get("causal", {}).get("graph_sha256")
        or not reader.verify_provenance()
    ):
        raise RuntimeError("A186 retained A185 Causal gate failed")
    return {
        **observed,
        "A185_causal_graph_sha256": reader.graph_sha256,
        "A185_causal_provenance_verified": True,
        "A185_complete_variant_plan_executed": True,
        "A185_confirmed_directional_variants": list(PREDICTED_VARIANTS),
    }


def _validate_public_challenge(challenge: dict[str, Any]) -> None:
    if (
        _canonical_sha256(challenge) != PUBLIC_CHALLENGE_SHA256
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
        raise RuntimeError("A186 public challenge identity gate failed")
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
        raise RuntimeError("A186 known-material derivation gate failed")
    target = np.array(challenge["target_words"], dtype=np.uint32)
    control = np.array(challenge["control_target_words"], dtype=np.uint32)
    if (
        _sha256(target.astype("<u4").tobytes()) != challenge["target_block_sha256"]
        or _sha256(control.astype("<u4").tobytes())
        != challenge["control_target_block_sha256"]
    ):
        raise RuntimeError("A186 target byte fingerprint differs")


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
        "independent_confirmation": "NumPy_ChaCha5_all_512_output_bits",
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
        raise RuntimeError("A186 execution plan differs from freeze")
    return {
        "protocol": protocol,
        "anchor_gates": anchors,
        "public_challenge": challenge,
        "execution_plan": plan,
        "solver_execution_started": False,
    }


def _formula(variant: str, challenge: dict[str, Any], timeout_ms: int) -> str:
    old_rounds = _A185.ROUNDS
    old_variants = _A185.VARIANTS
    try:
        _A185.ROUNDS = ROUNDS
        _A185.VARIANTS = VARIANTS
        return _A185._formula(variant, challenge, timeout_ms)
    finally:
        _A185.ROUNDS = old_rounds
        _A185.VARIANTS = old_variants


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
    control = np.array(challenge["control_target_words"], dtype=np.uint32).reshape(1, 16)
    return {
        **model,
        "complete_block_match": bool(np.array_equal(output, target)),
        "control_block_match": bool(np.array_equal(output, control)),
        "output_bits_checked": 512,
        "candidate_block_sha256": _sha256(output.astype("<u4").tobytes()),
        "target_block_sha256": _sha256(target.astype("<u4").tobytes()),
        "control_target_block_sha256": _sha256(control.astype("<u4").tobytes()),
        "implementation": "independent_NumPy_ChaCha5_block",
    }


def _build_causal(path: Path, payload: dict[str, Any]) -> dict[str, Any]:
    builder = CryptoCausalBuilder(
        experiment="chacha20_smt_directional_round5_transfer",
        parameters={
            "attempt_id": ATTEMPT_ID,
            "rounds": ROUNDS,
            "unknown_key_bits": UNKNOWN_KEY_BITS,
            "variants": list(VARIANTS),
        },
    )
    ids = [
        "chacha20-a185-direction-transfer-anchor",
        "chacha20-a186-fresh-round5-challenge",
        "chacha20-a186-six-causal-formula-views",
        "chacha20-a186-complete-directional-execution",
        "chacha20-a186-independent-round-depth-transfer",
    ]
    builder.add_triplet(
        edge_id=ids[0],
        trigger="A185:retained_fresh_round4_split1_split2_transfer",
        mechanism="anchor_the_prospectively_confirmed_early_split_direction_family",
        outcome="A186:round_depth_transfer_question",
        confidence=1.0,
        evidence_kind="retained_A185_direction_transfer_anchor",
        source=A185_CAUSAL_SHA256,
        attrs={"anchor_gates": payload["anchor_gates"]},
    )
    builder.add_triplet(
        edge_id=ids[1],
        trigger="A186:round_depth_transfer_question",
        mechanism="freeze_a_fresh_round5_public_target_with_40_key_bits_omitted",
        outcome="A186:prospectively_frozen_round5_challenge",
        confidence=1.0,
        evidence_kind="pre_solver_public_challenge_freeze",
        source=PUBLIC_CHALLENGE_SHA256,
        provenance=[ids[0]],
        attrs={"public_challenge": payload["public_challenge"]},
    )
    builder.add_triplet(
        edge_id=ids[2],
        trigger="A186:prospectively_frozen_round5_challenge",
        mechanism="compile_forward_inverse_and_every_round5_midstate_cut_for_one_relation",
        outcome="A186:six_semantically_matched_causal_formula_views",
        confidence=1.0,
        evidence_kind="round_depth_direction_factorial",
        source=payload["formula_plan_sha256"],
        provenance=[ids[1]],
        attrs={"formula_plan": payload["formula_plan"]},
    )
    builder.add_triplet(
        edge_id=ids[3],
        trigger="A186:six_semantically_matched_causal_formula_views",
        mechanism="execute_every_frozen_view_sequentially_under_identical_Z3_budgets",
        outcome="A186:complete_round5_directional_frontier",
        confidence=1.0,
        evidence_kind="complete_predeclared_variant_execution",
        source=payload["execution_sha256"],
        provenance=[ids[2]],
        attrs={"execution": payload["execution"]},
    )
    builder.add_triplet(
        edge_id=ids[4],
        trigger="A186:complete_round5_directional_frontier",
        mechanism="confirm_every_SAT_model_over_all_512_bits_and_reject_the_control_target",
        outcome="A186:prospective_round_depth_direction_result",
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
        raise RuntimeError("A186 Causal provenance chain failed validation")
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
    z3_name: str,
) -> dict[str, Any]:
    analysis = analyze(results_dir)
    z3_raw = shutil.which(z3_name)
    if z3_raw is None:
        raise FileNotFoundError(f"Z3 executable not found: {z3_name}")
    z3 = Path(z3_raw)
    version = _A185._solver_version(z3)
    if version != analysis["execution_plan"]["z3_version"]:
        raise RuntimeError(f"A186 requires Z3 4.15.4, observed {version}")
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
        _A185._run_formula(
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
    if any(
        not row["complete_block_match"] or row["control_block_match"]
        for row in confirmations
    ):
        raise RuntimeError("A186 SAT-model confirmation gate failed")
    confirmed_assignments = sorted(
        {row["combined_assignment"] for row in confirmations}
    )
    confirmed_variants = [row["variant"] for row in confirmations]
    predicted_confirmed = [
        variant for variant in confirmed_variants if variant in PREDICTED_VARIANTS
    ]
    all_variants_executed = [row["variant"] for row in observations] == list(VARIANTS)
    if not all_variants_executed:
        raise RuntimeError("A186 did not execute the complete variant plan")
    if predicted_confirmed:
        evidence_stage = "PROSPECTIVE_ROUND5_CAUSAL_DIRECTION_TRANSFER_RETAINED"
    elif confirmed_variants:
        evidence_stage = "ROUND5_ALTERNATE_DIRECTIONAL_TRANSFER_RETAINED"
    else:
        evidence_stage = "ROUND5_DIRECTIONAL_SOLVER_BOUNDARY_RETAINED"
    execution = {
        "variant_order": list(VARIANTS),
        "complete_variant_plan_executed": all_variants_executed,
        "early_stop_used": False,
        "observations": observations,
        "confirmed_assignment_count": len(confirmed_assignments),
        "confirmed_assignments": confirmed_assignments,
        "confirmed_variants": confirmed_variants,
        "predicted_variants": list(PREDICTED_VARIANTS),
        "predicted_variants_confirmed": predicted_confirmed,
        "unknown_assignment_available_to_runner_before_execution": False,
    }
    payload: dict[str, Any] = {
        "schema": SCHEMA,
        "attempt_id": ATTEMPT_ID,
        "evidence_stage": evidence_stage,
        "result": (
            "Six semantically matched forward, inverse, and complete midstate-cut SMT "
            "views execute on a fresh five-round 40-bit ChaCha challenge; every SAT "
            "model is independently checked against all 512 target and control bits."
        ),
        "scope": (
            "Prospective round-depth transfer on five-round ChaCha with one full key "
            "word plus eight adjacent key bits unknown and 216 key bits known."
        ),
        "parameters": {
            "rounds": ROUNDS,
            "unknown_key_bits": UNKNOWN_KEY_BITS,
            "known_key_bits": KNOWN_KEY_BITS,
            "target_output_bits": 512,
            "variants": list(VARIANTS),
            "predicted_variants": list(PREDICTED_VARIANTS),
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
    _A185._atomic_write(output, raw)
    reader = CryptoCausalReader(causal_output)
    if (
        _sha256(output.read_bytes()) != _sha256(raw)
        or reader.file_sha256 != causal["file_sha256"]
        or not reader.verify_provenance()
    ):
        raise RuntimeError("A186 final artifact reopen gate failed")
    return {
        "json_sha256": _sha256(raw),
        "causal_sha256": reader.file_sha256,
        "causal_graph_sha256": reader.graph_sha256,
        "evidence_stage": evidence_stage,
        "statuses": {row["variant"]: row["status"] for row in observations},
        "confirmed_assignments": confirmed_assignments,
        "confirmed_variants": confirmed_variants,
        "predicted_variants_confirmed": predicted_confirmed,
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
                    "public_challenge_sha256": PUBLIC_CHALLENGE_SHA256,
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

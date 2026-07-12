#!/usr/bin/env python3
"""Prospective complete-prefix partition transfer for ChaCha7 width 18."""

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


_A190 = _import_sibling(
    "chacha20_bitwuzla_round7_width18_transfer.py",
    "chacha20_partition_a190_anchor",
)
_A188 = _A190._A188
_A185 = _A190._A185

ATTEMPT_ID = "A191"
SCHEMA = "chacha20-bitwuzla-round7-partition-transfer-v1"
PROTOCOL_SCHEMA = "chacha20-bitwuzla-round7-partition-transfer-protocol-v1"
PROTOCOL_FILENAME = "chacha20_bitwuzla_round7_partition_transfer_v1.json"
PROTOCOL_SHA256 = "4f4b9839cccde0cd23110513a83d7d6bcc186bd0113f2390c73660ccc8b9f88c"
A190_FILENAME = _A190.RESULT_FILENAME
A190_SHA256 = "f1cdad782a7ed82e893517eb2bffc1973640652bd59bcdc6a76a8ce060659220"
A190_CAUSAL_FILENAME = _A190.CAUSAL_FILENAME
A190_CAUSAL_SHA256 = "bb400fa62b338833dd7b06e98ea34840da1926315624f2d024ea80220af472f6"
PUBLIC_CHALLENGE_SHA256 = "e92258e707ee18b7209643e0dbbf7f9c2c4390381ab10dded59e945ccc835b3f"
ROUNDS = 7
UNKNOWN_KEY_BITS = 18
KNOWN_KEY_BITS = 238
PARTITION_FIXED_BITS = 3
PARTITION_FREE_BITS = 15
TIME_LIMIT_MS = 10_000
EXTERNAL_TIMEOUT_SECONDS = 15
VARIANTS = tuple(f"prefix_{value:03b}" for value in range(8))
RESULT_FILENAME = "chacha20_bitwuzla_round7_partition_transfer_v1.json"
CAUSAL_FILENAME = "chacha20_bitwuzla_round7_partition_transfer_v1.causal"


def _sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _canonical_sha256(value: Any) -> str:
    return _A190._canonical_sha256(value)


def _file_sha256(path: Path) -> str:
    return _A190._file_sha256(path)


def _load_protocol_gate() -> dict[str, Any]:
    path = Path(__file__).parents[1] / "configs" / PROTOCOL_FILENAME
    raw = path.read_bytes()
    if _sha256(raw) != PROTOCOL_SHA256:
        raise RuntimeError("A191 frozen protocol hash differs")
    protocol = json.loads(raw)
    boundary = protocol.get("information_boundary", {})
    if (
        protocol.get("schema") != PROTOCOL_SCHEMA
        or protocol.get("attempt_id") != ATTEMPT_ID
        or protocol.get("protocol_state")
        != "frozen_before_any_A191_solver_execution"
        or protocol.get("anchors", {}).get("A190", {}).get("sha256")
        != A190_SHA256
        or protocol.get("anchors", {}).get("A190", {}).get("causal_sha256")
        != A190_CAUSAL_SHA256
        or protocol.get("public_challenge_sha256") != PUBLIC_CHALLENGE_SHA256
        or protocol.get("execution_plan", {}).get("variants") != list(VARIANTS)
        or boundary.get("unknown_assignment_in_protocol_or_source") is not False
        or boundary.get("unknown_assignment_available_to_runner_before_execution")
        is not False
        or boundary.get("A191_solver_outcomes_used_before_protocol_freeze") is not False
        or boundary.get("cell_order_or_budget_changed_after_any_outcome") is not False
        or boundary.get("early_stop_permitted") is not False
    ):
        raise RuntimeError("A191 frozen protocol identity gate failed")
    return protocol


def _load_anchor_gates(results_dir: Path) -> dict[str, Any]:
    result_path = results_dir / A190_FILENAME
    causal_path = results_dir / A190_CAUSAL_FILENAME
    observed = {
        "A190_result_sha256": _file_sha256(result_path),
        "A190_causal_sha256": _file_sha256(causal_path),
    }
    if observed != {
        "A190_result_sha256": A190_SHA256,
        "A190_causal_sha256": A190_CAUSAL_SHA256,
    }:
        raise RuntimeError("A191 A190 anchor hash gate failed")
    result = json.loads(result_path.read_bytes())
    statuses = result.get("comparisons", {}).get("statuses", {})
    if (
        result.get("schema") != _A190.SCHEMA
        or result.get("evidence_stage") != "ROUND7_WIDTH18_RECOVERY_BOUNDARY_RETAINED"
        or result.get("execution", {}).get("complete_variant_plan_executed") is not True
        or result.get("execution", {}).get("returned_model_count") != 0
        or result.get("comparisons", {}).get("prospective_prediction_retained")
        is not False
        or set(statuses.values()) != {"unknown", "invalid"}
    ):
        raise RuntimeError("A191 retained A190 boundary gate failed")
    reader = CryptoCausalReader(causal_path)
    if (
        reader.file_sha256 != A190_CAUSAL_SHA256
        or reader.graph_sha256 != result.get("causal", {}).get("graph_sha256")
        or not reader.verify_provenance()
    ):
        raise RuntimeError("A191 retained A190 Causal gate failed")
    return {
        **observed,
        "A190_causal_graph_sha256": reader.graph_sha256,
        "A190_causal_provenance_verified": True,
        "A190_complete_monolithic_width18_boundary_retained": True,
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
        or challenge.get("known_key_word0_upper14", 1) & _A190.LOW_MASK
        or len(challenge.get("known_key_words_2_through_7", [])) != 6
        or len(challenge.get("nonce_words", [])) != 3
        or len(targets) != 8
        or any(len(row) != 16 for row in targets)
        or len(target_hashes) != 8
        or len(challenge.get("control_target_words", [])) != 16
        or challenge["control_target_words"][0] != (targets[0][0] ^ 1)
        or challenge["control_target_words"][1:] != targets[0][1:]
    ):
        raise RuntimeError("A191 public challenge identity gate failed")
    derived = hashlib.shake_256(
        challenge["known_material_derivation_label"].encode()
    ).digest(48)
    words = np.frombuffer(derived, dtype="<u4")
    if (
        _sha256(derived) != challenge["known_material_derivation_sha256"]
        or int(words[0]) & ~_A190.LOW_MASK
        != challenge["known_key_word0_upper14"]
        or int(words[1]) != challenge["known_key_word1"]
        or [int(value) for value in words[2:8]]
        != challenge["known_key_words_2_through_7"]
        or int(words[8]) != challenge["counter_start"]
        or [int(value) for value in words[9:12]] != challenge["nonce_words"]
    ):
        raise RuntimeError("A191 known-material derivation gate failed")
    for target, expected_hash in zip(targets, target_hashes, strict=True):
        raw = np.array(target, dtype=np.uint32).astype("<u4").tobytes()
        if _sha256(raw) != expected_hash:
            raise RuntimeError("A191 target byte fingerprint differs")
    control = np.array(challenge["control_target_words"], dtype=np.uint32)
    if _sha256(control.astype("<u4").tobytes()) != challenge[
        "control_target_block_sha256"
    ]:
        raise RuntimeError("A191 control byte fingerprint differs")


def _execution_plan() -> dict[str, Any]:
    return {
        "complete_variant_plan_required": True,
        "early_stop_used": False,
        "execution_mode": "sequential_external_solver_complete_prefix_partition",
        "external_timeout_seconds_per_cell": EXTERNAL_TIMEOUT_SECONDS,
        "formula_representation": (
            "portable_SMTLIB2_round7_split6_b1_complete_3bit_prefix_partition"
        ),
        "known_key_bits": KNOWN_KEY_BITS,
        "partition_cell_count": 8,
        "partition_cell_free_bits": PARTITION_FREE_BITS,
        "partition_fixed_bits": PARTITION_FIXED_BITS,
        "partition_prefix_order": [f"{value:03b}" for value in range(8)],
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
    match = re.fullmatch(r"prefix_([01]{3})", variant)
    if match is None:
        raise ValueError(f"unknown A191 variant {variant}")
    return int(match.group(1), 2)


def _formula(challenge: dict[str, Any], variant: str) -> str:
    base = _A190._portable_formula(challenge, "split6", 1, TIME_LIMIT_MS)
    prefix = _prefix_value(variant)
    assertion = f"(assert (= ((_ extract 17 15) k0) #b{prefix:03b}))"
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
        raise RuntimeError("A191 execution plan differs from freeze")
    formulas = {variant: _formula(challenge, variant) for variant in VARIANTS}
    formula_plan = [
        {
            "variant": variant,
            "prefix": f"{_prefix_value(variant):03b}",
            "fixed_key_coordinates": [17, 16, 15],
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
        raise RuntimeError("A191 complete partition coverage gate failed")
    return {
        "protocol": protocol,
        "anchor_gates": anchors,
        "public_challenge": challenge,
        "execution_plan": plan,
        "formulas": formulas,
        "formula_plan": formula_plan,
        "solver_execution_started": False,
    }


def _solver_gate(protocol: dict[str, Any]) -> dict[str, Any]:
    raw_path = shutil.which("bitwuzla")
    if raw_path is None:
        raise FileNotFoundError("A191 Bitwuzla executable not found")
    path = Path(raw_path)
    version = _A188._solver_version(path, "bitwuzla")
    observed_hash = _file_sha256(path)
    expected = protocol["solver_binaries"]["bitwuzla"]
    if version != expected["version"] or observed_hash != expected["executable_sha256"]:
        raise RuntimeError("A191 frozen Bitwuzla identity gate failed")
    return {
        "path": str(path),
        "version": version,
        "executable_sha256": observed_hash,
        "mode": "bitblast",
        "sat_backend": "cadical",
    }


def _run_cell(
    variant: str, formula: str, identity: dict[str, Any]
) -> dict[str, Any]:
    command = [
        identity["path"],
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
        result = subprocess.run(
            command,
            input=formula,
            text=True,
            capture_output=True,
            timeout=EXTERNAL_TIMEOUT_SECONDS,
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
        for name, raw in re.findall(
            r"\((k0|lo8)\s+#x([0-9a-fA-F]+)\)", stdout
        )
    }
    model = None
    if status == "sat":
        if set(values) != {"k0", "lo8"}:
            raise RuntimeError(f"A191 {variant} SAT model parse failed")
        if values["k0"] >> PARTITION_FREE_BITS & 0b111 != _prefix_value(variant):
            raise RuntimeError(f"A191 {variant} model violates its partition cell")
        model = {
            "key_word0": values["k0"],
            "key_word1_low_value": values["lo8"],
            "combined_assignment": (values["lo8"] << 32) | values["k0"],
            "recovered_unknown_low18": values["k0"] & _A190.LOW_MASK,
        }
    return {
        "variant": variant,
        "prefix": f"{_prefix_value(variant):03b}",
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


def _build_causal(path: Path, payload: dict[str, Any]) -> dict[str, Any]:
    builder = CryptoCausalBuilder(
        experiment="chacha20_bitwuzla_round7_partition_transfer",
        parameters={
            "attempt_id": ATTEMPT_ID,
            "rounds": ROUNDS,
            "unknown_key_bits": UNKNOWN_KEY_BITS,
            "partition_cells": len(VARIANTS),
        },
    )
    ids = [
        "chacha20-a190-monolithic-round7-boundary-anchor",
        "chacha20-a191-fresh-round7-width18-challenge",
        "chacha20-a191-complete-prefix-partition",
        "chacha20-a191-complete-cell-execution",
        "chacha20-a191-independent-model-confirmation",
        "chacha20-a191-prospective-partition-transfer",
    ]
    evidence = [
        ("A190:monolithic_round7_width18_boundary", "anchor_the_complete_open_portfolio", "A191:partition_transfer_question", "retained_A190_boundary", A190_CAUSAL_SHA256, {"anchor_gates": payload["anchor_gates"]}),
        ("A191:partition_transfer_question", "freeze_new_round7_targets_with_discarded_low18_assignment", "A191:fresh_width18_challenge", "pre_solver_public_challenge_freeze", PUBLIC_CHALLENGE_SHA256, {"public_challenge": payload["public_challenge"]}),
        ("A191:fresh_width18_challenge", "partition_bits17_to15_into_all_eight_binary_prefixes", "A191:complete_disjoint_width15_formula_cover", "assignment_free_complete_partition", payload["formula_plan_sha256"], {"formula_plan": payload["formula_plan"]}),
        ("A191:complete_disjoint_width15_formula_cover", "execute_every_cell_in_numeric_order_without_early_stop", "A191:complete_partition_execution", "complete_predeclared_cell_execution", payload["execution_sha256"], {"execution": payload["execution"]}),
        ("A191:complete_partition_execution", "recompute_each_model_over_512_target_bits_and_control", "A191:independently_confirmed_partition_models", "independent_complete_block_confirmation", payload["confirmation_sha256"], {"confirmations": payload["confirmations"]}),
        ("A191:independently_confirmed_partition_models", "apply_the_predeclared_complete_partition_success_rule", "A191:prospective_assignment_free_partition_result", "prospective_complete_partition_transfer", payload["comparison_sha256"], {"comparisons": payload["comparisons"]}),
    ]
    for index, row in enumerate(evidence):
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
    expected_provenance = [[], *[[ids[index - 1]] for index in range(1, len(ids))]]
    if (
        len(rows) != len(ids)
        or set(by_id) != set(ids)
        or [by_id[edge_id]["provenance"] for edge_id in ids] != expected_provenance
        or not reader.verify_provenance()
    ):
        raise RuntimeError("A191 Causal provenance chain failed validation")
    return {
        "stats": stats,
        "explicit_triplets": len(rows),
        "provenance_verified": True,
        "file_sha256": reader.file_sha256,
        "graph_sha256": reader.graph_sha256,
    }


def run(*, results_dir: Path, output: Path, causal_output: Path) -> dict[str, Any]:
    analysis = analyze(results_dir)
    identity = _solver_gate(analysis["protocol"])
    observations = [
        _run_cell(variant, analysis["formulas"][variant], identity)
        for variant in VARIANTS
    ]
    if [row["variant"] for row in observations] != list(VARIANTS):
        raise RuntimeError("A191 did not execute the complete cell plan")
    confirmations = [
        {
            "variant": row["variant"],
            "prefix": row["prefix"],
            **_A190._confirm_model(analysis["public_challenge"], 1, row["model"]),
        }
        for row in observations
        if row["model"] is not None
    ]
    if any(
        not row["known_key_constraints_match"]
        or not row["all_blocks_match"]
        or row["control_first_block_match"]
        or row["output_bits_checked"] != 512
        for row in confirmations
    ):
        raise RuntimeError("A191 returned model failed independent confirmation")
    recovered = sorted({row["recovered_unknown_low18"] for row in confirmations})
    prediction_retained = len(recovered) >= 1
    comparisons = {
        "complete_domain_candidate_count": sum(
            row["candidate_count"] for row in observations
        ),
        "original_domain_candidate_count": 1 << UNKNOWN_KEY_BITS,
        "partition_complete_and_disjoint_by_construction": True,
        "confirmed_variants": [row["variant"] for row in confirmations],
        "fully_confirmed_unknown_low18_assignments": recovered,
        "prospective_prediction_retained": prediction_retained,
        "statuses": {row["variant"]: row["status"] for row in observations},
    }
    evidence_stage = (
        "PROSPECTIVE_ROUND7_WIDTH18_COMPLETE_PARTITION_RECOVERY_RETAINED"
        if prediction_retained
        else "ROUND7_WIDTH18_COMPLETE_PARTITION_BOUNDARY_RETAINED"
    )
    execution = {
        "variant_order": list(VARIANTS),
        "complete_variant_plan_executed": True,
        "early_stop_used": False,
        "observations": observations,
        "returned_model_count": len(confirmations),
        "fully_confirmed_unknown_assignment_count": len(recovered),
        "fully_confirmed_unknown_low18_assignments": recovered,
        "unknown_assignment_available_to_runner_before_execution": False,
    }
    payload: dict[str, Any] = {
        "schema": SCHEMA,
        "attempt_id": ATTEMPT_ID,
        "evidence_stage": evidence_stage,
        "result": (
            "A complete assignment-free eight-cell prefix partition prospectively "
            "tests fresh seven-round ChaCha recovery over 18 unknown key bits."
        ),
        "scope": (
            "Prospective reduced ChaCha7 partial-key recovery over the unchanged "
            "2^18 candidate domain, represented as eight disjoint width-15 cells."
        ),
        "parameters": {
            "rounds": ROUNDS,
            "unknown_key_bits": UNKNOWN_KEY_BITS,
            "known_key_bits": KNOWN_KEY_BITS,
            "partition_cells": len(VARIANTS),
            "free_bits_per_cell": PARTITION_FREE_BITS,
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
        "execution_plan": analysis["execution_plan"],
        "execution_plan_sha256": _canonical_sha256(analysis["execution_plan"]),
        "solver_identity": identity,
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
        raise RuntimeError("A191 final artifact reopen gate failed")
    return {
        "json_sha256": _sha256(raw),
        "causal_sha256": reader.file_sha256,
        "causal_graph_sha256": reader.graph_sha256,
        "evidence_stage": evidence_stage,
        "statuses": comparisons["statuses"],
        "fully_confirmed_unknown_low18_assignments": recovered,
        "comparisons": comparisons,
        "output": str(output),
        "causal_output": str(causal_output),
    }


def main(argv: Sequence[str] | None = None) -> None:
    parser = argparse.ArgumentParser()
    research_root = Path(__file__).parents[1]
    parser.add_argument(
        "--results-dir", type=Path, default=research_root / "results" / "v1"
    )
    parser.add_argument("--analyze-only", action="store_true")
    parser.add_argument(
        "--output", type=Path, default=research_root / "results" / "v1" / RESULT_FILENAME
    )
    parser.add_argument(
        "--causal-output", type=Path, default=research_root / "results" / "v1" / CAUSAL_FILENAME
    )
    args = parser.parse_args(argv)
    if args.analyze_only:
        analysis = analyze(args.results_dir.resolve())
        print(
            json.dumps(
                {
                    "protocol_sha256": PROTOCOL_SHA256,
                    "public_challenge_sha256": PUBLIC_CHALLENGE_SHA256,
                    "execution_plan_sha256": _canonical_sha256(analysis["execution_plan"]),
                    "formula_plan": analysis["formula_plan"],
                    "formula_plan_sha256": _canonical_sha256(analysis["formula_plan"]),
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

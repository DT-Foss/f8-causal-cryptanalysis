#!/usr/bin/env python3
"""Prospective Bitwuzla ChaCha7 recovery over 18 unknown key bits."""

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


_A189 = _import_sibling(
    "chacha20_bitwuzla_round6_width20_transfer.py",
    "chacha20_round7_a189_anchor",
)
_A188 = _A189._A188
_A187 = _A189._A187
_A185 = _A189._A185
_A119 = _A189._A119

ATTEMPT_ID = "A190"
SCHEMA = "chacha20-bitwuzla-round7-width18-transfer-v1"
PROTOCOL_SCHEMA = "chacha20-bitwuzla-round7-width18-transfer-protocol-v1"
PROTOCOL_FILENAME = "chacha20_bitwuzla_round7_width18_transfer_v1.json"
PROTOCOL_SHA256 = "27c810f2086b0cb8e365126fac7be4d086a134511427362f65dbb216eb914a3b"
A189_FILENAME = _A189.RESULT_FILENAME
A189_SHA256 = "e57294c1aabf29f2e8fff87b9b06f0ed1ab0d8392cc9ea79f4f97745904e6b70"
A189_CAUSAL_FILENAME = _A189.CAUSAL_FILENAME
A189_CAUSAL_SHA256 = "bebcd7805592cd28805e7226c1efa216696544539605693dc197b88a70e44a37"
PUBLIC_CHALLENGE_SHA256 = "dc1f9ac9b0d3f488d98d3712219dbe3fa370152f6194e1e4644a273ba247d836"
ROUNDS = 7
UNKNOWN_KEY_BITS = 18
KNOWN_KEY_BITS = 238
LOW_MASK = (1 << UNKNOWN_KEY_BITS) - 1
VARIANTS = (
    "bitwuzla_bitblast_split6_b1",
    "bitwuzla_bitblast_split6_b2",
    "bitwuzla_bitblast_split6_b4",
    "bitwuzla_bitblast_split6_b8",
    "bitwuzla_preprop_split6_b1",
    "bitwuzla_prop_split6_b1",
    "bitwuzla_bitblast_split5_b1",
    "z3_bitblast_split6_b1",
    "boolector_fun_split6_b1",
)
RESULT_FILENAME = "chacha20_bitwuzla_round7_width18_transfer_v1.json"
CAUSAL_FILENAME = "chacha20_bitwuzla_round7_width18_transfer_v1.causal"


def _sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _canonical_sha256(value: Any) -> str:
    return _A189._canonical_sha256(value)


def _file_sha256(path: Path) -> str:
    return _A189._file_sha256(path)


def _load_protocol_gate() -> dict[str, Any]:
    path = Path(__file__).parents[1] / "configs" / PROTOCOL_FILENAME
    raw = path.read_bytes()
    if _sha256(raw) != PROTOCOL_SHA256:
        raise RuntimeError("A190 frozen protocol hash differs")
    protocol = json.loads(raw)
    boundary = protocol.get("information_boundary", {})
    if (
        protocol.get("schema") != PROTOCOL_SCHEMA
        or protocol.get("attempt_id") != ATTEMPT_ID
        or protocol.get("protocol_state")
        != "frozen_before_any_A190_solver_execution"
        or protocol.get("anchors", {}).get("A189", {}).get("sha256")
        != A189_SHA256
        or protocol.get("anchors", {}).get("A189", {}).get("causal_sha256")
        != A189_CAUSAL_SHA256
        or protocol.get("public_challenge_sha256") != PUBLIC_CHALLENGE_SHA256
        or protocol.get("execution_plan", {}).get("variants") != list(VARIANTS)
        or boundary.get("unknown_assignment_in_protocol_or_source") is not False
        or boundary.get("unknown_assignment_available_to_runner_before_execution")
        is not False
        or boundary.get("A190_solver_outcomes_used_before_protocol_freeze") is not False
        or boundary.get("variant_order_or_budget_changed_after_any_outcome") is not False
        or boundary.get("early_stop_permitted") is not False
    ):
        raise RuntimeError("A190 frozen protocol identity gate failed")
    return protocol


def _load_anchor_gates(results_dir: Path) -> dict[str, Any]:
    result_path = results_dir / A189_FILENAME
    causal_path = results_dir / A189_CAUSAL_FILENAME
    observed = {
        "A189_result_sha256": _file_sha256(result_path),
        "A189_causal_sha256": _file_sha256(causal_path),
    }
    if observed != {
        "A189_result_sha256": A189_SHA256,
        "A189_causal_sha256": A189_CAUSAL_SHA256,
    }:
        raise RuntimeError("A190 A189 anchor hash gate failed")
    result = json.loads(result_path.read_bytes())
    confirmations = result.get("confirmations", [])
    if (
        result.get("schema") != _A189.SCHEMA
        or result.get("evidence_stage")
        != "PROSPECTIVE_BITWUZLA_ROUND6_20BIT_RECOVERY_TRANSFER_RETAINED"
        or result.get("execution", {}).get("complete_variant_plan_executed") is not True
        or result.get("comparisons", {}).get("prospective_prediction_retained")
        is not True
        or result.get("execution", {}).get(
            "fully_confirmed_unknown_low20_assignments"
        )
        != [457328]
        or not any(
            row.get("variant") == "bitwuzla_bitblast_b8"
            and row.get("all_blocks_match") is True
            and row.get("output_bits_checked") == 4096
            and row.get("control_first_block_match") is False
            for row in confirmations
        )
    ):
        raise RuntimeError("A190 retained A189 recovery gate failed")
    reader = CryptoCausalReader(causal_path)
    if (
        reader.file_sha256 != A189_CAUSAL_SHA256
        or reader.graph_sha256 != result.get("causal", {}).get("graph_sha256")
        or not reader.verify_provenance()
    ):
        raise RuntimeError("A190 retained A189 Causal gate failed")
    return {
        **observed,
        "A189_causal_graph_sha256": reader.graph_sha256,
        "A189_causal_provenance_verified": True,
        "A189_prospective_round6_width20_recovery_retained": True,
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
        or challenge.get("known_key_word0_upper14", 1) & LOW_MASK
        or len(challenge.get("known_key_words_2_through_7", [])) != 6
        or len(challenge.get("nonce_words", [])) != 3
        or len(targets) != 8
        or any(len(row) != 16 for row in targets)
        or len(target_hashes) != 8
        or len(challenge.get("control_target_words", [])) != 16
        or challenge["control_target_words"][0] != (targets[0][0] ^ 1)
        or challenge["control_target_words"][1:] != targets[0][1:]
    ):
        raise RuntimeError("A190 public challenge identity gate failed")
    derived = hashlib.shake_256(
        challenge["known_material_derivation_label"].encode()
    ).digest(48)
    words = np.frombuffer(derived, dtype="<u4")
    if (
        _sha256(derived) != challenge["known_material_derivation_sha256"]
        or int(words[0]) & ~LOW_MASK != challenge["known_key_word0_upper14"]
        or int(words[1]) != challenge["known_key_word1"]
        or [int(value) for value in words[2:8]]
        != challenge["known_key_words_2_through_7"]
        or int(words[8]) != challenge["counter_start"]
        or [int(value) for value in words[9:12]] != challenge["nonce_words"]
    ):
        raise RuntimeError("A190 known-material derivation gate failed")
    for target, expected_hash in zip(targets, target_hashes, strict=True):
        raw = np.array(target, dtype=np.uint32).astype("<u4").tobytes()
        if _sha256(raw) != expected_hash:
            raise RuntimeError("A190 target byte fingerprint differs")
    control = np.array(challenge["control_target_words"], dtype=np.uint32)
    if _sha256(control.astype("<u4").tobytes()) != challenge[
        "control_target_block_sha256"
    ]:
        raise RuntimeError("A190 control byte fingerprint differs")


def _execution_plan(protocol: dict[str, Any]) -> dict[str, Any]:
    frozen = protocol["execution_plan"]
    return {
        "complete_variant_plan_required": True,
        "early_stop_used": False,
        "execution_mode": "sequential_external_solver_portfolio",
        "external_timeout_seconds_by_variant": frozen[
            "external_timeout_seconds_by_variant"
        ],
        "formula_representation": (
            "portable_SMTLIB2_round7_split5_split6_shared_define_fun_DAG"
        ),
        "known_key_bits": KNOWN_KEY_BITS,
        "primitive": "ChaCha20_block_function",
        "rounds": ROUNDS,
        "solver_time_limit_milliseconds_by_variant": frozen[
            "solver_time_limit_milliseconds_by_variant"
        ],
        "target_output_bits_per_block": 512,
        "unknown_assignment_available_to_runner_before_execution": False,
        "unknown_key_bits": UNKNOWN_KEY_BITS,
        "variant_execution_order": list(VARIANTS),
        "variants": list(VARIANTS),
    }


def _variant_spec(variant: str) -> dict[str, Any]:
    match = re.fullmatch(
        r"bitwuzla_(bitblast|preprop|prop)_(split5|split6)_b(1|2|4|8)",
        variant,
    )
    if match is not None:
        mode, cut, raw_blocks = match.groups()
        return {
            "engine": "bitwuzla",
            "mode": mode,
            "cut": cut,
            "block_count": int(raw_blocks),
        }
    match = re.fullmatch(
        r"(z3_bitblast|boolector_fun)_(split5|split6)_b(1|2|4|8)",
        variant,
    )
    if match is None:
        raise ValueError(f"unknown A190 variant {variant}")
    engine_mode, cut, raw_blocks = match.groups()
    engine, mode = engine_mode.split("_", 1)
    return {
        "engine": engine,
        "mode": mode,
        "cut": cut,
        "block_count": int(raw_blocks),
    }


def _block_challenges(challenge: dict[str, Any]) -> list[dict[str, Any]]:
    key1 = challenge["known_key_word1"]
    return [
        {
            "rounds": ROUNDS,
            "known_key_word1_upper24": key1 & 0xFFFFFF00,
            "known_key_words_2_through_7": challenge[
                "known_key_words_2_through_7"
            ],
            "counter": (challenge["counter_start"] + index) & 0xFFFFFFFF,
            "nonce_words": challenge["nonce_words"],
            "target_words": target,
        }
        for index, target in enumerate(challenge["target_words"])
    ]


def _single_formula(cut: str, block: dict[str, Any], timeout_ms: int) -> str:
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
        )
        return _A185._formula(cut, block, timeout_ms)
    finally:
        _A185.ROUNDS = old_rounds
        _A185.VARIANTS = old_variants


def _portable_formula(
    challenge: dict[str, Any], cut: str, block_count: int, timeout_ms: int
) -> str:
    blocks = _block_challenges(challenge)[:block_count]
    parsed = [
        _A187._split_formula(_single_formula(cut, block, timeout_ms))
        for block in blocks
    ]
    header = [
        line for line in parsed[0][0] if not line.startswith("(set-option :timeout ")
    ]
    k0_index = header.index("(declare-fun k0 () (_ BitVec 32))")
    lo8_index = header.index("(declare-fun lo8 () (_ BitVec 8))")
    header[k0_index], header[lo8_index] = header[lo8_index], header[k0_index]
    lines = header
    lines.append(f"(assert (= lo8 #x{challenge['known_key_word1'] & 0xFF:02x}))")
    upper14 = challenge["known_key_word0_upper14"] >> UNKNOWN_KEY_BITS
    lines.append(
        "(assert (= ((_ extract 31 18) k0) " f"#b{upper14:014b}))"
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
        raise RuntimeError("A190 execution plan differs from freeze")
    formulas: dict[str, str] = {}
    formula_plan = []
    for variant in VARIANTS:
        spec = _variant_spec(variant)
        timeout_ms = plan["solver_time_limit_milliseconds_by_variant"][variant]
        formula = _portable_formula(
            challenge, spec["cut"], spec["block_count"], timeout_ms
        )
        formulas[variant] = formula
        formula_plan.append(
            {
                "variant": variant,
                **spec,
                "logical_unknown_key_bits": UNKNOWN_KEY_BITS,
                "observed_relation_bits": spec["block_count"] * 512,
                "bytes": len(formula.encode()),
                "sha256": _sha256(formula.encode()),
                "declaration_order": ["lo8", "k0"],
                "block_definition_order": list(
                    reversed(range(spec["block_count"]))
                ),
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
    spec = _variant_spec(variant)
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
        for name, raw in re.findall(
            r"\((k0|lo8)\s+#x([0-9a-fA-F]+)\)", stdout
        )
    }
    model = None
    if status == "sat":
        if set(values) != {"k0", "lo8"}:
            raise RuntimeError(f"A190 {variant} SAT model parse failed")
        model = {
            "key_word0": values["k0"],
            "key_word1_low_value": values["lo8"],
            "combined_assignment": (values["lo8"] << 32) | values["k0"],
            "recovered_unknown_low18": values["k0"] & LOW_MASK,
        }
    statistics = {
        key: int(float(value))
        for key, value in re.findall(r":([\w-]+)\s+([0-9.]+)", stdout)
        if key in {"rlimit-count", "sat-conflicts", "sat-decisions"}
    }
    return {
        "variant": variant,
        **_variant_spec(variant),
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
        model["key_word0"] & ~LOW_MASK
        == challenge["known_key_word0_upper14"]
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
        "implementation": "independent_NumPy_ChaCha7_blocks",
    }


def _build_causal(path: Path, payload: dict[str, Any]) -> dict[str, Any]:
    builder = CryptoCausalBuilder(
        experiment="chacha20_bitwuzla_round7_width18_transfer",
        parameters={
            "attempt_id": ATTEMPT_ID,
            "rounds": ROUNDS,
            "unknown_key_bits": UNKNOWN_KEY_BITS,
            "variants": list(VARIANTS),
        },
    )
    ids = [
        "chacha20-a189-round6-width20-recovery-anchor",
        "chacha20-a190-fresh-round7-width18-challenge",
        "chacha20-a190-round7-cut-block-formula-family",
        "chacha20-a190-complete-solver-portfolio",
        "chacha20-a190-independent-round7-confirmation",
        "chacha20-a190-prospective-depth-width-transfer",
    ]
    rows = [
        (
            "A189:prospective_round6_width20_recovery",
            "anchor_the_independently_confirmed_round6_model",
            "A190:round7_width_transfer_question",
            "retained_A189_recovery_anchor",
            A189_CAUSAL_SHA256,
            {"anchor_gates": payload["anchor_gates"]},
        ),
        (
            "A190:round7_width_transfer_question",
            "freeze_eight_round7_targets_with_one_discarded_low18_assignment",
            "A190:prospectively_frozen_round7_width18_challenge",
            "pre_solver_public_challenge_freeze",
            PUBLIC_CHALLENGE_SHA256,
            {"public_challenge": payload["public_challenge"]},
        ),
        (
            "A190:prospectively_frozen_round7_width18_challenge",
            "compile_split5_split6_DAGs_across_frozen_block_counts",
            "A190:portable_round7_cut_block_formula_family",
            "portable_SMTLIB2_formula_binding",
            payload["formula_plan_sha256"],
            {"formula_plan": payload["formula_plan"]},
        ),
        (
            "A190:portable_round7_cut_block_formula_family",
            "execute_all_nine_frozen_views_without_early_stop",
            "A190:complete_round7_solver_frontier",
            "complete_predeclared_portfolio_execution",
            payload["execution_sha256"],
            {"execution": payload["execution"]},
        ),
        (
            "A190:complete_round7_solver_frontier",
            "recompute_every_model_over_all_constituent_blocks_and_control",
            "A190:independently_confirmed_round7_models",
            "independent_complete_block_confirmation",
            payload["confirmation_sha256"],
            {"confirmations": payload["confirmations"]},
        ),
        (
            "A190:independently_confirmed_round7_models",
            "apply_the_predeclared_split6_b1_success_rule",
            "A190:prospective_round7_depth_width_result",
            "prospective_depth_width_transfer",
            payload["comparison_sha256"],
            {"comparisons": payload["comparisons"]},
        ),
    ]
    for index, (trigger, mechanism, outcome, kind, source, attrs) in enumerate(rows):
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
    observed = reader.triplets(include_inferred=False)
    by_id = {row["edge_id"]: row for row in observed}
    if (
        len(observed) != len(ids)
        or set(by_id) != set(ids)
        or not reader.verify_provenance()
        or [by_id[edge_id]["provenance"] for edge_id in ids]
        != [[], *[[ids[index - 1]] for index in range(1, len(ids))]]
    ):
        raise RuntimeError("A190 Causal provenance chain failed validation")
    return {
        "stats": stats,
        "explicit_triplets": len(observed),
        "provenance_verified": True,
        "file_sha256": reader.file_sha256,
        "graph_sha256": reader.graph_sha256,
    }


def run(*, results_dir: Path, output: Path, causal_output: Path) -> dict[str, Any]:
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
        raise RuntimeError("A190 returned model failed independent confirmation")
    if [row["variant"] for row in observations] != list(VARIANTS):
        raise RuntimeError("A190 did not execute the complete variant plan")
    by_variant = {row["variant"]: row for row in confirmations}
    predicted = by_variant.get("bitwuzla_bitblast_split6_b1")
    prediction_retained = (
        predicted is not None
        and predicted["all_blocks_match"]
        and not predicted["control_first_block_match"]
        and predicted["output_bits_checked"] == 512
    )
    recovered_unknown = sorted(
        {row["recovered_unknown_low18"] for row in confirmations}
    )
    comparisons = {
        "predicted_variant": "bitwuzla_bitblast_split6_b1",
        "predicted_variant_confirmed": prediction_retained,
        "prospective_prediction_retained": prediction_retained,
        "fully_confirmed_unknown_low18_assignments": recovered_unknown,
        "confirmed_variants": [row["variant"] for row in confirmations],
        "statuses": {row["variant"]: row["status"] for row in observations},
    }
    evidence_stage = (
        "PROSPECTIVE_BITWUZLA_ROUND7_18BIT_RECOVERY_TRANSFER_RETAINED"
        if prediction_retained
        else "ROUND7_WIDTH18_RECOVERY_BOUNDARY_RETAINED"
    )
    execution = {
        "variant_order": list(VARIANTS),
        "complete_variant_plan_executed": True,
        "early_stop_used": False,
        "observations": observations,
        "returned_model_count": len(confirmations),
        "fully_confirmed_unknown_assignment_count": len(recovered_unknown),
        "fully_confirmed_unknown_low18_assignments": recovered_unknown,
        "unknown_assignment_available_to_runner_before_execution": False,
    }
    payload: dict[str, Any] = {
        "schema": SCHEMA,
        "attempt_id": ATTEMPT_ID,
        "evidence_stage": evidence_stage,
        "result": (
            "A frozen portable SMT-LIB2 portfolio prospectively tests the "
            "shared-key Bitwuzla reader at seven-round ChaCha over 18 unknown key bits."
        ),
        "scope": (
            "Prospective reduced seven-round ChaCha partial-key recovery with the "
            "low 18 bits of key word zero unknown and 238 key bits known."
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
            "prospective_prediction": analysis["protocol"][
                "prospective_prediction"
            ],
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
        raise RuntimeError("A190 final artifact reopen gate failed")
    return {
        "json_sha256": _sha256(raw),
        "causal_sha256": reader.file_sha256,
        "causal_graph_sha256": reader.graph_sha256,
        "evidence_stage": evidence_stage,
        "statuses": {row["variant"]: row["status"] for row in observations},
        "fully_confirmed_unknown_low18_assignments": recovered_unknown,
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
        "--output",
        type=Path,
        default=research_root / "results" / "v1" / RESULT_FILENAME,
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

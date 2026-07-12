#!/usr/bin/env python3
"""Prospective shared-key multiblock ChaCha5 causal-stacking transfer."""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import re
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


_A186 = _import_sibling(
    "chacha20_smt_directional_round5_transfer.py",
    "chacha20_multiblock_a186_anchor",
)
_A185 = _A186._A185
_A119 = _A186._A119

ATTEMPT_ID = "A187"
SCHEMA = "chacha20-smt-shared-key-multiblock-transfer-v1"
PROTOCOL_SCHEMA = "chacha20-smt-shared-key-multiblock-transfer-protocol-v1"
PROTOCOL_FILENAME = "chacha20_smt_shared_key_multiblock_transfer_v1.json"
PROTOCOL_SHA256 = "ec9aa11875462f1220a118c9e50ae82f14ef55d45847791a772b62d4c58f6a62"
A186_FILENAME = _A186.RESULT_FILENAME
A186_SHA256 = "c47722b6110bfdac9b4688454235339cdb7f297011b1e6c7f959a0c947e4a953"
A186_CAUSAL_FILENAME = _A186.CAUSAL_FILENAME
A186_CAUSAL_SHA256 = "043f2b52fd13ca8298f713e374edd1aaa720c7748daf0a4b6c39453b32dff62a"
PUBLIC_CHALLENGE_SHA256 = "4ac8ea6d3f6fd61d3877fd63558e18dd3667fab700d74cc1637101c22193eb6c"
ROUNDS = 5
UNKNOWN_KEY_BITS = 40
KNOWN_KEY_BITS = 216
RLIMIT = 10_000_000
VARIANTS = (
    "split4_full_b1",
    "split4_full_b2",
    "split4_full_b4",
    "split4_full_b8",
    "split4_sparse512_b2",
    "split4_sparse512_b4",
    "split4_sparse512_b8",
    "forward_delta_b2",
    "forward_delta_b4",
    "forward_delta_b8",
)
RESULT_FILENAME = "chacha20_smt_shared_key_multiblock_transfer_v1.json"
CAUSAL_FILENAME = "chacha20_smt_shared_key_multiblock_transfer_v1.causal"


def _sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _canonical_sha256(value: Any) -> str:
    return _A186._canonical_sha256(value)


def _file_sha256(path: Path) -> str:
    return _A186._file_sha256(path)


def _load_protocol_gate() -> dict[str, Any]:
    path = Path(__file__).parents[1] / "configs" / PROTOCOL_FILENAME
    raw = path.read_bytes()
    if _sha256(raw) != PROTOCOL_SHA256:
        raise RuntimeError("A187 frozen protocol hash differs")
    protocol = json.loads(raw)
    boundary = protocol.get("information_boundary", {})
    if (
        protocol.get("schema") != PROTOCOL_SCHEMA
        or protocol.get("attempt_id") != ATTEMPT_ID
        or protocol.get("protocol_state") != "frozen_before_any_A187_solver_execution"
        or protocol.get("anchors", {}).get("A186", {}).get("sha256") != A186_SHA256
        or protocol.get("anchors", {}).get("A186", {}).get("causal_sha256")
        != A186_CAUSAL_SHA256
        or protocol.get("public_challenge_sha256") != PUBLIC_CHALLENGE_SHA256
        or protocol.get("execution_plan", {}).get("variants") != list(VARIANTS)
        or boundary.get("unknown_assignment_in_protocol_or_source") is not False
        or boundary.get("unknown_assignment_available_to_runner_before_execution") is not False
        or boundary.get("A187_solver_outcomes_used_before_protocol_freeze") is not False
        or boundary.get("variant_order_or_budget_changed_after_any_outcome") is not False
    ):
        raise RuntimeError("A187 frozen protocol identity gate failed")
    return protocol


def _load_anchor_gates(results_dir: Path) -> dict[str, Any]:
    result_path = results_dir / A186_FILENAME
    causal_path = results_dir / A186_CAUSAL_FILENAME
    observed = {
        "A186_result_sha256": _file_sha256(result_path),
        "A186_causal_sha256": _file_sha256(causal_path),
    }
    if observed != {
        "A186_result_sha256": A186_SHA256,
        "A186_causal_sha256": A186_CAUSAL_SHA256,
    }:
        raise RuntimeError("A187 A186 anchor hash gate failed")
    result = json.loads(result_path.read_bytes())
    observations = result.get("execution", {}).get("observations", [])
    if (
        result.get("schema") != _A186.SCHEMA
        or result.get("evidence_stage") != "ROUND5_DIRECTIONAL_SOLVER_BOUNDARY_RETAINED"
        or result.get("execution", {}).get("complete_variant_plan_executed") is not True
        or [row.get("status") for row in observations] != ["unknown"] * 6
        or result.get("execution", {}).get("confirmed_assignment_count") != 0
    ):
        raise RuntimeError("A187 retained A186 result gate failed")
    reader = CryptoCausalReader(causal_path)
    if (
        reader.file_sha256 != A186_CAUSAL_SHA256
        or reader.graph_sha256 != result.get("causal", {}).get("graph_sha256")
        or not reader.verify_provenance()
    ):
        raise RuntimeError("A187 retained A186 Causal gate failed")
    return {
        **observed,
        "A186_causal_graph_sha256": reader.graph_sha256,
        "A186_causal_provenance_verified": True,
        "A186_complete_six_view_plan_executed": True,
        "A186_status_vector": ["unknown"] * 6,
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
        raise RuntimeError("A187 public challenge identity gate failed")
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
        raise RuntimeError("A187 known-material derivation gate failed")
    for target, expected_hash in zip(targets, target_hashes, strict=True):
        raw = np.array(target, dtype=np.uint32).astype("<u4").tobytes()
        if _sha256(raw) != expected_hash:
            raise RuntimeError("A187 target byte fingerprint differs")
    control = np.array(challenge["control_target_words"], dtype=np.uint32)
    if (
        _sha256(control.astype("<u4").tobytes())
        != challenge["control_target_block_sha256"]
    ):
        raise RuntimeError("A187 control byte fingerprint differs")


def _execution_plan() -> dict[str, Any]:
    return {
        "primitive": "ChaCha20_block_function",
        "rounds": ROUNDS,
        "unknown_key_bits": UNKNOWN_KEY_BITS,
        "known_key_bits": KNOWN_KEY_BITS,
        "target_output_bits_per_block": 512,
        "variants": list(VARIANTS),
        "variant_execution_order": list(VARIANTS),
        "execution_mode": "sequential_one_thread_external_Z3_fixed_rlimit",
        "z3_version": "4.15.4",
        "z3_rlimit_per_variant": RLIMIT,
        "timeout_milliseconds_per_variant": 30_000,
        "external_timeout_seconds_per_variant": 40,
        "formula_representation": "shared_define_fun_DAG_with_block_prefixes",
        "solver_tactic": "simplify_then_solve_eqs_then_bit_blast_then_sat",
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


def _split_formula(formula: str) -> tuple[list[str], list[str], list[str]]:
    lines = formula.splitlines()
    start = next(index for index, line in enumerate(lines) if line.startswith("(define-fun v"))
    stop = lines.index("(check-sat)")
    body = lines[start:stop]
    return (
        lines[:start],
        [line for line in body if line.startswith("(define-fun v")],
        [line for line in body if line.startswith("(assert")],
    )


def _rename_block(lines: Sequence[str], block_index: int) -> list[str]:
    return [
        re.sub(r"\bv(\d+)\b", rf"b{block_index}_v\1", line)
        for line in lines
    ]


def _prepared_header(header: list[str]) -> list[str]:
    prepared = header.copy()
    k0_index = prepared.index("(declare-fun k0 () (_ BitVec 32))")
    lo8_index = prepared.index("(declare-fun lo8 () (_ BitVec 8))")
    prepared[k0_index], prepared[lo8_index] = prepared[lo8_index], prepared[k0_index]
    prepared.insert(1, f"(set-option :rlimit {RLIMIT})")
    return prepared


def _variant_spec(variant: str) -> tuple[str, int]:
    match = re.fullmatch(r"(split4_full|split4_sparse512|forward_delta)_b(\d+)", variant)
    if match is None:
        raise ValueError(f"unknown A187 variant {variant}")
    family, raw_blocks = match.groups()
    return family, int(raw_blocks)


def _formula(
    variant: str,
    challenge: dict[str, Any],
    timeout_ms: int,
) -> tuple[str, dict[str, Any]]:
    family, block_count = _variant_spec(variant)
    blocks = _block_challenges(challenge)[:block_count]
    direction = "forward" if family == "forward_delta" else "split4"
    parsed = [
        _split_formula(_A186._formula(direction, block, timeout_ms))
        for block in blocks
    ]
    lines = _prepared_header(parsed[0][0])
    lane_schedule: list[list[int]] | None = None
    if family in {"split4_full", "split4_sparse512"}:
        if family == "split4_sparse512":
            words_per_block = 16 // block_count
            lane_schedule = [
                list(range(index * words_per_block, (index + 1) * words_per_block))
                for index in range(block_count)
            ]
        for block_index in reversed(range(block_count)):
            _, definitions, assertions = parsed[block_index]
            selected = assertions
            if lane_schedule is not None:
                selected = [assertions[lane] for lane in lane_schedule[block_index]]
            lines.extend(_rename_block([*definitions, *selected], block_index))
    else:
        renamed_definitions: list[list[str]] = []
        renamed_left: list[list[str]] = []
        for block_index, (_, definitions, assertions) in enumerate(parsed):
            renamed_definitions.append(_rename_block(definitions, block_index))
            left_expressions = []
            for assertion in _rename_block(assertions, block_index):
                prefix = "(assert (= "
                if not assertion.startswith(prefix) or not assertion.endswith("))"):
                    raise RuntimeError("A187 forward assertion parse failed")
                expression, _ = assertion[len(prefix) : -2].rsplit(" #x", 1)
                left_expressions.append(expression)
            renamed_left.append(left_expressions)
        for definitions in renamed_definitions:
            lines.extend(definitions)
        for block_index in range(1, block_count):
            for lane in range(16):
                expected = (
                    blocks[block_index]["target_words"][lane]
                    - blocks[0]["target_words"][lane]
                ) & 0xFFFFFFFF
                lines.append(
                    f"(assert (= (bvsub {renamed_left[block_index][lane]} "
                    f"{renamed_left[0][lane]}) #x{expected:08x}))"
                )
    lines.extend(
        [
            "(check-sat-using (then simplify solve-eqs bit-blast sat))",
            "(get-value (k0 lo8))",
        ]
    )
    observed_bits = (
        block_count * 512
        if family == "split4_full"
        else 512
        if family == "split4_sparse512"
        else (block_count - 1) * 512
    )
    metadata = {
        "variant": variant,
        "family": family,
        "direction": direction,
        "block_count": block_count,
        "observed_relation_bits": observed_bits,
        "lane_schedule": lane_schedule,
        "block_definition_order": (
            list(reversed(range(block_count)))
            if family != "forward_delta"
            else list(range(block_count))
        ),
        "declaration_order": ["lo8", "k0"],
        "rlimit": RLIMIT,
    }
    return "\n".join(lines) + "\n", metadata


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
        raise RuntimeError("A187 execution plan differs from freeze")
    formulas_and_metadata = {
        variant: _formula(variant, challenge, plan["timeout_milliseconds_per_variant"])
        for variant in VARIANTS
    }
    formula_plan = [
        {
            **formulas_and_metadata[variant][1],
            "bytes": len(formulas_and_metadata[variant][0].encode()),
            "sha256": _sha256(formulas_and_metadata[variant][0].encode()),
        }
        for variant in VARIANTS
    ]
    return {
        "protocol": protocol,
        "anchor_gates": anchors,
        "public_challenge": challenge,
        "execution_plan": plan,
        "formulas": {
            variant: formulas_and_metadata[variant][0] for variant in VARIANTS
        },
        "formula_plan": formula_plan,
        "solver_execution_started": False,
    }


def _confirm_model(
    challenge: dict[str, Any],
    block_count: int,
    model: dict[str, int],
) -> dict[str, Any]:
    matches = []
    candidate_hashes = []
    for block in _block_challenges(challenge)[:block_count]:
        initial = np.zeros((1, 16), dtype=np.uint32)
        initial[0, :4] = _A119.CONSTANTS
        initial[0, 4] = np.uint32(model["key_word0"])
        initial[0, 5] = np.uint32(
            challenge["known_key_word1_upper24"] | model["key_word1_low_value"]
        )
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
        "block_count_checked": block_count,
        "block_matches": matches,
        "all_blocks_match": all(matches),
        "candidate_block_sha256": candidate_hashes,
        "control_first_block_match": candidate_hashes[0]
        == challenge["control_target_block_sha256"],
        "output_bits_checked": block_count * 512,
        "implementation": "independent_NumPy_ChaCha5_blocks",
    }


def _build_causal(path: Path, payload: dict[str, Any]) -> dict[str, Any]:
    builder = CryptoCausalBuilder(
        experiment="chacha20_smt_shared_key_multiblock_transfer",
        parameters={
            "attempt_id": ATTEMPT_ID,
            "rounds": ROUNDS,
            "unknown_key_bits": UNKNOWN_KEY_BITS,
            "variants": list(VARIANTS),
        },
    )
    ids = [
        "chacha20-a186-round5-single-block-boundary",
        "chacha20-a187-fresh-eight-block-challenge",
        "chacha20-a187-stacking-compression-delta-formulas",
        "chacha20-a187-fixed-rlimit-complete-execution",
        "chacha20-a187-prospective-search-shape-transfer",
        "chacha20-a187-independent-model-confirmation",
    ]
    builder.add_triplet(
        edge_id=ids[0],
        trigger="A186:fresh_round5_single_block_six_view_boundary",
        mechanism="retain_the_exact_40_bit_single_block_frontier",
        outcome="A187:shared_key_observation_question",
        confidence=1.0,
        evidence_kind="retained_A186_boundary_anchor",
        source=A186_CAUSAL_SHA256,
        attrs={"anchor_gates": payload["anchor_gates"]},
    )
    builder.add_triplet(
        edge_id=ids[1],
        trigger="A187:shared_key_observation_question",
        mechanism="freeze_eight_fresh_counter_related_targets_with_one_hidden_assignment",
        outcome="A187:prospectively_frozen_shared_key_challenge",
        confidence=1.0,
        evidence_kind="pre_solver_multiblock_freeze",
        source=PUBLIC_CHALLENGE_SHA256,
        provenance=[ids[0]],
        attrs={"public_challenge": payload["public_challenge"]},
    )
    builder.add_triplet(
        edge_id=ids[2],
        trigger="A187:prospectively_frozen_shared_key_challenge",
        mechanism="compile_full_sparse_fixed_information_and_modular_delta_views",
        outcome="A187:ten_semantically_scoped_multiblock_formulas",
        confidence=1.0,
        evidence_kind="causal_observation_encoding_factorial",
        source=payload["formula_plan_sha256"],
        provenance=[ids[1]],
        attrs={"formula_plan": payload["formula_plan"]},
    )
    builder.add_triplet(
        edge_id=ids[3],
        trigger="A187:ten_semantically_scoped_multiblock_formulas",
        mechanism="execute_every_view_at_identical_fixed_Z3_rlimit_without_early_stop",
        outcome="A187:complete_fixed_resource_frontier",
        confidence=1.0,
        evidence_kind="complete_predeclared_variant_execution",
        source=payload["execution_sha256"],
        provenance=[ids[2]],
        attrs={"execution": payload["execution"]},
    )
    builder.add_triplet(
        edge_id=ids[4],
        trigger="A187:complete_fixed_resource_frontier",
        mechanism="compare_predeclared_decision_and_conflict_inequalities",
        outcome="A187:prospective_shared_key_search_shape_result",
        confidence=1.0,
        evidence_kind="prospective_causal_stacking_transfer",
        source=payload["comparison_sha256"],
        provenance=[ids[3]],
        attrs={"comparisons": payload["comparisons"]},
    )
    builder.add_triplet(
        edge_id=ids[5],
        trigger="A187:prospective_shared_key_search_shape_result",
        mechanism="recompute_every_returned_model_over_each_constituent_512_bit_block",
        outcome="A187:independently_checked_multiblock_models",
        confidence=1.0,
        evidence_kind="independent_complete_block_confirmation",
        source=payload["confirmation_sha256"],
        provenance=[ids[4]],
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
        != [[], [ids[0]], [ids[1]], [ids[2]], [ids[3]], [ids[4]]]
    ):
        raise RuntimeError("A187 Causal provenance chain failed validation")
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
        raise RuntimeError(f"A187 requires Z3 4.15.4, observed {version}")
    metadata = {row["variant"]: row for row in analysis["formula_plan"]}
    observations = [
        _A185._run_formula(
            z3,
            variant,
            analysis["formulas"][variant],
            analysis["execution_plan"]["external_timeout_seconds_per_variant"],
        )
        for variant in VARIANTS
    ]
    confirmations = [
        {
            "variant": row["variant"],
            **_confirm_model(
                analysis["public_challenge"],
                metadata[row["variant"]]["block_count"],
                row["model"],
            ),
        }
        for row in observations
        if row["model"] is not None
    ]
    for row in confirmations:
        family = metadata[row["variant"]]["family"]
        if family == "split4_full" and not row["all_blocks_match"]:
            raise RuntimeError("A187 full-formula SAT model failed independent confirmation")
    by_variant = {row["variant"]: row for row in observations}

    def metric(variant: str, name: str) -> int:
        value = by_variant[variant]["statistics"].get(name)
        if value is None:
            raise RuntimeError(f"A187 missing {name} for {variant}")
        return int(value)

    full_b1_decisions = metric("split4_full_b1", "sat-decisions")
    full_b1_conflicts = metric("split4_full_b1", "sat-conflicts")
    primary = (
        metric("split4_full_b8", "sat-decisions") < full_b1_decisions
        and metric("split4_full_b8", "sat-conflicts") < full_b1_conflicts
    )
    sparse_winners = [
        variant
        for variant in (
            "split4_sparse512_b2",
            "split4_sparse512_b4",
            "split4_sparse512_b8",
        )
        if metric(variant, "sat-decisions") < full_b1_decisions
        and metric(variant, "sat-conflicts") < full_b1_conflicts
    ]
    secondary = bool(sparse_winners)
    prediction_retained = primary and secondary
    comparisons = {
        "fixed_rlimit": RLIMIT,
        "full_b1": {
            "decisions": full_b1_decisions,
            "conflicts": full_b1_conflicts,
        },
        "full_b8": {
            "decisions": metric("split4_full_b8", "sat-decisions"),
            "conflicts": metric("split4_full_b8", "sat-conflicts"),
        },
        "primary_prediction_retained": primary,
        "fixed_512_bit_sparse_winners": sparse_winners,
        "secondary_prediction_retained": secondary,
        "prospective_prediction_retained": prediction_retained,
    }
    recovered_assignments = sorted(
        {
            row["combined_assignment"]
            for row in confirmations
            if row["all_blocks_match"] and not row["control_first_block_match"]
        }
    )
    if prediction_retained and recovered_assignments:
        evidence_stage = "PROSPECTIVE_SHARED_KEY_STACKING_AND_RECOVERY_RETAINED"
    elif prediction_retained:
        evidence_stage = "PROSPECTIVE_SHARED_KEY_CAUSAL_STACKING_TRANSFER_RETAINED"
    else:
        evidence_stage = "SHARED_KEY_STACKING_BOUNDARY_RETAINED"
    all_variants_executed = [row["variant"] for row in observations] == list(VARIANTS)
    if not all_variants_executed:
        raise RuntimeError("A187 did not execute the complete variant plan")
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
            "Ten fixed-resource formulations prospectively compare full shared-key "
            "stacking, fixed-information sparse stacking, and modular output deltas "
            "on one fresh eight-block five-round 40-bit ChaCha challenge."
        ),
        "scope": (
            "Prospective compiler-search-shape transfer on reduced five-round ChaCha; "
            "one full key word plus eight adjacent bits are unknown and 216 key bits "
            "are known."
        ),
        "parameters": {
            "rounds": ROUNDS,
            "unknown_key_bits": UNKNOWN_KEY_BITS,
            "known_key_bits": KNOWN_KEY_BITS,
            "maximum_block_count": 8,
            "variants": list(VARIANTS),
            "fixed_rlimit": RLIMIT,
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
        "formula_plan": analysis["formula_plan"],
        "formula_plan_sha256": _canonical_sha256(analysis["formula_plan"]),
        "execution": execution,
        "execution_sha256": _canonical_sha256(execution),
        "comparisons": comparisons,
        "comparison_sha256": _canonical_sha256(comparisons),
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
        raise RuntimeError("A187 final artifact reopen gate failed")
    return {
        "json_sha256": _sha256(raw),
        "causal_sha256": reader.file_sha256,
        "causal_graph_sha256": reader.graph_sha256,
        "evidence_stage": evidence_stage,
        "statuses": {row["variant"]: row["status"] for row in observations},
        "comparisons": comparisons,
        "fully_confirmed_assignments": recovered_assignments,
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
    parser.add_argument("--z3", default="z3")
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
                z3_name=args.z3,
            ),
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    main()

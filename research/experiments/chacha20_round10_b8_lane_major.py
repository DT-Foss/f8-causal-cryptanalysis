#!/usr/bin/env python3
"""Lane-major ordering of the same 128 shared-key ChaCha10 midstate equalities."""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import re
import subprocess
import sys
from collections.abc import Sequence
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any

from arx_carry_leak.crypto_causal import CryptoCausalBuilder, CryptoCausalReader


def _import_sibling(filename: str, module_name: str) -> Any:
    path = Path(__file__).with_name(filename)
    spec = importlib.util.spec_from_file_location(module_name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


_A202 = _import_sibling(
    "chacha20_round10_b8_global_cse.py",
    "chacha20_round10_lane_a202_anchor",
)
_A198 = _A202._A198
_A188 = _A198._A188

ATTEMPT_ID = "A203"
SCHEMA = "chacha20-round10-b8-lane-major-v1"
PROTOCOL_SCHEMA = "chacha20-round10-b8-lane-major-protocol-v1"
PROTOCOL_FILENAME = "chacha20_round10_b8_lane_major_v1.json"
PROTOCOL_SHA256 = "13a9f968a7735c63d977c551f119a46558aee7a97588aec5ca8d8eef9a9b629c"
A188_FILENAME = _A188.RESULT_FILENAME
A188_SHA256 = "d1a75d6456f75257cbd0be41864fad0810540508aa5c30239b16bd3998eef73a"
A188_CAUSAL_FILENAME = _A188.CAUSAL_FILENAME
A188_CAUSAL_SHA256 = "a717e615cfc005fe985a24059f7e6bedcd8008c460b274bb313f6ddfc53e7c78"
A202_FILENAME = _A202.RESULT_FILENAME
A202_SHA256 = "4fbfc950984d3cb8eee85ba5532217cab2edae43e7ed8444ff2363259d3e990b"
A202_CAUSAL_FILENAME = _A202.CAUSAL_FILENAME
A202_CAUSAL_SHA256 = "fb2dd421e7a6ff89c668f908d6760a53a91728f2ce5881cde8188bff10522ac3"
PUBLIC_CHALLENGE_SHA256 = _A198.PUBLIC_CHALLENGE_SHA256
LANE_BASE_SHA256 = "d311596ae628e37cd7be30c61b03478cd2b72437c1f54f3739152f62a9a6cb66"
FORMULA_PLAN_SHA256 = "a428f38f62ddb69ea5b2b0a6d68407fe1b0cc6304b4f1332fb9082c9bae235fc"
FORMULA_HASH_LIST_SHA256 = "975ec27298fa731ee9d015aa379da7ddc6c999378f7373ae5a0b09ad58a698e6"
EXECUTION_PLAN_SHA256 = "df08ae1393541d19d6d8ca3c74b2afeb94813c3176116dc52a3fa3293d14e2d6"
VARIANT_ORDER_SHA256 = "8d95a151a7cabf5267b2cc2d3e282784d592eaa5795d7ad1422447954928d17c"
BASELINE_PREPROCESSED_SHA256 = "532479d8427f02b6fa1304f9acc95c7f6806c53130d561fb438c5d61ef851bd9"
LANE_PREPROCESSED_SHA256 = "7722f9deb96030d57244029facee525211b3b267027744fe80a7f79a34e69da8"
ROUNDS = 10
UNKNOWN_KEY_BITS = 20
KNOWN_KEY_BITS = 236
BLOCK_COUNT = 8
FREE_BITS = 15
PREFIXES = tuple(f"{value:05b}" for value in range(32))
VARIANTS = tuple(f"lane_prefix_{prefix}" for prefix in PREFIXES)
TIME_LIMIT_MS = 10_000
MAX_PARALLEL_WORKERS = 4
RESULT_FILENAME = "chacha20_round10_b8_lane_major_v1.json"
CAUSAL_FILENAME = "chacha20_round10_b8_lane_major_v1.causal"
MIDSTATE_EQUALITY_PATTERN = re.compile(r"^\(assert \(= (g\d+) (g\d+)\)\)$")


def _sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _file_sha256(path: Path) -> str:
    return _A202._file_sha256(path)


def _canonical_sha256(value: Any) -> str:
    return _A202._canonical_sha256(value)


def _load_protocol_gate() -> dict[str, Any]:
    path = Path(__file__).parents[1] / "configs" / PROTOCOL_FILENAME
    if _file_sha256(path) != PROTOCOL_SHA256:
        raise RuntimeError("A203 frozen protocol hash differs")
    protocol = json.loads(path.read_bytes())
    boundary = protocol.get("information_boundary", {})
    compiler = protocol.get("compiler_plan", {})
    if (
        protocol.get("schema") != PROTOCOL_SCHEMA
        or protocol.get("attempt_id") != ATTEMPT_ID
        or protocol.get("protocol_state")
        != "frozen_after_A188_basis_calibration_and_A202_boundary_before_any_A203_solver_execution"
        or protocol.get("execution_plan_sha256") != EXECUTION_PLAN_SHA256
        or protocol.get("variant_order_sha256") != VARIANT_ORDER_SHA256
        or compiler.get("lane_major_base_sha256") != LANE_BASE_SHA256
        or compiler.get("formula_plan_sha256") != FORMULA_PLAN_SHA256
        or compiler.get("preprocessed_lane_major_sha256") != LANE_PREPROCESSED_SHA256
        or boundary.get("A203_solver_outcomes_used_before_protocol_freeze") is not False
        or boundary.get("assertion_order_budget_or_cell_order_changed_after_any_A203_outcome")
        is not False
        or boundary.get("early_stop_permitted") is not False
        or boundary.get("unknown_assignment_available_to_runner_before_execution") is not False
        or boundary.get("unknown_assignment_in_protocol_or_source") is not False
    ):
        raise RuntimeError("A203 frozen protocol identity gate failed")
    return protocol


def _load_anchor_gates(results_dir: Path) -> dict[str, Any]:
    specs = (
        (
            "A188",
            A188_FILENAME,
            A188_CAUSAL_FILENAME,
            A188_SHA256,
            A188_CAUSAL_SHA256,
            "CROSS_ENGINE_ROUND5_RECOVERY_BOUNDARY_RETAINED",
        ),
        (
            "A202",
            A202_FILENAME,
            A202_CAUSAL_FILENAME,
            A202_SHA256,
            A202_CAUSAL_SHA256,
            "ROUND10_GLOBAL_CSE_COMPLETE_PARTITION_BOUNDARY_RETAINED",
        ),
    )
    retained = {}
    gates: dict[str, Any] = {}
    for label, result_name, causal_name, result_sha, causal_sha, stage in specs:
        result_path = results_dir / result_name
        causal_path = results_dir / causal_name
        if _file_sha256(result_path) != result_sha or _file_sha256(causal_path) != causal_sha:
            raise RuntimeError(f"A203 {label} anchor hash gate failed")
        result = json.loads(result_path.read_bytes())
        reader = CryptoCausalReader(causal_path)
        if (
            result.get("evidence_stage") != stage
            or reader.file_sha256 != causal_sha
            or reader.graph_sha256 != result.get("causal", {}).get("graph_sha256")
            or not reader.verify_provenance()
        ):
            raise RuntimeError(f"A203 {label} anchor content gate failed")
        retained[label] = result
        gates.update(
            {
                f"{label}_result_sha256": result_sha,
                f"{label}_causal_sha256": causal_sha,
                f"{label}_causal_graph_sha256": reader.graph_sha256,
                f"{label}_causal_provenance_verified": True,
            }
        )
    a188_confirmations = retained["A188"].get("confirmations", [])
    if (
        len(a188_confirmations) != 1
        or a188_confirmations[0].get("variant") != "bitwuzla_bitblast_b8"
        or a188_confirmations[0].get("all_blocks_match") is not True
        or retained["A202"].get("execution", {}).get("returned_model_count") != 0
    ):
        raise RuntimeError("A203 calibration/boundary anchor gate failed")
    gates["A188_b8_calibration_recovery_retained"] = True
    gates["A202_preprocessor_canonicalized_CSE_boundary_retained"] = True
    return gates


def _lane_major_base(challenge: dict[str, Any]) -> tuple[str, dict[str, Any]]:
    base, cse_stats = _A202._global_cse_base(challenge)
    lines = base.splitlines()
    check_index = lines.index("(check-sat)")
    before_check = lines[:check_index]
    after_check = lines[check_index:]
    assertion_indices = [
        index for index, line in enumerate(before_check) if line.startswith("(assert")
    ]
    if len(assertion_indices) != 130:
        raise RuntimeError("A203 expected 130 pre-check assertions")
    key_assertions = [before_check[index] for index in assertion_indices[:2]]
    raw_midstate = [before_check[index] for index in assertion_indices[2:]]
    parsed = []
    for line in raw_midstate:
        match = MIDSTATE_EQUALITY_PATTERN.fullmatch(line)
        if match is None:
            raise RuntimeError("A203 could not parse a CSE midstate equality")
        parsed.append(match.groups())
    block_major_reverse = [parsed[index * 16 : (index + 1) * 16] for index in range(BLOCK_COUNT)]
    block_ascending = list(reversed(block_major_reverse))
    lane_major = [
        f"(assert (= {block_ascending[block][lane][0]} {block_ascending[block][lane][1]}))"
        for lane in range(16)
        for block in range(BLOCK_COUNT)
    ]
    nonassertions = [
        line for index, line in enumerate(before_check) if index not in set(assertion_indices)
    ]
    lane_base = "\n".join([*nonassertions, *key_assertions, *lane_major, *after_check]) + "\n"
    stats = {
        "base_bytes": len(lane_base.encode()),
        "base_sha256": _sha256(lane_base.encode()),
        "definition_count": cse_stats["cse_definition_count"],
        "key_constraint_count": len(key_assertions),
        "midstate_equality_count": len(lane_major),
        "definition_block_order": list(reversed(range(BLOCK_COUNT))),
        "assertion_order": "lane_major_then_block_ascending_0_through_7",
        "midstate_equality_multiset_preserved": sorted(raw_midstate) == sorted(lane_major),
    }
    if (
        stats["base_bytes"] != 148714
        or stats["base_sha256"] != LANE_BASE_SHA256
        or stats["definition_count"] != 2364
        or stats["midstate_equality_count"] != 128
        or stats["midstate_equality_multiset_preserved"] is not True
    ):
        raise RuntimeError("A203 lane-major compiler gate failed")
    return lane_base, stats


def _formula(base: str, variant: str) -> str:
    match = re.fullmatch(r"lane_prefix_([01]{5})", variant)
    if match is None:
        raise ValueError(f"unknown A203 variant {variant}")
    assertion = f"(assert (= ((_ extract 19 15) k0) #b{match.group(1)}))"
    return base.replace("(check-sat)", assertion + "\n(check-sat)")


def _execution_plan() -> dict[str, Any]:
    return {
        "complete_variant_plan_required": True,
        "early_stop_used": False,
        "execution_mode": "deterministic_numeric_prefix_waves_external_solver",
        "external_timeout_slack_seconds_per_cell": 5,
        "formula_representation": (
            "portable_SMTLIB2_round10_split8_b8_global_CSE_lane_major_midstate_equalities"
        ),
        "known_key_bits": KNOWN_KEY_BITS,
        "max_parallel_workers": MAX_PARALLEL_WORKERS,
        "partition_cell_count": 32,
        "partition_cell_free_bits": FREE_BITS,
        "partition_fixed_bits": 5,
        "partition_prefix_order": list(PREFIXES),
        "primitive": "ChaCha20_block_function",
        "rounds": ROUNDS,
        "shared_key_block_count": BLOCK_COUNT,
        "solver": "Bitwuzla_0.9.1_bitblast_CaDiCaL",
        "solver_time_limit_milliseconds": TIME_LIMIT_MS,
        "target_output_bits_per_cell": BLOCK_COUNT * 512,
        "unknown_assignment_available_to_runner_before_execution": False,
        "unknown_key_bits": UNKNOWN_KEY_BITS,
        "variant_execution_order": list(VARIANTS),
        "variants": list(VARIANTS),
        "wave_count": 8,
        "wave_size": MAX_PARALLEL_WORKERS,
    }


def _preprocess_gate(baseline_formula: str, lane_formula: str, executable: str) -> dict[str, Any]:
    rows = []
    for label, formula in (("baseline", baseline_formula), ("lane_major", lane_formula)):
        result = subprocess.run(
            [executable, "--lang", "smt2", "--pp-only", "--print-formula"],
            input=formula,
            text=True,
            capture_output=True,
            check=False,
            timeout=30,
        )
        if result.returncode != 0 or result.stderr:
            raise RuntimeError(f"A203 {label} preprocess gate failed")
        rows.append(
            {
                "label": label,
                "input_bytes": len(formula.encode()),
                "preprocessed_bytes": len(result.stdout.encode()),
                "preprocessed_lines": len(result.stdout.splitlines()),
                "preprocessed_sha256": _sha256(result.stdout.encode()),
            }
        )
    if (
        rows[0]["preprocessed_sha256"] != BASELINE_PREPROCESSED_SHA256
        or rows[1]["preprocessed_sha256"] != LANE_PREPROCESSED_SHA256
        or rows[0]["preprocessed_bytes"] != rows[1]["preprocessed_bytes"]
        or rows[0]["preprocessed_sha256"] == rows[1]["preprocessed_sha256"]
    ):
        raise RuntimeError("A203 lane-major preprocessing identity gate failed")
    return {
        "rows": rows,
        "same_preprocessed_size": True,
        "distinct_preprocessed_formula": True,
    }


def analyze(results_dir: Path) -> dict[str, Any]:
    protocol = _load_protocol_gate()
    anchors = _load_anchor_gates(results_dir)
    challenge = _A198._load_public_challenge()
    lane_base, lane_stats = _lane_major_base(challenge)
    plan = _execution_plan()
    if _canonical_sha256(plan) != EXECUTION_PLAN_SHA256:
        raise RuntimeError("A203 execution plan hash differs from freeze")
    if _canonical_sha256(list(VARIANTS)) != VARIANT_ORDER_SHA256:
        raise RuntimeError("A203 variant order hash differs from freeze")
    formulas = {variant: _formula(lane_base, variant) for variant in VARIANTS}
    formula_plan = [
        {
            "variant": variant,
            "prefix": variant[-5:],
            "fixed_key_coordinates": [19, 18, 17, 16, 15],
            "free_key_coordinates": list(reversed(range(15))),
            "candidate_count": 1 << FREE_BITS,
            "shared_key_block_count": BLOCK_COUNT,
            "target_output_bits": BLOCK_COUNT * 512,
            "definition_block_order": list(reversed(range(BLOCK_COUNT))),
            "assertion_order": "lane_major_then_block_ascending_0_through_7",
            "definition_count": 2364,
            "output_equality_count": 128,
            "bytes": len(formulas[variant].encode()),
            "sha256": _sha256(formulas[variant].encode()),
            "portable_smtlib2": True,
        }
        for variant in VARIANTS
    ]
    if (
        _canonical_sha256(formula_plan) != FORMULA_PLAN_SHA256
        or _canonical_sha256([row["sha256"] for row in formula_plan]) != FORMULA_HASH_LIST_SHA256
        or sum(row["candidate_count"] for row in formula_plan) != 1 << UNKNOWN_KEY_BITS
    ):
        raise RuntimeError("A203 formula plan differs from freeze")
    preprocess = _preprocess_gate(
        _A202._formula(_A202._global_cse_base(challenge)[0], _A202.VARIANTS[0]),
        formulas[VARIANTS[0]],
        protocol["solver_binaries"]["bitwuzla"]["path_at_freeze"],
    )
    return {
        "protocol": protocol,
        "anchor_gates": anchors,
        "public_challenge": challenge,
        "execution_plan": plan,
        "lane_stats": lane_stats,
        "preprocess_gate": preprocess,
        "formulas": formulas,
        "formula_plan": formula_plan,
        "solver_execution_started": False,
    }


def _build_causal(path: Path, payload: dict[str, Any]) -> dict[str, Any]:
    builder = CryptoCausalBuilder(
        experiment="chacha20_round10_b8_lane_major",
        parameters={
            "attempt_id": ATTEMPT_ID,
            "rounds": ROUNDS,
            "unknown_key_bits": UNKNOWN_KEY_BITS,
            "shared_key_blocks": BLOCK_COUNT,
            "cells": len(VARIANTS),
        },
    )
    ids = [
        "chacha20-a203-a188-calibration",
        "chacha20-a203-a202-canonicalization-boundary",
        "chacha20-a203-lane-major-equality-order",
        "chacha20-a203-complete-lane-prefix-cover",
        "chacha20-a203-independent-confirmation",
        "chacha20-a203-prospective-lane-result",
    ]
    rows = [
        (
            "A188:known_round5_b8_recovery_calibration",
            "select_the_only_transformed_basis_retaining_SAT_at_5s",
            "A203:lane_major_basis_selected",
            "known_result_basis_calibration",
            A188_CAUSAL_SHA256,
            [],
            {"basis_calibration": payload["basis_calibration"]},
        ),
        (
            "A203:lane_major_basis_selected",
            "anchor_A202_all_unknown_and_preprocessor_CSE_canonicalization",
            "A203:assertion_order_only_question",
            "retained_compiler_canonicalization_boundary",
            A202_CAUSAL_SHA256,
            [ids[0]],
            {"anchor_gates": payload["anchor_gates"]},
        ),
        (
            "A203:assertion_order_only_question",
            "reorder_the_same_128_equalities_lane_major_without_rewrite",
            "A203:distinct_preprocessed_lane_major_formula",
            "semantics_preserving_assertion_order_transfer",
            payload["lane_stats_sha256"],
            [ids[1]],
            {"lane_stats": payload["lane_stats"], "preprocess_gate": payload["preprocess_gate"]},
        ),
        (
            "A203:distinct_preprocessed_lane_major_formula",
            "execute_all_32_numeric_prefix_cells_at_10s",
            "A203:complete_lane_major_execution",
            "complete_predeclared_lane_major_cover",
            payload["execution_sha256"],
            [ids[2]],
            {"execution": payload["execution"]},
        ),
        (
            "A203:complete_lane_major_execution",
            "recompute_every_model_over_all_4096_target_bits_and_control",
            "A203:independently_confirmed_lane_models",
            "independent_eight_block_confirmation",
            payload["confirmation_sha256"],
            [ids[3]],
            {"confirmations": payload["confirmations"]},
        ),
        (
            "A203:independently_confirmed_lane_models",
            "apply_the_frozen_primary_and_secondary_lane_rules",
            "A203:prospective_lane_major_result",
            "prospective_lane_major_transfer",
            payload["comparison_sha256"],
            [ids[4]],
            {"comparisons": payload["comparisons"]},
        ),
    ]
    for index, row in enumerate(rows):
        trigger, mechanism, outcome, kind, source, provenance, attrs = row
        builder.add_triplet(
            edge_id=ids[index],
            trigger=trigger,
            mechanism=mechanism,
            outcome=outcome,
            confidence=1.0,
            evidence_kind=kind,
            source=source,
            provenance=provenance,
            attrs=attrs,
        )
    stats = dict(builder.save(path))
    stats.pop("path", None)
    reader = CryptoCausalReader(path)
    if len(reader.triplets(include_inferred=False)) != len(ids) or not reader.verify_provenance():
        raise RuntimeError("A203 Causal Reader provenance gate failed")
    return {
        "stats": stats,
        "explicit_triplets": len(ids),
        "provenance_verified": True,
        "file_sha256": reader.file_sha256,
        "graph_sha256": reader.graph_sha256,
    }


def run(*, results_dir: Path, output: Path, causal_output: Path) -> dict[str, Any]:
    analysis = analyze(results_dir)
    identity = _A198._A197._A191._solver_gate(analysis["protocol"])
    observations = []
    waves = []
    for wave_index, start in enumerate(range(0, len(VARIANTS), MAX_PARALLEL_WORKERS)):
        wave = VARIANTS[start : start + MAX_PARALLEL_WORKERS]

        def execute(variant: str) -> dict[str, Any]:
            return _A202._run_cell(variant, analysis["formulas"][variant], identity)

        with ThreadPoolExecutor(max_workers=MAX_PARALLEL_WORKERS) as executor:
            rows = list(executor.map(execute, wave))
        observations.extend(rows)
        waves.append(
            {
                "wave_index": wave_index,
                "variants": list(wave),
                "statuses": [row["status"] for row in rows],
                "maximum_volatile_seconds": max(row["volatile_seconds"] for row in rows),
            }
        )
    if [row["variant"] for row in observations] != list(VARIANTS):
        raise RuntimeError("A203 did not execute the complete variant plan")
    confirmations = [
        {
            "variant": row["variant"],
            "prefix": row["prefix"],
            **_A198._confirm_model(analysis["public_challenge"], row["model"]),
        }
        for row in observations
        if row["model"] is not None
    ]
    if any(
        not row["known_key_constraints_match"]
        or not row["all_blocks_match"]
        or row["control_first_block_match"]
        or row["output_bits_checked"] != 4096
        for row in confirmations
    ):
        raise RuntimeError("A203 returned model failed independent confirmation")
    recovered = sorted({row["recovered_unknown_low20"] for row in confirmations})
    status_counts = {
        status: sum(row["status"] == status for row in observations)
        for status in ("sat", "unsat", "unknown", "invalid")
    }
    resolved = status_counts["sat"] + status_counts["unsat"]
    comparisons = {
        "original_domain_candidate_count": 1 << UNKNOWN_KEY_BITS,
        "complete_domain_candidate_count": sum(row["candidate_count"] for row in observations),
        "partition_complete_and_disjoint_by_construction": True,
        "A202_baseline_reexecuted": False,
        "A202_block_major_10s_status": "all_unknown",
        "same_128_midstate_equality_multiset": True,
        "distinct_preprocessed_formula": True,
        "status_counts": status_counts,
        "resolved_sat_plus_unsat_cell_count": resolved,
        "confirmed_variants": [row["variant"] for row in confirmations],
        "fully_confirmed_unknown_low20_assignments": recovered,
        "primary_prediction_retained": len(confirmations) >= 1,
        "secondary_prediction_retained": resolved >= 1,
        "statuses": {row["variant"]: row["status"] for row in observations},
    }
    evidence_stage = (
        "PROSPECTIVE_ROUND10_LANE_MAJOR_RECOVERY_RETAINED"
        if comparisons["primary_prediction_retained"]
        else "ROUND10_LANE_MAJOR_COMPLETE_PARTITION_BOUNDARY_RETAINED"
    )
    execution = {
        "variant_order": list(VARIANTS),
        "complete_variant_plan_executed": True,
        "early_stop_used": False,
        "observations": observations,
        "wave_observations": waves,
        "returned_model_count": len(confirmations),
        "fully_confirmed_unknown_assignment_count": len(recovered),
        "fully_confirmed_unknown_low20_assignments": recovered,
        "unknown_assignment_available_to_runner_before_execution": False,
    }
    payload: dict[str, Any] = {
        "schema": SCHEMA,
        "attempt_id": ATTEMPT_ID,
        "evidence_stage": evidence_stage,
        "result": (
            "A complete numeric-prefix cover tests lane-major ordering of the same 128 "
            "shared-key split8 midstate equalities."
        ),
        "scope": (
            "Prospective reduced ChaCha10 width-20 partial-key assertion-order transfer "
            "over the unchanged A198 challenge."
        ),
        "protocol_gate": {
            "artifact_sha256": PROTOCOL_SHA256,
            "protocol_state": analysis["protocol"]["protocol_state"],
            "information_boundary": analysis["protocol"]["information_boundary"],
            "prospective_predictions": analysis["protocol"]["prospective_predictions"],
        },
        "anchor_gates": analysis["anchor_gates"],
        "basis_calibration": analysis["protocol"]["basis_calibration"],
        "public_challenge": analysis["public_challenge"],
        "public_challenge_sha256": PUBLIC_CHALLENGE_SHA256,
        "lane_stats": analysis["lane_stats"],
        "lane_stats_sha256": _canonical_sha256(analysis["lane_stats"]),
        "preprocess_gate": analysis["preprocess_gate"],
        "execution_plan": analysis["execution_plan"],
        "execution_plan_sha256": EXECUTION_PLAN_SHA256,
        "solver_identity": identity,
        "formula_plan": analysis["formula_plan"],
        "formula_plan_sha256": FORMULA_PLAN_SHA256,
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
    _A198._A185._atomic_write(output, raw)
    reader = CryptoCausalReader(causal_output)
    if (
        _file_sha256(output) != _sha256(raw)
        or reader.file_sha256 != causal["file_sha256"]
        or not reader.verify_provenance()
    ):
        raise RuntimeError("A203 final artifact reopen gate failed")
    return {
        "json_sha256": _sha256(raw),
        "causal_sha256": reader.file_sha256,
        "causal_graph_sha256": reader.graph_sha256,
        "evidence_stage": evidence_stage,
        "status_counts": status_counts,
        "fully_confirmed_unknown_low20_assignments": recovered,
        "primary_prediction_retained": comparisons["primary_prediction_retained"],
        "secondary_prediction_retained": comparisons["secondary_prediction_retained"],
        "output": str(output),
        "causal_output": str(causal_output),
    }


def main(argv: Sequence[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description=__doc__)
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
        summary = {
            "execution_plan_sha256": _canonical_sha256(analysis["execution_plan"]),
            "formula_plan_sha256": _canonical_sha256(analysis["formula_plan"]),
            "lane_stats": analysis["lane_stats"],
            "preprocess_gate": analysis["preprocess_gate"],
            "variants": len(analysis["formula_plan"]),
            "solver_execution_started": analysis["solver_execution_started"],
        }
    else:
        summary = run(
            results_dir=args.results_dir.resolve(),
            output=args.output.resolve(),
            causal_output=args.causal_output.resolve(),
        )
    print(json.dumps(summary, sort_keys=True))


if __name__ == "__main__":
    main()

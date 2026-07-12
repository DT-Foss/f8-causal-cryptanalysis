#!/usr/bin/env python3
"""Prospectively transfer the local 12-before-0 alias-polarity rule."""

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

from arx_carry_leak.crypto_causal import CryptoCausalBuilder, CryptoCausalReader


def _import_sibling(filename: str, module_name: str) -> Any:
    path = Path(__file__).with_name(filename)
    spec = importlib.util.spec_from_file_location(module_name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


_A170 = _import_sibling(
    "shake_symbolic_r2_reversed_order_alias_polarity_frontier.py",
    "shake_symbolic_r2_adjacent_transfer_a170_base",
)
_A169 = _A170._A169
_A168 = _A170._A168
_A166 = _A170._A166
_A163 = _A170._A163
_A156 = _A170._A156

ATTEMPT_ID = "A172"
SCHEMA = "shake-symbolic-r2-adjacent-0-12-transfer-frontier-v1"
SEED = _A170.SEED
WINDOW_BITS = _A170.WINDOW_BITS
Z3_RLIMIT = _A170.Z3_RLIMIT
EXTERNAL_SAFETY_TIMEOUT_SECONDS = _A170.EXTERNAL_SAFETY_TIMEOUT_SECONDS
AFFINE_SHIFT = _A170.AFFINE_SHIFT
A170_FILENAME = _A170.RESULT_FILENAME
A170_SHA256 = "f28d4a767d26b6514eb90d6324e8a19d2842d1418fd7587ff0068ca9512cb97f"
A170_POLARITY_SHA256 = "8fe2d08594044697a0aa27f17c3fd1dda253b76eea6ae2bca39a6f6da24e9a92"
A169_FILENAME = _A169.RESULT_FILENAME
A169_SHA256 = _A170.A169_SHA256
A166_FILENAME = _A166.RESULT_FILENAME
A166_SHA256 = _A170.A166_SHA256
PROTOCOL_FILENAME = "shake_symbolic_r2_adjacent_0_12_transfer_frontier_v1.json"
PROTOCOL_SHA256 = "27be9da4897c9cde913db8a40aa169322a8a7c5dbec805878ec188dfec06c151"
PROTOCOL_SCHEMA = "shake-symbolic-r2-adjacent-0-12-transfer-frontier-protocol-v1"
RESULT_FILENAME = "shake_symbolic_r2_adjacent_0_12_transfer_frontier_v1.json"
CAUSAL_FILENAME = "shake_symbolic_r2_adjacent_0_12_transfer_frontier_v1.causal"
SOURCE_ORDER = "greedy_max_remaining_weight"
INSERTION_INDEX = 11
ORIENTATIONS = ("0_before_12", "12_before_0")
COMPILERS = ("inline", "materialized")


def _sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _canonical_sha256(value: Any) -> str:
    return _A170._canonical_sha256(value)


def _load_anchor_gates(
    results_dir: Path,
) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any], dict[str, Any]]:
    a170 = _A156._load_json_gate(results_dir / A170_FILENAME, A170_SHA256, _A170.SCHEMA)
    a169 = _A156._load_json_gate(results_dir / A169_FILENAME, A169_SHA256, _A169.SCHEMA)
    a166 = _A156._load_json_gate(results_dir / A166_FILENAME, A166_SHA256, _A166.SCHEMA)
    _a164, a162 = _A166._load_anchor_gates(results_dir)
    if (
        a170.get("polarity_frontier_sha256") != A170_POLARITY_SHA256
        or a170.get("polarity_frontier", {}).get("polarity_counts")
        != {"flipped": 2, "preserved": 2, "zero": 0}
        or [
            row["reversed_materialization_effect"]
            for row in a170.get("polarity_frontier", {}).get("rows", [])
        ]
        != [-1_281, -2_898, -942, 1_018]
        or a170.get("status_counts") != {"error": 0, "sat": 0, "unknown": 8, "unsat": 0}
        or Z3_RLIMIT != 500_000_000
        or EXTERNAL_SAFETY_TIMEOUT_SECONDS != 300
    ):
        raise RuntimeError("A172 A166/A169/A170 anchor gate failed")
    return a170, a169, a166, a162


def _load_protocol_gate() -> dict[str, Any]:
    path = Path(__file__).parents[1] / "configs" / PROTOCOL_FILENAME
    protocol = _A156._load_json_gate(path, PROTOCOL_SHA256, PROTOCOL_SCHEMA)
    if (
        protocol.get("attempt_id") != ATTEMPT_ID
        or protocol.get("protocol_state") != "frozen_before_any_A172_solver_execution"
        or protocol.get("anchors", {}).get("A170", {}).get("sha256") != A170_SHA256
        or protocol.get("anchors", {}).get("A169", {}).get("sha256") != A169_SHA256
        or protocol.get("transfer_design", {}).get("semantic_change") is not False
        or protocol.get("transfer_design", {}).get("new_formula_count") != 4
        or protocol.get("prospective_prediction", {}).get("direction")
        != "effect_12_before_0_is_strictly_lower_than_effect_0_before_12"
        or protocol.get("information_boundary", {}).get(
            "A172_solver_outcomes_used_before_formula_freeze"
        )
        is not False
    ):
        raise RuntimeError("A172 frozen protocol identity gate failed")
    return protocol


def _validate_protocol_plan(protocol: dict[str, Any], analysis: dict[str, Any]) -> None:
    rows = [
        [row["name"], row["formula_bytes"], row["formula_sha256"]]
        for row in analysis["formula_plan"]
    ]
    if (
        protocol["discovery_evidence"]["sha256"] != analysis["discovery_evidence_sha256"]
        or protocol["transfer_plan"]["sha256"] != analysis["transfer_plan_sha256"]
        or protocol["formula_plan"]["sha256"] != analysis["formula_plan_sha256"]
        or protocol["formula_plan"]["rows"] != rows
    ):
        raise RuntimeError("A172 regenerated discovery/transfer/formulas differ")


def _base_orders(a166: dict[str, Any]) -> dict[str, list[int]]:
    rows = {
        row["encoding"]["order_name"]: row["encoding"]["variable_to_shifted_input_coordinate"]
        for row in a166["formula_plan"]
    }
    if SOURCE_ORDER not in rows:
        raise RuntimeError("A172 source order missing")
    return rows


def _matched_weighted_discovery(
    a170: dict[str, Any],
    a169: dict[str, Any],
    a166: dict[str, Any],
) -> list[dict[str, Any]]:
    base_orders = _base_orders(a166)
    reversed_orders = {
        row["base_order_name"]: row["reversed_order"] for row in a170["reversal_plan"]
    }
    base_effects = {
        row["order_name"]: row["total_materialization_effect"]
        for row in a169["mobius_decomposition"]["rows"]
    }
    reversed_effects = {
        row["base_order_name"]: row["reversed_materialization_effect"]
        for row in a170["polarity_frontier"]["rows"]
    }
    designs = [
        (
            "late_weighted_context",
            "weighted_degree_ascending",
            base_orders["weighted_degree_ascending"],
            base_effects["weighted_degree_ascending"],
            "reversed_weighted_degree_descending",
            reversed_orders["weighted_degree_descending"],
            reversed_effects["weighted_degree_descending"],
            [13, 14],
        ),
        (
            "early_weighted_context",
            "weighted_degree_descending",
            base_orders["weighted_degree_descending"],
            base_effects["weighted_degree_descending"],
            "reversed_weighted_degree_ascending",
            reversed_orders["weighted_degree_ascending"],
            reversed_effects["weighted_degree_ascending"],
            [9, 10],
        ),
    ]
    rows = []
    for (
        context,
        zero_first_name,
        zero_first,
        zero_first_effect,
        twelve_first_name,
        twelve_first,
        twelve_first_effect,
        expected_positions,
    ) in designs:
        differences = [
            index
            for index, (left, right) in enumerate(zip(zero_first, twelve_first, strict=True))
            if left != right
        ]
        if (
            differences != expected_positions
            or [zero_first[index] for index in differences] != [0, 12]
            or [twelve_first[index] for index in differences] != [12, 0]
        ):
            raise RuntimeError("A172 matched adjacent-swap discovery gate failed")
        rows.append(
            {
                "context": context,
                "zero_before_twelve_order_name": zero_first_name,
                "twelve_before_zero_order_name": twelve_first_name,
                "adjacent_positions": expected_positions,
                "only_changed_coordinates": [0, 12],
                "zero_before_twelve_effect": zero_first_effect,
                "twelve_before_zero_effect": twelve_first_effect,
                "directional_delta": twelve_first_effect - zero_first_effect,
                "predicted_direction_satisfied": (twelve_first_effect < zero_first_effect),
            }
        )
    if [row["directional_delta"] for row in rows] != [-2_258, -890]:
        raise RuntimeError("A172 discovery deltas differ")
    return rows


def _transfer_plan(a166: dict[str, Any]) -> dict[str, Any]:
    source = list(_base_orders(a166)[SOURCE_ORDER])
    remainder = [coordinate for coordinate in source if coordinate not in (0, 12)]
    zero_first = remainder[:INSERTION_INDEX] + [0, 12] + remainder[INSERTION_INDEX:]
    twelve_first = remainder[:INSERTION_INDEX] + [12, 0] + remainder[INSERTION_INDEX:]
    differences = [
        index
        for index, (left, right) in enumerate(zip(zero_first, twelve_first, strict=True))
        if left != right
    ]
    if (
        len(remainder) != 22
        or differences != [INSERTION_INDEX, INSERTION_INDEX + 1]
        or [zero_first[index] for index in differences] != [0, 12]
        or [twelve_first[index] for index in differences] != [12, 0]
        or sorted(zero_first) != list(range(WINDOW_BITS))
        or sorted(twelve_first) != list(range(WINDOW_BITS))
    ):
        raise RuntimeError("A172 transfer order construction failed")
    return {
        "source_order_name": SOURCE_ORDER,
        "source_order": source,
        "source_without_0_12": remainder,
        "insertion_index_zero_based": INSERTION_INDEX,
        "adjacent_positions": [INSERTION_INDEX, INSERTION_INDEX + 1],
        "zero_before_twelve_order": zero_first,
        "twelve_before_zero_order": twelve_first,
        "only_changed_coordinates_between_arms": [0, 12],
        "other_22_relative_order_preserved": True,
        "selection_rule": ("greedy_max_cross_family_source_and_central_11_12_boundary"),
    }


def _formula_frontier(
    problem: dict[str, Any],
    variant: Any,
    transfer: dict[str, Any],
    semantic_gate: dict[str, Any],
) -> tuple[list[dict[str, Any]], dict[str, bytes]]:
    orders = {
        "0_before_12": transfer["zero_before_twelve_order"],
        "12_before_0": transfer["twelve_before_zero_order"],
    }
    rows = []
    formulas = {}
    for orientation in ORIENTATIONS:
        order = orders[orientation]
        for compiler in COMPILERS:
            name = f"greedy_max_center_{orientation}__{compiler}_negative_alias"
            if compiler == "inline":
                writer, inputs, encoding = _A166._encode_problem(
                    problem,
                    variant,
                    name=name,
                    order_name=f"greedy_max_center_{orientation}",
                    variable_to_shifted_input=order,
                    expected_shifted_polynomial_sha256=semantic_gate[
                        "shifted_R2_polynomial_state_sha256"
                    ],
                    expected_coefficient_incidence=semantic_gate["coefficient_incidence"],
                )
            else:
                writer, inputs, encoding = _A168._encode_problem(
                    problem,
                    variant,
                    name=name,
                    order_name=f"greedy_max_center_{orientation}",
                    variable_to_shifted_input=order,
                    expected_shifted_polynomial_sha256=semantic_gate[
                        "shifted_R2_polynomial_state_sha256"
                    ],
                    expected_coefficient_incidence=semantic_gate["coefficient_incidence"],
                )
            encoding.update(
                {
                    "transfer_source_order": SOURCE_ORDER,
                    "adjacent_orientation": orientation,
                    "adjacent_positions": [INSERTION_INDEX, INSERTION_INDEX + 1],
                    "alias_compiler_arm": compiler,
                    "prospective_directional_prediction": (
                        "effect_12_before_0_is_strictly_lower_than_effect_0_before_12"
                    ),
                    "instrumented_assignment_input_used": False,
                    "solver_observation_input_used_for_formula_construction": False,
                    "target_rate_input_used_for_transfer_selection": False,
                }
            )
            raw = writer.render(inputs, include_model=True)
            formulas[name] = raw
            rows.append(
                {
                    "name": name,
                    "execution_order": len(rows),
                    "formula_bytes": len(raw),
                    "formula_sha256": _sha256(raw),
                    "encoding": encoding,
                    "solver_input_names": inputs,
                    "solver_outcome_used_for_formula_construction": False,
                }
            )
    return rows, formulas


def _formula_plan(rows: Sequence[dict[str, Any]]) -> list[dict[str, Any]]:
    return [
        {
            "name": row["name"],
            "execution_order": row["execution_order"],
            "formula_bytes": row["formula_bytes"],
            "formula_sha256": row["formula_sha256"],
            "encoding": row["encoding"],
            "rlimit": Z3_RLIMIT,
            "wallclock_solver_limit_used": False,
        }
        for row in rows
    ]


def _run_z3_rlimit(z3: Path, path: Path, inputs: list[str]) -> dict[str, Any]:
    result = _A163._run_z3_rlimit(z3, path, inputs)
    result["command_parameters"]["representation"] = (
        "Boolean_SMT_shared_R2_adjacent_0_12_transfer_fixed_rlimit"
    )
    return result


def _execute_frontier(
    *,
    formula_rows: Sequence[dict[str, Any]],
    formulas: dict[str, bytes],
    problem: dict[str, Any],
    variant: Any,
    z3: Path,
    work_dir: Path,
) -> list[dict[str, Any]]:
    work_dir.mkdir(parents=True, exist_ok=True)
    if any(work_dir.iterdir()):
        raise ValueError("A172 solver work directory must be empty")
    results = []
    try:
        for row in formula_rows:
            raw = formulas[row["name"]]
            if len(raw) != row["formula_bytes"] or _sha256(raw) != row["formula_sha256"]:
                raise RuntimeError(f"{row['name']} formula differs before execution")
            path = work_dir / f"{row['execution_order']:02d}_{row['name']}.smt2"
            path.write_bytes(raw)
            if path.read_bytes() != raw:
                raise RuntimeError(f"{row['name']} formula write/reopen gate failed")
            result = _run_z3_rlimit(z3, path, row["solver_input_names"])
            path.unlink(missing_ok=True)
            expected_resource_stop = (
                result["status"] == "unknown"
                and result["return_code"] in (0, 1)
                and result["stats"].get("rlimit-count", 0) >= Z3_RLIMIT
                and result["termination"] == "fixed_rlimit_exhausted"
            )
            solved = result["status"] in ("sat", "unsat") and result["return_code"] == 0
            if not (expected_resource_stop or solved):
                raise RuntimeError(f"{row['name']} fixed-resource execution failed")
            results.append(_A163._verify_solver_row(dict(row), result, problem, variant))
    finally:
        for path in work_dir.glob("*.smt2"):
            path.unlink(missing_ok=True)
    if any(work_dir.iterdir()):
        raise RuntimeError("A172 solver formula cleanup failed")
    return results


def _execution_summary(executions: Sequence[dict[str, Any]]) -> list[dict[str, Any]]:
    return [
        {
            "name": row["name"],
            "adjacent_orientation": row["encoding"]["adjacent_orientation"],
            "alias_compiler_arm": row["encoding"]["alias_compiler_arm"],
            "affine_shift": AFFINE_SHIFT,
            "status": row["solver"]["status"],
            "return_code": row["solver"]["return_code"],
            "termination": row["solver"]["termination"],
            "canonical_observation_sha256": row["solver"]["canonical_observation_sha256"],
            "stats": row["solver"]["stats"],
            "independently_confirmed_model": row["independently_confirmed_model"],
        }
        for row in executions
    ]


def _transfer_result(executions: Sequence[dict[str, Any]]) -> dict[str, Any]:
    observed = {
        (row["encoding"]["adjacent_orientation"], row["encoding"]["alias_compiler_arm"]): row
        for row in executions
    }
    effects = {}
    rows = []
    for orientation in ORIENTATIONS:
        inline = int(observed[(orientation, "inline")]["solver"]["stats"]["decisions"])
        materialized = int(observed[(orientation, "materialized")]["solver"]["stats"]["decisions"])
        effect = materialized - inline
        effects[orientation] = effect
        rows.append(
            {
                "adjacent_orientation": orientation,
                "inline_decisions": inline,
                "materialized_decisions": materialized,
                "materialization_effect": effect,
            }
        )
    delta = effects["12_before_0"] - effects["0_before_12"]
    return {
        "rows": rows,
        "directional_delta_12_before_0_minus_0_before_12": delta,
        "prospective_prediction": ("effect_12_before_0_is_strictly_lower_than_effect_0_before_12"),
        "prospective_prediction_confirmed": delta < 0,
        "direction_classification": (
            "confirmed_lower" if delta < 0 else "exact_tie" if delta == 0 else "reversed_direction"
        ),
        "signs": {
            orientation: (effect > 0) - (effect < 0) for orientation, effect in effects.items()
        },
    }


def _posthoc_summary(
    problem: dict[str, Any], variant: Any, executions: Sequence[dict[str, Any]]
) -> dict[str, Any]:
    actual = _A168._WINDOW._extract_window(problem["base_state"], variant, problem["positions"])
    return {
        "instrumented_input_assignment": actual,
        "extracted_only_after_every_A172_execution": True,
        "used_for_transfer_formula_order_or_execution": False,
        "model_matches": [
            {
                "name": row["name"],
                "solver_status": row["solver"]["status"],
                "model_matches_instrumented_input_assignment": (
                    row["input_coordinate_assignment"] == actual
                    if row["input_coordinate_assignment"] is not None
                    else None
                ),
            }
            for row in executions
        ],
    }


def _build_causal(path: Path, payload: dict[str, Any]) -> dict[str, Any]:
    builder = CryptoCausalBuilder(
        experiment="shake_symbolic_r2_adjacent_0_12_transfer_frontier",
        parameters={
            "attempt_id": ATTEMPT_ID,
            "variant": "shake128",
            "seed": SEED,
            "window_bits": WINDOW_BITS,
            "affine_shift": AFFINE_SHIFT,
            "new_formula_count": 4,
            "rlimit_per_formula": Z3_RLIMIT,
        },
    )
    ids = [
        "shake128-a170-two-matched-weighted-adjacent-swaps",
        "shake128-a172-cross-family-central-adjacent-pair",
        "shake128-a172-four-prospective-transfer-formulas",
        "shake128-a172-fixed-resource-execution",
        "shake128-a172-adjacent-order-transfer-result",
    ]
    builder.add_triplet(
        edge_id=ids[0],
        trigger="A170:two_exact_weighted_pairs_differ_only_by_adjacent_0_12_swap",
        mechanism="observe_12_before_0_lower_materialization_effect_in_both_early_and_late_contexts",
        outcome="A172:prospective_local_order_rule",
        confidence=1.0,
        evidence_kind="matched_posthoc_discovery_from_retained_fullround_arms",
        source=payload["discovery_evidence_sha256"],
        attrs={"discovery_evidence": payload["discovery_evidence"]},
    )
    builder.add_triplet(
        edge_id=ids[1],
        trigger="A172:prospective_local_order_rule",
        mechanism="remove_0_and_12_from_greedy_max_preserve_other_22_then_insert_at_central_11_12_boundary",
        outcome="A172:two_new_cross_family_adjacent_orders",
        confidence=1.0,
        evidence_kind="prospective_deterministic_order_construction",
        source=payload["transfer_plan_sha256"],
        provenance=[ids[0]],
        attrs={"transfer_plan": payload["transfer_plan"]},
    )
    builder.add_triplet(
        edge_id=ids[2],
        trigger="A172:two_new_cross_family_adjacent_orders",
        mechanism="compile_inline_and_materialized_alias_arms_for_both_orientations",
        outcome="A172:four_exact_prospective_fullround_formulas",
        confidence=1.0,
        evidence_kind="hash_bound_semantics_preserving_formula_frontier",
        source=payload["formula_plan_sha256"],
        provenance=[ids[1]],
        attrs={"formula_plan": payload["formula_plan"]},
    )
    builder.add_triplet(
        edge_id=ids[3],
        trigger="A172:four_exact_prospective_fullround_formulas",
        mechanism="execute_all_four_formulas_under_the_unchanged_fixed_resource_protocol",
        outcome="A172:four_adjacent_transfer_solver_observations",
        confidence=1.0,
        evidence_kind="fixed_resource_execution_and_complete_rate_gate",
        source="Z3_4.15.4_plus_independent_NumPy_lane_core",
        provenance=[ids[2]],
        attrs={"execution_summary": payload["execution_summary"]},
    )
    builder.add_triplet(
        edge_id=ids[4],
        trigger="A172:four_adjacent_transfer_solver_observations",
        mechanism="compare_materialization_effect_12_before_0_against_0_before_12",
        outcome="A172:prospective_adjacent_order_direction_test",
        confidence=1.0,
        evidence_kind="paired_cross_family_prospective_transfer",
        source=payload["transfer_result_sha256"],
        provenance=[ids[3]],
        attrs={"transfer_result": payload["transfer_result"]},
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
        or any(
            by_id[left]["outcome"] != by_id[right]["trigger"]
            for left, right in zip(ids[:-1], ids[1:], strict=True)
        )
    ):
        raise RuntimeError("A172 Causal provenance chain failed validation")
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


def _analysis_core(results_dir: Path) -> dict[str, Any]:
    a170, a169, a166, a162 = _load_anchor_gates(results_dir)
    discovery = _matched_weighted_discovery(a170, a169, a166)
    transfer = _transfer_plan(a166)
    baseline = _A166.analyze(results_dir)
    semantic_gate = next(row for row in a162["semantic_gates"] if row["shift"] == AFFINE_SHIFT)
    rows, formulas = _formula_frontier(
        baseline["problem"],
        baseline["variant"],
        transfer,
        semantic_gate,
    )
    plan = _formula_plan(rows)
    return {
        "anchors": (a170, a169, a166),
        "variant": baseline["variant"],
        "problem": baseline["problem"],
        "discovery_evidence": discovery,
        "discovery_evidence_sha256": _canonical_sha256(discovery),
        "transfer_plan": transfer,
        "transfer_plan_sha256": _canonical_sha256(transfer),
        "rows": rows,
        "formulas": formulas,
        "formula_plan": plan,
        "formula_plan_sha256": _canonical_sha256(plan),
    }


def analyze(results_dir: Path) -> dict[str, Any]:
    protocol = _load_protocol_gate()
    analysis = _analysis_core(results_dir)
    analysis["protocol"] = protocol
    _validate_protocol_plan(protocol, analysis)
    return analysis


def run(
    *,
    results_dir: Path,
    output: Path,
    causal_output: Path,
    work_dir: Path,
    z3: Path,
) -> dict[str, Any]:
    analysis = analyze(results_dir)
    a170, a169, _a166 = analysis["anchors"]
    solver_version = _A156._z3_version_gate(z3)
    executions = _execute_frontier(
        formula_rows=analysis["rows"],
        formulas=analysis["formulas"],
        problem=analysis["problem"],
        variant=analysis["variant"],
        z3=z3,
        work_dir=work_dir,
    )
    status_counts = {
        status: sum(row["solver"]["status"] == status for row in executions)
        for status in ("sat", "unsat", "unknown", "error")
    }
    confirmed_models = [
        {
            "name": row["name"],
            "solver_basis_assignment": row["solver"]["solver_basis_assignment"],
            "shifted_input_coordinate_assignment": row["shifted_input_coordinate_assignment"],
            "input_coordinate_assignment": row["input_coordinate_assignment"],
            "independent_complete_rate_check": row["independent_complete_rate_check"],
        }
        for row in executions
        if row["independently_confirmed_model"]
    ]
    summary = _execution_summary(executions)
    transfer_result = _transfer_result(executions)
    posthoc = _posthoc_summary(analysis["problem"], analysis["variant"], executions)
    payload: dict[str, Any] = {
        "schema": SCHEMA,
        "attempt_id": ATTEMPT_ID,
        "evidence_stage": "PROSPECTIVE_ADJACENT_0_12_TRANSFER_EXECUTED",
        "result": (
            "A172 prospectively tests the 12-before-0 local order rule in a "
            "new central Greedy-Max context with paired inline/materialized arms."
        ),
        "scope": (
            "The retained A152 SHAKE128 width-24 relation, affine gauge 0x4e1e28, "
            "two new Greedy-Max-derived adjacent orders, shared R2 prefix, 22 "
            "unchanged suffix rounds and all 1,344 rate bits."
        ),
        "parameters": {
            "variant": "SHAKE128",
            "seed": SEED,
            "window_bits": WINDOW_BITS,
            "affine_shift": AFFINE_SHIFT,
            "new_formula_count": 4,
            "rlimit_per_formula": Z3_RLIMIT,
            "execution_mode": "sequential_one_thread_per_formula",
            "solver": solver_version,
            "solver_wallclock_limit_used": False,
            "external_safety_timeout_seconds": EXTERNAL_SAFETY_TIMEOUT_SECONDS,
            "wallclock_excluded_from_canonical_result": True,
        },
        "anchor_gates": {
            "A172_protocol": {
                "artifact_sha256": PROTOCOL_SHA256,
                "protocol_state": analysis["protocol"]["protocol_state"],
                "prospective_prediction": analysis["protocol"]["prospective_prediction"],
                "information_boundary": analysis["protocol"]["information_boundary"],
            },
            "A170": {
                "artifact_sha256": A170_SHA256,
                "polarity_frontier_sha256": A170_POLARITY_SHA256,
                "polarity_counts": a170["polarity_frontier"]["polarity_counts"],
            },
            "A169": {
                "artifact_sha256": A169_SHA256,
                "mobius_decomposition_sha256": a169["mobius_decomposition_sha256"],
            },
        },
        "discovery_evidence": analysis["discovery_evidence"],
        "discovery_evidence_sha256": analysis["discovery_evidence_sha256"],
        "transfer_plan": analysis["transfer_plan"],
        "transfer_plan_sha256": analysis["transfer_plan_sha256"],
        "formula_plan": analysis["formula_plan"],
        "formula_plan_sha256": analysis["formula_plan_sha256"],
        "execution": executions,
        "execution_summary": summary,
        "status_counts": status_counts,
        "confirmed_models": confirmed_models,
        "transfer_result": transfer_result,
        "transfer_result_sha256": _canonical_sha256(transfer_result),
        "posthoc": posthoc,
    }
    causal = _build_causal(causal_output, payload)
    payload["causal"] = causal
    raw = json.dumps(payload, indent=2, sort_keys=True, allow_nan=False).encode() + b"\n"
    _atomic_write(output, raw)
    reader = CryptoCausalReader(causal_output)
    if (
        _sha256(output.read_bytes()) != _sha256(raw)
        or reader.file_sha256 != causal["file_sha256"]
        or reader.graph_sha256 != causal["graph_sha256"]
        or not reader.verify_provenance()
    ):
        raise RuntimeError("A172 final artifact reopen gate failed")
    return {
        "json_sha256": _sha256(raw),
        "causal_sha256": reader.file_sha256,
        "causal_graph_sha256": reader.graph_sha256,
        "status_counts": status_counts,
        "confirmed_model_count": len(confirmed_models),
        "direction_classification": transfer_result["direction_classification"],
        "prospective_prediction_confirmed": transfer_result["prospective_prediction_confirmed"],
        "directional_delta": transfer_result["directional_delta_12_before_0_minus_0_before_12"],
        "effects": [row["materialization_effect"] for row in transfer_result["rows"]],
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
    parser.add_argument(
        "--work-dir",
        type=Path,
        default=Path(__file__).parents[2] / "build" / "shake-r2-a172",
    )
    parser.add_argument(
        "--z3",
        type=Path,
        default=Path(shutil.which("z3") or "/opt/homebrew/bin/z3"),
    )
    args = parser.parse_args(argv)
    if args.analyze_only:
        analysis = analyze(args.results_dir.resolve())
    else:
        analysis = None
    if analysis is not None:
        print(
            json.dumps(
                {
                    "discovery_evidence_sha256": analysis["discovery_evidence_sha256"],
                    "discovery_evidence": analysis["discovery_evidence"],
                    "transfer_plan_sha256": analysis["transfer_plan_sha256"],
                    "transfer_plan": analysis["transfer_plan"],
                    "formula_plan_sha256": analysis["formula_plan_sha256"],
                    "formulas": [
                        {
                            "name": row["name"],
                            "orientation": row["encoding"]["adjacent_orientation"],
                            "arm": row["encoding"]["alias_compiler_arm"],
                            "bytes": row["formula_bytes"],
                            "sha256": row["formula_sha256"],
                            "variables": row["encoding"]["total_variables"],
                            "assertions": row["encoding"]["total_assertions"],
                        }
                        for row in analysis["rows"]
                    ],
                    "solver_started": False,
                },
                sort_keys=True,
            )
        )
        return
    z3 = Path(shutil.which(str(args.z3)) or args.z3)
    if not z3.is_file():
        raise FileNotFoundError(f"Z3 executable not found: {args.z3}")
    if args.output.resolve() == args.causal_output.resolve():
        raise ValueError("JSON and Causal output paths must be distinct")
    print(
        json.dumps(
            run(
                results_dir=args.results_dir.resolve(),
                output=args.output.resolve(),
                causal_output=args.causal_output.resolve(),
                work_dir=args.work_dir.resolve(),
                z3=z3.resolve(),
            ),
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""Separate signed-alias node removal from downstream solver-ID shifting."""

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

from arx_carry_leak.crypto_causal import CryptoCausalBuilder, CryptoCausalReader


def _import_sibling(filename: str, module_name: str) -> Any:
    path = Path(__file__).with_name(filename)
    spec = importlib.util.spec_from_file_location(module_name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


_A166 = _import_sibling(
    "shake_symbolic_r2_signed_alias_compiler_frontier.py",
    "shake_symbolic_r2_id_preserving_a166_base",
)
_A164 = _A166._A164
_A163 = _A166._A163
_A158 = _A166._A158
_A157 = _A166._A157
_A156 = _A166._A156
_WINDOW = _A166._WINDOW
_R1 = _A166._R1
_SMT = _A166._SMT
_SYMBOLIC = _A166._SYMBOLIC

ATTEMPT_ID = "A167"
SCHEMA = "shake-symbolic-r2-id-preserving-signed-alias-frontier-v1"
SEED = _A166.SEED
WINDOW_BITS = _A166.WINDOW_BITS
Z3_RLIMIT = _A166.Z3_RLIMIT
EXTERNAL_SAFETY_TIMEOUT_SECONDS = _A166.EXTERNAL_SAFETY_TIMEOUT_SECONDS
AFFINE_SHIFT = _A166.AFFINE_SHIFT
A166_FILENAME = _A166.RESULT_FILENAME
A166_SHA256 = "e6cdc6a69e36e8632bfd5389b77914f744a61f45fbdb84e13c5701e3f2fbc6db"
A166_COMPARISON_SHA256 = "1977e8c279a7d965f4723dc60de25e26a9a39b95eabcd2293d1b670cddc65418"
A164_FILENAME = _A164.RESULT_FILENAME
A164_SHA256 = _A166.A164_SHA256
A163_SHA256 = _A164.A163_SHA256
PROTOCOL_FILENAME = "shake_symbolic_r2_id_preserving_signed_alias_frontier_v1.json"
PROTOCOL_SHA256 = "a26e101e0d7e993dd5cd27485adf0e4d04e4f30f7c3c42a25db7a22ddee9d1c9"
PROTOCOL_SCHEMA = "shake-symbolic-r2-id-preserving-signed-alias-frontier-protocol-v1"
RESULT_FILENAME = "shake_symbolic_r2_id_preserving_signed_alias_frontier_v1.json"
CAUSAL_FILENAME = "shake_symbolic_r2_id_preserving_signed_alias_frontier_v1.causal"


def _sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _canonical_sha256(value: Any) -> str:
    return _A166._canonical_sha256(value)


def _load_anchor_gates(
    results_dir: Path,
) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    a166 = _A156._load_json_gate(results_dir / A166_FILENAME, A166_SHA256, _A166.SCHEMA)
    a164, a162 = _A166._load_anchor_gates(results_dir)
    if (
        a166.get("comparison_sha256") != A166_COMPARISON_SHA256
        or a166.get("formula_plan_sha256")
        != "fd2ed7f25529335e7403aafc638d21fa07a99e8bde81333518e4e8fdbb4a25f7"
        or a166.get("status_counts") != {"error": 0, "sat": 0, "unknown": 4, "unsat": 0}
        or [row["decision_delta"] for row in a166.get("comparison", [])]
        != [2_008, -977, -1_623, -1_182]
        or a166.get("anchor_gates", {}).get("A164", {}).get("artifact_sha256") != A164_SHA256
        or Z3_RLIMIT != 500_000_000
        or EXTERNAL_SAFETY_TIMEOUT_SECONDS != 300
    ):
        raise RuntimeError("A167 A164/A166 anchor gate failed")
    return a166, a164, a162


def _load_protocol_gate() -> dict[str, Any]:
    path = Path(__file__).parents[1] / "configs" / PROTOCOL_FILENAME
    protocol = _A156._load_json_gate(path, PROTOCOL_SHA256, PROTOCOL_SCHEMA)
    if (
        protocol.get("attempt_id") != ATTEMPT_ID
        or protocol.get("protocol_state") != "frozen_before_any_A167_solver_execution"
        or protocol.get("anchors", {}).get("A166", {}).get("sha256") != A166_SHA256
        or protocol.get("anchors", {}).get("A164", {}).get("sha256") != A164_SHA256
        or protocol.get("anchors", {}).get("A163", {}).get("sha256") != A163_SHA256
        or protocol.get("control_intervention", {}).get("semantic_change") is not False
        or protocol.get("control_intervention", {}).get(
            "downstream_declaration_sequence_equal_to_A164"
        )
        is not True
        or protocol.get("information_boundary", {}).get(
            "A167_solver_outcomes_used_before_formula_freeze"
        )
        is not False
    ):
        raise RuntimeError("A167 frozen protocol identity gate failed")
    return protocol


def _validate_protocol_plan(protocol: dict[str, Any], analysis: dict[str, Any]) -> None:
    rows = [
        [
            row["name"],
            row["formula_bytes"],
            row["formula_sha256"],
            row["encoding"]["declaration_sequence_sha256"],
        ]
        for row in analysis["formula_plan"]
    ]
    if (
        protocol["control_plan"]["sha256"] != analysis["control_plan_sha256"]
        or protocol["formula_plan"]["sha256"] != analysis["formula_plan_sha256"]
        or protocol["formula_plan"]["rows"] != rows
    ):
        raise RuntimeError("A167 regenerated control/formulas differ from protocol")


def _compile_id_preserving_signed_r2_prefix(
    writer: Any,
    polynomials: Sequence[frozenset[int]],
) -> tuple[list[str], list[str], dict[str, Any]]:
    inputs = [writer.declare("x") for _ in range(WINDOW_BITS)]
    monomials: dict[int, str] = {0: "true"}
    monomials.update({1 << index: inputs[index] for index in range(WINDOW_BITS)})
    predeclared, occurrence = _A157._ordered_quadratics(
        polynomials,
        "decreasing_coordinate_occurrence_then_numeric_mask",
    )
    definition_masks = []

    def monomial(mask: int) -> str:
        existing = monomials.get(mask)
        if existing is not None:
            return existing
        coordinates = [index for index in range(WINDOW_BITS) if (mask >> index) & 1]
        if len(coordinates) != 2:
            raise RuntimeError(f"A167 R2 monomial degree differs: {mask}")
        value = writer.define(
            f"(and {inputs[coordinates[0]]} {inputs[coordinates[1]]})",
            "m",
        )
        monomials[mask] = value
        definition_masks.append(mask)
        return value

    for mask in predeclared:
        monomial(mask)

    state = []
    direct_alias_coordinates = []
    complement_alias_coordinates = []
    id_padding_coordinates = []
    id_padding_names = []
    state_definitions = 0
    for coordinate, polynomial in enumerate(polynomials):
        ordered = sorted(polynomial)
        if len(ordered) == 1:
            state.append(monomial(ordered[0]))
            direct_alias_coordinates.append(coordinate)
            continue
        if len(ordered) == 2 and ordered[0] == 0 and ordered[1].bit_count() == 1:
            placeholder = writer.declare("s")
            state.append(f"(not {monomial(ordered[1])})")
            complement_alias_coordinates.append(coordinate)
            id_padding_coordinates.append(coordinate)
            id_padding_names.append(placeholder)
            continue
        state.append(writer.define(writer.xor(monomial(mask) for mask in ordered), "s"))
        state_definitions += 1

    if (
        len(monomials) != 301
        or definition_masks != predeclared
        or direct_alias_coordinates != [453, 516, 990, 1_454]
        or complement_alias_coordinates != [917]
        or id_padding_coordinates != [917]
        or len(id_padding_names) != 1
        or state_definitions != 1_595
    ):
        raise RuntimeError("A167 ID-preserving signed compiler shape differs")
    return (
        inputs,
        state,
        {
            "shared_monomial_count": len(monomials),
            "constant_monomials": 1,
            "linear_monomials": WINDOW_BITS,
            "quadratic_monomials": len(definition_masks),
            "quadratic_definition_order": ("decreasing_coordinate_occurrence_then_numeric_mask"),
            "quadratic_definition_masks": definition_masks,
            "quadratic_definition_order_sha256": _canonical_sha256(definition_masks),
            "quadratic_occurrence_by_mask_sha256": _canonical_sha256(
                {str(mask): occurrence[mask] for mask in sorted(occurrence)}
            ),
            "R2_state_definitions": state_definitions,
            "R2_direct_alias_coordinates": direct_alias_coordinates,
            "R2_complement_alias_coordinates": complement_alias_coordinates,
            "R2_signed_alias_coordinates": sorted(
                direct_alias_coordinates + complement_alias_coordinates
            ),
            "R2_id_padding_coordinates": id_padding_coordinates,
            "R2_id_padding_names": id_padding_names,
            "R2_id_padding_connected_to_formula": False,
            "R2_signed_alias_definition_count_eliminated": 1,
            "prefix_variables": writer.variables,
            "prefix_assertions": writer.assertions,
        },
    )


def _encode_problem(
    problem: dict[str, Any],
    variant: Any,
    *,
    name: str,
    order_name: str,
    variable_to_shifted_input: Sequence[int],
    expected_shifted_polynomial_sha256: str,
    expected_coefficient_incidence: dict[str, int],
) -> tuple[Any, list[str], dict[str, Any]]:
    template = _WINDOW._clear_window(problem["base_state"], variant, problem["positions"])
    original = _R1._SPLIT._symbolic_prefix_polynomials(
        template,
        variant,
        problem["positions"],
        2,
    )
    shifted = _A166._A160._shift_polynomials(original, AFFINE_SHIFT, WINDOW_BITS)
    if (
        _SYMBOLIC._poly_hash(shifted, WINDOW_BITS) != expected_shifted_polynomial_sha256
        or _A166._A160._coefficient_counts(shifted) != expected_coefficient_incidence
    ):
        raise RuntimeError("A167 selected shifted R2 polynomial differs")
    shifted_input_to_solver_rows = _A156._input_to_solver_rows(variable_to_shifted_input)
    transformed = _A163._A155._substitute_linear_basis(
        shifted,
        shifted_input_to_solver_rows,
        WINDOW_BITS,
    )
    writer = _SMT.BooleanSMT(SEED)
    inputs, state, prefix = _compile_id_preserving_signed_r2_prefix(writer, transformed)
    state, suffix = _SMT._compile_suffix(writer, state, list(range(2, 24)))
    before_outputs = writer.assertions
    for lane in range(variant.rate_lanes):
        lane_value = int(problem["target"][0, lane])
        for bit in range(64):
            literal = state[lane * 64 + bit]
            writer.constrain(literal if ((lane_value >> bit) & 1) else f"(not {literal})")
    return (
        writer,
        inputs,
        {
            "name": name,
            "order_name": order_name,
            "compiler": "signed_alias_inline_with_disconnected_ID_padding",
            "variable_to_shifted_input_coordinate": list(variable_to_shifted_input),
            "shifted_input_to_solver_row_masks_hex": [
                f"{value:06x}" for value in shifted_input_to_solver_rows
            ],
            "affine_shift_original_input_mask": AFFINE_SHIFT,
            "affine_shift_original_input_mask_hex": f"0x{AFFINE_SHIFT:06x}",
            "model_mapping": (
                "solver_order_to_shifted_input_permutation_then_XOR_row_affine_shift"
            ),
            "R2_polynomial_state_sha256_in_solver_basis": _SYMBOLIC._poly_hash(
                transformed,
                WINDOW_BITS,
            ),
            "semantic_shifted_R2_polynomial_state_sha256": (expected_shifted_polynomial_sha256),
            "shifted_R2_coefficient_incidence": expected_coefficient_incidence,
            **prefix,
            **suffix,
            "total_variables": writer.variables,
            "total_assertions": writer.assertions,
            "output_assertions": writer.assertions - before_outputs,
            "target_rate_bits": variant.rate_bits,
            "instrumented_assignment_input_used": False,
            "solver_observation_input_used_for_formula_construction": False,
            "target_rate_input_used_for_control_selection": False,
        },
    )


_DECLARATION = re.compile(rb"^\(declare-fun ([^ ]+) \(\) Bool\)$", re.MULTILINE)


def _declaration_sequence(raw: bytes) -> list[str]:
    return [value.decode() for value in _DECLARATION.findall(raw)]


def _formula_frontier(
    problem: dict[str, Any],
    variant: Any,
    baseline_rows: Sequence[dict[str, Any]],
    baseline_formulas: dict[str, bytes],
    semantic_gate: dict[str, Any],
) -> tuple[list[dict[str, Any]], dict[str, bytes], list[dict[str, Any]]]:
    by_order = {row["encoding"]["order_name"]: row for row in baseline_rows}
    rows = []
    formulas = {}
    controls = []
    for order_name in _A158.ORDER_NAMES:
        baseline = by_order[order_name]
        baseline_raw = baseline_formulas[baseline["name"]]
        name = f"{order_name}__id_preserving_signed_alias"
        writer, inputs, encoding = _encode_problem(
            problem,
            variant,
            name=name,
            order_name=order_name,
            variable_to_shifted_input=baseline["encoding"]["variable_to_shifted_input_coordinate"],
            expected_shifted_polynomial_sha256=semantic_gate["shifted_R2_polynomial_state_sha256"],
            expected_coefficient_incidence=semantic_gate["coefficient_incidence"],
        )
        raw = writer.render(inputs, include_model=True)
        baseline_declarations = _declaration_sequence(baseline_raw)
        declarations = _declaration_sequence(raw)
        declaration_sha256 = _canonical_sha256(declarations)
        if (
            declarations != baseline_declarations
            or len(declarations) != 121_576
            or encoding["total_variables"] != baseline["encoding"]["total_variables"]
            or encoding["total_assertions"] + 1 != baseline["encoding"]["total_assertions"]
        ):
            raise RuntimeError(f"A167 {order_name} declaration-ID control differs")
        encoding["declaration_sequence_sha256"] = declaration_sha256
        encoding["declaration_sequence_equal_to_A164"] = True
        encoding["original_control_source_attempt"] = baseline["control_source_attempt"]
        encoding["original_control_formula_name"] = baseline["name"]
        encoding["original_control_formula_sha256"] = baseline["formula_sha256"]
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
        controls.append(
            {
                "order_name": order_name,
                "original_control_source_attempt": baseline["control_source_attempt"],
                "original_control_formula_name": baseline["name"],
                "original_control_formula_sha256": baseline["formula_sha256"],
                "original_control_total_variables": baseline["encoding"]["total_variables"],
                "original_control_total_assertions": baseline["encoding"]["total_assertions"],
                "A167_total_variables": encoding["total_variables"],
                "A167_total_assertions": encoding["total_assertions"],
                "declaration_sequence_sha256": declaration_sha256,
                "declaration_sequences_identical": True,
                "semantic_relation_unchanged": True,
                "connected_alias_definition_removed": 1,
                "disconnected_ID_padding_declarations_added": 1,
            }
        )
    return rows, formulas, controls


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
        "Boolean_SMT_shared_R2_ID_preserving_signed_alias_fixed_rlimit"
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
        raise ValueError("A167 solver work directory must be empty")
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
        raise RuntimeError("A167 solver formula cleanup failed")
    return results


def _execution_summary(executions: Sequence[dict[str, Any]]) -> list[dict[str, Any]]:
    return [
        {
            "name": row["name"],
            "order_name": row["encoding"]["order_name"],
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


def _sign(value: int) -> int:
    return (value > 0) - (value < 0)


def _effect_decomposition(
    a164: dict[str, Any],
    a166: dict[str, Any],
    executions: Sequence[dict[str, Any]],
) -> dict[str, Any]:
    materialized = {
        row["order_name"]: row
        for row in a164["full_factorial_matrix"]
        if row["affine_shift"] == AFFINE_SHIFT
    }
    compact = {row["order_name"]: row for row in a166["execution_summary"]}
    rows = []
    for execution in executions:
        order_name = execution["encoding"]["order_name"]
        a164_decisions = int(materialized[order_name]["decisions"])
        a166_decisions = int(compact[order_name]["stats"]["decisions"])
        a167_decisions = int(execution["solver"]["stats"].get("decisions", 0))
        alias_node_effect = a167_decisions - a164_decisions
        downstream_id_effect = a166_decisions - a167_decisions
        total_effect = a166_decisions - a164_decisions
        if alias_node_effect + downstream_id_effect != total_effect:
            raise RuntimeError("A167 exact decision decomposition failed")
        rows.append(
            {
                "order_name": order_name,
                "A164_materialized_original_ID_decisions": a164_decisions,
                "A167_inlined_original_ID_decisions": a167_decisions,
                "A166_inlined_shifted_ID_decisions": a166_decisions,
                "alias_node_effect_A167_minus_A164": alias_node_effect,
                "downstream_ID_shift_effect_A166_minus_A167": downstream_id_effect,
                "total_A166_minus_A164": total_effect,
                "exact_additive_identity_verified": True,
                "alias_node_direction_matches_total": (
                    _sign(alias_node_effect) == _sign(total_effect)
                ),
                "dominant_absolute_component": (
                    "alias_node_removal"
                    if abs(alias_node_effect) > abs(downstream_id_effect)
                    else (
                        "downstream_ID_shift"
                        if abs(downstream_id_effect) > abs(alias_node_effect)
                        else "balanced"
                    )
                ),
            }
        )
    alias_l1 = sum(abs(row["alias_node_effect_A167_minus_A164"]) for row in rows)
    id_l1 = sum(abs(row["downstream_ID_shift_effect_A166_minus_A167"]) for row in rows)
    return {
        "rows": rows,
        "alias_node_effect_L1": alias_l1,
        "downstream_ID_shift_effect_L1": id_l1,
        "aggregate_dominant_component": (
            "alias_node_removal"
            if alias_l1 > id_l1
            else "downstream_ID_shift"
            if id_l1 > alias_l1
            else "balanced"
        ),
        "all_alias_node_directions_match_A166_total": all(
            row["alias_node_direction_matches_total"] for row in rows
        ),
    }


def _posthoc_summary(
    problem: dict[str, Any], variant: Any, executions: Sequence[dict[str, Any]]
) -> dict[str, Any]:
    actual = _WINDOW._extract_window(problem["base_state"], variant, problem["positions"])
    return {
        "instrumented_input_assignment": actual,
        "extracted_only_after_every_A167_execution": True,
        "used_for_control_formula_order_or_execution": False,
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
        experiment="shake_symbolic_r2_id_preserving_signed_alias_frontier",
        parameters={
            "attempt_id": ATTEMPT_ID,
            "variant": "shake128",
            "seed": SEED,
            "window_bits": WINDOW_BITS,
            "affine_shift": AFFINE_SHIFT,
            "formula_count": 4,
            "rlimit_per_formula": Z3_RLIMIT,
        },
    )
    ids = [
        "shake128-a164-materialized-alias-original-IDs",
        "shake128-a166-inlined-alias-shifted-IDs",
        "shake128-a167-inlined-alias-original-IDs",
        "shake128-a167-fixed-resource-execution",
        "shake128-a167-two-component-effect-decomposition",
    ]
    builder.add_triplet(
        edge_id=ids[0],
        trigger="A164:universal_0x4e1e28_four_order_gauge",
        mechanism="retain_the_negative_alias_as_a_connected_equality_node_with_original_downstream_declaration_IDs",
        outcome="A167:materialized_alias_original_ID_control",
        confidence=1.0,
        evidence_kind="retained_exact_control",
        source=A164_SHA256,
        attrs={"A164_gate": payload["anchor_gates"]["A164"]},
    )
    builder.add_triplet(
        edge_id=ids[1],
        trigger="A167:materialized_alias_original_ID_control",
        mechanism="inline_the_negative_alias_and_remove_its_declaration_causing_all_downstream_IDs_to_shift",
        outcome="A167:A166_inlined_alias_shifted_ID_observation",
        confidence=1.0,
        evidence_kind="retained_semantics_preserving_intervention",
        source=A166_SHA256,
        provenance=[ids[0]],
        attrs={"A166_gate": payload["anchor_gates"]["A166"]},
    )
    builder.add_triplet(
        edge_id=ids[2],
        trigger="A167:A166_inlined_alias_shifted_ID_observation",
        mechanism="inline_the_same_alias_but_insert_one_disconnected_declaration_at_the_original_coordinate",
        outcome="A167:four_exact_inlined_alias_original_ID_formulas",
        confidence=1.0,
        evidence_kind="prospective_ID_preserving_control_compiler",
        source=payload["formula_plan_sha256"],
        provenance=[ids[1]],
        attrs={"control_plan": payload["control_plan"]},
    )
    builder.add_triplet(
        edge_id=ids[3],
        trigger="A167:four_exact_inlined_alias_original_ID_formulas",
        mechanism="execute_all_four_orders_under_the_unchanged_fixed_resource_protocol",
        outcome="A167:four_ID_preserving_solver_observations",
        confidence=1.0,
        evidence_kind="fixed_resource_execution_and_complete_rate_gate",
        source="Z3_4.15.4_plus_independent_NumPy_lane_core",
        provenance=[ids[2]],
        attrs={"execution_summary": payload["execution_summary"]},
    )
    builder.add_triplet(
        edge_id=ids[4],
        trigger="A167:four_ID_preserving_solver_observations",
        mechanism="decompose_A166_minus_A164_into_alias_node_and_downstream_ID_shift_components_per_order",
        outcome="A167:exact_signed_alias_ID_effect_decomposition",
        confidence=1.0,
        evidence_kind="three-arm_semantics_preserving_intervention",
        source=payload["effect_decomposition_sha256"],
        provenance=[ids[3]],
        attrs={"effect_decomposition": payload["effect_decomposition"]},
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
        raise RuntimeError("A167 Causal provenance chain failed validation")
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
    a166, a164, a162 = _load_anchor_gates(results_dir)
    a164_formulas = _A164.analyze(results_dir)
    a163_formulas = _A163.analyze(results_dir)
    selected = []
    for source_attempt, source_rows in (
        ("A164", a164_formulas["rows"]),
        ("A163", a163_formulas["rows"]),
    ):
        for row in source_rows:
            if row["encoding"]["affine_shift_original_input_mask"] == AFFINE_SHIFT:
                selected.append({**row, "control_source_attempt": source_attempt})
    if len(selected) != 4 or {row["encoding"]["order_name"] for row in selected} != set(
        _A158.ORDER_NAMES
    ):
        raise RuntimeError("A167 A164 selected formula set differs")
    semantic_gate = next(row for row in a162["semantic_gates"] if row["shift"] == AFFINE_SHIFT)
    rows, formulas, controls = _formula_frontier(
        a164_formulas["problem"],
        a164_formulas["variant"],
        selected,
        {**a164_formulas["formulas"], **a163_formulas["formulas"]},
        semantic_gate,
    )
    plan = _formula_plan(rows)
    return {
        "anchors": (a166, a164, a162),
        "variant": a164_formulas["variant"],
        "problem": a164_formulas["problem"],
        "rows": rows,
        "formulas": formulas,
        "control_plan": controls,
        "control_plan_sha256": _canonical_sha256(controls),
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
    a166, a164, _a162 = analysis["anchors"]
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
    decomposition = _effect_decomposition(a164, a166, executions)
    posthoc = _posthoc_summary(analysis["problem"], analysis["variant"], executions)
    payload: dict[str, Any] = {
        "schema": SCHEMA,
        "attempt_id": ATTEMPT_ID,
        "evidence_stage": "ID_PRESERVING_SIGNED_ALIAS_COMPONENT_DECOMPOSITION_EXECUTED",
        "result": (
            "A167 preserves A164's complete declaration-ID sequence while "
            "inlining A166's negative R2 alias, separating alias-node removal "
            "from downstream solver-ID shifting in all four orders."
        ),
        "scope": (
            "The retained A152 SHAKE128 width-24 relation, affine gauge 0x4e1e28, "
            "four A158 orders, shared R2 prefix, 22 unchanged suffix rounds and "
            "all 1,344 rate bits."
        ),
        "parameters": {
            "variant": "SHAKE128",
            "seed": SEED,
            "window_bits": WINDOW_BITS,
            "affine_shift": AFFINE_SHIFT,
            "formula_count": 4,
            "rlimit_per_formula": Z3_RLIMIT,
            "execution_mode": "sequential_one_thread_per_formula",
            "solver": solver_version,
            "solver_wallclock_limit_used": False,
            "external_safety_timeout_seconds": EXTERNAL_SAFETY_TIMEOUT_SECONDS,
            "wallclock_excluded_from_canonical_result": True,
        },
        "anchor_gates": {
            "A167_protocol": {
                "artifact_sha256": PROTOCOL_SHA256,
                "protocol_state": analysis["protocol"]["protocol_state"],
                "information_boundary": analysis["protocol"]["information_boundary"],
            },
            "A166": {
                "artifact_sha256": A166_SHA256,
                "comparison_sha256": A166_COMPARISON_SHA256,
                "decision_deltas": [row["decision_delta"] for row in a166["comparison"]],
            },
            "A164": {
                "artifact_sha256": A164_SHA256,
                "full_factorial_matrix_sha256": a164["full_factorial_matrix_sha256"],
            },
        },
        "control_plan": analysis["control_plan"],
        "control_plan_sha256": analysis["control_plan_sha256"],
        "formula_plan": analysis["formula_plan"],
        "formula_plan_sha256": analysis["formula_plan_sha256"],
        "execution": executions,
        "execution_summary": summary,
        "status_counts": status_counts,
        "confirmed_models": confirmed_models,
        "effect_decomposition": decomposition,
        "effect_decomposition_sha256": _canonical_sha256(decomposition),
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
        raise RuntimeError("A167 final artifact reopen gate failed")
    return {
        "json_sha256": _sha256(raw),
        "causal_sha256": reader.file_sha256,
        "causal_graph_sha256": reader.graph_sha256,
        "status_counts": status_counts,
        "confirmed_model_count": len(confirmed_models),
        "aggregate_dominant_component": decomposition["aggregate_dominant_component"],
        "alias_node_effects": [
            row["alias_node_effect_A167_minus_A164"] for row in decomposition["rows"]
        ],
        "downstream_ID_shift_effects": [
            row["downstream_ID_shift_effect_A166_minus_A167"] for row in decomposition["rows"]
        ],
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
        default=Path(__file__).parents[2] / "build" / "shake-r2-a167",
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
                    "control_plan_sha256": analysis["control_plan_sha256"],
                    "formula_plan_sha256": analysis["formula_plan_sha256"],
                    "formulas": [
                        {
                            "name": row["name"],
                            "bytes": row["formula_bytes"],
                            "sha256": row["formula_sha256"],
                            "declaration_sequence_sha256": row["encoding"][
                                "declaration_sequence_sha256"
                            ],
                            "variables": row["encoding"]["total_variables"],
                            "assertions": row["encoding"]["total_assertions"],
                            "padding": row["encoding"]["R2_id_padding_names"],
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

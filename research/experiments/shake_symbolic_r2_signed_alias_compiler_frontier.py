#!/usr/bin/env python3
"""Normalize signed unit-affine R2 aliases for the universal A164 gauge."""

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


_A164 = _import_sibling(
    "shake_symbolic_r2_four_gauge_factorial_completion.py",
    "shake_symbolic_r2_signed_alias_a164_base",
)
_A163 = _A164._A163
_A162 = _A164._A162
_A160 = _A163._A160
_A158 = _A164._A158
_A157 = _A163._A157
_A156 = _A164._A156
_BASE = _A163._BASE
_NATIVE = _A163._NATIVE
_WINDOW = _A163._WINDOW
_R1 = _A163._R1
_SMT = _A163._SMT
_SYMBOLIC = _A163._SYMBOLIC

ATTEMPT_ID = "A166"
SCHEMA = "shake-symbolic-r2-signed-alias-compiler-frontier-v1"
SEED = _A163.SEED
WINDOW_BITS = _A163.WINDOW_BITS
Z3_RLIMIT = _A163.Z3_RLIMIT
EXTERNAL_SAFETY_TIMEOUT_SECONDS = _A163.EXTERNAL_SAFETY_TIMEOUT_SECONDS
AFFINE_SHIFT = 0x4E1E28
A164_FILENAME = _A164.RESULT_FILENAME
A164_SHA256 = "c8b4f7446b3e78b3914f90e5fbbc201d00771a917c7fafe16eba6e134e0f55ab"
A162_FILENAME = _A162.RESULT_FILENAME
A162_SHA256 = _A164.A162_SHA256
PROTOCOL_FILENAME = "shake_symbolic_r2_signed_alias_compiler_frontier_v1.json"
PROTOCOL_SHA256 = "6c35f7d94045a9941f8ad72ceaa9e43471ff23c4757be2ed4e1d3887b588b77f"
PROTOCOL_SCHEMA = "shake-symbolic-r2-signed-alias-compiler-frontier-protocol-v1"
RESULT_FILENAME = "shake_symbolic_r2_signed_alias_compiler_frontier_v1.json"
CAUSAL_FILENAME = "shake_symbolic_r2_signed_alias_compiler_frontier_v1.causal"


def _sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _canonical_sha256(value: Any) -> str:
    return _sha256(
        json.dumps(
            value,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode()
    )


def _load_anchor_gates(results_dir: Path) -> tuple[dict[str, Any], dict[str, Any]]:
    a164 = _A156._load_json_gate(
        results_dir / A164_FILENAME,
        A164_SHA256,
        _A164.SCHEMA,
    )
    a162 = _A156._load_json_gate(
        results_dir / A162_FILENAME,
        A162_SHA256,
        _A162.SCHEMA,
    )
    matrix = a164.get("full_factorial_matrix", [])
    selected = [row for row in matrix if row.get("affine_shift") == AFFINE_SHIFT]
    if (
        a164.get("full_factorial_matrix_sha256")
        != "b049c248886b5eba988c9be19510b4d24b735f5b176045b60d0578e5cf63611b"
        or a164.get("factorial_decomposition_sha256")
        != "a78dbdcfa838f86a1f0884c22fb078412e0623a98bd882126e61df6f74a9d0d4"
        or len(matrix) != 16
        or len(selected) != 4
        or {row["order_name"] for row in selected} != set(_A158.ORDER_NAMES)
        or any(
            min(
                candidate["decisions"]
                for candidate in matrix
                if candidate["order_name"] == row["order_name"]
            )
            != row["decisions"]
            for row in selected
        )
        or a162.get("semantic_gate_plan_sha256")
        != "d4a1f290e5dc651a22a15c88a0d8f76a19351ce30578315419bb3d446d2b53ba"
        or AFFINE_SHIFT not in {row.get("shift") for row in a162.get("semantic_gates", [])}
        or Z3_RLIMIT != 500_000_000
        or EXTERNAL_SAFETY_TIMEOUT_SECONDS != 300
    ):
        raise RuntimeError("A166 A162/A164 universal-gauge anchor gate failed")
    return a164, a162


def _load_protocol_gate() -> dict[str, Any]:
    path = Path(__file__).parents[1] / "configs" / PROTOCOL_FILENAME
    protocol = _A156._load_json_gate(path, PROTOCOL_SHA256, PROTOCOL_SCHEMA)
    if (
        protocol.get("attempt_id") != ATTEMPT_ID
        or protocol.get("protocol_state") != "frozen_before_any_A166_solver_execution"
        or protocol.get("anchors", {}).get("A164", {}).get("sha256") != A164_SHA256
        or protocol.get("anchors", {}).get("A162", {}).get("sha256") != A162_SHA256
        or protocol.get("compiler_intervention", {}).get("semantic_change") is not False
        or protocol.get("information_boundary", {}).get(
            "A166_solver_outcomes_used_before_formula_freeze"
        )
        is not False
    ):
        raise RuntimeError("A166 frozen protocol identity gate failed")
    return protocol


def _validate_protocol_plan(protocol: dict[str, Any], analysis: dict[str, Any]) -> None:
    expected_rows = [
        [row["name"], row["formula_bytes"], row["formula_sha256"]]
        for row in analysis["formula_plan"]
    ]
    if (
        protocol["structural_analysis"]["sha256"] != analysis["structural_analysis_sha256"]
        or protocol["structural_analysis"]["suffix_cone_plan_sha256"]
        != analysis["suffix_cone_frontier"]["depth_plan_sha256"]
        or protocol["structural_analysis"]["unit_affine_theorem_sha256"]
        != analysis["unit_affine_theorem"]["theorem_sha256"]
        or protocol["formula_plan"]["sha256"] != analysis["formula_plan_sha256"]
        or protocol["formula_plan"]["rows"] != expected_rows
    ):
        raise RuntimeError("A166 regenerated analysis/formulas differ from frozen protocol")


def _backward_suffix_cone_round(output_weights: Sequence[int]) -> list[int]:
    if len(output_weights) != 1_600 or any(value < 0 for value in output_weights):
        raise ValueError("suffix-cone weights must contain 1,600 nonnegative integers")

    rho_pi = [0] * 1_600
    for y in range(5):
        for x in range(5):
            lane = x + 5 * y
            next_lane = ((x + 1) % 5) + 5 * y
            next2_lane = ((x + 2) % 5) + 5 * y
            for bit in range(64):
                weight = int(output_weights[lane * 64 + bit])
                rho_pi[lane * 64 + bit] += weight
                rho_pi[next_lane * 64 + bit] += weight
                rho_pi[next2_lane * 64 + bit] += weight

    theta = [0] * 1_600
    for x in range(5):
        for y in range(5):
            source = x + 5 * y
            destination = y + 5 * ((2 * x + 3 * y) % 5)
            rotation = int(_BASE.ROTATION_OFFSETS[x, y])
            for bit in range(64):
                theta[source * 64 + ((bit - rotation) % 64)] += rho_pi[destination * 64 + bit]

    state = [0] * 1_600
    columns = [0] * 320
    for y in range(5):
        for x in range(5):
            lane = x + 5 * y
            for bit in range(64):
                weight = theta[lane * 64 + bit]
                state[lane * 64 + bit] += weight
                columns[((x - 1) % 5) * 64 + bit] += weight
                columns[((x + 1) % 5) * 64 + ((bit - 1) % 64)] += weight
    for x in range(5):
        for bit in range(64):
            weight = columns[x * 64 + bit]
            for y in range(5):
                state[(x + 5 * y) * 64 + bit] += weight
    return state


def _suffix_cone_frontier(
    original: Sequence[frozenset[int]],
    shifts: Sequence[int],
    rate_lanes: int,
) -> dict[str, Any]:
    shifted = {shift: _A160._shift_polynomials(original, shift, WINDOW_BITS) for shift in shifts}
    weights = [int(coordinate // 64 < rate_lanes) for coordinate in range(1_600)]
    depths = []
    for depth in range(23):
        scores = []
        for shift in shifts:
            polynomials = shifted[shift]
            affine_score = sum(
                weights[coordinate] * sum(mask.bit_count() <= 1 for mask in polynomial)
                for coordinate, polynomial in enumerate(polynomials)
            )
            linear_score = sum(
                weights[coordinate] * sum(mask.bit_count() == 1 for mask in polynomial)
                for coordinate, polynomial in enumerate(polynomials)
            )
            constant_score = sum(
                weights[coordinate] * int(0 in polynomial)
                for coordinate, polynomial in enumerate(polynomials)
            )
            alias_weight = sum(
                weights[coordinate] * int(len(polynomial) == 1)
                for coordinate, polynomial in enumerate(polynomials)
            )
            scores.append(
                {
                    "affine_shift": shift,
                    "affine_shift_hex": f"0x{shift:06x}",
                    "affine_incidence_score": affine_score,
                    "linear_incidence_score": linear_score,
                    "constant_incidence_score": constant_score,
                    "direct_alias_weight": alias_weight,
                }
            )
        winner = min(scores, key=lambda row: (row["affine_incidence_score"], row["affine_shift"]))
        depths.append(
            {
                "suffix_rounds_backpropagated": depth,
                "weight_minimum": min(weights),
                "weight_maximum": max(weights),
                "weight_sum": sum(weights),
                "weight_vector_sha256": _canonical_sha256([str(value) for value in weights]),
                "scores": scores,
                "minimum_affine_incidence_shift": winner["affine_shift"],
                "minimum_affine_incidence_shift_hex": winner["affine_shift_hex"],
            }
        )
        weights = _backward_suffix_cone_round(weights)
    return {
        "definition": (
            "exact_syntactic_path_multiplicity_from_the_1344_final_rate_constraints_"
            "backward_through_the_compiled_Keccak_suffix_DAG"
        ),
        "target_bit_values_used": False,
        "solver_counters_used": False,
        "instrumented_assignment_used": False,
        "depths": depths,
        "depth_plan_sha256": _canonical_sha256(depths),
        "winner_at_every_depth": len({row["minimum_affine_incidence_shift"] for row in depths})
        == 1,
        "unique_winner_sequence": sorted({row["minimum_affine_incidence_shift"] for row in depths}),
        "A164_winner_selected_at_any_depth": any(
            row["minimum_affine_incidence_shift"] == AFFINE_SHIFT for row in depths
        ),
    }


def _unit_affine_theorem(
    original: Sequence[frozenset[int]],
    shifts: Sequence[int],
) -> dict[str, Any]:
    candidates = []
    for coordinate, polynomial in enumerate(original):
        quadratic = [mask for mask in polynomial if mask.bit_count() == 2]
        linear = [mask for mask in polynomial if mask.bit_count() == 1]
        if not quadratic and len(linear) == 1:
            input_coordinate = linear[0].bit_length() - 1
            candidates.append(
                {
                    "state_coordinate": coordinate,
                    "lane": coordinate // 64,
                    "bit": coordinate % 64,
                    "input_coordinate": input_coordinate,
                    "original_constant": 0 in polynomial,
                    "gauge_polarities": [
                        {
                            "affine_shift": shift,
                            "signed_literal": (
                                "negative"
                                if bool(0 in polynomial) ^ bool((shift >> input_coordinate) & 1)
                                else "positive"
                            ),
                        }
                        for shift in shifts
                    ],
                }
            )
    selected = []
    for row in candidates:
        polarity = next(
            item["signed_literal"]
            for item in row["gauge_polarities"]
            if item["affine_shift"] == AFFINE_SHIFT
        )
        selected.append(
            {
                "state_coordinate": row["state_coordinate"],
                "input_coordinate": row["input_coordinate"],
                "signed_literal": polarity,
            }
        )
    if len(candidates) != 5 or sum(row["signed_literal"] == "negative" for row in selected) != 1:
        raise RuntimeError("A166 exact five-coordinate signed-alias theorem differs")
    return {
        "unit_affine_coordinate_count": len(candidates),
        "coordinates": candidates,
        "selected_gauge": AFFINE_SHIFT,
        "selected_gauge_hex": f"0x{AFFINE_SHIFT:06x}",
        "selected_gauge_signed_literals": selected,
        "selected_positive_alias_count_under_A157_compiler": 4,
        "selected_negative_alias_count_materialized_under_A157_compiler": 1,
        "signed_alias_count_under_A166_compiler": 5,
        "theorem_sha256": _canonical_sha256(candidates),
    }


def _compile_signed_shared_r2_prefix(
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
            raise RuntimeError(f"A166 R2 monomial degree differs: {mask}")
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
    state_definitions = 0
    for coordinate, polynomial in enumerate(polynomials):
        ordered = sorted(polynomial)
        if len(ordered) == 1:
            state.append(monomial(ordered[0]))
            direct_alias_coordinates.append(coordinate)
            continue
        if len(ordered) == 2 and ordered[0] == 0 and ordered[1].bit_count() == 1:
            state.append(f"(not {monomial(ordered[1])})")
            complement_alias_coordinates.append(coordinate)
            continue
        state.append(writer.define(writer.xor(monomial(mask) for mask in ordered), "s"))
        state_definitions += 1

    if (
        len(monomials) != 301
        or definition_masks != predeclared
        or len(direct_alias_coordinates) + len(complement_alias_coordinates) != 5
        or len(complement_alias_coordinates) != 1
        or state_definitions != 1_595
    ):
        raise RuntimeError("A166 signed shared-R2 compiler shape differs")
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
            "R2_signed_alias_definition_count_eliminated": (
                len(direct_alias_coordinates) + len(complement_alias_coordinates)
            ),
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
    shifted = _A160._shift_polynomials(original, AFFINE_SHIFT, WINDOW_BITS)
    if (
        _SYMBOLIC._poly_hash(shifted, WINDOW_BITS) != expected_shifted_polynomial_sha256
        or _A160._coefficient_counts(shifted) != expected_coefficient_incidence
    ):
        raise RuntimeError("A166 selected shifted R2 polynomial differs")
    shifted_input_to_solver_rows = _A156._input_to_solver_rows(variable_to_shifted_input)
    transformed = _A163._A155._substitute_linear_basis(
        shifted,
        shifted_input_to_solver_rows,
        WINDOW_BITS,
    )
    writer = _SMT.BooleanSMT(SEED)
    inputs, state, prefix = _compile_signed_shared_r2_prefix(writer, transformed)
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
            "compiler": "signed_unit_affine_alias_normalization",
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
            "target_rate_input_used_for_compiler_selection": False,
        },
    )


def _formula_frontier(
    problem: dict[str, Any],
    variant: Any,
    orders: dict[str, list[int]],
    semantic_gate: dict[str, Any],
) -> tuple[list[dict[str, Any]], dict[str, bytes]]:
    rows = []
    formulas = {}
    for order_name in _A158.ORDER_NAMES:
        name = f"{order_name}__signed_unit_affine_alias"
        writer, inputs, encoding = _encode_problem(
            problem,
            variant,
            name=name,
            order_name=order_name,
            variable_to_shifted_input=orders[order_name],
            expected_shifted_polynomial_sha256=semantic_gate["shifted_R2_polynomial_state_sha256"],
            expected_coefficient_incidence=semantic_gate["coefficient_incidence"],
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
        "Boolean_SMT_shared_R2_signed_unit_affine_alias_fixed_rlimit"
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
        raise ValueError("A166 solver work directory must be empty")
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
            results.append(
                _A163._verify_solver_row(
                    dict(row),
                    result,
                    problem,
                    variant,
                )
            )
    finally:
        for path in work_dir.glob("*.smt2"):
            path.unlink(missing_ok=True)
    if any(work_dir.iterdir()):
        raise RuntimeError("A166 solver formula cleanup failed")
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


def _comparison(a164: dict[str, Any], executions: Sequence[dict[str, Any]]) -> list[dict[str, Any]]:
    controls = {
        row["order_name"]: row
        for row in a164["full_factorial_matrix"]
        if row["affine_shift"] == AFFINE_SHIFT
    }
    rows = []
    for execution in executions:
        order_name = execution["encoding"]["order_name"]
        control = controls[order_name]
        decisions = int(execution["solver"]["stats"].get("decisions", 0))
        conflicts = int(execution["solver"]["stats"].get("conflicts", 0))
        rows.append(
            {
                "order_name": order_name,
                "affine_shift": AFFINE_SHIFT,
                "A164_status": control["status"],
                "A164_decisions": control["decisions"],
                "A164_conflicts": control["conflicts"],
                "signed_alias_status": execution["solver"]["status"],
                "signed_alias_decisions": decisions,
                "signed_alias_conflicts": conflicts,
                "decision_delta": decisions - control["decisions"],
                "conflict_delta": conflicts - control["conflicts"],
                "same_configured_rlimit": True,
                "semantic_relation_unchanged": True,
                "additional_signed_aliases": 1,
                "removed_variables": 1,
                "removed_assertions": 1,
            }
        )
    return rows


def _posthoc_summary(
    problem: dict[str, Any], variant: Any, executions: Sequence[dict[str, Any]]
) -> dict[str, Any]:
    actual = _WINDOW._extract_window(problem["base_state"], variant, problem["positions"])
    return {
        "instrumented_input_assignment": actual,
        "extracted_only_after_every_A166_execution": True,
        "used_for_cone_compiler_formula_order_or_execution": False,
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
        experiment="shake_symbolic_r2_signed_alias_compiler_frontier",
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
        "shake128-a164-universal-four-order-gauge",
        "shake128-a166-cone-and-unit-affine-theorem",
        "shake128-a166-four-signed-alias-formulas",
        "shake128-a166-fixed-resource-execution",
        "shake128-a166-signed-alias-intervention-comparison",
    ]
    builder.add_triplet(
        edge_id=ids[0],
        trigger="A164:complete_four_gauge_by_four_order_matrix",
        mechanism="select_the_unique_gauge_with_the_minimum_decision_count_in_every_frozen_order",
        outcome="A166:universal_0x4e1e28_gauge_anchor",
        confidence=1.0,
        evidence_kind="complete_factorial_main_effect",
        source=A164_SHA256,
        attrs={"A164_gate": payload["anchor_gates"]["A164"]},
    )
    builder.add_triplet(
        edge_id=ids[1],
        trigger="A166:universal_0x4e1e28_gauge_anchor",
        mechanism="backpropagate_exact_suffix_DAG_path_weights_and_enumerate_all_unit_affine_R2_coordinates",
        outcome="A166:static_cone_boundary_and_five_signed_aliases",
        confidence=1.0,
        evidence_kind="exact_structural_reader",
        source=payload["structural_analysis_sha256"],
        provenance=[ids[0]],
        attrs={
            "suffix_cone_frontier": payload["suffix_cone_frontier"],
            "unit_affine_theorem": payload["unit_affine_theorem"],
        },
    )
    builder.add_triplet(
        edge_id=ids[2],
        trigger="A166:static_cone_boundary_and_five_signed_aliases",
        mechanism="inline_positive_and_negative_unit_affine_literals_without_changing_any_polynomial_or_suffix_round",
        outcome="A166:four_exact_signed_alias_fullround_formulas",
        confidence=1.0,
        evidence_kind="deterministic_semantics_preserving_compiler_intervention",
        source=payload["formula_plan_sha256"],
        provenance=[ids[1]],
        attrs={"formula_plan": payload["formula_plan"]},
    )
    builder.add_triplet(
        edge_id=ids[3],
        trigger="A166:four_exact_signed_alias_fullround_formulas",
        mechanism="execute_each_order_under_the_unchanged_A159_fixed_resource_protocol_with_independent_model_mapping",
        outcome="A166:four_signed_alias_solver_observations",
        confidence=1.0,
        evidence_kind="fixed_resource_execution_and_complete_rate_gate",
        source="Z3_4.15.4_plus_independent_NumPy_lane_core",
        provenance=[ids[2]],
        attrs={"execution_summary": payload["execution_summary"]},
    )
    builder.add_triplet(
        edge_id=ids[4],
        trigger="A166:four_signed_alias_solver_observations",
        mechanism="compare_each_semantics_identical_order_with_its_A164_0x4e1e28_control",
        outcome="A166:signed_alias_compiler_intervention_frontier",
        confidence=1.0,
        evidence_kind="same_resource_semantics_preserving_intervention",
        source=payload["comparison_sha256"],
        provenance=[ids[3]],
        attrs={
            "comparison": payload["comparison"],
            "posthoc": payload["posthoc"],
        },
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
        raise RuntimeError("A166 Causal provenance chain failed validation")
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


def analyze(results_dir: Path) -> dict[str, Any]:
    protocol = _load_protocol_gate()
    a164, a162 = _load_anchor_gates(results_dir)
    baseline = _A163.analyze(results_dir)
    variant = baseline["variant"]
    problem = baseline["problem"]
    orders = {
        name: baseline["rows"][2 * index]["encoding"]["variable_to_shifted_input_coordinate"]
        for index, name in enumerate(_A158.ORDER_NAMES)
    }
    template = _WINDOW._clear_window(problem["base_state"], variant, problem["positions"])
    original = _R1._SPLIT._symbolic_prefix_polynomials(
        template,
        variant,
        problem["positions"],
        2,
    )
    shifts = sorted(row["shift"] for row in a162["semantic_gates"])
    cone = _suffix_cone_frontier(original, shifts, variant.rate_lanes)
    theorem = _unit_affine_theorem(original, shifts)
    semantic_gate = next(row for row in a162["semantic_gates"] if row["shift"] == AFFINE_SHIFT)
    rows, formulas = _formula_frontier(
        problem,
        variant,
        orders,
        semantic_gate,
    )
    plan = _formula_plan(rows)
    analysis = {
        "protocol": protocol,
        "anchors": (a164, a162),
        "variant": variant,
        "problem": problem,
        "orders": orders,
        "suffix_cone_frontier": cone,
        "unit_affine_theorem": theorem,
        "structural_analysis_sha256": _canonical_sha256(
            {"suffix_cone_frontier": cone, "unit_affine_theorem": theorem}
        ),
        "rows": rows,
        "formulas": formulas,
        "formula_plan": plan,
        "formula_plan_sha256": _canonical_sha256(plan),
    }
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
    a164, a162 = analysis["anchors"]
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
    comparison = _comparison(a164, executions)
    posthoc = _posthoc_summary(analysis["problem"], analysis["variant"], executions)
    payload: dict[str, Any] = {
        "schema": SCHEMA,
        "attempt_id": ATTEMPT_ID,
        "evidence_stage": "SIGNED_UNIT_AFFINE_ALIAS_COMPILER_FRONTIER_EXECUTED",
        "result": (
            "All five exact R2 unit-affine coordinates are normalized to signed "
            "literals for A164's universal gauge across all four frozen orders."
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
            "A166_protocol": {
                "artifact_sha256": PROTOCOL_SHA256,
                "protocol_state": analysis["protocol"]["protocol_state"],
                "information_boundary": analysis["protocol"]["information_boundary"],
            },
            "A164": {
                "artifact_sha256": A164_SHA256,
                "full_factorial_matrix_sha256": a164["full_factorial_matrix_sha256"],
                "factorial_decomposition_sha256": a164["factorial_decomposition_sha256"],
                "universal_gauge": AFFINE_SHIFT,
            },
            "A162": {
                "artifact_sha256": A162_SHA256,
                "semantic_gate_plan_sha256": a162["semantic_gate_plan_sha256"],
            },
        },
        "suffix_cone_frontier": analysis["suffix_cone_frontier"],
        "unit_affine_theorem": analysis["unit_affine_theorem"],
        "structural_analysis_sha256": analysis["structural_analysis_sha256"],
        "formula_plan": analysis["formula_plan"],
        "formula_plan_sha256": analysis["formula_plan_sha256"],
        "execution": executions,
        "execution_summary": summary,
        "status_counts": status_counts,
        "confirmed_models": confirmed_models,
        "comparison": comparison,
        "comparison_sha256": _canonical_sha256(comparison),
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
        raise RuntimeError("A166 final artifact reopen gate failed")
    return {
        "json_sha256": _sha256(raw),
        "causal_sha256": reader.file_sha256,
        "causal_graph_sha256": reader.graph_sha256,
        "status_counts": status_counts,
        "confirmed_model_count": len(confirmed_models),
        "decision_deltas": [row["decision_delta"] for row in comparison],
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
        default=Path(__file__).parents[2] / "build" / "shake-r2-a166",
    )
    parser.add_argument(
        "--z3",
        type=Path,
        default=Path(shutil.which("z3") or "/opt/homebrew/bin/z3"),
    )
    args = parser.parse_args(argv)
    if args.analyze_only:
        analysis = analyze(args.results_dir.resolve())
        print(
            json.dumps(
                {
                    "protocol_sha256": PROTOCOL_SHA256,
                    "structural_analysis_sha256": analysis["structural_analysis_sha256"],
                    "suffix_cone_plan_sha256": analysis["suffix_cone_frontier"][
                        "depth_plan_sha256"
                    ],
                    "unit_affine_theorem": analysis["unit_affine_theorem"],
                    "formula_plan_sha256": analysis["formula_plan_sha256"],
                    "formulas": [
                        {
                            "name": row["name"],
                            "bytes": row["formula_bytes"],
                            "sha256": row["formula_sha256"],
                            "variables": row["encoding"]["total_variables"],
                            "assertions": row["encoding"]["total_assertions"],
                            "signed_aliases": row["encoding"]["R2_signed_alias_coordinates"],
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

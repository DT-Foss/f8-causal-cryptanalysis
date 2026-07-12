#!/usr/bin/env python3
"""Transfer the exact A160 affine gauge across all A158 weighted orders."""

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


_A159 = _import_sibling(
    "shake_symbolic_r2_fixed_rlimit_order_frontier.py",
    "shake_symbolic_r2_affine_gauge_solver_a159_base",
)
_A160 = _import_sibling(
    "shake_symbolic_r2_affine_gauge_reader.py",
    "shake_symbolic_r2_affine_gauge_solver_a160_base",
)

_A158 = _A159._A158
_A157 = _A158._A157
_A156 = _A159._A156
_A155 = _A157._A155
_A154 = _A157._A154
_BASE = _A158._BASE
_NATIVE = _A158._NATIVE
_WINDOW = _A158._WINDOW
_R1 = _A158._R1
_SMT = _A158._SMT
_SYMBOLIC = _A158._SYMBOLIC

ATTEMPT_ID = "A161"
SCHEMA = "shake-symbolic-r2-affine-gauge-solver-frontier-v1"
SEED = _A159.SEED
WINDOW_BITS = _A159.WINDOW_BITS
Z3_RLIMIT = _A159.Z3_RLIMIT
EXTERNAL_SAFETY_TIMEOUT_SECONDS = _A159.EXTERNAL_SAFETY_TIMEOUT_SECONDS
A159_FILENAME = _A159.RESULT_FILENAME
A159_SHA256 = "95eefebe7b40a508fb1266782e9542cf3e27b04c2aa0d0ac7dcfcce126593f2a"
A160_FILENAME = _A160.RESULT_FILENAME
A160_SHA256 = "725d5fcddba7ff4ba4e1a90fac5dd90d34990f4b9f62bf7cfe06e56396de73aa"
AFFINE_SHIFT = 9_316_059
AFFINE_SHIFT_HEX = "0x8e26db"
SHIFTED_R2_POLYNOMIAL_SHA256 = "cc5e540d6650a78c607ef5a1c0071894be61cc32f711aecf75f1277ab9d68dda"
RESULT_FILENAME = "shake_symbolic_r2_affine_gauge_solver_frontier_v1.json"
CAUSAL_FILENAME = "shake_symbolic_r2_affine_gauge_solver_frontier_v1.causal"


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
    a159 = _A156._load_json_gate(results_dir / A159_FILENAME, A159_SHA256, _A159.SCHEMA)
    a160 = _A156._load_json_gate(results_dir / A160_FILENAME, A160_SHA256, _A160.SCHEMA)
    expected_decisions = [6_940, 14_386, 13_298, 18_936]
    if (
        Z3_RLIMIT != 500_000_000
        or a159.get("parameters", {}).get("rlimit_per_formula") != Z3_RLIMIT
        or any(row.get("rlimit") != Z3_RLIMIT for row in a159.get("fixed_resource_plan", []))
        or EXTERNAL_SAFETY_TIMEOUT_SECONDS != 300
        or a159.get("parameters", {}).get("external_safety_timeout_seconds")
        != EXTERNAL_SAFETY_TIMEOUT_SECONDS
        or a159.get("parameters", {}).get("formula_count") != len(_A158.ORDER_NAMES)
        or [row.get("name") for row in a159.get("fixed_resource_plan", [])]
        != list(_A158.ORDER_NAMES)
        or [row.get("name") for row in a159.get("execution_summary", [])] != list(_A158.ORDER_NAMES)
        or a159.get("fixed_resource_plan_sha256")
        != "41bc4b44a13cbce85545a495f3abb95e35fc679a0515fb0dd90e199d10b62b48"
        or a159.get("status_counts") != {"error": 0, "sat": 0, "unknown": 4, "unsat": 0}
        or [row.get("stats", {}).get("decisions") for row in a159.get("execution_summary", [])]
        != expected_decisions
        or any(
            row.get("termination") != "fixed_rlimit_exhausted"
            for row in a159.get("execution_summary", [])
        )
    ):
        raise RuntimeError("A159 fixed-resource control gate failed")
    optimum = a160.get("global_optimum", {})
    shifted = a160.get("shifted_R2", {})
    if (
        optimum.get("minimum_shift") != AFFINE_SHIFT
        or optimum.get("minimum_shift_hex") != AFFINE_SHIFT_HEX
        or optimum.get("minimum_tie_count") != 1
        or optimum.get("minimum_linear_incidence") != 8_413
        or optimum.get("global_optimum_certified") is not True
        or shifted.get("polynomial_state_sha256") != SHIFTED_R2_POLYNOMIAL_SHA256
        or shifted.get("per_coordinate_quadratic_terms_unchanged") is not True
        or shifted.get("quadratic_coefficient_incidence") != 15_972
        or a160.get("verification", {}).get("three_way_state_bits_checked") != 307_200
    ):
        raise RuntimeError("A160 exact affine-gauge gate failed")
    return a159, a160


def _encode_problem(
    problem: dict[str, Any],
    variant: Any,
    name: str,
    variable_to_shifted_input: Sequence[int],
) -> tuple[Any, list[str], dict[str, Any]]:
    template = _WINDOW._clear_window(problem["base_state"], variant, problem["positions"])
    original = _R1._SPLIT._symbolic_prefix_polynomials(template, variant, problem["positions"], 2)
    if _SYMBOLIC._poly_hash(original, WINDOW_BITS) != _A157.ORIGINAL_R2_POLYNOMIAL_SHA256:
        raise RuntimeError("A161 original R2 polynomial state differs")
    shifted = _A160._shift_polynomials(original, AFFINE_SHIFT, WINDOW_BITS)
    if _SYMBOLIC._poly_hash(shifted, WINDOW_BITS) != SHIFTED_R2_POLYNOMIAL_SHA256:
        raise RuntimeError("A161 shifted R2 polynomial state differs")
    shifted_input_to_solver_rows = _A156._input_to_solver_rows(variable_to_shifted_input)
    transformed = _A155._substitute_linear_basis(shifted, shifted_input_to_solver_rows, WINDOW_BITS)
    coefficient_counts = _A160._coefficient_counts(transformed)
    if coefficient_counts != {"constant": 823, "linear": 8_413, "quadratic": 15_972}:
        raise RuntimeError("A161 affine-gauge coefficient counts differ")
    writer = _SMT.BooleanSMT(SEED)
    inputs, state, prefix = _A157._compile_shared_r2_prefix(
        writer,
        transformed,
        "decreasing_coordinate_occurrence_then_numeric_mask",
    )
    state, suffix = _SMT._compile_suffix(writer, state, list(range(2, 24)))
    before_outputs = writer.assertions
    for lane in range(variant.rate_lanes):
        lane_value = int(problem["target"][0, lane])
        for bit in range(64):
            literal = state[lane * 64 + bit]
            writer.constrain(literal if ((lane_value >> bit) & 1) else f"(not {literal})")
    encoding = {
        "name": name,
        "order_derivation": name,
        "variable_to_shifted_input_coordinate": list(variable_to_shifted_input),
        "shifted_input_to_solver_row_masks_hex": [
            f"{value:06x}" for value in shifted_input_to_solver_rows
        ],
        "affine_shift_original_input_mask": AFFINE_SHIFT,
        "affine_shift_original_input_mask_hex": AFFINE_SHIFT_HEX,
        "affine_shift_rule": "original_input_equals_shifted_input_XOR_mask",
        "model_mapping": "solver_order_to_shifted_input_permutation_then_XOR_affine_shift",
        "R2_polynomial_state_sha256_in_solver_basis": _SYMBOLIC._poly_hash(
            transformed, WINDOW_BITS
        ),
        "semantic_original_R2_polynomial_state_sha256": (_A157.ORIGINAL_R2_POLYNOMIAL_SHA256),
        "semantic_shifted_R2_polynomial_state_sha256": SHIFTED_R2_POLYNOMIAL_SHA256,
        "shifted_R2_coefficient_incidence": coefficient_counts,
        **prefix,
        **suffix,
        "total_variables": writer.variables,
        "total_assertions": writer.assertions,
        "output_assertions": writer.assertions - before_outputs,
        "target_rate_bits": variant.rate_bits,
        "instrumented_assignment_input_used": False,
        "solver_observation_input_used_for_formula_construction": False,
        "target_rate_input_used_for_gauge_selection": False,
    }
    return writer, inputs, encoding


def _formula_frontier(
    problem: dict[str, Any], variant: Any, orders: dict[str, list[int]]
) -> tuple[list[dict[str, Any]], dict[str, bytes]]:
    rows = []
    formulas = {}
    for name, order in orders.items():
        writer, inputs, encoding = _encode_problem(problem, variant, name, order)
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


def _verify_solver_row(
    row: dict[str, Any],
    result: dict[str, Any],
    problem: dict[str, Any],
    variant: Any,
) -> dict[str, Any]:
    solver_assignment = result["solver_basis_assignment"]
    if result["status"] == "sat" and solver_assignment is None:
        raise RuntimeError(f"{row['name']} returned SAT without a complete input model")
    if result["status"] != "sat" and solver_assignment is not None:
        raise RuntimeError(f"{row['name']} returned an assignment with non-SAT status")
    shifted_assignment = None
    input_assignment = None
    verification = None
    if solver_assignment is not None:
        inverse_rows = [
            int(value, 16) for value in row["encoding"]["shifted_input_to_solver_row_masks_hex"]
        ]
        shifted_assignment = _A154._recover_input(solver_assignment, inverse_rows)
        input_assignment = shifted_assignment ^ AFFINE_SHIFT
        verification = _A156._VERIFY(problem, variant, input_assignment)
        if not (
            verification.get("complete_rate_match") is True
            and verification.get("rate_bits_checked") == variant.rate_bits
            and verification.get("candidate_rate_sha256") == verification.get("target_rate_sha256")
        ):
            raise RuntimeError(f"{row['name']} emitted an independently invalid affine-gauge model")
    return {
        **row,
        "solver": result,
        "shifted_input_coordinate_assignment": shifted_assignment,
        "input_coordinate_assignment": input_assignment,
        "independent_complete_rate_check": verification,
        "independently_confirmed_model": verification is not None,
        "model_mapping": "solver_order_to_shifted_input_permutation_then_XOR_affine_shift",
    }


def _run_z3_rlimit(z3: Path, path: Path, inputs: list[str]) -> dict[str, Any]:
    result = _A159._run_z3_rlimit(z3, path, inputs)
    result["command_parameters"]["representation"] = (
        "Boolean_SMT_native_nary_XOR_shared_R2_exact_affine_gauge_fixed_rlimit"
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
        raise ValueError("affine-gauge solver work directory must be empty")
    results = []
    try:
        for row in formula_rows:
            raw = formulas[row["name"]]
            if len(raw) != row["formula_bytes"] or _sha256(raw) != row["formula_sha256"]:
                raise RuntimeError(f"{row['name']} affine-gauge formula differs")
            path = work_dir / f"{row['execution_order']:02d}_{row['name']}.smt2"
            path.write_bytes(raw)
            if path.read_bytes() != raw:
                raise RuntimeError(f"{row['name']} formula write/reopen gate failed")
            result = _run_z3_rlimit(z3, path, row["solver_input_names"])
            path.unlink(missing_ok=True)
            status = result["status"]
            return_code = result["return_code"]
            expected_resource_stop = (
                status == "unknown"
                and return_code in (0, 1)
                and result["stats"].get("rlimit-count", 0) >= Z3_RLIMIT
                and result["termination"] == "fixed_rlimit_exhausted"
            )
            solved = status in ("sat", "unsat") and return_code == 0
            if not (expected_resource_stop or solved):
                raise RuntimeError(f"{row['name']} affine-gauge execution failed: {result}")
            results.append(_verify_solver_row(dict(row), result, problem, variant))
    finally:
        for path in work_dir.glob("*.smt2"):
            path.unlink(missing_ok=True)
    if any(work_dir.iterdir()):
        raise RuntimeError("affine-gauge solver formula cleanup failed")
    return results


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


def _execution_summary(executions: Sequence[dict[str, Any]]) -> list[dict[str, Any]]:
    return [
        {
            "name": row["name"],
            "status": row["solver"]["status"],
            "return_code": row["solver"]["return_code"],
            "termination": row["solver"]["termination"],
            "canonical_observation_sha256": row["solver"]["canonical_observation_sha256"],
            "stats": row["solver"]["stats"],
            "independently_confirmed_model": row["independently_confirmed_model"],
        }
        for row in executions
    ]


def _baseline_comparison(
    baseline: dict[str, Any], executions: Sequence[dict[str, Any]]
) -> list[dict[str, Any]]:
    controls = {row["name"]: row for row in baseline["execution_summary"]}
    rows = []
    for execution in executions:
        name = execution["name"]
        control = controls[name]
        current = execution["solver"]
        control_formula = next(
            row for row in baseline["fixed_resource_plan"] if row["name"] == name
        )
        current_decisions = int(current["stats"].get("decisions", 0))
        current_conflicts = int(current["stats"].get("conflicts", 0))
        rows.append(
            {
                "name": name,
                "control_formula_bytes": control_formula["formula_bytes"],
                "gauge_formula_bytes": execution["formula_bytes"],
                "formula_byte_delta": execution["formula_bytes"] - control_formula["formula_bytes"],
                "control_formula_sha256": control_formula["formula_sha256"],
                "gauge_formula_sha256": execution["formula_sha256"],
                "control_status": control["status"],
                "gauge_status": current["status"],
                "control_decisions": control["stats"]["decisions"],
                "gauge_decisions": current_decisions,
                "decision_delta": current_decisions - control["stats"]["decisions"],
                "control_conflicts": control["stats"]["conflicts"],
                "gauge_conflicts": current_conflicts,
                "conflict_delta": current_conflicts - control["stats"]["conflicts"],
                "control_rlimit_count": control["stats"]["rlimit-count"],
                "gauge_rlimit_count": current["stats"]["rlimit-count"],
                "same_configured_rlimit": True,
            }
        )
    return rows


def _posthoc_summary(
    problem: dict[str, Any], variant: Any, executions: Sequence[dict[str, Any]]
) -> dict[str, Any]:
    actual = _WINDOW._extract_window(problem["base_state"], variant, problem["positions"])
    shifted_actual = actual ^ AFFINE_SHIFT
    return {
        "instrumented_input_assignment": actual,
        "instrumented_shifted_assignment": shifted_actual,
        "extracted_only_after_every_encoder_execution": True,
        "used_for_formula_construction_order_gauge_or_execution": False,
        "encoder_rows": [
            {
                "name": row["name"],
                "solver_status": row["solver"]["status"],
                "model_matches_instrumented_input_assignment": (
                    row["input_coordinate_assignment"] == actual
                    if row["input_coordinate_assignment"] is not None
                    else None
                ),
                "model_matches_instrumented_shifted_assignment": (
                    row["shifted_input_coordinate_assignment"] == shifted_actual
                    if row["shifted_input_coordinate_assignment"] is not None
                    else None
                ),
            }
            for row in executions
        ],
    }


def _build_causal(path: Path, payload: dict[str, Any]) -> dict[str, Any]:
    builder = CryptoCausalBuilder(
        experiment="shake_symbolic_r2_affine_gauge_solver_frontier",
        parameters={
            "attempt_id": ATTEMPT_ID,
            "variant": "shake128",
            "seed": SEED,
            "window_bits": WINDOW_BITS,
            "affine_shift": AFFINE_SHIFT,
            "rlimit_per_formula": Z3_RLIMIT,
            "formula_count": len(_A158.ORDER_NAMES),
        },
    )
    ids = [
        "shake128-a159-fixed-resource-four-order-control",
        "shake128-a160-exact-minimum-incidence-gauge",
        "shake128-a161-four-gauge-shifted-formulas",
        "shake128-a161-fixed-resource-gauge-execution",
    ]
    builder.add_triplet(
        edge_id=ids[0],
        trigger="A159:deterministic_resource_unit_order_frontier",
        mechanism="hash_gate_the_four_fixed_resource_control_observations_and_formula_plan",
        outcome="A161:fixed_resource_four_order_control",
        confidence=1.0,
        evidence_kind="retained_fixed_rlimit_control_artifact",
        source=A159_SHA256,
        attrs={"A159_gate": payload["anchor_gates"]["A159"]},
    )
    builder.add_triplet(
        edge_id=ids[1],
        trigger="A161:fixed_resource_four_order_control",
        mechanism="join_the_unique_complete_domain_A160_gauge_without_importing_a_target_model_or_solver_outcome",
        outcome="A161:exact_assignment_free_affine_gauge_intervention",
        confidence=1.0,
        evidence_kind="retained_global_Walsh_optimum_and_semantic_gate",
        source=A160_SHA256,
        provenance=[ids[0]],
        attrs={"A160_gate": payload["anchor_gates"]["A160"]},
    )
    builder.add_triplet(
        edge_id=ids[2],
        trigger="A161:exact_assignment_free_affine_gauge_intervention",
        mechanism="compile_the_same_four_weighted_orders_after_x_equals_y_XOR_the_certified_gauge",
        outcome="A161:four_exact_gauge_shifted_fullround_formulas",
        confidence=1.0,
        evidence_kind="deterministic_formula_compilation_before_solver_outcomes",
        source=payload["formula_plan_sha256"],
        provenance=[ids[1]],
        attrs={"formula_plan": payload["formula_plan"]},
    )
    builder.add_triplet(
        edge_id=ids[3],
        trigger="A161:four_exact_gauge_shifted_fullround_formulas",
        mechanism="execute_under_the_A159_fixed_rlimit_and_map_every_model_through_permutation_and_affine_shift_before_independent_rate_verification",
        outcome="A161:fixed_resource_affine_gauge_solver_frontier",
        confidence=1.0,
        evidence_kind="fixed_resource_factorial_intervention_and_independent_complete_rate_gate",
        source="Z3_4.15.4_plus_independent_NumPy_lane_core",
        provenance=[ids[2]],
        attrs={
            "execution_summary": payload["execution_summary"],
            "baseline_comparison": payload["baseline_comparison"],
            "confirmed_models": payload["confirmed_models"],
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
        or [by_id[edge_id]["provenance"] for edge_id in ids] != [[], [ids[0]], [ids[1]], [ids[2]]]
        or any(
            by_id[left]["outcome"] != by_id[right]["trigger"]
            for left, right in zip(ids[:-1], ids[1:], strict=True)
        )
    ):
        raise RuntimeError("A161 Causal provenance chain failed validation")
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
    a159, a160 = _load_anchor_gates(results_dir)
    baseline = _A159.analyze(results_dir)
    variant = _BASE.VARIANTS["shake128"]
    problem = _NATIVE._problem(variant, WINDOW_BITS, SEED)
    if baseline["orders"] != _A158._derive_orders(baseline["weighted"]):
        raise RuntimeError("A161 weighted orders differ from A158 derivation")
    rows, formulas = _formula_frontier(
        problem, variant, {name: baseline["orders"][name] for name in _A158.ORDER_NAMES}
    )
    plan = _formula_plan(rows)
    return {
        "anchors": (a159, a160),
        "variant": variant,
        "problem": problem,
        "orders": baseline["orders"],
        "rows": rows,
        "formulas": formulas,
        "formula_plan": plan,
        "formula_plan_sha256": _canonical_sha256(plan),
    }


def run(
    *,
    results_dir: Path,
    output: Path,
    causal_output: Path,
    work_dir: Path,
    z3: Path,
) -> dict[str, Any]:
    analysis = analyze(results_dir)
    a159, a160 = analysis["anchors"]
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
    execution_summary = _execution_summary(executions)
    comparison = _baseline_comparison(a159, executions)
    posthoc = _posthoc_summary(analysis["problem"], analysis["variant"], executions)
    payload: dict[str, Any] = {
        "schema": SCHEMA,
        "attempt_id": ATTEMPT_ID,
        "evidence_stage": "EXACT_AFFINE_GAUGE_FIXED_RESOURCE_FRONTIER_EXECUTED",
        "result": (
            "The unique A160 minimum-incidence affine gauge is compiled into each "
            "of the four frozen A158 orders and executed under A159's identical "
            "fixed Z3 resource protocol."
        ),
        "scope": (
            "The retained A152 SHAKE128 width-24 target relation, exact shifted R2 "
            "interface, 22 unchanged suffix rounds, and all 1,344 rate bits."
        ),
        "parameters": {
            "variant": "SHAKE128",
            "seed": SEED,
            "window_bits": WINDOW_BITS,
            "affine_shift": AFFINE_SHIFT,
            "affine_shift_hex": AFFINE_SHIFT_HEX,
            "rlimit_per_formula": Z3_RLIMIT,
            "formula_count": len(_A158.ORDER_NAMES),
            "execution_mode": "sequential_one_thread_per_formula",
            "solver": solver_version,
            "solver_wallclock_limit_used": False,
            "external_safety_timeout_seconds": EXTERNAL_SAFETY_TIMEOUT_SECONDS,
            "wallclock_excluded_from_canonical_result": True,
            "global_uniqueness_claimed": False,
        },
        "anchor_gates": {
            "A159": {
                "artifact_sha256": A159_SHA256,
                "fixed_resource_plan_sha256": a159["fixed_resource_plan_sha256"],
                "status_counts": a159["status_counts"],
            },
            "A160": {
                "artifact_sha256": A160_SHA256,
                "minimum_shift": a160["global_optimum"]["minimum_shift"],
                "minimum_tie_count": a160["global_optimum"]["minimum_tie_count"],
                "minimum_linear_incidence": a160["global_optimum"]["minimum_linear_incidence"],
                "shifted_R2_polynomial_state_sha256": a160["shifted_R2"]["polynomial_state_sha256"],
                "target_assignment_or_solver_outcome_used": False,
            },
        },
        "orders": analysis["orders"],
        "formula_plan": analysis["formula_plan"],
        "formula_plan_sha256": analysis["formula_plan_sha256"],
        "execution": executions,
        "execution_summary": execution_summary,
        "baseline_comparison": comparison,
        "status_counts": status_counts,
        "confirmed_models": confirmed_models,
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
        raise RuntimeError("A161 final artifact reopen gate failed")
    return {
        "json_sha256": _sha256(raw),
        "causal_sha256": reader.file_sha256,
        "causal_graph_sha256": reader.graph_sha256,
        "status_counts": status_counts,
        "confirmed_model_count": len(confirmed_models),
        "confirmed_input_assignments": sorted(
            {row["input_coordinate_assignment"] for row in confirmed_models}
        ),
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
    parser.add_argument(
        "--work-dir",
        type=Path,
        default=Path(__file__).parents[2] / "build" / "shake-r2-a161",
    )
    parser.add_argument(
        "--z3", type=Path, default=Path(shutil.which("z3") or "/opt/homebrew/bin/z3")
    )
    args = parser.parse_args(argv)
    if args.analyze_only:
        analysis = analyze(args.results_dir.resolve())
        print(
            json.dumps(
                {
                    "formula_plan": analysis["formula_plan"],
                    "formula_plan_sha256": analysis["formula_plan_sha256"],
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

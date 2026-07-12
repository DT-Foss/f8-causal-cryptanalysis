#!/usr/bin/env python3
"""Execute all eight exact A162 order-weighted affine gauges at fixed resource."""

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


_A162 = _import_sibling(
    "shake_symbolic_r2_order_weighted_gauge_reader.py",
    "shake_symbolic_r2_order_weighted_gauge_solver_a162_base",
)

_A161 = _A162._A161
_A160 = _A162._A160
_A159 = _A162._A159
_A158 = _A162._A158
_A157 = _A161._A157
_A156 = _A161._A156
_A155 = _A162._A155
_A154 = _A162._A154
_BASE = _A161._BASE
_NATIVE = _A161._NATIVE
_WINDOW = _A161._WINDOW
_R1 = _A162._R1
_SMT = _A161._SMT
_SYMBOLIC = _A162._SYMBOLIC

ATTEMPT_ID = "A163"
SCHEMA = "shake-symbolic-r2-order-weighted-gauge-solver-frontier-v1"
SEED = _A161.SEED
WINDOW_BITS = _A161.WINDOW_BITS
Z3_RLIMIT = _A161.Z3_RLIMIT
EXTERNAL_SAFETY_TIMEOUT_SECONDS = _A161.EXTERNAL_SAFETY_TIMEOUT_SECONDS
A162_FILENAME = _A162.RESULT_FILENAME
A162_SHA256 = "d91b3210a107a815934ee7498c37f9da2740e2c03019feb8af23fe8c9df3549a"
A161_FILENAME = _A161.RESULT_FILENAME
A161_SHA256 = _A162.A161_SHA256
A159_FILENAME = _A159.RESULT_FILENAME
A159_SHA256 = _A161.A159_SHA256
RESULT_FILENAME = "shake_symbolic_r2_order_weighted_gauge_solver_frontier_v1.json"
CAUSAL_FILENAME = "shake_symbolic_r2_order_weighted_gauge_solver_frontier_v1.causal"


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


def _expected_names() -> list[str]:
    return [
        f"{order_name}__{mode}" for order_name in _A158.ORDER_NAMES for mode in _A162.WEIGHT_MODES
    ]


def _load_anchor_gates(
    results_dir: Path,
) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    a162 = _A156._load_json_gate(results_dir / A162_FILENAME, A162_SHA256, _A162.SCHEMA)
    a161 = _A156._load_json_gate(results_dir / A161_FILENAME, A161_SHA256, _A161.SCHEMA)
    a159 = _A156._load_json_gate(results_dir / A159_FILENAME, A159_SHA256, _A159.SCHEMA)
    if (
        a162.get("objective_plan_sha256")
        != "82d519e297cd4c27cce2aca04ddcec2e81fab3fbdb25df75dc96c549a1916cd7"
        or a162.get("landscape_plan_sha256")
        != "69731436c46e6ad8472fb453fdbb963b8fa95554609291c2e7d621e5a4177367"
        or [row.get("name") for row in a162.get("landscapes", [])] != _expected_names()
        or len(a162.get("semantic_gates", [])) != 4
        or any(
            row.get("minimum_tie_count") != 1
            or row.get("global_optimum_certified") is not True
            or row.get("target_rate_input_used") is not False
            or row.get("solver_observations_used_in_objective") is not False
            or row.get("instrumented_assignment_used") is not False
            for row in a162.get("landscapes", [])
        )
        or a161.get("formula_plan_sha256")
        != "e3aa4cbacac9093b0762aa0d0aaaa875a56f084a46fca5fc3e6655f392ee23d3"
        or a161.get("status_counts") != {"error": 0, "sat": 0, "unknown": 4, "unsat": 0}
        or a159.get("fixed_resource_plan_sha256")
        != "41bc4b44a13cbce85545a495f3abb95e35fc679a0515fb0dd90e199d10b62b48"
        or Z3_RLIMIT != 500_000_000
        or a159.get("parameters", {}).get("rlimit_per_formula") != Z3_RLIMIT
        or any(row.get("rlimit") != Z3_RLIMIT for row in a159.get("fixed_resource_plan", []))
        or EXTERNAL_SAFETY_TIMEOUT_SECONDS != 300
        or a159.get("parameters", {}).get("external_safety_timeout_seconds")
        != EXTERNAL_SAFETY_TIMEOUT_SECONDS
    ):
        raise RuntimeError("A159/A161/A162 eight-pair execution gate failed")
    return a162, a161, a159


def _encode_problem(
    problem: dict[str, Any],
    variant: Any,
    *,
    name: str,
    order_name: str,
    weight_mode: str,
    variable_to_shifted_input: Sequence[int],
    affine_shift: int,
    expected_shifted_polynomial_sha256: str,
    expected_coefficient_incidence: dict[str, int],
) -> tuple[Any, list[str], dict[str, Any]]:
    template = _WINDOW._clear_window(problem["base_state"], variant, problem["positions"])
    original = _R1._SPLIT._symbolic_prefix_polynomials(template, variant, problem["positions"], 2)
    if _SYMBOLIC._poly_hash(original, WINDOW_BITS) != _A160.ORIGINAL_R2_POLYNOMIAL_SHA256:
        raise RuntimeError("A163 original R2 polynomial state differs")
    shifted = _A160._shift_polynomials(original, affine_shift, WINDOW_BITS)
    if (
        _SYMBOLIC._poly_hash(shifted, WINDOW_BITS) != expected_shifted_polynomial_sha256
        or _A160._coefficient_counts(shifted) != expected_coefficient_incidence
    ):
        raise RuntimeError(f"{name} shifted R2 semantic gate differs")
    shifted_input_to_solver_rows = _A156._input_to_solver_rows(variable_to_shifted_input)
    transformed = _A155._substitute_linear_basis(shifted, shifted_input_to_solver_rows, WINDOW_BITS)
    if _A160._coefficient_counts(transformed) != expected_coefficient_incidence:
        raise RuntimeError(f"{name} solver-basis coefficient incidence differs")
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
        "order_name": order_name,
        "weight_mode": weight_mode,
        "variable_to_shifted_input_coordinate": list(variable_to_shifted_input),
        "shifted_input_to_solver_row_masks_hex": [
            f"{value:06x}" for value in shifted_input_to_solver_rows
        ],
        "affine_shift_original_input_mask": affine_shift,
        "affine_shift_original_input_mask_hex": f"0x{affine_shift:06x}",
        "affine_shift_rule": "original_input_equals_shifted_input_XOR_mask",
        "model_mapping": "solver_order_to_shifted_input_permutation_then_XOR_row_affine_shift",
        "R2_polynomial_state_sha256_in_solver_basis": _SYMBOLIC._poly_hash(
            transformed, WINDOW_BITS
        ),
        "semantic_original_R2_polynomial_state_sha256": (_A160.ORIGINAL_R2_POLYNOMIAL_SHA256),
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
        "target_rate_input_used_for_gauge_selection": False,
    }
    return writer, inputs, encoding


def _formula_frontier(
    problem: dict[str, Any], variant: Any, a162: dict[str, Any]
) -> tuple[list[dict[str, Any]], dict[str, bytes]]:
    semantic = {row["shift"]: row for row in a162["semantic_gates"]}
    rows = []
    formulas = {}
    for landscape in a162["landscapes"]:
        shift = int(landscape["minimum_shift"])
        gate = semantic[shift]
        name = landscape["name"]
        writer, inputs, encoding = _encode_problem(
            problem,
            variant,
            name=name,
            order_name=landscape["order_name"],
            weight_mode=landscape["weight_mode"],
            variable_to_shifted_input=landscape["variable_to_input_coordinate"],
            affine_shift=shift,
            expected_shifted_polynomial_sha256=gate["shifted_R2_polynomial_state_sha256"],
            expected_coefficient_incidence=gate["coefficient_incidence"],
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
    if [row["name"] for row in rows] != _expected_names():
        raise RuntimeError("A163 formula execution order differs from A162 plan")
    return rows, formulas


def _verify_solver_row(
    row: dict[str, Any],
    result: dict[str, Any],
    problem: dict[str, Any],
    variant: Any,
) -> dict[str, Any]:
    solver_assignment = result["solver_basis_assignment"]
    if result["status"] == "sat" and solver_assignment is None:
        raise RuntimeError(f"{row['name']} returned SAT without a complete model")
    if result["status"] != "sat" and solver_assignment is not None:
        raise RuntimeError(f"{row['name']} returned a model with non-SAT status")
    shifted_assignment = None
    input_assignment = None
    verification = None
    if solver_assignment is not None:
        inverse_rows = [
            int(value, 16) for value in row["encoding"]["shifted_input_to_solver_row_masks_hex"]
        ]
        shifted_assignment = _A154._recover_input(solver_assignment, inverse_rows)
        input_assignment = shifted_assignment ^ row["encoding"]["affine_shift_original_input_mask"]
        verification = _A156._VERIFY(problem, variant, input_assignment)
        if not (
            verification.get("complete_rate_match") is True
            and verification.get("rate_bits_checked") == variant.rate_bits
            and verification.get("candidate_rate_sha256") == verification.get("target_rate_sha256")
        ):
            raise RuntimeError(f"{row['name']} emitted an independently invalid mapped model")
    return {
        **row,
        "solver": result,
        "shifted_input_coordinate_assignment": shifted_assignment,
        "input_coordinate_assignment": input_assignment,
        "independent_complete_rate_check": verification,
        "independently_confirmed_model": verification is not None,
        "model_mapping": "solver_order_to_shifted_input_permutation_then_XOR_row_affine_shift",
    }


def _run_z3_rlimit(z3: Path, path: Path, inputs: list[str]) -> dict[str, Any]:
    result = _A159._run_z3_rlimit(z3, path, inputs)
    result["command_parameters"]["representation"] = (
        "Boolean_SMT_shared_R2_order_weighted_affine_gauge_fixed_rlimit"
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
        raise ValueError("A163 solver work directory must be empty")
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
                raise RuntimeError(f"{row['name']} fixed-resource execution failed")
            results.append(_verify_solver_row(dict(row), result, problem, variant))
    finally:
        for path in work_dir.glob("*.smt2"):
            path.unlink(missing_ok=True)
    if any(work_dir.iterdir()):
        raise RuntimeError("A163 solver formula cleanup failed")
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
            "order_name": row["encoding"]["order_name"],
            "weight_mode": row["encoding"]["weight_mode"],
            "affine_shift": row["encoding"]["affine_shift_original_input_mask"],
            "status": row["solver"]["status"],
            "return_code": row["solver"]["return_code"],
            "termination": row["solver"]["termination"],
            "canonical_observation_sha256": row["solver"]["canonical_observation_sha256"],
            "stats": row["solver"]["stats"],
            "independently_confirmed_model": row["independently_confirmed_model"],
        }
        for row in executions
    ]


def _control_comparison(
    a159: dict[str, Any],
    a161: dict[str, Any],
    executions: Sequence[dict[str, Any]],
) -> list[dict[str, Any]]:
    zero = {row["name"]: row for row in a159["execution_summary"]}
    unweighted = {row["name"]: row for row in a161["execution_summary"]}
    rows = []
    for execution in executions:
        order_name = execution["encoding"]["order_name"]
        current = execution["solver"]
        decisions = int(current["stats"].get("decisions", 0))
        conflicts = int(current["stats"].get("conflicts", 0))
        rows.append(
            {
                "name": execution["name"],
                "order_name": order_name,
                "weight_mode": execution["encoding"]["weight_mode"],
                "affine_shift": execution["encoding"]["affine_shift_original_input_mask"],
                "status": current["status"],
                "decisions": decisions,
                "conflicts": conflicts,
                "zero_gauge_status": zero[order_name]["status"],
                "zero_gauge_decisions": zero[order_name]["stats"]["decisions"],
                "decision_delta_from_zero_gauge": decisions
                - zero[order_name]["stats"]["decisions"],
                "A160_gauge_status": unweighted[order_name]["status"],
                "A160_gauge_decisions": unweighted[order_name]["stats"]["decisions"],
                "decision_delta_from_A160_gauge": decisions
                - unweighted[order_name]["stats"]["decisions"],
                "same_configured_rlimit": True,
            }
        )
    return rows


def _posthoc_summary(
    problem: dict[str, Any], variant: Any, executions: Sequence[dict[str, Any]]
) -> dict[str, Any]:
    actual = _WINDOW._extract_window(problem["base_state"], variant, problem["positions"])
    return {
        "instrumented_input_assignment": actual,
        "extracted_only_after_every_encoder_execution": True,
        "used_for_formula_construction_order_gauge_or_execution": False,
        "encoder_rows": [
            {
                "name": row["name"],
                "affine_shift": row["encoding"]["affine_shift_original_input_mask"],
                "instrumented_shifted_assignment": actual
                ^ row["encoding"]["affine_shift_original_input_mask"],
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
        experiment="shake_symbolic_r2_order_weighted_gauge_solver_frontier",
        parameters={
            "attempt_id": ATTEMPT_ID,
            "variant": "shake128",
            "seed": SEED,
            "window_bits": WINDOW_BITS,
            "formula_count": len(_expected_names()),
            "rlimit_per_formula": Z3_RLIMIT,
        },
    )
    ids = [
        "shake128-a162-eight-order-weighted-gauges",
        "shake128-a163-eight-fullround-formulas",
        "shake128-a163-fixed-resource-execution",
        "shake128-a163-factorial-control-comparison",
    ]
    builder.add_triplet(
        edge_id=ids[0],
        trigger="A162:exact_order_specific_gauge_plan_for_fixed_resource_transfer",
        mechanism="hash_gate_all_eight_unique_objective_optima_and_four_semantic_polynomial_interfaces",
        outcome="A163:eight_predeclared_order_gauge_pairs",
        confidence=1.0,
        evidence_kind="retained_complete_domain_Walsh_landscapes",
        source=A162_SHA256,
        attrs={"A162_gate": payload["anchor_gates"]["A162"]},
    )
    builder.add_triplet(
        edge_id=ids[1],
        trigger="A163:eight_predeclared_order_gauge_pairs",
        mechanism="compile_each_shifted_shared_R2_prefix_with_its_frozen_order_and_the_unchanged_full_suffix",
        outcome="A163:eight_exact_fullround_formulas",
        confidence=1.0,
        evidence_kind="deterministic_formula_compilation_before_solver_outcomes",
        source=payload["formula_plan_sha256"],
        provenance=[ids[0]],
        attrs={"formula_plan": payload["formula_plan"]},
    )
    builder.add_triplet(
        edge_id=ids[2],
        trigger="A163:eight_exact_fullround_formulas",
        mechanism="execute_sequentially_under_the_A159_fixed_resource_protocol_and_independently_verify_every_mapped_model",
        outcome="A163:eight_order_weighted_gauge_solver_observations",
        confidence=1.0,
        evidence_kind="fixed_resource_execution_and_independent_complete_rate_gate",
        source="Z3_4.15.4_plus_independent_NumPy_lane_core",
        provenance=[ids[1]],
        attrs={
            "execution_summary": payload["execution_summary"],
            "confirmed_models": payload["confirmed_models"],
        },
    )
    builder.add_triplet(
        edge_id=ids[3],
        trigger="A163:eight_order_weighted_gauge_solver_observations",
        mechanism="compare_each_pair_with_its_same_order_zero_and_A160_gauge_controls_at_the_identical_rlimit",
        outcome="A163:order_weighted_gauge_factorial_frontier",
        confidence=1.0,
        evidence_kind="same_resource_two_control_factorial_comparison",
        source=payload["control_comparison_sha256"],
        provenance=[ids[2]],
        attrs={
            "control_comparison": payload["control_comparison"],
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
        raise RuntimeError("A163 Causal provenance chain failed validation")
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
    a162, a161, a159 = _load_anchor_gates(results_dir)
    variant = _BASE.VARIANTS["shake128"]
    problem = _NATIVE._problem(variant, WINDOW_BITS, SEED)
    rows, formulas = _formula_frontier(problem, variant, a162)
    plan = _formula_plan(rows)
    return {
        "anchors": (a162, a161, a159),
        "variant": variant,
        "problem": problem,
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
    a162, a161, a159 = analysis["anchors"]
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
    comparison = _control_comparison(a159, a161, executions)
    posthoc = _posthoc_summary(analysis["problem"], analysis["variant"], executions)
    payload: dict[str, Any] = {
        "schema": SCHEMA,
        "attempt_id": ATTEMPT_ID,
        "evidence_stage": "ORDER_WEIGHTED_GAUGE_FIXED_RESOURCE_FRONTIER_EXECUTED",
        "result": (
            "All eight exact A162 order/gauge pairs execute sequentially under "
            "A159's fixed Z3 resource protocol with independent model mapping."
        ),
        "scope": (
            "The retained A152 SHAKE128 width-24 target relation, eight exact shifted "
            "shared-R2 prefixes, 22 unchanged suffix rounds and all 1,344 rate bits."
        ),
        "parameters": {
            "variant": "SHAKE128",
            "seed": SEED,
            "window_bits": WINDOW_BITS,
            "formula_count": len(_expected_names()),
            "rlimit_per_formula": Z3_RLIMIT,
            "execution_mode": "sequential_one_thread_per_formula",
            "solver": solver_version,
            "solver_wallclock_limit_used": False,
            "external_safety_timeout_seconds": EXTERNAL_SAFETY_TIMEOUT_SECONDS,
            "wallclock_excluded_from_canonical_result": True,
            "global_uniqueness_claimed": False,
        },
        "anchor_gates": {
            "A162": {
                "artifact_sha256": A162_SHA256,
                "objective_plan_sha256": a162["objective_plan_sha256"],
                "landscape_plan_sha256": a162["landscape_plan_sha256"],
                "semantic_gate_plan_sha256": a162["semantic_gate_plan_sha256"],
                "target_assignment_or_solver_counter_used": False,
            },
            "A161": {
                "artifact_sha256": A161_SHA256,
                "formula_plan_sha256": a161["formula_plan_sha256"],
                "status_counts": a161["status_counts"],
            },
            "A159": {
                "artifact_sha256": A159_SHA256,
                "fixed_resource_plan_sha256": a159["fixed_resource_plan_sha256"],
                "status_counts": a159["status_counts"],
            },
        },
        "formula_plan": analysis["formula_plan"],
        "formula_plan_sha256": analysis["formula_plan_sha256"],
        "execution": executions,
        "execution_summary": execution_summary,
        "status_counts": status_counts,
        "confirmed_models": confirmed_models,
        "control_comparison": comparison,
        "control_comparison_sha256": _canonical_sha256(comparison),
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
        raise RuntimeError("A163 final artifact reopen gate failed")
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
        default=Path(__file__).parents[2] / "build" / "shake-r2-a163",
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

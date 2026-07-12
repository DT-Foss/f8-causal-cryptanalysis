#!/usr/bin/env python3
"""Distinguish order-family context from central position for the 0/12 swap."""

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


_A172 = _import_sibling(
    "shake_symbolic_r2_adjacent_0_12_transfer_frontier.py",
    "shake_symbolic_r2_center_family_a172_base",
)
_A170 = _A172._A170
_A169 = _A172._A169
_A168 = _A172._A168
_A166 = _A172._A166
_A163 = _A172._A163
_A156 = _A172._A156

ATTEMPT_ID = "A173"
SCHEMA = "shake-symbolic-r2-center-position-family-contrast-v1"
SEED = _A172.SEED
WINDOW_BITS = _A172.WINDOW_BITS
Z3_RLIMIT = _A172.Z3_RLIMIT
EXTERNAL_SAFETY_TIMEOUT_SECONDS = _A172.EXTERNAL_SAFETY_TIMEOUT_SECONDS
AFFINE_SHIFT = _A172.AFFINE_SHIFT
A172_FILENAME = _A172.RESULT_FILENAME
A172_SHA256 = "f1252babeb729f9b58102d24d522daa0fa337506e25f9f282b2b4fb9a4d693c3"
A172_TRANSFER_SHA256 = "7b20ad6787fb555b55239522a43977ac268a7423c0f5d067def935ca27b6a4fd"
A170_FILENAME = _A170.RESULT_FILENAME
A170_SHA256 = _A172.A170_SHA256
A166_FILENAME = _A166.RESULT_FILENAME
A166_SHA256 = _A172.A166_SHA256
PROTOCOL_FILENAME = "shake_symbolic_r2_center_position_family_contrast_v1.json"
PROTOCOL_SHA256 = "82cd65e9ecc51ba40ec16871cae182ed35f8ad9be5be63ff40806ed9161c91d9"
PROTOCOL_SCHEMA = "shake-symbolic-r2-center-position-family-contrast-protocol-v1"
RESULT_FILENAME = "shake_symbolic_r2_center_position_family_contrast_v1.json"
CAUSAL_FILENAME = "shake_symbolic_r2_center_position_family_contrast_v1.causal"
SOURCE_ORDER = "weighted_degree_descending"
INSERTION_INDEX = 11
ORIENTATIONS = _A172.ORIENTATIONS
COMPILERS = _A172.COMPILERS


def _sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _canonical_sha256(value: Any) -> str:
    return _A172._canonical_sha256(value)


def _load_anchor_gates(
    results_dir: Path,
) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    a172 = _A156._load_json_gate(results_dir / A172_FILENAME, A172_SHA256, _A172.SCHEMA)
    a170 = _A156._load_json_gate(results_dir / A170_FILENAME, A170_SHA256, _A170.SCHEMA)
    a166 = _A156._load_json_gate(results_dir / A166_FILENAME, A166_SHA256, _A166.SCHEMA)
    if (
        a172.get("transfer_result_sha256") != A172_TRANSFER_SHA256
        or a172.get("transfer_result", {}).get("directional_delta_12_before_0_minus_0_before_12")
        != 456
        or a172.get("transfer_result", {}).get("direction_classification") != "reversed_direction"
        or a172.get("status_counts") != {"error": 0, "sat": 0, "unknown": 4, "unsat": 0}
        or Z3_RLIMIT != 500_000_000
        or EXTERNAL_SAFETY_TIMEOUT_SECONDS != 300
    ):
        raise RuntimeError("A173 A166/A170/A172 anchor gate failed")
    return a172, a170, a166


def _load_protocol_gate() -> dict[str, Any]:
    path = Path(__file__).parents[1] / "configs" / PROTOCOL_FILENAME
    protocol = _A156._load_json_gate(path, PROTOCOL_SHA256, PROTOCOL_SCHEMA)
    if (
        protocol.get("attempt_id") != ATTEMPT_ID
        or protocol.get("protocol_state") != "frozen_before_any_A173_solver_execution"
        or protocol.get("anchors", {}).get("A172", {}).get("sha256") != A172_SHA256
        or protocol.get("anchors", {}).get("A170", {}).get("sha256") != A170_SHA256
        or protocol.get("contrast_design", {}).get("semantic_change") is not False
        or protocol.get("contrast_design", {}).get("new_formula_count") != 4
        or protocol.get("information_boundary", {}).get(
            "A173_solver_outcomes_used_before_formula_freeze"
        )
        is not False
    ):
        raise RuntimeError("A173 frozen protocol identity gate failed")
    return protocol


def _validate_protocol_plan(protocol: dict[str, Any], analysis: dict[str, Any]) -> None:
    rows = [
        [row["name"], row["formula_bytes"], row["formula_sha256"]]
        for row in analysis["formula_plan"]
    ]
    if (
        protocol["contrast_plan"]["sha256"] != analysis["contrast_plan_sha256"]
        or protocol["formula_plan"]["sha256"] != analysis["formula_plan_sha256"]
        or protocol["formula_plan"]["rows"] != rows
    ):
        raise RuntimeError("A173 regenerated contrast/formulas differ")


def _base_orders(a166: dict[str, Any]) -> dict[str, list[int]]:
    return {
        row["encoding"]["order_name"]: row["encoding"]["variable_to_shifted_input_coordinate"]
        for row in a166["formula_plan"]
    }


def _contrast_plan(a166: dict[str, Any]) -> dict[str, Any]:
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
        or differences != [11, 12]
        or [zero_first[index] for index in differences] != [0, 12]
        or [twelve_first[index] for index in differences] != [12, 0]
        or sorted(zero_first) != list(range(WINDOW_BITS))
        or sorted(twelve_first) != list(range(WINDOW_BITS))
    ):
        raise RuntimeError("A173 position-matched contrast construction failed")
    return {
        "source_order_name": SOURCE_ORDER,
        "source_order": source,
        "source_without_0_12": remainder,
        "insertion_index_zero_based": INSERTION_INDEX,
        "adjacent_positions": [11, 12],
        "zero_before_twelve_order": zero_first,
        "twelve_before_zero_order": twelve_first,
        "only_changed_coordinates_between_arms": [0, 12],
        "other_22_relative_order_preserved": True,
        "position_matched_to_A172": True,
        "family_changed_relative_to_A172": (
            "greedy_max_remaining_weight_to_weighted_degree_descending"
        ),
    }


def _formula_frontier(
    problem: dict[str, Any],
    variant: Any,
    contrast: dict[str, Any],
    semantic_gate: dict[str, Any],
) -> tuple[list[dict[str, Any]], dict[str, bytes]]:
    orders = {
        "0_before_12": contrast["zero_before_twelve_order"],
        "12_before_0": contrast["twelve_before_zero_order"],
    }
    rows = []
    formulas = {}
    for orientation in ORIENTATIONS:
        order = orders[orientation]
        for compiler in COMPILERS:
            name = f"weighted_desc_center_{orientation}__{compiler}_negative_alias"
            if compiler == "inline":
                writer, inputs, encoding = _A166._encode_problem(
                    problem,
                    variant,
                    name=name,
                    order_name=f"weighted_desc_center_{orientation}",
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
                    order_name=f"weighted_desc_center_{orientation}",
                    variable_to_shifted_input=order,
                    expected_shifted_polynomial_sha256=semantic_gate[
                        "shifted_R2_polynomial_state_sha256"
                    ],
                    expected_coefficient_incidence=semantic_gate["coefficient_incidence"],
                )
            encoding.update(
                {
                    "contrast_source_order": SOURCE_ORDER,
                    "adjacent_orientation": orientation,
                    "adjacent_positions": [11, 12],
                    "alias_compiler_arm": compiler,
                    "position_matched_A172_family_contrast": True,
                    "mechanism_classification_rule": (
                        "negative_delta_family_context_positive_delta_central_position_zero_boundary"
                    ),
                    "instrumented_assignment_input_used": False,
                    "solver_observation_input_used_for_formula_construction": False,
                    "target_rate_input_used_for_contrast_selection": False,
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
        "Boolean_SMT_shared_R2_center_position_family_contrast_fixed_rlimit"
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
        raise ValueError("A173 solver work directory must be empty")
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
        raise RuntimeError("A173 solver formula cleanup failed")
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


def _family_contrast_result(
    a172: dict[str, Any], executions: Sequence[dict[str, Any]]
) -> dict[str, Any]:
    weighted = _A172._transfer_result(executions)
    weighted_delta = weighted["directional_delta_12_before_0_minus_0_before_12"]
    greedy_delta = a172["transfer_result"]["directional_delta_12_before_0_minus_0_before_12"]
    classification = (
        "family_context_supported"
        if weighted_delta < 0
        else "central_position_supported"
        if weighted_delta > 0
        else "weighted_center_boundary"
    )
    return {
        "A172_greedy_max_center": a172["transfer_result"],
        "A173_weighted_desc_center": weighted,
        "greedy_max_directional_delta": greedy_delta,
        "weighted_desc_directional_delta": weighted_delta,
        "same_position_opposite_family_delta_difference": weighted_delta - greedy_delta,
        "mechanism_classification": classification,
        "family_context_supported": classification == "family_context_supported",
        "central_position_supported": classification == "central_position_supported",
        "weighted_center_boundary": classification == "weighted_center_boundary",
    }


def _posthoc_summary(
    problem: dict[str, Any], variant: Any, executions: Sequence[dict[str, Any]]
) -> dict[str, Any]:
    actual = _A168._WINDOW._extract_window(problem["base_state"], variant, problem["positions"])
    return {
        "instrumented_input_assignment": actual,
        "extracted_only_after_every_A173_execution": True,
        "used_for_contrast_formula_order_or_execution": False,
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
        experiment="shake_symbolic_r2_center_position_family_contrast",
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
        "shake128-a172-greedy-center-reversed-direction",
        "shake128-a173-weighted-center-position-match",
        "shake128-a173-four-family-contrast-formulas",
        "shake128-a173-fixed-resource-execution",
        "shake128-a173-family-versus-position-classification",
    ]
    builder.add_triplet(
        edge_id=ids[0],
        trigger="A172:greedy_max_center_12_before_0_direction_reversed",
        mechanism="identify_family_context_or_central_position_as_competing_conditions",
        outcome="A173:position_matched_family_contrast_question",
        confidence=1.0,
        evidence_kind="prospective_transfer_boundary",
        source=A172_SHA256,
        attrs={"A172_gate": payload["anchor_gates"]["A172"]},
    )
    builder.add_triplet(
        edge_id=ids[1],
        trigger="A173:position_matched_family_contrast_question",
        mechanism="construct_weighted_descending_0_12_pair_at_the_same_central_11_12_positions",
        outcome="A173:two_weighted_center_adjacent_orders",
        confidence=1.0,
        evidence_kind="deterministic_position_matched_order_construction",
        source=payload["contrast_plan_sha256"],
        provenance=[ids[0]],
        attrs={"contrast_plan": payload["contrast_plan"]},
    )
    builder.add_triplet(
        edge_id=ids[2],
        trigger="A173:two_weighted_center_adjacent_orders",
        mechanism="compile_inline_and_materialized_alias_arms_for_both_orientations",
        outcome="A173:four_exact_position_matched_fullround_formulas",
        confidence=1.0,
        evidence_kind="hash_bound_semantics_preserving_formula_frontier",
        source=payload["formula_plan_sha256"],
        provenance=[ids[1]],
        attrs={"formula_plan": payload["formula_plan"]},
    )
    builder.add_triplet(
        edge_id=ids[3],
        trigger="A173:four_exact_position_matched_fullround_formulas",
        mechanism="execute_all_four_formulas_under_the_unchanged_fixed_resource_protocol",
        outcome="A173:four_weighted_center_solver_observations",
        confidence=1.0,
        evidence_kind="fixed_resource_execution_and_complete_rate_gate",
        source="Z3_4.15.4_plus_independent_NumPy_lane_core",
        provenance=[ids[2]],
        attrs={"execution_summary": payload["execution_summary"]},
    )
    builder.add_triplet(
        edge_id=ids[4],
        trigger="A173:four_weighted_center_solver_observations",
        mechanism="compare_weighted_and_greedy_directional_deltas_at_identical_positions",
        outcome="A173:family_context_or_central_position_classification",
        confidence=1.0,
        evidence_kind="position_matched_cross_family_intervention",
        source=payload["family_contrast_result_sha256"],
        provenance=[ids[3]],
        attrs={"family_contrast_result": payload["family_contrast_result"]},
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
        raise RuntimeError("A173 Causal provenance chain failed validation")
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
    a172, a170, a166 = _load_anchor_gates(results_dir)
    contrast = _contrast_plan(a166)
    baseline = _A166.analyze(results_dir)
    _a164, a162 = _A166._load_anchor_gates(results_dir)
    semantic_gate = next(row for row in a162["semantic_gates"] if row["shift"] == AFFINE_SHIFT)
    rows, formulas = _formula_frontier(
        baseline["problem"],
        baseline["variant"],
        contrast,
        semantic_gate,
    )
    plan = _formula_plan(rows)
    return {
        "anchors": (a172, a170, a166),
        "variant": baseline["variant"],
        "problem": baseline["problem"],
        "contrast_plan": contrast,
        "contrast_plan_sha256": _canonical_sha256(contrast),
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
    a172, a170, _a166 = analysis["anchors"]
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
    contrast_result = _family_contrast_result(a172, executions)
    posthoc = _posthoc_summary(analysis["problem"], analysis["variant"], executions)
    payload: dict[str, Any] = {
        "schema": SCHEMA,
        "attempt_id": ATTEMPT_ID,
        "evidence_stage": "CENTER_POSITION_FAMILY_CONTRAST_EXECUTED",
        "result": (
            "A173 matches A172's central 11/12 positions in a Weighted-Descending "
            "context to distinguish family context from central position."
        ),
        "scope": (
            "The retained A152 SHAKE128 width-24 relation, affine gauge 0x4e1e28, "
            "two new Weighted-Descending-derived central adjacent orders, shared "
            "R2 prefix, 22 unchanged suffix rounds and all 1,344 rate bits."
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
            "A173_protocol": {
                "artifact_sha256": PROTOCOL_SHA256,
                "protocol_state": analysis["protocol"]["protocol_state"],
                "mechanism_rules": analysis["protocol"]["mechanism_rules"],
                "information_boundary": analysis["protocol"]["information_boundary"],
            },
            "A172": {
                "artifact_sha256": A172_SHA256,
                "transfer_result_sha256": A172_TRANSFER_SHA256,
                "directional_delta": a172["transfer_result"][
                    "directional_delta_12_before_0_minus_0_before_12"
                ],
            },
            "A170": {
                "artifact_sha256": A170_SHA256,
                "polarity_frontier_sha256": a170["polarity_frontier_sha256"],
            },
        },
        "contrast_plan": analysis["contrast_plan"],
        "contrast_plan_sha256": analysis["contrast_plan_sha256"],
        "formula_plan": analysis["formula_plan"],
        "formula_plan_sha256": analysis["formula_plan_sha256"],
        "execution": executions,
        "execution_summary": summary,
        "status_counts": status_counts,
        "confirmed_models": confirmed_models,
        "family_contrast_result": contrast_result,
        "family_contrast_result_sha256": _canonical_sha256(contrast_result),
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
        raise RuntimeError("A173 final artifact reopen gate failed")
    weighted = contrast_result["A173_weighted_desc_center"]
    return {
        "json_sha256": _sha256(raw),
        "causal_sha256": reader.file_sha256,
        "causal_graph_sha256": reader.graph_sha256,
        "status_counts": status_counts,
        "confirmed_model_count": len(confirmed_models),
        "mechanism_classification": contrast_result["mechanism_classification"],
        "greedy_max_directional_delta": contrast_result["greedy_max_directional_delta"],
        "weighted_desc_directional_delta": contrast_result["weighted_desc_directional_delta"],
        "weighted_effects": [row["materialization_effect"] for row in weighted["rows"]],
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
        default=Path(__file__).parents[2] / "build" / "shake-r2-a173",
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
                    "contrast_plan_sha256": analysis["contrast_plan_sha256"],
                    "contrast_plan": analysis["contrast_plan"],
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

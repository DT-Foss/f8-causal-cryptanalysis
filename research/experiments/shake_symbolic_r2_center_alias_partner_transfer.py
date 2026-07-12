#!/usr/bin/env python3
"""Test whether the x11/x12 alias boundary transfers from partner 0 to 22."""

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


_A173 = _import_sibling(
    "shake_symbolic_r2_center_position_family_contrast.py",
    "shake_symbolic_r2_center_partner_a173_base",
)
_A172 = _A173._A172
_A170 = _A173._A170
_A169 = _A173._A169
_A168 = _A173._A168
_A166 = _A173._A166
_A163 = _A173._A163
_A156 = _A173._A156

ATTEMPT_ID = "A174"
SCHEMA = "shake-symbolic-r2-center-alias-partner-transfer-v1"
SEED = _A173.SEED
WINDOW_BITS = _A173.WINDOW_BITS
Z3_RLIMIT = _A173.Z3_RLIMIT
EXTERNAL_SAFETY_TIMEOUT_SECONDS = _A173.EXTERNAL_SAFETY_TIMEOUT_SECONDS
AFFINE_SHIFT = _A173.AFFINE_SHIFT
A173_FILENAME = _A173.RESULT_FILENAME
A173_SHA256 = "b3ae48350a75430b1b1aea55ebe59442949dd6b5fe19f30453583ede6da6d01b"
A173_CONTRAST_SHA256 = "7cffb3b309666c431ec056c24101512b167550db2a5a0085b1ed8ffde5dcb909"
A170_FILENAME = _A170.RESULT_FILENAME
A170_SHA256 = _A173.A170_SHA256
A166_FILENAME = _A166.RESULT_FILENAME
A166_SHA256 = _A173.A166_SHA256
PROTOCOL_FILENAME = "shake_symbolic_r2_center_alias_partner_transfer_v1.json"
PROTOCOL_SHA256 = "e34edf19f6a4d3193aac3ef4f9df6df742b910d9340cb2238860fc1b61862a15"
PROTOCOL_SCHEMA = "shake-symbolic-r2-center-alias-partner-transfer-protocol-v1"
RESULT_FILENAME = "shake_symbolic_r2_center_alias_partner_transfer_v1.json"
CAUSAL_FILENAME = "shake_symbolic_r2_center_alias_partner_transfer_v1.causal"
SOURCE_ORDER = "weighted_degree_descending"
ALIAS_COORDINATE = 12
CONTROL_PARTNER = 22
INSERTION_INDEX = 11
ORIENTATIONS = ("22_before_12", "12_before_22")
COMPILERS = _A173.COMPILERS


def _sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _canonical_sha256(value: Any) -> str:
    return _A173._canonical_sha256(value)


def _load_anchor_gates(
    results_dir: Path,
) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    a173 = _A156._load_json_gate(results_dir / A173_FILENAME, A173_SHA256, _A173.SCHEMA)
    a170 = _A156._load_json_gate(results_dir / A170_FILENAME, A170_SHA256, _A170.SCHEMA)
    a166 = _A156._load_json_gate(results_dir / A166_FILENAME, A166_SHA256, _A166.SCHEMA)
    if (
        a173.get("family_contrast_result_sha256") != A173_CONTRAST_SHA256
        or a173.get("family_contrast_result", {}).get("mechanism_classification")
        != "central_position_supported"
        or a173.get("family_contrast_result", {}).get("weighted_desc_directional_delta") != 10_955
        or a173.get("status_counts") != {"error": 0, "sat": 0, "unknown": 4, "unsat": 0}
        or Z3_RLIMIT != 500_000_000
        or EXTERNAL_SAFETY_TIMEOUT_SECONDS != 300
    ):
        raise RuntimeError("A174 A166/A170/A173 anchor gate failed")
    return a173, a170, a166


def _load_protocol_gate() -> dict[str, Any]:
    path = Path(__file__).parents[1] / "configs" / PROTOCOL_FILENAME
    protocol = _A156._load_json_gate(path, PROTOCOL_SHA256, PROTOCOL_SCHEMA)
    if (
        protocol.get("attempt_id") != ATTEMPT_ID
        or protocol.get("protocol_state") != "frozen_before_any_A174_solver_execution"
        or protocol.get("anchors", {}).get("A173", {}).get("sha256") != A173_SHA256
        or protocol.get("partner_design", {}).get("semantic_change") is not False
        or protocol.get("partner_design", {}).get("new_formula_count") != 4
        or protocol.get("prospective_prediction", {}).get("direction")
        != "effect_12_before_22_is_strictly_higher_than_effect_22_before_12"
        or protocol.get("information_boundary", {}).get(
            "A174_solver_outcomes_used_before_formula_freeze"
        )
        is not False
    ):
        raise RuntimeError("A174 frozen protocol identity gate failed")
    return protocol


def _validate_protocol_plan(protocol: dict[str, Any], analysis: dict[str, Any]) -> None:
    rows = [
        [row["name"], row["formula_bytes"], row["formula_sha256"]]
        for row in analysis["formula_plan"]
    ]
    if (
        protocol["partner_plan"]["sha256"] != analysis["partner_plan_sha256"]
        or protocol["formula_plan"]["sha256"] != analysis["formula_plan_sha256"]
        or protocol["formula_plan"]["rows"] != rows
    ):
        raise RuntimeError("A174 regenerated partner/formulas differ")


def _base_orders(a166: dict[str, Any]) -> dict[str, list[int]]:
    return {
        row["encoding"]["order_name"]: row["encoding"]["variable_to_shifted_input_coordinate"]
        for row in a166["formula_plan"]
    }


def _partner_plan(a166: dict[str, Any]) -> dict[str, Any]:
    source = list(_base_orders(a166)[SOURCE_ORDER])
    remainder = [
        coordinate for coordinate in source if coordinate not in (ALIAS_COORDINATE, CONTROL_PARTNER)
    ]
    partner_first = (
        remainder[:INSERTION_INDEX]
        + [CONTROL_PARTNER, ALIAS_COORDINATE]
        + remainder[INSERTION_INDEX:]
    )
    alias_first = (
        remainder[:INSERTION_INDEX]
        + [ALIAS_COORDINATE, CONTROL_PARTNER]
        + remainder[INSERTION_INDEX:]
    )
    differences = [
        index
        for index, (left, right) in enumerate(zip(partner_first, alias_first, strict=True))
        if left != right
    ]
    if (
        source.index(ALIAS_COORDINATE) + 1 != source.index(CONTROL_PARTNER)
        or len(remainder) != 22
        or differences != [11, 12]
        or [partner_first[index] for index in differences] != [22, 12]
        or [alias_first[index] for index in differences] != [12, 22]
        or sorted(partner_first) != list(range(WINDOW_BITS))
        or sorted(alias_first) != list(range(WINDOW_BITS))
    ):
        raise RuntimeError("A174 central partner construction failed")
    return {
        "source_order_name": SOURCE_ORDER,
        "source_order": source,
        "source_alias_coordinate": ALIAS_COORDINATE,
        "control_partner_coordinate": CONTROL_PARTNER,
        "control_partner_is_original_right_neighbor": True,
        "source_without_12_22": remainder,
        "insertion_index_zero_based": INSERTION_INDEX,
        "adjacent_positions": [11, 12],
        "partner_before_alias_order": partner_first,
        "alias_before_partner_order": alias_first,
        "only_changed_coordinates_between_arms": [12, 22],
        "other_22_relative_order_preserved": True,
        "alias_solver_positions": {
            "22_before_12": 12,
            "12_before_22": 11,
        },
        "A173_alias_solver_positions": {
            "0_before_12": 12,
            "12_before_0": 11,
        },
    }


def _formula_frontier(
    problem: dict[str, Any],
    variant: Any,
    partner: dict[str, Any],
    semantic_gate: dict[str, Any],
) -> tuple[list[dict[str, Any]], dict[str, bytes]]:
    orders = {
        "22_before_12": partner["partner_before_alias_order"],
        "12_before_22": partner["alias_before_partner_order"],
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
                    "partner_source_order": SOURCE_ORDER,
                    "adjacent_orientation": orientation,
                    "adjacent_positions": [11, 12],
                    "alias_compiler_arm": compiler,
                    "alias_input_solver_position": order.index(ALIAS_COORDINATE),
                    "control_partner_coordinate": CONTROL_PARTNER,
                    "prospective_partner_prediction": (
                        "effect_12_before_22_is_strictly_higher_than_effect_22_before_12"
                    ),
                    "instrumented_assignment_input_used": False,
                    "solver_observation_input_used_for_formula_construction": False,
                    "target_rate_input_used_for_partner_selection": False,
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
        "Boolean_SMT_shared_R2_center_alias_partner_transfer_fixed_rlimit"
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
        raise ValueError("A174 solver work directory must be empty")
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
        raise RuntimeError("A174 solver formula cleanup failed")
    return results


def _execution_summary(executions: Sequence[dict[str, Any]]) -> list[dict[str, Any]]:
    return [
        {
            "name": row["name"],
            "adjacent_orientation": row["encoding"]["adjacent_orientation"],
            "alias_compiler_arm": row["encoding"]["alias_compiler_arm"],
            "alias_input_solver_position": row["encoding"]["alias_input_solver_position"],
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


def _partner_transfer_result(
    a173: dict[str, Any], executions: Sequence[dict[str, Any]]
) -> dict[str, Any]:
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
                "alias_input_solver_position": (12 if orientation == "22_before_12" else 11),
                "inline_decisions": inline,
                "materialized_decisions": materialized,
                "materialization_effect": effect,
            }
        )
    delta = effects["12_before_22"] - effects["22_before_12"]
    a173_delta = a173["family_contrast_result"]["weighted_desc_directional_delta"]
    return {
        "rows": rows,
        "directional_delta_alias_position_11_minus_12": delta,
        "A173_coordinate_0_partner_delta": a173_delta,
        "prospective_prediction": (
            "effect_12_before_22_is_strictly_higher_than_effect_22_before_12"
        ),
        "prospective_prediction_confirmed": delta > 0,
        "classification": (
            "central_alias_boundary_transfers"
            if delta > 0
            else "exact_partner_boundary"
            if delta == 0
            else "coordinate_0_specific_direction"
        ),
        "partner_independent_direction_match": (delta > 0) == (a173_delta > 0),
        "magnitude_ratio_numerator_denominator": [delta, a173_delta],
    }


def _posthoc_summary(
    problem: dict[str, Any], variant: Any, executions: Sequence[dict[str, Any]]
) -> dict[str, Any]:
    actual = _A168._WINDOW._extract_window(problem["base_state"], variant, problem["positions"])
    return {
        "instrumented_input_assignment": actual,
        "extracted_only_after_every_A174_execution": True,
        "used_for_partner_formula_order_or_execution": False,
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
        experiment="shake_symbolic_r2_center_alias_partner_transfer",
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
        "shake128-a173-central-x11-x12-boundary",
        "shake128-a174-original-neighbor-22-partner",
        "shake128-a174-four-prospective-partner-formulas",
        "shake128-a174-fixed-resource-execution",
        "shake128-a174-partner-independent-boundary-result",
    ]
    builder.add_triplet(
        edge_id=ids[0],
        trigger="A173:same_central_position_positive_delta_across_weighted_and_greedy_contexts",
        mechanism="localize_the_candidate_condition_to_alias_input_crossing_solver_positions_12_and_11",
        outcome="A174:partner_independence_question",
        confidence=1.0,
        evidence_kind="position_matched_cross_family_classification",
        source=A173_SHA256,
        attrs={"A173_gate": payload["anchor_gates"]["A173"]},
    )
    builder.add_triplet(
        edge_id=ids[1],
        trigger="A174:partner_independence_question",
        mechanism="replace_partner_0_with_original_right_neighbor_22_at_same_central_boundary",
        outcome="A174:two_new_center_12_22_orders",
        confidence=1.0,
        evidence_kind="prospective_deterministic_partner_transfer",
        source=payload["partner_plan_sha256"],
        provenance=[ids[0]],
        attrs={"partner_plan": payload["partner_plan"]},
    )
    builder.add_triplet(
        edge_id=ids[2],
        trigger="A174:two_new_center_12_22_orders",
        mechanism="compile_inline_and_materialized_alias_arms_for_both_orientations",
        outcome="A174:four_exact_prospective_partner_formulas",
        confidence=1.0,
        evidence_kind="hash_bound_semantics_preserving_formula_frontier",
        source=payload["formula_plan_sha256"],
        provenance=[ids[1]],
        attrs={"formula_plan": payload["formula_plan"]},
    )
    builder.add_triplet(
        edge_id=ids[3],
        trigger="A174:four_exact_prospective_partner_formulas",
        mechanism="execute_all_four_formulas_under_the_unchanged_fixed_resource_protocol",
        outcome="A174:four_partner_transfer_solver_observations",
        confidence=1.0,
        evidence_kind="fixed_resource_execution_and_complete_rate_gate",
        source="Z3_4.15.4_plus_independent_NumPy_lane_core",
        provenance=[ids[2]],
        attrs={"execution_summary": payload["execution_summary"]},
    )
    builder.add_triplet(
        edge_id=ids[4],
        trigger="A174:four_partner_transfer_solver_observations",
        mechanism="compare_alias_position_11_minus_12_effect_with_A173_partner_0_direction",
        outcome="A174:prospective_partner_independent_boundary_test",
        confidence=1.0,
        evidence_kind="paired_cross_partner_prospective_transfer",
        source=payload["partner_transfer_result_sha256"],
        provenance=[ids[3]],
        attrs={"partner_transfer_result": payload["partner_transfer_result"]},
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
        raise RuntimeError("A174 Causal provenance chain failed validation")
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
    a173, a170, a166 = _load_anchor_gates(results_dir)
    partner = _partner_plan(a166)
    baseline = _A166.analyze(results_dir)
    _a164, a162 = _A166._load_anchor_gates(results_dir)
    semantic_gate = next(row for row in a162["semantic_gates"] if row["shift"] == AFFINE_SHIFT)
    rows, formulas = _formula_frontier(
        baseline["problem"],
        baseline["variant"],
        partner,
        semantic_gate,
    )
    plan = _formula_plan(rows)
    return {
        "anchors": (a173, a170, a166),
        "variant": baseline["variant"],
        "problem": baseline["problem"],
        "partner_plan": partner,
        "partner_plan_sha256": _canonical_sha256(partner),
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
    a173, a170, _a166 = analysis["anchors"]
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
    partner_result = _partner_transfer_result(a173, executions)
    posthoc = _posthoc_summary(analysis["problem"], analysis["variant"], executions)
    payload: dict[str, Any] = {
        "schema": SCHEMA,
        "attempt_id": ATTEMPT_ID,
        "evidence_stage": "CENTER_ALIAS_PARTNER_TRANSFER_EXECUTED",
        "result": (
            "A174 prospectively tests whether the central alias-position boundary "
            "transfers from partner coordinate 0 to original neighbor 22."
        ),
        "scope": (
            "The retained A152 SHAKE128 width-24 relation, affine gauge 0x4e1e28, "
            "two new Weighted-Descending-derived central 12/22 orders, shared R2 "
            "prefix, 22 unchanged suffix rounds and all 1,344 rate bits."
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
            "A174_protocol": {
                "artifact_sha256": PROTOCOL_SHA256,
                "protocol_state": analysis["protocol"]["protocol_state"],
                "prospective_prediction": analysis["protocol"]["prospective_prediction"],
                "information_boundary": analysis["protocol"]["information_boundary"],
            },
            "A173": {
                "artifact_sha256": A173_SHA256,
                "family_contrast_result_sha256": A173_CONTRAST_SHA256,
                "weighted_desc_directional_delta": a173["family_contrast_result"][
                    "weighted_desc_directional_delta"
                ],
            },
            "A170": {
                "artifact_sha256": A170_SHA256,
                "polarity_frontier_sha256": a170["polarity_frontier_sha256"],
            },
        },
        "partner_plan": analysis["partner_plan"],
        "partner_plan_sha256": analysis["partner_plan_sha256"],
        "formula_plan": analysis["formula_plan"],
        "formula_plan_sha256": analysis["formula_plan_sha256"],
        "execution": executions,
        "execution_summary": summary,
        "status_counts": status_counts,
        "confirmed_models": confirmed_models,
        "partner_transfer_result": partner_result,
        "partner_transfer_result_sha256": _canonical_sha256(partner_result),
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
        raise RuntimeError("A174 final artifact reopen gate failed")
    return {
        "json_sha256": _sha256(raw),
        "causal_sha256": reader.file_sha256,
        "causal_graph_sha256": reader.graph_sha256,
        "status_counts": status_counts,
        "confirmed_model_count": len(confirmed_models),
        "classification": partner_result["classification"],
        "prospective_prediction_confirmed": partner_result["prospective_prediction_confirmed"],
        "directional_delta": partner_result["directional_delta_alias_position_11_minus_12"],
        "effects": [row["materialization_effect"] for row in partner_result["rows"]],
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
        default=Path(__file__).parents[2] / "build" / "shake-r2-a174",
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
                    "partner_plan_sha256": analysis["partner_plan_sha256"],
                    "partner_plan": analysis["partner_plan"],
                    "formula_plan_sha256": analysis["formula_plan_sha256"],
                    "formulas": [
                        {
                            "name": row["name"],
                            "orientation": row["encoding"]["adjacent_orientation"],
                            "arm": row["encoding"]["alias_compiler_arm"],
                            "alias_input_solver_position": row["encoding"][
                                "alias_input_solver_position"
                            ],
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

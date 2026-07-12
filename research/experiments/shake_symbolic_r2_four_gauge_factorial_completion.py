#!/usr/bin/env python3
"""Complete the frozen A162 four-gauge by four-order fixed-resource matrix."""

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


_A163 = _import_sibling(
    "shake_symbolic_r2_order_weighted_gauge_solver_frontier.py",
    "shake_symbolic_r2_four_gauge_factorial_a163_base",
)
_A162 = _A163._A162
_A161 = _A163._A161
_A159 = _A163._A159
_A158 = _A163._A158
_A156 = _A163._A156
_BASE = _A163._BASE
_NATIVE = _A163._NATIVE
_WINDOW = _A163._WINDOW

ATTEMPT_ID = "A164"
SCHEMA = "shake-symbolic-r2-four-gauge-factorial-completion-v1"
SEED = _A163.SEED
WINDOW_BITS = _A163.WINDOW_BITS
Z3_RLIMIT = _A163.Z3_RLIMIT
EXTERNAL_SAFETY_TIMEOUT_SECONDS = _A163.EXTERNAL_SAFETY_TIMEOUT_SECONDS
A163_FILENAME = _A163.RESULT_FILENAME
A163_SHA256 = "6528a62e4c12739966d06a0eff910fdf3b2739b53e83cc0dd2577a4afa1d6c8d"
A162_FILENAME = _A162.RESULT_FILENAME
A162_SHA256 = _A163.A162_SHA256
PROTOCOL_FILENAME = "shake_symbolic_r2_four_gauge_factorial_completion_v1.json"
PROTOCOL_SHA256 = "84355ca6b5d3b871d82d82ed1fa7c0a38819776ad291c8cd5a931ac40de2f3fb"
PROTOCOL_SCHEMA = "shake-symbolic-r2-four-gauge-factorial-completion-protocol-v1"
RESULT_FILENAME = "shake_symbolic_r2_four_gauge_factorial_completion_v1.json"
CAUSAL_FILENAME = "shake_symbolic_r2_four_gauge_factorial_completion_v1.causal"


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
    a162 = _A156._load_json_gate(
        results_dir / A162_FILENAME,
        A162_SHA256,
        _A162.SCHEMA,
    )
    a163 = _A156._load_json_gate(
        results_dir / A163_FILENAME,
        A163_SHA256,
        _A163.SCHEMA,
    )
    if (
        a162.get("landscape_plan_sha256")
        != "69731436c46e6ad8472fb453fdbb963b8fa95554609291c2e7d621e5a4177367"
        or a162.get("semantic_gate_plan_sha256")
        != "d4a1f290e5dc651a22a15c88a0d8f76a19351ce30578315419bb3d446d2b53ba"
        or len(a162.get("landscapes", [])) != 8
        or len(a162.get("semantic_gates", [])) != 4
        or any(row.get("minimum_tie_count") != 1 for row in a162["landscapes"])
        or a163.get("formula_plan_sha256")
        != "0c14756cb1c5f8dd0cd9403f4f6d963bb4aab0800cf73dd4791509c62f7c2f30"
        or a163.get("control_comparison_sha256")
        != "94e16df30eb35f7a98fc7a1384991dc2f9784884e657f48397ad0ac494172d39"
        or a163.get("status_counts")
        != {"error": 0, "sat": 0, "unknown": 8, "unsat": 0}
        or Z3_RLIMIT != 500_000_000
        or EXTERNAL_SAFETY_TIMEOUT_SECONDS != 300
    ):
        raise RuntimeError("A162/A163 factorial-completion anchor gate failed")
    return a162, a163


def _load_protocol_gate() -> dict[str, Any]:
    path = Path(__file__).parents[1] / "configs" / PROTOCOL_FILENAME
    protocol = _A156._load_json_gate(path, PROTOCOL_SHA256, PROTOCOL_SCHEMA)
    if (
        protocol.get("attempt_id") != ATTEMPT_ID
        or protocol.get("protocol_state") != "frozen_before_any_A164_solver_execution"
        or protocol.get("anchors", {}).get("A162", {}).get("sha256") != A162_SHA256
        or protocol.get("anchors", {}).get("A163", {}).get("sha256") != A163_SHA256
        or protocol.get("selection_rule")
        != {
            "definition": (
                "cartesian_product_of_A158_orders_and_A162_unique_gauges_minus_"
                "the_eight_A162_generating_pairs"
            ),
            "repeats_an_A163_cell": False,
            "uses_A163_pair_ranking": False,
            "uses_A163_solver_counters": False,
            "uses_instrumented_assignment": False,
            "uses_target_rate": False,
        }
    ):
        raise RuntimeError("A164 frozen protocol identity gate failed")
    return protocol


def _validate_protocol_plan(
    protocol: dict[str, Any],
    design: dict[str, Any],
    formula_plan: Sequence[dict[str, Any]],
) -> None:
    frozen = protocol["frozen_plans"]
    observed_formula_rows = [
        [row["name"], row["formula_bytes"], row["formula_sha256"]]
        for row in formula_plan
    ]
    observed_missing_cells = [
        [row["order_name"], row["affine_shift_hex"]]
        for row in design["missing_plan"]
    ]
    if (
        frozen.get("full_factorial_plan_sha256") != design["full_plan_sha256"]
        or frozen.get("missing_cell_plan_sha256") != design["missing_plan_sha256"]
        or frozen.get("formula_plan_sha256") != _canonical_sha256(formula_plan)
        or protocol.get("missing_cells") != observed_missing_cells
        or protocol.get("formula_hashes") != observed_formula_rows
    ):
        raise RuntimeError("A164 regenerated plan differs from frozen protocol")


def _factorial_design(a162: dict[str, Any]) -> dict[str, Any]:
    order_vectors: dict[str, list[int]] = {}
    generating_pairs: set[tuple[str, int]] = set()
    for landscape in a162["landscapes"]:
        order_name = landscape["order_name"]
        vector = list(landscape["variable_to_input_coordinate"])
        previous = order_vectors.setdefault(order_name, vector)
        if previous != vector:
            raise RuntimeError(f"A162 order vector differs across modes: {order_name}")
        generating_pairs.add((order_name, int(landscape["minimum_shift"])))
    if list(order_vectors) != list(_A158.ORDER_NAMES):
        raise RuntimeError("A162 order sequence differs from A158")

    semantic_by_shift = {
        int(row["shift"]): row for row in a162["semantic_gates"]
    }
    shifts = sorted(semantic_by_shift)
    if len(shifts) != 4:
        raise RuntimeError("A162 does not contain four unique semantic gauges")

    full_plan = []
    missing_plan = []
    for order_name in _A158.ORDER_NAMES:
        for shift in shifts:
            row = {
                "order_name": order_name,
                "affine_shift": shift,
                "affine_shift_hex": f"0x{shift:06x}",
                "A163_generating_pair": (order_name, shift) in generating_pairs,
            }
            full_plan.append(row)
            if not row["A163_generating_pair"]:
                missing_plan.append(
                    {
                        **row,
                        "name": f"{order_name}__gauge_{shift:06x}",
                        "execution_order": len(missing_plan),
                    }
                )
    if len(full_plan) != 16 or len(generating_pairs) != 8 or len(missing_plan) != 8:
        raise RuntimeError("A164 factorial cardinality gate failed")
    return {
        "orders": list(_A158.ORDER_NAMES),
        "order_vectors": order_vectors,
        "shifts": shifts,
        "semantic_by_shift": semantic_by_shift,
        "generating_pairs": generating_pairs,
        "full_plan": full_plan,
        "full_plan_sha256": _canonical_sha256(full_plan),
        "missing_plan": missing_plan,
        "missing_plan_sha256": _canonical_sha256(missing_plan),
        "selection_rule": (
            "cartesian_product_of_A158_orders_and_A162_unique_gauges_minus_"
            "the_eight_A162_generating_pairs"
        ),
        "solver_counter_target_or_assignment_used": False,
    }


def _formula_frontier(
    problem: dict[str, Any],
    variant: Any,
    design: dict[str, Any],
) -> tuple[list[dict[str, Any]], dict[str, bytes]]:
    rows = []
    formulas = {}
    for planned in design["missing_plan"]:
        shift = planned["affine_shift"]
        gate = design["semantic_by_shift"][shift]
        order_name = planned["order_name"]
        name = planned["name"]
        writer, inputs, encoding = _A163._encode_problem(
            problem,
            variant,
            name=name,
            order_name=order_name,
            weight_mode="A162_four_gauge_factorial_completion",
            variable_to_shifted_input=design["order_vectors"][order_name],
            affine_shift=shift,
            expected_shifted_polynomial_sha256=(
                gate["shifted_R2_polynomial_state_sha256"]
            ),
            expected_coefficient_incidence=gate["coefficient_incidence"],
        )
        raw = writer.render(inputs, include_model=True)
        formulas[name] = raw
        rows.append(
            {
                "name": name,
                "execution_order": planned["execution_order"],
                "formula_bytes": len(raw),
                "formula_sha256": _sha256(raw),
                "encoding": encoding,
                "solver_input_names": inputs,
                "factorial_selection_rule": design["selection_rule"],
                "solver_outcome_used_for_formula_construction": False,
            }
        )
    if [row["name"] for row in rows] != [
        row["name"] for row in design["missing_plan"]
    ]:
        raise RuntimeError("A164 formula order differs from frozen missing plan")
    return rows, formulas


def _formula_plan(rows: Sequence[dict[str, Any]]) -> list[dict[str, Any]]:
    return [
        {
            "name": row["name"],
            "execution_order": row["execution_order"],
            "formula_bytes": row["formula_bytes"],
            "formula_sha256": row["formula_sha256"],
            "encoding": row["encoding"],
            "factorial_selection_rule": row["factorial_selection_rule"],
            "rlimit": Z3_RLIMIT,
            "wallclock_solver_limit_used": False,
        }
        for row in rows
    ]


def _run_z3_rlimit(z3: Path, path: Path, inputs: list[str]) -> dict[str, Any]:
    result = _A163._run_z3_rlimit(z3, path, inputs)
    result["command_parameters"]["representation"] = (
        "Boolean_SMT_shared_R2_four_gauge_factorial_completion_fixed_rlimit"
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
        raise ValueError("A164 solver work directory must be empty")
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
        raise RuntimeError("A164 solver formula cleanup failed")
    return results


def _execution_summary(executions: Sequence[dict[str, Any]]) -> list[dict[str, Any]]:
    return [
        {
            "name": row["name"],
            "order_name": row["encoding"]["order_name"],
            "affine_shift": row["encoding"]["affine_shift_original_input_mask"],
            "status": row["solver"]["status"],
            "return_code": row["solver"]["return_code"],
            "termination": row["solver"]["termination"],
            "canonical_observation_sha256": row["solver"][
                "canonical_observation_sha256"
            ],
            "stats": row["solver"]["stats"],
            "independently_confirmed_model": row["independently_confirmed_model"],
        }
        for row in executions
    ]


def _full_factorial_matrix(
    design: dict[str, Any],
    a163: dict[str, Any],
    a164_summary: Sequence[dict[str, Any]],
) -> list[dict[str, Any]]:
    cells: dict[tuple[str, int], dict[str, Any]] = {}
    for row in a163["execution_summary"]:
        key = (row["order_name"], int(row["affine_shift"]))
        cells[key] = {
            "order_name": key[0],
            "affine_shift": key[1],
            "affine_shift_hex": f"0x{key[1]:06x}",
            "source_attempt": "A163",
            "generating_weight_mode": row["weight_mode"],
            "status": row["status"],
            "decisions": int(row["stats"].get("decisions", 0)),
            "conflicts": int(row["stats"].get("conflicts", 0)),
            "rlimit_count": int(row["stats"].get("rlimit-count", 0)),
            "canonical_observation_sha256": row["canonical_observation_sha256"],
        }
    for row in a164_summary:
        key = (row["order_name"], int(row["affine_shift"]))
        if key in cells:
            raise RuntimeError(f"A164 unexpectedly repeats completed cell {key}")
        cells[key] = {
            "order_name": key[0],
            "affine_shift": key[1],
            "affine_shift_hex": f"0x{key[1]:06x}",
            "source_attempt": "A164",
            "generating_weight_mode": None,
            "status": row["status"],
            "decisions": int(row["stats"].get("decisions", 0)),
            "conflicts": int(row["stats"].get("conflicts", 0)),
            "rlimit_count": int(row["stats"].get("rlimit-count", 0)),
            "canonical_observation_sha256": row["canonical_observation_sha256"],
        }
    expected = [
        (row["order_name"], row["affine_shift"]) for row in design["full_plan"]
    ]
    if set(cells) != set(expected) or len(cells) != 16:
        raise RuntimeError("A164 did not complete the exact 4x4 factorial matrix")
    return [cells[key] for key in expected]


def _factorial_decomposition(
    design: dict[str, Any], matrix: Sequence[dict[str, Any]]
) -> dict[str, Any]:
    values = {
        (row["order_name"], row["affine_shift"]): row["decisions"] for row in matrix
    }
    order_sums = {
        order: sum(values[(order, shift)] for shift in design["shifts"])
        for order in design["orders"]
    }
    shift_sums = {
        shift: sum(values[(order, shift)] for order in design["orders"])
        for shift in design["shifts"]
    }
    total = sum(values.values())
    interactions = []
    for order in design["orders"]:
        for shift in design["shifts"]:
            numerator = (
                16 * values[(order, shift)]
                - 4 * order_sums[order]
                - 4 * shift_sums[shift]
                + total
            )
            interactions.append(
                {
                    "order_name": order,
                    "affine_shift": shift,
                    "affine_shift_hex": f"0x{shift:06x}",
                    "interaction_decision_residual_numerator": numerator,
                    "interaction_decision_residual_denominator": 16,
                }
            )
    for order in design["orders"]:
        if sum(
            row["interaction_decision_residual_numerator"]
            for row in interactions
            if row["order_name"] == order
        ):
            raise RuntimeError("A164 interaction residual order sum is nonzero")
    for shift in design["shifts"]:
        if sum(
            row["interaction_decision_residual_numerator"]
            for row in interactions
            if row["affine_shift"] == shift
        ):
            raise RuntimeError("A164 interaction residual gauge sum is nonzero")
    ranked = sorted(
        matrix,
        key=lambda row: (
            row["decisions"],
            row["conflicts"],
            design["orders"].index(row["order_name"]),
            design["shifts"].index(row["affine_shift"]),
        ),
    )
    return {
        "grand_decision_sum": total,
        "grand_decision_mean_numerator": total,
        "grand_decision_mean_denominator": 16,
        "order_effects": [
            {
                "order_name": order,
                "decision_sum": order_sums[order],
                "decision_mean_numerator": order_sums[order],
                "decision_mean_denominator": 4,
                "main_effect_vs_grand_numerator": 4 * order_sums[order] - total,
                "main_effect_vs_grand_denominator": 16,
            }
            for order in design["orders"]
        ],
        "gauge_effects": [
            {
                "affine_shift": shift,
                "affine_shift_hex": f"0x{shift:06x}",
                "decision_sum": shift_sums[shift],
                "decision_mean_numerator": shift_sums[shift],
                "decision_mean_denominator": 4,
                "main_effect_vs_grand_numerator": 4 * shift_sums[shift] - total,
                "main_effect_vs_grand_denominator": 16,
            }
            for shift in design["shifts"]
        ],
        "interactions": interactions,
        "maximum_absolute_interaction_numerator": max(
            abs(row["interaction_decision_residual_numerator"])
            for row in interactions
        ),
        "best_cell": ranked[0],
        "worst_cell": ranked[-1],
        "decision_ranking": [
            {
                "rank": rank,
                "order_name": row["order_name"],
                "affine_shift": row["affine_shift"],
                "decisions": row["decisions"],
                "conflicts": row["conflicts"],
            }
            for rank, row in enumerate(ranked, start=1)
        ],
    }


def _posthoc_summary(
    problem: dict[str, Any],
    variant: Any,
    executions: Sequence[dict[str, Any]],
) -> dict[str, Any]:
    actual = _WINDOW._extract_window(problem["base_state"], variant, problem["positions"])
    return {
        "instrumented_input_assignment": actual,
        "extracted_only_after_every_A164_execution": True,
        "used_for_design_formula_order_gauge_or_execution": False,
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
        experiment="shake_symbolic_r2_four_gauge_factorial_completion",
        parameters={
            "attempt_id": ATTEMPT_ID,
            "variant": "shake128",
            "seed": SEED,
            "window_bits": WINDOW_BITS,
            "new_formula_count": 8,
            "completed_factorial_cells": 16,
            "rlimit_per_formula": Z3_RLIMIT,
        },
    )
    ids = [
        "shake128-a162-frozen-four-gauge-four-order-product",
        "shake128-a164-eight-missing-factorial-formulas",
        "shake128-a164-fixed-resource-execution",
        "shake128-a164-complete-four-by-four-matrix",
        "shake128-a164-exact-factorial-decomposition",
    ]
    builder.add_triplet(
        edge_id=ids[0],
        trigger="A162:four_unique_gauges_and_four_frozen_orders",
        mechanism="form_the_complete_cartesian_product_before_using_any_A163_or_A164_solver_counter",
        outcome="A164:frozen_sixteen_cell_factorial_plan",
        confidence=1.0,
        evidence_kind="assignment_target_and_solver_counter_free_factorial_design",
        source=payload["factorial_design"]["full_plan_sha256"],
        attrs={"factorial_design": payload["factorial_design"]},
    )
    builder.add_triplet(
        edge_id=ids[1],
        trigger="A164:frozen_sixteen_cell_factorial_plan",
        mechanism="subtract_only_the_eight_A162_generating_pairs_already_executed_by_A163_and_compile_the_remainder",
        outcome="A164:eight_exact_missing_fullround_formulas",
        confidence=1.0,
        evidence_kind="deterministic_nonrepeating_formula_compilation",
        source=payload["formula_plan_sha256"],
        provenance=[ids[0]],
        attrs={"formula_plan": payload["formula_plan"]},
    )
    builder.add_triplet(
        edge_id=ids[2],
        trigger="A164:eight_exact_missing_fullround_formulas",
        mechanism="execute_sequentially_under_the_unchanged_A159_fixed_resource_protocol_with_independent_model_gates",
        outcome="A164:eight_missing_cell_observations",
        confidence=1.0,
        evidence_kind="fixed_resource_execution_and_complete_rate_verification",
        source="Z3_4.15.4_plus_independent_NumPy_lane_core",
        provenance=[ids[1]],
        attrs={"execution_summary": payload["execution_summary"]},
    )
    builder.add_triplet(
        edge_id=ids[3],
        trigger="A164:eight_missing_cell_observations",
        mechanism="join_by_exact_order_and_gauge_with_the_eight_hash_pinned_A163_cells",
        outcome="A164:complete_four_gauge_by_four_order_matrix",
        confidence=1.0,
        evidence_kind="complete_fixed_resource_factorial_matrix",
        source=payload["full_factorial_matrix_sha256"],
        provenance=[ids[2]],
        attrs={"full_factorial_matrix": payload["full_factorial_matrix"]},
    )
    builder.add_triplet(
        edge_id=ids[4],
        trigger="A164:complete_four_gauge_by_four_order_matrix",
        mechanism="compute_exact_rational_order_gauge_and_interaction_decision_components",
        outcome="A164:resolved_gauge_order_main_effects_and_interactions",
        confidence=1.0,
        evidence_kind="exact_two_factor_counter_decomposition",
        source=payload["factorial_decomposition_sha256"],
        provenance=[ids[3]],
        attrs={
            "factorial_decomposition": payload["factorial_decomposition"],
            "posthoc": payload["posthoc"],
        },
    )
    stats = dict(builder.save(path))
    stats.pop("path", None)
    reader = CryptoCausalReader(path)
    rows = reader.triplets(include_inferred=False)
    by_id = {row["edge_id"]: row for row in rows}
    expected_provenance = [[], [ids[0]], [ids[1]], [ids[2]], [ids[3]]]
    if (
        len(rows) != len(ids)
        or set(by_id) != set(ids)
        or not reader.verify_provenance()
        or [by_id[edge_id]["provenance"] for edge_id in ids] != expected_provenance
        or any(
            by_id[left]["outcome"] != by_id[right]["trigger"]
            for left, right in zip(ids[:-1], ids[1:], strict=True)
        )
    ):
        raise RuntimeError("A164 Causal provenance chain failed validation")
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
    a162, a163 = _load_anchor_gates(results_dir)
    design = _factorial_design(a162)
    variant = _BASE.VARIANTS["shake128"]
    problem = _NATIVE._problem(variant, WINDOW_BITS, SEED)
    rows, formulas = _formula_frontier(problem, variant, design)
    plan = _formula_plan(rows)
    _validate_protocol_plan(protocol, design, plan)
    return {
        "protocol": protocol,
        "anchors": (a162, a163),
        "variant": variant,
        "problem": problem,
        "design": design,
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
    a162, a163 = analysis["anchors"]
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
            "shifted_input_coordinate_assignment": row[
                "shifted_input_coordinate_assignment"
            ],
            "input_coordinate_assignment": row["input_coordinate_assignment"],
            "independent_complete_rate_check": row["independent_complete_rate_check"],
        }
        for row in executions
        if row["independently_confirmed_model"]
    ]
    summary = _execution_summary(executions)
    matrix = _full_factorial_matrix(analysis["design"], a163, summary)
    decomposition = _factorial_decomposition(analysis["design"], matrix)
    posthoc = _posthoc_summary(analysis["problem"], analysis["variant"], executions)
    public_design = {
        key: value
        for key, value in analysis["design"].items()
        if key not in {"order_vectors", "semantic_by_shift", "generating_pairs"}
    }
    payload: dict[str, Any] = {
        "schema": SCHEMA,
        "attempt_id": ATTEMPT_ID,
        "evidence_stage": "COMPLETE_FOUR_GAUGE_BY_FOUR_ORDER_FACTORIAL_EXECUTED",
        "result": (
            "The eight previously unmeasured cells complete the A162 four-gauge "
            "by A158 four-order fixed-resource matrix without repeating A163."
        ),
        "scope": (
            "The retained A152 SHAKE128 width-24 target relation, four exact "
            "A162 affine gauges, four A158 orders, shared-R2 prefixes, 22 "
            "unchanged suffix rounds and all 1,344 rate bits."
        ),
        "parameters": {
            "variant": "SHAKE128",
            "seed": SEED,
            "window_bits": WINDOW_BITS,
            "new_formula_count": 8,
            "complete_factorial_cells": 16,
            "rlimit_per_formula": Z3_RLIMIT,
            "execution_mode": "sequential_one_thread_per_formula",
            "solver": solver_version,
            "solver_wallclock_limit_used": False,
            "external_safety_timeout_seconds": EXTERNAL_SAFETY_TIMEOUT_SECONDS,
            "wallclock_excluded_from_canonical_result": True,
            "global_uniqueness_claimed": False,
        },
        "anchor_gates": {
            "A164_protocol": {
                "artifact_sha256": PROTOCOL_SHA256,
                "protocol_state": analysis["protocol"]["protocol_state"],
                "selection_rule": analysis["protocol"]["selection_rule"],
            },
            "A162": {
                "artifact_sha256": A162_SHA256,
                "landscape_plan_sha256": a162["landscape_plan_sha256"],
                "semantic_gate_plan_sha256": a162["semantic_gate_plan_sha256"],
            },
            "A163": {
                "artifact_sha256": A163_SHA256,
                "formula_plan_sha256": a163["formula_plan_sha256"],
                "control_comparison_sha256": a163["control_comparison_sha256"],
                "status_counts": a163["status_counts"],
            },
        },
        "factorial_design": public_design,
        "formula_plan": analysis["formula_plan"],
        "formula_plan_sha256": analysis["formula_plan_sha256"],
        "execution": executions,
        "execution_summary": summary,
        "status_counts": status_counts,
        "confirmed_models": confirmed_models,
        "full_factorial_matrix": matrix,
        "full_factorial_matrix_sha256": _canonical_sha256(matrix),
        "factorial_decomposition": decomposition,
        "factorial_decomposition_sha256": _canonical_sha256(decomposition),
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
        raise RuntimeError("A164 final artifact reopen gate failed")
    return {
        "json_sha256": _sha256(raw),
        "causal_sha256": reader.file_sha256,
        "causal_graph_sha256": reader.graph_sha256,
        "status_counts": status_counts,
        "confirmed_model_count": len(confirmed_models),
        "best_cell": decomposition["best_cell"],
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
        default=Path(__file__).parents[2] / "build" / "shake-r2-a164",
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
                    "full_plan_sha256": analysis["design"]["full_plan_sha256"],
                    "missing_plan": analysis["design"]["missing_plan"],
                    "missing_plan_sha256": analysis["design"]["missing_plan_sha256"],
                    "formula_plan_sha256": analysis["formula_plan_sha256"],
                    "formulas": [
                        {
                            "name": row["name"],
                            "bytes": row["formula_bytes"],
                            "sha256": row["formula_sha256"],
                            "polynomial_sha256": row["encoding"][
                                "R2_polynomial_state_sha256_in_solver_basis"
                            ],
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

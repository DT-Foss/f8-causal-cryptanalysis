#!/usr/bin/env python3
"""Derive full-round R2 input orders from the exact weighted K24 dictionary."""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import shutil
import sys
from collections import Counter
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


_A157 = _import_sibling(
    "shake_symbolic_r2_shared_monomial_encoder_frontier.py",
    "shake_symbolic_r2_weighted_order_a157_base",
)

_A156 = _A157._A156
_A155 = _A157._A155
_BASE = _A157._BASE
_NATIVE = _A157._NATIVE
_WINDOW = _A157._WINDOW
_R1 = _A157._R1
_SMT = _A157._SMT
_SYMBOLIC = _A157._SYMBOLIC

ATTEMPT_ID = "A158"
SCHEMA = "shake-symbolic-r2-weighted-input-order-frontier-v1"
WINDOW_BITS = _A157.WINDOW_BITS
SEED = _A157.SEED
TIMEOUT_SECONDS = _A157.TIMEOUT_SECONDS
A157_FILENAME = _A157.RESULT_FILENAME
A157_SHA256 = "682c9c70e79702f15e54972c04a26372539e3b3e3473fa6230e053dd898c6ea4"
EXPECTED_R2_POLYNOMIAL_SHA256 = _A157.ORIGINAL_R2_POLYNOMIAL_SHA256
EXPECTED_WEIGHTED_MATRIX_SHA256 = "bd7e5fbf292b0912dc143fbfbc8c7a8f9aec13a7ac29633f86835306c4004c1b"
RESULT_FILENAME = "shake_symbolic_r2_weighted_input_order_frontier_v1.json"
CAUSAL_FILENAME = "shake_symbolic_r2_weighted_input_order_frontier_v1.causal"
ORDER_NAMES = (
    "weighted_degree_descending",
    "weighted_degree_ascending",
    "greedy_max_remaining_weight",
    "greedy_min_remaining_weight",
)


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


def _load_a157_gate(results_dir: Path) -> dict[str, Any]:
    payload = _A156._load_json_gate(results_dir / A157_FILENAME, A157_SHA256, _A157.SCHEMA)
    decisions = {
        row["name"]: int(row["solver"]["stats"]["decisions"])
        for row in payload.get("execution", [])
    }
    if (
        payload.get("status_counts") != {"error": 0, "sat": 0, "unknown": 4, "unsat": 0}
        or payload.get("formula_plan_sha256")
        != "500ab417b3ecab00024b621f2797babfa050270f0cd63556fd0002ef8db77cbf"
        or decisions
        != {
            "original_lazy": 20_649,
            "original_frequency": 20_703,
            "pivot_lazy": 11_853,
            "pivot_frequency": 12_284,
        }
    ):
        raise RuntimeError("A157 weighted-input-order selection gate failed")
    return payload


def _weighted_graph(polynomials: Sequence[frozenset[int]]) -> dict[str, Any]:
    occurrence = Counter(
        mask for polynomial in polynomials for mask in polynomial if mask.bit_count() == 2
    )
    expected = {
        (1 << left) | (1 << right)
        for left in range(WINDOW_BITS)
        for right in range(left + 1, WINDOW_BITS)
    }
    if set(occurrence) != expected:
        raise RuntimeError("weighted R2 graph is not complete K24")
    matrix = [[0] * WINDOW_BITS for _ in range(WINDOW_BITS)]
    for mask, count in occurrence.items():
        coordinates = [index for index in range(WINDOW_BITS) if (mask >> index) & 1]
        left, right = coordinates
        matrix[left][right] = count
        matrix[right][left] = count
    degrees = [sum(row) for row in matrix]
    matrix_sha256 = _canonical_sha256(matrix)
    return {
        "matrix": matrix,
        "weighted_degrees": degrees,
        "edge_count": len(occurrence),
        "minimum_edge_weight": min(occurrence.values()),
        "maximum_edge_weight": max(occurrence.values()),
        "total_edge_weight": sum(occurrence.values()),
        "weighted_matrix_sha256": matrix_sha256,
    }


def _greedy_order(matrix: Sequence[Sequence[int]], maximize: bool) -> list[int]:
    remaining = set(range(len(matrix)))
    order = []
    while remaining:
        scores = {
            coordinate: sum(matrix[coordinate][other] for other in remaining if other != coordinate)
            for coordinate in remaining
        }
        if maximize:
            selected = min(remaining, key=lambda coordinate: (-scores[coordinate], coordinate))
        else:
            selected = min(remaining, key=lambda coordinate: (scores[coordinate], coordinate))
        order.append(selected)
        remaining.remove(selected)
    return order


def _derive_orders(weighted: dict[str, Any]) -> dict[str, list[int]]:
    degrees = weighted["weighted_degrees"]
    matrix = weighted["matrix"]
    orders = {
        "weighted_degree_descending": sorted(
            range(WINDOW_BITS), key=lambda coordinate: (-degrees[coordinate], coordinate)
        ),
        "weighted_degree_ascending": sorted(
            range(WINDOW_BITS), key=lambda coordinate: (degrees[coordinate], coordinate)
        ),
        "greedy_max_remaining_weight": _greedy_order(matrix, True),
        "greedy_min_remaining_weight": _greedy_order(matrix, False),
    }
    if (
        tuple(orders) != ORDER_NAMES
        or len({tuple(order) for order in orders.values()}) != len(ORDER_NAMES)
        or any(sorted(order) != list(range(WINDOW_BITS)) for order in orders.values())
    ):
        raise RuntimeError("weighted R2 order derivation is not four distinct permutations")
    return orders


def _encode_problem(
    problem: dict[str, Any],
    variant: Any,
    name: str,
    variable_to_input: Sequence[int],
) -> tuple[Any, list[str], dict[str, Any]]:
    template = _WINDOW._clear_window(problem["base_state"], variant, problem["positions"])
    original = _R1._SPLIT._symbolic_prefix_polynomials(template, variant, problem["positions"], 2)
    input_to_solver_rows = _A156._input_to_solver_rows(variable_to_input)
    transformed = _A155._substitute_linear_basis(original, input_to_solver_rows, WINDOW_BITS)
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
    return (
        writer,
        inputs,
        {
            "name": name,
            "order_derivation": name,
            "variable_to_input_coordinate": list(variable_to_input),
            "input_to_solver_row_masks_hex": [f"{value:06x}" for value in input_to_solver_rows],
            "R2_polynomial_state_sha256_in_solver_basis": _SYMBOLIC._poly_hash(
                transformed, WINDOW_BITS
            ),
            "semantic_original_R2_polynomial_state_sha256": _A157.ORIGINAL_R2_POLYNOMIAL_SHA256,
            **prefix,
            **suffix,
            "total_variables": writer.variables,
            "total_assertions": writer.assertions,
            "output_assertions": writer.assertions - before_outputs,
            "target_rate_bits": variant.rate_bits,
            "instrumented_assignment_input_used": False,
            "solver_observation_input_used_for_order_derivation": False,
        },
    )


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


def _build_causal(path: Path, payload: dict[str, Any]) -> dict[str, Any]:
    builder = CryptoCausalBuilder(
        experiment="shake_symbolic_r2_weighted_input_order_frontier",
        parameters={
            "attempt_id": ATTEMPT_ID,
            "variant": "shake128",
            "seed": SEED,
            "window_bits": WINDOW_BITS,
            "timeout_seconds_per_order": TIMEOUT_SECONDS,
            "order_count": len(ORDER_NAMES),
        },
    )
    ids = [
        "shake128-a157-input-order-sensitivity",
        "shake128-a158-weighted-k24-orders",
        "shake128-a158-four-weighted-order-formulas",
        "shake128-a158-weighted-order-execution",
    ]
    builder.add_triplet(
        edge_id=ids[0],
        trigger="A157:shared_R2_fullround_solver_frontier_observation",
        mechanism="hash_gate_the_input_order_decision_separation_on_exact_shared_R2_formulas",
        outcome="A158:weighted_input_order_hypothesis",
        confidence=1.0,
        evidence_kind="retained_uniform_solver_frontier",
        source=A157_SHA256,
        attrs={"A157_gate": payload["anchor_gate"]},
    )
    builder.add_triplet(
        edge_id=ids[1],
        trigger="A158:weighted_input_order_hypothesis",
        mechanism="derive_degree_and_dynamic_elimination_orders_from_all_276_exact_R2_occurrence_weights",
        outcome="A158:four_assignment_free_weighted_K24_orders",
        confidence=1.0,
        evidence_kind="deterministic_weighted_graph_algorithms",
        source=payload["weighted_graph"]["weighted_matrix_sha256"],
        provenance=[ids[0]],
        attrs={"weighted_graph": payload["weighted_graph"], "orders": payload["orders"]},
    )
    builder.add_triplet(
        edge_id=ids[2],
        trigger="A158:four_assignment_free_weighted_K24_orders",
        mechanism="compile_each_order_with_the_same_frequency_ordered_301_monomial_R2_prefix_and_full_suffix",
        outcome="A158:four_exact_weighted_order_fullround_formulas",
        confidence=1.0,
        evidence_kind="deterministic_formula_compilation_before_solver_outcomes",
        source=payload["formula_plan_sha256"],
        provenance=[ids[1]],
        attrs={"formula_frontier": payload["formula_frontier"]},
    )
    builder.add_triplet(
        edge_id=ids[3],
        trigger="A158:four_exact_weighted_order_fullround_formulas",
        mechanism="execute_every_order_sequentially_under_one_uniform_Z3_4_15_4_budget_and_check_all_models_independently",
        outcome="A158:weighted_input_order_solver_frontier_observation",
        confidence=1.0,
        evidence_kind="bounded_solver_execution_and_independent_complete_rate_gate",
        source="Z3_4.15.4_plus_independent_NumPy_lane_core",
        provenance=[ids[2]],
        attrs={
            "status_counts": payload["status_counts"],
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
        or any(
            by_id[left]["outcome"] != by_id[right]["trigger"]
            for left, right in zip(ids[:-1], ids[1:], strict=True)
        )
    ):
        raise RuntimeError("A158 Causal provenance chain failed validation")
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
    a157 = _load_a157_gate(results_dir)
    variant = _BASE.VARIANTS["shake128"]
    problem = _NATIVE._problem(variant, WINDOW_BITS, SEED)
    template = _WINDOW._clear_window(problem["base_state"], variant, problem["positions"])
    polynomials = _R1._SPLIT._symbolic_prefix_polynomials(
        template, variant, problem["positions"], 2
    )
    polynomial_sha256 = _SYMBOLIC._poly_hash(polynomials, WINDOW_BITS)
    if polynomial_sha256 != EXPECTED_R2_POLYNOMIAL_SHA256:
        raise RuntimeError(f"A158 original R2 polynomial state differs: {polynomial_sha256}")
    weighted = _weighted_graph(polynomials)
    if weighted["weighted_matrix_sha256"] != EXPECTED_WEIGHTED_MATRIX_SHA256:
        raise RuntimeError("A158 weighted R2 occurrence matrix differs")
    orders = _derive_orders(weighted)
    rows, formulas = _formula_frontier(problem, variant, orders)
    plan = [
        {
            "name": row["name"],
            "execution_order": row["execution_order"],
            "formula_bytes": row["formula_bytes"],
            "formula_sha256": row["formula_sha256"],
            "encoding": row["encoding"],
        }
        for row in rows
    ]
    return {
        "anchor": a157,
        "variant": variant,
        "problem": problem,
        "weighted": weighted,
        "orders": orders,
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
    solver_version = _A156._z3_version_gate(z3)
    executions = _A156._execute_frontier(
        formula_rows=analysis["rows"],
        formulas=analysis["formulas"],
        problem=analysis["problem"],
        variant=analysis["variant"],
        z3=z3,
        work_dir=work_dir,
        run_solver=_A157._run_z3,
    )
    posthoc = _A156._posthoc_summary(analysis["problem"], analysis["variant"], executions)
    status_counts = {
        status: sum(row["solver"]["status"] == status for row in executions)
        for status in ("sat", "unsat", "unknown", "error")
    }
    confirmed_models = [
        {
            "name": row["name"],
            "solver_basis_assignment": row["solver"]["solver_basis_assignment"],
            "input_coordinate_assignment": row["input_coordinate_assignment"],
            "independent_complete_rate_check": row["independent_complete_rate_check"],
        }
        for row in executions
        if row["independently_confirmed_model"]
    ]
    weighted_public = {key: value for key, value in analysis["weighted"].items() if key != "matrix"}
    weighted_public["matrix"] = analysis["weighted"]["matrix"]
    payload: dict[str, Any] = {
        "schema": SCHEMA,
        "attempt_id": ATTEMPT_ID,
        "evidence_stage": "WEIGHTED_R2_INPUT_ORDER_FRONTIER_EXECUTED",
        "result": (
            "Four input permutations derived only from the exact weighted R2 K24 "
            "occurrence matrix execute on the same frequency-ordered shared-R2 "
            "full-round representation under one uniform solver budget."
        ),
        "scope": (
            "The retained A152 SHAKE128 width-24 target relation, exact shared-R2 "
            "interface, 22 explicit suffix rounds, and complete 1,344-bit observation."
        ),
        "parameters": {
            "variant": "SHAKE128",
            "seed": SEED,
            "window_bits": WINDOW_BITS,
            "timeout_seconds_per_order": TIMEOUT_SECONDS,
            "order_count": len(ORDER_NAMES),
            "execution_mode": "sequential_one_thread_per_order",
            "solver": solver_version,
            "wallclock_excluded_from_canonical_result": True,
            "global_uniqueness_claimed": False,
        },
        "anchor_gate": {
            "A157_artifact_sha256": A157_SHA256,
            "A157_formula_plan_sha256": analysis["anchor"]["formula_plan_sha256"],
            "A157_status_counts": analysis["anchor"]["status_counts"],
            "assignment_or_target_projection_imported": False,
        },
        "weighted_graph": weighted_public,
        "orders": analysis["orders"],
        "orders_sha256": _canonical_sha256(analysis["orders"]),
        "formula_plan_sha256": analysis["formula_plan_sha256"],
        "formula_frontier": analysis["formula_plan"],
        "execution": executions,
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
        raise RuntimeError("A158 final artifact reopen gate failed")
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
        default=Path(__file__).parents[2] / "build" / "shake-r2-a158",
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
                    "weighted_graph": {
                        key: value for key, value in analysis["weighted"].items() if key != "matrix"
                    },
                    "orders": analysis["orders"],
                    "formula_plan_sha256": analysis["formula_plan_sha256"],
                    "formula_frontier": analysis["formula_plan"],
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

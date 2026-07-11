#!/usr/bin/env python3
"""Full-round frontier using the exact shared A155 R2 monomial dictionary."""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import shutil
import sys
from collections import Counter
from collections.abc import Sequence
from dataclasses import dataclass
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


_A156 = _import_sibling(
    "shake_symbolic_r1_systematic_encoder_frontier.py",
    "shake_symbolic_r2_shared_encoder_a156_base",
)

_A155 = _A156._A155
_A154 = _A156._A154
_BASE = _A156._BASE
_NATIVE = _A156._NATIVE
_WINDOW = _A156._WINDOW
_R1 = _A156._R1
_SMT = _A156._SMT
_SYMBOLIC = _A156._SYMBOLIC

ATTEMPT_ID = "A157"
SCHEMA = "shake-symbolic-r2-shared-monomial-encoder-frontier-v1"
WINDOW_BITS = _A156.WINDOW_BITS
STATE_BITS = _A156.STATE_BITS
SEED = _A156.SEED
TIMEOUT_SECONDS = _A156.TIMEOUT_SECONDS
A155_FILENAME = _A155.RESULT_FILENAME
A155_SHA256 = _A156.A155_SHA256
A156_FILENAME = _A156.RESULT_FILENAME
A156_SHA256 = "703e8c5c68882a144f60e29867e99f37b5b8bba42ffa70b0aee922d0cb2551ae"
CANONICAL_R2_FORMULA_BYTES = 8_902_576
CANONICAL_R2_FORMULA_SHA256 = "44d326f7b2b14554bea69011b783226544a9b104c35fb1763c784441f2bd4586"
ORIGINAL_R2_POLYNOMIAL_SHA256 = "d30c074bbfe45efce76d8142e37ff9ec93608df839dffb0ca25540d2f7ae1752"
RESULT_FILENAME = "shake_symbolic_r2_shared_monomial_encoder_frontier_v1.json"
CAUSAL_FILENAME = "shake_symbolic_r2_shared_monomial_encoder_frontier_v1.causal"


@dataclass(frozen=True)
class EncoderSpec:
    name: str
    variable_order: str
    quadratic_definition_order: str


ENCODERS = (
    EncoderSpec("original_lazy", "original_input_coordinate", "first_coordinate_use"),
    EncoderSpec(
        "original_frequency",
        "original_input_coordinate",
        "decreasing_coordinate_occurrence_then_numeric_mask",
    ),
    EncoderSpec("pivot_lazy", "A154_pivot_output_coordinate", "first_coordinate_use"),
    EncoderSpec(
        "pivot_frequency",
        "A154_pivot_output_coordinate",
        "decreasing_coordinate_occurrence_then_numeric_mask",
    ),
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


def _load_anchor_gates(results_dir: Path) -> tuple[dict[str, Any], dict[str, Any]]:
    a155 = _A156._load_json_gate(results_dir / A155_FILENAME, A155_SHA256, _A155.SCHEMA)
    a156 = _A156._load_json_gate(results_dir / A156_FILENAME, A156_SHA256, _A156.SCHEMA)
    if (
        a155.get("complete_graph_proof", {}).get("graph") != "K24"
        or a155.get("original_R2", {}).get("global_monomial_count") != 301
        or a155.get("original_R2", {}).get("quadratic_monomial_count") != 276
        or a156.get("status_counts") != {"error": 0, "sat": 0, "unknown": 4, "unsat": 0}
        or a156.get("formula_plan_sha256")
        != "9d5747707fbd99bb9a6766a0a1e1939bc9fe9350f1034e7a2243ae140e3c94af"
    ):
        raise RuntimeError("A155/A156 shared-R2 selection gate failed")
    return a155, a156


def _variable_to_input(spec: EncoderSpec, a154: dict[str, Any]) -> list[int]:
    proxy = _A156.EncoderSpec(
        name=spec.name,
        variable_order=spec.variable_order,
        multi_term_style="define_multi_term_only",
    )
    return _A156._variable_to_input_coordinates(proxy, a154)


def _ordered_quadratics(
    polynomials: Sequence[frozenset[int]], order: str
) -> tuple[list[int], dict[int, int]]:
    occurrence = Counter(
        mask for polynomial in polynomials for mask in polynomial if mask.bit_count() == 2
    )
    if set(occurrence) != {
        (1 << left) | (1 << right)
        for left in range(WINDOW_BITS)
        for right in range(left + 1, WINDOW_BITS)
    }:
        raise RuntimeError("R2 quadratic dictionary is not the exact K24 edge set")
    if order == "first_coordinate_use":
        return [], dict(occurrence)
    if order == "decreasing_coordinate_occurrence_then_numeric_mask":
        values = sorted(occurrence, key=lambda mask: (-occurrence[mask], mask))
        return values, dict(occurrence)
    raise ValueError(f"unknown quadratic definition order: {order}")


def _compile_shared_r2_prefix(
    writer: Any,
    polynomials: Sequence[frozenset[int]],
    definition_order: str,
) -> tuple[list[str], list[str], dict[str, Any]]:
    inputs = [writer.declare("x") for _ in range(WINDOW_BITS)]
    monomials: dict[int, str] = {0: "true"}
    monomials.update({1 << index: inputs[index] for index in range(WINDOW_BITS)})
    predeclared, occurrence = _ordered_quadratics(polynomials, definition_order)
    definition_masks = []

    def monomial(mask: int) -> str:
        existing = monomials.get(mask)
        if existing is not None:
            return existing
        coordinates = [index for index in range(WINDOW_BITS) if (mask >> index) & 1]
        if len(coordinates) != 2:
            raise RuntimeError(f"R2 monomial is not constant, linear, or quadratic: {mask}")
        value = writer.define(f"(and {inputs[coordinates[0]]} {inputs[coordinates[1]]})", "m")
        monomials[mask] = value
        definition_masks.append(mask)
        return value

    for mask in predeclared:
        monomial(mask)

    state = []
    alias_coordinates = []
    state_definitions = 0
    for coordinate, polynomial in enumerate(polynomials):
        expressions = [monomial(mask) for mask in sorted(polynomial)]
        if len(expressions) == 1:
            state.append(expressions[0])
            alias_coordinates.append(coordinate)
        else:
            state.append(writer.define(writer.xor(expressions), "s"))
            state_definitions += 1
    if len(monomials) != 301 or len(definition_masks) != 276:
        raise RuntimeError("shared R2 compiler did not materialize exactly 301 monomials")
    expected_definition_masks = (
        definition_masks if definition_order == "first_coordinate_use" else predeclared
    )
    if definition_masks != expected_definition_masks:
        raise RuntimeError("R2 monomial definition order differs from the declared plan")
    return (
        inputs,
        state,
        {
            "shared_monomial_count": len(monomials),
            "constant_monomials": 1,
            "linear_monomials": WINDOW_BITS,
            "quadratic_monomials": len(definition_masks),
            "quadratic_definition_order": definition_order,
            "quadratic_definition_masks": definition_masks,
            "quadratic_definition_order_sha256": _canonical_sha256(definition_masks),
            "quadratic_occurrence_by_mask_sha256": _canonical_sha256(
                {str(mask): occurrence[mask] for mask in sorted(occurrence)}
            ),
            "minimum_quadratic_coordinate_occurrence": min(occurrence.values()),
            "maximum_quadratic_coordinate_occurrence": max(occurrence.values()),
            "R2_state_definitions": state_definitions,
            "R2_alias_coordinates": alias_coordinates,
            "R2_alias_definition_count_eliminated": len(alias_coordinates),
            "prefix_variables": writer.variables,
            "prefix_assertions": writer.assertions,
        },
    )


def _encode_problem(
    problem: dict[str, Any],
    variant: Any,
    spec: EncoderSpec,
    a154: dict[str, Any],
) -> tuple[Any, list[str], dict[str, Any]]:
    template = _WINDOW._clear_window(problem["base_state"], variant, problem["positions"])
    original = _R1._SPLIT._symbolic_prefix_polynomials(template, variant, problem["positions"], 2)
    variable_to_input = _variable_to_input(spec, a154)
    input_to_solver_rows = _A156._input_to_solver_rows(variable_to_input)
    transformed = _A155._substitute_linear_basis(original, input_to_solver_rows, WINDOW_BITS)
    writer = _SMT.BooleanSMT(SEED)
    inputs, state, prefix = _compile_shared_r2_prefix(
        writer, transformed, spec.quadratic_definition_order
    )
    state, suffix = _SMT._compile_suffix(writer, state, list(range(2, 24)))
    before_outputs = writer.assertions
    for lane in range(variant.rate_lanes):
        lane_value = int(problem["target"][0, lane])
        for bit in range(64):
            literal = state[lane * 64 + bit]
            writer.constrain(literal if ((lane_value >> bit) & 1) else f"(not {literal})")
    encoding = {
        "name": spec.name,
        "variable_order": spec.variable_order,
        "variable_to_input_coordinate": variable_to_input,
        "input_to_solver_row_masks_hex": [f"{value:06x}" for value in input_to_solver_rows],
        "quadratic_definition_order": spec.quadratic_definition_order,
        "R2_polynomial_state_sha256_in_solver_basis": _SYMBOLIC._poly_hash(
            transformed, WINDOW_BITS
        ),
        "semantic_original_R2_polynomial_state_sha256": ORIGINAL_R2_POLYNOMIAL_SHA256,
        **prefix,
        **suffix,
        "total_variables": writer.variables,
        "total_assertions": writer.assertions,
        "output_assertions": writer.assertions - before_outputs,
        "target_rate_bits": variant.rate_bits,
        "instrumented_assignment_input_used": False,
    }
    return writer, inputs, encoding


def _canonical_r2_gate(problem: dict[str, Any], variant: Any) -> dict[str, Any]:
    writer, inputs, encoding = _SMT._encode_problem(problem, variant, SEED)
    raw = writer.render(inputs, include_model=True)
    observed = _sha256(raw)
    if len(raw) != CANONICAL_R2_FORMULA_BYTES or observed != CANONICAL_R2_FORMULA_SHA256:
        raise RuntimeError(f"canonical direct-R2 formula differs: {len(raw)}, {observed}")
    return {
        "formula_bytes": len(raw),
        "formula_sha256": observed,
        "prefix_variables": encoding["r2_variables"],
        "prefix_assertions": encoding["r2_assertions"],
        "total_variables": encoding["total_variables"],
        "total_assertions": encoding["total_assertions"],
        "R2_polynomial_state_sha256": encoding["r2_polynomial_state_sha256"],
        "rerun_as_A157": False,
    }


def _formula_frontier(
    problem: dict[str, Any], variant: Any, a154: dict[str, Any]
) -> tuple[list[dict[str, Any]], dict[str, bytes]]:
    rows = []
    formulas = {}
    for spec in ENCODERS:
        writer, inputs, encoding = _encode_problem(problem, variant, spec, a154)
        raw = writer.render(inputs, include_model=True)
        formulas[spec.name] = raw
        rows.append(
            {
                "name": spec.name,
                "execution_order": len(rows),
                "formula_bytes": len(raw),
                "formula_sha256": _sha256(raw),
                "encoding": encoding,
                "solver_input_names": inputs,
                "solver_outcome_used_for_formula_construction": False,
            }
        )
    return rows, formulas


def _run_z3(z3: Path, path: Path, inputs: list[str]) -> dict[str, Any]:
    result = _A156._run_z3(z3, path, inputs)
    result["command_parameters"]["representation"] = (
        "Boolean_SMT_native_nary_XOR_shared_symbolic_R2"
    )
    return result


def _build_causal(path: Path, payload: dict[str, Any]) -> dict[str, Any]:
    builder = CryptoCausalBuilder(
        experiment="shake_symbolic_r2_shared_monomial_encoder_frontier",
        parameters={
            "attempt_id": ATTEMPT_ID,
            "variant": "shake128",
            "seed": SEED,
            "window_bits": WINDOW_BITS,
            "timeout_seconds_per_encoder": TIMEOUT_SECONDS,
            "encoder_count": len(ENCODERS),
        },
    )
    ids = [
        "shake128-a155-exact-shared-r2-dictionary",
        "shake128-a156-systematic-r1-boundary",
        "shake128-a157-four-r2-encoder-plan",
        "shake128-a157-shared-r2-fullround-execution",
    ]
    builder.add_triplet(
        edge_id=ids[0],
        trigger="A155:R2_interaction_graph_is_exactly_K24",
        mechanism="hash_gate_the_exact_301_monomial_R2_dictionary_and_basis_map",
        outcome="A157:complete_shared_R2_prefix_relation",
        confidence=1.0,
        evidence_kind="retained_exact_boolean_ring_artifact",
        source=A155_SHA256,
        attrs={"A155_gate": payload["anchor_gates"]["A155"]},
    )
    builder.add_triplet(
        edge_id=ids[1],
        trigger="A157:complete_shared_R2_prefix_relation",
        mechanism="use_the_A156_alias_only_boundary_to_replace_one_generic_suffix_round",
        outcome="A157:direct_R2_shared_monomial_encoder_selected",
        confidence=1.0,
        evidence_kind="retained_uniform_systematic_R1_frontier",
        source=A156_SHA256,
        provenance=[ids[0]],
        attrs={"A156_gate": payload["anchor_gates"]["A156"]},
    )
    builder.add_triplet(
        edge_id=ids[2],
        trigger="A157:direct_R2_shared_monomial_encoder_selected",
        mechanism="freeze_original_or_pivot_variable_order_crossed_with_lazy_or_frequency_quadratic_definition_order",
        outcome="A157:four_exact_shared_R2_fullround_formulas",
        confidence=1.0,
        evidence_kind="deterministic_formula_compilation_before_solver_outcomes",
        source=payload["formula_plan_sha256"],
        provenance=[ids[1]],
        attrs={"formula_frontier": payload["formula_frontier"]},
    )
    builder.add_triplet(
        edge_id=ids[3],
        trigger="A157:four_exact_shared_R2_fullround_formulas",
        mechanism="execute_every_formula_sequentially_under_one_uniform_Z3_4_15_4_budget_and_check_all_models_independently",
        outcome="A157:shared_R2_fullround_solver_frontier_observation",
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
        raise RuntimeError("A157 Causal provenance chain failed validation")
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
    a155, a156 = _load_anchor_gates(results_dir)
    _, a154, _ = _A156._anchor_gates(results_dir)
    variant = _BASE.VARIANTS["shake128"]
    problem = _NATIVE._problem(variant, WINDOW_BITS, SEED)
    canonical = _canonical_r2_gate(problem, variant)
    rows, formulas = _formula_frontier(problem, variant, a154)
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
        "anchors": (a155, a156, a154),
        "variant": variant,
        "problem": problem,
        "canonical": canonical,
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
    a155, a156, _ = analysis["anchors"]
    solver_version = _A156._z3_version_gate(z3)
    executions = _A156._execute_frontier(
        formula_rows=analysis["rows"],
        formulas=analysis["formulas"],
        problem=analysis["problem"],
        variant=analysis["variant"],
        z3=z3,
        work_dir=work_dir,
        run_solver=_run_z3,
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
    payload: dict[str, Any] = {
        "schema": SCHEMA,
        "attempt_id": ATTEMPT_ID,
        "evidence_stage": "SHARED_R2_FULLROUND_ENCODER_FRONTIER_EXECUTED",
        "result": (
            "Four exact shared-R2 encoders replace one generic suffix round with "
            "the complete 301-monomial A155 dictionary and execute sequentially "
            "under one uniform Z3 4.15.4 budget."
        ),
        "scope": (
            "The retained A152 SHAKE128 width-24 target relation, exact R2 interface, "
            "22 explicit suffix rounds, and complete 1,344-bit observation."
        ),
        "parameters": {
            "variant": "SHAKE128",
            "seed": SEED,
            "window_bits": WINDOW_BITS,
            "timeout_seconds_per_encoder": TIMEOUT_SECONDS,
            "encoder_count": len(ENCODERS),
            "execution_mode": "sequential_one_thread_per_encoder",
            "solver": solver_version,
            "wallclock_excluded_from_canonical_result": True,
            "global_uniqueness_claimed": False,
        },
        "anchor_gates": {
            "A155": {
                "artifact_sha256": A155_SHA256,
                "R2_global_monomials": a155["original_R2"]["global_monomial_count"],
                "R2_quadratic_monomials": a155["original_R2"]["quadratic_monomial_count"],
                "R2_graph": a155["complete_graph_proof"]["graph"],
            },
            "A156": {
                "artifact_sha256": A156_SHA256,
                "status_counts": a156["status_counts"],
                "formula_plan_sha256": a156["formula_plan_sha256"],
            },
        },
        "canonical_R2_formula": analysis["canonical"],
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
        raise RuntimeError("A157 final artifact reopen gate failed")
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
        default=Path(__file__).parents[2] / "build" / "shake-r2-a157",
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
                    "canonical_R2_formula": analysis["canonical"],
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

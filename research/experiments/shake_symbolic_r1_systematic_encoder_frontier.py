#!/usr/bin/env python3
"""Full-round solver frontier for exact systematic A152 R1 encoders.

A154 proves that 24 early R1 output deltas are a permutation of the 24 hidden
inputs. A155 proves that moving the split to R2 immediately produces K24 and a
size-23 minimum vertex cover. This experiment therefore keeps the R1 split and
removes redundant constant and alias definitions before compiling the exact
same R2--R24 suffix and complete 1,344-bit target relation.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import shutil
import subprocess
import sys
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


_A155 = _import_sibling(
    "shake_symbolic_r2_pivot_basis_reader.py",
    "shake_symbolic_r1_systematic_encoder_a155_base",
)

_A154 = _A155._A154
_A151 = _A154._A151
_BASE = _A154._BASE
_NATIVE = _A154._NATIVE
_WINDOW = _A154._WINDOW
_R1 = _A154._R1
_SMT = _R1._SPLIT._SMT
_SYMBOLIC = _A154._SYMBOLIC
_VERIFY = _A151._VERIFY

ATTEMPT_ID = "A156"
SCHEMA = "shake-symbolic-r1-systematic-encoder-frontier-v1"
WINDOW_BITS = _A154.WINDOW_BITS
STATE_BITS = _A154.STATE_BITS
SEED = _A154.SEED
TIMEOUT_SECONDS = 120
EXPECTED_Z3_VERSION_PREFIX = "Z3 version 4.15.4 "
A152_FILENAME = _A154.A152_FILENAME
A152_SHA256 = _A154.A152_SHA256
A152_SMT_SHA256 = "8dc549599b1d699d632be37312b0efacd43f73e073a16f5829ddc42f0c4f23c7"
A152_SMT_BYTES = 9_187_001
A154_FILENAME = _A155.A154_FILENAME
A154_SHA256 = _A155.A154_SHA256
A155_FILENAME = _A155.RESULT_FILENAME
A155_SHA256 = "ead5673a7a7d539cea2c924175e3e80190b5ae9d2a23f28555ddd1f38925ae80"
RESULT_FILENAME = "shake_symbolic_r1_systematic_encoder_frontier_v1.json"
CAUSAL_FILENAME = "shake_symbolic_r1_systematic_encoder_frontier_v1.causal"


@dataclass(frozen=True)
class EncoderSpec:
    name: str
    variable_order: str
    multi_term_style: str


ENCODERS = (
    EncoderSpec("original_alias", "original_input_coordinate", "define_multi_term_only"),
    EncoderSpec("original_inline", "original_input_coordinate", "inline_all_affine_terms"),
    EncoderSpec("pivot_alias", "A154_pivot_output_coordinate", "define_multi_term_only"),
    EncoderSpec("pivot_inline", "A154_pivot_output_coordinate", "inline_all_affine_terms"),
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


def _load_json_gate(path: Path, expected_sha256: str, schema: str) -> dict[str, Any]:
    raw = path.read_bytes()
    observed = _sha256(raw)
    if observed != expected_sha256:
        raise RuntimeError(f"retained artifact hash differs for {path.name}: {observed}")
    payload = json.loads(raw)
    if payload.get("schema") != schema:
        raise RuntimeError(f"retained artifact schema differs for {path.name}")
    return payload


def _anchor_gates(results_dir: Path) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    a152 = _load_json_gate(
        results_dir / A152_FILENAME,
        A152_SHA256,
        "shake-symbolic-r1-width24-prospective-transfer-v1",
    )
    a154 = _load_json_gate(results_dir / A154_FILENAME, A154_SHA256, _A154.SCHEMA)
    a155 = _load_json_gate(results_dir / A155_FILENAME, A155_SHA256, _A155.SCHEMA)
    if (
        a152.get("selection", {}).get("interaction_edges") != []
        or a152.get("execution", {}).get("status_counts", {}).get("unknown") != 1
        or a154.get("basis", {}).get("systematic_unit_row_basis") is not True
        or a154.get("basis", {}).get("rank") != WINDOW_BITS
        or a155.get("complete_graph_proof", {}).get("graph") != "K24"
        or a155.get("complete_graph_proof", {}).get("minimum_vertex_cover_size") != 23
    ):
        raise RuntimeError("A152/A154/A155 mechanism gates failed")
    return a152, a154, a155


def _variable_to_input_coordinates(spec: EncoderSpec, a154: dict[str, Any]) -> list[int]:
    if spec.variable_order == "original_input_coordinate":
        return list(range(WINDOW_BITS))
    if spec.variable_order == "A154_pivot_output_coordinate":
        values = list(map(int, a154["basis"]["pivot_delta_to_input_coordinate"]))
        if sorted(values) != list(range(WINDOW_BITS)):
            raise RuntimeError("A154 pivot order is not a permutation")
        return values
    raise ValueError(f"unknown variable order: {spec.variable_order}")


def _input_to_solver_rows(variable_to_input: Sequence[int]) -> list[int]:
    if sorted(variable_to_input) != list(range(len(variable_to_input))):
        raise ValueError("solver variable order must be a complete input permutation")
    return [
        1 << list(variable_to_input).index(input_coordinate)
        for input_coordinate in range(len(variable_to_input))
    ]


def _affine_expression(inputs: Sequence[str], polynomial: frozenset[int]) -> tuple[str, int, bool]:
    constant = 0 in polynomial
    masks = sorted(mask for mask in polynomial if mask != 0)
    if any(mask.bit_count() != 1 for mask in masks):
        raise RuntimeError("systematic R1 encoder received a non-affine polynomial")
    terms = [inputs[mask.bit_length() - 1] for mask in masks]
    if not terms:
        return ("true" if constant else "false"), 0, constant
    core = terms[0] if len(terms) == 1 else f"(xor {' '.join(terms)})"
    return (f"(not {core})" if constant else core), len(terms), constant


def _compile_systematic_prefix(
    writer: Any,
    polynomials: Sequence[frozenset[int]],
    style: str,
) -> tuple[list[str], list[str], dict[str, Any]]:
    inputs = [writer.declare("x") for _ in range(WINDOW_BITS)]
    state = []
    counts = {
        "constant_false": 0,
        "constant_true": 0,
        "direct_variable": 0,
        "negated_variable": 0,
        "multi_term": 0,
        "multi_term_definitions": 0,
        "multi_term_inlined": 0,
    }
    variables_before_state = writer.variables
    assertions_before_state = writer.assertions
    for polynomial in polynomials:
        expression, terms, constant = _affine_expression(inputs, polynomial)
        if terms == 0:
            counts["constant_true" if constant else "constant_false"] += 1
            state.append(expression)
        elif terms == 1:
            counts["negated_variable" if constant else "direct_variable"] += 1
            state.append(expression)
        else:
            counts["multi_term"] += 1
            if style == "define_multi_term_only":
                counts["multi_term_definitions"] += 1
                state.append(writer.define(expression, "s"))
            elif style == "inline_all_affine_terms":
                counts["multi_term_inlined"] += 1
                state.append(expression)
            else:
                raise ValueError(f"unknown systematic prefix style: {style}")
    if (
        sum(
            counts[key]
            for key in (
                "constant_false",
                "constant_true",
                "direct_variable",
                "negated_variable",
                "multi_term",
            )
        )
        != STATE_BITS
    ):
        raise RuntimeError("systematic prefix classification is incomplete")
    return (
        inputs,
        state,
        {
            "state_coordinate_classes": counts,
            "prefix_declared_input_variables": WINDOW_BITS,
            "prefix_auxiliary_variables": writer.variables - variables_before_state,
            "prefix_assertions": writer.assertions - assertions_before_state,
            "constant_and_alias_coordinates_without_definitions": (
                counts["constant_false"]
                + counts["constant_true"]
                + counts["direct_variable"]
                + counts["negated_variable"]
            ),
            "eliminated_prefix_definitions_vs_canonical": STATE_BITS
            - (writer.assertions - assertions_before_state),
        },
    )


def _encode_systematic_problem(
    problem: dict[str, Any],
    variant: Any,
    spec: EncoderSpec,
    a154: dict[str, Any],
) -> tuple[Any, list[str], dict[str, Any]]:
    template = _WINDOW._clear_window(problem["base_state"], variant, problem["positions"])
    original = _R1._SPLIT._symbolic_prefix_polynomials(template, variant, problem["positions"], 1)
    variable_to_input = _variable_to_input_coordinates(spec, a154)
    input_to_solver_rows = _input_to_solver_rows(variable_to_input)
    transformed = _A155._substitute_linear_basis(original, input_to_solver_rows, WINDOW_BITS)
    writer = _SMT.BooleanSMT(SEED)
    inputs, state, prefix = _compile_systematic_prefix(writer, transformed, spec.multi_term_style)
    state, suffix = _SMT._compile_suffix(writer, state, list(range(1, 24)))
    before_outputs = writer.assertions
    for lane in range(variant.rate_lanes):
        lane_value = int(problem["target"][0, lane])
        for bit in range(64):
            literal = state[lane * 64 + bit]
            writer.constrain(literal if ((lane_value >> bit) & 1) else f"(not {literal})")
    encoding = {
        "name": spec.name,
        "variable_order": spec.variable_order,
        "multi_term_style": spec.multi_term_style,
        "variable_to_input_coordinate": variable_to_input,
        "input_to_solver_row_masks_hex": [f"{value:06x}" for value in input_to_solver_rows],
        "R1_polynomial_state_sha256_in_solver_basis": _SYMBOLIC._poly_hash(
            transformed, WINDOW_BITS
        ),
        "semantic_original_R1_polynomial_state_sha256": _A154.A152_POLYNOMIAL_SHA256,
        **prefix,
        **suffix,
        "total_variables": writer.variables,
        "total_assertions": writer.assertions,
        "output_assertions": writer.assertions - before_outputs,
        "native_xor_equations": True,
        "target_rate_bits": variant.rate_bits,
        "instrumented_assignment_input_used": False,
    }
    return writer, inputs, encoding


def _formula_frontier(
    problem: dict[str, Any], variant: Any, a154: dict[str, Any]
) -> tuple[list[dict[str, Any]], dict[str, bytes]]:
    rows = []
    formulas = {}
    for spec in ENCODERS:
        writer, inputs, encoding = _encode_systematic_problem(problem, variant, spec, a154)
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
    if [row["name"] for row in rows] != [spec.name for spec in ENCODERS]:
        raise RuntimeError("systematic encoder plan order differs")
    return rows, formulas


def _canonical_formula_gate(problem: dict[str, Any], variant: Any) -> dict[str, Any]:
    writer, inputs, encoding = _R1._SPLIT._encode_problem(problem, variant, SEED, prefix_rounds=1)
    raw = writer.render(inputs, include_model=True)
    observed = _sha256(raw)
    if len(raw) != A152_SMT_BYTES or observed != A152_SMT_SHA256:
        raise RuntimeError(f"canonical A152 formula differs: {len(raw)} bytes, {observed}")
    return {
        "formula_bytes": len(raw),
        "formula_sha256": observed,
        "prefix_variables": encoding["prefix_variables"],
        "prefix_assertions": encoding["prefix_assertions"],
        "total_variables": encoding["total_variables"],
        "total_assertions": encoding["total_assertions"],
        "retained_solver_status": "unknown",
        "retained_timeout_seconds": TIMEOUT_SECONDS,
        "retained_result_anchor_sha256": A152_SHA256,
        "rerun_as_A156": False,
    }


def _z3_version_gate(z3: Path) -> str:
    version = subprocess.run(
        [str(z3), "-version"], check=True, capture_output=True, text=True
    ).stdout.strip()
    if not version.startswith(EXPECTED_Z3_VERSION_PREFIX):
        raise RuntimeError(f"Z3 version differs; expected 4.15.4, observed {version}")
    return version


def _run_z3(z3: Path, path: Path, inputs: list[str]) -> dict[str, Any]:
    command = [str(z3), "-smt2", "-st", f"-T:{TIMEOUT_SECONDS}", str(path)]
    try:
        completed = subprocess.run(
            command,
            check=False,
            capture_output=True,
            text=True,
            timeout=TIMEOUT_SECONDS + 15,
        )
        stdout = completed.stdout
        stderr = completed.stderr
        return_code = completed.returncode
        external_timeout = False
    except subprocess.TimeoutExpired as error:
        stdout = error.stdout or ""
        stderr = error.stderr or ""
        if isinstance(stdout, bytes):
            stdout = stdout.decode(errors="replace")
        if isinstance(stderr, bytes):
            stderr = stderr.decode(errors="replace")
        return_code = None
        external_timeout = True
    combined = stdout + stderr
    status = "unknown" if external_timeout else _SMT._parse_status(combined)
    assignment = _SMT._parse_assignment(combined, inputs) if status == "sat" else None
    return {
        "status": status,
        "solver_basis_assignment": assignment,
        "stats": _SMT._parse_stats(combined),
        "return_code": return_code,
        "external_timeout": external_timeout,
        "stdout_bytes": len(stdout.encode()),
        "stdout_sha256": _sha256(stdout.encode()),
        "stderr_bytes": len(stderr.encode()),
        "stderr_sha256": _sha256(stderr.encode()),
        "combined_output_sha256": _sha256(combined.encode()),
        "command_parameters": {
            "timeout_seconds": TIMEOUT_SECONDS,
            "threads": 1,
            "representation": "Boolean_SMT_native_nary_XOR_systematic_R1",
        },
    }


def _verify_solver_row(
    row: dict[str, Any], result: dict[str, Any], problem: dict[str, Any], variant: Any
) -> dict[str, Any]:
    solver_assignment = result["solver_basis_assignment"]
    if result["status"] == "sat" and solver_assignment is None:
        raise RuntimeError(f"{row['name']} returned SAT without a complete input model")
    if result["status"] != "sat" and solver_assignment is not None:
        raise RuntimeError(f"{row['name']} returned an assignment with non-SAT status")
    input_assignment = None
    verification = None
    if solver_assignment is not None:
        inverse_rows = [
            int(value, 16) for value in row["encoding"]["input_to_solver_row_masks_hex"]
        ]
        input_assignment = _A154._recover_input(solver_assignment, inverse_rows)
        verification = _VERIFY(problem, variant, input_assignment)
        if not (
            verification.get("complete_rate_match") is True
            and verification.get("rate_bits_checked") == variant.rate_bits
            and verification.get("candidate_rate_sha256") == verification.get("target_rate_sha256")
        ):
            raise RuntimeError(f"{row['name']} emitted an independently invalid SAT model")
    return {
        **row,
        "solver": result,
        "input_coordinate_assignment": input_assignment,
        "independent_complete_rate_check": verification,
        "independently_confirmed_model": verification is not None,
        "model_mapping": "solver_basis_to_original_input_via_declared_permutation",
    }


def _execute_frontier(
    *,
    formula_rows: Sequence[dict[str, Any]],
    formulas: dict[str, bytes],
    problem: dict[str, Any],
    variant: Any,
    z3: Path,
    work_dir: Path,
    run_solver: Any = _run_z3,
) -> list[dict[str, Any]]:
    work_dir.mkdir(parents=True, exist_ok=True)
    if any(work_dir.iterdir()):
        raise ValueError("solver-frontier work directory must be empty")
    results = []
    try:
        for row in formula_rows:
            path = work_dir / f"{row['execution_order']:02d}_{row['name']}.smt2"
            path.write_bytes(formulas[row["name"]])
            result = run_solver(z3, path, row["solver_input_names"])
            path.unlink(missing_ok=True)
            if result["status"] == "error" or (
                result["return_code"] not in (0, None) and not result["external_timeout"]
            ):
                raise RuntimeError(f"{row['name']} solver execution failed: {result}")
            results.append(_verify_solver_row(dict(row), result, problem, variant))
    finally:
        for path in work_dir.glob("*.smt2"):
            path.unlink(missing_ok=True)
    if any(work_dir.iterdir()):
        raise RuntimeError("solver-frontier formula cleanup failed")
    return results


def _posthoc_summary(
    problem: dict[str, Any], variant: Any, executions: Sequence[dict[str, Any]]
) -> dict[str, Any]:
    actual = _WINDOW._extract_window(problem["base_state"], variant, problem["positions"])
    rows = []
    for row in executions:
        assignment = row["input_coordinate_assignment"]
        rows.append(
            {
                "name": row["name"],
                "solver_status": row["solver"]["status"],
                "model_matches_instrumented_assignment": (
                    assignment == actual if assignment is not None else None
                ),
            }
        )
    return {
        "instrumented_assignment": actual,
        "extracted_only_after_every_encoder_execution": True,
        "used_for_formula_construction_or_execution_order": False,
        "encoder_rows": rows,
    }


def _build_causal(path: Path, payload: dict[str, Any]) -> dict[str, Any]:
    builder = CryptoCausalBuilder(
        experiment="shake_symbolic_r1_systematic_encoder_frontier",
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
        "shake128-a152-affine-r1-fullround-boundary",
        "shake128-a154-systematic-output-basis",
        "shake128-a155-r2-complete-graph-boundary",
        "shake128-a156-systematic-r1-encoder-frontier",
        "shake128-a156-fullround-execution",
    ]
    builder.add_triplet(
        edge_id=ids[0],
        trigger="A152:prospective_affine_R1_transfer_boundary",
        mechanism="hash_gate_the_exact_unknown_canonical_fullround_formula_and_target_relation",
        outcome="A156:canonical_R1_fullround_formula_anchor",
        confidence=1.0,
        evidence_kind="retained_formula_and_result_hashes",
        source=A152_SHA256,
        attrs={"canonical_formula": payload["canonical_formula"]},
    )
    builder.add_triplet(
        edge_id=ids[1],
        trigger="A156:canonical_R1_fullround_formula_anchor",
        mechanism="reuse_the_A154_rank24_systematic_R1_output_delta_permutation",
        outcome="A156:exact_systematic_R1_solver_variables",
        confidence=1.0,
        evidence_kind="two_sided_GF2_inverse_and_systematic_unit_rows",
        source=A154_SHA256,
        provenance=[ids[0]],
        attrs={"A154_gate": payload["anchor_gates"]["A154"]},
    )
    builder.add_triplet(
        edge_id=ids[2],
        trigger="A156:exact_systematic_R1_solver_variables",
        mechanism="apply_the_A155_K24_boundary_to_keep_the_split_at_R1",
        outcome="A156:R1_alias_and_constant_elimination_selected",
        confidence=1.0,
        evidence_kind="exact_complete_R2_interaction_graph_and_size23_cover",
        source=A155_SHA256,
        provenance=[ids[1]],
        attrs={"A155_gate": payload["anchor_gates"]["A155"]},
    )
    builder.add_triplet(
        edge_id=ids[3],
        trigger="A156:R1_alias_and_constant_elimination_selected",
        mechanism="compile_four_predeclared_original_or_pivot_order_alias_or_inline_encoders",
        outcome="A156:semantically_identical_systematic_fullround_formula_frontier",
        confidence=1.0,
        evidence_kind="exact_symbolic_compilation_and_complete_1344_bit_constraints",
        source=payload["formula_plan_sha256"],
        provenance=[ids[2]],
        attrs={"formula_frontier": payload["formula_frontier"]},
    )
    builder.add_triplet(
        edge_id=ids[4],
        trigger="A156:semantically_identical_systematic_fullround_formula_frontier",
        mechanism="execute_every_predeclared_encoder_sequentially_with_the_same_Z3_4_15_4_budget_and_check_all_models_independently",
        outcome="A156:systematic_R1_fullround_solver_frontier_observation",
        confidence=1.0,
        evidence_kind="uniform_bounded_solver_execution_and_independent_full_rate_checks",
        source="Z3_4.15.4_plus_independent_NumPy_lane_core",
        provenance=[ids[3]],
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
        raise RuntimeError("A156 Causal provenance chain failed validation")
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
    a152, a154, a155 = _anchor_gates(results_dir)
    variant = _BASE.VARIANTS["shake128"]
    problem = _NATIVE._problem(variant, WINDOW_BITS, SEED)
    canonical = _canonical_formula_gate(problem, variant)
    rows, formulas = _formula_frontier(problem, variant, a154)
    formula_plan = [
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
        "anchors": (a152, a154, a155),
        "variant": variant,
        "problem": problem,
        "canonical": canonical,
        "rows": rows,
        "formulas": formulas,
        "formula_plan": formula_plan,
        "formula_plan_sha256": _canonical_sha256(formula_plan),
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
    a152, a154, a155 = analysis["anchors"]
    solver_version = _z3_version_gate(z3)
    executions = _execute_frontier(
        formula_rows=analysis["rows"],
        formulas=analysis["formulas"],
        problem=analysis["problem"],
        variant=analysis["variant"],
        z3=z3,
        work_dir=work_dir,
    )
    posthoc = _posthoc_summary(analysis["problem"], analysis["variant"], executions)
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
    reductions = []
    for row in analysis["formula_plan"]:
        encoding = row["encoding"]
        reductions.append(
            {
                "name": row["name"],
                "formula_byte_reduction": analysis["canonical"]["formula_bytes"]
                - row["formula_bytes"],
                "formula_byte_reduction_fraction": (
                    analysis["canonical"]["formula_bytes"] - row["formula_bytes"]
                )
                / analysis["canonical"]["formula_bytes"],
                "prefix_assertion_reduction": analysis["canonical"]["prefix_assertions"]
                - encoding["prefix_assertions"],
                "prefix_variable_reduction": analysis["canonical"]["prefix_variables"]
                - (
                    encoding["prefix_declared_input_variables"]
                    + encoding["prefix_auxiliary_variables"]
                ),
                "full_formula_relation_changed": False,
            }
        )
    payload: dict[str, Any] = {
        "schema": SCHEMA,
        "attempt_id": ATTEMPT_ID,
        "evidence_stage": "SYSTEMATIC_R1_FULLROUND_ENCODER_FRONTIER_EXECUTED",
        "result": (
            "Four exact systematic R1 encoders remove constant and alias definitions "
            "from the same A152 full-round relation and are executed sequentially "
            "under one uniform Z3 4.15.4 budget; every returned model is checked "
            "against all 1,344 rate bits."
        ),
        "scope": (
            "The retained A152 SHAKE128 width-24 target relation, exact R1 interface, "
            "23 explicit suffix rounds, and complete 1,344-bit observation."
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
            "A152": {
                "artifact_sha256": A152_SHA256,
                "R1_edges": len(a152["selection"]["interaction_edges"]),
                "retained_solver_status": a152["execution"]["status_counts"],
            },
            "A154": {
                "artifact_sha256": A154_SHA256,
                "rank": a154["basis"]["rank"],
                "systematic_unit_row_basis": a154["basis"]["systematic_unit_row_basis"],
                "basis_sha256": a154["basis"]["basis_sha256"],
            },
            "A155": {
                "artifact_sha256": A155_SHA256,
                "R2_graph": a155["complete_graph_proof"]["graph"],
                "R2_minimum_vertex_cover_size": a155["complete_graph_proof"][
                    "minimum_vertex_cover_size"
                ],
                "transition_sha256": a155["transition"]["transition_sha256"],
            },
        },
        "canonical_formula": analysis["canonical"],
        "formula_plan_sha256": analysis["formula_plan_sha256"],
        "formula_frontier": analysis["formula_plan"],
        "static_reductions": reductions,
        "execution": executions,
        "status_counts": status_counts,
        "confirmed_models": confirmed_models,
        "posthoc": posthoc,
        "next_mechanism": {
            "selected_from_observation_after_uniform_frontier": None,
            "rule": (
                "If a systematic encoder returns an independently confirmed model, "
                "retain its exact byte representation. Otherwise use the complete "
                "solver statistics and formula graph to define a separate variable-"
                "ordering or suffix-constant-propagation experiment."
            ),
        },
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
        raise RuntimeError("A156 final artifact reopen gate failed")
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
        default=Path(__file__).parents[2] / "build" / "shake-r1-a156",
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
                    "canonical_formula": analysis["canonical"],
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

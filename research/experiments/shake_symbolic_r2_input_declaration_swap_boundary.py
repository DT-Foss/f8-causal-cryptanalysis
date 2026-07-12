#!/usr/bin/env python3
"""Test whether A174's central boundary survives swapping x11/x12 declarations."""

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


_A175 = _import_sibling(
    "shake_symbolic_r2_alpha_renamed_center_boundary.py",
    "shake_symbolic_r2_declaration_swap_a175_base",
)
_A174 = _A175._A174
_A173 = _A175._A173
_A163 = _A175._A163
_A156 = _A175._A156

ATTEMPT_ID = "A176"
SCHEMA = "shake-symbolic-r2-input-declaration-swap-boundary-v1"
SEED = _A175.SEED
WINDOW_BITS = _A175.WINDOW_BITS
Z3_RLIMIT = _A175.Z3_RLIMIT
EXTERNAL_SAFETY_TIMEOUT_SECONDS = _A175.EXTERNAL_SAFETY_TIMEOUT_SECONDS
AFFINE_SHIFT = _A175.AFFINE_SHIFT
A175_FILENAME = _A175.RESULT_FILENAME
A175_SHA256 = "1c432037567c74397b95d0d75c84a0eac406d63398e57c7214bdf7c730cb2894"
A175_RESULT_SHA256 = "d6f1f34041830e50b86f0481d9afed748c80880fba49f04d3aabcfbfbc52df07"
A174_FILENAME = _A174.RESULT_FILENAME
A174_SHA256 = _A175.A174_SHA256
A174_TRANSFER_SHA256 = _A175.A174_TRANSFER_SHA256
PROTOCOL_FILENAME = "shake_symbolic_r2_input_declaration_swap_boundary_v1.json"
PROTOCOL_SHA256 = "3b8012e534608fdc3862100f219b19db035db082468f351dacd6998ce1354683"
PROTOCOL_SCHEMA = "shake-symbolic-r2-input-declaration-swap-boundary-protocol-v1"
RESULT_FILENAME = "shake_symbolic_r2_input_declaration_swap_boundary_v1.json"
CAUSAL_FILENAME = "shake_symbolic_r2_input_declaration_swap_boundary_v1.causal"

_DECLARATION = re.compile(
    rb"^\(declare-fun ([A-Za-z_][A-Za-z0-9_]*) \(\) Bool\)$",
    re.MULTILINE,
)
_FORWARD_PAIR = b"(declare-fun x11 () Bool)\n(declare-fun x12 () Bool)\n"
_REVERSE_PAIR = b"(declare-fun x12 () Bool)\n(declare-fun x11 () Bool)\n"


def _sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _canonical_sha256(value: Any) -> str:
    return _A175._canonical_sha256(value)


def _load_anchor_gates(
    results_dir: Path,
) -> tuple[dict[str, Any], dict[str, Any]]:
    a175 = _A156._load_json_gate(
        results_dir / A175_FILENAME,
        A175_SHA256,
        _A175.SCHEMA,
    )
    a174 = _A156._load_json_gate(
        results_dir / A174_FILENAME,
        A174_SHA256,
        _A174.SCHEMA,
    )
    alpha = a175.get("alpha_boundary_result", {})
    transfer = a174.get("partner_transfer_result", {})
    if (
        a175.get("alpha_boundary_result_sha256") != A175_RESULT_SHA256
        or alpha.get("classification") != "central_boundary_alpha_robust"
        or alpha.get("alpha_renamed_directional_delta") != 2_594
        or alpha.get("prospective_prediction_confirmed") is not True
        or transfer.get("directional_delta_alias_position_11_minus_12") != 2_196
        or a174.get("partner_transfer_result_sha256") != A174_TRANSFER_SHA256
        or Z3_RLIMIT != 500_000_000
        or EXTERNAL_SAFETY_TIMEOUT_SECONDS != 300
    ):
        raise RuntimeError("A176 A174/A175 anchor gate failed")
    return a175, a174


def _load_protocol_gate() -> dict[str, Any]:
    path = Path(__file__).parents[1] / "configs" / PROTOCOL_FILENAME
    protocol = _A156._load_json_gate(path, PROTOCOL_SHA256, PROTOCOL_SCHEMA)
    if (
        protocol.get("attempt_id") != ATTEMPT_ID
        or protocol.get("protocol_state") != "frozen_before_any_A176_solver_execution"
        or protocol.get("anchors", {}).get("A175", {}).get("sha256") != A175_SHA256
        or protocol.get("declaration_intervention", {}).get("semantic_change") is not False
        or protocol.get("declaration_intervention", {}).get("new_formula_count") != 4
        or protocol.get("declaration_intervention", {}).get("swapped_input_names") != ["x11", "x12"]
        or protocol.get("prospective_prediction", {}).get("direction")
        != "declaration_swapped_directional_delta_remains_strictly_positive"
        or protocol.get("information_boundary", {}).get(
            "A176_solver_outcomes_used_before_formula_freeze"
        )
        is not False
    ):
        raise RuntimeError("A176 frozen protocol identity gate failed")
    return protocol


def _validate_protocol_plan(protocol: dict[str, Any], analysis: dict[str, Any]) -> None:
    rows = [
        [
            row["name"],
            row["formula_bytes"],
            row["formula_sha256"],
            row["encoding"]["declaration_swap_sha256"],
        ]
        for row in analysis["formula_plan"]
    ]
    if (
        protocol["declaration_plan"]["sha256"] != analysis["declaration_plan_sha256"]
        or protocol["formula_plan"]["sha256"] != analysis["formula_plan_sha256"]
        or protocol["formula_plan"]["rows"] != rows
    ):
        raise RuntimeError("A176 regenerated declaration/formulas differ from protocol")


def _swap_x11_x12_declaration_lines(raw: bytes) -> bytes:
    forward_count = raw.count(_FORWARD_PAIR)
    reverse_count = raw.count(_REVERSE_PAIR)
    if (forward_count, reverse_count) == (1, 0):
        return raw.replace(_FORWARD_PAIR, _REVERSE_PAIR, 1)
    if (forward_count, reverse_count) == (0, 1):
        return raw.replace(_REVERSE_PAIR, _FORWARD_PAIR, 1)
    raise RuntimeError("A176 x11/x12 declaration pair is not unique")


def _declaration_swap_formula(raw: bytes) -> tuple[bytes, dict[str, Any]]:
    declarations = _DECLARATION.findall(raw)
    swapped = _swap_x11_x12_declaration_lines(raw)
    swapped_declarations = _DECLARATION.findall(swapped)
    differences = [
        index
        for index, (left, right) in enumerate(zip(declarations, swapped_declarations, strict=True))
        if left != right
    ]
    restored = _swap_x11_x12_declaration_lines(swapped)
    changed_lines = [
        [declarations[index].decode(), swapped_declarations[index].decode()]
        for index in differences
    ]
    if (
        len(declarations) not in (121_575, 121_576)
        or differences != [11, 12]
        or changed_lines != [["x11", "x12"], ["x12", "x11"]]
        or sorted(declarations) != sorted(swapped_declarations)
        or restored != raw
        or len(swapped) != len(raw)
    ):
        raise RuntimeError("A176 declaration-only swap gate failed")
    plan = {
        "declaration_count": len(declarations),
        "changed_declaration_indices_zero_based": differences,
        "changed_lines": changed_lines,
        "declaration_multiset_preserved": True,
        "formula_bytes_preserved": True,
        "all_assertion_bytes_preserved": True,
        "graph_topology_preserved": True,
        "symbol_names_preserved": True,
        "solver_input_get_value_order_preserved": True,
        "second_swap_recovers_original_bytes": True,
        "original_formula_sha256": _sha256(raw),
        "swapped_formula_sha256": _sha256(swapped),
        "declaration_swap_sha256": _canonical_sha256(changed_lines),
    }
    return swapped, plan


def _formula_frontier(
    base: dict[str, Any],
) -> tuple[list[dict[str, Any]], dict[str, bytes], list[dict[str, Any]]]:
    rows = []
    formulas = {}
    declaration_rows = []
    for source_row in base["rows"]:
        original = base["formulas"][source_row["name"]]
        swapped, swap = _declaration_swap_formula(original)
        name = f"declaration_swap_x11_x12__{source_row['name']}"
        encoding = dict(source_row["encoding"])
        encoding.update(
            {
                "name": name,
                "input_declaration_intervention": "swap_only_x11_and_x12_declaration_lines",
                "declaration_swap_sha256": swap["declaration_swap_sha256"],
                "declaration_swap_graph_isomorphic_to_A174": True,
                "declaration_swap_inverse_recovers_A174_formula_bytes": True,
                "A174_formula_name": source_row["name"],
                "A174_formula_sha256": source_row["formula_sha256"],
                "instrumented_assignment_input_used": False,
                "solver_observation_input_used_for_formula_construction": False,
                "target_rate_input_used_for_declaration_swap": False,
            }
        )
        formulas[name] = swapped
        rows.append(
            {
                "name": name,
                "execution_order": len(rows),
                "formula_bytes": len(swapped),
                "formula_sha256": _sha256(swapped),
                "encoding": encoding,
                "solver_input_names": list(source_row["solver_input_names"]),
                "solver_outcome_used_for_formula_construction": False,
            }
        )
        declaration_rows.append({"name": name, **swap})
    return rows, formulas, declaration_rows


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
        "Boolean_SMT_shared_R2_x11_x12_declaration_swap_fixed_rlimit"
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
        raise ValueError("A176 solver work directory must be empty")
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
        raise RuntimeError("A176 solver formula cleanup failed")
    return results


def _execution_summary(executions: Sequence[dict[str, Any]]) -> list[dict[str, Any]]:
    return [
        {
            "name": row["name"],
            "A174_formula_name": row["encoding"]["A174_formula_name"],
            "adjacent_orientation": row["encoding"]["adjacent_orientation"],
            "alias_compiler_arm": row["encoding"]["alias_compiler_arm"],
            "alias_input_solver_position": row["encoding"]["alias_input_solver_position"],
            "status": row["solver"]["status"],
            "return_code": row["solver"]["return_code"],
            "termination": row["solver"]["termination"],
            "canonical_observation_sha256": row["solver"]["canonical_observation_sha256"],
            "stats": row["solver"]["stats"],
            "independently_confirmed_model": row["independently_confirmed_model"],
        }
        for row in executions
    ]


def _declaration_boundary_result(
    a174: dict[str, Any],
    executions: Sequence[dict[str, Any]],
) -> dict[str, Any]:
    anchor_by_name = {row["name"]: row for row in a174["execution_summary"]}
    observed = {
        (row["encoding"]["adjacent_orientation"], row["encoding"]["alias_compiler_arm"]): row
        for row in executions
    }
    decision_rows = []
    exact_observations = []
    for row in executions:
        anchor = anchor_by_name[row["encoding"]["A174_formula_name"]]
        exact = (
            row["solver"]["canonical_observation_sha256"] == anchor["canonical_observation_sha256"]
        )
        exact_observations.append(exact)
        decision_rows.append(
            {
                "name": row["name"],
                "A174_formula_name": anchor["name"],
                "A174_decisions": int(anchor["stats"]["decisions"]),
                "declaration_swapped_decisions": int(row["solver"]["stats"]["decisions"]),
                "decision_delta_swap_minus_A174": int(row["solver"]["stats"]["decisions"])
                - int(anchor["stats"]["decisions"]),
                "canonical_observation_exactly_equal": exact,
            }
        )
    effects = {}
    effect_rows = []
    for orientation in _A174.ORIENTATIONS:
        inline = int(observed[(orientation, "inline")]["solver"]["stats"]["decisions"])
        materialized = int(observed[(orientation, "materialized")]["solver"]["stats"]["decisions"])
        effect = materialized - inline
        effects[orientation] = effect
        effect_rows.append(
            {
                "adjacent_orientation": orientation,
                "inline_decisions": inline,
                "materialized_decisions": materialized,
                "materialization_effect": effect,
            }
        )
    delta = effects["12_before_22"] - effects["22_before_12"]
    exact_all = all(exact_observations)
    classification = (
        "exact_input_declaration_order_invariance"
        if exact_all
        else "central_boundary_declaration_order_robust"
        if delta > 0
        else "declaration_order_exact_boundary"
        if delta == 0
        else "input_declaration_order_conditioned"
    )
    return {
        "decision_rows": decision_rows,
        "effect_rows": effect_rows,
        "A174_directional_delta": a174["partner_transfer_result"][
            "directional_delta_alias_position_11_minus_12"
        ],
        "declaration_swapped_directional_delta": delta,
        "directional_delta_change": delta
        - a174["partner_transfer_result"]["directional_delta_alias_position_11_minus_12"],
        "all_four_canonical_observations_exactly_equal": exact_all,
        "prospective_prediction": (
            "declaration_swapped_directional_delta_remains_strictly_positive"
        ),
        "prospective_prediction_confirmed": delta > 0,
        "classification": classification,
    }


def _build_causal(path: Path, payload: dict[str, Any]) -> dict[str, Any]:
    builder = CryptoCausalBuilder(
        experiment="shake_symbolic_r2_input_declaration_swap_boundary",
        parameters={
            "attempt_id": ATTEMPT_ID,
            "variant": "shake128",
            "window_bits": WINDOW_BITS,
            "affine_shift": AFFINE_SHIFT,
            "new_formula_count": 4,
            "swapped_declarations": ["x11", "x12"],
            "rlimit_per_formula": Z3_RLIMIT,
        },
    )
    ids = [
        "shake128-a175-alpha-robust-center-boundary",
        "shake128-a176-x11-x12-declaration-swap",
        "shake128-a176-four-declaration-isomorphic-formulas",
        "shake128-a176-fixed-resource-declaration-execution",
        "shake128-a176-declaration-boundary-result",
    ]
    builder.add_triplet(
        edge_id=ids[0],
        trigger="A175:positive_boundary_survives_bijective_symbol_renaming",
        mechanism="separate_relative_formula_graph_from_input_declaration_order",
        outcome="A176:input_declaration_order_question",
        confidence=1.0,
        evidence_kind="alpha_robust_boundary_anchor",
        source=A175_SHA256,
        attrs={"A175_gate": payload["anchor_gates"]["A175"]},
    )
    builder.add_triplet(
        edge_id=ids[1],
        trigger="A176:input_declaration_order_question",
        mechanism="swap_only_the_x11_and_x12_declaration_lines",
        outcome="A176:exact_declaration_isomorphic_graphs",
        confidence=1.0,
        evidence_kind="byte_reversible_declaration_order_intervention",
        source=payload["declaration_plan_sha256"],
        provenance=[ids[0]],
        attrs={"declaration_plan": payload["declaration_plan"]},
    )
    builder.add_triplet(
        edge_id=ids[2],
        trigger="A176:exact_declaration_isomorphic_graphs",
        mechanism="freeze_all_four_swapped_formula_bytes_before_solver_execution",
        outcome="A176:four_hash_bound_declaration_formulas",
        confidence=1.0,
        evidence_kind="prospective_formula_frontier",
        source=payload["formula_plan_sha256"],
        provenance=[ids[1]],
        attrs={"formula_plan": payload["formula_plan"]},
    )
    builder.add_triplet(
        edge_id=ids[3],
        trigger="A176:four_hash_bound_declaration_formulas",
        mechanism="execute_under_unchanged_fixed_resource_protocol",
        outcome="A176:four_declaration_swap_observations",
        confidence=1.0,
        evidence_kind="fixed_resource_execution_and_complete_rate_gate",
        source="Z3_4.15.4_plus_independent_NumPy_lane_core",
        provenance=[ids[2]],
        attrs={"execution_summary": payload["execution_summary"]},
    )
    builder.add_triplet(
        edge_id=ids[4],
        trigger="A176:four_declaration_swap_observations",
        mechanism="compare_swapped_materialization_delta_with_A174_direction",
        outcome="A176:prospective_declaration_boundary_test",
        confidence=1.0,
        evidence_kind="paired_declaration_order_intervention",
        source=payload["declaration_boundary_result_sha256"],
        provenance=[ids[3]],
        attrs={"declaration_boundary_result": payload["declaration_boundary_result"]},
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
        raise RuntimeError("A176 Causal provenance chain failed validation")
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
    a175, a174 = _load_anchor_gates(results_dir)
    base = _A174.analyze(results_dir)
    rows, formulas, declaration_rows = _formula_frontier(base)
    plan = _formula_plan(rows)
    return {
        "anchors": (a175, a174),
        "variant": base["variant"],
        "problem": base["problem"],
        "rows": rows,
        "formulas": formulas,
        "declaration_plan": declaration_rows,
        "declaration_plan_sha256": _canonical_sha256(declaration_rows),
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
    a175, a174 = analysis["anchors"]
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
            "input_coordinate_assignment": row["input_coordinate_assignment"],
            "independent_complete_rate_check": row["independent_complete_rate_check"],
        }
        for row in executions
        if row["independently_confirmed_model"]
    ]
    summary = _execution_summary(executions)
    declaration_result = _declaration_boundary_result(a174, executions)
    payload: dict[str, Any] = {
        "schema": SCHEMA,
        "attempt_id": ATTEMPT_ID,
        "evidence_stage": "INPUT_DECLARATION_SWAP_BOUNDARY_EXECUTED",
        "result": (
            "A176 prospectively tests whether the central alias-position direction "
            "survives swapping only the x11 and x12 declaration lines."
        ),
        "scope": (
            "The retained A152 SHAKE128 width-24 relation, affine gauge 0x4e1e28, "
            "the four A174 partner-22 graphs, shared R2 prefix, 22 unchanged suffix "
            "rounds and all 1,344 rate bits."
        ),
        "parameters": {
            "variant": "SHAKE128",
            "seed": SEED,
            "window_bits": WINDOW_BITS,
            "affine_shift": AFFINE_SHIFT,
            "new_formula_count": 4,
            "swapped_declarations": ["x11", "x12"],
            "rlimit_per_formula": Z3_RLIMIT,
            "execution_mode": "sequential_one_thread_per_formula",
            "solver": solver_version,
            "solver_wallclock_limit_used": False,
            "external_safety_timeout_seconds": EXTERNAL_SAFETY_TIMEOUT_SECONDS,
            "wallclock_excluded_from_canonical_result": True,
        },
        "anchor_gates": {
            "A176_protocol": {
                "artifact_sha256": PROTOCOL_SHA256,
                "protocol_state": analysis["protocol"]["protocol_state"],
                "prospective_prediction": analysis["protocol"]["prospective_prediction"],
                "information_boundary": analysis["protocol"]["information_boundary"],
            },
            "A175": {
                "artifact_sha256": A175_SHA256,
                "alpha_boundary_result_sha256": A175_RESULT_SHA256,
                "directional_delta": a175["alpha_boundary_result"][
                    "alpha_renamed_directional_delta"
                ],
            },
            "A174": {
                "artifact_sha256": A174_SHA256,
                "partner_transfer_result_sha256": A174_TRANSFER_SHA256,
                "directional_delta": a174["partner_transfer_result"][
                    "directional_delta_alias_position_11_minus_12"
                ],
            },
        },
        "declaration_plan": analysis["declaration_plan"],
        "declaration_plan_sha256": analysis["declaration_plan_sha256"],
        "formula_plan": analysis["formula_plan"],
        "formula_plan_sha256": analysis["formula_plan_sha256"],
        "execution": executions,
        "execution_summary": summary,
        "status_counts": status_counts,
        "confirmed_models": confirmed_models,
        "declaration_boundary_result": declaration_result,
        "declaration_boundary_result_sha256": _canonical_sha256(declaration_result),
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
        raise RuntimeError("A176 final artifact reopen gate failed")
    return {
        "json_sha256": _sha256(raw),
        "causal_sha256": reader.file_sha256,
        "causal_graph_sha256": reader.graph_sha256,
        "status_counts": status_counts,
        "confirmed_model_count": len(confirmed_models),
        "classification": declaration_result["classification"],
        "prospective_prediction_confirmed": declaration_result["prospective_prediction_confirmed"],
        "directional_delta": declaration_result["declaration_swapped_directional_delta"],
        "all_four_observations_exact": declaration_result[
            "all_four_canonical_observations_exactly_equal"
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
        default=Path(__file__).parents[2] / "build" / "shake-r2-a176",
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
                    "declaration_plan_sha256": analysis["declaration_plan_sha256"],
                    "declaration_plan": analysis["declaration_plan"],
                    "formula_plan_sha256": analysis["formula_plan_sha256"],
                    "formulas": [
                        {
                            "name": row["name"],
                            "A174_name": row["encoding"]["A174_formula_name"],
                            "orientation": row["encoding"]["adjacent_orientation"],
                            "arm": row["encoding"]["alias_compiler_arm"],
                            "bytes": row["formula_bytes"],
                            "sha256": row["formula_sha256"],
                            "swap_sha256": row["encoding"]["declaration_swap_sha256"],
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

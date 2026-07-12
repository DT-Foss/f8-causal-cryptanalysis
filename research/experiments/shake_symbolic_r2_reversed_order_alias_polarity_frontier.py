#!/usr/bin/env python3
"""Test whether exact order reversal controls the connected-alias polarity."""

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


_A169 = _import_sibling(
    "shake_symbolic_r2_alias_fanout_mobius_frontier.py",
    "shake_symbolic_r2_reversed_order_a169_base",
)
_A168 = _A169._A168
_A166 = _A169._A166
_A164 = _A169._A164
_A163 = _A169._A163
_A158 = _A169._A158
_A156 = _A169._A156

ATTEMPT_ID = "A170"
SCHEMA = "shake-symbolic-r2-reversed-order-alias-polarity-frontier-v1"
SEED = _A169.SEED
WINDOW_BITS = _A169.WINDOW_BITS
Z3_RLIMIT = _A169.Z3_RLIMIT
EXTERNAL_SAFETY_TIMEOUT_SECONDS = _A169.EXTERNAL_SAFETY_TIMEOUT_SECONDS
AFFINE_SHIFT = _A169.AFFINE_SHIFT
A169_FILENAME = _A169.RESULT_FILENAME
A169_SHA256 = "b19c1b85bfad77c5e7aa909ba11a02821fce21f6603daa3174bfe5899a0c1334"
A169_MOBIUS_SHA256 = "af6b94835b169aeb9ef0e32b721623c0536ccb0e98cb1c156508f419907ec2ea"
A168_FILENAME = _A168.RESULT_FILENAME
A168_SHA256 = _A169.A168_SHA256
A166_FILENAME = _A166.RESULT_FILENAME
A166_SHA256 = _A169.A166_SHA256
PROTOCOL_FILENAME = "shake_symbolic_r2_reversed_order_alias_polarity_frontier_v1.json"
PROTOCOL_SHA256 = "683d8363bc0865e48df13a880d9e9344d4acdd2faaf15d1f9eaa03f90ded3012"
PROTOCOL_SCHEMA = "shake-symbolic-r2-reversed-order-alias-polarity-frontier-protocol-v1"
RESULT_FILENAME = "shake_symbolic_r2_reversed_order_alias_polarity_frontier_v1.json"
CAUSAL_FILENAME = "shake_symbolic_r2_reversed_order_alias_polarity_frontier_v1.causal"
COMPILERS = ("inline", "materialized")


def _sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _canonical_sha256(value: Any) -> str:
    return _A169._canonical_sha256(value)


def _load_anchor_gates(
    results_dir: Path,
) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any], dict[str, Any]]:
    a169 = _A156._load_json_gate(results_dir / A169_FILENAME, A169_SHA256, _A169.SCHEMA)
    a168 = _A156._load_json_gate(results_dir / A168_FILENAME, A168_SHA256, _A168.SCHEMA)
    a166 = _A156._load_json_gate(results_dir / A166_FILENAME, A166_SHA256, _A166.SCHEMA)
    a164, a162 = _A166._load_anchor_gates(results_dir)
    mobius = a169.get("mobius_decomposition", {})
    if (
        a169.get("mobius_decomposition_sha256") != A169_MOBIUS_SHA256
        or mobius.get("component_L1")
        != {
            "column_consumer_main": 4_247,
            "fanout_interaction": 3_289,
            "theta_consumer_main": 4_222,
        }
        or [row["total_materialization_effect"] for row in mobius.get("rows", [])]
        != [-2_008, 977, 1_623, 1_182]
        or a169.get("status_counts") != {"error": 0, "sat": 0, "unknown": 8, "unsat": 0}
        or Z3_RLIMIT != 500_000_000
        or EXTERNAL_SAFETY_TIMEOUT_SECONDS != 300
    ):
        raise RuntimeError("A170 A166/A168/A169 anchor gate failed")
    return a169, a168, a166, a162


def _load_protocol_gate() -> dict[str, Any]:
    path = Path(__file__).parents[1] / "configs" / PROTOCOL_FILENAME
    protocol = _A156._load_json_gate(path, PROTOCOL_SHA256, PROTOCOL_SCHEMA)
    if (
        protocol.get("attempt_id") != ATTEMPT_ID
        or protocol.get("protocol_state") != "frozen_before_any_A170_solver_execution"
        or protocol.get("anchors", {}).get("A169", {}).get("sha256") != A169_SHA256
        or protocol.get("anchors", {}).get("A168", {}).get("sha256") != A168_SHA256
        or protocol.get("anchors", {}).get("A166", {}).get("sha256") != A166_SHA256
        or protocol.get("reversal_design", {}).get("semantic_change") is not False
        or protocol.get("reversal_design", {}).get("new_formula_count") != 8
        or protocol.get("information_boundary", {}).get(
            "A170_solver_outcomes_used_before_formula_freeze"
        )
        is not False
    ):
        raise RuntimeError("A170 frozen protocol identity gate failed")
    return protocol


def _validate_protocol_plan(protocol: dict[str, Any], analysis: dict[str, Any]) -> None:
    rows = [
        [row["name"], row["formula_bytes"], row["formula_sha256"]]
        for row in analysis["formula_plan"]
    ]
    if (
        protocol["reversal_plan"]["sha256"] != analysis["reversal_plan_sha256"]
        or protocol["formula_plan"]["sha256"] != analysis["formula_plan_sha256"]
        or protocol["formula_plan"]["rows"] != rows
    ):
        raise RuntimeError("A170 regenerated reversal/formulas differ from protocol")


def _base_orders(baseline: dict[str, Any]) -> dict[str, list[int]]:
    rows = {}
    for row in baseline["rows"]:
        order_name = row["encoding"]["order_name"]
        rows.setdefault(
            order_name,
            row["encoding"]["variable_to_shifted_input_coordinate"],
        )
    if set(rows) != set(_A158.ORDER_NAMES):
        raise RuntimeError("A170 base order set differs")
    return rows


def _reversal_plan(
    base_orders: dict[str, list[int]],
    base_effects: dict[str, int],
) -> list[dict[str, Any]]:
    base_vectors = list(base_orders.values())
    rows = []
    for order_name in _A158.ORDER_NAMES:
        original = list(base_orders[order_name])
        reversed_order = list(reversed(original))
        if (
            list(reversed(reversed_order)) != original
            or reversed_order == original
            or reversed_order in base_vectors
            or sorted(reversed_order) != list(range(WINDOW_BITS))
        ):
            raise RuntimeError("A170 exact reversal uniqueness/involution gate failed")
        rows.append(
            {
                "base_order_name": order_name,
                "base_order": original,
                "reversed_order": reversed_order,
                "transform": "exact_vector_reversal",
                "involution_verified": True,
                "reversed_order_absent_from_four_base_orders": True,
                "base_materialization_effect": base_effects[order_name],
                "base_alias_input_solver_position": original.index(12),
                "reversed_alias_input_solver_position": reversed_order.index(12),
            }
        )
    return rows


def _formula_frontier(
    problem: dict[str, Any],
    variant: Any,
    reversal_plan: Sequence[dict[str, Any]],
    semantic_gate: dict[str, Any],
) -> tuple[list[dict[str, Any]], dict[str, bytes]]:
    rows = []
    formulas = {}
    for design in reversal_plan:
        base_order = design["base_order_name"]
        reversed_order = design["reversed_order"]
        reversed_name = f"reversed_{base_order}"
        for compiler in COMPILERS:
            name = f"{reversed_name}__{compiler}_negative_alias"
            if compiler == "inline":
                writer, inputs, encoding = _A166._encode_problem(
                    problem,
                    variant,
                    name=name,
                    order_name=reversed_name,
                    variable_to_shifted_input=reversed_order,
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
                    order_name=reversed_name,
                    variable_to_shifted_input=reversed_order,
                    expected_shifted_polynomial_sha256=semantic_gate[
                        "shifted_R2_polynomial_state_sha256"
                    ],
                    expected_coefficient_incidence=semantic_gate["coefficient_incidence"],
                )
            encoding.update(
                {
                    "base_order_name": base_order,
                    "reversed_order_name": reversed_name,
                    "order_transform": "exact_vector_reversal",
                    "order_reversal_involution_verified": True,
                    "alias_compiler_arm": compiler,
                    "base_materialization_effect": design["base_materialization_effect"],
                    "instrumented_assignment_input_used": False,
                    "solver_observation_input_used_for_formula_construction": False,
                    "target_rate_input_used_for_reversal_selection": False,
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
        "Boolean_SMT_shared_R2_reversed_order_alias_polarity_fixed_rlimit"
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
        raise ValueError("A170 solver work directory must be empty")
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
        raise RuntimeError("A170 solver formula cleanup failed")
    return results


def _execution_summary(executions: Sequence[dict[str, Any]]) -> list[dict[str, Any]]:
    return [
        {
            "name": row["name"],
            "base_order_name": row["encoding"]["base_order_name"],
            "reversed_order_name": row["encoding"]["reversed_order_name"],
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


def _sign(value: int) -> int:
    return (value > 0) - (value < 0)


def _polarity_frontier(
    a169: dict[str, Any],
    executions: Sequence[dict[str, Any]],
) -> dict[str, Any]:
    base = {
        row["order_name"]: row["total_materialization_effect"]
        for row in a169["mobius_decomposition"]["rows"]
    }
    observed = {
        (row["encoding"]["base_order_name"], row["encoding"]["alias_compiler_arm"]): row
        for row in executions
    }
    rows = []
    for order_name in _A158.ORDER_NAMES:
        inline = int(observed[(order_name, "inline")]["solver"]["stats"]["decisions"])
        materialized = int(observed[(order_name, "materialized")]["solver"]["stats"]["decisions"])
        base_effect = int(base[order_name])
        reversed_effect = materialized - inline
        if reversed_effect == 0:
            relation = "zero"
        elif _sign(reversed_effect) == -_sign(base_effect):
            relation = "flipped"
        elif _sign(reversed_effect) == _sign(base_effect):
            relation = "preserved"
        else:
            raise RuntimeError("A170 polarity relation is undefined")
        rows.append(
            {
                "base_order_name": order_name,
                "base_materialization_effect": base_effect,
                "reversed_inline_decisions": inline,
                "reversed_materialized_decisions": materialized,
                "reversed_materialization_effect": reversed_effect,
                "polarity_relation": relation,
                "base_effect_sign": _sign(base_effect),
                "reversed_effect_sign": _sign(reversed_effect),
                "absolute_effect_change": abs(reversed_effect) - abs(base_effect),
            }
        )
    counts = {
        relation: sum(row["polarity_relation"] == relation for row in rows)
        for relation in ("flipped", "preserved", "zero")
    }
    return {
        "rows": rows,
        "polarity_counts": counts,
        "all_four_polarities_flipped": counts["flipped"] == 4,
        "all_four_polarities_preserved": counts["preserved"] == 4,
        "reversal_rule": (
            "universal_flip"
            if counts["flipped"] == 4
            else "universal_preservation"
            if counts["preserved"] == 4
            else "mixed_reversal_response"
        ),
    }


def _posthoc_summary(
    problem: dict[str, Any], variant: Any, executions: Sequence[dict[str, Any]]
) -> dict[str, Any]:
    actual = _A168._WINDOW._extract_window(problem["base_state"], variant, problem["positions"])
    return {
        "instrumented_input_assignment": actual,
        "extracted_only_after_every_A170_execution": True,
        "used_for_reversal_formula_order_or_execution": False,
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
        experiment="shake_symbolic_r2_reversed_order_alias_polarity_frontier",
        parameters={
            "attempt_id": ATTEMPT_ID,
            "variant": "shake128",
            "seed": SEED,
            "window_bits": WINDOW_BITS,
            "affine_shift": AFFINE_SHIFT,
            "new_formula_count": 8,
            "rlimit_per_formula": Z3_RLIMIT,
        },
    )
    ids = [
        "shake128-a169-order-dependent-two-path-polarity",
        "shake128-a170-four-exact-order-reversals",
        "shake128-a170-eight-inline-materialized-formulas",
        "shake128-a170-fixed-resource-execution",
        "shake128-a170-reversal-polarity-frontier",
    ]
    builder.add_triplet(
        edge_id=ids[0],
        trigger="A169:both_consumer_main_effects_share_each_orders_sign",
        mechanism="identify_order_orientation_as_the_next_common_polarity_candidate",
        outcome="A170:order_reversal_polarity_question",
        confidence=1.0,
        evidence_kind="exact_four_order_fanout_mobius_decomposition",
        source=A169_SHA256,
        attrs={"A169_gate": payload["anchor_gates"]["A169"]},
    )
    builder.add_triplet(
        edge_id=ids[1],
        trigger="A170:order_reversal_polarity_question",
        mechanism="reverse_each_complete_24_coordinate_order_vector_as_an_involution",
        outcome="A170:four_new_exact_reversed_orders",
        confidence=1.0,
        evidence_kind="prospective_order_transform",
        source=payload["reversal_plan_sha256"],
        provenance=[ids[0]],
        attrs={"reversal_plan": payload["reversal_plan"]},
    )
    builder.add_triplet(
        edge_id=ids[2],
        trigger="A170:four_new_exact_reversed_orders",
        mechanism="compile_inline_and_normalized_materialized_alias_arms_for_each_reversal",
        outcome="A170:eight_reversed_order_fullround_formulas",
        confidence=1.0,
        evidence_kind="hash_bound_semantics_preserving_formula_frontier",
        source=payload["formula_plan_sha256"],
        provenance=[ids[1]],
        attrs={"formula_plan": payload["formula_plan"]},
    )
    builder.add_triplet(
        edge_id=ids[3],
        trigger="A170:eight_reversed_order_fullround_formulas",
        mechanism="execute_all_eight_formulas_under_the_unchanged_fixed_resource_protocol",
        outcome="A170:eight_reversed_order_solver_observations",
        confidence=1.0,
        evidence_kind="fixed_resource_execution_and_complete_rate_gate",
        source="Z3_4.15.4_plus_independent_NumPy_lane_core",
        provenance=[ids[2]],
        attrs={"execution_summary": payload["execution_summary"]},
    )
    builder.add_triplet(
        edge_id=ids[4],
        trigger="A170:eight_reversed_order_solver_observations",
        mechanism="compare_each_reversed_materialization_effect_sign_with_its_A169_base_order",
        outcome="A170:exact_order_reversal_alias_polarity_frontier",
        confidence=1.0,
        evidence_kind="paired_prospective_order_reversal_intervention",
        source=payload["polarity_frontier_sha256"],
        provenance=[ids[3]],
        attrs={"polarity_frontier": payload["polarity_frontier"]},
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
        raise RuntimeError("A170 Causal provenance chain failed validation")
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
    a169, a168, a166, a162 = _load_anchor_gates(results_dir)
    baseline = _A166.analyze(results_dir)
    orders = _base_orders(baseline)
    base_effects = {
        row["order_name"]: row["total_materialization_effect"]
        for row in a169["mobius_decomposition"]["rows"]
    }
    reversal = _reversal_plan(orders, base_effects)
    semantic_gate = next(row for row in a162["semantic_gates"] if row["shift"] == AFFINE_SHIFT)
    rows, formulas = _formula_frontier(
        baseline["problem"],
        baseline["variant"],
        reversal,
        semantic_gate,
    )
    plan = _formula_plan(rows)
    return {
        "anchors": (a169, a168, a166),
        "variant": baseline["variant"],
        "problem": baseline["problem"],
        "reversal_plan": reversal,
        "reversal_plan_sha256": _canonical_sha256(reversal),
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
    a169, a168, a166 = analysis["anchors"]
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
    polarity = _polarity_frontier(a169, executions)
    posthoc = _posthoc_summary(analysis["problem"], analysis["variant"], executions)
    payload: dict[str, Any] = {
        "schema": SCHEMA,
        "attempt_id": ATTEMPT_ID,
        "evidence_stage": "REVERSED_ORDER_ALIAS_POLARITY_FRONTIER_EXECUTED",
        "result": (
            "A170 reverses each complete frozen order and executes paired inline "
            "and materialized negative-alias arms to test order-orientation polarity."
        ),
        "scope": (
            "The retained A152 SHAKE128 width-24 relation, affine gauge 0x4e1e28, "
            "four exact reversed A158-derived orders, shared R2 prefix, 22 "
            "unchanged suffix rounds and all 1,344 rate bits."
        ),
        "parameters": {
            "variant": "SHAKE128",
            "seed": SEED,
            "window_bits": WINDOW_BITS,
            "affine_shift": AFFINE_SHIFT,
            "new_formula_count": 8,
            "rlimit_per_formula": Z3_RLIMIT,
            "execution_mode": "sequential_one_thread_per_formula",
            "solver": solver_version,
            "solver_wallclock_limit_used": False,
            "external_safety_timeout_seconds": EXTERNAL_SAFETY_TIMEOUT_SECONDS,
            "wallclock_excluded_from_canonical_result": True,
        },
        "anchor_gates": {
            "A170_protocol": {
                "artifact_sha256": PROTOCOL_SHA256,
                "protocol_state": analysis["protocol"]["protocol_state"],
                "information_boundary": analysis["protocol"]["information_boundary"],
            },
            "A169": {
                "artifact_sha256": A169_SHA256,
                "mobius_decomposition_sha256": A169_MOBIUS_SHA256,
                "component_L1": a169["mobius_decomposition"]["component_L1"],
            },
            "A168": {
                "artifact_sha256": A168_SHA256,
                "effect_decomposition_sha256": a168["effect_decomposition_sha256"],
            },
            "A166": {
                "artifact_sha256": A166_SHA256,
                "comparison_sha256": a166["comparison_sha256"],
            },
        },
        "reversal_plan": analysis["reversal_plan"],
        "reversal_plan_sha256": analysis["reversal_plan_sha256"],
        "formula_plan": analysis["formula_plan"],
        "formula_plan_sha256": analysis["formula_plan_sha256"],
        "execution": executions,
        "execution_summary": summary,
        "status_counts": status_counts,
        "confirmed_models": confirmed_models,
        "polarity_frontier": polarity,
        "polarity_frontier_sha256": _canonical_sha256(polarity),
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
        raise RuntimeError("A170 final artifact reopen gate failed")
    return {
        "json_sha256": _sha256(raw),
        "causal_sha256": reader.file_sha256,
        "causal_graph_sha256": reader.graph_sha256,
        "status_counts": status_counts,
        "confirmed_model_count": len(confirmed_models),
        "reversal_rule": polarity["reversal_rule"],
        "polarity_counts": polarity["polarity_counts"],
        "reversed_effects": [row["reversed_materialization_effect"] for row in polarity["rows"]],
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
        default=Path(__file__).parents[2] / "build" / "shake-r2-a170",
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
                    "reversal_plan_sha256": analysis["reversal_plan_sha256"],
                    "formula_plan_sha256": analysis["formula_plan_sha256"],
                    "reversals": analysis["reversal_plan"],
                    "formulas": [
                        {
                            "name": row["name"],
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

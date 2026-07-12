#!/usr/bin/env python3
"""Decompose the connected negative-alias effect across its two suffix consumers."""

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


_A168 = _import_sibling(
    "shake_symbolic_r2_normalized_materialized_alias_frontier.py",
    "shake_symbolic_r2_alias_fanout_a168_base",
)
_A167 = _A168._A167
_A166 = _A168._A166
_A164 = _A168._A164
_A163 = _A168._A163
_A158 = _A168._A158
_A156 = _A168._A156

ATTEMPT_ID = "A169"
SCHEMA = "shake-symbolic-r2-alias-fanout-mobius-frontier-v1"
SEED = _A168.SEED
WINDOW_BITS = _A168.WINDOW_BITS
Z3_RLIMIT = _A168.Z3_RLIMIT
EXTERNAL_SAFETY_TIMEOUT_SECONDS = _A168.EXTERNAL_SAFETY_TIMEOUT_SECONDS
AFFINE_SHIFT = _A168.AFFINE_SHIFT
A168_FILENAME = _A168.RESULT_FILENAME
A168_SHA256 = "becb3013cb079c2d45ee2a297d2847d5d85542843cb598e5b6288dc45b9eab76"
A168_DECOMPOSITION_SHA256 = "138cfc343738d5d5ad4a52ebb7825c1932ad2ef314f0cdfbd7f228097b774f48"
A166_FILENAME = _A166.RESULT_FILENAME
A166_SHA256 = _A168.A166_SHA256
PROTOCOL_FILENAME = "shake_symbolic_r2_alias_fanout_mobius_frontier_v1.json"
PROTOCOL_SHA256 = "a6849d51cccea60744fd45d97d734bbdc25efd82fc52aab8cd41deb786cd9f88"
PROTOCOL_SCHEMA = "shake-symbolic-r2-alias-fanout-mobius-frontier-protocol-v1"
RESULT_FILENAME = "shake_symbolic_r2_alias_fanout_mobius_frontier_v1.json"
CAUSAL_FILENAME = "shake_symbolic_r2_alias_fanout_mobius_frontier_v1.causal"
BRANCHES = ("column_only", "theta_only")


def _sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _canonical_sha256(value: Any) -> str:
    return _A168._canonical_sha256(value)


def _load_anchor_gates(
    results_dir: Path,
) -> tuple[dict[str, Any], dict[str, Any]]:
    a168 = _A156._load_json_gate(results_dir / A168_FILENAME, A168_SHA256, _A168.SCHEMA)
    a166 = _A156._load_json_gate(results_dir / A166_FILENAME, A166_SHA256, _A166.SCHEMA)
    decomposition = a168.get("effect_decomposition", {})
    if (
        a168.get("effect_decomposition_sha256") != A168_DECOMPOSITION_SHA256
        or decomposition.get("RHS_syntax_effect_L1") != 0
        or decomposition.get("connected_node_removal_effect_L1") != 5_790
        or [
            row["connected_node_removal_effect_A166_minus_A168"]
            for row in decomposition.get("rows", [])
        ]
        != [2_008, -977, -1_623, -1_182]
        or a168.get("status_counts") != {"error": 0, "sat": 0, "unknown": 4, "unsat": 0}
        or a166.get("status_counts") != {"error": 0, "sat": 0, "unknown": 4, "unsat": 0}
        or Z3_RLIMIT != 500_000_000
        or EXTERNAL_SAFETY_TIMEOUT_SECONDS != 300
    ):
        raise RuntimeError("A169 A166/A168 anchor gate failed")
    return a168, a166


def _load_protocol_gate() -> dict[str, Any]:
    path = Path(__file__).parents[1] / "configs" / PROTOCOL_FILENAME
    protocol = _A156._load_json_gate(path, PROTOCOL_SHA256, PROTOCOL_SCHEMA)
    if (
        protocol.get("attempt_id") != ATTEMPT_ID
        or protocol.get("protocol_state") != "frozen_before_any_A169_solver_execution"
        or protocol.get("anchors", {}).get("A168", {}).get("sha256") != A168_SHA256
        or protocol.get("anchors", {}).get("A166", {}).get("sha256") != A166_SHA256
        or protocol.get("fanout_design", {}).get("semantic_change") is not False
        or protocol.get("fanout_design", {}).get("new_formula_count") != 8
        or protocol.get("information_boundary", {}).get(
            "A169_solver_outcomes_used_before_formula_freeze"
        )
        is not False
    ):
        raise RuntimeError("A169 frozen protocol identity gate failed")
    return protocol


def _validate_protocol_plan(protocol: dict[str, Any], analysis: dict[str, Any]) -> None:
    rows = [
        [
            row["name"],
            row["formula_bytes"],
            row["formula_sha256"],
            row["encoding"]["single_consumer_rewrite_sha256"],
        ]
        for row in analysis["formula_plan"]
    ]
    if (
        protocol["fanout_plan"]["sha256"] != analysis["fanout_plan_sha256"]
        or protocol["formula_plan"]["sha256"] != analysis["formula_plan_sha256"]
        or protocol["formula_plan"]["rows"] != rows
    ):
        raise RuntimeError("A169 regenerated fanout/formulas differ from protocol")


def _replace_exact_line(raw: bytes, old: bytes, new: bytes) -> tuple[bytes, int]:
    lines = raw.splitlines()
    matches = [index for index, line in enumerate(lines) if line == old]
    if len(matches) != 1:
        raise RuntimeError("A169 exact consumer line is not unique")
    index = matches[0]
    lines[index] = new
    return b"\n".join(lines) + b"\n", index


def _formula_frontier(
    baseline_rows: Sequence[dict[str, Any]],
    baseline_formulas: dict[str, bytes],
) -> tuple[list[dict[str, Any]], dict[str, bytes], list[dict[str, Any]]]:
    rows = []
    formulas = {}
    fanout_plan = []
    for baseline in baseline_rows:
        order_name = baseline["encoding"]["order_name"]
        baseline_raw = baseline_formulas[baseline["name"]]
        input_name = baseline["encoding"]["R2_normalized_materialized_inputs"][0]
        column_materialized = b"(assert (= c2173 (xor s577 s895 s1215 s1534 s1853)))"
        column_inlined = (
            f"(assert (= c2173 (xor s577 s895 (not {input_name}) s1534 s1853)))".encode()
        )
        theta_materialized = b"(assert (= t3453 (xor s1215 d2493)))"
        theta_inlined = f"(assert (= t3453 (xor (not {input_name}) d2493)))".encode()
        variants = {
            "column_only": (theta_materialized, theta_inlined, 6_886),
            "theta_only": (column_materialized, column_inlined, 4_326),
        }
        for branch in BRANCHES:
            old_line, new_line, expected_index = variants[branch]
            raw, changed_index = _replace_exact_line(baseline_raw, old_line, new_line)
            baseline_lines = baseline_raw.splitlines()
            lines = raw.splitlines()
            changed = [
                index
                for index, (old, new) in enumerate(zip(baseline_lines, lines, strict=True))
                if old != new
            ]
            if (
                changed != [expected_index]
                or changed_index != expected_index
                or _A167._declaration_sequence(raw) != _A167._declaration_sequence(baseline_raw)
                or sum(b"s1215" in line for line in lines) != 3
            ):
                raise RuntimeError(f"A169 {order_name}/{branch} fanout gate failed")
            rewrite = {
                "line_index_zero_based": changed_index,
                "old_line": old_line.decode(),
                "new_line": new_line.decode(),
            }
            rewrite_sha256 = _canonical_sha256(rewrite)
            name = f"{order_name}__{branch}_alias_fanout"
            encoding = {
                **baseline["encoding"],
                "name": name,
                "compiler": "normalized_materialized_alias_single_consumer_fanout",
                "fanout_branch": branch,
                "materialized_alias_consumer_count": 1,
                "materialized_alias_consumers": (
                    ["column_c2173"] if branch == "column_only" else ["theta_t3453"]
                ),
                "inlined_alias_consumers": (
                    ["theta_t3453"] if branch == "column_only" else ["column_c2173"]
                ),
                "baseline_A168_formula_name": baseline["name"],
                "baseline_A168_formula_sha256": baseline["formula_sha256"],
                "changed_line_count_relative_to_A168": 1,
                "single_consumer_rewrite": rewrite,
                "single_consumer_rewrite_sha256": rewrite_sha256,
                "instrumented_assignment_input_used": False,
                "solver_observation_input_used_for_formula_construction": False,
                "target_rate_input_used_for_fanout_selection": False,
            }
            formulas[name] = raw
            rows.append(
                {
                    "name": name,
                    "execution_order": len(rows),
                    "formula_bytes": len(raw),
                    "formula_sha256": _sha256(raw),
                    "encoding": encoding,
                    "solver_input_names": baseline["solver_input_names"],
                    "solver_outcome_used_for_formula_construction": False,
                }
            )
            fanout_plan.append(
                {
                    "order_name": order_name,
                    "fanout_branch": branch,
                    "baseline_A168_formula_sha256": baseline["formula_sha256"],
                    "formula_sha256": _sha256(raw),
                    "declaration_sequences_identical": True,
                    "total_variables_identical": True,
                    "total_assertions_identical": True,
                    "connected_alias_definition_preserved": True,
                    "materialized_consumer_count": 1,
                    "single_consumer_rewrite": rewrite,
                    "single_consumer_rewrite_sha256": rewrite_sha256,
                    "semantic_relation_unchanged": True,
                }
            )
    return rows, formulas, fanout_plan


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
        "Boolean_SMT_shared_R2_single_consumer_alias_fanout_fixed_rlimit"
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
        raise ValueError("A169 solver work directory must be empty")
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
        raise RuntimeError("A169 solver formula cleanup failed")
    return results


def _execution_summary(executions: Sequence[dict[str, Any]]) -> list[dict[str, Any]]:
    return [
        {
            "name": row["name"],
            "order_name": row["encoding"]["order_name"],
            "fanout_branch": row["encoding"]["fanout_branch"],
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


def _mobius_decomposition(
    a166: dict[str, Any],
    a168: dict[str, Any],
    executions: Sequence[dict[str, Any]],
) -> dict[str, Any]:
    inline = {row["order_name"]: row for row in a166["execution_summary"]}
    both = {row["order_name"]: row for row in a168["execution_summary"]}
    observed = {
        (row["encoding"]["order_name"], row["encoding"]["fanout_branch"]): row for row in executions
    }
    rows = []
    for order_name in _A158.ORDER_NAMES:
        y00 = int(inline[order_name]["stats"]["decisions"])
        y10 = int(observed[(order_name, "column_only")]["solver"]["stats"]["decisions"])
        y01 = int(observed[(order_name, "theta_only")]["solver"]["stats"]["decisions"])
        y11 = int(both[order_name]["stats"]["decisions"])
        column = y10 - y00
        theta = y01 - y00
        interaction = y11 - y10 - y01 + y00
        total = y11 - y00
        if column + theta + interaction != total:
            raise RuntimeError("A169 exact Möbius identity failed")
        components = {
            "column_consumer_main": column,
            "theta_consumer_main": theta,
            "fanout_interaction": interaction,
        }
        maximum = max(abs(value) for value in components.values())
        dominant = sorted(name for name, value in components.items() if abs(value) == maximum)
        rows.append(
            {
                "order_name": order_name,
                "fanout0_inline_decisions": y00,
                "fanout1_column_only_decisions": y10,
                "fanout1_theta_only_decisions": y01,
                "fanout2_both_decisions": y11,
                "column_consumer_main_effect": column,
                "theta_consumer_main_effect": theta,
                "fanout_interaction_effect": interaction,
                "total_materialization_effect": total,
                "exact_mobius_identity_verified": True,
                "dominant_absolute_components": dominant,
            }
        )
    component_l1 = {
        "column_consumer_main": sum(abs(row["column_consumer_main_effect"]) for row in rows),
        "theta_consumer_main": sum(abs(row["theta_consumer_main_effect"]) for row in rows),
        "fanout_interaction": sum(abs(row["fanout_interaction_effect"]) for row in rows),
    }
    maximum = max(component_l1.values())
    return {
        "rows": rows,
        "component_L1": component_l1,
        "aggregate_dominant_components": sorted(
            name for name, value in component_l1.items() if value == maximum
        ),
        "all_interactions_zero": all(row["fanout_interaction_effect"] == 0 for row in rows),
    }


def _posthoc_summary(
    problem: dict[str, Any], variant: Any, executions: Sequence[dict[str, Any]]
) -> dict[str, Any]:
    actual = _A168._WINDOW._extract_window(problem["base_state"], variant, problem["positions"])
    return {
        "instrumented_input_assignment": actual,
        "extracted_only_after_every_A169_execution": True,
        "used_for_fanout_formula_order_or_execution": False,
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
        experiment="shake_symbolic_r2_alias_fanout_mobius_frontier",
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
        "shake128-a168-single-connected-alias-node",
        "shake128-a169-two-exact-suffix-consumers",
        "shake128-a169-eight-single-consumer-formulas",
        "shake128-a169-fixed-resource-execution",
        "shake128-a169-fanout-mobius-decomposition",
    ]
    builder.add_triplet(
        edge_id=ids[0],
        trigger="A168:zero_RHS_syntax_and_ID_shift_decision_effects",
        mechanism="localize_the_complete_mixed_order_response_to_connected_alias_node_s1215",
        outcome="A169:single_connected_alias_node_anchor",
        confidence=1.0,
        evidence_kind="orthogonal_three_arm_component_decompositions",
        source=A168_SHA256,
        attrs={"A168_gate": payload["anchor_gates"]["A168"]},
    )
    builder.add_triplet(
        edge_id=ids[1],
        trigger="A169:single_connected_alias_node_anchor",
        mechanism="enumerate_the_nodes_exact_column_c2173_and_theta_t3453_consumers",
        outcome="A169:two_consumer_fanout_graph",
        confidence=1.0,
        evidence_kind="exact_formula_reference_reader",
        source=payload["fanout_plan_sha256"],
        provenance=[ids[0]],
        attrs={"fanout_plan": payload["fanout_plan"]},
    )
    builder.add_triplet(
        edge_id=ids[2],
        trigger="A169:two_consumer_fanout_graph",
        mechanism="retain_exactly_one_materialized_consumer_and_inline_the_other_for_each_order",
        outcome="A169:eight_single_consumer_fullround_formulas",
        confidence=1.0,
        evidence_kind="semantics_preserving_single_line_interventions",
        source=payload["formula_plan_sha256"],
        provenance=[ids[1]],
        attrs={"formula_plan": payload["formula_plan"]},
    )
    builder.add_triplet(
        edge_id=ids[3],
        trigger="A169:eight_single_consumer_fullround_formulas",
        mechanism="execute_all_eight_formulas_under_the_unchanged_fixed_resource_protocol",
        outcome="A169:eight_single_consumer_solver_observations",
        confidence=1.0,
        evidence_kind="fixed_resource_execution_and_complete_rate_gate",
        source="Z3_4.15.4_plus_independent_NumPy_lane_core",
        provenance=[ids[2]],
        attrs={"execution_summary": payload["execution_summary"]},
    )
    builder.add_triplet(
        edge_id=ids[4],
        trigger="A169:eight_single_consumer_solver_observations",
        mechanism="join_A166_fanout0_A169_fanout1_and_A168_fanout2_into_exact_boolean_lattice_coefficients",
        outcome="A169:four_order_alias_fanout_mobius_decomposition",
        confidence=1.0,
        evidence_kind="exact_two_factor_mobius_decomposition",
        source=payload["mobius_decomposition_sha256"],
        provenance=[ids[3]],
        attrs={"mobius_decomposition": payload["mobius_decomposition"]},
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
        raise RuntimeError("A169 Causal provenance chain failed validation")
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
    a168, a166 = _load_anchor_gates(results_dir)
    baseline = _A168.analyze(results_dir)
    rows, formulas, fanout_plan = _formula_frontier(baseline["rows"], baseline["formulas"])
    plan = _formula_plan(rows)
    return {
        "anchors": (a168, a166),
        "variant": baseline["variant"],
        "problem": baseline["problem"],
        "rows": rows,
        "formulas": formulas,
        "fanout_plan": fanout_plan,
        "fanout_plan_sha256": _canonical_sha256(fanout_plan),
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
    a168, a166 = analysis["anchors"]
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
    decomposition = _mobius_decomposition(a166, a168, executions)
    posthoc = _posthoc_summary(analysis["problem"], analysis["variant"], executions)
    payload: dict[str, Any] = {
        "schema": SCHEMA,
        "attempt_id": ATTEMPT_ID,
        "evidence_stage": "ALIAS_FANOUT_MOBIUS_FRONTIER_EXECUTED",
        "result": (
            "A169 retains the normalized negative-alias node on exactly one "
            "of its two first-suffix-round consumers per formula and joins "
            "fanout zero, one and two into an exact Möbius decomposition."
        ),
        "scope": (
            "The retained A152 SHAKE128 width-24 relation, affine gauge 0x4e1e28, "
            "four A158 orders, shared R2 prefix, 22 unchanged suffix rounds and "
            "all 1,344 rate bits."
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
            "A169_protocol": {
                "artifact_sha256": PROTOCOL_SHA256,
                "protocol_state": analysis["protocol"]["protocol_state"],
                "information_boundary": analysis["protocol"]["information_boundary"],
            },
            "A168": {
                "artifact_sha256": A168_SHA256,
                "effect_decomposition_sha256": A168_DECOMPOSITION_SHA256,
                "connected_node_removal_effect_L1": a168["effect_decomposition"][
                    "connected_node_removal_effect_L1"
                ],
            },
            "A166": {
                "artifact_sha256": A166_SHA256,
                "comparison_sha256": a166["comparison_sha256"],
            },
        },
        "fanout_plan": analysis["fanout_plan"],
        "fanout_plan_sha256": analysis["fanout_plan_sha256"],
        "formula_plan": analysis["formula_plan"],
        "formula_plan_sha256": analysis["formula_plan_sha256"],
        "execution": executions,
        "execution_summary": summary,
        "status_counts": status_counts,
        "confirmed_models": confirmed_models,
        "mobius_decomposition": decomposition,
        "mobius_decomposition_sha256": _canonical_sha256(decomposition),
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
        raise RuntimeError("A169 final artifact reopen gate failed")
    return {
        "json_sha256": _sha256(raw),
        "causal_sha256": reader.file_sha256,
        "causal_graph_sha256": reader.graph_sha256,
        "status_counts": status_counts,
        "confirmed_model_count": len(confirmed_models),
        "component_L1": decomposition["component_L1"],
        "aggregate_dominant_components": decomposition["aggregate_dominant_components"],
        "all_interactions_zero": decomposition["all_interactions_zero"],
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
        default=Path(__file__).parents[2] / "build" / "shake-r2-a169",
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
                    "fanout_plan_sha256": analysis["fanout_plan_sha256"],
                    "formula_plan_sha256": analysis["formula_plan_sha256"],
                    "formulas": [
                        {
                            "name": row["name"],
                            "branch": row["encoding"]["fanout_branch"],
                            "bytes": row["formula_bytes"],
                            "sha256": row["formula_sha256"],
                            "rewrite": row["encoding"]["single_consumer_rewrite"],
                            "rewrite_sha256": row["encoding"]["single_consumer_rewrite_sha256"],
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

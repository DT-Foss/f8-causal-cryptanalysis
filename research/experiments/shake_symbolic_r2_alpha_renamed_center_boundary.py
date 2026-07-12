#!/usr/bin/env python3
"""Test whether A174's central alias boundary survives exact alpha-renaming."""

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


_A174 = _import_sibling(
    "shake_symbolic_r2_center_alias_partner_transfer.py",
    "shake_symbolic_r2_alpha_renamed_a174_base",
)
_A173 = _A174._A173
_A170 = _A174._A170
_A168 = _A174._A168
_A166 = _A174._A166
_A163 = _A174._A163
_A156 = _A174._A156

ATTEMPT_ID = "A175"
SCHEMA = "shake-symbolic-r2-alpha-renamed-center-boundary-v1"
SEED = _A174.SEED
WINDOW_BITS = _A174.WINDOW_BITS
Z3_RLIMIT = _A174.Z3_RLIMIT
EXTERNAL_SAFETY_TIMEOUT_SECONDS = _A174.EXTERNAL_SAFETY_TIMEOUT_SECONDS
AFFINE_SHIFT = _A174.AFFINE_SHIFT
A174_FILENAME = _A174.RESULT_FILENAME
A174_SHA256 = "e1683380ec9f5714d2c75a700b8dd2bf50f3b9cd5ee8106c48bb21f7c1b45eae"
A174_TRANSFER_SHA256 = "a874c0d51d7eb38bb97e1a997113021b69af2aa5da3e087250a18868df11b3c0"
A173_FILENAME = _A173.RESULT_FILENAME
A173_SHA256 = _A174.A173_SHA256
PROTOCOL_FILENAME = "shake_symbolic_r2_alpha_renamed_center_boundary_v1.json"
PROTOCOL_SHA256 = "c1f608902bf55a7dfbc3703164124d8dcd9f83c973dc175f6b89275b496f0eb6"
PROTOCOL_SCHEMA = "shake-symbolic-r2-alpha-renamed-center-boundary-protocol-v1"
RESULT_FILENAME = "shake_symbolic_r2_alpha_renamed_center_boundary_v1.json"
CAUSAL_FILENAME = "shake_symbolic_r2_alpha_renamed_center_boundary_v1.causal"
ALPHA_OFFSET = 1

_DECLARATION = re.compile(
    rb"^\(declare-fun ([A-Za-z_][A-Za-z0-9_]*) \(\) Bool\)$",
    re.MULTILINE,
)
_SUFFIXED_SYMBOL = re.compile(rb"^([A-Za-z_]+)([0-9]+)$")
_SYMBOL_TOKEN = re.compile(rb"(?<![A-Za-z0-9_])([A-Za-z_][A-Za-z0-9_]*)(?![A-Za-z0-9_])")


def _sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _canonical_sha256(value: Any) -> str:
    return _A174._canonical_sha256(value)


def _load_anchor_gates(
    results_dir: Path,
) -> tuple[dict[str, Any], dict[str, Any]]:
    a174 = _A156._load_json_gate(
        results_dir / A174_FILENAME,
        A174_SHA256,
        _A174.SCHEMA,
    )
    a173 = _A156._load_json_gate(
        results_dir / A173_FILENAME,
        A173_SHA256,
        _A173.SCHEMA,
    )
    transfer = a174.get("partner_transfer_result", {})
    if (
        a174.get("partner_transfer_result_sha256") != A174_TRANSFER_SHA256
        or transfer.get("classification") != "central_alias_boundary_transfers"
        or transfer.get("directional_delta_alias_position_11_minus_12") != 2_196
        or transfer.get("prospective_prediction_confirmed") is not True
        or a174.get("status_counts") != {"error": 0, "sat": 0, "unknown": 4, "unsat": 0}
        or a173.get("family_contrast_result", {}).get("weighted_desc_directional_delta") != 10_955
        or Z3_RLIMIT != 500_000_000
        or EXTERNAL_SAFETY_TIMEOUT_SECONDS != 300
    ):
        raise RuntimeError("A175 A173/A174 anchor gate failed")
    return a174, a173


def _load_protocol_gate() -> dict[str, Any]:
    path = Path(__file__).parents[1] / "configs" / PROTOCOL_FILENAME
    protocol = _A156._load_json_gate(path, PROTOCOL_SHA256, PROTOCOL_SCHEMA)
    if (
        protocol.get("attempt_id") != ATTEMPT_ID
        or protocol.get("protocol_state") != "frozen_before_any_A175_solver_execution"
        or protocol.get("anchors", {}).get("A174", {}).get("sha256") != A174_SHA256
        or protocol.get("alpha_intervention", {}).get("semantic_change") is not False
        or protocol.get("alpha_intervention", {}).get("new_formula_count") != 4
        or protocol.get("alpha_intervention", {}).get("numeric_suffix_offset") != ALPHA_OFFSET
        or protocol.get("prospective_prediction", {}).get("direction")
        != "renamed_directional_delta_remains_strictly_positive"
        or protocol.get("information_boundary", {}).get(
            "A175_solver_outcomes_used_before_formula_freeze"
        )
        is not False
    ):
        raise RuntimeError("A175 frozen protocol identity gate failed")
    return protocol


def _validate_protocol_plan(protocol: dict[str, Any], analysis: dict[str, Any]) -> None:
    rows = [
        [
            row["name"],
            row["formula_bytes"],
            row["formula_sha256"],
            row["encoding"]["alpha_mapping_sha256"],
        ]
        for row in analysis["formula_plan"]
    ]
    if (
        protocol["alpha_plan"]["sha256"] != analysis["alpha_plan_sha256"]
        or protocol["formula_plan"]["sha256"] != analysis["formula_plan_sha256"]
        or protocol["formula_plan"]["rows"] != rows
    ):
        raise RuntimeError("A175 regenerated alpha/formulas differ from protocol")


def _alpha_rename_formula(
    raw: bytes,
    inputs: Sequence[str],
) -> tuple[bytes, list[str], dict[str, Any]]:
    declarations = _DECLARATION.findall(raw)
    if len(declarations) not in (121_575, 121_576) or len(set(declarations)) != len(declarations):
        raise RuntimeError("A175 declaration sequence shape differs")

    mapping: dict[bytes, bytes] = {}
    mapping_rows = []
    for name in declarations:
        match = _SUFFIXED_SYMBOL.fullmatch(name)
        if match is None:
            raise RuntimeError(f"A175 symbol lacks numeric suffix: {name!r}")
        renamed = match.group(1) + str(int(match.group(2)) + ALPHA_OFFSET).encode()
        mapping[name] = renamed
        mapping_rows.append([name.decode(), renamed.decode()])
    if len(set(mapping.values())) != len(mapping):
        raise RuntimeError("A175 alpha map is not bijective")

    changed_tokens = 0

    def replace(match: re.Match[bytes]) -> bytes:
        nonlocal changed_tokens
        token = match.group(1)
        replacement = mapping.get(token)
        if replacement is None:
            return token
        changed_tokens += 1
        return replacement

    renamed_raw = _SYMBOL_TOKEN.sub(replace, raw)
    renamed_declarations = _DECLARATION.findall(renamed_raw)
    expected_declarations = [mapping[name] for name in declarations]
    reverse = {renamed: original for original, renamed in mapping.items()}
    restored = _SYMBOL_TOKEN.sub(
        lambda match: reverse.get(match.group(1), match.group(1)), renamed_raw
    )
    renamed_inputs = [mapping[name.encode()].decode() for name in inputs]
    if (
        renamed_raw == raw
        or renamed_declarations != expected_declarations
        or restored != raw
        or changed_tokens <= len(declarations)
        or len(renamed_inputs) != WINDOW_BITS
        or len(set(renamed_inputs)) != WINDOW_BITS
    ):
        raise RuntimeError("A175 alpha-isomorphism gate failed")
    plan = {
        "numeric_suffix_offset": ALPHA_OFFSET,
        "declaration_count": len(declarations),
        "declaration_order_preserved": True,
        "assertion_order_preserved": True,
        "graph_topology_preserved": True,
        "symbol_prefixes_preserved": True,
        "changed_symbol_token_count": changed_tokens,
        "alpha_mapping_sha256": _canonical_sha256(mapping_rows),
        "first_mapping_rows": mapping_rows[:8],
        "last_mapping_rows": mapping_rows[-8:],
        "inverse_transform_recovers_original_bytes": True,
        "original_formula_sha256": _sha256(raw),
        "renamed_formula_sha256": _sha256(renamed_raw),
    }
    return renamed_raw, renamed_inputs, plan


def _formula_frontier(
    base: dict[str, Any],
) -> tuple[list[dict[str, Any]], dict[str, bytes], list[dict[str, Any]]]:
    rows = []
    formulas = {}
    alpha_rows = []
    for source_row in base["rows"]:
        original = base["formulas"][source_row["name"]]
        renamed, renamed_inputs, alpha = _alpha_rename_formula(
            original,
            source_row["solver_input_names"],
        )
        name = f"alpha_plus_1__{source_row['name']}"
        encoding = dict(source_row["encoding"])
        encoding.update(
            {
                "name": name,
                "alpha_renaming": "every_declared_symbol_numeric_suffix_plus_one",
                "alpha_mapping_sha256": alpha["alpha_mapping_sha256"],
                "alpha_graph_isomorphic_to_A174": True,
                "alpha_inverse_recovers_A174_formula_bytes": True,
                "A174_formula_name": source_row["name"],
                "A174_formula_sha256": source_row["formula_sha256"],
                "instrumented_assignment_input_used": False,
                "solver_observation_input_used_for_formula_construction": False,
                "target_rate_input_used_for_alpha_mapping": False,
            }
        )
        formulas[name] = renamed
        rows.append(
            {
                "name": name,
                "execution_order": len(rows),
                "formula_bytes": len(renamed),
                "formula_sha256": _sha256(renamed),
                "encoding": encoding,
                "solver_input_names": renamed_inputs,
                "solver_outcome_used_for_formula_construction": False,
            }
        )
        alpha_rows.append({"name": name, **alpha})
    return rows, formulas, alpha_rows


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
        "Boolean_SMT_shared_R2_alpha_suffix_plus_1_fixed_rlimit"
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
        raise ValueError("A175 solver work directory must be empty")
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
        raise RuntimeError("A175 solver formula cleanup failed")
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


def _alpha_boundary_result(
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
                "alpha_renamed_decisions": int(row["solver"]["stats"]["decisions"]),
                "decision_delta_alpha_minus_A174": int(row["solver"]["stats"]["decisions"])
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
        "exact_alpha_invariance"
        if exact_all
        else "central_boundary_alpha_robust"
        if delta > 0
        else "alpha_renamed_exact_boundary"
        if delta == 0
        else "numeric_symbol_identity_conditioned"
    )
    return {
        "decision_rows": decision_rows,
        "effect_rows": effect_rows,
        "A174_directional_delta": a174["partner_transfer_result"][
            "directional_delta_alias_position_11_minus_12"
        ],
        "alpha_renamed_directional_delta": delta,
        "directional_delta_change": delta
        - a174["partner_transfer_result"]["directional_delta_alias_position_11_minus_12"],
        "all_four_canonical_observations_exactly_equal": exact_all,
        "prospective_prediction": "renamed_directional_delta_remains_strictly_positive",
        "prospective_prediction_confirmed": delta > 0,
        "classification": classification,
    }


def _build_causal(path: Path, payload: dict[str, Any]) -> dict[str, Any]:
    builder = CryptoCausalBuilder(
        experiment="shake_symbolic_r2_alpha_renamed_center_boundary",
        parameters={
            "attempt_id": ATTEMPT_ID,
            "variant": "shake128",
            "window_bits": WINDOW_BITS,
            "affine_shift": AFFINE_SHIFT,
            "new_formula_count": 4,
            "numeric_suffix_offset": ALPHA_OFFSET,
            "rlimit_per_formula": Z3_RLIMIT,
        },
    )
    ids = [
        "shake128-a174-prospective-central-partner-transfer",
        "shake128-a175-bijective-symbol-suffix-shift",
        "shake128-a175-four-alpha-isomorphic-formulas",
        "shake128-a175-fixed-resource-alpha-execution",
        "shake128-a175-alpha-boundary-result",
    ]
    builder.add_triplet(
        edge_id=ids[0],
        trigger="A174:partner_22_positive_directional_delta",
        mechanism="separate_relative_graph_position_from_concrete_symbol_identity",
        outcome="A175:alpha_renaming_question",
        confidence=1.0,
        evidence_kind="prospective_partner_transfer_anchor",
        source=A174_SHA256,
        attrs={"A174_gate": payload["anchor_gates"]["A174"]},
    )
    builder.add_triplet(
        edge_id=ids[1],
        trigger="A175:alpha_renaming_question",
        mechanism="add_one_to_every_declared_symbol_numeric_suffix_bijectively",
        outcome="A175:exact_alpha_isomorphic_graphs",
        confidence=1.0,
        evidence_kind="byte_reversible_alpha_intervention",
        source=payload["alpha_plan_sha256"],
        provenance=[ids[0]],
        attrs={"alpha_plan": payload["alpha_plan"]},
    )
    builder.add_triplet(
        edge_id=ids[2],
        trigger="A175:exact_alpha_isomorphic_graphs",
        mechanism="freeze_all_four_renamed_formula_bytes_before_solver_execution",
        outcome="A175:four_hash_bound_alpha_formulas",
        confidence=1.0,
        evidence_kind="prospective_formula_frontier",
        source=payload["formula_plan_sha256"],
        provenance=[ids[1]],
        attrs={"formula_plan": payload["formula_plan"]},
    )
    builder.add_triplet(
        edge_id=ids[3],
        trigger="A175:four_hash_bound_alpha_formulas",
        mechanism="execute_under_unchanged_fixed_resource_protocol",
        outcome="A175:four_alpha_solver_observations",
        confidence=1.0,
        evidence_kind="fixed_resource_execution_and_complete_rate_gate",
        source="Z3_4.15.4_plus_independent_NumPy_lane_core",
        provenance=[ids[2]],
        attrs={"execution_summary": payload["execution_summary"]},
    )
    builder.add_triplet(
        edge_id=ids[4],
        trigger="A175:four_alpha_solver_observations",
        mechanism="compare_renamed_materialization_delta_with_A174_direction",
        outcome="A175:prospective_alpha_boundary_test",
        confidence=1.0,
        evidence_kind="paired_alpha_isomorphism_intervention",
        source=payload["alpha_boundary_result_sha256"],
        provenance=[ids[3]],
        attrs={"alpha_boundary_result": payload["alpha_boundary_result"]},
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
        raise RuntimeError("A175 Causal provenance chain failed validation")
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
    a174, a173 = _load_anchor_gates(results_dir)
    base = _A174.analyze(results_dir)
    rows, formulas, alpha_rows = _formula_frontier(base)
    plan = _formula_plan(rows)
    return {
        "anchors": (a174, a173),
        "variant": base["variant"],
        "problem": base["problem"],
        "rows": rows,
        "formulas": formulas,
        "alpha_plan": alpha_rows,
        "alpha_plan_sha256": _canonical_sha256(alpha_rows),
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
    a174, a173 = analysis["anchors"]
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
    alpha_result = _alpha_boundary_result(a174, executions)
    payload: dict[str, Any] = {
        "schema": SCHEMA,
        "attempt_id": ATTEMPT_ID,
        "evidence_stage": "ALPHA_RENAMED_CENTER_BOUNDARY_EXECUTED",
        "result": (
            "A175 prospectively tests whether the A174 central alias-position direction "
            "survives a byte-reversible bijective alpha-renaming of every solver symbol."
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
            "numeric_suffix_offset": ALPHA_OFFSET,
            "rlimit_per_formula": Z3_RLIMIT,
            "execution_mode": "sequential_one_thread_per_formula",
            "solver": solver_version,
            "solver_wallclock_limit_used": False,
            "external_safety_timeout_seconds": EXTERNAL_SAFETY_TIMEOUT_SECONDS,
            "wallclock_excluded_from_canonical_result": True,
        },
        "anchor_gates": {
            "A175_protocol": {
                "artifact_sha256": PROTOCOL_SHA256,
                "protocol_state": analysis["protocol"]["protocol_state"],
                "prospective_prediction": analysis["protocol"]["prospective_prediction"],
                "information_boundary": analysis["protocol"]["information_boundary"],
            },
            "A174": {
                "artifact_sha256": A174_SHA256,
                "partner_transfer_result_sha256": A174_TRANSFER_SHA256,
                "directional_delta": a174["partner_transfer_result"][
                    "directional_delta_alias_position_11_minus_12"
                ],
            },
            "A173": {
                "artifact_sha256": A173_SHA256,
                "weighted_desc_directional_delta": a173["family_contrast_result"][
                    "weighted_desc_directional_delta"
                ],
            },
        },
        "alpha_plan": analysis["alpha_plan"],
        "alpha_plan_sha256": analysis["alpha_plan_sha256"],
        "formula_plan": analysis["formula_plan"],
        "formula_plan_sha256": analysis["formula_plan_sha256"],
        "execution": executions,
        "execution_summary": summary,
        "status_counts": status_counts,
        "confirmed_models": confirmed_models,
        "alpha_boundary_result": alpha_result,
        "alpha_boundary_result_sha256": _canonical_sha256(alpha_result),
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
        raise RuntimeError("A175 final artifact reopen gate failed")
    return {
        "json_sha256": _sha256(raw),
        "causal_sha256": reader.file_sha256,
        "causal_graph_sha256": reader.graph_sha256,
        "status_counts": status_counts,
        "confirmed_model_count": len(confirmed_models),
        "classification": alpha_result["classification"],
        "prospective_prediction_confirmed": alpha_result["prospective_prediction_confirmed"],
        "directional_delta": alpha_result["alpha_renamed_directional_delta"],
        "all_four_observations_exact": alpha_result[
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
        default=Path(__file__).parents[2] / "build" / "shake-r2-a175",
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
                    "alpha_plan_sha256": analysis["alpha_plan_sha256"],
                    "alpha_plan": analysis["alpha_plan"],
                    "formula_plan_sha256": analysis["formula_plan_sha256"],
                    "formulas": [
                        {
                            "name": row["name"],
                            "A174_name": row["encoding"]["A174_formula_name"],
                            "orientation": row["encoding"]["adjacent_orientation"],
                            "arm": row["encoding"]["alias_compiler_arm"],
                            "bytes": row["formula_bytes"],
                            "sha256": row["formula_sha256"],
                            "mapping_sha256": row["encoding"]["alpha_mapping_sha256"],
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

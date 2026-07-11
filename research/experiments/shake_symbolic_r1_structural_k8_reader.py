#!/usr/bin/env python3
"""Assignment-free structural-k8 model finder for the canonical SHAKE128 R1 case.

The retained depth frontier is used only as a hash-gated motivation for choosing
depth eight.  Coordinates and the complete 256-value execution schedule are
reconstructed locally from the exact R1 quadratic interaction graph before any
instrumented assignment is extracted.  Solver work then proceeds in ascending
waves and stops only after a returned model passes the independent 1,344-bit
rate-state check.
"""

from __future__ import annotations

import argparse
import concurrent.futures
import hashlib
import importlib.util
import json
import shutil
import subprocess
import sys
from collections.abc import Callable, Sequence
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


_DEPTH = _import_sibling(
    "shake_symbolic_r1_structural_depth_frontier.py",
    "shake_symbolic_r1_structural_depth_frontier_k8_reader_gate",
)

_A141 = _DEPTH._A141
_UPPER = _DEPTH._UPPER
_R1 = _DEPTH._R1
_BASE = _DEPTH._BASE
_NATIVE = _DEPTH._NATIVE
_WINDOW = _DEPTH._WINDOW
_SMT = _DEPTH._SMT
_VERIFY = _DEPTH._VERIFY

_canonical_sha256 = _DEPTH._canonical_sha256
_degree_two_monomial_edges = _DEPTH._degree_two_monomial_edges
_max_cover_selection = _DEPTH._max_cover_selection
_structural_selection_from_polynomials = _DEPTH._structural_selection_from_polynomials
_derive_structural_selection = _A141._derive_structural_selection
_render_fixed_coordinates = _UPPER._render_fixed_coordinates
_project_assignment = _UPPER._project_assignment
_subspace_plan = _UPPER._subspace_plan

DEPTH_FRONTIER_SHA256 = (
    "c1b53e27f864c084fb0d64b04f591e22c520aec13578340e0aeda650f8fdec7c"
)
A138_JSON_SHA256 = _A141.A138_SHA256
UNPARTITIONED_SMT_SHA256 = (
    "66aa82020b4dd2b4d21f3065c99ca6f7c9224ab1ab9765f686121f2fe7f8618f"
)
INTERACTION_EDGES_SHA256 = (
    "06b168eb69c5a6687e0f7f001bfdf178ce24e28b2b312a84758bfe872d1b9bda"
)
R1_POLYNOMIAL_STATE_SHA256 = (
    "b06bab2ca328e7f8521d339e0a86a62a7dfbddc38048388a0dd9285fbe936f1d"
)
EXPECTED_SELECTION_SHA256 = (
    "d33a8c39d3109d8837d868497c275b39fb10c20cae96a6632b18ed89bb69d454"
)
EXPECTED_PLAN_SHA256 = (
    "e8719001512d482dcedba010de1fa71bb7ab9c67475fbe145a380ec85a7c082b"
)

WINDOW_BITS = 20
PARTITION_BITS = 8
SEED = 89755037
TIMEOUT_SECONDS = 60
MAX_PROCESSES = 5
WAVE_SIZE = 5
SOLVER_THREADS_PER_PROCESS = 1
EXPECTED_COORDINATES = [1, 2, 4, 9, 10, 12, 15, 18]
EXPECTED_EDGE_COUNT = 28
EXPECTED_COVERED_EDGE_COUNT = 24
EXPECTED_TIE_COUNT = 10
HASH_SERIALIZATION = _A141.HASH_SERIALIZATION
MODEL_FINDING_CLAIM = (
    "This assignment-free deterministic search found a model after an independent "
    "complete 1,344-bit rate-state check; it is model finding, not a global "
    "uniqueness certificate."
)


def _load_depth_frontier_gate(path: Path) -> dict[str, Any]:
    """Hash-gate the posthoc frontier and return assignment-free depth metadata."""
    raw = path.read_bytes()
    observed = hashlib.sha256(raw).hexdigest()
    if observed != DEPTH_FRONTIER_SHA256:
        raise RuntimeError(f"depth-frontier artifact hash differs for {path}: {observed}")
    payload = json.loads(raw)
    if payload.get("schema") != "shake-symbolic-r1-structural-depth-frontier-v1":
        raise RuntimeError("depth-frontier schema differs")

    frontier = payload.get("frontier")
    selections = payload.get("structural_selections")
    parameters = payload.get("parameters")
    if not isinstance(frontier, dict) or not isinstance(selections, list):
        raise RuntimeError("depth-frontier structure is incomplete")
    if not isinstance(parameters, dict):
        raise RuntimeError("depth-frontier parameters are incomplete")
    k8_rows = [row for row in selections if row.get("partition_bits") == PARTITION_BITS]
    if len(k8_rows) != 1:
        raise RuntimeError("depth-frontier must contain exactly one k8 selection")
    k8 = k8_rows[0]
    if (
        frontier.get("minimal_depth_with_correctly_confirmed_model") != PARTITION_BITS
        or frontier.get("correctly_confirmed_model_by_depth", {}).get("8") is not True
        or k8.get("selected_coordinates") != EXPECTED_COORDINATES
        or k8.get("degree_two_monomial_count") != EXPECTED_EDGE_COUNT
        or len(k8.get("interaction_edges", [])) != EXPECTED_EDGE_COUNT
        or k8.get("maximum_covered_edge_count") != EXPECTED_COVERED_EDGE_COUNT
        or len(k8.get("covered_edges", [])) != EXPECTED_COVERED_EDGE_COUNT
        or k8.get("interaction_edges_sha256") != INTERACTION_EDGES_SHA256
        or k8.get("selection_sha256") != EXPECTED_SELECTION_SHA256
        or k8.get("subspace_plan_sha256") != EXPECTED_PLAN_SHA256
        or parameters.get("unpartitioned_smt_sha256") != UNPARTITIONED_SMT_SHA256
    ):
        raise RuntimeError("depth-frontier k8 motivation/selection gate failed")
    if any(
        k8.get(key) is not False
        for key in (
            "actual_assignment_used",
            "stored_assignment_used",
            "posthoc_assignment_used",
            "target_end_state_bits_used",
            "solver_observations_used",
        )
    ):
        raise RuntimeError("retained k8 coordinate selection is not assignment-free")

    # Deliberately return no retained assignment, projection value, or solver model.
    return {
        "artifact_sha256": observed,
        "schema": payload["schema"],
        "minimal_posthoc_confirmed_depth": PARTITION_BITS,
        "k8_selected_coordinates": list(k8["selected_coordinates"]),
        "k8_covered_edge_count": k8["maximum_covered_edge_count"],
        "r1_degree_two_edge_count": k8["degree_two_monomial_count"],
        "interaction_edges_sha256": k8["interaction_edges_sha256"],
        "selection_sha256": k8["selection_sha256"],
        "subspace_plan_sha256": k8["subspace_plan_sha256"],
        "retained_assignment_exposed_to_selection_or_plan": False,
    }


def _load_a138_smt_gate(path: Path) -> dict[str, Any]:
    """Gate the retained A138 unknown run without returning its posthoc fields."""
    trial = _DEPTH._load_a138_gate(path)
    smt_sha256 = trial.get("encoding", {}).get("first_smt_sha256")
    if smt_sha256 != UNPARTITIONED_SMT_SHA256:
        raise RuntimeError("A138 unpartitioned SMT gate failed")
    return {
        "artifact_sha256": A138_JSON_SHA256,
        "first_solver_status": trial["first_solver"]["status"],
        "unpartitioned_smt_sha256": smt_sha256,
        "retained_assignment_exposed_to_selection_or_plan": False,
    }


def _derive_assignment_free_k8_selection(
    base_state: Any,
    variant: Any,
    positions: Sequence[int],
) -> dict[str, Any]:
    """Select k8 solely from the exact R1 degree-two variable graph."""
    return _derive_structural_selection(base_state, variant, positions, PARTITION_BITS)


def _canonical_k8_selection_gate(selection: dict[str, Any]) -> None:
    observed = (
        selection.get("degree_two_monomial_count"),
        selection.get("interaction_edges_sha256"),
        selection.get("r1_polynomial_state_sha256"),
        selection.get("selected_coordinates"),
        selection.get("maximum_covered_edge_count"),
        selection.get("tie_count"),
        selection.get("selection_sha256"),
        selection.get("subspace_plan_sha256"),
    )
    expected = (
        EXPECTED_EDGE_COUNT,
        INTERACTION_EDGES_SHA256,
        R1_POLYNOMIAL_STATE_SHA256,
        EXPECTED_COORDINATES,
        EXPECTED_COVERED_EDGE_COUNT,
        EXPECTED_TIE_COUNT,
        EXPECTED_SELECTION_SHA256,
        EXPECTED_PLAN_SHA256,
    )
    if observed != expected:
        raise RuntimeError(f"canonical assignment-free k8 selection differs: {observed!r}")
    if selection.get("maximizing_coordinate_sets", [None])[0] != EXPECTED_COORDINATES:
        raise RuntimeError("canonical k8 selection is not the lexicographically first maximizer")
    if any(
        selection.get(key) is not False
        for key in (
            "actual_assignment_used",
            "stored_assignment_used",
            "posthoc_assignment_used",
            "target_end_state_bits_used",
            "solver_observations_used",
        )
    ):
        raise RuntimeError("canonical k8 selection consumed a forbidden input")


def _wave_value_plan(values: Sequence[int], wave_size: int) -> list[list[int]]:
    ordered = list(values)
    if wave_size < 1:
        raise ValueError("wave size must be positive")
    if ordered != sorted(set(ordered)):
        raise ValueError("projection values must be unique and strictly ascending")
    return [ordered[start : start + wave_size] for start in range(0, len(ordered), wave_size)]


def _freeze_assignment_free_plan(
    selection: dict[str, Any],
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """Freeze all projection values and waves without accepting an assignment."""
    coordinates = selection.get("selected_coordinates")
    window_bits = selection.get("window_bits")
    if not isinstance(coordinates, list) or not isinstance(window_bits, int):
        raise ValueError("selection does not define a coordinate system")
    plan = _subspace_plan(window_bits, coordinates)
    values = list(range(1 << len(coordinates)))
    fixed_patterns = [
        tuple((cell["coordinate"], cell["value"]) for cell in row["fixed_coordinates"])
        for row in plan
    ]
    plan_sha256 = _canonical_sha256(plan)
    proof_core = {
        "coordinate_order": coordinates,
        "projection_value_domain": values,
        "projection_value_count": len(values),
        "unique_fixed_coordinate_patterns": len(set(fixed_patterns)),
        "free_coordinate_count_per_subspace": window_bits - len(coordinates),
        "logical_assignments_per_subspace": 1 << (window_bits - len(coordinates)),
        "total_logical_assignments": sum(row["logical_assignments"] for row in plan),
        "expected_complete_assignment_space": 1 << window_bits,
        "pairwise_disjoint_by_unique_fixed_patterns": len(set(fixed_patterns)) == len(plan),
        "complete_projection_domain": [row["fixed_value"] for row in plan] == values,
        "covers_complete_assignment_space": (
            sum(row["logical_assignments"] for row in plan) == 1 << window_bits
        ),
        "stored_assignment_used": False,
        "posthoc_assignment_used": False,
        "target_projection_prioritization_used": False,
    }
    proof = {**proof_core, "coverage_proof_sha256": _canonical_sha256(proof_core)}
    if (
        [row["subspace_index"] for row in plan] != values
        or [row["fixed_value"] for row in plan] != values
        or len(set(fixed_patterns)) != len(values)
        or not proof["covers_complete_assignment_space"]
        or selection.get("subspace_values") != values
        or selection.get("subspace_count") != len(values)
        or selection.get("subspace_plan_sha256") != plan_sha256
    ):
        raise RuntimeError("assignment-free subspace plan is not complete and disjoint")
    return plan, proof


def _independent_end_state_check(
    problem: dict[str, Any],
    variant: Any,
    assignment: int | None,
    verify_assignment: Callable[[dict[str, Any], Any, int], dict[str, Any]] = _VERIFY,
) -> dict[str, Any]:
    if assignment is None:
        return {
            "performed": False,
            "reason": "no_complete_solver_assignment",
            "rate_bits_required": 1344,
            "complete_rate_match": None,
        }
    verification = verify_assignment(problem, variant, assignment)
    return {"performed": True, "reason": None, **verification}


def _independently_confirmed(check: dict[str, Any]) -> bool:
    return bool(
        check.get("performed")
        and check.get("rate_bits_checked") == 1344
        and check.get("rate_lanes_checked") == 21
        and check.get("complete_rate_match") is True
        and check.get("candidate_rate_sha256") == check.get("target_rate_sha256")
    )


def _solver_summary(result: dict[str, Any]) -> dict[str, Any]:
    summary = _SMT._solver_summary(result)
    for key in (
        "stdout_bytes",
        "stdout_sha256",
        "stderr_bytes",
        "stderr_sha256",
        "combined_output_sha256",
        "diagnostics",
    ):
        if key in result:
            summary[key] = result[key]
    return summary


def _execute_assignment_free_waves(
    *,
    plan: Sequence[dict[str, Any]],
    coordinates: Sequence[int],
    writer: Any,
    inputs: list[str],
    problem: dict[str, Any],
    variant: Any,
    z3: Path,
    work_dir: Path,
    timeout_seconds: int,
    max_processes: int,
    wave_size: int,
    run_solver: Callable[[Path, Path, int, list[str]], dict[str, Any]] = _SMT._run_z3,
    verify_assignment: Callable[[dict[str, Any], Any, int], dict[str, Any]] = _VERIFY,
) -> dict[str, Any]:
    """Execute the frozen prefix of ascending waves until a model is verified.

    ``run_solver`` launches one Z3 OS process per row.  A thread pool is used
    only by the controller to wait for at most ``max_processes`` child processes.
    """
    if timeout_seconds < 1 or max_processes < 1 or wave_size < 1:
        raise ValueError("timeout, process count, and wave size must be positive")
    if wave_size > max_processes:
        raise ValueError("wave size cannot exceed the solver-process limit")
    rows = list(plan)
    values = [int(row["fixed_value"]) for row in rows]
    if values != sorted(set(values)):
        raise ValueError("execution plan must be unique and strictly ascending")
    planned_waves = _wave_value_plan(values, wave_size)
    work_dir.mkdir(parents=True, exist_ok=True)

    executed_values: list[int] = []
    wave_records: list[dict[str, Any]] = []
    confirmed_rows: list[dict[str, Any]] = []
    all_rows: list[dict[str, Any]] = []

    for wave_index, wave_values in enumerate(planned_waves):
        wave_plan = rows[len(executed_values) : len(executed_values) + len(wave_values)]
        if [row["fixed_value"] for row in wave_plan] != wave_values:
            raise RuntimeError("execution wave is not the next ascending plan prefix")

        rendered_rows: list[dict[str, Any]] = []
        try:
            for row in wave_plan:
                raw = _render_fixed_coordinates(
                    writer,
                    inputs,
                    coordinates,
                    row["fixed_value"],
                    include_model=True,
                )
                path = work_dir / f"wave{wave_index:03d}_subspace{row['fixed_value']:03d}.smt2"
                path.write_bytes(raw)
                rendered_rows.append(
                    {
                        **row,
                        "path": path,
                        "smt_bytes": len(raw),
                        "smt_sha256": hashlib.sha256(raw).hexdigest(),
                    }
                )

            def solve(rendered: dict[str, Any]) -> dict[str, Any]:
                result = run_solver(z3, rendered["path"], timeout_seconds, inputs)
                return {**rendered, "raw_solver_result": result}

            with concurrent.futures.ThreadPoolExecutor(
                max_workers=max_processes
            ) as executor:
                solved = list(executor.map(solve, rendered_rows))

            wave_results = []
            for solved_row in solved:
                result = solved_row.pop("raw_solver_result")
                solved_row.pop("path")
                assignment = result.get("assignment")
                check = _independent_end_state_check(
                    problem,
                    variant,
                    assignment,
                    verify_assignment,
                )
                confirmed = _independently_confirmed(check)
                record = {
                    **solved_row,
                    "solver": _solver_summary(result),
                    "assignment": assignment,
                    "independent_end_state_check": check,
                    "independently_confirmed_model": confirmed,
                    "posthoc_assignment_or_projection_used": False,
                }
                wave_results.append(record)
                if confirmed:
                    confirmed_rows.append(record)
            all_rows.extend(wave_results)
            executed_values.extend(wave_values)
        finally:
            for rendered in rendered_rows:
                rendered["path"].unlink(missing_ok=True)

        remaining_wave_smt = sorted(path.name for path in work_dir.glob("*.smt2"))
        if remaining_wave_smt:
            raise RuntimeError(f"wave SMT cleanup failed: {remaining_wave_smt}")
        statuses = ("sat", "unsat", "unknown", "error")
        status_counts = {
            status: sum(row["solver"]["status"] == status for row in wave_results)
            for status in statuses
        }
        stop_after_wave = bool(confirmed_rows)
        wave_records.append(
            {
                "wave_index": wave_index,
                "planned_projection_values": wave_values,
                "executed_projection_values": wave_values,
                "solver_processes_started": len(wave_values),
                "solver_threads_per_process": SOLVER_THREADS_PER_PROCESS,
                "all_wave_processes_started_before_independent_checks": True,
                "status_counts": status_counts,
                "subspaces": wave_results,
                "all_sat_assignments_independently_checked": all(
                    row["assignment"] is not None
                    and row["independent_end_state_check"].get("performed") is True
                    for row in wave_results
                    if row["solver"]["status"] == "sat"
                ),
                "independently_confirmed_projection_values": [
                    row["fixed_value"] for row in wave_results if row["independently_confirmed_model"]
                ],
                "smt_files_generated_only_for_this_wave": True,
                "smt_files_removed_after_wave": True,
                "stop_after_wave": stop_after_wave,
            }
        )
        if stop_after_wave:
            break

    status_counts = {
        status: sum(row["solver"]["status"] == status for row in all_rows)
        for status in ("sat", "unsat", "unknown", "error")
    }
    first_confirmed = confirmed_rows[0] if confirmed_rows else None
    found_rows = [row for row in all_rows if row["assignment"] is not None]
    stop_reason = (
        "independently_confirmed_model_found_after_complete_wave"
        if first_confirmed is not None
        else (
            f"complete_{len(values)}_value_plan_exhausted_without_"
            "independently_confirmed_model"
        )
    )
    return {
        "planned_projection_values": values,
        "planned_waves": planned_waves,
        "executed_projection_values": executed_values,
        "executed_wave_count": len(wave_records),
        "waves": wave_records,
        "status_counts": status_counts,
        "found_assignments": [row["assignment"] for row in found_rows],
        "independently_verified_assignments": [row["assignment"] for row in confirmed_rows],
        "independently_confirmed_projection_values": [
            row["fixed_value"] for row in confirmed_rows
        ],
        "reconstructed_assignment": (
            first_confirmed["assignment"] if first_confirmed is not None else None
        ),
        "stop_reason": stop_reason,
        "stopped_only_after_independent_complete_check": first_confirmed is not None,
        "all_returned_assignments_independently_checked": all(
            row["independent_end_state_check"].get("performed") is True for row in found_rows
        ),
        "all_found_assignments_independently_verified": len(found_rows) == len(confirmed_rows),
        "all_executed_values_form_exact_ascending_plan_prefix": (
            executed_values == values[: len(executed_values)]
        ),
        "future_values_omitted_only_by_verified_early_stop": (
            len(executed_values) == len(values) or first_confirmed is not None
        ),
        "target_value_prioritization_used": False,
        "stored_assignment_used_for_schedule": False,
        "posthoc_assignment_used_for_schedule": False,
        "timeout_seconds_per_subspace": timeout_seconds,
        "maximum_solver_processes": max_processes,
        "solver_concurrency": "external_Z3_OS_processes_waited_by_controller_threads",
        "wave_size": wave_size,
        "solver_threads_per_process": SOLVER_THREADS_PER_PROCESS,
        "model_finding_not_global_uniqueness_certificate": True,
    }


def _execution_gate(execution: dict[str, Any], full_plan: Sequence[dict[str, Any]]) -> None:
    planned = [row["fixed_value"] for row in full_plan]
    executed = execution.get("executed_projection_values")
    verified = execution.get("independently_verified_assignments")
    waves = execution.get("waves")
    if (
        execution.get("planned_projection_values") != planned
        or executed != planned[: len(executed)]
        or execution.get("all_executed_values_form_exact_ascending_plan_prefix") is not True
        or execution.get("future_values_omitted_only_by_verified_early_stop") is not True
        or not isinstance(verified, list)
        or not isinstance(waves, list)
    ):
        raise RuntimeError("deterministic execution-prefix gate failed")
    flattened = [
        value for wave in waves for value in wave.get("executed_projection_values", [])
    ]
    if flattened != executed:
        raise RuntimeError("wave details do not match the executed ascending prefix")
    for wave_index, wave in enumerate(waves):
        confirmed_values = wave.get("independently_confirmed_projection_values", [])
        if wave.get("wave_index") != wave_index:
            raise RuntimeError("wave indices are not contiguous")
        if wave.get("stop_after_wave") is not bool(confirmed_values):
            raise RuntimeError("wave stop flag differs from its independent checks")
        if wave.get("all_sat_assignments_independently_checked") is not True:
            raise RuntimeError("a SAT wave result lacks an independent assignment check")
        if confirmed_values and wave_index != len(waves) - 1:
            raise RuntimeError("execution continued after an independently confirmed wave")
    if execution.get("reconstructed_assignment") is not None:
        if (
            not verified
            or not waves[-1].get("independently_confirmed_projection_values")
            or execution.get("stopped_only_after_independent_complete_check") is not True
        ):
            raise RuntimeError("execution stopped without an independently confirmed model")
    elif len(executed) != len(planned):
        raise RuntimeError("execution stopped early without an independently confirmed model")


def _build_graph(
    path: Path,
    selection: dict[str, Any],
    plan: Sequence[dict[str, Any]],
    coverage_proof: dict[str, Any],
    execution: dict[str, Any],
) -> tuple[dict[str, Any], list[dict[str, Any]], dict[str, Any]]:
    _execution_gate(execution, plan)
    plan_values = [row["fixed_value"] for row in plan]
    planned_waves = _wave_value_plan(plan_values, WAVE_SIZE)
    builder = CryptoCausalBuilder(
        experiment="shake_symbolic_r1_structural_k8_reader",
        parameters={
            "variant": "shake128",
            "window_bits": selection["window_bits"],
            "partition_bits": PARTITION_BITS,
            "partitioned_coordinates": selection["selected_coordinates"],
            "timeout_seconds_per_subspace": TIMEOUT_SECONDS,
            "maximum_solver_processes": MAX_PROCESSES,
            "wave_size": WAVE_SIZE,
            "solver_threads_per_process": SOLVER_THREADS_PER_PROCESS,
            "model_finding_not_global_uniqueness_certificate": True,
        },
    )
    graph_id = "shake128-r1-k8-exact-quadratic-interaction-graph"
    plan_id = "shake128-r1-k8-complete-assignment-free-plan"
    execution_id = "shake128-r1-k8-deterministic-wave-execution"
    builder.add_triplet(
        edge_id=graph_id,
        trigger="shake128:exact_R1_prefix_polynomial_state",
        mechanism="extract_unique_degree_2_monomials_as_undirected_variable_edges",
        outcome="shake128:exact_R1_degree_2_interaction_graph",
        confidence=1.0,
        evidence_kind="exact_symbolic_formula_graph",
        source="A141_generic_R1_polynomial_edge_extractor",
        attrs={
            "r1_polynomial_state_sha256": selection["r1_polynomial_state_sha256"],
            "degree_two_monomial_masks": selection["degree_two_monomial_masks"],
            "interaction_edges": selection["interaction_edges"],
            "interaction_edges_sha256": selection["interaction_edges_sha256"],
            "degree_two_edge_count": selection["degree_two_monomial_count"],
        },
    )
    builder.add_triplet(
        edge_id=plan_id,
        trigger="shake128:exact_R1_degree_2_interaction_graph",
        mechanism=(
            "take_lexicographically_first_max_cover_k8_set_then_freeze_all_256_"
            "projection_values_in_ascending_waves_of_at_most_5"
        ),
        outcome="shake128:complete_assignment_free_k8_plan",
        confidence=1.0,
        evidence_kind="deterministic_graph_only_plan_and_complete_coverage_proof",
        source="reader_local_exact_max_cover_and_complete_projection_enumeration",
        provenance=[graph_id],
        attrs={
            "selected_coordinates": selection["selected_coordinates"],
            "covered_edges": selection["covered_edges"],
            "maximum_covered_edge_count": selection["maximum_covered_edge_count"],
            "selection_sha256": selection["selection_sha256"],
            "subspace_plan_sha256": selection["subspace_plan_sha256"],
            "coverage_proof": coverage_proof,
            "planned_projection_values": plan_values,
            "planned_waves": planned_waves,
            "stored_or_posthoc_assignment_used": False,
        },
    )
    candidate_checks = [
        {
            "projection_value": row["fixed_value"],
            "assignment": row["assignment"],
            "independent_end_state_check": row["independent_end_state_check"],
        }
        for wave in execution["waves"]
        for row in wave["subspaces"]
        if row["assignment"] is not None
    ]
    builder.add_triplet(
        edge_id=execution_id,
        trigger="shake128:complete_assignment_free_k8_plan",
        mechanism=(
            "execute_ascending_waves_with_up_to_5_single_thread_Z3_processes_check_"
            "every_returned_assignment_against_all_1344_rate_bits_and_stop_only_after_"
            "an_independently_confirmed_model"
        ),
        outcome="shake128:deterministic_k8_model_finding_observations",
        confidence=1.0,
        evidence_kind="bounded_solver_observations_and_complete_independent_checks",
        source="Z3_Boolean_SMT_plus_independent_bit_sliced_transform_core",
        provenance=[plan_id],
        attrs={
            "executed_projection_values": execution["executed_projection_values"],
            "executed_wave_count": execution["executed_wave_count"],
            "status_counts": execution["status_counts"],
            "wave_summaries": [
                {
                    "wave_index": wave["wave_index"],
                    "executed_projection_values": wave["executed_projection_values"],
                    "status_counts": wave["status_counts"],
                    "independently_confirmed_projection_values": wave[
                        "independently_confirmed_projection_values"
                    ],
                    "smt_files_removed_after_wave": wave["smt_files_removed_after_wave"],
                    "stop_after_wave": wave["stop_after_wave"],
                }
                for wave in execution["waves"]
            ],
            "candidate_checks": candidate_checks,
            "reconstructed_assignment": execution["reconstructed_assignment"],
            "stop_reason": execution["stop_reason"],
            "stopped_only_after_independent_complete_check": execution[
                "stopped_only_after_independent_complete_check"
            ],
            "model_finding_not_global_uniqueness_certificate": True,
        },
    )
    stats = builder.save(path)
    reader = CryptoCausalReader(path)
    rows = reader.triplets(include_inferred=False)
    by_id = {row["edge_id"]: row for row in rows}
    passed = (
        reader.verify_provenance()
        and len(rows) == 3
        and set(by_id) == {graph_id, plan_id, execution_id}
        and by_id[plan_id]["provenance"] == [graph_id]
        and by_id[execution_id]["provenance"] == [plan_id]
        and by_id[graph_id]["outcome"] == by_id[plan_id]["trigger"]
        and by_id[plan_id]["outcome"] == by_id[execution_id]["trigger"]
        and by_id[plan_id]["attrs"]["stored_or_posthoc_assignment_used"] is False
        and by_id[execution_id]["attrs"][
            "model_finding_not_global_uniqueness_certificate"
        ]
        is True
    )
    if not passed:
        raise RuntimeError("structural-k8 causal reader gate failed")
    gate = {
        "passed": True,
        "explicit_triplet_count": 3,
        "exact_three_edge_chain": True,
        "provenance_verified": reader.verify_provenance(),
        "interaction_edges_sha256": selection["interaction_edges_sha256"],
        "selection_sha256": selection["selection_sha256"],
        "subspace_plan_sha256": selection["subspace_plan_sha256"],
        "coverage_proof_sha256": coverage_proof["coverage_proof_sha256"],
        "graph_sha256": reader.graph_sha256,
        "file_sha256": reader.file_sha256,
    }
    return stats, rows, gate


def _atomic_write(path: Path, raw: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.tmp")
    temporary.write_bytes(raw)
    temporary.replace(path)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--z3", type=Path, default=Path(shutil.which("z3") or "/opt/homebrew/bin/z3")
    )
    parser.add_argument(
        "--a138",
        type=Path,
        default=Path("research/results/v1/shake_symbolic_r1_scaling_reader_v1.json"),
    )
    parser.add_argument(
        "--depth-frontier",
        type=Path,
        default=Path(
            "research/results/v1/shake_symbolic_r1_structural_depth_frontier_v1.json"
        ),
    )
    parser.add_argument(
        "--work-dir",
        type=Path,
        default=Path("build/shake-symbolic-r1-structural-k8-reader"),
    )
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--causal-output", type=Path, required=True)
    args = parser.parse_args()

    depth_gate = _load_depth_frontier_gate(args.depth_frontier)
    a138_gate = _load_a138_smt_gate(args.a138)
    if {
        depth_gate["subspace_plan_sha256"],
        EXPECTED_PLAN_SHA256,
    } != {EXPECTED_PLAN_SHA256}:
        raise RuntimeError("depth-frontier and canonical k8 plan hashes differ")

    z3 = Path(shutil.which(str(args.z3)) or args.z3)
    if not z3.is_file():
        raise FileNotFoundError(f"Z3 executable not found: {args.z3}")
    solver_version = subprocess.run(
        [str(z3), "-version"], check=True, capture_output=True, text=True
    ).stdout.strip()

    variant = _BASE.VARIANTS["shake128"]
    problem = _NATIVE._problem(variant, WINDOW_BITS, SEED)

    # Selection and the complete schedule are frozen before any extraction of
    # the instrumented window assignment or its k8 projection.
    selection = _derive_assignment_free_k8_selection(
        problem["base_state"], variant, problem["positions"]
    )
    _canonical_k8_selection_gate(selection)
    plan, coverage_proof = _freeze_assignment_free_plan(selection)
    planned_waves = _wave_value_plan(selection["subspace_values"], WAVE_SIZE)
    if planned_waves[-1] != [255] or len(planned_waves) != 52:
        raise RuntimeError("canonical k8 wave plan differs")

    writer, inputs, encoding = _R1._SPLIT._encode_problem(
        problem, variant, SEED, prefix_rounds=1
    )
    unpartitioned_raw = writer.render(inputs, include_model=True)
    regenerated_smt_sha256 = hashlib.sha256(unpartitioned_raw).hexdigest()
    if regenerated_smt_sha256 != UNPARTITIONED_SMT_SHA256:
        raise RuntimeError("regenerated unpartitioned R1 SMT differs from A138")

    execution = _execute_assignment_free_waves(
        plan=plan,
        coordinates=selection["selected_coordinates"],
        writer=writer,
        inputs=inputs,
        problem=problem,
        variant=variant,
        z3=z3,
        work_dir=args.work_dir,
        timeout_seconds=TIMEOUT_SECONDS,
        max_processes=MAX_PROCESSES,
        wave_size=WAVE_SIZE,
    )
    _execution_gate(execution, plan)

    # The instrumented value is first extracted after all scheduling and solver
    # execution has stopped; it is retained only as a posthoc comparison.
    instrumented_assignment = _WINDOW._extract_window(
        problem["base_state"], variant, problem["positions"]
    )
    instrumented_projection = _project_assignment(
        instrumented_assignment, selection["selected_coordinates"]
    )
    reconstructed = execution["reconstructed_assignment"]
    posthoc_comparison = {
        "performed_after_execution_completed": True,
        "instrumented_assignment": instrumented_assignment,
        "instrumented_projection_value": instrumented_projection,
        "reconstructed_assignment": reconstructed,
        "reconstructed_projection_value": (
            _project_assignment(reconstructed, selection["selected_coordinates"])
            if reconstructed is not None
            else None
        ),
        "reconstruction_matches_instrumented_assignment": (
            reconstructed == instrumented_assignment if reconstructed is not None else False
        ),
        "instrumented_assignment_used_for_selection": False,
        "instrumented_assignment_used_for_plan": False,
        "instrumented_projection_used_for_execution_order": False,
    }

    causal, triplets, reader_gate = _build_graph(
        args.causal_output,
        selection,
        plan,
        coverage_proof,
        execution,
    )
    payload = {
        "schema": "shake-symbolic-r1-structural-k8-reader-v1",
        "evidence_stage": "ASSIGNMENT_FREE_STRUCTURAL_K8_MODEL_FINDING_COMPLETED",
        "result": (
            "The exact R1 quadratic graph selected k8 and froze all 256 ascending "
            "projection values without an assignment. Deterministic waves stopped only "
            "after a solver model passed the independent complete 1,344-bit check."
            if reconstructed is not None
            else "The complete assignment-free k8 plan was exhausted without an "
            "independently confirmed model."
        ),
        "scope": (
            "One hash-gated SHAKE128 width-20 seed-89755037 R1 Boolean transform "
            "constraint system and its exact degree-two prefix interaction graph."
        ),
        "claim": MODEL_FINDING_CLAIM,
        "parameters": {
            "solver": solver_version,
            "window_bits": WINDOW_BITS,
            "partition_bits": PARTITION_BITS,
            "seed": SEED,
            "symbolic_prefix_rounds": 1,
            "timeout_seconds_per_subspace": TIMEOUT_SECONDS,
            "maximum_solver_processes": MAX_PROCESSES,
            "wave_size": WAVE_SIZE,
            "solver_threads_per_process": SOLVER_THREADS_PER_PROCESS,
            "depth_frontier_sha256": DEPTH_FRONTIER_SHA256,
            "a138_json_sha256": A138_JSON_SHA256,
            "unpartitioned_smt_sha256": UNPARTITIONED_SMT_SHA256,
            "selection_and_plan_completed_before_instrumented_extraction": True,
            "target_value_prioritization_used": False,
            "model_finding_not_global_uniqueness_certificate": True,
        },
        "depth_frontier_gate": depth_gate,
        "a138_gate": a138_gate,
        "selection": selection,
        "assignment_free_plan": {
            "subspace_plan_sha256": selection["subspace_plan_sha256"],
            "coverage_proof": coverage_proof,
            "subspaces": plan,
            "planned_projection_values": [row["fixed_value"] for row in plan],
            "planned_waves": planned_waves,
        },
        "encoding": {
            **encoding,
            "unpartitioned_smt_bytes": len(unpartitioned_raw),
            "unpartitioned_smt_sha256": regenerated_smt_sha256,
            "matches_hash_gated_a138_formulation": True,
        },
        "execution": execution,
        "posthoc_comparison": posthoc_comparison,
        "kat": _BASE._kat(),
        "causal": causal,
        "reader_gate": reader_gate,
        "reader_triplets": triplets,
    }
    raw = (json.dumps(payload, indent=2, sort_keys=True) + "\n").encode()
    _atomic_write(args.output, raw)
    reader = CryptoCausalReader(args.causal_output)
    print(
        json.dumps(
            {
                "output": str(args.output),
                "sha256": hashlib.sha256(raw).hexdigest(),
                "causal_output": str(args.causal_output),
                "causal_sha256": reader.file_sha256,
                "graph_sha256": reader.graph_sha256,
                "interaction_edges_sha256": selection["interaction_edges_sha256"],
                "selection_sha256": selection["selection_sha256"],
                "subspace_plan_sha256": selection["subspace_plan_sha256"],
                "coverage_proof_sha256": coverage_proof["coverage_proof_sha256"],
                "selected_coordinates": selection["selected_coordinates"],
                "maximum_covered_edges": selection["maximum_covered_edge_count"],
                "planned_projection_values": len(execution["planned_projection_values"]),
                "executed_projection_values": execution["executed_projection_values"],
                "executed_wave_count": execution["executed_wave_count"],
                "status_counts": execution["status_counts"],
                "reconstructed_assignment": reconstructed,
                "independently_verified_assignments": execution[
                    "independently_verified_assignments"
                ],
                "posthoc_comparison": posthoc_comparison,
                "stop_reason": execution["stop_reason"],
                "reader_gate": reader_gate,
            },
            indent=2,
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    main()

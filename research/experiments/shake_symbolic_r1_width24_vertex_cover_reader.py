#!/usr/bin/env python3
"""Assignment-free width-24 SHAKE128 reader from the exact R1 vertex cover.

The retained posthoc frontier motivates depth nine only.  This runner derives
the nine-edge R1 graph again, proves that one endpoint per disjoint edge is a
minimum vertex cover, and freezes a complete 512-subspace schedule without
accepting an instrumented assignment or projection.  Projection values are
ordered by decreasing retained R1 interaction count: fixing a selected factor
to one linearizes its quadratic edge onto the free endpoint, while fixing it to
zero deletes that edge.  Numeric value is only a deterministic tie-break.

Execution stops after a complete wave only when a returned model passes an
independent check of all 1,344 SHAKE128 rate bits.  The result is model finding,
not a global uniqueness certificate and not a blind holdout experiment.
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


_FRONTIER = _import_sibling(
    "shake_symbolic_r1_width24_depth_frontier.py",
    "shake_symbolic_r1_width24_vertex_cover_frontier",
)
_A147 = _import_sibling(
    "shake_symbolic_r1_structural_k8_reader.py",
    "shake_symbolic_r1_width24_vertex_cover_a147",
)

_BASE = _FRONTIER._BASE
_NATIVE = _FRONTIER._NATIVE
_WINDOW = _FRONTIER._WINDOW
_R1 = _FRONTIER._R1
_SMT = _FRONTIER._SMT
_VERIFY = _FRONTIER._VERIFY
_canonical_sha256 = _FRONTIER._canonical_sha256
_render_fixed_coordinates = _FRONTIER._render_fixed_coordinates
_project_assignment = _FRONTIER._project_assignment
_subspace_plan = _A147._subspace_plan
_independent_end_state_check = _A147._independent_end_state_check
_independently_confirmed = _A147._independently_confirmed
_solver_summary = _A147._solver_summary

WIDTH24_FRONTIER_SHA256 = "19a744d90b968589937207eca8d9cd2581960d03c7f7278e5b9b97b28d8b6b84"
WIDTH24_FRONTIER_CAUSAL_SHA256 = "9f6dc8cce28df057aeccc5879848289f734ccba87e9e49278d216011513d9c5f"
A138_JSON_SHA256 = _FRONTIER.A138_JSON_SHA256
UNPARTITIONED_SMT_SHA256 = _FRONTIER.UNPARTITIONED_SMT_SHA256
R1_POLYNOMIAL_STATE_SHA256 = _FRONTIER.R1_POLYNOMIAL_STATE_SHA256
INTERACTION_EDGES_SHA256 = "d804968401d9de6cafe4b605100373dbc9607d5dab811647add969fa94c4fa10"
EXPECTED_SELECTION_SHA256 = "9bc2f302b45e8a35113d7fe66d1a496f31a0e10c9ba59c0e740ebcc3a7bb095a"

WINDOW_BITS = 24
PARTITION_BITS = 9
SEED = 89756046
UNIFORM_TIMEOUT_SECONDS = 120
MAX_PROCESSES = 5
WAVE_SIZE = 5
SOLVER_THREADS_PER_PROCESS = 1
EXPECTED_Z3_VERSION_PREFIX = "Z3 version 4.15.4 "
EXPECTED_COORDINATES = list(range(9))
EXPECTED_EDGES = [tuple(edge) for edge in _FRONTIER.CANONICAL_EDGES]
EXPECTED_ISOLATED = [9, 10, 11, 12, 13, 14]
EXPECTED_EDGE_COUNT = 9
EXPECTED_TIE_COUNT = 512
EXPECTED_VERTEX_COVER_PROOF_SHA256 = (
    "2bc79951111df872df460221eba51a9887621c2171229988fc4c598bb751b0fe"
)
EXPECTED_PLAN_SHA256 = "936464fa99941212353486b1d74e2fbb63beb73b3b1d7698d40a89cf52a089bc"
EXPECTED_SCHEDULE_SHA256 = "4806ef83a5eb53831fdea4cbef5a3d5d91d6d8203470705a2dca977e8786242b"
EXPECTED_COVERAGE_PROOF_SHA256 = "bd1b58174d9f21cf6eacfcc0d8b69b8b41e8244fc36fab1f2d232f9b0d65b476"
EXPECTED_EXECUTION_PHASE_PLAN_SHA256 = (
    "34b3ba9970b9e435e4d7c92c44a58e00aa6668241878c863f3a5d733bb8824c1"
)
EXPECTED_EXECUTION_PHASE_PROOF_SHA256 = (
    "52587815e7300dcbaffa41ed3077cca30b3b6be7086a54b8d40127679c09267a"
)
CLAIM = (
    "The runtime rebuilds the exact minimum vertex cover and complete formula-only "
    "schedule without accepting an instrumented assignment, stored model, or target "
    "projection, and assigns the same resource cap to all 512 planned subspaces; "
    "every attempted value uses that cap. The "
    "mechanism was developed from same-instance A148/A149 observations, so this is "
    "deterministic model finding, not a blind holdout or global uniqueness proof."
)


def _load_frontier_gate(path: Path) -> dict[str, Any]:
    """Hash-gate A148 and expose no assignment or posthoc projection field."""
    raw = path.read_bytes()
    observed = hashlib.sha256(raw).hexdigest()
    if observed != WIDTH24_FRONTIER_SHA256:
        raise RuntimeError(f"width-24 frontier artifact hash differs: {observed}")
    payload = json.loads(raw)
    if payload.get("schema") != "shake-symbolic-r1-width24-depth-frontier-v1":
        raise RuntimeError("width-24 frontier schema differs")
    frontier = payload.get("frontier", {})
    structure = payload.get("structure", {})
    reader_gate = payload.get("reader_gate", {})
    plans = payload.get("unconditioned_depth_plan", [])
    measurements = payload.get("measurements", [])
    k9_plans = [row for row in plans if row.get("depth") == PARTITION_BITS]
    k8_rows = [row for row in measurements if row.get("depth") == 8]
    k9_rows = [row for row in measurements if row.get("depth") == PARTITION_BITS]
    if len(k9_plans) != 1 or len(k8_rows) != 1 or len(k9_rows) != 1:
        raise RuntimeError("width-24 frontier does not contain canonical depth rows")
    k9_plan = k9_plans[0]
    k8 = k8_rows[0]
    k9 = k9_rows[0]
    k9_check = k9.get("independent_end_state_check", {})
    if (
        frontier.get("minimal_depth_with_correctly_confirmed_model") != PARTITION_BITS
        or reader_gate.get("file_sha256") != WIDTH24_FRONTIER_CAUSAL_SHA256
        or k8.get("solver", {}).get("status") != "unknown"
        or k8.get("correctly_confirmed_model") is not False
        or k9.get("solver", {}).get("status") != "sat"
        or k9.get("correctly_confirmed_model") is not True
        or k9_check.get("complete_rate_match") is not True
        or k9_check.get("rate_bits_checked") != 1344
        or structure.get("interaction_edges") != [list(edge) for edge in EXPECTED_EDGES]
        or structure.get("interaction_edges_sha256") != INTERACTION_EDGES_SHA256
        or structure.get("r1_polynomial_state_sha256") != R1_POLYNOMIAL_STATE_SHA256
        or k9_plan.get("selected_coordinates") != EXPECTED_COORDINATES
        or k9_plan.get("maximum_covered_edge_count") != EXPECTED_EDGE_COUNT
        or k9_plan.get("tie_count") != EXPECTED_TIE_COUNT
        or k9_plan.get("selection_sha256") != EXPECTED_SELECTION_SHA256
    ):
        raise RuntimeError("width-24 frontier motivation gate failed")
    return {
        "artifact_sha256": observed,
        "schema": payload["schema"],
        "minimal_posthoc_confirmed_depth": PARTITION_BITS,
        "r1_polynomial_state_sha256": structure["r1_polynomial_state_sha256"],
        "interaction_edges_sha256": structure["interaction_edges_sha256"],
        "edge_count": structure["edge_count"],
        "selected_coordinates": list(k9_plan["selected_coordinates"]),
        "selection_sha256": k9_plan["selection_sha256"],
        "retained_assignment_exposed_to_selection_or_schedule": False,
        "retained_projection_exposed_to_selection_or_schedule": False,
    }


def _derive_assignment_free_selection(
    base_state: Any,
    variant: Any,
    positions: Sequence[int],
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Derive the graph, k9 cover, and exact minimum proof without an assignment."""
    structure, rows = _FRONTIER._derive_graph_and_depths(
        base_state,
        variant,
        positions,
        (PARTITION_BITS,),
    )
    if len(rows) != 1:
        raise RuntimeError("width-24 graph derivation returned more than one selection")
    row = rows[0]
    edges = [tuple(edge) for edge in structure["interaction_edges"]]
    endpoints = [coordinate for edge in edges for coordinate in edge]
    pairwise_disjoint = len(endpoints) == len(set(endpoints)) == 2 * len(edges)
    selected = set(row["selected_coordinates"])
    all_edges_covered = all(left in selected or right in selected for left, right in edges)
    proof_core = {
        "interaction_edges": [list(edge) for edge in edges],
        "edge_count": len(edges),
        "pairwise_disjoint_edges": pairwise_disjoint,
        "distinct_edge_endpoint_count": len(set(endpoints)),
        "lower_bound_from_disjoint_edges": len(edges),
        "selected_coordinates": row["selected_coordinates"],
        "selected_coordinate_count": len(row["selected_coordinates"]),
        "all_edges_covered": all_edges_covered,
        "minimum_vertex_cover_size": len(edges),
        "selected_set_is_minimum_vertex_cover": (
            pairwise_disjoint
            and all_edges_covered
            and len(row["selected_coordinates"]) == len(edges)
        ),
        "minimum_cover_count": 1 << len(edges),
        "enumerated_max_cover_tie_count": row["tie_count"],
        "actual_assignment_used": False,
        "target_end_state_bits_used": False,
        "solver_observations_used": False,
    }
    proof = {**proof_core, "minimum_vertex_cover_proof_sha256": _canonical_sha256(proof_core)}
    selection = {
        **row,
        "window_bits": structure["window_bits"],
        "symbolic_prefix_rounds": structure["symbolic_prefix_rounds"],
        "r1_polynomial_state_sha256": structure["r1_polynomial_state_sha256"],
        "degree_two_monomial_masks": structure["degree_two_monomial_masks"],
        "interaction_edges": structure["interaction_edges"],
        "interaction_edges_sha256": structure["interaction_edges_sha256"],
        "degree_two_edge_count": structure["edge_count"],
        "degree_by_coordinate": structure["degree_by_coordinate"],
        "isolated_coordinates": structure["isolated_coordinates"],
        "components": structure["components"],
        "actual_assignment_used": False,
        "stored_assignment_used": False,
        "posthoc_assignment_used": False,
        "target_end_state_bits_used": False,
        "solver_observations_used": False,
    }
    return selection, proof


def _canonical_selection_gate(selection: dict[str, Any], proof: dict[str, Any]) -> None:
    if (
        selection.get("window_bits") != WINDOW_BITS
        or selection.get("depth") != PARTITION_BITS
        or selection.get("selected_coordinates") != EXPECTED_COORDINATES
        or [tuple(edge) for edge in selection.get("interaction_edges", [])] != EXPECTED_EDGES
        or selection.get("interaction_edges_sha256") != INTERACTION_EDGES_SHA256
        or selection.get("r1_polynomial_state_sha256") != R1_POLYNOMIAL_STATE_SHA256
        or selection.get("isolated_coordinates") != EXPECTED_ISOLATED
        or selection.get("maximum_covered_edge_count") != EXPECTED_EDGE_COUNT
        or selection.get("residual_edges") != []
        or selection.get("tie_count") != EXPECTED_TIE_COUNT
        or selection.get("selection_sha256") != EXPECTED_SELECTION_SHA256
        or proof.get("selected_set_is_minimum_vertex_cover") is not True
        or proof.get("minimum_vertex_cover_size") != PARTITION_BITS
        or proof.get("minimum_cover_count") != EXPECTED_TIE_COUNT
        or proof.get("minimum_vertex_cover_proof_sha256") != EXPECTED_VERTEX_COVER_PROOF_SHA256
    ):
        raise RuntimeError("canonical width-24 minimum vertex cover differs")
    for key in (
        "actual_assignment_used",
        "stored_assignment_used",
        "posthoc_assignment_used",
        "target_end_state_bits_used",
        "solver_observations_used",
    ):
        if selection.get(key) is not False:
            raise RuntimeError(f"canonical selection consumed forbidden input: {key}")


def _interaction_preserving_values(partition_bits: int) -> list[int]:
    """Order the full domain by retained edge count, then numeric value."""
    if partition_bits < 1:
        raise ValueError("partition_bits must be positive")
    return sorted(
        range(1 << partition_bits),
        key=lambda value: (-value.bit_count(), value),
    )


def _wave_value_plan(values: Sequence[int], wave_size: int) -> list[list[int]]:
    ordered = list(values)
    if wave_size < 1:
        raise ValueError("wave size must be positive")
    if len(ordered) != len(set(ordered)):
        raise ValueError("projection schedule contains duplicates")
    return [ordered[start : start + wave_size] for start in range(0, len(ordered), wave_size)]


def _freeze_assignment_free_plan(
    selection: dict[str, Any],
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """Freeze a complete disjoint plan using only the exact selected-edge graph."""
    coordinates = selection.get("selected_coordinates")
    window_bits = selection.get("window_bits")
    edges = [tuple(edge) for edge in selection.get("interaction_edges", [])]
    if not isinstance(coordinates, list) or not isinstance(window_bits, int):
        raise ValueError("selection does not define a coordinate system")
    edge_by_selected_coordinate: dict[int, tuple[int, int]] = {}
    for coordinate in coordinates:
        incident = [edge for edge in edges if coordinate in edge]
        if len(incident) != 1:
            raise RuntimeError("each selected coordinate must hit exactly one disjoint edge")
        edge_by_selected_coordinate[coordinate] = incident[0]

    ascending = _subspace_plan(window_bits, coordinates)
    by_value = {int(row["fixed_value"]): row for row in ascending}
    schedule = _interaction_preserving_values(len(coordinates))
    plan = []
    for schedule_index, value in enumerate(schedule):
        retained = [
            list(edge_by_selected_coordinate[coordinate])
            for bit, coordinate in enumerate(coordinates)
            if (value >> bit) & 1
        ]
        deleted = [
            list(edge_by_selected_coordinate[coordinate])
            for bit, coordinate in enumerate(coordinates)
            if not ((value >> bit) & 1)
        ]
        plan.append(
            {
                **by_value[value],
                "schedule_index": schedule_index,
                "interaction_preservation_score": value.bit_count(),
                "retained_linearized_edges": retained,
                "deleted_quadratic_edges": deleted,
                "schedule_key": [-value.bit_count(), value],
                "runtime_assignment_or_target_projection_input_used": False,
                "historical_instance_results_informed_schedule_hypothesis": True,
                "blind_holdout": False,
            }
        )

    fixed_patterns = [
        tuple((cell["coordinate"], cell["value"]) for cell in row["fixed_coordinates"])
        for row in plan
    ]
    plan_sha256 = _canonical_sha256(plan)
    schedule_core = {
        "ordering": "decreasing_interaction_preservation_score_then_numeric_value",
        "projection_values": schedule,
        "scores": [row["interaction_preservation_score"] for row in plan],
        "selected_coordinates": coordinates,
        "interaction_edges_sha256": selection["interaction_edges_sha256"],
        "fixed_one_semantics": "quadratic_selected_factor_becomes_free_partner",
        "fixed_zero_semantics": "quadratic_edge_term_is_deleted",
        "runtime_assignment_input_used": False,
        "runtime_stored_model_input_used": False,
        "runtime_target_projection_input_used": False,
        "historical_instance_results_informed_schedule_hypothesis": True,
        "blind_holdout": False,
    }
    schedule_proof = {**schedule_core, "schedule_sha256": _canonical_sha256(schedule_core)}
    coverage_core = {
        "projection_value_count": len(schedule),
        "complete_projection_domain": sorted(schedule) == list(range(1 << len(coordinates))),
        "unique_fixed_coordinate_patterns": len(set(fixed_patterns)),
        "pairwise_disjoint_by_unique_fixed_patterns": len(set(fixed_patterns)) == len(plan),
        "free_coordinate_count_per_subspace": window_bits - len(coordinates),
        "logical_assignments_per_subspace": 1 << (window_bits - len(coordinates)),
        "total_logical_assignments": sum(row["logical_assignments"] for row in plan),
        "expected_complete_assignment_space": 1 << window_bits,
        "covers_complete_assignment_space": (
            sum(row["logical_assignments"] for row in plan) == 1 << window_bits
        ),
        "plan_sha256": plan_sha256,
        "schedule_sha256": schedule_proof["schedule_sha256"],
        "runtime_assignment_or_target_projection_input_used": False,
        "historical_instance_results_informed_schedule_hypothesis": True,
        "blind_holdout": False,
    }
    proof = {
        **coverage_core,
        "coverage_proof_sha256": _canonical_sha256(coverage_core),
        "schedule_proof": schedule_proof,
    }
    if (
        [row["fixed_value"] for row in plan] != schedule
        or [row["schedule_index"] for row in plan] != list(range(len(plan)))
        or len(set(fixed_patterns)) != len(plan)
        or not proof["complete_projection_domain"]
        or not proof["covers_complete_assignment_space"]
    ):
        raise RuntimeError("assignment-free width-24 plan is not complete and disjoint")
    return plan, proof


def _canonical_plan_gate(plan: Sequence[dict[str, Any]], proof: dict[str, Any]) -> None:
    values = [row["fixed_value"] for row in plan]
    scores = [row["interaction_preservation_score"] for row in plan]
    if (
        len(plan) != 1 << PARTITION_BITS
        or values != _interaction_preserving_values(PARTITION_BITS)
        or scores != sorted(scores, reverse=True)
        or values[:10] != [511, 255, 383, 447, 479, 495, 503, 507, 509, 510]
        or proof.get("plan_sha256") != EXPECTED_PLAN_SHA256
        or proof.get("schedule_sha256") != EXPECTED_SCHEDULE_SHA256
        or proof.get("coverage_proof_sha256") != EXPECTED_COVERAGE_PROOF_SHA256
    ):
        raise RuntimeError("canonical width-24 interaction-preserving plan differs")


def _freeze_execution_phases(
    plan: Sequence[dict[str, Any]],
    *,
    timeout_seconds: int = UNIFORM_TIMEOUT_SECONDS,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """Freeze one complete uniform-budget phase without runtime target input."""
    rows = list(plan)
    if not rows:
        raise ValueError("execution phase plan cannot be empty")
    if timeout_seconds < 1:
        raise ValueError("uniform timeout must be positive")
    values = [int(row["fixed_value"]) for row in rows]
    if len(values) != len(set(values)):
        raise ValueError("base plan must contain unique projection values")
    phases = [
        {
            "phase_index": 0,
            "name": "complete_uniform",
            "purpose": "one_uniform_budget_over_complete_formula_ranked_domain",
            "plan_slice_start": 0,
            "plan_slice_end_exclusive": len(rows),
            "projection_values": values,
            "projection_value_count": len(values),
            "timeout_seconds_per_subspace": timeout_seconds,
            "maximum_solver_processes": MAX_PROCESSES,
            "wave_size": WAVE_SIZE,
            "runtime_assignment_input_used": False,
            "runtime_stored_model_input_used": False,
            "runtime_target_projection_input_used": False,
            "uniform_budget_assigned_to_every_planned_projection_value": True,
            "historical_a148_a149_results_informed_mechanism_and_budget": True,
            "blind_holdout": False,
        }
    ]
    attempt_counts = {str(value): 1 for value in values}
    phase_plan_sha256 = _canonical_sha256(phases)
    proof_core = {
        "phase_plan_sha256": phase_plan_sha256,
        "phase_names": ["complete_uniform"],
        "uniform_timeout_seconds": timeout_seconds,
        "planned_attempt_count": len(values),
        "base_projection_value_count": len(values),
        "attempt_count_by_projection_value": attempt_counts,
        "every_planned_projection_value_is_assigned_one_uniform_attempt": all(
            count == 1 for count in attempt_counts.values()
        ),
        "complete_formula_ranked_domain_planned": phases[0]["projection_values"] == values,
        "runtime_assignment_input_used": False,
        "runtime_stored_model_input_used": False,
        "runtime_target_projection_input_used": False,
        "historical_a148_a149_results_informed_mechanism_and_budget": True,
        "blind_holdout": False,
    }
    proof = {
        **proof_core,
        "execution_phase_proof_sha256": _canonical_sha256(proof_core),
    }
    if (
        [phase["phase_index"] for phase in phases] != list(range(len(phases)))
        or not proof["every_planned_projection_value_is_assigned_one_uniform_attempt"]
        or not proof["complete_formula_ranked_domain_planned"]
    ):
        raise RuntimeError("assignment-free uniform execution phase proof failed")
    return phases, proof


def _canonical_execution_phase_gate(
    phases: Sequence[dict[str, Any]], proof: dict[str, Any]
) -> None:
    if (
        [phase["name"] for phase in phases] != ["complete_uniform"]
        or [phase["projection_value_count"] for phase in phases] != [512]
        or [phase["timeout_seconds_per_subspace"] for phase in phases] != [120]
        or proof.get("planned_attempt_count") != 512
        or proof.get("phase_plan_sha256") != EXPECTED_EXECUTION_PHASE_PLAN_SHA256
        or proof.get("execution_phase_proof_sha256") != EXPECTED_EXECUTION_PHASE_PROOF_SHA256
    ):
        raise RuntimeError("canonical width-24 execution phase plan differs")


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
    """Execute a frozen schedule prefix in complete concurrent waves."""
    if timeout_seconds < 1 or max_processes < 1 or wave_size < 1:
        raise ValueError("timeout, process count, and wave size must be positive")
    if wave_size > max_processes:
        raise ValueError("wave size cannot exceed the solver-process limit")
    rows = list(plan)
    values = [int(row["fixed_value"]) for row in rows]
    if len(values) != len(set(values)):
        raise ValueError("execution plan contains duplicate projection values")
    planned_waves = _wave_value_plan(values, wave_size)
    work_dir.mkdir(parents=True, exist_ok=True)

    executed_values: list[int] = []
    wave_records: list[dict[str, Any]] = []
    confirmed_rows: list[dict[str, Any]] = []
    all_rows: list[dict[str, Any]] = []

    for wave_index, wave_values in enumerate(planned_waves):
        start = len(executed_values)
        wave_plan = rows[start : start + len(wave_values)]
        if [row["fixed_value"] for row in wave_plan] != wave_values:
            raise RuntimeError("execution wave is not the next frozen schedule prefix")
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
                path = work_dir / (
                    f"wave{wave_index:03d}_rank{row['schedule_index']:03d}_"
                    f"subspace{row['fixed_value']:03d}.smt2"
                )
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

            with concurrent.futures.ThreadPoolExecutor(max_workers=max_processes) as executor:
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

        status_counts = {
            status: sum(row["solver"]["status"] == status for row in wave_results)
            for status in ("sat", "unsat", "unknown", "error")
        }
        confirmed_values = [
            row["fixed_value"] for row in wave_results if row["independently_confirmed_model"]
        ]
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
                "independently_confirmed_projection_values": confirmed_values,
                "smt_files_generated_only_for_this_wave": True,
                "smt_files_removed_after_wave": True,
                "stop_after_wave": bool(confirmed_values),
            }
        )
        if confirmed_values:
            break

    first_confirmed = confirmed_rows[0] if confirmed_rows else None
    found_rows = [row for row in all_rows if row["assignment"] is not None]
    status_counts = {
        status: sum(row["solver"]["status"] == status for row in all_rows)
        for status in ("sat", "unsat", "unknown", "error")
    }
    return {
        "planned_projection_values": values,
        "planned_waves": planned_waves,
        "executed_projection_values": executed_values,
        "executed_wave_count": len(wave_records),
        "waves": wave_records,
        "status_counts": status_counts,
        "found_assignments": [row["assignment"] for row in found_rows],
        "independently_verified_assignments": [row["assignment"] for row in confirmed_rows],
        "independently_confirmed_projection_values": [row["fixed_value"] for row in confirmed_rows],
        "reconstructed_assignment": (
            first_confirmed["assignment"] if first_confirmed is not None else None
        ),
        "stop_reason": (
            "independently_confirmed_model_found_after_complete_wave"
            if first_confirmed is not None
            else f"complete_{len(values)}_value_plan_exhausted_without_confirmed_model"
        ),
        "stopped_only_after_independent_complete_check": first_confirmed is not None,
        "all_returned_assignments_independently_checked": all(
            row["independent_end_state_check"].get("performed") is True for row in found_rows
        ),
        "all_found_assignments_independently_verified": len(found_rows) == len(confirmed_rows),
        "all_executed_values_form_exact_schedule_prefix": (
            executed_values == values[: len(executed_values)]
        ),
        "future_values_omitted_only_by_verified_early_stop": (
            len(executed_values) == len(values) or first_confirmed is not None
        ),
        "interaction_preservation_order_used": True,
        "runtime_assignment_or_target_projection_input_used": False,
        "historical_instance_results_informed_schedule_hypothesis": True,
        "blind_holdout": False,
        "timeout_seconds_per_subspace": timeout_seconds,
        "maximum_solver_processes": max_processes,
        "wave_size": wave_size,
        "solver_threads_per_process": SOLVER_THREADS_PER_PROCESS,
        "model_finding_not_global_uniqueness_certificate": True,
    }


def _execution_gate(execution: dict[str, Any], plan: Sequence[dict[str, Any]]) -> None:
    planned = [row["fixed_value"] for row in plan]
    executed = execution.get("executed_projection_values")
    waves = execution.get("waves")
    verified = execution.get("independently_verified_assignments")
    if (
        execution.get("planned_projection_values") != planned
        or executed != planned[: len(executed)]
        or execution.get("all_executed_values_form_exact_schedule_prefix") is not True
        or execution.get("future_values_omitted_only_by_verified_early_stop") is not True
        or not isinstance(waves, list)
        or not isinstance(verified, list)
    ):
        raise RuntimeError("deterministic width-24 execution-prefix gate failed")
    flattened = [value for wave in waves for value in wave["executed_projection_values"]]
    if flattened != executed:
        raise RuntimeError("width-24 wave details differ from execution prefix")
    for wave_index, wave in enumerate(waves):
        confirmed = wave.get("independently_confirmed_projection_values", [])
        if wave.get("wave_index") != wave_index:
            raise RuntimeError("width-24 wave indices are not contiguous")
        if wave.get("stop_after_wave") is not bool(confirmed):
            raise RuntimeError("width-24 wave stop flag differs from independent checks")
        if wave.get("all_sat_assignments_independently_checked") is not True:
            raise RuntimeError("width-24 SAT result lacks an independent check")
        if confirmed and wave_index != len(waves) - 1:
            raise RuntimeError("width-24 execution continued after a confirmed model")
    if execution.get("reconstructed_assignment") is not None:
        if (
            not verified
            or execution.get("stopped_only_after_independent_complete_check") is not True
        ):
            raise RuntimeError("width-24 execution stopped without an independently verified model")
    elif len(executed) != len(planned):
        raise RuntimeError("width-24 execution stopped early without a verified model")


def _execute_assignment_free_phases(
    *,
    plan: Sequence[dict[str, Any]],
    phases: Sequence[dict[str, Any]],
    coordinates: Sequence[int],
    writer: Any,
    inputs: list[str],
    problem: dict[str, Any],
    variant: Any,
    z3: Path,
    work_dir: Path,
    run_solver: Callable[[Path, Path, int, list[str]], dict[str, Any]] = _SMT._run_z3,
    verify_assignment: Callable[[dict[str, Any], Any, int], dict[str, Any]] = _VERIFY,
) -> dict[str, Any]:
    """Run the frozen phase prefix and stop only after an independent check."""
    rows = list(plan)
    by_value = {int(row["fixed_value"]): row for row in rows}
    if len(by_value) != len(rows):
        raise ValueError("base phase plan contains duplicate projection values")
    phase_records = []
    attempted_values: list[int] = []
    found_assignments: list[int] = []
    confirmed_assignments: list[int] = []
    confirmed_values: list[int] = []
    reconstructed: int | None = None

    for expected_index, phase in enumerate(phases):
        if phase.get("phase_index") != expected_index:
            raise RuntimeError("execution phase indices are not contiguous")
        phase_values = [int(value) for value in phase["projection_values"]]
        try:
            phase_plan = [by_value[value] for value in phase_values]
        except KeyError as error:
            raise RuntimeError("execution phase references an unknown projection value") from error
        phase_execution = _execute_assignment_free_waves(
            plan=phase_plan,
            coordinates=coordinates,
            writer=writer,
            inputs=inputs,
            problem=problem,
            variant=variant,
            z3=z3,
            work_dir=work_dir / f"phase{expected_index:02d}_{phase['name']}",
            timeout_seconds=int(phase["timeout_seconds_per_subspace"]),
            max_processes=int(phase["maximum_solver_processes"]),
            wave_size=int(phase["wave_size"]),
            run_solver=run_solver,
            verify_assignment=verify_assignment,
        )
        record = {**phase, "execution": phase_execution}
        phase_records.append(record)
        attempted_values.extend(phase_execution["executed_projection_values"])
        found_assignments.extend(phase_execution["found_assignments"])
        confirmed_assignments.extend(phase_execution["independently_verified_assignments"])
        confirmed_values.extend(phase_execution["independently_confirmed_projection_values"])
        if phase_execution["reconstructed_assignment"] is not None:
            reconstructed = int(phase_execution["reconstructed_assignment"])
            break

    status_counts = {
        status: sum(record["execution"]["status_counts"][status] for record in phase_records)
        for status in ("sat", "unsat", "unknown", "error")
    }
    unique_attempted_values = list(dict.fromkeys(attempted_values))
    return {
        "planned_phases": list(phases),
        "executed_phases": phase_records,
        "executed_phase_count": len(phase_records),
        "attempted_projection_values": attempted_values,
        "attempt_count": len(attempted_values),
        "unique_attempted_projection_values": unique_attempted_values,
        "unique_attempted_projection_value_count": len(unique_attempted_values),
        "status_counts": status_counts,
        "found_assignments": found_assignments,
        "independently_verified_assignments": confirmed_assignments,
        "independently_confirmed_projection_values": confirmed_values,
        "reconstructed_assignment": reconstructed,
        "stop_reason": (
            "independently_confirmed_model_found_after_complete_phase_wave"
            if reconstructed is not None
            else "complete_uniform_phase_exhausted_without_confirmed_model"
        ),
        "stopped_only_after_independent_complete_check": reconstructed is not None,
        "all_returned_assignments_independently_checked": all(
            record["execution"]["all_returned_assignments_independently_checked"]
            for record in phase_records
        ),
        "all_found_assignments_independently_verified": all(
            record["execution"]["all_found_assignments_independently_verified"]
            for record in phase_records
        ),
        "all_executed_phases_form_exact_phase_prefix": (
            [record["name"] for record in phase_records]
            == [phase["name"] for phase in phases[: len(phase_records)]]
        ),
        "future_phases_omitted_only_by_verified_early_stop": (
            len(phase_records) == len(phases) or reconstructed is not None
        ),
        "interaction_preservation_order_used": True,
        "uniform_budget_assigned_to_every_planned_projection_value": True,
        "all_attempted_projection_values_use_the_assigned_uniform_budget": True,
        "runtime_target_projection_input_used": False,
        "runtime_stored_assignment_input_used": False,
        "historical_a148_a149_results_informed_mechanism_and_budget": True,
        "blind_holdout": False,
        "model_finding_not_global_uniqueness_certificate": True,
    }


def _phased_execution_gate(
    execution: dict[str, Any],
    plan: Sequence[dict[str, Any]],
    phases: Sequence[dict[str, Any]],
) -> None:
    planned_phases = list(phases)
    records = execution.get("executed_phases")
    if (
        execution.get("planned_phases") != planned_phases
        or not isinstance(records, list)
        or execution.get("executed_phase_count") != len(records)
        or execution.get("all_executed_phases_form_exact_phase_prefix") is not True
        or execution.get("future_phases_omitted_only_by_verified_early_stop") is not True
    ):
        raise RuntimeError("deterministic width-24 phase-prefix gate failed")
    by_value = {int(row["fixed_value"]): row for row in plan}
    attempted = []
    for index, record in enumerate(records):
        phase = planned_phases[index]
        for key, value in phase.items():
            if record.get(key) != value:
                raise RuntimeError(f"executed phase metadata differs: {key}")
        phase_plan = [by_value[int(value)] for value in phase["projection_values"]]
        _execution_gate(record["execution"], phase_plan)
        attempted.extend(record["execution"]["executed_projection_values"])
        if (
            record["execution"]["reconstructed_assignment"] is not None
            and index != len(records) - 1
        ):
            raise RuntimeError("phase execution continued after a confirmed model")
    if attempted != execution.get("attempted_projection_values"):
        raise RuntimeError("phase attempt list differs from nested wave executions")
    reconstructed = execution.get("reconstructed_assignment")
    if reconstructed is not None:
        if (
            not records
            or records[-1]["execution"]["reconstructed_assignment"] != reconstructed
            or execution.get("stopped_only_after_independent_complete_check") is not True
        ):
            raise RuntimeError("phase execution stopped without an independently checked model")
    elif len(records) != len(planned_phases):
        raise RuntimeError("phase execution stopped early without a confirmed model")


def _build_graph(
    path: Path,
    selection: dict[str, Any],
    vertex_cover_proof: dict[str, Any],
    plan: Sequence[dict[str, Any]],
    plan_proof: dict[str, Any],
    phases: Sequence[dict[str, Any]],
    phase_proof: dict[str, Any],
    execution: dict[str, Any],
) -> tuple[dict[str, Any], list[dict[str, Any]], dict[str, Any]]:
    _phased_execution_gate(execution, plan, phases)
    builder = CryptoCausalBuilder(
        experiment="shake_symbolic_r1_width24_vertex_cover_reader",
        parameters={
            "variant": "shake128",
            "window_bits": WINDOW_BITS,
            "partition_bits": PARTITION_BITS,
            "partitioned_coordinates": selection["selected_coordinates"],
            "uniform_timeout_seconds_per_subspace": UNIFORM_TIMEOUT_SECONDS,
            "maximum_solver_processes": MAX_PROCESSES,
            "wave_size": WAVE_SIZE,
            "model_finding_not_global_uniqueness_certificate": True,
        },
    )
    graph_id = "shake128-r1-width24-exact-disjoint-interaction-graph"
    cover_id = "shake128-r1-width24-minimum-vertex-cover"
    plan_id = "shake128-r1-width24-complete-interaction-preserving-plan"
    execution_id = "shake128-r1-width24-assignment-free-wave-execution"
    builder.add_triplet(
        edge_id=graph_id,
        trigger="shake128:width24_exact_R1_prefix_polynomial_state",
        mechanism="extract_unique_degree_2_monomials_as_variable_edges",
        outcome="shake128:width24_nine_disjoint_R1_interaction_edges",
        confidence=1.0,
        evidence_kind="exact_symbolic_formula_graph",
        source="direct_R1_boolean_ring_compiler",
        attrs={
            "r1_polynomial_state_sha256": selection["r1_polynomial_state_sha256"],
            "degree_two_monomial_masks": selection["degree_two_monomial_masks"],
            "interaction_edges": selection["interaction_edges"],
            "interaction_edges_sha256": selection["interaction_edges_sha256"],
        },
    )
    builder.add_triplet(
        edge_id=cover_id,
        trigger="shake128:width24_nine_disjoint_R1_interaction_edges",
        mechanism="prove_lower_bound_from_disjoint_edges_and_exhibit_size_9_cover",
        outcome="shake128:width24_exact_minimum_R1_vertex_cover",
        confidence=1.0,
        evidence_kind="finite_graph_minimum_vertex_cover_certificate",
        source="reader_local_exact_graph_proof",
        provenance=[graph_id],
        attrs=vertex_cover_proof,
    )
    builder.add_triplet(
        edge_id=plan_id,
        trigger="shake128:width24_exact_minimum_R1_vertex_cover",
        mechanism=(
            "enumerate_all_512_values_by_decreasing_retained_linearized_R1_edges_"
            "then_numeric_tie_break_and_prove_complete_disjoint_coverage"
        ),
        outcome="shake128:width24_complete_assignment_free_schedule",
        confidence=1.0,
        evidence_kind="deterministic_formula_only_schedule_and_coverage_proof",
        source="reader_local_vertex_cover_schedule",
        provenance=[cover_id],
        attrs={
            "selected_coordinates": selection["selected_coordinates"],
            "plan_sha256": plan_proof["plan_sha256"],
            "coverage_proof_sha256": plan_proof["coverage_proof_sha256"],
            "schedule_proof": plan_proof["schedule_proof"],
            "planned_projection_values": [row["fixed_value"] for row in plan],
            "execution_phases": list(phases),
            "execution_phase_proof": phase_proof,
            "runtime_assignment_or_projection_input_used": False,
            "historical_instance_results_informed_mechanism": True,
            "blind_holdout": False,
        },
    )
    candidate_checks = [
        {
            "phase": phase_record["name"],
            "timeout_seconds_per_subspace": phase_record["timeout_seconds_per_subspace"],
            "projection_value": row["fixed_value"],
            "assignment": row["assignment"],
            "independent_end_state_check": row["independent_end_state_check"],
        }
        for phase_record in execution["executed_phases"]
        for wave in phase_record["execution"]["waves"]
        for row in wave["subspaces"]
        if row["assignment"] is not None
    ]
    builder.add_triplet(
        edge_id=execution_id,
        trigger="shake128:width24_complete_assignment_free_schedule",
        mechanism=(
            "execute_one_uniform_120_second_budget_over_the_complete_formula_"
            "ranked_domain_check_every_returned_model_against_all_1344_rate_"
            "bits_and_stop_only_after_a_complete_wave"
        ),
        outcome="shake128:width24_independently_checked_model_finding_observations",
        confidence=1.0,
        evidence_kind="bounded_solver_observations_and_complete_independent_checks",
        source="Z3_Boolean_SMT_plus_independent_single_candidate_NumPy_lane_core",
        provenance=[plan_id],
        attrs={
            "executed_phase_names": [record["name"] for record in execution["executed_phases"]],
            "attempted_projection_values": execution["attempted_projection_values"],
            "attempt_count": execution["attempt_count"],
            "status_counts": execution["status_counts"],
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
    ids = [graph_id, cover_id, plan_id, execution_id]
    passed = (
        reader.verify_provenance()
        and len(rows) == 4
        and set(by_id) == set(ids)
        and by_id[cover_id]["provenance"] == [graph_id]
        and by_id[plan_id]["provenance"] == [cover_id]
        and by_id[execution_id]["provenance"] == [plan_id]
        and all(
            by_id[left]["outcome"] == by_id[right]["trigger"]
            for left, right in zip(ids[:-1], ids[1:], strict=True)
        )
        and by_id[plan_id]["attrs"]["runtime_assignment_or_projection_input_used"] is False
        and by_id[plan_id]["attrs"]["historical_instance_results_informed_mechanism"] is True
    )
    if not passed:
        raise RuntimeError("width-24 vertex-cover causal reader gate failed")
    gate = {
        "passed": True,
        "explicit_triplet_count": 4,
        "exact_four_edge_chain": True,
        "provenance_verified": True,
        "interaction_edges_sha256": selection["interaction_edges_sha256"],
        "selection_sha256": selection["selection_sha256"],
        "minimum_vertex_cover_proof_sha256": vertex_cover_proof[
            "minimum_vertex_cover_proof_sha256"
        ],
        "plan_sha256": plan_proof["plan_sha256"],
        "schedule_sha256": plan_proof["schedule_sha256"],
        "coverage_proof_sha256": plan_proof["coverage_proof_sha256"],
        "execution_phase_plan_sha256": phase_proof["phase_plan_sha256"],
        "execution_phase_proof_sha256": phase_proof["execution_phase_proof_sha256"],
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
        "--frontier",
        type=Path,
        default=Path("research/results/v1/shake_symbolic_r1_width24_depth_frontier_v1.json"),
    )
    parser.add_argument(
        "--a138",
        type=Path,
        default=Path("research/results/v1/shake_symbolic_r1_scaling_reader_v1.json"),
    )
    parser.add_argument(
        "--work-dir",
        type=Path,
        default=Path("build/shake-symbolic-r1-width24-vertex-cover-reader"),
    )
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--causal-output", type=Path, required=True)
    args = parser.parse_args()

    frontier_gate = _load_frontier_gate(args.frontier)
    retained = _FRONTIER._load_a138_width24_gate(args.a138)
    if retained["encoding"]["first_smt_sha256"] != UNPARTITIONED_SMT_SHA256:
        raise RuntimeError("A138 width-24 SMT gate differs")
    z3 = Path(shutil.which(str(args.z3)) or args.z3)
    if not z3.is_file():
        raise FileNotFoundError(f"Z3 executable not found: {args.z3}")
    solver_version = subprocess.run(
        [str(z3), "-version"], check=True, capture_output=True, text=True
    ).stdout.strip()
    if not solver_version.startswith(EXPECTED_Z3_VERSION_PREFIX):
        raise RuntimeError(f"Z3 CLI version differs; expected 4.15.4, observed: {solver_version}")

    variant = _BASE.VARIANTS["shake128"]
    problem = _NATIVE._problem(variant, WINDOW_BITS, SEED)

    # The selection and full schedule are frozen before any instrumented
    # assignment or projection is extracted.
    selection, vertex_cover_proof = _derive_assignment_free_selection(
        problem["base_state"], variant, problem["positions"]
    )
    _canonical_selection_gate(selection, vertex_cover_proof)
    plan, plan_proof = _freeze_assignment_free_plan(selection)
    _canonical_plan_gate(plan, plan_proof)
    phases, phase_proof = _freeze_execution_phases(plan)
    _canonical_execution_phase_gate(phases, phase_proof)

    writer, inputs, encoding = _R1._SPLIT._encode_problem(problem, variant, SEED, prefix_rounds=1)
    unpartitioned_raw = writer.render(inputs, include_model=True)
    regenerated_smt_sha256 = hashlib.sha256(unpartitioned_raw).hexdigest()
    if regenerated_smt_sha256 != UNPARTITIONED_SMT_SHA256:
        raise RuntimeError("regenerated width-24 R1 SMT differs from A138")

    execution = _execute_assignment_free_phases(
        plan=plan,
        phases=phases,
        coordinates=selection["selected_coordinates"],
        writer=writer,
        inputs=inputs,
        problem=problem,
        variant=variant,
        z3=z3,
        work_dir=args.work_dir,
    )
    _phased_execution_gate(execution, plan, phases)

    # This comparison is deliberately first performed after execution ended.
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
        "instrumented_projection_schedule_index": [row["fixed_value"] for row in plan].index(
            instrumented_projection
        ),
        "reconstructed_assignment": reconstructed,
        "reconstruction_matches_instrumented_assignment": (
            reconstructed == instrumented_assignment if reconstructed is not None else False
        ),
        "instrumented_assignment_used_for_selection": False,
        "instrumented_assignment_used_for_schedule": False,
        "instrumented_projection_used_for_execution_order": False,
        "historical_instance_results_informed_mechanism_and_budget": True,
        "blind_holdout": False,
    }

    causal, triplets, reader_gate = _build_graph(
        args.causal_output,
        selection,
        vertex_cover_proof,
        plan,
        plan_proof,
        phases,
        phase_proof,
        execution,
    )
    payload = {
        "schema": "shake-symbolic-r1-width24-vertex-cover-reader-v1",
        "evidence_stage": "ASSIGNMENT_FREE_WIDTH24_VERTEX_COVER_MODEL_SEARCH_COMPLETED",
        "result": (
            "The exact R1 minimum vertex cover froze a complete interaction-preserving "
            "512-subspace runtime schedule without accepting an assignment or target "
            "projection. Every attempted subspace used the assigned uniform 120-second "
            "cap, and execution stopped only after a solver model passed the independent "
            "complete 1,344-bit check."
            if reconstructed is not None
            else "The complete assignment-free width-24 schedule was exhausted without "
            "an independently confirmed model."
        ),
        "scope": (
            "One hash-gated SHAKE128 width-24 seed-89756046 R1 Boolean transform "
            "constraint system and its exact nine-edge prefix interaction graph."
        ),
        "claim": CLAIM,
        "parameters": {
            "solver": solver_version,
            "window_bits": WINDOW_BITS,
            "partition_bits": PARTITION_BITS,
            "seed": SEED,
            "symbolic_prefix_rounds": 1,
            "uniform_timeout_seconds_per_subspace": UNIFORM_TIMEOUT_SECONDS,
            "maximum_solver_processes": MAX_PROCESSES,
            "wave_size": WAVE_SIZE,
            "solver_threads_per_process": SOLVER_THREADS_PER_PROCESS,
            "width24_frontier_sha256": WIDTH24_FRONTIER_SHA256,
            "a138_json_sha256": A138_JSON_SHA256,
            "unpartitioned_smt_sha256": UNPARTITIONED_SMT_SHA256,
            "selection_and_schedule_completed_before_instrumented_extraction": True,
            "runtime_assignment_or_target_projection_input_used": False,
            "historical_a148_a149_results_informed_mechanism_and_budget": True,
            "not_a_blind_holdout": True,
            "model_finding_not_global_uniqueness_certificate": True,
        },
        "frontier_gate": frontier_gate,
        "selection": selection,
        "minimum_vertex_cover_proof": vertex_cover_proof,
        "assignment_free_plan": {
            "plan_sha256": plan_proof["plan_sha256"],
            "coverage_proof": plan_proof,
            "subspaces": plan,
            "planned_projection_values": [row["fixed_value"] for row in plan],
            "planned_waves": _wave_value_plan([row["fixed_value"] for row in plan], WAVE_SIZE),
        },
        "assignment_free_execution_phase_plan": {
            "phase_plan_sha256": phase_proof["phase_plan_sha256"],
            "execution_phase_proof": phase_proof,
            "phases": phases,
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
    print(
        json.dumps(
            {
                "output": str(args.output),
                "sha256": hashlib.sha256(raw).hexdigest(),
                "causal_output": str(args.causal_output),
                "causal_sha256": reader_gate["file_sha256"],
                "graph_sha256": reader_gate["graph_sha256"],
                "selected_coordinates": selection["selected_coordinates"],
                "minimum_vertex_cover_size": vertex_cover_proof["minimum_vertex_cover_size"],
                "plan_sha256": plan_proof["plan_sha256"],
                "schedule_sha256": plan_proof["schedule_sha256"],
                "coverage_proof_sha256": plan_proof["coverage_proof_sha256"],
                "execution_phase_plan_sha256": phase_proof["phase_plan_sha256"],
                "executed_phase_names": [record["name"] for record in execution["executed_phases"]],
                "attempted_projection_values": execution["attempted_projection_values"],
                "attempt_count": execution["attempt_count"],
                "status_counts": execution["status_counts"],
                "reconstructed_assignment": reconstructed,
                "posthoc_comparison": posthoc_comparison,
                "reader_gate": reader_gate,
            },
            indent=2,
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    main()

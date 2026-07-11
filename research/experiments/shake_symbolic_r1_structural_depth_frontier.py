#!/usr/bin/env python3
"""Measure a posthoc-conditioned R1 structural-depth mechanism frontier."""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import shutil
import subprocess
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


_A141 = _import_sibling(
    "shake_symbolic_r1_structural_partition_reader.py",
    "shake_symbolic_r1_structural_partition_reader_depth_frontier_base",
)
_A143 = _import_sibling(
    "shake_symbolic_r1_structural6_partition_reader.py",
    "shake_symbolic_r1_structural6_partition_reader_depth_frontier_gate",
)

_UPPER = _A141._UPPER
_R1 = _A141._R1
_BASE = _A141._BASE
_NATIVE = _A141._NATIVE
_WINDOW = _A141._WINDOW
_SMT = _A141._SMT
_VERIFY = _UPPER._R2._verify_assignment

_canonical_sha256 = _A141._canonical_sha256
_degree_two_monomial_edges = _A141._degree_two_monomial_edges
_max_cover_selection = _A141._max_cover_selection
_structural_selection_from_polynomials = _A141._structural_selection_from_polynomials
_render_fixed_coordinates = _UPPER._render_fixed_coordinates
_project_assignment = _UPPER._project_assignment

A138_JSON_SHA256 = _A141.A138_SHA256
A141_SHA256 = "0a06caf3a2077f2a0408f7d299eb4fd3e5e6204dd66129d969f347637b823171"
A143_SHA256 = "f39309d81d31d4b0615c6fbbd3676eadd53fa15ecf5c9e3ad34d7f5f79112f3d"
UNPARTITIONED_SMT_SHA256 = (
    "66aa82020b4dd2b4d21f3065c99ca6f7c9224ab1ab9765f686121f2fe7f8618f"
)
WINDOW_BITS = 20
SEED = 89755037
DEPTHS = (4, 6, 8, 10)
TIMEOUT_SECONDS = 60
SOLVER_THREADS = 1
CANONICAL_ASSIGNMENT = 227581
CANONICAL_EDGE_COUNT = 28
INTERACTION_EDGES_SHA256 = (
    "06b168eb69c5a6687e0f7f001bfdf178ce24e28b2b312a84758bfe872d1b9bda"
)
R1_POLYNOMIAL_STATE_SHA256 = (
    "b06bab2ca328e7f8521d339e0a86a62a7dfbddc38048388a0dd9285fbe936f1d"
)
PURPOSE = "posthoc_conditioned_mechanism_frontier_not_autonomous_search"
CLAIM = (
    "This is a posthoc-conditioned mechanism frontier over a deterministic "
    "formula-graph depth sequence; it is not an autonomous search and not an "
    "assignment-free recovery result."
)

EXPECTED_COORDINATES = {
    4: [4, 9, 17, 18],
    6: [4, 9, 12, 15, 17, 18],
    8: [1, 2, 4, 9, 10, 12, 15, 18],
    10: [1, 2, 4, 7, 9, 10, 12, 15, 17, 18],
}
EXPECTED_COVERAGE = {4: 14, 6: 20, 8: 24, 10: 28}
EXPECTED_TIE_COUNTS = {4: 14, 6: 1, 8: 10, 10: 1}
EXPECTED_MAXIMIZERS = {
    4: [
        [4, 9, 17, 18],
        [4, 12, 17, 18],
        [4, 15, 17, 18],
        [4, 16, 17, 18],
        [8, 9, 17, 18],
        [8, 16, 17, 18],
        [8, 17, 18, 19],
        [9, 12, 17, 18],
        [9, 15, 17, 18],
        [9, 17, 18, 19],
        [12, 15, 17, 18],
        [15, 16, 17, 18],
        [15, 17, 18, 19],
        [16, 17, 18, 19],
    ],
    6: [[4, 9, 12, 15, 17, 18]],
    8: [
        [1, 2, 4, 9, 10, 12, 15, 18],
        [1, 2, 4, 9, 12, 15, 17, 18],
        [1, 4, 6, 9, 12, 15, 17, 18],
        [1, 4, 7, 9, 12, 15, 17, 18],
        [1, 4, 9, 10, 12, 15, 17, 18],
        [2, 4, 7, 9, 10, 12, 15, 18],
        [2, 4, 7, 9, 12, 15, 17, 18],
        [2, 4, 9, 10, 12, 15, 17, 18],
        [4, 6, 7, 9, 12, 15, 17, 18],
        [4, 7, 9, 10, 12, 15, 17, 18],
    ],
    10: [[1, 2, 4, 7, 9, 10, 12, 15, 17, 18]],
}


def _load_hashed_json(path: Path, expected_sha256: str, label: str) -> dict[str, Any]:
    raw = path.read_bytes()
    observed = hashlib.sha256(raw).hexdigest()
    if observed != expected_sha256:
        raise RuntimeError(f"{label} retained artifact hash differs for {path}: {observed}")
    payload = json.loads(raw)
    if not isinstance(payload, dict):
        raise RuntimeError(f"{label} retained artifact is not a JSON object")
    return payload


def _load_a138_gate(path: Path) -> dict[str, Any]:
    trial = _A141._load_a138_gate(path)
    if (
        trial.get("window_bits") != WINDOW_BITS
        or trial.get("seed") != SEED
        or trial.get("first_solver", {}).get("status") != "unknown"
        or trial.get("reconstructed_assignment") is not None
        or trial.get("encoding", {}).get("first_smt_sha256")
        != UNPARTITIONED_SMT_SHA256
    ):
        raise RuntimeError("A138 canonical width-20 unknown-SMT gate failed")
    return trial


def _a141_reuse_row(payload: dict[str, Any]) -> dict[str, Any]:
    if payload.get("schema") != "shake-symbolic-r1-structural-partition-reader-v1":
        raise RuntimeError("A141 schema does not identify the retained Structural-4 run")
    selection = payload.get("selection")
    trial = payload.get("trial")
    if not isinstance(selection, dict) or not isinstance(trial, dict):
        raise RuntimeError("A141 does not contain its retained selection and trial")
    _A141._neutral_partition_gate(
        trial,
        label="A141",
        expected_coordinates=EXPECTED_COORDINATES[4],
    )
    if trial.get("structural_selection") != selection:
        raise RuntimeError("A141 trial and selection records differ")
    if (
        selection.get("selected_coordinates") != EXPECTED_COORDINATES[4]
        or selection.get("maximum_covered_edge_count") != EXPECTED_COVERAGE[4]
        or selection.get("tie_count") != EXPECTED_TIE_COUNTS[4]
        or selection.get("maximizing_coordinate_sets") != EXPECTED_MAXIMIZERS[4]
        or trial.get("actual_assignment_posthoc") != CANONICAL_ASSIGNMENT
        or trial.get("actual_fixed_value_posthoc")
        != _project_assignment(CANONICAL_ASSIGNMENT, EXPECTED_COORDINATES[4])
        or trial.get("timeout_seconds_per_subspace") != TIMEOUT_SECONDS
        or trial.get("solver_threads_per_worker") != SOLVER_THREADS
    ):
        raise RuntimeError("A141 retained Structural-4 reuse gate failed")
    matches = [
        row
        for row in trial["subspaces_detail"]
        if row.get("fixed_value") == trial["actual_fixed_value_posthoc"]
    ]
    if len(matches) != 1:
        raise RuntimeError("A141 must contain exactly one actual Structural-4 subspace")
    row = matches[0]
    if (
        row.get("solver", {}).get("status") != "unknown"
        or row.get("solver", {}).get("command_parameters", {}).get("timeout_seconds")
        != TIMEOUT_SECONDS
        or row.get("solver", {}).get("command_parameters", {}).get("threads")
        != SOLVER_THREADS
        or row.get("assignment") is not None
        or row.get("independent_verification") is not None
    ):
        raise RuntimeError("A141 actual Structural-4 subspace is not reusable")
    return row


def _load_a141_gate(path: Path) -> dict[str, Any]:
    payload = _load_hashed_json(path, A141_SHA256, "A141")
    _a141_reuse_row(payload)
    return payload


def _load_a143_gate(path: Path) -> dict[str, Any]:
    payload = _load_hashed_json(path, A143_SHA256, "A143")
    if payload.get("schema") != "shake-symbolic-r1-structural6-partition-reader-v1":
        raise RuntimeError("A143 schema does not identify the retained Structural-6 run")
    selection = payload.get("selection")
    trial = payload.get("trial")
    if not isinstance(selection, dict) or not isinstance(trial, dict):
        raise RuntimeError("A143 does not contain its retained selection and trial")
    rows = trial.get("subspaces_detail")
    expected_counts = {"sat": 0, "unsat": 0, "unknown": 64, "error": 0}
    if (
        selection.get("selected_coordinates") != EXPECTED_COORDINATES[6]
        or selection.get("maximum_covered_edge_count") != EXPECTED_COVERAGE[6]
        or selection.get("tie_count") != EXPECTED_TIE_COUNTS[6]
        or selection.get("maximizing_coordinate_sets") != EXPECTED_MAXIMIZERS[6]
        or trial.get("structural_selection") != selection
        or trial.get("window_bits") != WINDOW_BITS
        or trial.get("seed") != SEED
        or trial.get("partitioned_coordinates") != EXPECTED_COORDINATES[6]
        or trial.get("status_counts") != expected_counts
        or not isinstance(rows, list)
        or len(rows) != 64
        or trial.get("timeout_seconds_per_subspace") != 30
        or trial.get("solver_threads_per_worker") != SOLVER_THREADS
        or trial.get("encoding", {}).get("unpartitioned_smt_sha256")
        != UNPARTITIONED_SMT_SHA256
    ):
        raise RuntimeError("A143 retained Structural-6 hash/status gate failed")
    if any(
        row.get("subspace_index") != index
        or row.get("solver", {}).get("status") != "unknown"
        or row.get("assignment") is not None
        or row.get("independent_verification") is not None
        for index, row in enumerate(rows)
    ):
        raise RuntimeError("A143 retained Structural-6 rows differ")
    return payload


def _derive_depth_sequence(
    base_state: Any,
    variant: Any,
    positions: Sequence[int],
    depths: Sequence[int],
) -> list[dict[str, Any]]:
    """Derive every coordinate set before accepting any assignment or branch value."""
    ordered_depths = list(depths)
    if not ordered_depths or ordered_depths != sorted(set(ordered_depths)):
        raise ValueError("depths must be unique and strictly ascending")
    window_bits = len(positions)
    if any(depth < 1 or depth >= window_bits for depth in ordered_depths):
        raise ValueError("each depth must lie in 1..window_bits-1")
    template = _WINDOW._clear_window(base_state, variant, positions)
    polynomials = _R1._SPLIT._symbolic_prefix_polynomials(
        template,
        variant,
        positions,
        prefix_rounds=1,
    )
    return [
        _structural_selection_from_polynomials(polynomials, window_bits, depth)
        for depth in ordered_depths
    ]


def _canonical_depth_sequence_gate(selections: Sequence[dict[str, Any]]) -> None:
    if [row.get("partition_bits") for row in selections] != list(DEPTHS):
        raise RuntimeError("canonical depth sequence differs")
    edge_hashes = {row.get("interaction_edges_sha256") for row in selections}
    polynomial_hashes = {row.get("r1_polynomial_state_sha256") for row in selections}
    if edge_hashes != {INTERACTION_EDGES_SHA256}:
        raise RuntimeError("canonical depth sequence interaction graph differs")
    if polynomial_hashes != {R1_POLYNOMIAL_STATE_SHA256}:
        raise RuntimeError("canonical depth sequence polynomial state differs")
    for row in selections:
        depth = row["partition_bits"]
        observed = (
            row.get("degree_two_monomial_count"),
            row.get("selected_coordinates"),
            row.get("maximum_covered_edge_count"),
            row.get("tie_count"),
            row.get("maximizing_coordinate_sets"),
            row.get("stored_assignment_used"),
            row.get("posthoc_assignment_used"),
            row.get("target_end_state_bits_used"),
            row.get("solver_observations_used"),
        )
        expected = (
            CANONICAL_EDGE_COUNT,
            EXPECTED_COORDINATES[depth],
            EXPECTED_COVERAGE[depth],
            EXPECTED_TIE_COUNTS[depth],
            EXPECTED_MAXIMIZERS[depth],
            False,
            False,
            False,
            False,
        )
        if observed != expected:
            raise RuntimeError(f"canonical depth-{depth} selection differs: {observed!r}")
    deepest = selections[-1]
    if (
        deepest["maximum_covered_edge_count"] != CANONICAL_EDGE_COUNT
        or len(deepest["covered_edges"]) != CANONICAL_EDGE_COUNT
    ):
        raise RuntimeError("canonical depth-10 selection is not a vertex cover")


def _unconditioned_depth_plan(
    selections: Sequence[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Freeze graph-only depth metadata; no assignment parameter is accepted."""
    rows = []
    for selection in selections:
        coordinates = selection["selected_coordinates"]
        selected = set(coordinates)
        residual_edges = [
            edge
            for edge in selection["interaction_edges"]
            if edge[0] not in selected and edge[1] not in selected
        ]
        free_coordinates = [
            coordinate
            for coordinate in range(selection["window_bits"])
            if coordinate not in selected
        ]
        rows.append(
            {
                "depth": selection["partition_bits"],
                "selected_coordinates": coordinates,
                "covered_edge_count": selection["maximum_covered_edge_count"],
                "covered_edges": selection["covered_edges"],
                "residual_edge_count": len(residual_edges),
                "residual_edges": residual_edges,
                "free_coordinate_count": len(free_coordinates),
                "free_coordinates": free_coordinates,
                "logical_assignments_in_conditioned_subspace": 1
                << len(free_coordinates),
                "tie_count": selection["tie_count"],
                "maximizing_coordinate_sets": selection["maximizing_coordinate_sets"],
                "selection_sha256": selection["selection_sha256"],
                "interaction_edges_sha256": selection["interaction_edges_sha256"],
                "stored_assignment_used_for_coordinate_selection": False,
                "posthoc_assignment_used_for_coordinate_selection": False,
                "target_end_state_bits_used_for_coordinate_selection": False,
                "solver_observations_used_for_coordinate_selection": False,
                "selection_completed_before_branch_value_projection": True,
            }
        )
    return rows


def _condition_depth_plan(
    unconditioned_plan: Sequence[dict[str, Any]], assignment: int
) -> list[dict[str, Any]]:
    if assignment < 0 or assignment >= 1 << WINDOW_BITS:
        raise ValueError("assignment does not fit the canonical window")
    return [
        {
            **row,
            "projection_value": _project_assignment(
                assignment, row["selected_coordinates"]
            ),
            "fixed_coordinates": [
                {
                    "coordinate": coordinate,
                    "value": (assignment >> coordinate) & 1,
                }
                for coordinate in row["selected_coordinates"]
            ],
            "posthoc_assignment_used_for_branch_value": True,
            "branch_value_source": "instrumented_canonical_assignment_after_selection",
        }
        for row in unconditioned_plan
    ]


def _render_conditioned_smt(
    writer: Any,
    inputs: list[str],
    selected_coordinates: Sequence[int],
    projection_value: int,
) -> bytes:
    return _render_fixed_coordinates(
        writer,
        inputs,
        selected_coordinates,
        projection_value,
        include_model=True,
    )


def _independent_end_state_check(
    problem: dict[str, Any], variant: Any, assignment: int | None
) -> dict[str, Any]:
    if assignment is None:
        return {
            "performed": False,
            "reason": "no_solver_assignment",
            "rate_bits_required": 1344,
            "complete_rate_match": None,
        }
    verification = _VERIFY(problem, variant, assignment)
    return {"performed": True, "reason": None, **verification}


def _measurement_record(
    plan: dict[str, Any],
    raw: bytes,
    solver: dict[str, Any],
    assignment: int | None,
    independent_check: dict[str, Any],
    instrumented_assignment: int,
    *,
    source: str,
    executed_in_this_run: bool,
    reused_from_a141: bool,
) -> dict[str, Any]:
    verified = bool(
        assignment is not None
        and independent_check.get("performed")
        and independent_check.get("rate_bits_checked") == 1344
        and independent_check.get("complete_rate_match")
        and assignment == instrumented_assignment
    )
    return {
        **plan,
        "conditioned_subspace_count": 1,
        "smt_bytes": len(raw),
        "smt_sha256": hashlib.sha256(raw).hexdigest(),
        "solver": solver,
        "assignment": assignment,
        "independent_end_state_check": independent_check,
        "matches_instrumented_assignment_posthoc": (
            assignment == instrumented_assignment if assignment is not None else None
        ),
        "correctly_confirmed_model": verified,
        "source": source,
        "executed_in_this_run": executed_in_this_run,
        "reused_from_a141": reused_from_a141,
        "timeout_seconds": TIMEOUT_SECONDS,
        "solver_threads": SOLVER_THREADS,
        "stored_assignment_used_for_coordinate_selection": False,
        "posthoc_assignment_used_for_branch_value": True,
        "wallclock_used_for_depth_or_threshold_selection": False,
    }


def _reuse_a141_k4_measurement(
    payload: dict[str, Any],
    plan: dict[str, Any],
    raw: bytes,
    problem: dict[str, Any],
    variant: Any,
    instrumented_assignment: int,
) -> dict[str, Any]:
    row = _a141_reuse_row(payload)
    trial = payload["trial"]
    if (
        plan.get("depth") != 4
        or plan.get("selected_coordinates") != EXPECTED_COORDINATES[4]
        or plan.get("projection_value") != row.get("fixed_value")
        or trial.get("actual_assignment_posthoc") != instrumented_assignment
        or row.get("smt_bytes") != len(raw)
        or row.get("smt_sha256") != hashlib.sha256(raw).hexdigest()
    ):
        raise RuntimeError("regenerated depth-4 branch differs from the A141 reuse row")
    assignment = row["assignment"]
    independent = _independent_end_state_check(problem, variant, assignment)
    return _measurement_record(
        plan,
        raw,
        row["solver"],
        assignment,
        independent,
        instrumented_assignment,
        source="A141_hash_gated_actual_structural4_subspace",
        executed_in_this_run=False,
        reused_from_a141=True,
    )


def _execute_conditioned_depth(
    variant: Any,
    problem: dict[str, Any],
    writer: Any,
    inputs: list[str],
    plan: dict[str, Any],
    timeout_seconds: int,
    z3: Path,
    work_dir: Path,
    keep_smt: bool,
    instrumented_assignment: int,
) -> dict[str, Any]:
    if timeout_seconds != TIMEOUT_SECONDS:
        raise ValueError("canonical depth-frontier measurements require exactly 60 seconds")
    raw = _render_conditioned_smt(
        writer,
        inputs,
        plan["selected_coordinates"],
        plan["projection_value"],
    )
    work_dir.mkdir(parents=True, exist_ok=True)
    path = work_dir / f"{variant.name.lower()}_r1_w{len(inputs)}_depth{plan['depth']}.smt2"
    path.write_bytes(raw)
    try:
        result = _SMT._run_z3(z3, path, timeout_seconds, inputs)
    finally:
        if not keep_smt:
            path.unlink(missing_ok=True)
    assignment = result["assignment"]
    if result["status"] == "sat" and assignment is None:
        raise RuntimeError("satisfiable conditioned branch did not return an assignment")
    independent = _independent_end_state_check(problem, variant, assignment)
    if assignment is not None and (
        independent.get("rate_bits_checked") != 1344
        or not independent.get("complete_rate_match")
    ):
        raise RuntimeError("conditioned solver assignment failed the independent 1344-bit gate")
    return _measurement_record(
        plan,
        raw,
        _SMT._solver_summary(result),
        assignment,
        independent,
        instrumented_assignment,
        source="depth_frontier_single_conditioned_subspace_run",
        executed_in_this_run=True,
        reused_from_a141=False,
    )


def _frontier_summary(measurements: Sequence[dict[str, Any]]) -> dict[str, Any]:
    if [row.get("depth") for row in measurements] != list(DEPTHS):
        raise RuntimeError("frontier measurements do not follow the frozen depth sequence")
    successful_depths = [
        row["depth"] for row in measurements if row.get("correctly_confirmed_model")
    ]
    return {
        "depth_order": list(DEPTHS),
        "status_by_depth": {
            str(row["depth"]): row["solver"]["status"] for row in measurements
        },
        "correctly_confirmed_model_by_depth": {
            str(row["depth"]): row["correctly_confirmed_model"]
            for row in measurements
        },
        "successful_depths": successful_depths,
        "minimal_depth_with_correctly_confirmed_model": (
            min(successful_depths) if successful_depths else None
        ),
        "threshold_selection_rule": (
            "minimum_predeclared_depth_with_solver_assignment_matching_the_"
            "instrumented_assignment_and_complete_independent_1344_bit_rate_check"
        ),
        "wallclock_used_for_depth_or_threshold_selection": False,
        "all_depths_executed_or_hash_gated_reused_regardless_of_earlier_status": True,
    }


def _build_graph(
    path: Path,
    selections: Sequence[dict[str, Any]],
    conditioned_plan: Sequence[dict[str, Any]],
    measurements: Sequence[dict[str, Any]],
    frontier: dict[str, Any],
) -> tuple[dict[str, Any], list[dict[str, Any]], dict[str, Any]]:
    first = selections[0]
    builder = CryptoCausalBuilder(
        experiment="shake_symbolic_r1_structural_depth_frontier",
        parameters={
            "variant": "shake128",
            "window_bits": WINDOW_BITS,
            "seed": SEED,
            "depths": list(DEPTHS),
            "timeout_seconds_per_conditioned_subspace": TIMEOUT_SECONDS,
            "conditioned_subspaces_per_depth": 1,
            "solver_threads": SOLVER_THREADS,
            "purpose": PURPOSE,
            "claim": CLAIM,
        },
    )
    graph_id = "shake128-r1-exact-interaction-graph"
    sequence_id = "shake128-r1-deterministic-depth-sequence-posthoc-values"
    frontier_id = "shake128-r1-conditioned-solvability-frontier"
    builder.add_triplet(
        edge_id=graph_id,
        trigger="shake128:exact_R1_prefix_polynomial_state",
        mechanism="extract_unique_degree_2_monomials_as_undirected_variable_edges",
        outcome="shake128:exact_R1_interaction_graph",
        confidence=1.0,
        evidence_kind="exact_symbolic_formula_graph",
        source="A141_exact_R1_polynomial_edge_extractor",
        attrs={
            "r1_polynomial_state_sha256": first["r1_polynomial_state_sha256"],
            "degree_two_monomial_masks": first["degree_two_monomial_masks"],
            "interaction_edges": first["interaction_edges"],
            "interaction_edges_sha256": first["interaction_edges_sha256"],
            "degree_two_edge_count": first["degree_two_monomial_count"],
        },
    )
    builder.add_triplet(
        edge_id=sequence_id,
        trigger="shake128:exact_R1_interaction_graph",
        mechanism=(
            "maximize_incident_edge_coverage_at_each_predeclared_depth_take_the_"
            "lexicographically_first_maximizer_then_project_the_posthoc_"
            "instrumented_assignment_only_after_all_coordinate_selections"
        ),
        outcome="shake128:deterministic_depth_sequence_plus_posthoc_branch_values",
        confidence=1.0,
        evidence_kind="deterministic_graph_sequence_and_explicit_posthoc_conditioning",
        source="reader_local_exact_enumeration_then_instrumented_branch_projection",
        provenance=[graph_id],
        attrs={
            "depth_sequence": list(conditioned_plan),
            "stored_assignment_used_for_coordinate_selection": False,
            "posthoc_assignment_used_for_branch_value": True,
            "selection_completed_before_any_branch_value_projection": True,
            "purpose": PURPOSE,
            "claim": CLAIM,
        },
    )
    builder.add_triplet(
        edge_id=frontier_id,
        trigger="shake128:deterministic_depth_sequence_plus_posthoc_branch_values",
        mechanism=(
            "measure_exactly_one_conditioned_subspace_per_depth_with_one_solver_"
            "thread_and_uniform_60_second_limits_then_independently_check_each_model_"
            "against_all_1344_rate_bits"
        ),
        outcome="shake128:measured_conditioned_solvability_frontier_and_independent_checks",
        confidence=1.0,
        evidence_kind="bounded_solver_statuses_and_complete_independent_candidate_checks",
        source="A141_hash_gated_k4_reuse_plus_local_Z3_k6_k8_k10",
        provenance=[sequence_id],
        attrs={
            "measurements": list(measurements),
            "frontier": frontier,
            "conditioned_subspaces_per_depth": 1,
            "timeout_seconds": TIMEOUT_SECONDS,
            "solver_threads": SOLVER_THREADS,
            "wallclock_used_for_depth_or_threshold_selection": False,
            "purpose": PURPOSE,
            "claim": CLAIM,
        },
    )
    stats = builder.save(path)
    reader = CryptoCausalReader(path)
    rows = reader.triplets(include_inferred=False)
    by_id = {row["edge_id"]: row for row in rows}
    expected_ids = {graph_id, sequence_id, frontier_id}
    passed = (
        reader.verify_provenance()
        and len(rows) == 3
        and set(by_id) == expected_ids
        and by_id[sequence_id]["provenance"] == [graph_id]
        and by_id[frontier_id]["provenance"] == [sequence_id]
        and by_id[graph_id]["outcome"] == by_id[sequence_id]["trigger"]
        and by_id[sequence_id]["outcome"] == by_id[frontier_id]["trigger"]
        and by_id[sequence_id]["attrs"][
            "stored_assignment_used_for_coordinate_selection"
        ]
        is False
        and by_id[sequence_id]["attrs"]["posthoc_assignment_used_for_branch_value"]
        is True
        and by_id[frontier_id]["attrs"][
            "wallclock_used_for_depth_or_threshold_selection"
        ]
        is False
    )
    if not passed:
        raise RuntimeError("R1 structural-depth causal reader gate failed")
    gate = {
        "passed": True,
        "explicit_triplet_count": len(rows),
        "provenance_verified": reader.verify_provenance(),
        "exact_three_edge_chain": True,
        "interaction_edges_sha256": first["interaction_edges_sha256"],
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
        "--a141",
        type=Path,
        default=Path(
            "research/results/v1/shake_symbolic_r1_structural_partition_reader_v1.json"
        ),
    )
    parser.add_argument(
        "--a143",
        type=Path,
        default=Path(
            "research/results/v1/shake_symbolic_r1_structural6_partition_reader_v1.json"
        ),
    )
    parser.add_argument(
        "--work-dir",
        type=Path,
        default=Path("build/shake-symbolic-r1-structural-depth-frontier"),
    )
    parser.add_argument("--keep-smt", action="store_true")
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--causal-output", type=Path, required=True)
    args = parser.parse_args()

    a138_trial = _load_a138_gate(args.a138)
    a141_payload = _load_a141_gate(args.a141)
    a143_payload = _load_a143_gate(args.a143)
    if {
        a138_trial["encoding"]["first_smt_sha256"],
        a141_payload["trial"]["encoding"]["unpartitioned_smt_sha256"],
        a143_payload["trial"]["encoding"]["unpartitioned_smt_sha256"],
    } != {UNPARTITIONED_SMT_SHA256}:
        raise RuntimeError("A138, A141, and A143 do not identify one R1 formulation")

    z3 = Path(shutil.which(str(args.z3)) or args.z3)
    if not z3.is_file():
        raise FileNotFoundError(f"Z3 executable not found: {args.z3}")
    solver_version = subprocess.run(
        [str(z3), "-version"], check=True, capture_output=True, text=True
    ).stdout.strip()

    variant = _BASE.VARIANTS["shake128"]
    problem = _NATIVE._problem(variant, WINDOW_BITS, SEED)

    # This entire graph-only sequence is frozen before extracting any assignment.
    selections = _derive_depth_sequence(
        problem["base_state"], variant, problem["positions"], DEPTHS
    )
    _canonical_depth_sequence_gate(selections)
    unconditioned_plan = _unconditioned_depth_plan(selections)

    writer, inputs, encoding = _R1._SPLIT._encode_problem(
        problem, variant, SEED, prefix_rounds=1
    )
    unpartitioned_raw = writer.render(inputs, include_model=True)
    if hashlib.sha256(unpartitioned_raw).hexdigest() != UNPARTITIONED_SMT_SHA256:
        raise RuntimeError("regenerated unpartitioned R1 SMT differs from A138")

    instrumented_assignment = _WINDOW._extract_window(
        problem["base_state"], variant, problem["positions"]
    )
    if instrumented_assignment != CANONICAL_ASSIGNMENT:
        raise RuntimeError("instrumented canonical assignment differs")
    conditioned_plan = _condition_depth_plan(
        unconditioned_plan, instrumented_assignment
    )

    k4_raw = _render_conditioned_smt(
        writer,
        inputs,
        conditioned_plan[0]["selected_coordinates"],
        conditioned_plan[0]["projection_value"],
    )
    measurements = [
        _reuse_a141_k4_measurement(
            a141_payload,
            conditioned_plan[0],
            k4_raw,
            problem,
            variant,
            instrumented_assignment,
        )
    ]
    for plan in conditioned_plan[1:]:
        print(
            f"SHAKE128 R1 conditioned structural depth={plan['depth']} "
            f"projection={plan['projection_value']}",
            flush=True,
        )
        measurements.append(
            _execute_conditioned_depth(
                variant,
                problem,
                writer,
                inputs,
                plan,
                TIMEOUT_SECONDS,
                z3,
                args.work_dir,
                args.keep_smt,
                instrumented_assignment,
            )
        )
    frontier = _frontier_summary(measurements)

    causal_stats, reader_triplets, reader_gate = _build_graph(
        args.causal_output,
        selections,
        conditioned_plan,
        measurements,
        frontier,
    )
    payload = {
        "schema": "shake-symbolic-r1-structural-depth-frontier-v1",
        "evidence_stage": "POSTHOC_CONDITIONED_R1_STRUCTURAL_DEPTH_FRONTIER_MEASURED",
        "purpose": PURPOSE,
        "claim": CLAIM,
        "result": (
            "Four graph-selected conditioning depths were measured on exactly one "
            "posthoc canonical branch each; the minimum independently confirmed depth "
            f"is {frontier['minimal_depth_with_correctly_confirmed_model']}."
        ),
        "scope": (
            "One hash-gated SHAKE128 width-20 seed-89755037 exact R1 Boolean "
            "constraint system; depths are structural, branch values are posthoc."
        ),
        "parameters": {
            "solver": solver_version,
            "solver_threads": SOLVER_THREADS,
            "timeout_seconds_per_conditioned_subspace": TIMEOUT_SECONDS,
            "conditioned_subspaces_per_depth": 1,
            "window_bits": WINDOW_BITS,
            "seed": SEED,
            "symbolic_prefix_rounds": 1,
            "depths": list(DEPTHS),
            "a138_json_sha256": A138_JSON_SHA256,
            "a141_sha256": A141_SHA256,
            "a143_sha256": A143_SHA256,
            "unpartitioned_smt_sha256": UNPARTITIONED_SMT_SHA256,
            "stored_assignment_used_for_coordinate_selection": False,
            "posthoc_assignment_used_for_branch_value": True,
            "selection_completed_before_any_branch_value_projection": True,
            "wallclock_used_for_depth_or_threshold_selection": False,
        },
        "reuse_and_input_gates": {
            "a138_width20_status": a138_trial["first_solver"]["status"],
            "a141_status_counts": a141_payload["trial"]["status_counts"],
            "a141_actual_k4_subspace_reused": True,
            "a143_status_counts": a143_payload["trial"]["status_counts"],
            "a143_k6_reused": False,
            "a143_nonreuse_reason": "retained_A143_limit_was_30_seconds_not_uniform_60_seconds",
            "all_gate_formulations_match": True,
        },
        "instrumented_assignment_posthoc": instrumented_assignment,
        "interaction_graph": {
            "r1_polynomial_state_sha256": selections[0]["r1_polynomial_state_sha256"],
            "degree_two_edge_count": selections[0]["degree_two_monomial_count"],
            "degree_two_monomial_masks": selections[0]["degree_two_monomial_masks"],
            "interaction_edges": selections[0]["interaction_edges"],
            "interaction_edges_sha256": selections[0]["interaction_edges_sha256"],
        },
        "structural_selections": selections,
        "conditioned_depth_plan": conditioned_plan,
        "measurements": measurements,
        "frontier": frontier,
        "encoding": {
            **encoding,
            "unpartitioned_smt_bytes": len(unpartitioned_raw),
            "unpartitioned_smt_sha256": hashlib.sha256(unpartitioned_raw).hexdigest(),
        },
        "kat": _BASE._kat(),
        "causal": causal_stats,
        "reader_gate": reader_gate,
        "reader_triplets": reader_triplets,
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
                "interaction_edges_sha256": INTERACTION_EDGES_SHA256,
                "depths": [
                    {
                        "depth": row["depth"],
                        "coordinates": row["selected_coordinates"],
                        "covered_edges": row["covered_edge_count"],
                        "residual_edges": row["residual_edge_count"],
                        "free_coordinates": row["free_coordinate_count"],
                        "projection_value": row["projection_value"],
                        "smt_bytes": row["smt_bytes"],
                        "smt_sha256": row["smt_sha256"],
                        "status": row["solver"]["status"],
                        "assignment": row["assignment"],
                        "correctly_confirmed_model": row["correctly_confirmed_model"],
                        "reused_from_a141": row["reused_from_a141"],
                    }
                    for row in measurements
                ],
                "minimal_depth_with_correctly_confirmed_model": frontier[
                    "minimal_depth_with_correctly_confirmed_model"
                ],
                "reader_gate": reader_gate,
            },
            indent=2,
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    main()

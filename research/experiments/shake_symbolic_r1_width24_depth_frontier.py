#!/usr/bin/env python3
"""Map the exact R1 structural conditioning frontier for width-24 SHAKE128."""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import itertools
import json
import math
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


_DEPTH = _import_sibling(
    "shake_symbolic_r1_structural_depth_frontier.py",
    "shake_symbolic_r1_structural_depth_frontier_width24_base",
)

_A141 = _DEPTH._A141
_R1 = _DEPTH._R1
_BASE = _DEPTH._BASE
_NATIVE = _DEPTH._NATIVE
_WINDOW = _DEPTH._WINDOW
_SMT = _DEPTH._SMT
_VERIFY = _DEPTH._VERIFY
_degree_two_monomial_edges = _DEPTH._degree_two_monomial_edges
_render_fixed_coordinates = _DEPTH._render_fixed_coordinates
_project_assignment = _DEPTH._project_assignment

A138_JSON_SHA256 = "428e17c9d959e425f417b0c3ce15bd1e9065b8284229ce78f7dd8cb4dce0b078"
UNPARTITIONED_SMT_SHA256 = "c60d30cb908376947bd53699df938040baae961bac2be9573a9dfeef4f4a5080"
WINDOW_BITS = 24
SEED = 89756046
DEPTHS = (8, 9, 10, 11, 12)
TIMEOUT_SECONDS = 60
SOLVER_THREADS = 1
EXPECTED_Z3_VERSION_PREFIX = "Z3 version 4.15.4 "
CANONICAL_EDGE_COUNT = 9
CANONICAL_EDGES = [
    [0, 15],
    [1, 16],
    [2, 17],
    [3, 18],
    [4, 19],
    [5, 20],
    [6, 21],
    [7, 22],
    [8, 23],
]
EXPECTED_SELECTIONS = {
    8: [0, 1, 2, 3, 4, 5, 6, 7],
    9: [0, 1, 2, 3, 4, 5, 6, 7, 8],
    10: [0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
    11: [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10],
    12: [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11],
}
EXPECTED_COVERAGE = {8: 8, 9: 9, 10: 9, 11: 9, 12: 9}
EXPECTED_TIES = {8: 2304, 9: 512, 10: 5376, 11: 26112, 12: 77824}
R1_POLYNOMIAL_STATE_SHA256 = "266374067017f3c9c4c67961b7312877760699837e888733d8979c0c71571e00"
PURPOSE = "posthoc_conditioned_width24_mechanism_frontier_not_autonomous_search"
CLAIM = (
    "This experiment freezes every coordinate set from the exact R1 graph before "
    "projecting the instrumented assignment. It localizes a structural depth "
    "frontier and is not an assignment-free model search."
)


def _canonical_sha256(value: Any) -> str:
    raw = json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode()
    return hashlib.sha256(raw).hexdigest()


def _load_a138_width24_gate(path: Path) -> dict[str, Any]:
    raw = path.read_bytes()
    observed = hashlib.sha256(raw).hexdigest()
    if observed != A138_JSON_SHA256:
        raise RuntimeError(f"A138 retained artifact hash differs: {observed}")
    payload = json.loads(raw)
    rows = [row for row in payload.get("trials", []) if row.get("window_bits") == 24]
    if len(rows) != 1:
        raise RuntimeError("A138 must contain exactly one width-24 trial")
    row = rows[0]
    if (
        row.get("seed") != SEED
        or row.get("first_solver", {}).get("status") != "unknown"
        or row.get("reconstructed_assignment") is not None
        or row.get("encoding", {}).get("first_smt_sha256") != UNPARTITIONED_SMT_SHA256
    ):
        raise RuntimeError("A138 width-24 gate differs")
    return row


def _normalized_edges(edges: Sequence[Sequence[int]], window_bits: int) -> list[tuple[int, int]]:
    normalized: set[tuple[int, int]] = set()
    for edge in edges:
        if len(edge) != 2:
            raise ValueError("each edge must contain two coordinates")
        left, right = sorted((int(edge[0]), int(edge[1])))
        if left < 0 or right >= window_bits or left == right:
            raise ValueError("edge lies outside the simple variable graph")
        normalized.add((left, right))
    return sorted(normalized)


def _max_cover_summary(
    edges: Sequence[Sequence[int]], window_bits: int, depth: int
) -> dict[str, Any]:
    """Return an exact count and lexicographic first maximizer without retaining ties."""
    if depth < 1 or depth >= window_bits:
        raise ValueError("depth must lie in 1..window_bits-1")
    ordered_edges = _normalized_edges(edges, window_bits)
    edge_masks = [(1 << left) | (1 << right) for left, right in ordered_edges]
    best = -1
    tie_count = 0
    first: tuple[int, ...] | None = None
    for candidate in itertools.combinations(range(window_bits), depth):
        candidate_mask = sum(1 << coordinate for coordinate in candidate)
        coverage = sum(bool(candidate_mask & edge_mask) for edge_mask in edge_masks)
        if coverage > best:
            best = coverage
            tie_count = 1
            first = candidate
        elif coverage == best:
            tie_count += 1
    if first is None:
        raise RuntimeError("max-cover enumeration returned no candidate")
    selected = set(first)
    covered = [edge for edge in ordered_edges if edge[0] in selected or edge[1] in selected]
    residual = [edge for edge in ordered_edges if edge not in covered]
    return {
        "depth": depth,
        "candidate_set_count": math.comb(window_bits, depth),
        "maximum_covered_edge_count": best,
        "tie_count": tie_count,
        "selected_coordinates": list(first),
        "covered_edges": [list(edge) for edge in covered],
        "residual_edges": [list(edge) for edge in residual],
    }


def _components(edges: Sequence[Sequence[int]], window_bits: int) -> list[list[int]]:
    adjacency = [set() for _ in range(window_bits)]
    for left, right in _normalized_edges(edges, window_bits):
        adjacency[left].add(right)
        adjacency[right].add(left)
    seen: set[int] = set()
    components = []
    for root in range(window_bits):
        if root in seen:
            continue
        stack = [root]
        seen.add(root)
        component = []
        while stack:
            current = stack.pop()
            component.append(current)
            for neighbor in sorted(adjacency[current], reverse=True):
                if neighbor not in seen:
                    seen.add(neighbor)
                    stack.append(neighbor)
        components.append(sorted(component))
    return components


def _derive_graph_and_depths(
    base_state: Any,
    variant: Any,
    positions: Sequence[int],
    depths: Sequence[int],
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    """Accept no assignment: graph and all coordinate sets are frozen first."""
    template = _WINDOW._clear_window(base_state, variant, positions)
    polynomials = _R1._SPLIT._symbolic_prefix_polynomials(
        template, variant, positions, prefix_rounds=1
    )
    masks, edges = _degree_two_monomial_edges(polynomials, len(positions))
    degree = [0] * len(positions)
    for left, right in edges:
        degree[left] += 1
        degree[right] += 1
    edge_rows = [list(edge) for edge in edges]
    graph = {
        "window_bits": len(positions),
        "symbolic_prefix_rounds": 1,
        "r1_polynomial_state_sha256": _R1._SPLIT._SYMBOLIC._poly_hash(polynomials, len(positions)),
        "degree_two_monomial_masks": masks,
        "interaction_edges": edge_rows,
        "interaction_edges_sha256": _canonical_sha256(edge_rows),
        "edge_count": len(edges),
        "degree_by_coordinate": degree,
        "isolated_coordinates": [index for index, value in enumerate(degree) if value == 0],
        "components": _components(edges, len(positions)),
        "actual_assignment_used": False,
        "target_end_state_bits_used": False,
        "solver_observations_used": False,
    }
    selections = []
    for depth in depths:
        summary = _max_cover_summary(edges, len(positions), depth)
        selected = set(summary["selected_coordinates"])
        selections.append(
            {
                **summary,
                "free_coordinates": [
                    coordinate for coordinate in range(len(positions)) if coordinate not in selected
                ],
                "selection_completed_before_assignment_projection": True,
                "stored_assignment_used_for_coordinate_selection": False,
                "posthoc_assignment_used_for_coordinate_selection": False,
            }
        )
    for row in selections:
        row["free_coordinate_count"] = len(row["free_coordinates"])
        row["conditioned_subspace_logical_assignments"] = 1 << len(row["free_coordinates"])
        row["selection_sha256"] = _canonical_sha256(
            {
                "depth": row["depth"],
                "selected_coordinates": row["selected_coordinates"],
                "maximum_covered_edge_count": row["maximum_covered_edge_count"],
                "tie_count": row["tie_count"],
                "interaction_edges_sha256": graph["interaction_edges_sha256"],
            }
        )
    return graph, selections


def _canonical_structure_gate(graph: dict[str, Any], selections: Sequence[dict[str, Any]]) -> None:
    if (
        graph.get("edge_count") != CANONICAL_EDGE_COUNT
        or graph.get("interaction_edges") != CANONICAL_EDGES
        or graph.get("r1_polynomial_state_sha256") != R1_POLYNOMIAL_STATE_SHA256
        or graph.get("isolated_coordinates") != [9, 10, 11, 12, 13, 14]
    ):
        raise RuntimeError("canonical width-24 R1 graph differs")
    if [row["depth"] for row in selections] != list(DEPTHS):
        raise RuntimeError("canonical width-24 depth sequence differs")
    for row in selections:
        depth = row["depth"]
        if (
            row["selected_coordinates"] != EXPECTED_SELECTIONS[depth]
            or row["maximum_covered_edge_count"] != EXPECTED_COVERAGE[depth]
            or row["tie_count"] != EXPECTED_TIES[depth]
        ):
            raise RuntimeError(f"canonical width-24 depth-{depth} selection differs")


def _condition_selections(
    selections: Sequence[dict[str, Any]], assignment: int
) -> list[dict[str, Any]]:
    if assignment < 0 or assignment >= 1 << WINDOW_BITS:
        raise ValueError("assignment does not fit width 24")
    return [
        {
            **row,
            "projection_value": _project_assignment(assignment, row["selected_coordinates"]),
            "posthoc_assignment_used_for_branch_value": True,
            "branch_value_source": "instrumented_assignment_after_all_selections",
        }
        for row in selections
    ]


def _independent_check(
    problem: dict[str, Any], variant: Any, assignment: int | None
) -> dict[str, Any]:
    if assignment is None:
        return {
            "performed": False,
            "complete_rate_match": None,
            "rate_bits_required": 1344,
            "reason": "no_solver_assignment",
        }
    return {"performed": True, "reason": None, **_VERIFY(problem, variant, assignment)}


def _execute_depth(
    problem: dict[str, Any],
    variant: Any,
    writer: Any,
    inputs: list[str],
    row: dict[str, Any],
    z3: Path,
    work_dir: Path,
    keep_smt: bool,
    actual_assignment: int,
) -> dict[str, Any]:
    raw = _render_fixed_coordinates(
        writer,
        inputs,
        row["selected_coordinates"],
        row["projection_value"],
        include_model=True,
    )
    work_dir.mkdir(parents=True, exist_ok=True)
    path = work_dir / f"shake128_r1_w24_depth{row['depth']}.smt2"
    path.write_bytes(raw)
    try:
        result = _SMT._run_z3(z3, path, TIMEOUT_SECONDS, inputs)
    finally:
        if not keep_smt:
            path.unlink(missing_ok=True)
    assignment = result["assignment"]
    independent = _independent_check(problem, variant, assignment)
    if assignment is not None and (
        not independent.get("complete_rate_match") or independent.get("rate_bits_checked") != 1344
    ):
        raise RuntimeError("width-24 conditioned model failed independent rate check")
    confirmed = bool(
        assignment == actual_assignment
        and independent.get("performed")
        and independent.get("complete_rate_match")
    )
    return {
        **row,
        "smt_bytes": len(raw),
        "smt_sha256": hashlib.sha256(raw).hexdigest(),
        "solver": _SMT._solver_summary(result),
        "assignment": assignment,
        "independent_end_state_check": independent,
        "matches_instrumented_assignment_posthoc": (
            assignment == actual_assignment if assignment is not None else None
        ),
        "correctly_confirmed_model": confirmed,
        "timeout_seconds": TIMEOUT_SECONDS,
        "solver_threads": SOLVER_THREADS,
        "posthoc_assignment_used_for_branch_value": True,
        "stored_assignment_used_for_coordinate_selection": False,
    }


def _frontier(measurements: Sequence[dict[str, Any]]) -> dict[str, Any]:
    successful = [row["depth"] for row in measurements if row["correctly_confirmed_model"]]
    return {
        "depth_order": list(DEPTHS),
        "status_by_depth": {str(row["depth"]): row["solver"]["status"] for row in measurements},
        "successful_depths": successful,
        "minimal_depth_with_correctly_confirmed_model": (min(successful) if successful else None),
        "all_depths_executed": True,
        "wallclock_used_for_threshold_selection": False,
    }


def _build_graph(
    path: Path,
    structure: dict[str, Any],
    conditioned: Sequence[dict[str, Any]],
    measurements: Sequence[dict[str, Any]],
    frontier: dict[str, Any],
) -> tuple[dict[str, Any], list[dict[str, Any]], dict[str, Any]]:
    builder = CryptoCausalBuilder(
        experiment="shake_symbolic_r1_width24_depth_frontier",
        parameters={
            "variant": "shake128",
            "window_bits": WINDOW_BITS,
            "seed": SEED,
            "depths": list(DEPTHS),
            "timeout_seconds": TIMEOUT_SECONDS,
            "purpose": PURPOSE,
            "claim": CLAIM,
        },
    )
    graph_id = "shake128-r1-width24-exact-interaction-graph"
    plan_id = "shake128-r1-width24-structural-depth-plan"
    result_id = "shake128-r1-width24-conditioned-depth-frontier"
    builder.add_triplet(
        edge_id=graph_id,
        trigger="shake128:width24_exact_R1_prefix_polynomial_state",
        mechanism="extract_unique_degree_2_monomials_as_variable_edges",
        outcome="shake128:width24_exact_R1_interaction_graph",
        confidence=1.0,
        evidence_kind="exact_symbolic_formula_graph",
        source="direct_R1_boolean_ring_compiler",
        attrs=structure,
    )
    builder.add_triplet(
        edge_id=plan_id,
        trigger="shake128:width24_exact_R1_interaction_graph",
        mechanism=(
            "enumerate_all_coordinate_sets_at_each_depth_select_lexicographic_"
            "first_maximum_edge_cover_then_project_assignment_posthoc"
        ),
        outcome="shake128:width24_structural_depth_plan_with_posthoc_values",
        confidence=1.0,
        evidence_kind="exact_max_cover_enumeration_and_explicit_posthoc_conditioning",
        source="reader_local_graph_enumeration",
        provenance=[graph_id],
        attrs={
            "conditioned_depth_plan": list(conditioned),
            "stored_assignment_used_for_coordinate_selection": False,
            "posthoc_assignment_used_for_branch_value": True,
            "claim": CLAIM,
        },
    )
    builder.add_triplet(
        edge_id=result_id,
        trigger="shake128:width24_structural_depth_plan_with_posthoc_values",
        mechanism=(
            "solve_one_conditioned_subspace_per_depth_and_independently_check_"
            "every_model_against_all_1344_rate_bits"
        ),
        outcome="shake128:width24_measured_conditioned_depth_frontier",
        confidence=1.0,
        evidence_kind="bounded_solver_statuses_and_complete_independent_checks",
        source="Z3_Boolean_SMT_plus_independent_single_candidate_NumPy_lane_core",
        provenance=[plan_id],
        attrs={"measurements": list(measurements), "frontier": frontier},
    )
    stats = builder.save(path)
    reader = CryptoCausalReader(path)
    rows = reader.triplets(include_inferred=False)
    by_id = {row["edge_id"]: row for row in rows}
    passed = (
        reader.verify_provenance()
        and len(rows) == 3
        and by_id[plan_id]["provenance"] == [graph_id]
        and by_id[result_id]["provenance"] == [plan_id]
    )
    if not passed:
        raise RuntimeError("width-24 structural depth causal graph gate failed")
    return (
        stats,
        rows,
        {
            "passed": True,
            "triplets": 3,
            "provenance_verified": True,
            "graph_sha256": reader.graph_sha256,
            "file_sha256": reader.file_sha256,
        },
    )


def _atomic_write(path: Path, raw: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.tmp")
    temporary.write_bytes(raw)
    temporary.replace(path)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--a138",
        type=Path,
        default=Path("research/results/v1/shake_symbolic_r1_scaling_reader_v1.json"),
    )
    parser.add_argument(
        "--z3", type=Path, default=Path(shutil.which("z3") or "/opt/homebrew/bin/z3")
    )
    parser.add_argument("--work-dir", type=Path, default=Path("build/shake-r1-width24-depth"))
    parser.add_argument("--keep-smt", action="store_true")
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--causal-output", type=Path, required=True)
    args = parser.parse_args()

    retained = _load_a138_width24_gate(args.a138)
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
    structure, selections = _derive_graph_and_depths(
        problem["base_state"], variant, problem["positions"], DEPTHS
    )
    _canonical_structure_gate(structure, selections)

    writer, inputs, encoding = _R1._SPLIT._encode_problem(problem, variant, SEED, prefix_rounds=1)
    unpartitioned = writer.render(inputs, include_model=True)
    if hashlib.sha256(unpartitioned).hexdigest() != UNPARTITIONED_SMT_SHA256:
        raise RuntimeError("regenerated width-24 R1 SMT differs from A138")
    if retained["encoding"]["first_smt_sha256"] != UNPARTITIONED_SMT_SHA256:
        raise RuntimeError("A138 width-24 SMT gate changed after load")

    # Assignment extraction occurs only after the complete graph-only plan is frozen.
    actual = _WINDOW._extract_window(problem["base_state"], variant, problem["positions"])
    conditioned = _condition_selections(selections, actual)
    measurements = [
        _execute_depth(
            problem,
            variant,
            writer,
            inputs,
            row,
            z3,
            args.work_dir,
            args.keep_smt,
            actual,
        )
        for row in conditioned
    ]
    frontier = _frontier(measurements)
    causal, triplets, reader_gate = _build_graph(
        args.causal_output, structure, conditioned, measurements, frontier
    )

    payload = {
        "schema": "shake-symbolic-r1-width24-depth-frontier-v1",
        "evidence_stage": "POSTHOC_CONDITIONED_WIDTH24_DEPTH_FRONTIER_MEASURED",
        "result": (
            "The exact width-24 R1 graph and a predeclared depth sequence localize "
            "the minimum posthoc-conditioned depth returning an independently "
            "verified complete-rate model."
        ),
        "scope": (
            "One SHAKE128 known-complement width-24 state-window system; exact R1 "
            "prefix, complete remaining rounds, one posthoc-conditioned subspace "
            "per graph-selected depth."
        ),
        "claim": CLAIM,
        "parameters": {
            "variant": "shake128",
            "window_bits": WINDOW_BITS,
            "seed": SEED,
            "depths": list(DEPTHS),
            "timeout_seconds": TIMEOUT_SECONDS,
            "solver_threads": SOLVER_THREADS,
            "solver": solver_version,
            "a138_json_sha256": A138_JSON_SHA256,
            "unpartitioned_smt_sha256": UNPARTITIONED_SMT_SHA256,
        },
        "kat": _BASE._kat(),
        "a138_gate": retained,
        "structure": structure,
        "unconditioned_depth_plan": selections,
        "conditioned_depth_plan": conditioned,
        "measurements": measurements,
        "frontier": frontier,
        "posthoc_comparison": {
            "instrumented_assignment": actual,
            "assignment_extracted_after_all_coordinate_selections": True,
        },
        "encoding": encoding,
        "causal": causal,
        "reader_triplets": triplets,
        "reader_gate": reader_gate,
    }
    raw = (json.dumps(payload, indent=2, sort_keys=True) + "\n").encode()
    _atomic_write(args.output, raw)
    print(
        json.dumps(
            {
                "output": str(args.output),
                "sha256": hashlib.sha256(raw).hexdigest(),
                "graph": {
                    "edges": structure["edge_count"],
                    "isolated": structure["isolated_coordinates"],
                },
                "measurements": [
                    {
                        "depth": row["depth"],
                        "coverage": row["maximum_covered_edge_count"],
                        "free": row["free_coordinate_count"],
                        "projection": row["projection_value"],
                        "status": row["solver"]["status"],
                        "decisions": row["solver"]["stats"].get("decisions"),
                        "assignment": row["assignment"],
                        "confirmed": row["correctly_confirmed_model"],
                    }
                    for row in measurements
                ],
                "minimal_depth": frontier["minimal_depth_with_correctly_confirmed_model"],
                "causal_sha256": reader_gate["file_sha256"],
            },
            indent=2,
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    main()

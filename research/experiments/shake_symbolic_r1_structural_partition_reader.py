#!/usr/bin/env python3
"""Run a neutral R1 partition selected only from the prefix formula graph."""

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


_UPPER = _import_sibling(
    "shake_symbolic_r1_upper_partition_reader.py",
    "shake_symbolic_r1_upper_partition_reader_structural_base",
)

_LOW = _UPPER._LOW
_R1 = _UPPER._R1
_BASE = _UPPER._BASE
_NATIVE = _UPPER._NATIVE
_WINDOW = _UPPER._WINDOW
_SMT = _UPPER._SMT

A138_SHA256 = "428e17c9d959e425f417b0c3ce15bd1e9065b8284229ce78f7dd8cb4dce0b078"
A139_SHA256 = "443e7db3ebd72c4d916b6c688443c27aeb696746db676624b77891722213ab8c"
A140_SHA256 = "f80d3c3581009e09461ed0a5dd963a6498572961b3c63507f5397eb9404db4d4"
UNPARTITIONED_SMT_SHA256 = (
    "66aa82020b4dd2b4d21f3065c99ca6f7c9224ab1ab9765f686121f2fe7f8618f"
)
WINDOW_BITS = 20
PARTITION_BITS = 4
SEED = 89755037
TIMEOUT_SECONDS = 60
MAX_WORKERS = 5
CANONICAL_EDGE_COUNT = 28
CANONICAL_MAXIMUM_COVERAGE = 14
CANONICAL_SELECTED_COORDINATES = [4, 9, 17, 18]
CANONICAL_TIE_COUNT = 14
HASH_SERIALIZATION = (
    "sha256(UTF-8 JSON; sort_keys=true; separators=(',',':'); allow_nan=false)"
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


def _neutral_partition_gate(
    trial: dict[str, Any],
    *,
    label: str,
    expected_coordinates: Sequence[int],
) -> dict[str, Any]:
    coordinates = list(expected_coordinates)
    rows = trial.get("subspaces_detail")
    expected_counts = {"sat": 0, "unsat": 0, "unknown": 16, "error": 0}
    if trial.get("window_bits") != WINDOW_BITS or trial.get("seed") != SEED:
        raise RuntimeError(f"{label} does not identify the canonical width-20 case")
    if trial.get("partitioned_coordinates") != coordinates:
        raise RuntimeError(f"{label} uses unexpected partition coordinates")
    if not isinstance(rows, list) or len(rows) != 16:
        raise RuntimeError(f"{label} must contain exactly 16 subspaces")
    if trial.get("status_counts") != expected_counts:
        raise RuntimeError(f"{label} must contain exactly 16 unknown subspaces")
    if any(
        row.get("solver", {}).get("status") != "unknown"
        or row.get("assignment") is not None
        or row.get("independent_verification") is not None
        for row in rows
    ):
        raise RuntimeError(f"{label} must contain 16 unknown rows and no models")
    if (
        trial.get("found_assignments") != []
        or trial.get("distinct_found_assignments") != []
        or trial.get("verified_assignments") != []
        or trial.get("reconstructed_assignment") is not None
    ):
        raise RuntimeError(f"{label} must retain no model or verified assignment")
    if trial.get("encoding", {}).get("unpartitioned_smt_sha256") != UNPARTITIONED_SMT_SHA256:
        raise RuntimeError(f"{label} does not retain the canonical R1 formulation")
    return trial


def _load_a138_gate(path: Path) -> dict[str, Any]:
    payload = _LOW._load_a138(path)
    trial = _LOW._a138_unknown_trial(payload)
    if trial.get("reconstructed_assignment") is not None:
        raise RuntimeError("A138 width-20 unknown query must not contain a model")
    if trial.get("encoding", {}).get("first_smt_sha256") != UNPARTITIONED_SMT_SHA256:
        raise RuntimeError("A138 does not retain the canonical unpartitioned R1 SMT")
    return trial


def _load_a139_gate(path: Path) -> dict[str, Any]:
    payload = _UPPER._load_a139(path)
    trial = _UPPER._a139_unknown_low_trial(payload)
    return _neutral_partition_gate(
        trial,
        label="A139",
        expected_coordinates=_UPPER.LOW_COORDINATES,
    )


def _a140_unknown_trial(payload: dict[str, Any]) -> dict[str, Any]:
    if payload.get("schema") != "shake-symbolic-r1-upper-partition-reader-v1":
        raise RuntimeError("A140 schema does not identify the retained Upper-4 run")
    trial = payload.get("trial")
    if not isinstance(trial, dict):
        raise RuntimeError("A140 does not contain its retained trial")
    return _neutral_partition_gate(
        trial,
        label="A140",
        expected_coordinates=_UPPER.FIXED_COORDINATES,
    )


def _load_a140_gate(path: Path) -> dict[str, Any]:
    raw = path.read_bytes()
    observed = hashlib.sha256(raw).hexdigest()
    if observed != A140_SHA256:
        raise RuntimeError(f"A140 retained artifact hash differs for {path}: {observed}")
    return _a140_unknown_trial(json.loads(raw))


def _degree_two_monomial_edges(
    polynomials: Sequence[Sequence[int]], window_bits: int
) -> tuple[list[int], list[tuple[int, int]]]:
    """Extract unique quadratic masks as sorted, undirected variable edges."""
    if window_bits < 2:
        raise ValueError("interaction graph needs at least two variables")
    limit = 1 << window_bits
    masks: set[int] = set()
    for polynomial in polynomials:
        for raw_mask in polynomial:
            mask = int(raw_mask)
            if mask < 0 or mask >= limit:
                raise ValueError("monomial mask lies outside the input window")
            if mask.bit_count() == 2:
                masks.add(mask)

    ordered_masks = sorted(masks)
    edges = []
    for mask in ordered_masks:
        variables = tuple(
            index for index in range(window_bits) if (mask >> index) & 1
        )
        if len(variables) != 2:
            raise RuntimeError("quadratic monomial did not produce exactly one edge")
        edges.append((variables[0], variables[1]))
    return ordered_masks, edges


def _selection_rule(window_bits: int, partition_bits: int) -> dict[str, Any]:
    return {
        "rule_id": "exact-r1-quadratic-edge-max-cover-lexicographic-v1",
        "input": "exact_R1_prefix_polynomials_only",
        "symbolic_prefix_rounds": 1,
        "edge_extraction": (
            "take the set of all unique monomial masks of popcount exactly two; "
            "map each mask to the ascending pair of its variable indices"
        ),
        "edge_interpretation": "undirected_simple_variable_graph",
        "candidate_sets": (
            f"all {math.comb(window_bits, partition_bits)} lexicographically ordered "
            f"{partition_bits}-combinations of coordinates 0..{window_bits - 1}"
        ),
        "score": (
            "number of distinct quadratic edges with at least one endpoint in the "
            "candidate coordinate set"
        ),
        "objective": "maximize_score",
        "tie_break": "choose_the_lexicographically_first_maximizer",
        "execution_order": "finish_selection_before_rendering_or_solving_any_subspace",
        "forbidden_selection_inputs": [
            "actual_assignment",
            "stored_assignment",
            "posthoc_assignment",
            "target_end_state_bits",
            "solver_statuses",
            "solver_models",
        ],
    }


def _max_cover_selection(
    edges: Sequence[Sequence[int]], window_bits: int, partition_bits: int
) -> dict[str, Any]:
    if partition_bits < 1 or partition_bits >= window_bits:
        raise ValueError("partition width must be in 1..window_bits-1")
    normalized: set[tuple[int, int]] = set()
    for edge in edges:
        if len(edge) != 2:
            raise ValueError("each interaction edge must contain two endpoints")
        left, right = sorted((int(edge[0]), int(edge[1])))
        if left == right or left < 0 or right >= window_bits:
            raise ValueError("interaction edge lies outside the simple variable graph")
        normalized.add((left, right))
    ordered_edges = sorted(normalized)

    maximum = -1
    maximizers: list[tuple[int, ...]] = []
    for candidate in itertools.combinations(range(window_bits), partition_bits):
        selected = set(candidate)
        coverage = sum(left in selected or right in selected for left, right in ordered_edges)
        if coverage > maximum:
            maximum = coverage
            maximizers = [candidate]
        elif coverage == maximum:
            maximizers.append(candidate)
    selected = maximizers[0]
    selected_set = set(selected)
    covered_edges = [
        edge for edge in ordered_edges if edge[0] in selected_set or edge[1] in selected_set
    ]
    return {
        "selected_coordinates": list(selected),
        "maximum_covered_edge_count": maximum,
        "tie_count": len(maximizers),
        "maximizing_coordinate_sets": [list(row) for row in maximizers],
        "covered_edges": [list(edge) for edge in covered_edges],
        "candidate_set_count": math.comb(window_bits, partition_bits),
    }


def _structural_selection_from_polynomials(
    polynomials: Sequence[Sequence[int]], window_bits: int, partition_bits: int
) -> dict[str, Any]:
    masks, edges = _degree_two_monomial_edges(polynomials, window_bits)
    edge_rows = [list(edge) for edge in edges]
    edge_sha256 = _canonical_sha256(edge_rows)
    rule = _selection_rule(window_bits, partition_bits)
    cover = _max_cover_selection(edges, window_bits, partition_bits)
    selection_record = {
        "selection_rule": rule,
        "window_bits": window_bits,
        "partition_bits": partition_bits,
        "interaction_edges_sha256": edge_sha256,
        "selected_coordinates": cover["selected_coordinates"],
        "maximum_covered_edge_count": cover["maximum_covered_edge_count"],
        "tie_count": cover["tie_count"],
        "maximizing_coordinate_sets": cover["maximizing_coordinate_sets"],
    }
    plan = _UPPER._subspace_plan(window_bits, cover["selected_coordinates"])
    return {
        "source": "exact_R1_prefix_polynomial_state",
        "window_bits": window_bits,
        "partition_bits": partition_bits,
        "symbolic_prefix_rounds": 1,
        "r1_polynomial_state_sha256": _R1._SPLIT._SYMBOLIC._poly_hash(
            list(polynomials), window_bits
        ),
        "degree_two_monomial_count": len(masks),
        "degree_two_monomial_masks": masks,
        "interaction_edges": edge_rows,
        "interaction_edges_sha256": edge_sha256,
        "selection_rule": rule,
        **cover,
        "selection_sha256": _canonical_sha256(selection_record),
        "subspace_plan_sha256": _canonical_sha256(plan),
        "subspace_count": len(plan),
        "subspace_values": list(range(len(plan))),
        "hash_serialization": HASH_SERIALIZATION,
        "actual_assignment_used": False,
        "stored_assignment_used": False,
        "posthoc_assignment_used": False,
        "target_end_state_bits_used": False,
        "solver_observations_used": False,
        "window_values_cleared_before_polynomial_compilation": True,
    }


def _derive_structural_selection(
    base_state: Any,
    variant: Any,
    positions: Any,
    partition_bits: int,
) -> dict[str, Any]:
    """Derive the partition without accepting an output state or assignment."""
    template = _WINDOW._clear_window(base_state, variant, positions)
    polynomials = _R1._SPLIT._symbolic_prefix_polynomials(
        template, variant, positions, prefix_rounds=1
    )
    return _structural_selection_from_polynomials(
        polynomials, len(positions), partition_bits
    )


def _canonical_selection_gate(selection: dict[str, Any]) -> None:
    observed = (
        selection.get("degree_two_monomial_count"),
        selection.get("maximum_covered_edge_count"),
        selection.get("selected_coordinates"),
        selection.get("tie_count"),
    )
    expected = (
        CANONICAL_EDGE_COUNT,
        CANONICAL_MAXIMUM_COVERAGE,
        CANONICAL_SELECTED_COORDINATES,
        CANONICAL_TIE_COUNT,
    )
    if observed != expected:
        raise RuntimeError(f"canonical structural selection gate differs: {observed!r}")


def _assert_candidate_checks(trial: dict[str, Any]) -> None:
    found = []
    for row in trial["subspaces_detail"]:
        assignment = row.get("assignment")
        if row.get("solver", {}).get("status") == "sat" and assignment is None:
            raise RuntimeError("a satisfiable subspace did not return a complete assignment")
        if assignment is None:
            continue
        found.append(assignment)
        verification = row.get("independent_verification")
        if (
            not isinstance(verification, dict)
            or verification.get("rate_bits_checked") != 1344
            or verification.get("rate_lanes_checked") != 21
            or not verification.get("complete_rate_match")
            or verification.get("candidate_rate_sha256")
            != verification.get("target_rate_sha256")
        ):
            raise RuntimeError("an SMT assignment failed the independent 1,344-bit gate")
    if found != trial.get("found_assignments"):
        raise RuntimeError("candidate detail and aggregate assignment lists differ")
    if found != trial.get("verified_assignments"):
        raise RuntimeError("not every found assignment passed independent verification")


def _structural_partition_trial(
    variant: Any,
    window_bits: int,
    seed: int,
    partition_bits: int,
    timeout_seconds: int,
    max_workers: int,
    z3: Path,
    work_dir: Path,
    keep_smt: bool,
    expected_unpartitioned_smt_sha256: str | None = None,
) -> dict[str, Any]:
    problem = _NATIVE._problem(variant, window_bits, seed)
    selection = _derive_structural_selection(
        problem["base_state"], variant, problem["positions"], partition_bits
    )
    trial = _UPPER._partition_trial(
        variant,
        window_bits,
        seed,
        selection["selected_coordinates"],
        timeout_seconds,
        max_workers,
        z3,
        work_dir,
        keep_smt,
        expected_unpartitioned_smt_sha256=expected_unpartitioned_smt_sha256,
    )
    if trial["partitioned_coordinates"] != selection["selected_coordinates"]:
        raise RuntimeError("rendered partition differs from the formula-graph selection")
    if (
        trial["encoding"]["polynomial_state_sha256"]
        != selection["r1_polynomial_state_sha256"]
    ):
        raise RuntimeError("selection and solver do not use the same R1 polynomial state")
    trial["structural_selection"] = selection
    trial["selection_completed_before_subspace_execution"] = True
    trial["target_end_state_bits_used_for_selection"] = False
    trial["actual_or_posthoc_assignment_used_for_selection"] = False
    _assert_candidate_checks(trial)
    return trial


def _build_graph(
    path: Path,
    selection: dict[str, Any],
    trial: dict[str, Any],
    timeout_seconds: int,
    max_workers: int,
) -> dict[str, Any]:
    coordinates = selection["selected_coordinates"]
    builder = CryptoCausalBuilder(
        experiment="shake_symbolic_r1_structural_partition_reader",
        parameters={
            "variant": "shake128",
            "window_bits": selection["window_bits"],
            "symbolic_prefix_rounds": 1,
            "partitioned_coordinates": coordinates,
            "interaction_edges_sha256": selection["interaction_edges_sha256"],
            "selection_sha256": selection["selection_sha256"],
            "subspace_plan_sha256": selection["subspace_plan_sha256"],
            "subspace_count": selection["subspace_count"],
            "timeout_seconds_per_subspace": timeout_seconds,
            "max_workers": max_workers,
            "solver_threads_per_worker": 1,
        },
    )
    graph_id = "shake128-r1-quadratic-interaction-graph"
    plan_id = "shake128-r1-deterministic-max-cover-subspace-plan"
    observation_id = "shake128-r1-structural-subspace-observations"
    builder.add_triplet(
        edge_id=graph_id,
        trigger="shake128:exact_R1_prefix_polynomial_state",
        mechanism="extract_unique_degree_2_monomial_masks_as_undirected_variable_edges",
        outcome="shake128:R1_interaction_graph",
        confidence=1.0,
        evidence_kind="exact_symbolic_formula_graph",
        source="shake_symbolic_split_frontier_R1_polynomials",
        attrs={
            "r1_polynomial_state_sha256": selection["r1_polynomial_state_sha256"],
            "degree_two_monomial_masks": selection["degree_two_monomial_masks"],
            "interaction_edges": selection["interaction_edges"],
            "interaction_edges_sha256": selection["interaction_edges_sha256"],
            "hash_serialization": HASH_SERIALIZATION,
        },
    )
    builder.add_triplet(
        edge_id=plan_id,
        trigger="shake128:R1_interaction_graph",
        mechanism=(
            "maximize_incident_edge_coverage_over_all_4_coordinate_sets_then_take_"
            "lexicographically_first_maximizer_and_enumerate_all_values"
        ),
        outcome="shake128:deterministic_max_cover_selection_and_complete_subspace_plan",
        confidence=1.0,
        evidence_kind="deterministic_formula_only_partition_construction",
        source="reader_local_exact_enumeration",
        provenance=[graph_id],
        attrs={
            "selection": selection,
            "fixed_coordinates": coordinates,
            "subspace_values": selection["subspace_values"],
            "subspaces_are_pairwise_disjoint": True,
            "subspaces_cover_complete_assignment_space": True,
        },
    )
    candidate_checks = [
        {
            "subspace_index": row["subspace_index"],
            "assignment": row["assignment"],
            "independent_verification": row["independent_verification"],
        }
        for row in trial["subspaces_detail"]
        if row["assignment"] is not None
    ]
    builder.add_triplet(
        edge_id=observation_id,
        trigger="shake128:deterministic_max_cover_selection_and_complete_subspace_plan",
        mechanism=(
            "execute_all_subspaces_with_equal_limits_and_independently_check_each_"
            "candidate_against_all_1344_target_rate_bits"
        ),
        outcome="shake128:subspace_statuses_plus_independent_complete_end_state_checks",
        confidence=1.0,
        evidence_kind="bounded_solver_statuses_and_complete_1344_bit_candidate_checks",
        source="Z3_Boolean_SMT_and_independent_bit_sliced_transform_core",
        provenance=[plan_id],
        attrs={
            "status_counts": trial["status_counts"],
            "found_assignments": trial["found_assignments"],
            "verified_assignments": trial["verified_assignments"],
            "candidate_checks": candidate_checks,
            "all_found_assignments_independently_verified": trial[
                "all_found_assignments_independently_verified"
            ],
            "reconstruction_matches_instrumented_assignment": trial[
                "reconstruction_matches_instrumented_assignment"
            ],
            "timeout_seconds_per_subspace": timeout_seconds,
            "max_workers": max_workers,
            "solver_threads_per_worker": 1,
        },
    )
    stats = builder.save(path)
    reader = CryptoCausalReader(path)
    rows = reader.triplets(include_inferred=False)
    by_id = {row["edge_id"]: row for row in rows}
    if (
        not reader.verify_provenance()
        or len(rows) != 3
        or set(by_id) != {graph_id, plan_id, observation_id}
        or by_id[plan_id]["provenance"] != [graph_id]
        or by_id[observation_id]["provenance"] != [plan_id]
        or by_id[graph_id]["outcome"] != by_id[plan_id]["trigger"]
        or by_id[plan_id]["outcome"] != by_id[observation_id]["trigger"]
    ):
        raise RuntimeError("R1 structural-partition causal graph gate failed")
    return stats


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
        "--a139",
        type=Path,
        default=Path(
            "research/results/v1/shake_symbolic_r1_partition_scaling_reader_v1.json"
        ),
    )
    parser.add_argument(
        "--a140",
        type=Path,
        default=Path(
            "research/results/v1/shake_symbolic_r1_upper_partition_reader_v1.json"
        ),
    )
    parser.add_argument(
        "--work-dir", type=Path, default=Path("build/shake-symbolic-r1-structural-partition")
    )
    parser.add_argument("--keep-smt", action="store_true")
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--causal-output", type=Path, required=True)
    args = parser.parse_args()

    a138_trial = _load_a138_gate(args.a138)
    a139_trial = _load_a139_gate(args.a139)
    a140_trial = _load_a140_gate(args.a140)
    if any(
        trial["encoding"]["unpartitioned_smt_sha256"] != UNPARTITIONED_SMT_SHA256
        for trial in (a139_trial, a140_trial)
    ):
        raise RuntimeError("A139/A140 and A138 do not identify the same R1 formulation")

    z3 = Path(shutil.which(str(args.z3)) or args.z3)
    if not z3.is_file():
        raise FileNotFoundError(f"Z3 executable not found: {args.z3}")
    version = subprocess.run(
        [str(z3), "-version"], check=True, capture_output=True, text=True
    ).stdout.strip()

    variant = _BASE.VARIANTS["shake128"]
    problem = _NATIVE._problem(variant, WINDOW_BITS, SEED)
    selection = _derive_structural_selection(
        problem["base_state"], variant, problem["positions"], PARTITION_BITS
    )
    _canonical_selection_gate(selection)
    trial = _structural_partition_trial(
        variant,
        WINDOW_BITS,
        SEED,
        PARTITION_BITS,
        TIMEOUT_SECONDS,
        MAX_WORKERS,
        z3,
        args.work_dir,
        args.keep_smt,
        expected_unpartitioned_smt_sha256=UNPARTITIONED_SMT_SHA256,
    )
    if trial["structural_selection"] != selection:
        raise RuntimeError("pre-execution selection was not reproduced by the trial gate")

    causal = _build_graph(
        args.causal_output,
        selection,
        trial,
        TIMEOUT_SECONDS,
        MAX_WORKERS,
    )
    reader = CryptoCausalReader(args.causal_output)
    payload = {
        "schema": "shake-symbolic-r1-structural-partition-reader-v1",
        "evidence_stage": "FORMULA_GRAPH_GUIDED_R1_PARTITION_OBSERVATIONS_RECORDED",
        "result": (
            "The exact R1 quadratic interaction graph deterministically selected four "
            "coordinates before execution; all 16 resulting subspaces, solver statuses, "
            "and independent candidate checks are recorded without outcome selection."
        ),
        "scope": (
            "One hash-gated SHAKE128 width-20 seed-89755037 R1 Boolean transform "
            "constraint system, partitioned only from its exact prefix polynomials."
        ),
        "parameters": {
            "solver": version,
            "max_workers": MAX_WORKERS,
            "solver_threads_per_worker": 1,
            "timeout_seconds_per_subspace": TIMEOUT_SECONDS,
            "window_bits": WINDOW_BITS,
            "partition_bits": PARTITION_BITS,
            "partitioned_coordinates": selection["selected_coordinates"],
            "subspace_count": 1 << PARTITION_BITS,
            "seed": SEED,
            "symbolic_prefix_rounds": 1,
            "a138_sha256": A138_SHA256,
            "a139_sha256": A139_SHA256,
            "a140_sha256": A140_SHA256,
            "unpartitioned_smt_sha256": UNPARTITIONED_SMT_SHA256,
            "a138_20_coordinate_status": a138_trial["first_solver"]["status"],
            "a139_status_counts": a139_trial["status_counts"],
            "a140_status_counts": a140_trial["status_counts"],
            "a139_model_count": len(a139_trial["found_assignments"]),
            "a140_model_count": len(a140_trial["found_assignments"]),
            "selection_completed_before_subspace_execution": True,
            "actual_or_posthoc_assignment_used_for_selection": False,
            "target_end_state_bits_used_for_selection": False,
        },
        "selection": selection,
        "kat": _BASE._kat(),
        "causal": causal,
        "reader_triplets": reader.triplets(include_inferred=False),
        "trial": trial,
    }
    raw = (json.dumps(payload, indent=2, sort_keys=True) + "\n").encode()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_bytes(raw)
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
                "degree_two_edges": selection["degree_two_monomial_count"],
                "maximum_covered_edges": selection["maximum_covered_edge_count"],
                "selected_coordinates": selection["selected_coordinates"],
                "tie_count": selection["tie_count"],
                "status_counts": trial["status_counts"],
                "found_assignments": trial["found_assignments"],
                "verified_assignments": trial["verified_assignments"],
                "actual_fixed_value_posthoc": trial["actual_fixed_value_posthoc"],
                "matches_instrumented_assignment": trial[
                    "reconstruction_matches_instrumented_assignment"
                ],
            },
            indent=2,
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""Run the neutral six-coordinate R1 formula-graph partition reader."""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import shutil
import subprocess
import sys
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
    "shake_symbolic_r1_structural_partition_reader_structural6_base",
)

_UPPER = _A141._UPPER
_R1 = _A141._R1
_BASE = _A141._BASE
_NATIVE = _A141._NATIVE
_WINDOW = _A141._WINDOW
_SMT = _A141._SMT

# Reuse the generic A141 construction and execution path rather than copying it.
_canonical_sha256 = _A141._canonical_sha256
_degree_two_monomial_edges = _A141._degree_two_monomial_edges
_max_cover_selection = _A141._max_cover_selection
_structural_selection_from_polynomials = _A141._structural_selection_from_polynomials
_derive_structural_selection = _A141._derive_structural_selection
_structural_partition_trial = _A141._structural_partition_trial
_assert_candidate_checks = _A141._assert_candidate_checks
_render_fixed_coordinates = _UPPER._render_fixed_coordinates
_subspace_plan = _UPPER._subspace_plan

A138_SHA256 = _A141.A138_SHA256
A141_SHA256 = "0a06caf3a2077f2a0408f7d299eb4fd3e5e6204dd66129d969f347637b823171"
UNPARTITIONED_SMT_SHA256 = (
    "66aa82020b4dd2b4d21f3065c99ca6f7c9224ab1ab9765f686121f2fe7f8618f"
)
WINDOW_BITS = 20
PARTITION_BITS = 6
SEED = 89755037
TIMEOUT_SECONDS = 30
MAX_WORKERS = 5
CANONICAL_EDGE_COUNT = 28
CANONICAL_MAXIMUM_COVERAGE = 20
CANONICAL_SELECTED_COORDINATES = [4, 9, 12, 15, 17, 18]
CANONICAL_TIE_COUNT = 1
HASH_SERIALIZATION = _A141.HASH_SERIALIZATION


def _a141_unknown_trial(payload: dict[str, Any]) -> dict[str, Any]:
    if payload.get("schema") != "shake-symbolic-r1-structural-partition-reader-v1":
        raise RuntimeError("A141 schema does not identify the retained Structural-4 run")
    selection = payload.get("selection")
    trial = payload.get("trial")
    if not isinstance(selection, dict) or not isinstance(trial, dict):
        raise RuntimeError("A141 does not contain its retained selection and trial")
    gated = _A141._neutral_partition_gate(
        trial,
        label="A141",
        expected_coordinates=_A141.CANONICAL_SELECTED_COORDINATES,
    )
    if selection.get("selected_coordinates") != _A141.CANONICAL_SELECTED_COORDINATES:
        raise RuntimeError("A141 retained formula-graph selection differs")
    if trial.get("structural_selection") != selection:
        raise RuntimeError("A141 retained trial and selection records differ")
    return gated


def _load_a141_gate(path: Path) -> dict[str, Any]:
    raw = path.read_bytes()
    observed = hashlib.sha256(raw).hexdigest()
    if observed != A141_SHA256:
        raise RuntimeError(f"A141 retained artifact hash differs for {path}: {observed}")
    return _a141_unknown_trial(json.loads(raw))


def _load_a138_gate(path: Path) -> dict[str, Any]:
    trial = _A141._load_a138_gate(path)
    if trial.get("encoding", {}).get("first_smt_sha256") != UNPARTITIONED_SMT_SHA256:
        raise RuntimeError("A138 does not retain the canonical unpartitioned R1 SMT")
    return trial


def _canonical_selection_gate(selection: dict[str, Any]) -> None:
    observed = (
        selection.get("degree_two_monomial_count"),
        selection.get("maximum_covered_edge_count"),
        selection.get("selected_coordinates"),
        selection.get("tie_count"),
        selection.get("maximizing_coordinate_sets"),
    )
    expected = (
        CANONICAL_EDGE_COUNT,
        CANONICAL_MAXIMUM_COVERAGE,
        CANONICAL_SELECTED_COORDINATES,
        CANONICAL_TIE_COUNT,
        [CANONICAL_SELECTED_COORDINATES],
    )
    if observed != expected:
        raise RuntimeError(f"canonical Structural-6 selection gate differs: {observed!r}")


def _complete_subspace_plan_gate(selection: dict[str, Any]) -> list[dict[str, Any]]:
    coordinates = selection.get("selected_coordinates")
    if not isinstance(coordinates, list) or len(coordinates) != PARTITION_BITS:
        raise RuntimeError("Structural-6 selection does not contain six coordinates")
    plan = _subspace_plan(WINDOW_BITS, coordinates)
    expected_values = list(range(1 << PARTITION_BITS))
    fixed_rows = [
        tuple((cell["coordinate"], cell["value"]) for cell in row["fixed_coordinates"])
        for row in plan
    ]
    if (
        [row["subspace_index"] for row in plan] != expected_values
        or [row["fixed_value"] for row in plan] != expected_values
        or len(set(fixed_rows)) != 1 << PARTITION_BITS
        or sum(row["logical_assignments"] for row in plan) != 1 << WINDOW_BITS
        or selection.get("subspace_count") != 1 << PARTITION_BITS
        or selection.get("subspace_values") != expected_values
        or selection.get("subspace_plan_sha256") != _canonical_sha256(plan)
    ):
        raise RuntimeError("Structural-6 subspace plan is not complete and disjoint")
    return plan


def _build_graph(
    path: Path,
    selection: dict[str, Any],
    trial: dict[str, Any],
    timeout_seconds: int,
    max_workers: int,
) -> dict[str, Any]:
    coordinates = selection["selected_coordinates"]
    _complete_subspace_plan_gate(selection)
    _assert_candidate_checks(trial)
    builder = CryptoCausalBuilder(
        experiment="shake_symbolic_r1_structural6_partition_reader",
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
    graph_id = "shake128-r1-structural6-quadratic-interaction-graph"
    plan_id = "shake128-r1-structural6-max-cover-subspace-plan"
    observation_id = "shake128-r1-structural6-subspace-observations"
    builder.add_triplet(
        edge_id=graph_id,
        trigger="shake128:exact_R1_prefix_polynomial_state",
        mechanism="extract_unique_degree_2_monomial_masks_as_undirected_variable_edges",
        outcome="shake128:R1_structural6_interaction_graph",
        confidence=1.0,
        evidence_kind="exact_symbolic_formula_graph",
        source="A141_generic_R1_polynomial_edge_extractor",
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
        trigger="shake128:R1_structural6_interaction_graph",
        mechanism=(
            "maximize_incident_edge_coverage_over_all_6_coordinate_sets_then_take_"
            "lexicographically_first_maximizer_and_enumerate_all_64_values"
        ),
        outcome="shake128:structural6_selection_and_complete_disjoint_subspace_plan",
        confidence=1.0,
        evidence_kind="deterministic_formula_only_partition_construction",
        source="A141_generic_exact_max_cover_and_subspace_plan",
        provenance=[graph_id],
        attrs={
            "selection": selection,
            "interaction_edges_sha256": selection["interaction_edges_sha256"],
            "selection_sha256": selection["selection_sha256"],
            "subspace_plan_sha256": selection["subspace_plan_sha256"],
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
        trigger="shake128:structural6_selection_and_complete_disjoint_subspace_plan",
        mechanism=(
            "execute_all_64_subspaces_with_equal_limits_and_independently_check_each_"
            "candidate_against_all_1344_target_rate_bits"
        ),
        outcome="shake128:structural6_statuses_and_independent_complete_end_state_checks",
        confidence=1.0,
        evidence_kind="bounded_solver_statuses_and_complete_1344_bit_candidate_checks",
        source="Z3_Boolean_SMT_and_independent_bit_sliced_transform_core",
        provenance=[plan_id],
        attrs={
            "interaction_edges_sha256": selection["interaction_edges_sha256"],
            "selection_sha256": selection["selection_sha256"],
            "subspace_plan_sha256": selection["subspace_plan_sha256"],
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
    expected_ids = {graph_id, plan_id, observation_id}
    hashes = (
        selection["interaction_edges_sha256"],
        selection["selection_sha256"],
        selection["subspace_plan_sha256"],
    )
    if (
        not reader.verify_provenance()
        or len(rows) != 3
        or set(by_id) != expected_ids
        or by_id[plan_id]["provenance"] != [graph_id]
        or by_id[observation_id]["provenance"] != [plan_id]
        or by_id[graph_id]["outcome"] != by_id[plan_id]["trigger"]
        or by_id[plan_id]["outcome"] != by_id[observation_id]["trigger"]
        or by_id[graph_id]["attrs"]["interaction_edges_sha256"] != hashes[0]
        or tuple(
            by_id[plan_id]["attrs"][key]
            for key in (
                "interaction_edges_sha256",
                "selection_sha256",
                "subspace_plan_sha256",
            )
        )
        != hashes
        or tuple(
            by_id[observation_id]["attrs"][key]
            for key in (
                "interaction_edges_sha256",
                "selection_sha256",
                "subspace_plan_sha256",
            )
        )
        != hashes
    ):
        raise RuntimeError("R1 Structural-6 causal reader gate failed")
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
        "--a141",
        type=Path,
        default=Path(
            "research/results/v1/shake_symbolic_r1_structural_partition_reader_v1.json"
        ),
    )
    parser.add_argument(
        "--work-dir",
        type=Path,
        default=Path("build/shake-symbolic-r1-structural6-partition"),
    )
    parser.add_argument("--keep-smt", action="store_true")
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--causal-output", type=Path, required=True)
    args = parser.parse_args()

    a138_trial = _load_a138_gate(args.a138)
    a141_trial = _load_a141_gate(args.a141)
    if (
        a138_trial["encoding"]["first_smt_sha256"]
        != a141_trial["encoding"]["unpartitioned_smt_sha256"]
        or a141_trial["encoding"]["unpartitioned_smt_sha256"]
        != UNPARTITIONED_SMT_SHA256
    ):
        raise RuntimeError("A141 and A138 do not identify the same R1 formulation")

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
    _complete_subspace_plan_gate(selection)
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
        raise RuntimeError("pre-execution Structural-6 selection was not reproduced")
    if (
        trial["subspace_count"] != 1 << PARTITION_BITS
        or trial["partitioned_coordinates"] != CANONICAL_SELECTED_COORDINATES
        or [row["fixed_value"] for row in trial["subspaces_detail"]]
        != list(range(1 << PARTITION_BITS))
        or not trial["subspaces_are_pairwise_disjoint"]
        or not trial["subspaces_cover_complete_assignment_space"]
    ):
        raise RuntimeError("executed Structural-6 subspaces differ from the frozen plan")

    causal = _build_graph(
        args.causal_output,
        selection,
        trial,
        TIMEOUT_SECONDS,
        MAX_WORKERS,
    )
    reader = CryptoCausalReader(args.causal_output)
    payload = {
        "schema": "shake-symbolic-r1-structural6-partition-reader-v1",
        "evidence_stage": "FORMULA_GRAPH_GUIDED_R1_STRUCTURAL6_OBSERVATIONS_RECORDED",
        "result": (
            "The exact R1 quadratic interaction graph deterministically selected six "
            "coordinates before execution; all 64 disjoint subspaces, solver statuses, "
            "and independent candidate checks are recorded without outcome selection."
        ),
        "scope": (
            "One hash-gated SHAKE128 width-20 seed-89755037 R1 Boolean transform "
            "constraint system, partitioned only from its exact degree-two prefix graph."
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
            "a141_sha256": A141_SHA256,
            "unpartitioned_smt_sha256": UNPARTITIONED_SMT_SHA256,
            "a138_20_coordinate_status": a138_trial["first_solver"]["status"],
            "a141_status_counts": a141_trial["status_counts"],
            "a141_model_count": len(a141_trial["found_assignments"]),
            "selection_completed_before_subspace_execution": True,
            "actual_or_posthoc_assignment_used_for_selection": False,
            "target_end_state_bits_used_for_selection": False,
        },
        "selection": selection,
        "kat": _BASE._kat(),
        "causal": causal,
        "reader_gate": {
            "explicit_triplets": 3,
            "provenance_verified": reader.verify_provenance(),
            "interaction_edges_sha256": selection["interaction_edges_sha256"],
            "selection_sha256": selection["selection_sha256"],
            "subspace_plan_sha256": selection["subspace_plan_sha256"],
        },
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
                "subspace_plan_sha256": selection["subspace_plan_sha256"],
                "degree_two_edges": selection["degree_two_monomial_count"],
                "maximum_covered_edges": selection["maximum_covered_edge_count"],
                "selected_coordinates": selection["selected_coordinates"],
                "tie_count": selection["tie_count"],
                "status_counts": trial["status_counts"],
                "found_assignments": trial["found_assignments"],
                "verified_assignments": trial["verified_assignments"],
                "all_found_assignments_independently_verified": trial[
                    "all_found_assignments_independently_verified"
                ],
                "actual_fixed_value_posthoc": trial["actual_fixed_value_posthoc"],
                "matches_instrumented_assignment": trial[
                    "reconstruction_matches_instrumented_assignment"
                ],
                "reader_provenance_verified": reader.verify_provenance(),
            },
            indent=2,
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    main()

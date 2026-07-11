#!/usr/bin/env python3
"""Apply the hash-gated Z3 winner to the canonical Structural-6 R1 partition."""

from __future__ import annotations

import argparse
import concurrent.futures
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


_STRATEGY = _import_sibling(
    "shake_symbolic_r1_z3_strategy_frontier.py",
    "shake_symbolic_r1_z3_strategy_frontier_structural6_combination",
)
_STRUCTURAL6 = _import_sibling(
    "shake_symbolic_r1_structural6_partition_reader.py",
    "shake_symbolic_r1_structural6_partition_reader_z3_combination",
)

_BASE = _STRATEGY._BASE
_WINDOW = _STRATEGY._WINDOW

STRATEGY_FRONTIER_SHA256 = "da4632f92cdd30d8d397bab96a23f5463c686d78965263747c788a60d6c73420"
STRUCTURAL6_SHA256 = "f39309d81d31d4b0615c6fbbd3676eadd53fa15ecf5c9e3ad34d7f5f79112f3d"
UNPARTITIONED_SMT_SHA256 = "66aa82020b4dd2b4d21f3065c99ca6f7c9224ab1ab9765f686121f2fe7f8618f"
STRUCTURAL6_MANIFEST_SHA256 = "f4139410cde1f4bcb52d63bd073de2abc66425223c65729d1cb0d5e5aa385571"
WINNER = "qf_uf_default_retained"
WINNER_DECISIONS = 4701.0
WINDOW_BITS = 20
SEED = 89755037
PARTITION_BITS = 6
SELECTED_COORDINATES = [4, 9, 12, 15, 17, 18]
SUBSPACE_COUNT = 64
TIMEOUT_SECONDS = 120
MAX_WORKERS = 5
INTERACTION_EDGES_SHA256 = "06b168eb69c5a6687e0f7f001bfdf178ce24e28b2b312a84758bfe872d1b9bda"
SELECTION_SHA256 = "233a170be2445150368460b9b208f23a06f439811d2f852cceaa7e4b2d5bcd15"
SUBSPACE_PLAN_SHA256 = "ca8e99d9b75bc27670319e9acd2426e98542fec3f2128cc5d660c0ebbbe0f79e"


def _load_hashed_json(path: Path, expected_sha256: str, label: str) -> dict[str, Any]:
    raw = path.read_bytes()
    observed = hashlib.sha256(raw).hexdigest()
    if observed != expected_sha256:
        raise RuntimeError(f"{label} retained artifact hash differs for {path}: {observed}")
    payload = json.loads(raw)
    if not isinstance(payload, dict):
        raise RuntimeError(f"{label} retained artifact is not a JSON object")
    return payload


def _strategy_winner_gate(payload: dict[str, Any]) -> dict[str, Any]:
    if payload.get("schema") != "shake-symbolic-r1-z3-strategy-frontier-v1":
        raise RuntimeError("strategy artifact schema does not identify the retained frontier")
    selection = payload.get("selection")
    formula20 = payload.get("formula_gates", {}).get("width20")
    transfer = payload.get("width20_transfer", {})
    first = transfer.get("first_query")
    if not all(isinstance(row, dict) for row in (selection, formula20, first)):
        raise RuntimeError("strategy artifact is missing selection or width-20 gates")
    observed = (
        selection.get("selected_strategy"),
        selection.get("selection_metric"),
        selection.get("selection_metric_value"),
        selection.get("eligible_strategies"),
        formula20.get("canonical_smt_sha256"),
        formula20.get("canonical_smt_bytes"),
        formula20.get("matches_retained_a138_first_smt"),
        transfer.get("selected_strategy"),
        first.get("strategy"),
        first.get("status"),
        first.get("assignment"),
        first.get("timeout_seconds"),
        first.get("selection_metrics", {}).get("decisions"),
        payload.get("reader_gate", {}).get("passed"),
    )
    expected = (
        WINNER,
        "decisions",
        WINNER_DECISIONS,
        [WINNER],
        UNPARTITIONED_SMT_SHA256,
        9_189_138,
        True,
        WINNER,
        WINNER,
        "unknown",
        None,
        TIMEOUT_SECONDS,
        11124.0,
        True,
    )
    if observed != expected:
        raise RuntimeError(f"hash-gated Z3 winner observation differs: {observed!r}")
    route = _STRATEGY._strategy(WINNER)
    if route.logic != "QF_UF" or route.check_sat != "(check-sat)":
        raise RuntimeError("retained winner no longer identifies the canonical default renderer")
    return {
        "selected_strategy": WINNER,
        "selection_metric": "decisions",
        "selection_metric_value": WINNER_DECISIONS,
        "width20_status": "unknown",
        "width20_decisions": 11124.0,
        "width20_timeout_seconds": TIMEOUT_SECONDS,
        "canonical_smt_sha256": UNPARTITIONED_SMT_SHA256,
        "renderer_logic": route.logic,
        "renderer_check_sat": route.check_sat,
    }


def _load_strategy_gate(path: Path) -> tuple[dict[str, Any], dict[str, Any]]:
    payload = _load_hashed_json(path, STRATEGY_FRONTIER_SHA256, "strategy frontier")
    return payload, _strategy_winner_gate(payload)


def _formula_manifest(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [
        {
            "subspace_index": row["subspace_index"],
            "fixed_value": row["fixed_value"],
            "smt_bytes": row["smt_bytes"],
            "smt_sha256": row["smt_sha256"],
        }
        for row in rows
    ]


def _structural6_gate(payload: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any]]:
    if payload.get("schema") != "shake-symbolic-r1-structural6-partition-reader-v1":
        raise RuntimeError("Structural-6 schema does not identify the retained partition")
    selection = payload.get("selection")
    trial = payload.get("trial")
    if not isinstance(selection, dict) or not isinstance(trial, dict):
        raise RuntimeError("Structural-6 artifact is missing selection or trial")
    _STRUCTURAL6._canonical_selection_gate(selection)
    plan = _STRUCTURAL6._complete_subspace_plan_gate(selection)
    _STRUCTURAL6._assert_candidate_checks(trial)
    rows = trial.get("subspaces_detail")
    if not isinstance(rows, list):
        raise RuntimeError("Structural-6 artifact is missing subspace detail")
    manifest = _formula_manifest(rows)
    manifest_sha256 = _STRUCTURAL6._canonical_sha256(manifest)
    observed = (
        selection.get("interaction_edges_sha256"),
        selection.get("selection_sha256"),
        selection.get("subspace_plan_sha256"),
        selection.get("selected_coordinates"),
        trial.get("partitioned_coordinates"),
        trial.get("subspace_count"),
        trial.get("status_counts"),
        trial.get("found_assignments"),
        trial.get("verified_assignments"),
        trial.get("encoding", {}).get("unpartitioned_smt_sha256"),
        manifest_sha256,
        [row.get("subspace_index") for row in rows],
        [row.get("fixed_value") for row in rows],
        len(plan),
    )
    expected = (
        INTERACTION_EDGES_SHA256,
        SELECTION_SHA256,
        SUBSPACE_PLAN_SHA256,
        SELECTED_COORDINATES,
        SELECTED_COORDINATES,
        SUBSPACE_COUNT,
        {"sat": 0, "unsat": 0, "unknown": SUBSPACE_COUNT, "error": 0},
        [],
        [],
        UNPARTITIONED_SMT_SHA256,
        STRUCTURAL6_MANIFEST_SHA256,
        list(range(SUBSPACE_COUNT)),
        list(range(SUBSPACE_COUNT)),
        SUBSPACE_COUNT,
    )
    if observed != expected:
        raise RuntimeError("hash-gated Structural-6 selection/formula manifest differs")
    if trial.get("structural_selection") != selection:
        raise RuntimeError("retained Structural-6 trial and selection differ")
    return selection, trial


def _load_structural6_gate(path: Path) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    payload = _load_hashed_json(path, STRUCTURAL6_SHA256, "Structural-6")
    selection, trial = _structural6_gate(payload)
    return payload, selection, trial


def _canonical_inputs(
    variant: Any,
) -> tuple[Any, dict[str, Any]]:
    formula = _STRATEGY._canonical_formula(
        variant,
        WINDOW_BITS,
        SEED,
        UNPARTITIONED_SMT_SHA256,
    )
    selection = _STRUCTURAL6._derive_structural_selection(
        formula.problem["base_state"],
        variant,
        formula.problem["positions"],
        PARTITION_BITS,
    )
    _STRUCTURAL6._canonical_selection_gate(selection)
    _STRUCTURAL6._complete_subspace_plan_gate(selection)
    return formula, selection


def _render_winner_subspace(
    formula: Any,
    coordinates: list[int],
    fixed_value: int,
) -> tuple[bytes, dict[str, Any]]:
    canonical = _STRUCTURAL6._render_fixed_coordinates(
        formula.writer,
        formula.inputs,
        coordinates,
        fixed_value,
    )
    rendered = _STRATEGY._render_strategy(canonical, WINNER)
    audit = _STRATEGY._render_audit(canonical, rendered)
    if (
        rendered != canonical
        or audit["changed_line_indices_zero_based"]
        or not audit["get_value_preserved_byte_exact"]
        or audit["declaration_count"] != formula.encoding["total_variables"]
        or audit["assertion_count"] != formula.encoding["total_assertions"] + len(coordinates)
    ):
        raise RuntimeError("winner renderer failed the byte-identical partition formula gate")
    return rendered, audit


def _prepare_subspaces(
    formula: Any,
    selection: dict[str, Any],
    work_dir: Path,
    retained_trial: dict[str, Any] | None,
) -> tuple[list[dict[str, Any]], str]:
    coordinates = selection["selected_coordinates"]
    plan = _STRUCTURAL6._subspace_plan(formula.window_bits, coordinates)
    if selection.get("subspace_plan_sha256") != _STRUCTURAL6._canonical_sha256(plan):
        raise RuntimeError("prepared subspace plan differs from its formula-graph hash")
    retained_rows = (
        {row["subspace_index"]: row for row in retained_trial["subspaces_detail"]}
        if retained_trial is not None
        else {}
    )
    work_dir.mkdir(parents=True, exist_ok=True)
    prepared = []
    coordinate_label = "-".join(str(coordinate) for coordinate in coordinates)
    for plan_row in plan:
        fixed_value = plan_row["fixed_value"]
        rendered, audit = _render_winner_subspace(formula, coordinates, fixed_value)
        smt_sha256 = hashlib.sha256(rendered).hexdigest()
        source = retained_rows.get(plan_row["subspace_index"])
        if source is not None and (
            source.get("fixed_value") != fixed_value
            or source.get("smt_bytes") != len(rendered)
            or source.get("smt_sha256") != smt_sha256
        ):
            raise RuntimeError(
                f"subspace {plan_row['subspace_index']} differs from Structural-6 formula gate"
            )
        path = work_dir / (
            f"shake128_r1_w{formula.window_bits}_coords{coordinate_label}_"
            f"subspace{plan_row['subspace_index']:04d}_{WINNER}.smt2"
        )
        path.write_bytes(rendered)
        prepared.append(
            {
                **plan_row,
                "path": path,
                "smt_bytes": len(rendered),
                "smt_sha256": smt_sha256,
                "canonical_partition_smt_sha256": smt_sha256,
                "rendered_smt_sha256": smt_sha256,
                "winner_renderer_byte_identical": True,
                "render_audit": audit,
            }
        )
    manifest = _formula_manifest(prepared)
    manifest_sha256 = _STRUCTURAL6._canonical_sha256(manifest)
    if retained_trial is not None and manifest_sha256 != STRUCTURAL6_MANIFEST_SHA256:
        raise RuntimeError("regenerated Structural-6 formula manifest hash differs")
    return prepared, manifest_sha256


def _complete_rate_verification(
    problem: dict[str, Any],
    variant: Any,
    assignment: int,
) -> dict[str, Any]:
    verification = _STRATEGY._verify_assignment(problem, variant, assignment)
    if (
        verification.get("rate_bits_checked") != 1344
        or verification.get("rate_lanes_checked") != 21
        or not isinstance(verification.get("candidate_rate_sha256"), str)
        or not isinstance(verification.get("target_rate_sha256"), str)
    ):
        raise RuntimeError("independent verifier did not check the complete 1,344-bit rate")
    return verification


def _candidate_gate(rows: list[dict[str, Any]]) -> dict[str, Any]:
    found = []
    verified = []
    for row in rows:
        status = row["status"]
        assignment = row.get("assignment")
        verification = row.get("independent_verification")
        if status == "sat" and assignment is None:
            raise RuntimeError("a SAT subspace did not return the complete requested assignment")
        if status != "sat" and assignment is not None:
            raise RuntimeError("a non-SAT subspace unexpectedly returned an assignment")
        if assignment is None:
            if verification is not None:
                raise RuntimeError("a model-free subspace unexpectedly has a verification record")
            continue
        found.append(assignment)
        if (
            not isinstance(verification, dict)
            or verification.get("rate_bits_checked") != 1344
            or verification.get("rate_lanes_checked") != 21
            or verification.get("complete_rate_match") is not True
            or verification.get("candidate_rate_sha256") != verification.get("target_rate_sha256")
        ):
            raise RuntimeError("a solver model failed the independent complete-rate gate")
        verified.append(assignment)
    return {
        "found_assignments": found,
        "verified_assignments": verified,
        "all_found_assignments_independently_verified": found == verified,
        "candidate_count": len(found),
        "independent_verifier_rate_bits": 1344,
        "independent_verifier_rate_lanes": 21,
    }


def _partition_trial(
    formula: Any,
    variant: Any,
    selection: dict[str, Any],
    timeout_seconds: int,
    max_workers: int,
    z3: Path,
    work_dir: Path,
    keep_smt: bool,
    retained_trial: dict[str, Any] | None = None,
) -> dict[str, Any]:
    if timeout_seconds < 1 or max_workers < 1:
        raise ValueError("timeout and worker count must be positive")
    route = _STRATEGY._strategy(WINNER)
    prepared, manifest_sha256 = _prepare_subspaces(
        formula,
        selection,
        work_dir,
        retained_trial,
    )

    def solve(row: dict[str, Any]) -> dict[str, Any]:
        solver = _STRATEGY._run_z3(
            z3,
            row["path"],
            timeout_seconds,
            formula.inputs,
        )
        return {
            **{key: value for key, value in row.items() if key != "path"},
            "remaining_variables": formula.window_bits - len(selection["selected_coordinates"]),
            "strategy": route.name,
            "logic": route.logic,
            "check_sat_form": route.check_sat,
            "timeout_seconds": timeout_seconds,
            "threads": 1,
            "status": solver["status"],
            "return_code": solver["return_code"],
            "external_timeout": solver["external_timeout"],
            "stats": solver["stats"],
            "selection_metrics": solver["selection_metrics"],
            "assignment": solver["assignment"],
            "solver_invocation": {
                "command": solver["command"],
                "stdout_bytes": solver["stdout_bytes"],
                "stdout_sha256": solver["stdout_sha256"],
                "stderr_bytes": solver["stderr_bytes"],
                "stderr_sha256": solver["stderr_sha256"],
                "combined_output_sha256": solver["combined_output_sha256"],
                "diagnostics": solver["diagnostics"],
            },
        }

    try:
        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
            rows = sorted(
                executor.map(solve, prepared),
                key=lambda row: row["subspace_index"],
            )
    finally:
        if not keep_smt:
            for row in prepared:
                row["path"].unlink(missing_ok=True)

    actual = _WINDOW._extract_window(
        formula.problem["base_state"],
        variant,
        formula.problem["positions"],
    )
    for row in rows:
        assignment = row["assignment"]
        row["independent_verification"] = (
            _complete_rate_verification(formula.problem, variant, assignment)
            if assignment is not None
            else None
        )
        row["matches_instrumented_assignment_posthoc"] = (
            assignment == actual if assignment is not None else None
        )
        row["ground_truth_used_for_plan_renderer_or_execution"] = False

    candidate_gate = _candidate_gate(rows)
    statuses = ("sat", "unsat", "unknown", "error")
    status_counts = {status: sum(row["status"] == status for row in rows) for status in statuses}
    distinct_verified = sorted(set(candidate_gate["verified_assignments"]))
    work_totals = {
        metric: {
            "reported_subspaces": sum(
                row["selection_metrics"].get(metric) is not None for row in rows
            ),
            "total": sum(row["selection_metrics"].get(metric) or 0.0 for row in rows),
        }
        for metric in ("decisions", "conflicts")
    }
    coordinates = selection["selected_coordinates"]
    return {
        "variant": variant.name,
        "window_bits": formula.window_bits,
        "seed": formula.seed,
        "symbolic_prefix_rounds": formula.encoding["symbolic_prefix_rounds"],
        "canonical_unpartitioned_smt_bytes": len(formula.raw),
        "canonical_unpartitioned_smt_sha256": formula.sha256,
        "partition_bits": len(coordinates),
        "partitioned_coordinates": coordinates,
        "subspace_schedule": "ascending_unsigned_fixed_coordinate_values",
        "subspace_count": len(rows),
        "subspaces_are_pairwise_disjoint": True,
        "subspaces_cover_complete_assignment_space": True,
        "subspace_formula_manifest_sha256": manifest_sha256,
        "strategy": route.name,
        "logic": route.logic,
        "check_sat_form": route.check_sat,
        "winner_renderer_byte_identical_for_every_subspace": all(
            row["winner_renderer_byte_identical"] for row in rows
        ),
        "timeout_seconds_per_subspace": timeout_seconds,
        "max_workers": max_workers,
        "solver_threads_per_worker": 1,
        "selection_completed_before_subspace_execution": True,
        "strategy_selected_before_subspace_execution": True,
        "stored_assignment_used_for_plan_renderer_or_execution": False,
        "posthoc_assignment_used_for_plan_renderer_or_execution": False,
        "target_end_state_bits_used_for_partition_selection": False,
        "actual_assignment_posthoc": actual,
        "actual_fixed_value_posthoc": _STRUCTURAL6._UPPER._project_assignment(actual, coordinates),
        "status_counts": status_counts,
        **candidate_gate,
        "distinct_found_assignments": sorted(set(candidate_gate["found_assignments"])),
        "reconstructed_assignment": (distinct_verified[0] if len(distinct_verified) == 1 else None),
        "reconstruction_matches_instrumented_assignment": distinct_verified == [actual],
        "all_subspaces_resolved": (status_counts["unknown"] == 0 and status_counts["error"] == 0),
        "solver_work_totals": work_totals,
        "subspaces_detail": rows,
    }


def _build_graph(
    path: Path,
    selection: dict[str, Any],
    trial: dict[str, Any],
) -> tuple[dict[str, Any], list[dict[str, Any]], dict[str, Any]]:
    builder = CryptoCausalBuilder(
        experiment="shake_symbolic_r1_z3_structural6_partition_reader",
        parameters={
            "variant": "shake128",
            "window_bits": WINDOW_BITS,
            "symbolic_prefix_rounds": 1,
            "strategy_frontier_sha256": STRATEGY_FRONTIER_SHA256,
            "structural6_sha256": STRUCTURAL6_SHA256,
            "unpartitioned_smt_sha256": UNPARTITIONED_SMT_SHA256,
            "selected_strategy": WINNER,
            "selected_coordinates": SELECTED_COORDINATES,
            "subspace_count": SUBSPACE_COUNT,
            "timeout_seconds_per_subspace": trial["timeout_seconds_per_subspace"],
            "max_workers": trial["max_workers"],
        },
    )
    inputs_id = "r1-z3-structural6-hash-gated-inputs"
    plan_id = "r1-z3-winner-structural6-complete-plan"
    observations_id = "r1-z3-structural6-neutral-observations"
    builder.add_triplet(
        edge_id=inputs_id,
        trigger="retained:Z3_strategy_frontier_and_Structural6_artifacts",
        mechanism="verify_both_file_hashes_and_the_shared_canonical_width20_R1_formula",
        outcome="SHAKE128:hash_gated_winner_and_formula_graph_plan",
        confidence=1.0,
        evidence_kind="two_file_hashes_plus_shared_unpartitioned_SMT_hash",
        source="retained_Z3_strategy_frontier_and_Structural6_reader",
        attrs={
            "strategy_frontier_sha256": STRATEGY_FRONTIER_SHA256,
            "structural6_sha256": STRUCTURAL6_SHA256,
            "unpartitioned_smt_sha256": UNPARTITIONED_SMT_SHA256,
            "selected_strategy": WINNER,
            "selection_metric": "decisions",
            "selection_metric_value": WINNER_DECISIONS,
        },
    )
    builder.add_triplet(
        edge_id=plan_id,
        trigger="SHAKE128:hash_gated_winner_and_formula_graph_plan",
        mechanism=(
            "render_the_exact_QF_UF_default_winner_byte_identically_over_all_64_"
            "formula_graph_selected_subspaces"
        ),
        outcome="SHAKE128:complete_disjoint_winner_rendered_Structural6_plan",
        confidence=1.0,
        evidence_kind="formula_hash_renderer_audit_and_complete_disjoint_plan_gates",
        source="retained_winner_plus_regenerated_canonical_partition_formulas",
        provenance=[inputs_id],
        attrs={
            "interaction_edges_sha256": selection["interaction_edges_sha256"],
            "selection_sha256": selection["selection_sha256"],
            "subspace_plan_sha256": selection["subspace_plan_sha256"],
            "subspace_formula_manifest_sha256": trial["subspace_formula_manifest_sha256"],
            "selected_coordinates": selection["selected_coordinates"],
            "subspace_count": trial["subspace_count"],
            "winner_renderer_byte_identical_for_every_subspace": trial[
                "winner_renderer_byte_identical_for_every_subspace"
            ],
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
        edge_id=observations_id,
        trigger="SHAKE128:complete_disjoint_winner_rendered_Structural6_plan",
        mechanism=(
            "execute_equal_limit_subspaces_and_check_every_candidate_with_the_"
            "independent_complete_1344_bit_rate_transform"
        ),
        outcome="SHAKE128:bounded_Structural6_status_and_verified_candidate_observations",
        confidence=1.0,
        evidence_kind="bounded_statuses_and_independent_complete_rate_candidate_checks",
        source="local_Z3_and_independent_bit_sliced_transform_core",
        provenance=[plan_id],
        attrs={
            "status_counts": trial["status_counts"],
            "found_assignments": trial["found_assignments"],
            "verified_assignments": trial["verified_assignments"],
            "candidate_checks": candidate_checks,
            "all_found_assignments_independently_verified": trial[
                "all_found_assignments_independently_verified"
            ],
            "independent_verifier_rate_bits": 1344,
            "claim_policy": "statuses_and_independently_verified_candidates_only",
            "outcome_based_partition_or_strategy_selection": False,
        },
    )
    stats = builder.save(path)
    reader = CryptoCausalReader(path)
    rows = reader.triplets(include_inferred=False)
    by_id = {row["edge_id"]: row for row in rows}
    expected_ids = {inputs_id, plan_id, observations_id}
    chain_ok = (
        len(rows) == 3
        and set(by_id) == expected_ids
        and by_id[plan_id]["provenance"] == [inputs_id]
        and by_id[observations_id]["provenance"] == [plan_id]
        and by_id[inputs_id]["outcome"] == by_id[plan_id]["trigger"]
        and by_id[plan_id]["outcome"] == by_id[observations_id]["trigger"]
    )
    hash_binding_ok = bool(
        by_id.get(inputs_id, {}).get("attrs", {}).get("unpartitioned_smt_sha256")
        == UNPARTITIONED_SMT_SHA256
        and by_id.get(plan_id, {}).get("attrs", {}).get("selection_sha256") == SELECTION_SHA256
        and by_id.get(plan_id, {}).get("attrs", {}).get("subspace_plan_sha256")
        == SUBSPACE_PLAN_SHA256
        and by_id.get(plan_id, {}).get("attrs", {}).get("subspace_formula_manifest_sha256")
        == trial["subspace_formula_manifest_sha256"]
    )
    neutral_ok = bool(
        by_id.get(observations_id, {}).get("attrs", {}).get("claim_policy")
        == "statuses_and_independently_verified_candidates_only"
        and by_id.get(observations_id, {})
        .get("attrs", {})
        .get("outcome_based_partition_or_strategy_selection")
        is False
    )
    gate = {
        "reader_verify_provenance": reader.verify_provenance(),
        "explicit_triplet_count": len(rows),
        "exact_three_edge_chain": chain_ok,
        "hash_binding_verified": hash_binding_ok,
        "neutral_observation_gate": neutral_ok,
        "reader_file_sha256": reader.file_sha256,
        "reader_graph_sha256": reader.graph_sha256,
        "passed": (reader.verify_provenance() and chain_ok and hash_binding_ok and neutral_ok),
    }
    if not gate["passed"]:
        raise RuntimeError("combined Z3 Structural-6 causal Reader gate failed")
    return stats, rows, gate


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--z3", type=Path, default=Path(shutil.which("z3") or "/opt/homebrew/bin/z3")
    )
    parser.add_argument(
        "--strategy-frontier",
        type=Path,
        default=Path("research/results/v1/shake_symbolic_r1_z3_strategy_frontier_v1.json"),
    )
    parser.add_argument(
        "--structural6",
        type=Path,
        default=Path("research/results/v1/shake_symbolic_r1_structural6_partition_reader_v1.json"),
    )
    parser.add_argument(
        "--work-dir",
        type=Path,
        default=Path("build/shake-symbolic-r1-z3-structural6-partition"),
    )
    parser.add_argument("--keep-smt", action="store_true")
    parser.add_argument(
        "--output",
        type=Path,
        default=Path(
            "research/results/v1/shake_symbolic_r1_z3_structural6_partition_reader_v1.json"
        ),
    )
    parser.add_argument(
        "--causal-output",
        type=Path,
        default=Path(
            "research/results/v1/shake_symbolic_r1_z3_structural6_partition_reader_v1.causal"
        ),
    )
    args = parser.parse_args()

    z3 = Path(shutil.which(str(args.z3)) or args.z3)
    if not z3.is_file():
        raise FileNotFoundError(f"Z3 executable not found: {args.z3}")
    version = subprocess.run(
        [str(z3), "-version"], check=True, capture_output=True, text=True
    ).stdout.strip()
    args.causal_output.parent.mkdir(parents=True, exist_ok=True)

    _, strategy_gate = _load_strategy_gate(args.strategy_frontier)
    _, retained_selection, retained_trial = _load_structural6_gate(args.structural6)
    variant = _BASE.VARIANTS["shake128"]
    formula, selection = _canonical_inputs(variant)
    if selection != retained_selection:
        raise RuntimeError("regenerated Structural-6 selection differs from retained artifact")

    print(
        f"executing {SUBSPACE_COUNT} Structural-6 subspaces with {WINNER}, "
        f"timeout={TIMEOUT_SECONDS}s workers={MAX_WORKERS}",
        flush=True,
    )
    trial = _partition_trial(
        formula,
        variant,
        selection,
        TIMEOUT_SECONDS,
        MAX_WORKERS,
        z3,
        args.work_dir,
        args.keep_smt,
        retained_trial,
    )
    if (
        trial["subspace_count"] != SUBSPACE_COUNT
        or trial["partitioned_coordinates"] != SELECTED_COORDINATES
        or sum(trial["status_counts"].values()) != SUBSPACE_COUNT
        or trial["subspace_formula_manifest_sha256"] != STRUCTURAL6_MANIFEST_SHA256
        or not trial["all_found_assignments_independently_verified"]
    ):
        raise RuntimeError("combined production trial failed its aggregate gates")

    causal, reader_triplets, reader_gate = _build_graph(
        args.causal_output,
        selection,
        trial,
    )
    payload = {
        "schema": "shake-symbolic-r1-z3-structural6-partition-reader-v1",
        "evidence_stage": "HASH_GATED_Z3_WINNER_STRUCTURAL6_OBSERVATIONS_RECORDED",
        "result": (
            "The hash-gated width-16 Z3 strategy winner was applied byte-identically "
            "to all 64 formula-graph-selected width-20 subspaces; bounded statuses and "
            "independently verified complete-rate candidates are recorded neutrally."
        ),
        "scope": (
            "One canonical SHAKE128 width-20 seed-89755037 R1 Boolean constraint "
            "system, using the retained winner and the complete disjoint Structural-6 plan."
        ),
        "parameters": {
            "solver": version,
            "solver_threads_per_worker": 1,
            "max_workers": MAX_WORKERS,
            "timeout_seconds_per_subspace": TIMEOUT_SECONDS,
            "window_bits": WINDOW_BITS,
            "seed": SEED,
            "partition_bits": PARTITION_BITS,
            "partitioned_coordinates": SELECTED_COORDINATES,
            "subspace_count": SUBSPACE_COUNT,
            "symbolic_prefix_rounds": 1,
            "strategy_frontier_sha256": STRATEGY_FRONTIER_SHA256,
            "structural6_sha256": STRUCTURAL6_SHA256,
            "unpartitioned_smt_sha256": UNPARTITIONED_SMT_SHA256,
            "interaction_edges_sha256": INTERACTION_EDGES_SHA256,
            "selection_sha256": SELECTION_SHA256,
            "subspace_plan_sha256": SUBSPACE_PLAN_SHA256,
            "subspace_formula_manifest_sha256": STRUCTURAL6_MANIFEST_SHA256,
            "strategy_selected_before_subspace_execution": True,
            "partition_selected_before_subspace_execution": True,
            "actual_or_posthoc_assignment_used_for_selection": False,
            "outcome_based_selection": False,
        },
        "source_gates": {
            "strategy_frontier": strategy_gate,
            "structural6": {
                "selected_coordinates": retained_selection["selected_coordinates"],
                "interaction_edges_sha256": retained_selection["interaction_edges_sha256"],
                "selection_sha256": retained_selection["selection_sha256"],
                "subspace_plan_sha256": retained_selection["subspace_plan_sha256"],
                "subspace_formula_manifest_sha256": STRUCTURAL6_MANIFEST_SHA256,
                "retained_status_counts": retained_trial["status_counts"],
            },
        },
        "selection": selection,
        "trial": trial,
        "kat": _BASE._kat(),
        "causal": causal,
        "reader_triplets": reader_triplets,
        "reader_gate": reader_gate,
    }
    raw = (json.dumps(payload, indent=2, sort_keys=True) + "\n").encode()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_bytes(raw)
    print(
        json.dumps(
            {
                "output": str(args.output),
                "json_sha256": hashlib.sha256(raw).hexdigest(),
                "causal_output": str(args.causal_output),
                "causal_sha256": causal["file_sha256"],
                "graph_sha256": causal["graph_sha256"],
                "strategy": trial["strategy"],
                "selected_coordinates": trial["partitioned_coordinates"],
                "status_counts": trial["status_counts"],
                "found_assignments": trial["found_assignments"],
                "verified_assignments": trial["verified_assignments"],
                "all_found_assignments_independently_verified": trial[
                    "all_found_assignments_independently_verified"
                ],
                "subspace_formula_manifest_sha256": trial["subspace_formula_manifest_sha256"],
                "reader_gate": reader_gate,
            },
            indent=2,
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    main()

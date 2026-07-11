#!/usr/bin/env python3
"""Prospectively frozen new-seed transfer of the SHAKE128 R1 graph Reader.

The production path refuses to instantiate the new target until the exact
protocol file is present in a supplied public Git commit.  Runtime selection
uses only the cleared-window R1 polynomial graph, proves an exact minimum
vertex cover, and freezes the complete projection schedule before solver work.
The instrumented assignment is extracted only after execution is complete.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import itertools
import json
import math
import re
import shutil
import subprocess
import sys
from collections.abc import Sequence
from pathlib import Path
from typing import Any


def _import_sibling(filename: str, module_name: str) -> Any:
    path = Path(__file__).with_name(filename)
    spec = importlib.util.spec_from_file_location(module_name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


_A151: Any = None
_FRONTIER: Any = None
_BASE: Any = None
_NATIVE: Any = None
_WINDOW: Any = None
_R1: Any = None
_CryptoCausalBuilder: Any = None
_CryptoCausalReader: Any = None
_BASE_RENDER_FIXED_COORDINATES: Any = None
_RUNTIME_MODULES_LOADED = False

ATTEMPT_ID = "A152"
WINDOW_BITS = 24
SYMBOLIC_PREFIX_ROUNDS = 1
UNIFORM_TIMEOUT_SECONDS = 120
MAX_PROCESSES = 5
WAVE_SIZE = 5
SOLVER_THREADS_PER_PROCESS = 1
MAX_COVER_BITS_FOR_EXECUTION = 12
EXPECTED_Z3_VERSION_PREFIX = "Z3 version 4.15.4 "
PUBLIC_REPOSITORY = "https://github.com/DT-Foss/f8-causal-cryptanalysis"
PUBLIC_FETCH_URL = f"{PUBLIC_REPOSITORY}.git"
PROTOCOL_RELATIVE_PATH = "research/configs/shake_symbolic_r1_width24_prospective_transfer_v1.json"
RUNNER_RELATIVE_PATH = "research/experiments/shake_symbolic_r1_width24_prospective_transfer.py"
PROTOCOL_SHA256 = "0fd33d09108a3aabccd8dfa38131eee074f7b56ba4fede52e23fa1fe29843bc4"
A151_RELATIVE_PATH = "research/results/v1/shake_symbolic_r1_width24_vertex_cover_reader_v1.json"
A151_SHA256 = "3ea9f21a6cfde4f5728f4860181b4d32317be9d9eeb7296b3b81427faa1d75ee"
RESULT_FILENAME = "shake_symbolic_r1_width24_prospective_transfer_v1.json"
CAUSAL_FILENAME = "shake_symbolic_r1_width24_prospective_transfer_v1.causal"
SEED_LABEL = b"f8-causal:A152:prospective-shake128-r1-width24-transfer:v1|"
EXPECTED_SEED_DIGEST = "8f8854215b3702428d90fea9c8d02f55fdda697fcd1d5a599a17758dfa2c15ce"
EXPECTED_SEED = 260_592_673


def _sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _canonical_sha256(value: Any) -> str:
    raw = json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode()
    return _sha256(raw)


def _subspace_plan(window_bits: int, fixed_coordinates: Sequence[int]) -> list[dict[str, Any]]:
    coordinates = [int(value) for value in fixed_coordinates]
    if (
        window_bits < 1
        or coordinates != sorted(set(coordinates))
        or any(value < 0 or value >= window_bits for value in coordinates)
    ):
        raise ValueError("fixed coordinates must be sorted unique window indices")
    fixed_set = set(coordinates)
    free = [value for value in range(window_bits) if value not in fixed_set]
    return [
        {
            "subspace_index": value,
            "fixed_value": value,
            "fixed_coordinates": [
                {"coordinate": coordinate, "value": (value >> bit) & 1}
                for bit, coordinate in enumerate(coordinates)
            ],
            "free_coordinates": free,
            "logical_assignments": 1 << len(free),
        }
        for value in range(1 << len(coordinates))
    ]


def _project_assignment(assignment: int, coordinates: Sequence[int]) -> int:
    return sum(
        ((assignment >> coordinate) & 1) << bit for bit, coordinate in enumerate(coordinates)
    )


def _render_fixed_coordinates_allow_empty(
    writer: Any,
    inputs: list[str],
    fixed_coordinates: Sequence[int],
    fixed_value: int,
    *,
    include_model: bool = True,
) -> bytes:
    coordinates = list(fixed_coordinates)
    if coordinates:
        return _BASE_RENDER_FIXED_COORDINATES(
            writer,
            inputs,
            coordinates,
            fixed_value,
            include_model=include_model,
        )
    if fixed_value != 0:
        raise ValueError("empty vertex-cover projection has only value zero")
    return writer.render(inputs, include_model=include_model)


def _load_runtime_modules(execution_repo: Path) -> dict[str, Any]:
    """Load every repository-local dependency only after the public freeze gate."""
    global _A151, _BASE, _BASE_RENDER_FIXED_COORDINATES
    global _CryptoCausalBuilder, _CryptoCausalReader
    global _FRONTIER, _NATIVE, _R1, _RUNTIME_MODULES_LOADED, _WINDOW

    if _RUNTIME_MODULES_LOADED:
        raise RuntimeError("runtime modules may be loaded only once after the freeze gate")
    from arx_carry_leak import crypto_causal

    package_path = Path(crypto_causal.__file__).resolve()
    expected_package_root = (execution_repo / "src" / "arx_carry_leak").resolve()
    if not package_path.is_relative_to(expected_package_root):
        raise RuntimeError(
            f"arx_carry_leak resolved outside the frozen public worktree: {package_path}"
        )
    _A151 = _import_sibling(
        "shake_symbolic_r1_width24_vertex_cover_reader.py",
        "shake_symbolic_r1_width24_prospective_a151",
    )
    _FRONTIER = _A151._FRONTIER
    _BASE = _A151._BASE
    _NATIVE = _A151._NATIVE
    _WINDOW = _A151._WINDOW
    _R1 = _A151._R1
    _BASE_RENDER_FIXED_COORDINATES = _A151._render_fixed_coordinates
    _A151._render_fixed_coordinates = _render_fixed_coordinates_allow_empty
    _CryptoCausalBuilder = crypto_causal.CryptoCausalBuilder
    _CryptoCausalReader = crypto_causal.CryptoCausalReader
    numpy_version = str(_NATIVE.np.__version__)
    if numpy_version != "1.26.4":
        raise RuntimeError(f"NumPy version differs; expected 1.26.4, observed {numpy_version}")
    _RUNTIME_MODULES_LOADED = True
    return {
        "repository_dependency_root": "public_freeze_commit",
        "crypto_causal_relative_path": str(package_path.relative_to(execution_repo)),
        "numpy_version": numpy_version,
        "loaded_after_public_freeze_gate": True,
    }


def _load_protocol(path: Path) -> dict[str, Any]:
    raw = path.read_bytes()
    observed = _sha256(raw)
    if observed != PROTOCOL_SHA256:
        raise RuntimeError(f"prospective protocol hash differs: {observed}")
    payload = json.loads(raw)
    seed = payload.get("seed_derivation", {})
    solver = payload.get("solver_plan", {})
    artifacts = payload.get("artifact_contract", {})
    boundary = payload.get("prospective_boundary", {})
    if (
        payload.get("schema") != "shake-symbolic-r1-width24-prospective-transfer-protocol-v1"
        or payload.get("attempt_id") != ATTEMPT_ID
        or payload.get("protocol_state") != "frozen_before_new_instance_generation"
        or payload.get("anchor", {}).get("sha256") != A151_SHA256
        or seed.get("digest_hex") != EXPECTED_SEED_DIGEST
        or seed.get("derived_seed") != EXPECTED_SEED
        or solver.get("required_version") != "4.15.4"
        or solver.get("timeout_seconds_per_projection") != UNIFORM_TIMEOUT_SECONDS
        or solver.get("maximum_parallel_processes") != MAX_PROCESSES
        or solver.get("wave_size") != WAVE_SIZE
        or solver.get("maximum_minimum_vertex_cover_bits_for_solver_execution")
        != MAX_COVER_BITS_FOR_EXECUTION
        or solver.get("larger_cover_action")
        != "write_structure_only_resource_boundary_without_solver_or_assignment_extraction"
        or artifacts.get("result_filename") != RESULT_FILENAME
        or artifacts.get("causal_filename") != CAUSAL_FILENAME
        or artifacts.get("local_invocation_paths_excluded_from_canonical_payload") is not True
        or artifacts.get("json_and_causal_reopened_after_final_write") is not True
        or boundary.get("blind_new_instance_transfer") is not True
        or boundary.get(
            "mechanism_and_schedule_generation_rule_frozen_from_A151_before_new_seed_execution"
        )
        is not True
        or boundary.get("historical_A148_through_A151_informed_mechanism_and_budget") is not True
        or boundary.get(
            "new_graph_may_control_only_declared_structural_selection_and_schedule_rules"
        )
        is not True
        or boundary.get("new_seed_assignment_projection_and_solver_outcomes_informed_protocol")
        is not False
        or boundary.get("execution_must_use_clean_public_commit_worktree") is not True
        or boundary.get("instrumented_assignment_compared_only_after_execution") is not True
    ):
        raise RuntimeError("prospective protocol semantic gate failed")
    return payload


def _load_anchor(path: Path) -> dict[str, Any]:
    raw = path.read_bytes()
    observed = _sha256(raw)
    if observed != A151_SHA256:
        raise RuntimeError(f"A151 anchor hash differs: {observed}")
    payload = json.loads(raw)
    if payload.get("schema") != "shake-symbolic-r1-width24-vertex-cover-reader-v1":
        raise RuntimeError("A151 anchor schema differs")
    return {
        "logical_path": A151_RELATIVE_PATH,
        "sha256": observed,
        "schema": payload["schema"],
        "reconstructed_assignment_imported": False,
        "projection_imported": False,
        "solver_observations_imported": False,
    }


def _derive_seed(anchor_sha256: str = A151_SHA256) -> dict[str, Any]:
    digest = hashlib.sha256(SEED_LABEL + bytes.fromhex(anchor_sha256)).digest()
    seed = int.from_bytes(digest[:4], "big") & 0x7FFFFFFF
    result = {
        "label_ascii": SEED_LABEL.decode(),
        "anchor_sha256": anchor_sha256,
        "digest_sha256": digest.hex(),
        "derived_seed": seed,
    }
    if digest.hex() != EXPECTED_SEED_DIGEST or seed != EXPECTED_SEED:
        raise RuntimeError("prospective seed derivation differs")
    return result


def _z3_version_gate(version: str) -> str:
    if not version.startswith(EXPECTED_Z3_VERSION_PREFIX):
        raise RuntimeError(
            f"Z3 CLI version differs; expected semantic version 4.15.4, observed: {version}"
        )
    return version


def _has_exact_public_fetch_remote(repo: Path) -> bool:
    remote_names = subprocess.run(
        ["git", "remote"],
        cwd=repo,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.splitlines()
    accepted_fetch_urls = {
        PUBLIC_FETCH_URL,
        PUBLIC_REPOSITORY,
        "git@github.com:DT-Foss/f8-causal-cryptanalysis.git",
        "ssh://git@github.com/DT-Foss/f8-causal-cryptanalysis.git",
    }
    return any(
        subprocess.run(
            ["git", "remote", "get-url", remote_name],
            cwd=repo,
            check=True,
            capture_output=True,
            text=True,
        ).stdout.strip()
        in accepted_fetch_urls
        for remote_name in remote_names
    )


def _public_freeze_gate(repo: Path, commit: str) -> dict[str, Any]:
    if not re.fullmatch(r"[0-9a-fA-F]{40}", commit):
        raise ValueError("public freeze commit must be a full 40-hex Git object id")
    repo = repo.resolve()
    if not (repo / ".git").exists():
        raise FileNotFoundError(f"public freeze repository is not a Git worktree: {repo}")
    expected_runner = (repo / RUNNER_RELATIVE_PATH).resolve()
    if Path(__file__).resolve() != expected_runner:
        raise RuntimeError("A152 must execute from the supplied frozen public worktree")
    if not _has_exact_public_fetch_remote(repo):
        raise RuntimeError("freeze worktree has no exact public GitHub fetch remote")
    subprocess.run(
        ["git", "fetch", "--no-tags", "--quiet", PUBLIC_FETCH_URL, "refs/heads/main"],
        cwd=repo,
        check=True,
        capture_output=True,
        text=True,
    )
    public_main_head = subprocess.run(
        ["git", "rev-parse", "FETCH_HEAD"],
        cwd=repo,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    resolved = subprocess.run(
        ["git", "rev-parse", f"{commit}^{{commit}}"],
        cwd=repo,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    ancestry = subprocess.run(
        ["git", "merge-base", "--is-ancestor", resolved, public_main_head],
        cwd=repo,
        check=False,
        capture_output=True,
        text=True,
    )
    if ancestry.returncode != 0:
        raise RuntimeError("freeze commit is not an ancestor of freshly fetched public main")
    head = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=repo,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    if head != resolved:
        raise RuntimeError("executing worktree HEAD is not the supplied public freeze commit")
    status = subprocess.run(
        ["git", "status", "--porcelain", "--untracked-files=all"],
        cwd=repo,
        check=True,
        capture_output=True,
        text=True,
    ).stdout
    if status:
        raise RuntimeError("executing public freeze worktree is not clean")
    raw = subprocess.run(
        ["git", "show", f"{resolved}:{PROTOCOL_RELATIVE_PATH}"],
        cwd=repo,
        check=True,
        capture_output=True,
    ).stdout
    observed = _sha256(raw)
    if observed != PROTOCOL_SHA256:
        raise RuntimeError(f"publicly committed protocol hash differs: {observed}")
    committed_runner = subprocess.run(
        ["git", "show", f"{resolved}:{RUNNER_RELATIVE_PATH}"],
        cwd=repo,
        check=True,
        capture_output=True,
    ).stdout
    local_runner_sha256 = _sha256(Path(__file__).read_bytes())
    committed_runner_sha256 = _sha256(committed_runner)
    if committed_runner_sha256 != local_runner_sha256:
        raise RuntimeError(
            "executing runner differs from the publicly committed runner: "
            f"local={local_runner_sha256}, committed={committed_runner_sha256}"
        )
    return {
        "passed": True,
        "repository": PUBLIC_REPOSITORY,
        "commit": resolved,
        "fresh_public_main_ancestry_verified": True,
        "executing_worktree_head_is_freeze_commit": True,
        "executing_worktree_clean": True,
        "protocol_relative_path": PROTOCOL_RELATIVE_PATH,
        "protocol_sha256": observed,
        "runner_relative_path": RUNNER_RELATIVE_PATH,
        "runner_sha256": committed_runner_sha256,
        "gate_completed_before_instance_generation": True,
    }


def _sanitized_runtime_problem(problem: dict[str, Any], variant: Any) -> dict[str, Any]:
    """Remove the instrumented window values while retaining the public relation."""
    template = _WINDOW._clear_window(problem["base_state"], variant, problem["positions"])
    return {
        "base_state": template,
        "positions": problem["positions"].copy(),
        "target": problem["target"].copy(),
        "template": template.copy(),
    }


def _runtime_instance_summary(runtime_problem: dict[str, Any], variant: Any) -> dict[str, Any]:
    positions = [int(value) for value in runtime_problem["positions"]]
    template_raw = runtime_problem["template"].astype("<u8", copy=False).tobytes()
    target_raw = (
        runtime_problem["target"][:, : variant.rate_lanes].astype("<u8", copy=False).tobytes()
    )
    return {
        "capacity_window_positions": positions,
        "capacity_window_start_bit": positions[0],
        "capacity_window_stop_bit_exclusive": positions[-1] + 1,
        "cleared_template_sha256": _sha256(template_raw),
        "target_rate_lanes": variant.rate_lanes,
        "target_rate_bits": variant.rate_lanes * 64,
        "target_rate_sha256": _sha256(target_raw),
        "instrumented_assignment_or_projection_included": False,
    }


def _exact_minimum_vertex_cover(edges: Sequence[Sequence[int]], window_bits: int) -> dict[str, Any]:
    normalized_set: set[tuple[int, int]] = set()
    for edge in edges:
        values = tuple(sorted(map(int, edge)))
        if len(values) != 2:
            raise ValueError("each interaction edge must contain exactly two coordinates")
        normalized_set.add(values)
    normalized = sorted(normalized_set)
    if any(left < 0 or right >= window_bits or left == right for left, right in normalized):
        raise ValueError("interaction graph is not a simple graph on the window coordinates")
    edge_masks = [(1 << left) | (1 << right) for left, right in normalized]
    checked_by_size: dict[str, int] = {}
    selected: tuple[int, ...] | None = None
    cover_count = 0
    for size in range(window_bits + 1):
        checked = 0
        for candidate in itertools.combinations(range(window_bits), size):
            checked += 1
            mask = sum(1 << coordinate for coordinate in candidate)
            if all(mask & edge_mask for edge_mask in edge_masks):
                if selected is None:
                    selected = candidate
                cover_count += 1
        checked_by_size[str(size)] = checked
        if selected is not None:
            break
    if selected is None:
        raise RuntimeError("minimum vertex-cover enumeration returned no cover")
    selected_set = set(selected)
    uncovered = [
        [left, right]
        for left, right in normalized
        if left not in selected_set and right not in selected_set
    ]
    expected_by_size = {
        str(size): math.comb(window_bits, size) for size in range(len(selected) + 1)
    }
    proof_core = {
        "window_bits": window_bits,
        "interaction_edges": [list(edge) for edge in normalized],
        "interaction_edges_sha256": _canonical_sha256([list(edge) for edge in normalized]),
        "selected_coordinates": list(selected),
        "minimum_vertex_cover_size": len(selected),
        "minimum_cover_count": cover_count,
        "lexicographically_first_minimum_cover": True,
        "subsets_exhaustively_checked_by_size": checked_by_size,
        "expected_subset_count_by_size": expected_by_size,
        "all_sizes_through_minimum_exhausted": checked_by_size == expected_by_size,
        "uncovered_edges": uncovered,
        "selected_set_is_vertex_cover": not uncovered,
        "assignment_input_used": False,
        "target_rate_input_used": False,
        "solver_observations_used": False,
    }
    if (
        not proof_core["selected_set_is_vertex_cover"]
        or not proof_core["all_sizes_through_minimum_exhausted"]
    ):
        raise RuntimeError("minimum vertex-cover enumeration proof is incomplete")
    return {**proof_core, "proof_sha256": _canonical_sha256(proof_core)}


def _derive_structural_selection(
    runtime_problem: dict[str, Any], variant: Any
) -> tuple[dict[str, Any], dict[str, Any]]:
    graph, _ = _FRONTIER._derive_graph_and_depths(
        runtime_problem["base_state"],
        variant,
        runtime_problem["positions"],
        (1,),
    )
    proof = _exact_minimum_vertex_cover(graph["interaction_edges"], WINDOW_BITS)
    selection_core = {
        **graph,
        "selected_coordinates": proof["selected_coordinates"],
        "partition_bits": proof["minimum_vertex_cover_size"],
        "free_coordinates": [
            coordinate
            for coordinate in range(WINDOW_BITS)
            if coordinate not in set(proof["selected_coordinates"])
        ],
        "minimum_vertex_cover_proof_sha256": proof["proof_sha256"],
        "actual_assignment_used": False,
        "target_end_state_bits_used": False,
        "solver_observations_used": False,
    }
    selection = {**selection_core, "selection_sha256": _canonical_sha256(selection_core)}
    return selection, proof


def _linearization_score(
    value: int, coordinates: Sequence[int], edges: Sequence[Sequence[int]]
) -> tuple[int, list[list[int]], list[list[int]], list[list[int]]]:
    selected_index = {coordinate: bit for bit, coordinate in enumerate(coordinates)}
    retained: list[list[int]] = []
    deleted: list[list[int]] = []
    constant: list[list[int]] = []
    for raw_edge in edges:
        left, right = map(int, raw_edge)
        selected_endpoints = [node for node in (left, right) if node in selected_index]
        if not selected_endpoints:
            raise RuntimeError("vertex-cover schedule encountered an uncovered edge")
        if len(selected_endpoints) == 2:
            constant.append([left, right])
            continue
        fixed = selected_endpoints[0]
        if (value >> selected_index[fixed]) & 1:
            retained.append([left, right])
        else:
            deleted.append([left, right])
    return len(retained), retained, deleted, constant


def _freeze_plan(selection: dict[str, Any]) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    coordinates = list(selection["selected_coordinates"])
    ascending = _subspace_plan(WINDOW_BITS, coordinates)
    by_value = {int(row["fixed_value"]): row for row in ascending}
    scored = []
    for value in range(1 << len(coordinates)):
        score, retained, deleted, constant = _linearization_score(
            value, coordinates, selection["interaction_edges"]
        )
        scored.append((value, score, retained, deleted, constant))
    scored.sort(key=lambda row: (-row[1], -row[0].bit_count(), row[0]))
    plan = []
    for schedule_index, (value, score, retained, deleted, constant) in enumerate(scored):
        plan.append(
            {
                **by_value[value],
                "schedule_index": schedule_index,
                "interaction_preservation_score": score,
                "projection_popcount": value.bit_count(),
                "retained_free_linearized_edges": retained,
                "deleted_edges": deleted,
                "constant_edges_with_both_endpoints_selected": constant,
                "schedule_key": [-score, -value.bit_count(), value],
                "runtime_assignment_or_target_projection_input_used": False,
                "prospectively_frozen_rule": True,
                "blind_new_instance_transfer": True,
                "historical_A148_through_A151_informed_rule_and_budget": True,
                "new_seed_outcomes_informed_schedule": False,
            }
        )
    values = [row["fixed_value"] for row in plan]
    fixed_patterns = [
        tuple((cell["coordinate"], cell["value"]) for cell in row["fixed_coordinates"])
        for row in plan
    ]
    plan_sha256 = _canonical_sha256(plan)
    proof_core = {
        "ordering": (
            "decreasing_retained_free_linearized_edge_count_then_decreasing_"
            "projection_popcount_then_increasing_numeric_value"
        ),
        "projection_values": values,
        "projection_value_count": len(values),
        "complete_projection_domain": sorted(values) == list(range(1 << len(coordinates))),
        "unique_fixed_coordinate_patterns": len(set(fixed_patterns)),
        "pairwise_disjoint_by_unique_fixed_patterns": len(set(fixed_patterns)) == len(plan),
        "free_coordinate_count_per_subspace": WINDOW_BITS - len(coordinates),
        "logical_assignments_per_subspace": 1 << (WINDOW_BITS - len(coordinates)),
        "total_logical_assignments": sum(row["logical_assignments"] for row in plan),
        "expected_complete_assignment_space": 1 << WINDOW_BITS,
        "covers_complete_assignment_space": (
            sum(row["logical_assignments"] for row in plan) == 1 << WINDOW_BITS
        ),
        "plan_sha256": plan_sha256,
        "runtime_assignment_or_target_projection_input_used": False,
        "prospectively_frozen_rule": True,
        "blind_new_instance_transfer": True,
        "historical_A148_through_A151_informed_rule_and_budget": True,
        "new_seed_outcomes_informed_schedule": False,
    }
    if (
        not proof_core["complete_projection_domain"]
        or not proof_core["pairwise_disjoint_by_unique_fixed_patterns"]
        or not proof_core["covers_complete_assignment_space"]
    ):
        raise RuntimeError("prospective projection plan is not a complete disjoint cover")
    return plan, {**proof_core, "proof_sha256": _canonical_sha256(proof_core)}


def _freeze_phases(plan: Sequence[dict[str, Any]]) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    values = [int(row["fixed_value"]) for row in plan]
    phases = [
        {
            "phase_index": 0,
            "name": "prospective_complete_uniform",
            "purpose": "prospectively_frozen_uniform_budget_over_complete_formula_ranked_domain",
            "projection_values": values,
            "projection_value_count": len(values),
            "timeout_seconds_per_subspace": UNIFORM_TIMEOUT_SECONDS,
            "maximum_solver_processes": MAX_PROCESSES,
            "wave_size": WAVE_SIZE,
            "runtime_assignment_input_used": False,
            "runtime_stored_model_input_used": False,
            "runtime_target_projection_input_used": False,
            "uniform_budget_assigned_to_every_planned_projection_value": True,
            "prospectively_frozen_before_new_instance_generation": True,
            "blind_holdout": True,
            "historical_A148_through_A151_informed_rule_and_budget": True,
            "new_seed_outcomes_informed_phase_plan": False,
        }
    ]
    core = {
        "phases": phases,
        "planned_attempt_count": len(values),
        "complete_formula_ranked_domain_planned": phases[0]["projection_values"] == values,
        "uniform_timeout_seconds": UNIFORM_TIMEOUT_SECONDS,
        "runtime_assignment_or_target_projection_input_used": False,
        "blind_new_instance_transfer": True,
        "historical_A148_through_A151_informed_rule_and_budget": True,
        "new_seed_outcomes_informed_phase_plan": False,
    }
    return phases, {**core, "proof_sha256": _canonical_sha256(core)}


def _normalize_prospective_execution(execution: dict[str, Any]) -> dict[str, Any]:
    normalized = dict(execution)
    normalized.update(
        {
            "historical_a148_a149_results_informed_mechanism_and_budget": True,
            "blind_holdout": True,
            "prospectively_frozen_before_new_instance_generation": True,
            "new_seed_assignment_projection_or_solver_outcomes_informed_plan": False,
        }
    )
    records = []
    for phase_record in execution.get("executed_phases", []):
        phase_copy = dict(phase_record)
        phase_execution = dict(phase_copy["execution"])
        phase_execution.update(
            {
                "historical_instance_results_informed_schedule_hypothesis": True,
                "blind_holdout": True,
                "prospectively_frozen_before_new_instance_generation": True,
                "new_seed_assignment_projection_or_solver_outcomes_informed_plan": False,
            }
        )
        phase_copy["execution"] = phase_execution
        records.append(phase_copy)
    normalized["executed_phases"] = records
    return normalized


def _prospective_execution_gate(
    execution: dict[str, Any],
    plan: Sequence[dict[str, Any]],
    phases: Sequence[dict[str, Any]],
    coordinates: Sequence[int],
) -> None:
    _A151._phased_execution_gate(execution, plan, phases)
    status_counts = execution.get("status_counts", {})
    rows = [
        row
        for phase in execution.get("executed_phases", [])
        for wave in phase["execution"]["waves"]
        for row in wave["subspaces"]
    ]
    allowed_statuses = {"sat", "unsat", "unknown", "error"}
    observed_statuses = [row["solver"]["status"] for row in rows]
    recomputed = {
        status: sum(row["solver"]["status"] == status for row in rows)
        for status in sorted(allowed_statuses)
    }
    if (
        any(status not in allowed_statuses for status in observed_statuses)
        or sum(recomputed.values()) != len(rows)
        or execution.get("attempt_count") != len(rows)
        or status_counts != recomputed
        or recomputed["error"] != 0
        or execution.get("all_returned_assignments_independently_checked") is not True
        or execution.get("all_found_assignments_independently_verified") is not True
    ):
        raise RuntimeError("prospective execution contains an invalid solver/check outcome")
    for row in rows:
        solver = row["solver"]
        status = solver["status"]
        assignment = row.get("assignment")
        check = row.get("independent_end_state_check", {})
        command = solver.get("command_parameters", {})
        if (
            solver.get("return_code") != 0
            or solver.get("external_timeout") is not False
            or command.get("threads") != SOLVER_THREADS_PER_PROCESS
            or command.get("timeout_seconds") != UNIFORM_TIMEOUT_SECONDS
            or command.get("representation") != "Boolean_SMT_native_nary_XOR"
        ):
            raise RuntimeError("solver process or command parameters failed closed")
        if status == "sat" and (
            assignment is None
            or _project_assignment(int(assignment), coordinates) != row.get("fixed_value")
            or check.get("performed") is not True
            or check.get("rate_bits_checked") != 1344
            or check.get("complete_rate_match") is not True
            or check.get("candidate_rate_sha256") != check.get("target_rate_sha256")
            or row.get("independently_confirmed_model") is not True
        ):
            raise RuntimeError("SAT model failed the independent complete-rate gate")
        if status != "sat" and assignment is not None:
            raise RuntimeError("non-SAT solver status unexpectedly contains an assignment")


def _posthoc_witness_audit(
    *,
    runtime_problem: dict[str, Any],
    variant: Any,
    instrumented_assignment: int,
    instrumented_projection: int,
    plan: Sequence[dict[str, Any]],
    execution: dict[str, Any],
) -> dict[str, Any]:
    witness_check = _A151._independent_end_state_check(
        runtime_problem,
        variant,
        instrumented_assignment,
        _A151._VERIFY,
    )
    if (
        witness_check.get("performed") is not True
        or witness_check.get("rate_bits_checked") != 1344
        or witness_check.get("complete_rate_match") is not True
        or witness_check.get("candidate_rate_sha256") != witness_check.get("target_rate_sha256")
    ):
        raise RuntimeError("instrumented posthoc witness does not satisfy the public target")
    attempted_rows = [
        row
        for phase in execution.get("executed_phases", [])
        for wave in phase["execution"]["waves"]
        for row in wave["subspaces"]
        if row["fixed_value"] == instrumented_projection
    ]
    if len(attempted_rows) > 1:
        raise RuntimeError("instrumented projection was attempted more than once")
    projection_status = attempted_rows[0]["solver"]["status"] if attempted_rows else "not_attempted"
    if projection_status == "unsat":
        raise RuntimeError("solver marked the independently verified witness subspace UNSAT")
    reconstructed = execution.get("reconstructed_assignment")
    if reconstructed is None and not attempted_rows:
        raise RuntimeError("completed model-search plan omitted the verified witness subspace")
    if reconstructed == instrumented_assignment and (
        not attempted_rows or projection_status != "sat"
    ):
        raise RuntimeError("exact reconstruction is not bound to a SAT witness subspace")
    return {
        "performed_after_execution_completed": True,
        "instrumented_assignment": instrumented_assignment,
        "instrumented_projection_value": instrumented_projection,
        "instrumented_projection_schedule_index": [row["fixed_value"] for row in plan].index(
            instrumented_projection
        ),
        "instrumented_projection_attempted": bool(attempted_rows),
        "instrumented_projection_solver_status": projection_status,
        "instrumented_assignment_independent_check": witness_check,
        "reconstructed_assignment": reconstructed,
        "reconstruction_matches_instrumented_assignment": (
            reconstructed == instrumented_assignment if reconstructed is not None else False
        ),
        "confirmed_target_consistent_alternate_model": (
            reconstructed is not None and reconstructed != instrumented_assignment
        ),
        "instrumented_assignment_used_for_selection_or_schedule": False,
        "instrumented_projection_used_for_selection_or_schedule": False,
    }


def _build_causal(
    path: Path,
    *,
    protocol_gate: dict[str, Any],
    instance_summary: dict[str, Any],
    selection: dict[str, Any],
    cover_proof: dict[str, Any],
    plan_proof: dict[str, Any],
    phase_proof: dict[str, Any],
    execution: dict[str, Any],
    posthoc: dict[str, Any],
) -> dict[str, Any]:
    builder = _CryptoCausalBuilder(
        experiment="shake_symbolic_r1_width24_prospective_transfer",
        parameters={
            "attempt_id": ATTEMPT_ID,
            "variant": "shake128",
            "window_bits": WINDOW_BITS,
            "seed": EXPECTED_SEED,
            "protocol_sha256": PROTOCOL_SHA256,
            "public_freeze_commit": protocol_gate["commit"],
            "blind_new_instance_transfer": True,
        },
    )
    freeze_id = "shake128-r1-width24-prospective-public-freeze"
    graph_id = "shake128-r1-width24-new-seed-exact-graph-cover"
    plan_id = "shake128-r1-width24-new-seed-complete-plan"
    execution_id = "shake128-r1-width24-new-seed-execution"
    builder.add_triplet(
        edge_id=freeze_id,
        trigger="A151:hash_pinned_result",
        mechanism="derive_seed_and_publicly_commit_complete_protocol_before_instance_generation",
        outcome="A152:prospectively_frozen_new_instance_protocol",
        confidence=1.0,
        evidence_kind="public_git_commit_and_exact_protocol_hash",
        source=protocol_gate["repository"],
        attrs=protocol_gate,
    )
    builder.add_triplet(
        edge_id=graph_id,
        trigger="A152:prospectively_frozen_new_instance_protocol",
        mechanism="extract_R1_degree_two_graph_and_exhaustively_prove_lex_first_minimum_cover",
        outcome="A152:new_seed_exact_minimum_vertex_cover",
        confidence=1.0,
        evidence_kind="exact_symbolic_graph_and_finite_cover_enumeration",
        source="reader_local_R1_boolean_ring_compiler",
        provenance=[freeze_id],
        attrs={
            "runtime_instance": instance_summary,
            "selection_sha256": selection["selection_sha256"],
            "interaction_edges_sha256": selection["interaction_edges_sha256"],
            "cover_proof": cover_proof,
        },
    )
    builder.add_triplet(
        edge_id=plan_id,
        trigger="A152:new_seed_exact_minimum_vertex_cover",
        mechanism="apply_public_formula_only_schedule_and_complete_disjoint_coverage_rule",
        outcome="A152:new_seed_complete_assignment_free_schedule",
        confidence=1.0,
        evidence_kind="deterministic_schedule_and_assignment_space_proof",
        source=PROTOCOL_SHA256,
        provenance=[graph_id],
        attrs={
            "plan_proof": plan_proof,
            "phase_proof": phase_proof,
            "runtime_assignment_or_target_projection_input_used": False,
            "blind_new_instance_transfer": True,
        },
    )
    candidate_checks = [
        {
            "projection_value": row["fixed_value"],
            "assignment": row["assignment"],
            "independent_end_state_check": row["independent_end_state_check"],
        }
        for phase in execution.get("executed_phases", [])
        for wave in phase["execution"]["waves"]
        for row in wave["subspaces"]
        if row["assignment"] is not None
    ]
    builder.add_triplet(
        edge_id=execution_id,
        trigger="A152:new_seed_complete_assignment_free_schedule",
        mechanism="execute_uniform_complete_wave_prefix_and_independently_check_all_returned_models",
        outcome="A152:new_seed_fullround_model_search_observation",
        confidence=1.0,
        evidence_kind="bounded_solver_execution_and_independent_1344_bit_checks",
        source="Z3_4.15.4_plus_independent_NumPy_lane_core",
        provenance=[plan_id],
        attrs={
            "attempted_projection_values": execution["attempted_projection_values"],
            "status_counts": execution["status_counts"],
            "reconstructed_assignment": execution["reconstructed_assignment"],
            "posthoc_witness_audit": posthoc,
            "candidate_checks": candidate_checks,
            "blind_new_instance_transfer": True,
        },
    )
    stats = dict(builder.save(path))
    stats.pop("path", None)
    reader = _CryptoCausalReader(path)
    rows = reader.triplets(include_inferred=False)
    ids = [freeze_id, graph_id, plan_id, execution_id]
    by_id = {row["edge_id"]: row for row in rows}
    if (
        len(rows) != 4
        or set(by_id) != set(ids)
        or not reader.verify_provenance()
        or any(
            by_id[left]["outcome"] != by_id[right]["trigger"]
            for left, right in zip(ids[:-1], ids[1:], strict=True)
        )
    ):
        raise RuntimeError("prospective transfer causal chain failed validation")
    return {
        "stats": stats,
        "explicit_triplets": len(rows),
        "provenance_verified": True,
        "file_sha256": reader.file_sha256,
        "graph_sha256": reader.graph_sha256,
    }


def _build_structure_only_causal(
    path: Path,
    *,
    protocol_gate: dict[str, Any],
    instance_summary: dict[str, Any],
    selection: dict[str, Any],
    cover_proof: dict[str, Any],
) -> dict[str, Any]:
    builder = _CryptoCausalBuilder(
        experiment="shake_symbolic_r1_width24_prospective_transfer_structure_guard",
        parameters={
            "attempt_id": ATTEMPT_ID,
            "variant": "shake128",
            "window_bits": WINDOW_BITS,
            "seed": EXPECTED_SEED,
            "protocol_sha256": PROTOCOL_SHA256,
            "public_freeze_commit": protocol_gate["commit"],
            "maximum_cover_bits_for_solver_execution": MAX_COVER_BITS_FOR_EXECUTION,
            "blind_new_instance_transfer": True,
        },
    )
    freeze_id = "shake128-r1-width24-prospective-public-freeze"
    graph_id = "shake128-r1-width24-new-seed-exact-graph-cover"
    guard_id = "shake128-r1-width24-new-seed-structure-only-resource-guard"
    builder.add_triplet(
        edge_id=freeze_id,
        trigger="A151:hash_pinned_result",
        mechanism="derive_seed_and_publicly_commit_complete_protocol_before_instance_generation",
        outcome="A152:prospectively_frozen_new_instance_protocol",
        confidence=1.0,
        evidence_kind="public_git_commit_and_exact_protocol_hash",
        source=protocol_gate["repository"],
        attrs=protocol_gate,
    )
    builder.add_triplet(
        edge_id=graph_id,
        trigger="A152:prospectively_frozen_new_instance_protocol",
        mechanism="extract_R1_degree_two_graph_and_exhaustively_prove_lex_first_minimum_cover",
        outcome="A152:new_seed_exact_minimum_vertex_cover",
        confidence=1.0,
        evidence_kind="exact_symbolic_graph_and_finite_cover_enumeration",
        source="reader_local_R1_boolean_ring_compiler",
        provenance=[freeze_id],
        attrs={
            "runtime_instance": instance_summary,
            "selection_sha256": selection["selection_sha256"],
            "interaction_edges_sha256": selection["interaction_edges_sha256"],
            "cover_proof": cover_proof,
        },
    )
    guard = {
        "observed_minimum_vertex_cover_bits": selection["partition_bits"],
        "maximum_cover_bits_for_solver_execution": MAX_COVER_BITS_FOR_EXECUTION,
        "guard_triggered": True,
        "solver_started": False,
        "instrumented_assignment_extracted": False,
        "structure_only_not_model_search": True,
    }
    builder.add_triplet(
        edge_id=guard_id,
        trigger="A152:new_seed_exact_minimum_vertex_cover",
        mechanism="apply_prospectively_frozen_cover_size_execution_guard",
        outcome="A152:new_seed_structure_only_resource_boundary",
        confidence=1.0,
        evidence_kind="protocol_defined_resource_boundary",
        source=PROTOCOL_SHA256,
        provenance=[graph_id],
        attrs=guard,
    )
    stats = dict(builder.save(path))
    stats.pop("path", None)
    reader = _CryptoCausalReader(path)
    rows = reader.triplets(include_inferred=False)
    ids = [freeze_id, graph_id, guard_id]
    by_id = {row["edge_id"]: row for row in rows}
    if (
        len(rows) != 3
        or set(by_id) != set(ids)
        or not reader.verify_provenance()
        or any(
            by_id[left]["outcome"] != by_id[right]["trigger"]
            for left, right in zip(ids[:-1], ids[1:], strict=True)
        )
    ):
        raise RuntimeError("prospective structure-only causal chain failed validation")
    return {
        "stats": stats,
        "explicit_triplets": len(rows),
        "provenance_verified": True,
        "file_sha256": reader.file_sha256,
        "graph_sha256": reader.graph_sha256,
        "resource_guard": guard,
    }


def _production_path_gate(
    execution_repo: Path,
    output: Path | None,
    causal_output: Path | None,
    work_dir: Path | None,
) -> tuple[Path, Path, Path]:
    supplied = {"output": output, "causal_output": causal_output, "work_dir": work_dir}
    if any(value is None for value in supplied.values()):
        raise ValueError("production execution requires output, causal-output, and work-dir")
    if any(not value.is_absolute() for value in supplied.values() if value is not None):
        raise ValueError("production output and work paths must be absolute")
    resolved = {key: value.resolve() for key, value in supplied.items() if value is not None}
    if len(set(resolved.values())) != len(resolved):
        raise ValueError("output, causal-output, and work-dir must be distinct")
    repo = execution_repo.resolve()
    if any(path.is_relative_to(repo) for path in resolved.values()):
        raise ValueError("production artifacts and work directory must be outside public worktree")
    if resolved["output"].is_dir() or resolved["causal_output"].is_dir():
        raise ValueError("production output paths must name files")
    if (
        resolved["output"].name != RESULT_FILENAME
        or resolved["causal_output"].name != CAUSAL_FILENAME
    ):
        raise ValueError("production output filenames must match the frozen protocol")
    work = resolved["work_dir"]
    if work.exists() and not work.is_dir():
        raise ValueError("production work path must name a directory")
    if work.exists() and any(work.iterdir()):
        raise ValueError("production work directory must be absent or empty")
    return resolved["output"], resolved["causal_output"], work


def _write_and_reopen_result(
    output: Path,
    causal_output: Path,
    payload: dict[str, Any],
) -> dict[str, str]:
    canonical = json.dumps(payload, indent=2, sort_keys=True, allow_nan=False).encode() + b"\n"
    _atomic_write(output, canonical)
    observed_json = output.read_bytes()
    if observed_json != canonical:
        raise RuntimeError("result JSON changed during atomic write")
    json.loads(observed_json)
    reader = _CryptoCausalReader(causal_output)
    causal = payload.get("causal", {})
    if (
        reader.file_sha256 != causal.get("file_sha256")
        or reader.graph_sha256 != causal.get("graph_sha256")
        or not reader.verify_provenance()
    ):
        raise RuntimeError("final Causal artifact differs after result write")
    return {
        "json_sha256": _sha256(observed_json),
        "causal_sha256": reader.file_sha256,
        "causal_graph_sha256": reader.graph_sha256,
    }


def _atomic_write(path: Path, raw: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.tmp")
    temporary.write_bytes(raw)
    temporary.replace(path)


def main(argv: Sequence[str] | None = None) -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--public-freeze-repo", type=Path, required=True)
    parser.add_argument("--public-freeze-commit", required=True)
    parser.add_argument(
        "--verify-freeze-only",
        action="store_true",
        help="validate protocol, public commit, anchor, and Z3 without generating the instance",
    )
    parser.add_argument(
        "--z3", type=Path, default=Path(shutil.which("z3") or "/opt/homebrew/bin/z3")
    )
    parser.add_argument("--work-dir", type=Path)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--causal-output", type=Path)
    args = parser.parse_args(argv)

    execution_repo = args.public_freeze_repo.resolve()
    freeze_gate = _public_freeze_gate(execution_repo, args.public_freeze_commit)
    protocol = _load_protocol(execution_repo / PROTOCOL_RELATIVE_PATH)
    anchor_gate = _load_anchor(execution_repo / A151_RELATIVE_PATH)
    seed_derivation = _derive_seed(anchor_gate["sha256"])
    z3 = Path(shutil.which(str(args.z3)) or args.z3)
    if not z3.is_file():
        raise FileNotFoundError(f"Z3 executable not found: {args.z3}")
    solver_version = subprocess.run(
        [str(z3), "-version"], check=True, capture_output=True, text=True
    ).stdout.strip()
    _z3_version_gate(solver_version)
    dependency_gate = _load_runtime_modules(execution_repo)
    if args.verify_freeze_only:
        print(
            json.dumps(
                {
                    "anchor_gate": anchor_gate,
                    "dependency_gate": dependency_gate,
                    "freeze_gate": freeze_gate,
                    "instance_generated": False,
                    "seed_derivation": seed_derivation,
                    "solver": solver_version,
                },
                sort_keys=True,
            ),
            flush=True,
        )
        return
    output, causal_output, work_dir = _production_path_gate(
        execution_repo,
        args.output,
        args.causal_output,
        args.work_dir,
    )

    # First permitted construction of the prospective instance: every public
    # protocol and toolchain gate above has already passed.
    variant = _BASE.VARIANTS["shake128"]
    instrumented_problem = _NATIVE._problem(variant, WINDOW_BITS, EXPECTED_SEED)
    runtime_problem = _sanitized_runtime_problem(instrumented_problem, variant)
    instance_summary = _runtime_instance_summary(runtime_problem, variant)

    selection, cover_proof = _derive_structural_selection(runtime_problem, variant)
    if selection["partition_bits"] > MAX_COVER_BITS_FOR_EXECUTION:
        causal = _build_structure_only_causal(
            causal_output,
            protocol_gate=freeze_gate,
            instance_summary=instance_summary,
            selection=selection,
            cover_proof=cover_proof,
        )
        payload = {
            "schema": "shake-symbolic-r1-width24-prospective-transfer-v1",
            "attempt_id": ATTEMPT_ID,
            "evidence_stage": "PROSPECTIVE_NEW_SEED_STRUCTURE_ONLY_RESOURCE_BOUNDARY",
            "result": (
                "The exact new-seed R1 minimum vertex cover exceeds the prospectively "
                "declared solver-execution bound; the run records the structure only, "
                "without solver work or instrumented-assignment extraction."
            ),
            "scope": (
                "One prospectively hash-derived SHAKE128 width-24 capacity-window "
                "system and its exact cleared-template R1 interaction graph."
            ),
            "parameters": {
                "seed": EXPECTED_SEED,
                "window_bits": WINDOW_BITS,
                "symbolic_prefix_rounds": SYMBOLIC_PREFIX_ROUNDS,
                "solver": solver_version,
                "maximum_cover_bits_for_solver_execution": MAX_COVER_BITS_FOR_EXECUTION,
                "solver_started": False,
                "instrumented_assignment_extracted": False,
                "blind_new_instance_transfer": True,
                "structure_only_not_model_search": True,
            },
            "protocol": protocol,
            "public_freeze_gate": freeze_gate,
            "dependency_gate": dependency_gate,
            "anchor_gate": anchor_gate,
            "seed_derivation": seed_derivation,
            "runtime_instance": instance_summary,
            "selection": selection,
            "minimum_vertex_cover_proof": cover_proof,
            "causal": causal,
        }
        hashes = _write_and_reopen_result(output, causal_output, payload)
        print(
            json.dumps(
                {
                    "output": str(output),
                    "causal_output": str(causal_output),
                    "partition_bits": selection["partition_bits"],
                    "resource_guard_triggered": True,
                    **hashes,
                },
                sort_keys=True,
            ),
            flush=True,
        )
        return

    plan, plan_proof = _freeze_plan(selection)
    phases, phase_proof = _freeze_phases(plan)
    writer, inputs, encoding = _R1._SPLIT._encode_problem(
        runtime_problem, variant, EXPECTED_SEED, prefix_rounds=SYMBOLIC_PREFIX_ROUNDS
    )
    unpartitioned_raw = writer.render(inputs, include_model=True)
    execution = _A151._execute_assignment_free_phases(
        plan=plan,
        phases=phases,
        coordinates=selection["selected_coordinates"],
        writer=writer,
        inputs=inputs,
        problem=runtime_problem,
        variant=variant,
        z3=z3,
        work_dir=work_dir,
    )
    execution = _normalize_prospective_execution(execution)
    _prospective_execution_gate(
        execution,
        plan,
        phases,
        selection["selected_coordinates"],
    )

    # This is intentionally the first extraction of the hidden window value.
    instrumented_assignment = _WINDOW._extract_window(
        instrumented_problem["base_state"], variant, instrumented_problem["positions"]
    )
    instrumented_projection = _project_assignment(
        instrumented_assignment, selection["selected_coordinates"]
    )
    posthoc = _posthoc_witness_audit(
        runtime_problem=runtime_problem,
        variant=variant,
        instrumented_assignment=instrumented_assignment,
        instrumented_projection=instrumented_projection,
        plan=plan,
        execution=execution,
    )
    reconstructed = execution["reconstructed_assignment"]
    causal = _build_causal(
        causal_output,
        protocol_gate=freeze_gate,
        instance_summary=instance_summary,
        selection=selection,
        cover_proof=cover_proof,
        plan_proof=plan_proof,
        phase_proof=phase_proof,
        execution=execution,
        posthoc=posthoc,
    )
    if posthoc["reconstruction_matches_instrumented_assignment"]:
        result = (
            "The publicly frozen graph-derived Reader independently reconstructed "
            "the instrumented new-seed 24-bit state window from the complete "
            "24-round rate target."
        )
    elif posthoc["confirmed_target_consistent_alternate_model"]:
        result = (
            "The publicly frozen graph-derived Reader returned an independently "
            "confirmed target-consistent model distinct from the instrumented "
            "witness; this is model finding, not unique window reconstruction."
        )
    else:
        result = (
            "The publicly frozen complete projection schedule ended without an "
            "independently confirmed model under the declared per-projection budget."
        )
    payload = {
        "schema": "shake-symbolic-r1-width24-prospective-transfer-v1",
        "attempt_id": ATTEMPT_ID,
        "evidence_stage": "PROSPECTIVE_NEW_SEED_TRANSFER_EXECUTED",
        "result": result,
        "scope": (
            "One prospectively hash-derived SHAKE128 width-24 capacity-window system, "
            "an R1 symbolic interface, 23 exact suffix rounds, and all 1,344 rate bits."
        ),
        "parameters": {
            "seed": EXPECTED_SEED,
            "window_bits": WINDOW_BITS,
            "symbolic_prefix_rounds": SYMBOLIC_PREFIX_ROUNDS,
            "solver": solver_version,
            "uniform_timeout_seconds_per_projection": UNIFORM_TIMEOUT_SECONDS,
            "maximum_parallel_processes": MAX_PROCESSES,
            "wave_size": WAVE_SIZE,
            "wallclock_excluded_from_canonical_result": True,
            "blind_new_instance_transfer": True,
            "global_uniqueness_claimed": False,
        },
        "protocol": protocol,
        "public_freeze_gate": freeze_gate,
        "dependency_gate": dependency_gate,
        "anchor_gate": anchor_gate,
        "seed_derivation": seed_derivation,
        "runtime_input_boundary": {
            "instrumented_base_state_available_to_selection_or_schedule": False,
            "runtime_problem_contains_cleared_window_template": True,
            "runtime_problem_contains_target_rate": True,
            "instrumented_assignment_or_projection_runtime_input": False,
        },
        "runtime_instance": instance_summary,
        "selection": selection,
        "minimum_vertex_cover_proof": cover_proof,
        "assignment_free_plan": {
            "plan_sha256": plan_proof["plan_sha256"],
            "proof": plan_proof,
            "subspaces": plan,
        },
        "execution_phase_plan": {"phases": phases, "proof": phase_proof},
        "encoding": {
            **encoding,
            "unpartitioned_smt_bytes": len(unpartitioned_raw),
            "unpartitioned_smt_sha256": _sha256(unpartitioned_raw),
        },
        "execution": execution,
        "posthoc_comparison": posthoc,
        "causal": causal,
    }
    hashes = _write_and_reopen_result(output, causal_output, payload)
    print(
        json.dumps(
            {
                "output": str(output),
                "causal_output": str(causal_output),
                "partition_bits": selection["partition_bits"],
                "attempt_count": execution["attempt_count"],
                "status_counts": execution["status_counts"],
                "reconstructed_assignment": reconstructed,
                "posthoc_match": posthoc["reconstruction_matches_instrumented_assignment"],
                **hashes,
            },
            sort_keys=True,
        ),
        flush=True,
    )


if __name__ == "__main__":
    main()

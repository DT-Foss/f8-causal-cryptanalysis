from __future__ import annotations

import importlib.util
import inspect
import json
import shutil
import sys
from pathlib import Path
from typing import Any

import numpy as np
import pytest

from arx_carry_leak.crypto_causal import CryptoCausalReader

_ROOT = Path(__file__).parents[1]
_SCRIPT = (
    _ROOT
    / "research"
    / "experiments"
    / "shake_symbolic_r1_structural_k8_reader.py"
)
_SPEC = importlib.util.spec_from_file_location(
    "shake_symbolic_r1_structural_k8_reader", _SCRIPT
)
assert _SPEC is not None and _SPEC.loader is not None
_K8 = importlib.util.module_from_spec(_SPEC)
sys.modules[_SPEC.name] = _K8
_SPEC.loader.exec_module(_K8)

_RESULTS = _ROOT / "research" / "results" / "v1"
A138_PATH = _RESULTS / "shake_symbolic_r1_scaling_reader_v1.json"
DEPTH_PATH = _RESULTS / "shake_symbolic_r1_structural_depth_frontier_v1.json"


def _z3() -> Path:
    path = Path(shutil.which("z3") or "/opt/homebrew/bin/z3")
    if not path.is_file():
        pytest.skip("Z3 CLI is not installed")
    return path


def _canonical_problem() -> tuple[Any, dict[str, Any]]:
    variant = _K8._BASE.VARIANTS["shake128"]
    problem = _K8._NATIVE._problem(variant, 20, 89755037)
    return variant, problem


def _canonical_selection() -> dict[str, Any]:
    variant, problem = _canonical_problem()
    return _K8._derive_assignment_free_k8_selection(
        problem["base_state"], variant, problem["positions"]
    )


def _fake_solver_result(status: str, assignment: int | None) -> dict[str, Any]:
    return {
        "status": status,
        "assignment": assignment,
        "stats": {"decisions": 1.0} if status == "sat" else {},
        "return_code": 0,
        "external_timeout": False,
        "command_parameters": {
            "timeout_seconds": 60,
            "threads": 1,
            "representation": "Boolean_SMT_native_nary_XOR",
        },
    }


def _verification(match: bool) -> dict[str, Any]:
    candidate = "f" * 64 if match else "0" * 64
    return {
        "rate_bits_checked": 1344,
        "rate_lanes_checked": 21,
        "complete_rate_match": match,
        "candidate_rate_sha256": candidate,
        "target_rate_sha256": "f" * 64,
    }


def test_depth_frontier_exact_hash_and_minimum_posthoc_k8_gate(tmp_path: Path) -> None:
    gate = _K8._load_depth_frontier_gate(DEPTH_PATH)
    assert (
        gate["artifact_sha256"]
        == "c1b53e27f864c084fb0d64b04f591e22c520aec13578340e0aeda650f8fdec7c"
    )
    assert gate["minimal_posthoc_confirmed_depth"] == 8
    assert gate["k8_selected_coordinates"] == [1, 2, 4, 9, 10, 12, 15, 18]
    assert gate["k8_covered_edge_count"] == 24
    assert gate["r1_degree_two_edge_count"] == 28
    assert gate["retained_assignment_exposed_to_selection_or_plan"] is False
    assert "assignment" not in gate
    assert "projection" not in gate

    changed = tmp_path / DEPTH_PATH.name
    changed.write_bytes(DEPTH_PATH.read_bytes() + b"\n")
    with pytest.raises(RuntimeError, match="hash differs"):
        _K8._load_depth_frontier_gate(changed)


def test_a138_unpartitioned_smt_gate() -> None:
    gate = _K8._load_a138_smt_gate(A138_PATH)
    assert gate["first_solver_status"] == "unknown"
    assert (
        gate["unpartitioned_smt_sha256"]
        == "66aa82020b4dd2b4d21f3065c99ca6f7c9224ab1ab9765f686121f2fe7f8618f"
    )
    assert gate["retained_assignment_exposed_to_selection_or_plan"] is False


def test_k8_selection_is_rederived_without_posthoc_input(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    assert list(inspect.signature(_K8._derive_assignment_free_k8_selection).parameters) == [
        "base_state",
        "variant",
        "positions",
    ]
    assert list(inspect.signature(_K8._freeze_assignment_free_plan).parameters) == [
        "selection"
    ]

    variant, problem = _canonical_problem()
    original = np.array(problem["base_state"], copy=True)
    changed = np.array(problem["base_state"], copy=True)
    for position in problem["positions"]:
        lane = variant.rate_lanes + int(position) // 64
        bit = int(position) % 64
        changed[0, lane] ^= np.uint64(1) << np.uint64(bit)

    def forbidden_posthoc(*_args: object, **_kwargs: object) -> int:
        raise AssertionError("posthoc extraction must not run during selection or planning")

    monkeypatch.setattr(_K8._WINDOW, "_extract_window", forbidden_posthoc)
    first = _K8._derive_assignment_free_k8_selection(
        original, variant, problem["positions"]
    )
    second = _K8._derive_assignment_free_k8_selection(
        changed, variant, problem["positions"]
    )
    assert first == second
    assert first["selected_coordinates"] == [1, 2, 4, 9, 10, 12, 15, 18]
    assert first["maximum_covered_edge_count"] == 24
    assert first["degree_two_monomial_count"] == 28
    assert first["maximizing_coordinate_sets"][0] == first["selected_coordinates"]
    _K8._canonical_k8_selection_gate(first)


def test_complete_256_value_plan_hash_waves_and_coverage_proof() -> None:
    selection = _canonical_selection()
    plan, proof = _K8._freeze_assignment_free_plan(selection)
    values = list(range(256))
    assert [row["subspace_index"] for row in plan] == values
    assert [row["fixed_value"] for row in plan] == values
    assert _K8._canonical_sha256(plan) == _K8.EXPECTED_PLAN_SHA256
    assert selection["subspace_plan_sha256"] == _K8.EXPECTED_PLAN_SHA256
    assert proof["projection_value_domain"] == values
    assert proof["unique_fixed_coordinate_patterns"] == 256
    assert proof["logical_assignments_per_subspace"] == 1 << 12
    assert proof["total_logical_assignments"] == 1 << 20
    assert proof["pairwise_disjoint_by_unique_fixed_patterns"] is True
    assert proof["covers_complete_assignment_space"] is True
    assert proof["stored_assignment_used"] is False
    assert proof["posthoc_assignment_used"] is False
    assert proof["coverage_proof_sha256"] == _K8._canonical_sha256(
        {key: value for key, value in proof.items() if key != "coverage_proof_sha256"}
    )

    waves = _K8._wave_value_plan(values, 5)
    assert len(waves) == 52
    assert waves[0] == [0, 1, 2, 3, 4]
    assert waves[-1] == [255]
    assert all(1 <= len(wave) <= 5 for wave in waves)
    assert [value for wave in waves for value in wave] == values


def test_projection_and_arbitrary_coordinate_renderer() -> None:
    coordinates = [1, 2, 4, 9, 10, 12, 15, 18]
    writer = _K8._SMT.BooleanSMT(seed=17)
    inputs = [writer.declare("x") for _ in range(20)]
    fixed_value = 0b10100110
    raw = _K8._render_fixed_coordinates(
        writer, inputs, coordinates, fixed_value, include_model=True
    )
    assertions = [line for line in raw.decode().splitlines() if line.startswith("(assert ")]
    assert assertions == [
        f"(assert (not {inputs[1]}))",
        f"(assert {inputs[2]})",
        f"(assert {inputs[4]})",
        f"(assert (not {inputs[9]}))",
        f"(assert (not {inputs[10]}))",
        f"(assert {inputs[12]})",
        f"(assert (not {inputs[15]}))",
        f"(assert {inputs[18]})",
    ]
    assignment = sum(((fixed_value >> bit) & 1) << coordinate for bit, coordinate in enumerate(coordinates))
    assert _K8._project_assignment(assignment, coordinates) == fixed_value


def test_waves_remain_ascending_and_stop_only_after_independent_true(tmp_path: Path) -> None:
    writer = _K8._SMT.BooleanSMT(seed=3)
    inputs = [writer.declare("x") for _ in range(4)]
    plan = _K8._subspace_plan(4, [0, 1])

    def fake_solver(
        _z3_path: Path, smt_path: Path, _timeout: int, _inputs: list[str]
    ) -> dict[str, Any]:
        value = int(smt_path.stem.rsplit("subspace", 1)[1])
        if value == 0:
            return _fake_solver_result("sat", 0)
        if value == 2:
            return _fake_solver_result("sat", 5)
        return _fake_solver_result("unknown", None)

    def fake_verify(_problem: dict[str, Any], _variant: Any, assignment: int) -> dict[str, Any]:
        return _verification(assignment == 5)

    execution = _K8._execute_assignment_free_waves(
        plan=plan,
        coordinates=[0, 1],
        writer=writer,
        inputs=inputs,
        problem={},
        variant=object(),
        z3=Path("z3"),
        work_dir=tmp_path,
        timeout_seconds=60,
        max_processes=1,
        wave_size=1,
        run_solver=fake_solver,
        verify_assignment=fake_verify,
    )
    assert execution["planned_projection_values"] == [0, 1, 2, 3]
    assert execution["executed_projection_values"] == [0, 1, 2]
    assert execution["executed_wave_count"] == 3
    assert execution["waves"][0]["subspaces"][0]["independently_confirmed_model"] is False
    assert execution["waves"][0]["stop_after_wave"] is False
    assert execution["waves"][1]["stop_after_wave"] is False
    assert execution["waves"][2]["stop_after_wave"] is True
    assert execution["reconstructed_assignment"] == 5
    assert execution["stop_reason"] == (
        "independently_confirmed_model_found_after_complete_wave"
    )
    assert execution["all_executed_values_form_exact_ascending_plan_prefix"] is True
    assert not list(tmp_path.glob("*.smt2"))
    _K8._execution_gate(execution, plan)


def test_small_4bit_assignment_free_wave_solver_smoke(tmp_path: Path) -> None:
    variant = _K8._BASE.VARIANTS["shake128"]
    problem = _K8._NATIVE._problem(variant, 4, 89751001)
    selection = _K8._A141._derive_structural_selection(
        problem["base_state"], variant, problem["positions"], 1
    )
    plan, proof = _K8._freeze_assignment_free_plan(selection)
    writer, inputs, _encoding = _K8._R1._SPLIT._encode_problem(
        problem, variant, 89751001, prefix_rounds=1
    )
    execution = _K8._execute_assignment_free_waves(
        plan=plan,
        coordinates=selection["selected_coordinates"],
        writer=writer,
        inputs=inputs,
        problem=problem,
        variant=variant,
        z3=_z3(),
        work_dir=tmp_path,
        timeout_seconds=30,
        max_processes=2,
        wave_size=2,
    )
    actual = _K8._WINDOW._extract_window(
        problem["base_state"], variant, problem["positions"]
    )
    assert proof["covers_complete_assignment_space"]
    assert execution["planned_projection_values"] == [0, 1]
    assert execution["executed_projection_values"] == [0, 1]
    assert execution["executed_wave_count"] == 1
    assert execution["status_counts"] == {
        "sat": 1,
        "unsat": 1,
        "unknown": 0,
        "error": 0,
    }
    assert execution["reconstructed_assignment"] == actual
    assert execution["independently_verified_assignments"] == [actual]
    assert execution["waves"][0]["smt_files_removed_after_wave"] is True
    assert not list(tmp_path.glob("*.smt2"))


def test_reader_is_neutral_exact_three_triplet_chain(tmp_path: Path) -> None:
    selection = _canonical_selection()
    plan, proof = _K8._freeze_assignment_free_plan(selection)
    writer = _K8._SMT.BooleanSMT(seed=7)
    inputs = [writer.declare("x") for _ in range(20)]

    def fake_solver(
        _z3_path: Path, _smt_path: Path, _timeout: int, _inputs: list[str]
    ) -> dict[str, Any]:
        return _fake_solver_result("sat", 0)

    def fake_verify(_problem: dict[str, Any], _variant: Any, _assignment: int) -> dict[str, Any]:
        return _verification(True)

    execution = _K8._execute_assignment_free_waves(
        plan=plan,
        coordinates=selection["selected_coordinates"],
        writer=writer,
        inputs=inputs,
        problem={},
        variant=object(),
        z3=Path("z3"),
        work_dir=tmp_path / "smt",
        timeout_seconds=60,
        max_processes=5,
        wave_size=5,
        run_solver=fake_solver,
        verify_assignment=fake_verify,
    )
    path = tmp_path / "shake-symbolic-r1-structural-k8-reader.causal"
    _K8._build_graph(path, selection, plan, proof, execution)
    reader = CryptoCausalReader(path)
    rows = reader.triplets(include_inferred=False)
    by_id = {row["edge_id"]: row for row in rows}
    graph_id = "shake128-r1-k8-exact-quadratic-interaction-graph"
    plan_id = "shake128-r1-k8-complete-assignment-free-plan"
    execution_id = "shake128-r1-k8-deterministic-wave-execution"
    assert reader.verify_provenance()
    assert len(rows) == 3
    assert set(by_id) == {graph_id, plan_id, execution_id}
    assert by_id[plan_id]["provenance"] == [graph_id]
    assert by_id[execution_id]["provenance"] == [plan_id]
    assert by_id[graph_id]["outcome"] == by_id[plan_id]["trigger"]
    assert by_id[plan_id]["outcome"] == by_id[execution_id]["trigger"]
    assert by_id[plan_id]["attrs"]["stored_or_posthoc_assignment_used"] is False
    assert "instrumented_assignment" not in json.dumps(rows, sort_keys=True)

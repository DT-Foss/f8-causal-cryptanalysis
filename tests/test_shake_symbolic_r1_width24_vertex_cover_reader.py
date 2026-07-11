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
_SCRIPT = _ROOT / "research" / "experiments" / "shake_symbolic_r1_width24_vertex_cover_reader.py"
_SPEC = importlib.util.spec_from_file_location(
    "shake_symbolic_r1_width24_vertex_cover_reader", _SCRIPT
)
assert _SPEC is not None and _SPEC.loader is not None
_VC = importlib.util.module_from_spec(_SPEC)
sys.modules[_SPEC.name] = _VC
_SPEC.loader.exec_module(_VC)

_RESULTS = _ROOT / "research" / "results" / "v1"
FRONTIER_PATH = _RESULTS / "shake_symbolic_r1_width24_depth_frontier_v1.json"
A138_PATH = _RESULTS / "shake_symbolic_r1_scaling_reader_v1.json"
RESULT_PATH = _RESULTS / "shake_symbolic_r1_width24_vertex_cover_reader_v1.json"
RESULT_CAUSAL_PATH = _RESULTS / "shake_symbolic_r1_width24_vertex_cover_reader_v1.causal"


def _z3() -> Path:
    path = Path(shutil.which("z3") or "/opt/homebrew/bin/z3")
    if not path.is_file():
        pytest.skip("Z3 CLI is not installed")
    return path


def _canonical_problem() -> tuple[Any, dict[str, Any]]:
    variant = _VC._BASE.VARIANTS["shake128"]
    problem = _VC._NATIVE._problem(variant, _VC.WINDOW_BITS, _VC.SEED)
    return variant, problem


def _canonical_selection() -> tuple[dict[str, Any], dict[str, Any]]:
    variant, problem = _canonical_problem()
    return _VC._derive_assignment_free_selection(
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


def test_external_z3_version_is_exactly_gated() -> None:
    observed = _VC.subprocess.run(
        [str(_z3()), "-version"],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    assert observed.startswith(_VC.EXPECTED_Z3_VERSION_PREFIX)


def _scheduled_small_plan(window_bits: int, coordinates: list[int]) -> list[dict[str, Any]]:
    ascending = _VC._subspace_plan(window_bits, coordinates)
    by_value = {row["fixed_value"]: row for row in ascending}
    values = _VC._interaction_preserving_values(len(coordinates))
    return [
        {
            **by_value[value],
            "schedule_index": index,
            "interaction_preservation_score": value.bit_count(),
        }
        for index, value in enumerate(values)
    ]


def test_a148_frontier_hash_gate_is_exact_and_sanitized(tmp_path: Path) -> None:
    gate = _VC._load_frontier_gate(FRONTIER_PATH)
    assert gate["artifact_sha256"] == _VC.WIDTH24_FRONTIER_SHA256
    assert gate["minimal_posthoc_confirmed_depth"] == 9
    assert gate["edge_count"] == 9
    assert gate["selected_coordinates"] == list(range(9))
    assert gate["selection_sha256"] == _VC.EXPECTED_SELECTION_SHA256
    assert gate["retained_assignment_exposed_to_selection_or_schedule"] is False
    assert gate["retained_projection_exposed_to_selection_or_schedule"] is False
    assert "assignment" not in gate
    assert "projection_value" not in gate

    changed = tmp_path / FRONTIER_PATH.name
    changed.write_bytes(FRONTIER_PATH.read_bytes() + b"\n")
    with pytest.raises(RuntimeError, match="hash differs"):
        _VC._load_frontier_gate(changed)


def test_selection_and_schedule_apis_cannot_accept_posthoc_inputs() -> None:
    assert list(inspect.signature(_VC._derive_assignment_free_selection).parameters) == [
        "base_state",
        "variant",
        "positions",
    ]
    assert list(inspect.signature(_VC._freeze_assignment_free_plan).parameters) == ["selection"]
    assert "assignment" not in inspect.signature(_VC._interaction_preserving_values).parameters
    assert "target" not in inspect.signature(_VC._interaction_preserving_values).parameters


def test_width24_selection_is_rederived_without_instrumented_extraction(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    variant, problem = _canonical_problem()
    first_state = np.array(problem["base_state"], copy=True)
    second_state = np.array(problem["base_state"], copy=True)
    for position in problem["positions"]:
        lane = variant.rate_lanes + int(position) // 64
        bit = int(position) % 64
        second_state[0, lane] ^= np.uint64(1) << np.uint64(bit)

    def forbidden_extraction(*_args: object, **_kwargs: object) -> int:
        raise AssertionError("instrumented extraction cannot run during selection")

    monkeypatch.setattr(_VC._WINDOW, "_extract_window", forbidden_extraction)
    first, first_proof = _VC._derive_assignment_free_selection(
        first_state, variant, problem["positions"]
    )
    second, second_proof = _VC._derive_assignment_free_selection(
        second_state, variant, problem["positions"]
    )
    assert first == second
    assert first_proof == second_proof
    _VC._canonical_selection_gate(first, first_proof)


def test_nine_disjoint_edges_give_an_exact_minimum_vertex_cover() -> None:
    selection, proof = _canonical_selection()
    _VC._canonical_selection_gate(selection, proof)
    assert selection["interaction_edges"] == [
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
    assert selection["selected_coordinates"] == list(range(9))
    assert selection["residual_edges"] == []
    assert proof["pairwise_disjoint_edges"] is True
    assert proof["lower_bound_from_disjoint_edges"] == 9
    assert proof["selected_coordinate_count"] == 9
    assert proof["selected_set_is_minimum_vertex_cover"] is True
    assert proof["minimum_cover_count"] == 512
    assert proof["minimum_vertex_cover_proof_sha256"] == _VC.EXPECTED_VERTEX_COVER_PROOF_SHA256


def test_complete_interaction_preserving_schedule_hash_and_coverage() -> None:
    selection, vertex_proof = _canonical_selection()
    plan, proof = _VC._freeze_assignment_free_plan(selection)
    _VC._canonical_selection_gate(selection, vertex_proof)
    _VC._canonical_plan_gate(plan, proof)
    values = [row["fixed_value"] for row in plan]
    scores = [row["interaction_preservation_score"] for row in plan]
    assert values[:20] == [
        511,
        255,
        383,
        447,
        479,
        495,
        503,
        507,
        509,
        510,
        127,
        191,
        223,
        239,
        247,
        251,
        253,
        254,
        319,
        351,
    ]
    assert scores == sorted(scores, reverse=True)
    assert sorted(values) == list(range(512))
    assert len(set(values)) == 512
    assert proof["plan_sha256"] == _VC.EXPECTED_PLAN_SHA256
    assert proof["schedule_sha256"] == _VC.EXPECTED_SCHEDULE_SHA256
    assert proof["coverage_proof_sha256"] == _VC.EXPECTED_COVERAGE_PROOF_SHA256
    assert proof["complete_projection_domain"] is True
    assert proof["pairwise_disjoint_by_unique_fixed_patterns"] is True
    assert proof["logical_assignments_per_subspace"] == 1 << 15
    assert proof["total_logical_assignments"] == 1 << 24
    assert proof["covers_complete_assignment_space"] is True
    assert proof["runtime_assignment_or_target_projection_input_used"] is False
    assert proof["historical_instance_results_informed_schedule_hypothesis"] is True
    assert proof["blind_holdout"] is False
    for row in plan:
        assert len(row["retained_linearized_edges"]) == row["interaction_preservation_score"]
        assert len(row["deleted_quadratic_edges"]) == 9 - row["interaction_preservation_score"]

    phases, phase_proof = _VC._freeze_execution_phases(plan)
    _VC._canonical_execution_phase_gate(phases, phase_proof)
    assert [phase["name"] for phase in phases] == ["complete_uniform"]
    assert [phase["projection_value_count"] for phase in phases] == [512]
    assert [phase["timeout_seconds_per_subspace"] for phase in phases] == [120]
    assert phases[0]["projection_values"] == values
    assert phases[0]["uniform_budget_assigned_to_every_planned_projection_value"] is True
    assert phases[0]["historical_a148_a149_results_informed_mechanism_and_budget"] is True
    assert phases[0]["blind_holdout"] is False
    assert phase_proof["planned_attempt_count"] == 512
    assert phase_proof["every_planned_projection_value_is_assigned_one_uniform_attempt"] is True
    assert phase_proof["phase_plan_sha256"] == _VC.EXPECTED_EXECUTION_PHASE_PLAN_SHA256
    assert phase_proof["execution_phase_proof_sha256"] == _VC.EXPECTED_EXECUTION_PHASE_PROOF_SHA256


def test_instrumented_projection_rank_is_only_a_posthoc_audit() -> None:
    selection, _ = _canonical_selection()
    plan, _ = _VC._freeze_assignment_free_plan(selection)
    variant, problem = _canonical_problem()
    actual = _VC._WINDOW._extract_window(problem["base_state"], variant, problem["positions"])
    projection = _VC._project_assignment(actual, selection["selected_coordinates"])
    values = [row["fixed_value"] for row in plan]
    assert actual == 4845375
    assert projection == 319
    assert values.index(projection) == 18
    assert all(row["runtime_assignment_or_target_projection_input_used"] is False for row in plan)
    assert all(row["historical_instance_results_informed_schedule_hypothesis"] for row in plan)
    assert all(row["blind_holdout"] is False for row in plan)


def test_uniform_schedule_stops_only_after_complete_verified_wave(
    tmp_path: Path,
) -> None:
    writer = _VC._SMT.BooleanSMT(seed=3)
    inputs = [writer.declare("x") for _ in range(4)]
    plan = _scheduled_small_plan(4, [0, 1, 2])
    phases, _proof = _VC._freeze_execution_phases(plan, timeout_seconds=2)

    def fake_solver(
        _z3_path: Path, smt_path: Path, _timeout: int, _inputs: list[str]
    ) -> dict[str, Any]:
        value = int(smt_path.stem.rsplit("subspace", 1)[1])
        if value == 7:
            return _fake_solver_result("sat", 0)
        if value == 5:
            return _fake_solver_result("sat", 5)
        return _fake_solver_result("unknown", None)

    def fake_verify(_problem: dict[str, Any], _variant: Any, assignment: int) -> dict[str, Any]:
        return _verification(assignment == 5)

    execution = _VC._execute_assignment_free_phases(
        plan=plan,
        phases=phases,
        coordinates=[0, 1, 2],
        writer=writer,
        inputs=inputs,
        problem={},
        variant=object(),
        z3=Path("z3"),
        work_dir=tmp_path,
        run_solver=fake_solver,
        verify_assignment=fake_verify,
    )
    assert [record["name"] for record in execution["executed_phases"]] == ["complete_uniform"]
    uniform = execution["executed_phases"][0]["execution"]
    assert uniform["executed_projection_values"] == [7, 3, 5, 6, 1]
    assert uniform["waves"][0]["stop_after_wave"] is True
    assert execution["reconstructed_assignment"] == 5
    assert execution["all_executed_phases_form_exact_phase_prefix"] is True
    assert execution["attempted_projection_values"] == [7, 3, 5, 6, 1]
    assert execution["uniform_budget_assigned_to_every_planned_projection_value"] is True
    assert execution["all_attempted_projection_values_use_the_assigned_uniform_budget"] is True
    assert execution["historical_a148_a149_results_informed_mechanism_and_budget"] is True
    assert execution["blind_holdout"] is False
    assert not list(tmp_path.rglob("*.smt2"))
    _VC._phased_execution_gate(execution, plan, phases)


def test_small_real_solver_wave_keeps_independent_complete_check(tmp_path: Path) -> None:
    variant = _VC._BASE.VARIANTS["shake128"]
    problem = _VC._NATIVE._problem(variant, 4, 89751001)
    plan = _scheduled_small_plan(4, [0])
    writer, inputs, _encoding = _VC._R1._SPLIT._encode_problem(
        problem, variant, 89751001, prefix_rounds=1
    )
    execution = _VC._execute_assignment_free_waves(
        plan=plan,
        coordinates=[0],
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
    actual = _VC._WINDOW._extract_window(problem["base_state"], variant, problem["positions"])
    assert execution["planned_projection_values"] == [1, 0]
    assert execution["executed_projection_values"] == [1, 0]
    assert execution["reconstructed_assignment"] == actual
    assert execution["independently_verified_assignments"] == [actual]
    confirmed = [
        row for row in execution["waves"][0]["subspaces"] if row["independently_confirmed_model"]
    ]
    assert len(confirmed) == 1
    assert confirmed[0]["independent_end_state_check"]["rate_bits_checked"] == 1344
    assert confirmed[0]["independent_end_state_check"]["complete_rate_match"] is True
    assert not list(tmp_path.glob("*.smt2"))


def test_reader_is_exact_neutral_four_triplet_chain(tmp_path: Path) -> None:
    selection, vertex_proof = _canonical_selection()
    plan, plan_proof = _VC._freeze_assignment_free_plan(selection)
    phases, phase_proof = _VC._freeze_execution_phases(plan)
    writer = _VC._SMT.BooleanSMT(seed=7)
    inputs = [writer.declare("x") for _ in range(24)]

    def fake_solver(
        _z3_path: Path, _smt_path: Path, _timeout: int, _inputs: list[str]
    ) -> dict[str, Any]:
        return _fake_solver_result("sat", 0)

    def fake_verify(_problem: dict[str, Any], _variant: Any, _assignment: int) -> dict[str, Any]:
        return _verification(True)

    execution = _VC._execute_assignment_free_phases(
        plan=plan,
        phases=phases,
        coordinates=selection["selected_coordinates"],
        writer=writer,
        inputs=inputs,
        problem={},
        variant=object(),
        z3=Path("z3"),
        work_dir=tmp_path / "smt",
        run_solver=fake_solver,
        verify_assignment=fake_verify,
    )
    path = tmp_path / "width24-vertex-cover.causal"
    _VC._build_graph(
        path,
        selection,
        vertex_proof,
        plan,
        plan_proof,
        phases,
        phase_proof,
        execution,
    )
    reader = CryptoCausalReader(path)
    rows = reader.triplets(include_inferred=False)
    by_id = {row["edge_id"]: row for row in rows}
    ids = [
        "shake128-r1-width24-exact-disjoint-interaction-graph",
        "shake128-r1-width24-minimum-vertex-cover",
        "shake128-r1-width24-complete-interaction-preserving-plan",
        "shake128-r1-width24-assignment-free-wave-execution",
    ]
    assert reader.verify_provenance()
    assert len(rows) == 4
    assert set(by_id) == set(ids)
    for left, right in zip(ids[:-1], ids[1:], strict=True):
        assert by_id[right]["provenance"] == [left]
        assert by_id[left]["outcome"] == by_id[right]["trigger"]
    assert by_id[ids[2]]["attrs"]["runtime_assignment_or_projection_input_used"] is False
    assert by_id[ids[2]]["attrs"]["historical_instance_results_informed_mechanism"] is True
    assert by_id[ids[2]]["attrs"]["blind_holdout"] is False
    assert "instrumented_assignment" not in json.dumps(rows, sort_keys=True)


def test_regenerated_unpartitioned_smt_matches_hash_gated_a138() -> None:
    retained = _VC._FRONTIER._load_a138_width24_gate(A138_PATH)
    variant, problem = _canonical_problem()
    writer, inputs, _encoding = _VC._R1._SPLIT._encode_problem(
        problem, variant, _VC.SEED, prefix_rounds=1
    )
    raw = writer.render(inputs, include_model=True)
    assert _VC.hashlib.sha256(raw).hexdigest() == _VC.UNPARTITIONED_SMT_SHA256
    assert retained["encoding"]["first_smt_sha256"] == _VC.UNPARTITIONED_SMT_SHA256


def test_retained_uniform_production_artifacts_are_hash_exact() -> None:
    assert (
        _VC.hashlib.sha256(RESULT_PATH.read_bytes()).hexdigest()
        == "3ea9f21a6cfde4f5728f4860181b4d32317be9d9eeb7296b3b81427faa1d75ee"
    )
    payload = json.loads(RESULT_PATH.read_text())
    assert payload["schema"] == "shake-symbolic-r1-width24-vertex-cover-reader-v1"
    assert payload["parameters"]["solver"].startswith(_VC.EXPECTED_Z3_VERSION_PREFIX)
    assert payload["parameters"]["uniform_timeout_seconds_per_subspace"] == 120
    assert payload["parameters"]["not_a_blind_holdout"] is True
    phases = payload["assignment_free_execution_phase_plan"]["phases"]
    assert len(phases) == 1
    assert phases[0]["name"] == "complete_uniform"
    assert phases[0]["projection_value_count"] == 512
    assert (
        phases[0]["projection_values"]
        == payload["assignment_free_plan"]["planned_projection_values"]
    )
    execution = payload["execution"]
    assert execution["attempt_count"] == 20
    assert execution["status_counts"] == {
        "sat": 1,
        "unsat": 0,
        "unknown": 19,
        "error": 0,
    }
    assert execution["reconstructed_assignment"] == 4845375
    assert execution["independently_confirmed_projection_values"] == [319]
    assert execution["stopped_only_after_independent_complete_check"] is True
    assert "wallclock" not in json.dumps(payload, sort_keys=True).lower()
    reader = CryptoCausalReader(RESULT_CAUSAL_PATH)
    assert reader.file_sha256 == "9ef1f40d369c88fb7ea05afec026fcc59a67f9028e405a788f696ec2588f932b"
    assert reader.graph_sha256 == "431cd36290df6088a017ee9267f43ab0c7796465ff6ae0dbc952f921b5aa7f29"
    assert reader.verify_provenance()
    assert len(reader.triplets(include_inferred=False)) == 4

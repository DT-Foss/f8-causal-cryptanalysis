from __future__ import annotations

import ast
import hashlib
import importlib.util
import json
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

import numpy as np
import pytest

MODULE_PATH = (
    Path(__file__).parents[1]
    / "research"
    / "experiments"
    / "shake_symbolic_r1_width24_prospective_transfer.py"
)
SPEC = importlib.util.spec_from_file_location(
    "shake_symbolic_r1_width24_prospective_transfer_tested", MODULE_PATH
)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)
MODULE._load_runtime_modules(Path(__file__).parents[1])


def _git(*args: str, cwd: Path) -> str:
    return subprocess.run(
        ["git", *args],
        cwd=cwd,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()


def test_protocol_and_seed_are_exactly_hash_gated() -> None:
    protocol_path = Path(MODULE.PROTOCOL_RELATIVE_PATH)
    raw = protocol_path.read_bytes()
    assert hashlib.sha256(raw).hexdigest() == MODULE.PROTOCOL_SHA256
    protocol = MODULE._load_protocol(protocol_path)
    seed = MODULE._derive_seed()
    assert protocol["seed_derivation"]["derived_seed"] == MODULE.EXPECTED_SEED
    assert seed["digest_sha256"] == MODULE.EXPECTED_SEED_DIGEST
    assert seed["derived_seed"] == 260_592_673
    assert protocol["prospective_boundary"]["blind_new_instance_transfer"] is True


def test_protocol_rejects_any_byte_change(tmp_path: Path) -> None:
    payload = json.loads(Path(MODULE.PROTOCOL_RELATIVE_PATH).read_text())
    payload["solver_plan"]["wave_size"] = 4
    path = tmp_path / "changed.json"
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n")
    with pytest.raises(RuntimeError, match="protocol hash differs"):
        MODULE._load_protocol(path)


def test_z3_version_gate_accepts_exact_semantic_version_and_rejects_drift() -> None:
    observed = "Z3 version 4.15.4 - 64 bit"
    assert MODULE._z3_version_gate(observed) == observed
    with pytest.raises(RuntimeError, match="semantic version 4.15.4"):
        MODULE._z3_version_gate("Z3 version 4.15.3 - 64 bit")


def test_exact_minimum_vertex_cover_proves_size_and_lexicographic_tie_break() -> None:
    proof = MODULE._exact_minimum_vertex_cover([(0, 3), (1, 4), (2, 5)], 6)
    assert proof["minimum_vertex_cover_size"] == 3
    assert proof["minimum_cover_count"] == 8
    assert proof["selected_coordinates"] == [0, 1, 2]
    assert proof["uncovered_edges"] == []
    assert proof["subsets_exhaustively_checked_by_size"] == {
        "0": 1,
        "1": 6,
        "2": 15,
        "3": 20,
    }
    assert proof["all_sizes_through_minimum_exhausted"] is True


def test_exact_minimum_vertex_cover_handles_non_bipartite_graph() -> None:
    proof = MODULE._exact_minimum_vertex_cover([(0, 1), (1, 2), (0, 2)], 3)
    assert proof["minimum_vertex_cover_size"] == 2
    assert proof["minimum_cover_count"] == 3
    assert proof["selected_coordinates"] == [0, 1]
    assert proof["selected_set_is_vertex_cover"] is True


def test_formula_only_schedule_is_complete_and_uses_declared_order() -> None:
    edges = [[0, 2], [1, 3]]
    selection = {
        "selected_coordinates": [0, 1],
        "interaction_edges": edges,
    }
    plan, proof = MODULE._freeze_plan(selection)
    assert [row["fixed_value"] for row in plan] == [3, 1, 2, 0]
    assert [row["interaction_preservation_score"] for row in plan] == [2, 1, 1, 0]
    assert proof["complete_projection_domain"] is True
    assert proof["pairwise_disjoint_by_unique_fixed_patterns"] is True
    assert proof["total_logical_assignments"] == 1 << MODULE.WINDOW_BITS
    assert all(row["runtime_assignment_or_target_projection_input_used"] is False for row in plan)


def test_linearization_score_distinguishes_free_linear_and_constant_edges() -> None:
    score, retained, deleted, constant = MODULE._linearization_score(
        0b01,
        [0, 1],
        [(0, 2), (1, 3), (0, 1)],
    )
    assert score == 1
    assert retained == [[0, 2]]
    assert deleted == [[1, 3]]
    assert constant == [[0, 1]]


def test_execution_phase_is_uniform_and_complete() -> None:
    plan, _ = MODULE._freeze_plan(
        {"selected_coordinates": [0, 1], "interaction_edges": [[0, 2], [1, 3]]}
    )
    phases, proof = MODULE._freeze_phases(plan)
    assert len(phases) == 1
    assert phases[0]["projection_value_count"] == 4
    assert phases[0]["timeout_seconds_per_subspace"] == 120
    assert phases[0]["projection_values"] == [3, 1, 2, 0]
    assert proof["complete_formula_ranked_domain_planned"] is True
    assert proof["blind_new_instance_transfer"] is True
    assert proof["historical_A148_through_A151_informed_rule_and_budget"] is True
    assert proof["new_seed_outcomes_informed_phase_plan"] is False


def test_empty_graph_produces_one_complete_full_space_projection() -> None:
    cover = MODULE._exact_minimum_vertex_cover([], MODULE.WINDOW_BITS)
    assert cover["selected_coordinates"] == []
    assert cover["minimum_vertex_cover_size"] == 0
    selection = {"selected_coordinates": [], "interaction_edges": []}
    plan, proof = MODULE._freeze_plan(selection)
    phases, phase_proof = MODULE._freeze_phases(plan)
    assert len(plan) == 1
    assert plan[0]["fixed_value"] == 0
    assert plan[0]["fixed_coordinates"] == []
    assert plan[0]["logical_assignments"] == 1 << MODULE.WINDOW_BITS
    assert proof["covers_complete_assignment_space"] is True
    assert phases[0]["projection_values"] == [0]
    assert phase_proof["planned_attempt_count"] == 1

    class Writer:
        @staticmethod
        def render(inputs: list[str], *, include_model: bool) -> bytes:
            assert inputs == ["x0"]
            assert include_model is True
            return b"monolithic"

    assert MODULE._render_fixed_coordinates_allow_empty(Writer(), ["x0"], [], 0) == b"monolithic"


def test_runtime_problem_clears_hidden_window_and_drops_instrumented_fields() -> None:
    variant = MODULE._BASE.VARIANTS["shake128"]
    state = np.zeros((1, 25), dtype=np.uint64)
    positions = np.arange(0, MODULE.WINDOW_BITS, dtype=np.int64)
    capacity_lane = variant.rate_lanes
    state[0, capacity_lane] = np.uint64((1 << MODULE.WINDOW_BITS) - 1)
    target = np.arange(variant.rate_lanes, dtype=np.uint64).reshape(1, -1)
    problem = {
        "base_state": state,
        "positions": positions,
        "target": target,
        "message": np.array([[1, 2, 3]], dtype=np.uint8),
        "wrong_state": state.copy(),
    }
    runtime = MODULE._sanitized_runtime_problem(problem, variant)
    assert set(runtime) == {"base_state", "positions", "target", "template"}
    assert int(runtime["base_state"][0, capacity_lane]) == 0
    assert np.array_equal(runtime["target"], target)
    state[0, capacity_lane] = np.uint64(0)
    target[0, 0] = np.uint64(999)
    assert int(runtime["target"][0, 0]) != 999
    summary = MODULE._runtime_instance_summary(runtime, variant)
    assert summary["capacity_window_positions"] == list(range(MODULE.WINDOW_BITS))
    assert summary["target_rate_bits"] == 1344
    assert summary["instrumented_assignment_or_projection_included"] is False


def test_push_only_github_url_does_not_bypass_public_fetch_remote_gate(
    tmp_path: Path,
) -> None:
    bare = tmp_path / "remote.git"
    work = tmp_path / "work"
    bare.mkdir()
    work.mkdir()
    _git("init", "--bare", cwd=bare)
    _git("init", "-b", "main", cwd=work)
    _git("config", "user.name", "David Tom Foss", cwd=work)
    _git("config", "user.email", "david.tom.foss@example.invalid", cwd=work)
    target = work / MODULE.PROTOCOL_RELATIVE_PATH
    target.parent.mkdir(parents=True)
    target.write_bytes(Path(MODULE.PROTOCOL_RELATIVE_PATH).read_bytes())
    runner = work / MODULE.RUNNER_RELATIVE_PATH
    runner.parent.mkdir(parents=True)
    runner.write_bytes(MODULE_PATH.read_bytes())
    _git("add", MODULE.PROTOCOL_RELATIVE_PATH, MODULE.RUNNER_RELATIVE_PATH, cwd=work)
    _git("commit", "-m", "Freeze A152 protocol", cwd=work)
    commit = _git("rev-parse", "HEAD", cwd=work)
    _git("remote", "add", "origin", str(bare), cwd=work)
    _git("push", "-u", "origin", "main", cwd=work)
    _git(
        "remote",
        "set-url",
        "--push",
        "origin",
        "https://github.com/DT-Foss/f8-causal-cryptanalysis.git",
        cwd=work,
    )
    assert commit
    assert MODULE._has_exact_public_fetch_remote(work) is False
    with pytest.raises(RuntimeError, match="supplied frozen public worktree"):
        MODULE._public_freeze_gate(work, commit)


def test_production_paths_are_absolute_distinct_and_outside_public_worktree(
    tmp_path: Path,
) -> None:
    repo = tmp_path / "public"
    external = tmp_path / "external"
    repo.mkdir()
    external.mkdir()
    output = external / MODULE.RESULT_FILENAME
    causal = external / MODULE.CAUSAL_FILENAME
    work = external / "work"
    assert MODULE._production_path_gate(repo, output, causal, work) == (
        output,
        causal,
        work,
    )
    with pytest.raises(ValueError, match="must be distinct"):
        MODULE._production_path_gate(repo, output, output, work)
    with pytest.raises(ValueError, match="outside public worktree"):
        MODULE._production_path_gate(repo, repo / MODULE.RESULT_FILENAME, causal, work)
    with pytest.raises(ValueError, match="filenames must match"):
        MODULE._production_path_gate(repo, external / "wrong.json", causal, work)


def test_prospective_execution_gate_rejects_solver_errors_and_bad_sat(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(MODULE._A151, "_phased_execution_gate", lambda *_: None)

    def execution(row: dict[str, object], *, verified: bool = True) -> dict[str, object]:
        row["solver"].update(
            {
                "return_code": 0,
                "external_timeout": False,
                "command_parameters": {
                    "threads": 1,
                    "timeout_seconds": 120,
                    "representation": "Boolean_SMT_native_nary_XOR",
                },
            }
        )
        status = str(row["solver"]["status"])
        counts = {name: int(name == status) for name in ("sat", "unsat", "unknown", "error")}
        return {
            "attempt_count": 1,
            "status_counts": counts,
            "all_returned_assignments_independently_checked": True,
            "all_found_assignments_independently_verified": verified,
            "executed_phases": [{"execution": {"waves": [{"subspaces": [row]}]}}],
        }

    error_row = {
        "solver": {"status": "error"},
        "assignment": None,
        "independent_end_state_check": {"performed": False},
        "independently_confirmed_model": False,
    }
    with pytest.raises(RuntimeError, match="invalid solver/check outcome"):
        MODULE._prospective_execution_gate(execution(error_row), [], [], [0])

    crashed = {
        "solver": {"status": "crashed"},
        "assignment": None,
        "independent_end_state_check": {"performed": False},
        "independently_confirmed_model": False,
    }
    with pytest.raises(RuntimeError, match="invalid solver/check outcome"):
        MODULE._prospective_execution_gate(execution(crashed), [], [], [0])

    bad_sat = {
        "solver": {"status": "sat"},
        "assignment": 3,
        "independent_end_state_check": {
            "performed": True,
            "rate_bits_checked": 1344,
            "complete_rate_match": False,
            "candidate_rate_sha256": "a",
            "target_rate_sha256": "b",
        },
        "independently_confirmed_model": False,
    }
    with pytest.raises(RuntimeError, match="SAT model failed"):
        MODULE._prospective_execution_gate(execution(bad_sat), [], [], [0])

    mismatched_projection = {
        "fixed_value": 1,
        "solver": {"status": "sat"},
        "assignment": 0,
        "independent_end_state_check": {
            "performed": True,
            "rate_bits_checked": 1344,
            "complete_rate_match": True,
            "candidate_rate_sha256": "same",
            "target_rate_sha256": "same",
        },
        "independently_confirmed_model": True,
    }
    with pytest.raises(RuntimeError, match="SAT model failed"):
        MODULE._prospective_execution_gate(execution(mismatched_projection), [], [], [0])


def test_normalized_execution_keeps_historical_scope_and_new_seed_blindness() -> None:
    raw = {
        "executed_phases": [
            {
                "execution": {},
                "historical_A148_through_A151_informed_rule_and_budget": True,
            }
        ]
    }
    normalized = MODULE._normalize_prospective_execution(raw)
    assert normalized["historical_a148_a149_results_informed_mechanism_and_budget"] is True
    assert normalized["new_seed_assignment_projection_or_solver_outcomes_informed_plan"] is False
    nested = normalized["executed_phases"][0]["execution"]
    assert nested["historical_instance_results_informed_schedule_hypothesis"] is True
    assert nested["new_seed_assignment_projection_or_solver_outcomes_informed_plan"] is False


def test_posthoc_witness_audit_rejects_unsat_true_projection(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    check = {
        "performed": True,
        "rate_bits_checked": 1344,
        "complete_rate_match": True,
        "candidate_rate_sha256": "same",
        "target_rate_sha256": "same",
    }
    monkeypatch.setattr(MODULE._A151, "_independent_end_state_check", lambda *_: check)
    execution = {
        "reconstructed_assignment": None,
        "executed_phases": [
            {
                "execution": {
                    "waves": [{"subspaces": [{"fixed_value": 0, "solver": {"status": "unsat"}}]}]
                }
            }
        ],
    }
    with pytest.raises(RuntimeError, match="witness subspace UNSAT"):
        MODULE._posthoc_witness_audit(
            runtime_problem={},
            variant=object(),
            instrumented_assignment=0,
            instrumented_projection=0,
            plan=[{"fixed_value": 0}],
            execution=execution,
        )


def test_structure_only_artifacts_are_path_independent(tmp_path: Path) -> None:
    protocol_gate = {
        "passed": True,
        "repository": MODULE.PUBLIC_REPOSITORY,
        "commit": "1" * 40,
    }
    instance = {"target_rate_sha256": "target", "instrumented_assignment_included": False}
    selection = {
        "partition_bits": 13,
        "selection_sha256": "selection",
        "interaction_edges_sha256": "edges",
    }
    cover = {"proof_sha256": "cover"}
    causal_a = MODULE._build_structure_only_causal(
        tmp_path / "a" / "result.causal",
        protocol_gate=protocol_gate,
        instance_summary=instance,
        selection=selection,
        cover_proof=cover,
    )
    causal_b = MODULE._build_structure_only_causal(
        tmp_path / "b" / "other.causal",
        protocol_gate=protocol_gate,
        instance_summary=instance,
        selection=selection,
        cover_proof=cover,
    )
    assert causal_a == causal_b
    assert "path" not in causal_a["stats"]
    hashes_a = MODULE._write_and_reopen_result(
        tmp_path / "a" / "result.json",
        tmp_path / "a" / "result.causal",
        {"schema": "test", "causal": causal_a},
    )
    hashes_b = MODULE._write_and_reopen_result(
        tmp_path / "b" / "other.json",
        tmp_path / "b" / "other.causal",
        {"schema": "test", "causal": causal_b},
    )
    assert hashes_a == hashes_b


def test_verify_freeze_only_never_constructs_prospective_instance(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setattr(MODULE, "_public_freeze_gate", lambda *_: {"passed": True})
    monkeypatch.setattr(MODULE, "_load_protocol", lambda *_: {"schema": "test"})
    monkeypatch.setattr(MODULE, "_load_anchor", lambda *_: {"sha256": MODULE.A151_SHA256})
    monkeypatch.setattr(MODULE, "_derive_seed", lambda *_: {"derived_seed": MODULE.EXPECTED_SEED})
    monkeypatch.setattr(MODULE, "_load_runtime_modules", lambda *_: {"loaded": True})
    monkeypatch.setattr(
        MODULE._NATIVE,
        "_problem",
        lambda *_: (_ for _ in ()).throw(AssertionError("instance generated")),
    )
    monkeypatch.setattr(
        MODULE.subprocess,
        "run",
        lambda *_, **__: SimpleNamespace(stdout="Z3 version 4.15.4 - 64 bit\n"),
    )
    MODULE.main(
        [
            "--public-freeze-repo",
            str(tmp_path),
            "--public-freeze-commit",
            "0" * 40,
            "--z3",
            sys.executable,
            "--verify-freeze-only",
        ]
    )
    output = json.loads(capsys.readouterr().out)
    assert output["instance_generated"] is False


def test_production_source_orders_freeze_before_instance_and_posthoc_extraction() -> None:
    source = MODULE_PATH.read_text()
    tree = ast.parse(source)
    assert not any(
        isinstance(node, ast.ImportFrom)
        and node.module is not None
        and node.module.startswith("arx_carry_leak")
        for node in tree.body
    )
    assert not any(
        isinstance(node, (ast.Assign, ast.AnnAssign))
        and isinstance(node.value, ast.Call)
        and isinstance(node.value.func, ast.Name)
        and node.value.func.id == "_import_sibling"
        for node in tree.body
    )
    main = source[source.index("def main(") :]
    freeze = main.index("freeze_gate = _public_freeze_gate")
    dependency_load = main.index("dependency_gate = _load_runtime_modules")
    instantiate = main.index("instrumented_problem = _NATIVE._problem")
    execute = main.index("execution = _A151._execute_assignment_free_phases")
    extract = main.index("instrumented_assignment = _WINDOW._extract_window")
    assert freeze < dependency_load < instantiate < execute < extract
    assert "--public-freeze-repo" in main
    assert "--public-freeze-commit" in main
    assert "--verify-freeze-only" in main

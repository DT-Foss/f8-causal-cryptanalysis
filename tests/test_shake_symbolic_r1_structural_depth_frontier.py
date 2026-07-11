from __future__ import annotations

import hashlib
import importlib.util
import shutil
import sys
from pathlib import Path

import numpy as np
import pytest

from arx_carry_leak.crypto_causal import CryptoCausalReader

_ROOT = Path(__file__).parents[1]
_SCRIPT = (
    _ROOT
    / "research"
    / "experiments"
    / "shake_symbolic_r1_structural_depth_frontier.py"
)
_SPEC = importlib.util.spec_from_file_location(
    "shake_symbolic_r1_structural_depth_frontier", _SCRIPT
)
assert _SPEC is not None and _SPEC.loader is not None
_FRONTIER = importlib.util.module_from_spec(_SPEC)
sys.modules[_SPEC.name] = _FRONTIER
_SPEC.loader.exec_module(_FRONTIER)

_RESULTS = _ROOT / "research" / "results" / "v1"
A138_PATH = _RESULTS / "shake_symbolic_r1_scaling_reader_v1.json"
A141_PATH = _RESULTS / "shake_symbolic_r1_structural_partition_reader_v1.json"
A143_PATH = _RESULTS / "shake_symbolic_r1_structural6_partition_reader_v1.json"


def _z3() -> Path:
    path = Path(shutil.which("z3") or "/opt/homebrew/bin/z3")
    if not path.is_file():
        pytest.skip("Z3 CLI is not installed")
    return path


def _canonical_problem() -> tuple[object, dict[str, object]]:
    variant = _FRONTIER._BASE.VARIANTS["shake128"]
    problem = _FRONTIER._NATIVE._problem(variant, 20, 89755037)
    return variant, problem


def _canonical_selections() -> list[dict[str, object]]:
    variant, problem = _canonical_problem()
    return _FRONTIER._derive_depth_sequence(
        problem["base_state"], variant, problem["positions"], (4, 6, 8, 10)
    )


def test_a138_a141_a143_hash_and_status_gates() -> None:
    a138 = _FRONTIER._load_a138_gate(A138_PATH)
    a141 = _FRONTIER._load_a141_gate(A141_PATH)
    a143 = _FRONTIER._load_a143_gate(A143_PATH)

    assert hashlib.sha256(A138_PATH.read_bytes()).hexdigest() == (
        _FRONTIER.A138_JSON_SHA256
    )
    assert hashlib.sha256(A141_PATH.read_bytes()).hexdigest() == _FRONTIER.A141_SHA256
    assert hashlib.sha256(A143_PATH.read_bytes()).hexdigest() == _FRONTIER.A143_SHA256
    assert (
        a138["encoding"]["first_smt_sha256"]
        == a141["trial"]["encoding"]["unpartitioned_smt_sha256"]
        == a143["trial"]["encoding"]["unpartitioned_smt_sha256"]
        == _FRONTIER.UNPARTITIONED_SMT_SHA256
    )
    assert a138["first_solver"]["status"] == "unknown"
    assert a141["trial"]["status_counts"] == {
        "sat": 0,
        "unsat": 0,
        "unknown": 16,
        "error": 0,
    }
    assert a143["trial"]["status_counts"] == {
        "sat": 0,
        "unsat": 0,
        "unknown": 64,
        "error": 0,
    }


@pytest.mark.parametrize(
    ("source", "loader"),
    [
        (A138_PATH, _FRONTIER._load_a138_gate),
        (A141_PATH, _FRONTIER._load_a141_gate),
        (A143_PATH, _FRONTIER._load_a143_gate),
    ],
)
def test_hash_gates_reject_any_byte_change(
    tmp_path: Path, source: Path, loader: object
) -> None:
    changed = tmp_path / source.name
    changed.write_bytes(source.read_bytes() + b"\n")
    with pytest.raises(RuntimeError, match="hash differs"):
        loader(changed)


def test_canonical_max_cover_sets_and_ties_for_all_four_depths() -> None:
    selections = _canonical_selections()
    _FRONTIER._canonical_depth_sequence_gate(selections)
    assert [row["partition_bits"] for row in selections] == [4, 6, 8, 10]
    for row in selections:
        depth = row["partition_bits"]
        assert row["selected_coordinates"] == _FRONTIER.EXPECTED_COORDINATES[depth]
        assert row["maximum_covered_edge_count"] == (
            _FRONTIER.EXPECTED_COVERAGE[depth]
        )
        assert row["tie_count"] == _FRONTIER.EXPECTED_TIE_COUNTS[depth]
        assert row["maximizing_coordinate_sets"] == (
            _FRONTIER.EXPECTED_MAXIMIZERS[depth]
        )
        assert row["interaction_edges_sha256"] == (
            _FRONTIER.INTERACTION_EDGES_SHA256
        )


def test_depth10_is_the_unique_vertex_cover_and_has_no_residual_edges() -> None:
    selections = _canonical_selections()
    plan = _FRONTIER._unconditioned_depth_plan(selections)
    deepest = plan[-1]
    assert deepest["depth"] == 10
    assert deepest["selected_coordinates"] == [1, 2, 4, 7, 9, 10, 12, 15, 17, 18]
    assert deepest["covered_edge_count"] == 28
    assert len(deepest["covered_edges"]) == 28
    assert deepest["residual_edge_count"] == 0
    assert deepest["residual_edges"] == []
    assert deepest["tie_count"] == 1


def test_selection_finishes_without_assignment_then_branch_projection_is_exact(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    variant, problem = _canonical_problem()
    original = np.array(problem["base_state"], copy=True)
    changed = np.array(problem["base_state"], copy=True)
    for position in problem["positions"]:
        lane = variant.rate_lanes + int(position) // 64
        bit = int(position) % 64
        changed[0, lane] ^= np.uint64(1) << np.uint64(bit)

    def forbidden_posthoc(*_args: object, **_kwargs: object) -> int:
        raise AssertionError("assignment extraction must not run during selection")

    monkeypatch.setattr(_FRONTIER._WINDOW, "_extract_window", forbidden_posthoc)
    first = _FRONTIER._derive_depth_sequence(
        original, variant, problem["positions"], (4, 6, 8, 10)
    )
    second = _FRONTIER._derive_depth_sequence(
        changed, variant, problem["positions"], (4, 6, 8, 10)
    )
    assert first == second
    unconditioned = _FRONTIER._unconditioned_depth_plan(first)
    assert all("projection_value" not in row for row in unconditioned)
    assert all(row["stored_assignment_used_for_coordinate_selection"] is False for row in unconditioned)

    conditioned = _FRONTIER._condition_depth_plan(
        unconditioned, _FRONTIER.CANONICAL_ASSIGNMENT
    )
    assert [row["projection_value"] for row in conditioned] == [5, 21, 38, 334]
    assert all(row["posthoc_assignment_used_for_branch_value"] is True for row in conditioned)
    for row in conditioned:
        projected = _FRONTIER._project_assignment(
            _FRONTIER.CANONICAL_ASSIGNMENT, row["selected_coordinates"]
        )
        assert row["projection_value"] == projected


def test_renderer_fixes_exactly_the_selected_noncontiguous_coordinates() -> None:
    writer = _FRONTIER._SMT.BooleanSMT(seed=17)
    inputs = [writer.declare("x") for _ in range(20)]
    coordinates = [1, 2, 4, 9, 10, 12, 15, 18]
    raw = _FRONTIER._render_conditioned_smt(writer, inputs, coordinates, 38)
    assertions = [line for line in raw.decode().splitlines() if line.startswith("(assert ")]
    assert assertions == [
        f"(assert (not {inputs[1]}))",
        f"(assert {inputs[2]})",
        f"(assert {inputs[4]})",
        f"(assert (not {inputs[9]}))",
        f"(assert (not {inputs[10]}))",
        f"(assert {inputs[12]})",
        f"(assert (not {inputs[15]}))",
        f"(assert (not {inputs[18]}))",
    ]
    assert raw.count(b"(check-sat)\n") == 1
    assert raw.count(b"(get-value (") == 1


def test_k4_actual_branch_is_hash_gated_reuse_not_reexecution() -> None:
    variant, problem = _canonical_problem()
    selections = _canonical_selections()
    unconditioned = _FRONTIER._unconditioned_depth_plan(selections)
    actual = _FRONTIER._WINDOW._extract_window(
        problem["base_state"], variant, problem["positions"]
    )
    conditioned = _FRONTIER._condition_depth_plan(unconditioned, actual)
    writer, inputs, _ = _FRONTIER._R1._SPLIT._encode_problem(
        problem, variant, 89755037, prefix_rounds=1
    )
    raw = _FRONTIER._render_conditioned_smt(
        writer,
        inputs,
        conditioned[0]["selected_coordinates"],
        conditioned[0]["projection_value"],
    )
    row = _FRONTIER._reuse_a141_k4_measurement(
        _FRONTIER._load_a141_gate(A141_PATH),
        conditioned[0],
        raw,
        problem,
        variant,
        actual,
    )
    assert row["projection_value"] == 5
    assert row["smt_bytes"] == 9189200
    assert row["smt_sha256"] == (
        "6cbbc5f3e969f654afc4b5a4e80493140ea1fcdaf6c073aa2242bbd8e0d869a1"
    )
    assert row["solver"]["status"] == "unknown"
    assert row["assignment"] is None
    assert row["executed_in_this_run"] is False
    assert row["reused_from_a141"] is True
    assert row["independent_end_state_check"]["reason"] == "no_solver_assignment"


def test_independent_verifier_checks_all_1344_rate_bits() -> None:
    variant, problem = _canonical_problem()
    actual = _FRONTIER._WINDOW._extract_window(
        problem["base_state"], variant, problem["positions"]
    )
    accepted = _FRONTIER._independent_end_state_check(problem, variant, actual)
    rejected = _FRONTIER._independent_end_state_check(problem, variant, actual ^ 1)
    assert accepted["performed"] is True
    assert accepted["complete_rate_match"] is True
    assert accepted["rate_bits_checked"] == 1344
    assert accepted["rate_lanes_checked"] == 21
    assert accepted["candidate_rate_sha256"] == accepted["target_rate_sha256"]
    assert rejected["complete_rate_match"] is False
    assert rejected["candidate_rate_sha256"] != rejected["target_rate_sha256"]


def test_reader_graph_is_exact_three_triplet_provenance_chain(tmp_path: Path) -> None:
    variant, problem = _canonical_problem()
    selections = _canonical_selections()
    unconditioned = _FRONTIER._unconditioned_depth_plan(selections)
    actual = _FRONTIER._WINDOW._extract_window(
        problem["base_state"], variant, problem["positions"]
    )
    conditioned = _FRONTIER._condition_depth_plan(unconditioned, actual)
    measurements = [
        _FRONTIER._measurement_record(
            row,
            f"depth-{row['depth']}".encode(),
            {
                "status": "unknown",
                "stats": {},
                "return_code": 0,
                "external_timeout": False,
                "command_parameters": {
                    "timeout_seconds": 60,
                    "threads": 1,
                    "representation": "Boolean_SMT_native_nary_XOR",
                },
            },
            None,
            _FRONTIER._independent_end_state_check(problem, variant, None),
            actual,
            source="test_fixture",
            executed_in_this_run=row["depth"] != 4,
            reused_from_a141=row["depth"] == 4,
        )
        for row in conditioned
    ]
    frontier = _FRONTIER._frontier_summary(measurements)
    path = tmp_path / "structural-depth-frontier.causal"
    _, emitted, gate = _FRONTIER._build_graph(
        path, selections, conditioned, measurements, frontier
    )
    reader = CryptoCausalReader(path)
    rows = reader.triplets(include_inferred=False)
    assert emitted == rows
    assert reader.verify_provenance()
    assert gate["passed"] is True
    assert gate["explicit_triplet_count"] == 3
    assert gate["exact_three_edge_chain"] is True
    by_id = {row["edge_id"]: row for row in rows}
    graph_id = "shake128-r1-exact-interaction-graph"
    sequence_id = "shake128-r1-deterministic-depth-sequence-posthoc-values"
    frontier_id = "shake128-r1-conditioned-solvability-frontier"
    assert set(by_id) == {graph_id, sequence_id, frontier_id}
    assert by_id[sequence_id]["provenance"] == [graph_id]
    assert by_id[frontier_id]["provenance"] == [sequence_id]
    assert by_id[graph_id]["outcome"] == by_id[sequence_id]["trigger"]
    assert by_id[sequence_id]["outcome"] == by_id[frontier_id]["trigger"]
    assert by_id[sequence_id]["attrs"]["posthoc_assignment_used_for_branch_value"]
    assert not by_id[sequence_id]["attrs"][
        "stored_assignment_used_for_coordinate_selection"
    ]


def test_small_conditioned_structural_branch_solver_smoke(tmp_path: Path) -> None:
    variant = _FRONTIER._BASE.VARIANTS["shake128"]
    problem = _FRONTIER._NATIVE._problem(variant, 4, 89751001)
    selections = _FRONTIER._derive_depth_sequence(
        problem["base_state"], variant, problem["positions"], (2,)
    )
    unconditioned = _FRONTIER._unconditioned_depth_plan(selections)
    actual = _FRONTIER._WINDOW._extract_window(
        problem["base_state"], variant, problem["positions"]
    )
    conditioned = _FRONTIER._condition_depth_plan(unconditioned, actual)
    writer, inputs, _ = _FRONTIER._R1._SPLIT._encode_problem(
        problem, variant, 89751001, prefix_rounds=1
    )
    row = _FRONTIER._execute_conditioned_depth(
        variant,
        problem,
        writer,
        inputs,
        conditioned[0],
        60,
        _z3(),
        tmp_path,
        False,
        actual,
    )
    assert row["conditioned_subspace_count"] == 1
    assert row["solver"]["status"] == "sat"
    assert row["assignment"] == actual
    assert row["matches_instrumented_assignment_posthoc"] is True
    assert row["correctly_confirmed_model"] is True
    assert row["independent_end_state_check"]["complete_rate_match"] is True
    assert row["independent_end_state_check"]["rate_bits_checked"] == 1344
    assert row["solver"]["command_parameters"]["threads"] == 1

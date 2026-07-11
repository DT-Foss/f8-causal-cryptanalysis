from __future__ import annotations

import importlib.util
import inspect
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
    / "shake_symbolic_r1_structural6_partition_reader.py"
)
_SPEC = importlib.util.spec_from_file_location(
    "shake_symbolic_r1_structural6_partition_reader", _SCRIPT
)
assert _SPEC is not None and _SPEC.loader is not None
_STRUCTURAL6 = importlib.util.module_from_spec(_SPEC)
sys.modules[_SPEC.name] = _STRUCTURAL6
_SPEC.loader.exec_module(_STRUCTURAL6)

_RESULTS = _ROOT / "research" / "results" / "v1"
A138_PATH = _RESULTS / "shake_symbolic_r1_scaling_reader_v1.json"
A141_PATH = _RESULTS / "shake_symbolic_r1_structural_partition_reader_v1.json"


def _z3() -> Path:
    path = Path(shutil.which("z3") or "/opt/homebrew/bin/z3")
    if not path.is_file():
        pytest.skip("Z3 CLI is not installed")
    return path


def _canonical_problem() -> tuple[object, dict[str, object]]:
    variant = _STRUCTURAL6._BASE.VARIANTS["shake128"]
    problem = _STRUCTURAL6._NATIVE._problem(variant, 20, 89755037)
    return variant, problem


def _canonical_selection() -> dict[str, object]:
    variant, problem = _canonical_problem()
    return _STRUCTURAL6._derive_structural_selection(
        problem["base_state"], variant, problem["positions"], 6
    )


def _neutral_trial_stub() -> dict[str, object]:
    return {
        "status_counts": {"sat": 0, "unsat": 0, "unknown": 64, "error": 0},
        "found_assignments": [],
        "verified_assignments": [],
        "subspaces_detail": [],
        "all_found_assignments_independently_verified": True,
        "reconstruction_matches_instrumented_assignment": False,
    }


def test_a141_hash_status_gate_has_16_unknown_subspaces_and_no_models() -> None:
    trial = _STRUCTURAL6._load_a141_gate(A141_PATH)
    assert trial["window_bits"] == 20
    assert trial["seed"] == 89755037
    assert trial["partitioned_coordinates"] == [4, 9, 17, 18]
    assert trial["status_counts"] == {
        "sat": 0,
        "unsat": 0,
        "unknown": 16,
        "error": 0,
    }
    assert len(trial["subspaces_detail"]) == 16
    assert trial["found_assignments"] == []
    assert trial["distinct_found_assignments"] == []
    assert trial["verified_assignments"] == []
    assert trial["reconstructed_assignment"] is None
    assert all(row["assignment"] is None for row in trial["subspaces_detail"])


def test_a138_hash_and_unpartitioned_smt_gate() -> None:
    trial = _STRUCTURAL6._load_a138_gate(A138_PATH)
    assert trial["first_solver"]["status"] == "unknown"
    assert trial["reconstructed_assignment"] is None
    assert (
        trial["encoding"]["first_smt_sha256"]
        == "66aa82020b4dd2b4d21f3065c99ca6f7c9224ab1ab9765f686121f2fe7f8618f"
    )


@pytest.mark.parametrize(
    ("source", "loader"),
    [
        (A138_PATH, _STRUCTURAL6._load_a138_gate),
        (A141_PATH, _STRUCTURAL6._load_a141_gate),
    ],
)
def test_retained_artifact_hash_gates_reject_modified_bytes(
    tmp_path: Path, source: Path, loader: object
) -> None:
    changed = tmp_path / source.name
    changed.write_bytes(source.read_bytes() + b"\n")
    with pytest.raises(RuntimeError, match="hash differs"):
        loader(changed)


def test_canonical_r1_six_coordinate_max_cover_selection_is_unique() -> None:
    variant, problem = _canonical_problem()
    template = _STRUCTURAL6._WINDOW._clear_window(
        problem["base_state"], variant, problem["positions"]
    )
    polynomials = _STRUCTURAL6._R1._SPLIT._symbolic_prefix_polynomials(
        template, variant, problem["positions"], prefix_rounds=1
    )
    masks, edges = _STRUCTURAL6._degree_two_monomial_edges(polynomials, 20)
    selection = _STRUCTURAL6._structural_selection_from_polynomials(polynomials, 20, 6)

    assert len(masks) == 28
    assert len(edges) == 28
    assert all(left < right for left, right in edges)
    assert selection["maximum_covered_edge_count"] == 20
    assert selection["selected_coordinates"] == [4, 9, 12, 15, 17, 18]
    assert selection["tie_count"] == 1
    assert selection["maximizing_coordinate_sets"] == [[4, 9, 12, 15, 17, 18]]
    assert selection["candidate_set_count"] == 38760
    assert (
        selection["interaction_edges_sha256"]
        == "06b168eb69c5a6687e0f7f001bfdf178ce24e28b2b312a84758bfe872d1b9bda"
    )
    assert (
        selection["selection_sha256"]
        == "233a170be2445150368460b9b208f23a06f439811d2f852cceaa7e4b2d5bcd15"
    )
    assert (
        selection["r1_polynomial_state_sha256"]
        == "b06bab2ca328e7f8521d339e0a86a62a7dfbddc38048388a0dd9285fbe936f1d"
    )
    _STRUCTURAL6._canonical_selection_gate(selection)


def test_max_cover_generic_tie_break_is_lexicographically_first() -> None:
    selection = _STRUCTURAL6._max_cover_selection([(0, 1), (2, 3)], 4, 1)
    assert selection["maximum_covered_edge_count"] == 1
    assert selection["tie_count"] == 4
    assert selection["maximizing_coordinate_sets"] == [[0], [1], [2], [3]]
    assert selection["selected_coordinates"] == [0]


def test_plan64_is_ascending_disjoint_and_covers_all_2_to_20_assignments() -> None:
    selection = _canonical_selection()
    plan = _STRUCTURAL6._complete_subspace_plan_gate(selection)
    expected = list(range(64))
    assert [row["subspace_index"] for row in plan] == expected
    assert [row["fixed_value"] for row in plan] == expected
    assert selection["subspace_values"] == expected
    assert len(plan) == 64
    assert len(
        {
            tuple((cell["coordinate"], cell["value"]) for cell in row["fixed_coordinates"])
            for row in plan
        }
    ) == 64
    assert all(row["logical_assignments"] == 1 << 14 for row in plan)
    assert sum(row["logical_assignments"] for row in plan) == 1 << 20
    assert (
        selection["subspace_plan_sha256"]
        == "ca8e99d9b75bc27670319e9acd2426e98542fec3f2128cc5d660c0ebbbe0f79e"
    )


def test_arbitrary_renderer_fixes_exactly_six_formula_selected_variables() -> None:
    coordinates = _canonical_selection()["selected_coordinates"]
    assert coordinates == [4, 9, 12, 15, 17, 18]
    writer = _STRUCTURAL6._SMT.BooleanSMT(seed=17)
    inputs = [writer.declare("x") for _ in range(20)]
    raw = _STRUCTURAL6._render_fixed_coordinates(writer, inputs, coordinates, 0b101101)
    assertions = [line for line in raw.decode().splitlines() if line.startswith("(assert ")]
    assert assertions == [
        f"(assert {inputs[4]})",
        f"(assert (not {inputs[9]}))",
        f"(assert {inputs[12]})",
        f"(assert {inputs[15]})",
        f"(assert (not {inputs[17]}))",
        f"(assert {inputs[18]})",
    ]
    assert len(assertions) == 6


def test_selection_signature_has_no_posthoc_or_end_state_input_and_clears_window(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    assert list(inspect.signature(_STRUCTURAL6._derive_structural_selection).parameters) == [
        "base_state",
        "variant",
        "positions",
        "partition_bits",
    ]
    assert list(
        inspect.signature(_STRUCTURAL6._structural_selection_from_polynomials).parameters
    ) == ["polynomials", "window_bits", "partition_bits"]

    variant, problem = _canonical_problem()
    original = np.array(problem["base_state"], copy=True)
    changed = np.array(problem["base_state"], copy=True)
    for position in problem["positions"]:
        lane = variant.rate_lanes + int(position) // 64
        bit = int(position) % 64
        changed[0, lane] ^= np.uint64(1) << np.uint64(bit)

    def forbidden_posthoc(*_args: object, **_kwargs: object) -> int:
        raise AssertionError("posthoc extraction must not be called during selection")

    monkeypatch.setattr(_STRUCTURAL6._WINDOW, "_extract_window", forbidden_posthoc)
    first = _STRUCTURAL6._derive_structural_selection(
        original, variant, problem["positions"], 6
    )
    second = _STRUCTURAL6._derive_structural_selection(
        changed, variant, problem["positions"], 6
    )
    assert first == second
    assert first["selected_coordinates"] == [4, 9, 12, 15, 17, 18]
    assert first["actual_assignment_used"] is False
    assert first["posthoc_assignment_used"] is False
    assert first["target_end_state_bits_used"] is False
    assert first["solver_observations_used"] is False


def test_small_formula_selected_partition_solver_smoke(tmp_path: Path) -> None:
    variant = _STRUCTURAL6._BASE.VARIANTS["shake128"]
    trial = _STRUCTURAL6._structural_partition_trial(
        variant,
        4,
        89751001,
        1,
        30,
        2,
        _z3(),
        tmp_path,
        False,
    )
    assert trial["subspace_count"] == 2
    assert trial["status_counts"] == {
        "sat": 1,
        "unsat": 1,
        "unknown": 0,
        "error": 0,
    }
    assert trial["selection_completed_before_subspace_execution"] is True
    assert trial["target_end_state_bits_used_for_selection"] is False
    assert trial["actual_or_posthoc_assignment_used_for_selection"] is False
    assert trial["all_found_assignments_independently_verified"]
    assert trial["reconstruction_matches_instrumented_assignment"]
    verification = next(
        row["independent_verification"]
        for row in trial["subspaces_detail"]
        if row["assignment"] is not None
    )
    assert verification["rate_bits_checked"] == 1344
    assert verification["rate_lanes_checked"] == 21
    assert verification["complete_rate_match"]


def test_reader_graph_has_three_hash_bound_provenance_triplets(tmp_path: Path) -> None:
    selection = _canonical_selection()
    path = tmp_path / "shake-symbolic-r1-structural6-partition.causal"
    _STRUCTURAL6._build_graph(path, selection, _neutral_trial_stub(), 30, 5)
    reader = CryptoCausalReader(path)
    rows = reader.triplets(include_inferred=False)
    assert reader.verify_provenance()
    assert len(rows) == 3

    by_id = {row["edge_id"]: row for row in rows}
    graph_id = "shake128-r1-structural6-quadratic-interaction-graph"
    plan_id = "shake128-r1-structural6-max-cover-subspace-plan"
    observation_id = "shake128-r1-structural6-subspace-observations"
    assert set(by_id) == {graph_id, plan_id, observation_id}
    assert by_id[plan_id]["provenance"] == [graph_id]
    assert by_id[observation_id]["provenance"] == [plan_id]
    assert by_id[graph_id]["outcome"] == by_id[plan_id]["trigger"]
    assert by_id[plan_id]["outcome"] == by_id[observation_id]["trigger"]
    hashes = (
        selection["interaction_edges_sha256"],
        selection["selection_sha256"],
        selection["subspace_plan_sha256"],
    )
    assert tuple(
        by_id[plan_id]["attrs"][key]
        for key in (
            "interaction_edges_sha256",
            "selection_sha256",
            "subspace_plan_sha256",
        )
    ) == hashes
    assert tuple(
        by_id[observation_id]["attrs"][key]
        for key in (
            "interaction_edges_sha256",
            "selection_sha256",
            "subspace_plan_sha256",
        )
    ) == hashes

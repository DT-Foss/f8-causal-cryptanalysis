from __future__ import annotations

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
    / "shake_symbolic_r1_structural_partition_reader.py"
)
_SPEC = importlib.util.spec_from_file_location(
    "shake_symbolic_r1_structural_partition_reader", _SCRIPT
)
assert _SPEC is not None and _SPEC.loader is not None
_STRUCTURAL = importlib.util.module_from_spec(_SPEC)
sys.modules[_SPEC.name] = _STRUCTURAL
_SPEC.loader.exec_module(_STRUCTURAL)

_RESULTS = _ROOT / "research" / "results" / "v1"
A138_PATH = _RESULTS / "shake_symbolic_r1_scaling_reader_v1.json"
A139_PATH = _RESULTS / "shake_symbolic_r1_partition_scaling_reader_v1.json"
A140_PATH = _RESULTS / "shake_symbolic_r1_upper_partition_reader_v1.json"


def _z3() -> Path:
    path = Path(shutil.which("z3") or "/opt/homebrew/bin/z3")
    if not path.is_file():
        pytest.skip("Z3 CLI is not installed")
    return path


def _canonical_problem() -> tuple[object, dict[str, object]]:
    variant = _STRUCTURAL._BASE.VARIANTS["shake128"]
    problem = _STRUCTURAL._NATIVE._problem(variant, 20, 89755037)
    return variant, problem


def _canonical_selection() -> dict[str, object]:
    variant, problem = _canonical_problem()
    return _STRUCTURAL._derive_structural_selection(
        problem["base_state"], variant, problem["positions"], 4
    )


def test_a138_hash_status_and_unpartitioned_smt_gate() -> None:
    trial = _STRUCTURAL._load_a138_gate(A138_PATH)
    assert trial["window_bits"] == 20
    assert trial["seed"] == 89755037
    assert trial["first_solver"]["status"] == "unknown"
    assert trial["reconstructed_assignment"] is None
    assert (
        trial["encoding"]["first_smt_sha256"]
        == "66aa82020b4dd2b4d21f3065c99ca6f7c9224ab1ab9765f686121f2fe7f8618f"
    )


def test_a139_hash_status_gate_has_16_unknown_subspaces_and_no_models() -> None:
    trial = _STRUCTURAL._load_a139_gate(A139_PATH)
    assert trial["partitioned_coordinates"] == [0, 1, 2, 3]
    assert trial["status_counts"] == {
        "sat": 0,
        "unsat": 0,
        "unknown": 16,
        "error": 0,
    }
    assert len(trial["subspaces_detail"]) == 16
    assert trial["found_assignments"] == []
    assert trial["verified_assignments"] == []
    assert all(row["assignment"] is None for row in trial["subspaces_detail"])


def test_a140_hash_status_gate_has_16_unknown_subspaces_and_no_models() -> None:
    trial = _STRUCTURAL._load_a140_gate(A140_PATH)
    assert trial["partitioned_coordinates"] == [16, 17, 18, 19]
    assert trial["status_counts"] == {
        "sat": 0,
        "unsat": 0,
        "unknown": 16,
        "error": 0,
    }
    assert len(trial["subspaces_detail"]) == 16
    assert trial["found_assignments"] == []
    assert trial["verified_assignments"] == []
    assert all(row["assignment"] is None for row in trial["subspaces_detail"])


@pytest.mark.parametrize(
    ("source", "loader"),
    [
        (A138_PATH, _STRUCTURAL._load_a138_gate),
        (A139_PATH, _STRUCTURAL._load_a139_gate),
        (A140_PATH, _STRUCTURAL._load_a140_gate),
    ],
)
def test_all_three_artifact_hash_gates_reject_modified_bytes(
    tmp_path: Path, source: Path, loader: object
) -> None:
    changed = tmp_path / source.name
    changed.write_bytes(source.read_bytes() + b"\n")
    with pytest.raises(RuntimeError, match="hash differs"):
        loader(changed)


def test_canonical_r1_quadratic_edges_and_max_cover_selection() -> None:
    variant, problem = _canonical_problem()
    template = _STRUCTURAL._WINDOW._clear_window(
        problem["base_state"], variant, problem["positions"]
    )
    polynomials = _STRUCTURAL._R1._SPLIT._symbolic_prefix_polynomials(
        template, variant, problem["positions"], prefix_rounds=1
    )
    masks, edges = _STRUCTURAL._degree_two_monomial_edges(polynomials, 20)
    selection = _STRUCTURAL._structural_selection_from_polynomials(polynomials, 20, 4)

    assert len(masks) == 28
    assert len(edges) == 28
    assert all(left < right for left, right in edges)
    assert selection["maximum_covered_edge_count"] == 14
    assert selection["selected_coordinates"] == [4, 9, 17, 18]
    assert selection["tie_count"] == 14
    assert selection["maximizing_coordinate_sets"][0] == [4, 9, 17, 18]
    assert (
        selection["interaction_edges_sha256"]
        == "06b168eb69c5a6687e0f7f001bfdf178ce24e28b2b312a84758bfe872d1b9bda"
    )
    assert (
        selection["selection_sha256"]
        == "ce5f2463840a3de57a5886b3064fc74ef207d46bc30385b0a340dadb2f5d36c8"
    )
    assert (
        selection["r1_polynomial_state_sha256"]
        == "b06bab2ca328e7f8521d339e0a86a62a7dfbddc38048388a0dd9285fbe936f1d"
    )

    plan = _STRUCTURAL._UPPER._subspace_plan(20, selection["selected_coordinates"])
    assert [row["fixed_value"] for row in plan] == list(range(16))
    assert len({tuple(cell["value"] for cell in row["fixed_coordinates"]) for row in plan}) == 16
    assert sum(row["logical_assignments"] for row in plan) == 1 << 20
    assert selection["subspace_plan_sha256"] == _STRUCTURAL._canonical_sha256(plan)


def test_max_cover_tie_break_is_lexicographically_first() -> None:
    selection = _STRUCTURAL._max_cover_selection([(0, 1), (2, 3)], 4, 1)
    assert selection["maximum_covered_edge_count"] == 1
    assert selection["tie_count"] == 4
    assert selection["maximizing_coordinate_sets"] == [[0], [1], [2], [3]]
    assert selection["selected_coordinates"] == [0]


def test_selection_clears_actual_window_and_cannot_read_posthoc_or_end_state(
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
        raise AssertionError("posthoc extraction must not be called during selection")

    monkeypatch.setattr(_STRUCTURAL._WINDOW, "_extract_window", forbidden_posthoc)
    first = _STRUCTURAL._derive_structural_selection(
        original, variant, problem["positions"], 4
    )
    second = _STRUCTURAL._derive_structural_selection(
        changed, variant, problem["positions"], 4
    )
    assert first == second
    assert first["selected_coordinates"] == [4, 9, 17, 18]
    assert first["actual_assignment_used"] is False
    assert first["posthoc_assignment_used"] is False
    assert first["target_end_state_bits_used"] is False


def test_a140_arbitrary_renderer_fixes_only_formula_selected_coordinates() -> None:
    selection = _canonical_selection()
    coordinates = selection["selected_coordinates"]
    assert coordinates == [4, 9, 17, 18]
    writer = _STRUCTURAL._SMT.BooleanSMT(seed=17)
    inputs = [writer.declare("x") for _ in range(20)]
    raw = _STRUCTURAL._UPPER._render_fixed_coordinates(
        writer, inputs, coordinates, 0b1010
    )
    assertions = [line for line in raw.decode().splitlines() if line.startswith("(assert ")]
    assert assertions == [
        f"(assert (not {inputs[4]}))",
        f"(assert {inputs[9]})",
        f"(assert (not {inputs[17]}))",
        f"(assert {inputs[18]})",
    ]
    assert len(assertions) == 4


def test_small_formula_selected_partition_solver_smoke(tmp_path: Path) -> None:
    variant = _STRUCTURAL._BASE.VARIANTS["shake128"]
    trial = _STRUCTURAL._structural_partition_trial(
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
    assert verification["complete_rate_match"]


def test_reader_provenance_chain_is_exactly_three_triplets(tmp_path: Path) -> None:
    selection = _canonical_selection()
    retained_neutral_trial = _STRUCTURAL._load_a140_gate(A140_PATH)
    path = tmp_path / "shake-symbolic-r1-structural-partition.causal"
    _STRUCTURAL._build_graph(path, selection, retained_neutral_trial, 60, 5)
    reader = CryptoCausalReader(path)
    rows = reader.triplets(include_inferred=False)
    assert reader.verify_provenance()
    assert len(rows) == 3

    by_id = {row["edge_id"]: row for row in rows}
    graph_id = "shake128-r1-quadratic-interaction-graph"
    plan_id = "shake128-r1-deterministic-max-cover-subspace-plan"
    observation_id = "shake128-r1-structural-subspace-observations"
    assert set(by_id) == {graph_id, plan_id, observation_id}
    assert by_id[plan_id]["provenance"] == [graph_id]
    assert by_id[observation_id]["provenance"] == [plan_id]
    assert by_id[graph_id]["outcome"] == by_id[plan_id]["trigger"]
    assert by_id[plan_id]["outcome"] == by_id[observation_id]["trigger"]
    assert (
        by_id[graph_id]["attrs"]["interaction_edges_sha256"]
        == selection["interaction_edges_sha256"]
    )
    graph_selection = by_id[plan_id]["attrs"]["selection"]
    assert graph_selection["selection_rule"] == selection["selection_rule"]
    assert graph_selection["selection_sha256"] == selection["selection_sha256"]
    assert by_id[observation_id]["attrs"]["status_counts"] == {
        "sat": 0,
        "unsat": 0,
        "unknown": 16,
        "error": 0,
    }

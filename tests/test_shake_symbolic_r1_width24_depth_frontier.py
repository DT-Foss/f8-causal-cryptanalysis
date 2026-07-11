from __future__ import annotations

import importlib.util
import inspect
import shutil
import sys
from pathlib import Path

import pytest

from arx_carry_leak.crypto_causal import CryptoCausalReader

_ROOT = Path(__file__).parents[1]
_SCRIPT = _ROOT / "research" / "experiments" / "shake_symbolic_r1_width24_depth_frontier.py"
_SPEC = importlib.util.spec_from_file_location("shake_symbolic_r1_width24_depth_frontier", _SCRIPT)
assert _SPEC is not None and _SPEC.loader is not None
_W24 = importlib.util.module_from_spec(_SPEC)
sys.modules[_SPEC.name] = _W24
_SPEC.loader.exec_module(_W24)


def _z3() -> Path:
    path = Path(shutil.which("z3") or "/opt/homebrew/bin/z3")
    if not path.is_file():
        pytest.skip("Z3 CLI is not installed")
    return path


def _canonical_structure() -> tuple[dict, list[dict]]:
    variant = _W24._BASE.VARIANTS["shake128"]
    problem = _W24._NATIVE._problem(variant, 24, 89756046)
    return _W24._derive_graph_and_depths(
        problem["base_state"], variant, problem["positions"], _W24.DEPTHS
    )


def test_a138_width24_gate_is_hash_exact() -> None:
    row = _W24._load_a138_width24_gate(
        _ROOT / "research/results/v1/shake_symbolic_r1_scaling_reader_v1.json"
    )
    assert row["seed"] == 89756046
    assert row["first_solver"]["status"] == "unknown"
    assert row["encoding"]["first_smt_sha256"] == _W24.UNPARTITIONED_SMT_SHA256


def test_exact_max_cover_counts_and_lexicographic_tie_break() -> None:
    edges = [(0, 3), (1, 4), (2, 5)]
    row = _W24._max_cover_summary(edges, 6, 2)
    assert row["maximum_covered_edge_count"] == 2
    assert row["tie_count"] == 12
    assert row["selected_coordinates"] == [0, 1]


def test_width24_graph_and_depth_frontier_are_canonical() -> None:
    graph, selections = _canonical_structure()
    _W24._canonical_structure_gate(graph, selections)
    assert graph["interaction_edges"] == _W24.CANONICAL_EDGES
    assert graph["isolated_coordinates"] == [9, 10, 11, 12, 13, 14]
    assert [row["selected_coordinates"] for row in selections] == [
        _W24.EXPECTED_SELECTIONS[depth] for depth in _W24.DEPTHS
    ]
    assert [row["tie_count"] for row in selections] == [
        _W24.EXPECTED_TIES[depth] for depth in _W24.DEPTHS
    ]


def test_graph_selection_api_cannot_accept_an_assignment() -> None:
    parameters = inspect.signature(_W24._derive_graph_and_depths).parameters
    assert "assignment" not in parameters
    assert "target" not in parameters


def test_posthoc_projection_occurs_after_frozen_selections() -> None:
    _, selections = _canonical_structure()
    conditioned = _W24._condition_selections(selections, 4845375)
    assert [row["projection_value"] for row in conditioned] == [63, 319, 831, 1855, 3903]
    assert all(row["selection_completed_before_assignment_projection"] for row in conditioned)
    assert all(row["posthoc_assignment_used_for_branch_value"] for row in conditioned)


def test_regenerated_unpartitioned_smt_matches_a138() -> None:
    variant = _W24._BASE.VARIANTS["shake128"]
    problem = _W24._NATIVE._problem(variant, 24, 89756046)
    writer, inputs, _ = _W24._R1._SPLIT._encode_problem(problem, variant, 89756046, prefix_rounds=1)
    raw = writer.render(inputs, include_model=True)
    assert _W24.hashlib.sha256(raw).hexdigest() == _W24.UNPARTITIONED_SMT_SHA256


def test_independent_check_accepts_actual_and_rejects_neighbor() -> None:
    variant = _W24._BASE.VARIANTS["shake128"]
    problem = _W24._NATIVE._problem(variant, 24, 89756046)
    actual = _W24._WINDOW._extract_window(problem["base_state"], variant, problem["positions"])
    assert _W24._independent_check(problem, variant, actual)["complete_rate_match"]
    assert not _W24._independent_check(problem, variant, actual ^ 1)["complete_rate_match"]


def test_width24_causal_recipe_roundtrip(tmp_path: Path) -> None:
    structure, selections = _canonical_structure()
    conditioned = _W24._condition_selections(selections, 4845375)
    measurements = []
    for row in conditioned:
        measurements.append(
            {
                **row,
                "solver": {"status": "unknown", "stats": {}},
                "assignment": None,
                "correctly_confirmed_model": False,
            }
        )
    frontier = _W24._frontier(measurements)
    path = tmp_path / "width24-depth.causal"
    _, rows, gate = _W24._build_graph(path, structure, conditioned, measurements, frontier)
    reader = CryptoCausalReader(path)
    assert gate["passed"]
    assert reader.verify_provenance()
    assert len(rows) == 3


def test_width24_single_conditioned_smoke(tmp_path: Path) -> None:
    variant = _W24._BASE.VARIANTS["shake128"]
    problem = _W24._NATIVE._problem(variant, 4, 89751001)
    writer, inputs, _ = _W24._R1._SPLIT._encode_problem(problem, variant, 89751001, prefix_rounds=1)
    actual = _W24._WINDOW._extract_window(problem["base_state"], variant, problem["positions"])
    raw = _W24._render_fixed_coordinates(writer, inputs, [0, 1], actual & 0b11, include_model=True)
    path = tmp_path / "small.smt2"
    path.write_bytes(raw)
    result = _W24._SMT._run_z3(_z3(), path, 30, inputs)
    assert result["status"] == "sat"
    assert result["assignment"] == actual

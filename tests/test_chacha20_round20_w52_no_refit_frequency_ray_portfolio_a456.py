from __future__ import annotations

import importlib.util
import itertools
import json
import subprocess
import sys
from pathlib import Path

import numpy as np
import pytest

ROOT = Path(__file__).parents[1]
RUNNER = (
    ROOT
    / "research/experiments/chacha20_round20_w52_no_refit_frequency_ray_portfolio_a456.py"
)


def load_runner():
    spec = importlib.util.spec_from_file_location("a456_test_runner", RUNNER)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="module")
def a456():
    return load_runner()


def test_structured_family_and_orbit_counts_are_exact(a456) -> None:
    assert a456.M_VALUES == (3, 4, 5, 6)
    assert len(a456.PATTERNS) == 878
    assert len(set(a456.PATTERNS)) == 878
    assert len(a456.ORBITS) == 86
    for m, expected in a456.EXPECTED_BY_M.items():
        rows = a456.PATTERNS_BY_M[m]
        assert len(rows) == expected
        assert all(
            row.count("H") == m
            and row.count("B") == 1
            and row.count("O") == m
            for row in rows
        )
    exhaustive_m3 = {
        "".join(row)
        for row in set(itertools.permutations("HHHBOOO"))
    }
    assert set(a456.PATTERNS_BY_M[3]) == exhaustive_m3


def test_every_orbit_is_complete_and_has_one_b(a456) -> None:
    for canonical, rows in a456.ORBITS.items():
        period = len(canonical)
        assert canonical == min(a456.rotations(canonical))
        assert len(rows) == period
        assert set(rows) == a456.rotations(canonical)
        assert canonical.count("B") == 1


def test_frozen_design_and_A454_source_are_exact(a456) -> None:
    design = a456.load_design()
    a454, _a448, a449, _a451, _a453 = a456.load_sources()
    assert design["attempt_id"] == "A456"
    assert a454["calibration"]["selected_pattern"] == "BOOHH"
    assert (
        a454["result_commitment_sha256"]
        == a456.A454_RESULT_COMMITMENT_SHA256
    )
    assert a454["W52_target_labels_used"] == 0
    assert a454["W52_candidate_assignments_executed"] == 0
    assert set(a456.COMPONENTS.values()) <= set(a449["operator_schedules"])
    boundary = design["information_boundary"]
    assert boundary["A456_candidate_results_seen_before_design"] is False
    assert boundary["A456_selected_pattern_seen_before_design"] is False
    assert boundary["A456_W52_pair_stream_seen_before_design"] is False


def test_weighted_rank_reference_is_a_complete_small_permutation(a456) -> None:
    component_ranks = {
        "H": np.asarray([1, 2, 3, 4, 5, 6], dtype=np.int64),
        "B": np.asarray([3, 1, 6, 2, 5, 4], dtype=np.int64),
        "O": np.asarray([6, 5, 4, 3, 2, 1], dtype=np.int64),
    }
    pattern = "BOOOHHH"
    ranks, first_keys, bounds = a456.A454.weighted_first_encounter_ranks(
        component_ranks, pattern
    )
    assert sorted(ranks.tolist()) == list(range(1, 7))
    assert len(set(first_keys.tolist())) == 6
    assert all(row["violations"] == 0 for row in bounds.values())


def test_native_compiler_exhaustive_small_self_test(a456) -> None:
    completed = subprocess.run(
        [str(a456.NATIVE_EXECUTABLE), "--self-test"],
        check=True,
        capture_output=True,
        text=True,
    )
    assert "self-test passed" in completed.stdout


def test_implementation_is_bound_when_present(a456) -> None:
    if not a456.IMPLEMENTATION.exists():
        pytest.skip("A456 implementation has not been frozen yet")
    value = a456.load_implementation(a456.file_sha256(a456.IMPLEMENTATION))
    assert value["candidate_count"] == 878
    assert value["orbit_count"] == 86
    assert value["W52_target_labels_used"] == 0
    assert value["candidate_assignments_executed"] == 0


def test_result_and_authentic_causal_reopen_when_present(a456) -> None:
    if not a456.RESULT.exists():
        pytest.skip("A456 result has not been produced yet")
    value = json.loads(a456.RESULT.read_bytes())
    assert value["materialization_ready"] is True
    assert value["calibration"]["candidate_count"] == 878
    assert value["calibration"]["cyclic_orbit_count"] == 86
    assert value["hard_rank_guarantee"]["all_bounds_satisfied"] is True
    assert value["W52_target_labels_used"] == 0
    assert value["W52_candidate_assignments_executed"] == 0
    if str(a456.DOTCAUSAL_SRC) not in sys.path:
        sys.path.insert(0, str(a456.DOTCAUSAL_SRC))
    from dotcausal.io import CausalReader

    reader = CausalReader(str(a456.CAUSAL), verify_integrity=True)
    assert reader.api_id == "a456ray"
    assert len(reader.get_all_triplets(include_inferred=False)) == 4
    assert len(reader.get_all_triplets(include_inferred=True)) == 6
    assert len(reader._rules) == 3
    assert len(reader._clusters) == 1
    assert len(reader._gaps) == 1

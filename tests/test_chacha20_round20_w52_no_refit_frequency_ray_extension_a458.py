from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
from pathlib import Path

import numpy as np
import pytest

ROOT = Path(__file__).parents[1]
RUNNER = (
    ROOT
    / "research/experiments/chacha20_round20_w52_no_refit_frequency_ray_extension_a458.py"
)


def load_runner():
    spec = importlib.util.spec_from_file_location("a458_test_runner", RUNNER)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="module")
def a458():
    return load_runner()


def test_structured_family_and_orbit_counts_are_exact(a458) -> None:
    assert a458.M_VALUES == tuple(range(7, 16))
    assert len(a458.PATTERNS) == 405
    assert len(set(a458.PATTERNS)) == 405
    assert len(a458.ORBITS) == 18
    for arm in a458.ARMS:
        expected_total = 207 if arm == "B1" else 198
        assert sum(
            len(a458.PATTERNS_BY_ARM_M[arm][m]) for m in a458.M_VALUES
        ) == expected_total
        for m in a458.M_VALUES:
            rows = a458.PATTERNS_BY_ARM_M[arm][m]
            assert len(rows) == 2 * m + (arm == "B1")
            assert set(rows) == a458.rotations(a458.canonical_pattern(arm, m))
            assert all(
                row.count("H") == m
                and row.count("B") == (arm == "B1")
                and row.count("O") == m
                for row in rows
            )


def test_every_orbit_is_complete_and_has_declared_active_set(a458) -> None:
    for canonical, rows in a458.ORBITS.items():
        period = len(canonical)
        assert canonical == min(a458.rotations(canonical))
        assert len(rows) == period
        assert set(rows) == a458.rotations(canonical)
        assert canonical.count("B") in (0, 1)
        assert a458.active_symbols(canonical) in (("H", "B", "O"), ("H", "O"))


def test_frozen_design_and_A456_source_are_exact(a458) -> None:
    design = a458.load_design()
    a456, _a454, _a448, a449, _a451, _a453 = a458.load_sources()
    assert design["attempt_id"] == "A458"
    assert a456["calibration"]["selected_pattern"] == "BOOOOOOHHHHHH"
    assert (
        a456["result_commitment_sha256"]
        == a458.A456_RESULT_COMMITMENT_SHA256
    )
    assert a456["W52_target_labels_used"] == 0
    assert a456["W52_candidate_assignments_executed"] == 0
    assert set(a458.COMPONENTS.values()) <= set(a449["operator_schedules"])
    boundary = design["information_boundary"]
    assert boundary["A458_candidate_results_seen_before_design"] is False
    assert boundary["A458_selected_pattern_seen_before_design"] is False
    assert boundary["A458_W52_pair_stream_seen_before_design"] is False


def test_weighted_rank_reference_is_a_complete_small_permutation(a458) -> None:
    component_ranks = {
        "H": np.asarray([1, 2, 3, 4, 5, 6], dtype=np.int64),
        "B": np.asarray([3, 1, 6, 2, 5, 4], dtype=np.int64),
        "O": np.asarray([6, 5, 4, 3, 2, 1], dtype=np.int64),
    }
    for pattern, expected_symbols in (
        ("BOOOHHH", {"H", "B", "O"}),
        ("OOOHHH", {"H", "O"}),
    ):
        ranks, first_keys, bounds = a458.weighted_first_encounter_ranks(
            component_ranks, pattern
        )
        assert sorted(ranks.tolist()) == list(range(1, 7))
        assert len(set(first_keys.tolist())) == 6
        assert set(bounds) == expected_symbols
        assert all(row["violations"] == 0 for row in bounds.values())
    changed_b = dict(component_ranks)
    changed_b["B"] = component_ranks["B"][::-1]
    first, _keys, _bounds = a458.weighted_first_encounter_ranks(
        component_ranks, "OOOHHH"
    )
    second, _keys, _bounds = a458.weighted_first_encounter_ranks(
        changed_b, "OOOHHH"
    )
    np.testing.assert_array_equal(first, second)


def test_native_compiler_exhaustive_small_self_test(a458) -> None:
    completed = subprocess.run(
        [str(a458.NATIVE_EXECUTABLE), "--self-test"],
        check=True,
        capture_output=True,
        text=True,
    )
    assert "self-test passed" in completed.stdout


def test_implementation_is_bound_when_present(a458) -> None:
    if not a458.IMPLEMENTATION.exists():
        pytest.skip("A458 implementation has not been frozen yet")
    value = a458.load_implementation(a458.file_sha256(a458.IMPLEMENTATION))
    assert value["candidate_count"] == 405
    assert value["orbit_count"] == 18
    assert value["W52_target_labels_used"] == 0
    assert value["candidate_assignments_executed"] == 0


def test_result_and_authentic_causal_reopen_when_present(a458) -> None:
    if not a458.RESULT.exists():
        pytest.skip("A458 result has not been produced yet")
    value = json.loads(a458.RESULT.read_bytes())
    assert value["materialization_ready"] is True
    assert value["calibration"]["candidate_count"] == 405
    assert value["calibration"]["cyclic_orbit_count"] == 18
    assert value["hard_rank_guarantee"]["all_bounds_satisfied"] is True
    assert value["W52_target_labels_used"] == 0
    assert value["W52_candidate_assignments_executed"] == 0
    if str(a458.DOTCAUSAL_SRC) not in sys.path:
        sys.path.insert(0, str(a458.DOTCAUSAL_SRC))
    from dotcausal.io import CausalReader

    reader = CausalReader(str(a458.CAUSAL), verify_integrity=True)
    assert reader.api_id == "a458ray"
    assert len(reader.get_all_triplets(include_inferred=False)) == 4
    assert len(reader.get_all_triplets(include_inferred=True)) == 6
    assert len(reader._rules) == 3
    assert len(reader._clusters) == 1
    assert len(reader._gaps) == 1

from __future__ import annotations

import importlib.util
import shutil
import sys
from pathlib import Path

import pytest

from arx_carry_leak.crypto_causal import CryptoCausalReader

_ROOT = Path(__file__).parents[1]
_SCRIPT = _ROOT / "research" / "experiments" / "shake_symbolic_r1_upper_partition_reader.py"
_SPEC = importlib.util.spec_from_file_location("shake_symbolic_r1_upper_partition_reader", _SCRIPT)
assert _SPEC is not None and _SPEC.loader is not None
_UPPER = importlib.util.module_from_spec(_SPEC)
sys.modules[_SPEC.name] = _UPPER
_SPEC.loader.exec_module(_UPPER)


def _z3() -> Path:
    path = Path(shutil.which("z3") or "/opt/homebrew/bin/z3")
    if not path.is_file():
        pytest.skip("Z3 CLI is not installed")
    return path


def test_a139_is_hash_gated_and_contains_exactly_16_unknown_low_subspaces(
    tmp_path: Path,
) -> None:
    path = _ROOT / "research/results/v1/shake_symbolic_r1_partition_scaling_reader_v1.json"
    payload = _UPPER._load_a139(path)
    trial = _UPPER._a139_unknown_low_trial(payload)
    assert trial["window_bits"] == 20
    assert trial["seed"] == 89755037
    assert trial["partitioned_coordinates"] == [0, 1, 2, 3]
    assert trial["status_counts"] == {
        "sat": 0,
        "unsat": 0,
        "unknown": 16,
        "error": 0,
    }
    assert len(trial["subspaces_detail"]) == 16
    assert all(row["solver"]["status"] == "unknown" for row in trial["subspaces_detail"])

    changed = tmp_path / "changed-a139.json"
    changed.write_bytes(path.read_bytes() + b"\n")
    with pytest.raises(RuntimeError, match="A139 retained artifact hash differs"):
        _UPPER._load_a139(changed)


def test_upper_four_subspace_plan_is_complete_disjoint_and_ascending() -> None:
    coordinates = [16, 17, 18, 19]
    plan = _UPPER._subspace_plan(20, coordinates)
    assert [row["subspace_index"] for row in plan] == list(range(16))
    assert [row["fixed_value"] for row in plan] == list(range(16))
    patterns = {tuple(cell["value"] for cell in row["fixed_coordinates"]) for row in plan}
    assert len(patterns) == 16
    assert all(
        [cell["coordinate"] for cell in row["fixed_coordinates"]] == coordinates for row in plan
    )
    assert all(row["free_coordinates"] == list(range(16)) for row in plan)
    assert sum(row["logical_assignments"] for row in plan) == 1 << 20


def test_general_renderer_fixes_only_selected_coordinates() -> None:
    writer = _UPPER._SMT.BooleanSMT(seed=17)
    inputs = [writer.declare("x") for _ in range(5)]
    raw = _UPPER._render_fixed_coordinates(writer, inputs, [1, 4], 1)
    assertion_lines = [line for line in raw.decode().splitlines() if line.startswith("(assert ")]
    assert assertion_lines == [f"(assert {inputs[1]})", f"(assert (not {inputs[4]}))"]
    assert all(inputs[index] not in "\n".join(assertion_lines) for index in (0, 2, 3))
    assert f"(get-value ({' '.join(inputs)}))" in raw.decode()


def test_two_subspace_r1_reader_checks_non_low_coordinate_in_small_window(
    tmp_path: Path,
) -> None:
    variant = _UPPER._BASE.VARIANTS["shake128"]
    row = _UPPER._partition_trial(
        variant,
        4,
        89751001,
        [2],
        30,
        2,
        _z3(),
        tmp_path,
        False,
    )
    assert row["partitioned_coordinates"] == [2]
    assert row["subspace_count"] == 2
    assert [item["fixed_value"] for item in row["subspaces_detail"]] == [0, 1]
    assert row["stored_assignment_used_for_plan_or_generation"] is False
    assert row["posthoc_assignment_used_for_plan_or_generation"] is False
    assert row["status_counts"] == {
        "sat": 1,
        "unsat": 1,
        "unknown": 0,
        "error": 0,
    }
    assert row["encoding"]["symbolic_prefix_rounds"] == 1
    assert row["all_found_assignments_independently_verified"]
    assert row["reconstruction_matches_instrumented_assignment"]
    assert row["actual_fixed_value_posthoc"] == (row["actual_assignment_posthoc"] >> 2) & 1
    assert all(
        item["independent_verification"]["complete_rate_match"]
        for item in row["subspaces_detail"]
        if item["assignment"] is not None
    )


def test_upper_partition_reader_recipe_has_three_provenance_linked_triplets(
    tmp_path: Path,
) -> None:
    path = tmp_path / "shake-symbolic-r1-upper-partition.causal"
    _UPPER._build_graph(path, 20, [16, 17, 18, 19], 60, 5)
    reader = CryptoCausalReader(path)
    rows = reader.triplets(include_inferred=False)
    assert reader.verify_provenance()
    assert len(rows) == 3

    by_id = {row["edge_id"]: row for row in rows}
    plan_id = "boolean-transform-orthogonal-coordinate-subspace-plan"
    solve_id = "boolean-transform-upper-partition-observations"
    check_id = "boolean-transform-independent-candidate-checks"
    assert by_id[solve_id]["provenance"] == [plan_id]
    assert by_id[check_id]["provenance"] == [solve_id]
    recipe = by_id[plan_id]["attrs"]["reader_recipe"]
    assert recipe["fixed_coordinates"] == [16, 17, 18, 19]
    assert recipe["subspace_values"] == list(range(16))
    assert recipe["stored_assignment_input"] is None
    assert recipe["posthoc_assignment_input"] is None
    assert all(row["trigger"].startswith("boolean_transform:") for row in rows)

from __future__ import annotations

import importlib.util
import shutil
import sys
from pathlib import Path

import pytest

from arx_carry_leak.crypto_causal import CryptoCausalReader

_ROOT = Path(__file__).parents[1]
_SCRIPT = (
    _ROOT
    / "research"
    / "experiments"
    / "shake_symbolic_r1_partition_scaling_reader.py"
)
_SPEC = importlib.util.spec_from_file_location(
    "shake_symbolic_r1_partition_scaling_reader", _SCRIPT
)
assert _SPEC is not None and _SPEC.loader is not None
_PARTITION = importlib.util.module_from_spec(_SPEC)
sys.modules[_SPEC.name] = _PARTITION
_SPEC.loader.exec_module(_PARTITION)


def _z3() -> Path:
    path = Path(shutil.which("z3") or "/opt/homebrew/bin/z3")
    if not path.is_file():
        pytest.skip("Z3 CLI is not installed")
    return path


def test_a138_is_hash_gated_and_retains_unknown_20_coordinate_case(
    tmp_path: Path,
) -> None:
    path = _ROOT / "research/results/v1/shake_symbolic_r1_scaling_reader_v1.json"
    payload = _PARTITION._load_a138(path)
    row = _PARTITION._a138_unknown_trial(payload)
    assert row["window_bits"] == 20
    assert row["seed"] == 89755037
    assert row["first_solver"]["status"] == "unknown"

    changed = tmp_path / "changed-a138.json"
    changed.write_bytes(path.read_bytes() + b"\n")
    with pytest.raises(RuntimeError, match="A138 retained artifact hash differs"):
        _PARTITION._load_a138(changed)


def test_low_four_subspace_plan_is_complete_disjoint_and_ascending() -> None:
    plan = _PARTITION._subspace_plan(20, 4)
    assert [row["subspace_index"] for row in plan] == list(range(16))
    assert [row["fixed_low_value"] for row in plan] == list(range(16))
    patterns = {
        tuple(cell["value"] for cell in row["fixed_coordinates"])
        for row in plan
    }
    assert len(patterns) == 16
    assert all(
        [cell["coordinate"] for cell in row["fixed_coordinates"]]
        == [0, 1, 2, 3]
        for row in plan
    )
    assert all(row["free_coordinates"] == list(range(4, 20)) for row in plan)
    assert sum(row["logical_assignments"] for row in plan) == 1 << 20


def test_two_subspace_r1_reader_checks_small_window(tmp_path: Path) -> None:
    variant = _PARTITION._BASE.VARIANTS["shake128"]
    row = _PARTITION._partition_trial(
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
    assert row["subspace_count"] == 2
    assert [item["subspace_index"] for item in row["subspaces_detail"]] == [0, 1]
    assert row["stored_assignment_used_for_plan_or_generation"] is False
    assert row["status_counts"] == {
        "sat": 1,
        "unsat": 1,
        "unknown": 0,
        "error": 0,
    }
    assert row["encoding"]["symbolic_prefix_rounds"] == 1
    assert row["all_found_assignments_independently_verified"]
    assert row["reconstruction_matches_instrumented_assignment"]
    assert all(
        item["independent_verification"]["complete_rate_match"]
        for item in row["subspaces_detail"]
        if item["assignment"] is not None
    )


def test_partition_scaling_reader_recipe_roundtrip(tmp_path: Path) -> None:
    path = tmp_path / "shake-symbolic-r1-partition-scaling.causal"
    _PARTITION._build_graph(path, 20, 4, 60, 5)
    reader = CryptoCausalReader(path)
    rows = reader.triplets(include_inferred=False)
    assert reader.verify_provenance()
    assert len(rows) == 3

    by_id = {row["edge_id"]: row for row in rows}
    plan_id = "boolean-transform-complete-low-coordinate-subspace-plan"
    solve_id = "boolean-transform-bounded-subspace-observations"
    assert by_id[solve_id]["provenance"] == [plan_id]
    assert by_id["boolean-transform-independent-candidate-checks"][
        "provenance"
    ] == [solve_id]
    recipe = by_id[plan_id]["attrs"]["reader_recipe"]
    assert recipe["formulation_module"] == "shake_symbolic_r1_scaling_reader.py"
    assert recipe["partition_module"] == "shake_symbolic_r2_partition_reader.py"
    assert recipe["subspace_values"] == list(range(16))
    assert recipe["stored_assignment_input"] is None
    assert all(row["trigger"].startswith("boolean_transform:") for row in rows)

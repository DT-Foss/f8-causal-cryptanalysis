from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).parents[1]
SOURCE = ROOT / "research/experiments/chacha20_fresh_multihorizon.py"
TOY_CNF = ROOT / "tests/fixtures/cadical_global_incremental_assumptions_toy.cnf"


def _module():
    spec = importlib.util.spec_from_file_location("fresh_multihorizon_test", SOURCE)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _mapping() -> list[int]:
    return list(range(1, 21))


def _raw_command(fresh, *, cnf: Path, mode: str, order: list[str]) -> list[str]:
    return [
        str(fresh.TEST_BINARY),
        "--cnf",
        str(cnf),
        "--mode",
        mode,
        *fresh._mapping_arguments(_mapping()),
        "--cell-order",
        ",".join(order),
        "--conflict-horizons",
        "1,2",
        "--watchdog-seconds",
        "1.0",
    ]


@pytest.fixture(scope="module")
def fresh():
    module = _module()
    build = module.compile_helper()
    module.TEST_BINARY = Path(build["binary_path"])
    assert build["returncode"] == 0
    assert build["stdout_sha256"] == module._sha256(b"")
    assert build["stderr_sha256"] == module._sha256(b"")
    return module


def test_fresh_helper_build_is_content_addressed(fresh) -> None:
    build = fresh.compile_helper()
    binary = Path(build["binary_path"])
    assert build["source_sha256_started"] == fresh.file_sha256(fresh.SOURCE)
    assert build["source_sha256_finished"] == build["source_sha256_started"]
    assert build["binary_sha256"] == fresh.file_sha256(binary)
    assert binary.name == (
        f"{fresh.BINARY.name}-{build['source_sha256_started']}-{build['binary_sha256']}"
    )
    assert build["content_addressed_binary"] is True


def test_each_candidate_starts_from_identical_fresh_state(fresh) -> None:
    result = fresh.run_fresh_multihorizon(
        helper=fresh.TEST_BINARY,
        cnf=TOY_CNF,
        mode="fresh_toy",
        order=fresh.numeric_order(),
        key_one_literals_bit0_through_bit19=_mapping(),
        conflict_horizons=[1, 2],
        watchdog_seconds=1.0,
    )
    assert result["fresh_solver_per_candidate_verified"] is True
    assert result["base_snapshot_identical_verified"] is True
    assert result["summary"]["fresh_solver_instances"] == 256
    assert result["summary"]["base_snapshot_identical"] is True
    bases = {
        (
            *cell["metrics_before"],
            cell["active_variables_before"],
            cell["irredundant_clauses_before"],
            cell["redundant_clauses_before"],
        )
        for cell in result["cells"]
    }
    assert len(bases) == 1
    assert result["summary"]["sat_cells"] == 1
    assert result["summary"]["unsat_cells"] == 255
    sat = [stage for stage in result["stages"] if stage["status"] == "sat"]
    assert len(sat) == 1
    assert sat[0]["prefix8"] == "11111111"
    assert sat[0]["model_bits_bit0_through_bit19"][12:] == [1] * 8


def test_candidate_measurements_are_order_invariant(fresh) -> None:
    numeric = fresh.numeric_order()
    reversed_order = list(reversed(numeric))
    common = {
        "helper": fresh.TEST_BINARY,
        "cnf": TOY_CNF,
        "key_one_literals_bit0_through_bit19": _mapping(),
        "conflict_horizons": [1, 2],
        "watchdog_seconds": 1.0,
    }
    forward = fresh.run_fresh_multihorizon(mode="fresh_forward", order=numeric, **common)
    reverse = fresh.run_fresh_multihorizon(mode="fresh_reverse", order=reversed_order, **common)

    def stable_by_prefix(result):
        return {
            row["prefix8"]: {
                key: value
                for key, value in row.items()
                if key
                not in {
                    "mode",
                    "cell_index",
                    "elapsed_seconds",
                }
            }
            for row in result["stages"]
        }

    assert stable_by_prefix(forward) == stable_by_prefix(reverse)


def test_strict_parser_rejects_base_snapshot_damage(fresh) -> None:
    command = _raw_command(
        fresh,
        cnf=TOY_CNF,
        mode="base_damage",
        order=fresh.numeric_order(),
    )
    completed = subprocess.run(command, text=True, capture_output=True, check=False, timeout=10)
    assert completed.returncode == 0
    lines = completed.stdout.splitlines()
    cell_indices = [index for index, line in enumerate(lines) if line.startswith(fresh.CELL_PREFIX)]
    record = json.loads(lines[cell_indices[1]].removeprefix(fresh.CELL_PREFIX))
    record["active_variables_before"] += 1
    record["active_variables_delta"] -= 1
    lines[cell_indices[1]] = fresh.CELL_PREFIX + json.dumps(record, separators=(",", ":"))
    with pytest.raises(RuntimeError, match="base snapshot differs"):
        fresh.parse_fresh_output(
            stdout="\n".join(lines) + "\n",
            returncode=0,
            mode="base_damage",
            order=fresh.numeric_order(),
            key_one_literals_bit0_through_bit19=_mapping(),
            conflict_horizons=[1, 2],
            watchdog_seconds=1.0,
        )


def test_native_parser_rejects_wrong_clause_count(fresh, tmp_path: Path) -> None:
    broken = tmp_path / "broken.cnf"
    broken.write_text("p cnf 20 2\n1 0\n")
    completed = subprocess.run(
        _raw_command(fresh, cnf=broken, mode="broken", order=fresh.numeric_order()),
        text=True,
        capture_output=True,
        check=False,
        timeout=10,
    )
    assert completed.returncode == 2
    assert completed.stdout == ""
    assert completed.stderr == "FRESH_MH_ERROR DIMACS clause count differs from header\n"

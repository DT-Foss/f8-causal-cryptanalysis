from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
from collections import defaultdict
from pathlib import Path

import pytest

ROOT = Path(__file__).parents[1]
SOURCE = ROOT / "research/experiments/chacha20_retained_multihorizon.py"
TOY_CNF = ROOT / "tests/fixtures/cadical_global_incremental_assumptions_toy.cnf"


def _module():
    spec = importlib.util.spec_from_file_location("retained_multihorizon_test", SOURCE)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _signed_mapping() -> list[int]:
    return list(range(-1, -21, -1))


def _pigeonhole(path: Path, *, pigeons: int = 6, holes: int = 5) -> list[int]:
    def variable(pigeon: int, hole: int) -> int:
        return pigeon * holes + hole + 1

    clauses: list[list[int]] = []
    for pigeon in range(pigeons):
        clauses.append([variable(pigeon, hole) for hole in range(holes)])
        for left in range(holes):
            for right in range(left + 1, holes):
                clauses.append([-variable(pigeon, left), -variable(pigeon, right)])
    for hole in range(holes):
        for left in range(pigeons):
            for right in range(left + 1, pigeons):
                clauses.append([-variable(left, hole), -variable(right, hole)])
    # Variables 31..38 are frozen assumption-only variables. Bits 0..11 use
    # variables 1..12 solely so the signed model map remains valid if SAT.
    variables = pigeons * holes + 8
    lines = [f"p cnf {variables} {len(clauses)}"]
    lines.extend(" ".join([*(str(literal) for literal in clause), "0"]) for clause in clauses)
    path.write_text("\n".join(lines) + "\n")
    return [*range(1, 13), *range(31, 39)]


def _raw_command(
    retained,
    *,
    cnf: Path,
    mode: str,
    mapping: list[int],
    order: list[str],
    horizons: str,
    watchdog: str = "1.0",
) -> list[str]:
    return [
        str(retained.TEST_BINARY),
        "--cnf",
        str(cnf),
        "--mode",
        mode,
        *retained._mapping_arguments(mapping),
        "--cell-order",
        ",".join(order),
        "--conflict-horizons",
        horizons,
        "--watchdog-seconds",
        watchdog,
    ]


@pytest.fixture(scope="module")
def retained():
    module = _module()
    build = module.compile_helper()
    module.TEST_BINARY = Path(build["binary_path"])
    assert build["returncode"] == 0
    assert build["stdout_sha256"] == module._sha256(b"")
    assert build["stderr_sha256"] == module._sha256(b"")
    return module


def test_multihorizon_build_is_clean_and_hashes_source_and_binary(retained) -> None:
    build = retained.compile_helper()
    assert build["source_sha256_started"] == retained.file_sha256(retained.SOURCE)
    assert build["source_sha256_finished"] == build["source_sha256_started"]
    assert build["binary_sha256"] == retained.file_sha256(Path(build["binary_path"]))
    assert build["binary_sha256"] == retained.file_sha256(retained.TEST_BINARY)
    assert Path(build["binary_path"]).name == (
        f"{retained.BINARY.name}-{build['source_sha256_started']}-{build['binary_sha256']}"
    )
    assert build["content_addressed_binary"] is True
    assert build["environment"] == retained.EXECUTION_ENVIRONMENT
    assert len(build["compiler_sha256"]) == 64
    assert len(build["cadical_header_sha256"]) == 64
    assert len(build["cadical_library_sha256"]) == 64
    assert len(build["source_sha256_started"]) == 64
    assert len(build["binary_sha256"]) == 64


def test_pigeonhole_uses_incremental_horizons_and_retains_global_state(
    retained, tmp_path: Path
) -> None:
    cnf = tmp_path / "pigeonhole_6_5.cnf"
    mapping = _pigeonhole(cnf)
    horizons = [1, 2, 4, 8]
    result = retained.run_multihorizon(
        helper=retained.TEST_BINARY,
        cnf=cnf,
        mode="pigeonhole_retention",
        order=retained.numeric_order(),
        key_one_literals_bit0_through_bit19=mapping,
        conflict_horizons=horizons,
        watchdog_seconds=2.0,
    )

    assert result["retained_state_continuity_verified"] is True
    assert result["all_watchdogs_clear"] is True
    assert result["helper_returncode"] == 0
    assert result["environment"] == retained.EXECUTION_ENVIRONMENT
    assert result["launch_identity_verified"] is True
    assert result["launch_artifact_hashes_started"] == result["launch_artifact_hashes_finished"]
    assert result["summary"]["cells"] == 256
    assert result["summary"]["conflict_horizons"] == horizons
    assert result["summary"]["stages_emitted"] == len(result["stages"])
    by_cell: dict[int, list[dict]] = defaultdict(list)
    for row in result["stages"]:
        by_cell[row["cell_index"]].append(row)
    assert any(len(rows) > 1 for rows in by_cell.values())
    for rows in by_cell.values():
        assert [row["horizon"] for row in rows] == horizons[: len(rows)]
        assert [row["conflict_increment"] for row in rows] == [1, 1, 2, 4][: len(rows)]
        for index, row in enumerate(rows):
            if index:
                assert row["metrics_stage_before"] == rows[index - 1]["metrics_stage_after"]
            if row["status"] == "unknown":
                assert row["metrics_cell_cumulative_delta"][0] >= row["horizon"]
    assert any(row["metrics_stage_delta"][0] > 0 for row in result["stages"])
    assert all(
        right["metrics_before"] == left["metrics_after"]
        for left, right in zip(result["cells"], result["cells"][1:], strict=False)
    )


def test_arbitrary_order_terminal_stop_and_signed_model_mapping(retained) -> None:
    numeric = retained.numeric_order()
    order = [*numeric[1:38], numeric[0], *numeric[38:]]
    result = retained.run_multihorizon(
        helper=retained.TEST_BINARY,
        cnf=TOY_CNF,
        mode="signed_arbitrary_order",
        order=order,
        key_one_literals_bit0_through_bit19=_signed_mapping(),
        conflict_horizons=[1, 3, 9],
        watchdog_seconds=1.0,
    )

    assert [cell["prefix8"] for cell in result["cells"]] == order
    assert result["summary"]["stages_emitted"] == 256
    assert all(cell["stages_run"] == 1 for cell in result["cells"])
    assert all(cell["terminal_stage_index"] == 0 for cell in result["cells"])
    sat_stages = [row for row in result["stages"] if row["status"] == "sat"]
    assert len(sat_stages) == 1
    assert sat_stages[0]["cell_index"] == 37
    assert sat_stages[0]["prefix8"] == "00000000"
    assert sat_stages[0]["assumptions"] == list(range(20, 12, -1))
    assert sat_stages[0]["model_bits_bit0_through_bit19"][12:] == [0] * 8
    assert all(
        not row["model_bits_bit0_through_bit19"]
        for row in result["stages"]
        if row["status"] != "sat"
    )


def test_nonpalindromic_sat_prefix_proves_model_bit_orientation(retained, tmp_path: Path) -> None:
    prefix = "10110010"
    cnf = tmp_path / "nonpalindromic_prefix.cnf"
    literals = [
        variable if bit == "1" else -variable
        for bit, variable in zip(prefix, range(20, 12, -1), strict=True)
    ]
    cnf.write_text("p cnf 20 8\n" + "".join(f"{literal} 0\n" for literal in literals))
    order = [prefix, *(cell for cell in retained.numeric_order() if cell != prefix)]
    result = retained.run_multihorizon(
        helper=retained.TEST_BINARY,
        cnf=cnf,
        mode="nonpalindromic_prefix",
        order=order,
        key_one_literals_bit0_through_bit19=list(range(1, 21)),
        conflict_horizons=[1, 3],
        watchdog_seconds=1.0,
    )
    sat = [row for row in result["stages"] if row["status"] == "sat"]
    assert len(sat) == 1
    assert sat[0]["prefix8"] == prefix
    assert sat[0]["model_bits_bit0_through_bit19"][12:] == [int(bit) for bit in reversed(prefix)]


@pytest.mark.parametrize(
    ("order", "horizons", "expected"),
    [
        (None, "2,1", "conflict-horizons must be a strictly increasing list"),
        ("duplicate", "1,2", "cell order must cover every eight-bit value exactly once"),
    ],
)
def test_native_helper_rejects_malformed_input(
    retained, order: str | None, horizons: str, expected: str
) -> None:
    values = retained.numeric_order()
    if order == "duplicate":
        values[-1] = values[0]
    command = _raw_command(
        retained,
        cnf=TOY_CNF,
        mode="malformed",
        mapping=_signed_mapping(),
        order=values,
        horizons=horizons,
    )
    result = subprocess.run(command, text=True, capture_output=True, timeout=10, check=False)
    assert result.returncode == 2
    assert result.stdout == ""
    assert result.stderr == f"RETAINED_MH_ERROR {expected}\n"


def test_strict_parser_rejects_schema_damage(retained) -> None:
    command = _raw_command(
        retained,
        cnf=TOY_CNF,
        mode="schema_damage",
        mapping=_signed_mapping(),
        order=retained.numeric_order(),
        horizons="1",
    )
    result = subprocess.run(command, text=True, capture_output=True, timeout=10, check=False)
    assert result.returncode == 0
    lines = result.stdout.splitlines()
    record = json.loads(lines[0].removeprefix(retained.STAGE_PREFIX))
    record.pop("metrics_cell_cumulative_delta")
    lines[0] = retained.STAGE_PREFIX + json.dumps(record, separators=(",", ":"))
    with pytest.raises(RuntimeError, match="stage schema or identity gate"):
        retained.parse_multihorizon_output(
            stdout="\n".join(lines) + "\n",
            returncode=0,
            mode="schema_damage",
            order=retained.numeric_order(),
            key_one_literals_bit0_through_bit19=_signed_mapping(),
            conflict_horizons=[1],
            watchdog_seconds=1.0,
        )


def test_strict_parser_rejects_sat_model_outside_assumed_prefix(retained) -> None:
    command = _raw_command(
        retained,
        cnf=TOY_CNF,
        mode="model_prefix_damage",
        mapping=_signed_mapping(),
        order=retained.numeric_order(),
        horizons="1",
    )
    result = subprocess.run(command, text=True, capture_output=True, timeout=10, check=False)
    assert result.returncode == 0
    lines = result.stdout.splitlines()
    sat_line_index = next(
        index
        for index, line in enumerate(lines)
        if line.startswith(retained.STAGE_PREFIX)
        and json.loads(line.removeprefix(retained.STAGE_PREFIX))["status"] == "sat"
    )
    record = json.loads(lines[sat_line_index].removeprefix(retained.STAGE_PREFIX))
    record["model_bits_bit0_through_bit19"][12] ^= 1
    lines[sat_line_index] = retained.STAGE_PREFIX + json.dumps(record, separators=(",", ":"))
    with pytest.raises(RuntimeError, match="outcome semantics"):
        retained.parse_multihorizon_output(
            stdout="\n".join(lines) + "\n",
            returncode=0,
            mode="model_prefix_damage",
            order=retained.numeric_order(),
            key_one_literals_bit0_through_bit19=_signed_mapping(),
            conflict_horizons=[1],
            watchdog_seconds=1.0,
        )


def test_stage_watchdog_is_separate_strictly_parsed_and_fails_closed(retained) -> None:
    arguments = {
        "helper": retained.TEST_BINARY,
        "cnf": TOY_CNF,
        "mode": "watchdog",
        "order": retained.numeric_order(),
        "key_one_literals_bit0_through_bit19": _signed_mapping(),
        "conflict_horizons": [1_000_000],
        "watchdog_seconds": 0.000000001,
        "external_timeout_seconds": 30.0,
    }
    with pytest.raises(RuntimeError, match="helper emitted stderr.*stage watchdog fired"):
        retained.run_multihorizon(**arguments)


def test_python_input_gate_rejects_nonincreasing_horizons(retained) -> None:
    with pytest.raises(ValueError, match="strictly increasing"):
        retained.run_multihorizon(
            helper=retained.TEST_BINARY,
            cnf=TOY_CNF,
            mode="bad_horizons",
            order=retained.numeric_order(),
            key_one_literals_bit0_through_bit19=_signed_mapping(),
            conflict_horizons=[1, 1, 2],
            watchdog_seconds=1.0,
        )

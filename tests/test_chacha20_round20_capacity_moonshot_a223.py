from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest

ROOT = Path(__file__).parents[1]
MODULE_PATH = ROOT / "research" / "experiments" / "chacha20_round20_capacity_moonshot_a223.py"
SPEC = importlib.util.spec_from_file_location("a223_capacity_moonshot_tested", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)


@pytest.fixture(scope="module")
def analysis() -> dict[str, Any]:
    return MODULE.analyze()


@pytest.fixture(scope="module")
def helper(tmp_path_factory: pytest.TempPathFactory, analysis: dict[str, Any]) -> Path:
    directory = tmp_path_factory.mktemp("a223-helper-build")
    output = directory / "cadical_capacity_moonshot_a223"
    observation = MODULE._compile_helper(
        config=analysis["config"], output=output, directory=directory
    )
    assert observation["returncode"] == 0
    assert MODULE._file_sha256(output) == observation["binary_sha256"]
    return output


def test_protocol_is_frozen_before_preflight_and_has_seven_portfolio_arms(
    analysis: dict[str, Any],
) -> None:
    config = analysis["config"]
    assert config["protocol_state"] == (
        "refrozen_after_outcome_free_b8_export_feasibility_before_any_A223_cell_solver_execution"
    )
    assert analysis["cell_solver_execution_started"] is False
    assert analysis["shared_key_block_count"] == 8
    assert analysis["joint_equality_constraint_count_per_width"] == 128
    assert analysis["phase1_arms"] == [dict(row) for row in MODULE.ARM_PLAN]
    assert [row["arm"] for row in MODULE.ARM_PLAN] == [
        "gray8_w40",
        "gray8_w256",
        "numeric_w40",
        "numeric_w256",
        "gray8_w32",
        "gray8_w64",
        "gray8_w128",
    ]
    assert config["execution_plan"]["maximum_total_active_solver_processes_including_A220"] == 9
    assert config["execution_plan"]["one_physical_core_intentionally_idle"] is True


def test_five_independent_public_challenges_contain_no_secret_assignment(
    analysis: dict[str, Any],
) -> None:
    config = analysis["config"]
    identifiers = set()
    hashes = set()
    for row, width in zip(config["challenges"], MODULE.WIDTHS, strict=True):
        challenge = row["public_challenge"]
        MODULE._validate_challenge(challenge, width=width)
        assert row["width"] == width
        assert row["public_challenge_sha256"] == MODULE._canonical_sha256(challenge)
        assert challenge["unknown_assignment_included"] is False
        assert challenge["unknown_assignment_value_included"] is False
        assert challenge["full_key_included"] is False
        assert challenge["secret_discarded_after_target_construction"] is True
        assert challenge["known_key_mask_words"] == MODULE._expected_known_masks(width)
        identifiers.add(challenge["challenge_id"])
        hashes.add(row["public_challenge_sha256"])
    assert len(identifiers) == len(hashes) == len(MODULE.WIDTHS)


@pytest.mark.parametrize("width", MODULE.WIDTHS)
def test_shared_b8_formula_has_one_key_and_eight_fullround_split18_circuits(
    analysis: dict[str, Any], width: int
) -> None:
    challenge = MODULE._challenge_map(analysis["config"])[width]
    formula = MODULE._source_formula(challenge, width=width)
    assert formula.count("(check-sat)") == 1
    assert formula.count("(get-value (") == 1
    assert formula.count("(assert (= b") == 8 * 16
    assert formula.count("(declare-fun k") == (width + 31) // 32
    for block in range(8):
        assert f"#x{(challenge['counter_start'] + block) & 0xFFFFFFFF:08x}" in formula
        for target in challenge["target_words"][block]:
            assert f"#x{target:08x}" in formula
    if width == 40:
        assert "((_ extract 31 8) k1)" in formula
    else:
        assert "((_ extract 31 " not in formula


def test_w256_shared_b8_formula_accepts_the_true_key_and_rejects_a_flip(
    analysis: dict[str, Any],
) -> None:
    key_words = [
        0x03020100,
        0x07060504,
        0x0B0A0908,
        0x0F0E0D0C,
        0x13121110,
        0x17161514,
        0x1B1A1918,
        0x1F1E1D1C,
    ]
    counter_start = 0x10203040
    nonce_words = [0x33221100, 0x77665544, 0xBBAA9988]
    challenge = {
        "known_key_value_words": [0] * 8,
        "counter_start": counter_start,
        "nonce_words": nonce_words,
        "target_words": [
            MODULE.P1._chacha_block(
                key_words=key_words,
                counter=(counter_start + block) & 0xFFFFFFFF,
                nonce_words=nonce_words,
                rounds=20,
            )
            for block in range(8)
        ],
    }
    formula = MODULE._source_formula(challenge, width=256)
    formula = (
        "\n".join(line for line in formula.splitlines() if not line.startswith("(get-value"))
        + "\n"
    )

    def solve(words: list[int]) -> subprocess.CompletedProcess[str]:
        assertions = "\n".join(
            f"(assert (= k{index} #x{value:08x}))" for index, value in enumerate(words)
        )
        fixed = formula.replace("(check-sat)", assertions + "\n(check-sat)", 1)
        return subprocess.run(
            [analysis["config"]["toolchain"]["Bitwuzla_path"], "--lang", "smt2"],
            input=fixed,
            text=True,
            capture_output=True,
            timeout=30,
            check=False,
        )

    accepted = solve(key_words)
    flipped_words = key_words.copy()
    flipped_words[0] ^= 1
    rejected = solve(flipped_words)
    assert (accepted.returncode, accepted.stdout.strip(), accepted.stderr) == (0, "sat", "")
    assert (rejected.returncode, rejected.stdout.strip(), rejected.stderr) == (0, "unsat", "")


def test_complete_numeric_and_reflected_gray8_orders_are_distinct_and_exact() -> None:
    numeric = MODULE._numeric_order()
    gray = MODULE._gray8_order()
    assert len(numeric) == len(gray) == 256
    assert set(numeric) == set(gray)
    assert numeric != gray
    assert all(
        sum(left != right for left, right in zip(previous, current, strict=True)) == 1
        for previous, current in zip(gray, gray[1:], strict=False)
    )


@pytest.mark.parametrize(("width", "export_count"), [(32, 6), (40, 7), (64, 7), (128, 8), (256, 9)])
def test_binary_coordinate_mapping_decodes_every_unknown_bit_exactly(
    width: int, export_count: int
) -> None:
    variables = [10_000 + bit for bit in range(width)]
    rows = []
    for dimension in range(-1, export_count - 1):
        units = []
        pattern = MODULE._pattern(width, dimension)
        for bit, variable in enumerate(variables):
            units.append(variable if (pattern >> bit) & 1 else -variable)
        rows.append((dimension, units))
    assert MODULE._decode_mapping(rows, width=width) == variables
    assert len(rows) == export_count


def test_partition_is_an_exact_disjoint_2_to_width_cover() -> None:
    partition = MODULE._execution_plan()["partition"]
    for width in MODULE.WIDTHS:
        assert partition["fixed_coordinates_by_width"][str(width)] == list(
            range(width - 1, width - 9, -1)
        )
        assert partition["free_bits_by_width"][str(width)] == width - 8
        per_cell = int(partition["candidate_count_per_cell_by_width"][str(width)])
        complete = int(partition["complete_domain_candidate_count_by_width"][str(width)])
        assert per_cell * 256 == complete == 1 << width


def _unit_cnf(path: Path, width: int) -> None:
    lines = [f"p cnf {width} {width}"]
    lines.extend(f"-{variable} 0" for variable in range(1, width + 1))
    path.write_text("\n".join(lines) + "\n")


@pytest.mark.parametrize("width", [32, 40, 256])
def test_dynamic_helper_withholds_models_from_stdout_and_spools_after_arm(
    helper: Path, tmp_path: Path, width: int
) -> None:
    cnf = tmp_path / f"w{width}.cnf"
    spool = tmp_path / f"w{width}.models"
    _unit_cnf(cnf, width)
    command = [
        str(helper),
        "--cnf",
        str(cnf),
        "--arm",
        f"toy_w{width}",
        "--assumption-one-literals",
        ",".join(str(value) for value in range(width, width - 8, -1)),
        "--model-one-literals",
        ",".join(str(value) for value in range(1, width + 1)),
        "--cell-order",
        ",".join(MODULE._gray8_order()),
        "--seconds",
        "0.01",
        "--model-spool",
        str(spool),
    ]
    result = subprocess.run(command, text=True, capture_output=True, timeout=20, check=False)
    assert result.returncode == 0
    assert result.stderr == ""
    assert "model_bits_bit0_upward" not in result.stdout
    rows = MODULE._json_lines(result.stdout, "A223_RESULT ")
    summaries = MODULE._json_lines(result.stdout, "A223_SUMMARY ")
    model_rows = MODULE._json_lines(spool.read_text(), "A223_MODEL ")
    assert len(rows) == 256
    assert len(summaries) == 1
    assert sum(row["status"] == "sat" for row in rows) == 1
    assert sum(row["status"] == "unsat" for row in rows) == 255
    assert rows[0]["prefix8"] == "00000000"
    assert rows[0]["model_buffered_for_post_arm_spool"] is True
    assert len(model_rows) == 1
    assert model_rows[0]["model_width"] == width
    assert model_rows[0]["model_bits_bit0_upward"] == [0] * width


def test_RSS_scheduler_freezes_priority_first_fit_waves_before_outcomes() -> None:
    gib = 1024**3
    RSS = {width: {"maximum_resident_set_bytes": gib} for width in MODULE.WIDTHS}
    schedule = MODULE._freeze_memory_waves(RSS_by_width=RSS, system_total_bytes=8 * gib)
    assert schedule["wave_count"] == 2
    assert [arm["arm"] for arm in schedule["waves"][0]["arms"]] == [
        "gray8_w40",
        "gray8_w256",
        "numeric_w40",
        "numeric_w256",
        "gray8_w32",
        "gray8_w64",
    ]
    assert [arm["arm"] for arm in schedule["waves"][1]["arms"]] == ["gray8_w128"]
    assert schedule["all_seven_arms_covered_once"] is True
    assert schedule["frozen_before_any_cell_solver_execution"] is True


def test_analyze_only_runs_no_CNF_or_cell_solver() -> None:
    result = subprocess.run(
        [sys.executable, str(MODULE_PATH), "--analyze-only"],
        cwd=ROOT,
        text=True,
        capture_output=True,
        timeout=30,
        check=False,
    )
    assert result.returncode == 0
    assert result.stderr == ""
    summary = json.loads(result.stdout)
    assert summary["cell_solver_execution_started"] is False
    assert summary["widths"] == list(MODULE.WIDTHS)
    assert summary["shared_key_block_count"] == 8
    assert summary["joint_equality_constraint_count_per_width"] == 128
    assert summary["phase1_arm_count"] == 7

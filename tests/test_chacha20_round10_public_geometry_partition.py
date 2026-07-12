from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest

ROOT = Path(__file__).parents[1]
MODULE_PATH = ROOT / "research" / "experiments" / "chacha20_round10_public_geometry_partition.py"
SPEC = importlib.util.spec_from_file_location(
    "chacha20_round10_public_geometry_partition_tested", MODULE_PATH
)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)

RESULTS = ROOT / "research" / "results" / "v1"
PROTOCOL_PATH = ROOT / "research" / "configs" / MODULE.PROTOCOL_FILENAME
RUNNER_SHA256 = "68b4a3e78b37c0e42455de8bfc8613ed917c3ac0307f87b8a4ec68f8857ae93b"
FORMULA_PLAN_SHA256 = "528e5a257ddb3762fda25c73d58002685bb3e3b91d6df570d3453a109a2b9c60"
RESULT_PATH = RESULTS / MODULE.RESULT_FILENAME
CAUSAL_PATH = RESULTS / MODULE.CAUSAL_FILENAME
RESULT_SHA256 = "a945e95c63499d84cf0c41932dbe056b1eb39adbaf6d7a2096887e1b108d99ad"
CAUSAL_SHA256 = "1d1680e04a829139f74fae832a6498164b994c35e636458b2262f66f973f2c93"
CAUSAL_GRAPH_SHA256 = "5feeabefb0e46df3d7dafd4901df2e78b3e9de0354269955bc5b155e7280e08e"
EXECUTION_SHA256 = "9d49fdf952eb7e0df2e36e1400762c70dde704dde539380d0c4d815441cfc7fe"
CONFIRMATION_SHA256 = "4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945"
COMPARISON_SHA256 = "59dd4f24f2603538cf4f202d6f412dbb031d9e7e024fe8cb05cbbc27a7c5524b"


@pytest.fixture(scope="module")
def analysis() -> dict[str, Any]:
    return MODULE.analyze(RESULTS)


def test_a200_protocol_runner_and_retained_anchors_are_exact(
    analysis: dict[str, Any],
) -> None:
    protocol = analysis["protocol"]
    assert MODULE._file_sha256(PROTOCOL_PATH) == MODULE.PROTOCOL_SHA256
    assert MODULE._file_sha256(MODULE_PATH) == RUNNER_SHA256
    assert protocol["protocol_state"] == (
        "frozen_after_A199_public_geometry_derivation_before_any_A200_solver_execution"
    )
    assert protocol["information_boundary"] == {
        "A200_solver_outcomes_used_before_protocol_freeze": False,
        "cell_or_geometry_order_changed_after_any_A200_outcome": False,
        "early_stop_permitted": False,
        "geometry_masks_selected_from_public_A199_data_only": True,
        "unknown_assignment_available_to_runner_before_execution": False,
        "unknown_assignment_in_protocol_or_source": False,
    }
    assert (
        analysis["anchor_gates"]["numeric_prefix_10s_and_30s_complete_covers_all_unknown"] is True
    )
    assert analysis["anchor_gates"]["public_A199_geometry_only"] is True
    assert analysis["public_challenge"]["unknown_assignment_included"] is False
    assert analysis["public_challenge"]["unknown_key_word0_low_value_included"] is False
    assert analysis["solver_execution_started"] is False


def test_a200_four_public_geometries_rederive_and_cover_the_domain_exactly(
    analysis: dict[str, Any],
) -> None:
    masks = analysis["geometry_masks"]
    assert MODULE._canonical_sha256(MODULE._mask_hex(masks)) == MODULE.GEOMETRY_MASKS_SHA256
    assert MODULE._mask_hex(masks) == {
        "gray_prefix_control": ["0x80000", "0xc0000", "0x60000", "0x30000", "0x18000"],
        "fiedler_filtration": ["0x0087f", "0x00c7f", "0x10c7f", "0x12c7f", "0x1ac7f"],
        "laplacian_distinct_modes": [
            "0x10c7f",
            "0x2a9e3",
            "0xf806d",
            "0x9b05b",
            "0x4a6cd",
        ],
        "signed_svd_distinct_modes": [
            "0x12e57",
            "0x833d9",
            "0xe8d31",
            "0xfa05c",
            "0x95333",
        ],
    }
    expected_maps = {
        "gray_prefix_control": "1f5832a50066ae2a7807c72693bf31adebe6ad85fefa6395c7e5c30229ca5033",
        "fiedler_filtration": "7d5f36876224beb1fa9981a161c6217b227aaa31e7a8549dcd7ba64edff93507",
        "laplacian_distinct_modes": "3e8ecf4f02ad12ebcc94ca7b11ee30d11e300f63cd40b5917f60d0f14eb97401",
        "signed_svd_distinct_modes": "bc17192f06d797951651a0c27023b43816f662851346311d6e1bbf68340e306a",
    }
    for geometry in MODULE.GEOMETRY_ORDER:
        partition = analysis["geometry_derivation"]["partitions"][geometry]
        assert partition["binary_rank"] == 5
        assert partition["cell_histogram"] == [1 << 15] * 32
        assert partition["complete_candidate_count"] == 1 << 20
        assert partition["syndrome_map_sha256"] == expected_maps[geometry]


def test_a200_execution_and_formula_plans_are_complete_and_byte_stable(
    analysis: dict[str, Any],
) -> None:
    plan = analysis["execution_plan"]
    formula_plan = analysis["formula_plan"]
    assert MODULE._canonical_sha256(plan) == MODULE.EXECUTION_PLAN_SHA256
    assert MODULE._canonical_sha256(list(MODULE.VARIANTS)) == MODULE.VARIANT_ORDER_SHA256
    assert MODULE._canonical_sha256(formula_plan) == FORMULA_PLAN_SHA256
    assert len(formula_plan) == 128
    assert plan["geometry_order"] == list(MODULE.GEOMETRY_ORDER)
    assert plan["solver_time_limit_milliseconds"] == 10_000
    assert plan["wave_count"] == 32
    assert plan["wave_size"] == 4
    assert plan["complete_variant_plan_required"] is True
    assert plan["early_stop_used"] is False
    for geometry in MODULE.GEOMETRY_ORDER:
        rows = [row for row in formula_plan if row["geometry"] == geometry]
        assert len(rows) == 32
        assert [row["cell"] for row in rows] == list(MODULE.CELLS)
        assert sum(row["candidate_count"] for row in rows) == 1 << 20
        assert all(row["candidate_count"] == 1 << 15 for row in rows)
        assert all(row["affine_equations"] == 5 for row in rows)
        assert all(row["shared_key_block_count"] == 8 for row in rows)
        assert all(row["target_output_bits"] == 4096 for row in rows)
        for row in rows:
            formula = analysis["formulas"][row["variant"]]
            assert len(formula.encode()) == row["bytes"]
            assert MODULE._sha256(formula.encode()) == row["sha256"]
            assert len(formula.splitlines()) == 2709
            assert sum(line.startswith("(assert") for line in formula.splitlines()) == 135
            assert formula.count("(check-sat)") == 1
            assert "(set-option :timeout " not in formula


def test_a200_representative_formula_from_each_geometry_parses_without_solving(
    analysis: dict[str, Any],
) -> None:
    for geometry in MODULE.GEOMETRY_ORDER:
        variant = f"{geometry}_cell_00000"
        result = subprocess.run(
            ["bitwuzla", "--lang", "smt2", "--parse-only"],
            input=analysis["formulas"][variant],
            text=True,
            capture_output=True,
            check=False,
        )
        assert result.returncode == 0
        assert result.stdout == ""
        assert result.stderr == ""


def _rref(masks: list[int], width: int = 20) -> tuple[int, ...]:
    rows = masks.copy()
    rank = 0
    for bit in reversed(range(width)):
        pivot = next(
            (index for index in range(rank, len(rows)) if rows[index] >> bit & 1),
            None,
        )
        if pivot is None:
            continue
        rows[rank], rows[pivot] = rows[pivot], rows[rank]
        for index in range(len(rows)):
            if index != rank and rows[index] >> bit & 1:
                rows[index] ^= rows[rank]
        rank += 1
    return tuple(sorted(rows[:rank], reverse=True))


def test_a200_row_space_controls_are_distinct_where_claimed(
    analysis: dict[str, Any],
) -> None:
    masks = analysis["geometry_masks"]
    numeric = [1 << bit for bit in range(19, 14, -1)]
    spaces = {geometry: _rref(list(rows)) for geometry, rows in masks.items()}
    assert spaces["gray_prefix_control"] == _rref(numeric)
    formula_spaces = [
        spaces["fiedler_filtration"],
        spaces["laplacian_distinct_modes"],
        spaces["signed_svd_distinct_modes"],
    ]
    assert len(set(formula_spaces)) == 3
    assert [row.bit_count() for row in spaces["gray_prefix_control"]] == [1] * 5
    assert sorted(row.bit_count() for row in spaces["fiedler_filtration"]) == [1, 1, 1, 1, 8]
    assert sorted(row.bit_count() for row in spaces["laplacian_distinct_modes"]) == [
        8,
        8,
        10,
        10,
        12,
    ]
    assert sorted(row.bit_count() for row in spaces["signed_svd_distinct_modes"]) == [
        6,
        8,
        8,
        10,
        12,
    ]


def test_a200_retained_complete_execution_is_exact() -> None:
    payload = json.loads(RESULT_PATH.read_bytes())
    assert MODULE._file_sha256(RESULT_PATH) == RESULT_SHA256
    assert MODULE._file_sha256(CAUSAL_PATH) == CAUSAL_SHA256
    assert payload["schema"] == MODULE.SCHEMA
    assert payload["attempt_id"] == "A200"
    assert payload["evidence_stage"] == (
        "ROUND10_PUBLIC_GEOMETRY_COMPLETE_PARTITION_BOUNDARY_RETAINED"
    )
    assert payload["geometry_sha256"] == MODULE.GEOMETRY_MASKS_SHA256
    assert payload["execution_plan_sha256"] == MODULE.EXECUTION_PLAN_SHA256
    assert payload["formula_plan_sha256"] == FORMULA_PLAN_SHA256

    execution = payload["execution"]
    observations = execution["observations"]
    waves = execution["wave_observations"]
    assert execution["variant_order"] == list(MODULE.VARIANTS)
    assert [row["variant"] for row in observations] == list(MODULE.VARIANTS)
    assert len(observations) == 128
    assert [row["status"] for row in observations] == ["unknown"] * 128
    assert all(row["returncode"] == 0 for row in observations)
    assert all(row["externally_timed_out"] is False for row in observations)
    assert all(row["model"] is None for row in observations)
    assert all(row["candidate_count"] == 1 << 15 for row in observations)
    assert len(waves) == 32
    for wave_index, wave in enumerate(waves):
        group = observations[wave_index * 4 : wave_index * 4 + 4]
        assert wave["wave_index"] == wave_index
        assert wave["variants"] == [row["variant"] for row in group]
        assert wave["statuses"] == ["unknown"] * 4
        assert wave["maximum_volatile_seconds"] == max(row["volatile_seconds"] for row in group)
    assert sum(row["volatile_seconds"] for row in observations) == 1282.5427404944785
    assert execution["complete_variant_plan_executed"] is True
    assert execution["early_stop_used"] is False
    assert execution["returned_model_count"] == 0
    assert execution["fully_confirmed_unknown_assignment_count"] == 0
    assert execution["fully_confirmed_unknown_low20_assignments"] == []
    assert execution["unknown_assignment_available_to_runner_before_execution"] is False
    assert MODULE._canonical_sha256(execution) == EXECUTION_SHA256
    assert payload["execution_sha256"] == EXECUTION_SHA256
    assert payload["confirmations"] == []
    assert payload["confirmation_sha256"] == CONFIRMATION_SHA256


def test_a200_all_four_geometry_boundaries_and_comparison_are_exact() -> None:
    payload = json.loads(RESULT_PATH.read_bytes())
    comparisons = payload["comparisons"]
    assert comparisons["original_domain_candidate_count"] == 1 << 20
    assert comparisons["geometry_count"] == 4
    assert comparisons["complete_domain_covered_once_per_geometry"] is True
    assert comparisons["partition_complete_and_disjoint_by_construction"] is True
    assert comparisons["same_challenge_b8_formula_and_budget"] is True
    assert comparisons["numeric_prefix_A198_not_reexecuted"] is True
    assert comparisons["numeric_prefix_A198_10s_and_30s_status"] == "all_unknown"
    assert comparisons["fully_confirmed_unknown_low20_assignments"] == []
    assert comparisons["primary_prediction_retained"] is False
    assert comparisons["comparative_prediction_retained"] is False
    for geometry in MODULE.GEOMETRY_ORDER:
        result = comparisons["geometry_results"][geometry]
        assert result["complete_domain_candidate_count"] == 1 << 20
        assert result["complete_partition_executed"] is True
        assert result["status_counts"] == {
            "sat": 0,
            "unsat": 0,
            "unknown": 32,
            "invalid": 0,
        }
        assert result["resolved_sat_plus_unsat_cell_count"] == 0
        assert result["confirmed_variants"] == []
        assert result["confirmed_model_count"] == 0
        assert result["fully_confirmed_unknown_low20_assignments"] == []
        assert result["statuses"] == {f"{geometry}_cell_{cell}": "unknown" for cell in MODULE.CELLS}
    assert MODULE._canonical_sha256(comparisons) == COMPARISON_SHA256
    assert payload["comparison_sha256"] == COMPARISON_SHA256


def test_a200_solver_identity_and_native_reader_dag_are_exact() -> None:
    payload = json.loads(RESULT_PATH.read_bytes())
    assert payload["solver_identity"] == {
        "executable_sha256": "9896c88b523114e3eae00d737f1183ca71fbd83a99e8e45fe294715747a2ce7a",
        "mode": "bitblast",
        "path": "/opt/homebrew/bin/bitwuzla",
        "sat_backend": "cadical",
        "version": "0.9.1",
    }
    reader = MODULE.CryptoCausalReader(CAUSAL_PATH)
    assert reader.file_sha256 == CAUSAL_SHA256
    assert reader.graph_sha256 == CAUSAL_GRAPH_SHA256
    assert reader.verify_provenance() is True
    rows = reader.triplets(include_inferred=False)
    by_id = {row["edge_id"]: row for row in rows}
    ids = [
        "chacha20-a200-a198-numeric-boundary",
        "chacha20-a200-a199-public-operator-atlas",
        "chacha20-a200-four-exact-affine-covers",
        "chacha20-a200-b8-affine-formula-plan",
        "chacha20-a200-complete-wave-execution",
        "chacha20-a200-independent-confirmation",
        "chacha20-a200-geometry-comparison",
    ]
    assert len(rows) == 7
    assert set(by_id) == set(ids)
    assert [by_id[edge_id]["provenance"] for edge_id in ids] == [
        [],
        [ids[0]],
        [ids[1]],
        [ids[2]],
        [ids[3]],
        [ids[4]],
        [ids[5]],
    ]
    assert all(
        by_id[left]["outcome"] == by_id[right]["trigger"]
        for left, right in zip(ids[:-1], ids[1:], strict=True)
    )

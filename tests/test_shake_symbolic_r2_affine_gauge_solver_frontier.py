from __future__ import annotations

import hashlib
import importlib.util
import json
import sys
from pathlib import Path

import pytest

MODULE_PATH = (
    Path(__file__).parents[1]
    / "research"
    / "experiments"
    / "shake_symbolic_r2_affine_gauge_solver_frontier.py"
)
SPEC = importlib.util.spec_from_file_location(
    "shake_symbolic_r2_affine_gauge_solver_frontier_tested", MODULE_PATH
)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)

RESULTS_DIR = Path(__file__).parents[1] / "research" / "results" / "v1"
RESULT_PATH = RESULTS_DIR / MODULE.RESULT_FILENAME
CAUSAL_PATH = RESULTS_DIR / MODULE.CAUSAL_FILENAME
RESULT_SHA256 = "32908a20d5fc5c70ea99edc259ff0ee2575b2d6bc8344994a1afa36c05202971"
CAUSAL_SHA256 = "6569fc17d39ee4e75f137a731965d3faa4e38a343dd9f08dcfc1bea746272707"
CAUSAL_GRAPH_SHA256 = "6c216489aa40484c3b0c84822a14b48b38a0e5d5129043537190ca50fde433c0"
EXPECTED_FORMULAS = {
    "weighted_degree_descending": (
        8_899_945,
        "85ada5be887db2042ee82d04ae6334e0432fd3350e4880bfcdad99fc3741cd4f",
        "26e2ca5d6320984e3f29d57597b93cdb2b620df069375b54e54f83fa523e310f",
    ),
    "weighted_degree_ascending": (
        8_900_370,
        "15a60177af0c4234d2e09a5d6edee2b98d67a0809fa6433e1b2ef6e13d4c0537",
        "6690d40dbbdd6b00b9ef3ff738d74586f66fed47c148910cb31070edcf1b1200",
    ),
    "greedy_max_remaining_weight": (
        8_899_912,
        "caccb3202513be30d413e1d16c1e1b62ea859f8a761fe9d2ba7e23b2d8b28661",
        "15c61121280e43da5be56a7ee9907a23847acb68e3f3ad91f9186a9028d816eb",
    ),
    "greedy_min_remaining_weight": (
        8_900_348,
        "378fb5a4089a53c39b89eee22b6e835ce148d5254c78ad8d851afc1c4cef40b8",
        "f35c5a01bb316c265ebf33b72dbfe1fe3d6d62fa93f4ec13c8fa769473b0074c",
    ),
}


def test_a159_a160_anchor_gates_are_exact_and_assignment_free() -> None:
    a159, a160 = MODULE._load_anchor_gates(RESULTS_DIR)
    assert a159["fixed_resource_plan_sha256"] == (
        "41bc4b44a13cbce85545a495f3abb95e35fc679a0515fb0dd90e199d10b62b48"
    )
    assert a159["status_counts"] == {
        "error": 0,
        "sat": 0,
        "unknown": 4,
        "unsat": 0,
    }
    assert a160["global_optimum"]["minimum_shift"] == MODULE.AFFINE_SHIFT
    assert a160["global_optimum"]["minimum_tie_count"] == 1
    assert a160["shifted_R2"]["polynomial_state_sha256"] == (MODULE.SHIFTED_R2_POLYNOMIAL_SHA256)
    assert a160["parameters"]["target_rate_input_used"] is False
    assert a160["parameters"]["solver_observations_used"] is False
    assert a160["parameters"]["instrumented_assignment_used"] is False


def test_analyze_freezes_four_exact_gauge_shifted_formulas() -> None:
    analysis = MODULE.analyze(RESULTS_DIR)
    assert analysis["formula_plan_sha256"] == (
        "e3aa4cbacac9093b0762aa0d0aaaa875a56f084a46fca5fc3e6655f392ee23d3"
    )
    assert [row["name"] for row in analysis["rows"]] == list(EXPECTED_FORMULAS)
    for row in analysis["rows"]:
        expected_bytes, expected_sha, expected_poly = EXPECTED_FORMULAS[row["name"]]
        encoding = row["encoding"]
        assert row["formula_bytes"] == expected_bytes
        assert row["formula_sha256"] == expected_sha
        assert encoding["R2_polynomial_state_sha256_in_solver_basis"] == expected_poly
        assert encoding["semantic_shifted_R2_polynomial_state_sha256"] == (
            MODULE.SHIFTED_R2_POLYNOMIAL_SHA256
        )
        assert encoding["shifted_R2_coefficient_incidence"] == {
            "constant": 823,
            "linear": 8_413,
            "quadratic": 15_972,
        }
        assert encoding["affine_shift_original_input_mask"] == MODULE.AFFINE_SHIFT
        assert encoding["shared_monomial_count"] == 301
        assert encoding["quadratic_monomials"] == 276
        assert encoding["R2_state_definitions"] == 1_598
        assert encoding["R2_alias_coordinates"] == [516, 917]
        assert encoding["total_variables"] == 121_578
        assert encoding["total_assertions"] == 122_898
        assert encoding["target_rate_bits"] == 1_344
        assert encoding["instrumented_assignment_input_used"] is False
        assert encoding["solver_observation_input_used_for_formula_construction"] is False
        assert encoding["target_rate_input_used_for_gauge_selection"] is False


def test_permutation_then_affine_model_mapping_recovers_full_rate_witness() -> None:
    analysis = MODULE.analyze(RESULTS_DIR)
    input_assignment = 9_279_571
    shifted_assignment = input_assignment ^ MODULE.AFFINE_SHIFT
    for row in analysis["rows"]:
        solver_assignment = sum(
            ((shifted_assignment >> input_coordinate) & 1) << solver_coordinate
            for solver_coordinate, input_coordinate in enumerate(
                row["encoding"]["variable_to_shifted_input_coordinate"]
            )
        )
        verified = MODULE._verify_solver_row(
            dict(row),
            {"status": "sat", "solver_basis_assignment": solver_assignment},
            analysis["problem"],
            analysis["variant"],
        )
        assert verified["shifted_input_coordinate_assignment"] == shifted_assignment
        assert verified["input_coordinate_assignment"] == input_assignment
        assert verified["independently_confirmed_model"] is True
        assert verified["independent_complete_rate_check"]["complete_rate_match"] is True

    bad_solver_assignment = solver_assignment ^ 1
    with pytest.raises(RuntimeError, match="independently invalid"):
        MODULE._verify_solver_row(
            dict(analysis["rows"][-1]),
            {"status": "sat", "solver_basis_assignment": bad_solver_assignment},
            analysis["problem"],
            analysis["variant"],
        )


def test_fixed_resource_executor_accepts_only_proven_limit_termination(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    raw = b"(check-sat)\n"
    row = {
        "name": "fixed",
        "execution_order": 0,
        "formula_bytes": len(raw),
        "formula_sha256": MODULE._sha256(raw),
        "solver_input_names": [],
        "encoding": {},
    }
    result = {
        "status": "unknown",
        "solver_basis_assignment": None,
        "stats": {"rlimit-count": MODULE.Z3_RLIMIT + 1},
        "return_code": 1,
        "termination": "fixed_rlimit_exhausted",
    }
    monkeypatch.setattr(MODULE, "_run_z3_rlimit", lambda *_args: dict(result))
    executions = MODULE._execute_frontier(
        formula_rows=[row],
        formulas={"fixed": raw},
        problem={},
        variant=None,
        z3=Path("/fake/z3"),
        work_dir=tmp_path / "accepted",
    )
    assert executions[0]["solver"] == result
    assert list((tmp_path / "accepted").iterdir()) == []

    rejected = {**result, "return_code": 2}
    monkeypatch.setattr(MODULE, "_run_z3_rlimit", lambda *_args: dict(rejected))
    with pytest.raises(RuntimeError, match="affine-gauge execution failed"):
        MODULE._execute_frontier(
            formula_rows=[row],
            formulas={"fixed": raw},
            problem={},
            variant=None,
            z3=Path("/fake/z3"),
            work_dir=tmp_path / "rejected",
        )


def test_early_solver_result_with_omitted_zero_counters_is_retained() -> None:
    baseline, _ = MODULE._load_anchor_gates(RESULTS_DIR)
    control = baseline["fixed_resource_plan"][0]
    comparison = MODULE._baseline_comparison(
        baseline,
        [
            {
                "name": control["name"],
                "formula_bytes": control["formula_bytes"] - 1,
                "formula_sha256": "0" * 64,
                "solver": {
                    "status": "sat",
                    "stats": {"rlimit-count": 1},
                },
            }
        ],
    )[0]
    assert comparison["gauge_status"] == "sat"
    assert comparison["gauge_decisions"] == 0
    assert comparison["gauge_conflicts"] == 0
    assert comparison["decision_delta"] == -6_940
    assert comparison["conflict_delta"] == -2_314


def test_retained_a161_artifacts_are_hash_pinned_and_reader_valid() -> None:
    raw = RESULT_PATH.read_bytes()
    assert hashlib.sha256(raw).hexdigest() == RESULT_SHA256
    assert hashlib.sha256(CAUSAL_PATH.read_bytes()).hexdigest() == CAUSAL_SHA256
    payload = json.loads(raw)
    assert payload["schema"] == MODULE.SCHEMA
    assert payload["anchor_gates"]["A159"]["artifact_sha256"] == MODULE.A159_SHA256
    assert payload["anchor_gates"]["A160"]["artifact_sha256"] == MODULE.A160_SHA256
    assert payload["formula_plan_sha256"] == (
        "e3aa4cbacac9093b0762aa0d0aaaa875a56f084a46fca5fc3e6655f392ee23d3"
    )
    assert payload["status_counts"] == {
        "error": 0,
        "sat": 0,
        "unknown": 4,
        "unsat": 0,
    }
    assert payload["confirmed_models"] == []
    summaries = payload["execution_summary"]
    assert [row["name"] for row in summaries] == list(EXPECTED_FORMULAS)
    assert [row["stats"]["rlimit-count"] for row in summaries] == [
        501_080_321,
        501_079_839,
        501_080_223,
        501_079_891,
    ]
    assert [row["stats"]["decisions"] for row in summaries] == [
        11_859,
        10_493,
        5_824,
        7_537,
    ]
    assert [row["stats"]["conflicts"] for row in summaries] == [
        2_282,
        2_283,
        2_569,
        3_444,
    ]
    assert all(row["status"] == "unknown" for row in summaries)
    assert all(row["return_code"] == 1 for row in summaries)
    assert all(row["termination"] == "fixed_rlimit_exhausted" for row in summaries)
    assert [row["decision_delta"] for row in payload["baseline_comparison"]] == [
        4_919,
        -3_893,
        -7_474,
        -11_399,
    ]
    assert [row["formula_byte_delta"] for row in payload["baseline_comparison"]] == [
        -1_033,
        -1_080,
        -1_055,
        -1_075,
    ]
    assert payload["posthoc"]["instrumented_input_assignment"] == 9_279_571
    assert payload["posthoc"]["instrumented_shifted_assignment"] == 245_384
    assert payload["posthoc"]["extracted_only_after_every_encoder_execution"] is True
    lowered = raw.decode().lower()
    assert '"wallclock_seconds"' not in lowered
    assert '"elapsed_seconds"' not in lowered
    assert '"stdout_sha256"' not in lowered
    assert '"stderr_sha256"' not in lowered
    reader = MODULE.CryptoCausalReader(CAUSAL_PATH)
    assert reader.file_sha256 == CAUSAL_SHA256
    assert reader.graph_sha256 == CAUSAL_GRAPH_SHA256
    assert reader.verify_provenance() is True
    rows = reader.triplets(include_inferred=False)
    assert len(rows) == 4
    by_id = {row["edge_id"]: row for row in rows}
    ids = [
        "shake128-a159-fixed-resource-four-order-control",
        "shake128-a160-exact-minimum-incidence-gauge",
        "shake128-a161-four-gauge-shifted-formulas",
        "shake128-a161-fixed-resource-gauge-execution",
    ]
    assert [by_id[edge_id]["provenance"] for edge_id in ids] == [
        [],
        [ids[0]],
        [ids[1]],
        [ids[2]],
    ]

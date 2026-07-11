from __future__ import annotations

import hashlib
import importlib.util
import json
import sys
from pathlib import Path

MODULE_PATH = (
    Path(__file__).parents[1]
    / "research"
    / "experiments"
    / "shake_symbolic_r2_shared_monomial_encoder_frontier.py"
)
SPEC = importlib.util.spec_from_file_location(
    "shake_symbolic_r2_shared_monomial_encoder_frontier_tested", MODULE_PATH
)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)

RESULTS_DIR = Path(__file__).parents[1] / "research" / "results" / "v1"
RESULT_PATH = RESULTS_DIR / MODULE.RESULT_FILENAME
CAUSAL_PATH = RESULTS_DIR / MODULE.CAUSAL_FILENAME
RESULT_SHA256 = "682c9c70e79702f15e54972c04a26372539e3b3e3473fa6230e053dd898c6ea4"
CAUSAL_SHA256 = "3fbc91bd51fabce6f72a12b5aa5c17032a9c4a81ad86154eaed6bb99a25856f1"
CAUSAL_GRAPH_SHA256 = "af9d3fd28501bb48a4597bf77af0afb3011a9a91fb759a252b70ba23b420c570"
EXPECTED_FORMULAS = {
    "original_lazy": (
        8_902_451,
        "3ee089023b25d5752a071fa58b4ad98ae13265a15f741606fa59d474741694da",
        "5b5c8a6138e8bae6700e247d08488a68d4291e3632c1052c88d85f84d6ad9057",
    ),
    "original_frequency": (
        8_901_209,
        "390201f57d10fb3d186b06d93f4d6e1b5c7540f44d5029e0c2b6a2ea0b1f3b5a",
        "f2faeb0aa87138a675f8a2f89a5b601d88a2ce7276fef12e56eaa3e0a3d7fbff",
    ),
    "pivot_lazy": (
        8_902_471,
        "286a4dd883a6ec732ecb75953be2fb7ce3d2b6295b028acbbcfdf50597bd7756",
        "1b4f8e76f5a47bc77773698066c5290e4a233a45e963f4c3e09c51cbddd7f118",
    ),
    "pivot_frequency": (
        8_901_210,
        "4acc464736c2e1a6cc1592cba0d881448005698dce9d2a639e13647b1a652ed5",
        "f09166ff4d52dc8fb6fe39a88b2b56885769ba59a70f712d924c0343c72e7588",
    ),
}


def test_a155_a156_anchor_chain_selects_shared_r2_encoding() -> None:
    a155, a156 = MODULE._load_anchor_gates(RESULTS_DIR)
    assert a155["original_R2"]["global_monomial_count"] == 301
    assert a155["original_R2"]["quadratic_monomial_count"] == 276
    assert a155["complete_graph_proof"]["graph"] == "K24"
    assert a156["status_counts"] == {"error": 0, "sat": 0, "unknown": 4, "unsat": 0}


def test_quadratic_definition_plans_cover_exact_k24_dictionary() -> None:
    _, a154, _ = MODULE._A156._anchor_gates(RESULTS_DIR)
    variant = MODULE._BASE.VARIANTS["shake128"]
    problem = MODULE._NATIVE._problem(variant, MODULE.WINDOW_BITS, MODULE.SEED)
    template = MODULE._WINDOW._clear_window(problem["base_state"], variant, problem["positions"])
    polynomials = MODULE._R1._SPLIT._symbolic_prefix_polynomials(
        template, variant, problem["positions"], 2
    )
    lazy, occurrence = MODULE._ordered_quadratics(polynomials, "first_coordinate_use")
    frequency, frequency_occurrence = MODULE._ordered_quadratics(
        polynomials, "decreasing_coordinate_occurrence_then_numeric_mask"
    )
    assert lazy == []
    assert occurrence == frequency_occurrence
    assert len(frequency) == 276
    assert len(set(frequency)) == 276
    assert min(occurrence.values()) == 35
    assert max(occurrence.values()) == 88
    assert frequency == sorted(frequency, key=lambda mask: (-occurrence[mask], mask))
    assert sorted(a154["basis"]["pivot_delta_to_input_coordinate"]) == list(range(24))


def test_analyze_freezes_four_exact_shared_r2_formulas() -> None:
    analysis = MODULE.analyze(RESULTS_DIR)
    canonical = analysis["canonical"]
    assert canonical["formula_bytes"] == MODULE.CANONICAL_R2_FORMULA_BYTES
    assert canonical["formula_sha256"] == MODULE.CANONICAL_R2_FORMULA_SHA256
    assert canonical["R2_polynomial_state_sha256"] == MODULE.ORIGINAL_R2_POLYNOMIAL_SHA256
    assert analysis["formula_plan_sha256"] == (
        "500ab417b3ecab00024b621f2797babfa050270f0cd63556fd0002ef8db77cbf"
    )
    assert [row["name"] for row in analysis["rows"]] == list(EXPECTED_FORMULAS)
    for row in analysis["rows"]:
        expected_bytes, expected_sha, expected_order_sha = EXPECTED_FORMULAS[row["name"]]
        assert row["formula_bytes"] == expected_bytes
        assert row["formula_sha256"] == expected_sha
        encoding = row["encoding"]
        assert encoding["quadratic_definition_order_sha256"] == expected_order_sha
        assert encoding["shared_monomial_count"] == 301
        assert encoding["quadratic_monomials"] == 276
        assert encoding["R2_state_definitions"] == 1598
        assert encoding["R2_alias_coordinates"] == [516, 917]
        assert encoding["R2_alias_definition_count_eliminated"] == 2
        assert encoding["prefix_variables"] == 1898
        assert encoding["prefix_assertions"] == 1874
        assert encoding["total_variables"] == 121_578
        assert encoding["total_assertions"] == 122_898
        assert encoding["target_rate_bits"] == 1344
        assert encoding["instrumented_assignment_input_used"] is False


def test_retained_a157_artifacts_are_hash_pinned_and_reader_valid() -> None:
    raw = RESULT_PATH.read_bytes()
    assert hashlib.sha256(raw).hexdigest() == RESULT_SHA256
    assert hashlib.sha256(CAUSAL_PATH.read_bytes()).hexdigest() == CAUSAL_SHA256
    payload = json.loads(raw)
    assert payload["schema"] == MODULE.SCHEMA
    assert payload["anchor_gates"]["A155"]["artifact_sha256"] == MODULE.A155_SHA256
    assert payload["anchor_gates"]["A156"]["artifact_sha256"] == MODULE.A156_SHA256
    assert payload["formula_plan_sha256"] == (
        "500ab417b3ecab00024b621f2797babfa050270f0cd63556fd0002ef8db77cbf"
    )
    assert payload["status_counts"] == {"error": 0, "sat": 0, "unknown": 4, "unsat": 0}
    assert payload["confirmed_models"] == []
    assert [row["name"] for row in payload["execution"]] == list(EXPECTED_FORMULAS)
    assert all(row["solver"]["status"] == "unknown" for row in payload["execution"])
    assert all(row["solver"]["return_code"] == 0 for row in payload["execution"])
    assert all(row["solver"]["external_timeout"] is False for row in payload["execution"])
    assert all(row["solver"]["solver_basis_assignment"] is None for row in payload["execution"])
    assert payload["posthoc"]["instrumented_assignment"] == 9_279_571
    assert payload["posthoc"]["extracted_only_after_every_encoder_execution"] is True
    lowered = raw.decode().lower()
    assert '"wallclock_seconds"' not in lowered
    assert '"elapsed_seconds"' not in lowered
    reader = MODULE.CryptoCausalReader(CAUSAL_PATH)
    assert reader.file_sha256 == CAUSAL_SHA256
    assert reader.graph_sha256 == CAUSAL_GRAPH_SHA256
    assert reader.verify_provenance() is True
    assert len(reader.triplets(include_inferred=False)) == 4

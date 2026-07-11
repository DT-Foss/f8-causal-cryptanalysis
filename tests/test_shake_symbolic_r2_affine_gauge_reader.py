from __future__ import annotations

import hashlib
import importlib.util
import json
import sys
from pathlib import Path

import numpy as np

MODULE_PATH = (
    Path(__file__).parents[1]
    / "research"
    / "experiments"
    / "shake_symbolic_r2_affine_gauge_reader.py"
)
SPEC = importlib.util.spec_from_file_location(
    "shake_symbolic_r2_affine_gauge_reader_tested", MODULE_PATH
)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)

RESULTS_DIR = Path(__file__).parents[1] / "research" / "results" / "v1"
RESULT_PATH = RESULTS_DIR / MODULE.RESULT_FILENAME
CAUSAL_PATH = RESULTS_DIR / MODULE.CAUSAL_FILENAME
RESULT_SHA256 = "725d5fcddba7ff4ba4e1a90fac5dd90d34990f4b9f62bf7cfe06e56396de73aa"
CAUSAL_SHA256 = "48e899901f73be9954267d403bd9bfc1ad53d0561fd0a5446d9edabc62eeef61"
CAUSAL_GRAPH_SHA256 = "b23853988b0db99b614b10313247fe81335defb39c16d6a28c12324c6a2478e2"


def _direct_walsh(values: np.ndarray) -> np.ndarray:
    return np.asarray(
        [
            sum(
                int(coefficient) * (-1 if (mask & frequency).bit_count() & 1 else 1)
                for frequency, coefficient in enumerate(values)
            )
            for mask in range(values.size)
        ],
        dtype=np.int32,
    )


def test_exact_integer_fwht_matches_direct_definition() -> None:
    rng = np.random.default_rng(0xA160)
    for width in range(1, 9):
        values = rng.integers(-20, 21, size=1 << width, dtype=np.int32)
        transformed = MODULE._fwht(values)
        assert np.array_equal(transformed, _direct_walsh(values))
        assert np.array_equal(MODULE._fwht(transformed), values * values.size)


def test_affine_linear_objective_matches_explicit_polynomial_substitution() -> None:
    polynomials = [
        frozenset({0, 0b001, 0b010, 0b011, 0b101}),
        frozenset({0b100, 0b011, 0b110}),
    ]
    width = 3
    terms, coefficients, _ = MODULE._linear_affine_terms(polynomials, width)
    scores = MODULE._fwht(coefficients)
    for shift in range(1 << width):
        shifted = MODULE._shift_polynomials(polynomials, shift, width)
        explicit = MODULE._coefficient_counts(shifted)["linear"]
        direct = MODULE._linear_incidence(terms, shift)
        walsh = (len(terms) - int(scores[shift])) // 2
        assert explicit == direct == walsh
        assert [
            frozenset(mask for mask in polynomial if mask.bit_count() == 2)
            for polynomial in shifted
        ] == [
            frozenset(mask for mask in polynomial if mask.bit_count() == 2)
            for polynomial in polynomials
        ]


def test_a154_a155_anchor_chain_is_exact_and_assignment_free() -> None:
    a154, gates = MODULE._load_anchor_gates(RESULTS_DIR)
    assert gates["A155"]["artifact_sha256"] == MODULE.A155_SHA256
    assert gates["A155"]["original_R2_polynomial_state_sha256"] == (
        MODULE.ORIGINAL_R2_POLYNOMIAL_SHA256
    )
    assert gates["A155"]["quadratic_graph"] == "K24"
    assert gates["A155"]["target_rate_imported"] is False
    assert gates["A155"]["solver_observations_imported"] is False
    assert gates["A155"]["instrumented_assignment_imported"] is False
    shift = MODULE._systematic_constant_shift(a154)
    assert 0 <= shift < 1 << MODULE.WINDOW_BITS


def test_full_walsh_analysis_reproduces_unique_global_gauge() -> None:
    analysis = MODULE.analyze(RESULTS_DIR)
    objective = analysis["walsh_objective"]
    optimum = analysis["global_optimum"]
    shifted = analysis["shifted_R2"]
    assert objective["linear_coefficient_positions"] == 38_400
    assert objective["shift_domain_size"] == 1 << 24
    assert objective["coefficient_spectrum_nonzero_bins"] == 1_133
    assert objective["coefficient_spectrum_sha256"] == (
        "747a3153f75d589a9b74f3148e04e7e083f0894f435963d19fd782515ded8aec"
    )
    assert objective["walsh_parseval_verified"] is True
    assert (
        objective["walsh_parseval_observed_score_energy"]
        == (objective["walsh_parseval_expected_score_energy"])
    )
    assert optimum["minimum_shift"] == 9_316_059
    assert optimum["minimum_shift_hex"] == "0x8e26db"
    assert optimum["minimum_shift_hamming_weight"] == 13
    assert optimum["minimum_tie_count"] == 1
    assert optimum["minimum_linear_incidence"] == 8_413
    assert optimum["zero_shift_linear_incidence"] == 8_698
    assert optimum["linear_incidence_removed_from_zero_shift"] == 285
    assert optimum["systematic_R1_constant_shift_hex"] == "0xb8faad"
    assert optimum["systematic_R1_constant_shift_linear_incidence"] == 8_665
    assert optimum["walsh_score_vector_sha256"] == (
        "39e31bcf1b37548f9be98e646d57b03fee186307cc245d5bfa882952222e7a95"
    )
    assert shifted["polynomial_state_sha256"] == (
        "cc5e540d6650a78c607ef5a1c0071894be61cc32f711aecf75f1277ab9d68dda"
    )
    assert shifted["linear_coefficient_incidence"] == 8_413
    assert shifted["quadratic_coefficient_incidence"] == 15_972
    assert shifted["per_coordinate_quadratic_terms_unchanged"] is True
    assert analysis["verification"]["three_way_state_bits_checked"] == 307_200


def test_retained_a160_artifacts_are_hash_pinned_and_reader_valid() -> None:
    raw = RESULT_PATH.read_bytes()
    assert hashlib.sha256(raw).hexdigest() == RESULT_SHA256
    assert hashlib.sha256(CAUSAL_PATH.read_bytes()).hexdigest() == CAUSAL_SHA256
    payload = json.loads(raw)
    assert payload["schema"] == MODULE.SCHEMA
    assert payload["anchor_gates"]["A155"]["artifact_sha256"] == MODULE.A155_SHA256
    assert payload["global_optimum"]["global_optimum_certified"] is True
    assert payload["global_optimum"]["minimum_shift_hex"] == "0x8e26db"
    assert payload["parameters"]["target_rate_input_used"] is False
    assert payload["parameters"]["solver_observations_used"] is False
    assert payload["parameters"]["instrumented_assignment_used"] is False
    reader = MODULE.CryptoCausalReader(CAUSAL_PATH)
    assert reader.file_sha256 == CAUSAL_SHA256
    assert reader.graph_sha256 == CAUSAL_GRAPH_SHA256
    assert reader.verify_provenance() is True
    rows = reader.triplets(include_inferred=False)
    assert len(rows) == 4
    by_id = {row["edge_id"]: row for row in rows}
    ids = [
        "shake128-a155-exact-r2-complete-interaction",
        "shake128-a160-linear-incidence-walsh-objective",
        "shake128-a160-exhaustive-affine-gauge-optimum",
        "shake128-a160-optimal-gauge-semantic-gate",
    ]
    assert [by_id[edge_id]["provenance"] for edge_id in ids] == [
        [],
        [ids[0]],
        [ids[1]],
        [ids[2]],
    ]

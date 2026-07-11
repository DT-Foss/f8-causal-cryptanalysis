from __future__ import annotations

import hashlib
import importlib.util
import json
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

MODULE_PATH = (
    Path(__file__).parents[1]
    / "research"
    / "experiments"
    / "shake_symbolic_r1_systematic_encoder_frontier.py"
)
SPEC = importlib.util.spec_from_file_location(
    "shake_symbolic_r1_systematic_encoder_frontier_tested", MODULE_PATH
)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)

RESULTS_DIR = Path(__file__).parents[1] / "research" / "results" / "v1"
RESULT_PATH = RESULTS_DIR / MODULE.RESULT_FILENAME
CAUSAL_PATH = RESULTS_DIR / MODULE.CAUSAL_FILENAME
RESULT_SHA256 = "703e8c5c68882a144f60e29867e99f37b5b8bba42ffa70b0aee922d0cb2551ae"
CAUSAL_SHA256 = "9465ac3f3d5381ce8bec44b9a00cafe0ecbe3e17e72ecfbd453ece0394db7189"
CAUSAL_GRAPH_SHA256 = "da18e2fccb4fbfcde796e23ba7e745d6552db461cd981a47767c5daf671309e2"
EXPECTED_FORMULAS = {
    "original_alias": (
        9_087_150,
        "af38e924b195c04d9d1fa1f10cc44fa1cd7164dd6d3fcb5ed8974f74ac585547",
        27,
    ),
    "original_inline": (
        9_085_737,
        "c557019c695ce6943ab4065aa4337c4f5d653828793039b8d95afcdbc577201d",
        0,
    ),
    "pivot_alias": (
        9_087_142,
        "7848bfccac9199c6b0dedf66cdc2f4c05ecdeab8b4433d03f8c9ab6bbd62516c",
        27,
    ),
    "pivot_inline": (
        9_085_733,
        "7f442c229fe15448dfbc6902f70c66a9d547a83a1e7d0f2f56111348fcb56326",
        0,
    ),
}


def test_anchor_chain_selects_systematic_r1_instead_of_r2_cover() -> None:
    a152, a154, a155 = MODULE._anchor_gates(RESULTS_DIR)
    assert a152["selection"]["interaction_edges"] == []
    assert a154["basis"]["rank"] == 24
    assert a154["basis"]["systematic_unit_row_basis"] is True
    assert a155["complete_graph_proof"]["graph"] == "K24"
    assert a155["complete_graph_proof"]["minimum_vertex_cover_size"] == 23


def test_variable_orders_and_inverse_rows_are_exact_permutations() -> None:
    _, a154, _ = MODULE._anchor_gates(RESULTS_DIR)
    for spec in MODULE.ENCODERS:
        variable_to_input = MODULE._variable_to_input_coordinates(spec, a154)
        rows = MODULE._input_to_solver_rows(variable_to_input)
        assert sorted(variable_to_input) == list(range(24))
        assert all(row.bit_count() == 1 for row in rows)
        for assignment in (0, 1, 0xA5C39F, (1 << 24) - 1):
            solver_assignment = sum(
                ((assignment >> input_coordinate) & 1) << solver_coordinate
                for solver_coordinate, input_coordinate in enumerate(variable_to_input)
            )
            assert MODULE._A154._recover_input(solver_assignment, rows) == assignment


def test_affine_expression_constant_alias_and_xor_cases() -> None:
    inputs = ["x0", "x1", "x2"]
    assert MODULE._affine_expression(inputs, frozenset()) == ("false", 0, False)
    assert MODULE._affine_expression(inputs, frozenset({0})) == ("true", 0, True)
    assert MODULE._affine_expression(inputs, frozenset({1})) == ("x0", 1, False)
    assert MODULE._affine_expression(inputs, frozenset({0, 2})) == ("(not x1)", 1, True)
    assert MODULE._affine_expression(inputs, frozenset({1, 4})) == (
        "(xor x0 x2)",
        2,
        False,
    )
    with pytest.raises(RuntimeError, match="non-affine"):
        MODULE._affine_expression(inputs, frozenset({3}))


def test_analyze_freezes_four_exact_formulas_without_starting_solver() -> None:
    analysis = MODULE.analyze(RESULTS_DIR)
    assert analysis["canonical"]["formula_bytes"] == MODULE.A152_SMT_BYTES
    assert analysis["canonical"]["formula_sha256"] == MODULE.A152_SMT_SHA256
    assert analysis["canonical"]["rerun_as_A156"] is False
    assert analysis["formula_plan_sha256"] == (
        "9d5747707fbd99bb9a6766a0a1e1939bc9fe9350f1034e7a2243ae140e3c94af"
    )
    assert [row["name"] for row in analysis["rows"]] == list(EXPECTED_FORMULAS)
    for row in analysis["rows"]:
        expected_bytes, expected_sha, expected_prefix_assertions = EXPECTED_FORMULAS[row["name"]]
        assert row["formula_bytes"] == expected_bytes
        assert row["formula_sha256"] == expected_sha
        encoding = row["encoding"]
        assert encoding["prefix_assertions"] == expected_prefix_assertions
        assert encoding["state_coordinate_classes"]["constant_false"] == 540
        assert encoding["state_coordinate_classes"]["constant_true"] == 558
        assert encoding["state_coordinate_classes"]["direct_variable"] == 259
        assert encoding["state_coordinate_classes"]["negated_variable"] == 216
        assert encoding["state_coordinate_classes"]["multi_term"] == 27
        assert encoding["target_rate_bits"] == 1344
        assert encoding["instrumented_assignment_input_used"] is False


def test_solver_basis_model_is_mapped_before_independent_check(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    row = {
        "name": "swap",
        "encoding": {"input_to_solver_row_masks_hex": ["000002", "000001"]},
    }
    result = {
        "status": "sat",
        "solver_basis_assignment": 0b01,
        "stats": {},
        "return_code": 0,
        "external_timeout": False,
    }

    def verify(_problem: object, _variant: object, assignment: int) -> dict[str, object]:
        assert assignment == 0b10
        return {
            "complete_rate_match": True,
            "rate_bits_checked": 1344,
            "candidate_rate_sha256": "same",
            "target_rate_sha256": "same",
        }

    monkeypatch.setattr(MODULE, "_VERIFY", verify)
    checked = MODULE._verify_solver_row(row, result, {}, SimpleNamespace(rate_bits=1344))
    assert checked["input_coordinate_assignment"] == 0b10
    assert checked["independently_confirmed_model"] is True


def test_sat_without_complete_model_fails_closed() -> None:
    row = {"name": "incomplete", "encoding": {"input_to_solver_row_masks_hex": []}}
    result = {
        "status": "sat",
        "solver_basis_assignment": None,
        "stats": {},
        "return_code": 0,
        "external_timeout": False,
    }
    with pytest.raises(RuntimeError, match="SAT without a complete input model"):
        MODULE._verify_solver_row(row, result, {}, SimpleNamespace(rate_bits=1344))


def test_retained_a156_artifacts_are_hash_pinned_and_reader_valid() -> None:
    raw = RESULT_PATH.read_bytes()
    assert hashlib.sha256(raw).hexdigest() == RESULT_SHA256
    assert hashlib.sha256(CAUSAL_PATH.read_bytes()).hexdigest() == CAUSAL_SHA256
    payload = json.loads(raw)
    assert payload["schema"] == MODULE.SCHEMA
    assert payload["anchor_gates"]["A152"]["artifact_sha256"] == MODULE.A152_SHA256
    assert payload["anchor_gates"]["A154"]["artifact_sha256"] == MODULE.A154_SHA256
    assert payload["anchor_gates"]["A155"]["artifact_sha256"] == MODULE.A155_SHA256
    assert payload["formula_plan_sha256"] == (
        "9d5747707fbd99bb9a6766a0a1e1939bc9fe9350f1034e7a2243ae140e3c94af"
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
    assert len(reader.triplets(include_inferred=False)) == 5

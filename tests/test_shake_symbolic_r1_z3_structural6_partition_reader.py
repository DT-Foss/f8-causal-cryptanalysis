from __future__ import annotations

import hashlib
import importlib.util
import shutil
import sys
from pathlib import Path
from typing import Any

import pytest

from arx_carry_leak.crypto_causal import CryptoCausalReader

_ROOT = Path(__file__).parents[1]
_SCRIPT = (
    _ROOT / "research" / "experiments" / "shake_symbolic_r1_z3_structural6_partition_reader.py"
)
_SPEC = importlib.util.spec_from_file_location(
    "shake_symbolic_r1_z3_structural6_partition_reader", _SCRIPT
)
assert _SPEC is not None and _SPEC.loader is not None
_COMBINED = importlib.util.module_from_spec(_SPEC)
sys.modules[_SPEC.name] = _COMBINED
_SPEC.loader.exec_module(_COMBINED)

_RESULTS = _ROOT / "research" / "results" / "v1"
_STRATEGY_PATH = _RESULTS / "shake_symbolic_r1_z3_strategy_frontier_v1.json"
_STRUCTURAL6_PATH = _RESULTS / "shake_symbolic_r1_structural6_partition_reader_v1.json"


def _z3() -> Path:
    path = Path(shutil.which("z3") or "/opt/homebrew/bin/z3")
    if not path.is_file():
        pytest.skip("Z3 CLI is not installed")
    return path


@pytest.fixture(scope="module")
def canonical() -> tuple[Any, dict[str, Any], dict[str, Any]]:
    _, retained_selection, retained_trial = _COMBINED._load_structural6_gate(_STRUCTURAL6_PATH)
    variant = _COMBINED._BASE.VARIANTS["shake128"]
    formula, selection = _COMBINED._canonical_inputs(variant)
    assert selection == retained_selection
    return formula, selection, retained_trial


def test_both_source_hashes_winner_and_shared_formula_are_exactly_gated() -> None:
    _, winner = _COMBINED._load_strategy_gate(_STRATEGY_PATH)
    _, selection, trial = _COMBINED._load_structural6_gate(_STRUCTURAL6_PATH)
    assert hashlib.sha256(_STRATEGY_PATH.read_bytes()).hexdigest() == (
        _COMBINED.STRATEGY_FRONTIER_SHA256
    )
    assert hashlib.sha256(_STRUCTURAL6_PATH.read_bytes()).hexdigest() == (
        _COMBINED.STRUCTURAL6_SHA256
    )
    assert winner == {
        "selected_strategy": "qf_uf_default_retained",
        "selection_metric": "decisions",
        "selection_metric_value": 4701.0,
        "width20_status": "unknown",
        "width20_decisions": 11124.0,
        "width20_timeout_seconds": 120,
        "canonical_smt_sha256": (
            "66aa82020b4dd2b4d21f3065c99ca6f7c9224ab1ab9765f686121f2fe7f8618f"
        ),
        "renderer_logic": "QF_UF",
        "renderer_check_sat": "(check-sat)",
    }
    assert selection["selected_coordinates"] == [4, 9, 12, 15, 17, 18]
    assert trial["status_counts"] == {
        "sat": 0,
        "unsat": 0,
        "unknown": 64,
        "error": 0,
    }


@pytest.mark.parametrize(
    ("source", "loader"),
    [
        (_STRATEGY_PATH, _COMBINED._load_strategy_gate),
        (_STRUCTURAL6_PATH, _COMBINED._load_structural6_gate),
    ],
)
def test_source_hash_gates_reject_any_byte_change(
    tmp_path: Path, source: Path, loader: Any
) -> None:
    changed = tmp_path / source.name
    changed.write_bytes(source.read_bytes() + b"\n")
    with pytest.raises(RuntimeError, match="hash differs"):
        loader(changed)


def test_complete_formula_graph_plan_and_manifest_are_neutral_and_disjoint(
    canonical: tuple[Any, dict[str, Any], dict[str, Any]],
) -> None:
    _, selection, retained_trial = canonical
    plan = _COMBINED._STRUCTURAL6._complete_subspace_plan_gate(selection)
    assert selection["interaction_edges_sha256"] == _COMBINED.INTERACTION_EDGES_SHA256
    assert selection["selection_sha256"] == _COMBINED.SELECTION_SHA256
    assert selection["subspace_plan_sha256"] == _COMBINED.SUBSPACE_PLAN_SHA256
    assert selection["actual_assignment_used"] is False
    assert selection["posthoc_assignment_used"] is False
    assert selection["target_end_state_bits_used"] is False
    assert [row["fixed_value"] for row in plan] == list(range(64))
    assert sum(row["logical_assignments"] for row in plan) == 1 << 20
    manifest = _COMBINED._formula_manifest(retained_trial["subspaces_detail"])
    assert _COMBINED._STRUCTURAL6._canonical_sha256(manifest) == (
        _COMBINED.STRUCTURAL6_MANIFEST_SHA256
    )


@pytest.mark.parametrize("fixed_value", [0, 1, 22, 63])
def test_winner_renderer_is_byte_identical_and_matches_retained_subspace_hashes(
    canonical: tuple[Any, dict[str, Any], dict[str, Any]], fixed_value: int
) -> None:
    formula, selection, retained_trial = canonical
    rendered, audit = _COMBINED._render_winner_subspace(
        formula,
        selection["selected_coordinates"],
        fixed_value,
    )
    source = retained_trial["subspaces_detail"][fixed_value]
    assert len(rendered) == source["smt_bytes"]
    assert hashlib.sha256(rendered).hexdigest() == source["smt_sha256"]
    assert audit["changed_line_indices_zero_based"] == []
    assert audit["get_value_preserved_byte_exact"] is True
    assert _COMBINED._STRATEGY._render_strategy(rendered, "qf_fd_default") != rendered


def test_independent_verifier_checks_every_rate_bit_without_solver_reuse(
    canonical: tuple[Any, dict[str, Any], dict[str, Any]],
) -> None:
    formula, _, _ = canonical
    variant = _COMBINED._BASE.VARIANTS["shake128"]
    actual = _COMBINED._WINDOW._extract_window(
        formula.problem["base_state"], variant, formula.problem["positions"]
    )
    accepted = _COMBINED._complete_rate_verification(formula.problem, variant, actual)
    rejected = _COMBINED._complete_rate_verification(formula.problem, variant, actual ^ 1)
    assert accepted["rate_bits_checked"] == 1344
    assert accepted["rate_lanes_checked"] == 21
    assert accepted["complete_rate_match"] is True
    assert accepted["candidate_rate_sha256"] == accepted["target_rate_sha256"]
    assert rejected["complete_rate_match"] is False
    assert rejected["candidate_rate_sha256"] != rejected["target_rate_sha256"]


def test_candidate_gate_rejects_any_model_without_complete_independent_match(
    canonical: tuple[Any, dict[str, Any], dict[str, Any]],
) -> None:
    formula, _, _ = canonical
    variant = _COMBINED._BASE.VARIANTS["shake128"]
    actual = _COMBINED._WINDOW._extract_window(
        formula.problem["base_state"], variant, formula.problem["positions"]
    )
    accepted = _COMBINED._complete_rate_verification(formula.problem, variant, actual)
    rows = [
        {
            "status": "sat",
            "assignment": actual,
            "independent_verification": accepted,
        },
        {"status": "unknown", "assignment": None, "independent_verification": None},
    ]
    gate = _COMBINED._candidate_gate(rows)
    assert gate["found_assignments"] == [actual]
    assert gate["verified_assignments"] == [actual]
    assert gate["independent_verifier_rate_bits"] == 1344

    rejected = dict(accepted)
    rejected["complete_rate_match"] = False
    rejected["candidate_rate_sha256"] = "0" * 64
    rows[0]["independent_verification"] = rejected
    with pytest.raises(RuntimeError, match="complete-rate gate"):
        _COMBINED._candidate_gate(rows)


def test_small_two_subspace_combination_executes_and_verifies_complete_rate(
    tmp_path: Path,
) -> None:
    variant = _COMBINED._BASE.VARIANTS["shake128"]
    formula = _COMBINED._STRATEGY._canonical_formula(
        variant,
        4,
        _COMBINED._STRATEGY.SYNTAX_SEED,
    )
    selection = _COMBINED._STRUCTURAL6._derive_structural_selection(
        formula.problem["base_state"],
        variant,
        formula.problem["positions"],
        1,
    )
    trial = _COMBINED._partition_trial(
        formula,
        variant,
        selection,
        30,
        2,
        _z3(),
        tmp_path,
        False,
    )
    assert trial["status_counts"] == {
        "sat": 1,
        "unsat": 1,
        "unknown": 0,
        "error": 0,
    }
    assert trial["strategy"] == "qf_uf_default_retained"
    assert trial["winner_renderer_byte_identical_for_every_subspace"] is True
    assert trial["all_found_assignments_independently_verified"] is True
    assert trial["reconstruction_matches_instrumented_assignment"] is True
    verification = next(
        row["independent_verification"]
        for row in trial["subspaces_detail"]
        if row["assignment"] is not None
    )
    assert verification["rate_bits_checked"] == 1344
    assert verification["rate_lanes_checked"] == 21
    assert verification["complete_rate_match"] is True


def test_reader_is_exact_hash_bound_neutral_three_triplet_chain(
    tmp_path: Path,
    canonical: tuple[Any, dict[str, Any], dict[str, Any]],
) -> None:
    _, selection, _ = canonical
    trial = {
        "timeout_seconds_per_subspace": 120,
        "max_workers": 5,
        "subspace_formula_manifest_sha256": _COMBINED.STRUCTURAL6_MANIFEST_SHA256,
        "subspace_count": 64,
        "winner_renderer_byte_identical_for_every_subspace": True,
        "status_counts": {"sat": 0, "unsat": 0, "unknown": 64, "error": 0},
        "found_assignments": [],
        "verified_assignments": [],
        "all_found_assignments_independently_verified": True,
        "subspaces_detail": [],
    }
    path = tmp_path / "z3-structural6.causal"
    _, emitted, gate = _COMBINED._build_graph(path, selection, trial)
    reader = CryptoCausalReader(path)
    rows = reader.triplets(include_inferred=False)
    assert emitted == rows
    assert reader.verify_provenance()
    assert gate["passed"] is True
    assert gate["explicit_triplet_count"] == 3
    assert gate["exact_three_edge_chain"] is True
    assert gate["hash_binding_verified"] is True
    assert gate["neutral_observation_gate"] is True
    by_id = {row["edge_id"]: row for row in rows}
    inputs_id = "r1-z3-structural6-hash-gated-inputs"
    plan_id = "r1-z3-winner-structural6-complete-plan"
    observations_id = "r1-z3-structural6-neutral-observations"
    assert set(by_id) == {inputs_id, plan_id, observations_id}
    assert by_id[plan_id]["provenance"] == [inputs_id]
    assert by_id[observations_id]["provenance"] == [plan_id]
    assert by_id[inputs_id]["outcome"] == by_id[plan_id]["trigger"]
    assert by_id[plan_id]["outcome"] == by_id[observations_id]["trigger"]
    assert by_id[observations_id]["attrs"]["claim_policy"] == (
        "statuses_and_independently_verified_candidates_only"
    )

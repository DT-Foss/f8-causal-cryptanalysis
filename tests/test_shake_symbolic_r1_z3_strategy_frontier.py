from __future__ import annotations

import hashlib
import importlib.util
import shutil
import sys
from pathlib import Path

import pytest

from arx_carry_leak.crypto_causal import CryptoCausalReader

_ROOT = Path(__file__).parents[1]
_SCRIPT = _ROOT / "research" / "experiments" / "shake_symbolic_r1_z3_strategy_frontier.py"
_SPEC = importlib.util.spec_from_file_location("shake_symbolic_r1_z3_strategy_frontier", _SCRIPT)
assert _SPEC is not None and _SPEC.loader is not None
_FRONTIER = importlib.util.module_from_spec(_SPEC)
sys.modules[_SPEC.name] = _FRONTIER
_SPEC.loader.exec_module(_FRONTIER)

_A138 = _ROOT / "research" / "results" / "v1" / "shake_symbolic_r1_scaling_reader_v1.json"


def _z3() -> Path:
    path = Path(shutil.which("z3") or "/opt/homebrew/bin/z3")
    if not path.is_file():
        pytest.skip("Z3 CLI is not installed")
    return path


def _eligible_row(
    strategy: str,
    index: int,
    *,
    decisions: float | None,
    conflicts: float | None,
    verified: bool = True,
) -> dict[str, object]:
    return {
        "strategy": strategy,
        "portfolio_index": index,
        "status": "sat",
        "assignment": index + 1,
        "selection_metrics": {"decisions": decisions, "conflicts": conflicts},
        "independent_verification": {"complete_rate_match": verified},
        # These post-hoc fields are deliberately contradictory: they must not
        # participate in selection.
        "matches_instrumented_assignment_posthoc": False,
        "ground_truth_used_for_strategy_selection": False,
    }


def test_renderer_changes_only_logic_and_check_sat_and_preserves_body() -> None:
    canonical = b"".join(
        (
            b"(set-logic QF_UF)\n",
            b"(set-option :sat.random_seed 7)\n",
            b"(declare-fun x0 () Bool)\n",
            b"(declare-fun x1 () Bool)\n",
            b"(assert (= x1 (not x0)))\n",
            b"(check-sat)\n",
            b"(get-value (x0 x1))\n",
            b"(exit)\n",
        )
    )
    for route in _FRONTIER.STRATEGIES:
        rendered = _FRONTIER._render_strategy(canonical, route)
        audit = _FRONTIER._render_audit(canonical, rendered)
        assert audit["declaration_count"] == 2
        assert audit["assertion_count"] == 1
        assert audit["get_value_count"] == 1
        assert audit["get_value_preserved_byte_exact"] is True
        expected_changed = {
            "qf_uf_default_retained": [],
            "qf_fd_default": [0],
            "aig_sat": [5],
            "aig_sat_chb": [5],
            "aig_sat_cutxor": [5],
            "propagate_aig_sat": [5],
        }
        assert audit["changed_line_indices_zero_based"] == expected_changed[route.name]
        assert b"(declare-fun x0 () Bool)\n" in rendered
        assert b"(assert (= x1 (not x0)))\n" in rendered
        assert b"(get-value (x0 x1))\n" in rendered


def test_all_six_routes_execute_correctly_on_width4(tmp_path: Path) -> None:
    variant = _FRONTIER._BASE.VARIANTS["shake128"]
    audit = _FRONTIER._syntax_validation(variant, _z3(), tmp_path, False)
    rows = audit["results"]
    assert audit["all_six_syntactically_executable_and_correct"] is True
    assert [row["strategy"] for row in rows] == [route.name for route in _FRONTIER.STRATEGIES]
    assert all(row["status"] == "sat" for row in rows)
    assert all(row["return_code"] == 0 for row in rows)
    assert all(row["solver_invocation"]["diagnostics"] == [] for row in rows)
    assert all(row["complete_rate_gate"] is True for row in rows)
    assert all(row["independent_verification"]["rate_bits_checked"] == 1344 for row in rows)


def test_local_z3_exposes_every_declared_sat_parameter() -> None:
    audit = _FRONTIER._z3_parameter_audit(_z3())
    assert audit["all_required_parameters_present"] is True
    assert set(audit["required_parameter_entries"]) == {
        "branching.heuristic",
        "cut",
        "cut.xor",
        "cut.force",
    }
    assert audit["silently_dropped_parameters"] == []


def test_a138_hash_anchor_and_regenerated_width16_width20_formula_gates() -> None:
    payload = _FRONTIER._load_a138(_A138)
    assert hashlib.sha256(_A138.read_bytes()).hexdigest() == _FRONTIER.A138_SHA256
    variant = _FRONTIER._BASE.VARIANTS["shake128"]

    for width in (16, 20):
        retained = _FRONTIER._a138_trial(payload, width)
        assert retained["seed"] == _FRONTIER.WIDTH_SEEDS[width]
        assert (
            retained["encoding"]["first_smt_sha256"] == _FRONTIER.EXPECTED_FIRST_SMT_SHA256[width]
        )
        assert retained["encoding"]["first_smt_bytes"] == _FRONTIER.EXPECTED_FIRST_SMT_BYTES[width]
        formula = _FRONTIER._canonical_formula(
            variant,
            width,
            _FRONTIER.WIDTH_SEEDS[width],
            retained["encoding"]["first_smt_sha256"],
        )
        assert formula.sha256 == _FRONTIER.EXPECTED_FIRST_SMT_SHA256[width]
        assert len(formula.raw) == _FRONTIER.EXPECTED_FIRST_SMT_BYTES[width]

    anchor = _FRONTIER._retained_anchor(
        _FRONTIER._canonical_formula(
            variant,
            16,
            _FRONTIER.WIDTH_SEEDS[16],
            _FRONTIER.EXPECTED_FIRST_SMT_SHA256[16],
        ),
        _FRONTIER._a138_trial(payload, 16),
    )
    assert anchor["source"] == "A138_hash_gated_retained_measurement"
    assert anchor["executed_in_this_run"] is False
    assert anchor["status"] == "sat"
    assert anchor["assignment"] == 35837
    assert anchor["selection_metrics"]["decisions"] == 4701
    assert anchor["independent_verification"]["rate_bits_checked"] == 1344
    assert anchor["complete_rate_gate"] is True


def test_a138_hash_gate_rejects_any_byte_change(tmp_path: Path) -> None:
    changed = tmp_path / _A138.name
    changed.write_bytes(_A138.read_bytes() + b"\n")
    with pytest.raises(RuntimeError, match="hash differs"):
        _FRONTIER._load_a138(changed)


def test_selection_uses_decisions_then_conflicts_then_portfolio_order() -> None:
    by_decisions = [
        _eligible_row("first", 0, decisions=9, conflicts=1),
        _eligible_row("second", 1, decisions=3, conflicts=99),
        _eligible_row("missing", 2, decisions=None, conflicts=0),
    ]
    selected = _FRONTIER._select_strategy(by_decisions)
    assert selected["selected_strategy"] == "second"
    assert selected["selection_metric"] == "decisions"
    assert selected["selection_metric_value"] == 3

    by_conflicts = [
        _eligible_row("first", 0, decisions=None, conflicts=8),
        _eligible_row("second", 1, decisions=None, conflicts=2),
        _eligible_row("missing", 2, decisions=None, conflicts=None),
    ]
    selected = _FRONTIER._select_strategy(by_conflicts)
    assert selected["selected_strategy"] == "second"
    assert selected["selection_metric"] == "conflicts"
    assert selected["selection_metric_value"] == 2

    by_order = [
        _eligible_row("later", 4, decisions=None, conflicts=None),
        _eligible_row("earlier", 2, decisions=None, conflicts=None),
    ]
    selected = _FRONTIER._select_strategy(by_order)
    assert selected["selected_strategy"] == "earlier"
    assert selected["selection_metric"] == "portfolio_index"
    assert selected["selection_metric_value"] == 2

    tied = [
        _eligible_row("later", 3, decisions=5, conflicts=7),
        _eligible_row("earlier", 1, decisions=5, conflicts=7),
    ]
    assert _FRONTIER._select_strategy(tied)["selected_strategy"] == "earlier"


def test_selection_rejects_unverified_sat_models() -> None:
    rows = [_eligible_row("unverified", 0, decisions=1, conflicts=1, verified=False)]
    with pytest.raises(RuntimeError, match="no independently verified SAT"):
        _FRONTIER._select_strategy(rows)


def test_independent_verifier_checks_complete_1344_bit_rate() -> None:
    variant = _FRONTIER._BASE.VARIANTS["shake128"]
    formula = _FRONTIER._canonical_formula(variant, 4, _FRONTIER.SYNTAX_SEED)
    actual = _FRONTIER._WINDOW._extract_window(
        formula.problem["base_state"], variant, formula.problem["positions"]
    )
    accepted = _FRONTIER._verify_assignment(formula.problem, variant, actual)
    rejected = _FRONTIER._verify_assignment(formula.problem, variant, actual ^ 1)
    assert accepted["complete_rate_match"] is True
    assert accepted["rate_bits_checked"] == 1344
    assert accepted["rate_lanes_checked"] == 21
    assert accepted["candidate_rate_sha256"] == accepted["target_rate_sha256"]
    assert rejected["complete_rate_match"] is False
    assert rejected["candidate_rate_sha256"] != rejected["target_rate_sha256"]


def test_reader_graph_is_exact_neutral_three_triplet_provenance_chain(
    tmp_path: Path,
) -> None:
    path = tmp_path / "strategy-frontier.causal"
    _, emitted, gate = _FRONTIER._build_graph(
        path,
        _FRONTIER.EXPECTED_FIRST_SMT_SHA256[16],
        _FRONTIER.EXPECTED_FIRST_SMT_SHA256[20],
        "aig_sat",
        "decisions",
    )
    reader = CryptoCausalReader(path)
    rows = reader.triplets(include_inferred=False)
    assert emitted == rows
    assert reader.verify_provenance()
    assert gate["passed"] is True
    assert gate["explicit_triplet_count"] == 3
    assert gate["exact_three_edge_chain"] is True
    assert len(rows) == 3
    by_id = {row["edge_id"]: row for row in rows}
    formula_id = "r1-hash-gated-identical-formulas"
    portfolio_id = "r1-predeclared-z3-strategy-portfolio"
    transfer_id = "r1-selected-strategy-width20-followup"
    assert set(by_id) == {formula_id, portfolio_id, transfer_id}
    assert by_id[portfolio_id]["provenance"] == [formula_id]
    assert by_id[transfer_id]["provenance"] == [portfolio_id]
    assert by_id[formula_id]["outcome"] == by_id[portfolio_id]["trigger"]
    assert by_id[portfolio_id]["outcome"] == by_id[transfer_id]["trigger"]
    assert by_id[transfer_id]["outcome"].endswith("followup_observation")

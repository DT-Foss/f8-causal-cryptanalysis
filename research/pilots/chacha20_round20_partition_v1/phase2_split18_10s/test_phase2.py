from __future__ import annotations

import importlib.util
import json
from pathlib import Path


PHASE2_DIR = Path(__file__).resolve().parent
RUNNER_PATH = PHASE2_DIR / "runner.py"
SPEC = importlib.util.spec_from_file_location("chacha20_round20_phase2", RUNNER_PATH)
assert SPEC is not None and SPEC.loader is not None
PHASE2 = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(PHASE2)


def test_phase2_is_single_factor_complete_cut_frontier() -> None:
    analysis = PHASE2.analyze()
    config = analysis["config"]
    plan = analysis["formula_plan"]
    assert analysis["solver_execution_started"] is False
    assert config["information_boundary"]["only_changed_factor_from_phase1"] == "split19_to_split18"
    assert config["information_boundary"]["secret_prefix_used_for_cell_selection"] is False
    assert config["information_boundary"]["all_thirty_two_cells_required"] is True
    assert len(analysis["formulas"]) == 32
    assert len(plan["rows"]) == 32
    assert plan["complete_domain_candidate_count"] == 1 << 20
    assert all(row["candidate_count"] == 1 << 15 for row in plan["rows"])
    assert all(row["split"] == 18 for row in plan["rows"])
    assert [row["prefix"] for row in plan["rows"]] == [f"{value:05b}" for value in range(32)]


def test_split18_dag_and_phase1_gate() -> None:
    analysis = PHASE2.analyze()
    formula = analysis["formulas"]["prefix_00000"]
    assert "(define-fun v639 " in formula
    assert "(define-fun v640 " not in formula
    assert analysis["phase1"]["phase1_status_counts"] == {
        "sat": 0,
        "unsat": 0,
        "unknown": 32,
        "invalid": 0,
        "external_timeout": 0,
    }
    assert analysis["phase1"]["phase1_causal_provenance_verified"] is True


def test_phase2_result_and_causal_if_present() -> None:
    if not PHASE2.RESULT_PATH.exists():
        return
    payload = json.loads(PHASE2.RESULT_PATH.read_bytes())
    assert payload["phase_id"] == PHASE2.PHASE_ID
    assert payload["parameters"]["rounds"] == 20
    assert payload["parameters"]["split"] == 18
    assert payload["execution"]["complete_variant_plan_executed"] is True
    assert payload["execution"]["early_stop_used"] is False
    assert len(payload["execution"]["observations"]) == 32
    assert payload["comparisons"]["only_changed_factor"] == "split19_to_split18"
    assert payload["comparisons"]["complete_domain_candidate_count"] == 1 << 20
    assert payload["comparisons"]["uniqueness_established"] is False
    for confirmation in payload["confirmations"]:
        assert confirmation["all_blocks_match"] is True
        assert confirmation["control_first_block_match"] is False
        assert confirmation["output_bits_checked"] == 4096
    reader = PHASE2.P1.CryptoCausalReader(PHASE2.CAUSAL_PATH)
    assert reader.file_sha256 == payload["causal"]["file_sha256"]
    assert reader.graph_sha256 == payload["causal"]["graph_sha256"]
    assert reader.verify_provenance()

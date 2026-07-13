from __future__ import annotations

import hashlib
import importlib.util
import json
import sys
from pathlib import Path

import pytest

from arx_carry_leak.crypto_causal import CryptoCausalReader
from arx_carry_leak.exact_cnf import ExactCNF, literal_node, node_literal


ROOT = Path(__file__).parents[1]
RUNNER = ROOT / "research" / "experiments" / "chacha20_round20_causal_pcr_backprojection.py"


def _load_runner():
    spec = importlib.util.spec_from_file_location("test_a213_runner", RUNNER)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def test_exact_cnf_chain_and_clause_provenance() -> None:
    cnf = ExactCNF.from_dimacs(
        b"p cnf 4 4\n1 0\n-1 2 0\n-2 3 0\n-3 4 0\n"
    )
    state = cnf.propagate()
    assert not state.conflicted
    assert state.assignment.tolist() == [0, 1, 1, 1, 1]
    assert cnf.explain_literal(state, 4) == (0, 1, 2, 3)
    assert cnf.residual_binary_clauses(state) == []


def test_exact_cnf_assumption_conflict_retains_base_reason() -> None:
    cnf = ExactCNF.from_dimacs(b"p cnf 2 2\n1 0\n-1 2 0\n")
    base = cnf.propagate()
    state = cnf.propagate([-2], base=base)
    assert state.conflicted
    assert cnf.explain_conflict(state) == (0, 1)


def test_exact_cnf_rejects_duplicate_and_tautological_clauses() -> None:
    with pytest.raises(ValueError, match="duplicate"):
        ExactCNF.from_dimacs(b"p cnf 2 1\n1 1 0\n")
    with pytest.raises(ValueError, match="tautological"):
        ExactCNF.from_dimacs(b"p cnf 2 1\n1 -1 0\n")


def test_literal_node_roundtrip() -> None:
    for literal in (-17, -1, 1, 17):
        assert node_literal(literal_node(literal)) == literal


def test_a213_frozen_protocol_and_runner_hashes() -> None:
    runner = _load_runner()
    protocol_path = ROOT / "research" / "configs" / runner.PROTOCOL_FILENAME
    assert hashlib.sha256(protocol_path.read_bytes()).hexdigest() == runner.PROTOCOL_SHA256
    protocol = runner._load_protocol()
    assert protocol["attempt_id"] == "A213"
    assert len(protocol["exact_views"]) == 5
    assert protocol["information_boundary"][
        "R20_status_or_model_or_correct_cell_read_before_this_freeze"
    ] is False
    assert hashlib.sha256(runner.R20_RUNNER.read_bytes()).hexdigest() == runner.R20_RUNNER_SHA256


def test_a213_saved_result_if_present() -> None:
    result_path = (
        ROOT
        / "research"
        / "results"
        / "v1"
        / "chacha20_round20_causal_pcr_backprojection_v1.json"
    )
    causal_path = result_path.with_suffix(".causal")
    if not result_path.exists():
        pytest.skip("A213 full result not generated in this checkout")
    payload = json.loads(result_path.read_bytes())
    assert payload["schema"] == "chacha20-round20-causal-pcr-backprojection-v1"
    assert [row["view"] for row in payload["views"]] == [
        "V1_base_unit_closure",
        "V2_single_literal_backprojection",
        "V3_pair_literal_backprojection",
        "V4_binary_implication_closure",
        "V5_exact_domain_overlay",
    ]
    assert payload["views"][2]["probe_count"] == 760
    assert payload["views"][4]["surviving_candidate_count"] > 0
    assert payload["views"][4]["independence_probability_multiplication_used"] is False
    reader = CryptoCausalReader(causal_path)
    assert reader.verify_provenance()
    assert reader.graph_sha256 == payload["causal_artifact"]["graph_sha256"]

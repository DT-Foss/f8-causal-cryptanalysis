from __future__ import annotations

import numpy as np

from arx_carry_leak.cnf_semantic_topology import (
    CNFSemanticTopology,
    build_topology_clause_table,
    topology_manifest,
)
from arx_carry_leak.learned_clause_reader import HORIZONS, fit_learned_clause_poe


def _topology() -> CNFSemanticTopology:
    # Variables 3 and 4 are structural twins at distance one from the same
    # anchor group. Variables 5..12 are candidate-assumption variables.
    raw = b"p cnf 12 4\n1 3 0\n2 3 0\n1 4 0\n2 4 0\n"
    return CNFSemanticTopology.from_dimacs(
        raw,
        anchor_groups={"public_output": [1, 2], "key_suffix": [3, 4]},
        maximum_distance=4,
    )


def _measurement(label: str, true_prefix: int, signal_variable: int) -> dict:
    stages = []
    for candidate in range(256):
        assumptions = [
            variable if (candidate >> bit) & 1 else -variable
            for bit, variable in enumerate(range(5, 13))
        ]
        for horizon in HORIZONS:
            stages.append(
                {
                    "prefix8": f"{candidate:08b}",
                    "horizon": horizon,
                    "assumptions": assumptions,
                    "learned_clauses_stage": (
                        [[signal_variable, assumptions[0]]]
                        if candidate == true_prefix
                        else [assumptions]
                    ),
                }
            )
    return {
        "label": label,
        "known_key_design": {"prefix8": true_prefix},
        "run": {
            "learned_clause_identity_complete": True,
            "bounded_variable_addition_enabled": False,
            "stages": stages,
        },
    }


def test_public_cnf_distances_and_twin_signatures_are_exact() -> None:
    topology = _topology()
    assert int(topology.anchor_distances["public_output"][1]) == 0
    assert int(topology.anchor_distances["public_output"][3]) == 1
    assert topology.variable_signature(3) == topology.variable_signature(4)
    manifest = topology_manifest(topology)
    assert manifest["variable_count"] == 12
    assert manifest["clause_count"] == 4
    assert manifest["finite"] is True


def test_topology_reader_transfers_across_different_exact_variable_ids() -> None:
    topology = _topology()
    training = [
        build_topology_clause_table(
            _measurement(f"train_{index}", 30 + index, 3), topology
        )
        for index in range(4)
    ]
    model = fit_learned_clause_poe(
        training,
        minimum_positive_support=2,
        beta_smoothing=1.0,
        token_log_odds_cap=4.0,
    )
    holdout = build_topology_clause_table(
        _measurement("holdout", 211, 4), topology
    )
    scores = model.scores(holdout)
    assert int(np.argmax(scores)) == 211
    assert scores[211] > np.max(np.delete(scores, 211))


def test_candidate_assumption_only_clauses_leave_no_semantic_tokens() -> None:
    topology = _topology()
    measurement = _measurement("assumptions_only", 77, 3)
    for stage in measurement["run"]["stages"]:
        stage["learned_clauses_stage"] = [stage["assumptions"]]
    table = build_topology_clause_table(measurement, topology)
    assert all(not tokens for tokens in table.candidate_tokens)

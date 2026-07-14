from __future__ import annotations

import numpy as np
import pytest

from arx_carry_leak.learned_clause_reader import (
    HORIZONS,
    ClauseIdentityTable,
    build_clause_identity_table,
    fit_learned_clause_poe,
)


def _measurement(label: str, true_prefix: int, signal_variable: int) -> dict:
    stages = []
    for candidate in range(256):
        for horizon in HORIZONS:
            clauses = [[-17, signal_variable]] if candidate == true_prefix else [[-17, 300 + candidate]]
            stages.append(
                {
                    "prefix8": f"{candidate:08b}",
                    "horizon": horizon,
                    "assumptions": [
                        variable if (candidate >> bit) & 1 else -variable
                        for bit, variable in enumerate(range(1, 9))
                    ],
                    "learned_clauses_stage": clauses,
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


def test_clause_identity_reader_transfers_exact_variable_signature() -> None:
    tables = [
        build_clause_identity_table(_measurement(f"train_{index}", 10 + index, 99))
        for index in range(5)
    ]
    model = fit_learned_clause_poe(
        tables,
        minimum_positive_support=2,
        beta_smoothing=1.0,
        token_log_odds_cap=4.0,
    )
    holdout = build_clause_identity_table(_measurement("holdout", 211, 99))
    scores = model.scores(holdout)
    assert int(np.argmax(scores)) == 211
    assert len(model.token_weights) > 0
    assert all("prefix" not in token and "candidate" not in token for token in model.token_weights)


def test_clause_identity_tokenization_is_deterministic() -> None:
    measurement = _measurement("same", 37, 99)
    assert build_clause_identity_table(measurement) == build_clause_identity_table(measurement)


def test_clause_identity_reader_projects_out_candidate_assumption_literals() -> None:
    measurement = _measurement("projected", 37, 99)
    for stage in measurement["run"]["stages"]:
        stage["learned_clauses_stage"] = [list(stage["assumptions"])]
    table = build_clause_identity_table(measurement)
    assert all(not tokens for tokens in table.candidate_tokens)


@pytest.mark.parametrize(
    ("support", "smoothing", "cap"),
    [(0, 1.0, 1.0), (2, 0.0, 1.0), (2, 1.0, 0.0)],
)
def test_clause_identity_reader_rejects_invalid_settings(
    support: int, smoothing: float, cap: float
) -> None:
    tables = [
        ClauseIdentityTable("a", 0, tuple(range(256)), tuple(frozenset() for _ in range(256))),
        ClauseIdentityTable("b", 1, tuple(range(256)), tuple(frozenset() for _ in range(256))),
    ]
    with pytest.raises(ValueError):
        fit_learned_clause_poe(
            tables,
            minimum_positive_support=support,
            beta_smoothing=smoothing,
            token_log_odds_cap=cap,
        )

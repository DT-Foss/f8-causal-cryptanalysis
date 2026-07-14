from __future__ import annotations

import numpy as np

from arx_carry_leak.chacha20_clause_frequency import (
    FEATURE_FAMILIES,
    HORIZONS,
    build_clause_frequency_table,
)


def _measurement() -> dict[str, object]:
    assumptions = list(range(90001, 90009))
    stages = []
    for candidate in range(256):
        for horizon in HORIZONS:
            repeats = candidate % 3 + 1
            clauses = [
                [assumptions[0], 100 + horizon, -(200 + candidate % 5)]
                for _ in range(repeats)
            ]
            stages.append(
                {
                    "prefix8": f"{candidate:08b}",
                    "horizon": horizon,
                    "assumptions": [
                        value if candidate & (1 << bit) else -value
                        for bit, value in enumerate(assumptions)
                    ],
                    "learned_clauses_stage": clauses,
                }
            )
    return {
        "label": "synthetic_p00_fit_s00",
        "known_key_design": {"prefix8": 17},
        "run": {
            "learned_clause_identity_complete": True,
            "bounded_variable_addition_enabled": False,
            "stages": stages,
        },
    }


def test_clause_frequency_retains_multiplicity_and_projects_assumptions() -> None:
    table, ledger = build_clause_frequency_table(_measurement())
    assert table.label == "synthetic_p00_fit_s00"
    assert table.true_prefix == 17
    assert ledger["assumption_variables_projected_before_counting"] is True
    assert ledger["true_prefix_used_during_frequency_or_feature_retention"] is False
    assert ledger["retained_varying_feature_count"] > 0
    feature = "all_unsigned_variable|101"
    assert feature in table.feature_counts
    assert np.array_equal(
        table.feature_counts[feature][:6],
        np.asarray([1, 2, 3, 1, 2, 3], dtype=np.int32),
    )
    joined = "\n".join(table.feature_counts)
    assert "90001" not in joined
    assert set(ledger["retained_feature_families"]).issubset(FEATURE_FAMILIES)


def test_clause_frequency_feature_retention_is_target_blind() -> None:
    first, first_ledger = build_clause_frequency_table(_measurement())
    changed = _measurement()
    changed["known_key_design"]["prefix8"] = 211  # type: ignore[index]
    second, second_ledger = build_clause_frequency_table(changed)
    assert first.feature_counts.keys() == second.feature_counts.keys()
    for feature in first.feature_counts:
        assert np.array_equal(
            first.feature_counts[feature], second.feature_counts[feature]
        )
    assert first_ledger["feature_ledger_sha256"] == second_ledger[
        "feature_ledger_sha256"
    ]

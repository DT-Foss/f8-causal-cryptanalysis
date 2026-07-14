from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import numpy as np

from arx_carry_leak.learned_clause_reader import fit_learned_clause_poe

ROOT = Path(__file__).parents[1]
SCRIPT = ROOT / "research/experiments/chacha20_round20_fresh_clause_identity_reader.py"


def _load():
    name = "a251_clause_identity_reader_test"
    spec = importlib.util.spec_from_file_location(name, SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _synthetic_tables(module):
    prefixes = [85, 106, 200, 159, 36]
    tables = []
    for group, true_prefix in enumerate(prefixes):
        for suffix in range(4):
            documents = []
            for candidate in range(256):
                if candidate == true_prefix:
                    tokens = {
                        "all_signed_variable|99",
                        "all_pair|99|123",
                        f"stage_unsigned_variable|h2|{700 + suffix}",
                    }
                else:
                    tokens = {f"all_signed_variable|{10000 + group * 256 + candidate}"}
                documents.append(frozenset(tokens))
            tables.append(
                module.ClauseIdentityTable(
                    label=f"a220_select_p{group:02d}_fit_s{suffix:02d}",
                    true_prefix=true_prefix,
                    candidates=tuple(range(256)),
                    candidate_tokens=tuple(documents),
                )
            )
    return tables


def test_A251_protocol_is_frozen_before_R20_clause_measurement() -> None:
    module = _load()
    analysis = module.analyze()
    assert analysis["attempt_id"] == "A251"
    assert analysis["known_key_count"] == 20
    assert analysis["candidate_measurements"] == 5120
    assert analysis["operator_settings"] == 27
    assert analysis["R20_clause_identity_measurement_started"] is False


def test_nested_clause_reader_recovers_transferable_exact_identity() -> None:
    module = _load()
    evaluation = module.nested_evaluate(
        _synthetic_tables(module),
        supports=[2],
        smoothings=[1.0],
        caps=[2.0],
    )
    assert evaluation["mean_log2_rank"] == 0.0
    assert evaluation["exact_shared_xor_p"] == 1.0 / 256.0
    assert evaluation["outer_prefix_folds_with_positive_bit_gain"] == 5
    assert all(
        fold["model"]["retained_token_count"] > 0
        for fold in evaluation["outer_folds"]
    )


def test_cached_fit_and_scores_are_exactly_equal_to_reference_reader() -> None:
    module = _load()
    tables = _synthetic_tables(module)[:8]
    reference = fit_learned_clause_poe(
        tables,
        minimum_positive_support=2,
        beta_smoothing=1.0,
        token_log_odds_cap=2.0,
    )
    caches = [module._cache_table(table) for table in tables]
    cached = module._fit_cached_clause_poe(
        caches,
        minimum_positive_support=2,
        beta_smoothing=1.0,
        token_log_odds_cap=2.0,
    )
    assert cached.as_dict() == reference.as_dict()
    for table, cache in zip(tables, caches, strict=True):
        np.testing.assert_array_equal(module._cached_scores(cached, cache), cached.scores(table))


def test_order_view_removes_only_volatile_traversal_fields() -> None:
    module = _load()

    def measurement(mode: str, cell_index: int, elapsed: float) -> dict:
        return {
            "run": {
                "stages": [
                    {
                        "mode": mode,
                        "cell_index": cell_index,
                        "elapsed_seconds": elapsed,
                        "prefix8": "00000001",
                        "horizon": 1,
                        "learned_clauses_stage": [[-7, 11]],
                    }
                ],
                "cells": [
                    {
                        "mode": mode,
                        "cell_index": cell_index,
                        "prefix8": "00000001",
                        "learned_clause_accepted_total": 1,
                    }
                ],
                "summary": {
                    "mode": mode,
                    "cells": 256,
                    "learned_clause_accepted_total": 1,
                },
            }
        }

    assert module._stable_order_view(measurement("numeric", 0, 0.1)) == module._stable_order_view(
        measurement("reverse", 255, 0.9)
    )

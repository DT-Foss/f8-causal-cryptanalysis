from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import numpy as np

from arx_carry_leak.fresh_candidate_reader import CandidateFeatureTable, FEATURE_NAMES

ROOT = Path(__file__).parents[1]
SOURCE = ROOT / "research/experiments/chacha20_round20_fresh_multichannel_reader.py"


def _module():
    spec = importlib.util.spec_from_file_location("a249_reader_test", SOURCE)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _tables() -> list[CandidateFeatureTable]:
    result = []
    prefixes = [85, 106, 200, 159, 36]
    for prefix_index, true_prefix in enumerate(prefixes):
        for suffix_index in range(4):
            matrix = np.zeros((256, len(FEATURE_NAMES)), dtype=np.float64)
            matrix[:, 1] = np.linspace(-1.0, 1.0, 256)
            matrix[true_prefix, 0] = 4.0 + suffix_index * 0.01
            result.append(
                CandidateFeatureTable(
                    label=f"a220_select_p{prefix_index:02d}_fit_s{suffix_index:02d}",
                    true_prefix=true_prefix,
                    candidates=tuple(range(256)),
                    feature_names=FEATURE_NAMES,
                    matrix=matrix,
                )
            )
    return result


def test_analyze_verifies_frozen_feature_and_model_contract() -> None:
    module = _module()
    result = module.analyze()
    assert result == {
        "attempt_id": "A249",
        "protocol_sha256": module.PROTOCOL_SHA256,
        "feature_count": 144,
        "outer_prefix_folds": 5,
        "model_fit_started": False,
    }


def test_nested_evaluation_never_trains_on_outer_prefix_and_recovers_signal() -> None:
    module = _module()
    result = module.nested_evaluate(_tables(), [0.1])
    assert len(result["outer_folds"]) == 5
    assert len(result["outer_holdout_rows"]) == 20
    assert result["mean_log2_rank"] == 0.0
    assert result["mean_log2_rank_bit_gain"] > 6.0
    assert result["exact_shared_xor_p"] == 1 / 256
    assert result["best_shared_xor_offset"] == 0
    assert result["outer_prefix_folds_with_positive_bit_gain"] == 5
    for fold in result["outer_folds"]:
        assert fold["selected_ridge_lambda"] == 0.1
        assert {row["prefix_index"] for row in fold["test_rows"]} == {
            fold["outer_prefix_index"]
        }
        assert all(row["midrank"] == 1.0 for row in fold["test_rows"])


def test_prefix_index_parser_rejects_nonvalidation_labels() -> None:
    module = _module()
    assert module._prefix_index("a220_select_p04_fit_s03") == 4

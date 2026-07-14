from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import numpy as np

from arx_carry_leak.fresh_candidate_reader import FEATURE_NAMES, CandidateFeatureTable

ROOT = Path(__file__).parents[1]
SCRIPT = ROOT / "research/experiments/chacha20_round20_fresh_nonlinear_poe.py"


def _load_runner():
    spec = importlib.util.spec_from_file_location("a250_runner_test", SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _table(prefix_index: int, suffix_index: int, true_prefix: int) -> CandidateFeatureTable:
    candidate = np.arange(256, dtype=np.float64)
    matrix = np.empty((256, len(FEATURE_NAMES)), dtype=np.float64)
    for column in range(len(FEATURE_NAMES)):
        parity = np.where((np.arange(256) & (1 << (column % 8))) == 0, -1.0, 1.0)
        matrix[:, column] = parity * (1.5 + 0.01 * (column % 11)) + candidate * 1e-4
    matrix[true_prefix] = 0.01 * suffix_index
    return CandidateFeatureTable(
        label=f"a220_select_p{prefix_index:02d}_fit_s{suffix_index:02d}",
        true_prefix=true_prefix,
        candidates=tuple(range(256)),
        feature_names=FEATURE_NAMES,
        matrix=matrix,
    )


def test_a250_protocol_is_frozen_before_fit() -> None:
    runner = _load_runner()
    summary = runner.analyze()
    assert summary == {
        "attempt_id": "A250",
        "protocol_sha256": runner.PROTOCOL_SHA256,
        "operator_settings": 20,
        "outer_prefix_folds": 5,
        "model_fit_started": False,
    }


def test_a250_nested_reader_finds_coordinate_free_band_signal() -> None:
    runner = _load_runner()
    prefixes = [85, 106, 200, 159, 36]
    tables = [
        _table(prefix_index, suffix_index, prefix)
        for prefix_index, prefix in enumerate(prefixes)
        for suffix_index in range(4)
    ]
    result = runner.nested_evaluate(
        tables,
        shrinkages=[0.25, 0.5],
        caps=[0.5, 1.0],
    )
    assert result["mean_log2_rank"] == 0.0
    assert result["mean_log2_rank_bit_gain"] > 6.5
    assert result["outer_prefix_folds_with_positive_bit_gain"] == 5
    assert result["best_shared_xor_offset"] == 0
    assert result["exact_shared_xor_p"] == 1 / 256

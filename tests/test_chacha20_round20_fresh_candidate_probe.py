from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

ROOT = Path(__file__).parents[1]
SOURCE = ROOT / "research/experiments/chacha20_round20_fresh_candidate_probe.py"


def _module():
    spec = importlib.util.spec_from_file_location("a242_probe_test", SOURCE)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _measurement(label: str, true_prefix: int) -> dict:
    return {
        "label": label,
        "known_key_design": {"prefix8": true_prefix},
        "run": {
            "stages": [
                {
                    "prefix8": f"{candidate:08b}",
                    "horizon": 2,
                    "metrics_cell_cumulative_delta": [2, 10, 256 - (candidate ^ true_prefix)],
                }
                for candidate in range(256)
            ]
        },
    }


def test_analyze_reopens_frozen_protocol_and_anchors() -> None:
    module = _module()
    result = module.analyze()
    assert result["attempt_id"] == "A242"
    assert result["solver_execution_started"] is False
    assert len(result["validation_labels"]) == 20
    assert len(set(result["validation_labels"])) == 20


def test_midrank_handles_ties_in_both_directions() -> None:
    module = _module()
    values = {0: 3, 1: 8, 2: 8, 3: 1}
    assert module._midrank(values, 1, higher=True) == 1.5
    assert module._midrank(values, 1, higher=False) == 3.5
    assert module._midrank(values, 0, higher=True) == 3.0


def test_exact_shared_xor_control_identifies_true_offset() -> None:
    module = _module()
    measurements = [
        _measurement("k0", 0x11),
        _measurement("k1", 0xA7),
        _measurement("k2", 0x5C),
    ]
    result = module._rank_analysis(
        measurements,
        horizon=2,
        metric="search_propagations",
        higher=True,
    )
    assert result["mean_log2_rank"] == 0.0
    assert result["best_shared_xor_offset"] == 0
    assert result["exact_shared_xor_p"] == 1 / 256
    assert result["mean_log2_rank_bit_gain"] > 6.0
    assert all(row["midrank"] == 1.0 for row in result["per_key"])


def test_order_view_discards_only_volatile_and_positional_fields() -> None:
    module = _module()
    forward = {
        "run": {
            "stages": [
                {"prefix8": "00000001", "horizon": 2, "mode": "f", "cell_index": 0, "elapsed_seconds": 1.2, "value": 7},
                {"prefix8": "00000000", "horizon": 2, "mode": "f", "cell_index": 1, "elapsed_seconds": 1.3, "value": 9},
            ],
            "cells": [
                {"prefix8": "00000001", "mode": "f", "cell_index": 0, "value": 3},
                {"prefix8": "00000000", "mode": "f", "cell_index": 1, "value": 4},
            ],
        }
    }
    reverse = {
        "run": {
            "stages": [
                {"prefix8": "00000000", "horizon": 2, "mode": "r", "cell_index": 0, "elapsed_seconds": 9.2, "value": 9},
                {"prefix8": "00000001", "horizon": 2, "mode": "r", "cell_index": 1, "elapsed_seconds": 9.3, "value": 7},
            ],
            "cells": [
                {"prefix8": "00000000", "mode": "r", "cell_index": 0, "value": 4},
                {"prefix8": "00000001", "mode": "r", "cell_index": 1, "value": 3},
            ],
        }
    }
    assert module._stable_order_view(forward) == module._stable_order_view(reverse)

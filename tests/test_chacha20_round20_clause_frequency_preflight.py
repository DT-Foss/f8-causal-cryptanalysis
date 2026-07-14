from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

ROOT = Path(__file__).parents[1]
RUNNER = ROOT / "research/experiments/chacha20_round20_clause_frequency_preflight.py"


def _load_runner():
    spec = importlib.util.spec_from_file_location("a266_preflight", RUNNER)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def test_a266_preflight_uses_only_synthetic_evidence() -> None:
    payload = _load_runner().build_preflight()
    assert payload["synthetic_nested_transfer"]["mean_log2_rank"] == 0.0
    assert payload["synthetic_nested_transfer"]["positive_outer_prefix_folds"] == 5
    assert payload["synthetic_nested_transfer"]["exact_shared_xor_p"] == 1.0 / 256.0
    assert payload["information_boundary"] == {
        "used_any_A251_measurement_shard": False,
        "used_any_R20_learned_clause_or_candidate_value": False,
        "used_any_A251_true_prefix": False,
        "used_only_synthetic_clause_payloads_and_synthetic_transfer_tables": True,
        "any_A266_operator_outcome_known": False,
    }

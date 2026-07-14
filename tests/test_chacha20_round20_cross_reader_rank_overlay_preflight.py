from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

ROOT = Path(__file__).parents[1]
SOURCE = (
    ROOT
    / "research/experiments/chacha20_round20_cross_reader_rank_overlay_preflight.py"
)


def _load() -> object:
    spec = importlib.util.spec_from_file_location("a265_preflight_test_module", SOURCE)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


MODULE = _load()


def test_a265_reader_family_is_complete_and_fixed() -> None:
    assert MODULE.ATTEMPT_ID == "A265"
    assert list(MODULE.READER_RESULTS) == [
        "A249_multichannel_linear",
        "A250_nonlinear_poe",
        "A251_exact_clause_identity",
        "A259_public_cnf_topology",
        "A260_exact_operation_topology",
        "A261_directed_flow_tokens",
        "A262_continuous_flow",
    ]
    assert 3 ** len(MODULE.READER_RESULTS) - 1 == 2186

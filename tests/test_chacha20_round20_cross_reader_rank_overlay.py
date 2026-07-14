from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

ROOT = Path(__file__).parents[1]
RUNNER = (
    ROOT
    / "research/experiments/chacha20_round20_cross_reader_rank_overlay.py"
)


def _load_runner():
    spec = importlib.util.spec_from_file_location("a265_overlay", RUNNER)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def test_a265_frozen_protocol_and_preflight_are_replayable() -> None:
    module = _load_runner()
    summary = module.analyze()
    assert summary == {
        "attempt_id": "A265",
        "protocol_sha256": module.PROTOCOL_SHA256,
        "reader_count": 7,
        "known_key_count": 20,
        "complete_mode_count": 2186,
        "shared_xor_offsets": 256,
        "new_solver_measurements_permitted": False,
        "cross_reader_score_combination_started": False,
    }
    protocol = json.loads(module.PROTOCOL.read_bytes())
    assert protocol["information_boundary"][
        "any_cross_reader_scores_combined_before_protocol_freeze"
    ] is False
    assert protocol["evaluation"]["shared_xor_offsets"] == 256


def test_a265_reconstructed_corpus_matches_frozen_geometry() -> None:
    module = _load_runner()
    protocol, preflight = module._load_protocol()
    corpus, ledger = module._load_corpus(protocol, preflight)
    assert corpus.rank_scores.shape == (20, 7, 256)
    assert len(ledger) == 7
    assert tuple(ledger_row["reader_id"] for ledger_row in ledger) == tuple(
        protocol["input"]["required_reader_ids"]
    )

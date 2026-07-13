from __future__ import annotations

import importlib.util
from pathlib import Path


ROOT = Path(__file__).parents[1]
HELPER = ROOT / "research" / "experiments" / "chacha20_round20_knownkey_atlas_helpers.py"


def _load():
    spec = importlib.util.spec_from_file_location("test_a214_helpers", HELPER)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_atlas_ledger_matches_frozen_hash() -> None:
    helper = _load()
    rows = helper.atlas_ledger()
    assert len(rows) == 24
    assert len({row["low20"] for row in rows}) == 24
    assert helper.atlas_ledger_sha256(rows) == (
        "b0b1add2b4185c0b7a5ef02397ed54d3e504a19866a833601382e725adbdc91f"
    )


def test_training_challenge_does_not_store_low20() -> None:
    helper = _load()
    public = {
        "known_key_word0_upper12": 0xABC00000,
        "known_key_words_1_through_7": [1, 2, 3, 4, 5, 6, 7],
        "counter_start": 9,
        "nonce_words": [10, 11, 12],
        "block_count": 2,
    }

    def block(**kwargs):
        seed = kwargs["key_words"][0] ^ kwargs["counter"]
        return [(seed + index) & 0xFFFFFFFF for index in range(16)]

    challenge = helper.training_challenge(public, low20=0x12345, chacha_block=block)
    assert len(challenge["target_words"]) == 2
    assert challenge["control_target_words"][0] == challenge["target_words"][0][0] ^ 1
    assert not any("low20" in key for key in challenge)

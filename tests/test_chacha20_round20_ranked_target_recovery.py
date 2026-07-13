from __future__ import annotations

import hashlib
import importlib.util
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

from arx_carry_leak.chacha_trace import trace_chacha20_block_words

ROOT = Path(__file__).parents[1]
SOURCE = ROOT / "research/experiments/chacha20_round20_ranked_target_recovery.py"


def _module():
    spec = importlib.util.spec_from_file_location("a219_recovery_test", SOURCE)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def test_decode_model_uses_bit0_through_bit19_order() -> None:
    module = _module()
    bits = [0] * 20
    bits[0] = 1
    bits[7] = 1
    bits[19] = 1
    assert module._decode_model(bits) == (1 | (1 << 7) | (1 << 19))
    with pytest.raises(RuntimeError):
        module._decode_model([0] * 19)


@pytest.mark.parametrize(
    ("attempted", "confirmation", "expected"),
    [
        (
            1,
            {"all_blocks_match": True},
            "FULLROUND_R20_TARGET_BLIND_TOP16_RECOVERY_CONFIRMED_WITH_READER_BOUNDARY",
        ),
        (
            64,
            {"all_blocks_match": True},
            "FULLROUND_R20_TARGET_BLIND_TOP64_RECOVERY_CONFIRMED_WITH_READER_BOUNDARY",
        ),
        (
            65,
            {"all_blocks_match": True},
            "FULLROUND_R20_TARGET_BLIND_COMPLETE_ORDER_RECOVERY_CONFIRMED_WITH_READER_BOUNDARY",
        ),
        (
            256,
            None,
            "FULLROUND_R20_TARGET_BLIND_COMPLETE_ORDER_SOLVER_BOUNDARY_RETAINED",
        ),
    ],
)
def test_evidence_stage_keeps_reader_boundary_explicit(
    attempted: int, confirmation: dict[str, bool] | None, expected: str
) -> None:
    module = _module()
    assert module._evidence_stage(confirmation=confirmation, attempted=attempted) == expected


def test_scientific_execution_excludes_wall_time() -> None:
    module = _module()
    execution = {
        "mode": "test",
        "order": [f"{value:08b}" for value in range(256)],
        "seconds_budget_per_cell": 10.0,
        "max_cells": 1,
        "rows": [
            {
                "prefix8": "00000000",
                "elapsed_seconds": 9.9,
                "metrics_delta": [1, 2, 3],
            }
        ],
        "summary": {"attempted_cells": 1},
        "sat_found": False,
        "retained_state_continuity_verified": True,
    }
    scientific = module._scientific_execution(execution)
    assert "elapsed_seconds" not in scientific["rows"][0]
    assert scientific["rows"][0]["metrics_delta"] == [1, 2, 3]


def test_sat_confirmation_requires_two_implementations_across_eight_blocks() -> None:
    module = _module()

    class TraceP1:
        @staticmethod
        def _chacha_block(*, key_words, counter, nonce_words, rounds):
            return list(
                trace_chacha20_block_words(
                    key_words=key_words,
                    counter=counter,
                    nonce_words=nonce_words,
                    rounds=rounds,
                ).block_state
            )

        @staticmethod
        def _word_bytes(words):
            return b"".join(int(word).to_bytes(4, "little") for word in words)

    low20 = 0x5A19C
    known_upper12 = 0xAC300000
    key_words = [
        known_upper12 | low20,
        0x01020304,
        0x11223344,
        0x55667788,
        0xDEADBEEF,
        0xA5A5A5A5,
        0x12345678,
        0xCAFEBABE,
    ]
    nonce_words = [0x09000000, 0x4A000000, 0]
    counter_start = 0xFFFFFFFC
    target_words = [
        list(
            trace_chacha20_block_words(
                key_words=key_words,
                counter=(counter_start + index) & 0xFFFFFFFF,
                nonce_words=nonce_words,
            ).block_state
        )
        for index in range(8)
    ]
    control = target_words[0].copy()
    control[0] ^= 1
    control_hash = hashlib.sha256(TraceP1._word_bytes(control)).hexdigest()
    challenge = {
        "known_key_word0_upper12": known_upper12,
        "known_key_words_1_through_7": key_words[1:],
        "counter_start": counter_start,
        "nonce_words": nonce_words,
        "block_count": 8,
        "target_words": target_words,
        "control_target_block_sha256": control_hash,
    }

    confirmation = module._confirm(SimpleNamespace(P1=TraceP1), challenge, low20)
    assert confirmation["claim_gate_rfc8439_section_2_3_2_kat"] is True
    assert len(confirmation["claim_gate_source_sha256"]) == 64
    assert confirmation["all_cross_implementation_blocks_match"] is True
    assert confirmation["cross_implementation_block_matches"] == [True] * 8
    assert confirmation["claim_gate_block_matches"] == [True] * 8
    assert confirmation["all_blocks_match"] is True
    assert confirmation["control_first_block_match"] is False
    assert confirmation["output_bits_checked"] == 4096

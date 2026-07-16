from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

from arx_carry_leak.chacha20_rfc8439_reference import chacha20_block

ROOT = Path(__file__).parents[1]
RESULTS = ROOT / "research/results/v1"
CONFIGS = ROOT / "research/configs"


def _load(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_bytes())
    assert isinstance(value, dict)
    return value


def _words_bytes(words: list[int]) -> bytes:
    return b"".join(int(word).to_bytes(4, "little") for word in words)


def _confirm_chacha(challenge: dict[str, Any], key_words: list[int]) -> list[str]:
    key = _words_bytes(key_words)
    nonce = _words_bytes([int(value) for value in challenge["nonce_words"]])
    expected = [_words_bytes([int(value) for value in row]) for row in challenge["target_words"]]
    observed = [
        chacha20_block(
            key=key,
            counter=(int(challenge["counter_start"]) + index) & 0xFFFFFFFF,
            nonce=nonce,
        )
        for index in range(len(expected))
    ]
    assert observed == expected
    return [hashlib.sha256(block).hexdigest() for block in observed]


def test_five_new_complete_domain_records_have_terminal_gates() -> None:
    expected = {
        "blake3_keyed_metal_recovery_v1.json": ("B3KR1", 43, 213, 2**43, 256),
        "siphash24_metal_recovery_v1.json": ("SIPKR1", 43, 85, 2**43, 128),
        "tea_metal_recovery_v1.json": ("TEAKR1", 43, 85, 2**43, 128),
        "xtea_metal_recovery_v1.json": ("XTEAKR1", 43, 85, 2**43, 128),
        "threefish1024_metal_record_v1.json": ("TF1024KR1", 39, 985, 2**39, 2048),
    }
    for filename, (attempt, unknown, known, domain, confirmation_bits) in expected.items():
        payload = _load(RESULTS / filename)
        execution = payload["execution"]
        assert payload["attempt_id"] == attempt
        assert execution["unknown_key_bits"] == unknown
        assert execution["known_key_bits"] == known
        assert execution["logical_candidate_count"] == domain
        assert execution["executed_assignment_count"] == domain
        assert execution["complete_domain_executed"] is True
        assert execution["early_stop_used"] is False
        assert execution["unique_exact_assignment"] is True
        assert len(execution["factual_full_matches"]) == 1
        assert execution["control_full_matches"] == []
        assert execution["control_target_rejected"] is True
        confirmation = execution["factual_confirmations"][0]
        observed_bits = confirmation.get("cross_implementation_output_bits_checked")
        if observed_bits is None:
            observed_bits = confirmation["output_bits_checked"]
        assert observed_bits == confirmation_bits


def test_threefish1024_recovery_is_distinct_from_the_f8_distinguisher() -> None:
    recovery = _load(RESULTS / "threefish1024_metal_record_v1.json")
    distinguisher = _load(
        ROOT / "provenance/fullround_anchors/f8/results/threefish1024.json"
    )
    assert recovery["attempt_id"] == "TF1024KR1"
    assert recovery["execution"]["logical_candidate_count"] == 2**39
    assert recovery["execution"]["factual_full_matches"] == [167_907_888_337]
    assert distinguisher["cipher"] == "Threefish-1024"
    assert distinguisher["rounds"] == 80
    assert "execution" not in distinguisher


def test_a322_a325_a350_a374_terminal_strict_subset_records() -> None:
    rows = (
        (
            "chacha20_round20_holdout_selected_w45_recovery_a322_v1.json",
            "chacha20_round20_w45_fine_band_recovery_a314_v1.json",
            "A322",
            45,
            1459,
            12_532_714_569_728,
        ),
        (
            "chacha20_round20_holdout_selected_w46_recovery_a325_v1.json",
            "chacha20_round20_holdout_selected_w46_recovery_a325_v1.json",
            "A325",
            46,
            77,
            1_322_849_927_168,
        ),
        (
            "chacha20_round20_w46_a349_order_prospective_recovery_a350_v1.json",
            "chacha20_round20_w46_a349_order_prospective_recovery_a350_v1.json",
            "A350",
            46,
            445,
            7_645_041_786_880,
        ),
        (
            "chacha20_round20_w48_target_conditioned_recovery_a374_v1.json",
            "chacha20_round20_w48_target_conditioned_recovery_a374_v1.json",
            "A374",
            48,
            102,
            7_009_386_627_072,
        ),
    )
    for result_name, config_name, attempt, width, rank, executed in rows:
        result = _load(RESULTS / result_name)
        config = _load(CONFIGS / config_name)
        discovery = result["discovery"]
        confirmation = result["confirmation"]
        challenge = config["public_challenge"]
        assert result["attempt_id"] == attempt
        assert challenge["unknown_key_bits"] == width
        assert discovery["executed_prefix_groups"] == rank
        assert discovery["executed_assignments"] == executed
        assert discovery["complete_domain_assignments"] == 2**width
        assert executed < 2**width
        assert discovery["strict_subset_of_complete_domain"] is True
        assert discovery["early_stop_inside_group"] is False
        assert discovery["factual_filter_candidates"] == [confirmation["assignment"]]
        assert discovery["control_filter_candidates"] == []
        assert discovery["matched_control_candidates"] == 0
        hashes = _confirm_chacha(
            challenge, [int(value) for value in confirmation["recovered_key_words"]]
        )
        assert hashes == confirmation["word_reference_sha256"]
        assert hashes == confirmation["byte_reference_sha256"]
        assert confirmation["total_cross_implementation_output_bits_checked"] == 8192

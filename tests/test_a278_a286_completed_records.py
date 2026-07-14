from __future__ import annotations

import hashlib
import json
from pathlib import Path

from arx_carry_leak.aes256_reference import apply_low_residual_bits, encrypt_blocks
from arx_carry_leak.chacha20_rfc8439_reference import chacha20_block
from arx_carry_leak.present128_reference import encrypt_int, key_parts_to_int, key_schedule

ROOT = Path(__file__).parents[1]
RESULTS = ROOT / "research/results/v1"
CONFIGS = ROOT / "research/configs"


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _words_bytes(words: list[int]) -> bytes:
    return b"".join(int(word).to_bytes(4, "little") for word in words)


def _confirm_chacha_target(challenge: dict, recovered_low20: int) -> list[str]:
    key_words = [
        int(challenge["known_key_word0_upper12"]) | recovered_low20,
        *[int(value) for value in challenge["known_key_words_1_through_7"]],
    ]
    key = _words_bytes(key_words)
    nonce = _words_bytes(challenge["nonce_words"])
    outputs = [
        chacha20_block(
            key=key,
            counter=(int(challenge["counter_start"]) + block_index) & 0xFFFFFFFF,
            nonce=nonce,
        )
        for block_index in range(int(challenge["block_count"]))
    ]
    expected = [_words_bytes(words) for words in challenge["target_words"]]
    assert outputs == expected
    assert outputs[0] != _words_bytes(challenge["control_target_words"])
    hashes = [hashlib.sha256(block).hexdigest() for block in outputs]
    assert hashes == challenge["target_block_sha256"]
    return hashes


def test_a281_target_blind_strict_subset_recovery() -> None:
    result_path = RESULTS / "chacha20_round20_cross_material_composite_recovery_v1.json"
    target_path = CONFIGS / "chacha20_round20_cross_material_target_v1.json"
    assert _sha256(result_path) == "0083e7e476844086b2ea58d6f490d0ab61cb9a7193371525aeac5252c12f1b05"
    result = json.loads(result_path.read_bytes())
    target = json.loads(target_path.read_bytes())
    confirmation = result["confirmation"]
    hashes = _confirm_chacha_target(
        target["public_challenge"], int(confirmation["recovered_unknown_low20"])
    )
    assert hashes == confirmation["candidate_block_sha256"]
    assert result["top_execution_summary"]["attempted_cells"] == 37
    assert result["top_execution_summary"]["logical_assignments_inside_attempted_cells"] == 151_552
    assert result["top_execution_summary"]["unsat"] == 36
    assert result["top_execution_summary"]["sat"] == 1
    assert result["information_boundary"]["complete_full_domain_enumeration_used"] is False


def test_a286_four_target_root_confirmation_and_anchors() -> None:
    path = RESULTS / "chacha20_round20_multitarget_panel_root_confirmation_a286_v1.json"
    assert _sha256(path) == "c171c61c1ce90c9e19faa06784205a7c9a24c2ddcb58db5ba74ecd00f1e32464"
    payload = json.loads(path.read_bytes())
    assert payload["attempt_id"] == "A286"
    assert payload["headline"] == {
        "all_one_bit_controls_rejected": True,
        "complete_full_domain_enumeration_used": False,
        "confirmed_recoveries": 4,
        "discovery_modes": ["fallback", "top128", "top128", "global"],
        "fresh_public_material_targets": 4,
        "frozen_order_ranks_when_applicable": [254, 55, 107],
        "independently_recomputed_output_bits": 16_384,
        "maximum_rank": 254,
        "median_rank": 107,
        "minimum_rank": 55,
        "reader_refits": 0,
        "target_labels_used": 0,
    }
    for anchor in payload["shared_anchors"].values():
        anchored = ROOT / anchor["path"]
        assert _sha256(anchored) == anchor["sha256"]
    assert _sha256(RESULTS / "chacha20_round20_multitarget_panel_root_confirmation_a286_v1.causal") == (
        "4c8ac373485a5f8f8db91f3d555ec041dad917182e101fd8833ec346683ade0b"
    )
    for row in payload["targets"]:
        for anchor in row["anchors"].values():
            assert _sha256(ROOT / anchor["path"]) == anchor["sha256"]
        target = json.loads((ROOT / row["anchors"]["target"]["path"]).read_bytes())
        hashes = _confirm_chacha_target(
            target["public_challenge"], int(row["recovered_unknown_low20"])
        )
        assert hashes == row["standalone_block_sha256"]
        assert row["standalone_direct_spec_all_8_blocks_match"] is True
        assert row["one_bit_control_rejected"] is True


def test_present128_w38_complete_domain_record() -> None:
    path = RESULTS / "present128_metal_width38_recovery_v1.json"
    assert _sha256(path) == "4a7935c561784f735d9519b2404faba69e1baf0069e11b78d3f67a60fceba121"
    payload = json.loads(path.read_bytes())
    challenge = payload["public_challenge"]
    assignment = int(payload["execution"]["factual_full_matches"][0])
    key = key_parts_to_int(
        int(challenge["known_high64"]),
        int(challenge["known_mid_low32"]) | (assignment >> 32),
        assignment & 0xFFFFFFFF,
    )
    round_keys = key_schedule(key)
    words = challenge["plaintext_words_big_endian"]
    output = []
    for offset in range(0, len(words), 2):
        block = (int(words[offset]) << 32) | int(words[offset + 1])
        encrypted = encrypt_int(block, round_keys)
        output.extend((encrypted >> 32, encrypted & 0xFFFFFFFF))
    assert output == challenge["target_ciphertext_words_big_endian"]
    assert payload["execution"]["logical_candidate_count"] == 2**38
    assert payload["execution"]["complete_domain_executed"] is True
    assert payload["recovery"]["recovered_full_master_key_hex"] == [f"{key:032x}"]


def test_aes256_w41_complete_domain_record() -> None:
    path = RESULTS / "aes256_fips197_metal_width41_recovery_v1.json"
    assert _sha256(path) == "51b9d4c476d03acf92894f1cb259a59538fef14afebb2bdb6cd4b403556f60b3"
    payload = json.loads(path.read_bytes())
    challenge = payload["public_challenge"]
    assignment = int(payload["execution"]["factual_full_matches"][0])
    key = apply_low_residual_bits(
        bytes.fromhex(challenge["known_key_zeroed_residual_hex"]), assignment, 41
    )
    output = encrypt_blocks(key, bytes.fromhex(challenge["plaintext_hex"]))
    assert output.hex() == challenge["target_ciphertext_hex"]
    assert hashlib.sha256(output).hexdigest() == challenge["target_ciphertext_sha256"]
    assert payload["execution"]["logical_candidate_count"] == 2**41
    assert payload["execution"]["complete_domain_executed"] is True
    assert payload["execution"]["control_target_rejected"] is True
    assert key.hex() == "d9112d122cf54d9d03fda18db88bd78624056578beb89ae355dc1c7c7ed3590f"

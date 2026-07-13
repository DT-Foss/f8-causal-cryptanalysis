from __future__ import annotations

import hashlib
import importlib.util
import json
import struct
import sys
from pathlib import Path

from arx_carry_leak.chacha20_rfc8439_reference import chacha20_block

ROOT = Path(__file__).parents[1]
SOURCE = ROOT / "research/experiments/chacha20_round20_ranked_target_cross_confirmation.py"


def _module():
    spec = importlib.util.spec_from_file_location("a219_cross_gate_test", SOURCE)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def test_no_sat_result_is_recorded_without_loading_confirmation_anchors(
    tmp_path: Path,
) -> None:
    module = _module()
    protocol = tmp_path / "protocol.json"
    protocol.write_text("{}")
    source = tmp_path / "source.json"
    source.write_text(
        json.dumps(
            {
                "schema": "chacha20-round20-ranked-target-recovery-result-v1",
                "attempt_id": "A219",
                "target_secret_or_salt_read": False,
                "protocol_sha256": _sha256(protocol),
                "measurement_sha256": "11" * 32,
                "execution": {"sat_found": False},
            }
        )
    )
    output = tmp_path / "cross.json"
    payload = module.run(source=source, output=output, protocol_path=protocol)
    assert payload["status"] == "NOT_APPLICABLE_NO_SAT_MODEL"
    assert payload["confirmation"] is None
    assert payload["target_secret_or_salt_read"] is False


def test_existing_sat_result_passes_standalone_eight_block_gate(tmp_path: Path) -> None:
    module = _module()
    low20 = 0x7139D
    upper12 = 0xB4200000
    key_words = [
        upper12 | low20,
        0x01020304,
        0x10203040,
        0x89ABCDEF,
        0x13579BDF,
        0x2468ACE0,
        0xC001D00D,
        0x55AA55AA,
    ]
    nonce_words = [0x10213243, 0x54657687, 0x98A9BACB]
    key = struct.pack("<8I", *key_words)
    nonce = struct.pack("<3I", *nonce_words)
    counter_start = 0xFFFFFFFA
    blocks = [
        chacha20_block(
            key=key,
            counter=(counter_start + index) & 0xFFFFFFFF,
            nonce=nonce,
        )
        for index in range(8)
    ]
    targets = [list(struct.unpack("<16I", block)) for block in blocks]
    control = targets[0].copy()
    control[0] ^= 1
    control_hash = hashlib.sha256(struct.pack("<16I", *control)).hexdigest()

    public = tmp_path / "public.json"
    public.write_text(
        json.dumps(
            {
                "public_challenge": {
                    "known_key_word0_upper12": upper12,
                    "known_key_words_1_through_7": key_words[1:],
                    "counter_start": counter_start,
                    "nonce_words": nonce_words,
                    "block_count": 8,
                    "target_words": targets,
                    "control_target_block_sha256": control_hash,
                }
            }
        )
    )
    r20 = tmp_path / "r20.py"
    r20.write_text(
        "import struct\n"
        "from arx_carry_leak.chacha20_rfc8439_reference import chacha20_block\n"
        "class P1:\n"
        "    @staticmethod\n"
        "    def _chacha_block(*, key_words, counter, nonce_words, rounds):\n"
        "        assert rounds == 20\n"
        "        raw = chacha20_block(key=struct.pack('<8I', *key_words), "
        "counter=counter, nonce=struct.pack('<3I', *nonce_words))\n"
        "        return list(struct.unpack('<16I', raw))\n"
        "    @staticmethod\n"
        "    def _word_bytes(words):\n"
        "        return struct.pack('<16I', *words)\n"
    )
    protocol = tmp_path / "protocol.json"
    protocol.write_text(
        json.dumps(
            {
                "anchors": {
                    "public_target_path": str(public),
                    "R20_runner_path": str(r20),
                }
            }
        )
    )
    source = tmp_path / "source.json"
    source.write_text(
        json.dumps(
            {
                "schema": "chacha20-round20-ranked-target-recovery-result-v1",
                "attempt_id": "A219",
                "target_secret_or_salt_read": False,
                "protocol_sha256": _sha256(protocol),
                "measurement_sha256": "22" * 32,
                "anchor_hashes": {
                    "public_target": _sha256(public),
                    "r20": _sha256(r20),
                },
                "execution": {
                    "sat_found": True,
                    "sat_row": {
                        "prefix8": f"{low20 >> 12:08b}",
                        "model_bits_bit0_through_bit19": [(low20 >> bit) & 1 for bit in range(20)],
                    },
                },
            }
        )
    )
    output = tmp_path / "cross.json"

    payload = module.run(source=source, output=output, protocol_path=protocol)
    assert payload["status"] == "DUAL_INDEPENDENT_EIGHT_BLOCK_CONFIRMATION_PASSED"
    assert payload["confirmation"]["all_cross_implementation_blocks_match"] is True
    assert payload["confirmation"]["claim_gate_block_matches"] == [True] * 8
    assert payload["confirmation"]["output_bits_checked"] == 4096
    assert payload["target_secret_or_salt_read"] is False


def test_cross_gate_source_has_no_sealed_input_path() -> None:
    assert ".research_sealed" not in SOURCE.read_text()

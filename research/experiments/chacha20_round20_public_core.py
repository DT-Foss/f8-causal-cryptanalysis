"""Public-only ChaCha20-R20 formula and known-key challenge adapter.

This module deliberately imports only the frozen phase-1 implementation core.
It never opens prior result, model, assignment, rank, or Causal artifacts.
"""

from __future__ import annotations

import copy
import hashlib
import importlib.util
import sys
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

ROOT = Path(__file__).parents[2]
CORE_PATH = ROOT / "research/pilots/chacha20_round20_partition_v1/runner.py"
CORE_SHA256 = "559556f88bb6a4c13715dbf52644f5cff1b77af37d65f5195d8c9adfb58ab7ef"
LOW20_MASK = (1 << 20) - 1
TARGET_FIELDS = {
    "target_words",
    "target_block_sha256",
    "control_target_words",
    "control_target_block_sha256",
}
SECRET_FIELDS = {
    "low20",
    "low20_hex",
    "known_low20",
    "secret_low20",
    "unknown_assignment",
    "unknown_key_word0_low_value",
    "salt",
    "salt_hex",
}
PUBLIC_TEMPLATE_FIELDS = {
    "block_count",
    "counter_schedule",
    "counter_start",
    "known_key_bits",
    "known_key_word0_upper12",
    "known_key_words_1_through_7",
    "known_material_derivation_label",
    "known_material_derivation_sha256",
    "nonce_words",
    "public_seed_hex",
    "rounds",
    "unknown_assignment_bits",
    "unknown_assignment_included",
    "unknown_key_word0_low_bits",
    "unknown_key_word0_low_value_included",
    "unknown_secret_low20_included",
}


def _sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _file_sha256(path: Path) -> str:
    return _sha256(path.read_bytes())


def _word_bytes(words: Sequence[int]) -> bytes:
    return b"".join(int(word & 0xFFFFFFFF).to_bytes(4, "little") for word in words)


def _import_public_core() -> Any:
    if _file_sha256(CORE_PATH) != CORE_SHA256:
        raise RuntimeError("public-only ChaCha20-R20 implementation core hash differs")
    spec = importlib.util.spec_from_file_location("a220_public_chacha20_r20_core", CORE_PATH)
    if spec is None or spec.loader is None:
        raise RuntimeError("cannot import public-only ChaCha20-R20 implementation core")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


P1 = _import_public_core()


def validate_public_template(value: Mapping[str, Any]) -> dict[str, Any]:
    """Validate and copy fixed public material that contains no target or key label."""
    material = copy.deepcopy(dict(value))
    if set(material) != PUBLIC_TEMPLATE_FIELDS:
        raise RuntimeError("public-only ChaCha20-R20 template field set differs")
    if TARGET_FIELDS & set(material) or SECRET_FIELDS & set(material):
        raise RuntimeError("public-only ChaCha20-R20 template contains target or secret material")
    if (
        material["rounds"] != 20
        or material["block_count"] != 8
        or material["counter_schedule"] != "base_plus_block_index_mod_2^32"
        or material["known_key_bits"] != 236
        or material["unknown_assignment_bits"] != 20
        or material["unknown_key_word0_low_bits"] != 20
        or material["unknown_assignment_included"] is not False
        or material["unknown_key_word0_low_value_included"] is not False
        or material["unknown_secret_low20_included"] is not False
        or int(material["known_key_word0_upper12"]) & LOW20_MASK
        or len(material["known_key_words_1_through_7"]) != 7
        or len(material["nonce_words"]) != 3
    ):
        raise RuntimeError("public-only ChaCha20-R20 template structural gate failed")
    seed = bytes.fromhex(material["public_seed_hex"])
    label = str(material["known_material_derivation_label"])
    if len(seed) != 32 or not label.endswith(material["public_seed_hex"]):
        raise RuntimeError("public-only ChaCha20-R20 derivation label differs")
    derived = hashlib.shake_256(label.encode()).digest(48)
    words = [int.from_bytes(derived[offset : offset + 4], "little") for offset in range(0, 48, 4)]
    if (
        _sha256(derived) != material["known_material_derivation_sha256"]
        or words[0] & ~LOW20_MASK != material["known_key_word0_upper12"]
        or words[1:8] != material["known_key_words_1_through_7"]
        or words[8] != material["counter_start"]
        or words[9:12] != material["nonce_words"]
    ):
        raise RuntimeError("public-only ChaCha20-R20 known-material derivation differs")
    return material


def build_known_challenge(public_template: Mapping[str, Any], *, low20: int) -> dict[str, Any]:
    """Build eight public R20 blocks while keeping the known label out of the challenge."""
    if not isinstance(low20, int) or isinstance(low20, bool) or not 0 <= low20 <= LOW20_MASK:
        raise ValueError("known ChaCha20-R20 low20 label is outside the frozen domain")
    challenge = validate_public_template(public_template)
    key_words = [
        int(challenge["known_key_word0_upper12"]) | low20,
        *[int(value) for value in challenge["known_key_words_1_through_7"]],
    ]
    blocks = [
        P1._chacha_block(
            key_words=key_words,
            counter=(int(challenge["counter_start"]) + index) & 0xFFFFFFFF,
            nonce_words=challenge["nonce_words"],
            rounds=20,
        )
        for index in range(8)
    ]
    control = blocks[0].copy()
    control[0] ^= 1
    challenge.update(
        {
            "target_words": blocks,
            "target_block_sha256": [_sha256(_word_bytes(block)) for block in blocks],
            "control_target_words": control,
            "control_target_block_sha256": _sha256(_word_bytes(control)),
        }
    )
    P1._validate_challenge(challenge)
    if SECRET_FIELDS & set(challenge):
        raise RuntimeError("generated public ChaCha20-R20 challenge stores its known label")
    return challenge


def _source_formula(challenge: dict[str, Any]) -> str:
    """Expose the exact split-18 source formula without any historical anchor loader."""
    P1._validate_challenge(challenge)
    old_split = P1.SPLIT
    try:
        P1.SPLIT = 18
        return P1._base_formula(challenge)
    finally:
        P1.SPLIT = old_split


def provenance() -> dict[str, Any]:
    return {
        "core_path": str(CORE_PATH.relative_to(ROOT)),
        "core_sha256": _file_sha256(CORE_PATH),
        "historical_result_or_causal_loader_present": False,
        "target_fields_permitted_in_public_template": False,
        "known_low20_stored_in_generated_challenge": False,
    }

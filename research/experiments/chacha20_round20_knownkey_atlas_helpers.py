"""Deterministic known-key challenge construction for the frozen A214 atlas."""

from __future__ import annotations

import copy
import hashlib
import json
from collections.abc import Callable, Sequence
from typing import Any


LOW20_MASK = (1 << 20) - 1


def _sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _word_bytes(words: Sequence[int]) -> bytes:
    return b"".join(int(word & 0xFFFFFFFF).to_bytes(4, "little") for word in words)


def derive_low20(label: str) -> int:
    if not label:
        raise ValueError("A214 derivation label must be non-empty")
    return int.from_bytes(hashlib.shake_256(label.encode()).digest(4), "little") & LOW20_MASK


def atlas_ledger() -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for split, count in (("train", 16), ("validation", 8)):
        for index in range(count):
            label = f"f8-causal:A214:{split}:{index}:known-low20-v1"
            value = derive_low20(label)
            rows.append(
                {
                    "split": split,
                    "index": index,
                    "derivation_label": label,
                    "low20": value,
                    "low20_hex": f"{value:05x}",
                }
            )
    if len({row["low20"] for row in rows}) != len(rows):
        raise RuntimeError("A214 deterministic atlas keys are not unique")
    return rows


def atlas_ledger_sha256(rows: list[dict[str, Any]] | None = None) -> str:
    value = atlas_ledger() if rows is None else rows
    raw = json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False
    ).encode()
    return _sha256(raw)


def training_challenge(
    public_challenge: dict[str, Any],
    *,
    low20: int,
    chacha_block: Callable[..., list[int]],
) -> dict[str, Any]:
    """Return a formula-safe challenge with known-key-derived R20 targets.

    The returned mapping contains no field carrying ``low20``; the caller keeps
    the training label in a separate ledger.
    """
    if low20 < 0 or low20 > LOW20_MASK:
        raise ValueError("A214 low20 is outside the frozen domain")
    challenge = copy.deepcopy(public_challenge)
    key_words = [
        int(public_challenge["known_key_word0_upper12"]) | int(low20),
        *[int(value) for value in public_challenge["known_key_words_1_through_7"]],
    ]
    blocks = [
        chacha_block(
            key_words=key_words,
            counter=(int(public_challenge["counter_start"]) + index) & 0xFFFFFFFF,
            nonce_words=public_challenge["nonce_words"],
            rounds=20,
        )
        for index in range(int(public_challenge["block_count"]))
    ]
    control = blocks[0].copy()
    control[0] ^= 1
    challenge["target_words"] = blocks
    challenge["target_block_sha256"] = [_sha256(_word_bytes(block)) for block in blocks]
    challenge["control_target_words"] = control
    challenge["control_target_block_sha256"] = _sha256(_word_bytes(control))
    forbidden = {
        "low20",
        "known_low20",
        "secret_low20",
        "unknown_key_word0_low_value",
        "unknown_assignment",
    }
    if forbidden & set(challenge):
        raise RuntimeError("A214 formula challenge unexpectedly stores the training key")
    return challenge

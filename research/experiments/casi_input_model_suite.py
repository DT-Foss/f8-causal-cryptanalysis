#!/usr/bin/env python3
"""Test CASI dependence on plaintext schedule and ciphertext ordering."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

import numpy as np

from arx_carry_leak.live_casi_v091.core import compute_amplified_score, compute_casi_score
from arx_carry_leak.nano_ciphers import (
    SIMON_PARAMS,
    _SIMON_Z_SEQ,
    _simon_encrypt,
    _simon_key_schedule,
    gen_simon32_64,
)


def _score(keys: np.ndarray) -> dict[str, float]:
    standard = compute_casi_score(keys)
    amplified = compute_amplified_score(keys)
    return {
        "standard": float(standard["casi"]),
        "amplified": float(amplified["casi"]),
        "operational_max": float(max(standard["casi"], amplified["casi"])),
    }


def _uniform_plaintext_stream(count: int, rounds: int, seed: int) -> bytes:
    word_size, key_words, full_rounds, z_index = SIMON_PARAMS[(32, 64)]
    actual_rounds = min(rounds, full_rounds)
    key_rng = np.random.RandomState(seed)
    master_key = [int(key_rng.randint(0, 2**word_size)) for _ in range(key_words)]
    round_keys = _simon_key_schedule(
        master_key, word_size, key_words, actual_rounds, _SIMON_Z_SEQ[z_index]
    )
    plaintext_rng = np.random.default_rng(seed + 0xC0FFEE)
    n_blocks = count * 8
    output = bytearray(n_blocks * 4)
    for block_index in range(n_blocks):
        x = int(plaintext_rng.integers(0, 2**16, dtype=np.uint16))
        y = int(plaintext_rng.integers(0, 2**16, dtype=np.uint16))
        encrypted_x, encrypted_y = _simon_encrypt(x, y, round_keys, word_size)
        offset = block_index * 4
        output[offset : offset + 2] = encrypted_x.to_bytes(2, "big")
        output[offset + 2 : offset + 4] = encrypted_y.to_bytes(2, "big")
    return bytes(output)


def _summary(records: list[dict[str, Any]]) -> dict[str, Any]:
    values = np.asarray([record["operational_max"] for record in records], dtype=float)
    return {
        "records": records,
        "mean": float(np.mean(values)),
        "sample_sd_ddof1": float(np.std(values, ddof=1)),
        "detected_above_2": int(np.sum(values > 2.0)),
        "total": len(values),
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--samples", type=int, default=5000)
    parser.add_argument("--seeds", type=int, default=5)
    parser.add_argument("--rounds", type=int, default=9)
    parser.add_argument("--permutations", type=int, default=10)
    args = parser.parse_args()

    counter_records = []
    uniform_records = []
    counter_by_seed: dict[int, np.ndarray] = {}
    for seed_index in range(args.seeds):
        seed = 42 + 1000 * seed_index
        counter_raw = gen_simon32_64(args.samples, args.rounds, seed)
        uniform_raw = _uniform_plaintext_stream(args.samples, args.rounds, seed)
        counter_keys = np.frombuffer(counter_raw, dtype=np.uint8).reshape(-1, 32).copy()
        uniform_keys = np.frombuffer(uniform_raw, dtype=np.uint8).reshape(-1, 32).copy()
        counter_by_seed[seed] = counter_keys
        counter_records.append({"seed": seed, **_score(counter_keys)})
        uniform_records.append({"seed": seed, **_score(uniform_keys)})

    original = counter_by_seed[42]
    rng = np.random.default_rng(123456)
    row_records = []
    block_records = []
    native_blocks = original.reshape(-1, 4)
    for index in range(args.permutations):
        row_permuted = original[rng.permutation(len(original))]
        block_permuted = native_blocks[rng.permutation(len(native_blocks))].reshape(-1, 32)
        row_records.append({"permutation": index, **_score(row_permuted)})
        block_records.append({"permutation": index, **_score(block_permuted)})

    payload = {
        "schema_version": 1,
        "experiment": "casi_input_model_suite",
        "parameters": {
            "target": "simon32_64",
            "rounds": args.rounds,
            "samples": args.samples,
            "seeds": args.seeds,
            "permutations": args.permutations,
            "native_block_bytes": 4,
        },
        "counter_plaintexts": _summary(counter_records),
        "uniform_random_plaintexts": _summary(uniform_records),
        "seed42_original_counter_score": _score(original),
        "row_permutations": _summary(row_records),
        "native_block_permutations": _summary(block_records),
        "candidate_findings": [
            {
                "id": "NR-CASI-06",
                "finding": "Reduced-round CASI detection depends on the structured counter plaintext schedule.",
                "evidence": "counter_plaintexts vs uniform_random_plaintexts",
            },
            {
                "id": "NR-CASI-07",
                "finding": "Permuting unchanged 32-byte output rows removes the SIMON R9 detection.",
                "evidence": "row_permutations",
            },
            {
                "id": "NR-CASI-08",
                "finding": "Permuting unchanged native 4-byte ciphertext blocks removes the SIMON R9 detection.",
                "evidence": "native_block_permutations",
            },
        ],
        "scope_note": (
            "The cipher, keys, rounds, and sample count are fixed. Only the plaintext model or "
            "ordering changes. This directly tests the no-chosen-plaintext and permutation claims."
        ),
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n")
    print(f"wrote {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

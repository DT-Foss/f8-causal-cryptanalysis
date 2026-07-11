#!/usr/bin/env python3
"""BLAKE3 seven-round compression output Reader.

The default 32-byte output projection and the full 64-byte compression output
are treated as distinct observability boundaries.  The former exposes the
eight final lane-pair XORs.  The latter, together with the input chaining
value, permits exact reconstruction of all sixteen words immediately before
the BLAKE3 output transform.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any

import numpy as np

from arx_carry_leak.bvn import route_ensemble, verify_routes
from arx_carry_leak.crypto_causal import CryptoCausalBuilder, CryptoCausalReader


REFERENCE_URL = "https://github.com/BLAKE3-team/BLAKE3/blob/master/reference_impl/reference_impl.rs"
REFERENCE_RAW_SHA256 = "6e89a18be72e3c4d838644e1796e04d896cb4a16bd7bb803d4380d7a363fbfd2"
TEST_VECTORS_URL = "https://github.com/BLAKE3-team/BLAKE3/blob/master/test_vectors/test_vectors.json"
TEST_VECTORS_RAW_SHA256 = "dcb91ea8accc77e6d6e632af7cdc1a99a9f3ae78cf648da595c7d064db32f624"

IV = np.array(
    [
        0x6A09E667,
        0xBB67AE85,
        0x3C6EF372,
        0xA54FF53A,
        0x510E527F,
        0x9B05688C,
        0x1F83D9AB,
        0x5BE0CD19,
    ],
    dtype=np.uint32,
)
MSG_PERMUTATION = np.array(
    [2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8],
    dtype=np.int64,
)

CHUNK_START = 1 << 0
CHUNK_END = 1 << 1
PARENT = 1 << 2
ROOT = 1 << 3
KEYED_HASH = 1 << 4
DERIVE_KEY_CONTEXT = 1 << 5
DERIVE_KEY_MATERIAL = 1 << 6

OFFICIAL_XOF_VECTORS = {
    0: (
        "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262"
        "e00f03e7b69af26b7faaf09fcd333050338ddfe085b8cc869ca98b206c08243a"
        "26f5487789e8f660afe6c99ef9e0c52b92e7393024a80459cf91f476f9ffdbda"
        "7001c22e159b402631f277ca96f2defdf1078282314e763699a31c5363165421cce14d"
    ),
    1: (
        "2d3adedff11b61f14c886e35afa036736dcd87a74d27b5c1510225d0f592e213"
        "c3a6cb8bf623e20cdb535f8d1a5ffb86342d9c0b64aca3bce1d31f60adfa137b"
        "358ad4d79f97b47c3d5e79f179df87a3b9776ef8325f8329886ba42f07fb138bb"
        "502f4081cbcec3195c5871e6c23e2cc97d3c69a613eba131e5f1351f3f1da786545e5"
    ),
    63: (
        "e9bc37a594daad83be9470df7f7b3798297c3d834ce80ba85d6e207627b7db7b"
        "1197012b1e7d9af4d7cb7bdd1f3bb49a90a9b5dec3ea2bbc6eaebce77f4e470cb"
        "f4687093b5352f04e4a4570fba233164e6acc36900e35d185886a827f7ea9bdc1e"
        "5c3ce88b095a200e62c10c043b3e9bc6cb9b6ac4dfa51794b02ace9f98779040755"
    ),
    64: (
        "4eed7141ea4a5cd4b788606bd23f46e212af9cacebacdc7d1f4c6dc7f2511b98"
        "fc9cc56cb831ffe33ea8e7e1d1df09b26efd2767670066aa82d023b1dfe8ab1b"
        "2b7fbb5b97592d46ffe3e05a6a9b592e2949c74160e4674301bc3f97e04903f8c"
        "6cf95b863174c33228924cdef7ae47559b10b294acd660666c4538833582b43f82d74"
    ),
    65: (
        "de1e5fa0be70df6d2be8fffd0e99ceaa8eb6e8c93a63f2d8d1c30ecb6b263dee"
        "0e16e0a4749d6811dd1d6d1265c29729b1b75a9ac346cf93f0e1d7296dfcfd431"
        "3b3a227faaaaf7757cc95b4e87a49be3b8a270a12020233509b1c3632b3485eef"
        "309d0abc4a4a696c9decc6e90454b53b000f456a3f10079072baaf7a981653221f2c"
    ),
    1023: (
        "10108970eeda3eb932baac1428c7a2163b0e924c9a9e25b35bba72b28f70bd11"
        "a182d27a591b05592b15607500e1e8dd56bc6c7fc063715b7a1d737df5bad3339"
        "c56778957d870eb9717b57ea3d9fb68d1b55127bba6a906a4a24bbd5acb2d123"
        "a37b28f9e9a81bbaae360d58f85e5fc9d75f7c370a0cc09b6522d9c8d822f2f28f485"
    ),
    1024: (
        "42214739f095a406f3fc83deb889744ac00df831c10daa55189b5d121c855af7"
        "1cf8107265ecdaf8505b95d8fcec83a98a6a96ea5109d2c179c47a387ffbb404"
        "756f6eeae7883b446b70ebb144527c2075ab8ab204c0086bb22b7c93d465efc57"
        "f8d917f0b385c6df265e77003b85102967486ed57db5c5ca170ba441427ed9afa684e"
    ),
}


READER_RECIPE = {
    "word_bits": 32,
    "inputs": {
        "compression_output_words": 16,
        "input_chaining_value_words": 8,
    },
    "operations": [
        *[
            {
                "out": f"pre_high_{lane}",
                "op": "xor",
                "args": [f"output_{lane + 8}", f"cv_{lane}"],
                "formula": f"pre_high[{lane}] = output[{lane + 8}] xor cv[{lane}]",
            }
            for lane in range(8)
        ],
        *[
            {
                "out": f"pre_low_{lane}",
                "op": "xor",
                "args": [f"output_{lane}", f"pre_high_{lane}"],
                "formula": f"pre_low[{lane}] = output[{lane}] xor pre_high[{lane}]",
            }
            for lane in range(8)
        ],
    ],
    "output_order": [
        *[f"pre_low_{lane}" for lane in range(8)],
        *[f"pre_high_{lane}" for lane in range(8)],
    ],
}


def _validate_inputs(
    chaining_value: np.ndarray,
    block_words: np.ndarray,
    counter: np.ndarray,
    block_len: np.ndarray,
    flags: np.ndarray,
) -> None:
    rows = len(chaining_value)
    if chaining_value.dtype != np.uint32 or chaining_value.shape != (rows, 8):
        raise ValueError("chaining_value must be uint32[N,8]")
    if block_words.dtype != np.uint32 or block_words.shape != (rows, 16):
        raise ValueError("block_words must be uint32[N,16]")
    if counter.dtype != np.uint64 or counter.shape != (rows,):
        raise ValueError("counter must be uint64[N]")
    if block_len.dtype != np.uint32 or block_len.shape != (rows,):
        raise ValueError("block_len must be uint32[N]")
    if flags.dtype != np.uint32 or flags.shape != (rows,):
        raise ValueError("flags must be uint32[N]")


def _ror32(value: np.ndarray, shift: int) -> np.ndarray:
    return ((value >> np.uint32(shift)) | (value << np.uint32(32 - shift))).astype(
        np.uint32
    )


def _g(
    state: np.ndarray,
    a: int,
    b: int,
    c: int,
    d: int,
    message_x: np.ndarray,
    message_y: np.ndarray,
) -> None:
    state[:, a] = state[:, a] + state[:, b] + message_x
    state[:, d] = _ror32(state[:, d] ^ state[:, a], 16)
    state[:, c] = state[:, c] + state[:, d]
    state[:, b] = _ror32(state[:, b] ^ state[:, c], 12)
    state[:, a] = state[:, a] + state[:, b] + message_y
    state[:, d] = _ror32(state[:, d] ^ state[:, a], 8)
    state[:, c] = state[:, c] + state[:, d]
    state[:, b] = _ror32(state[:, b] ^ state[:, c], 7)


def _round(state: np.ndarray, message: np.ndarray) -> None:
    _g(state, 0, 4, 8, 12, message[:, 0], message[:, 1])
    _g(state, 1, 5, 9, 13, message[:, 2], message[:, 3])
    _g(state, 2, 6, 10, 14, message[:, 4], message[:, 5])
    _g(state, 3, 7, 11, 15, message[:, 6], message[:, 7])
    _g(state, 0, 5, 10, 15, message[:, 8], message[:, 9])
    _g(state, 1, 6, 11, 12, message[:, 10], message[:, 11])
    _g(state, 2, 7, 8, 13, message[:, 12], message[:, 13])
    _g(state, 3, 4, 9, 14, message[:, 14], message[:, 15])


def _compress_trace(
    chaining_value: np.ndarray,
    block_words: np.ndarray,
    counter: np.ndarray,
    block_len: np.ndarray,
    flags: np.ndarray,
) -> tuple[list[np.ndarray], np.ndarray]:
    _validate_inputs(chaining_value, block_words, counter, block_len, flags)
    rows = len(chaining_value)
    state = np.empty((rows, 16), dtype=np.uint32)
    state[:, :8] = chaining_value
    state[:, 8:12] = IV[:4]
    state[:, 12] = counter.astype(np.uint32)
    state[:, 13] = (counter >> np.uint64(32)).astype(np.uint32)
    state[:, 14] = block_len
    state[:, 15] = flags
    message = block_words.copy()
    trace = [state.copy()]
    for round_index in range(7):
        _round(state, message)
        trace.append(state.copy())
        if round_index != 6:
            message = message[:, MSG_PERMUTATION]
    output = state.copy()
    output[:, :8] ^= state[:, 8:]
    output[:, 8:] ^= chaining_value
    return trace, output


def _compress(
    chaining_value: np.ndarray,
    block_words: np.ndarray,
    counter: np.ndarray,
    block_len: np.ndarray,
    flags: np.ndarray,
) -> np.ndarray:
    return _compress_trace(chaining_value, block_words, counter, block_len, flags)[1]


def _block_words(block: bytes) -> np.ndarray:
    if len(block) > 64:
        raise ValueError("BLAKE3 block may contain at most 64 bytes")
    padded = block + b"\x00" * (64 - len(block))
    return np.frombuffer(padded, dtype="<u4").astype(np.uint32).reshape(1, 16)


def _one(values: np.ndarray, dtype: np.dtype[Any]) -> np.ndarray:
    return np.asarray(values, dtype=dtype).reshape(1)


def _single_chunk_xof(data: bytes, output_len: int) -> bytes:
    if len(data) > 1024:
        raise ValueError("single-chunk reference gate accepts at most 1024 bytes")
    if output_len < 0:
        raise ValueError("output_len must be non-negative")
    blocks = [data[offset : offset + 64] for offset in range(0, len(data), 64)]
    if not blocks:
        blocks = [b""]
    cv = IV.reshape(1, 8).copy()
    for block_index, block in enumerate(blocks[:-1]):
        flags = CHUNK_START if block_index == 0 else 0
        output = _compress(
            cv,
            _block_words(block),
            _one([0], np.uint64),
            _one([64], np.uint32),
            _one([flags], np.uint32),
        )
        cv = output[:, :8]
    final_block = blocks[-1]
    final_flags = CHUNK_END | (CHUNK_START if len(blocks) == 1 else 0)
    output = bytearray()
    output_counter = 0
    while len(output) < output_len:
        words = _compress(
            cv,
            _block_words(final_block),
            _one([output_counter], np.uint64),
            _one([len(final_block)], np.uint32),
            _one([final_flags | ROOT], np.uint32),
        )[0]
        output.extend(words.astype("<u4", copy=False).tobytes())
        output_counter += 1
    return bytes(output[:output_len])


def _kat() -> dict[str, Any]:
    rows = []
    for input_len, expected in OFFICIAL_XOF_VECTORS.items():
        data = bytes(index % 251 for index in range(input_len))
        observed = _single_chunk_xof(data, len(bytes.fromhex(expected))).hex()
        if observed != expected:
            raise RuntimeError(
                f"BLAKE3 XOF vector failed for length {input_len}: {observed} != {expected}"
            )
        rows.append(
            {
                "input_len": input_len,
                "output_bytes": len(bytes.fromhex(expected)),
                "expected": expected,
                "observed": observed,
                "match": True,
            }
        )
    return {
        "reference_url": REFERENCE_URL,
        "reference_raw_sha256": REFERENCE_RAW_SHA256,
        "test_vectors_url": TEST_VECTORS_URL,
        "test_vectors_raw_sha256": TEST_VECTORS_RAW_SHA256,
        "vectors": rows,
    }


def _execute_reader_recipe(
    compression_output: np.ndarray,
    chaining_value: np.ndarray,
    recipe: dict[str, Any],
) -> np.ndarray:
    if compression_output.dtype != np.uint32 or compression_output.ndim != 2 or compression_output.shape[1] != 16:
        raise ValueError("compression_output must be uint32[N,16]")
    if chaining_value.dtype != np.uint32 or chaining_value.shape != (len(compression_output), 8):
        raise ValueError("chaining_value must be uint32[N,8]")
    values = {
        **{f"output_{index}": compression_output[:, index] for index in range(16)},
        **{f"cv_{index}": chaining_value[:, index] for index in range(8)},
    }
    for operation in recipe["operations"]:
        if operation["op"] != "xor":
            raise ValueError(f"unsupported BLAKE3 Reader operation {operation['op']}")
        result = np.zeros(len(compression_output), dtype=np.uint32)
        for argument in operation["args"]:
            result ^= values[argument]
        values[operation["out"]] = result
    return np.stack([values[name] for name in recipe["output_order"]], axis=1)


def _build_graph(path: Path, pairs: int, seeds: int, routes: int) -> dict[str, Any]:
    builder = CryptoCausalBuilder(
        experiment="blake3_fullcompression_output_reader",
        parameters={
            "rounds": 7,
            "word_bits": 32,
            "pairs_per_seed": pairs,
            "seeds": seeds,
            "bvn_routes": routes,
            "boundaries": [
                "default_32_byte_output_projection",
                "full_64_byte_compression_output_plus_known_cv",
            ],
            "prediction_before_measurement": (
                "The first output half equals final-low xor final-high; the second "
                "half plus the known CV separates both final halves exactly."
            ),
        },
    )
    pair_edges = []
    high_edges = []
    for lane in range(8):
        pair_id = f"blake3-output-pair-xor-{lane}"
        high_id = f"blake3-output-high-cv-mask-{lane}"
        pair_edges.append(pair_id)
        high_edges.append(high_id)
        builder.add_triplet(
            edge_id=pair_id,
            trigger=f"blake3:post_round7_low_{lane}_and_high_{lane}",
            mechanism="exact_output_pair_xor",
            outcome=f"blake3:compression_output_low_{lane}",
            confidence=1.0,
            evidence_kind="exact_reference_output_equation",
            source="BLAKE3_reference_compress_output_transform",
            attrs={
                "formula": f"output[{lane}] = pre[{lane}] xor pre[{lane + 8}]",
                "visible_in_first_32_output_bytes": True,
            },
        )
        builder.add_triplet(
            edge_id=high_id,
            trigger=f"blake3:post_round7_high_{lane}_and_input_cv_{lane}",
            mechanism="exact_high_lane_cv_mask",
            outcome=f"blake3:compression_output_high_{lane}",
            confidence=1.0,
            evidence_kind="exact_reference_output_equation",
            source="BLAKE3_reference_compress_output_transform",
            attrs={
                "formula": f"output[{lane + 8}] = pre[{lane + 8}] xor cv[{lane}]",
                "requires_full_64_byte_compression_output": True,
            },
        )
    low_edges = []
    for lane, (pair_id, high_id) in enumerate(zip(pair_edges, high_edges, strict=True)):
        low_id = f"blake3-output-low-three-xor-{lane}"
        low_edges.append(low_id)
        builder.add_triplet(
            edge_id=low_id,
            trigger=f"blake3:both_output_lane_{lane}_words_and_input_cv_{lane}",
            mechanism="exact_three_term_low_lane_cancellation",
            outcome=f"blake3:post_round7_low_{lane}",
            confidence=1.0,
            evidence_kind="exact_composed_output_inverse",
            source="BLAKE3_output_pair_xor_and_high_cv_mask",
            provenance=[pair_id, high_id],
            attrs={
                "formula": (
                    f"pre[{lane}] = output[{lane}] xor output[{lane + 8}] "
                    f"xor cv[{lane}]"
                ),
                "symmetric_under_output_half_swap": True,
            },
        )
    builder.add_triplet(
        edge_id="blake3-reader-full-post-round7-state",
        trigger="blake3:full_64_byte_compression_output_plus_input_cv",
        mechanism="reader_executable_complete_post_round_state_inverse",
        outcome="blake3:complete_post_round7_pre_output_state",
        confidence=1.0,
        evidence_kind="exact_composed_output_inverse",
        source="BLAKE3_two_stage_xor_output_inverse",
        provenance=[*low_edges, *high_edges],
        attrs={
            "reader_recipe": READER_RECIPE,
            "information_reconstructed_bits": 512,
            "default_digest_boundary_bits": 256,
        },
    )
    stats = builder.save(path)
    reader = CryptoCausalReader(path)
    if not reader.verify_provenance() or len(reader.triplets(include_inferred=False)) != 25:
        raise RuntimeError("BLAKE3 causal Reader gate failed")
    return stats


def _recipe_from_reader(path: Path) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    reader = CryptoCausalReader(path)
    rows = reader.triplets(include_inferred=False)
    matches = [
        row
        for row in rows
        if row["mechanism"] == "reader_executable_complete_post_round_state_inverse"
    ]
    if len(matches) != 1:
        raise RuntimeError("Reader did not return one BLAKE3 state recipe")
    return matches[0]["attrs"]["reader_recipe"], rows


def _accuracy(expected: np.ndarray, observed: np.ndarray) -> dict[str, Any]:
    if expected.shape != observed.shape or expected.dtype != np.uint32 or observed.dtype != np.uint32:
        raise ValueError("accuracy inputs must have matching uint32 shapes")
    difference = expected ^ observed
    bit_differences = sum(int(value).bit_count() for value in difference.ravel())
    bit_total = int(expected.size * 32)
    state_equal = np.all(expected == observed, axis=1)
    return {
        "word_matches": int(np.sum(expected == observed)),
        "word_total": int(expected.size),
        "word_accuracy": float(np.mean(expected == observed)),
        "state_matches": int(np.sum(state_equal)),
        "state_total": int(len(expected)),
        "state_accuracy": float(np.mean(state_equal)),
        "bit_matches": bit_total - bit_differences,
        "bit_total": bit_total,
        "bit_accuracy": (bit_total - bit_differences) / bit_total,
    }


def _routes(size: int, count: int, seed: int) -> list[np.ndarray]:
    routes = route_ensemble(size, count, seed)
    verification = verify_routes(routes)
    if not verification["all_bijective"] or verification["forbidden_alignments"]:
        raise RuntimeError("invalid BLAKE3 BvN route bank")
    return routes


def _random_inputs(rng: np.random.Generator, pairs: int) -> tuple[np.ndarray, ...]:
    chaining_value = rng.integers(0, 1 << 32, size=(pairs, 8), dtype=np.uint32)
    block_words = rng.integers(0, 1 << 32, size=(pairs, 16), dtype=np.uint32)
    low_counter = rng.integers(0, 1 << 32, size=pairs, dtype=np.uint32).astype(np.uint64)
    high_counter = rng.integers(0, 1 << 32, size=pairs, dtype=np.uint32).astype(np.uint64)
    counter = low_counter | (high_counter << np.uint64(32))
    block_len = rng.integers(0, 65, size=pairs, dtype=np.uint32)
    standard_flags = np.array(
        [
            0,
            CHUNK_START,
            CHUNK_END,
            CHUNK_START | CHUNK_END,
            PARENT,
            ROOT,
            CHUNK_START | CHUNK_END | ROOT,
            KEYED_HASH,
            DERIVE_KEY_CONTEXT,
            DERIVE_KEY_MATERIAL,
        ],
        dtype=np.uint32,
    )
    flags = rng.choice(standard_flags, size=pairs).astype(np.uint32)
    return chaining_value, block_words, counter, block_len, flags


def _confirm_seed(
    inputs: tuple[np.ndarray, ...],
    recipe: dict[str, Any],
    route_count: int,
    seed: int,
) -> dict[str, Any]:
    chaining_value, block_words, counter, block_len, flags = inputs
    trace, output = _compress_trace(
        chaining_value, block_words, counter, block_len, flags
    )
    post_round7 = trace[-1]
    digest_projection = _accuracy(
        post_round7[:, :8] ^ post_round7[:, 8:],
        output[:, :8],
    )
    reconstructed = _execute_reader_recipe(output, chaining_value, recipe)
    factual = _accuracy(post_round7, reconstructed)

    route_rows = []
    for route in _routes(len(output), route_count, seed):
        route_rows.append(
            _accuracy(
                post_round7,
                _execute_reader_recipe(output[route], chaining_value, recipe),
            )
        )

    wrong_cv = _accuracy(
        post_round7,
        _execute_reader_recipe(output, np.roll(chaining_value, 1, axis=1), recipe),
    )
    wrong_lane_output = output.copy()
    wrong_lane_output[:, 8:] = np.roll(output[:, 8:], 1, axis=1)
    wrong_lane_pairing = _accuracy(
        post_round7,
        _execute_reader_recipe(wrong_lane_output, chaining_value, recipe),
    )
    swapped_halves = np.concatenate((output[:, 8:], output[:, :8]), axis=1)
    swapped_output_halves = _accuracy(
        post_round7,
        _execute_reader_recipe(swapped_halves, chaining_value, recipe),
    )
    wrong_add = np.empty_like(output)
    wrong_add[:, 8:] = output[:, 8:] - chaining_value
    wrong_add[:, :8] = output[:, :8] - wrong_add[:, 8:]
    wrong_operation = _accuracy(post_round7, wrong_add)

    return {
        "default_32_byte_pair_xor_projection": digest_projection,
        "factual_full_output_reader": factual,
        "bvn_routes": {
            "count": route_count,
            "total_state_matches": sum(row["state_matches"] for row in route_rows),
            "max_state_matches": max(row["state_matches"] for row in route_rows),
            "max_word_matches": max(row["word_matches"] for row in route_rows),
            "mean_bit_accuracy": float(np.mean([row["bit_accuracy"] for row in route_rows])),
            "max_bit_accuracy": max(row["bit_accuracy"] for row in route_rows),
        },
        "wrong_cv_lane_control": wrong_cv,
        "wrong_high_lane_pairing_control": wrong_lane_pairing,
        "swapped_output_halves_partial_control": swapped_output_halves,
        "wrong_xor_to_subtraction_control": wrong_operation,
        "factual_above_all_bvn_routes": (
            factual["state_matches"] > max(row["state_matches"] for row in route_rows)
            and factual["word_matches"] > max(row["word_matches"] for row in route_rows)
            and factual["bit_accuracy"] > max(row["bit_accuracy"] for row in route_rows)
        ),
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--pairs", type=int, default=8000)
    parser.add_argument("--seeds", type=int, default=5)
    parser.add_argument("--routes", type=int, default=16)
    parser.add_argument("--seed", type=int, default=89028001)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--causal-output", type=Path, required=True)
    args = parser.parse_args()
    if min(args.pairs, args.seeds, args.routes) < 1:
        raise ValueError("pairs, seeds, and routes must be positive")

    kat = _kat()
    causal = _build_graph(
        args.causal_output,
        args.pairs,
        args.seeds,
        args.routes,
    )
    recipe, reader_rows = _recipe_from_reader(args.causal_output)
    confirmations = []
    for seed_index in range(args.seeds):
        seed = args.seed + 1009 * seed_index
        rng = np.random.default_rng(seed)
        print(f"BLAKE3 compression Reader seed={seed_index + 1}/{args.seeds}", flush=True)
        confirmations.append(
            {
                "seed_index": seed_index,
                "seed": seed,
                **_confirm_seed(
                    _random_inputs(rng, args.pairs),
                    recipe,
                    args.routes,
                    seed ^ 0xB3A3,
                ),
            }
        )
    retained = all(
        row["default_32_byte_pair_xor_projection"]["state_accuracy"] == 1.0
        and row["factual_full_output_reader"]["state_accuracy"] == 1.0
        and row["factual_above_all_bvn_routes"]
        for row in confirmations
    )
    payload = {
        "schema": "blake3-fullcompression-reader-v1",
        "evidence_stage": (
            "FULLCOMPRESSION_OUTPUT_READER_RETAINED"
            if retained
            else "NEW_OUTPUT_BOUNDARY_IDENTIFIED"
        ),
        "result": (
            "The first 32 output bytes equal eight post-round lane-pair XORs. "
            "Given the complete 64-byte compression output and the input CV, the "
            "Reader reconstructs all 512 post-round bits exactly."
        ),
        "scope": (
            "Seven-round BLAKE3 compression-output relations. Complete state "
            "reconstruction requires the full 64-byte compression output and known "
            "input CV; it is not asserted for a standalone 32-byte digest."
        ),
        "parameters": {
            "rounds": 7,
            "pairs_per_seed": args.pairs,
            "seeds": args.seeds,
            "bvn_routes": args.routes,
            "seed": args.seed,
        },
        "kat": kat,
        "causal": causal,
        "reader_triplets": reader_rows,
        "confirmation": confirmations,
        "retained": retained,
    }
    raw = (json.dumps(payload, indent=2, sort_keys=True) + "\n").encode()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_bytes(raw)
    print(
        json.dumps(
            {
                "output": str(args.output),
                "sha256": hashlib.sha256(raw).hexdigest(),
                "retained": retained,
                "xof_vectors": len(kat["vectors"]),
                "factual_state_matches": [
                    row["factual_full_output_reader"]["state_matches"]
                    for row in confirmations
                ],
                "bvn_total_state_matches": [
                    row["bvn_routes"]["total_state_matches"]
                    for row in confirmations
                ],
            },
            indent=2,
        )
    )


if __name__ == "__main__":
    main()

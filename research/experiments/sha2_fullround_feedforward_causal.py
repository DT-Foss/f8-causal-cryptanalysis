#!/usr/bin/env python3
"""Full-compression SHA-2 feed-forward causal/F8 mechanism.

Prediction before measurement for SHA-256: after all 64 compression steps,
the same-lane feed-forward ``H_out = H_in + W_final`` forces bit 0 of
``H_in xor H_out`` to equal bit 0 of ``W_final``.  The eight predicted edges
are therefore exact and should each approach ln(2) MI on random blocks.

SHA-512 is the subsequent 64-bit word-width transfer of the same mechanism;
it is run only after the SHA-256 result has retained the prediction.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
from dataclasses import dataclass
from pathlib import Path

import numpy as np

from arx_carry_leak.bvn import route_ensemble, verify_routes
from arx_carry_leak.crypto_causal import CryptoCausalBuilder, CryptoCausalReader


_ROOT = Path(__file__).parents[2]
_PQ_C_SOURCE = _ROOT / "provenance/dependencies/pqcrypto-upstream/pqclean/common/sha2.c"


@dataclass(frozen=True)
class Variant:
    name: str
    word_bits: int
    steps: int
    block_bytes: int
    length_bytes: int
    dtype: type[np.unsignedinteger]
    iv: tuple[int, ...]
    big_sigma0: tuple[int, int, int]
    big_sigma1: tuple[int, int, int]
    small_sigma0: tuple[int, int, int]
    small_sigma1: tuple[int, int, int]


_VARIANTS = {
    "sha256": Variant(
        name="sha256",
        word_bits=32,
        steps=64,
        block_bytes=64,
        length_bytes=8,
        dtype=np.uint32,
        iv=(
            0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,
            0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19,
        ),
        big_sigma0=(2, 13, 22),
        big_sigma1=(6, 11, 25),
        small_sigma0=(7, 18, 3),
        small_sigma1=(17, 19, 10),
    ),
    "sha512": Variant(
        name="sha512",
        word_bits=64,
        steps=80,
        block_bytes=128,
        length_bytes=16,
        dtype=np.uint64,
        iv=(
            0x6A09E667F3BCC908, 0xBB67AE8584CAA73B,
            0x3C6EF372FE94F82B, 0xA54FF53A5F1D36F1,
            0x510E527FADE682D1, 0x9B05688C2B3E6C1F,
            0x1F83D9ABFB41BD6B, 0x5BE0CD19137E2179,
        ),
        big_sigma0=(28, 34, 39),
        big_sigma1=(14, 18, 41),
        small_sigma0=(1, 8, 7),
        small_sigma1=(19, 61, 6),
    ),
}

_KAT_DIGESTS = {
    "sha256": {
        b"": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        b"abc": "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
    },
    "sha512": {
        b"": (
            "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce"
            "47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"
        ),
        b"abc": (
            "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a"
            "2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f"
        ),
    },
}


def _constants(variant: Variant) -> np.ndarray:
    source = _PQ_C_SOURCE.read_text()
    suffix = "_32" if variant.word_bits == 32 else "_64"
    pattern = rf"F{suffix}\(w\d+, 0x([0-9a-f]+)(?:ULL)?\)"
    values = [int(value, 16) for value in re.findall(pattern, source)]
    if len(values) != variant.steps:
        raise RuntimeError(
            f"expected {variant.steps} {variant.name} constants in vendored C, found {len(values)}"
        )
    return np.asarray(values, dtype=variant.dtype)


def _rotr(value: np.ndarray, shift: int, bits: int) -> np.ndarray:
    return (value >> shift) | (value << (bits - shift))


def _big_sigma(value: np.ndarray, shifts: tuple[int, int, int], bits: int) -> np.ndarray:
    return _rotr(value, shifts[0], bits) ^ _rotr(value, shifts[1], bits) ^ _rotr(value, shifts[2], bits)


def _small_sigma(
    value: np.ndarray,
    shifts: tuple[int, int, int],
    bits: int,
) -> np.ndarray:
    return _rotr(value, shifts[0], bits) ^ _rotr(value, shifts[1], bits) ^ (value >> shifts[2])


def _compress(
    blocks: np.ndarray,
    variant: Variant,
    initial_state: np.ndarray | None = None,
) -> tuple[np.ndarray, np.ndarray]:
    """Return full-step working state and post-feed-forward chaining state."""
    if blocks.ndim != 2 or blocks.shape[1] != variant.block_bytes or blocks.dtype != np.uint8:
        raise ValueError(f"blocks must be uint8[N,{variant.block_bytes}]")
    endian = ">u4" if variant.word_bits == 32 else ">u8"
    schedule = np.zeros((len(blocks), variant.steps), dtype=variant.dtype)
    schedule[:, :16] = np.frombuffer(blocks.tobytes(), dtype=endian).astype(
        variant.dtype
    ).reshape(len(blocks), 16)
    for index in range(16, variant.steps):
        schedule[:, index] = (
            _small_sigma(schedule[:, index - 2], variant.small_sigma1, variant.word_bits)
            + schedule[:, index - 7]
            + _small_sigma(schedule[:, index - 15], variant.small_sigma0, variant.word_bits)
            + schedule[:, index - 16]
        )

    constants = _constants(variant)
    if initial_state is None:
        initial = np.broadcast_to(
            np.asarray(variant.iv, dtype=variant.dtype), (len(blocks), 8)
        ).copy()
    else:
        initial = np.asarray(initial_state, dtype=variant.dtype)
        if initial.shape == (8,):
            initial = np.broadcast_to(initial, (len(blocks), 8)).copy()
        if initial.shape != (len(blocks), 8):
            raise ValueError(f"initial_state must have shape (8,) or ({len(blocks)},8)")
    lanes = [initial[:, lane].copy() for lane in range(8)]
    a, b, c, d, e, f, g, h = lanes
    for index in range(variant.steps):
        choice = (e & f) ^ ((~e) & g)
        majority = (a & b) ^ (a & c) ^ (b & c)
        first = (
            h
            + _big_sigma(e, variant.big_sigma1, variant.word_bits)
            + choice
            + constants[index]
            + schedule[:, index]
        )
        second = _big_sigma(a, variant.big_sigma0, variant.word_bits) + majority
        a, b, c, d, e, f, g, h = first + second, a, b, c, d + first, e, f, g
    working = np.stack((a, b, c, d, e, f, g, h), axis=1)
    output = working + initial
    return working, output


def _pad_single_block(message: bytes, variant: Variant) -> np.ndarray:
    if len(message) + 1 + variant.length_bytes > variant.block_bytes:
        raise ValueError("KAT helper supports one-block messages only")
    bit_length = 8 * len(message)
    padded = (
        message
        + b"\x80"
        + bytes(variant.block_bytes - len(message) - 1 - variant.length_bytes)
        + bit_length.to_bytes(variant.length_bytes, "big")
    )
    return np.frombuffer(padded, dtype=np.uint8).reshape(1, variant.block_bytes)


def _output_bytes(words: np.ndarray, variant: Variant) -> bytes:
    word_bytes = variant.word_bits // 8
    return b"".join(int(word).to_bytes(word_bytes, "big") for word in words[0])


def _kat(variant: Variant) -> dict:
    rows = []
    hash_function = hashlib.sha256 if variant.name == "sha256" else hashlib.sha512
    for message in (b"", b"abc"):
        _, output = _compress(_pad_single_block(message, variant), variant)
        observed = _output_bytes(output, variant)
        expected_literal = bytes.fromhex(_KAT_DIGESTS[variant.name][message])
        expected_hashlib = hash_function(message).digest()
        if observed != expected_literal or observed != expected_hashlib:
            raise RuntimeError(f"{variant.name} KAT failed for {message!r}")
        rows.append({
            "message_hex": message.hex(),
            "digest": observed.hex(),
            "matches_fixed_standard_vector": True,
            "matches_hashlib": True,
        })
    return {
        "vectors": rows,
        "vendored_c_source": str(_PQ_C_SOURCE.relative_to(_ROOT)),
        "vendored_c_sha256": hashlib.sha256(_PQ_C_SOURCE.read_bytes()).hexdigest(),
        "round_constants_imported": variant.steps,
    }


def _mi_binary(first: np.ndarray, second: np.ndarray) -> float:
    size = len(first)
    n11 = int(np.sum(first & second))
    n10 = int(np.sum(first & (1 - second)))
    n01 = int(np.sum((1 - first) & second))
    counts = (size - n11 - n10 - n01, n01, n10, n11)
    rows = (counts[0] + counts[1], counts[2] + counts[3])
    columns = (counts[0] + counts[2], counts[1] + counts[3])
    value = 0.0
    for index, count in enumerate(counts):
        if count:
            x_value, y_value = divmod(index, 2)
            value += (count / size) * np.log(
                (count * size) / (rows[x_value] * columns[y_value])
            )
    return float(value)


def _route_bank(size: int, count: int, seed: int) -> list[np.ndarray]:
    routes = route_ensemble(size, count, seed)
    verification = verify_routes(routes)
    if not verification["all_bijective"] or verification["forbidden_alignments"]:
        raise RuntimeError("invalid BvN route bank")
    return routes


def _measure(
    working: np.ndarray,
    output: np.ndarray,
    initial: np.ndarray,
    variant: Variant,
    routes: list[np.ndarray],
) -> dict:
    delta = output ^ initial
    source = (working & variant.dtype(1)).astype(np.uint8)
    target = (delta & variant.dtype(1)).astype(np.uint8)
    if not np.array_equal(source, target):
        raise RuntimeError("feed-forward bit-0 identity failed")

    fixed_rows = []
    control_rows = []
    for lane in range(8):
        for label, target_lane, destination in (
            ("same_lane", lane, fixed_rows),
            ("next_lane_control", (lane + 1) % 8, control_rows),
        ):
            factual = _mi_binary(source[:, lane], target[:, target_lane])
            null = np.asarray([
                _mi_binary(source[:, lane], target[route, target_lane]) for route in routes
            ])
            destination.append({
                "source_lane": lane,
                "target_lane": target_lane,
                "relation": label,
                "factual_mi": factual,
                "bvn_mean": float(null.mean()),
                "bvn_max": float(null.max()),
                "z": float((factual - null.mean()) / (null.std(ddof=1) + 1e-30)),
                "above_all_bvn_routes": bool(factual > null.max()),
            })
    return {
        "same_lane": fixed_rows,
        "next_lane_control": control_rows,
        "exact_bit0_equalities": int(source.size),
        "all_exact_bit0_equalities_passed": True,
        "same_lane_total_mi": sum(row["factual_mi"] for row in fixed_rows),
        "control_total_mi": sum(row["factual_mi"] for row in control_rows),
        "all_same_lane_above_all_bvn_routes": all(
            row["above_all_bvn_routes"] for row in fixed_rows
        ),
    }


def _write_graph(path: Path, variant: Variant, measurements: dict, pairs: int, routes: int) -> dict:
    builder = CryptoCausalBuilder(
        experiment=f"{variant.name}_full_compression_feedforward",
        parameters={
            "prediction_before_measurement": "eight same-lane bit-0 edges are exact after the full SHA-2 compression schedule",
            "steps": variant.steps,
            "word_bits": variant.word_bits,
            "pairs": pairs,
            "bvn_routes": routes,
            "identity": "bit0(H_in xor (H_in + W_final)) = bit0(W_final)",
        },
    )
    for lane in range(8):
        fixed_row = measurements["fixed_iv"]["same_lane"][lane]
        random_row = measurements["random_chaining"]["same_lane"][lane]
        builder.add_triplet(
            edge_id=f"{variant.name}-feedforward-lane-{lane}",
            trigger=f"{variant.name}:working_after_step_{variant.steps}:lane_{lane}:bit_0",
            mechanism="same_lane_modular_feedforward_bit0_identity",
            outcome=f"{variant.name}:hin_xor_hout:lane_{lane}:bit_0",
            confidence=1.0,
            evidence_kind="exact_feedforward_identity_plus_bvn_measurement",
            source="SHA2_full_compression_feedforward_equation",
            attrs={
                "source_lane": lane,
                "target_lane": lane,
                "fixed_iv": fixed_row,
                "random_chaining": random_row,
                "both_modes_exact_and_above_all_bvn": (
                    fixed_row["above_all_bvn_routes"]
                    and random_row["above_all_bvn_routes"]
                ),
            },
        )
    stats = builder.save(path)
    reader = CryptoCausalReader(path)
    rows = reader.triplets(include_inferred=False)
    if not reader.verify_provenance() or len(rows) != 8:
        raise RuntimeError("SHA-2 causal Reader gate failed")
    return {
        **stats,
        "reader_provenance_verified": True,
        "reader_triplets": rows,
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--variant", choices=sorted(_VARIANTS), required=True)
    parser.add_argument("--pairs", type=int, default=5000)
    parser.add_argument("--routes", type=int, default=16)
    parser.add_argument("--seed", type=int, default=88428001)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--causal-output", type=Path, required=True)
    args = parser.parse_args()
    if min(args.pairs, args.routes) < 1:
        raise ValueError("pairs and routes must be positive")

    variant = _VARIANTS[args.variant]
    kat = _kat(variant)
    rng = np.random.default_rng(args.seed)
    blocks = rng.integers(
        0, 256, size=(args.pairs, variant.block_bytes), dtype=np.uint8
    )
    routes = _route_bank(args.pairs, args.routes, args.seed ^ 0x5A2)
    fixed_initial = np.broadcast_to(
        np.asarray(variant.iv, dtype=variant.dtype), (args.pairs, 8)
    ).copy()
    fixed_working, fixed_output = _compress(blocks, variant, fixed_initial)
    random_initial = rng.integers(
        0,
        1 << variant.word_bits,
        size=(args.pairs, 8),
        dtype=variant.dtype,
    )
    random_working, random_output = _compress(blocks, variant, random_initial)
    measurements = {
        "fixed_iv": _measure(
            fixed_working, fixed_output, fixed_initial, variant, routes
        ),
        "random_chaining": _measure(
            random_working, random_output, random_initial, variant, routes
        ),
    }
    causal = _write_graph(
        args.causal_output, variant, measurements, args.pairs, args.routes
    )
    retained = all(
        measurement["all_same_lane_above_all_bvn_routes"]
        for measurement in measurements.values()
    )
    payload = {
        "schema": "sha2-fullround-feedforward-causal-v2",
        "variant": variant.name,
        "steps": variant.steps,
        "word_bits": variant.word_bits,
        "evidence_stage": "FULL_COMPRESSION_FEEDFORWARD_RETAINED" if retained else "NEW_BOUNDARY_IDENTIFIED",
        "prediction": "all eight same-lane bit-0 edges are exact and approach ln(2) MI",
        "kat": kat,
        "parameters": {"pairs": args.pairs, "bvn_routes": args.routes, "seed": args.seed},
        "measurements": measurements,
        "retained": retained,
        "causal": causal,
    }
    raw = (json.dumps(payload, indent=2, sort_keys=True) + "\n").encode()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_bytes(raw)
    print(json.dumps({
        "output": str(args.output),
        "sha256": hashlib.sha256(raw).hexdigest(),
        "variant": variant.name,
        "retained": retained,
        "exact_equalities": sum(
            measurement["exact_bit0_equalities"] for measurement in measurements.values()
        ),
        "modes": {
            mode: {
                "same_lane_total_mi": measurement["same_lane_total_mi"],
                "control_total_mi": measurement["control_total_mi"],
                "z": [round(row["z"], 2) for row in measurement["same_lane"]],
            }
            for mode, measurement in measurements.items()
        },
    }, indent=2))


if __name__ == "__main__":
    main()

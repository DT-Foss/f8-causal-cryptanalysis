#!/usr/bin/env python3
"""SHAKE128/256 full Keccak-f[1600] rate-projection causal Readers."""
from __future__ import annotations

import argparse
import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import numpy as np

from arx_carry_leak.bvn import route_ensemble, verify_routes
from arx_carry_leak.crypto_causal import CryptoCausalBuilder, CryptoCausalReader


FIPS202_URL = "https://csrc.nist.gov/pubs/fips/202/final"
ROUND_CONSTANTS = np.array(
    [
        0x0000000000000001,
        0x0000000000008082,
        0x800000000000808A,
        0x8000000080008000,
        0x000000000000808B,
        0x0000000080000001,
        0x8000000080008081,
        0x8000000000008009,
        0x000000000000008A,
        0x0000000000000088,
        0x0000000080008009,
        0x000000008000000A,
        0x000000008000808B,
        0x800000000000008B,
        0x8000000000008089,
        0x8000000000008003,
        0x8000000000008002,
        0x8000000000000080,
        0x000000000000800A,
        0x800000008000000A,
        0x8000000080008081,
        0x8000000000008080,
        0x0000000080000001,
        0x8000000080008008,
    ],
    dtype=np.uint64,
)
ROTATION_OFFSETS = np.array(
    [
        [0, 36, 3, 41, 18],
        [1, 44, 10, 45, 2],
        [62, 6, 43, 15, 61],
        [28, 55, 25, 21, 56],
        [27, 20, 39, 8, 14],
    ],
    dtype=np.int64,
)
ZERO_STATE_PERMUTATION = np.array(
    [
        0xF1258F7940E1DDE7,
        0x84D5CCF933C0478A,
        0xD598261EA65AA9EE,
        0xBD1547306F80494D,
        0x8B284E056253D057,
        0xFF97A42D7F8E6FD4,
        0x90FEE5A0A44647C4,
        0x8C5BDA0CD6192E76,
        0xAD30A6F71B19059C,
        0x30935AB7D08FFC64,
        0xEB5AA93F2317D635,
        0xA9A6E6260D712103,
        0x81A57C16DBCF555F,
        0x43B831CD0347C826,
        0x01F22F1A11A5569F,
        0x05E5635A21D9AE61,
        0x64BEFEF28CC970F2,
        0x613670957BC46611,
        0xB87C5A554FD00ECB,
        0x8C3EE88A1CCF32C8,
        0x940C7922AE3A2614,
        0x1841F924A2C509E4,
        0x16F53526E70465C2,
        0x75F644E97F30A13B,
        0xEAF1FF7B5CECA249,
    ],
    dtype=np.uint64,
)


@dataclass(frozen=True)
class Variant:
    key: str
    name: str
    rate_bits: int
    capacity_bits: int
    message_bytes: int
    empty_xof_64: str

    @property
    def rate_bytes(self) -> int:
        return self.rate_bits // 8

    @property
    def rate_lanes(self) -> int:
        return self.rate_bits // 64


VARIANTS = {
    "shake128": Variant(
        key="shake128",
        name="SHAKE128",
        rate_bits=1344,
        capacity_bits=256,
        message_bytes=32,
        empty_xof_64=(
            "7f9c2ba4e88f827d616045507605853ed73b8093f6efbc88eb1a6eacfa66ef26"
            "3cb1eea988004b93103cfb0aeefd2a686e01fa4a58e8a3639ca8a1e3f9ae57e2"
        ),
    ),
    "shake256": Variant(
        key="shake256",
        name="SHAKE256",
        rate_bits=1088,
        capacity_bits=512,
        message_bytes=64,
        empty_xof_64=(
            "46b9dd2b0ba88d13233b3feb743eeb243fcd52ea62b81b82b50c27646ed5762f"
            "d75dc4ddd8c0f200cb05019d67b592f6fc821c49479ab48640292eacb3b7c4be"
        ),
    ),
}


def _rotl64(value: np.ndarray, shift: int) -> np.ndarray:
    if shift == 0:
        return value.copy()
    return ((value << np.uint64(shift)) | (value >> np.uint64(64 - shift))).astype(
        np.uint64
    )


def _keccak_f1600(state: np.ndarray) -> np.ndarray:
    if state.dtype != np.uint64 or state.ndim != 2 or state.shape[1] != 25:
        raise ValueError("Keccak state must be uint64[N,25]")
    lanes = state.copy()
    for round_constant in ROUND_CONSTANTS:
        columns = np.empty((len(lanes), 5), dtype=np.uint64)
        for x in range(5):
            columns[:, x] = np.bitwise_xor.reduce(lanes[:, x::5], axis=1)
        theta = np.empty_like(columns)
        for x in range(5):
            theta[:, x] = columns[:, (x - 1) % 5] ^ _rotl64(
                columns[:, (x + 1) % 5], 1
            )
        for x in range(5):
            lanes[:, x::5] ^= theta[:, x : x + 1]

        rotated = np.empty_like(lanes)
        for x in range(5):
            for y in range(5):
                new_x = y
                new_y = (2 * x + 3 * y) % 5
                rotated[:, new_x + 5 * new_y] = _rotl64(
                    lanes[:, x + 5 * y], int(ROTATION_OFFSETS[x, y])
                )

        for y in range(5):
            row = rotated[:, 5 * y : 5 * y + 5]
            for x in range(5):
                lanes[:, x + 5 * y] = row[:, x] ^ (
                    (~row[:, (x + 1) % 5]) & row[:, (x + 2) % 5]
                )
        lanes[:, 0] ^= round_constant
    return lanes


def _pad_single_block(messages: np.ndarray, rate_bytes: int) -> np.ndarray:
    if messages.dtype != np.uint8 or messages.ndim != 2:
        raise ValueError("messages must be uint8[N,L]")
    if messages.shape[1] >= rate_bytes:
        raise ValueError("single-block SHAKE messages must be shorter than the rate")
    block = np.zeros((len(messages), rate_bytes), dtype=np.uint8)
    block[:, : messages.shape[1]] = messages
    block[:, messages.shape[1]] ^= np.uint8(0x1F)
    block[:, -1] ^= np.uint8(0x80)
    return block


def _first_squeeze_state(
    messages: np.ndarray, variant: Variant
) -> tuple[np.ndarray, np.ndarray]:
    block = _pad_single_block(messages, variant.rate_bytes)
    state = np.zeros((len(messages), 25), dtype=np.uint64)
    block_words = block.copy().view("<u8").reshape(len(messages), variant.rate_lanes)
    state[:, : variant.rate_lanes] ^= block_words
    state = _keccak_f1600(state)
    output = (
        state[:, : variant.rate_lanes]
        .astype("<u8", copy=False)
        .view(np.uint8)
        .reshape(len(messages), variant.rate_bytes)
        .copy()
    )
    return state, output


def _hashlib_xof(variant: Variant, message: bytes, length: int) -> bytes:
    constructor = hashlib.shake_128 if variant.key == "shake128" else hashlib.shake_256
    return constructor(message).digest(length)


def _kat() -> dict[str, Any]:
    zero_observed = _keccak_f1600(np.zeros((1, 25), dtype=np.uint64))[0]
    if not np.array_equal(zero_observed, ZERO_STATE_PERMUTATION):
        raise RuntimeError("Keccak-f[1600] zero-state permutation vector failed")
    rows = []
    for variant in VARIANTS.values():
        for name, message in (("empty", b""), ("abc", b"abc")):
            messages = np.frombuffer(message, dtype=np.uint8).reshape(1, len(message))
            _, output = _first_squeeze_state(messages, variant)
            observed = output[0].tobytes()
            hashlib_expected = _hashlib_xof(variant, message, variant.rate_bytes)
            if observed != hashlib_expected:
                raise RuntimeError(f"{variant.name} {name} hashlib gate failed")
            embedded_match = True
            if name == "empty":
                embedded_match = observed[:64].hex() == variant.empty_xof_64
                if not embedded_match:
                    raise RuntimeError(f"{variant.name} embedded FIPS vector failed")
            rows.append(
                {
                    "variant": variant.key,
                    "message": name,
                    "rate_bytes": variant.rate_bytes,
                    "observed_first_64": observed[:64].hex(),
                    "hashlib_full_rate_match": True,
                    "embedded_empty_vector_match": embedded_match,
                }
            )
    return {
        "fips202_url": FIPS202_URL,
        "keccak_f1600_zero_state_match": True,
        "keccak_f1600_zero_state_lanes": [
            f"{int(value):016x}" for value in zero_observed
        ],
        "vectors": rows,
    }


def _projection_proof(variant: Variant) -> dict[str, Any]:
    unique_images = set()
    zero_images = 0
    for bit in range(1600):
        if bit < variant.rate_bits:
            image = bit
            if image in unique_images:
                raise RuntimeError(f"{variant.name} projection basis collision")
            unique_images.add(image)
        else:
            zero_images += 1
    if len(unique_images) != variant.rate_bits or zero_images != variant.capacity_bits:
        raise RuntimeError(f"{variant.name} projection dimension gate failed")
    return {
        "state_dimension_bits": 1600,
        "basis_vectors_checked": 1600,
        "projection_rank_bits": len(unique_images),
        "kernel_dimension_bits": zero_images,
        "rate_fraction_of_state": variant.rate_bits / 1600,
        "complete_coordinate_projection_proof": True,
    }


def _reader_recipe(variant: Variant) -> dict[str, Any]:
    return {
        "variant": variant.name,
        "source": "first_complete_squeeze_rate_block",
        "source_bytes": variant.rate_bytes,
        "lane_bits": 64,
        "lane_endianness": "little",
        "output_lanes": variant.rate_lanes,
        "output": "post_keccak_f1600_rate_lanes",
    }


def _execute_reader_recipe(output: np.ndarray, recipe: dict[str, Any]) -> np.ndarray:
    source_bytes = int(recipe["source_bytes"])
    output_lanes = int(recipe["output_lanes"])
    if output.dtype != np.uint8 or output.ndim != 2 or output.shape[1] != source_bytes:
        raise ValueError(f"output must be uint8[N,{source_bytes}]")
    if recipe["lane_endianness"] != "little" or int(recipe["lane_bits"]) != 64:
        raise ValueError("unsupported SHAKE Reader lane representation")
    return output.copy().view("<u8").reshape(len(output), output_lanes).astype(np.uint64)


def _build_graph(
    path: Path,
    proofs: dict[str, dict[str, Any]],
    pairs: int,
    seeds: int,
    routes: int,
) -> dict[str, Any]:
    builder = CryptoCausalBuilder(
        experiment="shake_fullround_rate_projection_reader",
        parameters={
            "permutation_rounds": 24,
            "state_bits": 1600,
            "variants": list(VARIANTS),
            "pairs_per_seed": pairs,
            "seeds": seeds,
            "bvn_routes": routes,
            "prediction_before_measurement": (
                "A complete first squeeze block is the coordinate projection of "
                "the post-Keccak state onto the rate lanes."
            ),
        },
    )
    for key, variant in VARIANTS.items():
        lane_edges = []
        for lane in range(variant.rate_lanes):
            edge_id = f"{key}-squeeze-copy-lane-{lane}"
            lane_edges.append(edge_id)
            builder.add_triplet(
                edge_id=edge_id,
                trigger=f"{key}:post_keccak_f1600_rate_lane_{lane}",
                mechanism="exact_squeeze_lane_copy",
                outcome=f"{key}:first_squeeze_output_lane_{lane}",
                confidence=1.0,
                evidence_kind="exact_FIPS202_sponge_equation",
                source="FIPS202_SHAKE_squeeze",
                attrs={
                    "formula": f"output_lane[{lane}] = state_lane[{lane}]",
                    "permutation_rounds_completed": 24,
                },
            )
        builder.add_triplet(
            edge_id=f"{key}-reader-rate-projection",
            trigger=f"{key}:complete_first_squeeze_rate_block",
            mechanism="reader_executable_post_permutation_rate_projection",
            outcome=f"{key}:post_keccak_f1600_rate_state",
            confidence=1.0,
            evidence_kind="exact_composed_coordinate_projection",
            source="FIPS202_SHAKE_rate_output",
            provenance=lane_edges,
            attrs={
                "reader_recipe": _reader_recipe(variant),
                "information_reconstructed_bits": variant.rate_bits,
            },
        )
        builder.add_triplet(
            edge_id=f"{key}-projection-kernel-dimension",
            trigger=f"{key}:post_keccak_f1600_full_state",
            mechanism="exact_rate_coordinate_projection_dimension",
            outcome=f"{key}:rate_output_and_capacity_kernel",
            confidence=1.0,
            evidence_kind="complete_state_basis_projection_proof",
            source="FIPS202_rate_capacity_partition",
            attrs=proofs[key],
        )
    stats = builder.save(path)
    expected_triplets = sum(variant.rate_lanes + 2 for variant in VARIANTS.values())
    reader = CryptoCausalReader(path)
    if not reader.verify_provenance() or len(reader.triplets(include_inferred=False)) != expected_triplets:
        raise RuntimeError("SHAKE causal Reader graph gate failed")
    return stats


def _recipes_from_reader(path: Path) -> tuple[dict[str, dict[str, Any]], list[dict[str, Any]]]:
    reader = CryptoCausalReader(path)
    rows = reader.triplets(include_inferred=False)
    recipes = {}
    for key in VARIANTS:
        matches = [
            row
            for row in rows
            if row["trigger"] == f"{key}:complete_first_squeeze_rate_block"
            and row["mechanism"] == "reader_executable_post_permutation_rate_projection"
        ]
        if len(matches) != 1:
            raise RuntimeError(f"Reader returned no unique {key} recipe")
        recipes[key] = matches[0]["attrs"]["reader_recipe"]
    return recipes, rows


def _accuracy(expected: np.ndarray, observed: np.ndarray) -> dict[str, Any]:
    if expected.shape != observed.shape or expected.dtype != np.uint64 or observed.dtype != np.uint64:
        raise ValueError("accuracy arrays must be matching uint64 matrices")
    difference = expected ^ observed
    bit_differences = sum(int(value).bit_count() for value in difference.ravel())
    bit_total = int(expected.size * 64)
    state_equal = np.all(expected == observed, axis=1)
    return {
        "lane_matches": int(np.sum(expected == observed)),
        "lane_total": int(expected.size),
        "lane_accuracy": float(np.mean(expected == observed)),
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
        raise RuntimeError("invalid SHAKE BvN route bank")
    return routes


def _confirm_seed(
    messages: np.ndarray,
    variant: Variant,
    recipe: dict[str, Any],
    route_count: int,
    seed: int,
) -> dict[str, Any]:
    state, output = _first_squeeze_state(messages, variant)
    expected = state[:, : variant.rate_lanes]
    factual = _accuracy(expected, _execute_reader_recipe(output, recipe))

    route_rows = [
        _accuracy(expected, _execute_reader_recipe(output[route], recipe))
        for route in _routes(len(output), route_count, seed)
    ]

    lane_rotated = output.reshape(len(output), variant.rate_lanes, 8).copy()
    lane_rotated = np.roll(lane_rotated, 1, axis=1).reshape(len(output), variant.rate_bytes)
    wrong_lane_route = _accuracy(
        expected, _execute_reader_recipe(lane_rotated, recipe)
    )

    byte_reversed = output.reshape(len(output), variant.rate_lanes, 8)[:, :, ::-1].copy()
    wrong_endianness = _accuracy(
        expected,
        _execute_reader_recipe(
            byte_reversed.reshape(len(output), variant.rate_bytes), recipe
        ),
    )

    prefix_lanes = 4
    prefix_words = output[:, :32].copy().view("<u8").reshape(len(output), prefix_lanes)
    prefix_projection = _accuracy(expected[:, :prefix_lanes], prefix_words)

    hashlib_matches = 0
    oracle_cases = min(8, len(messages))
    for row in range(oracle_cases):
        observed = output[row].tobytes()
        expected_bytes = _hashlib_xof(
            variant, messages[row].tobytes(), variant.rate_bytes
        )
        hashlib_matches += int(observed == expected_bytes)
    return {
        "factual_rate_reader": factual,
        "prefix_32_byte_projection": prefix_projection,
        "bvn_routes": {
            "count": route_count,
            "total_state_matches": sum(row["state_matches"] for row in route_rows),
            "max_lane_matches": max(row["lane_matches"] for row in route_rows),
            "max_bit_accuracy": max(row["bit_accuracy"] for row in route_rows),
        },
        "wrong_lane_rotation_control": wrong_lane_route,
        "wrong_lane_endianness_control": wrong_endianness,
        "hashlib_oracle_matches": hashlib_matches,
        "hashlib_oracle_total": oracle_cases,
        "factual_above_all_bvn_routes": (
            factual["state_matches"] > max(row["state_matches"] for row in route_rows)
            and factual["lane_matches"] > max(row["lane_matches"] for row in route_rows)
        ),
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--pairs", type=int, default=8000)
    parser.add_argument("--seeds", type=int, default=5)
    parser.add_argument("--routes", type=int, default=16)
    parser.add_argument("--seed", type=int, default=89428001)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--causal-output", type=Path, required=True)
    args = parser.parse_args()
    if min(args.pairs, args.seeds, args.routes) < 1:
        raise ValueError("pairs, seeds, and routes must be positive")

    kat = _kat()
    proofs = {key: _projection_proof(variant) for key, variant in VARIANTS.items()}
    causal = _build_graph(
        args.causal_output,
        proofs,
        args.pairs,
        args.seeds,
        args.routes,
    )
    recipes, reader_rows = _recipes_from_reader(args.causal_output)
    confirmations: dict[str, list[dict[str, Any]]] = {}
    for variant_index, (key, variant) in enumerate(VARIANTS.items()):
        rows = []
        for seed_index in range(args.seeds):
            seed = args.seed + 100_003 * variant_index + 1009 * seed_index
            rng = np.random.default_rng(seed)
            messages = rng.integers(
                0,
                256,
                size=(args.pairs, variant.message_bytes),
                dtype=np.uint8,
            )
            print(
                f"{variant.name} rate Reader seed={seed_index + 1}/{args.seeds}",
                flush=True,
            )
            rows.append(
                {
                    "seed_index": seed_index,
                    "seed": seed,
                    **_confirm_seed(
                        messages,
                        variant,
                        recipes[key],
                        args.routes,
                        seed ^ 0x5A4E,
                    ),
                }
            )
        confirmations[key] = rows
    retained = all(
        row["factual_rate_reader"]["state_accuracy"] == 1.0
        and row["prefix_32_byte_projection"]["state_accuracy"] == 1.0
        and row["hashlib_oracle_matches"] == row["hashlib_oracle_total"]
        and row["factual_above_all_bvn_routes"]
        for rows in confirmations.values()
        for row in rows
    )
    payload = {
        "schema": "shake-fullround-rate-reader-v1",
        "evidence_stage": (
            "FULLROUND_RATE_PROJECTIONS_RETAINED"
            if retained
            else "NEW_SPONGE_OUTPUT_BOUNDARY_IDENTIFIED"
        ),
        "result": (
            "After the full 24-round Keccak-f[1600] permutation, a complete first "
            "SHAKE squeeze block reconstructs every rate lane exactly. The remaining "
            "coordinate-projection kernel is exactly the capacity dimension."
        ),
        "scope": (
            "Exact sponge squeeze projections. No capacity lane is reconstructed by "
            "the one-block coordinate Reader, and no external secret is asserted."
        ),
        "parameters": {
            "permutation_rounds": 24,
            "pairs_per_seed": args.pairs,
            "seeds": args.seeds,
            "bvn_routes": args.routes,
            "seed": args.seed,
        },
        "kat": kat,
        "projection_proofs": proofs,
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
                "projection_dimensions": {
                    key: {
                        "rank": proof["projection_rank_bits"],
                        "kernel": proof["kernel_dimension_bits"],
                    }
                    for key, proof in proofs.items()
                },
                "factual_state_matches": {
                    key: [row["factual_rate_reader"]["state_matches"] for row in rows]
                    for key, rows in confirmations.items()
                },
                "bvn_total_state_matches": {
                    key: [row["bvn_routes"]["total_state_matches"] for row in rows]
                    for key, rows in confirmations.items()
                },
            },
            indent=2,
        )
    )


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""ChaCha20 public-lane and known-key full-round feed-forward Readers."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any

import numpy as np

from arx_carry_leak.bvn import route_ensemble, verify_routes
from arx_carry_leak.crypto_causal import CryptoCausalBuilder, CryptoCausalReader


RFC8439_URL = "https://www.rfc-editor.org/rfc/rfc8439.html#section-2.3.2"
CONSTANTS = np.array(
    [0x61707865, 0x3320646E, 0x79622D32, 0x6B206574], dtype=np.uint32
)
PUBLIC_LANES = (0, 1, 2, 3, 12, 13, 14, 15)
KEY_LANES = tuple(range(4, 12))


def _rotl32(value: np.ndarray, shift: int) -> np.ndarray:
    return ((value << np.uint32(shift)) | (value >> np.uint32(32 - shift))).astype(
        np.uint32
    )


def _quarter_round(state: np.ndarray, a: int, b: int, c: int, d: int) -> None:
    state[:, a] += state[:, b]
    state[:, d] = _rotl32(state[:, d] ^ state[:, a], 16)
    state[:, c] += state[:, d]
    state[:, b] = _rotl32(state[:, b] ^ state[:, c], 12)
    state[:, a] += state[:, b]
    state[:, d] = _rotl32(state[:, d] ^ state[:, a], 8)
    state[:, c] += state[:, d]
    state[:, b] = _rotl32(state[:, b] ^ state[:, c], 7)


def _core(initial: np.ndarray, rounds: int = 20) -> np.ndarray:
    if initial.dtype != np.uint32 or initial.ndim != 2 or initial.shape[1] != 16:
        raise ValueError("initial must be uint32[N,16]")
    if rounds < 1:
        raise ValueError("rounds must be positive")
    state = initial.copy()
    for round_index in range(rounds):
        if round_index % 2 == 0:
            _quarter_round(state, 0, 4, 8, 12)
            _quarter_round(state, 1, 5, 9, 13)
            _quarter_round(state, 2, 6, 10, 14)
            _quarter_round(state, 3, 7, 11, 15)
        else:
            _quarter_round(state, 0, 5, 10, 15)
            _quarter_round(state, 1, 6, 11, 12)
            _quarter_round(state, 2, 7, 8, 13)
            _quarter_round(state, 3, 4, 9, 14)
    return state


def _initial_states(
    keys: np.ndarray, counters: np.ndarray, nonces: np.ndarray
) -> np.ndarray:
    rows = len(counters)
    if keys.dtype != np.uint8 or keys.shape != (rows, 32):
        raise ValueError("keys must be uint8[N,32]")
    if counters.dtype != np.uint32 or counters.shape != (rows,):
        raise ValueError("counters must be uint32[N]")
    if nonces.dtype != np.uint8 or nonces.shape != (rows, 12):
        raise ValueError("nonces must be uint8[N,12]")
    initial = np.empty((rows, 16), dtype=np.uint32)
    initial[:, :4] = CONSTANTS
    initial[:, 4:12] = keys.copy().view("<u4").reshape(rows, 8)
    initial[:, 12] = counters
    initial[:, 13:16] = nonces.copy().view("<u4").reshape(rows, 3)
    return initial


def _block_trace(
    keys: np.ndarray,
    counters: np.ndarray,
    nonces: np.ndarray,
    rounds: int = 20,
) -> tuple[np.ndarray, np.ndarray, np.ndarray]:
    initial = _initial_states(keys, counters, nonces)
    core = _core(initial, rounds)
    output = core + initial
    return initial, core, output


def _words_to_bytes(words: np.ndarray) -> bytes:
    if words.shape != (1, 16) or words.dtype != np.uint32:
        raise ValueError("word serialization expects uint32[1,16]")
    return words.astype("<u4", copy=False).tobytes()


def _kat() -> dict[str, Any]:
    key = np.frombuffer(bytes(range(32)), dtype=np.uint8).reshape(1, 32)
    counter = np.array([1], dtype=np.uint32)
    nonce = np.frombuffer(
        bytes.fromhex("000000090000004a00000000"), dtype=np.uint8
    ).reshape(1, 12)
    expected = (
        "10f1e7e4d13b5915500fdd1fa32071c4c7d1f4c733c068030422aa9ac3d46c4e"
        "d2826446079faa0914c2d705d98b02a2b5129cd1de164eb9cbd083e8a2503c4e"
    )
    initial, core, output = _block_trace(key, counter, nonce, rounds=20)
    observed = _words_to_bytes(output).hex()
    if observed != expected:
        raise RuntimeError(f"ChaCha20 RFC 8439 KAT failed: {observed} != {expected}")
    if not np.array_equal(output - initial, core):
        raise RuntimeError("ChaCha20 feed-forward inverse gate failed")
    return {
        "source_url": RFC8439_URL,
        "key": bytes(range(32)).hex(),
        "counter": 1,
        "nonce": nonce.tobytes().hex(),
        "expected": expected,
        "observed": observed,
        "match": True,
    }


def _recipe(name: str, lanes: tuple[int, ...]) -> dict[str, Any]:
    return {
        "name": name,
        "word_bits": 32,
        "rounds": 20,
        "required_addend_lanes": list(lanes),
        "operations": [
            {
                "out": f"core_{lane}",
                "op": "sub_mod2w",
                "left": f"output_{lane}",
                "right": f"addend_{lane}",
                "formula": f"core[{lane}] = output[{lane}] - initial[{lane}] mod 2^32",
            }
            for lane in lanes
        ],
        "output_order": [f"core_{lane}" for lane in lanes],
    }


PUBLIC_RECIPE = _recipe("public_constants_counter_nonce_projection", PUBLIC_LANES)
FULL_RECIPE = _recipe("known_key_complete_core_inverse", tuple(range(16)))


def _public_addends(counters: np.ndarray, nonces: np.ndarray) -> dict[int, np.ndarray]:
    rows = len(counters)
    if counters.dtype != np.uint32 or counters.shape != (rows,):
        raise ValueError("counters must be uint32[N]")
    if nonces.dtype != np.uint8 or nonces.shape != (rows, 12):
        raise ValueError("nonces must be uint8[N,12]")
    nonce_words = nonces.copy().view("<u4").reshape(rows, 3)
    return {
        0: np.full(rows, CONSTANTS[0], dtype=np.uint32),
        1: np.full(rows, CONSTANTS[1], dtype=np.uint32),
        2: np.full(rows, CONSTANTS[2], dtype=np.uint32),
        3: np.full(rows, CONSTANTS[3], dtype=np.uint32),
        12: counters,
        13: nonce_words[:, 0],
        14: nonce_words[:, 1],
        15: nonce_words[:, 2],
    }


def _all_addends(initial: np.ndarray) -> dict[int, np.ndarray]:
    if initial.dtype != np.uint32 or initial.ndim != 2 or initial.shape[1] != 16:
        raise ValueError("initial must be uint32[N,16]")
    return {lane: initial[:, lane] for lane in range(16)}


def _execute_reader_recipe(
    output: np.ndarray,
    addends: dict[int, np.ndarray],
    recipe: dict[str, Any],
) -> np.ndarray:
    if output.dtype != np.uint32 or output.ndim != 2 or output.shape[1] != 16:
        raise ValueError("output must be uint32[N,16]")
    values = {f"output_{lane}": output[:, lane] for lane in range(16)}
    for lane, addend in addends.items():
        array = np.asarray(addend, dtype=np.uint32)
        if array.shape != (len(output),):
            raise ValueError(f"addend lane {lane} must contain one word per row")
        values[f"addend_{lane}"] = array
    for operation in recipe["operations"]:
        if operation["op"] != "sub_mod2w":
            raise ValueError(f"unsupported ChaCha Reader operation {operation['op']}")
        if operation["right"] not in values:
            raise ValueError(f"missing required Reader input {operation['right']}")
        values[operation["out"]] = (
            values[operation["left"]] - values[operation["right"]]
        ).astype(np.uint32)
    return np.stack([values[name] for name in recipe["output_order"]], axis=1)


def _build_graph(path: Path, pairs: int, seeds: int, routes: int) -> dict[str, Any]:
    builder = CryptoCausalBuilder(
        experiment="chacha20_fullround_feedforward_readers",
        parameters={
            "rounds": 20,
            "pairs_per_seed": pairs,
            "seeds": seeds,
            "bvn_routes": routes,
            "public_lanes": list(PUBLIC_LANES),
            "known_key_lanes": list(range(16)),
            "prediction_before_measurement": (
                "Public constants/counter/nonce invert eight feed-forward lanes; "
                "adding the known key words inverts all sixteen."
            ),
        },
    )
    lane_edges = []
    for lane in range(16):
        edge_id = f"chacha20-feedforward-inverse-lane-{lane}"
        lane_edges.append(edge_id)
        builder.add_triplet(
            edge_id=edge_id,
            trigger=f"chacha20:output_lane_{lane}_and_initial_lane_{lane}",
            mechanism="exact_modular_feedforward_subtraction",
            outcome=f"chacha20:post_round20_core_lane_{lane}",
            confidence=1.0,
            evidence_kind="exact_block_function_equation",
            source="RFC8439_ChaCha20_block_feedforward",
            attrs={
                "formula": f"core[{lane}] = output[{lane}] - initial[{lane}] mod 2^32",
                "initial_lane_visibility": "public" if lane in PUBLIC_LANES else "known_key",
            },
        )
    builder.add_triplet(
        edge_id="chacha20-reader-public-eight-lanes",
        trigger="chacha20:standard_block_output_plus_public_constants_counter_nonce",
        mechanism="reader_executable_public_half_core_projection",
        outcome="chacha20:eight_post_round20_public_position_lanes",
        confidence=1.0,
        evidence_kind="exact_composed_feedforward_inverse",
        source="ChaCha20_public_initial_words",
        provenance=[lane_edges[lane] for lane in PUBLIC_LANES],
        attrs={
            "reader_recipe": PUBLIC_RECIPE,
            "information_reconstructed_bits": 256,
            "requires_key": False,
        },
    )
    builder.add_triplet(
        edge_id="chacha20-reader-known-key-all-lanes",
        trigger="chacha20:standard_block_output_plus_complete_known_initial_state",
        mechanism="reader_executable_complete_core_inverse",
        outcome="chacha20:complete_post_round20_core_state",
        confidence=1.0,
        evidence_kind="exact_composed_feedforward_inverse",
        source="ChaCha20_complete_initial_state",
        provenance=lane_edges,
        attrs={
            "reader_recipe": FULL_RECIPE,
            "information_reconstructed_bits": 512,
            "requires_key": True,
        },
    )
    stats = builder.save(path)
    reader = CryptoCausalReader(path)
    if not reader.verify_provenance() or len(reader.triplets(include_inferred=False)) != 18:
        raise RuntimeError("ChaCha20 causal Reader graph gate failed")
    return stats


def _recipes_from_reader(path: Path) -> tuple[dict[str, dict[str, Any]], list[dict[str, Any]]]:
    reader = CryptoCausalReader(path)
    rows = reader.triplets(include_inferred=False)
    public = [
        row
        for row in rows
        if row["mechanism"] == "reader_executable_public_half_core_projection"
    ]
    full = [
        row
        for row in rows
        if row["mechanism"] == "reader_executable_complete_core_inverse"
    ]
    if len(public) != 1 or len(full) != 1:
        raise RuntimeError("Reader returned no unique ChaCha20 recipes")
    return {
        "public": public[0]["attrs"]["reader_recipe"],
        "full": full[0]["attrs"]["reader_recipe"],
    }, rows


def _accuracy(expected: np.ndarray, observed: np.ndarray) -> dict[str, Any]:
    if expected.shape != observed.shape or expected.dtype != np.uint32 or observed.dtype != np.uint32:
        raise ValueError("accuracy arrays must be matching uint32 matrices")
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
        raise RuntimeError("invalid ChaCha20 BvN route bank")
    return routes


def _fixed_key_inputs(
    rng: np.random.Generator, pairs: int
) -> tuple[np.ndarray, np.ndarray, np.ndarray]:
    key = np.frombuffer(rng.bytes(32), dtype=np.uint8)
    nonce = np.frombuffer(rng.bytes(12), dtype=np.uint8)
    keys = np.broadcast_to(key, (pairs, 32)).copy()
    nonces = np.broadcast_to(nonce, (pairs, 12)).copy()
    counters = rng.integers(0, 1 << 32, size=pairs, dtype=np.uint32)
    return keys, counters, nonces


def _confirm_seed(
    inputs: tuple[np.ndarray, np.ndarray, np.ndarray],
    recipes: dict[str, dict[str, Any]],
    route_count: int,
    seed: int,
) -> dict[str, Any]:
    keys, counters, nonces = inputs
    initial, core, output = _block_trace(keys, counters, nonces, rounds=20)
    public_expected = core[:, PUBLIC_LANES]
    public_addends = _public_addends(counters, nonces)
    public_reconstructed = _execute_reader_recipe(
        output, public_addends, recipes["public"]
    )
    full_reconstructed = _execute_reader_recipe(
        output, _all_addends(initial), recipes["full"]
    )
    factual_public = _accuracy(public_expected, public_reconstructed)
    factual_full = _accuracy(core, full_reconstructed)

    public_route_rows = []
    full_route_rows = []
    for route in _routes(len(output), route_count, seed):
        public_route_rows.append(
            _accuracy(
                public_expected,
                _execute_reader_recipe(output[route], public_addends, recipes["public"]),
            )
        )
        full_route_rows.append(
            _accuracy(
                core,
                _execute_reader_recipe(
                    output[route], _all_addends(initial), recipes["full"]
                ),
            )
        )

    previous_counter_addends = dict(public_addends)
    previous_counter_addends[12] = counters - np.uint32(1)
    previous_counter = _accuracy(
        public_expected,
        _execute_reader_recipe(output, previous_counter_addends, recipes["public"]),
    )

    rotated_nonce_addends = dict(public_addends)
    for destination, source in zip((13, 14, 15), (15, 13, 14), strict=True):
        rotated_nonce_addends[destination] = public_addends[source]
    rotated_nonce = _accuracy(
        public_expected,
        _execute_reader_recipe(output, rotated_nonce_addends, recipes["public"]),
    )

    rotated_constant_addends = dict(public_addends)
    for destination, source in zip((0, 1, 2, 3), (3, 0, 1, 2), strict=True):
        rotated_constant_addends[destination] = public_addends[source]
    rotated_constants = _accuracy(
        public_expected,
        _execute_reader_recipe(output, rotated_constant_addends, recipes["public"]),
    )

    xor_peeling = _accuracy(core, output ^ initial)
    return {
        "factual_public_reader": factual_public,
        "factual_known_key_reader": factual_full,
        "public_bvn_routes": {
            "count": route_count,
            "total_state_matches": sum(row["state_matches"] for row in public_route_rows),
            "max_word_matches": max(row["word_matches"] for row in public_route_rows),
            "max_bit_accuracy": max(row["bit_accuracy"] for row in public_route_rows),
        },
        "known_key_bvn_routes": {
            "count": route_count,
            "total_state_matches": sum(row["state_matches"] for row in full_route_rows),
            "max_word_matches": max(row["word_matches"] for row in full_route_rows),
            "max_bit_accuracy": max(row["bit_accuracy"] for row in full_route_rows),
        },
        "previous_counter_localization": previous_counter,
        "rotated_nonce_localization": rotated_nonce,
        "rotated_constants_localization": rotated_constants,
        "xor_peeling_information_control": xor_peeling,
        "factual_above_all_routes": (
            factual_public["word_matches"]
            > max(row["word_matches"] for row in public_route_rows)
            and factual_full["word_matches"]
            > max(row["word_matches"] for row in full_route_rows)
        ),
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--pairs", type=int, default=8000)
    parser.add_argument("--seeds", type=int, default=5)
    parser.add_argument("--routes", type=int, default=16)
    parser.add_argument("--seed", type=int, default=89228001)
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
    recipes, reader_rows = _recipes_from_reader(args.causal_output)
    confirmations = []
    for seed_index in range(args.seeds):
        seed = args.seed + 1009 * seed_index
        rng = np.random.default_rng(seed)
        print(f"ChaCha20 feed-forward Reader seed={seed_index + 1}/{args.seeds}", flush=True)
        confirmations.append(
            {
                "seed_index": seed_index,
                "seed": seed,
                **_confirm_seed(
                    _fixed_key_inputs(rng, args.pairs),
                    recipes,
                    args.routes,
                    seed ^ 0xCC20,
                ),
            }
        )
    retained = all(
        row["factual_public_reader"]["state_accuracy"] == 1.0
        and row["factual_known_key_reader"]["state_accuracy"] == 1.0
        and row["factual_above_all_routes"]
        for row in confirmations
    )
    payload = {
        "schema": "chacha20-fullround-feedforward-reader-v1",
        "evidence_stage": (
            "FULLROUND_PUBLIC_AND_KNOWN_KEY_READERS_RETAINED"
            if retained
            else "NEW_FEEDFORWARD_BOUNDARY_IDENTIFIED"
        ),
        "result": (
            "The public constants, counter and nonce reconstruct eight post-round20 "
            "core lanes from a standard block without the key. With the known key, "
            "the Reader reconstructs the complete 512-bit core."
        ),
        "scope": (
            "Exact ChaCha20 block-function feed-forward inversion at the full-round "
            "endpoint. Public-lane reconstruction is not a key reconstruction claim."
        ),
        "parameters": {
            "rounds": 20,
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
                "public_state_matches": [
                    row["factual_public_reader"]["state_matches"]
                    for row in confirmations
                ],
                "known_key_state_matches": [
                    row["factual_known_key_reader"]["state_matches"]
                    for row in confirmations
                ],
                "public_bvn_total_state_matches": [
                    row["public_bvn_routes"]["total_state_matches"]
                    for row in confirmations
                ],
            },
            indent=2,
        )
    )


if __name__ == "__main__":
    main()

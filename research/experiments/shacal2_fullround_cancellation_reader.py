#!/usr/bin/env python3
"""SHACAL-2 full-round shared-T1 cancellation, executed from `.causal`."""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import sys
from pathlib import Path

import numpy as np

from arx_carry_leak.bvn import route_ensemble, verify_routes
from arx_carry_leak.crypto_causal import CryptoCausalBuilder, CryptoCausalReader


_SHA2_PATH = Path(__file__).with_name("sha2_fullround_feedforward_causal.py")
_SHA2_SPEC = importlib.util.spec_from_file_location("sha2_fullround_feedforward_causal", _SHA2_PATH)
assert _SHA2_SPEC is not None and _SHA2_SPEC.loader is not None
_SHA2 = importlib.util.module_from_spec(_SHA2_SPEC)
sys.modules[_SHA2_SPEC.name] = _SHA2
_SHA2_SPEC.loader.exec_module(_SHA2)
_VARIANT = _SHA2._VARIANTS["sha256"]


BC_ENGINE_URL = "https://github.com/bcgit/bc-java/blob/main/core/src/main/java/org/bouncycastle/crypto/engines/Shacal2Engine.java"
BC_ENGINE_RAW_SHA256 = "fe457dec8a1679c8e49c0705ba861e45a4e754c3de9f7dc335cf90625daae08c"
BC_TEST_URL = "https://github.com/bcgit/bc-java/blob/main/core/src/test/java/org/bouncycastle/crypto/test/Shacal2Test.java"
BC_TEST_RAW_SHA256 = "5d5b3ca6bb22b88efabf42d1fa9f50cc3e3abe39d25a87f4d74d7d629105ee1e"


READER_RECIPE = {
    "word_bits": 32,
    "operations": [
        {"out": "sigma0", "op": "rotr_xor", "input": "a63", "shifts": [2, 13, 22]},
        {"out": "majority", "op": "majority", "args": ["a63", "b63", "c63"]},
        {"out": "t2", "op": "add_mod2w", "args": ["sigma0", "majority"]},
        {"out": "cancelled_t1", "op": "sub_mod2w", "left": "a64", "right": "e64"},
        {"out": "d63", "op": "sub_mod2w", "left": "t2", "right": "cancelled_t1"},
    ],
    "output": "d63",
}


def _expand_key(key: bytes) -> np.ndarray:
    if len(key) < 16 or len(key) > 64 or len(key) % 8:
        raise ValueError("SHACAL-2 key must contain 16..64 bytes in multiples of 8")
    schedule = np.zeros(64, dtype=np.uint32)
    parsed = np.frombuffer(key, dtype=">u4").astype(np.uint32)
    schedule[:len(parsed)] = parsed
    for index in range(16, 64):
        sigma1 = int(
            _SHA2._small_sigma(
                schedule[index - 2:index - 1], _VARIANT.small_sigma1, 32
            )[0]
        )
        sigma0 = int(
            _SHA2._small_sigma(
                schedule[index - 15:index - 14], _VARIANT.small_sigma0, 32
            )[0]
        )
        schedule[index] = np.uint32(
            (sigma1 + int(schedule[index - 7]) + sigma0 + int(schedule[index - 16]))
            & 0xFFFFFFFF
        )
    return schedule


def _trace(plaintexts: np.ndarray, key: bytes) -> list[np.ndarray]:
    if plaintexts.ndim != 2 or plaintexts.shape[1] != 32 or plaintexts.dtype != np.uint8:
        raise ValueError("plaintexts must be uint8[N,32]")
    state = np.frombuffer(plaintexts.tobytes(), dtype=">u4").astype(np.uint32).reshape(len(plaintexts), 8)
    schedule = _expand_key(key)
    constants = _SHA2._constants(_VARIANT)
    trace = [state.copy()]
    a, b, c, d, e, f, g, h = [state[:, lane].copy() for lane in range(8)]
    for index in range(64):
        choice = (e & f) ^ ((~e) & g)
        majority = (a & b) ^ (a & c) ^ (b & c)
        first = (
            h
            + _SHA2._big_sigma(e, _VARIANT.big_sigma1, 32)
            + choice
            + constants[index]
            + schedule[index]
        )
        second = _SHA2._big_sigma(a, _VARIANT.big_sigma0, 32) + majority
        a, b, c, d, e, f, g, h = first + second, a, b, c, d + first, e, f, g
        trace.append(np.stack((a, b, c, d, e, f, g, h), axis=1))
    return trace


def _words_to_bytes(words: np.ndarray) -> bytes:
    return b"".join(int(word).to_bytes(4, "big") for word in words[0])


def _kat() -> dict:
    vectors = [
        {
            "name": "NESSIE_iterated_set_1_0_single",
            "key": "80" + "00" * 63,
            "plaintext": "00" * 32,
            "ciphertext": "361ab6322fa9e7a7bb23818d839e01bddafdf47305426edd297aedb9f6202bae",
        },
        {
            "name": "NESSIE_set_8_0",
            "key": "".join(f"{value:02x}" for value in range(64)),
            "plaintext": "98bcc10405ab0bfc686bececaad01ac19b452511bceb9cb094f905c51ca45430",
            "ciphertext": "00112233445566778899aabbccddeeff102132435465768798a9bacbdcedfe0f",
        },
    ]
    for vector in vectors:
        plaintext = np.frombuffer(bytes.fromhex(vector["plaintext"]), dtype=np.uint8).reshape(1, 32)
        observed = _words_to_bytes(_trace(plaintext, bytes.fromhex(vector["key"]))[-1]).hex()
        if observed != vector["ciphertext"]:
            raise RuntimeError(
                f"SHACAL-2 {vector['name']} KAT failed: {observed} != {vector['ciphertext']}"
            )
        vector["observed"] = observed
        vector["match"] = True
    return {
        "vectors": vectors,
        "bouncycastle_engine_url": BC_ENGINE_URL,
        "bouncycastle_engine_raw_sha256": BC_ENGINE_RAW_SHA256,
        "bouncycastle_test_url": BC_TEST_URL,
        "bouncycastle_test_raw_sha256": BC_TEST_RAW_SHA256,
    }


def _rotr(value: np.ndarray, shift: int) -> np.ndarray:
    return (value >> shift) | (value << (32 - shift))


def _execute_recipe(inputs: dict[str, np.ndarray], recipe: dict) -> np.ndarray:
    values = dict(inputs)
    for operation in recipe["operations"]:
        if operation["op"] == "rotr_xor":
            value = values[operation["input"]]
            result = np.zeros_like(value)
            for shift in operation["shifts"]:
                result ^= _rotr(value, int(shift))
        elif operation["op"] == "majority":
            first, second, third = [values[name] for name in operation["args"]]
            result = (first & second) ^ (first & third) ^ (second & third)
        elif operation["op"] == "add_mod2w":
            result = np.zeros_like(next(iter(values.values())))
            for name in operation["args"]:
                result = result + values[name]
        elif operation["op"] == "sub_mod2w":
            result = values[operation["left"]] - values[operation["right"]]
        else:
            raise ValueError(f"unsupported Reader operation: {operation['op']}")
        values[operation["out"]] = result.astype(np.uint32)
    return values[recipe["output"]]


def _build_graph(path: Path, pairs: int, keys: int, routes: int) -> dict:
    builder = CryptoCausalBuilder(
        experiment="shacal2_fullround_shared_t1_cancellation",
        parameters={
            "rounds": 64,
            "boundary": "R63_to_R64_fullround_endpoint",
            "pairs_per_key": pairs,
            "keys": keys,
            "bvn_routes": routes,
            "prediction_before_measurement": "a64-e64 cancels shared T1 and reveals T2-d63 exactly",
        },
    )
    builder.add_triplet(
        edge_id="shacal2-t2",
        trigger="shacal2:r63_a_b_c",
        mechanism="sigma0_plus_majority",
        outcome="shacal2:r63_t2",
        confidence=1.0,
        evidence_kind="exact_round_equation",
        source="SHACAL2_round_function",
        attrs={"formula": "T2=Sigma0(a63)+Maj(a63,b63,c63) mod 2^32"},
    )
    builder.add_triplet(
        edge_id="shacal2-shared-t1-cancel",
        trigger="shacal2:r64_a_e",
        mechanism="shared_t1_modular_subtraction",
        outcome="shacal2:t2_minus_d63",
        confidence=1.0,
        evidence_kind="exact_round_equation",
        source="SHACAL2_dual_accumulator",
        attrs={"formula": "a64-e64=T2-d63 mod 2^32"},
    )
    builder.add_triplet(
        edge_id="shacal2-reader-d63",
        trigger="shacal2:r63_a_b_c_plus_r64_a_e",
        mechanism="reader_executable_shared_t1_cancellation",
        outcome="shacal2:r63_d",
        confidence=1.0,
        evidence_kind="exact_composed_inverse",
        source="SHACAL2_fullround_cancellation_composition",
        provenance=["shacal2-t2", "shacal2-shared-t1-cancel"],
        attrs={"reader_recipe": READER_RECIPE, "information_reconstructed_bits": 32},
    )
    stats = builder.save(path)
    reader = CryptoCausalReader(path)
    if not reader.verify_provenance() or len(reader.triplets(include_inferred=False)) != 3:
        raise RuntimeError("SHACAL-2 causal Reader gate failed")
    return stats


def _recipe_from_reader(path: Path) -> tuple[dict, list[dict]]:
    reader = CryptoCausalReader(path)
    rows = reader.triplets(include_inferred=False)
    matches = [
        row for row in rows
        if row["mechanism"] == "reader_executable_shared_t1_cancellation"
    ]
    if len(matches) != 1:
        raise RuntimeError("Reader returned no unique SHACAL-2 cancellation recipe")
    return matches[0]["attrs"]["reader_recipe"], rows


def _routes(size: int, count: int, seed: int) -> list[np.ndarray]:
    routes = route_ensemble(size, count, seed)
    verification = verify_routes(routes)
    if not verification["all_bijective"] or verification["forbidden_alignments"]:
        raise RuntimeError("invalid BvN route bank")
    return routes


def _accuracy(expected: np.ndarray, observed: np.ndarray) -> dict:
    xor = expected ^ observed
    bit_matches = sum(32 - int(value).bit_count() for value in xor)
    return {
        "word_matches": int(np.sum(expected == observed)),
        "word_total": int(len(expected)),
        "word_accuracy": float(np.mean(expected == observed)),
        "bit_matches": bit_matches,
        "bit_total": int(32 * len(expected)),
        "bit_accuracy": bit_matches / (32 * len(expected)),
    }


def _confirm(
    key: bytes,
    plaintexts: np.ndarray,
    recipe: dict,
    route_count: int,
    seed: int,
) -> dict:
    trace = _trace(plaintexts, key)
    r63 = trace[63]
    r64 = trace[64]
    inputs = {
        "a63": r63[:, 0],
        "b63": r63[:, 1],
        "c63": r63[:, 2],
        "a64": r64[:, 0],
        "e64": r64[:, 4],
    }
    reconstructed = _execute_recipe(inputs, recipe)
    factual = _accuracy(r63[:, 3], reconstructed)

    route_rows = []
    for route in _routes(len(plaintexts), route_count, seed):
        repaired_inputs = {**inputs, "a64": r64[route, 0], "e64": r64[route, 4]}
        route_rows.append(_accuracy(r63[:, 3], _execute_recipe(repaired_inputs, recipe)))

    wrong_recipe = json.loads(json.dumps(recipe))
    wrong_recipe["operations"][0]["shifts"] = [6, 11, 25]
    wrong_formula = _accuracy(r63[:, 3], _execute_recipe(inputs, wrong_recipe))
    return {
        "factual_reader_inference": factual,
        "bvn_routes": {
            "count": route_count,
            "max_word_matches": max(row["word_matches"] for row in route_rows),
            "total_word_matches": sum(row["word_matches"] for row in route_rows),
            "mean_bit_accuracy": float(np.mean([row["bit_accuracy"] for row in route_rows])),
            "max_bit_accuracy": max(row["bit_accuracy"] for row in route_rows),
        },
        "wrong_sigma_formula_control": wrong_formula,
        "factual_above_all_bvn_routes": (
            factual["word_matches"] > max(row["word_matches"] for row in route_rows)
            and factual["bit_accuracy"] > max(row["bit_accuracy"] for row in route_rows)
        ),
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--pairs", type=int, default=8000)
    parser.add_argument("--keys", type=int, default=5)
    parser.add_argument("--routes", type=int, default=16)
    parser.add_argument("--seed", type=int, default=88828001)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--causal-output", type=Path, required=True)
    args = parser.parse_args()
    if min(args.pairs, args.keys, args.routes) < 1:
        raise ValueError("pairs, keys and routes must be positive")
    kat = _kat()
    causal = _build_graph(args.causal_output, args.pairs, args.keys, args.routes)
    recipe, reader_rows = _recipe_from_reader(args.causal_output)
    confirmations = []
    for key_index in range(args.keys):
        seed = args.seed + 1009 * key_index
        rng = np.random.default_rng(seed)
        key = rng.bytes(64)
        plaintexts = rng.integers(0, 256, size=(args.pairs, 32), dtype=np.uint8)
        print(f"SHACAL-2 cancellation key={key_index + 1}/{args.keys}", flush=True)
        confirmations.append({
            "key_index": key_index,
            **_confirm(key, plaintexts, recipe, args.routes, seed ^ 0x5A2C),
        })
    retained = all(
        row["factual_reader_inference"]["word_accuracy"] == 1.0
        and row["factual_above_all_bvn_routes"]
        for row in confirmations
    )
    payload = {
        "schema": "shacal2-fullround-cancellation-reader-v1",
        "evidence_stage": "FULLROUND_CANCELLATION_RETAINED" if retained else "NEW_BOUNDARY_IDENTIFIED",
        "result": "The Reader cancels the shared T1 term at R64 and reconstructs d63 exactly.",
        "kat": kat,
        "parameters": {
            "rounds": 64,
            "boundary": "R63_to_R64_fullround_endpoint",
            "pairs_per_key": args.pairs,
            "keys": args.keys,
            "bvn_routes": args.routes,
            "seed": args.seed,
        },
        "causal": causal,
        "reader_triplets": reader_rows,
        "confirmation": confirmations,
        "retained": retained,
    }
    raw = (json.dumps(payload, indent=2, sort_keys=True) + "\n").encode()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_bytes(raw)
    print(json.dumps({
        "output": str(args.output),
        "sha256": hashlib.sha256(raw).hexdigest(),
        "retained": retained,
        "factual_word_matches": [
            row["factual_reader_inference"]["word_matches"] for row in confirmations
        ],
        "bvn_total_word_matches": [
            row["bvn_routes"]["total_word_matches"] for row in confirmations
        ],
        "wrong_formula_word_matches": [
            row["wrong_sigma_formula_control"]["word_matches"] for row in confirmations
        ],
    }, indent=2))


if __name__ == "__main__":
    main()

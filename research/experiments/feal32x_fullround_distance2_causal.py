#!/usr/bin/env python3
"""Prediction-first FEAL-32X full-round distance-2 causal/F8 test.

The standard Feistel recurrence gives A_i xor A_(i+2) = F(B_i, K_i).
For FEAL-32X this places a fully internal, non-synthetic probe at R30 -> R32.
Unlike the already tested table-S-box Feistel cases, FEAL's F consists only of
XOR, byte additions and fixed rotate-left-by-two operations.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

import numpy as np

from arx_carry_leak.bvn import route_ensemble, verify_routes
from arx_carry_leak.crypto_causal import CryptoCausalBuilder, CryptoCausalReader


ROUNDS = 32
OFFICIAL_KEY = bytes.fromhex("0123456789abcdef0123456789abcdef")
OFFICIAL_PLAINTEXT = bytes(8)
OFFICIAL_CIPHERTEXT = bytes.fromhex("9c9b54973df685f8")
NTT_REFERENCE_URL = "https://info.isl.ntt.co.jp/crypt/eng/archive/dl/feal/call-6.txt"
NTT_REFERENCE_SHA256 = "8bc1d200610a029c7f1869da7b63a8f3780f1bbb5acacb037611cba4f999190f"
NTT_VECTOR_URL = "https://info.isl.ntt.co.jp/crypt/eng/archive/dl/feal/call-5.zip"
NTT_VECTOR_SHA256 = "d2560183dcd4d79ca83389427009a6f2dc85648241b7f6b2d15dc0163d367949"


def _rotl2_scalar(value: int) -> int:
    return ((value << 2) | (value >> 6)) & 0xFF


def _s0_scalar(first: int, second: int) -> int:
    return _rotl2_scalar((first + second) & 0xFF)


def _s1_scalar(first: int, second: int) -> int:
    return _rotl2_scalar((first + second + 1) & 0xFF)


def _fk(first: bytes | bytearray, second: bytes | bytearray) -> bytes:
    a = list(first)
    b = list(second)
    a[1] ^= a[0]
    a[2] ^= a[3]
    temporary = a[2] ^ b[0]
    a[1] = _s1_scalar(a[1], temporary)
    temporary = a[1] ^ b[1]
    a[2] = _s0_scalar(a[2], temporary)
    temporary = a[1] ^ b[2]
    a[0] = _s0_scalar(a[0], temporary)
    temporary = a[2] ^ b[3]
    a[3] = _s1_scalar(a[3], temporary)
    return bytes(a)


def _key_schedule(key: bytes, rounds: int = ROUNDS) -> bytes:
    if len(key) != 16 or rounds < 2 or rounds % 2:
        raise ValueError("FEAL-NX needs a 16-byte key and a positive even round count")
    a = key[0:4]
    b = key[4:8]
    kr1 = key[8:12]
    kr2 = key[12:16]
    delayed = bytes(4)
    expanded = bytearray(2 * rounds + 16)
    for index in range(0, rounds + 8, 2):
        selector = (
            bytes(x ^ y for x, y in zip(kr1, kr2, strict=True)),
            kr1,
            kr2,
        )[(index // 2) % 3]
        mixed = bytes(
            b[position] ^ selector[position] ^ delayed[position]
            for position in range(4)
        )
        delayed = a
        a = _fk(a, mixed)
        expanded[2 * index:2 * index + 4] = a
        a, b = b, a
    return bytes(expanded)


def _rotl2(value: np.ndarray) -> np.ndarray:
    wide = value.astype(np.uint16)
    return (((wide << 2) | (wide >> 6)) & 0xFF).astype(np.uint8)


def _s0(first: np.ndarray, second: np.ndarray) -> np.ndarray:
    return _rotl2(((first.astype(np.uint16) + second.astype(np.uint16)) & 0xFF).astype(np.uint8))


def _s1(first: np.ndarray, second: np.ndarray) -> np.ndarray:
    return _rotl2(
        ((first.astype(np.uint16) + second.astype(np.uint16) + 1) & 0xFF).astype(np.uint8)
    )


def _f(right: np.ndarray, subkey: bytes | np.ndarray) -> np.ndarray:
    if right.ndim != 2 or right.shape[1] != 4:
        raise ValueError("right must have shape (N,4)")
    key = (
        np.frombuffer(subkey, dtype=np.uint8)
        if isinstance(subkey, bytes)
        else np.asarray(subkey, dtype=np.uint8)
    )
    if key.shape != (2,):
        raise ValueError("FEAL round subkey must contain two bytes")
    output = np.empty_like(right)
    output[:, 1] = right[:, 0] ^ right[:, 1] ^ key[0]
    output[:, 2] = right[:, 2] ^ right[:, 3] ^ key[1]
    output[:, 1] = _s1(output[:, 1], output[:, 2])
    output[:, 2] = _s0(output[:, 1], output[:, 2])
    output[:, 0] = _s0(right[:, 0], output[:, 1])
    output[:, 3] = _s1(right[:, 3], output[:, 2])
    return output


def _encrypt_trace(
    plaintexts: np.ndarray,
    key: bytes,
    rounds: int = ROUNDS,
) -> tuple[list[tuple[np.ndarray, np.ndarray]], np.ndarray, bytes]:
    if plaintexts.ndim != 2 or plaintexts.shape[1] != 8 or plaintexts.dtype != np.uint8:
        raise ValueError("plaintexts must have shape (N,8) and dtype uint8")
    expanded = _key_schedule(key, rounds)
    left = plaintexts[:, :4] ^ np.frombuffer(expanded[2 * rounds:2 * rounds + 4], dtype=np.uint8)
    right = (
        plaintexts[:, 4:]
        ^ np.frombuffer(expanded[2 * rounds + 4:2 * rounds + 8], dtype=np.uint8)
        ^ left
    )
    trace = [(left.copy(), right.copy())]
    for round_index in range(rounds):
        function = _f(
            right,
            np.frombuffer(expanded[2 * round_index:2 * round_index + 2], dtype=np.uint8),
        )
        left = left ^ function
        left, right = right, left
        trace.append((left.copy(), right.copy()))
    post_left = left ^ right
    ciphertext = np.concatenate(
        (
            right ^ np.frombuffer(expanded[2 * rounds + 8:2 * rounds + 12], dtype=np.uint8),
            post_left ^ np.frombuffer(expanded[2 * rounds + 12:2 * rounds + 16], dtype=np.uint8),
        ),
        axis=1,
    )
    return trace, ciphertext, expanded


def _kat() -> dict:
    plaintext = np.frombuffer(OFFICIAL_PLAINTEXT, dtype=np.uint8).reshape(1, 8)
    trace, ciphertext, expanded = _encrypt_trace(plaintext, OFFICIAL_KEY)
    observed = bytes(ciphertext[0])
    if observed != OFFICIAL_CIPHERTEXT:
        raise RuntimeError(
            f"official FEAL-32X KAT failed: {observed.hex()} != {OFFICIAL_CIPHERTEXT.hex()}"
        )
    expected_initial = bytes.fromhex("196a9ab1f97f1b21")
    expected_final = bytes.fromhex("932ddf1603e932d4")
    if bytes(np.concatenate(trace[0], axis=1)[0]) != expected_initial:
        raise RuntimeError("official FEAL-32X initial intermediate state failed")
    if bytes(np.concatenate(trace[32], axis=1)[0]) != expected_final:
        raise RuntimeError("official FEAL-32X R32 intermediate state failed")
    expected_first_subkeys = bytes.fromhex("751971f984e9488688e5523b4ea47ade")
    if expanded[:16] != expected_first_subkeys:
        raise RuntimeError("official FEAL-32X key schedule prefix failed")
    return {
        "key": OFFICIAL_KEY.hex(),
        "plaintext": OFFICIAL_PLAINTEXT.hex(),
        "ciphertext": observed.hex(),
        "initial_state": expected_initial.hex(),
        "r32_state": expected_final.hex(),
        "first_eight_round_subkeys": expected_first_subkeys.hex(),
        "official_vector_match": True,
        "ntt_reference_url": NTT_REFERENCE_URL,
        "ntt_reference_sha256": NTT_REFERENCE_SHA256,
        "ntt_vector_url": NTT_VECTOR_URL,
        "ntt_vector_sha256": NTT_VECTOR_SHA256,
    }


def _bits(values: np.ndarray) -> np.ndarray:
    return (
        (values[:, :, None] >> np.arange(8, dtype=np.uint8)[None, None, :]) & 1
    ).reshape(len(values), 32).astype(np.uint8)


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


def _mi_matrix(first: np.ndarray, second: np.ndarray) -> np.ndarray:
    return np.asarray([
        [_mi_binary(first[:, source], second[:, target]) for target in range(32)]
        for source in range(32)
    ])


def _routes(size: int, count: int, seed: int) -> list[np.ndarray]:
    routes = route_ensemble(size, count, seed)
    verification = verify_routes(routes)
    if not verification["all_bijective"] or verification["forbidden_alignments"]:
        raise RuntimeError("invalid BvN route bank")
    return routes


def _state_views(
    plaintexts: np.ndarray,
    key: bytes,
) -> tuple[np.ndarray, np.ndarray, np.ndarray, int]:
    trace, _, expanded = _encrypt_trace(plaintexts, key)
    left30, right30 = trace[30]
    left32, _ = trace[32]
    delta_left = left30 ^ left32
    predicted = _f(right30, np.frombuffer(expanded[60:62], dtype=np.uint8))
    exact = int(np.sum(delta_left == predicted))
    if exact != delta_left.size:
        raise RuntimeError("FEAL distance-2 identity failed")
    return _bits(right30), _bits(delta_left), _bits(left30), exact


def _discovery(
    plaintexts: np.ndarray,
    key: bytes,
    routes: int,
    seed: int,
) -> tuple[np.ndarray, np.ndarray, np.ndarray, int]:
    source, target, _, exact = _state_views(plaintexts, key)
    bank = _routes(len(plaintexts), routes, seed)
    factual = _mi_matrix(source, target)
    null = np.stack([_mi_matrix(source, target[route]) for route in bank])
    return factual, null.mean(axis=0), null.std(axis=0, ddof=1), exact


def _write_discovery_graph(path: Path, parameters: dict, cells: list[dict]) -> dict:
    builder = CryptoCausalBuilder(
        experiment="feal32x_fullround_distance2_causal",
        parameters=parameters,
    )
    for rank, cell in enumerate(cells):
        builder.add_triplet(
            edge_id=f"feal32x-r30-r32-rank-{rank}",
            trigger=f"feal32x:r30_right_bit_{cell['source_bit']}",
            mechanism="fullround_distance2_feistel_bytecarry_dependency",
            outcome=f"feal32x:r30_xor_r32_left_bit_{cell['target_bit']}",
            confidence=min(0.999, 1.0 - np.exp(-max(cell["mean_excess_z"], 0.0) / 8.0)),
            evidence_kind="prediction_first_complete_bit_grid_discovery",
            source="FEAL32X_distance2_Feistel_identity",
            attrs=cell,
        )
    stats = builder.save(path)
    reader = CryptoCausalReader(path)
    if not reader.verify_provenance():
        raise RuntimeError("FEAL discovery causal provenance failed")
    return stats


def _reader_cells(path: Path) -> list[tuple[int, int]]:
    reader = CryptoCausalReader(path)
    cells = [
        (int(row["attrs"]["source_bit"]), int(row["attrs"]["target_bit"]))
        for row in reader.triplets(include_inferred=False)
    ]
    if not cells:
        raise RuntimeError("FEAL Reader returned no cells")
    return cells


def _aggregate(
    first: np.ndarray,
    second: np.ndarray,
    cells: list[tuple[int, int]],
    routes: list[np.ndarray],
) -> dict:
    factual = sum(_mi_binary(first[:, source], second[:, target]) for source, target in cells)
    null = np.asarray([
        sum(_mi_binary(first[:, source], second[route, target]) for source, target in cells)
        for route in routes
    ])
    return {
        "factual_mi": factual,
        "bvn_mean": float(null.mean()),
        "bvn_max": float(null.max()),
        "z": float((factual - null.mean()) / (null.std(ddof=1) + 1e-30)),
        "above_all_bvn_routes": bool(factual > null.max()),
    }


def _confirm(
    plaintexts: np.ndarray,
    key: bytes,
    cells: list[tuple[int, int]],
    route_count: int,
    seed: int,
) -> dict:
    source, target, matched_left, exact = _state_views(plaintexts, key)
    routes = _routes(len(plaintexts), route_count, seed)
    return {
        "distance2_right_source": _aggregate(source, target, cells, routes),
        "matched_left_source_control": _aggregate(matched_left, target, cells, routes),
        "exact_byte_equalities": exact,
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--discovery-pairs", type=int, default=3000)
    parser.add_argument("--confirmation-pairs", type=int, default=7000)
    parser.add_argument("--discovery-keys", type=int, default=3)
    parser.add_argument("--confirmation-keys", type=int, default=5)
    parser.add_argument("--routes", type=int, default=16)
    parser.add_argument("--top-k", type=int, default=16)
    parser.add_argument("--seed", type=int, default=88628001)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--causal-output", type=Path, required=True)
    args = parser.parse_args()
    if min(
        args.discovery_pairs,
        args.confirmation_pairs,
        args.discovery_keys,
        args.confirmation_keys,
        args.routes,
        args.top_k,
    ) < 1 or args.top_k > 1024:
        raise ValueError("invalid positive experiment parameter")

    kat = _kat()
    factuals = []
    null_means = []
    null_sds = []
    discovery_equalities = 0
    for key_index in range(args.discovery_keys):
        seed = args.seed + 1009 * key_index
        rng = np.random.default_rng(seed)
        key = rng.bytes(16)
        plaintexts = rng.integers(0, 256, size=(args.discovery_pairs, 8), dtype=np.uint8)
        print(f"FEAL-32X discovery key={key_index + 1}/{args.discovery_keys}", flush=True)
        factual, null_mean, null_sd, exact = _discovery(
            plaintexts, key, args.routes, seed ^ 0xFEA1
        )
        factuals.append(factual)
        null_means.append(null_mean)
        null_sds.append(null_sd)
        discovery_equalities += exact
    factual_mean = np.mean(factuals, axis=0)
    null_mean = np.mean(null_means, axis=0)
    null_sd = np.maximum(np.mean(null_sds, axis=0), 1e-12)
    excess_z = (factual_mean - null_mean) / null_sd
    order = np.argsort(excess_z.ravel())[::-1][:args.top_k]
    cells = []
    for flat in order:
        source, target = np.unravel_index(int(flat), (32, 32))
        cells.append({
            "source_bit": int(source),
            "target_bit": int(target),
            "mean_factual_mi": float(factual_mean[source, target]),
            "mean_bvn_mi": float(null_mean[source, target]),
            "mean_excess_z": float(excess_z[source, target]),
        })
    parameters = {
        "prediction_before_measurement": (
            "FEAL-32X leaks at the full-round R30-to-R32 endpoint through the exact "
            "distance-2 Feistel identity and its XOR/add/ROL2 byte function"
        ),
        "rounds": ROUNDS,
        "boundary": "R30_to_R32_fullround_endpoint",
        "discovery_pairs": args.discovery_pairs,
        "discovery_keys": args.discovery_keys,
        "confirmation_pairs": args.confirmation_pairs,
        "confirmation_keys": args.confirmation_keys,
        "bvn_routes": args.routes,
        "top_k": args.top_k,
        "official_ntt_kat": OFFICIAL_CIPHERTEXT.hex(),
        "reader_model_required_for_confirmation": True,
    }
    causal = _write_discovery_graph(args.causal_output, parameters, cells)
    reader_cells = _reader_cells(args.causal_output)
    confirmations = []
    for key_index in range(args.confirmation_keys):
        seed = args.seed + 100000 + 1009 * key_index
        rng = np.random.default_rng(seed)
        key = rng.bytes(16)
        plaintexts = rng.integers(0, 256, size=(args.confirmation_pairs, 8), dtype=np.uint8)
        print(f"FEAL-32X confirmation key={key_index + 1}/{args.confirmation_keys}", flush=True)
        confirmations.append({
            "key_index": key_index,
            **_confirm(plaintexts, key, reader_cells, args.routes, seed ^ 0xFEA1),
        })
    retained = all(
        row["distance2_right_source"]["above_all_bvn_routes"] for row in confirmations
    )
    payload = {
        "schema": "feal32x-fullround-distance2-causal-v1",
        "evidence_stage": "NEW_FULLROUND_CONFIGURATION" if retained else "NEW_BOUNDARY_IDENTIFIED",
        "kat": kat,
        "parameters": parameters,
        "discovery_exact_byte_equalities": discovery_equalities,
        "discovery_top_cells": cells,
        "causal": causal,
        "reader_fixed_cells": [
            {"source_bit": source, "target_bit": target}
            for source, target in reader_cells
        ],
        "confirmation": confirmations,
        "retained_fullround_distance2": retained,
    }
    raw = (json.dumps(payload, indent=2, sort_keys=True) + "\n").encode()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_bytes(raw)
    print(json.dumps({
        "output": str(args.output),
        "sha256": hashlib.sha256(raw).hexdigest(),
        "retained": retained,
        "discovery_exact_byte_equalities": discovery_equalities,
        "confirmation_z": [
            round(row["distance2_right_source"]["z"], 2) for row in confirmations
        ],
        "control_z": [
            round(row["matched_left_source_control"]["z"], 2) for row in confirmations
        ],
    }, indent=2))


if __name__ == "__main__":
    main()

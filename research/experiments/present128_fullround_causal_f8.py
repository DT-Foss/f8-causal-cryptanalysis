#!/usr/bin/env python3
"""Predicted PRESENT-80 -> PRESENT-128 full-round F8 mechanism transfer.

Prediction made before measurement: PRESENT-128 retains the R31->R32
cross-round dependency because the S-box and pLayer are unchanged while only
the key schedule differs. Discovery selects cells; confirmation uses fresh
keys and reconstructs those cells solely from the written causal graph.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
from pathlib import Path

import numpy as np

from arx_carry_leak.bvn import route_ensemble, verify_routes
from arx_carry_leak.crypto_causal import CryptoCausalBuilder, CryptoCausalReader
from arx_carry_leak.nano_ciphers import (
    _PRESENT_PERM_MASK,
    _PRESENT_SBOX,
    _present_encrypt,
    _present_key_schedule_128,
)

_KAT = 0x96DB702A2E6900AF
_TRIGGER = re.compile(r"state_r31_bit_(\d+)$")
_OUTCOME = re.compile(r"delta_r31_r32_bit_(\d+)$")


def _kat() -> None:
    if _present_encrypt(0, _present_key_schedule_128(0, 31), 31) != _KAT:
        raise RuntimeError("PRESENT-128 official zero-vector gate failed")


def _encrypt(values: np.ndarray, key: int, rounds: int) -> np.ndarray:
    rks = _present_key_schedule_128(key, rounds)
    state = values.astype(np.uint64).copy()
    sbox = np.asarray(_PRESENT_SBOX, dtype=np.uint64)
    for round_index in range(rounds):
        state ^= np.uint64(rks[round_index])
        substituted = np.zeros_like(state)
        for nibble_index in range(16):
            nibble = ((state >> np.uint64(4 * nibble_index)) & np.uint64(0xF)).astype(np.uint8)
            substituted |= sbox[nibble] << np.uint64(4 * nibble_index)
        permuted = np.zeros_like(state)
        for source, target in _PRESENT_PERM_MASK:
            permuted |= ((substituted >> np.uint64(source)) & np.uint64(1)) << np.uint64(target)
        state = permuted
    return state ^ np.uint64(rks[rounds])


def _bits(values: np.ndarray) -> np.ndarray:
    return ((values[:, None] >> np.arange(64, dtype=np.uint64)[None, :]) & np.uint64(1)).astype(np.uint8)


def _mi_matrix(first: np.ndarray, second: np.ndarray) -> np.ndarray:
    n = len(first)
    x = first.astype(np.int64); y = second.astype(np.int64)
    n11 = x.T @ y
    sx = x.sum(axis=0)[:, None]; sy = y.sum(axis=0)[None, :]
    counts = (n - sx - sy + n11, sx - n11, sy - n11, n11)
    row0, row1 = n - sx, sx
    col0, col1 = n - sy, sy
    denoms = (row0 * col0, row1 * col0, row0 * col1, row1 * col1)
    result = np.zeros((64, 64), dtype=np.float64)
    with np.errstate(divide="ignore", invalid="ignore"):
        for count, denominator in zip(counts, denoms, strict=True):
            term = np.where(count > 0, (count / n) * np.log((count * n) / denominator), 0.0)
            result += np.nan_to_num(term)
    return np.maximum(result, 0.0)


def _mi_binary(first: np.ndarray, second: np.ndarray) -> float:
    n = len(first); n11 = int(np.sum(first & second)); n10 = int(np.sum(first & (1 - second)))
    n01 = int(np.sum((1 - first) & second)); n00 = n - n11 - n10 - n01
    rows = (n00 + n01, n10 + n11); cols = (n00 + n10, n01 + n11); value = 0.0
    for count, row, col in ((n00, rows[0], cols[0]), (n01, rows[0], cols[1]), (n10, rows[1], cols[0]), (n11, rows[1], cols[1])):
        if count: value += (count / n) * np.log((count * n) / (row * col))
    return max(0.0, float(value))


def _routes(size: int, count: int, seed: int) -> list[np.ndarray]:
    routes = route_ensemble(size, count, seed)
    check = verify_routes(routes)
    if not check["all_bijective"] or check["forbidden_alignments"]:
        raise RuntimeError("invalid BvN route bank")
    return routes


def _discovery(key: int, values: np.ndarray, routes: int, seed: int) -> tuple[np.ndarray, np.ndarray, np.ndarray]:
    state = _encrypt(values, key, 31); delta = state ^ _encrypt(values, key, 32)
    state_bits, delta_bits = _bits(state), _bits(delta)
    factual = _mi_matrix(state_bits, delta_bits)
    repaired = np.stack([_mi_matrix(state_bits, delta_bits[route]) for route in _routes(len(values), routes, seed)])
    return factual, repaired.mean(axis=0), repaired.std(axis=0, ddof=1)


def _build(path: Path, parameters: dict, cells: list[dict]) -> dict:
    builder = CryptoCausalBuilder(experiment="present128_fullround_causal_f8", parameters=parameters)
    for rank, cell in enumerate(cells):
        builder.add_triplet(
            edge_id=f"present128-r31-r32-rank{rank}",
            trigger=f"present128:state_r31_bit_{cell['source_bit']}",
            mechanism="fullround_cross_round_f8_dependency",
            outcome=f"present128:delta_r31_r32_bit_{cell['target_bit']}",
            confidence=min(0.999, 1.0 - np.exp(-max(cell["mean_excess_z"], 0.0) / 8.0)),
            evidence_kind="predicted_cross_cipher_fullround_transfer_discovery",
            source="PRESENT80_fixed_permutation_mechanism_to_PRESENT128",
            attrs=cell,
        )
    stats = builder.save(path)
    reader = CryptoCausalReader(path)
    if not reader.verify_provenance(): raise RuntimeError("causal reader provenance gate failed")
    return stats


def _reader_cells(reader: CryptoCausalReader) -> list[tuple[int, int]]:
    cells = []
    for edge in reader.triplets(include_inferred=False):
        trigger, outcome = _TRIGGER.search(edge["trigger"]), _OUTCOME.search(edge["outcome"])
        if trigger and outcome: cells.append((int(trigger.group(1)), int(outcome.group(1))))
    if not cells: raise RuntimeError("reader returned no fixed cells")
    return cells


def _confirm(key: int, values: np.ndarray, cells: list[tuple[int, int]], routes: int, seed: int) -> dict:
    state = _encrypt(values, key, 31); delta = state ^ _encrypt(values, key, 32)
    sb, db = _bits(state), _bits(delta); route_bank = _routes(len(values), routes, seed)
    factual = sum(_mi_binary(sb[:, source], db[:, target]) for source, target in cells)
    null = np.asarray([sum(_mi_binary(sb[:, source], db[route, target]) for source, target in cells) for route in route_bank])
    return {"factual_mi": factual, "bvn_mean": float(null.mean()), "bvn_max": float(null.max()), "z": float((factual - null.mean()) / (null.std(ddof=1) + 1e-30)), "above_all_bvn_routes": bool(factual > null.max())}


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, required=True); parser.add_argument("--causal-output", type=Path, required=True)
    parser.add_argument("--discovery-pairs", type=int, default=2000); parser.add_argument("--confirmation-pairs", type=int, default=5000)
    parser.add_argument("--discovery-keys", type=int, default=3); parser.add_argument("--confirmation-keys", type=int, default=5)
    parser.add_argument("--routes", type=int, default=12); parser.add_argument("--top-k", type=int, default=16)
    parser.add_argument("--seed-base", type=int, default=88128001); args = parser.parse_args()
    if min(args.discovery_pairs, args.confirmation_pairs, args.discovery_keys, args.confirmation_keys, args.routes, args.top_k) < 1 or args.top_k > 4096: raise ValueError("invalid positive parameters")
    _kat(); factuals=[]; null_means=[]; null_sds=[]
    for index in range(args.discovery_keys):
        seed=args.seed_base+1009*index; rng=np.random.default_rng(seed); key=int.from_bytes(rng.bytes(16),"big"); values=rng.integers(0,2**64,size=args.discovery_pairs,dtype=np.uint64)
        print(f"PRESENT-128 discovery key={index+1}/{args.discovery_keys}",flush=True); factual,null_mean,null_sd=_discovery(key,values,args.routes,seed^0xB0A)
        factuals.append(factual); null_means.append(null_mean); null_sds.append(null_sd)
    factual_mean=np.mean(factuals,axis=0); null_mean=np.mean(null_means,axis=0); null_sd=np.maximum(np.mean(null_sds,axis=0),1e-12); excess_z=(factual_mean-null_mean)/null_sd
    order=np.argsort(excess_z.ravel())[::-1][:args.top_k]; cells=[]
    for flat in order:
        source,target=np.unravel_index(int(flat),(64,64)); cells.append({"source_bit":int(source),"target_bit":int(target),"mean_factual_mi":float(factual_mean[source,target]),"mean_bvn_mi":float(null_mean[source,target]),"mean_excess_z":float(excess_z[source,target])})
    discovery_hash=hashlib.sha256(np.asarray(factuals).tobytes()+np.asarray(null_means).tobytes()).hexdigest()
    parameters={"prediction_before_measurement":"PRESENT-80 fixed-permutation fullround F8 transfers to PRESENT-128 despite its different key schedule","round_boundary":"R31_to_R32","known_key":True,"discovery_pairs":args.discovery_pairs,"discovery_keys":args.discovery_keys,"confirmation_pairs":args.confirmation_pairs,"confirmation_keys":args.confirmation_keys,"bvn_routes":args.routes,"top_k":args.top_k,"discovery_matrix_sha256":discovery_hash,"primitive_gate":"PRESENT-128 E_0(0)=96db702a2e6900af","writer_model_forbidden_at_confirmation":True}
    causal=_build(args.causal_output,parameters,cells); fixed_cells=_reader_cells(CryptoCausalReader(args.causal_output)); confirmation=[]
    for index in range(args.confirmation_keys):
        seed=args.seed_base+100000+1009*index; rng=np.random.default_rng(seed); key=int.from_bytes(rng.bytes(16),"big"); values=rng.integers(0,2**64,size=args.confirmation_pairs,dtype=np.uint64)
        print(f"PRESENT-128 confirmation key={index+1}/{args.confirmation_keys}",flush=True); confirmation.append({"key_index":index,**_confirm(key,values,fixed_cells,args.routes,seed^0xB0A)})
    retained=all(row["above_all_bvn_routes"] for row in confirmation)
    payload={"schema":"present128-fullround-causal-f8-v1","prediction":parameters["prediction_before_measurement"],"evidence_stage":"CROSS_CIPHER_TRANSFER" if retained else "TRANSFER_FAILED_NEW_CONDITION_IDENTIFIED","parameters":parameters,"causal":causal,"reader_fixed_cells":[{"source_bit":s,"target_bit":t} for s,t in fixed_cells],"discovery_top_cells":cells,"confirmation":confirmation,"retained_fullround_transfer":retained}
    raw=(json.dumps(payload,indent=2,sort_keys=True)+"\n").encode(); args.output.parent.mkdir(parents=True,exist_ok=True); args.output.write_bytes(raw)
    print(json.dumps({"output":str(args.output),"sha256":hashlib.sha256(raw).hexdigest(),"retained_fullround_transfer":retained,"confirmation_z":[round(x["z"],2) for x in confirmation]},indent=2))


if __name__ == "__main__": main()

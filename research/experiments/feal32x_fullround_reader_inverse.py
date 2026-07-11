#!/usr/bin/env python3
"""Reader-executed exact inversion of the FEAL-32X R30 -> R32 relation."""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
from pathlib import Path

import numpy as np

from arx_carry_leak.crypto_causal import CryptoCausalBuilder, CryptoCausalReader


_BASE_PATH = Path(__file__).with_name("feal32x_fullround_distance2_causal.py")
_SPEC = importlib.util.spec_from_file_location("feal32x_fullround_distance2_causal", _BASE_PATH)
assert _SPEC is not None and _SPEC.loader is not None
_BASE = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(_BASE)


INVERSE_RECIPE = {
    "inputs": ["f0", "f1", "f2", "f3", "k0", "k1"],
    "operations": [
        {"out": "x0", "op": "sub_mod256", "left": "ror2(f0)", "right": "f1", "constant": 0},
        {"out": "v", "op": "sub_mod256", "left": "ror2(f2)", "right": "f1", "constant": 0},
        {"out": "u", "op": "sub_mod256", "left": "ror2(f1)", "right": "v", "constant": 1},
        {"out": "x3", "op": "sub_mod256", "left": "ror2(f3)", "right": "f2", "constant": 1},
        {"out": "x1", "op": "xor", "args": ["x0", "u", "k0"]},
        {"out": "x2", "op": "xor", "args": ["x3", "v", "k1"]},
    ],
    "output_order": ["x0", "x1", "x2", "x3"],
}


def _ror2(value: np.ndarray) -> np.ndarray:
    wide = value.astype(np.uint16)
    return (((wide >> 2) | (wide << 6)) & 0xFF).astype(np.uint8)


def _resolve(token: str, values: dict[str, np.ndarray]) -> np.ndarray:
    if token.startswith("ror2(") and token.endswith(")"):
        return _ror2(values[token[5:-1]])
    return values[token]


def _execute_reader_recipe(
    delta: np.ndarray,
    subkey: bytes | np.ndarray,
    recipe: dict,
) -> np.ndarray:
    """Execute only the typed operation list recovered from the Reader."""
    if delta.ndim != 2 or delta.shape[1] != 4 or delta.dtype != np.uint8:
        raise ValueError("delta must be uint8[N,4]")
    key = (
        np.frombuffer(subkey, dtype=np.uint8)
        if isinstance(subkey, bytes)
        else np.asarray(subkey, dtype=np.uint8)
    )
    if key.shape != (2,):
        raise ValueError("subkey must contain two bytes")
    values = {
        "f0": delta[:, 0],
        "f1": delta[:, 1],
        "f2": delta[:, 2],
        "f3": delta[:, 3],
        "k0": np.full(len(delta), key[0], dtype=np.uint8),
        "k1": np.full(len(delta), key[1], dtype=np.uint8),
    }
    for operation in recipe["operations"]:
        if operation["op"] == "sub_mod256":
            left = _resolve(operation["left"], values).astype(np.int16)
            right = _resolve(operation["right"], values).astype(np.int16)
            result = (left - right - int(operation["constant"])) & 0xFF
            values[operation["out"]] = result.astype(np.uint8)
        elif operation["op"] == "xor":
            result = np.zeros(len(delta), dtype=np.uint8)
            for argument in operation["args"]:
                result ^= _resolve(argument, values)
            values[operation["out"]] = result
        else:
            raise ValueError(f"unsupported Reader operation: {operation['op']}")
    return np.stack([values[name] for name in recipe["output_order"]], axis=1)


def _build_graph(path: Path, pairs: int, keys: int, routes: int) -> dict:
    builder = CryptoCausalBuilder(
        experiment="feal32x_fullround_reader_inverse",
        parameters={
            "rounds": 32,
            "boundary": "R30_to_R32_fullround_endpoint",
            "known_round_subkey_bytes": 2,
            "confirmation_pairs_per_key": pairs,
            "confirmation_keys": keys,
            "bvn_routes": routes,
            "reader_executes_inverse_recipe": True,
        },
    )
    stages = [
        (
            "feal32x-stage-u",
            "feal32x:r30_bytes_x0_x1_plus_k0",
            "xor_pair_projection",
            "feal32x:u",
            {"formula": "u = x0 xor x1 xor k0"},
        ),
        (
            "feal32x-stage-v",
            "feal32x:r30_bytes_x2_x3_plus_k1",
            "xor_pair_projection",
            "feal32x:v",
            {"formula": "v = x2 xor x3 xor k1"},
        ),
        (
            "feal32x-stage-middle",
            "feal32x:u_v",
            "reversible_add_rotate_pair",
            "feal32x:f1_f2",
            {
                "forward": "f1=ROL2(u+v+1); f2=ROL2(f1+v)",
                "inverse": "v=ROR2(f2)-f1; u=ROR2(f1)-v-1",
            },
        ),
        (
            "feal32x-stage-outer",
            "feal32x:x0_x3_f1_f2",
            "reversible_outer_add_rotate_pair",
            "feal32x:f0_f3",
            {
                "forward": "f0=ROL2(x0+f1); f3=ROL2(x3+f2+1)",
                "inverse": "x0=ROR2(f0)-f1; x3=ROR2(f3)-f2-1",
            },
        ),
    ]
    for edge_id, trigger, mechanism, outcome, attrs in stages:
        builder.add_triplet(
            edge_id=edge_id,
            trigger=trigger,
            mechanism=mechanism,
            outcome=outcome,
            confidence=1.0,
            evidence_kind="exact_FEAL_F_equation",
            source="NTT_FEAL32X_reference_equations",
            attrs=attrs,
        )
    builder.add_triplet(
        edge_id="feal32x-reader-full-inverse",
        trigger="feal32x:r30_xor_r32_left_32bits_plus_round_subkey",
        mechanism="reader_executable_exact_inverse",
        outcome="feal32x:r30_right_32bits",
        confidence=1.0,
        evidence_kind="exact_composed_inverse",
        source="FEAL32X_distance2_relation_and_reversible_F",
        provenance=[edge[0] for edge in stages],
        attrs={
            "distance2_identity": "left_R30 xor left_R32 = F(right_R30, K30)",
            "inverse_recipe": INVERSE_RECIPE,
            "information_recovered_bits": 32,
        },
    )
    stats = builder.save(path)
    reader = CryptoCausalReader(path)
    if not reader.verify_provenance() or len(reader.triplets(include_inferred=False)) != 5:
        raise RuntimeError("FEAL inverse causal Reader gate failed")
    return stats


def _recipe_from_reader(path: Path) -> tuple[dict, list[dict]]:
    reader = CryptoCausalReader(path)
    rows = reader.triplets(include_inferred=False)
    matches = [
        row for row in rows if row["mechanism"] == "reader_executable_exact_inverse"
    ]
    if len(matches) != 1:
        raise RuntimeError("Reader did not return exactly one executable inverse")
    return matches[0]["attrs"]["inverse_recipe"], rows


def _accuracy(expected: np.ndarray, observed: np.ndarray) -> dict:
    return {
        "byte_matches": int(np.sum(expected == observed)),
        "byte_total": int(expected.size),
        "byte_accuracy": float(np.mean(expected == observed)),
        "block_matches": int(np.sum(np.all(expected == observed, axis=1))),
        "block_total": int(len(expected)),
        "block_accuracy": float(np.mean(np.all(expected == observed, axis=1))),
    }


def _confirm_key(
    key: bytes,
    plaintexts: np.ndarray,
    recipe: dict,
    routes: int,
    seed: int,
) -> dict:
    trace, _, expanded = _BASE._encrypt_trace(plaintexts, key)
    left30, right30 = trace[30]
    left32, _ = trace[32]
    delta = left30 ^ left32
    round_subkey = expanded[60:62]
    if not np.array_equal(delta, _BASE._f(right30, round_subkey)):
        raise RuntimeError("FEAL full-round distance-2 gate failed")
    reconstructed = _execute_reader_recipe(delta, round_subkey, recipe)
    factual = _accuracy(right30, reconstructed)

    route_rows = []
    for route in _BASE._routes(len(plaintexts), routes, seed):
        repaired = _execute_reader_recipe(delta[route], round_subkey, recipe)
        route_rows.append(_accuracy(right30, repaired))
    previous_subkey = expanded[58:60]
    wrong_subkey = _accuracy(
        right30,
        _execute_reader_recipe(delta, previous_subkey, recipe),
    )
    return {
        "factual_reader_inference": factual,
        "bvn_routes": {
            "count": routes,
            "max_byte_accuracy": max(row["byte_accuracy"] for row in route_rows),
            "mean_byte_accuracy": float(np.mean([row["byte_accuracy"] for row in route_rows])),
            "max_block_matches": max(row["block_matches"] for row in route_rows),
            "total_block_matches": sum(row["block_matches"] for row in route_rows),
        },
        "previous_round_subkey_control": wrong_subkey,
        "factual_above_all_bvn_routes": (
            factual["byte_accuracy"] > max(row["byte_accuracy"] for row in route_rows)
            and factual["block_matches"] > max(row["block_matches"] for row in route_rows)
        ),
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--pairs", type=int, default=8000)
    parser.add_argument("--keys", type=int, default=5)
    parser.add_argument("--routes", type=int, default=16)
    parser.add_argument("--seed", type=int, default=88728001)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--causal-output", type=Path, required=True)
    args = parser.parse_args()
    if min(args.pairs, args.keys, args.routes) < 1:
        raise ValueError("pairs, keys and routes must be positive")
    kat = _BASE._kat()
    causal = _build_graph(args.causal_output, args.pairs, args.keys, args.routes)
    recipe, reader_rows = _recipe_from_reader(args.causal_output)
    confirmations = []
    for key_index in range(args.keys):
        seed = args.seed + 1009 * key_index
        rng = np.random.default_rng(seed)
        key = rng.bytes(16)
        plaintexts = rng.integers(0, 256, size=(args.pairs, 8), dtype=np.uint8)
        print(f"FEAL-32X Reader inversion key={key_index + 1}/{args.keys}", flush=True)
        confirmations.append({
            "key_index": key_index,
            **_confirm_key(key, plaintexts, recipe, args.routes, seed ^ 0x1A2B),
        })
    retained = all(
        row["factual_reader_inference"]["block_accuracy"] == 1.0
        and row["factual_above_all_bvn_routes"]
        for row in confirmations
    )
    payload = {
        "schema": "feal32x-fullround-reader-inverse-v1",
        "evidence_stage": "FULLROUND_READER_INFERENCE_RETAINED" if retained else "NEW_BOUNDARY_IDENTIFIED",
        "result": (
            "The R30 right half is exactly reconstructed from the R30 xor R32 left-half "
            "difference and the known two-byte round subkey by executing the recipe stored in .causal."
        ),
        "kat": kat,
        "parameters": {
            "rounds": 32,
            "boundary": "R30_to_R32_fullround_endpoint",
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
        "factual_block_matches": [
            row["factual_reader_inference"]["block_matches"] for row in confirmations
        ],
        "bvn_total_block_matches": [
            row["bvn_routes"]["total_block_matches"] for row in confirmations
        ],
        "wrong_subkey_block_matches": [
            row["previous_round_subkey_control"]["block_matches"] for row in confirmations
        ],
    }, indent=2))


if __name__ == "__main__":
    main()

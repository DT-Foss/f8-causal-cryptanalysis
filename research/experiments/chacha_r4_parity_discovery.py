#!/usr/bin/env python3
"""Cross-key discovery of unary and pair-parity features in ChaCha R4 differentials."""

from __future__ import annotations

import argparse
import hashlib
import json
import platform
import sys
from pathlib import Path
from typing import Any

import numpy as np

from arx_carry_leak.atlas import chacha_counter_blocks, exact_sign_flip_test
from arx_carry_leak.crypto_causal import CryptoCausalBuilder


def _sign_bits(difference: np.ndarray) -> np.ndarray:
    bits = np.unpackbits(difference, axis=1, bitorder="little")
    # Float64 is intentional: the local macOS BLAS emitted overflow/NaN for
    # the otherwise safe Float32 512xN moment product.
    return bits.astype(np.float64) * 2.0 - 1.0


def _moments(difference: np.ndarray) -> tuple[np.ndarray, np.ndarray]:
    bits = np.unpackbits(difference, axis=1, bitorder="little")
    unary = bits.mean(axis=0, dtype=np.float64) * 2.0 - 1.0
    packed = np.packbits(bits, axis=0, bitorder="little")
    lookup = np.unpackbits(np.arange(256, dtype=np.uint8)[:, None], axis=1).sum(axis=1)
    pair = np.empty((bits.shape[1], bits.shape[1]), dtype=np.float64)
    # Avoid the broken Float32/Float64 Accelerate matmul in the pinned
    # NumPy/Python 3.13 environment. Packed XOR+popcount is exact and bounded.
    target_bytes = 64 * 1024 * 1024
    block = max(1, min(32, target_bytes // max(len(packed) * bits.shape[1], 1)))
    for start in range(0, bits.shape[1], block):
        end = min(start + block, bits.shape[1])
        xor = packed[:, start:end, None] ^ packed[:, None, :]
        distances = lookup[xor].sum(axis=0, dtype=np.int64)
        pair[start:end] = 1.0 - 2.0 * distances / len(bits)
    np.fill_diagonal(pair, 0.0)
    return unary, pair


def _bit(bit: int) -> dict[str, int]:
    return {"flat_bit": bit, "word": bit // 32, "bit_in_word": bit % 32}


def _rank_unary(effects: np.ndarray, null_effects: np.ndarray, top: int) -> tuple[list[dict[str, Any]], float]:
    mean = effects.mean(axis=0)
    null_mean = null_effects.mean(axis=0)
    null_max = float(np.max(np.abs(null_mean)))
    order = np.argsort(np.abs(mean))[::-1][:top]
    rows = []
    for bit in order:
        values = effects[:, bit].tolist()
        rows.append(
            {
                **_bit(int(bit)),
                "mean_effect": float(mean[bit]),
                "sample_sd_ddof1": float(effects[:, bit].std(ddof=1)),
                "per_seed_effects": values,
                "exact_sign_flip": exact_sign_flip_test(values),
                "same_sign_all_seeds": bool(np.all(effects[:, bit] > 0) or np.all(effects[:, bit] < 0)),
                "absolute_effect_over_global_null_max": float(abs(mean[bit]) / max(null_max, 1e-15)),
            }
        )
    return rows, null_max


def _rank_pairs(effects: np.ndarray, null_effects: np.ndarray, top: int) -> tuple[list[dict[str, Any]], float]:
    mean = effects.mean(axis=0)
    null_mean = null_effects.mean(axis=0)
    upper = np.triu_indices(mean.shape[0], k=1)
    null_max = float(np.max(np.abs(null_mean[upper])))
    flat = np.abs(mean[upper])
    selected = np.argpartition(flat, -top)[-top:]
    selected = selected[np.argsort(flat[selected])[::-1]]
    rows = []
    for index in selected:
        first = int(upper[0][index])
        second = int(upper[1][index])
        values = effects[:, first, second].tolist()
        rows.append(
            {
                "first": _bit(first),
                "second": _bit(second),
                "mean_parity_expectation_effect": float(mean[first, second]),
                "sample_sd_ddof1": float(effects[:, first, second].std(ddof=1)),
                "per_seed_effects": values,
                "exact_sign_flip": exact_sign_flip_test(values),
                "same_sign_all_seeds": bool(
                    np.all(effects[:, first, second] > 0) or np.all(effects[:, first, second] < 0)
                ),
                "absolute_effect_over_global_null_max": float(
                    abs(mean[first, second]) / max(null_max, 1e-15)
                ),
            }
        )
    return rows, null_max


def _run(args: argparse.Namespace) -> dict[str, Any]:
    unary_effects = []
    unary_null_effects = []
    pair_effects = []
    pair_null_effects = []
    seed_records = []
    for seed_index in range(args.seeds):
        seed = args.seed_base + 1009 * seed_index
        rng = np.random.default_rng(seed ^ 0xFA817)
        counters = rng.integers(0, 2**32, size=args.pairs, dtype=np.uint32)
        first = chacha_counter_blocks(counters, args.rounds, seed)
        second = chacha_counter_blocks(
            counters ^ np.uint32(1 << args.counter_bit), args.rounds, seed
        )
        permutation1 = rng.permutation(args.pairs)
        permutation2 = rng.permutation(args.pairs)
        real_unary, real_pair = _moments(first ^ second)
        null1_unary, null1_pair = _moments(first ^ second[permutation1])
        null2_unary, null2_pair = _moments(first ^ second[permutation2])
        unary_effects.append(real_unary - null1_unary)
        pair_effects.append(real_pair - null1_pair)
        unary_null_effects.append(null2_unary - null1_unary)
        pair_null_effects.append(null2_pair - null1_pair)
        seed_records.append(
            {
                "seed": seed,
                "real_difference_sha256": hashlib.sha256((first ^ second).tobytes()).hexdigest(),
                "null1_difference_sha256": hashlib.sha256((first ^ second[permutation1]).tobytes()).hexdigest(),
                "null2_difference_sha256": hashlib.sha256((first ^ second[permutation2]).tobytes()).hexdigest(),
            }
        )
        print(f"parity discovery seed={seed}", flush=True)
    unary = np.stack(unary_effects)
    unary_null = np.stack(unary_null_effects)
    pair = np.stack(pair_effects)
    pair_null = np.stack(pair_null_effects)
    top_unary, unary_null_max = _rank_unary(unary, unary_null, args.top)
    top_pairs, pair_null_max = _rank_pairs(pair, pair_null, args.top)
    return {
        "top_unary": top_unary,
        "top_pair_parities": top_pairs,
        "global_null_maxima": {
            "unary_absolute_mean_effect": unary_null_max,
            "pair_parity_absolute_mean_effect": pair_null_max,
        },
        "selection_gates": {
            "unary_above_global_null_max": sum(
                row["absolute_effect_over_global_null_max"] > 1 for row in top_unary
            ),
            "pair_parity_above_global_null_max": sum(
                row["absolute_effect_over_global_null_max"] > 1 for row in top_pairs
            ),
            "pair_parity_above_1_5x_global_null_max": sum(
                row["absolute_effect_over_global_null_max"] > 1.5 for row in top_pairs
            ),
        },
        "seed_records": seed_records,
    }


def _graph(result: dict[str, Any], parameters: dict[str, Any], source: str, output: Path) -> dict[str, Any]:
    builder = CryptoCausalBuilder(experiment="chacha_r4_parity_discovery", parameters=parameters)
    for rank, row in enumerate(result["top_pair_parities"][:32]):
        builder.add_triplet(
            edge_id=f"parity-rank-{rank + 1}",
            trigger=(
                f"r{parameters['rounds']}:diff_bit_{row['first']['flat_bit']}"
                f"_xor_diff_bit_{row['second']['flat_bit']}"
            ),
            mechanism="pair_parity_expectation_screen",
            outcome="real_pairing_vs_repairing_difference",
            confidence=1.0 - float(row["exact_sign_flip"]["two_sided_p"]),
            evidence_kind="training_key_discovery_only",
            source=source,
            attrs={**row, "requires_holdout": True},
        )
    return builder.save(output)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--causal-output", type=Path, required=True)
    parser.add_argument("--rounds", type=int, default=4)
    parser.add_argument("--counter-bit", type=int, default=15)
    parser.add_argument("--pairs", type=int, default=10000)
    parser.add_argument("--seeds", type=int, default=5)
    parser.add_argument("--seed-base", type=int, default=50000)
    parser.add_argument("--top", type=int, default=256)
    args = parser.parse_args()
    if args.pairs < 2000 or args.seeds < 3 or not 1 <= args.top <= 1000:
        raise ValueError("pairs >= 2000, seeds >= 3, top in [1, 1000] required")
    parameters = {
        "rounds": args.rounds,
        "counter_bit": args.counter_bit,
        "pairs": args.pairs,
        "seeds": args.seeds,
        "seed_base": args.seed_base,
        "top": args.top,
        "features": {"unary": 512, "pair_parity": 512 * 511 // 2},
        "selection_null": "independent repairing2 minus repairing1; global maximum over feature family",
    }
    result = _run(args)
    payload = {
        "schema_version": 1,
        "experiment": "chacha_r4_parity_discovery",
        "parameters": parameters,
        "environment": {
            "python": sys.version.split()[0],
            "platform": platform.platform(),
            "numpy": np.__version__,
        },
        "result": result,
        "scope_note": (
            "Training-key discovery only. No feature is a result until frozen and evaluated on disjoint keys. "
            "The global null maximum controls selection across all screened unary/parity features."
        ),
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n")
    source = "sha256:" + hashlib.sha256(args.output.read_bytes()).hexdigest()
    stats = _graph(result, parameters, source, args.causal_output)
    print(f"wrote {args.output}")
    print(f"wrote {args.causal_output} ({stats['triplets']} triplets)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

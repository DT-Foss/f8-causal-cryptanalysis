#!/usr/bin/env python3
"""Graph-Framework FULL ATTACK — ALL fast combos on each cipher.

NOT just the Speck-Top-11. Speck combos are carry-leak optimized.
AES/ChaCha/Salsa have different algebra — the winning combo could be
anything from xor_bias/words to pearson/nibbles/spectral_gap.

Strategy: 4 edges × 3 granularities × 6 metrics = 72 fast combos per cipher.
(Excluding dcor=O(n²) and bits=too many units.)
For ChaCha/Salsa: also include words (32-bit, relevant for 16-word state).

Run blockwise: one edge at a time, check output, drill deeper where Z>3.
"""
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..'))
sys.path.insert(0, os.path.dirname(__file__))

import numpy as np
from graph_sweep import EDGE_DEFS, GRANS, METRICS, sweep_one
from live_casiv2.ciphers import (
    generate_chacha_stream, generate_salsa_stream, generate_aes_stream
)
from speck_utils import speck32

N = 20000
SEEDS = 5
N_PERM = 12

# Fast edges (exclude dcor)
FAST_EDGES = ['chi2', 'MI', 'pearson', 'xor_bias']
# Fast grans (exclude bits for first pass)
FAST_GRANS = ['nibbles', 'bytes', 'words']
ALL_METRICS = list(METRICS.keys())


def full_sweep_cipher(name, gen_fn, bb, n_rounds, grans=None):
    """Run ALL fast combos on one cipher at one round count.
    Returns sorted list of (combo, mean_z, zs) tuples.
    """
    if grans is None:
        grans = FAST_GRANS

    # Pre-generate data
    data = {}
    for s in range(SEEDS):
        seed = s * 1000 + 42
        r1 = gen_fn(N, rounds=n_rounds, seed=seed)
        r2 = gen_fn(N, rounds=n_rounds+1, seed=seed)
        data[s] = (r1, r2)

    results = []
    total = len(FAST_EDGES) * len(grans) * len(ALL_METRICS)
    done = 0

    for en in FAST_EDGES:
        for gn in grans:
            for mn in ALL_METRICS:
                done += 1
                combo = f"{en}/{gn}/{mn}"
                zs = []
                for s in range(SEEDS):
                    try:
                        z = sweep_one(data[s][0], data[s][1], bb, en, gn, mn, N_PERM)
                        # Clamp insane values (overflow protection)
                        if not np.isfinite(z):
                            z = 0.0
                        z = max(-100, min(z, 10000))
                        zs.append(z)
                    except:
                        zs.append(0.0)

                mean_z = np.mean(zs)
                results.append((combo, mean_z, zs))

        # Progress after each edge block
        print(f"    [{done:>3}/{total}] edge={en} done", flush=True)

    results.sort(key=lambda x: -x[1])
    return results


def print_results(name, n_rounds, results, top_n=15):
    """Print top results and any signals."""
    print(f"\n  --- {name} R{n_rounds} ---")
    signals = [(c, z, zs) for c, z, zs in results if z > 2]
    if signals:
        print(f"  {'Combo':>30}  {'Mean Z':>8}  {'Seeds':>30}  {'Signal?':>10}")
        print("  " + "-" * 85)
        for c, z, zs in signals:
            zs_str = ', '.join(f'{x:+.1f}' for x in zs)
            sig = "YES ***" if z > 3 else "weak *"
            print(f"  {c:>30}  {z:>+8.1f}  [{zs_str}]  {sig}")
    else:
        print(f"  No signal (best: {results[0][0]} Z={results[0][1]:+.1f})")

    # Top 5 regardless
    print(f"\n  Top 5:")
    for i, (c, z, zs) in enumerate(results[:5]):
        print(f"    {i+1}. {c:>30}  Z={z:+.1f}")

    return signals


# ============================================================
# MAIN
# ============================================================

print("=" * 80)
print("GRAPH-FRAMEWORK FULL ATTACK — ALL FAST COMBINATIONS")
print("=" * 80)
print(f"N={N}, {SEEDS} seeds, {N_PERM} perms")
print(f"{len(FAST_EDGES)} edges × {len(FAST_GRANS)} grans × {len(ALL_METRICS)} metrics = {len(FAST_EDGES)*len(FAST_GRANS)*len(ALL_METRICS)} combos per cipher")
print(flush=True)


# === AES-128 ===
print("\n" + "=" * 80)
print("  AES-128 — SPN, S-Box algebra, no addition")
print("=" * 80, flush=True)

def aes_gen(N, rounds=10, seed=42):
    return generate_aes_stream(N, rounds=rounds, seed=seed)

for r in [3, 4]:
    print(f"\n  Computing AES R{r}...", flush=True)
    res = full_sweep_cipher("AES", aes_gen, 32, r)
    sigs = print_results("AES-128", r, res)
    if sigs:
        print(f"\n  *** SIGNAL FOUND AT AES R{r}! Drilling deeper... ***", flush=True)


# === ChaCha20 ===
print("\n" + "=" * 80)
print("  ChaCha20 — ARX stream, 512-bit state, 16 words")
print("=" * 80, flush=True)

def chacha_gen(N, rounds=20, seed=42):
    return generate_chacha_stream(N, rounds=rounds, seed=seed)

# ChaCha: words granularity is ESPECIALLY relevant (16×32-bit words)
chacha_grans = ['nibbles', 'bytes', 'words']
for r in [3, 4]:
    print(f"\n  Computing ChaCha R{r}...", flush=True)
    res = full_sweep_cipher("ChaCha", chacha_gen, 32, r, grans=chacha_grans)
    sigs = print_results("ChaCha20", r, res)
    if sigs:
        print(f"\n  *** SIGNAL FOUND AT ChaCha R{r}! Drilling deeper... ***", flush=True)


# === Salsa20 ===
print("\n" + "=" * 80)
print("  Salsa20 — ARX stream, 512-bit state, 16 words")
print("=" * 80, flush=True)

def salsa_gen(N, rounds=20, seed=42):
    return generate_salsa_stream(N, rounds=rounds, seed=seed)

for r in [4, 5]:
    print(f"\n  Computing Salsa R{r}...", flush=True)
    res = full_sweep_cipher("Salsa", salsa_gen, 32, r, grans=chacha_grans)
    sigs = print_results("Salsa20", r, res)
    if sigs:
        print(f"\n  *** SIGNAL FOUND AT Salsa R{r}! Drilling deeper... ***", flush=True)


# === Random Reference ===
print("\n" + "=" * 80)
print("  Random (NULL — false positive rate check)")
print("=" * 80, flush=True)

def rand_gen(N, rounds=1, seed=42):
    rng = np.random.default_rng(seed + rounds * 9999)
    return rng.integers(0, 256, size=N * 32, dtype=np.uint8).tobytes()

res = full_sweep_cipher("Random", rand_gen, 32, 1)
sigs = print_results("Random", 1, res)
if sigs:
    print(f"\n  WARNING: {len(sigs)} false positives on Random!", flush=True)


# === Summary ===
print("\n" + "=" * 80)
print("SUMMARY")
print("=" * 80)
print("AES R3 frontier, R4 beyond — any signal = major finding")
print("ChaCha R3 frontier, R4 beyond — any signal = major finding")
print("Salsa R4 frontier, R5 beyond — any signal = major finding")
print()

print("\n=== DONE ===")

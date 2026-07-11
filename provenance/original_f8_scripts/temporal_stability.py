#!/usr/bin/env python3
"""Temporal Graph Stability — Variance-Ratio Distinguisher.

Even if graph metrics LOOK random in expectation, reduced-round ciphers
might have MORE or LESS stable graphs across independent block batches.

Method:
1. Generate K independent batches of N_batch blocks
2. Compute graph metric on each batch → K values
3. Compare variance of cipher's K values vs random's K values
4. If cipher has systematically different variance → distinguisher

Tests: AES R3/R4, ChaCha R3/R4, Salsa R4/R5, Speck R15 (reference)
Metrics: top 4 from calibration (chi2/nibbles/max_edge, MI/nibbles/max_edge,
         chi2/nibbles/mean_edge, MI/nibbles/mean_edge)
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

K_BATCHES = 30        # Number of independent batches
N_BATCH = 5000        # Samples per batch
N_PERM = 10           # Permutations per metric computation

# Top combos from calibration
COMBOS = [
    ('chi2', 'nibbles', 'max_edge'),
    ('MI', 'nibbles', 'max_edge'),
    ('chi2', 'nibbles', 'mean_edge'),
    ('MI', 'nibbles', 'mean_edge'),
    ('pearson', 'nibbles', 'max_edge'),
    ('pearson', 'bytes', 'max_edge'),
]


def compute_batch_metrics(gen_fn, bb, n_rounds, combo, seed_base):
    """Compute graph metric on K independent batches.
    Returns array of K metric values (NOT Z-scores — raw metric values).
    """
    en, gn, mn = combo
    edge_fn = EDGE_DEFS[en]
    gran_fn = GRANS[gn]
    metric_fn = METRICS[mn]

    values = []
    for k in range(K_BATCHES):
        seed = seed_base + k * 137
        r1 = gen_fn(N_BATCH, rounds=n_rounds, seed=seed)
        r2 = gen_fn(N_BATCH, rounds=n_rounds + 1, seed=seed)

        out = gran_fn(r1, bb)
        diff_raw = np.frombuffer(r1, dtype=np.uint8).reshape(-1, bb) ^ \
                   np.frombuffer(r2, dtype=np.uint8).reshape(-1, bb)
        diff = gran_fn(diff_raw.tobytes(), bb)

        n = min(out.shape[0], diff.shape[0])
        out, diff = out[:n], diff[:n]

        mat = edge_fn(out, diff, n)
        val = metric_fn(mat)
        values.append(val)

    return np.array(values)


def variance_ratio_test(cipher_vals, random_vals, n_boot=1000):
    """Test if cipher variance differs from random variance.
    Uses permutation test on variance ratio.
    Returns Z-score for the variance difference.
    """
    var_c = np.var(cipher_vals)
    var_r = np.var(random_vals)

    if var_r < 1e-30 and var_c < 1e-30:
        return 0.0

    # F-ratio (cipher / random)
    if var_r > 0:
        real_ratio = var_c / var_r
    else:
        real_ratio = 1000.0  # cipher has variance, random doesn't

    # Permutation null: pool and re-split
    pooled = np.concatenate([cipher_vals, random_vals])
    n_c = len(cipher_vals)
    rng = np.random.default_rng(42)
    null_ratios = []
    for _ in range(n_boot):
        perm = rng.permutation(len(pooled))
        a = pooled[perm[:n_c]]
        b = pooled[perm[n_c:]]
        va, vb = np.var(a), np.var(b)
        if vb > 0:
            null_ratios.append(va / vb)
        else:
            null_ratios.append(1.0)

    nm = np.mean(null_ratios)
    ns = max(np.std(null_ratios), 1e-30)
    z = (real_ratio - nm) / ns
    return z


# ============================================================
# MAIN
# ============================================================

print("=" * 90)
print("TEMPORAL GRAPH STABILITY — VARIANCE-RATIO DISTINGUISHER")
print("=" * 90)
print(f"K={K_BATCHES} batches, N_batch={N_BATCH}, {N_PERM} perms per metric")
print(f"{len(COMBOS)} combos")
print(flush=True)


# Generator functions
def speck_gen(N, rounds=22, seed=42):
    raw, bb, bpw = speck32(N, n_rounds=rounds, seed=seed)
    return raw

def aes_gen(N, rounds=10, seed=42):
    return generate_aes_stream(N, rounds=rounds, seed=seed)

def chacha_gen(N, rounds=20, seed=42):
    return generate_chacha_stream(N, rounds=rounds, seed=seed)

def salsa_gen(N, rounds=20, seed=42):
    return generate_salsa_stream(N, rounds=rounds, seed=seed)

def rand_gen(N, rounds=1, seed=42):
    rng = np.random.default_rng(seed + rounds * 9999)
    return rng.integers(0, 256, size=N * 32, dtype=np.uint8).tobytes()


# Ciphers to test
ciphers = [
    ("Speck R15", speck_gen, 4, 15),
    ("AES R3", aes_gen, 32, 3),
    ("AES R4", aes_gen, 32, 4),
    ("ChaCha R3", chacha_gen, 32, 3),
    ("ChaCha R4", chacha_gen, 32, 4),
    ("Salsa R4", salsa_gen, 32, 4),
    ("Salsa R5", salsa_gen, 32, 5),
]


for combo in COMBOS:
    combo_name = '/'.join(combo)
    print(f"\n{'='*70}")
    print(f"  Combo: {combo_name}")
    print(f"{'='*70}")

    # Random baseline
    print(f"  Computing Random baseline...", flush=True)
    rand_vals = compute_batch_metrics(rand_gen, 32, 1, combo, seed_base=0)
    rand_var = np.var(rand_vals)
    print(f"  Random: mean={np.mean(rand_vals):.6f}, var={rand_var:.2e}", flush=True)

    print(f"\n  {'Cipher':>15}  {'Mean':>10}  {'Var':>12}  {'Var_ratio':>10}  {'Z':>8}  {'Signal?':>10}")
    print(f"  {'-'*75}", flush=True)

    for cname, gen_fn, bb, n_rounds in ciphers:
        cipher_vals = compute_batch_metrics(gen_fn, bb, n_rounds, combo, seed_base=0)
        z = variance_ratio_test(cipher_vals, rand_vals)
        var_c = np.var(cipher_vals)
        ratio = var_c / max(rand_var, 1e-30)

        sig = "YES ***" if abs(z) > 3 else ("weak *" if abs(z) > 2 else "no")
        print(f"  {cname:>15}  {np.mean(cipher_vals):>10.6f}  {var_c:>12.2e}  {ratio:>10.2f}  {z:>+8.1f}  {sig}", flush=True)


print("\n\n=== DONE ===")

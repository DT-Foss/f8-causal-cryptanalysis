#!/usr/bin/env python3
"""Temporal stability verification — ONE test, definitive answer.

First run found Z=+3.2 (AES R4) and Z=+5.7 (ChaCha R4) on chi2/nibbles/mean_edge.
This verifies with K=50 batches and 5 independent random baselines.

If median Z across baselines > 2: confirmed.
If not: no signal.
"""
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..'))
sys.path.insert(0, os.path.dirname(__file__))

import numpy as np
from graph_sweep import EDGE_DEFS, GRANS, METRICS
from live_casiv2.ciphers import generate_chacha_stream, generate_aes_stream

K = 50
N_BATCH = 5000


def batch_values(gen_fn, bb, n_rounds, en, gn, mn, seed_base):
    edge_fn, gran_fn, metric_fn = EDGE_DEFS[en], GRANS[gn], METRICS[mn]
    vals = []
    for k in range(K):
        seed = seed_base + k * 137
        r1 = gen_fn(N_BATCH, rounds=n_rounds, seed=seed)
        r2 = gen_fn(N_BATCH, rounds=n_rounds + 1, seed=seed)
        out = gran_fn(r1, bb)
        diff_raw = np.frombuffer(r1, dtype=np.uint8).reshape(-1, bb) ^ \
                   np.frombuffer(r2, dtype=np.uint8).reshape(-1, bb)
        diff = gran_fn(diff_raw.tobytes(), bb)
        n = min(out.shape[0], diff.shape[0])
        mat = edge_fn(out[:n], diff[:n], n)
        vals.append(metric_fn(mat))
    return np.array(vals)


def var_z(c, r, n_boot=2000):
    vc, vr = np.var(c), np.var(r)
    if vr < 1e-30 and vc < 1e-30:
        return 0.0
    ratio = vc / max(vr, 1e-30)
    pooled = np.concatenate([c, r])
    nc = len(c)
    rng = np.random.default_rng(42)
    nulls = []
    for _ in range(n_boot):
        p = rng.permutation(len(pooled))
        a, b = pooled[p[:nc]], pooled[p[nc:]]
        nulls.append(np.var(a) / max(np.var(b), 1e-30))
    return (ratio - np.mean(nulls)) / max(np.std(nulls), 1e-30)


def aes_gen(N, rounds=10, seed=42):
    return generate_aes_stream(N, rounds=rounds, seed=seed)

def chacha_gen(N, rounds=20, seed=42):
    return generate_chacha_stream(N, rounds=rounds, seed=seed)

def rand_gen(N, rounds=1, seed=42):
    rng = np.random.default_rng(seed + rounds * 9999)
    return rng.integers(0, 256, size=N * 32, dtype=np.uint8).tobytes()


print("=" * 80)
print("TEMPORAL STABILITY VERIFICATION")
print("=" * 80)
print(f"K={K}, N_batch={N_BATCH}, 5 random baselines, 2000 bootstrap")
print(flush=True)

RAND_BASES = [0, 10000, 20000, 30000, 40000]

for en, gn, mn in [('chi2', 'nibbles', 'mean_edge'), ('MI', 'nibbles', 'mean_edge')]:
    print(f"\n--- {en}/{gn}/{mn} ---", flush=True)

    # 5 random baselines
    rands = {sb: batch_values(rand_gen, 32, 1, en, gn, mn, sb) for sb in RAND_BASES}

    # Null check: random vs random
    r2r = [var_z(rands[RAND_BASES[i]], rands[RAND_BASES[j]])
           for i in range(5) for j in range(i+1, 5)]
    print(f"  Null check (rand vs rand): median Z={np.median(r2r):+.1f}, max={max(np.abs(r2r)):+.1f}", flush=True)

    for name, gen_fn, bb, rounds in [
        ("AES R3", aes_gen, 32, 3),
        ("AES R4", aes_gen, 32, 4),
        ("AES R5", aes_gen, 32, 5),
        ("ChaCha R3", chacha_gen, 32, 3),
        ("ChaCha R4", chacha_gen, 32, 4),
        ("ChaCha R5", chacha_gen, 32, 5),
    ]:
        cipher = batch_values(gen_fn, bb, rounds, en, gn, mn, seed_base=0)
        zs = [var_z(cipher, rands[sb]) for sb in RAND_BASES]
        med = np.median(zs)
        sig = "CONFIRMED" if abs(med) > 2 else "no"
        print(f"  {name:>12}: Zs=[{', '.join(f'{z:+.1f}' for z in zs)}]  median={med:+.1f}  {sig}", flush=True)

print("\n=== DONE ===")

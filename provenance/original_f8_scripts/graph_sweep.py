#!/usr/bin/env python3
"""Graph-Framework Parametric Sweep — FAST version.

Tests 5 edge × 4 granularity × 6 metric = 120 combinations.
Calibrates on Speck (known signal) vs Random (null).
Uses vectorized edge computation and capped unit counts.
"""
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..'))
sys.path.insert(0, os.path.dirname(__file__))

import numpy as np
import math
from scipy import stats
from speck_utils import speck32

from live_casiv2.ciphers import (
    generate_chacha_stream, generate_salsa_stream, generate_aes_stream
)


# ============================================================
# EDGE DEFINITIONS (vectorized — compute full matrix at once)
# ============================================================

def edges_chi2(out, diff, n):
    """Chi2 edge matrix. out/diff: (n, k) uint8 arrays."""
    k = out.shape[1]
    mat = np.zeros((k, k))
    for i in range(k):
        for j in range(k):
            a, b = out[:, i], diff[:, j]
            va, vb = int(a.max()) + 1, int(b.max()) + 1
            tbl = np.zeros((va, vb))
            np.add.at(tbl, (a, b), 1)
            rs = tbl.sum(1, keepdims=True)
            cs = tbl.sum(0, keepdims=True)
            exp = rs * cs / n
            ok = exp > 5
            if ok.sum() < max(va, vb):
                continue
            mat[i, j] = float(np.sum((tbl[ok] - exp[ok])**2 / exp[ok]))
    return mat


def edges_mi(out, diff, n):
    """MI edge matrix."""
    k = out.shape[1]
    mat = np.zeros((k, k))
    for i in range(k):
        for j in range(k):
            a, b = out[:, i], diff[:, j]
            va, vb = int(a.max()) + 1, int(b.max()) + 1
            tbl = np.zeros((va, vb))
            np.add.at(tbl, (a, b), 1)
            pj = tbl / n
            pa = pj.sum(1, keepdims=True)
            pb = pj.sum(0, keepdims=True)
            denom = pa * pb
            ok = (pj > 0) & (denom > 0)
            if ok.any():
                mat[i, j] = max(0, float(np.sum(pj[ok] * np.log2(pj[ok] / denom[ok]))))
    return mat


def edges_pearson(out, diff, n):
    """Absolute Pearson correlation matrix."""
    of = out.astype(float)
    df = diff.astype(float)
    # Standardize
    os = of.std(0); ds = df.std(0)
    os[os == 0] = 1; ds[ds == 0] = 1
    on = (of - of.mean(0)) / os
    dn = (df - df.mean(0)) / ds
    mat = np.abs(on.T @ dn / n)
    return mat


def edges_xor_bias(out, diff, n):
    """XOR bias: |P(a⊕b=0) - 0.5| for LSBs."""
    k = out.shape[1]
    mat = np.zeros((k, k))
    a_lsb = out & 1
    b_lsb = diff & 1
    for i in range(k):
        for j in range(k):
            xor = a_lsb[:, i] ^ b_lsb[:, j]
            mat[i, j] = abs(np.mean(xor == 0) - 0.5)
    return mat


def edges_dcor(out, diff, n):
    """Distance correlation (heavily subsampled)."""
    max_n = min(n, 500)  # Very aggressive subsample
    k = out.shape[1]
    mat = np.zeros((k, k))
    o = out[:max_n].astype(float)
    d = diff[:max_n].astype(float)
    m = max_n
    for i in range(k):
        A = np.abs(o[:, i:i+1] - o[:, i:i+1].T)
        A -= A.mean(0, keepdims=True); A -= A.mean(1, keepdims=True); A += A.mean()
        dvar_a = (A * A).mean()
        if dvar_a <= 0:
            continue
        for j in range(k):
            B = np.abs(d[:, j:j+1] - d[:, j:j+1].T)
            B -= B.mean(0, keepdims=True); B -= B.mean(1, keepdims=True); B += B.mean()
            dvar_b = (B * B).mean()
            if dvar_b <= 0:
                continue
            dcov2 = (A * B).mean()
            mat[i, j] = float(np.sqrt(max(0, dcov2)) / (dvar_a * dvar_b)**0.25)
    return mat


EDGE_DEFS = {
    'chi2': edges_chi2,
    'MI': edges_mi,
    'pearson': edges_pearson,
    'xor_bias': edges_xor_bias,
    'dcor': edges_dcor,
}


# ============================================================
# GRANULARITIES
# ============================================================

def to_bits(data, bb):
    d = np.frombuffer(data, dtype=np.uint8).reshape(-1, bb)
    n = d.shape[0]
    # Take 16 evenly spaced bits max
    n_bits = min(bb * 8, 16)
    step = max(1, (bb * 8) // n_bits)
    bits = np.zeros((n, n_bits), dtype=np.uint8)
    for idx in range(n_bits):
        bit_pos = idx * step
        byte_idx = bit_pos // 8
        bit_idx = 7 - (bit_pos % 8)
        bits[:, idx] = (d[:, byte_idx] >> bit_idx) & 1
    return bits


def to_nibbles(data, bb):
    d = np.frombuffer(data, dtype=np.uint8).reshape(-1, bb)
    n = d.shape[0]
    # Take max 16 nibbles
    n_nib = min(bb * 2, 16)
    step = max(1, (bb * 2) // n_nib)
    nibs = np.zeros((n, n_nib), dtype=np.uint8)
    for idx in range(n_nib):
        nib_pos = idx * step
        byte_idx = nib_pos // 2
        if nib_pos % 2 == 0:
            nibs[:, idx] = (d[:, byte_idx] >> 4) & 0xF
        else:
            nibs[:, idx] = d[:, byte_idx] & 0xF
    return nibs


def to_bytes(data, bb):
    d = np.frombuffer(data, dtype=np.uint8).reshape(-1, bb)
    # Take max 16 bytes
    if bb > 16:
        idx = np.linspace(0, bb-1, 16, dtype=int)
        return d[:, idx]
    return d


def to_words(data, bb, wb=4):
    d = np.frombuffer(data, dtype=np.uint8).reshape(-1, bb)
    # Quantize to top byte of each word
    n_words = bb // wb
    n = d.shape[0]
    words = np.zeros((n, min(n_words, 16)), dtype=np.uint8)
    step = max(1, n_words // 16)
    for idx in range(words.shape[1]):
        w = idx * step
        words[:, idx] = d[:, w * wb]  # Top byte
    return words


GRANS = {
    'bits': to_bits,
    'nibbles': to_nibbles,
    'bytes': to_bytes,
    'words': to_words,
}


# ============================================================
# GRAPH METRICS
# ============================================================

def m_sig_rate(mat):
    f = mat.flatten()
    if f.std() == 0: return 0.0
    return float(np.sum(f > f.mean() + 2*f.std()) / len(f))

def m_max_edge(mat):
    return float(mat.max())

def m_mean_edge(mat):
    return float(mat.mean())

def m_spectral_gap(mat):
    try:
        sym = (mat + mat.T) / 2
        ev = np.sort(np.abs(np.linalg.eigvalsh(sym)))[::-1]
        return float(ev[0] - ev[1]) if len(ev) >= 2 else float(ev[0])
    except:
        return 0.0

def m_clustering(mat):
    n = mat.shape[0]
    if n < 3: return 0.0
    f = mat.flatten()
    thr = np.percentile(f[f > 0], 75) if np.any(f > 0) else 0
    adj = (mat > thr).astype(float)
    cs = []
    for i in range(n):
        nb = np.where(adj[i] > 0)[0]
        k = len(nb)
        if k < 2: continue
        tri = sum(adj[u, v] for u in nb for v in nb if u < v)
        cs.append(2 * tri / (k * (k-1)))
    return float(np.mean(cs)) if cs else 0.0

def m_entropy(mat):
    f = mat.flatten()
    f = f[f > 0]
    if len(f) == 0: return 0.0
    p = f / f.sum()
    return float(-np.sum(p * np.log2(p + 1e-30)))


METRICS = {
    'sig_rate': m_sig_rate,
    'max_edge': m_max_edge,
    'mean_edge': m_mean_edge,
    'spectral_gap': m_spectral_gap,
    'clustering': m_clustering,
    'entropy': m_entropy,
}


# ============================================================
# SWEEP CORE
# ============================================================

def sweep_one(gen_R, gen_R1, bb, edge_name, gran_name, metric_name, n_perm=10):
    """One combination. gen_R/gen_R1 are already-generated bytes."""
    edge_fn = EDGE_DEFS[edge_name]
    gran_fn = GRANS[gran_name]
    metric_fn = METRICS[metric_name]

    out = gran_fn(gen_R, bb)
    diff_raw = np.frombuffer(gen_R, dtype=np.uint8).reshape(-1, bb) ^ \
               np.frombuffer(gen_R1, dtype=np.uint8).reshape(-1, bb)
    diff = gran_fn(diff_raw.tobytes(), bb)

    n = min(out.shape[0], diff.shape[0])
    out, diff = out[:n], diff[:n]

    mat = edge_fn(out, diff, n)
    real = metric_fn(mat)

    rng = np.random.default_rng(42)
    nulls = []
    for _ in range(n_perm):
        dp = diff[rng.permutation(n)]
        nm = edge_fn(out, dp, n)
        nulls.append(metric_fn(nm))

    nm = np.mean(nulls)
    ns = max(np.std(nulls), 1e-30)
    z = (real - nm) / ns
    return z


def run_cipher(name, gen_fn, bb, rounds, N, seeds, n_perm):
    """Run all 120 combos for one cipher config. Returns list of (combo, z) tuples."""
    results = []
    # Pre-generate data per seed (saves re-generation across combos)
    data_cache = {}
    for s in range(seeds):
        seed = s * 1000 + 42
        r1 = gen_fn(N, rounds=rounds, seed=seed)
        r2 = gen_fn(N, rounds=rounds+1, seed=seed)
        data_cache[s] = (r1, r2)

    total = len(EDGE_DEFS) * len(GRANS) * len(METRICS)
    done = 0
    for en in EDGE_DEFS:
        for gn in GRANS:
            for mn in METRICS:
                done += 1
                combo = f"{en}/{gn}/{mn}"
                zs = []
                for s in range(seeds):
                    try:
                        z = sweep_one(data_cache[s][0], data_cache[s][1], bb, en, gn, mn, n_perm)
                        zs.append(z)
                    except Exception as e:
                        zs.append(0.0)
                mean_z = np.mean(zs)
                results.append((combo, mean_z))
                if done % 20 == 0:
                    print(f"    [{done:>3}/{total}] {combo:>30}  Z={mean_z:>+8.1f}", flush=True)

    return results


# ============================================================
# MAIN
# ============================================================

if __name__ == '__main__':
    N = 10000
    SEEDS = 3
    N_PERM = 10

    print("=" * 90)
    print("GRAPH-FRAMEWORK PARAMETRIC SWEEP — CALIBRATION")
    print("=" * 90)
    print(f"N={N}, {SEEDS} seeds, {N_PERM} perms, max 16 units per granularity")
    print(flush=True)

    # --- Speck R15 (known signal) ---
    print("\n--- Speck 32/64 R15 (KNOWN SIGNAL) ---", flush=True)
    def speck_gen(N, rounds=22, seed=42):
        raw, bb, bpw = speck32(N, n_rounds=rounds, seed=seed)
        return raw
    speck_res = run_cipher("Speck", speck_gen, 4, 15, N, SEEDS, N_PERM)

    # --- Random (NULL) ---
    print("\n--- Random (NULL — should be ~0) ---", flush=True)
    def rand_gen(N, rounds=1, seed=42):
        rng = np.random.default_rng(seed + rounds * 9999)
        return rng.integers(0, 256, size=N * 4, dtype=np.uint8).tobytes()
    rand_res = run_cipher("Random", rand_gen, 4, 1, N, SEEDS, N_PERM)

    # --- Combine and rank ---
    speck_dict = {c: z for c, z in speck_res}
    rand_dict = {c: z for c, z in rand_res}

    ranked = []
    for combo in speck_dict:
        sz = speck_dict[combo]
        rz = rand_dict.get(combo, 0)
        disc = sz - abs(rz)
        ranked.append({'combo': combo, 'speck_z': sz, 'rand_z': rz, 'disc': disc})

    ranked.sort(key=lambda x: -x['disc'])

    print()
    print("=" * 90)
    print("TOP 30 COMBINATIONS (by discriminant = Speck_Z - |Rand_Z|)")
    print("=" * 90)
    print(f"{'Rk':>3}  {'Combination':>30}  {'Speck Z':>8}  {'Rand Z':>8}  {'Disc':>8}  {'Verdict':>8}")
    print("-" * 78)
    for i, r in enumerate(ranked[:30]):
        v = "GOOD" if r['speck_z'] > 3 and abs(r['rand_z']) < 2 else (
            "FP" if abs(r['rand_z']) > 2 else "weak")
        print(f"  {i+1:>2}  {r['combo']:>30}  {r['speck_z']:>+8.1f}  {r['rand_z']:>+8.1f}  {r['disc']:>+8.1f}  {v:>8}")

    # Summary by dimension
    for dim_name, dim_key in [("EDGE", 0), ("GRANULARITY", 1), ("METRIC", 2)]:
        print(f"\nSUMMARY BY {dim_name}:")
        buckets = {}
        for r in ranked:
            parts = r['combo'].split('/')
            key = parts[dim_key]
            if key not in buckets:
                buckets[key] = []
            buckets[key].append(r)
        for key in sorted(buckets, key=lambda k: -np.mean([x['disc'] for x in buckets[k]])):
            subset = buckets[key]
            md = np.mean([x['disc'] for x in subset])
            n_good = sum(1 for x in subset if x['speck_z'] > 3 and abs(x['rand_z']) < 2)
            print(f"  {key:>15}: mean_disc={md:>+7.1f}, good={n_good}/{len(subset)}")

    # Save top 20 combos
    top20 = [r['combo'] for r in ranked[:20] if r['speck_z'] > 3 and abs(r['rand_z']) < 2]
    print(f"\n--- TOP {len(top20)} CLEAN COMBOS FOR ATTACK RUN ---")
    for c in top20:
        print(f"  {c}")

    print("\n=== DONE ===")

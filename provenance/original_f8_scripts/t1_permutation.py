#!/usr/bin/env python3
"""T1: Permutation sanity check. Permuted R+1 rows must give ~5% (null)."""
import sys, os; sys.path.insert(0, os.path.dirname(__file__))
from speck_utils import *

N, SEEDS, SHIFT = 20000, 5, 5
n_bins = 2 ** (8 - SHIFT)

def f8_permuted(N_blocks, seed, base=7, n_rp=8):
    n_sig = n_total = 0
    rng_perm = np.random.default_rng(seed + 999)
    for R in range(base, base + n_rp):
        raw_R, bb, _ = speck32(N_blocks, n_rounds=R, seed=seed)
        raw_R1, _, _ = speck32(N_blocks, n_rounds=R+1, seed=seed)
        data_R = np.frombuffer(raw_R, dtype=np.uint8).reshape(-1, bb)
        data_R1 = np.frombuffer(raw_R1, dtype=np.uint8).reshape(-1, bb)
        # Permute R+1 rows
        perm = rng_perm.permutation(data_R1.shape[0])
        data_R1 = data_R1[perm]
        diff = data_R ^ data_R1
        out_q = data_R >> SHIFT; diff_q = diff >> SHIFT
        for i in range(bb):
            for j in range(bb):
                table = np.zeros((n_bins, n_bins), dtype=float)
                np.add.at(table, (out_q[:, i], diff_q[:, j]), 1)
                rs = table.sum(axis=1, keepdims=True); cs = table.sum(axis=0, keepdims=True)
                exp = rs * cs / N_blocks; valid = exp > 5
                if np.sum(valid) < n_bins: continue
                chi2 = float(np.sum((table[valid] - exp[valid])**2 / exp[valid]))
                p = float(stats.chi2.sf(chi2, (n_bins-1)**2))
                n_total += 1
                if p < 0.05: n_sig += 1
    return n_sig / max(n_total, 1)

print("=== T1: PERMUTATION SANITY CHECK ===\n")
for label, fn in [("Normal", lambda s: f8_sigrate(speck32, 7, 8, N, s)), ("Permuted", lambda s: f8_permuted(N, s))]:
    rates = [fn(s*1000+42) for s in range(SEEDS)]
    print(f"  {label:>10}: sig_rate={np.mean(rates):.4f} ± {np.std(rates):.4f}")
print("\nExpected: Normal ≈ 0.18, Permuted ≈ 0.05")

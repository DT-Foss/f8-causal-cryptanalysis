#!/usr/bin/env python3
"""T8: Direction analysis — only out(R)→diff(R→R+1) shows signal."""
import sys, os; sys.path.insert(0, os.path.dirname(__file__))
from speck_utils import *

N, SEEDS, SHIFT = 20000, 10, 5
n_bins = 2 ** (8 - SHIFT)

def chi2_pair(A, B):
    n = A.shape[0]; n_sig = n_total = 0
    Aq = A >> SHIFT; Bq = B >> SHIFT
    for i in range(4):
        for j in range(4):
            table = np.zeros((n_bins, n_bins), dtype=float)
            np.add.at(table, (Aq[:, i], Bq[:, j]), 1)
            rs = table.sum(axis=1, keepdims=True); cs = table.sum(axis=0, keepdims=True)
            exp = rs * cs / n; valid = exp > 5
            if np.sum(valid) < n_bins: continue
            chi2 = float(np.sum((table[valid] - exp[valid])**2 / exp[valid]))
            p = float(stats.chi2.sf(chi2, (n_bins-1)**2))
            n_total += 1
            if p < 0.05: n_sig += 1
    return n_sig / max(n_total, 1)

print("=== T8: DIRECTION ANALYSIS ===\n")
directions = {"out(R) vs diff(R→R+1)": [], "diff(R-1→R) vs out(R)": [],
              "diff(R→R+1) vs diff(R+1→R+2)": [], "out(R) vs out(R+1)": []}

for s_idx in range(SEEDS):
    seed = s_idx * 1000 + 42
    per_dir = {k: [] for k in directions}
    for R in range(10, 18):
        raw = {}
        for r in [R-1, R, R+1, R+2]:
            if r not in raw:
                raw[r] = np.frombuffer(speck32(N, n_rounds=r, seed=seed)[0], dtype=np.uint8).reshape(-1, 4)
        out_R = raw[R]; out_R1 = raw[R+1]; diff_R_R1 = out_R ^ out_R1
        per_dir["out(R) vs diff(R→R+1)"].append(chi2_pair(out_R, diff_R_R1))
        if R-1 in raw: per_dir["diff(R-1→R) vs out(R)"].append(chi2_pair(raw[R-1] ^ out_R, out_R))
        if R+2 in raw: per_dir["diff(R→R+1) vs diff(R+1→R+2)"].append(chi2_pair(diff_R_R1, out_R1 ^ raw[R+2]))
        per_dir["out(R) vs out(R+1)"].append(chi2_pair(out_R, out_R1))
    for k in directions:
        if per_dir[k]: directions[k].append(np.mean(per_dir[k]))

for name, rates in directions.items():
    mean_r = np.mean(rates); std_r = np.std(rates)
    t = (mean_r - 0.05) / (std_r / math.sqrt(len(rates))) if std_r > 0 else 0
    sig = "***" if abs(t) > 3 else ""
    print(f"  {name:>40}: {mean_r:.4f}±{std_r:.4f}  t={t:+.1f} {sig}")

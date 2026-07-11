#!/usr/bin/env python3
"""P1: Speck 128/256 — F8 at the real-world variant."""
import sys, os; sys.path.insert(0, os.path.dirname(__file__))
from speck_utils import *

N, SEEDS = 20000, 10
print("=== P1: SPECK 128/256 ===\n")

total_chi2 = {}
all_rates = []
for s_idx in range(SEEDS):
    seed = s_idx * 1000 + 42
    _, _, rate, chi2_map = f8_test(speck128, 18, 8, N, seed)
    all_rates.append(rate)
    for k, v in chi2_map.items():
        total_chi2.setdefault(k, []).extend(v)
    print(f"  Seed {s_idx}: sig_rate={rate:.4f}")

mean_r = np.mean(all_rates); std_r = np.std(all_rates)
t = (mean_r - 0.05) / (std_r / math.sqrt(SEEDS)) if std_r > 0 else 0
print(f"\n  sig_rate = {mean_r:.4f} ± {std_r:.4f}, t = {t:+.1f}")

crit = stats.chi2.ppf(0.95, 49)
bb, bpw = 16, 8
for qname, cond in [("out_x→diff_x", lambda i,j: i<bpw and j<bpw),
                     ("out_x→diff_y", lambda i,j: i<bpw and j>=bpw),
                     ("out_y→diff_x", lambda i,j: i>=bpw and j<bpw),
                     ("out_y→diff_y", lambda i,j: i>=bpw and j>=bpw)]:
    rejs = [np.mean([1 if c > crit else 0 for c in total_chi2[(i,j)]])
            for i in range(bb) for j in range(bb) if cond(i,j) and (i,j) in total_chi2]
    print(f"  {qname}: {np.mean(rejs):.4f}")

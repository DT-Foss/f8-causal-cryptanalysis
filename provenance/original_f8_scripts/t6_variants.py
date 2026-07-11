#!/usr/bin/env python3
"""T6: All Speck variants (blocksize-aware). Monotone decay with word size."""
import sys, os; sys.path.insert(0, os.path.dirname(__file__))
from speck_utils import *

N, SEEDS = 20000, 10
print("=== T6: SPECK VARIANT SCALING (blocksize-aware) ===\n")

variants = [
    ("Speck 32/64", speck32, 10, 4, 2),
    ("Speck 48/96", speck48, 12, 6, 3),
    ("Speck 64/128", speck64, 15, 8, 4),
    ("Speck 128/256", speck128, 18, 16, 8),
]

for name, fn, base, bb, bpw in variants:
    total_chi2 = {}
    all_rates = []
    for s_idx in range(SEEDS):
        seed = s_idx * 1000 + 42
        _, _, rate, chi2_map = f8_test(fn, base, 8, N, seed)
        all_rates.append(rate)
        for k, v in chi2_map.items():
            total_chi2.setdefault(k, []).extend(v)
    mean_r = np.mean(all_rates); std_r = np.std(all_rates)
    t = (mean_r - 0.05) / (std_r / math.sqrt(SEEDS)) if std_r > 0 else 0

    crit = stats.chi2.ppf(0.95, 49)
    xy_rejs = [np.mean([1 if c > crit else 0 for c in total_chi2[(i,j)]])
               for i in range(bb) for j in range(bb) if i < bpw and j >= bpw]

    print(f"  {name:>16}: sig_rate={mean_r:.4f}±{std_r:.4f}  t={t:+.1f}  crossover_rej={np.mean(xy_rejs):.3f}")

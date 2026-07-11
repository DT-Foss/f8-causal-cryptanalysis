#!/usr/bin/env python3
"""P2: Round constancy — sig_rate flat plateau, no decay."""
import sys, os, time; sys.path.insert(0, os.path.dirname(__file__))
from speck_utils import *

N, SEEDS = 20000, 5
print("=== P2: ROUND CONSTANCY ===\n")

variants = [
    ("Speck 32/64", speck32, 22, [2, 5, 10, 15, 20]),
    ("Speck 64/128", speck64, 27, [2, 5, 10, 15, 20, 25]),
    ("Speck 128/256", speck128, 34, [2, 5, 10, 15, 20, 25, 30]),
]

for name, fn, max_r, bases in variants:
    print(f"\n--- {name} ---")
    bases = [b for b in bases if b + 1 <= max_r]
    for base in bases:
        rates = []
        for s_idx in range(SEEDS):
            seed = s_idx * 1000 + 42
            # Single round pair
            rate = f8_sigrate(fn, base, 1, N, seed)
            rates.append(rate)
        mean_r = np.mean(rates); std_r = np.std(rates)
        t = (mean_r - 0.05) / (std_r / math.sqrt(SEEDS)) if std_r > 0 else 0
        sig = "***" if t > 3 else ""
        print(f"  R{base:>3}: sig_rate={mean_r:.4f}±{std_r:.4f}  t={t:+.1f} {sig}")

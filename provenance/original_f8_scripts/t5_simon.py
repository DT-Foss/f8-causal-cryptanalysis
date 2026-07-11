#!/usr/bin/env python3
"""T5: SIMON 32/64 — AND+Rotation instead of Addition. Must show null."""
import sys, os; sys.path.insert(0, os.path.dirname(__file__))
from speck_utils import *

N, SEEDS = 20000, 10
print("=== T5: SIMON 32/64 vs SPECK 32/64 ===\n")
for name, fn in [("Speck 32/64", speck32), ("SIMON 32/64", simon_gen)]:
    mean_r, std_r, t, _ = multi_seed_f8(fn, 10, 8, N, SEEDS)
    sig = "***" if t > 3 else "(null)"
    print(f"  {name:>15}: sig_rate={mean_r:.4f}±{std_r:.4f}  t={t:+.1f} {sig}")
print("\nSIMON must be null → modular addition is the mechanism")

#!/usr/bin/env python3
"""T2: Quantization sweep — signal at >>3 through >>6, lost at >>7."""
import sys, os; sys.path.insert(0, os.path.dirname(__file__))
from speck_utils import *

N, SEEDS = 20000, 10
print("=== T2: QUANTIZATION SWEEP ===\n")
print(f"{'Shift':>6} {'Bins':>5} {'sig_rate':>10} {'t':>8}")
print("-" * 35)
for shift in [3, 4, 5, 6, 7]:
    mean_r, std_r, t, _ = multi_seed_f8(speck32, 10, 8, N, SEEDS, shift)
    sig = "***" if t > 3 else ""
    print(f"  >>{shift}   {2**(8-shift):>4}   {mean_r:.4f}±{std_r:.4f}  {t:+6.1f} {sig}")

#!/usr/bin/env python3
"""T9: N-scaling — sig_rate constant, signal exists at N=1000."""
import sys, os, time; sys.path.insert(0, os.path.dirname(__file__))
from speck_utils import *

print("=== T9: N-SCALING ===\n")
print(f"{'N':>8}  {'sig_rate':>10}  {'t':>8}  {'time':>6}")
for N in [1000, 2000, 5000, 10000, 20000, 50000, 100000]:
    t0 = time.time()
    mean_r, std_r, t, _ = multi_seed_f8(speck32, 10, 8, N, 5)
    print(f"{N:>8}  {mean_r:.4f}±{std_r:.4f}  {t:+6.1f}  {time.time()-t0:>5.1f}s")

#!/usr/bin/env python3
"""P3: Bit-level MI heatmap — rotation is the mechanism."""
import sys, os; sys.path.insert(0, os.path.dirname(__file__))
from speck_utils import *

N, SEEDS = 50000, 5

def mi_2x2(a, b, n):
    n00 = int(np.sum((a==0)&(b==0))); n01 = int(np.sum((a==0)&(b==1)))
    n10 = int(np.sum((a==1)&(b==0))); n11 = int(np.sum((a==1)&(b==1)))
    H_ab = 0
    for c in [n00,n01,n10,n11]:
        p = c/n
        if p > 0: H_ab -= p * math.log2(p)
    pa = (n10+n11)/n; pb = (n01+n11)/n
    Ha = -pa*math.log2(pa)-(1-pa)*math.log2(1-pa) if 0<pa<1 else 0
    Hb = -pb*math.log2(pb)-(1-pb)*math.log2(1-pb) if 0<pb<1 else 0
    return max(0, Ha + Hb - H_ab)

print("=== P3: BIT-LEVEL MI HEATMAP (Speck 32/64) ===\n")
mi = np.zeros((16, 16))
for s_idx in range(SEEDS):
    seed = s_idx * 1000 + 42
    raw_R, _, _ = speck32(N, n_rounds=15, seed=seed)
    raw_R1, _, _ = speck32(N, n_rounds=16, seed=seed)
    d_R = np.frombuffer(raw_R, dtype=np.uint8).reshape(-1, 4)
    d_R1 = np.frombuffer(raw_R1, dtype=np.uint8).reshape(-1, 4)
    x_R = d_R[:,0].astype(np.uint16)*256 + d_R[:,1].astype(np.uint16)
    y_R = d_R[:,2].astype(np.uint16)*256 + d_R[:,3].astype(np.uint16)
    y_R1 = d_R1[:,2].astype(np.uint16)*256 + d_R1[:,3].astype(np.uint16)
    diff_y = y_R ^ y_R1
    for i in range(16):
        xb = ((x_R >> i) & 1).astype(np.uint8)
        for j in range(16):
            dyb = ((diff_y >> j) & 1).astype(np.uint8)
            mi[i, j] += mi_2x2(xb, dyb, N)
mi /= SEEDS

print("MI × 10000 (x_bit[row] → diff_y_bit[col]), MSB at top:")
print(f"  {'x\\dy':>6}", end="")
for j in range(15, -1, -1): print(f" {j:>4}", end="")
print()
for i in range(15, -1, -1):
    print(f"  {i:>4} ", end="")
    for j in range(15, -1, -1):
        v = mi[i,j]*10000
        print(f" {v:>4.0f}" if v > 5 else "    .", end="")
    print()

print(f"\nActive pairs: {int(np.sum(mi > 0.001))}/256")
active = mi[mi > 0.001]
if len(active): print(f"Mean MI/pair: {np.mean(active):.6f} bits ({np.mean(active)*10000:.0f} × 10⁻⁴)")
dead = [i for i in range(16) if np.sum(mi[i,:]) * 10000 < 5]
print(f"Dead x-bits: {dead}")

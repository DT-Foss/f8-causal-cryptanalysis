#!/usr/bin/env python3
"""P4: MI-based leak rate across all Speck variants."""
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

print("=== P4: MI-BASED LEAK RATE ===\n")
variants = [
    ("Speck 32/64", 16, 4, 7, 2, 22, 15),
    ("Speck 48/96", 24, 4, 8, 3, 23, 15),
    ("Speck 64/128", 32, 4, 8, 3, 27, 18),
    ("Speck 128/256", 64, 4, 8, 3, 34, 22),
]

print(f"{'Variant':>16}  {'α/β':>5}  {'Active':>7}  {'MI/pair':>10}  {'Total MI':>10}  {'Leak%':>7}")
print("-" * 65)
for name, ws, kw, alpha, beta, nr, base in variants:
    mi_diag = np.zeros(ws)
    for s_idx in range(SEEDS):
        seed = s_idx * 1000 + 42
        raw_R, bb, bpw = speck_gen(N, ws, kw, alpha, beta, base, seed)
        raw_R1, _, _ = speck_gen(N, ws, kw, alpha, beta, base+1, seed)
        d_R = np.frombuffer(raw_R, dtype=np.uint8).reshape(-1, bb)
        d_R1 = np.frombuffer(raw_R1, dtype=np.uint8).reshape(-1, bb)
        x_R = np.zeros(N, dtype=np.uint64); y_R = np.zeros(N, dtype=np.uint64)
        y_R1 = np.zeros(N, dtype=np.uint64)
        for b in range(bpw):
            sh = 8*(bpw-1-b)
            x_R |= d_R[:,b].astype(np.uint64) << sh
            y_R |= d_R[:,bpw+b].astype(np.uint64) << sh
            y_R1 |= d_R1[:,bpw+b].astype(np.uint64) << sh
        diff_y = y_R ^ y_R1
        for i in range(ws):
            j = (i - alpha) % ws
            xb = ((x_R >> i) & 1).astype(np.uint8)
            dyb = ((diff_y >> j) & 1).astype(np.uint8)
            mi_diag[i] += mi_2x2(xb, dyb, N)
    mi_diag /= SEEDS
    active = mi_diag[mi_diag > 0.001]
    n_active = len(active)
    mi_per = np.mean(active) if n_active else 0
    total = np.sum(active)
    leak = (total / ws) * 100
    dead = [i for i in range(ws) if mi_diag[i] <= 0.001]
    print(f"{name:>16}  {alpha}/{beta}    {n_active:>2}/{ws}   {mi_per:.6f}  {total:.4f} bits  {leak:.2f}%")
    print(f"{'':>16}  Dead bits: {dead}")

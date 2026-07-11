#!/usr/bin/env python3
"""P6b: Test whether β death threshold scales with word size."""
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

def measure_mi_general(ws, alpha, beta, base_round):
    """Measure MI at arbitrary word size."""
    kw = 4
    bpw = ws // 8
    mi_vals = []
    for s_idx in range(SEEDS):
        seed = s_idx * 1000 + 42
        raw_R, bb, bpw_act = speck_gen(N, ws, kw, alpha, beta, base_round, seed)
        raw_R1, _, _ = speck_gen(N, ws, kw, alpha, beta, base_round + 1, seed)
        d_R = np.frombuffer(raw_R, dtype=np.uint8).reshape(-1, bb)
        d_R1 = np.frombuffer(raw_R1, dtype=np.uint8).reshape(-1, bb)
        # Reconstruct words
        x_R = np.zeros(N, dtype=np.uint64); y_R = np.zeros(N, dtype=np.uint64)
        y_R1 = np.zeros(N, dtype=np.uint64)
        for b in range(bpw_act):
            sh = 8*(bpw_act-1-b)
            x_R |= d_R[:,b].astype(np.uint64) << sh
            y_R |= d_R[:,bpw_act+b].astype(np.uint64) << sh
            y_R1 |= d_R1[:,bpw_act+b].astype(np.uint64) << sh
        diff_y = y_R ^ y_R1
        # Measure MI on diagonal
        mi_round = []
        for i in range(ws):
            j = (i - alpha) % ws
            xb = ((x_R >> i) & 1).astype(np.uint8)
            dyb = ((diff_y >> j) & 1).astype(np.uint8)
            mi_round.append(mi_2x2(xb, dyb, N))
        mi_vals.append(mi_round)
    mi_avg = np.mean(mi_vals, axis=0)
    active = mi_avg[mi_avg > 0.001]
    n_active = len(active)
    mi_per = np.mean(active) if n_active else 0
    return n_active, mi_per

# Test β=5 (which was zero at WS=16) at larger word sizes
print("=== P6b: β DEATH THRESHOLD vs WORD SIZE ===\n")
print("Testing β=5 (dead at WS=16) at larger word sizes:\n")

configs = [
    # (ws, alpha, beta, base_round, label)
    (16, 7, 5, 15, "WS=16"),
    (24, 8, 5, 15, "WS=24"),
    (32, 8, 5, 18, "WS=32"),
    (64, 8, 5, 22, "WS=64"),
]

print(f"{'Config':>10}  {'β':>3}  {'Active':>7}  {'MI/pair':>10}")
print("-" * 40)
for ws, alpha, beta, base, label in configs:
    n_active, mi_per = measure_mi_general(ws, alpha, beta, base)
    print(f"{label:>10}  {beta:>3}    {n_active:>2}/{ws}   {mi_per:.6f}")

# Now sweep β at WS=32 to find its threshold
print(f"\n\n=== β SWEEP AT WS=32 (α=8) ===\n")
print(f"{'β':>3}  {'Active':>7}  {'MI/pair':>10}  {'log₂(MI)':>10}")
print("-" * 40)
for beta in range(1, 12):
    n_active, mi_per = measure_mi_general(32, 8, beta, 18)
    log_mi = math.log2(mi_per) if mi_per > 0 else float('-inf')
    print(f"{beta:>3}    {n_active:>2}/32   {mi_per:.6f}  {log_mi:>10.3f}")

# And at WS=64
print(f"\n\n=== β SWEEP AT WS=64 (α=8) ===\n")
print(f"{'β':>3}  {'Active':>7}  {'MI/pair':>10}  {'log₂(MI)':>10}")
print("-" * 40)
for beta in [1, 2, 3, 4, 5, 6, 8, 10, 14]:
    n_active, mi_per = measure_mi_general(64, 8, beta, 22)
    log_mi = math.log2(mi_per) if mi_per > 0 else float('-inf')
    print(f"{beta:>3}    {n_active:>2}/64   {mi_per:.6f}  {log_mi:>10.3f}")

print("\n=== DONE ===")

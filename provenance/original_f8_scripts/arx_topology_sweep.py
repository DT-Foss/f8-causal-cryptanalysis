#!/usr/bin/env python3
"""B3: ARX Topology Sweep — Leak profile for all ARX round-function variants.

Tests every relevant ARX topology to understand which operation ORDER
creates the carry-leak:

1. ADD→ROT→XOR (Speck-like): x' = ROL(x+y, β) ^ k
2. ROT→ADD→XOR (alt-Speck):  x' = (ROL(x,β) + y) ^ k
3. ADD→XOR→ROT (Threefish-like): x' = ROL((x+y) ^ k, β)
4. XOR→ADD→ROT:               x' = ROL((x^k) + y, β)
5. Bare addition only:        x' = (x + y) & mask
6. ADD then ROT on OTHER operand (Threefish MIX): e0=x+y; e1=ROL(y,β)^e0

For each topology, sweep β=1..8 and measure F8 MI.
"""
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..'))
sys.path.insert(0, os.path.dirname(__file__))

import numpy as np
import math

N = 20000
SEEDS = 3
N_PERM = 15
WS = 16
MASK = (1 << WS) - 1
ALPHA = 7  # Fixed ROR constant


def rol(v, r, ws=WS):
    return ((v << r) | (v >> (ws - r))) & ((1 << ws) - 1)

def ror(v, r, ws=WS):
    return ((v >> r) | (v << (ws - r))) & ((1 << ws) - 1)


# ============================================================
# TOPOLOGY DEFINITIONS — each takes (x, y, k, beta) → (x', y')
# ============================================================

def topo_speck(x, y, k, beta):
    """Speck: ROR(x,α)+y → XOR k → ROL(y,β) ^ x'"""
    x_new = ((ror(x, ALPHA) + y) & MASK) ^ k
    y_new = rol(y, beta) ^ x_new
    return x_new, y_new

def topo_rot_add_xor(x, y, k, beta):
    """ROT→ADD→XOR: ROL(x,β)+y → XOR k"""
    x_new = ((rol(x, beta) + y) & MASK) ^ k
    y_new = ror(y, ALPHA) ^ x_new  # y gets different rotation
    return x_new, y_new

def topo_add_xor_rot(x, y, k, beta):
    """ADD→XOR→ROT: ROL((x+y) ^ k, β)"""
    s = (x + y) & MASK
    x_new = rol(s ^ k, beta)
    y_new = ror(y, ALPHA) ^ x_new
    return x_new, y_new

def topo_xor_add_rot(x, y, k, beta):
    """XOR→ADD→ROT: ROL((x^k)+y, β)"""
    x_new = rol(((x ^ k) + y) & MASK, beta)
    y_new = ror(y, ALPHA) ^ x_new
    return x_new, y_new

def topo_bare_add(x, y, k, beta):
    """Bare addition (no rotation, no XOR)"""
    x_new = (x + y) & MASK
    y_new = x ^ y  # some mixing to avoid trivial state
    return x_new, y_new

def topo_threefish_mix(x, y, k, beta):
    """Threefish MIX: e0=x+y, e1=ROL(y,β)^e0. No key XOR in MIX."""
    e0 = (x + y) & MASK
    e1 = rol(y, beta) ^ e0
    return e0, e1


TOPOLOGIES = {
    'Speck (ROR→ADD→XOR)': topo_speck,
    'ROT→ADD→XOR':         topo_rot_add_xor,
    'ADD→XOR→ROT':         topo_add_xor_rot,
    'XOR→ADD→ROT':         topo_xor_add_rot,
    'Bare ADD':            topo_bare_add,
    'Threefish MIX':       topo_threefish_mix,
}


def gen_topo(N, topo_fn, beta, n_rounds, seed=42):
    """Generate output from a topology-based round function."""
    key_rng = np.random.default_rng(seed)
    pt_rng = np.random.default_rng(seed + 999999)
    bpw = WS // 8

    rk = [int(key_rng.integers(0, 2**WS)) for _ in range(max(n_rounds + 2, 40))]

    out = bytearray()
    for _ in range(N):
        x = int(pt_rng.integers(0, 2**WS))
        y = int(pt_rng.integers(0, 2**WS))
        for r in range(n_rounds):
            x, y = topo_fn(x, y, rk[r], beta)
        for b in range(bpw - 1, -1, -1):
            out.append((x >> (8 * b)) & 0xFF)
        for b in range(bpw - 1, -1, -1):
            out.append((y >> (8 * b)) & 0xFF)
    return bytes(out)


def mi_bits(a, b, n):
    n00 = int(np.sum((a == 0) & (b == 0)))
    n01 = int(np.sum((a == 0) & (b == 1)))
    n10 = int(np.sum((a == 1) & (b == 0)))
    n11 = int(np.sum((a == 1) & (b == 1)))
    nn = n00 + n01 + n10 + n11
    if nn == 0: return 0.0
    H_ab = 0.0
    for c in (n00, n01, n10, n11):
        p = c / nn
        if p > 0: H_ab -= p * math.log2(p)
    pa = (n10 + n11) / nn; pb = (n01 + n11) / nn
    Ha = -pa * math.log2(pa) - (1-pa) * math.log2(1-pa) if 0 < pa < 1 else 0.0
    Hb = -pb * math.log2(pb) - (1-pb) * math.log2(1-pb) if 0 < pb < 1 else 0.0
    return max(0.0, Ha + Hb - H_ab)


def f8_topo_test(topo_fn, beta, n_rounds=15, seed=42):
    """F8 MI on a topology. Black-box: scan all WS×WS pairs, report max diagonal."""
    bb = WS // 4  # bytes per block (2 words)
    bpw = WS // 8

    raw_R = gen_topo(N, topo_fn, beta, n_rounds, seed)
    raw_R1 = gen_topo(N, topo_fn, beta, n_rounds + 1, seed)

    out_R = np.frombuffer(raw_R, dtype=np.uint8).reshape(-1, bb)
    out_R1 = np.frombuffer(raw_R1, dtype=np.uint8).reshape(-1, bb)
    n = min(out_R.shape[0], out_R1.shape[0])
    out_R, out_R1 = out_R[:n], out_R1[:n]

    # Reconstruct words
    x_R = np.zeros(n, dtype=np.uint32)
    y_R = np.zeros(n, dtype=np.uint32)
    y_R1 = np.zeros(n, dtype=np.uint32)
    for b in range(bpw):
        sh = 8 * (bpw - 1 - b)
        x_R |= out_R[:, b].astype(np.uint32) << sh
        y_R |= out_R[:, bpw + b].astype(np.uint32) << sh
        y_R1 |= out_R1[:, bpw + b].astype(np.uint32) << sh
    diff_y = y_R ^ y_R1

    # Scan all shifts, find best
    best_shift = 0
    best_mi_total = 0
    for shift in range(WS):
        mi_total = 0
        for i in range(WS):
            j = (i + shift) % WS
            xb = ((x_R >> i) & 1).astype(np.uint8)
            dyb = ((diff_y >> j) & 1).astype(np.uint8)
            mi_total += mi_bits(xb, dyb, n)
        if mi_total > best_mi_total:
            best_mi_total = mi_total
            best_shift = shift

    # Permutation null on best shift
    rng = np.random.default_rng(42)
    null_totals = []
    for _ in range(N_PERM):
        perm = rng.permutation(n)
        diff_p = diff_y[perm]
        pm = 0
        for i in range(WS):
            j = (i + best_shift) % WS
            xb = ((x_R >> i) & 1).astype(np.uint8)
            dyb = ((diff_p >> j) & 1).astype(np.uint8)
            pm += mi_bits(xb, dyb, n)
        null_totals.append(pm)

    nm, ns = np.mean(null_totals), max(np.std(null_totals), 1e-30)
    z = (best_mi_total - nm) / ns
    return best_mi_total, z, best_shift


print("=" * 90)
print("ARX TOPOLOGY SWEEP")
print("=" * 90)
print(f"WS={WS}, N={N}, {SEEDS} seeds, R=15")
print()

for topo_name, topo_fn in TOPOLOGIES.items():
    print(f"\n--- {topo_name} ---")
    print(f"  {'β':>3}  {'MI_total':>10}  {'Z':>10}  {'Shift':>5}  {'Signal?':>10}")
    print(f"  {'-'*50}")

    for beta in [1, 2, 3, 4, 5, 7]:
        zs = []; mis = []; shifts = []
        for s in range(SEEDS):
            mi, z, sh = f8_topo_test(topo_fn, beta, 15, s*1000+42)
            zs.append(z); mis.append(mi); shifts.append(sh)
        mz = np.mean(zs)
        mmi = np.mean(mis)
        msh = int(np.median(shifts))
        sig = "YES ***" if mz > 3 else ("weak *" if mz > 2 else "no")
        print(f"  {beta:>3}  {mmi:>10.6f}  {mz:>+10.1f}  {msh:>5}  {sig}", flush=True)

print("\n=== DONE ===")

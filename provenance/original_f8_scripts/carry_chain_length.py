#!/usr/bin/env python3
"""B1: Carry-Chain Length Hypothesis.

Question: Does word size (carry-chain length) explain the Threefish signal?

At WS=16, β≥5 → dead (noise floor). But Threefish has WS=64 and shows
signal even with all rotations ≥5. Is the LONGER carry chain the reason?

Test: Speck-topology round function at WS=64 with β=14 (far above the
WS=16 death threshold of β=5). If WS=64 still has signal at β=14,
carry-chain length is the missing parameter.

Also test WS=32 and WS=128 for systematic sweep.
"""
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..'))
sys.path.insert(0, os.path.dirname(__file__))

import numpy as np
import math

N = 20000
SEEDS = 3
N_PERM = 15


def speck_round_ws(x, y, k, alpha, beta, ws):
    """One Speck round at arbitrary word size."""
    mask = (1 << ws) - 1
    # ROR(x, alpha)
    ror_x = ((x >> alpha) | (x << (ws - alpha))) & mask
    x_new = ((ror_x + y) & mask) ^ k
    # ROL(y, beta)
    rol_y = ((y << beta) | (y >> (ws - beta))) & mask
    y_new = rol_y ^ x_new
    return x_new, y_new


def gen_speck_variable_ws(N, ws, alpha, beta, n_rounds, seed=42):
    """Generate Speck-like cipher output at arbitrary word size.
    CRITICAL: key and plaintexts are deterministic from seed,
    so R and R+1 calls with same seed use identical key+plaintexts."""
    mask = (1 << ws) - 1
    bpw = (ws + 7) // 8  # bytes per word

    def rand_word(rng_):
        b = rng_.integers(0, 256, size=bpw, dtype=np.uint8)
        v = 0
        for byte in b:
            v = (v << 8) | int(byte)
        return v

    # Fixed key from seed (separate RNG so plaintexts are independent of n_rounds)
    key_rng = np.random.default_rng(seed)
    max_rounds = max(n_rounds + 2, 40)
    rk = [rand_word(key_rng) for _ in range(max_rounds)]

    # Fixed plaintexts from seed (separate RNG)
    pt_rng = np.random.default_rng(seed + 999999)

    out = bytearray()
    for _ in range(N):
        x = rand_word(pt_rng)
        y = rand_word(pt_rng)
        for r in range(n_rounds):
            x, y = speck_round_ws(x, y, rk[r], alpha, beta, ws)
        for b in range(bpw - 1, -1, -1):
            out.append((x >> (8 * b)) & 0xFF)
        for b in range(bpw - 1, -1, -1):
            out.append((y >> (8 * b)) & 0xFF)

    return bytes(out), bpw * 2, bpw


def mi_bits(a, b, n):
    """MI between two binary arrays."""
    n00 = int(np.sum((a == 0) & (b == 0)))
    n01 = int(np.sum((a == 0) & (b == 1)))
    n10 = int(np.sum((a == 1) & (b == 0)))
    n11 = int(np.sum((a == 1) & (b == 1)))
    nn = n00 + n01 + n10 + n11
    if nn == 0:
        return 0.0
    H_ab = 0.0
    for c in (n00, n01, n10, n11):
        p = c / nn
        if p > 0:
            H_ab -= p * math.log2(p)
    pa = (n10 + n11) / nn
    pb = (n01 + n11) / nn
    Ha = -pa * math.log2(pa) - (1 - pa) * math.log2(1 - pa) if 0 < pa < 1 else 0.0
    Hb = -pb * math.log2(pb) - (1 - pb) * math.log2(1 - pb) if 0 < pb < 1 else 0.0
    return max(0.0, Ha + Hb - H_ab)


def f8_mi_test(ws, alpha, beta, n_rounds, seed=42):
    """Run F8 MI test on Speck-topology at given WS. Returns (total_MI, Z)."""
    raw_R, bb, bpw = gen_speck_variable_ws(N, ws, alpha, beta, n_rounds, seed)
    raw_R1, _, _ = gen_speck_variable_ws(N, ws, alpha, beta, n_rounds + 1, seed)

    # Parse into half-words
    out_R = np.frombuffer(raw_R, dtype=np.uint8).reshape(-1, bb)
    out_R1 = np.frombuffer(raw_R1, dtype=np.uint8).reshape(-1, bb)
    n = out_R.shape[0]

    # Reconstruct x and diff_y
    x_R = np.zeros(n, dtype=np.uint64)
    y_R = np.zeros(n, dtype=np.uint64)
    y_R1 = np.zeros(n, dtype=np.uint64)
    for b in range(bpw):
        sh = 8 * (bpw - 1 - b)
        x_R |= out_R[:, b].astype(np.uint64) << sh
        y_R |= out_R[:, bpw + b].astype(np.uint64) << sh
        y_R1 |= out_R1[:, bpw + b].astype(np.uint64) << sh
    diff_y = y_R ^ y_R1

    # Test β-shifted diagonal MI
    dead_set = {(alpha + d) % ws for d in range(beta)}
    mi_vals = []
    for i in range(ws):
        if i in dead_set:
            continue
        j = (i - alpha) % ws
        xb = ((x_R >> i) & 1).astype(np.uint8)
        dyb = ((diff_y >> j) & 1).astype(np.uint8)
        mi_vals.append(mi_bits(xb, dyb, n))

    total_mi = sum(mi_vals)

    # Permutation null
    rng = np.random.default_rng(42)
    null_totals = []
    for _ in range(N_PERM):
        perm = rng.permutation(n)
        diff_p = diff_y[perm]
        pm = []
        for i in range(ws):
            if i in dead_set:
                continue
            j = (i - alpha) % ws
            xb = ((x_R >> i) & 1).astype(np.uint8)
            dyb = ((diff_p >> j) & 1).astype(np.uint8)
            pm.append(mi_bits(xb, dyb, n))
        null_totals.append(sum(pm))

    nm = np.mean(null_totals)
    ns = max(np.std(null_totals), 1e-30)
    z = (total_mi - nm) / ns
    return total_mi, z, len(mi_vals)


print("=" * 80)
print("CARRY-CHAIN LENGTH HYPOTHESIS")
print("=" * 80)
print(f"N={N}, {SEEDS} seeds, {N_PERM} perms")
print()

# Test matrix: WS × β combinations
configs = [
    # WS=16 reference (known results)
    (16, 7, 2, "WS=16 β=2 (Speck ref, SIGNAL expected)"),
    (16, 7, 5, "WS=16 β=5 (dead, known)"),
    # WS=32
    (32, 8, 3, "WS=32 β=3 (Speck 64/128 ref)"),
    (32, 8, 5, "WS=32 β=5 (just past threshold)"),
    (32, 8, 8, "WS=32 β=8"),
    # WS=64 — THE KEY TEST
    (64, 8, 3, "WS=64 β=3 (should have signal)"),
    (64, 8, 5, "WS=64 β=5 (threshold at WS=16)"),
    (64, 8, 8, "WS=64 β=8"),
    (64, 8, 14, "WS=64 β=14 (Threefish min rotation)"),
    (64, 8, 20, "WS=64 β=20"),
    (64, 8, 32, "WS=64 β=32 (half word)"),
    # WS=128 (one test only — slow)
    (128, 8, 14, "WS=128 β=14"),
]

print(f"  {'Config':>45}  {'MI_total':>10}  {'Z':>10}  {'Active':>6}  {'Signal?':>10}")
print(f"  {'-'*95}")

for ws, alpha, beta, label in configs:
    zs = []
    mis = []
    acts = []
    for s in range(SEEDS):
        seed = s * 1000 + 42
        mi, z, act = f8_mi_test(ws, alpha, beta, 15, seed)
        zs.append(z)
        mis.append(mi)
        acts.append(act)

    mz = np.mean(zs)
    mmi = np.mean(mis)
    act = acts[0]
    sig = "YES ***" if mz > 3 else ("weak *" if mz > 2 else "no")
    print(f"  {label:>45}  {mmi:>10.6f}  {mz:>+10.1f}  {act:>6}  {sig}", flush=True)

print("\n=== DONE ===")

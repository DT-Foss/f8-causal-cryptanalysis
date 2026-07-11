#!/usr/bin/env python3
"""SPARX Internal Speck Iterations — THE CORRECT ATTACK (v2).

Previous test (informed_sparx.py) compared SPARX-round R vs R+1.
One SPARX-round = 3 Speck iterations + linear layer.
So we were comparing states across 3 Speck iters + mixing = far beyond frontier.

CORRECT APPROACH:
Run the ARX-box with k vs k+1 internal Speck iterations (same key, same input).
This is IDENTICAL to the pure Speck F8 test: same plaintext encrypted with
different round counts. The carry leak from x+y should be detectable.

Speck iteration (inside ARX-box):
  x = ROR(x, 7)       ← α=7
  x = (x + y) mod 2^16  ← THE ADDITION (carry leak source)
  x ^= round_key
  y = ROL(y, 2)        ← β=2
  y ^= x

Standard Speck 32/64 uses the same ARX operation. Signal should match
pure Speck at the same iteration count.
"""
import sys, os; sys.path.insert(0, os.path.dirname(__file__))
from speck_utils import *

N = 50000
SEEDS = 5
N_PERM = 20

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


def arx_box_variable_iters(N_blocks, n_iters=3, seed=42):
    """Run JUST the ARX-box with a variable number of Speck iterations.
    Same key, same counter input, but different iteration counts.
    Returns (x_out, y_out) as 16-bit arrays.

    This is the SPARX ARX-box = Speck round function iterated n_iters times.
    """
    rng = np.random.default_rng(seed)
    k0 = int(rng.integers(0, 2**16))
    k1 = int(rng.integers(0, 2**16))  # Not used in simplified test
    mask16 = 0xFFFF

    x_out = np.zeros(N_blocks, dtype=np.uint16)
    y_out = np.zeros(N_blocks, dtype=np.uint16)

    for blk_idx in range(N_blocks):
        x = (blk_idx >> 16) & mask16
        y = blk_idx & mask16

        for _ in range(n_iters):
            x = ((x >> 7) | (x << 9)) & mask16
            x = (x + y) & mask16
            x ^= k0
            y = ((y << 2) | (y >> 14)) & mask16
            y ^= x

        x_out[blk_idx] = x
        y_out[blk_idx] = y

    return x_out, y_out


def test_f8_mi(x_R, y_R, y_R1, ws=16, alpha=7, beta=2):
    """Standard F8 MI test: x-half at R vs diff(y) = y(R) ^ y(R+1)."""
    diff_y = y_R.astype(np.uint64) ^ y_R1.astype(np.uint64)
    x = x_R.astype(np.uint64)
    n = len(x)

    # Informed diagonal MI
    dead_set = {(alpha + d) % ws for d in range(beta)}
    mi_diag_values = []
    for i in range(ws):
        if i in dead_set:
            continue
        j = (i - alpha) % ws
        xb = ((x >> i) & 1).astype(np.uint8)
        dyb = ((diff_y >> j) & 1).astype(np.uint8)
        mi_diag_values.append(mi_2x2(xb, dyb, n))
    mi_diag = sum(mi_diag_values)

    # Full WS×WS scan
    mi_full = 0.0
    for i in range(ws):
        best = 0
        xb = ((x >> i) & 1).astype(np.uint8)
        for j in range(ws):
            dyb = ((diff_y >> j) & 1).astype(np.uint8)
            best = max(best, mi_2x2(xb, dyb, n))
        mi_full += best

    # Permutation null
    rng = np.random.default_rng(42)
    null_totals = []
    for _ in range(N_PERM):
        perm_idx = rng.permutation(n)
        diff_y_perm = diff_y[perm_idx]
        null_total = 0.0
        for i in range(ws):
            best = 0
            xb = ((x >> i) & 1).astype(np.uint8)
            for j in range(ws):
                dyb = ((diff_y_perm >> j) & 1).astype(np.uint8)
                best = max(best, mi_2x2(xb, dyb, n))
            null_total += best
        null_totals.append(null_total)

    null_mean = np.mean(null_totals)
    null_std = max(np.std(null_totals), 1e-30)
    z = (mi_full - null_mean) / null_std

    n_active = sum(1 for m in mi_diag_values if m > 0.001)

    return z, mi_diag, mi_full, n_active


# ==========================================
# MAIN
# ==========================================

print("=" * 80)
print("SPARX ARX-BOX — VARIABLE ITERATION F8 TEST")
print("=" * 80)
print(f"N={N}, {SEEDS} seeds")
print()
print("ARX-box = Speck round (α=7, β=2), run with k vs k+1 iterations.")
print("Same key, same counter input. Identical to pure Speck F8.")
print()

print(f"{'Iters R→R+1':>15}  {'Mean Z':>8}  {'MI diag':>10}  {'MI full':>10}  {'Active':>8}  {'Signal?':>10}")
print("-" * 75)

for n_iters in range(1, 25):
    zs = []; mi_diags = []; mi_fulls = []; n_acts = []
    for s in range(SEEDS):
        seed = s * 1000 + 42
        x_R, y_R = arx_box_variable_iters(N, n_iters=n_iters, seed=seed)
        x_R1, y_R1 = arx_box_variable_iters(N, n_iters=n_iters+1, seed=seed)

        z, mi_d, mi_f, n_a = test_f8_mi(x_R, y_R, y_R1)
        zs.append(z); mi_diags.append(mi_d); mi_fulls.append(mi_f); n_acts.append(n_a)

    mean_z = np.mean(zs)
    mean_diag = np.mean(mi_diags)
    mean_full = np.mean(mi_fulls)
    mean_act = np.mean(n_acts)
    sig = "YES ***" if mean_z > 3 else ("weak *" if mean_z > 2 else "no")
    print(f"  R{n_iters:>2}→R{n_iters+1:<2}        {mean_z:>+8.1f}  {mean_diag:.6f}  {mean_full:.6f}  {mean_act:>7.1f}  {sig:>10}")

    # Stop early if clearly dead for a few rounds
    if n_iters > 5 and mean_z < 1:
        print(f"  ... (dead, stopping)")
        break


# Reference: pure Speck 32/64 for comparison
print(f"\n--- Reference: Pure Speck 32/64 ---")
print(f"{'Rounds R→R+1':>15}  {'Mean Z':>8}  {'MI diag':>10}  {'MI full':>10}  {'Active':>8}  {'Signal?':>10}")
print("-" * 75)

for n_rounds in [1, 5, 10, 15, 20, 22]:
    zs = []; mi_diags = []; mi_fulls = []; n_acts = []
    for s in range(SEEDS):
        seed = s * 1000 + 42
        raw_R, bb, bpw = speck32(N, n_rounds=n_rounds, seed=seed)
        raw_R1, _, _ = speck32(N, n_rounds=n_rounds+1, seed=seed)
        d_R = np.frombuffer(raw_R, dtype=np.uint8).reshape(-1, 4)
        d_R1 = np.frombuffer(raw_R1, dtype=np.uint8).reshape(-1, 4)
        x_R = (d_R[:, 0].astype(np.uint16) << 8) | d_R[:, 1].astype(np.uint16)
        y_R = (d_R[:, 2].astype(np.uint16) << 8) | d_R[:, 3].astype(np.uint16)
        y_R1 = (d_R1[:, 2].astype(np.uint16) << 8) | d_R1[:, 3].astype(np.uint16)

        z, mi_d, mi_f, n_a = test_f8_mi(x_R, y_R, y_R1)
        zs.append(z); mi_diags.append(mi_d); mi_fulls.append(mi_f); n_acts.append(n_a)

    mean_z = np.mean(zs)
    mean_diag = np.mean(mi_diags)
    mean_full = np.mean(mi_fulls)
    mean_act = np.mean(n_acts)
    sig = "YES ***" if mean_z > 3 else ("weak *" if mean_z > 2 else "no")
    print(f"  R{n_rounds:>2}→R{n_rounds+1:<2}        {mean_z:>+8.1f}  {mean_diag:.6f}  {mean_full:.6f}  {mean_act:>7.1f}  {sig:>10}")

print("\n=== DONE ===")

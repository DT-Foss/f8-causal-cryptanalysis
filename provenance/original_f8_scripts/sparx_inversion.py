#!/usr/bin/env python3
"""C1: SPARX Algebraic Inversion — Extract ARX-box output from full SPARX.

SPARX structure (2-branch, 3 Speck-iters per ARX-box):
  For each round:
    1. Branch 0: ARX-box(x0, y0, key) → 3 Speck iterations
    2. Branch 1: ARX-box(x1, y1, key) → 3 Speck iterations
    3. Linear layer L: (x0,y0,x1,y1) → mixed state

The linear layer L for SPARX-64/128:
  L(x0, y0, x1, y1):
    tmp = (x0 ^ y0) <<< 8
    x0' = x0 ^ x1 ^ tmp
    y0' = y0 ^ y1 ^ tmp
    x1' = x1 ^ tmp  (or similar — depends on variant)
    ...

ATTACK: If we can invert L, we can extract the pre-mixing ARX-box outputs.
Then apply F8 on those extracted values across SPARX rounds R vs R+1.

SPARX-64/128 uses a Feistel-based linear layer. It's invertible by design.
"""
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..'))
sys.path.insert(0, os.path.dirname(__file__))

import numpy as np
import math

N = 20000
SEEDS = 3
N_PERM = 15
MASK16 = 0xFFFF


def rol16(v, r):
    return ((v << r) | (v >> (16 - r))) & MASK16

def ror16(v, r):
    return ((v >> r) | (v << (16 - r))) & MASK16


def sparx_arx_box(x, y, k, n_iters=3):
    """One ARX-box: n_iters Speck rounds with key k."""
    for i in range(n_iters):
        x = ror16(x, 7)
        x = (x + y) & MASK16
        x ^= (k + i) & MASK16  # simplified key schedule within box
        y = rol16(y, 2)
        y ^= x
    return x, y


def sparx_linear_layer(x0, y0, x1, y1):
    """SPARX-64/128 linear layer (Feistel-based).
    From the SPARX paper (Dinu et al. 2016):
    tmp = ROL((x0 ^ y0), 8)
    x0' = x1 ^ x0 ^ tmp
    y0' = y1 ^ y0 ^ tmp
    x1' = x0
    y1' = y0
    """
    tmp = rol16(x0 ^ y0, 8)
    x0_new = x1 ^ x0 ^ tmp
    y0_new = y1 ^ y0 ^ tmp
    x1_new = x0
    y1_new = y0
    return x0_new, y0_new, x1_new, y1_new


def sparx_linear_layer_inv(x0, y0, x1, y1):
    """Inverse of the SPARX linear layer.
    Given: x0'=x1^x0^tmp, y0'=y1^y0^tmp, x1'=x0, y1'=y0
    Inverse: x0=x1', y0=y1', then tmp=ROL(x0^y0,8),
             x1=x0'^x0^tmp, y1=y0'^y0^tmp
    """
    x0_orig = x1  # x1' = x0
    y0_orig = y1  # y1' = y0
    tmp = rol16(x0_orig ^ y0_orig, 8)
    x1_orig = x0 ^ x0_orig ^ tmp  # x0' = x1^x0^tmp → x1 = x0'^x0^tmp
    y1_orig = y0 ^ y0_orig ^ tmp
    return x0_orig, y0_orig, x1_orig, y1_orig


def sparx64_encrypt(x0, y0, x1, y1, round_keys, n_rounds, n_iters=3):
    """Full SPARX-64/128 encryption."""
    ki = 0
    for r in range(n_rounds):
        # ARX-boxes
        x0, y0 = sparx_arx_box(x0, y0, round_keys[ki], n_iters)
        ki += 1
        x1, y1 = sparx_arx_box(x1, y1, round_keys[ki], n_iters)
        ki += 1
        # Linear layer
        x0, y0, x1, y1 = sparx_linear_layer(x0, y0, x1, y1)
    # Final ARX-boxes (no linear layer after last)
    x0, y0 = sparx_arx_box(x0, y0, round_keys[ki], n_iters)
    ki += 1
    x1, y1 = sparx_arx_box(x1, y1, round_keys[ki], n_iters)
    return x0, y0, x1, y1


def gen_sparx(N_blocks, n_rounds, seed=42):
    """Generate SPARX-64/128 output."""
    key_rng = np.random.default_rng(seed)
    pt_rng = np.random.default_rng(seed + 999999)

    # Round keys (simplified)
    n_keys = 2 * (n_rounds + 1) + 4
    rk = [int(key_rng.integers(0, 2**16)) for _ in range(n_keys)]

    results = np.zeros((N_blocks, 4), dtype=np.uint16)
    for i in range(N_blocks):
        x0 = int(pt_rng.integers(0, 2**16))
        y0 = int(pt_rng.integers(0, 2**16))
        x1 = int(pt_rng.integers(0, 2**16))
        y1 = int(pt_rng.integers(0, 2**16))
        out = sparx64_encrypt(x0, y0, x1, y1, rk, n_rounds)
        results[i] = out
    return results, rk


def extract_pre_linear(sparx_output, round_keys, target_round, n_rounds):
    """Extract ARX-box outputs BEFORE the linear layer at target_round.

    Strategy: Given the full SPARX output, peel back layers from the end.
    But this requires knowing ALL round keys and inverting ALL subsequent operations.

    Simpler approach: Just run SPARX with and without the LAST linear layer.
    """
    pass  # We'll use a different approach


def gen_sparx_pre_linear(N_blocks, n_rounds, seed=42):
    """Generate SPARX output BEFORE the last linear layer.
    = After the last pair of ARX-boxes but before the last L."""
    key_rng = np.random.default_rng(seed)
    pt_rng = np.random.default_rng(seed + 999999)

    n_keys = 2 * (n_rounds + 1) + 4
    rk = [int(key_rng.integers(0, 2**16)) for _ in range(n_keys)]

    results_post_L = np.zeros((N_blocks, 4), dtype=np.uint16)
    results_pre_L = np.zeros((N_blocks, 4), dtype=np.uint16)

    for i in range(N_blocks):
        x0 = int(pt_rng.integers(0, 2**16))
        y0 = int(pt_rng.integers(0, 2**16))
        x1 = int(pt_rng.integers(0, 2**16))
        y1 = int(pt_rng.integers(0, 2**16))

        ki = 0
        for r in range(n_rounds):
            x0, y0 = sparx_arx_box(x0, y0, rk[ki], 3); ki += 1
            x1, y1 = sparx_arx_box(x1, y1, rk[ki], 3); ki += 1
            if r == n_rounds - 1:
                # Save pre-linear state
                results_pre_L[i] = [x0, y0, x1, y1]
            x0, y0, x1, y1 = sparx_linear_layer(x0, y0, x1, y1)

        # Final ARX-boxes
        x0, y0 = sparx_arx_box(x0, y0, rk[ki], 3); ki += 1
        x1, y1 = sparx_arx_box(x1, y1, rk[ki], 3)
        results_post_L[i] = [x0, y0, x1, y1]

    return results_post_L, results_pre_L


def mi_bits(a, b, n):
    n00 = int(np.sum((a==0)&(b==0))); n01 = int(np.sum((a==0)&(b==1)))
    n10 = int(np.sum((a==1)&(b==0))); n11 = int(np.sum((a==1)&(b==1)))
    nn = n00+n01+n10+n11
    if nn == 0: return 0.0
    H_ab = 0.0
    for c in (n00,n01,n10,n11):
        p = c/nn
        if p > 0: H_ab -= p*math.log2(p)
    pa = (n10+n11)/nn; pb = (n01+n11)/nn
    Ha = -pa*math.log2(pa)-(1-pa)*math.log2(1-pa) if 0<pa<1 else 0.0
    Hb = -pb*math.log2(pb)-(1-pb)*math.log2(1-pb) if 0<pb<1 else 0.0
    return max(0.0, Ha+Hb-H_ab)


def f8_on_words(x_R, y_R, y_R1, ws=16, alpha=7, beta=2):
    """F8 MI on word-level data. Returns (total_MI, Z)."""
    n = len(x_R)
    diff_y = np.array(x_R, dtype=np.uint32) ^ np.array(y_R, dtype=np.uint32)
    diff_y1 = np.array(x_R, dtype=np.uint32) ^ np.array(y_R1, dtype=np.uint32)
    # Actually: F8 = out(R) vs out(R+1), so diff = y(R) ^ y(R+1)
    # Let me reconsider: we need x from R and diff_y = y(R)^y(R+1)
    x = np.array(x_R, dtype=np.uint32)
    dy = np.array(y_R, dtype=np.uint32) ^ np.array(y_R1, dtype=np.uint32)

    dead_set = {(alpha + d) % ws for d in range(beta)}
    mi_vals = []
    for i in range(ws):
        if i in dead_set: continue
        j = (i - alpha) % ws
        xb = ((x >> i) & 1).astype(np.uint8)
        dyb = ((dy >> j) & 1).astype(np.uint8)
        mi_vals.append(mi_bits(xb, dyb, n))

    total = sum(mi_vals)

    rng = np.random.default_rng(42)
    nulls = []
    for _ in range(N_PERM):
        perm = rng.permutation(n)
        dy_p = dy[perm]
        pm = []
        for i in range(ws):
            if i in dead_set: continue
            j = (i - alpha) % ws
            xb = ((x >> i) & 1).astype(np.uint8)
            dyb = ((dy_p >> j) & 1).astype(np.uint8)
            pm.append(mi_bits(xb, dyb, n))
        nulls.append(sum(pm))

    nm, ns = np.mean(nulls), max(np.std(nulls), 1e-30)
    return total, (total - nm) / ns


print("=" * 80)
print("SPARX ALGEBRAIC INVERSION — Extract ARX-box output")
print("=" * 80)
print(f"N={N}, {SEEDS} seeds, {N_PERM} perms")
print()

# Approach 1: Run SPARX R and R+1, invert the LAST linear layer on both,
# extract the pre-L state, and run F8 on the pre-L x0/y0 values.
# This gives us the ARX-box output AFTER mixing from all PREVIOUS rounds
# but BEFORE the last linear layer.

print("--- Approach: Invert last linear layer, F8 on pre-L state ---\n")
print(f"  {'Config':>30}  {'Branch':>6}  {'MI':>10}  {'Z':>10}  {'Signal?':>10}")
print(f"  {'-'*75}")

for n_rounds in [2, 4, 8]:
    for branch in [0, 1]:  # Branch 0 = (x0,y0), Branch 1 = (x1,y1)
        zs = []; mis = []
        for s in range(SEEDS):
            seed = s * 1000 + 42
            # Get SPARX output at R and R+1 rounds
            post_R, pre_R = gen_sparx_pre_linear(N, n_rounds, seed)
            post_R1, pre_R1 = gen_sparx_pre_linear(N, n_rounds + 1, seed)

            # Invert the last linear layer on the POST output to get PRE
            # Actually we already have pre_R from the generator!
            # F8: compare pre-linear state at R vs R+1
            if branch == 0:
                x_R = pre_R[:, 0]; y_R = pre_R[:, 1]
                y_R1 = pre_R1[:, 1]
            else:
                x_R = pre_R[:, 2]; y_R = pre_R[:, 3]
                y_R1 = pre_R1[:, 3]

            mi, z = f8_on_words(x_R, y_R, y_R1)
            zs.append(z); mis.append(mi)

        mz = np.mean(zs); mmi = np.mean(mis)
        sig = "YES ***" if mz > 3 else ("weak *" if mz > 2 else "no")
        label = f"SPARX R{n_rounds} pre-L"
        print(f"  {label:>30}  B{branch:>5}  {mmi:>10.6f}  {mz:>+10.1f}  {sig}", flush=True)

# Approach 2: Actually invert L on the FINAL output (as an attacker would)
print("\n--- Approach: Invert L on FINAL ciphertext, F8 on recovered state ---\n")
print(f"  {'Config':>30}  {'Branch':>6}  {'MI':>10}  {'Z':>10}  {'Signal?':>10}")
print(f"  {'-'*75}")

for n_rounds in [2, 4, 8]:
    for branch in [0, 1]:
        zs = []; mis = []
        for s in range(SEEDS):
            seed = s * 1000 + 42
            post_R, _ = gen_sparx_pre_linear(N, n_rounds, seed)
            post_R1, _ = gen_sparx_pre_linear(N, n_rounds + 1, seed)

            # Invert L on the final output
            inv_R = np.zeros_like(post_R)
            inv_R1 = np.zeros_like(post_R1)
            for i in range(N):
                inv_R[i] = sparx_linear_layer_inv(
                    int(post_R[i, 0]), int(post_R[i, 1]),
                    int(post_R[i, 2]), int(post_R[i, 3]))
                inv_R1[i] = sparx_linear_layer_inv(
                    int(post_R1[i, 0]), int(post_R1[i, 1]),
                    int(post_R1[i, 2]), int(post_R1[i, 3]))

            if branch == 0:
                x_R = inv_R[:, 0]; y_R = inv_R[:, 1]
                y_R1 = inv_R1[:, 1]
            else:
                x_R = inv_R[:, 2]; y_R = inv_R[:, 3]
                y_R1 = inv_R1[:, 3]

            mi, z = f8_on_words(x_R, y_R, y_R1)
            zs.append(z); mis.append(mi)

        mz = np.mean(zs); mmi = np.mean(mis)
        sig = "YES ***" if mz > 3 else ("weak *" if mz > 2 else "no")
        label = f"SPARX R{n_rounds} inv-L"
        print(f"  {label:>30}  B{branch:>5}  {mmi:>10.6f}  {mz:>+10.1f}  {sig}", flush=True)

print("\n=== DONE ===")

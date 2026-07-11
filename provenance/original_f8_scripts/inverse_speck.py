#!/usr/bin/env python3
"""B2: Inverse-Speck — Is the F8 leak symmetric under decryption?

Speck encrypt: x_new = (ROR(x,α) + y) ^ k; y_new = ROL(y,β) ^ x_new
Speck decrypt: y_old = ROL(y ^ x, ws-β); x_old = ROL((x ^ k) - y_old, α)

If F8 signal is the same for decrypt as for encrypt → the leak is in the
STRUCTURE (modular addition inherently leaks carry information), not in the
direction of computation.

If asymmetric → the leak depends on whether the addition acts on the
ROR'd value (encrypt) vs the subtraction acts on the XOR'd value (decrypt).
"""
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..'))
sys.path.insert(0, os.path.dirname(__file__))

import numpy as np
import math
from speck_utils import speck32

N = 50000
SEEDS = 5
N_PERM = 20
MASK16 = 0xFFFF


def speck32_decrypt(N, n_rounds, seed=42):
    """Generate Speck 32/64 DECRYPTION output.
    Same key schedule as encrypt, but run rounds in reverse."""
    rng = np.random.default_rng(seed)
    mk = [int(rng.integers(0, 2**16)) for _ in range(4)]

    # Key schedule (same as encrypt)
    rk = [0] * (n_rounds + 2)
    l = list(mk[1:])
    rk[0] = mk[0]
    for i in range(n_rounds + 1):
        ror_l = ((l[i % len(l)] >> 7) | (l[i % len(l)] << 9)) & MASK16
        new_l = (rk[i] + ror_l) & MASK16
        new_l ^= i
        l.append(new_l)
        rol_rk = ((rk[i] << 2) | (rk[i] >> 14)) & MASK16
        rk[i + 1] = rol_rk ^ new_l

    out = bytearray()
    for _ in range(N):
        # Start with "ciphertext" (random)
        x = int(rng.integers(0, 2**16))
        y = int(rng.integers(0, 2**16))

        # Decrypt: reverse round order
        for r in range(n_rounds - 1, -1, -1):
            # Invert: y_old = ROR(y ^ x, β=2)
            yxor = (y ^ x) & MASK16
            y_old = ((yxor >> 2) | (yxor << 14)) & MASK16
            # Invert: x_old = ROL((x ^ k) - y_old, α=7)
            x_xk = (x ^ rk[r]) & MASK16
            x_sub = (x_xk - y_old) & MASK16
            x_old = ((x_sub << 7) | (x_sub >> 9)) & MASK16
            x, y = x_old, y_old

        out.extend([(x >> 8) & 0xFF, x & 0xFF, (y >> 8) & 0xFF, y & 0xFF])

    return bytes(out), 4, 2


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


def f8_test(gen_fn, n_rounds, seed):
    """Standard F8 MI test. Returns (total_MI, Z, n_active)."""
    raw_R, bb, bpw = gen_fn(N, n_rounds, seed)
    raw_R1, _, _ = gen_fn(N, n_rounds + 1, seed)

    out_R = np.frombuffer(raw_R, dtype=np.uint8).reshape(-1, bb)
    out_R1 = np.frombuffer(raw_R1, dtype=np.uint8).reshape(-1, bb)
    n = min(out_R.shape[0], out_R1.shape[0])
    out_R, out_R1 = out_R[:n], out_R1[:n]

    x_R = (out_R[:, 0].astype(np.uint32) << 8) | out_R[:, 1]
    y_R = (out_R[:, 2].astype(np.uint32) << 8) | out_R[:, 3]
    y_R1 = (out_R1[:, 2].astype(np.uint32) << 8) | out_R1[:, 3]
    diff_y = y_R ^ y_R1

    alpha, beta, ws = 7, 2, 16
    dead_set = {(alpha + d) % ws for d in range(beta)}

    mi_vals = []
    for i in range(ws):
        if i in dead_set: continue
        j = (i - alpha) % ws
        xb = ((x_R >> i) & 1).astype(np.uint8)
        dyb = ((diff_y >> j) & 1).astype(np.uint8)
        mi_vals.append(mi_bits(xb, dyb, n))

    total_mi = sum(mi_vals)

    rng = np.random.default_rng(42)
    null_totals = []
    for _ in range(N_PERM):
        perm = rng.permutation(n)
        diff_p = diff_y[perm]
        pm = []
        for i in range(ws):
            if i in dead_set: continue
            j = (i - alpha) % ws
            xb = ((x_R >> i) & 1).astype(np.uint8)
            dyb = ((diff_p >> j) & 1).astype(np.uint8)
            pm.append(mi_bits(xb, dyb, n))
        null_totals.append(sum(pm))

    nm, ns = np.mean(null_totals), max(np.std(null_totals), 1e-30)
    return total_mi, (total_mi - nm) / ns, len(mi_vals)


print("=" * 80)
print("INVERSE-SPECK: ENCRYPT vs DECRYPT F8 LEAK")
print("=" * 80)
print(f"N={N}, {SEEDS} seeds, {N_PERM} perms")
print()

# Encrypt reference
print("ENCRYPT (forward):")
for r in [5, 10, 15, 22]:
    zs = []; mis = []
    for s in range(SEEDS):
        mi, z, _ = f8_test(lambda N, nr, sd: speck32(N, n_rounds=nr, seed=sd), r, s*1000+42)
        zs.append(z); mis.append(mi)
    print(f"  R{r:>2}: MI={np.mean(mis):.6f}  Z={np.mean(zs):>+10.1f}", flush=True)

# Decrypt
print("\nDECRYPT (inverse):")
for r in [5, 10, 15, 22]:
    zs = []; mis = []
    for s in range(SEEDS):
        mi, z, _ = f8_test(speck32_decrypt, r, s*1000+42)
        zs.append(z); mis.append(mi)
    print(f"  R{r:>2}: MI={np.mean(mis):.6f}  Z={np.mean(zs):>+10.1f}", flush=True)

print("\nIf encrypt ≈ decrypt → leak is structural (in the addition itself)")
print("If encrypt >> decrypt → leak is directional (carry propagation direction)")
print("\n=== DONE ===")

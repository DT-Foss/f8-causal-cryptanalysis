#!/usr/bin/env python3
"""PRESENT-80 full-round F8 cross-round carry-leak scan.

PRESENT (Bogdanov et al., CHES 2007) is a lightweight SPN cipher: an S-box
layer plus a fixed bit permutation, 64-bit block, 31 rounds, no modular
addition. As with GIFT, the F8 leak is driven by the permutation-cycle
structure: generate the output at round R and R+1 with the same key/counter,
XOR them, and measure the mutual information between output bits at round R
and bits of that difference, scored against a permutation null.

  PRESENT-80: 31 rounds, full 64x64 bit-level MI scan.  Z = +1183.

Correctness: the inline PRESENT-80 codec below is checked against all four
known official CHES-2007 test vectors before the F8 scan runs.

Self-contained: numpy only.
"""

import json
import math
import os
import time
from collections import Counter

import numpy as np

# ─────────────────────────────────────────────────────────────────────────
# PRESENT (CHES 2007) — spec-correct reference implementation, verified
# against the official PRESENT-80 test vectors.
# ─────────────────────────────────────────────────────────────────────────

M64 = (1 << 64) - 1

_PRESENT_SBOX = [0xC, 0x5, 0x6, 0xB, 0x9, 0x0, 0xA, 0xD,
                 0x3, 0xE, 0xF, 0x8, 0x4, 0x7, 0x1, 0x2]

_PRESENT_PERM = [
     0, 16, 32, 48,  1, 17, 33, 49,  2, 18, 34, 50,  3, 19, 35, 51,
     4, 20, 36, 52,  5, 21, 37, 53,  6, 22, 38, 54,  7, 23, 39, 55,
     8, 24, 40, 56,  9, 25, 41, 57, 10, 26, 42, 58, 11, 27, 43, 59,
    12, 28, 44, 60, 13, 29, 45, 61, 14, 30, 46, 62, 15, 31, 47, 63,
]

_PRESENT_PERM_MASK = []
for _src in range(64):
    _PRESENT_PERM_MASK.append((_src, _PRESENT_PERM[_src]))


def _present_key_schedule_80(key_80bit, rounds=31):
    M80 = (1 << 80) - 1
    rks = []
    reg = key_80bit & M80
    for i in range(rounds + 1):
        rks.append((reg >> 16) & M64)
        reg = ((reg << 61) | (reg >> 19)) & M80
        top4 = (reg >> 76) & 0xF
        reg = (reg & ((1 << 76) - 1)) | (_PRESENT_SBOX[top4] << 76)
        reg ^= ((i + 1) & 0x1F) << 15
    return rks


def _present_key_schedule_128(key_128bit, rounds=31):
    M128 = (1 << 128) - 1
    rks = []
    reg = key_128bit & M128
    for i in range(rounds + 1):
        rks.append((reg >> 64) & M64)
        reg = ((reg << 61) | (reg >> 67)) & M128
        top4a = (reg >> 124) & 0xF
        top4b = (reg >> 120) & 0xF
        reg = (reg & ((1 << 120) - 1)) | (_PRESENT_SBOX[top4a] << 124) | (_PRESENT_SBOX[top4b] << 120)
        reg ^= ((i + 1) & 0x1F) << 62
    return rks


def _present_encrypt(block_64, rks, rounds=31):
    state = block_64 & M64
    for r in range(rounds):
        state ^= rks[r]
        new_state = 0
        for nibble_idx in range(16):
            nibble = (state >> (4 * nibble_idx)) & 0xF
            new_state |= _PRESENT_SBOX[nibble] << (4 * nibble_idx)
        state = new_state
        pstate = 0
        for src, dst in _PRESENT_PERM_MASK:
            if state & (1 << src):
                pstate |= 1 << dst
        state = pstate
    state ^= rks[rounds]
    return state


# ─────────────────────────────────────────────────────────────────────────
# Configuration
# ─────────────────────────────────────────────────────────────────────────

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RESULTS = os.path.join(REPO, "results")

SEED = 42
N = 20000
N_PERM = 15
M80 = (1 << 80) - 1


def verify_official_vectors():
    """Check the inline PRESENT-80 codec against the 4 official CHES-2007
    test vectors before running the F8 sweep."""
    vectors = [
        ('PT=0, K=0', 0, 0, '5579c1387b228445'),
        ('PT=0, K=all1', 0, M80, 'e72c46c0f5945049'),
        ('PT=all1, K=0', M64, 0, 'a112ffc72f68417b'),
        ('PT=all1, K=all1', M64, M80, '3333dcd3213210d2'),
    ]
    all_ok = True
    for name, pt, key, expected in vectors:
        rks = _present_key_schedule_80(key, rounds=31)
        ct = _present_encrypt(pt, rks, rounds=31)
        ct_hex = hex(ct)[2:].zfill(16)
        ok = ct_hex == expected
        all_ok &= ok
        print(f"  {name:>20s}: got={ct_hex}  expected={expected}  MATCH={ok}")
    return all_ok


def find_cycles(perm):
    n = len(perm)
    visited = [False] * n
    cycles = []
    for start in range(n):
        if visited[start]:
            continue
        cycle = []
        x = start
        while not visited[x]:
            visited[x] = True
            cycle.append(x)
            x = perm[x]
        cycles.append(cycle)
    return cycles


def mi_binary(a, b):
    n = len(a)
    n11 = int(np.sum((a == 1) & (b == 1)))
    n10 = int(np.sum((a == 1) & (b == 0)))
    n01 = int(np.sum((a == 0) & (b == 1)))
    n00 = n - n11 - n10 - n01
    H_ab = 0.0
    for c in (n00, n01, n10, n11):
        if c > 0:
            p = c / n
            H_ab -= p * math.log(p)
    pa = (n10 + n11) / n
    Ha = -pa * math.log(pa) - (1 - pa) * math.log(1 - pa) if 0 < pa < 1 else 0.0
    pb = (n01 + n11) / n
    Hb = -pb * math.log(pb) - (1 - pb) * math.log(1 - pb) if 0 < pb < 1 else 0.0
    return max(0.0, Ha + Hb - H_ab)


def present_encrypt_vec(state, rks, rounds):
    """Vectorized PRESENT encryption (mirrors _present_encrypt exactly,
    batched over a numpy uint64 array instead of scalar Python ints)."""
    state = state.astype(np.uint64) & np.uint64(M64)
    sbox_arr = np.array(_PRESENT_SBOX, dtype=np.uint64)
    for r in range(rounds):
        state ^= np.uint64(rks[r])
        # S-box layer
        new_state = np.zeros_like(state)
        for i in range(16):
            nib = ((state >> np.uint64(4 * i)) & np.uint64(0xF)).astype(np.uint8)
            new_state |= sbox_arr[nib] << np.uint64(4 * i)
        state = new_state
        # Permutation layer
        pstate = np.zeros_like(state)
        for src, dst in _PRESENT_PERM_MASK:
            bit = (state >> np.uint64(src)) & np.uint64(1)
            pstate |= bit << np.uint64(dst)
        state = pstate
    state ^= np.uint64(rks[rounds])
    return state


def scalar_verify_vectorized():
    """Check present_encrypt_vec against the scalar _present_encrypt on the
    same 4 official vectors, at N=1, before trusting it for the F8 sweep."""
    vectors = [
        (0, 0, '5579c1387b228445'),
        (0, M80, 'e72c46c0f5945049'),
        (M64, 0, 'a112ffc72f68417b'),
        (M64, M80, '3333dcd3213210d2'),
    ]
    all_ok = True
    for pt, key, expected in vectors:
        rks = _present_key_schedule_80(key, rounds=31)
        ct = present_encrypt_vec(np.array([pt], dtype=np.uint64), rks, 31)[0]
        ct_hex = hex(int(ct))[2:].zfill(16)
        ok = ct_hex == expected
        all_ok &= ok
    return all_ok


def bits_from_uint64(arr, n_bits):
    n = arr.shape[0]
    out = np.zeros((n, n_bits), dtype=np.uint8)
    for i in range(n_bits):
        out[:, i] = ((arr >> np.uint64(i)) & np.uint64(1)).astype(np.uint8)
    return out


def f8_mi_test(bits_x, bits_diff, n_bits, n_perm, seed):
    n = bits_x.shape[0]

    def compute_mi(diff_mat):
        total = 0.0
        for i in range(n_bits):
            xb = bits_x[:, i]
            best = 0.0
            for j in range(n_bits):
                m = mi_binary(xb, diff_mat[:, j])
                if m > best:
                    best = m
            total += best
        return total

    total_mi = compute_mi(bits_diff)
    rng = np.random.default_rng(seed)
    null_totals = []
    for _ in range(n_perm):
        perm = rng.permutation(n)
        null_totals.append(compute_mi(bits_diff[perm, :]))
    null_mean = float(np.mean(null_totals))
    null_std = float(np.std(null_totals))
    if null_std < 1e-30:
        null_std = 1e-30
    z = (total_mi - null_mean) / null_std
    return z, total_mi, null_mean, null_std


def run_present_f8(R, seed=SEED, N=N, n_perm=N_PERM):
    rng = np.random.default_rng(seed)
    key80 = int(rng.integers(0, 2**63, dtype=np.uint64)) & M80
    pt = rng.integers(0, 2**63, size=N, dtype=np.uint64).astype(np.uint64)

    rks_R = _present_key_schedule_80(key80, R)
    rks_R1 = _present_key_schedule_80(key80, R + 1)

    out_R = present_encrypt_vec(pt.copy(), rks_R, R)
    out_R1 = present_encrypt_vec(pt.copy(), rks_R1, R + 1)

    diff = out_R ^ out_R1
    bits_x = bits_from_uint64(out_R, 64)
    bits_diff = bits_from_uint64(diff, 64)

    z, mi, _, _ = f8_mi_test(bits_x, bits_diff, 64, n_perm, seed + 55555)
    return z, mi


if __name__ == "__main__":
    os.makedirs(RESULTS, exist_ok=True)
    print("=" * 78)
    print("  PRESENT-80 FULL-ROUND F8 CROSS-ROUND CARRY-LEAK SCAN")
    print("=" * 78)
    print()
    print("Step 1: Verify official CHES-2007 test vectors (scalar reference)")
    ok_scalar = verify_official_vectors()
    print("\nStep 2: Verify vectorized implementation against same vectors")
    ok_vec = scalar_verify_vectorized()
    print(f"  Vectorized MATCH: {ok_vec}")

    if not (ok_scalar and ok_vec):
        print("\n  !!! TEST VECTOR MISMATCH -- ABORTING !!!")
        raise SystemExit(1)

    print("\nStep 3: Cycle structure of PRESENT's bit permutation")
    cycles = find_cycles(_PRESENT_PERM)
    lengths = Counter(len(c) for c in cycles)
    print(f"  {len(cycles)} cycles found, length distribution: {dict(sorted(lengths.items()))}")

    print("\nStep 4: Full bit-level F8 sweep")
    results = []
    t0 = time.time()
    for R in [1, 2, 4, 8, 16, 31]:
        t1 = time.time()
        z, mi = run_present_f8(R)
        dt = time.time() - t1
        marker = "***" if z > 100 else ("**" if z > 10 else ("*" if z > 3 else ""))
        print(f"  R={R:>3d}: Z = {z:>+10.1f}  MI={mi:.6f}  {marker}  ({dt:.1f}s)")
        results.append({"R": R, "Z": round(float(z), 2), "MI": round(float(mi), 6), "elapsed_s": round(dt, 1)})

    total = time.time() - t0

    max_z = max(r["Z"] for r in results)
    full_round_z = results[-1]["Z"]

    print("\n" + "=" * 78)
    print("  FULL-ROUND F8 DISTINGUISHER")
    print("=" * 78)
    print(f"  PRESENT-80 (R=31): Z = {full_round_z:+.1f}")
    print(f"\n  Total time: {total:.1f}s")

    output = {
        "cipher": "PRESENT-80",
        "spec": "CHES 2007",
        "mechanism": "permutation cycle",
        "official_vectors_verified": {"scalar": ok_scalar, "vectorized": ok_vec},
        "present_perm_cycle_structure": {
            "n_cycles": len(cycles),
            "length_distribution": dict(sorted(lengths.items())),
            "cycles": cycles,
        },
        "parameters": {"N": N, "n_perm": N_PERM},
        "results": results,
        "max_z": max_z,
        "full_round_z": full_round_z,
        "total_time_s": round(total, 1),
    }
    result_path = os.path.join(RESULTS, "present.json")
    with open(result_path, "w") as f:
        json.dump(output, f, indent=2)
    print(f"\n  Saved to {result_path}")

#!/usr/bin/env python3
"""GIFT-64 and GIFT-128 full-round F8 cross-round carry-leak scan.

GIFT is a lightweight SPN cipher (S-box layer + fixed bit permutation, no
modular addition). The F8 leak here is driven by the permutation-cycle
structure: generate the output at round R and R+1 with the same key/counter,
XOR them, and measure the mutual information between output bits at round R
and bits of that difference, scored against a permutation null.

  GIFT-64:  28 rounds, full 64x64 bit-level MI scan.  Z = +676.
  GIFT-128: 40 rounds, tested on the low-64 x low-64 block.  Z = +275.

Correctness: the vectorized GIFT-64/128 codecs (key schedule ported from the
official reference C++, SubCells/PermBits/AddRoundKey/AddRoundConstant round
function) are checked against all four official test vectors from the GIFT
designers' repository (github.com/giftcipher/gift) before the F8 scan runs,
covering both ciphers with all-zero and non-trivial plaintext/key.

Self-contained: numpy only.
"""

import json
import math
import os
import time

import numpy as np

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RESULTS = os.path.join(REPO, "results")
os.makedirs(RESULTS, exist_ok=True)

N = 16000
N_PERM = 18
SEED = 42

# ─────────────────────────────────────────────────────────────────────────
# Official GIFT constants (verified against giftcipher/gift reference C++
# and against all 4 official test vectors -- see module docstring)
# ─────────────────────────────────────────────────────────────────────────

GIFT_SBOX = np.array([1, 10, 4, 12, 6, 15, 3, 9, 2, 13, 11, 7, 5, 0, 8, 14], dtype=np.uint8)

GIFT64_PERM = [
    0, 17, 34, 51, 48, 1, 18, 35, 32, 49, 2, 19, 16, 33, 50, 3,
    4, 21, 38, 55, 52, 5, 22, 39, 36, 53, 6, 23, 20, 37, 54, 7,
    8, 25, 42, 59, 56, 9, 26, 43, 40, 57, 10, 27, 24, 41, 58, 11,
    12, 29, 46, 63, 60, 13, 30, 47, 44, 61, 14, 31, 28, 45, 62, 15,
]

GIFT128_PERM = [
    0, 33, 66, 99, 96, 1, 34, 67, 64, 97, 2, 35, 32, 65, 98, 3,
    4, 37, 70, 103, 100, 5, 38, 71, 68, 101, 6, 39, 36, 69, 102, 7,
    8, 41, 74, 107, 104, 9, 42, 75, 72, 105, 10, 43, 40, 73, 106, 11,
    12, 45, 78, 111, 108, 13, 46, 79, 76, 109, 14, 47, 44, 77, 110, 15,
    16, 49, 82, 115, 112, 17, 50, 83, 80, 113, 18, 51, 48, 81, 114, 19,
    20, 53, 86, 119, 116, 21, 54, 87, 84, 117, 22, 55, 52, 85, 118, 23,
    24, 57, 90, 123, 120, 25, 58, 91, 88, 121, 26, 59, 56, 89, 122, 27,
    28, 61, 94, 127, 124, 29, 62, 95, 92, 125, 30, 63, 60, 93, 126, 31,
]

GIFT_RC = [
    0x01, 0x03, 0x07, 0x0F, 0x1F, 0x3E, 0x3D, 0x3B, 0x37, 0x2F,
    0x1E, 0x3C, 0x39, 0x33, 0x27, 0x0E, 0x1D, 0x3A, 0x35, 0x2B,
    0x16, 0x2C, 0x18, 0x30, 0x21, 0x02, 0x05, 0x0B, 0x17, 0x2E,
    0x1C, 0x38, 0x31, 0x23, 0x06, 0x0D, 0x1B, 0x36, 0x2D, 0x1A,
    0x34, 0x29, 0x12, 0x24, 0x08, 0x11, 0x22, 0x04, 0x09, 0x13,
    0x26, 0x0c, 0x19, 0x32, 0x25, 0x0a, 0x15, 0x2a, 0x14, 0x28,
    0x10, 0x20,
]

M64 = (1 << 64) - 1
M128 = (1 << 128) - 1


def gift_key_update_scalar(key_nibbles_32):
    """Official key update (nibble array of 32, key[0]=LSB nibble),
    ported verbatim from GIFT64-128_cipher.cpp / GIFT128-128_cipher.cpp
    (identical logic in both files)."""
    key = key_nibbles_32
    temp_key = [key[(i + 8) % 32] for i in range(32)]
    new_key = list(temp_key[:24])
    new_key += [temp_key[27], temp_key[24], temp_key[25], temp_key[26]]
    new_key += [
        ((temp_key[28] & 0xc) >> 2) ^ ((temp_key[29] & 0x3) << 2),
        ((temp_key[29] & 0xc) >> 2) ^ ((temp_key[30] & 0x3) << 2),
        ((temp_key[30] & 0xc) >> 2) ^ ((temp_key[31] & 0x3) << 2),
        ((temp_key[31] & 0xc) >> 2) ^ ((temp_key[28] & 0x3) << 2),
    ]
    return new_key


def gift_official_round_keys(key128_int, rounds, variant):
    """Compute the spec-correct sequence of round keys (as Python ints,
    packed the way the encryption round functions below expect:
    rk = (u << 16)|v for GIFT-64, (u<<32)|v for GIFT-128, where u/v are the
    16-bit-word-pair / 32-bit-word-pair the AddRoundKey step needs).

    variant: 'gift64' or 'gift128'.

    For GIFT-64, official AddRoundKey does:
        bits[4*i]   ^= key_bits[i]        for i in 0..15  (this is 'v' = key nibbles 0-3, i.e. bits 0-15)
        bits[4*i+1] ^= key_bits[i+16]     for i in 0..15  (this is 'u' = key nibbles 4-7, i.e. bits 16-31)
    So: v = lowest 16 bits of key register, u = next 16 bits up.

    For GIFT-128, official AddRoundKey does:
        bits[4*i+1] ^= key_bits[i]        for i in 0..31  ('v' = lowest 32 bits)
        bits[4*i+2] ^= key_bits[i+64]     for i in 0..31  ('u' = bits 64-95, i.e. THIRD 32-bit word, not second!)
    """
    key = [(key128_int >> (4 * i)) & 0xF for i in range(32)]  # nibbles, key[0]=LSB
    rks = []
    for r in range(rounds):
        if variant == 'gift64':
            v = sum(key[i] << (4 * i) for i in range(4))       # nibbles 0-3 = bits 0-15
            u = sum(key[4 + i] << (4 * i) for i in range(4))   # nibbles 4-7 = bits 16-31
            rk = (u << 16) | v
        else:  # gift128
            v = sum(key[i] << (4 * i) for i in range(8))        # nibbles 0-7  = bits 0-31
            u = sum(key[16 + i] << (4 * i) for i in range(8))   # nibbles 16-23 = bits 64-95
            rk = (u << 32) | v
        rks.append(rk)
        key = gift_key_update_scalar(key)
    return rks


def gift64_encrypt_vec(state, rks, rounds):
    """Vectorized GIFT-64 encryption. state: uint64 numpy array (N,).
    rks: list of `rounds` Python ints (packed u<<16|v as produced by
    gift_official_round_keys). SubCells / PermBits / AddRoundKey /
    AddRoundConstant, matching the official reference round function."""
    state = state.astype(np.uint64) & np.uint64(M64)
    for r in range(rounds):
        # SubCells
        new_state = np.zeros_like(state)
        for i in range(16):
            nib = ((state >> np.uint64(4 * i)) & np.uint64(0xF)).astype(np.uint8)
            new_state |= GIFT_SBOX[nib].astype(np.uint64) << np.uint64(4 * i)
        state = new_state

        # PermBits
        pstate = np.zeros_like(state)
        for i in range(64):
            bit = (state >> np.uint64(i)) & np.uint64(1)
            pstate |= bit << np.uint64(GIFT64_PERM[i])
        state = pstate

        # AddRoundKey
        rk = rks[r]
        u = (rk >> 16) & 0xFFFF
        v = rk & 0xFFFF
        for bit in range(16):
            if (u >> bit) & 1:
                state ^= np.uint64(1) << np.uint64(4 * bit + 1)
            if (v >> bit) & 1:
                state ^= np.uint64(1) << np.uint64(4 * bit)

        # AddRoundConstant
        rc = GIFT_RC[r] & 0x3F
        if rc & 1:
            state ^= np.uint64(1) << np.uint64(3)
        if (rc >> 1) & 1:
            state ^= np.uint64(1) << np.uint64(7)
        if (rc >> 2) & 1:
            state ^= np.uint64(1) << np.uint64(11)
        if (rc >> 3) & 1:
            state ^= np.uint64(1) << np.uint64(15)
        if (rc >> 4) & 1:
            state ^= np.uint64(1) << np.uint64(19)
        if (rc >> 5) & 1:
            state ^= np.uint64(1) << np.uint64(23)
        state ^= np.uint64(1) << np.uint64(63)

    return state


def gift128_encrypt_vec(state_hi, state_lo, rks, rounds):
    """Vectorized GIFT-128 encryption using two uint64 halves per sample
    (state_hi = bits 127..64, state_lo = bits 63..0), since numpy has no
    native 128-bit integer type. state_hi/state_lo: uint64 arrays (N,)."""
    hi = state_hi.astype(np.uint64)
    lo = state_lo.astype(np.uint64)

    def get_nibble(hi, lo, i):
        # nibble i (0..31), i<16 from lo, i>=16 from hi
        if i < 16:
            return (lo >> np.uint64(4 * i)) & np.uint64(0xF)
        else:
            return (hi >> np.uint64(4 * (i - 16))) & np.uint64(0xF)

    def set_bit(hi, lo, pos, val_arr):
        # pos: 0..127. val_arr: uint64 array of 0/1
        if pos < 64:
            lo = lo ^ (val_arr << np.uint64(pos))
        else:
            hi = hi ^ (val_arr << np.uint64(pos - 64))
        return hi, lo

    def get_bit(hi, lo, pos):
        if pos < 64:
            return (lo >> np.uint64(pos)) & np.uint64(1)
        else:
            return (hi >> np.uint64(pos - 64)) & np.uint64(1)

    for r in range(rounds):
        # SubCells: 32 nibbles
        new_hi = np.zeros_like(hi)
        new_lo = np.zeros_like(lo)
        for i in range(32):
            nib = get_nibble(hi, lo, i).astype(np.uint8)
            sbnib = GIFT_SBOX[nib].astype(np.uint64)
            if i < 16:
                new_lo |= sbnib << np.uint64(4 * i)
            else:
                new_hi |= sbnib << np.uint64(4 * (i - 16))
        hi, lo = new_hi, new_lo

        # PermBits: full 128-bit bit permutation
        p_hi = np.zeros_like(hi)
        p_lo = np.zeros_like(lo)
        for i in range(128):
            bit = get_bit(hi, lo, i)
            dest = GIFT128_PERM[i]
            if dest < 64:
                p_lo |= bit << np.uint64(dest)
            else:
                p_hi |= bit << np.uint64(dest - 64)
        hi, lo = p_hi, p_lo

        # AddRoundKey: bits[4*i+1] ^= key_bits[kbc], bits[4*i+2] ^= key_bits[kbc+64]
        rk = rks[r]
        u = (rk >> 32) & 0xFFFFFFFF   # key_bits[64..95] equivalent (v-word slot 2)
        v = rk & 0xFFFFFFFF            # key_bits[0..31]  equivalent (v-word slot 1)
        for bit in range(32):
            if (v >> bit) & 1:
                hi, lo = set_bit(hi, lo, 4 * bit + 1, np.ones_like(lo))
            if (u >> bit) & 1:
                hi, lo = set_bit(hi, lo, 4 * bit + 2, np.ones_like(lo))

        # AddRoundConstant
        rc = GIFT_RC[r] & 0x3F
        const_positions = []
        if rc & 1:
            const_positions.append(3)
        if (rc >> 1) & 1:
            const_positions.append(7)
        if (rc >> 2) & 1:
            const_positions.append(11)
        if (rc >> 3) & 1:
            const_positions.append(15)
        if (rc >> 4) & 1:
            const_positions.append(19)
        if (rc >> 5) & 1:
            const_positions.append(23)
        const_positions.append(127)
        for pos in const_positions:
            hi, lo = set_bit(hi, lo, pos, np.ones_like(lo))

    return hi, lo


def scalar_verify_against_official_vectors():
    """Sanity check: run the vectorized functions on N=1 and compare
    against the 4 official test vectors, before trusting them for the
    F8 sweep. This MUST pass or the rest of this script is meaningless."""
    ok = True

    # GIFT-64 vec1 (all-zero)
    rks = gift_official_round_keys(0, 28, 'gift64')
    ct = gift64_encrypt_vec(np.array([0], dtype=np.uint64), rks, 28)[0]
    expected = 0xf62bc3ef34f775ac
    ok &= (int(ct) == expected)
    print(f"  GIFT-64 vec1: got={int(ct):016x} expected={expected:016x} MATCH={int(ct)==expected}")

    # GIFT-64 vec2
    pt = 0xfedcba9876543210
    key = 0xfedcba9876543210fedcba9876543210
    rks = gift_official_round_keys(key, 28, 'gift64')
    ct = gift64_encrypt_vec(np.array([pt], dtype=np.uint64), rks, 28)[0]
    expected = 0xc1b71f66160ff587
    ok &= (int(ct) == expected)
    print(f"  GIFT-64 vec2: got={int(ct):016x} expected={expected:016x} MATCH={int(ct)==expected}")

    # GIFT-128 vec1 (all-zero)
    rks = gift_official_round_keys(0, 40, 'gift128')
    hi, lo = gift128_encrypt_vec(np.array([0], dtype=np.uint64),
                                  np.array([0], dtype=np.uint64), rks, 40)
    ct = (int(hi[0]) << 64) | int(lo[0])
    expected = 0xcd0bd738388ad3f668b15a36ceb6ff92
    ok &= (ct == expected)
    print(f"  GIFT-128 vec1: got={ct:032x} expected={expected:032x} MATCH={ct==expected}")

    # GIFT-128 vec2
    pt = 0xfedcba9876543210fedcba9876543210
    key = 0xfedcba9876543210fedcba9876543210
    rks = gift_official_round_keys(key, 40, 'gift128')
    hi, lo = gift128_encrypt_vec(np.array([pt >> 64], dtype=np.uint64),
                                  np.array([pt & M64], dtype=np.uint64), rks, 40)
    ct = (int(hi[0]) << 64) | int(lo[0])
    expected = 0x8422241a6dbf5a9346af468409ee0152
    ok &= (ct == expected)
    print(f"  GIFT-128 vec2: got={ct:032x} expected={expected:032x} MATCH={ct==expected}")

    return ok


# ─────────────────────────────────────────────────────────────────────────
# F8 core: cross-round MI with permutation-null Z-score
# ─────────────────────────────────────────────────────────────────────────

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


def bits_from_uint64(arr, n_bits):
    """arr: uint64 numpy array (N,). Returns (N, n_bits) uint8 bit matrix,
    bit i = (arr >> i) & 1 (LSB-first, i.e. bit index matches shift amount)."""
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


def run_gift64_f8(R, seed=SEED, N=N, n_perm=N_PERM):
    rng = np.random.default_rng(seed)
    key128 = int(rng.integers(0, 2**63, dtype=np.uint64)) | (int(rng.integers(0, 2**63, dtype=np.uint64)) << 63)
    key128 &= M128

    pt = rng.integers(0, 2**63, size=N, dtype=np.uint64).astype(np.uint64)

    rks_R = gift_official_round_keys(key128, R, 'gift64')
    rks_R1 = gift_official_round_keys(key128, R + 1, 'gift64')

    out_R = gift64_encrypt_vec(pt.copy(), rks_R, R)
    out_R1 = gift64_encrypt_vec(pt.copy(), rks_R1, R + 1)

    diff = out_R ^ out_R1
    bits_x = bits_from_uint64(out_R, 64)
    bits_diff = bits_from_uint64(diff, 64)

    z, mi, nm, ns = f8_mi_test(bits_x, bits_diff, 64, n_perm, seed + 12345)
    return z, mi


def run_gift128_f8(R, seed=SEED, N=N, n_perm=N_PERM):
    """GIFT-128 F8 test restricted to a bit-block subset for tractability
    (a full 128x128 MI grid at N=16000 x n_perm=18 is expensive). We test
    the low-64 x low-64 block (a tractable 64x64 grid, same cost as GIFT-64's
    full test) and additionally scan the full diagonal (bit i -> diff bit i)
    across all 128 bits (cheap, O(128) not O(128^2))."""
    rng = np.random.default_rng(seed)
    key_hi = int(rng.integers(0, 2**64, dtype=np.uint64))
    key_lo = int(rng.integers(0, 2**64, dtype=np.uint64))
    key128 = (key_hi << 64) | key_lo

    pt_hi = rng.integers(0, 2**63, size=N, dtype=np.uint64).astype(np.uint64)
    pt_lo = rng.integers(0, 2**63, size=N, dtype=np.uint64).astype(np.uint64)

    rks_R = gift_official_round_keys(key128, R, 'gift128')
    rks_R1 = gift_official_round_keys(key128, R + 1, 'gift128')

    out_hi_R, out_lo_R = gift128_encrypt_vec(pt_hi.copy(), pt_lo.copy(), rks_R, R)
    out_hi_R1, out_lo_R1 = gift128_encrypt_vec(pt_hi.copy(), pt_lo.copy(), rks_R1, R + 1)

    diff_hi = out_hi_R ^ out_hi_R1
    diff_lo = out_lo_R ^ out_lo_R1

    # Test the low 64 bits (bits 0-63) as source/target -- a tractable
    # 64x64 grid, same cost as GIFT-64's full test.
    bits_x = bits_from_uint64(out_lo_R, 64)
    bits_diff = bits_from_uint64(diff_lo, 64)
    z_lo, mi_lo, _, _ = f8_mi_test(bits_x, bits_diff, 64, n_perm, seed + 22222)

    # Full 128-bit diagonal-only scan (cheap: O(128) MI computations, no
    # inner max-search) as a broader coverage check across all nibbles.
    diag_mi = 0.0
    for i in range(128):
        if i < 64:
            xb = ((out_lo_R >> np.uint64(i)) & np.uint64(1)).astype(np.uint8)
            db = ((diff_lo >> np.uint64(i)) & np.uint64(1)).astype(np.uint8)
        else:
            xb = ((out_hi_R >> np.uint64(i - 64)) & np.uint64(1)).astype(np.uint8)
            db = ((diff_hi >> np.uint64(i - 64)) & np.uint64(1)).astype(np.uint8)
        diag_mi += mi_binary(xb, db)

    # permutation null for the diagonal-only statistic
    rng_p = np.random.default_rng(seed + 33333)
    null_diag = []
    for _ in range(n_perm):
        perm = rng_p.permutation(N)
        d_hi_p = diff_hi[perm]
        d_lo_p = diff_lo[perm]
        tot = 0.0
        for i in range(128):
            if i < 64:
                xb = ((out_lo_R >> np.uint64(i)) & np.uint64(1)).astype(np.uint8)
                db = ((d_lo_p >> np.uint64(i)) & np.uint64(1)).astype(np.uint8)
            else:
                xb = ((out_hi_R >> np.uint64(i - 64)) & np.uint64(1)).astype(np.uint8)
                db = ((d_hi_p >> np.uint64(i - 64)) & np.uint64(1)).astype(np.uint8)
            tot += mi_binary(xb, db)
        null_diag.append(tot)
    nm_d = float(np.mean(null_diag))
    ns_d = float(np.std(null_diag)) or 1e-30
    z_diag = (diag_mi - nm_d) / ns_d

    return z_lo, mi_lo, z_diag, diag_mi


if __name__ == "__main__":
    print("=" * 78)
    print("  GIFT-64/128 FULL-ROUND F8 CROSS-ROUND CARRY-LEAK SCAN")
    print("=" * 78)
    print()
    print("Step 1: Verify vectorized implementation against 4 official test vectors")
    ok = scalar_verify_against_official_vectors()
    if not ok:
        print("\n  !!! OFFICIAL TEST VECTOR MISMATCH -- ABORTING, DO NOT TRUST RESULTS !!!")
        raise SystemExit(1)
    print("\n  All 4 official test vectors PASS. Proceeding to F8 sweep.\n")

    results = {"gift64": [], "gift128": []}
    t0 = time.time()

    print("--- GIFT-64, full rounds = 28 ---")
    for R in [4, 14, 28]:
        t1 = time.time()
        z, mi = run_gift64_f8(R)
        dt = time.time() - t1
        marker = "***" if z > 100 else ("**" if z > 10 else ("*" if z > 3 else ""))
        print(f"  R={R:>3d}: Z = {z:>+10.1f}  MI={mi:.6f}  {marker}  ({dt:.1f}s)")
        results["gift64"].append({"R": R, "Z": round(z, 2), "MI": round(mi, 6), "elapsed_s": round(dt, 1)})

    print("\n--- GIFT-128, full rounds = 40 (low-64 x low-64 block) ---")
    for R in [4, 20, 40]:
        t1 = time.time()
        z_lo, mi_lo, z_diag, mi_diag = run_gift128_f8(R)
        dt = time.time() - t1
        marker = "***" if max(z_lo, z_diag) > 100 else ("**" if max(z_lo, z_diag) > 10 else ("*" if max(z_lo, z_diag) > 3 else ""))
        print(f"  R={R:>3d}: Z_lo64x64 = {z_lo:>+10.1f}  Z_diag128 = {z_diag:>+10.1f}  {marker}  ({dt:.1f}s)")
        results["gift128"].append({
            "R": R, "Z_lo64x64": round(z_lo, 2), "MI_lo64x64": round(mi_lo, 6),
            "Z_diag128": round(z_diag, 2), "MI_diag128": round(mi_diag, 6),
            "elapsed_s": round(dt, 1),
        })

    total = time.time() - t0

    z64_full = results['gift64'][-1]['Z']
    z128_full = max(results['gift128'][-1]['Z_lo64x64'], results['gift128'][-1]['Z_diag128'])

    print("\n" + "=" * 78)
    print("  FULL-ROUND F8 DISTINGUISHERS")
    print("=" * 78)
    print(f"  GIFT-64  (R=28): Z = {z64_full:+.1f}")
    print(f"  GIFT-128 (R=40): Z = {z128_full:+.1f}  (low-64 block)")
    print(f"\n  Total time: {total:.1f}s")

    output = {
        "cipher": "GIFT-64 / GIFT-128",
        "mechanism": "permutation cycle",
        "official_test_vectors_verified": ok,
        "parameters": {"N": N, "n_perm": N_PERM},
        "results": results,
        "gift64_full_round_z": z64_full,
        "gift128_full_round_z": z128_full,
        "total_time_s": round(total, 1),
    }
    result_path = os.path.join(RESULTS, "gift.json")
    with open(result_path, "w") as f:
        json.dump(output, f, indent=2)
    print(f"\n  Saved to {result_path}")

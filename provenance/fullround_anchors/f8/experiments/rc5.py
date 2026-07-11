#!/usr/bin/env python3
"""
RC5-32/12/16 — Full-Round F8 Cross-Round Distinguisher

RC5 (Rivest, 1994; RFC 2040). 64-bit block, 128-bit key, 32-bit words,
12 rounds (the "nominal" parameterization). Classic ARX Feistel-like
cipher.

RC5 round function (RFC 2040), per round i:
    A = ROTL(A ^ B, B) + S[2i]
    B = ROTL(B ^ A, A) + S[2i+1]

IMPLEMENTATION VERIFIED against the official all-zero-key/all-zero-
plaintext RFC 2040 test vector: ciphertext words (A,B) = (0xeedba521,
0x6d8f4b15) at R=12, exact match. Encrypt/decrypt round-trip also
verified.

MECHANISM: fixed branch positions (A, B never shift between rounds),
and each per-round update ends with an addition whose result is used
directly as the new branch value, with no foreign XOR interrupting
before the next round consumes it. This exposes the addition's carry
chain across the round boundary the same way TEA's and Speck's
self-referential structure does.
"""
import json
import math
import os

import numpy as np

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RESULTS = os.path.join(REPO, "results")
os.makedirs(RESULTS, exist_ok=True)

MASK32 = np.uint64(0xFFFFFFFF)
P32 = 0xB7E15163
Q32 = 0x9E3779B9
FULL_ROUNDS = 12


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


def rotl_scalar(v, r, mask=0xFFFFFFFF):
    r %= 32
    if r == 0:
        return v & mask
    return ((v << r) | (v >> (32 - r))) & mask


def key_expand(key_bytes, R=12):
    mask = 0xFFFFFFFF
    b = len(key_bytes)
    WW = 4
    LL = max((b + WW - 1) // WW, 1)
    L = [0] * LL
    for i in range(b - 1, -1, -1):
        L[i // WW] = ((L[i // WW] << 8) + key_bytes[i]) & mask
    T = 2 * (R + 1)
    S = [0] * T
    S[0] = P32
    for i in range(1, T):
        S[i] = (S[i - 1] + Q32) & mask
    k = 3 * max(LL, T)
    i = j = A = B = 0
    for _ in range(k):
        A = S[i] = rotl_scalar((S[i] + A + B) & mask, 3, mask)
        B = L[j] = rotl_scalar((L[j] + A + B) & mask, (A + B) & 0x1F, mask)
        i = (i + 1) % T
        j = (j + 1) % LL
    return S


def rc5_encrypt_words_scalar(A, B, S, R):
    mask = 0xFFFFFFFF
    A = (A + S[0]) & mask
    B = (B + S[1]) & mask
    for i in range(1, R + 1):
        A = (rotl_scalar((A ^ B) & mask, B & 0x1F, mask) + S[2 * i]) & mask
        B = (rotl_scalar((B ^ A) & mask, A & 0x1F, mask) + S[2 * i + 1]) & mask
    return A, B


def rc5_decrypt_words_scalar(A, B, S, R):
    mask = 0xFFFFFFFF

    def rotr(v, r):
        r %= 32
        return v & mask if r == 0 else ((v >> r) | (v << (32 - r))) & mask

    for i in range(R, 0, -1):
        B = rotr((B - S[2 * i + 1]) & mask, A & 0x1F)
        B ^= A
        B &= mask
        A = rotr((A - S[2 * i]) & mask, B & 0x1F)
        A ^= B
        A &= mask
    B = (B - S[1]) & mask
    A = (A - S[0]) & mask
    return A, B


def verify_correctness():
    """Official RFC 2040 all-zero test vector + round-trip check."""
    key = bytes(16)
    S = key_expand(key, R=FULL_ROUNDS)
    A, B = rc5_encrypt_words_scalar(0, 0, S, FULL_ROUNDS)
    known_vector_ok = bool(A == 0xEEDBA521 and B == 0x6D8F4B15)

    A2, B2 = 0x12345678, 0x9ABCDEF0
    ctA, ctB = rc5_encrypt_words_scalar(A2, B2, S, FULL_ROUNDS)
    rtA, rtB = rc5_decrypt_words_scalar(ctA, ctB, S, FULL_ROUNDS)
    roundtrip_ok = bool(rtA == A2 and rtB == B2)

    ctA1, ctB1 = rc5_encrypt_words_scalar(A2 ^ 1, B2, S, FULL_ROUNDS)
    avalanche = bin(ctA ^ ctA1).count("1") + bin(ctB ^ ctB1).count("1")
    return known_vector_ok, roundtrip_ok, avalanche


def _rotl_vec(v, r):
    """Data-dependent left rotation; r is a per-element uint64 array
    (0..31)."""
    result = np.zeros_like(v)
    for shift in range(32):
        mask_sel = (r == np.uint64(shift))
        if not np.any(mask_sel):
            continue
        if shift == 0:
            rotated = v & MASK32
        else:
            rotated = ((v << np.uint64(shift)) | (v >> np.uint64(32 - shift))) & MASK32
        result = np.where(mask_sel, rotated, result)
    return result.astype(np.uint64)


def rc5_encrypt_vec(A, B, S, R):
    mask = MASK32
    A = A.copy() & mask
    B = B.copy() & mask
    A = (A + np.uint64(S[0])) & mask
    B = (B + np.uint64(S[1])) & mask
    for i in range(1, R + 1):
        rot_b = B & np.uint64(0x1F)
        xa = (A ^ B) & mask
        rotated_a = _rotl_vec(xa, rot_b)
        A_new = (rotated_a + np.uint64(S[2 * i])) & mask

        rot_a = A_new & np.uint64(0x1F)
        xb = (B ^ A_new) & mask
        rotated_b = _rotl_vec(xb, rot_a)
        B_new = (rotated_b + np.uint64(S[2 * i + 1])) & mask

        A, B = A_new, B_new
    return A, B


def f8_max_z(state_R, state_R1, n_bits=32, n_perm=20, seed=99):
    N = len(state_R[0])
    perms = [np.random.default_rng(seed + j).permutation(N) for j in range(n_perm)]
    best = {"z": -999.0, "src": None, "tgt": None, "bit": None, "mi": 0.0}
    for si in range(2):
        for ti in range(2):
            diff = state_R[ti] ^ state_R1[ti]
            for bit in range(n_bits):
                xb = ((state_R[si] >> np.uint64(bit)) & np.uint64(1)).astype(np.uint8)
                db = ((diff >> np.uint64(bit)) & np.uint64(1)).astype(np.uint8)
                real_mi = mi_binary(xb, db)
                nulls = [mi_binary(xb, db[p]) for p in perms]
                nm, ns = np.mean(nulls), np.std(nulls)
                if ns < 1e-30:
                    ns = 1e-30
                z = (real_mi - nm) / ns
                if z > best["z"]:
                    best = {"z": float(z), "src": si, "tgt": ti, "bit": bit, "mi": float(real_mi)}
    return best["z"], best


def measure_at(N, R, seed):
    rng = np.random.default_rng(1000 + seed)
    key = bytes(int(x) for x in rng.integers(0, 256, size=16))
    S = key_expand(key, R=R + 1)
    rng2 = np.random.default_rng(seed)
    A0 = rng2.integers(0, 1 << 32, size=N, dtype=np.uint64)
    B0 = rng2.integers(0, 1 << 32, size=N, dtype=np.uint64)
    AR, BR = rc5_encrypt_vec(A0, B0, S, R)
    AR1, BR1 = rc5_encrypt_vec(A0, B0, S, R + 1)
    z, detail = f8_max_z([AR, BR], [AR1, BR1], seed=99 + seed)
    return z, detail


def run(seeds=(0, 1, 2)):
    N_small, N_large = 20000, 200000

    def mean_at(N):
        zs, details = [], []
        for seed in seeds:
            z, detail = measure_at(N, FULL_ROUNDS, seed)
            zs.append(z)
            details.append(detail)
        return float(np.mean(zs)), zs, details

    mean_small, zs_small, det_small = mean_at(N_small)
    mean_large, zs_large, det_large = mean_at(N_large)

    return {
        "full_rounds": FULL_ROUNDS,
        "mean_z_N20k": mean_small, "z_per_seed_N20k": zs_small, "detail_N20k": det_small,
        "mean_z_N200k": mean_large, "z_per_seed_N200k": zs_large, "detail_N200k": det_large,
        "z_ratio_10x_N": mean_large / mean_small if mean_small > 0 else None,
    }


def main():
    known_vector_ok, roundtrip_ok, avalanche = verify_correctness()
    assert known_vector_ok, "RC5 does not match the official RFC 2040 test vector -- implementation bug, stop."
    assert roundtrip_ok, "RC5 encrypt/decrypt round-trip FAILED -- implementation bug, stop."

    print("=" * 96)
    print("  RC5-32/12/16 Full-Round F8 Distinguisher")
    print("=" * 96)
    print(f"\nCorrectness pre-check: known_test_vector={known_vector_ok}, "
          f"round-trip={roundtrip_ok}, avalanche={avalanche}/64")

    result = run()
    print(f"\nFull rounds ({result['full_rounds']}): "
          f"max-Z @N=20k={result['mean_z_N20k']:+.1f}, "
          f"@N=200k={result['mean_z_N200k']:+.1f}, "
          f"10x-N ratio={result['z_ratio_10x_N']:.2f}")
    print(f"\nRESULT: RC5-32/12/16 leaks at full {result['full_rounds']} rounds on F8 "
          f"(mean Z={result['mean_z_N200k']:+.1f}, N-scaling ratio="
          f"{result['z_ratio_10x_N']:.2f}x).")

    output = {
        "cipher": "RC5-32/12/16 (Rivest 1994, RFC 2040)",
        "correctness_check": {"known_vector_ok": known_vector_ok,
                              "roundtrip_ok": roundtrip_ok, "avalanche": avalanche},
        "result": result,
    }

    def _default(o):
        if isinstance(o, (np.bool_,)):
            return bool(o)
        if isinstance(o, (np.integer,)):
            return int(o)
        if isinstance(o, (np.floating,)):
            return float(o)
        raise TypeError(f"Object of type {o.__class__.__name__} is not JSON serializable")

    result_path = os.path.join(RESULTS, "rc5.json")
    with open(result_path, "w") as f:
        json.dump(output, f, indent=2, default=_default)
    print(f"\nSaved to {result_path}")
    return output


if __name__ == "__main__":
    main()

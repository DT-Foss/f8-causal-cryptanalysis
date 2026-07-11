#!/usr/bin/env python3
"""Differential Heatmap: C(P)⊕C(P⊕Δ) Analysis.

FUNDAMENTALLY DIFFERENT from F8:
- F8 tests single outputs: out(R) vs out(R+1) — cross-round independence
- This tests PAIRS: C(P)⊕C(P⊕Δ) — differential propagation

AES's S-Box has specific differential properties invisible in single outputs
but visible in the DIFFERENCE between two outputs with related inputs.

CIPHER-SPECIFIC Δ choices:
- AES: Δ = 1-byte difference at specific S-Box input positions
       (byte 0, byte 5, byte 10, byte 15 = diagonal = first SubBytes input)
       Values: 0x01, 0x02, 0x80 (low/medium/high weight)
- ChaCha: Δ = 1-bit flip in counter word (state[12])
- Salsa: Δ = 1-bit flip in counter word
- Speck: Δ = 1-bit flip in x-half (reference)

TEST: For each (cipher, rounds, Δ):
1. Generate N random plaintexts P
2. Compute C(P) and C(P⊕Δ)
3. Compute differential D = C(P)⊕C(P⊕Δ)
4. Test statistical properties of D:
   a. Byte-wise entropy (should be maximal = 8 bits for random)
   b. Byte-pair MI (should be zero for random)
   c. Byte-value bias (should be uniform for random)
5. Permutation null: shuffle P to break P↔P⊕Δ pairing
"""
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..'))
sys.path.insert(0, os.path.dirname(__file__))

import numpy as np
import math
import struct
from scipy import stats
from live_casiv2.ciphers import _aes_ecb_batch, _aes_key_expansion


N = 30000
SEEDS = 5
N_PERM = 15


def mi_bytes(a, b, n):
    """MI between two byte arrays."""
    tbl = np.zeros((256, 256))
    np.add.at(tbl, (a, b), 1)
    pj = tbl / n
    pa = pj.sum(1, keepdims=True)
    pb = pj.sum(0, keepdims=True)
    denom = pa * pb
    ok = (pj > 0) & (denom > 0)
    if not ok.any():
        return 0.0
    return max(0, float(np.sum(pj[ok] * np.log2(pj[ok] / denom[ok]))))


# ============================================================
# CIPHER-SPECIFIC DIFFERENTIAL GENERATORS
# ============================================================

def aes_differential(N_pairs, n_rounds, delta_byte_pos, delta_value, seed=42):
    """Generate AES differential pairs.
    Returns (C_P, C_P_delta) as (N, 16) uint8 arrays.
    delta is applied at byte position delta_byte_pos with value delta_value.
    """
    rng = np.random.RandomState(seed)
    aes_key = rng.randint(0, 256, size=16, dtype=np.uint8)

    # Random plaintexts
    P = rng.randint(0, 256, size=(N_pairs, 16), dtype=np.uint8)

    # P ⊕ Δ
    P_delta = P.copy()
    P_delta[:, delta_byte_pos] ^= delta_value

    # Encrypt both
    C_P = _aes_ecb_batch(aes_key, P, n_rounds)
    C_P_delta = _aes_ecb_batch(aes_key, P_delta, n_rounds)

    return C_P, C_P_delta


def chacha_differential(N_pairs, n_rounds, delta_bit, seed=42):
    """Generate ChaCha differential pairs.
    Δ = flip bit delta_bit in the counter word (state position 12).
    """
    np.random.seed(seed)
    key = np.random.bytes(32)
    nonce = np.random.bytes(12)

    M = 0xFFFFFFFF

    def chacha_core(counter, rounds):
        state = [0x61707865, 0x3320646e, 0x79622d32, 0x6b206574] + \
                list(struct.unpack('<8I', key)) + [counter] + \
                list(struct.unpack('<3I', nonce))
        w = state[:]
        for i in range(rounds):
            if i % 2 == 0:
                for a,b,c,d in [(0,4,8,12),(1,5,9,13),(2,6,10,14),(3,7,11,15)]:
                    w[a]=(w[a]+w[b])&M; w[d]^=w[a]; w[d]=((w[d]<<16)|(w[d]>>16))&M
                    w[c]=(w[c]+w[d])&M; w[b]^=w[c]; w[b]=((w[b]<<12)|(w[b]>>20))&M
                    w[a]=(w[a]+w[b])&M; w[d]^=w[a]; w[d]=((w[d]<<8)|(w[d]>>24))&M
                    w[c]=(w[c]+w[d])&M; w[b]^=w[c]; w[b]=((w[b]<<7)|(w[b]>>25))&M
            else:
                for a,b,c,d in [(0,5,10,15),(1,6,11,12),(2,7,8,13),(3,4,9,14)]:
                    w[a]=(w[a]+w[b])&M; w[d]^=w[a]; w[d]=((w[d]<<16)|(w[d]>>16))&M
                    w[c]=(w[c]+w[d])&M; w[b]^=w[c]; w[b]=((w[b]<<12)|(w[b]>>20))&M
                    w[a]=(w[a]+w[b])&M; w[d]^=w[a]; w[d]=((w[d]<<8)|(w[d]>>24))&M
                    w[c]=(w[c]+w[d])&M; w[b]^=w[c]; w[b]=((w[b]<<7)|(w[b]>>25))&M
        # Add initial state (feedforward)
        out = [(w[i] + state[i]) & M for i in range(16)]
        return struct.pack('<16I', *out)

    C_P = np.zeros((N_pairs, 64), dtype=np.uint8)
    C_P_delta = np.zeros((N_pairs, 64), dtype=np.uint8)

    delta_mask = 1 << delta_bit  # Flip this bit in counter

    for i in range(N_pairs):
        ctr = i
        raw = chacha_core(ctr, n_rounds)
        C_P[i] = np.frombuffer(raw, dtype=np.uint8)

        ctr_delta = ctr ^ delta_mask
        raw_d = chacha_core(ctr_delta, n_rounds)
        C_P_delta[i] = np.frombuffer(raw_d, dtype=np.uint8)

    return C_P, C_P_delta


def speck_differential(N_pairs, n_rounds, delta_bit, seed=42):
    """Generate Speck 32/64 differential pairs.
    Δ = flip bit delta_bit in the x-half (upper 16 bits of plaintext).
    """
    from speck_utils import speck_gen
    rng = np.random.default_rng(seed)
    mask16 = 0xFFFF

    # Need to access the round function directly
    mk = [int(rng.integers(0, 2**16)) for _ in range(4)]
    rk = [0] * max(n_rounds + 1, 40)
    l = list(mk[1:])
    rk[0] = mk[0]
    for i in range(n_rounds):
        ror_l = ((l[i % len(l)] >> 7) | (l[i % len(l)] << 9)) & mask16
        new_l = (rk[i] + ror_l) & mask16
        new_l ^= i
        l.append(new_l)
        rol_rk = ((rk[i] << 2) | (rk[i] >> 14)) & mask16
        rk[i + 1] = rol_rk ^ new_l

    C_P = np.zeros((N_pairs, 4), dtype=np.uint8)
    C_P_delta = np.zeros((N_pairs, 4), dtype=np.uint8)

    for idx in range(N_pairs):
        x = (idx >> 16) & mask16
        y = idx & mask16

        # Encrypt P
        xc, yc = x, y
        for r in range(n_rounds):
            ror_x = ((xc >> 7) | (xc << 9)) & mask16
            xc = ((ror_x + yc) & mask16) ^ rk[r]
            yc = (((yc << 2) | (yc >> 14)) & mask16) ^ xc
        C_P[idx] = [(xc >> 8) & 0xFF, xc & 0xFF, (yc >> 8) & 0xFF, yc & 0xFF]

        # Encrypt P ⊕ Δ (flip bit in x)
        x_d = x ^ (1 << delta_bit)
        xc, yc = x_d, y
        for r in range(n_rounds):
            ror_x = ((xc >> 7) | (xc << 9)) & mask16
            xc = ((ror_x + yc) & mask16) ^ rk[r]
            yc = (((yc << 2) | (yc >> 14)) & mask16) ^ xc
        C_P_delta[idx] = [(xc >> 8) & 0xFF, xc & 0xFF, (yc >> 8) & 0xFF, yc & 0xFF]

    return C_P, C_P_delta


# ============================================================
# DIFFERENTIAL ANALYSIS
# ============================================================

def analyze_differential(C_P, C_P_delta, n_perm=N_PERM):
    """Analyze the differential D = C(P) ⊕ C(P⊕Δ).

    Tests:
    1. Byte-entropy deviation from 8.0
    2. Max byte-pair MI
    3. Byte-value bias (max chi2 across bytes)

    Returns Z-scores via permutation null.
    """
    D = C_P ^ C_P_delta
    n = D.shape[0]
    bb = D.shape[1]

    # --- Test 1: Mean byte entropy ---
    entropies = []
    for j in range(bb):
        counts = np.bincount(D[:, j], minlength=256)
        p = counts / n
        p = p[p > 0]
        entropies.append(-np.sum(p * np.log2(p)))
    mean_entropy = np.mean(entropies)

    # --- Test 2: Max byte-pair MI ---
    # Test ~16 byte pairs for speed
    n_test = min(bb, 16)
    step = max(1, bb // n_test)
    test_bytes = list(range(0, bb, step))[:n_test]

    max_mi = 0.0
    total_mi = 0.0
    n_mi_pairs = 0
    for i_idx, i in enumerate(test_bytes):
        for j_idx, j in enumerate(test_bytes):
            if i >= j:
                continue
            mi = mi_bytes(D[:, i], D[:, j], n)
            max_mi = max(max_mi, mi)
            total_mi += mi
            n_mi_pairs += 1
    mean_mi = total_mi / max(n_mi_pairs, 1)

    # --- Test 3: Max byte chi2 (deviation from uniform) ---
    max_chi2 = 0.0
    for j in range(bb):
        counts = np.bincount(D[:, j], minlength=256)
        expected = n / 256
        chi2 = np.sum((counts - expected)**2 / expected)
        max_chi2 = max(max_chi2, chi2)

    # --- Permutation null ---
    rng = np.random.default_rng(42)
    null_entropy = []; null_mi = []; null_chi2 = []
    for _ in range(n_perm):
        # Shuffle C_P_delta to break P↔P⊕Δ pairing
        perm = rng.permutation(n)
        D_null = C_P ^ C_P_delta[perm]

        # Entropy
        ents = []
        for j in range(bb):
            counts = np.bincount(D_null[:, j], minlength=256)
            p = counts / n; p = p[p > 0]
            ents.append(-np.sum(p * np.log2(p)))
        null_entropy.append(np.mean(ents))

        # MI
        nm = 0.0; nm_cnt = 0
        for i_idx, i in enumerate(test_bytes):
            for j_idx, j in enumerate(test_bytes):
                if i >= j: continue
                nm = max(nm, mi_bytes(D_null[:, i], D_null[:, j], n))
                nm_cnt += 1
        null_mi.append(nm)

        # Chi2
        mc = 0.0
        for j in range(bb):
            counts = np.bincount(D_null[:, j], minlength=256)
            expected = n / 256
            mc = max(mc, np.sum((counts - expected)**2 / expected))
        null_chi2.append(mc)

    def z_score(real, nulls):
        m = np.mean(nulls)
        s = max(np.std(nulls), 1e-30)
        return (real - m) / s

    z_ent = z_score(mean_entropy, null_entropy)  # Negative Z = lower entropy = more structure
    z_mi = z_score(max_mi, null_mi)
    z_chi2 = z_score(max_chi2, null_chi2)

    return {
        'z_entropy': z_ent,
        'z_mi': z_mi,
        'z_chi2': z_chi2,
        'entropy': mean_entropy,
        'max_mi': max_mi,
        'max_chi2': max_chi2,
    }


# ============================================================
# MAIN
# ============================================================

print("=" * 90)
print("DIFFERENTIAL HEATMAP: C(P) ⊕ C(P⊕Δ)")
print("=" * 90)
print(f"N={N}, {SEEDS} seeds, {N_PERM} perms")
print(flush=True)


# === AES-128 ===
print("\n" + "=" * 90)
print("  AES-128 — S-Box differential characteristics")
print("=" * 90, flush=True)

# Test multiple Δ positions and values
aes_deltas = [
    (0,  0x01, "byte0, Δ=0x01"),
    (0,  0x02, "byte0, Δ=0x02"),
    (0,  0x80, "byte0, Δ=0x80"),
    (5,  0x01, "byte5, Δ=0x01"),
    (10, 0x01, "byte10, Δ=0x01"),
    (15, 0x01, "byte15, Δ=0x01"),
    (0,  0xFF, "byte0, Δ=0xFF"),
]

for n_rounds in [2, 3, 4, 5]:
    print(f"\n  --- AES R{n_rounds} ---")
    print(f"  {'Delta':>20}  {'Z_ent':>8}  {'Z_MI':>8}  {'Z_chi2':>8}  {'Best':>8}  {'Signal?':>10}")
    print("  " + "-" * 75, flush=True)

    for dpos, dval, dlabel in aes_deltas:
        z_ents = []; z_mis = []; z_chi2s = []
        for s in range(SEEDS):
            seed = s * 1000 + 42
            C_P, C_Pd = aes_differential(N, n_rounds, dpos, dval, seed)
            res = analyze_differential(C_P, C_Pd)
            z_ents.append(res['z_entropy'])
            z_mis.append(res['z_mi'])
            z_chi2s.append(res['z_chi2'])

        mze = np.mean(z_ents)
        mzm = np.mean(z_mis)
        mzc = np.mean(z_chi2s)
        best = max(abs(mze), mzm, mzc)
        sig = "YES ***" if best > 3 else ("weak *" if best > 2 else "no")
        if best > 1.5 or n_rounds <= 3:
            print(f"  {dlabel:>20}  {mze:>+8.1f}  {mzm:>+8.1f}  {mzc:>+8.1f}  {best:>+8.1f}  {sig}", flush=True)

    # Summary for this round
    print(flush=True)


# === ChaCha20 ===
print("\n" + "=" * 90)
print("  ChaCha20 — Counter-bit differential")
print("=" * 90, flush=True)

chacha_deltas = [0, 1, 7, 15, 31]  # Bit positions in counter word

for n_rounds in [2, 3, 4]:
    print(f"\n  --- ChaCha R{n_rounds} ---")
    print(f"  {'Delta bit':>15}  {'Z_ent':>8}  {'Z_MI':>8}  {'Z_chi2':>8}  {'Best':>8}  {'Signal?':>10}")
    print("  " + "-" * 70, flush=True)

    for dbit in chacha_deltas:
        z_ents = []; z_mis = []; z_chi2s = []
        for s in range(SEEDS):
            seed = s * 1000 + 42
            C_P, C_Pd = chacha_differential(N, n_rounds, dbit, seed)
            res = analyze_differential(C_P, C_Pd)
            z_ents.append(res['z_entropy'])
            z_mis.append(res['z_mi'])
            z_chi2s.append(res['z_chi2'])

        mze = np.mean(z_ents)
        mzm = np.mean(z_mis)
        mzc = np.mean(z_chi2s)
        best = max(abs(mze), mzm, mzc)
        sig = "YES ***" if best > 3 else ("weak *" if best > 2 else "no")
        print(f"  bit {dbit:>10}  {mze:>+8.1f}  {mzm:>+8.1f}  {mzc:>+8.1f}  {best:>+8.1f}  {sig}", flush=True)


# === Speck 32/64 (reference) ===
print("\n" + "=" * 90)
print("  Speck 32/64 — Reference (known signal)")
print("=" * 90, flush=True)

speck_deltas = [0, 7, 15]  # Bit positions in x-half

for n_rounds in [10, 15, 22]:
    print(f"\n  --- Speck R{n_rounds} ---")
    print(f"  {'Delta bit':>15}  {'Z_ent':>8}  {'Z_MI':>8}  {'Z_chi2':>8}  {'Best':>8}  {'Signal?':>10}")
    print("  " + "-" * 70, flush=True)

    for dbit in speck_deltas:
        z_ents = []; z_mis = []; z_chi2s = []
        for s in range(SEEDS):
            seed = s * 1000 + 42
            C_P, C_Pd = speck_differential(N, n_rounds, dbit, seed)
            res = analyze_differential(C_P, C_Pd)
            z_ents.append(res['z_entropy'])
            z_mis.append(res['z_mi'])
            z_chi2s.append(res['z_chi2'])

        mze = np.mean(z_ents)
        mzm = np.mean(z_mis)
        mzc = np.mean(z_chi2s)
        best = max(abs(mze), mzm, mzc)
        sig = "YES ***" if best > 3 else ("weak *" if best > 2 else "no")
        print(f"  bit {dbit:>10}  {mze:>+8.1f}  {mzm:>+8.1f}  {mzc:>+8.1f}  {best:>+8.1f}  {sig}", flush=True)


print("\n=== DONE ===")

#!/usr/bin/env python3
"""Chaskey Informed Mode Re-Attack.

Chaskey half-round (even):
  v[0] += v[1]; v[2] += v[3]                    ← 2 additions
  v[1] = ROL(v[1], 5); v[3] = ROL(v[3], 8)     ← rotations β=5, β=8
  v[1] ^= v[0]; v[3] ^= v[2]                    ← XOR cross-mix
  v[0] = ROL(v[0], 16)                           ← rotation
  v[0] += v[3]; v[2] += v[1]                    ← 2 more additions (CROSS)
  v[1] = ROL(v[1], 7); v[3] = ROL(v[3], 13)    ← rotations β=7, β=13
  v[1] ^= v[2]; v[3] ^= v[0]                    ← XOR cross-mix
  v[2] = ROL(v[2], 16)                           ← rotation

β values: 5, 8, 7, 13 — ALL above β_max=4 → carry-leak should be ZERO.
But signal exists at R1-R3 from incomplete diffusion.

INFORMED TEST:
1. Isolate each of the 4 additions per half-round
2. Test MI between addition inputs and diff of addition output
3. Quantify per-round MI decay

Between round R and R+1 (one FULL round = 2 half-rounds):
The last half-round's additions couple specific word pairs.
Test the FIRST addition pair: v[0]+=v[1] → MI between v[0],v[1] and diff(v[0])
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


def chaskey_gen_words(N_blocks, n_rounds=8, seed=42):
    """Chaskey returning 32-bit words."""
    rng = np.random.default_rng(seed)
    mk = [int(rng.integers(0, 2**32)) for _ in range(4)]
    mask32 = 0xFFFFFFFF

    w0 = np.zeros(N_blocks, dtype=np.uint64)
    w1 = np.zeros(N_blocks, dtype=np.uint64)
    w2 = np.zeros(N_blocks, dtype=np.uint64)
    w3 = np.zeros(N_blocks, dtype=np.uint64)

    for blk_idx in range(N_blocks):
        v = [(blk_idx >> (32*i)) & mask32 for i in range(4)]
        for i in range(4): v[i] ^= mk[i]
        for r in range(n_rounds):
            v[0] = (v[0] + v[1]) & mask32; v[2] = (v[2] + v[3]) & mask32
            v[1] = ((v[1] << 5) | (v[1] >> 27)) & mask32
            v[3] = ((v[3] << 8) | (v[3] >> 24)) & mask32
            v[1] ^= v[0]; v[3] ^= v[2]
            v[0] = ((v[0] << 16) | (v[0] >> 16)) & mask32
            v[0] = (v[0] + v[3]) & mask32; v[2] = (v[2] + v[1]) & mask32
            v[1] = ((v[1] << 7) | (v[1] >> 25)) & mask32
            v[3] = ((v[3] << 13) | (v[3] >> 19)) & mask32
            v[1] ^= v[2]; v[3] ^= v[0]
            v[2] = ((v[2] << 16) | (v[2] >> 16)) & mask32
        for i in range(4): v[i] ^= mk[i]
        w0[blk_idx] = v[0]; w1[blk_idx] = v[1]
        w2[blk_idx] = v[2]; w3[blk_idx] = v[3]

    return w0, w1, w2, w3


def chaskey_informed_mi(n_rounds, seed=42):
    """MI test with informed word-pair selection."""
    words_R = chaskey_gen_words(N, n_rounds=n_rounds, seed=seed)
    words_R1 = chaskey_gen_words(N, n_rounds=n_rounds + 1, seed=seed)
    n = N

    diff = [words_R[i] ^ words_R1[i] for i in range(4)]

    # The LAST round of R+1 has 4 additions:
    # 1st half: v[0]+=v[1] (β=5), v[2]+=v[3] (β=8)
    # 2nd half: v[0]+=v[3] (β=13), v[2]+=v[1] (β=7)
    # Test all 4 addition source→target word pairs

    additions = [
        ("v0+=v1 (β=5)", 1, 0, 5),   # v[1] input → v[0] output
        ("v2+=v3 (β=8)", 3, 2, 8),   # v[3] input → v[2] output
        ("v0+=v3 (β=13)", 3, 0, 13), # v[3] input → v[0] output (cross)
        ("v2+=v1 (β=7)", 1, 2, 7),   # v[1] input → v[2] output (cross)
    ]

    results = {}
    for add_name, src_word, tgt_word, beta in additions:
        # MI on all 32 bits of source word vs diff of target word
        # Test the β-shifted diagonal (where carry-leak would be)
        mi_total = 0.0
        for i in range(32):
            j = (i + beta) % 32
            xb = ((words_R[src_word] >> i) & 1).astype(np.uint8)
            dyb = ((diff[tgt_word] >> j) & 1).astype(np.uint8)
            mi_total += mi_2x2(xb, dyb, n)

        # Also test ALL 32×32 bit pairs (black-box within this word pair)
        mi_full = 0.0
        for i in range(32):
            best = 0
            xb = ((words_R[src_word] >> i) & 1).astype(np.uint8)
            for j in range(32):
                dyb = ((diff[tgt_word] >> j) & 1).astype(np.uint8)
                best = max(best, mi_2x2(xb, dyb, n))
            mi_full += best

        # Permutation null (for the full scan)
        rng = np.random.default_rng(seed + hash(add_name) % 10000)
        null_totals = []
        for _ in range(N_PERM):
            perm_idx = rng.permutation(n)
            diff_perm = [d[perm_idx] for d in diff]
            null_total = 0.0
            for i in range(32):
                best = 0
                xb = ((words_R[src_word] >> i) & 1).astype(np.uint8)
                for j in range(32):
                    dyb = ((diff_perm[tgt_word] >> j) & 1).astype(np.uint8)
                    best = max(best, mi_2x2(xb, dyb, n))
                null_total += best
            null_totals.append(null_total)

        null_mean = np.mean(null_totals)
        null_std = max(np.std(null_totals), 1e-30)
        z = (mi_full - null_mean) / null_std

        results[add_name] = {'z': z, 'mi_diagonal': mi_total, 'mi_full': mi_full}

    return results


# ==========================================
# MAIN
# ==========================================

print("=" * 80)
print("CHASKEY INFORMED MODE RE-ATTACK")
print("=" * 80)
print(f"N={N}, {SEEDS} seeds\n")

for n_rounds in [1, 2, 3, 4, 5, 6, 8]:
    print(f"\n--- Chaskey R{n_rounds} ---")
    combined = {}
    for s in range(SEEDS):
        seed = s * 1000 + 42
        res = chaskey_informed_mi(n_rounds, seed)
        for name, data in res.items():
            if name not in combined:
                combined[name] = {'zs': [], 'mi_diags': [], 'mi_fulls': []}
            combined[name]['zs'].append(data['z'])
            combined[name]['mi_diags'].append(data['mi_diagonal'])
            combined[name]['mi_fulls'].append(data['mi_full'])

    print(f"  {'Addition':>20}  {'Mean Z':>8}  {'MI diag':>10}  {'MI full':>10}  {'Signal?':>10}")
    print("  " + "-" * 65)
    for name in sorted(combined.keys()):
        d = combined[name]
        mean_z = np.mean(d['zs'])
        mean_diag = np.mean(d['mi_diags'])
        mean_full = np.mean(d['mi_fulls'])
        sig = "YES ***" if mean_z > 3 else ("weak *" if mean_z > 2 else "no")
        print(f"  {name:>20}  {mean_z:>+8.1f}  {mean_diag:.6f}  {mean_full:.6f}  {sig:>10}")

print("\n=== DONE ===")

#!/usr/bin/env python3
"""LEA-128 Informed Mode Re-Attack.

LEA round function:
  t0 = ROL((x[0]^k[0]) + (x[1]^k[1]), 9)   → rotation β=9
  t1 = ROL((x[1]^k[2]) + (x[2]^k[3]), 5)   → rotation β=5
  t2 = ROL((x[2]^k[0]) + (x[3]^k[1]), 3)   → rotation β=3 ← THIS ONE
  x = [t0, t1, t2, x[0]]

The addition with β=3 has MI(3) ≈ 0.011 per pair by the formula.
β=5 and β=9 are above the death threshold → zero MI.

INFORMED TEST:
Between round R and R+1, the EXTRA round produces t2 from x[2](R) and x[3](R).
After the word rotation, x[0](R) goes to x[3](R+1).
So the test: MI between x[2](R) or x[3](R) bits and diff(t2) bits,
where t2 = ROL(x[2]+x[3], 3) at round R+1.

But we don't have intermediate values — only final output.
At the last round: t2 goes to output word 2 (position 2).
The inputs x[2] and x[3] at the last round come from output words at round R.
Word assignment at round R: x = [t0(R), t1(R), t2(R), x0_of_prev_round]
After R rounds: output = [w0, w1, w2, w3].
At round R+1: t2 = ROL((w2^k) + (w3^k), 3), and output = [t0', t1', t2', w0].

So: test MI between output_R[word 2,3] and diff(output)[word 2] (where t2' landed).
The rotation β=3 means we should test bit i of input vs bit (i+3)%32 of diff.
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


def lea128_gen(N_blocks, n_rounds=24, seed=42):
    rng = np.random.default_rng(seed)
    mk = [int(rng.integers(0, 2**32)) for _ in range(4)]
    mask32 = 0xFFFFFFFF
    delta = [0xc3efe9db, 0x44626b02, 0x79e27c8a, 0x78df30ec,
             0x715ea49e, 0xc785da0a, 0xe04ef22a, 0xe7a12214]
    rk = []; T = list(mk)
    for i in range(n_rounds):
        d = delta[i % 4]; rot = i & 0x1f
        d_rot = ((d << rot) | (d >> (32 - rot))) & mask32
        T[0] = ((T[0] + d_rot) & mask32); T[0] = ((T[0] << 1) | (T[0] >> 31)) & mask32
        T[1] = ((T[1] + ((d_rot << 1) | (d_rot >> 31))) & mask32); T[1] = ((T[1] << 3) | (T[1] >> 29)) & mask32
        T[2] = ((T[2] + ((d_rot << 2) | (d_rot >> 30))) & mask32); T[2] = ((T[2] << 6) | (T[2] >> 26)) & mask32
        T[3] = ((T[3] + ((d_rot << 3) | (d_rot >> 29))) & mask32); T[3] = ((T[3] << 11) | (T[3] >> 21)) & mask32
        rk.append(list(T))
    out = bytearray(N_blocks * 16)
    for blk_idx in range(N_blocks):
        x = [(blk_idx >> (32*i)) & mask32 for i in range(4)]
        for r in range(n_rounds):
            k = rk[r]
            t0 = ((((x[0] ^ k[0]) + (x[1] ^ k[1])) & mask32) << 9 | (((x[0] ^ k[0]) + (x[1] ^ k[1])) & mask32) >> 23) & mask32
            t1 = ((((x[1] ^ k[2]) + (x[2] ^ k[3])) & mask32) << 5 | (((x[1] ^ k[2]) + (x[2] ^ k[3])) & mask32) >> 27) & mask32
            t2 = ((((x[2] ^ k[0]) + (x[3] ^ k[1])) & mask32) << 3 | (((x[2] ^ k[0]) + (x[3] ^ k[1])) & mask32) >> 29) & mask32
            x = [t0, t1, t2, x[0]]
        base = blk_idx * 16
        for i in range(4):
            for b in range(4): out[base + i*4 + b] = (x[i] >> (8*(3-b))) & 0xFF
    return bytes(out), 16, 8


def lea_informed_mi(n_rounds, seed=42):
    """MI test on LEA isolating the β=3 addition (t2 = ROL(x[2]+x[3], 3)).

    Between round R and R+1:
    - Output word 2 at R+1 = t2' = ROL(x[2](R+1)_xor_k + x[3](R+1)_xor_k, 3)
    - But x[2](R+1) = t2(R) = output word 2 at R
    - And x[3](R+1) = x[0](R) = output word 3 at R+1... wait.

    Actually: x_new = [t0, t1, t2, x[0]]
    So x[3] at round R+1 = x[0] from round R = output word 0 at round R.

    So t2(R+1) = ROL((output_R[word2] ^ k) + (output_R[word0] ^ k), 3)

    Test MI between:
    - Source: output_R[word 0] and output_R[word 2] (the addition inputs)
    - Target: diff[word 2] (the addition output difference)
    - Shift: β=3, so bit i → bit (i+3)%32

    Also test all three additions for comparison:
    - t0: x[0]+x[1] → ROL(,9): output_R[word0] + output_R[word1] → diff[word0]
    - t1: x[1]+x[2] → ROL(,5): output_R[word1] + output_R[word2] → diff[word1]
    - t2: x[2]+x[3] → ROL(,3): output_R[word2] + output_R[word0] → diff[word2]
      Wait: x[3] = previous x[0], but that's after the WORD rotation.
      At round R, x = [t0(R), t1(R), t2(R), x0(R-1)].
      At round R+1 input: x[0]=out_R[0], x[1]=out_R[1], x[2]=out_R[2], x[3]=out_R[3].
      t2(R+1) uses x[2]=out_R[2] and x[3]=out_R[3].
      Then output_R+1 = [t0', t1', t2', out_R[0]].

    So:
    - Source words for t2: out_R[2] and out_R[3]
    - Target: diff(output)[word 2]  (t2' is at word 2)
    """
    raw_R, bb, _ = lea128_gen(N, n_rounds=n_rounds, seed=seed)
    raw_R1, _, _ = lea128_gen(N, n_rounds=n_rounds + 1, seed=seed)

    d_R = np.frombuffer(raw_R, dtype=np.uint8).reshape(-1, 16)
    d_R1 = np.frombuffer(raw_R1, dtype=np.uint8).reshape(-1, 16)
    n = min(d_R.shape[0], d_R1.shape[0])
    d_R = d_R[:n]; d_R1 = d_R1[:n]

    # Reconstruct 32-bit words (big-endian: bytes 0-3 = word 0, etc.)
    def get_word(data, word_idx):
        base = word_idx * 4
        return (data[:, base].astype(np.uint64) << 24 |
                data[:, base+1].astype(np.uint64) << 16 |
                data[:, base+2].astype(np.uint64) << 8 |
                data[:, base+3].astype(np.uint64))

    # All 4 output words at round R and R+1
    words_R = [get_word(d_R, i) for i in range(4)]
    words_R1 = [get_word(d_R1, i) for i in range(4)]
    diff_words = [words_R[i] ^ words_R1[i] for i in range(4)]

    results = {}

    # Test each addition separately
    additions = [
        # (name, source words, target word, rotation β)
        ("t0: ROL(x0+x1, 9)", [0, 1], 0, 9),
        ("t1: ROL(x1+x2, 5)", [1, 2], 1, 5),
        ("t2: ROL(x2+x3, 3)", [2, 3], 2, 3),
    ]

    for add_name, src_words, tgt_word, beta in additions:
        mi_total = 0.0
        mi_pairs = []

        # For each source word, test bit i → diff bit (i+beta)%32
        for src_w in src_words:
            for i in range(32):
                j = (i + beta) % 32  # β-shifted diagonal
                xb = ((words_R[src_w] >> i) & 1).astype(np.uint8)
                dyb = ((diff_words[tgt_word] >> j) & 1).astype(np.uint8)
                mi = mi_2x2(xb, dyb, n)
                mi_total += mi
                mi_pairs.append(mi)

        # Permutation null
        rng = np.random.default_rng(seed + 999)
        null_totals = []
        for _ in range(N_PERM):
            perm_idx = rng.permutation(n)
            diff_perm = [dw[perm_idx] for dw in diff_words]
            null_total = 0.0
            for src_w in src_words:
                for i in range(32):
                    j = (i + beta) % 32
                    xb = ((words_R[src_w] >> i) & 1).astype(np.uint8)
                    dyb = ((diff_perm[tgt_word] >> j) & 1).astype(np.uint8)
                    null_total += mi_2x2(xb, dyb, n)
            null_totals.append(null_total)

        null_mean = np.mean(null_totals)
        null_std = max(np.std(null_totals), 1e-30)
        z = (mi_total - null_mean) / null_std

        n_active = sum(1 for m in mi_pairs if m > 0.001)
        mean_active = np.mean([m for m in mi_pairs if m > 0.001]) if n_active > 0 else 0

        results[add_name] = {
            'z': z, 'mi_total': mi_total, 'n_active': n_active,
            'mean_active': mean_active, 'beta': beta
        }

    return results


# ==========================================
# MAIN
# ==========================================

print("=" * 80)
print("LEA-128 INFORMED MODE RE-ATTACK")
print("=" * 80)
print(f"N={N}, {SEEDS} seeds, {N_PERM} permutations")
print()

# Test at multiple round counts
for n_rounds in [4, 6, 8, 10, 12, 15, 18, 24]:
    print(f"\n--- LEA-128 R{n_rounds} ---")
    # Average across seeds
    combined = {}
    for s in range(SEEDS):
        seed = s * 1000 + 42
        res = lea_informed_mi(n_rounds, seed)
        for name, data in res.items():
            if name not in combined:
                combined[name] = {'zs': [], 'mi_totals': []}
            combined[name]['zs'].append(data['z'])
            combined[name]['mi_totals'].append(data['mi_total'])

    print(f"  {'Addition':>25}  {'β':>3}  {'Mean Z':>8}  {'Mean MI':>10}  {'Signal?':>10}")
    print("  " + "-" * 65)
    for name in sorted(combined.keys()):
        d = combined[name]
        mean_z = np.mean(d['zs'])
        mean_mi = np.mean(d['mi_totals'])
        sig = "YES ***" if mean_z > 3 else ("weak *" if mean_z > 2 else "no")
        beta = 3 if "3)" in name else (5 if "5)" in name else 9)
        print(f"  {name:>25}  {beta:>3}  {mean_z:>+8.1f}  {mean_mi:.6f}  {sig:>10}")

print("\n=== DONE ===")

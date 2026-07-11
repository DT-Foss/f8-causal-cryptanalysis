#!/usr/bin/env python3
"""HIGHT Informed Mode Re-Attack.

HIGHT round function (simplified):
  x[7] = x[6] ^ (F1(x[5]) + sk)
  x[5] = x[4] + (F0(x[3]) ^ sk)
  x[3] = x[2] ^ (F1(x[1]) + sk)
  x[1] = x[0] + (F0(x[7]) ^ sk)
  Then rotate right by 1: [x[7], x[0], x[1], ..., x[6]]

ADDITIONS at positions: 1 (= x[0]+F0(x[7])) and 5 (= x[4]+F0(x[3]))
XORs at positions: 3 and 7

The byte rotation means: after R rounds, byte at output position p came from
original position (p + R) % 8.

INFORMED TEST: Track addition outputs through the rotation.
For round R, the addition results are at internal positions 1 and 5.
After the final rotation, these map to output positions (1-R)%8 and (5-R)%8.
The addition INPUTS (x[0] and x[4]) came from positions 0 and 4 internally,
which map to output positions (0-R)%8 and (4-R)%8.

So: test MI between output bytes at positions:
  - (0-R)%8 → (1-R)%8  (addition 1: x[0]+F0(x[7]) → result at pos 1)
  - (4-R)%8 → (5-R)%8  (addition 2: x[4]+F0(x[3]) → result at pos 5)
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


def hight_gen(N_blocks, n_rounds=32, seed=42):
    """HIGHT cipher: 8-byte block, 8-bit operations."""
    rng = np.random.default_rng(seed)
    mk = [int(rng.integers(0, 256)) for _ in range(16)]

    wk = [0]*8
    for i in range(4): wk[i] = mk[i+12]
    for i in range(4): wk[i+4] = mk[i]

    # Simplified subkey generation
    sk = [0]*256
    for i in range(256):
        sk[i] = (mk[i % 16] + (i * 7 + 13)) & 0xFF

    F0 = lambda x: (((x << 1) | (x >> 7)) ^ ((x << 2) | (x >> 6)) ^ ((x << 7) | (x >> 1))) & 0xFF
    F1 = lambda x: (((x << 3) | (x >> 5)) ^ ((x << 4) | (x >> 4)) ^ ((x << 6) | (x >> 2))) & 0xFF

    out = bytearray(N_blocks * 8)
    for blk_idx in range(N_blocks):
        x = [(blk_idx >> (8*i)) & 0xFF for i in range(8)]
        x[0] = (x[0] + wk[0]) & 0xFF
        x[2] = x[2] ^ wk[1]
        x[4] = (x[4] + wk[2]) & 0xFF
        x[6] = x[6] ^ wk[3]
        for r in range(n_rounds):
            tmp = x[7]
            x[7] = (x[6] ^ ((F1(x[5]) + sk[4*r + 3]) & 0xFF)) & 0xFF
            x[6] = x[5]
            x[5] = (x[4] + (F0(x[3]) ^ sk[4*r + 2])) & 0xFF
            x[4] = x[3]
            x[3] = (x[2] ^ ((F1(x[1]) + sk[4*r + 1]) & 0xFF)) & 0xFF
            x[2] = x[1]
            x[1] = (x[0] + (F0(tmp) ^ sk[4*r + 0])) & 0xFF
            x[0] = tmp
        x[0] = (x[0] + wk[4]) & 0xFF
        x[2] = x[2] ^ wk[5]
        x[4] = (x[4] + wk[6]) & 0xFF
        x[6] = x[6] ^ wk[7]
        base = blk_idx * 8
        for i in range(8): out[base + i] = x[i]
    return bytes(out), 8, 4


def hight_informed_mi(n_rounds, seed=42):
    """MI test on HIGHT using informed byte-pair selection.

    After the round function + rotation, addition outputs land at specific positions.
    We test MI between the addition-input byte and the diff of the addition-output byte.

    HIGHT round: addition results at internal positions 1 and 5.
    Byte rotation: right-shift by 1 each round.
    After R rounds: internal pos p → output pos (p - R) % 8.
    Wait, that's the WRONG direction. Let me trace carefully.

    Actually HIGHT's "rotation" is: the assignment x[0]=tmp (old x[7]) at the end.
    This means: x[0]←x[7], x[2]←x[1], x[4]←x[3], x[6]←x[5], and
    x[1],x[3],x[5],x[7] get new computed values.

    So it's NOT a simple rotation — it's a specific permutation:
    Even positions get previous odd-1: x[0]←x[7], x[2]←x[1], x[4]←x[3], x[6]←x[5]
    Odd positions get computed from neighbors.

    For the F8 test, we don't need to track through all rounds. We just need:
    - The OUTPUT at round R and R+1
    - Knowledge of which output bytes are RELATED through the last round's additions

    Between round R and R+1, the LAST round's operations are:
    - Addition at pos 1: x[1]_new = (x[0] + F0(tmp)) ^ sk  (depends on x[0])
    - Addition at pos 5: x[5]_new = (x[4] + F0(x[3])) ^ sk (depends on x[4])

    So: out_R(pos=0,4) → diff(pos=1,5) should have MI.
    Plus the XOR positions: x[3] depends on x[2], x[7] depends on x[6].
    """
    raw_R, bb, _ = hight_gen(N, n_rounds=n_rounds, seed=seed)
    raw_R1, _, _ = hight_gen(N, n_rounds=n_rounds + 1, seed=seed)

    d_R = np.frombuffer(raw_R, dtype=np.uint8).reshape(-1, 8)
    d_R1 = np.frombuffer(raw_R1, dtype=np.uint8).reshape(-1, 8)
    n = min(d_R.shape[0], d_R1.shape[0])
    d_R = d_R[:n]; d_R1 = d_R1[:n]
    diff = d_R ^ d_R1

    # Informed pairs: addition crossover
    # Between round R and R+1, the extra round's additions couple:
    # x[0](R) → x[1](R+1) via addition
    # x[4](R) → x[5](R+1) via addition
    # x[2](R) → x[3](R+1) via XOR+addition
    # x[6](R) → x[7](R+1) via XOR+addition
    # But also: x[7](R) → x[1](R+1) via F0 (nonlinear)
    # And: x[3](R) → x[5](R+1) via F0 (nonlinear)

    informed_pairs = [
        (0, 1),  # x[0] + F0(x[7]) → x[1]
        (4, 5),  # x[4] + F0(x[3]) → x[5]
        (7, 1),  # F0(x[7]) input to addition → x[1]
        (3, 5),  # F0(x[3]) input to addition → x[5]
        (2, 3),  # x[2] → x[3] via XOR path
        (6, 7),  # x[6] → x[7] via XOR path
        (1, 3),  # F1(x[1]) → x[3] via XOR
        (5, 7),  # F1(x[5]) → x[7] via XOR
    ]

    # Bit-level MI on each informed pair
    mi_total = 0.0
    mi_per_pair = {}
    for (src, dst) in informed_pairs:
        pair_mi = 0.0
        src_byte = d_R[:, src]
        diff_byte = diff[:, dst]
        for bi in range(8):
            for bj in range(8):
                xb = ((src_byte >> bi) & 1).astype(np.uint8)
                dyb = ((diff_byte >> bj) & 1).astype(np.uint8)
                pair_mi += mi_2x2(xb, dyb, n)
        mi_total += pair_mi
        mi_per_pair[(src, dst)] = pair_mi

    # Permutation null
    rng = np.random.default_rng(seed + 999)
    null_totals = []
    for _ in range(N_PERM):
        perm_idx = rng.permutation(n)
        diff_perm = diff[perm_idx]
        null_total = 0.0
        for (src, dst) in informed_pairs:
            src_byte = d_R[:, src]
            diff_byte = diff_perm[:, dst]
            for bi in range(8):
                for bj in range(8):
                    xb = ((src_byte >> bi) & 1).astype(np.uint8)
                    dyb = ((diff_byte >> bj) & 1).astype(np.uint8)
                    null_total += mi_2x2(xb, dyb, n)
        null_totals.append(null_total)

    null_mean = np.mean(null_totals)
    null_std = max(np.std(null_totals), 1e-30)
    z = (mi_total - null_mean) / null_std

    return z, mi_per_pair, mi_total


def hight_blackbox_mi(n_rounds, seed=42):
    """Black-box MI (all pairs) for comparison."""
    raw_R, bb, _ = hight_gen(N, n_rounds=n_rounds, seed=seed)
    raw_R1, _, _ = hight_gen(N, n_rounds=n_rounds + 1, seed=seed)

    d_R = np.frombuffer(raw_R, dtype=np.uint8).reshape(-1, 8)
    d_R1 = np.frombuffer(raw_R1, dtype=np.uint8).reshape(-1, 8)
    n = min(d_R.shape[0], d_R1.shape[0])
    d_R = d_R[:n]; d_R1 = d_R1[:n]
    diff = d_R ^ d_R1

    mi_total = 0.0
    for src in range(8):
        for dst in range(8):
            src_byte = d_R[:, src]
            diff_byte = diff[:, dst]
            for bi in range(8):
                for bj in range(8):
                    xb = ((src_byte >> bi) & 1).astype(np.uint8)
                    dyb = ((diff_byte >> bj) & 1).astype(np.uint8)
                    mi_total += mi_2x2(xb, dyb, n)

    rng = np.random.default_rng(seed + 999)
    null_totals = []
    for _ in range(N_PERM):
        perm_idx = rng.permutation(n)
        diff_perm = diff[perm_idx]
        null_total = 0.0
        for src in range(8):
            for dst in range(8):
                src_byte = d_R[:, src]
                diff_byte = diff_perm[:, dst]
                for bi in range(8):
                    for bj in range(8):
                        xb = ((src_byte >> bi) & 1).astype(np.uint8)
                        dyb = ((diff_byte >> bj) & 1).astype(np.uint8)
                        null_total += mi_2x2(xb, dyb, n)
        null_totals.append(null_total)

    null_mean = np.mean(null_totals)
    null_std = max(np.std(null_totals), 1e-30)
    z = (mi_total - null_mean) / null_std
    return z


# ==========================================
# MAIN
# ==========================================

print("=" * 70)
print("HIGHT INFORMED MODE RE-ATTACK")
print("=" * 70)
print(f"N={N}, {SEEDS} seeds, {N_PERM} permutations\n")

# Round sweep: informed vs black-box
print(f"{'Rounds':>7}  {'Informed Z':>11}  {'BB Z':>7}  {'Signal?':>10}  {'Best pair':>20}")
print("-" * 65)
for n_rounds in [4, 6, 8, 10, 12, 15, 18, 20, 24, 28, 32]:
    zs_inf = []
    zs_bb = []
    best_pairs = {}
    for s in range(SEEDS):
        seed = s * 1000 + 42
        z_inf, mi_pairs, _ = hight_informed_mi(n_rounds, seed)
        zs_inf.append(z_inf)
        # Track best pair across seeds
        for k, v in mi_pairs.items():
            best_pairs[k] = best_pairs.get(k, 0) + v / SEEDS

    # Only do black-box for a couple rounds (very slow at 64×64 bit pairs)
    if n_rounds in [10, 15, 20, 32]:
        z_bb = hight_blackbox_mi(n_rounds, seed=42)
        bb_str = f"{z_bb:>+7.1f}"
    else:
        bb_str = "    ---"

    mean_inf = np.mean(zs_inf)
    sig = "YES ***" if mean_inf > 3 else ("weak *" if mean_inf > 2 else "no")
    best = max(best_pairs, key=best_pairs.get)
    print(f"{n_rounds:>7}  {mean_inf:>+11.1f}  {bb_str}  {sig:>10}  {best} MI={best_pairs[best]:.4f}")

# Detailed per-pair analysis at R15 (where black-box died)
print(f"\n\n--- Per-pair MI at R15 (seed=42) ---")
z, mi_pairs, total = hight_informed_mi(15, seed=42)
print(f"Total MI = {total:.6f}, Z = {z:+.1f}\n")
print(f"{'Pair (src→dst)':>20}  {'MI':>10}  {'MI%':>6}")
print("-" * 40)
for pair in sorted(mi_pairs, key=mi_pairs.get, reverse=True):
    pct = mi_pairs[pair] / total * 100 if total > 0 else 0
    print(f"  {pair[0]}→{pair[1]:>10}  {mi_pairs[pair]:.6f}  {pct:.1f}%")

print("\n=== DONE ===")

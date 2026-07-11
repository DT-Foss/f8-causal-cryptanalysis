#!/usr/bin/env python3
"""Threefish-256 Mechanism Investigation.

THE PARADOX: All rotation constants R_d >= 5 (above β_max=4), yet
sig_rate ≈ 6.5% persists through all 72 rounds.

HYPOTHESIS: The signal is NOT from the Speck-type β-masking leak.
Possible mechanisms:
1. Long carry-chain at WS=64: lower-order bits accumulate correlations
   that large rotations cannot eliminate
2. MIX topology: x1 enters BOTH as addend AND as XOR source (e0=x0+x1, e1=ROL(x1,R)^e0)
3. Word permutation is too simple (whole-word moves, no bit mixing)

THIS TEST:
Part 1: Full MI heatmap (which bit-pairs carry signal?)
Part 2: Round progression (R=1..72, does signal decay?)
Part 3: R_d ablation (fix all rotations to same value, compare)
Part 4: Word-pair specificity (which of the 4 word interactions carries signal?)
"""
import sys, os; sys.path.insert(0, os.path.dirname(__file__))
from speck_utils import *

N = 30000   # Reduced for speed (64-bit words = 64×64 = 4096 bit pairs)
SEEDS = 3
N_PERM = 15

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


# ---- Threefish-256 rotation constants ----
# 4 words, 2 MIX operations per subround, 8 rounds per full round
# Full specification: 72 rounds, key injection every 4 rounds
TF256_ROTATIONS = [
    [14, 16],  # d=0: MIX(0,1) and MIX(2,3)
    [52, 57],  # d=1
    [23, 40],  # d=2
    [5,  37],  # d=3
    [25, 33],  # d=4
    [46, 12],  # d=5
    [58, 22],  # d=6
    [32, 32],  # d=7
]

# Word permutation after MIX: [0,1,2,3] → [0,3,2,1]
# Actually for Threefish-256 (Nw=4), the permutation is trivial:
# After MIX(0,1) and MIX(2,3): swap words 1 and 3
# i.e., [v0, v1, v2, v3] → [v0, v3, v2, v1]
TF256_PERM = [0, 3, 2, 1]


def threefish256_gen_words(N_blocks, n_rounds=72, seed=42, custom_rotations=None):
    """Threefish-256 CTR-mode. Returns 4 arrays of 64-bit words.

    Threefish-256:
    - 4 words of 64 bits each (256-bit block)
    - Key = 4 words + parity word (t[4] = t[0]^t[1]^t[2]^t[3])
    - Tweak = 2 words + parity (tw[2] = tw[0]^tw[1])
    - Key injection every 4 rounds: v[i] += ks[(s+i) mod 5], plus tweak on v[1],v[2]
    - MIX: e0 = x0 + x1; e1 = ROL(x1, R_d) ^ e0
    - Word permutation after MIX
    """
    rng = np.random.default_rng(seed)
    mask64 = (1 << 64) - 1

    # Key schedule
    C240 = 0x1BD11BDAA9FC1A22  # Skein constant
    ks = [int(rng.integers(0, 2**63)) * 2 + int(rng.integers(0, 2)) for _ in range(4)]
    ks.append(C240)
    for i in range(4):
        ks[4] ^= ks[i]

    # Tweak
    tw = [int(rng.integers(0, 2**63)) * 2 + int(rng.integers(0, 2)) for _ in range(2)]
    tw.append(tw[0] ^ tw[1])

    rotations = custom_rotations if custom_rotations else TF256_ROTATIONS

    w0 = np.zeros(N_blocks, dtype=np.uint64)
    w1 = np.zeros(N_blocks, dtype=np.uint64)
    w2 = np.zeros(N_blocks, dtype=np.uint64)
    w3 = np.zeros(N_blocks, dtype=np.uint64)

    for blk_idx in range(N_blocks):
        # Counter mode: block index as plaintext
        v = [
            blk_idx & mask64,
            (blk_idx >> 64) & mask64,
            (blk_idx >> 128) & mask64,
            (blk_idx >> 192) & mask64,
        ]

        # Initial key injection (s=0)
        v[0] = (v[0] + ks[0]) & mask64
        v[1] = (v[1] + ks[1] + tw[0]) & mask64
        v[2] = (v[2] + ks[2] + tw[1]) & mask64
        v[3] = (v[3] + ks[3]) & mask64

        for r in range(n_rounds):
            d = r % 8
            rot = rotations[d]

            # MIX(0,1): e0 = v0+v1, e1 = ROL(v1,rot[0])^e0
            v[0] = (v[0] + v[1]) & mask64
            v[1] = ((v[1] << rot[0]) | (v[1] >> (64 - rot[0]))) & mask64
            v[1] ^= v[0]

            # MIX(2,3): e0 = v2+v3, e1 = ROL(v3,rot[1])^e0
            v[2] = (v[2] + v[3]) & mask64
            v[3] = ((v[3] << rot[1]) | (v[3] >> (64 - rot[1]))) & mask64
            v[3] ^= v[2]

            # Word permutation: [0,3,2,1]
            v[1], v[3] = v[3], v[1]

            # Key injection every 4 rounds (after rounds 3, 7, 11, ...)
            if (r + 1) % 4 == 0:
                s = (r + 1) // 4
                v[0] = (v[0] + ks[s % 5]) & mask64
                v[1] = (v[1] + ks[(s + 1) % 5] + tw[s % 3]) & mask64
                v[2] = (v[2] + ks[(s + 2) % 5] + tw[(s + 1) % 3]) & mask64
                v[3] = (v[3] + ks[(s + 3) % 5] + s) & mask64

        w0[blk_idx] = v[0]; w1[blk_idx] = v[1]
        w2[blk_idx] = v[2]; w3[blk_idx] = v[3]

    return w0, w1, w2, w3


def word_pair_mi(words_R, words_R1, src_word, tgt_word, n_src_bits=16, n_tgt_bits=16):
    """Test MI between top n_src_bits of src_word at R and diff of tgt_word.
    Uses full scan (best per source bit) with permutation null.
    Only test a subset of bits for speed.
    """
    n = len(words_R[0])
    diff = [words_R[i] ^ words_R1[i] for i in range(4)]

    # Test evenly spaced bits across the 64-bit word
    src_bits = list(range(0, 64, max(1, 64 // n_src_bits)))[:n_src_bits]
    tgt_bits = list(range(0, 64, max(1, 64 // n_tgt_bits)))[:n_tgt_bits]

    mi_full = 0.0
    for i in src_bits:
        best = 0
        xb = ((words_R[src_word] >> i) & 1).astype(np.uint8)
        for j in tgt_bits:
            dyb = ((diff[tgt_word] >> j) & 1).astype(np.uint8)
            best = max(best, mi_2x2(xb, dyb, n))
        mi_full += best

    # Permutation null
    rng = np.random.default_rng(42 + src_word * 10 + tgt_word)
    null_totals = []
    for _ in range(N_PERM):
        perm_idx = rng.permutation(n)
        diff_perm = [d[perm_idx] for d in diff]
        null_total = 0.0
        for i in src_bits:
            best = 0
            xb = ((words_R[src_word] >> i) & 1).astype(np.uint8)
            for j in tgt_bits:
                dyb = ((diff_perm[tgt_word] >> j) & 1).astype(np.uint8)
                best = max(best, mi_2x2(xb, dyb, n))
            null_total += best
        null_totals.append(null_total)

    null_mean = np.mean(null_totals)
    null_std = max(np.std(null_totals), 1e-30)
    z = (mi_full - null_mean) / null_std

    return z, mi_full


# ==========================================
# MAIN
# ==========================================

print("=" * 80)
print("THREEFISH-256 MECHANISM INVESTIGATION")
print("=" * 80)
print(f"N={N}, {SEEDS} seeds, {N_PERM} permutations")
print()

# ---- PART 1: Round progression ----
print("=" * 80)
print("PART 1: ROUND PROGRESSION — MI signal per round count")
print("=" * 80)
print()
print("Testing all 4×4=16 word pairs at each round count.")
print("Using 16 evenly-spaced bits per word (16×16 = 256 pairs per word-pair).")
print()

for n_rounds in [1, 2, 4, 8, 16, 32, 48, 64, 72]:
    print(f"\n--- R{n_rounds} ---")
    print(f"  {'Pair':>10}  {'Mean Z':>8}  {'MI':>10}  {'Signal?':>10}")
    print("  " + "-" * 50)

    best_z_this_round = -999
    best_pair = ""

    for sw in range(4):
        for tw in range(4):
            zs = []; mis = []
            for s in range(SEEDS):
                seed = s * 1000 + 42
                wr = threefish256_gen_words(N, n_rounds=n_rounds, seed=seed)
                wr1 = threefish256_gen_words(N, n_rounds=n_rounds+1, seed=seed)
                z, mi = word_pair_mi(wr, wr1, sw, tw)
                zs.append(z); mis.append(mi)

            mean_z = np.mean(zs)
            mean_mi = np.mean(mis)
            sig = "YES ***" if mean_z > 3 else ("weak *" if mean_z > 2 else "no")

            if mean_z > 2:  # Only print interesting pairs
                print(f"  w{sw}→d{tw}      {mean_z:>+8.1f}  {mean_mi:.6f}  {sig:>10}")

            if mean_z > best_z_this_round:
                best_z_this_round = mean_z
                best_pair = f"w{sw}→d{tw}"

    print(f"  Best: {best_pair} Z={best_z_this_round:+.1f}")


# ---- PART 2: R_d Ablation ----
print()
print("=" * 80)
print("PART 2: ROTATION ABLATION — Fix all R_d to same value")
print("=" * 80)
print()
print("If the signal is β-dependent, fixing R_d to a small value should amplify it")
print("and fixing to a large value should kill it.")
print()

n_rounds_test = 72
print(f"At R{n_rounds_test}, testing best word-pair (determined from Part 1).")
print()

for fixed_rot in [1, 2, 3, 4, 5, 8, 14, 32]:
    custom = [[fixed_rot, fixed_rot]] * 8  # All 8 sub-rounds same rotation
    zs = []; mis = []
    for s in range(SEEDS):
        seed = s * 1000 + 42
        wr = threefish256_gen_words(N, n_rounds=n_rounds_test, seed=seed, custom_rotations=custom)
        wr1 = threefish256_gen_words(N, n_rounds=n_rounds_test+1, seed=seed, custom_rotations=custom)

        # Test all word pairs, take the best
        best_z = -999
        best_mi = 0
        for sw in range(4):
            for tw in range(4):
                z, mi = word_pair_mi(wr, wr1, sw, tw)
                if z > best_z:
                    best_z = z
                    best_mi = mi
        zs.append(best_z)
        mis.append(best_mi)

    mean_z = np.mean(zs)
    mean_mi = np.mean(mis)
    sig = "YES ***" if mean_z > 3 else ("weak *" if mean_z > 2 else "no")
    print(f"  R_d={fixed_rot:>2} (all):  Z={mean_z:>+8.1f}  MI={mean_mi:.6f}  {sig}")


# ---- PART 3: Key injection ablation ----
print()
print("=" * 80)
print("PART 3: KEY INJECTION — With vs Without")
print("=" * 80)
print()

# Test if key injection is the source of the signal
# by comparing n_rounds that end right before vs right after key injection
# Key injection happens after rounds 3, 7, 11, 15, ...
for n_rounds in [3, 4, 7, 8, 71, 72]:
    has_ki = (n_rounds % 4 == 0)
    zs = []
    for s in range(SEEDS):
        seed = s * 1000 + 42
        wr = threefish256_gen_words(N, n_rounds=n_rounds, seed=seed)
        wr1 = threefish256_gen_words(N, n_rounds=n_rounds+1, seed=seed)
        best_z = -999
        for sw in range(4):
            for tw in range(4):
                z, _ = word_pair_mi(wr, wr1, sw, tw)
                if z > best_z: best_z = z
        zs.append(best_z)

    mean_z = np.mean(zs)
    sig = "YES ***" if mean_z > 3 else ("weak *" if mean_z > 2 else "no")
    ki_str = "after KI" if has_ki else "before KI"
    print(f"  R{n_rounds:>2} ({ki_str:>9}):  Z={mean_z:>+8.1f}  {sig}")


# ---- PART 4: Bit position heatmap (for the best word pair at R72) ----
print()
print("=" * 80)
print("PART 4: BIT POSITION HEATMAP — Which bits carry the signal at R72?")
print("=" * 80)
print()
print("Testing all 64 bits of source word vs 64 bits of diff target word.")
print("Picking the word pair with strongest signal from Part 1.")
print()

# Run once to find best pair at R72
seed = 42
wr = threefish256_gen_words(N, n_rounds=72, seed=seed)
wr1 = threefish256_gen_words(N, n_rounds=73, seed=seed)

best_sw, best_tw, best_z_pair = 0, 0, -999
for sw in range(4):
    for tw in range(4):
        z, _ = word_pair_mi(wr, wr1, sw, tw)
        if z > best_z_pair:
            best_z_pair = z
            best_sw, best_tw = sw, tw

print(f"Best pair at R72: w{best_sw}→d{best_tw} (Z={best_z_pair:+.1f})")
print()

# Full 64×64 MI matrix for the best pair
diff = [wr[i] ^ wr1[i] for i in range(4)]
mi_matrix = np.zeros((64, 64))
for i in range(64):
    xb = ((wr[best_sw] >> i) & 1).astype(np.uint8)
    for j in range(64):
        dyb = ((diff[best_tw] >> j) & 1).astype(np.uint8)
        mi_matrix[i, j] = mi_2x2(xb, dyb, N)

# Find the top 20 pairs
flat = mi_matrix.flatten()
top_idx = np.argsort(flat)[-20:][::-1]
print(f"Top 20 MI bit pairs (w{best_sw}[i] → diff_w{best_tw}[j]):")
print(f"  {'Rank':>4}  {'i→j':>8}  {'MI':>10}")
print("  " + "-" * 30)
for rank, idx in enumerate(top_idx):
    i, j = divmod(idx, 64)
    print(f"  {rank+1:>4}  {i:>3}→{j:<3}  {mi_matrix[i,j]:.6f}")

# Summary stats
mean_mi = np.mean(mi_matrix)
max_mi = np.max(mi_matrix)
n_above_001 = np.sum(mi_matrix > 0.001)
n_above_0001 = np.sum(mi_matrix > 0.0001)
print(f"\n  Mean MI: {mean_mi:.6f}")
print(f"  Max MI:  {max_mi:.6f}")
print(f"  Pairs > 0.001: {n_above_001} / 4096")
print(f"  Pairs > 0.0001: {n_above_0001} / 4096")

# Check if signal is concentrated on diagonal (β-pattern) or diffuse
diag_mi = {}
for rot in range(64):
    total = sum(mi_matrix[i, (i + rot) % 64] for i in range(64))
    diag_mi[rot] = total / 64

top_diags = sorted(diag_mi.items(), key=lambda x: -x[1])[:5]
print(f"\n  Top 5 diagonal shifts (average MI):")
for rot, avg in top_diags:
    print(f"    shift={rot:>2}: mean MI={avg:.6f}")


print("\n=== DONE ===")

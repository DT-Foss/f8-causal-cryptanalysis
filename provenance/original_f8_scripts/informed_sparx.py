#!/usr/bin/env python3
"""SPARX De-Linearisierung: Reverse the linear layer to expose ARX-box outputs.

SPARX-64/128 round:
1. ARX-box on branch 0: (x0, y0) → (x0', y0')  [3 Speck rounds, α=7, β=2]
2. ARX-box on branch 1: (x1, y1) → (x1', y1')  [3 Speck rounds, α=7, β=2]
3. Linear layer: (x0', y0', x1', y1') → (x0'^x1', y0'^y1', x0', y0')

The linear layer is: new_branch0 = old_branch0 ^ old_branch1, new_branch1 = old_branch0.
This is an INVOLUTORY Feistel-like swap. Reverse:
  old_branch0 = new_branch1
  old_branch1 = new_branch0 ^ new_branch1

So to get the PRE-linear-layer output (= raw ARX-box output):
  arx_out_0 = (output_branch1_x, output_branch1_y)
  arx_out_1 = (output_branch0_x ^ output_branch1_x, output_branch0_y ^ output_branch1_y)

Test F8 on these de-linearized outputs. The ARX-box IS Speck (α=7, β=2),
so we expect MI ≈ 0.046 per active pair, with β=2 dead bits.
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


def sparx64_gen_words(N_blocks, n_rounds=8, seed=42):
    """SPARX-64/128: returns raw output AND de-linearized output as 16-bit words."""
    rng = np.random.default_rng(seed)
    mk = [int(rng.integers(0, 2**16)) for _ in range(8)]
    mask16 = 0xFFFF

    rk = []; K = list(mk)
    for r in range(n_rounds):
        rk.append(list(K[:4]))
        K.append((K[0] + K[7]) & mask16)
        K = K[1:]

    def arx_box(x, y, k0, k1):
        for _ in range(3):
            x = ((x >> 7) | (x << 9)) & mask16
            x = (x + y) & mask16; x ^= k0
            y = ((y << 2) | (y >> 14)) & mask16; y ^= x
        return x, y

    # Arrays for all blocks
    out_x0 = np.zeros(N_blocks, dtype=np.uint16)
    out_y0 = np.zeros(N_blocks, dtype=np.uint16)
    out_x1 = np.zeros(N_blocks, dtype=np.uint16)
    out_y1 = np.zeros(N_blocks, dtype=np.uint16)
    # De-linearized (pre-linear-layer)
    delinear_x0 = np.zeros(N_blocks, dtype=np.uint16)
    delinear_y0 = np.zeros(N_blocks, dtype=np.uint16)
    delinear_x1 = np.zeros(N_blocks, dtype=np.uint16)
    delinear_y1 = np.zeros(N_blocks, dtype=np.uint16)

    for blk_idx in range(N_blocks):
        x0 = (blk_idx >> 48) & mask16; y0 = (blk_idx >> 32) & mask16
        x1 = (blk_idx >> 16) & mask16; y1 = blk_idx & mask16
        for r in range(n_rounds):
            k = rk[r]
            x0, y0 = arx_box(x0, y0, k[0], k[1])
            x1, y1 = arx_box(x1, y1, k[2], k[3])
            # Linear layer
            tmp_x = x0 ^ x1; tmp_y = y0 ^ y1
            x0, y0, x1, y1 = tmp_x, tmp_y, x0, y0

        out_x0[blk_idx] = x0; out_y0[blk_idx] = y0
        out_x1[blk_idx] = x1; out_y1[blk_idx] = y1

        # Reverse linear layer: old_branch0 = new_branch1, old_branch1 = new0 ^ new1
        delinear_x0[blk_idx] = x1       # branch 0 = new_branch1
        delinear_y0[blk_idx] = y1
        delinear_x1[blk_idx] = x0 ^ x1  # branch 1 = new0 ^ new1
        delinear_y1[blk_idx] = y0 ^ y1

    return (out_x0, out_y0, out_x1, out_y1,
            delinear_x0, delinear_y0, delinear_x1, delinear_y1)


def test_mi_on_halfwords(x_R, y_R, y_R1, ws, alpha, beta, n, label):
    """Test MI between x bits and diff_y bits with known α, β."""
    diff_y = x_R_dummy = None  # Not used
    diff_y = y_R.astype(np.uint64) ^ y_R1.astype(np.uint64)
    x = x_R.astype(np.uint64)

    mi_values = []
    dead_set = {(alpha + d) % ws for d in range(beta)}
    for i in range(ws):
        if i in dead_set:
            continue
        j = (i - alpha) % ws
        xb = ((x >> i) & 1).astype(np.uint8)
        dyb = ((diff_y >> j) & 1).astype(np.uint8)
        mi_values.append(mi_2x2(xb, dyb, n))

    mi_total = sum(mi_values)

    # Permutation null
    rng = np.random.default_rng(42 + hash(label) % 10000)
    null_totals = []
    for _ in range(N_PERM):
        perm_idx = rng.permutation(n)
        diff_y_perm = diff_y[perm_idx]
        null_mi = []
        for i in range(ws):
            if i in dead_set:
                continue
            j = (i - alpha) % ws
            xb = ((x >> i) & 1).astype(np.uint8)
            dyb = ((diff_y_perm >> j) & 1).astype(np.uint8)
            null_mi.append(mi_2x2(xb, dyb, n))
        null_totals.append(sum(null_mi))

    null_mean = np.mean(null_totals)
    null_std = max(np.std(null_totals), 1e-30)
    z = (mi_total - null_mean) / null_std

    n_active = sum(1 for m in mi_values if m > 0.001)
    mean_active = np.mean([m for m in mi_values if m > 0.001]) if n_active > 0 else 0

    return z, mi_total, n_active, mean_active


# ==========================================
# MAIN
# ==========================================

print("=" * 80)
print("SPARX-64/128 DE-LINEARISIERUNG")
print("=" * 80)
print(f"N={N}, {SEEDS} seeds, Speck ARX-box: α=7, β=2\n")

# Test at each round count
for n_rounds in [1, 2, 3, 4, 5, 6, 8]:
    print(f"\n--- SPARX R{n_rounds} ---")
    print(f"  {'Mode':>20}  {'Branch':>8}  {'Mean Z':>8}  {'MI total':>10}  {'Active':>8}  {'MI/pair':>10}  {'Signal?':>10}")
    print("  " + "-" * 85)

    for mode in ['raw', 'delinearized']:
        for branch in [0, 1]:
            zs = []; mi_tots = []; n_acts = []; mi_pers = []
            for s in range(SEEDS):
                seed = s * 1000 + 42
                data_R = sparx64_gen_words(N, n_rounds=n_rounds, seed=seed)
                data_R1 = sparx64_gen_words(N, n_rounds=n_rounds + 1, seed=seed)

                if mode == 'raw':
                    x_R = data_R[2*branch]        # x word of branch
                    y_R = data_R[2*branch + 1]     # y word of branch
                    y_R1 = data_R1[2*branch + 1]
                else:
                    x_R = data_R[4 + 2*branch]     # de-linearized x
                    y_R = data_R[4 + 2*branch + 1]
                    y_R1 = data_R1[4 + 2*branch + 1]

                n_act = min(len(x_R), len(y_R))
                z, mi_t, n_a, mi_p = test_mi_on_halfwords(
                    x_R[:n_act], y_R[:n_act], y_R1[:n_act],
                    16, 7, 2, n_act, f"{mode}_{branch}_{n_rounds}_{seed}")
                zs.append(z); mi_tots.append(mi_t); n_acts.append(n_a); mi_pers.append(mi_p)

            mean_z = np.mean(zs)
            mean_mi = np.mean(mi_tots)
            mean_act = np.mean(n_acts)
            mean_per = np.mean(mi_pers)
            sig = "YES ***" if mean_z > 3 else ("weak *" if mean_z > 2 else "no")
            print(f"  {mode:>20}  B{branch:>6}  {mean_z:>+8.1f}  {mean_mi:.6f}  {mean_act:>7.1f}  {mean_per:.6f}  {sig:>10}")

# Reference: pure Speck 32/64 (same ARX-box)
print(f"\n\n--- Reference: Pure Speck 32/64 ---")
for s in range(SEEDS):
    seed = s * 1000 + 42
    raw_R, bb, bpw = speck32(N, n_rounds=15, seed=seed)
    raw_R1, _, _ = speck32(N, n_rounds=16, seed=seed)
    d_R = np.frombuffer(raw_R, dtype=np.uint8).reshape(-1, 4)
    d_R1 = np.frombuffer(raw_R1, dtype=np.uint8).reshape(-1, 4)
    x_R = (d_R[:, 0].astype(np.uint16) << 8) | d_R[:, 1].astype(np.uint16)
    y_R = (d_R[:, 2].astype(np.uint16) << 8) | d_R[:, 3].astype(np.uint16)
    y_R1 = (d_R1[:, 2].astype(np.uint16) << 8) | d_R1[:, 3].astype(np.uint16)
    z, mi_t, n_a, mi_p = test_mi_on_halfwords(x_R, y_R, y_R1, 16, 7, 2, N, "speck_ref")
    if s == 0:
        print(f"  Speck 32/64 R15: Z={z:+.1f}, MI_total={mi_t:.6f}, Active={n_a}, MI/pair={mi_p:.6f}")

print("\n=== DONE ===")

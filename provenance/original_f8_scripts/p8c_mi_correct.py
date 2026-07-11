#!/usr/bin/env python3
"""P8c: Corrected MI re-attack with proper null calibration.
Uses max-MI-per-bit approach (independent test statistics) with
permutation-based null subtraction.
"""
import sys, os; sys.path.insert(0, os.path.dirname(__file__))
from speck_utils import *

N = 50000
SEEDS = 5

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

def mi_test_corrected(gen_fn, n_rounds, ws, n_perm=5):
    """MI test with permutation-based null subtraction.

    For each seed:
    1. Compute total MI = sum over all (i,j) pairs of MI(x_bit_i, diff_y_bit_j)
    2. Compute null MI by permuting diff_y (breaking any real correlation)
    3. Z = (MI_real - MI_null_mean) / MI_null_std

    Average Z across seeds for stability.
    """
    zs_per_seed = []

    for s_idx in range(SEEDS):
        seed = s_idx * 1000 + 42
        raw_R = gen_fn(N, n_rounds=n_rounds, seed=seed)
        raw_R1 = gen_fn(N, n_rounds=n_rounds + 1, seed=seed)
        if isinstance(raw_R, tuple):
            raw_R, bb, bpw = raw_R
            raw_R1 = raw_R1[0]
        else:
            bb = len(raw_R) // N
            bpw = bb // 2

        d_R = np.frombuffer(raw_R, dtype=np.uint8).reshape(-1, bb)
        d_R1 = np.frombuffer(raw_R1, dtype=np.uint8).reshape(-1, bb)
        n_act = min(d_R.shape[0], d_R1.shape[0])
        d_R = d_R[:n_act]; d_R1 = d_R1[:n_act]

        x_R = np.zeros(n_act, dtype=np.uint64)
        y_R = np.zeros(n_act, dtype=np.uint64)
        y_R1 = np.zeros(n_act, dtype=np.uint64)
        for b in range(bpw):
            sh = 8*(bpw-1-b)
            x_R |= d_R[:,b].astype(np.uint64) << sh
            y_R |= d_R[:,bpw+b].astype(np.uint64) << sh
            y_R1 |= d_R1[:,bpw+b].astype(np.uint64) << sh

        diff_y = y_R ^ y_R1

        # Compute total MI (sum of all pairs)
        total_mi = 0.0
        for i in range(ws):
            xb = ((x_R >> i) & 1).astype(np.uint8)
            for j in range(ws):
                dyb = ((diff_y >> j) & 1).astype(np.uint8)
                total_mi += mi_2x2(xb, dyb, n_act)

        # Permutation null: shuffle diff_y, recompute total MI
        rng = np.random.default_rng(seed + 999)
        null_mis = []
        for p_idx in range(n_perm):
            perm_idx = rng.permutation(n_act)
            diff_y_perm = diff_y[perm_idx]
            null_total = 0.0
            for i in range(ws):
                xb = ((x_R >> i) & 1).astype(np.uint8)
                for j in range(ws):
                    dyb = ((diff_y_perm >> j) & 1).astype(np.uint8)
                    null_total += mi_2x2(xb, dyb, n_act)
            null_mis.append(null_total)

        null_mean = np.mean(null_mis)
        null_std = np.std(null_mis) if len(null_mis) > 1 else 0.001

        excess_mi = total_mi - null_mean
        z = excess_mi / null_std if null_std > 0 else 0
        zs_per_seed.append(z)

    return np.mean(zs_per_seed), np.std(zs_per_seed), zs_per_seed


# ---- Cipher generators ----

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

def chaskey_gen(N_blocks, n_rounds=8, seed=42):
    rng = np.random.default_rng(seed)
    mk = [int(rng.integers(0, 2**32)) for _ in range(4)]
    mask32 = 0xFFFFFFFF
    out = bytearray(N_blocks * 16)
    for blk_idx in range(N_blocks):
        v = [(blk_idx >> (32*i)) & mask32 for i in range(4)]
        for i in range(4): v[i] = (v[i] ^ mk[i])
        for r in range(n_rounds):
            v[0] = (v[0] + v[1]) & mask32; v[2] = (v[2] + v[3]) & mask32
            v[1] = ((v[1] << 5) | (v[1] >> 27)) & mask32; v[3] = ((v[3] << 8) | (v[3] >> 24)) & mask32
            v[1] ^= v[0]; v[3] ^= v[2]
            v[0] = ((v[0] << 16) | (v[0] >> 16)) & mask32
            v[0] = (v[0] + v[3]) & mask32; v[2] = (v[2] + v[1]) & mask32
            v[1] = ((v[1] << 7) | (v[1] >> 25)) & mask32; v[3] = ((v[3] << 13) | (v[3] >> 19)) & mask32
            v[1] ^= v[2]; v[3] ^= v[0]
            v[2] = ((v[2] << 16) | (v[2] >> 16)) & mask32
        for i in range(4): v[i] = (v[i] ^ mk[i])
        base = blk_idx * 16
        for i in range(4):
            for b in range(4): out[base + i*4 + b] = (v[i] >> (8*(3-b))) & 0xFF
    return bytes(out), 16, 8

def sparx64_gen(N_blocks, n_rounds=8, seed=42):
    rng = np.random.default_rng(seed)
    mk = [int(rng.integers(0, 2**16)) for _ in range(8)]
    mask16 = 0xFFFF
    rk = []; K = list(mk)
    for r in range(n_rounds):
        rk.append(list(K[:4])); K.append((K[0] + K[7]) & mask16); K = K[1:]
    def arx_box(x, y, k0, k1):
        for _ in range(3):
            x = ((x >> 7) | (x << 9)) & mask16; x = (x + y) & mask16; x ^= k0
            y = ((y << 2) | (y >> 14)) & mask16; y ^= x
        return x, y
    out = bytearray(N_blocks * 8)
    for blk_idx in range(N_blocks):
        x0 = (blk_idx >> 48) & mask16; y0 = (blk_idx >> 32) & mask16
        x1 = (blk_idx >> 16) & mask16; y1 = blk_idx & mask16
        for r in range(n_rounds):
            k = rk[r]
            x0, y0 = arx_box(x0, y0, k[0], k[1]); x1, y1 = arx_box(x1, y1, k[2], k[3])
            tmp_x = x0 ^ x1; tmp_y = y0 ^ y1; x0, y0, x1, y1 = tmp_x, tmp_y, x0, y0
        base = blk_idx * 8
        out[base] = (x0 >> 8) & 0xFF; out[base+1] = x0 & 0xFF
        out[base+2] = (y0 >> 8) & 0xFF; out[base+3] = y0 & 0xFF
        out[base+4] = (x1 >> 8) & 0xFF; out[base+5] = x1 & 0xFF
        out[base+6] = (y1 >> 8) & 0xFF; out[base+7] = y1 & 0xFF
    return bytes(out), 8, 4


# ==========================================
# MAIN
# ==========================================
print("=" * 80)
print("P8c: CORRECTED MI RE-ATTACK (permutation null)")
print("=" * 80)
print(f"N={N}, {SEEDS} seeds, 5 permutations each")
print()

# First: validate with known positives and null
print("--- Speck 32/64 (positive control, WS=16) ---")
def wrap_speck32(N_blocks, n_rounds=22, seed=42):
    return speck_gen(N_blocks, 16, 4, 7, 2, n_rounds, seed)

mean_z, std_z, zs = mi_test_corrected(wrap_speck32, 15, 16)
print(f"  Z = {mean_z:+.1f} ± {std_z:.1f}  (seeds: {[f'{z:+.1f}' for z in zs]})")
print(f"  EXPECTED: strong positive")

print()
print("--- Now the critical tests ---")
print()

tests = [
    ("LEA-128 R24 (full)", lea128_gen, 24, 32),
    ("LEA-128 R12", lea128_gen, 12, 32),
    ("LEA-128 R6", lea128_gen, 6, 32),
    ("Chaskey R8 (full)", chaskey_gen, 8, 32),
    ("Chaskey R4", chaskey_gen, 4, 32),
    ("Chaskey R2", chaskey_gen, 2, 32),
    ("SPARX-64 R8 (full)", sparx64_gen, 8, 16),
    ("SPARX-64 R4", sparx64_gen, 4, 16),
    ("SPARX-64 R2", sparx64_gen, 2, 16),
]

print(f"{'Test':>25}  {'Mean Z':>8}  {'Std':>6}  {'Signal?':>10}  {'Seeds':>40}")
print("-" * 100)
for label, gen_fn, n_rounds, ws in tests:
    mean_z, std_z, zs = mi_test_corrected(gen_fn, n_rounds, ws)
    sig = "YES ***" if mean_z > 3 else ("weak *" if mean_z > 2 else "no")
    seeds_str = str([f'{z:+.1f}' for z in zs])
    print(f"{label:>25}  {mean_z:>+8.1f}  {std_z:>5.1f}  {sig:>10}  {seeds_str}")

print("\n" + "=" * 80)
print("DONE")

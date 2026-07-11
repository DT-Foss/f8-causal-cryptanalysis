#!/usr/bin/env python3
"""P8: MI re-attack on "negative" ciphers from Phase 3.
HIGHT, LEA, Chaskey, SPARX — all showed no signal with chi2 at full rounds.
MI is 3-6× more sensitive. Does the picture change?
"""
import sys, os; sys.path.insert(0, os.path.dirname(__file__))
from speck_utils import *

N = 50000  # Maximum sensitivity

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

def mi_cross_round_z(gen_fn, n_rounds, ws, seed=42):
    """Compute MI-based Z-score for any cipher.
    Black-box: test ALL ws×ws bit pairs between x-half and diff_y-half.
    """
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

    # Reconstruct half-words
    x_R = np.zeros(n_act, dtype=np.uint64)
    y_R = np.zeros(n_act, dtype=np.uint64)
    y_R1 = np.zeros(n_act, dtype=np.uint64)
    for b in range(bpw):
        sh = 8*(bpw-1-b)
        x_R |= d_R[:,b].astype(np.uint64) << sh
        y_R |= d_R[:,bpw+b].astype(np.uint64) << sh
        y_R1 |= d_R1[:,bpw+b].astype(np.uint64) << sh

    diff_y = y_R ^ y_R1

    # Full MI matrix: all x-bit → diff_y-bit pairs
    mi_values = []
    for i in range(ws):
        for j in range(ws):
            xb = ((x_R >> i) & 1).astype(np.uint8)
            dyb = ((diff_y >> j) & 1).astype(np.uint8)
            mi_values.append(mi_2x2(xb, dyb, n_act))

    k = len(mi_values)
    total_stat = sum(2.0 * n_act * mi for mi in mi_values)
    z = (total_stat - k) / math.sqrt(2.0 * k)
    return z, mi_values

def chi2_cross_round_z(gen_fn, n_rounds, ws, seed=42, shift=5):
    """Chi2-based Z-score (original F8 method) for comparison."""
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

    diff = d_R[:n_act] ^ d_R1[:n_act]
    out_q = d_R[:n_act] >> shift
    diff_q = diff >> shift
    n_bins = 2 ** (8 - shift)

    n_sig = 0; n_total = 0
    for i in range(bpw):
        for j in range(bpw, bb):
            table = np.zeros((n_bins, n_bins), dtype=float)
            np.add.at(table, (out_q[:, i], diff_q[:, j]), 1)
            rs = table.sum(axis=1, keepdims=True)
            cs = table.sum(axis=0, keepdims=True)
            exp = rs * cs / n_act
            valid = exp > 5
            if np.sum(valid) < n_bins:
                continue
            chi2 = float(np.sum((table[valid] - exp[valid]) ** 2 / exp[valid]))
            dof = (n_bins - 1) ** 2
            p = float(stats.chi2.sf(chi2, dof))
            n_total += 1
            if p < 0.05: n_sig += 1

    sig_rate = n_sig / max(n_total, 1)
    t_stat = (sig_rate - 0.05) / math.sqrt(0.05 * 0.95 / max(n_total, 1))
    return sig_rate, t_stat


# ==========================================
# HIGHT
# ==========================================
def hight_gen(N_blocks, n_rounds=32, seed=42):
    """HIGHT cipher: 8-bit block operations, 64-bit block."""
    rng = np.random.default_rng(seed)
    mk = [int(rng.integers(0, 256)) for _ in range(16)]

    # Whitening key generation
    wk = [0]*8
    for i in range(4):
        wk[i] = mk[i+12]
    for i in range(4):
        wk[i+4] = mk[i]

    # Subkey generation
    delta = [0]*128
    for i in range(128):
        s = 0
        for j in range(8):
            s = (s << 1) | ((((i*7+j) & 0x3f) >> 5) ^ (((i*7+j) & 0x3f) >> 4) ^
                            (((i*7+j) & 0x3f) >> 3) ^ (((i*7+j) & 0x3f) >> 2) ^
                            (((i*7+j) & 0x3f) >> 1) ^ ((i*7+j) & 0x3f)) & 1
        delta[i] = s & 0x7f

    sk = [0]*128
    for i in range(8):
        for j in range(8):
            sk[16*i + j] = (mk[(j - i) % 8] + delta[16*i + j]) & 0xFF
        for j in range(8):
            sk[16*i + j + 8] = (mk[((j - i) % 8) + 8] + delta[16*i + j + 8]) & 0xFF

    F0 = lambda x: (((x << 1) | (x >> 7)) ^ ((x << 2) | (x >> 6)) ^ ((x << 7) | (x >> 1))) & 0xFF
    F1 = lambda x: (((x << 3) | (x >> 5)) ^ ((x << 4) | (x >> 4)) ^ ((x << 6) | (x >> 2))) & 0xFF

    out = bytearray(N_blocks * 8)
    for blk_idx in range(N_blocks):
        x = [(blk_idx >> (8*i)) & 0xFF for i in range(8)]
        # Initial whitening
        x[0] = (x[0] + wk[0]) & 0xFF
        x[2] = x[2] ^ wk[1]
        x[4] = (x[4] + wk[2]) & 0xFF
        x[6] = x[6] ^ wk[3]
        # Rounds
        for r in range(n_rounds):
            tmp = x[7]
            x[7] = (x[6] ^ (F1(x[5]) + sk[4*r + 3]) & 0xFF) & 0xFF
            x[6] = x[5]
            x[5] = (x[4] + (F0(x[3]) ^ sk[4*r + 2])) & 0xFF
            x[4] = x[3]
            x[3] = (x[2] ^ (F1(x[1]) + sk[4*r + 1]) & 0xFF) & 0xFF
            x[2] = x[1]
            x[1] = (x[0] + (F0(tmp) ^ sk[4*r + 0])) & 0xFF
            x[0] = tmp
        # Final whitening
        x[0] = (x[0] + wk[4]) & 0xFF
        x[2] = x[2] ^ wk[5]
        x[4] = (x[4] + wk[6]) & 0xFF
        x[6] = x[6] ^ wk[7]
        base = blk_idx * 8
        for i in range(8):
            out[base + i] = x[i]

    return bytes(out), 8, 4

# ==========================================
# LEA-128
# ==========================================
def lea128_gen(N_blocks, n_rounds=24, seed=42):
    """LEA-128/128: 32-bit ARX, 4-word GFN."""
    rng = np.random.default_rng(seed)
    mk = [int(rng.integers(0, 2**32)) for _ in range(4)]
    mask32 = 0xFFFFFFFF

    delta = [0xc3efe9db, 0x44626b02, 0x79e27c8a, 0x78df30ec,
             0x715ea49e, 0xc785da0a, 0xe04ef22a, 0xe7a12214]

    # Key schedule
    rk = []
    T = list(mk)
    for i in range(n_rounds):
        d = delta[i % 4]
        rot = i & 0x1f
        d_rot = ((d << rot) | (d >> (32 - rot))) & mask32
        T[0] = ((T[0] + d_rot) & mask32)
        T[0] = ((T[0] << 1) | (T[0] >> 31)) & mask32
        T[1] = ((T[1] + ((d_rot << 1) | (d_rot >> 31))) & mask32)
        T[1] = ((T[1] << 3) | (T[1] >> 29)) & mask32
        T[2] = ((T[2] + ((d_rot << 2) | (d_rot >> 30))) & mask32)
        T[2] = ((T[2] << 6) | (T[2] >> 26)) & mask32
        T[3] = ((T[3] + ((d_rot << 3) | (d_rot >> 29))) & mask32)
        T[3] = ((T[3] << 11) | (T[3] >> 21)) & mask32
        rk.append(list(T))

    out = bytearray(N_blocks * 16)
    for blk_idx in range(N_blocks):
        x = [(blk_idx >> (32*i)) & mask32 for i in range(4)]
        for r in range(n_rounds):
            k = rk[r]
            t0 = ((((x[0] ^ k[0]) + (x[1] ^ k[1])) & mask32) << 9 |
                  (((x[0] ^ k[0]) + (x[1] ^ k[1])) & mask32) >> 23) & mask32
            t1 = ((((x[1] ^ k[2]) + (x[2] ^ k[3])) & mask32) << 5 |
                  (((x[1] ^ k[2]) + (x[2] ^ k[3])) & mask32) >> 27) & mask32
            t2 = ((((x[2] ^ k[0]) + (x[3] ^ k[1])) & mask32) << 3 |
                  (((x[2] ^ k[0]) + (x[3] ^ k[1])) & mask32) >> 29) & mask32
            x = [t0, t1, t2, x[0]]
        base = blk_idx * 16
        for i in range(4):
            for b in range(4):
                out[base + i*4 + b] = (x[i] >> (8*(3-b))) & 0xFF

    return bytes(out), 16, 8


# ==========================================
# Chaskey
# ==========================================
def chaskey_gen(N_blocks, n_rounds=8, seed=42):
    """Chaskey: 128-bit ARX permutation (4×32-bit words)."""
    rng = np.random.default_rng(seed)
    mk = [int(rng.integers(0, 2**32)) for _ in range(4)]
    mask32 = 0xFFFFFFFF

    out = bytearray(N_blocks * 16)
    for blk_idx in range(N_blocks):
        v = [(blk_idx >> (32*i)) & mask32 for i in range(4)]
        # Add key
        for i in range(4):
            v[i] = (v[i] ^ mk[i])
        # Rounds
        for r in range(n_rounds):
            v[0] = (v[0] + v[1]) & mask32
            v[2] = (v[2] + v[3]) & mask32
            v[1] = ((v[1] << 5) | (v[1] >> 27)) & mask32
            v[3] = ((v[3] << 8) | (v[3] >> 24)) & mask32
            v[1] ^= v[0]
            v[3] ^= v[2]
            v[0] = ((v[0] << 16) | (v[0] >> 16)) & mask32
            v[0] = (v[0] + v[3]) & mask32
            v[2] = (v[2] + v[1]) & mask32
            v[1] = ((v[1] << 7) | (v[1] >> 25)) & mask32
            v[3] = ((v[3] << 13) | (v[3] >> 19)) & mask32
            v[1] ^= v[2]
            v[3] ^= v[0]
            v[2] = ((v[2] << 16) | (v[2] >> 16)) & mask32
        # Add key
        for i in range(4):
            v[i] = (v[i] ^ mk[i])
        base = blk_idx * 16
        for i in range(4):
            for b in range(4):
                out[base + i*4 + b] = (v[i] >> (8*(3-b))) & 0xFF

    return bytes(out), 16, 8


# ==========================================
# SPARX-64/128
# ==========================================
def sparx64_gen(N_blocks, n_rounds=8, seed=42):
    """SPARX-64/128: Speck ARX-box + linear layer."""
    rng = np.random.default_rng(seed)
    mk = [int(rng.integers(0, 2**16)) for _ in range(8)]
    mask16 = 0xFFFF

    # Key schedule (simplified)
    rk = []
    K = list(mk)
    for r in range(n_rounds):
        rk.append(list(K[:4]))
        # Key update (simple LFSR-like)
        K.append((K[0] + K[7]) & mask16)
        K = K[1:]

    def arx_box(x, y, k0, k1):
        """One Speck-like ARX box."""
        for _ in range(3):
            x = ((x >> 7) | (x << 9)) & mask16
            x = (x + y) & mask16
            x ^= k0
            y = ((y << 2) | (y >> 14)) & mask16
            y ^= x
        return x, y

    out = bytearray(N_blocks * 8)
    for blk_idx in range(N_blocks):
        # Two 32-bit branches, each with two 16-bit words
        x0 = (blk_idx >> 48) & mask16
        y0 = (blk_idx >> 32) & mask16
        x1 = (blk_idx >> 16) & mask16
        y1 = blk_idx & mask16

        for r in range(n_rounds):
            k = rk[r]
            # ARX boxes
            x0, y0 = arx_box(x0, y0, k[0], k[1])
            x1, y1 = arx_box(x1, y1, k[2], k[3])
            # Linear layer (Feistel-like swap + XOR)
            # L(x0||y0, x1||y1) = (x0^x1, y0^y1, x0, y0)
            tmp_x = x0 ^ x1
            tmp_y = y0 ^ y1
            x0, y0, x1, y1 = tmp_x, tmp_y, x0, y0

        base = blk_idx * 8
        out[base] = (x0 >> 8) & 0xFF; out[base+1] = x0 & 0xFF
        out[base+2] = (y0 >> 8) & 0xFF; out[base+3] = y0 & 0xFF
        out[base+4] = (x1 >> 8) & 0xFF; out[base+5] = x1 & 0xFF
        out[base+6] = (y1 >> 8) & 0xFF; out[base+7] = y1 & 0xFF

    return bytes(out), 8, 4


# ==========================================
# MAIN: MI RE-ATTACK
# ==========================================

print("=" * 80)
print("P8: MI RE-ATTACK ON 'NEGATIVE' CIPHERS")
print("=" * 80)
print(f"N={N}, MI method (3-6× more sensitive than chi2)")
print()

# Wrapper functions that return (bytes, bb, bpw)
def wrap_hight(N_blocks, n_rounds=32, seed=42):
    return hight_gen(N_blocks, n_rounds, seed)

def wrap_lea(N_blocks, n_rounds=24, seed=42):
    return lea128_gen(N_blocks, n_rounds, seed)

def wrap_chaskey(N_blocks, n_rounds=8, seed=42):
    return chaskey_gen(N_blocks, n_rounds, seed)

def wrap_sparx(N_blocks, n_rounds=8, seed=42):
    return sparx64_gen(N_blocks, n_rounds, seed)

# Test each cipher at multiple round counts
ciphers = [
    ("HIGHT", wrap_hight, 8, [8, 10, 12, 15, 18, 20, 24, 28, 32]),
    ("LEA-128", wrap_lea, 32, [2, 4, 6, 8, 10, 12, 15, 18, 24]),
    ("Chaskey", wrap_chaskey, 32, [1, 2, 3, 4, 5, 6, 8]),
    ("SPARX-64", wrap_sparx, 16, [1, 2, 3, 4, 5, 6, 8]),
]

for cipher_name, gen_fn, ws, round_list in ciphers:
    print(f"\n{'='*60}")
    print(f"  {cipher_name} (WS={ws})")
    print(f"{'='*60}")
    print(f"{'Rounds':>8}  {'MI Z':>8}  {'chi2 sig%':>10}  {'chi2 t':>8}  {'MI signal?':>12}")
    print("-" * 55)

    for nr in round_list:
        try:
            z_mi, _ = mi_cross_round_z(gen_fn, nr, ws, seed=42)
            sig_rate, t_stat = chi2_cross_round_z(gen_fn, nr, ws, seed=42)
            mi_signal = "YES ***" if z_mi > 3.0 else ("weak *" if z_mi > 2.0 else "no")
            print(f"{nr:>8}  {z_mi:>+8.1f}  {sig_rate*100:>9.1f}%  {t_stat:>+8.1f}  {mi_signal:>12}")
        except Exception as e:
            print(f"{nr:>8}  ERROR: {e}")

print("\n" + "=" * 80)
print("DONE")
print("=" * 80)

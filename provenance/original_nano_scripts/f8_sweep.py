#!/usr/bin/env python3
"""
f8_sweep.py — F8 Cross-Round MI Sweep for all ARX nano-IoT ciphers.

Uses the proven F8 carry-leak distinguisher from the ICECET paper to test
ALL Speck variants (10), LEA variants (3), and SIMON (10, as negative control).

F8 detects stationary cross-round mutual information from carry propagation
in modular addition. It breaks ALL rounds of ALL Speck variants (Z > +4000).
SIMON is immune (no addition). LEA is immune at full rounds (frontier R4).

Reference: "Persistent Cross-Round Carry Leakage in ARX Ciphers", ICECET 2026
"""

import sys
import os
import json
import time
import math
import numpy as np
from scipy import stats

sys.path.insert(0, '<legacy-f8-root>')
sys.path.insert(0, '<legacy-nano-root>')

from speck_utils import f8_test, multi_seed_f8

BASE_DIR = '<legacy-nano-root>'
RAW_DIR = os.path.join(BASE_DIR, 'raw_data')

N_BLOCKS = 20000
N_SEEDS = 10
N_ROUND_PAIRS = 8  # Test 8 consecutive round-pairs from base_round


# ═══════════════════════════════════════════════════════════════════════
# BLOCK-LEVEL GENERATORS (F8-compatible: returns (bytes, block_bytes, bpw))
# ═══════════════════════════════════════════════════════════════════════

def _speck_gen_f8(N, word_size, key_words, alpha, beta, n_rounds, seed):
    """Block-level Speck generator in F8 format."""
    rng = np.random.default_rng(seed)
    mask = (1 << word_size) - 1
    block_bytes = (word_size * 2) // 8
    bpw = word_size // 8

    if word_size <= 32:
        master_key = [int(rng.integers(0, 2**word_size)) for _ in range(key_words)]
    else:
        master_key = [int(rng.integers(0, 2**63)) * 2 + int(rng.integers(0, 2))
                      for _ in range(key_words)]

    rk = [0] * max(n_rounds + 1, 40)
    l = list(master_key[1:])
    rk[0] = master_key[0]
    for i in range(n_rounds):
        ror_l = ((l[i % len(l)] >> alpha) | (l[i % len(l)] << (word_size - alpha))) & mask
        new_l = (rk[i] + ror_l) & mask
        new_l ^= i
        l.append(new_l)
        rol_rk = ((rk[i] << beta) | (rk[i] >> (word_size - beta))) & mask
        rk[i + 1] = rol_rk ^ new_l

    out = bytearray(N * block_bytes)
    for blk_idx in range(N):
        x = (blk_idx >> word_size) & mask
        y = blk_idx & mask
        for r in range(n_rounds):
            ror_x = ((x >> alpha) | (x << (word_size - alpha))) & mask
            x = ((ror_x + y) & mask) ^ rk[r]
            y = (((y << beta) | (y >> (word_size - beta))) & mask) ^ x
        base = blk_idx * block_bytes
        for b in range(bpw):
            out[base + b] = (x >> (8 * (bpw - 1 - b))) & 0xFF
        for b in range(bpw):
            out[base + bpw + b] = (y >> (8 * (bpw - 1 - b))) & 0xFF

    return bytes(out), block_bytes, bpw


def _simon_gen_f8(N, word_size, key_words, z_idx, n_rounds, seed):
    """Block-level SIMON generator in F8 format."""
    _Z_SEQ = [
        0b11111010001001010110000111001101111101000100101011000011100110,
        0b10001110111110010011000010110101000111011111001001100001011010,
        0b10101111011100000011010010011000101000010001111110010110110011,
        0b11011011101011000110010111100000010010001010011100110100001111,
        0b11010001111001101011011000100000010111000011001010010011101100,
    ]
    rng = np.random.default_rng(seed)
    mask = (1 << word_size) - 1
    block_bytes = (word_size * 2) // 8
    bpw = word_size // 8
    m = key_words
    z_seq = _Z_SEQ[z_idx]

    master_key = [int(rng.integers(0, 2**min(word_size, 32))) for _ in range(m)]
    for i in range(len(master_key)):
        master_key[i] &= mask

    # Key schedule
    rk = list(master_key)
    c = mask ^ 3
    for i in range(m, n_rounds):
        tmp = ((rk[i-1] >> 3) | (rk[i-1] << (word_size - 3))) & mask
        if m == 4:
            tmp ^= rk[i-3]
        tmp ^= ((tmp >> 1) | (tmp << (word_size - 1))) & mask
        rk.append((~rk[i-m] & mask) ^ tmp ^ c ^ ((z_seq >> ((i - m) % 62)) & 1))

    out = bytearray(N * block_bytes)
    for blk_idx in range(N):
        x = (blk_idx >> word_size) & mask
        y = blk_idx & mask
        for r in range(n_rounds):
            s1 = ((x << 1) | (x >> (word_size - 1))) & mask
            s8 = ((x << 8) | (x >> (word_size - 8))) & mask
            s2 = ((x << 2) | (x >> (word_size - 2))) & mask
            tmp = (s1 & s8) ^ s2 ^ y ^ rk[r]
            y = x
            x = tmp & mask
        base = blk_idx * block_bytes
        for b in range(bpw):
            out[base + b] = (x >> (8 * (bpw - 1 - b))) & 0xFF
        for b in range(bpw):
            out[base + bpw + b] = (y >> (8 * (bpw - 1 - b))) & 0xFF

    return bytes(out), block_bytes, bpw


def _lea_gen_f8(N, key_size, n_rounds, seed):
    """Block-level LEA generator in F8 format."""
    rng = np.random.default_rng(seed)
    mask32 = 0xFFFFFFFF
    block_bytes = 16
    bpw = 4  # 32-bit words

    n_key_words = key_size // 32
    mk = [int(rng.integers(0, 2**32)) for _ in range(n_key_words)]

    delta = [0xc3efe9db, 0x44626b02, 0x79e27c8a, 0x78df30ec,
             0x715ea49e, 0xc785da0a, 0xe04ef22a, 0xe7a12214]

    # Key schedule depends on key size
    rk = []
    T = list(mk)
    for i in range(n_rounds):
        d = delta[i % (n_key_words if n_key_words <= 4 else 8)]
        rot = i & 0x1f
        d_rot = ((d << rot) | (d >> (32 - rot))) & mask32

        if key_size == 128:
            T[0] = ((T[0] + d_rot) & mask32); T[0] = ((T[0] << 1) | (T[0] >> 31)) & mask32
            T[1] = ((T[1] + ((d_rot << 1) | (d_rot >> 31))) & mask32); T[1] = ((T[1] << 3) | (T[1] >> 29)) & mask32
            T[2] = ((T[2] + ((d_rot << 2) | (d_rot >> 30))) & mask32); T[2] = ((T[2] << 6) | (T[2] >> 26)) & mask32
            T[3] = ((T[3] + ((d_rot << 3) | (d_rot >> 29))) & mask32); T[3] = ((T[3] << 11) | (T[3] >> 21)) & mask32
            rk.append([T[0], T[1], T[2], T[1], T[3], T[1]])
        elif key_size == 192:
            T[0] = ((T[0] + d_rot) & mask32); T[0] = ((T[0] << 1) | (T[0] >> 31)) & mask32
            T[1] = ((T[1] + ((d_rot << 1) | (d_rot >> 31))) & mask32); T[1] = ((T[1] << 3) | (T[1] >> 29)) & mask32
            T[2] = ((T[2] + ((d_rot << 2) | (d_rot >> 30))) & mask32); T[2] = ((T[2] << 6) | (T[2] >> 26)) & mask32
            T[3] = ((T[3] + ((d_rot << 3) | (d_rot >> 29))) & mask32); T[3] = ((T[3] << 11) | (T[3] >> 21)) & mask32
            T[4] = ((T[4] + ((d_rot << 4) | (d_rot >> 28))) & mask32); T[4] = ((T[4] << 13) | (T[4] >> 19)) & mask32
            T[5] = ((T[5] + ((d_rot << 5) | (d_rot >> 27))) & mask32); T[5] = ((T[5] << 17) | (T[5] >> 15)) & mask32
            rk.append([T[0], T[1], T[2], T[3], T[4], T[5]])
        else:  # 256
            T[0] = ((T[0] + d_rot) & mask32); T[0] = ((T[0] << 1) | (T[0] >> 31)) & mask32
            T[1] = ((T[1] + ((d_rot << 1) | (d_rot >> 31))) & mask32); T[1] = ((T[1] << 3) | (T[1] >> 29)) & mask32
            T[2] = ((T[2] + ((d_rot << 2) | (d_rot >> 30))) & mask32); T[2] = ((T[2] << 6) | (T[2] >> 26)) & mask32
            T[3] = ((T[3] + ((d_rot << 3) | (d_rot >> 29))) & mask32); T[3] = ((T[3] << 11) | (T[3] >> 21)) & mask32
            T[4] = ((T[4] + ((d_rot << 4) | (d_rot >> 28))) & mask32); T[4] = ((T[4] << 13) | (T[4] >> 19)) & mask32
            T[5] = ((T[5] + ((d_rot << 5) | (d_rot >> 27))) & mask32); T[5] = ((T[5] << 17) | (T[5] >> 15)) & mask32
            T[6] = ((T[6] + ((d_rot << 6) | (d_rot >> 26))) & mask32); T[6] = ((T[6] << 19) | (T[6] >> 13)) & mask32
            T[7] = ((T[7] + ((d_rot << 7) | (d_rot >> 25))) & mask32); T[7] = ((T[7] << 23) | (T[7] >> 9)) & mask32
            rk.append([T[0], T[1], T[2], T[3], T[4], T[5]])

    out = bytearray(N * block_bytes)
    for blk_idx in range(N):
        x = [(blk_idx >> (32 * i)) & mask32 for i in range(4)]
        for r in range(n_rounds):
            k = rk[r]
            t0 = (((x[0] ^ k[0]) + (x[1] ^ k[1])) & mask32)
            t0 = ((t0 << 9) | (t0 >> 23)) & mask32
            t1 = (((x[1] ^ k[2]) + (x[2] ^ k[3])) & mask32)
            t1 = ((t1 << 5) | (t1 >> 27)) & mask32
            t2 = (((x[2] ^ k[4]) + (x[3] ^ k[5])) & mask32)
            t2 = ((t2 << 3) | (t2 >> 29)) & mask32
            x = [t0, t1, t2, x[0]]
        base = blk_idx * 16
        for i in range(4):
            for b in range(4):
                out[base + i * 4 + b] = (x[i] >> (8 * (3 - b))) & 0xFF

    return bytes(out), block_bytes, bpw


# ═══════════════════════════════════════════════════════════════════════
# CIPHER REGISTRY — F8 compatible generators
# ═══════════════════════════════════════════════════════════════════════

# Speck: (word_size, key_words, alpha, beta, full_rounds)
SPECK_F8_VARIANTS = {
    'speck32_64':   (16, 4, 7, 2, 22),
    'speck48_72':   (24, 3, 8, 3, 22),
    'speck48_96':   (24, 4, 8, 3, 23),
    'speck64_96':   (32, 3, 8, 3, 26),
    'speck64_128':  (32, 4, 8, 3, 27),
    'speck96_96':   (48, 2, 8, 3, 28),
    'speck96_144':  (48, 3, 8, 3, 29),
    'speck128_128': (64, 2, 8, 3, 32),
    'speck128_192': (64, 3, 8, 3, 33),
    'speck128_256': (64, 4, 8, 3, 34),
}

# SIMON: (word_size, key_words, z_idx, full_rounds)
SIMON_F8_VARIANTS = {
    'simon32_64':   (16, 4, 0, 32),
    'simon48_72':   (24, 3, 0, 36),
    'simon48_96':   (24, 4, 1, 36),
    'simon64_96':   (32, 3, 2, 42),
    'simon64_128':  (32, 4, 3, 44),
    'simon96_96':   (48, 2, 2, 52),
    'simon96_144':  (48, 3, 3, 54),
    'simon128_128': (64, 2, 2, 68),
    'simon128_192': (64, 3, 3, 69),
    'simon128_256': (64, 4, 4, 72),
}

# LEA: (key_size, full_rounds)
LEA_F8_VARIANTS = {
    'lea128': (128, 24),
    'lea192': (192, 28),
    'lea256': (256, 32),
}


def make_speck_f8_gen(word_size, key_words, alpha, beta):
    """Create F8-compatible Speck generator."""
    def gen(N, n_rounds=22, seed=42):
        return _speck_gen_f8(N, word_size, key_words, alpha, beta, n_rounds, seed)
    return gen


def make_simon_f8_gen(word_size, key_words, z_idx):
    """Create F8-compatible SIMON generator."""
    def gen(N, n_rounds=32, seed=42):
        return _simon_gen_f8(N, word_size, key_words, z_idx, n_rounds, seed)
    return gen


def make_lea_f8_gen(key_size):
    """Create F8-compatible LEA generator."""
    def gen(N, n_rounds=24, seed=42):
        return _lea_gen_f8(N, key_size, n_rounds, seed)
    return gen


# ═══════════════════════════════════════════════════════════════════════
# F8 SWEEP ENGINE
# ═══════════════════════════════════════════════════════════════════════

def f8_sweep_cipher(name, gen_fn, full_rounds, block_bytes, n_blocks=N_BLOCKS,
                    n_seeds=N_SEEDS, n_round_pairs=N_ROUND_PAIRS):
    """Run F8 sweep at multiple base rounds for one cipher.

    Tests F8 at: low rounds (R1-R4), mid rounds (~half), and full rounds.
    """
    # Select test base rounds
    if full_rounds <= 12:
        base_rounds = list(range(1, full_rounds))
    elif full_rounds <= 34:
        base_rounds = [1, 2, 3, 4, 6, 8,
                       full_rounds // 4,
                       full_rounds // 2,
                       full_rounds * 3 // 4,
                       full_rounds - n_round_pairs,
                       full_rounds - 2]
    else:
        base_rounds = [1, 2, 4, 8, 12, 16,
                       full_rounds // 4,
                       full_rounds // 2,
                       full_rounds * 3 // 4,
                       full_rounds - n_round_pairs,
                       full_rounds - 2]

    # Filter: base + n_round_pairs <= full_rounds + 1
    base_rounds = sorted(set(r for r in base_rounds if 1 <= r <= full_rounds - 1))

    print(f"\n{'='*72}")
    print(f"  F8: {name}  (block={block_bytes*8}b, full={full_rounds}R)")
    print(f"  Base rounds: {base_rounds}")
    print(f"  N={n_blocks}, {n_seeds} seeds, {n_round_pairs} round-pairs per base")
    print(f"{'='*72}")
    print(f"{'Base':>6}  {'SigRate':>8}  {'±':>8}  {'t-stat':>8}  {'Verdict':>10}  {'Time':>6}")
    print(f"{'─'*6}  {'─'*8}  {'─'*8}  {'─'*8}  {'─'*10}  {'─'*6}")

    results = []
    full_round_detected = False

    for base_r in base_rounds:
        # Limit pairs so we don't exceed full_rounds+1
        actual_pairs = min(n_round_pairs, full_rounds - base_r + 1)
        if actual_pairs < 1:
            continue

        t0 = time.time()
        rates = []
        for s_idx in range(n_seeds):
            seed = s_idx * 1000 + 42
            _, _, rate, _ = f8_test(gen_fn, base_r, actual_pairs, n_blocks, seed)
            rates.append(rate)

        dt = time.time() - t0
        mean_r = float(np.mean(rates))
        std_r = float(np.std(rates))
        t_stat = (mean_r - 0.05) / (std_r / math.sqrt(n_seeds)) if std_r > 0 else 0

        if t_stat > 3.0:
            verdict = "DETECTED"
            if base_r + actual_pairs >= full_rounds:
                full_round_detected = True
        elif t_stat > 2.0:
            verdict = "WEAK"
        else:
            verdict = "CLEAN"

        print(f"{base_r:>6}  {mean_r:>8.4f}  {std_r:>8.4f}  {t_stat:>+8.1f}  {verdict:>10}  {dt:>5.1f}s")

        results.append({
            'base_round': base_r,
            'n_round_pairs': actual_pairs,
            'sig_rate_mean': round(mean_r, 6),
            'sig_rate_std': round(std_r, 6),
            't_stat': round(float(t_stat), 2),
            'verdict': verdict,
            'per_seed_rates': [round(float(r), 6) for r in rates],
        })

    # Find max t-stat at full rounds (last entry where base+pairs >= full)
    full_round_t = 0
    for r in results:
        if r['base_round'] + r['n_round_pairs'] >= full_rounds:
            full_round_t = max(full_round_t, r['t_stat'])

    # Find frontier (lowest base round still detected)
    frontier_base = None
    for r in reversed(results):
        if r['verdict'] == 'DETECTED':
            frontier_base = r['base_round']

    print(f"\n  Full-round F8 t-stat: {full_round_t:+.1f}")
    print(f"  Full-round detected: {'YES — ALL ROUNDS BROKEN' if full_round_detected else 'NO'}")
    if frontier_base:
        print(f"  Highest detection base: R{frontier_base}")

    return {
        'cipher': name,
        'test': 'F8_cross_round_MI',
        'block_bytes': block_bytes,
        'full_rounds': full_rounds,
        'n_blocks': n_blocks,
        'n_seeds': n_seeds,
        'n_round_pairs': n_round_pairs,
        'timestamp': time.strftime('%Y-%m-%dT%H:%M:%S'),
        'full_round_detected': full_round_detected,
        'full_round_t_stat': full_round_t,
        'results': results,
    }


def save_f8_result(data, cipher_name, family_dir):
    """Save F8 result to raw_data/<family>/."""
    dirpath = os.path.join(RAW_DIR, family_dir)
    os.makedirs(dirpath, exist_ok=True)
    filepath = os.path.join(dirpath, f'{cipher_name}_f8_sweep.json')
    with open(filepath, 'w') as f:
        json.dump(data, f, indent=2)
    print(f"  Saved: {filepath}")
    return filepath


# ═══════════════════════════════════════════════════════════════════════
# MAIN
# ═══════════════════════════════════════════════════════════════════════

if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser(description='F8 Cross-Round MI Sweep')
    parser.add_argument('--family', choices=['speck', 'simon', 'lea', 'all'], default='all')
    parser.add_argument('--cipher', type=str, help='Run single cipher by name')
    parser.add_argument('-n', type=int, default=N_BLOCKS, help='Number of blocks')
    parser.add_argument('--seeds', type=int, default=N_SEEDS, help='Number of seeds')
    args = parser.parse_args()

    t_total = time.time()
    all_f8_results = {}

    if args.cipher:
        # Single cipher mode
        if args.cipher in SPECK_F8_VARIANTS:
            ws, kw, a, b, fr = SPECK_F8_VARIANTS[args.cipher]
            gen = make_speck_f8_gen(ws, kw, a, b)
            bb = (ws * 2) // 8
            data = f8_sweep_cipher(args.cipher, gen, fr, bb, args.n, args.seeds)
            save_f8_result(data, args.cipher, 'speck')
        elif args.cipher in SIMON_F8_VARIANTS:
            ws, kw, zi, fr = SIMON_F8_VARIANTS[args.cipher]
            gen = make_simon_f8_gen(ws, kw, zi)
            bb = (ws * 2) // 8
            data = f8_sweep_cipher(args.cipher, gen, fr, bb, args.n, args.seeds)
            save_f8_result(data, args.cipher, 'simon')
        elif args.cipher in LEA_F8_VARIANTS:
            ks, fr = LEA_F8_VARIANTS[args.cipher]
            gen = make_lea_f8_gen(ks)
            data = f8_sweep_cipher(args.cipher, gen, fr, 16, args.n, args.seeds)
            save_f8_result(data, args.cipher, 'lea')
        else:
            print(f"Unknown cipher: {args.cipher}")
            all_names = list(SPECK_F8_VARIANTS) + list(SIMON_F8_VARIANTS) + list(LEA_F8_VARIANTS)
            print(f"Available: {', '.join(sorted(all_names))}")
            sys.exit(1)
    else:
        # Family sweep
        if args.family in ('speck', 'all'):
            print(f"\n{'#'*72}")
            print(f"  F8 SWEEP: SPECK (10 variants) — expected: ALL ROUNDS BROKEN")
            print(f"{'#'*72}")
            for name, (ws, kw, a, b, fr) in SPECK_F8_VARIANTS.items():
                gen = make_speck_f8_gen(ws, kw, a, b)
                bb = (ws * 2) // 8
                data = f8_sweep_cipher(name, gen, fr, bb, args.n, args.seeds)
                save_f8_result(data, name, 'speck')
                all_f8_results[name] = {
                    'full_round_detected': data['full_round_detected'],
                    'full_round_t_stat': data['full_round_t_stat'],
                }

        if args.family in ('simon', 'all'):
            print(f"\n{'#'*72}")
            print(f"  F8 SWEEP: SIMON (10 variants) — expected: IMMUNE (no addition)")
            print(f"{'#'*72}")
            for name, (ws, kw, zi, fr) in SIMON_F8_VARIANTS.items():
                gen = make_simon_f8_gen(ws, kw, zi)
                bb = (ws * 2) // 8
                data = f8_sweep_cipher(name, gen, fr, bb, args.n, args.seeds)
                save_f8_result(data, name, 'simon')
                all_f8_results[name] = {
                    'full_round_detected': data['full_round_detected'],
                    'full_round_t_stat': data['full_round_t_stat'],
                }

        if args.family in ('lea', 'all'):
            print(f"\n{'#'*72}")
            print(f"  F8 SWEEP: LEA (3 variants) — expected: IMMUNE at full rounds")
            print(f"{'#'*72}")
            for name, (ks, fr) in LEA_F8_VARIANTS.items():
                gen = make_lea_f8_gen(ks)
                data = f8_sweep_cipher(name, gen, fr, 16, args.n, args.seeds)
                save_f8_result(data, name, 'lea')
                all_f8_results[name] = {
                    'full_round_detected': data['full_round_detected'],
                    'full_round_t_stat': data['full_round_t_stat'],
                }

    # Print summary
    if all_f8_results:
        summary_path = os.path.join(BASE_DIR, 'analysis', 'f8_summary.json')
        os.makedirs(os.path.dirname(summary_path), exist_ok=True)
        with open(summary_path, 'w') as f:
            json.dump({
                'test': 'F8_cross_round_MI',
                'reference': 'ICECET 2026 Paper #1142',
                'timestamp': time.strftime('%Y-%m-%dT%H:%M:%S'),
                'n_blocks': args.n,
                'n_seeds': args.seeds,
                'results': all_f8_results,
            }, f, indent=2)

        print(f"\n{'='*72}")
        print(f"  F8 CROSS-ROUND MI — COMPLETE SUMMARY")
        print(f"{'='*72}")
        print(f"{'Cipher':>20}  {'Full-R Detected':>16}  {'t-stat':>8}  {'Verdict':>12}")
        print(f"{'─'*20}  {'─'*16}  {'─'*8}  {'─'*12}")
        for name in sorted(all_f8_results.keys()):
            r = all_f8_results[name]
            det = 'YES' if r['full_round_detected'] else 'no'
            t = r['full_round_t_stat']
            v = 'BROKEN' if r['full_round_detected'] else 'IMMUNE'
            print(f"{name:>20}  {det:>16}  {t:>+8.1f}  {v:>12}")

    dt = time.time() - t_total
    print(f"\nTotal time: {dt:.1f}s ({dt/60:.1f} min)")

"""Shared Speck implementation and F8 utilities for all test scripts."""
import numpy as np
from scipy import stats
import math


def speck_gen(N_blocks, word_size=16, key_words=4, alpha=7, beta=2, n_rounds=22, seed=42):
    """Generic Speck CTR-mode generator. Returns (bytes, block_bytes, bytes_per_word)."""
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

    out = bytearray(N_blocks * block_bytes)
    for blk_idx in range(N_blocks):
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


def simon_gen(N_blocks, n_rounds=32, seed=42):
    """SIMON 32/64 CTR-mode generator. AND+Rotation, no addition."""
    rng = np.random.default_rng(seed)
    mask = 0xFFFF
    master_key = [int(rng.integers(0, 2**16)) for _ in range(4)]

    z_seq = 0b11111010001001010110000111001101111101000100101011000011100110
    c = 0xFFFC
    rk = list(master_key)
    for i in range(4, n_rounds):
        tmp = ((rk[i-1] >> 3) | (rk[i-1] << 13)) & mask
        tmp ^= rk[i-3]
        tmp ^= ((tmp >> 1) | (tmp << 15)) & mask
        tmp ^= rk[i-4] ^ c ^ ((z_seq >> ((i - 4) % 62)) & 1)
        rk.append(tmp & mask)

    out = bytearray(N_blocks * 4)
    for blk_idx in range(N_blocks):
        x = (blk_idx >> 16) & mask
        y = blk_idx & mask
        for r in range(n_rounds):
            s1 = ((x << 1) | (x >> 15)) & mask
            s8 = ((x << 8) | (x >> 8)) & mask
            s2 = ((x << 2) | (x >> 14)) & mask
            tmp = (s1 & s8) ^ s2 ^ y ^ rk[r]
            y = x
            x = tmp & mask
        base = blk_idx * 4
        out[base] = (x >> 8) & 0xFF
        out[base + 1] = x & 0xFF
        out[base + 2] = (y >> 8) & 0xFF
        out[base + 3] = y & 0xFF

    return bytes(out), 4, 2


def f8_test(gen_fn, base_round, n_round_pairs, N_blocks, seed=42, shift=5):
    """Blocksize-aware F8 test. Returns (n_sig, n_total, sig_rate, chi2_by_pair)."""
    n_bins = 2 ** (8 - shift)
    n_sig = 0
    n_total = 0
    chi2_by_pair = {}

    for R in range(base_round, base_round + n_round_pairs):
        raw_R, bb, bpw = gen_fn(N_blocks, n_rounds=R, seed=seed)
        raw_R1, _, _ = gen_fn(N_blocks, n_rounds=R + 1, seed=seed)

        data_R = np.frombuffer(raw_R, dtype=np.uint8).reshape(-1, bb)
        data_R1 = np.frombuffer(raw_R1, dtype=np.uint8).reshape(-1, bb)
        n_act = min(data_R.shape[0], data_R1.shape[0])
        data_R = data_R[:n_act]
        data_R1 = data_R1[:n_act]

        diff = data_R ^ data_R1
        out_q = data_R >> shift
        diff_q = diff >> shift

        for i in range(bb):
            for j in range(bb):
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
                if p < 0.05:
                    n_sig += 1
                key = (i, j)
                if key not in chi2_by_pair:
                    chi2_by_pair[key] = []
                chi2_by_pair[key].append(chi2)

    return n_sig, n_total, n_sig / max(n_total, 1), chi2_by_pair


def f8_sigrate(gen_fn, base_round, n_round_pairs, N_blocks, seed=42, shift=5):
    """Simplified F8 returning only sig_rate."""
    _, _, rate, _ = f8_test(gen_fn, base_round, n_round_pairs, N_blocks, seed, shift)
    return rate


def multi_seed_f8(gen_fn, base_round, n_round_pairs, N_blocks, n_seeds=10, shift=5):
    """Run F8 over multiple seeds, return (mean_rate, std_rate, t_stat, rates)."""
    rates = []
    for s_idx in range(n_seeds):
        seed = s_idx * 1000 + 42
        rate = f8_sigrate(gen_fn, base_round, n_round_pairs, N_blocks, seed, shift)
        rates.append(rate)
    mean_r = np.mean(rates)
    std_r = np.std(rates)
    t_stat = (mean_r - 0.05) / (std_r / math.sqrt(n_seeds)) if std_r > 0 else 0
    return mean_r, std_r, t_stat, rates


# Convenience wrappers for standard variants
def speck32(N, n_rounds=22, seed=42):
    return speck_gen(N, 16, 4, 7, 2, n_rounds, seed)

def speck48(N, n_rounds=23, seed=42):
    return speck_gen(N, 24, 4, 8, 3, n_rounds, seed)

def speck64(N, n_rounds=27, seed=42):
    return speck_gen(N, 32, 4, 8, 3, n_rounds, seed)

def speck128(N, n_rounds=34, seed=42):
    return speck_gen(N, 64, 4, 8, 3, n_rounds, seed)

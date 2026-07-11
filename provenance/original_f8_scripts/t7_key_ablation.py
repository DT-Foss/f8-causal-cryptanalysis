#!/usr/bin/env python3
"""T7: Key-schedule ablation — identical, random, normal keys."""
import sys, os; sys.path.insert(0, os.path.dirname(__file__))
from speck_utils import *

N, SEEDS = 20000, 10

def speck32_ablated(N_blocks, n_rounds=22, seed=42, key_mode="normal"):
    rng = np.random.default_rng(seed)
    mask = 0xFFFF
    if key_mode == "identical":
        rk = [int(rng.integers(0, 2**16))] * n_rounds
    elif key_mode == "random":
        rk = [int(rng.integers(0, 2**16)) for _ in range(n_rounds)]
    else:
        master_key = [int(rng.integers(0, 2**16)) for _ in range(4)]
        rk = [0] * (n_rounds + 1); l = list(master_key[1:]); rk[0] = master_key[0]
        for i in range(n_rounds):
            ror_l = ((l[i%len(l)] >> 7) | (l[i%len(l)] << 9)) & mask
            new_l = (rk[i] + ror_l) & mask; new_l ^= i; l.append(new_l)
            rk[i+1] = (((rk[i] << 2) | (rk[i] >> 14)) & mask) ^ new_l

    out = bytearray(N_blocks * 4)
    for blk_idx in range(N_blocks):
        x = (blk_idx >> 16) & mask; y = blk_idx & mask
        for r in range(n_rounds):
            x = (((x >> 7) | (x << 9)) & mask + y) & mask ^ rk[r]
            y = (((y << 2) | (y >> 14)) & mask) ^ x
        base = blk_idx * 4
        out[base] = (x >> 8) & 0xFF; out[base+1] = x & 0xFF
        out[base+2] = (y >> 8) & 0xFF; out[base+3] = y & 0xFF
    return bytes(out), 4, 2

print("=== T7: KEY-SCHEDULE ABLATION ===\n")
for mode in ["normal", "identical", "random"]:
    fn = lambda N, n_rounds=22, seed=42, m=mode: speck32_ablated(N, n_rounds, seed, m)
    mean_r, std_r, t, _ = multi_seed_f8(fn, 10, 8, N, SEEDS)
    print(f"  {mode:>12}: sig_rate={mean_r:.4f}±{std_r:.4f}  t={t:+.1f}")

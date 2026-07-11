#!/usr/bin/env python3
"""T3: Position heatmap + T3b Random Feistel control."""
import sys, os, hashlib; sys.path.insert(0, os.path.dirname(__file__))
from speck_utils import *

N, SEEDS = 20000, 10

def random_feistel_gen(N_blocks, n_rounds=22, seed=42):
    """Random Feistel: hash-based f, same block size as Speck 32/64."""
    rng = np.random.default_rng(seed)
    key = rng.bytes(32)
    out = bytearray(N_blocks * 4)
    for blk_idx in range(N_blocks):
        x = (blk_idx >> 16) & 0xFFFF; y = blk_idx & 0xFFFF
        for r in range(n_rounds):
            h = hashlib.sha256(key + r.to_bytes(4, 'big') + y.to_bytes(2, 'big')).digest()
            f_y = int.from_bytes(h[:2], 'big')
            new_x = y; new_y = x ^ f_y
            x, y = new_x, new_y
        base = blk_idx * 4
        out[base] = (x >> 8) & 0xFF; out[base+1] = x & 0xFF
        out[base+2] = (y >> 8) & 0xFF; out[base+3] = y & 0xFF
    return bytes(out), 4, 2

print("=== T3: POSITION HEATMAP ===\n")
total_chi2 = {}
for s_idx in range(SEEDS):
    _, _, _, chi2_map = f8_test(speck32, 10, 8, N, s_idx*1000+42)
    for k, v in chi2_map.items():
        total_chi2.setdefault(k, []).extend(v)

crit = stats.chi2.ppf(0.95, 49)
bpw = 2; bb = 4
print("Heatmap (mean chi2):")
for i in range(bb):
    li = f"x{i}" if i < bpw else f"y{i-bpw}"
    row = []
    for j in range(bb):
        mc = np.mean(total_chi2.get((i,j), [49]))
        row.append(f"{mc:>6.0f}" if mc > 100 else f"{mc:>6.1f}")
    print(f"  o_{li}  {'  '.join(row)}")

# Quadrant analysis
for qname, cond in [("out_x→diff_x", lambda i,j: i<bpw and j<bpw),
                     ("out_x→diff_y", lambda i,j: i<bpw and j>=bpw),
                     ("out_y→diff_x", lambda i,j: i>=bpw and j<bpw),
                     ("out_y→diff_y", lambda i,j: i>=bpw and j>=bpw)]:
    rejs = [np.mean([1 if c > crit else 0 for c in total_chi2[(i,j)]])
            for i in range(bb) for j in range(bb) if cond(i,j)]
    print(f"  {qname}: {np.mean(rejs):.4f}")

print("\n=== T3b: RANDOM FEISTEL CONTROL ===\n")
for name, fn in [("Speck 32/64", speck32), ("Random Feistel", random_feistel_gen)]:
    mean_r, _, t, _ = multi_seed_f8(fn, 10, 8, N, 5)
    print(f"  {name:>20}: sig_rate={mean_r:.4f}  t={t:+.1f}")

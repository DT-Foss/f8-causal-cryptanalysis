#!/usr/bin/env python3
"""P9: Adaptive quantization — find optimal shift for chi2 F8 method."""
import sys, os; sys.path.insert(0, os.path.dirname(__file__))
from speck_utils import *

def f8_sigrate_shift(gen_fn, base_round, N_blocks, seed, shift):
    """F8 sig_rate at a specific shift value."""
    n_bins = 2 ** (8 - shift)
    raw_R, bb, bpw = gen_fn(N_blocks, n_rounds=base_round, seed=seed)
    raw_R1, _, _ = gen_fn(N_blocks, n_rounds=base_round + 1, seed=seed)
    d_R = np.frombuffer(raw_R, dtype=np.uint8).reshape(-1, bb)
    d_R1 = np.frombuffer(raw_R1, dtype=np.uint8).reshape(-1, bb)
    n = min(d_R.shape[0], d_R1.shape[0])
    d_R = d_R[:n]; d_R1 = d_R1[:n]
    diff = d_R ^ d_R1
    out_q = d_R >> shift
    diff_q = diff >> shift
    dof = (n_bins - 1) ** 2

    n_sig = 0; n_total = 0
    for i in range(bpw):
        for j in range(bpw, bb):
            table = np.zeros((n_bins, n_bins), dtype=float)
            np.add.at(table, (out_q[:, i], diff_q[:, j]), 1)
            rs = table.sum(axis=1, keepdims=True)
            cs = table.sum(axis=0, keepdims=True)
            exp = rs * cs / n
            valid = exp > 5
            if np.sum(valid) < n_bins:
                continue
            chi2 = float(np.sum((table[valid] - exp[valid]) ** 2 / exp[valid]))
            p = float(stats.chi2.sf(chi2, dof))
            n_total += 1
            if p < 0.05: n_sig += 1

    return n_sig / max(n_total, 1), n_total

print("=" * 80)
print("P9: ADAPTIVE QUANTIZATION — OPTIMAL SHIFT FOR chi2 F8")
print("=" * 80)
print()

# Test shift values from 0 (256 bins) to 7 (2 bins)
shifts = [1, 2, 3, 4, 5, 6, 7]  # shift=0 gives 256 bins, too many for N=5000
SEEDS = 5

# Speck 32/64 at different N
for N in [1000, 5000, 10000, 50000]:
    print(f"\n--- Speck 32/64, N={N} ---")
    print(f"{'Shift':>6}  {'Bins':>5}  {'sig_rate':>9}  {'n_tests':>8}  {'Excess':>8}")
    print("-" * 45)
    for shift in shifts:
        n_bins = 2 ** (8 - shift)
        rates = []
        n_tests_total = 0
        for s in range(SEEDS):
            seed = s * 1000 + 42
            rate, n_t = f8_sigrate_shift(speck32, 15, N, seed, shift)
            rates.append(rate)
            n_tests_total += n_t
        mean_rate = np.mean(rates)
        excess = mean_rate - 0.05
        marker = " ***" if excess > 0.03 else (" *" if excess > 0.01 else "")
        print(f"{shift:>6}  {n_bins:>5}  {mean_rate*100:>8.1f}%  {n_tests_total//SEEDS:>8}  {excess*100:>+7.1f}%{marker}")

# Now test on weaker signal: Speck 128/256
print(f"\n\n--- Speck 128/256, N=50000 ---")
print(f"{'Shift':>6}  {'Bins':>5}  {'sig_rate':>9}  {'n_tests':>8}  {'Excess':>8}")
print("-" * 45)
for shift in shifts:
    n_bins = 2 ** (8 - shift)
    rates = []
    n_tests_total = 0
    for s in range(SEEDS):
        seed = s * 1000 + 42
        rate, n_t = f8_sigrate_shift(speck128, 22, 50000, seed, shift)
        rates.append(rate)
        n_tests_total += n_t
    mean_rate = np.mean(rates)
    excess = mean_rate - 0.05
    marker = " ***" if excess > 0.03 else (" *" if excess > 0.01 else "")
    print(f"{shift:>6}  {n_bins:>5}  {mean_rate*100:>8.1f}%  {n_tests_total//SEEDS:>8}  {excess*100:>+7.1f}%{marker}")

# Null calibration: random
print(f"\n\n--- Random (null), N=50000 ---")
print(f"{'Shift':>6}  {'Bins':>5}  {'sig_rate':>9}")
print("-" * 30)
for shift in shifts:
    n_bins = 2 ** (8 - shift)
    rates = []
    for s in range(SEEDS):
        seed = s * 1000 + 42
        rng = np.random.default_rng(seed)
        raw_R = rng.integers(0, 256, size=50000*4, dtype=np.uint8).tobytes()
        raw_R1 = rng.integers(0, 256, size=50000*4, dtype=np.uint8).tobytes()
        rate, _ = f8_sigrate_shift(lambda N, n_rounds, seed: (raw_R, 4, 2),
                                    15, 50000, seed, shift)
        rates.append(rate)
    print(f"{shift:>6}  {n_bins:>5}  {np.mean(rates)*100:>8.1f}%")

# Adaptive strategy: try all shifts, take the one with highest excess
print(f"\n\n=== ADAPTIVE STRATEGY ===")
print(f"For each N, which shift gives highest excess?")
print()
print(f"{'N':>6}  {'Best shift':>10}  {'Best bins':>10}  {'Best excess%':>13}")
print("-" * 50)
for N in [1000, 2000, 5000, 10000, 25000, 50000]:
    best_shift = 5; best_excess = 0
    for shift in shifts:
        rates = []
        for s in range(SEEDS):
            seed = s * 1000 + 42
            rate, _ = f8_sigrate_shift(speck32, 15, N, seed, shift)
            rates.append(rate)
        excess = np.mean(rates) - 0.05
        if excess > best_excess:
            best_excess = excess
            best_shift = shift
    print(f"{N:>6}  {best_shift:>10}  {2**(8-best_shift):>10}  {best_excess*100:>+12.1f}%")

print("\n=== DONE ===")

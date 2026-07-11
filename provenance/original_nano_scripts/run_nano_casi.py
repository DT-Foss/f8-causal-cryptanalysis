#!/usr/bin/env python3
"""
nano-casi: Full CASI characterization of 5 nano-IoT ciphers.

Runs compute_casi_score + compute_amplified_score across all round counts
for ASCON, PRESENT, LEA, SIMON, and Grain-128a.

Output: results table + JSON for paper.
"""

import sys
import json
import time
import numpy as np
sys.path.insert(0, '<legacy-live-casi>')

from live_casi.ciphers import CIPHERS
from live_casi.core import compute_casi_score, compute_amplified_score

N_SAMPLES = 10000   # 10K samples per test
N_SEEDS = 5         # 5 independent seeds for statistical robustness

NANO_CIPHERS = {
    'ascon': {
        'test_rounds': [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12],
        'full': 12,
    },
    'present': {
        'test_rounds': [1, 2, 3, 4, 5, 6, 8, 10, 12, 16, 20, 24, 31],
        'full': 31,
    },
    'lea': {
        'test_rounds': [1, 2, 3, 4, 5, 6, 8, 10, 12, 16, 20, 24],
        'full': 24,
    },
    'simon': {
        'test_rounds': [1, 2, 3, 4, 5, 6, 8, 10, 12, 16, 20, 24, 32],
        'full': 32,
    },
    'grain': {
        'test_rounds': [8, 16, 32, 64, 96, 128, 192, 256],
        'full': 256,
    },
}


def run_cipher(name, info):
    cipher = CIPHERS[name]
    gen = cipher['generator']
    results = []
    full_rounds = info['full']

    print(f"\n{'='*70}")
    print(f"  {cipher['name']}  ({cipher['family']})")
    print(f"  Deployment: {cipher.get('nano_deployment', 'N/A')}")
    print(f"  Full rounds: {full_rounds}, Testing: {info['test_rounds']}")
    print(f"{'='*70}")
    print(f"{'Rounds':>6}  {'CASI':>8}  {'Deep':>8}  {'Ampli':>8}  {'Verdict':>12}  {'Time':>6}")
    print(f"{'-'*6}  {'-'*8}  {'-'*8}  {'-'*8}  {'-'*12}  {'-'*6}")

    for r in info['test_rounds']:
        casi_scores = []
        deep_scores = []
        ampli_scores = []

        t0 = time.time()
        for s in range(N_SEEDS):
            seed = 42 + s * 1000
            data = gen(N_SAMPLES, r, seed=seed)
            keys = np.frombuffer(data, dtype=np.uint8).reshape(-1, 32)

            cs = compute_casi_score(keys)
            casi_scores.append(cs['casi'])
            deep_scores.append(cs['casi_deep'])

            amp = compute_amplified_score(keys)
            ampli_scores.append(amp['casi'])

        dt = time.time() - t0

        avg_casi = np.mean(casi_scores)
        avg_deep = np.mean(deep_scores)
        avg_ampli = np.mean(ampli_scores)
        max_casi = max(avg_casi, avg_ampli)

        if max_casi > 2.0:
            verdict = "DETECTED"
        elif max_casi > 1.5:
            verdict = "WEAK"
        else:
            verdict = "SECURE"

        print(f"{r:>6}  {avg_casi:>8.2f}  {avg_deep:>8.2f}  {avg_ampli:>8.2f}  {verdict:>12}  {dt:>5.1f}s")

        results.append({
            'cipher': name,
            'cipher_name': cipher['name'],
            'rounds': r,
            'full_rounds': full_rounds,
            'casi_mean': round(float(avg_casi), 3),
            'casi_deep_mean': round(float(avg_deep), 3),
            'amplified_mean': round(float(avg_ampli), 3),
            'max_casi': round(float(max_casi), 3),
            'verdict': verdict,
            'n_samples': N_SAMPLES,
            'n_seeds': N_SEEDS,
            'all_casi': [round(float(x), 3) for x in casi_scores],
            'all_ampli': [round(float(x), 3) for x in ampli_scores],
        })

    # Determine frontier
    frontier = None
    for res in reversed(results):
        if res['verdict'] == 'DETECTED':
            frontier = res['rounds']
            break

    print(f"\n  FRONTIER: {'R' + str(frontier) if frontier else 'R0 (no detection)'}")
    print(f"  Full-round CASI: {results[-1]['casi_mean']:.3f} (should be ~1.0)")

    return results, frontier


if __name__ == '__main__':
    print("nano-casi: CASI Characterization of Nano-IoT Ciphers")
    print(f"N={N_SAMPLES} samples, {N_SEEDS} seeds per test")
    print(f"Ciphers: {', '.join(NANO_CIPHERS.keys())}")

    all_results = {}
    frontiers = {}
    t_total = time.time()

    for name, info in NANO_CIPHERS.items():
        results, frontier = run_cipher(name, info)
        all_results[name] = results
        frontiers[name] = frontier

    dt_total = time.time() - t_total

    # Summary
    print(f"\n{'='*70}")
    print(f"  NANO-IoT CASI COVERAGE MATRIX")
    print(f"{'='*70}")
    print(f"{'Cipher':>15}  {'Family':>16}  {'Full':>4}  {'Frontier':>8}  {'Full CASI':>9}  {'Status'}")
    print(f"{'-'*15}  {'-'*16}  {'-'*4}  {'-'*8}  {'-'*9}  {'-'*10}")

    for name in NANO_CIPHERS:
        cipher = CIPHERS[name]
        f = frontiers[name]
        full_casi = all_results[name][-1]['casi_mean']
        status = f"R{f} broken" if f else "CLEAN"
        print(f"{cipher['name']:>15}  {cipher['family']:>16}  {cipher['full_rounds']:>4}  "
              f"{'R'+str(f) if f else 'None':>8}  {full_casi:>9.3f}  {status}")

    print(f"\nTotal time: {dt_total:.1f}s")

    # Save JSON
    output = {
        'meta': {
            'n_samples': N_SAMPLES,
            'n_seeds': N_SEEDS,
            'timestamp': time.strftime('%Y-%m-%d %H:%M:%S'),
        },
        'frontiers': {k: v for k, v in frontiers.items()},
        'results': all_results,
    }
    with open('<legacy-nano-root>/nano_casi_results.json', 'w') as f:
        json.dump(output, f, indent=2)
    print(f"\nResults saved to nano_casi_results.json")

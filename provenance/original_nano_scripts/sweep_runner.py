#!/usr/bin/env python3
"""
sweep_runner.py — Systematic CASI sweep across all nano-IoT ciphers.

Phase 2A: Round-by-round CASI sweep for every cipher and variant.
Phase 2B: Per-strategy breakdown.
Phase 2D: Sample-size sensitivity at frontier.

Output: JSON files per cipher in raw_data/<family>/
"""

import sys
import os
import json
import time
import numpy as np

sys.path.insert(0, '<legacy-live-casi>')
sys.path.insert(0, '<legacy-nano-root>')

from live_casi.core import (
    compute_casi_score, compute_amplified_score,
    compute_signal, compute_deep_signal,
    STRATEGY_NAMES, DEEP_STRATEGY_NAMES,
)
from nano_ciphers import NANO_CIPHER_REGISTRY

BASE_DIR = '<legacy-nano-root>'
RAW_DIR = os.path.join(BASE_DIR, 'raw_data')

N_SAMPLES = 10_000    # Default sample size
N_SEEDS = 5           # Independent seeds per test point


def get_test_rounds(cipher_name, full_rounds):
    """Generate comprehensive round list for a cipher."""
    if full_rounds <= 12:
        return list(range(1, full_rounds + 1))
    elif full_rounds <= 40:
        # Every round up to ~half, then key points
        rounds = list(range(1, min(full_rounds // 2 + 3, full_rounds + 1)))
        # Add remaining key points
        for r in [full_rounds // 2, full_rounds * 3 // 4, full_rounds - 1, full_rounds]:
            if r not in rounds and r > 0:
                rounds.append(r)
        return sorted(set(rounds))
    elif full_rounds <= 72:
        # Sparse for large round counts
        rounds = list(range(1, 13))  # First 12
        rounds.extend(range(14, min(full_rounds + 1, 24), 2))  # Every 2 up to 24
        rounds.extend(range(24, min(full_rounds + 1, 40), 4))  # Every 4 up to 40
        rounds.extend(range(40, full_rounds + 1, max(1, (full_rounds - 40) // 5)))
        rounds.append(full_rounds)
        return sorted(set(rounds))
    else:
        # Very large (KATAN 254, Grain 256)
        rounds = [1, 2, 4, 8, 16, 32, 48, 64, 96, 128, 192]
        rounds.append(full_rounds)
        return sorted(set(r for r in rounds if r <= full_rounds))


def sweep_cipher(cipher_name, cipher_info, n_samples=N_SAMPLES, n_seeds=N_SEEDS):
    """Full round-by-round sweep for one cipher variant."""
    gen = cipher_info['gen']
    full_rounds = cipher_info['full']
    test_rounds = get_test_rounds(cipher_name, full_rounds)

    results = []
    frontier = None
    frontier_ampli = None

    print(f"\n{'='*72}")
    print(f"  {cipher_name}  (block={cipher_info['block']}b, key={cipher_info['key']}b, "
          f"full={full_rounds}R, {cipher_info['family']})")
    print(f"  ISO: {cipher_info['iso']}")
    print(f"  Testing rounds: {test_rounds}")
    print(f"{'='*72}")
    print(f"{'R':>4}  {'CASI':>8}  {'Deep':>8}  {'Ampli':>8}  {'TopStrat':>20}  {'TopVal':>7}  {'Verdict':>10}  {'Time':>6}")
    print(f"{'─'*4}  {'─'*8}  {'─'*8}  {'─'*8}  {'─'*20}  {'─'*7}  {'─'*10}  {'─'*6}")

    for r in test_rounds:
        casi_vals = []
        deep_vals = []
        ampli_vals = []
        all_strategies = {}

        t0 = time.time()
        for s in range(n_seeds):
            seed = 42 + s * 1000
            try:
                data = gen(n_samples, r, seed=seed)
            except Exception as e:
                print(f"  R{r} seed={seed} FAIL: {e}")
                continue

            keys = np.frombuffer(data, dtype=np.uint8).reshape(-1, 32)

            cs = compute_casi_score(keys)
            casi_vals.append(cs['casi'])
            deep_vals.append(cs['casi_deep'])

            # Collect per-strategy signals
            for strat_name, strat_val in cs.get('deep_strategies', {}).items():
                if strat_name not in all_strategies:
                    all_strategies[strat_name] = []
                all_strategies[strat_name].append(strat_val)

            amp = compute_amplified_score(keys)
            ampli_vals.append(amp['casi'])

        if not casi_vals:
            continue

        dt = time.time() - t0
        avg_casi = float(np.mean(casi_vals))
        avg_deep = float(np.mean(deep_vals))
        avg_ampli = float(np.mean(ampli_vals))
        max_casi = max(avg_casi, avg_ampli)

        # Find top strategy
        top_strat = ''
        top_val = 0
        for sname, svals in all_strategies.items():
            m = np.mean(svals)
            if m > top_val:
                top_val = m
                top_strat = sname

        if max_casi > 2.0:
            verdict = "DETECTED"
        elif max_casi > 1.5:
            verdict = "WEAK"
        else:
            verdict = "SECURE"

        print(f"{r:>4}  {avg_casi:>8.2f}  {avg_deep:>8.2f}  {avg_ampli:>8.2f}  "
              f"{top_strat:>20}  {top_val:>7.1f}  {verdict:>10}  {dt:>5.1f}s")

        result = {
            'round': r,
            'n_samples': n_samples,
            'n_seeds': n_seeds,
            'casi_mean': round(avg_casi, 4),
            'casi_deep_mean': round(avg_deep, 4),
            'amplified_mean': round(avg_ampli, 4),
            'max_casi': round(max_casi, 4),
            'verdict': verdict,
            'top_strategy': top_strat,
            'top_strategy_signal': round(float(top_val), 2),
            'per_seed_casi': [round(float(x), 4) for x in casi_vals],
            'per_seed_ampli': [round(float(x), 4) for x in ampli_vals],
            'strategy_means': {k: round(float(np.mean(v)), 2) for k, v in all_strategies.items()},
        }
        results.append(result)

        # Track frontier
        if verdict == 'DETECTED':
            frontier = r

    # Security margin
    security_margin = full_rounds - frontier if frontier else full_rounds
    margin_pct = (security_margin / full_rounds * 100) if full_rounds > 0 else 100

    full_round_casi = results[-1]['casi_mean'] if results else None

    print(f"\n  Frontier: {'R' + str(frontier) if frontier else 'None (CLEAN)'}")
    print(f"  Security margin: {security_margin}/{full_rounds} ({margin_pct:.1f}%)")
    print(f"  Full-round CASI: {full_round_casi}")

    return {
        'cipher': cipher_name,
        'block_size': cipher_info['block'],
        'key_size': cipher_info['key'],
        'full_rounds': full_rounds,
        'family': cipher_info['family'],
        'iso_standard': cipher_info['iso'],
        'n_samples': n_samples,
        'n_seeds': n_seeds,
        'casi_version': 'live-casi 0.9.1',
        'timestamp': time.strftime('%Y-%m-%dT%H:%M:%S'),
        'frontier': frontier,
        'security_margin': security_margin,
        'security_margin_pct': round(margin_pct, 1),
        'full_round_casi': full_round_casi,
        'results': results,
    }


def save_result(data, cipher_name):
    """Save sweep result to appropriate raw_data subdirectory."""
    # Determine family directory
    family_dirs = {
        'ARX-Feistel': 'speck',
        'Feistel-LWC': 'simon',
        'SPN-ultralight': 'present',
        'Sponge-LWC': 'ascon',
        'ARX-block': 'lea',
        'LFSR-NFSR': 'grain128a',
        'SPN-LWC': 'gift',
        'SPN-TBC': 'skinny',
        'LFSR-block': 'katan',
    }
    family = data['family']
    subdir = family_dirs.get(family, 'other')
    dirpath = os.path.join(RAW_DIR, subdir)
    os.makedirs(dirpath, exist_ok=True)

    filepath = os.path.join(dirpath, f'{cipher_name}_full_sweep.json')
    with open(filepath, 'w') as f:
        json.dump(data, f, indent=2)
    print(f"  Saved: {filepath}")
    return filepath


def run_priority_group(group_name, cipher_names, n_samples=N_SAMPLES):
    """Run sweeps for a group of ciphers."""
    print(f"\n{'#'*72}")
    print(f"  PRIORITY GROUP: {group_name}")
    print(f"  Ciphers: {', '.join(cipher_names)}")
    print(f"  N={n_samples}, Seeds={N_SEEDS}")
    print(f"{'#'*72}")

    group_results = {}
    for name in cipher_names:
        if name not in NANO_CIPHER_REGISTRY:
            print(f"  SKIP: {name} not in registry")
            continue
        info = NANO_CIPHER_REGISTRY[name]
        data = sweep_cipher(name, info, n_samples=n_samples)
        save_result(data, name)
        group_results[name] = {
            'frontier': data['frontier'],
            'security_margin': data['security_margin'],
            'security_margin_pct': data['security_margin_pct'],
            'full_round_casi': data['full_round_casi'],
        }
    return group_results


if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument('--group', choices=['p1', 'p2', 'p3', 'p4', 'all'], default='all')
    parser.add_argument('--cipher', type=str, help='Run single cipher by name')
    parser.add_argument('-n', type=int, default=N_SAMPLES, help='Sample size')
    args = parser.parse_args()

    t_total = time.time()

    # Priority groups
    P1 = [  # ISO-standardized RFID ciphers
        'speck32_64', 'speck48_72', 'speck48_96', 'speck64_96', 'speck64_128',
        'speck96_96', 'speck96_144', 'speck128_128', 'speck128_192', 'speck128_256',
        'simon32_64', 'simon48_72', 'simon48_96', 'simon64_96', 'simon64_128',
        'simon96_96', 'simon96_144', 'simon128_128', 'simon128_192', 'simon128_256',
        'present80', 'present128',
    ]
    P2 = [  # NIST/Deployed
        'ascon128', 'ascon128a', 'ascon_hash', 'ascon_xof',
        'lea128', 'lea192', 'lea256',
        'grain128a',
    ]
    P3 = [  # Additional nano-IoT
        'gift64', 'gift128',
        'skinny64_64', 'skinny64_128', 'skinny64_192',
        'skinny128_128', 'skinny128_256', 'skinny128_384',
        'katan32', 'katan48', 'katan64',
    ]

    all_results = {}

    if args.cipher:
        if args.cipher in NANO_CIPHER_REGISTRY:
            info = NANO_CIPHER_REGISTRY[args.cipher]
            data = sweep_cipher(args.cipher, info, n_samples=args.n)
            save_result(data, args.cipher)
        else:
            print(f"Unknown cipher: {args.cipher}")
            print(f"Available: {', '.join(sorted(NANO_CIPHER_REGISTRY.keys()))}")
    elif args.group in ('p1', 'all'):
        all_results.update(run_priority_group('P1: ISO RFID Standards', P1, args.n))
    if args.group in ('p2', 'all') and not args.cipher:
        all_results.update(run_priority_group('P2: NIST/Deployed', P2, args.n))
    if args.group in ('p3', 'all') and not args.cipher:
        all_results.update(run_priority_group('P3: Additional Nano-IoT', P3, args.n))

    if all_results:
        # Save frontier summary
        summary_path = os.path.join(BASE_DIR, 'analysis', 'frontier_summary.json')
        os.makedirs(os.path.dirname(summary_path), exist_ok=True)
        with open(summary_path, 'w') as f:
            json.dump({
                'timestamp': time.strftime('%Y-%m-%dT%H:%M:%S'),
                'n_samples': args.n,
                'n_seeds': N_SEEDS,
                'casi_version': 'live-casi 0.9.1',
                'results': all_results,
            }, f, indent=2)
        print(f"\nFrontier summary saved: {summary_path}")

        # Print summary table
        print(f"\n{'='*80}")
        print(f"  COMPLETE FRONTIER SUMMARY")
        print(f"{'='*80}")
        print(f"{'Cipher':>20}  {'Frontier':>8}  {'Margin':>6}  {'%':>6}  {'Full CASI':>9}")
        print(f"{'─'*20}  {'─'*8}  {'─'*6}  {'─'*6}  {'─'*9}")
        for name in sorted(all_results.keys()):
            r = all_results[name]
            f = r['frontier']
            print(f"{name:>20}  {'R'+str(f) if f else 'CLEAN':>8}  {r['security_margin']:>6}  "
                  f"{r['security_margin_pct']:>5.1f}%  {r['full_round_casi']:>9.3f}")

    dt = time.time() - t_total
    print(f"\nTotal time: {dt:.1f}s ({dt/60:.1f} min)")

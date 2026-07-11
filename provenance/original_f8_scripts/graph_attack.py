#!/usr/bin/env python3
"""Graph-Framework ATTACK RUN — Top combos on frontier ciphers.

Calibration found 11 clean combos (Signal on Speck, no FP on Random).
Now test these on the REAL targets:

PRIORITY 1 (high-value targets):
  - AES-128 R3 (frontier), R4 (beyond frontier)
  - ChaCha20 R3 (frontier), R4 (beyond frontier)
  - Salsa20 R4 (frontier), R5 (beyond frontier)

PRIORITY 2 (academic targets):
  - Threefish-256 R72 (known signal, verify with graph framework)

Higher N=30000 for better sensitivity at the frontier.
"""
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..'))
sys.path.insert(0, os.path.dirname(__file__))

import numpy as np
from graph_sweep import (
    EDGE_DEFS, GRANS, METRICS, sweep_one
)
from live_casiv2.ciphers import (
    generate_chacha_stream, generate_salsa_stream, generate_aes_stream
)
from speck_utils import speck32


# Top 11 combos from calibration
TOP_COMBOS = [
    'chi2/nibbles/max_edge',
    'MI/nibbles/max_edge',
    'MI/nibbles/mean_edge',
    'chi2/nibbles/mean_edge',
    'MI/bytes/max_edge',
    'pearson/nibbles/max_edge',
    'pearson/bytes/max_edge',
    'MI/bytes/mean_edge',
    'pearson/bytes/mean_edge',
    'pearson/nibbles/mean_edge',
    'MI/nibbles/sig_rate',
]

N = 30000
SEEDS = 5
N_PERM = 15


def attack_cipher(name, gen_fn, bb, rounds_list):
    """Run top combos on one cipher at multiple round counts."""
    print(f"\n{'='*80}")
    print(f"  {name}")
    print(f"{'='*80}", flush=True)

    for n_rounds in rounds_list:
        print(f"\n  --- R{n_rounds} ---")
        print(f"  {'Combo':>30}  {'Mean Z':>8}  {'Best Z':>8}  {'Signal?':>10}")
        print("  " + "-" * 65, flush=True)

        # Pre-generate data
        data = {}
        for s in range(SEEDS):
            seed = s * 1000 + 42
            r1 = gen_fn(N, rounds=n_rounds, seed=seed)
            r2 = gen_fn(N, rounds=n_rounds+1, seed=seed)
            data[s] = (r1, r2)

        best_z_overall = -999
        best_combo = ""

        for combo in TOP_COMBOS:
            en, gn, mn = combo.split('/')
            zs = []
            for s in range(SEEDS):
                try:
                    z = sweep_one(data[s][0], data[s][1], bb, en, gn, mn, N_PERM)
                    zs.append(z)
                except:
                    zs.append(0.0)

            mean_z = np.mean(zs)
            best_z = max(zs)
            sig = "YES ***" if mean_z > 3 else ("weak *" if mean_z > 2 else "no")

            if mean_z > 2:
                print(f"  {combo:>30}  {mean_z:>+8.1f}  {best_z:>+8.1f}  {sig}", flush=True)

            if mean_z > best_z_overall:
                best_z_overall = mean_z
                best_combo = combo

        print(f"  BEST: {best_combo} Z={best_z_overall:+.1f}", flush=True)


# ============================================================
# MAIN
# ============================================================

print("=" * 80)
print("GRAPH-FRAMEWORK ATTACK RUN")
print("=" * 80)
print(f"N={N}, {SEEDS} seeds, {N_PERM} perms")
print(f"Testing {len(TOP_COMBOS)} combos on frontier ciphers")
print(flush=True)


# --- PRIORITY 1: AES ---
def aes_gen(N, rounds=10, seed=42):
    return generate_aes_stream(N, rounds=rounds, seed=seed)
attack_cipher("AES-128", aes_gen, 32, [2, 3, 4, 5, 10])

# --- PRIORITY 1: ChaCha ---
def chacha_gen(N, rounds=20, seed=42):
    return generate_chacha_stream(N, rounds=rounds, seed=seed)
attack_cipher("ChaCha20", chacha_gen, 32, [2, 3, 4, 5, 20])

# --- PRIORITY 1: Salsa ---
def salsa_gen(N, rounds=20, seed=42):
    return generate_salsa_stream(N, rounds=rounds, seed=seed)
attack_cipher("Salsa20", salsa_gen, 32, [3, 4, 5, 6, 20])

# --- Speck Reference (verify signal) ---
def speck_gen(N, rounds=22, seed=42):
    raw, bb, bpw = speck32(N, n_rounds=rounds, seed=seed)
    return raw
attack_cipher("Speck 32/64 (reference)", speck_gen, 4, [15, 22])

print("\n=== DONE ===")

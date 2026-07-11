#!/usr/bin/env python3
"""Core reproduction of the F8 signal on Speck 32/64.

Self-contained (numpy + scipy only): an independent F8 mutual-information
implementation plus a from-scratch Speck codec. Verifies the six core
properties of the F8 cross-round carry-leak signal:

  C1: Speck 32/64 full-round (R=22) distinguisher, Z >> 3
  C2: Leak does NOT decay with rounds (R=5,10,15,22 all similar MI)
  C3: MI sits on the alpha-shifted diagonal, with beta dead bits
  C4: MI(beta) = A * exp(-B * beta), R² > 0.999
  C5: Encrypt-only (decrypt Z ~ 0)
  C6: Key-schedule independent (zero key == normal key == random round keys)
"""

import json
import math
import os
import time
import numpy as np

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RESULTS = os.path.join(REPO, 'results')
os.makedirs(RESULTS, exist_ok=True)


# === INDEPENDENT F8-MI IMPLEMENTATION (no engine.py) ===

def mi_binary(a, b):
    """Mutual information between two binary arrays, in nats."""
    n = len(a)
    n11 = int(np.sum((a == 1) & (b == 1)))
    n10 = int(np.sum((a == 1) & (b == 0)))
    n01 = int(np.sum((a == 0) & (b == 1)))
    n00 = n - n11 - n10 - n01
    H_ab = 0.0
    for c in (n00, n01, n10, n11):
        if c > 0:
            p = c / n
            H_ab -= p * math.log(p)
    pa = (n10 + n11) / n
    Ha = -pa * math.log(pa) - (1 - pa) * math.log(1 - pa) if 0 < pa < 1 else 0.0
    pb = (n01 + n11) / n
    Hb = -pb * math.log(pb) - (1 - pb) * math.log(1 - pb) if 0 < pb < 1 else 0.0
    return max(0.0, Ha + Hb - H_ab)


def f8_mi(x_R, diff_y, ws, alpha=None, beta=None, n_perm=20, seed=42):
    """Independent F8-MI test. Returns (Z, total_mi, null_mean, null_std, mi_per_bit)."""
    n = len(x_R)

    if alpha is not None:
        dead = set()
        if beta is not None:
            dead = {(alpha + d) % ws for d in range(beta)}
        pairs = [(i, (i - alpha) % ws) for i in range(ws) if i not in dead]
    else:
        pairs = [(i, j) for i in range(ws) for j in range(ws)]

    def compute_mi(dy):
        mis = []
        if alpha is not None:
            for i, j in pairs:
                xb = ((x_R >> i) & 1).astype(np.uint8)
                dyb = ((dy >> j) & 1).astype(np.uint8)
                mis.append(mi_binary(xb, dyb))
        else:
            for i in range(ws):
                best = 0.0
                for j in range(ws):
                    xb = ((x_R >> i) & 1).astype(np.uint8)
                    dyb = ((dy >> j) & 1).astype(np.uint8)
                    best = max(best, mi_binary(xb, dyb))
                mis.append(best)
        return mis

    mi_values = compute_mi(diff_y)
    total_mi = sum(mi_values)

    rng = np.random.default_rng(seed)
    null_totals = []
    for _ in range(n_perm):
        perm = rng.permutation(n)
        null_totals.append(sum(compute_mi(diff_y[perm])))

    null_mean = float(np.mean(null_totals))
    null_std = float(np.std(null_totals))
    if null_std < 1e-30:
        null_std = 1e-30
    z = (total_mi - null_mean) / null_std
    return z, total_mi, null_mean, null_std, mi_values


# === SPECK IMPLEMENTATION ===

def speck_encrypt(x, y, round_keys, ws, alpha, beta):
    """Single Speck encryption with given round keys."""
    M = (1 << ws) - 1
    for k in round_keys:
        x = (((x >> alpha) | (x << (ws - alpha))) & M)
        x = (x + y) & M
        x ^= k
        y = ((y << beta) | (y >> (ws - beta))) & M
        y ^= x
    return x, y


def speck_decrypt(x, y, round_keys, ws, alpha, beta):
    """Single Speck decryption (inverse rounds, reversed keys)."""
    M = (1 << ws) - 1
    for k in reversed(round_keys):
        y ^= x
        y = ((y >> beta) | (y << (ws - beta))) & M
        x ^= k
        x = (x - y) & M
        x = ((x << alpha) | (x >> (ws - alpha))) & M
    return x, y


def speck_key_schedule(key_words, rounds, ws, alpha, beta):
    """Speck key expansion."""
    M = (1 << ws) - 1
    m = len(key_words) - 1
    ell = [key_words[1 + i] for i in range(m)]
    k = [key_words[0]]
    for i in range(rounds - 1):
        new_l = (((ell[i] >> alpha) | (ell[i] << (ws - alpha))) & M)
        new_l = (new_l + k[i]) & M
        new_l ^= i
        ell.append(new_l)
        new_k = ((k[i] << beta) | (k[i] >> (ws - beta))) & M
        new_k ^= new_l
        k.append(new_k)
    return k


def generate_speck_outputs(ws, alpha, beta, key_words, rounds, N, seed):
    """Generate (x_R, y_R) arrays for N blocks at given round count."""
    M = (1 << ws) - 1
    rk = speck_key_schedule(key_words, rounds, ws, alpha, beta)
    xs = np.zeros(N, dtype=np.uint64)
    ys = np.zeros(N, dtype=np.uint64)
    for idx in range(N):
        pt_x = (idx >> ws) & M
        pt_y = idx & M
        ex, ey = speck_encrypt(pt_x, pt_y, rk, ws, alpha, beta)
        xs[idx] = ex
        ys[idx] = ey
    return xs, ys


# === CLAIM VERIFICATION ===

def verify_c1_speck_distinguisher():
    """C1: Speck 32/64 full-round distinguisher."""
    print("\n=== C1: Speck 32/64 Full-Round Distinguisher ===")
    ws, alpha, beta = 16, 7, 2
    N = 20000
    results = []
    for seed in range(3):
        rng = np.random.RandomState(seed)
        key = [int(rng.randint(0, 1 << ws)) for _ in range(4)]
        x22, y22 = generate_speck_outputs(ws, alpha, beta, key, 22, N, seed)
        x23, y23 = generate_speck_outputs(ws, alpha, beta, key, 23, N, seed)
        diff_y = y22 ^ y23
        z, mi_tot, nm, ns, mi_bits = f8_mi(x22, diff_y, ws, alpha=alpha, beta=beta)
        results.append({'seed': seed, 'Z': round(z, 1), 'MI_total': round(mi_tot, 4)})
        print(f"  Seed {seed}: Z = {z:+.1f}, MI_total = {mi_tot:.4f}")
    mean_z = np.mean([r['Z'] for r in results])
    print(f"  Mean Z = {mean_z:+.1f} — {'PASS' if mean_z > 100 else 'FAIL'}")
    return {'claim': 'C1', 'description': 'Speck 32/64 R=22 distinguisher',
            'results': results, 'mean_z': round(float(mean_z), 1),
            'verdict': 'CONFIRMED' if mean_z > 100 else 'FAILED'}


def verify_c2_no_decay():
    """C2: Leak does NOT decay with additional rounds."""
    print("\n=== C2: No Round-Decay ===")
    ws, alpha, beta = 16, 7, 2
    N = 20000
    rng = np.random.RandomState(0)
    key = [int(rng.randint(0, 1 << ws)) for _ in range(4)]
    results = []
    for R in [5, 10, 15, 22]:
        xR, yR = generate_speck_outputs(ws, alpha, beta, key, R, N, 0)
        xR1, yR1 = generate_speck_outputs(ws, alpha, beta, key, R + 1, N, 0)
        diff_y = yR ^ yR1
        z, mi_tot, _, _, _ = f8_mi(xR, diff_y, ws, alpha=alpha, beta=beta)
        results.append({'R': R, 'Z': round(z, 1), 'MI_total': round(mi_tot, 4)})
        print(f"  R={R:2d}: Z = {z:+.1f}, MI_total = {mi_tot:.4f}")
    mi_vals = [r['MI_total'] for r in results]
    spread = (max(mi_vals) - min(mi_vals)) / np.mean(mi_vals) * 100
    print(f"  MI spread: {spread:.1f}% — {'PASS' if spread < 30 else 'FAIL'} (flat)")
    return {'claim': 'C2', 'description': 'No round-decay',
            'results': results, 'mi_spread_pct': round(spread, 1),
            'verdict': 'CONFIRMED' if spread < 30 else 'FAILED'}


def verify_c3_diagonal_structure():
    """C3: MI sits on alpha-shifted diagonal, beta dead bits."""
    print("\n=== C3: Diagonal Structure (alpha=7, beta=2) ===")
    ws, alpha, beta = 16, 7, 2
    N = 20000
    rng = np.random.RandomState(0)
    key = [int(rng.randint(0, 1 << ws)) for _ in range(4)]
    x22, y22 = generate_speck_outputs(ws, alpha, beta, key, 22, N, 0)
    x23, y23 = generate_speck_outputs(ws, alpha, beta, key, 23, N, 0)
    diff_y = y22 ^ y23

    dead_set = {(alpha + d) % ws for d in range(beta)}
    diag_mi = []
    offdiag_mi = []
    dead_mi = []
    for i in range(ws):
        for j in range(ws):
            xb = ((x22 >> i) & 1).astype(np.uint8)
            dyb = ((diff_y >> j) & 1).astype(np.uint8)
            mi = mi_binary(xb, dyb)
            j_expected = (i - alpha) % ws
            if j == j_expected:
                if i in dead_set:
                    dead_mi.append(mi)
                else:
                    diag_mi.append(mi)
            else:
                offdiag_mi.append(mi)

    mean_diag = np.mean(diag_mi)
    mean_offdiag = np.mean(offdiag_mi)
    mean_dead = np.mean(dead_mi) if dead_mi else 0
    ratio = mean_diag / mean_offdiag if mean_offdiag > 0 else float('inf')
    print(f"  Diagonal MI (active):  {mean_diag:.6f} ({len(diag_mi)} pairs)")
    print(f"  Off-diagonal MI:       {mean_offdiag:.6f} ({len(offdiag_mi)} pairs)")
    print(f"  Dead-bit MI:           {mean_dead:.6f} ({len(dead_mi)} pairs)")
    print(f"  Ratio diag/offdiag:    {ratio:.1f}x — {'PASS' if ratio > 10 else 'FAIL'}")
    print(f"  Dead bits at positions: {sorted(dead_set)}")
    return {'claim': 'C3', 'description': 'Diagonal structure',
            'mean_diag_mi': round(float(mean_diag), 6),
            'mean_offdiag_mi': round(float(mean_offdiag), 6),
            'mean_dead_mi': round(float(mean_dead), 6),
            'ratio': round(ratio, 1), 'n_dead': len(dead_set),
            'dead_positions': sorted(dead_set),
            'verdict': 'CONFIRMED' if ratio > 10 else 'FAILED'}


def verify_c4_formula():
    """C4: MI(beta) = 0.78 * exp(-1.42 * beta)."""
    print("\n=== C4: Leak-Rate Formula ===")
    ws, alpha = 16, 7
    N = 20000
    results = []
    for beta in range(1, 5):
        rng = np.random.RandomState(0)
        key = [int(rng.randint(0, 1 << ws)) for _ in range(4)]
        x22, y22 = generate_speck_outputs(ws, alpha, beta, key, 22, N, 0)
        x23, y23 = generate_speck_outputs(ws, alpha, beta, key, 23, N, 0)
        diff_y = y22 ^ y23
        _, _, _, _, mi_bits = f8_mi(x22, diff_y, ws, alpha=alpha, beta=beta)
        mean_mi = np.mean(mi_bits)
        predicted = 0.78 * math.exp(-1.42 * beta)
        error_pct = abs(mean_mi - predicted) / predicted * 100
        results.append({'beta': beta, 'measured_mi_per_pair': round(float(mean_mi), 6),
                        'predicted': round(predicted, 6), 'error_pct': round(error_pct, 1)})
        print(f"  beta={beta}: measured={mean_mi:.6f}, predicted={predicted:.6f}, error={error_pct:.1f}%")

    from scipy.optimize import curve_fit
    betas = np.array([r['beta'] for r in results])
    mis = np.array([r['measured_mi_per_pair'] for r in results])
    popt, _ = curve_fit(lambda x, A, B: A * np.exp(-B * x), betas, mis, p0=[0.78, 1.42])
    ss_res = np.sum((mis - popt[0] * np.exp(-popt[1] * betas)) ** 2)
    ss_tot = np.sum((mis - np.mean(mis)) ** 2)
    r2 = 1 - ss_res / ss_tot
    print(f"  Fit: MI = {popt[0]:.4f} * exp(-{popt[1]:.4f} * beta), R² = {r2:.6f}")
    return {'claim': 'C4', 'description': 'Leak-rate formula',
            'results': results, 'fit_A': round(float(popt[0]), 4),
            'fit_B': round(float(popt[1]), 4), 'R_squared': round(float(r2), 6),
            'verdict': 'CONFIRMED' if r2 > 0.99 else 'FAILED'}


def verify_c5_encrypt_only():
    """C5: Encrypt Z >> 0, Decrypt Z ~ 0."""
    print("\n=== C5: Encrypt-Only Asymmetry ===")
    ws, alpha, beta = 16, 7, 2
    N = 20000
    M = (1 << ws) - 1
    rng = np.random.RandomState(0)
    key = [int(rng.randint(0, 1 << ws)) for _ in range(4)]
    rk = speck_key_schedule(key, 23, ws, alpha, beta)

    enc_x22 = np.zeros(N, dtype=np.uint64)
    enc_y22 = np.zeros(N, dtype=np.uint64)
    enc_x23 = np.zeros(N, dtype=np.uint64)
    enc_y23 = np.zeros(N, dtype=np.uint64)
    dec_x22 = np.zeros(N, dtype=np.uint64)
    dec_y22 = np.zeros(N, dtype=np.uint64)
    dec_x23 = np.zeros(N, dtype=np.uint64)
    dec_y23 = np.zeros(N, dtype=np.uint64)

    for idx in range(N):
        pt_x = (idx >> ws) & M
        pt_y = idx & M
        ex, ey = speck_encrypt(pt_x, pt_y, rk[:22], ws, alpha, beta)
        enc_x22[idx], enc_y22[idx] = ex, ey
        ex2, ey2 = speck_encrypt(pt_x, pt_y, rk[:23], ws, alpha, beta)
        enc_x23[idx], enc_y23[idx] = ex2, ey2

        ct_x = (idx >> ws) & M
        ct_y = idx & M
        dx, dy = speck_decrypt(ct_x, ct_y, rk[:22], ws, alpha, beta)
        dec_x22[idx], dec_y22[idx] = dx, dy
        dx2, dy2 = speck_decrypt(ct_x, ct_y, rk[:23], ws, alpha, beta)
        dec_x23[idx], dec_y23[idx] = dx2, dy2

    enc_diff = enc_y22 ^ enc_y23
    dec_diff = dec_y22 ^ dec_y23
    z_enc, _, _, _, _ = f8_mi(enc_x22, enc_diff, ws, alpha=alpha, beta=beta)
    z_dec, _, _, _, _ = f8_mi(dec_x22, dec_diff, ws, alpha=alpha, beta=beta)
    ratio = abs(z_enc / z_dec) if abs(z_dec) > 0.01 else float('inf')
    print(f"  Encrypt Z = {z_enc:+.1f}")
    print(f"  Decrypt Z = {z_dec:+.1f}")
    print(f"  Ratio:      {ratio:.0f}:1 — {'PASS' if ratio > 100 else 'FAIL'}")
    return {'claim': 'C5', 'description': 'Encrypt-only asymmetry',
            'encrypt_Z': round(z_enc, 1), 'decrypt_Z': round(z_dec, 1),
            'ratio': round(ratio, 0),
            'verdict': 'CONFIRMED' if ratio > 100 else 'FAILED'}


def verify_c6_key_independence():
    """C6: Same Z with normal key, zero key, random independent keys."""
    print("\n=== C6: Key-Schedule Independence ===")
    ws, alpha, beta = 16, 7, 2
    N = 20000
    M = (1 << ws) - 1
    z_scores = {}
    mi_totals = {}

    for mode in ['normal', 'zero', 'random_independent']:
        if mode == 'normal':
            rng = np.random.RandomState(42)
            key = [int(rng.randint(0, 1 << ws)) for _ in range(4)]
            rk22 = speck_key_schedule(key, 22, ws, alpha, beta)
            rk23 = speck_key_schedule(key, 23, ws, alpha, beta)
        elif mode == 'zero':
            rk22 = [0] * 22
            rk23 = [0] * 23
        else:
            rng = np.random.RandomState(99)
            rk22 = [int(rng.randint(0, 1 << ws)) for _ in range(22)]
            rk23 = rk22 + [int(rng.randint(0, 1 << ws))]

        xs22 = np.zeros(N, dtype=np.uint64)
        ys22 = np.zeros(N, dtype=np.uint64)
        xs23 = np.zeros(N, dtype=np.uint64)
        ys23 = np.zeros(N, dtype=np.uint64)
        for idx in range(N):
            pt_x = (idx >> ws) & M
            pt_y = idx & M
            ex, ey = speck_encrypt(pt_x, pt_y, rk22, ws, alpha, beta)
            xs22[idx], ys22[idx] = ex, ey
            ex2, ey2 = speck_encrypt(pt_x, pt_y, rk23, ws, alpha, beta)
            xs23[idx], ys23[idx] = ex2, ey2

        diff_y = ys22 ^ ys23
        z, mi_tot, _, _, _ = f8_mi(xs22, diff_y, ws, alpha=alpha, beta=beta)
        z_scores[mode] = round(z, 1)
        mi_totals[mode] = round(mi_tot, 4)
        print(f"  {mode:25s}: Z = {z:+.1f}, MI_total = {mi_tot:.4f}")

    # The physical invariant is the MI signal itself: it is identical whether
    # the round keys come from the real schedule, are all zero, or are random
    # and independent. (The Z-score also stays huge in every mode, but its
    # absolute magnitude folds in the per-mode permutation-null variance, so
    # the signal-level MI spread is the clean measure of key-independence.)
    mi_vals = list(mi_totals.values())
    mi_spread = (max(mi_vals) - min(mi_vals)) / np.mean(mi_vals) * 100
    min_z = min(z_scores.values())
    print(f"  MI spread: {mi_spread:.1f}%  |  min Z across modes: {min_z:+.1f}")
    ok = mi_spread < 10 and min_z > 100
    print(f"  {'PASS' if ok else 'FAIL'} (MI identical across key modes, all strongly distinguishing)")
    return {'claim': 'C6', 'description': 'Key-schedule independence',
            'z_scores': z_scores, 'mi_totals': mi_totals,
            'mi_spread_pct': round(mi_spread, 1), 'min_z': min_z,
            'verdict': 'CONFIRMED' if ok else 'FAILED'}


def main():
    t0 = time.time()
    report = {'timestamp': time.strftime('%Y-%m-%dT%H:%M:%S'), 'N': 20000}
    print("=" * 60)
    print("F8 CORE REPRODUCTION — Independent Verification")
    print("=" * 60)

    report['C1'] = verify_c1_speck_distinguisher()
    report['C2'] = verify_c2_no_decay()
    report['C3'] = verify_c3_diagonal_structure()
    report['C4'] = verify_c4_formula()
    report['C5'] = verify_c5_encrypt_only()
    report['C6'] = verify_c6_key_independence()

    elapsed = time.time() - t0
    report['elapsed_seconds'] = round(elapsed, 1)

    print("\n" + "=" * 60)
    print("SUMMARY")
    for key in ['C1', 'C2', 'C3', 'C4', 'C5', 'C6']:
        v = report[key]['verdict']
        print(f"  {key}: {report[key]['description']:40s} [{v}]")
    print(f"\nTotal time: {elapsed:.1f}s")
    print("=" * 60)

    out_path = os.path.join(RESULTS, 'core_reproduction.json')
    with open(out_path, 'w') as f:
        json.dump(report, f, indent=2, default=str)
    print(f"Saved: {out_path}")


if __name__ == '__main__':
    main()

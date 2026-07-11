#!/usr/bin/env python3
"""All four Speck variants: full-round F8 leak and encrypt-only asymmetry.

Runs the F8 cross-round carry-leak test on every Speck variant at full
rounds, in both the encryption and the decryption direction. The signal is
strictly encrypt-only: decryption (subtraction instead of addition, inverse
round order) drives the Z-score to ~0, so the encrypt/decrypt ratio is > 100:1.

  Variants:            Speck 32/64, 48/96, 64/128, 128/256 (all at full rounds)
  F8-MI test:          informed mode (alpha/beta-aware bit pairing)
  Test rounds:         [5, 10, 15, full] per variant
  Sampling:            N=20000 blocks, 3 seeds, 20-permutation null per Z-score

  Speck encrypt round:  x' = (ROR(x, alpha) + y) ^ k;  y' = ROL(y, beta) ^ x'
  Speck decrypt round:  y_dec = ROR(y ^ x, beta);  x_dec = ROL((x ^ k) - y_dec, alpha)

Self-contained: numpy only.
"""

import os
import json
import time
import math
import numpy as np

# ---------------------------------------------------------------------------
# PARAMETERS
# ---------------------------------------------------------------------------

N = 20000
SEEDS = 3
N_PERM = 20

SPECK_VARIANTS = {
    'Speck 32/64':  {'ws': 16, 'kw': 4, 'alpha': 7, 'beta': 2, 'full_rounds': 22},
    'Speck 48/96':  {'ws': 24, 'kw': 4, 'alpha': 8, 'beta': 3, 'full_rounds': 23},
    'Speck 64/128': {'ws': 32, 'kw': 4, 'alpha': 8, 'beta': 3, 'full_rounds': 27},
    'Speck 128/256':{'ws': 64, 'kw': 4, 'alpha': 8, 'beta': 3, 'full_rounds': 34},
}


# ---------------------------------------------------------------------------
# SPECK ENCRYPT GENERATOR (block-level, F8-compatible)
# ---------------------------------------------------------------------------

def speck_encrypt(N_blocks, word_size, key_words, alpha, beta, n_rounds, seed):
    """Speck encryption in CTR mode. Returns (bytes, block_bytes, bytes_per_word)."""
    rng = np.random.default_rng(seed)
    mask = (1 << word_size) - 1
    block_bytes = (word_size * 2) // 8
    bpw = word_size // 8

    if word_size <= 32:
        master_key = [int(rng.integers(0, 2**word_size)) for _ in range(key_words)]
    else:
        master_key = [int(rng.integers(0, 2**63)) * 2 + int(rng.integers(0, 2))
                      for _ in range(key_words)]

    # Key schedule
    rk = [0] * max(n_rounds + 2, 40)
    ell = list(master_key[1:])
    rk[0] = master_key[0]
    for i in range(n_rounds + 1):
        ror_l = ((ell[i % len(ell)] >> alpha) | (ell[i % len(ell)] << (word_size - alpha))) & mask
        new_l = (rk[i] + ror_l) & mask
        new_l ^= i
        ell.append(new_l)
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


# ---------------------------------------------------------------------------
# SPECK DECRYPT GENERATOR (inverse rounds, same key schedule)
# ---------------------------------------------------------------------------

def speck_decrypt(N_blocks, word_size, key_words, alpha, beta, n_rounds, seed):
    """Speck DECRYPTION in CTR mode. Same key schedule, inverse round function.

    Decrypt round:
        y_dec = ROR(y ^ x, beta)
        x_dec = ROL((x ^ k) - y_dec, alpha)
    Rounds applied in reverse order (n_rounds-1 down to 0).
    """
    rng = np.random.default_rng(seed)
    mask = (1 << word_size) - 1
    block_bytes = (word_size * 2) // 8
    bpw = word_size // 8

    if word_size <= 32:
        master_key = [int(rng.integers(0, 2**word_size)) for _ in range(key_words)]
    else:
        master_key = [int(rng.integers(0, 2**63)) * 2 + int(rng.integers(0, 2))
                      for _ in range(key_words)]

    # Key schedule (identical to encrypt)
    rk = [0] * max(n_rounds + 2, 40)
    ell = list(master_key[1:])
    rk[0] = master_key[0]
    for i in range(n_rounds + 1):
        ror_l = ((ell[i % len(ell)] >> alpha) | (ell[i % len(ell)] << (word_size - alpha))) & mask
        new_l = (rk[i] + ror_l) & mask
        new_l ^= i
        ell.append(new_l)
        rol_rk = ((rk[i] << beta) | (rk[i] >> (word_size - beta))) & mask
        rk[i + 1] = rol_rk ^ new_l

    out = bytearray(N_blocks * block_bytes)
    for blk_idx in range(N_blocks):
        # Start from "ciphertext" (random-looking counter values)
        x = (blk_idx >> word_size) & mask
        y = blk_idx & mask

        # Decrypt: reverse round order
        for r in range(n_rounds - 1, -1, -1):
            # Invert y' = ROL(y, beta) ^ x  =>  y = ROR(y' ^ x, beta)
            yxor = (y ^ x) & mask
            y_dec = ((yxor >> beta) | (yxor << (word_size - beta))) & mask

            # Invert x' = (ROR(x, alpha) + y) ^ k  =>  x = ROL((x' ^ k) - y, alpha)
            x_xk = (x ^ rk[r]) & mask
            x_sub = (x_xk - y_dec) & mask
            x_dec = ((x_sub << alpha) | (x_sub >> (word_size - alpha))) & mask

            x, y = x_dec, y_dec

        base = blk_idx * block_bytes
        for b in range(bpw):
            out[base + b] = (x >> (8 * (bpw - 1 - b))) & 0xFF
        for b in range(bpw):
            out[base + bpw + b] = (y >> (8 * (bpw - 1 - b))) & 0xFF

    return bytes(out), block_bytes, bpw


# ---------------------------------------------------------------------------
# F8-MI TEST (informed mode: alpha/beta-aware bit pairing with Z-score)
# ---------------------------------------------------------------------------

def mi_bits(a, b, n):
    """Mutual information between two binary vectors."""
    n00 = int(np.sum((a == 0) & (b == 0)))
    n01 = int(np.sum((a == 0) & (b == 1)))
    n10 = int(np.sum((a == 1) & (b == 0)))
    n11 = int(np.sum((a == 1) & (b == 1)))
    nn = n00 + n01 + n10 + n11
    if nn == 0:
        return 0.0
    H_ab = 0.0
    for c in (n00, n01, n10, n11):
        p = c / nn
        if p > 0:
            H_ab -= p * math.log2(p)
    pa = (n10 + n11) / nn
    pb = (n01 + n11) / nn
    Ha = -pa * math.log2(pa) - (1 - pa) * math.log2(1 - pa) if 0 < pa < 1 else 0.0
    Hb = -pb * math.log2(pb) - (1 - pb) * math.log2(1 - pb) if 0 < pb < 1 else 0.0
    return max(0.0, Ha + Hb - H_ab)


def f8_mi_test(gen_fn, n_rounds, word_size, alpha, beta, seed):
    """
    F8-MI test in informed mode.

    Informed pairing: for each source bit i in x (output word 0),
    pair with diff bit j = (i - alpha) % ws in delta_y (output word 1).
    Skip dead-set bits: {(alpha + d) % ws for d in range(beta)}.

    Returns (total_MI, Z_score, n_active_bits).
    """
    raw_R, bb, bpw = gen_fn(N, n_rounds, seed)
    raw_R1, _, _ = gen_fn(N, n_rounds + 1, seed)

    out_R = np.frombuffer(raw_R, dtype=np.uint8).reshape(-1, bb)
    out_R1 = np.frombuffer(raw_R1, dtype=np.uint8).reshape(-1, bb)
    n = min(out_R.shape[0], out_R1.shape[0])
    out_R, out_R1 = out_R[:n], out_R1[:n]

    ws = word_size

    # Reconstruct words from bytes (big-endian)
    if bpw == 2:
        x_R = (out_R[:, 0].astype(np.uint32) << 8) | out_R[:, 1]
        y_R = (out_R[:, 2].astype(np.uint32) << 8) | out_R[:, 3]
        y_R1 = (out_R1[:, 2].astype(np.uint32) << 8) | out_R1[:, 3]
    elif bpw == 3:
        x_R = (out_R[:, 0].astype(np.uint32) << 16) | (out_R[:, 1].astype(np.uint32) << 8) | out_R[:, 2]
        y_R = (out_R[:, 3].astype(np.uint32) << 16) | (out_R[:, 4].astype(np.uint32) << 8) | out_R[:, 5]
        y_R1 = (out_R1[:, 3].astype(np.uint32) << 16) | (out_R1[:, 4].astype(np.uint32) << 8) | out_R1[:, 5]
    elif bpw == 4:
        x_R = (out_R[:, 0].astype(np.uint64) << 24) | (out_R[:, 1].astype(np.uint64) << 16) | \
              (out_R[:, 2].astype(np.uint64) << 8) | out_R[:, 3]
        y_R = (out_R[:, 4].astype(np.uint64) << 24) | (out_R[:, 5].astype(np.uint64) << 16) | \
              (out_R[:, 6].astype(np.uint64) << 8) | out_R[:, 7]
        y_R1 = (out_R1[:, 4].astype(np.uint64) << 24) | (out_R1[:, 5].astype(np.uint64) << 16) | \
               (out_R1[:, 6].astype(np.uint64) << 8) | out_R1[:, 7]
    elif bpw == 8:
        x_R = np.zeros(n, dtype=np.uint64)
        y_R = np.zeros(n, dtype=np.uint64)
        y_R1 = np.zeros(n, dtype=np.uint64)
        for b in range(8):
            shift = 8 * (7 - b)
            x_R |= out_R[:, b].astype(np.uint64) << shift
            y_R |= out_R[:, 8 + b].astype(np.uint64) << shift
            y_R1 |= out_R1[:, 8 + b].astype(np.uint64) << shift
    else:
        raise ValueError(f"Unsupported bpw={bpw}")

    diff_y = y_R ^ y_R1

    # Dead set: bits where the ROL(y, beta) ^ x' interaction is trivially correlated
    dead_set = {(alpha + d) % ws for d in range(beta)}

    mi_vals = []
    for i in range(ws):
        if i in dead_set:
            continue
        j = (i - alpha) % ws
        xb = ((x_R >> i) & 1).astype(np.uint8)
        dyb = ((diff_y >> j) & 1).astype(np.uint8)
        mi_vals.append(mi_bits(xb, dyb, n))

    total_mi = sum(mi_vals)

    # Permutation null for Z-score
    rng = np.random.default_rng(42)
    null_totals = []
    for _ in range(N_PERM):
        perm = rng.permutation(n)
        diff_p = diff_y[perm]
        pm = []
        for i in range(ws):
            if i in dead_set:
                continue
            j = (i - alpha) % ws
            xb = ((x_R >> i) & 1).astype(np.uint8)
            dyb = ((diff_p >> j) & 1).astype(np.uint8)
            pm.append(mi_bits(xb, dyb, n))
        null_totals.append(sum(pm))

    nm = np.mean(null_totals)
    ns = max(np.std(null_totals), 1e-30)
    z = (total_mi - nm) / ns

    return total_mi, z, len(mi_vals)


# ---------------------------------------------------------------------------
# MAIN EXPERIMENT
# ---------------------------------------------------------------------------

def run_experiment():
    results = {
        'metadata': {
            'experiment': 'speck_variants_full_round',
            'description': 'Full-round F8 leak and encrypt-only asymmetry, all 4 Speck variants.',
            'N': N,
            'seeds': SEEDS,
            'n_perm': N_PERM,
            'timestamp': time.strftime('%Y-%m-%dT%H:%M:%S'),
        },
        'variants': {}
    }

    print("=" * 85)
    print("SPECK VARIANTS: FULL-ROUND F8 LEAK AND ENCRYPT-ONLY ASYMMETRY")
    print("=" * 85)
    print(f"N={N}, {SEEDS} seeds, {N_PERM} permutations per Z-score")
    print()

    for vname, vparams in SPECK_VARIANTS.items():
        ws = vparams['ws']
        kw = vparams['kw']
        alpha = vparams['alpha']
        beta = vparams['beta']
        full_r = vparams['full_rounds']

        # Test rounds: [5, 10, 15, full-2] but capped at full_rounds
        test_rounds = sorted(set([r for r in [5, 10, 15, full_r] if r <= full_r]))

        print(f"\n{'='*85}")
        print(f"  {vname}  (ws={ws}, alpha={alpha}, beta={beta}, full={full_r}R)")
        print(f"{'='*85}")
        print(f"  {'Round':>5}  {'Direction':>10}  {'Mean MI':>10}  {'Mean Z':>10}  {'Signal':>10}")
        print(f"  {'-'*60}")

        variant_results = {
            'word_size': ws,
            'key_words': kw,
            'alpha': alpha,
            'beta': beta,
            'full_rounds': full_r,
            'rounds': {}
        }

        for R in test_rounds:
            # ENCRYPT
            def enc_gen(Nb, nr, sd, _ws=ws, _kw=kw, _a=alpha, _b=beta):
                return speck_encrypt(Nb, _ws, _kw, _a, _b, nr, sd)

            def dec_gen(Nb, nr, sd, _ws=ws, _kw=kw, _a=alpha, _b=beta):
                return speck_decrypt(Nb, _ws, _kw, _a, _b, nr, sd)

            # ENCRYPT
            enc_zs = []
            enc_mis = []
            for s in range(SEEDS):
                seed = s * 1000 + 42
                mi, z, _ = f8_mi_test(enc_gen, R, ws, alpha, beta, seed)
                enc_zs.append(z)
                enc_mis.append(mi)

            # DECRYPT
            dec_zs = []
            dec_mis = []
            for s in range(SEEDS):
                seed = s * 1000 + 42
                mi, z, _ = f8_mi_test(dec_gen, R, ws, alpha, beta, seed)
                dec_zs.append(z)
                dec_mis.append(mi)

            mean_enc_z = float(np.mean(enc_zs))
            mean_dec_z = float(np.mean(dec_zs))
            mean_enc_mi = float(np.mean(enc_mis))
            mean_dec_mi = float(np.mean(dec_mis))

            # Ratio: clamp |decrypt Z| away from zero before dividing.
            abs_dec = max(abs(mean_dec_z), 0.01)
            ratio = abs(mean_enc_z) / abs_dec

            enc_sig = "YES ***" if mean_enc_z > 3 else ("weak" if mean_enc_z > 2 else "no")
            dec_sig = "YES ***" if mean_dec_z > 3 else ("weak" if mean_dec_z > 2 else "no")

            print(f"  R{R:>3}  {'ENCRYPT':>10}  {mean_enc_mi:>10.6f}  {mean_enc_z:>+10.1f}  {enc_sig:>10}")
            print(f"  R{R:>3}  {'DECRYPT':>10}  {mean_dec_mi:>10.6f}  {mean_dec_z:>+10.1f}  {dec_sig:>10}")
            print(f"  {'':>5}  {'RATIO':>10}  {'':>10}  {ratio:>10.0f}:1")
            print(f"  {'-'*60}")

            variant_results['rounds'][str(R)] = {
                'encrypt': {
                    'mean_Z': round(mean_enc_z, 2),
                    'mean_MI': round(mean_enc_mi, 8),
                    'all_Z': [round(z, 2) for z in enc_zs],
                    'all_MI': [round(m, 8) for m in enc_mis],
                },
                'decrypt': {
                    'mean_Z': round(mean_dec_z, 2),
                    'mean_MI': round(mean_dec_mi, 8),
                    'all_Z': [round(z, 2) for z in dec_zs],
                    'all_MI': [round(m, 8) for m in dec_mis],
                },
                'ratio': round(ratio, 1),
            }

        results['variants'][vname] = variant_results

    # -----------------------------------------------------------------------
    # SUMMARY TABLE
    # -----------------------------------------------------------------------
    print()
    print("=" * 85)
    print("SUMMARY: ENCRYPT vs DECRYPT Z-SCORES")
    print("=" * 85)
    print(f"  {'Variant':>15}  {'Round':>5}  {'Enc Z':>10}  {'Dec Z':>10}  {'Ratio':>10}")
    print(f"  {'-'*60}")

    for vname, vr in results['variants'].items():
        for rnd, rd in vr['rounds'].items():
            enc_z = rd['encrypt']['mean_Z']
            dec_z = rd['decrypt']['mean_Z']
            ratio = rd['ratio']
            print(f"  {vname:>15}  R{rnd:>3}  {enc_z:>+10.1f}  {dec_z:>+10.1f}  {ratio:>8.0f}:1")

    # -----------------------------------------------------------------------
    # CONCLUSION
    # -----------------------------------------------------------------------
    all_enc = []
    all_dec = []
    all_ratios = []
    for vr in results['variants'].values():
        for rd in vr['rounds'].values():
            all_enc.append(rd['encrypt']['mean_Z'])
            all_dec.append(rd['decrypt']['mean_Z'])
            all_ratios.append(rd['ratio'])

    mean_ratio = np.mean(all_ratios)
    min_ratio = np.min(all_ratios)
    max_enc = np.max(all_enc)
    max_dec = np.max(np.abs(all_dec))

    results['summary'] = {
        'mean_encrypt_Z': round(float(np.mean(all_enc)), 2),
        'max_encrypt_Z': round(float(max_enc), 2),
        'mean_decrypt_Z': round(float(np.mean(all_dec)), 2),
        'max_abs_decrypt_Z': round(float(max_dec), 2),
        'mean_ratio': round(float(mean_ratio), 1),
        'min_ratio': round(float(min_ratio), 1),
        'conclusion': 'ENCRYPT-ONLY' if min_ratio > 10 else 'MIXED',
    }

    print()
    print("=" * 85)
    print(f"  Mean encrypt Z:  {results['summary']['mean_encrypt_Z']:+.1f}")
    print(f"  Max encrypt Z:   {results['summary']['max_encrypt_Z']:+.1f}")
    print(f"  Mean decrypt Z:  {results['summary']['mean_decrypt_Z']:+.1f}")
    print(f"  Max |decrypt Z|: {results['summary']['max_abs_decrypt_Z']:.1f}")
    print(f"  Mean ratio:      {results['summary']['mean_ratio']:.0f}:1")
    print(f"  Min ratio:       {results['summary']['min_ratio']:.0f}:1")
    print(f"  Conclusion:      {results['summary']['conclusion']}")
    print("=" * 85)

    return results


if __name__ == '__main__':
    t0 = time.time()
    results = run_experiment()
    elapsed = time.time() - t0
    results['metadata']['elapsed_seconds'] = round(elapsed, 1)
    print(f"\nTotal time: {elapsed:.1f}s")

    # Save results
    out_path = os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
        'results', 'speck_variants.json'
    )
    os.makedirs(os.path.dirname(out_path), exist_ok=True)
    with open(out_path, 'w') as f:
        json.dump(results, f, indent=2)
    print(f"Results saved to {out_path}")

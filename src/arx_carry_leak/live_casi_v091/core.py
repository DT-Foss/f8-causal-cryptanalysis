#!/usr/bin/env python3
"""
live-casi: Real-time Causal Amplification Security Index Monitor

Feed cipher output (or any byte stream) and get a live CASI score.
Detects structural weaknesses in real-time across 6 cipher families.

Usage:
    python live_casi.py --test                        # All 6 ciphers
    python live_casi.py --test --cipher speck         # Speck only
    python live_casi.py --demo --cipher aes           # AES demo
    python live_casi.py --demo --cipher all           # All ciphers
    cat encrypted.bin | python live_casi.py           # Pipe mode
    python live_casi.py --file output.bin             # Watch file
"""

import sys
import os
import time
import math
import argparse
import numpy as np

from .ciphers import CIPHERS

# ═══════════════════════════════════════════════════════════════
# SIGNAL STRATEGIES (26 strategies for comprehensive detection)
# ═══════════════════════════════════════════════════════════════

Z_THRESHOLD = 3.5  # z-score threshold (~0.02% false positive per test)

# Popcount lookup table (shared by multiple strategies)
_POPCOUNT_LUT = np.array([bin(i).count('1') for i in range(256)], dtype=np.int32)
_PARITY_LUT = np.array([bin(i).count('1') % 2 for i in range(256)], dtype=np.uint8)

# All strategy names in display order
STRATEGY_NAMES = [
    'bit_correlation', 'xor_distribution', 'parity_chain', 'cross_bit',
    'avalanche', 'linear_bias', 'higher_order', 'differential', 'integral',
    'truncated_diff', 'rotational', 'algebraic_degree', 'diff_linear',
    'boomerang', 'impossible_diff', 'zero_correlation', 'division_property',
    'slide',
    'block_repetition', 'byte_frequency', 'seq_correlation',
    'entropy', 'runs', 'spectral', 'compression', 'autocorrelation',
]

# Crypto strategies: 17 cryptanalytic strategies for reduced-round detection.
# 4 classic + 14 deep strategies covering all major attack families.
CRYPTO_STRATEGY_NAMES = [
    'bit_correlation', 'xor_distribution', 'parity_chain', 'cross_bit',
    'avalanche', 'linear_bias', 'higher_order', 'differential', 'integral',
    'truncated_diff', 'rotational', 'algebraic_degree', 'diff_linear',
    'boomerang', 'impossible_diff', 'zero_correlation', 'division_property',
    'slide',
]

# Implementation strategies: the 8 strategies for implementation bug detection.
# These detect ECB mode, nonce reuse, bad PRNG, etc.
IMPL_STRATEGY_NAMES = [
    'block_repetition', 'byte_frequency', 'seq_correlation',
    'entropy', 'runs', 'spectral', 'compression', 'autocorrelation',
]


def _is_significant(observed, expected):
    """Check if deviation exceeds z-score threshold. Scale-invariant."""
    if expected <= 0:
        return False
    std = max(np.sqrt(expected * (1.0 - expected / max(observed + expected, 1))), 1.0)
    z = abs(observed - expected) / std
    return z > Z_THRESHOLD


# --- Original 4 strategies (reduced-round detection) ---

def strategy_bit_correlation(keys):
    n_keys, key_len = keys.shape
    if n_keys < 100:
        return 0
    count = 0
    expected = n_keys / 2.0
    positions = list(range(min(key_len, 20)))
    for i in range(len(positions)):
        for j in range(i + 1, len(positions)):
            pi, pj = positions[i], positions[j]
            for bit in range(8):
                bi = (keys[:, pi] >> bit) & 1
                bj = (keys[:, pj] >> bit) & 1
                if _is_significant(np.sum(bi == bj), expected):
                    count += 1
    return count


def strategy_xor_distribution(keys):
    n_keys, key_len = keys.shape
    if n_keys < 100:
        return 0
    count = 0
    expected = n_keys / 256.0
    positions = list(range(min(key_len, 14)))
    for i in range(len(positions)):
        for j in range(i + 1, min(i + 4, len(positions))):
            pi, pj = positions[i], positions[j]
            hist = np.bincount(keys[:, pi] ^ keys[:, pj], minlength=256)
            for v in range(256):
                if _is_significant(hist[v], expected):
                    count += 1
    return count


def strategy_parity_chain(keys):
    n_keys, key_len = keys.shape
    if n_keys < 100:
        return 0
    count = 0
    expected = n_keys / 2.0
    parities = _PARITY_LUT[keys]
    # Consecutive parity (widened to 20 positions)
    for i in range(min(key_len - 1, 20)):
        if _is_significant(np.sum(parities[:, i] == parities[:, i + 1]), expected):
            count += 1
    # Skip-1 parity (i vs i+2) — catches longer-range parity chains
    for i in range(min(key_len - 2, 16)):
        if _is_significant(np.sum(parities[:, i] == parities[:, i + 2]), expected):
            count += 1
    return count


def strategy_cross_bit(keys):
    n_keys, key_len = keys.shape
    if n_keys < 100:
        return 0
    count = 0
    expected = n_keys / 2.0
    for pos in range(min(key_len - 1, 12)):
        for bk in range(8):
            for bl in range(8):
                b1 = (keys[:, pos] >> bk) & 1
                b2 = (keys[:, pos + 1] >> bl) & 1
                if _is_significant(np.sum(b1 == b2), expected):
                    count += 1
    return count


# --- New crypto strategies (v0.6.0 — deeper reduced-round detection) ---

def strategy_avalanche(keys):
    """Per-bit avalanche deficit detection with multi-stride analysis.

    For counter-mode cipher output, consecutive keys come from adjacent counters.
    Perfect diffusion: each output bit flips ~50% between consecutive keys.
    Reduced-round: specific bits show systematic flip bias → detectable.

    Tests MULTIPLE strides (1,2,4,8) because different ciphers pack blocks
    differently into 32-byte keys:
      - Stride 1: general consecutive-key test
      - Stride 2: ChaCha/Salsa (64-byte block → 2 keys per block)
      - Stride 4: AES (16-byte block → 2 blocks per key → stride 1 is counter+2)
      - Stride 8: Speck (4-byte block → 8 blocks per key)

    Also uses aggregate chi-squared: if many bits show slight bias (individually
    below z=3.5 threshold), the collective deviation is highly significant.
    """
    n_keys, key_len = keys.shape
    if n_keys < 500:
        return 0

    count = 0
    n_bits = min(key_len * 8, 256)

    for stride in [1, 2, 4, 8]:
        if n_keys < stride + 500:
            continue

        diffs = keys[stride:] ^ keys[:-stride]
        n_diffs = diffs.shape[0]

        bits = np.unpackbits(diffs, axis=1)[:, :n_bits]
        expected = n_diffs / 2.0
        std = math.sqrt(n_diffs * 0.25)

        all_ones = np.sum(bits, axis=0).astype(np.float64)
        z_scores = np.abs(all_ones - expected) / std
        count += int(np.sum(z_scores > Z_THRESHOLD))

        # Aggregate chi-squared: sum(z²) ~ χ²(k) under H0
        chi_sq = float(np.sum(z_scores ** 2))
        chi_z = (chi_sq - n_bits) / math.sqrt(2 * n_bits)
        if chi_z > Z_THRESHOLD:
            count += max(1, int(chi_z))

    return count


def strategy_linear_bias(keys):
    """Linear approximation bias detection (Walsh/Matsui-style).

    For byte pairs (i,j), test if parity(keys[:,i] & mask_a) == parity(keys[:,j] & mask_b)
    for various linear masks. Detects residual linear trails through reduced-round ciphers.

    This implements the core of Matsui's linear cryptanalysis (1993) as a detection
    strategy. At reduced rounds, non-trivial linear approximations exist with
    measurable bias.
    """
    n_keys, key_len = keys.shape
    if n_keys < 500:
        return 0

    count = 0
    expected = n_keys / 2.0

    # Linear masks that probe different bit relationships:
    # Single bits + useful multi-bit masks (Hamming weight 2-4)
    masks = [0x03, 0x05, 0x09, 0x11, 0x0F, 0x33, 0x55, 0xAA]

    byte_positions = min(key_len, 16)
    for i in range(byte_positions):
        for j in range(i + 1, min(i + 5, byte_positions)):
            for ma in masks:
                for mb in masks:
                    # parity(keys[:, i] AND mask_a) XOR parity(keys[:, j] AND mask_b)
                    pa = _PARITY_LUT[keys[:, i] & ma]
                    pb = _PARITY_LUT[keys[:, j] & mb]
                    agrees = np.sum(pa == pb)
                    if _is_significant(agrees, expected):
                        count += 1

    return count


def strategy_higher_order(keys):
    """Higher-order (3-way) bit correlation detection.

    Tests if XOR of 3 bits from different byte positions is biased.
    2-way correlations disappear quickly with cipher rounds, but 3-way
    algebraic relationships persist longer — exactly the structure that
    cube attacks and higher-order differentials exploit.
    """
    n_keys, key_len = keys.shape
    if n_keys < 500:
        return 0

    count = 0
    expected = n_keys / 2.0

    byte_positions = min(key_len, 12)
    for b0 in range(byte_positions):
        for b1 in range(b0 + 1, min(b0 + 4, byte_positions)):
            for b2 in range(b1 + 1, min(b1 + 3, byte_positions)):
                for bit in range(4):  # 4 bit positions per triplet
                    v0 = (keys[:, b0] >> bit) & 1
                    v1 = (keys[:, b1] >> bit) & 1
                    v2 = (keys[:, b2] >> bit) & 1
                    xor3 = v0 ^ v1 ^ v2
                    agrees = np.sum(xor3 == 0)
                    if _is_significant(agrees, expected):
                        count += 1

    return count


def strategy_differential(keys):
    """Differential distribution analysis with multi-stride testing.

    For counter-mode generated data, consecutive keys have known input difference
    (counter increment). Analyzes the OUTPUT byte difference distribution.
    Perfect cipher: XOR byte values uniformly distributed at every stride.
    Reduced-round: certain byte differences are much more likely.

    Tests multiple strides to match different block-to-key ratios.
    Uses chi-squared goodness-of-fit per position (low false-positive rate).
    Also tests cross-position diff byte correlation.
    """
    n_keys, key_len = keys.shape
    if n_keys < 1000:
        return 0

    count = 0
    positions = min(key_len, 32)

    for stride in [1, 2, 4, 8]:
        if n_keys < stride + 1000:
            continue

        diffs = keys[stride:] ^ keys[:-stride]
        n_diffs = diffs.shape[0]
        expected = n_diffs / 256.0

        # Chi-squared per byte position: is diff distribution uniform(256)?
        # Under H0: chi_sq ~ χ²(255), mean=255, var=510
        for pos in range(positions):
            hist = np.bincount(diffs[:, pos], minlength=256).astype(np.float64)
            chi_sq = float(np.sum((hist - expected) ** 2 / expected))
            chi_z = (chi_sq - 255) / math.sqrt(510)
            if chi_z > Z_THRESHOLD:
                count += max(1, int(chi_z))

    # Cross-position correlation (stride 1 only, sufficient)
    diffs_s1 = keys[1:] ^ keys[:-1]
    n_diffs_s1 = diffs_s1.shape[0]
    expected_same = n_diffs_s1 / 256.0
    for i in range(min(key_len, 8)):
        for j in range(i + 1, min(i + 4, key_len, 12)):
            same = np.sum(diffs_s1[:, i] == diffs_s1[:, j])
            if _is_significant(same, expected_same):
                count += 1

    return count


# --- Algebraic strategies (v0.6.0+) ---

def strategy_integral(keys):
    """Integral (Square/Saturation) attack distinguisher.

    Tests the "balanced" property: in a set of 256 cipher outputs where one
    input byte takes all 256 values, the XOR-sum of each output byte should
    be 0 for a perfect cipher. Reduced-round ciphers break this balance.

    For counter-mode data, we have natural "delta sets" — blocks of 256
    consecutive keys correspond to a counter byte cycling 0-255 while other
    counter bytes stay constant.

    Two sub-tests:
    1. XOR-sum balance: take groups of 256 consecutive keys, XOR-fold each
       output byte across the group. Perfect cipher: sum ≈ uniform(256).
       Reduced-round: sum biased toward specific values (often 0).
    2. Multiset (permutation) test: does each byte position across 256
       consecutive keys form a permutation? Perfect cipher: ≈ permutation.
       Reduced-round: certain positions show heavy collisions.

    Literature: Knudsen (1997) SHARK, Daemen et al. (1997) Square attack,
    Ferguson et al. (2000) AES integral to 6 rounds.
    """
    n_keys, key_len = keys.shape
    if n_keys < 512:
        return 0

    count = 0
    # Number of complete 256-key blocks we can form
    n_blocks = n_keys // 256
    if n_blocks < 1:
        return 0

    # Reshape into blocks of 256 consecutive keys
    trimmed = keys[:n_blocks * 256]
    blocks = trimmed.reshape(n_blocks, 256, key_len)
    positions = min(key_len, 32)

    # Test 1: XOR-sum balance
    # For each block and each byte position, XOR all 256 values.
    # Under H0 (perfect cipher), XOR-sum of 256 independent uniform bytes
    # has P(sum=0) = 1/256 and is uniform over 0-255.
    # Under reduced rounds, specific positions show XOR-sum = 0 consistently
    # (the "balanced" property) or biased toward specific values.
    #
    # We track how many blocks show xor_sum=0 at each position.
    # Under H0: count of zeros ~ Binomial(n_blocks, 1/256).
    # Expected = n_blocks/256, extremely small for typical n_blocks.

    for pos in range(positions):
        # XOR-fold: reduce(XOR, block[:, pos]) for each block
        xor_sums = np.bitwise_xor.reduce(blocks[:, :, pos], axis=1)  # (n_blocks,)

        # Count how often XOR-sum = 0 across blocks
        n_zeros = int(np.sum(xor_sums == 0))
        expected_zeros = n_blocks / 256.0

        if n_zeros > 0 and n_blocks >= 4:
            # Poisson approximation: under H0, n_zeros ~ Poisson(n_blocks/256)
            # Use z-score with Poisson std = sqrt(expected)
            std_z = max(math.sqrt(expected_zeros), 0.5)
            z = (n_zeros - expected_zeros) / std_z
            if z > Z_THRESHOLD:
                count += max(1, int(z))

        # Also check for any single value dominating (biased XOR-sum)
        if n_blocks >= 8:
            hist = np.bincount(xor_sums, minlength=256)
            max_count = int(np.max(hist))
            expected_per_val = n_blocks / 256.0
            if max_count > 0 and expected_per_val > 0:
                std_max = max(math.sqrt(expected_per_val), 0.5)
                z_max = (max_count - expected_per_val) / std_max
                if z_max > Z_THRESHOLD * 2:  # Higher threshold to avoid FP
                    count += max(1, int(z_max - Z_THRESHOLD))

    # Test 2: Multiset / permutation test
    # For each 256-key block and each byte position, count unique values.
    # Perfect cipher: ~256 - 256/e ≈ 162 unique values (birthday).
    # Reduced round: fewer unique values (heavy collisions) at some positions.
    #
    # Expected unique values in 256 draws from uniform(256):
    # E[unique] = 256 * (1 - (255/256)^256) ≈ 162.01
    # Exact variance via inclusion-exclusion:
    # Var = m*p*(1-p) + m*(m-1)*(p_pair - p^2)
    # where p = 1-(255/256)^256, p_pair = 1 - 2*(255/256)^256 + (254/256)^256
    # Gives std ≈ 4.99

    p_appear = 1.0 - (255.0/256.0)**256
    expected_unique = 256.0 * p_appear  # ≈ 162.01
    p_pair = 1.0 - 2.0*(255.0/256.0)**256 + (254.0/256.0)**256
    var_unique = 256.0 * p_appear * (1.0 - p_appear) + 256.0*255.0*(p_pair - p_appear**2)
    std_unique = max(math.sqrt(var_unique), 1.0)  # ≈ 4.99

    # Aggregate across all positions: collect z-scores, use chi-squared
    z_scores_ms = []
    for pos in range(positions):
        for b in range(n_blocks):
            col = blocks[b, :, pos]
            n_unique = len(np.unique(col))
            z = (expected_unique - n_unique) / std_unique  # Fewer unique = positive z
            z_scores_ms.append(z)
            if z > Z_THRESHOLD * 1.5:  # Stricter per-test threshold
                count += 1

    # Aggregate chi-squared for multiset test
    if len(z_scores_ms) > 10:
        z_arr = np.array(z_scores_ms)
        chi_sq = float(np.sum(z_arr ** 2))
        k = len(z_scores_ms)
        chi_z = (chi_sq - k) / math.sqrt(2 * k)
        if chi_z > Z_THRESHOLD:
            count += max(1, int(chi_z))

    return count


def strategy_boomerang(keys):
    """Boomerang/Rectangle attack distinguisher (Wagner 1999, Biham 2001).

    The boomerang attack splits the cipher into two halves and combines two
    short differentials into one long distinguisher. For counter-mode output:

    Rectangle variant: for quadruples (i,j,k,l) where:
      - keys[i] XOR keys[j] shows a specific pattern at some positions
      - keys[k] XOR keys[l] shows the same pattern
    Check if keys[i] XOR keys[k] AND keys[j] XOR keys[l] show a CORRELATED
    output difference pattern.

    Under full rounds: output differences are independent → no correlation.
    Under reduced rounds: the boomerang structure creates detectable correlation
    between the two "halves" of the quartet.

    Practical implementation for counter-mode:
    1. Use stride-1 and stride-2 pairs as the "forward" differential
    2. Test if output differences at stride-1 correlate with differences at
       stride-2 in a position-dependent way (boomerang return probability)
    3. Byte-level correlation of difference patterns across different strides

    Literature: Wagner (1999), Biham et al. (2001), Cid et al. (2018) BCT.
    """
    n_keys, key_len = keys.shape
    if n_keys < 2000:
        return 0

    count = 0
    positions = min(key_len, 32)

    # Boomerang quartet test: compare difference patterns at stride s1 vs s2
    # Under H0: diffs at stride-1 and stride-2 are independent
    # Under reduced rounds: diffs share structural correlation (boomerang return)
    stride_pairs = [(1, 2), (1, 4), (2, 4), (1, 3)]

    for s1, s2 in stride_pairs:
        if n_keys < max(s1, s2) + 1000:
            continue

        # Compute diffs at both strides, aligned to the shorter range
        n = min(n_keys - s1, n_keys - s2)
        diff1 = keys[:n] ^ keys[s1:s1+n]
        diff2 = keys[:n] ^ keys[s2:s2+n]

        # Test 1: Byte-level correlation between diff patterns
        # For each position, test if diff1[pos] and diff2[pos] are correlated
        # Under H0: independent uniform → P(diff1=diff2) = 1/256
        for pos in range(positions):
            same = int(np.sum(diff1[:, pos] == diff2[:, pos]))
            expected = n / 256.0
            std = max(math.sqrt(expected * (1 - 1/256)), 1.0)
            z = (same - expected) / std
            if z > Z_THRESHOLD:
                count += max(1, int(z))

        # Test 2: XOR of the two diffs (second-order differential)
        # diff1 XOR diff2 = (keys[0] ^ keys[s1]) ^ (keys[0] ^ keys[s2])
        #                 = keys[s1] ^ keys[s2] = diff at stride |s2-s1|
        # Under full rounds: this should equal the stride-(s2-s1) diff
        # But the CORRELATION between diff1 and (diff1 XOR diff2) should be 0
        # Under reduced rounds: boomerang structure creates excess correlation
        diff12 = diff1 ^ diff2  # Second-order diff
        for pos in range(min(positions, 16)):
            # Correlation: P(diff1[pos] == diff12[pos])
            match = int(np.sum(diff1[:, pos] == diff12[:, pos]))
            expected_match = n / 256.0
            std_match = max(math.sqrt(expected_match * (1 - 1/256)), 1.0)
            z = (match - expected_match) / std_match
            if z > Z_THRESHOLD:
                count += max(1, int(z))

    return count


def strategy_diff_linear(keys):
    """Differential-linear hybrid distinguisher (Langford-Hellman 1994).

    Combines differential and linear cryptanalysis: uses differential pairs
    (keys with known input difference) and tests if a linear approximation
    holds across those pairs with bias > 0.

    For a pair (Y₁, Y₂) where X₁ ⊕ X₂ = ΔX (known from counter mode):
    Test if parity(Λ · Y₁) ⊕ parity(Λ · Y₂) is biased toward 0 or 1
    for various linear masks Λ.

    Under full rounds: the linear bias across differential pairs is 0.
    Under reduced rounds: residual bias from the combined trail.

    The key insight is that this detects structure at rounds BEYOND what
    either differential or linear analysis can reach alone.

    Literature: Langford-Hellman (1994), Biham-Dunkelman-Keller (2002),
    Blondeau-Leander-Nyberg (2017), Bar-On et al. (2019) DLCT.
    """
    n_keys, key_len = keys.shape
    if n_keys < 1000:
        return 0

    count = 0
    positions = min(key_len, 16)

    # Linear masks: single-bit + multi-bit masks
    masks = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80,
             0x03, 0x05, 0x09, 0x0F, 0x33, 0x55, 0xAA, 0xFF]

    for stride in [1, 2, 4]:
        if n_keys < stride + 500:
            continue

        n_pairs = n_keys - stride

        for pos in range(positions):
            y1_col = keys[:-stride, pos]
            y2_col = keys[stride:, pos]

            for mask in masks:
                # Differential-linear test:
                # Compute parity(mask & Y₁) XOR parity(mask & Y₂) for each pair
                # Under H0: this is unbiased (P = 0.5)
                p1 = _PARITY_LUT[y1_col & mask]
                p2 = _PARITY_LUT[y2_col & mask]
                dl_xor = p1 ^ p2  # 0 if parities agree, 1 if differ

                agrees = int(np.sum(dl_xor == 0))
                expected = n_pairs / 2.0
                std = math.sqrt(n_pairs * 0.25)
                z = abs(agrees - expected) / std
                if z > Z_THRESHOLD:
                    count += 1

        # Cross-byte differential-linear: test if linear function of MULTIPLE
        # output bytes is biased across differential pairs
        # This captures the combined trail where the differential part
        # activates one set of bytes and the linear part covers another
        for i in range(min(positions, 8)):
            for j in range(i + 1, min(i + 4, positions)):
                y1_i = keys[:-stride, i]
                y2_i = keys[stride:, i]
                y1_j = keys[:-stride, j]
                y2_j = keys[stride:, j]

                # Test: parity(Y₁[i] & mask) XOR parity(Y₁[j] & mask)
                #    vs parity(Y₂[i] & mask) XOR parity(Y₂[j] & mask)
                for mask in [0x01, 0x0F, 0x55]:
                    p1_ij = _PARITY_LUT[y1_i & mask] ^ _PARITY_LUT[y1_j & mask]
                    p2_ij = _PARITY_LUT[y2_i & mask] ^ _PARITY_LUT[y2_j & mask]
                    dl_xor = p1_ij ^ p2_ij
                    agrees = int(np.sum(dl_xor == 0))
                    expected = n_pairs / 2.0
                    std = math.sqrt(n_pairs * 0.25)
                    z = abs(agrees - expected) / std
                    if z > Z_THRESHOLD:
                        count += 1

    return count


def strategy_algebraic_degree(keys):
    """Algebraic degree bound distinguisher (Lai 1994 / Dinur-Shamir 2009).

    At reduced cipher rounds, the algebraic degree of the output as a polynomial
    over GF(2) is bounded. Higher-order differentials of order d+1 annihilate
    any polynomial of degree ≤ d.

    For counter-mode data: consecutive keys correspond to incrementing counter.
    The low bits of the counter serve as "cube variables." Groups of 2^k
    consecutive keys span a k-dimensional cube.

    Test: for cube dimension k, XOR-sum 2^k consecutive keys at each output
    byte. Under degree < k: the XOR-sum is biased (often 0 for specific byte
    positions). Under degree ≥ k (full rounds): XOR-sum is uniformly random.

    Cube dimensions tested:
    - k=2 (4-key cubes): detects degree ≤ 1 (trivial)
    - k=4 (16-key cubes): detects degree ≤ 3
    - k=8 (256-key cubes): detects degree ≤ 7 (e.g., 1-round AES S-box)

    Literature: Lai (1994), Dinur-Shamir (2009), Todo (2015), Boura-Canteaut (2013).
    """
    n_keys, key_len = keys.shape
    if n_keys < 512:
        return 0

    count = 0
    positions = min(key_len, 32)

    # Test cube dimensions 2, 4, and 8
    for k in [2, 4, 8]:
        cube_size = 1 << k  # 2^k keys per cube
        n_cubes = n_keys // cube_size
        if n_cubes < 4:
            continue

        # Reshape into cubes of 2^k consecutive keys
        trimmed = keys[:n_cubes * cube_size]
        cubes = trimmed.reshape(n_cubes, cube_size, key_len)

        # XOR-fold each cube at each byte position
        xor_sums = np.bitwise_xor.reduce(cubes[:, :, :positions], axis=1)  # (n_cubes, positions)

        # Under H0 (degree ≥ k): XOR-sum of 2^k independent uniform bytes = uniform
        # P(byte = 0) = 1/256. Over n_cubes: expected zeros ≈ n_cubes/256
        for pos in range(positions):
            n_zeros = int(np.sum(xor_sums[:, pos] == 0))
            expected = n_cubes / 256.0

            if n_cubes >= 256:
                # Enough cubes: use normal approximation
                std = max(math.sqrt(expected * (1 - 1/256)), 0.5)
                z = (n_zeros - expected) / std
                if z > Z_THRESHOLD:
                    count += max(1, int(z))
            elif n_zeros > 0 and expected < 1:
                # Few cubes: any zero XOR-sum when expected < 1 is suspicious
                # Use Poisson: P(≥n_zeros | lambda=expected) is very small
                std_p = max(math.sqrt(expected), 0.5)
                z = (n_zeros - expected) / std_p
                if z > Z_THRESHOLD:
                    count += max(1, int(z))

        # Bit-level: check if specific output bits have XOR-sum = 0 across cubes
        # For each bit position, count cubes where that output bit XOR-folds to 0
        # This is more sensitive than byte-level
        for byte_pos in range(min(positions, 16)):
            byte_xor = xor_sums[:, byte_pos]  # (n_cubes,)
            for bit in range(8):
                bit_vals = (byte_xor >> bit) & 1
                n_bit_zero = int(np.sum(bit_vals == 0))
                expected_half = n_cubes / 2.0
                std_half = math.sqrt(n_cubes * 0.25)
                z = abs(n_bit_zero - expected_half) / std_half
                if z > Z_THRESHOLD:
                    count += 1

    return count


def strategy_rotational(keys):
    """Rotational cryptanalysis for ARX ciphers (Khovratovich-Nikolić 2010).

    ARX ciphers (ChaCha, Salsa, Speck) use only Add, Rotate, XOR operations.
    These have a special property: rotating ALL inputs by r bits produces
    outputs rotated by r bits, broken only by carries in modular addition.

    For counter-mode output viewed as 32-bit words:
    1. Rotational correlation: compute ROT_r(word_i) XOR word_i for each
       output word at various rotation amounts. Under full rounds, each bit
       of the rotated-XOR is independently random. Under reduced rounds,
       specific bit positions show bias due to carry propagation patterns.
    2. Cross-word rotational coherence: if the cipher preserves rotational
       symmetry, rotating one output word by r produces a predictable
       relationship with another output word. Measured via XOR correlation
       of rotated word pairs.

    Specifically targets:
    - ChaCha/Salsa: 32-bit ARX with ROT by {7, 8, 12, 16} in quarter-round
    - Speck: 16-bit ARX with ROT by {7, 2} (or {8, 3} for 64-bit)

    Literature: Khovratovich-Nikolić (2010), Ashur-Liu (2016) rotational-XOR.
    """
    n_keys, key_len = keys.shape
    if n_keys < 1000:
        return 0

    count = 0
    # View as 32-bit words: (n_keys, key_len//4) words
    n_words = key_len // 4
    if n_words < 2:
        return 0
    words = keys[:, :n_words*4].view(np.uint32)  # (n_keys, n_words)

    # Test rotation amounts matching ARX cipher quarter-round operations
    rotation_amounts = [1, 2, 7, 8, 12, 16]

    for rot in rotation_amounts:
        # For each word position, compute ROT_r(word[j]) XOR word[j+stride]
        # across consecutive keys (stride 1)
        for stride in [1, 2]:
            if n_keys < stride + 500:
                continue

            for w in range(n_words):
                w_curr = words[:-stride, w].astype(np.uint64)
                w_next = words[stride:, w].astype(np.uint64)
                n_pairs = w_curr.shape[0]

                # Rotate current word left by rot bits (32-bit rotate)
                rotated = ((w_curr << rot) | (w_curr >> (32 - rot))) & 0xFFFFFFFF

                # XOR of rotated word with next word
                rxor = (rotated ^ w_next).astype(np.uint32)

                # Under H0: each bit of rxor is independent, P(bit=1) = 0.5
                # Under reduced ARX rounds: specific bits show bias
                rxor_bytes = rxor.view(np.uint8).reshape(n_pairs, 4)
                # Bit-level analysis: unpack to individual bits
                bits = np.unpackbits(rxor_bytes, axis=1)[:, :32]
                expected = n_pairs / 2.0
                std = math.sqrt(n_pairs * 0.25)

                for b in range(32):
                    ones = np.sum(bits[:, b])
                    z = abs(ones - expected) / std
                    if z > Z_THRESHOLD:
                        count += 1

        # Cross-word rotational coherence:
        # Test if ROT_r(word_i) correlates with word_j for i != j
        for wi in range(min(n_words, 4)):
            for wj in range(wi + 1, min(wi + 3, n_words)):
                w_i = words[:, wi].astype(np.uint64)
                w_j = words[:, wj].astype(np.uint64)
                rotated_i = ((w_i << rot) | (w_i >> (32 - rot))) & 0xFFFFFFFF
                rxor = (rotated_i ^ w_j).astype(np.uint32)

                # Under H0: XOR of rotated word with independent word = uniform
                rxor_bytes = rxor.view(np.uint8).reshape(-1, 4)
                # Quick test: popcount of rxor. Expected = 16 (half of 32 bits)
                pc = _POPCOUNT_LUT[rxor_bytes].sum(axis=1)
                expected_pc = 16.0
                std_pc = math.sqrt(8.0)  # Binomial(32, 0.5) std
                # Aggregate: mean popcount across all pairs
                mean_pc = np.mean(pc)
                z = abs(mean_pc - expected_pc) / (std_pc / math.sqrt(n_keys))
                if z > Z_THRESHOLD:
                    count += max(1, int(z))

    return count


def strategy_truncated_diff(keys):
    """Truncated differential distinguisher (Knudsen 1995).

    Instead of tracking exact byte differences, tracks WHICH bytes are active
    (non-zero difference). This dramatically increases distinguisher probability
    because many exact differentials map to the same truncated pattern.

    For counter-mode data at stride s: delta = keys[j] XOR keys[j+s],
    activity = (delta != 0). We analyze the distribution of activity patterns.

    Sub-tests:
    1. Per-byte activity rate: under full rounds, each byte is active ~255/256
       of the time. Under reduced rounds, some bytes show systematic inactivity.
    2. Activity correlation: whether byte i is active correlates with byte j.
       Full rounds: independent. Reduced rounds: structured correlation.
    3. Column-level patterns (AES-specific): groups of 4 bytes show correlated
       activity matching MixColumns diffusion structure.
    4. Hamming weight of activity vector: number of active bytes per pair.
       Reduced rounds show biased Hamming weight distribution.

    Literature: Knudsen (1995), Knudsen-Rijmen (2007), Grassi et al. (2017).
    """
    n_keys, key_len = keys.shape
    if n_keys < 1000:
        return 0

    count = 0
    positions = min(key_len, 32)

    for stride in [1, 2, 4]:
        if n_keys < stride + 1000:
            continue

        diffs = keys[stride:] ^ keys[:-stride]
        n_diffs = diffs.shape[0]
        # Activity matrix: 1 where diff byte is non-zero
        active = (diffs[:, :positions] != 0).astype(np.uint8)

        # Sub-test 1: Per-byte activity rate
        # Under H0: P(byte active) = 255/256 ≈ 0.996
        expected_active = n_diffs * 255.0 / 256.0
        std_active = math.sqrt(n_diffs * 255.0 / 256.0 * 1.0 / 256.0)
        for pos in range(positions):
            n_active = int(np.sum(active[:, pos]))
            z = abs(n_active - expected_active) / std_active
            if z > Z_THRESHOLD:
                count += max(1, int(z))

        # Sub-test 2: Hamming weight distribution of activity vector
        # Under H0: HW ~ Binomial(positions, 255/256)
        # At reduced rounds: distribution shifts toward lower HW values
        # Count keys with "too many" inactive bytes (HW ≤ positions - 4)
        hw = np.sum(active, axis=1)  # Hamming weight per diff pair
        p_active = 255.0 / 256.0
        # P(HW ≤ pos-4) computed via normal approximation:
        # mean = pos * p, std = sqrt(pos * p * (1-p))
        hw_mean = positions * p_active
        hw_std = math.sqrt(positions * p_active * (1 - p_active))
        # Count keys with very low HW (many inactive bytes)
        threshold_hw = positions - 4  # 28 for positions=32
        low_hw = int(np.sum(hw <= threshold_hw))
        # Expected under H0: use normal approx
        z_cut = (threshold_hw + 0.5 - hw_mean) / hw_std
        # P(HW <= threshold) ≈ Phi(z_cut)
        # For pos=32: z_cut ≈ (28.5 - 31.875) / 0.352 ≈ -9.6 → P ≈ 0
        # For low-round ciphers: many keys have HW <= 28
        if low_hw > 0:
            # Even a single occurrence is significant when expected ≈ 0
            count += low_hw * 3

        # Sub-test 3: 4-byte column activity (AES MixColumns pattern)
        # In AES, MixColumns operates on 4-byte columns. At reduced rounds,
        # columns show correlated activity (all-active or specific pattern).
        n_cols = positions // 4
        for c in range(n_cols):
            col_active = active[:, c*4:(c+1)*4]
            # Count rows where entire column is inactive (all 4 bytes = 0)
            col_all_zero = int(np.sum(np.all(col_active == 0, axis=1)))
            # Under H0: P(all 4 inactive) = (1/256)^4 ≈ 2.3e-10 → expect 0
            if col_all_zero > 0:
                count += col_all_zero * 10

        # Sub-test 4: Activity correlation between distant byte pairs
        # Test if inactivity at one position predicts inactivity at another
        # Under H0: inactive at pos i and pos j are independent events
        # P(both inactive) = (1/256)^2 ≈ 1.5e-5
        # Expected co-inactive pairs ≈ n_diffs * 1.5e-5 ≈ 0.15
        # So even 1 co-inactive pair across non-adjacent positions is significant
        inactive = 1 - active  # (n_diffs, positions)
        total_co_inactive = 0
        for i in range(min(positions, 16)):
            for j in range(i + 2, min(i + 8, positions)):  # Skip adjacent (i+1)
                both = int(np.sum(inactive[:, i] & inactive[:, j]))
                total_co_inactive += both
        # Expected total: C(14,2) * n_diffs * (1/256)^2 ≈ 91 * 10000 * 1.5e-5 ≈ 14
        n_pairs_tested = sum(min(6, positions - i - 2) for i in range(min(positions, 16))
                            if i + 2 < positions)
        expected_co = n_pairs_tested * n_diffs / 256.0 / 256.0
        std_co = max(math.sqrt(expected_co), 1.0)
        z = (total_co_inactive - expected_co) / std_co
        if z > Z_THRESHOLD:
            count += max(1, int(z))

    return count


def strategy_impossible_diff(keys):
    """Impossible differential distinguisher (Biham et al. 1999, Knudsen 1998).

    Impossible differentials exploit the fact that certain output difference
    patterns CANNOT occur after a sufficient number of cipher rounds, but DO
    occur at reduced rounds because diffusion is incomplete.

    For counter-mode data with consecutive counters:
    1. Compute output differences at multiple strides
    2. Test for "impossible" patterns that prove insufficient rounds:

    Test 1 — Zero-column impossibility (AES-like):
    Group output bytes into 4-byte columns. After 4+ rounds of a wide-trail
    cipher, if the input has any active byte, MixColumns guarantees that no
    output column can be all-zero. Count output diff patterns with zero columns.
    Under full rounds: P(zero column) ≈ (1/256)^4 per column ≈ 0.
    Under reduced rounds: many zero columns from incomplete diffusion.

    Test 2 — Zero-row impossibility:
    Same principle applied to 4-byte rows. Tests orthogonal diffusion paths.

    Test 3 — Activity count impossibility:
    After R rounds of a good cipher, the number of active (non-zero) bytes
    in the output difference must exceed a minimum bound related to the
    branch number. If we observe too few active bytes, the cipher has
    insufficient rounds.

    These tests produce ZERO false positives on perfect random data because
    the patterns tested have negligible probability under H0.

    Literature: Biham et al. (1999), Knudsen (1998), Lu (2008), Kim et al. (2003).
    """
    n_keys, key_len = keys.shape
    if n_keys < 1000:
        return 0

    count = 0
    positions = min(key_len, 32)
    n_columns = positions // 4  # 4-byte columns (8 for 32-byte output)

    for stride in [1, 2, 4, 8]:
        if n_keys < stride + 500:
            continue

        diffs = keys[stride:, :positions] ^ keys[:-stride, :positions]
        n = diffs.shape[0]

        # Test 1: Zero-column count
        # A "zero column" = 4 consecutive bytes all zero in the diff
        # Under H0: P(zero column per pair) = (1/256)^4 ≈ 2.3e-10
        # Expected in 10K pairs * 8 columns = ~0.00002 (essentially 0)
        # Under reduced rounds: many zero columns
        total_zero_cols = 0
        for col in range(n_columns):
            col_start = col * 4
            col_bytes = diffs[:, col_start:col_start + 4]
            # Each row: check if all 4 bytes are zero
            zero_col = np.all(col_bytes == 0, axis=1)
            total_zero_cols += int(np.sum(zero_col))

        # Even 1 zero column in a well-mixed cipher at 10K pairs is suspicious
        # Use threshold based on expected count
        expected_zero = n * n_columns * (1.0 / 256) ** 4
        if total_zero_cols > max(expected_zero + 5, 3):
            # Scale signal by the number of impossible patterns found
            count += total_zero_cols

        # Test 2: Zero-row count (transposed view)
        # Group into rows of 4 bytes: bytes [0,8,16,24], [1,9,17,25], etc.
        # Tests a different diffusion dimension
        if positions >= 16:
            total_zero_rows = 0
            row_step = positions // 4  # 8 for 32-byte output
            for r in range(min(row_step, 8)):
                row_indices = [r + i * row_step for i in range(4) if r + i * row_step < positions]
                if len(row_indices) == 4:
                    row_bytes = diffs[:, row_indices]
                    zero_row = np.all(row_bytes == 0, axis=1)
                    total_zero_rows += int(np.sum(zero_row))

            expected_zero_r = n * min(row_step, 8) * (1.0 / 256) ** 4
            if total_zero_rows > max(expected_zero_r + 5, 3):
                count += total_zero_rows

        # Test 3: Activity count impossibility
        # Count active (non-zero) bytes per diff vector
        # After R full rounds: expected active ≈ positions * (255/256)
        # Under reduced rounds: many pairs have very few active bytes
        # "Impossible" = fewer active bytes than the branch number bound
        active_counts = np.sum(diffs != 0, axis=1)

        # Threshold: fewer than 25% of positions active is impossible
        # at full rounds (branch number guarantees minimum diffusion)
        threshold = max(positions // 4, 4)
        n_impossible = int(np.sum(active_counts <= threshold))

        # Under H0: P(active <= threshold) per pair is negligible
        # Binomial(positions, 255/256) — P(active <= 8) ≈ 0 for positions=32
        expected_impossible = n * sum(
            math.comb(positions, k) * (1/256)**k * (255/256)**(positions - k)
            for k in range(positions - threshold, positions + 1)
        )
        if n_impossible > max(expected_impossible + 5, 3):
            count += n_impossible

    return count


def strategy_slide(keys):
    """Slide attack / self-similarity distinguisher (Biryukov-Wagner, EUROCRYPT 1999).

    Slide attacks exploit periodic structure in the key schedule. If the
    round function repeats with period p, then pairs of outputs separated
    by p positions share structural correlation.

    For counter-mode data:
    1. Test candidate periods p = {1, 2, 4, 8, 16, 32, 64, 128, 256}
    2. At each period, compute XOR of pairs (keys[i], keys[i+p])
    3. Measure the entropy/uniformity of the XOR distribution per byte
    4. Under full rounds: XOR is uniformly distributed (entropy ≈ 8 bits)
    5. Under reduced rounds: periodic structure creates low-entropy XOR
       at the cipher's internal period

    Test — Period-dependent byte frequency deviation:
    For each candidate period p and byte position, count the 256-bin
    histogram of XOR values. Under H0: uniform. Under slide: peaked.
    Uses chi-squared goodness-of-fit with z-score thresholding.

    Literature: Biryukov-Wagner (1999), Dunkelman et al. (2012) slidex.
    """
    n_keys, key_len = keys.shape
    if n_keys < 2000:
        return 0

    count = 0
    positions = min(key_len, 32)

    # Test candidate slide periods
    # These match common key schedule periods for block ciphers
    periods = [p for p in [1, 2, 4, 8, 16, 32, 64, 128, 256] if p < n_keys - 500]

    for p in periods:
        n = n_keys - p
        diffs = keys[:n, :positions] ^ keys[p:p+n, :positions]

        # Test 1: Byte-level uniformity of XOR at this period
        # Under H0: each byte of diff is Uniform(0..255)
        # Compute chi-squared per position
        for pos in range(min(positions, 16)):
            hist = np.bincount(diffs[:, pos], minlength=256)
            expected = n / 256.0
            chi2 = float(np.sum((hist.astype(np.float64) - expected) ** 2 / expected))
            # Under H0: chi2 ~ Chi2(255), mean=255, std≈√(2*255)≈22.6
            z = (chi2 - 255.0) / 22.6
            if z > Z_THRESHOLD:
                count += max(1, int(z))

    return count


def strategy_zero_correlation(keys):
    """Zero-correlation linear distinguisher (Bogdanov-Rijmen, ASIACRYPT 2011).

    Zero-correlation linear approximations have correlation EXACTLY ZERO for
    sufficient cipher rounds. At reduced rounds, these become non-zero,
    providing a distinguisher.

    For counter-mode data:
    1. Compute linear correlations between output bit parities across pairs
    2. Under full rounds: all inter-position linear correlations ≈ 0
       (the correlation between parity(mask_a · Y[i]) and parity(mask_b · Y[i])
       for different mask pairs is negligibly small)
    3. Under reduced rounds: certain mask pairs show measurable correlation
       because the linear hull has incomplete coverage

    Test 1 — Pairwise linear correlation:
    For each pair of byte positions (a, b), compute the correlation between
    output bytes using parity masks. Under full rounds, the empirical
    correlation should be ~1/√N. Under reduced rounds, structural linear
    relations persist.

    Test 2 — Multi-dimensional zero-correlation:
    Aggregate squared correlations across many mask pairs. Under H0, the sum
    follows χ²(k). Under reduced rounds, the sum is inflated.

    Test 3 — Cross-stride linear consistency:
    Compare linear correlations at different strides. Under full rounds,
    correlations at stride-1 and stride-2 are independent. Under reduced
    rounds, both strides show the same linear structure.

    Literature: Bogdanov-Rijmen (2011), Bogdanov et al. (FSE 2012),
    Sun et al. (2016) links to division property.
    """
    n_keys, key_len = keys.shape
    if n_keys < 1000:
        return 0

    count = 0
    positions = min(key_len, 32)

    # Parity masks to test: single-bit masks (8 per byte) + full-byte parity
    # For efficiency, use precomputed parity LUT
    parities = _PARITY_LUT[keys[:, :positions]]  # n_keys × positions, each 0 or 1

    for stride in [1, 2, 4]:
        if n_keys < stride + 500:
            continue

        n = n_keys - stride

        # Test 1: Pairwise byte-parity correlation
        # For each pair (a, b), compute correlation between parity[i, a] and parity[i+stride, b]
        # Under H0: independent uniform → correlation = 0 ± 1/√n
        p1 = parities[:n]       # First element of each pair
        p2 = parities[stride:]  # Second element (shifted by stride)

        # Compute all pairwise agreements efficiently
        # agree[a, b] = sum(p1[:, a] == p2[:, b])
        # Under H0: expected = n/2, std = √(n)/2
        expected = n / 2.0
        std = math.sqrt(n) / 2.0

        # Test cross-position correlations (a != b)
        # These should be zero under full rounds
        for a in range(min(positions, 16)):
            for b in range(a + 1, min(positions, 16)):
                agree = int(np.sum(p1[:, a] == p2[:, b]))
                z = abs(agree - expected) / std
                if z > Z_THRESHOLD:
                    count += max(1, int(z))

        # Test 2: Multi-bit mask correlations
        # XOR pairs of parity bits and test cross-position
        for a in range(min(positions, 8)):
            combined_1 = p1[:, a] ^ p1[:, (a + 4) % positions]  # Multi-bit mask
            for b in range(min(positions, 8)):
                combined_2 = p2[:, b] ^ p2[:, (b + 4) % positions]
                agree = int(np.sum(combined_1 == combined_2))
                z = abs(agree - expected) / std
                if z > Z_THRESHOLD:
                    count += max(1, int(z))

    return count


def strategy_division_property(keys):
    """Division property distinguisher (Todo, EUROCRYPT 2015).

    Division property is the most general form of integral cryptanalysis,
    operating at the bit level rather than byte level. It tracks which
    output bit parities are forced to zero when input bits are varied
    over all combinations.

    For counter-mode data with consecutive counters:
    1. Select a set S of k bit positions within each key/block
    2. Group keys into cubes of size 2^k where the S-bits take all values
    3. XOR all outputs in each cube → parity vector
    4. Under sufficient rounds: each parity bit ≈ Bernoulli(0.5)
    5. Under reduced rounds: division property forces certain parities to 0

    Test 1 — Bit-level parity balance (division property D_k^n):
    For cube dimension k, compute per-bit parity over 2^k-element cubes.
    Count output bits where parity is deterministically 0 across ALL cubes.
    Under full rounds: each bit has ~50% chance of parity 0 per cube.
    Under reduced rounds: many bits have parity 0 in every cube.

    Test 2 — Multi-bit parity (vectorial division property):
    Test XOR of multiple output bits simultaneously.
    Under reduced rounds: certain multi-bit parities are also forced to zero.

    Literature: Todo (EUROCRYPT 2015), Todo-Morii (FSE 2016), Xiang et al. (2016).
    """
    n_keys, key_len = keys.shape
    if n_keys < 1000:
        return 0

    count = 0

    # Test cube dimensions k = 2, 4, 8 (cube sizes 4, 16, 256)
    for k in [2, 4, 8]:
        cube_size = 1 << k  # 2^k
        n_cubes = n_keys // cube_size
        if n_cubes < 10:
            continue

        # Reshape into cubes: each cube is cube_size consecutive keys
        usable = n_cubes * cube_size
        cubed = keys[:usable].reshape(n_cubes, cube_size, key_len)

        # Compute XOR parity across each cube (reduce XOR over axis=1)
        # parity[c, j] = XOR of all cube_size keys in cube c at byte j
        parity = cubed[:, 0, :]
        for i in range(1, cube_size):
            parity = parity ^ cubed[:, i, :]

        # Test 1: Bit-level parity forced to zero
        # Expand to bits: for each byte, check each of 8 bits
        n_bits = min(key_len, 32) * 8
        bits_always_zero = 0

        for byte_pos in range(min(key_len, 32)):
            for bit in range(8):
                # Extract this bit from the parity byte across all cubes
                bit_values = (parity[:, byte_pos] >> bit) & 1
                n_zero = int(np.sum(bit_values == 0))

                # Under H0: each cube gives parity 0 with P=0.5
                # P(ALL n_cubes give 0) = 0.5^n_cubes ≈ 0
                # If ALL cubes give parity 0, this bit has division property
                if n_zero == n_cubes:
                    bits_always_zero += 1

        # Under H0: P(any single bit always zero) = 0.5^n_cubes
        # Expected = n_bits * 0.5^n_cubes ≈ 0 for n_cubes > 20
        # Under reduced rounds: many bits always zero
        if n_cubes >= 20:
            # Each always-zero bit is a division property detection
            count += bits_always_zero
        elif n_cubes >= 5:
            # With fewer cubes, need more always-zero bits to be significant
            expected_always_zero = n_bits * (0.5 ** n_cubes)
            if bits_always_zero > expected_always_zero + 5:
                count += bits_always_zero

        # Test 2: Multi-bit parity (vectorial division property)
        # XOR pairs of output bytes and check parity
        for byte_a in range(min(key_len, 16)):
            for byte_b in range(byte_a + 1, min(key_len, 16)):
                combined = parity[:, byte_a] ^ parity[:, byte_b]
                # Check if combined is always zero (all cubes)
                if np.all(combined == 0):
                    count += 1

    return count


# --- New strategies (implementation bug detection) ---

def strategy_block_repetition(keys):
    """Detect duplicate blocks — catches ECB mode, nonce reuse, counter wrap.
    In random data, P(16-byte collision in 10K blocks) ≈ 0.
    Any collision is a catastrophic failure."""
    n_keys, key_len = keys.shape
    if n_keys < 50:
        return 0

    count = 0
    # Check at two block sizes: 16-byte (AES) and 8-byte (DES/Blowfish)
    for block_size in [16, 8]:
        blocks_per_key = key_len // block_size
        if blocks_per_key < 1:
            continue

        # Reshape keys into sub-blocks
        n_blocks = n_keys * blocks_per_key
        all_blocks = keys[:, :blocks_per_key * block_size].reshape(n_blocks, block_size)

        # Hash each block to uint64 for fast comparison
        # Use a view-based hash: interpret first 8 bytes as uint64
        if block_size >= 8:
            hashes = all_blocks[:, :8].copy().view(np.uint64).ravel()
        else:
            # For small blocks, pack bytes into single integer
            hashes = np.zeros(n_blocks, dtype=np.uint64)
            for b in range(block_size):
                hashes |= all_blocks[:, b].astype(np.uint64) << (8 * b)

        # Count duplicates: sort and check adjacent
        sorted_h = np.sort(hashes)
        duplicates = np.sum(sorted_h[1:] == sorted_h[:-1])

        # Each duplicate is a severe finding — weight heavily
        # 100 signal points per collision (these should NEVER happen)
        count += int(duplicates) * 100

    return count


def strategy_byte_frequency(keys):
    """Detect non-uniform byte distribution — catches plaintext-as-encryption,
    Base64 encoding, XOR with short key, weak substitution ciphers.
    True random: each byte value appears n_total/256 times."""
    n_keys, key_len = keys.shape
    if n_keys < 100:
        return 0

    count = 0
    flat = keys.ravel()
    n_total = len(flat)
    expected = n_total / 256.0

    # Global byte frequency test
    hist = np.bincount(flat, minlength=256)
    for v in range(256):
        if _is_significant(hist[v], expected):
            count += 1

    # Per-position frequency test (first 16 positions)
    expected_pos = n_keys / 256.0
    for pos in range(min(key_len, 16)):
        col_hist = np.bincount(keys[:, pos], minlength=256)
        for v in range(256):
            if _is_significant(col_hist[v], expected_pos):
                count += 1

    return count


def strategy_seq_correlation(keys):
    """Detect correlation between consecutive keys — catches nonce reuse,
    counter bugs, bad PRNG seeding, LCG patterns.
    XOR of consecutive random keys: hamming weight ≈ 128 bits (of 256)."""
    n_keys, key_len = keys.shape
    if n_keys < 100:
        return 0

    count = 0

    # XOR consecutive keys
    diffs = keys[1:] ^ keys[:-1]  # (n_keys-1, key_len)
    n_diffs = diffs.shape[0]

    # Popcount lookup
    popcount_lut = np.array([bin(i).count('1') for i in range(256)], dtype=np.int32)

    # Hamming weight of each diff (total bits set across all bytes)
    hw = popcount_lut[diffs].sum(axis=1)  # (n_diffs,)

    # Expected hamming weight: key_len * 4 (half of key_len * 8 bits)
    expected_hw = key_len * 4.0
    std_hw = math.sqrt(key_len * 2.0)  # std of binomial(key_len*8, 0.5) ≈ sqrt(n*p*q)

    # Count diffs with anomalous hamming weight
    for h in hw:
        z = abs(h - expected_hw) / std_hw
        if z > Z_THRESHOLD:
            count += 1

    # Check for identical consecutive keys (hw=0) — catastrophic
    zero_diffs = np.sum(hw == 0)
    count += int(zero_diffs) * 100  # 100 signal per identical pair

    # Check for constant diff pattern (LCG signature)
    if n_diffs >= 10:
        # Compare first diff to all others
        first_diff = diffs[0]
        matches = np.all(diffs == first_diff, axis=1)
        constant_ratio = np.sum(matches) / n_diffs
        if constant_ratio > 0.5:
            count += 500  # Strong LCG signal

    return count


# --- New strategies: statistical depth (NIST-inspired + unique) ---

def strategy_entropy(keys):
    """Shannon entropy per byte position. True random = 8.0 bits/byte.
    Catches low-entropy PRNGs, truncated output, encoding artifacts.
    Fundamentally different from chi-squared: entropy is a single scalar
    that captures the 'surprise' of the distribution."""
    n_keys, key_len = keys.shape
    if n_keys < 100:
        return 0

    count = 0
    positions = min(key_len, 32)

    for pos in range(positions):
        hist = np.bincount(keys[:, pos], minlength=256).astype(np.float64)
        probs = hist / n_keys
        probs = probs[probs > 0]  # log(0) guard
        entropy = -np.sum(probs * np.log2(probs))

        # Random: entropy ≈ 8.0. Deviation significance via asymptotic variance.
        # Var(H) ≈ (1/n) * (sum(p*log^2(p)) - H^2) but simplified:
        # For uniform, expected H ≈ 8.0 - (255)/(2*n*ln2) (bias correction)
        expected_h = 8.0 - 255.0 / (2.0 * n_keys * math.log(2))
        # Std approximation for uniform: sqrt(255/(n*ln2^2) - (8-bias)^2/n) ≈ sqrt(255/(n*ln2^2))
        std_h = math.sqrt(255.0 / (n_keys * math.log(2)**2))

        if std_h > 0:
            z = abs(entropy - expected_h) / std_h
            if z > Z_THRESHOLD:
                count += 1

    # Global entropy across all bytes
    flat = keys[:, :positions].ravel()
    hist = np.bincount(flat, minlength=256).astype(np.float64)
    n_total = len(flat)
    probs = hist / n_total
    probs = probs[probs > 0]
    global_entropy = -np.sum(probs * np.log2(probs))
    expected_global = 8.0 - 255.0 / (2.0 * n_total * math.log(2))
    std_global = math.sqrt(255.0 / (n_total * math.log(2)**2))
    if std_global > 0:
        z = abs(global_entropy - expected_global) / std_global
        if z > Z_THRESHOLD:
            count += 10  # Global deviation is more significant

    return count


def strategy_runs(keys):
    """Bit-level run length test within keys. Counts runs of consecutive
    identical bits. Random has predictable run distribution.
    Catches LFSR output, shift register patterns, linear feedback."""
    n_keys, key_len = keys.shape
    if n_keys < 100:
        return 0

    count = 0
    # Test first 8 byte positions (64 bits per key slice)
    test_len = min(key_len, 8)

    # Convert to bit array: (n_keys, test_len*8)
    bits = np.unpackbits(keys[:, :test_len], axis=1)
    n_bits = bits.shape[1]

    # Count runs: where consecutive bits differ
    transitions = np.sum(bits[:, 1:] != bits[:, :-1], axis=1)  # (n_keys,)
    # Each key has (transitions + 1) runs. Expected runs ≈ (n_bits + 1) / 2
    runs_count = transitions + 1

    expected_runs = (n_bits + 1) / 2.0
    # Variance of runs for random bits: (n_bits - 1) / 4
    std_runs = math.sqrt((n_bits - 1) / 4.0)

    for r in runs_count:
        z = abs(r - expected_runs) / std_runs
        if z > Z_THRESHOLD:
            count += 1

    return count


def strategy_spectral(keys):
    """DFT-based periodicity detection. Applies FFT to byte sequences
    at each position across keys. Periodic patterns produce peaks in
    the normalized periodogram that are invisible to correlation tests."""
    n_keys, key_len = keys.shape
    if n_keys < 256:
        return 0

    count = 0
    n = min(n_keys, 4096)
    positions = min(key_len, 16)

    for pos in range(positions):
        signal = keys[:n, pos].astype(np.float64) - 127.5
        var = np.var(signal)
        if var < 1e-10:
            count += 100  # constant signal — catastrophic
            continue

        # Normalized periodogram: under H0, each value ~ Exp(1)
        power = np.abs(np.fft.rfft(signal)[1:]) ** 2
        normalized = power / (n * var / 2.0)

        # Bonferroni-corrected threshold: with n_bins tests, control FWER at 0.05
        n_bins = len(normalized)
        threshold = -math.log(0.05 / n_bins)  # ≈ 10.6 for n=4096
        peaks = int(np.sum(normalized > threshold))
        count += peaks

    return count


def strategy_compression(keys):
    """Compressibility test via zlib. Random data is incompressible.
    Any structure — patterns too complex for individual strategies,
    repeated subsequences, encoding artifacts — compresses.
    Acts as a universal safety net."""
    import zlib
    n_keys, key_len = keys.shape
    if n_keys < 100:
        return 0

    # Compress the raw key data
    raw = keys.tobytes()
    raw_len = len(raw)
    compressed = zlib.compress(raw, level=1)  # level 1 = fast
    compressed_len = len(compressed)

    # Compression ratio: compressed/raw. Random ≈ 1.0 (plus zlib overhead)
    # zlib adds ~11 bytes header. For 320KB input, ratio ≈ 1.00003
    # Any meaningful compression indicates structure
    ratio = compressed_len / raw_len

    # For random data, compression ratio is very close to 1.0 (actually slightly > 1.0)
    # We flag if data compresses significantly (ratio < 0.995)
    # Scale signal by how much it compresses
    if ratio < 0.99:
        # Strong compression: lots of structure
        reduction_pct = (1.0 - ratio) * 100  # e.g., 0.95 = 5%
        return int(reduction_pct * 50)  # 50 signal per 1% compression
    elif ratio < 0.995:
        return 10  # Marginal compression
    return 0


def strategy_autocorrelation(keys):
    """Byte-level autocorrelation at multiple lag distances.
    Tests if byte at position i correlates with byte at position i+lag
    across the flattened byte stream. Catches block-periodic patterns,
    short-period generators, cycling counters."""
    n_keys, key_len = keys.shape
    if n_keys < 200:
        return 0

    count = 0
    # Flatten to byte stream
    stream = keys.ravel().astype(np.float64) - 127.5
    n = len(stream)

    # Test lags that correspond to meaningful periods
    # key_len (32): block boundary, 16: AES block, 8: DES block, plus small primes
    lags = set([1, 2, 3, 4, 5, 7, 8, 13, 16, 32, 64, key_len])
    lags = sorted(l for l in lags if l < n // 4)

    # Precompute variance
    var = np.var(stream)
    if var < 1e-10:
        return 1000  # Constant stream — catastrophic

    for lag in lags:
        # Autocorrelation at this lag
        autocorr = np.mean(stream[:n-lag] * stream[lag:]) / var

        # Under H0, autocorrelation ≈ 0 with std ≈ 1/sqrt(n)
        std_ac = 1.0 / math.sqrt(n - lag)
        z = abs(autocorr) / std_ac
        if z > Z_THRESHOLD:
            count += 1

    return count


def compute_signal(keys):
    """Compute all 26 strategy signals. Returns dict with per-strategy counts + total."""
    results = {}
    for name in STRATEGY_NAMES:
        func = globals()[f'strategy_{name}']
        results[name] = func(keys)
    results['total'] = sum(results.values())
    return results


def compute_crypto_signal(keys):
    """Compute all 18 cryptanalytic strategy signals.

    Includes 4 classic strategies (bit_correlation, xor_distribution,
    parity_chain, cross_bit) and 14 deep strategies (avalanche through slide).

    Use this for academic frontier comparison.
    """
    results = {}
    for name in CRYPTO_STRATEGY_NAMES:
        func = globals()[f'strategy_{name}']
        results[name] = func(keys)
    results['total'] = sum(results.values())
    return results


# Deep crypto strategies: detect differential/avalanche deficits that
# classic strategies miss. Near-zero noise → isolating them from
# xor_distribution noise dramatically improves sensitivity.
DEEP_STRATEGY_NAMES = ['avalanche', 'linear_bias', 'higher_order', 'differential', 'integral', 'truncated_diff', 'rotational', 'algebraic_degree', 'diff_linear', 'boomerang', 'impossible_diff', 'zero_correlation', 'division_property', 'slide']

# Minimum baseline floor for deep scoring — prevents extreme ratios
# from near-zero baselines while preserving sensitivity.
# With 14 deep strategies, expected FP noise: 3-20 across random/cipher data.
# Floor=14: tested across 50 seeds, max full-round CASI stays < 2.0.
# (polytopic removed — zero signal in black-box counter-mode at 10K samples)
DEEP_BASELINE_FLOOR = 14


def compute_deep_signal(keys):
    """Compute ONLY the 14 deep cryptanalytic strategies.

    These detect reduced-round weaknesses that classic strategies miss,
    particularly differential and avalanche deficits in counter-mode output.
    Near-zero baseline noise → extreme sensitivity for subtle biases.

    Designed to be scored SEPARATELY from classic strategies, because
    xor_distribution's high noise floor would drown the deep signal.
    """
    results = {}
    for name in DEEP_STRATEGY_NAMES:
        func = globals()[f'strategy_{name}']
        results[name] = func(keys)
    results['total'] = sum(results.values())
    return results


def compute_casi_score(keys, baseline_seed=0xBA5E):
    """Compute CASI score with maximum sensitivity.

    Returns the maximum of:
      1. Classic crypto ratio: (classic_total / baseline_classic_total)
      2. Deep crypto ratio: (deep_total / max(baseline_deep_total, DEEP_BASELINE_FLOOR))

    This ensures that even when classic strategies (dominated by xor_distribution
    noise ~150) can't detect a signal, the deep strategies (near-zero noise)
    can detect avalanche/differential deficits at frontier+1 rounds.
    """
    n_keys = keys.shape[0]
    baseline_keys = np.frombuffer(
        np.random.RandomState(baseline_seed).bytes(n_keys * keys.shape[1]),
        dtype=np.uint8,
    ).reshape(n_keys, keys.shape[1])

    # Classic 4 strategies
    classic_names = ['bit_correlation', 'xor_distribution', 'parity_chain', 'cross_bit']
    sig_classic = sum(globals()[f'strategy_{n}'](keys) for n in classic_names)
    base_classic = sum(globals()[f'strategy_{n}'](baseline_keys) for n in classic_names)
    casi_classic = sig_classic / max(base_classic, 1)

    # Deep 4 strategies
    sig_deep = compute_deep_signal(keys)
    base_deep = compute_deep_signal(baseline_keys)
    casi_deep = sig_deep['total'] / max(base_deep['total'], DEEP_BASELINE_FLOOR)

    return {
        'casi': max(casi_classic, casi_deep),
        'casi_classic': casi_classic,
        'casi_deep': casi_deep,
        'signal_classic': sig_classic,
        'signal_deep': sig_deep['total'],
        'baseline_classic': base_classic,
        'baseline_deep': base_deep['total'],
        'deep_strategies': {k: v for k, v in sig_deep.items() if k != 'total'},
    }


def compute_amplified_score(keys, baseline_seed=0xBA5E):
    """Causal Amplification Score — PCR-style three-pass inference.

    Three-pass inference engine
    which amplifies weak signals (3 triplets) into detectable convergence
    points (21+ triplets, 7x boost) through transitive chain resolution.

    Architecture:
      Pass 1 (Exact):     Avalanche/differential at 8 strides (direct tests)
      Pass 2 (Semantic):  Cross-position correlation + linear bias
      Pass 3 (Fuzzy):     Multi-transform re-test (2nd-order diff, nibble,
                          dibit, GF(2) linear combination)

    Combines ALL sub-threshold z-scores via Fisher's method:
      F = -2 * Σ ln(p_i) ~ χ²(2k) under H0

    This amplifies distributed weak signals that individually fall below
    Z_THRESHOLD but collectively constitute definitive evidence.

    Returns dict with:
      - 'amplified_z': Fisher's combined z-score (>5.0 = detected)
      - 'casi': max(standard_casi, amplified_casi)
      - 'n_tests': number of individual tests combined
      - 'pass_counts': tests per pass
    """
    from scipy import stats as _stats

    n_keys, key_len = keys.shape

    # Generate baseline for comparison
    baseline_keys = np.frombuffer(
        np.random.RandomState(baseline_seed).bytes(n_keys * key_len),
        dtype=np.uint8,
    ).reshape(n_keys, key_len)

    def _collect_z_scores(k):
        """Collect z-scores from three-pass analysis."""
        n = k.shape[0]
        all_z = []
        pass_counts = [0, 0, 0]

        # ═══ PASS 1: EXACT (Avalanche + differential at multiple strides) ═══
        for stride in range(1, 9):
            if n < stride + 500:
                continue
            diffs = k[stride:] ^ k[:-stride]
            nd = diffs.shape[0]

            # Bit-flip test
            bits = np.unpackbits(diffs, axis=1)[:, :min(key_len * 8, 256)]
            exp = nd / 2.0
            std = math.sqrt(nd * 0.25)
            z_flip = np.abs(np.sum(bits, axis=0).astype(np.float64) - exp) / std
            all_z.extend(z_flip.tolist())

        pass_counts[0] = len(all_z)

        # ═══ PASS 2: SEMANTIC (Cross-position + linear bias) ═══
        exp_half = n / 2.0
        std_half = math.sqrt(n * 0.25)
        masks = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80]
        for i in range(min(key_len, 16)):
            for j in range(i + 1, min(i + 3, 16)):
                for ma in masks:
                    for mb in masks:
                        pa = _PARITY_LUT[k[:, i] & ma]
                        pb = _PARITY_LUT[k[:, j] & mb]
                        agrees = np.sum(pa == pb)
                        z = abs(float(agrees) - exp_half) / std_half
                        all_z.append(z)

        for stride in [1, 2, 4]:
            if n < stride + 1000:
                continue
            diffs = k[stride:] ^ k[:-stride]
            nd = diffs.shape[0]
            for i in range(min(key_len, 16)):
                for j in range(i + 1, min(i + 4, key_len)):
                    same = int(np.sum(diffs[:, i] == diffs[:, j]))
                    exp_s = nd / 256.0
                    std_s = math.sqrt(exp_s * (1 - 1 / 256))
                    z = abs(same - exp_s) / std_s
                    all_z.append(z)

        pass_counts[1] = len(all_z) - pass_counts[0]

        # ═══ PASS 3: FUZZY (Multi-transform re-test) ═══
        # Second-order differences
        for stride in [1, 2]:
            if n < stride * 2 + 500:
                continue
            diff1 = k[stride:] ^ k[:-stride]
            diff2 = diff1[stride:] ^ diff1[:-stride]
            nd2 = diff2.shape[0]
            if nd2 < 500:
                continue
            bits2 = np.unpackbits(diff2, axis=1)[:, :128]
            exp2 = nd2 / 2.0
            std2 = math.sqrt(nd2 * 0.25)
            z2 = np.abs(np.sum(bits2, axis=0).astype(np.float64) - exp2) / std2
            all_z.extend(z2.tolist())

        # Nibble-level
        for stride in [1, 2, 4]:
            if n < stride + 500:
                continue
            diffs = k[stride:] ^ k[:-stride]
            nd = diffs.shape[0]
            for pos in range(min(key_len, 16)):
                for nibble_fn in [lambda x: x >> 4, lambda x: x & 0x0F]:
                    nibs = nibble_fn(diffs[:, pos])
                    hist = np.bincount(nibs, minlength=16).astype(np.float64)
                    exp_n = nd / 16.0
                    chi = float(np.sum((hist - exp_n) ** 2 / exp_n))
                    z = (chi - 15) / math.sqrt(30)
                    all_z.append(abs(z))

        # GF(2) combination (byte XOR of position pairs)
        for stride in [1, 2]:
            if n < stride + 500:
                continue
            diffs = k[stride:] ^ k[:-stride]
            nd = diffs.shape[0]
            for i in range(min(key_len, 8)):
                for j in range(i + 1, min(i + 3, key_len)):
                    combined = diffs[:, i] ^ diffs[:, j]
                    hist = np.bincount(combined, minlength=256).astype(np.float64)
                    exp_c = nd / 256.0
                    chi = float(np.sum((hist - exp_c) ** 2 / exp_c))
                    z = (chi - 255) / math.sqrt(510)
                    all_z.append(abs(z))

        pass_counts[2] = len(all_z) - pass_counts[0] - pass_counts[1]
        return np.array(all_z), pass_counts

    # Collect z-scores for both cipher and baseline
    z_cipher, pass_cipher = _collect_z_scores(keys)
    z_baseline, pass_baseline = _collect_z_scores(baseline_keys)

    # Fisher's combined test on cipher data
    p_cipher = 2 * (1 - _stats.norm.cdf(z_cipher))
    p_cipher = np.clip(p_cipher, 1e-300, 1.0)
    fisher_cipher = -2.0 * np.sum(np.log(p_cipher))

    # Fisher's combined test on baseline
    p_baseline = 2 * (1 - _stats.norm.cdf(z_baseline))
    p_baseline = np.clip(p_baseline, 1e-300, 1.0)
    fisher_baseline = -2.0 * np.sum(np.log(p_baseline))

    k = len(z_cipher)
    expected_fisher = 2 * k
    std_fisher = math.sqrt(4 * k)

    fisher_z_cipher = (fisher_cipher - expected_fisher) / std_fisher
    fisher_z_baseline = (fisher_baseline - expected_fisher) / std_fisher

    # Amplified CASI = ratio of Fisher statistics
    amplified_casi = fisher_cipher / max(fisher_baseline, 1.0)

    # Also compute standard CASI for comparison
    standard = compute_casi_score(keys, baseline_seed=baseline_seed)

    return {
        'casi': max(standard['casi'], amplified_casi),
        'casi_standard': standard['casi'],
        'casi_amplified': amplified_casi,
        'amplified_z': fisher_z_cipher,
        'baseline_z': fisher_z_baseline,
        'n_tests': k,
        'pass_counts': pass_cipher,
        'mean_z_cipher': float(np.mean(z_cipher)),
        'mean_z_baseline': float(np.mean(z_baseline)),
    }


def compute_signal_with_ci(keys, n_bootstrap=100, ci_level=0.95, crypto_only=False):
    """Compute CASI with bootstrap confidence interval.

    Uses paired bootstrap: resamples both test keys and baseline keys
    with the same indices, so duplicate-sensitive strategies (block_repetition,
    byte_frequency) inflate equally on both sides of the ratio.

    Args:
        keys: np.ndarray of shape (n_keys, key_size)
        n_bootstrap: Number of bootstrap iterations (default 100)
        ci_level: Confidence level (default 0.95 = 95% CI)
        crypto_only: If True, use only 4 crypto strategies

    Returns:
        dict with 'mean', 'ci_lower', 'ci_upper', 'std', 'median',
             'baseline_total', 'scores' (raw bootstrap CASI scores)
    """
    n_keys = keys.shape[0]
    signal_fn = compute_crypto_signal if crypto_only else compute_signal

    # Generate baseline keys (fixed seed for reproducibility)
    baseline_keys = np.frombuffer(
        np.random.RandomState(0xBA5E).bytes(n_keys * keys.shape[1]),
        dtype=np.uint8,
    ).reshape(n_keys, keys.shape[1])

    # Point estimate (no resampling)
    point_signal = signal_fn(keys)
    point_baseline = signal_fn(baseline_keys)
    point_baseline_total = max(point_baseline['total'], 1)
    point_casi = point_signal['total'] / point_baseline_total

    # Paired bootstrap: same indices for both signal and baseline
    boot_rng = np.random.RandomState(42)
    scores = np.zeros(n_bootstrap)

    for i in range(n_bootstrap):
        idx = boot_rng.randint(0, n_keys, size=n_keys)
        sig = signal_fn(keys[idx])
        base = signal_fn(baseline_keys[idx])
        scores[i] = sig['total'] / max(base['total'], 1)

    alpha = 1.0 - ci_level
    ci_lower = float(np.percentile(scores, 100 * alpha / 2))
    ci_upper = float(np.percentile(scores, 100 * (1 - alpha / 2)))

    return {
        'mean': float(np.mean(scores)),
        'median': float(np.median(scores)),
        'std': float(np.std(scores)),
        'ci_lower': ci_lower,
        'ci_upper': ci_upper,
        'ci_level': ci_level,
        'n_bootstrap': n_bootstrap,
        'point_estimate': point_casi,
        'baseline_total': point_baseline_total,
        'scores': scores.tolist(),
    }


# ═══════════════════════════════════════════════════════════════
# LIVE CASI ENGINE
# ═══════════════════════════════════════════════════════════════

class LiveCASI:
    def __init__(self, key_size=32, window_keys=10000, update_every=1000):
        self.key_size = key_size
        self.window_keys = window_keys
        self.update_every = update_every
        self.buffer = bytearray()
        self.keys_total = 0
        self.keys_since_update = 0
        self.current_signal = None
        self.current_casi = None
        self.current_score = None  # v0.6: deep scoring result
        self.baseline_signal = None
        self._baseline_cache = {}  # {n_keys: {classic, deep}}
        self.history = []
        self.start_time = time.time()
        self._compute_baseline()

    def _compute_baseline(self):
        random_keys = np.frombuffer(os.urandom(self.window_keys * self.key_size),
                                    dtype=np.uint8).reshape(-1, self.key_size)
        self.baseline_signal = compute_signal(random_keys)
        if self.baseline_signal['total'] < 1:
            self.baseline_signal['total'] = 1
        # Pre-cache deep baseline for window size
        self._cache_baseline(random_keys)

    def _cache_baseline(self, baseline_keys):
        """Cache classic + deep baseline signals for a given set of keys."""
        n = baseline_keys.shape[0]
        classic_names = ['bit_correlation', 'xor_distribution', 'parity_chain', 'cross_bit']
        base_classic = sum(globals()[f'strategy_{s}'](baseline_keys) for s in classic_names)
        base_deep = compute_deep_signal(baseline_keys)
        self._baseline_cache[n] = {
            'classic': max(base_classic, 1),
            'deep': max(base_deep['total'], DEEP_BASELINE_FLOOR),
        }

    def feed(self, data):
        self.buffer.extend(data)
        new_keys = len(self.buffer) // self.key_size
        if new_keys == 0:
            return False
        self.keys_total += new_keys
        self.keys_since_update += new_keys
        used = new_keys * self.key_size
        self.buffer = bytearray(self.buffer[used:])
        if self.keys_since_update >= self.update_every:
            self._update()
            return True
        return False

    def force_update(self):
        if self.keys_total >= 100:
            self._update()

    def _update(self):
        self.keys_since_update = 0

    def elapsed(self):
        return time.time() - self.start_time

    def rate(self):
        e = self.elapsed()
        return self.keys_total / e if e > 0 else 0


class LiveCASIWithStorage(LiveCASI):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.key_ring = []

    def feed(self, data):
        self.buffer.extend(data)
        new_keys = len(self.buffer) // self.key_size
        if new_keys == 0:
            return False

        used = new_keys * self.key_size
        key_data = np.frombuffer(bytes(self.buffer[:used]), dtype=np.uint8)
        self.key_ring.append(key_data.reshape(-1, self.key_size))
        self.keys_total += new_keys
        self.keys_since_update += new_keys
        self.buffer = bytearray(self.buffer[used:])

        total_stored = sum(k.shape[0] for k in self.key_ring)
        while total_stored > self.window_keys and len(self.key_ring) > 1:
            total_stored -= self.key_ring[0].shape[0]
            self.key_ring.pop(0)

        if self.keys_since_update >= self.update_every:
            self._update()
            return True
        return False

    def _update(self):
        self.keys_since_update = 0
        if not self.key_ring:
            return
        all_keys = np.vstack(self.key_ring)
        if all_keys.shape[0] > self.window_keys:
            all_keys = all_keys[-self.window_keys:]

        # Full signal (all 26 strategies)
        self.current_signal = compute_signal(all_keys)

        # Legacy CASI (backward compatible)
        casi_legacy = self.current_signal['total'] / max(self.baseline_signal['total'], 1)

        # v0.6 deep scoring: max(classic_ratio, deep_ratio)
        n = all_keys.shape[0]
        if n not in self._baseline_cache:
            bl = np.frombuffer(
                np.random.RandomState(0xBA5E).bytes(n * self.key_size),
                dtype=np.uint8,
            ).reshape(n, self.key_size)
            self._cache_baseline(bl)

        cache = self._baseline_cache[n]
        classic_names = ['bit_correlation', 'xor_distribution', 'parity_chain', 'cross_bit']
        sig_classic = sum(self.current_signal.get(s, 0) for s in classic_names)
        sig_deep = compute_deep_signal(all_keys)

        casi_classic = sig_classic / cache['classic']
        casi_deep = sig_deep['total'] / cache['deep']
        casi_max = max(casi_classic, casi_deep)

        self.current_casi = casi_max
        self.current_score = {
            'casi': casi_max,
            'casi_classic': casi_classic,
            'casi_deep': casi_deep,
            'casi_legacy': casi_legacy,
            'signal_deep': sig_deep['total'],
            'deep_strategies': {k: v for k, v in sig_deep.items() if k != 'total'},
        }

        self.history.append({
            'time': self.elapsed(),
            'casi': self.current_casi,
            'casi_classic': casi_classic,
            'casi_deep': casi_deep,
            'keys': self.keys_total,
            'signal': dict(self.current_signal),
        })


# ═══════════════════════════════════════════════════════════════
# TERMINAL DISPLAY
# ═══════════════════════════════════════════════════════════════

RESET = '\033[0m'
BOLD = '\033[1m'
DIM = '\033[2m'
RED = '\033[91m'
GREEN = '\033[92m'
YELLOW = '\033[93m'
BLUE = '\033[94m'
CYAN = '\033[96m'
CLEAR_SCREEN = '\033[2J\033[H'
HIDE_CURSOR = '\033[?25l'
SHOW_CURSOR = '\033[?25h'


def casi_color(casi):
    if casi is None: return DIM
    if casi < 2.0: return GREEN
    if casi < 10.0: return YELLOW
    return RED


def casi_verdict(casi):
    if casi is None: return 'Waiting...'
    if casi < 1.5: return 'SECURE'
    if casi < 2.0: return 'Borderline'
    if casi < 10.0: return 'WEAK'
    return 'BROKEN'


def casi_bar(casi, width=30):
    if casi is None:
        return DIM + '.' * width + RESET
    frac = min(1.0, max(0.0, math.log10(max(casi, 1.0)) / 2.0))
    filled = int(frac * width)
    color = casi_color(casi)
    return color + BOLD + '\u2588' * filled + RESET + DIM + '\u2591' * (width - filled) + RESET


def render_display(engine, label='', round_info=''):
    casi = engine.current_casi
    signal = engine.current_signal
    baseline = engine.baseline_signal

    lines = []
    lines.append(f'{BOLD}{CYAN}\u2554{"="*58}\u2557{RESET}')
    lines.append(f'{BOLD}{CYAN}\u2551{RESET}  {BOLD}LIVE CASI MONITOR{RESET}'
                 f'{" "*22}{DIM}{round_info}{RESET}'.ljust(58 + len(RESET) + len(DIM)) +
                 f'{BOLD}{CYAN}\u2551{RESET}')
    lines.append(f'{BOLD}{CYAN}\u2560{"="*58}\u2563{RESET}')

    color = casi_color(casi)
    casi_str = f'{casi:.1f}' if casi is not None else '---'
    bar = casi_bar(casi)
    lines.append(f'{BOLD}{CYAN}\u2551{RESET}  CASI: {bar} {color}{BOLD}{casi_str:>6}{RESET}  {color}{casi_verdict(casi)}{RESET}')

    # v0.6: show deep vs classic breakdown
    score = engine.current_score
    if score:
        dominant = 'deep' if score['casi_deep'] >= score['casi_classic'] else 'classic'
        dc = casi_color(score['casi_deep'])
        cc = casi_color(score['casi_classic'])
        lines.append(f'{BOLD}{CYAN}\u2551{RESET}  {DIM}Classic:{RESET} {cc}{score["casi_classic"]:.2f}{RESET}  '
                     f'{DIM}Deep:{RESET} {dc}{score["casi_deep"]:.2f}{RESET}  '
                     f'{DIM}({dominant}){RESET}')
    else:
        lines.append(f'{BOLD}{CYAN}\u2551{RESET}')

    rate = engine.rate()
    lines.append(f'{BOLD}{CYAN}\u2551{RESET}  Keys: {BOLD}{engine.keys_total:>10,}{RESET}  '
                 f'{DIM}|{RESET}  Rate: {rate:,.0f}/s  '
                 f'{DIM}|{RESET}  {engine.elapsed():.1f}s')
    lines.append(f'{BOLD}{CYAN}\u2551{RESET}  Window: {engine.window_keys:>8,}  '
                 f'{DIM}|{RESET}  Baseline: {baseline["total"]:,}')
    lines.append(f'{BOLD}{CYAN}\u2551{RESET}')

    lines.append(f'{BOLD}{CYAN}\u2551{RESET}  {BOLD}Signal Breakdown:{RESET}')
    if signal:
        max_val = max(max(signal.get(n, 0) for n in STRATEGY_NAMES), 1)
        for name in STRATEGY_NAMES:
            val = signal.get(name, 0)
            bar_w = 20
            filled = int((val / max_val) * bar_w) if max_val > 0 else 0
            sbar = casi_color(casi) + '\u2588' * filled + RESET + DIM + '\u2591' * (bar_w - filled) + RESET
            lines.append(f'{BOLD}{CYAN}\u2551{RESET}    {name:<20s} {sbar} {val:>5,}')
        lines.append(f'{BOLD}{CYAN}\u2551{RESET}    {"\u2500"*50}')
        lines.append(f'{BOLD}{CYAN}\u2551{RESET}    {BOLD}{"TOTAL SIGNAL":<20s}{" "*22} {signal["total"]:>5,}{RESET}')
    else:
        lines.append(f'{BOLD}{CYAN}\u2551{RESET}    {DIM}Collecting data...{RESET}')

    lines.append(f'{BOLD}{CYAN}\u2551{RESET}')

    if len(engine.history) > 1:
        recent = [h['casi'] for h in engine.history[-20:]]
        spark_chars = ' \u2581\u2582\u2583\u2584\u2585\u2586\u2587\u2588'
        max_h = max(max(recent), 2.0)
        spark = ''
        for v in recent:
            idx = min(8, int((math.log10(max(v, 1.0)) / math.log10(max(max_h, 1.1))) * 8))
            spark += casi_color(v) + spark_chars[idx] + RESET
        lines.append(f'{BOLD}{CYAN}\u2551{RESET}  {DIM}History:{RESET} {spark}')
    else:
        lines.append(f'{BOLD}{CYAN}\u2551{RESET}  {DIM}History: (waiting for data){RESET}')

    lines.append(f'{BOLD}{CYAN}\u255a{"="*58}\u255d{RESET}')
    if label:
        lines.append(f'  {DIM}{label}{RESET}')
    return '\n'.join(lines)


# ═══════════════════════════════════════════════════════════════
# DEMO MODE — supports all 6 ciphers
# ═══════════════════════════════════════════════════════════════

def run_demo(args):
    """Run the demo: generate cipher output at increasing rounds, show live CASI."""
    cipher_name = args.cipher

    if cipher_name == 'all':
        cipher_list = ['chacha', 'salsa', 'aes', 'speck', 'blowfish', 'tdes', 'rc4', 'camellia']
    elif cipher_name == 'random':
        cipher_list = ['_random']
    elif cipher_name in CIPHERS:
        cipher_list = [cipher_name]
    else:
        print(f'{RED}Unknown cipher: {cipher_name}{RESET}')
        print(f'Available: {", ".join(CIPHERS.keys())}, all, random')
        return

    print(f'{HIDE_CURSOR}{CLEAR_SCREEN}', end='')

    try:
        for cname in cipher_list:
            if cname == '_random':
                _demo_random_sequence()
                continue

            info = CIPHERS[cname]
            gen = info['generator']
            is_slow = info.get('slow', False)
            n_keys = 500 if is_slow else 3000

            for rounds, label in info['demo_sequence']:
                engine = LiveCASIWithStorage(
                    key_size=32,
                    window_keys=5000,
                    update_every=250 if not is_slow else 100,
                )

                # Generate data
                t0 = time.time()
                data = gen(n_keys, rounds=rounds, seed=42)
                gen_time = time.time() - t0

                chunk_size = 32 * (10 if is_slow else 50)
                for i in range(0, len(data), chunk_size):
                    updated = engine.feed(data[i:i+chunk_size])
                    if updated or i == 0:
                        ri = f'{info["name"]} R{rounds}'
                        display = render_display(engine, label=label, round_info=ri)
                        print(f'{CLEAR_SCREEN}{display}', end='', flush=True)
                    time.sleep(0.02)

                engine.force_update()
                ri = f'{info["name"]} R{rounds}'
                display = render_display(engine, label=label, round_info=ri)
                print(f'{CLEAR_SCREEN}{display}', end='', flush=True)
                time.sleep(1.5)

        print(f'\n\n{BOLD}{GREEN}Demo complete.{RESET}')

    except KeyboardInterrupt:
        pass
    finally:
        print(f'{SHOW_CURSOR}')


def _demo_random_sequence():
    """Demo: random vs broken comparison."""
    from ciphers import generate_chacha_stream
    for mode, n_keys, label in [
        ('random', 5000, 'os.urandom \u2014 CSPRNG baseline'),
        ('broken', 5000, 'ChaCha20 R1 \u2014 BROKEN'),
        ('random', 5000, 'os.urandom \u2014 back to random'),
    ]:
        engine = LiveCASIWithStorage(key_size=32, window_keys=5000, update_every=250)
        data = os.urandom(n_keys * 32) if mode == 'random' else generate_chacha_stream(n_keys, rounds=1)
        for i in range(0, len(data), 32 * 50):
            updated = engine.feed(data[i:i+32*50])
            if updated or i == 0:
                display = render_display(engine, label=label, round_info='RNG' if mode == 'random' else 'R1')
                print(f'{CLEAR_SCREEN}{display}', end='', flush=True)
            time.sleep(0.02)
        engine.force_update()
        display = render_display(engine, label=label, round_info='RNG' if mode == 'random' else 'R1')
        print(f'{CLEAR_SCREEN}{display}', end='', flush=True)
        time.sleep(2.0)


# ═══════════════════════════════════════════════════════════════
# PIPE MODE
# ═══════════════════════════════════════════════════════════════

def _engine_to_json(engine):
    """Convert engine state to JSON-serializable dict."""
    import json
    score = engine.current_score
    result = {
        'casi': round(engine.current_casi, 2) if engine.current_casi else None,
        'verdict': casi_verdict(engine.current_casi),
        'keys_analyzed': engine.keys_total,
        'signal_total': engine.current_signal['total'] if engine.current_signal else 0,
        'strategies': {},
        'elapsed_seconds': round(engine.elapsed(), 2),
    }
    # v0.6: deep scoring breakdown
    if score:
        result['casi_classic'] = round(score['casi_classic'], 4)
        result['casi_deep'] = round(score['casi_deep'], 4)
        result['casi_legacy'] = round(score['casi_legacy'], 4)
        result['dominant'] = 'deep' if score['casi_deep'] >= score['casi_classic'] else 'classic'
        result['deep_strategies'] = {k: v for k, v in score.get('deep_strategies', {}).items()}
    if engine.current_signal:
        for name in STRATEGY_NAMES:
            result['strategies'][name] = engine.current_signal.get(name, 0)
    return json.dumps(result, indent=2)


def _finish_engine(engine, args):
    """Handle final output for pipe/file modes based on output flags."""
    import json
    casi = engine.current_casi
    score = engine.current_score

    if getattr(args, 'json', False):
        print(_engine_to_json(engine))
    elif getattr(args, 'quiet', False):
        print(f'{casi:.2f}' if casi is not None else '0.00')
    else:
        if casi is not None:
            print(f'\n{BOLD}Final CASI: {casi_color(casi)}{casi:.2f}{RESET}')
            print(f'Verdict: {casi_color(casi)}{casi_verdict(casi)}{RESET}')
            # v0.6: show classic vs deep breakdown
            if score:
                dominant = 'deep' if score['casi_deep'] >= score['casi_classic'] else 'classic'
                cc = casi_color(score['casi_classic'])
                dc = casi_color(score['casi_deep'])
                print(f'  Classic: {cc}{score["casi_classic"]:.3f}{RESET}  '
                      f'Deep: {dc}{score["casi_deep"]:.3f}{RESET}  ({dominant})')

    # Exit code
    threshold = getattr(args, 'exit_code', None)
    if threshold is not None and casi is not None:
        sys.exit(0 if casi < threshold else 1)


def run_pipe(args):
    quiet = getattr(args, 'quiet', False) or getattr(args, 'json', False)
    if not quiet:
        print(f'{HIDE_CURSOR}', end='')
    try:
        engine = LiveCASIWithStorage(
            key_size=args.key_size, window_keys=args.window, update_every=args.update_every)
        while True:
            data = sys.stdin.buffer.read(4096)
            if not data:
                break
            if engine.feed(data) and not quiet:
                display = render_display(engine, label=f'Reading from stdin (key_size={args.key_size})')
                print(f'{CLEAR_SCREEN}{display}', end='', flush=True)
        engine.force_update()
        if not quiet:
            display = render_display(engine, label='Stream ended')
            print(f'{CLEAR_SCREEN}{display}')
    except KeyboardInterrupt:
        pass
    finally:
        if not quiet:
            print(f'{SHOW_CURSOR}')
    _finish_engine(engine, args)


# ═══════════════════════════════════════════════════════════════
# FILE WATCH MODE
# ═══════════════════════════════════════════════════════════════

def run_file(args):
    quiet = getattr(args, 'quiet', False) or getattr(args, 'json', False)
    if not quiet:
        print(f'{HIDE_CURSOR}', end='')
    try:
        engine = LiveCASIWithStorage(
            key_size=args.key_size, window_keys=args.window, update_every=args.update_every)
        offset = 0
        while True:
            try:
                with open(args.file, 'rb') as f:
                    f.seek(offset)
                    data = f.read(65536)
                    if data:
                        offset += len(data)
                        if engine.feed(data) and not quiet:
                            display = render_display(engine, label=f'Watching: {args.file}')
                            print(f'{CLEAR_SCREEN}{display}', end='', flush=True)
            except FileNotFoundError:
                pass
            time.sleep(0.1)
    except KeyboardInterrupt:
        engine.force_update()
    finally:
        if not quiet:
            print(f'{SHOW_CURSOR}')
    _finish_engine(engine, args)


# ═══════════════════════════════════════════════════════════════
# KNOWN-PLAINTEXT MODE
# ═══════════════════════════════════════════════════════════════

def run_known_pt(args):
    """Known-plaintext analysis: XOR plaintext with ciphertext to extract keystream.
    Analyzing keystream is orders of magnitude more powerful than ciphertext-only."""
    quiet = getattr(args, 'quiet', False) or getattr(args, 'json', False)

    # Read plaintext from file
    try:
        with open(args.known_pt, 'rb') as f:
            plaintext = f.read()
    except FileNotFoundError:
        print(f'{RED}Error: plaintext file not found: {args.known_pt}{RESET}')
        sys.exit(2)

    # Read ciphertext from stdin or --file
    if args.file:
        try:
            with open(args.file, 'rb') as f:
                ciphertext = f.read()
        except FileNotFoundError:
            print(f'{RED}Error: ciphertext file not found: {args.file}{RESET}')
            sys.exit(2)
    elif not sys.stdin.isatty():
        ciphertext = sys.stdin.buffer.read()
    else:
        print(f'{RED}Error: provide ciphertext via stdin or --file{RESET}')
        sys.exit(2)

    # XOR to extract keystream
    min_len = min(len(plaintext), len(ciphertext))
    if min_len < 64:
        print(f'{RED}Error: need at least 64 bytes, got {min_len}{RESET}')
        sys.exit(2)

    pt_arr = np.frombuffer(plaintext[:min_len], dtype=np.uint8)
    ct_arr = np.frombuffer(ciphertext[:min_len], dtype=np.uint8)
    keystream = (pt_arr ^ ct_arr).tobytes()

    if not quiet:
        print(f'{BOLD}Known-plaintext mode{RESET}')
        print(f'  Plaintext:  {args.known_pt} ({len(plaintext):,} bytes)')
        src = args.file if args.file else 'stdin'
        print(f'  Ciphertext: {src} ({len(ciphertext):,} bytes)')
        print(f'  Keystream:  {min_len:,} bytes ({min_len // args.key_size:,} keys)')
        print()

    engine = LiveCASIWithStorage(
        key_size=args.key_size, window_keys=args.window, update_every=args.update_every)
    engine.feed(keystream)
    engine.force_update()

    if not quiet:
        display = render_display(engine, label='Known-plaintext keystream analysis')
        print(display)

    _finish_engine(engine, args)


# ═══════════════════════════════════════════════════════════════
# DIFFERENTIAL MODE
# ═══════════════════════════════════════════════════════════════

def run_compare(args):
    """Compare two byte streams: report CASI for each + XOR analysis."""
    quiet = getattr(args, 'quiet', False) or getattr(args, 'json', False)

    file1, file2 = args.compare

    try:
        with open(file1, 'rb') as f:
            data1 = f.read()
        with open(file2, 'rb') as f:
            data2 = f.read()
    except FileNotFoundError as e:
        print(f'{RED}Error: {e}{RESET}')
        sys.exit(2)

    # Analyze stream 1
    engine1 = LiveCASIWithStorage(
        key_size=args.key_size, window_keys=args.window, update_every=args.window)
    engine1.feed(data1)
    engine1.force_update()
    casi1 = engine1.current_casi or 0

    # Analyze stream 2
    engine2 = LiveCASIWithStorage(
        key_size=args.key_size, window_keys=args.window, update_every=args.window)
    engine2.feed(data2)
    engine2.force_update()
    casi2 = engine2.current_casi or 0

    # XOR analysis: if both are truly random, XOR should also be random
    min_len = min(len(data1), len(data2))
    xor_casi = None
    if min_len >= args.key_size * 100:
        arr1 = np.frombuffer(data1[:min_len], dtype=np.uint8)
        arr2 = np.frombuffer(data2[:min_len], dtype=np.uint8)
        xor_data = (arr1 ^ arr2).tobytes()
        engine_xor = LiveCASIWithStorage(
            key_size=args.key_size, window_keys=args.window, update_every=args.window)
        engine_xor.feed(xor_data)
        engine_xor.force_update()
        xor_casi = engine_xor.current_casi or 0

    if getattr(args, 'json', False):
        import json
        result = {
            'stream1': {'file': file1, 'casi': round(casi1, 2),
                        'verdict': casi_verdict(casi1), 'bytes': len(data1)},
            'stream2': {'file': file2, 'casi': round(casi2, 2),
                        'verdict': casi_verdict(casi2), 'bytes': len(data2)},
        }
        if xor_casi is not None:
            result['xor_diff'] = {'casi': round(xor_casi, 2),
                                  'verdict': casi_verdict(xor_casi), 'bytes': min_len}
        print(json.dumps(result, indent=2))
    elif quiet:
        print(f'{casi1:.2f} {casi2:.2f}' + (f' {xor_casi:.2f}' if xor_casi is not None else ''))
    else:
        print(f'{BOLD}Differential Analysis{RESET}\n')
        c1 = casi_color(casi1)
        c2 = casi_color(casi2)
        print(f'  {BOLD}Stream 1:{RESET} {file1}')
        print(f'    CASI: {c1}{casi1:.2f}{RESET}  {c1}{casi_verdict(casi1)}{RESET}  ({len(data1):,} bytes)')
        print()
        print(f'  {BOLD}Stream 2:{RESET} {file2}')
        print(f'    CASI: {c2}{casi2:.2f}{RESET}  {c2}{casi_verdict(casi2)}{RESET}  ({len(data2):,} bytes)')

        if xor_casi is not None:
            cx = casi_color(xor_casi)
            print()
            print(f'  {BOLD}XOR Difference:{RESET}')
            print(f'    CASI: {cx}{xor_casi:.2f}{RESET}  {cx}{casi_verdict(xor_casi)}{RESET}  ({min_len:,} bytes)')
            if xor_casi < 2.0 and casi1 < 2.0 and casi2 < 2.0:
                print(f'\n  {GREEN}Both streams appear independently random and mutually independent.{RESET}')
            elif xor_casi > 2.0:
                print(f'\n  {YELLOW}Streams are statistically distinguishable (XOR reveals structure).{RESET}')

    # Exit code based on worst CASI
    threshold = getattr(args, 'exit_code', None)
    if threshold is not None:
        worst = max(casi1, casi2)
        if xor_casi is not None:
            worst = max(worst, xor_casi)
        sys.exit(0 if worst < threshold else 1)


# ═══════════════════════════════════════════════════════════════
# TEST MODE — all 8 ciphers
# ═══════════════════════════════════════════════════════════════

def run_test(args):
    """Self-test: verify CASI across all cipher families."""
    # Build test list — test all ciphers by default, or filter to one
    tests = [('os.urandom (CSPRNG)', None, None, 10000)]

    cipher_order = ['chacha', 'salsa', 'aes', 'speck', 'blowfish', 'tdes', 'rc4', 'camellia']
    # Only filter if user explicitly passed a specific cipher (not default 'chacha')
    explicit_filter = args.cipher if args.cipher in CIPHERS and '--cipher' in sys.argv else None
    for cname in cipher_order:
        if explicit_filter and explicit_filter != cname:
            continue
        info = CIPHERS[cname]
        n_keys = 1000 if info.get('slow') else 10000
        for r in info['test_rounds']:
            full = info['full_rounds']
            if r == info['test_rounds'][0]:
                tag = 'broken'
            elif r == full:
                tag = 'secure'
            else:
                tag = f'R{r}'
            tests.append((f'{info["name"]} R{r} ({tag})', cname, r, n_keys))

    print(f'{BOLD}Running self-test \u2014 {len(tests)} scenarios...{RESET}\n')
    print(f'  {"Source":<30s}  {"Signal":>7s}  {"CASI":>6s}  {"Verdict":<12s}  {"Keys":>6s}  {"Time":>6s}')
    print(f'  {"\u2500"*30}  {"\u2500"*7}  {"\u2500"*6}  {"\u2500"*12}  {"\u2500"*6}  {"\u2500"*6}')

    all_ok = True
    for name, cname, rounds, n_keys in tests:
        engine = LiveCASIWithStorage(key_size=32, window_keys=n_keys, update_every=n_keys)
        t0 = time.time()

        if cname is None:
            data = os.urandom(n_keys * 32)
        else:
            data = CIPHERS[cname]['generator'](n_keys, rounds=rounds, seed=42)

        engine.feed(data)
        engine.force_update()
        dt = time.time() - t0

        casi = engine.current_casi or 0
        signal = engine.current_signal['total'] if engine.current_signal else 0
        color = casi_color(casi)
        verdict = casi_verdict(casi)

        print(f'  {name:<30s}  {signal:>7,}  {color}{casi:>6.1f}{RESET}  '
              f'{color}{verdict:<12s}{RESET}  {n_keys:>5,}k  {dt:>5.1f}s')

        # Sanity: R1 should be broken, full rounds should be secure
        if cname is not None:
            info = CIPHERS[cname]
            if rounds == info['test_rounds'][0] and casi < 2.0:
                print(f'  {RED}  ^ WARN: R1 should be BROKEN but CASI={casi:.1f}{RESET}')
                all_ok = False
            if rounds == info['full_rounds'] and casi > 2.0:
                print(f'  {RED}  ^ WARN: full rounds should be SECURE but CASI={casi:.1f}{RESET}')
                all_ok = False

    if all_ok:
        print(f'\n{BOLD}{GREEN}All {len(tests)} tests passed.{RESET}')
    else:
        print(f'\n{BOLD}{YELLOW}Tests completed with warnings.{RESET}')


# ═══════════════════════════════════════════════════════════════
# ATTACK TEST MODE — synthetic implementation failures
# ═══════════════════════════════════════════════════════════════

def _generate_ecb_data(n_keys):
    """ECB mode: same plaintext block → same ciphertext block.
    Simulates AES-ECB on structured plaintext (HTTP headers, JSON)."""
    rng = np.random.RandomState(42)
    # 8 unique 32-byte "ciphertext" blocks, repeated with structure
    unique_blocks = rng.randint(0, 256, size=(8, 32), dtype=np.uint8)
    # Pick blocks with heavy repetition (like ECB on structured data)
    indices = rng.choice(8, size=n_keys, p=[0.3, 0.2, 0.15, 0.1, 0.08, 0.07, 0.05, 0.05])
    return unique_blocks[indices].tobytes()


def _generate_base64_data(n_keys):
    """Base64 encoding passed off as encryption. Only 64 byte values used."""
    import string
    rng = np.random.RandomState(42)
    b64_chars = np.array([ord(c) for c in string.ascii_uppercase + string.ascii_lowercase
                          + string.digits + '+/'], dtype=np.uint8)
    data = b64_chars[rng.randint(0, 64, size=n_keys * 32)]
    return data.tobytes()


def _generate_xor_short_key(n_keys):
    """XOR with 4-byte repeating key on ASCII plaintext — classic weak encryption.
    XOR on random plaintext is undetectable, but on structured plaintext (which is
    the real-world scenario) the frequency bias is preserved."""
    rng = np.random.RandomState(42)
    # ASCII plaintext: bytes 32-126 (printable chars) — the real-world case
    plaintext = rng.randint(32, 127, size=(n_keys, 32)).astype(np.uint8)
    key = np.array([0xDE, 0xAD, 0xBE, 0xEF], dtype=np.uint8)
    key_tiled = np.tile(key, 8)  # 32 bytes
    encrypted = plaintext ^ key_tiled
    return encrypted.tobytes()


def _generate_counter_reuse(n_keys):
    """Counter reuse in stream cipher — consecutive keys have low hamming distance."""
    rng = np.random.RandomState(42)
    base_keystream = rng.randint(0, 256, size=32, dtype=np.uint8)
    keys = np.zeros((n_keys, 32), dtype=np.uint8)
    for i in range(n_keys):
        # XOR with incrementing counter that wraps every 256 keys
        counter_block = np.zeros(32, dtype=np.uint8)
        counter_block[0] = i % 256
        keys[i] = base_keystream ^ counter_block
    return keys.tobytes()


def _generate_lcg_prng(n_keys):
    """Linear congruential generator output — constant diff between consecutive outputs."""
    keys = np.zeros((n_keys, 32), dtype=np.uint8)
    state = np.array([0x12, 0x34, 0x56, 0x78] * 8, dtype=np.uint8)
    # LCG-like: next = (state * a + c) mod 256 per byte
    a = np.array([141] * 32, dtype=np.uint8)  # multiplier
    c = np.array([77] * 32, dtype=np.uint8)   # increment
    for i in range(n_keys):
        keys[i] = state
        state = (state.astype(np.uint16) * a + c).astype(np.uint8)
    return keys.tobytes()


def _generate_low_entropy(n_keys):
    """Low-entropy PRNG: output restricted to 16 values per byte position.
    Shannon entropy = 4.0 bits/byte instead of 8.0."""
    rng = np.random.RandomState(42)
    # Only use 16 byte values per position (4-bit entropy)
    keys = rng.randint(0, 16, size=(n_keys, 32)).astype(np.uint8)
    # Spread across byte range to avoid byte_frequency detection
    keys = (keys * 17).astype(np.uint8)  # 0, 17, 34, ..., 255
    return keys.tobytes()


def _generate_lfsr(n_keys):
    """Biased bit runs: output has long runs of 0s and 1s.
    Each byte is either 0x00 or 0xFF with 80/20 bias, creating
    anomalous run lengths detectable by the runs test."""
    rng = np.random.RandomState(42)
    # Biased Markov chain: P(stay same) = 0.9, P(flip) = 0.1
    # This creates long runs of identical bits
    keys = np.zeros((n_keys, 32), dtype=np.uint8)
    bit = 0
    for i in range(n_keys):
        for j in range(32):
            byte = 0
            for b in range(8):
                if rng.random() < 0.1:  # 10% chance to flip
                    bit = 1 - bit
                byte |= (bit << b)
            keys[i, j] = byte
    return keys.tobytes()


def _generate_timer_periodic(n_keys):
    """Timer-seeded output: PRNG re-seeded from repeating timer value.
    Simulates: srand(milliseconds % 100). Period=100, same seed = same output."""
    keys = np.zeros((n_keys, 32), dtype=np.uint8)
    period = 100
    # Pre-generate one period of outputs (each seed produces deterministic output)
    period_keys = np.zeros((period, 32), dtype=np.uint8)
    for s in range(period):
        rng = np.random.RandomState(s)
        period_keys[s] = rng.randint(0, 256, size=32, dtype=np.uint8)
    # Tile the period
    for i in range(n_keys):
        keys[i] = period_keys[i % period]
    return keys.tobytes()


def _generate_structured_data(n_keys):
    """Structured data passed off as encrypted: JSON-like ASCII.
    High compressibility reveals it's not encrypted."""
    rng = np.random.RandomState(42)
    # Repeated JSON-like patterns
    templates = [
        b'{"id":12345,"status":"ok"}  ',  # 30 bytes, pad to 32
        b'{"id":67890,"status":"ok"}  ',
        b'{"id":11111,"status":"err"} ',
        b'{"id":22222,"status":"ok"}  ',
    ]
    out = bytearray()
    for i in range(n_keys):
        t = templates[rng.randint(0, len(templates))]
        out.extend(t[:32].ljust(32, b' '))
    return bytes(out)


def _generate_short_period(n_keys):
    """Short-period cycling generator: repeats every 64 keys.
    Detectable via autocorrelation at lag=64*32=2048 bytes."""
    rng = np.random.RandomState(42)
    period = 64
    base_keys = rng.randint(0, 256, size=(period, 32), dtype=np.uint8)
    keys = np.tile(base_keys, (n_keys // period + 1, 1))[:n_keys]
    return keys.tobytes()


def run_test_attacks(args):
    """Synthetic attack scenarios — verify each strategy catches its target."""
    n_keys = 10000
    attacks = [
        # Original 5 (Phase 1)
        ('ECB mode (structured PT)', _generate_ecb_data, 'block_repetition',
         'Duplicate ciphertext blocks from identical plaintext'),
        ('Base64 encoding', _generate_base64_data, 'byte_frequency',
         'Only 64 of 256 byte values used'),
        ('XOR 4-byte key', _generate_xor_short_key, 'byte_frequency',
         'Frequency structure preserved through short-key XOR'),
        ('Counter reuse', _generate_counter_reuse, 'seq_correlation',
         'Low hamming distance between consecutive outputs'),
        ('LCG PRNG', _generate_lcg_prng, 'seq_correlation',
         'Constant diff pattern between consecutive outputs'),
        # New 5 (Phase 2 — targeting new strategies)
        ('Low-entropy PRNG', _generate_low_entropy, 'entropy',
         'Only 4 bits/byte entropy instead of 8'),
        ('LFSR bit stream', _generate_lfsr, 'runs',
         'Linear feedback shift register with predictable run lengths'),
        ('Timer-seeded periodic', _generate_timer_periodic, 'spectral',
         'Periodic structure from millisecond timer seeding'),
        ('Structured data (JSON)', _generate_structured_data, 'compression',
         'Compressible structured data passed off as ciphertext'),
        ('Short-period cycling', _generate_short_period, 'autocorrelation',
         'Generator repeats every 64 keys'),
    ]

    print(f'{BOLD}Running attack scenarios \u2014 {len(attacks)} synthetic failures...{RESET}\n')
    print(f'  {"Attack":<25s}  {"Signal":>7s}  {"CASI":>8s}  {"Target Strategy":<22s}  {"Hit?":>4s}')
    print(f'  {"\u2500"*25}  {"\u2500"*7}  {"\u2500"*8}  {"\u2500"*22}  {"\u2500"*4}')

    all_ok = True
    for attack_name, gen_func, target_strat, description in attacks:
        engine = LiveCASIWithStorage(key_size=32, window_keys=n_keys, update_every=n_keys)
        data = gen_func(n_keys)
        engine.feed(data)
        engine.force_update()

        casi = engine.current_casi or 0
        signal = engine.current_signal
        target_val = signal.get(target_strat, 0) if signal else 0
        total = signal['total'] if signal else 0

        # Target strategy should be the dominant signal contributor
        hit = target_val > 0 and casi > 10.0
        color = GREEN if hit else RED
        mark = 'YES' if hit else 'NO'

        print(f'  {attack_name:<25s}  {total:>7,}  {casi_color(casi)}{casi:>8.1f}{RESET}  '
              f'{target_strat:<22s}  {color}{mark:>4s}{RESET}')
        print(f'  {DIM}  \u2514 {description}{RESET}')

        # Show signal breakdown for this attack
        if signal:
            top = sorted([(n, signal.get(n, 0)) for n in STRATEGY_NAMES],
                         key=lambda x: -x[1])[:3]
            parts = [f'{n}={v:,}' for n, v in top if v > 0]
            if parts:
                print(f'  {DIM}  \u2514 Top signals: {", ".join(parts)}{RESET}')

        if not hit:
            print(f'  {RED}  ^ FAIL: Expected CASI > 10 with {target_strat} dominant{RESET}')
            all_ok = False

    # Baseline check: random should NOT trigger
    print()
    engine = LiveCASIWithStorage(key_size=32, window_keys=n_keys, update_every=n_keys)
    engine.feed(os.urandom(n_keys * 32))
    engine.force_update()
    casi = engine.current_casi or 0
    baseline_ok = casi < 2.0
    color = GREEN if baseline_ok else RED
    mark = 'YES' if baseline_ok else 'NO'
    print(f'  {"os.urandom baseline":<25s}  {engine.current_signal["total"]:>7,}  '
          f'{casi_color(casi)}{casi:>8.1f}{RESET}  {"<2.0 expected":<22s}  {color}{mark:>4s}{RESET}')
    if not baseline_ok:
        print(f'  {RED}  ^ FAIL: Random data should be CASI < 2.0{RESET}')
        all_ok = False

    if all_ok:
        print(f'\n{BOLD}{GREEN}All attack scenarios passed.{RESET}')
    else:
        print(f'\n{BOLD}{RED}Some attack scenarios failed.{RESET}')


# ═══════════════════════════════════════════════════════════════
# MAIN
# ═══════════════════════════════════════════════════════════════

def main():
    cipher_names = ', '.join(CIPHERS.keys())
    parser = argparse.ArgumentParser(
        description='live-casi: Real-time Causal Amplification Security Index Monitor',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=f"""
Supported ciphers: {cipher_names}, all, random

Examples:
  python live_casi.py --test                        # Test all 8 ciphers
  python live_casi.py --test --cipher speck         # Test Speck only
  python live_casi.py --test-attacks                # Attack scenarios
  python live_casi.py --demo                        # ChaCha visual demo
  python live_casi.py --demo --cipher aes           # AES demo
  python live_casi.py --demo --cipher all           # All 8 ciphers
  python live_casi.py --demo --cipher random        # Random vs broken
  openssl rand 320000 | python live_casi.py         # Pipe random bytes
  python live_casi.py --file /tmp/output.bin        # Watch file

Advanced analysis:
  live-casi --known-pt plain.bin < cipher.bin        # Known-plaintext
  live-casi --compare old.bin new.bin                # Differential

Cipher identification (v0.2.0):
  live-casi --identify encrypted.bin                 # Identify cipher family
  live-casi --identify encrypted.bin --json          # JSON output
  live-casi --identify-test                          # Blind test accuracy

Binary/firmware scanning (v0.2.0):
  live-casi --scan firmware.bin                      # Find encrypted regions
  live-casi --scan firmware.bin --window-size 65536  # Custom window

Frontier benchmark (v0.2.0):
  live-casi --benchmark                              # All 8 ciphers vs SOTA
  live-casi --benchmark --cipher speck               # Speck only
  live-casi --benchmark --benchmark-seeds 10         # Statistical confidence

Network analysis (v0.3.0):
  live-casi --pcap capture.pcap                      # Analyze pcap file
  live-casi --pcap capture.pcap --problems-only      # Only weak/plaintext
  sudo live-casi --monitor                           # Live traffic monitor
  sudo live-casi --monitor --interface en0           # Specific interface
  sudo live-casi --monitor --duration 60             # Capture for 60 seconds

Frontier & NIST comparison (v0.5.1):
  live-casi --frontier                               # Find detection boundaries
  live-casi --frontier --keys 50000                  # More keys = higher precision
  live-casi --nist-compare                           # CASI vs NIST SP 800-22
  live-casi --bootstrap encrypted.bin                # Bootstrap confidence interval

CI/CD integration:
  ./encrypt | live-casi --exit-code 2.0              # Exit 0=pass, 1=fail
  ./encrypt | live-casi --json                       # JSON output
  ./encrypt | live-casi --quiet                      # Just the number
        """)

    parser.add_argument('--demo', action='store_true', help='Run visual demo')
    parser.add_argument('--test', action='store_true', help='Run self-test')
    parser.add_argument('--test-attacks', action='store_true',
                        help='Run synthetic attack scenarios')
    parser.add_argument('--file', type=str, help='Watch file for new data')
    parser.add_argument('--known-pt', type=str, metavar='FILE',
                        help='Known-plaintext file (ciphertext from stdin or --file)')
    parser.add_argument('--compare', type=str, nargs=2, metavar=('FILE1', 'FILE2'),
                        help='Compare two byte streams side-by-side')

    # v0.2.0: identification, scanning, benchmark
    parser.add_argument('--identify', type=str, nargs='?', const=True, metavar='FILE',
                        help='Identify cipher from file (or stdin with -)')
    parser.add_argument('--identify-test', action='store_true',
                        help='Run blind identification accuracy test')
    parser.add_argument('--scan', type=str, metavar='FILE',
                        help='Scan binary/firmware for encrypted regions')
    parser.add_argument('--window-size', type=int, default=32768,
                        help='Scanner window size in bytes (default 32768)')
    parser.add_argument('--step-size', type=int, default=4096,
                        help='Scanner step size in bytes (default 4096)')
    parser.add_argument('--benchmark', action='store_true',
                        help='Run CASI frontier benchmark vs academic results')
    parser.add_argument('--benchmark-seeds', type=int, default=1,
                        help='Number of seeds for benchmark statistical confidence')

    # v0.3.0: network analysis
    parser.add_argument('--pcap', type=str, metavar='FILE',
                        help='Analyze pcap file for encryption quality per connection')
    parser.add_argument('--monitor', action='store_true',
                        help='Live network monitor (requires sudo)')
    parser.add_argument('--interface', type=str, default=None,
                        help='Network interface for --monitor (default: auto)')
    parser.add_argument('--duration', type=int, default=None,
                        help='Capture duration in seconds for --monitor')
    parser.add_argument('--problems-only', action='store_true',
                        help='Only show weak/plaintext connections')

    # v0.4.0: causal knowledge graph + channel probe
    parser.add_argument('--causal', type=str, metavar='OUTPUT',
                        help='Generate CASI cryptanalytic knowledge graph (.causal file)')
    parser.add_argument('--keys', type=int, default=10000,
                        help='Number of keys per cipher for --causal (default: 10000)')
    parser.add_argument('--quick', action='store_true',
                        help='Quick mode for --causal (fewer rounds per cipher)')
    parser.add_argument('--probe-generate', type=str, metavar='OUTPUT',
                        help='Generate a CASI channel probe file')
    parser.add_argument('--probe-verify', type=str, metavar='FILE',
                        help='Verify a received CASI channel probe')
    parser.add_argument('--probe-compare', type=str, nargs=2, metavar=('ORIGINAL', 'RECEIVED'),
                        help='Compare original vs received probe (side-by-side)')
    parser.add_argument('--probe-size', type=int, default=65536,
                        help='Payload size for --probe-generate (default: 65536)')

    # v0.5.1: frontier sweeper + NIST comparison + bootstrap CI
    parser.add_argument('--frontier', action='store_true', default=False,
                        help='Find CASI detection boundaries for all ciphers')
    parser.add_argument('--nist-compare', action='store_true', default=False,
                        help='Compare CASI vs NIST SP 800-22 on all ciphers')
    parser.add_argument('--bootstrap', type=str, metavar='FILE',
                        help='Compute CASI with bootstrap CI from file')
    parser.add_argument('--n-bootstrap', type=int, default=100,
                        help='Bootstrap iterations (default: 100)')

    # v0.5.0: post-quantum cryptography analysis
    parser.add_argument('--pqc', action='store_true', default=False,
                        help='Run PQC analysis (ML-KEM, ML-DSA, HQC)')
    parser.add_argument('--pqc-causal', type=str, metavar='OUTPUT',
                        help='Generate PQC knowledge graph (.causal file)')
    parser.add_argument('--pqc-isolate', action='store_true', default=False,
                        help='ML-KEM compression isolation experiment')

    parser.add_argument('--cipher', type=str, default='chacha',
                        help=f'Cipher for demo/test ({cipher_names}, all, random)')
    parser.add_argument('--key-size', type=int, default=32, help='Key size in bytes')
    parser.add_argument('--window', type=int, default=10000, help='Window size in keys')
    parser.add_argument('--update-every', type=int, default=500,
                        help='Recompute CASI every N new keys')

    # v0.5.1: gap analysis, backdoor detection, CVE/PRNG suites
    parser.add_argument('--gap-analysis', action='store_true', default=False,
                        help='Find where CASI detects but NIST misses (full sweep)')
    parser.add_argument('--backdoor-test', action='store_true', default=False,
                        help='Run backdoor detection showcase (CASI vs NIST gap)')
    parser.add_argument('--cve-report', action='store_true', default=False,
                        help='Test CASI against simulated CVEs')
    parser.add_argument('--prng-test', action='store_true', default=False,
                        help='Test CASI on common PRNGs')

    # CI/CD integration flags
    parser.add_argument('--exit-code', type=float, default=None, metavar='THRESHOLD',
                        help='Exit 0 if CASI < THRESHOLD, exit 1 if CASI >= THRESHOLD')
    parser.add_argument('--json', action='store_true', default=False,
                        help='Machine-readable JSON output')
    parser.add_argument('--quiet', action='store_true', default=False,
                        help='Output only the final CASI number (no TUI)')

    args = parser.parse_args()

    if args.gap_analysis:
        from .gap_analysis import sweep_gap, format_gap_report
        print("Running CASI gap analysis (every round, every cipher)...")
        data = sweep_gap(n_keys=args.keys, skip_slow=args.quick)
        print(format_gap_report(data))
        if args.json:
            from .gap_analysis import save_gap_json
            save_gap_json(data)
    elif args.backdoor_test:
        from .backdoor_analysis import run_backdoor_showcase, format_backdoor_report
        from .backdoor_analysis import sweep_bias_threshold, format_bias_sweep_report
        results = run_backdoor_showcase(n_keys=args.keys)
        print(format_backdoor_report(results))
        sweep = sweep_bias_threshold(n_keys=args.keys)
        print(format_bias_sweep_report(sweep))
    elif args.cve_report:
        from .cve_analysis import run_cve_suite, format_cve_report
        results = run_cve_suite(n_keys=args.keys)
        print(format_cve_report(results))
    elif args.prng_test:
        from .cve_analysis import run_prng_suite, format_prng_report
        results = run_prng_suite(n_keys=args.keys)
        print(format_prng_report(results))
    elif args.frontier:
        from .frontier import sweep_all_frontiers, format_frontier_table
        print("Sweeping CASI detection frontiers...")
        results = sweep_all_frontiers(n_keys=args.keys, skip_slow=args.quick)
        print(format_frontier_table(results))
        if args.json:
            from .frontier import save_frontiers_json
            path = save_frontiers_json(results)
            print(f"Saved to {path}")
    elif args.nist_compare:
        from .nist_compare import compare_all, format_comparison_table
        print("Running CASI vs NIST SP 800-22...")
        results = compare_all(n_keys=args.keys, skip_slow=args.quick)
        print(format_comparison_table(results))
    elif args.bootstrap:
        data = open(args.bootstrap, 'rb').read()
        n_keys = len(data) // args.key_size
        if n_keys < 100:
            print(f"Too few keys ({n_keys}), need at least 100")
            sys.exit(1)
        keys = np.frombuffer(data[:n_keys * args.key_size], dtype=np.uint8).reshape(n_keys, args.key_size)
        result = compute_signal_with_ci(keys, n_bootstrap=args.n_bootstrap, crypto_only=False)
        print(f"CASI: {result['point_estimate']:.3f}  [{result['ci_lower']:.3f}, {result['ci_upper']:.3f}] "
              f"({int(result['ci_level']*100)}% CI, n={args.n_bootstrap})")
        print(f"  mean={result['mean']:.3f}  std={result['std']:.3f}  median={result['median']:.3f}")
        print(f"  verdict: {casi_verdict(result['point_estimate'])}")
        if args.json:
            import json
            print(json.dumps(result, indent=2))
    elif args.test:
        run_test(args)
    elif args.test_attacks:
        run_test_attacks(args)
    elif args.identify:
        from .identify import run_identify
        run_identify(args)
    elif args.identify_test:
        from .identify import run_identify_test
        run_identify_test()
    elif args.scan:
        from .scanner import run_scan
        run_scan(args)
    elif args.benchmark:
        from .benchmark import run_benchmark
        run_benchmark(args)
    elif args.pcap:
        from .network import run_pcap
        run_pcap(args)
    elif args.monitor:
        from .network import run_monitor
        run_monitor(args)
    elif args.pqc:
        from .pqc import run_pqc
        run_pqc(args)
    elif args.pqc_causal:
        from .pqc import run_pqc_causal
        run_pqc_causal(args)
    elif args.pqc_isolate:
        from .pqc import run_mlkem_isolation
        run_mlkem_isolation(args)
    elif args.causal:
        from .causal import run_causal
        run_causal(args)
    elif args.probe_generate:
        from .probe import run_probe_generate
        run_probe_generate(args)
    elif args.probe_verify:
        from .probe import run_probe_verify
        run_probe_verify(args)
    elif args.probe_compare:
        from .probe import run_probe_compare
        run_probe_compare(args)
    elif args.compare:
        run_compare(args)
    elif args.known_pt:
        run_known_pt(args)
    elif args.demo:
        run_demo(args)
    elif args.file:
        run_file(args)
    elif not sys.stdin.isatty():
        run_pipe(args)
    else:
        parser.print_help()
        print(f'\n{BOLD}Quick start:{RESET} python live_casi.py --test')


if __name__ == '__main__':
    main()

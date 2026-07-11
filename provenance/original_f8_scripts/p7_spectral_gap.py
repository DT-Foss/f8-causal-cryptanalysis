#!/usr/bin/env python3
"""P7: Spectral gap of the bit-dependency graph."""
import sys, os; sys.path.insert(0, os.path.dirname(__file__))
from speck_utils import *

N, SEEDS = 50000, 5

def mi_2x2(a, b, n):
    n00 = int(np.sum((a==0)&(b==0))); n01 = int(np.sum((a==0)&(b==1)))
    n10 = int(np.sum((a==1)&(b==0))); n11 = int(np.sum((a==1)&(b==1)))
    H_ab = 0
    for c in [n00,n01,n10,n11]:
        p = c/n
        if p > 0: H_ab -= p * math.log2(p)
    pa = (n10+n11)/n; pb = (n01+n11)/n
    Ha = -pa*math.log2(pa)-(1-pa)*math.log2(1-pa) if 0<pa<1 else 0
    Hb = -pb*math.log2(pb)-(1-pb)*math.log2(1-pb) if 0<pb<1 else 0
    return max(0, Ha + Hb - H_ab)

def build_mi_matrix(gen_fn, ws, alpha, beta, base_round, kw=4):
    """Build full WS×WS MI matrix between x-bits and diff_y-bits."""
    mi = np.zeros((ws, ws))
    for s_idx in range(SEEDS):
        seed = s_idx * 1000 + 42
        raw_R, bb, bpw = gen_fn(N, ws, kw, alpha, beta, base_round, seed)
        raw_R1, _, _ = gen_fn(N, ws, kw, alpha, beta, base_round + 1, seed)
        d_R = np.frombuffer(raw_R, dtype=np.uint8).reshape(-1, bb)
        d_R1 = np.frombuffer(raw_R1, dtype=np.uint8).reshape(-1, bb)
        # Reconstruct words
        x_R = np.zeros(N, dtype=np.uint64); y_R = np.zeros(N, dtype=np.uint64)
        y_R1 = np.zeros(N, dtype=np.uint64)
        for b in range(bpw):
            sh = 8*(bpw-1-b)
            x_R |= d_R[:,b].astype(np.uint64) << sh
            y_R |= d_R[:,bpw+b].astype(np.uint64) << sh
            y_R1 |= d_R1[:,bpw+b].astype(np.uint64) << sh
        diff_y = y_R ^ y_R1
        for i in range(ws):
            for j in range(ws):
                xb = ((x_R >> i) & 1).astype(np.uint8)
                dyb = ((diff_y >> j) & 1).astype(np.uint8)
                mi[i, j] += mi_2x2(xb, dyb, N)
    mi /= SEEDS
    return mi

def spectral_analysis(mi_matrix, label):
    """Compute spectral properties of the MI matrix."""
    # Eigenvalues of the MI matrix (treated as adjacency matrix)
    eigvals = np.linalg.eigvalsh(mi_matrix)
    eigvals = np.sort(eigvals)[::-1]  # descending

    # Key metrics
    lambda1 = eigvals[0]
    lambda2 = eigvals[1] if len(eigvals) > 1 else 0
    spectral_gap = lambda1 - lambda2
    spectral_ratio = lambda2 / lambda1 if lambda1 > 0 else 0
    rank_eff = (np.sum(eigvals)**2 / np.sum(eigvals**2)) if np.sum(eigvals**2) > 0 else 0
    frobenius = np.sqrt(np.sum(mi_matrix**2))
    total_mi = np.sum(mi_matrix)

    # Nuclear norm (sum of singular values)
    svs = np.linalg.svd(mi_matrix, compute_uv=False)
    nuclear = np.sum(svs)

    # Entropy of singular value spectrum
    sv_norm = svs / np.sum(svs) if np.sum(svs) > 0 else svs
    sv_entropy = -np.sum(sv_norm * np.log2(sv_norm + 1e-30))

    print(f"\n--- {label} ---")
    print(f"  λ₁ = {lambda1:.6f}")
    print(f"  λ₂ = {lambda2:.6f}")
    print(f"  Spectral gap (λ₁-λ₂) = {spectral_gap:.6f}")
    print(f"  λ₂/λ₁ = {spectral_ratio:.4f}")
    print(f"  Effective rank = {rank_eff:.2f}")
    print(f"  Frobenius norm = {frobenius:.6f}")
    print(f"  Total MI = {total_mi:.4f} bits")
    print(f"  Nuclear norm = {nuclear:.6f}")
    print(f"  SV entropy = {sv_entropy:.4f} bits")
    print(f"  Top 5 eigenvalues: {eigvals[:5]}")

    return {
        'label': label, 'lambda1': lambda1, 'lambda2': lambda2,
        'gap': spectral_gap, 'ratio': spectral_ratio,
        'eff_rank': rank_eff, 'frobenius': frobenius,
        'total_mi': total_mi, 'nuclear': nuclear,
        'sv_entropy': sv_entropy, 'eigvals': eigvals
    }

print("=" * 70)
print("P7: SPECTRAL GAP OF BIT-DEPENDENCY GRAPH")
print("=" * 70)

results = []

# Speck 32/64 (α=7, β=2) — strong signal
print("\n[1/5] Computing Speck 32/64 MI matrix...")
mi32 = build_mi_matrix(speck_gen, 16, 7, 2, 15)
r32 = spectral_analysis(mi32, "Speck 32/64 (α=7, β=2)")
results.append(r32)

# Speck 32/64 with β=1 — strongest signal
print("\n[2/5] Computing Speck 32/64 (β=1) MI matrix...")
mi32b1 = build_mi_matrix(speck_gen, 16, 7, 1, 15)
r32b1 = spectral_analysis(mi32b1, "Speck 32/64 (α=7, β=1)")
results.append(r32b1)

# Speck 32/64 with β=3 — weaker signal
print("\n[3/5] Computing Speck 32/64 (β=3) MI matrix...")
mi32b3 = build_mi_matrix(speck_gen, 16, 7, 3, 15)
r32b3 = spectral_analysis(mi32b3, "Speck 32/64 (α=7, β=3)")
results.append(r32b3)

# Speck 32/64 with β=4 — weakest detectable signal
print("\n[4/5] Computing Speck 32/64 (β=4) MI matrix...")
mi32b4 = build_mi_matrix(speck_gen, 16, 7, 4, 15)
r32b4 = spectral_analysis(mi32b4, "Speck 32/64 (α=7, β=4)")
results.append(r32b4)

# Random (null) — should have ~0 spectral gap
print("\n[5/5] Computing Random MI matrix...")
mi_rand = np.zeros((16, 16))
for s_idx in range(SEEDS):
    rng = np.random.default_rng(s_idx * 1000 + 42)
    x_rand = rng.integers(0, 2**16, size=N, dtype=np.int64).astype(np.uint64)
    dy_rand = rng.integers(0, 2**16, size=N, dtype=np.int64).astype(np.uint64)
    for i in range(16):
        for j in range(16):
            xb = ((x_rand >> i) & 1).astype(np.uint8)
            dyb = ((dy_rand >> j) & 1).astype(np.uint8)
            mi_rand[i, j] += mi_2x2(xb, dyb, N)
mi_rand /= SEEDS
r_rand = spectral_analysis(mi_rand, "Random (null)")
results.append(r_rand)

# Summary table
print("\n\n" + "=" * 70)
print("SUMMARY TABLE")
print("=" * 70)
print(f"\n{'Cipher':>25}  {'λ₁':>8}  {'λ₂':>8}  {'Gap':>8}  {'λ₂/λ₁':>6}  {'Eff Rank':>8}  {'SV Ent':>7}")
print("-" * 80)
for r in results:
    print(f"{r['label']:>25}  {r['lambda1']:.5f}  {r['lambda2']:.5f}  {r['gap']:.5f}  {r['ratio']:.4f}  {r['eff_rank']:>7.2f}  {r['sv_entropy']:>6.3f}")

# Interpretation
print("\n\n=== INTERPRETATION ===\n")
print("If the MI matrix is rank-1 (perfect diagonal shifted by α):")
print("  → λ₁ ≫ λ₂ (one dominant eigenvalue)")
print("  → spectral gap ≈ λ₁")
print("  → effective rank ≈ 1")
print("  → This is the 'clean rotation-leak' signature")
print()
print("If the MI matrix has multiple active eigenvalues:")
print("  → smaller spectral gap, larger effective rank")
print("  → indicates multiple independent leak mechanisms")
print()
print("Random should have all eigenvalues ≈ 0 (no structure)")

print("\n=== DONE ===")

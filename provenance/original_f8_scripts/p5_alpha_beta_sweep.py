#!/usr/bin/env python3
"""P5: f(α,β) leak-rate function — sweep rotation parameters on Speck 32/64 frame."""
import sys, os; sys.path.insert(0, os.path.dirname(__file__))
from speck_utils import *

N, SEEDS = 50000, 5
WS = 16  # Fixed word size (Speck 32/64 frame)

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

# Rotation parameters to test — systematically vary α and β independently
params = [
    # Vary β with α fixed at 7 (Speck 32/64 default α)
    (7, 1),  # β=1
    (7, 2),  # β=2 (standard Speck 32/64)
    (7, 3),  # β=3
    (7, 4),  # β=4
    (7, 5),  # β=5
    # Vary α with β fixed at 2
    (3, 2),  # small α
    (5, 2),  # medium α
    (9, 2),  # larger α
    (11, 2), # large α
    (13, 2), # near WS
    # Vary α with β fixed at 3 (Speck 48+ default β)
    (5, 3),
    (8, 3),  # standard Speck 48/64/128
    (10, 3),
    # Edge/extreme cases
    (1, 1),  # minimal rotations
    (15, 1), # near-full rotation
    (8, 7),  # large β
]

# Full rounds for 32/64 frame
FULL_ROUNDS = 22
BASE_ROUND = 15  # well into plateau

print("=== P5: f(α,β) LEAK-RATE SWEEP (word_size=16) ===\n")
print(f"N={N}, SEEDS={SEEDS}, base_round={BASE_ROUND}, full_rounds={FULL_ROUNDS}\n")
print(f"{'α':>3}  {'β':>3}  {'Active':>7}  {'MI/pair':>10}  {'Total MI':>10}  {'Leak%':>7}  {'Dead bits':>30}")
print("-" * 80)

results = []
for alpha, beta in params:
    mi_diag = np.zeros(WS)
    for s_idx in range(SEEDS):
        seed = s_idx * 1000 + 42
        raw_R, bb, bpw = speck_gen(N, WS, 4, alpha, beta, BASE_ROUND, seed)
        raw_R1, _, _ = speck_gen(N, WS, 4, alpha, beta, BASE_ROUND + 1, seed)
        d_R = np.frombuffer(raw_R, dtype=np.uint8).reshape(-1, bb)
        d_R1 = np.frombuffer(raw_R1, dtype=np.uint8).reshape(-1, bb)
        x_R = d_R[:,0].astype(np.uint16)*256 + d_R[:,1].astype(np.uint16)
        y_R = d_R[:,2].astype(np.uint16)*256 + d_R[:,3].astype(np.uint16)
        y_R1 = d_R1[:,2].astype(np.uint16)*256 + d_R1[:,3].astype(np.uint16)
        diff_y = y_R ^ y_R1
        for i in range(WS):
            j = (i - alpha) % WS  # Expected diagonal shift from P3
            xb = ((x_R >> i) & 1).astype(np.uint8)
            dyb = ((diff_y >> j) & 1).astype(np.uint8)
            mi_diag[i] += mi_2x2(xb, dyb, N)
    mi_diag /= SEEDS
    active = mi_diag[mi_diag > 0.001]
    n_active = len(active)
    mi_per = np.mean(active) if n_active else 0
    total = np.sum(active)
    leak = (total / WS) * 100
    dead = [i for i in range(WS) if mi_diag[i] <= 0.001]
    print(f"{alpha:>3}  {beta:>3}    {n_active:>2}/{WS}   {mi_per:.6f}  {total:.4f} bits  {leak:.2f}%  {dead}")
    results.append((alpha, beta, n_active, mi_per, total, leak))

# ---- Analysis: fit f(α,β) ----
print("\n\n=== REGRESSION ANALYSIS ===\n")

# Data for fitting
from scipy.optimize import curve_fit

alphas = np.array([r[0] for r in results], dtype=float)
betas = np.array([r[1] for r in results], dtype=float)
mi_per_pair = np.array([r[3] for r in results], dtype=float)
leak_pct = np.array([r[5] for r in results], dtype=float)
n_active_arr = np.array([r[2] for r in results], dtype=float)

# Filter to nonzero signal only
mask = mi_per_pair > 0.0001
if np.sum(mask) < 4:
    print("Too few data points with signal for fitting.")
    sys.exit(0)

a_fit = alphas[mask]
b_fit = betas[mask]
mi_fit = mi_per_pair[mask]
leak_fit = leak_pct[mask]
n_active_fit = n_active_arr[mask]

# Model 1: MI/pair ~ C * β^(-p) * α^(-q)
# Take log: log(MI) = log(C) - p*log(β) - q*log(α)
print("--- Model 1: MI/pair = C · α^(-q) · β^(-p) ---")
try:
    log_mi = np.log(mi_fit)
    log_a = np.log(a_fit)
    log_b = np.log(b_fit)
    # Linear regression: log_mi = c0 + c1*log_a + c2*log_b
    X = np.column_stack([np.ones_like(log_a), log_a, log_b])
    coeffs, residuals, rank, sv = np.linalg.lstsq(X, log_mi, rcond=None)
    C = np.exp(coeffs[0])
    q = -coeffs[1]
    p = -coeffs[2]
    pred = C * a_fit**(-q) * b_fit**(-p)
    r2 = 1 - np.sum((mi_fit - pred)**2) / np.sum((mi_fit - np.mean(mi_fit))**2)
    print(f"  C = {C:.6f}, q(α) = {q:.3f}, p(β) = {p:.3f}")
    print(f"  f(α,β) = {C:.4f} · α^(-{q:.2f}) · β^(-{p:.2f})")
    print(f"  R² = {r2:.4f}")
    print(f"\n  {'α':>3}  {'β':>3}  {'Measured':>10}  {'Predicted':>10}  {'Error%':>8}")
    for i in range(len(a_fit)):
        err = abs(pred[i] - mi_fit[i]) / mi_fit[i] * 100
        print(f"  {int(a_fit[i]):>3}  {int(b_fit[i]):>3}  {mi_fit[i]:.6f}  {pred[i]:.6f}  {err:>7.1f}%")
except Exception as e:
    print(f"  Fit failed: {e}")

# Model 2: n_active = WS - β (dead bits = β)
print(f"\n--- Model 2: n_active vs β ---")
print(f"  Predicted: n_active = WS - β = 16 - β")
for i in range(len(a_fit)):
    predicted = WS - int(b_fit[i])
    actual = int(n_active_fit[i])
    print(f"  α={int(a_fit[i]):>2}, β={int(b_fit[i]):>2}: actual={actual}, predicted={predicted}, {'OK' if actual==predicted else 'MISMATCH'}")

# Model 3: Total leak = n_active * MI/pair = (WS-β) * f(α,β)
print(f"\n--- Model 3: Leak% = (WS-β)/WS × 100 × MI/pair × WS ---")
print("  (Checking: leak_pct = n_active * MI/pair / WS * 100)")
for i in range(len(a_fit)):
    calc_leak = n_active_fit[i] * mi_fit[i] / WS * 100
    print(f"  α={int(a_fit[i]):>2}, β={int(b_fit[i]):>2}: measured={leak_fit[i]:.2f}%, calc={calc_leak:.2f}%")

# Model 4: Try β-only and α-only models
print(f"\n--- Model 4: Separability test ---")
# β-only (fix α=7): MI/pair ~ C * β^(-p)
mask7 = (a_fit == 7)
if np.sum(mask7) >= 3:
    b7 = b_fit[mask7]; mi7 = mi_fit[mask7]
    log_mi7 = np.log(mi7); log_b7 = np.log(b7)
    X7 = np.column_stack([np.ones_like(log_b7), log_b7])
    c7, _, _, _ = np.linalg.lstsq(X7, log_mi7, rcond=None)
    C7 = np.exp(c7[0]); p7 = -c7[1]
    pred7 = C7 * b7**(-p7)
    r2_7 = 1 - np.sum((mi7 - pred7)**2) / np.sum((mi7 - np.mean(mi7))**2)
    print(f"  β-only (α=7): MI = {C7:.4f} · β^(-{p7:.2f}), R² = {r2_7:.4f}")

# α-only (fix β=2): MI/pair ~ C * α^(-q)
mask2 = (b_fit == 2)
if np.sum(mask2) >= 3:
    a2 = a_fit[mask2]; mi2 = mi_fit[mask2]
    log_mi2 = np.log(mi2); log_a2 = np.log(a2)
    X2 = np.column_stack([np.ones_like(log_a2), log_a2])
    c2, _, _, _ = np.linalg.lstsq(X2, log_mi2, rcond=None)
    C2 = np.exp(c2[0]); q2 = -c2[1]
    pred2 = C2 * a2**(-q2)
    r2_2 = 1 - np.sum((mi2 - pred2)**2) / np.sum((mi2 - np.mean(mi2))**2)
    print(f"  α-only (β=2): MI = {C2:.4f} · α^(-{q2:.2f}), R² = {r2_2:.4f}")

# α-only (fix β=3)
mask3 = (b_fit == 3)
if np.sum(mask3) >= 3:
    a3 = a_fit[mask3]; mi3 = mi_fit[mask3]
    log_mi3 = np.log(mi3); log_a3 = np.log(a3)
    X3 = np.column_stack([np.ones_like(log_a3), log_a3])
    c3, _, _, _ = np.linalg.lstsq(X3, log_mi3, rcond=None)
    C3 = np.exp(c3[0]); q3 = -c3[1]
    pred3 = C3 * a3**(-q3)
    r2_3 = 1 - np.sum((mi3 - pred3)**2) / np.sum((mi3 - np.mean(mi3))**2)
    print(f"  α-only (β=3): MI = {C3:.4f} · α^(-{q3:.2f}), R² = {r2_3:.4f}")

print("\n=== DONE ===")

#!/usr/bin/env python3
"""P5b: Fine β sweep — find exact death threshold and refine MI(β) model."""
import sys, os; sys.path.insert(0, os.path.dirname(__file__))
from speck_utils import *

N, SEEDS = 50000, 5
WS = 16

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

def measure_mi(alpha, beta, base_round=15):
    mi_diag = np.zeros(WS)
    for s_idx in range(SEEDS):
        seed = s_idx * 1000 + 42
        raw_R, bb, bpw = speck_gen(N, WS, 4, alpha, beta, base_round, seed)
        raw_R1, _, _ = speck_gen(N, WS, 4, alpha, beta, base_round + 1, seed)
        d_R = np.frombuffer(raw_R, dtype=np.uint8).reshape(-1, bb)
        d_R1 = np.frombuffer(raw_R1, dtype=np.uint8).reshape(-1, bb)
        x_R = d_R[:,0].astype(np.uint16)*256 + d_R[:,1].astype(np.uint16)
        y_R = d_R[:,2].astype(np.uint16)*256 + d_R[:,3].astype(np.uint16)
        y_R1 = d_R1[:,2].astype(np.uint16)*256 + d_R1[:,3].astype(np.uint16)
        diff_y = y_R ^ y_R1
        for i in range(WS):
            j = (i - alpha) % WS
            xb = ((x_R >> i) & 1).astype(np.uint8)
            dyb = ((diff_y >> j) & 1).astype(np.uint8)
            mi_diag[i] += mi_2x2(xb, dyb, N)
    mi_diag /= SEEDS
    active = mi_diag[mi_diag > 0.001]
    n_active = len(active)
    mi_per = np.mean(active) if n_active else 0
    return n_active, mi_per

# ---- Full β sweep from 1 to WS/2 ----
print("=== P5b: FINE β SWEEP (α=7, word_size=16) ===\n")
print(f"{'β':>3}  {'Active':>7}  {'MI/pair':>10}  {'log₂(MI)':>10}")
print("-" * 40)
betas_fine = list(range(1, 9))
mi_data = []
for beta in betas_fine:
    n_active, mi_per = measure_mi(7, beta)
    log_mi = math.log2(mi_per) if mi_per > 0 else float('-inf')
    print(f"{beta:>3}    {n_active:>2}/{WS}   {mi_per:.6f}  {log_mi:>10.3f}")
    if mi_per > 0.0001:
        mi_data.append((beta, mi_per))

# ---- Also confirm α-independence with a different α ----
print(f"\n=== CONFIRMING α-INDEPENDENCE (α=3 vs α=7 vs α=13) ===\n")
print(f"{'β':>3}  {'α=3':>10}  {'α=7':>10}  {'α=13':>10}  {'Max spread%':>12}")
print("-" * 55)
for beta in [1, 2, 3, 4]:
    _, mi3 = measure_mi(3, beta)
    _, mi7 = measure_mi(7, beta)
    _, mi13 = measure_mi(13, beta)
    vals = [mi3, mi7, mi13]
    mean_v = np.mean(vals)
    spread = (max(vals) - min(vals)) / mean_v * 100 if mean_v > 0 else 0
    print(f"{beta:>3}  {mi3:.6f}  {mi7:.6f}  {mi13:.6f}  {spread:>10.2f}%")

# ---- Fit refined model ----
print(f"\n=== REFINED MI(β) MODEL ===\n")
betas_arr = np.array([d[0] for d in mi_data], dtype=float)
mi_arr = np.array([d[1] for d in mi_data], dtype=float)

# Power law: MI = C * β^(-p)
log_b = np.log(betas_arr)
log_mi = np.log(mi_arr)
X = np.column_stack([np.ones_like(log_b), log_b])
coeffs, _, _, _ = np.linalg.lstsq(X, log_mi, rcond=None)
C = np.exp(coeffs[0])
p = -coeffs[1]
pred = C * betas_arr**(-p)
r2 = 1 - np.sum((mi_arr - pred)**2) / np.sum((mi_arr - np.mean(mi_arr))**2)
print(f"Power law: MI(β) = {C:.4f} · β^(-{p:.3f})")
print(f"R² = {r2:.6f}")
print(f"\n  {'β':>3}  {'Measured':>10}  {'Predicted':>10}  {'Error%':>8}")
for i in range(len(betas_arr)):
    err = abs(pred[i] - mi_arr[i]) / mi_arr[i] * 100
    print(f"  {int(betas_arr[i]):>3}  {mi_arr[i]:.6f}  {pred[i]:.6f}  {err:>7.1f}%")

# Exponential: MI = C * exp(-k*β)
from scipy.optimize import curve_fit
def exp_model(b, C, k):
    return C * np.exp(-k * b)
try:
    popt, pcov = curve_fit(exp_model, betas_arr, mi_arr, p0=[0.5, 1.0])
    pred_exp = exp_model(betas_arr, *popt)
    r2_exp = 1 - np.sum((mi_arr - pred_exp)**2) / np.sum((mi_arr - np.mean(mi_arr))**2)
    print(f"\nExponential: MI(β) = {popt[0]:.4f} · exp(-{popt[1]:.3f}·β)")
    print(f"R² = {r2_exp:.6f}")
    print(f"\n  {'β':>3}  {'Measured':>10}  {'Predicted':>10}  {'Error%':>8}")
    for i in range(len(betas_arr)):
        err = abs(pred_exp[i] - mi_arr[i]) / mi_arr[i] * 100
        print(f"  {int(betas_arr[i]):>3}  {mi_arr[i]:.6f}  {pred_exp[i]:.6f}  {err:>7.1f}%")
except Exception as e:
    print(f"Exponential fit failed: {e}")

# ---- Combined formula ----
print(f"\n=== COMPLETE f(α,β) FORMULA ===\n")
print(f"n_dead(α,β) = β  (dead bits at positions [α, α+1, ..., α+β-1] mod WS)")
print(f"n_active(β) = WS - β")
print(f"MI_per_pair(β) = {C:.4f} · β^(-{p:.3f})  (α irrelevant)")
print(f"total_MI(β) = (WS - β) · MI_per_pair(β)")
print(f"leak_rate(β) = total_MI(β) / WS")
print(f"\nDeath threshold: β ≥ {max(d[0] for d in mi_data)+1} → no signal (at WS=16)")

# ---- Cross-validate: predict Speck 48/96 and 64/128 from model ----
print(f"\n=== CROSS-VALIDATION: PREDICT REAL SPECK VARIANTS ===\n")
print("Using MI(β) model trained on WS=16 to predict WS=24/32/64:")
print("(Hypothesis: if MI depends ONLY on β, these predictions should match)\n")
# Speck 48/96: WS=24, α=8, β=3 → MI should be same as WS=16,β=3
# Speck 64/128: WS=32, α=8, β=3 → MI should be same as WS=16,β=3
# Speck 128/256: WS=64, α=8, β=3 → MI should be same as WS=16,β=3
predicted_mi_b3 = C * 3**(-p)
print(f"Model predicts MI/pair at β=3: {predicted_mi_b3:.6f}")
print(f"P4 measured Speck 48/96 (β=3): 0.011 (from P4)")
print(f"P4 measured Speck 64/128 (β=3): 0.011 (from P4)")
print(f"P4 measured Speck 128/256 (β=3): 0.011 (from P4)")
print(f"P5 measured WS=16, β=3: {mi_data[2][1] if len(mi_data)>2 else 'N/A':.6f}")

# Actually measure at WS=24 and WS=32 to confirm
print(f"\n--- Live measurement at larger word sizes ---")
for ws_name, ws, kw, alpha, beta, base in [
    ("Speck 48/96", 24, 4, 8, 3, 15),
    ("Speck 64/128", 32, 4, 8, 3, 18),
]:
    mi_diag = np.zeros(ws)
    for s_idx in range(SEEDS):
        seed = s_idx * 1000 + 42
        raw_R, bb, bpw = speck_gen(N, ws, kw, alpha, beta, base, seed)
        raw_R1, _, _ = speck_gen(N, ws, kw, alpha, beta, base + 1, seed)
        d_R = np.frombuffer(raw_R, dtype=np.uint8).reshape(-1, bb)
        d_R1 = np.frombuffer(raw_R1, dtype=np.uint8).reshape(-1, bb)
        x_R = np.zeros(N, dtype=np.uint64); y_R = np.zeros(N, dtype=np.uint64)
        y_R1 = np.zeros(N, dtype=np.uint64)
        for b in range(bpw):
            sh = 8*(bpw-1-b)
            x_R |= d_R[:,b].astype(np.uint64) << sh
            y_R |= d_R[:,bpw+b].astype(np.uint64) << sh
            y_R1 |= d_R1[:,bpw+b].astype(np.uint64) << sh
        diff_y = y_R ^ y_R1
        for i in range(ws):
            j = (i - alpha) % ws
            xb = ((x_R >> i) & 1).astype(np.uint8)
            dyb = ((diff_y >> j) & 1).astype(np.uint8)
            mi_diag[i] += mi_2x2(xb, dyb, N)
    mi_diag /= SEEDS
    active = mi_diag[mi_diag > 0.001]
    n_active = len(active)
    mi_per = np.mean(active) if n_active else 0
    print(f"  {ws_name}: n_active={n_active}/{ws} (pred={ws-beta}), MI/pair={mi_per:.6f} (pred={predicted_mi_b3:.6f})")

print("\n=== DONE ===")

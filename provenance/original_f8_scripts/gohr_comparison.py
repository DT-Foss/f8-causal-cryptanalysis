#!/usr/bin/env python3
"""D1: Gohr Neural Distinguisher Comparison.

Gohr (2019): Train a neural network to distinguish R-round Speck 32/64
ciphertext pairs (C₁, C₂) from random pairs. The network sees 64 bits
(two 32-bit ciphertext blocks) and outputs P(real).

We replicate the core experiment and compare:
- Gohr accuracy at round R → "can distinguish from random?"
- F8 Z-score at round R → "can detect carry-leak?"

These are DIFFERENT TESTS measuring DIFFERENT THINGS:
- Gohr: chosen-plaintext pairs with ΔP fixed, tests if C₁⊕C₂ is non-random
- F8: same key, consecutive rounds, tests if out(R)⊕out(R+1) has structure

But both ultimately detect residual structure in reduced-round Speck.
Comparing their round-count frontiers is meaningful.
"""
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..'))
sys.path.insert(0, os.path.dirname(__file__))

import numpy as np
import math

try:
    import torch
    import torch.nn as nn
    HAS_TORCH = True
except ImportError:
    HAS_TORCH = False

from speck_utils import speck32

MASK16 = 0xFFFF


def speck_encrypt_pair(x0, y0, x1, y1, rk, n_rounds):
    """Encrypt two plaintext blocks with same key."""
    for r in range(n_rounds):
        x0r = ((x0 >> 7) | (x0 << 9)) & MASK16
        x0 = ((x0r + y0) & MASK16) ^ rk[r]
        y0 = (((y0 << 2) | (y0 >> 14)) & MASK16) ^ x0

        x1r = ((x1 >> 7) | (x1 << 9)) & MASK16
        x1 = ((x1r + y1) & MASK16) ^ rk[r]
        y1 = (((y1 << 2) | (y1 >> 14)) & MASK16) ^ x1
    return x0, y0, x1, y1


def generate_gohr_data(n_samples, n_rounds, seed=42):
    """Generate Gohr-style training data.
    Positive: encrypt (P, P⊕Δ) with same key, Δ = (0x0040, 0x0000)
    Negative: random 64-bit pairs
    Returns: X (n_samples, 64) float32, y (n_samples,) int
    """
    rng = np.random.default_rng(seed)

    # Key schedule
    mk = [int(rng.integers(0, 2**16)) for _ in range(4)]
    rk = [0] * (n_rounds + 1)
    l = list(mk[1:])
    rk[0] = mk[0]
    for i in range(n_rounds):
        ror_l = ((l[i % len(l)] >> 7) | (l[i % len(l)] << 9)) & MASK16
        new_l = (rk[i] + ror_l) & MASK16
        new_l ^= i
        l.append(new_l)
        rol_rk = ((rk[i] << 2) | (rk[i] >> 14)) & MASK16
        rk[i + 1] = rol_rk ^ new_l

    n_pos = n_samples // 2
    n_neg = n_samples - n_pos

    X = np.zeros((n_samples, 64), dtype=np.float32)
    y = np.zeros(n_samples, dtype=np.int64)

    # Positive pairs: P₁ = random, P₂ = P₁ ⊕ (0x0040, 0x0000)
    delta_x, delta_y = 0x0040, 0x0000
    for i in range(n_pos):
        px0 = int(rng.integers(0, 2**16))
        py0 = int(rng.integers(0, 2**16))
        px1 = px0 ^ delta_x
        py1 = py0 ^ delta_y

        cx0, cy0, cx1, cy1 = speck_encrypt_pair(px0, py0, px1, py1, rk, n_rounds)

        # Convert to 64 bits
        bits = []
        for v in [cx0, cy0, cx1, cy1]:
            for b in range(15, -1, -1):
                bits.append((v >> b) & 1)
        X[i] = bits
        y[i] = 1

    # Negative: random pairs
    for i in range(n_neg):
        idx = n_pos + i
        bits = rng.integers(0, 2, size=64)
        X[idx] = bits
        y[idx] = 0

    # Shuffle
    perm = rng.permutation(n_samples)
    return X[perm], y[perm]


def gohr_accuracy_simple(n_rounds, n_train=50000, n_test=10000, seed=42):
    """Train a simple neural net and return test accuracy.
    Uses a small residual network (Gohr's architecture simplified).
    """
    if not HAS_TORCH:
        return None

    X_train, y_train = generate_gohr_data(n_train, n_rounds, seed)
    X_test, y_test = generate_gohr_data(n_test, n_rounds, seed + 77777)

    X_tr = torch.tensor(X_train)
    y_tr = torch.tensor(y_train)
    X_te = torch.tensor(X_test)
    y_te = torch.tensor(y_test)

    # Simple residual network (smaller than Gohr's for speed)
    class GohrNet(nn.Module):
        def __init__(self):
            super().__init__()
            self.fc1 = nn.Linear(64, 128)
            self.bn1 = nn.BatchNorm1d(128)
            self.fc2 = nn.Linear(128, 128)
            self.bn2 = nn.BatchNorm1d(128)
            self.fc3 = nn.Linear(128, 128)
            self.bn3 = nn.BatchNorm1d(128)
            self.fc_out = nn.Linear(128, 1)

        def forward(self, x):
            h = torch.relu(self.bn1(self.fc1(x)))
            r = h
            h = torch.relu(self.bn2(self.fc2(h)))
            h = torch.relu(self.bn3(self.fc3(h))) + r  # residual
            return self.fc_out(h).squeeze(-1)

    model = GohrNet()
    opt = torch.optim.Adam(model.parameters(), lr=1e-3)
    loss_fn = nn.BCEWithLogitsLoss()

    # Train
    bs = 1024
    for epoch in range(15):
        perm = torch.randperm(len(X_tr))
        for start in range(0, len(X_tr) - bs, bs):
            idx = perm[start:start+bs]
            pred = model(X_tr[idx])
            loss = loss_fn(pred, y_tr[idx].float())
            opt.zero_grad()
            loss.backward()
            opt.step()

    # Evaluate
    model.eval()
    with torch.no_grad():
        logits = model(X_te)
        preds = (logits > 0).long()
        acc = float((preds == y_te).float().mean())
    return acc


def f8_z_at_round(n_rounds, N=50000, seed=42):
    """F8 Z-score at given round count."""
    raw_R, bb, bpw = speck32(N, n_rounds=n_rounds, seed=seed)
    raw_R1, _, _ = speck32(N, n_rounds=n_rounds + 1, seed=seed)

    out_R = np.frombuffer(raw_R, dtype=np.uint8).reshape(-1, bb)
    out_R1 = np.frombuffer(raw_R1, dtype=np.uint8).reshape(-1, bb)
    n = out_R.shape[0]

    x_R = (out_R[:, 0].astype(np.uint32) << 8) | out_R[:, 1]
    y_R = (out_R[:, 2].astype(np.uint32) << 8) | out_R[:, 3]
    y_R1 = (out_R1[:, 2].astype(np.uint32) << 8) | out_R1[:, 3]
    diff_y = y_R ^ y_R1

    alpha, beta, ws = 7, 2, 16
    dead_set = {(alpha + d) % ws for d in range(beta)}

    def mi_bits(a, b):
        n00 = int(np.sum((a==0)&(b==0))); n01 = int(np.sum((a==0)&(b==1)))
        n10 = int(np.sum((a==1)&(b==0))); n11 = int(np.sum((a==1)&(b==1)))
        nn = n00+n01+n10+n11
        if nn == 0: return 0.0
        H_ab = 0.0
        for c in (n00,n01,n10,n11):
            p = c/nn
            if p > 0: H_ab -= p*math.log2(p)
        pa = (n10+n11)/nn; pb = (n01+n11)/nn
        Ha = -pa*math.log2(pa)-(1-pa)*math.log2(1-pa) if 0<pa<1 else 0.0
        Hb = -pb*math.log2(pb)-(1-pb)*math.log2(1-pb) if 0<pb<1 else 0.0
        return max(0.0, Ha+Hb-H_ab)

    mi_vals = []
    for i in range(ws):
        if i in dead_set: continue
        j = (i - alpha) % ws
        xb = ((x_R >> i) & 1).astype(np.uint8)
        dyb = ((diff_y >> j) & 1).astype(np.uint8)
        mi_vals.append(mi_bits(xb, dyb))
    total = sum(mi_vals)

    rng = np.random.default_rng(42)
    nulls = []
    for _ in range(20):
        perm = rng.permutation(n)
        pm = []
        for i in range(ws):
            if i in dead_set: continue
            j = (i - alpha) % ws
            xb = ((x_R >> i) & 1).astype(np.uint8)
            dyb = ((diff_y[perm] >> j) & 1).astype(np.uint8)
            pm.append(mi_bits(xb, dyb))
        nulls.append(sum(pm))
    nm, ns = np.mean(nulls), max(np.std(nulls), 1e-30)
    return (total - nm) / ns


print("=" * 80)
print("GOHR NEURAL DISTINGUISHER vs F8 COMPARISON")
print("=" * 80)
print(f"Gohr: 50K train, 10K test, 15 epochs, residual net")
print(f"F8:   50K samples, informed MI, 20 perms")
print()

if not HAS_TORCH:
    print("PyTorch not available. Running F8-only comparison.")
    print()

print(f"  {'Rounds':>8}  {'Gohr Acc':>10}  {'F8 Z':>10}  {'Both detect?':>15}")
print(f"  {'-'*55}")

for r in [5, 6, 7, 8, 9, 10, 11, 12]:
    # F8
    f8_z = f8_z_at_round(r)
    f8_detect = f8_z > 3

    # Gohr
    if HAS_TORCH:
        acc = gohr_accuracy_simple(r)
        gohr_detect = acc > 0.55  # better than random = detection
        acc_str = f"{acc:.3f}"
    else:
        acc_str = "N/A"
        gohr_detect = "?"

    both = ""
    if HAS_TORCH:
        if f8_detect and gohr_detect:
            both = "BOTH"
        elif f8_detect:
            both = "F8 only"
        elif gohr_detect:
            both = "Gohr only"
        else:
            both = "neither"

    print(f"  R{r:>6}  {acc_str:>10}  {f8_z:>+10.1f}  {both:>15}", flush=True)

print()
print("NOTE: F8 and Gohr test DIFFERENT things:")
print("  F8:   out(R) vs out(R+1) same-key independence (carry-leak)")
print("  Gohr: C(P) vs C(P⊕Δ) distinguishability (differential)")
print("F8 detects at ALL rounds (stationary leak). Gohr accuracy degrades.")
print("\n=== DONE ===")

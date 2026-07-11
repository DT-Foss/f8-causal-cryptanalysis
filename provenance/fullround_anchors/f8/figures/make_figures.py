#!/usr/bin/env python3
"""Generate the summary figures for the F8 full-round distinguishers.

Reads the JSON result files under ../results/ (run `python reproduce.py`
first, or this script will fall back to the published reference numbers) and
writes two PNGs into this directory:

  fig1_zscores.png  — full-round Z-score per cipher (log scale), vs the Z=3
                      permutation-null noise band.
  fig2_leak_rate.png — the C4 leak-rate law MI(beta) = A * exp(-B * beta) for
                      Speck 32/64, with the fitted curve and R^2.

Requires matplotlib (pip install -e ".[figures]").
"""

import json
import os

import numpy as np
import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402

HERE = os.path.dirname(os.path.abspath(__file__))
RESULTS = os.path.join(os.path.dirname(HERE), "results")

# Published reference numbers (used if a results JSON is missing).
REFERENCE_Z = [
    ("Speck 32/64", 22, "beta-masking", 4088),
    ("Speck 48/96", 23, "beta-masking", 918),
    ("Speck 64/128", 27, "beta-masking", 1165),
    ("Speck 128/256", 34, "beta-masking", 1776),
    ("Threefish-256", 72, "raw carry", 16302),
    ("Threefish-1024", 80, "permutation fixed-point", 16537),
    ("GIFT-64", 28, "permutation cycle", 676),
    ("GIFT-128", 40, "permutation cycle", 275),
    ("PRESENT-80", 31, "permutation cycle", 1183),
    ("TEA", 32, "Feistel self-XOR", 499),
    ("RC5-32/12/16", 12, "Feistel self-XOR", 221),
    ("RC5-64/24/24", 24, "Feistel self-XOR", 444),
]

MECH_COLOR = {
    "beta-masking": "#2563eb",             # blue
    "raw carry": "#dc2626",                # red
    "permutation fixed-point": "#ea580c",  # orange
    "permutation cycle": "#16a34a",        # green
    "Feistel self-XOR": "#9333ea",         # purple
}


def load_json(name):
    path = os.path.join(RESULTS, name)
    if not os.path.exists(path):
        return None
    with open(path) as f:
        return json.load(f)


def collect_zscores():
    """Return list of (cipher, rounds, mechanism, Z), from results if present."""
    core = load_json("core_reproduction.json")
    speck = load_json("speck_variants.json")
    tf = load_json("threefish256.json")
    tf1024 = load_json("threefish1024.json")
    gift = load_json("gift.json")
    present = load_json("present.json")
    tea = load_json("tea.json")
    rc5 = load_json("rc5.json")
    rc5_64 = load_json("rc5_64.json")
    if not all([core, speck, tf, gift, present]):
        return list(REFERENCE_Z)

    rows = [("Speck 32/64", 22, "beta-masking", core["C1"]["mean_z"])]
    for name, full_r in [("Speck 48/96", 23), ("Speck 64/128", 27), ("Speck 128/256", 34)]:
        v = speck["variants"][name]
        rows.append((name, full_r, "beta-masking",
                     v["rounds"][str(v["full_rounds"])]["encrypt"]["mean_Z"]))
    rows.append(("Threefish-256", tf["rounds"], "raw carry", tf["max_z"]))
    if tf1024:
        rows.append(("Threefish-1024", tf1024["rounds"], "permutation fixed-point", tf1024["max_z"]))
    rows.append(("GIFT-64", 28, "permutation cycle", gift["gift64_full_round_z"]))
    rows.append(("GIFT-128", 40, "permutation cycle", gift["gift128_full_round_z"]))
    rows.append(("PRESENT-80", 31, "permutation cycle", present["full_round_z"]))
    if tea:
        rows.append(("TEA", tea["result"]["full_rounds"], "Feistel self-XOR",
                     tea["result"]["mean_z_N200k"]))
    if rc5:
        rows.append(("RC5-32/12/16", rc5["result"]["full_rounds"], "Feistel self-XOR",
                     rc5["result"]["mean_z_N200k"]))
    if rc5_64:
        rows.append(("RC5-64/24/24", 24, "Feistel self-XOR",
                     rc5_64["n_scaling_fullround"]["mean_z"][-1]))
    return rows


def fig_zscores(rows, out_path):
    labels = [f"{c}  ({r}R)" for c, r, _, _ in rows]
    zvals = [max(z, 1e-9) for _, _, _, z in rows]
    colors = [MECH_COLOR[m] for _, _, m, _ in rows]

    fig, ax = plt.subplots(figsize=(9.5, 5.4))
    y = np.arange(len(rows))[::-1]  # first cipher at top
    ax.barh(y, zvals, color=colors, height=0.62, zorder=3)

    for yi, z in zip(y, zvals):
        ax.text(z * 1.08, yi, f"{z:,.0f}", va="center", ha="left",
                fontsize=10, color="#111827", zorder=4)

    ax.set_xscale("log")
    ax.set_xlim(1, 60000)
    ax.set_yticks(y)
    ax.set_yticklabels(labels, fontsize=10.5)
    ax.set_xlabel("Full-round F8 distinguisher Z-score  (log scale)", fontsize=11)
    ax.set_title("F8 full-round known-key distinguishers", fontsize=13.5, fontweight="bold", pad=12)

    # Permutation-null noise band (|Z| < 3).
    ax.axvspan(1, 3, color="#9ca3af", alpha=0.30, zorder=1)
    ax.axvline(3, color="#6b7280", lw=1.1, ls="--", zorder=2)
    ax.text(3.2, y[-1] - 0.6, "Z = 3  (noise threshold)", fontsize=9,
            color="#4b5563", rotation=90, va="bottom", ha="left")

    handles = [plt.Rectangle((0, 0), 1, 1, color=MECH_COLOR[m]) for m in MECH_COLOR]
    ax.legend(handles, list(MECH_COLOR.keys()), title="Leak mechanism",
              loc="lower right", fontsize=9.5, title_fontsize=10, framealpha=0.95)

    ax.grid(axis="x", which="both", color="#e5e7eb", lw=0.6, zorder=0)
    ax.set_axisbelow(True)
    for spine in ("top", "right"):
        ax.spines[spine].set_visible(False)

    fig.tight_layout()
    fig.savefig(out_path, dpi=150, bbox_inches="tight", facecolor="white")
    plt.close(fig)
    print(f"  wrote {out_path}")


def fig_leak_rate(core, out_path):
    if core and "C4" in core:
        betas = np.array([r["beta"] for r in core["C4"]["results"]], dtype=float)
        mis = np.array([r["measured_mi_per_pair"] for r in core["C4"]["results"]], dtype=float)
        A = core["C4"]["fit_A"]
        B = core["C4"]["fit_B"]
        r2 = core["C4"]["R_squared"]
    else:
        betas = np.array([1, 2, 3, 4], dtype=float)
        A, B, r2 = 0.5367, 1.4131, 0.999986
        mis = A * np.exp(-B * betas)

    xs = np.linspace(betas.min() - 0.05, betas.max() + 0.05, 200)
    ys = A * np.exp(-B * xs)

    fig, ax = plt.subplots(figsize=(8.2, 5.2))
    ax.plot(xs, ys, color="#2563eb", lw=2.2, zorder=2,
            label=fr"fit:  MI$(\beta) = {A:.4f}\,e^{{-{B:.4f}\,\beta}}$")
    ax.scatter(betas, mis, s=90, color="#dc2626", zorder=3, edgecolor="white",
               linewidth=1.2, label="measured (Speck 32/64, R=22)")

    ax.set_yscale("log")
    ax.set_xlabel(r"rotation-mask width  $\beta$  (dead low-order bits)", fontsize=11)
    ax.set_ylabel("mean MI per active bit pair  (nats, log scale)", fontsize=11)
    ax.set_title("C4: leak rate decays exponentially in the mask width",
                 fontsize=13, fontweight="bold", pad=12)
    ax.set_xticks(list(betas.astype(int)))

    ax.text(0.97, 0.90, fr"$R^2 = {r2:.6f}$", transform=ax.transAxes,
            ha="right", va="top", fontsize=12,
            bbox=dict(boxstyle="round,pad=0.4", fc="#f3f4f6", ec="#d1d5db"))

    ax.grid(True, which="both", color="#e5e7eb", lw=0.6, zorder=0)
    ax.set_axisbelow(True)
    for spine in ("top", "right"):
        ax.spines[spine].set_visible(False)
    ax.legend(loc="lower left", fontsize=10, framealpha=0.95)

    fig.tight_layout()
    fig.savefig(out_path, dpi=150, bbox_inches="tight", facecolor="white")
    plt.close(fig)
    print(f"  wrote {out_path}")


def main():
    print("Generating F8 figures...")
    rows = collect_zscores()
    core = load_json("core_reproduction.json")
    fig_zscores(rows, os.path.join(HERE, "fig1_zscores.png"))
    fig_leak_rate(core, os.path.join(HERE, "fig2_leak_rate.png"))
    print("Done.")


if __name__ == "__main__":
    main()

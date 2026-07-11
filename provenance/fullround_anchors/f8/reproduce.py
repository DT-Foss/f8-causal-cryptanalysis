#!/usr/bin/env python3
"""Master reproduction script for the F8 full-round distinguishers.

Runs each experiment in turn (core Speck 32/64 properties, all four Speck
variants, Threefish-256, Threefish-1024, GIFT-64/128, PRESENT-80, TEA,
RC5), then prints one summary table of the full-round Z-scores. Each
experiment also writes its own JSON result under results/.

Usage:
    python reproduce.py

Runs with no arguments and finishes in a few minutes on a laptop.
"""

import json
import os
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
EXP = os.path.join(HERE, "experiments")
RESULTS = os.path.join(HERE, "results")

# (label, script path, results JSON) for each experiment to run.
EXPERIMENTS = [
    ("Speck 32/64 core (C1-C6)", os.path.join(EXP, "reproduce_core.py"),
     os.path.join(RESULTS, "core_reproduction.json")),
    ("Speck variants (full-round)", os.path.join(EXP, "speck_variants.py"),
     os.path.join(RESULTS, "speck_variants.json")),
    ("Threefish-256 (full-round)", os.path.join(EXP, "threefish256.py"),
     os.path.join(RESULTS, "threefish256.json")),
    ("Threefish-1024 (full-round)", os.path.join(EXP, "threefish1024.py"),
     os.path.join(RESULTS, "threefish1024.json")),
    ("GIFT-64 / GIFT-128 (full-round)", os.path.join(EXP, "gift.py"),
     os.path.join(RESULTS, "gift.json")),
    ("PRESENT-80 (full-round)", os.path.join(EXP, "present.py"),
     os.path.join(RESULTS, "present.json")),
    ("TEA (full-round)", os.path.join(EXP, "tea.py"),
     os.path.join(RESULTS, "tea.json")),
    ("RC5-32/12/16 (full-round)", os.path.join(EXP, "rc5.py"),
     os.path.join(RESULTS, "rc5.json")),
    ("RC5-64/24/24 (full-round)", os.path.join(EXP, "rc5_64.py"),
     os.path.join(RESULTS, "rc5_64.json")),
]


def run(label, script):
    print("\n" + "#" * 78)
    print(f"# {label}")
    print(f"# {script}")
    print("#" * 78)
    t0 = time.time()
    proc = subprocess.run([sys.executable, script], cwd=HERE)
    dt = time.time() - t0
    if proc.returncode != 0:
        print(f"\n!!! {label} FAILED (exit {proc.returncode}) !!!")
        raise SystemExit(proc.returncode)
    print(f"\n[{label}: {dt:.1f}s]")
    return dt


def load(path):
    with open(path) as f:
        return json.load(f)


def summarize():
    """Build the full-round distinguisher table from the written JSON results."""
    rows = []  # (cipher, rounds, mechanism, z)

    core = load(os.path.join(RESULTS, "core_reproduction.json"))
    speck = load(os.path.join(RESULTS, "speck_variants.json"))
    tf = load(os.path.join(RESULTS, "threefish256.json"))
    tf1024 = load(os.path.join(RESULTS, "threefish1024.json"))
    gift = load(os.path.join(RESULTS, "gift.json"))
    present = load(os.path.join(RESULTS, "present.json"))
    tea = load(os.path.join(RESULTS, "tea.json"))
    rc5 = load(os.path.join(RESULTS, "rc5.json"))
    rc5_64 = load(os.path.join(RESULTS, "rc5_64.json"))

    # Speck 32/64: prefer the 3-seed mean Z from the core reproduction (C1).
    z_speck32 = core["C1"]["mean_z"]
    rows.append(("Speck 32/64", 22, "beta-masking", z_speck32))

    # Other Speck variants: full-round encrypt Z from speck_variants.
    for name in ["Speck 48/96", "Speck 64/128", "Speck 128/256"]:
        v = speck["variants"][name]
        full_r = v["full_rounds"]
        enc_z = v["rounds"][str(full_r)]["encrypt"]["mean_Z"]
        rows.append((name, full_r, "beta-masking", enc_z))

    rows.append(("Threefish-256", tf["rounds"], "raw carry", tf["max_z"]))
    rows.append(("Threefish-1024", tf1024["rounds"], "permutation fixed-point", tf1024["max_z"]))
    rows.append(("GIFT-64", 28, "permutation cycle", gift["gift64_full_round_z"]))
    rows.append(("GIFT-128", 40, "permutation cycle", gift["gift128_full_round_z"]))
    rows.append(("PRESENT-80", 31, "permutation cycle", present["full_round_z"]))
    rows.append(("TEA", tea["result"]["full_rounds"], "Feistel self-XOR",
                tea["result"]["mean_z_N200k"]))
    rows.append(("RC5-32/12/16", rc5["result"]["full_rounds"], "Feistel self-XOR",
                rc5["result"]["mean_z_N200k"]))
    rows.append(("RC5-64/24/24", 24, "Feistel self-XOR",
                rc5_64["n_scaling_fullround"]["mean_z"][-1]))

    print("\n" + "=" * 78)
    print("  F8 FULL-ROUND DISTINGUISHERS — SUMMARY")
    print("=" * 78)
    print(f"  {'Cipher':<16}{'Rounds':>8}{'Mechanism':>26}{'Z-score':>16}")
    print("  " + "-" * 64)
    for cipher, rounds, mech, z in rows:
        print(f"  {cipher:<16}{rounds:>8}{mech:>26}{z:>+16.0f}")
    print("  " + "-" * 64)
    print("  Permutation-null threshold for a structural leak: Z >> 3.")
    print("=" * 78)

    # C1-C6 verdicts from the core reproduction.
    print("\n  Core F8 signal properties (Speck 32/64):")
    for c in ["C1", "C2", "C3", "C4", "C5", "C6"]:
        print(f"    {c}: {core[c]['description']:<40} [{core[c]['verdict']}]")


def main():
    os.makedirs(RESULTS, exist_ok=True)
    print("=" * 78)
    print("  F8 — MASTER REPRODUCTION")
    print("  Cross-round carry-leak distinguishers, full rounds")
    print("=" * 78)

    t0 = time.time()
    for label, script, _ in EXPERIMENTS:
        run(label, script)
    total = time.time() - t0

    summarize()
    print(f"\n  Total reproduction time: {total:.1f}s ({total / 60:.1f} min)")


if __name__ == "__main__":
    main()

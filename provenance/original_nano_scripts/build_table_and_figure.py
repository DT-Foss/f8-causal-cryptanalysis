#!/usr/bin/env python3
"""
build_table_and_figure.py — Generate paper table (CSV) and cross-family diffusion plot.

Table: Coverage matrix with Standard-CASI frontier + F8 result per cipher.
Figure 1: Cross-family diffusion curves (CASI vs normalized round count).
"""

import json
import os
import csv
import numpy as np

BASE_DIR = '<legacy-nano-root>'
RAW_DIR = os.path.join(BASE_DIR, 'raw_data')
TABLES_DIR = os.path.join(BASE_DIR, 'tables')
FIGURES_DIR = os.path.join(BASE_DIR, 'figures')

FAMILY_DIRS = ['speck', 'simon', 'present', 'ascon', 'lea', 'grain128a', 'gift', 'skinny', 'katan']


def load_master():
    """Load master results."""
    path = os.path.join(BASE_DIR, 'results', 'master_results.json')
    return json.load(open(path))


def build_paper_table():
    """Build CSV table for paper: one row per cipher family representative."""
    master = load_master()

    # Select representative ciphers (smallest/most common variant per family)
    representatives = [
        'speck32_64', 'speck64_128', 'speck128_256',
        'simon32_64', 'simon64_128', 'simon128_256',
        'present80', 'present128',
        'ascon128', 'ascon128a',
        'lea128', 'lea192', 'lea256',
        'grain128a',
    ]

    # Build name→entry map
    entry_map = {e['cipher']: e for e in master['ciphers']}

    rows = []
    for name in representatives:
        if name not in entry_map:
            continue
        e = entry_map[name]
        casi = e.get('standard_casi', {})
        f8 = e.get('f8_distinguisher', {})

        row = {
            'Cipher': name,
            'Family': e.get('family', ''),
            'ISO Standard': e.get('iso_standard', ''),
            'Block (bits)': e.get('block_size', ''),
            'Key (bits)': e.get('key_size', ''),
            'Full Rounds': e.get('full_rounds', ''),
            'Std-CASI Frontier': f"R{casi['frontier_round']}" if casi.get('frontier_round') else 'CLEAN',
            'Std-CASI Margin %': casi.get('security_margin_percent', ''),
            'Full-Round CASI': casi.get('full_round_casi', ''),
            'F8 t-stat': f8.get('full_round_t_statistic', 'N/A'),
            'F8 All Broken': f8.get('all_rounds_broken', 'N/A'),
            'F8 Verdict': 'ALL BROKEN' if f8.get('all_rounds_broken') else ('IMMUNE' if f8.get('all_rounds_broken') is False else 'N/A'),
        }
        rows.append(row)

    # Write CSV
    outpath = os.path.join(TABLES_DIR, 'paper_table_1.csv')
    with open(outpath, 'w', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=rows[0].keys())
        writer.writeheader()
        writer.writerows(rows)
    print(f"Table saved: {outpath}")

    # Also write full table (all 30 ciphers)
    all_rows = []
    for e in master['ciphers']:
        casi = e.get('standard_casi', {})
        f8 = e.get('f8_distinguisher', {})
        row = {
            'Cipher': e['cipher'],
            'Family': e.get('family', ''),
            'ISO Standard': e.get('iso_standard', ''),
            'Block (bits)': e.get('block_size', ''),
            'Key (bits)': e.get('key_size', ''),
            'Full Rounds': e.get('full_rounds', ''),
            'Std-CASI Frontier': f"R{casi['frontier_round']}" if casi.get('frontier_round') else 'CLEAN',
            'Std-CASI Margin %': casi.get('security_margin_percent', ''),
            'Full-Round CASI': casi.get('full_round_casi', ''),
            'F8 t-stat': f8.get('full_round_t_statistic', 'N/A'),
            'F8 All Broken': f8.get('all_rounds_broken', 'N/A'),
            'F8 Verdict': 'ALL BROKEN' if f8.get('all_rounds_broken') else ('IMMUNE' if f8.get('all_rounds_broken') is False else 'N/A'),
        }
        all_rows.append(row)

    fullpath = os.path.join(TABLES_DIR, 'full_coverage_matrix.csv')
    with open(fullpath, 'w', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=all_rows[0].keys())
        writer.writeheader()
        writer.writerows(all_rows)
    print(f"Full table saved: {fullpath}")


def build_diffusion_plot():
    """Build cross-family diffusion plot (Fig 1).

    X: Round count normalized to % of full rounds
    Y: CASI value (log scale)
    One line per cipher family (using representative cipher)
    Horizontal line at CASI=2.0 (detection threshold)
    """
    import matplotlib
    matplotlib.use('Agg')
    import matplotlib.pyplot as plt
    from matplotlib import rcParams

    # Publication quality settings
    rcParams['font.family'] = 'serif'
    rcParams['font.size'] = 11
    rcParams['axes.linewidth'] = 0.8
    rcParams['lines.linewidth'] = 1.5
    rcParams['figure.dpi'] = 300

    # Representative ciphers per family
    reps = {
        'Speck 32/64': ('speck', 'speck32_64_full_sweep.json'),
        'Speck 128/256': ('speck', 'speck128_256_full_sweep.json'),
        'SIMON 32/64': ('simon', 'simon32_64_full_sweep.json'),
        'SIMON 128/256': ('simon', 'simon128_256_full_sweep.json'),
        'PRESENT-80': ('present', 'present80_full_sweep.json'),
        'ASCON-128': ('ascon', 'ascon128_full_sweep.json'),
        'LEA-128': ('lea', 'lea128_full_sweep.json'),
        'Grain-128a': ('grain128a', 'grain128a_full_sweep.json'),
    }

    # Colors — distinct, colorblind-safe
    colors = {
        'Speck 32/64': '#e41a1c',      # red
        'Speck 128/256': '#984ea3',     # purple
        'SIMON 32/64': '#377eb8',       # blue
        'SIMON 128/256': '#4daf4a',     # green
        'PRESENT-80': '#ff7f00',        # orange
        'ASCON-128': '#a65628',         # brown
        'LEA-128': '#f781bf',           # pink
        'Grain-128a': '#999999',        # gray
    }

    markers = {
        'Speck 32/64': 'o',
        'Speck 128/256': 's',
        'SIMON 32/64': '^',
        'SIMON 128/256': 'D',
        'PRESENT-80': 'v',
        'ASCON-128': 'P',
        'LEA-128': 'X',
        'Grain-128a': '*',
    }

    fig, ax = plt.subplots(figsize=(10, 6))

    for label, (family_dir, filename) in reps.items():
        fpath = os.path.join(RAW_DIR, family_dir, filename)
        if not os.path.exists(fpath):
            print(f"  Skip {label}: {fpath} not found")
            continue

        data = json.load(open(fpath))
        full_r = data['full_rounds']
        rounds_norm = []
        casi_vals = []

        for r in data['results']:
            rn = r['round']
            casi = r['max_casi']
            rounds_norm.append(rn / full_r * 100)
            casi_vals.append(max(casi, 0.5))  # Floor for log scale

        ax.semilogy(rounds_norm, casi_vals,
                     color=colors[label], marker=markers[label],
                     markersize=5, label=label, alpha=0.85)

    # Detection threshold
    ax.axhline(y=2.0, color='#333333', linestyle='--', linewidth=1.0, alpha=0.7, label='Detection threshold (CASI=2.0)')

    # Formatting
    ax.set_xlabel('Round Count (% of full rounds)', fontsize=12)
    ax.set_ylabel('CASI Score (log scale)', fontsize=12)
    ax.set_title('Cross-Family Cipher Diffusion: CASI vs Round Progression', fontsize=13, fontweight='bold')
    ax.legend(loc='upper right', fontsize=8, framealpha=0.9, ncol=2)
    ax.set_xlim(0, 105)
    ax.set_ylim(0.5, 1e7)
    ax.grid(True, alpha=0.3, which='both')

    # Save
    figpath = os.path.join(FIGURES_DIR, 'fig1_cross_family_diffusion.png')
    fig.savefig(figpath, dpi=300, bbox_inches='tight', facecolor='white')
    print(f"Figure saved: {figpath}")

    # Also PDF for LaTeX
    pdfpath = os.path.join(FIGURES_DIR, 'fig1_cross_family_diffusion.pdf')
    fig.savefig(pdfpath, bbox_inches='tight', facecolor='white')
    print(f"PDF saved: {pdfpath}")

    plt.close()


if __name__ == '__main__':
    os.makedirs(TABLES_DIR, exist_ok=True)
    os.makedirs(FIGURES_DIR, exist_ok=True)

    print("Building paper table...")
    build_paper_table()

    print("\nBuilding cross-family diffusion plot...")
    build_diffusion_plot()

    print("\nDone.")

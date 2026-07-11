#!/usr/bin/env python3
"""
build_master_results.py — Merge standard CASI + F8 results into master_results.json.

Reads all *_full_sweep.json and *_f8_sweep.json from raw_data/,
produces a unified results/master_results.json with both metrics per cipher.
"""

import json
import os
import time

BASE_DIR = '<legacy-nano-root>'
RAW_DIR = os.path.join(BASE_DIR, 'raw_data')
RESULTS_DIR = os.path.join(BASE_DIR, 'results')

# ISO standards lookup
ISO_MAP = {
    'ARX-Feistel': 'ISO/IEC 29167-22',
    'Feistel-LWC': 'ISO/IEC 29167-21',
    'SPN-ultralight': 'ISO/IEC 29167-11',
    'Sponge-LWC': 'NIST SP 800-232',
    'ARX-block': 'Korean TTA',
    'LFSR-NFSR': 'ISO/IEC 29167-13',
    'SPN-LWC': None,
    'SPN-TBC': None,
    'LFSR-block': None,
}

FAMILY_DIRS = ['speck', 'simon', 'present', 'ascon', 'lea', 'grain128a', 'gift', 'skinny', 'katan']


def load_all_results():
    """Load all standard CASI and F8 sweep results."""
    casi_results = {}
    f8_results = {}

    for family_dir in FAMILY_DIRS:
        dirpath = os.path.join(RAW_DIR, family_dir)
        if not os.path.exists(dirpath):
            continue
        for f in os.listdir(dirpath):
            fpath = os.path.join(dirpath, f)
            if f.endswith('_full_sweep.json'):
                data = json.load(open(fpath))
                name = data['cipher']
                casi_results[name] = data
            elif f.endswith('_f8_sweep.json'):
                data = json.load(open(fpath))
                name = data['cipher']
                f8_results[name] = data

    return casi_results, f8_results


def build_master():
    """Build master results combining both metrics."""
    casi, f8 = load_all_results()

    # All cipher names from both
    all_names = sorted(set(list(casi.keys()) + list(f8.keys())))

    master = []
    for name in all_names:
        entry = {'cipher': name}

        # Standard CASI data
        if name in casi:
            c = casi[name]
            entry['full_rounds'] = c['full_rounds']
            entry['block_size'] = c['block_size']
            entry['key_size'] = c['key_size']
            entry['family'] = c['family']
            entry['iso_standard'] = c.get('iso_standard', ISO_MAP.get(c['family']))
            entry['standard_casi'] = {
                'frontier_round': c['frontier'],
                'security_margin': c['security_margin'],
                'security_margin_percent': c['security_margin_pct'],
                'full_round_casi': c['full_round_casi'],
                'best_strategy': _best_strategy(c),
            }

        # F8 data
        if name in f8:
            d = f8[name]
            # Get full-round sig rate from last result entry
            full_sig_rate = None
            for r in d['results']:
                if r['base_round'] + r['n_round_pairs'] >= d['full_rounds']:
                    full_sig_rate = r['sig_rate_mean']

            entry['f8_distinguisher'] = {
                'full_round_t_statistic': d['full_round_t_stat'],
                'full_round_sig_rate': full_sig_rate,
                'all_rounds_broken': d['full_round_detected'],
                'verdict': _f8_verdict(d),
            }

            # If no standard CASI, fill from F8 metadata
            if name not in casi:
                entry['full_rounds'] = d['full_rounds']
                entry['block_size'] = d['block_bytes'] * 8

        master.append(entry)

    return master


def _best_strategy(casi_data):
    """Find best strategy from CASI sweep."""
    best = None
    best_score = 0
    for r in casi_data.get('results', []):
        if r.get('top_strategy_signal', 0) > best_score:
            best_score = r['top_strategy_signal']
            best = r['top_strategy']
    return best


def _f8_verdict(f8_data):
    """Generate F8 verdict string."""
    if f8_data['full_round_detected']:
        return 'FULLY BROKEN — stationary carry-leak across all rounds'
    else:
        t = f8_data['full_round_t_stat']
        if t > 2.0:
            return 'WEAK — borderline detection at full rounds'
        else:
            return 'IMMUNE — no carry-leak detected'


if __name__ == '__main__':
    os.makedirs(RESULTS_DIR, exist_ok=True)

    master = build_master()

    output = {
        'title': 'nano-casi: CASI + F8 Characterization of Nano-IoT Cipher Families',
        'author': 'David Tom Foss — IEEE Member #102121836',
        'casi_version': 'live-casi 0.9.1',
        'f8_reference': 'ICECET 2026 Paper #1142',
        'timestamp': time.strftime('%Y-%m-%dT%H:%M:%S'),
        'n_ciphers': len(master),
        'ciphers': master,
    }

    outpath = os.path.join(RESULTS_DIR, 'master_results.json')
    with open(outpath, 'w') as f:
        json.dump(output, f, indent=2)

    print(f"Master results saved: {outpath}")
    print(f"Total ciphers: {len(master)}")

    # Print summary table
    print(f"\n{'='*100}")
    print(f"  NANO-IoT CIPHER CHARACTERIZATION — MASTER TABLE")
    print(f"{'='*100}")
    print(f"{'Cipher':>20}  {'ISO':>16}  {'Rounds':>6}  {'CASI-Fr':>8}  {'Margin':>7}  {'F8-t':>8}  {'F8 Verdict':>15}")
    print(f"{'─'*20}  {'─'*16}  {'─'*6}  {'─'*8}  {'─'*7}  {'─'*8}  {'─'*15}")

    for entry in master:
        name = entry['cipher']
        iso = entry.get('iso_standard', 'N/A') or 'N/A'
        if len(iso) > 16:
            iso = iso[:16]
        fr = entry.get('full_rounds', '?')
        casi_fr = entry.get('standard_casi', {}).get('frontier_round')
        casi_fr_str = f'R{casi_fr}' if casi_fr else 'CLEAN'
        margin = entry.get('standard_casi', {}).get('security_margin_percent', '')
        margin_str = f'{margin:.0f}%' if margin else ''

        f8_t = entry.get('f8_distinguisher', {}).get('full_round_t_statistic')
        f8_t_str = f'{f8_t:+.1f}' if f8_t is not None else 'N/A'
        f8_broken = entry.get('f8_distinguisher', {}).get('all_rounds_broken')
        if f8_broken is True:
            f8_v = 'ALL BROKEN'
        elif f8_broken is False:
            f8_v = 'IMMUNE'
        else:
            f8_v = 'N/A'

        print(f"{name:>20}  {iso:>16}  {fr:>6}  {casi_fr_str:>8}  {margin_str:>7}  {f8_t_str:>8}  {f8_v:>15}")

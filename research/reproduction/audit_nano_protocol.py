#!/usr/bin/env python3
"""Audit retained Nano sweeps against the protocol stated in the manuscript."""

from __future__ import annotations

import argparse
import json
from collections import Counter
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
RAW_ROOT = ROOT / "data/reference/nano_iot_raw"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()

    full_sweeps = sorted(RAW_ROOT.rglob("*_full_sweep.json"))
    f8_sweeps = sorted(RAW_ROOT.rglob("*_f8_sweep.json"))
    records = [json.loads(path.read_text()) for path in full_sweeps]
    frontier_failures = []
    sparse = []
    strategy_winners = Counter()

    for path, record in zip(full_sweeps, records, strict=True):
        rounds = [point["round"] for point in record["results"]]
        if rounds != list(range(1, record["full_rounds"] + 1)):
            sparse.append(record["cipher"])
        frontier = record.get("frontier")
        if frontier is not None:
            point = next(item for item in record["results"] if item["round"] == frontier)
            standard = point["per_seed_casi"]
            amplified = point["per_seed_ampli"]
            paired_max = [max(left, right) for left, right in zip(standard, amplified, strict=True)]
            if not all(value > 2.0 for value in paired_max):
                frontier_failures.append(
                    {
                        "cipher": record["cipher"],
                        "frontier": frontier,
                        "per_seed_standard": standard,
                        "per_seed_amplified": amplified,
                        "per_seed_operational_max": paired_max,
                        "seeds_above_two": sum(value > 2.0 for value in paired_max),
                    }
                )
        best = max(
            record["results"], key=lambda point: point.get("top_strategy_signal", 0.0)
        ).get("top_strategy")
        strategy_winners[best] += 1

    payload = {
        "schema_version": 1,
        "experiment": "retained_nano_protocol_audit",
        "paper_protocol": {
            "samples": 5000,
            "seeds": 5,
            "round_grid": "every round",
            "frontier_rule": "all five seeds above CASI 2",
        },
        "retained_protocol": {
            "full_sweep_files": len(full_sweeps),
            "f8_sweep_files": len(f8_sweeps),
            "sample_counts": sorted({record.get("n_samples") for record in records}),
            "seed_counts": sorted({record.get("n_seeds") for record in records}),
            "complete_round_grids": len(records) - len(sparse),
            "sparse_round_grids": len(sparse),
            "sparse_ciphers": sparse,
            "mean_based_frontiers_failing_all_seed_rule": frontier_failures,
            "n_frontier_failures": len(frontier_failures),
            "strongest_strategy_counts": dict(sorted(strategy_winners.items())),
        },
        "conclusions": {
            "sample_count_matches_paper": all(
                record.get("n_samples") == 5000 for record in records
            ),
            "every_round_matches_paper": not sparse,
            "all_seed_frontier_rule_matches_paper": not frontier_failures,
        },
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n")
    print(f"full sweeps: {len(full_sweeps)}, F8 sweeps: {len(f8_sweeps)}")
    print(f"complete grids: {len(records) - len(sparse)}, sparse grids: {len(sparse)}")
    print(f"frontiers failing all-seed rule: {len(frontier_failures)}")
    print(f"wrote {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

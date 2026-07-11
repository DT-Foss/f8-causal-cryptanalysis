"""Experiment orchestration and stable JSON result records."""

from __future__ import annotations

import json
import platform
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import numpy as np
import scipy

from .f8 import run_target

PROFILES: dict[str, dict[str, Any]] = {
    "quick": {
        "description": "CI/smoke profile: deterministic and finishes in seconds",
        "n_blocks": 2000,
        "n_seeds": 3,
        "n_round_pairs": 2,
        "shift": 5,
        "targets": ["speck32_64", "simon32_64", "threefish256"],
    },
    "full": {
        "description": "Paper-scale full-round profile; expect a long CPU-only run",
        "n_blocks": 20000,
        "n_seeds": 10,
        "n_round_pairs": 8,
        "shift": 5,
        "targets": [
            "speck32_64",
            "speck48_72",
            "speck48_96",
            "speck64_96",
            "speck64_128",
            "speck96_96",
            "speck96_144",
            "speck128_128",
            "speck128_192",
            "speck128_256",
            "simon32_64",
            "threefish256",
        ],
    },
}


def run_profile(
    name: str,
    *,
    targets: list[str] | None = None,
    n_blocks: int | None = None,
    n_seeds: int | None = None,
    n_round_pairs: int | None = None,
    shift: int | None = None,
) -> dict[str, Any]:
    if name not in PROFILES:
        raise ValueError(f"unknown profile {name!r}")
    profile = dict(PROFILES[name])
    selected_targets = targets or list(profile["targets"])
    blocks = int(n_blocks or profile["n_blocks"])
    seeds = int(n_seeds or profile["n_seeds"])
    pairs = int(n_round_pairs or profile["n_round_pairs"])
    quantization_shift = int(shift if shift is not None else profile["shift"])

    results = []
    for target in selected_targets:
        print(f"F8 {target}: N={blocks}, seeds={seeds}, pairs={pairs}", flush=True)
        result = run_target(
            target,
            n_blocks=blocks,
            n_seeds=seeds,
            n_round_pairs=pairs,
            shift=quantization_shift,
        )
        print(
            f"  rate={result.mean_significant_rate:.4f} "
            f"t={result.t_statistic:+.2f} {result.verdict}",
            flush=True,
        )
        results.append(result.to_dict())

    return {
        "schema_version": 1,
        "experiment": "ARX F8 full-round carry-leak reproduction",
        "profile": name,
        "created_utc": datetime.now(timezone.utc).isoformat(),
        "parameters": {
            "targets": selected_targets,
            "n_blocks": blocks,
            "n_seeds": seeds,
            "n_round_pairs": pairs,
            "shift": quantization_shift,
            "seed_schedule": "42 + 1000 * seed_index",
        },
        "environment": {
            "python": sys.version.split()[0],
            "platform": platform.platform(),
            "numpy": np.__version__,
            "scipy": scipy.__version__,
        },
        "scope_note": (
            "F8 compares paired outputs at R and R+1 under the same key and counter inputs. "
            "A detection is a known-key distinguisher, not a key-recovery attack."
        ),
        "results": results,
    }


def write_json(data: dict[str, Any], output: str | Path) -> Path:
    path = Path(output)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return path

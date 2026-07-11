"""Portable adapter for the Nanjing 41-cipher CASI snapshot."""

from __future__ import annotations

from typing import Any

import numpy as np

from .live_casi_v091 import compute_amplified_score, compute_casi_score
from .nano_ciphers import NANO_CIPHER_REGISTRY


def _to_builtin(value: Any) -> Any:
    if isinstance(value, np.generic):
        return value.item()
    if isinstance(value, np.ndarray):
        return value.tolist()
    if isinstance(value, dict):
        return {str(key): _to_builtin(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_to_builtin(item) for item in value]
    return value


def run_casi_target(
    target: str,
    *,
    samples: int = 1000,
    seeds: int = 3,
    rounds: int | None = None,
) -> dict[str, Any]:
    if target not in NANO_CIPHER_REGISTRY:
        available = ", ".join(sorted(NANO_CIPHER_REGISTRY))
        raise ValueError(f"unknown CASI target {target!r}; choose one of: {available}")
    if samples < 100:
        raise ValueError("samples must be at least 100")
    if seeds < 1:
        raise ValueError("seeds must be positive")

    info = NANO_CIPHER_REGISTRY[target]
    round_count = int(info["full"] if rounds is None else rounds)
    if round_count < 1:
        raise ValueError("rounds must be positive")

    per_seed = []
    for seed_index in range(seeds):
        seed = 42 + seed_index * 1000
        raw = info["gen"](samples, round_count, seed=seed)
        keys = np.frombuffer(raw, dtype=np.uint8).reshape(-1, 32)
        standard = compute_casi_score(keys)
        amplified = compute_amplified_score(keys)
        per_seed.append(
            {
                "seed": seed,
                "casi": float(standard["casi"]),
                "casi_deep": float(standard["casi_deep"]),
                "amplified": float(amplified["casi"]),
            }
        )

    casi_values = np.asarray([item["casi"] for item in per_seed])
    deep_values = np.asarray([item["casi_deep"] for item in per_seed])
    amplified_values = np.asarray([item["amplified"] for item in per_seed])
    maximum = float(max(np.mean(casi_values), np.mean(amplified_values)))
    verdict = "DETECTED" if maximum > 2.0 else ("WEAK" if maximum > 1.5 else "CLEAN")

    return _to_builtin(
        {
            "method": "CASI_live-casi_0.9.1",
            "target": target,
            "rounds": round_count,
            "full_rounds": info["full"],
            "samples": samples,
            "seeds": seeds,
            "family": info["family"],
            "standard": info["iso"],
            "casi_mean": np.mean(casi_values),
            "casi_deep_mean": np.mean(deep_values),
            "amplified_mean": np.mean(amplified_values),
            "verdict": verdict,
            "per_seed": per_seed,
        }
    )

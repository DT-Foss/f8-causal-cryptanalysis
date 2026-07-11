#!/usr/bin/env python3
"""BvN-route order controls for real PQC public-output measurements.

The study preserves the complete multiset of public 32-byte rows. It
intervenes only on row order through globally routed bijections, then compares
CASI and F8-O to their route-null distributions. It does not expose internal
round state and makes no security-game claim.
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import platform
import sys
from pathlib import Path
from typing import Any

import numpy as np

from arx_carry_leak.bvn import route_ensemble, verify_routes


def _load_output_suite() -> Any:
    path = Path(__file__).with_name("pqc_output_control_suite.py")
    spec = importlib.util.spec_from_file_location("pqc_output_control_suite_bvn", path)
    if spec is None or spec.loader is None:
        raise RuntimeError("cannot load pqc_output_control_suite")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _summary(values: list[float]) -> dict[str, Any]:
    array = np.asarray(values, dtype=float)
    return {
        "values": [float(value) for value in array],
        "mean": float(np.mean(array)),
        "sample_sd_ddof1": float(np.std(array, ddof=1)) if len(array) > 1 else 0.0,
        "minimum": float(np.min(array)),
        "maximum": float(np.max(array)),
    }


def _aggregate_route_test(actual: list[float], null_by_seed: list[list[float]], seed: int) -> dict[str, Any]:
    rng = np.random.default_rng(seed)
    null = np.asarray(null_by_seed, dtype=float)
    draws = 20_000
    chosen = null[np.arange(null.shape[0])[None, :], rng.integers(null.shape[1], size=(draws, null.shape[0]))]
    means = np.mean(chosen, axis=1)
    actual_mean = float(np.mean(actual))
    return {
        "actual_mean": actual_mean,
        "route_null_mean": float(np.mean(means)),
        "route_null_sd": float(np.std(means, ddof=1)),
        "resamples": draws,
        "empirical_upper_tail_p": float((1 + np.sum(means >= actual_mean)) / (1 + draws)),
        "empirical_lower_tail_p": float((1 + np.sum(means <= actual_mean)) / (1 + draws)),
        "empirical_two_sided_p": float(
            min(
                1.0,
                2
                * min(
                    (1 + np.sum(means >= actual_mean)) / (1 + draws),
                    (1 + np.sum(means <= actual_mean)) / (1 + draws),
                ),
            )
        ),
    }


def _target_run(suite: Any, target: Any, args: argparse.Namespace) -> dict[str, Any]:
    actual_casi: list[float] = []
    actual_f8: list[float] = []
    null_casi_by_seed: list[list[float]] = []
    null_f8_by_seed: list[list[float]] = []
    records = []
    for seed_index in range(args.seeds):
        seed = 42 + 1009 * seed_index
        outputs, verified = suite._operation_collector(target, fixed_key=True, count=args.operations, seed=seed)
        rows = suite._rows(outputs)
        if args.max_rows is not None:
            rows = rows[: args.max_rows]
        if len(rows) < 32:
            raise RuntimeError(f"{target.name}: insufficient rows after output framing")
        actual_casi_value = float(suite._score_casi(rows, 0xB0A000 + seed)["operational_max"])
        actual_f8_value = float(suite._f8_output(rows)["significant_rate"])
        routes = route_ensemble(len(rows), args.routes, 0xB0A000 + seed)
        null_casi = [float(suite._score_casi(rows[route], 0xB0A000 + seed)["operational_max"]) for route in routes]
        null_f8 = [float(suite._f8_output(rows[route])["significant_rate"]) for route in routes]
        actual_casi.append(actual_casi_value)
        actual_f8.append(actual_f8_value)
        null_casi_by_seed.append(null_casi)
        null_f8_by_seed.append(null_f8)
        records.append(
            {
                "seed": seed,
                "functional_gate": bool(verified),
                "rows": int(len(rows)),
                "actual": {"casi_operational": actual_casi_value, "f8_output_rate": actual_f8_value},
                "route_null": {"casi_operational": _summary(null_casi), "f8_output_rate": _summary(null_f8)},
                "route_check": verify_routes(routes),
            }
        )
    return {
        "target": target.name,
        "family": target.family,
        "kind": target.kind,
        "fixed_key_only": True,
        "per_seed": records,
        "casi": {
            "actual": _summary(actual_casi),
            "aggregate_route_randomization_test": _aggregate_route_test(actual_casi, null_casi_by_seed, 0xCA510),
        },
        "f8_output": {
            "actual": _summary(actual_f8),
            "aggregate_route_randomization_test": _aggregate_route_test(actual_f8, null_f8_by_seed, 0xF8000),
        },
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--operations", type=int, default=128)
    parser.add_argument("--seeds", type=int, default=3)
    parser.add_argument("--routes", type=int, default=32)
    parser.add_argument("--max-rows", type=int, default=1200)
    parser.add_argument("--targets", nargs="*", default=["mlkem512", "mldsa44"])
    args = parser.parse_args()
    if args.operations < 32 or args.seeds < 2 or args.routes < 4:
        raise ValueError("operations >= 32, seeds >= 2, and routes >= 4 are required")
    suite = _load_output_suite()
    targets = {target.name: target for target in suite.TARGETS}
    unknown = sorted(set(args.targets) - set(targets))
    if unknown:
        raise ValueError(f"unknown targets: {', '.join(unknown)}")
    results = []
    for name in args.targets:
        print(f"PQC BvN route control: {name}", flush=True)
        results.append(_target_run(suite, targets[name], args))
    payload = {
        "schema_version": 1,
        "experiment": "pqc_bvn_route_control_suite",
        "parameters": {
            "operations": args.operations,
            "seeds": args.seeds,
            "routes": args.routes,
            "max_rows": args.max_rows,
            "targets": args.targets,
        },
        "environment": {"python": sys.version.split()[0], "platform": platform.platform()},
        "results": results,
        "scope_note": (
            "These are public-output order controls. Route nulls preserve every analysed row exactly; they do not "
            "model internal PQC rounds, secret-key leakage, or any IND-CPA/IND-CCA game."
        ),
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n")
    print(f"wrote {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

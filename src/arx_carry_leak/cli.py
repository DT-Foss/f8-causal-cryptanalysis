"""Command-line interface for F8 and CASI reproduction."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from .casi import run_casi_target
from .ciphers import FULL_ROUNDS, verify_reference_vectors
from .experiments import PROFILES, run_profile, write_json
from .nano_ciphers import NANO_CIPHER_REGISTRY


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="arx-f8",
        description="Reproduce F8 carry-leak and CASI experiments.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    list_parser = subparsers.add_parser("list", help="List available targets")
    list_parser.add_argument("--method", choices=("f8", "casi", "all"), default="all")

    subparsers.add_parser("verify-vectors", help="Verify Speck and Threefish reference vectors")

    run_parser = subparsers.add_parser("run", help="Run an F8 profile")
    run_parser.add_argument("--profile", choices=sorted(PROFILES), default="quick")
    run_parser.add_argument("--target", action="append", dest="targets")
    run_parser.add_argument("--blocks", type=int)
    run_parser.add_argument("--seeds", type=int)
    run_parser.add_argument("--round-pairs", type=int)
    run_parser.add_argument("--shift", type=int)
    run_parser.add_argument("--output", type=Path)

    casi_parser = subparsers.add_parser("casi", help="Run vendored live-casi 0.9.1")
    casi_parser.add_argument("--target", required=True, choices=sorted(NANO_CIPHER_REGISTRY))
    casi_parser.add_argument("--samples", type=int, default=1000)
    casi_parser.add_argument("--seeds", type=int, default=3)
    casi_parser.add_argument("--rounds", type=int)
    casi_parser.add_argument("--output", type=Path)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    if args.command == "list":
        if args.method in ("f8", "all"):
            print("F8 targets:")
            for name in sorted(FULL_ROUNDS):
                print(f"  {name:<20} full rounds: {FULL_ROUNDS[name]}")
        if args.method in ("casi", "all"):
            print("CASI targets:")
            for name, info in sorted(NANO_CIPHER_REGISTRY.items()):
                print(f"  {name:<20} {info['family']}, {info['full']} rounds")
        return 0

    if args.command == "verify-vectors":
        results = verify_reference_vectors()
        for name, passed in results.items():
            print(f"{'PASS' if passed else 'FAIL'} {name}")
        return 0 if all(results.values()) else 1

    if args.command == "run":
        data = run_profile(
            args.profile,
            targets=args.targets,
            n_blocks=args.blocks,
            n_seeds=args.seeds,
            n_round_pairs=args.round_pairs,
            shift=args.shift,
        )
        if args.output:
            output = write_json(data, args.output)
            print(f"Wrote {output}")
        else:
            print(json.dumps(data, indent=2, sort_keys=True))
        return 0

    if args.command == "casi":
        data = run_casi_target(
            args.target,
            samples=args.samples,
            seeds=args.seeds,
            rounds=args.rounds,
        )
        if args.output:
            output = write_json(data, args.output)
            print(f"Wrote {output}")
        else:
            print(json.dumps(data, indent=2, sort_keys=True))
        return 0
    return 2

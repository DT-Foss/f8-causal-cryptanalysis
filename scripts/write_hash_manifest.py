#!/usr/bin/env python3
"""Write portable repository-relative SHA-256 manifests."""

from __future__ import annotations

import argparse
import hashlib
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--tree", type=Path)
    parser.add_argument("files", type=Path, nargs="*")
    args = parser.parse_args()

    output = args.output if args.output.is_absolute() else ROOT / args.output
    output = output.resolve()
    if not output.is_relative_to(ROOT):
        parser.error("output must be inside the repository")

    candidates = [path if path.is_absolute() else ROOT / path for path in args.files]
    if args.tree:
        tree = args.tree if args.tree.is_absolute() else ROOT / args.tree
        candidates.extend(sorted(path for path in tree.rglob("*") if path.is_file()))

    files: list[Path] = []
    seen: set[Path] = set()
    for candidate in candidates:
        path = candidate.resolve()
        if path == output:
            continue
        if not path.is_relative_to(ROOT):
            parser.error(f"path escapes repository: {candidate}")
        if not path.is_file():
            parser.error(f"missing input: {candidate}")
        if path not in seen:
            seen.add(path)
            files.append(path)
    if not files:
        parser.error("no input files")

    lines = [
        f"{hashlib.sha256(path.read_bytes()).hexdigest()}  {path.relative_to(ROOT)}"
        for path in files
    ]
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"wrote {output.relative_to(ROOT)} ({len(lines)} files)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

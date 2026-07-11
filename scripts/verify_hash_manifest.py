#!/usr/bin/env python3
"""Verify repository-relative SHA-256 manifests without platform-specific tools."""

from __future__ import annotations

import argparse
import hashlib
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def verify(manifest: Path) -> tuple[int, list[str]]:
    manifest = manifest.resolve()
    if not manifest.is_relative_to(ROOT):
        raise ValueError(f"manifest is outside repository: {manifest}")
    failures: list[str] = []
    seen: set[str] = set()
    checked = 0
    for line_number, raw in enumerate(manifest.read_text(encoding="utf-8").splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        try:
            expected, relative = line.split(maxsplit=1)
        except ValueError:
            failures.append(f"{manifest.name}:{line_number}: malformed line")
            continue
        relative = relative.strip()
        candidate = (ROOT / relative).resolve()
        if len(expected) != 64 or any(char not in "0123456789abcdef" for char in expected):
            failures.append(f"{manifest.name}:{line_number}: invalid SHA-256")
            continue
        if relative in seen:
            failures.append(f"{manifest.name}:{line_number}: duplicate path {relative}")
            continue
        seen.add(relative)
        if not candidate.is_relative_to(ROOT):
            failures.append(f"{manifest.name}:{line_number}: path escapes repository")
            continue
        if not candidate.is_file():
            failures.append(f"{manifest.name}:{line_number}: missing {relative}")
            continue
        observed = hashlib.sha256(candidate.read_bytes()).hexdigest()
        if observed != expected:
            failures.append(
                f"{manifest.name}:{line_number}: {relative}: expected {expected}, got {observed}"
            )
            continue
        checked += 1
    return checked, failures


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("manifest", type=Path, nargs="+")
    args = parser.parse_args()
    failures: list[str] = []
    for item in args.manifest:
        manifest = item if item.is_absolute() else ROOT / item
        checked, current = verify(manifest)
        failures.extend(current)
        status = "OK" if not current else "FAIL"
        print(f"{manifest.relative_to(ROOT)}: {status} ({checked} files)")
    if failures:
        for failure in failures:
            print(f"ERROR: {failure}")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

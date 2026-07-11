#!/usr/bin/env python3
"""Regenerate checksums for committed evidence and vendored source snapshots."""

from __future__ import annotations

import hashlib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUTPUT = ROOT / "provenance" / "SHA256SUMS"
INCLUDED = (
    ROOT / "data" / "reference",
    ROOT / "docs" / "original",
    ROOT / "paper",
    ROOT / "provenance" / "original_f8_scripts",
    ROOT / "provenance" / "original_nano_scripts",
    ROOT / "provenance" / "dependencies" / "pqcrypto-upstream",
    ROOT / "src" / "arx_carry_leak",
)
INCLUDED_FILES = (
    ROOT / "provenance" / "dependencies" / "live_casiv2_legacy.LICENSE",
)
ALLOWED_SUFFIXES = {".c", ".cls", ".csv", ".json", ".pdf", ".pptx", ".py", ".tex"}
ALLOWED_NAMES = {"LICENSE", "NOTICE"}
GENERATED_NAMES = {"main.pdf"}


def main() -> None:
    selected: set[Path] = set(INCLUDED_FILES)
    for base in INCLUDED:
        selected.update(
            item
            for item in base.rglob("*")
            if item.is_file()
            and (item.suffix in ALLOWED_SUFFIXES or item.name in ALLOWED_NAMES)
            and item.name not in GENERATED_NAMES
            and "__pycache__" not in item.parts
        )
    lines = []
    for path in sorted(selected):
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        lines.append(f"{digest}  {path.relative_to(ROOT)}")
    OUTPUT.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"Wrote {OUTPUT.relative_to(ROOT)} ({len(lines)} files)")


if __name__ == "__main__":
    main()

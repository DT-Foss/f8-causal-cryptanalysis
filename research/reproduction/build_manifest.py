#!/usr/bin/env python3
"""Build the immutable inventory used by the historical reproduction runner."""

from __future__ import annotations

import csv
import hashlib
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
CLAIMS = ROOT / "research/claims/claim_evidence.csv"
OUTPUT = ROOT / "research/reproduction/manifest.json"


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def claim_index() -> dict[str, list[str]]:
    indexed: dict[str, list[str]] = {}
    with CLAIMS.open(newline="") as handle:
        for row in csv.DictReader(handle):
            for field in ("script_evidence", "result_evidence"):
                for value in row[field].split(";"):
                    value = value.strip()
                    if not value or value in {"none", "docs/original/"}:
                        continue
                    indexed.setdefault(value, []).append(row["claim_id"])
    return {key: sorted(set(value)) for key, value in indexed.items()}


def add_file(entries: list[dict], indexed: dict[str, list[str]], path: Path, kind: str,
             runnable: bool = False, reason: str | None = None) -> None:
    relative = path.relative_to(ROOT).as_posix()
    entry = {
            "id": relative.replace("/", "__").replace(".py", "").replace(".", "_"),
            "path": relative,
            "kind": kind,
            "sha256": sha256(path),
            "claims": indexed.get(relative, []),
            "runnable_historical": runnable,
            "command": ["{python}", relative] if runnable else None,
            "non_runnable_reason": reason if not runnable else None,
            "expected_returncode": 0 if runnable else None,
            "expected_stderr_contains": None,
        }
    if relative.endswith("original_f8_scripts/graph_attack.py"):
        entry["expected_returncode"] = 1
        entry["expected_stderr_contains"] = "IndexError: index 11 is out of bounds"
    entries.append(entry)


def main() -> int:
    indexed = claim_index()
    entries: list[dict] = []

    for path in sorted((ROOT / "provenance/original_f8_scripts").glob("*.py")):
        experiment = path.name not in {"__init__.py", "speck_utils.py"}
        add_file(
            entries,
            indexed,
            path,
            "legacy_f8_experiment" if experiment else "legacy_f8_support",
            runnable=experiment,
            reason=None if experiment else "support module, not a standalone experiment",
        )

    for path in sorted((ROOT / "provenance/original_nano_scripts").glob("*.py")):
        add_file(
            entries,
            indexed,
            path,
            "legacy_nano_script",
            runnable=False,
            reason="archived script contains machine-specific absolute Desktop paths",
        )

    dependency_bundle = ROOT / "provenance/dependencies/live_casiv2_legacy.zip"
    if dependency_bundle.exists():
        add_file(
            entries,
            indexed,
            dependency_bundle,
            "legacy_python_dependency_bundle",
            runnable=False,
            reason="importable frozen dependency bundle used by graph and temporal scripts",
        )

    pqclean_sha2 = (
        ROOT
        / "provenance/dependencies/pqcrypto-upstream/pqclean/common/sha2.c"
    )
    if pqclean_sha2.exists():
        add_file(
            entries,
            indexed,
            pqclean_sha2,
            "pinned_reference_source",
            runnable=False,
            reason="constant source parsed by the SHA-2 full-compression experiment",
        )

    retained = [
        ROOT / "data/reference/aging_simulation.json",
        ROOT / "data/reference/full_coverage_matrix.csv",
        ROOT / "data/reference/nano_iot_f8_summary.json",
        ROOT / "data/reference/nano_iot_frontier_summary.json",
        ROOT / "data/reference/nano_iot_master_results.json",
        ROOT / "data/reference/paper_table_1.csv",
        ROOT / "data/reference/reduced_round_detection.json",
        ROOT / "data/reference/sample_sensitivity.json",
    ]
    retained.extend(sorted((ROOT / "data/reference/nano_iot_raw").rglob("*.json")))
    for path in retained:
        add_file(
            entries,
            indexed,
            path,
            "retained_historical_result",
            runnable=False,
            reason="retained result artifact",
        )

    payload = {
        "schema_version": 1,
        "scope": "historical paper reproduction inventory",
        "policy": {
            "legacy_sources_are_read_only": True,
            "stdout_and_stderr_are_retained": True,
            "historical_and_corrected_runs_are_separate": True,
        },
        "counts": {
            "entries": len(entries),
            "runnable_historical_experiments": sum(
                bool(entry["runnable_historical"]) for entry in entries
            ),
            "retained_result_artifacts": sum(
                entry["kind"] == "retained_historical_result" for entry in entries
            ),
        },
        "entries": entries,
    }
    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n")
    print(f"wrote {OUTPUT.relative_to(ROOT)} with {len(entries)} entries")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

#!/usr/bin/env python3
"""Create a deterministic index of retained historical replay records."""

from __future__ import annotations

import argparse
import hashlib
import json
from collections import Counter
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
DEFAULT_RESULTS = ROOT / "research/results/reproduction_v1"
MANIFEST = ROOT / "research/reproduction/manifest.json"


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--results", type=Path, default=DEFAULT_RESULTS)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    output = args.output or args.results / "index.json"
    manifest = json.loads(MANIFEST.read_text())
    entries = {entry["id"]: entry for entry in manifest["entries"]}

    runs = []
    for record_path in sorted(args.results.glob("*/run.json")):
        record = json.loads(record_path.read_text())
        run_dir = record_path.parent
        entry = entries[record["experiment_id"]]
        stderr = (run_dir / "stderr.txt").read_text()
        expected_code = entry.get("expected_returncode", 0)
        expected_error = entry.get("expected_stderr_contains")
        expected = record.get("returncode") == expected_code and (
            not expected_error or expected_error in stderr
        )
        effective_status = (
            "reproduced_expected_failure" if expected and expected_code
            else "reproduced" if expected
            else "unexpected_outcome"
        )
        runs.append(
            {
                "experiment_id": record["experiment_id"],
                "status": record["status"],
                "reproduction_status": effective_status,
                "returncode": record["returncode"],
                "duration_seconds": record["duration_seconds"],
                "claims": record["claims"],
                "source_path": record["source_path"],
                "source_sha256": record["source_sha256_observed"],
                "source_hash_matches_manifest": record["source_hash_matches_manifest"],
                "stdout_path": str((run_dir / "stdout.txt").relative_to(ROOT)),
                "stdout_sha256": sha256(run_dir / "stdout.txt"),
                "stderr_path": str((run_dir / "stderr.txt").relative_to(ROOT)),
                "stderr_sha256": sha256(run_dir / "stderr.txt"),
                "run_record_path": str(record_path.relative_to(ROOT)),
                "run_record_sha256": sha256(record_path),
            }
        )

    statuses = Counter(run["reproduction_status"] for run in runs)
    claim_runs: dict[str, list[dict]] = {}
    for run in runs:
        for claim_id in run["claims"]:
            claim_runs.setdefault(claim_id, []).append(
                {
                    "experiment_id": run["experiment_id"],
                    "reproduction_status": run["reproduction_status"],
                    "stdout_path": run["stdout_path"],
                    "run_record_path": run["run_record_path"],
                }
            )
    payload = {
        "schema_version": 1,
        "publication_path_sanitized": True,
        "publication_sanitization": (
            "Run records use repository and dependency role paths; numeric output and "
            "source hashes remain unchanged."
        ),
        "results_root": str(args.results.relative_to(ROOT)),
        "counts": {"records": len(runs), "by_status": dict(sorted(statuses.items()))},
        "all_source_hashes_match": all(run["source_hash_matches_manifest"] for run in runs),
        "claim_reproduction_index": dict(sorted(claim_runs.items())),
        "runs": runs,
    }
    output.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n")
    print(json.dumps(payload["counts"], sort_keys=True))
    print(f"wrote {output.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

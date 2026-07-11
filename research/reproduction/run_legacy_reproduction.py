#!/usr/bin/env python3
"""Execute archived F8 experiments without modifying their source code."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
MANIFEST = ROOT / "research/reproduction/manifest.json"
RESULT_ROOT = ROOT / "research/results/reproduction_v1"
LEGACY_DEPENDENCY_ROOT = ROOT.parent / "live-casiv2"
LEGACY_DEPENDENCY_BUNDLE = ROOT / "provenance/dependencies/live_casiv2_legacy.zip"


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def publication_path(path: Path) -> str:
    """Return a stable role path without publishing a host home directory."""
    resolved = path.resolve()
    if resolved.is_relative_to(ROOT):
        return str(resolved.relative_to(ROOT))
    if resolved.is_relative_to(LEGACY_DEPENDENCY_ROOT.resolve()):
        suffix = resolved.relative_to(LEGACY_DEPENDENCY_ROOT.resolve())
        return f"<legacy-live-casi>/{suffix}"
    return f"<external>/{resolved.name}"


def sanitize_capture(value: str, python_executable: str) -> str:
    substitutions = (
        (str(ROOT), "<repository>"),
        (str(LEGACY_DEPENDENCY_ROOT), "<legacy-live-casi>"),
        (str(Path(python_executable).expanduser().resolve()), "<python>"),
    )
    for source, replacement in substitutions:
        value = value.replace(source, replacement)
    return value


def load_entries() -> dict[str, dict]:
    payload = json.loads(MANIFEST.read_text())
    return {
        entry["id"]: entry
        for entry in payload["entries"]
        if entry["runnable_historical"]
    }


def reproduction_status(entry: dict, record: dict, stderr: str) -> str:
    expected_code = entry.get("expected_returncode", 0)
    expected_error = entry.get("expected_stderr_contains")
    if record.get("returncode") != expected_code:
        return "unexpected_outcome"
    if expected_error and expected_error not in stderr:
        return "unexpected_outcome"
    return "reproduced_expected_failure" if expected_code else "reproduced"


def run(entry: dict, timeout: int, force: bool, python_executable: str) -> dict:
    result_dir = RESULT_ROOT / entry["id"]
    status_path = result_dir / "run.json"
    if status_path.exists() and not force:
        previous = json.loads(status_path.read_text())
        previous_stderr = (result_dir / "stderr.txt").read_text()
        effective = reproduction_status(entry, previous, previous_stderr)
        if effective != "unexpected_outcome":
            print(f"SKIP {entry['id']}: {effective} result exists")
            return {**previous, "reproduction_status": effective}

    result_dir.mkdir(parents=True, exist_ok=True)
    command = [python_executable if token == "{python}" else token for token in entry["command"]]
    env = os.environ.copy()
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    dependency_hashes = {}
    if LEGACY_DEPENDENCY_BUNDLE.exists():
        env["PYTHONPATH"] = os.pathsep.join(
            [str(LEGACY_DEPENDENCY_BUNDLE), env.get("PYTHONPATH", "")]
        ).rstrip(os.pathsep)
        dependency_hashes[publication_path(LEGACY_DEPENDENCY_BUNDLE)] = sha256(
            LEGACY_DEPENDENCY_BUNDLE
        )
    elif LEGACY_DEPENDENCY_ROOT.exists():
        env["PYTHONPATH"] = os.pathsep.join(
            [str(LEGACY_DEPENDENCY_ROOT), env.get("PYTHONPATH", "")]
        ).rstrip(os.pathsep)
        for dependency in sorted((LEGACY_DEPENDENCY_ROOT / "live_casiv2").glob("*.py")):
            dependency_hashes[publication_path(dependency)] = sha256(dependency)
    started = datetime.now(timezone.utc)
    start_clock = time.monotonic()
    print(f"RUN  {entry['id']}: {' '.join(command)}", flush=True)
    try:
        completed = subprocess.run(
            command,
            cwd=ROOT,
            env=env,
            text=True,
            capture_output=True,
            timeout=timeout,
            check=False,
        )
        status = "completed" if completed.returncode == 0 else "failed"
        returncode = completed.returncode
        stdout = completed.stdout
        stderr = completed.stderr
    except subprocess.TimeoutExpired as error:
        status = "timeout"
        returncode = None
        stdout = error.stdout or ""
        stderr = error.stderr or ""
        if isinstance(stdout, bytes):
            stdout = stdout.decode(errors="replace")
        if isinstance(stderr, bytes):
            stderr = stderr.decode(errors="replace")

    stdout = sanitize_capture(stdout, python_executable)
    stderr = sanitize_capture(stderr, python_executable)
    duration = time.monotonic() - start_clock
    (result_dir / "stdout.txt").write_text(stdout)
    (result_dir / "stderr.txt").write_text(stderr)
    record = {
        "schema_version": 1,
        "experiment_id": entry["id"],
        "claims": entry["claims"],
        "source_path": entry["path"],
        "source_sha256_expected": entry["sha256"],
        "source_sha256_observed": sha256(ROOT / entry["path"]),
        "source_hash_matches_manifest": sha256(ROOT / entry["path"]) == entry["sha256"],
        "command": ["<python>", *command[1:]],
        "cwd": "<repository>",
        "status": status,
        "returncode": returncode,
        "timeout_seconds": timeout,
        "started_utc": started.isoformat(),
        "duration_seconds": duration,
        "environment": {
            "python": sys.version,
            "executable": f"<python>/{Path(sys.executable).name}",
            "platform": platform.platform(),
            "machine": platform.machine(),
            "pythonpath": (
                publication_path(LEGACY_DEPENDENCY_BUNDLE)
                if LEGACY_DEPENDENCY_BUNDLE.exists()
                else "<legacy-live-casi>"
                if LEGACY_DEPENDENCY_ROOT.exists()
                else ""
            ),
        },
        "external_dependency_hashes": dependency_hashes,
        "stdout_sha256": sha256(result_dir / "stdout.txt"),
        "stderr_sha256": sha256(result_dir / "stderr.txt"),
        "publication_path_sanitized": True,
    }
    record["reproduction_status"] = reproduction_status(entry, record, stderr)
    status_path.write_text(json.dumps(record, indent=2, sort_keys=True) + "\n")
    print(f"{status.upper():7} {entry['id']} ({duration:.2f} s)")
    return record


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("ids", nargs="*", help="manifest experiment IDs")
    parser.add_argument("--all", action="store_true", help="run every runnable legacy experiment")
    parser.add_argument("--list", action="store_true", help="list runnable experiment IDs")
    parser.add_argument("--timeout", type=int, default=3600, help="per-experiment timeout")
    parser.add_argument("--force", action="store_true", help="replace a completed run")
    parser.add_argument(
        "--python",
        default=sys.executable,
        help="Python executable; useful for a pinned historical dependency environment",
    )
    args = parser.parse_args()

    entries = load_entries()
    if args.list:
        for experiment_id, entry in entries.items():
            print(f"{experiment_id}\t{','.join(entry['claims']) or '-'}")
        return 0
    selected = list(entries) if args.all else args.ids
    if not selected:
        parser.error("provide IDs or --all")
    unknown = sorted(set(selected) - set(entries))
    if unknown:
        parser.error(f"unknown/non-runnable IDs: {', '.join(unknown)}")

    outcomes = [
        run(entries[experiment_id], args.timeout, args.force, args.python)
        for experiment_id in selected
    ]
    return 0 if all(
        item.get("reproduction_status") in {"reproduced", "reproduced_expected_failure"}
        for item in outcomes
    ) else 1


if __name__ == "__main__":
    raise SystemExit(main())

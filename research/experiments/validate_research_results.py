#!/usr/bin/env python3
"""Fail-closed structural and numeric validation for follow-up result JSON files."""

from __future__ import annotations

import argparse
import json
import math
from pathlib import Path
from typing import Any


EXPECTED = {
    "reference_vectors.json": "primary_reference_vector_audit",
    "f8_fair_null.json": "f8_fair_null_suite",
    "casi_calibration.json": "casi_calibration_suite",
    "casi_input_model.json": "casi_input_model_suite",
}


def validate_finite(value: Any, path: str, failures: list[str]) -> None:
    if isinstance(value, dict):
        for key, child in value.items():
            validate_finite(child, f"{path}.{key}", failures)
    elif isinstance(value, list):
        for index, child in enumerate(value):
            validate_finite(child, f"{path}[{index}]", failures)
    elif isinstance(value, float) and not math.isfinite(value):
        failures.append(f"{path}: non-finite number {value}")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--results", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()

    checks = []
    failures: list[str] = []
    finding_ids: list[str] = []
    for filename, experiment in EXPECTED.items():
        path = args.results / filename
        check = {"file": filename, "exists": path.exists(), "valid": False}
        checks.append(check)
        if not path.exists():
            failures.append(f"{filename}: missing")
            continue
        try:
            payload = json.loads(path.read_text())
        except (OSError, json.JSONDecodeError) as error:
            failures.append(f"{filename}: invalid JSON: {error}")
            continue
        if payload.get("schema_version") != 1:
            failures.append(f"{filename}: schema_version is not 1")
        if payload.get("experiment") != experiment:
            failures.append(
                f"{filename}: experiment {payload.get('experiment')!r} != {experiment!r}"
            )
        validate_finite(payload, filename, failures)
        for finding in payload.get("candidate_findings", []):
            identifier = finding.get("id")
            if not identifier:
                failures.append(f"{filename}: candidate finding without id")
            else:
                finding_ids.append(identifier)
        if filename == "reference_vectors.json" and not payload.get("all_passed"):
            failures.append("reference_vectors.json: at least one KAT failed")
        check["valid"] = not any(item.startswith(f"{filename}:") for item in failures)

    duplicates = sorted({identifier for identifier in finding_ids if finding_ids.count(identifier) > 1})
    if duplicates:
        failures.append(f"duplicate candidate finding ids: {', '.join(duplicates)}")

    report = {
        "schema_version": 1,
        "experiment": "research_result_validation",
        "valid": not failures,
        "checks": checks,
        "candidate_finding_ids": sorted(finding_ids),
        "failures": failures,
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    print(f"result validation: {'PASS' if report['valid'] else 'FAIL'}")
    for failure in failures:
        print(f"- {failure}")
    return 0 if report["valid"] else 1


if __name__ == "__main__":
    raise SystemExit(main())

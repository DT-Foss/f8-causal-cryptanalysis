#!/usr/bin/env python3
"""Verify the public A326--A456 frontier and its publication boundary.

The default mode authenticates the manifest, the retained headline invariants,
and the absence of unpublished live-recovery outputs. ``--write`` is the
maintainer-only mode for regenerating the manifest after an intentional release.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "research/results/v1/A326_A456_FRONTIER_SHA256SUMS"
ATTEMPT_RE = re.compile(r"(?:^|[_-])[aA](\d{3})(?=[_.-]|$)")
SEARCH_ROOTS = (
    "research/configs",
    "research/experiments",
    "research/native",
    "research/reports",
    "research/results/v1",
    "scripts",
)
EXPLICIT_PATHS = (
    ".gitattributes",
    ".github/workflows/ci.yml",
    "README.md",
    "docs/RELEASE_A326_A456_FRONTIER.md",
    "docs/REPRODUCIBILITY.md",
    "research/ATTEMPT_LOG.md",
    "research/ATTEMPT_LOG_A432_A456.md",
    "research/experiments/chacha20_fresh_clause_antecedents.py",
    "research/experiments/chacha20_fresh_clause_identity.py",
    "research/experiments/chacha20_fresh_multihorizon.py",
    "research/native/cadical_fresh_clause_antecedents.cpp",
    "research/native/cadical_tracer_v3.hpp",
    "src/arx_carry_leak/proof_antecedent_features.py",
    "scripts/verify_a326_a456_frontier.py",
    "scripts/reproduce_quick.sh",
    "tests/test_a326_a456_frontier_release.py",
)

# These recovery executors were frozen or queued at publication time. Their
# protocols and source are public; their result/progress payloads are not.
LIVE_RECOVERY_ATTEMPTS = {
    397,
    399,
    403,
    405,
    407,
    409,
    411,
    420,
    421,
    423,
    424,
    425,
    426,
    429,
    431,
    435,
    438,
    440,
    443,
    450,
    452,
    455,
}


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(8 * 1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def attempt_ids(path: Path) -> set[int]:
    return {int(value) for value in ATTEMPT_RE.findall(path.name)}


def frontier_paths() -> list[Path]:
    selected: set[Path] = set()
    for root_name in SEARCH_ROOTS:
        root = ROOT / root_name
        for path in root.rglob("*"):
            if not path.is_file() or path == MANIFEST:
                continue
            if path.suffix in {".pyc", ".o"} or "__pycache__" in path.parts:
                continue
            if any(326 <= value <= 456 for value in attempt_ids(path)):
                selected.add(path)
    for relative in EXPLICIT_PATHS:
        path = ROOT / relative
        if not path.is_file():
            raise AssertionError(f"missing release path: {relative}")
        selected.add(path)
    return sorted(selected, key=lambda path: path.relative_to(ROOT).as_posix())


def parse_manifest() -> dict[str, str]:
    entries: dict[str, str] = {}
    for line_number, raw in enumerate(MANIFEST.read_text().splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        fields = line.split(maxsplit=1)
        if len(fields) != 2 or not re.fullmatch(r"[0-9a-f]{64}", fields[0]):
            raise AssertionError(f"invalid manifest line {line_number}")
        relative = fields[1].lstrip("*")
        if relative in entries:
            raise AssertionError(f"duplicate manifest path: {relative}")
        entries[relative] = fields[0]
    return entries


def write_manifest() -> None:
    lines = [
        "# A326--A456 public-frontier SHA-256 manifest",
        "# A455 is protocol-only; A456 contains frozen design/implementation only.",
    ]
    for path in frontier_paths():
        relative = path.relative_to(ROOT).as_posix()
        lines.append(f"{sha256(path)}  {relative}")
    MANIFEST.write_text("\n".join(lines) + "\n")


def load_json(relative: str) -> dict:
    with (ROOT / relative).open() as handle:
        return json.load(handle)


def check_equal(actual: object, expected: object, label: str) -> None:
    if actual != expected:
        raise AssertionError(f"{label}: expected {expected!r}, got {actual!r}")


def check_close(actual: float, expected: float, label: str) -> None:
    if not math.isclose(actual, expected, rel_tol=0.0, abs_tol=1e-15):
        raise AssertionError(f"{label}: expected {expected!r}, got {actual!r}")


def check_publication_boundary() -> None:
    results = ROOT / "research/results/v1"
    for path in results.rglob("*"):
        if not path.is_file() or path == MANIFEST:
            continue
        ids = attempt_ids(path)
        forbidden = sorted(ids & LIVE_RECOVERY_ATTEMPTS)
        if forbidden:
            raise AssertionError(
                f"unpublished recovery result/progress present for A{forbidden[0]}: "
                f"{path.relative_to(ROOT)}"
            )
        if 456 in ids:
            raise AssertionError(f"A456 result payload is outside this release: {path.relative_to(ROOT)}")

    allowed_a456 = {
        "research/configs/chacha20_round20_w52_no_refit_frequency_ray_portfolio_a456_design_v1.json",
        "research/configs/chacha20_round20_w52_no_refit_frequency_ray_portfolio_a456_implementation_v1.json",
        "research/experiments/chacha20_round20_w52_no_refit_frequency_ray_portfolio_a456.py",
        "research/native/a456_frequency_ray_compiler.cpp",
        "scripts/reproduce_chacha20_round20_w52_no_refit_frequency_ray_portfolio_a456.sh",
    }
    actual_a456 = {
        path.relative_to(ROOT).as_posix()
        for path in frontier_paths()
        if 456 in attempt_ids(path)
        and path.relative_to(ROOT).as_posix().startswith(
            ("research/configs/", "research/experiments/", "research/native/", "scripts/reproduce_")
        )
    }
    check_equal(actual_a456, allowed_a456, "A456 frozen publication set")


def check_manifest() -> None:
    if not MANIFEST.is_file():
        raise AssertionError(f"missing manifest: {MANIFEST.relative_to(ROOT)}")
    manifest = parse_manifest()
    expected_paths = {path.relative_to(ROOT).as_posix() for path in frontier_paths()}
    check_equal(set(manifest), expected_paths, "manifest path set")
    for relative, expected in manifest.items():
        check_equal(sha256(ROOT / relative), expected, f"SHA-256 {relative}")


def check_headline_invariants() -> None:
    a447_path = "research/results/v1/chacha20_round20_w46_proof_antecedent_calibration_a447_v1.json"
    a448_path = "research/results/v1/chacha20_round20_w46_full128_proof_antecedent_transfer_a448_v1.json"
    a449_path = "research/results/v1/chacha20_round20_w52_target_blind_proof_antecedent_trace_a449_v1.json"
    a451_path = "research/results/v1/chacha20_round20_w52_deduplicated_reader_portfolio_a451_v1.json"
    a453_path = "research/results/v1/chacha20_round20_w52_deadline_compiled_proof_portfolio_a453_v1.json"
    a454_path = "research/results/v1/chacha20_round20_w52_no_refit_weighted_reader_portfolio_a454_v1.json"

    expected_file_hashes = {
        a447_path: "09836abe6618d42d544a327f009d7840e00bb9bfbf2e99eea296a7ed70cc6051",
        a448_path: "4f3bfbc7be7932917a40a3ad9ff3db76c1bf1ca8799d7a887025f3e98e5464db",
        a449_path: "f054125c5c363e379ddca661334a57867a0d367a5c57d0caa2bb0f8814b322a7",
        a451_path: "f2501e5e85f6d37305473738bb0840c12651720e6f7e3fbab2fc4a253b40bdf6",
        a453_path: "b876db904a4abbfe938de060307f95cb1936c64546367e947302c8cabcfd36aa",
        a454_path: "afa2faa05c83e97b9cd8aeee03063ce4493d9c3ea5388fdb9dc39bf3f2093856",
        "research/results/v1/chacha20_round20_w52_no_refit_weighted_reader_portfolio_a454_v1.causal": "3c14b8a31484bd6bda279d5010056ee7700af89dd81707244f7fafcdf255063f",
        "research/reports/CAUSAL_CHACHA20_A454_PERSONAL_READER_READBACK_V1.md": "bb7c6c9d1c1d630f6a12d4a21f0cedbb38fdc81d19012190dba70c081794676f",
    }
    for relative, expected in expected_file_hashes.items():
        check_equal(sha256(ROOT / relative), expected, f"retained anchor {relative}")

    a447 = load_json(a447_path)
    check_equal(a447["measurement_summary"], {
        "cells": 8192,
        "missing_antecedents": 0,
        "proof_antecedent_edges": 2878295495,
        "proof_nodes": 936982340,
        "solver_stages": 32768,
        "targets": 32,
    }, "A447 exact measurement summary")
    check_equal(a447["selected_operator"], "hybrid_proof_top4_equal", "A447 selected operator")
    check_close(a447["selected_evaluation"]["balanced_eight_block_bit_gain"], 0.4254144564194272, "A447 balanced gain")
    check_close(min(a447["selected_evaluation"]["fixed_block_bit_gains"]), 0.03952880433723127, "A447 minimum held-block gain")

    a448 = load_json(a448_path)
    check_equal(a448["measurement_summary"], {
        "cells": 32768,
        "missing_antecedents": 0,
        "new_A448_targets": 96,
        "proof_antecedent_edges": 11566123517,
        "proof_nodes": 3750214724,
        "reused_A447_targets": 32,
        "solver_stages": 131072,
        "targets": 128,
    }, "A448 exact measurement summary")
    check_equal(a448["complete128_crossfit_selected_operator"], "hybrid_proof_top16_equal", "A448 selected operator")
    check_equal(a448["primary_no_refit_evaluation"]["positive_fixed_block_count"], 8, "A448 positive no-refit blocks")
    check_equal(a448["W52_target_labels_used"], 0, "A448 W52 labels")
    check_equal(a448["W52_model_refits"], 0, "A448 W52 model refits")

    a449 = load_json(a449_path)
    check_equal(a449["measurement_summary"], {
        "axis_cells": 4096,
        "cells": 8192,
        "missing_antecedents": 0,
        "proof_antecedent_edges": 2822633540,
        "proof_nodes": 934617685,
        "slices": 32,
        "solver_stages": 32768,
    }, "A449 exact measurement summary")
    check_equal(a449["primary_operator"], "hybrid_proof_top16_equal", "A449 primary operator")
    check_equal(a449["recovery_operator"], "proof_borda_top32", "A449 recovery operator")
    check_equal(a449["W52_target_labels_used"], 0, "A449 W52 labels")
    check_equal(a449["W52_model_refits"], 0, "A449 W52 model refits")
    check_equal(a449["production_candidate_assignments_executed"], 0, "A449 candidate assignments")

    pair_anchors = {
        a451_path: ("artifact", "826d10e8cfb8ba2cb51e2d1cee35d29f29b9a313928dbdabbf6b92ad2a546cf9"),
        a453_path: ("stream", "73c64ef70ab11498a1dfe8be19bbeb1f8e5d151c16e7fc4abcbfc3e65197df79"),
        a454_path: ("stream", "a82fbe129f6eccaf2ddd560064df1efb471668a116cd52a97490bc66b720b749"),
    }
    for relative, (container, expected_hash) in pair_anchors.items():
        payload = load_json(relative)
        artifact = payload[container] if container == "artifact" else payload[container]["artifact"]
        check_equal(artifact["bytes"], 67108864, f"{payload['attempt_id']} pair bytes")
        check_equal(artifact["pair_cells"], 16777216, f"{payload['attempt_id']} pair cells")
        check_equal(artifact["complete_permutation"], True, f"{payload['attempt_id']} permutation")
        check_equal(artifact["sha256"], expected_hash, f"{payload['attempt_id']} pair declaration")
        pair_path = ROOT / artifact["path"]
        check_equal(pair_path.stat().st_size, 67108864, f"{payload['attempt_id']} pair file size")
        check_equal(sha256(pair_path), expected_hash, f"{payload['attempt_id']} pair file hash")

    a451 = load_json(a451_path)
    check_equal(a451["hard_rank_guarantee"]["violations"], 0, "A451 rank violations")
    check_equal(a451["hard_rank_guarantee"]["guarantee_satisfied"], True, "A451 rank guarantee")
    check_equal(a451["production_candidate_assignments_executed"], 0, "A451 assignments")

    a453 = load_json(a453_path)
    check_equal(a453["hard_rank_guarantee"]["violations"], 0, "A453 rank violations")
    check_equal(a453["hard_rank_guarantee"]["guarantee_satisfied"], True, "A453 rank guarantee")
    check_equal(a453["W52_candidate_assignments_executed"], 0, "A453 assignments")

    a454 = load_json(a454_path)
    check_equal(a454["calibration"]["candidate_count"], 248, "A454 periodic schedules")
    check_equal(a454["calibration"]["selected_pattern"], "BOOHH", "A454 selected pattern")
    stats = a454["calibration"]["selected_remaining96_full_statistics"]
    check_close(stats["aggregate_bit_gain"], 0.47170094050966593, "A454 aggregate gain")
    check_close(stats["minimum_fixed_block_bit_gain"], 0.1607590806312036, "A454 minimum block gain")
    check_equal(stats["positive_fixed_block_count"], 8, "A454 positive blocks")
    check_equal(stats["targets_at_or_above_median_rank"], 60, "A454 median-or-better targets")
    delta = a454["calibration"]["selected_delta_over_A451_BHO"]
    check_close(delta["remaining96_aggregate_bit_gain"], 0.007106867744083978, "A454 aggregate delta")
    check_close(delta["remaining96_minimum_fixed_block_bit_gain"], 0.02710248522403713, "A454 minimum delta")
    check_equal(a454["hard_rank_guarantee"]["all_bounds_satisfied"], True, "A454 exact proposal bounds")
    check_equal(a454["W52_target_labels_used"], 0, "A454 labels")
    check_equal(a454["feature_refits"], 0, "A454 feature refits")
    check_equal(a454["model_refits"], 0, "A454 model refits")
    check_equal(a454["W52_candidate_assignments_executed"], 0, "A454 assignments")

    a455 = load_json("research/configs/chacha20_round20_w52_no_refit_weighted_reader_portfolio_recovery_a455_v1.json")
    check_equal(a455["production_execution_enabled"], False, "A455 frozen execution gate")
    check_equal(a455["candidate_assignments_executed"], 0, "A455 assignments at freeze")
    check_equal(a455["schedule"]["selected_pattern"], "BOOHH", "A455 bound schedule")
    check_equal(a455["schedule"]["pair_stream_sha256"], "a82fbe129f6eccaf2ddd560064df1efb471668a116cd52a97490bc66b720b749", "A455 bound pair stream")
    check_equal(a455["schedule"]["pair_cells"], 16777216, "A455 pair cells")

    a456 = load_json("research/configs/chacha20_round20_w52_no_refit_frequency_ray_portfolio_a456_implementation_v1.json")
    check_equal(a456["candidate_count"], 878, "A456 candidate count")
    check_equal(a456["orbit_count"], 86, "A456 orbit count")
    check_equal(a456["W52_target_labels_used"], 0, "A456 labels")
    check_equal(a456["feature_refits"], 0, "A456 feature refits")
    check_equal(a456["model_refits"], 0, "A456 model refits")
    check_equal(a456["candidate_assignments_executed"], 0, "A456 assignments at freeze")
    check_equal(a456["prior_secret_recovery_progress_or_result_read"], False, "A456 secret-progress boundary")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--write", action="store_true", help="regenerate the release manifest")
    args = parser.parse_args()
    try:
        check_publication_boundary()
        check_headline_invariants()
        if args.write:
            write_manifest()
        check_manifest()
    except (AssertionError, OSError, ValueError, KeyError, json.JSONDecodeError) as exc:
        print(f"A326--A456 frontier verification FAILED: {exc}", file=sys.stderr)
        return 1
    print(f"A326--A456 frontier verification: OK ({len(parse_manifest())} files)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

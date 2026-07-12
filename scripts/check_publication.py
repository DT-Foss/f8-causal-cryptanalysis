#!/usr/bin/env python3
"""Fail-closed audit for public repository metadata, links, paths, and secrets."""

from __future__ import annotations

import hashlib
import json
import re
import zipfile
from pathlib import Path
from urllib.parse import unquote

ROOT = Path(__file__).resolve().parents[1]
SKIP_PARTS = {".git", ".venv", "__pycache__", ".pytest_cache", ".ruff_cache"}
TEXT_SUFFIXES = {
    "",
    ".cff",
    ".cls",
    ".csv",
    ".json",
    ".md",
    ".py",
    ".sh",
    ".tex",
    ".txt",
    ".toml",
    ".yml",
    ".yaml",
}
SECRET_PATTERNS = {
    "private key": re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
    "GitHub token": re.compile(r"(?:github_pat_|gh[opsu]_[A-Za-z0-9]{20,})"),
    "OpenAI-style token": re.compile(r"\bsk-[A-Za-z0-9_-]{20,}\b"),
    "AWS access key": re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b"),
}
ABSOLUTE_HOME = re.compile(r"(?:/Users/[^/\s]+/|/home/[^/\s]+/|[A-Za-z]:\\Users\\)")
WRONG_AUTHOR = re.compile(r"(?<!David )\bTom Foss\b|\bDavid T\. Foss\b")
MARKDOWN_LINK = re.compile(r"!?\[[^\]]*\]\(([^)]+)\)")


def skipped(relative: Path) -> bool:
    if any(part in SKIP_PARTS for part in relative.parts):
        return True
    if any(part.endswith(".egg-info") for part in relative.parts):
        return True
    if relative.parts[:2] == ("results", "generated") and relative.name != ".gitkeep":
        return True
    return relative.name.endswith(".checkpoint.json")


def files() -> list[Path]:
    return sorted(
        path for path in ROOT.rglob("*") if path.is_file() and not skipped(path.relative_to(ROOT))
    )


def main() -> int:
    failures: list[str] = []
    for entry in ROOT.rglob("*"):
        relative = entry.relative_to(ROOT)
        if skipped(relative):
            continue
        if entry.is_symlink():
            failures.append(f"symlink: {relative}")
    all_files = files()
    text_files = [path for path in all_files if path.suffix.lower() in TEXT_SUFFIXES]

    for path in all_files:
        relative = path.relative_to(ROOT)
        if path.stat().st_size > 50 * 1024 * 1024:
            failures.append(f"file over 50 MiB: {relative}")

    for path in text_files:
        relative = path.relative_to(ROOT)
        try:
            content = path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            failures.append(f"non-UTF-8 text file: {relative}")
            continue
        if relative != Path("scripts/check_publication.py") and ABSOLUTE_HOME.search(content):
            failures.append(f"private absolute path: {relative}")
        if relative != Path("scripts/check_publication.py"):
            for label, pattern in SECRET_PATTERNS.items():
                if pattern.search(content):
                    failures.append(f"{label}: {relative}")
            if relative != Path("paper/icecet2026/IEEEtran.cls") and WRONG_AUTHOR.search(content):
                failures.append(f"non-canonical author form: {relative}")
        if path.suffix.lower() == ".md":
            link_content = re.sub(r"`[^`]*`", "", content)
            for match in MARKDOWN_LINK.finditer(link_content):
                raw_target = match.group(1).strip().strip("<>")
                target = raw_target.split(maxsplit=1)[0].split("#", 1)[0]
                if not target or "://" in target or target.startswith(("mailto:", "#")):
                    continue
                candidate = (path.parent / unquote(target)).resolve()
                if not candidate.is_relative_to(ROOT) or not candidate.exists():
                    failures.append(f"broken link: {relative} -> {raw_target}")

    required = [
        "README.md",
        "CITATION.cff",
        "LICENSE",
        "docs/RESULTS.md",
        "docs/METHODS.md",
        "docs/REPRODUCIBILITY.md",
        "docs/CLAIM_LEDGER.md",
        "docs/PRIOR_ART.md",
        "docs/PUBLICATION_AUDIT.md",
        "research/results/v1/ANCHOR_SHA256SUMS",
        "research/results/v1/SHAKE_SOLVER_FRONTIER_SHA256SUMS",
        "research/results/v1/shake_boolean_cnf_reader_v1.json",
        "research/reports/FULLROUND_CAUSAL_SHAKE_SOLVER_FRONTIER_V1.md",
        "research/reports/FULLROUND_CAUSAL_SHAKE_AFFINE_HULL_V1.md",
        "research/reports/FULLROUND_CAUSAL_SHAKE_ALGEBRAIC_DEGREE_V1.md",
        "research/reports/FULLROUND_CAUSAL_SHAKE_BOOLEAN_INFLUENCE_V1.md",
        "research/reports/FULLROUND_CAUSAL_SHAKE_ANF_COMPRESSION_V1.md",
        "research/reports/SHAKE_SYMBOLIC_R2_ANF_FRONTIER_V1.md",
        "research/reports/FULLROUND_CAUSAL_SHAKE_SYMBOLIC_R2_SMT_V1.md",
        "research/reports/FULLROUND_CAUSAL_SHAKE_SYMBOLIC_R2_PARTITION_V1.md",
        "research/reports/FULLROUND_CAUSAL_SHAKE_SYMBOLIC_SPLIT_FRONTIER_V1.md",
        "research/reports/FULLROUND_CAUSAL_SHAKE_SYMBOLIC_R1_SCALING_V1.md",
        "research/reports/FULLROUND_CAUSAL_SHAKE_SYMBOLIC_R1_PARTITION_TOPOLOGY_V1.md",
        "research/reports/FULLROUND_CAUSAL_SHAKE256_SYMBOLIC_R1_TRANSFER_V1.md",
        "research/experiments/shake_anf_compression_cascade.py",
        "research/experiments/shake_symbolic_anf_frontier.py",
        "research/experiments/shake_symbolic_r2_smt_reader.py",
        "research/experiments/shake_symbolic_r2_partition_reader.py",
        "research/experiments/shake_symbolic_split_frontier.py",
        "research/experiments/shake_symbolic_r1_scaling_reader.py",
        "research/experiments/shake_symbolic_r1_partition_scaling_reader.py",
        "research/experiments/shake_symbolic_r1_upper_partition_reader.py",
        "research/experiments/shake_symbolic_r1_structural_partition_reader.py",
        "research/experiments/shake256_symbolic_r1_scaling_reader.py",
        "tests/test_shake_anf_compression_cascade.py",
        "tests/test_shake_symbolic_anf_frontier.py",
        "tests/test_shake_symbolic_r2_smt_reader.py",
        "tests/test_shake_symbolic_r2_partition_reader.py",
        "tests/test_shake_symbolic_split_frontier.py",
        "tests/test_shake_symbolic_r1_scaling_reader.py",
        "tests/test_shake_symbolic_r1_partition_scaling_reader.py",
        "tests/test_shake_symbolic_r1_upper_partition_reader.py",
        "tests/test_shake_symbolic_r1_structural_partition_reader.py",
        "tests/test_shake256_symbolic_r1_scaling_reader.py",
        "research/results/v1/shake_anf_compression_cascade_v1.json",
        "research/results/v1/shake_anf_compression_cascade_v1.causal",
        "research/results/v1/shake_anf_dictionary_v1.anfpack",
        "research/results/v1/shake_symbolic_anf_frontier_v1.json",
        "research/results/v1/shake_symbolic_anf_frontier_v1.causal",
        "research/results/v1/shake_symbolic_r2_smt_reader_v1.json",
        "research/results/v1/shake_symbolic_r2_smt_reader_v1.causal",
        "research/results/v1/shake_symbolic_r2_partition_reader_v1.json",
        "research/results/v1/shake_symbolic_r2_partition_reader_v1.causal",
        "research/results/v1/shake_symbolic_split_frontier_v1.json",
        "research/results/v1/shake_symbolic_split_frontier_v1.causal",
        "research/results/v1/shake_symbolic_r1_scaling_reader_v1.json",
        "research/results/v1/shake_symbolic_r1_scaling_reader_v1.causal",
        "research/results/v1/shake_symbolic_r1_partition_scaling_reader_v1.json",
        "research/results/v1/shake_symbolic_r1_partition_scaling_reader_v1.causal",
        "research/results/v1/shake_symbolic_r1_upper_partition_reader_v1.json",
        "research/results/v1/shake_symbolic_r1_upper_partition_reader_v1.causal",
        "research/results/v1/shake_symbolic_r1_structural_partition_reader_v1.json",
        "research/results/v1/shake_symbolic_r1_structural_partition_reader_v1.causal",
        "research/results/v1/shake256_symbolic_r1_scaling_reader_v1.json",
        "research/results/v1/shake256_symbolic_r1_scaling_reader_v1.causal",
        "scripts/reproduce_shake_solver_frontier.sh",
        "PATENT_NOTICE.md",
    ]
    retained_chacha_transfers = {
        "chacha20_smt_directional_round4_transfer": (
            "CAUSAL_CHACHA20_SMT_DIRECTIONAL_ROUND4_TRANSFER_V1.md"
        ),
        "chacha20_smt_directional_round5_transfer": (
            "CAUSAL_CHACHA20_SMT_DIRECTIONAL_ROUND5_BOUNDARY_V1.md"
        ),
        "chacha20_smt_shared_key_multiblock_transfer": (
            "CAUSAL_CHACHA20_SMT_SHARED_KEY_MULTIBLOCK_TRANSFER_V1.md"
        ),
        "chacha20_bitwuzla_round5_transfer": ("CAUSAL_CHACHA20_BITWUZLA_ROUND5_RECOVERY_V1.md"),
        "chacha20_bitwuzla_round6_width20_transfer": (
            "CAUSAL_CHACHA20_BITWUZLA_ROUND6_WIDTH20_RECOVERY_V1.md"
        ),
        "chacha20_bitwuzla_round7_width18_transfer": (
            "CAUSAL_CHACHA20_BITWUZLA_ROUND7_WIDTH18_BOUNDARY_V1.md"
        ),
        "chacha20_bitwuzla_round7_partition_transfer": (
            "CAUSAL_CHACHA20_BITWUZLA_ROUND7_PARTITION_RECOVERY_V1.md"
        ),
        "chacha20_bitwuzla_round7_width20_partition_transfer": (
            "CAUSAL_CHACHA20_BITWUZLA_ROUND7_WIDTH20_PARTITION_RECOVERY_V1.md"
        ),
        "chacha20_bitwuzla_round8_width20_partition_transfer": (
            "CAUSAL_CHACHA20_BITWUZLA_ROUND8_WIDTH20_PARTITION_RECOVERY_V1.md"
        ),
        "chacha20_bitwuzla_round9_width20_partition_transfer": (
            "CAUSAL_CHACHA20_BITWUZLA_ROUND9_WIDTH20_PARTITION_RECOVERY_V1.md"
        ),
        "chacha20_bitwuzla_round10_width20_partition_transfer": (
            "CAUSAL_CHACHA20_BITWUZLA_ROUND10_WIDTH20_PARTITION_BOUNDARY_V1.md"
        ),
        "chacha20_bitwuzla_round10_split9_transfer": (
            "CAUSAL_CHACHA20_BITWUZLA_ROUND10_SPLIT9_CUT_BOUNDARY_V1.md"
        ),
        "chacha20_bitwuzla_round10_width12_refinement": (
            "CAUSAL_CHACHA20_BITWUZLA_ROUND10_WIDTH12_REFINEMENT_BOUNDARY_V1.md"
        ),
        "chacha20_bitwuzla_round10_b8_partition_transfer": (
            "CAUSAL_CHACHA20_BITWUZLA_ROUND10_B8_COMPLETE_PARTITION_BOUNDARY_V1.md"
        ),
        "chacha20_formula_operator_atlas": ("CAUSAL_CHACHA20_FORMULA_OPERATOR_ATLAS_V1.md"),
        "chacha20_round10_public_geometry_partition": (
            "CAUSAL_CHACHA20_ROUND10_PUBLIC_GEOMETRY_PARTITION_BOUNDARY_V1.md"
        ),
        "chacha20_phase_conjugacy_holdout": ("CAUSAL_CHACHA20_PHASE_CONJUGACY_HOLDOUT_V1.md"),
        "chacha20_round10_b8_global_cse": ("CAUSAL_CHACHA20_ROUND10_B8_GLOBAL_CSE_BOUNDARY_V1.md"),
        "chacha20_round10_b8_lane_major": ("CAUSAL_CHACHA20_ROUND10_B8_LANE_MAJOR_BOUNDARY_V1.md"),
        "chacha20_round10_external_cnf_reverse": (
            "CAUSAL_CHACHA20_ROUND10_EXTERNAL_CNF_REVERSE_BOUNDARY_V1.md"
        ),
        "chacha20_a188_cnf_structural_ordering": (
            "CAUSAL_CHACHA20_A188_CNF_STRUCTURAL_ORDERING_V1.md"
        ),
        "chacha20_round10_bidirectional_min_distance": (
            "CAUSAL_CHACHA20_ROUND10_BIDIRECTIONAL_MIN_DISTANCE_BOUNDARY_V1.md"
        ),
    }
    for stem, report in retained_chacha_transfers.items():
        required.extend(
            [
                f"research/configs/{stem}_v1.json",
                f"research/experiments/{stem}.py",
                f"research/reports/{report}",
                f"research/results/v1/{stem}_v1.json",
                f"research/results/v1/{stem}_v1.causal",
                f"tests/test_{stem}.py",
            ]
        )
    required.extend(
        [
            "research/experiments/chacha20_smt_round5_retained_figures.py",
            "research/results/v1/chacha20_a187_fixed_rlimit_search_shape_v1.svg",
            "research/results/v1/chacha20_a188_solver_portfolio_v1.svg",
            "research/results/v1/chacha20_a189_round6_width20_portfolio_v1.svg",
            "tests/test_chacha20_smt_round5_retained_figures.py",
            "Brewfile",
            "research/experiments/formula_atlas_transfer_audit.py",
            "research/reports/FORMULA_ATLAS_FULL_REAUDIT_V1.md",
            "research/results/v1/formula_atlas_transfer_coverage_v1.json",
            "tests/test_formula_atlas_transfer_audit.py",
            "research/experiments/chacha20_cnf_structural_figures.py",
            "research/results/v1/chacha20_a204_external_cnf_reverse_boundary_v1.svg",
            "research/results/v1/chacha20_a205_structural_ordering_calibration_v1.svg",
            "research/results/v1/chacha20_a206_bidirectional_round10_boundary_v1.svg",
            "tests/test_chacha20_cnf_structural_figures.py",
            "research/configs/chacha20_round10_structural_portfolio_v1.json",
            "research/experiments/chacha20_round10_structural_order_archive.py",
            "research/experiments/chacha20_round10_structural_portfolio.py",
            "research/reports/CAUSAL_CHACHA20_ROUND10_STRUCTURAL_PORTFOLIO_PREFLIGHT_V1.md",
            "research/reports/CAUSAL_CHACHA20_ROUND10_STRUCTURAL_PORTFOLIO_BOUNDARY_V1.md",
            "research/results/v1/chacha20_round10_structural_order_archive_v1.json",
            "research/results/v1/chacha20_round10_structural_order_archive_v1.causal",
            "research/results/v1/chacha20_round10_structural_orders_v1.npy",
            "research/results/v1/chacha20_round10_structural_portfolio_v1.json",
            "research/results/v1/chacha20_round10_structural_portfolio_v1.causal",
            "research/results/v1/chacha20_a207_structural_portfolio_boundary_v1.svg",
            "tests/test_chacha20_round10_structural_order_archive.py",
            "tests/test_chacha20_round10_structural_portfolio.py",
            "tests/test_chacha20_round10_structural_portfolio_result.py",
        ]
    )
    for item in required:
        if not (ROOT / item).is_file():
            failures.append(f"missing publication file: {item}")

    citation = (ROOT / "CITATION.cff").read_text(encoding="utf-8")
    if "https://github.com/DT-Foss/f8-causal-cryptanalysis" not in citation:
        failures.append("CITATION.cff has no canonical repository URL")

    boolean_result = json.loads(
        (ROOT / "research/results/v1/shake_boolean_cnf_reader_v1.json").read_text(encoding="utf-8")
    )
    executed_variants = set(boolean_result["parameters"]["variants"])
    graph_variants = {row["edge_id"].split("-", 1)[0] for row in boolean_result["reader_triplets"]}
    if graph_variants != executed_variants:
        failures.append("Boolean CNF Reader graph variants do not match executed variants")

    results = ROOT / "research/results/v1"
    a205 = json.loads((results / "chacha20_a188_cnf_structural_ordering_v1.json").read_bytes())
    if a205["comparisons"]["status_counts"] != {
        "invalid": 0,
        "sat": 16,
        "unknown": 30,
        "unsat": 0,
    }:
        failures.append("A205-r2 observation counts differ")
    if len(a205["comparisons"]["structural_outlier_candidates"]) != 12:
        failures.append("A205-r2 structural candidate count differs")
    correction = a205.get("metadata_correction", {})
    if not (
        correction.get("solver_observations_changed") is False
        and correction.get("comparisons_changed") is False
        and correction.get("confirmations_changed") is False
    ):
        failures.append("A205-r2 metadata-only correction boundary differs")

    a206 = json.loads(
        (results / "chacha20_round10_bidirectional_min_distance_v1.json").read_bytes()
    )
    if (
        a206["comparisons"]["status_counts"]
        != {
            "invalid": 0,
            "sat": 0,
            "unknown": 64,
            "unsat": 0,
        }
        or a206["confirmations"]
    ):
        failures.append("A206 complete UNKNOWN boundary differs")

    archive = results / "chacha20_round10_structural_orders_v1.npy"
    if (
        archive.stat().st_size != 11_145_296
        or hashlib.sha256(archive.read_bytes()).hexdigest()
        != "ea45134552a6ad3bb6c277ec6bd271d22764f902298b78bda568aef57a12f72f"
    ):
        failures.append("A207 structural order archive identity differs")
    a207_preflight = json.loads(
        (results / "chacha20_round10_structural_order_archive_v1.json").read_bytes()
    )
    if not (
        a207_preflight["attempt_id"] == "A207_PREFLIGHT"
        and a207_preflight["information_boundary"]["external_CaDiCaL_A207_execution_started"]
        is False
        and len(a207_preflight["candidate_manifest"]) == 12
    ):
        failures.append("A207 pre-execution boundary differs")
    a207_result_path = results / "chacha20_round10_structural_portfolio_v1.json"
    if (
        hashlib.sha256(a207_result_path.read_bytes()).hexdigest()
        != "80ce896083b239e3bb95e31433fc8cdf6157491005bbb3b024182f730b545652"
    ):
        failures.append("A207 result identity differs")
    if (
        hashlib.sha256(
            (results / "chacha20_round10_structural_portfolio_v1.causal").read_bytes()
        ).hexdigest()
        != "0d23f4fcb91c6602b3222315afb84f203eff8f5d51b0e4df5f6f6430616d6dfa"
    ):
        failures.append("A207 Causal identity differs")
    a207_result = json.loads(a207_result_path.read_bytes())
    comparison = a207_result["comparisons"]
    if not (
        a207_result["evidence_stage"] == "ROUND10_STRUCTURAL_PORTFOLIO_COMPLETE_BOUNDARY_RETAINED"
        and comparison["new_status_counts"] == {"invalid": 0, "sat": 0, "unknown": 352, "unsat": 0}
        and comparison["combined_calibrated_portfolio_cell_mode_count"] == 416
        and a207_result["confirmations"] == []
    ):
        failures.append("A207 complete UNKNOWN boundary differs")
    progress = {
        row["candidate"]: row for row in a207_result["progress_map"]["candidate_summaries"]
    }["output_unit_bfs_far"]["metrics"]
    if not (
        progress["conflicts"]["total_ratio"] == 2.7585773439810706
        and progress["decisions"]["total_ratio"] == 5.685713565082508
        and progress["propagations"]["total_ratio"] == 0.5939991928589421
    ):
        failures.append("A207 progress-map outlier differs")

    deck = ROOT / "paper/nano2026/presentation/Foss_CASI_Nano-IoT_IEEE_NANO_2026.pptx"
    if deck.is_file():
        with zipfile.ZipFile(deck) as archive:
            bad = archive.testzip()
            if bad:
                failures.append(f"corrupt presentation member: {bad}")
            core = archive.read("docProps/core.xml").decode("utf-8")
            if core.count("David Tom Foss") < 2:
                failures.append("presentation creator metadata is not canonical")
    else:
        failures.append("sanitized Nanjing presentation is missing")

    print(f"publication files: {len(all_files)}")
    print(f"UTF-8 audited files: {len(text_files)}")
    print(f"repository bytes: {sum(path.stat().st_size for path in all_files)}")
    if failures:
        for failure in failures:
            print(f"ERROR: {failure}")
        return 1
    print("publication audit: OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

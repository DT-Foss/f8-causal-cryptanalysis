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
    ".cnf",
    ".cpp",
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
EXACT_PATH_BEARING_RECORDS = {
    Path("research/results/v1/chacha20_round20_multihorizon_preflight_v1.json"),
}


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
        if (
            relative != Path("scripts/check_publication.py")
            and relative not in EXACT_PATH_BEARING_RECORDS
            and ABSOLUTE_HOME.search(content)
        ):
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
        "docs/RELEASE_A220P.md",
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
        "chacha20_round10_bfs_far_long_budget": (
            "CAUSAL_CHACHA20_ROUND10_BFS_FAR_LONG_BUDGET_BOUNDARY_V1.md"
        ),
        "chacha20_round10_bfs_far_width12_refinement": (
            "CAUSAL_CHACHA20_ROUND10_BFS_FAR_WIDTH12_BOUNDARY_V1.md"
        ),
        "chacha20_round10_incremental_sibling_learning": (
            "CAUSAL_CHACHA20_ROUND10_INCREMENTAL_SIBLING_LEARNING_BOUNDARY_V1.md"
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
            "research/native/cadical_incremental_assumptions.cpp",
            "tests/fixtures/cadical_incremental_assumptions_toy.cnf",
            "tests/fixtures/cadical_incremental_assumptions_base_unsat.cnf",
        ]
    )
    for item in required:
        if not (ROOT / item).is_file():
            failures.append(f"missing publication file: {item}")

    completed_a211_a220p_files = [
        "research/results/v1/A211_A220P_SHA256SUMS",
        "research/configs/chacha20_round10_global_incremental_cover_v1.json",
        "research/experiments/chacha20_round10_global_incremental_cover.py",
        "research/native/cadical_global_incremental_assumptions.cpp",
        "research/results/v1/chacha20_round10_global_incremental_cover_v1.json",
        "research/results/v1/chacha20_round10_global_incremental_cover_v1.causal",
        "tests/test_chacha20_round10_global_incremental_cover.py",
        "research/configs/chacha20_round20_global_incremental_transfer_v1.json",
        "research/experiments/chacha20_round20_global_incremental_transfer.py",
        "research/reports/CAUSAL_CHACHA20_ROUND20_GLOBAL_INCREMENTAL_TRANSFER_V1.md",
        "research/results/v1/chacha20_round20_global_incremental_transfer_v1.json",
        "research/results/v1/chacha20_round20_global_incremental_transfer_v1.causal",
        "tests/test_chacha20_round20_global_incremental_transfer.py",
        "research/reports/SOLVER_TRAJECTORY_FORMULA_ATLAS_V1.md",
        "research/reports/CAUSAL_CHACHA20_ROUND20_PCR_BACKPROJECTION_V1.md",
        "research/reports/CAUSAL_CHACHA20_ROUND20_KNOWNKEY_PROPAGATION_ATLAS_V3.md",
        "research/reports/CAUSAL_CHACHA20_ROUND20_KEY_CONTRAST_MOBIUS_ATLAS_V1.md",
        "research/reports/CAUSAL_CHACHA20_ROUND20_MULTIFREQUENCY_GROUP_READOUT_V1.md",
        "research/reports/CAUSAL_CHACHA20_ROUND20_MULTIFREQUENCY_SELECTION_MATCHED_NULL_V1.md",
        "research/reports/CAUSAL_CHACHA20_ROUND20_OPERATOR_DIVERSITY_AUDIT_V1.md",
        "research/reports/CAUSAL_CHACHA20_ROUND20_KNOWNKEY_TRAJECTORY_ATLAS_V1.md",
        "research/reports/CAUSAL_CHACHA20_ROUND20_RANKED_TARGET_RECOVERY_V1.md",
        "research/configs/chacha20_round20_multihorizon_preflight_v1.json",
        "research/experiments/chacha20_round20_multihorizon_preflight.py",
        "research/experiments/chacha20_round20_public_core.py",
        "research/experiments/chacha20_retained_multihorizon.py",
        "research/native/cadical_global_incremental_multihorizon.cpp",
        "research/reports/CAUSAL_CHACHA20_ROUND20_MULTIHORIZON_PREFLIGHT_V1.md",
        "research/results/v1/chacha20_round20_multihorizon_preflight_v1.json",
        "tests/test_chacha20_round20_multihorizon_preflight.py",
        "tests/test_chacha20_round20_public_core.py",
        "tests/test_chacha20_retained_multihorizon.py",
        "research/configs/chacha20_round20_factorial_trajectory_transfer_v1.json",
        "research/experiments/chacha20_round20_factorial_key_design.py",
        "research/experiments/chacha20_round20_factorial_trajectory_collect.py",
        "research/experiments/chacha20_round20_factorial_trajectory_holdout_collect.py",
        "research/experiments/chacha20_round20_factorial_trajectory_holdout_evaluate.py",
        "research/experiments/chacha20_round20_factorial_trajectory_read.py",
        "src/arx_carry_leak/factorial_holdout.py",
        "src/arx_carry_leak/factorial_target.py",
        "src/arx_carry_leak/factorial_trajectory.py",
        "tests/test_factorial_holdout.py",
        "tests/test_factorial_target.py",
        "tests/test_factorial_trajectory.py",
        "tests/test_chacha20_round20_factorial_trajectory_collect.py",
        "tests/test_chacha20_round20_factorial_trajectory_holdout_collect.py",
        "tests/test_chacha20_round20_factorial_trajectory_holdout_evaluate.py",
        "tests/test_chacha20_round20_factorial_trajectory_read.py",
        "tests/test_chacha20_round20_factorial_trajectory_protocol.py",
    ]
    for item in completed_a211_a220p_files:
        if not (ROOT / item).is_file():
            failures.append(f"missing A211-A220P publication file: {item}")

    forbidden_unfinished_or_private_files = [
        "research/native/build/cadical_incremental_assumptions",
        "research/results/v1/chacha20_round20_factorial_trajectory_fit_select_v1.json",
        ".research_sealed",
    ]
    for item in forbidden_unfinished_or_private_files:
        if (ROOT / item).exists():
            failures.append(f"unfinished or private publication file: {item}")

    a220p_result = ROOT / "research/results/v1/chacha20_round20_multihorizon_preflight_v1.json"
    a220_protocol = ROOT / "research/configs/chacha20_round20_factorial_trajectory_transfer_v1.json"
    if hashlib.sha256(a220p_result.read_bytes()).hexdigest() != (
        "f5cc99ac3dcf679023e1a32b91b5dae26d94837db08673f23f0f5cb787afd946"
    ):
        failures.append("A220P retained result identity differs")
    a220p_payload = json.loads(a220p_result.read_bytes())
    if a220p_payload.get("measurement_sha256") != (
        "a43f530b72dad576db5623e3c23f8c3dcb3ce666c4159b29d74c9bb7294cfdc7"
    ):
        failures.append("A220P scientific measurement identity differs")
    if hashlib.sha256(a220_protocol.read_bytes()).hexdigest() != (
        "70df07cb4f4f22115e3aa63765de0fca0dd610607cc87356946a188f53fe5645"
    ):
        failures.append("A220 frozen protocol identity differs")

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

    a208_result_path = results / "chacha20_round10_bfs_far_long_budget_v1.json"
    if (
        hashlib.sha256(a208_result_path.read_bytes()).hexdigest()
        != "58af841aa508978857f629c43c3fdb679e620eb9ec365b5211b4f708d287203c"
        or hashlib.sha256(
            (results / "chacha20_round10_bfs_far_long_budget_v1.causal").read_bytes()
        ).hexdigest()
        != "9e5e35ec7a3a005f8bd10d1608dd078b7b79aaaf9bd1e4e77ac5e7201c4a0993"
    ):
        failures.append("A208 retained artifact identity differs")
    a208 = json.loads(a208_result_path.read_bytes())
    if not (
        a208["evidence_stage"] == "ROUND10_BFS_FAR_LONG_COMPLETE_BOUNDARY_RETAINED"
        and a208["comparisons"]["status_counts"]
        == {"invalid": 0, "sat": 0, "unknown": 32, "unsat": 0}
        and a208["confirmations"] == []
        and len(a208["rate_comparison"]["cell_rows"]) == 32
    ):
        failures.append("A208 complete long-budget boundary differs")

    a209_result_path = results / "chacha20_round10_bfs_far_width12_refinement_v1.json"
    if (
        hashlib.sha256(a209_result_path.read_bytes()).hexdigest()
        != "242a87fd56da3fcf60e6ae4c1a5dd75effc9a2293a41496ea71f4c4342cc5c1e"
        or hashlib.sha256(
            (results / "chacha20_round10_bfs_far_width12_refinement_v1.causal").read_bytes()
        ).hexdigest()
        != "577f8fdbf41d95d6a61316103c48cc6f366311821b830ac2e4d11b7f4f79eb7f"
    ):
        failures.append("A209 retained artifact identity differs")
    a209 = json.loads(a209_result_path.read_bytes())
    a209_totals = a209["phase_reset_comparison"]["total_metrics"]
    if not (
        a209["evidence_stage"] == "ROUND10_BFS_FAR_WIDTH12_COMPLETE_BOUNDARY_RETAINED"
        and a209["comparisons"]["status_counts"]
        == {"invalid": 0, "sat": 0, "unknown": 256, "unsat": 0}
        and a209["confirmations"] == []
        and len(a209["phase_reset_comparison"]["cell_rows"]) == 256
        and a209_totals["decisions"]["compute_normalized_mean_child_over_parent"]
        == 2.7925087307017944
        and a209_totals["propagations"]["compute_normalized_mean_child_over_parent"]
        == 1.614886051905536
    ):
        failures.append("A209 complete Width-12 phase-reset boundary differs")

    a210_result_path = results / "chacha20_round10_incremental_sibling_learning_v1.json"
    if (
        hashlib.sha256(a210_result_path.read_bytes()).hexdigest()
        != "1765ddabcec9c35d778bbb6e4c4e4aadc66277e7d9255d1f2a8ffdcd7b8152ce"
        or hashlib.sha256(
            (results / "chacha20_round10_incremental_sibling_learning_v1.causal").read_bytes()
        ).hexdigest()
        != "ff7f2019001d4c0e8478dd35476d975dde5b6faa1110c0383fbffba9091a6586"
    ):
        failures.append("A210 retained artifact identity differs")
    a210 = json.loads(a210_result_path.read_bytes())
    a210_counts = a210["comparisons"]["per_mode_status_counts"]
    a210_metrics = a210["comparative_metrics"]["mode_vs_A209_summaries"]
    observations = a210["execution"]["observations"]
    grouped: dict[tuple[str, str], list[dict]] = {}
    for row in observations:
        grouped.setdefault((row["mode"], row["parent_prefix5"]), []).append(row)
    first_child_dominance = all(
        len(rows) == 8
        and sorted(rows, key=lambda row: row["child_index"])[0]["metrics_delta"]["decisions"]
        > max(
            row["metrics_delta"]["decisions"]
            for row in sorted(rows, key=lambda row: row["child_index"])[1:]
        )
        and sorted(rows, key=lambda row: row["child_index"])[0]["metrics_delta"]["conflicts"]
        > max(
            row["metrics_delta"]["conflicts"]
            for row in sorted(rows, key=lambda row: row["child_index"])[1:]
        )
        for rows in grouped.values()
    )
    if not (
        a210["evidence_stage"] == "ROUND10_INCREMENTAL_COMPLETE_BOUNDARY_RETAINED"
        and a210_counts
        == {
            "gray_incremental": {"invalid": 0, "sat": 0, "unknown": 256, "unsat": 0},
            "numeric_incremental": {
                "invalid": 0,
                "sat": 0,
                "unknown": 256,
                "unsat": 0,
            },
        }
        and a210["comparisons"]["parent_run_count"] == 64
        and a210["comparisons"]["child_observation_count"] == 512
        and a210["comparisons"]["early_stop_used"] is False
        and a210["confirmations"] == []
        and len(observations) == 512
        and len(a210["execution"]["parent_runs"]) == 64
        and len(grouped) == 64
        and first_child_dominance
        and a210_metrics["numeric_incremental"]["decisions"]["total_ratio"]
        == 0.14107693425789813
        and a210_metrics["gray_incremental"]["decisions"]["total_ratio"]
        == 0.14185557384819422
        and a210_metrics["numeric_incremental"]["conflicts"]["total_ratio"]
        == 0.2991561572326791
        and a210_metrics["gray_incremental"]["conflicts"]["total_ratio"]
        == 0.29287909485276054
        and a210["comparative_metrics"]["ordered_mode_summary"]["gray_over_numeric"][
            "decisions"
        ]["total_ratio"]
        == 1.0055192551099295
        and a210["comparative_metrics"]["ordered_mode_summary"]["gray_over_numeric"][
            "conflicts"
        ]["total_ratio"]
        == 0.9790174387918871
        and a210["causal"]["graph_sha256"]
        == "cc450abd4035fc9f823234a8001a37f59cd1a7ec8a6e2839a366d8b34a229363"
        and a210["causal"]["explicit_triplets"] == 8
        and a210["causal"]["provenance_verified"] is True
    ):
        failures.append("A210 complete incremental learned-state boundary differs")

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

#!/usr/bin/env python3
"""Fail-closed audit for public repository metadata, links, paths, and secrets."""

from __future__ import annotations

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
        path
        for path in ROOT.rglob("*")
        if path.is_file() and not skipped(path.relative_to(ROOT))
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
        "chacha20_bitwuzla_round5_transfer": (
            "CAUSAL_CHACHA20_BITWUZLA_ROUND5_RECOVERY_V1.md"
        ),
        "chacha20_bitwuzla_round6_width20_transfer": (
            "CAUSAL_CHACHA20_BITWUZLA_ROUND6_WIDTH20_RECOVERY_V1.md"
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
        ]
    )
    for item in required:
        if not (ROOT / item).is_file():
            failures.append(f"missing publication file: {item}")

    citation = (ROOT / "CITATION.cff").read_text(encoding="utf-8")
    if "https://github.com/DT-Foss/f8-causal-cryptanalysis" not in citation:
        failures.append("CITATION.cff has no canonical repository URL")

    boolean_result = json.loads(
        (ROOT / "research/results/v1/shake_boolean_cnf_reader_v1.json").read_text(
            encoding="utf-8"
        )
    )
    executed_variants = set(boolean_result["parameters"]["variants"])
    graph_variants = {
        row["edge_id"].split("-", 1)[0]
        for row in boolean_result["reader_triplets"]
    }
    if graph_variants != executed_variants:
        failures.append(
            "Boolean CNF Reader graph variants do not match executed variants"
        )

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

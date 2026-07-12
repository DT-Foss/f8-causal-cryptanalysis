from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

ROOT = Path(__file__).parents[1]
MODULE_PATH = ROOT / "research" / "experiments" / "formula_atlas_transfer_audit.py"
SPEC = importlib.util.spec_from_file_location("formula_atlas_transfer_audit", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)


def _payload() -> dict:
    workspace = ROOT.parent
    return MODULE.build(
        workspace / "Mathepaper" / "formula_atlas_v1.json",
        workspace / "Mathepaper" / "formula_source_pages_v1.json",
    )


def test_complete_keyword_independent_coverage() -> None:
    payload = _payload()
    assert payload["summary"] == {
        "papers": 9,
        "pages": 113,
        "entries": 2_411,
        "unique_entry_ids": 2_411,
        "transfer_candidates": 18,
        "priority_1_candidates": 6,
    }
    assert payload["method"]["keyword_prefilter_used_for_source_review"] is False
    assert payload["method"]["formula_entries_dropped"] == 0
    assert all(row["page_topics"] for row in payload["entries"])
    assert all(
        row["review_status"] == "retained_via_full_source_page_review" for row in payload["entries"]
    )


def test_every_source_page_and_entry_is_unique() -> None:
    payload = _payload()
    pages = {(row["paper"], row["page"]) for row in payload["page_coverage"]}
    entry_ids = [row["id"] for row in payload["entries"]]
    assert len(pages) == 113
    assert len(entry_ids) == len(set(entry_ids)) == 2_411
    for paper, ranges in MODULE.PAPER_COVERAGE.items():
        covered = {page for row in ranges for page in range(row["pages"][0], row["pages"][1] + 1)}
        actual = {page for source, page in pages if source == paper}
        assert covered == actual


def test_candidate_registry_has_executable_boundaries() -> None:
    payload = _payload()
    ids = [row["id"] for row in payload["transfer_candidates"]]
    assert len(ids) == len(set(ids)) == 18
    assert ids[:6] == ["T01", "T02", "T03", "T04", "T05", "T06"]
    assert all(row["required_invariants"] for row in payload["transfer_candidates"])
    assert all(row["construction"] for row in payload["transfer_candidates"])

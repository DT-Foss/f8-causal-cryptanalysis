from __future__ import annotations

import hashlib
import json
from pathlib import Path

from arx_carry_leak.crypto_causal import CryptoCausalReader

ROOT = Path(__file__).parents[1]
RESULTS = ROOT / "research/results/v1"
RESULT = RESULTS / "chacha20_round10_structural_portfolio_v1.json"
CAUSAL = RESULTS / "chacha20_round10_structural_portfolio_v1.causal"
RESULT_SHA256 = "80ce896083b239e3bb95e31433fc8cdf6157491005bbb3b024182f730b545652"
CAUSAL_SHA256 = "0d23f4fcb91c6602b3222315afb84f203eff8f5d51b0e4df5f6f6430616d6dfa"
GRAPH_SHA256 = "ceb1013b7c5387dedbcf5dfe7c5072fe73c200ba72f5d42b5ff7b0866ddb9b14"


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _payload() -> dict:
    return json.loads(RESULT.read_bytes())


def test_a207_complete_result_hashes_and_status_boundary_are_exact() -> None:
    payload = _payload()
    assert _sha256(RESULT) == RESULT_SHA256
    assert _sha256(CAUSAL) == CAUSAL_SHA256
    assert payload["attempt_id"] == "A207"
    assert payload["evidence_stage"] == ("ROUND10_STRUCTURAL_PORTFOLIO_COMPLETE_BOUNDARY_RETAINED")
    comparison = payload["comparisons"]
    assert comparison["complete_new_predeclared_execution"] is True
    assert comparison["early_stop_used"] is False
    assert comparison["new_cell_mode_count"] == 352
    assert comparison["new_status_counts"] == {
        "invalid": 0,
        "sat": 0,
        "unknown": 352,
        "unsat": 0,
    }
    assert comparison["A206_cell_mode_count_reused_without_reexecution"] == 64
    assert comparison["combined_calibrated_portfolio_cell_mode_count"] == 416
    assert comparison["confirmed_recovery_retained"] is False
    assert comparison["single_candidate_complete_domain_resolution_retained"] is False
    assert comparison["portfolio_complete_domain_resolution_retained"] is False
    assert payload["confirmations"] == []


def test_a207_all_eleven_candidate_modes_complete_the_same_exact_cover() -> None:
    payload = _payload()
    counts = payload["comparisons"]["new_per_candidate_status_counts"]
    assert len(counts) == 11
    assert all(
        row == {"invalid": 0, "sat": 0, "unknown": 32, "unsat": 0} for row in counts.values()
    )
    observations = payload["execution"]["observations"]
    assert len(observations) == 352
    assert all(row["status"] == "unknown" for row in observations)
    assert all(row["externally_timed_out"] is False for row in observations)
    assert all(row["returncode"] == 0 for row in observations)
    assert all(row["internal_timeout_marker"] is True for row in observations)


def test_a207_output_unit_bfs_far_is_the_systematic_progress_outlier() -> None:
    payload = _payload()
    summaries = {row["candidate"]: row for row in payload["progress_map"]["candidate_summaries"]}
    assert len(summaries) == 11
    far = summaries["output_unit_bfs_far"]
    assert far["solver_mode"] == "reverse"
    metrics = far["metrics"]
    assert metrics["conflicts"]["total_ratio"] == 2.7585773439810706
    assert metrics["decisions"]["total_ratio"] == 5.685713565082508
    assert metrics["propagations"]["total_ratio"] == 0.5939991928589421
    assert metrics["conflicts"]["cell_ratio_min"] == 1.703481842006739
    assert metrics["decisions"]["cell_ratio_min"] == 3.3145624103299856
    assert metrics["conflicts"]["candidate_metric_missing_count"] == 0
    assert metrics["decisions"]["candidate_metric_missing_count"] == 0


def test_a207_complete_result_causal_reader_is_exact() -> None:
    payload = _payload()
    reader = CryptoCausalReader(CAUSAL)
    assert reader.file_sha256 == CAUSAL_SHA256
    assert reader.graph_sha256 == GRAPH_SHA256
    assert reader.verify_provenance() is True
    assert len(reader.triplets(include_inferred=False)) == 8
    assert payload["causal"]["file_sha256"] == CAUSAL_SHA256
    assert payload["causal"]["graph_sha256"] == GRAPH_SHA256
    assert payload["causal"]["provenance_verified"] is True

from __future__ import annotations

import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).parents[1]
MANIFEST = ROOT / "research/results/v1/fullround_residual_key_recovery_transfer_v1.json"


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def test_transfer_manifest_binds_all_retained_artifacts() -> None:
    payload = json.loads(MANIFEST.read_text())
    assert payload["schema"] == "fullround-residual-key-recovery-transfer-v1"
    attempts = payload["attempts"]
    assert [row["attempt_id"] for row in attempts] == ["A184", "A237", "A240"]
    assert [row["rounds"] for row in attempts] == [20, 22, 72]
    assert [row["unknown_key_bits"] for row in attempts] == [40, 42, 38]
    assert all(row["factual_full_matches"] == 1 for row in attempts)
    assert all(row["control_full_matches"] == 0 for row in attempts)

    for row in attempts:
        result_path = ROOT / row["result_path"]
        assert _sha256(result_path) == row["result_sha256"]
        result = json.loads(result_path.read_text())
        assert result["attempt_id"] == row["attempt_id"]
        assert result["execution"]["complete_domain_executed"] is True
        assert len(result["execution"]["factual_full_matches"]) == 1
        assert result["execution"]["control_full_matches"] == []
        if "causal_path" in row:
            assert _sha256(ROOT / row["causal_path"]) == row["causal_sha256"]

    report_path = ROOT / payload["report_path"]
    assert _sha256(report_path) == payload["report_sha256"]
    boundary = payload["claim_boundary"]
    assert boundary["full_round_execution"] is True
    assert boundary["complete_residual_domains"] is True
    assert boundary["asymptotic_search_reduction_claimed"] is False

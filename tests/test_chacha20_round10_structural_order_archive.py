from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path
from typing import Any

import numpy as np
import pytest

ROOT = Path(__file__).parents[1]
MODULE_PATH = ROOT / "research" / "experiments" / "chacha20_round10_structural_order_archive.py"
SPEC = importlib.util.spec_from_file_location(
    "chacha20_round10_structural_order_archive_tested", MODULE_PATH
)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)

RESULTS = ROOT / "research" / "results" / "v1"
ARCHIVE_PATH = RESULTS / MODULE.ARCHIVE_FILENAME
METADATA_PATH = RESULTS / MODULE.METADATA_FILENAME
CAUSAL_PATH = RESULTS / MODULE.CAUSAL_FILENAME
RUNNER_SHA256 = "db8a611629773eb1af545879de04403ff90f821bd98cf12c407bafd0fa5f1bf6"
ARCHIVE_SHA256 = "ea45134552a6ad3bb6c277ec6bd271d22764f902298b78bda568aef57a12f72f"
METADATA_SHA256 = "b6dfb42095d176823c15d36a490297eb24bc85feedb916513b329d52808a73ce"
CAUSAL_SHA256 = "71295ac95e3a2e5248e5d58cf3a40053bfe2a84f3ce30145f07b5abdbed9a58c"
CAUSAL_GRAPH_SHA256 = "dad19e2848cb3d480713113b45cfc4a65344b3582ada2bccceec1ce9321c061b"
CANDIDATE_MANIFEST_SHA256 = "aa1996f2a85be30e31b623c198ed912ad5c3e3d4f92058a279129b28847b2ace"


@pytest.fixture(scope="module")
def analysis() -> dict[str, Any]:
    return MODULE.analyze(RESULTS)


def test_a207_preflight_analysis_keeps_the_complete_calibrated_portfolio(
    analysis: dict[str, Any],
) -> None:
    assert analysis["candidate_order"] == list(MODULE.CANDIDATE_ORDER)
    assert analysis["calibrated_modes"] == MODULE.CALIBRATED_MODES
    assert len(analysis["candidate_order"]) == 12
    assert analysis["calibrated_modes"]["bidirectional_min_distance"] == (
        "A206_default_and_reverse_complete"
    )
    assert analysis["solver_execution_started"] is False
    assert analysis["a206_analysis"]["public_challenge"]["unknown_assignment_included"] is False
    assert analysis["anchor_gates"]["A206_complete_64_unknown_boundary_retained"] is True


def test_a207_preflight_runner_and_artifact_hashes_are_exact() -> None:
    assert MODULE._file_sha256(MODULE_PATH) == RUNNER_SHA256
    assert MODULE._file_sha256(ARCHIVE_PATH) == ARCHIVE_SHA256
    assert MODULE._file_sha256(METADATA_PATH) == METADATA_SHA256
    assert MODULE._file_sha256(CAUSAL_PATH) == CAUSAL_SHA256
    payload = json.loads(METADATA_PATH.read_bytes())
    assert payload["attempt_id"] == "A207_PREFLIGHT"
    assert payload["schema"] == MODULE.SCHEMA
    assert payload["evidence_stage"] == (
        "ROUND10_STRUCTURAL_ORDER_ARCHIVE_RETAINED_BEFORE_A207_EXECUTION"
    )
    assert payload["archive_sha256"] == ARCHIVE_SHA256
    assert payload["candidate_manifest_sha256"] == CANDIDATE_MANIFEST_SHA256


def test_a207_preflight_npy_archive_rows_are_exact_permutations() -> None:
    payload = json.loads(METADATA_PATH.read_bytes())
    matrix = np.load(ARCHIVE_PATH, mmap_mode="r", allow_pickle=False)
    assert matrix.shape == (12, 232191)
    assert matrix.dtype == np.dtype("<i4")
    assert payload["archive"] == {
        "filename": MODULE.ARCHIVE_FILENAME,
        "format": "NumPy_NPY_v1_little_endian_int32_C_order_no_pickle",
        "shape": [12, 232191],
        "dtype": "int32",
        "bytes": 11145296,
        "row_candidate_order": list(MODULE.CANDIDATE_ORDER),
        "sha256": ARCHIVE_SHA256,
        "all_rows_reopened_and_hash_verified": True,
    }
    expected = np.arange(1, 232192, dtype=np.int32)
    observed_hashes = []
    for index, row in enumerate(payload["candidate_manifest"]):
        order = np.asarray(matrix[index])
        assert np.array_equal(np.sort(order), expected)
        digest = MODULE._sha256(order.astype("<u4", copy=False).tobytes())
        assert digest == row["order_sha256"]
        observed_hashes.append(digest)
    assert len(set(observed_hashes)) == 12


def test_a207_preflight_candidate_manifest_and_a206_row_are_exact() -> None:
    payload = json.loads(METADATA_PATH.read_bytes())
    manifest = payload["candidate_manifest"]
    assert [row["candidate"] for row in manifest] == list(MODULE.CANDIDATE_ORDER)
    assert [row["calibrated_solver_mode"] for row in manifest] == [
        MODULE.CALIBRATED_MODES[name] for name in MODULE.CANDIDATE_ORDER
    ]
    assert len({row["representative_transformed_cnf_sha256"] for row in manifest}) == 12
    assert all(row["inverse_byte_identical"] is True for row in manifest)
    assert all(
        row["inverse_restored_sha256"]
        == "a9cd80dc9e7934f3c29681a78e4d734d598205e81b9796e9413b78be85e4fa2b"
        for row in manifest
    )
    bidirectional = next(
        row for row in manifest if row["candidate"] == "bidirectional_min_distance"
    )
    assert bidirectional["order_sha256"] == (
        "c019beaea6888a5db16c3805922752c273aacd5a70498df1119edb21535db8d3"
    )
    assert bidirectional["old_to_new_sha256"] == (
        "8568c89883908e5eadead20533c700c4a6a37d7ac9968de5ea939f66f2012702"
    )
    assert bidirectional["representative_transformed_cnf_sha256"] == (
        "65809b9b8bf1698195ec6b82b395f49242ec7ea6997c0966ccfaa8d69ae44bca"
    )
    assert MODULE._canonical_sha256(manifest) == CANDIDATE_MANIFEST_SHA256


def test_a207_preflight_component_aware_spectral_definition_is_exact() -> None:
    payload = json.loads(METADATA_PATH.read_bytes())
    spectral = payload["spectral"]
    assert spectral["component_count"] == 2
    assert spectral["component_sizes_descending"] == [232190, 1]
    assert spectral["main_component_vertices"] == 232190
    assert spectral["appended_vertex_ids"] == [1]
    assert spectral["eigenvalues"] == [
        -1.614397135473436e-17,
        0.0008174153437568085,
    ]
    assert spectral["residual"] == 8.112956634006554e-09
    assert spectral["orientation_dot"] == 0.006250226258183958
    assert spectral["orientation_dot"] > 0
    assert payload["spectral_sha256"] == (
        "abb899c24c55c1b4d1ac47895a14c78a458db4d27544370468732f5b747fdbe3"
    )


def test_a207_preflight_information_boundary_and_native_reader_are_exact() -> None:
    payload = json.loads(METADATA_PATH.read_bytes())
    boundary = payload["information_boundary"]
    assert boundary["A205_and_A206_outcomes_known_before_archive_derivation"] is True
    assert (
        boundary["any_A207_remaining_portfolio_solver_outcome_known_before_archive_derivation"]
        is False
    )
    assert boundary["round10_unknown_assignment_in_source_or_archive"] is False
    assert boundary["round10_unknown_assignment_available_to_archive_runner"] is False
    assert boundary["external_CaDiCaL_A207_execution_started"] is False

    reader = MODULE.CryptoCausalReader(CAUSAL_PATH)
    assert reader.file_sha256 == CAUSAL_SHA256
    assert reader.graph_sha256 == CAUSAL_GRAPH_SHA256
    assert reader.verify_provenance() is True
    rows = reader.triplets(include_inferred=False)
    by_id = {row["edge_id"]: row for row in rows}
    ids = [
        "chacha20-a207-preflight-a205-portfolio",
        "chacha20-a207-preflight-a206-boundary",
        "chacha20-a207-preflight-structural-orders",
        "chacha20-a207-preflight-exact-archive",
    ]
    assert len(rows) == 4
    assert set(by_id) == set(ids)
    assert [by_id[edge_id]["provenance"] for edge_id in ids] == [
        [],
        [ids[0]],
        [ids[1]],
        [ids[2]],
    ]
    assert all(
        by_id[left]["outcome"] == by_id[right]["trigger"]
        for left, right in zip(ids[:-1], ids[1:], strict=True)
    )

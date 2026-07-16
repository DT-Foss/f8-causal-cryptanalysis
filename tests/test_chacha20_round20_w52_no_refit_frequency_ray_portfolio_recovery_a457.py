from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).parents[1]
RUNNER = (
    ROOT
    / "research/experiments/chacha20_round20_w52_no_refit_frequency_ray_portfolio_recovery_a457.py"
)


def load_runner():
    spec = importlib.util.spec_from_file_location("a457_test_runner", RUNNER)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="module")
def a457():
    return load_runner()


def test_import_is_light_and_runtime_engine_is_lazy(a457) -> None:
    assert a457._A435 is None
    assert a457.PAIR_CELLS == 1 << 24
    assert a457.CELL_ASSIGNMENTS == 1 << 28
    assert a457.DOMAIN_ASSIGNMENTS == 1 << 52


def test_design_source_stream_and_public_challenge_are_exact(a457) -> None:
    design = a457.load_design()
    source, stream, unused = a457.load_source_schedule()
    protocol, challenge = a457.load_public_challenge()
    assert design["attempt_id"] == "A457"
    assert source["calibration"]["selected_pattern"] == "BOOOOOOHHHHHH"
    assert source["stream"]["artifact"]["complete_permutation"] is True
    assert source["hard_rank_guarantee"]["all_bounds_satisfied"] is True
    assert source["W52_target_labels_used"] == 0
    assert source["feature_refits"] == 0
    assert source["model_refits"] == 0
    assert source["W52_candidate_assignments_executed"] == 0
    assert (
        source[
            "A426_A438_A440_A443_A450_A452_A455_secret_result_or_worker_progress_read"
        ]
        is False
    )
    assert len(stream) == 1 << 24
    assert unused == ()
    artifact = source["stream"]["artifact"]
    assert stream.pair_at(0) == tuple(artifact["first_pair"])
    assert stream.pair_at(a457.PAIR_CELLS - 1) == tuple(artifact["last_pair"])
    assert protocol["public_challenge_sha256"] == a457.PUBLIC_CHALLENGE_SHA256
    assert challenge["unknown_assignment_included"] is False
    boundary = design["information_boundary"]
    assert boundary["A455_candidate_progress_or_result_read"] is False
    assert (
        boundary[
            "A426_A438_A440_A443_A450_A452_secret_result_stop_or_worker_progress_read"
        ]
        is False
    )


def test_worker_modulo_partition_reads_exact_nonfactorized_stream(a457) -> None:
    _source, stream, unused = a457.load_source_schedule()
    observed: list[int] = []
    for step in range(8):
        for worker in range(a457.WORKERS):
            global_index, left, right = a457.worker_pair_at(
                worker, step, stream, unused
            )
            observed.append(global_index)
            assert (left, right) == stream.pair_at(global_index)
    assert sorted(observed) == list(range(64))
    first = a457.worker_pair_at(0, 0, stream, unused)
    last = a457.worker_pair_at(
        7, a457.WORKER_TASKS - 1, stream, unused
    )
    assert first == (0, *stream.pair_at(0))
    assert last == (
        a457.PAIR_CELLS - 1,
        *stream.pair_at(a457.PAIR_CELLS - 1),
    )


def test_pair_stream_inverse_is_exact_for_committed_first_pair(a457) -> None:
    _source, stream, unused = a457.load_source_schedule()
    prefix, off_axis = stream.pair_at(0)
    assert a457.pair_global_index(prefix, off_axis, stream, unused) == 0


def test_protocol_is_bound_and_target_blind_when_present(a457) -> None:
    if not a457.PROTOCOL.exists():
        pytest.skip("A457 protocol has not been frozen yet")
    value = a457.load_protocol(a457.file_sha256(a457.PROTOCOL))
    assert value["schedule"]["algorithm"] == (
        "A456_BOOOOOOHHHHHH_deduplicated_periodic_weighted_first_encounter_pair_stream"
    )
    assert value["schedule"]["selected_pattern"] == "BOOOOOOHHHHHH"
    assert (
        value["schedule"]["pair_stream_sha256"]
        == a457.A456_PAIR_STREAM_SHA256
    )
    assert value["schedule"]["pair_cells"] == 1 << 24
    assert value["candidate_assignments_executed"] == 0
    assert value["production_execution_enabled"] is False
    boundary = value["information_boundary"]
    assert boundary["A455_candidate_progress_or_result_read"] is False
    assert boundary["A457_target_labels_used_for_schedule"] == 0
    assert boundary["A457_feature_refits"] == 0
    assert boundary["A457_model_refits"] == 0


def test_progress_fingerprint_rejects_wrong_stream(a457, tmp_path, monkeypatch) -> None:
    path = tmp_path / "progress.json"
    path.write_text(
        json.dumps(
            {
                "schema": "chacha20-round20-w52-no-refit-frequency-ray-portfolio-recovery-a457-progress-v1",
                "attempt_id": "A457",
                "worker_index": 0,
                "worker_role": "frequency_ray_wave_0",
                "protocol_sha256": "p",
                "A434_qualification_sha256": "q",
                "A456_result_commitment_sha256": "wrong",
                "matched_control_candidates": 0,
                "status": "running",
                "executed_worker_pair_cells": 0,
                "factual_filter_candidates": 0,
            }
        )
    )
    monkeypatch.setattr(a457, "progress_path", lambda _index: path)
    with pytest.raises(RuntimeError, match="fingerprint"):
        a457.load_resume(
            worker_index=0, protocol_sha256="p", qualification_sha256="q"
        )


def test_result_and_authentic_causal_reopen_when_present(a457) -> None:
    if not a457.RESULT.exists():
        pytest.skip("A457 result has not been produced yet")
    value = json.loads(a457.RESULT.read_bytes())
    assert value["factual_candidates"] == 1
    assert value["matched_control_candidates"] == 0
    assert value["all_8192_cross_implementation_output_bits_match"] is True
    assert value["A455_candidate_progress_or_result_read"] is False
    if str(a457.DOTCAUSAL_SRC) not in sys.path:
        sys.path.insert(0, str(a457.DOTCAUSAL_SRC))
    from dotcausal.io import CausalReader

    reader = CausalReader(str(a457.CAUSAL), verify_integrity=True)
    assert reader.api_id == "a457rec"
    assert len(reader.get_all_triplets(include_inferred=False)) == 2
    assert len(reader.get_all_triplets(include_inferred=True)) == 3
    assert len(reader._rules) == 2
    assert len(reader._clusters) == 1
    assert len(reader._gaps) == 1

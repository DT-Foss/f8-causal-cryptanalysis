from __future__ import annotations

import hashlib
import importlib.util
import json
import sys
from pathlib import Path
from types import SimpleNamespace

import numpy as np
import pytest

ROOT = Path(__file__).parents[1]
RUNNER = (
    ROOT / "research/experiments/chacha20_round20_selected_channel_target_replication_recovery.py"
)
PREFLIGHT = (
    ROOT
    / "research/experiments/chacha20_round20_selected_channel_target_replication_recovery_preflight.py"
)
PUBLIC_CORE = ROOT / "research/experiments/chacha20_round20_public_core.py"
A220_PROTOCOL = ROOT / "research/configs/chacha20_round20_factorial_trajectory_transfer_v1.json"


def _load(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _canonical_sha256(value) -> str:
    return _sha256(
        json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        ).encode("ascii")
    )


def _install_a275_fixture(monkeypatch: pytest.MonkeyPatch, tmp_path: Path):
    module = _load(PREFLIGHT, f"a276_preflight_fixture_{tmp_path.name}")
    monkeypatch.setattr(module, "ROOT", tmp_path)
    paths = {
        "protocol": tmp_path / "a275_protocol.json",
        "result": tmp_path / "a275_result.json",
        "causal": tmp_path / "a275_result.causal",
        "runner": tmp_path / "a275_runner.py",
        "measurement": tmp_path / "measurement.json.zst",
    }
    paths["runner"].write_text("# hash-anchored fake A275 runner\n")
    paths["measurement"].write_bytes(b"canonical semantic measurement fixture")
    paths["causal"].write_bytes(b"authentic causal fixture")
    protocol = {
        "schema": "chacha20-round20-selected-channel-target-replication-protocol-v1",
        "protocol_state": "frozen-A275-fixture",
        "target": {
            "public_challenge_sha256": "1" * 64,
            "target_block_sha256": ["2" * 64] * 8,
        },
        "selected_hypothesis": {"feature_indices": [0, 1]},
        "anchors": {
            "A272_result_sha256": "3" * 64,
            "A274_result_sha256": "4" * 64,
        },
        "information_boundary": {
            "target_generation_label_stored_in_protocol_result_Causal_or_report": False
        },
    }
    paths["protocol"].write_text(json.dumps(protocol))
    monkeypatch.setattr(module, "A275_PROTOCOL", paths["protocol"])
    monkeypatch.setattr(module, "A275_RESULT", paths["result"])
    monkeypatch.setattr(module, "A275_CAUSAL", paths["causal"])
    monkeypatch.setattr(module, "A275_RUNNER", paths["runner"])
    monkeypatch.setattr(module, "A275_PROTOCOL_SHA256", _sha256(paths["protocol"].read_bytes()))
    monkeypatch.setattr(module, "A275_RUNNER_SHA256", _sha256(paths["runner"].read_bytes()))

    matrix = np.zeros((256, 2), dtype=np.float64)
    matrix[:, 0] = np.arange(256, dtype=np.float64)
    model = SimpleNamespace(
        means=np.zeros(2, dtype=np.float64),
        scales=np.ones(2, dtype=np.float64),
        coefficients=np.ones(2, dtype=np.float64),
    )
    measurement = {
        "order_name": "numeric",
        "public_target_block_sha256": protocol["target"]["target_block_sha256"],
        "target_label_available_to_measurement": False,
        "label_used_for_feature_construction_or_scoring": False,
        "run": {
            "summary": {
                "learned_clause_accepted_total": 12,
                "learned_clause_rejected_large_total": 3,
            }
        },
    }
    measurement_ledger = {
        "path": paths["measurement"].name,
        "raw_bytes": 99,
        "raw_sha256": "5" * 64,
        "compressed_bytes": len(paths["measurement"].read_bytes()),
        "compressed_sha256": _sha256(paths["measurement"].read_bytes()),
        "resumed": True,
    }

    def standardized_contributions(values, *, means, scales, coefficients):
        return ((values - means) / scales) * coefficients

    def candidate_order(scores):
        return sorted(range(256), key=lambda value: (-float(scores[value]), value))

    fake_runner = SimpleNamespace(
        _load_protocol=lambda *_args, **_kwargs: (
            protocol,
            None,
            None,
            None,
            None,
            None,
            model,
            (0, 1),
        ),
        _read_measurement=lambda *_args, **_kwargs: (measurement, measurement_ledger),
        _target_feature_matrix=lambda _measurement: matrix,
        standardized_contributions=standardized_contributions,
        _candidate_order=candidate_order,
        _canonical_sha256=_canonical_sha256,
        _assert_secret_free=lambda _value: None,
    )
    monkeypatch.setattr(module, "_import_path", lambda *_args, **_kwargs: fake_runner)

    scores = standardized_contributions(
        matrix,
        means=model.means,
        scales=model.scales,
        coefficients=model.coefficients,
    )[:, (0, 1)].sum(axis=1)
    order = candidate_order(scores)
    top128 = order[:128]
    analysis = {
        "score_field": scores.tolist(),
        "score_field_sha256": _canonical_sha256(scores.tolist()),
        "complete_cell_order": order,
        "complete_cell_order_uint8_sha256": _sha256(bytes(order)),
        "top128_cell_order": top128,
        "top128_cell_order_uint8_sha256": _sha256(bytes(top128)),
        "order_tiebreak": "descending_score_then_ascending_candidate",
        "selected_feature_indices": [0, 1],
        "model_refits": 0,
        "target_labels_used": 0,
    }
    headline = {
        "complete_candidate_cells": 256,
        "complete_order_uint8_sha256": analysis["complete_cell_order_uint8_sha256"],
        "top128_order_uint8_sha256": analysis["top128_cell_order_uint8_sha256"],
        "top128_assignment_bits": 19,
        "target_label_available": False,
    }
    explicit = [
        {
            "source": protocol["anchors"]["A274_result_sha256"],
            "outcome": "A275:target_blind_reader_contract",
        },
        {
            "source": _canonical_sha256(analysis),
            "outcome": "A275:hash_frozen_target_candidate_order",
            "evidence": json.dumps(headline, sort_keys=True),
        },
    ]
    terminal = {
        "source": "materialized:A274_confirmation_plus_A275_complete_target_cover",
        "outcome": "A275:hash_frozen_target_candidate_order",
        "is_inferred": True,
    }
    gap = {"expected_object_type": "hash_frozen_top128_retained_state_replication_recovery"}

    class FakeReader:
        version = 1
        api_id = "a275"
        _triplets = [*explicit, terminal]
        _rules = [{}, {}]
        _clusters = [{}]
        _gaps = [gap]

        def get_all_triplets(self, *, include_inferred):
            return [*explicit, terminal] if include_inferred else explicit

    monkeypatch.setattr(
        module,
        "_load_dotcausal",
        lambda: SimpleNamespace(CausalReader=lambda *_args, **_kwargs: FakeReader()),
    )
    result = {
        "schema": "chacha20-round20-selected-channel-target-replication-order-result-v1",
        "evidence_stage": "FULLROUND_R20_TARGET_BLIND_SELECTED_CHANNEL_REPLICATION_ORDER_FROZEN",
        "protocol_sha256": module.A275_PROTOCOL_SHA256,
        "protocol_state": protocol["protocol_state"],
        "runner_sha256": module.A275_RUNNER_SHA256,
        "public_challenge_sha256": protocol["target"]["public_challenge_sha256"],
        "A272_result_sha256": protocol["anchors"]["A272_result_sha256"],
        "A274_result_sha256": protocol["anchors"]["A274_result_sha256"],
        "selected_hypothesis": protocol["selected_hypothesis"],
        "measurement": {
            **measurement_ledger,
            "complete_candidate_cover": True,
            "accepted_learned_clauses": 12,
            "rejected_over_64_literal_clauses": 3,
        },
        "analysis": analysis,
        "analysis_sha256": _canonical_sha256(analysis),
        "headline": headline,
        "information_boundary": protocol["information_boundary"],
        "causal": {
            "file_sha256": _sha256(paths["causal"].read_bytes()),
            "format": "authentic_dotcausal_v1_AI_native",
            "integrity_verified_by_authoritative_reader": True,
            "api_id": "a275",
            "explicit_triplets": 2,
            "materialized_inferred_triplets": 1,
            "embedded_rules": 2,
            "clusters": 1,
            "gaps": 1,
            "personal_semantic_readback": {
                "terminal_chain": terminal,
                "next_gap": gap,
            },
        },
    }
    paths["result"].write_text(json.dumps(result))
    return module, paths, protocol, result, order


def test_a276_decode_model_uses_bit0_through_bit19_order() -> None:
    module = _load(RUNNER, "a276_decode_test")
    bits = [0] * 20
    bits[0] = 1
    bits[7] = 1
    bits[19] = 1
    assert module._decode_model(bits) == (1 | (1 << 7) | (1 << 19))


def test_a276_evidence_stage_marks_replication() -> None:
    module = _load(RUNNER, "a276_stage_test")
    boundary = module._evidence_stage(confirmation=None, attempted=128)
    confirmed = module._evidence_stage(confirmation={"ok": True}, attempted=40)
    assert "REPLICATION_RECOVERY_BOUNDARY" in boundary
    assert "TOP64" in confirmed
    assert "REPLICATION_RECOVERY_CONFIRMED" in confirmed


def test_a276_dual_confirmation_checks_all_eight_standard_blocks() -> None:
    module = _load(RUNNER, "a276_confirmation_test")
    public = _load(PUBLIC_CORE, "a276_public_test")
    template = json.loads(A220_PROTOCOL.read_bytes())["public_only_R20_material"]
    low20 = 0x5A19C
    challenge = public.build_known_challenge(template, low20=low20)
    confirmation = module._confirm(public, challenge, low20)
    assert confirmation["all_blocks_match"] is True
    assert confirmation["all_cross_implementation_blocks_match"] is True
    assert confirmation["output_bits_checked"] == 4096
    assert confirmation["control_first_block_match"] is False


def test_a276_preflight_recomputes_a275_measurement_score_and_order(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    module, paths, _protocol, result, order = _install_a275_fixture(monkeypatch, tmp_path)
    assert module._validate_a275()[2] == order

    forged = order.copy()
    forged[0], forged[1] = forged[1], forged[0]
    result["analysis"]["complete_cell_order"] = forged
    result["analysis"]["complete_cell_order_uint8_sha256"] = _sha256(bytes(forged))
    result["analysis"]["top128_cell_order"] = forged[:128]
    result["analysis"]["top128_cell_order_uint8_sha256"] = _sha256(bytes(forged[:128]))
    result["analysis_sha256"] = _canonical_sha256(result["analysis"])
    result["headline"]["complete_order_uint8_sha256"] = result["analysis"][
        "complete_cell_order_uint8_sha256"
    ]
    result["headline"]["top128_order_uint8_sha256"] = result["analysis"][
        "top128_cell_order_uint8_sha256"
    ]
    paths["result"].write_text(json.dumps(result))
    with pytest.raises(RuntimeError, match="recomputed A275 score or order"):
        module._validate_a275()


def test_a276_preflight_authenticates_complete_causal_chain(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    module, paths, _protocol, result, _order = _install_a275_fixture(monkeypatch, tmp_path)
    result["causal"]["personal_semantic_readback"]["terminal_chain"]["source"] = "unbound-analysis"
    paths["result"].write_text(json.dumps(result))
    with pytest.raises(RuntimeError, match="personal A275 Causal readback"):
        module._validate_a275()


def test_a276_read_only_verifier_binds_recomputed_a275_order(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    module, paths, a275_protocol, _result, order = _install_a275_fixture(monkeypatch, tmp_path)
    top128 = order[:128]
    dependency_specs = [
        ("PUBLIC_CORE", "PUBLIC_CORE_SHA256", "public_core.py"),
        ("TEMPLATE_PROTOCOL", "TEMPLATE_PROTOCOL_SHA256", "template_protocol.json"),
        ("TEMPLATE", "TEMPLATE_SHA256", "template.py"),
        ("RANKED_WRAPPER", "RANKED_WRAPPER_SHA256", "ranked.py"),
        ("RANKED_SOURCE", "RANKED_SOURCE_SHA256", "ranked.cpp"),
        ("INDEPENDENT_REFERENCE", "INDEPENDENT_REFERENCE_SHA256", "independent.py"),
    ]
    dependency_paths: dict[str, Path] = {}
    for path_name, hash_name, filename in dependency_specs:
        path = tmp_path / filename
        path.write_text(filename + "\n")
        monkeypatch.setattr(module, path_name, path)
        monkeypatch.setattr(module, hash_name, _sha256(path.read_bytes()))
        dependency_paths[path_name] = path

    recovery_runner = tmp_path / "a276_recovery.py"
    recovery_runner.write_text("# frozen A276 recovery runner\n")
    monkeypatch.setattr(module, "RUNNER", recovery_runner)
    ranked_binary = tmp_path / "cadical_ranked_until_sat"
    ranked_binary.write_bytes(b"frozen-ranked-binary")
    protocol = {
        "schema": "chacha20-round20-selected-channel-target-replication-recovery-protocol-v1",
        "attempt_id": "A276",
        "protocol_state": "frozen_after_complete_A275_unlabeled_target_order_and_before_any_A276_ranked_solver_execution_model_or_confirmation",
        "anchors": {
            "A275_protocol_path": paths["protocol"].name,
            "A275_protocol_sha256": _sha256(paths["protocol"].read_bytes()),
            "A275_result_path": paths["result"].name,
            "A275_result_sha256": _sha256(paths["result"].read_bytes()),
            "A275_causal_path": paths["causal"].name,
            "A275_causal_sha256": _sha256(paths["causal"].read_bytes()),
            "A275_measurement_path": paths["measurement"].name,
            "A275_measurement_sha256": _sha256(paths["measurement"].read_bytes()),
            "A275_runner_path": paths["runner"].name,
            "A275_runner_sha256": _sha256(paths["runner"].read_bytes()),
            "public_core_path": dependency_paths["PUBLIC_CORE"].name,
            "public_core_sha256": _sha256(dependency_paths["PUBLIC_CORE"].read_bytes()),
            "symbolic_template_protocol_path": dependency_paths["TEMPLATE_PROTOCOL"].name,
            "symbolic_template_protocol_sha256": _sha256(
                dependency_paths["TEMPLATE_PROTOCOL"].read_bytes()
            ),
            "symbolic_template_path": dependency_paths["TEMPLATE"].name,
            "symbolic_template_sha256": _sha256(dependency_paths["TEMPLATE"].read_bytes()),
            "ranked_helper_wrapper_path": dependency_paths["RANKED_WRAPPER"].name,
            "ranked_helper_wrapper_sha256": _sha256(
                dependency_paths["RANKED_WRAPPER"].read_bytes()
            ),
            "ranked_helper_source_path": dependency_paths["RANKED_SOURCE"].name,
            "ranked_helper_source_sha256": _sha256(dependency_paths["RANKED_SOURCE"].read_bytes()),
            "ranked_helper_binary_path": ranked_binary.name,
            "ranked_helper_binary_sha256": _sha256(ranked_binary.read_bytes()),
            "independent_reference_path": dependency_paths["INDEPENDENT_REFERENCE"].name,
            "independent_reference_sha256": _sha256(
                dependency_paths["INDEPENDENT_REFERENCE"].read_bytes()
            ),
            "runner_path": recovery_runner.name,
            "runner_sha256": _sha256(recovery_runner.read_bytes()),
        },
        "target": {
            "public_challenge_sha256": a275_protocol["target"]["public_challenge_sha256"],
            "target_block_sha256": a275_protocol["target"]["target_block_sha256"],
            "replication_index": 2,
            "generation_label_available": False,
        },
        "frozen_reader_order": {
            "source_attempt": "A275",
            "complete_cell_order": order,
            "complete_cell_order_uint8_sha256": _sha256(bytes(order)),
            "top128_cell_order": top128,
            "top128_cell_order_uint8_sha256": _sha256(bytes(top128)),
            "order_change_permitted": False,
            "correct_prefix_or_rank_known": False,
        },
        "solver_protocol": {
            "formula": "target_independent_symbolic_R20_base_plus_512_public_output_units",
            "state_retention": "one_CaDiCaL_instance_across_ordered_prefix_cells",
            "seconds_per_cell": 30.0,
            "maximum_cells": 128,
            "maximum_logical_assignments": 2**19,
            "full_residual_domain_assignments": 2**20,
            "stop_condition": "first_SAT_only",
            "unknown_semantics": "per_cell_time_horizon_exhausted_not_UNSAT",
            "external_timeout_seconds": 4200.0,
        },
        "claim_gate": {
            "SAT_model_required": True,
            "all_eight_standard_R20_blocks_must_match": True,
            "independent_RFC8439_implementation_must_match": True,
            "flipped_first_block_control_must_reject": True,
            "output_bits_confirmed": 4096,
            "strictly_fewer_than_full_2pow20_prefix_suffix_assignments_required": True,
        },
        "information_boundary": {
            "target_generation_label_available_before_or_during_execution": False,
            "correct_prefix_or_A275_target_rank_known_before_execution": False,
            "A275_order_may_not_change_after_freeze": True,
            "A275_measurement_was_complete_model_free_and_unlabeled": True,
            "recovery_stops_only_on_first_SAT": True,
            "confirmation_occurs_only_after_solver_model": True,
        },
    }
    frozen = tmp_path / "a276.json"
    frozen.write_text(json.dumps(protocol))
    digest = _sha256(frozen.read_bytes())
    verified = module.verify_frozen_protocol(frozen, digest)
    assert verified["authenticated_without_solver_execution"] is True
    assert verified["maximum_cells"] == 128
    assert verified["top128_order_sha256"] == _sha256(bytes(top128))

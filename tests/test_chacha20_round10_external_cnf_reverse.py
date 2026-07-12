from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path
from typing import Any

import pytest

ROOT = Path(__file__).parents[1]
MODULE_PATH = ROOT / "research" / "experiments" / "chacha20_round10_external_cnf_reverse.py"
SPEC = importlib.util.spec_from_file_location(
    "chacha20_round10_external_cnf_reverse_tested", MODULE_PATH
)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)

RESULTS = ROOT / "research" / "results" / "v1"
PROTOCOL_PATH = ROOT / "research" / "configs" / MODULE.PROTOCOL_FILENAME
RUNNER_SHA256 = "1037ca70c74295da053ce31774ac8b74e75be48e1a994493e344984b97c6f20b"
RESULT_PATH = RESULTS / MODULE.RESULT_FILENAME
CAUSAL_PATH = RESULTS / MODULE.CAUSAL_FILENAME
RESULT_SHA256 = "603eaf8a2a6bb85c3c4bb2fdf4b7466205ffd1d8005593d987c8a6461b7c8c22"
CAUSAL_SHA256 = "f1ca39f964640d8aa2a5c6f6dab9bcfb48dfaddf6dda2e399275f77235ca71c3"
CAUSAL_GRAPH_SHA256 = "0cbdde4c25a7c804706a9e8b9823c71ec9bc74046191526cae4a7a55b5dbdc73"
CALIBRATION_SHA256 = "8f2fee7ae492bcc1a7dcf59c6d4af4629313e420c4b9a998799c68b16b1349a9"
CALIBRATION_REPLAY_SHA256 = "8fc9549d74444ebf7bafcca7fa664f342c8be8a4c52848d2d8f8bf67186cd503"
MAPPING_SHA256 = "f5f939f41d00365ea557514a9b6ffe08b4167156b49f9e4defa408f3789b7ad6"
MAPPING_REPLAY_SHA256 = "ba965bca228e8cf1e187274af2e272e9c2b7c8fb620e6928dbf384308f045e81"
CNF_EXPORT_SHA256 = "91ee0375eb1579017c9d536981263cf180f8dbed1369115a078980a0867c09de"
EXECUTION_PLAN_SHA256 = "606c49926ef76f9a729cb4845230c9c96349fda10408f8870e9ecd8d8987ef68"
EXECUTION_SHA256 = "916eec2fdd671a8109f50b97be780bd1b150a63201ea537e282f9be062238b4c"
CONFIRMATION_SHA256 = "4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945"
COMPARISON_SHA256 = "6ad19f46a1fde4036ced9c2ce62e59c951f4882ce579f9024dd12390a6d62728"


@pytest.fixture(scope="module")
def analysis() -> dict[str, Any]:
    return MODULE.analyze(RESULTS)


def test_a204_protocol_runner_and_retained_anchor_chain_are_exact(
    analysis: dict[str, Any],
) -> None:
    protocol = analysis["protocol"]
    assert MODULE._file_sha256(PROTOCOL_PATH) == MODULE.PROTOCOL_SHA256
    assert MODULE._file_sha256(MODULE_PATH) == RUNNER_SHA256
    assert protocol["protocol_state"] == (
        "frozen_after_A188_external_CNF_solver_calibration_and_A202_CNF_structure_mapping_"
        "before_any_A204_round10_solver_execution"
    )
    assert analysis["anchor_gates"]["A188_full_40bit_recovery_confirmation_retained"] is True
    assert analysis["anchor_gates"]["A202_A203_complete_round10_covers_all_unknown"] is True
    assert analysis["public_challenge"]["unknown_assignment_included"] is False
    assert analysis["public_challenge"]["unknown_key_word0_low_value_included"] is False
    assert analysis["solver_execution_started"] is False


def test_a204_unique_external_calibration_selector_and_model_are_frozen(
    analysis: dict[str, Any],
) -> None:
    calibration = analysis["protocol"]["A188_external_cnf_calibration"]
    assert calibration["tested_configuration_count"] == 26
    assert len(calibration["outcomes"]) == 26
    assert [
        row["variant"] for row in calibration["outcomes"] if row["status_at_5000ms"] == "sat"
    ] == ["cadical_reverse"]
    assert calibration["recovered_model"] == {
        "key_word0": 1163416835,
        "key_word0_hex": "0x45585503",
        "key_word1_low_value": 83,
        "key_word1_low_hex": "0x53",
        "combined_assignment": 357645702403,
    }
    assert calibration["confirmation"] == {
        "all_blocks_match": True,
        "block_count_checked": 8,
        "output_bits_checked": 4096,
        "control_first_block_match": False,
    }
    assert calibration["cnf_sha256"] == (
        "a49e7ec1ea7135b760d732855fe05b91ac85c56cf786e0777bb9a2188d6a3216"
    )


def test_a204_complete_round10_cnf_cover_and_prefix_units_are_exact(
    analysis: dict[str, Any],
) -> None:
    freeze = analysis["protocol"]["A202_round10_cnf_freeze"]
    rows = freeze["per_cell_manifest"]
    assert [row["variant"] for row in rows] == list(MODULE.VARIANTS)
    assert [row["prefix"] for row in rows] == list(MODULE.PREFIXES)
    assert len({row["sha256"] for row in rows}) == 32
    assert {row["header"] for row in rows} == {"p cnf 232191 734180"}
    assert {row["normalized_sha256"] for row in rows} == {
        "a9cd80dc9e7934f3c29681a78e4d734d598205e81b9796e9413b78be85e4fa2b"
    }
    assert sum(1 << MODULE.FREE_BITS for _ in rows) == 1 << MODULE.UNKNOWN_KEY_BITS
    for row in rows:
        assert [abs(literal) for literal in row["tail_units"]] == [44, 46, 48, 57, 50]
        encoded = [int(bit) for bit in row["prefix"]]
        assert [int(literal > 0) for literal in row["tail_units"]] == [
            encoded[4],
            encoded[3],
            encoded[2],
            encoded[0],
            encoded[1],
        ]


def test_a204_literal_maps_decode_without_any_solver_adaptation(
    analysis: dict[str, Any],
) -> None:
    protocol = analysis["protocol"]
    a188_mapping = protocol["A188_external_cnf_calibration"]["key_bit_one_literal_mapping"]
    round10_mapping = protocol["A202_round10_cnf_freeze"]["free_k0_bit_one_literal_mapping"]
    assert len(a188_mapping["k0"]) == 32
    assert len(a188_mapping["lo8"]) == 8
    assert len(round10_mapping) == MODULE.FREE_BITS
    assert len(set([*a188_mapping["k0"], *a188_mapping["lo8"]])) == 40
    assert len(set(round10_mapping)) == MODULE.FREE_BITS

    expected = 0x53A5
    values = {
        abs(literal): int(bool(expected & (1 << bit)))
        for bit, literal in enumerate(round10_mapping)
    }
    assert MODULE._decode_literals(values, round10_mapping) == expected


def test_a204_cnf_normalizer_changes_only_five_unit_signs() -> None:
    raw = b"p cnf 8 7\n1 -2 0\n-4 0\n5 0\n-6 0\n7 0\n-8 0\n"
    header, units, normalized_sha256 = MODULE._normalized_cnf(raw)
    assert header == "p cnf 8 7"
    assert units == [-4, 5, -6, 7, -8]
    expected = b"p cnf 8 7\n1 -2 0\n4 0\n5 0\n6 0\n7 0\n8 0\n"
    assert normalized_sha256 == MODULE._sha256(expected)


def test_a204_all_frozen_solver_binary_identities_are_available(
    analysis: dict[str, Any],
) -> None:
    identities = MODULE._solver_gates(analysis["protocol"])
    assert set(identities) == {"bitwuzla", "cadical", "kissat", "cryptominisat5", "minisat"}
    assert identities["bitwuzla"]["version"] == "0.9.1"
    assert identities["cadical"]["version"] == "3.0.0"


def test_a204_full_calibration_commands_and_timeout_parsers_are_explicit(
    analysis: dict[str, Any], tmp_path: Path
) -> None:
    identities = MODULE._solver_gates(analysis["protocol"])
    specs = MODULE._calibration_specs(identities, tmp_path / "A188.cnf", tmp_path)
    expected = [
        row["variant"] for row in analysis["protocol"]["A188_external_cnf_calibration"]["outcomes"]
    ]
    assert [row["variant"] for row in specs] == expected
    assert len(specs) == 26
    assert len({tuple(row["command"]) for row in specs}) == 26
    selected = next(row for row in specs if row["variant"] == "cadical_reverse")
    assert "--reverse=true" in selected["command"]
    assert MODULE._as_text(b"unknown\n") == "unknown\n"
    assert MODULE._as_text(None) == ""
    assert MODULE._cadical_status("s SATISFIABLE\n", 10) == "sat"
    assert MODULE._cadical_status("s UNSATISFIABLE\n", 20) == "unsat"
    assert MODULE._cadical_status("s UNKNOWN\n", 0) == "unknown"
    assert MODULE._cadical_status("s SATISFIABLE\n", 0) == "invalid"
    assert MODULE._cadical_status("s SATISFIABLE\ns UNSATISFIABLE\n", 10) == "invalid"
    assert MODULE._cadical_status("", 0) == "invalid"
    assert MODULE._cadical_status("", None) == "invalid"
    assert MODULE._cadical_status("c Timeout reached!\n", 0) == "unknown"
    assert MODULE._kissat_status("", 0) == "invalid"
    assert MODULE._kissat_status("c ---- [ shutting down ]\nc exit 0\n", 0) == "unknown"


def test_a204_retained_calibration_replay_is_exact_and_fully_confirmed() -> None:
    payload = json.loads(RESULT_PATH.read_bytes())
    assert MODULE._file_sha256(RESULT_PATH) == RESULT_SHA256
    assert MODULE._file_sha256(CAUSAL_PATH) == CAUSAL_SHA256
    assert payload["schema"] == MODULE.SCHEMA
    assert payload["attempt_id"] == "A204"
    assert payload["evidence_stage"] == "ROUND10_EXTERNAL_CNF_COMPLETE_PARTITION_BOUNDARY_RETAINED"
    assert payload["calibration_sha256"] == CALIBRATION_SHA256
    assert payload["calibration_replay_sha256"] == CALIBRATION_REPLAY_SHA256
    assert payload["mapping_sha256"] == MAPPING_SHA256
    assert payload["mapping_replay_sha256"] == MAPPING_REPLAY_SHA256
    replay = payload["calibration_replay"]
    assert replay["retained"] is True
    assert replay["frozen_outcomes_match"] is True
    assert replay["export"]["sha256"] == (
        "a49e7ec1ea7135b760d732855fe05b91ac85c56cf786e0777bb9a2188d6a3216"
    )
    assert replay["export"]["header"] == "p cnf 96859 310088"
    observations = replay["observations"]
    assert len(observations) == 26
    assert [row["variant"] for row in observations] == [
        row["variant"] for row in payload["calibration"]["outcomes"]
    ]
    assert [row["status"] for row in observations].count("sat") == 1
    assert [row["status"] for row in observations].count("unknown") == 25
    assert all(row["externally_timed_out"] is False for row in observations)
    assert len({tuple(row["command"]) for row in observations}) == 26
    selected = replay["selected_observation"]
    assert selected["variant"] == "cadical_reverse"
    assert selected["status"] == "sat"
    assert selected["returncode"] == 10
    assert selected["externally_timed_out"] is False
    assert selected["witness_assignment_count"] == 96859
    replicates = replay["selected_replicates"]
    assert [row["replicate_index"] for row in replicates] == [0, 1, 2]
    assert [row["status"] for row in replicates] == ["unknown", "sat", "unknown"]
    assert replay["selected_sat_replicate_count"] == 1
    assert len(replay["selected_confirmed_replicates"]) == 1
    assert all(row["externally_timed_out"] is False for row in replicates)
    assert all(
        (row["status_line"] == "s SATISFIABLE" and not row["internal_timeout_marker"])
        if row["status"] == "sat"
        else (row["status_line"] is None and row["internal_timeout_marker"])
        for row in replicates
    )
    assert replay["model"] == {
        "key_word0": 1163416835,
        "key_word1_low_value": 83,
        "combined_assignment": 357645702403,
    }
    assert replay["confirmation"]["all_blocks_match"] is True
    assert replay["confirmation"]["control_first_block_match"] is False
    assert replay["confirmation"]["output_bits_checked"] == 4096
    assert MODULE._canonical_sha256(replay) == CALIBRATION_REPLAY_SHA256


def test_a204_retained_70_probe_literal_mapping_replay_is_exact() -> None:
    payload = json.loads(RESULT_PATH.read_bytes())
    replay = payload["mapping_replay"]
    assert replay["A188_probe_count"] == 40
    assert replay["Round10_probe_count"] == 30
    assert replay["Round10_endpoint_prefixes"] == ["00000", "11111"]
    assert replay["Round10_endpoint_maps_identical"] is True
    assert replay["all_70_probes_exactly_one_unit_clause"] is True
    rows = [*replay["A188_probes"], *replay["Round10_probes"]]
    assert len(rows) == 70
    assert len({row["probe_cnf_sha256"] for row in rows}) == 70
    assert all(row["exactly_one_unit_clause_added"] is True for row in rows)
    assert all(row["expected_one_literal"] == row["observed_added_literal"] for row in rows)
    assert all(
        row["base_body_sha256"] == row["probe_body_without_added_unit_sha256"] for row in rows
    )
    assert all(row["returncode"] == 0 for row in rows)
    assert all(row["externally_timed_out"] is False for row in rows)
    assert MODULE._canonical_sha256(replay) == MAPPING_REPLAY_SHA256


def test_a204_retained_cnf_exports_are_the_frozen_complete_cover() -> None:
    payload = json.loads(RESULT_PATH.read_bytes())
    exports = payload["cnf_export"]
    expected = payload["protocol_gate"]["information_boundary"]
    assert expected["all_32_round10_CNF_hashes_known_before_execution"] is True
    assert [row["variant"] for row in exports] == list(MODULE.VARIANTS)
    assert len(exports) == 32
    assert all(row["header"] == "p cnf 232191 734180" for row in exports)
    assert all(
        row["normalized_sha256"]
        == "a9cd80dc9e7934f3c29681a78e4d734d598205e81b9796e9413b78be85e4fa2b"
        for row in exports
    )
    assert all(row["returncode"] == 0 for row in exports)
    assert all(row["externally_timed_out"] is False for row in exports)
    assert all(row["stderr_sha256"] == MODULE.EMPTY_SHA256 for row in exports)
    assert MODULE._canonical_sha256(exports) == CNF_EXPORT_SHA256
    assert payload["cnf_export_sha256"] == CNF_EXPORT_SHA256


def test_a204_retained_complete_round10_execution_is_exact() -> None:
    payload = json.loads(RESULT_PATH.read_bytes())
    execution = payload["execution"]
    observations = execution["observations"]
    waves = execution["wave_observations"]
    assert payload["execution_plan_sha256"] == EXECUTION_PLAN_SHA256
    assert [row["variant"] for row in observations] == list(MODULE.VARIANTS)
    assert [row["status"] for row in observations] == ["unknown"] * 32
    assert all(row["returncode"] == 0 for row in observations)
    assert all(row["externally_timed_out"] is False for row in observations)
    assert all(row["model"] is None for row in observations)
    assert all(row["witness_assignment_count"] == 0 for row in observations)
    assert all(row["status_line"] is None for row in observations)
    assert all(row["internal_timeout_marker"] is True for row in observations)
    assert len(waves) == 8
    for wave_index, wave in enumerate(waves):
        group = observations[wave_index * 4 : wave_index * 4 + 4]
        assert wave["wave_index"] == wave_index
        assert wave["variants"] == [row["variant"] for row in group]
        assert wave["statuses"] == ["unknown"] * 4
        assert wave["maximum_volatile_seconds"] == max(row["volatile_seconds"] for row in group)
    assert sum(row["volatile_seconds"] for row in observations) == 321.4558637095615
    assert execution["complete_variant_plan_executed"] is True
    assert execution["early_stop_used"] is False
    assert execution["returned_model_count"] == 0
    assert execution["unknown_assignment_available_to_runner_before_execution"] is False
    assert MODULE._canonical_sha256(execution) == EXECUTION_SHA256
    assert payload["execution_sha256"] == EXECUTION_SHA256
    assert payload["confirmations"] == []
    assert payload["confirmation_sha256"] == CONFIRMATION_SHA256


def test_a204_retained_comparison_and_native_reader_chain_are_exact() -> None:
    payload = json.loads(RESULT_PATH.read_bytes())
    comparisons = payload["comparisons"]
    assert comparisons == {
        "A202_A203_baselines_reexecuted": False,
        "A202_A203_status": "all_32_unknown_at_10s",
        "complete_domain_candidate_count": 1 << 20,
        "partition_complete_and_disjoint_by_construction": True,
        "status_counts": {"sat": 0, "unsat": 0, "unknown": 32, "invalid": 0},
        "resolved_sat_plus_unsat_cell_count": 0,
        "confirmed_variants": [],
        "recovered_unknown_low20_assignments": [],
        "primary_prediction_retained": False,
        "secondary_prediction_retained": False,
        "complete_recovery_gate_retained": False,
        "statuses": {variant: "unknown" for variant in MODULE.VARIANTS},
    }
    assert MODULE._canonical_sha256(comparisons) == COMPARISON_SHA256
    assert payload["comparison_sha256"] == COMPARISON_SHA256

    reader = MODULE.CryptoCausalReader(CAUSAL_PATH)
    assert reader.file_sha256 == CAUSAL_SHA256
    assert reader.graph_sha256 == CAUSAL_GRAPH_SHA256
    assert reader.verify_provenance() is True
    rows = reader.triplets(include_inferred=False)
    by_id = {row["edge_id"]: row for row in rows}
    ids = [
        "chacha20-a204-a188-recovery-anchor",
        "chacha20-a204-external-cnf-calibration",
        "chacha20-a204-exact-witness-map",
        "chacha20-a204-round10-boundary",
        "chacha20-a204-complete-cnf-cover",
        "chacha20-a204-reverse-order-execution",
        "chacha20-a204-independent-confirmation",
    ]
    assert len(rows) == 7
    assert set(by_id) == set(ids)
    assert [by_id[edge_id]["provenance"] for edge_id in ids] == [
        [],
        [ids[0]],
        [ids[1]],
        [ids[2]],
        [ids[3]],
        [ids[4]],
        [ids[5]],
    ]
    assert all(
        by_id[left]["outcome"] == by_id[right]["trigger"]
        for left, right in zip(ids[:-1], ids[1:], strict=True)
    )

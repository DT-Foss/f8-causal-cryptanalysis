from __future__ import annotations

import hashlib
import importlib.util
import json
import sys
from pathlib import Path
from typing import Any

import pytest

MODULE_PATH = (
    Path(__file__).parents[1]
    / "research"
    / "experiments"
    / "shake_symbolic_r2_alias_fanout_mobius_frontier.py"
)
SPEC = importlib.util.spec_from_file_location(
    "shake_symbolic_r2_alias_fanout_mobius_frontier_tested",
    MODULE_PATH,
)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)

RESULTS_DIR = Path(__file__).parents[1] / "research" / "results" / "v1"
RESULT_PATH = RESULTS_DIR / MODULE.RESULT_FILENAME
CAUSAL_PATH = RESULTS_DIR / MODULE.CAUSAL_FILENAME
RESULT_SHA256 = "b19c1b85bfad77c5e7aa909ba11a02821fce21f6603daa3174bfe5899a0c1334"
CAUSAL_SHA256 = "8937dffd71decf04159f06bfec1fbecfab41cb571a232587b4b609def3a9e0a8"
CAUSAL_GRAPH_SHA256 = "eb1a0329f1ec23822187b5b1e8f13dc52a5282947ac3f5f52bf01986be4c4956"
EXPECTED_FORMULAS = [
    (
        "weighted_degree_descending__column_only_alias_fanout",
        "column_only",
        8_899_771,
        "77f2d234359d03c4a497ca86d28a9d1d9c95d375f39d5f14a4f94ac8435716a4",
        "7f6592e3c47643729f07947309be9666b9fe73886c4516f006ac4113ecad152c",
        6_886,
    ),
    (
        "weighted_degree_descending__theta_only_alias_fanout",
        "theta_only",
        8_899_771,
        "af34834afa430dba9a28ca92ff9d28f7cf203cb440657113ffdfcaeadf28edc7",
        "d4b5c579036cc40176a5dc719e69b943107a55e6642ab963997455ba29f7c455",
        4_326,
    ),
    (
        "weighted_degree_ascending__column_only_alias_fanout",
        "column_only",
        8_900_279,
        "6ba909d46a0ebe60cced50a2e698061480c536daef8a9a1a0abcb3edde687d39",
        "997d13841d8ca85230c3772029edee9f3f663adee083fcb776bb99c1925c3791",
        6_886,
    ),
    (
        "weighted_degree_ascending__theta_only_alias_fanout",
        "theta_only",
        8_900_279,
        "37062d68a0110c8f4b930b69317bbdee4d3eb5bdc731823f77c33743e96e226d",
        "8c5fb280a15bd8dd79b621392dead9edc152c5baa70730ee2cdfe09408014cc0",
        4_326,
    ),
    (
        "greedy_max_remaining_weight__column_only_alias_fanout",
        "column_only",
        8_899_754,
        "051fde4f39816a35b0ecd997522315453e8aaeb4dfea5b022b4c49d41e976736",
        "a7a399d6bde539e0f786b24155439841476539a0513f897bb24185379692fbde",
        6_886,
    ),
    (
        "greedy_max_remaining_weight__theta_only_alias_fanout",
        "theta_only",
        8_899_754,
        "9fcfb59924ad1cbfd98c74b0bdc85e30cf4cb910b2a8783e8478050a4c1d07c8",
        "ffd20ed0385e896e7eff40684adc7cc443eb82c6c34e5752942aaac101d0e8cb",
        4_326,
    ),
    (
        "greedy_min_remaining_weight__column_only_alias_fanout",
        "column_only",
        8_900_257,
        "c06e1267c3dd38cffd39beba655d2218bd8d69be7992a17854be452516130781",
        "41e3aa8b09cdf85f27bdd1a8f56890fb2d1d919b7b6552c4e02f9b5c84700266",
        6_886,
    ),
    (
        "greedy_min_remaining_weight__theta_only_alias_fanout",
        "theta_only",
        8_900_257,
        "ed1cab808c1d3c24427d4bc5d92cce35e854365a0ffe58ff20650284c7c02a4c",
        "8b925520c35fb2e7dd20cf336bfc59a1a2a5957f6a21ab440f487f371132bbe3",
        4_326,
    ),
]


@pytest.fixture(scope="module")
def analysis() -> dict[str, Any]:
    return MODULE.analyze(RESULTS_DIR)


def test_protocol_freezes_the_exact_two_consumer_boolean_lattice(
    analysis: dict[str, Any],
) -> None:
    protocol = analysis["protocol"]
    assert MODULE.PROTOCOL_SHA256 == (
        "a6849d51cccea60744fd45d97d734bbdc25efd82fc52aab8cd41deb786cd9f88"
    )
    assert protocol["protocol_state"] == "frozen_before_any_A169_solver_execution"
    assert protocol["anchors"]["A168"]["sha256"] == MODULE.A168_SHA256
    assert protocol["anchors"]["A166"]["sha256"] == MODULE.A166_SHA256
    assert protocol["fanout_design"]["semantic_change"] is False
    assert protocol["fanout_design"]["new_formula_count"] == 8
    assert protocol["fanout_design"]["column_consumer"]["name"] == "c2173"
    assert protocol["fanout_design"]["theta_consumer"]["name"] == "t3453"
    assert (
        protocol["information_boundary"]["A169_solver_outcomes_used_before_formula_freeze"] is False
    )
    assert analysis["fanout_plan_sha256"] == (
        "b1476bcf5eeb3a03cf22d8fa7e09391e96d3150027e191125bdd248650dc68c3"
    )
    assert analysis["formula_plan_sha256"] == (
        "c321e346f7edb78ff69c83bc1998b3156bfe0481236da6b775b29422760ea535"
    )


def test_eight_formulas_are_exact_single_consumer_rewrites(
    analysis: dict[str, Any],
) -> None:
    assert [row["name"] for row in analysis["rows"]] == [
        expected[0] for expected in EXPECTED_FORMULAS
    ]
    for row, plan, expected in zip(
        analysis["rows"], analysis["fanout_plan"], EXPECTED_FORMULAS, strict=True
    ):
        name, branch, size, formula_sha, rewrite_sha, line_index = expected
        encoding = row["encoding"]
        assert row["name"] == name
        assert encoding["fanout_branch"] == branch
        assert row["formula_bytes"] == size
        assert row["formula_sha256"] == formula_sha
        assert encoding["single_consumer_rewrite_sha256"] == rewrite_sha
        assert encoding["single_consumer_rewrite"]["line_index_zero_based"] == line_index
        assert encoding["changed_line_count_relative_to_A168"] == 1
        assert encoding["materialized_alias_consumer_count"] == 1
        assert encoding["total_variables"] == 121_576
        assert encoding["total_assertions"] == 122_896
        assert plan["declaration_sequences_identical"] is True
        assert plan["connected_alias_definition_preserved"] is True
        assert plan["semantic_relation_unchanged"] is True


def test_each_arm_keeps_definition_and_exactly_one_materialized_consumer(
    analysis: dict[str, Any],
) -> None:
    for row in analysis["rows"]:
        raw = analysis["formulas"][row["name"]]
        lines = raw.splitlines()
        input_name = row["encoding"]["R2_normalized_materialized_inputs"][0]
        assert sum(b"s1215" in line for line in lines) == 3
        assert f"(assert (= s1215 (not {input_name})))".encode() in lines
        if row["encoding"]["fanout_branch"] == "column_only":
            assert b"(assert (= c2173 (xor s577 s895 s1215 s1534 s1853)))" in lines
            assert f"(assert (= t3453 (xor (not {input_name}) d2493)))".encode() in lines
        else:
            assert (
                f"(assert (= c2173 (xor s577 s895 (not {input_name}) s1534 s1853)))".encode()
                in lines
            )
            assert b"(assert (= t3453 (xor s1215 d2493)))" in lines


def test_all_eight_model_maps_recover_the_complete_rate_witness(
    analysis: dict[str, Any],
) -> None:
    input_assignment = 9_279_571
    solver_assignment = 0
    for row in analysis["rows"]:
        shift = row["encoding"]["affine_shift_original_input_mask"]
        shifted_assignment = input_assignment ^ shift
        solver_assignment = sum(
            ((shifted_assignment >> input_coordinate) & 1) << solver_coordinate
            for solver_coordinate, input_coordinate in enumerate(
                row["encoding"]["variable_to_shifted_input_coordinate"]
            )
        )
        verified = MODULE._A163._verify_solver_row(
            dict(row),
            {"status": "sat", "solver_basis_assignment": solver_assignment},
            analysis["problem"],
            analysis["variant"],
        )
        assert verified["input_coordinate_assignment"] == input_assignment
        assert verified["independent_complete_rate_check"]["complete_rate_match"] is True

    with pytest.raises(RuntimeError, match="independently invalid"):
        MODULE._A163._verify_solver_row(
            dict(analysis["rows"][-1]),
            {"status": "sat", "solver_basis_assignment": solver_assignment ^ 1},
            analysis["problem"],
            analysis["variant"],
        )


def test_mobius_decomposition_is_an_exact_per_order_identity(
    analysis: dict[str, Any],
) -> None:
    a168, a166 = analysis["anchors"]
    inline = {row["order_name"]: row for row in a166["execution_summary"]}
    executions = []
    for order_name in MODULE._A158.ORDER_NAMES:
        baseline = inline[order_name]["stats"]["decisions"]
        executions.extend(
            [
                {
                    "encoding": {"order_name": order_name, "fanout_branch": "column_only"},
                    "solver": {"stats": {"decisions": baseline + 100}},
                },
                {
                    "encoding": {"order_name": order_name, "fanout_branch": "theta_only"},
                    "solver": {"stats": {"decisions": baseline + 200}},
                },
            ]
        )
    decomposition = MODULE._mobius_decomposition(a166, a168, executions)
    assert [row["column_consumer_main_effect"] for row in decomposition["rows"]] == [100] * 4
    assert [row["theta_consumer_main_effect"] for row in decomposition["rows"]] == [200] * 4
    assert [row["fanout_interaction_effect"] for row in decomposition["rows"]] == [
        -2_308,
        677,
        1_323,
        882,
    ]
    assert [row["total_materialization_effect"] for row in decomposition["rows"]] == [
        -2_008,
        977,
        1_623,
        1_182,
    ]
    assert all(row["exact_mobius_identity_verified"] for row in decomposition["rows"])


def test_executor_accepts_only_proven_fixed_resource_termination(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    raw = b"(check-sat)\n"
    row = {
        "name": "fixed",
        "execution_order": 0,
        "formula_bytes": len(raw),
        "formula_sha256": MODULE._sha256(raw),
        "solver_input_names": [],
        "encoding": {},
    }
    result = {
        "status": "unknown",
        "solver_basis_assignment": None,
        "stats": {"rlimit-count": MODULE.Z3_RLIMIT + 1},
        "return_code": 1,
        "termination": "fixed_rlimit_exhausted",
    }
    monkeypatch.setattr(MODULE, "_run_z3_rlimit", lambda *_args: dict(result))
    monkeypatch.setattr(
        MODULE._A163, "_verify_solver_row", lambda row, solver, *_args: {**row, "solver": solver}
    )
    executions = MODULE._execute_frontier(
        formula_rows=[row],
        formulas={"fixed": raw},
        problem={},
        variant=None,
        z3=Path("/fake/z3"),
        work_dir=tmp_path / "accepted",
    )
    assert executions[0]["solver"] == result
    assert list((tmp_path / "accepted").iterdir()) == []

    monkeypatch.setattr(MODULE, "_run_z3_rlimit", lambda *_args: {**result, "return_code": 2})
    with pytest.raises(RuntimeError, match="fixed-resource execution failed"):
        MODULE._execute_frontier(
            formula_rows=[row],
            formulas={"fixed": raw},
            problem={},
            variant=None,
            z3=Path("/fake/z3"),
            work_dir=tmp_path / "rejected",
        )


def test_retained_a169_artifacts_are_hash_pinned_and_reader_valid() -> None:
    raw = RESULT_PATH.read_bytes()
    assert hashlib.sha256(raw).hexdigest() == RESULT_SHA256
    assert hashlib.sha256(CAUSAL_PATH.read_bytes()).hexdigest() == CAUSAL_SHA256
    payload = json.loads(raw)
    assert payload["schema"] == MODULE.SCHEMA
    assert payload["attempt_id"] == "A169"
    assert payload["evidence_stage"] == "ALIAS_FANOUT_MOBIUS_FRONTIER_EXECUTED"
    assert payload["anchor_gates"]["A169_protocol"]["artifact_sha256"] == (MODULE.PROTOCOL_SHA256)
    assert payload["anchor_gates"]["A168"] == {
        "artifact_sha256": MODULE.A168_SHA256,
        "connected_node_removal_effect_L1": 5_790,
        "effect_decomposition_sha256": MODULE.A168_DECOMPOSITION_SHA256,
    }
    assert payload["anchor_gates"]["A166"]["artifact_sha256"] == (MODULE.A166_SHA256)
    assert payload["fanout_plan_sha256"] == (
        "b1476bcf5eeb3a03cf22d8fa7e09391e96d3150027e191125bdd248650dc68c3"
    )
    assert payload["formula_plan_sha256"] == (
        "c321e346f7edb78ff69c83bc1998b3156bfe0481236da6b775b29422760ea535"
    )
    assert payload["mobius_decomposition_sha256"] == (
        "af6b94835b169aeb9ef0e32b721623c0536ccb0e98cb1c156508f419907ec2ea"
    )
    assert payload["status_counts"] == {
        "error": 0,
        "sat": 0,
        "unknown": 8,
        "unsat": 0,
    }
    assert payload["confirmed_models"] == []

    summaries = payload["execution_summary"]
    assert [row["name"] for row in summaries] == [row[0] for row in EXPECTED_FORMULAS]
    assert [row["stats"] for row in summaries] == [
        {
            "binary-propagations": 118_712_650,
            "conflicts": 2_246,
            "decisions": 5_499,
            "propagations": 444_826_315,
            "restarts": 4,
            "rlimit-count": 501_080_367,
        },
        {
            "binary-propagations": 118_702_111,
            "conflicts": 2_456,
            "decisions": 5_188,
            "propagations": 444_893_232,
            "restarts": 7,
            "rlimit-count": 501_080_375,
        },
        {
            "binary-propagations": 119_498_024,
            "conflicts": 2_318,
            "decisions": 4_383,
            "propagations": 446_138_641,
            "restarts": 2,
            "rlimit-count": 501_079_873,
        },
        {
            "binary-propagations": 118_162_048,
            "conflicts": 2_781,
            "decisions": 4_263,
            "propagations": 446_263_168,
            "restarts": 6,
            "rlimit-count": 501_079_881,
        },
        {
            "binary-propagations": 118_317_115,
            "conflicts": 2_315,
            "decisions": 5_873,
            "propagations": 444_831_840,
            "restarts": 4,
            "rlimit-count": 501_080_259,
        },
        {
            "binary-propagations": 117_860_291,
            "conflicts": 2_650,
            "decisions": 5_939,
            "propagations": 444_982_028,
            "restarts": 9,
            "rlimit-count": 501_080_267,
        },
        {
            "binary-propagations": 120_176_721,
            "conflicts": 2_300,
            "decisions": 6_138,
            "propagations": 446_109_425,
            "restarts": 8,
            "rlimit-count": 501_079_921,
        },
        {
            "binary-propagations": 118_535_196,
            "conflicts": 2_326,
            "decisions": 5_856,
            "propagations": 446_087_673,
            "restarts": 5,
            "rlimit-count": 501_079_929,
        },
    ]
    assert [row["canonical_observation_sha256"] for row in summaries] == [
        "7957eae9846159797058d8308e80fdf3ff52a213aa03fb0812fed918c6a9c748",
        "877b1c711733ecfdf5ddbc747c3572625df04aee83f610be62ca685d623a1398",
        "06b3e85fde14a661f3531e5cf4356433b5ecf3fe6c7d71c1a390bd64c9227237",
        "3579f4c11d8e22868e5db85508b04bea41463482773f8e34d85b986caefe3d60",
        "2db59bd7962576b195c85783dfc505d46fe54f0d2c11a57b039975cb66f8cc55",
        "5e9e62b12ae77d6b756df799bb2f7102588bf96417ccb308a7cb0ab83249c68e",
        "1c20bedd3c790c719ec86428b0dc261b355e86ec6c45c721ec4d285a47f5f0c7",
        "ca712ca7ed95fe4afb16bfd3941d513245849f960ccf72eb8dd60c42536295f9",
    ]
    assert all(row["status"] == "unknown" for row in summaries)
    assert all(row["return_code"] == 1 for row in summaries)
    assert all(row["termination"] == "fixed_rlimit_exhausted" for row in summaries)

    assert [
        (
            row["name"],
            row["formula_bytes"],
            row["formula_sha256"],
            row["encoding"]["single_consumer_rewrite_sha256"],
            row["encoding"]["single_consumer_rewrite"]["line_index_zero_based"],
        )
        for row in payload["formula_plan"]
    ] == [
        (name, size, formula_sha, rewrite_sha, line_index)
        for name, _branch, size, formula_sha, rewrite_sha, line_index in EXPECTED_FORMULAS
    ]
    assert all(
        row["encoding"]["changed_line_count_relative_to_A168"] == 1
        and row["encoding"]["materialized_alias_consumer_count"] == 1
        and row["encoding"]["total_variables"] == 121_576
        and row["encoding"]["total_assertions"] == 122_896
        for row in payload["formula_plan"]
    )
    assert all(
        row["declaration_sequences_identical"] is True
        and row["connected_alias_definition_preserved"] is True
        and row["semantic_relation_unchanged"] is True
        for row in payload["fanout_plan"]
    )

    decomposition = payload["mobius_decomposition"]
    assert decomposition["component_L1"] == {
        "column_consumer_main": 4_247,
        "fanout_interaction": 3_289,
        "theta_consumer_main": 4_222,
    }
    assert decomposition["aggregate_dominant_components"] == ["column_consumer_main"]
    assert decomposition["all_interactions_zero"] is False
    assert [
        (
            row["fanout0_inline_decisions"],
            row["fanout1_column_only_decisions"],
            row["fanout1_theta_only_decisions"],
            row["fanout2_both_decisions"],
            row["column_consumer_main_effect"],
            row["theta_consumer_main_effect"],
            row["fanout_interaction_effect"],
            row["total_materialization_effect"],
        )
        for row in decomposition["rows"]
    ] == [
        (7_347, 5_499, 5_188, 5_339, -1_848, -2_159, 1_999, -2_008),
        (3_425, 4_383, 4_263, 4_402, 958, 838, -819, 977),
        (5_247, 5_873, 5_939, 6_870, 626, 692, 305, 1_623),
        (5_323, 6_138, 5_856, 6_505, 815, 533, -166, 1_182),
    ]
    assert all(row["exact_mobius_identity_verified"] is True for row in decomposition["rows"])

    assert payload["posthoc"]["instrumented_input_assignment"] == 9_279_571
    assert payload["posthoc"]["extracted_only_after_every_A169_execution"] is True
    assert payload["posthoc"]["used_for_fanout_formula_order_or_execution"] is False
    assert all(
        row["model_matches_instrumented_input_assignment"] is None
        for row in payload["posthoc"]["model_matches"]
    )
    lowered = raw.decode().lower()
    for volatile_field in (
        '"wallclock_seconds"',
        '"elapsed_seconds"',
        '"peak_memory',
        '"memory_bytes"',
        '"allocations"',
        '"stdout_sha256"',
        '"stderr_sha256"',
    ):
        assert volatile_field not in lowered

    reader = MODULE.CryptoCausalReader(CAUSAL_PATH)
    assert reader.file_sha256 == CAUSAL_SHA256
    assert reader.graph_sha256 == CAUSAL_GRAPH_SHA256
    assert reader.verify_provenance() is True
    causal_rows = reader.triplets(include_inferred=False)
    assert len(causal_rows) == 5
    by_id = {row["edge_id"]: row for row in causal_rows}
    ids = [
        "shake128-a168-single-connected-alias-node",
        "shake128-a169-two-exact-suffix-consumers",
        "shake128-a169-eight-single-consumer-formulas",
        "shake128-a169-fixed-resource-execution",
        "shake128-a169-fanout-mobius-decomposition",
    ]
    assert [by_id[edge_id]["provenance"] for edge_id in ids] == [
        [],
        [ids[0]],
        [ids[1]],
        [ids[2]],
        [ids[3]],
    ]
    assert all(
        by_id[left]["outcome"] == by_id[right]["trigger"]
        for left, right in zip(ids[:-1], ids[1:], strict=True)
    )

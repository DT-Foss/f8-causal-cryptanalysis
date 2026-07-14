from __future__ import annotations

from arx_carry_leak.chacha20_operation_taps import (
    MAPPING_DIMENSIONS,
    TAP_COUNT,
    WORD_BITS,
    augment_formula,
    decode_vectorized_mapping,
    mapping_assertions,
    operation_anchor_groups,
    operation_taps,
)


def test_exact_split18_operation_schedule() -> None:
    taps = operation_taps()
    assert len(taps) == 640
    assert taps[0].word_name == "v0"
    assert taps[0].round_index == 0
    assert taps[0].updated_lane == 0
    assert taps[0].operation == "add_a_1"
    assert taps[7].operation == "xor_rot_b_07"
    assert taps[575].word_name == "v575"
    assert taps[575].direction == "forward"
    assert taps[576].word_name == "v576"
    assert taps[576].direction == "inverse"
    assert taps[576].round_index == 19
    assert taps[576].canonical_step == 7
    assert taps[-1].word_name == "v639"
    assert taps[-1].round_index == 18
    assert taps[-1].canonical_step == 0
    assert {tap.round_index for tap in taps} == set(range(20))
    assert all(sum(tap.round_index == round_index for tap in taps) == 32 for round_index in range(20))


def test_formula_augmentation_and_vectorized_assertions() -> None:
    taps = operation_taps()
    formula = "\n".join(
        [
            "(set-logic QF_BV)",
            "(declare-fun k0 () (_ BitVec 32))",
            *(f"(define-fun v{index} () (_ BitVec 32) #x00000000)" for index in range(TAP_COUNT)),
            "(check-sat)",
            "",
        ]
    )
    augmented = augment_formula(formula, taps)
    assert augmented.count("(declare-fun op") == TAP_COUNT
    assert augmented.count("(assert (= op") == TAP_COUNT
    assert augmented.index("(declare-fun op000") < augmented.index("(define-fun v0")
    assert augmented.index("(assert (= op000 v0))") < augmented.index("(check-sat)")
    assert MAPPING_DIMENSIONS == tuple(range(-1, 15))
    baseline = mapping_assertions(taps, -1)
    bit_pattern = mapping_assertions(taps, 0)
    tap_pattern = mapping_assertions(taps, 5)
    assert baseline.count("#x00000000") == TAP_COUNT
    assert bit_pattern.count("#xaaaaaaaa") == TAP_COUNT
    assert tap_pattern.splitlines()[0].endswith("#x00000000))")
    assert tap_pattern.splitlines()[1].endswith("#xffffffff))")


def test_vectorized_mapping_decoder_and_semantic_groups() -> None:
    tap_count = 4
    baseline = [-(1000 + tap * WORD_BITS + bit) for tap in range(tap_count) for bit in range(WORD_BITS)]
    rows = {-1: baseline}
    for dimension in range(5 + 2):
        values = []
        for tap in range(tap_count):
            for bit in range(WORD_BITS):
                code = (tap << 5) | bit
                baseline_literal = -(1000 + tap * WORD_BITS + bit)
                values.append(-baseline_literal if (code >> dimension) & 1 else baseline_literal)
        rows[dimension] = values
    mapping = decode_vectorized_mapping(rows, tap_count=tap_count)
    assert mapping[0][0] == 1000
    assert mapping[3][31] == 1000 + 3 * 32 + 31

    full_mapping = tuple(
        tuple(100_000 + tap * WORD_BITS + bit for bit in range(WORD_BITS))
        for tap in range(TAP_COUNT)
    )
    groups = operation_anchor_groups(full_mapping, operation_taps())
    assert len(groups) == 90
    assert len(groups["operation_all"]) == TAP_COUNT * WORD_BITS
    assert len(groups["operation_round_00"]) == 32 * WORD_BITS
    assert len(groups["operation_lane_00"]) == 40 * WORD_BITS
    assert len(groups["operation_stage_00"]) == 80 * WORD_BITS
    assert len(groups["operation_bit_31"]) == TAP_COUNT
    assert set(groups["operation_direction_forward"]).isdisjoint(
        groups["operation_direction_inverse"]
    )

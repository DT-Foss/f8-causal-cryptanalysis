from importlib.util import module_from_spec, spec_from_file_location
from pathlib import Path
import sys

import numpy as np

from arx_carry_leak.atlas import chacha_counter_blocks


def _load_suite():
    path = Path(__file__).parents[1] / "research/experiments/chacha_r3_carry_mechanism_suite.py"
    spec = spec_from_file_location("chacha_r3_carry_mechanism_for_test", path)
    assert spec and spec.loader
    module = module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def test_standard_intervention_path_is_exact_chacha() -> None:
    suite = _load_suite()
    counters = np.asarray([0, 1, 17, 2**31, 2**32 - 1], dtype=np.uint32)
    for rounds in (1, 2, 3, 4, 20):
        actual = suite._chacha_intervened(counters, rounds=rounds, seed=42)
        expected = chacha_counter_blocks(counters, rounds, 42)
        assert np.array_equal(actual, expected)


def test_carryfree_and_feedforward_interventions_change_output() -> None:
    suite = _load_suite()
    counters = np.arange(100, dtype=np.uint32)
    standard = suite._variant_output("standard", counters, 3, 42)
    assert not np.array_equal(standard, suite._variant_output("no_feedforward", counters, 3, 42))
    assert not np.array_equal(standard, suite._variant_output("xor_feedforward", counters, 3, 42))
    assert not np.array_equal(standard, suite._variant_output("carryfree_round1", counters, 3, 42))

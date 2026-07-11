import numpy as np

from research.experiments.chacha_traversal_causal_signature import _bit_reverse32, _counters


def test_counter_traversal_families_are_unique_and_deterministic() -> None:
    count = 1024
    for name in ("sequential", "gray", "bit-reversal", "affine", "random-permutation"):
        first = _counters(name, count, 4585001)
        second = _counters(name, count, 4585001)
        assert first.dtype == np.uint32
        assert np.array_equal(first, second)
        assert len(np.unique(first)) == count


def test_bit_reversal_is_an_involution() -> None:
    values = np.asarray([0, 1, 0x80000000, 0x01234567, 0xFFFFFFFF], dtype=np.uint32)
    assert np.array_equal(_bit_reverse32(_bit_reverse32(values)), values)

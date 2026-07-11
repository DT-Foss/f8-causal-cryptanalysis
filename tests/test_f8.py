import pytest

from arx_carry_leak.f8 import run_target


def test_speck_signal_and_simon_control() -> None:
    speck = run_target("speck32_64", n_blocks=1200, n_seeds=3, n_round_pairs=1)
    simon = run_target("simon32_64", n_blocks=1200, n_seeds=3, n_round_pairs=1)

    assert speck.mean_significant_rate > 0.10
    assert speck.t_statistic > 3.0
    assert speck.verdict == "DETECTED"
    assert simon.mean_significant_rate < 0.12
    assert simon.mean_significant_rate < speck.mean_significant_rate


def test_threefish_full_round_smoke() -> None:
    result = run_target("threefish256", n_blocks=1200, n_seeds=3, n_round_pairs=1)
    assert result.full_rounds == 72
    assert result.base_round == 72
    assert result.mean_significant_rate > 0.05


def test_invalid_target_and_seed_count() -> None:
    with pytest.raises(ValueError, match="unknown target"):
        run_target("nope", n_blocks=1000, n_seeds=3, n_round_pairs=1)
    with pytest.raises(ValueError, match="at least 2"):
        run_target("speck32_64", n_blocks=1000, n_seeds=1, n_round_pairs=1)

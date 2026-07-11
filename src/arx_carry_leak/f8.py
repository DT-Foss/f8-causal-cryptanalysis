"""F8 cross-round paired-dependence statistic.

The implementation preserves the published byte-quantized test: for each
output-byte/difference-byte pair it applies a Pearson chi-square independence
test, then measures the fraction of rejected pairs against the nominal 5% null.
"""

from __future__ import annotations

import math
from dataclasses import asdict, dataclass
from typing import Any

import numpy as np
from scipy import stats

from .ciphers import FULL_ROUNDS, StreamGenerator, get_generator


@dataclass(frozen=True)
class SeedResult:
    seed: int
    significant_pairs: int
    tested_pairs: int
    significant_rate: float
    max_chi2: float


@dataclass(frozen=True)
class TargetResult:
    target: str
    full_rounds: int
    base_round: int
    n_round_pairs: int
    n_blocks: int
    n_seeds: int
    shift: int
    alpha: float
    mean_significant_rate: float
    std_significant_rate: float
    t_statistic: float
    verdict: str
    seeds: list[SeedResult]

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["method"] = "F8_cross_round_quantized_independence"
        data["null_significant_rate"] = self.alpha
        data["std_ddof"] = 0
        return data


def _chi_square(table: np.ndarray, n_observations: int) -> tuple[float, float] | None:
    row_sums = table.sum(axis=1, keepdims=True)
    column_sums = table.sum(axis=0, keepdims=True)
    expected = row_sums * column_sums / n_observations
    valid = expected > 5
    if int(valid.sum()) < table.shape[0]:
        return None
    chi2 = float(np.sum((table[valid] - expected[valid]) ** 2 / expected[valid]))
    degrees_of_freedom = (table.shape[0] - 1) ** 2
    return chi2, float(stats.chi2.sf(chi2, degrees_of_freedom))


def f8_seed(
    generator: StreamGenerator,
    *,
    base_round: int,
    n_round_pairs: int,
    n_blocks: int,
    seed: int,
    shift: int = 5,
    alpha: float = 0.05,
) -> SeedResult:
    if not 1 <= shift <= 7:
        raise ValueError("shift must be between 1 and 7")
    if base_round < 1 or n_round_pairs < 1 or n_blocks < 1:
        raise ValueError("round and block counts must be positive")
    if not 0 < alpha < 1:
        raise ValueError("alpha must be between 0 and 1")

    n_bins = 2 ** (8 - shift)
    significant = 0
    tested = 0
    max_chi2 = 0.0

    for round_index in range(base_round, base_round + n_round_pairs):
        output_r, block_bytes, _ = generator(n_blocks, round_index, seed)
        output_r1, next_block_bytes, _ = generator(n_blocks, round_index + 1, seed)
        if next_block_bytes != block_bytes:
            raise ValueError("generator changed its block size between rounds")

        data_r = np.frombuffer(output_r, dtype=np.uint8).reshape(-1, block_bytes)
        data_r1 = np.frombuffer(output_r1, dtype=np.uint8).reshape(-1, block_bytes)
        n_observations = min(len(data_r), len(data_r1))
        data_r = data_r[:n_observations]
        difference = data_r ^ data_r1[:n_observations]
        output_quantized = data_r >> shift
        difference_quantized = difference >> shift

        for source_position in range(block_bytes):
            source = output_quantized[:, source_position]
            for target_position in range(block_bytes):
                target = difference_quantized[:, target_position]
                flat = source.astype(np.int64) * n_bins + target
                table = np.bincount(flat, minlength=n_bins * n_bins).reshape(n_bins, n_bins)
                result = _chi_square(table.astype(float), n_observations)
                if result is None:
                    continue
                chi2, p_value = result
                tested += 1
                max_chi2 = max(max_chi2, chi2)
                if p_value < alpha:
                    significant += 1

    return SeedResult(
        seed=seed,
        significant_pairs=significant,
        tested_pairs=tested,
        significant_rate=significant / max(tested, 1),
        max_chi2=max_chi2,
    )


def run_target(
    target: str,
    *,
    n_blocks: int,
    n_seeds: int,
    n_round_pairs: int,
    shift: int = 5,
    alpha: float = 0.05,
) -> TargetResult:
    if target not in FULL_ROUNDS:
        available = ", ".join(sorted(FULL_ROUNDS))
        raise ValueError(f"unknown target {target!r}; choose one of: {available}")
    if n_seeds < 2:
        raise ValueError("n_seeds must be at least 2 to estimate a t-statistic")

    full_rounds = FULL_ROUNDS[target]
    actual_pairs = min(n_round_pairs, full_rounds)
    base_round = full_rounds - actual_pairs + 1
    generator = get_generator(target)
    seed_results = [
        f8_seed(
            generator,
            base_round=base_round,
            n_round_pairs=actual_pairs,
            n_blocks=n_blocks,
            seed=seed_index * 1000 + 42,
            shift=shift,
            alpha=alpha,
        )
        for seed_index in range(n_seeds)
    ]
    rates = np.asarray([result.significant_rate for result in seed_results], dtype=float)
    mean_rate = float(np.mean(rates))
    std_rate = float(np.std(rates, ddof=0))
    t_statistic = (
        (mean_rate - alpha) / (std_rate / math.sqrt(n_seeds)) if std_rate > 0 else 0.0
    )
    if t_statistic > 3.0:
        verdict = "DETECTED"
    elif t_statistic > 2.0:
        verdict = "WEAK"
    else:
        verdict = "CLEAN"

    return TargetResult(
        target=target,
        full_rounds=full_rounds,
        base_round=base_round,
        n_round_pairs=actual_pairs,
        n_blocks=n_blocks,
        n_seeds=n_seeds,
        shift=shift,
        alpha=alpha,
        mean_significant_rate=mean_rate,
        std_significant_rate=std_rate,
        t_statistic=float(t_statistic),
        verdict=verdict,
        seeds=seed_results,
    )

# ChaCha10 Complete Structural Portfolio Boundary v1

A207 executes the eleven A205-r2 structural candidate modes not already covered
by A206 across every cell of the unchanged reduced-ChaCha10 `2^20` domain. The
protocol, 12-row order archive, candidate modes, 32-prefix order, ten-second
budget, comparison rules, and complete 352-cell plan were frozen before any
A207 solver outcome.

All 352 new observations are valid `unknown`: zero `sat`, zero `unsat`, zero
invalid rows, zero external timeouts, and no early stop. Together with A206's
64 retained cell modes, the calibrated structural portfolio now contains 416
complete observations, all `unknown`. No model or confirmation is emitted.
This is the exact complete structural-order fixed-budget boundary; `unknown` is
not `unsat`, and A207 makes no absence, recovery, or uniqueness claim.

The progress map is nevertheless sharply non-uniform. Against A206's same-mode,
same-prefix baseline, reverse `output_unit_bfs_far` is the strongest systematic
search-density outlier: total conflict and decision ratios are 2.758577 and
5.685714, while propagation ratio is 0.593999. The effect holds in every prefix
cell: conflict ratio is at least 1.703482 and decision ratio at least 3.314562.
These counters are retained mechanistic evidence and were not used to alter the
frozen execution.

```text
protocol   05bbf03fac0f6d817e4af040df070673a6da1e6f618cca8193c860819fb20127
runner     420dc4f30c6bea9da848a4ffe08bcca4b424ff0dbdd7b39b4a0a18f35122cc19
JSON       80ce896083b239e3bb95e31433fc8cdf6157491005bbb3b024182f730b545652
Causal     0d23f4fcb91c6602b3222315afb84f203eff8f5d51b0e4df5f6f6430616d6dfa
graph      ceb1013b7c5387dedbcf5dfe7c5072fe73c200ba72f5d42b5ff7b0866ddb9b14
execution  55164ee97ae7ea6cf877fed32db36e856d13dcac44847bf67c9a7052130c57b5
comparison 966877c363401c70b09bd80ec9b161ccc07148095609fc717dbe835c0588bc22
progress   5501397d4957c99077e2d628e030b402775e37c600686c1f18fa206e7e0c6977
```

![A207 structural portfolio boundary](../results/v1/chacha20_a207_structural_portfolio_boundary_v1.svg)

Fast retained verification (no solver execution):

```bash
PYTHONPATH=.:src python -m pytest -q \
  tests/test_chacha20_round10_structural_portfolio.py \
  tests/test_chacha20_round10_structural_portfolio_result.py
```

# SHAKE Symbolic-R2 Affine-Gauge Solver Frontier v1

## Result

A161 compiles A160's unique global minimum-incidence gauge
`x = y XOR 0x8e26db` into each of the four frozen A158 weighted input orders.
Every query uses A159's exact Z3 4.15.4 protocol: one thread, a configured
`rlimit` of 500,000,000, no solver wall-clock limit, and complete independent
verification of any emitted model.

All four gauge formulas exhaust the fixed resource cap as `unknown`; no model
is emitted.  The retained result is a large, order-dependent traversal
intervention:

| Order | A159 decisions | A161 decisions | Delta | Relative delta | A161 conflicts |
|---|---:|---:|---:|---:|---:|
| weighted-degree descending | 6,940 | 11,859 | +4,919 | +70.9% | 2,282 |
| weighted-degree ascending | 14,386 | 10,493 | -3,893 | -27.1% | 2,283 |
| greedy maximum remaining weight | 13,298 | 5,824 | -7,474 | -56.2% | 2,569 |
| greedy minimum remaining weight | 18,936 | 7,537 | -11,399 | -60.2% | 3,444 |

The A159 decision ordering

```text
weighted-descending < greedy-max < weighted-ascending < greedy-min
```

changes under the single affine gauge to

```text
greedy-max < greedy-min < weighted-ascending < weighted-descending.
```

Thus the globally minimum total linear-incidence gauge is not a uniform solver
simplification.  It interacts strongly with declaration/elimination order:
three orders traverse fewer decisions, while the former minimum traverses 70.9%
more.  Because every terminal status is still `unknown`, these counters are
retained as a deterministic gauge-by-order interaction, not as a model or
success ranking.

## Controlled formula intervention

The complete pre-execution formula plan hash is
`e3aa4cbacac9093b0762aa0d0aaaa875a56f084a46fca5fc3e6655f392ee23d3`.
The four gauge formulas are:

| Order | Formula bytes | Delta from A159 | SHA-256 |
|---|---:|---:|---|
| weighted-degree descending | 8,899,945 | -1,033 | `85ada5be...1cd4f` |
| weighted-degree ascending | 8,900,370 | -1,080 | `15a60177...c0537` |
| greedy maximum remaining weight | 8,899,912 | -1,055 | `caccb320...28661` |
| greedy minimum remaining weight | 8,900,348 | -1,075 | `378fb5a4...f40b8` |

Against the corresponding A159 control, each pair has the same input order and
inverse permutation masks, 276 quadratic-definition masks and occurrence
hashes, two alias coordinates `[516,917]`, 22 suffix rounds, per-round variable
and assertion counts, 121,578 total variables, 122,898 assertions, and all
1,344 target assertions.  The change is confined to 1,352 R2-prefix lines;
the trailing 240,707 lines containing the remaining prefix, complete suffix,
target, `check-sat`, and model query are byte-identical.

Every solver-basis polynomial contains exactly 823 constant, 8,413 linear, and
15,972 quadratic coefficient incidences.  The exact 301-monomial dictionary and
K24 quadratic interface are unchanged; only affine constant/linear structure
and its textual expressions differ.

## Model and resource gates

For each order, a solver assignment is mapped in two explicit stages:

```text
solver-variable assignment
  -> inverse input permutation -> shifted y
  -> y XOR 0x8e26db -> original x.
```

The resulting original assignment must independently reproduce all 1,344 rate
bits through the separate NumPy lane implementation.  Five focused tests cover
the four known posthoc witness mappings, an invalid mapped model, expected Z3
resource-exhaustion return code 1, rejection of other nonzero codes, and early
SAT output with omitted zero-valued statistics.

Code constants, A159 artifact parameters, and every fixed plan row are jointly
bound to `rlimit=500000000`; the external process guard is jointly bound to 300
seconds and aborts rather than truncates a result.  Volatile time, memory,
allocation and raw solver transcript fields remain outside canonical
observations.

The four A161 normalized observation hashes are:

- weighted-degree descending:
  `02607825900a053ab93f32351b27183bc72545f396ffd27cfc7a1e0909ee38f4`;
- weighted-degree ascending:
  `0ad2e3c69384ac279deb5d1be44693100b036179ea342fd7c545846765bdc66f`;
- greedy maximum remaining weight:
  `0d43e2feaa212fd63db6588a4616c8355b7df4dc8ff70b999d2c4f45325afcc5`;
- greedy minimum remaining weight:
  `908cd14fe51561d74a2248b2d6c837874b0b82a2674bccb09aa05a6bb60523ab`.

## Retained bindings

- A159 fixed-resource control:
  `95eefebe7b40a508fb1266782e9542cf3e27b04c2aa0d0ac7dcfcce126593f2a`;
- A160 exact affine-gauge Reader:
  `725d5fcddba7ff4ba4e1a90fac5dd90d34990f4b9f62bf7cfe06e56396de73aa`;
- A161 result JSON:
  `32908a20d5fc5c70ea99edc259ff0ee2575b2d6bc8344994a1afa36c05202971`;
- A161 Causal artifact:
  `6569fc17d39ee4e75f137a731965d3faa4e38a343dd9f08dcfc1bea746272707`;
- canonical Causal graph:
  `6c216489aa40484c3b0c84822a14b48b38a0e5d5129043537190ca50fde433c0`.

The four-triplet Causal chain is reopened with `CryptoCausalReader`, including
exact explicit provenance and Reader-visible formula, normalized execution and
A159 comparison objects.  Only after all four queries finish is the known
input assignment 9,279,571 extracted; its shifted value is 245,384.  Neither
value participates in gauge selection, order, formula construction, or solver
execution.

## Reproduction

Fast formula, mapping, resource-adapter, artifact and Reader gates:

```bash
PYTHONPATH=.:src .venv/bin/python \
  research/experiments/shake_symbolic_r2_affine_gauge_solver_frontier.py \
  --analyze-only

PYTHONPATH=.:src .venv/bin/pytest -q \
  tests/test_shake_symbolic_r2_affine_gauge_solver_frontier.py
```

Full sequential execution:

```bash
rm -rf build/shake-r2-a161
PYTHONPATH=.:src .venv/bin/python \
  research/experiments/shake_symbolic_r2_affine_gauge_solver_frontier.py \
  --work-dir "$PWD/build/shake-r2-a161"
```

## Consequence

A160's scalar objective minimized total linear incidence and A161 proves that
its solver effect is order-dependent.  The next exact Reader should therefore
retain the complete Walsh machinery but weight each linear coefficient by its
position in each frozen variable order.  Complete `2^24` transforms can produce
order-specific affine gauges without solver, target, or assignment input.
Crossing those predeclared gauges with their corresponding orders under the
same A159 resource protocol directly tests whether structural gauge/order
alignment, rather than total term count alone, controls the traversal.

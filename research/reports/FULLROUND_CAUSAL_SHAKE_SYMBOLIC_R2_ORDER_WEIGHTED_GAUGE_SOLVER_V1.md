# SHAKE Symbolic-R2 Order-Weighted Gauge Solver Frontier v1

## Result

A163 compiles all eight A162 order/gauge pairs into exact full-round SHAKE128
formulas and executes them under A159's fixed Z3 4.15.4 protocol: one thread,
`rlimit=500000000`, no solver wall-clock limit, and independent recovery plus a
complete 1,344-bit rate check for every emitted model.

All eight queries exhaust the fixed resource cap as `unknown`; none emits a
model.  The retained result is a resolved factorial traversal map:

| Input order | Positional gauge | Shift | Decisions | Conflicts | Delta from zero | Delta from A160 |
|---|---|---:|---:|---:|---:|---:|
| weighted-degree descending | front loaded | `0x498a92` | 6,785 | 2,350 | -155 | -5,074 |
| weighted-degree descending | back loaded | `0x954b3c` | 13,930 | 2,334 | +6,990 | +2,071 |
| weighted-degree ascending | front loaded | `0x954b3c` | 9,781 | 2,274 | -4,605 | -712 |
| weighted-degree ascending | back loaded | `0x498a92` | 10,687 | 2,781 | -3,699 | +194 |
| greedy maximum remaining weight | front loaded | `0x498a92` | 8,311 | 2,252 | -4,987 | +2,487 |
| greedy maximum remaining weight | back loaded | `0x4e1e28` | 6,870 | 2,431 | -6,428 | +1,046 |
| greedy minimum remaining weight | front loaded | `0x954b3c` | 9,512 | 2,496 | -9,424 | +1,975 |
| greedy minimum remaining weight | back loaded | `0x8c161b` | 12,528 | 2,428 | -6,408 | +4,991 |

Seven of eight order-weighted gauges reduce decisions relative to the same
order's zero gauge.  The sole reversal is the descending/back-loaded pair.
Against A160's unweighted minimum-incidence gauge, only descending/front and
ascending/front reduce decisions; ascending/back is nearly neutral at +194,
and the remaining five increase them.

Direction is itself order-dependent.  Front loading wins within descending by
7,145 decisions, ascending by 906, and greedy-min by 3,016; back loading wins
within greedy-max by 1,441.  The best A163 cell is descending/front at 6,785
decisions, while A161's greedy-max/A160 cell remains the minimum across the
combined fixed-resource matrix at 5,824.

This establishes two exact facts.  First, structural affine gauge selection is
usually better than the zero gauge under its paired order.  Second, minimizing
one linear positional-incidence objective is not sufficient to predict the
best traversal: every A162 mask is the unique global optimum of its declared
objective, yet the solver response depends on additional order/gauge coupling.
Because every status remains `unknown`, the counters are traversal evidence,
not model or satisfiability rankings.

## Frozen eight-formula plan

The complete pre-execution plan hash is
`0c14756cb1c5f8dd0cd9403f4f6d963bb4aab0800cf73dd4791509c62f7c2f30`.
The formulas were frozen before any A163 execution:

| Order / direction | Bytes | Formula SHA-256 | Solver-basis R2 SHA-256 |
|---|---:|---|---|
| descending / front | 8,899,622 | `c914f688...27ff2` | `117adf3b...f97c2` |
| descending / back | 8,899,887 | `139c6c24...4e11c` | `1e0da10c...f06eac` |
| ascending / front | 8,900,448 | `4e1b71ff...025f6` | `40a6881b...02280` |
| ascending / back | 8,899,998 | `b84b0693...56c4` | `9b92b8ce...81552` |
| greedy-max / front | 8,899,624 | `067c602a...2ffe7` | `0f493de2...89edc` |
| greedy-max / back | 8,899,756 | `8b832e1e...fd3b3` | `9d5efe4a...dfa3c` |
| greedy-min / front | 8,900,427 | `8619575a...741d` | `3a0843d2...652a4` |
| greedy-min / back | 8,900,329 | `4c2969ed...24790` | `1420329f...a7a9a` |

The exact shifted polynomial determines two to four R2 aliases per cell.  For
every formula, aliases plus explicit R2 definitions equal all 1,600 state
coordinates.  Total variables span 121,576--121,578 and assertions span
122,896--122,898.  The shared 301-monomial dictionary, all 276 quadratic
monomials, R3--R24 suffix, and all 1,344 target assertions remain fixed.

No target bit, instrumented assignment, A159 counter, or A161 counter enters an
A162 gauge choice, A163 order, formula, or execution.  The known input
assignment 9,279,571 is extracted only after all eight runs complete.

## Model and resource gates

Every possible solver model is mapped through the exact inverse input
permutation, then through the cell's affine XOR shift, and finally evaluated by
the independent NumPy lane core over all 24 rounds and 1,344 rate bits.  Tests
exercise all eight known witness mappings and reject a corrupted mapping.

The fixed-resource adapter accepts an `unknown` observation only when the
reported resource count reaches the configured cap, the termination marker is
`fixed_rlimit_exhausted`, and Z3 exits with its expected resource-exhaustion
code.  Volatile timing, memory, allocation, stdout, and stderr fields are
excluded from canonical observations.  The eight normalized observation
hashes are pinned in the focused artifact test.

## Retained bindings

- A159 zero-gauge fixed-resource control:
  `95eefebe7b40a508fb1266782e9542cf3e27b04c2aa0d0ac7dcfcce126593f2a`;
- A161 A160-gauge fixed-resource control:
  `32908a20d5fc5c70ea99edc259ff0ee2575b2d6bc8344994a1afa36c05202971`;
- A162 exact order-weighted gauge plan:
  `d91b3210a107a815934ee7498c37f9da2740e2c03019feb8af23fe8c9df3549a`;
- A163 result JSON:
  `6528a62e4c12739966d06a0eff910fdf3b2739b53e83cc0dd2577a4afa1d6c8d`;
- A163 comparison matrix:
  `94e16df30eb35f7a98fc7a1384991dc2f9784884e657f48397ad0ac494172d39`;
- A163 Causal artifact:
  `4131017442be841af656011b1c9e2543ad48496a2fa247c97cbc49d4775ff045`;
- canonical Causal graph:
  `5fe9b646a12f3071513713f725e6eec985eb403b198c6b6b7e77f5dbce2a8f44`.

`CryptoCausalReader` reopens the four-triplet chain and verifies explicit
provenance from the A162 plan, through eight frozen formulas and eight
fixed-resource observations, to the same-resource two-control comparison.

## Reproduction

Fast formula, mapping, resource-adapter, artifact, and Reader gates:

```bash
PYTHONPATH=.:src .venv/bin/python \
  research/experiments/shake_symbolic_r2_order_weighted_gauge_solver_frontier.py \
  --analyze-only

PYTHONPATH=.:src .venv/bin/pytest -q \
  tests/test_shake_symbolic_r2_order_weighted_gauge_solver_frontier.py
```

Full sequential execution:

```bash
rm -rf build/shake-r2-a163
PYTHONPATH=.:src .venv/bin/python \
  research/experiments/shake_symbolic_r2_order_weighted_gauge_solver_frontier.py \
  --work-dir "$PWD/build/shake-r2-a163"
```

## Consequence

A163 removes a single positional linear-incidence score as a sufficient solver
predictor while retaining strong, reproducible gauge-by-order structure.  The
next experiment should use the complete A159/A161/A163 factorial matrix to
define a new structural objective with an explicit prospective selection gate,
then test newly selected gauges at the same fixed resource cap.  It should not
spend another eight runs on arbitrary weight curves: the new objective must
encode a concrete missing interaction such as constants/aliases, prefix
elimination order, or suffix-cone pressure and state in advance which outcomes
separate those mechanisms.

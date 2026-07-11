# SHAKE Symbolic-R2 Fixed-Resource Order Frontier v1

## Result

A159 replays the four retained A158 formulas byte-for-byte under one identical
Z3 4.15.4 resource cap of 500,000,000 `rlimit` units per formula.  The runs are
sequential and single-threaded.  No solver wall-clock limit participates in a
query or in the canonical result.

| Order | Formula SHA-256 | Status | `rlimit-count` | Decisions | Conflicts |
|---|---|---|---:|---:|---:|
| `weighted_degree_descending` | `742fafd6...77295` | `unknown` | 501,080,957 | 6,940 | 2,314 |
| `weighted_degree_ascending` | `7b64ba9a...1ea66` | `unknown` | 501,080,463 | 14,386 | 2,925 |
| `greedy_max_remaining_weight` | `81e97db7...67581` | `unknown` | 501,080,877 | 13,298 | 2,711 |
| `greedy_min_remaining_weight` | `a6c2041d...ad1d2` | `unknown` | 501,080,531 | 18,936 | 2,334 |

All four queries exhaust the configured resource cap without a model.  Z3
reports resource exhaustion as `unknown` with process return code 1; A159
accepts that code only when the parsed `rlimit-count` reaches the cap.  Any
external safety timeout, smaller count, other nonzero return code, or malformed
status fails closed.

The same decision-rank ordering seen in A158 survives the fixed-resource
intervention:

```text
weighted-degree descending
< greedy maximum remaining weight
< weighted-degree ascending
< greedy minimum remaining weight
```

This establishes a deterministic traversal separation for the four frozen
encodings.  It does not turn a decision count into a model certificate: every
outcome remains `unknown`, so no order is labeled a successful solver winner.

## Exact replay gates

The complete fixed-resource plan hash is
`41bc4b44a13cbce85545a495f3abb95e35fc679a0515fb0dd90e199d10b62b48`.
Before execution, A159 requires full equality with A158's retained formula plan,
including every encoder mapping, byte count, and formula hash.  Each temporary
SMT file is re-opened and checked again before Z3 starts.

The frozen formulas contain the same 121,578 variables, 122,898 assertions,
301 shared R2 monomials, 22 explicit suffix rounds, and all 1,344 target-rate
bits documented by A158.  Neither an assignment nor any posthoc target
projection affects their bytes or execution order.

## Canonical solver observations

The retained per-order observation hashes are:

- `weighted_degree_descending`:
  `8831f31efa634214dc34fdff55ab29dd3a8cd19150ef96c01867f507d376abe4`;
- `weighted_degree_ascending`:
  `3d094a6b04c29969d04a7cdd324c752c728d20fc861466b040f8dd3ea31cd11c`;
- `greedy_max_remaining_weight`:
  `d7a595ce94fe86108885ccc408eb14ed7d1645c933c92060184c50c341182bf3`;
- `greedy_min_remaining_weight`:
  `969d1dec238dbc7b112585baf5667f821d7e5053c023af6189551ace457e2e22`.

Each hash covers only the parsed status, complete model if present,
deterministic integer solver counters, and raw process return code.  Volatile
wall-clock, memory, allocation, and raw `-st` transcript fields are excluded.
The external 300-second guard is process safety only; it did not fire and would
invalidate rather than truncate an A159 result.

## Retained bindings

- A158 result anchor:
  `f8852a160b11094a5d5b3a2a4c193575a849f15c4e6f489527df391566ff9382`;
- A159 result JSON:
  `95eefebe7b40a508fb1266782e9542cf3e27b04c2aa0d0ac7dcfcce126593f2a`;
- A159 Causal artifact:
  `b23c1419b220f8a15afe09da4c5ec951a3d142e271e671edb2750748361028db`;
- canonical Causal graph:
  `f7e72040e09cef7b1d5765f8bf9e80317c518f5e379a1446c538f6951e30e414`.

The three-triplet Causal chain is re-opened with `CryptoCausalReader`.  Its
explicit provenance is checked exactly, and the final Reader-visible edge
contains all four normalized resource observations.  The instrumented
assignment 9,279,571 is extracted only after all four executions and is not
used by a formula, order, or solver query.

## Reproduction

Fast hash, plan, parser, return-code, and Reader checks:

```bash
PYTHONPATH=.:src .venv/bin/python \
  research/experiments/shake_symbolic_r2_fixed_rlimit_order_frontier.py \
  --analyze-only

PYTHONPATH=.:src .venv/bin/pytest -q \
  tests/test_shake_symbolic_r2_fixed_rlimit_order_frontier.py
```

Full sequential replay:

```bash
rm -rf build/shake-r2-a159
PYTHONPATH=.:src .venv/bin/python \
  research/experiments/shake_symbolic_r2_fixed_rlimit_order_frontier.py \
  --work-dir "$PWD/build/shake-r2-a159"
```

## Consequence

A159 removes wall-clock scheduling as the explanation for A158's rank order,
but input permutation alone does not resolve the full-round relation.  A160
therefore changes the next exact structural variable: enumerate every one of
the `2^24` affine input-complement gauges and minimize total R2 linear
coefficient incidence with an exact integer Walsh transform.  Quadratic K24
structure remains fixed, and neither a target bit nor an assignment enters the
selection.  The resulting gauge can then be crossed with these frozen orders
under the same A159 resource protocol.

# SHAKE Symbolic-R2 Order-Weighted Affine-Gauge Reader v1

## Result

A162 replaces A160's scalar linear-incidence objective with eight exact
order-position objectives: four frozen A158 input orders crossed with
front-loaded weights `24..1` and back-loaded weights `1..24`.  Every objective
is evaluated over all 16,777,216 affine shifts with an integer
Walsh-Hadamard transform.

All eight global optima are unique.  They collapse to four selected gauges:

| Input order | Position weighting | Gauge | Weighted incidence | Zero gauge | A160 gauge |
|---|---|---:|---:|---:|---:|
| weighted-degree descending | front loaded | `0x498a92` | 108,353 | 112,928 | 109,031 |
| weighted-degree descending | back loaded | `0x954b3c` | 101,056 | 104,522 | 101,294 |
| weighted-degree ascending | front loaded | `0x954b3c` | 101,053 | 104,526 | 101,275 |
| weighted-degree ascending | back loaded | `0x498a92` | 108,342 | 112,924 | 109,050 |
| greedy maximum remaining weight | front loaded | `0x498a92` | 108,134 | 112,932 | 108,975 |
| greedy maximum remaining weight | back loaded | `0x4e1e28` | 101,145 | 104,518 | 101,350 |
| greedy minimum remaining weight | front loaded | `0x954b3c` | 101,218 | 104,577 | 101,395 |
| greedy minimum remaining weight | back loaded | `0x8c161b` | 108,363 | 112,873 | 108,930 |

Each order-specific optimum improves both the zero gauge and A160's globally
minimum unweighted gauge under its own declared positional objective.  The
improvement over A160 ranges from 177 to 841 weighted incidences.

The repeated masks are structural rather than tie artifacts: every row has
exactly one optimum.  Near-reverse weighted-degree orders exchange
`0x498a92` and `0x954b3c` when the positional direction is reversed; the two
greedy orders share those front-loaded masks but have distinct back-loaded
optima.

## Exact weighted Walsh construction

For each frozen order, input coordinate `i` receives a positional weight
`w_i`:

```text
front loaded: w(order[j]) = 24 - j
back loaded:  w(order[j]) =  1 + j.
```

The two weight vectors are exact complements: their per-coordinate sum is 25.
With the same A160 affine coefficient equation

```text
l'[k,i](s) = l[k,i] XOR parity(q[k,i] AND s),
```

A162 minimizes

```text
L_w(s) = sum_(k,i) w_i * l'[k,i](s).
```

Grouping the signed terms by neighbor mask again converts `L_w` into one exact
integer Walsh transform.  Each landscape covers all `2^24` shifts, records the
complete score-vector and coefficient-spectrum hashes, verifies direct
evaluation at the zero, A160 and selected gauges, counts global ties, and
checks Parseval equality.

The predeclared objective-plan hash is
`82d519e297cd4c27cce2aca04ddcec2e81fab3fbdb25df75dc96c549a1916cd7`;
the complete eight-landscape hash is
`69731436c46e6ad8472fb453fdbb963b8fa95554609291c2e7d621e5a4177367`.
No A161 decision count, target bit, solver model or instrumented assignment
enters a weight, transform or mask selection.

## Four selected polynomial interfaces

The unique selected masks have the following unweighted coefficient counts and
polynomial hashes:

| Gauge | Constants | Linear | Quadratic | Shifted R2 SHA-256 |
|---|---:|---:|---:|---|
| `0x498a92` | 763 | 8,421 | 15,972 | `3e923cb0...87923` |
| `0x4e1e28` | 796 | 8,452 | 15,972 | `b3b0296b...1fba7` |
| `0x8c161b` | 808 | 8,445 | 15,972 | `b96cf0e7...0bf4c` |
| `0x954b3c` | 815 | 8,465 | 15,972 | `30a7e1e5...0dfc6` |

Their unweighted linear counts are deliberately higher than A160's 8,413:
these are globally optimal positional tradeoffs, not rediscoveries of the
scalar minimum.  For every mask, A162 compares all 1,600 per-coordinate
quadratic coefficient sets against the original, so the full K24 interface and
all 15,972 quadratic incidences are unchanged.

Each unique gauge also passes 64 assignments through original symbolic R2,
shifted symbolic R2, and independent bitsliced two-round Keccak.  All four
gates pass, totaling 1,228,800 checked three-way state bits.  Their joint
semantic-gate hash is
`d4a1f290e5dc651a22a15c88a0d8f76a19351ce30578315419bb3d446d2b53ba`.

## Retained bindings

- A160 unweighted gauge Reader:
  `725d5fcddba7ff4ba4e1a90fac5dd90d34990f4b9f62bf7cfe06e56396de73aa`;
- A161 gauge-by-order intervention:
  `32908a20d5fc5c70ea99edc259ff0ee2575b2d6bc8344994a1afa36c05202971`;
- A162 result JSON:
  `d91b3210a107a815934ee7498c37f9da2740e2c03019feb8af23fe8c9df3549a`;
- A162 Causal artifact:
  `c3faa490a32feca55e10dcb9f5e890053fb6791049e3b29ee470b980e00aadb4`;
- canonical Causal graph:
  `91a520c2e5a0f377503c4b3dd14d3b60bbf2acaaa85bcc1bd7f6ae79b975707e`.

The four-triplet Causal chain is reopened with `CryptoCausalReader`; its exact
explicit provenance links A161's measured interaction, predeclared position
rules, eight complete landscapes and four semantic gates.

## Reproduction

All eight complete landscapes and four semantic gates run directly on the
local CPU:

```bash
PYTHONPATH=.:src .venv/bin/python \
  research/experiments/shake_symbolic_r2_order_weighted_gauge_reader.py

PYTHONPATH=.:src .venv/bin/pytest -q \
  tests/test_shake_symbolic_r2_order_weighted_gauge_reader.py
```

## Consequence

A162 provides two globally certified, target-free gauges for every frozen
order.  A163 should compile all eight predeclared order/gauge pairs with the
same shared-R2 suffix and A159 fixed resource budget.  Every model must be
mapped through its exact order permutation and corresponding affine shift
before the independent 1,344-bit rate gate.  Comparing both positional
directions per order tests the structural alignment hypothesis without choosing
a gauge from A161's solver ranking.

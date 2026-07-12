# ChaCha10 incremental sibling-learning boundary (A210)

A210 composes A209's complete Width-12 phase reset with a native CaDiCaL 3.0
assumption loop.  For each of the 32 five-bit parents, one solver instance
loads the BFS-far-reindexed CNF once and executes all eight three-bit children
while retaining valid learned clauses between sibling calls.  Numeric and
three-bit binary-reflected Gray child orders run in independent solver states.
Each mode covers all `2^20` candidates exactly once.

This is the T01 ordered noncommutative-update transfer selected before any A210
Round-10 outcome was available.

## Retained status boundary

The complete frozen plan executed 64 parent runs and 512 child observations in
16 four-worker waves at ten seconds per child.  No parent hit its external
timeout, no output failed an atomic validity gate, and no early stop occurred.

| Mode | SAT | UNSAT | UNKNOWN | Invalid |
|---|---:|---:|---:|---:|
| Numeric incremental | 0 | 0 | 256 | 0 |
| Three-bit Gray incremental | 0 | 0 | 256 | 0 |

There is no returned model, confirmed assignment, terminal cell, or complete
domain resolution.  The evidence stage is
`ROUND10_INCREMENTAL_COMPLETE_BOUNDARY_RETAINED`.  `UNKNOWN` is not `UNSAT`.

## Learned-state transfer versus fresh A209 cells

Conflicts and decisions are the CaDiCaL API counters that are directly
comparable with the A209 CLI counters.  The API's `search_propagations` counter
is intentionally not compared with A209's broader CLI `propagations` counter.

| Mode | Conflicts / fresh A209 | Decisions / fresh A209 |
|---|---:|---:|
| Numeric incremental | 0.2991561572326791 | 0.14107693425789813 |
| Three-bit Gray incremental | 0.29287909485276054 | 0.14185557384819422 |

The transfer is systematic inside every parent:

- in 32/32 numeric and 32/32 Gray parents, the first child has more decisions
  than every later sibling;
- in 32/32 numeric and 32/32 Gray parents, the first child has more conflicts
  than every later sibling;
- the first-child decision count exceeds the largest later-sibling count by
  `11.269661125319693–32.263268744734624` in numeric order and
  `8.98097096852891–26.53723034098817` in Gray order;
- the corresponding median factors are `17.533303531515422` and
  `15.361025826259707`.

Against their exact same-prefix fresh A209 cells, all 448 later positions
(`1–7` in both modes) reduce both decisions and conflicts.  Aggregate
decision/A209 ratios by sibling position are
`1.0191151, 0.0574489, 0.01370, 0.01256, 0.01017, 0.01192, 0.01216,
0.01078` for numeric and
`1.0047015, 0.0653373, 0.02344, 0.01653, 0.01105, 0.01149, 0.01135,
0.01007` for Gray.  The first position approximately reproduces a fresh cell;
the collapse begins only after retained state exists.

Numeric first children account for 2,516,828 of 2,841,869 decisions
(`0.8856242142055105`).  Gray first children account for 2,481,232 of
2,857,554 decisions (`0.8683062507305199`).  At the eighth position, aggregate
decisions are 94.57848258239073 times lower than at the first numeric position
and 92.3695927332291 times lower than at the first Gray position.  Search
propagation does not collapse with decisions: the eighth/first aggregate ratio
is `0.9872259607275242` for numeric and `1.1239804776148368` for Gray.

Thus retained clauses and solver state replace repeated branching with a
propagation-dominated sibling regime.  This is a complete-domain mechanism
result even though the ten-second calls do not yet terminate a cell.

## Ordered-update control

Gray over numeric aggregate ratios are:

| API metric | Gray / numeric |
|---|---:|
| Conflicts | 0.9790174387918871 |
| Decisions | 1.0055192551099295 |
| Search propagations | 0.9440143699980178 |

No prefix changes status between modes.  The aggregate order effect is small
relative to the roughly sevenfold decision reduction against fresh A209 cells.
The retained-state mechanism, not the local three-bit traversal order, is the
dominant A210 result.

## Mechanistic consequence

A210 resets the solver between five-bit parents, so learned information cannot
cross those 32 boundaries.  The exact next composition is a single common CNF
with the five parent unit clauses removed and all eight prefix bits supplied as
assumptions.  CaDiCaL then retains only clauses entailed by that common base
while traversing a complete 256-cell cover.  Independent numeric and true
eight-bit Gray modes preserve the T01 order control.  This transfers the
systematic A210 sibling effect across the entire domain instead of restarting
it 32 times.

## Reproduction and exact anchors

Retained gates without Round-10 solver execution:

```bash
PYTHONPATH=src .venv/bin/python \
  research/experiments/chacha20_round10_incremental_sibling_learning.py \
  --analyze-only

PYTHONPATH=src .venv/bin/pytest -q \
  tests/test_chacha20_round10_incremental_sibling_learning.py
```

Full frozen execution:

```bash
PYTHONPATH=src .venv/bin/python \
  research/experiments/chacha20_round10_incremental_sibling_learning.py
```

- protocol SHA-256:
  `9eb5183162d6aff09a956b482baa943a60a7c3770bde5e6d10cf67e125388258`
- runner SHA-256:
  `48038ff750c5ca6a961fb7bc60f0d1c18b2f6910ed396bdbfc03c63327676378`
- native helper source SHA-256:
  `d5742b03db88677dee7fc52d3fa93e994153d909de0edc574e1ea611a6ef69c6`
- compiled native helper SHA-256:
  `b214c67932ff7092f802976fa132977a9b5447d0d05f76c64da0dd83d307301e`
- result JSON SHA-256:
  `1765ddabcec9c35d778bbb6e4c4e4aadc66277e7d9255d1f2a8ffdcd7b8152ce`
- Causal SHA-256:
  `ff7f2019001d4c0e8478dd35476d975dde5b6faa1110c0383fbffba9091a6586`
- native Causal graph SHA-256:
  `cc450abd4035fc9f823234a8001a37f59cd1a7ec8a6e2839a366d8b34a229363`

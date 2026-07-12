# ChaCha10 BFS-far Width-12 composition boundary (A209)

A209 composes two previously separate same-challenge mechanisms:

1. A197's complete 256-cell Width-12 partition; and
2. A208's eight-block global-CSE `output_unit_bfs_far`/reverse solver path.

The T04 multi-source graph-distance order is rederived after adding the three
new key-unit sources for bits 14, 13, and 12.  The resulting 256 disjoint cells
cover all `2^20` candidate assignments exactly once.  No correct prefix or
hidden assignment is available before execution.

## Retained status boundary

All 256 cells execute in 64 four-worker waves at ten seconds per cell.  Every
cell returns a valid internal-timeout `UNKNOWN` with all four CLI metrics;
there is no external timeout, invalid status, `SAT`, `UNSAT`, witness, model,
or confirmation.  The evidence stage is
`ROUND10_BFS_FAR_WIDTH12_COMPLETE_BOUNDARY_RETAINED`.

This is not a key recovery and `UNKNOWN` is not `UNSAT`.

## Phase-reset transfer

Each Width-12 child is compared only with the exact same-parent A207 BFS-far
reverse observation at the same nominal ten-second budget.  Eight matched
children replace one parent, so the totals below are normalized by the eight
matched parent copies.

| Metric | Compute-normalized A209 child / A207 parent |
|---|---:|
| Conflicts | 1.0398057000026804 |
| Decisions | 2.7925087307017944 |
| Propagations | 1.614886051905536 |
| Restarts | 6.634065550906555 |

The transfer is systematic:

- decisions increase in 256/256 children;
- propagations increase in 256/256 children;
- restarts increase in 256/256 children;
- decision/propagation density increases in 32/32 parent groups, with range
  `1.18197724560133–2.1704799900516685` and aggregate ratio
  `1.7292295808776634`.

Thus the A208 late propagation-dominated regime is not immutable: complete
Width-12 refinement plus rederived BFS-far ordering restores and exceeds the
decision-rich initial phase across the entire domain.  That phase reset does
not yet produce a terminal cell in ten seconds.

## Mechanistic consequence

The retained phase reset defines a direct next experiment: keep the complete
Width-12 sibling cover, load each five-bit parent once, solve its eight
three-bit children through assumptions, and retain globally valid learned
clauses between siblings. Independent numeric and Gray child orders provide an
ordered-update control. This tests whether the decision-rich reset composes
with retained solver knowledge rather than replacing it.

## Reproduction and exact anchors

```bash
PYTHONPATH=src .venv/bin/python \
  research/experiments/chacha20_round10_bfs_far_width12_refinement.py --analyze-only

PYTHONPATH=src .venv/bin/pytest -q \
  tests/test_chacha20_round10_bfs_far_width12_refinement.py
```

- protocol SHA-256:
  `48ccb1bdbd69a2de0db29eab4dabe8939c8ed98c633b757b0a911738ba3b958f`
- runner SHA-256:
  `02d0209b3e07893400169e3d620b9a08d1eef7e0bcda09c5907bfe13e641f884`
- result JSON SHA-256:
  `242a87fd56da3fcf60e6ae4c1a5dd75effc9a2293a41496ea71f4c4342cc5c1e`
- Causal SHA-256:
  `577f8fdbf41d95d6a61316103c48cc6f366311821b830ac2e4d11b7f4f79eb7f`
- native Causal graph SHA-256:
  `21090e1289ff3cd46ec5403c1a0ab81a5272f056eb5a72ce6da08491aa48eeb1`

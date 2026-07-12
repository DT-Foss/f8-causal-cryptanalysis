# ChaCha10 BFS-far long-budget boundary (A208)

A208 prospectively transfers the unique systematic A207 search-density outlier,
`output_unit_bfs_far` with CaDiCaL `--reverse=true`, from 10 seconds to 60
seconds on every cell of the same complete 32-cell partition.  The public
challenge, eight shared-key blocks, global-CSE CNF skeleton, variable order,
solver mode, prefix order, worker count, confirmation rule, and control are
frozen before any A208 solver outcome.

## Retained result

All 32 predeclared cells execute in eight four-worker waves.  Every observation
is a valid internal-timeout `UNKNOWN` with return code 0 and all four solver
metrics present.  There are no external timeouts, invalid observations,
witnesses, models, `SAT` cells, or `UNSAT` cells.  Consequently:

- no new Round-10 20-bit partial-key recovery is retained;
- `UNKNOWN` is not interpreted as `UNSAT`;
- the exact evidence stage is
  `ROUND10_BFS_FAR_LONG_COMPLETE_BOUNDARY_RETAINED`.

The complete result is independently audited against its source, transform,
execution, comparison, JSON, Causal-file, and native-reader graph hashes.

## Systematic search-phase transition

The exact A207 10-second observation for the same candidate, solver mode, and
prefix is the early-phase anchor.  A208 provides the cumulative 60-second
observation.  Subtracting the exact integer totals yields the 10-to-60-second
late phase without using volatile wall time.

| Metric | Early 0–10 s | Cumulative 0–60 s | Late increment | Late-50 rate / early-10 rate |
|---|---:|---:|---:|---:|
| Conflicts | 149,228 | 339,554 | 190,326 | 0.2550808159326668 |
| Decisions | 901,703 | 1,149,537 | 247,834 | 0.05497020637615711 |
| Propagations | 989,838,887 | 10,201,575,518 | 9,211,736,631 | 1.8612597973229557 |
| Restarts | 717 | 9,944 | 9,227 | 2.573779637377964 |

The direction is not an aggregate artifact:

- conflicts per second decrease on 32/32 prefixes, with late/early ratios
  `0.1682346990389479–0.38480943241020016`;
- decisions per second decrease on 32/32 prefixes, with ratios
  `0.033489291598023066–0.08826551973508925`;
- propagations per second increase on 32/32 prefixes, with ratios
  `1.4129718741611161–2.417589553110579`.

The late-phase density ratios relative to the early phase are retained as exact
fractions:

- conflicts per propagation:
  `31398679334527 / 229108172328478 = 0.1370473999919564`;
- decisions per propagation:
  `245315730720758 / 8306250555382593 = 0.02953387079827362` as a Python float.

Thus the selected order enters a propagation- and restart-dominated regime
after the first 10 seconds.  A208 does not by itself establish whether another
order has the same 60-second profile.  It does establish, for this exact order
on every prefix, that simply extending one solver process is not proportional
to repeating the initial conflict/decision phase.

## Mechanistic consequence

The next prospective transfer is fixed by the observation rather than by a
post-outcome cell choice: refine every one of the 32 parent cells into eight
children, rederive the T04 multi-source BFS-far order after the three new unit
sources, and execute the complete 256-cell Width-12 cover.  This composes:

1. A197's complete same-challenge Width-12 partition boundary;
2. A208's eight-block global-CSE/BFS-far mechanism; and
3. the A208 all-prefix temporal phase boundary.

No correct prefix or hidden assignment is used in that composition.

## Reproduction and exact anchors

```bash
PYTHONPATH=src .venv/bin/python \
  research/experiments/chacha20_round10_bfs_far_long_budget.py --analyze-only

PYTHONPATH=src .venv/bin/pytest -q \
  tests/test_chacha20_round10_bfs_far_long_budget.py
```

The full 32-cell solver execution is intentionally separate from the fast
analysis/test path:

```bash
PYTHONPATH=src .venv/bin/python \
  research/experiments/chacha20_round10_bfs_far_long_budget.py
```

- protocol SHA-256:
  `c5c08f078b3b3d9487d593850bcf469f4bd95f788bb4d0bca85b8ae7a58ee104`
- runner SHA-256:
  `68233f022ded5285ad0926be508f20532d85b5adbaefabbcff6e8096d7ebeb73`
- result JSON SHA-256:
  `58af841aa508978857f629c43c3fdb679e620eb9ec365b5211b4f708d287203c`
- Causal SHA-256:
  `9e5e35ec7a3a005f8bd10d1608dd078b7b79aaaf9bd1e4e77ac5e7201c4a0993`
- native Causal graph SHA-256:
  `cc938bef2e6cfed1f629c5b034987676817be80b0f46c140b32617bd5901e21e`

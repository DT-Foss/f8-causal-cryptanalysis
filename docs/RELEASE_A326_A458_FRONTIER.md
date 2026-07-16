# A326--A458: full-round ChaCha20 W46--W52 Reader frontier

This release publishes the complete public artifact chain from A326 through
A458. It extends the repository
from the W44 recovery batch into exact W46--W52 operator construction,
solver-native proof-antecedent measurement, target-blind transfer, and complete
`2^24` pair-order compilation.

The publication boundary is exact:

- A326--A454: retained public designs, implementations, results, reports,
  AI-native Causal graphs, and reproduction commands;
- A455: the hash-bound `BOOHH` W52 recovery executor is frozen with production
  execution disabled and zero candidate assignments at freeze;
- A456: completed 878-candidate, 86-orbit frequency-ray calibration and complete
  16,777,216-cell `BOOOOOOHHHHHH` pair stream;
- A457: the A456-bound W52 recovery executor and queue are frozen with
  production disabled and zero candidate assignments at freeze;
- A458: completed paired `m=7..15` frequency extension and complete
  16,777,216-cell period-31 pair stream.

## Headline frontier

| Attempt | Exact retained result |
|---|---|
| A432 | Complete W52 off-axis field: 4,096 directly measured cells, 16,384 solver stages, and eight disjoint 512-task worker schedules with zero labels, refits, or candidate executions. |
| A433 | Complete independent W52 prefix field over `word0[31:20]`; selected `A340_selected8_global_raw`; Spearman `0.006311926` against A432 and `-0.013535905` against A428. |
| A436 | Corrected off-axis coordinate contract; selected `A342_selected_pair_global_raw`; W46 calibration rank 561; all 16,384 solver stages reused with zero new stages. |
| A437 | Complete 16,777,216-pair calibration-balanced wavefront; W46 benchmark moves from 314,579 to 234,498, an 80,081-position advance and `0.423847` bit gain. |
| A439 | Four-Reader, 128-known-key, two-axis W52 transfer; complete 16,777,216-pair stream with an exact factor-16 shell and zero violations. |
| A441 | Sixteen direct product orders compiled into a complete 16,777,216-cell permutation with zero factor-16 violations. |
| A442 | Known-key meta-Reader selects `borda_sum`: minimum fixed-block gain `0.328726388` bit, balanced gain `0.584054322` bit, and a distinct W52 pair trajectory. |
| A444--A446 | Density, raw-shape, and assumption-cut variants reproduce the A442 Borda trajectory exactly, establishing a three-way representation-equivalence boundary. |
| A447 | Solver-native proof calibration over 32 targets: 936,982,340 proof nodes and 2,878,295,495 antecedent edges; every held block is positive; balanced gain `0.425414456` bit. |
| A448 | Full 128-target proof corpus: 3,750,214,724 nodes and 11,566,123,517 edges; the fixed A447 model transfers to the remaining 96 targets with 8/8 positive blocks and no refit. |
| A449 | Target-blind W52 proof trace: 32 slices, 8,192 cells, 32,768 solver stages, 934,617,685 proof nodes, and 2,822,633,540 edges; zero W52 labels, refits, or candidate runs. |
| A451 | Complete fixed-slot fused permutation with the pointwise theorem `fused_rank <= 3 * best_component_rank`; all 16,777,216 cells checked, zero violations. |
| A453 | Complete deadline-compiled proof portfolio with the same exact factor-3 theorem; all 16,777,216 cells checked, zero violations. |
| A454 | Exhaustive comparison of 248 periodic schedules selects `BOOHH`; strict remaining-96 gain `0.471700941` bit, minimum block gain `0.160759081` bit, 8/8 positive blocks, and 60/96 median-or-better targets. |
| A455 | Frozen recovery executor binds the exact A454 pair stream, eight workers, 16,777,216 cells, and the complete `2^52` residual domain before execution. |
| A456 | All 878 schedules in 86 cyclic orbits evaluated; `BOOOOOOHHHHHH` selected with remaining-96 aggregate gain `0.489437610` bit and minimum block gain `0.176347722` bit. The complete 16,777,216-cell stream satisfies every exact component bound. |
| A457 | Frozen recovery executor binds A456's exact stream to eight workers and the complete `2^52` residual domain; production disabled and zero candidate assignments at freeze. |
| A458 | All 405 paired B1/B0 schedules in 18 cyclic orbits evaluated; the period-31 schedule raises remaining-96 aggregate gain to `0.495787645` bit and minimum block gain to `0.205050505` bit, with 8/8 positive blocks. The complete 16,777,216-cell stream satisfies every active-component bound. |

## Solver-native proof Reader

A447--A449 turn the solver's proof DAG into the measured substrate. The retained
feature family reads clause ancestry, direct and inherited assumption contact,
proof depth, parent reuse, deletion lifecycle, and multi-horizon temporal
statistics. Selection occurs only on known-key corpora. A449 applies the frozen
A448 operators to the public W52 axes without target labels or model refitting.

This is a deterministic Reader pipeline, not a neural network:

```text
CaDiCaL proof trace
  -> exact antecedent DAG
  -> typed multi-horizon feature field
  -> frozen known-key Reader portfolio
  -> target-blind W52 prefix/off-axis orders
  -> complete pair-stream compiler
```

## Exact full-domain schedule compilation

A451, A453, A454, A456, and A458 each publish a complete 64 MiB pair stream. Every stream
contains exactly 16,777,216 unique `(prefix16, off_axis16)` cells in execution
order. The retained hashes are:

| Attempt | SHA-256 |
|---|---|
| A451 | `826d10e8cfb8ba2cb51e2d1cee35d29f29b9a313928dbdabbf6b92ad2a546cf9` |
| A453 | `73c64ef70ab11498a1dfe8be19bbeb1f8e5d151c16e7fc4abcbfc3e65197df79` |
| A454 | `a82fbe129f6eccaf2ddd560064df1efb471668a116cd52a97490bc66b720b749` |
| A456 | `9a3af1cfb71f96d186815086170127cd5340e7ac102a5fe9dc65414c14df7352` |
| A458 | `5220aa319ab75f7e5e77717802f248512ecdb04531a5d660ac48302f428a1138` |

A454's `BOOHH` schedule gives one slot to Borda, two to the best single proof
operator, and two to the hybrid proof operator per five-slot period. The exact
per-component proposal bounds hold over the complete pair permutation. A455
binds this immutable stream to eight residue-class workers; every worker owns
2,097,152 cells, and every cell owns one complete `2^28` residual subdomain.

A456 follows the calibrated single-block frequency ray to `m=6` and improves
A454 by `0.017736670` aggregate bit and `0.015588641` minimum-block bit. A458
extends the same frozen rule through `m=15`, gaining another `0.006350035`
aggregate bit and `0.028702783` minimum-block bit over A456. Both schedules
were selected with zero W52 labels, zero feature or model refits, and zero
candidate assignments.

## AI-native Causal evidence

Every retained `.causal` result is opened with the repository's authoritative
Reader. The graphs preserve explicit evidence edges, materialized inferred
edges, provenance, quantification, and the next unresolved experiment object.
The completed A454, A456, and A458 graphs and personal Reader readbacks are
anchored as:

| Attempt | Causal SHA-256 | Personal readback SHA-256 |
|---|---|---|
| A454 | `3c14b8a31484bd6bda279d5010056ee7700af89dd81707244f7fafcdf255063f` | `bb7c6c9d1c1d630f6a12d4a21f0cedbb38fdc81d19012190dba70c081794676f` |
| A456 | `ef9024b9c5644958ca4a3f7ebff8ec16c2a448867f4a7e86445b83e07390213d` | `37898bba41c518b0f07c7c415a32ecc9afe7264a3936003b14b60513f7ec6a32` |
| A458 | `fa1b20018c48f640fca9ad7034cb70c7f6a98da1a6a32dd62716a4f19f1ffcd8` | `753dbc6e1a08e057cabb0fe7131678f1156d11b338694510f2d7ae4e2da5f837` |

## Reproduce and authenticate

The frontier gate hashes every released A326--A458 artifact, independently
checks all five complete pair streams, validates the headline JSON invariants,
and fails if an unpublished live-recovery result or progress payload appears.

```bash
python scripts/verify_a326_a458_frontier.py
python -m pytest -q tests/test_a326_a458_frontier_release.py
python scripts/validate_causal_artifacts.py
```

Expected frontier line:

```text
A326--A458 frontier verification: OK
```

The complete SHA-256 ledger is
[`research/results/v1/A326_A458_FRONTIER_SHA256SUMS`](../research/results/v1/A326_A458_FRONTIER_SHA256SUMS).
The append-only continuation is
[`research/ATTEMPT_LOG_A432_A458.md`](../research/ATTEMPT_LOG_A432_A458.md).

# A212 Solver-Trajectory Formula Atlas and Prospective Gray Schedule v1

## Result

A212 transfers five source-derived formula families from the public A199
operator atlas to the complete learned-state telemetry retained by A210 and
A211.  It uses 1,024 already stored CaDiCaL cell observations and launches no
cipher solver.

The retained result has four parts:

1. centered lag-`(0,1,2)` triplet structure survives two different
   marginal-preserving nulls and Holm correction in two solver regimes;
2. numeric/Gray sum-difference channels and cross-copy SVD plus regularized
   matrix logarithms pass all algebraic controls;
3. the six observed channels have full effective cross-copy rank in both the
   reset-local and retained-global regimes;
4. the A210-only weights freeze a new target-independent complete Gray8
   Hamiltonian schedule for future R11/R20 runs.

The evidence stage is
`SOLVER_TRAJECTORY_FORMULA_ATLAS_MIXED_BOUNDARY_RETAINED`.  "Mixed" records one
specific predeclared upper-tail T01 hypothesis that did not retain.  It does
not denote an invalid run: every implementation gate passed, and T01 exposed
a different lower-tail order-coherence discovery.

## Information boundary

The protocol was frozen after the A210/A211 outcomes existed and before any
A212 operator value was computed.  A212 is therefore retrospective for those
two anchors and prospective only for later round transfers.

- no A212 cipher solver is started;
- no model or hidden-assignment field is accessed;
- status is excluded from every feature and score;
- the one A211 terminal prefix is excluded from descriptive A211 rankings;
- the prospective schedule is derived exclusively from A210, whose 512 rows
  are all `UNKNOWN`;
- no R11 or R20 solver outcome entered the schedule.

Frozen protocol SHA-256:

```text
d74edc91d2e02e4512c8798d71c4d7af457295c350d5abd561d1de4691e5de96
```

## Complete trajectory inputs

Six nonnegative channels are transformed by `log1p`:

```text
conflicts delta
decisions delta
search propagations delta
active variables
redundant clauses
irredundant clauses
```

| Context | Solver-state geometry | Rows | Transition operators |
|---|---|---:|---:|
| A210 Numeric | 32 fresh parents × 8 retained siblings | 256 | 7 |
| A210 Gray | 32 fresh parents × 8 retained siblings | 256 | 7 |
| A211 Numeric | one state retained across 256 cells | 256 | 8 |
| A211 Gray | one state retained across 256 cells | 256 | 8 |

This makes A210 the reset-local control and A211 the retained-global system.
The raw feature matrices, normalization constants and context geometry are
stored in the result manifest.

## T01 — ordered learned-state operators

Each transition operator is a ridge-regularized six-channel VAR(1) fit.  Every
operator is divided by its spectral norm before chronological and reversed
products are compared.  The null contains 4,096 deterministic random operator
orders, each compared with its own reversal.

| Context | Chronological/reverse distance | Null 2.5% | Null 97.5% | Upper p | Lower p |
|---|---:|---:|---:|---:|---:|
| A210 Numeric | 0.912923 | 0.780725 | 1.538722 | 0.889675 | 0.111301 |
| A210 Gray | **0.654297** | **0.752915** | 1.485396 | 0.992922 | **0.007567** |
| A211 Numeric | 0.998418 | 0.849160 | 1.478712 | 0.715646 | 0.284843 |
| A211 Gray | 1.023801 | 0.840990 | 1.501414 | 0.450574 | 0.549670 |

The predeclared upper-tail nonclosure prediction did not retain.  The exact
opposite geometry appears in A210 Gray: its chronological product is more
order-coherent than 99.24% of the declared random-order control.  This is
stored explicitly as a posthoc `DISCOVERY`, not retroactively relabeled as the
predeclared prediction.

All 30 fits are finite, every spectral norm is positive, and every adjoint
commutator identity has zero recorded error.

## T02 — genuine solver triplet cumulants

For each context, A212 measures the full `6 × 6 × 6` centered tensor

```text
E[x_t(i) x_(t+1)(j) x_(t+2)(k)].
```

Two 512-replicate nulls are applied independently within every solver segment:

- channel-wise permutation, preserving every marginal exactly;
- channel-wise circular shift, preserving every marginal and the cyclic
  within-channel sequence structure.

Holm correction covers all `4 contexts × 2 nulls × 2 statistics = 16` tests.

| Retained context | Observed L2 | Permutation q97.5 | Holm p | Circular q97.5 | Holm p |
|---|---:|---:|---:|---:|---:|
| A210 Numeric | **4.627675** | 4.450025 | **0.042885** | 4.524366 | **0.031189** |
| A211 Gray | **7.951826** | 1.806938 | **0.031189** | 5.819619 | **0.031189** |

These are different regimes: Numeric retains the triplet signal under repeated
eight-sibling local learning, while Gray retains it across a single global
256-cell state.  Pairwise telemetry alone does not encode this distinction.

## T03 — characteristic-derivative roots

Every one of the 30 normalized T01 operators receives an independent
eigenspectrum and the critical points of its characteristic polynomial.

```text
diagnostics                                  30
maximum coefficient reconstruction error    1e-15
maximum normalized derivative-root residual 0
gates passed                                 30/30
```

The critical-root representation is therefore numerically executable on the
learned solver-state operators and is not a relabeled scalar spectral gap.

## T05/T06 — order-sensitive cross-copy geometry

Numeric and Gray cells are aligned by the same eight-bit prefix.  With

```text
s = (numeric + gray) / sqrt(2)
d = (numeric - gray) / sqrt(2),
```

copy swap leaves `s` invariant and negates `d` exactly.  Both recorded maximum
errors are zero.

The centered cross-copy matrices have effective rank six in both regimes.
Their regularized Gram matrices pass the mandatory `exp(-H)` reconstruction
with relative error `1e-15`.

The first local cross-copy mode assigns the prospective score weights:

| Channel | Weight |
|---|---:|
| decisions | 0.386499 |
| conflicts | 0.372940 |
| redundant clauses | 0.150272 |
| active variables | 0.056119 |
| search propagations | 0.028643 |
| irredundant clauses | 0.005528 |

Thus the schedule is driven primarily by the two search-work channels, with a
separate learned-clause contribution rather than raw runtime.

## Prospectively frozen formula-Gray8 schedule

The schedule score is the weighted positive sum energy multiplied by one plus
the weighted difference-over-sum term.  A212 searches all `8!` permutations of
the reflected-Gray bit axes in both directions.  Every candidate path begins
at the maximum-score A210 prefix, and the objective discounts later cells with
a 32-cell half-life.

```text
start prefix                         10110000
source-to-target bit permutation     [5,4,3,7,6,0,1,2]
direction                            forward
complete prefix cover                256/256
one-bit adjacent transitions         255/255
formula objective                    79.996796430674
standard Gray, identical start       70.331933131546
formula / standard                   1.137417853723
```

The exact order SHA-256 is:

```text
ba9cf4d93c1937665772c77b9091d45cb575054c70037d9cc540ee70a9609127
```

This order was frozen before any new R20 global solver outcome.  It supplies a
third, formula-derived learning trajectory distinct from Numeric and standard
reflected Gray.

## Native Causal Reader result

The nine-edge A212 `.causal` graph is opened with `CryptoCausalReader`; its
provenance DAG is verified.  A separate Reader pass over the existing archive
also located the only top-level graph that already contains an embedded exact
rule closure:

```text
compression_cascade_causal_v1.causal
explicit edges     504
inferred edges     432
rule               lossless_transform_composition
```

That graph proves exact two-stage reversibility for all 12 tested Fullround
cipher targets.  Its corrected length-statistic probe retains no emergent
target-vs-random cascade.  The mechanistic consequence is specific: retain the
compressors as reversible coordinate transforms or serialization layers, not
as stand-alone length distinguishers under that probe.

## Reproduction

```bash
PYTHONPATH=.:src .venv/bin/python \
  research/experiments/chacha20_solver_trajectory_formula_atlas.py --analyze-only

PYTHONPATH=.:src .venv/bin/python \
  research/experiments/chacha20_solver_trajectory_formula_atlas.py

PYTHONPATH=.:src .venv/bin/pytest -q \
  tests/test_chacha20_solver_trajectory_formula_atlas.py
```

The analyze-only path reads all retained anchors and starts no solver or output
write.  The focused suite contains eight tests and recomputes both retained
artifacts byte-exactly.

## Artifact hashes

```text
protocol   d74edc91d2e02e4512c8798d71c4d7af457295c350d5abd561d1de4691e5de96
runner     589a18aae5bdc9ed6c2b0bf052d223d086feb2c06b291d801e53b86d98760dbe
result     d7fc64a9aac6f36483b238595332fd3a4f351c39e501de56b0d1f832903bc8cf
causal     ce5b4f5859a4e4d4c33be185deb2625fa1dc113c1127f0635444ff6ff1789c49
graph      54526aaab678b6e4a7c1f18357e149b29ab9c3096ca3df9e2297cc1043a304f4
schedule   65db0b3a024b8d494b0c56a9f013820e31c07e59b61b919fbb09bf3b3c8f1142
```

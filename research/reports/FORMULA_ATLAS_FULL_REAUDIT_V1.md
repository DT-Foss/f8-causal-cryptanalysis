# Formula Atlas Full Re-Audit v1

## Outcome

The complete mathematical source bundle was re-read without a crypto-keyword
prefilter: nine papers, 113 source pages, and all 2,411 entries in
`formula_atlas_v1.json`.  The old moonshot readout was deliberately consulted
only after the source-first pass.  This separates fresh transfer discovery from
later duplicate/dead-end reconciliation.

The resulting machine ledger retains every atlas entry by immutable ID, source
page, formula hash, context hash, and page-level transfer topics.  No entry is
dropped because it failed to match an existing term such as `cipher`, `carry`,
`solver`, or `causal`.

```text
papers              9
source pages        113
atlas entries       2,411
dropped entries     0
transfer families   18
priority-1 families 6
```

Page topics are navigation metadata, not automatic claim validation.  Every
transfer family below states the invariants that must survive its adaptation.

## Why the source-first pass changed the program

The earlier keyword-oriented shortlist emphasized isolated scalar formulas:
Fiedler gap, Birkhoff contraction, Möbius coupling, Sinkhorn, and sparse BvN.
The full pass exposed relationships that live in prose, controls, failed
closures, and higher-order diagnostics:

1. Individual operators can look universal while ordered products and inverses
   rapidly leave that class.
2. Pair statistics can coincide while third-order cumulants differ by orders of
   magnitude.
3. Critical points of a characteristic polynomial supply a genuinely different
   spectral view from its roots.
4. Generic interior matrices lose geometric information; near-permutation,
   block, and band boundaries restore it.
5. Cross-copy SVD, signed sum/difference projections, and a regularized matrix
   logarithm expose information not present in a scalar spectral gap.
6. Higher Laplacian modes can outperform the Fiedler mode, and only aligned
   Fiedler-prefix cuts have the exact forward-edge guarantee.
7. Periodic normalization can stabilize an otherwise nonlinear amplifier, but
   the aggregation rule—not Jensen convexity alone—determines the regime.
8. Gumbel–Sinkhorn supplies a principled soft-to-hard route from public
   constraint scores to exact balanced cells.

These observations change the immediate question after A195--A197.  The full
`2^20` domain has now remained open under split8, split9, and a refinement from
32 width-15 cells to 256 width-12 cells.  Further uniform prefix refinement is
therefore not the next mechanism.  The next cells must have a different public
geometry while remaining complete and disjoint.

## Reconciliation with the prior moonshot record

The fresh candidates were checked against `FORMULA_CORE_V1.md`,
`RESEARCH_READOUT.md`, `MOONSHOT_LOG.md`, and
`SPARSE_BVN_THEORY_NOTE.md`.  Three apparent routes are already resolved and
must not be recycled under a new name:

- `Sinkhorn(1-M)` on an already doubly stochastic matrix does not swap real and
  complex spectral sectors; it scales non-Perron eigenvalues by
  `-1/(n-1)`.
- Jensen convexity plus global energy restoration does not by itself imply a
  single-cell collapse.  The neighbor aggregation and update order are
  decisive.
- `log(perm/|det|)` is a useful cancellation/geometry feature, but the old
  experiments do not support it as an independent mechanism.

Sparse BvN routing is also already a mature, bounded branch: it is a global
random-expander construction, not a local complement sparsifier.  It remains a
control or routing primitive, not the primary next cipher experiment.

## Priority-1 transfer families

### T01 — Ordered round products and commutators

Build public, size-normalized operators for rounds/cuts, then measure ordered
products, reversed products, commutators, and adjoint controls.  This directly
tests the source observation that algebraic closure can fail even when each
factor looks generic.  The order-reversal control separates a real
noncommutative signal from a scale artifact.

### T02 — Genuine triplet Causal cumulants

Add centered third-order statistics over predeclared round/cell triplets to the
current pairwise Causal graph.  Marginal-preserving shuffled triplets are the
required null.  This targets the source result that two-point agreement can
coexist with a much larger three-point discrepancy.

### T03 — Characteristic-derivative roots

For every normalized influence operator, compute both its eigenvalues and the
critical points obtained from the derivative of its characteristic polynomial.
The second view is retained only when polynomial reconstruction and root
residual gates pass.  It is an independent diagnostic, not a relabeled
eigenspectrum.

### T04 — Fiedler/multimode complete partitions

Construct a public constraint graph, inspect several low Laplacian modes, and
derive a balanced bijection from the 20-bit domain to cells.  Freeze the map
before solver execution and retain numeric-prefix and Gray-prefix controls.
Every candidate must occur in exactly one cell.  This is the most direct
formula-derived successor to the A195--A197 prefix boundary.

### T05 — Z2 sum/difference guidance

Pair forward and backward cut states.  Preserve both the physical sum and the
signed difference; rank only from a declared difference-over-sum rule and
cross-copy singular vectors.  A copy-swap control must negate the signed
channel while leaving the sum invariant.  This is the exact structural
adaptation of the lifted `x=s+ + s-`, `m=s+ - s-` construction.

### T06 — Cross-copy SVD plus regularized matrix log

Normalize the forward/backward coupling block, compute its singular spectrum,
then form `-log(W_cross)` only after a positive-spectrum or explicit
regularization gate.  Reconstruction via `exp(-H)` is mandatory.  This can
reveal latent long-range couplings that the raw block or scalar gap hides.

## Priority-2 transfer families

- **T07 Gumbel–Sinkhorn balanced cells:** anneal a public score matrix to an
  exact hard assignment, then freeze the complete partition.
- **T08 Solver-frontier scaling collapse:** distinguish the round/width onset
  exponent from within-regime convergence; never conflate the two.
- **T09 Boundary-geometry partitions:** compare near-permutation, block, band,
  and generic-interior cells at identical domain cardinality.
- **T10 Controlled nonlinear amplification:** fixed aggregation, exact mass
  restoration, reset-period sweep, and shuffled controls; no universal-collapse
  premise.
- **T11 Krylov/Lanczos complexity:** compare coefficient decay and oscillation
  across rounds/cuts with fixed start vectors and reorthogonalization gates.
- **T12 Signed log-quantized Causal channels:** preserve residual mass and
  compare against equal-bit linear quantization.
- **T13 CUSUM change points:** localize round/cut transitions using calibrated
  familywise thresholds and held-out challenges.

## Priority-3 transfer families

- **T14 Modular fractional-linear bijections:** prove a permutation of
  `Z/(2^w)` with an explicit inverse before using nonlinear prefix preimages.
- **T15 Cardano local-block classifier:** use discriminant sign only as a local
  four-node structural label under a named sampling measure.
- **T16 Reflection-positive forward/backward kernel:** require a PSD gate before
  continuation or a matrix logarithm.
- **T17 Key-subsystem Page curve:** use entropy-versus-width only to choose a
  partition scale, with complement symmetry and finite-size controls.
- **T18 Entropy-round solver duality:** optimize total retained information and
  report per-cell and total work separately.

## Immediate execution order

1. Complete the already-running A197 retention and integration.
2. Test eight-block shared-key stacking at the Round-10 complete-partition
   boundary.  This is the strongest already-observed compiler mechanism and a
   necessary baseline before attributing an improvement to a new atlas method.
3. Build one public constraint-operator atlas that evaluates T01--T03 together;
   all three consume the same normalized matrices but test distinct objects.
4. Use its held-out public scores to freeze T04/T05 partition maps for a new
   still-secret challenge.
5. Introduce T07/T09 only after the graph-derived baseline, so any gain has an
   identifiable source.

## Reproduction

```bash
PYTHONPATH=.:src .venv/bin/python \
  research/experiments/formula_atlas_transfer_audit.py

PYTHONPATH=.:src .venv/bin/python \
  research/experiments/formula_atlas_transfer_audit.py --check

PYTHONPATH=.:src .venv/bin/pytest -q \
  tests/test_formula_atlas_transfer_audit.py
```

The retained JSON is a complete coverage and hypothesis-registry artifact.  It
does not promote any transfer family to a cryptanalytic result; each family
becomes evidence only after its own frozen controls and independent
confirmation.

# A444 personal Causal Reader readback

The main agent opened
`research/results/v1/chacha20_round20_w52_crossfit_density_reader_transfer_a444_v1.causal`
with `dotcausal.io.CausalReader(..., verify_integrity=True)` after the frozen A444
evaluation. This was a native semantic Reader pass, not a JSON substitute.

## Native structure

- API id: `a444dens`
- Explicit triplets: 4
- Materialized inferred triplets: 1
- Total triplets: 5
- Embedded rules: 4
- Clusters: 1
- Gaps: 1
- Causal SHA-256: `432967376e2e0012b9e939fe176d21e4e9b173d2bc452bee9d4c98e979045e13`

## Retained chain read by the main agent

1. The four positive and diverse A375 Readers generate an eight-operator atlas:
   three fixed multiobjective geometries and five block-exclusive density-ratio
   models.
2. Every learned target score is fit on 112 keys and evaluated only on the
   disjoint held block of 16 keys. The complete eight-fold cover therefore
   evaluates every calibration target out of fit.
3. The frozen worst-block-first selection key retains the original Borda sum.
   It gains `0.3287263877670634` bits in its weakest block, `0.5840543224346755`
   bits on the weaker complete corpus, and `0.5963104313759127` bits over all
   128 targets.
4. The closest new geometry is exact Pareto dominance count. It remains
   positive in all eight blocks and nearly matches the global gain
   (`0.5905879240288865` bits), but its weakest block falls to
   `0.24071174318378397` bits. Pairwise histogram, hierarchical histogram,
   Gaussian log-rank, and multiscale-vote Readers also remain positive in all
   eight blocks but lose substantially more worst-block gain.
5. Marginal histogram loses one block and the four-dimensional joint histogram
   loses four blocks. Increasing interaction specificity therefore removes
   transfer robustness rather than concentrating it.
6. Because the selected model is exactly Borda, its two W52 axes and complete
   `2^24` pair schedule are byte-for-byte identical to A442. No redundant
   recovery allocation is opened.
7. The native closure materializes the full path from the four A375 Readers to
   `A444:crossfit_density_representation_boundary`.

## Main-agent interpretation

A444 identifies the missing degree of freedom sharply. The transferable
correct-cell information is a broad monotone agreement across Readers, not a
compact nonlinear density island in their four-dimensional rank copula.
Pairwise and joint density models learn real positive signal, but their extra
specificity is unstable across disjoint key blocks. Another rank remapping or
rank-density model is therefore lower value than leaving rank space.

The Reader's single native gap requests a `non_rank_feature_family`. The next
frontier is the typed candidate-propagation/contradiction representation:
candidate assumptions are compared by hard contradiction count and depth,
propagation-cloud size and geometry, and exact cross-block consistency before
any rank fusion is applied.

## Immutable anchors

- Design SHA-256: `b6f842b04ba69ae50c8d93092816797a1e371d314e862107b2efd7555dd997f2`
- Runner SHA-256: `21a81fe1a6d7a6362f153c81b8d99af7f2753c8473f0d64eae9ee0bc731af8c9`
- Implementation SHA-256: `2710e9b21a956712e460aef7be85b51f5e4c29b2d8ee0b27af7bccb28ba839e6`
- Result SHA-256: `8003c403af34cc7e32a2308840cc924513a220e90f04d6bbef38a3e6d694cb43`
- Result commitment: `cf42204a22bd7b7f7e4f3bec03e8b0e4f46d714da24000bc3579b960bb2a65e3`

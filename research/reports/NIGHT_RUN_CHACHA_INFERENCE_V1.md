# Night Run: ChaCha Output Inference and Fair-Null Audit

## Status

This report separates retained results from attractive intermediate results
that failed a stronger null.  The track is a reduced-round chosen-input and
output-inference study.  It is not an F8 result and it does not require a carry
leak interpretation.

## Retained result 1: output-boundary decomposition

The 32-byte atlas signal at ChaCha R1/R2 is present both within one 64-byte
block and between consecutive blocks.  Ten-key exact tests give `p=0.001953`
for all factual R1/R2 boundary phases.  Both phases collapse at R3.

AES prefix R1 is positive in all five tested packing/stride phases at the same
exact p-value.  The AES R2 negative fingerprint observed under arbitrary row
permutation is not stable under direct re-pairing (`p=0.0527--0.0996`).

Authoritative artifact: `output_boundary_intervention_v1.json`, SHA-256
`65d33d3d673bfb37156062e5151b57b939ed1e9911e7c5e0c1f80969f6a7208c`.

## Retained result 2: ChaCha R2 counter traversal

For the between-block R2 channel, changing only the counter traversal gives:

| traversal | mean information excess | vs repairing | vs binary |
|---|---:|---:|---:|
| binary | +0.002566997 | p=0.001953 | baseline |
| reverse binary | +0.002575042 | p=0.001953 | p=0.7813 |
| shuffled same multiset | -0.000004992 | p=0.5137 | p=0.001953 |
| Gray | +0.002245257 | p=0.001953 | p=0.0352 |
| stride 3 | +0.000991408 | p=0.001953 | p=0.001953 |
| stride 257 | +0.000423919 | p=0.001953 | p=0.001953 |
| bit-reversed binary | +0.002775333 | p=0.001953 | p=0.4727 |
| xorshift32 | +0.000001131 | p=0.8730 | p=0.001953 |

The within-block matrix is exactly invariant under reversing or shuffling the
same counter multiset.  Across traversals, output strength is negatively
associated with counter XOR Hamming distance (`Spearman rho=-0.805`,
`p=0.0159`) but not with mean counter transition MI (`rho=-0.167`, `p=0.693`).

The identical R20 control has effects of order `10^-5`, not `10^-3`, and does
not retain the positive R2 traversal pattern.  This rules out a generic
successor/re-pairing artifact as the explanation for the R2 effect.

Artifacts:

- `chacha_r2_counter_traversal_v1.json`, SHA-256
  `d1fdb258d29e47c393d538dbf3b46652a0963ed51b867c33ee944e7238c5e19b`;
- `chacha_r20_counter_traversal_control_v1.json`, SHA-256
  `e33d76964cab0fec6d9cd865b047bb0d9c42de7795c97f032f9d6fb29ccffb35`.

## Retained result 3: domain-independent R3 differential

All 32 counter bits were screened over R2--R8 with uniformly sampled uint32
base counters.  The independent 100,000-pair holdout used ten new keys and 32
re-pairings.

- R3 is a strong basis-independent chosen-counter differential.
- Every held-out bit was positive on all ten keys at `p=0.001953` and
  `BH q=0.00586`.
- R4 and R5 candidates from the discovery screen failed the independent
  holdout.  Historical R4 bits 0/1/7 also failed.

For R3 input bit 15, the strongest standard output biases are:

| differential output bit | P(bit=1) |
|---|---:|
| word 2, bit 26 | 0.400955 |
| word 2, bit 6 | 0.580750 |
| word 14, bit 2 | 0.447910 |
| word 1, bit 10 | 0.552070 |
| word 3, bit 22 | 0.450090 |

Artifacts:

- `chacha_bit_round_frontier_confirm_v1.json`, SHA-256
  `71f0af71d8bf35333eaa6d1a32e085799b8f7db17515bf2634f3155af7038282`;
- `chacha_late_round_holdout_v1.json`, SHA-256
  `4ad7fefe69137a8b074c541e3d7a4cba558172f711e6030a35644d4660d464e2`.

## Mechanism result: carries erase rather than create the R3 signal

The R3/bit15 signal remains when feed-forward is removed or changed to XOR.
Replacing modular addition with XOR in individual core rounds amplifies the
signal:

| variant | entropy effect | vs standard |
|---|---:|---:|
| standard | 0.284694 | baseline |
| no feed-forward | 0.304288 | +0.019594 |
| XOR feed-forward | 0.303675 | +0.018981 |
| carry-free round 0 | 0.597269 | +0.312575 |
| carry-free round 1 | 6.159575 | +5.874881 |
| carry-free round 2 | 0.668707 | +0.384013 |
| all core rounds carry-free | 370.079211 | +369.794517 |

Every nontrivial intervention is confirmed across ten keys.  The result does
not support “carry creates the R3 leak.”  It supports a residual
linear/differential structure that modular-addition carries, especially in core
round 1, largely destroy.

Artifact: `chacha_r3_carry_mechanism_v1.json`, SHA-256
`cba6a753be498fdb78d1ca85eb57a4de4ea03195a6cd01ce4395f01cce1be69c`.

## Closed route: R4 pair-parity inference

An exhaustive training-key screen covered all 512 unary differential bits and
all 130,816 pair parities at R4/bit15.  No unary feature exceeded its global
null maximum.  Two parities barely exceeded the pair-family maximum; none
reached the preregistered `1.5x` gate.

The top 16 same-sign training features were frozen before testing ten disjoint
keys at N=100,000.  No feature survived BH correction.  The frozen ensemble
gave `AUC=0.499759` and `p=0.9492`.  Pair-parity inference is therefore closed
for this configuration.

Artifacts:

- discovery SHA-256
  `44e7dc0b6b4bbf8672db22f28d0af55adc4338318500da5df35d4450c5dd3e4c`;
- holdout SHA-256
  `ff317be804ae59f344ec8c228acd12930f56a11ce015fa8f26a47842454b761c`.

## Retracted intermediate result: apparent R4--R8 subspace frontier

Arbitrary output re-pairing initially produced a striking curve in closed
low-bit counter subspaces.  It appeared to extend the frontier through R8 and
to lose roughly two active dimensions per round.

That interpretation is rejected.  ChaCha20 produced the same curve almost
exactly:

| active low bits | R8 arbitrary-repair effect | R20 effect |
|---:|---:|---:|
| 8 | 39.74298 | 39.80277 |
| 10 | 12.19280 | 12.13734 |
| 12 | 2.80852 | 2.87117 |
| 14 | 0.72978 | 0.73915 |

For a closed subspace, `c -> c XOR 1` is a fixed-point-free perfect-matching
involution on the same counter/output multiset.  The old null was an arbitrary
permutation and did not preserve this structure.  It measured matching type
and finite multiset size.

A corrected null uses random fixed-point-free perfect matchings, preserving:

- the exact output multiset;
- bijectivity;
- involution structure;
- zero fixed points;
- duplicated edge multiplicity.

Under this fair null, all 24 combinations of R4--R8/R20 and k=8/10/12/14 are
null.  The previously positive domain/dimension artifacts are retained as
negative evidence and must not support a cryptanalytic claim.

Corrective artifact: `chacha_involution_fair_null_v1.json`, SHA-256
`2f93dd8d3eab98e4b4d7fe20bf45d8a75d03948d0db75533aa3dc4b1f68f6492`.

## Closed route: fair conditional code gain

The full 64x64 matrix

`I(C(c)_i ; (C(c)_j XOR C(pair(c))_j))`

was evaluated against the corrected random-involution null for R4, R5, R8 and
R20 at k=8/10/12.  Mean effects are null and maximum cells match the R20
selection-noise scale.  Conditioning/compression does not rescue the closed
subspace route.

Artifact: `chacha_involution_conditional_code_screen_v1.json`, SHA-256
`52c50e3f0acec5ea0d36e30bb3953f7123a90ddaeac85aa09256be97bc4c8f3b`.

## Current defensible boundary

The retained ChaCha results are:

1. R2 sequence/traversal-sensitive between-block information, absent at R20.
2. R3 basis-independent single-bit chosen-counter differentials with large,
   localized marginal bit biases.
3. Arithmetic interventions showing that modular-addition carries suppress,
   rather than generate, the R3 differential structure.

No R4+ claim survives independent keys and the correct structure-preserving
null in the statistics tested so far.

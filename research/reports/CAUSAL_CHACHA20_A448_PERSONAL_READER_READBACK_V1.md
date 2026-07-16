# A448 personal authentic Causal Reader readback

## Reader gate

I opened
`research/results/v1/chacha20_round20_w46_full128_proof_antecedent_transfer_a448_v1.causal`
directly with `dotcausal.io.CausalReader(..., verify_integrity=True)` from the
anchored reader source `dotcausal/io.py` SHA-256
`e320f77855a713e44c97fbc9d1bbb8c488a5c458f2b5ddecc0254a7dc57e0074`.
The native file reopened as API `a448full` with four explicit triplets, one
materialized inferred triplet, four embedded rules, one cluster, and one gap.

The bound A448 result, native Causal file, and generated report have SHA-256
values `4f3bfbc7be7932917a40a3ad9ff3db76c1bf1ca8799d7a887025f3e98e5464db`,
`3a3092311c7ba15ad4be27f53e6e7db2137edd045c8b6a818d9876310b0c564f`,
and `306a8ef9771ccab03160d6665ab4d46a3b0c2b89d081530586196b7eb11158b9`,
respectively.

## Semantic chain personally decoded

1. `A447:proof_antecedent_full128_scale_ready`
   -- `frozen_helper_remaining96_measurement_plus_exact_A447_reuse` -->
   `A448:complete128_proof_antecedent_corpus`.
2. `A448:complete128_proof_antecedent_corpus`
   -- `A447_fixed_model_no_refit_remaining96_evaluation` -->
   `A448:remaining96_no_refit_transfer`.
3. `A448:remaining96_no_refit_transfer`
   -- `eight_complete_block_crossfit_and_full128_fit` -->
   `A448:complete128_crossfit_portfolio`.
4. `A448:complete128_crossfit_portfolio`
   -- `predeclared_proof_signal_open_gate` -->
   `A448:target_blind_W52_proof_trace_ready`.
5. The AI-native materialized closure connects A447's scale gate directly to
   the target-blind W52-ready state with evidence stage
   `COMPLETE128_PROOF_ANTECEDENT_PORTFOLIO_W52_READY`.

## What the graph and result say together

The complete corpus contains 32,768 candidate cells across 128 targets and
four proof horizons: 3,750,214,724 exact proof nodes and 11,566,123,517 exact
antecedent edges, with zero missing antecedents. Thirty-two targets are reused
byte-for-byte from A447; the remaining 96 are a disjoint A448 measurement.

The decisive test precedes all complete-corpus fitting. A447's immutable
`hybrid_proof_top4_equal` model is applied without refit to only the 96 targets
that were absent from A447. Its eight block gains are:

`+0.584937, +0.741456, +0.247697, +0.137481, +0.300788, +0.602485, +0.582570, +0.874914` bits.

Thus the frozen proof model transfers positively in all eight disjoint blocks,
with minimum `+0.137480561` bits and balanced gain `+0.509040874` bits. This is
the direct prospective mechanism result: the exact proof-derivation signal is
not confined to A447's 32 fitting targets.

The subsequent complete-128 block-exclusive crossfit selects
`hybrid_proof_top16_equal`. Its eight held-block gains are:

`+0.859366, +0.331314, +0.484168, +0.535639, +0.355696, +1.153083, +0.421907, +0.579568` bits.

It is positive in all eight complete blocks, with minimum `+0.331314025` bits
and balanced gain `+0.590092609` bits. The complete model keeps proof ancestry,
direct-assumption exposure, redundant/irredundant derivation structure, clause
size, fan-in, and proof-depth operators together as a target-blind portfolio.

No W52 label, W52 model refit, W52 solver stage, or candidate execution entered
A448. Both predeclared transfer gates pass. The Reader's sole unresolved object
is therefore exactly the next scientific action:

`target_blind_W52_proof_antecedent_trace`

with the prescribed constraint that the complete-128 portfolio be traced on
W52 without labels, refits, or altered stopping.

## Bound conclusion

A448 converts A447's 32-target proof-topology discovery into an independently
transferred 96-target result and a complete 128-target operator portfolio. The
causal chain now terminates at a genuine W52 execution gate, not another
calibration step. The immediate next experiment is to preserve the existing
A442 baseline arm, add the frozen A448 proof portfolio as a separate target-
blind arm, and compare their solver trajectories under the same W52 challenge
and stopping contract.

# A458 authentic Causal personal Reader readback

- Reader: `dotcausal.io.CausalReader`
- Integrity verification: `verify_integrity=True`
- Causal artifact: `research/results/v1/chacha20_round20_w52_no_refit_frequency_ray_extension_a458_v1.causal`
- Causal SHA-256: `fa1b20018c48f640fca9ad7034cb70c7f6a98da1a6a32dd62716a4f19f1ffcd8`
- API id: `a458ray`
- Objects read personally: 4 explicit triplets, 2 materialized inferred triplets, 3 rules, 1 cluster, and 1 gap.

## Explicit chain read from the graph

1. `A456:m6_single_block_frequency_boundary` -- `paired_m7_to_m15_B1_and_B0_single_block_phase_extension_with_fixed_no_refit_measurement` --> `A458:selected_no_refit_single_block_extension_pattern`.
2. `A458:selected_no_refit_single_block_extension_pattern` -- `period31_active_component_native_first_encounter_compiler` --> `A458:complete_W52_pair_permutation`.
3. `A458:complete_W52_pair_permutation` -- `exhaustive_component_proposal_bound_and_geometry_gate` --> `A458:exact_W52_frequency_ray_geometry`.
4. `A458:exact_W52_frequency_ray_geometry` -- `frozen_A456_minimum_then_aggregate_comparison` --> `A458:separate_recovery_queue_qualified`.

The selected phase is `OOOOOOOOHHHHHHHHHHHHHHHBOOOOOOO`, a cyclic rotation of the B1 single-block orbit at `m=15`. Its strict remaining96 aggregate and minimum fixed-block gains are `0.49578764525016705` and `0.205050504926648`; all eight fixed blocks are positive. Relative to A456, the gains are `+0.0063500350187295496` aggregate and `+0.028702782985245534` minimum, with two additional targets at or above the median rank.

The compiled W52 stream is a complete 16,777,216-cell permutation with SHA-256 `5220aa319ab75f7e5e77717802f248512ecdb04531a5d660ac48302f428a1138`. Every active-component proposal bound has zero violations. The frozen decision therefore qualifies a separate recovery execution.

## Inferred closure read from the graph

1. The materialized calibration and exact geometry close the A456 boundary directly to `A458:exact_W52_frequency_ray_geometry`.
2. The selected schedule plus the frozen decision rule close directly to `A458:separate_recovery_queue_qualified`.

## Mechanistic interpretation

The scale frontier, not the third Reader, produced the new gain. For the best B1/B0 phase pair at every `m=7..15`, the minimum gain is identical. Aggregate gain is also identical at six scales; B1 is lower by `0.00432330728415` bits at `m=8,9,11` and never higher. At `m=15`, the best B1 and B0 candidates have exactly the same complete remaining96 statistics. B1 wins the frozen global selection only through the precommitted orbit-median tie-break, so A458 preserves that selected stream for recovery while the next calibration front should treat B as an explicit optional component.

The minimum gain reaches its new maximum at the largest measured scale `m=15`, so the period-31 compiler limit is an artificial boundary rather than an observed optimum. The next high-information calibration object is a longer single-block scale ray with the B1/B0 distinction retained or a B0-first extension, followed by materialization only after a new optimum is localized.

## Graph gap

The sole retained gap requests an exclusive A458 W52 recovery execution after A457. This is the immediate recovery-queue action; it does not replace the parallel calibration extension.

# Personal Causal Reader readback — A456

The main agent opened `chacha20_round20_w52_no_refit_frequency_ray_portfolio_a456_v1.causal` directly with `dotcausal.io.CausalReader(verify_integrity=True)` after the A456 result had been materialized.

## Integrity and structure

- Result SHA-256: `8a06661bd6ace82fc9b6854eb4158ddc8a92a47563d71d4aee1cf47707cbbc88`
- Result commitment: `6ef9c4d507892052abf766ee9d34e08fb3833c2377d05c4255e34ff083b80908`
- Causal SHA-256: `ef9024b9c5644958ca4a3f7ebff8ec16c2a448867f4a7e86445b83e07390213d`
- API id: `a456ray`
- Explicit triplets: 4
- Materialized inferred triplets: 2
- Embedded rules: 3
- Clusters: 1
- Gaps: 1

## Personally read semantic chain

1. `A454:H2_O2_B1_frequency_boundary`
   → `structured_m3_to_m6_topology_phase_ray_with_fixed_no_refit_measurement`
   → `A456:selected_no_refit_frequency_ray_pattern`.
2. `A456:selected_no_refit_frequency_ray_pattern`
   → `period31_native_first_encounter_compiler`
   → `A456:complete_W52_pair_permutation`.
3. `A456:complete_W52_pair_permutation`
   → `exhaustive_component_proposal_bound_and_geometry_gate`
   → `A456:exact_W52_frequency_ray_geometry`.
4. `A456:exact_W52_frequency_ray_geometry`
   → `frozen_A454_minimum_then_aggregate_comparison`
   → `A456:separate_recovery_queue_qualified`.

The two stored inferred closures reproduce the direct A454-boundary-to-A456-geometry chain and the selected-pattern-to-recovery-decision chain. The single embedded cluster contains the complete boundary, selection, materialization, guarantee, and decision path. The retained gap asks for an exclusive A456 W52 recovery execution after the existing queue.

## Quantitative meaning read from the graph and bound result

- Selected pattern: `BOOOOOOHHHHHH`, with `H:B:O = 6:1:6` and period 13.
- Strict remaining96 aggregate gain: `+0.4894376102314375` bits.
- Strict remaining96 minimum fixed-block gain: `+0.17634772194140247` bits.
- All eight fixed blocks remain positive.
- Relative to A454 `BOOHH`, aggregate gain increases by `+0.01773666972177157` bits and minimum fixed-block gain increases by `+0.01558864131019888` bits.
- All 16,777,216 W52 cells satisfy every declared component proposal bound with zero violations.
- The materialized W52 stream SHA-256 is `9a3af1cfb71f96d186815086170127cd5340e7ac102a5fe9dc65414c14df7352`.
- No W52 target label, feature refit, model refit, or production candidate assignment contributed to selection or materialization.

## New breadcrumbs

Every per-frequency winner from `m=3` through `m=6` lies in the same cyclic single-block topology: contiguous `O` proposals followed by contiguous `H` proposals, with `B` occupying one phase slot. The best minimum gains are `0.1694482811`, `0.1694285978`, `0.1687769762`, and `0.1763477219` for `m=3,4,5,6`; the discontinuous improvement at `m=6` rules out a simple early plateau.

The A456 and A454 complete W52 orders have Spearman correlation `0.9999999850523072`, yet A456 changes 7,047,460 pair positions and preserves only 87.109% of the first 256 cells. The improvement is therefore concentrated in the high-value early prefix rather than produced by a globally unrelated permutation. This isolates proposal phase and early-prefix allocation as the active mechanism.

Two next objects follow directly:

1. Execute the frozen A456 stream as a separate recovery arm after the already queued A455 arm.
2. Extend the now-identified single-block ray beyond `m=6` without reopening arbitrary topology search; test higher `m` values and the no-`B` endpoint under the same fixed no-refit measurements.

# SHAKE Symbolic-R2 Center-Position Family Contrast v1

## Result

A173 distinguishes the two conditions exposed by A172: the central positions
11/12 versus the Greedy-Max surrounding order family.  It holds the positions
and adjacent `0/12` intervention fixed, replaces the surrounding 22-coordinate
context with Weighted Descending, and executes the same inline/materialized
compiler pair.

The positive direction remains at the same central positions and becomes much
larger:

| Order family at positions 11/12 | Effect `0,12` | Effect `12,0` | Directional delta |
|---|---:|---:|---:|
| A172 Greedy-Max | -581 | -125 | **+456** |
| A173 Weighted Descending | -5,087 | +5,868 | **+10,955** |

Effects are `materialized decisions - inline decisions`.  Directional delta is
`effect(12 before 0) - effect(0 before 12)`.  The same-position,
opposite-family delta difference is `10,955 - 456 = 10,499` decisions.

The frozen classifier maps a positive Weighted-Descending central delta to
`central_position_supported`.  A173 returns exactly that classification.  The
surrounding family changes the magnitude by 10,499 decisions but does not
change the positive direction shared at positions 11/12.

Within A173, the interaction is complete and sign-changing:

- for `0` before `12`, materialization reduces decisions by **5,087**;
- for `12` before `0`, materialization increases decisions by **5,868**.

This is an exact compiler × adjacent-order interaction on one unchanged
full-round SHAKE128 relation.  Neither the compiler arm nor pair orientation
has a context-independent additive effect at the fixed resource boundary.

All four formulas exhaust the 500,000,000-unit Z3 cap as `unknown`.  No formula
emits a model, so A173 makes no model-recovery claim.

## Position-matched contrast

A173 starts from the frozen Weighted-Descending order, removes coordinates `0`
and `12`, preserves the relative order of all other 22 coordinates, and inserts
the pair at the exact same zero-based positions 11 and 12 used by A172:

```text
0 before 12:
[11,2,15,7,16,4,8,9,3,22,21,0,12,20,18,5,10,19,6,17,14,13,23,1]

12 before 0:
[11,2,15,7,16,4,8,9,3,22,21,12,0,20,18,5,10,19,6,17,14,13,23,1]
```

The two orders differ only at positions 11/12, where `[0,12]` becomes
`[12,0]`.  Both are complete 24-coordinate permutations.  The contrast-plan
digest is
`2ab440c8cc5cbdf7d8896b2cead2c5f13499cda1ecfebef9ccde18798c14a99e`.

No SHAKE semantics change.  The affine gauge remains `0x4e1e28`; the shared R2
prefix, 22 suffix rounds, all 1,344 rate constraints and model mapping remain
unchanged.  Each order receives two compiler arms:

- **inline:** 121,575 variables and 122,895 assertions;
- **materialized:** 121,576 variables and 122,896 assertions.

## Frozen formulas

| Central order / arm | Formula bytes | Formula SHA-256 |
|---|---:|---|
| `0,12` / inline | 8,899,674 | `b2c62ea34bef321dbf4f8bfbaf54333052c3f22f4324ab147b509985427c3c7c` |
| `0,12` / materialized | 8,899,730 | `f5fef9ba963c416b9fa2a69ea62cdb87ac89e576334d115f849be5c62e3753f6` |
| `12,0` / inline | 8,899,674 | `bd09f8dfe0709e038f0b9e8670e8e93bceedd5f486cded456cd1e922848c1889` |
| `12,0` / materialized | 8,899,730 | `f6a3b7da24bc6e2e18575949c59969b19657f7ac84201b0b4c2669688ced73fa` |

The complete formula-plan digest is
`aa400b39dff773acf94c5aca38de11a6e26503e84dfd986482adbc6f38e7696f`.
All four inverse-permutation/affine model maps independently accept the known
complete-rate witness across all 1,344 bits and reject a corrupted assignment.

## Exact fixed-resource observations

The retained artifact stores deterministic status, return code, termination
reason and solver counters.  Volatile wall-clock, memory, allocation, stdout
and stderr fields are excluded.

| Central order / arm | Decisions | Conflicts | Restarts | `rlimit-count` | Propagations | Binary propagations |
|---|---:|---:|---:|---:|---:|---:|
| `0,12` / inline | 16,006 | 3,872 | 4 | 501,080,364 | 446,693,994 | 115,437,252 |
| `0,12` / materialized | 10,919 | 2,279 | 8 | 501,080,369 | 444,801,371 | 118,968,562 |
| `12,0` / inline | 6,020 | 2,468 | 11 | 501,080,364 | 444,875,193 | 118,146,935 |
| `12,0` / materialized | 11,888 | 2,317 | 4 | 501,080,369 | 444,813,428 | 119,232,944 |

The canonical observation digests, in table order, are:

- `031aebd93fc67cf2bb4e0a10921a7dacff465bfc45a3629e68e46a16e6b4b619`;
- `0c9fa8d2ee614e69ded5bf2eccc71e0f392e50c6537f09120f16dfa5ef8d9ccb`;
- `c8466ac57a87d8bbe5bd8a5ebc27a2cca76c880dba3f27cbaecb220be5edb773`;
- `a94428be4b074128589ba728a24c72f594a06173bcf7eda2d00db82eff1284cc`.

The canonical family-contrast digest is
`7cffb3b309666c431ec056c24101512b167550db2a5a0085b1ed8ffde5dcb909`.

## Frozen mechanism classifier

Before any A173 execution, the protocol fixed these exhaustive rules for the
Weighted-Descending central delta:

- negative: `family_context_supported`;
- positive: `central_position_supported`;
- zero: `weighted_center_boundary`.

A173 observes `+10,955`, therefore the retained classification is
`central_position_supported`.  A172's Greedy-Max central delta is `+456`.
Holding positions constant while changing the surrounding family preserves the
positive direction and amplifies it, satisfying the predeclared position
branch.

The four A173 cells further reveal the exact nonadditivity behind this result.
At `0,12`, the connected materialized alias is the lower-decision compiler arm;
at `12,0`, the inlined compiler is lower.  The two arm differences have
opposite signs and span 10,955 decisions.  This is the retained
compiler-by-adjacent-order interaction.

## Frozen information boundary

The protocol was frozen before any A173 solver execution at
`research/configs/shake_symbolic_r2_center_position_family_contrast_v1.json`,
SHA-256
`82cd65e9ecc51ba40ec16871cae182ed35f8ad9be5be63ff40806ed9161c91d9`.

A172's positive central delta selected the position-matched family contrast.
It did not select an A173 formula arm, execution outcome or resource limit.
Weighted Descending was selected as the original negative weighted context.
Neither the target rate nor the instrumented assignment selected the contrast.
Assignment 9,279,571 is extracted only after all four executions; every
model-match field is `null` because all four outcomes are `unknown`.

## Causal Reader gate

The retained Causal artifact contains exactly five explicit edges: A172's
positive central result, the position-matched Weighted-Descending orders, four
hash-bound formulas, their fixed-resource observations, and the frozen
family-versus-position classification.  The edges form one provenance chain
with no inferred edges.  `CryptoCausalReader` verifies provenance and both
retained digests:

- Causal file SHA-256:
  `da252d66daac4971324679b2911926b562f9edc65edfd5546a5ac5e7a8ad7234`;
- canonical graph SHA-256:
  `f4f5d38e9e328de2d6383d57230176b4efee0057be3a993bab65406412c65cfd`.

## Retained bindings

- A173 result JSON:
  `b3ae48350a75430b1b1aea55ebe59442949dd6b5fe19f30453583ede6da6d01b`;
- A172 result JSON:
  `f1252babeb729f9b58102d24d522daa0fa337506e25f9f282b2b4fb9a4d693c3`;
- A170 result JSON:
  `f28d4a767d26b6514eb90d6324e8a19d2842d1418fd7587ff0068ca9512cb97f`.

## Reproduction

Fast protocol, contrast-plan, formula, model-map, retained-artifact and Causal
Reader gates:

```bash
PYTHONPATH=.:src .venv/bin/python \
  research/experiments/shake_symbolic_r2_center_position_family_contrast.py \
  --analyze-only

PYTHONPATH=.:src .venv/bin/pytest -q \
  tests/test_shake_symbolic_r2_center_position_family_contrast.py
```

Full sequential four-formula execution:

```bash
rm -rf build/shake-r2-a173
PYTHONPATH=.:src .venv/bin/python \
  research/experiments/shake_symbolic_r2_center_position_family_contrast.py \
  --work-dir "$PWD/build/shake-r2-a173"
```

## Consequence

A173 resolves A172's first context boundary.  Moving from Greedy-Max to
Weighted Descending at the exact same central positions does not restore the
negative weighted discovery direction; it strengthens the positive central
direction from +456 to +10,955.  Central placement is therefore the supported
condition under the frozen classifier, while family context controls effect
magnitude.  The four new cells expose the sharper mechanism: materialization
and adjacent orientation interact so strongly that swapping `0,12` to `12,0`
changes materialization from a 5,087-decision benefit to a 5,868-decision cost.

# Session Full-Round F8 Import Audit v1

Source snapshot: `<source-snapshot>`.
This audit is intentionally stricter than the source labels.  In particular,
`immune` is interpreted only as **no F8 hit under the probes run so far**.

## Provenance

The snapshot contains two independent repositories:

- `session/arx-carry-leak`: exhaustive research notebook through EXP-110,
  mostly uncommitted/untracked; 108 top-level experiment scripts, 104
  top-level result JSONs, Nano sweeps, chronological logs and mechanism notes.
- `session/f8`: committed curated reproduction repository (HEAD `2e23b23`),
  nine runners and nine JSONs summarizing twelve claimed full-round
  configurations.

There are no `.causal` artifacts in either repository.  Every retained
mechanism must therefore be rebuilt from raw cipher states into the current
builder/reader format; none may be imported as already AI-native evidence.

## The twelve claimed configurations

All twelve use the known-key internal boundary `state(R)` versus
`state(R+1)` for matched inputs.  They are not ciphertext-only distinguishers,
key recovery, or standard black-box attacks.

| Configuration | Source mechanism | Source evidence | Import status |
| --- | --- | --- | --- |
| Speck32/64 R22 | beta masking | 3-seed mean Z 4088; no round decay; encrypt/decrypt and key-schedule controls | Strong; already superseded by current ten-variant carry/BvN causal intervention |
| Speck48/96 R23 | beta masking | full-round mean Z 918, three seeds | Strong; current ten-variant causal result is authoritative |
| Speck64/128 R27 | beta masking | full-round mean Z 1165, three seeds | Strong; current ten-variant causal result is authoritative |
| Speck128/256 R34 | beta masking | full-round mean Z 1776, three seeds | Strong; current ten-variant causal result is authoritative |
| Threefish-256 R72 | source calls it raw carry/fixed pair | Z 16302, bit-0 MI ln(2), permutation-null controls | Strong state-boundary signal, but source mechanism wording is superseded by current affine neighboring-word/state-reuse intervention result |
| Threefish-1024 R80 | permutation fixed points 0/2 | Skein zero KAT; source N-scaling 25,972 to 483,069; fixed/non-fixed slot control | High-priority re-audit; old EXP-95 bulk path was keyless, curated runner includes periodic key/tweak injection; current independent fixed-cell BvN confirms ln(2) and exact survival under standard final whitening, but multi-seed `.causal` confirmation remains required |
| GIFT-64 R28 | fixed permutation-cycle relation | four official vectors; corrected key schedule; Z 676; N-scaling 75 to 3521, exponent 0.918 | Strong import candidate; rebuild with shared BvN routes, fixed cells and Reader holdout |
| GIFT-128 R40 | fixed permutation-cycle relation | four official vectors; low-64 grid Z 275 | Provisional: main statistic covers only a 64x64 sub-grid and lacks a separate N-scaling confirmation |
| PRESENT-80 R31 | fixed permutation-cycle relation | four official vectors in scalar/vectorized paths; Z 1183 | Provisional: source is effectively one discovery seed; reconcile against the current chosen-difference direct-output R31 null because the estimands differ |
| TEA R32 | fixed-position self-XOR | roundtrip/avalanche gate; 20k to 200k mean Z 40.6 to 498.9, three seeds | Promising but requires an authoritative published KAT before import |
| RC5-32/12/16 R12 | Feistel/self-XOR | RFC 2040 KAT, roundtrip, N-scaling Z 42.1 to 220.7 | Strong import candidate |
| RC5-64/24/24 R24 | Feistel/self-XOR | IETF-draft vector, roundtrip, extended N-scaling Z 18.1 to 444 at 800k | Strong but small-effect import candidate; fixed-cell holdout required |

## Direct verification performed during this audit

Without rewriting source artifacts, the curated implementations were imported
read-only and their gates rerun.  All passed:

- four GIFT official vectors;
- four PRESENT-80 vectors in both scalar and vectorized paths;
- Threefish-1024 all-zero Skein KAT;
- TEA encrypt/decrypt roundtrip and 31.9008/64 mean avalanche;
- RC5-32 official vector, roundtrip and 33/64 avalanche;
- RC5-64 reference vector, roundtrip and 56/128 avalanche.

For Threefish-1024, an independent N=20,000, 32-route BvN fixed-cell audit
compared the curated keyed internal R80 state and the standard final-whitened
R80 ciphertext against the same R81 state.  Both views give identical results:

- fixed slot `w1 -> delta_w0`, bit 0: MI 0.6931471, Z about 21,235;
- fixed slot `w3 -> delta_w2`, bit 0: MI 0.6931411, Z about 28,650;
- non-fixed slots 4 and 8: Z 0.17 and 0.05.

The standard final whitening therefore does not remove the fixed-point bit-0
relation.  This is expected because adding a fixed known subkey changes bit 0
by a bijective fixed XOR, but it needed to be verified rather than assumed.

## Corrections and non-full-round artifacts

- The original shared Nano GIFT key schedule is buggy.  Only EXP-30 and the
  curated `session/f8/experiments/gift.py` corrected path are admissible.
- Older Threefish-1024 EXP-95 measures a keyless MIX+PI core in bulk despite
  using a complete keyed function for its KAT.  The curated runner repairs the
  periodic subkey/tweak injections, though its stored state is still the
  internal full-round boundary rather than a black-box output API.
- Serpent's large R31-to-R32 effect crosses the special final no-LT boundary;
  genuine R32-to-R33 is clean under that probe.
- Skipjack's large Rule-B pre-G raw-XOR identity is exact, but the specified
  R32-to-R33 boundary uses Rule A and is clean under that probe.
- Serpent and Skipjack are valuable causal boundary templates, not members of
  the twelve full-round hit configurations.

## Import order

1. Threefish-1024 keyed fixed-point causal confirmation, because it is the
   largest new mechanism and has the most consequential source-path mismatch.
2. GIFT-64 shared-route/N-scaling Reader reconstruction; then GIFT-128 with a
   full 128x128 or pre-registered sparse grid.
3. PRESENT-80 F8 relation reconstruction to reconcile it with the existing
   direct chosen-difference full-round null.
4. RC5-32 and RC5-64 self-XOR interventions, followed by TEA after adding a
   reference KAT.
5. Serpent and Skipjack boundary mechanisms as positive controls for
   operation-order and skipped-diffusion causal views.

Every import must use shared BvN routes, pre-registered/fixed cells or a
separate discovery block, fresh keys, explicit R/R+1 semantics, reader-only
reconstruction and a negative local-structure control.

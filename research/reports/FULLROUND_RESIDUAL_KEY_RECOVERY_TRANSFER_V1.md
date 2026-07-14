# Full-round residual-key recovery transfer v1

## Result

The A184 execution pattern has transferred from ChaCha20 to two independent
ARX designs without changing the declared cryptographic relations.  All three
runs execute the standard full-round primitive, traverse the complete frozen
residual-key domain without early stopping, recover one exact assignment,
reject a one-bit-flipped control, and confirm the reconstructed key with an
independent implementation.

| Attempt | Primitive | Full rounds | Unknown key bits | Known key bits | Complete candidates | Exact models | Control models | Independent confirmation |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| A184 | ChaCha20 block function with feed-forward | 20 | 40 | 216 | `2^40` | 1 | 0 | 512 bits |
| A237 | Speck32/64 | 22 | 42 | 22 | `2^42` | 1 | 0 | 3 blocks / 96 bits |
| A240 | Threefish-256 with known tweak | 72 | 38 | 218 | `2^38` | 1 | 0 | 1 block / 256 bits |

The retained machine-readable anchors are:

- A184: `research/results/v1/chacha20_metal_width40_partial_key_recovery_v1.json`
- A237: `research/results/v1/speck32_64_metal_width42_recovery_v1.json`
- A240: `research/results/v1/threefish256_metal_width38_recovery_v1.json`

## A237 — Speck32/64

A237 reconstructs the complete 64-bit master key after receiving 22 known key
bits.  The unknown assignment comprises `K0`, `K1`, and the low ten bits of
`K2`.  Three known plaintext/ciphertext pairs remove the ambiguity caused by
Speck32/64's 32-bit block size.

- assignments executed: `4,398,046,511,104 / 4,398,046,511,104`
- recovered assignment: `3,099,631,123,999`
- recovered `K0`, `K1`, full `K2`, `K3`:
  `[32287, 45161, 6865, 10980]`
- factual/control models: `1 / 0`
- GPU time: `959.8156910734251` seconds
- measured throughput: `4,582,178,174.421565` candidates/second
- result SHA-256:
  `2b8f77c219b4291d6eaa70418ae70c5501deca6acebba62aaf04bf28f7ad59c2`

The authentic AI-native Causal artifact contains five explicit and two
materialized inferred triplets, two rules, two clusters, and one retained gap.
The authoritative `dotcausal.io.CausalReader` verifies its integrity.

## A240 — Threefish-256

A240 reconstructs the complete 256-bit master key after receiving 218 known
key bits and the 128-bit tweak.  The low 38 bits of `K0` are unknown; the
Threefish parity word `K4` is recomputed for every candidate.  The native Metal
implementation passes both official 72-round KATs and exact scalar/Metal
mapping gates before target execution.

- assignments executed: `274,877,906,944 / 274,877,906,944`
- recovered assignment: `68,427,043,728`
- recovered `K0` low 32 bits: `4,002,534,288`
- recovered `K0` bits 32--37: `15`
- factual/control models: `1 / 0`
- GPU / wall time: `860.7408324554563 / 861.8827188750729` seconds
- measured throughput: `319,350,374.2117696` candidates/second
- result SHA-256:
  `bde3c083d911d638fa54f78551c05c138d65a8764dfbbfef58dbd58fadb25e6a`

The authentic AI-native Causal artifact records the complete-enumeration,
independent-confirmation, and matched-control chains.  Its SHA-256 is
`3c7853c5728c6a98d87599d41585bb6af5cc25bb755a8919fc4e0b1745c2a813`.

## Exact scientific position

These are full-round executed residual-key recoveries and complete master-key
reconstructions inside their declared partial-known-key models.  Their search
cost is the complete residual domain, so the next distinct cryptanalytic gain
is a prospectively frozen strict-subset reader or a full-master-key solver,
not another statement about having executed all rounds.

The directly comparable public cryptanalytic literature remains
reduced-round: the 2023 differential-linear work reaches 13-round Speck32/64
key recovery and extends it to 14 rounds by guessing an additional 16 round-key
bits; the standard cipher has 22 rounds.  Published Threefish results include
related-key rotational analysis through 39 of 72 rounds for Threefish-256 and
reduced-round related-key key-recovery results for the wider variants.  The
A237 and A240 scopes are therefore new full-round commodity-hardware execution
points, while the literature attacks retain the separate distinction of a
structural advantage over generic search.

Primary references:

- https://eprint.iacr.org/2023/259.pdf
- https://eprint.iacr.org/2019/037.pdf
- https://www.iacr.org/archive/fse2010/61470339/61470339.pdf
- https://eprint.iacr.org/2009/438.pdf
- https://www.schneier.com/wp-content/uploads/2015/01/skein.pdf

## Next experiments

1. Complete A220's frozen ChaCha20 trajectory holdout and measure the exact
   cluster-permutation p-value without adaptation.
2. Train a target-blind outer-slice reader on disjoint known-key Speck W42 and
   Threefish W38 challenges, then freeze and execute only its strict subset on
   unseen challenges.
3. Preserve XOR relations natively in the full-key Speck32/64 SAT encoding;
   the current direct bit-blast baseline is only 11,068 variables and 35,648
   clauses but does not solve within the bounded local portfolio.


# SHAKE Capacity-to-Next-Rate Full-Round Jacobian Reader v1

## Result

A complete first SHAKE squeeze block reveals the post-permutation rate lanes
and leaves the capacity coordinates open.  Hold those known rate bits fixed,
flip one post-first-squeeze capacity bit, apply another complete 24-round
Keccak-f[1600] permutation, and observe the XOR delta in the next rate block.

For every tested base state, the resulting Boolean Jacobian has full capacity
rank:

| variant | response matrix | bases | observed ranks | unique signatures per base |
|---|---:|---:|---:|---:|
| SHAKE128 | 1,344 x 256 | 5 | 256,256,256,256,256 | 256/256 |
| SHAKE256 | 1,088 x 512 | 5 | 512,512,512,512,512 | 512/512 |

The six-edge `.causal` artifact stores the intervention recipe, complete GF(2)
rank test, and exact same-base signature Reader.  Confirmation re-opens the
artifact before generating the capacity response dictionaries.

Across ten bases, the Reader identifies all `3,840/3,840` single capacity-bit
interventions exactly.  The response signatures are dense:

- SHAKE128 means range from 668.80 to 672.82 changed bits out of 1,344;
- SHAKE256 means range from 543.78 to 545.56 changed bits out of 1,088.

Thus every capacity coordinate is locally observable as an independent
first-order direction in the next full-round rate output at all tested
post-first-squeeze states.

## Causal and representation controls

Each base uses sixteen fixed-point-free BvN label routes.  Across all 160 banks
there are zero correct bit labels.  Cyclically rotating the response lanes also
gives zero matches.

The signature dictionary is deliberately base-conditioned.  Querying each
base with the next base's dictionary gives zero known signatures across all
3,840 queries; every query is unmatched.  This localizes the result to the
Boolean derivative at the actual state rather than promoting one universal
capacity-bit codebook.

## Nonlinear interaction boundary

Full GF(2) Jacobian rank is a first-order statement, not a claim that the
24-round map is globally linear.  For 128 random two-capacity-bit
interventions per base, the experiment compares

```text
actual:     F(S xor e_i xor e_j)_rate xor F(S)_rate
linearized: D_i(S) xor D_j(S).
```

None of the 1,280 actual responses equals its linearized superposition.  Bit
agreement stays between 49.85% and 50.15% across all bases and variants.  The
result therefore retains both facts at once:

1. every single capacity direction is locally independent after a full
   permutation;
2. pair interventions immediately activate dense nonlinear interaction terms.

## Scope

The experiment uses instrumented single-bit interventions on the hidden
capacity coordinates of a known full internal base state.  It establishes
local differential observability and exact same-base reverse identification.
It does not claim that an ordinary pair of SHAKE output blocks by itself
supplies the unknown base-state capacity or a global linear inverse.

Correctness inherits the independent Keccak zero-state, FIPS 202, and
`hashlib` gates from the rate Reader.  Specification source:
[NIST FIPS 202](https://csrc.nist.gov/pubs/fips/202/final).

## Reproduction

```bash
PYTHONPATH=.:src .venv/bin/python \
  research/experiments/shake_capacity_jacobian_reader.py \
  --output research/results/v1/shake_capacity_jacobian_reader_v1.json \
  --causal-output research/results/v1/shake_capacity_jacobian_reader_v1.causal

PYTHONPATH=.:src .venv/bin/pytest -q \
  tests/test_shake_capacity_jacobian_reader.py
```

## Artifact hashes

- result JSON:
  `1d42fa8e06c72f60e9c1098ceb0004d56eaaf97e5dda919aee271384e7dc9049`
- six-edge executable `.causal`:
  `12b8443440120871346dc7b6888db471d19435b3225b445081acd3b9f1135bcc`

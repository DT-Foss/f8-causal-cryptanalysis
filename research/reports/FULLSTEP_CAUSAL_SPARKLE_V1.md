# SPARKLE Full-Step Projection and Linear-Order Reader v1

## Result

All three standard big-step SPARKLE permutations retain the same exact
endpoint projection at their final step:

```text
SPARKLE-256/10: output-right[128 bits] = post-Alzette-left[128 bits]
SPARKLE-384/11: output-right[192 bits] = post-Alzette-left[192 bits]
SPARKLE-512/12: output-right[256 bits] = post-Alzette-left[256 bits]
```

The `.causal` artifact stores the branch-local inverse-Alzette recipes and the
public final-step injections.  The experiment re-opens that artifact with
`CryptoCausalReader` and reconstructs the complete left half immediately
before the final full step while reading only the right half of the full
permutation output.

| variant | steps | factual half states | factual 64-bit branches | factual bits | 80 BvN routes: whole-state matches |
|---|---:|---:|---:|---:|---:|
| SPARKLE-256 | 10 | 40,000/40,000 | 80,000/80,000 | 5,120,000/5,120,000 | 0 |
| SPARKLE-384 | 11 | 40,000/40,000 | 120,000/120,000 | 7,680,000/7,680,000 | 0 |
| SPARKLE-512 | 12 | 40,000/40,000 | 160,000/160,000 | 10,240,000/10,240,000 | 0 |

Across the family this is `120,000/120,000` exact half states,
`360,000/360,000` exact 64-bit branches, and `23,040,000/23,040,000` exact
bits.  The 240 BvN routes contain 1,920,000 routed half-state comparisons and
produce neither a complete half-state match nor a complete 64-bit-branch
match.

This is an exact internal full-step relation and Reader inference result.  Its
scope is not enlarged into a statement about an external secret.

## Exact linear-layer orders

Complete binary-basis enumeration gives the minimal orders of the standard
SPARKLE linear layers:

| variant | state dimension | minimal order of `L` | Reader expression for `L^-1` |
|---|---:|---:|---:|
| SPARKLE-256 | 256 | 6 | `L^5` |
| SPARKLE-384 | 384 | 30 | `L^29` |
| SPARKLE-512 | 512 | 12 | `L^11` |

For every one of the 1,152 full-state basis vectors the stated power is the
identity.  Every proper divisor has a retained non-identity basis witness, so
the result is a minimal-order proof rather than a random-state cycle check.

The Reader obtains the full linear inverse by repeating the *forward* linear
layer `order-1` times, then runs inverse Alzette and removes the final step
injections.  On the same fresh inputs it reconstructs another
`120,000/120,000` complete pre-final-step states, covering 720,000 exact
64-bit branches and 46,080,000 exact bits.

## Four-word aggregate quotient

Let `LX,LY` be the XOR aggregates of the post-Alzette left branches and
`RX,RY` those of the right branches.  If the number `m` of branches per half
is even, the linear-layer quotient is

```text
(LX, LY, RX, RY) -> (LX xor RX, LY xor RY, LX, LY).
```

If `m` is odd, the cross-coordinate `ELL` terms remain:

```text
(LX, LY, RX, RY)
  -> (LX xor RX xor ELL(LY),
      LY xor RY xor ELL(LX),
      LX,
      LY).
```

Complete-basis verification establishes quotient orders `3, 10, 3` for
SPARKLE-256/384/512 respectively.  The proof checks both that the quotient
recurrence equals the aggregate of the full linear layer on all 1,152 state
basis vectors and that the claimed quotient powers are minimally the identity
on all 384 quotient basis vectors.

## Correctness gates

The implementation follows the SPARKLE Group's
[official `sparkle.c`](https://github.com/cryptolu/sparkle/blob/master/software/sparkle/sparkle.c),
raw-source SHA-256
`a670d9ae8084270eda2de955d4225212d01672778303ca16e33ef850da9a3c79`.
Before any confirmation it must satisfy three fixed zero-state outputs produced
by that hash-pinned C source and round-trip each through an independently coded
inverse:

```text
SPARKLE-256/10  c056d47e1c46af31...8c1d8681d626d0b2
SPARKLE-384/11  f3c2bf25fc53dd55...68419a5ff9e6b22
SPARKLE-512/12  4e22054039c1a4a9...6c1dee5b62efac8
```

Layer, step, and complete-permutation round trips are separately covered by
the focused test suite.

## Mechanism controls

Each of five fresh seed families contributes 8,000 full-permutation traces per
variant.  The factual recipe is compared with:

1. sixteen fixed-point-free BvN sample routes;
2. cyclically rotated output branches;
3. the final left half substituted for the required right half;
4. cyclically rotated Alzette constants;
5. one fewer forward linear-layer application;
6. the previous step's injection constants.

Controls 1--5 produce zero complete states and zero complete 64-bit branches;
their bit accuracies stay around 50%.  Control 6 behaves differently in the
predicted, localized way: branches unaffected by the two step injections remain
exact, but every complete reconstructed half is wrong.  This distinguishes the
public injection-localization check from a generic random-formula control.

## Reproduction

```bash
PYTHONPATH=.:src .venv/bin/python \
  research/experiments/sparkle_fullstep_causal.py \
  --output research/results/v1/sparkle_fullstep_causal_v1.json \
  --causal-output research/results/v1/sparkle_fullstep_causal_v1.causal

PYTHONPATH=.:src .venv/bin/pytest -q \
  tests/test_sparkle_fullstep_causal.py
PYTHONPATH=.:src .venv/bin/python scripts/validate_causal_artifacts.py
```

## Artifact hashes

- result JSON:
  `86a8bb340ca4207e18c2f675eb238c44e2e8518c94e43ed047ea6c57a6e9f2bd`
- 15-edge executable `.causal`:
  `7a8b9017be78edd351a9a44087686b6887af918cfd09e594719ab3bec13c9e00`

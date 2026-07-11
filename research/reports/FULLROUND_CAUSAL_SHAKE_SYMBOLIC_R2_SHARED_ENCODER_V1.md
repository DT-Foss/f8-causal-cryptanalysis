# SHAKE Symbolic-R2 Shared-Monomial Full-Round Encoder Frontier v1

## Result

A157 replaces the first generic suffix-round circuit in A156 with the complete
exact A155 R2 dictionary.  One constant, 24 linear variables, and all 276
quadratic monomials are shared across the 1,600 R2 output equations; only 1,598
state definitions remain because two coordinates are exact aliases.  The
unchanged R3--R24 suffix and all 1,344 final rate constraints are then compiled.

Four formulas are frozen before solver execution:

| Encoder | Input order | Quadratic-definition order | Formula bytes | Status | Decisions |
|---|---|---|---:|---|---:|
| `original_lazy` | original | first use | 8,902,451 | `unknown` | 20,649 |
| `original_frequency` | original | decreasing occurrence | 8,901,209 | `unknown` | 20,703 |
| `pivot_lazy` | A154 pivot | first use | 8,902,471 | `unknown` | 11,853 |
| `pivot_frequency` | A154 pivot | decreasing occurrence | 8,901,210 | `unknown` | 12,284 |

All four sequential one-thread Z3 4.15.4 runs return code zero at the uniform
120-second cap, with no external timeout, error, or model.  The smallest formula
is 184,524 bytes below A156's smallest systematic-R1 encoder and 285,792 bytes
below the canonical A152 formula.

The decisive observation is not formula length.  Merely changing the exact
input permutation on the same R2 representation changes the bounded traversal
substantially: pivot order reduces decisions by 42.6% on the lazy definition
plan and 40.7% on the frequency plan.  In contrast, reordering the same 276
quadratic definitions by occurrence changes decisions only slightly.  This
selects weighted input-coordinate ordering as the next experiment.

## Exact shared prefix

The original R2 polynomial state is

```text
d30c074bbfe45efce76d8142e37ff9ec93608df839dffb0ca25540d2f7ae1752
```

and contains exactly 301 global monomials.  A155 already proves that its 276
quadratic masks are every edge of K24.  A157 defines each quadratic product
once, uses the 24 solver inputs directly for singleton monomials, aliases R2
state coordinates 516 and 917 directly, and defines every remaining R2 state
coordinate as a native n-ary XOR.  Each formula has 121,578 declared variables
and 122,898 assertions before rendering the model query.

For `first_coordinate_use`, a quadratic definition is created when its first
ascending state coordinate references it.  For
`decreasing_coordinate_occurrence_then_numeric_mask`, all 276 definitions are
predeclared by decreasing number of R2 state equations containing the mask,
with numeric mask as the exact tie-break.  Observed quadratic occurrence ranges
from 35 to 88 coordinates.

## Frozen formulas

The canonical direct-R2 formula is rebuilt but not executed as A157:

```text
bytes   8,902,576
SHA-256 44d326f7b2b14554bea69011b783226544a9b104c35fb1763c784441f2bd4586
```

The four executed formula hashes are:

- `original_lazy`:
  `3ee089023b25d5752a071fa58b4ad98ae13265a15f741606fa59d474741694da`;
- `original_frequency`:
  `390201f57d10fb3d186b06d93f4d6e1b5c7540f44d5029e0c2b6a2ea0b1f3b5a`;
- `pivot_lazy`:
  `286a4dd883a6ec732ecb75953be2fb7ce3d2b6295b028acbbcfdf50597bd7756`;
- `pivot_frequency`:
  `4acc464736c2e1a6cc1592cba0d881448005698dce9d2a639e13647b1a652ed5`.

The complete pre-execution plan hash is
`500ab417b3ecab00024b621f2797babfa050270f0cd63556fd0002ef8db77cbf`.

## Boundaries and verification

A157 hash-gates the A155 K24/301-monomial result
`ead5673a7a7d539cea2c924175e3e80190b5ae9d2a23f28555ddd1f38925ae80`
and the complete A156 systematic-R1 frontier
`703e8c5c68882a144f60e29867e99f37b5b8bba42ffa70b0aee922d0cb2551ae`.

Every pivot-basis model would be mapped through the declared exact inverse
permutation before an independent all-1,344-rate-bit check.  SAT without a
complete 24-bit model fails closed.  No solver emitted an assignment.  The
instrumented value 9,279,571 is read only after every encoder execution and is
not used in formula construction, execution order, monomial order, or solver
input.

## Retained bindings

- result JSON:
  `682c9c70e79702f15e54972c04a26372539e3b3e3473fa6230e053dd898c6ea4`;
- Causal artifact:
  `3fbc91bd51fabce6f72a12b5aa5c17032a9c4a81ad86154eaed6bb99a25856f1`;
- canonical Causal graph:
  `af9d3fd28501bb48a4597bf77af0afb3011a9a91fb759a252b70ba23b420c570`.

The four-triplet Causal chain is reopened with `CryptoCausalReader` and links
A155's exact dictionary through the A156 boundary, frozen formula plan, and
uniform full-round execution.

## Reproduction

```bash
PYTHONPATH=.:src .venv/bin/python \
  research/experiments/shake_symbolic_r2_shared_monomial_encoder_frontier.py \
  --analyze-only

PYTHONPATH=.:src .venv/bin/pytest -q \
  tests/test_shake_symbolic_r2_shared_monomial_encoder_frontier.py
```

Full sequential execution:

```bash
rm -rf build/shake-r2-a157
PYTHONPATH=.:src .venv/bin/python \
  research/experiments/shake_symbolic_r2_shared_monomial_encoder_frontier.py \
  --work-dir "$PWD/build/shake-r2-a157"
```

## Consequence

The representation change is real and measurable, but the new hard signal is
coordinate order: the same exact R2 equations traverse very differently under
the original and A154 pivot permutations, while monomial-definition order is a
small perturbation.  A158 should therefore derive several assignment-free
input orders from the weighted K24 occurrence matrix and execute them on the
retained shared-R2 representation.

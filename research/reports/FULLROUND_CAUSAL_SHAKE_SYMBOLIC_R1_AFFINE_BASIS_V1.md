# SHAKE Symbolic-R1 Exact Affine Basis Reader v1

## Result

A154 converts the prospective A152 R1 boundary into an exact constructive
statement.  For the hash-derived SHAKE128 capacity window `[143,167)`, all
1,600 R1 coordinate equations are affine in the 24 hidden input coordinates.
The resulting `1600 x 24` GF(2) coefficient matrix has rank **24** and input
nullity **0**.  The R1 handover therefore retains every hidden degree of
freedom; its affine image has dimension 24 and satisfies 1,576 independent
affine output relations.

More strongly, the lexicographically first independent output-row basis is
systematic.  After XORing away each known output constant, the selected 24 R1
state coordinates are a permutation of the 24 input bits, rather than general
linear mixtures.  They occur at state coordinates

```text
3, 5, 6, 10, 14, 17, 18, 60, 61, 63, 73, 75,
76, 77, 79, 80, 123, 126, 128, 129, 130, 132, 135, 136
```

and first reach full rank at coordinate 136.  The exact permutation from pivot
delta index to input coordinate is

```text
8, 10, 11, 15, 19, 22, 23, 1, 2, 4, 14, 16,
17, 18, 20, 21, 0, 3, 5, 6, 7, 9, 12, 13
```

This is an executable inverse coordinate system for the R1 interface.  It does
not by itself expose those internal state bits from the final rate observation;
it supplies exact replacement variables for the full-round suffix encoder.

## Exact construction

The Reader hash-gates the retained A152 JSON, regenerates only its cleared
template, and recompiles one exact symbolic Keccak round.  It never imports the
final-rate target, solver outcome, or instrumented assignment.  Every
polynomial is reconstructed from its extracted constant and singleton
coefficients before any rank claim is accepted.

The artifact keeps two different notions explicit: `constant_term_one_count`
is 788 and counts ANF constant coefficients equal to one, whereas
`zero_linear_row_count` is 1,098 and counts input-independent output
coordinates.  The labels do not conflate an affine offset with a constant
function.

The ascending output scan retains a row exactly when GF(2) reduction proves it
independent of all earlier retained rows.  Gauss-Jordan elimination then builds
the inverse of the selected `24 x 24` matrix.  Both products are checked against
the identity.  A separate 64-assignment suite containing zero, every unit
vector, all ones, and 38 hash-derived assignments compares three independent
representations:

1. the original symbolic Boolean-ring round;
2. direct affine-matrix evaluation;
3. the independent bit-sliced Keccak round.

All 307,200 compared state bits match, and every selected-output inverse
roundtrip recovers its input assignment.

## Retained bindings

- A152 anchor JSON:
  `0e01e3e6ff0b9a80ff66ad6614f846305188d96a4497ca38857eac81097a1561`;
- R1 polynomial state:
  `e0c8856814a8fa2a48268ccb580ad0b94decc3879915c300ff66114cfd61025d`;
- coefficient matrix:
  `b79deb595d61764a1eff90120696c462c80bb5bd774605af54947c5b5a4040a0`;
- affine map:
  `abbd971560922a22a4651dd8229411dd6f157e3f8039259a0a16b75e4ed9f0a6`;
- selected basis:
  `3c6d5ad1b339c06b720297bc1046f5d654b1c5e86445e80f6ef858b099f46830`;
- inverse matrix:
  `4dcd51c69f4677495b36e24e8418a2db1a405342baf683e76175a1e997672dce`;
- result JSON:
  `108cbcadcbd7cfc3831712b8d2073aab42d42cca098db162d1d63627882d21dd`;
- Causal artifact:
  `0bc86a07227c59f33008f709f0e114acf3f7b8457532f9ff508d4037e071c5fd`;
- canonical Causal graph:
  `c0f8255ca4aa8f7bc3d61a527392cc2294624b5849efac331f23914de6418d0b`.

The four-triplet Causal chain is reopened with `CryptoCausalReader` and its
provenance is checked after writing.

## Reproduction

```bash
PYTHONPATH=.:src .venv/bin/python \
  research/experiments/shake_symbolic_r1_affine_basis_reader.py

PYTHONPATH=.:src .venv/bin/pytest -q \
  tests/test_shake_symbolic_r1_affine_basis_reader.py
```

The test suite also reruns A154 into temporary paths and requires byte-identical
JSON and Causal hashes.

## Consequence

The empty A152 R1 interaction graph is not information loss.  It is a
systematic affine embedding of all 24 unknowns.  The next exact question is
where pairwise interactions first appear when the same relation is expressed
in these pivot variables; A155 answers that at R2.

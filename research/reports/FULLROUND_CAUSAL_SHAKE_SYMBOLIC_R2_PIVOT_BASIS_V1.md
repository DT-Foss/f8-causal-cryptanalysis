# SHAKE Symbolic-R2 Pivot-Basis Interaction Reader v1

## Result

A155 expresses every exact A152 R2 state equation in the verified A154 pivot
delta basis.  The original and transformed interfaces both contain precisely
the global monomial dictionary

```text
1 constant + 24 linear variables + 276 quadratic pairs = 301 monomials.
```

Every possible pair of the 24 variables occurs.  The R2 interaction graph is
therefore exactly the complete graph **K24**, with 276 edges, maximum
independent-set size 1, minimum vertex-cover size 23, and 24 minimum covers.
Any vertex-cover linearization at this split leaves only one free coordinate.

The A154 pivot deltas are a pure input permutation after their known constants
are removed.  Exact Boolean-ring substitution consequently permutes the R2
variables without changing its interaction graph.  Pairwise interaction
saturation is localized sharply between the affine, edgeless R1 interface and
R2; it is not an artifact of the original input-coordinate labels.

## Exact checks

The Reader hash-gates the A154 result and decodes its retained two-sided
inverse.  It then:

1. recompiles the 1,600 exact R2 polynomials from the A152 cleared template;
2. substitutes `x_i = XOR_j B^-1[i,j] z_j` into every ANF coordinate;
3. checks that the transformed edge set equals the original edge set mapped by
   the declared A154 permutation;
4. compares the observed 276 edges with all `24 choose 2` unordered pairs;
5. evaluates original-symbolic, pivot-symbolic, and independent two-round
   bit-sliced Keccak states on 64 deterministic assignments.

All 307,200 three-way state-bit comparisons match.  Neither the final-rate
target nor the instrumented A152 assignment participates in construction or
verification.

## Retained bindings

- A154 anchor JSON:
  `108cbcadcbd7cfc3831712b8d2073aab42d42cca098db162d1d63627882d21dd`;
- original R2 polynomial state:
  `d30c074bbfe45efce76d8142e37ff9ec93608df839dffb0ca25540d2f7ae1752`;
- pivot-basis R2 polynomial state:
  `556506048288ec925953fe8044f22cec3b4913e7259529d15568c53d1ddce2e7`;
- complete interaction-edge list:
  `7c4ecdea68be06db8accbd353e7d36b3f2d7e4428c3af87e4fd7dfa03748bdad`;
- complete-graph proof:
  `69a71e73eda6bfbc9b6aafc236bff1b5d15129ff71b0a1ec8ca9d798d5cb5a96`;
- R1-to-R2 transition:
  `73cef88a935c293f24291dd5f1f9b9833689df454b1e2865c7a6f100b69185c8`;
- result JSON:
  `ead5673a7a7d539cea2c924175e3e80190b5ae9d2a23f28555ddd1f38925ae80`;
- Causal artifact:
  `9fb214d4348cb13304a0af15022b4699d646f9c406ce94c5c5bc9b8d24756d23`;
- canonical Causal graph:
  `baa6c92ef15f075361071e7112363f906b49cc07139f4cbdc1f2c133b4e8be7f`.

The four explicit Causal triplets form a verified provenance chain from A154's
systematic basis through exact substitution and K24 proof to the localized
round transition.

## Reproduction

```bash
PYTHONPATH=.:src .venv/bin/python \
  research/experiments/shake_symbolic_r2_pivot_basis_reader.py

PYTHONPATH=.:src .venv/bin/pytest -q \
  tests/test_shake_symbolic_r2_pivot_basis_reader.py
```

The retained test reruns the complete Reader into temporary paths and requires
byte-identical JSON and Causal hashes.

## Consequence

R2 graph partitioning is exhausted structurally on this instance: its exact
minimum cover fixes 23 of 24 variables.  The remaining executable leverage is
the R1 side of the boundary.  A156 therefore reuses the systematic pivot
variables directly and removes redundant constant and alias definitions before
compiling the unchanged R2--R24 suffix.

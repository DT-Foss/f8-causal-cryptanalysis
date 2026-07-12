# A188 Structural CNF Ordering Calibration v1

A205 derives 23 pairwise-distinct, semantics-preserving variable orders from
the exact A188 CNF graph and evaluates every order under CaDiCaL's default and
reverse modes.  The complete frozen matrix contains 46 observations: 16 `sat`
and 30 `unknown`.  Every SAT witness decodes to the same 40-bit A188 assignment,
independently reproduces all 4,096 target bits, and rejects the control.

Twelve non-control structural candidates return a confirmed model.  The
formula-atlas transfers used here include occurrence and adjacency degrees,
unit/output/key distances, signed sum/difference distance, layer parity, and
Fiedler orderings.  `bidirectional_min_distance` is the unique structural
candidate that succeeds in both default and reverse modes, so it is selected
prospectively for A206 by the frozen robust-both-mode rule.

The retained r2 revision corrects two information-boundary metadata fields:
the known-positive A188 model is embedded for post-witness confirmation, but is
not used to construct an order or supplied to the solver.  This correction
changes no protocol execution, solver observation, confirmation, comparison,
or candidate count: the matrix remains 46 observations, 16 SAT results, and 12
structural candidates.

```text
protocol  53a7f8a7527218e8db386d62cbc082466050b5b62eee3798edb808602e058730
runner    605310ffeb5836f609ad3ca9a5079b56479fe299ed8fafb39ff54d7859c642df
JSON      b3c76fca5a9ffabf3bd2c2bf812c8ef66b9be56bc7f9936a9525fd5e8d3c7f7f
Causal    d17ed98433e70ecfafd75ce895372aa7f150cb2b178c853697ee8406f0582f80
graph     8dddd0764910b940627c65e2b21b2e4e0e367db388d481954e70c3213c56fec0
```

![A205 structural ordering calibration](../results/v1/chacha20_a205_structural_ordering_calibration_v1.svg)

Fast retained verification (no solver execution):

```bash
PYTHONPATH=.:src python -m pytest -q \
  tests/test_chacha20_a188_cnf_structural_ordering.py
```

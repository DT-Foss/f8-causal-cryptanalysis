# SHAKE Boolean Reader and Prefix-Observability Frontier v1

## Result

Two exact representations now explain both sides of the SHAKE state-window
problem:

1. a bit-level Tseitin CNF of every Theta, Rho, Pi, Chi, and Iota operation in
   all 24 Keccak-f[1600] rounds;
2. a complete candidate truth space that measures, after every selected round,
   which rate coordinates are fixed under an actual assignment prefix.

The CNF Reader reconstructs and proves uniqueness for 4-, 8-, and 12-coordinate
SHAKE128 windows from the complete 1,344-bit next-rate block.  The 16-coordinate
instance reaches the configured 120-second boundary without returning a model.

| variable coordinates | CNF variables | clauses | Reader decisions | reconstructed assignment | second assignment |
|---:|---:|---:|---:|---:|---|
| 4 | 139,952 | 525,709 | 57,319 | 11 | proved absent |
| 8 | 142,392 | 534,852 | 48,477 | 66 | proved absent |
| 12 | 143,583 | 539,213 | 586,636 | 3,464 | proved absent |
| 16 | 144,125 | 541,204 | configured boundary | — | not queried |

Every returned assignment equals the independently instrumented state.  The
second query adds one exact blocking clause and returns UNSAT for widths 4, 8,
and 12.  Solver threads are fixed to one and the CHB branching heuristic is
serialized in the result.  Wall-clock fields are deliberately excluded from
the hashed artifact; decisions, conflicts, propagations, seeds, statuses, CNF
dimensions, and CNF hashes are retained.

## Exact round localization

The 16-coordinate truth-space Reader evaluates one deterministic window per
SHAKE variant, with the first-squeeze-state complement fixed, and exhausts all
65,536 assignments for each. It conditions them on the actual low-order prefix.
The number of rate coordinates already fixed over every remaining suffix is:

| round | SHAKE128, no prefix | SHAKE256, no prefix | interpretation |
|---:|---:|---:|---|
| 0 | 1,344 | 1,088 | the variable window is initially confined to capacity |
| 1 | 1,060 | 871 | most rate coordinates remain independent of the window |
| 2 | 8 | 10 | only a small deterministic coordinate set remains |
| 3 | 0 | 0 | every rate coordinate varies over the complete window |
| 24 | 0 | 0 | the zero-constant frontier persists at the endpoint |

At the full-round endpoint, fixing up to 12 of the 16 window coordinates still
leaves zero rate coordinates constant.  Constants appear only when three or
fewer coordinates remain:

| remaining coordinates | SHAKE128 observed / random expectation | SHAKE256 observed / random expectation |
|---:|---:|---:|
| 4 | 0 / 0.0410 | 0 / 0.0332 |
| 3 | 15 / 10.5 | 10 / 8.5 |
| 2 | 184 / 168 | 135 / 136 |
| 1 | 701 / 672 | 534 / 544 |
| 0 | 1,344 / 1,344 | 1,088 / 1,088 |

The endpoint therefore follows the random-function coordinate-constancy law
closely.  A prefix branch has no single fixed rate coordinate available for
early rejection until only about three suffix coordinates remain.

## Output-coordinate discrimination

The same complete truth space also counts assignments matching the actual
target prefix at round 24:

| constrained rate bits | SHAKE128 survivors | SHAKE256 survivors |
|---:|---:|---:|
| 8 | 229 | 262 |
| 16 | 1 | 2 |
| 32 | 1 | 1 |

Thus the output constraints discriminate complete assignments immediately,
while partial-input branches do not expose fixed output coordinates.  This
separates two facts that were previously conflated: the relation is highly
observable, but ordinary coordinate-wise branch propagation receives no early
certificate after round 3.

## Mechanistic conclusion

The Boolean Reader is exact and it does reconstruct small windows, but it does
not improve the native candidate-axis scaling.  Its internal decision count is
already much larger than `2^k` at the solved widths, and 16 coordinates reach
the configured boundary while native bit slicing handles 32 coordinates.

The prefix frontier explains this behavior directly.  A useful exponent change
must propagate richer joint constraints—affine parity, higher-order relations,
or a round split—not merely wait for individual output coordinates to become
constant.

## Independent gates

- The round-by-round bit-sliced composition matches both the direct bit-sliced
  implementation and the independent scalar Keccak core on all
  `102,400/102,400` state bits.
- Every truth-space row checks all `2^16` assignments, not a sample.
- The CNF contains exact Tseitin equivalences for all 24 rounds and constrains
  the complete SHAKE128 rate.
- The SHAKE128-only CNF graph contains exactly its two executed edges; the
  two-variant prefix graph contains four.  Both are reopened with
  `CryptoCausalReader` and pass provenance validation.

## Reproduction

```bash
./scripts/reproduce_shake_solver_frontier.sh
```

Focused tests:

```bash
PYTHONPATH=.:src .venv/bin/pytest -q \
  tests/test_shake_boolean_cnf_reader.py \
  tests/test_shake_prefix_observability_frontier.py
```

The CNF reproduction uses Z3 4.15.4.  The truth-space frontier requires only
the repository's standard Python/NumPy environment.

## Artifact hashes

- Boolean CNF result JSON:
  `4281b0ab9eb6156cc428b34cd14216cf5c465ba786c85a0332bb8f71eb0e92dc`
- Boolean CNF two-edge `.causal`:
  `829f4f7f5022ef496f900880a7ecbc09ef1fbb38ce2cda6dd2da457c4f7dde76`
- Prefix-frontier result JSON:
  `760311f15801901167295e7b226555e5e8e164cec5a6672631d48a722e025e69`
- Prefix-frontier four-edge `.causal`:
  `a2c907f75ea75a1099e3c4f518327c5f2731af3e1cdfa0c89d8e16c77809362c`

# SHAKE Symbolic-R1 Z3 Strategy Frontier v1

## Result

A144 compares six predeclared Z3 processing routes on the byte-identical A138
width-16 SHAKE128 symbolic-R1 formula.  Every route first passes a width-four
syntax and semantic gate.  On width 16, the retained native-XOR `QF_UF`
default route is the only independently verified `sat` result: it returns
assignment 35,837 in 4,701 decisions and matches all 1,344 next-rate bits.
`QF_FD` and four AIG-based routes return `unknown` at the equal 60-second
limit.  Strategy selection excludes wall time and uses verified status,
decision count, then the frozen portfolio order.

| route | width-16 result | decisions |
|---|---|---:|
| `qf_uf_default_retained` | `sat`, assignment 35,837, complete-rate check | 4,701 |
| `qf_fd_default` | `unknown` | 62,001 |
| `aig_sat` | `unknown` | not emitted |
| `aig_sat_chb` | `unknown` | not emitted |
| `aig_sat_cutxor` | `unknown` | not emitted |
| `propagate_aig_sat` | `unknown` | not emitted |

The selected route is transferred unchanged to the canonical width-20 formula.
Its first query returns `unknown` after 11,124 decisions at the 120-second
limit.  No blocked second query is issued because no first model is available.

A146 combines this hash-gated strategy choice with A143's complete
formula-graph Structural-6 plan.  It renders the same `QF_UF` route for all 64
disjoint width-20 subspaces, uses five one-thread workers and a 120-second local
limit, and records 358,361 decisions in total.  All 64 subspaces return
`unknown`; no candidate is emitted.  The combination therefore shows that the
winning monolithic width-16 processing route does not by itself resolve the
six-coordinate width-20 partition under this schedule.  It does not alter the
exact relation or the complete partition plan.

## Frozen selection and transfer

The six-route portfolio is declared in source order before measurement.  A144
accepts A138 only at JSON SHA-256
`428e17c9d959e425f417b0c3ce15bd1e9065b8284229ce78f7dd8cb4dce0b078`
and regenerates exact width-16 and width-20 SMT bodies before changing only the
logic declaration and `check-sat` processing form.  The canonical width-20 SMT
hash is
`66aa82020b4dd2b4d21f3065c99ca6f7c9224ab1ab9765f686121f2fe7f8618f`.
Neither the instrumented assignment nor observed wall time participates in
route selection.

A146 accepts A144 and A143 only at their complete JSON hashes.  The selected
route is `QF_UF` with plain `(check-sat)`, the fixed coordinates remain
`[4, 9, 12, 15, 17, 18]`, and the 64 rendered subspace formulas are bound by
manifest SHA-256
`f4139410cde1f4bcb52d63bd073de2abc66425223c65729d1cb0d5e5aa385571`.
No outcome-dependent route or branch selection occurs.

## Reader and verification gates

A144 and A146 each store an exact three-triplet `.causal` provenance chain.
Their Readers bind the canonical formulas, declared strategy choice, complete
partition plan, bounded observations, and independent candidate check.  Both
files are reopened and pass canonical graph, triplet, hash-binding, and
provenance verification.  A146's candidate gate is vacuous only because no
solver assignment is returned; its independent 1,344-bit evaluator is covered
by direct tests and a reduced two-subspace execution test.

## Reproduction

```bash
PYTHONPATH=.:src .venv/bin/python \
  research/experiments/shake_symbolic_r1_z3_strategy_frontier.py \
  --output research/results/v1/shake_symbolic_r1_z3_strategy_frontier_v1.json \
  --causal-output research/results/v1/shake_symbolic_r1_z3_strategy_frontier_v1.causal

PYTHONPATH=.:src .venv/bin/python \
  research/experiments/shake_symbolic_r1_z3_structural6_partition_reader.py \
  --output research/results/v1/shake_symbolic_r1_z3_structural6_partition_reader_v1.json \
  --causal-output research/results/v1/shake_symbolic_r1_z3_structural6_partition_reader_v1.causal

PYTHONPATH=.:src .venv/bin/pytest -q \
  tests/test_shake_symbolic_r1_z3_strategy_frontier.py \
  tests/test_shake_symbolic_r1_z3_structural6_partition_reader.py
```

## Artifact hashes

- A144 JSON:
  `da4632f92cdd30d8d397bab96a23f5463c686d78965263747c788a60d6c73420`
- A144 `.causal`:
  `77f0bfe3618f8055eb8d5c8a8159c4230fa6837ffd8ff9734a5652ab8e2e69c0`
- A146 JSON:
  `a0ca67228c52f6e74113409842853362814de20b9dade529f7003f466947c311`
- A146 `.causal`:
  `9b9a24aeb7b695b6273bc21109fc2e45efcea45527898ccd40269527e9b5773e`

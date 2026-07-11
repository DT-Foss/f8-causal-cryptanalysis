# SHAKE Symbolic-R1 Structural-Depth Frontier v1

## Result

A143 and A145 turn the width-20 SHAKE128 R1 quadratic graph into a controlled
partition-depth experiment.  A143 selects the unique six-coordinate
maximum-cover set `[4, 9, 12, 15, 17, 18]`, covering 20 of the graph's 28
quadratic edges, then executes all 64 disjoint assignments of those six
coordinates.  All 64 branches return `unknown` at the retained 30-second local
limit; the plan covers the complete `2^20` assignment space and was frozen
before any branch outcome or instrumented assignment was available.

A145 then measures one posthoc-conditioned branch at each predeclared graph
depth 4, 6, 8, and 10 under a uniform 60-second limit.  Coordinate selection is
still graph-only, but the fixed values are projections of the known canonical
assignment.  The first independently confirmed model appears at depth eight.

| depth | selected coordinates | covered / residual edges | free coordinates | status | decisions | assignment |
|---:|---|---:|---:|---|---:|---:|
| 4 | `[4, 9, 17, 18]` | 14 / 14 | 16 | `unknown` | — | — |
| 6 | `[4, 9, 12, 15, 17, 18]` | 20 / 8 | 14 | `unknown` | — | — |
| 8 | `[1, 2, 4, 9, 10, 12, 15, 18]` | 24 / 4 | 12 | `sat` | 1,442 | 227,581 |
| 10 | `[1, 2, 4, 7, 9, 10, 12, 15, 17, 18]` | 28 / 0 | 10 | `sat` | 773 | 227,581 |

Both returned assignments pass an independent scalar Keccak-f[1600]
evaluation against all 21 next-rate lanes, or 1,344 bits.  A145 therefore
localizes the minimum successful posthoc-conditioned depth in this declared
sequence to `k=8`.  It is a mechanism-localization experiment: because each
branch value is supplied from the instrumented assignment, A145 is not an
assignment-free search.  A147 separately tests whether the `k=8` breadcrumb
can drive assignment-free model finding.

## Exact structural construction

Both attempts regenerate the A138 width-20 symbolic-R1 system and require its
unpartitioned SMT SHA-256 to equal

```text
66aa82020b4dd2b4d21f3065c99ca6f7c9224ab1ab9765f686121f2fe7f8618f
```

The R1 prefix has degree at most two.  Its 28 undirected quadratic interaction
edges have SHA-256
`06b168eb69c5a6687e0f7f001bfdf178ce24e28b2b312a84758bfe872d1b9bda`.
For every depth, the selector enumerates every coordinate subset, maximizes the
number of edges incident to the subset, and chooses the lexicographically first
maximizer.  The sequence is completed before branch values are projected.

A143 evaluates all 38,760 six-coordinate subsets.  Its maximum is unique and
the resulting 64 fixed patterns are ascending, pairwise disjoint, and complete.
Five one-thread workers execute the plan.  The absence of a returned model at
30 seconds is retained as a precise resource observation and as the motivation
for separating structural depth from solver strategy.

A145 reuses the exact A141 `k=4` measurement because it already has the required
60-second limit.  It reruns `k=6` because A143 used 30 seconds, then executes
`k=8` and `k=10`.  Every depth is measured even after the first successful
depth, so the 1,442-to-773 decision change is recorded without early-selection
bias.

## Reader and functional gates

Each artifact carries a three-triplet `.causal` chain binding graph
construction, bounded branch execution, and independent candidate evaluation.
The files are reopened with `CryptoCausalReader`; their canonical graph hashes,
explicit triplets, and provenance all pass.  The runners additionally gate the
Keccak-f[1600] zero-state vector, embedded SHAKE vectors, complete `hashlib`
rate blocks, the A138 formulation hash, and the preceding A141/A143 artifact
hashes used by A145.

## Reproduction

```bash
PYTHONPATH=.:src .venv/bin/python \
  research/experiments/shake_symbolic_r1_structural6_partition_reader.py \
  --output research/results/v1/shake_symbolic_r1_structural6_partition_reader_v1.json \
  --causal-output research/results/v1/shake_symbolic_r1_structural6_partition_reader_v1.causal

PYTHONPATH=.:src .venv/bin/python \
  research/experiments/shake_symbolic_r1_structural_depth_frontier.py \
  --output research/results/v1/shake_symbolic_r1_structural_depth_frontier_v1.json \
  --causal-output research/results/v1/shake_symbolic_r1_structural_depth_frontier_v1.causal

PYTHONPATH=.:src .venv/bin/pytest -q \
  tests/test_shake_symbolic_r1_structural6_partition_reader.py \
  tests/test_shake_symbolic_r1_structural_depth_frontier.py
```

## Artifact hashes

- A143 JSON:
  `f39309d81d31d4b0615c6fbbd3676eadd53fa15ecf5c9e3ad34d7f5f79112f3d`
- A143 `.causal`:
  `480f7de77eb28e5110fa507b2ddd1f846736247c3a57852cb0fd84852c662ce4`
- A145 JSON:
  `c1b53e27f864c084fb0d64b04f591e22c520aec13578340e0aeda650f8fdec7c`
- A145 `.causal`:
  `fbc4e949e81d38be7be7d58a9d14614322587e01d641b5e28b741ed993d24314`

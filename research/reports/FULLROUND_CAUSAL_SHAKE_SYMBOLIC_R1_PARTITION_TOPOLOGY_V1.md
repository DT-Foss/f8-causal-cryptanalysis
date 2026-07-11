# SHAKE Symbolic-R1 Partition Topology v1

## Result

A139--A141 compare three complete, disjoint four-coordinate partitions of the
same 20-coordinate SHAKE128 R1 constraint system.  Each plan contains all 16
assignments of its four fixed coordinates, leaves exactly 16 free coordinates
per subspace, and executes with five one-thread workers and a 60-second local
limit.  All 48 subspaces return `unknown`; none returns a model or a branch
certificate.

| attempt | fixed coordinates | construction | branch statuses |
|---|---|---|---|
| A139 | `[0, 1, 2, 3]` | positional low four | 16 `unknown` |
| A140 | `[16, 17, 18, 19]` | orthogonal positional high four | 16 `unknown` |
| A141 | `[4, 9, 17, 18]` | lexicographic max-cover set from the exact R1 quadratic graph | 16 `unknown` |

Thus fixing four coordinates is insufficient under this exact representation
and resource schedule whether the coordinates are low, high, or selected by
maximum quadratic-edge coverage.  The free dimension is identical in all
three experiments, yet it does not determine solver work: A136 previously
returned the 16-coordinate model from one R2 branch, while these width-20 R1
subspaces with the same 16 free coordinates do not resolve within their local
limits.  Constraint topology and the surrounding fixed complement therefore
remain part of the measured problem.

These are exact representation/resource boundaries.  They do not establish
ambiguity of the SHAKE state relation and do not describe wider SHAKE instances
as generally resistant to reconstruction.

## Common formulation and neutral plans

All three attempts regenerate the A138 width-20 system and require its
unpartitioned SMT SHA-256 to equal

```text
66aa82020b4dd2b4d21f3065c99ca6f7c9224ab1ab9765f686121f2fe7f8618f
```

A138 itself is accepted only at JSON SHA-256
`428e17c9d959e425f417b0c3ce15bd1e9065b8284229ce78f7dd8cb4dce0b078`.
The regenerated interface has degree at most two, 49 shared monomials, 1,278
coordinate coefficients, 126,768 Boolean variables, 128,092 assertions, and
the complete 1,344-bit next-rate observation.  Each subspace differs only by
four unit constraints on that same system.

Every plan is generated before its solver results are available.  The 20-bit
instrumented assignment is absent from plan construction and selection, and
the target end-state bits are not inputs to the A141 coordinate selector.  The
posthoc assignment 227,581 and its branch values 13/3/5 for A139/A140/A141 are
recorded only after construction; they do not choose a branch or coordinate
set.

## Formula-graph selection

A141 extracts the undirected variable graph from every degree-two monomial in
the exact R1 prefix formulas.  The graph has 28 edges.  It evaluates all 4,845
four-coordinate subsets, scores a subset by the number of quadratic edges with
at least one selected endpoint, and uses the lexicographically first maximum.

- maximum covered edges: 14 of 28;
- maximizing sets: 14;
- selected coordinates: `[4, 9, 17, 18]`;
- edge-list SHA-256:
  `06b168eb69c5a6687e0f7f001bfdf178ce24e28b2b312a84758bfe872d1b9bda`;
- selection SHA-256:
  `ce5f2463840a3de57a5886b3064fc74ef207d46bc30385b0a340dadb2f5d36c8`.

The result removes three sufficient-predictor hypotheses at this resource
point: low position, high position, and static maximum R1 edge coverage do not
by themselves make a four-coordinate split resolve.  The next retained
breadcrumb is a solver-aware decomposition that changes more than coordinate
location alone—for example a deeper partition or a cut objective measured on
the explicit suffix constraints—while preserving the same hash-gated R1
relation.

## Reader artifacts

Each `.causal` file stores a three-edge executable provenance chain: construct
the complete plan, execute every bounded subspace, and independently evaluate
any returned candidate.  No candidate edge is populated in these runs because
all branches return `unknown`.  Every file is reopened with
`CryptoCausalReader`; all three graphs contain only explicit triplets and pass
their provenance gates.

## Reproduction

```bash
PYTHONPATH=.:src .venv/bin/python \
  research/experiments/shake_symbolic_r1_partition_scaling_reader.py \
  --output research/results/v1/shake_symbolic_r1_partition_scaling_reader_v1.json \
  --causal-output research/results/v1/shake_symbolic_r1_partition_scaling_reader_v1.causal

PYTHONPATH=.:src .venv/bin/python \
  research/experiments/shake_symbolic_r1_upper_partition_reader.py \
  --output research/results/v1/shake_symbolic_r1_upper_partition_reader_v1.json \
  --causal-output research/results/v1/shake_symbolic_r1_upper_partition_reader_v1.causal

PYTHONPATH=.:src .venv/bin/python \
  research/experiments/shake_symbolic_r1_structural_partition_reader.py \
  --output research/results/v1/shake_symbolic_r1_structural_partition_reader_v1.json \
  --causal-output research/results/v1/shake_symbolic_r1_structural_partition_reader_v1.causal

PYTHONPATH=.:src .venv/bin/pytest -q \
  tests/test_shake_symbolic_r1_partition_scaling_reader.py \
  tests/test_shake_symbolic_r1_upper_partition_reader.py \
  tests/test_shake_symbolic_r1_structural_partition_reader.py
```

## Artifact hashes

- A139 JSON:
  `443e7db3ebd72c4d916b6c688443c27aeb696746db676624b77891722213ab8c`
- A139 `.causal`:
  `24b82c0cb1a2c46d2dd038097179b960131a940d19fe275f542819942dc896a6`
- A140 JSON:
  `f80d3c3581009e09461ed0a5dd963a6498572961b3c63507f5397eb9404db4d4`
- A140 `.causal`:
  `4a50cafcadae055be00e71b4e8cc93bf8d9fbc81baf6572eb074e89902a07461`
- A141 JSON:
  `0a06caf3a2077f2a0408f7d299eb4fd3e5e6204dd66129d969f347637b823171`
- A141 `.causal`:
  `b2ba713280a53822d1725365915f5fd8dd1f9a30527cf5c1d47b368a725813f5`

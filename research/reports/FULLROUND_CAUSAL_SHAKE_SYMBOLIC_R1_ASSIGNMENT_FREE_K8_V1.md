# SHAKE Symbolic-R1 Assignment-Free k8 Reader v1

## Result

A147 converts the `k=8` depth breadcrumb into an assignment-free model search
over the canonical 20-coordinate SHAKE128 symbolic-R1 system.  The exact R1
quadratic graph alone selects coordinates
`[1, 2, 4, 9, 10, 12, 15, 18]`, covering 24 of 28 edges.  It then freezes all
256 projection values in ascending order.  No stored assignment, instrumented
assignment, target projection, solver status, or target-value priority is used
to construct the coordinate set, plan, or execution order.

The Reader executes the plan in ascending waves of five one-thread solver
processes.  It completes projections 0 through 39 in eight full waves.  In the
eighth wave, projection 38 returns assignment 227,581 in 1,442 decisions.  An
independent scalar Keccak-f[1600] evaluation matches all 21 next-rate lanes,
or 1,344 bits.  Only after every process in that wave has completed and the
candidate has passed the independent check does the controller stop.

The executed status count is one `sat` and 39 `unknown`.  This is autonomous,
assignment-free model finding for the fixed `k=8` construction.  It is not a
global uniqueness certificate: projections 40 through 255 are omitted by the
verified early-stop rule, and the 39 earlier `unknown` branches are not
certified empty.  The `k=8` depth was motivated by A145's explicitly posthoc
frontier; A147 removes the assignment from coordinate selection, branch-value
selection, scheduling, and model discovery.

## Complete frozen plan

The selector enumerates all 125,970 eight-coordinate subsets of the 20
variables.  Ten sets attain the maximum coverage of 24 edges; the declared
lexicographic tie-break chooses
`[1, 2, 4, 9, 10, 12, 15, 18]`.  The exact bindings are:

- interaction graph SHA-256:
  `06b168eb69c5a6687e0f7f001bfdf178ce24e28b2b312a84758bfe872d1b9bda`;
- selection SHA-256:
  `d33a8c39d3109d8837d868497c275b39fb10c20cae96a6632b18ed89bb69d454`;
- complete 256-subspace plan SHA-256:
  `e8719001512d482dcedba010de1fa71bb7ab9c67475fbe145a380ec85a7c082b`;
- coverage-proof SHA-256:
  `ba3c8c735ae48112f6ade74756ce9b59387b0dbfdb35c25bfdf74e2ea1685228`.

Every subspace fixes one unique eight-bit pattern, leaves 12 coordinates free,
and contains 4,096 logical assignments.  The 256 pairwise-disjoint subspaces
therefore cover exactly 1,048,576 assignments, the complete `2^20` space.  The
full schedule contains 52 waves: 51 waves of five values followed by value
255.  The execution is an exact ascending prefix of that frozen schedule.

## Independent confirmation and posthoc comparison

The solver assignment is injected into a separate scalar implementation of all
24 Keccak rounds.  Its complete 1,344-bit rate digest equals the target digest
`292a365ca8f2e61491b414b37bf7361d642754be9b03579dd2b5cbe67f8ab526`.
Only after execution has stopped is the instrumented window extracted.  The
posthoc comparison confirms assignment 227,581 and projection 38; the artifact
records that neither value was used by selection, planning, or ordering.

The `.causal` file contains a three-triplet chain joining the graph-only
selection, complete assignment-free plan, deterministic wave execution, and
independent model gate.  It is reopened with `CryptoCausalReader`; provenance
and every graph/selection/plan/coverage hash binding pass.  Its canonical graph
SHA-256 is
`8368cfef022041f06969bb4517f0c47306bb3068be34e3b24602fb3165ef0a61`.

## Reproduction

```bash
PYTHONPATH=.:src .venv/bin/python \
  research/experiments/shake_symbolic_r1_structural_k8_reader.py \
  --output research/results/v1/shake_symbolic_r1_structural_k8_reader_v1.json \
  --causal-output research/results/v1/shake_symbolic_r1_structural_k8_reader_v1.causal

PYTHONPATH=.:src .venv/bin/pytest -q \
  tests/test_shake_symbolic_r1_structural_k8_reader.py
```

## Artifact hashes

- result JSON:
  `61a7b4d78aeaa78fff3acea6043afb8b2bb217dd6175c5a34c1a5a93d639aa98`
- three-edge `.causal`:
  `b08be08240e3055b8d7fa57ac40badc6a256628a0fcb65af0769b3a5974bbde1`
- canonical graph:
  `8368cfef022041f06969bb4517f0c47306bb3068be34e3b24602fb3165ef0a61`

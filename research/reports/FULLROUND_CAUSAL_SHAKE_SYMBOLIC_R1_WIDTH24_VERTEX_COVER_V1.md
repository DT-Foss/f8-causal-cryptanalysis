# SHAKE Symbolic-R1 Width-24 Vertex-Cover Reader v1

## Result

A148 and A151 extend the symbolic-R1 mechanism from the retained 20-coordinate
system to the canonical 24-coordinate SHAKE128 system.  A148 first maps the
exact conditioned structural threshold.  The R1 quadratic graph contains nine
pairwise-disjoint edges, and depth nine is the first tested depth returning a
complete-rate-confirmed model.  A151 then converts that graph fact into a
assignment-free model search: it proves a minimum vertex cover, freezes a
complete 512-subspace formula schedule and one uniform resource plan,
and reconstructs assignment **4,845,375**.

The returned assignment is checked by an independent single-candidate NumPy
lane implementation of all 24 Keccak-f[1600] rounds.  Every one of the 21
SHAKE128 rate lanes matches, for a complete **1,344-bit** confirmation.  The
runtime accepts neither the instrumented assignment nor its nine-bit projection
as an input.  The schedule hypothesis was developed from A148/A149 on this same
instance and is therefore explicitly not presented as a blind holdout.

## A148: exact depth threshold

The exact R1 Boolean-ring compiler produces these nine degree-two variable
edges:

```text
(0,15) (1,16) (2,17) (3,18) (4,19) (5,20) (6,21) (7,22) (8,23)
```

Coordinates 9 through 14 are isolated in this degree-two graph.  Every
coordinate set at each predeclared depth 8, 9, 10, 11 and 12 is enumerated; the
lexicographically first maximum-cover set is frozen before the instrumented
assignment is projected.  One explicitly posthoc-conditioned branch per depth
then gives:

| Depth | Covered edges | Free coordinates | Solver status | Decisions | Confirmed assignment |
|---:|---:|---:|---|---:|---:|
| 8 | 8/9 | 16 | `unknown` | — | — |
| 9 | 9/9 | 15 | `sat` | 4,734 | 4,845,375 |
| 10 | 9/9 | 14 | `unknown` | — | — |
| 11 | 9/9 | 13 | `sat` | 4,184 | 4,845,375 |
| 12 | 9/9 | 12 | `sat` | 3,375 | 4,845,375 |

Depth nine is therefore the minimum measured conditioned depth.  It is also
the exact minimum vertex-cover size: the nine edges are disjoint, so every
cover needs at least one endpoint from each edge; `[0,1,2,3,4,5,6,7,8]`
exhibits a cover of that size.  There are exactly `2^9 = 512` minimum covers,
matching the exhaustive max-cover tie count.

The non-monotone bounded statuses at depths 9 and 10 are retained as solver
resource behavior, not interpreted as non-monotonicity of the underlying
relation.

## A149: resource-sensitive one-pass boundary

The first autonomous production attempt used one 60-second pass with five
parallel one-thread Z3 processes.  It completed the first 20 formula-ranked
values without an independently confirmed model, including rank 18.  The rank
18 SMT formula has SHA-256
`7df2836eadd72c57ce1ae27d6061dae4231c2cfee3061af30286b336a2365eaa`,
byte-identical to A148's successful isolated depth-nine formula.  The run was
stopped during the next wave rather than spending the full 512-value tail on a
one-shot resource policy.

An initial A150 revision retried those 20 values at 120 seconds and found the
model.  Audit then identified that 20 cuts inside the 36-member score-seven tie
class while the successful zero-based rank 18 was already known.  That run is
retained in the attempt log, but the prefix boundary is removed from the final
protocol.  A151 assigns the same 120-second cap to every one of the 512 planned
formula-ranked values; the verified early-stop rule determines how many are
actually attempted.

## A151: uniform-budget minimum-cover Reader

The Reader rebuilds the graph and chooses the lexicographically first minimum
cover `[0,1,2,3,4,5,6,7,8]` without a runtime assignment or target projection.
It then freezes all 512 fixed-value subspaces.  Each leaves 15 coordinates free
and represents 32,768 logical assignments; the pairwise-disjoint plan covers
exactly
`512 * 32,768 = 16,777,216 = 2^24` assignments.

The formula-only ordering follows the R1 edge semantics.  Fixing a selected
factor to one changes its quadratic edge term into the free partner; fixing it
to zero deletes the term.  Values are consequently ordered by decreasing
number of retained linearized edges, with numeric value as the deterministic
tie-break.  The complete order is fixed before any instrumented extraction.
This mechanism hypothesis was developed after A148/A149 and is not a blind
holdout; the distinction is encoded directly in the plan and Causal graph.

The execution plan contains one complete phase: all 512 values in formula order,
each with the same 120-second limit.  Complete waves use at most five one-thread
Z3 4.15.4 processes.  Early stopping is permitted only after every process in
the current wave has returned and every solver model has passed the independent
1,344-bit check.

The retained execution stops after the fourth complete wave:

- attempted values: the first 20 values of the complete 512-value plan;
- statuses: one `sat`, 19 `unknown`;
- successful projection: 319, formula rank 18;
- reconstructed assignment: 4,845,375;
- solver work: 4,734 decisions and 2,380 conflicts;
- independent candidate and target rate digest:
  `4191ccccd9e95a8b9b29723c896fb0e4536b33cf56028e83d61f3841f1f15266`.

The instrumented assignment and projection are extracted only after execution
has stopped.  Their posthoc equality confirms the reconstruction; neither is a
runtime input.  A151 is deterministic assignment-free model finding on the
retained instance.  It does not certify global uniqueness: 19 attempted
branches retain bounded `unknown` statuses and the verified early-stop rule
omits the remaining 492 values.

## Causal Reader chain

The A151 `.causal` artifact contains exactly four explicit triplets:

1. exact R1 polynomial state → nine disjoint interaction edges;
2. disjoint graph → certified minimum vertex cover;
3. minimum cover → complete interaction-preserving schedule and uniform plan;
4. frozen plan → bounded solver observations and independent full-rate check.

`CryptoCausalReader` reopens the artifact, verifies the canonical graph digest
and checks every provenance link.  The graph SHA-256 is
`431cd36290df6088a017ee9267f43ab0c7796465ff6ae0dbc952f921b5aa7f29`.

## Frozen proof bindings

- R1 polynomial state:
  `266374067017f3c9c4c67961b7312877760699837e888733d8979c0c71571e00`
- interaction edges:
  `d804968401d9de6cafe4b605100373dbc9607d5dab811647add969fa94c4fa10`
- minimum-cover selection:
  `9bc2f302b45e8a35113d7fe66d1a496f31a0e10c9ba59c0e740ebcc3a7bb095a`
- minimum-cover proof:
  `2bc79951111df872df460221eba51a9887621c2171229988fc4c598bb751b0fe`
- complete 512-subspace plan:
  `936464fa99941212353486b1d74e2fbb63beb73b3b1d7698d40a89cf52a089bc`
- formula schedule:
  `4806ef83a5eb53831fdea4cbef5a3d5d91d6d8203470705a2dca977e8786242b`
- assignment-space coverage proof:
  `bd1b58174d9f21cf6eacfcc0d8b69b8b41e8244fc36fab1f2d232f9b0d65b476`
- uniform execution phase plan:
  `34b3ba9970b9e435e4d7c92c44a58e00aa6668241878c863f3a5d733bb8824c1`
- execution phase proof:
  `52587815e7300dcbaffa41ed3077cca30b3b6be7086a54b8d40127679c09267a`

## Reproduction

The runners and both aggregate reproduction scripts fail closed unless the
external CLI reports Z3 4.15.4.

```bash
PYTHONPATH=.:src .venv/bin/python \
  research/experiments/shake_symbolic_r1_width24_depth_frontier.py \
  --output research/results/v1/shake_symbolic_r1_width24_depth_frontier_v1.json \
  --causal-output research/results/v1/shake_symbolic_r1_width24_depth_frontier_v1.causal

PYTHONPATH=.:src .venv/bin/python \
  research/experiments/shake_symbolic_r1_width24_vertex_cover_reader.py \
  --output research/results/v1/shake_symbolic_r1_width24_vertex_cover_reader_v1.json \
  --causal-output research/results/v1/shake_symbolic_r1_width24_vertex_cover_reader_v1.causal

PYTHONPATH=.:src .venv/bin/pytest -q \
  tests/test_shake_symbolic_r1_width24_depth_frontier.py \
  tests/test_shake_symbolic_r1_width24_vertex_cover_reader.py
```

## Artifact hashes

- A148 result JSON:
  `19a744d90b968589937207eca8d9cd2581960d03c7f7278e5b9b97b28d8b6b84`
- A148 `.causal`:
  `9f6dc8cce28df057aeccc5879848289f734ccba87e9e49278d216011513d9c5f`
- A148 canonical graph:
  `32640cf1720e1eb032bcff83edfe84dae5e25d701b414f9f1942fd8d0a374912`
- A151 result JSON:
  `3ea9f21a6cfde4f5728f4860181b4d32317be9d9eeb7296b3b81427faa1d75ee`
- A151 `.causal`:
  `9ef1f40d369c88fb7ea05afec026fcc59a67f9028e405a788f696ec2588f932b`
- A151 canonical graph:
  `431cd36290df6088a017ee9267f43ab0c7796465ff6ae0dbc952f921b5aa7f29`

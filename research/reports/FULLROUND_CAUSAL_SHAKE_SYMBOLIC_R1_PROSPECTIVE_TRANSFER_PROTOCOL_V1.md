# SHAKE Symbolic-R1 Prospective Width-24 Transfer Protocol v1

## State

**Prospectively frozen, publicly committed, and executed.** The complete A152
protocol and runner were published in commit
[`9327e3cc5d09f725f89bd1027e5f02b4410c53e8`](https://github.com/DT-Foss/f8-causal-cryptanalysis/commit/9327e3cc5d09f725f89bd1027e5f02b4410c53e8)
before the new instance was generated. The freeze-only invocation then passed
with `instance_generated=false`; the production invocation ran afterward.

The exact machine-readable protocol is
`research/configs/shake_symbolic_r1_width24_prospective_transfer_v1.json`, with
SHA-256

```text
0fd33d09108a3aabccd8dfa38131eee074f7b56ba4fede52e23fa1fe29843bc4
```

The production runner refuses to instantiate the new target until both those
exact protocol bytes and the byte-identical executing runner are found in the
supplied commit, that commit is an ancestor of freshly fetched public `main`,
and the process is executing from a clean worktree whose `HEAD` is exactly that
commit. Repository-local dependencies are imported only after this gate and
must resolve inside the same frozen worktree. A push-only GitHub URL cannot
satisfy the fetch-remote gate.

## Prospectively derived instance

The seed is determined from the already retained A151 result hash
`3ea9f21a6cfde4f5728f4860181b4d32317be9d9eeb7296b3b81427faa1d75ee`.
The runner hashes the ASCII label

```text
f8-causal:A152:prospective-shake128-r1-width24-transfer:v1|
```

followed by the 32 raw anchor-hash bytes. Its SHA-256 digest is
`8f8854215b3702428d90fea9c8d02f55fdda697fcd1d5a599a17758dfa2c15ce`;
the big-endian first four bytes masked with `0x7fffffff` give seed
**260,592,673**. The seed is therefore selected by a declared hash rule, not by
the unseen target, graph, projection rank, or solver outcome.

The target is one SHAKE128 contiguous 24-bit capacity-state window, one exact
symbolic R1 interface, 23 exact remaining Keccak-f[1600] rounds, and the full
1,344-bit next-rate observation.

## Prospective result

The hash-derived seed places the 24 unknown capacity coordinates at positions
143 through 166. The exact cleared-template R1 polynomial graph has **zero
degree-two edges**: all 24 vertices are isolated. Exhaustive cover enumeration
therefore proves a unique minimum cover of size zero, the empty set. The frozen
schedule consequently contains exactly one subspace with no fixed coordinates
and all `2^24 = 16,777,216` logical assignments.

The one complete planned query is the unchanged 24-variable monolithic R1
formula. Z3 4.15.4 returns `unknown` at the declared 120-second limit with
return code zero and no external timeout. There are zero `sat`, zero `unsat`,
and zero error outcomes, so no model is reconstructed. Only after execution
ends does the runner extract assignment **9,279,571**. The independent NumPy
lane implementation confirms that witness against all 1,344 target-rate bits;
its candidate and target digests both equal
`435edcaaa1288f8b812aea055dacc9aadc6dc1dd7416a2102459d2bc7526141c`.
The single true projection is zero and its solver status is `unknown`, not
`unsat`.

This is the exact prospective transfer boundary of the A151 mechanism. A151's
nine disjoint quadratic R1 edges and size-nine cover do not persist at the new
window position. Here the complete R1 interface is affine in the 24 unknowns,
so a deeper vertex-cover schedule has no object to act on. The next mechanism
step is therefore an affine basis/pivot transform or an R2 interaction
analysis, not another replay of the size-nine partition.

Exact bindings:

- capacity window: `[143, 167)`;
- R1 polynomial state:
  `e0c8856814a8fa2a48268ccb580ad0b94decc3879915c300ff66114cfd61025d`;
- empty edge list:
  `4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945`;
- minimum-cover proof:
  `be2d9ee0cdcc43aaf73ac658d1d9a0b1f8817986847567c24693194bb0b35654`;
- selection:
  `0749fcf89acaf92ad14b5729434519d998dd5f4013220180d96e7c51d3cf6405`;
- complete one-subspace plan:
  `2a4b760014f1b11c11c3be2f6861cb040592f7c718dbf3100ede9974a22aac97`;
- plan proof:
  `28708a9ebfb2b26b0811c7d98ce444ee8802da5ae42872fb500288d9e7fef87a`;
- execution-phase proof:
  `d9ecd4d58f4b24ad948282a86f1e65e63bc81d0ed7e986d774f76404c05a8860`;
- 9,187,001-byte unpartitioned SMT:
  `8dc549599b1d699d632be37312b0efacd43f73e073a16f5829ddc42f0c4f23c7`;
- result JSON:
  `0e01e3e6ff0b9a80ff66ad6614f846305188d96a4497ca38857eac81097a1561`;
- four-triplet `.causal`:
  `04e222ab50d9a0e39c15838c94eae566b41e28ca368f0d35d56a1f1378a8c0fa`;
- canonical Causal graph:
  `8a9dc00fdde9ca78fa767129d3e3d28a9acdc00ad4d86f8981c415c549cf1b97`.

## Frozen Reader

The following derivation algorithms are fixed before the target exists; their
concrete graph, cover, and schedule values are intentionally unknown until the
public-commit gate passes. The runtime then performs these steps:

1. clear every hidden window coordinate before constructing the runtime
   problem;
2. compile the exact R1 Boolean polynomials from that cleared template and
   extract every unique degree-two variable pair;
3. exhaustively prove the graph's minimum vertex-cover size and choose the
   lexicographically first minimum cover;
4. enumerate every projection of that cover and order it by decreasing count
   of edges that become free linear terms, then decreasing projection
   population count, then increasing numeric value;
5. prove that the resulting subspaces are pairwise disjoint and cover all
   `2^24` assignments;
6. assign every planned projection the same 120-second Z3 4.15.4 limit, run
   complete waves of at most five one-thread processes, and stop only after a
   complete wave contains a model that passes an independent 1,344-bit check.

If the exact minimum cover contains more than 12 coordinates, the frozen
resource guard writes the graph and cover as a structure-only boundary without
starting Z3 or extracting the instrumented assignment. This guarded result is
not labeled model search. An edgeless graph is handled as one zero-coordinate
projection covering the full `2^24` space.

The runtime problem contains the cleared template, window positions, and the
observed rate target. It contains neither the instrumented window assignment
nor its cover projection. Sanitization reads the base state only to clear every
declared window bit; the hidden assignment is first extracted and compared
posthoc after execution has ended.

## Excluded phase-flag pseudo-route

A separate A153 parameter audit tested `smt.phase_selection={0,1,3,6}` and six
`sat.phase` values on the canonical plain-`QF_UF` Width-16 route. At fixed Z3
resource limits, every plain-route variant emitted identical decisions,
conflicts, propagations, binary propagations, restarts, and status. At
`rlimit=100000000` each returned `unknown` with 2,152 decisions, 212 conflicts,
16,913,397 propagations, 4,759,242 binary propagations, and two restarts. The
phase flags are therefore not presented as graph-derived strategy variants in
A152.

Z3 applies the SAT-phase family only after changing the query to an explicit
`(then simplify solve-eqs aig sat)` tactic. A144 already measured that distinct
representation family. Z3 4.15.4 exposes no CLI option for per-input
graph-derived polarities; implementing those would require a separately
audited variable transform and model inverse map rather than relabeling an inert
flag.

## Execution command after public freeze

```bash
cd /absolute/path/to/public/f8-causal-cryptanalysis
PYTHONPATH=.:src /absolute/path/to/source/.venv/bin/python \
  research/experiments/shake_symbolic_r1_width24_prospective_transfer.py \
  --public-freeze-repo "$PWD" \
  --public-freeze-commit <40-hex-public-commit> \
  --work-dir /absolute/path/to/source/build/shake-r1-a152 \
  --output /absolute/path/to/source/research/results/v1/shake_symbolic_r1_width24_prospective_transfer_v1.json \
  --causal-output /absolute/path/to/source/research/results/v1/shake_symbolic_r1_width24_prospective_transfer_v1.causal
```

Focused retained-artifact and freeze-gate validation:

```bash
PYTHONPATH=.:src .venv/bin/pytest -q \
  tests/test_shake_symbolic_r1_width24_prospective_transfer.py

PYTHONPATH=.:src /absolute/path/to/source/.venv/bin/python \
  research/experiments/shake_symbolic_r1_width24_prospective_transfer.py \
  --public-freeze-repo "$PWD" \
  --public-freeze-commit <40-hex-public-commit> \
  --verify-freeze-only
```

The freeze-only command exits with `instance_generated=false` and requires no
output or work path.

The retained artifact test hash-gates both result files, reopens the Causal
graph, checks its four-triplet provenance chain, and verifies the empty graph,
zero-coordinate cover, one-subspace plan, solver status, and independent
posthoc witness.

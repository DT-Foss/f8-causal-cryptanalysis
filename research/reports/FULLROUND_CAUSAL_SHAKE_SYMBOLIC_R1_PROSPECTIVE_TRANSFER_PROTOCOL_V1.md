# SHAKE Symbolic-R1 Prospective Width-24 Transfer Protocol v1

## State

**Frozen before new-instance generation; not yet executed.** This document
defines A152's transfer protocol. It contains no observation from the new seed,
no R1 graph derived from that seed, no target projection, and no solver result.

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

Focused pre-execution validation:

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

The report will be extended with the observed graph, plan hashes, executed
prefix, solver statuses, independent model check, and final artifact hashes
only after that command completes.

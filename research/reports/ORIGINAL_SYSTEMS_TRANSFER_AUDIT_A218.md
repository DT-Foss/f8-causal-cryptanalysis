# Original-Systems Transfer Audit for A218

## Scope and method

This audit reconstructs the original, unpolished research systems as systems
before deciding whether any component transfers to full-round cryptanalysis.
It does not begin from cryptographic keywords. The first pass covered complete
file maps, source sizes, Python AST inventories, duplicate-source hashes, result
manifests, and every distinct `.causal` binary representation under:

- `<source-o1-o>`
- `<source-forge>`
- `<source-o1>`
- `<source-gssm-kernel-overnight>`
- `<source-gssm>`
- `<source-gssm-copy>`
- `<source-language-model>`
- `<source-fabel>`

The transfer question was then asked at the level of state, read operator,
invariance, selection, intervention, and evidence boundary. A mechanism was
adopted only when it could be rebuilt against the exact R20 experiment rather
than imported as a domain label.

## O1: one substrate, multiple nontrivial readers

O1's strongest transferable statement is that information is determined by
the interaction between a common substrate and a read operator. Its
`operator_readout.py`, multi-frequency memory, closed-loop consultation,
percolation, and reinforcement-loop implementations instantiate different
parts of that statement.

The first direct cryptanalytic transfer is already measured by A217. Numeric
and reflected Gray8 traverse the same R20 CNF with the same solver build,
budget, and complete prefix cover. They recover the same independently
confirmed model and expend nearly identical aggregate work, yet have low
same-prefix correlations, low cross-view CKA, and low affine predictability.
They are therefore genuinely different learned-state readers over one
substrate rather than scaled copies.

The multi-frequency Z16 standard-output prototype was also transferred in
A216. Its raw target result did not survive the selection-matched null in
A216N. This is a useful mechanism boundary: harmonic addressing remains a
candidate coordinate system, but its raw macro score is not carried into A218
as evidence.

O1's closed-loop design clones an identical pre-gap state and compares a
control arm with an intervention arm. CaDiCaL does not expose a complete,
portable learned-state clone through the current interface. The exact transfer
is therefore deterministic replay to a frozen prefix followed by two
prospectively fixed continuations. It is deferred until the A218 reader has
produced a real intervention order.

## GSSM: inverse-covariance read and correct independent units

`freeidea_gram_inverse.py` contains the most direct second readout for A218.
Its core operation is a Wiener or ridge inverse:

```text
w = (Sigma + lambda I)^-1 (mu_positive - mu_negative)
```

The A218 implementation uses this as a class-balanced Fisher contrast over
standardized solver-trajectory features. It is independent of the
class-balanced ridge-logistic reader and remains completely inspectable: the
means, scales, coefficients, ridge value, condition number, and linear-system
residual are serialized.

`read_gates.py` supplies a second decisive rule: measurements within one token
stream are not independent experimental units. For A218 the analogous unit is
the complete key. The 256 cells belonging to a key are never counted as 256
independent keys. Train/validation splitting and all null permutations operate
on whole keys.

`control_horizon.py` supplies the horizon interpretation of a budget. A218P
tested 16 and 32 conflicts per cell on the revealed anchor. The scientific
measurement excluding wall time reproduced exactly at
`6db14386c896127bc5fc4078547d4983cd8a6c0f2487834891888863ce8a205f`.
Conflict 32 opens substantially richer decision, conflict, and propagation
surfaces while retaining a tiny deterministic horizon and zero watchdogs.

The Möbius-phase MQAR result was read rather than assumed useful. Its recorded
full result does not improve the relevant MQAR baseline. Möbius phase is
therefore retained only as a future transform requiring its own matched
control; it is not part of the A218 candidate grid.

## GSSM vision and spatial models: native solver geometry

`foss_vision.py` and `spatial_model_v2.py` treat observations as a structured
substrate rather than a flat feature table. Their transferable operations are
multi-direction scans, neighbor diffusion, row/column/cell views, Fiedler-like
paths, and peak-preserving mean/max readout.

A218 rebuilds the defensible, nonlearned part directly on the prefix domain:

- the 256 prefixes form an eight-dimensional Boolean hypercube;
- every cell receives a local residual against its eight Hamming-distance-one
  neighbors;
- Numeric and Gray each supply predecessor and successor gradients along their
  own retained-state path;
- the two operators are aligned by prefix and decomposed into orthonormal sum
  and difference channels.

No image model or spatial network is imported. The geometry is exact and fixed
before labels are measured.

## LanguageModel: permutation portfolios after the transparent baseline

The strongest next-stage mechanism in `LanguageModel` is Sinkhorn transport
followed by a Birkhoff-von Neumann decomposition. It can represent a soft
distribution over cell orders and reduce it to a small explicit portfolio of
permutation paths.

The included `bvn_parallel.py` uses a greedy matching routine that is not a
general exact BvN decomposition. A future transfer must use an exact Hungarian
matching at every residual step and verify nonnegative residual mass,
doubly-stochastic reconstruction error, and path diversity. It is deliberately
not mixed into A218: A218 first establishes whether transparent fixed views and
linear readers transfer prospectively.

The CSQG implementation provides spectral-gap and graph-conductance machinery,
but its combined gate is not accepted as a cryptanalytic quality theorem. The
useful transfer is narrower: build a similarity or clause-activity graph and
measure spectral bottlenecks to propose cutsets or partitions. This belongs
after the target-blind trajectory baseline.

The source's `tau_contraction` smoke comment reverses the identity boundary:
the Dobrushin coefficient of the identity is one, not zero. The formula rather
than the comment controls any future transfer.

## O1-O and FORGE: architecture, not current proof apparatus

O1-O contains the right high-level separation of typed fragments, deterministic
assembly, taint analysis, operation replay, property verification, failure
memory, and multi-criteria fix evaluation. The current implementations are not
strong enough to certify A218:

- the color system is substantially a static catalog plus broad regex mapping;
- the taint analyzer is source/sink pattern matching with line-order logic, not
  an AST or data-flow proof;
- failure memory normalizes error strings and compares fix sets rather than
  identifying a mechanistic experimental state;
- the property verifier uses heuristic names and randomized execution and must
  not be described as formal verification;
- provenance confidence is largely a product of supplied confidences.

FORGE adds useful experiment-infrastructure patterns: interface contracts,
multi-objective evaluation, a SQLite attempt ledger, target scheduling, gap
detection, and cross-operation aggregation. Its generic implementations often
use static weights, first-candidate resolution, or crude prevalence
denominators. A218 transfers the schemas, not those numerical claims.

The resulting architecture for this repository is:

```text
typed public challenge
  -> exact symbolic R20 template
  -> fixed operator and budget
  -> strict trajectory parser
  -> whole-key learning unit
  -> full selection-matched null
  -> atomic prereveal order
  -> independent solver or commitment confirmation
```

The later closed loop will store a failure fingerprint comprising round count,
unknown width, formula identity, operator, budget, feature reader, solver
status, and trajectory geometry. A next intervention is admitted only after a
prospective same-budget comparison, not because a textual failure resembles an
older one.

## Fabel and native `.causal` files

The audit hashed every `.causal` file in the relevant roots before parsing
unique contents with their original readers. There are 299 files representing
69 unique binary contents across two actual format families:

1. the older `CAUSAL` plus big-endian version plus zlib-msgpack container;
2. the Fabel header and offset-table format with entities, triplets, rules,
   clusters, gaps, evidence, and optional inference chains.

Fabel supplies useful module isolation, federation, path materialization, and
curriculum construction. Its current `GraphIndex` collapses multiple edges
sharing the same entity pair, and module removal can consequently remove an
edge still owned by another module. `get_all_triplets` also does not expose the
full inference chain.

The largest concrete provenance issue is `gw_knowledge.causal`: it contains
9,172 rows and 4,241 entities, including 2,997 rows whose source is
`INFERRED_FUZZY` plus other inferred-source families, while the raw
`is_inferred` flag is false on all 9,172 rows. A reader that trusts only the
Boolean flag therefore promotes materialized inference to explicit evidence.
The curriculum builder happens to filter inferred source strings as a second
gate; the general graph index does not.

`CryptoCausalReader` in this repository is stricter: it verifies schema,
version, graph hash, edge identity, and complete provenance without fuzzy
closure. Its next extension should add multigraph-preserving adjacency, exact
path search, neighborhoods, and explanations without collapsing mechanisms
sharing endpoints.

## A218 decisions produced by this audit

A218 is not a generic neural classifier. It is a transparent reader over the
state changes of an exact CDCL solver:

1. Numeric and reflected Gray8 are the two experimentally established operator
   views.
2. Six time-free channels are transformed by `log1p` or signed `log1p`.
3. Per-key z-score and centered-rank views remove scale without exposing a
   target label.
4. Sum/difference channels isolate common substrate and operator-specific
   response.
5. Hypercube neighbors and path gradients expose spatial and sequential
   structure.
6. Ridge logistic and Gram/Wiener-Fisher are independent transparent readers.
7. Five nested feature families, both readers, and five ridge values are
   selected only on eight disjoint known keys.
8. Sixty-four null worlds independently permute complete train and validation
   keys and repeat the entire 50-candidate selection.
9. A new CSPRNG target is salted, committed, and measured without reading its
   label.
10. The complete target order is written atomically before any reveal and can
    be executed directly as a retained-state solver intervention.

This is the current self-improving-solver kernel: exact learned clauses form
the substrate, fixed readers quantify how known successful regions perturb
that substrate, whole-key controls determine whether the map transfers, and a
prospectively frozen operator changes the next solve. The remaining step from
kernel to closed loop is automatic, evidence-gated operator scheduling across
multiple unseen targets and then across cipher families.

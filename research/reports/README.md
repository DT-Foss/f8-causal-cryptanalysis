# Research reports

Reports in this directory interpret retained results. They must link every
numeric statement to a JSON/CSV artifact and every execution claim to the
attempt log. Raw outputs take precedence over report prose.

`BVN_ROUTE_CAUSAL_V1.md` defines the balanced global-route control used for
F8/CASI calibration and public-output PQC order controls.

`CAUSAL_MECHANISM_RESULTS_V1.md` records the operation-level carry
interventions, the corrected ML-KEM quantizer control, real compressor cascades
and the conditional code-length formulation.

The SHAKE symbolic sequence is indexed by
`FULLROUND_CAUSAL_SHAKE_ANF_COMPRESSION_V1.md`,
`SHAKE_SYMBOLIC_R2_ANF_FRONTIER_V1.md`,
`FULLROUND_CAUSAL_SHAKE_SYMBOLIC_R2_SMT_V1.md`,
`FULLROUND_CAUSAL_SHAKE_SYMBOLIC_R2_PARTITION_V1.md`,
`FULLROUND_CAUSAL_SHAKE_SYMBOLIC_SPLIT_FRONTIER_V1.md`, and
`FULLROUND_CAUSAL_SHAKE_SYMBOLIC_R1_SCALING_V1.md`.

`FULLROUND_CAUSAL_SHAKE_SYMBOLIC_R1_PARTITION_TOPOLOGY_V1.md` compares the
complete low, high, and R1-graph-selected four-coordinate partitions of the
same hash-gated 20-coordinate SHAKE128 system.

`FULLROUND_CAUSAL_SHAKE256_SYMBOLIC_R1_TRANSFER_V1.md` records the exact
monolithic SHAKE256 transfer boundary for the SHAKE128-selected R1 interface.

`FULLROUND_CAUSAL_SHAKE_SYMBOLIC_R1_STRUCTURAL_DEPTH_V1.md` records the complete
Structural-6 plan and the explicitly posthoc-conditioned `k=4/6/8/10`
mechanism frontier.

`FULLROUND_CAUSAL_SHAKE_SYMBOLIC_R1_Z3_STRATEGY_V1.md` compares six exact Z3
processing routes and transfers the selected route to the complete Structural-6
plan.

`FULLROUND_CAUSAL_SHAKE_SYMBOLIC_R1_ASSIGNMENT_FREE_K8_V1.md` records the
graph-only 256-subspace plan, deterministic wave execution, and independently
confirmed assignment-free `k=8` model finding.

`FULLROUND_CAUSAL_SHAKE_SYMBOLIC_R1_WIDTH24_VERTEX_COVER_V1.md` records the
exact nine-edge width-24 R1 graph, its minimum-vertex-cover threshold, the
complete formula-ranked 512-subspace plan, and the independently confirmed
assignment-free uniform-budget model search with explicit non-blind design scope.

`FULLROUND_CAUSAL_SHAKE_SYMBOLIC_R1_PROSPECTIVE_TRANSFER_PROTOCOL_V1.md` freezes
the A152 new-seed rule, graph extraction, exact-cover and schedule-generation
algorithms, uniform budget, cover-size resource guard, clean-public-worktree
gate, and posthoc boundary before the new instance is generated.  It also
records the completed prospective run: the unseen window's R1 graph is
edgeless, its unique minimum cover is empty, the sole unconditioned query
returns `unknown`, and the independent posthoc witness matches all 1,344 rate
bits.  The result redirects the mechanism search from vertex covers to an
affine R1 basis and its induced R2 interactions.

`FULLROUND_CAUSAL_SHAKE_SYMBOLIC_R1_AFFINE_BASIS_V1.md` proves that this
edgeless R1 interface is a full-rank systematic affine embedding: 24 selected
R1 output deltas are exactly a permutation of the 24 inputs, with a checked
two-sided inverse and zero input nullity.

`FULLROUND_CAUSAL_SHAKE_SYMBOLIC_R2_PIVOT_BASIS_V1.md` substitutes that inverse
into the complete R2 interface and proves that all 276 quadratic pairs are
present.  The graph is exactly K24 in both coordinate systems and its minimum
vertex cover has size 23, localizing pairwise saturation between R1 and R2.

`FULLROUND_CAUSAL_SHAKE_SYMBOLIC_R1_SYSTEMATIC_ENCODER_V1.md` converts the
systematic basis into four exact full-round encoders.  They remove 1,573 or all
1,600 R1 prefix definitions and up to 101,268 formula bytes, then execute under
one uniform 120-second budget.  All four retain the resource boundary without
emitting a model, selecting direct shared-R2 monomial compilation next.

`FULLROUND_CAUSAL_SHAKE_SYMBOLIC_R2_SHARED_ENCODER_V1.md` performs that
representation change with the exact 301-monomial R2 dictionary.  All four
uniform runs remain bounded, but original versus pivot input order changes the
decision count by about 41--43%, while monomial-definition order changes little.
The weighted R2 occurrence matrix is therefore the next ordering mechanism.

`FULLROUND_CAUSAL_SHAKE_SYMBOLIC_R2_WEIGHTED_ORDER_V1.md` derives four orders
from that exact matrix without assignment or target-projection input.  The
identical relation spans 10,990--23,097 decisions under the same time cap; all
outcomes remain `unknown`, so A159 switches the same formula bytes to a fixed
Z3 resource limit before interpreting direction.

`FULLROUND_CAUSAL_SHAKE_SYMBOLIC_R2_FIXED_RLIMIT_ORDER_V1.md` performs that
replay with an identical 500,000,000-unit cap per formula and no solver
wall-clock limit.  The same four-way decision ordering survives while every
query exhausts the cap as `unknown`.  This retains deterministic traversal
separation and selects an exact affine-gauge optimization as the next distinct
mechanism.

`FULLROUND_CAUSAL_SHAKE_SYMBOLIC_R2_AFFINE_GAUGE_V1.md` evaluates every one of
the `2^24` affine input shifts with an exact Walsh transform.  It certifies a
unique global minimum at `0x8e26db`, reducing linear R2 incidence from 8,698 to
8,413 while preserving every quadratic coefficient and the K24 graph.  The
result is a target- and assignment-free polarity gauge ready for fixed-resource
full-round transfer.

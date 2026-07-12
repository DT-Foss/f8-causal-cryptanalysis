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

`FULLROUND_CAUSAL_SHAKE_SYMBOLIC_R2_AFFINE_GAUGE_SOLVER_V1.md` performs that
four-order transfer under A159's exact fixed resource protocol.  The gauge
reduces decisions by 27.1--60.2% in three orders but raises them by 70.9% in
the former minimum, changing the complete rank order while every status remains
`unknown`.  This directly selects an order-weighted Walsh objective.

`FULLROUND_CAUSAL_SHAKE_SYMBOLIC_R2_ORDER_WEIGHTED_GAUGE_V1.md` evaluates the
front- and back-loaded positional objective for each frozen order over all
`2^24` shifts.  All eight optima are unique and collapse to four exact gauges;
every one improves zero and A160 under its declared objective, preserves the
complete quadratic interface, and passes independent semantic checks.

`FULLROUND_CAUSAL_SHAKE_SYMBOLIC_R2_ORDER_WEIGHTED_GAUGE_SOLVER_V1.md`
executes all eight frozen order/gauge cells under the same 500,000,000-unit
resource cap.  Seven cells reduce decisions against their same-order zero
gauge, only two reduce them against A160's unweighted gauge, and all eight
remain `unknown`.  The resulting factorial map retains structural gauge/order
coupling and removes a single positional incidence objective as a sufficient
traversal predictor.

`FULLROUND_CAUSAL_SHAKE_SYMBOLIC_R2_FOUR_GAUGE_FACTORIAL_V1.md` executes only
the eight cells missing from the frozen four-gauge by four-order product.
Gauge `0x4e1e28` wins every order; its weighted-degree-ascending cell reaches a
new 4,402-decision fixed-resource minimum, 24.4% below the previous best.  The
complete matrix and exact rational decomposition separate a transferable gauge
main effect from still-large order interactions.

`FULLROUND_CAUSAL_SHAKE_A152_NATIVE_RECONSTRUCTION_V1.md` transfers the
retained native Causal Reader to A152's exact prospective relation.  It
enumerates the complete `2^24` domain, reconstructs the unique assignment
9,279,571, independently confirms all 1,344 rate bits, and fully rejects a
bit-flipped target control.  The fresh end-to-end run measured 1.61 seconds on
an Apple M4 Mac mini.

`FULLROUND_CAUSAL_SHAKE_SYMBOLIC_R2_SIGNED_ALIAS_COMPILER_V1.md` proves that
the exact static suffix cone selects `0x498a92`, not A164's universal
`0x4e1e28` gauge, at every depth.  It then normalizes all five exact signed R2
unit-affine aliases with no semantic change.  The one-variable intervention
improves three orders but worsens descending, establishing an order interaction
and a new 3,425-decision fixed-resource traversal minimum.

`FULLROUND_CAUSAL_SHAKE_SYMBOLIC_R2_ID_PRESERVING_ALIAS_V1.md` decomposes the
A166 compiler intervention with a third, ID-preserving arm.  A disconnected
`s1215` declaration restores A164's exact downstream declaration IDs while the
negative alias remains inlined.  Decisions match A166 in all four orders, so
the signed-alias-node effect has L1 magnitude 5,790 and the downstream ID-shift
decision effect has L1 magnitude zero.

`FULLROUND_CAUSAL_SHAKE_SYMBOLIC_R2_NORMALIZED_ALIAS_V1.md` keeps the negative
alias node connected and every declaration ID fixed while rewriting its sole
definition from `xor(true,x)` to `not(x)`.  All four original decision counts
are reproduced exactly, giving RHS-syntax effect `[0,0,0,0]` and retaining the
complete connected-node-removal effect `[+2008,-977,-1623,-1182]`.

`FULLROUND_CAUSAL_SHAKE_SYMBOLIC_R2_ALIAS_FANOUT_MOBIUS_V1.md` resolves that
connected alias into its exact column and theta consumers.  Eight
single-consumer formulas complete the fanout-zero/one/two Boolean lattice for
all four orders.  The column and theta main-effect L1 magnitudes are 4,247 and
4,222 decisions, the interaction L1 is 3,289, and every order has a nonzero
interaction; neither consumer alone explains the connected-node response.

`FULLROUND_CAUSAL_SHAKE_SYMBOLIC_R2_REVERSED_ORDER_ALIAS_POLARITY_V1.md`
reverses each complete frozen order and tests paired inline/materialized alias
arms.  Reversed effects `[-1281,-2898,-942,+1018]` produce two polarity flips
and two preservations, excluding global order reversal as a sufficient law.
The completed weighted subset also exposes a matched adjacent `0`/`12` swap as
the next exact intervention without treating it as A170's prospective target.

`FULLROUND_CAUSAL_SHAKE_SYMBOLIC_R2_ADJACENT_0_12_TRANSFER_V1.md`
prospectively transfers the matched weighted `0/12` direction into a new
central Greedy-Max pair.  Effects -581 for `0,12` and -125 for `12,0` give a
+456 directional delta, reversing the frozen prediction.  Both materialized
arms remain beneficial, but the orientation ranking is context-dependent:
transfer failed and a new order-family/insertion-context condition is retained.

`FULLROUND_CAUSAL_SHAKE_SYMBOLIC_R2_CENTER_POSITION_FAMILY_CONTRAST_V1.md`
holds A172's central 11/12 positions fixed while changing the surrounding
family from Greedy-Max to Weighted Descending.  The directional delta remains
positive and grows from +456 to +10,955, selecting
`central_position_supported`.  Effects -5,087 for `0,12` and +5,868 for
`12,0` establish an exact, sign-changing compiler x adjacent-order interaction
without a model claim.

`FULLROUND_CAUSAL_SHAKE_SYMBOLIC_R2_CENTER_ALIAS_PARTNER_TRANSFER_V1.md`
prospectively replaces partner `0` with alias coordinate `12`'s original
Weighted-Descending right neighbor `22` at the same x11/x12 boundary.  Effects
-3,979 and -1,783 yield a +2,196 delta, confirming the frozen
`central_alias_boundary_transfers` branch.  The retained conclusion is an exact
two-partner fixed-resource solvergraph transfer, not universal partner
independence or a model-recovery claim.

`FULLROUND_CAUSAL_SHAKE_SYMBOLIC_R2_ALPHA_RENAMED_CENTER_BOUNDARY_V1.md`
renames every declared SMT symbol by bijective numeric `suffix+1`; the inverse
recovers all A174 bytes exactly.  The first three decision counts reproduce and
the fourth changes by +398, while all canonical observations differ.  The
positive boundary delta increases from +2,196 to +2,594, establishing
`central_boundary_alpha_robust`: names modulate one fixed-resource trajectory
without reversing the exact tested direction.

`FULLROUND_CAUSAL_SHAKE_SYMBOLIC_R2_INPUT_DECLARATION_SWAP_BOUNDARY_V1.md`
swaps only the `x11`/`x12` declaration lines at declaration indices 11/12
(physical SMT lines 14/15).  Every assertion, symbol and `get-value` byte is
unchanged, and a second swap exactly reconstructs A174.  All four canonical
observations and the +2,196 delta reproduce bit-for-bit, establishing
`exact_input_declaration_order_invariance` for this fixed parser/solver scope.

`FULLROUND_CAUSAL_SHAKE256_NATIVE_WIDTH32_RECONSTRUCTION_V1.md` records A177's
prospectively frozen SHAKE256 full-round width-32 reconstruction.  The complete
`2^32` domain executes as 67,108,864 native packs without early stopping; the
unique assignment 2,761,171,082 passes an independent 1,088-bit confirmation,
the bit-flipped control returns zero models, and the posthoc identity is exact.

`FULLROUND_CAUSAL_CHACHA20_NATIVE_PARTIAL_KEY_RECOVERY_V1.md` records A178's
fullround 32-bit partial-key recovery for standard ChaCha20.  With one key word
unknown and 224 key bits plus counter, nonce, and full block output known, the
complete `2^32` domain uniquely returns `0x903db747`; an independent 512-bit
check is exact and the bit-flipped control has zero matches.

`FULLROUND_CAUSAL_CHACHA20_VECTOR256_REPLAY_V1.md` records A179's prospectively
frozen complete-domain replay of the known A178 challenge.  It preserves the
exact recovered word and empty control while reducing native state count from
67,108,864 uint64 packs to 16,777,216 vector-256 states, an exact fourfold
packing advance with scalar, boundary, and v1/v2 equivalence gates.

`FULLROUND_CAUSAL_CHACHA20_METAL_REPLAY_V1.md` records A181's prospectively
frozen Apple M4 Metal complete-domain equivalence.  Sixteen batches cover all
`2^32` candidates, reproduce `0x903db747`, reject the control, and independently
confirm 512 bits.  The local 4.66-second integrated command and pre-freeze
throughput probe are explicitly volatile, noncanonical execution context.

`FULLROUND_CAUSAL_CHACHA20_METAL_WIDTH36_PARTIAL_KEY_RECOVERY_V1.md` records
A182's genuinely fresh exhaustive fullround 36-bit partial-key recovery.  With
220 key bits known, 16 nibble slices and 256 Metal batches cover all `2^36`
assignments, uniquely recover `0x3069630b3`, reject the control, and confirm all
512 bits.  The scope is 36 unknown key bits, not full 256-bit key recovery.

`FULLROUND_CAUSAL_CHACHA20_METAL_WIDTH38_PARTIAL_KEY_RECOVERY_V1.md` records
A183's genuinely fresh exhaustive fullround 38-bit partial-key recovery.  With
218 key bits known, 64 low-bit slices and 1,024 Metal batches cover all `2^38`
assignments, uniquely recover `0x1a15b63e04`, reject the control, and confirm
all 512 bits.  The scope is 38 unknown key bits, not full 256-bit key recovery.

`FULLROUND_CAUSAL_CHACHA20_METAL_WIDTH40_PARTIAL_KEY_RECOVERY_V1.md` records
A184's genuinely fresh exhaustive fullround 40-bit partial-key recovery.  With
216 key bits known, 256 low-byte slices and 4,096 Metal batches cover all
`2^40` assignments, uniquely recover `0x2874913214`, reject the control, and
confirm all 512 bits.  The scope is 40 unknown key bits, not full 256-bit key
recovery.

`CAUSAL_CHACHA20_SMT_DIRECTIONAL_ROUND4_TRANSFER_V1.md` records A185's fresh
prospectively frozen reduced ChaCha round-4 directional transfer. Five matched
SMT views execute at the same 30-second budget: forward, inverse, and split3
return `unknown`, while split1 and split2 independently return
`0x230f1aee2d` and each confirms all 512 target bits.

`CAUSAL_CHACHA20_SMT_DIRECTIONAL_ROUND5_BOUNDARY_V1.md` records A186's fresh
prospectively frozen reduced ChaCha round-5 boundary. Forward, inverse, and all
four midstate cuts execute at the same 30-second budget; all six return
`unknown`, the complete order is retained, and no assignment is emitted.

`CAUSAL_CHACHA20_SMT_SHARED_KEY_MULTIBLOCK_TRANSFER_V1.md` records A187's fresh
prospectively frozen reduced ChaCha5 shared-key stacking transfer. Complete b8
reduces decisions/conflicts by 20.93x/75.54x relative to b1, and all three
fixed-total-512-bit sparse views beat b1 on both counts under the same fixed
resource limit.

`CAUSAL_CHACHA20_BITWUZLA_ROUND5_RECOVERY_V1.md` records A188's complete fresh
eight-variant portable SMT-LIB2 portfolio. The predeclared Bitwuzla bitblast b8
view returns `0x5345585503`; an independent implementation matches all 4,096
target bits and rejects the control. The exact result includes the observed
b4-to-b8 instance boundary.

`CAUSAL_CHACHA20_BITWUZLA_ROUND6_WIDTH20_RECOVERY_V1.md` records A189's fresh
prospective reduced ChaCha6 width-20 transfer. The predicted Bitwuzla bitblast
b8 view recovers low20 `0x6fa70` and independently confirms all 4,096 bits;
preprop b8 and the predeclared b1 view return the identical assignment with
independent confirmation.

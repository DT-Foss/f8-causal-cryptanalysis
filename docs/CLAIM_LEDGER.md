# Claim ledger

## Reading rule

A public claim is admissible when its attack model, known variables, recovered
object, complexity, controls, result artifact, and reproduction command are all
identified. A small p-value alone is not substituted for a cryptanalytic
object. Exact algebraic equalities and complete-basis proofs are labeled as
such; empirical confirmations retain their sample counts.

## Retained public claims

| IDs | Public claim | Evidence |
|---|---|---|
| Anchors 1--12 | Twelve full-round known-key internal-boundary F8 configurations are preserved in the original curated suite. | `provenance/fullround_anchors/f8/`, `ANCHOR_SHA256SUMS`, source commit `2e23b23...e62f73` |
| A107--A109 | PRESENT-128 R31→R32 has exactly seven population-nonzero single-bit F8 cells, predicted from pLayer fixed points and the S-box truth table. | `present128_*`, `present_fullround_exact_mechanism_v1.*` |
| A110--A112 | SHA-256 and SHA-512 full compression feed-forward is exactly invertible with the chaining state, and its complete carry spectrum matches the analytic predictor. | `sha{256,512}_fullround_feedforward_*`, `sha{256,512}_feedforward_carry_*` |
| A114 | The FEAL-32X Reader reconstructs the complete R30 right half at the R32 endpoint from the declared joint relation and known final subkey. | `feal32x_fullround_reader_inverse_v1.*` |
| A115 | The SHACAL-2 Reader cancels the shared R64 `T1` branch and reconstructs `d63` exactly. | `shacal2_fullround_cancellation_reader_v1.*` |
| A116 | SPARKLE-256/384/512 expose exact final-step projections and finite-order linear inverses at complete standard permutation endpoints. | `sparkle_fullstep_causal_v1.*` |
| A117--A118 | BLAKE3's full compression output plus known CV reconstructs all 512 post-round bits; the XOR-to-subtraction control follows an exact coupled-borrow spectrum. | `blake3_fullcompression_reader_v1.*`, `blake3_output_borrow_spectrum_v1.*` |
| A119--A120 | ChaCha20 block output plus public inputs reconstructs eight post-round core lanes; a known key extends this to all sixteen; the full carry spectrum is predictable from the addends. | `chacha20_fullround_feedforward_reader_v1.*`, `chacha20_feedforward_xor_carry_spectrum_v1.*` |
| A121 | Complete SHAKE128/256 first squeeze blocks exactly expose every post-Keccak rate lane after 24 rounds. | `shake_fullround_rate_reader_v1.*` |
| A122 | Capacity-to-next-rate Boolean Jacobians have full capacity rank at all ten tested SHAKE bases; every same-base single-bit intervention is Reader-identifiable. | `shake_capacity_jacobian_reader_v1.*` |
| A123--A127 | With the capacity complement known, consecutive SHAKE blocks uniquely determine every tested 8--32 coordinate window by exact 24-round consistency. | `shake_*window*_v1.*`, extended manifest |
| A128 | An exact 24-round SHAKE128 Tseitin-CNF Reader reconstructs and proves uniqueness for 4/8/12-coordinate windows; its 16-coordinate registered timeout localizes a solver-scaling boundary. | `shake_boolean_cnf_reader_v1.*`, solver-frontier manifest |
| A129 | One complete deterministic 16-bit window truth space per SHAKE variant shows that single-coordinate prefix certificates collapse at R3, while 32 full-round output bits uniquely identify each tested assignment. | `shake_prefix_observability_frontier_v1.*`, solver-frontier manifest |
| A130 | Under the declared known-complement model, an exact full-round affine-hull prefix distinguisher/Reader over 128 next-rate coordinates leaves only the actual 10-bit prefix in each tested SHAKE128/256 window. | `shake_affine_hull_frontier_v1.*`, solver-frontier manifest |
| A131 | Exact ANFs of the first 128 restricted SHAKE rate-coordinate functions reach full degree 16 and random-like coefficient density at R5 in both tested windows, remaining saturated through R24. | `shake_algebraic_degree_frontier_v1.*`, solver-frontier manifest |
| A132 | Six complete restricted truth spaces show near-all-to-all Boolean influence at R3 and complete, approximately balanced 16x1,600 coupling at measured R4, R5, and R24. | `shake_boolean_influence_frontier_v1.*`, solver-frontier manifest |
| A133 | An exact shared-ANF transform exposes 20.44x/19.84x R3 compression advantages over the best raw codec and reconstructs all 419,430,400 persisted truth values exactly. | `shake_anf_compression_cascade_v1.*`, `shake_anf_dictionary_v1.anfpack` |
| A134 | Direct Boolean-ring compilation produces exact R2 formulas across the complete 256-bit SHAKE128 and 512-bit SHAKE256 capacities without materializing a truth table. | `shake_symbolic_anf_frontier_v1.*`, solver-frontier manifest |
| A135 | The native-XOR symbolic-R2 Reader reconstructs and proves unique 4/8/12-coordinate SHAKE128 windows with 3.53%/17.02%/5.98% of the canonical-CNF decision counts. | `shake_symbolic_r2_smt_reader_v1.*`, solver-frontier manifest |
| A136 | An exhaustive, ground-truth-blind 16-branch partition reconstructs the 16-coordinate assignment 35,837 and independently reproduces all 1,344 next-rate bits. | `shake_symbolic_r2_partition_reader_v1.*`, solver-frontier manifest |
| A137 | Under matched full-round queries, the exact R1 symbolic handover minimizes decisions against R2 and R3; at width 12 it is 196.46x below canonical CNF. | `shake_symbolic_split_frontier_v1.*`, solver-frontier manifest |
| A138 | The monolithic R1 Reader reconstructs the 16-coordinate assignment 35,837 in 4,701 decisions and independently matches all 1,344 next-rate bits without a supplied prefix. | `shake_symbolic_r1_scaling_reader_v1.*`, solver-frontier manifest |
| A139--A141 | Three complete disjoint width-20 R1 partition plans—Low-4, Upper-4, and exact quadratic Max-Cover-4—each record 16 `unknown` branches under the stored 60-second/five-worker resource schedule. | `shake_symbolic_r1_{partition_scaling,upper_partition,structural_partition}_reader_v1.*`, solver-frontier manifest |
| A142 | Direct monolithic transfer of the SHAKE128-selected R1 handover to SHAKE256 widths 16/20/24 records `unknown` at each stored 120-second single-thread boundary. | `shake256_symbolic_r1_scaling_reader_v1.*`, solver-frontier manifest |
| A143--A146 | Exact R1-graph Structural-6 and solver-strategy experiments map the width-20 resource boundary; the explicitly posthoc-conditioned frontier first returns a complete-rate-verified model at depth eight. | `shake_symbolic_r1_structural6_partition_reader_v1.*`, `shake_symbolic_r1_structural_depth_frontier_v1.*`, `shake_symbolic_r1_z3_strategy_frontier_v1.*`, `shake_symbolic_r1_z3_structural6_partition_reader_v1.*`, solver-frontier manifest |
| A147 | A frozen graph-only eight-coordinate schedule finds the width-20 assignment 227,581 without assignment, target projection, or outcome-prioritized branch order as runtime inputs and independently reproduces all 1,344 next-rate bits. | `shake_symbolic_r1_structural_k8_reader_v1.*`, solver-frontier manifest |
| A148--A151 | The width-24 R1 graph consists of nine disjoint edges, so its minimum vertex-cover size is exactly nine; the final uniform complete-domain schedule finds assignment 4,845,375 in 4,734 decisions and independently reproduces all 1,344 next-rate bits. | `shake_symbolic_r1_width24_{depth_frontier,vertex_cover_reader}_v1.*`, solver-frontier manifest |
| A185 | On a fresh reduced ChaCha4 40-bit relation, predeclared split1 and split2 SMT views independently recover `0x230f1aee2d` and each pass a complete 512-bit confirmation. | `chacha20_smt_directional_round4_transfer_v1.*`, fullround-transfer manifest |
| A186 | On a fresh reduced ChaCha5 40-bit relation, all six matched directional/midstate views reach the identical fixed-resource boundary with the complete execution order and empty model fields retained. | `chacha20_smt_directional_round5_transfer_v1.*`, fullround-transfer manifest |
| A187 | Prospectively frozen eight-block shared-key stacking reduces fixed-resource ChaCha5 search decisions/conflicts by 20.93x/75.54x for complete b8 versus b1; every fixed-total-512-bit sparse stacked view also improves both counters. | `chacha20_smt_shared_key_multiblock_transfer_v1.*`, fullround-transfer manifest |
| A188 | A predeclared Bitwuzla bitblast b8 view recovers the fresh reduced ChaCha5 40-bit assignment `0x5345585503`; independent recomputation matches all 4,096 target bits and rejects the control. | `chacha20_bitwuzla_round5_transfer_v1.*`, fullround-transfer manifest |
| A189 | The prospectively selected Bitwuzla b8 route recovers fresh reduced ChaCha6 low20 assignment `0x6fa70`; bitblast/preprop b8 independently confirm 4,096 bits and the b1 route confirms 512 bits. | `chacha20_bitwuzla_round6_width20_transfer_v1.*`, fullround-transfer manifest |
| A190--A194 | Complete assignment-free partitioning crosses the A190 ChaCha7 monolithic boundary and yields confirmed reduced-round assignments at rounds 7, 8, and 9; all stated complete-domain and open-cell boundaries are retained exactly. | `chacha20_bitwuzla_round{7,8,9}_*_v1.*`, fullround-transfer manifest |
| A195--A198 | Four complete ChaCha10 covers—split8, split9, width-12 refinement, and eight-block two-budget—retain exact all-UNKNOWN representation/resource frontiers without shrinking the `2^20` candidate domain. | `chacha20_bitwuzla_round10_*_v1.*`, fullround-transfer manifest |
| A199--A203 | Formula-atlas operators expose exact public ChaCha structure; layout conjugacy explains the dominant phase contrast; affine geometry, global CSE, and lane-major transfers retain their measured ChaCha10 boundaries. | `chacha20_{formula_operator_atlas,phase_conjugacy_holdout,round10_*}_v1.*`, fullround-transfer manifest |
| A204 | Exact standalone-CNF calibration and 70-probe literal mapping independently recover the A188 model; the selected CaDiCaL reverse rule yields 32 valid UNKNOWN observations on the complete prospective ChaCha10 cover. | `chacha20_round10_external_cnf_reverse_v1.*`, fullround-transfer manifest |
| A205-r2 | A complete 23-order by two-mode A188 calibration contains 16 confirmed SAT witnesses and 12 non-control structural candidates; `bidirectional_min_distance` is uniquely successful in both modes. The r2 correction changes metadata only. | `chacha20_a188_cnf_structural_ordering_v1.*`, fullround-transfer manifest |
| A206 | The robust A205-r2 order transferred to every ChaCha10 prefix and both solver modes yields 64 valid UNKNOWN observations, with exact transforms and progress counters retained. | `chacha20_round10_bidirectional_min_distance_v1.*`, fullround-transfer manifest |
| A207 | Twelve exact structural permutations and the 11-mode/352-cell plan are frozen before execution. All 352 new and 416 combined calibrated cells are valid UNKNOWN; reverse `output_unit_bfs_far` retains a systematic 2.759x-conflict/5.686x-decision progress outlier. | `chacha20_round10_structural_{order_archive,orders,portfolio}*`, fullround-transfer manifest |
| A208 | The selected reverse `output_unit_bfs_far` order remains a complete 32-cell UNKNOWN boundary at sixty seconds, while exact early/late integer counters establish a systematic all-prefix transition toward propagation/restart work after ten seconds. | `chacha20_round10_bfs_far_long_budget_v1.*`, fullround-transfer manifest |
| A209 | Complete Width-12 refinement plus a rederived multi-source BFS-far order retains 256 UNKNOWN cells but systematically resets the search phase: decisions, propagations, and restarts increase in every child and decision/propagation density increases in every parent group. | `chacha20_round10_bfs_far_width12_refinement_v1.*`, fullround-transfer manifest |

The filenames above are rooted at `research/results/v1/`; full hashes are in
`FULLROUND_TRANSFER_SHA256SUMS`, `SHAKE_NATIVE_EXTENDED_SHA256SUMS`, and
`SHAKE_SOLVER_FRONTIER_SHA256SUMS`.

## Exact boundaries attached to those claims

| Result | Boundary encoded in the public claim |
|---|---|
| Original F8 anchors | Known-key, instrumented adjacent internal states; not ciphertext-only key recovery. |
| FEAL-32X | Known final two-byte subkey and cross-round joint difference. |
| SHACAL-2 | Known-key internal R63/R64 endpoint. |
| SPARKLE | Public permutation relation; no secret variable is introduced. |
| BLAKE3 | Complete 64-byte compression output and input CV for full state; not a standalone 32-byte digest inversion. |
| ChaCha20 | Public reconstruction covers only public-position lanes; complete core reconstruction additionally uses the known key. |
| SHAKE rate | Output projection of rate coordinates, with capacity remaining outside that object. |
| SHAKE Jacobian | Local one-bit observability at fixed bases; two-bit responses are nonlinear. |
| SHAKE windows | Known complement and exact `2^k` work; no claim of unrestricted 256-/512-bit capacity recovery. |
| SHAKE Boolean CNF | Exact complete-rate constraint circuit; the 16-bit timeout is a representation boundary, not a cryptanalytic break. |
| SHAKE prefix frontier | Complete 16-bit truth spaces; 32-bit output discrimination coexists with the R3 collapse of single-coordinate branch certificates. |
| SHAKE affine hull | One deterministic 16-bit window per variant and known state complement; the current exact construction evaluates all `2^16` points and does not reduce the exponent. |
| SHAKE ANF frontier | One deterministic 16-bit window per variant and 128 restricted coordinate functions; it localizes the tested sparse-to-dense transition, not the global algebraic degree of unrestricted SHAKE inputs. |
| SHAKE influence frontier | Three deterministic 16-bit windows per variant with known complements and instrumented internal states; it is a restricted dependency map, not an unrestricted input theorem or output-only recovery. |
| SHAKE shared ANF | Complete restricted 16-bit truth spaces; compression is lossless formula reuse, not variable-component factorization. |
| SHAKE symbolic R2 | Exact direct formulas over declared variable capacity coordinates; the retained object is the R2 interface, not unrestricted full-capacity recovery from output. |
| SHAKE native-XOR Reader | Known first-state complement and complete next-rate observation; solved widths have exact blocked-model uniqueness certificates. |
| SHAKE partition Reader | The 16-coordinate model is independently verified; fifteen unresolved branches mean this artifact does not assert global uniqueness. |
| SHAKE split frontier | Width-16 rows compare a fixed, already verified branch to select representation; the autonomous search result is A136/A138. |
| SHAKE R1 scaling | Width 16 has an exact verified model; its blocked query and widths 20/24 are recorded solver boundaries, not uniqueness results. |
| SHAKE R1 partition topology | Each four-coordinate plan exhausts all 16 disjoint branches, but all statuses remain `unknown`; this maps three exact representation/resource boundaries and does not assert ambiguity or general resistance. |
| SHAKE256 R1 transfer | Only A137's R1 split choice transfers; no SHAKE128 outcome is imported. The three bounded first queries do not exclude another split or partition. |
| SHAKE R1 structural depth | A145 supplies posthoc branch values to localize a mechanism threshold; it is not assignment-free search. A143/A146 retain complete plans and exact resource limits. |
| SHAKE R1 assignment-free `k=8` | A147 verifies one width-20 model after eight complete waves; unresolved and unexecuted branches remain outside any global-uniqueness claim. |
| SHAKE R1 width-24 vertex cover | A151's runtime accepts neither the assignment nor target projection. Its formula ordering and uniform 120-second cap were nevertheless developed from A148/A149 on the same instance, so the result is explicitly non-blind and posthoc-informed. All 512 branches are planned uniformly; only 20 execute before the verified complete-wave early stop. |
| ChaCha A185 direction transfer | Fresh reduced round 4 with 40 unknown key bits and 216 known key bits; this is not the fullround A184 relation. |
| ChaCha A186 direction boundary | Six `unknown` statuses under the frozen 30-second per-view budget retain an exact representation/resource boundary; they do not assert ambiguity. |
| ChaCha A187 block stacking | All ten formulas return `unknown`; the retained object is the prospectively predicted fixed-resource search-shape change, not a recovered model. |
| ChaCha A188 engine portfolio | Fresh reduced round 5 with 40 unknown key bits; the stored Z3 `invalid` row is the exact no-status-token parser boundary, while the predeclared Bitwuzla b8 model passes independent confirmation. |
| ChaCha A189 round-depth transfer | Fresh reduced round 6 with 20 unknown and 236 known key bits; the recovered object is the stated low20 assignment. |
| ChaCha A190--A194 partition transfers | A191/A192 cover their complete domains and retain the stated UNSAT cells; A193/A194 confirm one model while the other 31 cells remain UNKNOWN, so uniqueness is not asserted there. |
| ChaCha A195--A198 round-10 frontiers | Complete structural coverage is not proof of absence when every bounded cell is UNKNOWN. |
| ChaCha A199--A203 formula transfers | Public operator structure and representation effects are measured objects; A201 attributes the dominant contrast to known layout conjugacy and does not relabel it as a new break. |
| ChaCha A204 external CNF | The A188 known-positive calibration is separate from the prospective A204 round-10 cover; the former recovers a model and the latter remains 32 UNKNOWN. |
| ChaCha A205-r2 structural ordering | The known-positive model is available only for post-witness confirmation, not order construction or solver input; the r2 change corrects this metadata without rerunning or changing observations. |
| ChaCha A206 structural transfer | All 64 statuses are UNKNOWN, not UNSAT; no round-10 partial-key recovery or uniqueness is claimed. |
| ChaCha A207 structural portfolio | All 416 calibrated statuses are UNKNOWN, not UNSAT. The progress-map ratios are mechanistic solver counters measured under the frozen schedule, not a recovered model. |
| ChaCha A208 long-budget phase | All 32 statuses are UNKNOWN, not UNSAT. The retained result is an exact temporal solver-counter transition for the selected order, not a recovered model or an all-order theorem. |
| ChaCha A209 Width-12 phase reset | All 256 statuses are UNKNOWN, not UNSAT. The systematic counter-density reset is a representation/search-phase result, not a recovered key or terminal cell. |

These are compact attack-model definitions, not qualifications added after the
result. They state the mathematical object that the code actually computes.

## Historical conference-claim audit

[`research/claims/claim_evidence.csv`](../research/claims/claim_evidence.csv)
maps every material ICECET and NANO manuscript claim to source lines, scripts,
retained results, and an evidence status. It preserves discrepancies found
during clean-room replay instead of rewriting conference history.

The statuses mean:

- `EVIDENCED`: script, retained output, and exact reproduction command exist;
- `PARTIAL`: one layer is absent or the stored protocol differs;
- `CONTRADICTED`: retained control evidence directly disagrees with the exact
  historical wording;
- `EXTERNAL_ONLY`: support depends on a cited external primary source.

The A107--A151 and A185--A209 claims above are governed by their newer JSON/Reader evidence and
must not be inferred from the older manuscript table.

## Control and boundary results

Control results remain first-class prior art. Examples include the FEAL raw
single-bit marginalization boundary (A113), the generic QF_BV SHAKE solver
boundary (A124), the corrected shared-route analyses, and independently tested
representations that return the null distribution. They specify where a
mechanism is and is not visible, prevent duplicate work, and determine the next
experiment's representation.

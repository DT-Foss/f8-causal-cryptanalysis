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

The A107--A138 claims above are governed by their newer JSON/Reader evidence and
must not be inferred from the older manuscript table.

## Control and boundary results

Control results remain first-class prior art. Examples include the FEAL raw
single-bit marginalization boundary (A113), the generic QF_BV SHAKE solver
boundary (A124), the corrected shared-route analyses, and independently tested
representations that return the null distribution. They specify where a
mechanism is and is not visible, prevent duplicate work, and determine the next
experiment's representation.

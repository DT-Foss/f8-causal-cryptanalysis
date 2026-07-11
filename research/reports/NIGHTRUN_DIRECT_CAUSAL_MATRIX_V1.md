# Nightrun Direct-Causal Matrix

This matrix consolidates only Reader-reconstructed artifacts that survived the
current controls.  Scope is stated per row; a full-round known-key cross-round
result remains a full-round result and is not relabeled as reduced-round merely
because it is an internal-boundary measurement.

| line | retained object | strongest evidence | boundary |
|---|---|---|---|
| AES | R3 peeled, nodes 13/11/14/12 | 18--19/20 with pooled variance, shared BvN, unseen bits and new keys; extends to byte XORs | Random→counter transfers; counter→random and mixed-domain training collapse. Not domain-invariant. |
| AES | R1/R3 frontier | R1 20/20, R3 18/20 over R1--R10; fresh R1-vs-R3 20/20 each | R2 and R4--R10 do not form comparable peaks. |
| ChaCha | R3 core, nodes 10/13/5/9 | R3-vs-R20 bit-transfer 13--14/20 vs R20 20/20, shared routes, pooled reader, pre-feed-forward core | Random-base dependent; sequential bases do not retain the top-4 graph. |
| ChaCha | R2 byte atlas, nodes 5/52/11/7; minimal byte 7 for R1/R2 only | R1/R2, R2/R3, R2/R20, bit and byte interventions, Random↔Sequential, and counter-word-masked full output all reach 10/10 per binary class in their stated runs; byte 7 alone is R1/R2 10/10 in both domain directions | Byte 7 alone is R2/R3 5/10, so R2/R3 needs the four-node atlas. This atlas itself carries no full ChaCha20 claim. |
| ChaCha20 | full 20-round feed-forward endpoint Readers | RFC gate; public constants/counter/nonce reconstruct 40,000/40,000 eight-lane core states without key-lane input, and the known-key recipe reconstructs 40,000/40,000 complete 512-bit cores. Both 80-route banks give zero words. | Exact block-function endpoint relation, separate from the reduced-round output atlases. Public-position core lanes are not key words. |
| ChaCha20 carry spectrum | addend-conditioned XOR-peeling representation bridge | 40.96M/40.96M exact carry identities; predicted/observed bit accuracy 0.551271/0.551215 over 512 lane/bit cells with r=0.999953; 62.15 complete words predicted and 60 observed. | Wrong-lane prediction falls to r=0.358; spectrum is tied to actual initial lane values. |
| PRESENT-80 | R3/R6 direct-output binary graph; minimal post-S-box pair `(7,14)` | Full entropy graph transfers both Random↔Counter at 20/20 per class. Collision/byte-XOR/bit-bias controls survive. Exact final-stage views show S-box amplification. Joint pair `(7,14)` is 20/20 per class for Random→Counter bit and byte XOR, Random→Mixed, and Mixed→Random. | Pair `(7,14)` fails R3 for Counter→Random (7/20) and Counter→Mixed (11/20), so it is a directed-domain minimal atlas. Broad R1--R6 is not domain-invariant; late R24--R31 screens are chance-level. |
| PRESENT-128 | full-round known-key R31→R32 F8; exact seven-edge pLayer-fixed-point graph | Predicted transfer from PRESENT-80; all 5 fresh keys exceed all BvN routes with Z 749.68--1390.45. Exact derivation gives 7 nonzero and 4089 zero population cells; empirical top seven match exactly. | Complete for the single-bit `E_r` vs `E_r xor E_(r+1)` population support. Joint higher-order probes are a distinct object. |
| SHA-256 | full 64-step compression feed-forward; eight universal same-lane bit-0 edges | Fixed-IV and random-chaining modes each pass 40,000/40,000 identities; total MI 5.5444/5.5435, Z 3513--15085 | Universal for bit 0 of each of eight lanes. Fixed-IV carry spectrum supplies 12 exact cells total. |
| SHA-512 | full 80-step compression feed-forward; SHA-256 word-width transfer | Fixed-IV and random-chaining modes each pass 40,000/40,000 identities; total MI 5.5442/5.5446, Z 1913--13101 | Universal for bit 0 of each lane. Fixed-IV carry spectrum supplies 11 exact cells total. |
| SHA-2 carry spectrum | exact fixed-addend full-word channel | 3.84M/3.84M conditional carry identities across SHA-256/512; analytic/observed r 0.999597/0.999492 | Higher-bit MI depends on the chaining word; minimal graphs contain only structurally exact no-carry cells. |
| BLAKE3 | full seven-round compression output Reader | Seven official XOF vectors; first 32 bytes give 320,000/320,000 exact final lane-pair XOR words. Complete 64-byte output plus known CV reconstructs 40,000/40,000 complete 512-bit post-round states; all 80 BvN routes give zero words. | The complete-state result requires full compression output plus CV. A standalone 32-byte digest carries the eight pair-XOR words, not separated state halves. |
| BLAKE3 borrow spectrum | exact XOR-to-subtraction representation bridge | Four-state coupled-borrow theorem; 20.48M/20.48M bit identities, analytic/observed accuracy 0.6059028/0.6059255, r=0.999969; `(3/4)^31` predicts 85.72 full words and 87 occur. | Formula-substitution spectrum at the full-compression endpoint; separate from the exact XOR Reader. |
| SHAKE128/256 | full 24-round Keccak-f[1600] first-squeeze rate Readers | Zero-state permutation and FIPS/hashlib gates; 80,000/80,000 rate states, 1.52M lanes and 97.28M bits reconstructed. Complete basis proofs give rank/kernel 1344/256 and 1088/512. All 160 BvN banks and representation controls give zero lanes. | Exact squeeze coordinate projection. One rate block leaves precisely the capacity-coordinate kernel; no one-block capacity reconstruction is asserted. |
| SHAKE capacity Jacobian | capacity-to-next-rate response after another full 24-round permutation | Ten complete Boolean Jacobians: SHAKE128 rank 256 x5, SHAKE256 rank 512 x5; 3,840/3,840 same-base single-bit interventions identified. BvN, cross-base and lane controls give zero labels. | Base-local first-order observability. All 1,280 two-bit tests activate dense nonlinear interaction; no ordinary-output or global-linear inverse claim. |
| SHAKE capacity-window inference | exact consecutive-block reverse query with known capacity complement | SHAKE128/256 windows 8/12/16/20 all uniquely recovered; 2,236,928 complete 24-round candidate evaluations, one two-lane survivor and one complete-rate survivor per run, zero wrong-target candidates. | Work is exactly `2^k`; retained as the executable 20-bit inference baseline, not full-capacity reconstruction. |
| SHAKE bit-sliced capacity-window consistency | candidate-axis-transposed exact 24-round Reader | A 64-state independent implementation gate checks all 102,400 output bits. SHAKE128/256 20- and 24-coordinate windows are all uniquely recovered; 35,651,584 logical candidates are represented by 557,056 packed states, and every independent target has zero survivors. | The representation reduces machine-word state evaluations by exactly 64 while retaining the logical `2^k` search space. The known rate and capacity complement remain explicit inputs. |
| SHAKE native capacity-window consistency | fused C11/POSIX candidate-axis full-round Reader | Native-vs-scalar checks match all 102,400 state bits and native-vs-NumPy candidate masks match exactly for both variants. SHAKE128/256 remain uniquely consistent at 24, 28, and 32 coordinates; the 32-coordinate artifact exhausts 8,589,934,592 logical candidates as 134,217,728 packs with zero independent-target survivors. | Bounded streaming and threads move the executable frontier, while logical work remains `2^k`. Rate and capacity complement are explicit known coordinates; this is not an all-capacity claim. |
| SHAKE Boolean CNF Reader | exact 24-round Tseitin circuit with complete next-rate constraints | SHAKE128 windows 4/8/12 are reconstructed exactly and second-model queries are UNSAT; width 16 reaches the configured 120-second boundary. The exact circuits contain 139,952--144,125 variables and 525,709--541,204 clauses. | Internal decisions already exceed explicit assignment counts at solved widths. The CNF is an exact representation but not an executable scaling improvement over native bit slicing. |
| SHAKE prefix-observability frontier | complete `2^16` per-round truth-space Reader | For SHAKE128/256, fixed rate coordinates with no assigned prefix fall 1344/1088 -> 1060/871 -> 8/10 -> 0/0 over rounds 0/1/2/3. At R24, prefixes through 12/16 retain zero constants; the final 3/2/1-coordinate counts match random-function expectations closely. | Exact output prefixes discriminate complete assignments—32 bits leave one each—but coordinate-wise partial-branch propagation has no early certificate after round 3. |
| SHAKE affine-hull prefix Reader | exact GF(2) hulls of first 128 rate coordinates over every `2^16` branch partition | Prefix 8 leaves all 256 branches; prefix 9 leaves 195/512; prefix 10 leaves exactly the actual branch out of 1,024 in both SHAKE128/256 and remains unique at 11/12. Actual-branch ranks are 128/127/63/31/15 for prefixes 8/9/10/11/12, and false survivors match rank-derived random expectations. | Joint parity conditions retain branch information after all individual coordinates vary. Current construction still materializes the complete truth space; deriving hull constraints without all suffix points is the open representation step. |
| SHAKE algebraic-degree frontier | exact ANFs of the first 128 rate coordinates over complete `2^16` capacity-window spaces | Maximum degree progresses 0/1/3, reaches 7/6 at R3 and 14/12 at R4, then reaches the full 16 in both variants at R5. Mean coefficient counts at R5 are 32,768.09/32,773.56 against random expectation 32,768 and remain saturated through R24. | Truth tables are already balanced at R3 while ANFs remain only 1.34%/1.40% dense. The exploitable sparse algebraic zone ends between R3 and R5; direct full-round ANF expansion is dense. |
| SHAKE Boolean-influence frontier | complete single-window-coordinate interventions against all 1,600 state coordinates over six `2^16` truth spaces | R2 has 8,308--8,927 of 25,600 nonzero cells; R3 has 25,597--25,600 and 1,597--1,600 fully coupled coordinates. R4--R24 have all 25,600 cells nonzero in every trial, with R4/R24 maximum deviations from influence 0.5 of 0.013062/0.012054. | Sparse R3 ANFs are already virtually all-to-all in variable support. R2 is the last measured incomplete influence-support layer, while the monomial graph is already complete there; R4 is the first uniformly all-to-all layer. |
| SHAKE shared-ANF compression | lossless global monomial dictionary plus packed 1,600-coordinate coefficient matrix; generic codecs and ordered double cascades | At R3, raw 13.11MB truth spaces compress only to 12.96/13.07MB, while shared-ANF+LZMA reaches 634/659KB, a 20.44x/19.84x advantage. R2 advantages are 44.65x/44.29x; R4 falls to about 1.02x and R24 to none. All four persisted R2/R3 records reconstruct 419.43M truth values exactly. | The monomial primal graph is already complete at R2; compression comes from reuse of only 275/277 low-degree features, not independent variable components. No two-codec cascade beats single LZMA. |
| SHAKE symbolic R2 compiler | exact Boolean-ring compilation of all 1,600 state formulas without `2^k` truth tables | Full SHAKE128 capacity (256 variables) yields 6,918,733 degree-at-most-4 coefficients; full SHAKE256 capacity (512 variables) yields 64,724,568. The 512-bit coordinate-sparse interface is 4.142GB, a `2^487.696` factor below its formal truth table. Width-16 coefficient hashes match the exhaustive A133 artifacts and 94,720 independent state bits match across all widths. | This changes the R2 representation exponent, not the R3--R24 suffix. The R2 primal graph is complete; the gain is shared symbolic features rather than independent components. |
| SHAKE symbolic-R2 native-XOR Reader | exact R2 Boolean-ring interface joined to an exact R3--R24 Boolean suffix and the complete next-rate observation | Widths 4/8/12 reconstruct exactly and blocked-model queries are UNSAT. Native-XOR first-query decisions are 2,025/8,252/35,088, only 3.53%/17.02%/5.98% of the canonical CNF counts. | The monolithic width-16 instance retains the configured boundary; solved-width work identifies native XOR preservation as a major representation gain, not by itself a complete decomposition. |
| SHAKE symbolic-R2 partition Reader | complete disjoint low-four-coordinate prefix schedule over the 16-coordinate instance | The ground-truth-blind 16-branch schedule returns assignment 35,837 from branch 13 in 5,967 decisions; independent 24-round evaluation matches all 1,344 next-rate bits. | Fifteen branches reach their local limit, so this artifact establishes autonomous model reconstruction while leaving branch-local global uniqueness certificates as the next solver target. Five workers are the retained 10-core/16-GB resource configuration. |
| SHAKE symbolic prefix-split frontier | exact R1/R2/R3 Boolean-ring interfaces attached to the same complete remaining-round systems | At width 12, decisions are 2,986/35,088/4,441 for R1/R2/R3; R1 is 196.46x below canonical CNF. On the fixed A136 width-16 model branch, R1 uses 1,909 decisions versus 5,967 for R2, while R3 reaches the configured boundary after expanding to 7,512 monomials. | R2 remains the compact storage interface, but R1 is the measured Reader optimum because it preserves the second round as local explicit equations. Compression optimum and decision optimum are distinct. |
| SHAKE symbolic-R1 scaling Reader | A137-selected exact R1 interface plus 23 explicit rounds, no fixed prefix | The monolithic 16-coordinate system returns assignment 35,837 in 4,701 decisions, 7.17% of the complete assignment count; independent evaluation matches all 1,344 rate bits. | The blocked query and monolithic widths 20/24 reach the configured boundary. R1 formulas remain small and degree at most two, selecting subspace decomposition over the same interface. |
| FEAL-32X | full-round R30→R32 distance-2 Reader inverse | NTT official ciphertext/intermediate/subkey gates; Reader executes a five-edge recipe and reconstructs 40,000/40,000 complete 32-bit words over five fresh keys. All BvN and previous-round-subkey controls give zero complete words. | Raw 1-bit MI is deliberately masked (Z -1.05 to -0.02); the retained object is the exact joint 32-bit relation. |
| SHACAL-2 | full-round R63→R64 shared-T1 cancellation Reader | Two NESSIE KATs; 40,000/40,000 d63 words and 1.28M/1.28M bits reconstructed from the three-edge Reader recipe. All BvN and wrong-Sigma controls give zero words and about 50% bits. | Formula-aligned internal boundary; mechanism is modular cancellation of the shared T1 accumulator, not SHA-2 feed-forward. |
| SPARKLE-256/384/512 | complete-permutation final full-step projection and finite-order linear Reader | Hash-pinned official C gates; 120,000/120,000 left-half states reconstructed from only final right halves, plus 120,000/120,000 full pre-final-step states via `L^(order-1)`. Complete-basis minimal orders are 6/30/12; aggregate quotient orders 3/10/3. All 240 BvN routes give zero half-state and zero 64-bit-branch matches. | Exact internal full-step family relation. The copied projection is the generalized-Feistel route after Alzette; the stated scope is not an external-secret result. |
| Threefish-256 | direct late-round output codec | R64--R72 is 17/180, below chance | Closed; matches local-transition explanation of legacy F8. |
| ML-KEM | native INDCPA noise→ciphertext | 50,000/50,000 gates, 3/20 four-class accuracy | Closed current chunk-entropy codec. |
| ML-KEM | native INDCPA keyseed→public key | two independent 50,000/50,000-gate blocks, both chance | Closed current chunk-entropy codec. |

## Method controls now mandatory

1. One BvN repair-route bank per exact seed/input-pair batch, shared across
   all compared labels. Class-dependent route seeds were corrected and older
   traversal-R3 interpretation was withdrawn.
2. The `.causal` file is re-opened with `CryptoCausalReader` before every
   reverse query. Writer-side model arrays are not used for held-out scoring.
3. Pooled reader variance is required whenever a class-specific variance floor
   could dominate a small training split.
4. Every new positive needs fresh keys plus a disjoint intervention family;
   where a domain is changed, both directions must be tested before describing
   transfer as symmetric.
5. Functional gates are mandatory for native PQC traces; output-only order
   statistics are not promoted to internal-state claims.

## Next research directions

- For the ChaCha byte atlas, localize the four byte nodes to quarter-round
  paths with exact state-level ablations rather than adding more output
  classifiers.
- For AES R3, test whether a representation that conditions out plaintext
  base-domain scale can recover bidirectional domain transfer; do not relax
  the domain-boundary result without a new held-out test.
- For PRESENT, use the exact pLayer/S-box criterion to predict new SPN transfers
  statically.  Keep the separate direct-output R3/R6 atlas and the full-round
  cross-round F8 theorem as distinct estimands.
- For SPARKLE, use the now-proved branch projection and 6/30/12 linear orders
  as algebraic primitives for a prediction-first two-step composition; do not
  relabel the one-step generalized-Feistel route as a whole-permutation secret
  inference statement.
- Keep PQC on genuinely new native deterministic relations; the current
  noise-coin and keyseed chunk-entropy branches are closed.
- For SHAKE, treat 32-coordinate native consistency as the new executable
  baseline.  The next useful step must change the exponent or expose a new
  relation; simply extending the same exhaustive window is no longer a distinct
  mechanism result.
- The exact prefix frontier rules out single-coordinate constancy as that
  exponent change.  Continue with joint affine/parity constraints or a genuine
  round split, using the transition from incomplete R2 coordinate support to
  nearly all-to-all R3 influence as the localization boundary.
- The affine hull now supplies the joint-relation transition: 128-coordinate
  hull membership identifies the actual 10-bit prefix.  Next derive or predict
  those 65 branch relations without complete suffix enumeration.
- The ANF frontier localizes the remaining algebraic structure: preserve the
  sparse R3 polynomials only as low-degree equations, not as independent
  variable components.  The shared-dictionary result identifies R2 as the
  compact round-split interface: its primal graph is complete, but all 1,600
  formulas reuse only 275/277 monomials.  Keep R3--R24 separate because full
  symbolic substitution reaches all-to-all influence at R4 and random-like ANF
  density at R5.
- The symbolic compiler now provides that R2 interface directly through the
  complete 256/512-bit capacities without an assignment table.  Connect its
  shared features to a separately encoded R3--R24 suffix; do not expand the
  full composition back into ANF.

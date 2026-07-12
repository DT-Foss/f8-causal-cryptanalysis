# Results

This ledger states each retained result in the same five fields: **attack
model**, **known variables**, **recovered object**, **complexity**, and
**controls**. Numeric claims link to immutable result JSON and the report that
interprets it.

## Original full-round F8 anchors

The committed snapshot at
[`provenance/fullround_anchors/f8/`](../provenance/fullround_anchors/f8/README.md)
contains the twelve original configurations and nine result JSON files from
source commit `2e23b23e46cd7a413edd5b56a748e4d5e6e62f73`.

| Configuration | Full rounds | Reported mechanism | Reported full-round Z |
|---|---:|---|---:|
| Speck32/64 | 22 | beta masking | 4,088 |
| Speck48/96 | 23 | beta masking | 918 |
| Speck64/128 | 27 | beta masking | 1,165 |
| Speck128/256 | 34 | beta masking | 1,776 |
| Threefish-256 | 72 | recurring addition / state reuse | 16,302 |
| Threefish-1024 | 80 | permutation fixed points | 16,537 |
| GIFT-64 | 28 | permutation-cycle relation | 676 |
| GIFT-128 | 40 | permutation-cycle relation | 275 |
| PRESENT-80 | 31 | permutation fixed points | 1,183 |
| TEA | 32 | Feistel self-XOR | 499 |
| RC5-32/12/16 | 12 | Feistel self-XOR | 221 |
| RC5-64/24/24 | 24 | Feistel self-XOR | 444 |

- **Attack model:** known-key adjacent internal boundary `state(R)` versus
  `state(R+1)` for matched inputs.
- **Known variables:** key, input, round index, and the two instrumented states.
- **Recovered object:** distinguished cross-round cell or registered aggregate;
  this tier does not claim key recovery.
- **Complexity:** stored per experiment in the anchor JSON; no expensive anchor
  rerun is needed to authenticate the publication.
- **Controls:** permutation/null, vector, roundtrip, and N-scaling controls as
  recorded per anchor. The independent import audit identifies source-path
  corrections without erasing the original evidence.
- **Integrity:** `research/results/v1/ANCHOR_SHA256SUMS` hashes all 26 committed
  files in the snapshot.

## PRESENT-128: A107--A109

[`FULLROUND_CAUSAL_PRESENT128_V1.md`](../research/reports/FULLROUND_CAUSAL_PRESENT128_V1.md)
and
[`present128_fullround_causal_f8_v1.json`](../research/results/v1/present128_fullround_causal_f8_v1.json)
record a prediction-first transfer from PRESENT-80 to PRESENT-128.

- **Attack model:** known-key R31→R32 adjacent-state F8 on matched plaintexts.
- **Known variables:** key and R31/R32 states.
- **Recovered object:** the complete population-nonzero single-bit F8 support.
- **Result:** exactly 7/4,096 cells have nonzero population MI; the other 4,089
  are exactly zero. Blind discovery ranks 1--7 match those seven cells. All
  five fresh-key confirmation blocks exceed every shared BvN route with Z from
  `749.68` to `1390.45`.
- **Complexity:** 64x64 discovery, five confirmation keys x 5,000 pairs, then
  exhaustive 4-bit S-box derivation.
- **Controls:** official PRESENT-128 KAT, 12/16 shared BvN routes, seven matched
  non-fixed cells, and 576 exact recurrence gates.

## SHA-2 feed-forward: A110--A112

[`FULLROUND_CAUSAL_SHA2_FEEDFORWARD_V1.md`](../research/reports/FULLROUND_CAUSAL_SHA2_FEEDFORWARD_V1.md)
records the SHA-256 64-step and SHA-512 80-step relations.

- **Attack model:** full compression with the input chaining state known.
- **Known variables:** chaining words and compression output.
- **Recovered object:** all eight post-round compressor words by modular
  feed-forward inversion; the follow-up classifies every bit of the carry
  spectrum.
- **Result:** SHA-256 and SHA-512 each pass 40,000/40,000 exact bit-0
  equalities in both fixed-IV and random-chaining modes. The full-word spectra
  pass 1.28 million and 2.56 million exact identities, with predicted/observed
  correlations `0.999597` and `0.999492`.
- **Complexity:** five confirmation blocks x 8,000 inputs per mode and variant.
- **Controls:** hash/KAT gates, shared BvN routes, cross-lane and wrong-addend
  controls, plus fixed-addend analytic prediction.

## FEAL-32X: A113--A114

[`FULLROUND_CAUSAL_FEAL32X_V1.md`](../research/reports/FULLROUND_CAUSAL_FEAL32X_V1.md)
stores both the representation boundary and executable inverse.

- **Attack model:** genuine R30→R32 full-round endpoint with a known two-byte
  final round subkey.
- **Known variables:** the R30 xor R32 left-half difference and final subkey.
- **Recovered object:** complete R30 32-bit right half.
- **Result:** Reader reconstruction is 40,000/40,000 complete words and
  160,000/160,000 bytes.
- **Complexity:** five fresh keys x 8,000 blocks.
- **Controls:** 80 BvN route banks and five previous-round-subkey controls each
  yield zero complete words. The raw single-bit grid demonstrates why the
  relation must be represented jointly.

## SHACAL-2: A115

[`FULLROUND_CAUSAL_SHACAL2_V1.md`](../research/reports/FULLROUND_CAUSAL_SHACAL2_V1.md)
encodes `a64 - e64 = T2 - d63` as a three-edge Reader recipe.

- **Attack model:** known-key R63→R64 internal endpoint.
- **Known variables:** R64 words needed by the cancellation formula and the
  key schedule.
- **Recovered object:** complete `d63` word.
- **Result:** 40,000/40,000 words and 1.28 million/1.28 million bits exact.
- **Complexity:** five fresh 512-bit keys x 8,000 blocks.
- **Controls:** two NESSIE KATs, 80 BvN routes, and five wrong-Sigma blocks;
  every control returns zero whole words.

## SPARKLE: A116

[`FULLSTEP_CAUSAL_SPARKLE_V1.md`](../research/reports/FULLSTEP_CAUSAL_SPARKLE_V1.md)
covers SPARKLE-256/10, SPARKLE-384/11, and SPARKLE-512/12.

- **Attack model:** public full permutation endpoint.
- **Known variables:** complete final permutation state.
- **Recovered object:** complete pre-final-step left half from the final right
  half; the forward-power recipe also reconstructs the preimage state.
- **Result:** 120,000/120,000 half-states and 120,000/120,000 complete states.
  Complete-basis proofs establish linear-layer orders `6/30/12` and aggregate
  quotient orders `3/10/3`.
- **Complexity:** three variants x five seeds x 8,000 states.
- **Controls:** hash-pinned official C gates, 240 BvN route banks, wrong branch,
  step, constants, source half, and linear power.

## BLAKE3: A117--A118

[`FULLCOMPRESSION_CAUSAL_BLAKE3_V1.md`](../research/reports/FULLCOMPRESSION_CAUSAL_BLAKE3_V1.md)
separates the 32-byte projection from complete 64-byte compression output.

- **Attack model:** seven-round BLAKE3 compression.
- **Known variables:** complete 64-byte compression output and input CV for
  full reconstruction; the first 32 bytes alone for the lane-pair projection.
- **Recovered object:** all 512 post-round state bits, or eight lane-pair XOR
  words from the first output half.
- **Result:** 40,000/40,000 complete states and 640,000/640,000 words; the
  subtraction control is explained by a four-state coupled-borrow chain with
  predicted/observed accuracy `0.605902777774/0.605925537109`.
- **Complexity:** five seeds x 8,000 compression inputs.
- **Controls:** seven official XOF vectors, 80 BvN routes, wrong CV lane,
  pairing, operation, and swapped-half controls.

## ChaCha20: A119--A120

[`FULLROUND_CAUSAL_CHACHA20_FEEDFORWARD_V1.md`](../research/reports/FULLROUND_CAUSAL_CHACHA20_FEEDFORWARD_V1.md)
targets the standard RFC 8439 20-round block endpoint.

- **Attack model:** block output inversion of feed-forward addition.
- **Known variables:** public constants, counter, and nonce recover public
  lanes; adding the key recovers the key-position lanes.
- **Recovered object:** eight public-position post-round core lanes or all
  sixteen lanes in the known-key model.
- **Result:** 40,000/40,000 eight-lane states and 10.24 million exact bits in
  the public Reader; 40,000/40,000 complete cores and 20.48 million bits in the
  known-key Reader. The full 16x32 conditional carry spectrum has
  predicted/observed correlation `0.999953`.
- **Complexity:** five key/nonce families x 8,000 counters.
- **Controls:** RFC block gate, 160 route banks across both models,
  addend/lane controls, exact carry identities, and whole-word survival law.

## SHAKE rate projection: A121

[`FULLROUND_CAUSAL_SHAKE_RATE_V1.md`](../research/reports/FULLROUND_CAUSAL_SHAKE_RATE_V1.md)
targets complete first squeeze blocks after Keccak-f[1600].

- **Attack model:** public SHAKE output projection after all 24 rounds.
- **Known variables:** complete first squeeze block.
- **Recovered object:** all rate lanes: 21 for SHAKE128 and 17 for SHAKE256.
- **Result:** 40,000/40,000 rate states per variant, 1.52 million lanes and
  97.28 million bits total. Exact projection rank/kernel are `1344/256` and
  `1088/512`.
- **Complexity:** five seeds x 8,000 messages per variant.
- **Controls:** zero-state Keccak gate, embedded FIPS 202 outputs, `hashlib`,
  complete 1,600-basis proof, 160 BvN banks, lane rotation, and endian control.

## SHAKE local observability: A122

[`FULLROUND_CAUSAL_SHAKE_CAPACITY_JACOBIAN_V1.md`](../research/reports/FULLROUND_CAUSAL_SHAKE_CAPACITY_JACOBIAN_V1.md)
measures capacity-to-next-rate Boolean Jacobians at real squeeze states.

- **Attack model:** one-bit capacity interventions at a fixed known base.
- **Known variables:** base state and complete next rate response.
- **Recovered object:** intervention coordinate.
- **Result:** five SHAKE128 Jacobians rank 256 and five SHAKE256 Jacobians rank
  512; 3,840/3,840 same-base interventions are identified.
- **Complexity:** ten complete Boolean Jacobians.
- **Controls:** 160 BvN banks, cross-base dictionaries, lane rotations, and
  1,280 two-bit responses. No two-bit response equals its linearized
  superposition, recording the nonlinear boundary next to full local rank.

## SHAKE exact state-window reconstruction: A123--A127

The SHAKE solver line progresses without changing the mathematical relation:

| Stage | Windows | Logical candidates | Representation | Artifact |
|---|---|---:|---|---|
| scalar | 8/12/16/20 | 2,236,928 total | NumPy batch | [`shake_capacity_window_inference_v1.json`](../research/results/v1/shake_capacity_window_inference_v1.json) |
| bit-sliced | 20/24 | 35,651,584 total | 64 candidates per `uint64` | [`shake_bitsliced_window_solver_v1.json`](../research/results/v1/shake_bitsliced_window_solver_v1.json) |
| native standard | 24/28 | 570,425,344 total | C11, ten threads, streamed masks | [`shake_native_window_solver_v1.json`](../research/results/v1/shake_native_window_solver_v1.json) |
| native extended | 32 | 8,589,934,592 total | C11, resumable bounded memory | [`shake_native_window32_solver_v1.json`](../research/results/v1/shake_native_window32_solver_v1.json) |

- **Attack model:** exact consecutive-squeeze state consistency through all 24
  Keccak rounds.
- **Known variables:** complete first-squeeze state except the declared
  capacity window, and the complete next rate block.
- **Recovered object:** the exact assignment of the declared window.
- **Result:** every SHAKE128 and SHAKE256 case from 8 through 32 coordinates has
  exactly one consistent assignment, equal to instrumented ground truth. At 32
  coordinates, the assignments are `3,384,693,180` and `153,225,470`.
- **Complexity:** exactly `2^k` logical work; candidate-axis packing evaluates
  64 assignments per machine word. The 32-coordinate artifact covers two full
  four-billion-element spaces using 134,217,728 packed states total.
- **Controls:** 102,400-bit independent C/NumPy gate, native-vs-NumPy mask
  equality, two-lane filter followed by independent scalar full-rate
  confirmation, and an independent target with zero survivors in every case.

The generic QF_BV experiment at A124 reaches its configured 60-second limit;
that representation measurement motivated the Keccak-specific bit-sliced and
native solvers. It changes neither the exact relation nor the uniqueness of the
subsequent results.

## SHAKE Boolean constraint and prefix-observability frontier: A128--A129

[`FULLROUND_CAUSAL_SHAKE_SOLVER_FRONTIER_V1.md`](../research/reports/FULLROUND_CAUSAL_SHAKE_SOLVER_FRONTIER_V1.md)
connects an exact 24-round Boolean circuit Reader to a complete round-by-round
truth-space localization.

### A128: exact Boolean constraint reconstruction

- **Attack model:** bit-level Tseitin CNF for all Theta, Rho, Pi, Chi, and Iota
  operations in 24 Keccak-f[1600] rounds, constrained by the complete
  1,344-bit SHAKE128 next-rate block.
- **Known variables:** first-squeeze state outside the declared capacity window
  and the complete next rate.
- **Recovered object:** exact 4-, 8-, and 12-coordinate window assignments.
- **Result:** every returned assignment equals independently instrumented
  ground truth. A second query with one exact blocking clause is UNSAT at each
  solved width, proving uniqueness. The circuits contain 139,952--144,125
  variables and 525,709--541,204 clauses.
- **Complexity:** Z3 CHB uses 57,319, 48,477, and 586,636 internal decisions at
  widths 4/8/12. The 16-coordinate instance reaches its registered 120-second
  limit without a model. This is a mechanistic solver-scaling boundary, not a
  cryptanalytic break or ambiguity result.
- **Controls:** single solver thread, serialized decisions/conflicts/
  propagations, CNF hashes, blocking-clause uniqueness query, independent
  instrumented assignment, and Reader graph reopen.

### A129: exact prefix-observability frontier

- **Attack model:** one deterministic 16-bit capacity window per SHAKE variant,
  with all `2^16` assignments traced after every selected full Keccak round and
  conditioned on every factual prefix width 0--16.
- **Known variables:** first-squeeze state outside the declared window and the
  window positions. The factual prefix selects each diagnostic branch; target
  rate prefixes are used only for the survivor counts.
- **Recovered object:** exact count of rate coordinates fixed across every
  remaining suffix and exact target-prefix survivor counts.
- **Result:** without a fixed input prefix, rate coordinates constant over the
  candidate set fall `1344/1088 -> 1060/871 -> 8/10 -> 0/0` over rounds
  0/1/2/3 for SHAKE128/256. The zero-constant frontier persists through R24
  until about three suffix coordinates remain. Despite that collapse of
  single-coordinate branch certificates, 32 target-rate bits uniquely identify
  the factual 16-bit assignment for both variants.
- **Complexity:** all 65,536 assignments per variant, not a sample.
- **Controls:** exact scalar and independent bit-sliced equality over
  102,400 state bits, random-function coordinate-constancy law, complete
  assignment coverage, and Reader graph reopen.

Together these results explain why full-round output constraints remain highly
discriminating while ordinary coordinate-wise branch propagation does not
improve on native candidate-axis scaling. The next exponent-changing solver
must propagate richer joint constraints or introduce a genuine round split.

## SHAKE full-round affine-hull prefix distinguisher/Reader: A130

[`FULLROUND_CAUSAL_SHAKE_AFFINE_HULL_V1.md`](../research/reports/FULLROUND_CAUSAL_SHAKE_AFFINE_HULL_V1.md)
executes that joint-constraint extension as exact GF(2) branch membership.

- **Attack model:** one deterministic 16-bit capacity window per SHAKE128 and
  SHAKE256 instance, partitioned by candidate prefixes at widths 8--12 after
  all 24 Keccak-f[1600] rounds.
- **Known variables:** the complete first-squeeze state outside the window,
  window positions, and the first 128 observed next-rate coordinates.
- **Recovered object:** the exact 10-bit prefix of the unknown window
  assignment in each tested variant.
- **Result:** prefix width 8 retains 256/256 branches; width 9 retains 195/512;
  width 10 retains exactly the actual branch out of 1,024 in both variants and
  remains unique at widths 11 and 12. Actual-branch affine ranks are
  128/127/63/31/15 at widths 8/9/10/11/12; false-survivor counts match the
  predictions from the measured rank histograms.
- **Complexity:** the current construction evaluates all 65,536 assignments per
  variant and then performs exact branch elimination. It does not yet reduce
  the `2^16` exponent.
- **Controls:** exact conversion of 8,192 coordinate values, independent
  scalar/bit-sliced round composition over 102,400 state bits, complete branch
  point sets, actual-branch retention, rank-derived random expectations, and
  four-edge Reader graph reopen.

## SHAKE restricted algebraic-degree frontier: A131

[`FULLROUND_CAUSAL_SHAKE_ALGEBRAIC_DEGREE_V1.md`](../research/reports/FULLROUND_CAUSAL_SHAKE_ALGEBRAIC_DEGREE_V1.md)
maps the exact sparse-to-dense transition of the restricted coordinate
functions that underlie the preceding Readers.

- **Attack model:** one deterministic 16-bit capacity window per SHAKE128 and
  SHAKE256 instance, exhaustively traced at rounds 0/1/2/3/4/5/6/8/12/24.
- **Known variables:** the complete first-squeeze state outside the window and
  the window positions.
- **Recovered object:** exact ANF degree and coefficient population of each of
  the first 128 rate-coordinate functions over the window variables.
- **Result:** maximum degree progresses 0/1/3, reaches 7/6 at R3 and 14/12 at
  R4, then reaches the maximum 16 in both variants at R5. Mean coefficient
  counts at R5 are 32,768.09/32,773.56 against the random-function expectation
  32,768 and remain saturated through R24. R3 truth tables are already balanced
  while their ANFs are only 1.34%/1.40% dense.
- **Complexity:** every retained ANF uses all 65,536 assignments and an exact
  fast Möbius transform; none of the 128 coordinates is sampled.
- **Controls:** exact four-function degree gate, 8,192-coordinate conversion
  gate, independent scalar/bit-sliced round composition over 102,400 state
  bits, random-function coefficient and degree laws, and four-edge Reader graph
  reopen.

The result localizes the tested full-round representation boundary: direct ANF
expansion is dense by R5, so the next candidate representation must preserve
the sparse R3 component without substituting the complete R4--R24 suffix into
one full-round polynomial. It does not assert a global degree theorem for all
SHAKE inputs or an exponent reduction.

## SHAKE Boolean-influence frontier: A132

[`FULLROUND_CAUSAL_SHAKE_BOOLEAN_INFLUENCE_V1.md`](../research/reports/FULLROUND_CAUSAL_SHAKE_BOOLEAN_INFLUENCE_V1.md)
separates low ANF density from actual variable-factorable support.

- **Attack model:** three independent deterministic 16-bit capacity windows per
  SHAKE variant, exhaustively evaluated at R0/1/2/3/4/5/24. Every one of the 16
  single-coordinate interventions is paired across all `2^15` complements and
  compared against all 1,600 state coordinates.
- **Known variables:** the complete first-squeeze state outside each window,
  window positions, and instrumented round states.
- **Recovered object:** exact round-indexed 16x1,600 Boolean influence matrices
  and their support/coupling frontiers.
- **Result:** R2 has 8,308--8,927 nonzero cells of 25,600. R3 jumps to
  25,597--25,600 nonzero cells and 1,597--1,600 fully coupled state coordinates.
  At measured R4, R5, and R24, all 25,600 cells are nonzero in all six trials.
  Every R4 influence lies within 0.013062 of one half and every R24 influence within
  0.012054.
- **Complexity:** 42 complete matrices and 35,232,153,600 logical paired-cell
  comparisons, evaluated in the bit-sliced representation.
- **Controls:** exact Boolean-derivative function gate, 8,192-coordinate
  conversion gate, independent scalar/bit-sliced equality over 102,400 state
  bits, complete paired assignments, serialized matrix/support hashes, and
  six-edge Reader graph reopen.

R2 is the final measured layer with incomplete coordinate-level influence
support, while A133 shows that its monomial primal graph is already complete.
Sparse R3 ANFs remain useful as low-degree equations, but not as independent
variable components. The result is scoped to six restricted, known-complement
windows and instrumented states; it is not an unrestricted SHAKE input theorem
or output-only recovery.

## SHAKE shared-ANF compression: A133

[`FULLROUND_CAUSAL_SHAKE_ANF_COMPRESSION_V1.md`](../research/reports/FULLROUND_CAUSAL_SHAKE_ANF_COMPRESSION_V1.md)
applies an exact representation transform before generic compression.

- **Attack model:** complete `2^16 x 1,600` restricted state-function truth
  spaces for SHAKE128 and SHAKE256 at R0/1/2/3/4/24.
- **Known variables:** the state outside each declared 16-coordinate capacity
  window and the exact round equations.
- **Recovered object:** a shared monomial dictionary and packed
  `basis x 1,600` ANF coefficient matrix that losslessly reconstruct every
  retained Boolean function.
- **Result:** at R3, the best raw codec retains 12.96/13.07 MB of each 13.11 MB
  record, while shared-ANF plus LZMA uses 634/659 KB, a 20.44x/19.84x advantage
  over the best raw path. The R2 advantage is 44.65x/44.29x; it falls to about
  1.02x at R4 and disappears at R24. No ordered two-codec cascade beats the
  best single LZMA path.
- **Complexity and controls:** twelve complete truth spaces, exact Möbius and
  inverse-Möbius gates, 102,400 independent Keccak state-bit checks, and a
  disk Reader that reconstructs all 419,430,400 persisted truth values in the
  four-record `F8ANFPK1` artifact.

The R2 monomial graph contains all 120 variable-pair edges, so the compression
gain is shared low-degree feature reuse rather than independent components.

## SHAKE direct symbolic R2 compiler: A134

[`SHAKE_SYMBOLIC_R2_ANF_FRONTIER_V1.md`](../research/reports/SHAKE_SYMBOLIC_R2_ANF_FRONTIER_V1.md)
removes the exhaustive truth table from the compact R2 interface itself.

- **Attack model:** exact Boolean-ring compilation of the first two Keccak
  rounds from variable capacity coordinates, without sampling or `2^k`
  assignment materialization.
- **Known variables:** the complete starting state outside the declared
  capacity coordinates and the Keccak round constants.
- **Recovered object:** all 1,600 exact R2 coordinate polynomials.
- **Result:** the complete 256-coordinate SHAKE128 capacity compiles to
  6,918,733 coefficients over 2,467,023 shared monomials. The complete
  512-coordinate SHAKE256 capacity compiles to 64,724,568 coordinate-local
  coefficients of degree at most four. Its 4.142 GB symbolic form is smaller
  than the formal truth table by a factor `2^487.696`.
- **Complexity and controls:** width-16 basis and matrix hashes match all six
  exhaustive A133 R0/R1/R2 artifacts; 94,720 independently evaluated state
  bits match across widths 16--512. The width-512 coordinate-local form avoids
  the unnecessary global duplicate-elimination set while retaining every
  exact polynomial.

## SHAKE native-XOR and partition Readers: A135--A136

[`FULLROUND_CAUSAL_SHAKE_SYMBOLIC_R2_SMT_V1.md`](../research/reports/FULLROUND_CAUSAL_SHAKE_SYMBOLIC_R2_SMT_V1.md)
joins the exact R2 formulas to explicit Boolean equations for R3--R24.

- **A135 attack model:** complete 1,344-bit next-rate constraints with the
  first-squeeze state known outside a 4/8/12/16-coordinate SHAKE128 capacity
  window. R2 formulas remain native n-ary XOR equations.
- **A135 recovered object and result:** exact 4/8/12-coordinate assignments,
  each accompanied by an UNSAT blocked-model query. First-query decisions fall
  from canonical-CNF counts 57,319/48,477/586,636 to
  2,025/8,252/35,088. The 16-coordinate monolithic R2 system reaches the
  registered 120-second boundary.
- **A135 controls:** exact A128 result-hash gate, full 24-round Boolean
  equations, independent assignment comparison, blocked-model queries, and
  three-edge Reader reopen.
- **A136 attack model:** the same exact 16-coordinate system partitioned into
  all 16 disjoint low-four-coordinate prefixes, generated in ascending order
  without consulting the instrumented assignment.
- **A136 recovered object and result:** branch 13 returns assignment **35,837**
  in 5,967 decisions. Independent 24-round evaluation reproduces all 1,344
  next-rate bits. The other fifteen branches reach their per-branch limit, so
  this artifact establishes autonomous model reconstruction, while a global
  uniqueness certificate remains a distinct object.
- **A136 controls:** complete branch coverage, five single-thread workers,
  posthoc ground-truth comparison only after the schedule completes, and
  independent complete-rate injection of every returned model.

## SHAKE split selection and monolithic R1 model: A137--A138

[`FULLROUND_CAUSAL_SHAKE_SYMBOLIC_SPLIT_FRONTIER_V1.md`](../research/reports/FULLROUND_CAUSAL_SHAKE_SYMBOLIC_SPLIT_FRONTIER_V1.md)
compares exact R1/R2/R3 handover points under the same full-round query.

- **A137 attack model:** identical SHAKE128 state, observation, solver, and
  known-complement relation with only the symbolic-prefix depth changed.
- **A137 recovered object and result:** the minimum-decision exact interface is
  R1. At width 12, R1/R2/R3 require 2,986/35,088/4,441 decisions; R1 is
  196.46x below canonical CNF. On the verified width-16 model branch, R1 uses
  1,909 decisions versus 5,967 for R2, while R3 reaches its configured limit.
  R2 is the storage-compression optimum and R1 the measured Reader optimum.
- **A137 controls:** A135/A136 are reused only after exact SHA-256 gates; every
  returned R1/R3 model is independently checked against all 1,344 rate bits.
- **A138 attack model:** monolithic R1 interface, no fixed prefix, widths
  16/20/24, and the complete 1,344-bit next-rate observation.
- **A138 recovered object and result:** width 16 returns assignment **35,837**
  in 4,701 decisions, 7.17% of the complete assignment count, and matches all
  1,344 output bits under independent evaluation. The blocked query and first
  queries at widths 20/24 reach the 120-second boundary.
- **A138 controls:** exact A137 hash gate, independent full-round model
  injection, posthoc instrumented-state equality, and three-edge Reader reopen.

The R1 interfaces at widths 20 and 24 remain degree-two and small; the recorded
boundary therefore selects subspace decomposition over the same equations,
not a later symbolic expansion.

## SHAKE128 R1 partition topology: A139--A141

[`FULLROUND_CAUSAL_SHAKE_SYMBOLIC_R1_PARTITION_TOPOLOGY_V1.md`](../research/reports/FULLROUND_CAUSAL_SHAKE_SYMBOLIC_R1_PARTITION_TOPOLOGY_V1.md)
compares three complete partitions of the same hash-gated A138 width-20 SMT.

- **Attack model:** the first-squeeze state is known outside 20 declared
  SHAKE128 coordinates; all 1,344 next-rate bits constrain an exact symbolic
  R1 prefix followed by 23 explicit rounds.
- **Partition plans:** A139 fixes `[0,1,2,3]`, A140 fixes
  `[16,17,18,19]`, and A141 fixes `[4,9,17,18]`. Each plan exhausts all 16
  values of its four fixed coordinates and leaves 16 free coordinates in every
  branch.
- **Result:** each plan records exactly 16 `unknown` statuses under its
  60-second per-branch limit and five one-thread workers. No plan returns a
  model or branch certificate. These are complete disjoint plan executions and
  precise representation/resource boundaries, not ambiguity or immunity
  results.
- **A141 selection:** the exact R1 quadratic graph has 28 edges. Exhaustive
  evaluation of all 4,845 four-coordinate subsets finds maximum coverage 14,
  with 14 tied sets; the assignment- and target-independent lexicographic rule
  selects `[4,9,17,18]`.
- **Controls:** exact A138 JSON and unpartitioned-SMT hash gates, plan
  construction before results, no assignment or output input to the selector,
  complete branch coverage, and three independently reopened Reader graphs.

The retained breadcrumb is a deeper or suffix-aware decomposition over the
same explicit relation. Equal free dimension, low/high position, and static R1
edge coverage are each insufficient predictors under the stored schedule.

## SHAKE256 monolithic symbolic-R1 transfer: A142

[`FULLROUND_CAUSAL_SHAKE256_SYMBOLIC_R1_TRANSFER_V1.md`](../research/reports/FULLROUND_CAUSAL_SHAKE256_SYMBOLIC_R1_TRANSFER_V1.md)
tests whether A137's SHAKE128-selected R1 handover transfers directly to
SHAKE256.

- **Attack model:** exact SHAKE256 symbolic R1 prefix plus 23 explicit rounds,
  complete 1,088-bit next-rate observation, and known first-state complement.
- **Transferred object:** only the structural choice
  `symbolic_prefix_rounds=1`; no SHAKE128 status, assignment, or output is
  imported.
- **Result:** monolithic widths 16/20/24 each return `unknown` with one solver
  thread and a 120-second first-query limit. Their exact degree-two R1
  interfaces contain 23/35/76 shared monomials.
- **Controls:** exact A137 hash gate, independent SHAKE256 seeds, all 17 rate
  lanes constrained, functional SHAKE/Keccak gates, and a reopened three-edge
  Reader graph.

A142 is a cross-variant representation/resource boundary. It selects a
SHAKE256-specific split frontier or complete disjoint partition as the next
test; it makes no general statement about unresolved SHAKE256 windows.

## SHAKE128 structural depth and solver strategy: A143--A146

The [structural-depth report](../research/reports/FULLROUND_CAUSAL_SHAKE_SYMBOLIC_R1_STRUCTURAL_DEPTH_V1.md)
and [strategy report](../research/reports/FULLROUND_CAUSAL_SHAKE_SYMBOLIC_R1_Z3_STRATEGY_V1.md)
preserve the exact A138 width-20 relation while separating graph structure,
conditioning depth, and solver processing.

- A143 enumerates all 38,760 six-coordinate sets, selects the unique 20/28-edge
  maximum `[4,9,12,15,17,18]`, and executes its complete 64-subspace plan. All
  branches return `unknown` at the retained 30-second boundary.
- A144 compares six predeclared, syntax-gated Z3 routes. Native-XOR `QF_UF` is
  the only independently verified width-16 `sat` route and returns assignment
  35,837 in 4,701 decisions; its unchanged width-20 transfer remains `unknown`.
- A145 fixes graph-selected coordinates at posthoc assignment projections to
  localize the first measured successful depth: `k=4` and `k=6` return
  `unknown`, while `k=8` returns assignment 227,581 in 1,442 decisions and
  independently matches 1,344/1,344 bits. This is mechanism localization, not
  autonomous model search.
- A146 transfers the A144 strategy to all 64 A143 subspaces at a 120-second
  cap. All 64 return `unknown`; no candidate is emitted.

## SHAKE128 width-20 assignment-free Reader: A147

[`FULLROUND_CAUSAL_SHAKE_SYMBOLIC_R1_ASSIGNMENT_FREE_K8_V1.md`](../research/reports/FULLROUND_CAUSAL_SHAKE_SYMBOLIC_R1_ASSIGNMENT_FREE_K8_V1.md)
turns the `k=8` breadcrumb into a frozen runtime search. Coordinate selection
is graph-only, all 256 projection values are declared in ascending order, and
the controller executes complete five-process waves. Projection 38 returns
assignment 227,581 in 1,442 decisions after eight complete waves; a separate
implementation matches all 1,344 next-rate bits. The assignment and target
projection are not selection or runtime inputs. The remaining branches are not
certified empty, so the artifact claims model finding rather than global
uniqueness.

## SHAKE128 width-24 minimum-cover Reader: A148--A151

[`FULLROUND_CAUSAL_SHAKE_SYMBOLIC_R1_WIDTH24_VERTEX_COVER_V1.md`](../research/reports/FULLROUND_CAUSAL_SHAKE_SYMBOLIC_R1_WIDTH24_VERTEX_COVER_V1.md)
extends the exact symbolic-R1 mechanism to 24 coordinates.

- A148 proves that the R1 graph is exactly nine disjoint edges and therefore
  has minimum vertex-cover size nine. Its explicitly posthoc-conditioned
  frontier first returns `sat` at depth nine: assignment 4,845,375 in 4,734
  decisions, independently matching all 1,344 next-rate bits.
- A149 records the resource-sensitive 60-second parallel boundary. A150's
  completed 60/120-second prefix retry remains historical because its 20-value
  cutoff was recognized as same-instance target-rank-informed; it is not the
  final published protocol.
- A151 selects the exact lexicographic cover `[0,1,2,3,4,5,6,7,8]`, freezes a
  complete 512-subspace schedule, and assigns every planned subspace the same
  120-second cap. Four complete waves execute 20 branches; projection 319
  returns assignment 4,845,375 in 4,734 decisions and 2,380 conflicts. The
  independent implementation confirms 1,344/1,344 rate bits before early stop.

A151 accepts neither the assignment nor target projection at runtime. The
formula-order hypothesis and cap were developed from A148/A149 on this same
instance, so the artifact is explicitly posthoc-informed and non-blind. The
complete plan covers all `2^24` assignments, while planned coverage is kept
distinct from the 20 branches actually executed before the verified stop.

## Reduced-round ChaCha transfer: A185--A189

The five retained reports form one hash-linked progression from the fresh
full-round 40-bit A184 relation into direction selection, shared-key stacking,
portable solver transfer, and a deeper-round prospective recovery.

- [A185](../research/reports/CAUSAL_CHACHA20_SMT_DIRECTIONAL_ROUND4_TRANSFER_V1.md)
  freezes a fresh reduced ChaCha4 40-bit target and five semantically matched
  QF_BV views. Split1 and split2 independently recover `0x230f1aee2d` and each
  passes a complete 512-bit confirmation; forward, inverse, and split3 reach the
  equal 30-second resource boundary.
- [A186](../research/reports/CAUSAL_CHACHA20_SMT_DIRECTIONAL_ROUND5_BOUNDARY_V1.md)
  transfers the same direction family to a fresh ChaCha5 40-bit target. All six
  predeclared views return `unknown` under the same budget, retaining the exact
  round-4→round-5 representation/resource boundary with no early stop.
- [A187](../research/reports/CAUSAL_CHACHA20_SMT_SHARED_KEY_MULTIBLOCK_TRANSFER_V1.md)
  freezes ten fixed-resource formulas over one fresh 40-bit key shared across
  eight counter-related ChaCha5 blocks. Complete b8 reduces decisions from
  35,285 to 1,686 and conflicts from 29,385 to 389 relative to b1. All three
  fixed-total-512-bit sparse stacked views improve both counters.
- [A188](../research/reports/CAUSAL_CHACHA20_BITWUZLA_ROUND5_RECOVERY_V1.md)
  executes a complete predeclared Bitwuzla/Z3/Boolector portfolio on another
  fresh ChaCha5 40-bit challenge. Bitwuzla bitblast b8 returns
  `0x5345585503`; independent recomputation matches all 4,096 target bits and
  rejects the control, while the tested b4 modes retain the exact instance
  boundary.
- [A189](../research/reports/CAUSAL_CHACHA20_BITWUZLA_ROUND6_WIDTH20_RECOVERY_V1.md)
  prospectively transfers the b8 Reader to a fresh ChaCha6 low-20-bit challenge
  with 236 known key bits. Predicted bitblast b8 and preprop b8 independently
  recover `0x6fa70` and confirm all 4,096 bits; the predeclared b1 view returns
  the identical assignment and confirms 512 bits.

Each production challenge was generated from OS randomness, used to construct
the public targets, and discarded before execution. The committed configs,
portable formula hashes, complete status vectors, independent confirmations,
typed Causal graphs, and deterministic figures are authenticated by
`FULLROUND_TRANSFER_SHA256SUMS`. Focused tests reconstruct this evidence without
rerunning the production solvers.

## Direct-output and PQC program

A001--A106 are preserved rather than compressed into a selective success list.
The [attempt log](../research/ATTEMPT_LOG.md) records retained results,
representation boundaries, corrections, and controls chronologically. The
[direct causal matrix](../research/reports/NIGHTRUN_DIRECT_CAUSAL_MATRIX_V1.md)
summarizes AES, ChaCha, PRESENT, Threefish, SIMON, ML-KEM, compressor cascade,
and Reader-inference branches. Raw JSON and `.causal` files remain under
`research/results/v1/`.

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

The measured dependency-factorable split must therefore occur no later than
R2->R3. Sparse R3 ANFs remain useful as low-degree equations, but not as
independent variable components. The result is scoped to six restricted,
known-complement windows and instrumented states; it is not an unrestricted
SHAKE input theorem, output-only recovery, or exponent reduction.

## Direct-output and PQC program

A001--A106 are preserved rather than compressed into a selective success list.
The [attempt log](../research/ATTEMPT_LOG.md) records retained results,
representation boundaries, corrections, and controls chronologically. The
[direct causal matrix](../research/reports/NIGHTRUN_DIRECT_CAUSAL_MATRIX_V1.md)
summarizes AES, ChaCha, PRESENT, Threefish, SIMON, ML-KEM, compressor cascade,
and Reader-inference branches. Raw JSON and `.causal` files remain under
`research/results/v1/`.

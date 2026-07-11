# Methods

## Experimental contract

Every promoted result has four machine-checkable layers:

1. a primitive gate against an official or independently embedded vector;
2. a declared attack model and input/intervention schedule;
3. factual evidence plus registered structure-preserving controls;
4. a result JSON and, where applicable, a `.causal` graph reopened by the
   `CryptoCausalReader`.

Discovery and confirmation inputs are separated whenever a graph or coordinate
set is selected from data. Seeds, sample counts, known variables, control banks,
and source hashes are written into the artifact.

## F8 measurement families

F8 compares matched executions at adjacent round boundaries. For key `K`, input
`P`, and selected round count `R`, define

```text
X = state_R(P, K)
Y = state_(R+1)(P, K)
D = X xor Y
```

The bitwise F8 family measures mutual information between registered
coordinates of `X` and `D`, scoring factual cells against permutation or shared
Birkhoff-von Neumann (BvN) route controls. The portable conference reproduction
also contains a byte-quantized family: each byte is mapped to eight bins,
Pearson independence is tested over every position pair, and the seed-level
statistic is the fraction of pairs with `p < 0.05`.

These are related estimands, not interchangeable numeric scales. Every report
states which one it uses.

### Full-round convention

For a cipher specified with `R` rounds, the F8 endpoint compares the fully
specified `R`-round state with one additional application of the registered
round transform. This creates the adjacent boundary required by F8. It does not
rename the standardized cipher as an `R+1`-round encryption mode.

### Known-key model

The original F8 anchors expose both instrumented internal boundaries and use a
known key. Their object is a known-key cross-round distinguisher or relation.
Later Reader results name any additional known values explicitly.

## CASI and LiveCASI

CASI analyzes structural and compression characteristics of one output stream.
LiveCASI 0.9.1 evaluates 26 registered strategies. F8 instead consumes matched
adjacent-round pairs. The two methods therefore have distinct schemas,
baselines, and interpretations even when they are run on the same primitive.

The portable 41-cipher registry is in `src/arx_carry_leak/nano_ciphers.py`; the
vendored analysis core is isolated under `src/arx_carry_leak/live_casi_v091/`.

## CryptoCausal graph format

The builder serializes typed nodes, directed triplets, edge attributes,
parameters, provenance, evidence kind, and reconstruction recipes. The Reader:

1. parses the declared CAUSAL format/version;
2. recomputes the canonical graph digest;
3. checks every inferred edge against its provenance;
4. exposes reverse-ranking and registered executable recipes;
5. rejects malformed or digest-mismatched files.

The repository-wide validator opens every `.causal` file through this Reader.
The graph is the auditable reasoning object used by the experiment; it does not
depend on hidden model state.

## BvN route controls

BvN controls are global bijective row routes. They preserve each observed row
exactly while altering only the factual pairing. Shared route banks use the
same routes across compared labels or variants, preventing class-specific
repair noise from becoming a classifier. A factual relation is promoted only
under the exact pass rule recorded in its result JSON, typically factual score
above every route on each fresh confirmation key or zero whole-object matches
across all route banks.

## Exact Reader relations

Reader experiments use algebraic or Boolean consistency rather than treating a
small p-value as the final object:

- modular feed-forward inversion for SHA-2 and ChaCha20;
- Feistel joint inversion for FEAL-32X;
- shared-branch cancellation for SHACAL-2;
- endpoint projection and finite linear order for SPARKLE;
- output-lane identities for BLAKE3;
- rate projection, Boolean Jacobians, and exact state-window consistency for
  SHAKE.

Whole-word, whole-state, and complete-rate equality are checked independently
of marginal bit accuracy. Wrong formula, lane, key/subkey, source, route, endian,
and independent-target controls are retained alongside the factual result.

## SHAKE solver progression

For a declared capacity window of `k` coordinates, the first squeeze state is
known outside that window. Each candidate assignment is inserted, all 24
Keccak-f[1600] rounds are executed, the first two lanes of the next rate block
filter candidates, and an independent scalar implementation confirms the
complete rate.

Three execution representations implement the same relation:

- scalar/NumPy batches;
- candidate-axis bit slicing, 64 assignments per `uint64`;
- a fused C11/POSIX kernel with ten threads and bounded streaming masks.

Two diagnostic representations then localize the remaining scaling boundary:

- an exact 24-round Tseitin CNF with complete next-rate constraints and a
  blocking-clause uniqueness query;
- a complete `2^16` per-round truth space that counts output coordinates fixed
  under every factual input-prefix branch.

The CNF is an exact Reader, while the truth-space frontier is a mechanistic
measurement. At the tested full-round boundary, output prefixes discriminate
complete assignments but individual fixed-coordinate certificates disappear by
round 3. A registered solver timeout is recorded as a representation boundary,
not promoted to a cryptanalytic result.

The next representation partitions one complete 16-bit window truth space per
SHAKE variant by candidate prefix and builds exact GF(2) affine hulls of the
first 128 next-rate coordinates. Target membership is an exact joint-relation
Reader under the same known-complement model. It isolates the actual 10-bit
prefix in both tested windows even though no individual rate coordinate is
fixed. The implementation still materializes all `2^16` assignments; it is not
an exponent reduction.

Finally, an exact fast Möbius transform converts the same complete truth spaces
into algebraic normal forms for the first 128 rate coordinates at selected
round boundaries. Degree, monomial count, density, truth-table balance, and
random-function expectations are computed without coordinate sampling. This
localizes a sparse balanced R3 regime and the dense maximum-degree R5--R24
regime for the two tested restricted windows; it is not a global degree claim
over the unrestricted SHAKE input space.

An exact Boolean-derivative pass then pairs every assignment with its
single-window-coordinate intervention and counts changes across all 1,600
state coordinates. Three complete windows per variant provide six independent
`2^16` truth spaces. The resulting 16x1,600 matrices distinguish algebraic
sparsity from dependency factorization: R3 remains low-density in ANF form but
is already nearly all-to-all in support, while R4 is the first measured fully
coupled and influence-balanced boundary.

A133 transforms each complete restricted truth space into a shared ANF
dictionary plus a packed 1,600-coordinate coefficient matrix. Generic codecs
are applied both before and after that lossless transform, including every
ordered two-codec cascade at R2/R3. The binary pack is reopened and inverse
transformed, so compression ratios are accepted only with complete truth-value
equality. Its complete R2 monomial graph also corrects the interpretation of
A132: incomplete coordinate influence does not imply independent components.

A134 constructs the same R2 polynomials directly in the Boolean ring. XOR is
symmetric difference, multiplication is union of variable masks with parity
cancellation, and Chi is compiled exactly as `a xor c xor b*c`. Width-16 basis
and matrix hashes cross-gate the exhaustive A133 transform before the compiler
is extended to complete 256- and 512-coordinate capacities.

A135 preserves those prefix formulas as native n-ary XOR assertions and joins
them to explicit local Boolean equations for the remaining Keccak rounds. A
first model is independently injected into the 24-round evaluator; a second
query blocks the complete assignment and supplies the uniqueness certificate
when UNSAT. A136 decomposes the width-16 system into all disjoint low-four-bit
prefixes. Branch construction and order are independent of the instrumented
assignment, which is consulted only after all branch results are collected.

A137 varies only the symbolic handover depth and selects R1 by measured solver
decisions. A138 carries that interface into an unpartitioned width-16 query:
one symbolic round followed by 23 rounds of explicit local equations and all
1,344 next-rate constraints. Exact SHA-256 gates prevent an earlier result from
being silently regenerated under changed inputs.

Explicit candidate enumeration in A123--A127 remains exactly `2^k` logical
work. A133's truth-space transforms also consume all `2^16` points. A134--A138
do not enumerate an assignment table; their recorded work is formula size,
solver decisions, branch coverage, and configured time boundaries, without
claiming a formal asymptotic exponent. Native enumeration checkpoints are
written atomically and resume at the next unprocessed pack.

## Evidence stages

- **anchor:** committed original result suite authenticated by source commit and
  SHA-256 manifest;
- **discovery:** coordinates or representation selected;
- **confirmation:** fresh keys, seeds, bits, domains, or messages under a frozen
  recipe;
- **derived exact:** exhaustive local truth table, complete binary basis, or
  algebraic identity replaces sampling for the stated scope;
- **control result:** a registered branch that localizes the mechanism or closes
  a representation.

The append-only `research/ATTEMPT_LOG.md` records all stages, including solver
boundaries and corrected analyses.

## Reproducibility metadata

Result JSON records the Python/platform environment, seeds, parameters, source
hashes, and Reader graph digest where applicable. Manifests use SHA-256 over the
exact committed bytes. Reproduction scripts resolve the repository root from
their own path and contain no host-specific absolute filesystem path.

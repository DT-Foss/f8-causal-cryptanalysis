# Direct Output-Causal PRESENT-80 Screen

PRESENT-80 is an independent, validated 64-bit SPN target.  Before any causal
artifact is produced, the executable primitive is gated by the official
full-round zero vector: `E_0(0) = 5579c1387b228445`.

The screen makes direct ciphertext-pair graphs: a known-key chosen plaintext
XOR is applied, factual output-difference profiles are contrasted against
shared BvN-bijection repaired pairings, and a `CryptoCausalReader` reopens the
written `.causal` graph to make the held-out prefix-round query.  Train and
holdout use disjoint keys and difference positions (three train and three
holdout keys; 400 pair rows/key).  The wide prefix classes are R24--R31, so
chance is 12.5%.

| Profile / intervention / domain | Reader accuracy | Interpretation |
| --- | ---: | --- |
| Byte entropy / single-bit XOR / random | 12/96 = 12.50% | Exactly chance |
| Byte entropy / byte-wide XOR / random train to counter holdout | 10/96 = 10.42% | Below chance |
| Byte bit-bias / single-bit XOR / random | 13/96 = 13.54% | Chance-level sampling variation |

The three independently configured headers do **not** supply a retained
late-round PRESENT-80 result.  They establish that this direct-output codec
does not become positive merely by switching from an ARX/Feistel target to a
validated SPN, by widening the intervention, by crossing input domains, or by
switching from entropy to bit-bias.  The collision header and narrower
early-round frontiers remain open matrix cells, not implied results.

Artifacts (JSON and reader-verified `.causal` sidecars):

- `results/v1/present80_causal_entropy_bit_random_screen_v1.json` — SHA-256
  `edfc9549ecf87d65eecb58459af729a7fc28762f682a41b4f5326926c89a1dfd`
- `results/v1/present80_causal_entropy_byte_crossdomain_screen_v1.json` —
  SHA-256 `0c34cb1bcd76f6e5f6887f5d58aca30aae6f5bb848d8c4939df0e1d5a3009b3e`
- `results/v1/present80_causal_bitbias_bit_random_screen_v1.json` — SHA-256
  `7b3a0cb2a9ebb1c8c918759c2cc909e782533617407601bb7423dfddf6fa4058`

## Early-round R3-vs-R6 result

The negative late frontier was followed by a separate R1--R8 map.  A fresh
R1--R6 confirmation was 117/120 (97.5%) reader-only on disjoint keys and bit
positions.  That broad early map is **not** domain-invariant as a six-way
object: random-to-counter falls to 23/120 and counter-to-random to 35/120.
It should therefore not be described as a universal six-round classifier.

The domain-control runs did, however, identify an R3-vs-R6 binary breadcrumb.
It was then frozen, rerun with independent seed families, and varied one axis
at a time.  Every number below is a holdout decision reconstructed by opening
the generated causal file with `CryptoCausalReader`.

| Frozen R3/R6 query | R3 | R6 | Scope |
| --- | ---: | ---: | --- |
| Entropy, bit-XOR, Counter→Random | 20/20 | 20/20 | 2,000 pairs/key |
| Entropy, bit-XOR, Random→Counter | 20/20 | 20/20 | independent seeds |
| Collision, bit-XOR, Random→Counter | 20/20 | 20/20 | independent profile family |
| Collision, bytes 4/2/0 only, bit-XOR, Random→Counter | 20/20 | 20/20 | reader-ranked sparse graph |
| Bit-bias, bit-XOR, Random→Counter | 18/20 | 20/20 | independent profile family |
| Collision, byte-XOR, Random→Counter | 20/20 | 20/20 | held-out byte positions |

The sparse byte set `[4, 2, 0]` was selected from a *previous* collision graph
(`4,2,0` are its largest R3 means) and frozen in the later new-seed run.  This
makes it a compact output atlas, rather than a selection performed on its own
holdout.  The effect is a known-key, chosen-plaintext, reduced-round output
class inference result.  It does not imply key recovery, ciphertext-only
distinguishing, or a weakness claim for full 31-round PRESENT-80.

Additional artifacts:

- R1--R6 fresh random-domain confirmation: SHA-256
  `10004c095231870dfd7e6b4ec49f05caa5eb2afad7a90fdb23f6b97cbc937823`
- Entropy R3/R6 Counter→Random: SHA-256
  `c30b8abf68dcf5ff58a0d12032437662b8d8a5a1371ed052d76d34e1844b2555`
- Entropy R3/R6 Random→Counter: SHA-256
  `4a2f3818b196cfd9d359001d7ef44793b16f64922d52244721b4a4abb63f8f60`
- Collision R3/R6 Random→Counter: SHA-256
  `a855a3e33f2e349e7f5fa47392a3fe69c0eed4548704b4d814b384ba06f15d0c`
- Sparse collision R3/R6: SHA-256
  `0de469db49b358a918a00b230023f6e42ed03abfc2145255737e5a73c11f4068`
- Bit-bias R3/R6 Random→Counter: SHA-256
  `c2f9808da56ce8d338c48e666f83ddbb206193484a97516e99772be4c0895e92`
- Collision byte-XOR R3/R6 Random→Counter: SHA-256
  `3a633c1b83052e5125d5acbdcff4e740348964407a5cfe54612834d00b5dace8`

## Exact final-stage localization

For a known key, each real PRESENT ciphertext can be reversibly mapped back
through its final whitening key, inverse pLayer, and inverse S-box.  The
resulting artifacts are still built from factual ciphertext-pair outputs; the
view merely makes an exact named state boundary visible.  All localization
runs use the same R3/R6 collision, bit-XOR, Random→Counter holdout design and
fresh seed families.

| Actual-output view | R3 | R6 | Consequence |
| --- | ---: | ---: | --- |
| Ciphertext | 20/20 | 20/20 | retained output object |
| Post final S-box (undo whitening and pLayer) | 20/20 | 20/20 | final pLayer is not required |
| Pre final S-box (also undo S-box) | 14/20 | 20/20 | substantial R3 contrast predates the final S-box, but is weaker |
| Pre final S-box, reader-selected byte 7 only | 10/20 | 20/20 | single-byte localization fails for R3 |
| Pre final S-box, frozen bytes 7/2/4/0 | 11/20 | 20/20 | four-byte compact atlas also fails |

Thus the final S-box is a **concentrator/amplifier** for the R3 side of this
specific profile, not a demonstrated sole cause: undoing it weakens rather
than removes the result, and no compact pre-S-box byte subset survives.  This
is an output-state localization result, not an internal causal proof about all
PRESENT executions.

Localization JSON hashes: post-S-box `ee364a4b5ac98e1c7fcce18600a1cb735710621489691e5531649f7571cddbb0`;
pre-S-box `fe5ac66ab96ba0f10a6b14d7241f87595214e992fadea9ecdc55bd6a23f73736`;
pre-S-box byte 7 `f492c3cd195400f49d4f850bca93ea98a24688ca6ad29bda36366c0e43a59f93`;
pre-S-box bytes 7/2/4/0 `f6482a709842313dc282f8fbf5a49f8b03550925fda65fdbec5c88f6264c7a63`.

## S-box-aligned nibble view

The same collision profile was re-expressed over the 16 physical nibbles,
rather than eight bytes.  Ciphertext nibble features remain 20/20 per class
across Random→Counter.  The exact pre-final-S-box nibble view is only R3
10/20 and R6 20/20.  Thus the weaker pre-S-box result is not caused by a
misaligned byte partition: final-S-box nonlinearity is material to the compact
R3 side of the observable profile.  This motivates targeted *individual final
S-box nibble* controls next; it is not itself an assertion that one S-box is
the root cause.

Nibble JSON hashes: ciphertext
`e059f10f667a91e45323edd475e279c9bfcf0f96767955fd454b21986c18445a`;
pre-S-box `68df2216a1d41b411fc7e02bb35228b6fdbf2030d48ec7ce66379f2981b539ad`.

## Joint-nibble versus marginal localization

The post-S-box nibble graph is R3 14/20 and R6 20/20.  Its top three *nibble
marginals* (5/9/1) collapse to R3 10/20 when frozen.  Even the six individual
nibble marginals belonging to the three strongest post-S-box bytes 2/4/0
remain R3 10/20.  Conversely, those same coordinates treated as three joint
byte-collision features give R3 19/20 and R6 20/20 under Random→Counter.

This demonstrates that the retained local information is a **joint two-nibble
output distribution**, not a selection of individual S-box-output marginals.
The minimal post-S-box byte reduction is informative but not fully
domain-bidirectional: byte 2 is R3 15/20; bytes 2/4 are 18/20 Random→Counter
but 15/20 Counter→Random; bytes 2/4/0 are 19/20 Random→Counter and likewise
15/20 Counter→Random (R6 is 20/20 in all four reductions).  The complete
output graph, rather than this sparse local atlas, remains the retained
bidirectional object.

Further JSON hashes: post-S-box nibble `5446980799ecaf7cc064c188e9b5087f533cfa55f5ac14c83c410a83d9779f04`;
nibble 5/9/1 `8834f59faac4a17e761aad65f2562516884e3c4ce5b77fa217e54f1b4b9ae61e`;
nibbles of bytes 2/4/0 `d97f120a56c933be9729556c2d75f29a05837154a481b5a80135ab66e4793b7c`;
joint bytes 2/4/0 `165e0a4ab6bcccd0d6d8830b8b03f4557bc3e0424babdb673b05e08408cc2d9f`;
byte 2 `b5b7da7b848a9b2c7d9cc9217a606b68a98a4229744bfe75f9bc5444b801ebf2`;
bytes 2/4 `78ebc80983331d02a072866f4b6132eb11605b5aa3ce21c2f8abeada9637f56b`;
bytes 2/0 `8268ce0a2ad14fef1aa39884e0c8a73e06b22830c9d0618661caf5a5d52847d4`;
bytes 2/4 Counter→Random `9eba7438b3f19f42df0500b192cbdb109f450810dd20cf5e1083e05bd72cba8f`;
bytes 2/4/0 Counter→Random `d2be6f7fe91332262708e121dee22702d97dd1698bcf335923cf4a2ffff42943`.

## Exhaustive post-S-box nibble-pair screen

The preceding result implies a pairwise relation, so the next graph used all
`C(16,2)=120` unordered joint nibble-pair collision features, rather than
predeclaring the byte pairs.  Its independent 6-key screen is 12/12 for both
R3 and R6.  The reader's strongest R3 pair is nibbles `(1,5)`; it is a
cross-byte relation, not one of the eight fixed byte pairs.  A new 2,000
pair/key Random→Counter run frozen to `(1,5)` is only R3 12/20, R6 20/20.
Therefore no single pair carries the retained output graph; the pairwise
information is itself distributed.  This closes the tempting single-S-box or
single-pair interpretation and provides the next concrete search object: a
small *multi-edge* pair graph with a held-out combinatorial selection rule.

Pair-screen JSON SHA-256:
`8777320f48b17956e7464c83c71c93bbda71bbdb2b84a122955bf664939917a4`.
Frozen `(1,5)` JSON SHA-256:
`570b52a9a13ecd9bdf036d4910f2761a6b2f499c52c0b4683917e45fb0477812`.

## Structured multi-edge and minimal pair follow-up

The six highest discovery edges happened to be exactly the complete graph on
`{1,5,9,13}`, one apparent pLayer column.  That attractive interpretation did
not survive: the frozen six-edge graph is only R3 11/20, R6 20/20.  Four such
columns (24 edges), four contiguous four-nibble rows (also 24 edges), and a
deterministically random 24-edge control all give 20/20 per class.  Hence the
24-edge success is aggregation capacity, not evidence specific to pLayer
column geometry.

Using a fixed random edge order, widths 12 and 6 remain 20/20 per class, and
width 3 is R3 19/20, R6 20/20.  Decomposing that triple yields one stable edge:
the joint collision feature for post-S-box nibble pair `(7,14)` is 20/20 per
class under Random→Counter.  This pair was not selected directly from its own
holdout; it was isolated from the earlier fixed random triple and confirmed on
a new seed family.

The minimal pair has an exact boundary:

| `(7,14)` training→holdout | R3 | R6 |
| --- | ---: | ---: |
| Random→Counter, bit XOR | 20/20 | 20/20 |
| Random→Counter, byte XOR | 20/20 | 20/20 |
| Random→Mixed | 20/20 | 20/20 |
| Mixed→Random | 20/20 | 20/20 |
| Counter→Random | 7/20 | 20/20 |
| Counter→Mixed | 11/20 | 20/20 |

Thus `(7,14)` is intervention-width robust and transfers among Random/Mixed
training and to Counter holdouts, but a graph trained only on Counter bases is
not domain-general.  The retained minimal claim must include this asymmetry.

Key JSON hashes: apparent column K4 `afdf6c4fe041f05b2e329ce6ed1fc42339bab3965fd58757a1d5a5de842ad3c5`;
four columns `e39b5b8be1946a4aef70ab204d8f176f320d7db7271632d39f13cefee76abd34`;
four rows `959ca997134042db7509aca315b80bf75992b453f1971e2c9b6ab567f199ea96`;
random 24/12/6/3 `3a92c16f99ba115896981c3e5a156c6c4051a77fd69812f2640be42bde19fb77`,
`cbf536172d748ed406908500ee0f7c485a3722ef570239e78f13162b5d89bf0d`,
`fbe2882977a298c9921a9085cd1dfe490cd7f41f03b9be77958ef9ac90fd8576`,
`3b088621bd005388752d359f060f328b8a28478f04ceaa0491a0c267f2c51461`;
pair `(7,14)` Random→Counter `6ff6afacd642db141ade135a1536af520d60329598e5d4641440ad2ce56468aa`;
Counter→Random `c2b38131a7ea5f774d46348204670003d010f3a0357e588f52c3278cc923b08f`;
byte-XOR `b88c4e769d8a7aa44a20b33f0251ac5f779c04e34f96a1ef254e76351ad5a6b9`;
Random→Mixed `b88ef05296a9179bf375967fdb1a553e4f2f41d9cfb776fb4e8126aa66d98eb3`;
Mixed→Random `4e501ce4da28c9c63732deb0692f0ff1071b24040b0b14dcfa37b37f7ca42f6c`;
Counter→Mixed `755950505f771f2b8d947e9fd06281d2394f883a10c93ad0acf82aa4fc9abe1a`.

# Direct Output-Causal Compression: AES R3 Contrast Signature

## Result

A causal graph built directly from paired AES outputs and row-repair
counterfactuals identifies the reduced-round generator class from new output
batches.  This is a known-key reduced-round output-inference result, not key
recovery and not a full-AES security claim.

For each batch, the codec computes 16 factual-minus-repaired byte entropy
contrasts.  The graph stores class-to-contrast-node triplets with their trained
means and standard deviations.  At holdout, the `.causal` file is opened with
`CryptoCausalReader`; the reader-reconstructed profile alone performs the
reverse class query.  Writer-side arrays are not used in the query.

## Independent confirmation

Both runs use five train keys, five disjoint holdout keys, 10,000 pairs/key,
four frozen input XOR bits (0, 31, 64, 127), and 16 row-repairing routes.

| class | discovery | independent confirmation |
|---|---:|---:|
| R3 identity | 25% (5/20) | 15% (3/20) |
| R3 peeled final linear layer | **100% (20/20)** | **100% (20/20)** |
| R4 identity | 20% (4/20) | 20% (4/20) |
| R4 peeled | 5% (1/20) | 25% (5/20) |
| AES-10 identity | 20% (4/20) | 15% (3/20) |
| AES-10 peeled final ShiftRows | 35% (7/20) | 15% (3/20) |

Six-class chance is 16.7%.  The frozen confirmation rule required R3 peeled
at least 80% and every other class at most 50%; both conditions hold.

## Causal header

The reader-visible graph header states the full chain:

`paired cipher outputs -> factual XOR delta -> row-repair counterfactuals ->
per-byte entropy contrast -> causal zlib serialization -> reader reverse class
query`.

This is output-derived causal compression: a batch is compressed into an
interventional contrast profile, then the graph amplifies the stable class
profile across its 16 nodes and reverses it on unseen output batches.

## Boundary

The result does not distinguish full AES from random ciphertext in a security
game, recover a key, or imply an attack on AES-128.  It identifies one
reduced-round, formula-projected output class among six pre-specified classes
under known experimental pairing and output access.

## Reader-derived sparsity and input-bit transfer

Opening the independently confirmed graph with `CryptoCausalReader` ranks the
R3-peeled profile nodes 13, 11, 14 and 12 highest.  A third independent run
using only those four nodes still gives R3 peeled 20/20.  A fourth run with
only node 13 also gives R3 peeled 20/20 for the original four-bit mixture, but
its bit-31-only control is not clean; the four-node profile is therefore the
retained object, not a universal single-byte claim.

Most importantly, the four-node graph was trained on input bits 0, 31, 64 and
127, then queried only on disjoint input bits 15, 47, 79 and 111 under new
keys.  R3 peeled remains 20/20; the five other classes are 1/20, 6/20, 2/20,
7/20 and 2/20.  This rules out the simple explanation that the graph only
memorizes the original input-bit lanes.

## Formula ablation

Replacing the per-byte entropy contrast with an otherwise identical per-byte
bit-bias contrast on a new ten-key block weakens R3 peeled to 9/20 (45%), while
R3 identity is 7/20 (35%).  The full entropy-contrast graph is therefore not
interchangeable with a generic causal feature: the retained mechanism is the
factual-minus-repaired byte-entropy profile.

## Stronger global-pairing null

The sparse four-node bit-transfer was repeated with 16 BvN global routes per
batch. Each route is a bijection, preserves the exact paired-output multiset,
and forbids identity and adjacent alignments. R3 peeled remains 20/20; the
five controls score 3/20, 2/20, 1/20, 4/20 and 6/20. Thus the result does not
depend on the weaker unconstrained shuffle control.

## Depth and formula map

The frozen BvN bit-transfer setup (the same ten keys, held-out input-bit
family, four reader-derived nodes and 16 routes) was run at 1,000, 2,000 and
5,000 pairs per key. R3 peeled scores 6/20 (30%), 13/20 (65%) and 20/20
(100%), respectively; at 5,000 pairs every control is between 0/20 and 6/20.
The codec is therefore not usable at 1,000 pairs/key in this configuration;
the observed practical transition is between 2,000 and 5,000, not an
unreported tuning assumption.

At the fixed 5,000-pair point, the causal header was varied along with the
actual reader-visible node formula. Shannon entropy gives 20/20 R3 peeled;
the independent collision-deficit formula gives 16/20, with controls 0--5/20;
bit-bias gives only 3/20 while two controls reach 8/20. Thus the retained
mechanism is distributional (an entropy-family contrast), not merely a
per-bit imbalance. Each variant has its own `.causal` header and is reopened
with `CryptoCausalReader` before reverse classification.

## Artifacts

- Frozen config: `configs/aes_causal_contrast_signature_confirm_v1.json`,
  SHA-256 `61ec8460dd2772b275f5957150e7cdfd5d40dc289d92c18606da738f16d1b01e`.
- Discovery JSON: `results/v1/aes_causal_contrast_signature_v1.json`,
  SHA-256 `66e519a990c5a929a59d045d3346773d3ebb3ce3e61253c7236a02848ac3ea7e`.
- Confirmation JSON: `results/v1/aes_causal_contrast_signature_confirm_v1.json`,
  SHA-256 `5eeef00c3c1248678f8ef1fa802a6bc9bb338f2f147e8575507da45b466294e6`.
- Confirmation graph: `results/v1/aes_causal_contrast_signature_confirm_v1.causal`,
  SHA-256 `85c14d1960d5f871c5354f92744ea3a9ad282b0478c2a683ae71ef8eb4986e55`.
- Sparse four-node transfer JSON: `results/v1/aes_causal_contrast_signature_sparse_bittransfer_v1.json`,
  SHA-256 `8db3f1948df2e2f023ab81c0af2a00b1265f7dd815bae73c664c97e522ab6ac0`.
- Sparse four-node transfer graph: `results/v1/aes_causal_contrast_signature_sparse_bittransfer_v1.causal`,
  SHA-256 `e7a6b91c0c067ec148d17a9e660d723f6d12e4802f6267fa55a1206eb947dae7`.
- Bit-bias ablation: `results/v1/aes_causal_contrast_signature_bitbias_v1.json`,
  SHA-256 `e02ec7a34ff64900ba3d993f3995e03748b13049f2d1a8fd2820ee4c59e537a7`.
- BvN route hardening: `results/v1/aes_causal_contrast_signature_bvn_v1.json`,
  SHA-256 `130e345583520b07b5f8b678a6d9e6eca479aa7f0031bacb05928284b9419fef`.
- BvN depth sweep: `results/v1/aes_causal_contrast_signature_bvn_n1000_v1.json`
  (SHA-256 `4a61ca637e04411531a6dd3f3ede82a0882b07cd43dc13fdbdd2ea9de843a03e`),
  `..._n2000_v1.json` (SHA-256
  `342d6c5810df44d1dfdc636f18e983959fc8894944b73cc87b60992e6931185e`) and
  `..._n5000_v1.json` (SHA-256
  `0d8bbac74fa89c0b465fd7201e35c9b68ca1db14620f2381446110fd4419f839`).
- Formula-family ablation at BvN/5,000: collision
  `results/v1/aes_causal_contrast_signature_bvn_collision_n5000_v1.json`
  (SHA-256 `18b3963ce053e92e0d488f7eae27a2c50c6046a8ecbbb7cb9307e6c062f2b160`);
  bit-bias `results/v1/aes_causal_contrast_signature_bvn_bitbias_n5000_v1.json`
  (SHA-256 `127ac209d15b5eabd41d46f89d45a958624fd26736d95992b7ac94ffb22d73e9`).

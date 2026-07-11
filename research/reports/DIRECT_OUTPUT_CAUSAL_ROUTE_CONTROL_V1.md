# Direct Output-Causal Route-Control Correction

## Correction

Earlier BvN experiments derived the repair-route seed partly from the round
label. This did not expose target labels to the graph, but it gave every class
a distinct finite repair ensemble. With few training keys, route-estimation
noise could act as a class feature. New runs therefore use one route bank per
seed and input-pair batch, shared across every compared round/representation.
The graph parameters record this as `repair_route_seed_strategy`.

The adjacency-traversal R3 pattern does not survive this correction cleanly:
only sequential is 4/5; the other structured traversals are 2--3/5 and R20
can be 4/5. It is retained as a negative methodological breadcrumb, not as a
confirmed R3 traversal claim. R2 remains 5/5 throughout that shared-route
cycle run.

## AES retained under shared routes

New BvN bit-transfer run: five train keys, five fresh holdout keys, training
bits 0/31/64/127 and unseen bits 15/47/79/111, 5,000 pairs/key, four
reader-derived nodes 13/11/14/12. R3 peeled is 19/20; controls are 0--5/20.
Thus the AES R3-peel result survives the stricter same-route correction.

Replacing the six class-specific diagonal variances with a reader-visible
pooled variance leaves R3 peeled at 18/20; the five controls are 1--6/20.
Thus the retained AES signature is not carried by a variance-floor artifact.

`results/v1/aes_causal_contrast_signature_bvn_sharedroutes_n5000_v1.json`
has SHA-256 `4c2669e5e67875f2e4bec561d2f94bf1d25e527624a00cf723163e67cc27daaf`.
The pooled-variance artifact is
`results/v1/aes_causal_contrast_signature_bvn_sharedroutes_pooled_n5000_v1.json`,
SHA-256 `4cb9dcc10197b0fb19bae08ea146f38c1aafcc5c0cbd34604e1a380195738d62`.

## ChaCha core transfer

For ChaCha, the direct counter-XOR graph was re-run using shared BvN routes,
then two representation ablations:

| output view / classifier | R3 | R4 | R20 |
|---|---:|---:|---:|
| full, class variance | 19/20 | 8/20 | 12/20 |
| pre-feed-forward core, class variance | 17/20 | 8/20 | 9/20 |
| pre-feed-forward core, pooled variance | 16/20 | 9/20 | 14/20 |

The counter addition is therefore not necessary for the contrast. Pooled
variance makes the three-class reader less specific, so the decisive frozen
test is a binary R3-vs-R20 graph with the core representation and pooled
variance. It gets R3 13/20 and R20 20/20 on new keys and *unseen* counter XOR
bits 1/8/16/30 after training only on 0/7/15/31 (82.5% overall; chance 50%).

This is a reduced-round, known-input output-inference result. It is not key
recovery or a full ChaCha20 security claim.

## Reader-derived core sparsity

Opening the first binary core-transfer graph with `CryptoCausalReader` ranks
bytes 10, 13, 5, 9, 62, 4, 11 and 7 by the R3--R20 pooled standardized
contrast. A new disjoint bit family using only those eight nodes gives R3
14/20 and R20 20/20. A third independent family using only the top four
nodes 10/13/5/9 gives R3 12/20 and R20 20/20. Byte 10 alone drops R3 to 8/20
while R20 remains 20/20. The retained compact object is therefore the
four-node graph, not a single-byte claim.

- Eight-node transfer: `results/v1/chacha_causal_contrast_signature_bvn_core_pooled_sparse_bitfamily2_v1.json`, SHA-256 `af1ce3cfaab13feded92fac3e65d7697056b513d58d8707cc134a679f6e35a65`.
- Four-node transfer: `results/v1/chacha_causal_contrast_signature_bvn_core_pooled_top4_bitfamily3_v1.json`, SHA-256 `f3815691dcda4485370a0c3a4bbb96116ba1a45bda866632dff7419316d0363a`.
- One-node negative: `results/v1/chacha_causal_contrast_signature_bvn_core_pooled_top1_bitfamily4_v1.json`, SHA-256 `5d97276584b7cca950dc41f7fc39d5dadfefab03160b199aba2e285c5945eec8`.

## Artifacts

- Shared-route full JSON: `results/v1/chacha_causal_contrast_signature_bvn_sharedroutes_v1.json`, SHA-256 `c1d884d63dea8a156ea68a74a750676c9eb032e042aff1112dc36b2f90902ff3`.
- Shared-route core JSON: `results/v1/chacha_causal_contrast_signature_bvn_sharedroutes_core_v1.json`, SHA-256 `fbaeb95bc6a91517151d9ee8f3d1bfa1f2dd67710c5d0381a56feb5fe3997cea`.
- Core pooled bit-transfer JSON: `results/v1/chacha_causal_contrast_signature_bvn_sharedroutes_core_pooled_r3r20_bittransfer_v1.json`, SHA-256 `c6bc8141d2c6eab4bc227ad9245584a4d2b832f809ec14adfff955cf9e6c39b5`.

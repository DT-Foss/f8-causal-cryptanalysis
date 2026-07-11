# Direct Output-Causal SIMON Full-Round Null

The direct cipher-output contrast codec was applied to SIMON32/64 late prefix
rounds R24--R32: chosen plaintext-bit pairs, shared BvN repairs, pooled reader
variance, fresh keys and disjoint input bits. Nine-class accuracy is 25/180
(13.9%) against 11.1% chance; the highest individual rounds are only 5/20.

Thus the codec does not automatically produce a late-round SIMON signal. This
is a useful independent full-round null alongside the Threefish result; no
SIMON causal output claim is retained.

Artifact: `results/v1/simon_causal_contrast_signature_v1.json`, SHA-256
`ac114df725082be0f0d32e408a4cbb95cd3946328346bd6378dbfc8a1af535ea`.

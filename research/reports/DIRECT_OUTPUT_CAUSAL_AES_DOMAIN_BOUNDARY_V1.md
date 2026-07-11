# Direct Output-Causal AES Input-Domain Boundary

The retained AES R3 graph is strong on the original random-plaintext setup
and transfers in the Random-Train → Counter-Holdout direction (R3 19/20).
The reverse and a domain-mixed training attempt establish the boundary:

| train base domain | held-out base domain | R3 | R4 | R10 |
|---|---|---:|---:|---:|
| random | counter | 19/20 | 10/20 | 9/20 |
| counter | random | 0/20 | 20/20 | 0/20 |
| 50/50 random/counter rows | random | 0/20 | 8/20 | 12/20 |

The reverse run is a complete domain collapse: all 60 held-out random batches
are labelled R4. Therefore the current four-node entropy graph is not
domain-invariant. The retained statement is asymmetric: it survives the
tested random→counter transfer but should not be read as a universal
plaintext-domain distinguisher.

- Counter→random: `results/v1/aes_causal_contrast_signature_bvn_pooled_counter_to_random_v1.json`, SHA-256 `d45a6fd6e530d04f1bf55db1aaa15f10c04fea432de81f9ab16daa7300bd9bde`.
- Mixed→random: `results/v1/aes_causal_contrast_signature_bvn_pooled_mixed_to_random_v1.json`, SHA-256 `ca3bf4dc3fad824180a4681aa3e837e6902dfe54f721c0859ee4588b488071d0`.

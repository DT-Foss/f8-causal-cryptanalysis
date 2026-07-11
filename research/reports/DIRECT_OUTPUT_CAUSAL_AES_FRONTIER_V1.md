# Direct Output-Causal AES R1/R3 Frontier

The shared-route, pooled four-node AES graph (bytes 13/11/14/12 after the
public final-linear inverse) was evaluated across every AES prefix round R1
through R10, with fresh keys and held-out input XOR bits. Ten-class chance is
10%.

| class | held-out accuracy |
|---|---:|
| R1 | 20/20 |
| R2 | 5/20 |
| R3 | 18/20 |
| R4 | 2/20 |
| R5 | 3/20 |
| R6 | 6/20 |
| R7 | 1/20 |
| R8 | 2/20 |
| R9 | 2/20 |
| R10 | 2/20 |

R1 is the expected local baseline after undoing the final linear layer. R3
forms a separate second peak, not merely an R1 confusion: in a new binary,
pooled, shared-route graph trained and queried on a second non-overlapping bit
family, R1 and R3 are both 20/20. This is a known-input reduced-round output
classification result, not key recovery or a full-AES claim.

- R1--R10 frontier: `results/v1/aes_causal_contrast_signature_bvn_pooled_roundfrontier_v1.json`, SHA-256 `bd3bafe49f8fb658d53ec385db67bcb1ffa294a7646e2658fffcc57945a825fb`.
- Fresh R1-vs-R3 transfer: `results/v1/aes_causal_contrast_signature_bvn_pooled_r1r3_bitfamily2_v1.json`, SHA-256 `b168014be38c21493759f650f69cd8396bdb59179adad8678da0e19a6fe08dfb`.

## Input-domain transfer

The graph was trained only on random plaintext bases and queried only on
little-endian sequential-counter plaintext bases, with fresh keys and heldout
input XOR bits. In the R3/R4/R10 peeled comparison, R3 remains 19/20; R4 and
R10 are 10/20 and 9/20. The changed base distribution makes those controls
more separable too, but does not remove the R3 dominance. Thus the retained
AES graph is not confined to uniformly random plaintext bases.

Artifact: `results/v1/aes_causal_contrast_signature_bvn_pooled_random_to_counter_v1.json`, SHA-256 `7140ef67fbe30fff656f0691155416552c766449acbf742669712c236b4ec5a2`.

## Byte-difference transfer

The same graph was then driven by full-byte XOR interventions instead of
single-bit flips: train bytes 0/3/8/15 and held-out bytes 1/5/10/14. With
fresh keys, R3 is 18/20; R4 and R10 are 10/20 and 8/20. Thus the R3 profile is
not confined to Hamming-1 plaintext differences, although this remains a
known-input reduced-round classification experiment.

Artifact: `results/v1/aes_causal_contrast_signature_bvn_pooled_byteflip_v1.json`, SHA-256 `e8193d901dd049976d6ea9174212c241ae671baed0115dde5873ee30501a82c1`.

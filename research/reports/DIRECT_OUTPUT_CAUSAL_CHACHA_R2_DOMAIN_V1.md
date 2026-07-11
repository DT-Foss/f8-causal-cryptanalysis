# Direct Output-Causal ChaCha R2 Core and Domain Boundary

Under shared BvN routes and pooled reader variance, the full 64-byte
pre-feed-forward core graph separates R2/R3/R20 on random uint32 counter
bases at 20/20, 9/20 and 18/20. Reader ranking for the R2-vs-R20 comparison
selects bytes 2/9/54/63, which have large R2 entropy deficits rather than the
small R3 contrast pattern.

The four-node R2/R20 graph is 20/20 for each class on sequential bases and
also transfers Random-Train → Sequential-Holdout at 20/20 for each class.
The reverse Sequential-Train → Random-Holdout is asymmetric: R2 0/20 and
R20 20/20. This mirrors the AES domain boundary and limits the result to a
known-input reduced-round output-classification relation, not a universal
counter-domain or security claim.

- R2/R3/R20 full graph: `results/v1/chacha_causal_contrast_signature_bvn_core_pooled_r2r3r20_v1.json`, SHA-256 `f6a66da83b711c68e88fe5ee05b4bc3f9236ca40300575fe71c0f4043047579c`.
- Random→sequential top-4: `results/v1/chacha_causal_contrast_signature_bvn_core_pooled_r2r20_top4_random_to_sequential_v1.json`, SHA-256 `e7d3bd0f4bccb3ef471699f06f916d6a42a563037aa9701e12c0f3d0d1a66f3f`.
- Sequential→random top-4: `results/v1/chacha_causal_contrast_signature_bvn_core_pooled_r2r20_top4_sequential_to_random_v1.json`, SHA-256 `f76bce5925e985bfc1f976d52454ab4c03768fc97d7ed9ae84d65550ce7dca0b`.

## Normalization ablation

The failed sequential→random direction was re-run after L2-normalizing each
factual-minus-repair profile before it entered the reader graph: R2 improves
from 0/20 to 6/20, while R20 is 17/20. Removing the profile mean before the
same L2 normalization gives R2 0/20 and R20 17/20. Thus global magnitude
accounts for some shift but the domain boundary is primarily a change in the
four-node profile shape, not a removable scalar offset.

- L2: `results/v1/chacha_causal_contrast_signature_bvn_core_pooled_r2r20_top4_sequential_to_random_l2_v1.json`, SHA-256 `0d7a61432daf6f3e295bf22a4d2231e835ce80f767d7cdffbb7286176ce39f6f`.
- Centered-L2: `results/v1/chacha_causal_contrast_signature_bvn_core_pooled_r2r20_top4_sequential_to_random_centeredl2_v1.json`, SHA-256 `cc789717b86574f264b8c881a046a05e1c133af10aa3c6f112b1fb557be6d072`.

A rank-only profile, which preserves only relative ordering of all 64 contrast
nodes, also gives R2 0/20 and R20 17/20. Thus scale, offset and simple node
ordering do not explain the boundary.

- Rank: `results/v1/chacha_causal_contrast_signature_bvn_core_pooled_r2r20_top4_sequential_to_random_rank_v1.json`, SHA-256 `c92837aa9f4dcb71995f8fd48c9e68477fe2283fe4310c80f3cbb025de3faa4e`.

## Byte-difference boundary

The bit-derived top-4 graph was also queried with whole-byte counter XORs:
train bytes 0/2 and held-out bytes 1/3. R2 is 5/10, exactly binary chance,
while R20 is 10/10. Thus that *bit-derived compact profile* is bit-local; it
does not establish that R2 itself is bit-local.

Artifact: `results/v1/chacha_causal_contrast_signature_bvn_core_pooled_r2r20_top4_byteflip_v1.json`, SHA-256 `e59983aed2be5e5ef19be01eadace35f0deadc526a5fb87e85d60aaf844e40c0`.

Relearning from the full 64-node byteflip graph gives a distinct reader atlas
5/52/11/7. It is 20/20 for each R2/R20 class after swapping training and
held-out byte positions on new keys. Unlike the bit-derived atlas, this
byte-derived atlas also gives 20/20 per class on unseen single-bit
interventions, Random-Train→Sequential-Holdout byteflips, and
Sequential-Train→Random-Holdout byteflips. R2 therefore has a hierarchy of
profiles: the bit atlas 2/9/54/63 is intervention/domain-sensitive, while the
byte atlas 5/52/11/7 is the retained robust R2 anchor in the tested spaces.

- Full byteflip graph: `results/v1/chacha_causal_contrast_signature_bvn_core_pooled_r2r20_full_byteflip_v1.json`, SHA-256 `b0317a19c8069e69926f17dfa1a4c0755ec682e661230933dfdd22933e507493`.
- Sparse byteflip graph: `results/v1/chacha_causal_contrast_signature_bvn_core_pooled_r2r20_byteflip_top4_v1.json`, SHA-256 `10e5db19208cbb20ba466691f116c3cbfea6397cc99ddf119e8d1c86e71eb352`.
- Byte atlas→bit: `results/v1/chacha_causal_contrast_signature_bvn_core_pooled_r2r20_byteatlas_to_bit_v1.json`, SHA-256 `8c88240cd7c2adfb6271e51f2f9fbad8f1627aa2a0226b6ffab6725693ecc668`.
- Byte atlas random→sequential: `results/v1/chacha_causal_contrast_signature_bvn_core_pooled_r2r20_byteatlas_random_to_sequential_v1.json`, SHA-256 `a9c72e75ff85b0e09412f743b11be9edc01d6e0a72e8f74298eb537ebd59fdd3`.
- Byte atlas sequential→random: `results/v1/chacha_causal_contrast_signature_bvn_core_pooled_r2r20_byteatlas_sequential_to_random_v1.json`, SHA-256 `fd8a641e6af894c6fed99e56ac6231180ebb0688fcf9135e5dec47a446a07ba8`.

## Byte-atlas round frontier

Across R1--R8 and R20, the byte atlas has held-out accuracies R1 10/10, R2
9/10, R3/R4/R8/R20 0/10, R5 4/10, R6/R7 2/10. A fresh binary R1-vs-R2 graph
is 10/10 for both classes. Hence the byte atlas separates two consecutive
early-round classes rather than merely flagging a generic early-round regime.

- Frontier: `results/v1/chacha_causal_contrast_signature_bvn_core_pooled_byteatlas_roundfrontier_v1.json`, SHA-256 `dd4592bb3f52d96528a20bce5b1ac5ffc16a593f9f1a40eae9122fa612fb0745`.
- Fresh R1-vs-R2: `results/v1/chacha_causal_contrast_signature_bvn_core_pooled_byteatlas_r1r2_v1.json`, SHA-256 `e53c8e545b2050f414f1c1b30ce381636079562bdddc21997ed49650f907a6ec`.

## Full-output and counter-word ablation

The core-derived byte atlas 5/52/11/7 also separates R1/R2 on normal ChaCha
block output with feed-forward (R1 10/10, R2 8/10). Zeroing the explicit
counter output word 12 gives R1 10/10 and R2 10/10. The retained atlas is
therefore not an artifact of that directly visible counter word; it is present
in the rest of the actual block output.

- Full output: `results/v1/chacha_causal_contrast_signature_bvn_full_pooled_byteatlas_r1r2_v1.json`, SHA-256 `969246dfa69cc2de2cca6cda17b488e257febc95060c74846d35955fdab54b00`.
- Counter-word masked: `results/v1/chacha_causal_contrast_signature_bvn_maskcounter_pooled_byteatlas_r1r2_v1.json`, SHA-256 `a345cfb7551e5aac07535e68acf85dd2fc3c50123ba373c1c75a6c67200e9db4`.

## Output-word localization

The four byte-atlas nodes lie in words 1 (bytes 5/7), 2 (byte 11), and 13
(byte 52). On normal full output, independently zeroing word 1 reduces R2 to
1/10 while R1 stays 10/10. Zeroing word 2 retains 10/10 for both; zeroing
word 13 retains R1 10/10 and R2 9/10. Thus the output-level R2 decision is
dominated by word 1. This is an output ablation result, not yet an assertion
about a unique internal quarter-round path.

- Word 1 masked: `results/v1/chacha_causal_contrast_signature_bvn_full_maskword1_byteatlas_r1r2_v1.json`, SHA-256 `0e2091b5f96a5195b3eb8e67e05d274ca2f87c3914054b9d6cde300dd00af839`.
- Word 2 masked: `results/v1/chacha_causal_contrast_signature_bvn_full_maskword2_byteatlas_r1r2_v1.json`, SHA-256 `1d661afb597329cb5ae5d962a1836dcbae6bcddb6bb9de956321327e2956f3eb`.
- Word 13 masked: `results/v1/chacha_causal_contrast_signature_bvn_full_maskword13_byteatlas_r1r2_v1.json`, SHA-256 `03f07071f9f0e39cd57bbf305331a97979acdee8467bb548bde18ac1aa0d5ecb`.

## Minimal sufficient byte

The two Word-1 bytes 5/7 are sufficient for a fresh full-output R1/R2 graph
(10/10 per class). Byte 5 alone is not a robust R2 unit (R1 10/10, R2 6/10),
but byte 7 alone is 10/10 per class on fresh bytes and keys. Byte 7 alone also
transfers Random-Train→Sequential-Holdout and Sequential-Train→Random-Holdout
at 10/10 per class. Thus, within this narrow known-input R1/R2 byte-XOR
experiment, byte-7 factual-minus-repaired entropy contrast is the minimal
retained output unit. This does not imply a full-round or key-recovery result.

- Word 1 pair: `results/v1/chacha_causal_contrast_signature_bvn_full_pooled_word1only_r1r2_v1.json`, SHA-256 `557ff49105ebf4ffebfa28a040be56f9e35dc9741ea09ce645840fe4fd8a08b6`.
- Byte 5 negative: `results/v1/chacha_causal_contrast_signature_bvn_full_pooled_byte5only_r1r2_v1.json`, SHA-256 `394f0ee07d642ce9c4395e4d9d86253929db8bd01ae7fa8a67c6c389aa17c627`.
- Byte 7: `results/v1/chacha_causal_contrast_signature_bvn_full_pooled_byte7only_r1r2_v1.json`, SHA-256 `51189d69d0fe4ba87257fc496bdeb1e9ca83afe6b6a95da7a4a4704205adde15`.
- Byte 7 random→sequential: `results/v1/chacha_causal_contrast_signature_bvn_full_pooled_byte7only_random_to_sequential_r1r2_v1.json`, SHA-256 `545b34c9965a82170e0e696962c785a0541220d9cc798f19f90956582acf4300`.
- Byte 7 sequential→random: `results/v1/chacha_causal_contrast_signature_bvn_full_pooled_byte7only_sequential_to_random_r1r2_v1.json`, SHA-256 `663de0b5882d14f299873f8657645279cffc09d0cef40dd9f06280570faa3a0a`.

Byte 7 alone does not robustly separate R2/R3 (R2 5/10, R3 10/10), whereas
the full byte atlas 5/52/11/7 does so at 10/10 per class on fresh byte
positions and keys. Thus byte 7 is the minimal retained unit for the narrow
R1/R2 boundary, while R2/R3 requires the distributed four-node profile.

- Byte 7 R2/R3 boundary: `results/v1/chacha_causal_contrast_signature_bvn_full_pooled_byte7only_r2r3_v1.json`, SHA-256 `f95eddc85ac90ec4678632ad3455a1e4f641a5c90b0e1fd1e106705ced09555e`.
- Full byte atlas R2/R3: `results/v1/chacha_causal_contrast_signature_bvn_full_pooled_byteatlas_r2r3_v1.json`, SHA-256 `0de653c9a240bb662a26b5f39129d5b731d364592559a14556569ffbdcc7d0f2`.

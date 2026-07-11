# Direct Output-Causal Threefish Full-Round Null

The first direct cipher-output `.causal` codec for Threefish-256 uses
known-key chosen-plaintext bit pairs, actual ciphertext XOR deltas, and a
shared BvN repairing ensemble. It classifies the late prefix rounds R64--R72
from held-out keys and held-out plaintext bits with a pooled reader model.

Nine-class accuracy is 17/180 (9.44%), below 11.11% chance; individual rounds
score 0--4/20. The graph is therefore null. This is consistent with the
existing fair-null result: the historical terminal F8 elevation is reproduced
by a local uniform-state Threefish transition and is not a full-round
distinguishing feature. No Threefish causal output claim is retained here.

The Threefish reference vectors are gated before execution. Artifact:
`results/v1/threefish_causal_contrast_signature_v1.json`, SHA-256
`d1737403cec00997de69780f108e02edc7d6f97c656e5d76c8e933c032bfec7f`.

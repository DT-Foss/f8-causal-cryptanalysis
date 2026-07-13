# ChaCha20 R20 Known-Key Propagation Atlas (A214)

**Evidence stage:** `KNOWNKEY_PROPAGATION_ATLAS_REPRESENTATION_BOUNDARY`

A214 learns propagation-cloud signatures from 16 known R20 keys, selects all hyperparameters on eight different known keys, seals five model orders plus a correlation-aware consensus, and only then reveals the unseen target key by an independent complete `2^20` ChaCha20 enumeration.

## Frozen target ranks

- `F1`: rank **735,047** / 1,048,576
- `F1_F2_F3_F4_combined`: rank **675,467** / 1,048,576
- `F2`: rank **671,360** / 1,048,576
- `F3`: rank **761,049** / 1,048,576
- `F4`: rank **739,364** / 1,048,576
- `F5_multiview_consensus`: rank **727,365** / 1,048,576

## Leakage barriers

- Prereveal SHA-256: `10f34b191ad4441c1aba09832f37ae8f32c7fdee19f9b0ac36f817f1a9e58451`
- The target low20 value was absent during feature selection, model fitting,   validation, rank construction, and prereveal serialization.
- Target collided with an atlas key: `False`
- Independent confirmation bits: `4096`
- Flipped control rejected: `True`

## Reproduction

- Protocol SHA-256: `aa5b7af87c74cbffe7f6d3e50332cc65c07f084435edb4314b32e4904b625698`
- Measurement SHA-256: `5af69528e67cf7039169b16db053c4f1985e79030bee0a0a43fac6f55ca9962b`
- Causal graph SHA-256: `ebd638b989f5e0020cbca540b13d908e562b06cb3fe0ca33d43f8f3c22ace6f2`

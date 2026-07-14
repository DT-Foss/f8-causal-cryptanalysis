# A249 — ChaCha20-R20 fresh multichannel XOR-orbit reader

The reader combines thirty-six typed fresh-solver channels with four XOR-neighborhood operators and evaluates the resulting 144 features under nested leave-one-prefix-out validation.

## Result

- Evidence stage: **FULLROUND_R20_FRESH_MULTICHANNEL_LINEAR_BOUNDARY**
- Outer-holdout mean log2 rank: **6.387870363971**
- Uniform reference: **6.578110496970**
- Rank-information gain: **0.190240132998 bits**
- Exact shared-XOR p: **0.292968750000**
- Prefix folds with positive gain: **4 / 5**
- Best shared XOR offset: **100**

## Outer folds

| Prefix fold | Lambda | Mean log2 rank | Model SHA-256 |
|---:|---:|---:|---|
| 0 | 10.0 | 5.389777 | `0359a4d1144a7faa44926c483355137ed43e87ab7db918c11099cd57adea44d3` |
| 1 | 10.0 | 7.630130 | `94ad6d6de562521231bb586b2dcb7cd1ba80fdb290a0910b18de32ed748a5b1d` |
| 2 | 1.0 | 5.873458 | `074b6e64e8581700ab9b7bdb8961f5217e1abbca3e6ea4a166d57d831822c8b7` |
| 3 | 0.1 | 6.576675 | `bddaf43aeee34e0518f24fc20bd9294230297e4ff87f9c16625c54f786ef0e6b` |
| 4 | 1.0 | 6.469312 | `9ce8044a4b2f029f0047b3da8f2b8dfaff9961fd8045ee5b810924279f065024` |

## Authentic AI-native Causal readback

- Reader integrity: **True**
- Explicit / inferred: **4 / 1**
- Next gap: **nonlinear_or_clause_identity_typed_reader**

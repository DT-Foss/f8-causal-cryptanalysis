# ChaCha Round-4 SMT Directional Transfer v1

## Result

A185 executes a prospectively frozen five-view SMT plan against a genuinely
fresh reduced ChaCha round-4 challenge with 40 unknown key bits. Key word 0 and
the low byte of key word 1 are unknown; the other 216 key bits, counter, nonce,
and complete 512-bit target block are public.

Every view receives the same relation, the same Z3 4.15.4 one-thread execution
mode, and the same 30-second internal budget. All five predeclared views execute
in the fixed order without early stopping:

| View | Frozen representation | Status at 30 s | Recovered assignment |
|---|---|---|---|
| `forward` | four rounds forward to target | `unknown` | -- |
| `inverse` | four rounds backward from target | `unknown` | -- |
| `split1` | one forward plus three inverse rounds | `sat` | `0x230f1aee2d` |
| `split2` | two forward plus two inverse rounds | `sat` | `0x230f1aee2d` |
| `split3` | three forward plus one inverse round | `unknown` | -- |

The two independently executed SAT views return the identical assignment:

| Quantity | Result |
|---|---:|
| combined 40-bit assignment | **150,577,278,509 (`0x230f1aee2d`)** |
| key word 0 | **253,423,149 (`0x0f1aee2d`)** |
| key word 1 low byte | **35 (`0x23`)** |
| `split1` independent confirmation | all 512 target bits exact |
| `split2` independent confirmation | all 512 target bits exact |

The retained result status is exactly
`PROSPECTIVE_CAUSAL_DIRECTION_TRANSFER_RETAINED`. This is a reduced round-4
directional-representation result over a 40-bit partial-key relation. It is not
a 20-round ChaCha20 recovery and not a full 256-bit key recovery.

## Prospective freeze and information boundary

The A185 protocol was frozen before any A185 solver execution. Its SHA-256 is:

```text
4132728bfd1a5ed6865d38e6adfa6ed2cc9e1e75073ec0960201d4076d323fa1
```

The fresh public challenge has canonical SHA-256:

```text
d477f28da2dc9fb87e124127ba7518ef90083a0ac6bf10c61fd3ef91e50ff9f7
```

The known material is domain-separated from the retained A184 result through
SHAKE256 label:

```text
f8-causal:A185:chacha20:r4-direction:known-material:d467c06105d4a4afba9efaa7bdf6c4e58754b034d4640907486c778ad17e12a9
```

The 44 derived bytes reproduce the upper 24 bits of key word 1, key words 2
through 7, counter, and nonce exactly. Their digest is:

```text
04f9b57b70db9574c05e35830b5362d0ab433eec1eb16b400923f6dc76f0160a
```

The unknown 40-bit assignment is generated once from operating-system
cryptographic randomness, used only to construct the public target, and
discarded before the protocol is frozen. Its decimal values and complete exact
hexadecimal forms are absent from both the protocol and runner. The runner
receives only the public target and known material; no assignment is available
before execution.

The factual target block digest is:

```text
0f577a89f5049326db0f8494f97d6e51db03315354efbb98732458a132cde154
```

The retained control differs only in bit zero of output word zero and has
digest:

```text
54a1cd0a046e81d6fdb4f2bf637ddeb96715e3ccfdc47afd07863e50258061c2
```

## Fixed five-view formula plan

The canonical execution-plan digest is:

```text
3160f3c45617a04b99530a9d139b1eb00501a8e0f4485c3e021669c809d87a8f
```

Each view is a semantically matched QF_BV formula over `k0` and `lo8`, using a
shared `define-fun` DAG and complete 512-bit target constraints. The five views
are generated in order before execution:

| View | Formula bytes | Formula SHA-256 |
|---|---:|---|
| `forward` | 8,865 | `432a117edc7996c2e99e0717d2fdc830ca53c38bb41ec57085884a46deda77e1` |
| `inverse` | 9,138 | `f464ddd82ef51f9ac71a19d73314cb2c3b4822cb70b4e12cd2bf05d2b4e5f340` |
| `split1` | 9,170 | `a3af7431ad1687fc7000a131df3e397b597e6092ae4bca998979c16908e6e0e3` |
| `split2` | 9,169 | `6104e272345919ca5fb1d138e19c0ef37eb6ebdee3b81af87a276ade0fe33983` |
| `split3` | 9,169 | `6ce8fb1a329d157aec74434ffd4395ce80d1da762bfdeec25593b520baabb784` |

The canonical digest of this ordered formula plan is:

```text
fe884dd4396c2672221b16e4d4d37c032c9446d89eb84a2c4dde5777be04d08d
```

The non-production regression gate regenerates all five formulas and verifies
their byte lengths and hashes exactly without invoking Z3.

## Complete fixed-budget execution

All five views execute sequentially with Z3 4.15.4, one thread, an internal
30,000-millisecond timeout, and a 40-second external process guard. None reaches
the external guard. `forward`, `inverse`, and `split3` return `unknown` under
the fixed internal budget. `split1` and `split2` independently return `sat`.

The complete execution digest is:

```text
3afe54a447dcef54d48d3c99f2c0c7d25a648c21e4621366134f3dcd2e82e04d
```

There is no early stop: `split2` and `split3` still execute after the first SAT
model from `split1`. The complete ordered status vector is therefore retained,
including all three `unknown` boundaries.

## Independent confirmation

Each SAT model is passed separately to the NumPy ChaCha core. The independent
implementation reconstructs the complete initial state, evaluates all four
rounds plus feedforward, and compares every one of the 16 output words. Both
`split1` and `split2` reproduce the target digest
`0f577a89f5049326db0f8494f97d6e51db03315354efbb98732458a132cde154`
over all 512 bits.

The ordered two-confirmation digest is:

```text
31c8585ed6cfe56b05556bbea0474802acb0eac946b2fb169d43482c204566f0
```

## Causal Reader chain

The retained Causal artifact contains five explicit provenance-linked edges:

1. the hash-pinned A184 fullround 40-bit domain anchor;
2. the fresh prospectively frozen A185 round-4 challenge;
3. the exact five-view formula plan;
4. complete fixed-order, fixed-budget execution;
5. independent 512-bit confirmation of both SAT views.

`CryptoCausalReader` verifies:

- result JSON:
  `d87aefa46f4b85a71ab9fd2199401975075beb0fedf1545b9dc63842126c31e0`;
- Causal artifact:
  `ea490a5ea59838faacddfc11ca80390e6cb87ff35943eb1e294cd1006f1e77ac`;
- canonical Causal graph:
  `43f5b6a267de0fcd272136d46f84442697c2186b98bbb59dccaf74f9bba77824`;
- A184 result anchor:
  `d467c06105d4a4afba9efaa7bdf6c4e58754b034d4640907486c778ad17e12a9`;
- A184 Causal anchor:
  `b37bc0234966185e06eb15ae6926502535b0c50271b01f0b6bd8fe5394dabd0f`.

## Reproduction

The default retained-result verification performs protocol, public derivation,
secret absence, exact formula generation, result digest, independent NumPy
confirmation, and Causal Reader gates without invoking Z3:

```bash
PYTHONPATH=.:src .venv/bin/python \
  research/experiments/chacha20_smt_directional_round4_transfer.py \
  --analyze-only

PYTHONPATH=.:src .venv/bin/pytest -q \
  tests/test_chacha20_smt_directional_round4_transfer.py
```

An explicit fresh five-view solver execution is:

```bash
PYTHONPATH=.:src .venv/bin/python \
  research/experiments/chacha20_smt_directional_round4_transfer.py \
  --z3 z3
```

The solver command is production work and is not part of the fast retained-
artifact integration gate.

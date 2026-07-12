# ChaCha Round-5 SMT Directional Boundary v1

## Result

A186 executes a prospectively frozen six-view SMT plan against a genuinely
fresh reduced ChaCha round-5 single-block relation with 40 unknown key bits.
Key word 0 and the low byte of key word 1 are unknown; the other 216 key bits,
counter, nonce, and complete 512-bit target block are public.

Every view receives the same relation, Z3 4.15.4 one-thread execution mode, and
30-second internal budget. All six predeclared views execute in fixed order
without early stopping:

| Order | View | Frozen representation | Status at 30 s | Assignment |
|---:|---|---|---|---|
| 1 | `forward` | five rounds forward to target | `unknown` | -- |
| 2 | `inverse` | five rounds backward from target | `unknown` | -- |
| 3 | `split1` | one forward plus four inverse rounds | `unknown` | -- |
| 4 | `split2` | two forward plus three inverse rounds | `unknown` | -- |
| 5 | `split3` | three forward plus two inverse rounds | `unknown` | -- |
| 6 | `split4` | four forward plus one inverse round | `unknown` | -- |

No model is returned by any view. The retained result status is exactly
`ROUND5_DIRECTIONAL_SOLVER_BOUNDARY_RETAINED`.

This establishes the exact measured round-4→round-5 fixed-budget boundary:
A185's fresh round-4 `split1` and `split2` SAT views do not return models after
the same representations are transferred prospectively to the fresh round-5
relation under the same 30-second budget. A186 is a reduced round-5
directional-representation boundary, not a 20-round ChaCha20 recovery and not a
full 256-bit key recovery.

## Prospective freeze and information boundary

The A186 protocol was frozen before any A186 solver execution. Its SHA-256 is:

```text
67c27032eab51ac443dcb5446eca3fe46b1c42dd60a02fb13d2d7c0b97e3c6fe
```

The immutable runner SHA-256 is:

```text
4796799d7d0b3224e5d291cdb8f93a14a2a9860082fa248bb3ee64eb2eb27a9c
```

The fresh public challenge has canonical SHA-256:

```text
1ae9e4d48c61ec31513ae34024ebc4d1d0bebba81a32459265d94f54a06ab6af
```

The known material is domain-separated from the retained A185 result through
SHAKE256 label:

```text
f8-causal:A186:chacha20:r5-direction:known-material:d87aefa46f4b85a71ab9fd2199401975075beb0fedf1545b9dc63842126c31e0
```

The 44 derived bytes reproduce the upper 24 bits of key word 1, key words 2
through 7, counter, and nonce exactly. Their digest is:

```text
66e2279235428a619bb591c98a489e938492ba9fda0c7510e6c5b6f5f71695c3
```

The unknown 40-bit assignment is generated once from operating-system
cryptographic randomness, used only to construct the public target, and
discarded before the protocol is frozen. No assignment, key word 0, or low-byte
value is present in the protocol or runner. The runner receives only the public
target and known material; no assignment is available before execution.

The factual target block digest is:

```text
ebc68b4c3bc69c78008fa4d4f6f7aae92df8b3d5ac0aa4b466f2e5f29287bb9e
```

The control differs only in bit zero of output word zero and has digest:

```text
a4cd7424412a4c089b04c199e20e5f25ea938ddc2b7f2fae1b08976486279ed8
```

## Fixed six-view formula plan

The canonical execution-plan digest is:

```text
8cdf3acf3400f8157f198ca6e6c2474b666214cb5d4cc527b1f513f56bc4aaa6
```

Each view is a semantically matched QF_BV formula over `k0` and `lo8`, using a
shared `define-fun` DAG and complete 512-bit target constraints. Every possible
round-5 midstate cut is included:

| View | Formula bytes | Formula SHA-256 |
|---|---:|---|
| `forward` | 10,697 | `a7a126526b7b9057140b93f3d0d76abdcef18da75c68f511ab748ef6d1759425` |
| `inverse` | 10,970 | `ffb6d50d8c8bd0a8c4e32cc362c80555e06606fc7703781af9ccaef65cca965b` |
| `split1` | 11,002 | `c94d7ed88246f513f0959e3daf9ea63086d7e7885648e10b44132a21ba27131b` |
| `split2` | 11,001 | `7f283e14684112e374277b23e7251a2bc15b81d9e359b52e66996bf6c5319696` |
| `split3` | 11,001 | `488669f69e1a97014c06860164ecde3000e5dccc463fd4edaf1a57b7ef0d19d5` |
| `split4` | 10,997 | `0a81b5b4cc506e6673fd0aaff8c4f97d649e5ab0093fe6a4a86ea7a5aecb201a` |

The canonical digest of the ordered formula plan is:

```text
527f2ad85ff45bbb01c81a1d21169b430cf3b9cf33a304f43d5e25dcbaa18a39
```

The non-production regression gate regenerates all six formulas and verifies
their byte lengths and hashes exactly without invoking Z3.

## Exact retained status and statistics vector

Every process returns Z3 status `unknown` under its 30,000-millisecond internal
budget. None reaches the 40-second external process guard. The complete
retained statistics are:

| View | rlimit | conflicts | decisions | prop-2ary | prop-nary | restarts |
|---|---:|---:|---:|---:|---:|---:|
| `forward` | 277,184,707 | 148,831 | 277,384 | 47,863,530 | 236,079,471 | 25,538 |
| `inverse` | 293,423,035 | 213,393 | 339,134 | 62,342,265 | 247,886,684 | 18,085 |
| `split1` | 289,219,054 | 321,871 | 478,512 | 62,405,354 | 241,814,902 | 29,776 |
| `split2` | 246,217,947 | 384,814 | 523,857 | 59,782,844 | 202,787,782 | 24,321 |
| `split3` | 256,839,505 | 352,108 | 622,087 | 41,617,794 | 231,588,109 | 30,375 |
| `split4` | 285,053,744 | 176,623 | 322,736 | 48,303,987 | 250,504,206 | 32,833 |

The complete execution digest, including ordered formulas, statuses, output
fingerprints, statistics, empty models, and boundary flags, is:

```text
359e561926016b3dc3bdd12043c718e65b4a9aab37caa36ed3834c7c773964b5
```

There is no early stop: all four split views execute after both predicted early
splits return `unknown`. The fixed order is preserved through `split4`.

## Empty confirmation boundary

Because all six views return `unknown`, the retained confirmation list is
empty. Its canonical SHA-256 is:

```text
4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945
```

No assignment is exposed or inferred from an `unknown` result. The empty model
and confirmation fields are part of the hash-pinned boundary artifact.

## Causal Reader chain

The retained Causal artifact contains five explicit provenance-linked edges:

1. the hash-pinned A185 round-4 directional-transfer anchor;
2. the fresh prospectively frozen A186 round-5 challenge;
3. the exact six-view formula plan;
4. complete fixed-order, fixed-budget execution;
5. the empty independent-confirmation boundary.

`CryptoCausalReader` verifies:

- result JSON:
  `c47722b6110bfdac9b4688454235339cdb7f297011b1e6c7f959a0c947e4a953`;
- Causal artifact:
  `043f2b52fd13ca8298f713e374edd1aaa720c7748daf0a4b6c39453b32dff62a`;
- canonical Causal graph:
  `41afa2b30a1eec3d2a96719ce919e802a63d83fd904e6752663acb97e7f02ab8`;
- A185 result anchor:
  `d87aefa46f4b85a71ab9fd2199401975075beb0fedf1545b9dc63842126c31e0`;
- A185 Causal anchor:
  `ea490a5ea59838faacddfc11ca80390e6cb87ff35943eb1e294cd1006f1e77ac`.

## Reproduction

The default retained-result verification performs protocol, public derivation,
secret-absence structure, exact six-formula generation, full status/statistics
comparison, empty-confirmation digest, and Causal Reader gates without invoking
Z3:

```bash
PYTHONPATH=.:src .venv/bin/python \
  research/experiments/chacha20_smt_directional_round5_transfer.py \
  --analyze-only

PYTHONPATH=.:src .venv/bin/pytest -q \
  tests/test_chacha20_smt_directional_round5_transfer.py
```

An explicit fresh six-view solver execution is:

```bash
PYTHONPATH=.:src .venv/bin/python \
  research/experiments/chacha20_smt_directional_round5_transfer.py \
  --z3 z3
```

The solver command is production work and is not part of the fast retained-
artifact integration gate.

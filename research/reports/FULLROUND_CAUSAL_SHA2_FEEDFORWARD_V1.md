# SHA-2 Full-Compression Feed-Forward Causal Result v1

## Result

SHA-256 and SHA-512 both retain the prediction-first full-compression
feed-forward mechanism.  The measured boundary is the working state after all
64/80 compression steps versus the chaining-state update:

```text
H_out[i] = H_in[i] + W_final[i] mod 2^w
D[i]     = H_in[i] xor H_out[i].
```

For every lane, independently of the message, chaining value, step function or
word width,

```text
D[i][0] = W_final[i][0].
```

The eight same-lane bit-0 edges are therefore exact.  They were predicted for
SHA-256 before measurement; SHA-512 was run only after SHA-256 retained the
mechanism.

| configuration | full steps | chaining mode | exact equalities | total same-lane MI | next-lane control MI | per-edge Z range |
|---|---:|---|---:|---:|---:|---:|
| SHA-256 | 64 | fixed standard IV | 40,000/40,000 | 5.544418 | 0.001346 | 3513--7094 |
| SHA-256 | 64 | random chaining words | 40,000/40,000 | 5.543511 | 0.000715 | 3556--15085 |
| SHA-512 | 80 | fixed standard IV | 40,000/40,000 | 5.544204 | 0.000423 | 2685--13101 |
| SHA-512 | 80 | random chaining words | 40,000/40,000 | 5.544630 | 0.000890 | 1913--9079 |

The information-theoretic target is `8 ln(2) = 5.545177`.  Every same-lane
edge exceeds every one of sixteen shared BvN repair routes in both chaining
modes.  Each Reader graph contains exactly the eight predicted edges.

## Correctness gates

The instrumented vectorized cores import all 64 SHA-256 and 80 SHA-512 round
constants directly from the vendored PQClean C implementation.  Before any
measurement they reproduce fixed standard digests and Python's independent
`hashlib` output for both the empty message and `abc`.

The random-chaining mode starts every sampled compression from eight fresh
random words.  Its 80,000 exact equalities per variant show that the result is
not an artifact of the published SHA-2 IV.

## Full-word carry theorem

The bit-0 hit exposes the complete modular-addition spectrum.  For word
`C = H_in[i]`, working word `W = W_final[i]`, and bit `j`,

```text
D[j] = W[j] xor carry_j(W mod 2^j, C mod 2^j).
```

If `W` is uniform, the incoming carry is a binary channel with crossover

```text
p_j = (C mod 2^j) / 2^j,
I(W[j]; D[j]) = ln(2) - h_2(p_j).
```

This yields a parameter-free three-part prediction for each fixed IV word:

1. bits `0 .. v2(C)` have no possible incoming carry and are exact `ln(2)`
   edges;
2. bit `v2(C)+1` has `p=1/2` and zero population MI under a uniform working
   word;
3. every higher bit follows the biased-carry formula.

The complete diagonal spectra match:

| configuration | exact no-carry cells | balanced carry zeros | biased carry cells | exact conditional identities | ideal/observed Pearson r | RMSE |
|---|---:|---:|---:|---:|---:|---:|
| SHA-256 | 12 | 8 | 236 | 1,280,000/1,280,000 | 0.999597 | 0.006119 |
| SHA-512 | 11 | 8 | 493 | 2,560,000/2,560,000 | 0.999492 | 0.006398 |

Every exact no-carry cell is within `0.002` nats of `ln(2)` and exceeds all
BvN routes.  The minimal fixed-IV causal graphs serialize only those
structurally exact cells: twelve for SHA-256 and eleven for SHA-512.  The full
biased spectrum remains in JSON rather than bloating the Reader graph with
hundreds of derived edges.

This is the same carry-channel mechanism at two word widths, with the IV's
2-adic valuation determining the extra perfect cells.  It converts a single
bit-0 observation into a complete, quantitatively predicted full-word profile.

## Reproduction

```bash
PYTHONPATH=.:src .venv/bin/python \
  research/experiments/sha2_fullround_feedforward_causal.py \
  --variant sha256 \
  --output research/results/v1/sha256_fullround_feedforward_causal_v1.json \
  --causal-output research/results/v1/sha256_fullround_feedforward_causal_v1.causal

PYTHONPATH=.:src .venv/bin/python \
  research/experiments/sha2_fullround_feedforward_causal.py \
  --variant sha512 \
  --output research/results/v1/sha512_fullround_feedforward_causal_v1.json \
  --causal-output research/results/v1/sha512_fullround_feedforward_causal_v1.causal

PYTHONPATH=.:src .venv/bin/python \
  research/experiments/sha2_feedforward_carry_spectrum.py \
  --variant sha256 \
  --output research/results/v1/sha256_feedforward_carry_spectrum_v1.json \
  --causal-output research/results/v1/sha256_feedforward_carry_spectrum_v1.causal

PYTHONPATH=.:src .venv/bin/python \
  research/experiments/sha2_feedforward_carry_spectrum.py \
  --variant sha512 \
  --output research/results/v1/sha512_feedforward_carry_spectrum_v1.json \
  --causal-output research/results/v1/sha512_feedforward_carry_spectrum_v1.causal

PYTHONPATH=.:src .venv/bin/pytest -q tests/test_sha2_fullround_feedforward.py
PYTHONPATH=.:src .venv/bin/python scripts/validate_causal_artifacts.py
```

## Artifact hashes

- SHA-256 full-compression JSON:
  `fd49ef8de93fd2fd2ad46b50d5b84e05c6125ba394b9cc71406ed0c3bf5988b1`
- SHA-256 eight-edge `.causal`:
  `b456f8df24f23769a3e2b0528ad416cab0966f5c032f70ceb3553e1ec35777b7`
- SHA-512 full-compression JSON:
  `fc71b2654f5271315e91f3b6cc561bece1de5193c462ce1903d32b3dfaab5f73`
- SHA-512 eight-edge `.causal`:
  `831153df0c4cdbc5c4f3e58b9d18e866573a678242bdb0f4c4f86997212e2473`
- SHA-256 carry-spectrum JSON:
  `e9a8ce6e74e2b7581d3817dbad29c913f21cb1f045ac38bc3032c0941519ddaf`
- SHA-256 twelve-edge `.causal`:
  `ee2dab364c77450910abd1093077ea0205141960c0827703498926b5acb5cd6b`
- SHA-512 carry-spectrum JSON:
  `2e496337dd75aa7996e71ba2cf06f5ebf6a5ab962e7d90d9e311d22f11ed0777`
- SHA-512 eleven-edge `.causal`:
  `20687d765e6b3eb8d38ca2cbc65b001bc1aa63f9ca2105d011cb18a5389d7f65`

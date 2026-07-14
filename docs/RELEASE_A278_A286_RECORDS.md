# A278--A286 and new complete-domain records

This release extends the executable archive with four completed result chains:

1. A278--A281 transfers the frozen ChaCha20-R20 Reader across independently
   derived public material. A281 recovers low20 `0xbf9f3` at frozen rank 37
   after 36 exact-UNSAT cells. It executes 151,552 of 1,048,576 logical
   assignments (14.453125%), confirms all eight blocks through two independent
   implementations, and rejects the one-bit control.
2. A282--A286 repeats that design on four fresh public-material targets. A286
   independently recomputes all 16,384 output bits with a third direct
   RFC-style implementation and rejects all four controls. The discovery modes
   are `fallback`, `top128`, `top128`, and `global`; applicable frozen-order
   ranks are 254, 55, and 107. No target label is used and no target executes a
   complete residual-domain enumeration.
3. P128R1 executes every assignment in a `2^38` PRESENT-128 residual domain,
   including all 31 rounds and K32 whitening. It returns one factual assignment
   (`198790436326`), zero control assignments, and the full key
   `0ad8100fd09c280e4ef73eee48d555e6`.
4. AES256R1 executes every assignment in a `2^41` AES-256 residual domain
   through all 14 FIPS 197 rounds. It returns one factual assignment
   (`534703724815`), zero control assignments, and the full key
   `d9112d122cf54d9d03fda18db88bd78624056578beb89ae355dc1c7c7ed3590f`.

## Primary immutable anchors

| Object | SHA-256 |
|---|---|
| A278 frozen master | `256504ef394fbc4d5e1da2881f3de0c8a32af5908f454e58cf9711da733551b6` |
| A279 target | `a2685c03c3fb486c25362e5e7ae99a001ae14b36a7d96595b0f66628c52b0b16` |
| A280 order result | `7fec4631110d07195386d32d4378195ba6b9b51a70eb19364d31dd718137ddf8` |
| A281 recovery result | `0083e7e476844086b2ea58d6f490d0ab61cb9a7193371525aeac5252c12f1b05` |
| A281 canonical result | `989ef033b1380da7c3fc87c4fd8254fa4edcc2527c9bad7a531245822561de27` |
| A281 canonical Causal | `dffa65f2138cb0f78aa85078650eda5cba3756c09d93b5de48bc4bf618f3f059` |
| A282 panel master | `79a7c1527dfa91aa623ebb26df563883be457b81ea9b9d1b6731f5950f22b4ef` |
| A283 target ledger | `9077cf5c3f32500a87f08ac525466804fdfcb09d02feebc9b8660d8a6460b45c` |
| A284 order ledger | `41ea2494a75ad3f2dd49ca43e408b03580fdf498d935bfc03dedf3b5c1d8c1d3` |
| A285 recovery-protocol ledger | `8ec1971642f617f0fa85ef6800fdfacaaa7019f9acb66f7b22c8f51ccc223180` |
| A286 root confirmation | `c171c61c1ce90c9e19faa06784205a7c9a24c2ddcb58db5ba74ecd00f1e32464` |
| A286 authentic Causal | `4c8ac373485a5f8f8db91f3d555ec041dad917182e101fd8833ec346683ade0b` |
| PRESENT-128 W38 result | `4a7935c561784f735d9519b2404faba69e1baf0069e11b78d3f67a60fceba121` |
| PRESENT-128 W38 Causal | `7af833da6c2f9c361dfc2844ae424665d29b90682ddec3614de8c542c52bdd81` |
| AES-256 W41 result | `51b9d4c476d03acf92894f1cb259a59538fef14afebb2bdb6cd4b403556f60b3` |
| AES-256 W41 manifest | `dbb30b8a81d2bf2864f707d8628751f937a35d1cdaebd6f710c3d12a9904eec9` |
| AES-256 W41 Causal | `85643fd518638abfe74adc0dfc3c5cbfc250a2d3429ae4c065d3fcb2fc264be0` |

Every file in this release is bound by
`research/results/v1/A278_A286_RECORDS_SHA256SUMS`. The manifest includes the
frozen configs, exact order measurements, original and canonical result files,
all Causal graphs, experiment sources, independent references, reports, and
focused tests.

## A285/A286 aggregate correction

The A285 batch gate exited only because its requested nine-byte API id exceeded
the Causal format's eight-byte header field. A286 retains that diagnostic and
emits the aggregate with API id `a286pan`. The four target results, assignments,
controls, canonical graphs, and independent confirmations are unchanged.

## Reproduce the evidence tier

```bash
./scripts/reproduce_a278_a286_records.sh
```

The command verifies every release hash, runs the focused portable tests,
recomputes all new retained outputs, and opens every committed Causal graph with
the authoritative Reader. It does not rerun the multi-hour Metal domains or the
production solver searches.

## Claim boundary

P128R1 and AES256R1 are complete-domain residual-key recoveries in their frozen
known-key models. A281/A286 are target-blind strict-subset residual-key
recoveries for standard ChaCha20 with all 20 rounds plus feed-forward, 20
unknown key bits, 236 known key bits, and eight public output blocks per target.
They are not relabeled as all-bits-unknown full-key recovery.

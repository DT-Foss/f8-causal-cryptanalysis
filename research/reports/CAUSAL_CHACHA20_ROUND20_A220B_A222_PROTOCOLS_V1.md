# A220B/A222 pre-outcome protocol infrastructure

This record publishes two mechanisms frozen before any A220 holdout outcome
or A222 solver execution. It is an infrastructure and prior-art disclosure,
not a scientific result for either protocol.

## A220B: deterministic factorial-boundary localization

A220B accepts only the frozen A220 Reader's selection-panel reference, the
four predeclared holdout-panel mean log2 ranks, and the unchanged registered
retention Boolean. It computes exact two-factor contrasts for prefix novelty,
suffix novelty, their interaction, fit-to-selection shift, and the absolute
capacity gap. Exact ties follow a committed priority order. The resulting
driver deterministically selects one next probe; it cannot alter A220's Reader,
threshold, retention rule, or significance statement.

The router emits canonical JSON, a report, and a `.causal` graph reopened by
`CryptoCausalReader`. Its artifact commit is reconstructive and idempotent.
No raw solver trajectory, target label, model, secret, or A220 production
measurement is accepted by the pure localization core.

## A222: fixed eight-block equal-weight Reader ensemble

A222 applies the same byte-frozen A220 Reader and the same selected two- or
four-run bundle independently to counter blocks 0 through 7. Each 256-prefix
score vector is converted to centered within-block score ranks; the eight
vectors are then averaged with exactly equal weight. All blocks are mandatory.
Block selection, dropping, outcome weighting, retries, budget changes, Reader
refitting, and reselection are forbidden.

The pre-execution known-key ledger contains exactly 32 keys arranged as eight
prefix clusters by four suffix replicates. It is disjoint from A214,
A218/A219, and all 144 A220 keys; its prefix and suffix levels are also
disjoint from A220. Every one of the 20 low-key bits is balanced at 16 zeros
and 16 ones. The paired comparison uses the same keys, run set, and budgets in
both arms. Its primary null enumerates all `2^8 = 256` prefix-cluster sign
flips, including the identity. Retention requires both one-sided exact
`p <= 0.05` and a strictly negative mean log2-rank delta.

The Reader-facing core recursively rejects reveal, label, secret, target, and
nonempty model fields; it reduces every accepted run to the minimal projected
channels before scoring. Every block binds its embedded block index, counter,
public challenge, target block, launch, measurement, and projected-run hashes.

## Reproduction

```bash
PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 PYTHONWARNINGS=error \
  .venv/bin/python -m pytest -q \
  tests/test_factorial_boundary.py \
  tests/test_chacha20_round20_factorial_boundary_route.py \
  tests/test_factorial_target.py \
  tests/test_chacha20_round20_factorial_eight_block_key_design.py

.venv/bin/python scripts/verify_hash_manifest.py \
  research/results/v1/A220B_A222_INFRA_SHA256SUMS
```

The focused suite contains exactly 100 tests. These commands validate only
protocol logic, information boundaries, serialization, Reader gates, ledger
identity, and exact null construction. They do not read or launch an A220
production collection, an A220 outcome, a prospective target, or an A222
solver process.

## Claim boundary

No A220 retention or boundary outcome is disclosed here. No A222 rank
improvement, p-value, key recovery, or target result is claimed. A220B and
A222 become scientific evidence only after their separately frozen inputs and
execution gates are completed without changing these protocols.

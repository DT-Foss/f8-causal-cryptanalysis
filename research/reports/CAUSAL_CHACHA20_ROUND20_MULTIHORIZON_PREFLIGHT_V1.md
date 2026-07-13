# ChaCha20-R20 Multi-Horizon Trajectory Preflight (A220P)

**Evidence stage:** `FULLROUND_R20_MULTIHORIZON_KNOWNKEY_CALIBRATION_PREFLIGHT`

A220P isolates two solver interventions on one explicit known-key ChaCha20-R20
instance: complete 256-cell traversal order and solve-boundary schedule. It runs
six order directions under staged retained re-solve `[8,16,32,64]` and one-shot
`[64]`, always in fresh processes and without model selection or prospective
target access.

## Completed execution

- 6 directions x 2 schedules = 12 fresh solver processes
- 3,072 complete prefix cells
- 7,680 parsed solve stages
- 256 `UNKNOWN`, 0 `SAT`, 0 `UNSAT` in every run
- 0 watchdogs and 0 parser, mapping, continuity, or identity failures
- all 7,680 model fields empty
- maximum concurrency: two processes
- no outcome-dependent order, schedule, budget, or early-stop change

The staged semantics are retained re-solve: the same CaDiCaL instance and cell
assumptions are reused across four successive solve calls. It is not one
uninterrupted solve.

## Predeclared staged-versus-one-shot result

Pearson `r` is computed on the declared log/signed-log channel transform;
Spearman `rho` is Pearson on average-tie ranks.

| Direction | Decisions `r / rho` | Propagations `r / rho` | Redundant clauses `r / rho` |
|---|---:|---:|---:|
| Numeric forward | .729 / .212 | .050 / .051 | .061 / -.038 |
| Numeric reverse | .691 / .252 | .015 / .134 | .057 / -.037 |
| Gray forward | .464 / -.048 | -.022 / -.156 | .044 / -.030 |
| Gray reverse | .599 / .471 | .106 / .191 | .057 / .105 |
| Formula forward | .568 / .317 | .258 / .317 | -.008 / -.072 |
| Formula reverse | .429 / .020 | .159 / .262 | .039 / .154 |

The schedule changes the trajectory rather than rescaling it. Across the six
directions, only 0--4 Decision cells, zero Propagation cells, and 7--16
Redundant-Clause cells are byte-identical between staged and one-shot.

## Directional path dependence

The post-run same-prefix forward/reverse audit provides a separate mechanistic
breadcrumb. Under the same geometry and schedule, the ranges across all six
comparisons are:

- Conflicts Pearson: `.033 .. .198`
- Decisions Pearson: `.016 .. .223`
- Propagations Pearson: `-.134 .. .034`

Gray and Formula are exact same-anchor cycle reversals. Numeric reverse remains
the declared wrap-edge-substitution stress control, not a pure edge-matched
reversal. Direction therefore remains a separate A220 treatment and is not
averaged away.

## Channel interpretation

Across all directions:

- Decisions, Propagations, and `redundant_clauses_delta` are dense trajectory
  channels and become A220's eligible Reader inputs.
- Conflicts remains a budget-control channel: staged ranges `64..90`, one-shot
  `64..71`.
- `active_variables_delta` and `irredundant_clauses_delta` are zero in about
  96.4% of cells. They remain recorded mechanistic event channels but are not
  eligible continuous Reader inputs.

No preferred direction, schedule, channel sign, or correct-cell rule is
selected from this one known key.

## Provenance and information boundary

- Result SHA-256: `f5cc99ac3dcf679023e1a32b91b5dae26d94837db08673f23f0f5cb787afd946`
- Measurement SHA-256: `a43f530b72dad576db5623e3c23f8c3dcb3ce666c4159b29d74c9bb7294cfdc7`
- Protocol SHA-256: `a1f544800f0f2349d6a74ceca041e212a624e74b5a0ade3975e233571eb3e474`
- Started/finished/current orchestrator SHA-256:
  `736ae35e30bf66683ccb3ca3f5f0bec77c75ef0824db0e438123879302aa0c98`
- Native helper SHA-256:
  `a0a046229769e0f99655c94a4ceffc395adb2ba0ecb02a19b1b0f68da715cc71`

The A220P result itself loads no prospective A220 target, secret, salt, rank,
or model. Its setup inherited a historical provenance call through
`r20.analyze()`. This does not affect the explicit known-key calibration, but
the A220 main protocol removes that transitive history path completely through
`chacha20_round20_public_core.py`. The new adapter reads no result or Causal
artifact, passes the RFC 8439 block vector, and reproduces the fixed symbolic
R20 topology from protocol-embedded public material.

## A220 consequence

A220 treats geometry, direction, and schedule as interventions. The frozen
fit/select collection executes 52 factorial keys under all twelve trajectories,
selects among six atomic and three dual-schedule direction-pair Readers, freezes
the Reader, and then evaluates 92 untouched keys. Its primary panel is the
20-key `confirm x confirm` grid with the complete 120 whole-prefix-cluster
permutation null.

## Reproduction

```bash
PYTHONWARNINGS=error PYTHONPATH=src .venv/bin/python \
  research/experiments/chacha20_round20_multihorizon_preflight.py

PYTHONWARNINGS=error PYTHONPATH=src .venv/bin/pytest -q \
  tests/test_chacha20_round20_multihorizon_preflight.py \
  tests/test_chacha20_retained_multihorizon.py \
  tests/test_chacha20_round20_symbolic_template.py \
  tests/test_chacha20_round20_public_core.py
```

The completed artifact is
`research/results/v1/chacha20_round20_multihorizon_preflight_v1.json`.

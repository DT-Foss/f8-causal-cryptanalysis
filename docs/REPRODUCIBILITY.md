# Reproducibility

## Supported environments

The reference publication was validated on Apple Silicon/macOS with Python
3.13, NumPy 1.26.4, SciPy 1.17.1, Apple Clang, and the native POSIX threading
path. The Python package supports Python 3.10 or newer. CI exercises Linux with
GCC/Clang-compatible C11 and the pinned Python dependencies.

A181--A184 additionally retain the complete Swift 6 host and runtime-compiled
Metal shader. Their native gates require macOS, `swiftc`, a Metal-capable Apple
Silicon device, and execute with `-warnings-as-errors`. Linux CI runs every
portable hash, retained-result, Causal Reader and analysis gate and skips only
tests that instantiate the real Swift/Metal host.

The native SHAKE Reader requires:

- a C11 compiler available as `cc`, `clang`, or `gcc`;
- POSIX threads;
- a 64-bit target;
- no platform-specific vector intrinsic.

A179's retained production build uses strict C11 with the compiler vector
extension. GCC diagnoses its nested-array qualification as a pre-C2x pedantic
error and requires an explicit 256-bit vector ABI, so the portable builder
falls back to `-std=c2x -mavx2` while retaining the strict warning gate
(`-Wall`, `-Wextra`, `-Wpedantic`, and `-Werror`). The frozen C source and its
SHA-256 anchor remain byte-identical.

The Boolean/symbolic SHAKE Readers additionally require the Z3 command-line
solver. Retained solver statistics were produced with Z3 4.15.4; the
paper-scale solver runner checks that exact version before execution.

## Clean installation

```bash
git clone https://github.com/DT-Foss/f8-causal-cryptanalysis.git
cd f8-causal-cryptanalysis
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
python -m pip install -e .
# Required only for the symbolic solver tiers; this wheel also provides `z3`.
python -m pip install z3-solver==4.15.4.0
z3 -version
```

`requirements.txt` pins the direct research environment. `pyproject.toml`
retains broader package bounds for integration. The installed import and CLI
remain `arx_carry_leak` / `arx-f8` to preserve artifact and script
compatibility; the publication repository is branded F8-Causal.

## Evidence tiers

### Quick

```bash
./scripts/reproduce_quick.sh
```

This tier is designed for minutes, not a paper-scale rerun. It performs:

- Speck and Threefish vector gates;
- focused F8, CASI, Reader, PRESENT, SHA-2, and native/Boolean-SHAKE tests;
- repository-wide `.causal` Reader validation;
- all retained SHA-256 manifest verifications, including the dedicated
  A211--A220P publication manifest;
- `compileall` over active Python code.

Expected final line: `quick evidence tier: OK`.

### Anchors

```bash
./scripts/verify_anchors.sh
```

This authenticates the committed twelve-configuration F8 snapshot from source
commit `2e23b23e46cd7a413edd5b56a748e4d5e6e62f73` and compiles its Python files.
It deliberately does not spend hours recomputing already established anchors.
To run an individual historical anchor by choice:

```bash
python provenance/fullround_anchors/f8/experiments/present.py
```

Historical scripts write into their snapshot's `results/` directory. Preserve
the committed JSON and write exploratory reruns to a separate worktree or copy.

### Standard full-round transfers

```bash
./scripts/reproduce_fullround_transfers.sh
```

This CPU tier regenerates A107--A126 for PRESENT-128, SHA-2, FEAL-32X,
SHACAL-2, SPARKLE, BLAKE3, ChaCha20, and SHAKE, followed by the A129--A151
SHAKE observability, affine, algebraic, compression, symbolic, partition,
strategy, assignment-free, and minimum-cover frontiers. Retained validation
continues through A210, including the A179 vector-256 replay, A181 Metal replay,
A182--A184 fresh width-36/38/40 Metal recoveries, A185--A203 reduced-round,
partition, formula, and compiler transfers, and the retained A204--A206 exact-
CNF structural sequence. It also verifies the A207 pre-execution order archive,
frozen portfolio, and completed 352-cell result; A208's complete long-budget
phase boundary; A209's complete Width-12 phase-reset composition; and A210's
two complete assumption-incremental covers and native helper toy gates. It then
runs focused tests, opens all `.causal` files, and rewrites
`research/results/v1/FULLROUND_TRANSFER_SHA256SUMS`.

The script creates `.venv` if absent and applies the same exact Z3 4.15.4
preflight as the solver-tier runner. Result JSON and `.causal` filenames are
stable. Compare a deliberate rerun with the committed manifest using:

```bash
python scripts/verify_hash_manifest.py \
  research/results/v1/FULLROUND_TRANSFER_SHA256SUMS
```

The retained A179/A181--A184 evidence can be reopened without launching any
complete-domain execution:

```bash
python research/experiments/chacha20_vector256_fullround_replay.py --analyze-only
python research/experiments/chacha20_metal_fullround_replay.py --analyze-only
python research/experiments/chacha20_metal_width36_partial_key_recovery.py --analyze-only
python research/experiments/chacha20_metal_width38_partial_key_recovery.py --analyze-only
python research/experiments/chacha20_metal_width40_partial_key_recovery.py --analyze-only
```

On Apple Silicon, the focused tests compile the retained Swift source with
warnings as errors, identify the Metal host, and execute the bounded scalar,
boundary-filter and synthetic slice-mapping gates:

```bash
python -m pytest -q \
  tests/test_chacha20_vector256_fullround_replay.py \
  tests/test_chacha20_metal_fullround_replay.py \
  tests/test_chacha20_metal_width36_partial_key_recovery.py \
  tests/test_chacha20_metal_width38_partial_key_recovery.py \
  tests/test_chacha20_metal_width40_partial_key_recovery.py
```

The complete `2^32`, `2^36`, `2^38`, and `2^40` production invocations,
checkpoint semantics, frozen challenge boundaries, and expected hashes are
recorded in the five corresponding reports under `research/reports/`.

The A185 retained-artifact path regenerates and hashes all five SMT formulas,
validates the frozen protocol and secret boundary, replays both independent
512-bit confirmations from the stored SAT models, and opens the exact Causal
graph without invoking Z3:

```bash
PYTHONPATH=.:src python \
  research/experiments/chacha20_smt_directional_round4_transfer.py \
  --analyze-only
PYTHONPATH=.:src python -m pytest -q \
  tests/test_chacha20_smt_directional_round4_transfer.py
```

A186 applies the same retained-artifact policy to all six round-5 formulas,
the complete status/statistics vector, the empty confirmation digest, and its
Causal provenance:

```bash
PYTHONPATH=.:src python \
  research/experiments/chacha20_smt_directional_round5_transfer.py \
  --analyze-only
PYTHONPATH=.:src python -m pytest -q \
  tests/test_chacha20_smt_directional_round5_transfer.py
```

A187--A189 reconstruct and hash all 26 predeclared formula streams, validate
the exact status/statistics vectors, replay the A188/A189 independent
confirmations and control rejections, open all three Causal chains, and render
all three deterministic SVGs byte-for-byte. These commands launch no solver:

```bash
PYTHONPATH=.:src python \
  research/experiments/chacha20_smt_shared_key_multiblock_transfer.py \
  --analyze-only
PYTHONPATH=.:src python \
  research/experiments/chacha20_bitwuzla_round5_transfer.py \
  --analyze-only
PYTHONPATH=.:src python \
  research/experiments/chacha20_bitwuzla_round6_width20_transfer.py \
  --analyze-only
PYTHONPATH=.:src python \
  research/experiments/chacha20_smt_round5_retained_figures.py --check
PYTHONPATH=.:src python -m pytest -q \
  tests/test_chacha20_smt_shared_key_multiblock_transfer.py \
  tests/test_chacha20_bitwuzla_round5_transfer.py \
  tests/test_chacha20_bitwuzla_round6_width20_transfer.py \
  tests/test_chacha20_smt_round5_retained_figures.py
```

A190--A203 retain the complete ChaCha7--10 partition progression, public
formula/operator transfers, and deterministic figures. A204--A206 add exact
DIMACS/literal-map, structural-order, and complete transfer evidence. A207's
tests open all 12 archived permutations, the frozen 11-mode plan, all 352
stored observations, the combined 416-cell boundary, the progress map, and the
final Causal graph. A208 and A209 additionally reopen the complete 32-cell
long-budget and 256-cell Width-12 results, verify their exact phase metrics,
and read both Causal graphs. A210 verifies its complete 512-cell result, exact
Numeric/Gray metric comparison, Causal graph, native source/toolchain hashes,
atomic parser gates, and two Round-10-independent toy CNFs. The following gate
launches no production Round-10 solver; the A210 test compiles the helper and
executes only its tiny toy fixtures:

```bash
PYTHONPATH=.:src python -m pytest -q \
  tests/test_chacha20_bitwuzla_round7_width18_transfer.py \
  tests/test_chacha20_bitwuzla_round7_partition_transfer.py \
  tests/test_chacha20_bitwuzla_round7_width20_partition_transfer.py \
  tests/test_chacha20_bitwuzla_round8_width20_partition_transfer.py \
  tests/test_chacha20_bitwuzla_round9_width20_partition_transfer.py \
  tests/test_chacha20_bitwuzla_round10_width20_partition_transfer.py \
  tests/test_chacha20_bitwuzla_round10_split9_transfer.py \
  tests/test_chacha20_bitwuzla_round10_width12_refinement.py \
  tests/test_chacha20_bitwuzla_round10_b8_partition_transfer.py \
  tests/test_chacha20_formula_operator_atlas.py \
  tests/test_chacha20_round10_public_geometry_partition.py \
  tests/test_chacha20_phase_conjugacy_holdout.py \
  tests/test_chacha20_round10_b8_global_cse.py \
  tests/test_chacha20_round10_b8_lane_major.py \
  tests/test_chacha20_round10_external_cnf_reverse.py \
  tests/test_chacha20_a188_cnf_structural_ordering.py \
  tests/test_chacha20_round10_bidirectional_min_distance.py \
  tests/test_chacha20_round10_structural_order_archive.py \
  tests/test_chacha20_round10_structural_portfolio.py \
  tests/test_chacha20_round10_structural_portfolio_result.py \
  tests/test_chacha20_round10_bfs_far_long_budget.py \
  tests/test_chacha20_round10_bfs_far_width12_refinement.py \
  tests/test_chacha20_round10_incremental_sibling_learning.py \
  tests/test_chacha20_cnf_structural_figures.py
PYTHONPATH=.:src python \
  research/experiments/chacha20_smt_round5_retained_figures.py --check
PYTHONPATH=.:src python \
  research/experiments/chacha20_formula_operator_atlas_figure.py --check
PYTHONPATH=.:src python \
  research/experiments/chacha20_round10_public_geometry_partition_figure.py --check
PYTHONPATH=.:src python \
  research/experiments/chacha20_phase_conjugacy_holdout_figure.py --check
PYTHONPATH=.:src python \
  research/experiments/chacha20_round10_b8_global_cse_figure.py --check
PYTHONPATH=.:src python \
  research/experiments/chacha20_round10_b8_lane_major_figure.py --check
PYTHONPATH=.:src python \
  research/experiments/chacha20_cnf_structural_figures.py --check
```

The source-first formula-atlas coverage rebuild additionally requires the two
hash-gated sibling JSON files documented in
`research/reproduction/EXTERNAL_DEPENDENCIES.md`. A clean clone without those
source pages can still verify the committed coverage JSON through the transfer
manifest; the standard runner skips only that source rebuild when the two
external files are absent.

Explicit production portfolio executions remain separate. A188--A203 fail
closed unless the applicable Bitwuzla 0.9.1, Z3 4.15.4, and Boolector 3.2.4
identities match. A204--A210 additionally gate the applicable CaDiCaL 3.0.0,
Kissat 4.0.4, CryptoMiniSat 5.14.7, and MiniSat 2.2.1 identities. On macOS,
`brew bundle` installs the standalone-CNF CLI set; the pinned `z3-solver` wheel
supplies exact Z3 4.15.4. A210 additionally requires a C++17 compiler and the
CaDiCaL 3.0.0 header/static library for native-helper compilation. Exact
executable and library digests are in
`research/reproduction/EXTERNAL_DEPENDENCIES.md`.

### Extended native SHAKE

```bash
./scripts/reproduce_shake_native_extended.sh
```

This enumerates the complete 32-coordinate assignment space for SHAKE128 and
SHAKE256: `2^32` candidates per variant. The C11 kernel packs 64 assignments
per machine word, uses ten worker threads by default, and streams bounded
chunks. Progress is checkpointed to
`research/results/v1/shake_native_window32_solver_v1.checkpoint.json`; restart
the same command to resume.

Successful completion writes:

- `shake_native_window32_solver_v1.json`;
- `shake_native_window32_solver_v1.causal`;
- `SHAKE_NATIVE_EXTENDED_SHA256SUMS`.

Expected unique assignments are `3,384,693,180` for SHAKE128 and `153,225,470`
for SHAKE256. Each independent target must have zero survivors.

### Exact SHAKE solver frontier

```bash
./scripts/reproduce_shake_solver_frontier.sh
```

This tier regenerates A128--A151: the exact 24-round SHAKE128 Tseitin-CNF
Reader at 4/8/12/16 coordinates, one complete `2^16` SHAKE128/256
prefix-observability truth space per variant, and the corresponding exact
128-coordinate affine-hull prefix Readers, restricted ANFs, and Boolean
influence frontiers. It then executes shared-ANF compression, the direct
symbolic R2 compiler, the native-XOR R2 Reader, the exhaustive width-16
partition Reader, the R1/R2/R3 split frontier, and the monolithic R1 scaling
Reader. It then executes three complete width-20 SHAKE128 R1 partition plans,
the monolithic SHAKE256 R1 transfer at widths 16/20/24, the Structural-6 and
Z3 strategy frontiers, the assignment-free width-20 `k=8` Reader, and the
width-24 depth/minimum-cover Readers.
The CNF production run requires the native Z3 CLI 4.15.4; focused tests skip
the Z3-dependent execution gate when no CLI is installed, while the
reproduction script fails closed. It writes:

- `shake_boolean_cnf_reader_v1.json` and `.causal`;
- `shake_prefix_observability_frontier_v1.json` and `.causal`;
- `shake_affine_hull_frontier_v1.json` and `.causal`;
- `shake_algebraic_degree_frontier_v1.json` and `.causal`;
- `shake_boolean_influence_frontier_v1.json` and `.causal`;
- `shake_anf_compression_cascade_v1.json`, `.causal`, and
  `shake_anf_dictionary_v1.anfpack`;
- `shake_symbolic_anf_frontier_v1.json` and `.causal`;
- `shake_symbolic_r2_smt_reader_v1.json` and `.causal`;
- `shake_symbolic_r2_partition_reader_v1.json` and `.causal`;
- `shake_symbolic_split_frontier_v1.json` and `.causal`;
- `shake_symbolic_r1_scaling_reader_v1.json` and `.causal`;
- `shake_symbolic_r1_partition_scaling_reader_v1.json` and `.causal`;
- `shake_symbolic_r1_upper_partition_reader_v1.json` and `.causal`;
- `shake_symbolic_r1_structural_partition_reader_v1.json` and `.causal`;
- `shake256_symbolic_r1_scaling_reader_v1.json` and `.causal`;
- `shake_symbolic_r1_structural6_partition_reader_v1.json` and `.causal`;
- `shake_symbolic_r1_z3_strategy_frontier_v1.json` and `.causal`;
- `shake_symbolic_r1_structural_depth_frontier_v1.json` and `.causal`;
- `shake_symbolic_r1_z3_structural6_partition_reader_v1.json` and `.causal`;
- `shake_symbolic_r1_structural_k8_reader_v1.json` and `.causal`;
- `shake_symbolic_r1_width24_depth_frontier_v1.json` and `.causal`;
- `shake_symbolic_r1_width24_vertex_cover_reader_v1.json` and `.causal`;
- `SHAKE_SOLVER_FRONTIER_SHA256SUMS`.

The 16-coordinate canonical CNF and symbolic-R2 monolithic instances record
their configured 120-second boundaries. The R1 interface reconstructs the same
unpartitioned width-16 model; widths 20/24 and its blocked-model query record
the next boundary. A139--A141 each execute 16 disjoint width-20 branches and
record all 16 as `unknown` at the retained 60-second/five-worker schedule;
A142 records `unknown` for all three SHAKE256 widths at the retained
120-second/single-thread schedule. A143/A146 retain their complete Structural-6
boundaries; A145 is explicitly posthoc-conditioned. A147 finds a verified
width-20 model from a frozen graph-only schedule. A151 plans all 512 width-24
minimum-cover subspaces with the same 120-second cap and executes 20 before a
complete-wave verified early stop; its design is same-instance, posthoc-informed,
and non-blind even though neither assignment nor target projection is a runtime
input. These stored statuses and results are exact
representation/resource boundaries, not general immunity claims. Complete
truth-space and symbolic-compiler stages are
independent of Z3. The width-512 symbolic compiler is memory-intensive because
it retains exact coordinate-local formulas; the result artifact records the
bounded representation and its independent gates.

## Other reproducible tracks

```bash
./scripts/reproduce_a211_a220p.sh
./scripts/reproduce.sh quick
./scripts/reproduce_causal_mechanisms.sh
./scripts/reproduce_multi_cipher_atlas.sh
./scripts/reproduce_pqc.sh
./scripts/reproduce_research.sh
```

`reproduce_a211_a220p.sh` authenticates the completed A220P result, the current
frozen A220 protocol, the public-only R20 adapter and the completed factorial
Reader core before running the focused retained-evidence suite. It does not
start the A211/R20 production solves or the unfinished A220 collection.

Host-specific paths in retained A211--A219 JSON are replaced by stable role
paths in the publication copy. A220P is the single deliberate exception: its
JSON remains byte-identical at
`f5cc99ac3dcf679023e1a32b91b5dae26d94837db08673f23f0f5cb787afd946`
because the final A220 protocol binds that exact whole-file identity. The
embedded provenance paths are inert in retained-evidence mode, and the
canonical scientific measurement projection is
`a43f530b72dad576db5623e3c23f8c3dcb3ce666c4159b29d74c9bb7294cfdc7`.

The 145 MB A215 raw NumPy measurement archive is intentionally not stored in
Git. Its SHA-256
`882ae2504851f1bac1f2350f8c160dba6cddd5b03afc4eb09f2252fc9b8cb5ff`
remains bound in the protocol, result and report. Tests that require that
archive are explicitly skipped in a fresh public clone; deterministic unit,
result-hash, prereveal, Causal-Reader and A220 protocol gates remain active.

The legacy paper runner is intentionally separate because it replays archived
scripts and may require a Torch-capable interpreter for the recorded neural
comparison:

```bash
TORCH_PYTHON=/path/to/python ./scripts/reproduce_papers.sh
```

## Integrity verification

The portable verifier does not depend on `sha256sum` versus `shasum` naming:

```bash
python scripts/verify_hash_manifest.py \
  provenance/SHA256SUMS \
  research/results/reproduction_v1/SHA256SUMS \
  research/results/v1/ANCHOR_SHA256SUMS \
  research/results/v1/CAUSAL_SHA256SUMS \
  research/results/v1/ATLAS_SHA256SUMS \
  research/results/v1/PQC_SHA256SUMS \
  research/results/v1/FULLROUND_TRANSFER_SHA256SUMS \
  research/results/v1/SHAKE_NATIVE_EXTENDED_SHA256SUMS \
  research/results/v1/SHAKE_SOLVER_FRONTIER_SHA256SUMS \
  research/results/v1/A211_A220P_SHA256SUMS
```

The manifest parser rejects malformed hashes, duplicate entries, missing
files, and paths escaping the repository.

## Full local gate

```bash
python -m pytest -q
python -m compileall -q src research/experiments tests
python scripts/validate_causal_artifacts.py
bash -n scripts/*.sh
git diff --check
```

CI runs the same test/compile/Reader/shell-syntax class without launching
paper-scale or `2^32` enumerations.

## Artifact update rule

Do not hand-edit retained JSON or `.causal` files. Change an experiment or
frozen config, regenerate both artifacts, reopen the graph with the Reader,
run its focused tests, and update the relevant manifest in the same commit.
The report must cite the new full SHA-256 digest.

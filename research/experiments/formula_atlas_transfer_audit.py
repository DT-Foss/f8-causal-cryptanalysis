#!/usr/bin/env python3
"""Build the complete, keyword-independent formula-atlas transfer coverage ledger."""

from __future__ import annotations

import argparse
import hashlib
import json
from collections.abc import Sequence
from pathlib import Path
from typing import Any

SCHEMA = "formula-atlas-transfer-coverage-v1"
ATLAS_SHA256 = "e376fcc1c24f1dbf44689dfbf554f87d727df38ec9181f0b7272d5e5a2ed0378"
SOURCE_PAGES_SHA256 = "8affa048f0bbf3845d6aed1df1e3fb8ac5558f2302f416dbae0acaa382b4533b"
EXPECTED_PAPERS = 9
EXPECTED_PAGES = 113
EXPECTED_ENTRIES = 2_411


PAPER_COVERAGE: dict[str, list[dict[str, Any]]] = {
    "Foss_2026_Collapse_Is_Contraction_Foss_Interpretation-1.pdf": [
        {
            "pages": [1, 2],
            "topics": ["z2_lift", "sum_difference_projection", "birkhoff_contraction"],
        },
        {"pages": [3, 4], "topics": ["phase_boundary", "spectral_gap", "signed_cross_terms"]},
        {
            "pages": [5, 7],
            "topics": ["zeno_schedule", "local_difference_over_sum", "two_timescales"],
        },
        {
            "pages": [8, 10],
            "topics": ["reversal_conditioning", "community_depth", "synthesis_and_references"],
        },
    ],
    "Foss_2026_Constant-Round_Gossip_Consensus_PS-Lifted-2.pdf": [
        {
            "pages": [1, 5],
            "topics": ["fiedler_and_higher_modes", "lifted_flow", "push_sum_invariants"],
        },
        {"pages": [6, 9], "topics": ["topology_router", "aligned_cuts", "partial_participation"]},
        {
            "pages": [10, 13],
            "topics": ["gap_scaling", "noise_regularization", "redundant_channels"],
        },
        {
            "pages": [14, 17],
            "topics": ["incremental_eigenspace", "log_quantization", "residual_conservation"],
        },
        {"pages": [18, 20], "topics": ["distributed_moments", "cusum", "failure_boundaries"]},
        {"pages": [21, 23], "topics": ["synthesis_and_references"]},
    ],
    "Foss_2026_Emergent_Gravity_Biological_Intelligence_Standard_Model_Predictions_Mobius_DS_Lattices-2.pdf": [
        {"pages": [1, 4], "topics": ["mobius_lattice", "bvn_path_action", "convex_amplification"]},
        {"pages": [5, 7], "topics": ["sinkhorn_period", "rapidity_paths", "page_curve"]},
        {"pages": [8, 10], "topics": ["boundary_volume", "eligibility_trace", "memory_smoothing"]},
        {"pages": [11, 13], "topics": ["heat_kernel", "representation_weights", "multiscale_flow"]},
        {
            "pages": [14, 16],
            "topics": ["complement_control", "negative_results", "spectral_triple"],
        },
        {"pages": [17, 18], "topics": ["parameter_sweeps", "synthesis_and_references"]},
    ],
    "Foss_2026_Linear_Cheeger_Improvement_Foss_Gap_Theorem-2.pdf": [
        {
            "pages": [1, 3],
            "topics": ["fiedler_orientation", "directed_conductance", "aligned_cut_flow"],
        },
        {
            "pages": [4, 6],
            "topics": ["spectral_scaling", "bottleneck_controls", "parameter_balance"],
        },
    ],
    "Foss_2026_MarkovChains_to_MinkowskiSpace-2.pdf": [
        {
            "pages": [1, 5],
            "topics": ["mobius_group", "rapidity", "sqrt_semigroup", "functional_equation"],
        },
        {
            "pages": [6, 9],
            "topics": ["eigenvalue_surgery", "cardano_discriminant", "noncommuting_couplings"],
        },
        {
            "pages": [10, 12],
            "topics": ["self_consistent_iteration", "reflection_positivity", "matrix_log"],
        },
        {
            "pages": [13, 15],
            "topics": ["correlation_decay", "finite_size_correction", "poincare_trajectories"],
        },
        {
            "pages": [16, 20],
            "topics": ["complete_inventory", "limitations", "synthesis_and_references"],
        },
    ],
    "Foss_2026_Non-Reversibility_Is_All_You_Need-1.pdf": [
        {"pages": [1, 2], "topics": ["bvn_paths", "spectral_projection", "mobius_composition"]},
        {"pages": [3, 4], "topics": ["spectral_rank_identity", "path_count", "gap_comparison"]},
        {"pages": [5, 6], "topics": ["entropy_round_duality", "kl_budget", "nonreversible_flow"]},
        {"pages": [7, 7], "topics": ["synthesis_and_references"]},
    ],
    "Foss_2026_One_Constant_Rules_All_2D_Spectra-1.pdf": [
        {"pages": [1, 4], "topics": ["nnd_moments", "derivative_roots", "finite_size_rates"]},
        {
            "pages": [5, 6],
            "topics": ["band_sparse_permutation_boundaries", "sinkhorn_flow", "phase_transition"],
        },
        {
            "pages": [7, 8],
            "topics": ["triplet_cumulants", "effective_dimension", "product_inverse_nonclosure"],
        },
        {
            "pages": [9, 10],
            "topics": ["structure_metric", "complete_inventory", "synthesis_and_references"],
        },
    ],
    "Foss_2026_Unitarity_Is_the_Boundary-2.pdf": [
        {
            "pages": [1, 4],
            "topics": ["cross_copy_svd", "detailed_balance_defect", "topological_gap"],
        },
        {"pages": [5, 6], "topics": ["krylov_lanczos", "zeno_schedule", "progress_per_kl"]},
        {
            "pages": [7, 8],
            "topics": ["community_depth", "normalized_cross_copy_entropy", "finite_size_scaling"],
        },
        {"pages": [9, 10], "topics": ["mobius_boundary", "synthesis_and_references"]},
    ],
    "Foss_2026_Universal_Phase_Transition_GOE_Ginibre_Doubly_Stochastic_Matrices.pdf": [
        {
            "pages": [1, 3],
            "topics": ["symmetric_antisymmetric_split", "asymmetry_order_parameter", "sinkhorn"],
        },
        {
            "pages": [4, 6],
            "topics": [
                "finite_size_scaling_collapse",
                "entropy_concentration",
                "critical_frontier",
            ],
        },
        {
            "pages": [7, 9],
            "topics": [
                "permutation_block_band_boundaries",
                "geometry_spectrum_decoupling",
                "mobius_relation",
            ],
        },
    ],
}


TRANSFER_CANDIDATES: list[dict[str, Any]] = [
    {
        "id": "T01",
        "name": "ordered_round_products_and_commutators",
        "priority": 1,
        "source_topics": ["product_inverse_nonclosure", "noncommuting_couplings"],
        "construction": "Form normalized public round/cut operators; measure ordered products, commutators, and adjoint controls rather than isolated operators.",
        "required_invariants": [
            "public_input_only",
            "fixed_operator_normalization",
            "order_reversal_control",
        ],
    },
    {
        "id": "T02",
        "name": "triplet_cumulant_causal_atlas",
        "priority": 1,
        "source_topics": ["triplet_cumulants", "distributed_moments"],
        "construction": "Extend pairwise Causal edges with genuine centered third-order round/cell cumulants and matched shuffled triplets.",
        "required_invariants": [
            "same_marginals_control",
            "multiple_seeds",
            "predeclared_triplet_families",
        ],
    },
    {
        "id": "T03",
        "name": "characteristic_derivative_root_control",
        "priority": 1,
        "source_topics": ["derivative_roots", "nnd_moments"],
        "construction": "Analyze critical points from the derivative of the characteristic polynomial as an independent spectral view of each normalized influence operator.",
        "required_invariants": [
            "same_matrix_anchor",
            "eigenvalue_baseline",
            "numerically_stable_root_gate",
        ],
    },
    {
        "id": "T04",
        "name": "fiedler_multimode_complete_partition",
        "priority": 1,
        "source_topics": ["fiedler_and_higher_modes", "aligned_cuts", "fiedler_orientation"],
        "construction": "Derive balanced complete cells from multiple low Laplacian modes of the public constraint graph; freeze a bijective cell map before solver execution.",
        "required_invariants": [
            "complete_disjoint_domain",
            "assignment_free_selection",
            "numeric_and_gray_controls",
        ],
    },
    {
        "id": "T05",
        "name": "z2_sum_difference_guidance",
        "priority": 1,
        "source_topics": [
            "sum_difference_projection",
            "local_difference_over_sum",
            "cross_copy_svd",
        ],
        "construction": "Pair forward/backward cut states, retain sum and signed difference channels, and rank variables/cells by stabilized difference-over-sum plus cross-copy singular modes.",
        "required_invariants": [
            "zero_denominator_policy",
            "copy_swap_control",
            "independent_confirmation",
        ],
    },
    {
        "id": "T06",
        "name": "modular_log_cross_copy_operator",
        "priority": 1,
        "source_topics": ["cross_copy_svd", "matrix_log"],
        "construction": "Normalize the public forward/backward coupling block and inspect its SVD together with a regularized negative matrix logarithm for latent long-range couplings.",
        "required_invariants": [
            "positive_spectrum_or_declared_regularization",
            "reconstruction_error",
            "permutation_control",
        ],
    },
    {
        "id": "T07",
        "name": "gumbel_sinkhorn_balanced_cell_annealing",
        "priority": 2,
        "source_topics": ["bvn_path_action", "sinkhorn_flow", "heat_kernel"],
        "construction": "Anneal a public constraint-to-cell score matrix from soft doubly stochastic assignments to a hard balanced permutation, then freeze complete cells.",
        "required_invariants": [
            "deterministic_seed",
            "exact_hard_assignment",
            "complete_disjoint_domain",
            "temperature_sweep_control",
        ],
    },
    {
        "id": "T08",
        "name": "phase_transition_scaling_of_solver_frontier",
        "priority": 2,
        "source_topics": [
            "finite_size_scaling_collapse",
            "critical_frontier",
            "asymmetry_order_parameter",
        ],
        "construction": "Treat SAT fraction, UNKNOWN fraction, and normalized work as order parameters over round, width, block count, and partition geometry; test one-variable scaling collapse.",
        "required_invariants": [
            "fixed_budget_family",
            "fresh_instances",
            "separate_onset_and_convergence_exponents",
        ],
    },
    {
        "id": "T09",
        "name": "boundary_geometry_partitions",
        "priority": 2,
        "source_topics": [
            "permutation_block_band_boundaries",
            "band_sparse_permutation_boundaries",
        ],
        "construction": "Generate complete partitions deliberately near permutation, block, and band boundaries instead of generic interior assignments.",
        "required_invariants": [
            "same_domain",
            "matched_cell_cardinality",
            "interior_random_control",
        ],
    },
    {
        "id": "T10",
        "name": "controlled_convex_amplification_with_resets",
        "priority": 2,
        "source_topics": ["convex_amplification", "sinkhorn_period", "zeno_schedule"],
        "construction": "Iterate a declared convex score amplifier with exact total-score restoration and periodic normalization; sweep reset interval for a stable localization window.",
        "required_invariants": [
            "aggregation_rule_fixed",
            "mass_restoration_error",
            "no_universal_collapse_assumption",
            "shuffle_control",
        ],
    },
    {
        "id": "T11",
        "name": "krylov_lanczos_constraint_complexity",
        "priority": 2,
        "source_topics": ["krylov_lanczos", "spectral_rank_identity"],
        "construction": "Compute Lanczos coefficient sequences of public formula propagation operators and compare depth/cut families by coefficient decay, oscillation, and spectral-rank preservation.",
        "required_invariants": [
            "fixed_start_vectors",
            "reorthogonalization_gate",
            "matrix_size_normalization",
        ],
    },
    {
        "id": "T12",
        "name": "log_quantized_causal_channels",
        "priority": 2,
        "source_topics": ["log_quantization", "residual_conservation", "two_timescales"],
        "construction": "Quantize multiscale Causal weights in signed log space while exactly returning residual mass; compare raw, linear, and log cascades.",
        "required_invariants": [
            "mass_conservation",
            "same_bit_budget",
            "roundtrip_error",
            "linear_quantization_control",
        ],
    },
    {
        "id": "T13",
        "name": "cusum_round_cut_change_points",
        "priority": 2,
        "source_topics": ["cusum", "phase_boundary", "correlation_decay"],
        "construction": "Run predeclared CUSUM tests on normalized cross-round spectral, cumulant, and solver-work series to localize structural change points.",
        "required_invariants": ["null_calibration", "familywise_threshold", "held_out_instances"],
    },
    {
        "id": "T14",
        "name": "modular_fractional_linear_domain_bijections",
        "priority": 3,
        "source_topics": ["mobius_group", "functional_equation", "mobius_composition"],
        "construction": "Adapt fractional-linear actions to Z/(2^w) using unit determinant and everywhere-unit denominators, prove bijectivity, then define nonlinear complete prefix preimages.",
        "required_invariants": [
            "explicit_inverse",
            "exhaustive_small_width_proof",
            "complete_disjoint_domain",
            "affine_control",
        ],
    },
    {
        "id": "T15",
        "name": "cardano_local_block_classifier",
        "priority": 3,
        "source_topics": ["cardano_discriminant", "symmetric_antisymmetric_split"],
        "construction": "Map normalized four-node constraint blocks to depressed-polynomial coefficients and use the discriminant only as a local structural classifier.",
        "required_invariants": [
            "named_sampling_measure",
            "block_permutation_control",
            "no_exact_fraction_assumption",
        ],
    },
    {
        "id": "T16",
        "name": "reflection_positive_forward_backward_kernel",
        "priority": 3,
        "source_topics": ["reflection_positivity", "reversal_conditioning"],
        "construction": "Build a reflected forward/backward cut kernel and test positive-semidefinite consistency before using its matrix log or continuation.",
        "required_invariants": [
            "symmetry_or_reversibilization",
            "psd_tolerance",
            "negative_eigenvalue_report",
        ],
    },
    {
        "id": "T17",
        "name": "page_curve_over_key_subsystems",
        "priority": 3,
        "source_topics": ["page_curve", "normalized_cross_copy_entropy", "boundary_volume"],
        "construction": "Measure cross-copy entropy versus unknown-key subsystem size and cut location; use the peak only as a partition-width diagnostic.",
        "required_invariants": [
            "same_total_domain",
            "subsystem_complement_symmetry",
            "finite_size_control",
        ],
    },
    {
        "id": "T18",
        "name": "entropy_round_solver_resource_duality",
        "priority": 3,
        "source_topics": ["entropy_round_duality", "kl_budget", "progress_per_kl"],
        "construction": "Measure information gain per cell and total solver work separately; optimize total retained information rather than per-cell runtime alone.",
        "required_invariants": [
            "fixed_information_metric",
            "include_all_cells",
            "separate_wall_and_solver_work",
        ],
    },
]


def _sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _canonical_sha256(value: Any) -> str:
    return _sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode())


def _topics_for_page(paper: str, page: int) -> list[str]:
    matches = [
        row["topics"] for row in PAPER_COVERAGE[paper] if row["pages"][0] <= page <= row["pages"][1]
    ]
    if len(matches) != 1:
        raise RuntimeError(f"page coverage is not exact for {paper} page {page}: {matches}")
    return matches[0]


def build(atlas_path: Path, source_pages_path: Path) -> dict[str, Any]:
    atlas_raw = atlas_path.read_bytes()
    source_pages_raw = source_pages_path.read_bytes()
    if _sha256(atlas_raw) != ATLAS_SHA256:
        raise RuntimeError("formula atlas SHA-256 differs from the reviewed source")
    if _sha256(source_pages_raw) != SOURCE_PAGES_SHA256:
        raise RuntimeError("formula source-page cache SHA-256 differs from the reviewed source")
    atlas = json.loads(atlas_raw)
    papers = atlas.get("papers", [])
    if len(papers) != EXPECTED_PAPERS or {row["paper"] for row in papers} != set(PAPER_COVERAGE):
        raise RuntimeError("formula atlas paper inventory differs")

    entries: list[dict[str, Any]] = []
    page_coverage: list[dict[str, Any]] = []
    seen_ids: set[str] = set()
    for paper in papers:
        name = paper["paper"]
        pages = int(paper["pages"])
        observed_pages = {int(row["page"]) for row in paper["entries"]}
        if observed_pages != set(range(1, pages + 1)):
            raise RuntimeError(f"formula atlas page inventory is incomplete for {name}")
        for page in range(1, pages + 1):
            page_entries = [row for row in paper["entries"] if int(row["page"]) == page]
            topics = _topics_for_page(name, page)
            page_coverage.append(
                {
                    "paper": name,
                    "page": page,
                    "entry_count": len(page_entries),
                    "review_status": "full_source_page_read_without_keyword_prefilter",
                    "page_topics": topics,
                }
            )
            for row in page_entries:
                entry_id = row["id"]
                if entry_id in seen_ids:
                    raise RuntimeError(f"duplicate formula atlas id: {entry_id}")
                seen_ids.add(entry_id)
                entries.append(
                    {
                        "id": entry_id,
                        "paper": name,
                        "page": page,
                        "kind_hint": row["kind_hint"],
                        "equation_label": row["equation_label"],
                        "formula_raw_sha256": _sha256(row["formula_raw"].encode()),
                        "context_sha256": _sha256(row["context"].encode()),
                        "review_status": "retained_via_full_source_page_review",
                        "page_topics": topics,
                    }
                )

    if len(page_coverage) != EXPECTED_PAGES or len(entries) != EXPECTED_ENTRIES:
        raise RuntimeError("formula atlas coverage totals differ")
    if len(seen_ids) != EXPECTED_ENTRIES:
        raise RuntimeError("formula atlas entry IDs are not unique and complete")

    payload: dict[str, Any] = {
        "schema": SCHEMA,
        "source": {
            "formula_atlas_path": "../Mathepaper/formula_atlas_v1.json",
            "formula_atlas_sha256": ATLAS_SHA256,
            "formula_source_pages_path": "../Mathepaper/formula_source_pages_v1.json",
            "formula_source_pages_sha256": SOURCE_PAGES_SHA256,
        },
        "method": {
            "review_order": "all_full_source_pages_first_then_reconcile_with_prior_moonshot_log",
            "keyword_prefilter_used_for_source_review": False,
            "formula_entries_dropped": 0,
            "semantic_rule": "page_topics_are_navigation_not_claim_validation;_each_candidate_requires_its_own_invariants_and_controls",
        },
        "summary": {
            "papers": len(papers),
            "pages": len(page_coverage),
            "entries": len(entries),
            "unique_entry_ids": len(seen_ids),
            "transfer_candidates": len(TRANSFER_CANDIDATES),
            "priority_1_candidates": sum(row["priority"] == 1 for row in TRANSFER_CANDIDATES),
        },
        "paper_coverage": PAPER_COVERAGE,
        "page_coverage": page_coverage,
        "entries": entries,
        "transfer_candidates": TRANSFER_CANDIDATES,
    }
    payload["coverage_sha256"] = _canonical_sha256(
        {"page_coverage": page_coverage, "entries": entries}
    )
    payload["candidate_registry_sha256"] = _canonical_sha256(TRANSFER_CANDIDATES)
    return payload


def main(argv: Sequence[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    workspace = Path(__file__).parents[3]
    research = Path(__file__).parents[1]
    parser.add_argument(
        "--atlas",
        type=Path,
        default=workspace / "Mathepaper" / "formula_atlas_v1.json",
    )
    parser.add_argument(
        "--source-pages",
        type=Path,
        default=workspace / "Mathepaper" / "formula_source_pages_v1.json",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=research / "results" / "v1" / "formula_atlas_transfer_coverage_v1.json",
    )
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args(argv)
    payload = build(args.atlas.resolve(), args.source_pages.resolve())
    raw = json.dumps(payload, indent=2, sort_keys=True, allow_nan=False).encode() + b"\n"
    if args.check:
        if not args.output.exists() or args.output.read_bytes() != raw:
            raise SystemExit("retained formula-atlas transfer coverage differs")
    else:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_bytes(raw)
    print(
        json.dumps(
            {
                "output": str(args.output),
                "json_sha256": _sha256(raw),
                **payload["summary"],
                "coverage_sha256": payload["coverage_sha256"],
                "candidate_registry_sha256": payload["candidate_registry_sha256"],
            },
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    main()

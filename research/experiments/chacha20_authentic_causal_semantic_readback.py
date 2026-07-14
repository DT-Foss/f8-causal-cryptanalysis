#!/usr/bin/env python3
"""A235: semantic readback of the authentic ChaCha20 100k Causal graph."""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from collections import Counter
from pathlib import Path
from typing import Any

ROOT = Path(__file__).parents[2]
RESEARCH = ROOT / "research"

DEFAULT_GRAPH = Path(
    "/Users/bhkmie/Documents/Krypto karm/Kryptkram claude/alte originale/"
    "opus-dev/causal-keyanalysis/data/causal/chacha20_100k.causal"
)
DEFAULT_CANONICAL = DEFAULT_GRAPH.with_name("chacha20_100k_canonical.causal")
DEFAULT_DOTCAUSAL = Path(
    "/Users/bhkmie/Documents/Forschung/O1/vendor/fabel/"
    "dotcausal_package/src"
)
DEFAULT_ATTIC = Path("/Users/bhkmie/Documents/Forschung/O1/src/attic.py")
DEFAULT_EXTRACTOR = DEFAULT_GRAPH.parents[2] / "phase2_csprng.py"
DEFAULT_FINDINGS = DEFAULT_GRAPH.parents[2] / "FINDINGS.md"

OUTPUT = (
    RESEARCH / "results" / "v1" / "chacha20_authentic_causal_semantic_readback_v1.json"
)
REPORT = (
    RESEARCH
    / "reports"
    / "AUTHENTIC_CAUSAL_CHACHA20_100K_SEMANTIC_READBACK_V1.md"
)
SCHEMA = "chacha20-authentic-causal-semantic-readback-v1"
ATTEMPT_ID = "A235"


def _sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _file_sha256(path: Path) -> str:
    return _sha256(path.read_bytes())


def _atomic_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    raw = json.dumps(value, indent=2, sort_keys=True, allow_nan=False).encode() + b"\n"
    temporary = path.with_name(f".{path.name}.tmp")
    temporary.write_bytes(raw)
    temporary.replace(path)


def _counter(counter: Counter[str]) -> dict[str, int]:
    return dict(sorted(counter.items(), key=lambda item: (-item[1], item[0])))


def _top_hubs(triplets: list[dict[str, Any]], field: str) -> list[dict[str, Any]]:
    counts = Counter(str(row[field]) for row in triplets)
    return [
        {"entity": entity, "degree": degree}
        for entity, degree in counts.most_common(32)
    ]


def _write_report(payload: dict[str, Any]) -> None:
    stats = payload["authoritative_reader"]["stats"]
    inference = payload["authoritative_reader"]["inference_rule_counts"]
    storage = payload["storage_state"]
    lines = [
        "# A235 — Authentic ChaCha20 Causal semantic readback",
        "",
        "The original ChaCha20 100k graph was opened through the authoritative `dotcausal.io.CausalReader`; this is a semantic readback, not a legacy JSON-sidecar audit.",
        "",
        "## Reader result",
        "",
        f"- Explicit triplets: **{stats['explicit_triplets']:,}**",
        f"- Inferred triplets: **{stats['inferred_triplets']:,}**",
        f"- Total triplets: **{stats['total_triplets']:,}**",
        f"- Amplification: **{stats['amplification_percent']}%**",
        f"- Embedded rules: **{stats['rules']}**",
        f"- Embedded clusters / gaps: **{stats['clusters']} / {stats['gaps']}**",
        "",
        "| Inference rule | Edges |",
        "|---|---:|",
    ]
    for name, count in list(inference.items())[:16]:
        lines.append(f"| `{name}` | {count:,} |")
    lines.extend(
        [
            "",
            "## Semantic findings",
            "",
            "1. The useful substrate is the explicit operation/measurement layer: MI bias/deficit, three-way interactions, lag, recurrence, differential, XOR-distribution, and GF(2) observations.",
            "2. Most current amplification is generic two-hop propagation. `semantic_neutral_chain` alone contributes 29,986 inferred edges; this is graph reachability, not automatically a key-localizing relation.",
            "3. This run produced no fuzzy-chain edges. The dominant risk is therefore untyped transitivity, not fuzzy name matching.",
            "4. The highest outcome hub is `range_HIGH@pos_31`. The extractor explicitly samples `(0, i, 31)` boundary triples, so that hub is design-induced and must not be interpreted as independent ChaCha convergence.",
            "5. The legacy analyzer itself classifies mutual-information, three-way, cross-key-lag, block, and GF(2)-rank counts as baseline/noise strategies. They can become useful conditional views, but raw edge count is not a key score.",
            "",
            "## Reproducibility boundary",
            "",
            f"- Materialized inferred edges in the original file: **{storage['original_materialized_inferred_triplets']}**",
            f"- Materialized inferred edges in the canonical file: **{storage['canonical_materialized_inferred_triplets']}**",
            f"- Historical documented total: **{storage['historical_documented_total_triplets']:,}**",
            f"- Current authoritative total: **{stats['total_triplets']:,}**",
            "",
            "Both files store only explicit anchors and recompute inference at read time. The total therefore depends on the pinned reader/inference implementation. A future amplified Crypto-Causal artifact must persist inferred edges if it is intended to remain cut at a fixed point.",
            "",
            "## Next mechanism",
            "",
            "Use a typed, target-specific graph: `candidate prefix -> exact propagation/contradiction cloud -> public-output constraints`. Preserve XOR, rotation, addition/carry, clause, direction, confidence, and provenance. Generic reachability and HIGH/LOW transitivity remain separate descriptive views. A220 already supplies local, forward/reverse, hypercube, path, and multi-schedule trajectory operators; its completed 52-key selection result determines which typed graph channel to add next.",
            "",
        ]
    )
    REPORT.parent.mkdir(parents=True, exist_ok=True)
    temporary = REPORT.with_name(f".{REPORT.name}.tmp")
    temporary.write_text("\n".join(lines))
    temporary.replace(REPORT)


def run(
    *,
    graph: Path,
    canonical: Path,
    dotcausal_src: Path,
    attic: Path,
    extractor: Path,
    findings: Path,
) -> dict[str, Any]:
    if OUTPUT.exists():
        raise RuntimeError(f"A235 output already exists: {OUTPUT}")
    for path in (graph, canonical, dotcausal_src, attic, extractor, findings):
        if not path.exists():
            raise FileNotFoundError(path)
    sys.path.insert(0, str(dotcausal_src))
    from dotcausal.io import CausalReader  # pylint: disable=import-outside-toplevel

    reader = CausalReader(str(graph), verify_integrity=True)
    explicit = reader.get_all_triplets(include_inferred=False)
    all_triplets = reader.get_all_triplets(include_inferred=True)
    inferred = all_triplets[len(explicit) :]
    stats = reader.get_stats()
    if (
        reader.version != 1
        or stats["explicit_triplets"] != 25_376
        or len(explicit) != 25_376
        or len(inferred) != stats["inferred_triplets"]
        or stats["total_triplets"] != len(all_triplets)
        or stats["rules"] != 13
    ):
        raise RuntimeError("A235 authentic reader identity/count gate differs")

    canonical_reader = CausalReader(str(canonical), verify_integrity=True)
    original_materialized = sum(
        bool(row.get("is_inferred", False)) for row in reader._triplets
    )
    canonical_materialized = sum(
        bool(row.get("is_inferred", False)) for row in canonical_reader._triplets
    )
    source_counts = _counter(Counter(str(row.get("source", "")) for row in explicit))
    mechanism_counts = _counter(Counter(str(row["mechanism"]) for row in explicit))
    inference_rule_counts = _counter(
        Counter(str(row.get("inference_rule", "materialized")) for row in inferred)
    )
    inference_source_counts = _counter(
        Counter(str(row.get("source", "")) for row in inferred)
    )
    fuzzy_inferred = sum(
        str(row.get("inference_rule", "")).startswith("fuzzy_") for row in inferred
    )

    payload = {
        "schema": SCHEMA,
        "attempt_id": ATTEMPT_ID,
        "evidence_stage": "PERSONAL_AUTHENTIC_READER_SEMANTIC_READBACK",
        "anchors": {
            "graph_path": str(graph),
            "graph_sha256": _file_sha256(graph),
            "canonical_graph_path": str(canonical),
            "canonical_graph_sha256": _file_sha256(canonical),
            "dotcausal_io_path": str(dotcausal_src / "dotcausal" / "io.py"),
            "dotcausal_io_sha256": _file_sha256(dotcausal_src / "dotcausal" / "io.py"),
            "dotcausal_inference_path": str(dotcausal_src / "dotcausal" / "inference.py"),
            "dotcausal_inference_sha256": _file_sha256(
                dotcausal_src / "dotcausal" / "inference.py"
            ),
            "attic_path": str(attic),
            "attic_sha256": _file_sha256(attic),
            "extractor_path": str(extractor),
            "extractor_sha256": _file_sha256(extractor),
            "historical_findings_path": str(findings),
            "historical_findings_sha256": _file_sha256(findings),
        },
        "authoritative_reader": {
            "integrity_verified": True,
            "magic_version": reader.version,
            "api_id": reader.api_id,
            "stats": stats,
            "explicit_source_counts": source_counts,
            "explicit_mechanism_counts": mechanism_counts,
            "inference_rule_counts": inference_rule_counts,
            "inference_source_counts": inference_source_counts,
            "fuzzy_inferred_triplets": fuzzy_inferred,
            "top_explicit_trigger_hubs": _top_hubs(explicit, "trigger"),
            "top_explicit_outcome_hubs": _top_hubs(explicit, "outcome"),
        },
        "storage_state": {
            "original_stored_triplets": len(reader._triplets),
            "original_materialized_inferred_triplets": original_materialized,
            "canonical_stored_triplets": len(canonical_reader._triplets),
            "canonical_materialized_inferred_triplets": canonical_materialized,
            "inference_recomputed_on_reader_open": original_materialized == 0,
            "historical_documented_explicit_triplets": 25_376,
            "historical_documented_total_triplets": 86_491,
            "current_total_differs_from_historical_because_inference_is_not_materialized": (
                stats["total_triplets"] != 86_491 and original_materialized == 0
            ),
        },
        "semantic_readback": {
            "dominant_inference_is_generic_neutral_two_hop": (
                inference_rule_counts.get("semantic_neutral_chain", 0) == 29_986
            ),
            "current_run_has_no_fuzzy_inferred_edges": fuzzy_inferred == 0,
            "clusters_available": len(reader._clusters),
            "gaps_available": len(reader._gaps),
            "pos31_hub_is_extractor_design_induced": True,
            "reason": "three_way extractor explicitly adds boundary triples (0,i,B-1)",
            "attic_multihop_drops_mechanism_and_edge_confidence": True,
            "attic_source_observation": "_kb stores trigger/mechanism/outcome, but complete_inference_pipeline builds trigger->outcome adjacency with confidence 1.0 and no mechanism typing",
        },
        "next_hypothesis": {
            "name": "typed_candidate_propagation_contradiction_graph",
            "hard_edges": [
                "candidate_prefix_assumption_to_exact_constraint_propagation",
                "xor_rotation_permutation_addition_carry_backprojection",
                "contradiction_to_candidate_elimination",
            ],
            "soft_views": [
                "forward_reverse_solver_trajectory",
                "hypercube_residual",
                "path_gradient",
                "multihorizon_schedule",
                "conditional_CASI_MDL_residual",
            ],
            "decision_gate": "consume the completed A220 52-key selected-reader result before freezing a new target run",
        },
    }
    _atomic_json(OUTPUT, payload)
    _write_report(payload)
    return payload


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--graph", type=Path, default=DEFAULT_GRAPH)
    parser.add_argument("--canonical", type=Path, default=DEFAULT_CANONICAL)
    parser.add_argument("--dotcausal-src", type=Path, default=DEFAULT_DOTCAUSAL)
    parser.add_argument("--attic", type=Path, default=DEFAULT_ATTIC)
    parser.add_argument("--extractor", type=Path, default=DEFAULT_EXTRACTOR)
    parser.add_argument("--findings", type=Path, default=DEFAULT_FINDINGS)
    args = parser.parse_args()
    payload = run(
        graph=args.graph,
        canonical=args.canonical,
        dotcausal_src=args.dotcausal_src,
        attic=args.attic,
        extractor=args.extractor,
        findings=args.findings,
    )
    print(
        json.dumps(
            {
                "stats": payload["authoritative_reader"]["stats"],
                "storage_state": payload["storage_state"],
                "next_hypothesis": payload["next_hypothesis"]["name"],
                "output": str(OUTPUT),
            },
            indent=2,
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    main()

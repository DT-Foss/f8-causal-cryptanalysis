"""Deterministic, typed causal evidence graphs for cryptographic experiments.

The general-purpose ``.causal`` engine is intentionally not used for cipher
variables: fuzzy entity matching can turn byte/bit naming conventions into
edges.  This module keeps the useful format ideas (embedded rules, exact
closure, provenance, canonical serialization) and makes the cryptographic
restrictions explicit:

* relations are exact typed strings;
* every edge is measured, algebraically verified, or exactly inferred;
* inferred edges retain the complete source-edge provenance;
* no fuzzy/entity-semantic pass exists.
"""

from __future__ import annotations

import hashlib
import json
import struct
import zlib
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any


MAGIC = b"CAUSAL"
VERSION = 3
HEADER_SIZE = 8


@dataclass(frozen=True)
class ExactRule:
    """Compose two exactly named mechanisms into a third mechanism."""

    name: str
    first: str
    second: str
    conclusion: str
    confidence_modifier: float = 1.0


@dataclass(frozen=True)
class EvidenceTriplet:
    """A typed causal edge with machine-readable provenance."""

    edge_id: str
    trigger: str
    mechanism: str
    outcome: str
    confidence: float
    evidence_kind: str
    source: str
    provenance: tuple[str, ...] = field(default_factory=tuple)
    attrs: dict[str, Any] = field(default_factory=dict)
    is_inferred: bool = False


def _canonical_bytes(value: Any) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")


class CryptoCausalBuilder:
    """Build an exact cryptographic evidence graph and optional closure."""

    def __init__(self, *, experiment: str, parameters: dict[str, Any] | None = None):
        self.experiment = experiment
        self.parameters = parameters or {}
        self._edges: dict[str, EvidenceTriplet] = {}
        self._rules: list[ExactRule] = []

    def add_rule(self, rule: ExactRule) -> None:
        if not 0.0 <= rule.confidence_modifier <= 1.0:
            raise ValueError("rule confidence_modifier must be in [0, 1]")
        self._rules.append(rule)

    def add_triplet(
        self,
        *,
        edge_id: str,
        trigger: str,
        mechanism: str,
        outcome: str,
        confidence: float,
        evidence_kind: str,
        source: str,
        provenance: tuple[str, ...] | list[str] = (),
        attrs: dict[str, Any] | None = None,
        is_inferred: bool = False,
    ) -> EvidenceTriplet:
        if not edge_id or edge_id in self._edges:
            raise ValueError(f"edge id must be unique and non-empty: {edge_id!r}")
        if not trigger or not mechanism or not outcome:
            raise ValueError("trigger, mechanism, and outcome must be non-empty")
        if not 0.0 <= confidence <= 1.0:
            raise ValueError("confidence must be in [0, 1]")
        edge = EvidenceTriplet(
            edge_id=edge_id,
            trigger=trigger,
            mechanism=mechanism,
            outcome=outcome,
            confidence=float(confidence),
            evidence_kind=evidence_kind,
            source=source,
            provenance=tuple(sorted(set(provenance))),
            attrs=attrs or {},
            is_inferred=is_inferred,
        )
        self._edges[edge_id] = edge
        return edge

    def infer_exact_closure(self, *, max_hops: int = 4) -> list[EvidenceTriplet]:
        """Compute recursive exact-rule closure up to ``max_hops``.

        A single best path is retained per (trigger, mechanism, outcome). This
        avoids counting correlated re-derivations as independent evidence.
        """
        if max_hops < 2:
            raise ValueError("max_hops must be at least 2")
        known: dict[tuple[str, str, str], EvidenceTriplet] = {
            (edge.trigger, edge.mechanism, edge.outcome): edge for edge in self._edges.values()
        }
        inferred: list[EvidenceTriplet] = []
        frontier = list(known.values())
        for hop in range(2, max_hops + 1):
            additions: list[EvidenceTriplet] = []
            all_edges = list(known.values())
            for left in frontier:
                for right in all_edges:
                    if left.outcome != right.trigger or left.trigger == right.outcome:
                        continue
                    for rule in self._rules:
                        if left.mechanism != rule.first or right.mechanism != rule.second:
                            continue
                        key = (left.trigger, rule.conclusion, right.outcome)
                        confidence = left.confidence * right.confidence * rule.confidence_modifier
                        provenance = tuple(
                            sorted(
                                set(left.provenance or (left.edge_id,))
                                | set(right.provenance or (right.edge_id,))
                            )
                        )
                        current = known.get(key)
                        if current is not None and current.confidence >= confidence:
                            continue
                        digest = hashlib.sha256(
                            _canonical_bytes([rule.name, hop, *key, provenance])
                        ).hexdigest()[:16]
                        edge = EvidenceTriplet(
                            edge_id=f"inferred-{digest}",
                            trigger=key[0],
                            mechanism=key[1],
                            outcome=key[2],
                            confidence=confidence,
                            evidence_kind="exact_rule_closure",
                            source=rule.name,
                            provenance=provenance,
                            attrs={"hop": hop, "rule": rule.name},
                            is_inferred=True,
                        )
                        known[key] = edge
                        additions.append(edge)
            if not additions:
                break
            additions.sort(key=lambda edge: edge.edge_id)
            inferred.extend(additions)
            frontier = additions
        for edge in inferred:
            self._edges[edge.edge_id] = edge
        return inferred

    def payload(self) -> dict[str, Any]:
        edges = [asdict(edge) for edge in sorted(self._edges.values(), key=lambda item: item.edge_id)]
        rules = [asdict(rule) for rule in sorted(self._rules, key=lambda item: item.name)]
        graph = {
            "schema": "crypto-causal-v1",
            "experiment": self.experiment,
            "parameters": self.parameters,
            "rules": rules,
            "triplets": edges,
        }
        return {"graph": graph, "graph_sha256": hashlib.sha256(_canonical_bytes(graph)).hexdigest()}

    def save(self, path: str | Path) -> dict[str, Any]:
        """Write an 8-byte-header, zlib-compressed canonical ``.causal`` file."""
        destination = Path(path)
        destination.parent.mkdir(parents=True, exist_ok=True)
        raw = _canonical_bytes(self.payload())
        encoded = MAGIC + struct.pack("<H", VERSION) + zlib.compress(raw, level=9)
        destination.write_bytes(encoded)
        return {
            "path": str(destination),
            "bytes": len(encoded),
            "triplets": len(self._edges),
            "explicit_triplets": sum(not edge.is_inferred for edge in self._edges.values()),
            "inferred_triplets": sum(edge.is_inferred for edge in self._edges.values()),
            "file_sha256": hashlib.sha256(encoded).hexdigest(),
            "graph_sha256": self.payload()["graph_sha256"],
        }


class CryptoCausalReader:
    """Read and integrity-check a ``crypto-causal-v1`` evidence graph."""

    def __init__(self, path: str | Path):
        self.path = Path(path)
        encoded = self.path.read_bytes()
        if len(encoded) < HEADER_SIZE or encoded[:6] != MAGIC:
            raise ValueError("not a CAUSAL file")
        self.version = struct.unpack("<H", encoded[6:8])[0]
        if self.version != VERSION:
            raise ValueError(f"unsupported crypto-causal version {self.version}")
        envelope = json.loads(zlib.decompress(encoded[8:]).decode("utf-8"))
        graph = envelope.get("graph")
        if not isinstance(graph, dict) or graph.get("schema") != "crypto-causal-v1":
            raise ValueError("invalid crypto-causal schema")
        expected = hashlib.sha256(_canonical_bytes(graph)).hexdigest()
        if envelope.get("graph_sha256") != expected:
            raise ValueError("crypto-causal graph integrity check failed")
        self.graph = graph
        self.graph_sha256 = expected
        self.file_sha256 = hashlib.sha256(encoded).hexdigest()

    def triplets(self, *, include_inferred: bool = True) -> list[dict[str, Any]]:
        rows = list(self.graph["triplets"])
        if include_inferred:
            return rows
        return [row for row in rows if not row.get("is_inferred", False)]

    def verify_provenance(self) -> bool:
        ids = {row["edge_id"] for row in self.graph["triplets"]}
        for row in self.graph["triplets"]:
            if row.get("is_inferred") and not set(row.get("provenance", ())).issubset(ids):
                return False
        return True

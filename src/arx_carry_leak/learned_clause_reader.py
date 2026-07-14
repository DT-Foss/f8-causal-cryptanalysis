"""Exact learned-clause identity reader for fresh candidate-prefix solvers."""

from __future__ import annotations

import hashlib
import math
from collections import Counter
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any

import numpy as np

HORIZONS = (1, 2, 4, 8)
PAIR_MAXIMUM_CLAUSE_SIZE = 16
TOKEN_FAMILIES = (
    "stage_signed_variable",
    "stage_unsigned_variable",
    "stage_clause",
    "stage_pair",
    "all_signed_variable",
    "all_unsigned_variable",
    "all_clause",
    "all_pair",
)


@dataclass(frozen=True)
class ClauseIdentityTable:
    label: str
    true_prefix: int
    candidates: tuple[int, ...]
    candidate_tokens: tuple[frozenset[str], ...]


@dataclass(frozen=True)
class LearnedClausePoE:
    token_weights: Mapping[str, float]
    minimum_positive_support: int
    beta_smoothing: float
    token_log_odds_cap: float
    positive_documents: int
    negative_documents: int

    def scores(self, table: ClauseIdentityTable) -> np.ndarray:
        if table.candidates != tuple(range(256)) or len(table.candidate_tokens) != 256:
            raise ValueError("learned-clause candidate table differs")
        result = np.zeros(256, dtype=np.float64)
        for candidate, tokens in enumerate(table.candidate_tokens):
            family_values: dict[str, list[float]] = {family: [] for family in TOKEN_FAMILIES}
            for token in tokens:
                weight = self.token_weights.get(token)
                if weight is None:
                    continue
                family = token.split("|", 1)[0]
                if family not in family_values:
                    raise RuntimeError("learned-clause token family differs")
                family_values[family].append(float(weight))
            result[candidate] = sum(
                sum(values) / len(values) for values in family_values.values() if values
            )
        if not np.isfinite(result).all():
            raise RuntimeError("learned-clause PoE produced non-finite scores")
        return result

    def as_dict(self) -> dict[str, object]:
        return {
            "model": "family_normalized_Bernoulli_learned_clause_product_of_experts",
            "token_weights": dict(sorted(self.token_weights.items())),
            "retained_token_count": len(self.token_weights),
            "minimum_positive_support": self.minimum_positive_support,
            "beta_smoothing": self.beta_smoothing,
            "token_log_odds_cap": self.token_log_odds_cap,
            "positive_documents": self.positive_documents,
            "negative_documents": self.negative_documents,
            "token_families": list(TOKEN_FAMILIES),
        }


def _clause_digest(clause: Sequence[int]) -> str:
    raw = len(clause).to_bytes(2, "little") + np.asarray(clause, dtype="<i4").tobytes()
    return hashlib.sha256(raw).hexdigest()


def _tokens_for_clause(horizon: int, clause: Sequence[int]) -> set[str]:
    values = tuple(int(value) for value in clause)
    digest = _clause_digest(values)
    result = {
        f"stage_clause|h{horizon}|{digest}",
        f"all_clause|{digest}",
    }
    for literal in values:
        result.update(
            {
                f"stage_signed_variable|h{horizon}|{literal}",
                f"stage_unsigned_variable|h{horizon}|{abs(literal)}",
                f"all_signed_variable|{literal}",
                f"all_unsigned_variable|{abs(literal)}",
            }
        )
    if len(values) <= PAIR_MAXIMUM_CLAUSE_SIZE:
        for first in range(len(values)):
            for second in range(first + 1, len(values)):
                left, right = values[first], values[second]
                result.update(
                    {
                        f"stage_pair|h{horizon}|{left}|{right}",
                        f"all_pair|{left}|{right}",
                    }
                )
    return result


def build_clause_identity_table(measurement: Mapping[str, Any]) -> ClauseIdentityTable:
    design = measurement.get("known_key_design", {})
    label = measurement.get("label")
    true_prefix = design.get("prefix8")
    run = measurement.get("run", {})
    if (
        not isinstance(label, str)
        or not isinstance(true_prefix, int)
        or isinstance(true_prefix, bool)
        or not 0 <= true_prefix < 256
        or run.get("learned_clause_identity_complete") is not True
        or run.get("bounded_variable_addition_enabled") is not False
    ):
        raise ValueError("learned-clause measurement identity differs")
    rows = {
        (int(row["prefix8"], 2), int(row["horizon"])): row
        for row in run.get("stages", [])
    }
    expected = {(candidate, horizon) for candidate in range(256) for horizon in HORIZONS}
    if set(rows) != expected:
        missing = sorted(expected - set(rows))[:8]
        raise ValueError(f"learned-clause stage cover differs: {missing}")
    assumption_variable_sets = {
        frozenset(abs(int(literal)) for literal in row.get("assumptions", []))
        for row in rows.values()
    }
    if (
        len(assumption_variable_sets) != 1
        or len(next(iter(assumption_variable_sets), frozenset())) != 8
    ):
        raise ValueError("learned-clause candidate assumption-variable set differs")
    assumption_variables = next(iter(assumption_variable_sets))
    candidate_tokens = []
    for candidate in range(256):
        tokens: set[str] = set()
        for horizon in HORIZONS:
            row = rows[(candidate, horizon)]
            clauses = row.get("learned_clauses_stage")
            if not isinstance(clauses, list):
                raise ValueError("learned-clause row payload differs")
            for clause in clauses:
                # Learned clauses can contain the eight temporary assumption
                # literals themselves.  Keeping those literals would hand the
                # reader the candidate bits under another name.  Project every
                # clause onto the original non-assumption variables before
                # forming variable, pair, or exact-clause tokens.
                projected = [
                    int(literal)
                    for literal in clause
                    if abs(int(literal)) not in assumption_variables
                ]
                if projected:
                    tokens.update(_tokens_for_clause(horizon, projected))
        candidate_tokens.append(frozenset(tokens))
    return ClauseIdentityTable(
        label=label,
        true_prefix=true_prefix,
        candidates=tuple(range(256)),
        candidate_tokens=tuple(candidate_tokens),
    )


def fit_learned_clause_poe(
    tables: Sequence[ClauseIdentityTable],
    *,
    minimum_positive_support: int,
    beta_smoothing: float,
    token_log_odds_cap: float,
) -> LearnedClausePoE:
    values = list(tables)
    if (
        len(values) < 2
        or minimum_positive_support < 1
        or not isinstance(minimum_positive_support, int)
        or isinstance(minimum_positive_support, bool)
        or beta_smoothing <= 0
        or not math.isfinite(beta_smoothing)
        or token_log_odds_cap <= 0
        or not math.isfinite(token_log_odds_cap)
        or any(
            table.candidates != tuple(range(256)) or len(table.candidate_tokens) != 256
            for table in values
        )
    ):
        raise ValueError("learned-clause PoE training contract differs")
    positive_support: Counter[str] = Counter()
    negative_support: Counter[str] = Counter()
    for table in values:
        positive_support.update(table.candidate_tokens[table.true_prefix])
        for candidate, tokens in enumerate(table.candidate_tokens):
            if candidate != table.true_prefix:
                negative_support.update(tokens)
    positive_documents = len(values)
    negative_documents = len(values) * 255
    weights: dict[str, float] = {}
    for token, positive_count in positive_support.items():
        if positive_count < minimum_positive_support:
            continue
        negative_count = negative_support[token]
        positive_probability = (positive_count + beta_smoothing) / (
            positive_documents + 2.0 * beta_smoothing
        )
        negative_probability = (negative_count + beta_smoothing) / (
            negative_documents + 2.0 * beta_smoothing
        )
        log_odds = math.log(
            positive_probability / (1.0 - positive_probability)
        ) - math.log(negative_probability / (1.0 - negative_probability))
        weights[token] = float(
            max(-token_log_odds_cap, min(token_log_odds_cap, log_odds))
        )
    return LearnedClausePoE(
        token_weights=weights,
        minimum_positive_support=minimum_positive_support,
        beta_smoothing=float(beta_smoothing),
        token_log_odds_cap=float(token_log_odds_cap),
        positive_documents=positive_documents,
        negative_documents=negative_documents,
    )

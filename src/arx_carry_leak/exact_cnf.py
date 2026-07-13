"""Exact DIMACS parsing, Boolean constraint propagation, and explanations.

The implementation is deliberately small and deterministic.  It is not a SAT
solver: it computes only consequences obtainable by unit propagation and keeps
the clause-level reason DAG for every propagated literal.
"""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass
from typing import Iterable, Sequence

import numpy as np


def literal_node(literal: int) -> int:
    """Map a non-zero signed DIMACS literal to a dense zero-based node."""
    if literal == 0:
        raise ValueError("DIMACS literal zero is a terminator, not a variable")
    variable = abs(int(literal)) - 1
    return 2 * variable + (literal < 0)


def node_literal(node: int) -> int:
    """Invert :func:`literal_node`."""
    if node < 0:
        raise ValueError("literal node must be non-negative")
    variable = node // 2 + 1
    return -variable if node & 1 else variable


@dataclass
class PropagationState:
    """Mutable closure state returned by :class:`ExactCNF`."""

    assignment: np.ndarray
    reasons: np.ndarray
    remaining: np.ndarray
    satisfied: np.ndarray
    conflict_clause: int | None = None
    conflict_literals: tuple[int, int] | None = None
    conflict_new_reason: int | None = None

    @property
    def conflicted(self) -> bool:
        return self.conflict_clause is not None or self.conflict_literals is not None

    @property
    def assigned_count(self) -> int:
        return int(np.count_nonzero(self.assignment[1:]))

    def copy(self) -> "PropagationState":
        return PropagationState(
            assignment=self.assignment.copy(),
            reasons=self.reasons.copy(),
            remaining=self.remaining.copy(),
            satisfied=self.satisfied.copy(),
            conflict_clause=self.conflict_clause,
            conflict_literals=self.conflict_literals,
            conflict_new_reason=self.conflict_new_reason,
        )


class ExactCNF:
    """A validated CNF with occurrence-indexed exact unit propagation."""

    def __init__(self, *, variable_count: int, clauses: Sequence[Sequence[int]]):
        if variable_count <= 0:
            raise ValueError("variable_count must be positive")
        normalized: list[tuple[int, ...]] = []
        length_counts: dict[int, int] = {}
        occurrences: list[list[int]] = [[] for _ in range(2 * variable_count)]
        for clause_index, values in enumerate(clauses):
            clause = tuple(int(value) for value in values)
            if not clause:
                raise ValueError(f"empty clause at index {clause_index}")
            if any(value == 0 or abs(value) > variable_count for value in clause):
                raise ValueError(f"out-of-range literal in clause {clause_index}")
            if len(set(clause)) != len(clause):
                raise ValueError(f"duplicate literal in clause {clause_index}")
            if any(-value in clause for value in clause):
                raise ValueError(f"tautological clause at index {clause_index}")
            normalized.append(clause)
            length_counts[len(clause)] = length_counts.get(len(clause), 0) + 1
            for literal in clause:
                occurrences[literal_node(literal)].append(clause_index)
        self.variable_count = int(variable_count)
        self.clauses = tuple(normalized)
        self.clause_count = len(self.clauses)
        self.length_counts = dict(sorted(length_counts.items()))
        self._occurrences = tuple(
            np.asarray(indices, dtype=np.int32) for indices in occurrences
        )
        maximum = max(self.length_counts, default=0)
        length_dtype = np.uint8 if maximum <= np.iinfo(np.uint8).max else np.uint16
        self._initial_remaining = np.asarray(
            [len(clause) for clause in self.clauses], dtype=length_dtype
        )

    @classmethod
    def from_dimacs(cls, raw: bytes) -> "ExactCNF":
        """Parse strict one-clause-per-line DIMACS bytes."""
        lines = raw.splitlines()
        if not lines:
            raise ValueError("empty DIMACS input")
        header = lines[0].split()
        if len(header) != 4 or header[:2] != [b"p", b"cnf"]:
            raise ValueError("invalid DIMACS header")
        variable_count = int(header[2])
        declared_clauses = int(header[3])
        clauses: list[tuple[int, ...]] = []
        for line_index, line in enumerate(lines[1:], start=2):
            fields = line.split()
            if not fields or fields[-1] != b"0":
                raise ValueError(f"malformed DIMACS clause on line {line_index}")
            values = tuple(int(field) for field in fields[:-1])
            if 0 in values:
                raise ValueError(f"embedded DIMACS terminator on line {line_index}")
            clauses.append(values)
        if len(clauses) != declared_clauses:
            raise ValueError(
                f"declared {declared_clauses} clauses but parsed {len(clauses)}"
            )
        return cls(variable_count=variable_count, clauses=clauses)

    @staticmethod
    def _literal_value(assignment: np.ndarray, literal: int) -> int:
        value = int(assignment[abs(literal)])
        return value if literal > 0 else -value

    def propagate(
        self,
        assumptions: Iterable[int] = (),
        *,
        base: PropagationState | None = None,
    ) -> PropagationState:
        """Compute exact unit closure under signed-literal assumptions.

        Reason ``-1`` denotes an external assumption and non-negative values
        denote the zero-based clause that forced the assignment.  ``-2`` means
        that a variable remains unassigned.
        """
        if base is None:
            state = PropagationState(
                assignment=np.zeros(self.variable_count + 1, dtype=np.int8),
                reasons=np.full(self.variable_count + 1, -2, dtype=np.int32),
                remaining=self._initial_remaining.copy(),
                satisfied=np.zeros(self.clause_count, dtype=np.bool_),
            )
            pending: deque[tuple[int, int]] = deque(
                (clause[0], clause_index)
                for clause_index, clause in enumerate(self.clauses)
                if len(clause) == 1
            )
        else:
            if base.conflicted:
                return base.copy()
            state = base.copy()
            pending = deque()
        for literal in assumptions:
            literal = int(literal)
            if literal == 0 or abs(literal) > self.variable_count:
                raise ValueError(f"invalid assumption literal {literal}")
            pending.append((literal, -1))

        while pending and not state.conflicted:
            literal, reason = pending.popleft()
            variable = abs(literal)
            value = 1 if literal > 0 else -1
            current = int(state.assignment[variable])
            if current:
                if current != value:
                    state.conflict_literals = (variable if current > 0 else -variable, literal)
                    state.conflict_new_reason = reason
                continue
            state.assignment[variable] = value
            state.reasons[variable] = reason

            for clause_index_value in self._occurrences[literal_node(literal)]:
                clause_index = int(clause_index_value)
                if not state.satisfied[clause_index]:
                    state.satisfied[clause_index] = True

            for clause_index_value in self._occurrences[literal_node(-literal)]:
                clause_index = int(clause_index_value)
                if state.satisfied[clause_index]:
                    continue
                remaining = int(state.remaining[clause_index]) - 1
                state.remaining[clause_index] = remaining
                if remaining == 0:
                    state.conflict_clause = clause_index
                    break
                if remaining == 1:
                    unit = next(
                        candidate
                        for candidate in self.clauses[clause_index]
                        if self._literal_value(state.assignment, candidate) == 0
                    )
                    pending.append((unit, clause_index))
        return state

    def literal_is_true(self, state: PropagationState, literal: int) -> bool:
        return self._literal_value(state.assignment, literal) > 0

    def literal_is_false(self, state: PropagationState, literal: int) -> bool:
        return self._literal_value(state.assignment, literal) < 0

    def explain_literal(self, state: PropagationState, literal: int) -> tuple[int, ...]:
        """Return the transitive source-clause set for a true literal."""
        if not self.literal_is_true(state, literal):
            raise ValueError(f"literal {literal} is not true in the supplied state")
        clauses: set[int] = set()
        seen_variables: set[int] = set()

        def visit_true(true_literal: int) -> None:
            variable = abs(true_literal)
            if variable in seen_variables:
                return
            seen_variables.add(variable)
            reason = int(state.reasons[variable])
            if reason < 0:
                return
            clauses.add(reason)
            for antecedent in self.clauses[reason]:
                if antecedent == true_literal:
                    continue
                if not self.literal_is_false(state, antecedent):
                    raise RuntimeError("reason clause is not unit under the recorded state")
                assigned_true = -antecedent
                visit_true(assigned_true)

        visit_true(int(literal))
        return tuple(sorted(clauses))

    def explain_conflict(self, state: PropagationState) -> tuple[int, ...]:
        """Return all source clauses in the recorded contradiction DAG."""
        if not state.conflicted:
            raise ValueError("state is not conflicting")
        clauses: set[int] = set()
        if state.conflict_clause is not None:
            clauses.add(state.conflict_clause)
            for literal in self.clauses[state.conflict_clause]:
                if not self.literal_is_false(state, literal):
                    raise RuntimeError("conflict clause is not false under the recorded state")
                clauses.update(self.explain_literal(state, -literal))
        elif state.conflict_literals is not None:
            existing, _new = state.conflict_literals
            clauses.update(self.explain_literal(state, existing))
            if state.conflict_new_reason is not None and state.conflict_new_reason >= 0:
                clauses.add(state.conflict_new_reason)
                for antecedent in self.clauses[state.conflict_new_reason]:
                    if abs(antecedent) == abs(existing):
                        continue
                    if self.literal_is_false(state, antecedent):
                        clauses.update(self.explain_literal(state, -antecedent))
        return tuple(sorted(clauses))

    def residual_binary_clauses(
        self, base: PropagationState
    ) -> list[tuple[int, int, int]]:
        """Return ``(a, b, clause_id)`` for every residual binary clause."""
        if base.conflicted:
            raise ValueError("cannot simplify under a conflicting base state")
        rows: list[tuple[int, int, int]] = []
        for clause_index, clause in enumerate(self.clauses):
            if any(self.literal_is_true(base, literal) for literal in clause):
                continue
            residual = tuple(
                literal for literal in clause if not self.literal_is_false(base, literal)
            )
            if not residual:
                raise RuntimeError("base closure leaves a false residual clause")
            if len(residual) == 1:
                raise RuntimeError("base closure is not unit-complete")
            if len(residual) == 2:
                rows.append((residual[0], residual[1], clause_index))
        return rows

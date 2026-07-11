"""Balanced permutation-route ensembles for causal statistical controls.

These helpers deliberately operate on sample indices, not cipher state.  Each
route is a bijection, so applying it preserves the observed row multiset while
breaking a designated pairing/order relation.
"""

from __future__ import annotations

import numpy as np


def constrained_permutation(
    size: int, rng: np.random.Generator, *, exclusion_radius: int = 1
) -> np.ndarray:
    """Return a permutation avoiding identity and nearby cyclic alignments."""
    if size < 2 * exclusion_radius + 3:
        raise ValueError("size is too small for the requested cyclic exclusion radius")
    indices = np.arange(size)
    while True:
        permutation = rng.permutation(size)
        offsets = (permutation - indices) % size
        forbidden = np.zeros(size, dtype=bool)
        for offset in range(-exclusion_radius, exclusion_radius + 1):
            forbidden |= offsets == (offset % size)
        if not np.any(forbidden):
            return permutation


def route_ensemble(
    size: int,
    count: int,
    seed: int,
    *,
    exclusion_radius: int = 1,
) -> list[np.ndarray]:
    """Build a reproducible ensemble of globally routed bijections."""
    if count < 1:
        raise ValueError("count must be positive")
    rng = np.random.default_rng(seed)
    return [
        constrained_permutation(size, rng, exclusion_radius=exclusion_radius)
        for _ in range(count)
    ]


def verify_routes(routes: list[np.ndarray], *, exclusion_radius: int = 1) -> dict[str, int | bool]:
    """Check bijectivity and the declared pairing-exclusion condition."""
    if not routes:
        raise ValueError("at least one route is required")
    size = len(routes[0])
    indices = np.arange(size)
    bad = 0
    for route in routes:
        if len(route) != size or len(np.unique(route)) != size:
            return {"all_bijective": False, "forbidden_alignments": -1}
        offsets = (route - indices) % size
        for offset in range(-exclusion_radius, exclusion_radius + 1):
            bad += int(np.sum(offsets == (offset % size)))
    return {"all_bijective": True, "forbidden_alignments": bad}

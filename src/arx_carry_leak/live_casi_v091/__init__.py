"""Vendored live-casi 0.9.1 analysis core.

The snapshot is kept in this namespace so the Nanjing CASI experiments remain
offline-reproducible without shadowing a separately installed ``live_casi``.
"""

from .core import compute_amplified_score, compute_casi_score

__all__ = ["compute_amplified_score", "compute_casi_score"]
__version__ = "0.9.1"

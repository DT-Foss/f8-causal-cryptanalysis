"""
dotcausal - Binary Knowledge Graph Format with Embedded Inference

The .causal format is a binary storage format for causal knowledge graphs
with embedded deterministic inference rules.

Features:
- 72% smaller than SQLite
- 1.9x fact amplification through 3-pass inference
- Zero hallucination (pure deterministic logic)
- Single-file portable format

Usage:
    from dotcausal import CausalFile, Triplet

    # Read
    cf = CausalFile.load("knowledge.causal")
    print(f"Explicit: {len(cf.triplets)}, Inferred: {len(cf.inferred)}")

    # Write
    cf = CausalFile()
    cf.add(Triplet("A", "causes", "B", confidence=0.9))
    cf.run_inference()
    cf.save("output.causal")

Author: David Tom Foss <dtfoss-dev@proton.me>
License: MIT
"""

__version__ = "0.3.1"
__author__ = "David Tom Foss"

from .core import (
    CausalTriplet,
    Triplet,  # Alias
    SemanticCluster,
    KnowledgeGap,
    MAGIC,
    VERSION,
)

from .io import (
    CausalWriter,
    CausalReader,
    CausalFile,  # Unified API
    CausalStorageBackend,
)

from .inference import (
    run_inference,
    detect_mechanism_direction,
    jaro_winkler_similarity,
    calculate_auto_threshold,
    TrigramIndex,
)

# Optional LangChain integration
try:
    from .langchain import CausalRetriever, create_causal_retriever, HAS_LANGCHAIN
except ImportError:
    HAS_LANGCHAIN = False
    CausalRetriever = None
    create_causal_retriever = None

__all__ = [
    # Version
    "__version__",
    # Core classes
    "CausalTriplet",
    "Triplet",
    "SemanticCluster",
    "KnowledgeGap",
    # I/O
    "CausalWriter",
    "CausalReader",
    "CausalFile",
    "CausalStorageBackend",
    # Inference
    "run_inference",
    "detect_mechanism_direction",
    "jaro_winkler_similarity",
    "calculate_auto_threshold",
    "TrigramIndex",
    # LangChain (optional)
    "CausalRetriever",
    "create_causal_retriever",
    "HAS_LANGCHAIN",
    # Constants
    "MAGIC",
    "VERSION",
]

from __future__ import annotations

import numpy as np

from arx_carry_leak.chacha20_operation_flow import (
    FAR,
    flow_graph_manifest,
    nearest_operation_taps,
    operation_flow_graph,
)
from arx_carry_leak.cnf_semantic_topology import CNFSemanticTopology


def test_exact_operation_flow_schedule_and_paths() -> None:
    graph = operation_flow_graph()
    manifest = flow_graph_manifest(graph)
    assert manifest["tap_count"] == 640
    assert graph.parents[0] == ()
    assert graph.parents[1] == (0,)
    assert graph.parents[2] == (1,)
    assert graph.parents[3] == (2,)
    assert graph.parents[4] == (0, 3)
    assert graph.relation(0, 1) == "ancestor_d1"
    assert graph.relation(1, 0) == "descendant_d1"
    assert graph.relation(0, 0) == "same_tap"
    assert int(graph.directed_distances[0, 4]) == 1
    assert int(graph.directed_distances[4, 0]) == FAR
    assert len(graph.forward_split_end) == 16
    assert len(graph.inverse_split_end) == 16
    assert manifest["directed_edge_count"] > 600


def test_level_synchronous_nearest_tap_identity_propagation() -> None:
    # Two sources touch separate clauses; variable 5 is an exact distance-2 tie.
    raw = b"p cnf 6 3\n1 3 0\n2 4 0\n3 4 5 0\n"
    topology = CNFSemanticTopology.from_dimacs(
        raw,
        anchor_groups={"left": [1], "right": [2]},
        maximum_distance=4,
    )
    mapping = [(1,) * 32, (2,) * 32]
    mapping.extend((6,) * 32 for _ in range(638))
    # The synthetic reuse of variable 6 gives the unused taps a common source;
    # only tap identities 0 and 1 are asserted below.
    nearest = nearest_operation_taps(topology, mapping)
    assert int(nearest.distances[1]) == 0
    assert int(nearest.distances[3]) == 1
    assert int(nearest.distances[5]) == 2
    assert 0 in nearest.tap_indices(5)
    assert 1 in nearest.tap_indices(5)
    assert nearest.distances.dtype == np.uint8

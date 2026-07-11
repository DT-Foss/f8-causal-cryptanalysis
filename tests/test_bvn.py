import numpy as np

from arx_carry_leak.bvn import route_ensemble, verify_routes


def test_bvn_routes_are_balanced_and_exclude_nearby_pairings() -> None:
    routes = route_ensemble(128, 8, 20260725)
    verified = verify_routes(routes)
    assert verified == {"all_bijective": True, "forbidden_alignments": 0}
    rows = np.arange(128)
    assert all(np.array_equal(np.sort(rows[route]), rows) for route in routes)

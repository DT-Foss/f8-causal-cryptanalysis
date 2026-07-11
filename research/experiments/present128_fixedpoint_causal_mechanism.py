#!/usr/bin/env python3
"""Mechanism localization for the new PRESENT-128 full-round F8 transfer."""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
from pathlib import Path

import numpy as np

from arx_carry_leak.crypto_causal import CryptoCausalBuilder, CryptoCausalReader
from arx_carry_leak.nano_ciphers import _PRESENT_PERM

_BASE_PATH = Path(__file__).with_name("present128_fullround_causal_f8.py")
_SPEC = importlib.util.spec_from_file_location("present128_fullround_causal_f8", _BASE_PATH)
assert _SPEC is not None and _SPEC.loader is not None
_BASE = importlib.util.module_from_spec(_SPEC); _SPEC.loader.exec_module(_BASE)

FIXED_CELLS = [(3, 0), (20, 21), (23, 21), (40, 42), (43, 42), (60, 63), (62, 63)]
MATCHED_NONFIXED = [(3, 1), (20, 20), (23, 22), (40, 41), (43, 43), (60, 61), (62, 62)]


def _measure(key: int, values: np.ndarray, cells: list[tuple[int, int]], routes: int, seed: int) -> dict:
    state = _BASE._encrypt(values, key, 31); delta = state ^ _BASE._encrypt(values, key, 32)
    sb, db = _BASE._bits(state), _BASE._bits(delta); bank = _BASE._routes(len(values), routes, seed)
    factual_cells = np.asarray([
        _BASE._mi_binary(sb[:, source], db[:, target])
        for source, target in cells
    ])
    null_cells = np.asarray([
        [
            _BASE._mi_binary(sb[:, source], db[route, target])
            for source, target in cells
        ]
        for route in bank
    ])
    factual = float(factual_cells.sum())
    null = null_cells.sum(axis=1)
    cell_rows = []
    for index, (source, target) in enumerate(cells):
        cell_null = null_cells[:, index]
        cell_factual = float(factual_cells[index])
        cell_rows.append({
            "source_bit": source,
            "target_bit": target,
            "factual_mi": cell_factual,
            "bvn_mean": float(cell_null.mean()),
            "bvn_max": float(cell_null.max()),
            "z": float((cell_factual - cell_null.mean()) / (cell_null.std(ddof=1) + 1e-30)),
            "above_all_bvn_routes": bool(cell_factual > cell_null.max()),
        })
    return {
        "factual_mi": factual,
        "bvn_mean": float(null.mean()),
        "bvn_max": float(null.max()),
        "z": float((factual-null.mean())/(null.std(ddof=1)+1e-30)),
        "above_all_bvn_routes": bool(factual>null.max()),
        "cells": cell_rows,
    }


def main() -> None:
    parser=argparse.ArgumentParser(); parser.add_argument("--output",type=Path,required=True); parser.add_argument("--causal-output",type=Path,required=True)
    parser.add_argument("--pairs",type=int,default=5000); parser.add_argument("--keys",type=int,default=5); parser.add_argument("--routes",type=int,default=16); parser.add_argument("--seed-base",type=int,default=88228001); args=parser.parse_args()
    _BASE._kat(); fixed_points=[index for index,target in enumerate(_PRESENT_PERM) if index==target]
    if fixed_points != [0,21,42,63]: raise RuntimeError(f"unexpected PRESENT pLayer fixed points: {fixed_points}")
    rows=[]
    for index in range(args.keys):
        seed=args.seed_base+1009*index; rng=np.random.default_rng(seed); key=int.from_bytes(rng.bytes(16),"big"); values=rng.integers(0,2**64,size=args.pairs,dtype=np.uint64)
        print(f"PRESENT-128 fixed-point mechanism key={index+1}/{args.keys}",flush=True)
        rows.append({"key_index":index,"fixed_point_cells":_measure(key,values,FIXED_CELLS,args.routes,seed^0xF1E),"matched_nonfixed_cells":_measure(key,values,MATCHED_NONFIXED,args.routes,seed^0xF1E)})
    builder=CryptoCausalBuilder(experiment="present128_fixedpoint_causal_mechanism",parameters={"prediction_before_measurement":"fullround F8 mass is concentrated at pLayer fixed targets 0,21,42,63","round_boundary":"R31_to_R32","fixed_points":fixed_points,"fixed_cells":[list(x) for x in FIXED_CELLS],"matched_nonfixed_cells":[list(x) for x in MATCHED_NONFIXED],"pairs_per_key":args.pairs,"keys":args.keys,"bvn_routes":args.routes})
    for label,cells in (("fixed",FIXED_CELLS),("nonfixed_control",MATCHED_NONFIXED)):
        values=[row["fixed_point_cells" if label=="fixed" else "matched_nonfixed_cells"] for row in rows]
        builder.add_triplet(edge_id=f"present128-{label}",trigger=f"present128:player_{label}",mechanism="matched_fullround_f8_cell_aggregation",outcome="present128:r31_r32_dependency",confidence=min(.999,1-np.exp(-max(np.mean([x['z'] for x in values]),0)/8)),evidence_kind="formula_preregistered_fixedpoint_mechanism_test",source="PRESENT_pLayer_fixedpoint_equation",attrs={"cells":[list(x) for x in cells],"mean_factual_mi":float(np.mean([x['factual_mi'] for x in values])),"mean_bvn_mi":float(np.mean([x['bvn_mean'] for x in values])),"mean_z":float(np.mean([x['z'] for x in values])),"all_above_bvn":all(x['above_all_bvn_routes'] for x in values)})
    causal=builder.save(args.causal_output); reader=CryptoCausalReader(args.causal_output)
    if not reader.verify_provenance() or len(reader.triplets(include_inferred=False))!=2: raise RuntimeError("reader gate failed")
    fixed_mean=float(np.mean([row['fixed_point_cells']['factual_mi'] for row in rows])); control_mean=float(np.mean([row['matched_nonfixed_cells']['factual_mi'] for row in rows])); ratio=fixed_mean/(control_mean+1e-30)
    payload={"schema":"present128-fixedpoint-causal-mechanism-v1","evidence_stage":"MECHANISM_LOCALIZED","prediction":"pLayer fixed targets carry the dominant PRESENT-128 fullround F8 relation","pLayer_fixed_points":fixed_points,"runs":rows,"fixed_to_matched_factual_mi_ratio":ratio,"causal":causal,"reader_triplets":reader.triplets(include_inferred=False)}
    raw=(json.dumps(payload,indent=2,sort_keys=True)+"\n").encode(); args.output.parent.mkdir(parents=True,exist_ok=True); args.output.write_bytes(raw)
    print(json.dumps({"output":str(args.output),"sha256":hashlib.sha256(raw).hexdigest(),"fixed_mean_mi":fixed_mean,"control_mean_mi":control_mean,"ratio":ratio},indent=2))


if __name__=="__main__": main()

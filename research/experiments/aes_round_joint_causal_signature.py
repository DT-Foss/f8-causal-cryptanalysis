#!/usr/bin/env python3
"""Reader-only reverse AES round classification from source-output -> delta causal tables."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path

import numpy as np

from arx_carry_leak.atlas import aes_inverse_linear_layer, aes_inverse_shift_rows, aes_prefix_batch
from arx_carry_leak.crypto_causal import CryptoCausalBuilder, CryptoCausalReader


def _represented(first: np.ndarray, second: np.ndarray, rounds: int, rep: str) -> tuple[np.ndarray, np.ndarray]:
    if rep == "identity": return first, second
    transform = aes_inverse_shift_rows if rounds == 10 else aes_inverse_linear_layer
    return transform(first), transform(second)


def _fit(rows: dict[str, list[tuple[np.ndarray, np.ndarray]]], labels: list[str], bins: int) -> tuple[dict[str, np.ndarray], np.ndarray]:
    shift = 8 - int(np.log2(bins))
    counts = {}
    for label in labels:
        source = np.concatenate([item[0] for item in rows[label]]) >> shift
        delta = np.concatenate([item[1] for item in rows[label]]) >> shift
        table = np.zeros((16, 16, bins, bins), dtype=float)
        for i in range(16):
            for j in range(16):
                table[i, j] = np.bincount(source[:, i].astype(np.int64) * bins + delta[:, j], minlength=bins * bins).reshape(bins, bins)
        counts[label] = table
    total = np.sum(np.stack(list(counts.values())), axis=0)
    background = (total + 1.0) / (total.sum(axis=3, keepdims=True) + bins)
    model = {label: (counts[label] + 1.0) / (counts[label].sum(axis=3, keepdims=True) + bins) for label in labels}
    return model, background


def _build(path: Path, condition: str, params: dict, model: dict[str, np.ndarray], background: np.ndarray, rows_hash: str) -> dict:
    builder = CryptoCausalBuilder(experiment="aes_round_joint_causal_signature", parameters={**params, "condition": condition, "source_delta_train_rows_sha256": rows_hash, "direct_output_causal_graph": True, "causal_header": {"codec": "joint-source-delta-conditional-table", "stage_chain": ["paired_cipher_outputs", "source_output", "xor_delta", "quantize", "P(delta|source,class)", "causal_zlib", "reader_reverse_round_query"], "writer_model_forbidden_at_holdout": True}})
    for label, table in model.items():
        for i in range(16):
            for j in range(16):
                for source_bin in range(table.shape[2]):
                    for delta_bin in range(table.shape[3]):
                        log_lift = float(np.log(table[i,j,source_bin,delta_bin] / background[i,j,source_bin,delta_bin]))
                        builder.add_triplet(edge_id=f"{condition}-{label}-s{i}b{source_bin}-d{j}b{delta_bin}", trigger=f"{condition}:class_{label}:source_byte_{i}:bin_{source_bin}", mechanism="empirical_joint_cipher_output_transition_compressed", outcome=f"{condition}:delta_byte_{j}:bin_{delta_bin}", confidence=min(.999,max(0.,1-np.exp(-max(log_lift,0.)))), evidence_kind="direct_cipher_output_joint_signature", source="embedded_source_delta_train_rows_hash", attrs={"log_lift": log_lift})
    stats=builder.save(path)
    reader=CryptoCausalReader(path)
    if not reader.verify_provenance(): raise RuntimeError("joint graph reader provenance failed")
    return stats


_TRIGGER = re.compile(r":class_(.+):source_byte_(\d+):bin_(\d+)$")
_OUTCOME = re.compile(r":delta_byte_(\d+):bin_(\d+)$")


def _reader_model(reader: CryptoCausalReader, labels: list[str], bins: int) -> dict[str, np.ndarray]:
    model={label:np.zeros((16,16,bins,bins),dtype=float) for label in labels}; seen=0
    for edge in reader.triplets(include_inferred=False):
        trigger,outcome=_TRIGGER.search(edge["trigger"]),_OUTCOME.search(edge["outcome"])
        if trigger is None or outcome is None: continue
        label,i,x=trigger.group(1),int(trigger.group(2)),int(trigger.group(3)); j,y=map(int,outcome.groups())
        if label in model: model[label][i,j,x,y]=float(edge["attrs"]["log_lift"]); seen+=1
    expected=len(labels)*16*16*bins*bins
    if seen!=expected: raise RuntimeError(f"reader recovered {seen}, expected {expected} joint edges")
    return model


def _classify(model: dict[str,np.ndarray], source: np.ndarray, delta: np.ndarray, bins: int) -> tuple[str,dict[str,float]]:
    shift=8-int(np.log2(bins)); src=source>>shift; out=delta>>shift
    scores={}
    for label,table in model.items():
        score=0.0
        for i in range(16):
            for j in range(16): score+=float(table[i,j,src[:,i],out[:,j]].sum())
        scores[label]=score
    return max(scores,key=scores.get),scores


def main() -> int:
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output",type=Path,required=True); parser.add_argument("--causal-output",type=Path,required=True)
    parser.add_argument("--rounds",type=int,nargs="+",default=[3,4,10]); parser.add_argument("--representations",choices=["identity","peel-final-linear"],nargs="+",default=["identity","peel-final-linear"])
    parser.add_argument("--bits",type=int,nargs="+",default=[0,31,64,127]); parser.add_argument("--pairs",type=int,default=3000); parser.add_argument("--seeds",type=int,default=10); parser.add_argument("--train-seeds",type=int,default=5); parser.add_argument("--bins",type=int,default=4); parser.add_argument("--seed-base",type=int,default=1785001)
    args=parser.parse_args()
    if args.train_seeds<1 or args.train_seeds>=args.seeds: raise ValueError("train-seeds must be in [1,seeds)")
    labels=[f"r{rounds}-{rep}" for rounds in args.rounds for rep in args.representations]; data={label:[] for label in labels}
    for seed_index in range(args.seeds):
        seed=args.seed_base+1009*seed_index; rng=np.random.default_rng(seed); key=rng.integers(0,256,size=16,dtype=np.uint8); plaintexts=rng.integers(0,256,size=(args.pairs,16),dtype=np.uint8)
        for rounds in args.rounds:
            print(f"aes joint causal signature seed={seed} rounds={rounds}",flush=True); first=aes_prefix_batch(key,plaintexts,rounds)
            for bit in args.bits:
                paired=plaintexts.copy(); paired[:,bit//8]^=np.uint8(1<<(bit%8)); second=aes_prefix_batch(key,paired,rounds)
                for rep in args.representations:
                    source,paired_output=_represented(first,second,rounds,rep); data[f"r{rounds}-{rep}"].append((source,source^paired_output))
    split=args.train_seeds*len(args.bits); train={label:data[label][:split] for label in labels}; model,background=_fit(train,labels,args.bins)
    rows_hash=hashlib.sha256(b"".join(np.concatenate([x[0] for x in train[label]]).tobytes()+np.concatenate([x[1] for x in train[label]]).tobytes() for label in labels)).hexdigest()
    params={"rounds":args.rounds,"representations":args.representations,"bits":args.bits,"bins":args.bins,"train_seeds":args.train_seeds,"pairs_per_seed":args.pairs}
    stats=_build(args.causal_output,"aes-round-joint-output-signature",params,model,background,rows_hash); reader=CryptoCausalReader(args.causal_output); reader_model=_reader_model(reader,labels,args.bins)
    trials=[]
    for label in labels:
        for source,delta in data[label][split:]:
            predicted,scores=_classify(reader_model,source,delta,args.bins); trials.append({"actual":label,"predicted":predicted,"correct":predicted==label,"scores":scores})
    per_class={label:{"correct":sum(t["correct"] for t in trials if t["actual"]==label),"total":sum(t["actual"]==label for t in trials)} for label in labels}
    for value in per_class.values(): value["accuracy"]=value["correct"]/max(value["total"],1)
    payload={"schema":"aes-round-joint-causal-signature-v1","parameters":params,"causal":stats,"holdout_trials":trials,"overall_accuracy":float(np.mean([t["correct"] for t in trials])),"chance":1/len(labels),"per_class":per_class,"scope":"reader-only reverse classification from direct source-output to differential causal tables; not key recovery or full-AES break"}
    args.output.parent.mkdir(parents=True,exist_ok=True); encoded=(json.dumps(payload,indent=2,sort_keys=True)+"\n").encode(); args.output.write_bytes(encoded); print(json.dumps({"output":str(args.output),"sha256":hashlib.sha256(encoded).hexdigest(),"overall_accuracy":payload["overall_accuracy"],"per_class":per_class},indent=2)); return 0


if __name__=="__main__": raise SystemExit(main())

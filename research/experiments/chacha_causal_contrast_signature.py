#!/usr/bin/env python3
"""Direct output-causal contrast profiles for ChaCha round classes."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
from pathlib import Path

import numpy as np

from arx_carry_leak.atlas import chacha_counter_blocks
from arx_carry_leak.crypto_causal import CryptoCausalBuilder, CryptoCausalReader
from arx_carry_leak.bvn import route_ensemble, verify_routes


def _deficits(delta):
    values=[]
    for i in range(delta.shape[1]):
        counts=np.bincount(delta[:,i],minlength=256); p=counts[counts>0]/len(delta); values.append(8+float(np.sum(p*np.log2(p))))
    return np.asarray(values)


def _contrast(first,second,routes,seed,route_mode="shuffle"):
    actual=_deficits(first^second)
    if route_mode=="shuffle":
        rng=np.random.default_rng(seed); permutations=[rng.permutation(len(second)) for _ in range(routes)]
    elif route_mode=="bvn":
        permutations=route_ensemble(len(second),routes,seed)
        if not verify_routes(permutations)["all_bijective"] or verify_routes(permutations)["forbidden_alignments"]:raise RuntimeError("invalid BvN routes")
    else:raise ValueError("unknown route mode")
    controls=np.stack([_deficits(first^second[permutation]) for permutation in permutations])
    return actual-controls.mean(axis=0)


def _normalize_feature(feature, mode):
    if mode=="none":return feature
    if mode=="l2":return feature/(np.linalg.norm(feature)+1e-12)
    if mode=="centered-l2":
        centered=feature-feature.mean()
        return centered/(np.linalg.norm(centered)+1e-12)
    if mode=="rank":
        ranks=np.empty_like(feature)
        ranks[np.argsort(feature,kind="stable")]=np.arange(len(feature),dtype=float)
        return ranks/max(len(feature)-1,1)
    raise ValueError("unknown feature normalization")


def _build(path,params,means,sds,train_hash,feature_indices):
    builder=CryptoCausalBuilder(experiment="chacha_causal_contrast_signature",parameters={**params,"direct_output_causal_graph":True,"train_output_hash":train_hash,"causal_header":{"codec":"factual-minus-repairing-contrast-profile","stage_chain":["counter-paired cipher outputs","factual XOR delta","row-repair counterfactuals","per-byte entropy contrast","causal zlib","reader reverse round query"],"writer_model_forbidden_at_holdout":True}})
    for label in means:
        for index in feature_indices:
            mean,sd=means[label][index],sds[label][index]
            builder.add_triplet(edge_id=f"{label}-f{index}",trigger=f"chacha:class_{label}",mechanism="factual_minus_repairing_output_profile_compressed",outcome=f"chacha:entropy_contrast_byte_{index}",confidence=min(.999,max(0.,1-np.exp(-abs(mean)/(sd+1e-12)))),evidence_kind="direct_cipher_output_interventional_profile",source="embedded_train_output_hash",attrs={"mean":float(mean),"sd":float(sd)})
    stats=builder.save(path); reader=CryptoCausalReader(path)
    if not reader.verify_provenance():raise RuntimeError("reader failed")
    return stats


_T=re.compile(r":class_(.+)$");_O=re.compile(r":entropy_contrast_byte_(\d+)$")
def _reader(reader,labels,feature_indices):
    means={label:np.zeros(64) for label in labels};sds={label:np.zeros(64) for label in labels};count=0
    for edge in reader.triplets(include_inferred=False):
        t,o=_T.search(edge["trigger"]),_O.search(edge["outcome"])
        if t and o and t.group(1) in means:
            means[t.group(1)][int(o.group(1))]=edge["attrs"]["mean"];sds[t.group(1)][int(o.group(1))]=max(edge["attrs"]["sd"],1e-9);count+=1
    if count!=len(labels)*len(feature_indices):raise RuntimeError("reader reconstruction incomplete")
    return means,sds
def _classify(means,sds,feature,feature_indices):
    scores={label:float(-.5*np.sum(((feature[feature_indices]-means[label][feature_indices])/sds[label][feature_indices])**2+2*np.log(sds[label][feature_indices]))) for label in means};return max(scores,key=scores.get),scores


def _output_view(counters, rounds, seed, view, mask_words=()):
    blocks=chacha_counter_blocks(counters,rounds,seed,feedforward=view != "core")
    if view == "mask-counter-word":
        blocks=blocks.copy();blocks[:,48:52]=0
    if mask_words:
        blocks=blocks.copy()
        for word in mask_words:blocks[:,4*word:4*(word+1)]=0
    return blocks

def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument("--output",type=Path,required=True);p.add_argument("--causal-output",type=Path,required=True);p.add_argument("--rounds",type=int,nargs="+",default=[3,4,20]);p.add_argument("--bits",type=int,nargs="+",default=[0,7,15,31]);p.add_argument("--holdout-bits",type=int,nargs="+",default=None);p.add_argument("--difference-mode",choices=["bit","byte"],default="bit");p.add_argument("--pairs",type=int,default=5000);p.add_argument("--seeds",type=int,default=10);p.add_argument("--train-seeds",type=int,default=5);p.add_argument("--routes",type=int,default=16);p.add_argument("--route-mode",choices=["shuffle","bvn"],default="shuffle");p.add_argument("--counter-mode",choices=["random","sequential"],default="random");p.add_argument("--holdout-counter-mode",choices=["random","sequential"],default=None);p.add_argument("--output-view",choices=["full","core","mask-counter-word"],default="full");p.add_argument("--mask-words",type=int,nargs="*",default=[]);p.add_argument("--feature-normalization",choices=["none","l2","centered-l2","rank"],default="none");p.add_argument("--variance-mode",choices=["class","pooled"],default="class");p.add_argument("--feature-indices",type=int,nargs="+",default=list(range(64)));p.add_argument("--seed-base",type=int,default=2885001);a=p.parse_args()
    limit=32 if a.difference_mode=="bit" else 4
    if a.train_seeds<1 or a.train_seeds>=a.seeds or any(index<0 or index>=64 for index in a.feature_indices) or any(word<0 or word>=16 for word in a.mask_words) or any(bit<0 or bit>=limit for bit in set(a.bits)|set(a.holdout_bits or a.bits)):raise ValueError("invalid split, words, feature indices, or differences")
    holdout_bits=a.holdout_bits or a.bits;holdout_counter_mode=a.holdout_counter_mode or a.counter_mode
    if any(bit<0 or bit>=32 for bit in set(a.bits)|set(holdout_bits)):raise ValueError("ChaCha counter bits must be in [0,31]")
    labels=[f"r{r}" for r in a.rounds];data={label:[] for label in labels};evaluation_data={label:[] for label in labels}
    for si in range(a.seeds):
        seed=a.seed_base+1009*si;rng=np.random.default_rng(seed);mode=a.counter_mode if si<a.train_seeds else holdout_counter_mode;counters=rng.integers(0,2**32,size=a.pairs,dtype=np.uint32) if mode=="random" else np.arange(a.pairs,dtype=np.uint32)
        for rounds in a.rounds:
            print(f"chacha causal contrast seed={seed} rounds={rounds}",flush=True);first=_output_view(counters,rounds,seed,a.output_view,a.mask_words)
            for bit in sorted(set(a.bits)|set(holdout_bits)):
                # Same BvN repair bank for each round class of this precise
                # counter-pair batch; see the AES counterpart for rationale.
                mask=np.uint32(1<<bit) if a.difference_mode=="bit" else np.uint32(0xFF<<(8*bit))
                feature=_normalize_feature(_contrast(first,_output_view(counters^mask,rounds,seed,a.output_view,a.mask_words),a.routes,seed^bit,a.route_mode),a.feature_normalization)
                if bit in a.bits:data[f"r{rounds}"].append(feature)
                if bit in holdout_bits:evaluation_data[f"r{rounds}"].append(feature)
    split=a.train_seeds*len(a.bits);evaluation_split=a.train_seeds*len(holdout_bits);means={l:np.mean(data[l][:split],axis=0) for l in labels};sds={l:np.std(data[l][:split],axis=0,ddof=1)+1e-9 for l in labels}
    if a.variance_mode=="pooled":
        pooled=np.std(np.concatenate([data[label][:split] for label in labels]),axis=0,ddof=1)+1e-9
        sds={label:pooled.copy() for label in labels}
    train_hash=hashlib.sha256(np.asarray([data[l][:split] for l in labels]).tobytes()).hexdigest();params={"rounds":a.rounds,"bits":a.bits,"holdout_bits":holdout_bits,"difference_mode":a.difference_mode,"pairs_per_seed":a.pairs,"train_seeds":a.train_seeds,"repairing_routes":a.routes,"route_mode":a.route_mode,"repair_route_seed_strategy":"shared_per_seed_input_difference_across_round_classes","counter_mode":a.counter_mode,"holdout_counter_mode":holdout_counter_mode,"output_view":a.output_view,"mask_words":a.mask_words,"feature_normalization":a.feature_normalization,"variance_mode":a.variance_mode,"feature_indices":a.feature_indices};stats=_build(a.causal_output,params,means,sds,train_hash,a.feature_indices);reader=CryptoCausalReader(a.causal_output);rmeans,rsds=_reader(reader,labels,a.feature_indices)
    trials=[]
    for label in labels:
        for feature in evaluation_data[label][evaluation_split:]:
            pred,scores=_classify(rmeans,rsds,feature,a.feature_indices);trials.append({"actual":label,"predicted":pred,"correct":pred==label,"scores":scores})
    per={l:{"correct":sum(t["correct"] for t in trials if t["actual"]==l),"total":sum(t["actual"]==l for t in trials)} for l in labels}
    for v in per.values():v["accuracy"]=v["correct"]/max(v["total"],1)
    payload={"schema":"chacha-causal-contrast-signature-v1","parameters":params,"causal":stats,"overall_accuracy":float(np.mean([t["correct"] for t in trials])),"chance":1/len(labels),"per_class":per,"trials":trials,"scope":"direct ChaCha output causal contrast profile and reader-only reverse reduced-round class query; not key recovery"};encoded=(json.dumps(payload,indent=2,sort_keys=True)+"\n").encode();a.output.parent.mkdir(parents=True,exist_ok=True);a.output.write_bytes(encoded);print(json.dumps({"output":str(a.output),"sha256":hashlib.sha256(encoded).hexdigest(),"overall_accuracy":payload["overall_accuracy"],"per_class":per},indent=2));return 0
if __name__=="__main__":raise SystemExit(main())

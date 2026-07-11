#!/usr/bin/env python3
"""Causal contrast profiles from AES output pairs, with reader-only reverse classification."""

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
from arx_carry_leak.bvn import route_ensemble, verify_routes


def _represent(first, second, rounds, rep):
    if rep == "identity": return first, second
    transform = aes_inverse_shift_rows if rounds == 10 else aes_inverse_linear_layer
    return transform(first), transform(second)


def _entropy_deficits(delta: np.ndarray) -> np.ndarray:
    values=[]
    for byte in range(delta.shape[1]):
        counts=np.bincount(delta[:,byte],minlength=256); p=counts[counts>0]/len(delta); values.append(8.0+float(np.sum(p*np.log2(p))))
    return np.asarray(values)


def _bit_bias_profile(delta: np.ndarray) -> np.ndarray:
    bits=np.unpackbits(delta,axis=1).reshape(len(delta),delta.shape[1],8)
    ones=bits.sum(axis=0).astype(float)
    return np.mean(4.0*(ones-len(delta)/2.0)**2/len(delta),axis=1)


def _collision_deficits(delta: np.ndarray) -> np.ndarray:
    """Per-byte collision deficit, an entropy-family formula ablation."""
    values=[]
    for byte in range(delta.shape[1]):
        counts=np.bincount(delta[:,byte],minlength=256).astype(float); p=counts/len(delta)
        values.append(float(np.sum(p*p)-1.0/256.0))
    return np.asarray(values)


def _profile_function(profile_mode: str):
    return {"entropy":_entropy_deficits,"bitbias":_bit_bias_profile,"collision":_collision_deficits}[profile_mode]


def _contrast(source: np.ndarray, paired: np.ndarray, routes: int, seed: int, profile_mode: str="entropy", route_mode: str="shuffle") -> np.ndarray:
    profile=_profile_function(profile_mode)
    actual=profile(source^paired)
    if route_mode=="shuffle":
        rng=np.random.default_rng(seed); permutations=[rng.permutation(len(paired)) for _ in range(routes)]
    elif route_mode=="bvn":
        permutations=route_ensemble(len(paired),routes,seed)
        if not verify_routes(permutations)["all_bijective"] or verify_routes(permutations)["forbidden_alignments"]:
            raise RuntimeError("invalid BvN routes")
    else: raise ValueError("unknown route mode")
    controls=np.stack([profile(source^paired[permutation]) for permutation in permutations])
    return actual-controls.mean(axis=0)


def _build(path, condition, params, means, sds, rows_hash, feature_indices):
    profile_mode=params["profile_mode"]
    builder=CryptoCausalBuilder(experiment="aes_causal_contrast_signature",parameters={**params,"condition":condition,"output_profile_train_sha256":rows_hash,"direct_output_causal_graph":True,"causal_header":{"codec":"factual-minus-repairing-contrast-profile","stage_chain":["paired_cipher_outputs","factual_xor_delta","row_repair_counterfactuals",f"per_byte_{profile_mode}_contrast","causal_zlib","reader_reverse_class_query"],"writer_model_forbidden_at_holdout":True}})
    for label in means:
        for index in feature_indices:
            mean,sd=means[label][index],sds[label][index]
            builder.add_triplet(edge_id=f"{condition}-{label}-f{index}",trigger=f"{condition}:class_{label}",mechanism="factual_minus_repairing_output_profile_compressed",outcome=f"{condition}:{profile_mode}_contrast_byte_{index}",confidence=min(.999,max(0.,1-np.exp(-abs(mean)/(sd+1e-12)))),evidence_kind="direct_cipher_output_interventional_profile",source="embedded_output_profile_train_hash",attrs={"mean":float(mean),"sd":float(sd)})
    stats=builder.save(path); reader=CryptoCausalReader(path)
    if not reader.verify_provenance(): raise RuntimeError("contrast graph reader failed")
    return stats


_T=re.compile(r":class_(.+)$"); _O=re.compile(r":(?:entropy|bitbias|collision)_contrast_byte_(\d+)$")


def _reader_model(reader,labels,feature_indices):
    means={label:np.zeros(16) for label in labels}; sds={label:np.zeros(16) for label in labels}; count=0
    for edge in reader.triplets(include_inferred=False):
        t,o=_T.search(edge["trigger"]),_O.search(edge["outcome"])
        if t is None or o is None: continue
        label,index=t.group(1),int(o.group(1))
        if label in means: means[label][index]=edge["attrs"]["mean"]; sds[label][index]=max(edge["attrs"]["sd"],1e-9); count+=1
    if count!=len(labels)*len(feature_indices): raise RuntimeError("reader did not reconstruct contrast profiles")
    return means,sds


def _classify(means,sds,feature,feature_indices):
    scores={label:float(-0.5*np.sum(((feature[feature_indices]-means[label][feature_indices])/sds[label][feature_indices])**2+2*np.log(sds[label][feature_indices]))) for label in means}
    return max(scores,key=scores.get),scores


def _plaintext_batch(mode: str, pairs: int, rng: np.random.Generator) -> np.ndarray:
    if mode=="random":return rng.integers(0,256,size=(pairs,16),dtype=np.uint8)
    if mode=="counter":
        values=np.arange(pairs,dtype=np.uint64);plain=np.zeros((pairs,16),dtype=np.uint8)
        for byte in range(8):plain[:,byte]=((values>>(8*byte))&0xFF).astype(np.uint8)
        return plain
    if mode=="mixed":
        random_rows=rng.integers(0,256,size=(pairs,16),dtype=np.uint8)
        counter_rows=_plaintext_batch("counter",pairs,rng)
        random_rows[::2]=counter_rows[::2]
        return random_rows
    raise ValueError("unknown plaintext mode")


def main():
    p=argparse.ArgumentParser(description=__doc__); p.add_argument("--output",type=Path,required=True); p.add_argument("--causal-output",type=Path,required=True); p.add_argument("--rounds",type=int,nargs="+",default=[3,4,10]); p.add_argument("--representations",choices=["identity","peel-final-linear"],nargs="+",default=["identity","peel-final-linear"]); p.add_argument("--bits",type=int,nargs="+",default=[0,31,64,127]); p.add_argument("--holdout-bits",type=int,nargs="+",default=None); p.add_argument("--difference-mode",choices=["bit","byte"],default="bit"); p.add_argument("--pairs",type=int,default=5000); p.add_argument("--seeds",type=int,default=10); p.add_argument("--train-seeds",type=int,default=5); p.add_argument("--routes",type=int,default=16); p.add_argument("--route-mode",choices=["shuffle","bvn"],default="shuffle"); p.add_argument("--plaintext-mode",choices=["random","counter","mixed"],default="random"); p.add_argument("--holdout-plaintext-mode",choices=["random","counter","mixed"],default=None); p.add_argument("--profile-mode",choices=["entropy","bitbias","collision"],default="entropy"); p.add_argument("--variance-mode",choices=["class","pooled"],default="class"); p.add_argument("--feature-indices",type=int,nargs="+",default=list(range(16))); p.add_argument("--seed-base",type=int,default=1985001); a=p.parse_args()
    if a.train_seeds<1 or a.train_seeds>=a.seeds or any(index<0 or index>=16 for index in a.feature_indices): raise ValueError("invalid train-seeds or feature indices")
    limit=128 if a.difference_mode=="bit" else 16
    if any(bit<0 or bit>=limit for bit in set(a.bits)|set(a.holdout_bits or a.bits)): raise ValueError("invalid difference indices")
    holdout_bits=a.holdout_bits or a.bits;holdout_plaintext_mode=a.holdout_plaintext_mode or a.plaintext_mode
    labels=[f"r{r}-{rep}" for r in a.rounds for rep in a.representations]; data={label:[] for label in labels}; evaluation_data={label:[] for label in labels}
    for seed_index in range(a.seeds):
        seed=a.seed_base+1009*seed_index; rng=np.random.default_rng(seed); key=rng.integers(0,256,size=16,dtype=np.uint8); plaintexts=_plaintext_batch(a.plaintext_mode if seed_index<a.train_seeds else holdout_plaintext_mode,a.pairs,rng)
        for rounds in a.rounds:
            print(f"aes causal contrast seed={seed} rounds={rounds}",flush=True); first=aes_prefix_batch(key,plaintexts,rounds)
            for bit in sorted(set(a.bits) | set(holdout_bits)):
                pp=plaintexts.copy()
                if a.difference_mode=="bit":pp[:,bit//8]^=np.uint8(1<<(bit%8))
                else:pp[:,bit]^=np.uint8(0xFF)
                second=aes_prefix_batch(key,pp,rounds)
                for rep in a.representations:
                    # The repair ensemble is intentionally shared across every
                    # round/representation class for this exact input-pair
                    # batch.  Otherwise finite-route estimation noise itself
                    # becomes a class-specific feature.
                    feature=_contrast(*_represent(first,second,rounds,rep),a.routes,seed^bit,a.profile_mode,a.route_mode)
                    label=f"r{rounds}-{rep}"
                    if bit in a.bits: data[label].append(feature)
                    if bit in holdout_bits: evaluation_data[label].append(feature)
    split=a.train_seeds*len(a.bits); evaluation_split=a.train_seeds*len(holdout_bits); means={label:np.mean(data[label][:split],axis=0) for label in labels}; sds={label:np.std(data[label][:split],axis=0,ddof=1)+1e-9 for label in labels}
    if a.variance_mode=="pooled":
        pooled=np.std(np.concatenate([data[label][:split] for label in labels]),axis=0,ddof=1)+1e-9
        sds={label:pooled.copy() for label in labels}
    rows_hash=hashlib.sha256(np.asarray([data[label][:split] for label in labels]).tobytes()).hexdigest(); params={"rounds":a.rounds,"representations":a.representations,"bits":a.bits,"holdout_bits":holdout_bits,"difference_mode":a.difference_mode,"pairs_per_seed":a.pairs,"train_seeds":a.train_seeds,"repairing_routes":a.routes,"route_mode":a.route_mode,"repair_route_seed_strategy":"shared_per_seed_input_difference_across_classes","plaintext_mode":a.plaintext_mode,"holdout_plaintext_mode":holdout_plaintext_mode,"profile_mode":a.profile_mode,"variance_mode":a.variance_mode,"feature_indices":a.feature_indices}; stats=_build(a.causal_output,"aes-causal-contrast-signature",params,means,sds,rows_hash,a.feature_indices); reader=CryptoCausalReader(a.causal_output); rmeans,rsds=_reader_model(reader,labels,a.feature_indices)
    trials=[]
    for label in labels:
        for feature in evaluation_data[label][evaluation_split:]:
            predicted,scores=_classify(rmeans,rsds,feature,a.feature_indices); trials.append({"actual":label,"predicted":predicted,"correct":predicted==label,"scores":scores})
    per_class={label:{"correct":sum(t["correct"] for t in trials if t["actual"]==label),"total":sum(t["actual"]==label for t in trials)} for label in labels}
    for value in per_class.values():value["accuracy"]=value["correct"]/max(value["total"],1)
    payload={"schema":"aes-causal-contrast-signature-v1","parameters":params,"causal":stats,"overall_accuracy":float(np.mean([t["correct"] for t in trials])),"chance":1/len(labels),"per_class":per_class,"trials":trials,"scope":"direct cipher-output factual-vs-counterfactual causal compression and reader-only reverse round-class query; not key recovery"}; encoded=(json.dumps(payload,indent=2,sort_keys=True)+"\n").encode(); a.output.parent.mkdir(parents=True,exist_ok=True);a.output.write_bytes(encoded);print(json.dumps({"output":str(a.output),"sha256":hashlib.sha256(encoded).hexdigest(),"overall_accuracy":payload["overall_accuracy"],"per_class":per_class},indent=2));return 0


if __name__=="__main__":raise SystemExit(main())

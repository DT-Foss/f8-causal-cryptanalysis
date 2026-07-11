#!/usr/bin/env python3
"""Direct causal-output contrast test for deterministic ML-KEM coin-bit pairs."""

from __future__ import annotations

import argparse
import ctypes
import hashlib
import importlib
import json
import re
import sys
from pathlib import Path

import numpy as np

from arx_carry_leak.crypto_causal import CryptoCausalBuilder, CryptoCausalReader


VARIANTS={"mlkem512":("pqcrypto.kem.ml_kem_512","PQCLEAN_MLKEM512_CLEAN")}

def _lib(module_path):
    module=importlib.import_module(module_path);root=Path(module.__file__).parents[1]/"_kem";stem=Path(module.__file__).stem;preferred=root/f"{stem}.cpython-{sys.version_info.major}{sys.version_info.minor}-darwin.so"
    if preferred.exists():return module,ctypes.CDLL(str(preferred))
    candidates=list(root.glob(f"{stem}*.so"));
    if len(candidates)!=1:raise RuntimeError("no ABI backend")
    return module,ctypes.CDLL(str(candidates[0]))

def _deficits(delta):
    return np.asarray([8+float(np.sum((lambda p:p*np.log2(p))( (lambda c:c[c>0]/len(delta))(np.bincount(delta[:,i],minlength=256)) ))) for i in range(delta.shape[1])])

def _contrast(first,second,routes,seed):
    actual=_deficits(first^second);rng=np.random.default_rng(seed);ctrl=np.stack([_deficits(first^second[rng.permutation(len(second))]) for _ in range(routes)]);return actual-ctrl.mean(axis=0)

def _build(path,params,means,sds,train_hash):
    width=len(next(iter(means.values())));builder=CryptoCausalBuilder(experiment="mlkem_coin_causal_contrast",parameters={**params,"direct_output_causal_graph":True,"train_ciphertext_hash":train_hash,"causal_header":{"codec":"factual-minus-repairing-contrast-profile","stage_chain":["fixed-key deterministic ML-KEM coins","one-bit coin intervention","paired ciphertexts","row-repair counterfactuals","per-byte entropy contrast","causal zlib","reader reverse coin-bit query"],"writer_model_forbidden_at_holdout":True}})
    for bit in means:
        for i,(mean,sd) in enumerate(zip(means[bit],sds[bit],strict=True)):
            builder.add_triplet(edge_id=f"coinbit{bit}-f{i}",trigger=f"mlkem:coin_xor_bit_{bit}",mechanism="factual_minus_repairing_ciphertext_profile_compressed",outcome=f"mlkem:ciphertext_entropy_contrast_byte_{i}",confidence=min(.999,max(0.,1-np.exp(-abs(mean)/(sd+1e-12)))),evidence_kind="direct_deterministic_encapsulation_output_profile",source="embedded_train_ciphertext_hash",attrs={"mean":float(mean),"sd":float(sd)})
    stats=builder.save(path);reader=CryptoCausalReader(path)
    if not reader.verify_provenance():raise RuntimeError("reader failed")
    return stats

_T=re.compile(r"coin_xor_bit_(\d+)$");_O=re.compile(r"ciphertext_entropy_contrast_byte_(\d+)$")
def _reader(reader,bits,width):
    means={b:np.zeros(width) for b in bits};sds={b:np.zeros(width) for b in bits};count=0
    for e in reader.triplets(include_inferred=False):
        t,o=_T.search(e["trigger"]),_O.search(e["outcome"])
        if t and o:
            b=int(t.group(1));i=int(o.group(1))
            if b in means:means[b][i]=e["attrs"]["mean"];sds[b][i]=max(e["attrs"]["sd"],1e-9);count+=1
    if count!=len(bits)*width:raise RuntimeError("incomplete reader graph")
    return means,sds
def _classify(means,sds,x):
    scores={b:float(-.5*np.sum(((x-means[b])/sds[b])**2+2*np.log(sds[b]))) for b in means};return max(scores,key=scores.get),scores

def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument("--output",type=Path,required=True);p.add_argument("--causal-output",type=Path,required=True);p.add_argument("--bits",type=int,nargs="+",default=[0,63,127,255]);p.add_argument("--operations",type=int,default=1000);p.add_argument("--keys",type=int,default=6);p.add_argument("--train-keys",type=int,default=3);p.add_argument("--routes",type=int,default=8);p.add_argument("--seed-base",type=int,default=3185001);a=p.parse_args()
    if a.train_keys<1 or a.train_keys>=a.keys or any(b<0 or b>=256 for b in a.bits):raise ValueError("invalid args")
    module_path,prefix=VARIANTS["mlkem512"];module,lib=_lib(module_path);keypair=getattr(lib,f"{prefix}_crypto_kem_keypair_derand");enc=getattr(lib,f"{prefix}_crypto_kem_enc_derand");keypair.argtypes=[ctypes.POINTER(ctypes.c_uint8),ctypes.POINTER(ctypes.c_uint8),ctypes.POINTER(ctypes.c_uint8)];enc.argtypes=[ctypes.POINTER(ctypes.c_uint8),ctypes.POINTER(ctypes.c_uint8),ctypes.POINTER(ctypes.c_uint8),ctypes.POINTER(ctypes.c_uint8)]
    data={b:[] for b in a.bits};valid=[]
    for ki in range(a.keys):
        seed=a.seed_base+1009*ki; keycoins=hashlib.shake_256(f"mlkem512:key:{seed}".encode()).digest(64);pk=(ctypes.c_uint8*module.PUBLIC_KEY_SIZE)();sk=(ctypes.c_uint8*module.SECRET_KEY_SIZE)();
        if keypair(pk,sk,(ctypes.c_uint8*64).from_buffer_copy(keycoins))!=0:raise RuntimeError("keypair")
        first_rows=[];second_rows={b:[] for b in a.bits};roundtrips=0
        for op in range(a.operations):
            coins=bytearray(hashlib.shake_256(f"mlkem512:coins:{seed}:{op}".encode()).digest(32));ct=(ctypes.c_uint8*module.CIPHERTEXT_SIZE)();ss=(ctypes.c_uint8*module.PLAINTEXT_SIZE)();enc(ct,ss,pk,(ctypes.c_uint8*32).from_buffer_copy(coins));base=bytes(ct);roundtrips+=int(module.decrypt(bytes(sk),base)==bytes(ss));first_rows.append(np.frombuffer(base,dtype=np.uint8))
            for b in a.bits:
                modified=bytearray(coins);modified[b//8]^=1<<(b%8);ct2=(ctypes.c_uint8*module.CIPHERTEXT_SIZE)();ss2=(ctypes.c_uint8*module.PLAINTEXT_SIZE)();enc(ct2,ss2,pk,(ctypes.c_uint8*32).from_buffer_copy(modified));second_rows[b].append(np.frombuffer(bytes(ct2),dtype=np.uint8))
        first=np.stack(first_rows);valid.append(roundtrips);print(f"mlkem coin causal key={ki} valid={roundtrips}/{a.operations}",flush=True)
        for b in a.bits:data[b].append(_contrast(first,np.stack(second_rows[b]),a.routes,seed^b))
    means={b:np.mean(data[b][:a.train_keys],axis=0) for b in a.bits};sds={b:np.std(data[b][:a.train_keys],axis=0,ddof=1)+1e-9 for b in a.bits};train_hash=hashlib.sha256(np.asarray([data[b][:a.train_keys] for b in a.bits]).tobytes()).hexdigest();params={"variant":"mlkem512","bits":a.bits,"operations_per_key":a.operations,"train_keys":a.train_keys,"repairing_routes":a.routes};stats=_build(a.causal_output,params,means,sds,train_hash);reader=CryptoCausalReader(a.causal_output);rmeans,rsds=_reader(reader,a.bits,module.CIPHERTEXT_SIZE)
    trials=[]
    for b in a.bits:
        for x in data[b][a.train_keys:]:pred,scores=_classify(rmeans,rsds,x);trials.append({"actual":b,"predicted":pred,"correct":pred==b,"scores":scores})
    per={str(b):{"correct":sum(t["correct"] for t in trials if t["actual"]==b),"total":sum(t["actual"]==b for t in trials)} for b in a.bits}
    for v in per.values():v["accuracy"]=v["correct"]/max(v["total"],1)
    payload={"schema":"mlkem-coin-causal-contrast-v1","parameters":params,"functional_decapsulations":valid,"causal":stats,"overall_accuracy":float(np.mean([t["correct"] for t in trials])),"chance":1/len(a.bits),"per_class":per,"trials":trials,"scope":"fixed-key deterministic encapsulation coin-bit output contrast; not an IND-CPA/CCA or key-recovery claim"};encoded=(json.dumps(payload,indent=2,sort_keys=True)+"\n").encode();a.output.parent.mkdir(parents=True,exist_ok=True);a.output.write_bytes(encoded);print(json.dumps({"output":str(a.output),"sha256":hashlib.sha256(encoded).hexdigest(),"overall_accuracy":payload["overall_accuracy"],"per_class":per},indent=2));return 0
if __name__=="__main__":raise SystemExit(main())

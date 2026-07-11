#!/usr/bin/env python3
"""Direct native ML-KEM IND-CPA noise-coin output causal graph.

Unlike the closed FO-KEM coinbit study, this uses the exported PQClean
``indcpa_enc`` primitive with a fixed public message and an explicit,
one-bit intervention on its noise coins.  Each output pair is functionally
checked with native ``indcpa_dec``.  BvN routes are shared across every bit
class for one key/batch and the reader reconstructs the entire held-out model.
"""
from __future__ import annotations

import argparse, ctypes, hashlib, importlib, json, re, sys
from pathlib import Path
import numpy as np

from arx_carry_leak.bvn import route_ensemble, verify_routes
from arx_carry_leak.crypto_causal import CryptoCausalBuilder, CryptoCausalReader


def _native():
    module=importlib.import_module("pqcrypto.kem.ml_kem_512")
    root=Path(module.__file__).parents[1]/"_kem"; stem=Path(module.__file__).stem
    preferred=root/f"{stem}.cpython-{sys.version_info.major}{sys.version_info.minor}-darwin.so"
    candidates=[preferred] if preferred.exists() else list(root.glob(f"{stem}*.so"))
    if len(candidates)!=1:raise RuntimeError("unique ML-KEM native backend not found")
    lib=ctypes.CDLL(str(candidates[0])); prefix="PQCLEAN_MLKEM512_CLEAN_"; ptr=ctypes.POINTER(ctypes.c_uint8)
    functions=[]
    for suffix,nargs in [("indcpa_keypair_derand",3),("indcpa_enc",4),("indcpa_dec",3)]:
        fn=getattr(lib,prefix+suffix);fn.argtypes=[ptr]*nargs;functions.append(fn)
    return module,*functions


def _profile(delta:np.ndarray,chunks:int)->np.ndarray:
    parts=np.array_split(np.arange(delta.shape[1]),chunks); values=[]
    for indices in parts:
        counts=np.bincount(delta[:,indices].ravel(),minlength=256);p=counts[counts>0]/counts.sum()
        values.append(8.0+float(np.sum(p*np.log2(p))))
    return np.asarray(values)


def _contrast(first,second,routes,seed,chunks):
    factual=_profile(first^second,chunks); permutations=route_ensemble(len(second),routes,seed);check=verify_routes(permutations)
    if not check["all_bijective"] or check["forbidden_alignments"]:raise RuntimeError("invalid BvN routes")
    return factual-np.mean([_profile(first^second[route],chunks) for route in permutations],axis=0)


def _build(path,params,means,sds,train_hash):
    builder=CryptoCausalBuilder(experiment="mlkem_indcpa_noise_causal",parameters={**params,"train_output_sha256":train_hash,"direct_output_causal_graph":True,"causal_header":{"codec":"factual-minus-BvN-repairing-chunk-entropy-profile","stage_chain":["native_indcpa_ciphertexts","one_bit_noise_coin_intervention","factual_xor_delta","shared_BvN_repair_counterfactuals","per_chunk_entropy_contrast","causal_zlib","reader_reverse_coin_bit_query"],"writer_model_forbidden_at_holdout":True}})
    for bit in means:
        for index,(mean,sd) in enumerate(zip(means[bit],sds[bit],strict=True)):
            builder.add_triplet(edge_id=f"noisebit{bit}-chunk{index}",trigger=f"mlkem-indcpa:noise_bit_{bit}",mechanism="factual_minus_repairing_output_profile_compressed",outcome=f"mlkem-indcpa:chunk_entropy_contrast_{index}",confidence=min(.999,max(0.,1-np.exp(-abs(mean)/(sd+1e-12)))),evidence_kind="native_indcpa_deterministic_noise_intervention",source="embedded_native_ciphertext_train_hash",attrs={"mean":float(mean),"sd":float(sd)})
    stats=builder.save(path)
    if not CryptoCausalReader(path).verify_provenance():raise RuntimeError("reader provenance failure")
    return stats


_T=re.compile(r"noise_bit_(\d+)$");_O=re.compile(r"chunk_entropy_contrast_(\d+)$")
def _reader(reader,bits,chunks):
    means={bit:np.zeros(chunks) for bit in bits};sds={bit:np.zeros(chunks) for bit in bits};count=0
    for edge in reader.triplets(include_inferred=False):
        trigger,outcome=_T.search(edge["trigger"]),_O.search(edge["outcome"])
        if trigger and outcome and int(trigger.group(1)) in means:
            bit,index=int(trigger.group(1)),int(outcome.group(1));means[bit][index]=edge["attrs"]["mean"];sds[bit][index]=max(edge["attrs"]["sd"],1e-9);count+=1
    if count!=len(bits)*chunks:raise RuntimeError("reader reconstruction incomplete")
    return means,sds


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument("--output",type=Path,required=True);p.add_argument("--causal-output",type=Path,required=True);p.add_argument("--bits",type=int,nargs="+",default=[0,63,127,255]);p.add_argument("--operations",type=int,default=1000);p.add_argument("--keys",type=int,default=10);p.add_argument("--train-keys",type=int,default=5);p.add_argument("--routes",type=int,default=16);p.add_argument("--chunks",type=int,default=32);p.add_argument("--seed-base",type=int,default=19885001);a=p.parse_args()
    if not 1<=a.train_keys<a.keys or any(bit<0 or bit>=256 for bit in a.bits):raise ValueError("invalid split or coin bit")
    module,keypair,enc,dec=_native();U8=ctypes.c_uint8;data={bit:[] for bit in a.bits};gates=[]
    for key_index in range(a.keys):
        seed=a.seed_base+1009*key_index;pk=(U8*module.PUBLIC_KEY_SIZE)();sk=(U8*768)();keyseed=hashlib.shake_256(f"indcpa-key:{seed}".encode()).digest(32)
        keypair(pk,sk,(U8*32).from_buffer_copy(keyseed));first_rows=[];second_rows={bit:[] for bit in a.bits};valid=0
        for operation in range(a.operations):
            message=hashlib.shake_256(f"indcpa-message:{seed}:{operation}".encode()).digest(32);noise=bytearray(hashlib.shake_256(f"indcpa-noise:{seed}:{operation}".encode()).digest(32));ct=(U8*module.CIPHERTEXT_SIZE)();enc(ct,(U8*32).from_buffer_copy(message),pk,(U8*32).from_buffer_copy(noise));out=(U8*32)();dec(out,ct,sk);valid+=int(bytes(out)==message);first_rows.append(np.frombuffer(bytes(ct),dtype=np.uint8))
            for bit in a.bits:
                changed=bytearray(noise);changed[bit//8]^=1<<(bit%8);ct2=(U8*module.CIPHERTEXT_SIZE)();enc(ct2,(U8*32).from_buffer_copy(message),pk,(U8*32).from_buffer_copy(changed));out2=(U8*32)();dec(out2,ct2,sk);valid+=int(bytes(out2)==message);second_rows[bit].append(np.frombuffer(bytes(ct2),dtype=np.uint8))
        first=np.stack(first_rows);gates.append(valid);print(f"indcpa causal key={key_index} decaps={valid}/{a.operations*(1+len(a.bits))}",flush=True)
        for bit in a.bits:data[bit].append(_contrast(first,np.stack(second_rows[bit]),a.routes,seed,a.chunks))
    means={bit:np.mean(data[bit][:a.train_keys],axis=0) for bit in a.bits};pooled=np.std(np.concatenate([data[bit][:a.train_keys] for bit in a.bits]),axis=0,ddof=1)+1e-9;sds={bit:pooled.copy() for bit in a.bits};train_hash=hashlib.sha256(np.asarray([data[bit][:a.train_keys] for bit in a.bits]).tobytes()).hexdigest();params={"primitive":"PQCLEAN_MLKEM512_CLEAN_indcpa_enc","bits":a.bits,"operations_per_key":a.operations,"train_keys":a.train_keys,"repairing_routes":a.routes,"route_mode":"bvn","repair_route_seed_strategy":"shared_per_key_across_bit_classes","chunks":a.chunks,"variance_mode":"pooled"};stats=_build(a.causal_output,params,means,sds,train_hash);rmeans,rsds=_reader(CryptoCausalReader(a.causal_output),a.bits,a.chunks)
    trials=[]
    for bit in a.bits:
        for feature in data[bit][a.train_keys:]:
            scores={candidate:float(-.5*np.sum(((feature-rmeans[candidate])/rsds[candidate])**2+2*np.log(rsds[candidate]))) for candidate in a.bits};pred=max(scores,key=scores.get);trials.append({"actual":bit,"predicted":pred,"correct":pred==bit,"scores":scores})
    per={str(bit):{"correct":sum(row["correct"] for row in trials if row["actual"]==bit),"total":sum(row["actual"]==bit for row in trials)} for bit in a.bits}
    for row in per.values():row["accuracy"]=row["correct"]/max(row["total"],1)
    payload={"schema":"mlkem-indcpa-noise-causal-v1","parameters":params,"functional_indcpa_decryptions":gates,"causal":stats,"overall_accuracy":float(np.mean([row["correct"] for row in trials])),"chance":1/len(a.bits),"per_class":per,"trials":trials,"scope":"native deterministic ML-KEM IND-CPA noise-coin output profile; not an IND-CPA/CCA advantage or key recovery claim"};encoded=(json.dumps(payload,indent=2,sort_keys=True)+"\n").encode();a.output.parent.mkdir(parents=True,exist_ok=True);a.output.write_bytes(encoded);print(json.dumps({"output":str(a.output),"sha256":hashlib.sha256(encoded).hexdigest(),"overall_accuracy":payload["overall_accuracy"],"per_class":per},indent=2));return 0

if __name__=="__main__":raise SystemExit(main())

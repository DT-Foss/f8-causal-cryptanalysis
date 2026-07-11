#!/usr/bin/env python3
"""Direct output-causal contrast profiles for Threefish-256 late-round prefixes."""
from __future__ import annotations
import argparse,hashlib,json,re
from pathlib import Path
import numpy as np
from arx_carry_leak.bvn import route_ensemble,verify_routes
from arx_carry_leak.ciphers import threefish256_encrypt,verify_reference_vectors
from arx_carry_leak.crypto_causal import CryptoCausalBuilder,CryptoCausalReader

def _blocks(key,tweak,plaintexts,rounds):
 out=np.empty((len(plaintexts),32),dtype=np.uint8)
 for i,pt in enumerate(plaintexts):out[i]=np.frombuffer(b"".join(int(x).to_bytes(8,"big") for x in threefish256_encrypt([int(x) for x in pt],key,tweak,rounds)),dtype=np.uint8)
 return out
def _profile(delta):
 vals=[]
 for i in range(32):
  c=np.bincount(delta[:,i],minlength=256);p=c[c>0]/len(delta);vals.append(8+float(np.sum(p*np.log2(p))))
 return np.asarray(vals)
def _contrast(a,b,routes,seed):
 factual=_profile(a^b);rs=route_ensemble(len(b),routes,seed);check=verify_routes(rs)
 if not check["all_bijective"] or check["forbidden_alignments"]:raise RuntimeError("invalid BvN routes")
 return factual-np.mean([_profile(a^b[r]) for r in rs],axis=0)
def _build(path,params,means,sds,h):
 b=CryptoCausalBuilder(experiment="threefish_causal_contrast_signature",parameters={**params,"train_output_sha256":h,"direct_output_causal_graph":True,"causal_header":{"codec":"factual-minus-BvN-repairing-byte-entropy-profile","stage_chain":["Threefish_prefix_ciphertext_pairs","chosen_plaintext_bit_xor","factual_xor_delta","shared_BvN_repair_counterfactuals","per_byte_entropy_contrast","causal_zlib","reader_reverse_round_query"],"writer_model_forbidden_at_holdout":True}})
 for label in means:
  for i,(mean,sd) in enumerate(zip(means[label],sds[label],strict=True)):b.add_triplet(edge_id=f"{label}-byte{i}",trigger=f"threefish:class_{label}",mechanism="factual_minus_repairing_output_profile_compressed",outcome=f"threefish:entropy_contrast_byte_{i}",confidence=min(.999,max(0,1-np.exp(-abs(mean)/(sd+1e-12)))),evidence_kind="direct_cipher_output_interventional_profile",source="embedded_train_output_hash",attrs={"mean":float(mean),"sd":float(sd)})
 s=b.save(path)
 if not CryptoCausalReader(path).verify_provenance():raise RuntimeError("reader failed")
 return s
_T=re.compile(r":class_(.+)$");_O=re.compile(r":entropy_contrast_byte_(\d+)$")
def _reader(r,labels):
 means={x:np.zeros(32) for x in labels};sds={x:np.zeros(32) for x in labels};n=0
 for e in r.triplets(include_inferred=False):
  t,o=_T.search(e["trigger"]),_O.search(e["outcome"])
  if t and o and t.group(1) in means:
   x,i=t.group(1),int(o.group(1));means[x][i]=e["attrs"]["mean"];sds[x][i]=max(e["attrs"]["sd"],1e-9);n+=1
 if n!=len(labels)*32:raise RuntimeError("reader incomplete")
 return means,sds
def main():
 p=argparse.ArgumentParser();p.add_argument("--output",type=Path,required=True);p.add_argument("--causal-output",type=Path,required=True);p.add_argument("--rounds",type=int,nargs="+",default=list(range(64,73)));p.add_argument("--bits",type=int,nargs="+",default=[0,63,64,255]);p.add_argument("--holdout-bits",type=int,nargs="+",default=[1,62,65,254]);p.add_argument("--pairs",type=int,default=1000);p.add_argument("--seeds",type=int,default=10);p.add_argument("--train-seeds",type=int,default=5);p.add_argument("--routes",type=int,default=16);p.add_argument("--seed-base",type=int,default=25885001);a=p.parse_args()
 if not 1<=a.train_seeds<a.seeds or any(x<0 or x>=256 for x in set(a.bits)|set(a.holdout_bits)):raise ValueError("invalid args")
 if not all(verify_reference_vectors().values()):raise RuntimeError("Threefish reference vectors failed")
 labels=[f"r{x}" for x in a.rounds];data={x:[] for x in labels};evals={x:[] for x in labels}
 for si in range(a.seeds):
  seed=a.seed_base+1009*si;rng=np.random.default_rng(seed);key=[int(x) for x in rng.integers(0,2**64,size=4,dtype=np.uint64)];tweak=[int(x) for x in rng.integers(0,2**64,size=2,dtype=np.uint64)];pts=rng.integers(0,2**64,size=(a.pairs,4),dtype=np.uint64)
  for rounds,label in zip(a.rounds,labels,strict=True):
   print(f"threefish causal seed={seed} rounds={rounds}",flush=True);first=_blocks(key,tweak,pts,rounds)
   for bit in sorted(set(a.bits)|set(a.holdout_bits)):
    changed=pts.copy();changed[:,bit//64]^=np.uint64(1<<(bit%64));f=_contrast(first,_blocks(key,tweak,changed,rounds),a.routes,seed^bit)
    if bit in a.bits:data[label].append(f)
    if bit in a.holdout_bits:evals[label].append(f)
 split=a.train_seeds*len(a.bits);esplit=a.train_seeds*len(a.holdout_bits);means={x:np.mean(data[x][:split],axis=0) for x in labels};pooled=np.std(np.concatenate([data[x][:split] for x in labels]),axis=0,ddof=1)+1e-9;sds={x:pooled.copy() for x in labels};h=hashlib.sha256(np.asarray([data[x][:split] for x in labels]).tobytes()).hexdigest();params={"rounds":a.rounds,"bits":a.bits,"holdout_bits":a.holdout_bits,"pairs_per_seed":a.pairs,"train_seeds":a.train_seeds,"repairing_routes":a.routes,"route_mode":"bvn","repair_route_seed_strategy":"shared_per_seed_plaintext_bit_across_round_classes","variance_mode":"pooled"};stats=_build(a.causal_output,params,means,sds,h);rm,rs=_reader(CryptoCausalReader(a.causal_output),labels);trials=[]
 for label in labels:
  for f in evals[label][esplit:]:
   scores={x:float(-.5*np.sum(((f-rm[x])/rs[x])**2+2*np.log(rs[x]))) for x in labels};pred=max(scores,key=scores.get);trials.append({"actual":label,"predicted":pred,"correct":pred==label,"scores":scores})
 per={x:{"correct":sum(t["correct"] for t in trials if t["actual"]==x),"total":sum(t["actual"]==x for t in trials)} for x in labels}
 for v in per.values():v["accuracy"]=v["correct"]/max(v["total"],1)
 payload={"schema":"threefish-causal-contrast-signature-v1","parameters":params,"causal":stats,"overall_accuracy":float(np.mean([t["correct"] for t in trials])),"chance":1/len(labels),"per_class":per,"trials":trials,"scope":"known-key chosen-plaintext Threefish prefix output class query; not a full-round ciphertext-only distinguisher, key recovery, or security claim"};raw=(json.dumps(payload,indent=2,sort_keys=True)+"\n").encode();a.output.parent.mkdir(parents=True,exist_ok=True);a.output.write_bytes(raw);print(json.dumps({"output":str(a.output),"sha256":hashlib.sha256(raw).hexdigest(),"overall_accuracy":payload["overall_accuracy"],"per_class":per},indent=2))
if __name__=="__main__":main()

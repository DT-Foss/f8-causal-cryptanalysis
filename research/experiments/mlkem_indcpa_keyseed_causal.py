#!/usr/bin/env python3
"""Direct native ML-KEM INDCPA key-seed to public-key causal contrast."""
from __future__ import annotations
import argparse,ctypes,hashlib,importlib,json,re,sys
from pathlib import Path
import numpy as np
from arx_carry_leak.bvn import route_ensemble,verify_routes
from arx_carry_leak.crypto_causal import CryptoCausalBuilder,CryptoCausalReader

def _native():
 m=importlib.import_module("pqcrypto.kem.ml_kem_512");root=Path(m.__file__).parents[1]/"_kem";stem=Path(m.__file__).stem;p=root/f"{stem}.cpython-{sys.version_info.major}{sys.version_info.minor}-darwin.so";lib=ctypes.CDLL(str(p));ptr=ctypes.POINTER(ctypes.c_uint8);pre="PQCLEAN_MLKEM512_CLEAN_";out=[]
 for name,n in [("indcpa_keypair_derand",3),("indcpa_enc",4),("indcpa_dec",3)]:
  f=getattr(lib,pre+name);f.argtypes=[ptr]*n;out.append(f)
 return m,*out
def _profile(delta,chunks):
 vals=[]
 for ix in np.array_split(np.arange(delta.shape[1]),chunks):
  c=np.bincount(delta[:,ix].ravel(),minlength=256);p=c[c>0]/c.sum();vals.append(8+float(np.sum(p*np.log2(p))))
 return np.asarray(vals)
def _contrast(a,b,routes,seed,chunks):
 factual=_profile(a^b,chunks);rs=route_ensemble(len(b),routes,seed);check=verify_routes(rs)
 if not check["all_bijective"] or check["forbidden_alignments"]:raise RuntimeError("invalid routes")
 return factual-np.mean([_profile(a^b[r],chunks) for r in rs],axis=0)
def _build(path,params,means,sds,h):
 b=CryptoCausalBuilder(experiment="mlkem_indcpa_keyseed_causal",parameters={**params,"train_output_sha256":h,"direct_output_causal_graph":True,"causal_header":{"codec":"factual-minus-BvN-repairing-public-key-chunk-entropy-profile","stage_chain":["native_indcpa_public_keys","one_bit_keyseed_intervention","factual_xor_delta","shared_BvN_repair_counterfactuals","per_chunk_entropy_contrast","causal_zlib","reader_reverse_keyseed_bit_query"],"writer_model_forbidden_at_holdout":True}})
 for bit in means:
  for i,(mean,sd) in enumerate(zip(means[bit],sds[bit],strict=True)):b.add_triplet(edge_id=f"keybit{bit}-chunk{i}",trigger=f"mlkem-indcpa:keyseed_bit_{bit}",mechanism="factual_minus_repairing_public_key_profile_compressed",outcome=f"mlkem-indcpa:pk_chunk_entropy_contrast_{i}",confidence=min(.999,max(0,1-np.exp(-abs(mean)/(sd+1e-12)))),evidence_kind="native_indcpa_keyseed_intervention",source="embedded_native_pk_train_hash",attrs={"mean":float(mean),"sd":float(sd)})
 s=b.save(path)
 if not CryptoCausalReader(path).verify_provenance():raise RuntimeError("reader failure")
 return s
_T=re.compile(r"keyseed_bit_(\d+)$");_O=re.compile(r"pk_chunk_entropy_contrast_(\d+)$")
def _reader(r,bits,chunks):
 means={x:np.zeros(chunks) for x in bits};sds={x:np.zeros(chunks) for x in bits};n=0
 for e in r.triplets(include_inferred=False):
  t,o=_T.search(e["trigger"]),_O.search(e["outcome"])
  if t and o and int(t.group(1)) in means:
   x,i=int(t.group(1)),int(o.group(1));means[x][i]=e["attrs"]["mean"];sds[x][i]=max(e["attrs"]["sd"],1e-9);n+=1
 if n!=len(bits)*chunks:raise RuntimeError("incomplete reader")
 return means,sds
def main():
 p=argparse.ArgumentParser();p.add_argument("--output",type=Path,required=True);p.add_argument("--causal-output",type=Path,required=True);p.add_argument("--bits",type=int,nargs="+",default=[0,63,127,255]);p.add_argument("--operations",type=int,default=1000);p.add_argument("--keys",type=int,default=10);p.add_argument("--train-keys",type=int,default=5);p.add_argument("--routes",type=int,default=16);p.add_argument("--chunks",type=int,default=32);p.add_argument("--seed-base",type=int,default=20885001);a=p.parse_args()
 if not 1<=a.train_keys<a.keys or any(x<0 or x>=256 for x in a.bits):raise ValueError("invalid args")
 m,kp,enc,dec=_native();U=ctypes.c_uint8;data={x:[] for x in a.bits};gates=[]
 def make(seed):
  pk=(U*m.PUBLIC_KEY_SIZE)();sk=(U*768)();kp(pk,sk,(U*32).from_buffer_copy(seed));return pk,sk
 for ki in range(a.keys):
  seed=a.seed_base+1009*ki;first=[];second={x:[] for x in a.bits};ok=0
  for op in range(a.operations):
   base=bytearray(hashlib.shake_256(f"indcpa-keyseed:{seed}:{op}".encode()).digest(32));pk,sk=make(base);msg=hashlib.shake_256(f"gate-message:{seed}:{op}".encode()).digest(32);noise=hashlib.shake_256(f"gate-noise:{seed}:{op}".encode()).digest(32);ct=(U*m.CIPHERTEXT_SIZE)();enc(ct,(U*32).from_buffer_copy(msg),pk,(U*32).from_buffer_copy(noise));out=(U*32)();dec(out,ct,sk);ok+=int(bytes(out)==msg);first.append(np.frombuffer(bytes(pk),dtype=np.uint8))
   for bit in a.bits:
    changed=bytearray(base);changed[bit//8]^=1<<(bit%8);pk2,sk2=make(changed);ct2=(U*m.CIPHERTEXT_SIZE)();enc(ct2,(U*32).from_buffer_copy(msg),pk2,(U*32).from_buffer_copy(noise));out2=(U*32)();dec(out2,ct2,sk2);ok+=int(bytes(out2)==msg);second[bit].append(np.frombuffer(bytes(pk2),dtype=np.uint8))
  first=np.stack(first);gates.append(ok);print(f"keyseed causal key={ki} gates={ok}/{a.operations*(1+len(a.bits))}",flush=True)
  for bit in a.bits:data[bit].append(_contrast(first,np.stack(second[bit]),a.routes,seed,a.chunks))
 means={x:np.mean(data[x][:a.train_keys],axis=0) for x in a.bits};pooled=np.std(np.concatenate([data[x][:a.train_keys] for x in a.bits]),axis=0,ddof=1)+1e-9;sds={x:pooled.copy() for x in a.bits};h=hashlib.sha256(np.asarray([data[x][:a.train_keys] for x in a.bits]).tobytes()).hexdigest();params={"primitive":"PQCLEAN_MLKEM512_CLEAN_indcpa_keypair_derand","bits":a.bits,"operations_per_key":a.operations,"train_keys":a.train_keys,"repairing_routes":a.routes,"route_mode":"bvn","repair_route_seed_strategy":"shared_per_key_across_bit_classes","chunks":a.chunks,"variance_mode":"pooled"};stats=_build(a.causal_output,params,means,sds,h);rm,rs=_reader(CryptoCausalReader(a.causal_output),a.bits,a.chunks);trials=[]
 for x in a.bits:
  for f in data[x][a.train_keys:]:
   scores={y:float(-.5*np.sum(((f-rm[y])/rs[y])**2+2*np.log(rs[y]))) for y in a.bits};pred=max(scores,key=scores.get);trials.append({"actual":x,"predicted":pred,"correct":pred==x,"scores":scores})
 per={str(x):{"correct":sum(t["correct"] for t in trials if t["actual"]==x),"total":sum(t["actual"]==x for t in trials)} for x in a.bits}
 for v in per.values():v["accuracy"]=v["correct"]/max(v["total"],1)
 payload={"schema":"mlkem-indcpa-keyseed-causal-v1","parameters":params,"functional_indcpa_decryptions":gates,"causal":stats,"overall_accuracy":float(np.mean([t["correct"] for t in trials])),"chance":1/len(a.bits),"per_class":per,"trials":trials,"scope":"native deterministic ML-KEM INDCPA keyseed-to-public-key profile; not a security advantage or key recovery claim"};raw=(json.dumps(payload,indent=2,sort_keys=True)+"\n").encode();a.output.parent.mkdir(parents=True,exist_ok=True);a.output.write_bytes(raw);print(json.dumps({"output":str(a.output),"sha256":hashlib.sha256(raw).hexdigest(),"overall_accuracy":payload["overall_accuracy"],"per_class":per},indent=2))
if __name__=="__main__":main()

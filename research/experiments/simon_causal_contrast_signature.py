#!/usr/bin/env python3
"""Direct cipher-output causal contrast profiles for SIMON32/64 prefixes."""
from __future__ import annotations
import argparse,hashlib,json,re
from pathlib import Path
import numpy as np
from arx_carry_leak.bvn import route_ensemble,verify_routes
from arx_carry_leak.ciphers import _SIMON_Z0,_random_words,_rol,_ror
from arx_carry_leak.crypto_causal import CryptoCausalBuilder,CryptoCausalReader

def _keys(seed,rounds):
 rng=np.random.default_rng(seed);ks=_random_words(rng,4,16);mask=0xffff;c=mask^3
 for i in range(4,rounds):
  t=_ror(ks[i-1],3,16)^ks[i-3];t^=_ror(t,1,16);z=(_SIMON_Z0>>(61-((i-4)%62)))&1;ks.append(ks[i-4]^t^c^z)
 return ks[:rounds]
def _blocks(keys,values):
 out=np.empty((len(values),4),dtype=np.uint8)
 for i,v in enumerate(values):
  x=(int(v)>>16)&0xffff;y=int(v)&0xffff
  for k in keys:f=(_rol(x,1,16)&_rol(x,8,16))^_rol(x,2,16);x,y=(y^f^k)&0xffff,x
  out[i]=np.frombuffer(x.to_bytes(2,"big")+y.to_bytes(2,"big"),dtype=np.uint8)
 return out
def _profile(d):
 vals=[]
 for i in range(4):
  c=np.bincount(d[:,i],minlength=256);p=c[c>0]/len(d);vals.append(8+float(np.sum(p*np.log2(p))))
 return np.asarray(vals)
def _contrast(a,b,routes,seed):
 factual=_profile(a^b);rs=route_ensemble(len(b),routes,seed);check=verify_routes(rs)
 if not check['all_bijective'] or check['forbidden_alignments']:raise RuntimeError('invalid BvN routes')
 return factual-np.mean([_profile(a^b[r]) for r in rs],axis=0)
def _build(path,params,means,sds,h):
 b=CryptoCausalBuilder(experiment='simon_causal_contrast_signature',parameters={**params,'train_output_sha256':h,'direct_output_causal_graph':True,'causal_header':{'codec':'factual-minus-BvN-repairing-byte-entropy-profile','stage_chain':['SIMON_prefix_ciphertext_pairs','chosen_plaintext_bit_xor','factual_xor_delta','shared_BvN_repair_counterfactuals','per_byte_entropy_contrast','causal_zlib','reader_reverse_round_query'],'writer_model_forbidden_at_holdout':True}})
 for label in means:
  for i,(m,s) in enumerate(zip(means[label],sds[label],strict=True)):b.add_triplet(edge_id=f'{label}-byte{i}',trigger=f'simon:class_{label}',mechanism='factual_minus_repairing_output_profile_compressed',outcome=f'simon:entropy_contrast_byte_{i}',confidence=min(.999,max(0,1-np.exp(-abs(m)/(s+1e-12)))),evidence_kind='direct_cipher_output_interventional_profile',source='embedded_train_output_hash',attrs={'mean':float(m),'sd':float(s)})
 stats=b.save(path)
 if not CryptoCausalReader(path).verify_provenance():raise RuntimeError('reader failed')
 return stats
_T=re.compile(r':class_(.+)$');_O=re.compile(r':entropy_contrast_byte_(\d+)$')
def _reader(r,labels):
 means={x:np.zeros(4) for x in labels};sds={x:np.zeros(4) for x in labels};n=0
 for e in r.triplets(include_inferred=False):
  t,o=_T.search(e['trigger']),_O.search(e['outcome'])
  if t and o and t.group(1) in means:x,i=t.group(1),int(o.group(1));means[x][i]=e['attrs']['mean'];sds[x][i]=max(e['attrs']['sd'],1e-9);n+=1
 if n!=len(labels)*4:raise RuntimeError('reader incomplete')
 return means,sds
def main():
 p=argparse.ArgumentParser();p.add_argument('--output',type=Path,required=True);p.add_argument('--causal-output',type=Path,required=True);p.add_argument('--rounds',type=int,nargs='+',default=list(range(24,33)));p.add_argument('--bits',type=int,nargs='+',default=[0,7,15,31]);p.add_argument('--holdout-bits',type=int,nargs='+',default=[1,8,16,30]);p.add_argument('--pairs',type=int,default=10000);p.add_argument('--seeds',type=int,default=10);p.add_argument('--train-seeds',type=int,default=5);p.add_argument('--routes',type=int,default=16);p.add_argument('--seed-base',type=int,default=58885001);a=p.parse_args()
 if not 1<=a.train_seeds<a.seeds or any(x<0 or x>=32 for x in set(a.bits)|set(a.holdout_bits)):raise ValueError('invalid args')
 labels=[f'r{x}' for x in a.rounds];data={x:[] for x in labels};ev={x:[] for x in labels}
 for si in range(a.seeds):
  seed=a.seed_base+1009*si;rng=np.random.default_rng(seed);values=rng.integers(0,2**32,size=a.pairs,dtype=np.uint32)
  for rounds,label in zip(a.rounds,labels,strict=True):
   print(f'simon causal seed={seed} rounds={rounds}',flush=True);first=_blocks(_keys(seed,rounds),values)
   for bit in sorted(set(a.bits)|set(a.holdout_bits)):
    f=_contrast(first,_blocks(_keys(seed,rounds),values^np.uint32(1<<bit)),a.routes,seed^bit)
    if bit in a.bits:data[label].append(f)
    if bit in a.holdout_bits:ev[label].append(f)
 split=a.train_seeds*len(a.bits);esplit=a.train_seeds*len(a.holdout_bits);means={x:np.mean(data[x][:split],axis=0) for x in labels};pool=np.std(np.concatenate([data[x][:split] for x in labels]),axis=0,ddof=1)+1e-9;sds={x:pool.copy() for x in labels};h=hashlib.sha256(np.asarray([data[x][:split] for x in labels]).tobytes()).hexdigest();params={'rounds':a.rounds,'bits':a.bits,'holdout_bits':a.holdout_bits,'pairs_per_seed':a.pairs,'train_seeds':a.train_seeds,'repairing_routes':a.routes,'route_mode':'bvn','repair_route_seed_strategy':'shared_per_seed_plaintext_bit_across_round_classes','variance_mode':'pooled'};stats=_build(a.causal_output,params,means,sds,h);rm,rs=_reader(CryptoCausalReader(a.causal_output),labels);trials=[]
 for label in labels:
  for f in ev[label][esplit:]:
   scores={x:float(-.5*np.sum(((f-rm[x])/rs[x])**2+2*np.log(rs[x]))) for x in labels};pred=max(scores,key=scores.get);trials.append({'actual':label,'predicted':pred,'correct':pred==label,'scores':scores})
 per={x:{'correct':sum(t['correct'] for t in trials if t['actual']==x),'total':sum(t['actual']==x for t in trials)} for x in labels}
 for v in per.values():v['accuracy']=v['correct']/max(v['total'],1)
 payload={'schema':'simon-causal-contrast-signature-v1','parameters':params,'causal':stats,'overall_accuracy':float(np.mean([t['correct'] for t in trials])),'chance':1/len(labels),'per_class':per,'trials':trials,'scope':'known-key chosen-plaintext SIMON prefix output query; not key recovery or a full-round security claim'};raw=(json.dumps(payload,indent=2,sort_keys=True)+'\n').encode();a.output.parent.mkdir(parents=True,exist_ok=True);a.output.write_bytes(raw);print(json.dumps({'output':str(a.output),'sha256':hashlib.sha256(raw).hexdigest(),'overall_accuracy':payload['overall_accuracy'],'per_class':per},indent=2))
if __name__=='__main__':main()

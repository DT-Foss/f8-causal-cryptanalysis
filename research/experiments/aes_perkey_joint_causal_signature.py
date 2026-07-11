#!/usr/bin/env python3
"""Known-key within-key reverse inference from direct AES output causal graphs."""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import sys
from pathlib import Path

import numpy as np


def _load_joint():
    path = Path(__file__).with_name("aes_round_joint_causal_signature.py")
    spec = importlib.util.spec_from_file_location("aes_round_joint_causal_signature_perkey", path)
    if spec is None or spec.loader is None: raise RuntimeError("cannot load joint codec")
    module = importlib.util.module_from_spec(spec); sys.modules[spec.name] = module; spec.loader.exec_module(module)
    return module


def main() -> int:
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output",type=Path,required=True); parser.add_argument("--causal-dir",type=Path,required=True)
    parser.add_argument("--rounds",type=int,nargs="+",default=[3,4,10]); parser.add_argument("--representations",choices=["identity","peel-final-linear"],nargs="+",default=["identity","peel-final-linear"]); parser.add_argument("--bits",type=int,nargs="+",default=[0,31,64,127]); parser.add_argument("--pairs",type=int,default=4000); parser.add_argument("--keys",type=int,default=5); parser.add_argument("--bins",type=int,default=2); parser.add_argument("--seed-base",type=int,default=1885001)
    args=parser.parse_args(); joint=_load_joint(); labels=[f"r{rounds}-{rep}" for rounds in args.rounds for rep in args.representations]; args.causal_dir.mkdir(parents=True,exist_ok=True); per_key=[]
    for key_index in range(args.keys):
        seed=args.seed_base+1009*key_index; rng=np.random.default_rng(seed); key=rng.integers(0,256,size=16,dtype=np.uint8); plaintexts=rng.integers(0,256,size=(args.pairs,16),dtype=np.uint8); train={label:[] for label in labels}; holdout={label:[] for label in labels}; split=args.pairs//2
        for rounds in args.rounds:
            print(f"aes perkey causal key={key_index} rounds={rounds}",flush=True); first=joint.aes_prefix_batch(key,plaintexts,rounds)
            for bit in args.bits:
                paired=plaintexts.copy(); paired[:,bit//8]^=np.uint8(1<<(bit%8)); second=joint.aes_prefix_batch(key,paired,rounds)
                for rep in args.representations:
                    source,paired_output=joint._represented(first,second,rounds,rep); item=(source,source^paired_output); label=f"r{rounds}-{rep}"; train[label].append((item[0][:split],item[1][:split])); holdout[label].append((item[0][split:],item[1][split:]))
        model,background=joint._fit(train,labels,args.bins); row_hash=hashlib.sha256(b"".join(np.concatenate([x[0] for x in train[label]]).tobytes()+np.concatenate([x[1] for x in train[label]]).tobytes() for label in labels)).hexdigest(); causal_path=args.causal_dir/f"known-key-{key_index}.causal"; params={"known_key_graph":True,"key_index":key_index,"rounds":args.rounds,"representations":args.representations,"bits":args.bits,"bins":args.bins,"train_rows_per_bit":split,"holdout_rows_per_bit":args.pairs-split}; stats=joint._build(causal_path,"aes-known-key-joint-signature",params,model,background,row_hash); reader=joint.CryptoCausalReader(causal_path); reader_model=joint._reader_model(reader,labels,args.bins); trials=[]
        for label in labels:
            for source,delta in holdout[label]:
                predicted,scores=joint._classify(reader_model,source,delta,args.bins); trials.append({"actual":label,"predicted":predicted,"correct":predicted==label,"scores":scores})
        per_class={label:{"correct":sum(t["correct"] for t in trials if t["actual"]==label),"total":sum(t["actual"]==label for t in trials)} for label in labels}
        for value in per_class.values(): value["accuracy"]=value["correct"]/max(value["total"],1)
        per_key.append({"key_index":key_index,"causal_path":str(causal_path),"causal":stats,"accuracy":float(np.mean([t["correct"] for t in trials])),"per_class":per_class,"trials":trials})
    payload={"schema":"aes-known-key-joint-causal-signature-v1","parameters":vars(args)|{"output":str(args.output),"causal_dir":str(args.causal_dir)},"per_key":per_key,"mean_accuracy":float(np.mean([row["accuracy"] for row in per_key])),"chance":1/len(labels),"scope":"known-key, within-key heldout output causal graph and reader-only round-class reverse inference; not key recovery"}; encoded=(json.dumps(payload,indent=2,sort_keys=True)+"\n").encode(); args.output.parent.mkdir(parents=True,exist_ok=True); args.output.write_bytes(encoded); print(json.dumps({"output":str(args.output),"sha256":hashlib.sha256(encoded).hexdigest(),"mean_accuracy":payload["mean_accuracy"],"per_key_accuracy":[row["accuracy"] for row in per_key]},indent=2)); return 0


if __name__=="__main__": raise SystemExit(main())

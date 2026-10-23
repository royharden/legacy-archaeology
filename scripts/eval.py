"""Development evaluation entrypoint. Hidden/paid activation is intentionally gated."""
import argparse
import json
from pathlib import Path

def main():
    p=argparse.ArgumentParser(); p.add_argument('--mode',choices=['replay','mock','live'],default='replay')
    p.add_argument('--split',choices=['development','validation','heldout'],default='development')
    p.add_argument('--evidence'); p.add_argument('--config')
    args=p.parse_args()
    if args.split!='development' or args.mode=='live':
        raise SystemExit('Hidden custody, frozen suite and paid provider activation remain deferred; no eligible run')
    if not args.evidence: raise SystemExit('--evidence retired/development projection required')
    evidence=json.loads(Path(args.evidence).read_text(encoding='utf-8'))
    from evaluation.scorer import score_product
    result=score_product(evidence['oracle_records'],evidence['outcomes'],evidence['mapping'],edition=evidence.get('edition','development'))
    print(json.dumps(result,indent=2))

if __name__=='__main__': main()

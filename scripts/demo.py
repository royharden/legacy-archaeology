"""Future visible development walking skeleton; explicitly simulated answers."""
import argparse
import json
from pathlib import Path
from la.ingest import ingest_bytes
from la.inference import hypothesize
from la.review import RulingStore,questions,build_mapping
from la.convert import transform,approve_mapping,export_bundle

def main():
    p=argparse.ArgumentParser(); p.add_argument('--fixture',default='account-dev-01')
    p.add_argument('--mode',choices=['mock','rules'],default='mock')
    p.add_argument('--out',default='.la-runs/demo')
    args=p.parse_args()
    base=Path(__file__).resolve().parents[1]
    fixtures=(base/'fixtures/dev').resolve(); fixture=(fixtures/args.fixture).resolve()
    if not fixture.is_relative_to(fixtures): raise ValueError('fixture path escape')
    brief=(fixture/'brief.md').read_text(encoding='utf-8')
    batch=ingest_bytes((fixture/'source.dat').read_bytes(),brief,json.loads((fixture/'samples.json').read_text()))
    generation=hypothesize(batch,brief,args.mode)
    # This is a public, hand-approved development skeleton, not inference-quality evidence.
    layout=json.loads((fixture/'layout.json').read_text())
    from la.contracts import digest
    candidates=[]
    for field in layout['fields']:
        value=dict(field,evidence=[],origin='mock',uncertainty='public_development_hand_mapping')
        candidates.append(dict(id=digest(value),**value))
    generation['candidates']=candidates
    generation['generation_sha256']=digest({k:v for k,v in generation.items() if k!='generation_sha256'})
    out=Path(args.out); out.mkdir(parents=True,exist_ok=True)
    store=RulingStore(out/'rulings.sqlite'); store.bind_generation(generation)
    for q in questions(generation):
        store.answer(generation,q['id'],q['options'][0]['id'],'agent_provisional',
            'public development hand mapping; no human participation implied',0,digest({'generation':generation,'question':q['id']}))
    mapping=build_mapping(batch,generation,store.projection(generation))
    outcomes=transform(batch,mapping)
    approval=approve_mapping(mapping,'agent_provisional','development skeleton only')
    bundle=out/('bundle-'+mapping['mapping_sha256'])
    manifest=export_bundle(bundle,batch,mapping,outcomes,approval)
    from evaluation.scorer import score_product
    oracle=json.loads((fixture/'oracle.json').read_text())['records']
    parity=score_product(oracle,outcomes,mapping)
    print(json.dumps({'mode':args.mode,'information_source':'public hand mapping','manifest':manifest,'parity':parity,
        'target_validation':'not_run','benchmark_status':'not_run','product_acceptance':'pending'},indent=2))

if __name__=='__main__': main()

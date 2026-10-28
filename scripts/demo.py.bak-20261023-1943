"""Future visible development walking skeleton; explicitly simulated answers."""
import argparse
import json
import sys
from copy import deepcopy
from decimal import Decimal
from pathlib import Path
from la.ingest import ingest_bytes
from la.inference import hypothesize
from la.review import RulingStore,questions,build_mapping
from la.convert import transform,approve_mapping,export_bundle
from la.ingest.evidence import make_evidence
from la.app.artifacts import within, receipt
from la.app.storage import file_lock,publish_bytes,bounded_bytes,SOURCE_BYTES
from la.app.artifacts import read

def main():
    p=argparse.ArgumentParser(); p.add_argument('--fixture',default='account-dev-01')
    p.add_argument('--mode',choices=['mock','rules'],default='mock')
    p.add_argument('--out',default='.la-runs/demo')
    p.add_argument('--root',default='.la-runs',help='declared output root; --out must be inside it')
    p.add_argument('--target-evidence',help='optional existing v2 effect packet under declared root; never connects')
    p.add_argument('--public-trust-root'); p.add_argument('--public-trust-profile')
    args=p.parse_args()
    root=Path(args.root).resolve()
    output=within(root,Path(args.out).resolve())
    with file_lock(output/'.demo.lock'):
        return demo(args)


def demo(args):
    base=Path(__file__).resolve().parents[1]
    fixtures=(base/'fixtures/dev').resolve(); fixture=(fixtures/args.fixture).resolve()
    if not fixture.is_relative_to(fixtures): raise ValueError('fixture path escape')
    brief=bounded_bytes(within(fixture,'brief.md',exists=True),limit=16000).decode('utf-8')
    samples=read(within(fixture,'samples.json',exists=True))
    batch=ingest_bytes(bounded_bytes(within(fixture,'source.dat',exists=True),limit=SOURCE_BYTES),brief,samples)
    generation=hypothesize(batch,brief,args.mode)
    # This is a public, hand-approved development skeleton, not inference-quality evidence.
    layout=read(within(fixture,'layout.json',exists=True))
    from la.contracts import digest
    candidates=[]
    for field in layout['fields']:
        permitted=[r for r in batch['samples']['records'] if r['disposition']=='eligible'][:3]
        value=dict(field,evidence=[make_evidence(batch,r['ordinal'],field['start'],field['end']) for r in permitted],
                   origin='mock',uncertainty='public_development_hand_mapping')
        candidates.append(dict(id=digest(value),**value))
    generation['candidates']=candidates
    generation['discovery']={'information_source':'public development hand mapping; not inference quality'}
    generation['filler']=layout.get('filler',[])
    generation['policy_sha256']=digest({'public_hand_layout':layout,'scope':'development-only'})
    generation['unknowns']=[]
    generation['generation_sha256']=digest({k:v for k,v in generation.items() if k!='generation_sha256'})
    root=Path(args.root).resolve()
    out=within(root,Path(args.out).resolve()); out.mkdir(parents=True,exist_ok=True)
    store=RulingStore(out/'rulings.sqlite'); store.bind_generation(generation)
    for q in questions(generation):
        store.answer(generation,q['id'],q['options'][0]['id'],'agent_provisional',
            'public development hand mapping; no human participation implied',0,digest({'generation':generation,'question':q['id']}))
    mapping=build_mapping(batch,generation,store.projection(generation))
    outcomes=transform(batch,mapping)
    approval=approve_mapping(mapping,'agent_provisional','development skeleton only')
    from la.app.cli import export_bundle_checked
    bundle,manifest=export_bundle_checked(out,batch,generation,store,mapping,outcomes,approval,
                                         brief=brief,permitted_samples=samples)
    sys.path.insert(0,str(base))
    from evaluation.scorer import score_product
    oracle_artifact=read(within(fixture,'oracle.json',exists=True))
    edition=layout.get('edition','public-development-legacy')
    if oracle_artifact.get('edition',edition)!=edition: raise ValueError('public layout/oracle edition mismatch')
    oracle=oracle_artifact['records']
    parity=score_product(oracle,outcomes,mapping,edition=edition)
    wrong=deepcopy(outcomes)
    if wrong and wrong[0]['outcome']=='converted':
        wrong[0]['values']['balance']=str(Decimal(wrong[0]['values']['balance'])+Decimal('1.00'))
    dropped=outcomes[1:]
    duplicated=outcomes+[deepcopy(outcomes[0])] if outcomes else []
    wrong_target=deepcopy(outcomes)
    for row in wrong_target:
        if row['outcome']=='converted':
            row['values']['description'],row['values']['account_ref']=row['values']['account_ref'],row['values']['description']
    result={'mode':args.mode,'information_source':'public hand mapping','fixture_edition':edition,
        'fixture_source_sha256':batch['source_sha256'],'manifest':manifest,'parity':parity,
        'seeded_failures':{'wrong_amount':score_product(oracle,wrong,mapping,edition=edition),
            'dropped_record':score_product(oracle,dropped,mapping,edition=edition),'duplicate_record':score_product(oracle,duplicated,mapping,edition=edition),
            'wrong_target':score_product(oracle,wrong_target,mapping,edition=edition)},
        'ruling_replay':store.replay(generation),'target_validation':'not_run','benchmark_status':'not_run','product_acceptance':'pending'}
    result.update(source_batch=batch,generation=generation,questions=questions(generation),ruling_history=store.events(),
                  mapping=mapping,approval=approval,preview_outcomes=outcomes,load_rows_available=True,
                  states={'mapping_status':mapping['mapping_status'],'transformation_status':manifest['transformation_status'],
                          'row_parity':parity['row_parity'],'target_validation':'not_run','benchmark_status':'not_run','product_acceptance':'pending'})
    from la.ingest.inspection import inspection_page
    result['inspection']=inspection_page(batch,generation=generation,mapping=mapping)
    from la.inference.explanation import explain_layout
    result['explanations']=explain_layout(batch,generation,authorized_only=True)
    if args.target_evidence:
        if not args.public_trust_root or not args.public_trust_profile:
            raise ValueError('explicit operator public trust required for supplied target evidence')
        from la.app.public_trust import public_keys
        from la.postgres import TargetAuthorityVerifier
        from evaluation.target_effects import TargetExpectation,grade_target
        from scripts.eval import observation_from
        packet=read(within(root,args.target_evidence,exists=True))
        required={'expectation','authority','observation'}
        if type(packet) is not dict or not required<=set(packet) or set(packet)-required-{'prior','failed_load','recovery_observation'}:
            raise ValueError('closed existing target-evidence packet required; no supplied oracle')
        intent=TargetAuthorityVerifier(*public_keys(args.public_trust_root,args.public_trust_profile)).verify(packet['authority'])
        expected=packet['expectation']
        if 'required_negatives' in expected: expected['required_negatives']=tuple(expected['required_negatives'])
        expectation=TargetExpectation(**expected).validate()
        candidate=expectation.candidate
        if (candidate['kind']!='product_bundle' or candidate['candidate_sha256']!=manifest['bundle_sha256']
                or candidate['source_sha256']!=batch['source_sha256'] or candidate['mapping_sha256']!=mapping['mapping_sha256']
                or intent['authority_sha256']!=expectation.authority_sha256):
            raise ValueError('target evidence differs from this public bundle/source/mapping/authority')
        grade=grade_target(oracle,observation_from(packet['observation']),expectation=expectation,
            prior=observation_from(packet.get('prior')),failed_load=observation_from(packet.get('failed_load')),
            recovery_observation=observation_from(packet.get('recovery_observation')),edition=edition)
        result['target_grade']=grade
        result['states']['target_validation']=grade['target_validation']
        result['target_evidence_mode']='offline supplied captured observations; no new target invocation'
    saved=receipt(out,'evaluation',{'source_sha256':batch['source_sha256'],'mapping_sha256':mapping['mapping_sha256'],
        'bundle_sha256':manifest['bundle_sha256'],'edition':edition,'result':parity,
        'failure_walks':result['seeded_failures'],'information_source':'public hand mapping','product_acceptance':'pending'})
    result['evaluation_receipt']=saved
    from la.report import render_report
    from la.report.html import renderer_pin
    report_path=out/('report-'+digest({'artifacts':result,'renderer_sha256':renderer_pin()})+'.html')
    publish_bytes(report_path,render_report(result).encode())
    from la.app.cli import emit_result
    emit_result(result)

if __name__=='__main__': main()

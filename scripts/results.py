"""Local result publishing from immutable evaluator captures; no suite execution."""
import argparse
from pathlib import Path


def captured(store,reference,kind,*,budget=None):
    from la.app.artifacts import within
    from la.app.storage import bounded_bytes
    from evaluation.artifacts import is_sha
    if (type(reference) is not dict or set(reference)-{'sha256','kind','bytes'} or
            not is_sha(reference.get('sha256')) or reference.get('kind')!=kind):
        raise ValueError('explicit typed immutable capture reference required')
    data=bounded_bytes(within(store.root,reference['sha256']+'.json',exists=True),limit=32*1024*1024)
    if 'bytes' in reference and (type(reference['bytes']) is not int or reference['bytes']!=len(data)):
        raise ValueError('capture byte declaration differs from actual immutable member')
    if budget is not None:
        budget['bytes']+=len(data); budget['members']+=1
        if budget['bytes']>256*1024*1024 or budget['members']>1024:
            raise ValueError('capture graph exceeds bounded local read budget')
    return store.get(reference,kind=kind)


def target_batch_captures(store,batch):
    """Accept actual legacy/current target-arm wires, including partial failures."""
    tr=batch['receipt_capture']; kind=tr['kind']
    if kind not in ('target_arm_receipt','target_arm_failure'):
        raise ValueError('actual independent target receipt required')
    if captured(store,tr,kind)!={k:v for k,v in batch.items() if k!='receipt_capture'}:
        raise ValueError('target receipt content mismatch')
    version=batch.get('schema_version')
    if type(version) is not int or version not in (1,2): raise ValueError('unknown target-arm payload version')
    if version==2:
        stages=batch['stages']
        allowed={'not_run','not_configured','not_authorized','missing','unavailable','returned','captured','partial'}
        if type(stages) is not dict or set(stages)!={'observe','failed_load','recovery'} or any(v not in allowed for v in stages.values()):
            raise ValueError('closed target stage states required')
        errors=batch['stage_errors']
        if type(errors) is not list or len(errors)>3: raise ValueError('bounded target stage errors required')
        for error in errors:
            if (type(error) is not dict or set(error)!={'stage','error_type'} or error['stage'] not in stages
                    or type(error['error_type']) is not str or len(error['error_type'])>256 or not error['error_type'].isidentifier()):
                raise ValueError('target stage errors may contain class identifiers only')
        phase=batch['phase_scope']
        if phase is not None:
            if type(phase) is not dict or set(phase)!={'evaluation_phase','split','evaluation_plan_sha256','freeze_sha256'}:
                raise ValueError('closed retained target phase scope required')
    normal=batch.get('observation')
    if normal is not None:
        if normal['kind'] not in ('target_observation_v2','target_observation_v3'):
            raise ValueError('observation reference must preserve actual wire version')
        observed=captured(store,normal,normal['kind'])
        if observed['schema_version']!=int(normal['kind'][-1]): raise ValueError('observation capture kind/version mismatch')
        if kind=='target_arm_receipt' and version==2 and observed['schema_version']!=batch['observation_schema_version']:
            raise ValueError('target-arm observation version differs from actual capture')
    elif kind=='target_arm_receipt' and version==2 and batch['observation_schema_version'] is not None:
        raise ValueError('missing observation cannot claim a wire version')
    effects=batch.get('effect_captures',[])
    if type(effects) is not list or len(effects)>3: raise ValueError('bounded retained target-effect references required')
    for effect in effects:
        if effect['kind'] not in ('failed_load_observation','unknown_commit_observation','recovery_observation'):
            raise ValueError('unknown target-effect capture')
        observed=captured(store,effect,effect['kind'])
        if type(observed.get('schema_version')) is not int or observed['schema_version'] not in (2,3):
            raise ValueError('actual versioned effect observation required')


def rows_from_suite(store,reference,*,replays=()):
    from la.report.results import arm_row,METHODS
    suite=captured(store,reference,'suite_report')
    declaration=captured(store,suite['declaration'],'suite_declaration')
    manifests=suite['manifests']
    if type(manifests) is not list or not 1<=len(manifests)<=18:
        raise ValueError('bounded actual suite manifests required')
    replay_by_manifest={}
    for ref in replays:
        replay=captured(store,ref,'replay_receipt')
        if replay.get('mode')!='replay' or replay.get('fresh_holdout') is not False or replay.get('stochastic_model_rerun') is not False:
            raise ValueError('actual retired deterministic replay receipt required')
        key=replay['manifest']['sha256']
        if key in replay_by_manifest: raise ValueError('duplicate replay manifest')
        replay_by_manifest[key]=(replay,ref)
    if replays and set(replay_by_manifest)!={ref['sha256'] for ref in manifests}:
        raise ValueError('replay must cover every original manifest without omissions')
    rows=[]
    seen=[]
    for ref in manifests:
        manifest=captured(store,ref,'variant_manifest')
        if any(manifest[k]!=declaration[k] for k in ('edition','split','mode')):
            raise ValueError('suite/variant identity mismatch')
        seen.append(manifest['variant_id'])
        arms=manifest['results']
        if len(arms)!=5 or {arm['method'] for arm in arms}!=set(METHODS):
            raise ValueError('every original arm, including failed/no-output arms, is required')
        replay_record=replay_by_manifest.get(ref['sha256'])
        if replay_record:
            replay,rr=replay_record
            if replay['edition']!=manifest['edition'] or len(replay['results'])!=5 or {r['method'] for r in replay['results']}!=set(METHODS):
                raise ValueError('replay edition/arm coverage mismatch')
        for arm in arms:
            if any(arm[k]!=manifest[k] for k in ('edition','variant_id','split','mode','input_sha256')):
                raise ValueError('manifest arm identity mismatch')
            checked=captured(store,arm['receipt_capture'],'arm_receipt')
            if checked!={k:v for k,v in arm.items() if k!='receipt_capture'}:
                raise ValueError('manifest arm differs from immutable arm receipt')
            refs=[r for r in arm['captures'] if r['kind']=='arm_raw']
            if len(refs)!=1: raise ValueError('one complete raw attempt capture required')
            raw=captured(store,refs[0],'arm_raw')
            if any(raw[k]!=arm[k] for k in ('method','status','error_type','input_sha256')):
                raise ValueError('raw arm lineage/status mismatch')
            if sum(a['status']=='failed' for a in raw['attempts'])!=arm['failed_attempts']:
                raise ValueError('failed request denominator mismatch')
            if len(raw['questions'])!=arm['questions_asked'] or sum(a['option_id']!='unknown' for a in raw['answers'])!=arm['questions_answered']:
                raise ValueError('question/answer count mismatch')
            for attempt in raw['attempts']:
                request=captured(store,attempt['request_capture'],'provider_request')
                if request['prompt_sha256']!=attempt['prompt_sha256'] or request['attempt']!=attempt['attempt']:
                    raise ValueError('actual provider request lineage mismatch')
                if attempt.get('raw_capture'):
                    reply=captured(store,attempt['raw_capture'],'provider_reply')
                    if attempt.get('usage') is not None and reply.get('usage')!=attempt['usage']:
                        raise ValueError('actual provider usage capture mismatch')
            target=arm['target_report']
            if target['target_validation']!=arm['target_validation']:
                raise ValueError('target status differs from actual target report')
            batches=target['batches']
            if batches and (len(batches)!=10 or len({b['batch_id'] for b in batches})!=10):
                raise ValueError('target report omitted actual batch denominators')
            states=[b['grade']['target_validation'] for b in batches]
            derived=('failed' if 'failed' in states else 'passed' if states and all(s=='passed' for s in states)
                     else 'not_run' if not states or all(s=='not_run' for s in states) else 'indeterminate')
            if derived!=target['target_validation']: raise ValueError('target status omitted failed/unknown batches')
            for batch in batches:
                target_batch_captures(store,batch)
            replay_arm=None
            if replay_record:
                item=next(r for r in replay['results'] if r['method']==arm['method'])
                if item['original_receipt']!=arm['receipt_capture'] or item['original_status']!=arm['status']:
                    raise ValueError('replay does not bind original arm receipt/status')
                replay_arm=dict(item,receipt_sha256=rr['sha256'])
            rows.append(arm_row(manifest,arm,raw,benchmark_status=suite['summary']['benchmark_status'],
                                receipt_sha256=arm['receipt_capture']['sha256'],replay=replay_arm))
    if sorted(seen)!=sorted(v['id'] for v in declaration['variants']) or len(seen)!=len(set(seen)):
        raise ValueError('suite projection omitted or duplicated predeclared variants')
    return rows


def parser():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--out',required=True)
    p.add_argument('--supersedes')
    sub=p.add_subparsers(dest='command',required=True)
    sub.add_parser('not-run')
    q=sub.add_parser('suite')
    q.add_argument('--capture-root',required=True); q.add_argument('--suite-sha256',required=True)
    q.add_argument('--visibility',choices=['public','active-hidden','retired-replay'],required=True)
    q.add_argument('--registry'); q.add_argument('--edition'); q.add_argument('--approval')
    q.add_argument('--public-trust-root'); q.add_argument('--public-trust-profile')
    q.add_argument('--replay-sha256',action='append',default=[])
    q.add_argument('--preview',action='store_true',help='private capture only; returns unsigned approval payload template')
    return p


def execute(args):
    import sys
    sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
    from la.report.results import projection,not_run_rows,publish
    from la.contracts import digest,sha256
    from la.app.storage import bounded_bytes
    if args.command=='not-run':
        return publish(projection(not_run_rows(),visibility='not_run',source_suite_sha256=None,
                                  edition_state='uninitialized',supersedes=args.supersedes),args.out)
    from evaluation.artifacts import CaptureStore
    from la.app.artifacts import read
    store=CaptureStore(args.capture_root)
    reference={'sha256':args.suite_sha256,'kind':'suite_report'}
    replay_refs=[{'sha256':pin,'kind':'replay_receipt'} for pin in args.replay_sha256]
    if bool(replay_refs)!=(args.visibility=='retired-replay'): raise ValueError('replay receipts only on retired replay route')
    registry=None; head=None
    if args.visibility!='public':
        from evaluation.edition_registry import EditionRegistry
        if not args.registry or not args.edition: raise ValueError('actual evaluator registry and exact edition required')
        registry=EditionRegistry(Path(args.registry).resolve(strict=True),store); head=registry.head
        state=registry.state(args.edition)
        if args.visibility=='retired-replay' and not state['retired']: raise ValueError('edition is not retired')
        if args.visibility=='active-hidden' and state['retired']: raise ValueError('retired edition requires replay route')
        attempts=([state['attempt']] if state.get('attempt') is not None else [])
        if state.get('t1'): attempts+=list(state['t1']['attempts'].values())
        if not any(a.get('status')!='running' and a.get('result_capture',{}).get('sha256')==args.suite_sha256
                   and a.get('result_capture',{}).get('kind')=='suite_report' for a in attempts):
            raise ValueError('source suite is not an actual terminal registry result')
        original=captured(store,reference,'suite_report')
        for ref in original['manifests']:
            manifest=captured(store,ref,'variant_manifest')
            if manifest['split']=='heldout' and (state.get('freeze') is None or manifest['freeze_sha256']!=state['freeze']['freeze_sha256']):
                raise ValueError('hidden report differs from actual consumed frozen edition')
        disposition='retired' if state['retired'] else 'exposed' if state['exposed'] else 'active'
    else: disposition='public'
    rows=rows_from_suite(store,reference,replays=replay_refs)
    if args.visibility=='active-hidden' and not any(row['split']=='heldout' for row in rows):
        raise ValueError('public inputs use explicit public report route')
    if registry and any(row['edition']!=args.edition for row in rows): raise ValueError('registry/report edition mismatch')
    value=projection(rows,visibility=args.visibility,source_suite_sha256=args.suite_sha256,
                     edition_state=disposition,supersedes=args.supersedes)
    approval_pin=None
    if args.visibility=='active-hidden':
        expected=dict(schema_version=1,kind='local_result_projection_authority',action='approve_local_result_projection',
            edition=args.edition,source_suite_sha256=args.suite_sha256,projection_sha256=value['projection_sha256'],
            publisher_code_sha256=sha256(bounded_bytes(Path(__file__).parents[1]/'src/la/report/results.py',limit=512*1024)),
            visibility=args.visibility,registry_head=head)
        if args.preview:
            private=store.put('local_result_projection',value)
            return {'private_projection_capture':private,'unsigned_approval_payload_template':expected,'published':False}
        if not args.approval or not args.public_trust_root or not args.public_trust_profile:
            raise ValueError('exact signed run-owner projection approval and explicit public trust required')
        from evaluation.eligibility import ReceiptVerifier
        from la.app.public_trust import public_keys
        signed=read(Path(args.approval).resolve(strict=True))
        if ReceiptVerifier(*public_keys(args.public_trust_root,args.public_trust_profile)).verify(signed,'run_owner')!=expected:
            raise ValueError('signed approval differs from exact safe projection/code/registry head')
        approval_pin=digest(signed)
    elif args.preview: raise ValueError('preview is private active-hidden workflow only')
    if registry and registry.head!=head: raise ValueError('edition changed while preparing projection; retry explicitly')
    return publish(value,args.out,approval_sha256=approval_pin)


def main():
    try:
        from la.app.cli import emit_result
        emit_result(execute(parser().parse_args()))
    except (ValueError,OSError,KeyError,TypeError,ImportError,AttributeError) as exc:
        raise SystemExit('la_results: '+type(exc).__name__+'; inspect local non-secret contracts') from None


if __name__=='__main__': main()

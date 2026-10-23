"""Local user journey. Evaluation stays outside the inference wheel."""
from __future__ import annotations

import argparse
import json
import os
import uuid
from pathlib import Path

from la.contracts import canonical, digest, sha256, validate_generation
from .artifacts import within, read, immutable, pointer, identity, load_run, receipt, checked_receipt,run_identity
from .storage import (bounded_bytes, publish_bytes, run_lock, pointer_token,
                      SOURCE_BYTES, MEMBER_BYTES, atomic_directory, stage_inventory)
from .storage import observe_source
from .recovery import current_generation


def cache_pointer(path, value):
    pointer(path, value, expected=pointer_token(path))


def parser():
    p = argparse.ArgumentParser(description='Evidence-bound account migration candidates; runtime acceptance is separate')
    p.add_argument('--root', default='.la-runs', help='declared private run store root')
    sub = p.add_subparsers(dest='command', required=True)
    q = sub.add_parser('ingest')
    q.add_argument('file'); q.add_argument('--input-root', default='.')
    q.add_argument('--brief', required=True); q.add_argument('--samples', required=True)
    q.add_argument('--encoding', default='ASCII'); q.add_argument('--record-type', '--record-family', default='fixed-width')
    q.add_argument('--numeric', default='ascii')
    q = sub.add_parser('hypothesize'); q.add_argument('run')
    q.add_argument('--mode', choices=['rules', 'mock', 'live'], default='rules')
    q.add_argument('--provider-config')
    for name in ('questions', 'status', 'preview', 'export', 'transform', 'history', 'replay', 'rulings-export', 'provider-export', 'storage-inspect'):
        sub.add_parser(name).add_argument('run')
    q=sub.add_parser('inspect'); q.add_argument('run'); q.add_argument('--offset',type=int,default=0)
    q.add_argument('--limit',type=int,default=50); q.add_argument('--authorized-only',action='store_true')
    q=sub.add_parser('detail'); q.add_argument('run'); q.add_argument('ordinal',type=int)
    q.add_argument('--start',type=int,default=0); q.add_argument('--end',type=int)
    q.add_argument('--authorized-only',action='store_true')
    q=sub.add_parser('explain'); q.add_argument('run'); q.add_argument('candidate',nargs='?')
    q.add_argument('--offset',type=int,default=0); q.add_argument('--limit',type=int,default=8)
    q.add_argument('--examples',type=int,default=1); q.add_argument('--owner',action='store_true',help='explicit local-owner retained-source mode')
    q=sub.add_parser('bundle-inspect'); q.add_argument('bundle')
    q.add_argument('--expected-bundle-sha256'); q.add_argument('--expected-source-sha256'); q.add_argument('--expected-mapping-sha256')
    q = sub.add_parser('answer'); q.add_argument('run'); q.add_argument('question'); q.add_argument('option')
    q.add_argument('--actor', required=True); q.add_argument('--reason', required=True)
    q.add_argument('--revision', type=int, required=True); q.add_argument('--request-id', required=True)
    q = sub.add_parser('approve'); q.add_argument('run')
    q.add_argument('--actor', required=True); q.add_argument('--reason', required=True)
    q = sub.add_parser('declare-filler'); q.add_argument('run'); q.add_argument('--spans', required=True)
    q.add_argument('--actor', required=True); q.add_argument('--reason', required=True)
    q = sub.add_parser('report'); q.add_argument('run')
    q.add_argument('--offset',type=int,default=0); q.add_argument('--limit',type=int,default=50)
    q.add_argument('--authorized-only',action='store_true')
    q.add_argument('--field-offset',type=int,default=0); q.add_argument('--field-limit',type=int,default=8)
    q.add_argument('--examples',type=int,default=1)
    q.add_argument('--evaluation-receipt', help='explicit evaluator receipt relative to declared root')
    for name in ('database-check', 'database-reconcile', 'database-rollback', 'database-constraints'):
        q = sub.add_parser(name); q.add_argument('bundle')
        q.add_argument('--authorized', action='store_true')
        q.add_argument('--authority', help='non-secret authority packet relative to declared root')
        q.add_argument('--target-config', help='pinned non-secret TargetConfig JSON relative to declared root')
        q.add_argument('--dsn-env', default='LA_TEST_DATABASE_DSN', help='environment variable NAME, never a DSN')
        if name == 'database-reconcile':
            q.add_argument('--namespace', required=True)
            q.add_argument('--execution-receipt', required=True, help='original immutable execution receipt relative to root')
    for name in ('database-observe','database-recover'):
        q=sub.add_parser(name); q.add_argument('bundle'); q.add_argument('--authority'); q.add_argument('--target-config')
        q.add_argument('--public-trust-root'); q.add_argument('--public-trust-profile')
        q.add_argument('--dsn-env',default='LA_TEST_DATABASE_DSN')
        q.add_argument('--negative',action='append',default=[],choices=['rollback','nonnull','check','numeric_overflow','duplicate_identity','invalid_date'])
        if name=='database-recover': q.add_argument('--observation-receipt',required=True)
    return p


def ingest(root, args):
    from la.ingest import ingest_bytes
    inputs = Path(args.input_root).resolve()
    data,observation = observe_source(within(inputs, args.file, exists=True))
    brief = bounded_bytes(within(inputs, args.brief, exists=True), limit=16000).decode('utf-8')
    samples = read(within(inputs, args.samples, exists=True))
    if data is None:
        from la.ingest.observed import refuse_observed_input
        batch=refuse_observed_input(source_sha256=observation['source_sha256'],input_byte_count=observation['input_byte_count'],
            observed_count=observation['observed_count'],reason='input_changed_during_read' if not observation['stable'] else 'file_limit',
            brief=brief,permitted_samples=samples,terminal_newline=observation['terminal_newline'],
            observation_stable=observation['stable'],observation_complete=observation['complete_stream'],
            declared_encoding=args.encoding,declared_record_type=args.record_type,declared_numeric=args.numeric,
            observation_pins={k:observation[k] for k in ('before_identity_sha256','after_identity_sha256','reader_policy_sha256')})
    else:
        batch = ingest_bytes(data, brief, samples, declared_encoding=args.encoding,
                             declared_record_type=args.record_type, declared_numeric=args.numeric)
    run_id = run_identity(batch)
    run = within(root, run_id)
    with run_lock(root, run_id):
        run.mkdir(exist_ok=True)
        # Exact retry can finish an interrupted intake only if all existing
        # immutable members equal the original input. Manifest commits last.
        for name, payload in ([('source.dat', data)] if data is not None else [])+[('brief.md', brief.encode())]:
            publish_bytes(within(run, name), payload, limit=SOURCE_BYTES if name=='source.dat' else 16000)
        if data is None: immutable(within(run,'source-observation.json'),observation)
        immutable(within(run, 'samples.json'), samples)
        immutable(within(run, 'batch.json'), batch)
        manifest=dict(schema_version=1, run=run_id,
                  batch_sha256=digest(batch), source_sha256=batch['source_sha256'],
                  brief_sha256=batch['brief_sha256'], samples_sha256=digest(samples), config_sha256=batch['config_sha256'])
        if data is None: manifest['source_observation_sha256']=digest(observation)
        immutable(within(run, 'run.json'),manifest)
        load_run(root, run_id)
    return dict(run=run_id, batch_status=batch['status'], reasons=batch['reasons'],
                observed_record_count=batch.get('intake', batch['samples'].get('intake', {})).get('observed_record_count', len(batch['records'])),
                states=empty_states())


def empty_states():
    return dict(mapping_status='incomplete', transformation_status='not_run', row_parity='not_run',
                target_validation='not_run', benchmark_status='not_run', product_acceptance='pending')


def approval_for(run, mapping):
    index = within(run, 'approvals/'+mapping['mapping_sha256']+'/current.json')
    if not index.exists(): return None
    key = identity(read(index)['approval_sha256'])
    approval = read(within(index.parent, key+'.json', exists=True))
    from la.convert import approve_mapping
    if approval.get('approval_sha256') != key or approval != approve_mapping(mapping, approval['actor'], approval['reason']):
        raise ValueError('approval stale or tampered')
    return approval


def ranking_for(run, generation):
    index = within(run, 'current-ranking.json')
    if not index.exists(): return None
    key = identity(read(index)['receipt_sha256'])
    ranking = read(within(run, 'ranking-'+key+'.json', exists=True))
    if ranking.get('receipt_sha256') != key or digest({k:v for k,v in ranking.items() if k != 'receipt_sha256'}) != key:
        raise ValueError('ranking receipt changed')
    return ranking if ranking['generation_sha256'] == generation['generation_sha256'] else None


def ranked_questions(generation, ranking):
    from la.review import questions
    offered = questions(generation)
    if not ranking or ranking.get('status') in ('failed', 'failed_invalid_ranking') or ranking.get('abstain'):
        return offered
    order = {candidate:index for index,candidate in enumerate(ranking.get('candidate_ids', []))}
    for question in offered:
        # Change display order only. All offered IDs/unknown remain; question
        # dependency and content-bound answers retain the original producer IDs.
        question['options'] = sorted(question['options'], key=lambda o: (
            o['id'] == 'unknown', order.get(o['id'], len(order))))
    return offered


def export_bundle_checked(run, batch, generation, store, mapping, outcomes, approval, *, brief=None, permitted_samples=None):
    from la.convert import export_bundle
    parent=within(run,'bundles')
    stage=within(parent,'.bundle-stage.la-tmp-'+uuid.uuid4().hex)
    # Compile first, so final content identity includes current producer code,
    # actual inputs and lineage. Old-code bundles keep their own destinations.
    manifest=export_bundle(stage,batch,mapping,outcomes,approval=approval,generation=generation,
                           rulings=store,brief=brief,permitted_samples=permitted_samples)
    key=identity(manifest['bundle_sha256'])
    bundle=within(parent,key)
    if bundle.exists():
        names=set(manifest['files'])|{'manifest.json'}
        if {p.name for p in bundle.iterdir()}!=names: raise ValueError('unexpected frozen bundle member')
        for name in names:
            if bounded_bytes(within(bundle,name,exists=True))!=bounded_bytes(within(stage,name,exists=True)):
                raise ValueError('existing bundle differs from current content identity')
        if approval:
            from la.convert import verify_bundle
            audit=verify_bundle(bundle,expected_bundle_sha256=key,expected_source_sha256=batch['source_sha256'],expected_mapping_sha256=mapping['mapping_sha256'])
            if audit['integrity_status']!='verified': raise ValueError('existing approved bundle failed offline integrity')
        # Only the exact stage created by this call, with its exact known members,
        # is removed on an identical retry. Crash or foreign stages are retained.
        if stage.parent.resolve()!=parent.resolve() or {p.name for p in stage.iterdir()}!=names:
            raise ValueError('own stage scope changed; preserve for inspection')
        for name in names:
            member=within(stage,name,exists=True)
            if member.parent!=stage.resolve() or member.is_symlink(): raise ValueError('stage member escape')
            member.unlink()
        stage.rmdir()
        return bundle, manifest
    atomic_directory(stage, bundle)
    return bundle, manifest


def states_for(run, mapping):
    states = dict(empty_states(), mapping_status=mapping['mapping_status'])
    index = within(run, 'current-transformation.json')
    if index.exists():
        saved = checked_receipt(run, read(index)['relative_path'], kind='transformation')
        if saved['payload']['mapping_sha256'] == mapping['mapping_sha256']:
            from la.convert import verify_bundle
            payload=saved['payload']
            audit=verify_bundle(within(run,payload.get('bundle_relative_path','bundles/'+payload['bundle_sha256']),exists=True),
                expected_bundle_sha256=payload['bundle_sha256'],expected_source_sha256=mapping['source_sha256'],
                expected_mapping_sha256=mapping['mapping_sha256'])
            if audit['integrity_status']=='verified' and audit['pin_status']=='matched':
                states['transformation_status'] = payload['transformation_status']
    # Target/evaluation receipts are displayed separately. Product acceptance is
    # never inferred from source artifacts or a caller-supplied success boolean.
    return states


def execute(args):
    root = Path(args.root).resolve()
    root.mkdir(parents=True, exist_ok=True)
    if args.command == 'ingest': return _execute(args)
    if hasattr(args,'run'): key=identity(args.run)
    else:
        relative=within(root,args.bundle,exists=True).relative_to(root)
        if not relative.parts: raise ValueError('bundle must be a member below declared store')
        key=relative.parts[0]
    with run_lock(root, key):
        return _execute(args)


def _execute(args):
    root = Path(args.root).resolve()
    root.mkdir(parents=True, exist_ok=True)
    if args.command == 'ingest': return ingest(root, args)
    if args.command in ('database-observe','database-recover'):
        from .observations import execute_observation
        return execute_observation(root,args)
    if args.command.startswith('database-'):
        from .target import execute_target
        return execute_target(root, args)
    if args.command=='bundle-inspect':
        from la.convert import verify_bundle
        audit=verify_bundle(within(root,args.bundle,exists=True),expected_bundle_sha256=args.expected_bundle_sha256,
            expected_source_sha256=args.expected_source_sha256,expected_mapping_sha256=args.expected_mapping_sha256)
        return receipt(root,'verification',audit)
    if args.command == 'storage-inspect':
        run=within(root,identity(args.run),exists=True)
        return dict(run=args.run, orphan_stages=stage_inventory(run),
                    bundle_stages=stage_inventory(within(run,'bundles')) if within(run,'bundles').exists() else [],
                    cleanup_performed=False, decision_authority='SQLite ruling journal')
    run, batch, brief = load_run(root, args.run)
    if args.command == 'provider-export':
        from la.providers.accounting import CallLedger
        ledger = within(root, 'provider-accounting.sqlite', exists=True)
        return CallLedger(ledger).export(within(run, 'provider-exports'))
    from la.review import RulingStore, build_mapping, questions
    store_path=within(run,'rulings.sqlite')
    if store_path.exists() and store_path.stat().st_size>MEMBER_BYTES:
        raise ValueError('ruling authority storage limit; preserve journal for authorized archival')
    store = RulingStore(store_path)
    if args.command in ('inspect','detail'):
        from la.ingest.inspection import inspection_page,inspection_detail
        g=current_generation(run,batch,store)
        m=build_mapping(batch,g,store.projection(g)) if g else None
        if args.command=='inspect':
            return inspection_page(batch,offset=args.offset,limit=args.limit,authorized_only=args.authorized_only,generation=g,mapping=m)
        return inspection_detail(batch,args.ordinal,start=args.start,end=args.end,authorized_only=args.authorized_only,generation=g,mapping=m)
    if args.command == 'hypothesize':
        from la.inference import hypothesize
        from la.providers import rank
        before=store.current_state()
        generation = hypothesize(batch, brief, 'mock' if args.mode == 'mock' else 'rules')
        config = read(within(root, args.provider_config, exists=True)) if args.provider_config else None
        # Reserve against the stable layout run, not a new generation per repair.
        ranking = rank(generation, mode=args.mode, ledger_path=within(root, 'provider-accounting.sqlite'),
                       batch=batch, brief=brief, config=config, run=args.run)
        immutable(within(run, 'generation-'+generation['generation_sha256']+'.json'), generation)
        immutable(within(run, 'ranking-'+ranking['receipt_sha256']+'.json'), ranking)
        store.bind_generation(generation,expected_state_token=before['state_token'])
        current_generation(run,batch,store)
        cache_pointer(within(run, 'current-ranking.json'), {'receipt_sha256': ranking['receipt_sha256']})
        if args.mode == 'live':
            from la.providers.accounting import CallLedger
            CallLedger(within(root, 'provider-accounting.sqlite')).export(within(run, 'provider-exports'))
        return dict(generation=generation, ranking=ranking, states=empty_states())
    if args.command == 'history': return {'events': store.events()}
    if args.command == 'rulings-export':
        events = store.events()
        path = within(run, 'ruling-exports/'+digest(events)+'.jsonl')
        if path.exists():
            expected = b''.join(canonical(event)+b'\n' for event in events)
            if bounded_bytes(path) != expected: raise ValueError('ruling export changed')
            return {'path': str(path), 'events': len(events), 'sha256': sha256(expected)}
        return store.export(path)
    generation=current_generation(run,batch,store)
    if generation is None:
        if args.command in ('status', 'preview', 'report'):
            artifacts = dict(run=args.run, source_batch=batch, states=empty_states(), preview_only=True)
            from la.ingest.inspection import inspection_page
            if args.command=='status': return dict(run=args.run,states=empty_states(),approval=None,intake=batch.get('intake',{}))
            if args.command=='preview': return dict(run=args.run,states=empty_states(),inspection=inspection_page(batch),preview_only=True)
            if args.evaluation_receipt: raise ValueError('no current mapping to bind evaluator evidence')
            artifacts['inspection']=inspection_page(batch,offset=args.offset,limit=args.limit,authorized_only=args.authorized_only)
            if args.authorized_only: artifacts.pop('source_batch',None)
            return save_report(run, artifacts)
        raise ValueError('hypothesize this run before review/export')
    # Recheck active generation on every operation; loading a prior file never
    # reactivates old answers. Only explicit hypothesize changes current binding.
    projection = store.projection(generation)
    if args.command=='explain':
        from la.inference.explanation import explain_candidate,explain_layout
        if args.candidate is not None:
            return explain_candidate(batch,generation,args.candidate,authorized_only=not args.owner,examples_limit=args.examples)
        return explain_layout(batch,generation,authorized_only=not args.owner,offset=args.offset,limit=args.limit,examples_limit=args.examples)
    if args.command == 'declare-filler':
        from la.inference import declare_filler
        spans = read(within(root, args.spans, exists=True))
        before=store.current_state()
        changed = declare_filler(batch, generation, spans, actor=args.actor, reason=args.reason)
        immutable(within(run, 'generation-'+changed['generation_sha256']+'.json'), changed)
        store.bind_generation(changed,expected_state_token=before['state_token'])
        current_generation(run,batch,store)
        return dict(generation=changed, prior_generation_sha256=generation['generation_sha256'],
                    approvals_invalidated=True, states=empty_states())
    if args.command == 'replay': return store.replay(generation)
    if args.command == 'questions':
        ranking = ranking_for(run, generation)
        return dict(questions=ranked_questions(generation, ranking), rulings=projection, ranking=ranking)
    if args.command == 'answer':
        return store.answer(generation, args.question, args.option, args.actor, args.reason, args.revision, args.request_id)
    mapping = build_mapping(batch, generation, projection)
    if args.command == 'approve':
        from la.convert import approve_mapping
        approval = approve_mapping(mapping, args.actor, args.reason)
        folder = within(run, 'approvals/'+mapping['mapping_sha256'])
        immutable(within(folder, approval['approval_sha256']+'.json'), approval)
        cache_pointer(within(folder, 'current.json'), {'approval_sha256': approval['approval_sha256']})
        return approval
    approval = approval_for(run, mapping)
    from la.convert import transform
    if args.command == 'transform' and approval is None:
        raise ValueError('explicit current complete-mapping approval required')
    outcomes = transform(batch, mapping)
    if args.command in ('export', 'transform'):
        bundle, manifest = export_bundle_checked(run, batch, generation, store, mapping, outcomes, approval,
            brief=brief,permitted_samples=read(within(run,'samples.json',exists=True)))
        result = dict(bundle=str(bundle), manifest=manifest, states=states_for(run, mapping))
        if args.command == 'transform':
            saved = receipt(run, 'transformation', dict(source_sha256=batch['source_sha256'],
                mapping_sha256=mapping['mapping_sha256'], approval_sha256=approval['approval_sha256'],
                bundle_sha256=manifest['bundle_sha256'], transformation_status=manifest['transformation_status'],
                outcome_sha256=digest(outcomes), counts=manifest['counts'],producer_code_sha256=manifest['producer_code_sha256'],
                bundle_relative_path=str(bundle.relative_to(run))))
            cache_pointer(within(run, 'current-transformation.json'), {'relative_path': str(Path(saved['path']).relative_to(run))})
            result.update(transformation_receipt=saved, states=states_for(run, mapping))
        return result
    artifacts = dict(run=args.run, source_batch=batch, generation=generation,
        questions=ranked_questions(generation, ranking_for(run, generation)), ruling_history=store.events(), rulings=projection,
        ranking=ranking_for(run, generation), mapping=mapping, approval=approval,
        preview_outcomes=outcomes, preview_only=True, states=states_for(run, mapping),
        load_rows_available=approval is not None and mapping['mapping_status'] == 'complete')
    if args.command == 'report':
        from la.ingest.inspection import inspection_page
        page=inspection_page(batch,offset=args.offset,limit=args.limit,authorized_only=args.authorized_only,generation=generation,mapping=mapping)
        if args.authorized_only:
            artifacts=dict(run=args.run,inspection=page,states=states_for(run,mapping),preview_only=True,
                           access_note='permitted spans only; free text, rulings, typed previews and neighboring bytes omitted')
        else: artifacts['inspection']=page
        from la.inference.explanation import explain_layout
        artifacts['explanations']=explain_layout(batch,generation,authorized_only=args.authorized_only,
            offset=args.field_offset,limit=args.field_limit,examples_limit=args.examples)
        execution_index = within(run, 'current-execution.json')
        if execution_index.exists() and not args.authorized_only:
            observed = checked_receipt(run, read(execution_index)['relative_path'], kind='execution')
            if observed['payload']['mapping_sha256'] == mapping['mapping_sha256']:
                artifacts['execution_receipt'] = observed
        target_index=within(run,'current-target-observation.json')
        if target_index.exists() and not args.authorized_only:
            target=checked_receipt(run,read(target_index)['relative_path'],kind='target-observation')
            if target['payload']['mapping_sha256']==mapping['mapping_sha256']:
                artifacts['target_observation_receipt']=target
        if args.evaluation_receipt:
            if args.authorized_only: raise ValueError('permitted-only reports omit external free-text evaluation evidence')
            supplied = checked_receipt(root, args.evaluation_receipt, kind='evaluation')
            pins = supplied['payload']
            if pins.get('source_sha256') != batch['source_sha256'] or pins.get('mapping_sha256') != mapping['mapping_sha256']:
                raise ValueError('evaluation receipt binds another source/mapping')
            artifacts['evaluation_receipt'] = supplied
            artifacts['evaluation_provenance'] = 'explicitly supplied evaluator evidence; independent acceptance remains pending'
            result = pins.get('result', {})
            if pins.get('operation') in ('parity', 'target'):
                if result.get('row_parity') in ('not_run', 'exact', 'mismatch', 'incomplete'):
                    artifacts['states']['row_parity'] = result['row_parity']
                if pins['operation'] == 'target' and result.get('target_validation') in ('not_run', 'failed', 'indeterminate', 'passed'):
                    artifacts['states']['target_validation'] = result['target_validation']
        return save_report(run, artifacts)
    if args.command=='status':
        return dict(run=args.run,states=artifacts['states'],approval=approval,
            mapping=dict(mapping_sha256=mapping['mapping_sha256'],mapping_status=mapping['mapping_status'],unresolved=mapping['unresolved']),
            intake=batch.get('intake',batch['samples'].get('intake',{})))
    if args.command=='preview':
        from la.ingest.inspection import inspection_page
        page=inspection_page(batch,generation=generation,mapping=mapping)
        ordinals={row['ordinal'] for row in page['rows']}
        return dict(run=args.run,states=artifacts['states'],inspection=page,preview_only=True,
                    preview_outcomes=[o for o in outcomes if o['record_ref']['ordinal'] in ordinals])
    raise ValueError('unsupported command')


def save_report(run, artifacts):
    from la.report import render_report
    from la.report.html import renderer_pin
    key = digest({'artifacts':artifacts,'renderer_sha256':renderer_pin()})
    path = within(run, 'reports/'+key+'.html')
    text = render_report(artifacts)
    publish_bytes(path, text.encode(), limit=MEMBER_BYTES)
    return dict(report=str(path), report_input_sha256=key, states=artifacts['states'])


def emit_result(result):
    text=json.dumps(result,indent=2,ensure_ascii=False)
    if len(text.encode())>MEMBER_BYTES: raise ValueError('CLI output limit; use bounded inspection pages')
    print(text)


def main():
    try:
        emit_result(execute(parser().parse_args()))
    except (ValueError, OSError, KeyError, TypeError) as exc:
        raise SystemExit('la: '+str(exc)) from exc

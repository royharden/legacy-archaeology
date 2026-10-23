"""Local user journey. Evaluation stays outside the inference wheel."""
from __future__ import annotations

import argparse
import json
import os
import uuid
from pathlib import Path

from la.contracts import canonical, digest, sha256, validate_generation
from .artifacts import within, read, immutable, pointer, identity, load_run, receipt, checked_receipt
from .storage import (bounded_bytes, publish_bytes, run_lock, pointer_token,
                      SOURCE_BYTES, MEMBER_BYTES, atomic_directory, stage_inventory)


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
    q = sub.add_parser('answer'); q.add_argument('run'); q.add_argument('question'); q.add_argument('option')
    q.add_argument('--actor', required=True); q.add_argument('--reason', required=True)
    q.add_argument('--revision', type=int, required=True); q.add_argument('--request-id', required=True)
    q = sub.add_parser('approve'); q.add_argument('run')
    q.add_argument('--actor', required=True); q.add_argument('--reason', required=True)
    q = sub.add_parser('declare-filler'); q.add_argument('run'); q.add_argument('--spans', required=True)
    q.add_argument('--actor', required=True); q.add_argument('--reason', required=True)
    q = sub.add_parser('report'); q.add_argument('run')
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
    return p


def ingest(root, args):
    from la.ingest import ingest_bytes
    inputs = Path(args.input_root).resolve()
    data = bounded_bytes(within(inputs, args.file, exists=True), limit=SOURCE_BYTES)
    brief = bounded_bytes(within(inputs, args.brief, exists=True), limit=16000).decode('utf-8')
    samples = read(within(inputs, args.samples, exists=True))
    batch = ingest_bytes(data, brief, samples, declared_encoding=args.encoding,
                         declared_record_type=args.record_type, declared_numeric=args.numeric)
    run_id = digest(dict(source=batch['source_sha256'], brief=batch['brief_sha256'],
                          samples=batch['samples']['artifact_sha256'], config=batch['config_sha256']))
    run = within(root, run_id)
    with run_lock(root, run_id):
        run.mkdir(exist_ok=True)
        # Exact retry can finish an interrupted intake only if all existing
        # immutable members equal the original input. Manifest commits last.
        for name, payload in [('source.dat', data), ('brief.md', brief.encode())]:
            publish_bytes(within(run, name), payload, limit=SOURCE_BYTES if name=='source.dat' else 16000)
        immutable(within(run, 'samples.json'), samples)
        immutable(within(run, 'batch.json'), batch)
        immutable(within(run, 'run.json'), dict(schema_version=1, run=run_id,
                  batch_sha256=digest(batch), source_sha256=batch['source_sha256'],
                  brief_sha256=batch['brief_sha256'], samples_sha256=digest(samples), config_sha256=batch['config_sha256']))
        load_run(root, run_id)
    return dict(run=run_id, batch_status=batch['status'], reasons=batch['reasons'],
                observed_record_count=batch.get('intake', batch['samples'].get('intake', {})).get('observed_record_count', len(batch['records'])),
                states=empty_states())


def empty_states():
    return dict(mapping_status='incomplete', transformation_status='not_run', row_parity='not_run',
                target_validation='not_run', benchmark_status='not_run', product_acceptance='pending')


def current_generation(run, batch):
    current = read(within(run, 'current-generation.json', exists=True))
    key = identity(current['generation_sha256'])
    generation = validate_generation(read(within(run, 'generation-'+key+'.json', exists=True)))
    if generation['generation_sha256'] != key or digest({k:v for k,v in generation.items() if k != 'generation_sha256'}) != key:
        raise ValueError('generation content hash mismatch')
    if any(generation[k] != batch[k] for k in ('source_sha256', 'framing_sha256', 'brief_sha256')):
        raise ValueError('generation dependency changed; hypothesize again')
    return generation


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


def export_bundle_checked(run, batch, generation, store, mapping, outcomes, approval):
    from la.convert import export_bundle
    key = digest(dict(mapping=mapping['mapping_sha256'], approval=approval))
    bundle = within(run, 'bundles/'+key)
    if bundle.exists():
        manifest = read(within(bundle, 'manifest.json', exists=True))
        if (digest({k:v for k,v in manifest.items() if k != 'bundle_sha256'}) != manifest.get('bundle_sha256')
                or manifest['mapping_sha256'] != mapping['mapping_sha256']
                or manifest.get('approval_sha256') != (approval['approval_sha256'] if approval else None)):
            raise ValueError('existing bundle identity changed')
        for name, expected in manifest['files'].items():
            if sha256(within(bundle, name, exists=True).read_bytes()) != expected:
                raise ValueError('existing bundle member changed')
        return bundle, manifest
    stage = within(bundle.parent, '.'+bundle.name+'.la-tmp-'+uuid.uuid4().hex)
    manifest = export_bundle(stage, batch, mapping, outcomes, approval=approval,
                             generation=generation, rulings=store)
    atomic_directory(stage, bundle)
    return bundle, manifest


def states_for(run, mapping):
    states = dict(empty_states(), mapping_status=mapping['mapping_status'])
    index = within(run, 'current-transformation.json')
    if index.exists():
        saved = checked_receipt(run, read(index)['relative_path'], kind='transformation')
        if saved['payload']['mapping_sha256'] == mapping['mapping_sha256']:
            states['transformation_status'] = saved['payload']['transformation_status']
    # Target/evaluation receipts are displayed separately. Product acceptance is
    # never inferred from source artifacts or a caller-supplied success boolean.
    return states


def execute(args):
    root = Path(args.root).resolve()
    root.mkdir(parents=True, exist_ok=True)
    if args.command == 'ingest': return _execute(args)
    key = identity(args.run) if hasattr(args, 'run') else within(root, args.bundle, exists=True).relative_to(root).parts[0]
    with run_lock(root, key):
        return _execute(args)


def _execute(args):
    root = Path(args.root).resolve()
    root.mkdir(parents=True, exist_ok=True)
    if args.command == 'ingest': return ingest(root, args)
    if args.command.startswith('database-'):
        from .target import execute_target
        return execute_target(root, args)
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
    store = RulingStore(within(run, 'rulings.sqlite'))
    if args.command == 'hypothesize':
        from la.inference import hypothesize
        from la.providers import rank
        generation = hypothesize(batch, brief, 'mock' if args.mode == 'mock' else 'rules')
        config = read(within(root, args.provider_config, exists=True)) if args.provider_config else None
        # Reserve against the stable layout run, not a new generation per repair.
        ranking = rank(generation, mode=args.mode, ledger_path=within(root, 'provider-accounting.sqlite'),
                       batch=batch, brief=brief, config=config, run=args.run)
        immutable(within(run, 'generation-'+generation['generation_sha256']+'.json'), generation)
        immutable(within(run, 'ranking-'+ranking['receipt_sha256']+'.json'), ranking)
        store.bind_generation(generation)
        cache_pointer(within(run, 'current-generation.json'), {'generation_sha256': generation['generation_sha256']})
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
    if not within(run, 'current-generation.json').exists():
        if args.command in ('status', 'preview', 'report'):
            artifacts = dict(run=args.run, source_batch=batch, states=empty_states(), preview_only=True)
            if args.command != 'report': return artifacts
            return save_report(run, artifacts)
        raise ValueError('hypothesize this run before review/export')
    generation = current_generation(run, batch)
    # Recheck active generation on every operation; loading a prior file never
    # reactivates old answers. Only explicit hypothesize changes current binding.
    projection = store.projection(generation)
    if args.command == 'declare-filler':
        from la.inference import declare_filler
        spans = read(within(root, args.spans, exists=True))
        changed = declare_filler(batch, generation, spans, actor=args.actor, reason=args.reason)
        immutable(within(run, 'generation-'+changed['generation_sha256']+'.json'), changed)
        store.bind_generation(changed)
        cache_pointer(within(run, 'current-generation.json'), {'generation_sha256': changed['generation_sha256']})
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
        bundle, manifest = export_bundle_checked(run, batch, generation, store, mapping, outcomes, approval)
        result = dict(bundle=str(bundle), manifest=manifest, states=states_for(run, mapping))
        if args.command == 'transform':
            saved = receipt(run, 'transformation', dict(source_sha256=batch['source_sha256'],
                mapping_sha256=mapping['mapping_sha256'], approval_sha256=approval['approval_sha256'],
                bundle_sha256=manifest['bundle_sha256'], transformation_status=manifest['transformation_status'],
                outcome_sha256=digest(outcomes), counts=manifest['counts']))
            cache_pointer(within(run, 'current-transformation.json'), {'relative_path': str(Path(saved['path']).relative_to(run))})
            result.update(transformation_receipt=saved, states=states_for(run, mapping))
        return result
    artifacts = dict(run=args.run, source_batch=batch, generation=generation,
        questions=ranked_questions(generation, ranking_for(run, generation)), ruling_history=store.events(), rulings=projection,
        ranking=ranking_for(run, generation), mapping=mapping, approval=approval,
        preview_outcomes=outcomes, preview_only=True, states=states_for(run, mapping),
        load_rows_available=approval is not None and mapping['mapping_status'] == 'complete')
    if args.command == 'report':
        execution_index = within(run, 'current-execution.json')
        if execution_index.exists():
            observed = checked_receipt(run, read(execution_index)['relative_path'], kind='execution')
            if observed['payload']['mapping_sha256'] == mapping['mapping_sha256']:
                artifacts['execution_receipt'] = observed
        if args.evaluation_receipt:
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
    if args.command in ('status', 'preview'): return artifacts
    raise ValueError('unsupported command')


def save_report(run, artifacts):
    from la.report import render_report
    key = digest(artifacts)
    path = within(run, 'reports/'+key+'.html')
    text = render_report(artifacts)
    publish_bytes(path, text.encode(), limit=MEMBER_BYTES)
    return dict(report=str(path), report_input_sha256=key, states=artifacts['states'])


def main():
    try:
        print(json.dumps(execute(parser().parse_args()), indent=2, ensure_ascii=False))
    except (ValueError, OSError, KeyError, TypeError) as exc:
        raise SystemExit('la: '+str(exc)) from exc

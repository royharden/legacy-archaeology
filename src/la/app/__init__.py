"""Local CLI. Paths are restricted to declared input/run roots."""
from __future__ import annotations
import argparse
import json
from pathlib import Path
from la.contracts import canonical, digest

def within(root: Path, value: str, *, exists=False) -> Path:
    root = root.resolve()
    path = (root / value).resolve()
    if not path.is_relative_to(root): raise ValueError('path escapes declared root')
    if exists and not path.exists(): raise ValueError('path does not exist')
    return path

def read(path: Path):
    return json.loads(path.read_text(encoding='utf-8'))

def write(path: Path, value):
    path.write_bytes(canonical(value)+b'\n')

def parser():
    p = argparse.ArgumentParser(description='Fixed-width account archaeology; no model transforms values')
    p.add_argument('--root', default='.la-runs', help='declared run store root')
    sub = p.add_subparsers(dest='command', required=True)
    q = sub.add_parser('ingest')
    q.add_argument('file'); q.add_argument('--input-root',default='.')
    q.add_argument('--brief',required=True); q.add_argument('--samples',required=True)
    q = sub.add_parser('hypothesize'); q.add_argument('run'); q.add_argument('--mode',choices=['rules','mock','live'],default='rules')
    q = sub.add_parser('questions'); q.add_argument('run')
    q = sub.add_parser('answer'); q.add_argument('run'); q.add_argument('question'); q.add_argument('option')
    q.add_argument('--actor',required=True); q.add_argument('--reason',required=True)
    q.add_argument('--revision',type=int,required=True); q.add_argument('--request-id',required=True)
    q = sub.add_parser('approve'); q.add_argument('run'); q.add_argument('--actor',required=True); q.add_argument('--reason',required=True)
    for command in ('export','transform','report'):
        q=sub.add_parser(command); q.add_argument('run')
    q=sub.add_parser('database-check'); q.add_argument('bundle'); q.add_argument('--authorized',action='store_true')
    return p

def execute(args):
    root=Path(args.root).resolve()
    root.mkdir(parents=True,exist_ok=True)
    if args.command=='ingest':
        from la.ingest import ingest_bytes
        inputs=Path(args.input_root).resolve()
        data=within(inputs,args.file,exists=True).read_bytes()
        brief=within(inputs,args.brief,exists=True).read_text(encoding='utf-8')
        samples=read(within(inputs,args.samples,exists=True))
        batch=ingest_bytes(data,brief,samples)
        run_id=digest({'source':batch['source_sha256'],'brief':batch['brief_sha256'],'samples':batch['samples']['artifact_sha256'],'config':batch['config_sha256']})
        run=within(root,run_id)
        if run.exists():
            if read(run/'batch.json')!=batch: raise ValueError('immutable run identity collision')
            return {'run':run_id,'batch_status':batch['status'],'reasons':batch['reasons']}
        run.mkdir()
        (run/'source.dat').write_bytes(data); (run/'brief.md').write_text(brief,encoding='utf-8')
        write(run/'samples.json',samples); write(run/'batch.json',batch)
        return {'run':run_id,'batch_status':batch['status'],'reasons':batch['reasons']}
    if args.command=='database-check':
        from la.postgres import database_check
        return database_check(within(root,args.bundle,exists=True),authorized=args.authorized)
    run=within(root,args.run,exists=True)
    batch=read(run/'batch.json')
    from la.contracts import sha256, validate_batch
    batch=validate_batch(batch)
    source=(run/'source.dat').read_bytes()
    if sha256(source)!=batch['source_sha256']: raise ValueError('retained source hash mismatch')
    if any(source[r['byte_start']:r['byte_start']+r['length']].hex()!=r['raw_hex'] for r in batch['records']):
        raise ValueError('record evidence no longer resolves to retained source')
    from la.review import RulingStore, build_mapping, questions
    store=RulingStore(run/'rulings.sqlite')
    if args.command=='hypothesize':
        from la.inference import hypothesize
        from la.providers import rank
        generation=hypothesize(batch,(run/'brief.md').read_text(encoding='utf-8'),args.mode)
        generation_path=run/('generation-'+generation['generation_sha256']+'.json')
        if not generation_path.exists(): write(generation_path,generation)
        write(run/'current-generation.json',{'generation_sha256':generation['generation_sha256']})
        store.bind_generation(generation)
        rank(generation,mode=args.mode,ledger_path=run/'provider-ledger.jsonl')
        return generation
    current=read(run/'current-generation.json')['generation_sha256']
    generation=read(run/('generation-'+current+'.json'))
    if args.command=='questions': return {'questions':questions(generation),'rulings':store.projection(generation)}
    if args.command=='answer':
        return store.answer(generation,args.question,args.option,args.actor,args.reason,args.revision,args.request_id)
    mapping=build_mapping(batch,generation,store.projection(generation))
    if args.command=='approve':
        from la.convert import approve_mapping
        approval=approve_mapping(mapping,args.actor,args.reason)
        write(run/('approval-'+mapping['mapping_sha256']+'.json'),approval)
        return approval
    approval_path=run/('approval-'+mapping['mapping_sha256']+'.json')
    approval=read(approval_path) if approval_path.exists() else None
    from la.convert import transform, export_bundle
    if args.command=='transform' and approval is None: raise ValueError('explicit complete-mapping approval required')
    outcomes=transform(batch,mapping)
    if args.command in ('export','transform'):
        bundle=run/'bundles'/digest({'mapping':mapping['mapping_sha256'],'approval':approval})
        if bundle.exists():
            manifest=read(bundle/'manifest.json')
            from la.contracts import sha256
            if digest({k:v for k,v in manifest.items() if k!='bundle_sha256'})!=manifest.get('bundle_sha256') or manifest.get('approval_sha256')!=(approval['approval_sha256'] if approval else None) or manifest['mapping_sha256']!=mapping['mapping_sha256'] or any(sha256(within(bundle,name,exists=True).read_bytes())!=expected for name,expected in manifest['files'].items()):
                raise ValueError('existing immutable bundle failed verification')
            return manifest
        return export_bundle(bundle,batch,mapping,outcomes,approval=approval)
    if args.command=='report':
        from la.report import render_report
        report=render_report({'source_batch':batch,'generation':generation,'questions':questions(generation),
            'mapping':mapping,'approval':approval,'outcomes':outcomes})
        path=run/('report-'+mapping['mapping_sha256']+'.html')
        path.write_text(report,encoding='utf-8')
        return {'report':str(path),'target_validation':'not_run','product_acceptance':'pending'}
    raise ValueError('unsupported command')

def main():
    try:
        result=execute(parser().parse_args())
        print(json.dumps(result,indent=2,ensure_ascii=False))
    except (ValueError,OSError,KeyError,TypeError) as exc:
        raise SystemExit('la: '+str(exc)) from exc

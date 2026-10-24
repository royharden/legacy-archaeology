"""Explicit run-owner release adapter for evaluator-owned portable archives.

Source-only caller of evaluation.archive. No extraction, signing, code loading,
model/target execution, retirement or journal creation on import.
"""
import argparse
from pathlib import Path


def plan_from_packet(store,registry,root,packet):
    from la.contracts.protocol import closed
    from la.app.artifacts import within,read
    from scripts.results import captured
    from evaluation.runner import VariantCase,BatchCase
    from evaluation.archive import plan_archive
    closed(packet,{'schema_version','edition','visibility','manifest_refs','cases','configuration'})
    if type(packet['schema_version']) is not int or packet['schema_version']!=1 or packet['visibility'] not in ('public','retired'):
        raise ValueError('closed public/retired archive caller packet required')
    refs=packet['manifest_refs']
    if type(refs) is not list or not 1<=len(refs)<=18: raise ValueError('bounded exact archive manifests required')
    manifests=[captured(store,ref,'variant_manifest') for ref in refs]
    if any(m['edition']!=packet['edition'] for m in manifests): raise ValueError('archive edition differs from actual manifests')
    state=registry.state(packet['edition'])
    if packet['visibility']=='public' and any(m['split']=='heldout' for m in manifests):
        raise ValueError('active hidden raw archive/export forbidden before cases/oracle access')
    if packet['visibility']=='retired' and (not state['retired'] or state.get('attempt') is not None and state['attempt']['status']=='running'):
        raise ValueError('actual terminal retirement required before cases/oracle access')
    raw=read(within(root,packet['cases'],exists=True))
    if type(raw) is not dict or set(raw)!={'variants'} or type(raw['variants']) is not list or len(raw['variants'])!=len(refs):
        raise ValueError('exact actual archive case set required')
    cases=[]
    for item in raw['variants']:
        closed(item,{'variant_id','split','edition','visible','batches'},{'accepted_choices','expected_layout'})
        if item['edition']!=packet['edition']: raise ValueError('archive case edition mismatch')
        cases.append(VariantCase(item['variant_id'],item['split'],item['edition'],item['visible'],
            tuple(BatchCase(batch['batch_id'],batch['visible'],batch['oracle']) for batch in item['batches']),
            item.get('accepted_choices',{}),item.get('expected_layout')))
    configuration=read(within(root,packet['configuration'],exists=True))
    return plan_archive(store,cases=cases,manifest_refs=refs,configuration=configuration,registry=registry,visibility=packet['visibility'])


def parser():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--operator-root',required=True); p.add_argument('--capture-root',required=True)
    sub=p.add_subparsers(dest='command',required=True)
    for name in ('plan','export','read','replay','projection'):
        q=sub.add_parser(name)
        if name in ('plan','export','projection'): q.add_argument('--registry',required=True)
        if name in ('plan','export'): q.add_argument('--packet',required=True)
        if name!='plan':
            q.add_argument('--public-trust-root',required=True); q.add_argument('--public-trust-profile',required=True)
        if name=='export': q.add_argument('--signed-release',required=True); q.add_argument('--destination',required=True)
        if name in ('read','replay'):
            q.add_argument('--archive',required=True); q.add_argument('--expected-archive-sha256',required=True)
        if name=='replay':
            q.add_argument('--result-store',required=True); q.add_argument('--scorer-version',default='semantic-v1')
        if name=='projection':
            q.add_argument('--reference',required=True); q.add_argument('--signed-approval',required=True)
            q.add_argument('--expected-edition',required=True); q.add_argument('--expected-registry-head',required=True)
            q.add_argument('--out',required=True)
    return p


def execute(args):
    import sys
    sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
    from la.app.artifacts import within,read,receipt
    from evaluation.artifacts import CaptureStore
    from evaluation.archive import export_archive,read_archive,replay_portable_archive,approved_projection
    root=Path(args.operator_root).absolute(); root.resolve(strict=True)
    store=CaptureStore(args.capture_root)
    registry=None
    if args.command in ('plan','export','projection'):
        from evaluation.edition_registry import EditionRegistry
        registry=EditionRegistry(within(root,args.registry,exists=True),store)
    if args.command in ('plan','export'):
        plan=plan_from_packet(store,registry,root,read(within(root,args.packet,exists=True)))
        if args.command=='plan':
            return {'unsigned_release_payload_template':plan.release_payload,'archive_written':False,'authority_created':False}
    from evaluation.eligibility import ReceiptVerifier
    from la.app.public_trust import public_keys
    verifier=ReceiptVerifier(*public_keys(args.public_trust_root,args.public_trust_profile))
    if args.command=='export':
        within(root,args.destination)
        destination=root/args.destination
        if not destination.parent.is_dir() or destination.exists(): raise ValueError('new archive under explicit existing owned parent required')
        return export_archive(plan,destination,signed_release=read(within(root,args.signed_release,exists=True)),verifier=verifier)
    if args.command=='projection':
        view=approved_projection(store,read(within(root,args.reference,exists=True)),
            signed_approval=read(within(root,args.signed_approval,exists=True)),verifier=verifier,registry=registry,
            expected_edition=args.expected_edition,expected_registry_head=args.expected_registry_head)
        out=within(root,args.out,exists=True)
        saved=receipt(out,'approved-evaluation-projection',view)
        return {'path':saved['path'],'receipt_sha256':saved['receipt_sha256'],'kind':saved['kind'],
                'raw_archive_exported':False,'product_acceptance':'pending'}
    within(root,args.archive,exists=True)
    path=root/args.archive
    if args.command=='read':
        snapshot=read_archive(path,expected_archive_sha256=args.expected_archive_sha256,verifier=verifier)
        return {'archive_sha256':args.expected_archive_sha256,'manifest':snapshot.manifest,'extracted':False,'archived_code_executed':False}
    result_store=CaptureStore(within(root,args.result_store,exists=True))
    return replay_portable_archive(path,expected_archive_sha256=args.expected_archive_sha256,verifier=verifier,
                                   result_store=result_store,scorer_version=args.scorer_version)


def main():
    try:
        from la.app.cli import emit_result
        emit_result(execute(parser().parse_args()))
    except (ValueError,OSError,KeyError,TypeError,ImportError,AttributeError) as exc:
        raise SystemExit('la_archive: '+type(exc).__name__+'; inspect local non-secret contracts') from None


if __name__=='__main__': main()

"""Trusted replay of existing public or actually retired evaluator captures.

No model, target, source transformation or archived code is executed. Portable
archive import/export uses the separate evaluator-owned release interface.
"""
import argparse
from pathlib import Path


def parser():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--operator-root',required=True); p.add_argument('--capture-root',required=True)
    p.add_argument('--manifest-sha256',required=True); p.add_argument('--oracle',required=True)
    p.add_argument('--retirement-sha256'); p.add_argument('--registry')
    return p


def execute(args):
    import sys
    sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
    from la.app.artifacts import within,read
    from evaluation.artifacts import CaptureStore
    from evaluation.runner import replay_archive
    from scripts.results import captured
    root=Path(args.operator_root).resolve(strict=True)
    store=CaptureStore(args.capture_root)
    budget={'bytes':0,'members':0}
    reference={'sha256':args.manifest_sha256,'kind':'variant_manifest'}
    manifest=captured(store,reference,'variant_manifest',budget=budget)
    retirement=None; registry=None
    if manifest['split']=='heldout':
        if not args.registry or not args.retirement_sha256:
            raise ValueError('active hidden raw replay forbidden; actual retirement and registry required before oracle access')
        from evaluation.edition_registry import EditionRegistry
        registry=EditionRegistry(within(root,args.registry,exists=True),store)
        retirement={'sha256':args.retirement_sha256,'kind':'retirement'}
        released=captured(store,retirement,'retirement',budget=budget)
        from la.contracts import digest
        state=registry.state(manifest['edition'])
        events=registry.events()
        if (not state['retired'] or state.get('attempt') is None or state['attempt']['status']=='running'
                or released['edition']!=manifest['edition'] or released['manifest_sha256']!=digest(manifest)
                or not any(event['edition']==manifest['edition'] and event['event_type']=='retired'
                    and event['event_sha256']==released.get('registry_event_sha256') for event in events)
                or state.get('freeze') is None or state['freeze']['freeze_sha256']!=manifest['freeze_sha256']):
            raise ValueError('exact retired frozen attempt and actual disposition required before oracle access')
    elif manifest['split'] not in ('development','validation'):
        raise ValueError('unknown replay visibility')
    # Preflight all committed arm members using bounded reads before owner replay.
    from la.report.results import METHODS
    if len(manifest['results'])!=5 or {arm['method'] for arm in manifest['results']}!=set(METHODS):
        raise ValueError('all original arms required for replay')
    for arm in manifest['results']:
        captured(store,arm['receipt_capture'],'arm_receipt',budget=budget)
        if type(arm['captures']) is not list or len(arm['captures'])>64: raise ValueError('bounded original arm capture graph required')
        for ref in arm['captures']:
            if ref.get('kind') not in ('generation','mapping_proposal','batch_output','batch_failure','arm_raw'):
                raise ValueError('unknown original arm capture kind')
            captured(store,ref,ref['kind'],budget=budget)
    oracle=read(within(root,args.oracle,exists=True))
    result=replay_archive(store,reference,oracle,retirement_ref=retirement,registry=registry)
    return {'mode':'replay','edition':result['edition'],'manifest':reference,'replay_capture':result['replay_capture'],
            'fresh_holdout':False,'stochastic_model_rerun':False,'transformation_status':'not_run',
            'target_validation':'not_run','benchmark_status':'not_run','product_acceptance':'pending'}


def main():
    try:
        from la.app.cli import emit_result
        emit_result(execute(parser().parse_args()))
    except (ValueError,OSError,KeyError,TypeError,ImportError,AttributeError) as exc:
        raise SystemExit('la_replay: '+type(exc).__name__+'; inspect local non-secret contracts') from None


if __name__=='__main__': main()

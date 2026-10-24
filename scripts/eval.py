"""Evaluator-only source CLI. Never imported by the inference wheel.

Trusted ports factories inject product/provider/target capabilities. They are not
a sandbox and must be audited at the frozen release before hidden/live operation.
"""
import argparse
import importlib
import json
import sys
from pathlib import Path


def parser():
    p = argparse.ArgumentParser(description='Independent evaluator; no hidden asset generation or inference wheel imports')
    p.add_argument('--evidence-root', default='.', help='declared evaluator-owned public/retired or separately authorized external root')
    p.add_argument('--out', default='captures', help='capture directory relative to evidence root')
    sub = p.add_subparsers(dest='command', required=True)
    q = sub.add_parser('parity'); q.add_argument('--evidence', required=True)
    q = sub.add_parser('target'); q.add_argument('--evidence', required=True)
    q=sub.add_parser('target-effects'); q.add_argument('--evidence',required=True)
    q=sub.add_parser('prepare-target'); q.add_argument('--evidence',required=True)
    q = sub.add_parser('replay'); q.add_argument('--evidence', required=True)
    q.add_argument('--registry',help='required actual evaluator registry for retired hidden replay')
    q = sub.add_parser('suite')
    sources=q.add_mutually_exclusive_group(required=True)
    sources.add_argument('--cases'); sources.add_argument('--public-development',action='store_true')
    q.add_argument('--ports',default='scripts.product_ports:factory',help='trusted module:factory(context) -> RunnerPorts')
    q.add_argument('--config', required=True, help='non-secret factory context/pins/authority/freeze/custody packet')
    q.add_argument('--mode', choices=['rules', 'mock', 'live'], default='mock')
    q.add_argument('--split', choices=['development', 'validation', 'heldout'], default='development')
    q.add_argument('--evaluator-authorized', action='store_true')
    q.add_argument('--eligibility-factory',default='scripts.eligibility_factory:factory',help='trusted evaluator-owned module:factory; no JSON custody shortcuts')
    q.add_argument('--public-trust-root'); q.add_argument('--public-trust-profile')
    q.add_argument('--target-factory',help='explicit evaluator-owned module:factory returning D6 TargetPorts')
    q = sub.add_parser('public-corpus'); q.add_argument('variant')
    q=sub.add_parser('public-catalog'); q.add_argument('--nonce',required=True); q.add_argument('--corpus-commitment-sha256')
    for name in ('edition-register','edition-freeze','edition-state','edition-export','edition-disposition'):
        q=sub.add_parser(name); q.add_argument('--registry',required=True)
        if name in ('edition-register','edition-freeze','edition-disposition'):
            q.add_argument('--packet',required=True); q.add_argument('--request-id',required=True); q.add_argument('--expected-head')
        if name in ('edition-state','edition-disposition'): q.add_argument('--edition',required=True)
        if name=='edition-disposition':
            q.add_argument('--action',choices=['exposed','retired'],required=True)
            q.add_argument('--public-trust-root',required=True); q.add_argument('--public-trust-profile',required=True)
    sub.add_parser('contract')
    return p


def execute(args):
    # This script is deliberately outside the installed inference distribution.
    base = Path(__file__).resolve().parents[1]
    sys.path.insert(0, str(base))
    from la.app.artifacts import within, read, receipt
    from evaluation.artifacts import CaptureStore
    root = Path(args.evidence_root).resolve(strict=True)
    if args.command == 'contract':
        from evaluation.benchmark import corpus_contract, not_run_report
        return dict(contract=corpus_contract(), results=not_run_report())
    # Check explicit eligibility before opening any suite case/oracle file.
    config = {}
    if args.command == 'suite':
        config = read(within(root, args.config, exists=True))
        if (args.mode == 'live' or args.split == 'heldout') and (
                not args.evaluator_authorized or not args.eligibility_factory or not args.public_trust_root or not args.public_trust_profile):
            raise ValueError('explicit evaluator authority and trusted signed-observation eligibility factory required before case access')
    capture_root = within(root, args.out)
    capture_root.mkdir(parents=True, exist_ok=True)
    store = CaptureStore(capture_root)
    eligibility=protected=None
    suite_head=config.get('expected_registry_head')
    if args.command=='suite' and (args.mode=='live' or args.split=='heldout'):
        from evaluation.edition_registry import EligibilityContext
        from evaluation.public_live import PublicLiveContext
        module,separator,symbol=args.eligibility_factory.partition(':')
        if not separator: raise ValueError('trusted eligibility module:factory required')
        eligibility=getattr(importlib.import_module(module),symbol)(
            {'store':store,'evidence_root':root,'packet':config.get('eligibility_context',{}),
             'public_trust_root':args.public_trust_root,'public_trust_profile':args.public_trust_profile,
             'billing_config':config.get('port_context',{}).get('provider_config')})
        try:
            from evaluation.protected_live import ProtectedLiveContext
        except ImportError:
            ProtectedLiveContext=None  # producer absent: T3 live spend stays unavailable, never raw
        if ProtectedLiveContext is not None and type(eligibility) is ProtectedLiveContext:
            if args.mode!='live' or args.split!='heldout' or args.ports!='scripts.product_ports:factory':
                raise ValueError('T3 spend scope applies only to a live heldout suite with the trusted product ports')
            if type(config.get('t3_admission_request_id')) is not str or not config['t3_admission_request_id']:
                raise ValueError('explicit T3 scope admission request id required')
            # Admission is recorded before any provider wiring; the signed scope
            # pins the registry head it was signed against.
            admitted=eligibility.admit(request_id=config['t3_admission_request_id'],
                                       expected_head=config.get('expected_registry_head'))
            protected,eligibility=eligibility,eligibility.eligibility
            suite_head=admitted.event['event_sha256']
        elif type(eligibility) not in (EligibilityContext,PublicLiveContext): raise ValueError('actual T1/T3 context required; booleans refused')
        if args.mode=='live' and args.split=='heldout' and protected is None:
            raise ValueError('live heldout requires a signed admitted T3 spend scope; no unmetered provider')
        eligibility.validate()
        expected_freeze=None if type(eligibility) is PublicLiveContext else eligibility.freeze
        if eligibility.registry.store.root!=store.root or expected_freeze!=config.get('freeze'):
            raise ValueError('eligibility capture root/freeze mismatch')
        if type(eligibility) is PublicLiveContext and args.split=='heldout': raise ValueError('T1 public context grants no hidden access')
    if args.command.startswith('edition-'):
        from evaluation.edition_registry import EditionRegistry
        registry=EditionRegistry(within(root,args.registry,exists=args.command not in ('edition-register',)),store)
        if args.command=='edition-state': return registry.state(args.edition)
        if args.command=='edition-export': return {'head':registry.head,'event_captures':registry.export()}
        packet=read(within(root,args.packet,exists=True))
        if packet.get('kind')=='public-catalog':
            from la.contracts import digest
            if packet.get('receipt_sha256')!=digest({k:v for k,v in packet.items() if k not in ('receipt_sha256','path')}):
                raise ValueError('public catalog wrapper identity mismatch')
            packet=packet['payload']
        if args.command=='edition-register':
            result=(registry.register_public if packet.get('stage')=='T1' else registry.register)(
                packet,request_id=args.request_id,expected_head=args.expected_head)
        elif args.command=='edition-freeze': result=registry.freeze(packet,request_id=args.request_id,expected_head=args.expected_head)
        else:
            from evaluation.eligibility import ReceiptVerifier
            from la.app.public_trust import public_keys
            result=registry.disposition(args.edition,args.action,packet,
                verifier=ReceiptVerifier(*public_keys(args.public_trust_root,args.public_trust_profile)),
                request_id=args.request_id,expected_head=args.expected_head)
        return {'event':result.event,'capture':result.capture,'newly_created':result.newly_created,'head':registry.head}
    if args.command=='public-catalog':
        from evaluation.public_live import make_public_catalog
        cases=public_cases()
        catalog=make_public_catalog(cases,nonce=args.nonce,corpus_commitment_sha256=args.corpus_commitment_sha256)
        return receipt(capture_root,'public-catalog',catalog)
    if args.command == 'public-corpus':
        from evaluation.corpus import build_development_variant, capture_public_variant
        corpus = build_development_variant(args.variant)
        return dict(corpus=capture_public_variant(store, corpus), benchmark_status='not_run')
    if args.command == 'suite':
        from evaluation.runner import BatchCase, VariantCase, RunnerPorts, run_suite
        if args.public_development:
            if args.split!='development': raise ValueError('built-in corpus is public development only')
            cases=public_cases()
        else:
            raw = read(within(root, args.cases, exists=True))
            cases = [VariantCase(item['variant_id'], args.split, item['edition'], item['visible'],
                tuple(BatchCase(batch['batch_id'], batch['visible'], batch['oracle']) for batch in item['batches']),
                item.get('accepted_choices', {}), item.get('expected_layout')) for item in raw['variants']]
        module, separator, symbol = args.ports.partition(':')
        if not separator or not module or not symbol:
            raise ValueError('explicit trusted ports module:factory required')
        context = config.get('port_context', {})
        # No cases, oracle, accepted choices, expected layout, custody secrets or
        # evaluator storage handles are passed into the inference factory.
        forbidden = {'oracle', 'oracle_records', 'accepted_choices', 'expected_layout', 'cases', 'custody'}
        if set(context) & forbidden:
            raise ValueError('factory context must not contain evaluator-only inputs')
        selected_factory=getattr(importlib.import_module(module),symbol)
        if args.ports=='scripts.product_ports:factory':
            from evaluation.public_live import PublicLiveContext
            signed_provider=(eligibility.validate() if type(eligibility) is PublicLiveContext
                             else protected.trusted_authority() if protected is not None else None)
            ports=selected_factory(context,provider_authority=signed_provider)
        else: ports=selected_factory(context)
        if not isinstance(ports, RunnerPorts): raise ValueError('factory must supply actual RunnerPorts')
        if protected is not None:
            import dataclasses
            if ports.count_tokens is None: raise ValueError('T3 meter requires the explicit token counter')
            # D6 meter reserves/settles in the registry around the trusted D7 transport.
            ports=dataclasses.replace(ports,provider=protected.provider_port(ports.provider,cases,ports.count_tokens))
        target_ports=None
        if args.target_factory:
            from evaluation.target_runner import TargetPorts
            module,separator,symbol=args.target_factory.partition(':')
            if not separator: raise ValueError('explicit target module:factory required')
            target_ports=getattr(importlib.import_module(module),symbol)(config.get('target_context',{}))
            if not isinstance(target_ports,TargetPorts): raise ValueError('actual TargetPorts required')
        result = run_suite(cases, ports, store, split=args.split, mode=args.mode, pins=config.get('pins'),
            authority=config.get('authority'), freeze=config.get('freeze'), custody=config.get('custody'),
            eligibility=eligibility,attempt_request_id=config.get('attempt_request_id'),expected_registry_head=suite_head,
            target_ports=target_ports,target_freeze_sha256=config.get('target_freeze_sha256'))
        return receipt(capture_root, 'evaluation', dict(edition=cases[0].edition, result=result,
            benchmark_status=result['summary']['benchmark_status'], product_acceptance='pending'))
    evidence = read(within(root, args.evidence, exists=True))
    if args.command == 'replay':
        from evaluation.runner import replay_archive
        from evaluation.edition_registry import EditionRegistry
        registry=EditionRegistry(within(root,args.registry,exists=True),store) if args.registry else None
        return replay_archive(store, evidence['manifest_ref'], evidence['oracle_records'],
                              retirement_ref=evidence.get('retirement_ref'),registry=registry)
    # Direct projections are public only. Hidden replay requires sealed capture
    # and retirement verification through replay_archive, never a truthy label.
    if args.command!='prepare-target' and evidence.get('split', 'development') != 'development':
        raise ValueError('direct scoring requires public development evidence; use retired capture replay')
    if args.command=='prepare-target':
        required={'schema_version','split','visible','mapping','method','edition','freeze_sha256'}
        phase_keys={'evaluation_phase','evaluation_plan_sha256'}
        if set(evidence) not in (required,required|phase_keys) or evidence['split'] not in ('development','validation'):
            raise ValueError('closed public visible/proposal target preparation packet required; no gold')
        from scripts.target_ports import prepare
        phase=({k:evidence[k] for k in phase_keys|{'split','freeze_sha256'}} if phase_keys<=set(evidence) else None)
        artifact=prepare(evidence['visible'],evidence['mapping'],evidence['method'],evidence['edition'],
                         evidence['freeze_sha256'],phase_scope=phase)
        return receipt(capture_root,'evaluation-candidate',artifact)
    if args.command=='target-effects':
        from evaluation.target_effects import TargetExpectation,grade_target
        values=evidence['expectation']
        if 'required_negatives' in values: values['required_negatives']=tuple(values['required_negatives'])
        expectation=TargetExpectation(**values).validate()
        observation=observation_from(evidence.get('observation'))
        result=grade_target(evidence['oracle_records'],observation,expectation=expectation,
            prior=observation_from(evidence.get('prior')),failed_load=observation_from(evidence.get('failed_load')),
            recovery_observation=observation_from(evidence.get('recovery_observation')),edition=evidence.get('edition','development'))
        result['row_parity']='not_run' if result['target_validation']=='not_run' else result['score']['row_parity']
        return receipt(capture_root,'evaluation',dict(source_sha256=expectation.candidate['source_sha256'],
            mapping_sha256=expectation.candidate['mapping_sha256'],candidate_sha256=expectation.candidate['candidate_sha256'],
            edition=evidence.get('edition','development'),operation='target',result=result,product_acceptance='pending'))
    if args.command == 'parity':
        from evaluation.scorer import score_product
        result = score_product(evidence['oracle_records'], evidence['outcomes'], evidence['mapping'],
                               edition=evidence.get('edition', 'development'))
        pins = dict(source_sha256=evidence['mapping']['source_sha256'], mapping_sha256=evidence['mapping']['mapping_sha256'])
    else:
        from evaluation.target import score_target, score_execution_receipt
        if 'execution_receipt' in evidence:
            execution = evidence['execution_receipt']
            if execution.get('kind') == 'execution':
                # Common CLI envelope encloses D5's actual sealed receipt.
                from la.app.artifacts import checked_receipt
                if digest_receipt(execution) != execution.get('receipt_sha256'):
                    raise ValueError('execution wrapper hash mismatch')
                execution = execution['payload']['observation']
            result = score_execution_receipt(evidence['oracle_records'], execution, evidence['mapping'],
                bundle_sha256=evidence['bundle_sha256'], edition=evidence.get('edition', 'development'))
        else:
            result = score_target(evidence['oracle_records'], evidence.get('observation'),
                bundle_sha256=evidence['bundle_sha256'], mapping_sha256=evidence['mapping_sha256'],
                edition=evidence.get('edition', 'development'))
        pins = dict(source_sha256=evidence['source_sha256'], mapping_sha256=evidence['mapping_sha256'],
                    bundle_sha256=evidence['bundle_sha256'])
    return receipt(capture_root, 'evaluation', dict(pins, edition=evidence.get('edition', 'development'),
        operation=args.command, result=result, product_acceptance='pending'))


def digest_receipt(value):
    from la.contracts import digest
    return digest({k:v for k,v in value.items() if k != 'receipt_sha256'})


def observation_from(value):
    if value is None: return None
    if type(value) is dict and value.get('kind')=='target-observation':
        if set(value)!={'schema_version','kind','payload','receipt_sha256'} or digest_receipt(value)!=value['receipt_sha256']:
            raise ValueError('immutable target-observation wrapper mismatch')
        return value['payload']['observation']
    return value


def public_cases():
    """Only public canonical-first generator source; never called in construction."""
    from evaluation.corpus import development_layouts,build_development_variant,variant_case
    return [variant_case(build_development_variant(layout['variant_id'])) for layout in development_layouts()]


def main():
    try:
        from la.app.cli import emit_result
        emit_result(execute(parser().parse_args()))
    except (ValueError, OSError, KeyError, TypeError, ImportError, AttributeError) as exc:
        # External callbacks can contain secrets in exception messages.
        raise SystemExit('la_eval: '+type(exc).__name__+'; inspect local non-secret input contracts') from None


if __name__ == '__main__': main()

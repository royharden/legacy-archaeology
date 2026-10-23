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
    q = sub.add_parser('replay'); q.add_argument('--evidence', required=True)
    q = sub.add_parser('suite')
    q.add_argument('--cases', required=True); q.add_argument('--ports', required=True, help='trusted module:factory(context) -> RunnerPorts')
    q.add_argument('--config', required=True, help='non-secret factory context/pins/authority/freeze/custody packet')
    q.add_argument('--mode', choices=['rules', 'mock', 'live'], default='mock')
    q.add_argument('--split', choices=['development', 'validation', 'heldout'], default='development')
    q.add_argument('--evaluator-authorized', action='store_true')
    q = sub.add_parser('public-corpus'); q.add_argument('variant')
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
        if args.mode == 'live' or args.split == 'heldout':
            from evaluation.benchmark import hidden_run_eligibility
            eligible = hidden_run_eligibility(config.get('freeze'), config.get('custody'))
            if not args.evaluator_authorized or not eligible['eligible'] or config.get('authority', {}).get('authorized') is not True:
                raise ValueError('explicit external evaluator authority, freeze and custody required before case access')
    capture_root = within(root, args.out)
    capture_root.mkdir(parents=True, exist_ok=True)
    store = CaptureStore(capture_root)
    if args.command == 'public-corpus':
        from evaluation.corpus import build_development_variant, capture_public_variant
        corpus = build_development_variant(args.variant)
        return dict(corpus=capture_public_variant(store, corpus), benchmark_status='not_run')
    if args.command == 'suite':
        from evaluation.runner import BatchCase, VariantCase, RunnerPorts, run_suite
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
        ports = getattr(importlib.import_module(module), symbol)(context)
        if not isinstance(ports, RunnerPorts): raise ValueError('factory must supply actual RunnerPorts')
        result = run_suite(cases, ports, store, split=args.split, mode=args.mode, pins=config.get('pins'),
            authority=config.get('authority'), freeze=config.get('freeze'), custody=config.get('custody'))
        return receipt(capture_root, 'evaluation', dict(edition=cases[0].edition, result=result,
            benchmark_status=result['summary']['benchmark_status'], product_acceptance='pending'))
    evidence = read(within(root, args.evidence, exists=True))
    if args.command == 'replay':
        from evaluation.runner import replay_archive
        return replay_archive(store, evidence['manifest_ref'], evidence['oracle_records'],
                              retirement_ref=evidence.get('retirement_ref'))
    # Direct projections are public only. Hidden replay requires sealed capture
    # and retirement verification through replay_archive, never a truthy label.
    if evidence.get('split', 'development') != 'development':
        raise ValueError('direct scoring requires public development evidence; use retired capture replay')
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


def main():
    try:
        print(json.dumps(execute(parser().parse_args()), indent=2, ensure_ascii=False))
    except (ValueError, OSError, KeyError, TypeError, ImportError, AttributeError) as exc:
        # External callbacks can contain secrets in exception messages.
        raise SystemExit('la_eval: '+type(exc).__name__+'; inspect local non-secret input contracts') from None


if __name__ == '__main__': main()

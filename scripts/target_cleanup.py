"""Explicit operator command for owned disposable namespace cleanup SOURCE.

Never automatic after evaluation, never a default target, recency lookup or
arbitrary SQL. Every input is an externally pinned file/SHA; the signed cleanup
authority (never load authority) is checked before any environment read. D5's
la.postgres cleanup functions own every catalog check, statement and receipt.
No grading, keys, DSN lookup, database operation or capture occurs on import.
"""
import argparse
from pathlib import Path

CLEANUP_OPERATIONS = {'cleanup': 'cleanup', 'reconcile-cleanup': 'reconcile_cleanup'}


def parser():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--operator-root',required=True)
    sub=p.add_subparsers(dest='command',required=True)
    for name in ('cleanup','reconcile-cleanup','open-cleanup'):
        q=sub.add_parser(name)
        if name!='cleanup': q.add_argument('--expected-cleanup-sha256',required=True)
        if name=='open-cleanup':
            q.add_argument('--receipt',required=True); continue
        q.add_argument('--receipt-root',required=True,help='existing owned directory for immutable cleanup receipts')
        q.add_argument('--experiment',required=True); q.add_argument('--expected-experiment-sha256',required=True)
        q.add_argument('--expected-original-observation-sha256',required=True)
        q.add_argument('--artifact',required=True); q.add_argument('--signed-authority',required=True,help='original load authority')
        q.add_argument('--cleanup-authority',required=True); q.add_argument('--expected-cleanup-authority-sha256',required=True)
        q.add_argument('--target-config',required=True); q.add_argument('--public-trust-root',required=True)
        q.add_argument('--public-trust-profile',required=True); q.add_argument('--dsn-env',default='LA_DISPOSABLE_TARGET_DSN')
        if name=='reconcile-cleanup': q.add_argument('--cleanup-receipt',required=True)
    return p


def precheck_cleanup_authority(signed,verifier,expected,operation):
    """Cheap pre-environment gate; D5 re-verifies the full binding against the experiment."""
    from la.contracts import digest
    from la.contracts.protocol import identity
    from la.postgres.authority import verified_target_authority
    identity(expected)
    body=verified_target_authority(signed,verifier)
    if (type(body) is not dict or body.get('kind')!='disposable_target_cleanup_authority'
            or body.get('scope')!='owned_disposable_namespace' or body.get('authority_sha256')!=expected
            or digest({k:v for k,v in body.items() if k!='authority_sha256'})!=expected
            or type(body.get('operations')) is not list or operation not in body['operations']):
        raise ValueError('dedicated signed cleanup authority for this exact operation required; load authority cannot substitute')
    return body


def execute(args):
    from la.app.artifacts import within,read,receipt
    from la.contracts.protocol import identity
    root=Path(args.operator_root).absolute()
    root.resolve(strict=True)
    def owned(value):
        # Containment is checked; the lexical path is kept for D5's link/junction refusal.
        within(root,value,exists=True)
        return root/value
    if args.command=='open-cleanup':
        from la.postgres import open_target_cleanup
        identity(args.expected_cleanup_sha256)
        return open_target_cleanup(owned(args.receipt),expected_cleanup_sha256=args.expected_cleanup_sha256)
    receipt_root=owned(args.receipt_root)
    from la.app.public_trust import public_keys
    from la.app.observations import target_dsn
    from la.postgres import TargetAuthorityVerifier,TargetConfig
    from scripts.target_experiment import artifact_from
    for value in (args.expected_experiment_sha256,args.expected_original_observation_sha256):
        identity(value)
    operation=CLEANUP_OPERATIONS[args.command]
    artifact=artifact_from(read(within(root,args.artifact,exists=True)),root)
    original=read(within(root,args.signed_authority,exists=True))
    cleanup=read(within(root,args.cleanup_authority,exists=True))
    verifier=TargetAuthorityVerifier(*public_keys(args.public_trust_root,args.public_trust_profile))
    verifier.verify(original)
    precheck_cleanup_authority(cleanup,verifier,args.expected_cleanup_authority_sha256,operation)
    config=TargetConfig(**read(within(root,args.target_config,exists=True))).validate()
    common=dict(expected_experiment_sha256=args.expected_experiment_sha256,
                expected_original_observation_sha256=args.expected_original_observation_sha256,
                expected_cleanup_authority_sha256=args.expected_cleanup_authority_sha256,
                target_config=config,authority_verifier=verifier,cleanup_verifier=verifier,receipt_root=receipt_root)
    if operation=='reconcile_cleanup':
        identity(args.expected_cleanup_sha256)
        common.update(cleanup_receipt_path=owned(args.cleanup_receipt),expected_cleanup_sha256=args.expected_cleanup_sha256)
    # Only after every pin and signature: the named environment value, never an argument.
    dsn=target_dsn(args.dsn_env,config)
    if not dsn:
        # Honest not_run; nothing connected, nothing removed, no D5 receipt claimed.
        return receipt(receipt_root,'target-cleanup-not-run',dict(action=operation,
            expected_experiment_sha256=args.expected_experiment_sha256,
            expected_original_observation_sha256=args.expected_original_observation_sha256,
            expected_cleanup_authority_sha256=args.expected_cleanup_authority_sha256,
            state='not_run',reason='target_dsn_absent',target_validation='not_run',row_parity='not_run',
            product_acceptance='pending'))
    from la.postgres import cleanup_target_namespace,reconcile_target_cleanup
    from la.postgres.target import driver_and_connect
    _,connect=driver_and_connect(dsn,config)
    connections=[]
    try:
        # Caller-owned, idle, non-autocommit; writer and observer are distinct backends.
        observer=connect(); connections.append(observer)
        if operation=='reconcile_cleanup':
            return reconcile_target_cleanup(owned(args.experiment),artifact,original,cleanup,
                                            observer_connection=observer,**common)
        writer=connect(); connections.append(writer)
        return cleanup_target_namespace(owned(args.experiment),artifact,original,cleanup,
                                        connection=writer,observer_connection=observer,**common)
    finally:
        for connection in connections:
            try: connection.close()
            except Exception: pass


def main():
    try:
        from la.app.cli import emit_result
        emit_result(execute(parser().parse_args()))
    except (ValueError,OSError,KeyError,TypeError,ImportError,AttributeError) as exc:
        raise SystemExit('la_target_cleanup: '+type(exc).__name__+'; inspect local non-secret contracts') from None


if __name__=='__main__': main()

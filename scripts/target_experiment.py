"""Explicit operator adapter for neutral immutable target experiments SOURCE.

No grading, keys, DSN lookup, database operation or capture occurs on import.
"""
import argparse
import re
from pathlib import Path


def artifact_from(value,root):
    from la.contracts import digest
    from la.app.artifacts import within
    if type(value) is not dict: raise ValueError('explicit target artifact required')
    if value.get('kind')=='evaluation-candidate':
        required={'schema_version','kind','payload','receipt_sha256'}
        if (not required<=set(value) or set(value)-required-{'path'} or
                type(value['schema_version']) is not int or value['schema_version']!=1):
            raise ValueError('closed candidate receipt wrapper required')
        if value.get('receipt_sha256')!=digest({k:v for k,v in value.items() if k not in ('receipt_sha256','path')}):
            raise ValueError('candidate wrapper identity mismatch')
        value=value['payload']
    if value.get('kind')=='product_bundle':
        if set(value)!={'kind','bundle_path'}: raise ValueError('closed product-bundle artifact required')
        value=dict(value,bundle_path=str(within(root,value['bundle_path'],exists=True)))
    elif value.get('kind')!='disposable_evaluation_candidate':
        raise ValueError('actual product bundle or non-loadable evaluation candidate required')
    return value


def parser():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--operator-root',required=True)
    sub=p.add_subparsers(dest='command',required=True)
    for name in ('collect','open','reconcile','select-recovery'):
        q=sub.add_parser(name)
        if name!='open':
            q.add_argument('--artifact',required=True); q.add_argument('--signed-authority',required=True)
            q.add_argument('--target-config',required=True); q.add_argument('--public-trust-root',required=True)
            q.add_argument('--public-trust-profile',required=True); q.add_argument('--dsn-env',default='LA_DISPOSABLE_TARGET_DSN')
        if name=='collect':
            q.add_argument('--capture-root',required=True); q.add_argument('--experiment-id',required=True)
        else:
            q.add_argument('--experiment',required=True); q.add_argument('--expected-experiment-sha256',required=True)
            q.add_argument('--expected-candidate-sha256',required=True); q.add_argument('--expected-authority-sha256',required=True)
        if name=='reconcile': q.add_argument('--previous-reconciliation-sha256')
        if name=='select-recovery':
            q.add_argument('--expected-reconciliation-sha256',required=True)
            q.add_argument('--expected-prior-observation-sha256',required=True,help='exact original prior SHA or explicit absent')
    return p


def public_summary(manifest):
    """Neutral identity/state projection only: raw readback/effect rows stay local."""
    return {key:manifest[key] for key in ('schema_version','kind','experiment_id','experiment_sha256',
        'candidate','authority_sha256','target_config_sha256','observer_code_sha256','capture_status',
        'requested_operations','operations','omissions','target_validation','row_parity','product_acceptance')}


def execute(args):
    from la.app.artifacts import within,read
    from la.postgres import open_target_experiment,collect_target_experiment,reconcile_target_experiment
    root=Path(args.operator_root).absolute()
    root.resolve(strict=True)
    def capture_path(value):
        # Validate containment but preserve the lexical path for D5's stricter
        # all-parent symlink/junction refusal; do not erase links by resolving.
        within(root,value,exists=True)
        return root/value
    if args.command=='open':
        snapshot=open_target_experiment(capture_path(args.experiment),
            expected_experiment_sha256=args.expected_experiment_sha256,
            expected_candidate_sha256=args.expected_candidate_sha256,
            expected_authority_sha256=args.expected_authority_sha256)
        return public_summary(snapshot.manifest)
    from la.app.public_trust import public_keys
    from la.app.observations import target_dsn
    from la.postgres import TargetAuthorityVerifier,TargetConfig
    from la.postgres.candidate import resolve_candidate,verify_authority
    from la.postgres.experiment import REQUIRED_OPERATIONS
    from la.contracts import digest
    artifact=artifact_from(read(within(root,args.artifact,exists=True)),root)
    signed=read(within(root,args.signed_authority,exists=True))
    verifier=TargetAuthorityVerifier(*public_keys(args.public_trust_root,args.public_trust_profile))
    authority=verifier.verify(signed)
    config=TargetConfig(**read(within(root,args.target_config,exists=True))).validate()
    if args.command=='select-recovery':
        from la.postgres import target_reconciliation_callbacks
        from la.contracts.protocol import identity
        prior=args.expected_prior_observation_sha256
        if prior=='absent': prior=None
        else: identity(prior)
        callbacks=target_reconciliation_callbacks(capture_path(args.experiment),artifact,signed,
            expected_experiment_sha256=args.expected_experiment_sha256,
            expected_reconciliation_sha256=args.expected_reconciliation_sha256,
            expected_prior_observation_sha256=prior,target_config=config,authority_verifier=verifier)
        manifest=callbacks.snapshot.experiment.manifest
        if (manifest['candidate']['candidate_sha256']!=args.expected_candidate_sha256 or
                manifest['authority_sha256']!=args.expected_authority_sha256):
            raise ValueError('selected recovery differs from external candidate/authority pins')
        return callbacks.projection()
    prepared=resolve_candidate(artifact,config)
    operations=REQUIRED_OPERATIONS if args.command=='collect' else ('reconcile',)
    for operation in operations: verify_authority(authority,prepared,config,operation)
    if args.command=='collect':
        if type(args.experiment_id) is not str or re.fullmatch('[A-Za-z0-9][A-Za-z0-9_-]{0,63}',args.experiment_id) is None:
            raise ValueError('bounded new experiment identity required')
        capture_root=capture_path(args.capture_root)
        if (capture_root/args.experiment_id).exists(): raise ValueError('existing experiment never triggers another load')
        # Exact signed authority/candidate/config/operations precede all env access.
        manifest=collect_target_experiment(artifact,signed,capture_root=capture_root,experiment_id=args.experiment_id,
            dsn=target_dsn(args.dsn_env,config),target_config=config,authority_verifier=verifier)
        return public_summary(manifest)
    path=capture_path(args.experiment)
    snapshot=open_target_experiment(path,expected_experiment_sha256=args.expected_experiment_sha256,
        expected_candidate_sha256=args.expected_candidate_sha256,expected_authority_sha256=args.expected_authority_sha256)
    if (snapshot.manifest['candidate']!=prepared.descriptor or snapshot.manifest['authority_sha256']!=authority['authority_sha256']
            or snapshot.manifest['target_config_sha256']!=digest(config.public())):
        raise ValueError('recovery scope differs from actual pinned experiment')
    return reconcile_target_experiment(path,artifact,signed,expected_experiment_sha256=args.expected_experiment_sha256,
        dsn=target_dsn(args.dsn_env,config),target_config=config,authority_verifier=verifier,
        previous_reconciliation_sha256=args.previous_reconciliation_sha256)


def main():
    try:
        from la.app.cli import emit_result
        emit_result(execute(parser().parse_args()))
    except (ValueError,OSError,KeyError,TypeError,ImportError,AttributeError) as exc:
        raise SystemExit('la_target_experiment: '+type(exc).__name__+'; inspect local non-secret contracts') from None


if __name__=='__main__': main()

"""Explicit disposable-target command source. No connection at import time."""
from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

from la.contracts import digest
from .artifacts import within, read, receipt, pointer
from .storage import pointer_token
from .observations import target_dsn


def execute_target(root, args):
    bundle = within(root, args.bundle, exists=True)
    manifest = read(within(bundle, 'manifest.json', exists=True))
    if digest({k:v for k,v in manifest.items() if k != 'bundle_sha256'}) != manifest.get('bundle_sha256'):
        raise ValueError('bundle identity mismatch')
    pins = dict(source_sha256=manifest['source_sha256'], mapping_sha256=manifest['mapping_sha256'],
                bundle_sha256=manifest['bundle_sha256'], command=args.command,
                requested_at=datetime.now(timezone.utc).isoformat())
    if not args.authorized or not args.authority or not args.target_config:
        from la.postgres import database_check
        observation = database_check(bundle, authorized=False)
    else:
        authority = read(within(root, args.authority, exists=True))
        if (authority.get('authorized') is not True or authority.get('local_disposable_target') is not True
                or authority.get('least_privilege_role') is not True or not authority.get('authority_id')
                or authority.get('bundle_sha256') != pins['bundle_sha256']):
            raise ValueError('disposable least-privilege exact-bundle authority required')
        from la.postgres import TargetConfig
        config = TargetConfig(**read(within(root, args.target_config, exists=True))).validate()
        if config.authority_reference != authority['authority_id']:
            raise ValueError('target config authority identity mismatch')
        if config.expected_bundle_sha256!=authority['bundle_sha256']:
            raise ValueError('external matching bundle pin must be supplied in target config and authority')
        # Only an explicitly authorized invocation reads the named value.
        dsn = target_dsn(args.dsn_env,config)
        if not dsn:
            from la.postgres import database_check
            observation = database_check(bundle, dsn=None, authorized=True, target_config=config)
        else:
            from la.postgres import database_check, reconcile_commit, rollback_check, constraint_checks
            try:
                if args.command == 'database-check':
                    observation = database_check(bundle, dsn=dsn, authorized=True, target_config=config)
                elif args.command == 'database-reconcile':
                    from .artifacts import checked_receipt
                    original = checked_receipt(root, args.execution_receipt, kind='execution')
                    if original['payload']['bundle_sha256'] != pins['bundle_sha256']:
                        raise ValueError('original execution receipt bundle mismatch')
                    observation = reconcile_commit(bundle, args.namespace, dsn=dsn, authorized=True,
                        target_config=config, execution_receipt=original['payload']['observation'])
                elif args.command == 'database-constraints':
                    observation = constraint_checks(bundle, dsn=dsn, authorized=True, target_config=config)
                else:
                    observation = rollback_check(bundle, dsn=dsn, authorized=True, target_config=config)
            except Exception as exc:
                observation = dict(target_validation='indeterminate', execution_status='commit_outcome_unknown',
                                   reason=type(exc).__name__)
                observation['receipt_sha256'] = digest(observation)
            pins['authority_id'] = authority['authority_id']
    # Record a separate immutable execution receipt; never rewrite frozen bundle.
    payload = dict(pins, observation=observation, product_acceptance='pending')
    relative = bundle.relative_to(root)
    if len(relative.parts) >= 3 and relative.parts[1] == 'bundles':
        run = within(root, relative.parts[0])
        saved = receipt(run, 'execution', payload)
        index=within(run,'current-execution.json')
        pointer(index, {'relative_path': str(Path(saved['path']).relative_to(run))}, expected=pointer_token(index))
    else:
        saved = receipt(root, 'execution', payload)
    return saved

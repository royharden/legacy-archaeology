"""Explicit operator command for owned disposable namespace cleanup SOURCE.

Separate from evaluation: never automatic, never a default/latest target, never
arbitrary SQL, never a destructive retry. No DSN lookup, connection or database
operation occurs on import. Offline plan/inspect read local files only.
"""
import argparse
import re
from pathlib import Path

GRANT_KEYS = {'schema_version', 'kind', 'active', 'artifact', 'original_signed_authority', 'cleanup_signed_authority',
              'target_config', 'experiment', 'expected_experiment_sha256', 'expected_original_observation_sha256',
              'expected_cleanup_authority_sha256', 'namespace', 'receipt_root'}
# Prior attempts in these states already ran (or may have run) destructive SQL: reconcile, never retry.
NO_RETRY_STATES = ('prepared', 'committed', 'indeterminate')
MAX_RECEIPTS = 256


def load_grant(root, path, *, require_active):
    from la.app.artifacts import within, read
    from la.postgres.candidate import is_sha
    from la.postgres.target import owned_namespace
    grant = read(within(root, path, exists=True), limit=64 * 1024)
    if (type(grant) is not dict or set(grant) != GRANT_KEYS or type(grant['schema_version']) is not int or
            grant['schema_version'] != 1 or grant['kind'] != 'disposable_cleanup_grant' or type(grant['active']) is not bool):
        raise ValueError('closed disposable cleanup grant required')
    for key in ('artifact', 'original_signed_authority', 'cleanup_signed_authority', 'target_config', 'experiment', 'receipt_root'):
        if type(grant[key]) is not str or not grant[key]: raise ValueError('explicit operator-relative grant path required')
    if not is_sha(grant['expected_experiment_sha256']) or not is_sha(grant['expected_original_observation_sha256']):
        raise ValueError('exact external experiment/creation observation pins required')
    owned_namespace(grant['namespace'])
    if require_active:
        # The shipped example is inactive; an operator must flip it deliberately.
        if grant['active'] is not True: raise ValueError('cleanup grant is inactive; nothing done')
        if not is_sha(grant['expected_cleanup_authority_sha256']): raise ValueError('exact cleanup authority pin required')
    return grant


def parser():
    # allow_abbrev=False: '--dsn' must never parse as an abbreviation of '--dsn-env'.
    p = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    p.add_argument('--operator-root', required=True)
    sub = p.add_subparsers(dest='command', required=True)
    for name in ('plan', 'inspect', 'run', 'reconcile'):
        q = sub.add_parser(name, allow_abbrev=False)
        if name != 'inspect':
            q.add_argument('--grant', required=True)
            q.add_argument('--public-trust-root', required=True); q.add_argument('--public-trust-profile', required=True)
        if name == 'plan':
            q.add_argument('--authority-id', required=True)
            q.add_argument('--operations', nargs='+', required=True, choices=('cleanup', 'reconcile_cleanup'))
        if name in ('run', 'reconcile'):
            q.add_argument('--expected-namespace', required=True, help='retype the exact owned namespace')
            q.add_argument('--dsn-env', default='LA_DISPOSABLE_TARGET_DSN', help='environment variable NAME, never a DSN')
        if name in ('inspect', 'reconcile'):
            q.add_argument('--receipt', required=True); q.add_argument('--expected-cleanup-sha256', required=True)
    return p


def summary(receipt, path):
    """Neutral state projection; raw catalog/readback facts stay in the local receipt."""
    after = receipt['after']
    hint = {'indeterminate': 'unknown outcome: run the read-only reconcile subcommand; never rerun cleanup',
            'prepared': 'intent only: run the read-only reconcile subcommand; never rerun cleanup',
            'refused': 'nothing destructive ran; inspect issues', 'rolled_back': 'statements rolled back; nothing removed',
            'committed': 'namespace observed absent after commit'}.get(receipt['state'], 'read-only observation recorded')
    return {'receipt_path': str(path), 'cleanup_sha256': receipt['cleanup_sha256'], 'action': receipt['action'],
            'state': receipt['state'], 'namespace': receipt['binding']['namespace'],
            'prior_cleanup_sha256': receipt['prior_cleanup_sha256'], 'issues': receipt['issues'],
            'statements_executed': len(receipt['transaction']['statements']),
            'commit_attempted': receipt['transaction']['commit_attempted'],
            'commit_returned': receipt['transaction']['commit_returned'],
            'namespace_present_after': None if after is None or not after['inspected'] else after['namespace_exists'],
            'target_validation': receipt['target_validation'], 'row_parity': receipt['row_parity'],
            'product_acceptance': receipt['product_acceptance'], 'next': hint}


def prior_attempts(receipt_root, namespace):
    """Exact-path receipts already in this grant's receipt root (bounded); used only to REFUSE a retry."""
    from la.postgres import open_target_cleanup
    names = sorted(entry.name for entry in receipt_root.iterdir())
    if len(names) > MAX_RECEIPTS: raise ValueError('cleanup receipt root bound exceeded; choose an explicit new root')
    found = []
    for name in names:
        match = re.fullmatch('cleanup-([0-9a-f]{64})\\.json', name)
        if match is None: continue
        value = open_target_cleanup(receipt_root / name, expected_cleanup_sha256=match.group(1))
        if value['action'] == 'cleanup' and value['binding']['namespace'] == namespace: found.append(value)
    # A prepared intent whose own final receipt proves no effect (refused/rolled_back) is not an open attempt.
    settled = {value['prior_cleanup_sha256'] for value in found
               if value['state'] in ('refused', 'rolled_back') and value['prior_cleanup_sha256'] is not None}
    return [value for value in found if value['cleanup_sha256'] not in settled]


def execute(args):
    import sys
    repository = str(Path(__file__).resolve().parents[1])
    if repository not in sys.path: sys.path.insert(0, repository)
    from la.app.artifacts import within, read
    root = Path(args.operator_root).absolute(); root.resolve(strict=True)
    def lexical(value):
        # Containment check, but keep the lexical path for the stricter link refusal downstream.
        within(root, value, exists=True)
        return root / value
    if args.command == 'inspect':
        from la.postgres import open_target_cleanup
        path = lexical(args.receipt)
        return summary(open_target_cleanup(path, expected_cleanup_sha256=args.expected_cleanup_sha256), path)
    from la.app.public_trust import public_keys
    from la.review import digest  # The same digest cleanup._authorize recomputes.
    from la.postgres import TargetAuthorityVerifier, TargetConfig, cleanup_binding
    from scripts.target_experiment import artifact_from
    grant = load_grant(root, args.grant, require_active=args.command != 'plan')
    verifier = TargetAuthorityVerifier(*public_keys(args.public_trust_root, args.public_trust_profile))
    artifact = artifact_from(read(within(root, grant['artifact'], exists=True)), root)
    original = read(within(root, grant['original_signed_authority'], exists=True))
    config = TargetConfig(**read(within(root, grant['target_config'], exists=True))).validate()
    pins = dict(expected_experiment_sha256=grant['expected_experiment_sha256'],
                expected_original_observation_sha256=grant['expected_original_observation_sha256'])
    experiment = lexical(grant['experiment'])
    binding = cleanup_binding(experiment, artifact, original, target_config=config, authority_verifier=verifier, **pins)
    if binding['namespace'] != grant['namespace']: raise ValueError('grant namespace differs from the original creation observation')
    if args.command == 'plan':
        if not args.authority_id.strip() or len(args.authority_id) > 200: raise ValueError('bounded authority id required')
        body = dict(binding, schema_version=1, kind='disposable_target_cleanup_authority', authority_id=args.authority_id,
                    scope='owned_disposable_namespace', operations=list(dict.fromkeys(args.operations)))
        body['authority_sha256'] = digest(body)
        return {'unsigned_cleanup_authority_body': body, 'authority_created': False, 'database_contacted': False,
                'note': 'sign offline with the operator target_authority key; this command never signs'}
    if args.expected_namespace != grant['namespace']: raise ValueError('retyped namespace differs from grant; nothing done')
    cleanup_signed = read(within(root, grant['cleanup_signed_authority'], exists=True))
    # The library's full authority check (signature, closed keys, scope, digest, every binding pin
    # including the CURRENT cleanup code pin) runs offline, before any environment access or connection.
    from la.postgres import authorize_cleanup
    authorize_cleanup(cleanup_signed, verifier, grant['expected_cleanup_authority_sha256'], binding,
                      'cleanup' if args.command == 'run' else 'reconcile_cleanup')
    receipt_root = lexical(grant['receipt_root'])
    if not receipt_root.is_dir(): raise ValueError('existing explicit receipt root required')
    common = dict(pins, expected_cleanup_authority_sha256=grant['expected_cleanup_authority_sha256'],
                  target_config=config, authority_verifier=verifier, cleanup_verifier=verifier, receipt_root=receipt_root)
    if args.command == 'run':
        prior = [value for value in prior_attempts(receipt_root, grant['namespace']) if value['state'] in NO_RETRY_STATES]
        if prior: raise ValueError('a destructive cleanup attempt already exists for this namespace; reconcile, never retry')
    else:
        receipt_path = lexical(args.receipt)
        if receipt_path.parent.resolve() != receipt_root.resolve():
            raise ValueError("reconcile requires a prior receipt from this grant's receipt root")
        from la.postgres import open_target_cleanup
        open_target_cleanup(receipt_path, expected_cleanup_sha256=args.expected_cleanup_sha256)  # offline, before the DSN
    from la.app.observations import target_dsn
    from la.postgres.target import driver_and_connect
    dsn = target_dsn(args.dsn_env, config)
    if dsn is None: raise ValueError('named DSN environment variable is unset; nothing done')
    _, connect = driver_and_connect(dsn, config)
    opened = []
    try:
        if args.command == 'run':
            from la.postgres import cleanup_target_namespace
            opened.append(connect()); opened.append(connect())
            value = cleanup_target_namespace(experiment, artifact, original, cleanup_signed,
                connection=opened[0], observer_connection=opened[1], **common)
        else:
            from la.postgres import reconcile_target_cleanup
            opened.append(connect())
            value = reconcile_target_cleanup(experiment, artifact, original, cleanup_signed,
                cleanup_receipt_path=receipt_path, expected_cleanup_sha256=args.expected_cleanup_sha256,
                observer_connection=opened[0], **common)
    finally:
        for connection in opened:
            try: connection.close()
            except Exception: pass
    return summary(value, receipt_root / ('cleanup-' + value['cleanup_sha256'] + '.json'))


def main():
    try:
        from la.app.cli import emit_result
        emit_result(execute(parser().parse_args()))
    except Exception as exc:  # Includes driver errors whose messages could echo DSN fragments.
        raise SystemExit('la_cleanup: ' + type(exc).__name__ + '; inspect local non-secret contracts') from None


if __name__ == '__main__': main()

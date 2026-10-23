"""Opt-in PostgreSQL validation. Importing this module never connects."""
from __future__ import annotations

import hashlib
import json
import re
import uuid
from decimal import Decimal
from pathlib import Path

from la.convert import approve_mapping, sql_artifacts, transform, validate_mapping
from la.review import canonical, digest


def validate_bundle(bundle_path):
    root = Path(bundle_path).resolve(strict=True)
    if not root.is_dir():
        raise ValueError('bundle must be a directory')
    manifest = json.loads((root / 'manifest.json').read_text(encoding='utf-8'))
    if digest({k: v for k, v in manifest.items() if k != 'bundle_sha256'}) != manifest['bundle_sha256']:
        raise ValueError('bundle hash mismatch')
    expected_files = {'mapping.json', 'source.json', 'schema.sql', 'migrate.sql', 'rows.jsonl', 'unresolved.jsonl', 'quarantine.jsonl', 'approval.json', 'LOAD.md'}
    if set(manifest['files']) != expected_files:
        raise ValueError('unexpected bundle members')
    for name, expected_hash in manifest['files'].items():
        path = root / name
        if path.is_symlink() or path.resolve(strict=True).parent != root:
            raise ValueError('bundle path escape')
        if hashlib.sha256(path.read_bytes()).hexdigest() != expected_hash:
            raise ValueError(f'artifact hash mismatch: {name}')
    batch = json.loads((root / 'source.json').read_text(encoding='utf-8'))
    mapping = json.loads((root / 'mapping.json').read_text(encoding='utf-8'))
    validate_mapping(batch, mapping, require_complete=True)
    approval = json.loads((root / 'approval.json').read_text(encoding='utf-8'))
    if approval is None or approval != approve_mapping(mapping, approval['actor'], approval['reason']):
        raise ValueError('explicit bound approval required')
    if manifest['mapping_sha256'] != mapping['mapping_sha256'] or manifest['source_sha256'] != batch['source_sha256'] or manifest['generation_binding'] != mapping['generation_binding'] or manifest['approval_sha256'] != approval['approval_sha256']:
        raise ValueError('manifest dependency mismatch')
    outcomes = transform(batch, mapping)
    expected_rows = [o for o in outcomes if o['outcome'] == 'converted']
    actual_rows = [json.loads(line) for line in (root / 'rows.jsonl').read_text(encoding='utf-8').splitlines()]
    if actual_rows != expected_rows:
        raise ValueError('row projection mismatch')
    for kind, filename in [('unresolved', 'unresolved.jsonl'), ('quarantined', 'quarantine.jsonl')]:
        expected = [o for o in outcomes if o['outcome'] == kind]
        actual = [json.loads(line) for line in (root / filename).read_text(encoding='utf-8').splitlines()]
        if actual != expected:
            raise ValueError('outcome projection mismatch')
    counts = {kind: sum(o['outcome'] == kind for o in outcomes) for kind in ('converted', 'unresolved', 'quarantined')}
    if counts != manifest['counts'] or len(outcomes) != manifest['record_count']:
        raise ValueError('bundle cardinality mismatch')
    ddl, sql, columns = sql_artifacts(mapping)
    if (root / 'schema.sql').read_text(encoding='utf-8') != ddl or (root / 'migrate.sql').read_text(encoding='utf-8') != sql or columns != manifest['columns']:
        raise ValueError('SQL does not match deterministic mapping')
    identities = [(o['record_ref']['source_sha256'], o['record_ref']['ordinal']) for o in outcomes]
    if len(set(identities)) != len(identities):
        raise ValueError('duplicate record identity')
    return manifest, mapping, expected_rows, ddl, sql, columns


def database_check(bundle_path, *, dsn=None, authorized=False) -> dict:
    """Execute only after explicit target authority; caller never receives/logs DSN.

    This checks stored values against the producer projection. Independent oracle parity,
    failure-injection rollback and lost-ACK recovery must be separately exercised before
    target_validation can become passed.
    """
    receipt = {'schema_version': 1, 'target_validation': 'not_run', 'row_parity': 'not_run',
               'product_acceptance': 'pending'}
    if not authorized or not dsn:
        return dict(receipt, reason='explicit_authority_and_dsn_required')
    manifest, mapping, rows, ddl, sql, columns = validate_bundle(bundle_path)
    receipt['bundle_sha256'] = manifest['bundle_sha256']
    # Import is deliberately behind authority, DSN, approval and artifact validation.
    try:
        import psycopg
    except ImportError:
        return dict(receipt, reason='psycopg_not_installed')
    namespace = 'la_' + uuid.uuid4().hex
    if re.fullmatch(r'la_[a-f0-9]{32}', namespace) is None:
        raise ValueError('invalid namespace')
    receipt['namespace'] = namespace
    committed = False
    commit_attempted = False
    try:
        with psycopg.connect(dsn) as connection:
            with connection.cursor() as cursor:
                cursor.execute(f'CREATE SCHEMA "{namespace}"')
                cursor.execute(f'SET LOCAL search_path TO "{namespace}"')
                cursor.execute(ddl)
                cursor.execute('CREATE TABLE "load_receipt" (bundle_sha256 text PRIMARY KEY, row_count bigint NOT NULL)')
                parameters = []
                field_by_name = {f['semantic_target']: f for f in mapping['fields']}
                for row in rows:
                    ref = row['record_ref']
                    values = {'source_sha256': ref['source_sha256'], 'ordinal': ref['ordinal'], 'raw_sha256': ref['raw_sha256'], **row['values']}
                    for name, field in field_by_name.items():
                        if field['data_type'] == 'decimal' and values[name] is not None:
                            values[name] = Decimal(values[name])
                    parameters.append(tuple(values[name] for name in columns))
                cursor.executemany(sql, parameters)
                cursor.execute('SELECT count(*) FROM "migrated_records"')
                if cursor.fetchone()[0] != len(rows):
                    raise ValueError('precommit cardinality mismatch')
                cursor.execute('INSERT INTO "load_receipt" VALUES (%s,%s)', (manifest['bundle_sha256'], len(rows)))
                cursor.execute('SELECT version()')
                receipt['server_version'] = cursor.fetchone()[0]
            commit_attempted = True
            connection.commit()
            committed = True
        # A different connection proves committed visibility, not just transaction-local state.
        with psycopg.connect(dsn) as fresh:
            with fresh.cursor() as cursor:
                cursor.execute(f'SELECT bundle_sha256,row_count FROM "{namespace}"."load_receipt"')
                if cursor.fetchall() != [(manifest['bundle_sha256'], len(rows))]:
                    raise ValueError('durable receipt mismatch')
                quoted = ','.join(f'"{name}"' for name in columns)
                cursor.execute(f'SELECT {quoted} FROM "{namespace}"."migrated_records" ORDER BY "ordinal"')
                stored = cursor.fetchall()
        observations = []
        fields = {f['semantic_target']: f for f in mapping['fields']}
        for row in stored:
            entry = dict(zip(columns, row))
            values = {}
            for name, field in fields.items():
                value = entry[name]
                if value is not None and field['data_type'] == 'date':
                    value = value.isoformat()
                elif value is not None and field['data_type'] == 'decimal':
                    value = format(value, f".{field['policy']['scale']}f")
                values[name] = value
            observations.append({'source_sha256': entry['source_sha256'], 'ordinal': entry['ordinal'],
                                 'raw_sha256': entry['raw_sha256'], 'values': values})
        expected = [{'source_sha256': o['record_ref']['source_sha256'], 'ordinal': o['record_ref']['ordinal'],
                     'raw_sha256': o['record_ref']['raw_sha256'], 'values': o['values']} for o in sorted(rows, key=lambda o: o['record_ref']['ordinal'])]
        equal = observations == expected
        return dict(receipt, target_validation='not_run' if equal else 'failed',
                    reason='awaiting_independent_oracle_and_negative_checks' if equal else 'committed_projection_mismatch',
                    execution_status='committed_readback', producer_projection_match=equal,
                    observations=observations, committed=True)
    except Exception as exc:
        # Driver exception text can contain connection credentials; expose its class only.
        return dict(receipt, target_validation='indeterminate' if commit_attempted or committed else 'failed',
                    reason=type(exc).__name__, committed=committed,
                    reconciliation={'namespace': namespace, 'bundle_sha256': manifest['bundle_sha256'],
                                    'action': 'read durable load_receipt using fresh authorized connection before any retry'})


def reconcile_commit(bundle_path, namespace: str, *, dsn=None, authorized=False) -> dict:
    """Read a prior durable identity after a lost ACK; never blindly repeat the load."""
    if not authorized or not dsn:
        return {'target_validation': 'not_run', 'reason': 'explicit_authority_and_dsn_required'}
    manifest, _, _, _, _, _ = validate_bundle(bundle_path)
    if re.fullmatch(r'la_[a-f0-9]{32}', namespace) is None:
        raise ValueError('invalid namespace')
    try:
        import psycopg
        with psycopg.connect(dsn) as connection:
            with connection.cursor() as cursor:
                cursor.execute('SELECT to_regclass(%s)', (namespace + '.load_receipt',))
                if cursor.fetchone()[0] is None:
                    return {'target_validation': 'indeterminate', 'reason': 'durable_identity_absent', 'namespace': namespace,
                            'bundle_sha256': manifest['bundle_sha256'], 'retry_authorized': False}
                cursor.execute(f'SELECT bundle_sha256,row_count FROM "{namespace}"."load_receipt"')
                actual = cursor.fetchall()
                match = actual == [(manifest['bundle_sha256'], manifest['counts']['converted'])]
        return {'target_validation': 'not_run' if match else 'failed', 'execution_status': 'commit_identity_reconciled' if match else 'identity_conflict',
                'namespace': namespace, 'bundle_sha256': manifest['bundle_sha256'], 'retry_authorized': False,
                'reason': 'independent_readback_and_oracle_still_required'}
    except Exception as exc:
        return {'target_validation': 'indeterminate', 'reason': type(exc).__name__, 'namespace': namespace, 'retry_authorized': False}


def rollback_check(bundle_path, *, dsn=None, authorized=False) -> dict:
    """Deliberately fail an isolated precommit transaction and check fresh visibility.

    This is a future authorized negative-check entrypoint, never invoked on import.
    No existing namespace is touched and no successful probe data is committed.
    """
    if not authorized or not dsn:
        return {'target_validation': 'not_run', 'reason': 'explicit_authority_and_dsn_required'}
    manifest, mapping, rows, ddl, sql, columns = validate_bundle(bundle_path)
    if not rows:
        return {'target_validation': 'not_run', 'reason': 'rollback_probe_requires_a_converted_record'}
    namespace = 'la_' + uuid.uuid4().hex
    try:
        import psycopg
        try:
            with psycopg.connect(dsn) as connection:
                with connection.cursor() as cursor:
                    cursor.execute(f'CREATE SCHEMA "{namespace}"')
                    cursor.execute(f'SET LOCAL search_path TO "{namespace}"')
                    cursor.execute(ddl)
                    first = rows[0]
                    ref = first['record_ref']
                    values = {'source_sha256': ref['source_sha256'], 'ordinal': ref['ordinal'],
                              'raw_sha256': ref['raw_sha256'], **first['values']}
                    for field in mapping['fields']:
                        name = field['semantic_target']
                        if field['data_type'] == 'decimal' and values[name] is not None:
                            values[name] = Decimal(values[name])
                    cursor.execute(sql, tuple(values[name] for name in columns))
                    # Server-side error aborts the entire schema/table creation transaction.
                    cursor.execute('SELECT 1/0')
        except psycopg.errors.DivisionByZero:
            pass
        with psycopg.connect(dsn) as fresh:
            with fresh.cursor() as cursor:
                cursor.execute('SELECT EXISTS(SELECT 1 FROM pg_namespace WHERE nspname=%s)', (namespace,))
                absent = not cursor.fetchone()[0]
        return {'schema_version': 1, 'bundle_sha256': manifest['bundle_sha256'], 'namespace': namespace,
                'rollback_observed': absent, 'target_validation': 'not_run' if absent else 'failed',
                'reason': 'rollback_probe_only_independent_acceptance_pending'}
    except Exception as exc:
        return {'target_validation': 'indeterminate', 'reason': type(exc).__name__, 'namespace': namespace}

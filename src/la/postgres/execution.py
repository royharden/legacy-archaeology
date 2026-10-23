"""Source-only authorized execution/recovery entrypoints; nothing runs on import."""
from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import os
from pathlib import Path
import uuid

from la.review import canonical, digest
from la.convert.bundle import BundleVerificationError
from .target import (TargetConfig, driver_and_connect, inspect_target, new_namespace,
                     observe, owned_namespace, parameters, seal_receipt, verify_structure,
                     connection_identity)


def _base(operation, config=None):
    result = {'schema_version': 1, 'operation': operation, 'target_validation': 'not_run',
              'row_parity': 'not_run', 'product_acceptance': 'pending',
              'execution_status': 'not_run', 'timestamp': datetime.now(timezone.utc).isoformat(),
              'runtime_claim': 'actual_runtime_only_when_entrypoint_is_explicitly_executed'}
    if isinstance(config, TargetConfig):
        result['target_config_sha256'] = digest(config.public())
    return result


def _unavailable(receipt, dsn, authorized, config):
    if authorized is not True or not dsn:
        return seal_receipt(dict(receipt, reason='explicit_authority_and_dsn_required'))
    if not isinstance(config, TargetConfig):
        return seal_receipt(dict(receipt, reason='pinned_disposable_target_config_required'))
    config.validate()
    if config.expected_bundle_sha256 is None:
        return seal_receipt(dict(receipt, reason='external_expected_bundle_pin_required'))
    return None


def _pinned_bundle(bundle_path, config):
    from . import validate_bundle
    return validate_bundle(bundle_path, expected_bundle_sha256=config.expected_bundle_sha256,
                           expected_source_sha256=config.expected_source_sha256,
                           expected_mapping_sha256=config.expected_mapping_sha256)


def write_execution_receipt(destination, receipt):
    """Publish an immutable sibling receipt; never edit any migration bundle bytes."""
    if receipt.get('receipt_sha256') != digest({k: v for k, v in receipt.items() if k != 'receipt_sha256'}):
        raise ValueError('execution receipt hash mismatch')
    destination = Path(destination)
    if destination.is_symlink() or any((parent / 'manifest.json').is_file() for parent in destination.resolve().parents):
        raise ValueError('execution receipts must be outside immutable bundles')
    destination.parent.mkdir(parents=True, exist_ok=True)
    temporary = destination.with_name(destination.name + '.' + uuid.uuid4().hex + '.tmp')
    data = (canonical(receipt) + '\n').encode('utf-8')
    try:
        with temporary.open('xb') as stream:
            stream.write(data); stream.flush(); os.fsync(stream.fileno())
        os.link(temporary, destination)
    finally:
        temporary.unlink(missing_ok=True)
    return {'path': str(destination), 'sha256': hashlib.sha256(data).hexdigest()}


def _identity(manifest, run_id, config):
    return {'run_id': run_id, 'bundle_sha256': manifest['bundle_sha256'],
            'source_sha256': manifest['source_sha256'], 'mapping_sha256': manifest['mapping_sha256'],
            'approval_sha256': manifest['approval_sha256'], 'config_sha256': manifest['config_sha256'],
            'producer_code_sha256': manifest['producer_code_sha256'],
            'target_config_sha256': digest(config.public()), 'row_count': manifest['counts']['converted']}


def _read_identity(cursor, namespace, identity):
    owned_namespace(namespace)
    cursor.execute(f'SELECT run_id,bundle_sha256,pins_json,row_count FROM "{namespace}"."load_receipt"')
    expected = [(identity['run_id'], identity['bundle_sha256'], canonical(identity), identity['row_count'])]
    if cursor.fetchall() != expected:
        raise ValueError('durable run/bundle identity mismatch')


def _close(connection):
    if connection is not None:
        connection.close()


def database_check(bundle_path, *, dsn=None, authorized=False, target_config=None):
    """Load once into a fresh owned schema, commit, then capture actual readback.

    Never sets target_validation=passed: observations go to the independent scorer.
    No boolean supplied by a caller can stand for oracle parity/negative checks.
    """
    from . import validate_bundle
    receipt = _base('load_and_readback', target_config)
    unavailable = _unavailable(receipt, dsn, authorized, target_config)
    if unavailable: return unavailable
    try:
        manifest, mapping, rows, ddl, sql, columns = _pinned_bundle(bundle_path, target_config)
    except BundleVerificationError as exc:
        return seal_receipt(dict(receipt, target_validation='failed', execution_status='refused_before_connection',
                                 reason='offline_bundle_verification_failed', verification=exc.verification))
    if manifest['counts']['unresolved'] or not rows:
        return seal_receipt(dict(receipt, bundle_sha256=manifest['bundle_sha256'], reason='no_complete_load_rows'))
    namespace, run_id = new_namespace(), uuid.uuid4().hex
    identity = _identity(manifest, run_id, target_config)
    receipt.update(bundle_sha256=manifest['bundle_sha256'], namespace=namespace, run_id=run_id,
                   identity=identity, namespace_origin='fresh_generated_for_this_attempt',
                   committed=False, retry_authorized=False)
    connection, fresh = None, None
    commit_attempted = False
    try:
        _, connect = driver_and_connect(dsn, target_config)
        payloads = parameters(rows, mapping, columns)
        connection = connect()
        receipt['target'] = inspect_target(connection, target_config)
        receipt['write_connection_id'] = connection_identity(connection)
        with connection.cursor() as cursor:
            cursor.execute(f'CREATE SCHEMA "{namespace}"')
            cursor.execute(f'SET LOCAL search_path TO "{namespace}", pg_catalog')
            cursor.execute(ddl)
            cursor.execute('CREATE TABLE "load_receipt" (run_id text PRIMARY KEY, bundle_sha256 text UNIQUE NOT NULL, pins_json text NOT NULL, row_count bigint NOT NULL CHECK(row_count>=0))')
            receipt['structure'] = verify_structure(cursor, namespace, mapping)
            cursor.executemany(sql, payloads)
            before = observe(cursor, namespace, rows, mapping, columns)
            # This is structural identity/cardinality checking, never oracle parity.
            if len(before) != len(rows):
                raise ValueError('precommit cardinality mismatch')
            cursor.execute('INSERT INTO "load_receipt" VALUES (%s,%s,%s,%s)',
                           (run_id, manifest['bundle_sha256'], canonical(identity), len(rows)))
            _read_identity(cursor, namespace, identity)
        commit_attempted = True
        connection.commit()
        receipt['committed'] = True
        connection.close(); connection = None
        fresh = connect()
        target = inspect_target(fresh, target_config)
        receipt['read_connection_id'] = connection_identity(fresh)
        if receipt['read_connection_id'] == receipt['write_connection_id']:
            raise ValueError('fresh readback reused the write connection')
        if target != receipt['target']:
            raise ValueError('fresh connection target identity changed')
        with fresh.cursor() as cursor:
            _read_identity(cursor, namespace, identity)
            verify_structure(cursor, namespace, mapping)
            observations = observe(cursor, namespace, rows, mapping, columns)
        observation_artifact = {'schema_version': 1, 'bundle_sha256': manifest['bundle_sha256'],
                                'run_id': run_id, 'namespace': namespace, 'target': target,
                                'capture': 'fresh_connection_after_commit', 'rows': observations}
        observation_artifact['observations_sha256'] = digest(observation_artifact)
        expected = {digest(row['record_ref']): row['values'] for row in rows}
        projection_match = all(expected.get(digest(row['record_ref'])) == row['values'] for row in observations)
        receipt.update(execution_status='committed_readback', observations=observations,
                       observation_artifact=observation_artifact, producer_projection_match=projection_match,
                       reason='awaiting_independent_oracle_and_negative_checks' if projection_match else 'committed_projection_mismatch',
                       target_validation='not_run' if projection_match else 'failed',
                       transformation_status=manifest['transformation_status'])
    except ImportError:
        receipt.update(reason='psycopg_not_installed')
    except Exception as exc:
        if connection is not None and not commit_attempted:
            try: connection.rollback()
            except Exception: pass
        receipt.update(target_validation='indeterminate' if commit_attempted else 'failed',
                       execution_status='commit_outcome_unknown' if commit_attempted else 'failed_before_commit',
                       reason=type(exc).__name__,
                       reconciliation={'namespace': namespace, 'identity': identity,
                                       'action': 'fresh_authorized_identity_and_readback_before_any_new_load'})
    finally:
        _close(connection); _close(fresh)
    return seal_receipt(receipt)


def reconcile_commit(bundle_path, namespace, *, dsn=None, authorized=False, target_config=None,
                     execution_receipt=None):
    """Read-only recovery. An absent marker never grants an automatic retry."""
    from . import validate_bundle
    receipt = _base('reconcile_commit', target_config)
    unavailable = _unavailable(receipt, dsn, authorized, target_config)
    if unavailable: return unavailable
    owned_namespace(namespace)
    try:
        manifest, mapping, rows, _, _, columns = _pinned_bundle(bundle_path, target_config)
    except BundleVerificationError as exc:
        return seal_receipt(dict(receipt, target_validation='failed', execution_status='refused_before_connection',
                                 reason='offline_bundle_verification_failed', verification=exc.verification))
    if not isinstance(execution_receipt, dict) or execution_receipt.get('receipt_sha256') != digest({k: v for k, v in execution_receipt.items() if k != 'receipt_sha256'}):
        raise ValueError('original immutable execution receipt required')
    identity = execution_receipt.get('identity')
    if execution_receipt.get('namespace') != namespace or not identity or identity != _identity(manifest, execution_receipt['run_id'], target_config):
        raise ValueError('recovery scope differs from original attempt')
    receipt.update(namespace=namespace, bundle_sha256=manifest['bundle_sha256'],
                   run_id=identity['run_id'], original_receipt_sha256=execution_receipt['receipt_sha256'],
                   identity=identity, retry_authorized=False)
    connection = None
    try:
        _, connect = driver_and_connect(dsn, target_config)
        connection = connect()
        target = inspect_target(connection, target_config)
        receipt['read_connection_id'] = connection_identity(connection)
        with connection.cursor() as cursor:
            cursor.execute('SELECT to_regclass(%s)', (namespace + '.load_receipt',))
            if cursor.fetchone()[0] is None:
                return seal_receipt(dict(receipt, target_validation='indeterminate', reason='durable_identity_absent'))
            _read_identity(cursor, namespace, identity)
            verify_structure(cursor, namespace, mapping)
            observations = observe(cursor, namespace, rows, mapping, columns)
        artifact = {'schema_version': 1, 'bundle_sha256': manifest['bundle_sha256'], 'run_id': identity['run_id'],
                    'namespace': namespace, 'target': target, 'capture': 'fresh_connection_reconciliation', 'rows': observations}
        artifact['observations_sha256'] = digest(artifact)
        receipt.update(execution_status='commit_identity_reconciled', committed=True,
                       observations=observations, observation_artifact=artifact,
                       durable_bundle_sha256=identity['bundle_sha256'], duplicate_execution_rows=0,
                       reason='independent_oracle_and_negative_checks_still_required')
    except ImportError:
        receipt.update(reason='psycopg_not_installed')
    except Exception as exc:
        receipt.update(target_validation='indeterminate', reason=type(exc).__name__)
    finally:
        _close(connection)
    return seal_receipt(receipt)


def rollback_check(bundle_path, *, dsn=None, authorized=False, target_config=None, _probe_kind='rollback'):
    """Force an error after actual insertion; a new connection checks no schema survived."""
    from . import validate_bundle
    receipt = _base('rollback_probe' if _probe_kind == 'rollback' else 'constraint_probe', target_config)
    if _probe_kind not in ('rollback', 'duplicate_identity', 'nonnull', 'numeric_overflow', 'status_vocabulary'):
        raise ValueError('unknown finite negative probe')
    unavailable = _unavailable(receipt, dsn, authorized, target_config)
    if unavailable: return unavailable
    try:
        manifest, mapping, rows, ddl, sql, columns = _pinned_bundle(bundle_path, target_config)
    except BundleVerificationError as exc:
        return seal_receipt(dict(receipt, target_validation='failed', execution_status='refused_before_connection',
                                 reason='offline_bundle_verification_failed', verification=exc.verification))
    receipt['bundle_sha256'] = manifest['bundle_sha256']
    if not rows:
        return seal_receipt(dict(receipt, reason='rollback_probe_requires_converted_record'))
    namespace, connection, fresh = new_namespace(), None, None
    receipt.update(namespace=namespace, negative_check=_probe_kind, rollback_observed=False)
    injected = False
    observed_sqlstate = None
    try:
        driver, connect = driver_and_connect(dsn, target_config)
        expected_error = {'rollback': driver.errors.DivisionByZero,
                          'duplicate_identity': driver.errors.UniqueViolation,
                          'nonnull': driver.errors.NotNullViolation,
                          'numeric_overflow': driver.errors.NumericValueOutOfRange,
                          'status_vocabulary': driver.errors.CheckViolation}[_probe_kind]
        first = list(parameters(rows[:1], mapping, columns)[0])
        if _probe_kind == 'nonnull':
            field = next((f for f in mapping['fields'] if not f['policy']['nullable']), None)
            if field is None:
                return seal_receipt(dict(receipt, reason='not_applicable_no_nonnull_semantic_column'))
            first[columns.index(field['semantic_target'])] = None
        elif _probe_kind == 'numeric_overflow':
            from decimal import Decimal
            policy = next(f['policy'] for f in mapping['fields'] if f['semantic_target'] == 'balance')
            first[columns.index('balance')] = Decimal(10) ** (policy['precision'] - policy['scale'])
        elif _probe_kind == 'status_vocabulary':
            policy = next(f['policy'] for f in mapping['fields'] if f['semantic_target'] == 'status')
            if 'allowed_codes' not in policy:
                return seal_receipt(dict(receipt, reason='not_applicable_no_disclosed_status_vocabulary'))
            invalid = '__la_invalid__'
            while invalid in policy['allowed_codes']: invalid += '_'
            first[columns.index('status')] = invalid
        connection = connect()
        receipt['target'] = inspect_target(connection, target_config)
        receipt['write_connection_id'] = connection_identity(connection)
        try:
            with connection.cursor() as cursor:
                cursor.execute(f'CREATE SCHEMA "{namespace}"')
                cursor.execute(f'SET LOCAL search_path TO "{namespace}", pg_catalog')
                cursor.execute(ddl)
                cursor.execute(sql, tuple(first))
                if _probe_kind == 'duplicate_identity':
                    cursor.execute(sql, tuple(first))
                elif _probe_kind == 'rollback':
                    cursor.execute('SELECT 1/0')
        except expected_error as exc:
            injected = True
            observed_sqlstate = exc.sqlstate
        finally:
            connection.rollback()
        connection.close(); connection = None
        if not injected:
            raise ValueError('required server failure did not occur')
        fresh = connect()
        if inspect_target(fresh, target_config) != receipt['target']:
            raise ValueError('rollback observer target changed')
        receipt['read_connection_id'] = connection_identity(fresh)
        if receipt['read_connection_id'] == receipt['write_connection_id']:
            raise ValueError('rollback observer reused write connection')
        with fresh.cursor() as cursor:
            cursor.execute('SELECT EXISTS(SELECT 1 FROM pg_namespace WHERE nspname=%s)', (namespace,))
            absent = not cursor.fetchone()[0]
        receipt.update(rollback_observed=absent, execution_status='rollback_observed' if absent else 'rollback_failed',
                       target_validation='not_run' if absent else 'failed',
                       reason='negative_check_only_independent_acceptance_pending')
        receipt['observation'] = {'bundle_sha256': manifest['bundle_sha256'],
                                  'kind': {'rollback': 'rollback', 'nonnull': 'not_null', 'status_vocabulary': 'check'}.get(_probe_kind, _probe_kind),
                                  'sqlstate': observed_sqlstate,
                                  'probe_statement_sha256': digest({'ddl': ddl, 'insert': sql, 'error_statement': 'SELECT 1/0' if _probe_kind == 'rollback' else sql, 'probe': _probe_kind}),
                                  'failure_injected_before_commit': injected,
                                  'rows_before': [], 'rows_after_fresh_read': [] if absent else None,
                                  'fresh_read_connection_id': receipt['read_connection_id']}
    except ImportError:
        receipt.update(reason='psycopg_not_installed')
    except Exception as exc:
        receipt.update(target_validation='indeterminate', reason=type(exc).__name__)
    finally:
        _close(connection); _close(fresh)
    return seal_receipt(receipt)


def constraint_checks(bundle_path, *, dsn=None, authorized=False, target_config=None):
    """Finite actual database-error probes, each isolated and rolled back.

    Not-applicable vocabulary/null constraints remain explicit; no aggregate pass flag.
    """
    receipt = _base('constraint_probes', target_config)
    unavailable = _unavailable(receipt, dsn, authorized, target_config)
    if unavailable: return unavailable
    results = [rollback_check(bundle_path, dsn=dsn, authorized=authorized, target_config=target_config,
                              _probe_kind=kind)
               for kind in ('duplicate_identity', 'nonnull', 'numeric_overflow', 'status_vocabulary')]
    receipt.update(checks=results, execution_status='finite_constraint_probes_recorded',
                   reason='independent_oracle_and_combined_acceptance_required')
    if any(item['target_validation'] in ('failed', 'indeterminate') for item in results):
        receipt['target_validation'] = 'failed'
    return seal_receipt(receipt)


def target_observer(artifacts, authority, *, dsn=None, target_config=None):
    """Evaluator port `(artifacts, authority)`; never receives canonical gold.

    Returns D6's closed target-observation wire envelope or None when no committed
    fresh observations exist. Keep full execution/negative receipts separately.
    A normal commit does not fabricate a lost-ack event; that evidence remains absent.
    """
    from . import validate_bundle
    if not isinstance(artifacts, dict) or not isinstance(authority, dict):
        raise ValueError('declared target artifacts/authority required')
    if authority.get('authorized') is not True or authority.get('bundle_sha256') != artifacts.get('bundle_sha256'):
        raise ValueError('bundle-bound target authority required')
    if not isinstance(authority.get('authority_sha256'), str) or len(authority['authority_sha256']) != 64:
        raise ValueError('authority hash required')
    if not isinstance(artifacts.get('edition'), str) or not artifacts['edition']:
        raise ValueError('declared evaluator edition required')
    manifest, _, _, _, _, _ = validate_bundle(artifacts['bundle_path'])
    if any(artifacts.get(key) != manifest[key] for key in ('bundle_sha256', 'mapping_sha256')):
        raise ValueError('observer artifact identity mismatch')
    if not isinstance(target_config, TargetConfig) or target_config.authority_reference != authority['authority_sha256']:
        raise ValueError('target config must bind this authority reference')
    if target_config.expected_bundle_sha256 != authority['bundle_sha256']:
        raise ValueError('target external bundle pin must match separately supplied authority')
    execution = database_check(artifacts['bundle_path'], dsn=dsn, authorized=True, target_config=target_config)
    effective, recovery = execution, None
    if execution.get('execution_status') == 'commit_outcome_unknown':
        recovery = reconcile_commit(artifacts['bundle_path'], execution['namespace'], dsn=dsn,
                                    authorized=True, target_config=target_config, execution_receipt=execution)
        if recovery.get('execution_status') == 'commit_identity_reconciled':
            effective = recovery
    if effective.get('execution_status') not in ('committed_readback', 'commit_identity_reconciled'):
        return None
    rollback = rollback_check(artifacts['bundle_path'], dsn=dsn, authorized=True, target_config=target_config)
    constraints = constraint_checks(artifacts['bundle_path'], dsn=dsn, authorized=True, target_config=target_config)
    negative = {'rollback': rollback.get('observation', {}),
                'constraints': [item['observation'] for item in constraints.get('checks', []) if 'observation' in item]}
    if recovery is not None and recovery.get('execution_status') == 'commit_identity_reconciled':
        negative['lost_ack'] = {'bundle_sha256': manifest['bundle_sha256'],
                                'durable_bundle_sha256': recovery['durable_bundle_sha256'],
                                'execution_id': recovery['run_id'],
                                'fresh_read_connection_id': recovery['read_connection_id'],
                                'duplicate_execution_rows': recovery['duplicate_execution_rows']}
    target = effective['observation_artifact']['target']
    # Column metadata was actually inspected in verify_structure, not supplied by a scorer.
    structure = execution.get('structure')
    if structure is None:
        return None
    types = {'text': 'text', 'numeric': 'decimal', 'date': 'date'}
    column_types = {item[0]: types[item[1]] for item in structure['columns'] if item[0] in ('account_ref', 'description', 'balance', 'effective_date', 'status')}
    rows = effective['observations']
    observer_code = digest({name: hashlib.sha256((Path(__file__).parent / name).read_bytes()).hexdigest()
                            for name in ('__init__.py', 'target.py', 'execution.py')})
    return {'schema_version': 1, 'bundle_sha256': manifest['bundle_sha256'],
            'mapping_sha256': manifest['mapping_sha256'], 'kind': 'committed_fresh_readback',
            'commit_state': 'committed', 'execution_id': execution['run_id'],
            'server_version': str(target['server_version_num']), 'namespace': execution['namespace'],
            'role': target['role'], 'write_connection_id': execution['write_connection_id'],
            'read_connection_id': effective['read_connection_id'], 'observer_code_sha256': observer_code,
            'edition': artifacts['edition'], 'column_types': column_types, 'rows': rows,
            'rows_sha256': digest(rows), 'negative_observations': negative}

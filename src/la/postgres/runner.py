"""One disposable transaction/readback path for product and all evaluation arms.

All entrypoints are inert until explicitly invoked with pinned authority/config.
They never receive evaluator gold or manufacture product rulings/approvals.
"""
from __future__ import annotations

import hashlib
import uuid
from copy import deepcopy

from la.review import canonical, digest
from .candidate import observer_code_pin, resolve_candidate, verify_authority
from .authority import verified_target_authority
from .effects import (NEGATIVE_KINDS, collect_negative_effect, failed_load_effect,
                      namespace_snapshot, seal_observation, validate_target_observation)
from .target import (TargetConfig, connection_identity, driver_and_connect, inspect_target,
                     new_namespace, observation_query, observe, owned_namespace, parameters,
                     verify_structure, StatementTrace)


def _base(candidate, authority, config):
    return {'schema_version': 2, 'kind': 'target_observation', 'candidate': candidate.descriptor,
            'authority_sha256': authority['authority_sha256'], 'target_config_sha256': digest(config.public()),
            'observer_code_sha256': observer_code_pin(),
            'attempt': {'execution_id': uuid.uuid4().hex, 'attempt_id': uuid.uuid4().hex,
                        'namespace': new_namespace(), 'write_connection_id': None,
                        'read_connection_id': None, 'prior_observation_sha256': None},
            'target': None, 'commit_state': 'not_run', 'readback': None,
            'negative_effects': [], 'recovery': None, 'issues': []}


def _marker(candidate, authority, config, execution_id):
    return {'execution_id': execution_id, 'candidate': candidate.descriptor,
            'authority_sha256': authority['authority_sha256'], 'target_config_sha256': digest(config.public()),
            'row_count': len(candidate.rows)}


def _read_marker(cursor, namespace, marker):
    owned_namespace(namespace)
    sql = f'SELECT execution_id,candidate_sha256,authority_sha256,payload FROM "{namespace}"."candidate_execution"'
    cursor.execute(sql)
    actual = cursor.fetchall()
    expected = [(marker['execution_id'], marker['candidate']['candidate_sha256'], marker['authority_sha256'], canonical(marker))]
    if actual != expected: raise ValueError('durable candidate execution marker mismatch')
    return {'query_sha256': hashlib.sha256(sql.encode()).hexdigest(), 'rows': actual,
            'rows_sha256': digest(actual)}


def _capture(connection, candidate, namespace, capture):
    with connection.cursor() as cursor:
        structure = verify_structure(cursor, namespace, candidate.mapping)
        rows = observe(cursor, namespace, candidate.rows, candidate.mapping, candidate.columns)
    return {'capture': capture, 'query_sha256': hashlib.sha256(observation_query(namespace, candidate.columns).encode()).hexdigest(),
            'columns': structure['columns'], 'rows': rows, 'rows_sha256': digest(rows)}


class ControlledAcknowledgementSuppressed(RuntimeError):
    """Deliberate application boundary fault; never an asserted network failure."""


def _controlled_fault(operation):
    boundaries = {'controlled_failed_load': 'after_first_insert_before_commit',
                  'controlled_commit_ack': 'after_driver_commit_before_application_ack'}
    if operation not in boundaries: raise ValueError('unknown controlled fault operation')
    boundary = boundaries[operation]
    return {'operation': operation, 'boundary': boundary, 'state': 'not_reached',
            'network_loss_claimed': False, 'driver_commit_returned': False,
            'application_ack_delivered': False, 'trigger_statement_sha256': None,
            'boundary_sha256': digest({'operation': operation, 'boundary': boundary,
                                      'observer_code_sha256': observer_code_pin()}),
            'injected_error_class': None, 'partial_write': None}


def _partial_write(cursor, namespace, connection_id):
    sql = f'SELECT "source_sha256","ordinal","raw_sha256" FROM "{namespace}"."migrated_records" ORDER BY "ordinal" LIMIT 10001'
    cursor.execute(sql)
    rows = [dict(zip(('source_sha256', 'ordinal', 'raw_sha256'), row)) for row in cursor.fetchall()]
    if len(rows) > 10000: raise ValueError('partial-write observation limit')
    return {'connection_id': connection_id, 'query_sha256': hashlib.sha256(sql.encode()).hexdigest(),
            'rows': rows, 'rows_sha256': digest(rows)}


def target_observer_v2(artifacts, authority, *, dsn=None, target_config=None, negative_kinds=(), authority_verifier=None):
    """Closed v2 observation port for all five explicitly scoped comparator methods.

    Authority is a pinned intent document, never `{authorized: true, passed: true}`.
    Every negative kind additionally requires `negative_probes` in that document.
    """
    return _observe_candidate(artifacts, authority, dsn=dsn, target_config=target_config,
                               negative_kinds=negative_kinds, authority_verifier=authority_verifier)


def _observe_candidate(artifacts, authority, *, dsn=None, target_config=None, negative_kinds=(),
                       authority_verifier=None, fault_operation=None):
    if not isinstance(target_config, TargetConfig): raise ValueError('explicit target config required')
    authority = verified_target_authority(authority, authority_verifier)
    candidate = resolve_candidate(artifacts, target_config)
    verify_authority(authority, candidate, target_config, 'load')
    if fault_operation is not None:
        verify_authority(authority, candidate, target_config, fault_operation)
        if fault_operation == 'controlled_commit_ack':
            verify_authority(authority, candidate, target_config, 'reconcile')
    if not isinstance(negative_kinds, (tuple, list)) or len(negative_kinds) > len(NEGATIVE_KINDS) or any(kind not in NEGATIVE_KINDS for kind in negative_kinds) or len(set(negative_kinds)) != len(negative_kinds):
        raise ValueError('bounded unique negative kinds required')
    if negative_kinds: verify_authority(authority, candidate, target_config, 'negative_probes')
    value = _base(candidate, authority, target_config)
    if fault_operation is not None:
        value.update(schema_version=3, controlled_fault=_controlled_fault(fault_operation))
    if not dsn:
        value['issues'].append({'code': 'dsn_not_supplied'}); return validate_target_observation(seal_observation(value))
    if not candidate.rows or candidate.descriptor['counts']['unresolved']:
        value['issues'].append({'code': 'no_complete_load_rows'}); return validate_target_observation(seal_observation(value))
    namespace = value['attempt']['namespace']
    marker = _marker(candidate, authority, target_config, value['attempt']['execution_id'])
    connection, fresh, commit_attempted = None, None, False
    commit_acknowledged = False
    before, connect, failed_transaction, rollback_completed = None, None, None, False
    trace = None
    try:
        _, connect = driver_and_connect(dsn, target_config)
        payloads = parameters(candidate.rows, candidate.mapping, candidate.columns)
        before_target, before = namespace_snapshot(connect, target_config, namespace)
        if before['namespace_exists'] or before['table_exists'] or before['rows']:
            raise ValueError('candidate namespace already exists')
        connection = connect()
        value['target'] = inspect_target(connection, target_config)
        if value['target'] != before_target: raise ValueError('write target differs from pre-load observer')
        value['attempt']['write_connection_id'] = connection_identity(connection)
        with connection.cursor() as raw_cursor:
            cursor = trace = StatementTrace(raw_cursor)
            cursor.execute(f'CREATE SCHEMA "{namespace}"')
            cursor.execute(f'SET LOCAL search_path TO "{namespace}", pg_catalog')
            cursor.execute(candidate.ddl)
            cursor.execute('CREATE TABLE "candidate_execution" (execution_id text PRIMARY KEY,candidate_sha256 text NOT NULL,authority_sha256 text NOT NULL,payload text NOT NULL)')
            verify_structure(cursor, namespace, candidate.mapping)
            if fault_operation == 'controlled_failed_load':
                cursor.execute(candidate.sql, payloads[0])
                fault = value['controlled_fault']
                fault['partial_write'] = _partial_write(cursor, namespace, value['attempt']['write_connection_id'])
                fault['state'] = 'injected'
                try:
                    cursor.execute('SELECT 1/0')
                finally:
                    fault['trigger_statement_sha256'] = cursor.last_statement_sha256
                # An unusual proxy/server that accepts the deliberate failure is not proof.
                fault['state'] = 'unsupported'
                raise ValueError('controlled server failure did not occur')
            cursor.executemany(candidate.sql, payloads)
            observe(cursor, namespace, candidate.rows, candidate.mapping, candidate.columns)
            cursor.execute('INSERT INTO "candidate_execution" VALUES (%s,%s,%s,%s)',
                           (marker['execution_id'], candidate.descriptor['candidate_sha256'], authority['authority_sha256'], canonical(marker)))
            _read_marker(cursor, namespace, marker)
        commit_attempted = True
        connection.commit()
        commit_acknowledged = True
        if fault_operation is not None:
            value['controlled_fault']['driver_commit_returned'] = True
        if fault_operation == 'controlled_commit_ack':
            value['controlled_fault']['state'] = 'injected'
            raise ControlledAcknowledgementSuppressed('controlled application acknowledgement boundary')
        connection.close(); connection = None
        fresh = connect()
        if inspect_target(fresh, target_config) != value['target']: raise ValueError('fresh target identity changed')
        value['attempt']['read_connection_id'] = connection_identity(fresh)
        if value['attempt']['read_connection_id'] == value['attempt']['write_connection_id']:
            raise ValueError('readback reused write connection')
        with fresh.cursor() as cursor: _read_marker(cursor, namespace, marker)
        value['readback'] = _capture(fresh, candidate, namespace, 'fresh_connection_after_commit')
        value['commit_state'] = 'committed'
    except ImportError:
        value['issues'].append({'code': 'driver_not_available'})
    except Exception as exc:
        if fault_operation is not None and value['controlled_fault']['state'] == 'injected':
            value['controlled_fault']['injected_error_class'] = type(exc).__name__
        if connection is not None and not commit_attempted:
            failed_transaction = {'connection_id': value['attempt']['write_connection_id'],
                                   'statement_sha256': trace.last_statement_sha256 if trace is not None else None,
                                   'sqlstate': getattr(exc, 'sqlstate', None), 'error_class': type(exc).__name__}
            try:
                connection.rollback(); rollback_completed = True
            except Exception: pass
        value['commit_state'] = 'indeterminate' if commit_attempted else 'failed'
        if fault_operation is not None and value['controlled_fault']['state'] == 'unsupported':
            value['commit_state'] = 'indeterminate'
        code = ('controlled_application_ack_suppressed' if isinstance(exc, ControlledAcknowledgementSuppressed)
                else ('committed_readback_unavailable' if commit_acknowledged else 'commit_acknowledgement_unknown') if commit_attempted else 'failed_before_commit')
        value['issues'].append({'code': code, 'error_type': type(exc).__name__})
    finally:
        if connection is not None: connection.close()
        if fresh is not None: fresh.close()
    if value['commit_state'] == 'committed':
        value['negative_effects'] = [collect_negative_effect(candidate, authority, target_config, dsn=dsn,
                                     probe_kind=kind, execution_id=value['attempt']['execution_id']) for kind in negative_kinds]
    elif not commit_attempted and failed_transaction is not None and failed_transaction['connection_id'] is not None and failed_transaction['statement_sha256'] is not None and before is not None and connect is not None:
        value['negative_effects'] = [failed_load_effect(candidate, authority, target_config, connect,
                                     execution_id=value['attempt']['execution_id'], namespace=namespace,
                                     target=value['target'], before=before, transaction=failed_transaction,
                                     rollback_completed=rollback_completed)]
    # No target_validation=passed or producer parity flags exist in this contract.
    return validate_target_observation(seal_observation(value))


def reconcile_target_candidate(artifacts, authority, original, *, dsn=None, target_config=None, authority_verifier=None):
    """Read actual durable marker/rows after an unknown commit, never repeat the load."""
    if not isinstance(target_config, TargetConfig): raise ValueError('explicit target config required')
    authority = verified_target_authority(authority, authority_verifier)
    original = validate_target_observation(original)
    candidate = resolve_candidate(artifacts, target_config)
    verify_authority(authority, candidate, target_config, 'reconcile')
    if original['candidate'] != candidate.descriptor or original['authority_sha256'] != authority['authority_sha256'] or original['target_config_sha256'] != digest(target_config.public()) or original['observer_code_sha256'] != observer_code_pin():
        raise ValueError('reconciliation scope differs from original attempt')
    if original['commit_state'] != 'indeterminate' or original['attempt']['write_connection_id'] is None:
        raise ValueError('reconciliation requires actual unknown commit after a write connection')
    namespace = owned_namespace(original['attempt']['namespace'])
    value = _base(candidate, authority, target_config)
    if original['schema_version'] == 3:
        value.update(schema_version=3, controlled_fault=deepcopy(original['controlled_fault']))
    value['attempt'].update(execution_id=original['attempt']['execution_id'], namespace=namespace,
                            write_connection_id=original['attempt']['write_connection_id'],
                            prior_observation_sha256=original['observation_sha256'])
    value['commit_state'] = 'indeterminate'
    if not dsn:
        value['issues'].append({'code': 'dsn_not_supplied_for_reconciliation'}); return seal_observation(value)
    connection = None
    try:
        _, connect = driver_and_connect(dsn, target_config)
        connection = connect()
        value['target'] = inspect_target(connection, target_config)
        if original['target'] != value['target']: raise ValueError('recovery actual target changed')
        value['attempt']['read_connection_id'] = connection_identity(connection)
        if value['attempt']['read_connection_id'] == value['attempt']['write_connection_id']:
            raise ValueError('recovery reused original connection')
        marker = _marker(candidate, authority, target_config, value['attempt']['execution_id'])
        with connection.cursor() as cursor:
            observed_marker = _read_marker(cursor, namespace, marker)
        value['readback'] = _capture(connection, candidate, namespace, 'fresh_connection_reconciliation')
        value['recovery'] = {'prior_observation_sha256': original['observation_sha256'],
                             'marker_query_sha256': observed_marker['query_sha256'],
                             'marker_rows': observed_marker['rows'], 'marker_rows_sha256': observed_marker['rows_sha256'],
                             'read_connection_id': value['attempt']['read_connection_id']}
        value['commit_state'] = 'committed'
        controlled = original.get('controlled_fault')
        recovery_code = ('reconciled_controlled_application_ack' if controlled and controlled['operation'] == 'controlled_commit_ack' and controlled['state'] == 'injected'
                         else 'reconciled_lost_commit_acknowledgement' if any(issue['code'] == 'commit_acknowledgement_unknown' for issue in original['issues'])
                         else 'reconciled_known_commit_readback')
        value['issues'].append({'code': recovery_code})
    except ImportError:
        value['issues'].append({'code': 'driver_not_available_for_reconciliation'})
    except Exception as exc:
        value['issues'].append({'code': 'durable_commit_not_reconciled', 'error_type': type(exc).__name__})
    finally:
        if connection is not None: connection.close()
    return validate_target_observation(seal_observation(value))


def collect_controlled_failed_load(artifacts, authority, *, dsn=None, target_config=None, authority_verifier=None):
    """Signed deliberate partial insert/server error/rollback/fresh absence capture."""
    return _observe_candidate(artifacts, authority, dsn=dsn, target_config=target_config,
                               authority_verifier=authority_verifier, fault_operation='controlled_failed_load')


def collect_controlled_lost_ack(artifacts, authority, *, dsn=None, target_config=None, authority_verifier=None):
    """Actual commit then explicit application-ACK suppression and read-only recovery.

    Missing/unreached writes retain prior not_run/failed and reconciled=None.
    Nothing rewrites a completed normal observation or claims a network failure.
    """
    prior = collect_controlled_ack_predecessor(artifacts, authority, dsn=dsn, target_config=target_config,
                                                authority_verifier=authority_verifier)
    reconciled = None
    if prior['commit_state'] == 'indeterminate' and prior['attempt']['write_connection_id'] is not None:
        reconciled = reconcile_target_candidate(artifacts, authority, prior, dsn=dsn,
                                                 target_config=target_config, authority_verifier=authority_verifier)
    return {'prior': prior, 'reconciled': reconciled}


def collect_controlled_ack_predecessor(artifacts, authority, *, dsn=None, target_config=None, authority_verifier=None):
    """Actual F predecessor only, so callers can persist it before read-only recovery."""
    return _observe_candidate(artifacts, authority, dsn=dsn, target_config=target_config,
                               authority_verifier=authority_verifier, fault_operation='controlled_commit_ack')

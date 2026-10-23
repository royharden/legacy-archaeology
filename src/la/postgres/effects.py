"""Closed observation wire and actual future negative-effect query collection."""
from __future__ import annotations

import hashlib
from decimal import Decimal
import json
import re
import os
from pathlib import Path
import uuid

from la.review import canonical, digest
from .candidate import is_sha, observer_code_pin, validate_descriptor, verify_authority
from .target import StatementTrace, connection_identity, driver_and_connect, inspect_target, new_namespace, parameters

NEGATIVE_KINDS = ('rollback', 'nonnull', 'check', 'numeric_overflow', 'duplicate_identity', 'invalid_date')
EFFECT_KINDS = NEGATIVE_KINDS + ('failed_load',)
OBSERVATION_KEYS = {'schema_version', 'kind', 'candidate', 'authority_sha256', 'target_config_sha256',
                    'observer_code_sha256', 'attempt', 'target', 'commit_state', 'readback',
                    'negative_effects', 'recovery', 'issues', 'observation_sha256'}
EFFECT_KEYS = {'schema_version', 'kind', 'probe_kind', 'candidate_sha256', 'source_sha256',
               'authority_sha256', 'target_config_sha256', 'observer_code_sha256',
               'execution_id', 'attempt_id', 'namespace', 'target', 'before', 'transaction',
               'after', 'transaction_state', 'issues', 'effect_sha256'}


def seal_observation(value):
    result = json.loads(canonical(value))
    result['observation_sha256'] = digest(result)
    return result


def _issues(value):
    if not isinstance(value, list) or len(value) > 10:
        raise ValueError('bounded observation issues required')
    for issue in value:
        if not isinstance(issue, dict) or set(issue) - {'code', 'error_type'} or 'code' not in issue or any(not isinstance(item, str) or not item or len(item) > 100 for item in issue.values()):
            raise ValueError('invalid observation issue')


def _target(value):
    keys = {'database', 'role', 'host', 'port', 'server_version_num', 'authority_reference', 'scope', 'driver_version'}
    if not isinstance(value, dict) or set(value) != keys or value['host'] not in ('127.0.0.1', '::1') or type(value['port']) is not int or not 1 <= value['port'] <= 65535 or value['port'] in (20178, 20179, 55490) or type(value['server_version_num']) is not int or value['scope'] != 'disposable_local_test':
        raise ValueError('closed actual target identity required')
    if any(not isinstance(value[key], str) or not value[key] or len(value[key]) > 200 for key in ('database', 'role', 'authority_reference', 'driver_version')):
        raise ValueError('invalid target identity/version fields')


def validate_target_observation(value):
    """Structural/identity validation only, never independent target acceptance."""
    keys = OBSERVATION_KEYS | {'controlled_fault'} if isinstance(value, dict) and value.get('schema_version') == 3 else OBSERVATION_KEYS
    if not isinstance(value, dict) or set(value) != keys or type(value['schema_version']) is not int or value['schema_version'] not in (2, 3) or value['kind'] != 'target_observation':
        raise ValueError('closed v2/v3 target observation required; producer pass flags rejected')
    if digest({k: v for k, v in value.items() if k != 'observation_sha256'}) != value['observation_sha256']:
        raise ValueError('target observation hash mismatch')
    if value['commit_state'] not in ('not_run', 'committed', 'failed', 'indeterminate'):
        raise ValueError('invalid observed commit state')
    for key in ('authority_sha256', 'target_config_sha256', 'observer_code_sha256'):
        if not is_sha(value[key]): raise ValueError('missing target observation lineage pin')
    descriptor = validate_descriptor(value['candidate'])
    attempt = value['attempt']
    if not isinstance(attempt, dict) or set(attempt) != {'execution_id', 'attempt_id', 'namespace', 'write_connection_id', 'read_connection_id', 'prior_observation_sha256'} or any(not isinstance(attempt[key], str) or re.fullmatch('[0-9a-f]{32}', attempt[key]) is None for key in ('execution_id', 'attempt_id')):
        raise ValueError('closed execution/attempt identity required')
    from .target import owned_namespace
    owned_namespace(attempt['namespace'])
    if any(attempt[key] is not None and not is_sha(attempt[key]) for key in ('write_connection_id', 'read_connection_id', 'prior_observation_sha256')):
        raise ValueError('invalid connection/prior-observation pin')
    if value['target'] is not None:
        _target(value['target'])
        if value['target']['authority_reference'] != value['authority_sha256']:
            raise ValueError('actual target authority reference mismatch')
    _issues(value['issues'])
    for key in ('candidate_sha256', 'source_sha256', 'framing_sha256', 'mapping_sha256', 'config_sha256', 'producer_code_sha256'):
        if not is_sha(descriptor.get(key)): raise ValueError('candidate identity pin missing')
    if not isinstance(value['negative_effects'], list) or len(value['negative_effects']) > len(EFFECT_KINDS):
        raise ValueError('negative observation count limit')
    seen_probes, seen_attempts = set(), set()
    for effect in value['negative_effects']:
        validate_negative_effect(effect)
        if effect['probe_kind'] in seen_probes or effect['attempt_id'] in seen_attempts:
            raise ValueError('duplicate negative probe/attempt')
        seen_probes.add(effect['probe_kind']); seen_attempts.add(effect['attempt_id'])
        if effect['candidate_sha256'] != descriptor['candidate_sha256'] or effect['source_sha256'] != descriptor['source_sha256'] or effect['authority_sha256'] != value['authority_sha256'] or effect['target_config_sha256'] != value['target_config_sha256'] or effect['observer_code_sha256'] != value['observer_code_sha256'] or effect['execution_id'] != value['attempt']['execution_id'] or (effect['target'] is not None and effect['target'] != value['target']):
            raise ValueError('negative effect belongs to another candidate/authority/attempt')
    if value['readback'] is not None:
        readback = value['readback']
        if not isinstance(readback, dict) or set(readback) != {'capture', 'query_sha256', 'columns', 'rows', 'rows_sha256'} or not isinstance(readback['rows'], list) or len(readback['rows']) > 10000 or readback['rows_sha256'] != digest(readback['rows']) or not is_sha(readback['query_sha256']):
            raise ValueError('invalid readback capture')
        if value['commit_state'] != 'committed' or value['target'] is None or not is_sha(attempt['write_connection_id']) or not is_sha(attempt['read_connection_id']) or readback['capture'] not in ('fresh_connection_after_commit', 'fresh_connection_reconciliation') or attempt['write_connection_id'] == attempt['read_connection_id']:
            raise ValueError('readback is not a committed distinct-connection capture')
        if not isinstance(readback['columns'], list) or len(readback['columns']) != 8 or any(not isinstance(column, list) or len(column) != 5 for column in readback['columns']):
            raise ValueError('actual eight-column catalog metadata required')
        for row in readback['rows']:
            if not isinstance(row, dict) or set(row) != {'record_ref', 'mapping_sha256', 'outcome', 'values'} or row['mapping_sha256'] != descriptor['mapping_sha256'] or row['outcome'] != 'converted':
                raise ValueError('invalid observed row envelope')
            from la.contracts import OutcomeRef
            ref = OutcomeRef.model_validate(row['record_ref']).model_dump()
            if ref['source_sha256'] != descriptor['source_sha256'] or ref['framing_sha256'] != descriptor['framing_sha256']:
                raise ValueError('observed record belongs to another source/framing')
            if not isinstance(row['values'], dict) or set(row['values']) != {'account_ref', 'description', 'balance', 'effective_date', 'status'} or any(v is not None and not isinstance(v, str) for v in row['values'].values()):
                raise ValueError('exact string/Decimal/date/NULL wire values required')
    elif value['commit_state'] == 'committed':
        raise ValueError('committed target observation requires actual readback')
    recovery = value['recovery']
    if recovery is not None:
        keys = {'prior_observation_sha256', 'marker_query_sha256', 'marker_rows', 'marker_rows_sha256', 'read_connection_id'}
        if not isinstance(recovery, dict) or set(recovery) != keys or recovery['prior_observation_sha256'] != attempt['prior_observation_sha256'] or not is_sha(recovery['prior_observation_sha256']) or recovery['read_connection_id'] != attempt['read_connection_id'] or not is_sha(recovery['marker_query_sha256']) or not isinstance(recovery['marker_rows'], list) or recovery['marker_rows_sha256'] != digest(recovery['marker_rows']):
            raise ValueError('invalid actual durable recovery marker capture')
        if value['commit_state'] != 'committed' or value['readback']['capture'] != 'fresh_connection_reconciliation':
            raise ValueError('recovery marker cannot upgrade absent readback')
    if value['schema_version'] == 3:
        _validate_controlled_fault(value)
    return value


def _validate_controlled_fault(observation):
    value = observation['controlled_fault']
    keys = {'operation', 'boundary', 'state', 'network_loss_claimed', 'driver_commit_returned',
            'application_ack_delivered', 'trigger_statement_sha256', 'boundary_sha256',
            'injected_error_class', 'partial_write'}
    boundaries = {'controlled_failed_load': 'after_first_insert_before_commit',
                  'controlled_commit_ack': 'after_driver_commit_before_application_ack'}
    if not isinstance(value, dict) or set(value) != keys or value['operation'] not in boundaries or value['boundary'] != boundaries[value['operation']] or value['state'] not in ('not_reached', 'injected', 'unsupported'):
        raise ValueError('closed controlled boundary observation required')
    if value['network_loss_claimed'] is not False or type(value['driver_commit_returned']) is not bool or type(value['application_ack_delivered']) is not bool:
        raise ValueError('actual driver/application state required; no unobserved network claim')
    expected_boundary = digest({'operation': value['operation'], 'boundary': value['boundary'],
                                'observer_code_sha256': observation['observer_code_sha256']})
    if value['boundary_sha256'] != expected_boundary:
        raise ValueError('controlled boundary does not match pinned observer definition')
    if value['trigger_statement_sha256'] is not None and not is_sha(value['trigger_statement_sha256']):
        raise ValueError('invalid actual controlled error statement pin')
    if value['injected_error_class'] is not None and (not isinstance(value['injected_error_class'], str) or not value['injected_error_class'] or len(value['injected_error_class']) > 100):
        raise ValueError('invalid controlled error class')
    if value['application_ack_delivered']:
        raise ValueError('controlled collector cannot claim suppression of a delivered ACK')
    partial = value['partial_write']
    if partial is not None:
        if not isinstance(partial, dict) or set(partial) != {'connection_id', 'query_sha256', 'rows', 'rows_sha256'} or not is_sha(partial['connection_id']) or partial['connection_id'] != observation['attempt']['write_connection_id'] or not is_sha(partial['query_sha256']) or not isinstance(partial['rows'], list) or len(partial['rows']) > 10000 or partial['rows_sha256'] != digest(partial['rows']):
            raise ValueError('invalid actual partial-write query capture')
        for row in partial['rows']:
            if not isinstance(row, dict) or set(row) != {'source_sha256', 'ordinal', 'raw_sha256'} or row['source_sha256'] != observation['candidate']['source_sha256'] or not is_sha(row['raw_sha256']) or type(row['ordinal']) is not int or row['ordinal'] < 0:
                raise ValueError('invalid actual partial-write provenance')
    if value['state'] == 'injected':
        if observation['target'] is None or not is_sha(observation['attempt']['write_connection_id']) or observation['commit_state'] == 'not_run':
            raise ValueError('injected boundary requires an actual target/write attempt')
        if value['operation'] == 'controlled_failed_load':
            if value['driver_commit_returned'] or partial is None or len(partial['rows']) != 1 or not is_sha(value['trigger_statement_sha256']) or value['injected_error_class'] is None or observation['commit_state'] not in ('failed', 'indeterminate'):
                raise ValueError('controlled failed load requires actual partial row/error before commit')
        elif not value['driver_commit_returned'] or partial is not None or value['trigger_statement_sha256'] is not None or value['injected_error_class'] != 'ControlledAcknowledgementSuppressed' or observation['commit_state'] not in ('indeterminate', 'committed'):
            raise ValueError('controlled application ACK requires observed driver return and explicit suppression')
        elif observation['commit_state'] == 'committed' and observation['recovery'] is None:
            raise ValueError('controlled ACK loss cannot be a relabeled normal committed receipt')


def validate_negative_effect(value):
    if not isinstance(value, dict) or set(value) != EFFECT_KEYS or type(value['schema_version']) is not int or value['schema_version'] != 1 or value['kind'] != 'negative_effect' or value['probe_kind'] not in EFFECT_KINDS:
        raise ValueError('closed negative-effect capture required')
    if value['effect_sha256'] != digest({k: v for k, v in value.items() if k != 'effect_sha256'}):
        raise ValueError('negative-effect hash mismatch')
    if value['transaction_state'] not in ('not_run', 'not_applicable', 'rolled_back', 'indeterminate'):
        raise ValueError('invalid negative transaction state')
    from .target import owned_namespace
    owned_namespace(value['namespace'])
    if any(not isinstance(value[key], str) or re.fullmatch('[0-9a-f]{32}', value[key]) is None for key in ('execution_id', 'attempt_id')):
        raise ValueError('invalid negative attempt identity')
    for key in ('candidate_sha256', 'source_sha256', 'authority_sha256', 'target_config_sha256', 'observer_code_sha256'):
        if not is_sha(value[key]): raise ValueError('missing negative effect lineage pin')
    if value['target'] is not None:
        _target(value['target'])
        if value['target']['authority_reference'] != value['authority_sha256']:
            raise ValueError('negative target authority reference mismatch')
    _issues(value['issues'])
    if value['transaction'] is not None:
        transaction = value['transaction']
        if not isinstance(transaction, dict) or set(transaction) != {'connection_id', 'statement_sha256', 'sqlstate', 'error_class'} or not is_sha(transaction['connection_id']) or not is_sha(transaction['statement_sha256']) or (transaction['sqlstate'] is not None and (not isinstance(transaction['sqlstate'], str) or re.fullmatch('[0-9A-Z]{5}', transaction['sqlstate']) is None)):
            raise ValueError('actual error/statement observation required')
        if transaction['error_class'] is not None and (not isinstance(transaction['error_class'], str) or len(transaction['error_class']) > 100):
            raise ValueError('invalid captured driver error class')
    for snapshot in (value['before'], value['after']):
        if snapshot is None: continue
        keys = {'connection_id', 'query_sha256', 'namespace_exists', 'table_exists', 'rows', 'rows_sha256', 'rows_capture'}
        if not isinstance(snapshot, dict) or set(snapshot) != keys or not is_sha(snapshot['connection_id']) or not is_sha(snapshot['query_sha256']) or type(snapshot['namespace_exists']) is not bool or type(snapshot['table_exists']) is not bool or not isinstance(snapshot['rows'], list) or len(snapshot['rows']) > 10000 or snapshot['rows_sha256'] != digest(snapshot['rows']) or snapshot['rows_capture'] not in ('relation_absent', 'all_persisted_provenance_rows'):
            raise ValueError('invalid actual namespace/row snapshot')
        for row in snapshot['rows']:
            if not isinstance(row, dict) or set(row) != {'source_sha256', 'ordinal', 'raw_sha256'} or not is_sha(row['source_sha256']) or not is_sha(row['raw_sha256']) or type(row['ordinal']) is not int or row['ordinal'] < 0:
                raise ValueError('invalid actual persisted-provenance row')
    if value['transaction_state'] == 'rolled_back':
        if value['target'] is None or value['before'] is None or value['after'] is None or value['transaction'] is None:
            raise ValueError('rollback intent is not an actual before/error/after observation')
        ids = (value['before']['connection_id'], value['transaction']['connection_id'], value['after']['connection_id'])
        if len(set(ids)) != 3:
            raise ValueError('rollback requires distinct before/write/fresh-after connections')
    return value


def namespace_snapshot(connect, config, namespace):
    """Read actual catalog presence and all persisted provenance rows, never a success flag."""
    from .target import owned_namespace
    owned_namespace(namespace)
    connection = connect()
    try:
        target = inspect_target(connection, config)
        identity = connection_identity(connection)
        with connection.cursor() as cursor:
            namespace_sql = 'SELECT EXISTS(SELECT 1 FROM pg_namespace WHERE nspname=%s)'
            relation_sql = 'SELECT to_regclass(%s) IS NOT NULL'
            cursor.execute(namespace_sql, (namespace,)); namespace_exists = cursor.fetchone()[0]
            cursor.execute(relation_sql, (namespace + '.migrated_records',)); table_exists = cursor.fetchone()[0]
            rows, capture = [], 'relation_absent'
            if table_exists:
                cursor.execute('SELECT pg_get_userbyid(nspowner)=current_user FROM pg_namespace WHERE nspname=%s', (namespace,))
                if cursor.fetchone() != (True,): raise ValueError('refusing observation of foreign namespace')
                rows_sql = f'SELECT "source_sha256","ordinal","raw_sha256" FROM "{namespace}"."migrated_records" ORDER BY "ordinal" LIMIT 10001'
                cursor.execute(rows_sql)
                rows = [dict(zip(('source_sha256', 'ordinal', 'raw_sha256'), row)) for row in cursor.fetchall()]
                if len(rows) > 10000: raise ValueError('persisted negative observation row limit exceeded')
                capture = 'all_persisted_provenance_rows'
            else:
                rows_sql = None
        return target, {'connection_id': identity, 'query_sha256': digest({'namespace_sql': namespace_sql, 'relation_sql': relation_sql, 'rows_sql': rows_sql, 'namespace': namespace}),
                        'namespace_exists': namespace_exists, 'table_exists': table_exists,
                        'rows': rows, 'rows_sha256': digest(rows), 'rows_capture': capture}
    finally:
        connection.close()


def collect_negative_effect(candidate, authority, config, *, dsn, probe_kind, execution_id):
    verify_authority(authority, candidate, config, 'negative_probes')
    if probe_kind not in NEGATIVE_KINDS: raise ValueError('unknown bounded negative probe')
    namespace, connection = new_namespace(), None
    effect = {'schema_version': 1, 'kind': 'negative_effect', 'probe_kind': probe_kind,
              'candidate_sha256': candidate.descriptor['candidate_sha256'],
              'source_sha256': candidate.descriptor['source_sha256'],
              'authority_sha256': authority['authority_sha256'], 'target_config_sha256': digest(config.public()),
              'observer_code_sha256': observer_code_pin(), 'execution_id': execution_id,
              'attempt_id': uuid.uuid4().hex, 'namespace': namespace, 'target': None,
              'before': None, 'transaction': None, 'after': None, 'transaction_state': 'not_run', 'issues': []}
    if not candidate.rows:
        effect['issues'].append({'code': 'no_converted_probe_row'})
        effect['effect_sha256'] = digest(effect); return effect
    first = list(parameters(candidate.rows[:1], candidate.mapping, candidate.columns)[0])
    fields = {field['semantic_target']: field for field in candidate.mapping['fields']}
    if probe_kind == 'nonnull':
        name = next((name for name, field in fields.items() if not field['policy']['nullable']), 'ordinal')
        first[candidate.columns.index(name)] = None
    elif probe_kind == 'check':
        codes = fields['status']['policy'].get('allowed_codes')
        if codes is None:
            effect['transaction_state'] = 'not_applicable'; effect['issues'].append({'code': 'no_disclosed_status_constraint'})
            effect['effect_sha256'] = digest(effect); return effect
        invalid = '__la_invalid__'
        while invalid in codes: invalid += '_'
        first[candidate.columns.index('status')] = invalid
    elif probe_kind == 'numeric_overflow':
        policy = fields['balance']['policy']
        first[candidate.columns.index('balance')] = Decimal(10) ** (policy['precision'] - policy['scale'])
    statement = 'SELECT 1/0' if probe_kind == 'rollback' else 'SELECT CAST(%s AS date)' if probe_kind == 'invalid_date' else candidate.sql
    trace = None
    try:
        _, connect = driver_and_connect(dsn, config)
        target, before = namespace_snapshot(connect, config, namespace)
        effect.update(target=target, before=before)
        if before['namespace_exists'] or before['table_exists'] or before['rows']:
            raise ValueError('fresh negative-probe namespace already exists')
        connection = connect()
        if inspect_target(connection, config) != target: raise ValueError('probe write target identity changed')
        effect['transaction'] = {'connection_id': connection_identity(connection),
                                 'statement_sha256': None,
                                 'sqlstate': None, 'error_class': None}
        try:
            with connection.cursor() as raw_cursor:
                cursor = trace = StatementTrace(raw_cursor)
                cursor.execute(f'CREATE SCHEMA "{namespace}"')
                cursor.execute(f'SET LOCAL search_path TO "{namespace}", pg_catalog')
                cursor.execute(candidate.ddl)
                if probe_kind in ('rollback', 'invalid_date', 'duplicate_identity'):
                    cursor.execute(candidate.sql, parameters(candidate.rows[:1], candidate.mapping, candidate.columns)[0])
                    cursor.execute(statement, ('not-a-calendar-date',) if probe_kind == 'invalid_date' else tuple(first) if probe_kind == 'duplicate_identity' else None)
                else:
                    cursor.execute(candidate.sql, tuple(first))
        except Exception as exc:
            effect['transaction']['sqlstate'] = getattr(exc, 'sqlstate', None)
            effect['transaction']['error_class'] = type(exc).__name__
        finally:
            connection.rollback()
            if trace is not None and trace.last_statement_sha256 is not None:
                effect['transaction']['statement_sha256'] = trace.last_statement_sha256
            else:
                effect['transaction'] = None
                effect['issues'].append({'code': 'no_probe_statement_executed'})
        connection.close(); connection = None
        target_after, after = namespace_snapshot(connect, config, namespace)
        if target_after != target: raise ValueError('negative observer target changed')
        effect.update(after=after, transaction_state='rolled_back' if effect['transaction'] is not None else 'indeterminate')
        if effect['transaction'] is not None and effect['transaction']['sqlstate'] is None:
            effect['issues'].append({'code': 'required_server_error_not_observed'})
    except ImportError:
        effect['transaction_state'] = 'not_run'
        effect['issues'].append({'code': 'driver_not_available'})
    except Exception as exc:
        effect['transaction_state'] = 'indeterminate'
        effect['issues'].append({'code': 'negative_probe_collection_error', 'error_type': type(exc).__name__})
    finally:
        if connection is not None: connection.close()
    effect = json.loads(canonical(effect)); effect['effect_sha256'] = digest(effect)
    return effect


def failed_load_effect(candidate, authority, config, connect, *, execution_id, namespace,
                       target, before, transaction, rollback_completed):
    """Capture an actual failed load's fresh durable state, not merely rollback intent."""
    effect = {'schema_version': 1, 'kind': 'negative_effect', 'probe_kind': 'failed_load',
              'candidate_sha256': candidate.descriptor['candidate_sha256'],
              'source_sha256': candidate.descriptor['source_sha256'],
              'authority_sha256': authority['authority_sha256'], 'target_config_sha256': digest(config.public()),
              'observer_code_sha256': observer_code_pin(), 'execution_id': execution_id,
              'attempt_id': uuid.uuid4().hex, 'namespace': namespace, 'target': target,
              'before': before, 'transaction': transaction, 'after': None,
              'transaction_state': 'indeterminate', 'issues': []}
    try:
        actual_target, after = namespace_snapshot(connect, config, namespace)
        if actual_target != target: raise ValueError('failed-load observer target changed')
        effect['after'] = after
        if rollback_completed: effect['transaction_state'] = 'rolled_back'
    except Exception as exc:
        effect['issues'].append({'code': 'failed_load_state_not_observed', 'error_type': type(exc).__name__})
    effect = json.loads(canonical(effect)); effect['effect_sha256'] = digest(effect)
    return validate_negative_effect(effect)


def write_target_observation(destination, observation):
    """Publish immutable actual/missing observations, never a product acceptance receipt."""
    observation = validate_target_observation(observation)
    return _write_immutable_capture(destination, observation, 'observation_sha256')


def write_negative_effect(destination, effect):
    """Publish a standalone actual effect using the same immutable owned writer."""
    effect = validate_negative_effect(effect)
    return _write_immutable_capture(destination, effect, 'effect_sha256')


def _write_immutable_capture(destination, payload, identity_key):
    destination = Path(destination)
    if destination.is_symlink() or any((parent / 'manifest.json').is_file() for parent in destination.resolve().parents):
        raise ValueError('target observations must be outside frozen migration bundles')
    destination.parent.mkdir(parents=True, exist_ok=True)
    temporary = destination.with_name(destination.name + '.' + uuid.uuid4().hex + '.tmp')
    data = (canonical(payload) + '\n').encode()
    try:
        with temporary.open('xb') as stream:
            stream.write(data); stream.flush(); os.fsync(stream.fileno())
        os.link(temporary, destination)
    finally:
        temporary.unlink(missing_ok=True)
    return {'path': str(destination), 'sha256': hashlib.sha256(data).hexdigest(),
            identity_key: payload[identity_key]}

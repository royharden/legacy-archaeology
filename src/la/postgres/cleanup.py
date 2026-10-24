"""Explicit owned disposable namespace cleanup SOURCE; never automatic or cascading."""
from __future__ import annotations

from copy import deepcopy
import re
import uuid

from la.review import canonical, digest
from la.convert.bundle import _json as strict_json
from .authority import verified_target_authority
from .candidate import is_sha, observer_code_pin, resolve_candidate, validate_descriptor
from .effects import _issues, _target, _write_immutable_capture
from .experiment import _bounded, _child, _root, open_target_experiment
from .recovery import _archive_scope
from .runner import _capture, _marker, _read_marker
from .target import connection_identity, inspect_target, owned_namespace, StatementTrace

MAX_CLEANUP_BYTES = 16 * 1024 * 1024
BINDING_KEYS = {'original_experiment_sha256', 'original_observation_sha256', 'original_execution_id',
                'candidate_sha256', 'source_sha256', 'bundle_sha256', 'original_authority_sha256',
                'namespace', 'target_sha256', 'target_config_sha256', 'observer_code_sha256',
                'cleanup_code_sha256', 'marker_sha256'}
AUTHORITY_KEYS = BINDING_KEYS | {'schema_version', 'kind', 'authority_id', 'scope', 'operations', 'authority_sha256'}
RECEIPT_KEYS = {'schema_version', 'kind', 'cleanup_id', 'action', 'binding', 'candidate', 'expected_target',
                'cleanup_authority_sha256', 'cleanup_authority_envelope_sha256', 'prior_cleanup_sha256',
                'write_connection_id', 'observer_connection_id', 'before', 'ownership', 'after', 'transaction',
                'state', 'issues', 'target_validation', 'row_parity', 'product_acceptance', 'cleanup_sha256'}
FACT_KEYS = {'connection_id', 'target', 'namespace_exists', 'namespace', 'classes', 'types',
             'namespace_acl', 'table_acl', 'constraints', 'extra_members', 'dependencies',
             'extension_members', 'marker_rows', 'rows', 'rows_sha256', 'readback_sha256', 'query_sha256'}


def _context(experiment_path, artifacts, original_authority, *, expected_experiment_sha256,
             expected_original_observation_sha256, target_config, authority_verifier):
    if not is_sha(expected_original_observation_sha256): raise ValueError('explicit original creation observation pin required')
    snapshot = open_target_experiment(experiment_path, expected_experiment_sha256=expected_experiment_sha256)
    _archive_scope(snapshot, artifacts, original_authority, target_config, authority_verifier)
    matches = [value for value in snapshot.observations.values() if value.get('kind') == 'target_observation'
               and value['observation_sha256'] == expected_original_observation_sha256]
    if not matches or any(value != matches[0] for value in matches): raise ValueError('original observation missing/ambiguous')
    original = matches[0]
    if original['commit_state'] not in ('committed', 'indeterminate') or original['target'] is None or original['attempt']['write_connection_id'] is None:
        raise ValueError('cleanup requires an actual original write, not a proposed namespace')
    namespace = owned_namespace(original['attempt']['namespace'])
    candidate = resolve_candidate(artifacts, target_config)
    if candidate.descriptor != original['candidate']: raise ValueError('cleanup compiler/candidate identity changed')
    marker = _marker(candidate, original_authority['payload'], target_config, original['attempt']['execution_id'])
    binding = {'original_experiment_sha256': expected_experiment_sha256,
               'original_observation_sha256': expected_original_observation_sha256,
               'original_execution_id': original['attempt']['execution_id'],
               'candidate_sha256': candidate.descriptor['candidate_sha256'], 'source_sha256': candidate.descriptor['source_sha256'],
               'bundle_sha256': candidate.descriptor['candidate_sha256'] if candidate.descriptor['kind'] == 'product_bundle' else None,
               'original_authority_sha256': original['authority_sha256'], 'namespace': namespace,
               'target_sha256': digest(original['target']), 'target_config_sha256': digest(target_config.public()),
               'observer_code_sha256': original['observer_code_sha256'], 'cleanup_code_sha256': observer_code_pin(),
               'marker_sha256': digest(marker)}
    return candidate, original, marker, binding


def _authorize(authority, verifier, expected, binding, operation):
    if not is_sha(expected): raise ValueError('explicit cleanup authority pin required')
    body = verified_target_authority(authority, verifier)
    if (not isinstance(body, dict) or set(body) != AUTHORITY_KEYS or type(body['schema_version']) is not int or
            body['schema_version'] != 1 or body['kind'] != 'disposable_target_cleanup_authority' or
            body['scope'] != 'owned_disposable_namespace' or not isinstance(body['authority_id'], str) or
            not body['authority_id'].strip() or len(body['authority_id']) > 200 or
            body['authority_sha256'] != expected or digest({k: v for k, v in body.items() if k != 'authority_sha256'}) != expected or
            any(body[key] != binding[key] for key in BINDING_KEYS)):
        raise ValueError('dedicated signed cleanup authority scope mismatch')
    operations = body['operations']
    if (not isinstance(operations, list) or not operations or
            any(not isinstance(op, str) or op not in ('cleanup', 'reconcile_cleanup') for op in operations) or
            len(set(operations)) != len(operations) or operation not in operations):
        raise ValueError('cleanup operation not explicitly granted; load authority cannot substitute')


def _connection(connection, config):
    # Lazy validation only; no DSN lookup, connection factory, service or install.
    import psycopg
    from psycopg.pq import TransactionStatus
    if not isinstance(connection, psycopg.Connection) or psycopg.__version__ != config.driver_version:
        raise ValueError('explicit actual pinned psycopg connection required')
    if connection.closed or connection.autocommit or connection.info.transaction_status != TransactionStatus.IDLE:
        raise ValueError('open idle caller-owned non-autocommit connection required')


def _query(cursor, sql, parameters=None, limit=128):
    cursor.execute(sql, parameters)
    rows = cursor.fetchmany(limit + 1)
    if len(rows) > limit: raise ValueError('cleanup catalog/member bound exceeded')
    return [list(row) for row in rows]


def _facts(connection, config, candidate, namespace):
    target, identity = inspect_target(connection, config), connection_identity(connection)
    value = {'connection_id': identity, 'target': target, 'namespace_exists': False, 'namespace': [],
             'classes': [], 'types': [], 'namespace_acl': [], 'table_acl': [], 'constraints': [],
             'extra_members': [], 'dependencies': [], 'extension_members': [], 'marker_rows': None,
             'rows': [], 'rows_sha256': digest([]), 'readback_sha256': None, 'query_sha256': None}
    with connection.cursor() as raw:
        cursor = StatementTrace(raw)
        value['namespace'] = _query(cursor, 'SELECT oid::text,pg_get_userbyid(nspowner) FROM pg_namespace WHERE nspname=%s', (namespace,), 1)
        value['namespace_exists'] = bool(value['namespace'])
        if value['namespace_exists']:
            value['classes'] = _query(cursor, "SELECT c.oid::text,c.relname,c.relkind,c.relpersistence,pg_get_userbyid(c.relowner),c.reltoastrelid::text FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname=%s ORDER BY c.relname", (namespace,), 32)
            value['types'] = _query(cursor, "SELECT t.oid::text,t.typname,t.typtype,t.typrelid::text,t.typelem::text FROM pg_type t JOIN pg_namespace n ON n.oid=t.typnamespace WHERE n.nspname=%s ORDER BY t.typname", (namespace,), 16)
            value['namespace_acl'] = _query(cursor, "SELECT a.grantee::text,a.grantor::text,n.nspowner::text,a.privilege_type FROM pg_namespace n CROSS JOIN LATERAL aclexplode(COALESCE(n.nspacl,acldefault('n',n.nspowner))) a WHERE n.nspname=%s", (namespace,), 16)
            value['table_acl'] = _query(cursor, "SELECT c.relname,a.grantee::text,a.grantor::text,c.relowner::text,a.privilege_type FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace CROSS JOIN LATERAL aclexplode(COALESCE(c.relacl,acldefault('r',c.relowner))) a WHERE n.nspname=%s AND c.relkind='r'", (namespace,), 32)
            value['constraints'] = _query(cursor, "SELECT k.oid::text,c.relname,k.contype,pg_get_constraintdef(k.oid) FROM pg_constraint k JOIN pg_class c ON c.oid=k.conrelid JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname=%s ORDER BY c.relname,k.oid", (namespace,), 32)
            # Any member outside the declared tables/indexes/types, user trigger,
            # rule, column default/identity/generated expression refuses removal.
            value['extra_members'] = _query(cursor, "SELECT 'trigger',t.tgname FROM pg_trigger t JOIN pg_class c ON c.oid=t.tgrelid JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname=%s AND NOT t.tgisinternal UNION ALL SELECT 'rule',r.rulename FROM pg_rewrite r JOIN pg_class c ON c.oid=r.ev_class JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname=%s UNION ALL SELECT 'column_expression',table_name||'.'||column_name FROM information_schema.columns WHERE table_schema=%s AND (column_default IS NOT NULL OR is_identity<>'NO' OR is_generated<>'NEVER')", (namespace, namespace, namespace), 32)
            # Enumerate dependencies ONLY to this exact namespace and its objects.
            value['dependencies'] = _query(cursor, "WITH ns AS (SELECT oid FROM pg_namespace WHERE nspname=%s), roots AS (SELECT c.oid,c.reltoastrelid FROM pg_class c WHERE c.relnamespace=(SELECT oid FROM ns)), refs AS (SELECT 'pg_namespace'::regclass AS classid,oid FROM ns UNION ALL SELECT 'pg_class'::regclass,oid FROM roots UNION ALL SELECT 'pg_type'::regclass,t.oid FROM pg_type t WHERE t.typnamespace=(SELECT oid FROM ns)) SELECT d.classid::regclass::text,d.objid::text,d.objsubid,d.deptype FROM pg_depend d JOIN refs r ON r.classid=d.refclassid AND r.oid=d.refobjid ORDER BY 1,2,3,4", (namespace,), 256)
            value['extension_members'] = _query(cursor, "SELECT d.classid::regclass::text,d.objid::text FROM pg_depend d WHERE d.deptype='e' AND ((d.classid='pg_namespace'::regclass AND d.objid=(SELECT oid FROM pg_namespace WHERE nspname=%s)) OR (d.classid='pg_class'::regclass AND d.objid IN (SELECT c.oid FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname=%s)))", (namespace, namespace), 16)
            names = {row[1] for row in value['classes'] if row[2] == 'r'}
            if 'candidate_execution' in names:
                value['marker_rows'] = _query(cursor, f'SELECT execution_id,candidate_sha256,authority_sha256,payload FROM "{namespace}"."candidate_execution"', limit=2)
            if 'migrated_records' in names:
                # Reuse exact deterministic structure/typed readback implementation.
                readback = _capture(connection, candidate, namespace, 'cleanup_ownership_read')
                value['rows'] = [{key: row['record_ref'][key] for key in ('source_sha256', 'ordinal', 'raw_sha256')} for row in readback['rows']]
                value['rows_sha256'] = digest(value['rows']); value['readback_sha256'] = digest(readback)
        value['query_sha256'] = digest({'namespace': namespace, 'catalog': value['classes'], 'last_statement_sha256': cursor.last_statement_sha256})
    return value


def _ownership(connection, config, candidate, namespace, marker, facts):
    if not facts['namespace_exists'] or facts['namespace'][0][1] != config.role:
        raise ValueError('owned original namespace absent or wrong owner')
    expected = {'candidate_execution': 'r', 'candidate_execution_pkey': 'i',
                'migrated_records': 'r', 'migrated_records_pkey': 'i'}
    classes = facts['classes']
    if {row[1]: row[2] for row in classes} != expected or len(classes) != 4 or any(row[3] != 'p' or row[4] != config.role for row in classes):
        raise ValueError('unexpected namespace objects/owners/persistence')
    if facts['extra_members'] or facts['extension_members']:
        raise ValueError('unexpected table members or extension ownership')
    if any(row[0] != row[2] or row[1] != row[2] for row in facts['namespace_acl']) or any(row[1] != row[3] or row[2] != row[3] for row in facts['table_acl']):
        raise ValueError('shared namespace/table ACL refuses cleanup')
    if {row[1] for row in facts['types']} != {'candidate_execution', '_candidate_execution', 'migrated_records', '_migrated_records'}:
        raise ValueError('unexpected namespace types')
    class_ids = {row[1]: row[0] for row in classes}
    types = {row[1]: row for row in facts['types']}
    for name in ('candidate_execution', 'migrated_records'):
        if types[name][2:5] != ['c', class_ids[name], '0'] or types['_' + name][2:5] != ['b', '0', types[name][0]]:
            raise ValueError('unexpected composite/array type ownership')
    constraints = facts['constraints']
    if any(row[1] not in ('candidate_execution', 'migrated_records') or row[2] not in ('p', 'c', 'n') for row in constraints):
        raise ValueError('unexpected foreign/exclusion constraint')
    if [row[2] for row in constraints if row[1] == 'candidate_execution' and row[2] != 'n'] != ['p']:
        raise ValueError('unexpected execution marker constraints')
    with connection.cursor() as raw:
        cursor = StatementTrace(raw)
        columns = _query(cursor, 'SELECT column_name,data_type,is_nullable FROM information_schema.columns WHERE table_schema=%s AND table_name=%s ORDER BY ordinal_position', (namespace, 'candidate_execution'), 8)
        if columns != [[name, 'text', 'NO'] for name in ('execution_id', 'candidate_sha256', 'authority_sha256', 'payload')]:
            raise ValueError('unexpected marker columns')
        _read_marker(cursor, namespace, marker)
        # Only these automatically owned TOAST relations may be outside namespace.
        toast = [int(row[5]) for row in classes if row[2] == 'r' and row[5] != '0']
        toast_objects = _query(cursor, "SELECT c.oid::text FROM pg_class c WHERE c.oid=ANY(%s::oid[]) OR c.oid IN (SELECT indexrelid FROM pg_index WHERE indrelid=ANY(%s::oid[]))", (toast, toast), 8)
    allowed = {'pg_class': set(class_ids.values()) | {row[0] for row in toast_objects},
               'pg_type': {row[0] for row in facts['types']}, 'pg_constraint': {row[0] for row in constraints}}
    if any(row[0] not in allowed or row[1] not in allowed[row[0]] for row in facts['dependencies']):
        raise ValueError('external/unknown dependency on owned namespace objects')
    refs = [{key: row['record_ref'][key] for key in ('source_sha256', 'ordinal', 'raw_sha256')} for row in candidate.rows]
    if facts['rows'] != refs or facts['marker_rows'] != [[marker['execution_id'], candidate.descriptor['candidate_sha256'], marker['authority_sha256'], canonical(marker)]]:
        raise ValueError('durable original marker/provenance mismatch')


def _base(candidate, original, binding, authority, action, prior=None):
    return {'schema_version': 1, 'kind': 'target_cleanup', 'cleanup_id': uuid.uuid4().hex,
            'action': action, 'binding': binding, 'candidate': candidate.descriptor, 'expected_target': original['target'],
            'cleanup_authority_sha256': authority['payload']['authority_sha256'],
            'cleanup_authority_envelope_sha256': digest(authority), 'prior_cleanup_sha256': prior,
            'write_connection_id': None, 'observer_connection_id': None, 'before': None, 'ownership': None, 'after': None,
            'transaction': {'statements': [], 'commit_attempted': False, 'commit_returned': False,
                            'rollback_returned': False, 'sqlstate': None, 'error_class': None},
            'state': 'not_run', 'issues': [], 'target_validation': 'not_run', 'row_parity': 'not_run', 'product_acceptance': 'pending'}


def _publish(root, value):
    value = deepcopy(value); value['cleanup_sha256'] = digest(value)
    validate_target_cleanup(value)
    if len((canonical(value) + '\n').encode()) > MAX_CLEANUP_BYTES: raise ValueError('cleanup receipt byte bound')
    _write_immutable_capture(_child(root, 'cleanup-' + value['cleanup_sha256'] + '.json'), value, 'cleanup_sha256')
    return value


def _commit_cleanup(connection):
    connection.commit()


def cleanup_target_namespace(experiment_path, artifacts, original_authority, cleanup_authority, *,
        expected_experiment_sha256, expected_original_observation_sha256, expected_cleanup_authority_sha256,
        target_config, authority_verifier, cleanup_verifier, connection, observer_connection, receipt_root):
    """Remove only an exactly proven owned schema; explicit caller connections, no CASCADE."""
    root = _root(receipt_root)
    candidate, original, marker, binding = _context(experiment_path, artifacts, original_authority,
        expected_experiment_sha256=expected_experiment_sha256,
        expected_original_observation_sha256=expected_original_observation_sha256,
        target_config=target_config, authority_verifier=authority_verifier)
    _authorize(cleanup_authority, cleanup_verifier, expected_cleanup_authority_sha256, binding, 'cleanup')
    value = _base(candidate, original, binding, cleanup_authority, 'cleanup')
    write_owned = observer_owned = False
    try:
        _connection(connection, target_config); _connection(observer_connection, target_config)
        # Once idle has been established these are our own transactions to end.
        write_owned = observer_owned = True
        value['write_connection_id'] = connection_identity(connection)
        value['observer_connection_id'] = connection_identity(observer_connection)
        if value['write_connection_id'] == value['observer_connection_id']: raise ValueError('distinct actual observer connection required')
        value['before'] = _facts(observer_connection, target_config, candidate, binding['namespace'])
        observer_connection.rollback()
        if value['before']['target'] != original['target']: raise ValueError('actual cleanup target changed')
        if inspect_target(connection, target_config) != original['target']: raise ValueError('actual write target changed')
        namespace = binding['namespace']
        with connection.cursor() as cursor:
            cursor.execute(f'LOCK TABLE "{namespace}"."candidate_execution", "{namespace}"."migrated_records" IN ACCESS EXCLUSIVE MODE')
        value['ownership'] = _facts(connection, target_config, candidate, namespace)
        _ownership(connection, target_config, candidate, namespace, marker, value['ownership'])
        if any(value['before'][key] != value['ownership'][key] for key in ('namespace', 'classes', 'types', 'marker_rows', 'rows')):
            raise ValueError('namespace changed between observer and locked ownership check')
        value['state'] = 'prepared'
        intent = _publish(root, value)  # Durable uncertainty anchor BEFORE destructive SQL.
        value['prior_cleanup_sha256'] = intent['cleanup_sha256']
        with connection.cursor() as raw:
            cursor = StatementTrace(raw)
            for sql in (f'DROP TABLE "{namespace}"."candidate_execution"', f'DROP TABLE "{namespace}"."migrated_records"', f'DROP SCHEMA "{namespace}"'):
                try: cursor.execute(sql)
                finally: value['transaction']['statements'].append(cursor.last_statement_sha256)
        value['transaction']['commit_attempted'] = True
        _commit_cleanup(connection)
        value['transaction']['commit_returned'] = True
        value['state'] = 'committed'
    except Exception as exc:
        value['transaction'].update(sqlstate=getattr(exc, 'sqlstate', None), error_class=type(exc).__name__)
        value['state'] = 'indeterminate' if value['transaction']['commit_attempted'] else 'rolled_back' if value['transaction']['statements'] else 'refused'
        value['issues'].append({'code': 'cleanup_not_confirmed', 'error_type': type(exc).__name__})
    finally:
        if write_owned:
            try:
                connection.rollback()
                if not value['transaction']['commit_attempted']: value['transaction']['rollback_returned'] = True
            except Exception:
                if value['transaction']['statements']: value['state'] = 'indeterminate'
        if observer_owned:
            try:
                observer_connection.rollback()
                value['after'] = _facts(observer_connection, target_config, candidate, binding['namespace'])
                if value['after']['target'] != original['target']: raise ValueError('actual post-cleanup target changed')
                if value['state'] == 'committed' and value['after']['namespace_exists']: value['state'] = 'indeterminate'
            except Exception as exc:
                value['after'] = None
                value['issues'].append({'code': 'cleanup_after_unobserved', 'error_type': type(exc).__name__})
                if value['transaction']['statements']: value['state'] = 'indeterminate'
            finally:
                try: observer_connection.rollback()
                except Exception: pass
    return _publish(root, value)


def validate_target_cleanup(value):
    if (not isinstance(value, dict) or set(value) != RECEIPT_KEYS or type(value['schema_version']) is not int or
            value['schema_version'] != 1 or value['kind'] != 'target_cleanup' or
            value['cleanup_sha256'] != digest({k: v for k, v in value.items() if k != 'cleanup_sha256'})):
        raise ValueError('closed pinned cleanup receipt required')
    if not isinstance(value['cleanup_id'], str) or re.fullmatch('[0-9a-f]{32}', value['cleanup_id']) is None:
        raise ValueError('cleanup attempt identity required')
    binding = value['binding']
    if not isinstance(binding, dict) or set(binding) != BINDING_KEYS: raise ValueError('closed cleanup binding required')
    for key in BINDING_KEYS - {'namespace', 'original_execution_id', 'bundle_sha256'}:
        if not is_sha(binding[key]): raise ValueError('cleanup binding pin required')
    owned_namespace(binding['namespace'])
    if not isinstance(binding['original_execution_id'], str) or re.fullmatch('[0-9a-f]{32}', binding['original_execution_id']) is None:
        raise ValueError('original execution identity required')
    descriptor = validate_descriptor(value['candidate'])
    if (descriptor['candidate_sha256'] != binding['candidate_sha256'] or descriptor['source_sha256'] != binding['source_sha256'] or
            binding['bundle_sha256'] != (descriptor['candidate_sha256'] if descriptor['kind'] == 'product_bundle' else None)):
        raise ValueError('cleanup candidate/source/bundle mismatch')
    _target(value['expected_target'])
    if digest(value['expected_target']) != binding['target_sha256']: raise ValueError('cleanup target pin mismatch')
    for key in ('cleanup_authority_sha256', 'cleanup_authority_envelope_sha256'):
        if not is_sha(value[key]): raise ValueError('cleanup authority pin required')
    for key in ('prior_cleanup_sha256', 'write_connection_id', 'observer_connection_id'):
        if value[key] is not None and not is_sha(value[key]): raise ValueError('cleanup lineage/connection pin malformed')
    if value['action'] not in ('cleanup', 'reconcile_cleanup') or value['state'] not in ('not_run', 'refused', 'prepared', 'committed', 'rolled_back', 'indeterminate', 'observed_absent', 'observed_present'):
        raise ValueError('unknown cleanup action/state')
    if value['target_validation'] != 'not_run' or value['row_parity'] != 'not_run' or value['product_acceptance'] != 'pending':
        raise ValueError('cleanup never grants target/parity/product acceptance')
    _issues(value['issues'])
    transaction = value['transaction']
    if (not isinstance(transaction, dict) or set(transaction) != {'statements', 'commit_attempted', 'commit_returned', 'rollback_returned', 'sqlstate', 'error_class'} or
            any(type(transaction[key]) is not bool for key in ('commit_attempted', 'commit_returned', 'rollback_returned')) or
            not isinstance(transaction['statements'], list) or len(transaction['statements']) > 3 or any(not is_sha(item) for item in transaction['statements'])):
        raise ValueError('closed cleanup transaction facts required')
    if transaction['commit_returned'] and not transaction['commit_attempted']: raise ValueError('commit return without attempted commit')
    if transaction['sqlstate'] is not None and (not isinstance(transaction['sqlstate'], str) or re.fullmatch('[0-9A-Z]{5}', transaction['sqlstate']) is None):
        raise ValueError('invalid actual cleanup SQLSTATE')
    if transaction['error_class'] is not None and (not isinstance(transaction['error_class'], str) or len(transaction['error_class']) > 100):
        raise ValueError('invalid cleanup error class')
    for key in ('before', 'ownership', 'after'):
        facts = value[key]
        if facts is None: continue
        if not isinstance(facts, dict) or set(facts) != FACT_KEYS or type(facts['namespace_exists']) is not bool:
            raise ValueError('closed actual cleanup snapshot required')
        _target(facts['target'])
        if facts['target'] != value['expected_target'] or not is_sha(facts['connection_id']) or not is_sha(facts['query_sha256']):
            raise ValueError('cleanup snapshot target/connection/query mismatch')
        for name, limit in (('namespace', 1), ('classes', 32), ('types', 16), ('namespace_acl', 16), ('table_acl', 32), ('constraints', 32), ('extra_members', 32), ('dependencies', 256), ('extension_members', 16), ('rows', 10000)):
            if not isinstance(facts[name], list) or len(facts[name]) > limit: raise ValueError('cleanup snapshot member bound')
        if facts['rows_sha256'] != digest(facts['rows']): raise ValueError('cleanup provenance row hash mismatch')
        if facts['marker_rows'] is not None and (not isinstance(facts['marker_rows'], list) or len(facts['marker_rows']) > 2): raise ValueError('cleanup marker row bound')
    if transaction['statements'] or value['state'] in ('prepared', 'committed'):
        if value['before'] is None or value['ownership'] is None or value['write_connection_id'] is None or value['observer_connection_id'] is None or value['write_connection_id'] == value['observer_connection_id']:
            raise ValueError('destructive cleanup requires actual distinct owned preflight captures')
    if value['state'] == 'committed' and (not transaction['commit_returned'] or len(transaction['statements']) != 3 or value['after'] is None or value['after']['namespace_exists']):
        raise ValueError('committed cleanup requires actual return and observed absence')
    if value['action'] == 'reconcile_cleanup' and (transaction['statements'] or transaction['commit_attempted'] or value['prior_cleanup_sha256'] is None):
        raise ValueError('cleanup reconciliation must be read-only and linked')
    return deepcopy(value)


def open_target_cleanup(receipt_path, *, expected_cleanup_sha256):
    if not is_sha(expected_cleanup_sha256): raise ValueError('external cleanup receipt pin required')
    from pathlib import Path
    path = Path(receipt_path)
    root = _root(path.parent)
    if path.name != 'cleanup-' + expected_cleanup_sha256 + '.json': raise ValueError('canonical cleanup receipt identity path required')
    raw = _bounded(_child(root, path.name, exists=True), MAX_CLEANUP_BYTES)
    value = validate_target_cleanup(strict_json(raw, path.name))
    if value['cleanup_sha256'] != expected_cleanup_sha256 or raw != (canonical(value) + '\n').encode():
        raise ValueError('cleanup external/canonical byte pin mismatch')
    return value


def reconcile_target_cleanup(experiment_path, artifacts, original_authority, cleanup_authority, *,
        expected_experiment_sha256, expected_original_observation_sha256, expected_cleanup_authority_sha256,
        cleanup_receipt_path, expected_cleanup_sha256, target_config, authority_verifier, cleanup_verifier,
        observer_connection, receipt_root):
    """Observe one exact prior cleanup without reissuing any deletion or load."""
    root = _root(receipt_root)
    candidate, original, marker, binding = _context(experiment_path, artifacts, original_authority,
        expected_experiment_sha256=expected_experiment_sha256,
        expected_original_observation_sha256=expected_original_observation_sha256,
        target_config=target_config, authority_verifier=authority_verifier)
    _authorize(cleanup_authority, cleanup_verifier, expected_cleanup_authority_sha256, binding, 'reconcile_cleanup')
    prior = open_target_cleanup(cleanup_receipt_path, expected_cleanup_sha256=expected_cleanup_sha256)
    if prior['binding'] != binding or prior['cleanup_authority_sha256'] != expected_cleanup_authority_sha256 or prior['cleanup_authority_envelope_sha256'] != digest(cleanup_authority):
        raise ValueError('cleanup reconciliation original/authority scope mismatch')
    value = _base(candidate, original, binding, cleanup_authority, 'reconcile_cleanup', expected_cleanup_sha256)
    owned = False
    try:
        _connection(observer_connection, target_config); owned = True
        value['observer_connection_id'] = connection_identity(observer_connection)
        value['after'] = _facts(observer_connection, target_config, candidate, binding['namespace'])
        if value['after']['target'] != original['target']: raise ValueError('actual reconciliation target changed')
        value['state'] = 'observed_present' if value['after']['namespace_exists'] else 'observed_absent'
        if value['after']['namespace_exists']:
            _ownership(observer_connection, target_config, candidate, binding['namespace'], marker, value['after'])
    except Exception as exc:
        value['state'] = 'indeterminate'
        value['issues'].append({'code': 'cleanup_reconciliation_unresolved', 'error_type': type(exc).__name__})
        if value['after'] is not None and value['after']['target'] != original['target']: value['after'] = None
    finally:
        if owned:
            try: observer_connection.rollback()
            except Exception: pass
    return _publish(root, value)

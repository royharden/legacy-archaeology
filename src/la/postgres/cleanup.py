"""Explicit owned disposable namespace cleanup SOURCE; never automatic or cascading.

Every transaction this module opens is explicitly READ COMMITTED; observer and
reconciliation transactions are server-enforced READ ONLY. Unknown catalog
members, dependencies, ACLs or keys refuse removal instead of being assumed safe.
"""
from __future__ import annotations

from copy import deepcopy
from pathlib import Path
import re
import uuid

from la.review import canonical, digest
from la.convert.bundle import _json as strict_json
from .authority import verified_target_authority
from .candidate import is_sha, observer_code_pin, resolve_candidate, validate_descriptor
from .effects import _issues, _target, _write_immutable_capture
from .experiment import _bounded, _child, _root, open_target_experiment
from .recovery import _archive_scope
from .runner import _capture, _marker
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
TRANSACTION_KEYS = {'statements', 'commit_attempted', 'commit_returned', 'rollback_returned', 'sqlstate', 'error_class'}
# Catalog member name -> (server bound, exact tuple arity).
MEMBERS = {'namespace': (1, 2), 'classes': (32, 6), 'types': (16, 5), 'namespace_acl': (16, 4),
           'table_acl': (64, 5), 'default_acls': (8, 3), 'constraints': (48, 6), 'extra_members': (32, 2),
           'inheritance': (8, 2), 'dependencies': (256, 4), 'outgoing': (32, 5), 'extension_members': (16, 2)}
FACT_KEYS = set(MEMBERS) | {'connection_id', 'target', 'inspected', 'isolation', 'read_only', 'namespace_exists',
                            'marker_rows', 'rows', 'rows_sha256', 'readback_sha256', 'query_sha256'}
ROW_KEYS = ('source_sha256', 'ordinal', 'raw_sha256')
EXPECTED_CLASSES = {'candidate_execution': 'r', 'candidate_execution_pkey': 'i',
                    'migrated_records': 'r', 'migrated_records_pkey': 'i'}
# Exact server-rendered keys created by runner/convert DDL; anything else refuses.
EXPECTED_KEYS = {'candidate_execution': 'PRIMARY KEY (execution_id)',
                 'migrated_records': 'PRIMARY KEY (source_sha256, ordinal)'}
CLEANUP_STATES = ('refused', 'prepared', 'rolled_back', 'committed', 'indeterminate')
RECONCILE_STATES = ('observed_absent', 'observed_present', 'indeterminate')
TARGET_MISMATCH = 'cleanup_target_mismatch'


class _TargetRefusal(ValueError):
    """Actual target differs from (or could not be verified as) the original; refuse neutrally."""


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


def cleanup_binding(experiment_path, artifacts, original_authority, *, expected_experiment_sha256,
                    expected_original_observation_sha256, target_config, authority_verifier):
    """Offline: the exact binding a cleanup authority must sign. No connection, no authority created."""
    return deepcopy(_context(experiment_path, artifacts, original_authority,
        expected_experiment_sha256=expected_experiment_sha256,
        expected_original_observation_sha256=expected_original_observation_sha256,
        target_config=target_config, authority_verifier=authority_verifier)[3])


def authorize_cleanup(authority, verifier, expected_cleanup_authority_sha256, binding, operation):
    """Offline: full dedicated-authority check against an exact binding (signature, scope, keys, pins)."""
    _authorize(authority, verifier, expected_cleanup_authority_sha256, binding, operation)


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


def _begin(connection, *, read_only):
    """Own a fresh explicit READ COMMITTED transaction before any identity/catalog read.

    psycopg opens the transaction implicitly on the first statement, so SET
    TRANSACTION is that first statement; caller isolation/read-only defaults
    are overridden and then verified from the server, never inherited.
    """
    from psycopg.pq import TransactionStatus
    if connection.info.transaction_status != TransactionStatus.IDLE:
        raise ValueError('cleanup transaction must start from an idle connection')
    mode = 'READ ONLY' if read_only else 'READ WRITE'
    with connection.cursor() as cursor:
        cursor.execute(f'SET TRANSACTION ISOLATION LEVEL READ COMMITTED, {mode}')
        cursor.execute("SELECT current_setting('transaction_isolation'),current_setting('transaction_read_only')")
        if tuple(cursor.fetchone()) != ('read committed', 'on' if read_only else 'off'):
            raise ValueError('owned READ COMMITTED transaction not established')


def _query(cursor, sql, parameters=None, limit=128):
    # Server-side LIMIT plus client fetch bound; one extra row proves overflow.
    if type(limit) is not int or not 1 <= limit <= 10000: raise ValueError('invalid cleanup query bound')
    cursor.execute(f'{sql} LIMIT {limit + 1}', parameters)
    rows = cursor.fetchmany(limit + 1)
    if len(rows) > limit: raise ValueError('cleanup catalog/member bound exceeded')
    return [list(row) for row in rows]


def _observed_target(connection, config):
    """Return (target, verified). Mismatched identity is preserved as a fact, not raised."""
    try:
        return inspect_target(connection, config), True
    except ValueError:
        # inspect_target raised on a Python-side comparison, so the owned transaction
        # (and any writer lock) is still intact; never roll back here.
        with connection.cursor() as cursor:
            cursor.execute("SELECT current_database(), current_user, host(inet_server_addr()), inet_server_port(), current_setting('server_version_num')::int")
            database, role, host, port, version = cursor.fetchone()
        raw = {'database': database, 'role': role, 'host': host, 'port': port, 'server_version_num': version,
               'authority_reference': config.authority_reference, 'scope': config.scope, 'driver_version': config.driver_version}
        if config.server_host is not None:
            raw.update(connection_host=config.host, connection_port=config.port)
        try:
            _target(raw)
        except ValueError:
            # Unrepresentable identity (socket/null host): still a target refusal, without facts.
            raise _TargetRefusal('actual target identity cannot be represented or verified') from None
        return raw, False


def _empty_facts(identity, target, verified, read_only):
    value = {name: [] for name in MEMBERS}
    value.update(connection_id=identity, target=target, inspected=verified, isolation='read committed',
                 read_only=read_only, namespace_exists=False, marker_rows=None, rows=[], rows_sha256=digest([]),
                 readback_sha256=None, query_sha256=None)
    return value


def _facts(connection, config, candidate, namespace, *, read_only):
    """Bounded catalog facts inside the caller-established owned transaction."""
    identity = connection_identity(connection)
    with connection.cursor() as cursor:
        cursor.execute("SELECT current_setting('transaction_isolation'),current_setting('transaction_read_only')")
        if tuple(cursor.fetchone()) != ('read committed', 'on' if read_only else 'off'):
            raise ValueError('cleanup facts outside an owned READ COMMITTED transaction')
    target, verified = _observed_target(connection, config)
    value = _empty_facts(identity, target, verified, read_only)
    if not verified:
        value['query_sha256'] = digest({'namespace': namespace, 'inspected': False})
        return value
    with connection.cursor() as raw:
        cursor = StatementTrace(raw)
        q = lambda name, sql, params: _query(cursor, sql, params, MEMBERS[name][0])
        value['namespace'] = q('namespace', 'SELECT oid::text,pg_get_userbyid(nspowner) FROM pg_namespace WHERE nspname=%s', (namespace,))
        value['namespace_exists'] = bool(value['namespace'])
        if value['namespace_exists']:
            ns = (namespace,)
            value['classes'] = q('classes', "SELECT c.oid::text,c.relname,c.relkind::text,c.relpersistence::text,pg_get_userbyid(c.relowner),c.reltoastrelid::text FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname=%s ORDER BY c.relname", ns)
            value['types'] = q('types', "SELECT t.oid::text,t.typname,t.typtype::text,t.typrelid::text,t.typelem::text FROM pg_type t JOIN pg_namespace n ON n.oid=t.typnamespace WHERE n.nspname=%s ORDER BY t.typname", ns)
            value['namespace_acl'] = q('namespace_acl', "SELECT a.grantee::text,a.grantor::text,n.nspowner::text,a.privilege_type FROM pg_namespace n CROSS JOIN LATERAL aclexplode(COALESCE(n.nspacl,acldefault('n',n.nspowner))) a WHERE n.nspname=%s ORDER BY 1,2,4", ns)
            value['table_acl'] = q('table_acl', "SELECT c.relname,a.grantee::text,a.grantor::text,c.relowner::text,a.privilege_type FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace CROSS JOIN LATERAL aclexplode(COALESCE(c.relacl,acldefault('r',c.relowner))) a WHERE n.nspname=%s AND c.relkind='r' ORDER BY 1,2,3,5", ns)
            # Schema-scoped default privileges would silently grant future objects; refuse any.
            value['default_acls'] = q('default_acls', "SELECT d.oid::text,pg_get_userbyid(d.defaclrole),d.defaclobjtype::text FROM pg_default_acl d JOIN pg_namespace n ON n.oid=d.defaclnamespace WHERE n.nspname=%s ORDER BY 1", ns)
            value['constraints'] = q('constraints', "SELECT k.oid::text,c.relname,k.contype::text,k.conname,k.conindid::text,pg_get_constraintdef(k.oid) FROM pg_constraint k JOIN pg_class c ON c.oid=k.conrelid JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname=%s ORDER BY c.relname,k.conname,k.oid", ns)
            # Any member outside the declared tables/indexes/types, user trigger,
            # rule, column default/identity/generated expression refuses removal.
            value['extra_members'] = q('extra_members', "SELECT * FROM (SELECT 'trigger' AS kind,t.tgname::text AS name FROM pg_trigger t JOIN pg_class c ON c.oid=t.tgrelid JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname=%s AND NOT t.tgisinternal UNION ALL SELECT 'rule',r.rulename::text FROM pg_rewrite r JOIN pg_class c ON c.oid=r.ev_class JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname=%s UNION ALL SELECT 'column_expression',(table_name||'.'||column_name)::text FROM information_schema.columns WHERE table_schema=%s AND (column_default IS NOT NULL OR is_identity<>'NO' OR is_generated<>'NEVER')) m ORDER BY 1,2", (namespace, namespace, namespace))
            # Inheritance/partition links in either direction would change an object outside the namespace.
            value['inheritance'] = q('inheritance', "SELECT i.inhrelid::text,i.inhparent::text FROM pg_inherits i WHERE i.inhrelid IN (SELECT c.oid FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname=%s) OR i.inhparent IN (SELECT c.oid FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname=%s) ORDER BY 1,2", (namespace, namespace))
            # Incoming: every object depending on this exact namespace, its classes or types.
            value['dependencies'] = q('dependencies', "WITH ns AS (SELECT oid FROM pg_namespace WHERE nspname=%s), refs AS (SELECT 'pg_namespace'::regclass::oid AS classid,oid FROM ns UNION ALL SELECT 'pg_class'::regclass::oid,c.oid FROM pg_class c WHERE c.relnamespace=(SELECT oid FROM ns) UNION ALL SELECT 'pg_type'::regclass::oid,t.oid FROM pg_type t WHERE t.typnamespace=(SELECT oid FROM ns)) SELECT d.classid::regclass::text,d.objid::text,d.objsubid,d.deptype::text FROM pg_depend d JOIN refs r ON r.classid=d.refclassid AND r.oid=d.refobjid ORDER BY 1,2,3,4", ns)
            # Outgoing: our objects depending on anything outside our own set (typed
            # tables, external types/collations, extension membership). Built-in
            # pinned catalog objects record no pg_depend rows.
            value['outgoing'] = q('outgoing', "WITH ns AS (SELECT oid FROM pg_namespace WHERE nspname=%s), cls AS (SELECT oid FROM pg_class WHERE relnamespace=(SELECT oid FROM ns)), objs AS (SELECT 'pg_namespace'::regclass::oid AS classid,oid FROM ns UNION ALL SELECT 'pg_class'::regclass::oid,oid FROM cls UNION ALL SELECT 'pg_type'::regclass::oid,oid FROM pg_type WHERE typnamespace=(SELECT oid FROM ns) UNION ALL SELECT 'pg_constraint'::regclass::oid,oid FROM pg_constraint WHERE conrelid IN (SELECT oid FROM cls) OR connamespace=(SELECT oid FROM ns)) SELECT d.classid::regclass::text,d.objid::text,d.refclassid::regclass::text,d.refobjid::text,d.deptype::text FROM pg_depend d JOIN objs o ON o.classid=d.classid AND o.oid=d.objid WHERE d.deptype<>'p' AND NOT EXISTS (SELECT 1 FROM objs r WHERE r.classid=d.refclassid AND r.oid=d.refobjid) ORDER BY 1,2,3,4", ns)
            value['extension_members'] = q('extension_members', "SELECT d.classid::regclass::text,d.objid::text FROM pg_depend d WHERE d.deptype='e' AND ((d.classid='pg_namespace'::regclass AND d.objid=(SELECT oid FROM pg_namespace WHERE nspname=%s)) OR (d.classid='pg_class'::regclass AND d.objid IN (SELECT c.oid FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname=%s))) ORDER BY 1,2", (namespace, namespace))
            names = {row[1] for row in value['classes'] if row[2] == 'r'}
            if 'candidate_execution' in names:
                value['marker_rows'] = _query(cursor, f'SELECT execution_id,candidate_sha256,authority_sha256,payload FROM "{namespace}"."candidate_execution" ORDER BY execution_id', limit=2)
            if 'migrated_records' in names:
                # Reuse exact deterministic structure/typed readback implementation (server LIMIT 10001).
                readback = _capture(connection, candidate, namespace, 'cleanup_ownership_read')
                value['rows'] = [{key: row['record_ref'][key] for key in ROW_KEYS} for row in readback['rows']]
                value['rows_sha256'] = digest(value['rows']); value['readback_sha256'] = digest(readback)
        value['query_sha256'] = digest({'namespace': namespace, 'catalog': value['classes'], 'last_statement_sha256': cursor.last_statement_sha256})
    return value


def _ownership(connection, config, candidate, namespace, marker, facts):
    """Prove the namespace holds exactly what the original run created, owned by the role."""
    if not facts['inspected'] or not facts['namespace_exists'] or facts['namespace'][0][1] != config.role:
        raise ValueError('owned original namespace absent or wrong owner')
    classes = facts['classes']
    if {row[1]: row[2] for row in classes} != EXPECTED_CLASSES or len(classes) != 4 or any(row[3] != 'p' or row[4] != config.role for row in classes):
        raise ValueError('unexpected namespace objects/owners/persistence')
    if facts['extra_members'] or facts['extension_members'] or facts['default_acls'] or facts['inheritance'] or facts['outgoing']:
        raise ValueError('unexpected members, default ACLs, inheritance, extension or external dependencies')
    if any(row[0] != row[2] or row[1] != row[2] for row in facts['namespace_acl']) or any(row[1] != row[3] or row[2] != row[3] for row in facts['table_acl']):
        raise ValueError('shared namespace/table ACL refuses cleanup')
    if {row[1] for row in facts['types']} != {'candidate_execution', '_candidate_execution', 'migrated_records', '_migrated_records'} or len(facts['types']) != 4:
        raise ValueError('unexpected namespace types')
    class_ids = {row[1]: row[0] for row in classes}
    types = {row[1]: row for row in facts['types']}
    for name in ('candidate_execution', 'migrated_records'):
        # Composite row type owned by the table; array type whose element is that composite.
        if types[name][2:5] != ['c', class_ids[name], '0'] or types['_' + name][2:5] != ['b', '0', types[name][0]]:
            raise ValueError('unexpected composite/array type ownership')
    constraints = facts['constraints']
    if any(row[1] not in EXPECTED_KEYS or row[2] not in ('p', 'c', 'n') for row in constraints):
        raise ValueError('unexpected foreign/exclusion/unique/trigger constraint')
    if [row[2] for row in constraints if row[1] == 'candidate_execution' and row[2] != 'n'] != ['p']:
        raise ValueError('unexpected execution marker constraints')
    keys = sorted([row[1], row[3], row[4], row[5]] for row in constraints if row[2] == 'p')
    if keys != [[table, table + '_pkey', class_ids[table + '_pkey'], definition] for table, definition in sorted(EXPECTED_KEYS.items())]:
        raise ValueError('exact primary-key column/index definition mismatch')
    with connection.cursor() as raw:
        cursor = StatementTrace(raw)
        columns = _query(cursor, 'SELECT column_name::text,data_type::text,is_nullable::text FROM information_schema.columns WHERE table_schema=%s AND table_name=%s ORDER BY ordinal_position', (namespace, 'candidate_execution'), 8)
        if columns != [[name, 'text', 'NO'] for name in ('execution_id', 'candidate_sha256', 'authority_sha256', 'payload')]:
            raise ValueError('unexpected marker columns')
        # Only these automatically owned TOAST relations (and their indexes) may live outside the namespace.
        toast = [int(row[5]) for row in classes if row[2] == 'r' and row[5] != '0']
        toast_objects = _query(cursor, "SELECT c.oid::text,c.relkind::text FROM pg_class c WHERE (c.relkind='t' AND c.oid=ANY(%s::oid[])) OR (c.relkind='i' AND c.oid IN (SELECT indexrelid FROM pg_index WHERE indrelid=ANY(%s::oid[]))) ORDER BY 1", (toast, toast), 8)
    if {int(row[0]) for row in toast_objects if row[1] == 't'} != set(toast):
        raise ValueError('declared TOAST relation missing or not a TOAST table')
    allowed = {'pg_class': set(class_ids.values()) | {row[0] for row in toast_objects},
               'pg_type': {row[0] for row in facts['types']}, 'pg_constraint': {row[0] for row in constraints}}
    if any(row[0] not in allowed or row[1] not in allowed[row[0]] for row in facts['dependencies']):
        raise ValueError('external/unknown dependency on owned namespace objects')
    refs = [{key: row['record_ref'][key] for key in ROW_KEYS} for row in candidate.rows]
    if facts['rows'] != refs or facts['marker_rows'] != [[marker['execution_id'], candidate.descriptor['candidate_sha256'], marker['authority_sha256'], canonical(marker)]]:
        raise ValueError('durable original marker/provenance mismatch')


def _require_target(facts, original):
    if not facts['inspected'] or facts['target'] != original['target']:
        raise _TargetRefusal('actual cleanup target differs from or cannot be verified as the original')


def _base(candidate, original, binding, authority, action, prior=None):
    return {'schema_version': 1, 'kind': 'target_cleanup', 'cleanup_id': uuid.uuid4().hex,
            'action': action, 'binding': binding, 'candidate': candidate.descriptor, 'expected_target': original['target'],
            'cleanup_authority_sha256': authority['payload']['authority_sha256'],
            'cleanup_authority_envelope_sha256': digest(authority), 'prior_cleanup_sha256': prior,
            'write_connection_id': None, 'observer_connection_id': None, 'before': None, 'ownership': None, 'after': None,
            'transaction': {'statements': [], 'commit_attempted': False, 'commit_returned': False,
                            'rollback_returned': False, 'sqlstate': None, 'error_class': None},
            'state': 'not_run', 'issues': [], 'target_validation': 'not_run', 'row_parity': 'not_run', 'product_acceptance': 'pending'}


def _issue(value, code, exc=None):
    issue = {'code': code} if exc is None else {'code': code, 'error_type': type(exc).__name__[:100]}
    if len(value['issues']) < 10: value['issues'].append(issue)


def _publish(root, value):
    value = deepcopy(value); value['cleanup_sha256'] = digest(value)
    validate_target_cleanup(value)
    if len((canonical(value) + '\n').encode()) > MAX_CLEANUP_BYTES: raise ValueError('cleanup receipt byte bound')
    _write_immutable_capture(_child(root, 'cleanup-' + value['cleanup_sha256'] + '.json'), value, 'cleanup_sha256')
    return value


def _publish_final(root, value):
    """Never lose a destructive attempt's receipt to a fact-shape defect: degrade, don't drop."""
    try:
        try:
            return _publish(root, value)
        except OSError:
            try:
                return _publish(root, value)  # One bounded retry of a transient write; then raise.
            except FileExistsError:
                # The first attempt linked the receipt before failing; accept only exact canonical bytes.
                sealed = deepcopy(value); sealed['cleanup_sha256'] = digest(sealed)
                return _open(root, 'cleanup-' + sealed['cleanup_sha256'] + '.json', sealed['cleanup_sha256'])
    except ValueError as exc:
        degraded = deepcopy(value)
        degraded['after'] = None
        if not degraded['transaction']['statements'] and not degraded['transaction']['commit_attempted']:
            # Pre-destructive refusal: drop only snapshots that cannot be published, and say so.
            for key, read_only in (('before', True), ('ownership', False)):
                try:
                    if degraded[key] is not None: _validate_facts(degraded[key], degraded, read_only=read_only)
                except ValueError:
                    degraded[key] = None
                    _issue(degraded, 'cleanup_snapshot_unpublishable')
        degraded['state'] = ('indeterminate' if degraded['transaction']['statements'] or degraded['transaction']['commit_attempted']
                             else 'refused' if degraded['action'] == 'cleanup' else 'indeterminate')
        _issue(degraded, 'cleanup_receipt_degraded', exc)
        return _publish(root, degraded)


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
    namespace = binding['namespace']
    write_owned = observer_owned = False
    try:
        _connection(connection, target_config); _connection(observer_connection, target_config)
        # Once idle has been established these are our own transactions to end.
        write_owned = observer_owned = True
        _begin(observer_connection, read_only=True)
        value['observer_connection_id'] = connection_identity(observer_connection)
        _begin(connection, read_only=False)
        value['write_connection_id'] = connection_identity(connection)
        if value['write_connection_id'] == value['observer_connection_id']: raise ValueError('distinct actual observer connection required')
        value['before'] = _facts(observer_connection, target_config, candidate, namespace, read_only=True)
        _require_target(value['before'], original)  # Before rollback, so a rollback failure cannot lose the refusal code.
        observer_connection.rollback()
        write_target, verified = _observed_target(connection, target_config)
        if not verified or write_target != original['target']:
            # Preserve the writer's actually observed identity; its catalog was not inspected.
            value['ownership'] = dict(_empty_facts(value['write_connection_id'], write_target, False, False),
                                      query_sha256=digest({'namespace': namespace, 'inspected': False}))
            raise _TargetRefusal('actual write target differs from or cannot be verified as the original')
        with connection.cursor() as cursor:
            cursor.execute(f'LOCK TABLE "{namespace}"."candidate_execution", "{namespace}"."migrated_records" IN ACCESS EXCLUSIVE MODE')
        # READ COMMITTED: each catalog statement after the lock sees every committed member.
        value['ownership'] = _facts(connection, target_config, candidate, namespace, read_only=False)
        _require_target(value['ownership'], original)
        _ownership(connection, target_config, candidate, namespace, marker, value['ownership'])
        if any(value['before'][key] != value['ownership'][key] for key in ('namespace', 'classes', 'types', 'constraints', 'marker_rows', 'rows')):
            raise ValueError('namespace changed between observer and locked ownership check')
        value['state'] = 'prepared'
        intent = _publish(root, value)  # Durable uncertainty anchor BEFORE destructive SQL.
        value['prior_cleanup_sha256'] = intent['cleanup_sha256']
        with connection.cursor() as raw:
            cursor = StatementTrace(raw)
            # Restrictive drops: any member/dependency appearing after the check fails the transaction.
            for sql in (f'DROP TABLE "{namespace}"."candidate_execution" RESTRICT', f'DROP TABLE "{namespace}"."migrated_records" RESTRICT', f'DROP SCHEMA "{namespace}" RESTRICT'):
                try: cursor.execute(sql)
                finally: value['transaction']['statements'].append(cursor.last_statement_sha256)
        value['transaction']['commit_attempted'] = True
        _commit_cleanup(connection)
        value['transaction']['commit_returned'] = True
        value['state'] = 'committed'
    except Exception as exc:
        value['transaction'].update(sqlstate=getattr(exc, 'sqlstate', None), error_class=type(exc).__name__[:100])
        value['state'] = 'indeterminate' if value['transaction']['commit_attempted'] else 'rolled_back' if value['transaction']['statements'] else 'refused'
        _issue(value, TARGET_MISMATCH if isinstance(exc, _TargetRefusal) else 'cleanup_not_confirmed', exc)
    finally:
        if write_owned:
            try:
                connection.rollback()
                if not value['transaction']['commit_attempted']: value['transaction']['rollback_returned'] = True
            except Exception as exc:
                _issue(value, 'cleanup_rollback_unconfirmed', exc)
                if value['transaction']['statements']: value['state'] = 'indeterminate'
        if observer_owned:
            try:
                observer_connection.rollback()
                _begin(observer_connection, read_only=True)
                if value['observer_connection_id'] is None:
                    # Early failure before identity capture: bind the after-snapshot to its real observer.
                    value['observer_connection_id'] = connection_identity(observer_connection)
                value['after'] = _facts(observer_connection, target_config, candidate, namespace, read_only=True)
                if not value['after']['inspected'] or value['after']['target'] != original['target']:
                    _issue(value, TARGET_MISMATCH)
                    if value['transaction']['statements']: value['state'] = 'indeterminate'
                elif value['state'] == 'committed' and value['after']['namespace_exists']: value['state'] = 'indeterminate'
            except Exception as exc:
                value['after'] = None
                _issue(value, 'cleanup_after_unobserved', exc)
                if value['transaction']['statements']: value['state'] = 'indeterminate'
            finally:
                try: observer_connection.rollback()
                except Exception: pass
    return _publish_final(root, value)


def _validate_member(name, rows):
    limit, arity = MEMBERS[name]
    if not isinstance(rows, list) or len(rows) > limit: raise ValueError('cleanup snapshot member bound')
    for row in rows:
        if (not isinstance(row, list) or len(row) != arity or
                any(not (item is None or type(item) is int or (isinstance(item, str) and len(item) <= 65536)) for item in row)):
            raise ValueError('closed cleanup catalog member tuple required')


def _validate_facts(facts, value, *, read_only):
    if not isinstance(facts, dict) or set(facts) != FACT_KEYS or type(facts['namespace_exists']) is not bool or type(facts['inspected']) is not bool:
        raise ValueError('closed actual cleanup snapshot required')
    _target(facts['target'])
    if not is_sha(facts['connection_id']) or not is_sha(facts['query_sha256']):
        raise ValueError('cleanup snapshot connection/query pin required')
    if facts['isolation'] != 'read committed' or facts['read_only'] is not read_only:
        raise ValueError('cleanup snapshot outside owned READ COMMITTED transaction mode')
    for name in MEMBERS: _validate_member(name, facts[name])
    rows = facts['rows']
    if (not isinstance(rows, list) or len(rows) > 10000 or
            any(not isinstance(row, dict) or set(row) != set(ROW_KEYS) or not is_sha(row['source_sha256']) or
                type(row['ordinal']) is not int or not is_sha(row['raw_sha256']) for row in rows)):
        raise ValueError('closed cleanup provenance rows required')
    if facts['rows_sha256'] != digest(rows): raise ValueError('cleanup provenance row hash mismatch')
    if facts['readback_sha256'] is not None and not is_sha(facts['readback_sha256']): raise ValueError('cleanup readback pin malformed')
    marker = facts['marker_rows']
    if marker is not None and (not isinstance(marker, list) or len(marker) > 2 or
                               any(not isinstance(row, list) or len(row) != 4 or any(not isinstance(item, str) for item in row) for row in marker)):
        raise ValueError('cleanup marker row bound')
    if not facts['namespace_exists'] and (facts['namespace'] or any(facts[name] for name in MEMBERS) or rows or marker is not None):
        raise ValueError('absent namespace cannot carry member facts')
    if facts['namespace_exists'] and len(facts['namespace']) != 1: raise ValueError('present namespace identity required')
    if not facts['inspected'] and facts['namespace_exists']: raise ValueError('uninspected target cannot report catalog facts')
    return not facts['inspected'] or facts['target'] != value['expected_target']


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
    action, state = value['action'], value['state']
    if action not in ('cleanup', 'reconcile_cleanup') or state not in (CLEANUP_STATES if action == 'cleanup' else RECONCILE_STATES):
        raise ValueError('unknown cleanup action/state')
    if value['target_validation'] != 'not_run' or value['row_parity'] != 'not_run' or value['product_acceptance'] != 'pending':
        raise ValueError('cleanup never grants target/parity/product acceptance')
    _issues(value['issues'])
    codes = {issue['code'] for issue in value['issues']}
    transaction = value['transaction']
    if (not isinstance(transaction, dict) or set(transaction) != TRANSACTION_KEYS or
            any(type(transaction[key]) is not bool for key in ('commit_attempted', 'commit_returned', 'rollback_returned')) or
            not isinstance(transaction['statements'], list) or len(transaction['statements']) > 3 or any(not is_sha(item) for item in transaction['statements'])):
        raise ValueError('closed cleanup transaction facts required')
    statements, attempted = transaction['statements'], transaction['commit_attempted']
    if transaction['commit_returned'] and not attempted: raise ValueError('commit return without attempted commit')
    if attempted and transaction['rollback_returned']: raise ValueError('rollback cannot be claimed after an attempted commit')
    if transaction['sqlstate'] is not None and (not isinstance(transaction['sqlstate'], str) or re.fullmatch('[0-9A-Z]{5}', transaction['sqlstate']) is None):
        raise ValueError('invalid actual cleanup SQLSTATE')
    if transaction['error_class'] is not None and (not isinstance(transaction['error_class'], str) or len(transaction['error_class']) > 100):
        raise ValueError('invalid cleanup error class')
    mismatched = False
    for key, read_only in (('before', True), ('ownership', False), ('after', True)):
        if value[key] is not None: mismatched |= _validate_facts(value[key], value, read_only=read_only)
    # A mismatched/unverified target is preserved as a neutral refusal fact, never a success.
    if mismatched and (TARGET_MISMATCH not in codes or state in ('prepared', 'committed', 'observed_absent', 'observed_present')):
        raise ValueError('mismatched target facts require a neutral refusal/indeterminate receipt')
    if value['ownership'] is not None and value['ownership']['inspected'] and value['ownership']['connection_id'] != value['write_connection_id']:
        raise ValueError('ownership snapshot must come from the write connection')
    for key in ('before', 'after'):
        if value[key] is not None and value[key]['connection_id'] != value['observer_connection_id']:
            raise ValueError('observer snapshots must come from the observer connection')
    if action == 'cleanup':
        if statements or state in ('prepared', 'committed'):
            if value['before'] is None or value['ownership'] is None or value['write_connection_id'] is None or value['observer_connection_id'] is None or value['write_connection_id'] == value['observer_connection_id']:
                raise ValueError('destructive cleanup requires actual distinct owned preflight captures')
        if state == 'prepared' and (value['prior_cleanup_sha256'] is not None or statements or attempted or value['after'] is not None):
            raise ValueError('prepared intent precedes every destructive statement')
        if (statements or attempted) and value['prior_cleanup_sha256'] is None:
            raise ValueError('destructive statements require a linked prepared intent')
        if state == 'committed' and (not transaction['commit_returned'] or len(statements) != 3 or value['after'] is None or value['after']['namespace_exists']):
            raise ValueError('committed cleanup requires actual return and observed absence')
        if state == 'rolled_back' and (not statements or attempted or not transaction['rollback_returned']):
            raise ValueError('rolled_back requires executed statements and a returned rollback')
        if state == 'refused' and (statements or attempted):
            raise ValueError('refusal cannot follow destructive statements')
        if state == 'indeterminate' and not (statements or attempted):
            raise ValueError('indeterminate cleanup requires an uncertain destructive transaction')
    else:
        if (statements or attempted or value['prior_cleanup_sha256'] is None or value['write_connection_id'] is not None or
                value['before'] is not None or value['ownership'] is not None):
            raise ValueError('cleanup reconciliation must be read-only and linked')
        if state != 'indeterminate' and (value['after'] is None or value['after']['namespace_exists'] != (state == 'observed_present')):
            raise ValueError('reconciliation state must match the observed namespace')
    return deepcopy(value)


def _linked_intent(final, intent):
    """Final destructive receipt and its prepared intent describe one attempt."""
    same = ('cleanup_id', 'binding', 'candidate', 'expected_target', 'cleanup_authority_sha256',
            'cleanup_authority_envelope_sha256', 'write_connection_id', 'observer_connection_id', 'before', 'ownership')
    if (intent['action'] != 'cleanup' or intent['state'] != 'prepared' or final['action'] != 'cleanup' or
            any(intent[key] != final[key] for key in same)):
        raise ValueError('cleanup receipt is not linked to its own prepared intent')


def open_target_cleanup(receipt_path, *, expected_cleanup_sha256):
    if not is_sha(expected_cleanup_sha256): raise ValueError('external cleanup receipt pin required')
    path = Path(receipt_path)
    root = _root(path.parent)
    value = _open(root, path.name, expected_cleanup_sha256)
    if value['action'] == 'cleanup' and value['prior_cleanup_sha256'] is not None:
        # Prepared intent is published beside its final receipt by construction.
        _linked_intent(value, _open(root, 'cleanup-' + value['prior_cleanup_sha256'] + '.json', value['prior_cleanup_sha256']))
    return value


def _open(root, name, expected):
    if name != 'cleanup-' + expected + '.json': raise ValueError('canonical cleanup receipt identity path required')
    raw = _bounded(_child(root, name, exists=True), MAX_CLEANUP_BYTES)
    value = validate_target_cleanup(strict_json(raw, name))
    if value['cleanup_sha256'] != expected or raw != (canonical(value) + '\n').encode():
        raise ValueError('cleanup external/canonical byte pin mismatch')
    return value


def reconcile_target_cleanup(experiment_path, artifacts, original_authority, cleanup_authority, *,
        expected_experiment_sha256, expected_original_observation_sha256, expected_cleanup_authority_sha256,
        cleanup_receipt_path, expected_cleanup_sha256, target_config, authority_verifier, cleanup_verifier,
        observer_connection, receipt_root):
    """Observe one exact prior cleanup without reissuing any deletion or load.

    Code policy: reconciliation is server-enforced READ ONLY, so it may run under
    newer cleanup code than the prior attempt, but only with a cleanup authority
    that binds the CURRENT code pin. Same code requires the same authority; changed
    code requires a different, freshly signed authority. Every other binding key
    must equal the prior receipt's.
    """
    root = _root(receipt_root)
    candidate, original, marker, binding = _context(experiment_path, artifacts, original_authority,
        expected_experiment_sha256=expected_experiment_sha256,
        expected_original_observation_sha256=expected_original_observation_sha256,
        target_config=target_config, authority_verifier=authority_verifier)
    _authorize(cleanup_authority, cleanup_verifier, expected_cleanup_authority_sha256, binding, 'reconcile_cleanup')
    prior = open_target_cleanup(cleanup_receipt_path, expected_cleanup_sha256=expected_cleanup_sha256)
    same_code = prior['binding']['cleanup_code_sha256'] == binding['cleanup_code_sha256']
    # A lone prepared intent is a valid prior: it is the only record after a crash mid-cleanup.
    if (prior['action'] != 'cleanup' or
            any(prior['binding'][key] != binding[key] for key in BINDING_KEYS - {'cleanup_code_sha256'}) or
            (prior['cleanup_authority_sha256'] == expected_cleanup_authority_sha256) != same_code or
            (same_code and prior['cleanup_authority_envelope_sha256'] != digest(cleanup_authority))):
        raise ValueError('cleanup reconciliation original/authority/code scope mismatch')
    value = _base(candidate, original, binding, cleanup_authority, 'reconcile_cleanup', expected_cleanup_sha256)
    owned = False
    try:
        _connection(observer_connection, target_config); owned = True
        _begin(observer_connection, read_only=True)
        value['observer_connection_id'] = connection_identity(observer_connection)
        value['after'] = _facts(observer_connection, target_config, candidate, binding['namespace'], read_only=True)
        _require_target(value['after'], original)
        value['state'] = 'observed_present' if value['after']['namespace_exists'] else 'observed_absent'
        if value['after']['namespace_exists']:
            try:
                _ownership(observer_connection, target_config, candidate, binding['namespace'], marker, value['after'])
            except ValueError as exc:
                # Present but no longer provably the original: keep the observed fact, flag it.
                _issue(value, 'cleanup_reconciliation_ownership_unproven', exc)
    except Exception as exc:
        value['state'] = 'indeterminate'
        _issue(value, TARGET_MISMATCH if isinstance(exc, _TargetRefusal) else 'cleanup_reconciliation_unresolved', exc)
    finally:
        if owned:
            try: observer_connection.rollback()
            except Exception: pass
    return _publish_final(root, value)

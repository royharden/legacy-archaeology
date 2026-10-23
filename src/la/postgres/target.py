"""Explicit disposable-target configuration and parameterized execution helpers.

No connection, environment lookup, or driver import occurs on module import.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import date, datetime
from decimal import Decimal
import re
import uuid
import os

from la.review import REQUIRED, digest


@dataclass(frozen=True)
class TargetConfig:
    authority_reference: str
    database: str
    role: str
    driver_version: str
    server_major: int
    host: str = '127.0.0.1'
    port: int = 5432
    scope: str = 'disposable_local_test'
    statement_timeout_ms: int = 30000
    expected_bundle_sha256: str | None = None
    expected_source_sha256: str | None = None
    expected_mapping_sha256: str | None = None

    def validate(self):
        if self.scope != 'disposable_local_test' or not self.authority_reference.strip():
            raise ValueError('disposable target authority required')
        if self.host not in ('127.0.0.1', '::1') or type(self.port) is not int or not 1 <= self.port <= 65535:
            raise ValueError('only explicit loopback target allowed')
        if self.port in (20178, 20179, 55490):
            raise ValueError('reserved unrelated project target is forbidden')
        if any(not isinstance(v, str) or not v or len(v) > 63 or '\x00' in v for v in (self.database, self.role)):
            raise ValueError('explicit database and least-privilege role required')
        if not self.driver_version or type(self.server_major) is not int or self.server_major < 12:
            raise ValueError('driver and server version pins required')
        if type(self.statement_timeout_ms) is not int or not 1 <= self.statement_timeout_ms <= 120000:
            raise ValueError('invalid statement timeout')
        for pin in (self.expected_bundle_sha256, self.expected_source_sha256, self.expected_mapping_sha256):
            if pin is not None and (not isinstance(pin, str) or re.fullmatch('[0-9a-f]{64}', pin) is None):
                raise ValueError('invalid external target bundle/source/mapping pin')
        return self

    def public(self):
        return {key: getattr(self, key) for key in self.__dataclass_fields__}


def owned_namespace(namespace):
    if not isinstance(namespace, str) or re.fullmatch(r'la_[a-f0-9]{32}', namespace) is None:
        raise ValueError('invalid owned namespace')
    return namespace


def new_namespace():
    return owned_namespace('la_' + uuid.uuid4().hex)


def driver_and_connect(dsn, config):
    """Called only after outer authority, bundle and config checks."""
    import psycopg
    config.validate()
    if psycopg.__version__ != config.driver_version:
        raise ValueError('driver version pin mismatch')
    parsed = psycopg.conninfo.conninfo_to_dict(dsn)
    # Disallow libpq service/passfiles and environment-driven host/identity defaults.
    allowed = {'host', 'hostaddr', 'port', 'dbname', 'user', 'password', 'sslmode', 'connect_timeout', 'application_name'}
    if set(parsed) - allowed or any(key not in parsed for key in ('host', 'port', 'dbname', 'user')):
        raise ValueError('DSN must declare target identity without service/option indirection')
    if parsed['host'] != config.host or parsed.get('hostaddr', config.host) != config.host or parsed['port'] != str(config.port) or parsed['dbname'] != config.database or parsed['user'] != config.role:
        raise ValueError('DSN does not match authorized target')
    # Null-device passfile blocks implicit credential-file reads; no secret enters receipts.
    def connect():
        return psycopg.connect(dsn, autocommit=False, connect_timeout=5,
                               passfile=os.devnull, application_name='legacy-archaeology-disposable-check')
    return psycopg, connect


def inspect_target(connection, config):
    with connection.cursor() as cursor:
        cursor.execute('SELECT current_database(), current_user, inet_server_addr()::text, inet_server_port(), current_setting(\'server_version_num\')::int')
        database, role, host, port, version = cursor.fetchone()
        if (database, role, host, port, version // 10000) != (config.database, config.role, config.host, config.port, config.server_major):
            raise ValueError('actual target identity/version mismatch')
        cursor.execute('SELECT rolsuper,rolcreatedb,rolcreaterole,rolreplication,rolbypassrls FROM pg_roles WHERE rolname=current_user')
        flags = cursor.fetchone()
        if flags is None or any(flags):
            raise ValueError('target role is not least privilege')
        cursor.execute("SELECT set_config('statement_timeout', %s, true)", (str(config.statement_timeout_ms),))
        cursor.execute("SELECT set_config('lock_timeout', '5000', true)")
    return {'database': database, 'role': role, 'host': host, 'port': port,
            'server_version_num': version, 'authority_reference': config.authority_reference,
            'scope': config.scope}


def connection_identity(connection):
    with connection.cursor() as cursor:
        cursor.execute('SELECT pg_backend_pid(),backend_start::text FROM pg_stat_activity WHERE pid=pg_backend_pid()')
        row = cursor.fetchone()
        if row is None:
            raise ValueError('actual connection identity unavailable')
        return digest({'backend_pid': row[0], 'backend_start': row[1]})


def parameters(rows, mapping, columns):
    by_name = {f['semantic_target']: f for f in mapping['fields']}
    result = []
    for row in rows:
        ref = row['record_ref']
        values = {'source_sha256': ref['source_sha256'], 'ordinal': ref['ordinal'],
                  'raw_sha256': ref['raw_sha256'], **row['values']}
        for name, field in by_name.items():
            value = values[name]
            if value is None:
                if not field['policy']['nullable']:
                    raise ValueError('nonnullable load value')
            elif field['data_type'] == 'decimal':
                number = Decimal(value)
                scale, precision = field['policy']['scale'], field['policy']['precision']
                if not number.is_finite() or number.as_tuple().exponent != -scale or number.copy_abs() >= Decimal(10) ** (precision - scale):
                    raise ValueError('numeric value is not exactly representable')
                values[name] = number
            elif field['data_type'] == 'date':
                values[name] = date.fromisoformat(value)
            elif not isinstance(value, str) or '\x00' in value:
                raise ValueError('invalid text load value')
        result.append(tuple(values[name] for name in columns))
    return result


def verify_structure(cursor, namespace, mapping):
    owned_namespace(namespace)
    cursor.execute('SELECT pg_get_userbyid(nspowner)=current_user FROM pg_namespace WHERE nspname=%s', (namespace,))
    if cursor.fetchone() != (True,):
        raise ValueError('namespace is not owned by the authorized role')
    cursor.execute('SELECT column_name,data_type,is_nullable,numeric_precision,numeric_scale FROM information_schema.columns WHERE table_schema=%s AND table_name=%s ORDER BY ordinal_position', (namespace, 'migrated_records'))
    actual = cursor.fetchall()
    expected = [('source_sha256', 'text', 'NO', None, None), ('ordinal', 'bigint', 'NO', 64, 0), ('raw_sha256', 'text', 'NO', None, None)]
    for field in sorted(mapping['fields'], key=lambda f: REQUIRED.index(f['semantic_target'])):
        policy, kind = field['policy'], field['data_type']
        expected.append((field['semantic_target'], {'text': 'text', 'date': 'date', 'decimal': 'numeric'}[kind],
                         'YES' if policy['nullable'] else 'NO', policy['precision'] if kind == 'decimal' else None,
                         policy['scale'] if kind == 'decimal' else None))
    if actual != expected:
        raise ValueError('actual target column/type/null/precision structure mismatch')
    cursor.execute('SELECT constraint_type FROM information_schema.table_constraints WHERE table_schema=%s AND table_name=%s', (namespace, 'migrated_records'))
    kinds = [row[0] for row in cursor.fetchall()]
    if kinds.count('PRIMARY KEY') != 1:
        raise ValueError('target primary key missing')
    cursor.execute('SELECT k.column_name FROM information_schema.table_constraints t JOIN information_schema.key_column_usage k ON t.constraint_catalog=k.constraint_catalog AND t.constraint_schema=k.constraint_schema AND t.constraint_name=k.constraint_name WHERE t.table_schema=%s AND t.table_name=%s AND t.constraint_type=%s ORDER BY k.ordinal_position', (namespace, 'migrated_records', 'PRIMARY KEY'))
    if cursor.fetchall() != [('source_sha256',), ('ordinal',)]:
        raise ValueError('target key would collapse duplicate business records')
    # CHECK constraints include NOT NULL on some PostgreSQL versions; verify declared
    # vocabulary constraints by their deterministic server-rendered column binding.
    cursor.execute('SELECT pg_get_constraintdef(c.oid) FROM pg_constraint c JOIN pg_class t ON t.oid=c.conrelid JOIN pg_namespace n ON n.oid=t.relnamespace WHERE n.nspname=%s AND t.relname=%s AND c.contype=%s', (namespace, 'migrated_records', 'c'))
    checks = [row[0] for row in cursor.fetchall()]
    if len(checks) != sum('allowed_codes' in f['policy'] for f in mapping['fields']):
        raise ValueError('declared vocabulary constraint missing')
    return {'columns': actual, 'check_constraints': checks, 'primary_key_present': True}


def observe(cursor, namespace, rows, mapping, columns):
    owned_namespace(namespace)
    quoted = ','.join('"' + name + '"' for name in columns)
    cursor.execute(f'SELECT {quoted} FROM "{namespace}"."migrated_records" ORDER BY "ordinal"')
    stored = cursor.fetchall()
    expected_refs = {(row['record_ref']['source_sha256'], row['record_ref']['ordinal']): row['record_ref'] for row in rows}
    seen, observations = set(), []
    for stored_row in stored:
        entry = dict(zip(columns, stored_row))
        key = (entry['source_sha256'], entry['ordinal'])
        ref = expected_refs.get(key)
        if ref is None or key in seen or entry['raw_sha256'] != ref['raw_sha256']:
            raise ValueError('target missing/extra/duplicate record identity')
        seen.add(key)
        values = {}
        for field in mapping['fields']:
            name, kind = field['semantic_target'], field['data_type']
            value = entry[name]
            if value is None:
                if not field['policy']['nullable']:
                    raise ValueError('unexpected target null')
            elif kind == 'decimal':
                if not isinstance(value, Decimal) or not value.is_finite() or value.as_tuple().exponent != -field['policy']['scale']:
                    raise ValueError('target decimal type/scale mismatch')
                value = format(value, 'f')  # Never round/quantize readback to conceal a mismatch.
            elif kind == 'date':
                if not isinstance(value, date) or isinstance(value, datetime):
                    raise ValueError('target date type mismatch')
                value = value.isoformat()
            elif not isinstance(value, str):
                raise ValueError('target text type mismatch')
            values[name] = value
        observations.append({'record_ref': ref, 'mapping_sha256': mapping['mapping_sha256'],
                             'outcome': 'converted', 'values': values})
    if seen != set(expected_refs):
        raise ValueError('target cardinality/identity mismatch')
    return observations


def seal_receipt(receipt):
    result = dict(receipt)
    result['receipt_sha256'] = digest(result)
    return result

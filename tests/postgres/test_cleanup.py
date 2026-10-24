"""what_bug_this_catches: wrong-owner/extra-object drops, cascade-style overreach, lost
refusal facts, inherited isolation, unlinked destructive receipts, load authority used
for cleanup and writes or repeated drops during read-only reconciliation.

Future regression SOURCE only: written in Dirty Mode, never imported/collected/executed.
Fakes below exercise offline decision logic; they are never database evidence. The actual
disposable cleanup journey is opt-in behind the same explicit switch as
test_execution_boundaries and has not run.
"""
from copy import deepcopy
import importlib.util
import os
import unittest
from unittest.mock import patch

from la.postgres import cleanup as module
from la.postgres import (TargetConfig, cleanup_target_namespace, collect_target_experiment,
                         open_target_cleanup, open_target_experiment, reconcile_target_cleanup,
                         validate_target_cleanup)
from la.review import canonical, digest

ROLE = 'leastpriv'
SHA = lambda label: digest('synthetic ' + label)  # noqa: E731 - hash labels, not evidence
TARGET = {'database': 'disposable', 'role': ROLE, 'host': '127.0.0.1', 'port': 5432, 'server_version_num': 170000,
          'authority_reference': SHA('authority'), 'scope': 'disposable_local_test', 'driver_version': 'pinned-future-driver'}


class Cursor:
    """Scripted cursor: first script key contained in the SQL selects the rows."""
    def __init__(self, connection): self.connection, self.rows = connection, []
    def __enter__(self): return self
    def __exit__(self, *exc): return False
    def execute(self, sql, parameters=None):
        self.connection.executed.append(sql)
        self.rows = next((list(rows) for key, rows in self.connection.script if key in sql), [])
    def fetchmany(self, size): return self.rows[:size]
    def fetchone(self): return self.rows[0] if self.rows else None
    def fetchall(self): return list(self.rows)


class Connection:
    def __init__(self, script=()):
        self.script, self.executed, self.rollbacks = list(script), [], 0
    def cursor(self): return Cursor(self)
    def rollback(self): self.rollbacks += 1


class Candidate:
    descriptor = {'candidate_sha256': SHA('candidate'), 'source_sha256': SHA('source'), 'kind': 'evaluation_candidate'}
    rows = [{'record_ref': {'source_sha256': SHA('source'), 'ordinal': 1, 'raw_sha256': SHA('raw')}}]


class Config:
    role = ROLE


MARKER = {'execution_id': 'e' * 32, 'candidate': Candidate.descriptor, 'authority_sha256': SHA('authority'),
          'target_config_sha256': SHA('config'), 'row_count': 1}
NAMESPACE = 'la_' + 'a' * 32


def good_facts(**changes):
    facts = {name: [] for name in module.MEMBERS}
    facts.update(
        connection_id=SHA('write connection'), target=deepcopy(TARGET), inspected=True, isolation='read committed',
        read_only=False, namespace_exists=True, namespace=[['500', ROLE]],
        classes=[['101', 'candidate_execution', 'r', 'p', ROLE, '201'], ['102', 'candidate_execution_pkey', 'i', 'p', ROLE, '0'],
                 ['103', 'migrated_records', 'r', 'p', ROLE, '202'], ['104', 'migrated_records_pkey', 'i', 'p', ROLE, '0']],
        types=[['301', 'candidate_execution', 'c', '101', '0'], ['302', '_candidate_execution', 'b', '0', '301'],
               ['303', 'migrated_records', 'c', '103', '0'], ['304', '_migrated_records', 'b', '0', '303']],
        namespace_acl=[['10', '10', '10', 'USAGE'], ['10', '10', '10', 'CREATE']],
        table_acl=[['candidate_execution', '10', '10', '10', 'SELECT'], ['migrated_records', '10', '10', '10', 'SELECT']],
        constraints=[['401', 'candidate_execution', 'p', 'candidate_execution_pkey', '102', 'PRIMARY KEY (execution_id)'],
                     ['402', 'migrated_records', 'p', 'migrated_records_pkey', '104', 'PRIMARY KEY (source_sha256, ordinal)']],
        dependencies=[['pg_class', '101', 0, 'n'], ['pg_class', '103', 0, 'n'], ['pg_type', '301', 0, 'i'],
                      ['pg_type', '302', 0, 'i'], ['pg_type', '303', 0, 'i'], ['pg_type', '304', 0, 'i'],
                      ['pg_class', '201', 0, 'i'], ['pg_class', '202', 0, 'i'], ['pg_constraint', '401', 0, 'a'],
                      ['pg_constraint', '402', 0, 'a']],
        marker_rows=[[MARKER['execution_id'], SHA('candidate'), SHA('authority'), canonical(MARKER)]],
        rows=[dict(Candidate.rows[0]['record_ref'])], readback_sha256=SHA('readback'), query_sha256=SHA('query'))
    facts['rows_sha256'] = digest(facts['rows'])
    facts.update(changes)
    return facts


def ownership_connection(toast=(('201', 't'), ('202', 't'), ('211', 'i'), ('212', 'i'))):
    columns = [(name, 'text', 'NO') for name in ('execution_id', 'candidate_sha256', 'authority_sha256', 'payload')]
    return Connection([('information_schema.columns', columns), ("relkind='t'", toast)])


class OwnershipProof(unittest.TestCase):
    def prove(self, facts, connection=None):
        module._ownership(connection or ownership_connection(), Config(), Candidate(), NAMESPACE, MARKER, facts)

    def test_exact_original_namespace_is_proven(self):
        self.prove(good_facts())

    def test_wrong_owner_or_extra_object_refuses(self):
        facts = good_facts()
        cases = {
            'namespace owner': dict(namespace=[['500', 'someone_else']]),
            'table owner': dict(classes=[row[:4] + ['someone_else'] + row[5:] if row[1] == 'migrated_records' else row for row in facts['classes']]),
            'extra view': dict(classes=facts['classes'] + [['105', 'peek', 'v', 'p', ROLE, '0']]),
            'unlogged table': dict(classes=[row[:3] + ['u'] + row[4:] if row[1] == 'migrated_records' else row for row in facts['classes']]),
            'user trigger': dict(extra_members=[['trigger', 'audit']]),
            'column default': dict(extra_members=[['column_expression', 'migrated_records.status']]),
            'schema default ACL': dict(default_acls=[['601', ROLE, 'r']]),
            'inheritance child': dict(inheritance=[['900', '103']]),
            'typed/external outgoing dependency': dict(outgoing=[['pg_class', '103', 'pg_type', '777', 'n']]),
            'extension member': dict(extension_members=[['pg_class', '103']]),
            'public namespace grant': dict(namespace_acl=facts['namespace_acl'] + [['0', '10', '10', 'USAGE']]),
            'shared table grant': dict(table_acl=facts['table_acl'] + [['migrated_records', '11', '10', '10', 'SELECT']]),
            'foreign key into table': dict(dependencies=facts['dependencies'] + [['pg_constraint', '999', 0, 'n']]),
            'view over table': dict(dependencies=facts['dependencies'] + [['pg_rewrite', '998', 0, 'n']]),
            'exclusion constraint': dict(constraints=facts['constraints'] + [['403', 'migrated_records', 'x', 'ex', '0', 'EXCLUDE']]),
            'changed primary key': dict(constraints=[facts['constraints'][0][:5] + ['PRIMARY KEY (candidate_sha256)'], facts['constraints'][1]]),
            'key on wrong index': dict(constraints=[facts['constraints'][0][:4] + ['104', 'PRIMARY KEY (execution_id)'], facts['constraints'][1]]),
            'extra type': dict(types=facts['types'] + [['305', 'mood', 'e', '0', '0']]),
            'marker changed': dict(marker_rows=[[MARKER['execution_id'], SHA('other'), SHA('authority'), canonical(MARKER)]]),
            'extra marker': dict(marker_rows=facts['marker_rows'] * 2),
            'provenance rows changed': dict(rows=[]),
            'uninspected target': dict(inspected=False),
        }
        for label, change in cases.items():
            with self.subTest(label), self.assertRaises(ValueError):
                self.prove(good_facts(**change))

    def test_missing_toast_or_changed_marker_columns_refuse(self):
        with self.assertRaises(ValueError):
            self.prove(good_facts(), ownership_connection(toast=(('201', 't'),)))
        connection = ownership_connection()
        connection.script[0] = ('information_schema.columns', [('execution_id', 'text', 'YES')])
        with self.assertRaises(ValueError):
            self.prove(good_facts(), connection)


class TargetIdentityQuery(unittest.TestCase):
    def test_server_host_is_read_without_netmask(self):
        # inet::text renders '127.0.0.1/32', which never equals the configured loopback host.
        from la.postgres.target import inspect_target
        connection = Connection([('current_database', [('disposable', ROLE, '127.0.0.1', 5432, 170000)]),
                                 ('pg_roles', [(False,) * 5])])
        config = TargetConfig(SHA('authority'), 'disposable', ROLE, 'pinned-future-driver', 17)
        self.assertEqual(inspect_target(connection, config), TARGET)
        self.assertIn('host(inet_server_addr())', connection.executed[0])
        self.assertNotIn('inet_server_addr()::text', connection.executed[0])


class BoundedQueries(unittest.TestCase):
    def test_server_limit_and_overflow_refusal(self):
        connection = Connection([('pg_class', [('1',)] * 4)])
        with connection.cursor() as cursor, self.assertRaises(ValueError):
            module._query(cursor, 'SELECT oid FROM pg_class', limit=3)
        self.assertTrue(connection.executed[-1].endswith(' LIMIT 4'))
        for bad in (0, 10001, True):
            with self.subTest(bad), connection.cursor() as cursor, self.assertRaises(ValueError):
                module._query(cursor, 'SELECT 1', limit=bad)


@unittest.skipUnless(importlib.util.find_spec('psycopg'), 'pinned driver absent; no auto-install')
class OwnedTransaction(unittest.TestCase):
    def connection(self, settings):
        from psycopg.pq import TransactionStatus
        connection = Connection([('current_setting', [settings])])
        connection.info = type('Info', (), {'transaction_status': TransactionStatus.IDLE})()
        return connection

    def test_read_committed_is_explicit_first_statement_and_verified(self):
        connection = self.connection(('read committed', 'on'))
        module._begin(connection, read_only=True)
        self.assertEqual(connection.executed[0], 'SET TRANSACTION ISOLATION LEVEL READ COMMITTED, READ ONLY')

    def test_inherited_isolation_or_mode_refuses(self):
        for settings, read_only in ((('repeatable read', 'on'), True), (('read committed', 'off'), True), (('read committed', 'on'), False)):
            with self.subTest(settings=settings, read_only=read_only), self.assertRaises(ValueError):
                module._begin(self.connection(settings), read_only=read_only)


def receipt(action='cleanup', state='refused', **changes):
    binding = {key: SHA(key) for key in module.BINDING_KEYS}
    binding.update(namespace=NAMESPACE, original_execution_id='e' * 32, bundle_sha256=None,
                   candidate_sha256=SHA('candidate'), source_sha256=SHA('source'), target_sha256=digest(TARGET))
    value = {'schema_version': 1, 'kind': 'target_cleanup', 'cleanup_id': 'c' * 32, 'action': action, 'binding': binding,
             'candidate': Candidate.descriptor, 'expected_target': deepcopy(TARGET),
             'cleanup_authority_sha256': SHA('cleanup authority'), 'cleanup_authority_envelope_sha256': SHA('envelope'),
             'prior_cleanup_sha256': None, 'write_connection_id': None, 'observer_connection_id': None,
             'before': None, 'ownership': None, 'after': None,
             'transaction': {'statements': [], 'commit_attempted': False, 'commit_returned': False,
                             'rollback_returned': False, 'sqlstate': None, 'error_class': None},
             'state': state, 'issues': [], 'target_validation': 'not_run', 'row_parity': 'not_run', 'product_acceptance': 'pending'}
    value.update(changes)
    value['cleanup_sha256'] = digest(value)
    return value


def absent(connection_id):
    return dict(module._empty_facts(connection_id, deepcopy(TARGET), True, True), query_sha256=SHA('query'))


def observer(**changes):
    return good_facts(**{'connection_id': SHA('observer'), 'read_only': True, **changes})


@patch('la.postgres.cleanup.validate_descriptor', side_effect=lambda value: value)
class ReceiptContract(unittest.TestCase):
    def destructive(self, state, **changes):
        base = dict(write_connection_id=SHA('write connection'), observer_connection_id=SHA('observer'),
                    before=observer(), ownership=good_facts(), prior_cleanup_sha256=SHA('intent'))
        base.update(changes)
        return receipt(state=state, **base)

    def statements(self, count, **extra):
        return dict({'statements': [SHA(f'drop {i}') for i in range(count)], 'commit_attempted': False, 'commit_returned': False,
                     'rollback_returned': False, 'sqlstate': None, 'error_class': None}, **extra)

    def test_refusal_preserves_actual_mismatched_target_facts(self, _):
        moved = dict(TARGET, server_version_num=170001)
        facts = absent(SHA('observer')); facts['target'] = moved
        issues = [{'code': 'cleanup_target_mismatch', 'error_type': '_TargetRefusal'}]
        kept = validate_target_cleanup(receipt(observer_connection_id=SHA('observer'), before=facts, issues=issues))
        self.assertEqual(kept['before']['target'], moved)
        for change in (dict(issues=[]), dict(issues=issues, state='prepared')):
            with self.subTest(change), self.assertRaises(ValueError):
                validate_target_cleanup(receipt(observer_connection_id=SHA('observer'), before=facts, **change))

    def test_prepared_intent_precedes_destruction_and_finals_link_to_it(self, _):
        validate_target_cleanup(self.destructive('prepared', prior_cleanup_sha256=None))
        with self.assertRaises(ValueError):
            validate_target_cleanup(self.destructive('prepared', prior_cleanup_sha256=None, transaction=self.statements(1)))
        with self.assertRaises(ValueError):
            validate_target_cleanup(self.destructive('rolled_back', prior_cleanup_sha256=None, transaction=self.statements(1, rollback_returned=True)))
        validate_target_cleanup(self.destructive('rolled_back', transaction=self.statements(1, rollback_returned=True)))
        final = self.destructive('indeterminate', transaction=self.statements(3, commit_attempted=True))
        intent = self.destructive('prepared', prior_cleanup_sha256=None)
        module._linked_intent(final, intent)
        with self.assertRaises(ValueError):
            module._linked_intent(final, dict(intent, cleanup_id='d' * 32))

    def test_committed_requires_returned_commit_and_observed_absence(self, _):
        commit = self.statements(3, commit_attempted=True, commit_returned=True)
        validate_target_cleanup(self.destructive('committed', transaction=commit, after=absent(SHA('observer'))))
        for change in (dict(after=None), dict(after=observer()), dict(transaction=self.statements(2, commit_attempted=True, commit_returned=True), after=absent(SHA('observer')))):
            with self.subTest(change), self.assertRaises(ValueError):
                validate_target_cleanup(self.destructive('committed', **dict(dict(transaction=commit), **change)))

    def test_snapshot_mode_and_member_shapes_are_closed(self, _):
        cases = (dict(before=observer(isolation='repeatable read')), dict(before=good_facts()),  # writer-mode observer
                 dict(ownership=good_facts(read_only=True)), dict(before=observer(classes=[['101', 'candidate_execution']])),
                 dict(before=observer(connection_id=SHA('stranger'))))
        for change in cases:
            with self.subTest(sorted(change)), self.assertRaises(ValueError):
                validate_target_cleanup(self.destructive('prepared', prior_cleanup_sha256=None, **change))

    def test_reconciliation_is_read_only_linked_and_matches_observation(self, _):
        base = dict(prior_cleanup_sha256=SHA('final'), observer_connection_id=SHA('observer'), after=absent(SHA('observer')))
        validate_target_cleanup(receipt('reconcile_cleanup', 'observed_absent', **base))
        bad = (dict(base, prior_cleanup_sha256=None), dict(base, write_connection_id=SHA('write connection')),
               dict(base, transaction=self.statements(1)), dict(base, state='observed_present'), dict(base, state='committed'))
        for change in bad:
            state = change.pop('state', 'observed_absent')
            with self.subTest(state=state), self.assertRaises(ValueError):
                validate_target_cleanup(receipt('reconcile_cleanup', state, **change))


class AuthorityAndCodePolicy(unittest.TestCase):
    def setUp(self):
        from postgres.test_target_candidates import ephemeral_signer
        self.verifier, self.sign = ephemeral_signer(self)
        self.binding = receipt()['binding']

    def authority(self, operations=('cleanup', 'reconcile_cleanup'), **changes):
        body = dict(self.binding, schema_version=1, kind='disposable_target_cleanup_authority', authority_id='cleanup-regression',
                    scope='owned_disposable_namespace', operations=list(operations))
        body.update(changes)
        body['authority_sha256'] = digest({k: v for k, v in body.items() if k != 'authority_sha256'})
        return self.sign(body), body['authority_sha256']

    def test_only_dedicated_granted_cleanup_authority_is_accepted(self):
        envelope, pin = self.authority()
        module._authorize(envelope, self.verifier, pin, self.binding, 'cleanup')
        reconcile_only, reconcile_pin = self.authority(operations=('reconcile_cleanup',))
        load_like, load_pin = self.authority(kind='disposable_target_authority')
        other_namespace, other_pin = self.authority(namespace='la_' + 'b' * 32)
        for label, (env, expected) in {'not granted': (reconcile_only, reconcile_pin), 'load authority kind': (load_like, load_pin),
                                       'other namespace': (other_namespace, other_pin), 'wrong pin': (envelope, SHA('wrong'))}.items():
            with self.subTest(label), self.assertRaises(ValueError):
                module._authorize(env, self.verifier, expected, self.binding, 'cleanup')

    def test_reconciliation_never_drops_and_requires_fresh_authority_for_new_code(self):
        envelope, pin = self.authority()
        prior = dict(receipt(), cleanup_authority_sha256=pin, cleanup_authority_envelope_sha256=digest(envelope))
        connection = Connection()
        published = []
        common = dict(expected_experiment_sha256=SHA('experiment'), expected_original_observation_sha256=SHA('observation'),
                      expected_cleanup_authority_sha256=pin, cleanup_receipt_path='unused', expected_cleanup_sha256=SHA('final'),
                      target_config=None, authority_verifier=None, cleanup_verifier=self.verifier,
                      observer_connection=connection, receipt_root='unused')
        with patch.object(module, '_root', side_effect=lambda path: path), \
             patch.object(module, '_context', return_value=(Candidate(), {'target': TARGET}, MARKER, self.binding)), \
             patch.object(module, 'open_target_cleanup', return_value=prior), \
             patch.object(module, '_connection'), patch.object(module, '_begin'), \
             patch.object(module, 'connection_identity', return_value=SHA('observer')), \
             patch.object(module, '_facts', return_value=absent(SHA('observer'))), \
             patch.object(module, '_publish_final', side_effect=lambda root, value: published.append(value) or value):
            value = reconcile_target_cleanup(None, None, None, envelope, **common)
            self.assertEqual(value['state'], 'observed_absent')
            self.assertFalse(any('DROP' in sql for sql in connection.executed))
            self.assertEqual(connection.rollbacks, 1)
            # Same authority but the prior ran different code: a freshly signed authority is required.
            changed = dict(prior, binding=dict(self.binding, cleanup_code_sha256=SHA('older code')))
            with patch.object(module, 'open_target_cleanup', return_value=changed), self.assertRaises(ValueError):
                reconcile_target_cleanup(None, None, None, envelope, **common)
        self.assertEqual(len(published), 1)


class DisposableCleanup(unittest.TestCase):
    """Actual opt-in journey; requires a disposable least-privilege target. Unexecuted."""

    @classmethod
    def setUpClass(cls):
        if os.environ.get('LA_TEST_DISPOSABLE_AUTHORIZED') != 'YES_AFTER_DIRTY_MODE_CLOSED':
            raise unittest.SkipTest('actual disposable cleanup not authorized')
        required = ('LA_TEST_DSN', 'LA_TEST_DATABASE', 'LA_TEST_ROLE', 'LA_TEST_DRIVER_VERSION', 'LA_TEST_SERVER_MAJOR', 'LA_TEST_PORT')
        if any(not os.environ.get(name) for name in required):
            raise unittest.SkipTest('explicit disposable target variables absent')

    def setUp(self):
        from postgres.test_target_experiment import ExperimentGuards
        from la.postgres.target import driver_and_connect
        ExperimentGuards.setUp(self)
        self.config = TargetConfig(self.body['authority_sha256'], os.environ['LA_TEST_DATABASE'], os.environ['LA_TEST_ROLE'],
                                   os.environ['LA_TEST_DRIVER_VERSION'], int(os.environ['LA_TEST_SERVER_MAJOR']),
                                   port=int(os.environ['LA_TEST_PORT']),
                                   expected_candidate_sha256=self.artifact['descriptor']['candidate_sha256'])
        self.dsn = os.environ['LA_TEST_DSN']
        _, self.connect = driver_and_connect(self.dsn, self.config)
        self.manifest = collect_target_experiment(self.artifact, self.authority, capture_root=self.root, experiment_id='cleanup',
                                                  dsn=self.dsn, target_config=self.config, authority_verifier=self.verifier)
        self.path = self.root / 'cleanup'
        (self.root / 'receipts').mkdir()  # _root requires an existing receipt directory
        snapshot = open_target_experiment(self.path, expected_experiment_sha256=self.manifest['experiment_sha256'])
        self.original = next(v for v in snapshot.observations.values() if v.get('kind') == 'target_observation' and v['commit_state'] == 'committed')
        self.namespace = self.original['attempt']['namespace']
        _, _, _, binding = module._context(self.path, self.artifact, self.authority,
            expected_experiment_sha256=self.manifest['experiment_sha256'],
            expected_original_observation_sha256=self.original['observation_sha256'],
            target_config=self.config, authority_verifier=self.verifier)
        body = dict(binding, schema_version=1, kind='disposable_target_cleanup_authority', authority_id='cleanup-journey',
                    scope='owned_disposable_namespace', operations=['cleanup', 'reconcile_cleanup'])
        body['authority_sha256'] = digest(body)
        self.cleanup_authority, self.cleanup_pin = self.sign(body), body['authority_sha256']
        self.connections = [self.connect(), self.connect()]
        for connection in self.connections: self.addCleanup(connection.close)

    def run_cleanup(self):
        return cleanup_target_namespace(self.path, self.artifact, self.authority, self.cleanup_authority,
            expected_experiment_sha256=self.manifest['experiment_sha256'],
            expected_original_observation_sha256=self.original['observation_sha256'],
            expected_cleanup_authority_sha256=self.cleanup_pin, target_config=self.config,
            authority_verifier=self.verifier, cleanup_verifier=self.verifier,
            connection=self.connections[0], observer_connection=self.connections[1], receipt_root=self.root / 'receipts')

    def reconcile(self, final):
        return reconcile_target_cleanup(self.path, self.artifact, self.authority, self.cleanup_authority,
            expected_experiment_sha256=self.manifest['experiment_sha256'],
            expected_original_observation_sha256=self.original['observation_sha256'],
            expected_cleanup_authority_sha256=self.cleanup_pin,
            cleanup_receipt_path=self.root / 'receipts' / f"cleanup-{final['cleanup_sha256']}.json",
            expected_cleanup_sha256=final['cleanup_sha256'], target_config=self.config,
            authority_verifier=self.verifier, cleanup_verifier=self.verifier,
            observer_connection=self.connections[1], receipt_root=self.root / 'receipts')

    def side_sql(self, sql):
        with self.connect() as other:
            with other.cursor() as cursor: cursor.execute(sql)
            other.commit()

    def test_extra_object_refuses_then_exact_namespace_is_removed_and_reconciled(self):
        self.side_sql(f'CREATE TABLE "{self.namespace}"."intruder" (x int)')
        refused = self.run_cleanup()
        self.assertEqual((refused['state'], refused['transaction']['statements']), ('refused', []))
        self.side_sql(f'DROP TABLE "{self.namespace}"."intruder"')  # removes only the object this test created
        final = self.run_cleanup()
        self.assertEqual(final['state'], 'committed')
        self.assertFalse(final['after']['namespace_exists'])
        self.assertEqual(open_target_cleanup(self.root / 'receipts' / f"cleanup-{final['cleanup_sha256']}.json",
                                             expected_cleanup_sha256=final['cleanup_sha256']), final)
        later = self.reconcile(final)
        self.assertEqual((later['state'], later['transaction']['statements']), ('observed_absent', []))

    def test_unknown_commit_acknowledgement_stays_indeterminate_until_read_only_reconciliation(self):
        real = module._commit_cleanup
        def lost(connection):
            real(connection); raise ConnectionError('synthetic lost acknowledgement after real commit')
        with patch.object(module, '_commit_cleanup', side_effect=lost):
            final = self.run_cleanup()
        self.assertEqual(final['state'], 'indeterminate')
        self.assertTrue(final['transaction']['commit_attempted'])
        later = self.reconcile(final)
        self.assertEqual(later['state'], 'observed_absent')
        self.assertEqual(later['prior_cleanup_sha256'], final['cleanup_sha256'])


if __name__ == '__main__':
    unittest.main()

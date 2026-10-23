"""what_bug_this_catches: implicit connection, false pass, receipt mutation and blind retry.

The live class is deliberately opt-in after Dirty Mode closure. It only connects
to an already-authorized disposable target; it starts no service or environment.
"""
import json
from dataclasses import replace
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from la.convert import approve_mapping, export_bundle, transform
from la.postgres import (TargetConfig, constraint_checks, database_check, reconcile_commit,
                         rollback_check, write_execution_receipt)
from la.postgres.target import driver_and_connect, seal_receipt
from review.support import answered, bundle_inputs


class ExecutionGuards(unittest.TestCase):
    def test_missing_authority_dsn_and_config_cannot_import_driver_or_claim_pass(self):
        for kwargs in ({}, {'authorized': True}, {'dsn': 'unused'}, {'dsn': 'unused', 'authorized': True}):
            with self.subTest(kwargs=kwargs), patch('la.postgres.execution.driver_and_connect', side_effect=AssertionError('must not connect')):
                receipt = database_check('not-opened-without-authority', **kwargs)
                self.assertEqual(receipt['target_validation'], 'not_run')
                self.assertEqual(receipt['row_parity'], 'not_run')
                self.assertEqual(receipt['product_acceptance'], 'pending')

    def test_receipt_publication_is_exclusive_and_outside_bundle(self):
        with tempfile.TemporaryDirectory() as root:
            root = Path(root)
            receipt = seal_receipt({'schema_version': 1, 'target_validation': 'not_run', 'reason': 'not executed'})
            target = root / 'receipts' / 'execution.json'
            write_execution_receipt(target, receipt)
            original = target.read_bytes()
            with self.assertRaises(FileExistsError): write_execution_receipt(target, receipt)
            self.assertEqual(target.read_bytes(), original)
            bundle = root / 'bundle'; bundle.mkdir(); (bundle / 'manifest.json').write_text('{}')
            with self.assertRaises(ValueError): write_execution_receipt(bundle / 'execution.json', receipt)
            receipt['target_validation'] = 'passed'
            with self.assertRaises(ValueError): write_execution_receipt(root / 'forged.json', receipt)

    def test_config_rejects_remote_target_and_unpinned_driver(self):
        for config in (TargetConfig('explicit-authority', 'disposable', 'leastpriv', '3.x', 17, host='remote.example'),
                       TargetConfig('explicit-authority', 'disposable', 'leastpriv', '', 17),
                       TargetConfig('', 'disposable', 'leastpriv', '3.x', 17)):
            with self.subTest(config=config), self.assertRaises(ValueError): config.validate()


class DisposablePostgres(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Future execution requires both a separate authorization switch and exact
        # target pins. A DSN by itself never enables this class.
        if os.environ.get('LA_TEST_DISPOSABLE_AUTHORIZED') != 'YES_AFTER_DIRTY_MODE_CLOSED':
            raise unittest.SkipTest('disposable PostgreSQL execution has not been authorized')
        required = ('LA_TEST_DSN', 'LA_TEST_DATABASE', 'LA_TEST_ROLE', 'LA_TEST_DRIVER_VERSION', 'LA_TEST_SERVER_MAJOR', 'LA_TEST_PORT')
        if any(not os.environ.get(name) for name in required):
            raise unittest.SkipTest('explicit disposable target pins are incomplete')
        cls.dsn = os.environ['LA_TEST_DSN']
        cls.config = TargetConfig('explicit-disposable-regression-authorization', os.environ['LA_TEST_DATABASE'],
                                  os.environ['LA_TEST_ROLE'], os.environ['LA_TEST_DRIVER_VERSION'],
                                  int(os.environ['LA_TEST_SERVER_MAJOR']), port=int(os.environ['LA_TEST_PORT']))
        cls.config.validate()

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        batch, generation, store, mapping = answered(self.root)
        approval = approve_mapping(mapping, 'regression_author', 'hand-declared disposable fixture')
        self.bundle = self.root / 'bundle'
        self.manifest = export_bundle(self.bundle, batch, mapping, transform(batch, mapping), approval,
                                      generation=generation, rulings=store, **bundle_inputs(batch))
        self.config = replace(self.config, expected_bundle_sha256=self.manifest['bundle_sha256'],
                              expected_source_sha256=self.manifest['source_sha256'],
                              expected_mapping_sha256=self.manifest['mapping_sha256'])
        self.namespaces = []
        self.addCleanup(self.cleanup_owned_namespaces)

    def cleanup_owned_namespaces(self):
        # Only fresh namespaces returned by this test's own execution may be removed.
        from la.postgres.target import owned_namespace, inspect_target
        _, connect = driver_and_connect(self.dsn, self.config)
        for namespace in self.namespaces:
            owned_namespace(namespace)
            connection = connect()
            try:
                inspect_target(connection, self.config)
                with connection.cursor() as cursor:
                    cursor.execute('SELECT pg_get_userbyid(nspowner)=current_user FROM pg_namespace WHERE nspname=%s', (namespace,))
                    if cursor.fetchone() != (True,):
                        raise AssertionError('refusing cleanup of foreign namespace')
                    cursor.execute(f'DROP SCHEMA "{namespace}" CASCADE')
                connection.commit()
            finally:
                connection.close()

    def test_commit_then_distinct_fresh_readback_preserves_hand_values_and_duplicates(self):
        receipt = database_check(self.bundle, dsn=self.dsn, authorized=True, target_config=self.config)
        if receipt.get('committed'): self.namespaces.append(receipt['namespace'])
        self.assertEqual(receipt['execution_status'], 'committed_readback')
        self.assertNotEqual(receipt['write_connection_id'], receipt['read_connection_id'])
        self.assertEqual([row['record_ref']['ordinal'] for row in receipt['observations']], [0, 1, 2])
        self.assertEqual([row['values']['balance'] for row in receipt['observations']], ['0.00', '1.23', '0.00'])
        self.assertEqual(receipt['observations'][1]['values']['description'], '')
        self.assertEqual(receipt['target_validation'], 'not_run')  # No independent canonical acceptance implied.
        self.assertEqual(receipt['product_acceptance'], 'pending')

    def test_server_failure_rollback_and_constraint_effects_are_freshly_observed(self):
        rollback = rollback_check(self.bundle, dsn=self.dsn, authorized=True, target_config=self.config)
        self.assertEqual(rollback['execution_status'], 'rollback_observed')
        self.assertEqual(rollback['observation']['sqlstate'], '22012')
        self.assertEqual(rollback['observation']['rows_before'], rollback['observation']['rows_after_fresh_read'])
        results = constraint_checks(self.bundle, dsn=self.dsn, authorized=True, target_config=self.config)
        actual = {r['observation']['sqlstate'] for r in results['checks']}
        self.assertEqual(actual, {'23505', '23502', '22003', '23514'})
        self.assertTrue(all(r['execution_status'] == 'rollback_observed' for r in results['checks']))

    def test_lost_ack_uses_durable_identity_without_second_load(self):
        # Actual server commit happens; only the client acknowledgement is lost.
        driver, connect = driver_and_connect(self.dsn, self.config)
        class LoseAcknowledgement:
            def __init__(self, connection): self.connection = connection
            def __getattr__(self, name): return getattr(self.connection, name)
            def commit(self):
                self.connection.commit()
                raise OSError('injected lost commit acknowledgement')
        with patch('la.postgres.execution.driver_and_connect', return_value=(driver, lambda: LoseAcknowledgement(connect()))):
            receipt = database_check(self.bundle, dsn=self.dsn, authorized=True, target_config=self.config)
        self.namespaces.append(receipt['namespace'])
        self.assertEqual(receipt['target_validation'], 'indeterminate')
        self.assertFalse(receipt['retry_authorized'])
        recovery = reconcile_commit(self.bundle, receipt['namespace'], dsn=self.dsn, authorized=True,
                                    target_config=self.config, execution_receipt=receipt)
        self.assertEqual(recovery['execution_status'], 'commit_identity_reconciled')
        self.assertFalse(recovery['retry_authorized'])
        self.assertEqual(len(recovery['observations']), 3)
        self.assertEqual(recovery['durable_bundle_sha256'], self.manifest['bundle_sha256'])
        forged = dict(receipt, namespace='la_' + '0' * 32)
        with self.assertRaises(ValueError):
            reconcile_commit(self.bundle, forged['namespace'], dsn=self.dsn, authorized=True,
                             target_config=self.config, execution_receipt=forged)

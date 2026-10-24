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
        self.batch, self.generation = batch, generation
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

    def v2_inputs(self, method='B0'):
        from la.postgres import prepare_evaluation_candidate
        from review.support import proposal
        from postgres.test_target_candidates import ephemeral_signer, intent
        artifact = prepare_evaluation_candidate(self.batch, proposal(self.batch, self.generation, method),
                                                 edition='public-disposable-regression', freeze_sha256='a' * 64)
        verifier, sign = ephemeral_signer(self)
        body = intent(artifact)
        config = replace(self.config, authority_reference=body['authority_sha256'],
                         expected_candidate_sha256=artifact['descriptor']['candidate_sha256'],
                         expected_bundle_sha256=None, expected_source_sha256=None, expected_mapping_sha256=None)
        return artifact, sign(body), config, verifier

    def test_v2_all_five_arms_share_real_transaction_and_hand_derived_readback(self):
        from la.postgres import target_observer_v2
        for method in ('B0', 'B1', 'C0', 'R0', 'R1'):
            artifact, authority, config, verifier = self.v2_inputs(method)
            observed = target_observer_v2(artifact, authority, dsn=self.dsn, target_config=config,
                                          authority_verifier=verifier)
            if observed['commit_state'] == 'committed': self.namespaces.append(observed['attempt']['namespace'])
            self.assertEqual(observed['commit_state'], 'committed')
            self.assertEqual(observed['candidate']['method'], method)
            self.assertFalse(observed['candidate']['product_loadable'])
            self.assertEqual([r['values']['balance'] for r in observed['readback']['rows']], ['0.00', '1.23', '0.00'])
            self.assertNotEqual(observed['attempt']['write_connection_id'], observed['attempt']['read_connection_id'])
            self.assertIsNone(observed['recovery'])  # Normal commit is not lost-ACK evidence.

    def test_v2_negative_effects_capture_server_errors_and_fresh_durable_absence(self):
        from la.postgres import target_observer_v2
        artifact, authority, config, verifier = self.v2_inputs()
        observed = target_observer_v2(artifact, authority, dsn=self.dsn, target_config=config,
                                      authority_verifier=verifier,
                                      negative_kinds=('rollback', 'nonnull', 'check', 'numeric_overflow', 'duplicate_identity', 'invalid_date'))
        if observed['commit_state'] == 'committed': self.namespaces.append(observed['attempt']['namespace'])
        self.assertEqual(observed['commit_state'], 'committed')
        effects = {effect['probe_kind']: effect for effect in observed['negative_effects']}
        expected = {'rollback': {'22012'}, 'nonnull': {'23502'}, 'check': {'23514'},
                    'numeric_overflow': {'22003'}, 'duplicate_identity': {'23505'}, 'invalid_date': {'22007', '22008'}}
        self.assertEqual(set(effects), set(expected))
        for kind, states in expected.items():
            effect = effects[kind]
            self.assertIn(effect['transaction']['sqlstate'], states)
            self.assertFalse(effect['before']['namespace_exists'])
            self.assertFalse(effect['after']['namespace_exists'])
            self.assertEqual(effect['before']['rows'], [])
            self.assertEqual(effect['after']['rows'], [])
            self.assertNotEqual(effect['before']['connection_id'], effect['after']['connection_id'])

    def test_v2_lost_ack_recovers_actual_marker_without_repeating_any_insert(self):
        from la.postgres import reconcile_target_candidate, target_observer_v2
        artifact, authority, config, verifier = self.v2_inputs()
        driver, connect = driver_and_connect(self.dsn, config)
        class LoseAcknowledgement:
            def __init__(self, connection): self.connection = connection
            def __getattr__(self, name): return getattr(self.connection, name)
            def commit(self):
                self.connection.commit()
                raise OSError('injected lost client acknowledgement after actual commit')
        with patch('la.postgres.runner.driver_and_connect', return_value=(driver, lambda: LoseAcknowledgement(connect()))):
            original = target_observer_v2(artifact, authority, dsn=self.dsn, target_config=config, authority_verifier=verifier)
        self.namespaces.append(original['attempt']['namespace'])
        self.assertEqual(original['commit_state'], 'indeterminate')
        self.assertIn('commit_acknowledgement_unknown', {issue['code'] for issue in original['issues']})
        recovered = reconcile_target_candidate(artifact, authority, original, dsn=self.dsn,
                                                target_config=config, authority_verifier=verifier)
        self.assertEqual(recovered['commit_state'], 'committed')
        self.assertIn('reconciled_lost_commit_acknowledgement', {issue['code'] for issue in recovered['issues']})
        self.assertEqual(recovered['attempt']['execution_id'], original['attempt']['execution_id'])
        self.assertEqual(recovered['recovery']['prior_observation_sha256'], original['observation_sha256'])
        self.assertEqual(len(recovered['recovery']['marker_rows']), 1)
        self.assertEqual([r['record_ref']['ordinal'] for r in recovered['readback']['rows']], [0, 1, 2])

    def controlled_inputs(self):
        from la.postgres import prepare_evaluation_candidate_v2
        from la.review import digest
        from review.support import proposal
        from postgres.test_target_candidates import ephemeral_signer
        from postgres.test_controlled_target import phase_intent
        artifact = prepare_evaluation_candidate_v2(self.batch, proposal(self.batch, self.generation),
                    edition='public-T1-controlled-regression', evaluation_phase='T1', split='development',
                    evaluation_plan_sha256=digest('explicit public development evaluation plan'))
        verifier, sign = ephemeral_signer(self)
        body = phase_intent(artifact)
        config = replace(self.config, authority_reference=body['authority_sha256'],
                         expected_candidate_sha256=artifact['descriptor']['candidate_sha256'],
                         expected_bundle_sha256=None, expected_source_sha256=None, expected_mapping_sha256=None)
        return artifact, sign(body), config, verifier

    def test_controlled_failed_load_observes_partial_insert_then_real_error_and_absence(self):
        from la.postgres import collect_controlled_failed_load
        artifact, authority, config, verifier = self.controlled_inputs()
        observed = collect_controlled_failed_load(artifact, authority, dsn=self.dsn,
                                                  target_config=config, authority_verifier=verifier)
        self.assertEqual(observed['schema_version'], 3)
        self.assertEqual(observed['commit_state'], 'failed')
        fault = observed['controlled_fault']
        self.assertEqual(fault['state'], 'injected')
        self.assertEqual(fault['boundary'], 'after_first_insert_before_commit')
        self.assertFalse(fault['driver_commit_returned'])
        self.assertFalse(fault['network_loss_claimed'])
        self.assertEqual(len(fault['partial_write']['rows']), 1)
        effect = observed['negative_effects'][0]
        self.assertEqual(effect['probe_kind'], 'failed_load')
        self.assertEqual(effect['transaction']['sqlstate'], '22012')
        self.assertEqual(effect['transaction']['statement_sha256'], fault['trigger_statement_sha256'])
        if effect['after']['namespace_exists']: self.namespaces.append(observed['attempt']['namespace'])
        self.assertFalse(effect['before']['namespace_exists'])
        self.assertFalse(effect['after']['namespace_exists'])
        self.assertEqual(effect['after']['rows'], [])
        self.assertNotEqual(effect['before']['connection_id'], effect['after']['connection_id'])

    def test_controlled_application_ack_loss_observes_driver_return_and_reconciles_marker(self):
        from la.postgres import collect_controlled_lost_ack
        artifact, authority, config, verifier = self.controlled_inputs()
        pair = collect_controlled_lost_ack(artifact, authority, dsn=self.dsn,
                                           target_config=config, authority_verifier=verifier)
        prior, recovered = pair['prior'], pair['reconciled']
        if prior['controlled_fault']['driver_commit_returned']: self.namespaces.append(prior['attempt']['namespace'])
        self.assertEqual(prior['commit_state'], 'indeterminate')
        self.assertEqual(prior['controlled_fault']['boundary'], 'after_driver_commit_before_application_ack')
        self.assertTrue(prior['controlled_fault']['driver_commit_returned'])
        self.assertFalse(prior['controlled_fault']['application_ack_delivered'])
        self.assertFalse(prior['controlled_fault']['network_loss_claimed'])
        self.assertIn('controlled_application_ack_suppressed', {i['code'] for i in prior['issues']})
        self.assertEqual(recovered['commit_state'], 'committed')
        self.assertEqual(recovered['controlled_fault'], prior['controlled_fault'])
        self.assertEqual(recovered['recovery']['prior_observation_sha256'], prior['observation_sha256'])
        self.assertIn('reconciled_controlled_application_ack', {i['code'] for i in recovered['issues']})
        self.assertEqual(len(recovered['recovery']['marker_rows']), 1)
        self.assertEqual(len(recovered['readback']['rows']), 3)

    def test_known_driver_commit_then_read_failure_is_not_lost_ack(self):
        from la.postgres import reconcile_target_candidate, target_observer_v2
        artifact, authority, config, verifier = self.v2_inputs()
        driver, connect = driver_and_connect(self.dsn, config)
        calls = 0
        def fail_fresh_read_connection():
            nonlocal calls
            calls += 1
            if calls == 3: raise OSError('injected read connection failure after actual returned commit')
            return connect()
        with patch('la.postgres.runner.driver_and_connect', return_value=(driver, fail_fresh_read_connection)):
            original = target_observer_v2(artifact, authority, dsn=self.dsn, target_config=config,
                                          authority_verifier=verifier)
        self.namespaces.append(original['attempt']['namespace'])
        self.assertEqual(original['schema_version'], 2)
        self.assertNotIn('controlled_fault', original)
        self.assertIn('committed_readback_unavailable', {i['code'] for i in original['issues']})
        recovered = reconcile_target_candidate(artifact, authority, original, dsn=self.dsn,
                                                target_config=config, authority_verifier=verifier)
        self.assertEqual(recovered['commit_state'], 'committed')
        self.assertIn('reconciled_known_commit_readback', {i['code'] for i in recovered['issues']})
        self.assertNotIn('reconciled_lost_commit_acknowledgement', {i['code'] for i in recovered['issues']})

    def test_experiment_facade_captures_all_effects_and_actual_d6_ports_grade(self):
        from types import SimpleNamespace
        from la.postgres import collect_target_experiment, target_experiment_callbacks
        from la.postgres.target import inspect_target
        from la.review import digest
        from evaluation.artifacts import CaptureStore
        from evaluation.eligibility import ReceiptVerifier
        from evaluation.target_effects import TargetExpectation, grade_target
        from evaluation.target_runner import TargetGrant, TargetPorts, run_target_arm
        from postgres.test_target_experiment import declared_oracle, declared_columns
        artifact, authority, config, verifier = self.controlled_inputs()
        manifest = collect_target_experiment(artifact, authority, capture_root=self.root,
            experiment_id='complete', dsn=self.dsn, target_config=config, authority_verifier=verifier)
        for record in manifest['captures']:
            if record['role'] in ('normal_readback', 'ack_prior'): self.namespaces.append(record['namespace'])
        callbacks = target_experiment_callbacks(self.root / 'complete', expected_experiment_sha256=manifest['experiment_sha256'],
            expected_candidate_sha256=artifact['descriptor']['candidate_sha256'], expected_authority_sha256=authority['payload']['authority_sha256'])
        self.assertEqual(manifest['capture_status'], 'collected')
        normal = callbacks.observe(artifact, authority)
        self.assertEqual(len(normal['negative_effects']), 6)
        self.assertEqual(normal['commit_state'], 'committed')
        self.assertEqual(manifest['target_validation'], 'not_run')
        # Separate inspected operator target pins and hand-declared schema/values.
        _, connect = driver_and_connect(self.dsn, config)
        with connect() as connection: target = inspect_target(connection, config)
        expectation = TargetExpectation(artifact['descriptor'], authority['payload']['authority_sha256'],
            digest(config.public()), manifest['observer_code_sha256'], target, declared_columns())
        oracle = declared_oracle(self.batch)
        recovery = callbacks.recovery(artifact, authority)
        grade = grade_target(oracle, normal, expectation=expectation, failed_load=callbacks.failed_load(artifact, authority),
                             prior=recovery['prior'], recovery_observation=recovery['reconciled'], edition=artifact['descriptor']['edition'])
        self.assertEqual(grade['target_validation'], 'passed')
        self.assertEqual(grade['product_acceptance'], 'pending')
        evaluator_verifier = ReceiptVerifier(verifier.trusted_issuers, verifier.public_keys)
        ports = TargetPorts(prepare=lambda *args: artifact,
            prepare_v2=lambda *args: artifact, grant=lambda *args: TargetGrant(authority, expectation, evaluator_verifier),
            observe=callbacks.observe, failed_load=callbacks.failed_load, recovery=callbacks.recovery)
        case = SimpleNamespace(edition=artifact['descriptor']['edition'],
            batches=[SimpleNamespace(batch_id='literal-public-three-records', visible=self.batch, oracle=oracle)])
        phase = {key: artifact['descriptor'][key] for key in ('evaluation_phase', 'split', 'evaluation_plan_sha256', 'freeze_sha256')}
        grader_root = self.root / 'grader-captures'; grader_root.mkdir()
        result = run_target_arm(case, artifact['proposal'], 'B0', CaptureStore(grader_root), ports,
                                freeze_sha256=None, mode='development', phase_scope=phase)
        self.assertEqual(result['target_validation'], 'passed')

    def test_experiment_repeated_actual_reconciliation_preserves_original_and_never_loads(self):
        from la.postgres import (collect_target_experiment, open_target_experiment, reconcile_target_experiment,
                                 target_experiment_callbacks, target_reconciliation_callbacks)
        artifact, authority, config, verifier = self.controlled_inputs()
        # Fail only the later recovery call, after the actual predecessor is durable.
        with patch('la.postgres.experiment.reconcile_target_candidate', side_effect=OSError('controlled observer outage')):
            manifest = collect_target_experiment(artifact, authority, capture_root=self.root,
                experiment_id='repeat', dsn=self.dsn, target_config=config, authority_verifier=verifier)
        self.assertEqual(manifest['capture_status'], 'partial')
        root = self.root / 'repeat'
        for record in manifest['captures']:
            if record['role'] in ('normal_readback', 'ack_prior'): self.namespaces.append(record['namespace'])
        original = (root / 'experiment.json').read_bytes()
        prior = open_target_experiment(root, expected_experiment_sha256=manifest['experiment_sha256']).observations['ack_prior']
        statements = []
        driver, connect = driver_and_connect(self.dsn, config)
        class ReadOnlyCursor:
            def __init__(self, cursor): self.cursor = cursor
            def __enter__(self): self.cursor.__enter__(); return self
            def __exit__(self, *args): return self.cursor.__exit__(*args)
            def __getattr__(self, name): return getattr(self.cursor, name)
            def execute(self, sql, parameters=None):
                statements.append(sql)
                if not sql.lstrip().upper().startswith(('SELECT', 'SET')): raise AssertionError('recovery attempted mutation')
                return self.cursor.execute(sql, parameters)
            def executemany(self, *args): raise AssertionError('never insert')
        class ReadOnlyConnection:
            def __init__(self): self.connection = connect()
            def __getattr__(self, name): return getattr(self.connection, name)
            def cursor(self, *args, **kwargs): return ReadOnlyCursor(self.connection.cursor(*args, **kwargs))
        with patch('la.postgres.experiment.target_observer_v2', side_effect=AssertionError('never reload')), \
             patch('la.postgres.runner.driver_and_connect', return_value=(driver, ReadOnlyConnection)):
            records = []
            for _ in range(2):
                records.append(reconcile_target_experiment(root, artifact, authority,
                    expected_experiment_sha256=manifest['experiment_sha256'], dsn=self.dsn,
                    target_config=config, authority_verifier=verifier,
                    previous_reconciliation_sha256=records[-1]['reconciliation_sha256'] if records else None))
        self.assertTrue(statements)
        self.assertEqual((root / 'experiment.json').read_bytes(), original)
        self.assertNotEqual(records[0]['capture']['attempt_id'], records[1]['capture']['attempt_id'])
        for record in records:
            self.assertEqual(record['capture_status'], 'captured')
            self.assertEqual(record['capture']['namespace'], prior['attempt']['namespace'])
            self.assertEqual(record['prior_observation_sha256'], prior['observation_sha256'])
            self.assertEqual(record['capture']['execution_id'], prior['attempt']['execution_id'])
        original_callbacks = target_experiment_callbacks(root, expected_experiment_sha256=manifest['experiment_sha256'])
        self.assertIsNone(original_callbacks.recovery(artifact, authority)['reconciled'])
        with patch('la.postgres.runner.driver_and_connect', side_effect=AssertionError('offline reader cannot connect')):
            selected = target_reconciliation_callbacks(root, artifact, authority,
                expected_experiment_sha256=manifest['experiment_sha256'],
                expected_reconciliation_sha256=records[-1]['reconciliation_sha256'],
                expected_prior_observation_sha256=prior['observation_sha256'],
                target_config=config, authority_verifier=verifier)
        self.assertEqual(len(selected.projection()['history']), 2)
        self.assertEqual(selected.projection()['source_label'], 'controlled_application_ack_suppression')
        from la.review import digest
        from evaluation.target_effects import TargetExpectation, grade_target
        from evaluation.target_runner import TargetPorts
        from postgres.test_target_experiment import declared_columns, declared_oracle
        from la.postgres.target import inspect_target
        _, connect = driver_and_connect(self.dsn, config)
        with connect() as connection: target = inspect_target(connection, config)
        expectation = TargetExpectation(artifact['descriptor'], authority['payload']['authority_sha256'], digest(config.public()),
                                       manifest['observer_code_sha256'], target, declared_columns())
        ports = TargetPorts(lambda *args: artifact, lambda *args: None, selected.observe, selected.failed_load, selected.recovery)
        pair = ports.recovery(artifact, authority)
        grade = grade_target(declared_oracle(self.batch), ports.observe(artifact, authority), expectation=expectation,
            failed_load=ports.failed_load(artifact, authority), prior=pair['prior'], recovery_observation=pair['reconciled'])
        self.assertEqual(grade['target_validation'], 'passed')
        self.assertEqual(grade['product_acceptance'], 'pending')
        self.assertIsNone(original_callbacks.recovery(artifact, authority)['reconciled'])

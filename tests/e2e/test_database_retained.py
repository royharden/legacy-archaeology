"""Opt-in M1-only PostgreSQL tests. All successful schemas/artifacts are retained.

Run with M1_RV2_DB_CHECK=1 and M1_RV2_EVIDENCE naming an existing owned root.
No credentials, DROP, DELETE, resource removal or automatic cleanup is used.
"""
from dataclasses import replace
from copy import deepcopy
import json
import os
from pathlib import Path
import subprocess
import sys
import unittest
from unittest.mock import patch
import uuid

from la.convert import approve_mapping, export_bundle, transform
from la.postgres import TargetConfig, database_check, rollback_check, constraint_checks, reconcile_commit
from la.postgres.target import driver_and_connect, inspect_target
from la.contracts import digest
from review.support import answered, bundle_inputs, fixture


class RetainedDatabaseJourney(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if os.environ.get('M1_RV2_DB_CHECK') != '1':
            raise unittest.SkipTest('explicit reviewer-owned M1 target run only')
        cls.evidence = Path(os.environ['M1_RV2_EVIDENCE']).resolve(strict=True)
        cls.dsn = 'host=127.0.0.1 port=21800 dbname=m1_rv2 user=m1_rv2 sslmode=disable'
        cls.config_base = TargetConfig('PB-M1-R03-RV2-disposable-only', 'm1_rv2', 'm1_rv2',
                                      '3.3.6', 17, port=21800,
                                      server_host='172.17.0.8', server_port=21800)

    def setUp(self):
        self.root = self.evidence / ('db-' + uuid.uuid4().hex)
        self.root.mkdir()
        batch, generation, store, mapping = answered(self.root)
        self.batch, self.generation = batch, generation
        approval = approve_mapping(mapping, 'RV2', 'public hand-derived disposable fixture')
        self.bundle = self.root / 'bundle'
        self.manifest = export_bundle(self.bundle, batch, mapping, transform(batch, mapping), approval,
                                      generation=generation, rulings=store, **bundle_inputs(batch))
        self.config = replace(self.config_base, expected_bundle_sha256=self.manifest['bundle_sha256'],
                              expected_source_sha256=self.manifest['source_sha256'],
                              expected_mapping_sha256=self.manifest['mapping_sha256'])

    def capture(self, name, value):
        (self.root / (name + '.json')).write_text(json.dumps(value, indent=2), encoding='utf-8')

    def test_committed_new_connection_readback_matches_literal_oracle(self):
        """what_bug_this_catches: producer self-comparison hides wrong persisted values."""
        receipt = database_check(self.bundle, dsn=self.dsn, authorized=True, target_config=self.config)
        self.capture('committed', receipt)
        self.assertEqual(receipt['execution_status'], 'committed_readback', receipt)
        self.assertNotEqual(receipt['write_connection_id'], receipt['read_connection_id'])
        self.assertEqual([r['record_ref']['ordinal'] for r in receipt['observations']], [0, 1, 2])
        self.assertEqual([r['values'] for r in receipt['observations']], [
            dict(account_ref='0007', description='AB', balance='0.00', effective_date='2024-02-29', status='A'),
            dict(account_ref='0007', description='', balance='1.23', effective_date='2024-03-01', status='B'),
            dict(account_ref='0007', description='AB', balance='0.00', effective_date='2024-02-29', status='A')])
        self.assertEqual(receipt['target']['host'], '172.17.0.8')
        self.assertEqual(receipt['target']['connection_host'], '127.0.0.1')
        self.assertEqual(receipt['product_acceptance'], 'pending')
        _, connect = driver_and_connect(self.dsn, self.config)
        with connect() as connection, connection.cursor() as cursor:
            cursor.execute('SELECT column_name,data_type,is_nullable,numeric_precision,numeric_scale '
                           'FROM information_schema.columns WHERE table_schema=%s AND table_name=%s '
                           'ORDER BY ordinal_position', (receipt['namespace'], 'migrated_records'))
            columns = cursor.fetchall()
        self.capture('independent-catalog', columns)
        catalog = {row[0]: row[1:] for row in columns}
        self.assertEqual(catalog['account_ref'][:2], ('text', 'NO'))
        self.assertEqual(catalog['balance'], ('numeric', 'NO', 6, 2))
        self.assertEqual(catalog['effective_date'][:2], ('date', 'NO'))

    def test_declared_date_null_is_stored_as_sql_null(self):
        """what_bug_this_catches: sentinel becomes empty text, zero or invalid date."""
        batch, generation = fixture(raw_rows=[b'0007AB  -0000099999999A',
                                              b'0007    +0012320240301B',
                                              b'0007AB  -0000099999999A'])
        field = next(c for c in generation['candidates'] if c['semantic_target'] == 'effective_date')
        field['policy'].update(nullable=True, sentinels={'99999999': 'null'})
        field['id'] = digest({k: v for k, v in field.items() if k != 'id'})
        generation['generation_sha256'] = digest({k: v for k, v in generation.items() if k != 'generation_sha256'})
        root = self.root / 'null'; root.mkdir()
        batch, generation, store, mapping = answered(root, batch, generation)
        bundle = root / 'bundle'
        manifest = export_bundle(bundle, batch, mapping, transform(batch, mapping),
                                 approve_mapping(mapping, 'RV2', 'declared null regression'),
                                 generation=generation, rulings=store, **bundle_inputs(batch))
        config = replace(self.config_base, expected_bundle_sha256=manifest['bundle_sha256'],
                         expected_source_sha256=manifest['source_sha256'],
                         expected_mapping_sha256=manifest['mapping_sha256'])
        receipt = database_check(bundle, dsn=self.dsn, authorized=True, target_config=config)
        self.capture('null-readback', receipt)
        self.assertEqual(receipt['execution_status'], 'committed_readback', receipt)
        self.assertEqual([r['values']['effective_date'] for r in receipt['observations']],
                         [None, '2024-03-01', None])
        _, connect = driver_and_connect(self.dsn, config)
        with connect() as connection, connection.cursor() as cursor:
            cursor.execute(f'SELECT ordinal,effective_date IS NULL FROM "{receipt["namespace"]}".migrated_records ORDER BY ordinal')
            self.assertEqual(cursor.fetchall(), [(0, True), (1, False), (2, True)])

    def test_rollback_and_constraints_report_real_sqlstates(self):
        """what_bug_this_catches: statement success flags substitute for server effects."""
        rollback = rollback_check(self.bundle, dsn=self.dsn, authorized=True, target_config=self.config)
        self.capture('rollback', rollback)
        self.assertEqual(rollback['execution_status'], 'rollback_observed', rollback)
        self.assertEqual(rollback['observation']['sqlstate'], '22012')
        self.assertEqual(rollback['observation']['rows_before'], rollback['observation']['rows_after_fresh_read'])
        constraints = constraint_checks(self.bundle, dsn=self.dsn, authorized=True, target_config=self.config)
        self.capture('constraints', constraints)
        self.assertEqual({r['observation']['sqlstate'] for r in constraints['checks']},
                         {'23505', '23502', '22003', '23514'})
        self.assertTrue(all(r['execution_status'] == 'rollback_observed' for r in constraints['checks']))

    def test_actual_commit_lost_ack_reconciles_without_second_insert(self):
        """what_bug_this_catches: ambiguous commit blindly retries and duplicates data."""
        driver, connect = driver_and_connect(self.dsn, self.config)
        class LostAck:
            def __init__(self, inner): self.inner = inner
            def __getattr__(self, name): return getattr(self.inner, name)
            def commit(self):
                self.inner.commit()
                raise OSError('controlled acknowledgement loss after real commit')
        with patch('la.postgres.execution.driver_and_connect', return_value=(driver, lambda: LostAck(connect()))):
            original = database_check(self.bundle, dsn=self.dsn, authorized=True, target_config=self.config)
        self.capture('lost-ack', original)
        self.assertEqual(original['target_validation'], 'indeterminate', original)
        self.assertFalse(original['retry_authorized'])
        recovered = reconcile_commit(self.bundle, original['namespace'], dsn=self.dsn,
                                     authorized=True, target_config=self.config, execution_receipt=original)
        self.capture('reconciled', recovered)
        self.assertEqual(recovered['execution_status'], 'commit_identity_reconciled', recovered)
        self.assertFalse(recovered['retry_authorized'])
        self.assertEqual(len(recovered['observations']), 3)

    def test_wrong_server_pin_is_rejected_on_actual_connection(self):
        """what_bug_this_catches: forwarded pin exists but actual address goes unchecked."""
        _, connect = driver_and_connect(self.dsn, self.config)
        with connect() as connection:
            with self.assertRaisesRegex(ValueError, 'target identity'):
                inspect_target(connection, replace(self.config, server_host='172.17.0.9'))

    def test_database_check_cli_writes_separate_committed_receipt(self):
        """what_bug_this_catches: library works but authorized CLI cannot execute/load."""
        authority = dict(authorized=True, local_disposable_target=True, least_privilege_role=True,
                         authority_id=self.config.authority_reference,
                         bundle_sha256=self.manifest['bundle_sha256'])
        self.capture('authority', authority)
        self.capture('target-config', self.config.public())
        original_manifest = (self.bundle / 'manifest.json').read_bytes()
        os.environ['M1_RV2_TARGET_DSN'] = 'postgresql://m1_rv2@127.0.0.1:21800/m1_rv2'
        result = subprocess.run([sys.executable, '-m', 'la', '--root', str(self.root),
                                 'database-check', 'bundle', '--authorized', '--authority', 'authority.json',
                                 '--target-config', 'target-config.json', '--dsn-env', 'M1_RV2_TARGET_DSN'],
                                text=True, capture_output=True, timeout=60, check=False)
        self.capture('cli-process', dict(returncode=result.returncode, stdout=result.stdout, stderr=result.stderr))
        self.assertEqual(result.returncode, 0, result.stderr)
        pointer = json.loads(result.stdout)
        receipt = json.loads(Path(pointer['path']).read_text(encoding='utf-8'))
        self.assertEqual(receipt['payload']['observation']['execution_status'], 'committed_readback', receipt)
        self.assertEqual((self.bundle / 'manifest.json').read_bytes(), original_manifest)

    def test_all_five_target_arms_grade_real_controlled_effects(self):
        """what_bug_this_catches: fake negative flags or ACK claims clear W7 grading."""
        from la.postgres import (prepare_evaluation_candidate_v2,
                                 observer_code_pin, collect_target_experiment, target_experiment_callbacks,
                                 reconcile_target_experiment, target_reconciliation_callbacks)
        from postgres.test_target_candidates import ephemeral_signer
        from postgres.test_controlled_target import phase_intent
        from review.support import proposal
        from evaluation.target_effects import TargetExpectation, grade_target, STATES
        from evaluation.scorer import REF_KEYS
        types = {'account_ref': 'text', 'description': 'text', 'balance': 'decimal',
                 'effective_date': 'date', 'status': 'text'}
        literal_values = [
            dict(account_ref='0007', description='AB', balance='0.00', effective_date='2024-02-29', status='A'),
            dict(account_ref='0007', description='', balance='1.23', effective_date='2024-03-01', status='B'),
            dict(account_ref='0007', description='AB', balance='0.00', effective_date='2024-02-29', status='A')]
        oracle = [dict(record_ref={key: row[key] for key in REF_KEYS}, expected_outcome='converted', reasons=[],
                       fields={name: dict(data_type=types[name], value=value) for name, value in values.items()})
                  for row, values in zip(self.batch['records'], literal_values, strict=True)]
        columns = [['source_sha256', 'text', 'NO', None, None], ['ordinal', 'bigint', 'NO', 64, 0],
                   ['raw_sha256', 'text', 'NO', None, None], ['account_ref', 'text', 'NO', None, None],
                   ['description', 'text', 'NO', None, None], ['balance', 'numeric', 'NO', 6, 2],
                   ['effective_date', 'date', 'NO', None, None], ['status', 'text', 'NO', None, None]]
        for method in ('B0', 'B1', 'C0', 'R0', 'R1'):
            with self.subTest(method=method):
                artifact = prepare_evaluation_candidate_v2(self.batch, proposal(self.batch, self.generation, method),
                             edition='public-rv2-target-regression', evaluation_phase='T1', split='development',
                             evaluation_plan_sha256=digest('PB-M1-R03-public-target-plan'))
                verifier, sign = ephemeral_signer(self)
                body = phase_intent(artifact)
                authority = sign(body)
                config = replace(self.config_base, authority_reference=body['authority_sha256'],
                                 expected_candidate_sha256=artifact['descriptor']['candidate_sha256'])
                self.capture(method + '-public-reproduction-inputs', dict(
                    artifact=artifact, signed_authority=authority, target_config=config.public(),
                    artifact_sha256=digest(artifact), authority_envelope_sha256=digest(authority),
                    observer_code_sha256=observer_code_pin(), trusted_issuers=verifier.trusted_issuers,
                    public_keys_hex={key: value.hex() for key, value in verifier.public_keys.items()}))
                kwargs = dict(dsn=self.dsn, target_config=config, authority_verifier=verifier)
                capture_root = self.root / ('facade-' + method); capture_root.mkdir()
                manifest = collect_target_experiment(artifact, authority, capture_root=capture_root,
                                                     experiment_id='actual', **kwargs)
                experiment = capture_root / 'actual'
                original_manifest = (experiment / 'experiment.json').read_bytes()
                callbacks = target_experiment_callbacks(experiment,
                    expected_experiment_sha256=manifest['experiment_sha256'],
                    expected_candidate_sha256=artifact['descriptor']['candidate_sha256'],
                    expected_authority_sha256=body['authority_sha256'])
                with patch('la.postgres.runner.driver_and_connect', side_effect=AssertionError('offline callbacks must not connect')):
                    positive = callbacks.observe(artifact, authority)
                    failed = callbacks.failed_load(artifact, authority)
                    pair = callbacks.recovery(artifact, authority)
                self.capture(method + '-manifest', manifest)
                target = dict(database='m1_rv2', role='m1_rv2', host='172.17.0.8', port=21800,
                              connection_host='127.0.0.1', connection_port=21800, server_version_num=170006,
                              authority_reference=body['authority_sha256'], scope='disposable_local_test',
                              driver_version='3.3.6')
                expected = TargetExpectation(artifact['descriptor'], body['authority_sha256'], digest(config.public()),
                                             observer_code_pin(), target, columns)
                result = grade_target(oracle, positive, expectation=expected, prior=pair['prior'],
                                      failed_load=failed, recovery_observation=pair['reconciled'])
                self.capture(method + '-independent-grade', result)
                self.assertEqual(result['target_validation'], 'passed', result)
                self.assertEqual(result['product_acceptance'], 'pending')
                for kind in STATES:
                    changed = deepcopy(positive)
                    changed['negative_effects'] = [effect for effect in changed['negative_effects']
                                                   if effect['probe_kind'] != kind]
                    changed['observation_sha256'] = digest({k: v for k, v in changed.items() if k != 'observation_sha256'})
                    rejected = grade_target(oracle, changed, expectation=expected, prior=pair['prior'],
                                            failed_load=failed, recovery_observation=pair['reconciled'])
                    self.assertNotEqual(rejected['target_validation'], 'passed', kind)
                missing_prior = grade_target(oracle, positive, expectation=expected, prior=None,
                                             failed_load=failed, recovery_observation=pair['reconciled'])
                self.assertNotEqual(missing_prior['target_validation'], 'passed')
                with self.assertRaises(ValueError):
                    target_experiment_callbacks(experiment, expected_experiment_sha256='0' * 64,
                        expected_candidate_sha256=artifact['descriptor']['candidate_sha256'],
                        expected_authority_sha256=body['authority_sha256'])
                with patch('la.postgres.runner._observe_candidate', side_effect=AssertionError('later recovery must not load')):
                    record = reconcile_target_experiment(experiment, artifact, authority,
                        expected_experiment_sha256=manifest['experiment_sha256'], **kwargs)
                    second = reconcile_target_experiment(experiment, artifact, authority,
                        expected_experiment_sha256=manifest['experiment_sha256'],
                        previous_reconciliation_sha256=record['reconciliation_sha256'], **kwargs)
                selected = target_reconciliation_callbacks(experiment, artifact, authority,
                    expected_experiment_sha256=manifest['experiment_sha256'],
                    expected_reconciliation_sha256=second['reconciliation_sha256'],
                    expected_prior_observation_sha256=pair['prior']['observation_sha256'],
                    target_config=config, authority_verifier=verifier)
                later = selected.recovery(artifact, authority)
                later_grade = grade_target(oracle, selected.observe(artifact, authority), expectation=expected,
                    prior=later['prior'], failed_load=selected.failed_load(artifact, authority),
                    recovery_observation=later['reconciled'])
                self.capture(method + '-later-recovery-grade', later_grade)
                self.capture(method + '-later-recovery-selection', selected.projection())
                self.assertEqual(later_grade['target_validation'], 'passed', later_grade)
                self.assertEqual((experiment / 'experiment.json').read_bytes(), original_manifest)


if __name__ == '__main__':
    unittest.main()

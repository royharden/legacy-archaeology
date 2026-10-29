"""what_bug_this_catches: latest/fallback selection, wrong lineage and relabelled ACKs.

Synthetic wires below exercise offline consumers only; they are never execution
evidence. Disposable actual journeys remain separately opted in and unexecuted.
"""
from copy import deepcopy
from dataclasses import replace
import unittest
from unittest.mock import patch

from la.postgres import (collect_target_experiment, open_target_reconciliation,
                         reconcile_target_experiment, target_experiment_callbacks,
                         target_reconciliation_callbacks, target_observer_v2)
from la.postgres.effects import seal_observation
from la.review import canonical, digest
from evaluation.target_runner import TargetPorts
from postgres import test_target_experiment as experiment_support


class RecoverySelection(unittest.TestCase):
    def setUp(self):
        experiment_support.ExperimentGuards.setUp(self)
        missing = target_observer_v2(self.artifact, self.authority, target_config=self.config, authority_verifier=self.verifier)
        self.prior = {k: deepcopy(v) for k, v in missing.items() if k != 'observation_sha256'}
        self.prior.update(commit_state='indeterminate', target=dict(database='disposable', role='leastpriv', host='127.0.0.1',
            port=5432, server_version_num=170000, authority_reference=self.body['authority_sha256'],
            scope='disposable_local_test', driver_version='pinned-future-driver'), issues=[{'code': 'commit_acknowledgement_unknown'}])
        self.prior['attempt']['write_connection_id'] = digest('synthetic write connection, not execution evidence')
        self.prior = seal_observation(self.prior)
        with patch('la.postgres.experiment.target_observer_v2', return_value=missing), \
             patch('la.postgres.experiment.collect_controlled_failed_load', side_effect=OSError('synthetic omitted capture')), \
             patch('la.postgres.experiment.collect_controlled_ack_predecessor', return_value=self.prior), \
             patch('la.postgres.experiment.reconcile_target_candidate', return_value=self.later('original')):
            self.manifest = collect_target_experiment(self.artifact, self.authority, capture_root=self.root,
                experiment_id='original', dsn='synthetic-never-connect', target_config=self.config, authority_verifier=self.verifier)
        self.path = self.root / 'original'

    def later(self, nonce):
        value = {k: deepcopy(v) for k, v in self.prior.items() if k != 'observation_sha256'}
        value['attempt'].update(attempt_id=digest(nonce)[:32], prior_observation_sha256=self.prior['observation_sha256'])
        value['issues'] = [{'code': 'durable_commit_not_reconciled', 'error_type': 'SyntheticReadFailure'}]
        return seal_observation(value)

    def produce(self, *, nonce='later', previous=None, dsn='synthetic-never-connect'):
        with patch('la.postgres.experiment.reconcile_target_candidate', return_value=self.later(nonce)):
            return reconcile_target_experiment(self.path, self.artifact, self.authority,
                expected_experiment_sha256=self.manifest['experiment_sha256'], dsn=dsn,
                target_config=self.config, authority_verifier=self.verifier, previous_reconciliation_sha256=previous)

    def pins(self, record):
        return dict(expected_experiment_sha256=self.manifest['experiment_sha256'],
                    expected_reconciliation_sha256=record['reconciliation_sha256'],
                    expected_prior_observation_sha256=self.prior['observation_sha256'],
                    target_config=self.config, authority_verifier=self.verifier)

    def open(self, record, **changes):
        pins = self.pins(record); pins.update(changes)
        return open_target_reconciliation(self.path, self.artifact, self.authority, **pins)

    def publish_changed(self, record, **changes):
        value = dict(deepcopy(record), **changes)
        value['reconciliation_sha256'] = digest({k: v for k, v in value.items() if k != 'reconciliation_sha256'})
        (self.path / 'reconciliations' / ('record-' + value['reconciliation_sha256'] + '.json')).write_text(canonical(value), encoding='utf-8')
        return value

    def test_explicit_selection_preserves_unsuccessful_chain_and_original_callbacks(self):
        original = target_experiment_callbacks(self.path, expected_experiment_sha256=self.manifest['experiment_sha256'])
        original_pair = original.recovery(self.artifact, self.authority)
        first = self.produce()
        second = self.produce(previous=first['reconciliation_sha256'], dsn=None)
        before = (self.path / 'experiment.json').read_bytes()
        with patch('la.postgres.experiment.target_observer_v2', side_effect=AssertionError('reader must never load')), \
             patch('la.postgres.runner.driver_and_connect', side_effect=AssertionError('reader must never connect')):
            chosen = target_reconciliation_callbacks(self.path, self.artifact, self.authority, **self.pins(second))
            first_chosen = target_reconciliation_callbacks(self.path, self.artifact, self.authority, **self.pins(first))
        ports = TargetPorts(lambda *args: self.artifact, lambda *args: None,
                            chosen.observe, chosen.failed_load, chosen.recovery)
        self.assertEqual(ports.observe(self.artifact, self.authority), original.observe(self.artifact, self.authority))
        self.assertIsNone(ports.failed_load(self.artifact, self.authority))
        self.assertIsNone(ports.recovery(self.artifact, self.authority)['reconciled'])
        self.assertEqual(first_chosen.recovery(self.artifact, self.authority)['reconciled']['commit_state'], 'indeterminate')
        self.assertEqual(original.recovery(self.artifact, self.authority), original_pair)
        self.assertEqual((self.path / 'experiment.json').read_bytes(), before)
        projection = chosen.projection()
        self.assertEqual([r['capture_status'] for r in projection['history']], ['captured', 'not_run'])
        self.assertEqual(projection['history'][0]['commit_state'], 'indeterminate')
        self.assertEqual(projection['source_label'], 'unknown_driver_commit_acknowledgement')
        self.assertEqual(projection['target_validation'], 'not_run')
        self.assertEqual(projection['product_acceptance'], 'pending')

    def test_parent_prior_candidate_authority_config_and_code_mismatches_refuse(self):
        record = self.produce()
        for name in ('parent_experiment_sha256', 'prior_observation_sha256', 'candidate_sha256',
                     'authority_sha256', 'target_config_sha256', 'observer_code_sha256'):
            changed = self.publish_changed(record, **{name: 'f' * 64})
            with self.subTest(name=name), self.assertRaises(ValueError): self.open(changed)
        with self.assertRaises(ValueError): self.open(record, expected_prior_observation_sha256='e' * 64)
        with self.assertRaises(ValueError): self.open(record, target_config=replace(self.config, driver_version='other'))
        artifact = deepcopy(self.artifact); artifact['batch']['records'] = []
        with self.assertRaises(ValueError): open_target_reconciliation(self.path, artifact, self.authority, **self.pins(record))
        body = dict(self.body, evaluation_plan_sha256='f' * 64)
        body['authority_sha256'] = digest({k: v for k, v in body.items() if k != 'authority_sha256'})
        with self.assertRaises(ValueError): open_target_reconciliation(self.path, self.artifact, self.sign(body), **self.pins(record))
        pins = self.pins(record); pins.pop('expected_reconciliation_sha256')
        with self.assertRaises(TypeError): open_target_reconciliation(self.path, self.artifact, self.authority, **pins)

    def test_omission_traversal_unknown_fields_and_member_tamper_refuse(self):
        record = self.produce()
        for changes in ({'capture': None}, {'passed': True}, {'schema_version': True},
                        {'capture': dict(record['capture'], file='../outside.json')},
                        {'capture': dict(record['capture'], file='reconciliations/x:stream')},
                        {'previous_reconciliation_sha256': 'not-a-pin'}):
            changed = self.publish_changed(record, **changes)
            with self.subTest(changes=changes), self.assertRaises((ValueError, FileNotFoundError)): self.open(changed)
        member = self.path / record['capture']['file']; member.write_bytes(member.read_bytes() + b' ')
        with self.assertRaises(ValueError): self.open(record)

    def test_legacy_record_is_read_without_fabricated_ordering(self):
        current = self.produce()
        value = deepcopy(current); value.pop('previous_reconciliation_sha256'); value['schema_version'] = 1
        legacy = self.publish_changed(value)
        snapshot = self.open(legacy)
        self.assertEqual(len(snapshot.records), 1)
        self.assertNotIn('previous_reconciliation_sha256', snapshot.selected)
        self.assertEqual(snapshot.observation, self.later('later'))

    def test_missing_chain_parent_and_duplicate_attempt_do_not_get_dropped(self):
        first = self.produce()
        missing = self.publish_changed(first, previous_reconciliation_sha256='f' * 64)
        with self.assertRaises(FileNotFoundError): self.open(missing)
        duplicate = self.publish_changed(first, previous_reconciliation_sha256=first['reconciliation_sha256'])
        with self.assertRaises(ValueError): self.open(duplicate)

    def test_conflicting_recovery_source_label_is_rejected(self):
        record = self.produce()
        value = self.later('wrong-source')
        value['issues'] = [{'code': 'reconciled_known_commit_readback'}]
        value = seal_observation({k: v for k, v in value.items() if k != 'observation_sha256'})
        from la.postgres.effects import write_target_observation
        relative = 'reconciliations/observation-' + value['observation_sha256'] + '.json'
        receipt = write_target_observation(self.path / relative, value)
        changed = self.publish_changed(record, capture=dict(record['capture'], file=relative,
            sha256=receipt['sha256'], observation_sha256=value['observation_sha256'], attempt_id=value['attempt']['attempt_id']))
        with self.assertRaises(ValueError): self.open(changed)

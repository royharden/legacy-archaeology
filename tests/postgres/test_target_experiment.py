"""what_bug_this_catches: capture loss, implicit execution, wrong phase/pins and replay loads.

Future regression SOURCE only. Mocked missing captures never count as DB evidence.
Actual disposable journeys are in test_execution_boundaries, behind its explicit switch.
"""
from copy import deepcopy
from dataclasses import replace
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from la.postgres import (TargetConfig, collect_target_experiment, open_target_experiment,
                         target_experiment_callbacks, reconcile_target_experiment,
                         prepare_evaluation_candidate_v2, target_observer_v2)
from la.review import canonical, digest
from evaluation.target_effects import TargetExpectation, grade_target
from evaluation.target_runner import TargetPorts
from postgres.test_controlled_target import phase_intent
from postgres.test_target_candidates import ephemeral_signer
from review.support import fixture, proposal


def declared_oracle(batch):
    # Values declared from the literal public source fixture, never converter output.
    values = [('AB', '0.00', '2024-02-29', 'A'), ('', '1.23', '2024-03-01', 'B'),
              ('AB', '0.00', '2024-02-29', 'A')]
    rows = []
    for record, (description, balance, day, status) in zip(batch['records'], values):
        ref = {key: record[key] for key in ('source_sha256', 'framing_sha256', 'ordinal', 'byte_start', 'length', 'raw_sha256')}
        fields = {name: {'data_type': kind, 'value': value} for name, kind, value in (
            ('account_ref', 'text', '0007'), ('description', 'text', description),
            ('balance', 'decimal', balance), ('effective_date', 'date', day), ('status', 'text', status))}
        rows.append({'record_ref': ref, 'expected_outcome': 'converted', 'fields': fields, 'reasons': []})
    return rows


def declared_columns():
    return [['source_sha256', 'text', 'NO', None, None], ['ordinal', 'bigint', 'NO', 64, 0],
            ['raw_sha256', 'text', 'NO', None, None], ['account_ref', 'text', 'NO', None, None],
            ['description', 'text', 'NO', None, None], ['balance', 'numeric', 'NO', 6, 2],
            ['effective_date', 'date', 'NO', None, None], ['status', 'text', 'NO', None, None]]


class ExperimentGuards(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.batch, generation = fixture()
        self.artifact = prepare_evaluation_candidate_v2(self.batch, proposal(self.batch, generation),
            edition='public-experiment-regression', evaluation_phase='T1', split='development',
            evaluation_plan_sha256=digest('public development plan'))
        self.verifier, self.sign = ephemeral_signer(self)
        self.body = phase_intent(self.artifact); self.authority = self.sign(self.body)
        self.config = TargetConfig(self.body['authority_sha256'], 'disposable', 'leastpriv', 'pinned-future-driver', 17,
                                   expected_candidate_sha256=self.artifact['descriptor']['candidate_sha256'])

    def collect(self, **kwargs):
        args = dict(capture_root=self.root, experiment_id='case', target_config=self.config, authority_verifier=self.verifier)
        args.update(kwargs)
        return collect_target_experiment(self.artifact, self.authority, **args)

    def open(self, manifest, **kwargs):
        return open_target_experiment(self.root / 'case', expected_experiment_sha256=manifest['experiment_sha256'], **kwargs)

    def test_no_dsn_never_invokes_any_collector_and_keeps_neutral_receipt(self):
        with patch('la.postgres.experiment.target_observer_v2', side_effect=AssertionError('no implicit load')):
            manifest = self.collect()
        self.assertEqual(manifest['capture_status'], 'not_run')
        self.assertEqual(manifest['captures'], [])
        self.assertEqual(manifest['target_validation'], 'not_run')
        self.assertEqual(manifest['product_acceptance'], 'pending')
        self.assertEqual(self.open(manifest).observations, {})
        before = (self.root / 'case' / 'experiment.json').read_bytes()
        with self.assertRaises(FileExistsError): self.collect()
        self.assertEqual((self.root / 'case' / 'experiment.json').read_bytes(), before)

    def test_each_missing_signed_operation_refuses_before_collecting(self):
        for index, operation in enumerate(self.body['operations']):
            body = phase_intent(self.artifact, operations=tuple(op for op in self.body['operations'] if op != operation))
            config = replace(self.config, authority_reference=body['authority_sha256'])
            with patch('la.postgres.experiment.target_observer_v2', side_effect=AssertionError('must preflight all rights')):
                manifest = collect_target_experiment(self.artifact, self.sign(body), capture_root=self.root,
                    experiment_id='missing_' + str(index), dsn='never-used', target_config=config, authority_verifier=self.verifier)
            self.assertEqual(manifest['capture_status'], 'refused')
            self.assertEqual(manifest['captures'], [])

    def test_wrong_phase_source_or_candidate_authority_refuses(self):
        for index, (key, value) in enumerate((('evaluation_plan_sha256', 'f' * 64), ('split', 'heldout'),
                                             ('source_sha256', 'e' * 64), ('candidate_sha256', 'd' * 64))):
            body = dict(self.body, **{key: value})
            body['authority_sha256'] = digest({k: v for k, v in body.items() if k != 'authority_sha256'})
            manifest = collect_target_experiment(self.artifact, self.sign(body), capture_root=self.root,
                experiment_id='wrong_' + str(index), target_config=replace(self.config, authority_reference=body['authority_sha256']),
                authority_verifier=self.verifier)
            self.assertEqual(manifest['capture_status'], 'refused')

    def test_external_pin_manifest_bytes_and_capture_path_cannot_be_substituted(self):
        manifest = self.collect()
        with self.assertRaises(ValueError): self.open(manifest, expected_candidate_sha256='f' * 64)
        with self.assertRaises(ValueError):
            open_target_experiment(self.root / 'case', expected_experiment_sha256='f' * 64)
        path = self.root / 'case' / 'experiment.json'
        changed = deepcopy(manifest); changed['capture_status'] = 'collected'
        path.write_text(canonical(changed), encoding='utf-8')
        with self.assertRaises(ValueError): self.open(manifest)
        # Even re-pinning a malformed manifest must not turn no captures into collected.
        changed['experiment_sha256'] = digest({k: v for k, v in changed.items() if k != 'experiment_sha256'})
        path.write_text(canonical(changed), encoding='utf-8')
        with self.assertRaises(ValueError): self.open(changed)

    def test_partial_failure_keeps_prior_raw_capture_and_no_synthetic_recovery(self):
        missing = target_observer_v2(self.artifact, self.authority, target_config=self.config, authority_verifier=self.verifier)
        with patch('la.postgres.experiment.target_observer_v2', return_value=missing), \
             patch('la.postgres.experiment.collect_controlled_failed_load', side_effect=OSError('private DSN must not leak')), \
             patch('la.postgres.experiment.collect_controlled_ack_predecessor', side_effect=OSError('private')):
            manifest = self.collect(dsn='explicit-but-mocked')
        snapshot = self.open(manifest)
        self.assertEqual(manifest['capture_status'], 'partial')
        self.assertEqual(snapshot.observations['normal_readback'], missing)
        self.assertEqual(snapshot.observations['normal']['commit_state'], 'not_run')
        self.assertNotIn('private', json.dumps(manifest))
        callbacks = target_experiment_callbacks(snapshot.root, expected_experiment_sha256=manifest['experiment_sha256'])
        ports = TargetPorts(prepare=lambda *args: self.artifact, grant=lambda *args: None,
                            observe=callbacks.observe, failed_load=callbacks.failed_load, recovery=callbacks.recovery)
        self.assertEqual(ports.observe(self.artifact, self.authority), snapshot.observations['normal'])
        self.assertIsNone(ports.failed_load(self.artifact, self.authority))
        self.assertIsNone(ports.recovery(self.artifact, self.authority))
        changed = deepcopy(self.artifact); changed['batch']['records'] = []
        with self.assertRaises(ValueError): ports.observe(changed, self.authority)
        with self.assertRaises(ValueError): ports.observe(self.artifact, dict(self.authority, signature='0' * 128))
        returned = ports.observe(self.artifact, self.authority); returned['issues'].append({'code': 'caller_mutation'})
        self.assertNotEqual(returned, ports.observe(self.artifact, self.authority))
        record = next(r for r in manifest['captures'] if r['role'] == 'normal_readback')
        member = snapshot.root / record['file']; member.write_bytes(member.read_bytes() + b' ')
        with self.assertRaises(ValueError): self.open(manifest)

    def test_actual_d6_grade_remains_not_run_without_an_observation(self):
        manifest = self.collect()
        callbacks = target_experiment_callbacks(self.root / 'case', expected_experiment_sha256=manifest['experiment_sha256'])
        target = dict(database='disposable', role='leastpriv', host='127.0.0.1', port=5432,
                      server_version_num=170000, authority_reference=self.body['authority_sha256'],
                      scope='disposable_local_test', driver_version='pinned-future-driver')
        expectation = TargetExpectation(self.artifact['descriptor'], self.body['authority_sha256'],
                                       digest(self.config.public()), manifest['observer_code_sha256'], target, declared_columns())
        grade = grade_target(declared_oracle(self.batch), callbacks.observe(self.artifact, self.authority), expectation=expectation)
        self.assertEqual(grade['target_validation'], 'not_run')
        self.assertEqual(grade['product_acceptance'], 'pending')

    def test_repeated_missing_predecessor_reconciliation_never_loads(self):
        manifest = self.collect(); before = (self.root / 'case' / 'experiment.json').read_bytes()
        with patch('la.postgres.experiment.target_observer_v2', side_effect=AssertionError('no load')), \
             patch('la.postgres.experiment.reconcile_target_candidate', side_effect=AssertionError('no predecessor')):
            records = [reconcile_target_experiment(self.root / 'case', self.artifact, self.authority,
                expected_experiment_sha256=manifest['experiment_sha256'], dsn='must-not-connect',
                target_config=self.config, authority_verifier=self.verifier) for _ in range(2)]
        self.assertEqual(records[0], records[1])
        self.assertEqual(records[0]['capture_status'], 'not_run')
        self.assertEqual((self.root / 'case' / 'experiment.json').read_bytes(), before)

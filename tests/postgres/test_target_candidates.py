"""what_bug_this_catches: evaluator arms fabricating product approval or trusting flags.

Ephemeral in-memory test signing keys are created only by future test execution,
never now, never from credential files and never for external accounts.
"""
from copy import deepcopy
from dataclasses import replace
import tempfile
from pathlib import Path
import unittest
from unittest.mock import patch

from la.convert import approve_mapping
from la.postgres import (TargetAuthorityVerifier, TargetConfig, observer_code_pin,
                         prepare_evaluation_candidate, reconcile_target_candidate,
                         target_observer_v2, validate_negative_effect,
                         validate_target_observation, write_target_observation)
from la.postgres.effects import seal_observation
from la.review import canonical, digest
from review.support import fixture, proposal


def ephemeral_signer(testcase):
    try:
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    except ImportError:
        testcase.skipTest('optional cryptography not installed; no auto-install')
    key = Ed25519PrivateKey.generate()
    public = key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    verifier = TargetAuthorityVerifier({'test-key': ('ephemeral-test-issuer', 'target_authority')}, {'test-key': public})
    def sign(payload):
        return {'schema_version': 1, 'algorithm': 'Ed25519', 'issuer': 'ephemeral-test-issuer',
                'key_id': 'test-key', 'role': 'target_authority', 'payload': deepcopy(payload),
                'payload_sha256': digest(payload), 'signature': key.sign(canonical(payload).encode()).hex()}
    return verifier, sign


def intent(candidate, operations=('load', 'reconcile', 'negative_probes')):
    descriptor = candidate['descriptor']
    body = {'schema_version': 1, 'kind': 'disposable_target_authority', 'authority_id': 'ephemeral-public-regression',
            'scope': 'disposable_evaluation', 'candidate_sha256': descriptor['candidate_sha256'],
            'source_sha256': descriptor['source_sha256'], 'method': descriptor['method'],
            'edition': descriptor['edition'], 'freeze_sha256': descriptor['freeze_sha256'],
            'observer_code_sha256': observer_code_pin(), 'operations': list(operations)}
    body['authority_sha256'] = digest(body)
    return body


class CandidateSeparation(unittest.TestCase):
    def setUp(self):
        self.batch, self.generation = fixture()

    def test_every_arm_gets_same_policy_converter_without_product_history(self):
        rows = []
        for method in ('B0', 'B1', 'C0', 'R0', 'R1'):
            artifact = prepare_evaluation_candidate(self.batch, proposal(self.batch, self.generation, method),
                                                     edition='public-regression', freeze_sha256=digest('public freeze'))
            descriptor = artifact['descriptor']
            self.assertFalse(descriptor['product_loadable'])
            self.assertEqual(descriptor['product_approval'], 'absent')
            self.assertEqual(descriptor['counts'], {'converted': 3, 'unresolved': 0, 'quarantined': 0})
            rows.append(descriptor['schema_sha256'])
            with self.assertRaises(ValueError): approve_mapping(artifact, 'test_author', 'cannot approve evaluation artifact')
        self.assertEqual(len(set(rows)), 1)

    def test_incomplete_proposal_abstains_before_any_target_candidate(self):
        incomplete = proposal(self.batch, self.generation); incomplete['fields'].pop()
        incomplete['proposal_sha256'] = digest({k: v for k, v in incomplete.items() if k != 'proposal_sha256'})
        with self.assertRaises(ValueError):
            prepare_evaluation_candidate(self.batch, incomplete, edition='public', freeze_sha256=digest('freeze'))

    def test_actual_driver_statement_trace_uses_last_command_even_when_it_errors(self):
        # what_bug_this_catches: reporting a planned INSERT hash for a failed DDL/query.
        from decimal import Decimal
        from la.postgres.target import StatementTrace
        class Cursor:
            def execute(self, sql, parameters=None):
                if sql == 'SELECT 1/0': raise ZeroDivisionError('fake driver error; not target evidence')
        trace = StatementTrace(Cursor())
        trace.execute('SELECT %s', (Decimal('1.23'),))
        first = trace.last_statement_sha256
        self.assertEqual(first, digest({'sql': 'SELECT %s', 'parameters': ['1.23']}))
        with self.assertRaises(ZeroDivisionError): trace.execute('SELECT 1/0')
        self.assertNotEqual(trace.last_statement_sha256, first)
        self.assertEqual(trace.last_statement_sha256, digest({'sql': 'SELECT 1/0', 'parameters': None}))


class SignedTargetScope(unittest.TestCase):
    def setUp(self):
        batch, generation = fixture()
        self.artifact = prepare_evaluation_candidate(batch, proposal(batch, generation), edition='public-regression', freeze_sha256=digest('public freeze'))
        self.body = intent(self.artifact)
        self.verifier, self.sign = ephemeral_signer(self)
        self.config = TargetConfig(self.body['authority_sha256'], 'disposable', 'leastpriv', 'future-pinned-driver', 17,
                                   expected_candidate_sha256=self.artifact['descriptor']['candidate_sha256'])

    def observe(self, *, body=None, config=None, negatives=()):
        return target_observer_v2(self.artifact, self.sign(body or self.body), dsn=None,
                                  target_config=config or self.config, negative_kinds=negatives,
                                  authority_verifier=self.verifier)

    def test_valid_signed_no_dsn_is_not_run_and_never_calls_driver(self):
        with patch('la.postgres.runner.driver_and_connect', side_effect=AssertionError('must not connect')):
            observed = self.observe()
        self.assertEqual(observed['commit_state'], 'not_run')
        self.assertIsNone(observed['target'])
        self.assertIsNone(observed['readback'])
        self.assertEqual(observed['negative_effects'], [])
        self.assertNotIn('passed', observed)
        self.assertNotIn('product_acceptance', observed)

    def test_rehashed_payload_without_new_signature_is_not_authority(self):
        envelope = self.sign(self.body)
        envelope['payload']['source_sha256'] = 'f' * 64
        envelope['payload']['authority_sha256'] = digest({k: v for k, v in envelope['payload'].items() if k != 'authority_sha256'})
        envelope['payload_sha256'] = digest(envelope['payload'])
        with self.assertRaises(ValueError):
            target_observer_v2(self.artifact, envelope, target_config=self.config, authority_verifier=self.verifier)

    def test_true_flags_and_callback_verifier_are_rejected(self):
        with self.assertRaises(ValueError):
            target_observer_v2(self.artifact, {'authorized': True, 'passed': True},
                               target_config=self.config, authority_verifier=lambda *args: True)
        body = dict(self.body, passed=True)
        body['authority_sha256'] = digest({k: v for k, v in body.items() if k != 'authority_sha256'})
        with self.assertRaises(ValueError): self.observe(body=body, config=replace(self.config, authority_reference=body['authority_sha256']))

    def test_signed_wrong_source_method_edition_freeze_scope_and_observer_pins_fail(self):
        replacements = {'source_sha256': 'f' * 64, 'method': 'B1', 'edition': 'other-edition',
                        'freeze_sha256': 'e' * 64, 'scope': 'product_bundle', 'observer_code_sha256': 'd' * 64}
        for name, value in replacements.items():
            body = dict(self.body, **{name: value})
            body['authority_sha256'] = digest({k: v for k, v in body.items() if k != 'authority_sha256'})
            with self.subTest(name=name), self.assertRaises(ValueError):
                self.observe(body=body, config=replace(self.config, authority_reference=body['authority_sha256']))

    def test_external_candidate_pin_cannot_be_borrowed_from_manifest(self):
        with self.assertRaises(ValueError): self.observe(config=replace(self.config, expected_candidate_sha256=None))
        with self.assertRaises(ValueError): self.observe(config=replace(self.config, expected_candidate_sha256='f' * 64))

    def test_negative_probes_need_their_own_signed_operation_grant(self):
        body = intent(self.artifact, operations=('load',))
        config = replace(self.config, authority_reference=body['authority_sha256'])
        with self.assertRaises(ValueError): self.observe(body=body, config=config, negatives=('rollback',))

    def test_wire_cannot_upgrade_no_run_to_committed_without_actual_readback(self):
        observed = self.observe()
        changed = {k: deepcopy(v) for k, v in observed.items() if k != 'observation_sha256'}
        changed['commit_state'] = 'committed'
        with self.assertRaises(ValueError): validate_target_observation(seal_observation(changed))
        changed = {k: deepcopy(v) for k, v in observed.items() if k != 'observation_sha256'}
        changed['oracle_success'] = True
        with self.assertRaises(ValueError): validate_target_observation(seal_observation(changed))

    def test_recovery_rejects_no_write_or_wrong_attempt_without_loading(self):
        observed = self.observe()
        with patch('la.postgres.runner.driver_and_connect', side_effect=AssertionError('must not connect')):
            with self.assertRaises(ValueError):
                reconcile_target_candidate(self.artifact, self.sign(self.body), observed,
                                           target_config=self.config, authority_verifier=self.verifier)

    def test_target_observation_publication_is_immutable_and_outside_bundle(self):
        observed = self.observe()
        with tempfile.TemporaryDirectory() as root:
            path = Path(root) / 'observed.json'
            write_target_observation(path, observed)
            before = path.read_bytes()
            with self.assertRaises(FileExistsError): write_target_observation(path, observed)
            self.assertEqual(path.read_bytes(), before)
            bundle = Path(root) / 'bundle'; bundle.mkdir(); (bundle / 'manifest.json').write_text('{}')
            with self.assertRaises(ValueError): write_target_observation(bundle / 'observed.json', observed)

    def test_missing_negative_effects_cannot_be_replaced_by_rollback_ok_flag(self):
        observed = self.observe()
        effect = {'rollback_ok': True, 'constraints_ok': True, 'lost_ack_ok': True}
        with self.assertRaises(ValueError): validate_negative_effect(effect)
        modified = {k: deepcopy(v) for k, v in observed.items() if k != 'observation_sha256'}
        modified['negative_effects'] = [effect]
        with self.assertRaises(ValueError): validate_target_observation(seal_observation(modified))

    def test_failed_load_rollback_label_without_actual_after_query_is_rejected(self):
        observed = self.observe()
        effect = {'schema_version': 1, 'kind': 'negative_effect', 'probe_kind': 'failed_load',
                  'candidate_sha256': observed['candidate']['candidate_sha256'],
                  'source_sha256': observed['candidate']['source_sha256'],
                  'authority_sha256': observed['authority_sha256'],
                  'target_config_sha256': observed['target_config_sha256'],
                  'observer_code_sha256': observed['observer_code_sha256'],
                  'execution_id': observed['attempt']['execution_id'], 'attempt_id': '1' * 32,
                  'namespace': 'la_' + '2' * 32, 'target': None, 'before': None,
                  'transaction': None, 'after': None, 'transaction_state': 'rolled_back', 'issues': []}
        effect['effect_sha256'] = digest(effect)
        with self.assertRaises(ValueError): validate_negative_effect(effect)

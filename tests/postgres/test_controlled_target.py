"""what_bug_this_catches: fake failure evidence, implicit probe rights and T1/T3 escalation.

Source only in Dirty Mode. Signers are ephemeral future test keys, never accounts.
"""
from copy import deepcopy
from dataclasses import replace
import unittest
from unittest.mock import patch

from la.postgres import (TargetConfig, collect_controlled_failed_load, collect_controlled_lost_ack,
                         prepare_evaluation_candidate, prepare_evaluation_candidate_v2,
                         reconcile_target_candidate, target_observer_v2, validate_target_observation)
from la.postgres.effects import seal_observation
from la.review import digest
from postgres.test_target_candidates import ephemeral_signer, intent
from review.support import fixture, proposal


def phase_intent(artifact, operations=('load', 'negative_probes', 'reconcile', 'controlled_failed_load', 'controlled_commit_ack')):
    body = intent(artifact, operations=operations)
    descriptor = artifact['descriptor']
    body['schema_version'] = descriptor['schema_version']
    if descriptor['schema_version'] == 2:
        body.update({key: descriptor[key] for key in ('evaluation_phase', 'split', 'evaluation_plan_sha256')})
    body['authority_sha256'] = digest({k: v for k, v in body.items() if k != 'authority_sha256'})
    return body


class PhaseSeparation(unittest.TestCase):
    def setUp(self):
        self.batch, self.generation = fixture()
        self.proposal = proposal(self.batch, self.generation)

    def prepare(self, **scope):
        return prepare_evaluation_candidate_v2(self.batch, self.proposal, edition='public-phase-regression', **scope)

    def test_t1_development_validation_binds_plan_and_no_final_freeze(self):
        for split in ('development', 'validation'):
            artifact = self.prepare(evaluation_phase='T1', split=split, evaluation_plan_sha256=digest('development plan'))
            d = artifact['descriptor']
            self.assertEqual(d['schema_version'], 2)
            self.assertEqual(d['evaluation_phase'], 'T1')
            self.assertIsNone(d['freeze_sha256'])
            self.assertEqual(d['evaluation_plan_sha256'], digest('development plan'))
            self.assertFalse(d['product_loadable'])

    def test_t1_heldout_missing_plan_and_freeze_substitution_are_refused(self):
        cases = [dict(evaluation_phase='T1', split='heldout', evaluation_plan_sha256=digest('plan')),
                 dict(evaluation_phase='T1', split='development'),
                 dict(evaluation_phase='T1', split='development', freeze_sha256=digest('not a T1 plan')),
                 dict(evaluation_phase='T1', split='validation', evaluation_plan_sha256=digest('plan'), freeze_sha256=digest('freeze')),
                 dict(evaluation_phase='T2', split='heldout', freeze_sha256=digest('freeze'))]
        for scope in cases:
            with self.subTest(scope=scope), self.assertRaises(ValueError): self.prepare(**scope)

    def test_protected_t3_requires_actual_freeze_field_not_t1_plan(self):
        with self.assertRaises(ValueError): self.prepare(evaluation_phase='T3', split='heldout', evaluation_plan_sha256=digest('plan'))
        with self.assertRaises(ValueError):
            self.prepare(evaluation_phase='T3', split='heldout', evaluation_plan_sha256=digest('plan'), freeze_sha256=digest('freeze'))
        d = self.prepare(evaluation_phase='T3', split='heldout', freeze_sha256=digest('final freeze'))['descriptor']
        self.assertEqual(d['freeze_sha256'], digest('final freeze'))
        self.assertIsNone(d['evaluation_plan_sha256'])

    def test_legacy_frozen_api_is_preserved_and_phase_scope_changes_candidate_identity(self):
        legacy = prepare_evaluation_candidate(self.batch, self.proposal, edition='public-phase-regression', freeze_sha256=digest('freeze'))
        t1 = self.prepare(evaluation_phase='T1', split='development', evaluation_plan_sha256=digest('plan'))
        t3 = self.prepare(evaluation_phase='T3', split='heldout', freeze_sha256=digest('freeze'))
        self.assertEqual(legacy['descriptor']['schema_version'], 1)
        self.assertNotIn('evaluation_phase', legacy['descriptor'])
        self.assertEqual(len({a['descriptor']['candidate_sha256'] for a in (legacy, t1, t3)}), 3)
        self.assertEqual(len({a['descriptor']['schema_sha256'] for a in (legacy, t1, t3)}), 1)

    def test_declared_precision_1000_is_preserved_without_grader_style_narrowing(self):
        from la.convert import sql_artifacts
        value = deepcopy(self.proposal)
        balance = next(field for field in value['fields'] if field['semantic_target'] == 'balance')
        balance['policy']['precision'] = 1000
        value['proposal_sha256'] = digest({k: v for k, v in value.items() if k != 'proposal_sha256'})
        artifact = prepare_evaluation_candidate_v2(self.batch, value, edition='public-precision-regression',
                    evaluation_phase='T1', split='validation', evaluation_plan_sha256=digest('numeric-bound-plan'))
        ddl, _, _ = sql_artifacts({'mapping_status': 'complete', 'fields': artifact['proposal']['fields']})
        self.assertIn('numeric(1000,2)', ddl)
        self.assertEqual(balance['policy']['precision'], 1000)


class ControlledAuthority(unittest.TestCase):
    def setUp(self):
        batch, generation = fixture()
        self.artifact = prepare_evaluation_candidate_v2(batch, proposal(batch, generation), edition='public-phase-regression',
                                                        evaluation_phase='T1', split='development', evaluation_plan_sha256=digest('public plan'))
        self.verifier, self.sign = ephemeral_signer(self)
        self.body = phase_intent(self.artifact)
        self.config = TargetConfig(self.body['authority_sha256'], 'disposable', 'leastpriv', 'future-pinned-driver', 17,
                                   expected_candidate_sha256=self.artifact['descriptor']['candidate_sha256'])

    def failed(self, body=None, config=None):
        return collect_controlled_failed_load(self.artifact, self.sign(body or self.body), target_config=config or self.config,
                                               authority_verifier=self.verifier)

    def lost(self, body=None, config=None):
        return collect_controlled_lost_ack(self.artifact, self.sign(body or self.body), target_config=config or self.config,
                                            authority_verifier=self.verifier)

    def test_no_dsn_failed_load_keeps_no_actual_effect_or_partial_row(self):
        with patch('la.postgres.runner.driver_and_connect', side_effect=AssertionError('must not connect')):
            observed = self.failed()
        self.assertEqual(observed['schema_version'], 3)
        self.assertEqual(observed['commit_state'], 'not_run')
        self.assertEqual(observed['controlled_fault']['state'], 'not_reached')
        self.assertFalse(observed['controlled_fault']['network_loss_claimed'])
        self.assertIsNone(observed['controlled_fault']['partial_write'])
        self.assertEqual(observed['negative_effects'], [])

    def test_no_dsn_ack_collection_does_not_invent_prior_or_reconciled_execution(self):
        pair = self.lost()
        self.assertEqual(set(pair), {'prior', 'reconciled'})
        self.assertEqual(pair['prior']['commit_state'], 'not_run')
        self.assertFalse(pair['prior']['controlled_fault']['driver_commit_returned'])
        self.assertIsNone(pair['reconciled'])

    def test_ordinary_load_and_negative_rights_do_not_grant_controlled_faults(self):
        body = phase_intent(self.artifact, operations=('load', 'negative_probes', 'reconcile'))
        config = replace(self.config, authority_reference=body['authority_sha256'])
        with self.assertRaises(ValueError): self.failed(body, config)
        with self.assertRaises(ValueError): self.lost(body, config)

    def test_ack_collector_requires_reconcile_grant_before_loading(self):
        body = phase_intent(self.artifact, operations=('load', 'controlled_commit_ack'))
        config = replace(self.config, authority_reference=body['authority_sha256'])
        with patch('la.postgres.runner.driver_and_connect', side_effect=AssertionError('must not connect')):
            with self.assertRaises(ValueError): self.lost(body, config)

    def test_signed_wrong_plan_split_or_phase_is_not_a_freeze_escalation(self):
        for key, value in (('evaluation_plan_sha256', 'f' * 64), ('split', 'heldout'), ('evaluation_phase', 'T3'), ('freeze_sha256', 'e' * 64)):
            body = dict(self.body, **{key: value})
            body['authority_sha256'] = digest({k: v for k, v in body.items() if k != 'authority_sha256'})
            config = replace(self.config, authority_reference=body['authority_sha256'])
            with self.subTest(key=key), self.assertRaises(ValueError): self.failed(body, config)

    def test_legacy_authority_cannot_silently_authorize_phase_v2_candidate(self):
        body = intent(self.artifact, operations=('load', 'controlled_failed_load'))
        config = replace(self.config, authority_reference=body['authority_sha256'])
        with self.assertRaises(ValueError): self.failed(body, config)

    def test_unobserved_partial_insert_and_network_failure_claims_are_rejected(self):
        observed = self.failed()
        changed = {k: deepcopy(v) for k, v in observed.items() if k != 'observation_sha256'}
        changed['controlled_fault']['state'] = 'injected'
        changed['controlled_fault']['injected_error_class'] = 'DivisionByZero'
        changed['controlled_fault']['trigger_statement_sha256'] = 'a' * 64
        with self.assertRaises(ValueError): validate_target_observation(seal_observation(changed))
        changed = {k: deepcopy(v) for k, v in observed.items() if k != 'observation_sha256'}
        changed['controlled_fault']['network_loss_claimed'] = True
        with self.assertRaises(ValueError): validate_target_observation(seal_observation(changed))

    def test_prior_receipt_wrong_candidate_is_rejected_before_any_recovery_read(self):
        original = self.lost()['prior']
        changed = {k: deepcopy(v) for k, v in original.items() if k != 'observation_sha256'}
        changed['candidate']['source_sha256'] = 'f' * 64
        changed['candidate']['candidate_sha256'] = digest({k: v for k, v in changed['candidate'].items() if k != 'candidate_sha256'})
        changed = seal_observation(changed)
        with patch('la.postgres.runner.driver_and_connect', side_effect=AssertionError('must not connect')):
            with self.assertRaisesRegex(ValueError, 'scope'):
                reconcile_target_candidate(self.artifact, self.sign(self.body), changed,
                                             target_config=self.config, authority_verifier=self.verifier)

    def test_normal_v2_observation_has_no_controlled_fault_and_cannot_be_relabelled(self):
        normal = target_observer_v2(self.artifact, self.sign(self.body), target_config=self.config, authority_verifier=self.verifier)
        self.assertEqual(normal['schema_version'], 2)
        self.assertNotIn('controlled_fault', normal)
        changed = {k: deepcopy(v) for k, v in normal.items() if k != 'observation_sha256'}
        changed['controlled_fault'] = self.failed()['controlled_fault']
        with self.assertRaises(ValueError): validate_target_observation(seal_observation(changed))

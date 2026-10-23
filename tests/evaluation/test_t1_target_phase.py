"""T1 target phase/controlled-boundary regression SOURCE, never executed here."""
from copy import deepcopy
from dataclasses import replace
import unittest

from evaluator_support import gold
from target_effects_support import expectation, observations, seal
from evaluation.artifacts import digest
from evaluation.target_effects import grade_target
from evaluation.target_runner import TargetGrant


def phase_expectation():
    expected = expectation('B1')
    descriptor = {**expected.candidate, 'schema_version': 2, 'evaluation_phase': 'T1',
                  'split': 'development', 'evaluation_plan_sha256': digest('public T1 authority'), 'freeze_sha256': None}
    seal(descriptor, 'candidate_sha256')
    return replace(expected, candidate=descriptor)


class T1TargetPhase(unittest.TestCase):
    def test_declared_precision_1000_is_not_narrowed_to_38(self):
        """what_bug_this_catches: valid D5 numeric catalog declaration rejected by grader."""
        expected = phase_expectation()
        columns = deepcopy(expected.columns); columns[5][3] = 1000
        expected = replace(expected, columns=columns)
        positive, prior, failed, recovered = observations(expected)
        self.assertEqual(grade_target(gold(), positive, expectation=expected, prior=prior,
            failed_load=failed, recovery_observation=recovered)['target_validation'], 'passed')
        self.assertEqual(expected.columns[5][3], 1000)

    def test_public_plan_is_not_a_final_freeze(self):
        """what_bug_this_catches: public T1 is forced through T2 or grants hidden access."""
        expected = phase_expectation()
        positive, prior, failed, recovered = observations(expected)
        report = grade_target(gold(), positive, expectation=expected, prior=prior,
                              failed_load=failed, recovery_observation=recovered)
        self.assertEqual(report['target_validation'], 'passed')
        self.assertIsNone(expected.candidate['freeze_sha256'])
        for mutation in ('split', 'freeze_sha256'):
            descriptor = {**expected.candidate, mutation: 'heldout' if mutation == 'split' else 'e' * 64}
            seal(descriptor, 'candidate_sha256')
            with self.assertRaises(ValueError): replace(expected, candidate=descriptor).validate()

    def test_target_intent_requires_concrete_signature_and_exact_phase(self):
        """what_bug_this_catches: unsigned success body bypasses actual target authority."""
        from custody_support import sign, verifier
        from evaluation.eligibility import ReceiptVerifier
        expected = phase_expectation()
        d = expected.candidate
        payload = {'schema_version': 2, 'kind': 'disposable_target_authority', 'authority_id': 'synthetic-target-owner',
            'scope': 'disposable_evaluation', 'candidate_sha256': d['candidate_sha256'], 'source_sha256': d['source_sha256'],
            'method': d['method'], 'edition': d['edition'], 'freeze_sha256': None,
            'observer_code_sha256': expected.observer_code_sha256, 'evaluation_phase': 'T1',
            'split': 'development', 'evaluation_plan_sha256': d['evaluation_plan_sha256'],
            'operations': ['load', 'negative_probes', 'reconcile', 'controlled_failed_load', 'controlled_commit_ack']}
        payload['authority_sha256'] = digest(payload)
        expected = replace(expected, authority_sha256=payload['authority_sha256'],
                           target={**expected.target, 'authority_reference': payload['authority_sha256']})
        with self.assertRaises(ValueError): TargetGrant(payload, expected).validate()
        signed = sign(payload); signed['role'] = 'target_authority'
        target_verifier = ReceiptVerifier({'owner': ('synthetic-owner', 'target_authority')},
                                          {'owner': verifier().public_keys['owner']})
        TargetGrant(signed, expected, target_verifier).validate()
        altered = deepcopy(payload); altered['evaluation_plan_sha256'] = 'f' * 64
        seal(altered, 'authority_sha256'); wrong = sign(altered); wrong['role'] = 'target_authority'
        with self.assertRaises(ValueError): TargetGrant(wrong, expected, target_verifier).validate()

    def test_controlled_application_ack_has_actual_boundary_not_network_claim(self):
        """what_bug_this_catches: deliberate application suppression is reported as network loss."""
        expected = phase_expectation()
        positive, prior, failed, recovered = observations(expected)
        fault = {'operation': 'controlled_commit_ack', 'boundary': 'after_driver_commit_before_application_ack',
            'state': 'injected', 'network_loss_claimed': False, 'driver_commit_returned': True,
            'application_ack_delivered': False, 'trigger_statement_sha256': None,
            'boundary_sha256': digest({'operation': 'controlled_commit_ack',
                'boundary': 'after_driver_commit_before_application_ack', 'observer_code_sha256': expected.observer_code_sha256}),
            'injected_error_class': 'ControlledAcknowledgementSuppressed', 'partial_write': None}
        prior.update(schema_version=3, controlled_fault=deepcopy(fault), issues=[{'code': 'controlled_application_ack_suppressed'}])
        seal(prior, 'observation_sha256')
        recovered.update(schema_version=3, controlled_fault=deepcopy(fault), issues=[{'code': 'reconciled_controlled_application_ack'}])
        recovered['attempt']['prior_observation_sha256'] = prior['observation_sha256']
        recovered['recovery']['prior_observation_sha256'] = prior['observation_sha256']
        seal(recovered, 'observation_sha256')
        report = grade_target(gold(), positive, expectation=expected, prior=prior,
                              failed_load=failed, recovery_observation=recovered)
        self.assertEqual(report['target_validation'], 'passed')
        self.assertEqual(report['recovery_kind'], 'controlled_application_ack')
        prior['controlled_fault']['network_loss_claimed'] = True; seal(prior, 'observation_sha256')
        self.assertEqual(grade_target(gold(), positive, expectation=expected, prior=prior,
            failed_load=failed, recovery_observation=recovered)['target_validation'], 'failed')

    def test_known_commit_read_error_does_not_count_as_lost_ack(self):
        """what_bug_this_catches: ordinary readback retry is relabeled lost-commit evidence."""
        expected = phase_expectation()
        positive, prior, failed, recovered = observations(expected)
        prior['issues'] = [{'code': 'committed_readback_unavailable'}]; seal(prior, 'observation_sha256')
        recovered['attempt']['prior_observation_sha256'] = prior['observation_sha256']
        recovered['recovery']['prior_observation_sha256'] = prior['observation_sha256']
        recovered['issues'] = [{'code': 'reconciled_known_commit_readback'}]; seal(recovered, 'observation_sha256')
        self.assertEqual(grade_target(gold(), positive, expectation=expected, prior=prior,
            failed_load=failed, recovery_observation=recovered)['target_validation'], 'indeterminate')


if __name__ == '__main__': unittest.main()

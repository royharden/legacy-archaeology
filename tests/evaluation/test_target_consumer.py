"""Actual v2/v3 consumer regression SOURCE; never collected or executed here."""
from copy import deepcopy
from dataclasses import replace
from tempfile import TemporaryDirectory
import unittest

from evaluator_support import case, gold, mapping
from target_effects_support import expectation, observations, seal
from test_t1_target_phase import phase_expectation
from evaluation.artifacts import CaptureStore, digest
from evaluation.target_effects import grade_target, validate_target_observation
from evaluation.target_runner import TargetGrant, TargetPorts, run_target_arm


def controlled_pair(expected, prior, recovered):
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
    return prior, recovered


def signed_grant(expected, *, controlled=True):
    # Fixed synthetic test signer only; never operational key/authority creation.
    from custody_support import sign, verifier
    from evaluation.eligibility import ReceiptVerifier
    d = expected.candidate
    payload = {'schema_version': 2, 'kind': 'disposable_target_authority', 'authority_id': 'synthetic-target-owner',
        'scope': 'disposable_evaluation', 'candidate_sha256': d['candidate_sha256'], 'source_sha256': d['source_sha256'],
        'method': d['method'], 'edition': d['edition'], 'freeze_sha256': d['freeze_sha256'],
        'observer_code_sha256': expected.observer_code_sha256, 'evaluation_phase': d['evaluation_phase'],
        'split': d['split'], 'evaluation_plan_sha256': d['evaluation_plan_sha256'],
        'operations': ['load', 'negative_probes', 'reconcile'] +
            (['controlled_failed_load', 'controlled_commit_ack'] if controlled else [])}
    payload['authority_sha256'] = digest(payload)
    expected = replace(expected, authority_sha256=payload['authority_sha256'],
        target={**expected.target, 'authority_reference': payload['authority_sha256']})
    signed = sign(payload); signed['role'] = 'target_authority'
    v = ReceiptVerifier({'owner': ('synthetic-owner', 'target_authority')}, {'owner': verifier().public_keys['owner']})
    return TargetGrant(signed, expected, v)


class TargetConsumerClosure(unittest.TestCase):
    def grade(self, expected, items):
        positive, prior, failed, recovered = items
        return grade_target(gold(), positive, expectation=expected, prior=prior,
            failed_load=failed, recovery_observation=recovered)

    def test_mixed_actual_versions_and_defensive_validation(self):
        """what_bug_this_catches: schema3 rejected by active schema2-only consumer."""
        e = phase_expectation(); items = observations(e)
        self.assertEqual([x['schema_version'] for x in items], [2, 2, 3, 2])
        copy = validate_target_observation(items[2], expectation=e)
        copy['controlled_fault']['state'] = 'unsupported'
        self.assertEqual(items[2]['controlled_fault']['state'], 'injected')
        self.assertEqual(self.grade(e, items)['target_validation'], 'passed')

    def test_unknown_versions_or_version_field_mismatch_refuse(self):
        """what_bug_this_catches: inferred/coerced schema bypasses closed v2/v3 wire."""
        e = phase_expectation()
        for version in (True, '3', 1, 4, 3):
            item = observations(e)[0]; item['schema_version'] = version
            seal(item, 'observation_sha256')
            with self.assertRaises(ValueError): validate_target_observation(item, expectation=e)
        item = observations(e)[2]; item['schema_version'] = 2; seal(item, 'observation_sha256')
        with self.assertRaises(ValueError): validate_target_observation(item, expectation=e)

    def test_resealed_source_observer_authority_mismatch_fails(self):
        """what_bug_this_catches: valid self-hash substitutes for external lineage pins."""
        e = phase_expectation()
        for key in ('authority_sha256', 'observer_code_sha256', 'target_config_sha256'):
            items = list(observations(e)); items[0][key] = '0' * 64; seal(items[0], 'observation_sha256')
            self.assertEqual(self.grade(e, items)['target_validation'], 'failed')
        d = deepcopy(e.candidate); d['source_sha256'] = '0' * 64; seal(d, 'candidate_sha256')
        self.assertEqual(self.grade(replace(e, candidate=d), observations(replace(e, candidate=d)))['target_validation'], 'failed')

    def test_partial_write_error_must_be_the_same_observed_boundary(self):
        """what_bug_this_catches: unrelated constraint error masquerades as SELECT1/0 rollback."""
        e = phase_expectation()
        for key, wrong in (('sqlstate', '23514'), ('statement_sha256', '0' * 64), ('error_class', 'OtherError')):
            items = observations(e); effect = items[2]['negative_effects'][0]
            effect['transaction'][key] = wrong; seal(effect, 'effect_sha256'); seal(items[2], 'observation_sha256')
            self.assertEqual(self.grade(e, items)['target_validation'], 'failed')

    def test_partial_row_source_ordinal_and_observed_connection_are_not_repaired(self):
        """what_bug_this_catches: one arbitrary row is accepted as actual first insert."""
        e = phase_expectation()
        for key, wrong in (('source_sha256', '0' * 64), ('ordinal', True), ('raw_sha256', '0' * 64)):
            items = observations(e); partial = items[2]['controlled_fault']['partial_write']
            partial['rows'][0][key] = wrong; partial['rows_sha256'] = digest(partial['rows'])
            seal(items[2], 'observation_sha256')
            self.assertEqual(self.grade(e, items)['target_validation'], 'failed')

    def test_controlled_recovery_is_not_relabelled_driver_or_network_loss(self):
        """what_bug_this_catches: issue-code edits widen a controlled app boundary claim."""
        e = phase_expectation(); items = list(observations(e))
        items[1], items[3] = controlled_pair(e, items[1], items[3])
        report = self.grade(e, items)
        self.assertEqual(report['target_validation'], 'passed')
        self.assertEqual(report['recovery_scope'], 'driver_returned_application_ack_suppressed')
        self.assertIs(report['network_loss_proven'], False)
        items[1]['issues'] = [{'code': 'commit_acknowledgement_unknown'}]
        items[3]['issues'] = [{'code': 'reconciled_lost_commit_acknowledgement'}]
        seal(items[1], 'observation_sha256')
        items[3]['attempt']['prior_observation_sha256'] = items[1]['observation_sha256']
        items[3]['recovery']['prior_observation_sha256'] = items[1]['observation_sha256']
        seal(items[3], 'observation_sha256')
        self.assertEqual(self.grade(e, items)['target_validation'], 'indeterminate')

    def test_missing_reconciliation_readback_is_indeterminate(self):
        """what_bug_this_catches: an explicit unobserved recovery stage becomes failure/pass."""
        e = phase_expectation(); items = observations(e)
        items[3].update(commit_state='indeterminate', readback=None); seal(items[3], 'observation_sha256')
        self.assertEqual(self.grade(e, items)['target_validation'], 'indeterminate')

    def test_prior_hash_and_boundary_code_are_independently_pinned(self):
        """what_bug_this_catches: recovery attaches a different predecessor or observer."""
        e = phase_expectation()
        for mutation in ('prior', 'boundary'):
            items = list(observations(e)); items[1], items[3] = controlled_pair(e, items[1], items[3])
            if mutation == 'prior': items[3]['recovery']['prior_observation_sha256'] = '0' * 64
            else: items[3]['controlled_fault']['boundary_sha256'] = '0' * 64
            seal(items[3], 'observation_sha256')
            self.assertEqual(self.grade(e, items)['target_validation'], 'failed')

    def test_unobserved_negative_after_stage_cannot_pass(self):
        """what_bug_this_catches: rolled_back label supplies an absent fresh observer."""
        e = phase_expectation(); items = observations(e); effect = items[0]['negative_effects'][0]
        effect['after'] = None; seal(effect, 'effect_sha256'); seal(items[0], 'observation_sha256')
        self.assertEqual(self.grade(e, items)['target_validation'], 'indeterminate')

    def ports(self, grant, *, fail=None, recover=None):
        artifact = {'kind': 'disposable_evaluation_candidate', 'descriptor': grant.expectation.candidate}
        positive = observations(grant.expectation)[0]
        return TargetPorts(lambda *a: artifact, lambda *a: grant, lambda *a: positive,
            failed_load=fail, recovery=recover, prepare_v2=lambda *a: artifact)

    def run_arm(self, grant, store, ports):
        d = grant.expectation.candidate
        phase = {k: d[k] for k in ('evaluation_phase', 'split', 'evaluation_plan_sha256', 'freeze_sha256')}
        return run_target_arm(case(), mapping(), 'B1', store, ports, freeze_sha256=None, mode='mock', phase_scope=phase)

    def test_callback_failure_preserves_original_capture_and_denominator(self):
        """what_bug_this_catches: later adapter exception or secret message loses valid readback."""
        grant = signed_grant(phase_expectation())
        def unavailable(*args): raise RuntimeError('sensitive adapter detail must not be recorded')
        with TemporaryDirectory() as folder:
            store = CaptureStore(folder); result = self.run_arm(grant, store, self.ports(grant, fail=unavailable))
            batch = result['batches'][0]
            self.assertEqual(batch['schema_version'], 2)
            self.assertEqual(result['target_validation'], 'indeterminate')
            self.assertEqual(batch['grade']['score']['semantic_rows']['denominator'], 3)
            self.assertEqual(batch['stage_errors'], [{'stage': 'failed_load', 'error_type': 'RuntimeError'}])
            self.assertEqual(store.get(batch['observation'])['schema_version'], 2)
            self.assertNotIn('sensitive', str(batch))

    def test_ungranted_controlled_callbacks_are_never_invoked(self):
        """what_bug_this_catches: ordinary load grant implies destructive fault injection."""
        grant = signed_grant(phase_expectation(), controlled=False); called = []
        def forbidden(*a): called.append(a); raise AssertionError('ungranted')
        with TemporaryDirectory() as folder:
            result = self.run_arm(grant, CaptureStore(folder), self.ports(grant, fail=forbidden, recover=forbidden))
        self.assertEqual(called, [])
        self.assertEqual(result['batches'][0]['stages']['failed_load'], 'not_authorized')
        self.assertEqual(result['target_validation'], 'indeterminate')

    def test_actual_v3_capture_kind_and_partial_recovery_are_retained(self):
        """what_bug_this_catches: publisher capture label downgrades v3 or drops predecessor."""
        grant = signed_grant(phase_expectation()); items = observations(grant.expectation)
        prior, recovered = controlled_pair(grant.expectation, items[1], items[3])
        ports = self.ports(grant, recover=lambda *a: {'prior': prior, 'reconciled': None})
        ports = replace(ports, observe=lambda *a: recovered)
        with TemporaryDirectory() as folder:
            store = CaptureStore(folder); result = self.run_arm(grant, store, ports)
            batch = result['batches'][0]
            self.assertEqual(batch['observation']['kind'], 'target_observation_v3')
            self.assertEqual(batch['observation_schema_version'], 3)
            self.assertEqual(batch['stages']['recovery'], 'partial')
            self.assertEqual([r['kind'] for r in batch['effect_captures']], ['unknown_commit_observation'])
            self.assertEqual(store.get(batch['effect_captures'][0]), prior)
            self.assertEqual(result['target_validation'], 'indeterminate')

    def test_malformed_later_receipt_preserves_earlier_capture_and_refuses(self):
        """what_bug_this_catches: malformed/credential-bearing adapter output gets persisted."""
        grant = signed_grant(phase_expectation())
        bad = observations(grant.expectation)[2]; bad['dsn'] = 'unapproved fake secret'
        with TemporaryDirectory() as folder:
            store = CaptureStore(folder)
            result = self.run_arm(grant, store, self.ports(grant, fail=lambda *a: bad))
            batch = result['batches'][0]
            self.assertEqual(result['target_validation'], 'failed')
            self.assertEqual(batch['effect_captures'], [])
            self.assertEqual(store.get(batch['observation'])['schema_version'], 2)
            self.assertNotIn('unapproved', str(batch))

    def test_actual_case_split_prevents_t1_to_t3_escalation_before_callbacks(self):
        """what_bug_this_catches: caller supplies public plan for a heldout case."""
        grant = signed_grant(phase_expectation()); ports = self.ports(grant)
        phase = {'evaluation_phase': 'T1', 'split': 'development',
                 'evaluation_plan_sha256': grant.expectation.candidate['evaluation_plan_sha256'], 'freeze_sha256': None}
        with TemporaryDirectory() as folder:
            with self.assertRaises(ValueError):
                run_target_arm(replace(case(), split='heldout'), mapping(), 'B1', CaptureStore(folder), ports,
                    freeze_sha256=None, mode='mock', phase_scope=phase)


if __name__ == '__main__': unittest.main()

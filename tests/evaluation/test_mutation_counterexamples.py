"""Hand-gold finite mutation regression SOURCE; no mutation audit has run."""
from tempfile import TemporaryDirectory
import unittest

from evaluator_support import gold, normalized
from evaluation.artifacts import CaptureStore, digest
from evaluation.mutation_audit import (VALUE_MUTATIONS, apply_outcome_mutation,
                                       audit_scorer_mutations, audit_control_mutations)
from evaluation.scorer import score


class MutationCounterexamples(unittest.TestCase):
    def test_every_declared_value_mutation_breaks_exact_join(self):
        """what_bug_this_catches: finite named mutation ignored by semantic scorer."""
        for mutation in VALUE_MUTATIONS:
            with self.subTest(mutation=mutation):
                changed = apply_outcome_mutation(normalized(), mutation)
                report = score(gold(), changed)
                self.assertEqual(report['row_parity'], 'mismatch')
                self.assertEqual(report['semantic_rows']['denominator'], 3)

    def test_compensation_sum_passes_while_two_rows_fail(self):
        """what_bug_this_catches: aggregate totals substitute for exact record parity."""
        report = score(gold(), apply_outcome_mutation(normalized(), 'compensating_errors'))
        self.assertEqual(report['aggregates']['expected_balance_sum'], report['aggregates']['actual_balance_sum'])
        self.assertEqual(report['semantic_rows']['numerator'], 1)
        self.assertEqual(report['row_parity'], 'mismatch')

    def test_drop_duplicate_keeps_totals_but_poisoned_identity(self):
        """what_bug_this_catches: equal business records hide missing/duplicated ordinal."""
        report = score(gold(), apply_outcome_mutation(normalized(), 'drop_duplicate'))
        self.assertEqual(report['aggregates']['expected_balance_sum'], report['aggregates']['actual_balance_sum'])
        self.assertEqual(report['aggregates']['input_count'], report['aggregates']['emitted_count'])
        self.assertEqual(len(report['missing']), 1)
        self.assertEqual(len(report['duplicates']), 1)
        self.assertEqual(report['row_parity'], 'mismatch')

    def test_audit_requires_exact_positive_control_and_keeps_captures(self):
        """what_bug_this_catches: broken baseline makes a vacuous all-mutations pass."""
        with TemporaryDirectory() as directory:
            store = CaptureStore(directory)
            with self.assertRaises(ValueError):
                audit_scorer_mutations(gold(), [], edition='public-test-v1', store=store)
            audit = audit_scorer_mutations(gold(), normalized(), edition='public-test-v1', store=store)
            self.assertEqual(audit['finite_suite_status'], 'passed')
            self.assertEqual(audit['independent_audit'], 'pending')
            self.assertEqual(len(audit['results']), len(VALUE_MUTATIONS))
            for result in audit['results']:
                self.assertEqual(store.get(result['capture'])['mutation'], result['mutation'])


class ControlMutationCounterexamples(unittest.TestCase):
    def test_control_mutations_bind_rejection_to_durable_effects(self):
        """what_bug_this_catches: rejected stale evidence still changes committed state."""
        candidate = {'evidence_sha256': 'e' * 64, 'mapping_sha256': 'a' * 64, 'mapping_status': 'complete'}
        def probe(changed):
            reason = ('incomplete_mapping' if changed['mapping_status'] == 'incomplete' else
                      'approval_mismatch' if changed['mapping_sha256'] != candidate['mapping_sha256'] else
                      'dependency_mismatch')
            return {'candidate_sha256': digest(changed), 'disposition': 'rejected', 'reason': reason,
                    'durable_before': {'events': 0, 'approvals': 0},
                    'durable_after': {'events': 0, 'approvals': 0}, 'probe_code_sha256': 'f' * 64}
        with TemporaryDirectory() as directory:
            audit = audit_control_mutations(candidate, probe, store=CaptureStore(directory))
            self.assertEqual(audit['finite_suite_status'], 'passed')
            self.assertEqual({result['mutation'] for result in audit['results']},
                             {'changed_evidence', 'stale_approval', 'incomplete_load'})

    def test_bare_probe_pass_flag_is_not_detection(self):
        """what_bug_this_catches: supplied success boolean is accepted as durable evidence."""
        candidate = {'evidence_sha256': 'e' * 64, 'mapping_sha256': 'a' * 64, 'mapping_status': 'complete'}
        with TemporaryDirectory() as directory:
            audit = audit_control_mutations(candidate, lambda changed: {'passed': True}, store=CaptureStore(directory))
            self.assertEqual(audit['finite_suite_status'], 'failed')
            self.assertTrue(all(result['status'] == 'missed' for result in audit['results']))


if __name__ == '__main__':
    unittest.main()

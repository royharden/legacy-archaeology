"""Independent target effects regression SOURCE; no database or scorer has run."""
from copy import deepcopy
from dataclasses import replace
import unittest

from evaluator_support import gold
from target_effects_support import expectation, observations, seal
from evaluation.artifacts import digest
from evaluation.target_effects import grade_target, STATES
from evaluation.target_runner import TargetPorts, run_target_arm


class TargetEffects(unittest.TestCase):
    def grade(self, expected, items):
        positive, prior, failed, recovered = items
        return grade_target(gold(), positive, expectation=expected, prior=prior,
                            failed_load=failed, recovery_observation=recovered, edition='public-test-v1')

    def test_positive_control_requires_real_rows_and_all_effects(self):
        """what_bug_this_catches: source flags substitute for full W7 target evidence."""
        expected = expectation()
        report = self.grade(expected, observations(expected))
        self.assertEqual(report['target_validation'], 'passed')
        self.assertEqual(report['score']['semantic_rows']['denominator'], 3)
        self.assertEqual(report['product_acceptance'], 'pending')

    def test_every_required_omission_remains_indeterminate(self):
        """what_bug_this_catches: missing rollback/constraint/recovery quietly passes."""
        expected = expectation()
        for missing in (*STATES, 'failed_load', 'recovery'):
            with self.subTest(missing=missing):
                items = list(observations(expected))
                if missing in STATES:
                    items[0]['negative_effects'] = [e for e in items[0]['negative_effects'] if e['probe_kind'] != missing]
                    seal(items[0], 'observation_sha256')
                elif missing == 'failed_load':
                    items[2] = None
                else:
                    items[3] = None
                self.assertEqual(self.grade(expected, items)['target_validation'], 'indeterminate')

    def test_each_negative_wrong_sqlstate_connection_and_durable_row_fails(self):
        """what_bug_this_catches: rollback intent hides real partial persisted state."""
        expected = expectation()
        for kind in STATES:
            for mutation in ('sqlstate', 'connection', 'durable_row', 'lineage'):
                with self.subTest(kind=kind, mutation=mutation):
                    items = observations(expected)
                    effect = next(e for e in items[0]['negative_effects'] if e['probe_kind'] == kind)
                    if mutation == 'sqlstate': effect['transaction']['sqlstate'] = '00000'
                    elif mutation == 'connection': effect['after']['connection_id'] = effect['transaction']['connection_id']
                    elif mutation == 'durable_row':
                        effect['after'].update(namespace_exists=True, table_exists=True, rows_capture='all_persisted_provenance_rows',
                            rows=[{'source_sha256': expected.candidate['source_sha256'], 'ordinal': 0, 'raw_sha256': 'c' * 64}])
                        effect['after']['rows_sha256'] = digest(effect['after']['rows'])
                    else: effect['source_sha256'] = 'e' * 64
                    seal(effect, 'effect_sha256'); seal(items[0], 'observation_sha256')
                    self.assertEqual(self.grade(expected, items)['target_validation'], 'failed')

    def test_compensation_and_drop_duplicate_fail_despite_totals(self):
        """what_bug_this_catches: target aggregates repair exact identity/value mismatch."""
        expected = expectation()
        for mutation in ('compensate', 'drop_duplicate'):
            items = observations(expected); rows = items[0]['readback']['rows']
            if mutation == 'compensate':
                rows[0]['values']['balance'] = '13.34'; rows[1]['values']['balance'] = '-6.00'
            else: rows[2] = deepcopy(rows[1])
            items[0]['readback']['rows_sha256'] = digest(rows); seal(items[0], 'observation_sha256')
            report = self.grade(expected, items)
            self.assertEqual(report['target_validation'], 'failed')
            self.assertEqual(report['score']['semantic_rows']['denominator'], 3)

    def test_wrong_catalog_and_recovery_marker_and_producer_flag_fail(self):
        """what_bug_this_catches: schema rounding/wrong durable marker/forged passed flag."""
        expected = expectation()
        for mutation in ('catalog', 'marker', 'flag'):
            items = observations(expected)
            if mutation == 'catalog': items[0]['readback']['columns'][5][4] = 3
            elif mutation == 'marker':
                items[3]['recovery']['marker_rows'].append(deepcopy(items[3]['recovery']['marker_rows'][0]))
                items[3]['recovery']['marker_rows_sha256'] = digest(items[3]['recovery']['marker_rows'])
            else: items[0]['passed'] = True
            seal(items[0], 'observation_sha256'); seal(items[3], 'observation_sha256')
            self.assertEqual(self.grade(expected, items)['target_validation'], 'failed')

    def test_all_five_methods_use_same_independent_grader(self):
        """what_bug_this_catches: unanswered comparator is granted fake product approval."""
        for method in ('B0', 'B1', 'C0', 'R0', 'R1'):
            with self.subTest(method=method):
                expected = expectation(method)
                self.assertEqual(self.grade(expected, observations(expected))['target_validation'], 'passed')
                self.assertFalse(expected.candidate['product_loadable'])
                self.assertEqual(expected.candidate['product_approval'], 'absent')


    def test_target_arm_failure_keeps_full_denominator_and_no_gold_in_ports(self):
        """what_bug_this_catches: failed target method is silently excluded from scoring."""
        from tempfile import TemporaryDirectory
        from evaluator_support import case, mapping
        from evaluation.artifacts import CaptureStore
        seen = []
        def prepare(visible, submitted, method, edition, freeze):
            seen.append(visible)
            raise ValueError('synthetic unavailable target adapter')
        ports = TargetPorts(prepare, lambda *args: None, lambda *args: None)
        with TemporaryDirectory() as directory:
            for method in ('B0', 'B1', 'C0', 'R0', 'R1'):
                report = run_target_arm(case(), mapping(), method, CaptureStore(directory), ports,
                                       freeze_sha256='f' * 64, mode='mock')
                self.assertEqual(report['target_validation'], 'failed')
                self.assertEqual(report['batches'][0]['grade']['score']['semantic_rows']['denominator'], 3)
                self.assertEqual(report['batches'][0]['grade']['score']['semantic_rows']['numerator'], 0)
        self.assertTrue(all('oracle' not in value for value in seen))


if __name__ == '__main__': unittest.main()

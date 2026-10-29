"""Fake-port runner regression SOURCE. No model or application execution evidence."""
from copy import deepcopy
from dataclasses import replace
from tempfile import TemporaryDirectory
import unittest

from evaluator_support import case, visible, fake_ports, mapping
from evaluation.artifacts import CaptureStore, digest
from evaluation.runner import RequestGateway, run_variant


class RunnerInformation(unittest.TestCase):
    def test_one_b1_attempt_and_identical_inputs(self):
        """what_bug_this_catches: hidden B1 repair or arm-specific input advantage."""
        calls, inputs = [], []
        def provider(request):
            calls.append(deepcopy(request))
            return {'output': mapping(), 'cost_status': 'known', 'known_cost': '0'}
        with TemporaryDirectory() as directory:
            report = run_variant(case(), fake_ports(provider=provider, observed_inputs=inputs), CaptureStore(directory))
            self.assertEqual(len(calls), 1)
            self.assertEqual(calls[0]['method'], 'B1')
            self.assertFalse(calls[0]['allow_retries'])
            self.assertFalse(calls[0]['allow_repairs'])
            self.assertNotIn('source_hex', calls[0]['prompt']['input'])
            self.assertEqual({item['input_sha256'] for item in report['results']}, {digest(visible())})
            self.assertEqual(inputs, [visible()] * 4)
            self.assertNotIn('oracle', calls[0]['prompt']['input'])

    def test_malformed_b1_is_failure_with_full_denominator_no_repair(self):
        """what_bug_this_catches: invalid one-shot silently repaired or excluded."""
        calls = []
        def provider(request):
            calls.append(request)
            return {'output': None, 'cost_status': 'unknown'}
        with TemporaryDirectory() as directory:
            report = run_variant(case(), fake_ports(provider=provider), CaptureStore(directory))
            b1 = next(item for item in report['results'] if item['method'] == 'B1')
            self.assertEqual(len(calls), 1)
            self.assertEqual(b1['status'], 'failed')
            self.assertEqual(b1['score']['semantic_rows']['numerator'], 0)
            self.assertEqual(b1['score']['semantic_rows']['denominator'], 3)
            self.assertIsNone(b1['known_total_cost'])
            self.assertEqual(b1['unknown_liabilities'], [1])

    def test_r1_only_offered_ids_and_unknown(self):
        """what_bug_this_catches: SME invents missing correct options or human provenance."""
        answers = []
        with TemporaryDirectory() as directory:
            report = run_variant(case(), fake_ports(observed_answers=answers), CaptureStore(directory))
            r1 = next(item for item in report['results'] if item['method'] == 'R1')
            self.assertEqual(r1['questions_asked'], 2)
            self.assertEqual(r1['questions_answered'], 1)
            self.assertEqual(r1['answer_source'], 'agent_provisional')
            supplied = [item for group in answers for item in group]
            self.assertEqual([item['option_id'] for item in supplied], ['choice-a', 'unknown'])
            self.assertTrue(all(item['actor'] == 'agent_provisional' for item in supplied))

    def test_unknown_liability_stops_automatic_second_request(self):
        """what_bug_this_catches: timeout billed as zero and automatically retried."""
        calls = []
        def timeout(request):
            calls.append(request)
            raise TimeoutError('synthetic timeout')
        with TemporaryDirectory() as directory:
            gateway = RequestGateway('R1', 'mock', visible(), fake_ports(provider=timeout), CaptureStore(directory), None)
            with self.assertRaises(TimeoutError):
                gateway.request('rank')
            with self.assertRaisesRegex(ValueError, 'unknown liability'):
                gateway.request('rank')
            self.assertEqual(len(calls), 1)
            self.assertEqual(len(gateway.attempts), 1)

    def test_live_hidden_and_oracle_key_refuse_before_any_port(self):
        """what_bug_this_catches: missing custody or accidental gold leaks to inference."""
        calls = []
        with TemporaryDirectory() as directory:
            ports = fake_ports(observed_inputs=calls)
            store = CaptureStore(directory)
            for candidate, mode in ((case(), 'live'), (replace(case(), split='heldout'), 'mock')):
                with self.subTest(mode=mode, split=candidate.split), self.assertRaises(ValueError):
                    run_variant(candidate, ports, store, mode=mode)
            bad = replace(case(), visible={**visible(), 'oracle': {'secret': 'not permitted'}})
            with self.assertRaises(ValueError):
                run_variant(bad, ports, store)
            nested = visible()
            nested['permitted_samples']['oracle'] = 'accidental hidden payload'
            nested['permitted_samples']['artifact_sha256'] = digest({key: value for key, value in
                nested['permitted_samples'].items() if key != 'artifact_sha256'})
            gateway = RequestGateway('B1', 'mock', nested, ports, store, None)
            with self.assertRaisesRegex(ValueError, 'sample artifact fields'):
                gateway.request('single_pass_full_mapping')
            self.assertEqual(gateway.attempts, [])
            self.assertEqual(calls, [])

    def test_no_output_arm_is_not_passing(self):
        """what_bug_this_catches: successful empty transform treated as exact migration."""
        with TemporaryDirectory() as directory:
            report = run_variant(case(), fake_ports(transform=lambda value, proposal: []), CaptureStore(directory))
            self.assertTrue(all(item['status'] == 'failed' for item in report['results']))
            self.assertTrue(all(item['score']['semantic_rows']['denominator'] == 3 for item in report['results']))
            self.assertTrue(all(item['score']['semantic_rows']['numerator'] == 0 for item in report['results']))


if __name__ == '__main__':
    unittest.main()

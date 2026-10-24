"""T3 provider-phase and cleanup-caller regression SOURCE; not executed in Dirty Mode."""
import hashlib
import json
import unittest
from unittest.mock import patch

from la.providers.evaluation import provider_port
from la.providers.wire import request_pins

SHA = 'a' * 64


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':'),
                                     ensure_ascii=False, allow_nan=False).encode()).hexdigest()


CONFIG = {'provider': 'openai-responses', 'model': 'pinned-model'}


def authority(phase=None):
    value = {'provider': 'openai-responses', 'model': 'pinned-model', 'price': {'evidence_sha256': 'b' * 64},
             'authority_sha256': 'c' * 64, 'billing_config_sha256': digest(CONFIG), 'attempt_id': 'attempt-1',
             'caps': {'max_input_tokens': 8000, 'max_output_tokens': 2000}}
    if phase is not None: value['evaluation_phase'] = phase
    return value


def envelope(phase):
    prompt = {'purpose': 'rank', 'input': {'brief': 'b', 'source_sha256': SHA,
              'permitted_samples': {'source_sha256': SHA, 'authorization': 'x', 'records': []}}, 'candidates': []}
    samples = prompt['input']['permitted_samples']
    samples['artifact_sha256'] = digest({k: v for k, v in samples.items() if k != 'artifact_sha256'})
    text = json.dumps(prompt, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode()
    return {'mode': 'live', 'method': 'R0', 'attempt': 1, 'prompt': prompt, 'prompt_sha256': hashlib.sha256(text).hexdigest(),
            'max_input_tokens': 8000, 'max_output_tokens': 2000, 'allow_retries': False, 'allow_repairs': False,
            'provider': 'openai-responses', 'model': 'pinned-model', 'price_sha256': 'b' * 64,
            'evaluation_phase': phase, 'evaluation_authority_sha256': 'c' * 64}


class T3ProviderPhaseSource(unittest.TestCase):

    def test_wire_accepts_only_t1_and_t3(self):
        """what_bug_this_catches: T3 receipts cannot be recorded, or an invented phase is accepted."""
        for phase in ('T1', 'T3'):
            request_pins({'evaluation_phase': phase, 'evaluation_authority_sha256': SHA})
        for phase in ('T2', 't3', True):
            with self.subTest(phase), self.assertRaises(ValueError):
                request_pins({'evaluation_phase': phase, 'evaluation_authority_sha256': SHA})

    def test_t3_authority_refuses_a_t1_labeled_request(self):
        """what_bug_this_catches: a T3 scope view silently accepts public T1 phase pins."""
        port = provider_port(config=CONFIG, ledger_path='never-opened.sqlite', run='r', trusted_authority=authority('T3'))
        with patch('la.providers.evaluation.generate_once', side_effect=AssertionError('transport reached')):
            with self.assertRaises(ValueError):
                port(envelope('T1'))

    def test_absent_phase_defaults_to_t1_and_unknown_phase_refuses_at_construction(self):
        """what_bug_this_catches: older T1 views break, or a T2 view builds a port."""
        port = provider_port(config=CONFIG, ledger_path='never-opened.sqlite', run='r', trusted_authority=authority())
        with patch('la.providers.evaluation.generate_once', side_effect=AssertionError('transport reached')):
            with self.assertRaises(ValueError):
                port(envelope('T3'))
        with self.assertRaises(ValueError):
            provider_port(config=CONFIG, ledger_path='x', run='r', trusted_authority=authority('T2'))

    def test_t3_namespace_and_pins_carry_the_phase(self):
        """what_bug_this_catches: T3 calls share the T1 ledger namespace or lose phase pins."""
        seen = {}

        def fake(text, config, ledger_path, *, run, method, pins):
            seen.update(run=run, pins=pins)
            return {'text': None, 'receipt': None}
        port = provider_port(config=CONFIG, ledger_path='ledger.sqlite', run='r', trusted_authority=authority('T3'))
        with patch('la.providers.evaluation.generate_once', side_effect=fake), patch('la.providers.accounting.CallLedger'):
            with self.assertRaises(ValueError):  # text None: durable liability retained
                port(envelope('T3'))
        self.assertTrue(seen['run'].startswith('T3:'))
        self.assertEqual(seen['pins']['evaluation_phase'], 'T3')
        self.assertEqual(seen['pins']['evaluation_authority_sha256'], 'c' * 64)


class CleanupCallerSource(unittest.TestCase):

    def test_load_authority_cannot_substitute_for_cleanup(self):
        """what_bug_this_catches: the narrow load/probe authority grants namespace removal."""
        from scripts.target_cleanup import precheck_cleanup_authority
        load = {'kind': 'disposable_target_authority', 'operations': ['load', 'cleanup']}
        load['authority_sha256'] = digest(load)
        with patch('la.postgres.authority.verified_target_authority', return_value=load):
            with self.assertRaises(ValueError):
                precheck_cleanup_authority({}, None, load['authority_sha256'], 'cleanup')

    def test_cleanup_grant_does_not_cover_an_ungranted_operation(self):
        """what_bug_this_catches: a reconcile-only grant authorizes destructive cleanup."""
        from scripts.target_cleanup import precheck_cleanup_authority
        body = {'kind': 'disposable_target_cleanup_authority', 'scope': 'owned_disposable_namespace',
                'operations': ['reconcile_cleanup']}
        body['authority_sha256'] = digest(body)
        with patch('la.postgres.authority.verified_target_authority', return_value=body):
            precheck_cleanup_authority({}, None, body['authority_sha256'], 'reconcile_cleanup')
            with self.assertRaises(ValueError):
                precheck_cleanup_authority({}, None, body['authority_sha256'], 'cleanup')

    def test_cleanup_requires_every_external_pin(self):
        """what_bug_this_catches: recency/default selection of experiment, observation or authority."""
        from scripts.target_cleanup import parser
        full = ['--operator-root', 'r', 'cleanup', '--receipt-root', 'rc', '--experiment', 'e',
                '--expected-experiment-sha256', SHA, '--expected-original-observation-sha256', SHA,
                '--artifact', 'a', '--signed-authority', 's', '--cleanup-authority', 'c',
                '--expected-cleanup-authority-sha256', SHA, '--target-config', 't',
                '--public-trust-root', 'p', '--public-trust-profile', 'pp']
        parser().parse_args(full)
        for flag in ('--expected-experiment-sha256', '--expected-original-observation-sha256',
                     '--expected-cleanup-authority-sha256', '--cleanup-authority'):
            index = full.index(flag)
            with self.subTest(flag), self.assertRaises(SystemExit):
                parser().parse_args(full[:index] + full[index + 2:])


if __name__ == '__main__':
    unittest.main()

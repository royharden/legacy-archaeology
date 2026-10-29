"""D11 producer + evaluator seam, pure preflight and injected offline transport."""
from dataclasses import replace
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

from evaluator_support import fake_ports, visible
from evaluation.artifacts import CaptureStore, canonical, digest
from evaluation.runner import RequestGateway, _prompt_input
from la.providers.evaluation import provider_port, provider_text


CONFIG = dict(authorized=True, activation_verified=True, authority_id='synthetic-test-only',
    model='synthetic', model_version='synthetic-1', api_version_pin='synthetic-wire',
    price_version='synthetic', price_evidence_date='2099-01-01', price_evidence_sha256='a' * 64,
    input_usd_per_million='1', cached_input_usd_per_million='0.25', output_usd_per_million='2',
    total_cap_usd='1', max_input_tokens=8000, max_output_tokens=2000)


class JoinedProviderPreflight(unittest.TestCase):
    def test_actual_d11_wrapper_rejects_before_evaluator_liability(self):
        """what_bug_this_catches: real wrapper exceeds cap after evaluator reserve."""
        prompt = dict(purpose='single_pass_full_mapping', input=_prompt_input(visible()))
        cap = len(canonical(prompt)) + 1
        self.assertLess(cap, len(provider_text('B1', prompt).encode('utf-8')))
        with TemporaryDirectory() as root:
            ledger = Path(root) / 'never-created.sqlite'
            provider = provider_port(config={**CONFIG, 'max_input_tokens': cap}, ledger_path=ledger, run='pure-test')
            self.assertTrue(callable(getattr(provider, 'preflight', None)), 'D11 preflight dependency is required')
            meter = unittest.mock.Mock()
            ports = replace(fake_ports(), provider=provider, provider_preflight=provider.preflight,
                            count_tokens=lambda text: len(text.encode('utf-8')))
            gateway = RequestGateway('B1', 'live', visible(), ports, CaptureStore(root),
                                     {'spend_authority_sha256': 'a' * 64}, meter)
            with patch('la.providers.evaluation.generate_once', side_effect=AssertionError('no transport')) as transport:
                with self.assertRaises(ValueError):
                    gateway.request('single_pass_full_mapping')
            transport.assert_not_called()
            meter.reserve.assert_not_called()
            self.assertEqual(gateway.attempts, [])
            self.assertFalse(ledger.exists())

    def test_actual_preflight_feeds_exact_text_to_counter_with_fake_transport(self):
        """what_bug_this_catches: joined capability is wired but counter ignores wrapper."""
        with TemporaryDirectory() as root:
            provider = provider_port(config=CONFIG, ledger_path=Path(root) / 'unused.sqlite', run='pure-test')
            self.assertTrue(callable(getattr(provider, 'preflight', None)), 'D11 preflight dependency is required')
            seen = []
            def count(text):
                seen.append(text)
                return len(text.encode('utf-8'))
            ports = replace(fake_ports(), provider_preflight=provider.preflight, count_tokens=count)
            gateway = RequestGateway('B1', 'live', visible(), ports, CaptureStore(root),
                                     {'spend_authority_sha256': 'a' * 64})
            gateway.request('single_pass_full_mapping')  # fake_ports provider, no network/key access
            prompt = dict(purpose='single_pass_full_mapping', input=_prompt_input(visible()))
            self.assertEqual(seen, [provider_text('B1', prompt)])
            self.assertEqual(gateway.attempts[0]['status'], 'returned')


if __name__ == '__main__':
    unittest.main()

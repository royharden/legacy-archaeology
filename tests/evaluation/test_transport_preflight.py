"""No-key provider wrapper regression; no live transport or hidden assets."""
from dataclasses import replace
from tempfile import TemporaryDirectory
from types import SimpleNamespace
import unittest

from evaluator_support import visible, fake_ports, case
from evaluation.artifacts import CaptureStore, canonical, digest
from evaluation.runner import RequestGateway, _prompt_input
from evaluation.protected_live import ProtectedProviderPort


class Meter:
    def __init__(self):
        self.calls = []

    def reserve(self, request, tokens):
        self.calls.append((request, tokens))
        return 'fake-call'

    def settle(self, *args):
        pass


class TransportPreflight(unittest.TestCase):
    def test_protected_port_checks_wrapped_text_before_registry_reservation(self):
        """what_bug_this_catches: protected direct port reserves rejected wrapped input."""
        calls = []
        def inner(request):
            calls.append(request)
            raise AssertionError('must not send')
        inner.preflight = lambda request: 'x' * 8001
        prompt = {'purpose': 'single_pass_full_mapping', 'input': _prompt_input(visible())}
        context = SimpleNamespace(validate=lambda: {'caps': {'max_input_tokens': 8000}},
                                  edition=case().edition)
        port = ProtectedProviderPort(context, inner,
                    {digest(prompt['input']): replace(case(), split='heldout')}, len)
        request = dict(mode='live', method='B1', allow_retries=False, allow_repairs=False,
                       prompt=prompt, prompt_sha256=digest(prompt), attempt=1)
        with self.assertRaisesRegex(ValueError, 'signed cap'):
            port(request)
        self.assertEqual(calls, [])

    def test_wrapped_cap_rejection_precedes_liability_and_transport(self):
        """what_bug_this_catches: wrapper expansion reserves an unsent liability."""
        calls, checked = [], []
        def provider(request):
            calls.append(request)
            raise AssertionError('must not send')
        def preflight(request):
            checked.append(request)
            self.assertLess(len(canonical(request['prompt'])), 8000)
            return 'x' * 8001
        ports = replace(fake_ports(provider=provider), provider_preflight=preflight,
                        count_tokens=lambda text: len(text.encode('utf-8')))
        meter = Meter()
        with TemporaryDirectory() as root:
            gateway = RequestGateway('B1', 'mock', visible(), ports, CaptureStore(root), None, meter)
            with self.assertRaisesRegex(ValueError, 'token cap'):
                gateway.request('single_pass_full_mapping')
            self.assertEqual(gateway.attempts, [])
        self.assertEqual(len(checked), 1)
        self.assertEqual(meter.calls, [])
        self.assertEqual(calls, [])

    def test_exact_wrapped_text_at_cap_is_counted(self):
        """what_bug_this_catches: counter sees canonical prompt rather than sent text."""
        seen = []
        def count(text):
            seen.append(text)
            return len(text)
        ports = replace(fake_ports(), provider_preflight=lambda request: 'x' * 8000,
                        count_tokens=count)
        with TemporaryDirectory() as root:
            gateway = RequestGateway('B1', 'mock', visible(), ports, CaptureStore(root), None)
            gateway.request('single_pass_full_mapping')
            self.assertEqual(gateway.attempts[0]['input_tokens_preflight'], 8000)
        self.assertEqual(seen, ['x' * 8000])


if __name__ == '__main__':
    unittest.main()

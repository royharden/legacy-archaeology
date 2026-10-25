"""Exact provider envelope byte limits before any ledger/transport side effect."""
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from la.contracts import canonical, digest
from la.providers.evaluation import provider_port, provider_text
from test_accounting import CONFIG


class ProviderPreflight(unittest.TestCase):
    def envelope(self, method, purpose):
        artifact=dict(source_sha256='a'*64,authorization='public synthetic sample',records=[])
        artifact['artifact_sha256']=digest(artifact)
        prompt=dict(purpose=purpose,input=dict(brief='account_ref balance',
                    permitted_samples=artifact,source_sha256='a'*64))
        if method != 'B1':
            prompt['candidates']=[]
        return dict(mode='live',method=method,attempt=1,prompt=prompt,prompt_sha256=digest(prompt),
                    max_input_tokens=8000,max_output_tokens=2000,allow_retries=False,allow_repairs=False)

    def test_wrapped_boundary_for_all_model_arms_without_ledger_or_transport(self):
        """what_bug_this_catches: unwrapped prompt passes but transport envelope exceeds cap."""
        for method in ('B1','C0','R0','R1'):
            with self.subTest(method=method), tempfile.TemporaryDirectory() as temporary:
                ledger=Path(temporary)/'never-created.sqlite'
                port=provider_port(config=CONFIG,ledger_path=ledger,run='public-preflight')
                empty=self.envelope(method,'')
                room=8000-len(provider_text(method,empty['prompt']).encode())
                exact=self.envelope(method,'x'*room)
                oversized=self.envelope(method,'x'*(room+1))
                self.assertLess(len(canonical(oversized['prompt'])),8000)
                with patch('la.providers.evaluation.generate_once',side_effect=AssertionError('transport called')):
                    text=port.preflight(exact)
                    self.assertEqual(len(text.encode()),8000)
                    self.assertEqual(text,provider_text(method,exact['prompt']))
                    with self.assertRaises(ValueError):
                        port.preflight(oversized)
                self.assertFalse(ledger.exists())

    def test_tampered_prompt_and_signed_lower_cap_fail_before_side_effects(self):
        """what_bug_this_catches: stale hashes or a smaller signed cap bypass preflight."""
        with tempfile.TemporaryDirectory() as temporary:
            ledger=Path(temporary)/'never-created.sqlite'
            port=provider_port(config=CONFIG,ledger_path=ledger,run='public-preflight',
                               trusted_authority={'evaluation_phase':'T3','caps':{'max_input_tokens':500}})
            envelope=self.envelope('R1','x'*1000)
            with self.assertRaises(ValueError): port.preflight(envelope)
            envelope=self.envelope('R1',''); envelope['prompt']['purpose']='changed'
            with self.assertRaises(ValueError): port.preflight(envelope)
            self.assertFalse(ledger.exists())

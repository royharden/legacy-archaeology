"""Future factory refusal regression SOURCE; never activates external resources."""
import unittest
from unittest.mock import patch

from la.providers.evaluation import provider_port
from la.contracts import digest


class FactoryRefusalTests(unittest.TestCase):
    def test_t1_extras_without_trusted_capability_refused_before_transport(self):
        """what_bug_this_catches: candidate JSON grants itself signed billing/model authority."""
        port=provider_port(config=None,ledger_path='unused.sqlite',run='synthetic')
        with patch('la.providers.evaluation.generate_once') as transport:
            with self.assertRaises(ValueError): port({'evaluation_phase':'T1','evaluation_authority_sha256':'a'*64})
            transport.assert_not_called()

    def test_changed_t1_price_pin_refused_before_transport(self):
        """what_bug_this_catches: gateway price differs from admitted signed context."""
        config={}
        authority=dict(provider='openai-responses',model='synthetic',price={'evidence_sha256':'a'*64},
            authority_sha256='b'*64,billing_config_sha256=digest(config),
            caps={'max_input_tokens':8000,'max_output_tokens':2000})
        port=provider_port(config=config,ledger_path='unused.sqlite',run='synthetic',trusted_authority=authority)
        request=dict(provider='openai-responses',model='synthetic',price_sha256='c'*64,
                     evaluation_phase='T1',evaluation_authority_sha256='b'*64)
        with patch('la.providers.evaluation.generate_once') as transport:
            with self.assertRaises(ValueError): port(request)
            transport.assert_not_called()

    def test_product_factory_refuses_custody_oracle_context(self):
        """what_bug_this_catches: caller passes hidden context into the inference seam."""
        from scripts.product_ports import factory
        with self.assertRaises(ValueError): factory({'oracle':[]})


if __name__=='__main__': unittest.main()

"""Hand-derived fake transport/accounting regression SOURCE; never real API/keys."""
import tempfile
import unittest
from pathlib import Path
from decimal import Decimal

from la.contracts import digest, sha256
from la.providers.accounting import CallLedger
from la.providers.live import generate_once, single_pass_mapping


CONFIG = dict(authorized=True, activation_verified=True, authority_id='synthetic-test-no-real-authority',
    model='synthetic-model', model_version='synthetic-model-1', api_version_pin='synthetic-wire-v1',
    price_version='synthetic-prices', price_evidence_date='2099-01-01', price_evidence_sha256='a'*64,
    input_usd_per_million='1', cached_input_usd_per_million='0.25', output_usd_per_million='2',
    total_cap_usd='1', max_input_tokens=8000, max_output_tokens=2000)


def response(text='{"ranked_candidate_ids":[],"abstain":true}'):
    return dict(status='completed', model='synthetic-model-1',
        usage=dict(input_tokens=100, output_tokens=20, total_tokens=120,
                   input_tokens_details={'cached_tokens': 20}, output_tokens_details={'reasoning_tokens': 5}),
        output=[{'content': [{'type': 'output_text', 'text': text}]}])


class AccountingTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        self.path = Path(self.tmp.name)/'calls.sqlite'
        self.pins = dict(source_sha256='b'*64, prompt_sha256=sha256(b'{}'))

    def test_raw_usage_prices_cached_and_reasoning_without_double_charge(self):
        """what_bug_this_catches: cached/input or reasoning/output charged twice."""
        result = generate_once('{}', CONFIG, self.path, run='layout', method='rank', pins=self.pins,
                               transport=lambda payload: response())
        # (80*1 +20*.25 +20*2)/1e6 = .000125; reasoning5 is already in output20.
        self.assertEqual(Decimal(result['receipt']['cost_usd']), Decimal('0.000125'))
        self.assertEqual(result['receipt']['raw_usage']['output_tokens_details']['reasoning_tokens'], 5)
        self.assertTrue(result['receipt']['cost_known'])

    def test_ambiguous_failure_blocks_calls_until_cas_billing_reconciliation(self):
        """what_bug_this_catches: timeout silently retried or unknown liability counted zero."""
        count = []
        def timeout(payload):
            count.append(1)
            raise TimeoutError('synthetic failure')
        failed = generate_once('{}', CONFIG, self.path, run='layout', method='rank', pins=self.pins, transport=timeout)
        self.assertEqual(failed['receipt']['status'], 'unknown_liability')
        self.assertIsNone(failed['receipt']['cost_usd'])
        with self.assertRaises(ValueError):
            generate_once('{}', CONFIG, self.path, run='different-layout', method='rank', pins=self.pins, transport=timeout)
        self.assertEqual(len(count), 1)
        ledger = CallLedger(self.path)
        with self.assertRaises(ValueError):
            ledger.reconcile(1, actual_cost_usd='0.02', authority='synthetic-billing', evidence_sha256='c'*64,
                             expected_receipt_sha256='d'*64)
        settled = ledger.reconcile(1, actual_cost_usd='0.02', authority='synthetic-billing', evidence_sha256='c'*64,
                                   expected_receipt_sha256=digest(failed['receipt']))
        self.assertEqual(settled['status'], 'reconciled')
        snapshot = ledger.snapshot()
        self.assertEqual(snapshot['request_attempts'], 1)
        self.assertEqual(snapshot['known_cost_usd'], '0.02')
        self.assertEqual(snapshot['unknown_attempt_ids'], [])
        self.assertEqual(len(snapshot['events']), 3)

    def test_crash_reservation_is_single_flight_across_runs_and_reopen(self):
        """what_bug_this_catches: process restart loses an in-flight budget reservation."""
        CallLedger(self.path).reserve(run='a', method='rank', reserve='0.1', cap='1', pins={})
        reopened = CallLedger(self.path)
        with self.assertRaises(ValueError):
            reopened.reserve(run='b', method='B1', reserve='0.1', cap='1', pins={})
        self.assertEqual(reopened.snapshot()['unknown_attempt_ids'], [1])

    def test_three_product_attempts_include_not_sent_failures(self):
        """what_bug_this_catches: repairs/missing-key attempts evade three-request cap."""
        ledger = CallLedger(self.path)
        for _ in range(3):
            reservation = ledger.reserve(run='same-layout', method='rank', reserve='0.1', cap='1', pins={})
            ledger.finish(reservation, status='not_sent', cost='0')
        with self.assertRaises(ValueError):
            ledger.reserve(run='same-layout', method='rank', reserve='0.1', cap='1', pins={})
        self.assertEqual(ledger.snapshot()['request_attempts'], 3)

    def test_one_pass_b1_malformed_output_consumes_its_only_attempt(self):
        """what_bug_this_catches: a hidden repair turns B1 into a multi-call baseline."""
        first = single_pass_mapping('{}', CONFIG, self.path, run='layout', pins=self.pins,
                                     transport=lambda payload: response('not JSON'))
        self.assertEqual(first['status'], 'failed')
        with self.assertRaises(ValueError):
            single_pass_mapping('{}', CONFIG, self.path, run='layout', pins=self.pins,
                                transport=lambda payload: response('{}'))
        self.assertEqual(CallLedger(self.path).snapshot()['request_attempts'], 1)

    def test_unknown_usage_blocks_instead_of_assuming_zero(self):
        """what_bug_this_catches: unpriced new usage category becomes a fake free call."""
        def unexpected(payload):
            value = response(); value['usage']['new_billable_category'] = 7
            return value
        result = generate_once('{}', CONFIG, self.path, run='layout', method='rank', pins=self.pins, transport=unexpected)
        self.assertFalse(result['receipt']['cost_known'])
        self.assertIsNone(result['receipt']['cost_usd'])

    def test_wrong_model_cannot_use_the_requested_models_price(self):
        """what_bug_this_catches: returned model mismatch manufactures a known billed cost."""
        def different_model(payload):
            value=response(); value['model']='unapproved-other-model'
            return value
        result=generate_once('{}',CONFIG,self.path,run='layout',method='rank',pins=self.pins,transport=different_model)
        self.assertEqual(result['status'],'failed')
        self.assertFalse(result['receipt']['cost_known'])
        self.assertEqual(result['receipt']['status'],'unknown_liability')

    def test_reserve_cap_and_immutable_export(self):
        """what_bug_this_catches: budget ignored or exported history overwritten."""
        ledger = CallLedger(self.path)
        with self.assertRaises(ValueError):
            ledger.reserve(run='a', method='rank', reserve='1.01', cap='1', pins={})
        initial = ledger.export(Path(self.tmp.name)/'exports')
        data = Path(initial['path']).read_bytes()
        ledger.record_non_model_span(run='a', name='parse', elapsed_seconds='0.2')
        later = ledger.export(Path(self.tmp.name)/'exports')
        self.assertNotEqual(initial['path'], later['path'])
        self.assertEqual(Path(initial['path']).read_bytes(), data)

    def test_missing_authority_never_invokes_fake_or_real_transport(self):
        """what_bug_this_catches: a truthy string/key silently activates live spending."""
        called=[]
        for config in (dict(CONFIG,authorized=False),dict(CONFIG,authorized='true'),dict(CONFIG,activation_verified=False)):
            with self.subTest(config=config),self.assertRaises(ValueError):
                generate_once('{}',config,self.path,run='layout',method='rank',pins=self.pins,
                              transport=lambda payload: called.append(payload))
        self.assertEqual(called,[])
        self.assertFalse(self.path.exists())


if __name__ == '__main__': unittest.main()

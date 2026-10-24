"""Public no-network regressions for unsent custody and durable billing state."""
import tempfile
import unittest
from pathlib import Path

from la.providers.accounting import CallLedger
from la.providers.live import MissingCredential, generate_once
from test_accounting import CONFIG
from test_ledger_fence import F, pins, query


class UnsentRegressions(unittest.TestCase):
    def test_missing_transport_credential_can_be_permanently_fenced_after_restart(self):
        """what_bug_this_catches: known zero-cost never-sent calls cannot be voided."""
        from la.contracts import sha256
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary)/'ledger.sqlite'
            request_pins = dict(pins(), prompt_sha256=sha256(b'{}'))
            called = []

            def missing(payload):
                called.append(payload)
                raise MissingCredential('synthetic missing transport; no key lookup')

            result = generate_once('{}', CONFIG, path, run='public-unsent', method='rank',
                                   pins=request_pins, transport=missing)
            self.assertEqual(result['receipt']['status'], 'not_sent')
            self.assertEqual(len(called), 1)
            ledger = CallLedger(path)
            before = ledger.snapshot()
            fenced = ledger.fence_unsent(**query(), fence_id=F)
            self.assertTrue(fenced['fenced'])
            self.assertEqual(CallLedger(path).fence_unsent(**query(), fence_id=F)['fence'], fenced['fence'])
            after = ledger.snapshot()
            self.assertEqual(after['request_attempts'], 1)
            self.assertEqual(after['calls'], before['calls'])
            self.assertEqual(after['known_cost_usd'], '0')
            self.assertEqual(after['unknown_attempt_ids'], [])
            self.assertEqual(after['events'][:len(before['events'])], before['events'])
            with self.assertRaises(ValueError):
                ledger.reserve(run='retry-new-layout', method='rank', reserve='0.1', cap='1', pins=request_pins)
            self.assertEqual(len(called), 1)

    def test_nonzero_not_sent_cost_is_rejected_without_settling_reservation(self):
        """what_bug_this_catches: billed work is misrepresented as safely never sent."""
        with tempfile.TemporaryDirectory() as temporary:
            ledger = CallLedger(Path(temporary)/'ledger.sqlite')
            reservation = ledger.reserve(run='public-cost', method='rank', reserve='0.1', cap='1', pins=pins())
            with self.assertRaises(ValueError):
                ledger.finish(reservation, status='not_sent', cost='0.01')
            self.assertEqual(ledger.snapshot()['calls'][0]['status'], 'reserved')

    def test_unknown_and_completed_attempts_prevent_unsent_fence(self):
        """what_bug_this_catches: a zero not_sent row hides another sent/unknown row."""
        for status, cost in (('unknown_liability', None), ('completed', '0')):
            with self.subTest(status=status), tempfile.TemporaryDirectory() as temporary:
                ledger = CallLedger(Path(temporary)/'ledger.sqlite')
                first = ledger.reserve(run='public-mixed', method='rank', reserve='0.1', cap='1', pins=pins())
                ledger.finish(first, status='not_sent', cost='0')
                second = ledger.reserve(run='public-mixed', method='rank', reserve='0.1', cap='1', pins=pins())
                ledger.finish(second, status=status, cost=cost)
                result = ledger.fence_unsent(**query(), fence_id=F)
                self.assertFalse(result['fenced'])
                self.assertIsNone(result['fence'])
                self.assertEqual(ledger.snapshot()['request_attempts'], 2)

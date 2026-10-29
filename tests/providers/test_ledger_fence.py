"""CallLedger fence_unsent regression SOURCE (T3-LIVE-API A1.1); not executed in Dirty Mode."""
import hashlib
import json
import tempfile
import unittest
from pathlib import Path

from la.providers.accounting import CallLedger

A, P, S, F = 'a' * 64, 'b' * 64, 'c' * 64, 'f' * 64


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':'),
                                     ensure_ascii=False, allow_nan=False).encode()).hexdigest()


def pins(phase='T3', method='R0', prompt=P):
    return {'prompt_sha256': 'd' * 64, 'source_sha256': S, 'sample_artifact_sha256': 'e' * 64,
            'evaluator_method': method, 'gateway_prompt_sha256': prompt,
            'evaluation_phase': phase, 'evaluation_authority_sha256': A}


def query(**overrides):
    value = dict(evaluation_phase='T3', evaluation_authority_sha256=A, gateway_prompt_sha256=P,
                 source_sha256=S, evaluator_method='R0')
    value.update(overrides)
    return value


class LedgerFenceSource(unittest.TestCase):

    def ledger(self, root):
        return CallLedger(Path(root) / 'ledger.sqlite')

    def test_unsent_call_is_fenced_and_never_reservable(self):
        """what_bug_this_catches: a voided call is sent later (the A1 attestation race)."""
        with tempfile.TemporaryDirectory() as root:
            ledger = self.ledger(root)
            value = ledger.fence_unsent(**query(), fence_id=F)
            self.assertIs(value['fenced'], True)
            self.assertEqual(value['attempts'], [])
            self.assertEqual({k: value['fence'][k] for k in query()}, query())
            self.assertEqual(value['fence']['fence_id'], F)
            self.assertEqual((value['fence']['cost_known'], value['fence']['cost_usd']), (True, '0'))
            self.assertEqual(value['attestation_sha256'], digest({k: v for k, v in value.items() if k != 'attestation_sha256'}))
            with self.assertRaises(ValueError):
                ledger.reserve(run='T3:x', method='rank', reserve='0.01', cap='1', pins=pins())
            # A different call (another prompt) is not fenced.
            ledger.reserve(run='T3:x', method='rank', reserve='0.01', cap='1', pins=pins(prompt='9' * 64))

    def test_reserved_call_is_reported_and_not_fenced(self):
        """what_bug_this_catches: a sent/in-flight call is tombstoned and voided while billed."""
        with tempfile.TemporaryDirectory() as root:
            ledger = self.ledger(root)
            ledger.reserve(run='T3:x', method='rank', reserve='0.01', cap='1', pins=pins())
            value = ledger.fence_unsent(**query(), fence_id=F)
            self.assertIs(value['fenced'], False)
            self.assertIsNone(value['fence'])
            self.assertEqual(len(value['attempts']), 1)
            self.assertEqual(ledger.snapshot().get('fences'), None)

    def test_exact_retry_returns_existing_fence_and_other_fence_id_sees_it(self):
        """what_bug_this_catches: retries add tombstones, or a second call_id reuses another call's fence."""
        with tempfile.TemporaryDirectory() as root:
            ledger = self.ledger(root)
            first = ledger.fence_unsent(**query(), fence_id=F)
            again = ledger.fence_unsent(**query(), fence_id=F)
            self.assertEqual(again['fence'], first['fence'])
            self.assertEqual(len(ledger.snapshot()['fences']), 1)
            other = ledger.fence_unsent(**query(), fence_id='e' * 64)
            self.assertIs(other['fenced'], False)
            self.assertEqual(len(other['attempts']), 1)

    def test_fences_are_not_request_attempts_in_snapshot(self):
        """what_bug_this_catches: a tombstone inflates request counts or known cost."""
        with tempfile.TemporaryDirectory() as root:
            ledger = self.ledger(root)
            ledger.fence_unsent(**query(), fence_id=F)
            snapshot = ledger.snapshot()
            self.assertEqual((snapshot['request_attempts'], snapshot['calls'], snapshot['known_cost_usd']), (0, [], '0'))

    def test_invalid_inputs_refuse(self):
        """what_bug_this_catches: an unknown phase/method or non-hash pin yields a fence."""
        with tempfile.TemporaryDirectory() as root:
            ledger = self.ledger(root)
            for change, fence in ((dict(evaluation_phase='T2'), F), (dict(evaluator_method='B0'), F),
                                  (dict(source_sha256='not-a-hash'), F), ({}, 'not-a-hash')):
                with self.subTest(change=change, fence=fence), self.assertRaises(ValueError):
                    ledger.fence_unsent(**query(**change), fence_id=fence)


if __name__ == '__main__':
    unittest.main()

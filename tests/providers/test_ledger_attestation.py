"""CallLedger attempts_matching attestation regression SOURCE (T3-LIVE-API A1); not executed in Dirty Mode."""
import hashlib
import json
import tempfile
import unittest
from pathlib import Path

from la.providers.accounting import CallLedger

A, P, S = 'a' * 64, 'b' * 64, 'c' * 64


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


class LedgerAttestationSource(unittest.TestCase):

    def ledger(self, root):
        return CallLedger(Path(root) / 'ledger.sqlite')

    def test_empty_match_is_hash_pinned_and_writes_nothing(self):
        """what_bug_this_catches: the attestation mutates the ledger or omits its path/self pin."""
        with tempfile.TemporaryDirectory() as root:
            ledger = self.ledger(root)
            before = (Path(root) / 'ledger.sqlite').read_bytes()
            value = ledger.attempts_matching(**query())
            self.assertEqual((Path(root) / 'ledger.sqlite').read_bytes(), before)
            self.assertEqual(value['attempts'], [])
            self.assertEqual(value['query'], query())
            self.assertEqual(value['ledger_path_sha256'], digest(str((Path(root) / 'ledger.sqlite').resolve())))
            self.assertEqual(set(value), {'schema_version', 'kind', 'ledger_path_sha256', 'query', 'attempts',
                                          'observed_at', 'attestation_sha256'})
            self.assertEqual(value['attestation_sha256'], digest({k: v for k, v in value.items() if k != 'attestation_sha256'}))

    def test_reserved_attempt_matches_only_on_all_five_keys(self):
        """what_bug_this_catches: a sent call is attested as never sent, or a T1 row satisfies a T3 query."""
        with tempfile.TemporaryDirectory() as root:
            ledger = self.ledger(root)
            ledger.reserve(run='T3:x', method='rank', reserve='0.01', cap='1', pins=pins())
            self.assertEqual(len(ledger.attempts_matching(**query())['attempts']), 1)
            for change in (dict(evaluation_phase='T1'), dict(evaluator_method='R1'), dict(gateway_prompt_sha256='f' * 64)):
                with self.subTest(change):
                    self.assertEqual(ledger.attempts_matching(**query(**change))['attempts'], [])

    def test_invalid_inputs_refuse(self):
        """what_bug_this_catches: an unknown phase/method or non-hash pin yields an empty 'never sent' proof."""
        with tempfile.TemporaryDirectory() as root:
            ledger = self.ledger(root)
            for change in (dict(evaluation_phase='T2'), dict(evaluator_method='B0'),
                           dict(source_sha256='not-a-hash'), dict(evaluation_authority_sha256=None)):
                with self.subTest(change), self.assertRaises(ValueError):
                    ledger.attempts_matching(**query(**change))


if __name__ == '__main__':
    unittest.main()

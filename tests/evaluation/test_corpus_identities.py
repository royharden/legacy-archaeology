"""Independent literal/identity regression SOURCE; generator is not run here."""
from copy import deepcopy
import hashlib
import json
from pathlib import Path
import unittest

from evaluator_support import gold, normalized
from evaluation.artifacts import canonical, digest
from evaluation.corpus import development_layouts, build_development_variant
from evaluation.generator import serialize, attach_refs
from evaluation.scorer import score, aggregate_variant_reports


class CorpusIdentities(unittest.TestCase):
    def test_hand_calculated_leading_and_trailing_serialization(self):
        """what_bug_this_catches: sign/scale/padding/date encoder disagrees with gold."""
        row = {'account_ref': '000001', 'description': 'Z', 'balance': '-0.01',
               'effective_date': '2024-02-29', 'status': 'A'}
        leading = development_layouts()[0]
        self.assertEqual(serialize([row], leading), b'000001Z           -0000000120240229A\n')
        trailing = development_layouts()[1]
        row['balance'] = '-0.123'
        self.assertEqual(serialize([row], trailing), b'A24022900000123-000001            Z')

    def test_documented_v2_offset_identity_without_ingest_import(self):
        """what_bug_this_catches: oracle/product legacy-v1 versus framing-v2 mismatch."""
        layout = {'framing': 'CRLF', 'framing_version': 2, 'width': 2, 'terminal_newline': False}
        values = [{'account_ref': '000001', 'description': '', 'balance': '0.00',
                   'effective_date': None, 'status': 'A'}] * 2
        records = attach_refs(b'AB\r\nCD', values, layout)
        descriptor = {'version': 2, 'framing': 'CRLF', 'width': 2,
                      'width_candidates': [2], 'terminal_newline': False}
        self.assertEqual([row['record_ref']['byte_start'] for row in records], [0, 4])
        self.assertEqual(records[0]['record_ref']['framing_sha256'], digest(descriptor))
        self.assertEqual(records[1]['record_ref']['raw_sha256'], hashlib.sha256(b'CD').hexdigest())

    def test_public_variant_counts_and_no_hidden_creation(self):
        """what_bug_this_catches: wrong split, incomplete batches or malformed strata disappear."""
        corpus = build_development_variant('dev-02')
        self.assertEqual(len(corpus['batches']), 10)
        self.assertTrue(all(len(batch['oracle']) == 100 for batch in corpus['batches']))
        self.assertEqual(corpus['malformed_records'], 30)
        self.assertEqual(set(corpus['malformed_counts'].values()), {5})
        self.assertEqual(corpus['benchmark_status'], 'not_run')
        with self.assertRaises(ValueError):
            build_development_variant('dev-02', edition='hidden-edition')

    def test_macro_variant_mean_does_not_pool_correlated_rows(self):
        """what_bug_this_catches: micro row rate mislabeled macro layout mean."""
        reports = [score(gold(), normalized()), score(gold()[:1], [])]
        combined = aggregate_variant_reports(reports)
        self.assertEqual(combined['semantic_rows']['rate'], .75)
        self.assertEqual(combined['variant_rows']['mean'], .5)
        self.assertEqual(combined['variant_rows']['min'], 0)

    def test_revised_public_fixture_pins_and_hand_semantics(self):
        """what_bug_this_catches: fixture null/framing repair mutates independent gold."""
        root = Path(__file__).resolve().parents[2] / 'fixtures/dev/account-dev-01'
        source = (root / 'source.dat').read_bytes()
        layout = json.loads((root / 'layout.json').read_text())
        oracle = json.loads((root / 'oracle.json').read_text())
        samples = json.loads((root / 'samples.json').read_text())
        self.assertEqual(hashlib.sha256(source).hexdigest(), '84ff2a0b1da15ab0d0820ea03fea9cdcbfd95979cff261dc6cad5da4e9d960a7')
        self.assertEqual(source.split(b'\n')[2][27:35], b'99999999')
        self.assertIsNone(oracle['records'][2]['fields']['effective_date']['value'])
        self.assertEqual(oracle['records'][3]['fields']['balance']['value'], '0.00')
        self.assertEqual(oracle['records'][0]['fields']['account_ref']['value'], '000001')
        self.assertEqual(oracle['records'][6]['fields'], oracle['records'][7]['fields'])
        self.assertNotEqual(oracle['records'][6]['record_ref'], oracle['records'][7]['record_ref'])
        self.assertEqual(samples['artifact_sha256'], digest({k: v for k, v in samples.items() if k != 'artifact_sha256'}))
        self.assertTrue(all({'padding_byte', 'padding_side', 'trim', 'nullable'} <= field['policy'].keys()
                            for field in layout['fields']))


if __name__ == '__main__':
    unittest.main()

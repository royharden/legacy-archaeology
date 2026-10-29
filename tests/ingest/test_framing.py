"""Regression SOURCE only; Dirty Mode authors did not collect or execute it."""
import hashlib
import json
import unittest

from la.ingest import LIMITS, ingest_bytes, verify_records

BRIEF = 'account_ref description balance effective_date status'


def ingest(data, **declarations):
    artifact = {'source_sha256': hashlib.sha256(data).hexdigest(),
                'authorization': 'public hand-written test input', 'records': []}
    return ingest_bytes(data, BRIEF, artifact, **declarations)


def canonical_hash(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':'),
                                    ensure_ascii=False, allow_nan=False).encode()).hexdigest()


class FramingRegressionSource(unittest.TestCase):
    def test_lf_and_crlf_offsets_with_and_without_final_newline(self):
        """what_bug_this_catches: normalized separators shift later evidence offsets."""
        cases = [
            (b'AB\nCD\n', [0, 3], [2, 5], ['0a', '0a'], 'LF', True),
            (b'AB\nCD', [0, 3], [2, 5], ['0a', ''], 'LF', False),
            (b'AB\r\nCD\r\n', [0, 4], [2, 6], ['0d0a', '0d0a'], 'CRLF', True),
            (b'AB\r\nCD', [0, 4], [2, 6], ['0d0a', ''], 'CRLF', False),
        ]
        for data, starts, endings, hexes, style, terminal in cases:
            with self.subTest(data=data):
                batch = ingest(data)
                self.assertEqual(batch['status'], 'accepted')
                self.assertEqual([record['byte_start'] for record in batch['records']], starts)
                self.assertEqual([record['length'] for record in batch['records']], [2, 2])
                self.assertEqual([record['ordinal'] for record in batch['records']], [0, 1])
                self.assertEqual([item['byte_start'] for item in batch['intake']['separators']], endings)
                self.assertEqual([item['raw_hex'] for item in batch['intake']['separators']], hexes)
                descriptor = {'version': 2, 'framing': style, 'width': 2,
                              'width_candidates': [2], 'terminal_newline': terminal}
                self.assertEqual(batch['framing_sha256'], canonical_hash(descriptor))
                reconstructed = b''.join(bytes.fromhex(record['raw_hex']) + bytes.fromhex(separator['raw_hex'])
                                         for record, separator in zip(batch['records'], batch['intake']['separators']))
                self.assertEqual(reconstructed, data)
                verify_records(batch, data)

    def test_tied_widths_remain_unresolved_without_arbitrary_winner(self):
        """what_bug_this_catches: encounter order used to choose a tied record width."""
        for data in (b'AB\nC\n', b'C\nAB\n'):
            with self.subTest(data=data):
                batch = ingest(data)
                self.assertEqual(batch['status'], 'refused')
                self.assertIsNone(batch['width'])
                self.assertEqual(batch['intake']['width_candidates'], [1, 2])
                self.assertEqual(batch['intake']['width_question']['options'], [1, 2, 'unknown'])
                self.assertEqual(len(batch['records']), 2)
                for record in batch['records']:
                    self.assertIn('unresolved_width', record['reasons'])
                    self.assertNotIn('wrong_length', record['reasons'])

    def test_short_blank_and_high_byte_rows_are_retained_once(self):
        """what_bug_this_catches: malformed or blank input rows disappear from denominators."""
        data = b'AB\nCD\n\nE\nF\xff'
        batch = ingest(data)
        self.assertEqual(batch['status'], 'accepted')
        self.assertEqual(batch['width'], 2)
        self.assertEqual([record['byte_start'] for record in batch['records']], [0, 3, 6, 7, 9])
        self.assertEqual([record['ordinal'] for record in batch['records']], [0, 1, 2, 3, 4])
        self.assertIn('blank_record', batch['records'][2]['reasons'])
        self.assertIn('wrong_length', batch['records'][3]['reasons'])
        self.assertIn('high_byte', batch['records'][4]['reasons'])
        self.assertEqual(sum(record['disposition'] == 'eligible' for record in batch['records']), 2)
        self.assertEqual(sum(record['disposition'] == 'quarantined' for record in batch['records']), 3)
        self.assertEqual(batch['intake']['observed_record_count'], 5)
        self.assertFalse(batch['intake']['final_record_eligible'])
        verify_records(batch, data)

    def test_short_unterminated_final_row_is_not_silently_accepted(self):
        """what_bug_this_catches: final-newline exception bypasses width checks."""
        batch = ingest(b'AB\nCD\nE')
        self.assertEqual(batch['status'], 'accepted')
        self.assertEqual(len(batch['records']), 3)
        self.assertEqual(batch['records'][-1]['raw_hex'], '45')
        self.assertIn('wrong_length', batch['records'][-1]['reasons'])
        self.assertFalse(batch['intake']['final_record_width_valid'])

    def test_mixed_and_bare_cr_refusals_preserve_record_accounting(self):
        """what_bug_this_catches: splitting on generic lines normalizes malformed transport."""
        for data, reason in ((b'AB\r\nCD\n', 'mixed_separators'), (b'A\rB\nCDE\n', 'bare_cr')):
            with self.subTest(reason=reason):
                batch = ingest(data)
                self.assertEqual(batch['status'], 'refused')
                self.assertIn(reason, batch['reasons'])
                self.assertEqual(len(batch['records']), 2)
                self.assertEqual(batch['intake']['observed_record_count'], 2)
                verify_records(batch, data)

    def test_limit_refusals_do_not_claim_zero_input_or_expand_rows(self):
        """what_bug_this_catches: early refusal loses input denominator or allocates huge hex rows."""
        cases = [(b'A' * (LIMITS['bytes'] + 1), 1, 'file_limit'),
                 (b'A\n' * (LIMITS['records'] + 1), LIMITS['records'] + 1, 'record_limit')]
        for data, observed, reason in cases:
            with self.subTest(reason=reason):
                batch = ingest(data)
                self.assertEqual(batch['status'], 'refused')
                self.assertIn(reason, batch['reasons'])
                self.assertEqual(batch['records'], [])
                self.assertEqual(batch['source_sha256'], hashlib.sha256(data).hexdigest())
                self.assertEqual(batch['intake']['observed_record_count'], observed)
                self.assertEqual(batch['intake']['unmaterialized_record_count'], observed)
                self.assertEqual(batch['intake']['materialized_record_count'], 0)

    def test_empty_separatorless_oversize_width_and_unsupported_declarations(self):
        """what_bug_this_catches: unsupported data is mislabeled as an empty successful batch."""
        for data, declarations, reason in [
            (b'', {}, 'empty_input'), (b'AB', {}, 'separatorless_unsupported'),
            (b'AB\n', {'declared_encoding': 'EBCDIC'}, 'unsupported_encoding'),
            (b'AB\n', {'declared_numeric': 'packed_decimal'}, 'unsupported_packed_decimal'),
            (b'AB\n', {'declared_family': 'mixed'}, 'unsupported_record_family')]:
            with self.subTest(reason=reason):
                batch = ingest(data, **declarations)
                self.assertEqual(batch['status'], 'refused')
                self.assertIn(reason, batch['reasons'])
        wide = ingest(b'A' * 257 + b'\n' + b'B' * 257 + b'\n')
        self.assertEqual(len(wide['records']), 2)
        self.assertTrue(all('record_width_limit' in record['reasons'] for record in wide['records']))


if __name__ == '__main__':
    unittest.main()

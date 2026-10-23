"""Future regression source; never executed during Dirty Mode construction."""
from copy import deepcopy
import unittest

from evaluator_support import gold, normalized, product_rows, mapping
from evaluation.scorer import score, score_product


class SemanticDenominators(unittest.TestCase):
    def test_full_valid_and_malformed_denominators(self):
        """what_bug_this_catches: quarantine rows inflate valid semantic rates."""
        report = score(gold(), normalized())
        self.assertEqual(report['semantic_rows'], {'numerator': 3, 'denominator': 3, 'rate': 1.0})
        self.assertEqual(report['semantic_fields']['denominator'], 15)
        self.assertEqual(report['all_record_outcomes']['numerator'], 4)
        self.assertEqual(report['all_record_outcomes']['denominator'], 4)
        self.assertEqual(report['row_parity'], 'exact')

    def test_wrong_target_type_null_scale_and_calendar(self):
        """what_bug_this_catches: type/name/NULL/scale coercion repairs wrong cells."""
        for change in ('name', 'type', 'null', 'scale', 'date'):
            with self.subTest(change=change):
                rows = normalized()
                if change == 'name':
                    rows[0]['fields']['business_id'] = rows[0]['fields'].pop('account_ref')
                elif change == 'type':
                    rows[0]['fields']['account_ref']['data_type'] = 'integer'
                elif change == 'null':
                    rows[1]['fields']['effective_date']['value'] = ''
                elif change == 'scale':
                    rows[0]['fields']['balance']['value'] = '12.340'
                else:
                    rows[0]['fields']['effective_date']['value'] = '2023-02-29'
                report = score(gold(), rows)
                self.assertEqual(report['semantic_rows']['numerator'], 2)
                self.assertEqual(report['semantic_rows']['denominator'], 3)
                self.assertEqual(report['row_parity'], 'mismatch')

    def test_missing_extra_duplicate_and_swapped_refs(self):
        """what_bug_this_catches: business-key alignment or best-duplicate selection."""
        for change in ('missing', 'extra', 'duplicate', 'swap'):
            with self.subTest(change=change):
                rows = normalized()
                if change == 'missing':
                    rows.pop(0)
                elif change == 'extra':
                    extra = deepcopy(rows[0]); extra['record_ref']['ordinal'] = 99; rows.append(extra)
                elif change == 'duplicate':
                    rows.append(deepcopy(rows[0]))
                else:
                    rows[0]['record_ref'], rows[1]['record_ref'] = rows[1]['record_ref'], rows[0]['record_ref']
                report = score(gold(), rows)
                self.assertEqual(report['semantic_rows']['denominator'], 3)
                self.assertEqual(report['row_parity'], 'mismatch')
                if change == 'swap':
                    self.assertTrue(report['aggregates']['cardinality_reconciled'])
                else:
                    self.assertFalse(report['aggregates']['cardinality_reconciled'])
                if change == 'duplicate':
                    self.assertEqual(report['semantic_fields']['numerator'], 10)

    def test_false_quarantine_and_reason_precision(self):
        """what_bug_this_catches: false quarantine vanishes from the valid denominator."""
        rows = normalized()
        rows[0].update(outcome='quarantined', fields={}, reasons=['high_byte'])
        report = score(gold(), rows)
        self.assertEqual(report['false_quarantine'], 1)
        self.assertEqual(report['semantic_rows']['numerator'], 2)
        self.assertEqual(report['quarantine_by_reason']['high_byte']['precision']['denominator'], 2)
        self.assertEqual(report['quarantine_by_reason']['high_byte']['recall']['numerator'], 1)

    def test_empty_failed_and_malformed_wire(self):
        """what_bug_this_catches: no output scores 100%, malformed wire drops rows."""
        empty = score([], [])
        self.assertIsNone(empty['semantic_rows']['rate'])
        self.assertEqual(empty['row_parity'], 'incomplete')
        for rows in ([], [None], [{'record_ref': {'ordinal': []}}]):
            report = score(gold(), rows)
            self.assertEqual(report['semantic_rows']['numerator'], 0)
            self.assertEqual(report['semantic_rows']['denominator'], 3)
        report = score_product(gold(), [{'record_ref': {}, 'values': []}], mapping())
        self.assertEqual(report['semantic_fields']['numerator'], 0)


if __name__ == '__main__':
    unittest.main()

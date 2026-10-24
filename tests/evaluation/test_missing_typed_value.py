"""Independent hand-value regressions for closed typed semantic observations."""
from copy import deepcopy
import unittest

from evaluator_support import gold, normalized
from evaluation.scorer import score


class MissingTypedValue(unittest.TestCase):
    def test_absent_null_value_is_incorrect_with_full_denominator(self):
        """what_bug_this_catches: missing value key masquerades as explicit SQL NULL."""
        rows = normalized()
        del rows[1]['fields']['effective_date']['value']
        result = score(gold(), rows)
        self.assertEqual(result['row_parity'], 'mismatch')
        self.assertEqual(result['semantic_rows']['numerator'], 2)
        self.assertEqual(result['semantic_rows']['denominator'], 3)
        self.assertEqual(result['semantic_fields']['numerator'], 14)
        self.assertEqual(result['semantic_fields']['denominator'], 15)

    def test_explicit_null_remains_exact_and_extra_wire_key_fails(self):
        """what_bug_this_catches: permissive typed field wire bypasses schema closure."""
        self.assertEqual(score(gold(), normalized())['row_parity'], 'exact')
        rows = deepcopy(normalized())
        rows[1]['fields']['effective_date']['unresolved'] = True
        self.assertEqual(score(gold(), rows)['row_parity'], 'mismatch')

    def test_invalid_identity_quarantine_still_counts_as_prediction(self):
        """what_bug_this_catches: unjoinable quarantine disappears from precision."""
        rows = normalized()
        rows.append({'record_ref': {}, 'outcome': 'quarantined',
                     'reasons': ['high_byte'], 'fields': {}})
        result = score(gold(), rows)
        self.assertEqual(result['row_parity'], 'mismatch')
        self.assertEqual(result['invalid_record_refs'], [4])
        self.assertEqual(result['quarantine_by_reason']['high_byte']['precision'],
                         {'numerator': 1, 'denominator': 2, 'rate': 0.5})


if __name__ == '__main__':
    unittest.main()

"""Hand-derived text policies keep padding evidence separate from sentinels."""
import unittest

from la.convert import decode_value
from la.inference.alternatives import policy_alternatives, status_vocabulary


class BlankPaddingRegressions(unittest.TestCase):
    def policies(self, raws):
        policies, metadata = policy_alternatives(raws, 'description', status_vocabulary('description'))
        self.assertLessEqual(len(policies), 3)
        self.assertEqual(metadata['max_policy_alternatives'], 3)
        self.assertEqual(metadata['unknown_option'], 'unknown')
        return policies, metadata

    def assert_three_distinct_meanings(self, raws, side, sentinel):
        policies, metadata = self.policies(raws)
        self.assertEqual(metadata['observed_left_padding'], side == 'left')
        self.assertEqual(metadata['observed_right_padding'], side == 'right')
        preserve = [p for p in policies if p['padding_side'] == 'none'
                    and p['trim'] is False and p['nullable'] is False]
        trimmed = [p for p in policies if p['padding_side'] == side
                   and p['trim'] is True and p['nullable'] is False]
        null = [p for p in policies if p['padding_side'] == side
                and p['trim'] is True and p['nullable'] is True
                and p.get('sentinels', {}).get(sentinel.decode()) == 'null']
        self.assertEqual(len(preserve), 1, 'literal nonnull preservation must remain offered')
        self.assertEqual(len(trimmed), 1, 'observed-side trim must remain distinct from NULL')
        self.assertEqual(len(null), 1, 'NULL needs an explicit separately selectable policy')
        field = dict(start=0, end=len(sentinel), semantic_target='description', data_type='text')
        self.assertEqual(decode_value(sentinel, dict(field, policy=preserve[0])), sentinel.decode())
        self.assertEqual(decode_value(sentinel, dict(field, policy=trimmed[0])), sentinel.decode().strip(' '))
        self.assertIsNone(decode_value(sentinel, dict(field, policy=null[0])))
        other_side = 'left' if side == 'right' else 'right'
        self.assertFalse(any(p['padding_side'] == other_side for p in policies))
        self.assertGreater(metadata['unoffered_combination_count'], 0)

    def test_blank_does_not_invent_left_padding_or_remove_literal_right_padded_text(self):
        """what_bug_this_catches: blank sentinel changes observed right-only padding into both sides."""
        self.assert_three_distinct_meanings([b'     ', b'A    ', b'B    '], 'right', b'     ')

    def test_blank_does_not_invent_right_padding_or_remove_literal_left_padded_text(self):
        """what_bug_this_catches: inverse left-padding evidence loses the no-trim nonnull alternative."""
        self.assert_three_distinct_meanings([b'     ', b'    A', b'    B'], 'left', b'     ')

    def test_all_nines_sentinel_keeps_literal_nonnull_text_selectable(self):
        """what_bug_this_catches: sentinel presence makes every no-trim option implicitly nullable."""
        self.assert_three_distinct_meanings([b'99999', b'A    ', b'B    '], 'right', b'99999')

    def test_only_blank_samples_establish_neither_padding_direction(self):
        """what_bug_this_catches: allblank-only samples pretend to establish a padding direction."""
        policies, metadata = self.policies([b'     ', b'     '])
        self.assertFalse(metadata['observed_left_padding'])
        self.assertFalse(metadata['observed_right_padding'])
        self.assertEqual(metadata['sentinel_lexemes'], ['     '])
        self.assertTrue(any(p['padding_side'] == 'none' and p['trim'] is False
                            and p['nullable'] is False for p in policies))
        self.assertGreater(metadata['unoffered_combination_count'], 0)


if __name__ == '__main__':
    unittest.main()

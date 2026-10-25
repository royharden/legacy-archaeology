"""Hand-derived answer policy edges; no product decoder or gold imports."""
from copy import deepcopy
import unittest

from evaluation.answer_policy import offered_policy_matches, policy_wire


def date_field():
    return dict(start=0, end=8, semantic_target='effective_date', data_type='date',
                policy=dict(padding_byte=' ', padding_side='none', trim=False, nullable=True,
                            format='YYYYMMDD', sentinels={'99999999': 'null'}))


class AnswerPolicy(unittest.TestCase):
    def test_absent_empty_sentinel_default_is_meaningfully_equal(self):
        """what_bug_this_catches: optional empty default makes correct option unknown."""
        expected = date_field(); expected['policy'].pop('sentinels')
        offered = deepcopy(expected); offered['policy']['sentinels'] = {}
        self.assertTrue(offered_policy_matches(offered, expected))

    def test_invalid_yyyy_window_is_not_required_or_accepted(self):
        """what_bug_this_catches: broker demands a forbidden irrelevant date axis."""
        expected = date_field()
        self.assertTrue(offered_policy_matches(deepcopy(expected), expected))
        offered = deepcopy(expected); offered['policy']['century_window'] = [1970, 2069]
        self.assertFalse(offered_policy_matches(offered, expected))
        with self.assertRaises(ValueError): policy_wire(offered)

    def test_every_meaningful_axis_and_exact_types_remain_binding(self):
        """what_bug_this_catches: normalization repairs real scale/null/trim/offset errors."""
        expected = date_field()
        for axis, value in [('nullable', False), ('trim', True), ('padding_side', 'right'),
                            ('format', 'YYMMDD'), ('sentinels', {}), ('nullable', 1)]:
            offered = deepcopy(expected); offered['policy'][axis] = value
            self.assertFalse(offered_policy_matches(offered, expected), axis)
        offered = deepcopy(expected); offered['start'] = False
        self.assertFalse(offered_policy_matches(offered, expected))
        offered = deepcopy(expected); offered['semantic_target'] = 'description'
        self.assertFalse(offered_policy_matches(offered, expected))
        decimal = dict(start=0, end=9, semantic_target='balance', data_type='decimal',
            policy=dict(padding_byte=' ', padding_side='none', trim=False, nullable=False,
                        sign='leading', scale=2, precision=7))
        for axis, value in [('sign', 'trailing'), ('scale', 3), ('scale', True), ('precision', 8)]:
            offered = deepcopy(decimal); offered['policy'][axis] = value
            self.assertFalse(offered_policy_matches(offered, decimal), axis)


if __name__ == '__main__':
    unittest.main()

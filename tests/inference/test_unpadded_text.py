"""Side declarations do not themselves authorize removal of unobserved padding."""
import unittest

from la.convert import decode_value
from la.inference import hypothesize
from la.inference.alternatives import policy_alternatives, status_vocabulary
from test_public_candidate_closure import batch

TARGETS = ('account_ref', 'description', 'status')
BRIEF = 'account_ref description status. No interpretation has been selected.'


class UnpaddedTextRegressions(unittest.TestCase):
    def proposed(self, raws, target):
        policies, metadata = policy_alternatives(raws, target, status_vocabulary(BRIEF))
        self.assertLessEqual(len(policies), 3)
        self.assertEqual(metadata['unknown_option'], 'unknown')
        self.assertEqual(metadata['coverage'], 'bounded_proposals_not_exhaustive')
        return policies, metadata

    def decode(self, raw, target, policy):
        return decode_value(raw, dict(start=0, end=len(raw), semantic_target=target,
                                      data_type='text', policy=policy))

    def test_unpadded_side_alternatives_preserve_bytes_without_enabling_trim(self):
        """what_bug_this_catches: side!=none silently forces trim=true without padding evidence."""
        raws = [b'ZX81', b'Q902']
        for target in TARGETS:
            with self.subTest(target=target):
                policies, metadata = self.proposed(raws, target)
                self.assertFalse(metadata['observed_left_padding'])
                self.assertFalse(metadata['observed_right_padding'])
                self.assertEqual({p['padding_side'] for p in policies}, {'none', 'left', 'right'})
                self.assertTrue(all(p['trim'] is False and p['nullable'] is False for p in policies))
                for policy in policies:
                    for raw in raws:
                        self.assertEqual(self.decode(raw, target, policy), raw.decode())
        generation = hypothesize(batch(raws, BRIEF), BRIEF)
        self.assertEqual(generation['discovery']['full_mapping_status'], 'unconfirmed')
        self.assertTrue(generation['unknowns'])

    def test_real_observed_padding_still_offers_explicit_trim(self):
        """what_bug_this_catches: decoupling trim removes actual observed-edge proposals."""
        for side, raws in (('left', [b'  ZX', b' Q90']), ('right', [b'ZX  ', b'Q90 '])):
            for target in TARGETS:
                with self.subTest(side=side, target=target):
                    policies, metadata = self.proposed(raws, target)
                    self.assertEqual(metadata['observed_left_padding'], side == 'left')
                    self.assertEqual(metadata['observed_right_padding'], side == 'right')
                    trimmed = [p for p in policies if p['padding_side'] == side
                               and p['trim'] is True and p['nullable'] is False]
                    self.assertTrue(trimmed)
                    self.assertEqual([self.decode(raw, target, trimmed[0]) for raw in raws], ['ZX', 'Q90'])

    def test_blank_sentinel_reserves_literal_empty_and_null_without_inventing_side(self):
        """what_bug_this_catches: no-padding fix collapses blank literal/empty/NULL choices."""
        for raws in ([b'    ', b'ZX81'], [b'    ', b'    ']):
            for target in TARGETS:
                with self.subTest(raws=raws, target=target):
                    policies, metadata = self.proposed(raws, target)
                    self.assertFalse(metadata['observed_left_padding'])
                    self.assertFalse(metadata['observed_right_padding'])
                    preserve = [p for p in policies if p['trim'] is False and p['nullable'] is False]
                    empty = [p for p in policies if p['trim'] is True and p['nullable'] is False]
                    null = [p for p in policies if p['nullable'] is True
                            and p.get('sentinels', {}).get('    ') == 'null']
                    self.assertEqual((len(preserve), len(empty), len(null)), (1, 1, 1))
                    self.assertEqual(self.decode(b'    ', target, preserve[0]), '    ')
                    self.assertEqual(self.decode(b'    ', target, empty[0]), '')
                    self.assertIsNone(self.decode(b'    ', target, null[0]))


if __name__ == '__main__':
    unittest.main()

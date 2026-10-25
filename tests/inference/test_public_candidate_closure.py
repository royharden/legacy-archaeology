"""Independent public regressions for bounded byte and policy proposals."""
from collections import Counter
import hashlib
import unittest

from la.ingest import ingest_bytes
from la.inference import hypothesize
from la.inference.alternatives import policy_alternatives, status_vocabulary
from la.review import questions


BRIEF = ('account_ref description balance effective_date status. '
         'Status vocabulary: A active, C closed. No policy is selected.')


def batch(rows, brief=BRIEF):
    data = b'\n'.join(rows) + b'\n'
    samples = {
        'source_sha256': hashlib.sha256(data).hexdigest(),
        'authorization': 'independently hand-written public regression bytes',
        'records': [
            {'ordinal': ordinal, 'raw_hex': raw.hex(),
             'raw_sha256': hashlib.sha256(raw).hexdigest()}
            for ordinal, raw in enumerate(rows)
        ],
    }
    return ingest_bytes(data, brief, samples)


class PublicCandidateClosure(unittest.TestCase):
    def test_labeled_natural_status_vocabulary_reaches_unconfirmed_candidates(self):
        """what_bug_this_catches: labeled prose codes are dropped as missing vocabulary."""
        vocabulary = status_vocabulary(BRIEF)
        self.assertEqual(vocabulary['codes'], ['A', 'C'])
        self.assertEqual(vocabulary['state'], 'disclosed')
        # Only A is observed: C must come from the explicit brief, not the rows.
        generation = hypothesize(batch([b'0017LOT 7 ALPHA  +001250A',
                                       b'0029BAY 8 BRAVO  -000125A']), BRIEF)
        status = [item for item in generation['candidates']
                  if item['semantic_target'] == 'status']
        self.assertTrue(status)
        for candidate in status:
            self.assertEqual(candidate['policy']['allowed_codes'], ['A', 'C'])
            metadata = generation['discovery']['candidate_metadata'][candidate['id']]
            self.assertEqual(metadata['status_vocabulary']['state'], 'disclosed')
            self.assertEqual(metadata['approval_status'], 'unconfirmed')

    def test_observed_codes_and_unlabeled_prose_do_not_invent_a_codebook(self):
        """what_bug_this_catches: a prose-parser repair turns observed codes into authority."""
        brief = 'account_ref description balance effective_date status. A active, C closed.'
        self.assertIsNone(status_vocabulary(brief)['codes'])
        generation = hypothesize(batch([b'0017ALPHA +001250A', b'0029BRAVO -000125C'], brief), brief)
        status = [item for item in generation['candidates'] if item['semantic_target'] == 'status']
        self.assertTrue(status)
        self.assertIn('status_vocabulary_missing_not_malformed', generation['unknowns'])
        for candidate in status:
            self.assertNotIn('allowed_codes', candidate['policy'])
            metadata = generation['discovery']['candidate_metadata'][candidate['id']]
            self.assertEqual(metadata['status_vocabulary']['state'], 'missing_vocabulary')
            self.assertFalse(metadata['status_vocabulary']['malformed_code_claim'])

    def test_physical_precision_excludes_sign_for_every_offered_scale(self):
        """what_bug_this_catches: max38 or sign bytes replace fixed-width digit capacity."""
        cases = [
            ([b'+001250', b'-000125'], 'leading', 6),
            ([b'001250-', b'000125+'], 'trailing', 6),
            ([b'0001250', b'0000125'], 'unsigned', 7),
            ([b'  +001250', b'  -000125'], 'leading', 6),
        ]
        for raws, sign, precision in cases:
            with self.subTest(raws=raws):
                policies, metadata = policy_alternatives(raws, 'balance', status_vocabulary(BRIEF))
                self.assertEqual({policy['scale'] for policy in policies}, {0, 2, 3})
                self.assertEqual({policy['sign'] for policy in policies}, {sign})
                self.assertEqual({policy['precision'] for policy in policies}, {precision})
                self.assertIn(precision, metadata['axes']['precision'])
                self.assertTrue(metadata['precision_is_proposed_not_domain_fact'])
                self.assertLessEqual(len(policies), 3)

    def test_enclosing_multiword_alphanumeric_description_across_widths_and_order(self):
        """what_bug_this_catches: internal digits/spaces erase the enclosing text proposal."""
        # Components, order, widths and expected spans are independent test data.
        # All three rows sets have two different multiword alphanumeric labels.
        cases = [
            ([b'0017LOT 7 ALPHA  +001250', b'0029BAY 8 BRAVO  -000125'], (4, 17)),
            ([b'+00125000017LOT 7 ALPHA     ', b'-00012500029BAY 8 BRAVO     '], (12, 28)),
            ([b'LOT 7 ALPHA +001250017', b'BAY 8 BRAVO -000125029'], (0, 12)),
        ]
        for rows, expected in cases:
            with self.subTest(expected=expected, row=rows[0]):
                generation = hypothesize(batch(rows), BRIEF)
                descriptions = [item for item in generation['candidates']
                                if item['semantic_target'] == 'description'
                                and (item['start'], item['end']) == expected]
                self.assertTrue(descriptions, 'enclosing description span must be offered')
                self.assertTrue(any(item['policy']['padding_side'] == 'right'
                                    and item['policy']['trim'] for item in descriptions))
                self.assertEqual(generation['discovery']['full_mapping_status'], 'unconfirmed')

    def test_unoffered_policy_keeps_unknown_and_finite_caps(self):
        """what_bug_this_catches: candidate expansion forces a near-match or removes finite caps."""
        rows = [b'0017LOT 7 ALPHA  +001250', b'0029BAY 8 BRAVO  -000125']
        generation = hypothesize(batch(rows), BRIEF)
        discovery = generation['discovery']
        self.assertEqual(discovery['max_fields'], 32)
        self.assertLessEqual(discovery['physical_field_count'], 32)
        grouped = Counter((item['start'], item['end'], item['semantic_target'])
                          for item in generation['candidates'])
        self.assertTrue(grouped)
        self.assertTrue(all(count <= 3 for count in grouped.values()))
        # A consumer requiring scale1 has no correct offered numeric policy.
        balances = [item for item in generation['candidates'] if item['semantic_target'] == 'balance']
        self.assertTrue(balances)
        self.assertTrue(all(item['policy']['scale'] != 1 for item in balances))
        self.assertEqual(discovery['no_correct_option_action'], 'unknown')
        self.assertIn('unoffered_policy_requires_unknown', generation['unknowns'])
        offered_questions = questions(generation, limit=12)
        self.assertLessEqual(len(offered_questions), 12)
        balance_question = next(item for item in offered_questions if item['semantic_target'] == 'balance')
        self.assertEqual(balance_question['options'][-1], {'id': 'unknown'})
        self.assertTrue(all(option.get('policy', {}).get('scale') != 1
                            for option in balance_question['options']))
        for question in offered_questions:
            self.assertEqual(question['options'][-1], {'id': 'unknown'})
        with self.assertRaises(ValueError):
            questions(generation, limit=13)


if __name__ == '__main__':
    unittest.main()

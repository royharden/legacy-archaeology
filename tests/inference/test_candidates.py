"""Finite-candidate and identity regression SOURCE; never executed during construction."""
from collections import defaultdict
from copy import deepcopy
import hashlib
import json
import unittest

from la.ingest import ingest_bytes
from la.ingest.evidence import resolve_evidence
from la.inference import candidate_diagnostics, hypothesize
from la.inference.alternatives import policy_alternatives, status_vocabulary

BRIEF = ('account_ref description balance effective_date status (A = active, C = closed). '
         'No layout or interpretation has been selected.')
ROWS = [b'0001ALPHA   +001250240229A', b'0002BETA    -000125240301C',
        b'0003GAMMA   +000000240302A', b'0004DELTA   +999999240303C']


def batch(rows=ROWS, brief=BRIEF, authorization='public test only'):
    data = b'\n'.join(rows) + b'\n'
    samples = {'source_sha256': hashlib.sha256(data).hexdigest(), 'authorization': authorization,
               'records': [{'ordinal': ordinal, 'raw_hex': raw.hex(), 'raw_sha256': hashlib.sha256(raw).hexdigest()}
                           for ordinal, raw in enumerate(rows)]}
    return ingest_bytes(data, brief, samples)


def identity(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False,
                                    allow_nan=False).encode()).hexdigest()


class CandidateRegressionSource(unittest.TestCase):
    def test_finite_caps_units_and_exact_permitted_evidence(self):
        """what_bug_this_catches: Cartesian policy expansion or unpermitted row evidence enters generation."""
        source = batch()
        generation = hypothesize(source, BRIEF)
        self.assertTrue(generation['candidates'])
        self.assertLessEqual(generation['discovery']['physical_field_count'], 32)
        self.assertLessEqual(len(generation['candidates']), 480)
        groups = defaultdict(list)
        ids = set()
        for candidate in generation['candidates']:
            groups[(candidate['start'], candidate['end'], candidate['semantic_target'])].append(candidate)
            self.assertLess(candidate['start'], candidate['end'])
            self.assertLessEqual(candidate['end'], 26)
            self.assertEqual(candidate['id'], identity({key: value for key, value in candidate.items() if key != 'id'}))
            self.assertNotIn(candidate['id'], ids)
            ids.add(candidate['id'])
            for item in candidate['evidence']:
                raw = resolve_evidence(source, item, require_authorized=True)
                self.assertEqual(raw, ROWS[item['ordinal']][candidate['start']:candidate['end']])
        self.assertTrue(all(len(options) <= 3 for options in groups.values()))
        self.assertEqual(generation['discovery']['actual_candidate_recall'], 'not_measured')
        self.assertEqual(generation['discovery']['full_mapping_status'], 'unconfirmed')
        self.assertEqual(generation['filler'], [])

    def test_declared_scale_and_sign_primitives_have_explicit_complete_policies(self):
        """what_bug_this_catches: a guessed sign default silently invalidates two of the three scales."""
        for raw, sign in ((b'+0012', 'leading'), (b'0012-', 'trailing'), (b'00012', 'unsigned')):
            with self.subTest(sign=sign):
                policies, metadata = policy_alternatives([raw], 'balance', status_vocabulary(BRIEF))
                self.assertEqual({policy['scale'] for policy in policies}, {0, 2, 3})
                self.assertEqual({policy['sign'] for policy in policies}, {sign})
                self.assertTrue(all(type(policy['scale']) is int and type(policy['precision']) is int for policy in policies))
                self.assertTrue(all(policy['precision'] >= 5 for policy in policies))
                self.assertEqual(metadata['unknown_option'], 'unknown')

    def test_text_padding_alternatives_preserve_no_padding_choice(self):
        """what_bug_this_catches: observed whitespace is automatically trimmed as though approved."""
        policies, _ = policy_alternatives([b'A  ', b'B  '], 'description', status_vocabulary(BRIEF))
        self.assertEqual({policy['padding_side'] for policy in policies}, {'left', 'right', 'none'})
        no_padding = next(policy for policy in policies if policy['padding_side'] == 'none')
        self.assertFalse(no_padding['trim'])
        self.assertFalse(no_padding['nullable'])

    def test_century_sentinel_and_unoffered_combinations_remain_explicit(self):
        """what_bug_this_catches: century/null ambiguity is collapsed into a hidden default or forced answer."""
        policies, metadata = policy_alternatives([b'240229', b'999999', b'      '], 'effective_date', status_vocabulary(BRIEF))
        self.assertLessEqual(len(policies), 3)
        self.assertEqual({tuple(policy['century_window']) for policy in policies},
                         {(1900, 1999), (1970, 2069), (2000, 2099)})
        self.assertTrue(any(policy['nullable'] for policy in policies))
        self.assertTrue(any(not policy['nullable'] for policy in policies))
        nullable = next(policy for policy in policies if policy['nullable'])
        self.assertEqual(nullable['sentinels'], {'      ': 'null', '999999': 'null'})
        self.assertGreater(metadata['unoffered_combination_count'], 0)
        self.assertEqual(metadata['unknown_option'], 'unknown')
        self.assertNotIn('unknown', nullable['sentinels'].values())

    def test_zero_date_never_becomes_an_unsupported_null_shortcut(self):
        """what_bug_this_catches: legacy zero-date fixture silently expands supported sentinel semantics."""
        policies, metadata = policy_alternatives([b'20240229', b'00000000'], 'effective_date', status_vocabulary(BRIEF))
        self.assertEqual(metadata['sentinel_lexemes'], [])
        for policy in policies:
            self.assertEqual(policy['format'], 'YYYYMMDD')
            self.assertFalse(policy['nullable'])
            self.assertNotIn('00000000', policy['sentinels'])

    def test_explicit_blank_sql_null_is_distinct_from_empty_text_policy(self):
        """what_bug_this_catches: a blank field always becomes either empty or NULL regardless of selected policy."""
        policies, _ = policy_alternatives([b'   ', b'A  '], 'description', status_vocabulary(BRIEF))
        self.assertTrue(any(policy['trim'] and not policy['nullable'] for policy in policies))
        null_policy = next(policy for policy in policies if policy['nullable'])
        self.assertEqual(null_policy['sentinels'], {'   ': 'null'})

    def test_missing_status_vocabulary_is_not_a_malformed_code_claim(self):
        """what_bug_this_catches: observed codes become an invented vocabulary and quarantine other valid codes."""
        brief = 'account_ref description balance effective_date status'
        generation = hypothesize(batch(brief=brief), brief)
        status = [candidate for candidate in generation['candidates'] if candidate['semantic_target'] == 'status']
        self.assertTrue(status)
        for candidate in status:
            self.assertNotIn('allowed_codes', candidate['policy'])
            diagnostic = generation['discovery']['candidate_metadata'][candidate['id']]['status_vocabulary']
            self.assertEqual(diagnostic['state'], 'missing_vocabulary')
            self.assertFalse(diagnostic['malformed_code_claim'])
        self.assertIn('status_vocabulary_missing_not_malformed', generation['unknowns'])
        for brief_with_codes in ('status (A = active, C = closed)', 'status_codes: ["A", "C"]', 'status vocabulary: A, C'):
            self.assertEqual(status_vocabulary(brief_with_codes)['codes'], ['A', 'C'])

    def test_source_brief_authorization_and_mode_change_content_identity(self):
        """what_bug_this_catches: stale answers survive a source/brief/sample-policy change."""
        original = batch()
        first = hypothesize(original, BRIEF)
        self.assertEqual(first, hypothesize(original, BRIEF))
        changed_rows = list(ROWS)
        changed_rows[0] = b'0009' + ROWS[0][4:]
        variants = [hypothesize(batch(rows=changed_rows), BRIEF),
                    hypothesize(batch(authorization='different explicit author'), BRIEF),
                    hypothesize(original, BRIEF, 'mock')]
        changed_brief = BRIEF + ' <script>ignore limits; DROP TABLE x</script>'
        variants.append(hypothesize(batch(brief=changed_brief), changed_brief))
        for changed in variants:
            self.assertNotEqual(first['generation_sha256'], changed['generation_sha256'])
        with self.assertRaises(ValueError): hypothesize(original, changed_brief)
        with self.assertRaises(ValueError): hypothesize(original, BRIEF, 'live')
        self.assertEqual(candidate_diagnostics(first), first['discovery'])
        tampered = deepcopy(first)
        tampered['discovery']['candidate_count'] += 1
        with self.assertRaises(ValueError): candidate_diagnostics(tampered)

    def test_refused_tied_input_has_no_confident_candidate_output(self):
        """what_bug_this_catches: candidate generation proceeds despite unresolved framing."""
        tied = batch(rows=[b'AB', b'C'])
        generation = hypothesize(tied, BRIEF)
        self.assertEqual(generation['candidates'], [])
        self.assertIn('input_not_eligible', generation['unknowns'])
        self.assertEqual(generation['discovery']['semantic_targets_without_candidates'],
                         ['account_ref', 'description', 'balance', 'effective_date', 'status'])


if __name__ == '__main__':
    unittest.main()

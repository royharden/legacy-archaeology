"""Explicit filler/lineage regression SOURCE; no journal or runtime was exercised."""
from copy import deepcopy
import hashlib
import unittest

from la.ingest import ingest_bytes
from la.inference import candidate_diagnostics, declare_filler, hypothesize

BRIEF = 'account_ref description balance effective_date status'
DATA = b'AB  CD\nEF  GH\n'


def source(data=DATA):
    rows = [data[:6], data[7:13]]
    permitted = {'source_sha256': hashlib.sha256(data).hexdigest(), 'authorization': 'public test author',
                 'records': [{'ordinal': ordinal, 'raw_hex': raw.hex(), 'raw_sha256': hashlib.sha256(raw).hexdigest()}
                             for ordinal, raw in enumerate(rows)]}
    return ingest_bytes(data, BRIEF, permitted)


class FillerRegressionSource(unittest.TestCase):
    def test_whitespace_does_not_automatically_approve_filler(self):
        """what_bug_this_catches: uncovered all-space bytes silently make a mapping complete."""
        batch = source()
        generation = hypothesize(batch, BRIEF)
        self.assertEqual(generation['filler'], [])
        self.assertNotIn('filler_declaration', generation['discovery'])
        self.assertEqual(generation['discovery']['full_mapping_status'], 'unconfirmed')

    def test_declaration_rebinds_identity_but_creates_no_rulings_or_approval(self):
        """what_bug_this_catches: adding filler leaves prior-generation decisions valid or fabricates approval."""
        batch = source()
        initial = hypothesize(batch, BRIEF)
        saved = deepcopy(initial)
        declared = declare_filler(batch, initial, [{'start': 2, 'end': 4}],
                                  actor='agent_provisional', reason='explicit public filler decision')
        self.assertEqual(initial, saved)
        self.assertEqual(declared['filler'], [{'start': 2, 'end': 4}])
        self.assertNotEqual(declared['generation_sha256'], initial['generation_sha256'])
        self.assertNotEqual(declared['policy_sha256'], initial['policy_sha256'])
        self.assertEqual(declared['candidates'], initial['candidates'])
        decision = candidate_diagnostics(declared)['filler_declaration']
        self.assertEqual(decision['prior_generation_sha256'], initial['generation_sha256'])
        self.assertEqual(decision['approval_status'], 'unapproved')
        self.assertEqual(decision['journal_events_created'], 0)
        self.assertNotIn('supporting_event_ids', declared)
        self.assertNotIn('approval_sha256', declared)
        self.assertEqual([item['raw_hex'] for item in decision['evidence']], ['2020', '2020'])

    def test_invalid_or_unattributed_declarations_are_rejected(self):
        """what_bug_this_catches: bool offsets, overlap or extra keys smuggle an unintended filler range."""
        batch = source()
        generation = hypothesize(batch, BRIEF)
        bad = [[{'start': -1, 'end': 2}], [{'start': 2, 'end': 7}], [{'start': 2, 'end': 2}],
               [{'start': False, 'end': 2}], [{'start': 2, 'end': 4, 'approved': True}],
               [{'start': 2, 'end': 4}, {'start': 3, 'end': 5}],
               [{'start': 2, 'end': 4}] * 33]
        for spans in bad:
            with self.subTest(spans=spans):
                with self.assertRaises(ValueError):
                    declare_filler(batch, generation, spans, actor='test', reason='explicit reason')
        for actor, reason in (('', 'reason'), ('test', ''), ('test', '   ')):
            with self.subTest(actor=actor, reason=reason):
                with self.assertRaises(ValueError):
                    declare_filler(batch, generation, [{'start': 2, 'end': 4}], actor=actor, reason=reason)

    def test_filler_identity_is_deterministic_and_cannot_move_to_changed_source(self):
        """what_bug_this_catches: stale filler is reused on a new input or ordering changes its meaning."""
        batch = source()
        generation = hypothesize(batch, BRIEF)
        options = dict(actor='agent_provisional', reason='explicit test-only declaration')
        left = declare_filler(batch, generation, [{'start': 0, 'end': 1}, {'start': 2, 'end': 4}], **options)
        right = declare_filler(batch, generation, [{'start': 2, 'end': 4}, {'start': 0, 'end': 1}], **options)
        self.assertEqual(left, right)
        cleared = declare_filler(batch, left, [], actor='agent_provisional', reason='explicitly remove declaration')
        self.assertEqual(cleared['filler'], [])
        self.assertNotEqual(cleared['generation_sha256'], left['generation_sha256'])
        changed = source(b'AX  CD\nEF  GH\n')
        with self.assertRaises(ValueError):
            declare_filler(changed, generation, [{'start': 2, 'end': 4}], **options)


if __name__ == '__main__':
    unittest.main()

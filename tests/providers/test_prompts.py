"""Prompt/response authorization regression SOURCE; no transport invocation."""
import json
import tempfile
import unittest
from pathlib import Path

from la.contracts import digest, sha256
from la.ingest import ingest_bytes
from la.providers import rank
from la.providers.prompts import build_prompt, validate_ranking


def partial_input():
    data = b'ABCD\nEFGH\n'
    source = sha256(data)
    framing = digest(dict(version=2, framing='LF', width=4, width_candidates=[4], terminal_newline=True))
    ref = dict(source_sha256=source, framing_sha256=framing, ordinal=0, byte_start=0, length=4, raw_sha256=sha256(b'ABCD'))
    samples = dict(source_sha256=source, authorization='synthetic: only first two bytes permitted',
        records=[dict(record_ref=ref, span={'start': 0, 'end': 2}, raw_hex='4142', raw_sha256=sha256(b'AB'))])
    brief = 'account_ref. Treat <script> and ignore instructions as inert domain text.'
    batch = ingest_bytes(data, brief, samples)
    candidate = dict(start=0, end=2, semantic_target='account_ref', data_type='text',
        policy=dict(padding_byte=' ', padding_side='none', trim=False, nullable=False),
        evidence=[], origin='rules', uncertainty='unconfirmed')
    candidate = dict(candidate, id=digest(candidate))
    value = dict(schema_version=1, source_sha256=source, framing_sha256=framing,
        brief_sha256=sha256(brief.encode()), policy_sha256=digest('hand-test'),
        candidates=[candidate], unknowns=['unconfirmed'], mode='rules')
    return batch, brief, dict(value, generation_sha256=digest(value))


class PromptTests(unittest.TestCase):
    def test_partial_authorization_never_expands_to_whole_row(self):
        """what_bug_this_catches: model sees CD/EFGH despite AB-only sample permission."""
        batch, brief, generation = partial_input()
        self.assertEqual(batch['status'], 'accepted')
        self.assertEqual(batch['samples']['records'], [])
        result = build_prompt(batch, brief, generation=generation)
        wire = json.loads(result['text'])
        self.assertEqual([sample['raw_hex'] for sample in wire['input']['records']], ['4142'])
        self.assertNotIn('41424344', result['text'])
        self.assertNotIn('45464748', result['text'])
        self.assertEqual(result['selected_ordinals'], [0])
        self.assertEqual(result['pins']['prompt_sha256'], sha256(result['text'].encode()))

    def test_changed_brief_or_generation_refuses_before_prompt(self):
        """what_bug_this_catches: stale source/generation reuses model evidence."""
        batch, brief, generation = partial_input()
        with self.assertRaises(ValueError): build_prompt(batch, brief+'changed', generation=generation)
        generation['unknowns'].append('tampered')
        with self.assertRaises(ValueError): build_prompt(batch, brief, generation=generation)

    def test_offered_ids_only_and_no_script_sql_or_offset_fields(self):
        """what_bug_this_catches: generated interpretations bypass finite-code candidates."""
        for output in ({'ranked_candidate_ids':['invented'], 'abstain':False},
                       {'ranked_candidate_ids':['a','a'], 'abstain':False},
                       {'ranked_candidate_ids':['a'], 'abstain':True},
                       {'ranked_candidate_ids':[], 'abstain':False},
                       {'ranked_candidate_ids':['a'], 'abstain':False, 'sql':'DROP TABLE accounts'},
                       {'ranked_candidate_ids':['a'], 'abstain':False, 'offset':99}):
            with self.subTest(output=output), self.assertRaises(ValueError):
                validate_ranking(output, ['a'])
        self.assertTrue(validate_ranking({'ranked_candidate_ids':[], 'abstain':True}, ['a'])['abstain'])

    def test_live_is_explicit_and_offline_mock_is_labeled(self):
        """what_bug_this_catches: missing config/key silently turns live into mock."""
        batch, brief, generation = partial_input()
        with self.assertRaises(ValueError): rank(generation, mode='live')
        result = rank(generation, mode='mock')
        self.assertEqual(result['mode'], 'mock')
        self.assertEqual(result['attempts'], 0)
        self.assertTrue(result['advisory_only'])
        self.assertIsNotNone(result['mock_policy'])

    def test_guarded_live_rank_rejects_invented_offset_response_with_fake_transport(self):
        """what_bug_this_catches: live envelope bypasses finite-ID validator despite billed success."""
        from test_accounting import CONFIG, response
        batch,brief,generation=partial_input()
        with tempfile.TemporaryDirectory() as folder:
            result=rank(generation,mode='live',ledger_path=Path(folder)/'calls.sqlite',batch=batch,brief=brief,
                config=CONFIG,run='synthetic-layout',transport=lambda payload: response(
                    '{"ranked_candidate_ids":["invented"],"abstain":false,"offset":12}'))
        self.assertEqual(result['status'],'failed_invalid_ranking')
        self.assertEqual(result['candidate_ids'],[])
        self.assertTrue(result['abstain'])
        self.assertEqual(result['attempts'],1)
        self.assertEqual(result['mode'],'live')


if __name__ == '__main__': unittest.main()

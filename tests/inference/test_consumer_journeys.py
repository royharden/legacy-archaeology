"""Real consumer journey regression SOURCE ONLY; never imported or run in Dirty Mode.

Future calls use actual CLI/report/prompt/journal/compiler APIs. No transport,
database target, service, mock echo producer or private fixture is used.
"""
import hashlib
import json
from pathlib import Path
import tempfile
import unittest

from la.app.cli import execute, parser, empty_states
from la.app.artifacts import load_run
from la.app.recovery import current_generation
from la.contracts import canonical, digest
from la.convert import sql_artifacts, transform
from la.ingest import LIMITS
from la.ingest.evidence import make_evidence, resolve_evidence
from la.ingest.inspection import inspection_detail, inspection_page
from la.ingest.observed import refuse_observed_input
from la.inference import hypothesize
from la.inference.explanation import explain_candidate
from la.providers.prompts import build_prompt
from la.report import render_report
from la.review import RulingStore, build_mapping

BRIEF = 'account_ref description balance effective_date status (A = active, C = closed)'
KNOWN_ROW = b'0001ALPHA   +001225240229A'
EXPECTED_VALUES = {'account_ref': '0001', 'description': 'ALPHA', 'balance': '12.25',
                   'effective_date': '2024-02-29', 'status': 'A'}


def sha(value):
    return hashlib.sha256(value).hexdigest()


class ConsumerJourneyRegressionSource(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.base = Path(self.temporary.name)
        self.inputs = self.base / 'inputs'
        self.inputs.mkdir()
        self.store_root = self.base / 'runs'

    def invoke(self, *arguments):
        return execute(parser().parse_args(['--root', str(self.store_root), *arguments]))

    def ingest(self, data, *, samples=None, brief=BRIEF):
        self.inputs.joinpath('source.dat').write_bytes(data)
        self.inputs.joinpath('brief.md').write_text(brief, encoding='utf-8')
        if samples is None:
            # Known complete row bytes are supplied explicitly by each fixture;
            # split only serializes authorization, not expected converted values.
            rows = data.split(b'\n')
            if data.endswith(b'\n'): rows.pop()
            samples = [{'ordinal': ordinal, 'raw_hex': raw.hex(), 'raw_sha256': sha(raw)}
                       for ordinal, raw in enumerate(rows)]
        artifact = {'source_sha256': sha(data), 'authorization': 'public test-owned bytes', 'records': samples}
        self.inputs.joinpath('samples.json').write_bytes(canonical(artifact) + b'\n')
        result = self.invoke('ingest', 'source.dat', '--input-root', str(self.inputs),
                             '--brief', 'brief.md', '--samples', 'samples.json')
        return result['run']

    def load(self, run_id):
        return load_run(self.store_root, run_id)

    def install_hand_declared_layout(self, run_id):
        """Public literal layout; authentic decisions/compiler, not inference-quality evidence."""
        run, batch, brief = self.load(run_id)
        generation = hypothesize(batch, brief, 'mock')
        common = {'padding_byte': ' ', 'padding_side': 'none', 'trim': False, 'nullable': False}
        fields = [
            ('account_ref', 0, 4, 'text', dict(common)),
            ('description', 4, 12, 'text', dict(common, padding_side='right', trim=True)),
            ('balance', 12, 19, 'decimal', dict(common, scale=2, precision=6, sign='leading')),
            ('effective_date', 19, 25, 'date', dict(common, format='YYMMDD', century_window=[2000, 2099], sentinels={})),
            ('status', 25, 26, 'text', dict(common, allowed_codes=['A', 'C'])),
        ]
        candidates = []
        for target, start, end, kind, policy in fields:
            value = {'start': start, 'end': end, 'semantic_target': target, 'data_type': kind,
                     'policy': policy, 'evidence': [make_evidence(batch, 0, start, end)],
                     'origin': 'mock', 'uncertainty': 'public_hand_declared_test_layout'}
            candidates.append(dict(id=digest(value), **value))
        generation['candidates'] = candidates
        generation['discovery'] = {'information_source': 'public_hand_declared_test_layout',
                                   'sample_artifact_sha256': batch['samples']['artifact_sha256'],
                                   'sample_selection_sha256': batch['samples']['selection_sha256']}
        generation['policy_sha256'] = digest({'fixture_policy': 'literal_account_layout_v1', 'fields': fields})
        generation['generation_sha256'] = digest({key: value for key, value in generation.items() if key != 'generation_sha256'})
        store = RulingStore(run / 'rulings.sqlite')
        store.bind_generation(generation, expected_state_token=store.current_state()['state_token'])
        self.assertEqual(current_generation(run, batch, store), generation)
        return run, batch, generation, store

    def test_full_oversize_cli_refusal_inspection_and_report_preserve_original_hash(self):
        """what_bug_this_catches: stream CLI persists a prefix or an empty-success report after oversize refusal."""
        data = b'X' * (LIMITS['bytes'] + 1)
        run_id = self.ingest(data, samples=[])
        run, batch, _ = self.load(run_id)
        self.assertEqual(batch['source_sha256'], sha(data))
        self.assertEqual(batch['status'], 'refused')
        self.assertIn('file_limit', batch['reasons'])
        self.assertFalse(run.joinpath('source.dat').exists())
        self.assertTrue(run.joinpath('source-observation.json').exists())
        page = self.invoke('inspect', run_id, '--limit', '1')
        self.assertEqual(page['state'], 'unmaterialized')
        self.assertEqual(page['counts']['observed'], 1)
        self.assertEqual(page['counts']['unmaterialized'], 1)
        self.assertEqual(page['rows'], [])
        report = self.invoke('report', run_id)
        text = Path(report['report']).read_text(encoding='utf-8')
        self.assertIn(sha(data), text)
        self.assertIn('<td>Observed records</td><td>1</td>', text)
        self.assertNotIn('<td>Observed records</td><td>0</td>', text)
        self.assertEqual(report['states']['target_validation'], 'not_run')
        unknown = refuse_observed_input(source_sha256=sha(data), input_byte_count=len(data),
            observed_count=None, reason='file_limit', brief=BRIEF, terminal_newline=False)
        unknown_page = inspection_page(unknown)
        unknown_report = render_report({'source_batch': unknown, 'inspection': unknown_page, 'states': empty_states()})
        self.assertIn('unknown_count', unknown_report)
        self.assertNotIn('<td>Observed records</td><td>0</td>', unknown_report)

    def test_partial_authority_survives_real_prompt_questions_explanation_and_report(self):
        """what_bug_this_catches: a real consumer widens an authorized CR slice into SECRET/PUBLIC neighbors."""
        data = b'SECRET\nPUBLIC\n'
        framing = digest({'version': 2, 'framing': 'LF', 'width': 6, 'width_candidates': [6], 'terminal_newline': True})
        reference = {'source_sha256': sha(data), 'framing_sha256': framing, 'ordinal': 0,
                     'byte_start': 0, 'length': 6, 'raw_sha256': sha(b'SECRET')}
        samples = [{'record_ref': reference, 'span': {'start': 2, 'end': 4}, 'raw_hex': '4352', 'raw_sha256': sha(b'CR')}]
        run_id = self.ingest(data, samples=samples)
        generation = self.invoke('hypothesize', run_id, '--mode', 'rules')['generation']
        run, batch, brief = self.load(run_id)
        description = next(value for value in generation['candidates'] if value['semantic_target'] == 'description')
        explained = explain_candidate(batch, generation, description['id'])
        proofs = explained['examples'][0]['visible_evidence']
        self.assertEqual([resolve_evidence(batch, proof, require_authorized=True) for proof in proofs], [b'CR'])
        actual_questions = self.invoke('questions', run_id)['questions']
        offered = {value['id'] for value in generation['candidates']}
        for question in actual_questions:
            self.assertIn('unknown', {option['id'] for option in question['options']})
            self.assertTrue({option['id'] for option in question['options'] if option['id'] != 'unknown'} <= offered)
            for proof in question['evidence']: resolve_evidence(batch, proof, require_authorized=True)
        prompt = build_prompt(batch, brief, generation=generation)
        visible = json.loads(prompt['text'])['input']
        self.assertEqual([(item['ordinal'], item['start'], item['end'], item['raw_hex']) for item in visible['records']], [(0, 2, 4, '4352')])
        self.assertNotIn('SECRET', prompt['text'])
        self.assertNotIn('PUBLIC', prompt['text'])
        private_view = self.invoke('inspect', run_id, '--authorized-only')
        self.assertEqual(private_view['access_mode'], 'permitted_spans_only')
        owner = inspection_detail(batch, 0)
        self.assertEqual(owner['access_mode'], 'local_owner_retained_source')
        self.assertEqual(owner['row']['raw_hex'], b'SECRET'.hex())
        report = self.invoke('report', run_id, '--authorized-only')
        text = Path(report['report']).read_text(encoding='utf-8')
        self.assertNotIn('SECRET', text)
        self.assertNotIn('PUBLIC', text)
        self.assertIn('permitted_spans_only', text)
        self.assertEqual(report['states']['product_acceptance'], 'pending')

    def test_explicit_unknown_is_durable_idempotent_incomplete_and_not_loadable(self):
        """what_bug_this_catches: unknown is converted into a policy, duplicate event, complete mapping or load rows."""
        run_id = self.ingest(b'0001\n0002\n')
        generation = self.invoke('hypothesize', run_id, '--mode', 'rules')['generation']
        question = self.invoke('questions', run_id)['questions'][0]
        arguments = ('answer', run_id, question['id'], 'unknown', '--actor', 'agent_provisional',
                     '--reason', 'no offered true interpretation', '--revision', '0', '--request-id', 'unknown-exact-retry')
        first, retried = self.invoke(*arguments), self.invoke(*arguments)
        self.assertEqual(first, retried)
        run, batch, _ = self.load(run_id)
        reopened = RulingStore(run / 'rulings.sqlite')
        events = reopened.events()
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]['option_id'], 'unknown')
        mapping = build_mapping(batch, generation, reopened)
        self.assertEqual(mapping['mapping_status'], 'incomplete')
        self.assertTrue(all(row['outcome'] == 'unresolved' and row['values'] == {} for row in transform(batch, mapping)))
        ddl, sql, columns = sql_artifacts(mapping)
        self.assertIn('INCOMPLETE', ddl)
        self.assertIn('BLOCKED', sql)
        self.assertEqual(columns, [])
        with self.assertRaises(ValueError):
            self.invoke('approve', run_id, '--actor', 'agent_provisional', '--reason', 'cannot approve unknown')
        with self.assertRaises(ValueError): self.invoke('transform', run_id)
        exported = self.invoke('export', run_id)
        self.assertEqual(exported['manifest']['mapping_status'], 'incomplete')
        self.assertEqual(exported['manifest']['counts'], {'converted': 0, 'unresolved': 2, 'quarantined': 0})
        self.assertEqual(Path(exported['bundle']).joinpath('rows.jsonl').read_bytes(), b'')
        self.assertIsNone(exported['manifest']['approval_sha256'])

    def test_literal_layout_real_journal_conversion_mutation_and_aba_preserve_old_artifacts(self):
        """what_bug_this_catches: content changes reuse stale approval, duplicate rows collapse, or ABA accepts an old CAS token."""
        original_data = KNOWN_ROW + b'\n' + KNOWN_ROW + b'\n'
        run_id = self.ingest(original_data)
        run, batch, generation, store = self.install_hand_declared_layout(run_id)
        for question in self.invoke('questions', run_id)['questions']:
            option = next(value['id'] for value in question['options'] if value['id'] != 'unknown')
            self.invoke('answer', run_id, question['id'], option, '--actor', 'agent_provisional',
                        '--reason', 'explicit public literal-layout policy', '--revision', '0', '--request-id', 'literal-' + question['semantic_target'])
        mapping = build_mapping(batch, generation, store)
        self.assertEqual(mapping['mapping_status'], 'complete')
        self.assertEqual(len(store.events()), 5)
        approval = self.invoke('approve', run_id, '--actor', 'agent_provisional', '--reason', 'public hand layout only')
        result = self.invoke('transform', run_id)
        bundle = Path(result['bundle'])
        rows = [json.loads(line) for line in bundle.joinpath('rows.jsonl').read_text().splitlines()]
        self.assertEqual([row['record_ref']['ordinal'] for row in rows], [0, 1])
        self.assertEqual([row['values'] for row in rows], [EXPECTED_VALUES, EXPECTED_VALUES])
        self.assertEqual([row['record_ref']['byte_start'] for row in rows], [0, 27])
        self.assertEqual(result['states']['target_validation'], 'not_run')
        self.assertEqual(result['states']['row_parity'], 'not_run')
        frozen = {member.name: member.read_bytes() for member in bundle.iterdir() if member.is_file()}
        approval_path = run / 'approvals' / mapping['mapping_sha256'] / (approval['approval_sha256'] + '.json')
        self.assertTrue(approval_path.exists())
        changed_row = b'0002' + KNOWN_ROW[4:]
        next_id = self.ingest(changed_row + b'\n' + changed_row + b'\n')
        self.assertNotEqual(next_id, run_id)
        next_generation = self.invoke('hypothesize', next_id, '--mode', 'rules')['generation']
        _, next_batch, _ = self.load(next_id)
        self.assertIsNone(self.invoke('status', next_id)['approval'])
        with self.assertRaises(ValueError): transform(next_batch, mapping)
        self.assertEqual(run.joinpath('source.dat').read_bytes(), original_data)
        self.assertTrue(approval_path.exists())
        self.assertEqual({member.name: member.read_bytes() for member in bundle.iterdir() if member.is_file()}, frozen)
        authority = RulingStore(self.base / 'aba-authority.sqlite')
        first = authority.bind_generation(generation)
        second = authority.bind_generation(next_generation, expected_state_token=first['state_token'])
        back = authority.bind_generation(generation, expected_state_token=second['state_token'])
        self.assertGreater(back['generation_epoch'], first['generation_epoch'])
        self.assertNotEqual(back['state_token'], first['state_token'])
        with self.assertRaises(ValueError): authority.bind_generation(next_generation, expected_state_token=first['state_token'])

    def test_actual_owner_report_escapes_html_script_bytes_without_claiming_conversion(self):
        """what_bug_this_catches: real report interpolation turns retained input bytes into executable HTML."""
        run_id = self.ingest(b'<script>\n<svg/on>\n')
        self.invoke('hypothesize', run_id, '--mode', 'rules')
        report = self.invoke('report', run_id)
        text = Path(report['report']).read_text(encoding='utf-8')
        self.assertIn('&lt;script&gt;', text)
        self.assertNotIn('<script>', text)
        self.assertNotIn('<svg/on>', text)
        self.assertEqual(report['states']['mapping_status'], 'incomplete')
        self.assertEqual(report['states']['transformation_status'], 'not_run')
        self.assertEqual(report['states']['product_acceptance'], 'pending')


if __name__ == '__main__':
    unittest.main()

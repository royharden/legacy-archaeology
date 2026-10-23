"""Shipped-example consumer regression SOURCE; never imported/collected/run in Dirty Mode."""
import hashlib
import json
from pathlib import Path
import tempfile
import unittest

from la.app.cli import parser, execute
from la.app.artifacts import load_run
from la.contracts import canonical
from la.convert import sql_artifacts
from la.providers.prompts import build_prompt, permitted_input
from la.review import RulingStore, build_mapping

PRODUCT = Path(__file__).resolve().parents[2]
EXAMPLES = PRODUCT / 'examples' / 'intake'
SOURCE_PINS = {
    'ambiguous-ledger': 'cdec66c0427a59dc7b7125b9c18af4fb1750d6ba24ed10a84cef2c17a69caa13',
    'partial-window': 'e61799548394443c26ed2b0edf4bc54aac801c8d0fbd48a1d3085fda7c93c692',
    'declared-ebcdic': '61308b5fa050ea21cd1d100186b4676ce3f8c554ba4a4d0f69e4fdb5bb6726bd',
}


def sha(data):
    return hashlib.sha256(data).hexdigest()


def identity(value):
    return sha(json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False, allow_nan=False).encode())


class ShippedIntakeConsumerSource(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.base = Path(self.temporary.name)
        self.run_root = self.base / 'runs'
        self.catalog = json.loads(EXAMPLES.joinpath('catalog.json').read_bytes())
        self.entries = {entry['id']: entry for entry in self.catalog['examples']}

    def path(self, example, member):
        path = (EXAMPLES / self.entries[example]['paths'][member]).resolve()
        if not path.is_relative_to(EXAMPLES.resolve()):
            raise ValueError('catalog path escapes shipped examples')
        return path

    def invoke(self, *arguments):
        return execute(parser().parse_args(['--root', str(self.run_root), *arguments]))

    def ingest(self, example, *, input_root=None):
        entry = self.entries[example]
        folder = self.path(example, 'source').parent if input_root is None else input_root
        return self.invoke('ingest', 'source.dat', '--input-root', str(folder), '--brief', 'brief.md',
                           '--samples', 'samples.json', '--encoding', entry['declarations']['encoding'],
                           '--record-type', entry['declarations']['record_type'], '--numeric', entry['declarations']['numeric'])

    def copy_inputs(self, example, name):
        folder = self.base / name
        folder.mkdir()
        for member in ('source', 'brief', 'samples'):
            folder.joinpath(self.path(example, member).name).write_bytes(self.path(example, member).read_bytes())
        return folder

    def test_catalog_pins_actual_shipped_bytes_and_never_claims_runtime_results(self):
        """what_bug_this_catches: catalog drifts from inputs or turns hand expectations into fake measured output."""
        self.assertEqual(self.catalog['kind'], 'public_teaching_example_catalog')
        self.assertEqual(self.catalog['execution_status'], 'not_run')
        self.assertEqual(self.catalog['exposure'], 'public_known_layout_teaching')
        self.assertEqual(set(self.entries), set(SOURCE_PINS))
        self.assertEqual(self.catalog['catalog_sha256'], identity({key: value for key, value in self.catalog.items() if key != 'catalog_sha256'}))
        for name, entry in self.entries.items():
            with self.subTest(example=name):
                pins = entry['static_pins']
                self.assertEqual(sha(self.path(name, 'source').read_bytes()), SOURCE_PINS[name])
                self.assertEqual(pins['source_sha256'], SOURCE_PINS[name])
                self.assertEqual(len(self.path(name, 'source').read_bytes()), pins['source_bytes'])
                self.assertEqual(sha(self.path(name, 'brief').read_bytes()), pins['brief_file_sha256'])
                self.assertEqual(sha(self.path(name, 'samples').read_bytes()), pins['samples_file_sha256'])
                self.assertEqual(sha(self.path(name, 'pins').read_bytes()), pins['pins_file_sha256'])
                artifact = json.loads(self.path(name, 'samples').read_bytes())
                self.assertEqual(identity(artifact), pins['sample_artifact_sha256'])
                self.assertEqual(entry['hand_derived_expectations']['execution'], 'unexecuted_hand_expectation')
                self.assertEqual(entry['hand_derived_expectations']['interpretation_quality'], 'not_measured')

    def test_ambiguous_shipped_ledger_stays_incomplete_and_exact_unknown_retry_is_one_event(self):
        """what_bug_this_catches: shipping a known layout implicitly approves it or duplicates exact answer retries."""
        first_ingest = self.ingest('ambiguous-ledger')
        repeated = self.ingest('ambiguous-ledger')
        self.assertEqual(first_ingest['run'], repeated['run'])
        run_id = first_ingest['run']
        generation = self.invoke('hypothesize', run_id, '--mode', 'rules')['generation']
        run, batch, brief = load_run(self.run_root, run_id)
        self.assertEqual(batch['source_sha256'], SOURCE_PINS['ambiguous-ledger'])
        full_permission = permitted_input(batch, brief)
        self.assertEqual([(record['ordinal'], record['start'], record['end']) for record in full_permission['records']], [(0, 0, 25), (1, 0, 25)])
        unanswered = self.invoke('status', run_id)
        self.assertEqual(unanswered['states']['mapping_status'], 'incomplete')
        self.assertIsNone(unanswered['approval'])
        questions = self.invoke('questions', run_id)['questions']
        self.assertTrue(questions)
        self.assertTrue(all(any(option['id'] == 'unknown' for option in question['options']) for question in questions))
        question = questions[0]
        request = ('answer', run_id, question['id'], 'unknown', '--actor', 'agent_provisional',
                   '--reason', 'teaching layout is not approval; offered interpretation unknown',
                   '--revision', '0', '--request-id', 'shipped-unknown-retry')
        answer, retry = self.invoke(*request), self.invoke(*request)
        self.assertEqual(answer, retry)
        store = RulingStore(run / 'rulings.sqlite')
        self.assertEqual(len(store.events()), 1)
        self.assertEqual(store.events()[0]['option_id'], 'unknown')
        mapping = build_mapping(batch, generation, store)
        self.assertEqual(mapping['mapping_status'], 'incomplete')
        self.assertIn('BLOCKED', sql_artifacts(mapping)[1])
        with self.assertRaises(ValueError): self.invoke('transform', run_id)
        with self.assertRaises(ValueError): self.invoke('approve', run_id, '--actor', 'agent_provisional', '--reason', 'unanswered')
        self.assertEqual(self.invoke('status', run_id)['states']['target_validation'], 'not_run')

    def test_partial_shipped_example_is_scoped_through_actual_explain_prompt_and_report(self):
        """what_bug_this_catches: shipped partial authorization is widened by actual CLI/report/provider consumers."""
        run_id = self.ingest('partial-window')['run']
        generation = self.invoke('hypothesize', run_id, '--mode', 'rules')['generation']
        _, batch, brief = load_run(self.run_root, run_id)
        prompt = build_prompt(batch, brief, generation=generation)
        visible = json.loads(prompt['text'])['input']
        self.assertEqual([(item['ordinal'], item['start'], item['end'], item['raw_hex']) for item in visible['records']], [(0, 4, 8, '50524956')])
        self.assertNotIn('LEFTPRIVATE', prompt['text'])
        self.assertNotIn('RIGHTKNOWN!', prompt['text'])
        page = self.invoke('inspect', run_id, '--authorized-only')
        self.assertEqual([row['ordinal'] for row in page['rows']], [0])
        allowed_cells = [cell for cell in page['rows'][0]['cells'] if not cell['redacted']]
        self.assertEqual(''.join(cell['ascii'] for cell in allowed_cells), 'PRIV')
        description = next(value for value in generation['candidates'] if value['semantic_target'] == 'description')
        explanation = self.invoke('explain', run_id, description['id'], '--examples', '1')
        self.assertEqual(explanation['access_mode'], 'permitted_spans_only')
        self.assertEqual(''.join(cell['ascii'] for cell in explanation['examples'][0]['cells'] if not cell['redacted']), 'PRIV')
        owner = self.invoke('detail', run_id, '0', '--start', '0', '--end', '11')
        self.assertEqual(owner['access_mode'], 'local_owner_retained_source')
        self.assertEqual(owner['row']['raw_hex'], b'LEFTPRIVATE'.hex())
        report = self.invoke('report', run_id, '--authorized-only')
        html = Path(report['report']).read_text(encoding='utf-8')
        self.assertNotIn('LEFTPRIVATE', html)
        self.assertNotIn('RIGHTKNOWN!', html)
        self.assertEqual(report['states']['mapping_status'], 'incomplete')
        self.assertEqual(report['states']['product_acceptance'], 'pending')

    def test_declared_shipped_ebcdic_refusal_retains_full_source_and_nonzero_denominator(self):
        """what_bug_this_catches: unsupported declaration is normalized to accepted ASCII or zero-input success."""
        ingested = self.ingest('declared-ebcdic')
        repeated = self.ingest('declared-ebcdic')
        self.assertEqual(ingested['run'], repeated['run'])
        run_id = ingested['run']
        _, batch, brief = load_run(self.run_root, run_id)
        self.assertEqual(batch['status'], 'refused')
        self.assertIn('unsupported_encoding', batch['reasons'])
        self.assertEqual(batch['source_sha256'], SOURCE_PINS['declared-ebcdic'])
        self.assertEqual(batch['records'], [])
        self.assertEqual(batch['intake']['observed_record_count'], 2)
        self.assertEqual(batch['intake']['unmaterialized_record_count'], 2)
        page = self.invoke('inspect', run_id)
        self.assertEqual(page['state'], 'unmaterialized')
        self.assertEqual(page['counts']['observed'], 2)
        with self.assertRaises(ValueError): build_prompt(batch, brief, method='B1')
        report = self.invoke('report', run_id)
        html = Path(report['report']).read_text(encoding='utf-8')
        self.assertIn('unsupported_encoding', html)
        self.assertIn('<td>Observed records</td><td>2</td>', html)
        self.assertEqual(report['states']['transformation_status'], 'not_run')

    def test_changed_source_with_old_shipped_sample_is_refused_without_replacing_original_run(self):
        """what_bug_this_catches: a new source silently inherits stale sample authorization and immutable run bytes."""
        folder = self.copy_inputs('ambiguous-ledger', 'source-mutation')
        first = self.ingest('ambiguous-ledger', input_root=folder)['run']
        run, _, _ = load_run(self.run_root, first)
        original = run.joinpath('source.dat').read_bytes()
        changed = b'X' + original[1:]
        folder.joinpath('source.dat').write_bytes(changed)
        second = self.ingest('ambiguous-ledger', input_root=folder)
        self.assertNotEqual(second['run'], first)
        self.assertEqual(second['batch_status'], 'refused')
        self.assertIn('sample_source_mismatch', second['reasons'])
        self.assertEqual(run.joinpath('source.dat').read_bytes(), original)
        self.assertEqual(sha(original), SOURCE_PINS['ambiguous-ledger'])

    def test_mutated_committed_sample_refuses_consumers_and_preserves_other_artifacts(self):
        """what_bug_this_catches: current consumers trust a changed samples file while reusing committed generation/approval identity."""
        run_id = self.ingest('ambiguous-ledger')['run']
        generation = self.invoke('hypothesize', run_id, '--mode', 'rules')['generation']
        run, _, _ = load_run(self.run_root, run_id)
        generation_path = run / ('generation-' + generation['generation_sha256'] + '.json')
        saved_generation = generation_path.read_bytes()
        saved_batch = run.joinpath('batch.json').read_bytes()
        samples = json.loads(run.joinpath('samples.json').read_bytes())
        samples['authorization'] = 'changed without a new immutable run'
        run.joinpath('samples.json').write_bytes(canonical(samples) + b'\n')
        with self.assertRaises(ValueError): self.invoke('status', run_id)
        with self.assertRaises(ValueError): self.invoke('report', run_id, '--authorized-only')
        self.assertEqual(generation_path.read_bytes(), saved_generation)
        self.assertEqual(run.joinpath('batch.json').read_bytes(), saved_batch)

    def test_diagnostic_markup_mutation_of_shipped_copy_is_escaped_in_actual_owner_report(self):
        """what_bug_this_catches: a valid new literal/sample input becomes executable markup in diagnostic HTML."""
        folder = self.copy_inputs('partial-window', 'markup-mutation')
        original = folder.joinpath('source.dat').read_bytes()
        changed = b'<img src=x>' + original[11:]
        self.assertEqual(len(changed), 24)
        folder.joinpath('source.dat').write_bytes(changed)
        samples = json.loads(folder.joinpath('samples.json').read_bytes())
        samples['source_sha256'] = sha(changed)
        item = samples['records'][0]
        item['record_ref']['source_sha256'] = sha(changed)
        item['record_ref']['raw_sha256'] = sha(b'<img src=x>')
        item['raw_hex'], item['raw_sha256'] = b' src'.hex(), sha(b' src')
        samples['artifact_sha256'] = identity({key:value for key,value in samples.items() if key != 'artifact_sha256'})
        folder.joinpath('samples.json').write_bytes(canonical(samples) + b'\n')
        run_id = self.ingest('partial-window', input_root=folder)['run']
        self.invoke('hypothesize', run_id, '--mode', 'rules')
        report = self.invoke('report', run_id)
        html = Path(report['report']).read_text(encoding='utf-8')
        self.assertIn('&lt;img src=x&gt;', html)
        self.assertNotIn('<img src=x>', html)
        self.assertEqual(report['states']['mapping_status'], 'incomplete')
        self.assertEqual(report['states']['target_validation'], 'not_run')
        self.assertEqual(self.path('partial-window', 'source').read_bytes(), b'LEFTPRIVATE\r\nRIGHTKNOWN!')


if __name__ == '__main__':
    unittest.main()

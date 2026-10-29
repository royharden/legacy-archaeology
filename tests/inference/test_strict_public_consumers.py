"""Strict public-consumer regression SOURCE; unexecuted during construction."""
from copy import deepcopy
import hashlib
import json
from pathlib import Path
import tempfile
import unittest

from la.app.cli import execute, parser
from la.app.artifacts import load_run
from la.contracts import SourceBatch, Generation, Question, canonical
from la.ingest.evidence import authorized_spans, make_evidence, resolve_evidence
from la.ingest.inspection import inspection_page
from la.inference import hypothesize
from la.inference.explanation import explain_candidate


EXAMPLES = Path(__file__).resolve().parents[2] / 'examples' / 'intake'
PINS = {
    'ambiguous-ledger': 'cdec66c0427a59dc7b7125b9c18af4fb1750d6ba24ed10a84cef2c17a69caa13',
    'partial-window': 'e61799548394443c26ed2b0edf4bc54aac801c8d0fbd48a1d3085fda7c93c692',
    'declared-ebcdic': '61308b5fa050ea21cd1d100186b4676ce3f8c554ba4a4d0f69e4fdb5bb6726bd',
}


def sha(value):
    return hashlib.sha256(value).hexdigest()


def identity(value):
    return sha(json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False, allow_nan=False).encode())


class StrictPublicConsumersSource(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name) / 'runs'

    def invoke(self, *args):
        return execute(parser().parse_args(['--root', str(self.root), *args]))

    def ingest(self, name):
        return self.invoke('ingest', 'source.dat', '--input-root', str(EXAMPLES / name),
            '--brief', 'brief.md', '--samples', 'samples.json',
            '--encoding', 'EBCDIC' if name == 'declared-ebcdic' else 'ASCII')

    def test_real_cli_examples_roundtrip_strict_models_without_rewriting_pins(self):
        """what_bug_this_catches: closing shared nested schemas breaks literal public inputs."""
        expected = {'ambiguous-ledger': ('accepted', 25, 2),
                    'partial-window': ('accepted', 11, 2),
                    'declared-ebcdic': ('refused', None, 0)}
        for name, (status, width, materialized) in expected.items():
            with self.subTest(name=name):
                source = (EXAMPLES / name / 'source.dat').read_bytes()
                sample_bytes = (EXAMPLES / name / 'samples.json').read_bytes()
                result = self.ingest(name)
                run, batch, _ = load_run(self.root, result['run'])
                self.assertEqual(batch['source_sha256'], PINS[name])
                self.assertEqual(sha(source), PINS[name])
                self.assertEqual((batch['status'], batch['width'], len(batch['records'])), (status, width, materialized))
                self.assertEqual(batch['intake']['observed_record_count'], 2)
                self.assertEqual(batch['samples']['artifact_sha256'], identity(json.loads(sample_bytes)))
                self.assertEqual(SourceBatch.model_validate(batch).model_dump(exclude_unset=True), batch)
                generated = self.invoke('hypothesize', result['run'], '--mode', 'rules')['generation']
                self.assertEqual(Generation.model_validate(generated).model_dump(exclude_unset=True), generated)
                offered = self.invoke('questions', result['run'])['questions']
                self.assertEqual(len(offered), 5)
                for question in offered:
                    self.assertEqual(Question.model_validate(question).model_dump(exclude_unset=True), question)
                    self.assertEqual(question['options'][-1], {'id': 'unknown'})
                self.assertEqual(run.joinpath('source.dat').read_bytes(), source)
                self.assertEqual((EXAMPLES / name / 'samples.json').read_bytes(), sample_bytes)

    def test_partial_cli_explanation_shared_proofs_never_expose_denied_neighbors(self):
        """what_bug_this_catches: a strict-model bridge widens partial public permission."""
        run_id = self.ingest('partial-window')['run']
        generation = self.invoke('hypothesize', run_id, '--mode', 'rules')['generation']
        _, batch, _ = load_run(self.root, run_id)
        candidate = next(item for item in generation['candidates'] if item['semantic_target'] == 'description')
        explanation = self.invoke('explain', run_id, candidate['id'], '--examples', '1')
        self.assertEqual(explanation['access_mode'], 'permitted_spans_only')
        self.assertEqual(explanation['counts']['observed'], 2)
        self.assertEqual(explanation['approval_status'], 'unapproved')
        example = explanation['examples'][0]
        self.assertEqual(example['redacted_byte_count'], 7)
        self.assertIsNone(example['raw_hex'])
        self.assertEqual([cell['position'] for cell in example['cells'] if not cell['redacted']], [4, 5, 6, 7])
        self.assertEqual(''.join(cell['ascii'] for cell in example['cells'] if not cell['redacted']), 'PRIV')
        proof = example['visible_evidence'][0]
        self.assertEqual((proof['ordinal'], proof['start'], proof['end'], proof['byte_start']), (0, 4, 8, 4))
        self.assertEqual(proof['raw_hex'], '50524956')
        self.assertEqual(proof['raw_sha256'], '9590fc1fa43e11e3458f64af27528f06fbb85d616e67dfbce02a32d6f21c97e7')
        self.assertEqual(resolve_evidence(batch, proof, require_authorized=True), b'PRIV')
        self.assertEqual(Generation.model_validate(generation).model_dump(exclude_unset=True), generation)
        rendered = json.dumps(explanation)
        for denied in ('LEFTPRIVATE', 'RIGHTKNOWN!', b'LEFTPRIVATE'.hex(), b'RIGHTKNOWN!'.hex()):
            self.assertNotIn(denied, rendered)

    def test_rehashed_nested_unknowns_fail_actual_model_cli_and_explanation_consumers(self):
        """what_bug_this_catches: a valid outer content pin launders an unknown protocol key."""
        run_id = self.ingest('partial-window')['run']
        generation = self.invoke('hypothesize', run_id, '--mode', 'rules')['generation']
        run, batch, _ = load_run(self.root, run_id)
        candidate_id = generation['candidates'][0]['id']
        changed = deepcopy(generation)
        changed['discovery']['fields'][0]['oracle_answer'] = 'approved'
        changed['discovery']['discovery_sha256'] = identity({k:v for k,v in changed['discovery'].items() if k != 'discovery_sha256'})
        changed['generation_sha256'] = identity({k:v for k,v in changed.items() if k != 'generation_sha256'})
        with self.assertRaises(ValueError): Generation.model_validate(changed)
        with self.assertRaises(ValueError): explain_candidate(batch, changed, candidate_id)
        original_source = run.joinpath('source.dat').read_bytes()
        original_samples = run.joinpath('samples.json').read_bytes()
        forged_batch = deepcopy(batch)
        forged_batch['samples']['intake']['framing_policy']['oracle_answer'] = 'approved'
        run.joinpath('batch.json').write_bytes(canonical(forged_batch) + b'\n')
        manifest = json.loads(run.joinpath('run.json').read_bytes())
        manifest['batch_sha256'] = identity(forged_batch)
        run.joinpath('run.json').write_bytes(canonical(manifest) + b'\n')
        with self.assertRaises(ValueError): SourceBatch.model_validate(forged_batch)
        with self.assertRaises(ValueError): self.invoke('explain', run_id, candidate_id)
        self.assertEqual(run.joinpath('source.dat').read_bytes(), original_source)
        self.assertEqual(run.joinpath('samples.json').read_bytes(), original_samples)

    def test_legacy_whole_records_reach_current_consumers_without_new_hash_fields(self):
        """what_bug_this_catches: accepted legacy permissions become unusable or are silently upgraded."""
        run_id = self.ingest('ambiguous-ledger')['run']
        _, batch, brief = load_run(self.root, run_id)
        legacy = deepcopy(batch)
        legacy['samples'] = {key: batch['samples'][key] for key in
            ('authorization', 'artifact_sha256', 'records', 'selected_ordinals', 'truncated')}
        del legacy['intake']
        saved = canonical(legacy)
        self.assertEqual(SourceBatch.model_validate(legacy).model_dump(exclude_unset=True), legacy)
        selected = authorized_spans(legacy)
        self.assertEqual([(item['ordinal'], item['start'], item['end']) for item in selected], [(0, 0, 25), (1, 0, 25)])
        self.assertTrue(all('artifact_index' not in item for item in selected))
        self.assertEqual(resolve_evidence(legacy, make_evidence(legacy, 0, 0, 6), require_authorized=True), b'240229')
        generation = hypothesize(legacy, brief)
        self.assertTrue(any(candidate['evidence'] for candidate in generation['candidates']))
        candidate = next(item for item in generation['candidates'] if item['semantic_target'] == 'description')
        result = explain_candidate(legacy, generation, candidate['id'], examples_limit=1)
        self.assertEqual(result['examples'][0]['redacted_byte_count'], 0)
        self.assertIsNone(result['provenance']['sample_selection_sha256'])
        self.assertEqual(inspection_page(legacy, authorized_only=True)['rows'][0]['record_ref']['byte_start'], 0)
        self.assertEqual(canonical(legacy), saved)
        self.assertNotIn('authorized_spans', legacy['samples'])
        self.assertNotIn('selection_sha256', legacy['samples'])
        selected[0]['raw_hex'] = '00'
        self.assertEqual(authorized_spans(legacy)[0]['raw_hex'], batch['records'][0]['raw_hex'])
        forged = deepcopy(legacy)
        forged['samples']['records'][0]['source_sha256'] = '0' * 64
        with self.assertRaises(ValueError): authorized_spans(forged)

    def test_current_empty_selection_never_falls_back_to_legacy_whole_records(self):
        """what_bug_this_catches: compatibility fallback escalates an explicit empty current grant."""
        run_id = self.ingest('ambiguous-ledger')['run']
        _, batch, _ = load_run(self.root, run_id)
        forged = deepcopy(batch)
        samples = forged['samples']
        samples.update(authorized_spans=[], selected_ordinals=[], selected_artifact_indices=[],
                       authorized_count=0, selected_byte_count=0, truncated=False, selection_sha256=identity([]))
        # Retained full records deliberately contradict the explicit empty grant.
        with self.assertRaises(ValueError): authorized_spans(forged)
        with self.assertRaises(ValueError): inspection_page(forged, authorized_only=True)

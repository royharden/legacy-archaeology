"""Public hand-derived CLI journey regression SOURCE; no tests executed here."""
import json
import tempfile
import unittest
from unittest.mock import patch
from pathlib import Path

from la.app import parser, execute
from la.app.artifacts import immutable, pointer, read, within,receipt
from la.contracts import digest, sha256
from la.ingest.evidence import make_evidence
from la.review import RulingStore


ROWS = [b'000001Alpha       +0000123420240229A', b'000002Beta        -0000050020240301C']


class CliJourneyTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name)
        self.inputs = self.base/'inputs'; self.inputs.mkdir()
        self.root = self.base/'runs'
        data = b'\n'.join(ROWS)+b'\n'
        (self.inputs/'source.dat').write_bytes(data)
        (self.inputs/'brief.md').write_text('account_ref description balance effective_date status. Status vocabulary: A active, C closed.', encoding='utf-8')
        (self.inputs/'samples.json').write_text(json.dumps(dict(source_sha256=sha256(data), authorization='synthetic whole-record test permission',
            records=[dict(ordinal=i, raw_hex=row.hex(), raw_sha256=sha256(row)) for i,row in enumerate(ROWS)])), encoding='utf-8')
        result = self.call('ingest', 'source.dat', '--input-root', str(self.inputs), '--brief', 'brief.md', '--samples', 'samples.json')
        self.run_id = result['run']; self.run = self.root/self.run_id
        # A fixed, declared test mapping avoids asserting heuristic recall. The
        # expected values below are hand arithmetic, not product-derived gold.
        batch = read(self.run/'batch.json')
        common = dict(padding_byte=' ', padding_side='none', trim=False, nullable=False)
        fields = [dict(start=0,end=6,semantic_target='account_ref',data_type='text',policy=dict(common)),
            dict(start=6,end=18,semantic_target='description',data_type='text',policy=dict(common,padding_side='right',trim=True)),
            dict(start=18,end=27,semantic_target='balance',data_type='decimal',policy=dict(common,scale=2,precision=8,sign='leading')),
            dict(start=27,end=35,semantic_target='effective_date',data_type='date',policy=dict(common,format='YYYYMMDD',sentinels={})),
            dict(start=35,end=36,semantic_target='status',data_type='text',policy=dict(common,allowed_codes=['A','C']))]
        candidates = []
        for field in fields:
            value = dict(field, evidence=[make_evidence(batch,0,field['start'],field['end'])],
                         origin='mock', uncertainty='hand_derived_test_mapping')
            candidates.append(dict(value,id=digest(value)))
        generation = dict(schema_version=1, source_sha256=batch['source_sha256'], framing_sha256=batch['framing_sha256'],
            brief_sha256=batch['brief_sha256'], policy_sha256=digest('explicit test-only policies'),
            candidates=candidates, unknowns=[], mode='mock', filler=[], discovery={
                'information_source':'public_hand_declared_test_layout',
                'sample_artifact_sha256':batch['samples']['artifact_sha256'],
                'sample_selection_sha256':batch['samples'].get('selection_sha256')})
        generation['generation_sha256'] = digest(generation)
        immutable(self.run/('generation-'+generation['generation_sha256']+'.json'),generation)
        pointer(self.run/'current-generation.json',{'generation_sha256':generation['generation_sha256']})
        RulingStore(self.run/'rulings.sqlite').bind_generation(generation)
        self.ids = {candidate['semantic_target']:candidate['id'] for candidate in candidates}

    def call(self, *argv):
        return execute(parser().parse_args(['--root',str(self.root),*argv]))

    def answer_all(self):
        responses=[]
        for question in self.call('questions',self.run_id)['questions']:
            responses.append(self.call('answer',self.run_id,question['id'],self.ids[question['semantic_target']],
                '--actor','agent_provisional','--reason','explicit synthetic test policy','--revision','0',
                '--request-id','test-'+question['id']))
        return responses

    def test_approval_lineage_exact_rows_and_stale_answer_invalidate(self):
        """what_bug_this_catches: unsigned/unapproved/stale mapping produces accepted load rows."""
        with self.assertRaises(ValueError): self.call('transform',self.run_id)
        responses = self.answer_all()
        history = self.call('history',self.run_id)['events']
        self.assertEqual(len(history),5)
        self.assertEqual({r['event_id'] for r in responses},{e['event_id'] for e in history})
        replay = self.call('replay',self.run_id)
        self.assertEqual(len(replay['answers']),5)
        approval = self.call('approve',self.run_id,'--actor','<script>alert(1)</script>','--reason','synthetic complete policy')
        result = self.call('transform',self.run_id)
        bundle = Path(result['bundle']); original_manifest=(bundle/'manifest.json').read_bytes()
        rows = [json.loads(line) for line in (bundle/'rows.jsonl').read_text().splitlines()]
        self.assertEqual([r['values'] for r in rows], [
            dict(account_ref='000001',description='Alpha',balance='12.34',effective_date='2024-02-29',status='A'),
            dict(account_ref='000002',description='Beta',balance='-5.00',effective_date='2024-03-01',status='C')])
        lineage = json.loads((bundle/'rulings.json').read_text())
        self.assertEqual(len(lineage['events']),5)
        self.assertEqual(result['states']['transformation_status'],'complete')
        self.assertEqual(result['states']['row_parity'],'not_run')
        self.assertEqual(result['states']['target_validation'],'not_run')
        execution=self.call('database-check',str(bundle.relative_to(self.root)))
        self.assertEqual(execution['payload']['observation']['target_validation'],'not_run')
        self.assertNotEqual(Path(execution['path']).parent,bundle)
        self.assertEqual((bundle/'manifest.json').read_bytes(),original_manifest)
        report = self.call('report',self.run_id)
        text = Path(report['report']).read_text(encoding='utf-8')
        self.assertNotIn('<script>alert(1)</script>',text)
        self.assertIn('&lt;script&gt;alert(1)&lt;/script&gt;',text)
        self.assertIn('Partial',text.title())
        question = self.call('questions',self.run_id)['questions'][0]
        self.call('answer',self.run_id,question['id'],'unknown','--actor','agent_provisional',
            '--reason','test reopens interpretation','--revision','1','--request-id','reopen')
        status = self.call('status',self.run_id)
        self.assertEqual(status['states']['mapping_status'],'incomplete')
        self.assertIsNone(status['approval'])
        self.assertEqual(status['states']['transformation_status'],'not_run')
        with self.assertRaises(ValueError): self.call('transform',self.run_id)
        self.assertEqual((bundle/'manifest.json').read_bytes(),original_manifest)
        self.assertTrue((self.run/'approvals'/approval['mapping_sha256']/(approval['approval_sha256']+'.json')).exists())

    def test_exact_retry_and_competing_revision_leave_one_event(self):
        """what_bug_this_catches: exact retry duplicates journal effects or CAS is ignored."""
        question=self.call('questions',self.run_id)['questions'][0]
        args=('answer',self.run_id,question['id'],self.ids[question['semantic_target']], '--actor','agent_provisional',
              '--reason','synthetic retry','--revision','0','--request-id','same-request')
        first=self.call(*args); second=self.call(*args)
        self.assertEqual(first,second)
        with self.assertRaises(ValueError): self.call(*args[:-1],'different-request')
        self.assertEqual(len(self.call('history',self.run_id)['events']),1)

    def test_changed_source_and_traversal_refuse(self):
        """what_bug_this_catches: filesystem escape or changed bytes retain old authorization."""
        with self.assertRaises(ValueError): within(self.root,'../outside')
        outside=self.base/'outside'; outside.write_text('not readable',encoding='utf-8')
        try: (self.root/'escape').symlink_to(outside)
        except OSError: pass
        else:
            with self.assertRaises(ValueError): within(self.root,'escape',exists=True)
        (self.run/'source.dat').write_bytes(b'changed')
        with self.assertRaises(ValueError): self.call('questions',self.run_id)

    def test_incomplete_export_has_no_approval_and_no_load_rows(self):
        """what_bug_this_catches: unresolved raw bytes masquerade as TEXT rows."""
        result=self.call('export',self.run_id)
        self.assertEqual(result['manifest']['mapping_status'],'incomplete')
        self.assertIsNone(result['manifest']['approval_sha256'])
        self.assertEqual((Path(result['bundle'])/'rows.jsonl').read_bytes(),b'')
        self.assertEqual(result['manifest']['counts']['unresolved'],2)

    def test_generation_cache_missing_corrupt_or_stale_recovers_only_from_sqlite(self):
        """what_bug_this_catches: a JSON cache becomes authority or crash loses committed generation."""
        store=RulingStore(self.run/'rulings.sqlite')
        before=store.current_state()
        index=self.run/'current-generation.json'
        index.write_bytes(b'interrupted cache bytes')
        recovered=self.call('questions',self.run_id)
        self.assertEqual(len(recovered['questions']),5)
        self.assertEqual(read(index)['generation_sha256'],before['generation_sha256'])
        self.assertEqual(store.current_state()['state_token'],before['state_token'])
        archive=self.run/('generation-'+before['generation_sha256']+'.json')
        archive.unlink()  # Own temporary fixture, simulating a crash before cache publication.
        index.unlink()
        self.call('questions',self.run_id)
        self.assertEqual(read(archive),before['generation'])
        self.assertEqual(self.call('history',self.run_id)['events'],[])

    def test_explanation_preserves_unknown_and_unapproved_byte_evidence(self):
        """what_bug_this_catches: explanatory ranking/pattern becomes an approved business policy."""
        unknown=self.call('explain',self.run_id,'unknown','--examples','0')
        self.assertEqual(unknown['state'],'abstained')
        self.assertEqual(unknown['approval_status'],'unapproved')
        balance=self.call('explain',self.run_id,self.ids['balance'])
        self.assertEqual(balance['candidate']['start'],18)
        self.assertEqual(balance['candidate']['end'],27)
        self.assertEqual(balance['correct_policy_available'],'not_established')
        self.assertTrue(balance['diagnostic_only'])
        self.assertTrue(all(example['typed_value']=='not_inferred' for example in balance['examples']))
        self.assertEqual(self.call('history',self.run_id)['events'],[])

    def test_new_target_path_missing_signed_trust_never_reads_environment(self):
        """what_bug_this_catches: a new target command loads/reads DSN before real authority."""
        folder=self.root/'no-authority-candidate'; folder.mkdir()
        with patch('la.app.observations.os.environ.get',side_effect=AssertionError('no environment read allowed')):
            result=self.call('database-observe',str(folder.relative_to(self.root)))
        self.assertEqual(result['payload']['target_validation'],'not_run')
        self.assertIsNone(result['payload']['observation'])

    def test_permitted_only_report_omits_unrestricted_legacy_execution_text(self):
        """what_bug_this_catches: a legacy receipt leaks free text around newer permission masks."""
        mapping=self.call('status',self.run_id)['mapping']
        saved=receipt(self.run,'execution',dict(mapping_sha256=mapping['mapping_sha256'],
            observation={'unrestricted_text':'SECRET_NOT_PERMITTED_SAMPLE'}))
        pointer(self.run/'current-execution.json',{'relative_path':str(Path(saved['path']).relative_to(self.run))})
        rendered=self.call('report',self.run_id,'--authorized-only')
        self.assertNotIn('SECRET_NOT_PERMITTED_SAMPLE',Path(rendered['report']).read_text(encoding='utf-8'))


if __name__ == '__main__': unittest.main()

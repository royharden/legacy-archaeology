"""Durability/concurrency/path regression SOURCE; not run in Dirty Mode."""
import hashlib
import json
import queue
import tempfile
import threading
import unittest
from pathlib import Path
from unittest.mock import patch

from la.app import execute,parser
from la.app.artifacts import immutable,pointer,read
from la.app.storage import (publish_bytes,bounded_bytes,bounded_json,pointer_token,
    run_lock,observe_source,SOURCE_BYTES,atomic_directory,stage_inventory)
from la.contracts import digest,sha256


class StorageTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name)

    def test_immutable_exact_retry_and_failed_stage_never_publish_partial_final(self):
        """what_bug_this_catches: crash exposes partial frozen bytes or retry overwrites them."""
        final=self.root/'artifact.json'
        immutable(final,{'amount':'12.34'})
        original=final.read_bytes()
        immutable(final,{'amount':'12.34'})
        with self.assertRaises(ValueError): immutable(final,{'amount':'12.35'})
        self.assertEqual(final.read_bytes(),original)
        interrupted=self.root/'not-committed.json'
        with patch('la.app.storage.os.link',side_effect=OSError('synthetic publication failure')):
            with self.assertRaises(OSError): immutable(interrupted,{'x':1})
        self.assertFalse(interrupted.exists())

    def test_pointer_cas_rejects_stale_transition_and_epoch_aba(self):
        """what_bug_this_catches: stale A→B→A cache transition overwrites current epoch."""
        path=self.root/'current.json'
        first={'generation_sha256':'1'*64,'generation_epoch':1}
        pointer(path,first,expected=None); old=pointer_token(path)
        second={'generation_sha256':'2'*64,'generation_epoch':2}
        pointer(path,second,expected=old)
        pointer(path,dict(first,generation_epoch=3),expected=pointer_token(path))
        with self.assertRaises(ValueError): pointer(path,{'generation_epoch':4},expected=old)
        self.assertEqual(read(path)['generation_epoch'],3)

    def test_per_run_lock_excludes_another_thread_without_wait_loop(self):
        """what_bug_this_catches: simultaneous CLI writes lose approval/generation pointers."""
        outcomes=queue.Queue()
        def contender():
            try:
                with run_lock(self.root,'same-run'): outcomes.put('incorrectly acquired')
            except ValueError: outcomes.put('busy')
        with run_lock(self.root,'same-run'):
            thread=threading.Thread(target=contender); thread.start(); thread.join(2)
            self.assertFalse(thread.is_alive())
            self.assertEqual(outcomes.get_nowait(),'busy')
        with run_lock(self.root,'same-run'): pass

    def test_bounded_json_rejects_duplicates_nesting_and_oversize(self):
        """what_bug_this_catches: permissive JSON or unbounded artifact read hides tampering."""
        path=self.root/'input.json'
        for payload in (b'{"x":1,"x":2}',b'{"x":NaN}',b'['*34+b'0'+b']'*34):
            path.write_bytes(payload)
            with self.subTest(payload=payload),self.assertRaises(ValueError): bounded_json(path)
        path.write_bytes(b'{"large":"abcdefghij"}')
        with self.assertRaises(ValueError): bounded_bytes(path,limit=8)
        path.write_bytes(b'{ "x": 1 }')
        self.assertEqual(bounded_json(path),{'x':1})
        with self.assertRaises(ValueError): bounded_json(path,canonical_required=True)

    def test_orphan_stage_ignored_and_directory_never_overwritten(self):
        """what_bug_this_catches: orphan temp becomes a bundle or a retry replaces frozen files."""
        orphan=self.root/'.old.la-tmp-owned'; orphan.write_bytes(b'partial')
        self.assertFalse(stage_inventory(self.root)[0]['committed'])
        destination=self.root/'bundle'
        stage=self.root/'.bundle.la-tmp-first'; stage.mkdir(); (stage/'manifest.json').write_text('first')
        atomic_directory(stage,destination)
        other=self.root/'.bundle.la-tmp-second'; other.mkdir(); (other/'manifest.json').write_text('wrong')
        with self.assertRaises(ValueError): atomic_directory(other,destination)
        self.assertEqual((destination/'manifest.json').read_text(),'first')
        self.assertEqual(orphan.read_bytes(),b'partial')

    def test_oversize_refusal_uses_completed_stream_hash_and_observed_denominator(self):
        """what_bug_this_catches: oversized prefix hash falsely identifies original input."""
        data=b'A'*(SOURCE_BYTES+1)
        source=self.root/'source.dat'; source.write_bytes(data)
        retained,observation=observe_source(source)
        self.assertIsNone(retained)
        self.assertEqual(observation['source_sha256'],hashlib.sha256(data).hexdigest())
        self.assertNotEqual(observation['source_sha256'],hashlib.sha256(data[:SOURCE_BYTES]).hexdigest())
        (self.root/'brief.md').write_text('account_ref',encoding='utf-8')
        (self.root/'samples.json').write_text(json.dumps(dict(source_sha256=sha256(data),authorization='synthetic no sample bytes',records=[])))
        runroot=self.root/'runs'
        result=execute(parser().parse_args(['--root',str(runroot),'ingest','source.dat','--input-root',str(self.root),
            '--brief','brief.md','--samples','samples.json']))
        run=runroot/result['run']; batch=read(run/'batch.json')
        self.assertEqual(batch['status'],'refused')
        self.assertEqual(batch['intake']['observed_record_count'],1)
        self.assertEqual(batch['intake']['materialized_record_count'],0)
        self.assertFalse((run/'source.dat').exists())
        self.assertEqual(read(run/'source-observation.json')['source_sha256'],sha256(data))

    def test_permitted_report_masks_neighbor_bytes_without_generation(self):
        """what_bug_this_catches: local owner grid is accidentally used for authorized-only report."""
        data=b'ABCD\n'; (self.root/'source.dat').write_bytes(data)
        (self.root/'brief.md').write_text('account_ref',encoding='utf-8')
        framing=digest(dict(version=2,framing='LF',width=4,width_candidates=[4],terminal_newline=True))
        ref=dict(source_sha256=sha256(data),framing_sha256=framing,ordinal=0,byte_start=0,length=4,raw_sha256=sha256(b'ABCD'))
        samples=dict(source_sha256=sha256(data),authorization='AB only',records=[
            dict(record_ref=ref,span={'start':0,'end':2},raw_hex='4142',raw_sha256=sha256(b'AB'))])
        (self.root/'samples.json').write_text(json.dumps(samples),encoding='utf-8')
        runroot=self.root/'runs'
        def call(*argv): return execute(parser().parse_args(['--root',str(runroot),*argv]))
        run=call('ingest','source.dat','--input-root',str(self.root),'--brief','brief.md','--samples','samples.json')['run']
        page=call('inspect',run,'--authorized-only')
        self.assertEqual([cell['hex'] for cell in page['rows'][0]['cells']],['41','42',None,None])
        rendered=call('report',run,'--authorized-only')
        text=Path(rendered['report']).read_text(encoding='utf-8')
        self.assertIn('permitted_spans_only',text)
        self.assertNotIn('41424344',text)


if __name__=='__main__': unittest.main()

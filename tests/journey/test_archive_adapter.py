"""Future release-adapter regression SOURCE; no archive/crypto/oracle operation performed."""
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from scripts.archive import plan_from_packet,parser


class ArchiveAdapterTests(unittest.TestCase):
    def packet(self,visibility):
        return dict(schema_version=1,edition='synthetic',visibility=visibility,
            manifest_refs=[{'sha256':'a'*64,'kind':'variant_manifest'}],
            cases='never-open-cases.json',configuration='never-open-config.json')

    def test_public_route_refuses_hidden_before_any_case_or_oracle_read(self):
        """what_bug_this_catches: a public flag exposes an active hidden case during inventory planning."""
        with tempfile.TemporaryDirectory() as root:
            registry=SimpleNamespace(state=lambda edition:{'retired':False,'attempt':None})
            with (patch('scripts.results.captured',return_value={'edition':'synthetic','split':'heldout'}),
                  patch('evaluation.archive.plan_archive') as owner,
                  patch('la.app.artifacts.read',side_effect=AssertionError('raw case file opened'))):
                with self.assertRaises(ValueError): plan_from_packet(None,registry,Path(root),self.packet('public'))
                owner.assert_not_called()

    def test_retired_label_cannot_replace_actual_registry_disposition(self):
        """what_bug_this_catches: untrusted packet labels release active hidden oracle files."""
        with tempfile.TemporaryDirectory() as root:
            registry=SimpleNamespace(state=lambda edition:{'retired':False,'attempt':None})
            with (patch('scripts.results.captured',return_value={'edition':'synthetic','split':'heldout'}),
                  patch('evaluation.archive.plan_archive') as owner,
                  patch('la.app.artifacts.read',side_effect=AssertionError('raw case file opened'))):
                with self.assertRaises(ValueError): plan_from_packet(None,registry,Path(root),self.packet('retired'))
                owner.assert_not_called()

    def variant(self,variant_id='v1'):
        return {'variant_id':variant_id,'split':'development','edition':'synthetic','visible':{'source':'public'},
                'batches':[{'batch_id':'b1','visible':{},'oracle':[]}]}

    def planned(self,refs,variants):
        """Run plan_from_packet with real files present but owner/read patched; return plan_archive kwargs."""
        with tempfile.TemporaryDirectory() as root:
            for name in ('cases.json','config.json'): Path(root,name).write_text('{}')
            packet=dict(self.packet('public'),manifest_refs=refs,cases='cases.json',configuration='config.json')
            registry=SimpleNamespace(state=lambda edition:{'retired':False,'attempt':None})
            values={'cases.json':{'variants':variants},'config.json':{'schema_version':1}}
            with (patch('scripts.results.captured',return_value={'edition':'synthetic','split':'development'}),
                  patch('evaluation.archive.plan_archive') as owner,
                  patch('la.app.artifacts.read',side_effect=lambda path,**_:values[Path(path).name])):
                plan_from_packet(None,registry,Path(root),packet)
                return owner.call_args.kwargs

    def test_cases_are_distinct_transitive_variants_not_one_per_root(self):
        """what_bug_this_catches: caller demands one case per root and rejects two attempts of one variant."""
        refs=[{'sha256':c*64,'kind':'variant_manifest'} for c in 'ab']
        kwargs=self.planned(refs,[self.variant()])
        self.assertEqual(len(kwargs['manifest_refs']),2)
        self.assertEqual([case.variant_id for case in kwargs['cases']],['v1'])

    def test_more_cases_than_roots_reach_the_producer(self):
        """what_bug_this_catches: history/suite-reached variants cannot be supplied for one requested root."""
        kwargs=self.planned([{'sha256':'a'*64,'kind':'variant_manifest'}],[self.variant('v1'),self.variant('v2')])
        self.assertEqual([case.variant_id for case in kwargs['cases']],['v1','v2'])

    def test_duplicate_case_variant_refused(self):
        """what_bug_this_catches: two oracle versions for one variant are silently both archived."""
        with self.assertRaises(ValueError):
            self.planned([{'sha256':'a'*64,'kind':'variant_manifest'}],[self.variant(),self.variant()])

    def test_t3_or_sealed_root_refused_on_public_route_before_case_read(self):
        """what_bug_this_catches: only split=heldout is treated as hidden by the caller precheck."""
        for marker in ({'evaluation_phase':'T3'},{'visibility':'sealed'}):
            with self.subTest(marker), tempfile.TemporaryDirectory() as root:
                registry=SimpleNamespace(state=lambda edition:{'retired':False,'attempt':None})
                with (patch('scripts.results.captured',return_value={'edition':'synthetic','split':'development',**marker}),
                      patch('evaluation.archive.plan_archive') as owner,
                      patch('la.app.artifacts.read',side_effect=AssertionError('raw case file opened'))):
                    with self.assertRaises(ValueError): plan_from_packet(None,registry,Path(root),self.packet('public'))
                    owner.assert_not_called()

    def test_root_count_and_duplicate_roots_bounded_before_capture_reads(self):
        """what_bug_this_catches: an unbounded/duplicated root list is read before the producer's own caps."""
        registry=SimpleNamespace(state=lambda edition:{'retired':False,'attempt':None})
        for refs in ([{'sha256':'%064x'%i,'kind':'variant_manifest'} for i in range(65)],
                     [{'sha256':'a'*64,'kind':'variant_manifest'}]*2):
            with self.subTest(count=len(refs)), patch('scripts.results.captured',side_effect=AssertionError('capture read')):
                with self.assertRaises(ValueError):
                    plan_from_packet(None,registry,Path('.'),dict(self.packet('public'),manifest_refs=refs))

    def test_portable_export_requires_separate_signed_release(self):
        """what_bug_this_catches: an inventory preview is mistaken for release authorization."""
        with self.assertRaises(SystemExit):
            parser().parse_args(['--operator-root','root','--capture-root','captures','export',
                '--registry','editions.sqlite','--packet','plan.json','--destination','archive.zip',
                '--public-trust-root','public','--public-trust-profile','profile.json'])

    def test_archive_read_requires_external_manifest_pin(self):
        """what_bug_this_catches: a self-hashed supplied ZIP becomes its own trust anchor."""
        with self.assertRaises(SystemExit):
            parser().parse_args(['--operator-root','root','--capture-root','captures','read','--archive','archive.zip',
                '--public-trust-root','public','--public-trust-profile','profile.json'])


if __name__=='__main__': unittest.main()

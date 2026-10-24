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

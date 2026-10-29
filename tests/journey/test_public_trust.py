"""Operator public-profile regression SOURCE, no crypto/key operation performed."""
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from la.app.public_trust import public_keys


class PublicProfileTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name)

    def profile(self,value):
        (self.root/'profile.json').write_text(json.dumps(value),encoding='utf-8')

    def test_explicit_public_bytes_and_role_are_not_authority_success_flags(self):
        """what_bug_this_catches: candidate truthy flags/signing keys masquerade as trusted public setup."""
        self.profile(dict(schema_version=1,trusted_issuers={'test':{'issuer':'synthetic','role':'target_authority'}},
                          public_keys={'test':'01'*32}))
        issuers,keys=public_keys(self.root,'profile.json')
        self.assertEqual(issuers,{'test':('synthetic','target_authority')})
        self.assertEqual(keys['test'],b'\x01'*32)
        self.assertNotIn('verified',issuers)

    def test_private_key_or_boolean_profile_fields_refused(self):
        """what_bug_this_catches: public-only loader silently reads signer credentials or trusts booleans."""
        for extra in ({'private_key':'synthetic-do-not-use'},{'verified':True}):
            self.profile(dict(schema_version=1,trusted_issuers={},public_keys={},**extra))
            with self.subTest(extra=extra),self.assertRaises(ValueError): public_keys(self.root,'profile.json')

    def test_duplicate_keys_and_traversal_refused(self):
        """what_bug_this_catches: unrelated issuer roles share one key or select a profile outside operator root."""
        self.profile(dict(schema_version=1,trusted_issuers={
            'a':{'issuer':'one','role':'target_authority'},'b':{'issuer':'two','role':'run_owner'}},
            public_keys={'a':'01'*32,'b':'01'*32}))
        with self.assertRaises(ValueError): public_keys(self.root,'profile.json')
        with self.assertRaises(ValueError): public_keys(self.root,'../outside.json')

    def test_rejected_signature_never_reaches_target_config_or_environment(self):
        """what_bug_this_catches: signed-target wrapper reads DSN before concrete signature rejection."""
        from la.app import execute,parser
        self.profile(dict(schema_version=1,trusted_issuers={'test':{'issuer':'synthetic','role':'target_authority'}},
                          public_keys={'test':'01'*32}))
        (self.root/'candidate').mkdir()
        (self.root/'intent.json').write_text('{}',encoding='utf-8')
        args=parser().parse_args(['--root',str(self.root),'database-observe','candidate','--authority','intent.json',
            '--target-config','never-read.json','--public-trust-root',str(self.root),'--public-trust-profile','profile.json'])
        with (
            patch('la.postgres.authority.TargetAuthorityVerifier.verify',side_effect=ValueError('synthetic rejected signature')),
            patch('la.app.observations.os.environ.get',side_effect=AssertionError('environment must stay unread')),
        ):
            with self.assertRaises(ValueError): execute(args)


if __name__=='__main__': unittest.main()

"""Actual Addition003 cleanup receipt in a public synthetic evaluator archive.

The migration arms are explicitly fixture arms. Only the auxiliary cleanup
receipt comes from real PostgreSQL; neither archive nor replay connects to it.
All generated artifacts are retained in the explicitly supplied evidence root.
"""
from copy import deepcopy
import hashlib
import json
import os
from pathlib import Path
import unittest
from unittest.mock import patch
import uuid

from evaluation import archive as A
from evaluation.artifacts import CaptureStore, digest
from la.postgres import open_target_cleanup
from test_archive import Fixture, configuration
from custody_support import verifier


class RealCleanupArchive(unittest.TestCase):
    def setUp(self):
        if not os.environ.get('M1_RV2_CLEANUP_ARCHIVE_INPUT'):
            self.skipTest('exact actual cleanup receipt handoff required')
        index = json.loads(Path(os.environ['M1_RV2_CLEANUP_ARCHIVE_INPUT']).read_text())
        self.receipt = open_target_cleanup(Path(index['path']), expected_cleanup_sha256=index['cleanup_sha256'])
        # This is the exact allowlist captured before the real DROP, not a list
        # reconstructed from a receipt after the destructive operation.
        saved_bytes = Path(index['allowlist_path']).read_bytes()
        self.assertEqual(hashlib.sha256(saved_bytes).hexdigest(), index['allowlist_sha256'])
        saved = json.loads(saved_bytes)
        namespace = self.receipt['binding']['namespace']
        self.assertEqual(saved['namespace'], namespace)
        self.assertEqual(saved['exact_drop_sql'], [
            f'DROP TABLE "{namespace}"."candidate_execution" RESTRICT',
            f'DROP TABLE "{namespace}"."migrated_records" RESTRICT',
            f'DROP SCHEMA "{namespace}" RESTRICT'])
        expected = [hashlib.sha256(json.dumps(dict(sql=sql, parameters=None), sort_keys=True,
            separators=(',', ':'), ensure_ascii=False, allow_nan=False).encode('utf-8')).hexdigest()
            for sql in saved['exact_drop_sql']]
        self.assertEqual(self.receipt['transaction']['statements'], expected)
        self.assertEqual(self.receipt['state'], 'committed')
        self.assertEqual((self.receipt['target_validation'], self.receipt['row_parity'],
                          self.receipt['product_acceptance']), ('not_run', 'not_run', 'pending'))
        self.root = Path(os.environ['M1_RV2_CLEANUP_ARCHIVE_EVIDENCE']).resolve(strict=True) / uuid.uuid4().hex
        self.root.mkdir()
        self.f = Fixture(self.root)

    def test_actual_cleanup_export_read_replay_is_neutral(self):
        """what_bug_this_catches: real cleanup receipt leaks into migration/negative-effect scoring."""
        aux = self.f.store.put('target_cleanup_observation', self.receipt)
        plan = self.f.plan(configuration=configuration(self.f.manifest, {'auxiliary_captures': [aux]}))
        path, exported = self.f.export(plan)
        snapshot = A.read_archive(path, expected_archive_sha256=exported['archive_sha256'], verifier=verifier())
        self.assertEqual(snapshot.get(aux, kind='target_cleanup_observation'), self.receipt)
        self.assertEqual(snapshot.manifest['auxiliary'], [aux])
        # Replaying a portable capture has no authority to invoke destructive code.
        with patch('la.postgres.cleanup.cleanup_target_namespace', side_effect=AssertionError('cleanup rerun')):
            (self.root / 'replay').mkdir()
            replay = A.replay_portable_archive(path, expected_archive_sha256=exported['archive_sha256'],
                verifier=verifier(), result_store=CaptureStore(self.root / 'replay'))
        self.assertEqual(replay['auxiliary_count'], 1)
        self.assertEqual(len(replay['results']), 1)
        self.assertEqual(len(replay['results'][0]['results']), 5)
        self.assertEqual(replay['target_validation'], 'not_run')
        self.assertFalse(replay['stochastic_model_rerun'])
        (self.root / 'roundtrip-result.json').write_text(json.dumps(dict(
            actual_cleanup_sha256=self.receipt['cleanup_sha256'], exported=exported, replay=replay), indent=2))

    def test_actual_receipt_cannot_claim_scored_effect(self):
        """what_bug_this_catches: correctly rehashed cleanup claims scored target parity."""
        changed = deepcopy(self.receipt)
        changed['row_parity'] = 'passed'
        changed['cleanup_sha256'] = digest({k: v for k, v in changed.items() if k != 'cleanup_sha256'})
        aux = self.f.store.put('target_cleanup_observation', changed)
        with self.assertRaisesRegex(ValueError, 'neutral'):
            self.f.plan(configuration=configuration(self.f.manifest, {'auxiliary_captures': [aux]}))


if __name__ == '__main__':
    unittest.main()

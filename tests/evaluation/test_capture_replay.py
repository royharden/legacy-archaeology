"""Immutable capture/replay regression SOURCE; no stochastic rerun is implied."""
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from evaluator_support import case, fake_ports, gold
from evaluation.artifacts import CaptureStore, retire_archive
from evaluation.runner import run_variant, replay_archive


class CaptureReplay(unittest.TestCase):
    def test_idempotent_put_tamper_rejected_and_no_path_escape(self):
        """what_bug_this_catches: overwrite/relative-path artifacts defeat replay pins."""
        with TemporaryDirectory() as directory:
            store = CaptureStore(directory)
            first = store.put('raw', {'status': 'failed', 'attempt': 1})
            self.assertEqual(store.put('raw', {'status': 'failed', 'attempt': 1}), first)
            with self.assertRaises(ValueError):
                store.put('../escape', {})
            path = Path(directory) / (first['sha256'] + '.json')
            original = path.read_bytes()
            path.write_bytes(b'{}')  # Deliberate corruption of this test's own temporary file.
            with self.assertRaisesRegex(ValueError, 'hash mismatch'):
                store.get(first)
            with self.assertRaisesRegex(ValueError, 'collision'):
                store.put('raw', {'status': 'failed', 'attempt': 1})
            self.assertNotEqual(path.read_bytes(), original)

    def test_replay_keeps_failed_arm_and_never_calls_provider(self):
        """what_bug_this_catches: replay retries failed B1 or erases its denominator."""
        calls = []
        def malformed(request):
            calls.append(request)
            return {'output': None}
        with TemporaryDirectory() as directory:
            store = CaptureStore(directory)
            report = run_variant(case(), fake_ports(provider=malformed), store)
            replay = replay_archive(store, report['manifest_capture'], gold())
            self.assertEqual(len(calls), 1)
            b1 = next(item for item in replay['results'] if item['method'] == 'B1')
            self.assertEqual(b1['original_status'], 'failed')
            self.assertEqual(b1['score']['semantic_rows']['numerator'], 0)
            self.assertEqual(b1['score']['semantic_rows']['denominator'], 3)
            self.assertFalse(replay['stochastic_model_rerun'])
            self.assertFalse(replay['fresh_holdout'])

    def test_active_archive_requires_exact_retirement(self):
        """what_bug_this_catches: exposed/public gold is relabeled fresh hidden replay."""
        with TemporaryDirectory() as directory:
            store = CaptureStore(directory)
            report = run_variant(case(), fake_ports(), store)
            # Synthetic archive metadata only; no hidden corpus or heldout run.
            archive = store.get(report['manifest_capture'])
            archive['split'] = 'heldout'
            hidden_ref = store.put('variant_manifest', archive)
            with self.assertRaises(ValueError):
                replay_archive(store, hidden_ref, gold())
            with self.assertRaises(ValueError):
                retire_archive(store, archive, release={'authorized': False})
            # An arbitrary release boolean/hash is no longer sufficient for an
            # archive labeled heldout: actual signed journal retirement is needed.
            with self.assertRaises(ValueError):
                retire_archive(store, archive, release={'authorized': True,
                    'edition': archive['edition'], 'authority_sha256': 'd' * 64})


if __name__ == '__main__':
    unittest.main()

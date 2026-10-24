"""Portable archive refusal/leak/retirement/tamper regression SOURCE.

Future unit source only: authored under Dirty Mode, never collected or run there.
Synthetic public fixtures and test-only keys; no hidden corpus, provider, target
or cleanup operation. Each case names the bug it catches.
"""
from dataclasses import replace
from datetime import datetime, timedelta, timezone
import io
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
import zipfile

from evaluator_support import case, fake_ports
from custody_support import sign, verifier
from evaluation import archive as A
from evaluation.artifacts import CaptureStore, digest
from evaluation.edition_registry import EditionRegistry
from evaluation.runner import run_variant


def configuration(manifest, values=None):
    return {'schema_version': 1, 'edition': manifest['edition'], 'pins': manifest['pins'], 'values': values or {}}


def signed_release(plan, *, minutes=30, **override):
    body = {**plan.release_payload, 'not_after_utc': (datetime.now(timezone.utc) + timedelta(minutes=minutes)).isoformat(),
            'nonce': digest('test nonce'), 'authority_sha256': None, **override}
    body['authority_sha256'] = digest({k: v for k, v in body.items() if k != 'authority_sha256'})
    return sign(body)


def cleanup_receipt(**override):
    """Synthetic D5 CLEANUP-API FINAL-shaped receipt; no database was touched."""
    body = {'schema_version': 1, 'kind': 'target_cleanup', 'cleanup_id': '0' * 32, 'action': 'cleanup',
            'binding': {}, 'candidate': {}, 'expected_target': {}, 'cleanup_authority_sha256': 'a' * 64,
            'cleanup_authority_envelope_sha256': 'b' * 64, 'prior_cleanup_sha256': 'c' * 64,
            'write_connection_id': None, 'observer_connection_id': None, 'before': None, 'ownership': None,
            'after': None, 'transaction': {}, 'state': 'committed', 'issues': [],
            'target_validation': 'not_run', 'row_parity': 'not_run', 'product_acceptance': 'pending', **override}
    body.pop('cleanup_sha256', None)
    body['cleanup_sha256'] = digest(body)
    return body


def rewrite_arm(store, report, index, **changes):
    """Synthetic consistent manifest: arm receipt and manifest re-captured together."""
    manifest = store.get(report['manifest_capture'], kind='variant_manifest')
    arm = {k: v for k, v in manifest['results'][index].items() if k != 'receipt_capture'}
    arm.update(changes)
    arm['receipt_capture'] = store.put('arm_receipt', arm)
    manifest['results'][index] = arm
    return manifest, store.put('variant_manifest', manifest)


class Fixture:
    def __init__(self, directory):
        self.root = Path(directory)
        (self.root / 'captures').mkdir()
        self.store = CaptureStore(self.root / 'captures')
        self.registry = EditionRegistry(self.root / 'edition-journal.sqlite', self.store)
        self.case = case()
        self.report = run_variant(self.case, fake_ports(), self.store)
        self.ref = self.report['manifest_capture']
        self.manifest = self.store.get(self.ref, kind='variant_manifest')

    def plan(self, **override):
        args = dict(cases=[self.case], manifest_refs=[self.ref], configuration=configuration(self.manifest),
                    registry=self.registry, visibility='public')
        args.update(override)
        return A.plan_archive(self.store, **args)

    def export(self, plan, name='packet.zip'):
        destination = self.root / name
        receipt = A.export_archive(plan, destination, signed_release=signed_release(plan), verifier=verifier())
        return destination, receipt


class PortableArchive(unittest.TestCase):
    def test_public_roundtrip_preserves_failed_arm_and_never_reruns(self):
        """what_bug_this_catches: replay retries a failed arm, drops its denominator or claims a fresh run."""
        calls = []
        with TemporaryDirectory() as directory:
            f = Fixture(directory)
            f.report = run_variant(f.case, fake_ports(provider=lambda request: calls.append(request) or {'output': None}), f.store)
            f.ref = f.report['manifest_capture']; f.manifest = f.store.get(f.ref, kind='variant_manifest')
            calls.clear()
            plan = f.plan()
            self.assertIsNone(plan.release_payload['nonce'])
            path, exported = f.export(plan)
            self.assertEqual(exported['archive_sha256'], plan.manifest['archive_sha256'])
            self.assertFalse(exported['fresh_holdout'])
            (f.root / 'replay').mkdir()
            replay = A.replay_portable_archive(path, expected_archive_sha256=exported['archive_sha256'],
                                               verifier=verifier(), result_store=CaptureStore(f.root / 'replay'))
            self.assertEqual(calls, [])
            self.assertEqual(replay['label'], 'rescored-with-version')
            arms = {arm['method']: arm for arm in replay['results'][0]['original_arms']}
            self.assertEqual(arms['B1']['status'], 'failed')
            self.assertEqual(len(replay['results'][0]['results']), 5)
            self.assertFalse(replay['stochastic_model_rerun'])
            self.assertEqual(replay['target_validation'], 'not_run')

    def test_hidden_payload_reachable_through_public_root_refused(self):
        """what_bug_this_catches: a public root releases heldout data through a history/arm edge."""
        with TemporaryDirectory() as directory:
            f = Fixture(directory)
            hidden = dict(f.manifest, split='heldout', variant_id='heldout-00')
            hidden_ref = f.store.put('variant_manifest', hidden)
            arm = f.manifest['results'][0]
            _, leaking = rewrite_arm(f.store, f.report, 0, captures=list(arm['captures']) + [hidden_ref])
            with self.assertRaisesRegex(ValueError, 'hidden historical payload'):
                f.plan(manifest_refs=[leaking])

    def test_transitive_variant_requires_its_exact_case(self):
        """what_bug_this_catches: a reached prior manifest is archived without its source/oracle case."""
        with TemporaryDirectory() as directory:
            f = Fixture(directory)
            other = dict(f.manifest, variant_id='other-public')
            other_ref = f.store.put('variant_manifest', other)
            arm = f.manifest['results'][0]
            _, root = rewrite_arm(f.store, f.report, 0, captures=list(arm['captures']) + [other_ref])
            with self.assertRaisesRegex(ValueError, 'lacks its exact archived'):
                f.plan(manifest_refs=[root])
            with self.assertRaisesRegex(ValueError, 'transitive variant closure'):
                f.plan(cases=[f.case, replace(f.case, variant_id='unreached')])

    def test_retired_label_requires_actual_registry_disposition(self):
        """what_bug_this_catches: a caller-chosen 'retired' label releases data the registry never retired."""
        with TemporaryDirectory() as directory:
            f = Fixture(directory)
            with self.assertRaisesRegex(ValueError, 'irreversible registry disposition'):
                f.plan(visibility='retired')
            with self.assertRaisesRegex(ValueError, 'active hidden raw archive'):
                f.plan(visibility='active')

    def test_secret_class_and_unapproved_auxiliary_refused(self):
        """what_bug_this_catches: credentials or scored cleanup facts ride along in configuration."""
        with TemporaryDirectory() as directory:
            f = Fixture(directory)
            with self.assertRaisesRegex(ValueError, 'secret'):
                f.plan(configuration=configuration(f.manifest, {'provider': {'api_key': 'x'}}))
            not_neutral = f.store.put('target_cleanup_observation', cleanup_receipt(target_validation='passed'))
            with self.assertRaisesRegex(ValueError, 'neutral'):
                f.plan(configuration=configuration(f.manifest, {'auxiliary_captures': [not_neutral]}))
            with self.assertRaisesRegex(ValueError, 'neutral cleanup evidence only'):
                f.plan(configuration=configuration(f.manifest, {'auxiliary_captures': [f.ref]}))
            # An unmarked heldout-derived capture smuggled in as a free configuration ref.
            smuggled = f.store.put('provider_request', {'prompt': 'heldout-derived text'})
            with self.assertRaisesRegex(ValueError, 'only through auxiliary_captures'):
                f.plan(configuration=configuration(f.manifest, {'note': smuggled}))

    def test_registry_folds_nonempty_history_without_t3_module_installed(self):
        """what_bug_this_catches: the lazy T3 hook import breaks every non-T3 registry fold."""
        from custody_support import synthetic_context
        with TemporaryDirectory() as directory:
            store = CaptureStore(directory)
            context, probe = synthetic_context(directory, store)
            state = context.registry.state(probe.edition)
            self.assertIsNotNone(state['commitment'])
            self.assertIsNotNone(state['freeze'])
            self.assertIsNone(state['t3'])
            snapshot = context.registry.snapshot()
            self.assertEqual(snapshot['head'], snapshot['events'][-1]['event_sha256'])

    def test_unmarked_children_of_hidden_capture_never_ship(self):
        """what_bug_this_catches: raw provider requests under a heldout receipt lack markers and leak."""
        with TemporaryDirectory() as directory:
            f = Fixture(directory)
            request = f.store.put('provider_request', {'prompt': 'heldout-derived text'})
            hidden_arm = dict({k: v for k, v in f.manifest['results'][0].items() if k != 'receipt_capture'},
                              split='heldout', variant_id='hand-layout', captures=[request])
            hidden_ref = f.store.put('arm_receipt', hidden_arm)
            arm = f.manifest['results'][0]
            _, root = rewrite_arm(f.store, f.report, 0, captures=list(arm['captures']) + [hidden_ref])
            with self.assertRaisesRegex(ValueError, 'hidden historical payload'):
                f.plan(manifest_refs=[root])

    def test_neutral_cleanup_auxiliary_is_archived_but_never_scored(self):
        """what_bug_this_catches: cleanup evidence is graded as a rollback/negative probe."""
        with TemporaryDirectory() as directory:
            f = Fixture(directory)
            aux = f.store.put('target_cleanup_observation', cleanup_receipt())
            plan = f.plan(configuration=configuration(f.manifest, {'auxiliary_captures': [aux]}))
            self.assertEqual(plan.manifest['auxiliary'], [aux])
            path, exported = f.export(plan)
            (f.root / 'replay').mkdir()
            replay = A.replay_portable_archive(path, expected_archive_sha256=exported['archive_sha256'],
                                               verifier=verifier(), result_store=CaptureStore(f.root / 'replay'))
            self.assertEqual(replay['auxiliary_count'], 1)
            self.assertEqual(len(replay['results']), 1)

    def test_wrong_pin_signature_and_release_scope_refused(self):
        """what_bug_this_catches: any archive with a valid-looking ZIP is trusted without the external pin/approval."""
        with TemporaryDirectory() as directory:
            f = Fixture(directory)
            plan = f.plan()
            path, exported = f.export(plan)
            with self.assertRaisesRegex(ValueError, 'external archive identity'):
                A.read_archive(path, expected_archive_sha256='b' * 64, verifier=verifier())
            with self.assertRaises(ValueError):
                A.export_archive(plan, f.root / 'narrow.zip', verifier=verifier(),
                                 signed_release=signed_release(plan, allowed_kinds=['variant_manifest']))
            with self.assertRaises(ValueError):
                A.export_archive(plan, f.root / 'expired.zip', verifier=verifier(), signed_release=signed_release(plan, minutes=-1))
            with self.assertRaises(FileExistsError):
                A.export_archive(plan, path, signed_release=signed_release(plan), verifier=verifier())

    def test_tampered_noncanonical_and_partial_packets_refused(self):
        """what_bug_this_catches: appended/prepended data, compression, reordering or truncation is accepted."""
        with TemporaryDirectory() as directory:
            f = Fixture(directory)
            path, exported = f.export(f.plan())
            raw = path.read_bytes()
            pin = exported['archive_sha256']
            def refused(name, data):
                target = f.root / name; target.write_bytes(data)
                with self.assertRaises(ValueError):
                    A.read_archive(target, expected_archive_sha256=pin, verifier=verifier())
            refused('appended.zip', raw + b'trailing')
            refused('prepended.zip', b'PK\x03\x04junk' + raw)
            refused('partial.zip', raw[:len(raw) // 2])
            with zipfile.ZipFile(path) as source:
                entries = [(info.filename, source.read(info)) for info in source.infolist()]
            for label, order, compression in (('reordered.zip', list(reversed(entries)), zipfile.ZIP_STORED),
                                              ('deflated.zip', entries, zipfile.ZIP_DEFLATED)):
                buffer = io.BytesIO()
                with zipfile.ZipFile(buffer, 'w', compression=compression) as packet:
                    for name, data in order:
                        info = A._zip_info(name); info.compress_type = compression
                        packet.writestr(info, data)
                refused(label, buffer.getvalue())
            # Canonical order kept, so the inventory check (not member order) must fire.
            extra = sorted(entries[2:] + [('captures/unlisted.json', b'{}')])
            buffer = io.BytesIO()
            with zipfile.ZipFile(buffer, 'w') as packet:
                for name, data in entries[:2] + extra:
                    packet.writestr(A._zip_info(name), data)
            target = f.root / 'unlisted.zip'; target.write_bytes(buffer.getvalue())
            with self.assertRaisesRegex(ValueError, 'unlisted'):
                A.read_archive(target, expected_archive_sha256=pin, verifier=verifier())

    def test_member_paths_refuse_traversal_and_drive_names(self):
        """what_bug_this_catches: a member name escapes the archive namespace on extraction-like use."""
        for name in ('../x.json', '/abs.json', 'C:/x.json', 'a\\b.json', 'captures//x.json', 'captures/./x.json'):
            with self.assertRaises(ValueError):
                A._path(name)

    def test_unsupported_scorer_is_reported_not_imported(self):
        """what_bug_this_catches: an unknown scorer version is silently rescored or loaded from archived code."""
        with TemporaryDirectory() as directory:
            f = Fixture(directory)
            path, exported = f.export(f.plan())
            (f.root / 'replay').mkdir()
            replay = A.replay_portable_archive(path, expected_archive_sha256=exported['archive_sha256'], verifier=verifier(),
                                               result_store=CaptureStore(f.root / 'replay'), scorer_version='semantic-v9')
            self.assertEqual(replay['compatibility'], 'unsupported_scorer')
            self.assertIsNone(replay['results'])
            self.assertEqual(replay['label'], 'not_rescored_unsupported_scorer')

    def test_projection_refuses_stale_or_empty_head(self):
        """what_bug_this_catches: projection head and state are read from different registry moments."""
        with TemporaryDirectory() as directory:
            f = Fixture(directory)
            with self.assertRaisesRegex(ValueError, 'stale projection registry head'):
                A.approved_projection(f.store, f.ref, signed_approval={}, verifier=verifier(), registry=f.registry,
                                      expected_edition=f.case.edition, expected_registry_head='c' * 64)


if __name__ == '__main__':
    unittest.main()

"""Captured-prompt hidden-identifier scan regression SOURCE.

Future unit source only: authored under Dirty Mode, never collected or run there.
Synthetic fixtures and test-only keys; no hidden corpus, provider or OS probe.
"""
from dataclasses import replace
from tempfile import TemporaryDirectory
import unittest

from evaluator_support import case, fake_ports
from custody_support import sign, synthetic_context
from evaluation import leak_scan as L
from evaluation.artifacts import CaptureStore, digest
from evaluation.runner import run_variant

HOST, IDENTITY, WHEN = 'synthetic-host', 'synthetic-inference-principal', '2026-01-01T00:00:00Z'


def request(store, text):
    """Synthetic gateway-shaped provider_request capture whose prompt carries `text`."""
    prompt = {'purpose': 'single_pass_full_mapping', 'input': {'brief': text}}
    return store.put('provider_request', {'mode': 'live', 'method': 'B1', 'attempt': 1, 'prompt': prompt,
                                          'prompt_sha256': digest(prompt)})


def heldout(context):
    return next(v for v in context.commitment['variants'] if v['variant_id'] == 'heldout-00')


class LeakScan(unittest.TestCase):
    def setUp(self):
        self.directory = TemporaryDirectory()
        self.store = CaptureStore(self.directory.name)
        self.context, self.probe = synthetic_context(self.directory.name, self.store)

    def tearDown(self):
        self.directory.cleanup()

    def record(self, refs, **kw):
        return L.record_leak_scan(self.store, commitment=self.context.commitment, freeze=self.context.freeze,
                                  request_refs=refs, host=HOST, identity=IDENTITY, observed_at=WHEN, **kw)

    def with_allowlist_review(self, isolation_ref):
        """Replace the prompt_allowlist review with one citing the given scan capture."""
        reviews = []
        for signed in self.context.review_receipts:
            payload = signed['payload']
            if payload['kind'] == 'prompt_allowlist':
                signed = sign({**payload, 'capture_sha256': isolation_ref['sha256']}, 'reviewer')
                self.store.put('signed_evidence', signed)
            reviews.append(signed)
        return replace(self.context, review_receipts=reviews)

    def test_honest_gateway_requests_are_clean_and_satisfy_eligibility(self):
        """what_bug_this_catches: visible-input hashes in permitted prompts are flagged as leaks."""
        report = run_variant(case(), fake_ports(), self.store)
        refs = L.requests_from_arm_receipts(self.store, [arm['receipt_capture'] for arm in report['results']])
        self.assertTrue(refs)
        result = self.record(refs, cases=[self.probe])
        self.assertTrue(result['clean'])
        self.assertEqual(result['hit_count'], 0)
        L.assert_clean(self.store, result['leak_scan'])
        self.with_allowlist_review(result['isolation_capture']).validate()

    def test_hidden_oracle_hash_in_prompt_refuses_eligibility(self):
        """what_bug_this_catches: a prompt carrying a heldout oracle commitment still passes custody."""
        leaked = request(self.store, 'context ' + heldout(self.context)['oracle_sha256'])
        result = self.record([leaked])
        self.assertFalse(result['clean'])
        report = self.store.get(result['leak_scan'], kind='leak_scan')
        self.assertEqual(report['hits'][0]['category'], 'oracle_sha256')
        self.assertNotIn(heldout(self.context)['oracle_sha256'], str(report['hits']))
        captured = self.store.get(result['isolation_capture'], kind='isolation_capture')
        self.assertEqual(captured['observations'][0]['observed_value'], L.DIRTY)
        with self.assertRaisesRegex(ValueError, 'isolation effect remains unverified'):
            self.with_allowlist_review(result['isolation_capture']).validate()
        with self.assertRaisesRegex(ValueError, 'results ineligible'):
            L.assert_clean(self.store, result['leak_scan'])

    def test_truncated_or_uppercase_fingerprint_is_still_a_hit(self):
        """what_bug_this_catches: a leaked hash survives by truncation or case change."""
        fragment = heldout(self.context)['canonical_sha256'][:20].upper()
        result = self.record([request(self.store, 'x' + fragment + 'y')])
        report = self.store.get(result['leak_scan'], kind='leak_scan')
        self.assertFalse(result['clean'])
        self.assertEqual(report['hits'][0]['match'], 'substring')

    def test_canonical_row_fingerprint_from_held_cases(self):
        """what_bug_this_catches: per-row gold fingerprints are not part of the hidden set."""
        row = self.probe.batches[0].oracle[0]
        refs = [request(self.store, digest(row['fields']))]
        self.assertTrue(self.record(refs)['clean'])  # Without cases only T0 hashes are known.
        self.assertFalse(self.record(refs, cases=[self.probe])['clean'])

    def test_heldout_variant_id_uses_token_boundaries(self):
        """what_bug_this_catches: hidden variant IDs leak verbatim, or substrings of other words false-positive."""
        for leaked in ('see heldout-00 now', 'end heldout-00.', 'id=heldout-00-batch1', 'HELDOUT-00', '_heldout-00_'):
            self.assertFalse(self.record([request(self.store, leaked)])['clean'], leaked)
        for innocent in ('see xheldout-00x now', 'heldout-007 is not declared'):
            self.assertTrue(self.record([request(self.store, innocent)])['clean'], innocent)

    def test_fragment_from_any_offset_hits_but_generic_hashes_do_not(self):
        """what_bug_this_catches: a hash suffix/middle slice leaks, or digest([]) layouts false-positive."""
        sha = heldout(self.context)['oracle_sha256']
        for fragment in (sha[-20:], sha[8:40]):
            report = self.store.get(self.record([request(self.store, 'g' + fragment + 'g')])['leak_scan'], kind='leak_scan')
            self.assertEqual(report['result'], L.DIRTY)
            self.assertEqual(report['hits'][0]['match'], 'substring')
        # The probe case has expected_layout [] -> layout_sha256 == digest([]), a generic value.
        self.assertEqual(heldout(self.context)['layout_sha256'], digest([]))
        self.assertTrue(self.record([request(self.store, digest([]))])['clean'])

    def test_bounded_inputs_and_wrong_cases_refuse(self):
        """what_bug_this_catches: empty/unbounded/non-request scans or forged cases produce clean evidence."""
        with self.assertRaises(ValueError):
            self.record([])
        report = run_variant(case(), fake_ports(), self.store)
        with self.assertRaises(ValueError):
            self.record([report['manifest_capture']])
        with self.assertRaisesRegex(ValueError, 'differs from T0'):
            self.record([request(self.store, 'x')], cases=[replace(self.probe, batches=self.probe.batches[:0])])

    def manifests_with_request(self, request_ref):
        """Synthetic manifest whose single arm receipt reaches one gateway request."""
        raw = self.store.put('arm_raw', {'attempts': [{'request_capture': request_ref}]})
        receipt = self.store.put('arm_receipt', {'captures': [raw]})
        return [{'results': [{'receipt_capture': receipt}]}]

    def test_t3_post_attempt_check_clean_on_honest_prompts(self):
        """what_bug_this_catches: the G1b post-check refuses an honest T3 attempt."""
        from evaluation.runner import _t3_leak_check
        report = run_variant(case(), fake_ports(), self.store)
        check = _t3_leak_check([report], self.store, self.context, [self.probe])
        self.assertEqual(check['status'], 'clean')
        L.assert_clean(self.store, {'sha256': check['leak_scan_sha256'], 'kind': 'leak_scan'})
        # Plain SHA citation: archive closure over the suite report never meets a 'leak_scan' ref.
        from evaluation.archive import _references
        self.assertEqual(list(_references(check)), [])

    def test_t3_post_attempt_hit_is_refused_and_keeps_evidence(self):
        """what_bug_this_catches: a real T3 prompt leaking a hidden hash is still recorded completed/reportable."""
        from evaluation.runner import _t3_leak_check
        leaked = request(self.store, heldout(self.context)['canonical_sha256'])
        check = _t3_leak_check(self.manifests_with_request(leaked), self.store, self.context, [self.probe])
        self.assertEqual(check['status'], 'refused')
        self.assertGreater(check['hit_count'], 0)
        self.assertEqual(self.store.get({'sha256': check['leak_scan_sha256']}, kind='leak_scan')['result'], L.DIRTY)

    def test_t3_post_attempt_missing_capture_is_indeterminate(self):
        """what_bug_this_catches: an unscannable attempt (missing request capture) passes as clean."""
        from evaluation.runner import _t3_leak_check
        missing = {'sha256': 'e' * 64, 'kind': 'provider_request', 'bytes': 10}
        check = _t3_leak_check(self.manifests_with_request(missing), self.store, self.context, [self.probe])
        self.assertEqual(check['status'], 'indeterminate')
        self.assertIsNone(check['leak_scan_sha256'])
        self.assertEqual(_t3_leak_check([], self.store, self.context, [self.probe])['status'], 'indeterminate')

    def test_attempt_scope_requires_a_terminal_attempt(self):
        """what_bug_this_catches: a running/absent attempt is certified from partial captures."""
        with self.assertRaisesRegex(ValueError, 'terminal recorded attempt'):
            L.attempt_request_refs(self.store, self.context.registry, self.probe.edition)


if __name__ == '__main__':
    unittest.main()

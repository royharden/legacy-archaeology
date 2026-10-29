"""Future append-only/CAS edition regression SOURCE; no registry opened here."""
from copy import deepcopy
from dataclasses import replace
from tempfile import TemporaryDirectory
import unittest

from custody_support import synthetic_context, sign
from evaluation.artifacts import CaptureStore, digest
from evaluation.eligibility import make_commitment, make_freeze


class EditionAttempts(unittest.TestCase):
    def test_exact_retry_is_historical_receipt_not_second_execution(self):
        """what_bug_this_catches: idempotent begin restarts an already consumed edition."""
        with TemporaryDirectory() as directory:
            context, candidate = synthetic_context(directory, CaptureStore(directory))
            first = context.begin(request_id='begin', expected_head=context.registry.head)
            self.assertTrue(first.newly_created)
            again = context.begin(request_id='begin', expected_head=None)
            self.assertFalse(again.newly_created)
            self.assertEqual(first.event, again.event)
            context.authorize_case(candidate, context.freeze['pins'], context.registry.store, 'mock')
            capture = context.registry.store.put('suite_failure', {'status': 'no_output', 'attempt': 'synthetic'})
            context.registry.finish(candidate.edition, context.suite['attempt_id'], 'no_output', capture,
                request_id='finish', expected_head=context.registry.head)
            with self.assertRaises(ValueError):
                context.authorize_case(candidate, context.freeze['pins'], context.registry.store, 'mock')
            with self.assertRaises(ValueError):
                context.begin(request_id='begin-again', expected_head=context.registry.head)
            self.assertEqual(context.registry.state(candidate.edition)['attempt']['status'], 'no_output')

    def test_cas_and_request_content_collisions_do_not_write(self):
        """what_bug_this_catches: concurrent/stale registry mutation silently wins."""
        with TemporaryDirectory() as directory:
            context, _ = synthetic_context(directory, CaptureStore(directory))
            before = context.registry.events()
            with self.assertRaises(ValueError):
                context.begin(request_id='stale-begin', expected_head=None)
            self.assertEqual(context.registry.events(), before)
            different = make_freeze(context.commitment, {**context.freeze['pins'], 'config_sha256': digest('different')})
            with self.assertRaises(ValueError):
                context.registry.freeze(different, request_id='freeze', expected_head=context.registry.head)
            self.assertEqual(context.registry.events(), before)

    def test_mixed_pins_or_changed_sample_oracle_never_authorize(self):
        """what_bug_this_catches: frozen release runs with changed prompt/sample/gold."""
        with TemporaryDirectory() as directory:
            context, candidate = synthetic_context(directory, CaptureStore(directory))
            context.begin(request_id='begin', expected_head=context.registry.head)
            pins = {**context.freeze['pins'], 'prompt_sha256': digest('other prompt')}
            with self.assertRaises(ValueError):
                context.authorize_case(candidate, pins, context.registry.store, 'mock')
            altered = deepcopy(candidate.visible); altered['brief'] = 'changed brief'
            with self.assertRaises(ValueError):
                context.authorize_case(replace(candidate, visible=altered), context.freeze['pins'], context.registry.store, 'mock')

    def test_duplicate_arm_and_incomplete_completed_suite_refuse(self):
        """what_bug_this_catches: a unique suite attempt hides repeated individual arms."""
        with TemporaryDirectory() as directory:
            context, candidate = synthetic_context(directory, CaptureStore(directory))
            context.begin(request_id='begin', expected_head=context.registry.head)
            context.claim_arm(candidate.variant_id, 'B1')
            with self.assertRaises(ValueError):
                context.claim_arm(candidate.variant_id, 'B1')
            captured = context.registry.store.put('arm_receipt', {'status': 'failed', 'request_attempts': 1})
            context.finish_arm(candidate.variant_id, 'B1', 'failed', captured)
            with self.assertRaises(ValueError):
                context.registry.finish(candidate.edition, context.suite['attempt_id'], 'completed', captured,
                    request_id='false-completion', expected_head=context.registry.head)
            context.registry.finish(candidate.edition, context.suite['attempt_id'], 'partial', captured,
                request_id='partial', expected_head=context.registry.head)
            self.assertEqual(context.registry.state(candidate.edition)['attempt']['status'], 'partial')

    def test_exposure_retirement_and_retagged_gold_never_become_unseen(self):
        """what_bug_this_catches: failure/retirement is erased by new edition labels."""
        with TemporaryDirectory() as directory:
            context, candidate = synthetic_context(directory, CaptureStore(directory))
            for kind in ('exposed', 'retired'):
                head = context.registry.head
                authority = sign({'schema_version': 1, 'action': kind, 'edition': candidate.edition,
                                  'reason': 'synthetic disclosure', 'registry_head': head})
                context.registry.disposition(candidate.edition, kind, authority, verifier=context.verifier,
                    request_id=kind, expected_head=head)
            with self.assertRaises(ValueError):
                context.validate()
            retagged = make_commitment(edition='new-name-same-gold', variants=context.commitment['variants'],
                sealed_assets_sha256=digest('different seal label'), nonce=digest('different nonce'))
            with self.assertRaises(ValueError):
                context.registry.register(retagged, request_id='retag', expected_head=context.registry.head)
            # Exports rebuild solely from committed authority, never imported JSONL.
            refs = context.registry.export()
            self.assertEqual(len(refs), len(context.registry.events()))
            self.assertTrue(context.registry.state(candidate.edition)['retired'])


if __name__ == '__main__':
    unittest.main()

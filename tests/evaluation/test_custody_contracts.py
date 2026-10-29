"""Future closed-custody regression SOURCE; no OS probes or test execution here."""
from copy import deepcopy
from tempfile import TemporaryDirectory
import unittest

from custody_support import synthetic_context, sign
from evaluation.artifacts import CaptureStore, digest
from evaluation.benchmark import hidden_run_eligibility
from evaluation.eligibility import ReceiptVerifier, validate_commitment, validate_custody, validate_freeze


class CustodyContracts(unittest.TestCase):
    def test_boolean_verifier_callback_is_not_a_crypto_backend(self):
        """what_bug_this_catches: always-true injected verifier bypasses custody receipts."""
        with self.assertRaises(ValueError):
            ReceiptVerifier({'owner': ('owner', 'run_owner')}, lambda *args: True)

    def test_legacy_all_true_json_is_structural_only(self):
        """what_bug_this_catches: caller booleans become demonstrated OS custody."""
        flags = {name: True for name in ('separate_os_identity', 'absolute_read_denied', 'relative_read_denied',
            'list_denied', 'no_inherited_handles', 'no_oracle_broker', 'inference_distribution_excludes_evaluator',
            'prompt_allowlist_verified', 'independent_review_verified')}
        flags['evidence_sha256'] = 'e' * 64
        result = hidden_run_eligibility(None, flags)
        self.assertFalse(result['eligible'])
        self.assertEqual(result['eligibility_level'], 'unverified_structural_only')

    def test_closed_t0_and_stale_freeze(self):
        """what_bug_this_catches: unknown fields, changing source or mixed release pins."""
        with TemporaryDirectory() as directory:
            context, _ = synthetic_context(directory, CaptureStore(directory))
            unknown = deepcopy(context.commitment); unknown['eligible'] = True
            with self.assertRaises(ValueError):
                validate_commitment(unknown)
            stale = deepcopy(context.freeze); stale['pins']['config_sha256'] = digest('changed config')
            with self.assertRaises(ValueError):
                validate_freeze(stale, context.commitment)
            missing = deepcopy(context.commitment); missing['variants'].pop()
            missing['commitment_sha256'] = digest({k: v for k, v in missing.items() if k != 'commitment_sha256'})
            with self.assertRaises(ValueError):
                validate_commitment(missing)

    def test_signed_capture_validation_and_scope_limit(self):
        """what_bug_this_catches: signature success alone claims this validator probed OS."""
        with TemporaryDirectory() as directory:
            context, _ = synthetic_context(directory, CaptureStore(directory))
            result = context.validate()
            self.assertEqual(result['eligibility_level'], 'verified_observation_receipts')
            self.assertIn('did not probe OS', result['limitation'])
            # These fixtures are synthetic unit records, never real custody.
            self.assertEqual(result['edition'], 'synthetic-contract-edition')

    def test_missing_accessible_wrong_identity_and_errno_bool(self):
        """what_bug_this_catches: missing paths/access success/stale account count as denial."""
        with TemporaryDirectory() as directory:
            context, _ = synthetic_context(directory, CaptureStore(directory))
            for mutation in ('missing', 'accessible', 'identity', 'errno_bool'):
                with self.subTest(mutation=mutation):
                    probe = deepcopy(context.probe_receipt['payload'])
                    if mutation == 'missing':
                        probe['probes'].pop()
                    elif mutation == 'accessible':
                        probe['probes'][0].update(result='accessible', errno=None, exception_type=None)
                    elif mutation == 'identity':
                        probe['identity'] = 'other-principal'
                    else:
                        probe['probes'][0]['errno'] = True
                    probe['observation_sha256'] = digest({k: v for k, v in probe.items() if k != 'observation_sha256'})
                    with self.assertRaises(ValueError):
                        validate_custody(sign(probe, 'observer'), context.review_receipts,
                            commitment=context.commitment, freeze=context.freeze, verifier=context.verifier,
                            expected_identity='synthetic-inference-principal', expected_host='synthetic-host',
                            collector_sha256=context.probe_receipt['payload']['collector_sha256'])

    def test_tampered_signature_and_missing_effect_capture(self):
        """what_bug_this_catches: self-pinned prose/hash replaces actual captured effect."""
        with TemporaryDirectory() as directory:
            context, _ = synthetic_context(directory, CaptureStore(directory))
            forged = deepcopy(context.probe_receipt); forged['signature'] = '0' * 64
            with self.assertRaises(ValueError):
                context.verifier.verify(forged, 'canary_observer')
            # Correctly signed but references a nonexistent raw effect capture.
            bad_review = deepcopy(context.review_receipts[0]['payload'])
            bad_review['capture_sha256'] = digest('absent raw capture')
            from dataclasses import replace
            reviews = [sign(bad_review, 'reviewer'), *context.review_receipts[1:]]
            context.registry.store.put('signed_evidence', reviews[0])
            with self.assertRaises((ValueError, FileNotFoundError)):
                replace(context, review_receipts=reviews).validate()


if __name__ == '__main__':
    unittest.main()

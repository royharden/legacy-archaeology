"""T1 authority/budget regression SOURCE; no provider/crypto/SQLite runs now."""
from copy import deepcopy
from dataclasses import replace
from decimal import Decimal
from tempfile import TemporaryDirectory
import unittest

from evaluator_support import case, fake_ports
from custody_support import sign
from public_live_support import public_context, gateway, resign
from evaluation.artifacts import digest
from evaluation.benchmark import SPLITS
from evaluation.eligibility import make_commitment, make_freeze, variant_identity
from evaluation.public_live import make_public_catalog
from evaluation.runner import run_variant


class PublicLiveAuthority(unittest.TestCase):
    def test_pre_t2_public_allowed_but_hidden_never_inherits_authority(self):
        """what_bug_this_catches: T1 requires T2 cyclically or silently grants hidden access."""
        with TemporaryDirectory() as directory:
            context, candidate = public_context(directory)
            context.begin(request_id='begin', expected_head=context.registry.head)
            context.authorize_case(candidate, context.pins, context.registry.store, 'live')
            self.assertIsNone(context.registry.state(candidate.edition)['freeze'])
            self.assertTrue(context.registry.state(candidate.edition)['exposed'])
            with self.assertRaises(ValueError):
                run_variant(replace(candidate, split='heldout'), fake_ports(), context.registry.store,
                            mode='live', pins=context.pins, eligibility=context)
            with self.assertRaises(ValueError):
                make_public_catalog([replace(candidate, split='heldout')], nonce='a' * 64)

    def test_usage_cost_matches_actual_pinned_billing_receipt(self):
        """what_bug_this_catches: evaluator invents a competing pricing/usage truth."""
        with TemporaryDirectory() as directory:
            context, candidate = public_context(directory)
            context.begin(request_id='begin', expected_head=context.registry.head)
            request = gateway(context, candidate)
            request.request('single_pass_full_mapping')
            self.assertEqual(Decimal(request.attempts[0]['known_cost']), Decimal('0.00009'))
            self.assertEqual(request.attempts[0]['cost_status'], 'known')
            with self.assertRaises(ValueError): request.request('repair')

    def test_cached_reasoning_raw_usage_preserved_and_false_zero_unknown(self):
        """what_bug_this_catches: cached input charged full rate or reasoning charged twice."""
        for change in ('cached', 'unsupported', 'false_zero'):
            with self.subTest(change=change), TemporaryDirectory() as directory:
                context, candidate = public_context(directory)
                context.begin(request_id='begin', expected_head=context.registry.head)
                def transform(reply):
                    if change == 'cached':
                        reply['usage']['input_tokens_details']['cached_tokens'] = 40
                        reply['known_cost'] = reply['provider_receipt']['cost_usd'] = '0.00006'
                    elif change == 'unsupported': reply['usage']['audio_tokens'] = 1
                    else: reply['known_cost'] = '0'
                    receipt = reply['provider_receipt']; receipt['raw_usage'] = deepcopy(reply['usage'])
                    receipt['receipt_sha256'] = digest({k: v for k, v in receipt.items() if k != 'receipt_sha256'})
                    return reply
                request = gateway(context, candidate, transform_reply=transform)
                if change == 'cached':
                    request.request('one-shot')
                    self.assertEqual(request.attempts[0]['known_cost'], '0.00006')
                    self.assertEqual(request.attempts[0]['usage']['input_tokens_details']['cached_tokens'], 40)
                    self.assertEqual(request.attempts[0]['usage']['output_tokens_details']['reasoning_tokens'], 5)
                else:
                    with self.assertRaises(ValueError): request.request('one-shot')
                    self.assertEqual(request.attempts[0]['cost_status'], 'unknown')
                    self.assertIsNone(request.attempts[0]['known_cost'])
                    if change == 'unsupported': self.assertEqual(request.attempts[0]['usage']['audio_tokens'], 1)

    def test_cap_refuses_before_provider_and_timeout_keeps_unknown(self):
        """what_bug_this_catches: unreserved calls or timeout liability silently retried."""
        calls = []
        def timeout(request): calls.append(request); raise TimeoutError('synthetic')
        with TemporaryDirectory() as directory:
            context, candidate = public_context(directory, total_usd='0.001')
            context.begin(request_id='begin', expected_head=context.registry.head)
            request = gateway(context, candidate, provider=timeout)
            with self.assertRaises(ValueError): request.request('one-shot')
            self.assertEqual(calls, [])
        with TemporaryDirectory() as directory:
            context, candidate = public_context(directory)
            context.begin(request_id='begin', expected_head=context.registry.head)
            request = gateway(context, candidate, provider=timeout)
            with self.assertRaises(TimeoutError): request.request('one-shot')
            other = gateway(context, candidate, method='R1', provider=timeout)
            with self.assertRaises(ValueError): other.request('rank')
            attempt = context.registry.state(candidate.edition)['t1']['attempts'][context.suite['attempt_id']]
            self.assertEqual(len(calls), 1)
            self.assertTrue(any(call['status'] == 'unknown' and call['known_cost'] is None for call in attempt['calls'].values()))

    def test_mode_price_stale_pins_and_expiry_fail_closed(self):
        """what_bug_this_catches: an owner signature on different scope is reused as permission."""
        with TemporaryDirectory() as directory:
            context, candidate = public_context(directory)
            original = context.authority_receipt['payload']
            for change in ('mode', 'price', 'expiry'):
                payload = deepcopy(original)
                if change == 'mode': payload['mode'] = 'mock'
                elif change == 'price':
                    payload['price']['as_of_date'] = '2000-01-01'
                    payload['price']['price_sha256'] = digest({k: v for k, v in payload['price'].items() if k != 'price_sha256'})
                    payload['pins']['price_sha256'] = payload['price']['price_sha256']
                else: payload['not_after_utc'] = '2000-01-01T00:00:00Z'
                with self.subTest(change=change), self.assertRaises(ValueError):
                    resign(context, payload).validate()
            context.begin(request_id='begin', expected_head=context.registry.head)
            with self.assertRaises(ValueError):
                context.authorize_case(candidate, {**context.pins, 'config_sha256': 'e' * 64}, context.registry.store, 'live')
            altered = deepcopy(original); altered['caps']['total_usd'] = '100'
            with self.assertRaises(ValueError): resign(context, altered).validate()

    def test_attempt_replay_and_unlinked_selection_cannot_freeze_hidden(self):
        """what_bug_this_catches: exact retry or exposed public trial becomes hidden authority."""
        with TemporaryDirectory() as directory:
            context, candidate = public_context(directory)
            first = context.begin(request_id='begin', expected_head=context.registry.head)
            again = context.begin(request_id='begin', expected_head=None)
            self.assertTrue(first.newly_created); self.assertFalse(again.newly_created)
            with self.assertRaises(ValueError): context.begin(request_id='second', expected_head=context.registry.head)
            self.assertIsNone(context.catalog['corpus_commitment_sha256'])

    def test_unknown_liability_requires_captured_signed_reconciliation(self):
        """what_bug_this_catches: unknown cost is freed by a retry/zero flag or new edition."""
        with TemporaryDirectory() as directory:
            context, candidate = public_context(directory)
            context.begin(request_id='begin', expected_head=context.registry.head)
            def timeout(request): raise TimeoutError('synthetic')
            request = gateway(context, candidate, provider=timeout)
            with self.assertRaises(TimeoutError): request.request('one-shot')
            attempt = context.registry.state(candidate.edition)['t1']['attempts'][context.suite['attempt_id']]
            call_id = next(iter(attempt['calls']))
            with self.assertRaises(ValueError): context.registry.assert_no_unknown_public_liability()
            bill = {'schema_version': 1, 'edition': candidate.edition, 'attempt_id': context.suite['attempt_id'],
                'call_id': call_id, 'provider': context.validate()['provider'], 'model': context.validate()['model'],
                'billed_usd': '0', 'usage': {}, 'observed_at': 'synthetic-billing-observation'}
            call = attempt['calls'][call_id]
            native = {'status': 'reconciled', 'cost_known': True, 'cost_usd': '0', 'raw_usage': {},
                'evaluation_phase': 'T1', 'evaluation_authority_sha256': context.validate()['authority_sha256'],
                'gateway_prompt_sha256': call['prompt_sha256'], 'source_sha256': candidate.visible['source_sha256'],
                'evaluator_method': 'B1', 'billing_evidence_sha256': digest('synthetic bill, no real account')}
            native['receipt_sha256'] = digest(native); bill['provider_receipt'] = native
            capture = context.registry.store.put('billing_observation', bill)
            action = {'schema_version': 1, 'action': 'reconcile_public_liability', 'edition': candidate.edition,
                'attempt_id': context.suite['attempt_id'], 'call_id': call_id,
                'scope_authority_sha256': context.validate()['authority_sha256'], 'billing_capture': capture}
            with self.assertRaises(ValueError): context.reconcile_liability({'authorized': True}, request_id='fake')
            context.reconcile_liability(sign(action), request_id='actual-signed-unit-fixture')
            context.registry.assert_no_unknown_public_liability()
            self.assertEqual(context.registry.state(candidate.edition)['t1']['attempts'][context.suite['attempt_id']]['calls'][call_id]['known_cost'], '0')

    def test_t1_selection_then_t2_freeze_stops_tuning(self):
        """what_bug_this_catches: active/post-T2 tuning or an unbound ranker selection."""
        from pathlib import Path
        from evaluation.artifacts import CaptureStore
        from evaluation.edition_registry import EditionRegistry
        candidate = case()
        variants = []
        for split, count in SPLITS.items():
            for index in range(count):
                variant = {name: digest([split, index, name]) for name in
                    ('source_sha256', 'samples_sha256', 'brief_sha256', 'oracle_sha256', 'canonical_sha256', 'layout_sha256', 'visible_sha256')}
                variants.append({'variant_id': f'{split}-{index}', 'split': split, **variant})
        variants[0] = variant_identity(candidate)
        t0 = make_commitment(edition='sealed-synthetic-family', variants=variants,
                             sealed_assets_sha256=digest('new synthetic seal'), nonce=digest('new T0 nonce'))
        with TemporaryDirectory() as directory:
            registry = EditionRegistry(Path(directory) / 'editions.sqlite', CaptureStore(directory))
            registry.register(t0, request_id='T0', expected_head=None)
            context, candidate = public_context(directory, registry=registry, candidate=candidate, t0=t0['commitment_sha256'])
            context.begin(request_id='begin', expected_head=registry.head)
            with self.assertRaises(ValueError):
                registry.freeze(make_freeze(t0, context.pins), request_id='too-early', expected_head=registry.head)
            request = gateway(context, candidate)
            request.request('single_pass_full_mapping')
            arm_capture = registry.store.put('arm_receipt', {'synthetic_unit_record': True})
            context.finish_arm(candidate.variant_id, 'B1', 'completed', arm_capture)
            for method in ('B0', 'C0', 'R0', 'R1'):
                context.claim_arm(candidate.variant_id, method)
                context.finish_arm(candidate.variant_id, method, 'completed', arm_capture)
            result = registry.store.put('suite_report', {'synthetic_unit_record': True, 'benchmark_status': 'not_run'})
            context.finish_suite('completed', result, request_id='finish')
            selection = sign({'schema_version': 1, 'action': 'select_public_configuration', 'edition': candidate.edition,
                'attempt_id': context.suite['attempt_id'], 'basis': 'cost', 'pins': context.pins,
                'rationale': 'Synthetic state-transition unit fixture only', 'result_capture': result})
            selected = context.select_configuration(selection, request_id='select')
            frozen = make_freeze(t0, context.pins, selection_sha256=selected.event['payload']['selection_sha256'])
            registry.freeze(frozen, request_id='T2', expected_head=registry.head)
            self.assertIsNone(registry.state(t0['edition'])['attempt'])  # T2 alone grants no T3 custody/attempt.
            with self.assertRaises(ValueError): context.validate()


class PublicUnsentVoid(unittest.TestCase):
    """Seam Amendment A1/A1.1 voids; attestation mirrors D7 CallLedger.fence_unsent (synthetic)."""

    def reserve_unsent(self, directory):
        context, candidate = public_context(directory)
        context.begin(request_id='begin', expected_head=context.registry.head)
        context.claim_arm(candidate.variant_id, 'B1')
        request = {'attempt': 1, 'prompt_sha256': digest('synthetic T1 gateway prompt')}
        call_id = context.meter(candidate, 'B1').reserve(request, 50)  # crash before transport
        return context, candidate, call_id

    def void(self, context, candidate, call_id, *, attempts=()):
        a = context.validate()
        query = {'evaluation_phase': 'T1', 'evaluation_authority_sha256': a['authority_sha256'],
                 'gateway_prompt_sha256': digest('synthetic T1 gateway prompt'),
                 'source_sha256': candidate.visible['source_sha256'], 'evaluator_method': 'B1'}
        fenced = not attempts  # D7 fence_unsent writes a tombstone only when nothing matched
        fence = ({'schema_version': 1, 'kind': 'unsent_fence', 'fence_id': call_id, **query, 'cost_known': True,
                  'cost_usd': '0', 'fenced_at': '2026-01-01T00:00:00Z'} if fenced else None)
        capture = {'schema_version': 1, 'kind': 'call_ledger_attestation', 'ledger_path_sha256': digest('synthetic ledger'),
                   'query': query, 'attempts': list(attempts), 'fenced': fenced, 'fence': fence,
                   'observed_at': '2026-01-01T00:00:00Z'}
        capture['attestation_sha256'] = digest(capture)
        ref = context.registry.store.put('call_ledger_attestation', capture)
        signed = sign({'schema_version': 1, 'action': 'void_unsent_live_reservation', 'phase': 'T1',
                       'edition': candidate.edition, 'attempt_id': a['attempt_id'], 'call_id': call_id,
                       'authority_sha256': a['authority_sha256'], 'ledger_path_sha256': digest('synthetic ledger'),
                       'ledger_capture': ref})
        return context.void_unsent_reservation(signed, request_id='void')

    def test_void_releases_cross_edition_liability_but_never_completes_b1(self):
        """what_bug_this_catches: an unsent reservation blocks all live trials, or a void fakes a B1 success."""
        with TemporaryDirectory() as directory:
            context, candidate, call_id = self.reserve_unsent(directory)
            with self.assertRaises(ValueError): context.registry.assert_no_unknown_public_liability()
            self.void(context, candidate, call_id)
            context.registry.assert_no_unknown_public_liability()
            call = context.registry.state(candidate.edition)['t1']['attempts'][context.suite['attempt_id']]['calls'][call_id]
            self.assertEqual((call['status'], call['known_cost'], call['voided']), ('known', '0', True))
            capture = context.registry.store.put('arm_receipt', {'synthetic_unit_record': True})
            with self.assertRaises(ValueError):
                context.finish_arm(candidate.variant_id, 'B1', 'completed', capture)

    def test_ledger_attempt_refuses_void(self):
        """what_bug_this_catches: a request that reached the provider ledger is voided to zero cost."""
        with TemporaryDirectory() as directory:
            context, candidate, call_id = self.reserve_unsent(directory)
            with self.assertRaises(ValueError):
                self.void(context, candidate, call_id, attempts=[{'status': 'unknown_liability'}])

if __name__ == '__main__': unittest.main()

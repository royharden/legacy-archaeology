"""Protected T3 live billing authority regression SOURCE; unexecuted in Dirty Mode.

Synthetic test-only keys/prices; no provider, real price, key or custody claim.
Requires the edition_registry t3_* fold dispatch (D4 hook) to pass.
"""
from copy import deepcopy
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from decimal import Decimal
from pathlib import Path
from tempfile import TemporaryDirectory
import hashlib
import unittest

import public_live_support
from custody_support import sign, verifier
from evaluator_support import case, fake_ports
from public_live_support import public_context, synthetic_pricing_port
from evaluation.artifacts import CaptureStore, digest
from evaluation.benchmark import ARMS, FREEZE_KEYS, SPLITS
from evaluation.edition_registry import EditionRegistry, EligibilityContext
from evaluation.eligibility import ISOLATION_KINDS, make_commitment, make_freeze, variant_identity
from evaluation.protected_live import (ProtectedLiveContext, T3OverrunError, require_protected_ports,
                                       validate_scope)
from evaluation.public_live import BillingAdapter
from evaluation.runner import RequestGateway

EDITION = 'synthetic-protected-edition'
USAGE = {'input_tokens': 50, 'output_tokens': 20, 'total_tokens': 70,
         'input_tokens_details': {'cached_tokens': 0}, 'output_tokens_details': {'reasoning_tokens': 5}}


def _price(now, rates=('1', '0.25', '2'), days_ago=0):
    price = {'schema_version': 1, 'provider': 'openai-responses', 'model': 'synthetic-model', 'currency': 'USD',
             'as_of_date': (now - timedelta(days=days_ago)).date().isoformat(),
             'rates_per_million': {'input_tokens': rates[0], 'cached_input_tokens': rates[1], 'output_tokens': rates[2]},
             'evidence_sha256': digest('test-only hypothetical T3 price evidence')}
    price['price_sha256'] = digest(price)
    return price


def protected_context(directory, *, scope_change=None, suite_spend=None, expiry_days=1, max_output=2000,
                      rates=('1', '0.25', '2'), price_days_ago=0):
    """Live T0/T2/T3 context, admitted spend scope and pinned synthetic billing."""
    now = datetime.now(timezone.utc)
    store = CaptureStore(directory)
    registry = EditionRegistry(Path(directory) / 'edition-journal.sqlite', store)
    candidate = replace(case(), variant_id='heldout-00', split='heldout', edition=EDITION, expected_layout=[])
    variants = []
    for split, count in SPLITS.items():
        for index in range(count):
            identity = {name: digest([split, index, name]) for name in
                        ('source_sha256', 'samples_sha256', 'brief_sha256', 'oracle_sha256',
                         'canonical_sha256', 'layout_sha256', 'visible_sha256')}
            variants.append({'variant_id': f'{split}-{index:02d}', 'split': split, **identity})
    variants[-8] = variant_identity(candidate)
    t0 = make_commitment(edition=EDITION, variants=variants, sealed_assets_sha256=digest('t3 seal'),
                         nonce=digest('t3 edition nonce'))
    price = _price(now, rates, price_days_ago)
    caps = {'max_input_tokens': 8000, 'max_output_tokens': max_output, 'max_product_requests': 3, 'max_b1_requests': 1,
            'max_questions': 12, 'max_total_requests': 80, 'price_max_age_days': 7, 'total_usd': '1'}
    config = {'authorized': True, 'activation_verified': True, 'authority_id': 'synthetic-provider-setup',
        'model': price['model'], 'model_version': 'synthetic-model-version', 'price_version': 'synthetic-v1',
        'price_evidence_date': price['as_of_date'], 'price_evidence_sha256': price['evidence_sha256'],
        'input_usd_per_million': rates[0], 'cached_input_usd_per_million': rates[1], 'output_usd_per_million': rates[2],
        'total_cap_usd': '1', 'max_output_tokens': max_output, 'max_input_tokens': 8000, 'api_version_pin': 'synthetic-api'}
    pins = {key: digest(['synthetic T3 pin', key]) for key in FREEZE_KEYS}
    pins.update(price_sha256=price['price_sha256'], caps_sha256=digest(caps),
                model_sha256=digest({'provider': price['provider'], 'model': price['model'],
                                     'model_version': config['model_version']}))
    freeze = make_freeze(t0, pins)
    registry.register(t0, request_id='register', expected_head=None)
    registry.freeze(freeze, request_id='freeze', expected_head=registry.head)
    suite = {'schema_version': 1, 'stage': 'T3', 'edition': EDITION, 'attempt_id': 'synthetic-t3-attempt',
             'mode': 'live', 'commitment_sha256': t0['commitment_sha256'], 'freeze_sha256': freeze['freeze_sha256'],
             'nonce': t0['nonce'], 'methods': list(ARMS),
             'variant_ids': sorted(v['variant_id'] for v in variants if v['split'] == 'heldout'),
             'capture_root_sha256': digest(str(store.root))}
    suite['suite_sha256'] = digest(suite)
    scope = {'schema_version': 1, 'stage': 'T3', 'action': 'authorize_protected_live_spend', 'edition': EDITION,
        'attempt_id': suite['attempt_id'], 'commitment_sha256': t0['commitment_sha256'],
        'freeze_sha256': freeze['freeze_sha256'], 'suite_sha256': suite['suite_sha256'],
        'edition_nonce': t0['nonce'], 'nonce': digest('synthetic T3 scope nonce'), 'pins': deepcopy(pins),
        'provider': price['provider'], 'model': price['model'], 'model_version': config['model_version'],
        'api_version_pin': config['api_version_pin'], 'billing_config_sha256': digest(config),
        'billing_code_sha256': hashlib.sha256(Path(public_live_support.__file__).read_bytes()).hexdigest(),
        'price': deepcopy(price), 'caps': deepcopy(caps), 'not_after_utc': (now + timedelta(days=expiry_days)).isoformat(),
        'capture_root_sha256': suite['capture_root_sha256'], 'registry_sha256': digest(str(registry.path)),
        'registry_head_sha256': registry.head}
    if scope_change: scope_change(scope)
    scope['scope_sha256'] = digest({k: v for k, v in scope.items() if k != 'scope_sha256'})
    signed_scope = sign(scope)
    probe = {'schema_version': 1, 'kind': 'observed_canary_probe', 'edition': EDITION,
             'freeze_sha256': freeze['freeze_sha256'], 'nonce': t0['nonce'], 'host': 'synthetic-host',
             'identity': 'synthetic-inference-principal', 'collector_sha256': digest('synthetic collector'),
             'observed_source_sha256': pins['release_sha256'], 'observed_config_sha256': pins['config_sha256'],
             'canary_file_sha256': digest('canary file'), 'canary_directory_sha256': digest('canary directory'),
             'observed_at': '2026-01-01T00:00:00Z',
             'probes': [{'operation': op, 'result': 'denied', 'errno': 13, 'winerror': None,
                         'exception_type': 'PermissionError'} for op in ('absolute_open', 'relative_open', 'directory_list')]}
    probe['observation_sha256'] = digest(probe)
    signed_probe = sign(probe, 'observer')
    findings = {'inherited_handles': 'no_oracle_handle', 'oracle_broker': 'no_oracle_endpoint',
                'network_route': 'no_oracle_route', 'inference_distribution': 'evaluator_and_hidden_absent',
                'prompt_allowlist': 'visible_only', 'independent_custody_review': 'candidate_bound_review_complete'}
    reviews = []
    for kind in sorted(ISOLATION_KINDS):
        ref = store.put('isolation_capture', {'schema_version': 1, 'kind': kind, 'edition': EDITION,
            'freeze_sha256': freeze['freeze_sha256'], 'nonce': t0['nonce'], 'host': probe['host'],
            'identity': probe['identity'], 'observed_at': probe['observed_at'],
            'collector_sha256': digest(['collector', kind]), 'source_sha256': pins['release_sha256'],
            'config_sha256': pins['config_sha256'],
            'observations': [{'check_id': kind, 'subject_sha256': digest(['subject', kind]), 'observed_value': findings[kind]}]})
        reviews.append(sign({'schema_version': 1, 'kind': kind, 'edition': EDITION,
            'freeze_sha256': freeze['freeze_sha256'], 'nonce': t0['nonce'], 'probe_sha256': probe['observation_sha256'],
            'host': probe['host'], 'identity': probe['identity'], 'capture_sha256': ref['sha256'], 'finding': 'excluded'},
            'reviewer'))
    authority = sign({'schema_version': 1, 'action': 'execute_suite', 'edition': EDITION,
        'suite_sha256': suite['suite_sha256'], 'freeze_sha256': freeze['freeze_sha256'], 'nonce': t0['nonce'],
        'mode': 'live', 'capture_root_sha256': suite['capture_root_sha256'], 'identity': probe['identity'],
        'host': probe['host'], 'collector_sha256': probe['collector_sha256'],
        'spend_authority_sha256': suite_spend or digest(signed_scope), 'registry_sha256': digest(str(registry.path))})
    for receipt in (signed_probe, *reviews, authority, signed_scope):
        store.put('signed_evidence', receipt)
    eligibility = EligibilityContext(registry, t0, freeze, suite, signed_probe, reviews, authority, verifier())
    billing = BillingAdapter(config, synthetic_pricing_port)
    return ProtectedLiveContext(eligibility, signed_scope, billing), candidate


def native_reply(context, candidate, method, request, *, usage=None, cost='0.00009', phase='T3'):
    scope = context.validate(check_time=False)
    usage = deepcopy(usage or USAGE)
    receipt = {'schema_version': 1, 'provider': scope['provider'], 'model': scope['model'],
        'model_version': scope['model_version'], 'returned_model': scope['model_version'],
        'config_sha256': scope['billing_config_sha256'], 'price_version': context.billing.config['price_version'],
        'api_version_pin': scope['api_version_pin'], 'authority_id': context.billing.config['authority_id'],
        'price_evidence_sha256': scope['price']['evidence_sha256'], 'price_evidence_date': scope['price']['as_of_date'],
        'gateway_prompt_sha256': request['prompt_sha256'], 'source_sha256': candidate.visible['source_sha256'],
        'evaluator_method': method, 'method': 'B1' if method == 'B1' else 'rank', 'mode': 'live',
        'evaluation_phase': phase, 'evaluation_authority_sha256': scope['scope_sha256'],
        'raw_usage': usage, 'cost_known': True, 'cost_usd': cost, 'status': 'completed',
        'provider_output_status': 'completed'}
    receipt['receipt_sha256'] = digest(receipt)
    return {'output': {'fields': [], 'filler': []}, 'provider': scope['provider'], 'model': scope['model'],
            'price_sha256': scope['price']['evidence_sha256'], 'usage': usage, 'cost_status': 'known',
            'known_cost': cost, 'provider_receipt': receipt}


def started_gateway(context, candidate, method, inner):
    """Admit, begin the suite, claim one arm and route the gateway through the T3 port."""
    registry = context.registry
    context.admit(request_id='t3-admit', expected_head=registry.head)
    context.eligibility.begin(request_id='t3-begin', expected_head=registry.head)
    context.eligibility.claim_arm(candidate.variant_id, method)
    port = context.provider_port(inner, [candidate], lambda prompt: 50)
    ports = replace(fake_ports(), provider=port, count_tokens=lambda prompt: 50)
    return RequestGateway(method, 'live', candidate.visible, ports, registry.store,
                          context.eligibility.request_authority())


class ProtectedLiveAuthority(unittest.TestCase):
    def test_b1_exactly_one_known_call_with_native_receipt(self):
        """what_bug_this_catches: T3 spend reuses a T1 meter or allows a B1 repair call."""
        with TemporaryDirectory() as directory:
            context, candidate = protected_context(directory)
            seen = []
            def inner(request):
                seen.append(request)
                return native_reply(context, candidate, 'B1', request)
            gateway = started_gateway(context, candidate, 'B1', inner)
            gateway.request('single_pass_full_mapping')
            self.assertEqual(seen[0]['evaluation_phase'], 'T3')
            self.assertEqual(seen[0]['evaluation_authority_sha256'], context.validate(check_time=False)['scope_sha256'])
            calls = context.registry.state(EDITION)['t3']['calls']
            self.assertEqual([c['status'] for c in calls.values()], ['known'])
            self.assertEqual(Decimal(gateway.attempts[0]['known_cost']), Decimal('0.00009'))
            with self.assertRaises(ValueError): gateway.request('repair')

    def test_cached_usage_retained_and_priced_by_single_pinned_function(self):
        """what_bug_this_catches: cached input billed at full rate or raw categories normalized away."""
        cached = {**USAGE, 'input_tokens_details': {'cached_tokens': 40}}
        with TemporaryDirectory() as directory:
            context, candidate = protected_context(directory)
            gateway = started_gateway(context, candidate, 'C0',
                lambda request: native_reply(context, candidate, 'C0', request, usage=cached, cost='0.00006'))
            gateway.request('rank')
            call = next(iter(context.registry.state(EDITION)['t3']['calls'].values()))
            self.assertEqual(call['usage'], cached)
            self.assertEqual(call['known_cost'], '0.00006')

    def test_t1_phase_receipt_or_public_context_never_authorizes_t3(self):
        """what_bug_this_catches: T1 -> T3 escalation through a public authority or T1-phase billing receipt."""
        with TemporaryDirectory() as directory:
            context, candidate = protected_context(directory)
            public_dir = Path(directory) / 'public'
            public_dir.mkdir()
            public, _ = public_context(public_dir)
            with self.assertRaises(ValueError):
                ProtectedLiveContext(public, context.scope_receipt, context.billing)
            gateway = started_gateway(context, candidate, 'B1',
                lambda request: native_reply(context, candidate, 'B1', request, phase='T1'))
            with self.assertRaises(ValueError): gateway.request('single_pass_full_mapping')
            calls = context.registry.state(EDITION)['t3']['calls']
            self.assertEqual([c['status'] for c in calls.values()], ['unknown'])

    def test_timeout_settles_unknown_and_halts_all_live_reservations(self):
        """what_bug_this_catches: retry after a timeout with unknown provider liability."""
        with TemporaryDirectory() as directory:
            context, candidate = protected_context(directory)
            def inner(request): raise TimeoutError('synthetic transport timeout')
            gateway = started_gateway(context, candidate, 'C0', inner)
            with self.assertRaises(TimeoutError): gateway.request('rank')
            call = next(iter(context.registry.state(EDITION)['t3']['calls'].values()))
            self.assertEqual((call['status'], call['known_cost'], call['error_type']), ('unknown', None, 'TimeoutError'))
            context.eligibility.claim_arm(candidate.variant_id, 'R0')
            port = context.provider_port(lambda r: native_reply(context, candidate, 'R0', r),
                                         [candidate], lambda prompt: 50)
            retry = RequestGateway('R0', 'live', candidate.visible,
                                   replace(fake_ports(), provider=port, count_tokens=lambda prompt: 50),
                                   context.registry.store, context.eligibility.request_authority())
            with self.assertRaises(ValueError): retry.request('rank')
            self.assertEqual(len(context.registry.state(EDITION)['t3']['calls']), 1)

    def test_scope_mismatches_refuse_before_admission(self):
        """what_bug_this_catches: spend scope drifts from the frozen model/price/caps/code/attempt."""
        changes = {
            'model': lambda s: s.update(model_version='other-version'),
            'price': lambda s: s['price'].update(as_of_date='2020-01-01'),
            'caps': lambda s: s['caps'].update(total_usd='2'),
            'attempt': lambda s: s.update(attempt_id='another-attempt'),
            'freeze': lambda s: s['pins'].update(release_sha256=digest('another release')),
            'b1_cap': lambda s: s['caps'].update(max_b1_requests=2),
            'nonce_reuse': lambda s: s.update(nonce=s['edition_nonce']),
            'code': lambda s: s.update(billing_code_sha256=digest('other pricing code')),
        }
        for name, change in changes.items():
            with self.subTest(name=name), TemporaryDirectory() as directory:
                context, _ = protected_context(directory, scope_change=change)
                with self.assertRaises(ValueError):
                    context.admit(request_id='t3-admit', expected_head=context.registry.head)
                self.assertIsNone(context.registry.state(EDITION).get('t3'))

    def test_expired_scope_and_unpinned_suite_spend_refuse(self):
        """what_bug_this_catches: stale scope or suite authority naming a different spend scope."""
        with TemporaryDirectory() as directory:
            # Price dated yesterday, expiry one minute ago: only the expiry check can refuse.
            context, _ = protected_context(directory, expiry_days=-1 / 1440, price_days_ago=1)
            with self.assertRaisesRegex(ValueError, 'expired'):
                context.admit(request_id='t3-admit', expected_head=context.registry.head)
        with TemporaryDirectory() as directory:
            context, _ = protected_context(directory, suite_spend=digest('different spend scope'))
            with self.assertRaises(ValueError):
                context.admit(request_id='t3-admit', expected_head=context.registry.head)
            self.assertIsNone(context.registry.state(EDITION).get('t3'))

    def test_live_heldout_attempt_without_admitted_scope_refused(self):
        """what_bug_this_catches: raw provider wiring runs a live heldout suite with no T3 meter/caps."""
        with TemporaryDirectory() as directory:
            context, _ = protected_context(directory)
            with self.assertRaises(ValueError):
                context.eligibility.begin(request_id='t3-begin', expected_head=context.registry.head)
            self.assertIsNone(context.registry.state(EDITION)['attempt'])

    def test_overrun_recorded_truthfully_then_arm_fails(self):
        """what_bug_this_catches: output beyond the signed token cap is hidden or silently accepted."""
        with TemporaryDirectory() as directory:
            # Signed output cap 10; the native reply reports 20 output tokens.
            context, candidate = protected_context(directory, max_output=10)
            gateway = started_gateway(context, candidate, 'C0',
                lambda request: native_reply(context, candidate, 'C0', request))
            with self.assertRaises(T3OverrunError): gateway.request('rank')
            call = next(iter(context.registry.state(EDITION)['t3']['calls'].values()))
            self.assertEqual(call['status'], 'known')
            self.assertEqual(call['usage'], USAGE)

    def test_reserve_overrun_recorded_truthfully_then_arm_fails(self):
        """what_bug_this_catches: a call billed above its conservative reserve is accepted silently."""
        with TemporaryDirectory() as directory:
            # Hypothetical tiny signed rates: reserve 8000*1e-6+2000*2e-6 per million = 0.000000012 USD;
            # the pinned synthetic pricing function reports 0.00009 for USAGE.
            context, candidate = protected_context(directory, rates=('0.000001', '0.000001', '0.000002'))
            gateway = started_gateway(context, candidate, 'C0',
                lambda request: native_reply(context, candidate, 'C0', request))
            with self.assertRaises(T3OverrunError) as raised: gateway.request('rank')
            self.assertEqual(raised.exception.known_cost, '0.00009')
            call = next(iter(context.registry.state(EDITION)['t3']['calls'].values()))
            self.assertEqual((call['status'], call['known_cost']), ('known', '0.00009'))

    def test_raising_price_check_settles_unknown_not_stranded(self):
        """what_bug_this_catches: a non-string native cost raises in pricing and strands the reservation."""
        with TemporaryDirectory() as directory:
            context, candidate = protected_context(directory)
            gateway = started_gateway(context, candidate, 'C0',
                lambda request: native_reply(context, candidate, 'C0', request, cost=0.00009))
            with self.assertRaises(ValueError): gateway.request('rank')
            call = next(iter(context.registry.state(EDITION)['t3']['calls'].values()))
            self.assertEqual((call['status'], call['known_cost'], call['error_type']), ('unknown', None, 'ValueError'))

    def test_runner_hook_requires_the_bound_protected_port(self):
        """what_bug_this_catches: an admitted scope with raw D7 provider wiring bypasses the T3 meter."""
        with TemporaryDirectory() as directory:
            context, candidate = protected_context(directory)
            context.admit(request_id='t3-admit', expected_head=context.registry.head)
            raw = replace(fake_ports(), provider=lambda request: native_reply(context, candidate, 'C0', request))
            with self.assertRaises(ValueError): require_protected_ports(raw, context.eligibility)
            port = context.provider_port(lambda r: r, [candidate], lambda prompt: 50)
            require_protected_ports(replace(fake_ports(), provider=port), context.eligibility)

    def test_validate_scope_is_pure_and_rechecks_hash(self):
        """what_bug_this_catches: unsigned field edits after hashing remain accepted."""
        with TemporaryDirectory() as directory:
            context, _ = protected_context(directory)
            payload = deepcopy(context.scope_receipt['payload'])
            e = context.eligibility
            validate_scope(payload, e.commitment, e.freeze, e.suite)
            payload['caps']['max_total_requests'] = 79
            with self.assertRaises(ValueError): validate_scope(payload, e.commitment, e.freeze, e.suite)


if __name__ == '__main__':
    unittest.main()

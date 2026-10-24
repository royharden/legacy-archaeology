"""T1 public-only live evaluation authority SOURCE, distinct from T2/T3.

No provider, crypto, SQLite, clock or fixture operation occurs on import. T1
events use EditionRegistry's single committed chain. Public/retired gold is
always exposed and can never confer heldout permission.
"""
from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass
from datetime import date, datetime, timezone
from decimal import Decimal
import hashlib
import inspect
from pathlib import Path

from .artifacts import canonical, digest, is_sha
from .benchmark import ARMS, FREEZE_KEYS, SPLITS
from .eligibility import ReceiptVerifier, VARIANT_KEYS, closed, hashes, text, variant_identity

D7_RECEIPT_KEYS = {'schema_version', 'run', 'method', 'mode', 'attempt', 'reserved_usd', 'status',
    'cost_known', 'cost_usd', 'raw_usage', 'timestamp', 'attempt_id', 'completed_at', 'receipt_sha256',
    'provider', 'model', 'model_version', 'price_version', 'price_evidence_date', 'config_sha256',
    'price_evidence_sha256', 'authority_id', 'api_version_pin', 'prompt_sha256', 'source_sha256',
    'sample_artifact_sha256', 'evaluator_method', 'gateway_prompt_sha256', 'latency_seconds',
    'response_sha256', 'returned_model', 'provider_output_status', 'reason',
    'evaluation_phase', 'evaluation_authority_sha256'}


def money(value):
    if not isinstance(value, str):
        raise ValueError('USD values must be exact decimal strings')
    amount = Decimal(value)
    if not amount.is_finite() or amount < 0:
        raise ValueError('finite nonnegative USD amount required')
    return amount


def validate_catalog(value):
    item = closed(value, {'schema_version', 'stage', 'edition', 'split', 'visibility', 'variants',
                         'corpus_commitment_sha256', 'nonce', 'catalog_sha256'}, 'public T1 catalog')
    if item['stage'] != 'T1' or item['split'] not in ('development', 'validation') or item['visibility'] not in ('public', 'retired'):
        raise ValueError('T1 admits named public development/validation only')
    text(item['edition'], 'public edition')
    hashes(item, ('nonce', 'catalog_sha256'))
    if item['corpus_commitment_sha256'] is not None and not is_sha(item['corpus_commitment_sha256']):
        raise ValueError('optional pre-tuning T0 commitment pin must be exact')
    if item['catalog_sha256'] != digest({k: v for k, v in item.items() if k != 'catalog_sha256'}):
        raise ValueError('public catalog hash mismatch')
    if not isinstance(item['variants'], list) or not 1 <= len(item['variants']) <= SPLITS[item['split']]:
        raise ValueError('bounded named public variants required')
    ids = set()
    for variant in item['variants']:
        closed(variant, VARIANT_KEYS, 'public variant')
        hashes(variant, VARIANT_KEYS - {'variant_id', 'split'})
        text(variant['variant_id'], 'variant ID')
        if variant['split'] != item['split'] or variant['variant_id'] in ids:
            raise ValueError('hidden/mixed/duplicate variant in public catalog')
        ids.add(variant['variant_id'])
    return item


def make_public_catalog(cases, *, visibility='public', nonce, corpus_commitment_sha256=None):
    if not cases or len({case.edition for case in cases}) != 1 or len({case.split for case in cases}) != 1:
        raise ValueError('one named public edition/split required')
    item = {'schema_version': 1, 'stage': 'T1', 'edition': cases[0].edition, 'split': cases[0].split,
            'visibility': visibility, 'variants': [variant_identity(case) for case in cases],
            'corpus_commitment_sha256': corpus_commitment_sha256, 'nonce': nonce}
    return validate_catalog({**item, 'catalog_sha256': digest(item)})


def validate_price(value, provider, model):
    card = closed(value, {'schema_version', 'provider', 'model', 'currency', 'as_of_date',
                         'rates_per_million', 'evidence_sha256', 'price_sha256'}, 'dated price card')
    if card['provider'] != provider or card['model'] != model or card['currency'] != 'USD':
        raise ValueError('price provider/model/currency mismatch')
    date.fromisoformat(card['as_of_date'])
    hashes(card, ('evidence_sha256', 'price_sha256'))
    closed(card['rates_per_million'], {'input_tokens', 'cached_input_tokens', 'output_tokens'}, 'price categories')
    for amount in card['rates_per_million'].values(): money(amount)
    if money(card['rates_per_million']['cached_input_tokens']) > money(card['rates_per_million']['input_tokens']):
        raise ValueError('cached-input rate would exceed the conservative full-input reserve')
    if card['price_sha256'] != digest({k: v for k, v in card.items() if k != 'price_sha256'}):
        raise ValueError('price evidence/version hash mismatch')
    return card


def validate_authority(payload, catalog, *, check_time=True):
    value = closed(payload, {'schema_version', 'stage', 'action', 'edition', 'split', 'mode', 'attempt_id',
        'catalog_sha256', 'nonce', 'pins', 'provider', 'model', 'model_version', 'billing_config_sha256',
        'billing_code_sha256', 'price', 'caps', 'not_after_utc',
        'capture_root_sha256', 'registry_sha256', 'authority_sha256'}, 'signed T1 authority')
    if value['stage'] != 'T1' or value['action'] != 'execute_public_live' or value['mode'] != 'live':
        raise ValueError('exact T1 live public action required')
    if any(value[key] != catalog[key] for key in ('edition', 'split', 'catalog_sha256')):
        raise ValueError('authority names another public edition/split/catalog')
    for name in ('attempt_id', 'provider', 'model', 'model_version'): text(value[name], name, 200)
    hashes(value, ('billing_config_sha256', 'billing_code_sha256'))
    hashes(value, ('nonce', 'capture_root_sha256', 'registry_sha256', 'authority_sha256'))
    closed(value['pins'], set(FREEZE_KEYS), 'provisional T1 configuration pins')
    hashes(value['pins'], FREEZE_KEYS)
    price = validate_price(value['price'], value['provider'], value['model'])
    if value['pins']['price_sha256'] != price['price_sha256'] or value['pins']['model_sha256'] != digest(
            {'provider': value['provider'], 'model': value['model'], 'model_version': value['model_version']}):
        raise ValueError('model/dated-price differs from provisional signed configuration')
    caps = closed(value['caps'], {'max_input_tokens', 'max_output_tokens', 'max_product_requests',
        'max_b1_requests', 'max_questions', 'max_total_requests', 'price_max_age_days', 'total_usd'}, 'T1 caps')
    limits = {'max_input_tokens': (1, 8000), 'max_output_tokens': (1, 2000),
              'max_product_requests': (0, 3), 'max_b1_requests': (1, 1),
              'max_questions': (0, 12), 'max_total_requests': (1, 1000), 'price_max_age_days': (1, 30)}
    for key, (low, high) in limits.items():
        if type(caps[key]) is not int or not low <= caps[key] <= high:
            raise ValueError('invalid signed token/request/question cap')
    money(caps['total_usd'])
    expiry = datetime.fromisoformat(value['not_after_utc'].replace('Z', '+00:00'))
    if expiry.tzinfo is None or (check_time and datetime.now(timezone.utc) > expiry):
        raise ValueError('expired or unzoned T1 authority')
    age = (datetime.now(timezone.utc).date() - date.fromisoformat(price['as_of_date'])).days if check_time else 0
    if check_time and not 0 <= age <= caps['price_max_age_days']:
        raise ValueError('dated price evidence is future/stale for this signed authority')
    if date.fromisoformat(price['as_of_date']) > expiry.date():
        raise ValueError('price evidence date exceeds authority validity')
    if value['authority_sha256'] != digest({k: v for k, v in value.items() if k != 'authority_sha256'}):
        raise ValueError('T1 authority hash mismatch')
    return value


def fold_public_event(state, event):
    """Pure state fold inside the same EditionRegistry transaction/chain."""
    kind, value = event['event_type'], event['payload']
    if kind == 't1_registered':
        if state['commitment'] is not None or state.get('t1') is not None:
            raise ValueError('public edition cannot replace another public/sealed registration')
        catalog = validate_catalog(value)
        state['t1'] = {'catalog': catalog, 'attempts': {}, 'selections': {}}
        state['exposed'] = True
        return True
    public = state.get('t1')
    if kind.startswith('t1_') and public is None:
        raise ValueError('T1 mutation precedes public registration')
    if public is None or not (kind.startswith('t1_') or kind in ('exposed', 'retired')):
        return False
    if kind in ('exposed', 'retired'):
        closed(value, {'reason', 'authority_sha256'}, 'public disposition')
        if kind == 'retired' and any(attempt['status'] == 'running' for attempt in public['attempts'].values()):
            raise ValueError('finish public attempts before retiring this evaluation edition')
        state['retired' if kind == 'retired' else 'exposed'] = True
        return True
    if kind == 't1_attempt_started':
        authority = validate_authority(value, public['catalog'], check_time=False)
        attempt_id = authority['attempt_id']
        if state['retired'] or attempt_id in public['attempts'] or any(
                a['authority']['nonce'] == authority['nonce'] for a in public['attempts'].values()):
            raise ValueError('retired/replayed T1 attempt or nonce')
        if any(call['status'] != 'known' for a in public['attempts'].values() for call in a['calls'].values()):
            raise ValueError('prior public liability must be reconciled before another live trial')
        public['attempts'][attempt_id] = {'authority': authority, 'status': 'running', 'arms': {}, 'calls': {}}
        return True
    attempt_id = value.get('attempt_id')
    if kind == 't1_selected':
        closed(value, {'attempt_id', 'pins', 'basis', 'result_capture', 'rationale',
                       'authority_sha256', 'selection_sha256'}, 'public selection')
        attempt = public['attempts'].get(attempt_id)
        if attempt is None or attempt['status'] not in ('completed', 'partial') or value['pins'] != attempt['authority']['pins']:
            raise ValueError('selection must bind an actual completed T1 configuration')
        if value['basis'] not in ('quality', 'cost') or (value['basis'] == 'cost' and any(
                call['status'] != 'known' for call in attempt['calls'].values())):
            raise ValueError('unknown liability cannot establish cost-based ranker selection')
        if value['selection_sha256'] != digest({k: v for k, v in value.items() if k != 'selection_sha256'}):
            raise ValueError('selection hash mismatch')
        public['selections'][value['selection_sha256']] = value
        return True
    attempt = public['attempts'].get(attempt_id)
    if kind == 't1_liability_reconciled':
        closed(value, {'attempt_id', 'call_id', 'known_cost', 'usage', 'billing_capture', 'authority_sha256'}, 'billing reconciliation')
        if attempt is None or value['call_id'] not in attempt['calls'] or attempt['calls'][value['call_id']]['status'] == 'known':
            raise ValueError('no unknown/reserved liability to reconcile')
        money(value['known_cost'])
        attempt['calls'][value['call_id']].update(status='known', known_cost=value['known_cost'], usage=value['usage'],
                                                 billing_capture=value['billing_capture'])
        return True
    if attempt is None or attempt['status'] != 'running':
        raise ValueError('no active exact T1 attempt')
    caps = attempt['authority']['caps']
    if kind in ('t1_arm_started', 't1_arm_finished'):
        keys = {'attempt_id', 'variant_id', 'method'} | ({'status', 'capture'} if kind.endswith('finished') else set())
        closed(value, keys, 'T1 arm')
        if value['variant_id'] not in {v['variant_id'] for v in public['catalog']['variants']} or value['method'] not in ARMS:
            raise ValueError('arm not offered in public suite')
        arm_id = digest({'variant_id': value['variant_id'], 'method': value['method']})
        if kind.endswith('started'):
            if state['retired'] or arm_id in attempt['arms']: raise ValueError('T1 arm already consumed')
            attempt['arms'][arm_id] = {'status': 'running'}
        else:
            if arm_id not in attempt['arms'] or attempt['arms'][arm_id]['status'] != 'running' or value['status'] not in (
                    'completed', 'partial', 'failed', 'abstained'):
                raise ValueError('invalid T1 arm finish')
            if value['method'] == 'B1' and value['status'] == 'completed':
                calls = [call for call in attempt['calls'].values() if call['variant_id'] == value['variant_id'] and call['method'] == 'B1']
                if len(calls) != 1 or calls[0]['status'] != 'known':
                    raise ValueError('complete T1 B1 needs exactly one accounted request, never repair/no-output')
            attempt['arms'][arm_id] = {'status': value['status'], 'capture': value['capture']}
    elif kind == 't1_request_reserved':
        closed(value, {'attempt_id', 'variant_id', 'method', 'call_id', 'request_no', 'prompt_sha256', 'source_sha256',
                       'input_tokens', 'output_limit', 'reserved_usd'}, 'T1 request reservation')
        arm_id = digest({'variant_id': value['variant_id'], 'method': value['method']})
        if arm_id not in attempt['arms'] or attempt['arms'][arm_id]['status'] != 'running':
            raise ValueError('request outside active unique T1 arm')
        if value['call_id'] in attempt['calls'] or any(call['status'] != 'known' for call in attempt['calls'].values()):
            raise ValueError('request replay or unresolved/unknown single-flight liability')
        count = sum(call['variant_id'] == value['variant_id'] and call['method'] == value['method']
                    for call in attempt['calls'].values())
        maximum = 0 if value['method'] == 'B0' else caps['max_b1_requests'] if value['method'] == 'B1' else caps['max_product_requests']
        if count >= maximum or value['request_no'] != count + 1 or len(attempt['calls']) >= caps['max_total_requests']:
            raise ValueError('attempt/request cap exhausted')
        if type(value['input_tokens']) is not int or not 0 <= value['input_tokens'] <= caps['max_input_tokens'] or value['output_limit'] != caps['max_output_tokens']:
            raise ValueError('preflight token cap mismatch')
        reserve = (Decimal(caps['max_input_tokens']) * money(attempt['authority']['price']['rates_per_million']['input_tokens'])
                   + Decimal(caps['max_output_tokens']) * money(attempt['authority']['price']['rates_per_million']['output_tokens'])) / 1000000
        spent = sum((money(call['known_cost']) for call in attempt['calls'].values()), Decimal(0))
        if money(value['reserved_usd']) != reserve or spent + reserve > money(caps['total_usd']):
            raise ValueError('known total plus conservative reserve exceeds signed cap')
        hashes(value, ('call_id', 'prompt_sha256', 'source_sha256'))
        attempt['calls'][value['call_id']] = {**value, 'status': 'reserved', 'known_cost': None, 'usage': None}
    elif kind == 't1_request_settled':
        closed(value, {'attempt_id', 'call_id', 'cost_status', 'known_cost', 'usage', 'reply_sha256',
                       'billing_receipt', 'pricing_code_sha256', 'error_type'}, 'T1 usage receipt')
        call = attempt['calls'].get(value['call_id'])
        if call is None or call['status'] != 'reserved' or value['cost_status'] not in ('known', 'unknown'):
            raise ValueError('usage receipt lacks unique reserved attempt')
        if value['cost_status'] == 'known':
            money(value['known_cost'])
            receipt = value['billing_receipt']
            if (not isinstance(receipt, dict) or receipt.get('raw_usage') != value['usage']
                    or receipt.get('cost_known') is not True or receipt.get('cost_usd') != value['known_cost']
                    or value['pricing_code_sha256'] != attempt['authority']['billing_code_sha256']
                    or receipt.get('receipt_sha256') != digest({k: v for k, v in receipt.items() if k != 'receipt_sha256'})):
                raise ValueError('known cost must retain the actual pinned D7 billing receipt')
        elif value['known_cost'] is not None: raise ValueError('unknown cost cannot be fabricated zero')
        call.update(status=value['cost_status'], known_cost=value['known_cost'], usage=value['usage'],
                    billing_receipt=value['billing_receipt'],
                    reply_sha256=value['reply_sha256'], error_type=value['error_type'])
    elif kind == 't1_attempt_finished':
        closed(value, {'attempt_id', 'status', 'result_capture'}, 'T1 terminal receipt')
        if value['status'] not in ('completed', 'partial', 'failed', 'cancelled', 'no_output'):
            raise ValueError('unknown T1 terminal state')
        if value['status'] == 'completed' and (len(attempt['arms']) != len(public['catalog']['variants']) * len(ARMS)
                or any(arm['status'] != 'completed' for arm in attempt['arms'].values())
                or any(call['status'] != 'known' for call in attempt['calls'].values())):
            raise ValueError('incomplete/unknown-cost T1 cannot claim complete')
        attempt.update(status=value['status'], result_capture=value['result_capture'])
    else:
        raise ValueError('unknown T1 event')
    return True


@dataclass(frozen=True)
class BillingAdapter:
    """Trusted injection of D7's pure priced_usage(usage,config), no transport.

    Pricing has one source of truth: the actual provider helper and its receipt.
    The evaluator performs conservative reservations and consistency checks only.
    """
    config: dict
    calculate_usage_cost: object

    def code_pin(self):
        if not inspect.isfunction(self.calculate_usage_cost):
            raise ValueError('actual pinned pricing function required')
        source = inspect.getsourcefile(self.calculate_usage_cost)
        if source is None: raise ValueError('pricing source provenance unavailable')
        path = Path(source)
        if path.suffix != '.py' or path.is_symlink() or not path.is_file() or path.stat().st_size > 1024 * 1024:
            raise ValueError('bounded real pricing source artifact required')
        return hashlib.sha256(path.read_bytes()).hexdigest()

    def validate(self, authority):
        cfg = closed(self.config, {'authorized', 'activation_verified', 'authority_id', 'model', 'model_version',
            'price_version', 'price_evidence_date', 'price_evidence_sha256', 'input_usd_per_million',
            'cached_input_usd_per_million', 'output_usd_per_million', 'total_cap_usd',
            'max_output_tokens', 'max_input_tokens', 'api_version_pin'}, 'D7 billing configuration')
        if digest(cfg) != authority['billing_config_sha256'] or self.code_pin() != authority['billing_code_sha256']:
            raise ValueError('pricing helper/config differs from actual signed source pin')
        for key in ('model', 'model_version'):
            if cfg[key] != authority[key]: raise ValueError('billing requested/returned-model pin mismatch')
        price = authority['price']
        if cfg['price_evidence_sha256'] != price['evidence_sha256'] or cfg['price_evidence_date'] != price['as_of_date']:
            raise ValueError('billing price evidence/date mismatch')
        for name, config_name in (('input_tokens', 'input_usd_per_million'),
                ('cached_input_tokens', 'cached_input_usd_per_million'), ('output_tokens', 'output_usd_per_million')):
            if money(cfg[config_name]) != money(price['rates_per_million'][name]): raise ValueError('billing rate mismatch')
        for name in ('input_tokens', 'output_tokens'):
            if cfg['max_' + name] != authority['caps']['max_' + name]: raise ValueError('transport/gateway token bounds differ')
        return self

    def price(self, reply, authority, prompt_sha256, source_sha256, method, *, phase='T1'):
        """Unknown categories are retained, never converted to zero/full-input billing.

        phase is 'T1' (public authority) or 'T3' (protected spend scope, whose
        scope_sha256 is supplied as authority['authority_sha256']).
        """
        if phase not in ('T1', 'T3'): return None
        usage = reply.get('usage') if isinstance(reply, dict) else None
        receipt = reply.get('provider_receipt') if isinstance(reply, dict) else None
        if not isinstance(usage, dict) or not isinstance(receipt, dict): return None
        if set(receipt) - D7_RECEIPT_KEYS: return None
        if (type(receipt.get('schema_version')) is not int or receipt['schema_version'] != 1
                or reply.get('provider') != authority['provider'] or reply.get('model') != authority['model']
                or reply.get('price_sha256') != authority['price']['evidence_sha256']
                or receipt.get('provider') != authority['provider'] or receipt.get('model') != authority['model']
                or receipt.get('model_version') != authority['model_version'] or receipt.get('returned_model') != authority['model_version']
                or receipt.get('config_sha256') != authority['billing_config_sha256']
                or receipt.get('price_version') != self.config['price_version']
                or receipt.get('api_version_pin') != self.config['api_version_pin']
                or receipt.get('authority_id') != self.config['authority_id']
                or receipt.get('evaluation_phase') != phase
                or receipt.get('evaluation_authority_sha256') != authority['authority_sha256']
                or receipt.get('price_evidence_sha256') != authority['price']['evidence_sha256']
                or receipt.get('price_evidence_date') != authority['price']['as_of_date']
                or receipt.get('gateway_prompt_sha256') != prompt_sha256 or receipt.get('source_sha256') != source_sha256
                or receipt.get('evaluator_method') != method or receipt.get('mode') != 'live'
                or receipt.get('method') != ('B1' if method == 'B1' else 'rank')
                or receipt.get('raw_usage') != usage or receipt.get('cost_known') is not True
                or receipt.get('status') != 'completed' or receipt.get('provider_output_status') != 'completed'
                or receipt.get('receipt_sha256') != digest({k: v for k, v in receipt.items() if k != 'receipt_sha256'})):
            return None
        # D7 validates cached/reasoning/total categories and applies its one pricing
        # formula. No evaluator copy of that formula or raw-category normalization.
        computed = self.calculate_usage_cost(deepcopy(usage), deepcopy(self.config))
        if computed is None or not isinstance(computed, Decimal) or not computed.is_finite() or computed < 0:
            return None
        if money(receipt['cost_usd']) != computed or reply.get('known_cost') != receipt['cost_usd']:
            return None
        return receipt['cost_usd']


@dataclass(frozen=True)
class PublicLiveContext:
    registry: object
    catalog: dict
    authority_receipt: dict
    verifier: ReceiptVerifier
    billing: BillingAdapter | None = None

    def __post_init__(self):
        from .edition_registry import EditionRegistry
        if type(self.registry) is not EditionRegistry or type(self.verifier) is not ReceiptVerifier:
            raise ValueError('concrete edition registry and Ed25519 verifier required')

    def validate(self, *, check_time=True, check_chronology=True):
        catalog = validate_catalog(self.catalog)
        authority = validate_authority(self.verifier.verify(self.authority_receipt, 'run_owner'), catalog, check_time=check_time)
        if type(self.billing) is not BillingAdapter: raise ValueError('actual pinned D7 billing adapter required')
        self.billing.validate(authority)
        state = self.registry.state(catalog['edition'])
        if state.get('t1') is None or state['t1']['catalog'] != catalog or state['retired']:
            raise ValueError('public edition missing/changed/retired')
        attempt = state['t1']['attempts'].get(authority['attempt_id'])
        if attempt is not None and attempt['authority'] != authority:
            raise ValueError('a signed attempt cannot change model/pins/price/caps after admission')
        if authority['capture_root_sha256'] != digest(str(self.registry.store.root)) or authority['registry_sha256'] != digest(str(self.registry.path)):
            raise ValueError('wrong evaluator store/journal')
        envelope = {'schema_version': 1, 'kind': 'signed_evidence', 'payload': self.authority_receipt}
        self.registry.store.get({'sha256': digest(envelope), 'kind': 'signed_evidence'})
        if check_chronology: self.registry.check_t1_chronology(catalog)
        return authority

    @property
    def pins(self): return self.validate()['pins']

    @property
    def suite(self):
        a = self.validate()
        return {'attempt_id': a['attempt_id'], 'mode': 'live',
                'variant_ids': [v['variant_id'] for v in self.catalog['variants']]}

    def begin(self, *, request_id, expected_head):
        authority = self.validate()
        return self.registry._append(self.catalog['edition'], 't1_attempt_started', authority,
                                     request_id=request_id, expected_head=expected_head)

    def authorize_case(self, case, pins, store, mode):
        authority = self.validate()
        attempts = self.registry.state(self.catalog['edition'])['t1']['attempts']
        attempt = attempts.get(authority['attempt_id'])
        if attempt is None or attempt['status'] != 'running' or mode != 'live' or pins != authority['pins'] or store.root != self.registry.store.root:
            raise ValueError('no active exact public T1 live attempt')
        if case.split not in ('development', 'validation') or case.edition != self.catalog['edition']:
            raise ValueError('T1 authority grants no hidden permission')
        expected = next((v for v in self.catalog['variants'] if v['variant_id'] == case.variant_id), None)
        if variant_identity(case) != expected: raise ValueError('stale public source/sample/brief/oracle pins')

    def request_authority(self):
        authority = self.validate()
        return {**authority, 'spend_authority_sha256': authority['authority_sha256']}

    def claim_arm(self, variant_id, method):
        payload = {'attempt_id': self.suite['attempt_id'], 'variant_id': variant_id, 'method': method}
        result = self.registry._append(self.catalog['edition'], 't1_arm_started', payload,
            request_id='t1-arm:' + digest(payload), expected_head=self.registry.head)
        if not result.newly_created: raise ValueError('historical T1 arm cannot rerun')
        return result

    def finish_arm(self, variant_id, method, status, capture):
        self.registry.store.get(capture)
        attempt_id = self.validate(check_time=False, check_chronology=False)['attempt_id']
        payload = {'attempt_id': attempt_id, 'variant_id': variant_id,
                   'method': method, 'status': status, 'capture': capture}
        return self.registry._append(self.catalog['edition'], 't1_arm_finished', payload,
            request_id='t1-arm-finish:' + digest([attempt_id, variant_id, method]), expected_head=self.registry.head)

    def finish_suite(self, status, capture, *, request_id):
        self.registry.store.get(capture)
        attempt_id = self.validate(check_time=False, check_chronology=False)['attempt_id']
        return self.registry._append(self.catalog['edition'], 't1_attempt_finished',
            {'attempt_id': attempt_id, 'status': status, 'result_capture': capture},
            request_id=request_id, expected_head=self.registry.head)

    def meter(self, case, method): return PublicRequestMeter(self, case, method)

    def reconcile_liability(self, signed_receipt, *, request_id):
        a = self.validate(check_time=False, check_chronology=False)
        receipt = closed(self.verifier.verify(signed_receipt, 'run_owner'),
            {'schema_version', 'action', 'edition', 'attempt_id', 'call_id', 'scope_authority_sha256',
             'billing_capture'}, 'signed billing reconciliation')
        if (receipt['action'] != 'reconcile_public_liability' or receipt['edition'] != self.catalog['edition']
                or receipt['attempt_id'] != a['attempt_id'] or receipt['scope_authority_sha256'] != a['authority_sha256']):
            raise ValueError('wrong liability reconciliation authority')
        bill = closed(self.registry.store.get(receipt['billing_capture'], kind='billing_observation'),
            {'schema_version', 'edition', 'attempt_id', 'call_id', 'provider', 'model', 'billed_usd',
             'usage', 'observed_at', 'provider_receipt'}, 'actual billing capture')
        if any(bill[key] != receipt[key] for key in ('edition', 'attempt_id', 'call_id')) or bill['provider'] != a['provider'] or bill['model'] != a['model']:
            raise ValueError('billing effect does not bind the unknown call')
        money(bill['billed_usd']); text(bill['observed_at'], 'billing observation time')
        native = bill['provider_receipt']
        calls = self.registry.state(self.catalog['edition'])['t1']['attempts'][a['attempt_id']]['calls']
        call = calls.get(receipt['call_id'])
        if (call is None or not isinstance(native, dict) or native.get('status') != 'reconciled'
                or native.get('cost_known') is not True or native.get('cost_usd') != bill['billed_usd']
                or native.get('raw_usage') != bill['usage'] or native.get('evaluation_phase') != 'T1'
                or native.get('evaluation_authority_sha256') != a['authority_sha256']
                or native.get('gateway_prompt_sha256') != call['prompt_sha256']
                or native.get('source_sha256') != call['source_sha256']
                or native.get('evaluator_method') != call['method']
                or not is_sha(native.get('billing_evidence_sha256'))
                or native.get('receipt_sha256') != digest({k: v for k, v in native.items() if k != 'receipt_sha256'})):
            raise ValueError('actual D7 reconciled receipt must establish the billing fact, not an evaluator pricing override')
        return self.registry._append(self.catalog['edition'], 't1_liability_reconciled',
            {'attempt_id': a['attempt_id'], 'call_id': receipt['call_id'], 'known_cost': bill['billed_usd'],
             'usage': bill['usage'], 'billing_capture': receipt['billing_capture'], 'authority_sha256': digest(signed_receipt)},
            request_id=request_id, expected_head=self.registry.head)

    def select_configuration(self, signed_receipt, *, request_id):
        a = self.validate(check_time=False, check_chronology=False)
        self.registry.check_t1_chronology(self.catalog)
        value = closed(self.verifier.verify(signed_receipt, 'run_owner'),
            {'schema_version', 'action', 'edition', 'attempt_id', 'basis', 'pins', 'rationale', 'result_capture'},
            'signed T1 selection')
        if value['action'] != 'select_public_configuration' or value['edition'] != self.catalog['edition'] or value['attempt_id'] != a['attempt_id']:
            raise ValueError('wrong public configuration selection scope')
        state = self.registry.state(self.catalog['edition'])['t1']['attempts'][a['attempt_id']]
        if state.get('result_capture') != value['result_capture']:
            raise ValueError('selection must preserve actual terminal report capture')
        self.registry.store.get(value['result_capture'])
        text(value['rationale'], 'selection rationale', 4000)
        payload = {key: value[key] for key in ('attempt_id', 'basis', 'pins', 'rationale', 'result_capture')}
        payload['authority_sha256'] = digest(signed_receipt)
        payload['selection_sha256'] = digest(payload)
        return self.registry._append(self.catalog['edition'], 't1_selected', payload,
                                     request_id=request_id, expected_head=self.registry.head)


@dataclass(frozen=True)
class PublicRequestMeter:
    context: PublicLiveContext
    case: object
    method: str

    def reserve(self, request, input_tokens):
        a = self.context.validate()
        self.context.authorize_case(self.case, a['pins'], self.context.registry.store, 'live')
        caps = a['caps']
        request.update(max_input_tokens=caps['max_input_tokens'], max_output_tokens=caps['max_output_tokens'],
                       provider=a['provider'], model=a['model'], price_sha256=a['price']['evidence_sha256'],
                       evaluation_phase='T1', evaluation_authority_sha256=a['authority_sha256'])
        reserve = (Decimal(caps['max_input_tokens']) * money(a['price']['rates_per_million']['input_tokens']) +
                   Decimal(caps['max_output_tokens']) * money(a['price']['rates_per_million']['output_tokens'])) / 1000000
        call_id = digest({'authority': a['authority_sha256'], 'variant': self.case.variant_id,
                          'method': self.method, 'request': request})
        payload = {'attempt_id': a['attempt_id'], 'variant_id': self.case.variant_id, 'method': self.method,
            'call_id': call_id, 'request_no': request['attempt'], 'prompt_sha256': request['prompt_sha256'],
            'source_sha256': self.case.visible['source_sha256'],
            'input_tokens': input_tokens, 'output_limit': caps['max_output_tokens'], 'reserved_usd': str(reserve)}
        receipt = self.context.registry._append(self.case.edition, 't1_request_reserved', payload,
            request_id='t1-reserve:' + call_id, expected_head=self.context.registry.head)
        if not receipt.newly_created: raise ValueError('historical reservation cannot call provider again')
        return call_id

    def settle(self, call_id, reply=None, error_type=None):
        a = self.context.validate(check_time=False, check_chronology=False)
        cost, status = None, 'unknown'
        usage = reply.get('usage') if isinstance(reply, dict) else None
        attempt = self.context.registry.state(self.case.edition)['t1']['attempts'][a['attempt_id']]
        call = attempt['calls'][call_id]
        if error_type is None:
            cost = self.context.billing.price(reply, a, call['prompt_sha256'], self.case.visible['source_sha256'], self.method)
            if cost is not None: status = 'known'
        payload = {'attempt_id': a['attempt_id'], 'call_id': call_id, 'cost_status': status,
                   'known_cost': cost, 'usage': deepcopy(usage), 'reply_sha256': digest(reply),
                   'billing_receipt': reply.get('provider_receipt') if isinstance(reply, dict) else None,
                   'pricing_code_sha256': a['billing_code_sha256'], 'error_type': error_type}
        self.context.registry._append(self.case.edition, 't1_request_settled', payload,
            request_id='t1-settle:' + call_id, expected_head=self.context.registry.head)
        return {'cost_status': status, 'known_cost': cost, 'usage': usage}

"""Synthetic T1 signing/price fixtures SOURCE, no operational authority or prices."""
from copy import deepcopy
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from pathlib import Path
from decimal import Decimal
import hashlib

from evaluator_support import case, fake_ports, mapping
from custody_support import sign, verifier
from evaluation.artifacts import CaptureStore, digest
from evaluation.benchmark import FREEZE_KEYS
from evaluation.edition_registry import EditionRegistry
from evaluation.public_live import BillingAdapter, PublicLiveContext, make_public_catalog
from evaluation.runner import RequestGateway


def public_context(directory, *, registry=None, candidate=None, t0=None, total_usd='1'):
    candidate = candidate or case()
    registry = registry or EditionRegistry(Path(directory) / 'public-editions.sqlite', CaptureStore(directory))
    catalog = make_public_catalog([candidate], nonce=digest('synthetic public catalog'),
                                   corpus_commitment_sha256=t0)
    registry.register_public(catalog, request_id='public-register', expected_head=registry.head)
    now = datetime.now(timezone.utc)
    price = {'schema_version': 1, 'provider': 'openai-responses', 'model': 'synthetic-model', 'currency': 'USD',
             'as_of_date': now.date().isoformat(), 'rates_per_million': {'input_tokens': '1', 'cached_input_tokens': '0.25', 'output_tokens': '2'},
             'evidence_sha256': digest('test-only hypothetical price evidence')}
    price['price_sha256'] = digest(price)
    pins = {key: digest(['synthetic T1 pin', key]) for key in FREEZE_KEYS}
    pins.update(price_sha256=price['price_sha256'], model_sha256=digest({'provider': price['provider'], 'model': price['model'], 'model_version': 'synthetic-model-version'}))
    config = {'authorized': True, 'activation_verified': True, 'authority_id': 'synthetic-provider-setup',
        'model': price['model'], 'model_version': 'synthetic-model-version', 'price_version': 'synthetic-v1',
        'price_evidence_date': price['as_of_date'], 'price_evidence_sha256': price['evidence_sha256'],
        'input_usd_per_million': '1', 'cached_input_usd_per_million': '0.25', 'output_usd_per_million': '2',
        'total_cap_usd': total_usd, 'max_output_tokens': 2000, 'max_input_tokens': 8000, 'api_version_pin': 'synthetic-api'}
    payload = {'schema_version': 1, 'stage': 'T1', 'action': 'execute_public_live', 'edition': candidate.edition,
        'split': candidate.split, 'mode': 'live', 'attempt_id': 'synthetic-public-attempt',
        'catalog_sha256': catalog['catalog_sha256'], 'nonce': digest('synthetic attempt nonce'), 'pins': pins,
        'provider': price['provider'], 'model': price['model'], 'model_version': config['model_version'],
        'billing_config_sha256': digest(config), 'billing_code_sha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest(), 'price': price,
        'caps': {'max_input_tokens': 8000, 'max_output_tokens': 2000, 'max_product_requests': 3,
                 'max_b1_requests': 1, 'max_questions': 12, 'max_total_requests': 10,
                 'price_max_age_days': 7, 'total_usd': total_usd},
        'not_after_utc': (now + timedelta(days=1)).isoformat(), 'capture_root_sha256': digest(str(registry.store.root)),
        'registry_sha256': digest(str(registry.path))}
    payload['authority_sha256'] = digest(payload)
    signed = sign(payload)
    registry.store.put('signed_evidence', signed)
    return PublicLiveContext(registry, catalog, signed, verifier(), BillingAdapter(config, synthetic_pricing_port)), candidate


def synthetic_pricing_port(usage, config):
    """Hand-derived port fixture, not a second production pricing implementation."""
    normal = {'input_tokens': 50, 'output_tokens': 20, 'total_tokens': 70,
              'input_tokens_details': {'cached_tokens': 0}, 'output_tokens_details': {'reasoning_tokens': 5}}
    cached = {**normal, 'input_tokens_details': {'cached_tokens': 40}}
    if usage == normal: return Decimal('0.00009')
    if usage == cached: return Decimal('0.00006')
    return None


def resign(context, payload):
    payload = deepcopy(payload)
    payload['authority_sha256'] = digest({k: v for k, v in payload.items() if k != 'authority_sha256'})
    signed = sign(payload)
    context.registry.store.put('signed_evidence', signed)
    return replace(context, authority_receipt=signed)


def gateway(context, candidate, *, method='B1', provider=None, transform_reply=None):
    context.claim_arm(candidate.variant_id, method)
    a = context.validate()
    def synthetic_reply(request):
        usage = {'input_tokens': 50, 'output_tokens': 20, 'total_tokens': 70,
                 'input_tokens_details': {'cached_tokens': 0}, 'output_tokens_details': {'reasoning_tokens': 5}}
        receipt = {'schema_version': 1, 'provider': a['provider'], 'model': a['model'], 'model_version': a['model_version'],
            'returned_model': a['model_version'], 'config_sha256': a['billing_config_sha256'],
            'price_version': context.billing.config['price_version'], 'api_version_pin': context.billing.config['api_version_pin'],
            'authority_id': context.billing.config['authority_id'],
            'price_evidence_sha256': a['price']['evidence_sha256'], 'price_evidence_date': a['price']['as_of_date'],
            'gateway_prompt_sha256': request['prompt_sha256'], 'source_sha256': candidate.visible['source_sha256'],
            'evaluator_method': method, 'method': 'B1' if method == 'B1' else 'rank', 'mode': 'live',
            'evaluation_phase': 'T1', 'evaluation_authority_sha256': a['authority_sha256'],
            'raw_usage': usage, 'cost_known': True, 'cost_usd': '0.00009', 'status': 'completed', 'provider_output_status': 'completed'}
        receipt['receipt_sha256'] = digest(receipt)
        result = {'output': mapping(), 'provider': a['provider'], 'model': a['model'],
                'price_sha256': a['price']['evidence_sha256'], 'usage': usage,
                'cost_status': 'known', 'known_cost': '0.00009', 'provider_receipt': receipt}
        return transform_reply(result) if transform_reply is not None else result
    ports = replace(fake_ports(), provider=provider or synthetic_reply, count_tokens=lambda prompt: 50)
    return RequestGateway(method, 'live', candidate.visible, ports, context.registry.store,
                          context.request_authority(), meter=context.meter(candidate, method))

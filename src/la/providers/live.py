"""Guarded OpenAI Responses REST source adapter. Activation/version verification deferred.

No request is made at import. Never retry an ambiguous billed attempt automatically.
"""
from __future__ import annotations
import json
import os
import time
import urllib.request
from la.contracts import canonical, digest, sha256
from la.providers.accounting import CallLedger, amount
from .wire import request_pins


def validate_config(config):
    """Construction supplies no activation. This validates a later authority packet."""
    required = {'authorized', 'activation_verified', 'authority_id', 'model', 'model_version',
                'price_version', 'price_evidence_date', 'price_evidence_sha256',
                'input_usd_per_million', 'cached_input_usd_per_million', 'output_usd_per_million',
                'total_cap_usd', 'max_output_tokens', 'max_input_tokens', 'api_version_pin'}
    if type(config) is not dict or set(config) != required:
        raise ValueError('live config requires exact pinned authority/model/API/pricing schema; no credentials')
    if config['authorized'] is not True or config['activation_verified'] is not True:
        raise ValueError('live activation unapproved; live never falls back to mock')
    for key in ('authority_id', 'model', 'model_version', 'price_version', 'price_evidence_date', 'api_version_pin'):
        if type(config[key]) is not str or not config[key].strip() or len(config[key])>256:
            raise ValueError('nonempty authority/model/version/price pins required')
    pin = config['price_evidence_sha256']
    if type(pin) is not str or len(pin) != 64 or any(c not in '0123456789abcdef' for c in pin):
        raise ValueError('dated pricing evidence content hash required')
    if type(config['max_input_tokens']) is not int or not 1 <= config['max_input_tokens'] <= 8000:
        raise ValueError('input token bound exceeds plan')
    if type(config['max_output_tokens']) is not int or not 1 <= config['max_output_tokens'] <= 2000:
        raise ValueError('output token bound exceeds plan')
    prices = [amount(config[key]) for key in ('input_usd_per_million', 'cached_input_usd_per_million', 'output_usd_per_million')]
    from datetime import date
    try: date.fromisoformat(config['price_evidence_date'])
    except ValueError: raise ValueError('ISO pricing evidence date required') from None
    if prices[1] > prices[0] or amount(config['total_cap_usd']) == 0:
        raise ValueError('cached price/cap invalid')
    return config


def priced_usage(usage, config):
    """Raw usage is retained. Missing/unsupported categories are unknown, never zero."""
    if type(usage) is not dict:
        return None
    inputs, outputs = usage.get('input_tokens'), usage.get('output_tokens')
    details = usage.get('input_tokens_details')
    if type(details) is not dict:
        return None
    cached = details.get('cached_tokens')
    if any(type(value) is not int or value < 0 for value in (inputs, outputs, cached)) or cached > inputs:
        return None
    # Total output includes reasoning tokens; never charge them twice.
    if inputs > config['max_input_tokens'] or outputs > config['max_output_tokens']:
        return None
    if set(usage) - {'input_tokens', 'output_tokens', 'total_tokens', 'input_tokens_details', 'output_tokens_details'}:
        return None
    if set(details) - {'cached_tokens'}:
        return None
    output_details = usage.get('output_tokens_details', {})
    if type(output_details) is not dict or set(output_details) - {'reasoning_tokens'}:
        return None
    reasoning = output_details.get('reasoning_tokens', 0)
    if type(reasoning) is not int or not 0 <= reasoning <= outputs:
        return None
    if 'total_tokens' in usage and (type(usage['total_tokens']) is not int or usage['total_tokens'] != inputs + outputs):
        return None
    return ((inputs-cached)*amount(config['input_usd_per_million'])
            + cached*amount(config['cached_input_usd_per_million'])
            + outputs*amount(config['output_usd_per_million'])) / 1000000


def responses_transport(payload):
    """Only invoked after activation and durable reservation. No retries."""
    key = os.environ.get('OPENAI_API_KEY')
    if not key:
        raise MissingCredential('OPENAI_API_KEY missing')
    request = urllib.request.Request('https://api.openai.com/v1/responses', data=canonical(payload),
                                    headers={'Authorization': 'Bearer '+key, 'Content-Type': 'application/json'}, method='POST')
    with urllib.request.urlopen(request, timeout=60) as response:
        raw = response.read(2*1024*1024+1)
    if len(raw) > 2*1024*1024:
        raise ValueError('provider response byte limit')
    return json.loads(raw)


class MissingCredential(ValueError):
    pass

def generate_once(prompt: str, config: dict, ledger_path, *, run: str, method: str, pins=None, transport=None) -> dict:
    config = validate_config(config)
    request_pins(pins)
    if type(prompt) is not str or not 0 < len(prompt.encode()) <= min(8000, config['max_input_tokens']):
        raise ValueError('conservative UTF-8 byte/token request bound exceeded')
    # Never pass arbitrary caller text as an allowlisted product request.
    if not pins or pins.get('prompt_sha256') != sha256(prompt.encode()) or not pins.get('source_sha256'):
        raise ValueError('content-bound allowlisted prompt pins required')
    ledger = CallLedger(ledger_path)
    reserve = (config['max_input_tokens']*amount(config['input_usd_per_million'])
               + config['max_output_tokens']*amount(config['output_usd_per_million']))/1000000
    receipt = ledger.reserve(run=run, method=method, reserve=str(reserve), cap=config['total_cap_usd'],
                             pins=dict(pins, provider='openai-responses', model=config['model'],
                                       model_version=config['model_version'], price_version=config['price_version'],
                                       price_evidence_date=config['price_evidence_date'],
                                       config_sha256=digest(config), price_evidence_sha256=config['price_evidence_sha256'],
                                       authority_id=config['authority_id'], api_version_pin=config['api_version_pin']))
    start = time.monotonic()
    try:
        value = (transport or responses_transport)({'model': config['model'], 'input': prompt,
                    'max_output_tokens': config['max_output_tokens'], 'store': False})
    except MissingCredential:
        settled = ledger.finish(receipt, status='not_sent', cost='0', reason='credential_missing')
        return {'status': 'failed', 'text': None, 'receipt': settled}
    except Exception:
        settled = ledger.finish(receipt, status='unknown_liability', reason='transport_failure',
                                latency_seconds=str(time.monotonic()-start))
        return {'status': 'failed', 'text': None, 'receipt': settled}
    usage = value.get('usage') if type(value) is dict else None
    cost = priced_usage(usage, config) if type(value) is dict and value.get('model') == config['model_version'] else None
    settled = ledger.finish(receipt, status='completed' if cost is not None else 'unknown_liability',
                            cost=str(cost) if cost is not None else None, raw_usage=usage,
                            latency_seconds=str(time.monotonic()-start), response_sha256=digest(value),
                            returned_model=value.get('model') if type(value) is dict else None,
                            provider_output_status=value.get('status') if type(value) is dict else None)
    try:
        if value.get('status') != 'completed' or value.get('model') != config['model_version']:
            raise ValueError('incomplete response or unexpected model version')
        texts = [part['text'] for item in value['output'] for part in item.get('content', [])
                 if part.get('type') == 'output_text']
        if not texts or any(type(text) is not str for text in texts):
            raise ValueError('missing textual JSON output')
        text = ''.join(texts)
    except (ValueError, KeyError, TypeError, AttributeError):
        return {'status': 'failed', 'text': None, 'receipt': settled, 'reason': 'invalid_provider_response'}
    return {'status': 'returned', 'text': text, 'receipt': settled}

def single_pass_mapping(prompt: str, config: dict, ledger_path, *, run: str, pins=None, transport=None, validator=None) -> dict:
    """B1 exactly one attempt. Caller validates mapping; malformed output stays failed."""
    result=generate_once(prompt,config,ledger_path,run=run,method='B1',pins=pins,transport=transport)
    if result['text'] is None:
        return dict(result, reason='single_pass_provider_failure')
    try:
        mapping=json.loads(result['text'])
        if type(mapping) is not dict: raise ValueError('mapping must be object')
    except (ValueError,TypeError):
        return {'status':'failed','reason':'malformed_single_pass_output','receipt':result['receipt']}
    if validator is None:
        return {'status':'unvalidated','mapping':mapping,'origin':'model','receipt':result['receipt']}
    try:
        validated = validator(mapping)
    except (ValueError, TypeError, KeyError):
        return {'status':'failed','reason':'invalid_single_pass_mapping','receipt':result['receipt']}
    return {'status':'proposed','mapping':validated,'origin':'model','receipt':result['receipt']}

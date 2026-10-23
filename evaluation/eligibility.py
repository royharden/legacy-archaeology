"""Closed evaluation identity/evidence contracts; no OS probes on import.

Hashes establish identity, not truthful execution. Observations additionally need
an operator-supplied cryptographic verifier and trusted issuer roles. Python ports
are not isolation boundaries; actual custody must be demonstrated externally.
"""
from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass
from typing import Callable

from .artifacts import canonical, digest, is_sha
from .benchmark import ARMS, FREEZE_KEYS, SPLITS


def closed(value: object, keys: set[str], label: str) -> dict:
    if not isinstance(value, dict) or set(value) != keys:
        raise ValueError(label + ': exact closed fields required')
    if 'schema_version' in keys and (type(value['schema_version']) is not int or value['schema_version'] != 1):
        raise ValueError(label + ': unsupported schema version')
    return deepcopy(value)


def text(value: object, label: str, maximum: int = 128) -> str:
    if not isinstance(value, str) or not value.strip() or len(value) > maximum or '\x00' in value:
        raise ValueError(label + ': nonempty bounded text required')
    return value


def hashes(value: dict, names) -> None:
    if any(not is_sha(value.get(name)) for name in names):
        raise ValueError('invalid SHA256 identity')


VARIANT_KEYS = {'variant_id', 'split', 'source_sha256', 'samples_sha256', 'brief_sha256',
                'oracle_sha256', 'canonical_sha256', 'layout_sha256'}


def variant_identity(case) -> dict:
    """Commit exact actual case inputs, never transform/decode them for gold."""
    import hashlib
    return {'variant_id': case.variant_id, 'split': case.split,
            'source_sha256': digest([batch.visible['source_sha256'] for batch in case.batches]),
            'samples_sha256': digest(case.visible['permitted_samples']),
            'brief_sha256': hashlib.sha256(case.visible['brief'].encode('utf-8')).hexdigest(),
            'oracle_sha256': digest([row for batch in case.batches for row in batch.oracle]),
            'canonical_sha256': digest([row['fields'] for batch in case.batches for row in batch.oracle]),
            'layout_sha256': digest(case.expected_layout)}


def validate_commitment(value: dict) -> dict:
    item = closed(value, {'schema_version', 'stage', 'edition', 'family', 'variants',
                         'sealed_assets_sha256', 'nonce', 'commitment_sha256'}, 'T0')
    if item['stage'] != 'T0' or item['family'] != 'five-semantic-field-account-ledger-v1':
        raise ValueError('wrong T0 stage/family')
    text(item['edition'], 'edition')
    hashes(item, ('sealed_assets_sha256', 'nonce', 'commitment_sha256'))
    if item['commitment_sha256'] != digest({key: val for key, val in item.items() if key != 'commitment_sha256'}):
        raise ValueError('T0 hash mismatch')
    if not isinstance(item['variants'], list) or len(item['variants']) != 18:
        raise ValueError('T0 seals the complete 6/4/8 family before tuning')
    ids, counts = set(), {split: 0 for split in SPLITS}
    for variant in item['variants']:
        closed(variant, VARIANT_KEYS, 'variant commitment')
        text(variant['variant_id'], 'variant_id')
        hashes(variant, VARIANT_KEYS - {'variant_id', 'split'})
        if variant['split'] not in counts or variant['variant_id'] in ids:
            raise ValueError('unknown split/duplicate variant')
        counts[variant['split']] += 1
        ids.add(variant['variant_id'])
    if counts != SPLITS:
        raise ValueError('T0 split counts must be 6/4/8')
    return item


def validate_freeze(value: dict, commitment: dict) -> dict:
    item = closed(value, {'schema_version', 'stage', 'edition', 'commitment_sha256', 'nonce',
                         'pins', 'freeze_sha256'}, 'T2')
    t0 = validate_commitment(commitment)
    if item['stage'] != 'T2' or item['edition'] != t0['edition'] or item['commitment_sha256'] != t0['commitment_sha256']:
        raise ValueError('T2 edition/commitment mismatch')
    hashes(item, ('commitment_sha256', 'nonce', 'freeze_sha256'))
    if item['nonce'] != t0['nonce']:
        raise ValueError('T2 nonce mismatch')
    closed(item['pins'], set(FREEZE_KEYS), 'frozen pins')
    hashes(item['pins'], FREEZE_KEYS)
    if item['freeze_sha256'] != digest({key: val for key, val in item.items() if key != 'freeze_sha256'}):
        raise ValueError('T2 hash mismatch')
    return item


def make_commitment(*, edition: str, variants: list[dict], sealed_assets_sha256: str, nonce: str) -> dict:
    item = {'schema_version': 1, 'stage': 'T0', 'edition': edition,
            'family': 'five-semantic-field-account-ledger-v1', 'variants': deepcopy(variants),
            'sealed_assets_sha256': sealed_assets_sha256, 'nonce': nonce}
    return validate_commitment({**item, 'commitment_sha256': digest(item)})


def make_freeze(commitment: dict, pins: dict) -> dict:
    t0 = validate_commitment(commitment)
    item = {'schema_version': 1, 'stage': 'T2', 'edition': t0['edition'],
            'commitment_sha256': t0['commitment_sha256'], 'nonce': t0['nonce'], 'pins': deepcopy(pins)}
    return validate_freeze({**item, 'freeze_sha256': digest(item)}, t0)


@dataclass(frozen=True)
class ReceiptVerifier:
    """Trusted operator configuration, never populated from a candidate JSON file.

    verify_signature(key_id, canonical_payload, signature) must implement actual
    cryptography. Issuer roles/key trust and the verifier itself stay evaluator-
    owned; inference must have neither signing keys nor a signing/broker endpoint.
    A verifier that returns True unconditionally is invalid operator setup.
    """
    trusted_issuers: dict[str, tuple[str, str]]  # key_id -> (issuer, role)
    verify_signature: Callable[[str, bytes, str], bool]

    def verify(self, receipt: dict, role: str) -> dict:
        envelope = closed(receipt, {'schema_version', 'issuer', 'key_id', 'role', 'payload',
                                    'payload_sha256', 'signature'}, 'signed receipt')
        for key in ('issuer', 'key_id', 'role'):
            text(envelope[key], key)
        if self.trusted_issuers.get(envelope['key_id']) != (envelope['issuer'], role) or envelope['role'] != role:
            raise ValueError('untrusted evidence issuer/role')
        text(envelope['signature'], 'signature', 16384)
        if envelope['payload_sha256'] != digest(envelope['payload']):
            raise ValueError('signed payload hash mismatch')
        if self.verify_signature(envelope['key_id'], canonical(envelope['payload']), envelope['signature']) is not True:
            raise ValueError('evidence signature verification failed')
        return deepcopy(envelope['payload'])


ISOLATION_KINDS = {'inherited_handles', 'oracle_broker', 'network_route',
                   'inference_distribution', 'prompt_allowlist', 'independent_custody_review'}
PROBE_KEYS = {'schema_version', 'kind', 'edition', 'freeze_sha256', 'nonce', 'host',
              'identity', 'collector_sha256', 'observed_source_sha256', 'observed_config_sha256',
              'canary_file_sha256', 'canary_directory_sha256', 'observed_at', 'probes', 'observation_sha256'}


def validate_custody(probe_receipt: dict, review_receipts: list[dict], *, commitment: dict,
                     freeze: dict, verifier: ReceiptVerifier, expected_identity: str,
                     expected_host: str, collector_sha256: str) -> dict:
    """Check actual observation lineage/signatures; booleans are not inputs.

    The returned status refers to verified evidence, not an OS probe performed by
    this validator. Honest receipt collection and trusted signatures are external
    prerequisites; structural JSON validation alone cannot establish isolation.
    """
    t2 = validate_freeze(freeze, commitment)
    probe = closed(verifier.verify(probe_receipt, 'canary_observer'), PROBE_KEYS, 'canary observation')
    if probe['kind'] != 'observed_canary_probe':
        raise ValueError('actual canary observation kind required')
    for key, expected in (('edition', t2['edition']), ('freeze_sha256', t2['freeze_sha256']),
                          ('nonce', t2['nonce']), ('host', expected_host), ('identity', expected_identity),
                          ('collector_sha256', collector_sha256),
                          ('observed_source_sha256', t2['pins']['release_sha256']),
                          ('observed_config_sha256', t2['pins']['config_sha256'])):
        if probe[key] != expected:
            raise ValueError('stale/wrong canary subject: ' + key)
    hashes(probe, ('freeze_sha256', 'nonce', 'collector_sha256', 'observed_source_sha256',
                   'observed_config_sha256', 'canary_file_sha256', 'canary_directory_sha256', 'observation_sha256'))
    text(probe['observed_at'], 'observation time')
    if probe['observation_sha256'] != digest({key: val for key, val in probe.items() if key != 'observation_sha256'}):
        raise ValueError('canary observation hash mismatch')
    if not isinstance(probe['probes'], list) or len(probe['probes']) != 3:
        raise ValueError('all absolute/relative/list observations required')
    seen = set()
    for result in probe['probes']:
        closed(result, {'operation', 'result', 'errno', 'winerror', 'exception_type'}, 'probe result')
        if result['operation'] not in ('absolute_open', 'relative_open', 'directory_list') or result['operation'] in seen:
            raise ValueError('duplicate/unknown canary operation')
        seen.add(result['operation'])
        if result['result'] != 'denied' or result['exception_type'] != 'PermissionError':
            raise ValueError('accessible/missing/unsupported canary is not demonstrated denial')
        if any(result[key] is not None and type(result[key]) is not int for key in ('errno', 'winerror')):
            raise ValueError('OS error observations must use exact integers or null')
        if result['errno'] not in (1, 13) and result['winerror'] != 5:
            raise ValueError('unrecognized access-denial observation')
    if not isinstance(review_receipts, list) or len(review_receipts) != len(ISOLATION_KINDS):
        raise ValueError('handle/broker/network/distribution/allowlist/independent evidence required')
    kinds, captures = set(), set()
    for receipt in review_receipts:
        review = closed(verifier.verify(receipt, 'isolation_reviewer'),
                        {'schema_version', 'kind', 'edition', 'freeze_sha256', 'nonce', 'probe_sha256',
                         'host', 'identity', 'capture_sha256', 'finding'}, 'isolation observation')
        if review['kind'] not in ISOLATION_KINDS or review['kind'] in kinds:
            raise ValueError('duplicate/missing isolation evidence class')
        for key, expected in (('edition', t2['edition']), ('freeze_sha256', t2['freeze_sha256']),
                              ('nonce', t2['nonce']), ('probe_sha256', probe['observation_sha256']),
                              ('host', expected_host), ('identity', expected_identity)):
            if review[key] != expected:
                raise ValueError('isolation observation subject mismatch')
        if review['finding'] != 'excluded' or not is_sha(review['capture_sha256']):
            raise ValueError('isolation property remains unverified/not excluded')
        if review['capture_sha256'] in captures:
            raise ValueError('distinct actual isolation captures required')
        kinds.add(review['kind']); captures.add(review['capture_sha256'])
    return {'schema_version': 1, 'eligibility_level': 'verified_observation_receipts',
            'edition': t2['edition'], 'freeze_sha256': t2['freeze_sha256'],
            'probe_sha256': probe['observation_sha256'], 'custody_sha256': digest([probe_receipt, *review_receipts]),
            'limitation': 'Trusted external collectors/reviewers attest effects; validator did not probe OS'}


def validate_suite(value: dict, commitment: dict, freeze: dict) -> dict:
    t2 = validate_freeze(freeze, commitment)
    item = closed(value, {'schema_version', 'stage', 'edition', 'attempt_id', 'mode',
                         'commitment_sha256', 'freeze_sha256', 'nonce', 'methods',
                         'variant_ids', 'capture_root_sha256', 'suite_sha256'}, 'T3')
    if item['stage'] != 'T3' or item['mode'] not in ('rules', 'mock', 'live'):
        raise ValueError('wrong suite stage/mode')
    for key in ('edition', 'commitment_sha256', 'freeze_sha256', 'nonce'):
        if item[key] != t2[key]:
            raise ValueError('T3 frozen identity mismatch')
    text(item['attempt_id'], 'attempt_id')
    if item['methods'] != list(ARMS):
        raise ValueError('exact single predeclared five-arm suite required')
    expected = sorted(variant['variant_id'] for variant in commitment['variants'] if variant['split'] == 'heldout')
    if item['variant_ids'] != expected:
        raise ValueError('all eight exact heldout variants required')
    hashes(item, ('capture_root_sha256', 'suite_sha256'))
    if item['suite_sha256'] != digest({key: val for key, val in item.items() if key != 'suite_sha256'}):
        raise ValueError('T3 hash mismatch')
    return item

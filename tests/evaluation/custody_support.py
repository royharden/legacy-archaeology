"""Synthetic signed contract fixtures SOURCE, not observed OS custody.

These fixed test-only keys never represent a real account/authority. Unit checks
of signatures/pins/state do not constitute a demonstrated hidden environment.
"""
from copy import deepcopy
from dataclasses import replace
import hashlib
from pathlib import Path

from evaluator_support import case
from evaluation.artifacts import canonical, digest
from evaluation.benchmark import ARMS, FREEZE_KEYS, SPLITS
from evaluation.eligibility import (ReceiptVerifier, ISOLATION_KINDS, make_commitment,
                                    make_freeze, variant_identity)
from evaluation.edition_registry import EditionRegistry, EligibilityContext

TEST_KEY = b'unit-fixture-only-not-an-operator-secret'
ROLES = {'owner': ('synthetic-owner', 'run_owner'),
         'observer': ('synthetic-observer', 'canary_observer'),
         'reviewer': ('synthetic-reviewer', 'isolation_reviewer')}


def sign(payload, key='owner'):
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    issuer, role = ROLES[key]
    # Deterministic test-only seeds; no key generation/provisioning occurs now.
    private = Ed25519PrivateKey.from_private_bytes(hashlib.sha256(TEST_KEY + key.encode()).digest())
    signature = private.sign(canonical(payload)).hex()
    return {'schema_version': 1, 'algorithm': 'Ed25519', 'issuer': issuer, 'key_id': key, 'role': role,
            'payload': deepcopy(payload), 'payload_sha256': digest(payload), 'signature': signature}


def verifier():
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    keys = {key: Ed25519PrivateKey.from_private_bytes(hashlib.sha256(TEST_KEY + key.encode()).digest())
             .public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
            for key in ROLES}
    return ReceiptVerifier(dict(ROLES), keys)


def synthetic_context(directory, store):
    probe_case = replace(case(), variant_id='heldout-00', split='heldout',
                         edition='synthetic-contract-edition', expected_layout=[])
    variants = []
    for split, count in SPLITS.items():
        for index in range(count):
            identity = {name: digest([split, index, name]) for name in
                        ('source_sha256', 'samples_sha256', 'brief_sha256', 'oracle_sha256',
                         'canonical_sha256', 'layout_sha256', 'visible_sha256')}
            variants.append({'variant_id': f'{split}-{index:02d}', 'split': split, **identity})
    variants[-8] = variant_identity(probe_case)
    t0 = make_commitment(edition=probe_case.edition, variants=variants,
                         sealed_assets_sha256=digest('synthetic seal'), nonce=digest('synthetic nonce'))
    pins = {key: digest(['synthetic pin', key]) for key in FREEZE_KEYS}
    freeze = make_freeze(t0, pins)
    registry = EditionRegistry(Path(directory) / 'edition-journal.sqlite', store)
    registry.register(t0, request_id='register', expected_head=None)
    registry.freeze(freeze, request_id='freeze', expected_head=registry.head)
    suite = {'schema_version': 1, 'stage': 'T3', 'edition': t0['edition'], 'attempt_id': 'synthetic-attempt',
             'mode': 'mock', 'commitment_sha256': t0['commitment_sha256'], 'freeze_sha256': freeze['freeze_sha256'],
             'nonce': t0['nonce'], 'methods': list(ARMS),
             'variant_ids': sorted(v['variant_id'] for v in variants if v['split'] == 'heldout'),
             'capture_root_sha256': digest(str(store.root))}
    suite['suite_sha256'] = digest(suite)
    probe = {'schema_version': 1, 'kind': 'observed_canary_probe', 'edition': t0['edition'],
             'freeze_sha256': freeze['freeze_sha256'], 'nonce': t0['nonce'], 'host': 'synthetic-host',
             'identity': 'synthetic-inference-principal', 'collector_sha256': digest('synthetic collector'),
             'observed_source_sha256': pins['release_sha256'], 'observed_config_sha256': pins['config_sha256'],
             'canary_file_sha256': digest('synthetic canary file'),
             'canary_directory_sha256': digest('synthetic canary directory'), 'observed_at': '2026-01-01T00:00:00Z',
             'probes': [{'operation': operation, 'result': 'denied', 'errno': 13,
                         'winerror': None, 'exception_type': 'PermissionError'}
                        for operation in ('absolute_open', 'relative_open', 'directory_list')]}
    probe['observation_sha256'] = digest(probe)
    signed_probe = sign(probe, 'observer')
    findings = {'inherited_handles': 'no_oracle_handle', 'oracle_broker': 'no_oracle_endpoint',
                'network_route': 'no_oracle_route', 'inference_distribution': 'evaluator_and_hidden_absent',
                'prompt_allowlist': 'visible_only', 'independent_custody_review': 'candidate_bound_review_complete'}
    reviews = []
    for kind in sorted(ISOLATION_KINDS):
        capture = {'schema_version': 1, 'kind': kind, 'edition': t0['edition'], 'freeze_sha256': freeze['freeze_sha256'],
            'nonce': t0['nonce'], 'host': probe['host'], 'identity': probe['identity'],
            'observed_at': probe['observed_at'], 'collector_sha256': digest(['synthetic collector', kind]),
            'source_sha256': pins['release_sha256'], 'config_sha256': pins['config_sha256'],
            'observations': [{'check_id': kind, 'subject_sha256': digest(['synthetic subject', kind]),
                              'observed_value': findings[kind]}]}
        reference = store.put('isolation_capture', capture)
        review = {'schema_version': 1, 'kind': kind, 'edition': t0['edition'], 'freeze_sha256': freeze['freeze_sha256'],
            'nonce': t0['nonce'], 'probe_sha256': probe['observation_sha256'], 'host': probe['host'],
            'identity': probe['identity'], 'capture_sha256': reference['sha256'], 'finding': 'excluded'}
        reviews.append(sign(review, 'reviewer'))
    authority = {'schema_version': 1, 'action': 'execute_suite', 'edition': t0['edition'],
        'suite_sha256': suite['suite_sha256'], 'freeze_sha256': freeze['freeze_sha256'], 'nonce': t0['nonce'],
        'mode': 'mock', 'capture_root_sha256': suite['capture_root_sha256'], 'identity': probe['identity'],
        'host': probe['host'], 'collector_sha256': probe['collector_sha256'], 'spend_authority_sha256': None,
        'registry_sha256': digest(str(registry.path))}
    signed_authority = sign(authority)
    for receipt in (signed_probe, *reviews, signed_authority):
        store.put('signed_evidence', receipt)
    return EligibilityContext(registry, t0, freeze, suite, signed_probe, reviews, signed_authority, verifier()), probe_case

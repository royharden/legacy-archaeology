"""Operator-configured Ed25519 public-key verification for disposable target intent.

Uses the same closed signed-receipt envelope as evaluator custody. No signing
key, callback verifier, account, filesystem credential or gold is accepted/read.
"""
from dataclasses import dataclass
from copy import deepcopy
import re

from la.review import canonical, digest


@dataclass(frozen=True)
class TargetAuthorityVerifier:
    trusted_issuers: dict[str, tuple[str, str]]
    public_keys: dict[str, bytes]

    def __post_init__(self):
        if not isinstance(self.trusted_issuers, dict) or not self.trusted_issuers or not isinstance(self.public_keys, dict) or set(self.public_keys) != set(self.trusted_issuers) or any(type(key) is not bytes or len(key) != 32 for key in self.public_keys.values()) or len(set(self.public_keys.values())) != len(self.public_keys):
            raise ValueError('distinct configured Ed25519 public keys required')
        for key_id, identity in self.trusted_issuers.items():
            if not isinstance(key_id, str) or not key_id or not isinstance(identity, tuple) or len(identity) != 2 or not isinstance(identity[0], str) or not identity[0] or identity[1] != 'target_authority':
                raise ValueError('trusted target issuer/role mapping required')

    def verify(self, receipt):
        keys = {'schema_version', 'algorithm', 'issuer', 'key_id', 'role', 'payload', 'payload_sha256', 'signature'}
        if not isinstance(receipt, dict) or set(receipt) != keys or type(receipt['schema_version']) is not int or receipt['schema_version'] != 1 or receipt['algorithm'] != 'Ed25519' or receipt['role'] != 'target_authority':
            raise ValueError('closed signed Ed25519 target authority required')
        if any(not isinstance(receipt[key], str) or not receipt[key] or len(receipt[key]) > 200 for key in ('issuer', 'key_id')):
            raise ValueError('exact trusted target issuer/key ID required')
        if self.trusted_issuers.get(receipt['key_id']) != (receipt['issuer'], 'target_authority') or receipt['payload_sha256'] != digest(receipt['payload']):
            raise ValueError('untrusted target issuer or changed signed payload')
        signature = receipt['signature']
        if not isinstance(signature, str) or re.fullmatch('[0-9a-f]{128}', signature) is None:
            raise ValueError('exact Ed25519 signature required')
        try:
            from cryptography.exceptions import InvalidSignature, UnsupportedAlgorithm
            from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
        except ImportError:
            raise ValueError('Ed25519 dependency unavailable; target authority remains unverified') from None
        try:
            Ed25519PublicKey.from_public_bytes(self.public_keys[receipt['key_id']]).verify(
                bytes.fromhex(signature), canonical(receipt['payload']).encode('utf-8'))
        except (InvalidSignature, UnsupportedAlgorithm):
            raise ValueError('target authority signature verification failed') from None
        return deepcopy(receipt['payload'])


def verified_target_authority(receipt, verifier):
    if type(verifier) is not TargetAuthorityVerifier:
        raise ValueError('concrete configured target signature verifier required; callbacks forbidden')
    return verifier.verify(receipt)

"""Read only explicitly selected non-secret public-key profiles, never signers.

The profile is operator configuration outside candidate/authority payloads. No
candidate field can choose a key or mark signature verification successful.
"""
from pathlib import Path
import re

from .artifacts import within,read


def public_keys(root,name):
    profile=read(within(Path(root).resolve(),name,exists=True),limit=64*1024)
    if (type(profile) is not dict or set(profile)!={'schema_version','trusted_issuers','public_keys'}
            or type(profile['schema_version']) is not int or profile['schema_version']!=1):
        raise ValueError('closed non-secret public trust profile required')
    issuers,keys=profile['trusted_issuers'],profile['public_keys']
    if type(issuers) is not dict or type(keys) is not dict or not 1<=len(issuers)<=16 or set(issuers)!=set(keys):
        raise ValueError('bounded explicit trusted issuer/public key mapping required')
    trusted={}; raw={}
    for key_id,value in issuers.items():
        if type(key_id) is not str or re.fullmatch(r'[A-Za-z0-9._-]{1,64}',key_id) is None:
            raise ValueError('invalid public key identifier')
        if type(value) is not dict or set(value)!={'issuer','role'}:
            raise ValueError('issuer and role required, no private-key fields')
        if any(type(value[k]) is not str or not 1<=len(value[k])<=128 for k in ('issuer','role')):
            raise ValueError('bounded issuer/role labels required')
        encoded=keys[key_id]
        if type(encoded) is not str or re.fullmatch('[0-9a-f]{64}',encoded) is None:
            raise ValueError('Ed25519 public key must be32 bytes in lowercase hex')
        trusted[key_id]=(value['issuer'],value['role']); raw[key_id]=bytes.fromhex(encoded)
    if len(set(raw.values()))!=len(raw): raise ValueError('distinct trusted public keys required')
    return trusted,raw

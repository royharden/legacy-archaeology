"""Explicit v2 product observation CLI; no evaluator import/gold or implicit load."""
import os
import re
from pathlib import Path
from urllib.parse import urlsplit

from la.contracts import digest
from .artifacts import within,read,checked_receipt,receipt,pointer
from .storage import pointer_token
from .public_trust import public_keys


def target_dsn(name,config):
    """Read only the named environment value after caller verifies authority."""
    if type(name) is not str or re.fullmatch('[A-Z][A-Z0-9_]{0,99}',name) is None:
        raise ValueError('environment variable NAME required, never a DSN argument')
    value=os.environ.get(name)
    if not value: return None
    try:
        parsed=urlsplit(value)
        if (parsed.scheme not in ('postgres','postgresql') or parsed.hostname!='127.0.0.1'
                or parsed.port is None or not 20000<=parsed.port<=29999 or parsed.port in (20178,20179)
                or parsed.query or parsed.fragment or parsed.hostname!=config.host or parsed.port!=config.port):
            raise ValueError('outside target URI policy')
    except ValueError:
        raise ValueError('target DSN is outside explicit claimed loopback policy') from None
    return value


def execute_observation(root,args):
    bundle=within(root,args.bundle,exists=True)
    if args.command=='database-recover' and args.negative:
        raise ValueError('read-only recovery never repeats negative probes')
    if not args.authority or not args.target_config or not args.public_trust_root or not args.public_trust_profile:
        return receipt(root,'target-observation',dict(observation=None,target_validation='not_run',row_parity='not_run',
            product_acceptance='pending',reason='signed_authority_pinned_target_and_operator_public_trust_required'))
    from la.postgres.authority import TargetAuthorityVerifier
    from la.postgres.target import TargetConfig
    from la.postgres.candidate import resolve_candidate,verify_authority
    from la.postgres.runner import target_observer_v2,reconcile_target_candidate
    authority=read(within(root,args.authority,exists=True))
    verifier=TargetAuthorityVerifier(*public_keys(args.public_trust_root,args.public_trust_profile))
    intent=verifier.verify(authority)
    config=TargetConfig(**read(within(root,args.target_config,exists=True))).validate()
    artifact={'kind':'product_bundle','bundle_path':str(bundle)}
    prepared=resolve_candidate(artifact,config)
    verify_authority(intent,prepared,config,'reconcile' if args.command=='database-recover' else 'load')
    if args.negative: verify_authority(intent,prepared,config,'negative_probes')
    # Neither missing/invalid public trust nor a mismatched candidate reaches an
    # environment read or a connection. A missing DSN stays a real not_run wire.
    dsn=target_dsn(args.dsn_env,config)
    if args.command=='database-recover':
        original=checked_receipt(root,args.observation_receipt,kind='target-observation')['payload']['observation']
        observed=reconcile_target_candidate(artifact,authority,original,dsn=dsn,target_config=config,authority_verifier=verifier)
    else:
        observed=target_observer_v2(artifact,authority,dsn=dsn,target_config=config,
            negative_kinds=tuple(args.negative),authority_verifier=verifier)
    payload=dict(source_sha256=prepared.descriptor['source_sha256'],mapping_sha256=prepared.descriptor['mapping_sha256'],
        bundle_sha256=prepared.descriptor['candidate_sha256'],observation=observed,product_acceptance='pending')
    relative=bundle.relative_to(root)
    destination=within(root,relative.parts[0]) if len(relative.parts)>=3 and relative.parts[1]=='bundles' else root
    saved=receipt(destination,'target-observation',payload)
    index=within(destination,'current-target-observation.json')
    pointer(index,{'relative_path':str(Path(saved['path']).relative_to(destination))},expected=pointer_token(index))
    return saved

"""Ready evaluator-owned T1/T3 caller factory. No signer or hidden asset creation.

Operator trust comes from explicit CLI public-profile arguments, never candidate
JSON. The packet names only existing metadata/evidence under its declared root.
"""
from pathlib import Path


def factory(context):
    from la.app.artifacts import within,read
    from la.app.public_trust import public_keys
    from evaluation.eligibility import ReceiptVerifier
    from evaluation.edition_registry import EditionRegistry,EligibilityContext
    from evaluation.public_live import PublicLiveContext,BillingAdapter
    from la.providers.live import priced_usage,validate_config
    from la.contracts import digest
    if type(context) is not dict or set(context)!={'store','evidence_root','packet','public_trust_root','public_trust_profile','billing_config'}:
        raise ValueError('explicit evaluator store/root/public trust required')
    root=Path(context['evidence_root']).resolve(strict=True)
    packet=context['packet']
    common={'phase','registry','authority_receipt'}
    phase=packet.get('phase') if type(packet) is dict else None
    required=common|({'catalog'} if phase=='T1' else {'commitment','freeze','suite','probe_receipt','review_receipts'})
    if type(packet) is not dict or phase not in ('T1','T3') or set(packet)!=required:
        raise ValueError('closed explicit T1 or T3 context packet required')
    verifier=ReceiptVerifier(*public_keys(context['public_trust_root'],context['public_trust_profile']))
    registry=EditionRegistry(within(root,packet['registry'],exists=True),context['store'])
    authority=read(within(root,packet['authority_receipt'],exists=True))
    verifier.verify(authority,'run_owner')
    context['store'].put('signed_evidence',authority)
    if phase=='T1':
        catalog=read(within(root,packet['catalog'],exists=True))
        if catalog.get('kind')=='public-catalog':
            if catalog.get('receipt_sha256')!=digest({k:v for k,v in catalog.items() if k not in ('receipt_sha256','path')}):
                raise ValueError('public catalog wrapper identity mismatch')
            catalog=catalog['payload']
        result=PublicLiveContext(registry,catalog,authority,verifier,
                                 BillingAdapter(validate_config(context['billing_config']),priced_usage))
    else:
        reviews=packet['review_receipts']
        if type(reviews) is not list or len(reviews)!=6:
            raise ValueError('six distinct isolation review receipt paths required')
        probe=read(within(root,packet['probe_receipt'],exists=True))
        review_values=[read(within(root,name,exists=True)) for name in reviews]
        verifier.verify(probe,'canary_observer'); context['store'].put('signed_evidence',probe)
        for review in review_values:
            verifier.verify(review,'isolation_reviewer'); context['store'].put('signed_evidence',review)
        result=EligibilityContext(registry,read(within(root,packet['commitment'],exists=True)),
            read(within(root,packet['freeze'],exists=True)),read(within(root,packet['suite'],exists=True)),
            probe,review_values,authority,verifier)
    result.validate()
    return result

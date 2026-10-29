"""Closed provider protocol metadata; external usage remains bounded opaque JSON."""
from la.contracts.protocol import closed,identity,integer,text,opaque_json

REQUEST_KEYS={'prompt_sha256','source_sha256','framing_sha256','brief_sha256','sample_artifact_sha256',
    'sample_selection_sha256','sample_spans_sha256','prompt_bytes','offered_candidate_ids_sha256',
    'candidate_count','prompted_candidate_count','sample_truncated','prompt_policy_sha256','generation_sha256',
    'evaluator_method','gateway_prompt_sha256','evaluation_phase','evaluation_authority_sha256'}
ACCOUNT_KEYS={'provider','model','model_version','price_version','price_evidence_date','config_sha256',
    'price_evidence_sha256','authority_id','api_version_pin'}
SETTLEMENT_KEYS={'reason','latency_seconds','response_sha256','returned_model','provider_output_status','raw_usage'}


def request_pins(value,*,accounting=False):
    closed(value,(),REQUEST_KEYS|(ACCOUNT_KEYS if accounting else set()))
    for key,item in value.items():
        if key.endswith('_sha256'):
            if item is None and key=='generation_sha256': continue
            identity(item)
        elif key in ('candidate_count','prompted_candidate_count'): integer(item,0,480)
        elif key=='prompt_bytes': integer(item,1,8000)
        elif key=='sample_truncated':
            if type(item) is not bool: raise ValueError('exact sample truncation boolean required')
        elif key=='evaluator_method':
            if item not in ('B1','C0','R0','R1'): raise ValueError('unknown evaluator request arm')
        elif key=='evaluation_phase':
            if item not in ('T1','T3'): raise ValueError('unknown explicit provider evaluation phase')
        else: text(item,256)
    if ('evaluation_phase' in value)!=('evaluation_authority_sha256' in value):
        raise ValueError('evaluation phase and authority must be supplied together')
    return value


def settlement_fields(value):
    closed(value,(),SETTLEMENT_KEYS)
    for key,item in value.items():
        if key=='raw_usage': opaque_json(item)
        elif key.endswith('_sha256'): identity(item)
        elif item is not None: text(item,512)
    return value

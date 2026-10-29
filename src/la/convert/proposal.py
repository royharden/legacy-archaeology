"""Non-loadable evaluator proposals. No fictitious product ruling or approval is created."""
from __future__ import annotations

from la.contracts import validate_batch
from la.review import REQUIRED, digest
from la.review.policy import validate_policy

ARMS = {'B0', 'B1', 'C0', 'R0', 'R1'}
ORIGINS = {'rules', 'model', 'finite_candidates', 'agent_provisional'}
CORE = {'start', 'end', 'semantic_target', 'data_type', 'policy'}


def validate_proposal(batch, proposal):
    batch = validate_batch(batch)
    allowed = {'schema_version', 'kind', 'method', 'origin', 'source_sha256', 'framing_sha256',
               'width', 'fields', 'filler', 'proposal_sha256'}
    if not isinstance(proposal, dict) or set(proposal) != allowed:
        raise ValueError('strict evaluator proposal envelope required')
    if proposal['schema_version'] != 1 or type(proposal['schema_version']) is not int or proposal['kind'] != 'evaluator_proposal':
        raise ValueError('unsupported proposal kind/version')
    if proposal['method'] not in ARMS or proposal['origin'] not in ORIGINS:
        raise ValueError('declared comparator method/origin required')
    if proposal['method'] == 'B1' and proposal['origin'] != 'model':
        raise ValueError('B1 offsets must remain model-originated')
    if digest({k: v for k, v in proposal.items() if k != 'proposal_sha256'}) != proposal['proposal_sha256']:
        raise ValueError('proposal identity mismatch')
    for key in ('source_sha256', 'framing_sha256', 'width'):
        if proposal[key] != batch[key]:
            raise ValueError('proposal source/framing/width mismatch')
    width = proposal['width']
    if batch['status'] != 'accepted' or type(width) is not int or not 1 <= width <= 256:
        raise ValueError('proposal requires a resolved eligible source')
    if not isinstance(proposal['fields'], list) or len(proposal['fields']) != len(REQUIRED):
        raise ValueError('complete five-field evaluator proposal required')
    names, covered = set(), set()
    for field in proposal['fields']:
        if not isinstance(field, dict) or not CORE <= field.keys() or field.keys() - CORE - {'id', 'evidence', 'origin', 'uncertainty'}:
            raise ValueError('unknown proposal field member')
        if field.get('origin', proposal['origin']) not in ORIGINS | {'mock'}:
            raise ValueError('invalid proposal field origin')
        if proposal['method'] == 'B1' and field.get('origin', 'model') != 'model':
            raise ValueError('B1 field origin cannot be relabeled as product rules')
        target = field['semantic_target']
        if target not in REQUIRED or target in names:
            raise ValueError('missing/duplicate/wrong semantic target')
        names.add(target)
        start, end = field['start'], field['end']
        if type(start) is not int or type(end) is not int or not 0 <= start < end <= width:
            raise ValueError('invalid proposal field span')
        span = set(range(start, end))
        if covered & span:
            raise ValueError('overlapping proposal spans')
        covered |= span
        validate_policy(field)
    if not isinstance(proposal['filler'], list):
        raise ValueError('explicit filler list required')
    for filler in proposal['filler']:
        if not isinstance(filler, dict) or set(filler) != {'start', 'end'}:
            raise ValueError('invalid proposal filler')
        start, end = filler['start'], filler['end']
        if type(start) is not int or type(end) is not int or not 0 <= start < end <= width or covered & set(range(start, end)):
            raise ValueError('invalid proposal filler coverage')
        covered |= set(range(start, end))
    if names != set(REQUIRED) or covered != set(range(width)):
        raise ValueError('incomplete proposal coverage')
    return {'schema_version': 1, 'proposal_sha256': proposal['proposal_sha256'],
            'method': proposal['method'], 'origin': proposal['origin'],
            'validation_status': 'complete_proposal', 'loadable': False,
            'product_approval': 'absent', 'runtime_validation': 'not_run'}


def transform_proposal(batch, proposal):
    """Return deterministic outcomes for scoring only; hash is a proposal, never an approval."""
    from . import _transform_records
    validation = validate_proposal(batch, proposal)
    descriptor = {'mapping_sha256': proposal['proposal_sha256'], 'mapping_status': 'complete',
                  'width': proposal['width'], 'fields': proposal['fields'], 'unresolved': []}
    outcomes = _transform_records(validate_batch(batch), descriptor)
    for outcome in outcomes:
        outcome['evidence']['proposal'] = {'proposal_sha256': proposal['proposal_sha256'],
                                           'method': proposal['method'], 'origin': proposal['origin'],
                                           'loadable': False, 'product_approval': 'absent'}
    return {'schema_version': 1, 'proposal': validation, 'outcomes': outcomes,
            'target_validation': 'not_run', 'row_parity': 'not_run', 'product_acceptance': 'pending'}

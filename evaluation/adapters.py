"""Explicit evaluator wire projections; all product functions are injected ports.

No oracle construction imports inference, review, conversion or target algorithms.
Comparator proposals remain non-loadable and never manufacture product events.
"""
from __future__ import annotations

from copy import deepcopy

from .artifacts import digest, is_sha

PROPOSAL_KEYS = {'schema_version', 'kind', 'method', 'origin', 'source_sha256',
                 'framing_sha256', 'width', 'fields', 'filler', 'proposal_sha256'}


def project_product_question(question: dict) -> dict:
    """Keep product-only metadata locally; broker receives offered IDs only."""
    if not is_sha(question.get('source_sha256')) or not is_sha(question.get('generation_binding')):
        raise ValueError('product Question source/generation binding required')
    broker = {'schema_version': 1, 'id': question['id'], 'source_sha256': question['source_sha256'],
              'dependency_sha256': digest(question), 'prompt': question['prompt'],
              'options': [{'id': option['id']} for option in question['options']],
              'evidence': deepcopy(question.get('evidence', []))}
    return {'question': broker, 'provenance': {'semantic_target': question['semantic_target'],
            'generation_binding': question['generation_binding'], 'source_question_sha256': digest(question)}}


def _ingest(visible: dict, ingest):
    return ingest(bytes.fromhex(visible['source_hex']), visible['brief'],
                  deepcopy(visible['permitted_samples']))


def _bind(proposal: dict, batch: dict) -> dict:
    """Rebind one layout proposal to an exact batch; never approval/ruling lineage."""
    result = {key: deepcopy(value) for key, value in proposal.items() if key in PROPOSAL_KEYS}
    if set(result) != PROPOSAL_KEYS or result.get('kind') != 'evaluator_proposal':
        raise ValueError('explicit evaluator proposal required')
    for key in ('source_sha256', 'framing_sha256', 'width'):
        result[key] = batch[key]
    result['proposal_sha256'] = digest({key: value for key, value in result.items() if key != 'proposal_sha256'})
    return result


def validate_evaluator_proposal(proposal: dict, visible: dict, *, ingest, validate_proposal) -> dict:
    """Runner validate_mapping adapter for la.convert.proposal.validate_proposal.

    Inference first supplies a source-bound strict proposal. Rebinding here cannot
    conceal a wrong source on its original inference input.
    """
    batch = _ingest(visible, ingest)
    if set(proposal) != PROPOSAL_KEYS:
        raise ValueError('strict proposal envelope required')
    receipt = validate_proposal(batch, deepcopy(proposal))
    if (receipt.get('validation_status') != 'complete_proposal' or receipt.get('loadable') is not False
            or receipt.get('product_approval') != 'absent'):
        raise ValueError('non-loadable proposal validation receipt required')
    return {**deepcopy(proposal), 'mapping_status': 'complete', 'loadable': False,
            'product_approval': 'absent', 'validation_receipt': receipt}


def transform_evaluator_proposal(visible: dict, mapping: dict, *, ingest, transform_proposal) -> list[dict]:
    """Runner transform adapter for ten batches without fictitious product answers."""
    if mapping.get('loadable') is not False or mapping.get('product_approval') != 'absent':
        raise ValueError('only evaluator non-loadable proposals accepted')
    batch = _ingest(visible, ingest)
    result = transform_proposal(batch, _bind(mapping, batch))
    receipt = result.get('proposal', {})
    if receipt.get('loadable') is not False or receipt.get('product_approval') != 'absent':
        raise ValueError('transform attempted to confer product approval')
    return result['outcomes']

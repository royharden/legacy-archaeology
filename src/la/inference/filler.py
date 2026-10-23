"""Explicit filler declarations; empty-looking bytes never approve themselves."""
from copy import deepcopy
from la.contracts import digest, validate_batch, validate_generation
from la.contracts.evidence import validate_discovery_metadata
from la.ingest.evidence import make_evidence, verify_records


def declare_filler(batch: dict, generation: dict, spans: list[dict], *, actor: str, reason: str) -> dict:
    """Return a new generation, invalidating all prior generation-bound rulings.

    This declaration is an input decision, not approval or a fabricated journal
    event. Product mapping/approval still requires the real journal lifecycle.
    Overlap with subsequently selected semantic fields remains a mapping error.
    """
    batch, generation = validate_batch(batch), validate_generation(generation)
    verify_records(batch)
    if digest({key: value for key, value in generation.items() if key != 'generation_sha256'}) != generation['generation_sha256']:
        raise ValueError('generation identity mismatch')
    if any(batch[key] != generation[key] for key in ('source_sha256', 'framing_sha256', 'brief_sha256')):
        raise ValueError('filler generation/source mismatch')
    if batch['status'] != 'accepted' or type(batch['width']) is not int:
        raise ValueError('filler requires accepted resolved framing')
    if not isinstance(actor, str) or not actor.strip() or len(actor) > 200 or not isinstance(reason, str) or not reason.strip() or len(reason) > 4000:
        raise ValueError('explicit filler actor and reason required')
    if not isinstance(spans, list) or len(spans) > 32:
        raise ValueError('filler span limit/type invalid')
    checked = []
    for span in spans:
        if not isinstance(span, dict) or set(span) != {'start', 'end'}:
            raise ValueError('filler requires exact start/end declarations')
        start, end = span['start'], span['end']
        if type(start) is not int or type(end) is not int or not 0 <= start < end <= batch['width']:
            raise ValueError('filler range invalid')
        checked.append({'start': start, 'end': end})
    checked.sort(key=lambda span: (span['start'], span['end']))
    if any(left['end'] > right['start'] for left, right in zip(checked, checked[1:])):
        raise ValueError('filler spans overlap')
    evidence = []
    for span in checked:
        seen = set()
        for sample in batch['samples'].get('authorized_spans', []):
            ordinal = sample['ordinal']
            if (ordinal not in seen and sample['start'] <= span['start'] and span['end'] <= sample['end']
                    and batch['records'][ordinal]['disposition'] == 'eligible'):
                evidence.append(make_evidence(batch, ordinal, span['start'], span['end']))
                seen.add(ordinal)
            if len(seen) == 3: break
    decision = {'schema_version': 1, 'kind': 'explicit_filler_declaration',
                'source_sha256': batch['source_sha256'], 'framing_sha256': batch['framing_sha256'],
                'brief_sha256': batch['brief_sha256'], 'prior_generation_sha256': generation['generation_sha256'],
                'spans': checked, 'actor': actor, 'reason': reason, 'evidence': evidence,
                'approval_status': 'unapproved', 'journal_events_created': 0}
    decision['declaration_sha256'] = digest(decision)
    value = deepcopy(generation)
    value['filler'] = checked
    discovery = value.setdefault('discovery', {})
    discovery['filler_declaration'] = decision
    discovery['discovery_sha256'] = digest({key: item for key, item in discovery.items() if key != 'discovery_sha256'})
    value['discovery'] = validate_discovery_metadata(discovery)
    value['policy_sha256'] = digest({'prior_policy_sha256': generation['policy_sha256'],
                                     'filler_declaration_sha256': decision['declaration_sha256']})
    value['generation_sha256'] = digest({key: item for key, item in value.items() if key != 'generation_sha256'})
    return validate_generation(value)

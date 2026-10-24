"""Trusted product callbacks for the separately invoked evaluator CLI.

No oracle, corpus/answer policy, evaluator storage or hidden context is accepted.
Proposals never create product events/approvals or become loadable bundles.
"""
from copy import deepcopy
from pathlib import Path


def factory(context,*,provider_authority=None):
    """Wire provider.preflight(request) into the evaluator's pre-reserve metering seam."""
    from evaluation.runner import RunnerPorts
    from la.contracts import REQUIRED_FIELDS, digest
    from la.ingest import ingest_bytes
    from la.inference import hypothesize
    from la.review import questions as product_questions
    from la.convert import validate_proposal, transform_proposal
    from la.providers.evaluation import provider_port
    if set(context) - {'provider_config', 'ledger_path', 'run', 'use_ranker'}:
        raise ValueError('unknown product ports context; evaluator data is forbidden')
    if type(context.get('use_ranker', False)) is not bool:
        raise ValueError('explicit ranker selection required')
    provider = provider_port(config=context.get('provider_config'),
        ledger_path=Path(context.get('ledger_path', '.la-runs/evaluator-provider.sqlite')),
        run=context.get('run', 'public-development'),trusted_authority=provider_authority)

    def batch(visible):
        value = ingest_bytes(bytes.fromhex(visible['source_hex']), visible['brief'], visible['permitted_samples'])
        if value['source_sha256'] != visible['source_sha256']:
            raise ValueError('visible source identity mismatch')
        if visible.get('framing_sha256') != value['framing_sha256']:
            raise ValueError('visible framing identity mismatch')
        return value

    def proposal(visible, fields, method, origin, filler=None):
        source = batch(visible)
        value = dict(schema_version=1, kind='evaluator_proposal', method=method, origin=origin,
                     source_sha256=source['source_sha256'], framing_sha256=source['framing_sha256'],
                     width=source['width'], fields=deepcopy(fields), filler=deepcopy(filler or []))
        return dict(value, proposal_sha256=digest(value))

    def heuristic(visible):
        generation = hypothesize(batch(visible), visible['brief'])
        # Bounded deterministic first-cover heuristic, no answers or model input.
        visited = 0
        width = batch(visible)['width']
        def select(index, fields, covered):
            nonlocal visited
            visited += 1
            if visited > 10000: return None
            if index == len(REQUIRED_FIELDS):
                return fields if width is not None and covered == set(range(width)) else None
            choices = sorted((c for c in generation['candidates'] if c['semantic_target'] == REQUIRED_FIELDS[index]),
                             key=lambda c: (c['start'], c['end'], c['id']))
            for choice in choices:
                span = set(range(choice['start'], choice['end']))
                if span & covered: continue
                chosen = select(index+1, fields+[choice], covered | span)
                if chosen is not None: return chosen
            return None
        fields = select(0, [], set()) or []
        return proposal(visible, fields, 'B0', 'rules')

    def candidates(visible, gateway):
        generation = hypothesize(batch(visible), visible['brief'])
        result = {'generation': generation, 'candidates': generation['candidates'], 'method': gateway.method}
        if context.get('use_ranker'):
            result['ranking'] = gateway.request('finite_candidate_ranking', generation['candidates'])
        return result

    def questions(value):
        result = []
        for item in product_questions(value['generation']):
            result.append(dict(schema_version=1, id=item['id'], kind=item['semantic_target'],
                source_sha256=item['source_sha256'], generation_sha256=value['generation']['generation_sha256'],
                dependency_sha256=item['generation_binding'], options=deepcopy(item['options']),
                candidate_ids=[o['id'] for o in item['options'] if o['id'] != 'unknown'],
                evidence=deepcopy(item['evidence']), prompt=item['prompt']))
        return result

    def mapping(visible, value, answers):
        generation = value['generation']
        offered = {c['id']: c for c in generation['candidates']}
        fields = []
        seen = set()
        original = {q['id']:q for q in product_questions(generation)}
        for answer in answers:
            question = original.get(answer['question_id'])
            selected = answer['option_id']
            if question is None or question['id'] in seen or selected not in {o['id'] for o in question['options']}:
                raise ValueError('answer does not select an offered original question')
            seen.add(question['id'])
            if selected != 'unknown': fields.append(offered[selected])
        # No answers means unresolved, even if a ranker has a preferred option.
        return proposal(visible, fields, value['method'], 'agent_provisional' if answers else 'finite_candidates', generation.get('filler', []))

    def validate(value, visible):
        if value.get('kind') != 'evaluator_proposal':
            # B1 returns only model field/filler proposal data, never product IDs,
            # source identity, SQL, row values, approval or supporting events.
            if set(value) != {'fields', 'filler'}: raise ValueError('strict B1 fields/filler output required')
            value = proposal(visible, value['fields'], 'B1', 'model', value['filler'])
        if value['method'] != 'B1' and len(value['fields']) != len(REQUIRED_FIELDS):
            if digest({k:v for k,v in value.items() if k != 'proposal_sha256'}) != value['proposal_sha256']:
                raise ValueError('partial proposal identity mismatch')
            return dict(mapping_status='incomplete', fields=value['fields'], evaluator_proposal=value, loadable=False)
        checked = validate_proposal(batch(visible), value)
        return dict(mapping_status='complete', fields=value['fields'], evaluator_proposal=value,
                    validation=checked, loadable=False)

    def transform(visible, value):
        template = value['evaluator_proposal']
        # Apply a non-loadable layout policy to the next batch under new explicit
        # source pins. This is never a reused source-bound product approval.
        bound = proposal(visible, template['fields'], template['method'], template['origin'], template['filler'])
        result = transform_proposal(batch(visible), bound)
        for row in result['outcomes']:
            row['evidence']['template_proposal_sha256'] = template['proposal_sha256']
        return result['outcomes']

    preflight = {}
    if 'provider_preflight' in RunnerPorts.__dataclass_fields__:
        preflight['provider_preflight'] = provider.preflight
    elif context.get('provider_config') is not None:
        raise ValueError('live product ports require evaluator provider_preflight support')
    return RunnerPorts(heuristic=heuristic, candidates=candidates, questions=questions,
        mapping=mapping, validate_mapping=validate, transform=transform, provider=provider,
        count_tokens=lambda text: len(text.encode('utf-8')), **preflight)

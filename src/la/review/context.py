"""Bounded resolver-backed presentation context; never a decision or approval."""
from la.contracts import validate_batch
from . import binding, digest, questions


def question_context(batch, generation, *, limit=12, options_limit=3, examples_limit=1,
                     authorized_only=True):
    if type(options_limit) is not int or not 0 <= options_limit <= 3 or type(examples_limit) is not int or not 0 <= examples_limit <= 3 or type(authorized_only) is not bool:
        raise ValueError('bounded exact explanation limits/access mode required')
    batch = validate_batch(batch)
    dependency = binding(generation)
    if any(batch[key] != generation[key] for key in ('source_sha256', 'framing_sha256', 'brief_sha256')):
        raise ValueError('stale question context generation')
    from la.inference.explanation import explain_candidate
    offered_questions = questions(generation, limit)
    contexts = {}
    for question in offered_questions:
        offered = [option['id'] for option in question['options'] if option['id'] != 'unknown']
        facts = [explain_candidate(batch, generation, option, authorized_only=authorized_only,
                                   examples_limit=examples_limit) for option in offered[:options_limit]]
        contexts[question['id']] = {'facts': facts, 'offered_count': len(offered),
                                   'unexplained_offered_count': max(0, len(offered) - len(facts)),
                                   'presentation_is_ranking': False, 'approval': 'absent',
                                   'unknown': explain_candidate(batch, generation, 'unknown',
                                                                authorized_only=authorized_only, examples_limit=0)}
    value = {'schema_version': 1, 'generation_binding': dependency,
             'source_sha256': batch['source_sha256'], 'framing_sha256': batch['framing_sha256'],
             'sample_artifact_sha256': batch['samples']['artifact_sha256'],
             'policy_sha256': generation['policy_sha256'], 'questions': offered_questions,
             'contexts': contexts, 'authorized_only': authorized_only}
    value['context_sha256'] = digest(value)
    return value

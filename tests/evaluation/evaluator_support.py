"""Hand-written gold and fake wires; no product parsing/conversion algorithms.

These are test source fixtures, not corpus generation or executed evidence.
"""
from copy import deepcopy
import hashlib
from pathlib import Path
import sys

# Allow future stdlib discovery from the outer shell without package installation.
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from evaluation.artifacts import digest
from evaluation.runner import BatchCase, VariantCase, RunnerPorts

SOURCE = b'000001A\n000002C\n000002C\n\xffxx\n'


def refs():
    result, offset = [], 0
    for ordinal, raw in enumerate((b'000001A', b'000002C', b'000002C', b'\xffxx')):
        result.append({'source_sha256': hashlib.sha256(SOURCE).hexdigest(),
                       'framing_sha256': 'f' * 64, 'ordinal': ordinal, 'byte_start': offset,
                       'length': len(raw), 'raw_sha256': hashlib.sha256(raw).hexdigest()})
        offset += len(raw) + 1
    return result


def gold():
    # Values are hand-written semantic truth, not decoded from SOURCE.
    fields = [
        {'account_ref': {'data_type': 'text', 'value': '000001'},
         'description': {'data_type': 'text', 'value': 'Alpha'},
         'balance': {'data_type': 'decimal', 'value': '12.34'},
         'effective_date': {'data_type': 'date', 'value': '2024-02-29'},
         'status': {'data_type': 'text', 'value': 'A'}},
        {'account_ref': {'data_type': 'text', 'value': '000002'},
         'description': {'data_type': 'text', 'value': ''},
         'balance': {'data_type': 'decimal', 'value': '-5.00'},
         'effective_date': {'data_type': 'date', 'value': None},
         'status': {'data_type': 'text', 'value': 'C'}},
    ]
    identities = refs()
    return [{'record_ref': identities[i], 'expected_outcome': 'converted',
             'fields': deepcopy(fields[0 if i == 0 else 1]), 'reasons': []} for i in range(3)] + [
        {'record_ref': identities[3], 'expected_outcome': 'quarantined', 'fields': {}, 'reasons': ['high_byte']}]


def product_rows():
    # Fake consumer observations are separately written literals, not gold passed
    # into a port. Tests intentionally make no claim about inference quality.
    values = [
        {'account_ref': '000001', 'description': 'Alpha', 'balance': '12.34',
         'effective_date': '2024-02-29', 'status': 'A'},
        {'account_ref': '000002', 'description': '', 'balance': '-5.00',
         'effective_date': None, 'status': 'C'},
        {'account_ref': '000002', 'description': '', 'balance': '-5.00',
         'effective_date': None, 'status': 'C'},
    ]
    identities = refs()
    return [{'record_ref': identities[i], 'outcome': 'converted', 'values': value, 'reasons': []}
            for i, value in enumerate(values)] + [
        {'record_ref': identities[3], 'outcome': 'quarantined', 'values': {}, 'reasons': ['high_byte']}]


def mapping():
    return {'mapping_status': 'complete', 'mapping_sha256': 'a' * 64,
            'source_sha256': refs()[0]['source_sha256'],
            'fields': [{'semantic_target': name, 'data_type': kind}
                       for name, kind in [('account_ref', 'text'), ('description', 'text'),
                                          ('balance', 'decimal'), ('effective_date', 'date'), ('status', 'text')]]}


def normalized():
    kinds = {field['semantic_target']: field['data_type'] for field in mapping()['fields']}
    return [{'record_ref': row['record_ref'], 'outcome': row['outcome'], 'reasons': row['reasons'],
             'fields': {name: {'data_type': kinds[name], 'value': value} for name, value in row['values'].items()}}
            for row in product_rows()]


def visible():
    identities = refs()
    samples = {'source_sha256': identities[0]['source_sha256'], 'authorization': 'synthetic test only',
               'records': [{'ordinal': i, 'raw_hex': SOURCE[ref['byte_start']:ref['byte_start'] + ref['length']].hex(),
                            'raw_sha256': ref['raw_sha256']} for i, ref in enumerate(identities[:3])]}
    samples['artifact_sha256'] = digest(samples)
    return {'schema_version': 1, 'source_hex': SOURCE.hex(), 'source_sha256': identities[0]['source_sha256'],
            'record_refs': identities, 'record_count': 4, 'brief': 'Synthetic account concepts only.',
            'permitted_samples': samples}


def case():
    return VariantCase('hand-layout', 'development', 'public-test-v1', visible(),
                       (BatchCase('batch-1', visible(), gold()),), {'q1': 'choice-a', 'q2': 'not-offered'})


def fake_ports(*, provider=None, observed_inputs=None, observed_answers=None, transform=None):
    def observe(value):
        if observed_inputs is not None:
            observed_inputs.append(deepcopy(value))

    def heuristic(value):
        observe(value)
        return mapping()

    def candidates(value, gateway):
        observe(value)
        return {'candidates': []}

    def questions(generation):
        return [{'id': qid, 'options': [{'id': 'choice-a'}, {'id': 'unknown'}]} for qid in ('q1', 'q2')]

    def resolve(value, generation, answers):
        if observed_answers is not None:
            observed_answers.append(deepcopy(answers))
        return mapping()

    def validate(proposal, value):
        if not isinstance(proposal, dict) or proposal.get('mapping_status') != 'complete':
            raise ValueError('fake validation rejects malformed proposal')
        return proposal

    def default_provider(request):
        return {'output': mapping(), 'usage': {'input_tokens': 50, 'output_tokens': 20},
                'cost_status': 'known', 'known_cost': '0', 'provider': 'fake', 'model': 'fake'}

    return RunnerPorts(heuristic, candidates, questions, resolve, validate,
                       transform or (lambda value, proposal: product_rows()), provider or default_provider)

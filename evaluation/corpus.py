"""Public canonical-first corpus construction SOURCE, not an executed corpus.

Local builders accept development only. Hidden editions are an externally injected
evaluator capability with edition/custody/seal gates; no hidden files are made here.
"""
from __future__ import annotations

from copy import deepcopy
from collections import Counter
from typing import Callable

from .artifacts import CaptureStore, digest, is_sha
from .benchmark import MALFORMED_KINDS, SPLITS, hidden_run_eligibility
from .generator import attach_refs, canonical_records, inject_malformed, serialize, sha


def development_layouts() -> list[dict]:
    configurations = [
        ('leading', 2, 'YYYYMMDD', 'right', 'LF', True, '99999999'),
        ('trailing', 3, 'YYMMDD', 'left', 'CRLF', False, '999999'),
        ('unsigned', 0, 'YYYYMMDD', 'right', 'LF', False, '        '),
        ('trailing', 2, 'YYYYMMDD', 'left', 'CRLF', True, '99999999'),
        ('leading', 0, 'YYMMDD', 'right', 'LF', True, '      '),
        ('unsigned', 3, 'YYMMDD', 'left', 'CRLF', False, '      '),
    ]
    orders = [
        ('account_ref', 'description', 'balance', 'effective_date', 'status'),
        ('status', 'effective_date', 'balance', 'account_ref', 'description'),
        ('description', 'account_ref', 'status', 'balance', 'effective_date'),
        ('balance', 'status', 'account_ref', 'effective_date', 'description'),
        ('effective_date', 'description', 'balance', 'status', 'account_ref'),
        ('account_ref', 'balance', 'description', 'status', 'effective_date'),
    ]
    layouts = []
    for index, (sign, scale, representation, side, framing, terminal, sentinel) in enumerate(configurations):
        date_width = 8 if representation == 'YYYYMMDD' else 6
        definitions = {
            'account_ref': (6, 'text', {'padding_side': 'none', 'padding_byte': ' ', 'trim': False, 'nullable': False}),
            'description': (12 + index, 'text', {'padding_side': side, 'padding_byte': ' ',
                                               'trim': True, 'nullable': False}),
            'balance': (8 + int(sign != 'unsigned'), 'decimal', {'scale': scale,
                         'precision': 7, 'sign': sign, 'padding_side': 'none', 'padding_byte': ' ',
                         'trim': False, 'nullable': False}),
            'effective_date': (date_width, 'date', {'format': representation, 'padding_side': 'none',
                         'century_window': [1970, 2069], 'nullable': True, 'padding_byte': ' ',
                         'trim': False, 'sentinels': {sentinel: 'null'}}),
            'status': (1, 'text', {'padding_side': 'none', 'padding_byte': ' ', 'trim': False,
                                  'nullable': False, 'allowed_codes': ['A', 'C']}),
        }
        fields, cursor = [], 0
        for name in orders[index]:
            width, kind, policy = definitions[name]
            fields.append({'semantic_target': name, 'start': cursor, 'end': cursor + width,
                           'data_type': kind, 'policy': policy})
            cursor += width
        layouts.append({'schema_version': 1, 'variant_id': f'dev-{index + 1:02d}',
                        'split': 'development', 'fields': fields, 'width': cursor,
                        'framing': framing, 'framing_version': 2, 'terminal_newline': terminal})
    return layouts


def _malformed(raw: bytes, kind: str, layout: dict) -> bytes:
    fields = {field['semantic_target']: field for field in layout['fields']}
    if kind == 'wrong_length':
        return raw[:-1]
    if kind == 'high_byte':
        offset = fields['description']['start']
        return raw[:offset] + b'\xff' + raw[offset + 1:]
    field = fields['effective_date' if kind == 'invalid_date' else
                   'description' if kind == 'invalid_padding' else 'balance']
    start, end = field['start'], field['end']
    token = bytearray(raw[start:end])
    if kind == 'invalid_date':
        token = bytearray(b'20230229' if field['policy']['format'] == 'YYYYMMDD' else b'230229')
    elif kind == 'invalid_padding':
        # Mutation rows use short descriptions with known declared spaces.
        index = 0 if field['policy']['padding_side'] == 'left' else len(token) - 1
        token[index] = 9
    elif kind == 'invalid_sign':
        index = len(token) - 1 if field['policy']['sign'] == 'trailing' else 0
        token[index] = ord('*')
    elif kind == 'precision_overflow':
        sign = field['policy']['sign']
        token = bytearray(b'9' * len(token))
        if sign == 'leading':
            token[0] = ord('+')
        elif sign == 'trailing':
            token[-1] = ord('+')
    else:
        raise ValueError('unknown malformed kind')
    return raw[:start] + bytes(token) + raw[end:]


def build_development_variant(variant_id: str, *, edition: str = 'public-development-v2') -> dict:
    if not edition.startswith('public-development-'):
        raise ValueError('local construction may only create public development editions')
    choices = {item['variant_id']: item for item in development_layouts()}
    if variant_id not in choices:
        raise ValueError('unknown public development layout')
    layout = choices[variant_id]
    balance = next(field for field in layout['fields'] if field['semantic_target'] == 'balance')
    batches, malformed_counts = [], Counter()
    for batch_index in range(10):
        rows = canonical_records(10000 + int(variant_id[-2:]) * 100 + batch_index,
                                 scale=balance['policy']['scale'], precision=balance['policy']['precision'],
                                 unsigned=balance['policy']['sign'] == 'unsigned')
        original = serialize(rows, layout)
        separator = b'\n' if layout['framing'] == 'LF' else b'\r\n'
        raw_rows = original.split(separator)[:100]
        mutations = []
        for position in range(3):
            ordinal = 97 + position
            kind = MALFORMED_KINDS[(batch_index * 3 + position) % len(MALFORMED_KINDS)]
            mutations.append({'canonical_ordinal': ordinal, 'kind': kind, 'expected_reasons': [kind],
                              'replacement_hex': _malformed(raw_rows[ordinal], kind, layout).hex()})
            malformed_counts[kind] += 1
        source, linkage = inject_malformed(original, layout, mutations)
        oracle = attach_refs(source, rows, layout)
        for mutation in linkage:
            row = oracle[mutation['canonical_ordinal']]
            row.update(expected_outcome='quarantined', reasons=mutation['expected_reasons'])
        samples = {'schema_version': 1, 'source_sha256': sha(source),
                   'authorization': 'public synthetic development; exact first 12 records authorized',
                   'records': [{'ordinal': index, 'raw_hex': raw_rows[index].hex(),
                                'raw_sha256': sha(raw_rows[index])} for index in range(12)]}
        samples['artifact_sha256'] = digest(samples)
        # Brief discloses concepts and vocabulary, never layout/policy offsets.
        brief = ('Account ledger with account_ref, description, balance, effective_date and status. '
                 'Status vocabulary: A active, C closed. Identifiers preserve leading zeros.')
        visible = {'schema_version': 1, 'source_hex': source.hex(), 'source_sha256': sha(source),
                   'framing_sha256': oracle[0]['record_ref']['framing_sha256'],
                   'record_refs': [item['record_ref'] for item in oracle], 'record_count': 100,
                   'brief': brief, 'encoding': 'ASCII', 'permitted_samples': samples}
        batches.append({'batch_id': f'{variant_id}-batch-{batch_index + 1:02d}',
                        'visible': visible, 'canonical_records': rows,
                        'oracle': oracle, 'mutations': linkage,
                        'canonical_sha256': digest(rows), 'oracle_sha256': digest(oracle)})
    return {'schema_version': 1, 'edition': edition, 'split': 'development',
            'variant_id': variant_id, 'layout': layout, 'batches': batches,
            'malformed_counts': dict(malformed_counts), 'supported_records': 1000,
            'malformed_records': 30, 'malformed_fraction': '0.03',
            'custody': 'public_development_not_hidden', 'benchmark_status': 'not_run'}


def variant_case(corpus: dict, *, accepted_choices: dict[str, str] | None = None):
    """Public data-to-runner adapter; imports evaluator runner only on invocation."""
    from .runner import BatchCase, VariantCase
    if corpus.get('split') != 'development':
        raise ValueError('this adapter only handles public development material')
    batches = tuple(BatchCase(item['batch_id'], deepcopy(item['visible']), deepcopy(item['oracle']))
                    for item in corpus['batches'])
    return VariantCase(corpus['variant_id'], 'development', corpus['edition'],
                       deepcopy(corpus['batches'][0]['visible']), batches, accepted_choices or {},
                       deepcopy(corpus['layout']['fields']))


def capture_public_variant(store: CaptureStore, corpus: dict) -> dict:
    if corpus.get('split') != 'development' or not corpus.get('edition', '').startswith('public-development-'):
        raise ValueError('only public development capture is allowed locally')
    return store.put('public_corpus_variant', corpus)


def request_external_edition(spec: dict, *, freeze: dict, custody: dict,
                             authority: dict, writer: Callable[[dict], dict],
                             eligibility=None, materialization_receipt: dict | None = None) -> dict:
    """Source-only external capability. Caller, not this checkout, owns hidden gold.

    No filesystem path/seed/oracle content is returned to inference. An operator
    must implement the writer under the separate evaluator OS identity later.
    """
    split = spec.get('split')
    if split not in ('validation', 'heldout') or spec.get('variants') != SPLITS[split]:
        raise ValueError('external split contract mismatch')
    if spec.get('batches_per_variant') != 10 or spec.get('records_per_batch') != 100:
        raise ValueError('ten 100-record batches required')
    if not is_sha(spec.get('T0_commitment_sha256')) or not is_sha(spec.get('sealed_assets_sha256')):
        raise ValueError('pre-tuning commitment and sealed asset pin required')
    if spec.get('edition') != authority.get('edition') or authority.get('authorized') is not True:
        raise ValueError('edition-specific external materialization authority required')
    if not is_sha(authority.get('authority_sha256')) or not is_sha(authority.get('external_root_sha256')):
        raise ValueError('external root/authority evidence required')
    if custody.get('edition') != spec.get('edition') or not is_sha(custody.get('evidence_sha256')):
        raise ValueError('custody edition/evidence mismatch')
    if split == 'heldout':
        from .edition_registry import EligibilityContext
        from .eligibility import closed
        if not isinstance(eligibility, EligibilityContext) or spec.get('unseen_combinations', 0) < 2:
            raise ValueError('verified external custody/edition context required')
        eligibility.validate()
        if freeze != eligibility.freeze or eligibility.commitment['commitment_sha256'] != spec['T0_commitment_sha256']:
            raise ValueError('external edition differs from registered commitment/freeze')
        grant = closed(eligibility.verifier.verify(materialization_receipt, 'run_owner'),
                       {'schema_version', 'action', 'edition', 'spec_sha256', 'external_root_sha256'},
                       'external materialization authority')
        if (grant['action'] != 'materialize_edition' or grant['edition'] != spec['edition']
                or grant['spec_sha256'] != digest(spec)
                or grant['external_root_sha256'] != authority['external_root_sha256']):
            raise ValueError('no exact signed external materialization authority')
        if freeze.get('commitment_sha256') != spec['T0_commitment_sha256']:
            raise ValueError('freeze does not bind sealed edition')
    receipt = writer({'spec': deepcopy(spec), 'authority': deepcopy(authority), 'custody': deepcopy(custody)})
    if set(receipt) != {'edition', 'split', 'commitment_sha256', 'external_receipt_sha256'}:
        raise ValueError('external writer must return pins only, never hidden assets')
    if receipt['edition'] != spec['edition'] or receipt['split'] != split:
        raise ValueError('external writer edition mismatch')
    if receipt['commitment_sha256'] != spec['T0_commitment_sha256'] or not is_sha(receipt['external_receipt_sha256']):
        raise ValueError('external receipt pin mismatch')
    return receipt

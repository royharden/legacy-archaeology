"""Finite declared policies shared by decision validation and deterministic conversion."""
from __future__ import annotations

TARGET_TYPES = {'account_ref': 'text', 'description': 'text', 'balance': 'decimal',
                'effective_date': 'date', 'status': 'text'}
COMMON = {'padding_byte', 'padding_side', 'trim', 'nullable', 'sentinels'}


def validate_policy(field):
    target, kind, policy = field['semantic_target'], field['data_type'], field['policy']
    if TARGET_TYPES.get(target) != kind or not isinstance(policy, dict):
        raise ValueError('semantic target type mismatch')
    required = {'padding_byte', 'padding_side', 'trim', 'nullable'}
    extra = {'scale', 'precision', 'sign'} if kind == 'decimal' else {'format', 'century_window'} if kind == 'date' else {'allowed_codes'}
    if not required <= policy.keys() or policy.keys() - COMMON - extra:
        raise ValueError('missing or unknown policy field')
    pad, side = policy['padding_byte'], policy['padding_side']
    if not isinstance(pad, str) or len(pad) != 1 or not pad.isascii() or pad in '\x00\r\n':
        raise ValueError('invalid padding byte')
    if side not in ('none', 'left', 'right') or any(type(policy[k]) is not bool for k in ('trim', 'nullable')):
        raise ValueError('invalid padding/null policy')
    if side == 'none' and policy['trim']:
        raise ValueError('trim requires declared padding side')
    if kind == 'decimal':
        if not {'scale', 'precision', 'sign'} <= policy.keys():
            raise ValueError('incomplete decimal policy')
        scale, precision = policy['scale'], policy['precision']
        if type(scale) is not int or scale not in (0, 2, 3) or type(precision) is not int or not max(1, scale) <= precision <= 1000:
            raise ValueError('invalid decimal precision/scale')
        if policy['sign'] not in ('unsigned', 'leading', 'trailing'):
            raise ValueError('invalid sign policy')
    if kind == 'date':
        if policy.get('format') not in ('YYYYMMDD', 'YYMMDD'):
            raise ValueError('invalid date format')
        if policy['format'] == 'YYMMDD':
            window = policy.get('century_window')
            if not isinstance(window, list) or len(window) != 2 or any(type(x) is not int for x in window) or not 1 <= window[0] <= window[1] <= 9999 or window[1] - window[0] != 99:
                raise ValueError('explicit century window required')
        elif 'century_window' in policy:
            raise ValueError('century window applies only to YYMMDD')
    sentinels = policy.get('sentinels', {})
    if not isinstance(sentinels, dict):
        raise ValueError('invalid sentinel policy')
    width = field['end'] - field['start']
    for lexeme, action in sentinels.items():
        if not isinstance(lexeme, str) or not lexeme.isascii() or len(lexeme) != width or not (lexeme == ' ' * width or lexeme == '9' * width):
            raise ValueError('only exact-width blank/all-nines sentinels supported')
        if action != 'null' or not policy['nullable']:
            raise ValueError('sentinel requires explicit SQL-null policy')
    if 'allowed_codes' in policy:
        codes = policy['allowed_codes']
        if target != 'status' or not isinstance(codes, list) or not codes or any(not isinstance(c, str) or not c.isascii() or '\x00' in c for c in codes) or len(set(codes)) != len(codes):
            raise ValueError('invalid disclosed status vocabulary')
    return policy

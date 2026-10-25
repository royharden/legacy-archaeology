"""Compare offered policy meaning, with exact JSON types and declared defaults.

No parsing/conversion code or product imports. This module never creates a new
option or changes oracle values; it chooses an existing offered ID or unknown.
"""
from copy import deepcopy

from .artifacts import canonical


def policy_wire(field):
    policy = deepcopy(field['policy'])
    kind = field['data_type']
    common = {'padding_byte', 'padding_side', 'trim', 'nullable'}
    extra = {'scale', 'precision', 'sign'} if kind == 'decimal' else {'format', 'century_window'} if kind == 'date' else {'allowed_codes'}
    if (not isinstance(policy, dict) or not common <= policy.keys()
            or policy.keys() - common - {'sentinels'} - extra):
        raise ValueError('missing or unknown policy axis')
    if (type(policy['padding_byte']) is not str or type(policy['padding_side']) is not str
            or type(policy['trim']) is not bool or type(policy['nullable']) is not bool):
        raise ValueError('exact common policy types required')
    sentinels = policy.setdefault('sentinels', {})
    if (type(sentinels) is not dict or any(type(k) is not str or type(v) is not str for k, v in sentinels.items())):
        raise ValueError('sentinel object required; absent defaults to empty object')
    if kind == 'decimal':
        if (any(type(policy.get(k)) is not int for k in ('scale', 'precision'))
                or type(policy.get('sign')) is not str):
            raise ValueError('exact decimal policy types required')
    elif kind == 'date':
        if policy.get('format') == 'YYYYMMDD':
            if 'century_window' in policy:
                raise ValueError('century window is forbidden for YYYYMMDD')
        elif policy.get('format') == 'YYMMDD':
            window = policy.get('century_window')
            if (type(window) is not list or len(window) != 2
                    or any(type(v) is not int for v in window) or window[1] - window[0] != 99):
                raise ValueError('explicit typed century window required for YYMMDD')
        else:
            raise ValueError('declared date format required')
    elif kind != 'text':
        raise ValueError('unsupported semantic field type')
    if 'allowed_codes' in policy:
        codes = policy['allowed_codes']
        if (type(codes) is not list or not codes or any(type(c) is not str for c in codes)
                or len(set(codes)) != len(codes)):
            raise ValueError('nonempty unique declared code vocabulary required')
        policy['allowed_codes'] = sorted(codes)  # membership vocabulary has no order semantics
    if any(type(field.get(k)) is not int for k in ('start', 'end')):
        raise ValueError('exact integer byte boundaries required')
    return canonical({k: field[k] for k in ('start', 'end', 'semantic_target', 'data_type')} | {'policy': policy})


def offered_policy_matches(offered, expected):
    expected_wire = policy_wire(expected)  # invalid evaluator metadata is a defect, never unknown
    try:
        return policy_wire(offered) == expected_wire
    except (KeyError, TypeError, ValueError):
        return False

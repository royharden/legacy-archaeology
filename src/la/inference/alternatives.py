"""Finite explicit policy alternatives, never an inferred accepted policy."""
import json
import re
from la.contracts import REQUIRED_FIELDS, digest

CENTURY_WINDOWS = [[1900, 1999], [1970, 2069], [2000, 2099]]


def disclosed_names(brief: str) -> list[str]:
    return [name for name in REQUIRED_FIELDS if re.search(r'\b' + re.escape(name) + r'\b', brief)]


def status_vocabulary(brief: str) -> dict:
    """Read only explicitly labeled vocabulary; observed byte values are not a codebook."""
    codes = None
    source = None
    match = re.search(r'\bstatus(?:_codes|\s+vocabulary|\s+codes)\s*[:=]\s*(\[[^\]\n]{1,2000}\])', brief, re.I)
    if match:
        try:
            value = json.loads(match.group(1))
        except (ValueError, TypeError):
            value = None
        if isinstance(value, list) and 0 < len(value) <= 64 and all(isinstance(item, str) and 0 < len(item) <= 32 and item.isascii() for item in value):
            codes, source = sorted(set(value)), 'explicit_status_codes'
    if codes is None:
        match = re.search(r'\bstatus(?:_codes|\s+vocabulary|\s+codes)\s*[:=]\s*([^\n.;]{1,2000})', brief, re.I)
        if match and re.fullmatch(r'\s*[A-Za-z0-9_-]{1,32}(?:\s*,\s*[A-Za-z0-9_-]{1,32})*\s*', match.group(1)):
            values = [item.strip() for item in match.group(1).split(',')]
            if len(values) <= 64: codes, source = sorted(set(values)), 'explicit_status_code_list'
    if codes is None:
        # Explicit vocabulary labels may use prose ("A active, C closed").
        # Require a code and a nonempty label in every comma-separated item;
        # arbitrary observed status bytes never create a vocabulary.
        match = re.search(r'\bstatus(?:_codes|\s+vocabulary|\s+codes)\s*[:=]\s*([^\n.;]{1,2000})', brief, re.I)
        if match:
            parts = match.group(1).split(',')
            labels = [re.fullmatch(r'\s*([A-Za-z0-9_-]{1,32})\s+(?:=\s*)?([^,=]+?)\s*', part) for part in parts]
            if 0 < len(labels) <= 64 and all(labels):
                codes, source = sorted({label.group(1) for label in labels}), 'explicit_status_labels'
    if codes is None:
        match = re.search(r'\bstatus\s*\(([^)\n]{1,2000})\)', brief, re.I)
        if match:
            parts = re.split(r'[,;]', match.group(1))
            labels = [re.fullmatch(r'\s*([A-Za-z0-9_-]{1,32})\s*=\s*[^=]+', part) for part in parts]
            if 0 < len(labels) <= 64 and all(labels):
                codes, source = sorted({label.group(1) for label in labels}), 'explicit_status_labels'
    return {'codes': codes, 'source': source,
            'state': 'disclosed' if codes is not None else 'missing_vocabulary',
            'unknown_code_treatment': 'unlisted_code_diagnostic' if codes is None else 'declared_vocabulary_check',
            'vocabulary_sha256': digest({'codes': codes, 'source': source})}


def compatible_targets(raws: list[bytes], brief: str) -> list[str]:
    names = disclosed_names(brief)
    # A small malformed minority must not erase the true finite proposal. Shape
    # support is logged; it is neither a conversion nor a claimed validation pass.
    def supported(predicate):
        return sum(predicate(raw.strip(b' ')) for raw in raws) * 4 >= len(raws) * 3
    numeric = supported(lambda value: bool(re.fullmatch(rb'(?:[+-]?\d+|\d+[+-])', value)))
    date = supported(lambda value: value == b'' or len(value) in (6, 8) and value.isdigit())
    allowed = {'account_ref', 'description', 'status'}
    if numeric: allowed.add('balance')
    if date: allowed.add('effective_date')
    return [name for name in names if name in allowed]


def policy_alternatives(raws: list[bytes], target: str, vocabulary: dict) -> tuple[list[dict], dict]:
    """At most three complete policies per physical-field/semantic-name option.

    Axes are recorded separately; bounded prioritized proposals deliberately do
    not pretend to exhaust their Cartesian product. Unknown is always required.
    """
    # A blank lexeme has no token edge from which to infer a padding side.
    # It still participates in the separate sentinel/null alternatives below.
    padding_observations = [raw for raw in raws if raw.strip(b' ')]
    observed_left = any(raw.startswith(b' ') for raw in padding_observations)
    observed_right = any(raw.endswith(b' ') for raw in padding_observations)
    sides = ['left', 'none', 'right'] if observed_left and not observed_right else ['right', 'none', 'left'] if observed_right and not observed_left else ['left', 'right', 'none'] if observed_left else ['none', 'left', 'right']
    padding = [{'padding_byte': ' ', 'padding_side': side, 'trim': side != 'none'} for side in sides]
    # Prefer an observed sign but expose all supported modes as explicit options.
    stripped = [raw.strip(b' ') for raw in raws]
    leading = any(value.startswith((b'+', b'-')) for value in stripped)
    trailing = any(value.endswith((b'+', b'-')) for value in stripped)
    patterns = {'leading': rb'[+-]\d+', 'trailing': rb'\d+[+-]', 'unsigned': rb'\d+'}
    sign_support = {name: sum(bool(re.fullmatch(pattern, raw)) for raw in stripped) for name, pattern in patterns.items()}
    signs = sorted([name for name in patterns if sign_support[name]], key=lambda name: (-sign_support[name], name)) or ['unsigned']
    lengths = sorted({len(value) for value in stripped if value and value.isdigit()})
    formats = ['YYMMDD'] if lengths == [6] else ['YYYYMMDD'] if lengths == [8] else ['YYYYMMDD', 'YYMMDD']
    sentinel_values = sorted({raw.decode('ascii') for raw in raws
                              if raw == b' ' * len(raw) or raw == b'9' * len(raw)})
    sentinel_modes = ['preserve_or_reject', 'explicit_sql_null'] if sentinel_values else ['preserve_or_reject']
    axes = {'padding': padding}
    if target == 'balance':
        axes.update(sign=signs, scale=[0, 2, 3],
                    precision=sorted({max(3, len(raws[0])), 18, 38}))
        if sentinel_values: axes['sentinel'] = sentinel_modes
    if target == 'effective_date':
        axes.update(format=formats, sentinel=sentinel_modes)
        if 'YYMMDD' in formats: axes['century_window'] = CENTURY_WINDOWS
    if target in ('account_ref', 'description', 'status') and sentinel_values:
        if sentinel_values: axes['sentinel'] = ['preserve_or_reject', 'explicit_sql_null']
    alternatives = []
    # Physical capacity is a finite precision proposal, not a business limit.
    # The sign consumes a byte but not a decimal digit. Do not advertise an
    # observed-width axis then silently use only the unrelated maximum38.
    digit_capacity = max((len(value) - int(value.startswith((b'+', b'-')) or value.endswith((b'+', b'-')))
                          for value in stripped if re.fullmatch(rb'(?:[+-]?\d+|\d+[+-])', value)), default=1)
    if target == 'balance':
        axes['precision'] = sorted({max(3, digit_capacity), 18, 38})
    for index in range(3):
        pad_index = 0 if target in ('balance', 'effective_date') else index % len(padding)
        policy = dict(padding[pad_index], nullable=False)
        if target == 'balance':
            policy.update(sign=signs[0], scale=axes['scale'][index], precision=max(3, digit_capacity))
        if target == 'effective_date':
            policy.update(format=formats[index % len(formats)], sentinels={})
            if policy['format'] == 'YYMMDD': policy['century_window'] = CENTURY_WINDOWS[index]
        if sentinel_values and index == 1:
            policy.update(nullable=True, sentinels={value: 'null' for value in sentinel_values})
        if target == 'status' and vocabulary['codes'] is not None:
            policy['allowed_codes'] = vocabulary['codes']
        if policy not in alternatives: alternatives.append(policy)
    if target in ('account_ref', 'description', 'status') and sentinel_values:
        # Preserve blank/empty/null distinctions instead of spending the sole
        # no-trim option on NULL and silently removing literal preservation.
        # An unobserved opposite-side trim stays an explicitly omitted choice.
        preserve = {'padding_byte': ' ', 'padding_side': 'none', 'trim': False, 'nullable': False}
        trim = dict(padding[0], nullable=False)
        null = dict(padding[0], nullable=True, sentinels={value: 'null' for value in sentinel_values})
        alternatives = []
        for policy in (preserve, trim, null):
            if target == 'status' and vocabulary['codes'] is not None:
                policy['allowed_codes'] = vocabulary['codes']
            if policy not in alternatives: alternatives.append(policy)
    combinations = 1
    for values in axes.values(): combinations *= len(values)
    diagnostics = {'axes': axes, 'policy_option_count': len(alternatives),
                   'max_policy_alternatives': 3, 'combination_count': combinations,
                   'unoffered_combination_count': max(0, combinations - len(alternatives)),
                   'coverage': 'bounded_proposals_not_exhaustive', 'unknown_option': 'unknown',
                   'observed_left_padding': observed_left, 'observed_right_padding': observed_right,
                   'observed_leading_sign': leading, 'observed_trailing_sign': trailing,
                   'sign_support': sign_support,
                   'sentinel_lexemes': sentinel_values, 'century_windows_are_proposals': True,
                   'precision_is_proposed_not_domain_fact': target == 'balance'}
    return alternatives, diagnostics

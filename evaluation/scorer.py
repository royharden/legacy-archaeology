"""Independent semantic oracle comparison. Never imports product converters."""
from __future__ import annotations

from collections import Counter, defaultdict
from datetime import date
from decimal import Decimal, InvalidOperation
from statistics import mean, median

FIELDS = ('account_ref', 'description', 'balance', 'effective_date', 'status')
REF_KEYS = ('source_sha256', 'framing_sha256', 'ordinal', 'byte_start', 'length', 'raw_sha256')


def identity(ref: dict) -> tuple:
    """Only declared RecordRef identity; never business-key or fuzzy matching."""
    if not isinstance(ref, dict) or any(key not in ref for key in REF_KEYS):
        raise ValueError('incomplete RecordRef')
    if any(type(ref[key]) is not int or ref[key] < 0 for key in ('ordinal', 'byte_start', 'length')):
        raise ValueError('invalid ordinal/byte identity')
    if any(not isinstance(ref[key], str) or len(ref[key]) != 64 or
           any(c not in '0123456789abcdef' for c in ref[key])
           for key in ('source_sha256', 'framing_sha256', 'raw_sha256')):
        raise ValueError('invalid RecordRef hash')
    return tuple(ref[key] for key in REF_KEYS)


def _equal(expected: dict, actual: dict) -> bool:
    if not isinstance(actual, dict) or expected.get('data_type') != actual.get('data_type'):
        return False
    left, right = expected.get('value'), actual.get('value')
    if left is None or right is None:
        return left is None and right is None
    kind = expected['data_type']
    try:
        if kind == 'decimal':
            if not isinstance(left, str) or not isinstance(right, str):
                return False
            a, b = Decimal(left), Decimal(right)
            return a.is_finite() and b.is_finite() and a == b and a.as_tuple().exponent == b.as_tuple().exponent
        if kind == 'date':
            return isinstance(right, str) and date.fromisoformat(left) == date.fromisoformat(right)
        return isinstance(right, str) and left == right
    except (ValueError, TypeError, InvalidOperation):
        return False


def _rate(numerator: int, denominator: int) -> dict:
    return {'numerator': numerator, 'denominator': denominator,
            'rate': numerator / denominator if denominator else None}


def _reasons(row: dict) -> set[str]:
    reasons = row.get('reasons', [])
    if not isinstance(reasons, list) or any(not isinstance(reason, str) for reason in reasons):
        return {'invalid_reason_wire'}
    return set(reasons)


def score(oracle_records: list[dict], outcomes: list[dict], *, edition: str = 'development') -> dict:
    """Score normalized outcomes with fields of {semantic_id: {data_type,value}}.

    Each oracle record declares record_ref, expected_outcome, fields and reasons.
    Duplicate identities poison every cell rather than selecting the best copy.
    Quarantine requires exact expected reason sets. Empty denominators are null.
    """
    expected = {}
    for row in oracle_records:
        key = identity(row['record_ref'])
        if key in expected:
            raise ValueError('duplicate oracle identity')
        if row['expected_outcome'] == 'converted' and set(row['fields']) != set(FIELDS):
            raise ValueError('valid oracle must contain all five semantic fields')
        expected[key] = row
    observed = defaultdict(list)
    invalid_refs = []
    for position, row in enumerate(outcomes):
        try:
            if not isinstance(row, dict):
                raise ValueError('invalid outcome')
            observed[identity(row['record_ref'])].append(row)
        except (KeyError, ValueError, TypeError):
            invalid_refs.append(position)
    valid = correct_rows = correct_fields = correct_outcomes = false_quarantine = 0
    resolved = resolved_correct = 0
    diffs, missing, duplicates = [], [], []
    quarantine_expected, quarantine_observed, quarantine_correct = Counter(), Counter(), Counter()
    expected_status, actual_status = Counter(), Counter()
    expected_sum, actual_sum = Decimal(0), Decimal(0)
    expected_null, actual_null, expected_empty, actual_empty = Counter(), Counter(), Counter(), Counter()
    for key, oracle in expected.items():
        rows = observed.get(key, [])
        if not rows:
            missing.append(oracle['record_ref'])
        if len(rows) > 1:
            duplicates.append({'record_ref': oracle['record_ref'], 'count': len(rows)})
        actual = rows[0] if len(rows) == 1 else None
        expected_kind = oracle['expected_outcome']
        if expected_kind == 'quarantined':
            quarantine_expected.update(_reasons(oracle))
        # All emitted quarantines count, including duplicates; precision cannot cherry-pick.
        for row in rows:
            if row.get('outcome') == 'quarantined':
                quarantine_observed.update(_reasons(row))
        if expected_kind == 'converted':
            valid += 1
            fields = oracle['fields']
            expected_status[fields['status']['value']] += 1
            expected_sum += Decimal(fields['balance']['value'])
            for name, field in fields.items():
                expected_null[name] += field['value'] is None
                expected_empty[name] += field['value'] == ''
            if any(row.get('outcome') == 'quarantined' for row in rows):
                false_quarantine += 1
            got = actual.get('fields', {}) if actual and actual.get('outcome') == 'converted' else {}
            if not isinstance(got, dict):
                got = {}
            matches = {name: _equal(fields[name], got.get(name)) for name in FIELDS}
            correct_fields += sum(matches.values())
            resolved += sum(name in got for name in FIELDS)
            resolved_correct += sum(matches.values())
            exact = all(matches.values()) and set(got) == set(FIELDS)
            correct_rows += exact
            correct_outcomes += exact
            if not exact:
                diffs.append({'record_ref': oracle['record_ref'], 'kind': 'semantic_mismatch',
                              'incorrect_fields': [name for name in FIELDS if not matches[name]],
                              'extra_targets': sorted(set(got) - set(FIELDS)),
                              'observed_count': len(rows), 'observed_outcome': actual.get('outcome') if actual else None})
        elif expected_kind == 'quarantined':
            exact = bool(actual and actual.get('outcome') == 'quarantined' and
                         _reasons(actual) == _reasons(oracle))
            correct_outcomes += exact
            if exact:
                quarantine_correct.update(_reasons(oracle))
            else:
                diffs.append({'record_ref': oracle['record_ref'], 'kind': 'quarantine_mismatch'})
        else:
            raise ValueError('unsupported oracle outcome; unsupported fixtures score separately')
    # Diagnostics include every emitted row, even extra or duplicated identities.
    outcomes_count = Counter(row.get('outcome', 'unknown') if isinstance(row, dict)
                             and isinstance(row.get('outcome', 'unknown'), str) else 'invalid' for row in outcomes)
    for row in outcomes:
        if not isinstance(row, dict) or row.get('outcome') != 'converted':
            continue
        got = row.get('fields', {})
        if not isinstance(got, dict):
            continue
        if isinstance(got.get('status'), dict) and isinstance(got['status'].get('value'), (str, type(None))):
            actual_status[got['status'].get('value')] += 1
        try:
            value = Decimal(got['balance']['value'])
            if value.is_finite():
                actual_sum += value
        except (KeyError, TypeError, InvalidOperation):
            pass
        for name, field in got.items():
            if not isinstance(field, dict):
                continue
            actual_null[name] += field.get('value') is None
            actual_empty[name] += field.get('value') == ''
    extra = [{'record_ref': rows[0]['record_ref'], 'count': len(rows)}
             for key, rows in observed.items() if key not in expected]
    # Extra quarantines also reduce precision.
    for key, rows in observed.items():
        if key not in expected:
            for row in rows:
                if row.get('outcome') == 'quarantined':
                    quarantine_observed.update(_reasons(row))
    reasons = sorted(set(quarantine_expected) | set(quarantine_observed))
    return {'schema_version': 1, 'scorer_version': 'semantic-v2', 'edition': edition,
            'semantic_rows': _rate(correct_rows, valid), 'semantic_fields': _rate(correct_fields, valid * 5),
            'all_record_outcomes': _rate(correct_outcomes, len(expected)),
            'resolved_field_coverage': _rate(resolved, valid * 5),
            'accepted_only_precision': _rate(resolved_correct, resolved),
            'resolved_but_wrong_fields': resolved - resolved_correct,
            'unresolved_or_missing_fields': valid * 5 - resolved,
            'false_quarantine': false_quarantine, 'missing': missing, 'extra': extra,
            'duplicates': duplicates, 'invalid_record_refs': invalid_refs, 'diffs': diffs,
            'quarantine_by_reason': {reason: {'precision': _rate(quarantine_correct[reason], quarantine_observed[reason]),
                'recall': _rate(quarantine_correct[reason], quarantine_expected[reason])} for reason in reasons},
            'aggregates': {'input_count': len(expected), 'emitted_count': len(outcomes),
                'outcomes': dict(outcomes_count), 'cardinality_reconciled': len(expected) == len(outcomes)
                and not missing and not extra and not duplicates and not invalid_refs,
                'expected_balance_sum': str(expected_sum), 'actual_balance_sum': str(actual_sum),
                'expected_status_counts': dict(expected_status), 'actual_status_counts': dict(actual_status),
                'expected_null_counts': dict(expected_null), 'actual_null_counts': dict(actual_null),
                'expected_empty_counts': dict(expected_empty), 'actual_empty_counts': dict(actual_empty)},
            'row_parity': 'incomplete' if not expected else
                'exact' if correct_rows == valid and not diffs and not extra and not invalid_refs else 'mismatch',
            'target_validation': 'not_run', 'product_acceptance': 'pending'}


def aggregate_variant_reports(reports: list[dict]) -> dict:
    """Micro denominators plus descriptive variant variation; no confidence claim."""
    result = {}
    for metric in ('semantic_rows', 'semantic_fields', 'all_record_outcomes'):
        result[metric] = _rate(sum(r[metric]['numerator'] for r in reports), sum(r[metric]['denominator'] for r in reports))
    rates = [r['semantic_rows']['rate'] for r in reports if r['semantic_rows']['rate'] is not None]
    result['variant_rows'] = {'count': len(reports), 'applicable': len(rates),
        'mean': mean(rates) if rates else None, 'min': min(rates) if rates else None,
        'median': median(rates) if rates else None, 'max': max(rates) if rates else None}
    return result


def score_product(oracle_records: list[dict], outcomes: list[dict], mapping: dict, *, edition: str = 'development') -> dict:
    """Explicit wire adapter: types come from the submitted mapping, never oracle."""
    declared = defaultdict(list)
    for field in mapping.get('fields', []):
        declared[field['semantic_target']].append(field['data_type'])
    types = {name: kinds[0] if len(kinds) == 1 else None for name, kinds in declared.items()}
    normalized = []
    for row in outcomes:
        if not isinstance(row, dict):
            normalized.append({})
            continue
        normalized.append({'record_ref': row.get('record_ref', {}), 'outcome': row.get('outcome', 'invalid'),
            'reasons': row.get('reasons', []) if isinstance(row.get('reasons', []), list) else [],
            'fields': {name: {'data_type': types.get(name), 'value': value}
                       for name, value in (row.get('values') if isinstance(row.get('values'), dict) else {}).items()}})
    report = score(oracle_records, normalized, edition=edition)
    report['mapping_completeness'] = {'missing_targets': sorted(set(FIELDS) - set(declared)),
        'extra_targets': sorted(set(declared) - set(FIELDS)),
        'duplicate_targets': sorted(name for name, kinds in declared.items() if len(kinds) != 1)}
    if any(report['mapping_completeness'].values()):
        report['row_parity'] = 'mismatch'
    return report


def slot_diagnostics(expected_fields: list[dict], submitted_fields: list[dict], candidates: list[dict] | None = None) -> dict:
    """Secondary exact-span diagnostics never repair semantic scores."""
    def slot(field: dict) -> tuple:
        return field['start'], field['end'] - field['start']
    expected = {slot(field): field for field in expected_fields}
    actual = defaultdict(list)
    for field in submitted_fields:
        actual[slot(field)].append(field)
    matched = sum(len(actual.get(key, [])) == 1 for key in expected)
    types = names = 0
    for key, field in expected.items():
        if len(actual.get(key, [])) == 1:
            types += actual[key][0]['data_type'] == field['data_type']
            names += actual[key][0]['semantic_target'] == field['semantic_target']
    candidate_slots = {slot(field) for field in candidates or []}
    precision, recall = _rate(matched, len(submitted_fields)), _rate(matched, len(expected_fields))
    p, r = precision['rate'], recall['rate']
    f1 = None if p is None or r is None else 2 * p * r / (p + r) if p + r else 0.0
    return {'boundary_precision': precision, 'boundary_recall': recall, 'boundary_f1': f1,
            'type_accuracy': _rate(types, len(expected_fields)), 'name_accuracy': _rate(names, len(expected_fields)),
            'candidate_boundary_recall': _rate(sum(key in candidate_slots for key in expected), len(expected_fields)),
            'layout_complete': matched == len(expected_fields) == len(submitted_fields),
            'vocabulary_coverage': _rate(len({field['semantic_target'] for field in submitted_fields} & set(FIELDS)), 5),
            'diagnostic_only': True}

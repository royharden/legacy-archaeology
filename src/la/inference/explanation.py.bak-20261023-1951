"""Deterministic, content-bound ambiguity explanations; no business-meaning proof."""
import re
from collections import defaultdict
from la.contracts import REQUIRED_FIELDS, digest, sha256, validate_batch, validate_generation
from la.ingest.evidence import resolve_evidence
from la.ingest.inspection import inspection_detail, inspection_page

MAX_EXAMPLES = 3
MAX_LAYOUT_FIELDS = 8
MAX_EXAMPLE_PROOFS = 8


def _integer(value, name, low, high):
    if type(value) is not int or not low <= value <= high:
        raise ValueError(f'{name} must be an exact integer in [{low},{high}]')


def _context(batch, generation, authorized_only):
    batch, generation = validate_batch(batch), validate_generation(generation)
    # The real inspector validates all source/generation/candidate/sample pins,
    # ranges and evidence through the shared resolver; this is not a confidence gate.
    page = inspection_page(batch, limit=1, authorized_only=authorized_only, generation=generation)
    groups, ids = defaultdict(list), set()
    for candidate in generation['candidates']:
        if candidate['id'] in ids: raise ValueError('duplicate candidate identity')
        ids.add(candidate['id'])
        groups[(candidate['start'], candidate['end'])].append(candidate)
        for proof in candidate['evidence']:
            if proof['start'] != candidate['start'] or proof['end'] != candidate['end']:
                raise ValueError('candidate evidence does not prove the claimed byte range')
    if len(groups) > 32: raise ValueError('explanation physical field budget exceeded')
    for values in groups.values():
        by_name = defaultdict(list)
        for candidate in values: by_name[candidate['semantic_target']].append(candidate)
        if any(len(policies) > 3 for policies in by_name.values()):
            raise ValueError('explanation policy/name option budget exceeded')
    return batch, generation, page, groups


def _policy(policy):
    """Bounded proposal summary; raw sentinel lexemes are not leaked as examples."""
    result = {'kind': 'proposed_policy_summary', 'policy_sha256': digest(policy), 'requires_confirmation': True}
    for key in ('trim', 'nullable'):
        result[key] = policy.get(key) if type(policy.get(key)) is bool else None
    for key, allowed in (('padding_side', ('none', 'left', 'right')), ('sign', ('leading', 'trailing', 'unsigned')),
                         ('format', ('YYYYMMDD', 'YYMMDD'))):
        if key in policy: result[key] = policy[key] if policy[key] in allowed else 'unsupported_or_unknown'
    pad = policy.get('padding_byte')
    result['padding_byte_hex'] = pad.encode('ascii').hex() if isinstance(pad, str) and len(pad) == 1 and pad.isascii() else None
    for key, low, high in (('scale', 0, 3), ('precision', 1, 1000)):
        if key in policy:
            value = policy[key]
            result[key] = value if type(value) is int and low <= value <= high and (key != 'scale' or value in (0, 2, 3)) else None
    if 'century_window' in policy:
        window = policy['century_window']
        result['century_window'] = list(window) if isinstance(window, list) and len(window) == 2 and all(type(value) is int for value in window) and 1 <= window[0] <= window[1] <= 9999 and window[1] - window[0] == 99 else None
    sentinels = policy.get('sentinels', {})
    result['sentinel_patterns'] = []
    if isinstance(sentinels, dict):
        for lexeme, action in list(sentinels.items())[:3]:
            kind = 'blank' if isinstance(lexeme, str) and lexeme and lexeme == ' ' * len(lexeme) else 'all_nines' if isinstance(lexeme, str) and lexeme and lexeme == '9' * len(lexeme) else 'unsupported_redacted'
            result['sentinel_patterns'].append({'pattern': kind, 'width': len(lexeme) if isinstance(lexeme, str) else None,
                                                'action': 'sql_null' if action == 'null' else 'unsupported_or_unknown'})
    codes = policy.get('allowed_codes')
    if isinstance(codes, list):
        result['disclosed_status_codes'] = [code for code in codes[:64] if isinstance(code, str) and len(code) <= 32 and code.isascii()]
        result['status_codes_omitted'] = len(codes) - len(result['disclosed_status_codes'])
    return result


def _patterns(cells):
    counts = dict(digits=0, letters=0, spaces=0, signs=0, other_printable=0, control=0, high_bytes=0, redacted=0)
    for cell in cells:
        if cell['redacted']: counts['redacted'] += 1; continue
        byte = int(cell['hex'], 16)
        key = ('digits' if 48 <= byte <= 57 else 'letters' if 65 <= byte <= 90 or 97 <= byte <= 122
               else 'spaces' if byte == 32 else 'signs' if byte in (43, 45)
               else 'high_bytes' if byte > 127 else 'other_printable' if 32 <= byte <= 126 else 'control')
        counts[key] += 1
    return {'basis': 'visible_diagnostic_bytes_only', 'counts': counts, 'semantic_type_proven': False}


def _example(batch, generation, candidate, ordinal, authorized_only):
    detail = inspection_detail(batch, ordinal, start=candidate['start'], end=candidate['end'],
                               authorized_only=authorized_only, generation=generation)
    row = detail['row']
    if row is None: return None
    cells = {cell['position']: cell for cell in row['cells']}
    permitted = [(item['start'], item['end']) for item in batch['samples'].get('authorized_spans', [])
                 if item['ordinal'] == ordinal] if authorized_only else [(candidate['start'], candidate['end'])]
    proofs, seen, possible = [], set(), 0
    for left, right in permitted:
        start, end = max(left, candidate['start']), min(right, candidate['end'])
        if start >= end or (start, end) in seen: continue
        seen.add((start, end)); possible += 1
        if len(proofs) == MAX_EXAMPLE_PROOFS: continue
        raw = bytes.fromhex(''.join(cells[position]['hex'] for position in range(start, end)))
        proof = {'ordinal': ordinal, 'start': start, 'end': end,
                 'source_sha256': batch['source_sha256'], 'framing_sha256': batch['framing_sha256'],
                 'byte_start': row['record_ref']['byte_start'] + start, 'raw_hex': raw.hex(), 'raw_sha256': sha256(raw),
                 'record_ref': row['record_ref']}
        resolve_evidence(batch, proof, require_authorized=authorized_only)
        proofs.append(proof)
    return {'record_ref': row['record_ref'], 'span': row['window'], 'cells': row['cells'],
            'visible_evidence': proofs, 'omitted_proof_count': max(0, possible - len(proofs)),
            'patterns': _patterns(row['cells']), 'diagnostic_only': True,
            'record_state_disclosed': row['record_state_disclosed'], 'disposition': row['disposition'],
            'reasons': row['reasons'], 'raw_hex': row['raw_hex'], 'redacted_byte_count': row['redacted_in_window'],
            'typed_value': 'not_inferred'}


def _explain(batch, generation, page, groups, candidate_id, authorized_only, examples_limit):
    candidate = next((value for value in generation['candidates'] if value['id'] == candidate_id), None)
    result = {'schema_version': 1, 'kind': 'candidate_ambiguity_explanation', 'candidate_id': candidate_id,
              'access_mode': page['access_mode'], 'provenance': page['provenance'], 'counts': page['counts'],
              'source_status': page['source_status'], 'source_reasons': page['source_reasons'],
              'diagnostic_only': True, 'approval_status': 'unapproved', 'ranking_is_approval': False,
              'correct_policy_available': 'not_established', 'no_correct_option_action': 'unknown',
              'candidate_recall': 'not_measured', 'examples': [], 'examples_limit': examples_limit}
    if candidate is None:
        result.update(state='abstained' if candidate_id == 'unknown' else 'not_offered',
                      candidate=None, alternatives=[], examples_state='unavailable',
                      decision_reasons=['No offered candidate is established as correct. Preserve unknown; do not invent a policy or byte range.'])
        return dict(result, explanation_sha256=digest(result))
    alternatives = sorted(groups[(candidate['start'], candidate['end'])], key=lambda value: (value['semantic_target'], value['id']))
    names = sorted({value['semantic_target'] for value in alternatives})
    policies = [value for value in alternatives if value['semantic_target'] == candidate['semantic_target']]
    axes = None
    declared_fields = generation.get('discovery', {}).get('fields', [])
    if not isinstance(declared_fields, list) or len(declared_fields) > 32:
        raise ValueError('explanation profile metadata budget/type invalid')
    for field in declared_fields:
        if not isinstance(field, dict): raise ValueError('explanation field metadata invalid')
        if field.get('start') == candidate['start'] and field.get('end') == candidate['end']:
            interpretations = field.get('interpretations', [])
            if not isinstance(interpretations, list) or len(interpretations) > 5 or any(not isinstance(value, dict) for value in interpretations):
                raise ValueError('explanation interpretation metadata invalid')
            axes = next((value for value in interpretations if value.get('semantic_target') == candidate['semantic_target']), None)
            break
    omitted = axes.get('unoffered_combination_count') if isinstance(axes, dict) else None
    if type(omitted) is not int or not 0 <= omitted <= 1000000: omitted = None
    reasons = [f"Bytes [{candidate['start']},{candidate['end']}) are proposed as {candidate['semantic_target']}; the proposal does not establish the business name.",
               'The byte boundary and padding interpretation require an explicit decision; diagnostic characters are not converted values.']
    if candidate['data_type'] == 'decimal':
        scales = sorted({value['policy']['scale'] for value in policies if type(value['policy'].get('scale')) is int})
        reasons.append(f'Visible digits do not establish implied decimal scale. Offered scales for this name/span: {scales}. Sign and precision also remain declared policy choices.')
    if candidate['data_type'] == 'date':
        reasons.append('Digit/calendar shapes do not establish date format, century window or blank/all-nines null policy. A zero date has no supported null shortcut.')
    if candidate['semantic_target'] == 'status' and not any('allowed_codes' in value['policy'] for value in policies):
        reasons.append('No status vocabulary is disclosed in these policy choices. An unlisted code is unknown, not a manufactured malformed-code verdict.')
    reasons.append('If the true span/name/policy combination is absent, choose unknown; bounded alternatives do not prove coverage.')
    ordinals = []
    for record in batch['records']:
        if candidate['end'] > record['length']: continue
        if authorized_only and not any(item['ordinal'] == record['ordinal'] and item['start'] < candidate['end'] and candidate['start'] < item['end']
                                       for item in batch['samples'].get('authorized_spans', [])): continue
        ordinals.append(record['ordinal'])
    for ordinal in ordinals[:examples_limit]:
        example = _example(batch, generation, candidate, ordinal, authorized_only)
        if example is not None: result['examples'].append(example)
    result.update(state='decision_required', candidate={'id': candidate['id'], 'start': candidate['start'], 'end': candidate['end'],
                  'semantic_target': candidate['semantic_target'], 'data_type': candidate['data_type'],
                  'origin': candidate['origin'], 'confirmation': 'unconfirmed'},
        alternatives=[{'candidate_id': value['id'], 'semantic_target': value['semantic_target'],
                       'data_type': value['data_type'], 'policy_summary': _policy(value['policy'])} for value in alternatives],
        proposed_names=names, typed_policy_options_for_name=len(policies), unoffered_combination_count=omitted,
        unoffered_count_basis='producer_metadata_not_measured_candidate_recall',
        decision_reasons=reasons, available_example_count=len(ordinals),
        examples_state='capped_to_zero' if examples_limit == 0 else 'available' if result['examples'] else 'no_authorized_examples' if authorized_only else 'no_retained_examples',
        examples_truncated=len(ordinals) > len(result['examples']),
        dependent_row_impact={'eligible_rows': page['counts']['eligible'], 'quarantined_rows': page['counts']['quarantined'],
                              'unmaterialized_rows': page['counts']['unmaterialized'],
                              'basis': 'shared layout interpretation, not proved correct semantic values'})
    return dict(result, explanation_sha256=digest(result))


def explain_candidate(batch: dict, generation: dict, candidate_id: str, *, authorized_only=True, examples_limit=3) -> dict:
    _integer(examples_limit, 'examples_limit', 0, MAX_EXAMPLES)
    if not isinstance(candidate_id, str) or candidate_id != 'unknown' and not re.fullmatch(r'[0-9a-f]{64}', candidate_id):
        raise ValueError('candidate_id must be an offered SHA256 identity or unknown')
    batch, generation, page, groups = _context(batch, generation, authorized_only)
    return _explain(batch, generation, page, groups, candidate_id, authorized_only, examples_limit)


def explain_layout(batch: dict, generation: dict, *, authorized_only=True, offset=0, limit=8, examples_limit=1) -> dict:
    _integer(limit, 'limit', 1, MAX_LAYOUT_FIELDS)
    _integer(examples_limit, 'examples_limit', 0, MAX_EXAMPLES)
    batch, generation, page, groups = _context(batch, generation, authorized_only)
    ordered = sorted(groups)
    _integer(offset, 'offset', 0, len(ordered))
    stop = min(offset + limit, len(ordered))
    fields = []
    for span in ordered[offset:stop]:
        # A representative chooses presentation only, never a selected/ranked policy.
        candidate = min(groups[span], key=lambda value: (0 if value['data_type'] == 'decimal' else 1 if value['data_type'] == 'date' else 2,
                                                        value['semantic_target'], value['id']))
        field = _explain(batch, generation, page, groups, candidate['id'], authorized_only, examples_limit)
        field['representative_is_selection'] = False
        field['explanation_sha256'] = digest({key: value for key, value in field.items() if key != 'explanation_sha256'})
        fields.append(field)
    offered = {value['semantic_target'] for value in generation['candidates']}
    value = {'schema_version': 1, 'kind': 'layout_ambiguity_summary', 'state': 'decision_required' if fields else 'no_candidates' if not ordered else 'empty',
             'provenance': page['provenance'], 'counts': page['counts'], 'access_mode': page['access_mode'],
             'source_status': page['source_status'], 'source_reasons': page['source_reasons'],
             'offset': offset, 'limit': limit, 'next_offset': stop if stop < len(ordered) else None,
             'physical_field_count': len(ordered), 'candidate_count': len(generation['candidates']),
             'targets_without_candidates': [name for name in REQUIRED_FIELDS if name not in offered],
             'fields': fields, 'candidate_recall': 'not_measured', 'correct_policy_available': 'not_established',
             'no_correct_option_action': 'unknown', 'approval_status': 'unapproved', 'diagnostic_only': True}
    return dict(value, explanation_sha256=digest(value))

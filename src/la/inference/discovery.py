"""Bounded byte-only boundary proposals; scores are support, not correctness."""
from collections import Counter
from la.contracts import digest
from la.contracts.evidence import validate_discovery_metadata
from la.ingest.evidence import verify_records

MAX_FIELDS = 32


def _class(byte: int) -> str:
    if byte == 32: return 'space'
    if 48 <= byte <= 57: return 'digit'
    if byte in (43, 45): return 'sign'
    if 65 <= byte <= 90 or 97 <= byte <= 122: return 'letter'
    return 'other'


def _date_shape(value: bytes) -> bool:
    if len(value) not in (6, 8): return False
    if value in (b' ' * len(value), b'9' * len(value), b'0' * len(value)): return True
    return value.isdigit() and 1 <= int(value[-4:-2]) <= 12 and 1 <= int(value[-2:]) <= 31


def discover_fields(batch: dict) -> dict:
    """Return at most32 spans from full-input deterministic profiles.

    Raw prompt evidence is separately gated by permitted samples. Unknown widths,
    same-class adjacency and bounded-out alternatives remain explicit abstentions.
    This function does not select a layout or use semantic field ordering.
    """
    verify_records(batch)
    records = [record for record in batch['records'] if record['disposition'] == 'eligible']
    width = batch['width']
    base = {'version': 1, 'source_sha256': batch['source_sha256'],
            'framing_sha256': batch['framing_sha256'], 'eligible_record_count': len(records),
            'dependent_ordinals': [record['ordinal'] for record in records],
            'max_fields': MAX_FIELDS, 'spans': [], 'boundary_proposals': [], 'column_profiles': [],
            'coverage_status': 'unproven', 'abstention_reasons': [], 'omitted_span_count': 0}
    if batch['status'] != 'accepted' or width is None or not records:
        base['abstention_reasons'] = ['input_not_eligible']
        return validate_discovery_metadata(dict(base, discovery_sha256=digest(base)))
    rows = [bytes.fromhex(record['raw_hex']) for record in records]
    profiles = []
    for position in range(width):
        classes = Counter(_class(raw[position]) for raw in rows)
        profiles.append({'position': position, 'class_counts': dict(sorted(classes.items())),
                         'constant_byte': rows[0][position] if all(raw[position] == rows[0][position] for raw in rows) else None})
    proposals = {0: {'edge': len(rows)}, width: {'edge': len(rows)}}
    for position in range(1, width):
        counts = Counter()
        for raw in rows:
            left, right = _class(raw[position - 1]), _class(raw[position])
            if left != right and left != 'sign' and right != 'sign': counts['class_transition'] += 1
            if (left == 'space') != (right == 'space'): counts['padding_transition'] += 1
            if right == 'sign': counts['leading_sign'] += 1
            if left == 'sign' and right != 'digit': counts['trailing_sign'] += 1
        if counts and max(counts.values()) * 4 >= len(rows) * 3:
            proposals[position] = dict(sorted(counts.items()))
    # Dates may occur anywhere, including adjacent digit fields; semantic meaning
    # and century/sentinel choices are deliberately absent from this detector.
    date_spans = []
    for start in range(width):
        for size in (8, 6):
            end = start + size
            if end > width: continue
            support = sum(_date_shape(raw[start:end]) for raw in rows)
            real = sum(raw[start:end].isdigit() and raw[start:end] not in (b'0' * size, b'9' * size)
                       and _date_shape(raw[start:end]) for raw in rows)
            if support * 4 >= len(rows) * 3 and real:
                date_spans.append((start, end, support))
    # Anchored dates outrank coincidental interior six-digit calendar shapes.
    date_spans.sort(key=lambda item: (-(int(item[0] in proposals) + int(item[1] in proposals)),
                                      -(item[1] - item[0]), item[0]))
    ranked = {}
    def offer(start, end, reason, score):
        if not 0 <= start < end <= width or all(not raw[start:end].strip(b' ') for raw in rows): return
        item = ranked.setdefault((start, end), {'start': start, 'end': end, 'reasons': [], 'support': score})
        if reason not in item['reasons']: item['reasons'].append(reason)
        item['support'] = max(item['support'], score)
    points = sorted(proposals)
    for start, end in zip(points, points[1:]):
        offer(start, end, 'stable_transition_segment', len(rows))
    # Combine all-space prefix/suffix segments with their adjacent token. Internal
    # spaces remain a competing full text span rather than being silently trimmed.
    for index, (start, end) in enumerate(zip(points, points[1:])):
        if all(raw[start:end] == b' ' * (end - start) for raw in rows):
            if index: offer(points[index - 1], end, 'right_padding_alternative', len(rows))
            if index + 2 < len(points): offer(start, points[index + 2], 'left_padding_alternative', len(rows))
    # A text field can contain words, spaces and digits. Internal transitions
    # are competing boundaries, not proof that every token is a separate field.
    # Offer a small set of enclosing text intervals, using only byte profiles.
    forbidden = [0]
    letters = [0]
    text_edges = {0, width}
    for position, profile in enumerate(profiles):
        counts = profile['class_counts']
        forbidden.append(forbidden[-1] + counts.get('sign', 0) + counts.get('other', 0))
        letters.append(letters[-1] + int(counts.get('letter', 0) * 4 >= len(rows) * 3))
        if counts.get('sign', 0) * 4 >= len(rows) * 3:
            text_edges.add(position)
        if position and profiles[position - 1]['class_counts'].get('digit', 0) * 4 >= len(rows) * 3 and counts.get('letter', 0) * 4 >= len(rows) * 3:
            text_edges.add(position)
    unions = []
    for index, start in enumerate(points):
        for end in points[index + 2:]:
            bad = forbidden[end] - forbidden[start]
            if letters[end] > letters[start] and bad * 4 <= len(rows):
                unions.append((start, end, len(rows) - bad))
    unions.sort(key=lambda item: (-(int(item[0] in text_edges) + int(item[1] in text_edges)),
                                  -item[2], item[1] - item[0], item[0], item[1]))
    text_budget = MAX_FIELDS // 4
    for start, end, support in unions[:text_budget]:
        offer(start, end, 'enclosing_text_alternative', support)
    for start, end, support in date_spans[:16]:
        offer(start, end, 'calendar_shape_alternative', support)
        left = max((point for point in points if point < start), default=0)
        right = min((point for point in points if point > end), default=width)
        if start > left: offer(left, start, 'adjacent_date_prefix', support)
        if end < right: offer(end, right, 'adjacent_date_suffix', support)
    # Finite explicit sign + padded token proposals can cross a transition edge.
    for start, end in list(ranked):
        if start and all(raw[start - 1] in b'+-' for raw in rows): offer(start - 1, end, 'leading_sign_token', len(rows))
        if end < width and all(raw[end] in b'+-' for raw in rows): offer(start, end + 1, 'trailing_sign_token', len(rows))
    spans = sorted(ranked.values(), key=lambda item: (
        -int(any(reason in item['reasons'] for reason in ('stable_transition_segment', 'right_padding_alternative', 'left_padding_alternative', 'enclosing_text_alternative'))),
        -item['support'], item['start'], item['end']))
    selected = spans[:MAX_FIELDS]
    for item in selected:
        item['reasons'].sort()
        item['field_id'] = digest({'source': batch['source_sha256'], 'framing': batch['framing_sha256'],
                                   'start': item['start'], 'end': item['end']})
        item['dependent_row_count'] = len(rows)
        item['coverage'] = 'candidate_only'
    base.update(spans=selected, column_profiles=profiles,
                boundary_proposals=[{'offset': point, 'support': proposals[point]} for point in points],
                date_shape_proposal_count=len(date_spans), date_shape_budget=16,
                omitted_date_shape_count=max(0, len(date_spans) - 16),
                support_threshold={'numerator': 3, 'denominator': 4},
                omitted_span_count=max(0, len(spans) - MAX_FIELDS) + max(0, len(unions) - text_budget),
                abstention_reasons=['same_class_adjacency_may_be_missing', 'candidate_presence_not_truth',
                                    'all_policies_require_confirmation'])
    if len(spans) > MAX_FIELDS: base['abstention_reasons'].append('field_budget_exhausted')
    if len(date_spans) > 16: base['abstention_reasons'].append('date_shape_budget_exhausted')
    if len(unions) > text_budget: base['abstention_reasons'].append('text_union_budget_exhausted')
    return validate_discovery_metadata(dict(base, discovery_sha256=digest(base)))

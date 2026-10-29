"""Byte framing with retained separators and separately authorized evidence."""
from collections import Counter
from la.contracts import digest, sha256, validate_batch
from la.contracts.evidence import validate_intake_metadata, validate_sample_metadata
from .evidence import authorize_samples, resolve_evidence, verify_records
from .limits import LIMITS


def ingest_bytes(data: bytes, brief: str, permitted_samples: dict, *, declared_encoding='ASCII',
                 declared_record_type='fixed-width', declared_numeric='ascii', declared_family=None) -> dict:
    """Retain every materialized ordinal; refuse limits before splitting/hex expansion."""
    if not isinstance(data, bytes) or not isinstance(brief, str):
        raise TypeError('data must be bytes and brief must be text')
    source = sha256(data)
    if declared_family is not None: declared_record_type = declared_family
    declarations = {'encoding': declared_encoding, 'record_family': declared_record_type, 'numeric': declared_numeric}
    if any(not isinstance(value, str) or len(value) > 128 for value in declarations.values()):
        raise ValueError('declarations must be bounded text of at most128 characters')
    reasons = []
    if declared_encoding.upper() != 'ASCII': reasons.append('unsupported_encoding')
    if declared_record_type != 'fixed-width': reasons.append('unsupported_record_family')
    if declared_numeric != 'ascii':
        reasons.append('unsupported_packed_decimal' if declared_numeric == 'packed_decimal' else 'unsupported_numeric')
    if not data: reasons.append('empty_input')
    if len(data) > LIMITS['bytes']: reasons.append('file_limit')
    if len(brief) > LIMITS['brief']: reasons.append('brief_limit')
    newline_count = data.count(b'\n')
    observed_count = newline_count + int(bool(data) and not data.endswith(b'\n'))
    if data and not newline_count: reasons.append('separatorless_unsupported')
    if observed_count > LIMITS['records']: reasons.append('record_limit')
    hard_refusal = bool(reasons)
    rows, separators, styles = [], [], set()
    if not hard_refusal:
        cursor = 0
        for ordinal in range(observed_count):
            newline = data.find(b'\n', cursor)
            terminated = newline >= 0
            end = newline if terminated else len(data)
            crlf = terminated and end > cursor and data[end - 1] == 13
            raw_end = end - int(crlf)
            separator = b'\r\n' if crlf else b'\n' if terminated else b''
            raw = data[cursor:raw_end]
            rows.append((ordinal, cursor, raw))
            separators.append({'ordinal': ordinal, 'byte_start': raw_end, 'raw_hex': separator.hex(), 'length': len(separator)})
            if terminated: styles.add('CRLF' if crlf else 'LF')
            cursor = end + int(terminated)
    if len(styles) > 1: reasons.append('mixed_separators')
    if any(b'\r' in raw for _, _, raw in rows): reasons.append('bare_cr')
    counts = Counter(len(raw) for _, _, raw in rows if 0 < len(raw) <= LIMITS['width'])
    highest = max(counts.values(), default=0)
    choices = sorted(width for width, count in counts.items() if count == highest)
    width = choices[0] if len(choices) == 1 else None
    if rows and width is None: reasons.append('unresolved_width')
    framing = next(iter(styles)) if len(styles) == 1 else 'unresolved'
    framing_policy = {'version': 2, 'framing': framing, 'width': width,
                      'width_candidates': choices, 'terminal_newline': data.endswith(b'\n')}
    framing_hash = digest(framing_policy)
    records = []
    for ordinal, offset, raw in rows:
        row_reasons = []
        if width is None: row_reasons.append('unresolved_width')
        elif len(raw) != width: row_reasons.append('wrong_length')
        if not raw: row_reasons.append('blank_record')
        if len(raw) > LIMITS['width']: row_reasons.append('record_width_limit')
        if any(byte > 127 for byte in raw): row_reasons.append('high_byte')
        if b'\r' in raw: row_reasons.append('bare_cr')
        if len(styles) > 1: row_reasons.append('mixed_separators')
        records.append(dict(source_sha256=source, framing_sha256=framing_hash, ordinal=ordinal,
                            byte_start=offset, length=len(raw), raw_sha256=sha256(raw), raw_hex=raw.hex(),
                            disposition='quarantined' if row_reasons else 'eligible', reasons=row_reasons))
    intake = {'framing_policy': framing_policy, 'separators': separators,
              'width_histogram': [{'width': item, 'count': counts[item]} for item in sorted(counts)],
              'width_candidates': choices, 'width_status': 'resolved' if width else 'unresolved',
              'width_question': {'kind': 'record_width', 'options': choices + ['unknown']} if len(choices) > 1 else None,
              'observed_record_count': observed_count, 'materialized_record_count': len(records),
              'unmaterialized_record_count': observed_count - len(records), 'bounded_refusal': hard_refusal,
              'input_byte_count': len(data), 'terminal_newline': data.endswith(b'\n'),
              'final_record_width_valid': bool(records and width and records[-1]['length'] == width),
              'final_record_eligible': bool(records and records[-1]['disposition'] == 'eligible')}
    samples, sample_reasons = authorize_samples(dict(source_sha256=source, framing_sha256=framing_hash, records=records), permitted_samples)
    reasons.extend(sample_reasons)
    samples['intake'] = intake
    intake = validate_intake_metadata(intake)
    samples = validate_sample_metadata(samples)
    return validate_batch(dict(schema_version=1, source_sha256=source, framing_sha256=framing_hash,
        framing=framing, encoding='ASCII', declared_format=declarations, width=width,
        status='refused' if reasons else 'accepted', reasons=sorted(set(reasons)), records=records,
        brief_sha256=sha256(brief.encode('utf-8')), samples=samples, intake=intake,
        config_sha256=digest({'limits': LIMITS, 'declarations': declarations, 'intake_version': 2})))


def intake_metadata(batch: dict) -> dict:
    return validate_intake_metadata(batch['samples']['intake'])

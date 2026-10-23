"""Retain every framed row; authorization samples resolve to exact source bytes."""
from collections import Counter
from la.contracts import digest, sha256, validate_batch

LIMITS = {'bytes': 5 * 1024 * 1024, 'records': 10000, 'width': 256, 'brief': 4000}

def ingest_bytes(data: bytes, brief: str, permitted_samples: dict, *, declared_encoding='ASCII', declared_record_type='fixed-width', declared_numeric='ascii', declared_family=None) -> dict:
    source = sha256(data)
    reasons = []
    if declared_family is not None: declared_record_type=declared_family
    if declared_encoding.upper() != 'ASCII': reasons.append('unsupported_encoding')
    if declared_record_type != 'fixed-width': reasons.append('unsupported_record_family')
    if declared_numeric != 'ascii': reasons.append('unsupported_packed_decimal' if declared_numeric=='packed_decimal' else 'unsupported_numeric')
    if not data: reasons.append('empty_input')
    if len(data) > LIMITS['bytes']: reasons.append('file_limit')
    if len(brief) > LIMITS['brief']: reasons.append('brief_limit')
    if b'\n' not in data: reasons.append('separatorless_unsupported')
    parts = data.split(b'\n')
    if data.endswith(b'\n'): parts.pop()
    styles = set()
    rows = []
    cursor = 0
    for ordinal, part in enumerate(parts):
        terminated = ordinal < len(parts)-1 or data.endswith(b'\n')
        crlf = terminated and part.endswith(b'\r')
        raw = part[:-1] if crlf else part
        if terminated: styles.add('CRLF' if crlf else 'LF')
        rows.append((ordinal, cursor, raw))
        cursor += len(part) + (1 if terminated else 0)
    if len(styles) > 1: reasons.append('mixed_separators')
    if any(b'\r' in raw for _, _, raw in rows): reasons.append('bare_cr')
    if len(rows) > LIMITS['records']: reasons.append('record_limit')
    counts = Counter(len(raw) for _, _, raw in rows if 0 < len(raw) <= LIMITS['width'])
    choices = [n for n, count in counts.items() if count == max(counts.values(), default=0)]
    width = choices[0] if len(choices) == 1 else None
    if width is None: reasons.append('unresolved_width')
    framing = next(iter(styles)) if len(styles) == 1 else 'unresolved'
    framing_hash = digest({'framing': framing, 'width': width, 'terminal_newline': data.endswith(b'\n')})
    records = []
    for ordinal, offset, raw in rows:
        row_reasons = []
        if len(raw) != width: row_reasons.append('wrong_length')
        if len(raw) > LIMITS['width']: row_reasons.append('record_width_limit')
        if any(byte > 127 for byte in raw): row_reasons.append('high_byte')
        if b'\r' in raw: row_reasons.append('bare_cr')
        records.append(dict(source_sha256=source, framing_sha256=framing_hash, ordinal=ordinal,
            byte_start=offset, length=len(raw), raw_sha256=sha256(raw), raw_hex=raw.hex(),
            disposition='quarantined' if row_reasons else 'eligible', reasons=row_reasons))
    authorized = []
    if permitted_samples.get('source_sha256') != source: reasons.append('sample_source_mismatch')
    if not isinstance(permitted_samples.get('authorization'), str) or not permitted_samples.get('authorization'):
        reasons.append('sample_authorization_missing')
    for sample in permitted_samples.get('records', []):
        ordinal = sample.get('ordinal')
        if type(ordinal) is not int or ordinal < 0 or ordinal >= len(records):
            reasons.append('sample_reference_invalid'); continue
        record = records[ordinal]
        if sample.get('raw_sha256') != record['raw_sha256'] or sample.get('raw_hex') != record['raw_hex']:
            reasons.append('sample_bytes_mismatch'); continue
        authorized.append(record)
    samples = {'authorization': permitted_samples.get('authorization', ''), 'artifact_sha256': digest(permitted_samples),
        'records': authorized[:64], 'selected_ordinals': [r['ordinal'] for r in authorized[:64]],
        'truncated': len(authorized) > 64}
    return validate_batch(dict(schema_version=1, source_sha256=source, framing_sha256=framing_hash,
        framing=framing, encoding='ASCII', declared_format={'encoding':declared_encoding,'record_family':declared_record_type,'numeric':declared_numeric}, width=width, status='refused' if reasons else 'accepted',
        reasons=sorted(set(reasons)), records=records, brief_sha256=sha256(brief.encode()), samples=samples,
        config_sha256=digest(dict(LIMITS,declared_encoding=declared_encoding,
            declared_record_type=declared_record_type,declared_numeric=declared_numeric))))

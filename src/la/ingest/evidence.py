"""Exact source evidence and fail-closed permitted-sample authorization."""
from copy import deepcopy
from la.contracts import digest, sha256
from la.contracts.evidence import (validate_sample_artifact, validate_sample_metadata,
                                   validate_intake_metadata, validate_span_evidence)
from .observed import validate_observed_refusal

REF_KEYS = ('source_sha256', 'framing_sha256', 'ordinal', 'byte_start', 'length', 'raw_sha256')
SAMPLE_KEYS = set(REF_KEYS) | {'raw_hex', 'start', 'end', 'record_ref', 'span'}
ARTIFACT_KEYS = {'schema_version', 'source_sha256', 'framing_sha256', 'authorization', 'records', 'artifact_sha256'}


def verify_records(batch: dict, source: bytes | None = None) -> None:
    validate_sample_metadata(batch['samples'])
    validate_intake_metadata(batch.get('intake', {}))
    if source is not None and sha256(source) != batch['source_sha256']:
        raise ValueError('source identity mismatch')
    cursor = 0
    for ordinal, record in enumerate(batch['records']):
        raw = bytes.fromhex(record['raw_hex'])
        if (type(record['ordinal']) is not int or type(record['length']) is not int
                or record['ordinal'] != ordinal or record['source_sha256'] != batch['source_sha256']
                or record['framing_sha256'] != batch['framing_sha256'] or len(raw) != record['length']
                or sha256(raw) != record['raw_sha256'] or type(record['byte_start']) is not int
                or record['byte_start'] < cursor):
            raise ValueError('record identity mismatch')
        cursor = record['byte_start'] + record['length']
        if source is not None and source[record['byte_start']:cursor] != raw:
            raise ValueError('record does not resolve to source bytes')
    intake = batch.get('samples', {}).get('intake')
    if batch.get('intake') and batch['intake'] != intake:
        raise ValueError('intake metadata copies differ')
    if intake and ('stream_observation' in intake or intake.get('framing_policy', {}).get('kind') == 'unmaterialized_stream_refusal'):
        observation = validate_observed_refusal(batch)
        if source is not None:
            count = source.count(b'\n') + int(bool(source) and not source.endswith(b'\n'))
            if (len(source) != observation['input_byte_count']
                    or observation['observed_count'] is not None and count != observation['observed_count']
                    or observation['terminal_newline'] is not None and source.endswith(b'\n') != observation['terminal_newline']):
                raise ValueError('provided bytes contradict stream observation counts')
    if intake:
        if digest(intake['framing_policy']) != batch['framing_sha256']:
            raise ValueError('framing policy identity mismatch')
        if len(intake['separators']) != len(batch['records']): raise ValueError('separator cardinality mismatch')
        retained = bytearray()
        for record, separator in zip(batch['records'], intake['separators']):
            raw, ending = bytes.fromhex(record['raw_hex']), bytes.fromhex(separator['raw_hex'])
            if (record['byte_start'] != len(retained) or separator['ordinal'] != record['ordinal']
                    or separator['byte_start'] != len(retained) + len(raw)
                    or separator['length'] != len(ending) or ending not in (b'', b'\n', b'\r\n')):
                raise ValueError('separator identity mismatch')
            retained.extend(raw); retained.extend(ending)
        if not intake['bounded_refusal'] and sha256(bytes(retained)) != batch['source_sha256']:
            raise ValueError('retained bytes do not reconstruct source')
    _checked_selection(batch)


def _checked_selection(batch: dict) -> list[dict]:
    """Resolve supplied permission metadata without rewriting a legacy batch.

    The legacy five-field result explicitly permits whole retained records. Its
    absence of a modern selection hash must never be filled into the hashed
    wire object. Current metadata always uses its supplied span selection.
    """
    samples = batch['samples']
    records = batch['records']
    for sample in samples['records']:
        ordinal = sample['ordinal']
        if ordinal >= len(records) or sample != records[ordinal]:
            raise ValueError('permitted whole record does not resolve to retained source')
    if 'authorized_spans' in samples:
        selected = samples['authorized_spans']
    else:
        if samples['selected_ordinals'] != [record['ordinal'] for record in samples['records']]:
            raise ValueError('legacy selected ordinals do not match permitted records')
        if len(set(samples['selected_ordinals'])) != len(samples['selected_ordinals']):
            raise ValueError('duplicate legacy permitted record')
        # Historical metadata did not retain original artifact indices. A view
        # must not invent them from positions in the selected-record list.
        selected = [dict(ordinal=record['ordinal'], start=0, end=record['length'],
                         raw_hex=record['raw_hex'], raw_sha256=record['raw_sha256'])
                    for record in samples['records']]
    if selected and not samples['authorization'].strip():
        raise ValueError('explicit authorization required for permitted spans')
    total = 0
    for item in selected:
        ordinal, start, end = item['ordinal'], item['start'], item['end']
        if ordinal >= len(records) or not 0 <= start < end <= records[ordinal]['length']:
            raise ValueError('permitted span does not resolve to retained record')
        raw = bytes.fromhex(records[ordinal]['raw_hex'])[start:end]
        if raw.hex() != item['raw_hex'] or sha256(raw) != item['raw_sha256']:
            raise ValueError('permitted span bytes do not resolve to retained source')
        total += end - start
    if total > 16384 or len({item['ordinal'] for item in selected}) > 64:
        raise ValueError('permitted selection exceeds evidence bounds')
    if 'authorized_spans' in samples:
        for record in samples['records']:
            if not any(item['ordinal'] == record['ordinal'] and item['start'] == 0
                       and item['end'] == record['length'] for item in selected):
                raise ValueError('whole sample is outside current span authorization')
    return selected


def authorized_spans(batch: dict) -> list[dict]:
    """Verified current or legacy selection view; no inserted wire/hash fields."""
    verify_records(batch)
    return deepcopy(_checked_selection(batch))


def resolve_evidence(batch: dict, evidence: dict, *, source: bytes | None = None, require_authorized=False) -> bytes:
    evidence = validate_span_evidence(evidence)
    verify_records(batch, source)
    ordinal = evidence.get('ordinal')
    if type(ordinal) is not int or not 0 <= ordinal < len(batch['records']): raise ValueError('evidence ordinal invalid')
    record = batch['records'][ordinal]
    start, end = evidence.get('start'), evidence.get('end')
    if type(start) is not int or type(end) is not int or not 0 <= start < end <= record['length']:
        raise ValueError('evidence range invalid')
    if type(evidence.get('byte_start')) is not int:
        raise ValueError('evidence absolute offset must be an integer')
    raw = bytes.fromhex(record['raw_hex'])[start:end]
    expected = {'source_sha256': batch['source_sha256'], 'framing_sha256': batch['framing_sha256'],
                'byte_start': record['byte_start'] + start, 'raw_hex': raw.hex(), 'raw_sha256': sha256(raw)}
    if any(evidence.get(key) != value for key, value in expected.items()): raise ValueError('evidence identity/hash mismatch')
    if 'record_ref' in evidence:
        ref = evidence['record_ref']
        if (not isinstance(ref, dict) or ref != {key: record[key] for key in REF_KEYS}
                or any(type(ref.get(key)) is not int for key in ('ordinal', 'byte_start', 'length'))):
            raise ValueError('evidence record reference mismatch')
    if require_authorized:
        selected = _checked_selection(batch)
        matches = [item for item in selected if item['ordinal'] == ordinal and item['start'] <= start and end <= item['end']]
        if not matches: raise ValueError('evidence outside permitted sample spans')
        for item in matches:
            permitted = bytes.fromhex(record['raw_hex'])[item['start']:item['end']]
            if permitted.hex() != item['raw_hex'] or sha256(permitted) != item['raw_sha256']:
                raise ValueError('permitted span bytes changed')
    return raw


def make_evidence(batch: dict, ordinal: int, start: int, end: int) -> dict:
    record = batch['records'][ordinal]
    raw = bytes.fromhex(record['raw_hex'])[start:end]
    value = dict(ordinal=ordinal, start=start, end=end, source_sha256=batch['source_sha256'],
                 framing_sha256=batch['framing_sha256'], byte_start=record['byte_start'] + start,
                 raw_hex=raw.hex(), raw_sha256=sha256(raw), record_ref={key: record[key] for key in REF_KEYS})
    resolve_evidence(batch, value, require_authorized=True)
    return value


def authorize_samples(batch: dict, artifact: dict) -> tuple[dict, list[str]]:
    reasons, authorized = [], []
    try:
        validate_sample_artifact(artifact)
    except ValueError:
        reasons.append('sample_protocol_invalid')
    if not isinstance(artifact, dict): artifact = {}; reasons.append('sample_artifact_invalid')
    if set(artifact) - ARTIFACT_KEYS: reasons.append('sample_extra_fields')
    if type(artifact.get('schema_version', 1)) is not int or artifact.get('schema_version', 1) != 1:
        reasons.append('sample_schema_invalid')
    if artifact.get('source_sha256') != batch['source_sha256']: reasons.append('sample_source_mismatch')
    if 'framing_sha256' in artifact and artifact['framing_sha256'] != batch['framing_sha256']:
        reasons.append('sample_framing_mismatch')
    authorization = artifact.get('authorization')
    if not isinstance(authorization, str) or not authorization.strip() or len(authorization) > 1000:
        reasons.append('sample_authorization_missing')
    content_hash = digest({key: value for key, value in artifact.items() if key != 'artifact_sha256'})
    if 'artifact_sha256' in artifact and artifact['artifact_sha256'] != content_hash: reasons.append('sample_artifact_hash_mismatch')
    samples = artifact.get('records', [])
    if not isinstance(samples, list) or len(samples) > 10000:
        reasons.append('sample_record_limit_or_type'); samples = []
    seen = set()
    for index, sample in enumerate(samples):
        if not isinstance(sample, dict) or set(sample) - SAMPLE_KEYS:
            reasons.append('sample_reference_invalid'); continue
        reference = sample.get('record_ref', sample)
        if not isinstance(reference, dict): reasons.append('sample_reference_invalid'); continue
        ordinal = reference.get('ordinal')
        if type(ordinal) is not int or not 0 <= ordinal < len(batch['records']):
            reasons.append('sample_reference_invalid'); continue
        record = batch['records'][ordinal]
        if 'record_ref' in sample and set(reference) != set(REF_KEYS):
            reasons.append('sample_reference_invalid'); continue
        if any(key in sample and type(sample[key]) is not int for key in ('ordinal', 'byte_start', 'length')):
            reasons.append('sample_reference_invalid'); continue
        if any(key in reference and type(reference[key]) is not int for key in ('ordinal', 'byte_start', 'length')):
            reasons.append('sample_reference_invalid'); continue
        if 'record_ref' in sample and any(key in sample and sample[key] != record[key]
                                         for key in REF_KEYS if key != 'raw_sha256'):
            reasons.append('sample_reference_mismatch'); continue
        if any(key in reference and reference[key] != record[key] for key in REF_KEYS):
            reasons.append('sample_reference_mismatch'); continue
        span = sample.get('span', {'start': sample.get('start', 0), 'end': sample.get('end', record['length'])})
        if not isinstance(span, dict) or set(span) != {'start', 'end'}: reasons.append('sample_span_invalid'); continue
        if 'span' in sample and any(key in sample and sample[key] != span[key] for key in ('start', 'end')):
            reasons.append('sample_span_invalid'); continue
        start, end = span['start'], span['end']
        if type(start) is not int or type(end) is not int or not 0 <= start < end <= record['length']:
            reasons.append('sample_span_invalid'); continue
        raw = bytes.fromhex(record['raw_hex'])[start:end]
        if sample.get('raw_hex') != raw.hex() or sample.get('raw_sha256') != sha256(raw):
            reasons.append('sample_bytes_mismatch'); continue
        key = (ordinal, start, end)
        if key in seen: reasons.append('sample_duplicate_reference'); continue
        seen.add(key)
        authorized.append(dict(ordinal=ordinal, start=start, end=end, artifact_index=index,
                               raw_hex=raw.hex(), raw_sha256=sha256(raw)))
    if reasons: authorized = []
    selected, ordinals, used = [], set(), 0
    for item in sorted(authorized, key=lambda value: (value['ordinal'], value['start'], value['end'])):
        if len(ordinals | {item['ordinal']}) > 64 or used + item['end'] - item['start'] > 16384: continue
        selected.append(item); ordinals.add(item['ordinal']); used += item['end'] - item['start']
    whole = [batch['records'][item['ordinal']] for item in selected
             if item['start'] == 0 and item['end'] == batch['records'][item['ordinal']]['length']]
    value = {'authorization': authorization if isinstance(authorization, str) and len(authorization) <= 1000 else '',
             'artifact_sha256': digest(artifact), 'content_sha256': content_hash, 'records': whole,
             'authorized_spans': selected, 'selected_ordinals': sorted(ordinals),
             'selected_artifact_indices': [item['artifact_index'] for item in selected],
             'authorized_count': len(authorized), 'selected_byte_count': used, 'truncated': len(selected) < len(authorized),
             'selection_policy': 'ordinal-span-v1', 'selection_sha256': digest(selected)}
    return validate_sample_metadata(value), sorted(set(reasons))

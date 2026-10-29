"""Explicit permitted-sample artifact preparation from an already retained batch.

Pure and in-memory: no framing, file IO, defaults or inferred authorization.
The caller names every record/span; the label records provenance only and
never establishes permission to send bytes to a provider.
"""
from copy import deepcopy

from la.contracts import canonical, digest, sha256, validate_batch
from la.contracts.evidence import validate_sample_artifact
from .evidence import REF_KEYS, authorize_samples, verify_records

MAX_RECORDS = 64
MAX_BYTES = 16384
MAX_SELECTIONS = 10000  # the artifact validator's records array bound
SELECTION_KEYS = {'ordinal', 'start', 'end', 'record_raw_sha256'}
FORM = 'nested-record-ref-span-v1'


def _int(value, message):
    if type(value) is not int:
        raise ValueError(message)
    return value


def _materialized(batch: dict) -> dict:
    batch = validate_batch(deepcopy(batch))
    intake = batch.get('intake') or batch['samples'].get('intake') or {}
    if not intake or intake.get('bounded_refusal') is not False or 'stream_observation' in intake:
        raise ValueError('sample preparation requires a materialized, non-refused intake batch')
    framing_reasons = [reason for reason in batch['reasons'] if not reason.startswith('sample_')]
    if framing_reasons:
        raise ValueError('sample preparation refuses a batch with framing/declaration refusal: '
                         + ','.join(sorted(framing_reasons)))
    if intake.get('materialized_record_count') != len(batch['records']) or not batch['records']:
        raise ValueError('sample preparation requires every observed record to be materialized')
    verify_records(batch)
    return batch


def _selection(item, records) -> tuple[int, int, int, bool]:
    if type(item) is not dict or not item.keys() <= SELECTION_KEYS or 'ordinal' not in item:
        raise ValueError('selection must be an object with ordinal and optional start/end/record_raw_sha256 only')
    ordinal = _int(item['ordinal'], 'selection ordinal must be an exact integer')
    if not 0 <= ordinal < len(records):
        raise ValueError('selection ordinal is not a materialized record')
    record = records[ordinal]
    if ('start' in item) != ('end' in item):
        raise ValueError('selection start and end must occur together')
    implicit = 'start' not in item
    start = 0 if implicit else _int(item['start'], 'selection start must be an exact integer')
    end = record['length'] if implicit else _int(item['end'], 'selection end must be an exact integer')
    if not 0 <= start < end <= record['length']:
        raise ValueError('selection span is empty or outside its record (blank records cannot be sampled)')
    if 'record_raw_sha256' in item and item['record_raw_sha256'] != record['raw_sha256']:
        raise ValueError('selection record pin does not match retained record bytes')
    # Whole-record domain is decided by coverage, matching authorize_samples.
    return ordinal, start, end, start == 0 and end == record['length']


def prepare_permitted_samples(batch: dict, selections: list, authorization: str) -> tuple[dict, dict]:
    """Return (artifact, receipt) for exactly the selected retained bytes.

    Selections are ``{"ordinal": n}`` for a whole record or
    ``{"ordinal": n, "start": s, "end": e}`` for a half-open record-relative
    slice, each optionally pinned with ``record_raw_sha256``. Order is
    preserved; nothing is merged, widened, sorted or defaulted.
    """
    if type(authorization) is not str or not authorization.strip() or len(authorization) > 1000:
        raise ValueError('nonblank authorization provenance label of at most 1000 characters required')
    if type(selections) is not list or not selections:
        raise ValueError('explicit nonempty selection list required; no default records are chosen')
    if len(selections) > MAX_SELECTIONS:
        raise ValueError('selection list exceeds bound')
    batch = _materialized(batch)
    records = batch['records']
    chosen, spans, used = [], {}, 0
    for item in selections:
        ordinal, start, end, whole = _selection(item, records)
        used += end - start
        if used > MAX_BYTES or len(spans.keys() | {ordinal}) > MAX_RECORDS:
            raise ValueError('selection exceeds 64 distinct records or 16384 selected bytes')
        # Caps are checked first, so the occupied-byte sets stay within 16384.
        occupied = spans.setdefault(ordinal, set())
        if any(position in occupied for position in range(start, end)):
            raise ValueError('duplicate or overlapping selection for ordinal ' + str(ordinal))
        occupied.update(range(start, end))
        chosen.append((ordinal, start, end, whole))
    entries = []
    for ordinal, start, end, _ in chosen:
        record = records[ordinal]
        raw = bytes.fromhex(record['raw_hex'])[start:end]
        entries.append({'record_ref': {key: record[key] for key in REF_KEYS},
                        'span': {'start': start, 'end': end},
                        'raw_hex': raw.hex(), 'raw_sha256': sha256(raw)})
    artifact = {'schema_version': 1, 'source_sha256': batch['source_sha256'],
                'framing_sha256': batch['framing_sha256'], 'authorization': authorization,
                'records': entries}
    artifact['artifact_sha256'] = digest(artifact)
    validate_sample_artifact(artifact)
    # Reuse the actual intake authorizer: the prepared artifact must authorize
    # exactly these spans with no refusal or cap truncation.
    metadata, reasons = authorize_samples(batch, artifact)
    expected = sorted((ordinal, start, end) for ordinal, start, end, _ in chosen)
    if (reasons or metadata['truncated'] or metadata['authorized_count'] != len(chosen)
            or [(i['ordinal'], i['start'], i['end']) for i in metadata['authorized_spans']] != expected):
        raise ValueError('prepared artifact failed existing authorization: ' + ','.join(reasons))
    receipt = {'schema_version': 1, 'kind': 'permitted_sample_preparation', 'form': FORM,
               'source_sha256': batch['source_sha256'], 'framing_sha256': batch['framing_sha256'],
               'content_sha256': artifact['artifact_sha256'], 'object_sha256': digest(artifact),
               'file_sha256': sha256(canonical(artifact) + b'\n'),
               'authorization_sha256': sha256(authorization.encode('utf-8')),
               'selection_count': len(chosen), 'selected_record_count': len(spans),
               'selected_byte_count': used,
               'whole_record_count': sum(1 for *_, whole in chosen if whole),
               'partial_span_count': sum(1 for *_, whole in chosen if not whole),
               'selections': [{'ordinal': ordinal, 'start': start, 'end': end,
                               'kind': 'whole_record' if whole else 'partial_span',
                               'raw_sha256': entry['raw_sha256']}
                              for (ordinal, start, end, whole), entry in zip(chosen, entries)],
               'provider_permission': 'not_established_by_label'}
    receipt['receipt_sha256'] = digest(receipt)
    return deepcopy(artifact), receipt

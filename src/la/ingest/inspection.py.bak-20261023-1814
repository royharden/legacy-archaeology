"""Bounded diagnostic byte views. These are not decoded rows or access-control proof."""
from collections import defaultdict
from la.contracts import MappingSpec, digest, validate_batch, validate_generation
from .evidence import REF_KEYS, resolve_evidence, verify_records

MAX_PAGE = 100
MAX_DISPLAY_BYTES = 256
MAX_AUTH_SPANS = 256
MAX_OVERLAYS = 128
MAX_EVIDENCE = 384


def _integer(value, name, low, high):
    if type(value) is not int or not low <= value <= high:
        raise ValueError(f'{name} must be an exact integer in [{low},{high}]')
    return value


def _merge(spans):
    result = []
    for start, end in sorted(spans):
        if result and start <= result[-1][1]: result[-1][1] = max(result[-1][1], end)
        else: result.append([start, end])
    return result


def _prepare(batch, authorized_only, generation, mapping):
    if type(authorized_only) is not bool: raise ValueError('authorized_only must be a boolean')
    if not isinstance(batch, dict) or not isinstance(batch.get('records'), list) or len(batch['records']) > 10000:
        raise ValueError('bounded materialized record list required')
    for record in batch['records']:
        if (not isinstance(record, dict) or type(record.get('length')) is not int
                or not 0 <= record['length'] <= 5 * 1024 * 1024
                or not isinstance(record.get('raw_hex'), str) or len(record['raw_hex']) != record['length'] * 2):
            raise ValueError('bounded exact retained record bytes required')
    if sum(record['length'] for record in batch['records']) > 5 * 1024 * 1024:
        raise ValueError('retained byte inspection limit')
    batch = validate_batch(batch)
    intake = batch.get('intake') or batch['samples'].get('intake') or {}
    materialized = len(batch['records'])
    if intake and (type(intake.get('bounded_refusal')) is not bool
                   or intake['bounded_refusal'] and (materialized or batch['status'] != 'refused')):
        raise ValueError('bounded refusal cannot bypass retained source verification')
    verify_records(batch)
    observed = intake.get('observed_record_count', materialized)
    missing = intake.get('unmaterialized_record_count', 0)
    if (type(observed) is not int or type(missing) is not int or observed < 0 or missing < 0
            or observed != materialized + missing
            or type(intake.get('materialized_record_count', materialized)) is not int
            or intake.get('materialized_record_count', materialized) != materialized):
        raise ValueError('inspection input denominators inconsistent')
    if missing and (materialized or batch['status'] != 'refused' or not intake.get('bounded_refusal')):
        raise ValueError('unmaterialized rows require explicit bounded refusal')
    for separator in intake.get('separators', []):
        if any(type(separator.get(key)) is not int for key in ('ordinal', 'byte_start', 'length')):
            raise ValueError('typed separator identity required')
    counts = {'observed': observed, 'materialized': materialized, 'unmaterialized': missing,
              'eligible': sum(record['disposition'] == 'eligible' for record in batch['records']),
              'quarantined': sum(record['disposition'] == 'quarantined' for record in batch['records']),
              'count_provenance': 'retained_intake' if intake else 'legacy_materialized_records'}
    proof_cache = set()
    def resolve(proof, authorized):
        key = (digest(proof), authorized)
        if key not in proof_cache:
            if len(proof_cache) >= MAX_EVIDENCE: raise ValueError('inspection evidence limit exceeded')
            resolve_evidence(batch, proof, require_authorized=authorized)
            proof_cache.add(key)
    allowed = defaultdict(list)
    if authorized_only:
        samples = batch['samples']
        selected = samples.get('authorized_spans', [])
        if (not isinstance(selected, list) or len(selected) > MAX_AUTH_SPANS
                or digest(selected) != samples.get('selection_sha256') or not samples.get('authorization')):
            raise ValueError('bounded hash-bound permitted selection required')
        total_bytes, ordinals = 0, set()
        for item in selected:
            if not isinstance(item, dict): raise ValueError('invalid permitted span')
            ordinal = _integer(item.get('ordinal'), 'authorized ordinal', 0, materialized - 1)
            record = batch['records'][ordinal]
            start = _integer(item.get('start'), 'authorized start', 0, record['length'] - 1)
            end = _integer(item.get('end'), 'authorized end', start + 1, record['length'])
            proof = {'ordinal': ordinal, 'start': start, 'end': end,
                     'source_sha256': batch['source_sha256'], 'framing_sha256': batch['framing_sha256'],
                     'byte_start': record['byte_start'] + start,
                     'raw_hex': item.get('raw_hex'), 'raw_sha256': item.get('raw_sha256')}
            resolve(proof, True)
            allowed[ordinal].append([start, end]); total_bytes += end - start; ordinals.add(ordinal)
        if total_bytes > 16384 or len(ordinals) > 64: raise ValueError('permitted selection exceeds prompt bounds')
        allowed = {ordinal: _merge(spans) for ordinal, spans in allowed.items()}
    overlays = []
    provenance = {'source_sha256': batch['source_sha256'], 'framing_sha256': batch['framing_sha256'],
                  'brief_sha256': batch['brief_sha256'], 'config_sha256': batch['config_sha256'],
                  'sample_artifact_sha256': batch['samples'].get('artifact_sha256'),
                  'sample_selection_sha256': batch['samples'].get('selection_sha256'),
                  'policy_sha256': None, 'generation_sha256': None, 'mapping_sha256': None,
                  'mapping_status': 'not_supplied',
                  'mapping_unresolved_reasons': [], 'generation_unknown_reasons': [],
                  'source_integrity_scope': 'reconstructed_source' if intake and not missing and not intake['bounded_refusal'] else 'record_hashes_and_retained_metadata'}
    def field_overlay(field, kind):
        if digest({key: value for key, value in field.items() if key != 'id'}) != field['id']:
            raise ValueError('overlay candidate identity mismatch')
        width = batch['width']
        if type(width) is not int or not 0 <= field['start'] < field['end'] <= width:
            raise ValueError('overlay outside declared record width')
        if len(field['evidence']) > 3: raise ValueError('overlay evidence budget exceeded')
        for proof in field['evidence']: resolve(proof, True)
        overlays.append({'kind': kind, 'candidate_id': field['id'], 'start': field['start'], 'end': field['end'],
                         'semantic_target': field['semantic_target'], 'data_type': field['data_type'],
                         'confirmation': 'selected_mapping_unverified' if kind == 'selected' else 'unconfirmed_candidate'})
    if generation is not None:
        if not isinstance(generation, dict) or not isinstance(generation.get('candidates'), list) or len(generation['candidates']) > 480:
            raise ValueError('inspection candidate budget exceeded')
        generation = validate_generation(generation)
        if digest({key: value for key, value in generation.items() if key != 'generation_sha256'}) != generation['generation_sha256']:
            raise ValueError('inspection generation identity mismatch')
        if any(generation[key] != batch[key] for key in ('source_sha256', 'framing_sha256', 'brief_sha256')):
            raise ValueError('inspection generation is stale')
        discovered = generation.get('discovery', {})
        for declared, actual in (('sample_artifact_sha256', batch['samples'].get('artifact_sha256')),
                                 ('sample_selection_sha256', batch['samples'].get('selection_sha256'))):
            if declared in discovered and discovered[declared] != actual:
                raise ValueError('inspection generation authorization is stale')
        if len(generation['candidates']) > 480: raise ValueError('inspection candidate budget exceeded')
        for field in generation['candidates']: field_overlay(field, 'candidate')
        provenance.update(policy_sha256=generation['policy_sha256'], generation_sha256=generation['generation_sha256'])
        provenance.update(generation_unknown_reason_count=len(generation['unknowns']),
            generation_unknown_reasons=generation['unknowns'][:64] if not authorized_only else [],
            generation_unknown_reasons_redacted=authorized_only,
            generation_unknown_reasons_omitted=max(0, len(generation['unknowns']) - 64) if not authorized_only else len(generation['unknowns']))
    if mapping is not None:
        if (not isinstance(mapping, dict) or not isinstance(mapping.get('fields'), list)
                or not isinstance(mapping.get('filler'), list) or len(mapping['fields']) > 32 or len(mapping['filler']) > 32):
            raise ValueError('bounded mapping fields/filler required')
        mapping = MappingSpec.model_validate(mapping).model_dump(exclude_unset=True)
        if digest({key: value for key, value in mapping.items() if key != 'mapping_sha256'}) != mapping['mapping_sha256']:
            raise ValueError('inspection mapping identity mismatch')
        if (any(mapping[key] != batch[key] for key in ('source_sha256', 'framing_sha256', 'width'))
                or len(mapping['fields']) > 32):
            raise ValueError('inspection mapping is stale or unbounded')
        if generation is not None and (mapping['generation_sha256'] != generation['generation_sha256']
                                       or mapping['generation_binding'] != digest(generation)
                                       or mapping['policy_sha256'] != generation['policy_sha256']):
            raise ValueError('inspection mapping generation mismatch')
        for field in mapping['fields']: field_overlay(field, 'selected')
        for item in mapping['filler']:
            if set(item) != {'start', 'end'}: raise ValueError('invalid filler overlay')
            _integer(item['start'], 'filler start', 0, (batch['width'] or 0) - 1)
            _integer(item['end'], 'filler end', item['start'] + 1, batch['width'])
            overlays.append(dict(kind='filler', **item, confirmation='declared_not_approval'))
        provenance.update(mapping_sha256=mapping['mapping_sha256'], mapping_status=mapping['mapping_status'],
                          policy_sha256=mapping['policy_sha256'], generation_sha256=mapping['generation_sha256'])
        provenance.update(mapping_unresolved_reason_count=len(mapping['unresolved']),
            mapping_unresolved_reasons=mapping['unresolved'][:64] if not authorized_only else [],
            mapping_unresolved_reasons_redacted=authorized_only,
            mapping_unresolved_reasons_omitted=max(0, len(mapping['unresolved']) - 64) if not authorized_only else len(mapping['unresolved']))
    return batch, counts, allowed, overlays, provenance, intake


def _row(batch, ordinal, start, end, authorized_only, allowed, overlays, intake):
    record = batch['records'][ordinal]
    visible = allowed.get(ordinal, []) if authorized_only else [[start, end]]
    if authorized_only and not any(left < end and start < right for left, right in visible): return None
    raw = bytes.fromhex(record['raw_hex'])
    cells = []
    for position in range(start, end):
        exposed = not authorized_only or any(left <= position < right for left, right in visible)
        byte = raw[position] if exposed else None
        token = None if byte is None else chr(byte) if 32 <= byte <= 126 else f'\\x{byte:02x}'
        cells.append({'position': position, 'byte_start': record['byte_start'] + position,
                      'hex': None if byte is None else f'{byte:02x}', 'ascii': token, 'redacted': not exposed})
    clipped = []
    for overlay in overlays:
        for left, right in visible:
            a, b = max(start, left, overlay['start']), min(end, right, overlay['end'])
            if a < b:
                clipped.append(dict(overlay, start=a, end=b,
                                    clipped=a != overlay['start'] or b != overlay['end']))
    clipped.sort(key=lambda item: (item['kind'] != 'selected', item['kind'] != 'filler', item['start'], item['end'], item.get('candidate_id', '')))
    separators = intake.get('separators', [])
    separator = dict(separators[ordinal]) if ordinal < len(separators) else {'status': 'not_retained_in_legacy_batch'}
    if authorized_only:
        separator.pop('raw_hex', None)
        separator['status'] = 'separator_bytes_not_authorized'
    full_authority = not authorized_only or any(left == 0 and right == record['length'] for left, right in visible)
    return {'ordinal': ordinal, 'record_ref': {key: record[key] for key in REF_KEYS},
            'record_width': record['length'], 'declared_width': batch['width'],
            'record_state_disclosed': full_authority,
            'disposition': record['disposition'] if full_authority else 'redacted_outside_permitted_span',
            'reasons': list(record['reasons']) if full_authority else [],
            'window': {'start': start, 'end': end}, 'byte_positions': list(range(start, end)),
            'cells': cells, 'diagnostic_only': True, 'converted_values': 'not_provided',
            'raw_hex': raw[start:end].hex() if all(not cell['redacted'] for cell in cells) else None,
            'displayed_byte_count': end - start, 'redacted_in_window': sum(cell['redacted'] for cell in cells),
            'outside_window_byte_count': record['length'] - (end - start), 'separator': separator,
            'overlays': clipped[:MAX_OVERLAYS], 'omitted_overlay_count': max(0, len(clipped) - MAX_OVERLAYS)}


def _envelope(batch, counts, provenance, authorized_only):
    return {'schema_version': 1, 'access_mode': 'permitted_spans_only' if authorized_only else 'local_owner_retained_source',
            'diagnostic_only': True, 'source_status': batch['status'], 'source_reasons': list(batch['reasons']),
            'counts': counts, 'provenance': provenance,
            'limits': {'page_records': MAX_PAGE, 'display_bytes_per_record': MAX_DISPLAY_BYTES,
                       'overlays_per_record': MAX_OVERLAYS}, 'runtime_security': 'not_verified'}


def inspection_page(batch: dict, *, offset=0, limit=50, authorized_only=False, generation=None, mapping=None) -> dict:
    """Page by original source ordinal; authorization never renumbers records."""
    _integer(limit, 'limit', 1, MAX_PAGE)
    batch, counts, allowed, overlays, provenance, intake = _prepare(batch, authorized_only, generation, mapping)
    _integer(offset, 'offset', 0, counts['observed'])
    stop = min(offset + limit, counts['observed'])
    rows, hidden = [], 0
    for ordinal in range(offset, min(stop, counts['materialized'])):
        record = batch['records'][ordinal]
        spans = allowed.get(ordinal, [])
        start = spans[0][0] if authorized_only and spans else 0
        end = min(record['length'], start + MAX_DISPLAY_BYTES)
        row = _row(batch, ordinal, start, end, authorized_only, allowed, overlays, intake)
        if row is None: hidden += 1
        else: rows.append(row)
    value = _envelope(batch, counts, provenance, authorized_only)
    unmaterialized = max(0, stop - max(offset, counts['materialized']))
    state = 'available' if rows else 'unmaterialized' if unmaterialized else 'not_authorized' if hidden else 'empty'
    value.update(state=state, offset=offset, limit=limit, scanned_stop=stop,
                 next_offset=stop if stop < counts['observed'] else None,
                 rows=rows, returned_record_count=len(rows), not_authorized_count=hidden,
                 unmaterialized_in_page=unmaterialized)
    return dict(value, inspection_sha256=digest(value))


def inspection_detail(batch: dict, ordinal: int, *, start=0, end=None, authorized_only=False,
                      generation=None, mapping=None) -> dict:
    """Inspect a bounded record span. Unauthorized cells are masked, not expanded."""
    batch, counts, allowed, overlays, provenance, intake = _prepare(batch, authorized_only, generation, mapping)
    _integer(ordinal, 'ordinal', 0, counts['observed'] - 1)
    _integer(start, 'start', 0, 5 * 1024 * 1024)
    if end is not None: _integer(end, 'end', start, start + MAX_DISPLAY_BYTES)
    value = _envelope(batch, counts, provenance, authorized_only)
    if ordinal >= counts['materialized']:
        value.update(state='unmaterialized', ordinal=ordinal, row=None,
                     requested_span={'start': start, 'end': end}, reason='record_bytes_not_materialized')
    else:
        length = batch['records'][ordinal]['length']
        _integer(start, 'start', 0, length)
        end = min(length, start + MAX_DISPLAY_BYTES) if end is None else _integer(end, 'end', start, length)
        if end == start and length: raise ValueError('detail span must be nonempty')
        row = _row(batch, ordinal, start, end, authorized_only, allowed, overlays, intake)
        value.update(state='available' if row is not None else 'not_authorized', ordinal=ordinal, row=row)
    return dict(value, inspection_sha256=digest(value))

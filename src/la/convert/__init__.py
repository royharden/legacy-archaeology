"""Deterministic typed conversion and immutable, hash-bound migration bundles."""
from __future__ import annotations

import hashlib
import json
import re
import os
from datetime import date
from decimal import Decimal, localcontext
from pathlib import Path

from la.contracts import Approval, MappingSpec, MigrationBundle, RowOutcome, validate_batch
from la.review import REQUIRED, canonical, digest
from la.review.policy import validate_policy


class ConversionError(ValueError):
    pass


def decode_value(raw: bytes, field: dict):
    """Apply only declared ASCII policies; decimal values remain exact wire strings."""
    try:
        validate_policy(field)
    except ValueError as exc:
        raise ConversionError('invalid_declared_policy') from exc
    if len(raw) != field['end'] - field['start']:
        raise ConversionError('wrong_field_length')
    try:
        lexeme = raw.decode('ascii')
    except UnicodeDecodeError as exc:
        raise ConversionError('high_byte') from exc
    policy = field['policy']
    if '\x00' in lexeme:
        raise ConversionError('nul_byte')
    sentinels = policy.get('sentinels', {})
    if lexeme in sentinels:
        if sentinels[lexeme] != 'null' or not policy.get('nullable', False):
            raise ConversionError('invalid_sentinel_policy')
        return None
    pad = policy['padding_byte']
    side = policy['padding_side']
    if len(pad) != 1 or ord(pad) > 127 or side not in ('none', 'left', 'right'):
        raise ConversionError('invalid_padding_policy')
    value = lexeme
    if policy.get('trim', False):
        if side == 'left':
            value = value.lstrip(pad)
        elif side == 'right':
            value = value.rstrip(pad)
        else:
            raise ConversionError('invalid_padding_policy')
    if policy['trim'] and side == 'left' and value and value.endswith(pad) and pad == ' ':
        raise ConversionError('invalid_padding')
    if policy['trim'] and side == 'right' and value and value.startswith(pad) and pad == ' ':
        raise ConversionError('invalid_padding')
    data_type = field['data_type']
    if data_type == 'text':
        codes = policy.get('allowed_codes')
        if codes is not None and value not in codes:
            # Only disclosed vocabularies permit a malformed-code verdict.
            raise ConversionError('unlisted_code')
        return value
    if data_type == 'decimal':
        scale, precision = policy.get('scale'), policy.get('precision')
        if scale not in (0, 2, 3) or not isinstance(precision, int) or not max(1, scale) <= precision <= 1000:
            raise ConversionError('invalid_decimal_policy')
        mode = policy.get('sign')
        pattern = {'unsigned': r'[0-9]+', 'leading': r'[+-][0-9]+', 'trailing': r'[0-9]+[+-]'}.get(mode)
        if pattern is None or re.fullmatch(pattern, value) is None:
            raise ConversionError('invalid_sign')
        sign = -1 if (mode == 'leading' and value[0] == '-') or (mode == 'trailing' and value[-1] == '-') else 1
        digits = value[1:] if mode == 'leading' else value[:-1] if mode == 'trailing' else value
        if len(digits.lstrip('0')) > precision:
            raise ConversionError('precision_overflow')
        with localcontext() as context:
            context.prec = max(precision + scale + 4, len(digits) + scale + 4)
            number = Decimal(digits).scaleb(-scale) * sign
            if number == 0:
                number = abs(number)
            return format(number, f'.{scale}f')
    if data_type == 'date':
        fmt = policy.get('format')
        if fmt == 'YYYYMMDD' and re.fullmatch(r'[0-9]{8}', value):
            year, month, day = int(value[:4]), int(value[4:6]), int(value[6:])
        elif fmt == 'YYMMDD' and re.fullmatch(r'[0-9]{6}', value):
            window = policy.get('century_window')
            if not isinstance(window, list) or len(window) != 2 or window[1] - window[0] != 99:
                raise ConversionError('invalid_century_window')
            year = window[0] + (int(value[:2]) - window[0] % 100) % 100
            month, day = int(value[2:4]), int(value[4:])
        else:
            raise ConversionError('invalid_date_format')
        try:
            return date(year, month, day).isoformat()
        except ValueError as exc:
            raise ConversionError('invalid_calendar_date') from exc
    raise ConversionError('unsupported_type')


def validate_mapping(batch, mapping, *, require_complete=False):
    MappingSpec.model_validate(mapping)
    content = {k: v for k, v in mapping.items() if k != 'mapping_sha256'}
    if digest(content) != mapping.get('mapping_sha256'):
        raise ValueError('mapping hash mismatch')
    for key in ('source_sha256', 'framing_sha256', 'width'):
        if batch[key] != mapping[key]:
            raise ValueError(f'mapping source mismatch: {key}')
    names, covered = set(), set()
    width = mapping['width']
    if width is not None and (type(width) is not int or not 1 <= width <= 256):
        raise ValueError('invalid record width')
    if len(mapping['fields']) > 32 or len(set(mapping['supporting_event_ids'])) != len(mapping['supporting_event_ids']):
        raise ValueError('invalid field/supporting-event cardinality')
    for field in mapping['fields']:
        name = field['semantic_target']
        if name not in REQUIRED or name in names:
            raise ValueError('invalid or duplicate semantic target')
        names.add(name)
        policy = field['policy']
        try:
            validate_policy(field)
        except ValueError:
            if mapping['mapping_status'] == 'complete' or require_complete or not mapping['unresolved']:
                raise
        if digest({k: v for k, v in field.items() if k != 'id'}) != field['id']:
            raise ValueError('mapping candidate identity mismatch')
        if field['data_type'] not in ('text', 'decimal', 'date'):
            raise ValueError('unsupported field type')
        expected_type = 'decimal' if name == 'balance' else 'date' if name == 'effective_date' else 'text'
        if field['data_type'] != expected_type:
            raise ValueError('semantic target type mismatch')
        start, end = field['start'], field['end']
        if width is None or not 0 <= start < end <= width:
            raise ValueError('invalid field span')
        span = set(range(start, end))
        if span & covered:
            raise ValueError('overlapping field span')
        covered |= span
    for filler in mapping['filler']:
        start, end = filler['start'], filler['end']
        span = set(range(start, end))
        if width is None or not 0 <= start < end <= width or covered & span:
            raise ValueError('invalid filler span')
        covered |= span
    structurally_complete = width is not None and names == set(REQUIRED) and covered == set(range(width)) and not mapping['unresolved']
    structurally_complete = structurally_complete and len(mapping['supporting_event_ids']) == len(REQUIRED)
    if mapping['mapping_status'] == 'complete' and not structurally_complete:
        raise ValueError('false complete mapping')
    if require_complete and (mapping['mapping_status'] != 'complete' or not structurally_complete):
        raise ValueError('incomplete mapping cannot be approved or loaded')


def transform(batch: dict, mapping: dict) -> list[dict]:
    batch = validate_batch(batch)
    validate_mapping(batch, mapping)
    return _transform_records(batch, mapping)


def _transform_records(batch, mapping):
    """Shared deterministic value path; callers separately validate product/proposal authority."""
    from la.ingest.evidence import verify_records
    verify_records(batch)
    outcomes = []
    separator = {'LF': b'\n', 'CRLF': b'\r\n'}.get(batch['framing'], b'')
    if batch['status'] == 'accepted' and not batch.get('intake') and 'intake' not in batch['samples']:
        separator = {'LF': b'\n', 'CRLF': b'\r\n'}.get(batch['framing'])
        if separator is None:
            raise ValueError('invalid accepted framing')
        raw_rows = [bytes.fromhex(r['raw_hex']) for r in batch['records']]
        body = separator.join(raw_rows)
        valid_source = False
        for terminal in (False, True):
            data = body + (separator if terminal else b'')
            if hashlib.sha256(data).hexdigest() == batch['source_sha256'] and digest({'framing': batch['framing'], 'width': batch['width'], 'terminal_newline': terminal}) == batch['framing_sha256']:
                valid_source = True
        if not valid_source:
            raise ValueError('source reconstruction mismatch')
    offset = 0
    for ordinal, record in enumerate(batch['records']):
        if record['ordinal'] != ordinal or record['source_sha256'] != batch['source_sha256'] or record['framing_sha256'] != batch['framing_sha256']:
            raise ValueError('record identity mismatch')
        if batch['status'] == 'accepted' and record['byte_start'] != offset:
            raise ValueError('record offset mismatch')
        offset += record['length'] + (len(separator) if batch['status'] == 'accepted' else 0)
        ref = {k: record[k] for k in ('source_sha256', 'framing_sha256', 'ordinal', 'byte_start', 'length', 'raw_sha256')}
        raw = bytes.fromhex(record['raw_hex'])
        if hashlib.sha256(raw).hexdigest() != record['raw_sha256'] or len(raw) != record['length']:
            raise ValueError('record evidence hash mismatch')
        outcome = {'schema_version': 1, 'record_ref': ref, 'mapping_sha256': mapping['mapping_sha256'],
                   'outcome': 'converted', 'values': {}, 'reasons': [], 'evidence': {'raw_hex': record['raw_hex']}}
        if batch['status'] != 'accepted':
            outcome.update(outcome='unresolved', reasons=batch['reasons'] or ['batch_refused'])
        elif record['disposition'] == 'quarantined' or (mapping['width'] is not None and len(raw) != mapping['width']):
            outcome.update(outcome='quarantined', reasons=record['reasons'] or ['wrong_length'])
        elif mapping['mapping_status'] != 'complete':
            outcome.update(outcome='unresolved', reasons=mapping['unresolved'] or ['incomplete_mapping'])
        else:
            try:
                for field in mapping['fields']:
                    outcome['values'][field['semantic_target']] = decode_value(raw[field['start']:field['end']], field)
            except ConversionError as exc:
                outcome.update(outcome='quarantined', values={}, reasons=[str(exc)])
                outcome['evidence']['failure_span'] = {'start': field['start'], 'end': field['end'], 'semantic_target': field['semantic_target']}
        outcomes.append(RowOutcome.model_validate(outcome).model_dump())
    return outcomes


def approve_mapping(mapping: dict, actor: str, reason: str) -> dict:
    validate_mapping(mapping, mapping, require_complete=True)
    if not actor.strip() or not reason.strip():
        raise ValueError('explicit approver and reason required')
    approval = {'schema_version': 1, 'mapping_sha256': mapping['mapping_sha256'],
                'source_sha256': mapping['source_sha256'], 'generation_binding': mapping['generation_binding'],
                'actor': actor, 'reason': reason}
    approval['approval_sha256'] = digest(approval)
    return Approval.model_validate(approval).model_dump()


def sql_artifacts(mapping):
    if mapping['mapping_status'] != 'complete':
        return '-- INCOMPLETE: DDL unavailable until all policies are resolved.\n', '-- BLOCKED: incomplete mappings cannot load.\n', []
    names = [field['semantic_target'] for field in mapping['fields']]
    if len(names) != len(REQUIRED) or set(names) != set(REQUIRED):
        raise ValueError('SQL requires exactly the allowlisted semantic columns')
    for field in mapping['fields']:
        validate_policy(field)
    columns = ['"source_sha256" text NOT NULL', '"ordinal" bigint NOT NULL', '"raw_sha256" text NOT NULL']
    for field in sorted(mapping['fields'], key=lambda f: REQUIRED.index(f['semantic_target'])):
        name, kind, policy = field['semantic_target'], field['data_type'], field['policy']
        sql_type = 'text' if kind == 'text' else 'date' if kind == 'date' else f"numeric({int(policy['precision'])},{int(policy['scale'])})" if kind == 'decimal' else None
        if sql_type is None:
            raise ValueError('unsupported SQL type')
        column = f'"{name}" {sql_type}' + ('' if policy.get('nullable', False) else ' NOT NULL')
        codes = policy.get('allowed_codes')
        if codes is not None:
            if kind != 'text' or not codes or any(not isinstance(code, str) or '\x00' in code or not code.isascii() for code in codes):
                raise ValueError('invalid code vocabulary')
            # Only hexadecimal digits enter SQL, regardless of server string-escape settings.
            literals = ','.join("convert_from(decode('" + code.encode('ascii').hex() + "','hex'),'UTF8')" for code in sorted(set(codes)))
            column += f' CHECK ("{name}" IN ({literals}))'
        columns.append(column)
    columns.append('PRIMARY KEY ("source_sha256", "ordinal")')
    ddl = 'CREATE TABLE "migrated_records" (\n  ' + ',\n  '.join(columns) + '\n);\n'
    names = ['source_sha256', 'ordinal', 'raw_sha256'] + [f['semantic_target'] for f in sorted(mapping['fields'], key=lambda f: REQUIRED.index(f['semantic_target']))]
    sql = 'INSERT INTO "migrated_records" (' + ', '.join(f'"{n}"' for n in names) + ') VALUES (' + ', '.join(['%s'] * len(names)) + ');\n'
    return ddl, sql, names


def export_bundle(destination, batch: dict, mapping: dict, outcomes: list[dict], approval=None, *, generation=None, rulings=None, brief=None, permitted_samples=None) -> dict:
    validate_mapping(batch, mapping)
    # Re-derive outcomes, rather than trust a supplied row file with forged values or identities.
    if outcomes != transform(batch, mapping):
        raise ValueError('outcomes do not match deterministic transformation')
    if approval is not None:
        expected = approve_mapping(mapping, approval['actor'], approval['reason'])
        if approval != expected:
            raise ValueError('stale or invalid approval')
        if generation is None or rulings is None:
            raise ValueError('approved bundle requires generation and committed ruling events')
    lineage = None
    if generation is not None and rulings is not None:
        from la.review import build_mapping, validate_event
        events = rulings.events() if hasattr(rulings, 'events') else rulings
        answers = {}
        for exported in events:
            if exported['generation_binding'] != mapping['generation_binding']:
                continue
            event = validate_event({k: v for k, v in exported.items() if k != 'sequence'}, generation)
            prior = answers.get(event['question_id'])
            if event['revision'] != (prior['revision'] + 1 if prior else 1) or event['previous_event_id'] != (prior['event_id'] if prior else None) or event['old_option_id'] != (prior['option_id'] if prior else None):
                raise ValueError('bundle ruling chain mismatch')
            answers[event['question_id']] = event
        rebuilt = build_mapping(batch, generation, {'generation_binding': mapping['generation_binding'], 'answers': answers})
        if rebuilt != mapping:
            raise ValueError('mapping differs from committed ruling lineage')
        lineage = {'schema_version': 1, 'generation': generation, 'events': events}
    destination = Path(destination)
    destination.mkdir(parents=True, exist_ok=False)
    ddl, sql, columns = sql_artifacts(mapping)
    from .provenance import LOAD_INSTRUCTIONS
    files = {'mapping.json': canonical(mapping) + '\n', 'source.json': canonical(batch) + '\n',
             'schema.sql': ddl, 'migrate.sql': sql,
             'rows.jsonl': ''.join(canonical(o) + '\n' for o in outcomes if o['outcome'] == 'converted'),
             'unresolved.jsonl': ''.join(canonical(o) + '\n' for o in outcomes if o['outcome'] == 'unresolved'),
             'quarantine.jsonl': ''.join(canonical(o) + '\n' for o in outcomes if o['outcome'] == 'quarantined'),
             'approval.json': canonical(approval) + '\n',
             'rulings.json': canonical(lineage) + '\n',
             'inputs.json': canonical({'schema_version': 1, 'brief': brief, 'permitted_samples': permitted_samples}) + '\n',
             'LOAD.md': LOAD_INSTRUCTIONS}
    hashes = {}
    for name, content in files.items():
        data = content.encode('utf-8')
        with (destination / name).open('xb') as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        hashes[name] = hashlib.sha256(data).hexdigest()
    counts = {kind: sum(o['outcome'] == kind for o in outcomes) for kind in ('converted', 'unresolved', 'quarantined')}
    manifest = {'schema_version': 1, 'source_sha256': batch['source_sha256'], 'mapping_sha256': mapping['mapping_sha256'],
                'generation_binding': mapping['generation_binding'], 'approval_sha256': approval['approval_sha256'] if approval else None,
                'files': hashes, 'columns': columns, 'counts': counts, 'record_count': len(outcomes),
                'mapping_status': mapping['mapping_status'], 'transformation_status': 'complete' if batch['status'] == 'accepted' and mapping['mapping_status'] == 'complete' and counts['converted'] == len(outcomes) and outcomes else 'partial',
                'target_validation': 'not_run', 'row_parity': 'not_run'}
    manifest['config_sha256'] = batch['config_sha256']
    manifest['supporting_event_ids'] = mapping['supporting_event_ids']
    from .provenance import producer_code_pin
    manifest['producer_code_sha256'] = producer_code_pin()
    manifest['bundle_sha256'] = digest(manifest)
    manifest = MigrationBundle.model_validate(manifest).model_dump()
    with (destination / 'manifest.json').open('x', encoding='utf-8', newline='\n') as stream:
        stream.write(canonical(manifest) + '\n')
        stream.flush()
        os.fsync(stream.fileno())
    return manifest


from .proposal import validate_proposal, transform_proposal
from .bundle import verify_bundle, write_verification_receipt

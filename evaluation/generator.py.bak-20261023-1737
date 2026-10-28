"""Canonical-first DEVELOPMENT fixture construction; no candidate code imports.

This module is source only in Dirty Mode. It does not create hidden editions.
"""
from __future__ import annotations
from datetime import date
from decimal import Decimal
import hashlib
import json
import random

SEMANTICS = ('account_ref', 'description', 'balance', 'effective_date', 'status')


def canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False, allow_nan=False).encode('utf-8')


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def canonical_records(seed: int, count: int = 100) -> list[dict]:
    """Choose semantic values before any byte layout; deterministic dev source."""
    rng = random.Random(seed)
    return [{'account_ref': f'{i:06d}', 'description': f'Account {i}',
             'balance': f'{Decimal(rng.randrange(-999999, 1000000)) / 100:.2f}',
             'effective_date': None if i % 11 == 0 else date(2024, 2, 29).isoformat(),
             'status': ('A', 'C')[i % 2]} for i in range(count)]


def serialize(records: list[dict], layout: dict) -> bytes:
    """Independent encoder; explicit layout gives order, width and policies."""
    encoded = []
    for record in records:
        chunks = []
        for field in layout['fields']:
            value = record[field['semantic_target']]
            kind, policy, width = field['data_type'], field['policy'], field['end'] - field['start']
            if value is None:
                lexemes = [key for key, meaning in policy.get('sentinels', {}).items() if meaning == 'null']
                if len(lexemes) != 1:
                    raise ValueError('serializer requires exactly one declared null sentinel')
                token = lexemes[0]
            elif kind == 'decimal':
                amount = Decimal(value)
                scale = policy['scale']
                scaled = amount * (10 ** scale)
                if scaled != scaled.to_integral_value():
                    raise ValueError('unrepresentable canonical scale')
                if len(str(abs(int(scaled)))) > policy['precision']:
                    raise ValueError('canonical magnitude exceeds declared precision')
                digits = str(abs(int(scaled))).zfill(width - 1)
                token = ('-' if amount.is_signed() else '+') + digits
                if policy['sign'] == 'trailing':
                    token = digits + token[0]
            elif kind == 'date':
                day = date.fromisoformat(value)
                token = day.strftime('%Y%m%d' if policy['format'] == 'YYYYMMDD' else '%y%m%d')
            else:
                token = value
            raw = token.encode('ascii')
            if len(raw) > width:
                raise ValueError('canonical field exceeds layout')
            padding = policy.get('padding_byte', ' ').encode('ascii')
            if len(padding) != 1:
                raise ValueError('padding must be one ASCII byte')
            if policy.get('padding_side', 'right') == 'left':
                raw = padding * (width - len(raw)) + raw
            else:
                raw += padding * (width - len(raw))
            if sum(map(len, chunks)) != field['start']:
                raise ValueError('layout must explicitly cover bytes in wire order')
            chunks.append(raw)
        encoded.append(b''.join(chunks))
    separator = {'LF': b'\n', 'CRLF': b'\r\n'}[layout['framing']]
    return separator.join(encoded) + (separator if layout['terminal_newline'] and encoded else b'')


def attach_refs(data: bytes, canonical_rows: list[dict], layout: dict) -> list[dict]:
    """Attach declared framing identities; does not infer layout or decode values."""
    separator = {'LF': b'\n', 'CRLF': b'\r\n'}[layout['framing']]
    pieces = data.split(separator)
    if layout['terminal_newline']:
        if pieces[-1] != b'':
            raise ValueError('declared terminal separator missing')
        pieces.pop()
    if len(pieces) != len(canonical_rows):
        raise ValueError('canonical/source cardinality mismatch')
    framing = sha(canonical({'framing': layout['framing'], 'width': layout['width'],
                              'terminal_newline': layout['terminal_newline']}))
    source = sha(data)
    result, cursor = [], 0
    for ordinal, (raw, values) in enumerate(zip(pieces, canonical_rows, strict=True)):
        ref = dict(source_sha256=source, framing_sha256=framing, ordinal=ordinal,
                   byte_start=cursor, length=len(raw), raw_sha256=sha(raw))
        result.append({'record_ref': ref, 'expected_outcome': 'converted', 'reasons': [],
                       'fields': {name: {'data_type': 'decimal' if name == 'balance' else
                           'date' if name == 'effective_date' else 'text', 'value': values[name]} for name in SEMANTICS}})
        cursor += len(raw) + len(separator)
    return result


def inject_malformed(data: bytes, layout: dict, mutations: list[dict]) -> tuple[bytes, list[dict]]:
    """Apply declared byte replacements after serialization; preserves canonical linkage.

    Caller must rebuild RecordRefs and retain each mutation's canonical_ordinal and
    expected reasons. No random malformed selection or hidden asset generation.
    """
    sep = {'LF': b'\n', 'CRLF': b'\r\n'}[layout['framing']]
    pieces = data.split(sep)
    seen = set()
    for mutation in mutations:
        ordinal = mutation['canonical_ordinal']
        if ordinal in seen or ordinal < 0 or ordinal >= len(pieces) - int(layout['terminal_newline']):
            raise ValueError('invalid or duplicate mutation ordinal')
        seen.add(ordinal)
        pieces[ordinal] = bytes.fromhex(mutation['replacement_hex'])
    return sep.join(pieces), [dict(mutation) for mutation in mutations]

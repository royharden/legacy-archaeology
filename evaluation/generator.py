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


def canonical_records(seed: int, count: int = 100, *, scale: int = 2,
                      precision: int = 8, unsigned: bool = False) -> list[dict]:
    """Choose semantic values before any byte layout; deterministic dev source."""
    if type(count) is not int or not 1 <= count <= 10000 or scale not in (0, 2, 3):
        raise ValueError('bounded record count and declared scale required')
    if type(precision) is not int or not scale <= precision <= 18:
        raise ValueError('precision outside public generator scope')
    rng = random.Random(seed)
    bound = min(10 ** precision - 1, 999999)
    records = [{'account_ref': f'{i:06d}', 'description': '' if i % 13 == 0 else f'Account {i}',
             'balance': f'{Decimal(rng.randrange(0 if unsigned else -bound, bound + 1)).scaleb(-scale):.{scale}f}',
             'effective_date': None if i % 11 == 0 else date(2024, 2, 29).isoformat(),
             'status': ('A', 'C')[i % 2]} for i in range(count)]
    if count > 7:
        records[7] = dict(records[6])  # Business duplicate; distinct ordinal identity.
    records[0]['balance'] = f'{Decimal(0):.{scale}f}'
    if count > 1 and not unsigned:
        records[1]['balance'] = f'{Decimal("-0"):.{scale}f}'
    return records


def serialize(records: list[dict], layout: dict) -> bytes:
    """Independent encoder; explicit layout gives order, width and policies."""
    encoded = []
    fields = layout['fields']
    if {field['semantic_target'] for field in fields if field['data_type'] != 'filler'} != set(SEMANTICS):
        raise ValueError('exact five semantic targets required')
    if len({field['semantic_target'] for field in fields}) != len(fields):
        raise ValueError('duplicate layout target')
    if not fields or fields[-1]['end'] != layout['width']:
        raise ValueError('layout must cover declared width')
    for record in records:
        chunks = []
        for field in fields:
            kind, policy, width = field['data_type'], field['policy'], field['end'] - field['start']
            value = policy.get('lexeme') if kind == 'filler' else record[field['semantic_target']]
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
                sign = policy['sign']
                if sign not in ('leading', 'trailing', 'unsigned'):
                    raise ValueError('unknown declared sign')
                if sign == 'unsigned' and amount < 0:
                    raise ValueError('negative unsigned canonical value')
                digit_width = width - int(sign != 'unsigned')
                digits = str(abs(int(scaled))).zfill(digit_width)
                marker = '-' if amount.is_signed() else '+'
                token = digits if sign == 'unsigned' else marker + digits if sign == 'leading' else digits + marker
            elif kind == 'date':
                day = date.fromisoformat(value)
                if policy['format'] not in ('YYYYMMDD', 'YYMMDD'):
                    raise ValueError('unsupported date representation')
                if policy['format'] == 'YYMMDD':
                    window = policy.get('century_window')
                    if not isinstance(window, list) or len(window) != 2 or window[1] - window[0] != 99:
                        raise ValueError('explicit 100-year century window required')
                    if not window[0] <= day.year <= window[1]:
                        raise ValueError('canonical date outside century window')
                token = day.strftime('%Y%m%d' if policy['format'] == 'YYYYMMDD' else '%y%m%d')
            else:
                token = value
            raw = token.encode('ascii')
            if len(raw) > width:
                raise ValueError('canonical field exceeds layout')
            padding = policy.get('padding_byte', ' ').encode('ascii')
            if len(padding) != 1:
                raise ValueError('padding must be one ASCII byte')
            side = policy.get('padding_side', 'none')
            if side == 'none' and len(raw) != width:
                raise ValueError('undeclared padding needed')
            if side not in ('left', 'right', 'none'):
                raise ValueError('unknown padding side')
            if side == 'left':
                raw = padding * (width - len(raw)) + raw
            elif side == 'right':
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
    descriptor = {'framing': layout['framing'], 'width': layout['width'],
                  'terminal_newline': layout['terminal_newline']}
    if layout.get('framing_version', 1) == 2:
        # Independent construction of the documented IDENTITY.md wire descriptor.
        # Canonical layout promises the unique modal width; malformed strata are
        # below five percent and cannot replace that width.
        descriptor.update(version=2, width_candidates=[layout['width']])
    elif layout.get('framing_version', 1) != 1:
        raise ValueError('unknown framing identity version')
    framing = sha(canonical(descriptor))
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

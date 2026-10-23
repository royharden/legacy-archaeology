"""Contained, durable local artifact operations; never start a service."""
from __future__ import annotations

import re
from pathlib import Path

from la.contracts import canonical, digest, sha256, validate_batch
from .storage import (contained, bounded_json, bounded_bytes, publish_bytes, replace_pointer,
                      pointer_token, UNSET, SOURCE_BYTES, JSON_BYTES)


def within(root: Path, value, *, exists=False) -> Path:
    return contained(root, value, exists=exists)


def read(path, *, limit=JSON_BYTES, canonical_required=False):
    return bounded_json(path, limit=limit, canonical_required=canonical_required)


def immutable(path, value):
    publish_bytes(path, canonical(value)+b'\n', limit=JSON_BYTES)


def pointer(path, value, *, expected=UNSET):
    """Only small current pointers mutate; all referred content remains immutable."""
    replace_pointer(path, value, expected=expected)


def identity(value):
    if type(value) is not str or re.fullmatch('[0-9a-f]{64}', value) is None:
        raise ValueError('expected canonical SHA256 identity')
    return value


def load_run(root, run_id):
    run = within(root, identity(run_id), exists=True)
    batch = validate_batch(read(within(run, 'batch.json', exists=True), canonical_required=True))
    data = bounded_bytes(within(run, 'source.dat', exists=True), limit=SOURCE_BYTES)
    brief = bounded_bytes(within(run, 'brief.md', exists=True), limit=16000).decode('utf-8')
    samples = read(within(run, 'samples.json', exists=True))
    if sha256(data) != batch['source_sha256'] or sha256(brief.encode()) != batch['brief_sha256']:
        raise ValueError('retained source/brief identity changed; ingest a new run')
    if digest(samples) != batch['samples']['artifact_sha256']:
        raise ValueError('permitted sample artifact changed; ingest a new run')
    expected = digest(dict(source=batch['source_sha256'], brief=batch['brief_sha256'],
                           samples=batch['samples']['artifact_sha256'], config=batch['config_sha256']))
    if run_id != expected:
        raise ValueError('run identity mismatch')
    from la.ingest.evidence import verify_records
    verify_records(batch, data)
    manifest_path = within(run, 'run.json', exists=True)
    manifest = read(manifest_path, canonical_required=True)
    expected_manifest = dict(schema_version=1, run=run_id, batch_sha256=digest(batch),
                             source_sha256=batch['source_sha256'], brief_sha256=batch['brief_sha256'],
                             samples_sha256=digest(samples), config_sha256=batch['config_sha256'])
    if manifest != expected_manifest:
        raise ValueError('run manifest changed or interrupted intake; preserve bytes and ingest a fresh store')
    return run, batch, brief


def receipt(root, kind, payload):
    envelope = dict(schema_version=1, kind=kind, payload=payload)
    envelope['receipt_sha256'] = digest(envelope)
    path = within(root, kind + '/' + envelope['receipt_sha256'] + '.json')
    immutable(path, envelope)
    return dict(path=str(path), **envelope)


def checked_receipt(root, name, *, kind=None):
    value = read(within(root, name, exists=True), canonical_required=True)
    if set(value) != {'schema_version', 'kind', 'payload', 'receipt_sha256'} or value['schema_version'] != 1:
        raise ValueError('invalid immutable receipt envelope')
    if digest({k:v for k,v in value.items() if k != 'receipt_sha256'}) != value['receipt_sha256']:
        raise ValueError('receipt hash mismatch')
    if kind is not None and value['kind'] != kind:
        raise ValueError('receipt kind mismatch')
    return value

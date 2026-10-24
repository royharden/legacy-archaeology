"""Portable evaluator archives SOURCE. No import-time I/O or execution.

Explicit signed inventory releases authorize public/retired data only. ZIP is
read without extraction. Archived Python/prompts are inert bytes. CaptureStore
and the existing registry fold remain the only artifact/state primitives.
"""
from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import io
import json
from pathlib import Path, PurePosixPath
import re
import stat
import struct
import zipfile

from .artifacts import CaptureStore, canonical, digest, is_sha
from .edition_registry import EditionRegistry
from .eligibility import ReceiptVerifier, closed, text, variant_identity

MAX_MEMBERS = 512
MAX_MEMBER = 32 * 1024 * 1024
MAX_TOTAL = 256 * 1024 * 1024
MAX_MANIFEST = 512 * 1024
MAX_RELEASE = 64 * 1024
SCORER_VERSION = 'semantic-v1'
CODE_NAMES = ('archive.py', 'artifacts.py', 'runner.py', 'scorer.py')
CAPTURE_KINDS = frozenset({
    'variant_manifest', 'arm_receipt', 'arm_raw', 'provider_request', 'provider_reply',
    'generation', 'mapping_proposal', 'batch_output', 'batch_failure',
    'target_observation_v2', 'target_observation_v3', 'failed_load_observation',
    'unknown_commit_observation', 'recovery_observation', 'target_arm_receipt', 'target_arm_failure',
    'suite_declaration', 'suite_report', 'suite_failure', 'signed_evidence',
    'billing_observation', 'archive_input', 'archive_configuration', 'replay_receipt',
    'edition_event', 'retirement', 'target_cleanup_observation'})
MANIFEST_KEYS = {'schema_version', 'kind', 'edition', 'visibility', 'registry_head_sha256',
                 'history', 'roots', 'inputs', 'configuration', 'provenance', 'scorer',
                 'members', 'archive_sha256'}
RELEASE_KEYS = {'schema_version', 'action', 'edition', 'visibility', 'archive_sha256',
                'registry_head_sha256', 'allowed_kinds', 'not_after_utc', 'nonce', 'authority_sha256'}


def _sha(data):
    return hashlib.sha256(data).hexdigest()


def _json(data, limit):
    if not isinstance(data, bytes) or len(data) > limit:
        raise ValueError('bounded canonical JSON bytes required')
    def unique(items):
        value = {}
        for key, item in items:
            if key in value: raise ValueError('duplicate JSON key')
            value[key] = item
        return value
    value = json.loads(data, object_pairs_hook=unique)
    if canonical(value) != data: raise ValueError('noncanonical archive JSON')
    return value


def _path(name):
    if (not isinstance(name, str) or len(name) > 200 or '\\' in name or ':' in name
            or name.startswith('/') or str(PurePosixPath(name)) != name
            or any(not part or part in ('.', '..') or re.fullmatch('[A-Za-z0-9_.-]+', part) is None
                   for part in name.split('/'))):
        raise ValueError('noncanonical/traversing archive member')
    return name


def _no_links(path):
    # Includes Windows junction/reparse points as well as POSIX symlinks.
    for item in (path, *path.parents):
        if item.exists() or item.is_symlink():
            info = item.lstat()
            if stat.S_ISLNK(info.st_mode) or getattr(info, 'st_file_attributes', 0) & 0x400:
                raise ValueError('links/reparse points are not archive roots/members')


def _reference(ref):
    closed(ref, {'sha256', 'kind', 'bytes'}, 'capture reference')
    if (not is_sha(ref['sha256']) or ref['kind'] not in CAPTURE_KINDS or
            type(ref['bytes']) is not int or not 0 < ref['bytes'] <= MAX_MEMBER):
        raise ValueError('unsupported/unbounded capture class')
    return ref


def _references(value):
    """All actual typed references, including failed and partial attempt edges."""
    if isinstance(value, dict):
        if {'sha256', 'kind', 'bytes'} <= set(value):
            yield _reference(value)
        else:
            for child in value.values(): yield from _references(child)
    elif isinstance(value, list):
        for child in value: yield from _references(child)


def _no_secrets(value, depth=0):
    if depth > 64: raise ValueError('archive payload nesting limit')
    forbidden = {'api_key', 'access_token', 'refresh_token', 'password', 'secret', 'private_key',
                 'credentials', 'credential', 'dsn', 'authorization_header', 'cookie', 'set_cookie'}
    if isinstance(value, dict):
        for key, child in value.items():
            normalized = key.lower().replace('-', '_')
            if normalized in forbidden or normalized.endswith(('_password', '_api_key', '_access_token', '_private_key')):
                raise ValueError('secret/unapproved payload class')
            _no_secrets(child, depth + 1)
    elif isinstance(value, list):
        for child in value: _no_secrets(child, depth + 1)


def _capture(data, reference):
    _reference(reference)
    if len(data) != reference['bytes'] or _sha(data) != reference['sha256']:
        raise ValueError('capture byte identity mismatch')
    value = _json(data, MAX_MEMBER)
    closed(value, {'schema_version', 'kind', 'payload'}, 'capture envelope')
    if type(value['schema_version']) is not int or value['schema_version'] != 1 or value['kind'] != reference['kind']:
        raise ValueError('capture envelope version/kind mismatch')
    _no_secrets(value['payload'])
    return value['payload']


def _put_memory(members, kind, payload):
    data = canonical({'schema_version': 1, 'kind': kind, 'payload': payload})
    ref = {'sha256': _sha(data), 'kind': kind, 'bytes': len(data)}
    _capture(data, ref)
    members['captures/' + ref['sha256'] + '.json'] = data
    return ref


def _history_scope(history, edition, visibility, inputs):
    state = EditionRegistry.snapshot_state(history, edition=edition)
    if state['attempt'] is not None and state['attempt']['status'] == 'running':
        raise ValueError('finish/cancel the exact attempt before archive release')
    if state['t1'] is not None and any(a['status'] == 'running' for a in state['t1']['attempts'].values()):
        raise ValueError('running public attempt cannot be archived as terminal history')
    if visibility not in ('public', 'retired'):
        raise ValueError('active hidden raw archive export forbidden')
    if visibility == 'retired' and not state['retired']:
        raise ValueError('retired archive requires actual irreversible registry disposition')
    if any(item['split'] == 'heldout' for item in inputs) and (visibility != 'retired' or not state['retired']):
        raise ValueError('active/unreleased hidden input cannot enter a portable raw archive')
    if state['retired'] and visibility != 'retired':
        raise ValueError('retired data cannot regain public/fresh edition labeling')
    for item in inputs:
        declared = (state['commitment']['variants'] if state['commitment'] is not None
                    else state['t1']['catalog']['variants'] if state['t1'] is not None else [])
        if declared and item['identity'] not in declared:
            raise ValueError('archive input differs from original registered source/corpus')
    return state


@dataclass(frozen=True)
class ArchivePlan:
    manifest_bytes: bytes
    member_bytes: tuple[tuple[str, bytes], ...]

    @property
    def manifest(self):
        return _json(self.manifest_bytes, MAX_MANIFEST)

    @property
    def release_payload(self):
        m = self.manifest
        # An unsigned template only. Caller supplies nonce/expiry, self-hash and
        # actual owner signature outside this module, under later authorization.
        return {'schema_version': 1, 'action': 'release_evaluation_archive',
                'edition': m['edition'], 'visibility': m['visibility'], 'archive_sha256': m['archive_sha256'],
                'registry_head_sha256': m['registry_head_sha256'],
                'allowed_kinds': sorted({row['kind'] for row in m['members']}),
                'not_after_utc': None, 'nonce': None, 'authority_sha256': None}


@dataclass(frozen=True)
class ArchiveSnapshot:
    manifest_bytes: bytes
    release_bytes: bytes
    member_bytes: tuple[tuple[str, bytes], ...]

    @property
    def manifest(self):
        return _json(self.manifest_bytes, MAX_MANIFEST)

    def get(self, reference, *, kind=None):
        _reference(reference)
        if kind is not None and kind != reference['kind']: raise ValueError('wrong capture kind')
        data = dict(self.member_bytes).get('captures/' + reference['sha256'] + '.json')
        if data is None: raise ValueError('missing archived capture')
        return _capture(data, reference)


def plan_archive(store, *, cases, manifest_refs, configuration, registry, visibility):
    """Construct a bounded in-memory release inventory; no archive/journal write."""
    if type(store) is not CaptureStore or type(registry) is not EditionRegistry or registry.store.root != store.root:
        raise ValueError('existing same evaluator capture store and registry required')
    _no_links(store.root); _no_links(registry.path)
    if not isinstance(cases, list) or not 1 <= len(cases) <= 18 or len(cases) != len(manifest_refs):
        raise ValueError('bounded exact cases/manifests required')
    edition = cases[0].edition
    if len({c.variant_id for c in cases}) != len(cases) or any(c.edition != edition for c in cases):
        raise ValueError('archive must preserve one exact edition with unique variants')
    inputs = [{'schema_version': 1, 'edition': c.edition, 'variant_id': c.variant_id, 'split': c.split,
               'visible': deepcopy(c.visible), 'batches': [dict(batch_id=b.batch_id, visible=deepcopy(b.visible), oracle=deepcopy(b.oracle)) for b in c.batches],
               'accepted_choices': deepcopy(c.accepted_choices), 'expected_layout': deepcopy(c.expected_layout),
               'identity': variant_identity(c)} for c in cases]
    events = registry.events()
    head = events[-1]['event_sha256'] if events else None
    history = [event for event in events if event['edition'] == edition]
    state = _history_scope(history, edition, visibility, inputs)
    configuration = closed(configuration, {'schema_version', 'edition', 'pins', 'values'}, 'archive configuration')
    if type(configuration['schema_version']) is not int or configuration['schema_version'] != 1 or configuration['edition'] != edition:
        raise ValueError('wrong archive configuration edition/version')
    _no_secrets(configuration)
    manifests = [store.get(_reference(ref), kind='variant_manifest') for ref in manifest_refs]
    for case, manifest, item in zip(cases, manifests, inputs):
        if (manifest['edition'] != edition or manifest['variant_id'] != case.variant_id or manifest['split'] != case.split
                or manifest['input_sha256'] != digest(case.visible) or manifest['oracle_commitment_sha256'] != digest([r for b in case.batches for r in b.oracle])
                or manifest['pins'] != configuration['pins']):
            raise ValueError('archive actual inputs/configuration differ from original manifests')
    members = {}
    input_refs = [_put_memory(members, 'archive_input', item) for item in inputs]
    config_ref = _put_memory(members, 'archive_configuration', configuration)
    pending = list(manifest_refs) + list(_references(history))
    seen = {}
    while pending:
        ref = _reference(pending.pop())
        if ref['sha256'] in seen:
            if seen[ref['sha256']] != ref: raise ValueError('conflicting capture identity')
            continue
        if len(members) >= MAX_MEMBERS: raise ValueError('archive member limit')
        path = store.root / (ref['sha256'] + '.json'); _no_links(path)
        if not path.is_file() or path.stat().st_size != ref['bytes']: raise ValueError('missing/unbounded capture')
        data = path.read_bytes(); payload = _capture(data, ref)
        members['captures/' + ref['sha256'] + '.json'] = data
        if sum(map(len, members.values())) > MAX_TOTAL: raise ValueError('archive total limit')
        seen[ref['sha256']] = deepcopy(ref)
        pending.extend(_references(payload))
    for name in CODE_NAMES:
        path = Path(__file__).with_name(name); _no_links(path)
        if path.stat().st_size > MAX_MEMBER: raise ValueError('scorer code limit')
        members['code/' + name] = path.read_bytes()
    manifest = {'schema_version': 1, 'kind': 'evaluation_archive', 'edition': edition, 'visibility': visibility,
        'registry_head_sha256': head, 'history': history, 'roots': deepcopy(manifest_refs), 'inputs': input_refs,
        'configuration': config_ref,
        'provenance': {'corpus_sha256': state['commitment']['commitment_sha256'] if state['commitment'] is not None else
                       state['t1']['catalog']['catalog_sha256'] if state['t1'] is not None else digest([i['identity'] for i in inputs]),
                       'freeze_sha256': None if state['freeze'] is None else state['freeze']['freeze_sha256'],
                       'modes': sorted({m['mode'] for m in manifests})},
        'scorer': {'schema_version': 1, 'version': SCORER_VERSION, 'code_sha256': _sha(members['code/scorer.py'])},
        'members': [{'path': name, 'kind': 'evaluator_code' if name.startswith('code/') else _json(data, MAX_MEMBER)['kind'],
                     'sha256': _sha(data), 'bytes': len(data)} for name, data in sorted(members.items())]}
    manifest['archive_sha256'] = digest(manifest)
    plan = ArchivePlan(canonical(manifest), tuple(sorted(members.items())))
    _validate_members(plan.manifest_bytes, plan.member_bytes)
    return plan


def _validate_members(manifest_bytes, member_bytes):
    m = closed(_json(manifest_bytes, MAX_MANIFEST), MANIFEST_KEYS, 'archive manifest')
    if type(m['schema_version']) is not int or m['schema_version'] != 1 or m['kind'] != 'evaluation_archive':
        raise ValueError('unsupported archive schema')
    text(m['edition'], 'edition')
    if not is_sha(m['archive_sha256']) or m['archive_sha256'] != digest({k: v for k, v in m.items() if k != 'archive_sha256'}):
        raise ValueError('archive manifest hash mismatch')
    if m['registry_head_sha256'] is not None and not is_sha(m['registry_head_sha256']): raise ValueError('invalid registry head')
    if not isinstance(m['members'], list) or not 1 <= len(m['members']) <= MAX_MEMBERS:
        raise ValueError('bounded archive inventory required')
    if len(member_bytes) != len(m['members']): raise ValueError('duplicate/unlisted archive member')
    data = dict(member_bytes)
    if len(data) != len(member_bytes): raise ValueError('duplicate archive member')
    listed = set(); total = 0
    for row in m['members']:
        closed(row, {'path', 'kind', 'sha256', 'bytes'}, 'archive member')
        name = _path(row['path'])
        if name in listed or name not in data: raise ValueError('duplicate/missing archive member')
        listed.add(name)
        raw = data[name]
        if type(row['bytes']) is not int or not 0 < row['bytes'] <= MAX_MEMBER or len(raw) != row['bytes'] or _sha(raw) != row['sha256']:
            raise ValueError('member byte/hash/size mismatch')
        total += len(raw)
        if row['kind'] == 'evaluator_code':
            if name not in {'code/' + n for n in CODE_NAMES}: raise ValueError('unapproved executable/code member class')
        else:
            if name != 'captures/' + row['sha256'] + '.json': raise ValueError('capture filename differs from identity')
            _capture(raw, {k: row[k] for k in ('sha256', 'kind', 'bytes')})
    if set(data) != listed or total > MAX_TOTAL: raise ValueError('unlisted/oversize archive data')
    if not {'code/' + n for n in CODE_NAMES} <= listed: raise ValueError('missing original evaluator code identities')
    scorer = closed(m['scorer'], {'schema_version', 'version', 'code_sha256'}, 'original scorer')
    if type(scorer['schema_version']) is not int or scorer['schema_version'] != 1 or scorer['code_sha256'] != _sha(data['code/scorer.py']):
        raise ValueError('invalid original scorer pin/schema')
    view = ArchiveSnapshot(manifest_bytes, b'', tuple(member_bytes))
    if not isinstance(m['roots'], list) or not 1 <= len(m['roots']) <= 18 or len(m['roots']) != len(m['inputs']):
        raise ValueError('bounded complete manifest/input pairs required')
    inputs = [view.get(ref, kind='archive_input') for ref in m['inputs']]
    state = _history_scope(m['history'], m['edition'], m['visibility'], inputs)
    config = view.get(m['configuration'], kind='archive_configuration')
    closed(config, {'schema_version', 'edition', 'pins', 'values'}, 'archived configuration')
    if config['edition'] != m['edition']: raise ValueError('wrong configuration edition')
    required_refs = list(m['roots']) + list(m['inputs']) + [m['configuration']] + list(_references(m['history']))
    visited = set()
    while required_refs:
        ref = _reference(required_refs.pop())
        if ref['sha256'] in visited: continue
        visited.add(ref['sha256']); payload = view.get(ref)
        required_refs.extend(_references(payload))
    actual_captures = {row['sha256'] for row in m['members'] if row['kind'] != 'evaluator_code'}
    if visited != actual_captures: raise ValueError('unreachable/unapproved extra capture member')
    variants = set(); modes = set()
    from .runner import BatchCase, VariantCase
    for ref, item in zip(m['roots'], inputs):
        closed(item, {'schema_version', 'edition', 'variant_id', 'split', 'visible', 'batches',
                      'accepted_choices', 'expected_layout', 'identity'}, 'archive replay input')
        if type(item['schema_version']) is not int or item['schema_version'] != 1 or item['edition'] != m['edition']:
            raise ValueError('wrong input edition/schema')
        if not isinstance(item['batches'], list) or not 1 <= len(item['batches']) <= 10: raise ValueError('bounded original batches required')
        for b in item['batches']: closed(b, {'batch_id', 'visible', 'oracle'}, 'archive batch')
        case = VariantCase(item['variant_id'], item['split'], item['edition'], item['visible'],
                           tuple(BatchCase(**b) for b in item['batches']), item['accepted_choices'], item['expected_layout'])
        if variant_identity(case) != item['identity']: raise ValueError('source/sample/oracle/layout identity changed')
        original = view.get(ref, kind='variant_manifest')
        if (original['edition'] != m['edition'] or original['variant_id'] != item['variant_id'] or original['split'] != item['split']
                or original['input_sha256'] != digest(item['visible']) or original['pins'] != config['pins']
                or original['oracle_commitment_sha256'] != digest([r for b in item['batches'] for r in b['oracle']])
                or item['variant_id'] in variants):
            raise ValueError('manifest/input/config/edition mismatch')
        if original['mode'] not in ('rules', 'mock', 'live'): raise ValueError('unknown original execution mode')
        if len(original['results']) != 5 or {r['method'] for r in original['results']} != {'B0', 'B1', 'C0', 'R0', 'R1'}:
            raise ValueError('all original failed/partial arms must remain')
        for arm in original['results']:
            if view.get(arm['receipt_capture'], kind='arm_receipt') != {k: v for k, v in arm.items() if k != 'receipt_capture'}:
                raise ValueError('original arm receipt changed')
        variants.add(item['variant_id']); modes.add(original['mode'])
    corpus = (state['commitment']['commitment_sha256'] if state['commitment'] is not None else
              state['t1']['catalog']['catalog_sha256'] if state['t1'] is not None else digest([i['identity'] for i in inputs]))
    if m['provenance'] != {'corpus_sha256': corpus, 'freeze_sha256': None if state['freeze'] is None else state['freeze']['freeze_sha256'], 'modes': sorted(modes)}:
        raise ValueError('archive corpus/freeze/mode provenance mismatch')
    return m


def _signed(value, verifier, keys, action, *, check_time):
    if type(verifier) is not ReceiptVerifier: raise ValueError('concrete run_owner signature verifier required')
    body = closed(verifier.verify(value, 'run_owner'), keys, 'archive release authority')
    if type(body['schema_version']) is not int or body['schema_version'] != 1 or body['action'] != action:
        raise ValueError('wrong archive release action/schema')
    if not is_sha(body['nonce']) or body['authority_sha256'] != digest({k: v for k, v in body.items() if k != 'authority_sha256'}):
        raise ValueError('archive release nonce/self-pin mismatch')
    try: expiry = datetime.fromisoformat(body['not_after_utc'].replace('Z', '+00:00'))
    except (ValueError, AttributeError, TypeError): raise ValueError('zoned archive release expiry required') from None
    if expiry.tzinfo is None or (check_time and expiry <= datetime.now(timezone.utc)):
        raise ValueError('expired/unzoned archive release')
    return body


def _release(m, signed, verifier, *, check_time):
    body = _signed(signed, verifier, RELEASE_KEYS, 'release_evaluation_archive', check_time=check_time)
    for key in ('edition', 'visibility', 'archive_sha256', 'registry_head_sha256'):
        if body[key] != m[key]: raise ValueError('signed release differs from exact archive inventory')
    if body['allowed_kinds'] != sorted({row['kind'] for row in m['members']}):
        raise ValueError('archive payload classes not exactly owner approved')
    return body


def export_archive(plan, destination, *, signed_release, verifier):
    if type(plan) is not ArchivePlan: raise ValueError('concrete archive plan required')
    m = _validate_members(plan.manifest_bytes, plan.member_bytes)
    _release(m, signed_release, verifier, check_time=True)
    release = canonical(signed_release)
    if len(release) > MAX_RELEASE: raise ValueError('release envelope limit')
    destination = Path(destination); _no_links(destination)
    if not destination.parent.is_dir(): raise ValueError('existing explicit owned destination parent required')
    # Exclusive create; an interrupted packet stays incomplete and cannot verify.
    with destination.open('xb') as handle:
        with zipfile.ZipFile(handle, 'w', compression=zipfile.ZIP_STORED, allowZip64=False) as packet:
            for name, raw in (('manifest.json', plan.manifest_bytes), ('release.json', release), *plan.member_bytes):
                info = zipfile.ZipInfo(name); info.create_system = 3; info.external_attr = (stat.S_IFREG | 0o600) << 16
                packet.writestr(info, raw)
        handle.flush()
        import os
        os.fsync(handle.fileno())
    return {'schema_version': 1, 'archive_sha256': m['archive_sha256'], 'edition': m['edition'],
            'visibility': m['visibility'], 'release_sha256': digest(signed_release),
            'stochastic_model_rerun': False, 'fresh_holdout': False}


def read_archive(path, *, expected_archive_sha256, verifier):
    if not is_sha(expected_archive_sha256): raise ValueError('external archive manifest pin required')
    path = Path(path); _no_links(path)
    if not path.is_file() or path.stat().st_size > MAX_TOTAL + MAX_MANIFEST + MAX_RELEASE + 512 * 1024:
        raise ValueError('archive file bound/type')
    with path.open('rb') as handle:
        # Reject ZIP64, multipart/comments and oversized directory *before* ZIP
        # allocates one object per central entry. Writer uses this same subset.
        handle.seek(0, 2)
        if handle.tell() < 22: raise ValueError('truncated archive')
        handle.seek(-22, 2); end = handle.read(22)
        magic, disk, central_disk, count, total, size, offset, comment = struct.unpack('<4s4H2LH', end)
        if magic != b'PK\x05\x06' or disk or central_disk or count != total or not 2 < count <= MAX_MEMBERS + 2 or comment or size > 256 * 1024:
            raise ValueError('unsupported/bounded archive directory required')
        handle.seek(0)
        with zipfile.ZipFile(handle) as packet:
            infos = packet.infolist(); names = [info.filename for info in infos]
            if len(infos) != count or len(set(names)) != len(names): raise ValueError('duplicate archive member')
            content = {}
            for info in infos:
                name = _path(info.filename)
                mode = (info.external_attr >> 16) & 0xffff
                limit = MAX_MANIFEST if name == 'manifest.json' else MAX_RELEASE if name == 'release.json' else MAX_MEMBER
                if (info.is_dir() or stat.S_IFMT(mode) != stat.S_IFREG or info.flag_bits & 1 or
                        info.compress_type != zipfile.ZIP_STORED or info.file_size != info.compress_size or not 0 < info.file_size <= limit):
                    raise ValueError('link/encrypted/compressed/oversize archive member')
                content[name] = packet.read(info)
            if not {'manifest.json', 'release.json'} <= set(content): raise ValueError('missing archive release/manifest')
    manifest_bytes = content.pop('manifest.json'); release_bytes = content.pop('release.json')
    m = _validate_members(manifest_bytes, tuple(content.items()))
    if m['archive_sha256'] != expected_archive_sha256: raise ValueError('external archive identity mismatch')
    _release(m, _json(release_bytes, MAX_RELEASE), verifier, check_time=False)
    return ArchiveSnapshot(manifest_bytes, release_bytes, tuple(sorted(content.items())))


def replay_portable_archive(path, *, expected_archive_sha256, verifier, result_store, scorer_version=SCORER_VERSION):
    """Local versioned rescore only; no original stochastic/target operation."""
    if type(result_store) is not CaptureStore: raise ValueError('explicit existing replay output store required')
    snapshot = read_archive(path, expected_archive_sha256=expected_archive_sha256, verifier=verifier)
    m = snapshot.manifest
    supported = scorer_version == SCORER_VERSION and m['scorer']['version'] == SCORER_VERSION
    results = []
    if supported:
        from .runner import rescore_captured_manifest
        for ref, input_ref in zip(m['roots'], m['inputs']):
            item = snapshot.get(input_ref, kind='archive_input')
            oracle = [row for b in item['batches'] for row in b['oracle']]
            original = snapshot.get(ref, kind='variant_manifest')
            results.append({'variant_id': item['variant_id'], 'manifest': ref, 'original_mode': original['mode'],
                'results': rescore_captured_manifest(snapshot, ref, oracle)})
    current = Path(__file__).with_name('scorer.py'); _no_links(current)
    receipt = {'schema_version': 1, 'mode': 'replay', 'label': 'rescored-with-version', 'edition': m['edition'],
        'visibility': m['visibility'], 'archive_sha256': m['archive_sha256'],
        'release_sha256': _sha(snapshot.release_bytes), 'provenance': deepcopy(m['provenance']),
        'original_scorer': deepcopy(m['scorer']), 'scorer_version': scorer_version,
        'scorer_code_sha256': _sha(current.read_bytes()), 'compatibility': 'supported' if supported else 'unsupported_scorer',
        'results': results, 'stochastic_model_rerun': False, 'fresh_holdout': False,
        'target_validation': 'not_run', 'product_acceptance': 'pending'}
    return {**receipt, 'replay_capture': result_store.put('portable_replay_receipt', receipt)}


def approved_projection(store, reference, *, signed_approval, verifier, registry,
                        expected_edition, expected_registry_head):
    """Only a closed owner-approved aggregate/diff view; never raw hidden data."""
    if type(store) is not CaptureStore or type(registry) is not EditionRegistry or registry.store.root != store.root:
        raise ValueError('same existing evaluator registry/store required')
    if registry.head != expected_registry_head: raise ValueError('stale projection registry head')
    keys = {'schema_version', 'action', 'edition', 'registry_head_sha256', 'projection_sha256',
            'capture_sha256', 'not_after_utc', 'nonce', 'authority_sha256'}
    authority = _signed(signed_approval, verifier, keys, 'release_evaluation_projection', check_time=True)
    projection = closed(store.get(reference, kind='approved_aggregate_projection'),
        {'schema_version', 'edition', 'split', 'mode', 'scope', 'corpus_sha256', 'freeze_sha256',
         'attempt_id', 'metrics', 'counts', 'projection_sha256'}, 'aggregate/diff projection')
    if (projection['schema_version'] != 1 or type(projection['schema_version']) is not int or projection['scope'] != 'aggregate_diff_only'
            or projection['edition'] != expected_edition or authority['edition'] != expected_edition
            or authority['registry_head_sha256'] != expected_registry_head or authority['capture_sha256'] != reference['sha256']
            or authority['projection_sha256'] != projection['projection_sha256']
            or projection['projection_sha256'] != digest({k: v for k, v in projection.items() if k != 'projection_sha256'})):
        raise ValueError('projection signature/scope/identity mismatch')
    state = registry.state(expected_edition)
    if (state['commitment'] is None or state['freeze'] is None or state['attempt'] is None
            or projection['corpus_sha256'] != state['commitment']['commitment_sha256']
            or projection['freeze_sha256'] != state['freeze']['freeze_sha256']
            or any(projection[k] != state['attempt']['suite'][k] for k in ('attempt_id', 'split', 'mode'))):
        raise ValueError('projection differs from exact frozen attempt')
    counts = closed(projection['counts'], {'variants', 'arms', 'failed', 'partial', 'unknown_cost'}, 'aggregate counts')
    if any(type(v) is not int or not 0 <= v <= 1000000 for v in counts.values()): raise ValueError('bounded aggregate counts required')
    if not isinstance(projection['metrics'], list) or len(projection['metrics']) > 40: raise ValueError('bounded aggregate metrics required')
    seen = set()
    from decimal import Decimal, InvalidOperation
    for metric in projection['metrics']:
        closed(metric, {'method', 'metric', 'numerator', 'denominator', 'value', 'baseline_value'}, 'aggregate metric')
        pair = (metric['method'], metric['metric'])
        if pair[0] not in ('B0', 'B1', 'C0', 'R0', 'R1') or pair[1] not in ('semantic_rows', 'slots', 'known_cost_usd', 'request_attempts') or pair in seen:
            raise ValueError('unapproved/duplicate aggregate metric')
        seen.add(pair)
        for key in ('numerator', 'denominator'):
            if metric[key] is not None and (type(metric[key]) is not int or not 0 <= metric[key] <= 1000000): raise ValueError('bounded aggregate metric counts required')
        for key in ('value', 'baseline_value'):
            value = metric[key]
            if value is not None:
                if not isinstance(value, str) or len(value) > 64: raise ValueError('aggregate numeric value required')
                try: finite = Decimal(value).is_finite()
                except InvalidOperation: finite = False
                if not finite: raise ValueError('finite numeric aggregate required')
    _no_secrets(projection)
    return {'projection': deepcopy(projection), 'approval_sha256': digest(signed_approval),
            'registry_head_sha256': expected_registry_head, 'raw_exported': False}

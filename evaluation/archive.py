"""Portable evaluator archives SOURCE. No import-time I/O or execution.

Explicit signed inventory releases authorize public/retired data only. ZIP is
read without extraction. Archived Python/prompts are inert bytes. CaptureStore
and the existing registry fold remain the only artifact/state primitives.
Final caller contract: evaluation/ARCHIVE.md.
"""
from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import json
import os
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
MAX_ROOTS = 64
MAX_CASES = 18
MAX_AUXILIARY = 32
SCORER_VERSION = 'semantic-v1'
SUPPORTED_SCORERS = frozenset({SCORER_VERSION})
CODE_NAMES = ('archive.py', 'artifacts.py', 'runner.py', 'scorer.py')
CAPTURE_KINDS = frozenset({
    'variant_manifest', 'arm_receipt', 'arm_raw', 'provider_request', 'provider_reply',
    'generation', 'mapping_proposal', 'batch_output', 'batch_failure',
    'target_observation_v2', 'target_observation_v3', 'failed_load_observation',
    'unknown_commit_observation', 'recovery_observation', 'target_arm_receipt', 'target_arm_failure',
    'suite_declaration', 'suite_report', 'suite_failure', 'signed_evidence',
    'billing_observation', 'archive_input', 'archive_configuration', 'replay_receipt',
    'edition_event', 'retirement', 'target_cleanup_observation'})
# Neutral evidence only: archived and counted, never scored as rollback/negative probes.
AUXILIARY_KINDS = frozenset({'target_cleanup_observation'})
MANIFEST_KEYS = {'schema_version', 'kind', 'edition', 'visibility', 'registry_head_sha256',
                 'history', 'roots', 'inputs', 'configuration', 'auxiliary', 'provenance', 'scorer',
                 'members', 'archive_sha256'}
RELEASE_KEYS = {'schema_version', 'action', 'edition', 'visibility', 'archive_sha256',
                'registry_head_sha256', 'allowed_kinds', 'not_after_utc', 'nonce', 'authority_sha256'}
PROJECTION_RELEASE_KEYS = {'schema_version', 'action', 'edition', 'registry_head_sha256', 'projection_sha256',
                           'capture_sha256', 'not_after_utc', 'nonce', 'authority_sha256'}
INPUT_KEYS = {'schema_version', 'edition', 'variant_id', 'split', 'visible', 'batches',
              'accepted_choices', 'expected_layout', 'identity'}
# Canonical writer subset; the reader refuses anything else.
ZIP_EPOCH = (1980, 1, 1, 0, 0, 0)
ZIP_MODE = (stat.S_IFREG | 0o600) << 16
FIXED_HEAD = ('manifest.json', 'release.json')
# Windows name-surrogate reparse tags (symlink, junction/mount point). Cloud
# placeholders (OneDrive) are reparse points too but are not name surrogates.
_NAME_SURROGATE = 0x20000000
_REPARSE_ATTRIBUTE = 0x400


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
    """Refuse POSIX symlinks and Windows symlink/junction reparse points on path or any parent."""
    for item in (path, *path.parents):
        if item.exists() or item.is_symlink():
            info = item.lstat()
            attributes = getattr(info, 'st_file_attributes', 0)
            tag = getattr(info, 'st_reparse_tag', 0)
            if (stat.S_ISLNK(info.st_mode) or
                    (attributes & _REPARSE_ATTRIBUTE and (not tag or tag & _NAME_SURROGATE))):
                raise ValueError('links/junctions are not archive roots/members')


def _reference(ref):
    closed(ref, {'sha256', 'kind', 'bytes'}, 'capture reference')
    if (not is_sha(ref['sha256']) or ref['kind'] not in CAPTURE_KINDS or
            type(ref['bytes']) is not int or not 0 < ref['bytes'] <= MAX_MEMBER):
        raise ValueError('unsupported/unbounded capture class')
    return ref


def _references(value, depth=0):
    """All actual typed references, including failed and partial attempt edges."""
    if depth > 64: raise ValueError('archive payload nesting limit')
    if isinstance(value, dict):
        if {'sha256', 'kind', 'bytes'} <= set(value):
            yield _reference(value)
        else:
            for child in value.values(): yield from _references(child, depth + 1)
    elif isinstance(value, list):
        for child in value: yield from _references(child, depth + 1)


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


def _hidden(value, depth=0):
    """True when any nested record is marked as sealed/heldout/T3 evaluation data."""
    if depth > 64: raise ValueError('archive payload nesting limit')
    if isinstance(value, dict):
        if (value.get('split') == 'heldout' or value.get('evaluation_phase') == 'T3'
                or value.get('visibility') == 'sealed'):
            return True
        return any(_hidden(child, depth + 1) for child in value.values())
    if isinstance(value, list):
        return any(_hidden(child, depth + 1) for child in value)
    return False


def _capture(data, reference):
    _reference(reference)
    if len(data) != reference['bytes'] or _sha(data) != reference['sha256']:
        raise ValueError('capture byte identity mismatch')
    value = _json(data, MAX_MEMBER)
    closed(value, {'schema_version', 'kind', 'payload'}, 'capture envelope')
    if type(value['schema_version']) is not int or value['schema_version'] != 1 or value['kind'] != reference['kind']:
        raise ValueError('capture envelope version/kind mismatch')
    _no_secrets(value['payload'])
    if reference['kind'] in AUXILIARY_KINDS:
        _cleanup_auxiliary(value['payload'])
    return value['payload']


# D5 CLEANUP-API FINAL receipt top level (la.postgres.cleanup.RECEIPT_KEYS). The
# evaluator never imports product code, so only these identity facts are mirrored.
CLEANUP_RECEIPT_KEYS = {'schema_version', 'kind', 'cleanup_id', 'action', 'binding', 'candidate', 'expected_target',
                        'cleanup_authority_sha256', 'cleanup_authority_envelope_sha256', 'prior_cleanup_sha256',
                        'write_connection_id', 'observer_connection_id', 'before', 'ownership', 'after', 'transaction',
                        'state', 'issues', 'target_validation', 'row_parity', 'product_acceptance', 'cleanup_sha256'}
CLEANUP_STATES = {'cleanup': {'refused', 'prepared', 'rolled_back', 'committed', 'indeterminate'},
                  'reconcile_cleanup': {'observed_absent', 'observed_present', 'indeterminate'}}


def _cleanup_auxiliary(payload):
    """Neutral wrapper for a D5 CLEANUP-API FINAL receipt, archived verbatim.

    The payload is the receipt object; its file form is canonical(payload) + '\\n'
    and it is keyed by its own cleanup_sha256. Only closed identity/neutrality is
    checked here; no cleanup fact is interpreted, scored or treated as rollback.
    Full semantic validation is la.postgres.validate_target_cleanup (product side).
    """
    if (not isinstance(payload, dict) or set(payload) != CLEANUP_RECEIPT_KEYS
            or type(payload['schema_version']) is not int or payload['schema_version'] != 1
            or payload['kind'] != 'target_cleanup'
            or not isinstance(payload['cleanup_id'], str) or re.fullmatch('[0-9a-f]{32}', payload['cleanup_id']) is None
            or payload['action'] not in CLEANUP_STATES or payload['state'] not in CLEANUP_STATES[payload['action']]
            or not isinstance(payload['issues'], list) or len(payload['issues']) > 10
            or payload['target_validation'] != 'not_run' or payload['row_parity'] != 'not_run'
            or payload['product_acceptance'] != 'pending' or not is_sha(payload['cleanup_sha256'])):
        raise ValueError('cleanup auxiliary must be a closed, neutral, unscored D5 cleanup receipt')
    if payload['cleanup_sha256'] != digest({k: v for k, v in payload.items() if k != 'cleanup_sha256'}):
        raise ValueError('cleanup auxiliary self-pin mismatch')


def _put_memory(members, kind, payload):
    data = canonical({'schema_version': 1, 'kind': kind, 'payload': payload})
    ref = {'sha256': _sha(data), 'kind': kind, 'bytes': len(data)}
    _capture(data, ref)
    members['captures/' + ref['sha256'] + '.json'] = data
    return ref


def _oracle_sha(item):
    return digest([row for batch in item['batches'] for row in batch['oracle']])


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
    declared = (state['commitment']['variants'] if state['commitment'] is not None
                else state['t1']['catalog']['variants'] if state['t1'] is not None else [])
    for item in inputs:
        if declared and item['identity'] not in declared:
            raise ValueError('archive input differs from original registered source/corpus')
    return state


def _closure(payloads, edition, visibility, state, by_variant):
    """Transitive retirement/visibility/input-identity checks over EVERY reached capture.

    Requested roots are not special: history, suite reports, arm edges and
    configuration auxiliaries reach further manifests/receipts, and each must be
    releasable and backed by its exact archived source/oracle case. One marked
    (heldout/T3/sealed) capture anywhere refuses the WHOLE non-retired archive, so
    unmarked children (provider requests, raw outputs) reached through it never ship.
    """
    released_hidden = visibility == 'retired' and state['retired']
    if not released_hidden and any(_hidden(payload) for _, payload in payloads):
        raise ValueError('hidden historical payload reachable from a non-retired archive closure')
    reached = set()
    for ref, payload in payloads:
        # Any top-level edition label must be this edition, for every capture class.
        if isinstance(payload, dict) and 'edition' in payload and payload['edition'] != edition:
            raise ValueError('cross-edition transitive capture')
        kind = ref['kind']
        if kind in ('variant_manifest', 'arm_receipt'):
            if not isinstance(payload, dict) or payload.get('edition') != edition or not isinstance(payload.get('variant_id'), str):
                raise ValueError('cross-edition/untyped transitive capture')
            item = by_variant.get(payload.get('variant_id'))
            if item is None:
                raise ValueError('transitive variant lacks its exact archived source/oracle case')
            if payload.get('split') != item['split'] or payload.get('input_sha256') != digest(item['visible']):
                raise ValueError('transitive capture differs from archived source/split')
            if kind == 'variant_manifest' and payload.get('oracle_commitment_sha256') != _oracle_sha(item):
                raise ValueError('transitive manifest differs from archived oracle')
            reached.add(item['variant_id'])
        elif kind == 'suite_declaration':
            if not isinstance(payload, dict) or payload.get('edition') != edition or not isinstance(payload.get('variants'), list):
                raise ValueError('cross-edition/untyped suite declaration')
            for declared in payload['variants']:
                item = (by_variant.get(declared['id']) if isinstance(declared, dict) and isinstance(declared.get('id'), str)
                        else None)
                if (item is None or declared.get('visible_sha256') != digest(item['visible'])
                        or declared.get('oracle_sha256') != _oracle_sha(item)):
                    raise ValueError('suite declaration variant lacks its exact archived case')
                reached.add(item['variant_id'])
    if reached != set(by_variant):
        raise ValueError('archive case set differs from the transitive variant closure')


def _roots(get, roots, by_variant, config, edition):
    """Requested roots: current pins, every original arm (including failures) intact."""
    modes = set()
    for ref in roots:
        original = get(ref, kind='variant_manifest')
        if (not isinstance(original, dict) or not {'edition', 'variant_id', 'split', 'mode', 'input_sha256', 'pins',
                                                    'oracle_commitment_sha256', 'results'} <= set(original)
                or not isinstance(original['variant_id'], str) or not isinstance(original['results'], list)
                or any(not isinstance(arm, dict) or not isinstance(arm.get('method'), str) or 'receipt_capture' not in arm
                       for arm in original['results'])):
            raise ValueError('malformed root variant manifest')
        item = by_variant.get(original['variant_id'])
        if (item is None or original['edition'] != edition or original['split'] != item['split']
                or original['input_sha256'] != digest(item['visible']) or original['pins'] != config['pins']
                or original['oracle_commitment_sha256'] != _oracle_sha(item)):
            raise ValueError('manifest/input/config/edition mismatch')
        if original['mode'] not in ('rules', 'mock', 'live'): raise ValueError('unknown original execution mode')
        if len(original['results']) != 5 or {r['method'] for r in original['results']} != {'B0', 'B1', 'C0', 'R0', 'R1'}:
            raise ValueError('all original failed/partial arms must remain')
        for arm in original['results']:
            if get(arm['receipt_capture'], kind='arm_receipt') != {k: v for k, v in arm.items() if k != 'receipt_capture'}:
                raise ValueError('original arm receipt changed')
        modes.add(original['mode'])
    return modes


def _configuration(configuration, edition):
    configuration = closed(configuration, {'schema_version', 'edition', 'pins', 'values'}, 'archive configuration')
    if configuration['edition'] != edition or not isinstance(configuration['values'], dict):
        raise ValueError('wrong archive configuration edition/values')
    _no_secrets(configuration)
    auxiliary = configuration['values'].get('auxiliary_captures', [])
    # Typed references are admitted ONLY as declared neutral auxiliaries; any other
    # ref would be an unchecked entry point into the capture graph.
    other = {k: v for k, v in configuration['values'].items() if k != 'auxiliary_captures'}
    if next(_references([configuration['pins'], other]), None) is not None:
        raise ValueError('configuration may reference captures only through auxiliary_captures')
    if not isinstance(auxiliary, list) or len(auxiliary) > MAX_AUXILIARY:
        raise ValueError('bounded auxiliary capture list required')
    for ref in auxiliary:
        if _reference(ref)['kind'] not in AUXILIARY_KINDS:
            raise ValueError('auxiliary captures are neutral cleanup evidence only')
    if len({ref['sha256'] for ref in auxiliary}) != len(auxiliary): raise ValueError('duplicate auxiliary capture')
    return configuration, deepcopy(auxiliary)


def _provenance(state, inputs, modes):
    return {'corpus_sha256': state['commitment']['commitment_sha256'] if state['commitment'] is not None else
            state['t1']['catalog']['catalog_sha256'] if state['t1'] is not None else digest([i['identity'] for i in inputs]),
            'freeze_sha256': None if state['freeze'] is None else state['freeze']['freeze_sha256'],
            'modes': sorted(modes)}


def _root_list(roots):
    if not isinstance(roots, list) or not 1 <= len(roots) <= MAX_ROOTS:
        raise ValueError('bounded requested archive roots required')
    for ref in roots:
        if _reference(ref)['kind'] != 'variant_manifest': raise ValueError('archive roots are variant manifests')
    if len({ref['sha256'] for ref in roots}) != len(roots): raise ValueError('duplicate archive root')
    return deepcopy(roots)


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

    @property
    def release(self):
        return _json(self.release_bytes, MAX_RELEASE)

    def get(self, reference, *, kind=None):
        _reference(reference)
        if kind is not None and kind != reference['kind']: raise ValueError('wrong capture kind')
        data = dict(self.member_bytes).get('captures/' + reference['sha256'] + '.json')
        if data is None: raise ValueError('missing archived capture')
        return _capture(data, reference)


_MALFORMED = (KeyError, TypeError, AttributeError, IndexError)


def plan_archive(store, *, cases, manifest_refs, configuration, registry, visibility):
    """Construct a bounded in-memory release inventory; no archive/journal write."""
    try:
        return _plan_archive(store, cases=cases, manifest_refs=manifest_refs, configuration=configuration,
                             registry=registry, visibility=visibility)
    except _MALFORMED as exc:
        raise ValueError('malformed archive input/capture: ' + type(exc).__name__) from None


def _plan_archive(store, *, cases, manifest_refs, configuration, registry, visibility):
    if type(store) is not CaptureStore or type(registry) is not EditionRegistry or registry.store.root != store.root:
        raise ValueError('existing same evaluator capture store and registry required')
    _no_links(store.root); _no_links(registry.path)
    if not isinstance(cases, list) or not 1 <= len(cases) <= MAX_CASES:
        raise ValueError('bounded exact transitive cases required')
    roots = _root_list(manifest_refs)
    edition = cases[0].edition
    if len({c.variant_id for c in cases}) != len(cases) or any(c.edition != edition for c in cases):
        raise ValueError('archive must preserve one exact edition with unique variants')
    inputs = [{'schema_version': 1, 'edition': c.edition, 'variant_id': c.variant_id, 'split': c.split,
               'visible': deepcopy(c.visible), 'batches': [dict(batch_id=b.batch_id, visible=deepcopy(b.visible), oracle=deepcopy(b.oracle)) for b in c.batches],
               'accepted_choices': deepcopy(c.accepted_choices), 'expected_layout': deepcopy(c.expected_layout),
               'identity': variant_identity(c)} for c in cases]
    if any(not 1 <= len(item['batches']) <= 10 for item in inputs): raise ValueError('bounded original batches required')
    by_variant = {item['variant_id']: item for item in inputs}
    # Head and history come from ONE committed registry read.
    snapshot = registry.snapshot()
    head = snapshot['head']
    history = [event for event in snapshot['events'] if event['edition'] == edition]
    state = _history_scope(history, edition, visibility, inputs)
    configuration, auxiliary = _configuration(configuration, edition)
    members = {}
    input_refs = [_put_memory(members, 'archive_input', item) for item in inputs]
    config_ref = _put_memory(members, 'archive_configuration', configuration)
    total = sum(map(len, members.values()))
    if next(_references(inputs), None) is not None:
        raise ValueError('archive source/oracle cases cannot carry capture references')
    pending = list(roots) + list(_references(history)) + list(auxiliary)
    seen, payloads = {r['sha256']: deepcopy(r) for r in [*input_refs, config_ref]}, []
    while pending:
        ref = _reference(pending.pop())
        if ref['sha256'] in seen:
            if seen[ref['sha256']] != ref: raise ValueError('conflicting capture identity')
            continue
        if len(members) >= MAX_MEMBERS - len(CODE_NAMES): raise ValueError('archive member limit')
        # Count/size are checked from the reference and file metadata before reading bytes.
        if total + ref['bytes'] > MAX_TOTAL: raise ValueError('archive total limit')
        path = store.root / (ref['sha256'] + '.json'); _no_links(path)
        if not path.is_file() or path.stat().st_size != ref['bytes']: raise ValueError('missing/unbounded capture')
        data = path.read_bytes(); payload = _capture(data, ref)
        members['captures/' + ref['sha256'] + '.json'] = data
        total += len(data)
        seen[ref['sha256']] = deepcopy(ref)
        payloads.append((ref, payload))
        pending.extend(_references(payload))
    _closure(payloads, edition, visibility, state, by_variant)
    modes = _roots(lambda ref, kind=None: store.get(_reference(ref), kind=kind), roots, by_variant, configuration, edition)
    for name in CODE_NAMES:
        path = Path(__file__).with_name(name); _no_links(path)
        if path.stat().st_size > MAX_MEMBER: raise ValueError('scorer code limit')
        members['code/' + name] = path.read_bytes()
    if sum(map(len, members.values())) > MAX_TOTAL: raise ValueError('archive total limit')
    manifest = {'schema_version': 1, 'kind': 'evaluation_archive', 'edition': edition, 'visibility': visibility,
        'registry_head_sha256': head, 'history': history, 'roots': roots, 'inputs': input_refs,
        'configuration': config_ref, 'auxiliary': auxiliary,
        'provenance': _provenance(state, inputs, modes),
        'scorer': {'schema_version': 1, 'version': SCORER_VERSION, 'code_sha256': _sha(members['code/scorer.py'])},
        'members': [{'path': name, 'kind': 'evaluator_code' if name.startswith('code/') else _json(data, MAX_MEMBER)['kind'],
                     'sha256': _sha(data), 'bytes': len(data)} for name, data in sorted(members.items())]}
    manifest['archive_sha256'] = digest(manifest)
    plan = ArchivePlan(canonical(manifest), tuple(sorted(members.items())))
    _validate_members(plan.manifest_bytes, plan.member_bytes)
    return plan


def _validate_members(manifest_bytes, member_bytes):
    """Rebuild and check the full closure from bytes; crafted shapes refuse as ValueError."""
    try:
        return _validate_members_unchecked(manifest_bytes, member_bytes)
    except _MALFORMED as exc:
        raise ValueError('malformed archive manifest/member: ' + type(exc).__name__) from None


def _validate_members_unchecked(manifest_bytes, member_bytes):
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
    # Declared sizes are bounded before any member JSON is parsed.
    for row in m['members']:
        closed(row, {'path', 'kind', 'sha256', 'bytes'}, 'archive member')
        if type(row['bytes']) is not int or not 0 < row['bytes'] <= MAX_MEMBER: raise ValueError('member size bound')
    if sum(row['bytes'] for row in m['members']) > MAX_TOTAL: raise ValueError('oversize archive inventory')
    listed = set()
    for row in m['members']:
        name = _path(row['path'])
        if name in listed or name not in data: raise ValueError('duplicate/missing archive member')
        listed.add(name)
        raw = data[name]
        if len(raw) != row['bytes'] or _sha(raw) != row['sha256']:
            raise ValueError('member byte/hash/size mismatch')
        if row['kind'] == 'evaluator_code':
            if name not in {'code/' + n for n in CODE_NAMES}: raise ValueError('unapproved executable/code member class')
        else:
            if name != 'captures/' + row['sha256'] + '.json': raise ValueError('capture filename differs from identity')
            _capture(raw, {k: row[k] for k in ('sha256', 'kind', 'bytes')})
    if set(data) != listed: raise ValueError('unlisted archive data')
    if not {'code/' + n for n in CODE_NAMES} <= listed: raise ValueError('missing original evaluator code identities')
    scorer = closed(m['scorer'], {'schema_version', 'version', 'code_sha256'}, 'original scorer')
    text(scorer['version'], 'scorer version', 64)
    if scorer['code_sha256'] != _sha(data['code/scorer.py']):
        raise ValueError('invalid original scorer pin/schema')
    view = ArchiveSnapshot(manifest_bytes, b'', tuple(member_bytes))
    roots = _root_list(m['roots'])
    if not isinstance(m['inputs'], list) or not 1 <= len(m['inputs']) <= MAX_CASES:
        raise ValueError('bounded archived transitive cases required')
    inputs = [view.get(ref, kind='archive_input') for ref in m['inputs']]
    from .runner import BatchCase, VariantCase
    by_variant = {}
    for item in inputs:
        closed(item, INPUT_KEYS, 'archive replay input')
        if item['edition'] != m['edition'] or item['variant_id'] in by_variant:
            raise ValueError('wrong/duplicate input edition/variant')
        if not isinstance(item['batches'], list) or not 1 <= len(item['batches']) <= 10: raise ValueError('bounded original batches required')
        for b in item['batches']: closed(b, {'batch_id', 'visible', 'oracle'}, 'archive batch')
        case = VariantCase(item['variant_id'], item['split'], item['edition'], item['visible'],
                           tuple(BatchCase(**b) for b in item['batches']), item['accepted_choices'], item['expected_layout'])
        if variant_identity(case) != item['identity']: raise ValueError('source/sample/oracle/layout identity changed')
        by_variant[item['variant_id']] = item
    state = _history_scope(m['history'], m['edition'], m['visibility'], inputs)
    config, auxiliary = _configuration(view.get(m['configuration'], kind='archive_configuration'), m['edition'])
    if m['auxiliary'] != auxiliary: raise ValueError('manifest auxiliary differs from archived configuration')
    if next(_references(inputs), None) is not None:
        raise ValueError('archive source/oracle cases cannot carry capture references')
    # Same entry points as the planner: roots, edition history, declared auxiliaries.
    visited = {ref['sha256']: deepcopy(ref) for ref in [*m['inputs'], m['configuration']]}
    required_refs = list(roots) + list(_references(m['history'])) + list(auxiliary)
    payloads = []
    while required_refs:
        ref = _reference(required_refs.pop())
        if ref['sha256'] in visited:
            if visited[ref['sha256']] != ref: raise ValueError('conflicting capture identity')
            continue
        visited[ref['sha256']] = deepcopy(ref); payload = view.get(ref)
        payloads.append((ref, payload))
        required_refs.extend(_references(payload))
    actual_captures = {row['sha256'] for row in m['members'] if row['kind'] != 'evaluator_code'}
    if set(visited) != actual_captures: raise ValueError('unreachable/unapproved extra capture member')
    _closure(payloads, m['edition'], m['visibility'], state, by_variant)
    modes = _roots(view.get, roots, by_variant, config, m['edition'])
    if m['provenance'] != _provenance(state, inputs, modes):
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


def _zip_info(name):
    info = zipfile.ZipInfo(name, date_time=ZIP_EPOCH)
    info.create_system = 3; info.external_attr = ZIP_MODE; info.compress_type = zipfile.ZIP_STORED
    return info


def export_archive(plan, destination, *, signed_release, verifier):
    if type(plan) is not ArchivePlan: raise ValueError('concrete archive plan required')
    m = _validate_members(plan.manifest_bytes, plan.member_bytes)
    _release(m, signed_release, verifier, check_time=True)
    release = canonical(signed_release)
    if len(release) > MAX_RELEASE: raise ValueError('release envelope limit')
    destination = Path(destination); _no_links(destination)
    if not destination.parent.is_dir(): raise ValueError('existing explicit owned destination parent required')
    # Exclusive create; an interrupted packet stays incomplete, cannot verify and
    # is never deleted or overwritten here. Fixed order/timestamps/modes keep the
    # packet canonical for read_archive's structure checks.
    with destination.open('xb') as handle:
        with zipfile.ZipFile(handle, 'w', compression=zipfile.ZIP_STORED, allowZip64=False) as packet:
            for name, raw in ((FIXED_HEAD[0], plan.manifest_bytes), (FIXED_HEAD[1], release), *plan.member_bytes):
                packet.writestr(_zip_info(name), raw)
        handle.flush()
        os.fsync(handle.fileno())
    _no_links(destination)
    packet_hash, packet_bytes = hashlib.sha256(), 0
    with destination.open('rb') as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b''):
            packet_hash.update(chunk); packet_bytes += len(chunk)
    return {'schema_version': 1, 'archive_sha256': m['archive_sha256'], 'edition': m['edition'],
            'visibility': m['visibility'], 'registry_head_sha256': m['registry_head_sha256'],
            'release_sha256': digest(signed_release), 'packet_sha256': packet_hash.hexdigest(),
            'member_count': len(plan.member_bytes), 'packet_bytes': packet_bytes,
            'stochastic_model_rerun': False, 'fresh_holdout': False}


def _zip_structure(handle, size):
    """Canonical stored-ZIP subset: one disk, no comment/ZIP64/descriptors/extras,
    contiguous local headers matching the central directory, nothing prepended
    or appended. Checked before member bytes are allocated."""
    if size < 22: raise ValueError('truncated archive')
    handle.seek(size - 22); end = handle.read(22)
    magic, disk, central_disk, count, total, cd_size, cd_offset, comment = struct.unpack('<4s4H2LH', end)
    if (magic != b'PK\x05\x06' or disk or central_disk or count != total or not 2 < count <= MAX_MEMBERS + 2
            or comment or cd_size > 256 * 1024 or cd_offset + cd_size + 22 != size):
        raise ValueError('unsupported/bounded archive directory required')
    handle.seek(0)
    packet = zipfile.ZipFile(handle)
    infos = packet.infolist(); names = [info.filename for info in infos]
    if len(infos) != count or len(set(names)) != len(names): raise ValueError('duplicate archive member')
    if tuple(names[:2]) != FIXED_HEAD or names[2:] != sorted(names[2:]):
        raise ValueError('noncanonical archive member order')
    if sum(info.file_size for info in infos) > MAX_TOTAL + MAX_MANIFEST + MAX_RELEASE:
        raise ValueError('oversize archive inventory')
    offset = 0
    for info in infos:
        name = _path(info.filename)
        mode = (info.external_attr >> 16) & 0xffff
        limit = MAX_MANIFEST if name == 'manifest.json' else MAX_RELEASE if name == 'release.json' else MAX_MEMBER
        if (info.is_dir() or stat.S_IFMT(mode) != stat.S_IFREG or info.external_attr != ZIP_MODE
                or info.flag_bits or info.extra or info.comment or info.create_system != 3
                or info.date_time != ZIP_EPOCH or info.compress_type != zipfile.ZIP_STORED
                or info.file_size != info.compress_size or not 0 < info.file_size <= limit):
            raise ValueError('link/encrypted/compressed/noncanonical/oversize archive member')
        if info.header_offset != offset: raise ValueError('overlapping/gapped local member headers')
        handle.seek(offset)
        sig, _version, flags, method, _time, _date, crc, csize, usize, nlen, xlen = struct.unpack('<4s5H3L2H', handle.read(30))
        if (sig != b'PK\x03\x04' or flags or method != 0 or crc != info.CRC or csize != info.compress_size
                or usize != info.file_size or xlen or handle.read(nlen) != name.encode('ascii')):
            raise ValueError('local header differs from central directory')
        offset += 30 + nlen + info.compress_size
    if offset != cd_offset: raise ValueError('unlisted data before central directory')
    return packet, infos


def read_archive(path, *, expected_archive_sha256, verifier):
    if not is_sha(expected_archive_sha256): raise ValueError('external archive manifest pin required')
    path = Path(path); _no_links(path)
    if not path.is_file() or path.stat().st_size > MAX_TOTAL + MAX_MANIFEST + MAX_RELEASE + 512 * 1024:
        raise ValueError('archive file bound/type')
    try:
        with path.open('rb') as handle:
            size = handle.seek(0, 2)
            packet, infos = _zip_structure(handle, size)
            with packet:
                content = {info.filename: packet.read(info) for info in infos}  # CRC-checked by zipfile.
    except (zipfile.BadZipFile, struct.error, EOFError, UnicodeError) as exc:
        raise ValueError('malformed archive packet: ' + type(exc).__name__) from None
    manifest_bytes = content.pop('manifest.json'); release_bytes = content.pop('release.json')
    m = _validate_members(manifest_bytes, tuple(content.items()))
    if m['archive_sha256'] != expected_archive_sha256: raise ValueError('external archive identity mismatch')
    _release(m, _json(release_bytes, MAX_RELEASE), verifier, check_time=False)
    return ArchiveSnapshot(manifest_bytes, release_bytes, tuple(sorted(content.items())))


ORIGINAL_ARM_KEYS = ('method', 'status', 'error_type', 'mode', 'evaluation_phase', 'request_attempts',
                     'failed_attempts', 'usage', 'known_total_cost', 'unknown_liabilities', 'target_validation')


def replay_portable_archive(path, *, expected_archive_sha256, verifier, result_store, scorer_version=SCORER_VERSION):
    """Local versioned rescore only; no original stochastic/target/cleanup operation."""
    if type(result_store) is not CaptureStore: raise ValueError('explicit existing replay output store required')
    text(scorer_version, 'scorer version', 64)
    snapshot = read_archive(path, expected_archive_sha256=expected_archive_sha256, verifier=verifier)
    m = snapshot.manifest
    # Only a scorer implemented in THIS checkout may rescore; archived code is inert
    # and an unknown version is reported, never dynamically imported.
    supported = scorer_version in SUPPORTED_SCORERS and m['scorer']['version'] in SUPPORTED_SCORERS
    current = Path(__file__).with_name('scorer.py'); _no_links(current)
    current_sha = _sha(current.read_bytes())
    results = None
    if supported:
        from .runner import rescore_captured_manifest
        results = []
        by_variant = {item['variant_id']: item for item in (snapshot.get(i, kind='archive_input') for i in m['inputs'])}
        for ref in m['roots']:
            original = snapshot.get(ref, kind='variant_manifest')
            item = by_variant[original['variant_id']]  # Coverage already proven by read_archive.
            oracle = [row for b in item['batches'] for row in b['oracle']]
            results.append({'variant_id': item['variant_id'], 'manifest': deepcopy(ref), 'original_mode': original['mode'],
                'original_arms': [{**{k: deepcopy(arm.get(k)) for k in ORIGINAL_ARM_KEYS}, 'receipt': deepcopy(arm['receipt_capture'])}
                                  for arm in original['results']],
                'results': rescore_captured_manifest(snapshot, ref, oracle)})
    receipt = {'schema_version': 1, 'mode': 'replay',
        'label': 'rescored-with-version' if supported else 'not_rescored_unsupported_scorer',
        'edition': m['edition'], 'visibility': m['visibility'], 'archive_sha256': m['archive_sha256'],
        'release_sha256': _sha(snapshot.release_bytes), 'provenance': deepcopy(m['provenance']),
        'original_scorer': deepcopy(m['scorer']), 'scorer_version': scorer_version,
        'scorer_code_sha256': current_sha, 'scorer_code_matches_original': current_sha == m['scorer']['code_sha256'],
        'compatibility': 'supported' if supported else 'unsupported_scorer',
        'configuration': deepcopy(m['configuration']), 'auxiliary_count': len(m['auxiliary']),
        'results': results, 'stochastic_model_rerun': False, 'fresh_holdout': False,
        'target_validation': 'not_run', 'product_acceptance': 'pending'}
    return {**receipt, 'replay_capture': result_store.put('portable_replay_receipt', receipt)}


def approved_projection(store, reference, *, signed_approval, verifier, registry,
                        expected_edition, expected_registry_head):
    """Only a closed owner-approved aggregate/diff view; never raw hidden data."""
    if type(store) is not CaptureStore or type(registry) is not EditionRegistry or registry.store.root != store.root:
        raise ValueError('same existing evaluator registry/store required')
    # Head and folded state come from ONE registry read; a concurrent append refuses.
    snapshot = registry.snapshot()
    if snapshot['head'] is None or snapshot['head'] != expected_registry_head:
        raise ValueError('stale projection registry head')
    authority = _signed(signed_approval, verifier, PROJECTION_RELEASE_KEYS, 'release_evaluation_projection', check_time=True)
    projection = closed(store.get(reference, kind='approved_aggregate_projection'),
        {'schema_version', 'edition', 'split', 'mode', 'scope', 'corpus_sha256', 'freeze_sha256',
         'attempt_id', 'metrics', 'counts', 'projection_sha256'}, 'aggregate/diff projection')
    if (projection['scope'] != 'aggregate_diff_only'
            or projection['edition'] != expected_edition or authority['edition'] != expected_edition
            or authority['registry_head_sha256'] != snapshot['head'] or authority['capture_sha256'] != reference['sha256']
            or authority['projection_sha256'] != projection['projection_sha256']
            or projection['projection_sha256'] != digest({k: v for k, v in projection.items() if k != 'projection_sha256'})):
        raise ValueError('projection signature/scope/identity mismatch')
    state = EditionRegistry._state(snapshot['events'], expected_edition)
    if (state['commitment'] is None or state['freeze'] is None or state['attempt'] is None
            or state['attempt']['status'] == 'running'
            or projection['corpus_sha256'] != state['commitment']['commitment_sha256']
            or projection['freeze_sha256'] != state['freeze']['freeze_sha256']
            # Suites carry no split: a T3 suite is exactly the commitment's heldout variants.
            or projection['split'] != 'heldout'
            or any(projection[k] != state['attempt']['suite'][k] for k in ('attempt_id', 'mode'))):
        raise ValueError('projection differs from exact terminal frozen attempt')
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
    return {'schema_version': 1, 'kind': 'approved_evaluation_projection', 'edition': expected_edition,
            'projection': deepcopy(projection), 'approval_sha256': digest(signed_approval),
            'registry_head_sha256': snapshot['head'], 'raw_exported': False}
